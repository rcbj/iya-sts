// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The realms' signing key sets as `common/keystore.js` stores them: one
//! `sts_keys` row per realm (`default` for the default realm), the set's
//! JSON blob (`serialise()`) sealed under the realm's `signing-keys` data
//! key.
//!
//! * **Read at the start, held SEALED** (2026-09-06): the decrypt at load is
//!   a check — the wrong key-encryption key stops the service before it
//!   binds, rather than at the first signature hours later — and the
//!   plaintext is not kept; [`KeySets::open`] opens a set when it is used.
//! * **The blob is carried whole.** The RSA signing key, its certificate,
//!   its `kid` and the curve keys are read from it here; every other member
//!   (the post-quantum keys, the encryption keys, the generations, the XML
//!   and BBS keys, the signer groups) is kept exactly as Node wrote it, so a
//!   set this runtime writes back is a set Node can read.
//! * **A save never replaces a newer set** (`replaceKeySet()`'s
//!   `not-newer`): under the row's lock, the stored set wins unless the one
//!   offered is a later generation, so two processes racing to make the
//!   first set agree on the one written first.
//!
//! Not here yet: generating a key set, which is `helpers.js`'s
//! `makeStsKeys()` and a dozen members; `pki:` rows (the certificate
//! authorities) are passed over.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use openssl::sha::sha256;
use serde_json::Value as Json;
use sts_core::errors::codes;
use sts_core::log::tag;
use sts_crypto::secrets::dek_id_of;

use crate::driver::{Driver, KeyMerge};
use crate::keystore::{dek_realm, DataKeys, DEK_ROW_PREFIX};

/// What a key set's blob is sealed under.
const LABEL: &str = "signing-keys";
/// What a merge says of a stored set sealed under a data key not held here.
const UNHELD: &str = "the stored key set names a data key not held here: ";
/// A certificate authority's row, not a key set.
pub const PKI_ROW_PREFIX: &str = "pki:";

/// `kidOf()`: `sts-` and the first twelve hex digits of the SHA-256 of the
/// certificate's base64.
pub fn kid_of(cert_b64: &str) -> String {
    let digest = sha256(cert_b64.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
    format!("sts-{}", &hex[..12])
}

/// One realm's key set, opened.
#[derive(Clone, Debug, PartialEq)]
pub struct KeySet {
    pub realm: String,
    pub blob: Json,
}

/// One curve key of a set (`extraKeys`).
#[derive(Clone, Debug, PartialEq)]
pub struct CurveKey {
    pub alg: String,
    pub private_key_pem: String,
    pub public_jwk: Json,
}

impl KeySet {
    fn text(&self, key: &str) -> Option<&str> {
        self.blob
            .get(key)
            .and_then(Json::as_str)
            .filter(|s| !s.is_empty())
    }

    /// The RSA signing key, PKCS#8 PEM.
    pub fn private_key_pem(&self) -> Option<&str> {
        self.text("privateKeyPem")
    }

    /// The certificate the set was born with, base64 DER.
    pub fn cert_b64(&self) -> Option<&str> {
        self.text("certB64")
    }

    /// The signing key's `kid`, from the certificate the set was born with.
    pub fn kid(&self) -> Option<String> {
        self.cert_b64().map(kid_of)
    }

    pub fn created_at(&self) -> f64 {
        self.blob
            .get("createdAt")
            .and_then(Json::as_f64)
            .unwrap_or(0.0)
    }

    /// `generationOf()`.
    pub fn generation(&self) -> i64 {
        generation_of(&self.blob)
    }

    /// The curve keys, by JOSE `alg`.
    pub fn curve_keys(&self) -> Vec<CurveKey> {
        self.blob
            .get("extraKeys")
            .and_then(Json::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(|one| {
                        Some(CurveKey {
                            alg: one.get("alg")?.as_str()?.to_string(),
                            private_key_pem: one
                                .get("privateKeyPem")?
                                .as_str()?
                                .to_string(),
                            public_jwk: one
                                .get("publicJwk")
                                .cloned()
                                .unwrap_or(Json::Null),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn generation_of(blob: &Json) -> i64 {
    blob.pointer("/generations/generation")
        .and_then(Json::as_f64)
        .map(|n| n as i64)
        .unwrap_or(0)
}

/// What a save did.
#[derive(Clone, Debug, PartialEq)]
pub enum Saved {
    /// The set offered is the stored one now.
    Written,
    /// The store held a set at least as new; it is the one held here now.
    Kept(Box<KeySet>),
}

/// Every realm's key set, held sealed.
pub struct KeySets {
    driver: Arc<dyn Driver>,
    keys: Arc<DataKeys>,
    sealed: Mutex<BTreeMap<String, String>>,
}

impl KeySets {
    pub fn new(driver: Arc<dyn Driver>, keys: Arc<DataKeys>) -> Arc<KeySets> {
        Arc::new(KeySets {
            driver,
            keys,
            sealed: Mutex::new(BTreeMap::new()),
        })
    }

    fn held(&self) -> MutexGuard<'_, BTreeMap<String, String>> {
        self.sealed.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Opens a stored row, or says why it will not open — THE MOST
    /// IMPORTANT ERROR HERE: the likely cause is the wrong key-encryption
    /// key, and the wrong response is to make a new signing key.
    fn open_row(&self, realm: &str, cipher: &str) -> Result<Json, String> {
        if dek_id_of(cipher).is_none() {
            return Err(format!(
                "{}the stored key material for the \"{}\" realm was written before data encryption keys (#391), \
                 and this build does not read that format. Recreate the store: this service will not start rather \
                 than generate new signing keys over it.",
                tag(codes::STS_KEYS_0095),
                realm
            ));
        }
        let plain = self.keys.open(cipher, LABEL).ok_or_else(|| {
            format!(
                "{}the stored key material for the \"{}\" realm could not be decrypted. The key-encryption key is \
                 almost certainly not the one it was encrypted with (provider: file). This service will NOT start \
                 rather than generate a new signing key, because doing that would silently stop every token it has \
                 ever issued from verifying.",
                tag(codes::STS_KEYS_0029),
                realm
            )
        })?;
        serde_json::from_str(&plain).map_err(|e| {
            format!(
                "{}the stored key material for the \"{}\" realm decrypted to something that is not a key set: {}",
                tag(codes::STS_KEYS_0029),
                realm,
                e
            )
        })
    }

    /// Reads every stored key set, checks that each opens, and holds them
    /// sealed. Fatal when one will not open. Answers how many were read.
    pub async fn load(&self) -> Result<usize, String> {
        let rows = self.driver.load_keys().await.map_err(|e| {
            format!(
                "{}the stored key material could not be read: {}",
                tag(codes::STS_KEYS_0028),
                e
            )
        })?;
        let mut loaded = 0;
        for (realm, cipher) in rows {
            if realm.starts_with(DEK_ROW_PREFIX)
                || realm.starts_with(PKI_ROW_PREFIX)
            {
                continue;
            }
            self.open_row(&realm, &cipher)?;
            self.held().insert(realm, cipher);
            loaded += 1;
        }
        Ok(loaded)
    }

    /// The realms holding a set (`default` for the default realm).
    pub fn realms(&self) -> Vec<String> {
        self.held().keys().cloned().collect()
    }

    /// One realm's set, opened now and not kept; `None` where there is none
    /// or it will not open (said, with its code).
    pub fn open(&self, realm: &str) -> Option<KeySet> {
        let id = dek_realm(realm);
        let cipher = self.held().get(&id).cloned()?;
        match self.open_row(&id, &cipher) {
            Ok(blob) => Some(KeySet { realm: id, blob }),
            Err(e) => {
                tracing::error!("keystore: {}", e);
                None
            }
        }
    }

    /// Writes a realm's set, sealed — unless the store holds one at least as
    /// new, which is then the one held here.
    pub async fn save(
        &self,
        realm: &str,
        blob: &Json,
    ) -> Result<Saved, String> {
        let id = dek_realm(realm);
        let offered = generation_of(blob);
        let cipher = self
            .keys
            .seal(&blob.to_string(), LABEL, realm)
            .ok_or_else(|| "no key-encryption key is held".to_string())?;
        // The data key first: nothing is stored before the key it was
        // sealed under.
        self.keys.settle().await;
        let stored = if self.driver.merges_keys() {
            // THE OTHER PROCESSES' DATA KEYS FIRST (`writeAfterDeks()`): the
            // stored set may be sealed under one made a moment ago, and a set
            // that will not open here is never taken for an older one. A
            // merge that still meets one reads the rows again and tries once
            // more; past that it refuses rather than overwrite.
            let mut outcome = Err(String::new());
            for _ in 0..2 {
                self.keys.load(false).await?;
                let mine = cipher.clone();
                let keys = self.keys.clone();
                let realm_id = id.clone();
                let merge: KeyMerge = Box::new(move |current: Option<&str>| {
                    let Some(current) = current else {
                        return Ok(Some(mine));
                    };
                    let held = keys
                        .open(current, LABEL)
                        .ok_or_else(|| format!("{}{}", UNHELD, realm_id))
                        .and_then(|plain| {
                            serde_json::from_str::<Json>(&plain)
                                .map_err(|e| e.to_string())
                        })?;
                    if generation_of(&held) >= offered {
                        tracing::info!(
                            "keystore: the \"{}\" realm's key set in the store is not older than the one offered; \
                             it is kept.",
                            realm_id
                        );
                        Ok(None)
                    } else {
                        Ok(Some(mine))
                    }
                });
                outcome = self
                    .driver
                    .merge_keys(&id, merge)
                    .await
                    .map_err(|e| e.to_string());
                match &outcome {
                    Err(e) if e.contains(UNHELD) => continue,
                    _ => break,
                }
            }
            outcome?.unwrap_or(cipher.clone())
        } else {
            self.driver
                .save_keys(&id, &cipher)
                .await
                .map_err(|e| e.to_string())?;
            cipher.clone()
        };
        self.held().insert(id.clone(), stored.clone());
        if stored == cipher {
            return Ok(Saved::Written);
        }
        let theirs = self.open_row(&id, &stored)?;
        Ok(Saved::Kept(Box::new(KeySet {
            realm: id,
            blob: theirs,
        })))
    }
}
