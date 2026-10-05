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

// ---------------------------------------------------------------------------
// MAKING A KEY SET (`helpers.js`'s makeStsKeys()), in the blob's own shape:
// every member a fresh Node set carries, each `kid` by Node's recipe, so a
// set made here is a set Node reads and publishes the same names for. The
// post-quantum keys, the KEM keys, the BBS key, the signer groups and the
// generations are made lazily by Node, after the set exists, and are left
// empty here as Node leaves them.
// ---------------------------------------------------------------------------

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509Builder, X509NameBuilder};
use serde_json::json;

type Made<T> = Result<T, String>;

/// A curve key's `alg`, its curve where the `alg` does not say, and its maker.
type CurveSpec = (
    &'static str,
    Option<&'static str>,
    Box<dyn Fn() -> Made<PKey<Private>>>,
);

fn ossl<T>(r: Result<T, openssl::error::ErrorStack>) -> Made<T> {
    r.map_err(|e| e.to_string())
}

fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// RFC 7638's thumbprint (`jwkThumbprint()`), base64url, truncated.
pub fn jwk_thumbprint(jwk: &Json, truncate: usize) -> String {
    let members: &[&str] = match jwk.get("kty").and_then(Json::as_str) {
        Some("RSA") => &["e", "kty", "n"],
        Some("EC") => &["crv", "kty", "x", "y"],
        Some("OKP") => &["crv", "kty", "x"],
        _ => &["kty"],
    };
    let canonical = format!(
        "{{{}}}",
        members
            .iter()
            .map(|m| format!(
                "\"{}\":{}",
                m,
                jwk.get(*m).cloned().unwrap_or(Json::Null)
            ))
            .collect::<Vec<_>>()
            .join(",")
    );
    let digest = b64u(&sha256(canonical.as_bytes()));
    digest[..truncate.min(digest.len())].to_string()
}

/// The public JWK node's `export({ format: 'jwk' })` gives, in its member
/// order: EC coordinates at the field's full width, an Edwards key raw.
fn public_jwk_of(key: &PKey<Private>) -> Made<Json> {
    if let Ok(rsa) = key.rsa() {
        return Ok(json!({ "kty": "RSA", "n": b64u(&rsa.n().to_vec()),
                          "e": b64u(&rsa.e().to_vec()) }));
    }
    if let Ok(ec) = key.ec_key() {
        let group = ec.group();
        let (crv, width) = match group.curve_name() {
            Some(Nid::X9_62_PRIME256V1) => ("P-256", 32),
            Some(Nid::SECP384R1) => ("P-384", 48),
            Some(Nid::SECP521R1) => ("P-521", 66),
            Some(Nid::SECP256K1) => ("secp256k1", 32),
            _ => return Err("an EC key on a curve JOSE does not name".into()),
        };
        let mut x = ossl(BigNum::new())?;
        let mut y = ossl(BigNum::new())?;
        let mut ctx = ossl(BigNumContext::new())?;
        ossl(
            ec.public_key()
                .affine_coordinates(group, &mut x, &mut y, &mut ctx),
        )?;
        let pad = |n: &BigNum| ossl(n.to_vec_padded(width));
        return Ok(
            json!({ "kty": "EC", "x": b64u(&pad(&x)?), "y": b64u(&pad(&y)?), "crv": crv }),
        );
    }
    let crv = match key.id() {
        openssl::pkey::Id::ED25519 => "Ed25519",
        openssl::pkey::Id::ED448 => "Ed448",
        _ => return Err("a key of a kind JOSE does not publish".into()),
    };
    Ok(
        json!({ "crv": crv, "x": b64u(&ossl(key.raw_public_key())?), "kty": "OKP" }),
    )
}

/// `Object.assign(publicJwk, extra)`: the extra members after the key's.
fn with(mut jwk: Json, extra: Json) -> Json {
    if let (Some(base), Some(more)) = (jwk.as_object_mut(), extra.as_object()) {
        for (k, v) in more {
            base.insert(k.clone(), v.clone());
        }
    }
    jwk
}

fn pkcs8(key: &PKey<Private>) -> Made<String> {
    String::from_utf8(ossl(key.private_key_to_pem_pkcs8())?)
        .map_err(|e| e.to_string())
}

fn ec_key(nid: Nid) -> Made<PKey<Private>> {
    let group = ossl(EcGroup::from_curve_name(nid))?;
    ossl(PKey::from_ec_key(ossl(EcKey::generate(&group))?))
}

fn rsa_key(bits: u32) -> Made<PKey<Private>> {
    ossl(PKey::from_rsa(ossl(Rsa::generate(bits))?))
}

/// forge's PEM: CRLF line endings, 64 columns.
fn crlf(pem: &[u8]) -> Made<String> {
    Ok(String::from_utf8(pem.to_vec())
        .map_err(|e| e.to_string())?
        .replace("\r\n", "\n")
        .replace('\n', "\r\n"))
}

/// `selfSignedRsaCertificate()`: an RSA-2048 key and a certificate over it,
/// subject and issuer `CN=<cn>`, a 16-byte serial led by `prefix` (top bit
/// clear), five years, SHA-256, no extensions. `(privateKeyPem PKCS#1,
/// certPem, certB64)`.
fn self_signed_rsa(
    cn: &str,
    prefix: u8,
    now_ms: i64,
) -> Made<(String, String, String)> {
    let rsa = ossl(Rsa::generate(2048))?;
    let key = ossl(PKey::from_rsa(rsa.clone()))?;
    let mut serial = [0u8; 16];
    ossl(openssl::rand::rand_bytes(&mut serial[1..]))?;
    serial[0] = (prefix & 0x7f).max(1);
    let mut name = ossl(X509NameBuilder::new())?;
    ossl(name.append_entry_by_nid(Nid::COMMONNAME, cn))?;
    let name = name.build();
    let mut b = ossl(X509Builder::new())?;
    ossl(b.set_version(2))?;
    let serial = ossl(ossl(BigNum::from_slice(&serial))?.to_asn1_integer())?;
    ossl(b.set_serial_number(&serial))?;
    ossl(b.set_subject_name(&name))?;
    ossl(b.set_issuer_name(&name))?;
    ossl(b.set_pubkey(&key))?;
    let start = chrono::DateTime::from_timestamp_millis(now_ms)
        .ok_or("a time out of range")?;
    let end = start
        .checked_add_months(chrono::Months::new(60))
        .ok_or("a time out of range")?;
    let not_before =
        ossl(openssl::asn1::Asn1Time::from_unix(start.timestamp()))?;
    let not_after = ossl(openssl::asn1::Asn1Time::from_unix(end.timestamp()))?;
    ossl(b.set_not_before(&not_before))?;
    ossl(b.set_not_after(&not_after))?;
    ossl(b.sign(&key, MessageDigest::sha256()))?;
    let cert = b.build();
    let der = ossl(cert.to_der())?;
    Ok((
        crlf(&ossl(rsa.private_key_to_pem())?)?,
        crlf(&ossl(cert.to_pem())?)?,
        STANDARD.encode(der),
    ))
}

/// The curve signing keys (`CURVE_KEY_SPECS`), each `kid` naming its curve
/// and the first eight hex digits of the SHA-256 of `[crv, x, y]`.
fn curve_keys() -> Made<Vec<Json>> {
    let specs: [CurveSpec; 6] = [
        ("ES256", None, Box::new(|| ec_key(Nid::X9_62_PRIME256V1))),
        ("ES384", None, Box::new(|| ec_key(Nid::SECP384R1))),
        ("ES512", None, Box::new(|| ec_key(Nid::SECP521R1))),
        ("ES256K", None, Box::new(|| ec_key(Nid::SECP256K1))),
        ("EdDSA", None, Box::new(|| ossl(PKey::generate_ed25519()))),
        (
            "EdDSA",
            Some("Ed448"),
            Box::new(|| ossl(PKey::generate_ed448())),
        ),
    ];
    let mut out = Vec::new();
    for (alg, curve, make) in specs.iter() {
        let key = make()?;
        let jwk = public_jwk_of(&key)?;
        let material = serde_json::to_string(&json!([
            jwk["crv"],
            jwk["x"],
            jwk.get("y").cloned().unwrap_or(json!(""))
        ]))
        .map_err(|e| e.to_string())?;
        let hex: String = sha256(material.as_bytes())
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let kid = format!(
            "sts-{}-{}",
            curve.unwrap_or(alg).to_lowercase(),
            &hex[..8]
        );
        out.push(json!({
            "alg": alg,
            "privateKeyPem": pkcs8(&key)?,
            "publicJwk": with(with(json!({ "use": "sig", "alg": alg }), jwk), json!({ "kid": kid })),
        }));
    }
    Ok(out)
}

/// An encryption pair whose `kid` is `<prefix>-<kind>-<thumbprint>`.
fn enc_pair(key: PKey<Private>, kid: String, extra: Json) -> Made<Json> {
    let jwk = public_jwk_of(&key)?;
    Ok(json!({ "privateKeyPem": pkcs8(&key)?,
               "publicJwk": with(with(jwk, json!({ "kid": kid })), extra) }))
}

fn thumb_of(key: &PKey<Private>) -> Made<String> {
    Ok(jwk_thumbprint(&public_jwk_of(key)?, 16))
}

/// A new key set's blob (`makeStsKeys()` then `serialise()`), made at
/// `now_ms`.
pub fn generate_key_set(now_ms: i64) -> Result<Json, String> {
    let (private_key_pem, cert_pem, cert_b64) =
        self_signed_rsa("ws-trust-sts", 0x02, now_ms)?;
    let (xml_pem, xml_cert_pem, xml_cert_b64) =
        self_signed_rsa("ws-trust-sts-xml", 0x04, now_ms)?;

    let vci = rsa_key(2048)?;
    let vci_kid = format!("sts-req-enc-{}", thumb_of(&vci)?);
    let vci = enc_pair(
        vci,
        vci_kid,
        json!({ "alg": "RSA-OAEP-256", "use": "enc", "key_ops": ["encrypt"] }),
    )?;

    let pair = |prefix: &str| -> Made<Json> {
        let rsa = rsa_key(2048)?;
        let ec = ec_key(Nid::X9_62_PRIME256V1)?;
        let rsa_kid = format!("{}-rsa-{}", prefix, thumb_of(&rsa)?);
        let ec_kid = format!("{}-ec-{}", prefix, thumb_of(&ec)?);
        Ok(
            json!({ "rsa": enc_pair(rsa, rsa_kid, json!({ "use": "enc" }))?,
                   "ec": enc_pair(ec, ec_kid, json!({ "use": "enc" }))? }),
        )
    };
    let mut refresh = pair("sts-rt")?;
    let mut secret = [0u8; 64];
    ossl(openssl::rand::rand_bytes(&mut secret))?;
    refresh["secret"] = json!(STANDARD.encode(secret));
    refresh["secretKid"] =
        json!(format!("sts-rt-secret-{}", &b64u(&sha256(&secret))[..16]));
    let request_object = pair("sts-ro")?;

    let device = |using: &str, alg: &str| -> Made<Json> {
        let key = ec_key(Nid::X9_62_PRIME256V1)?;
        let kid = format!("sts-bd-{}-{}", using, thumb_of(&key)?);
        enc_pair(key, kid, json!({ "use": using, "alg": alg }))
    };
    let browser = json!({ "sign": device("sig", "ES256")?, "enc": device("enc", "ECDH-ES+A256KW")? });

    Ok(json!({
        "version": 1,
        "createdAt": now_ms,
        "privateKeyPem": private_key_pem,
        "certPem": cert_pem,
        "certB64": cert_b64,
        "pqKeys": [],
        "extraKeys": curve_keys()?,
        "vciRequestEncKey": vci,
        "refreshTokenEncKeys": refresh,
        "requestObjectEncKeys": request_object,
        "browserDeviceKeys": browser,
        "kemEncKeys": [],
        "xmlKey": { "privateKeyPem": xml_pem, "certPem": xml_cert_pem, "certB64": xml_cert_b64 },
        "bbsKey": null,
        "signerGroups": null,
        "generations": null,
    }))
}

/// `/oauth2/jwks` over one realm's set (`sendJwks()`), in Node's order:
///
/// * **the RSA key FIRST, and it must stay first** — everything signed by
///   default is RS256 with it, and readers take `keys[0]`; no `alg` member,
///   since the one key signs the whole RSA family, and `x5c` the chain from
///   its leaf (a self-signed leaf alone, while no hierarchy is built);
/// * then every curve key, and the post-quantum keys the set holds;
/// * the request object encryption keys LAST, `use: "enc"`.
///
/// Not here yet: the standby generations, the signer groups, the pinned
/// keys and the KEM keys, none of which a set made by this runtime holds;
/// and `keys.kidFormat: jwk-thumbprint-uri`'s second entries.
pub fn jwks_document(set: &KeySet) -> Result<Json, String> {
    let cert_b64 = set.cert_b64().ok_or("the key set holds no certificate")?;
    let der = STANDARD.decode(cert_b64).map_err(|e| e.to_string())?;
    let cert = ossl(openssl::x509::X509::from_der(&der))?;
    let public = ossl(cert.public_key())?;
    let rsa = ossl(public.rsa())?;
    let mut keys = vec![json!({
        "kty": "RSA", "use": "sig", "kid": kid_of(cert_b64),
        "n": b64u(&rsa.n().to_vec()), "e": b64u(&rsa.e().to_vec()),
        "x5c": [cert_b64],
    })];
    for member in ["extraKeys", "pqKeys"] {
        for one in set
            .blob
            .get(member)
            .and_then(Json::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(jwk) = one.get("publicJwk").filter(|j| j.is_object()) {
                keys.push(jwk.clone());
            }
        }
    }
    for kind in ["rsa", "ec"] {
        if let Some(jwk) = set
            .blob
            .pointer(&format!("/requestObjectEncKeys/{}/publicJwk", kind))
            .filter(|j| j.is_object())
        {
            keys.push(jwk.clone());
        }
    }
    Ok(json!({ "keys": keys }))
}

impl KeySet {
    /// `ownSignerFor()`: the key this realm signs its own tokens with under
    /// `alg`, and its `kid` — the RSA key for RS* and PS*, the curve key
    /// for the rest, the Edwards key on `eddsa_curve` (`oauth2.eddsaCurve`)
    /// for EdDSA. An HMAC or a post-quantum `alg` is refused: an HS*
    /// signature is made with a client's own secret, and this service signs
    /// its own tokens with a classical key.
    pub fn signer_for(
        &self,
        alg: &str,
        eddsa_curve: &str,
    ) -> Result<(sts_crypto::keys::JwsKey, String), String> {
        let refused = || {
            format!(
                "this service does not sign its own tokens with \"{}\"; it signs them with an RSA or elliptic-curve \
                 key of its own.",
                alg
            )
        };
        if alg.starts_with("HS")
            || alg.starts_with("ML-DSA")
            || alg.starts_with("SLH-DSA")
        {
            return Err(refused());
        }
        if alg.starts_with("RS") || alg.starts_with("PS") {
            let pem = self
                .private_key_pem()
                .ok_or("the key set holds no RSA signing key")?;
            let kid = self.kid().ok_or("the key set holds no certificate")?;
            let key = sts_crypto::keys::JwsKey::from_pem(pem)
                .map_err(|e| e.to_string())?;
            return Ok((key, kid));
        }
        let wanted = if eddsa_curve.is_empty() {
            "Ed25519"
        } else {
            eddsa_curve
        };
        let found = self
            .curve_keys()
            .into_iter()
            .find(|one| {
                one.alg == alg
                    && (alg != "EdDSA"
                        || one
                            .public_jwk
                            .get("crv")
                            .and_then(Json::as_str)
                            .unwrap_or("Ed25519")
                            == wanted)
            })
            .ok_or_else(|| {
                format!("this realm holds no key for \"{}\".", alg)
            })?;
        let kid = found
            .public_jwk
            .get("kid")
            .and_then(Json::as_str)
            .ok_or("a curve key with no kid")?
            .to_string();
        let key = sts_crypto::keys::JwsKey::from_pem(&found.private_key_pem)
            .map_err(|e| e.to_string())?;
        Ok((key, kid))
    }

    /// `signJwt()` over this set: the payload signed as a compact JWS under
    /// `alg`, its header naming the key's `kid`, `iat` added at `now`
    /// (seconds) unless the payload has one.
    pub fn sign_jwt(
        &self,
        payload: &serde_json::Map<String, Json>,
        alg: &str,
        eddsa_curve: &str,
        now: Option<i64>,
    ) -> Result<String, String> {
        let (key, kid) = self.signer_for(alg, eddsa_curve)?;
        sts_crypto::jws::sign_jws(
            payload,
            &key,
            &sts_crypto::jws::SignOptions {
                algorithm: Some(alg.to_string()),
                keyid: Some(kid),
                now,
                ..Default::default()
            },
        )
        .map_err(|e| e.to_string())
    }
}
