// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A key-encryption key that never leaves its key management service
//! (#391 P3): a DEK made here is wrapped by the handle when its row is
//! written (`wrapPending()`), under exactly `dekAad()`, and stored in the
//! handle's `$dekkms$1$` form; a second keystore over the same rows has the
//! handle unwrap each one at load and opens what the first sealed. The
//! handle here is a stand-in that records every call; the Transit handle
//! itself is proved against Node and OpenBao by `sts-core`'s
//! `secrets_openbao.rs`.

#![allow(clippy::unwrap_used)] // a test file

use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use sts_core::secrets::{kms_parts, kms_text, BoxFuture, Failure, RemoteKek};
use sts_crypto::secrets::{unwrap_dek, wrap_dek, KekInput};
use sts_store::keystore::DataKeys;
use sts_store::ldif_driver::LdifDriver;
use sts_store::Driver;

const KEK: &str = "c3RzIHJlbW90ZSBrZWsgZm9yIHRoZSB0ZXN0IG9ubHkhIQ==";

#[derive(Default)]
struct Kms {
    aads: Mutex<Vec<String>>,
}

impl RemoteKek for Kms {
    fn provider(&self) -> &str {
        "vault-transit"
    }
    fn key_ref(&self) -> &str {
        "sts-kek"
    }
    fn label(&self) -> String {
        "vault-transit:sts-kek".into()
    }
    fn wrap<'a>(
        &'a self,
        dek: &'a [u8],
        aad: &'a str,
    ) -> BoxFuture<'a, Result<String, Failure>> {
        Box::pin(async move {
            self.aads.lock().unwrap().push(format!("wrap {}", aad));
            let inner = wrap_dek(KekInput::Text(KEK), dek, aad).unwrap();
            // A Transit ciphertext carries no '$'; this stand-in's inner
            // wrap does, so it travels base64url.
            Ok(kms_text(
                "vault-transit",
                "sts-kek",
                &URL_SAFE_NO_PAD.encode(inner),
            ))
        })
    }
    fn unwrap<'a>(
        &'a self,
        text: &'a str,
        aad: &'a str,
    ) -> BoxFuture<'a, Result<Vec<u8>, Failure>> {
        Box::pin(async move {
            self.aads.lock().unwrap().push(format!("unwrap {}", aad));
            let (_, _, inner) = kms_parts(text).unwrap();
            let inner =
                String::from_utf8(URL_SAFE_NO_PAD.decode(inner).unwrap())
                    .unwrap();
            Ok(unwrap_dek(KekInput::Text(KEK), &inner, aad).unwrap())
        })
    }
    fn owns(&self, text: &str) -> bool {
        kms_parts(text).is_some()
    }
    fn is_stale(&self, _: &str) -> bool {
        false
    }
    fn rotate(&self) -> BoxFuture<'_, Result<String, Failure>> {
        Box::pin(async { Ok("2".into()) })
    }
}

#[tokio::test]
async fn deks_are_wrapped_and_unwrapped_by_the_kms() {
    let dir = std::env::temp_dir()
        .join(format!("sts-remote-kek-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let driver: Arc<dyn Driver> = Arc::new(LdifDriver::new(&dir));
    let kms = Arc::new(Kms::default());
    let first = DataKeys::durable_remote(kms.clone(), driver.clone(), None);
    assert!(first.sealed());
    let sealed = first
        .seal("held by the KMS", "minted-rows", "acme")
        .unwrap();
    first.settle().await;
    let rows = driver.load_keys().await.unwrap();
    let row = rows.iter().find(|(k, _)| k.starts_with("dek:")).unwrap();
    assert!(row.1.contains("$dekkms$1$vault-transit$"), "{}", row.1);
    let wraps: Vec<String> = kms.aads.lock().unwrap().clone();
    assert_eq!(wraps.len(), 1, "{:?}", wraps);
    assert!(wraps[0].starts_with("wrap sts dek v1|"), "{:?}", wraps);
    assert!(
        wraps[0].ends_with("|service|acme|minted-rows"),
        "{:?}",
        wraps
    );

    let again = Arc::new(Kms::default());
    let second = DataKeys::durable_remote(again.clone(), driver.clone(), None);
    second.load(true).await.unwrap();
    assert_eq!(
        second.open(&sealed, "minted-rows").as_deref(),
        Some("held by the KMS")
    );
    let unwraps = again.aads.lock().unwrap().clone();
    assert_eq!(unwraps, vec![wraps[0].replacen("wrap", "unwrap", 1)]);
    std::fs::remove_dir_all(&dir).unwrap();
}
