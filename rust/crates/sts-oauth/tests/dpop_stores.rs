// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! RFC 9449's proof check over its real stores, with a clock the test
//! moves: a nonce asked for, issued and accepted, and refused once it has
//! aged out; a proof used once and refused the second time; the replay
//! history refusing at its bound rather than forgetting a live proof; the
//! nonce store evicting its oldest at its bound; and a remembered proof
//! forgotten once twice the skew has passed.

#![allow(clippy::unwrap_used)] // a test file

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_core::errors::codes;
use sts_core::mode::Mode;
use sts_core::realm::{RealmRegistry, SettingsEnvironment};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::StoreHandles;
use sts_core::settings::Settings;
use sts_crypto::jws::{generate_key, sign_jws, SignOptions};
use sts_crypto::keys::JwsKey;
use sts_oauth::dpop::{verify_proof, ProofContext, ProofRequest, Seen};
use sts_oauth::dpop_stores::DpopStores;

const START: i64 = 1_791_000_000;
const HTU: &str = "https://sts.example/oauth2/token";

fn stores(file: Json) -> (Arc<DpopStores>, Arc<AtomicI64>) {
    let settings = Arc::new(Settings::new(file, HashMap::new()));
    let registry = Arc::new(RealmRegistry::new(Arc::new(
        SettingsEnvironment::new(settings.clone(), Vec::new()),
    )));
    let lifecycle = RealmLifecycle::new(
        registry,
        settings.clone(),
        Arc::new(Mode::new(settings.clone())),
    );
    let now = Arc::new(AtomicI64::new(START));
    let clock = now.clone();
    let s = DpopStores::new(
        &lifecycle,
        &StoreHandles::new(),
        settings,
        Arc::new(move || clock.load(Ordering::SeqCst)),
    );
    (s, now)
}

fn proof(key: &JwsKey, jti: &str, iat: i64, nonce: Option<&str>) -> String {
    let mut claims =
        json!({ "jti": jti, "htm": "POST", "htu": HTU, "iat": iat });
    if let Some(n) = nonce {
        claims["nonce"] = json!(n);
    }
    sign_jws(
        claims.as_object().unwrap(),
        key,
        &SignOptions {
            algorithm: Some("ES256".into()),
            header: json!({ "typ": "dpop+jwt", "jwk": key.public_jwk().unwrap().unwrap() })
                .as_object()
                .unwrap()
                .clone(),
            now: Some(iat),
            ..Default::default()
        },
    )
    .unwrap()
}

fn check(
    s: &DpopStores,
    p: &str,
    now: i64,
) -> Result<(), sts_core::errors::ErrorCode> {
    verify_proof(
        Some(p),
        &ProofRequest {
            htm: "POST",
            htu: HTU,
            access_token: None,
            expected_jkt: None,
            now,
        },
        s,
    )
    .map(|_| ())
    .map_err(|f| f.code)
}

#[test]
fn nonces_issued_accepted_and_aged_out() {
    let key = generate_key("ES256").unwrap();
    let (off, _) = stores(json!({}));
    assert!(!off.nonce_mode_on());
    assert_eq!(check(&off, &proof(&key, "a", START, None), START), Ok(()));

    let (s, now) = stores(
        json!({ "oauth2": { "dpopNonceRequired": true, "dpopNonceTtlS": 60 } }),
    );
    assert_eq!(
        check(&s, &proof(&key, "b", START, None), START),
        Err(codes::STS_OAUTH_0108)
    );
    let nonce = s.issue_nonce().unwrap();
    assert_eq!(nonce.len(), 22, "16 random bytes, base64url");
    assert_eq!(
        check(&s, &proof(&key, "c", START, Some(&nonce)), START),
        Ok(())
    );
    assert_eq!(
        check(&s, &proof(&key, "d", START, Some("made-up")), START),
        Err(codes::STS_OAUTH_0109)
    );
    now.store(START + 61, Ordering::SeqCst);
    assert_eq!(
        check(&s, &proof(&key, "e", START + 61, Some(&nonce)), START + 61),
        Err(codes::STS_OAUTH_0109)
    );
}

#[test]
fn a_proof_is_good_once_and_the_history_refuses_when_full() {
    let key = generate_key("ES256").unwrap();
    let (s, now) = stores(
        json!({ "oauth2": { "dpopReplayCacheSize": 2, "dpopIatSkewS": 30 } }),
    );
    let once = proof(&key, "j1", START, None);
    assert_eq!(check(&s, &once, START), Ok(()));
    assert_eq!(check(&s, &once, START), Err(codes::STS_OAUTH_0110));
    assert_eq!(check(&s, &proof(&key, "j2", START, None), START), Ok(()));
    assert_eq!(
        check(&s, &proof(&key, "j3", START, None), START),
        Err(codes::STS_OAUTH_0554)
    );
    assert!(
        s.seen("j3") == Seen::No,
        "a refused proof is not remembered"
    );
    // Twice the skew later the history has forgotten them, and has room.
    now.store(START + 61, Ordering::SeqCst);
    assert_eq!(s.seen("j1"), Seen::No);
    assert_eq!(
        check(&s, &proof(&key, "j4", START + 61, None), START + 61),
        Ok(())
    );
}

#[test]
fn the_nonce_store_evicts_its_oldest() {
    let (s, now) = stores(
        json!({ "oauth2": { "dpopNonceCacheSize": 2, "dpopNonceRequired": true } }),
    );
    let first = s.issue_nonce().unwrap();
    now.store(START + 1, Ordering::SeqCst);
    let second = s.issue_nonce().unwrap();
    now.store(START + 2, Ordering::SeqCst);
    let third = s.issue_nonce().unwrap();
    assert!(!s.nonce_is_current(&json!(first)));
    assert!(
        s.nonce_is_current(&json!(second)) && s.nonce_is_current(&json!(third))
    );
    assert_eq!(s.sizes().0, 2);
    assert!(!s.nonce_is_current(&json!("")) && !s.nonce_is_current(&json!(7)));
}
