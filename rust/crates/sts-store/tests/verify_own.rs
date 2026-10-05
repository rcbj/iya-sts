// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `verifyOwnJws()` over a key set: a token this realm signed verifies in
//! every algorithm it signs with, and under either spelling of its `kid`; a
//! token another realm signed does not; an expired token's error is its own;
//! a retired generation verifies until its grace ends and not after; an HMAC
//! token is never one of this realm's.

#![allow(clippy::unwrap_used)] // a test file

use serde_json::{json, Map, Value as Json};
use sts_crypto::jws::{ClaimChecks, JwtError, SignOptions};
use sts_crypto::keys::KeyPolicy;
use sts_store::key_sets::{generate_key_set, jwk_thumbprint, KeySet};

const NOW_S: i64 = 1_791_000_000;
const NOW_MS: f64 = 1_791_000_000_000.0;

fn set() -> KeySet {
    KeySet {
        realm: "default".into(),
        blob: generate_key_set(NOW_S * 1000).unwrap(),
    }
}

fn payload(exp: i64) -> Map<String, Json> {
    json!({ "sub": "alice", "exp": exp })
        .as_object()
        .unwrap()
        .clone()
}

fn checks() -> ClaimChecks {
    ClaimChecks {
        now: Some(NOW_S),
        ..Default::default()
    }
}

fn verify(set: &KeySet, token: &str) -> Result<Json, JwtError> {
    set.verify_own_jws(
        token,
        None,
        &checks(),
        KeyPolicy::STRICT,
        "Ed25519",
        NOW_MS,
    )
}

#[test]
fn own_tokens_verify_and_others_do_not() {
    let a = set();
    let b = set();
    for alg in [
        "RS256", "RS512", "PS256", "ES256", "ES384", "ES512", "ES256K", "EdDSA",
    ] {
        let token = a
            .sign_jwt(&payload(NOW_S + 60), alg, "Ed25519", Some(NOW_S))
            .unwrap();
        assert_eq!(verify(&a, &token).unwrap()["sub"], "alice", "{}", alg);
        assert!(
            verify(&b, &token).is_err(),
            "{} under another realm's set",
            alg
        );
    }

    // The kid as its RFC 9278 thumbprint URI names the same key.
    let (key, _) = a.signer_for("ES256", "Ed25519").unwrap();
    let jwk = a
        .curve_keys()
        .into_iter()
        .find(|k| k.alg == "ES256")
        .unwrap()
        .public_jwk;
    let uri = format!(
        "urn:ietf:params:oauth:jwk-thumbprint:sha-256:{}",
        jwk_thumbprint(&jwk, usize::MAX)
    );
    let named = sts_crypto::jws::sign_jws(
        &payload(NOW_S + 60),
        &key,
        &SignOptions {
            algorithm: Some("ES256".into()),
            keyid: Some(uri),
            now: Some(NOW_S),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(verify(&a, &named).is_ok());

    // An expired token answers that it expired, not "invalid signature".
    let old = a
        .sign_jwt(&payload(NOW_S - 600), "RS256", "Ed25519", Some(NOW_S - 900))
        .unwrap();
    assert!(
        matches!(verify(&a, &old), Err(JwtError::Claims(_))),
        "{:?}",
        verify(&a, &old)
    );

    // An HMAC token is not one of this realm's, keyed with anything.
    let hmac = sts_crypto::jws::sign_jws(
        &payload(NOW_S + 60),
        &sts_crypto::keys::JwsKey::secret(vec![7u8; 32]),
        &SignOptions {
            algorithm: Some("HS256".into()),
            now: Some(NOW_S),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(matches!(verify(&a, &hmac), Err(JwtError::Signature(_))));
}

#[test]
fn a_retired_generation_verifies_through_its_grace() {
    let old = set();
    let mut current = set();
    let token = old
        .sign_jwt(&payload(NOW_S + 60), "RS256", "Ed25519", Some(NOW_S))
        .unwrap();
    assert!(
        verify(&current, &token).is_err(),
        "not yet a generation of it"
    );
    let cert_pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        old.cert_b64().unwrap()
    );
    let standby = |until: f64| {
        json!({ "standby": [{
            "unit": "jose:RS256", "role": "retired", "kid": old.kid(),
            "certPem": cert_pem, "retiredAt": NOW_MS - 1000.0,
            "retiredUntil": until
        }] })
    };
    current.blob["generations"] = standby(NOW_MS + 60_000.0);
    assert_eq!(verify(&current, &token).unwrap()["sub"], "alice");
    current.blob["generations"] = standby(NOW_MS - 1.0);
    assert!(verify(&current, &token).is_err(), "past its grace");
    // A TOKEN NAMING THE RETIRED KEY is tried against that key alone, so an
    // expired one says it expired — not the current key's "invalid
    // signature" — under either spelling of its kid.
    let (old_key, old_kid) = old.signer_for("RS256", "").unwrap();
    current.blob["generations"] = standby(NOW_MS + 60_000.0);
    let expired = |kid: String| {
        sts_crypto::jws::sign_jws(
            &payload(NOW_S - 600),
            &old_key,
            &SignOptions {
                algorithm: Some("RS256".into()),
                keyid: Some(kid),
                now: Some(NOW_S - 900),
                ..Default::default()
            },
        )
        .unwrap()
    };
    let x5 = openssl::x509::X509::from_pem(cert_pem.as_bytes()).unwrap();
    let rsa = x5.public_key().unwrap().rsa().unwrap();
    use base64::Engine;
    let b64u =
        |b: Vec<u8>| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    let uri = format!(
        "urn:ietf:params:oauth:jwk-thumbprint:sha-256:{}",
        jwk_thumbprint(
            &json!({ "kty": "RSA", "n": b64u(rsa.n().to_vec()), "e": b64u(rsa.e().to_vec()) }),
            usize::MAX
        )
    );
    for kid in [old_kid, uri] {
        let r = verify(&current, &expired(kid.clone()));
        assert!(matches!(r, Err(JwtError::Claims(_))), "{}: {:?}", kid, r);
    }
    // A next key verifies whatever its dates say.
    current.blob["generations"]["standby"][0]["role"] = json!("next");
    assert!(verify(&current, &token).is_ok());
    // The same, one curve unit along.
    let ec = old
        .sign_jwt(&payload(NOW_S + 60), "ES384", "Ed25519", Some(NOW_S))
        .unwrap();
    let jwk = old
        .curve_keys()
        .into_iter()
        .find(|k| k.alg == "ES384")
        .unwrap();
    let pem = String::from_utf8(
        openssl::pkey::PKey::private_key_from_pem(
            jwk.private_key_pem.as_bytes(),
        )
        .unwrap()
        .public_key_to_pem()
        .unwrap(),
    )
    .unwrap();
    current.blob["generations"] = json!({ "standby": [{
        "unit": "jose:ES384:P-384", "role": "next",
        "kid": jwk.public_jwk["kid"], "certPem": pem
    }] });
    assert!(verify(&current, &ec).is_ok());
}
