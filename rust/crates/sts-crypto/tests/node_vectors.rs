// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE RUST HALF OF THE PARITY PROOF (rust/DESIGN.md sections 6 and 10.2).
//!
//! Every vector the Node service wrote (`tests/tools/crypto-vectors.js`,
//! `*-node.json`) must verify or decrypt here — and where the scheme is
//! deterministic, Rust's signature over the same input must be the same
//! bytes. With `STS_WRITE_VECTORS=1` this also writes `*-rust.json` beside
//! them — keys Rust generated, tokens Rust signed and JWEs Rust encrypted —
//! which `tests/rust_crypto_vectors.js` checks in Node.
//!
//! The directory is `STS_CRYPTO_VECTORS`, and it is NEVER COMMITTED: the
//! vectors carry private keys, and this repository commits no key material.
//! With it unset this test says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use std::path::PathBuf;

use serde_json::{json, Map, Value as Json};
use sts_crypto::jws::{
    generate_key, sign_input, sign_jws, verify_compact, verify_input,
    SignOptions, VerifyOptions,
};
use sts_crypto::jws_alg::{id_token_half_hash, ALGS};
use sts_crypto::keys::{JwsKey, KeyPolicy};

fn vectors(name: &str) -> Option<PathBuf> {
    let dir = std::env::var("STS_CRYPTO_VECTORS").ok()?;
    Some(PathBuf::from(dir).join(name))
}

fn read(name: &str) -> Option<Vec<Json>> {
    let Some(path) = vectors(name) else {
        eprintln!("STS_CRYPTO_VECTORS is not set: {} is not checked", name);
        return None;
    };
    let text = std::fs::read_to_string(path).unwrap();
    Some(serde_json::from_str(&text).unwrap())
}

#[test]
fn every_node_jws_verifies_here() {
    let Some(rows) = read("jws-node.json") else {
        return;
    };
    assert_eq!(rows.len(), ALGS.len(), "one vector per algorithm");
    for row in &rows {
        let alg = row["alg"].as_str().unwrap();
        let key = JwsKey::from_jwk(&row["jwk"])
            .unwrap_or_else(|e| panic!("{}: the key: {}", alg, e));
        let input = row["input"].as_str().unwrap().as_bytes();
        let signature = sts_crypto::b64::decode_strict(
            row["signature"].as_str().unwrap(),
            "signature",
        )
        .unwrap();
        assert!(
            verify_input(alg, &key, input, &signature, KeyPolicy::STRICT)
                .unwrap_or_else(|e| panic!("{}: {}", alg, e)),
            "{}: Node's signature does not verify",
            alg
        );
        if row["deterministic"] == true {
            assert_eq!(
                sign_input(alg, &key, input).unwrap(),
                signature,
                "{}: a deterministic signature differs from Node's",
                alg
            );
        }
        let verified = verify_compact(
            row["token"].as_str().unwrap(),
            &key,
            &VerifyOptions {
                algorithms: &[alg],
                empty_payload: false,
                policy: KeyPolicy::STRICT,
            },
        )
        .unwrap_or_else(|e| panic!("{}: Node's token: {}", alg, e));
        assert_eq!(verified.claims.unwrap()["sub"], "alice");
        assert_eq!(verified.header["kid"], "node-1");
        assert_eq!(
            id_token_half_hash("the-access-token", alg),
            row["idTokenHalfHash"].as_str().unwrap(),
            "{}: at_hash",
            alg
        );
    }
}

#[test]
fn write_the_rust_vectors_when_asked() {
    if std::env::var("STS_WRITE_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let mut out = Vec::new();
    for row in ALGS.iter() {
        let key = generate_key(row.name).unwrap();
        let mut payload = Map::new();
        payload.insert("sub".into(), json!("alice"));
        payload.insert("iat".into(), json!(1000));
        let token = sign_jws(
            &payload,
            &key,
            &SignOptions {
                algorithm: Some(row.name.into()),
                keyid: Some("rust-1".into()),
                ..SignOptions::default()
            },
        )
        .unwrap();
        // A shared secret is never published, so its vector carries it.
        let jwk = match key.public_jwk().unwrap() {
            Some(jwk) => jwk,
            None => match &key.material {
                sts_crypto::keys::Material::Secret(secret) => json!({
                    "kty": "oct",
                    "k": sts_crypto::b64::encode(secret),
                }),
                _ => Json::Null,
            },
        };
        out.push(json!({ "alg": row.name, "jwk": jwk, "token": token }));
    }
    let Some(path) = vectors("jws-rust.json") else {
        return;
    };
    std::fs::write(path, serde_json::to_string_pretty(&out).unwrap() + "\n")
        .unwrap();
}

fn jwe_private(
    jwk: &Json,
) -> Option<openssl::pkey::PKey<openssl::pkey::Private>> {
    match JwsKey::from_jwk(jwk).ok()?.material {
        sts_crypto::keys::Material::Private(key) => Some(key),
        _ => None,
    }
}

#[test]
fn every_node_jwe_decrypts_here() {
    use sts_crypto::jwe::{decrypt_compact, DecryptOptions};
    let Some(rows) = read("jwe-node.json") else {
        return;
    };
    assert!(rows.len() >= sts_crypto::jwe::algs().len());
    for row in &rows {
        let alg = row["alg"].as_str().unwrap();
        let secret = row["secret"]
            .as_str()
            .map(|s| sts_crypto::b64::decode_loose(s).unwrap());
        let private_key = row["privateJwk"]
            .as_object()
            .and_then(|_| jwe_private(&row["privateJwk"]));
        let out = decrypt_compact(
            row["compact"].as_str().unwrap(),
            &DecryptOptions {
                private_key: private_key.as_ref(),
                private_jwk: row["privateJwk"]
                    .as_object()
                    .map(|_| &row["privateJwk"]),
                secret: secret.as_deref(),
                ..DecryptOptions::default()
            },
        )
        .unwrap_or_else(|e| panic!("{} {}: {}", alg, row["enc"], e));
        assert_eq!(out.plaintext, br#"{"sub":"alice"}"#, "{}", alg);
    }
}

#[test]
fn write_the_rust_jwe_vectors_when_asked() {
    use sts_crypto::jwe::{
        algs, encrypt_compact, generate_kem_key_pair, AlgKind, EncryptOptions,
        ENCS,
    };
    if std::env::var("STS_WRITE_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let mut cases: Vec<(String, &str)> =
        algs().into_iter().map(|a| (a.name, "A256GCM")).collect();
    for enc in ENCS {
        cases.push(("RSA-OAEP-256".into(), enc.name));
        cases.push(("dir".into(), enc.name));
    }
    let mut out = Vec::new();
    for (name, enc) in cases {
        let alg = sts_crypto::jwe::alg(&name).unwrap();
        let mut row = json!({ "alg": name, "enc": enc });
        let (public, secret): (Option<Json>, Option<Vec<u8>>) = match alg.kind {
            AlgKind::RsaOaep { .. } | AlgKind::EcdhEs(_) => {
                let private = if matches!(alg.kind, AlgKind::RsaOaep { .. }) {
                    openssl::pkey::PKey::from_rsa(
                        openssl::rsa::Rsa::generate(2048).unwrap(),
                    )
                    .unwrap()
                } else {
                    let group = openssl::ec::EcGroup::from_curve_name(
                        openssl::nid::Nid::SECP384R1,
                    )
                    .unwrap();
                    openssl::pkey::PKey::from_ec_key(
                        openssl::ec::EcKey::generate(&group).unwrap(),
                    )
                    .unwrap()
                };
                row["privatePem"] = json!(String::from_utf8(
                    private.private_key_to_pem_pkcs8().unwrap()
                )
                .unwrap());
                let key =
                    JwsKey::of(sts_crypto::keys::Material::Private(private));
                (key.public_jwk().unwrap(), None)
            }
            AlgKind::MlKem { .. } | AlgKind::Hpke { .. } => {
                let (public, private) =
                    generate_kem_key_pair(&name, Some("rust-1")).unwrap();
                row["privateJwk"] = private;
                (Some(public), None)
            }
            AlgKind::AesKw(n) | AlgKind::AesGcmKw(n) => {
                (None, Some(vec![7u8; n]))
            }
            AlgKind::Dir => (
                None,
                Some(vec![8u8; sts_crypto::jwe::enc(enc).unwrap().cek_bytes]),
            ),
            AlgKind::Pbes2 { .. } => {
                (None, Some(b"a password for PBES2".to_vec()))
            }
        };
        if let Some(secret) = &secret {
            row["secret"] = json!(sts_crypto::b64::encode(secret));
        }
        row["compact"] = json!(encrypt_compact(
            br#"{"sub":"alice"}"#,
            &EncryptOptions {
                alg: Some(&name),
                enc,
                jwk: public.as_ref(),
                secret: secret.as_deref(),
                ..EncryptOptions::default()
            },
        )
        .unwrap());
        out.push(row);
    }
    let Some(path) = vectors("jwe-rust.json") else {
        return;
    };
    std::fs::write(path, serde_json::to_string_pretty(&out).unwrap() + "\n")
        .unwrap();
}
