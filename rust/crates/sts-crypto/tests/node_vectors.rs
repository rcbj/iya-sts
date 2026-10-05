// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE RUST HALF OF THE PARITY PROOF (rust/DESIGN.md sections 6 and 10.2).
//!
//! Every vector the Node service wrote (`tests/tools/crypto-vectors.js`,
//! `vectors/*-node.json`) must verify here — and where the scheme is
//! deterministic, Rust's signature over the same input must be the same
//! bytes. With `STS_WRITE_VECTORS=1` this also writes `vectors/*-rust.json`:
//! a key Rust generated and a token Rust signed, per algorithm, which
//! `tests/rust_crypto_vectors.js` verifies in Node. Both files are
//! committed, so neither proof needs the other runtime.

use std::path::PathBuf;

use serde_json::{json, Map, Value as Json};
use sts_crypto::jws::{
    generate_key, sign_input, sign_jws, verify_compact, verify_input,
    SignOptions, VerifyOptions,
};
use sts_crypto::jws_alg::{id_token_half_hash, ALGS};
use sts_crypto::keys::{JwsKey, KeyPolicy};

fn vectors(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("vectors")
        .join(name)
}

#[test]
fn every_node_jws_verifies_here() {
    let text = std::fs::read_to_string(vectors("jws-node.json")).unwrap();
    let rows: Vec<Json> = serde_json::from_str(&text).unwrap();
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
    std::fs::write(
        vectors("jws-rust.json"),
        serde_json::to_string_pretty(&out).unwrap() + "\n",
    )
    .unwrap();
}
