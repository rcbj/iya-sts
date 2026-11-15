// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The PKCS#12 an Azure client certificate in PEM is handed to
//! `azure_identity` as ([`sts_crypto::keys::pkcs12_of_pem`]), against what
//! Node's `@azure/identity` reads out of the same PEM: `kms-node.json`'s
//! `pkcs12` cases, written by `tests/tools/kms-vectors.js` through
//! `tests/tools/crypto-vectors.js` — the first certificate, the rest as its
//! chain in order, and the key's public half. Each PKCS#12 is opened again
//! here with its password and compared; with `STS_WRITE_VECTORS=1` they are
//! written to `kms-pkcs12-rust.json`, which Node opens. The directory is
//! `STS_CRYPTO_VECTORS`, never committed; unset, this says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value as Json};
use sts_crypto::keys::pkcs12_of_pem;

#[test]
fn every_pem_becomes_the_pkcs12_node_reads_it_as() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: kms-node.json is not checked"
        );
        return;
    };
    let path = std::path::Path::new(&dir).join("kms-node.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        eprintln!("no {}: run tests/tools/crypto-vectors.js", path.display());
        return;
    };
    let v: Json = serde_json::from_str(&text).unwrap();
    let cases = v["pkcs12"].as_array().unwrap();
    assert!(cases.len() >= 5);
    let mut out = Vec::new();
    for one in cases {
        let name = one["name"].as_str().unwrap();
        let pem = one["pem"].as_str().unwrap().as_bytes();
        let password = one["password"].as_str().unwrap();
        let built = pkcs12_of_pem(pem, password);
        if let Some(refusal) = one["refusal"].as_str() {
            let err = built.expect_err(name).to_string();
            assert_eq!(err, refusal, "{}", name);
            out.push(json!({ "name": name, "refusal": err }));
            continue;
        }
        let der = built.unwrap_or_else(|e| panic!("{}: {}", name, e));
        let parsed = openssl::pkcs12::Pkcs12::from_der(&der)
            .unwrap()
            .parse2(password)
            .unwrap();
        let leaf = parsed.cert.unwrap().to_der().unwrap();
        assert_eq!(STANDARD.encode(&leaf), one["leaf"], "{}: leaf", name);
        let chain: Vec<String> = parsed
            .ca
            .map(|s| {
                s.iter()
                    .map(|c| STANDARD.encode(c.to_der().unwrap()))
                    .collect()
            })
            .unwrap_or_default();
        let want: Vec<String> = one["chain"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap().to_string())
            .collect();
        assert_eq!(chain, want, "{}: chain", name);
        let spki = parsed.pkey.unwrap().public_key_to_der().unwrap();
        assert_eq!(STANDARD.encode(&spki), one["spki"], "{}: key", name);
        out.push(json!({ "name": name, "pfx": STANDARD.encode(&der) }));
    }
    if std::env::var("STS_WRITE_VECTORS").is_ok() {
        std::fs::write(
            std::path::Path::new(&dir).join("kms-pkcs12-rust.json"),
            serde_json::to_string_pretty(&json!({ "pkcs12": out })).unwrap(),
        )
        .unwrap();
    }
}
