// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A private key made PKCS#8 as node makes it (`crypto.createPrivateKey()
//! .export({ type: 'pkcs8', format: 'pem' })`): `pkcs8-node.json`, written
//! by `tests/tools/crypto-vectors.js`, holds keys in PKCS#1, SEC1 and
//! PKCS#8 with node's export of each, generated per run. The directory is
//! `STS_CRYPTO_VECTORS`, never committed; with it unset this says so and
//! passes.

#![allow(clippy::unwrap_used)] // a test file

use serde_json::Value as Json;
use sts_crypto::keys::private_key_pem_to_pkcs8;

#[test]
fn every_key_exports_as_node_exports_it() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: pkcs8-node.json is not checked"
        );
        return;
    };
    let path = std::path::Path::new(&dir).join("pkcs8-node.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        eprintln!("no {}: run tests/tools/crypto-vectors.js", path.display());
        return;
    };
    let v: Json = serde_json::from_str(&text).unwrap();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 4);
    for one in cases {
        let got =
            private_key_pem_to_pkcs8(one["input"].as_str().unwrap().as_bytes());
        match one["pkcs8"].as_str() {
            Some(want) => assert_eq!(
                String::from_utf8(got.unwrap()).unwrap(),
                want,
                "{}",
                one["name"]
            ),
            None => assert!(got.is_err(), "{} should be refused", one["name"]),
        }
    }
}
