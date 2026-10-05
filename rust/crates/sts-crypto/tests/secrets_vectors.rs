// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The secrets against Node, both ways: `secrets-node.json`, which
//! `tests/tools/crypto-vectors.js` writes, and — with `STS_WRITE_VECTORS`
//! — `secrets-rust.json`, which `tests/rust_crypto_vectors.js` checks in
//! Node. HOTP codes, the derived data keys and ids, the key-encryption
//! key's reading and the shared credentials must be the same bytes; scrypt
//! hashes, envelopes and wrapped keys are random, so each side opens the
//! other's.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed; with it unset
//! this test says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value as Json};
use sts_crypto::secrets::{self, KekInput, ScryptCost};

fn s(v: &Json) -> &str {
    v.as_str().unwrap()
}

fn b64(v: &Json) -> Vec<u8> {
    STANDARD.decode(s(v)).unwrap()
}

#[test]
fn secrets_match_node() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: secrets-node.json is not checked"
        );
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let v: Json = serde_json::from_str(
        &std::fs::read_to_string(dir.join("secrets-node.json")).unwrap(),
    )
    .unwrap();
    let mut failures = Vec::new();
    let mut checked = 0;
    let mut check = |ok: bool, what: String| {
        checked += 1;
        if !ok {
            failures.push(what);
        }
    };

    for h in v["hotp"].as_array().unwrap() {
        let code = secrets::hotp_code(
            &b64(&h["key"]),
            h["counter"].as_u64().unwrap(),
            Some(h["digits"].as_u64().unwrap() as u32),
            Some(s(&h["algorithm"])),
        )
        .unwrap();
        check(code == s(&h["code"]), format!("hotp {}", h));
    }
    let mut hashes = Vec::new();
    for h in v["hashes"].as_array().unwrap() {
        let plain = s(&h["plain"]);
        check(
            secrets::verify_secret(plain, s(&h["stored"])),
            format!("Node's hash of {:?}", plain),
        );
        check(
            !secrets::verify_secret(&format!("{}x", plain), s(&h["stored"])),
            format!("a wrong secret against {:?}", plain),
        );
        let ours = secrets::hash_secret(plain, ScryptCost::default()).unwrap();
        hashes.push(json!({ "plain": plain, "stored": ours }));
    }
    let mut envelopes = Vec::new();
    for e in v["envelopes"].as_array().unwrap() {
        let key = b64(&e["key"]);
        let opened =
            secrets::decrypt_with_dek(&key, s(&e["sealed"]), Some("vectors"));
        check(
            opened.as_deref().ok() == Some(s(&e["plain"])),
            format!("Node's {} envelope", s(&e["alg"])),
        );
        check(
            secrets::dek_id_of(s(&e["sealed"])) == Some(s(&e["id"])),
            format!("the {} envelope's id", s(&e["alg"])),
        );
        let ours = secrets::encrypt_with_dek(
            s(&e["id"]),
            &key,
            s(&e["plain"]),
            Some("vectors"),
        )
        .unwrap();
        envelopes.push(json!({ "alg": e["alg"], "key": e["key"], "plain": e["plain"], "sealed": ours }));
    }
    let mut wraps = Vec::new();
    for w in v["wraps"].as_array().unwrap() {
        let kek = s(&w["kek"]);
        let dek = secrets::unwrap_dek(
            KekInput::Text(kek),
            s(&w["wrapped"]),
            s(&w["aad"]),
        );
        check(
            dek.as_deref().ok() == Some(&b64(&w["dek"])[..]),
            format!("Node's wrap under {:?}", kek),
        );
        let ours = secrets::wrap_dek(
            KekInput::Text(kek),
            &b64(&w["dek"]),
            s(&w["aad"]),
        )
        .unwrap();
        wraps.push(json!({ "kek": kek, "aad": w["aad"], "dek": w["dek"], "wrapped": ours }));
    }
    for d in v["derived"].as_array().unwrap() {
        let kek = s(&d["kek"]);
        let bytes = secrets::kek_bytes(KekInput::Text(kek)).unwrap();
        check(bytes == b64(&d["kekBytes"]), format!("kekBytes({:?})", kek));
        let (id, key) =
            secrets::derive_dek(KekInput::Text(kek), s(&d["context"])).unwrap();
        check(
            id == s(&d["id"]) && key == b64(&d["key"]),
            format!("deriveDek under {:?}", kek),
        );
    }
    for r in v["kekRefusals"].as_array().unwrap() {
        let refused = secrets::kek_bytes(KekInput::Text(s(&r["kek"]))).is_err();
        check(
            refused == r["refused"].as_bool().unwrap(),
            format!("kekBytes refusal {}", r),
        );
    }
    for c in v["credentials"].as_array().unwrap() {
        let parts: Vec<&str> =
            c["parts"].as_array().unwrap().iter().map(s).collect();
        let ours = secrets::derive_shared_credential(
            s(&c["secret"]),
            s(&c["label"]),
            &parts,
        )
        .unwrap();
        check(
            ours == s(&c["credential"]),
            format!("deriveSharedCredential {}", c),
        );
    }

    if std::env::var("STS_WRITE_VECTORS").is_ok() {
        std::fs::write(
            dir.join("secrets-rust.json"),
            serde_json::to_string_pretty(&json!({
                "hashes": hashes, "envelopes": envelopes, "wraps": wraps,
            }))
            .unwrap(),
        )
        .unwrap();
    }
    assert!(
        failures.is_empty(),
        "{} differences:\n{}",
        failures.len(),
        failures.join("\n")
    );
    eprintln!("{} checks as Node computes them", checked);
}
