// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Develop's #1789, the cloud answer checks, against Node: `kms-node.json`'s
//! `azure` section, which `tests/tools/kms-vectors.js` records by driving
//! `common/secrets.js` through fake SDKs (`tests/kms_kek.js` section L's
//! way). For each Key Vault modulus Node read, the bits it reported (its
//! handle's label, its probe) and its STS-KEYS-0102 sentence are what
//! [`rsa_modulus_bits`] and [`azure_key_refusal`] give; for each key
//! version, its STS-KEYS-0198 sentence is [`azure_version_refusal`]'s; and
//! each empty answer Node refused is refused here with the same code and
//! sentence (read from the provider's source, since an SDK call is needed
//! to reach it). With `STS_WRITE_VECTORS=1` the answers go to
//! `kms-rust.json`, which Node compares. `STS_CRYPTO_VECTORS` names the
//! directory, never committed; unset, this says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value as Json};
use sts_core::errors::codes;
use sts_core::log::tag;
use sts_core::secrets::{
    azure_key_refusal, azure_version_refusal, rsa_modulus_bits,
};

/// A refusal of the key-encryption key's read as `read()` words it
/// (`tagReadFailure()`): STS-KEYS-0043, the refusal's own code, its text.
fn as_read(code: &str, why: &str) -> String {
    format!("{}{}{}", tag(codes::STS_KEYS_0043), tag(code), why)
}

/// The refusal's own text, a read's two tags taken off.
fn untagged(message: &str) -> &str {
    let mut rest = message;
    while let Some(after) = rest.strip_prefix('[') {
        match after.find("] ") {
            Some(end) => rest = &after[end + 2..],
            None => break,
        }
    }
    rest
}

#[test]
fn the_answer_checks_are_nodes() {
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
    let azure = &v["azure"];
    let vault = azure["vault"].as_str().unwrap();
    let key = azure["key"].as_str().unwrap();
    let ops = ["wrapKey".to_string(), "unwrapKey".to_string()];
    let mut moduli = Vec::new();
    for one in azure["moduli"].as_array().unwrap() {
        let n = one["n"]
            .as_str()
            .map(|t| URL_SAFE_NO_PAD.decode(t).unwrap())
            .unwrap_or_default();
        let bits = rsa_modulus_bits(&n);
        let message =
            azure_key_refusal(key, vault, "RSA", Some(true), &ops, bits)
                .map(|why| as_read(codes::STS_KEYS_0102.as_ref(), &why))
                .unwrap_or_default();
        let name = one["name"].as_str().unwrap();
        assert_eq!(message, one["message"].as_str().unwrap(), "{}", name);
        if let Some(label) = one["label"].as_str() {
            assert!(
                label.ends_with(&format!(" {})", bits)),
                "{}: Node's label {} against {} bits",
                name,
                label,
                bits
            );
        }
        if let Some(probe) = one["probeBits"].as_u64() {
            assert_eq!(probe as usize, bits, "{}: the probe", name);
        } else {
            assert_eq!(bits, 0, "{}: Node's probe reported none", name);
        }
        moduli.push(json!({ "name": name, "bits": bits, "message": message }));
    }
    let mut versions = Vec::new();
    for one in azure["versions"].as_array().unwrap() {
        let version = one["version"].as_str().unwrap_or("");
        let code: &str = codes::STS_KEYS_0198.as_ref();
        let (code, message) = match azure_version_refusal(key, vault, version) {
            Some(why) => (code, as_read(code, &why)),
            None => ("", String::new()),
        };
        assert_eq!(code, one["code"], "{:?}", version);
        assert_eq!(message, one["message"], "{:?}", version);
        versions.push(json!({ "code": code, "message": message }));
    }
    let src =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/secrets");
    let empties = azure["empty"].as_array().unwrap();
    assert!(empties.len() >= 10);
    for one in empties {
        let file = one["file"].as_str().unwrap();
        let code = one["code"].as_str().unwrap();
        let mut message =
            untagged(one["message"].as_str().unwrap()).to_string();
        assert!(!code.is_empty(), "Node refused {:?}", one["what"]);
        // The one sentence that names what was asked: its template.
        if let (Some(a), Some(b)) = (message.find('"'), message.rfind('"')) {
            if a < b {
                message.replace_range(a + 1..b, "{}");
                message = message.replace('"', "\\\"");
            }
        }
        let source =
            std::fs::read_to_string(src.join(format!("{}.rs", file))).unwrap();
        let at =
            source.find(&format!("\"{}\"", message)).unwrap_or_else(|| {
                panic!(
                    "{}.rs does not refuse {:?} with {:?}",
                    file, one["what"], message
                )
            });
        let before = &source[at.saturating_sub(160)..at];
        assert!(
            before.contains(&format!("codes::{}", code.replace('-', "_"))),
            "{}.rs refuses {:?} without {}",
            file,
            one["what"],
            code
        );
    }
    if std::env::var("STS_WRITE_VECTORS").is_ok() {
        std::fs::write(
            std::path::Path::new(&dir).join("kms-rust.json"),
            serde_json::to_string_pretty(&json!({
                "azure": { "moduli": moduli, "versions": versions }
            }))
            .unwrap(),
        )
        .unwrap();
    }
}
