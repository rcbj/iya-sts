// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The key-encryption key against Node and a running OpenBao (or Vault):
//! `tests/tools/secrets-interop.js` reads the KV key and wraps data keys
//! through `common/secrets.js`'s Transit handle (`secrets-node.json`); this
//! reads the same KV key through `sts_core::secrets`, unwraps every data
//! key Node wrapped, refuses one under a changed AAD, and wraps its own
//! (`secrets-rust.json`) for the tool's second run to unwrap.
//!
//! Skipped unless `STS_SECRETS_VECTORS` and `STS_KEYS_KEK_VAULT` are set;
//! the store is reached as the service reaches it, by the variables the
//! settings read (`STS_KEYS_VAULT_CLIENT_CERT`, `…_KEY`, `…_CA_CERT`).

#![allow(clippy::unwrap_used)] // a test file

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_core::secrets::{KeyNormalizer, Secret, Secrets, KEK};
use sts_core::settings::Settings;

/// The slot the composition root fills from sts-crypto, filled here from
/// openssl as a test's dev-dependency.
struct Pkcs8;

impl KeyNormalizer for Pkcs8 {
    fn pkcs8_pem(&self, key_pem: &[u8]) -> Result<Vec<u8>, String> {
        openssl::pkey::PKey::private_key_from_pem(key_pem)
            .and_then(|k| k.private_key_to_pem_pkcs8())
            .map_err(|e| e.to_string())
    }
}

fn secrets(env: &HashMap<String, String>, extra: &[(&str, &str)]) -> Secrets {
    let mut env = env.clone();
    for (k, v) in extra {
        env.insert(k.to_string(), v.to_string());
    }
    let s = Secrets::new(Arc::new(Settings::new(Json::Null, env.clone())), env);
    s.set_key_normalizer(Arc::new(Pkcs8));
    s
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[tokio::test]
async fn transit_and_kv_as_node_reads_and_wraps_them() {
    let (Ok(dir), Ok(_)) = (
        std::env::var("STS_SECRETS_VECTORS"),
        std::env::var("STS_KEYS_KEK_VAULT"),
    ) else {
        eprintln!("STS_SECRETS_VECTORS or STS_KEYS_KEK_VAULT unset: skipped");
        return;
    };
    let dir = std::path::Path::new(&dir);
    let node: Json = serde_json::from_str(
        &std::fs::read_to_string(dir.join("secrets-node.json")).unwrap(),
    )
    .unwrap();
    let env: HashMap<String, String> = std::env::vars()
        .filter(|(k, _)| k.starts_with("STS_KEYS_") || k.starts_with("VAULT_"))
        .collect();

    let kv = secrets(
        &env,
        &[
            ("STS_KEYS_KEK_PROVIDER", "vault"),
            ("STS_KEYS_KEK_REF", "secret/data/sts"),
            ("STS_KEYS_KEK_FIELD", "kek"),
        ],
    );
    match kv.read(&KEK).await.unwrap() {
        Secret::Value { bytes, text } => {
            assert!(text);
            assert_eq!(String::from_utf8(bytes).unwrap(), node["kv"]);
        }
        other => panic!("{:?}", other),
    }
    assert_eq!(kv.ledger()["kek"]["ok"], json!(true));

    let transit = secrets(
        &env,
        &[
            ("STS_KEYS_KEK_PROVIDER", "vault-transit"),
            ("STS_KEYS_KEK_REF", node["transitKey"].as_str().unwrap()),
        ],
    );
    let Secret::Remote(handle) = transit.read(&KEK).await.unwrap() else {
        panic!("vault-transit answered no handle");
    };
    let mut ours = Vec::new();
    let wrapped = node["wrapped"].as_array().unwrap();
    for one in wrapped {
        let text = one["text"].as_str().unwrap();
        let aad = one["aad"].as_str().unwrap();
        assert!(handle.owns(text), "{}", aad);
        assert_eq!(handle.is_stale(text), one["stale"].as_bool().unwrap());
        let dek = handle.unwrap(text, aad).await.unwrap();
        assert_eq!(hex(&dek), one["dek"], "{}", aad);
        let again = handle.wrap(&dek, aad).await.unwrap();
        assert!(again.starts_with("$dekkms$1$vault-transit$"));
        ours.push(json!({"dek": one["dek"], "aad": aad, "text": again}));
    }
    let first = &wrapped[0];
    let wrong = handle
        .unwrap(
            first["text"].as_str().unwrap(),
            &format!("{}x", first["aad"].as_str().unwrap()),
        )
        .await;
    assert!(wrong.is_err(), "a changed AAD was unwrapped");
    assert_eq!(node["wrongAadRefused"], json!(true));
    std::fs::write(
        dir.join("secrets-rust.json"),
        json!({"wrapped": ours}).to_string(),
    )
    .unwrap();
    eprintln!(
        "secrets: the KV key read as Node read it; {} Node-wrapped data keys \
         unwrapped and {} wrapped for Node",
        wrapped.len(),
        ours.len()
    );
}
