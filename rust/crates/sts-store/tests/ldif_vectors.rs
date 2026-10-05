// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The ldif store against Node: `ldif-node.json`, which
//! `tests/tools/crypto-vectors.js` writes with `persistence_ldif.js`'s own
//! driver. The Rust driver writes the same entries, realms and overrides
//! and every file is Node's byte for byte; Node's files read back here as
//! Node reads them; and LDIF Node did not write (folded lines, CRLF, URL
//! values, a line before any dn:) parses as it parses there.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed; with it unset
//! this test says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use std::collections::BTreeMap;

use indexmap::IndexMap;
use serde_json::{json, Value as Json};
use sts_store::ldif;
use sts_store::ldif_driver::LdifDriver;
use sts_store::{DirectoryChange, Driver, StoredEntry};

fn entry_of(v: &Json) -> StoredEntry {
    let mut attributes = IndexMap::new();
    for (name, values) in v["attributes"].as_object().unwrap() {
        attributes.insert(
            name.clone(),
            values
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect(),
        );
    }
    StoredEntry {
        dn: v["dn"].as_str().unwrap().to_string(),
        attributes,
        origin: v["origin"].as_str().map(str::to_string),
        created_at: None,
        modified_at: None,
    }
}

/// An entry as Node's JSON has it: `origin` only when there is one.
fn json_of(e: &StoredEntry) -> Json {
    let attributes: serde_json::Map<String, Json> = e
        .attributes
        .iter()
        .map(|(k, v)| (k.clone(), json!(v)))
        .collect();
    let mut out = json!({ "dn": e.dn, "attributes": attributes, "createdAt": e.created_at,
                          "modifiedAt": e.modified_at });
    if let Some(o) = &e.origin {
        out["origin"] = json!(o);
    }
    out
}

#[tokio::test]
async fn the_ldif_store_is_nodes() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: ldif-node.json is not checked"
        );
        return;
    };
    let v: Json = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(&dir).join("ldif-node.json"),
        )
        .unwrap(),
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

    let entries: Vec<StoredEntry> = v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(entry_of)
        .collect();
    let out =
        std::env::temp_dir().join(format!("sts-ldif-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    let driver = LdifDriver::new(&out);
    driver.open().await.unwrap();
    let mut all = BTreeMap::new();
    all.insert("default".to_string(), entries.clone());
    all.insert("acme".to_string(), entries[1..].to_vec());
    let change = DirectoryChange {
        touched: vec!["default".to_string(), "acme".to_string()],
        all,
        ..DirectoryChange::default()
    };
    driver.save_directory(&change).await.unwrap();
    driver
        .save_realms(&[
            json!({ "id": "acme", "name": "Acme", "domain": "a.example",
                               "overrides": { "x.y": 3, "z": "é" } }),
        ])
        .await
        .unwrap();
    driver
        .save_overrides(
            json!({ "global.logLevel": "debug", "n": 0.5 })
                .as_object()
                .unwrap(),
        )
        .await
        .unwrap();
    for (name, text) in v["files"].as_object().unwrap() {
        let mine = std::fs::read_to_string(out.join(name)).unwrap_or_default();
        check(
            mine == text.as_str().unwrap(),
            format!("{}:\n--- rust\n{}\n--- node\n{}", name, mine, text),
        );
    }

    // Node's files, read here.
    for (name, text) in v["files"].as_object().unwrap() {
        std::fs::write(out.join(name), text.as_str().unwrap()).unwrap();
    }
    let reread = driver.load_directory().await.unwrap().unwrap();
    for (realm, rows) in v["reread"].as_object().unwrap() {
        let mine: Vec<Json> = reread
            .get(realm)
            .map(|r| r.iter().map(json_of).collect())
            .unwrap_or_default();
        check(
            json!(mine) == *rows,
            format!("reread {}:\n{}\n{}", realm, json!(mine), rows),
        );
    }
    check(
        driver.load_realms().await.unwrap().map(Json::from)
            == Some(json!([{ "id": "acme", "name": "Acme",
            "domain": "a.example", "overrides": { "x.y": 3, "z": "é" } }])),
        "realms.json read back".to_string(),
    );
    let _ = std::fs::remove_dir_all(&out);

    for (text, node) in v["foreign"]
        .as_array()
        .unwrap()
        .iter()
        .zip(v["parsed"].as_array().unwrap())
    {
        let mine: Vec<Json> = ldif::from_ldif(text.as_str().unwrap())
            .iter()
            .map(json_of)
            .collect();
        check(
            json!(mine) == *node,
            format!("fromLdif:\n{}\n{}", json!(mine), node),
        );
    }

    assert!(
        failures.is_empty(),
        "{} differences:\n{}",
        failures.len(),
        failures.join("\n")
    );
    eprintln!("{} answers as Node gives them", checked);
}
