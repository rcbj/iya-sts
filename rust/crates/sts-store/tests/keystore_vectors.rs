// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The keystore's data keys against Node: `keystore-node.json`, which
//! `tests/tools/crypto-vectors.js` writes with `common/keystore.js` itself —
//! values sealed under a durable key-encryption key with the data-key rows
//! it stored, and under an ephemeral one with derived keys, and keyed
//! digests under both. Every value must open here, every digest must be
//! Node's, a derived key's id must be Node's, and a key-encryption key that
//! is not the one the rows were wrapped under must stop the start.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed (the KEK is in
//! it); with it unset this test says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_crypto::secrets::dek_id_of;
use sts_store::keystore::{dek_class, union_dek_rows, DataKeys};
use sts_store::ldif_driver::LdifDriver;
use sts_store::Driver;

fn vectors() -> Option<(PathBuf, Json)> {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: keystore-node.json is not checked"
        );
        return None;
    };
    let dir = PathBuf::from(dir);
    let text = std::fs::read_to_string(dir.join("keystore-node.json")).ok()?;
    Some((dir, serde_json::from_str(&text).unwrap()))
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sts-keystore-{}-{}",
        name,
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// An ldif store holding the rows Node wrote.
async fn store_of(v: &Json, name: &str) -> Arc<dyn Driver> {
    let driver: Arc<dyn Driver> = Arc::new(LdifDriver::new(scratch(name)));
    for row in v["durable"]["rows"].as_array().unwrap() {
        driver
            .save_keys(
                row["realm"].as_str().unwrap(),
                row["material"].as_str().unwrap(),
            )
            .await
            .unwrap();
    }
    driver
}

fn check_digests(keys: &DataKeys, list: &Json) {
    for one in list.as_array().unwrap() {
        assert_eq!(
            keys.keyed_digest(
                one["label"].as_str().unwrap(),
                one["text"].as_str().unwrap()
            )
            .as_deref(),
            one["digest"].as_str(),
            "{}",
            one
        );
    }
}

#[tokio::test]
async fn durable_keys_open_what_node_sealed() {
    let Some((dir, v)) = vectors() else {
        return;
    };
    let (kek, text) = DataKeys::read_kek_file(
        dir.join(v["kekFile"].as_str().unwrap()).to_str().unwrap(),
    )
    .unwrap();
    assert!(text);
    let driver = store_of(&v, "durable").await;
    let keys =
        DataKeys::durable(kek.clone(), true, driver.clone(), None).unwrap();
    assert!(keys.load(true).await.unwrap() > 0);
    for one in v["durable"]["sealed"].as_array().unwrap() {
        let label = one["label"].as_str().unwrap();
        let cipher = one["cipher"].as_str().unwrap();
        assert_eq!(
            keys.open(cipher, label).as_deref(),
            one["text"].as_str(),
            "{}",
            one
        );
        // Sealing again in the same realm and class uses Node's key.
        let again = keys
            .seal("again", label, one["realm"].as_str().unwrap())
            .unwrap();
        assert_eq!(dek_id_of(&again), dek_id_of(cipher));
        assert_eq!(keys.open(&again, label).as_deref(), Some("again"));
    }
    check_digests(&keys, &v["durable"]["digests"]);

    // A new class makes a key, stored before anything sealed under it is.
    let fresh = keys.seal("fresh", "brand-new", "acme").unwrap();
    keys.settle().await;
    let other = DataKeys::durable(kek, true, driver.clone(), None).unwrap();
    other.load(true).await.unwrap();
    assert_eq!(other.open(&fresh, "brand-new").as_deref(), Some("fresh"));
    let stored = driver.load_keys().await.unwrap();
    let acme = stored
        .iter()
        .find(|(k, _)| k == "dek:service:acme")
        .unwrap();
    let row: Json = serde_json::from_str(&acme.1).unwrap();
    assert!(row["deks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|d| d["cls"] == "brand-new"));
}

#[tokio::test]
async fn the_wrong_key_encryption_key_stops_the_start() {
    let Some((_, v)) = vectors() else {
        return;
    };
    let driver = store_of(&v, "wrong").await;
    let keys = DataKeys::durable(
        b"an entirely different key of 32+ bytes!!".to_vec(),
        true,
        driver,
        None,
    )
    .unwrap();
    let err = keys.load(true).await.unwrap_err();
    assert!(err.contains("STS-KEYS-0091"), "{}", err);
    assert!(err.contains("will NOT start"), "{}", err);
}

#[test]
fn ephemeral_keys_derive_what_node_derived() {
    let Some((_, v)) = vectors() else {
        return;
    };
    let keys =
        DataKeys::ephemeral(v["ephemeralKek"].as_str().unwrap()).unwrap();
    for one in v["ephemeral"]["sealed"].as_array().unwrap() {
        let label = one["label"].as_str().unwrap();
        let cipher = one["cipher"].as_str().unwrap();
        assert_eq!(keys.open(cipher, label).as_deref(), one["text"].as_str());
        let mine = keys
            .seal("x", label, one["realm"].as_str().unwrap())
            .unwrap();
        assert_eq!(dek_id_of(&mine), dek_id_of(cipher), "{}", one);
    }
    // A sibling holding the same key opens from the id alone.
    let sibling =
        DataKeys::ephemeral(v["ephemeralKek"].as_str().unwrap()).unwrap();
    let first = v["ephemeral"]["sealed"][0]["cipher"].as_str().unwrap();
    assert!(sibling.open(first, "").is_some());
    check_digests(&keys, &v["ephemeral"]["digests"]);
}

#[test]
fn no_key_seals_nothing() {
    let keys = DataKeys::none();
    assert!(!keys.sealed());
    assert_eq!(keys.seal("x", "authn-sessions", ""), None);
    assert_eq!(keys.keyed_digest("l", "x"), None);
}

#[test]
fn a_class_is_nodes() {
    assert_eq!(dek_class(""), "general");
    assert_eq!(dek_class("Odd Label!"), "odd-label");
    assert_eq!(dek_class("--a__b..c--"), "a-b..c");
    assert_eq!(dek_class(&"x".repeat(60)).len(), 48);
}

#[test]
fn the_union_keeps_both_and_one_digest_key() {
    let d = |id: &str, cls: &str, at: i64| {
        json!({ "id": id, "cls": cls, "createdAt": at, "alg": "aes-256-gcm",
                "activateAt": at, "wrappedAt": at, "status": "active", "wrapped": "w" })
    };
    let row = |deks: Vec<Json>| json!({ "v": 1, "scope": "service", "realm": "default", "deks": deks });
    let theirs = row(vec![
        d("AAAAAAAAAA", "s", 1),
        d("DIGEST0001", "keyed-digest", 1),
    ]);
    let mine = row(vec![
        d("BBBBBBBBBB", "s", 2),
        d("DIGEST0002", "keyed-digest", 0),
    ]);
    let merged = union_dek_rows(Some(&theirs), &mine).unwrap();
    let ids: Vec<&str> = merged["deks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["AAAAAAAAAA", "DIGEST0001", "BBBBBBBBBB"]);
    // Nothing new: nothing to write.
    assert!(union_dek_rows(Some(&merged), &theirs).is_none());
    // A destruction is kept, and its wrapping dropped.
    let mut gone = theirs.clone();
    gone["deks"][0]["status"] = json!("destroyed");
    let merged = union_dek_rows(Some(&theirs), &gone).unwrap();
    assert_eq!(merged["deks"][0]["status"], "destroyed");
    assert_eq!(merged["deks"][0]["wrapped"], "");
}
