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

#[tokio::test]
async fn key_sets_are_nodes() {
    use sts_store::key_sets::{KeySets, Saved};
    let Some((dir, v)) = vectors() else {
        return;
    };
    let Some(signing) = v["durable"].get("signing") else {
        eprintln!("keystore-node.json has no signing key set: regenerate it");
        return;
    };
    let (kek, _) = DataKeys::read_kek_file(
        dir.join(v["kekFile"].as_str().unwrap()).to_str().unwrap(),
    )
    .unwrap();
    let driver = store_of(&v, "key-sets").await;
    let keys =
        DataKeys::durable(kek.clone(), true, driver.clone(), None).unwrap();
    keys.load(true).await.unwrap();
    let sets = KeySets::new(driver.clone(), keys.clone());
    assert_eq!(sets.load().await.unwrap(), 1);
    assert_eq!(sets.realms(), vec!["default"]);
    let set = sets.open("").unwrap();
    assert_eq!(set.cert_b64(), signing["certB64"].as_str());
    assert_eq!(set.kid().as_deref(), signing["kid"].as_str(), "Node's kid");
    // The private key is the certificate's.
    use base64::Engine;
    let der = base64::engine::general_purpose::STANDARD
        .decode(set.cert_b64().unwrap())
        .unwrap();
    let cert = openssl::x509::X509::from_der(&der).unwrap();
    let private = openssl::pkey::PKey::private_key_from_pem(
        set.private_key_pem().unwrap().as_bytes(),
    )
    .unwrap();
    assert!(cert.public_key().unwrap().public_eq(&private));
    let curves = set.curve_keys();
    assert!(!curves.is_empty());
    for one in &curves {
        openssl::pkey::PKey::private_key_from_pem(
            one.private_key_pem.as_bytes(),
        )
        .unwrap_or_else(|e| panic!("{}: {}", one.alg, e));
    }

    // A save of the same generation keeps what is stored; a newer one is
    // written, and another process reads it back whole.
    let mut newer = set.blob.clone();
    newer["generations"] = json!({ "generation": set.generation() + 1 });
    let ldif_saved = sets.save("", &newer).await.unwrap();
    assert_eq!(ldif_saved, Saved::Written);
    let again = KeySets::new(driver.clone(), keys.clone());
    again.load().await.unwrap();
    assert_eq!(again.open("default").unwrap().blob, newer);

    // The wrong key-encryption key stops the start, with its code.
    let wrong = DataKeys::durable(
        b"an entirely different key of 32+ bytes!!".to_vec(),
        true,
        driver.clone(),
        None,
    )
    .unwrap();
    let refused = KeySets::new(driver, wrong).load().await.unwrap_err();
    assert!(refused.contains("STS-KEYS-0029"), "{}", refused);
}

#[test]
fn the_thumbprint_is_rfc_7638s() {
    // RFC 7638 section 3.1's example key and thumbprint.
    let jwk = json!({ "kty": "RSA", "e": "AQAB", "alg": "RS256", "kid": "2011-04-29",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw" });
    assert_eq!(
        sts_store::key_sets::jwk_thumbprint(&jwk, 64),
        "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    );
}

#[tokio::test]
async fn a_made_key_set_is_whole() {
    use sts_store::key_sets::{generate_key_set, kid_of, KeySet, KeySets};
    let blob = generate_key_set(1_791_000_000_000).unwrap();
    let set = KeySet {
        realm: "default".into(),
        blob: blob.clone(),
    };
    assert_eq!(set.kid(), Some(kid_of(set.cert_b64().unwrap())));
    use base64::Engine;
    let cert = openssl::x509::X509::from_der(
        &base64::engine::general_purpose::STANDARD
            .decode(set.cert_b64().unwrap())
            .unwrap(),
    )
    .unwrap();
    let key = openssl::pkey::PKey::private_key_from_pem(
        set.private_key_pem().unwrap().as_bytes(),
    )
    .unwrap();
    assert!(cert.public_key().unwrap().public_eq(&key));
    assert!(set
        .private_key_pem()
        .unwrap()
        .starts_with("-----BEGIN RSA PRIVATE KEY-----\r\n"));
    let cn = cert
        .subject_name()
        .entries()
        .next()
        .unwrap()
        .data()
        .to_string()
        .unwrap()
        .to_string();
    assert_eq!(cn, "ws-trust-sts");
    assert_eq!(cert.serial_number().to_bn().unwrap().to_vec()[0], 0x02);
    let curves = set.curve_keys();
    let kids: Vec<String> = curves
        .iter()
        .map(|c| c.public_jwk["kid"].as_str().unwrap()[..8].to_string())
        .collect();
    assert_eq!(
        kids,
        [
            "sts-es25", "sts-es38", "sts-es51", "sts-es25", "sts-edds",
            "sts-ed44"
        ]
    );
    for c in &curves {
        openssl::pkey::PKey::private_key_from_pem(c.private_key_pem.as_bytes())
            .unwrap();
    }
    assert!(blob["refreshTokenEncKeys"]["secretKid"]
        .as_str()
        .unwrap()
        .starts_with("sts-rt-secret-"));
    assert!(blob["vciRequestEncKey"]["publicJwk"]["kid"]
        .as_str()
        .unwrap()
        .starts_with("sts-req-enc-"));

    // Written for Node to read, where asked: the vectors' KEK, an ldif store.
    let Ok(out) = std::env::var("STS_KEYSET_OUT") else {
        return;
    };
    let Some((dir, v)) = vectors() else {
        return;
    };
    let (kek, _) = DataKeys::read_kek_file(
        dir.join(v["kekFile"].as_str().unwrap()).to_str().unwrap(),
    )
    .unwrap();
    let driver: Arc<dyn Driver> =
        Arc::new(LdifDriver::new(PathBuf::from(&out)));
    let keys = DataKeys::durable(kek, true, driver.clone(), None).unwrap();
    keys.ensure_digest_key().await;
    let sets = KeySets::new(driver, keys);
    sets.save("", &blob).await.unwrap();
    std::fs::write(
        PathBuf::from(&out).join("expected.json"),
        json!({ "kid": set.kid(), "curveKids": curves.iter().map(|c| c.public_jwk["kid"].clone()).collect::<Vec<_>>(),
                "vciKid": blob["vciRequestEncKey"]["publicJwk"]["kid"] }).to_string(),
    )
    .unwrap();
}
