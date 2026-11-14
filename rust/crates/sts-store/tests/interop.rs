// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The store's two-way proof against Node (#444 phase 2b; rcbj, 2026-11-14:
//! the Rust runtime upgrades a 1.x install IN PLACE). Node's half is
//! `tests/tools/store-interop.js`; both run against one real PostgreSQL with
//! `postgres/schema.sql` applied (`STS_TEST_DATABASE_URL`), sharing one
//! durable key-encryption key in `STS_INTEROP_DIR`, which is never
//! committed. In order:
//!
//! 1. `store-interop.js write` — Node writes the store;
//! 2. this test, [`rust_reads_what_node_wrote`] — every entry opens and
//!    reads back as Node wrote it, every lookup column and `dek_keys` Node
//!    stored is what this codec computes, and the realms, the overrides,
//!    the sealed values, the keyed digests and the signing key set are
//!    Node's;
//! 3. this test again with `STS_INTEROP_WRITE=1`,
//!    [`rust_writes_for_node`] — the store cleared and written by this
//!    runtime, and what it wrote recorded in `interop-rust.json`;
//! 4. `store-interop.js read` — Node reads it and checks the same things
//!    the other way round.
//!
//! With either variable unset, or no `interop-node.json`, it says so and
//! passes.

#![allow(clippy::unwrap_used)] // a test file

use std::path::PathBuf;
use std::sync::Arc;

use indexmap::IndexMap;
use serde_json::{json, Map, Value as Json};
use sts_store::codec::EntryCodec;
use sts_store::key_sets::KeySets;
use sts_store::keystore::DataKeys;
use sts_store::model::{DirectoryChange, DirectoryUpsert, StoredEntry};
use sts_store::postgres::PostgresDriver;
use sts_store::Driver;

fn setting() -> Option<(String, PathBuf)> {
    let url = std::env::var("STS_TEST_DATABASE_URL").ok()?;
    let dir = std::env::var("STS_INTEROP_DIR").ok()?;
    Some((url, PathBuf::from(dir)))
}

async fn store(
    url: &str,
    dir: &std::path::Path,
) -> (Arc<PostgresDriver>, Arc<DataKeys>) {
    let driver = Arc::new(PostgresDriver::new(url, false, 4).unwrap());
    driver.open().await.unwrap();
    let (kek, text) =
        DataKeys::read_kek_file(dir.join("interop-kek.txt").to_str().unwrap())
            .unwrap();
    let as_driver: Arc<dyn Driver> = driver.clone();
    let keys = DataKeys::durable(kek, text, as_driver, None).unwrap();
    keys.load(true).await.unwrap();
    keys.ensure_digest_key().await;
    driver.adopt_data_keys(&keys);
    (driver, keys)
}

async fn query(url: &str, sql: &str) -> Vec<tokio_postgres::Row> {
    let mut tls =
        openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())
            .unwrap();
    tls.set_verify(openssl::ssl::SslVerifyMode::NONE);
    let mut connector = postgres_openssl::MakeTlsConnector::new(tls.build());
    connector.set_callback(|c, _| {
        c.set_verify_hostname(false);
        Ok(())
    });
    let (client, conn) = tokio_postgres::connect(url, connector).await.unwrap();
    tokio::spawn(conn);
    client.query(sql, &[]).await.unwrap()
}

/// The stored rows' raw columns, as `store-interop.js`'s `columnsOf()`.
async fn columns(url: &str) -> Vec<Json> {
    query(
        url,
        "SELECT realm, dn_key, dn, attrs, origin, created_at, modified_at, name_keys, mail_keys, uuid_keys, \
         class_keys, value_keys, attr_names, dek_keys FROM sts_ldap_entries ORDER BY realm, dn_key",
    )
    .await
    .iter()
    .map(|r| {
        let attrs: Json = r.get("attrs");
        json!({ "realm": r.get::<_, String>("realm"), "key": r.get::<_, String>("dn_key"),
                "dn": r.get::<_, String>("dn"), "origin": r.get::<_, Option<String>>("origin"),
                "createdAt": r.get::<_, Option<String>>("created_at"),
                "modifiedAt": r.get::<_, Option<String>>("modified_at"),
                "sealed": attrs.is_string(), "attrs": attrs,
                "nameKeys": r.get::<_, Json>("name_keys"), "mailKeys": r.get::<_, Json>("mail_keys"),
                "uuidKeys": r.get::<_, Json>("uuid_keys"), "classKeys": r.get::<_, Json>("class_keys"),
                "valueKeys": r.get::<_, Json>("value_keys"), "attrNames": r.get::<_, Json>("attr_names"),
                "dekKeys": r.get::<_, Option<Json>>("dek_keys") })
    })
    .collect()
}

fn attributes(v: &Json) -> IndexMap<String, Vec<String>> {
    v.as_object()
        .unwrap()
        .iter()
        .map(|(k, x)| {
            (
                k.clone(),
                x.as_array()
                    .unwrap()
                    .iter()
                    .map(|s| s.as_str().unwrap().to_string())
                    .collect(),
            )
        })
        .collect()
}

/// Key order aside, as jsonb keeps it.
fn canonical(v: &Json) -> String {
    match v {
        Json::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            format!(
                "{{{}}}",
                keys.iter()
                    .map(|k| format!("{}:{}", json!(k), canonical(&m[*k])))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
        Json::Array(a) => {
            format!(
                "[{}]",
                a.iter().map(canonical).collect::<Vec<_>>().join(",")
            )
        }
        other => other.to_string(),
    }
}

/// Every lookup column this codec computes for a stored row, against what
/// is stored.
fn index_differences(codec: &EntryCodec, row: &Json, out: &mut Vec<String>) {
    let key = row["key"].as_str().unwrap();
    let Some(attrs) = codec.open_attributes(key, &row["attrs"]) else {
        out.push(format!("{} does not open here", key));
        return;
    };
    let index = codec.index_of(&attrs);
    let mine = json!({ "nameKeys": index.name_keys, "mailKeys": index.mail_keys,
                       "uuidKeys": index.uuid_keys, "classKeys": index.class_keys,
                       "valueKeys": index.value_keys, "attrNames": index.attr_names,
                       "dekKeys": EntryCodec::dek_keys_of(&attrs, &row["attrs"]) });
    for (k, v) in mine.as_object().unwrap() {
        if *v != row[k] {
            out.push(format!(
                "{} {}: stored {} computed {}",
                key, k, row[k], v
            ));
        }
    }
}

#[tokio::test]
async fn rust_reads_what_node_wrote() {
    let Some((url, dir)) = setting() else {
        eprintln!("STS_TEST_DATABASE_URL or STS_INTEROP_DIR is not set: the store is not checked against Node");
        return;
    };
    if std::env::var("STS_INTEROP_WRITE").is_ok() {
        return;
    }
    let Ok(text) = std::fs::read_to_string(dir.join("interop-node.json"))
    else {
        eprintln!("no interop-node.json: run tests/tools/store-interop.js write first");
        return;
    };
    let v: Json = serde_json::from_str(&text).unwrap();
    let (driver, keys) = store(&url, &dir).await;
    let codec = EntryCodec::new(keys.clone());
    assert!(codec.sealing(), "a durable key seals");
    let mut failures = Vec::new();

    // The entries, opened.
    let directory = driver.load_directory().await.unwrap().unwrap();
    for one in v["entries"].as_array().unwrap() {
        let realm = one["realm"].as_str().unwrap();
        let entry = &one["entry"];
        let got = directory.get(realm).and_then(|list| {
            list.iter().find(|e| e.dn == entry["dn"].as_str().unwrap())
        });
        match got {
            None => failures
                .push(format!("{} in {} is not read back", entry["dn"], realm)),
            Some(got) => {
                if got.attributes != attributes(&entry["attributes"]) {
                    failures.push(format!(
                        "{} attributes: {:?}",
                        entry["dn"], got.attributes
                    ));
                }
                if got.origin.as_deref() != entry["origin"].as_str() {
                    failures.push(format!(
                        "{} origin: {:?}",
                        entry["dn"], got.origin
                    ));
                }
                let created = entry["createdAt"].as_str();
                let modified = entry["modifiedAt"].as_str().or(created);
                if got.created_at.as_deref() != created
                    || got.modified_at.as_deref() != modified
                {
                    failures.push(format!(
                        "{} timestamps: {:?} {:?}",
                        entry["dn"], got.created_at, got.modified_at
                    ));
                }
            }
        }
    }
    // The lookup columns and dek_keys Node stored are this codec's.
    let rows = columns(&url).await;
    for (row, node) in rows.iter().zip(v["columns"].as_array().unwrap()) {
        if !row["sealed"].as_bool().unwrap() {
            failures.push(format!("{} is not sealed", row["key"]));
        }
        for k in [
            "nameKeys",
            "mailKeys",
            "uuidKeys",
            "classKeys",
            "valueKeys",
            "attrNames",
            "dekKeys",
        ] {
            if row[k] != node[k] {
                failures.push(format!(
                    "{} {}: the store holds {}, Node recorded {}",
                    row["key"], k, row[k], node[k]
                ));
            }
        }
        index_differences(&codec, row, &mut failures);
    }
    // The realms and the overrides.
    let realms = driver.load_realms().await.unwrap().unwrap_or_default();
    if canonical(&json!(realms)) != canonical(&v["realms"]) {
        failures.push(format!("realms: {}", json!(realms)));
    }
    let overrides = driver.load_overrides().await.unwrap().unwrap_or_default();
    if canonical(&Json::Object(overrides.clone())) != canonical(&v["overrides"])
    {
        failures.push(format!("overrides: {:?}", overrides));
    }
    // Sealed values, digests, the signing key set.
    for one in v["sealed"].as_array().unwrap() {
        let got = keys.open(
            one["cipher"].as_str().unwrap(),
            one["label"].as_str().unwrap(),
        );
        if got.as_deref() != one["text"].as_str() {
            failures.push(format!("sealed {}: {:?}", one["label"], got));
        }
    }
    for one in v["digests"].as_array().unwrap() {
        let got = keys.keyed_digest(
            one["label"].as_str().unwrap(),
            one["text"].as_str().unwrap(),
        );
        if got.as_deref() != one["digest"].as_str() {
            failures.push(format!("digest {}: {:?}", one["label"], got));
        }
    }
    let as_driver: Arc<dyn Driver> = driver.clone();
    let sets = KeySets::new(as_driver, keys.clone());
    sets.load().await.unwrap();
    let kid = sets.open("default").and_then(|s| s.kid());
    if kid.as_deref() != v["signing"]["kid"].as_str() {
        failures.push(format!("the signing key set: {:?}", kid));
    }
    assert!(
        failures.is_empty(),
        "{} differences:\n{}",
        failures.len(),
        failures.join("\n")
    );
    eprintln!("Rust read every row Node wrote, as Node wrote it");
}

fn stored(
    dn: &str,
    attrs: &[(&str, &[&str])],
    origin: Option<&str>,
    created: Option<&str>,
) -> StoredEntry {
    StoredEntry {
        dn: dn.to_string(),
        attributes: attrs
            .iter()
            .map(|(k, vs)| {
                (k.to_string(), vs.iter().map(|s| s.to_string()).collect())
            })
            .collect(),
        origin: origin.map(str::to_string),
        created_at: created.map(str::to_string),
        modified_at: created.map(str::to_string),
    }
}

#[tokio::test]
async fn rust_writes_for_node() {
    let Some((url, dir)) = setting() else {
        return;
    };
    if std::env::var("STS_INTEROP_WRITE").is_err() {
        return;
    }
    for table in [
        "sts_ldap_entries",
        "sts_realms",
        "sts_appconfig",
        "sts_keys",
        "sts_changes",
    ] {
        query(&url, &format!("DELETE FROM {}", table)).await;
    }
    let (driver, keys) = store(&url, &dir).await;
    let as_driver: Arc<dyn Driver> = driver.clone();
    let sets = KeySets::new(as_driver, keys.clone());
    let set = sets.open_or_make("default").await.unwrap();
    let cert = set.cert_b64().unwrap().to_string();
    let totp = keys.seal("JBSWY3DPEHPK3PXP", "totp-secret", "").unwrap();
    let entries = [
        (
            "default",
            "dc=example,dc=com",
            stored(
                "dc=example,dc=com",
                &[("objectClass", &["top", "domain"]), ("dc", &["example"])],
                Some("seed"),
                Some("20260101000000Z"),
            ),
        ),
        (
            "default",
            "uid=carol,ou=people,dc=example,dc=com",
            stored(
                "uid=carol,ou=people,dc=example,dc=com",
                &[
                    ("objectClass", &["top", "person", "inetOrgPerson"]),
                    ("uid", &["carol"]),
                    ("cn", &["Carol Ünïcode"]),
                    ("sn", &["C"]),
                    ("mail", &["Carol@Example.COM"]),
                    ("entryUUID", &["7D9E0000-1111-4222-8333-944455556666"]),
                    ("stsPseudonym", &["C4rol"]),
                    ("userCertificate;binary", &[cert.as_str()]),
                    ("stsTotpCredential", &[totp.as_str()]),
                    (
                        "description",
                        &[" leading", "trailing ", "", "line\nbreak"],
                    ),
                    ("spiffeSubject", &["spiffe://example.com/carol"]),
                ],
                None,
                Some("20260105000000Z"),
            ),
        ),
        (
            "default",
            "cn=ops,ou=groups,dc=example,dc=com",
            stored(
                "cn=ops,ou=groups,dc=example,dc=com",
                &[
                    ("objectClass", &["top", "groupOfUniqueNames"]),
                    ("cn", &["ops"]),
                    (
                        "uniqueMember",
                        &["uid=carol,ou=people,dc=example,dc=com"],
                    ),
                    ("appOwner", &[" UID=Carol, OU=People,dc=example,dc=com "]),
                    ("fedSubjectGroup", &["Partners"]),
                ],
                None,
                None,
            ),
        ),
        (
            "acme",
            "uid=dave,ou=people,dc=acme,dc=example",
            stored(
                "uid=dave,ou=people,dc=acme,dc=example",
                &[
                    ("objectClass", &["top", "inetOrgPerson"]),
                    ("uid", &["dave"]),
                    ("mail", &["dave@acme.example"]),
                    ("cn", &["Dave"]),
                    ("sn", &["D"]),
                ],
                Some("scim"),
                Some("20260106000000Z"),
            ),
        ),
    ];
    let change = DirectoryChange {
        upserts: entries
            .iter()
            .map(|(realm, key, entry)| DirectoryUpsert {
                realm: realm.to_string(),
                key: key.to_string(),
                entry: entry.clone(),
                base: None,
            })
            .collect(),
        touched: vec!["default".into(), "acme".into()],
        ..DirectoryChange::default()
    };
    driver.save_directory(&change).await.unwrap();
    let realms = vec![
        json!({ "id": "acme", "name": "Acme", "description": "written by Rust",
                              "domain": "acme.example", "createdAt": 1767312000000i64,
                              "overrides": { "saml.organizationName": "Acme by Rust",
                                             "oauth2.accessTokenTtlS": 600 },
                              "retiringSince": null }),
    ];
    driver.save_realms(&realms).await.unwrap();
    let mut overrides = Map::new();
    overrides.insert(
        "saml.organizationDisplayName".into(),
        json!("Rust wrote this"),
    );
    overrides.insert("scheduler.tickS".into(), json!(25));
    driver.save_overrides(&overrides).await.unwrap();
    let sealed: Vec<Json> = [
        ("minted-rows", ""),
        ("authn-sessions", "acme"),
        ("brand-new-class", "acme"),
    ]
    .iter()
    .map(|(label, realm)| {
        let text = format!("sealed by Rust for {} in [{}] é", label, realm);
        json!({ "label": label, "realm": realm, "text": text,
                    "cipher": keys.seal(&text, label, realm).unwrap() })
    })
    .collect();
    keys.settle().await;
    let digests: Vec<Json> = ["directory-index", "cluster-fingerprint"]
        .iter()
        .map(|l| json!({ "label": l, "text": "name\ncarol", "digest": keys.keyed_digest(l, "name\ncarol") }))
        .collect();
    let out = json!({
        "entries": entries.iter().map(|(realm, key, e)| json!({
            "realm": realm, "key": key,
            "entry": { "dn": e.dn, "attributes": e.attributes, "origin": e.origin } })).collect::<Vec<_>>(),
        "realms": realms, "overrides": overrides, "sealed": sealed, "digests": digests,
        "signing": { "kid": set.kid() },
    });
    std::fs::write(
        dir.join("interop-rust.json"),
        serde_json::to_string_pretty(&out).unwrap(),
    )
    .unwrap();
    eprintln!("Rust wrote the store for Node to read");
}
