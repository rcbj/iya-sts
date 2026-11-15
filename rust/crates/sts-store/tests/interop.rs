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
//! BOTH ENGINES AND THE SIDE TABLES (#444 phase 3): the URL's scheme picks
//! the driver (`postgres://`, or `mariadb://` for #677), and each direction
//! also covers what a minted flush keeps beside the sealed bodies —
//! `sts_sessions` as `SessionIndex::of()` computes it from the session,
//! `sts_minted_index` and its sort row, the change log's minted keys, the
//! kept counts (`sts_ldap_counts`, `sts_ldap_dek_counts`), MariaDB's
//! `sts_ldap_entry_keys`, and the stable origin claim with its fence lock —
//! each field for field against what this side computes from the same
//! plaintext.
//!
//! With either variable unset, or no `interop-node.json`, it says so and
//! passes.

#![allow(clippy::unwrap_used)] // a test file

use std::path::PathBuf;
use std::sync::Arc;

use indexmap::IndexMap;
use serde_json::{json, Map, Value as Json};
use sts_store::codec::EntryCodec;
use sts_store::driver::MintedWrite;
use sts_store::key_sets::KeySets;
use sts_store::keystore::DataKeys;
use sts_store::mariadb::{bases_of, entry_key_rows, table_key, MariadbDriver};
use sts_store::model::{
    DirectoryChange, DirectoryDelete, DirectoryUpsert, StoredEntry,
};
use sts_store::origin::AdoptOptions;
use sts_store::postgres::PostgresDriver;
use sts_store::side::{filed, IndexHooks, SessionIndex};
use sts_store::Driver;

const SESSIONS: &str = "authn.sessions";
const INDEXED: &str = "interop.indexed";
const NODE_ORIGIN: &str = "interop-node";
const RUST_ORIGIN: &str = "interop-rust";

fn mariadb(url: &str) -> bool {
    url.starts_with("mariadb://") || url.starts_with("mysql://")
}

/// Either engine's driver, and the two calls only a driver's own type has.
#[derive(Clone)]
enum Store {
    Pg(Arc<PostgresDriver>),
    Maria(Arc<MariadbDriver>),
}

impl Store {
    fn driver(&self) -> Arc<dyn Driver> {
        match self {
            Store::Pg(d) => d.clone(),
            Store::Maria(d) => d.clone(),
        }
    }

    async fn adopt(&self, name: &str) -> sts_store::origin::Adopted {
        let opts = AdoptOptions {
            name: name.to_string(),
            ttl_ms: 120_000,
            wait_ms: 0,
            node_id: String::new(),
        };
        match self {
            Store::Pg(d) => d.adopt_origin(&opts).await.unwrap(),
            Store::Maria(d) => d.adopt_origin(&opts).await.unwrap(),
        }
    }

    async fn count(&self, realm: &str, base: &str) -> i64 {
        match self {
            Store::Pg(d) => d.directory_count(realm, base).await.unwrap(),
            Store::Maria(d) => d.directory_count(realm, base).await.unwrap(),
        }
    }
}

fn setting() -> Option<(String, PathBuf)> {
    let url = std::env::var("STS_TEST_DATABASE_URL").ok()?;
    let dir = std::env::var("STS_INTEROP_DIR").ok()?;
    Some((url, PathBuf::from(dir)))
}

async fn store(url: &str, dir: &std::path::Path) -> (Store, Arc<DataKeys>) {
    let store = if mariadb(url) {
        Store::Maria(Arc::new(MariadbDriver::new(url, false, "", 4).unwrap()))
    } else {
        Store::Pg(Arc::new(PostgresDriver::new(url, false, 4).unwrap()))
    };
    let driver = store.driver();
    driver.open().await.unwrap();
    let (kek, text) =
        DataKeys::read_kek_file(dir.join("interop-kek.txt").to_str().unwrap())
            .unwrap();
    let keys = DataKeys::durable(kek, text, driver.clone(), None).unwrap();
    keys.load(true).await.unwrap();
    keys.ensure_digest_key().await;
    driver.adopt_data_keys(&keys);
    (store, keys)
}

/// A statement's rows as JSON objects, outside the driver: PostgreSQL's
/// through `row_to_json`, MariaDB's column by column (its JSON columns,
/// numbers and booleans as the text and integers it answers).
async fn query(url: &str, sql: &str) -> Vec<Map<String, Json>> {
    if mariadb(url) {
        use mysql_async::prelude::Queryable;
        let rest = url.split_once("://").unwrap().1;
        let (auth, place) = rest.rsplit_once('@').unwrap();
        let (user, pass) = auth.split_once(':').unwrap();
        let (hostport, db) = place.split_once('/').unwrap();
        let (host, port) = hostport.split_once(':').unwrap();
        let opts = mysql_async::OptsBuilder::default()
            .ip_or_hostname(host.to_string())
            .tcp_port(port.parse().unwrap())
            .user(Some(user.to_string()))
            .pass(Some(pass.to_string()))
            .db_name(Some(db.split('?').next().unwrap().to_string()))
            .prefer_socket(false)
            .ssl_opts(Some(
                mysql_async::SslOpts::default()
                    .with_danger_accept_invalid_certs(true)
                    .with_danger_skip_domain_validation(true),
            ))
            .init(vec!["SET time_zone = '+00:00'".to_string()]);
        let mut conn = mysql_async::Conn::new(opts).await.unwrap();
        let rows: Vec<mysql_async::Row> = conn.query(sql).await.unwrap();
        let out = rows
            .iter()
            .map(|r| {
                let mut m = Map::new();
                for (i, c) in r.columns_ref().iter().enumerate() {
                    let v = match r.as_ref(i).unwrap() {
                        mysql_async::Value::NULL => Json::Null,
                        mysql_async::Value::Int(n) => json!(n),
                        mysql_async::Value::UInt(n) => json!(n),
                        mysql_async::Value::Bytes(b) => {
                            Json::String(String::from_utf8_lossy(b).into())
                        }
                        other => Json::String(other.as_sql(true)),
                    };
                    m.insert(c.name_str().to_string(), v);
                }
                m
            })
            .collect();
        conn.disconnect().await.unwrap();
        return out;
    }
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
    if !sql.trim_start().to_ascii_uppercase().starts_with("SELECT") {
        client.batch_execute(sql).await.unwrap();
        return Vec::new();
    }
    client
        .query(
            &format!("SELECT row_to_json(t)::text FROM ({}) t", sql),
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| {
            let t: String = r.get(0);
            serde_json::from_str::<Json>(&t)
                .unwrap()
                .as_object()
                .unwrap()
                .clone()
        })
        .collect()
}

/// A JSON column: MariaDB's text parsed.
fn json_col(v: &Json) -> Json {
    match v {
        Json::String(s) => serde_json::from_str(s).unwrap_or(v.clone()),
        other => other.clone(),
    }
}

/// A number column: a bigint MariaDB may answer as text.
fn num(v: &Json) -> Json {
    match v {
        Json::String(s) => s.parse::<i64>().map_or(Json::Null, |n| json!(n)),
        other => other.clone(),
    }
}

/// A boolean column: MariaDB's 0 or 1.
fn truth(v: &Json) -> bool {
    match v {
        Json::Bool(b) => *b,
        Json::Number(n) => n.as_i64() == Some(1),
        Json::String(s) => s == "1" || s == "t",
        _ => false,
    }
}

/// The stored rows' raw columns, as `store-interop.js`'s `columnsOf()`.
async fn columns(url: &str) -> Vec<Json> {
    let mut rows = query(
        url,
        "SELECT realm, dn_key, dn, attrs, origin, created_at, modified_at, name_keys, mail_keys, uuid_keys, \
         class_keys, value_keys, attr_names, dek_keys FROM sts_ldap_entries",
    )
    .await;
    rows.sort_by(|a, b| {
        (a["realm"].as_str(), a["dn_key"].as_str())
            .cmp(&(b["realm"].as_str(), b["dn_key"].as_str()))
    });
    rows.iter()
        .map(|r| {
            let attrs = json_col(&r["attrs"]);
            json!({ "realm": r["realm"], "key": r["dn_key"], "dn": r["dn"], "origin": r["origin"],
                    "createdAt": r["created_at"], "modifiedAt": r["modified_at"],
                    "sealed": attrs.is_string(), "attrs": attrs,
                    "nameKeys": json_col(&r["name_keys"]), "mailKeys": json_col(&r["mail_keys"]),
                    "uuidKeys": json_col(&r["uuid_keys"]), "classKeys": json_col(&r["class_keys"]),
                    "valueKeys": json_col(&r["value_keys"]), "attrNames": json_col(&r["attr_names"]),
                    "dekKeys": json_col(&r["dek_keys"]) })
        })
        .collect()
}

/// `store-interop.js`'s `sideRows()`: the side tables, normalised.
async fn side_rows(url: &str) -> Json {
    let k = if mariadb(url) { "`key`" } else { "key" };
    let sessions: Vec<Json> = query(url, "SELECT * FROM sts_sessions")
        .await
        .iter()
        .map(|r| {
            json!({ "realm": r["realm"], "key": r["key"], "expiresAt": num(&r["expires_at"]),
                "lastSeenAt": num(&r["last_seen_at"]), "startedAt": num(&r["started_at"]),
                "subjectKey": r["subject_key"], "usernameKey": r["username_key"],
                "chosen": truth(&r["chosen"]), "authenticated": truth(&r["authenticated"]),
                "kind": r["kind"], "rpSurface": r["rp_surface"], "parentKey": r["parent_key"],
                "backsConsole": truth(&r["backs_console"]), "credentialKey": r["credential_key"],
                "partnerRelationship": r["partner_relationship"] })
        })
        .collect();
    let mut index: Vec<String> = query(url, "SELECT * FROM sts_minted_index")
        .await
        .iter()
        .map(|r| {
            let at = num(&r["sort_at"]);
            format!(
                "{}|{}|{}|{}|{}",
                r["handle"].as_str().unwrap(),
                r["realm"].as_str().unwrap(),
                r["index_key"].as_str().unwrap(),
                r["key"].as_str().unwrap(),
                if at.is_null() {
                    String::new()
                } else {
                    at.to_string()
                }
            )
        })
        .collect();
    index.sort();
    let mut counts = Map::new();
    for r in query(
        url,
        "SELECT realm, base_key, attribute, n FROM sts_ldap_counts",
    )
    .await
    {
        let id = format!(
            "{}|{}|{}",
            r["realm"].as_str().unwrap(),
            r["base_key"].as_str().unwrap(),
            r["attribute"].as_str().unwrap()
        );
        let n = counts.get(&id).and_then(Json::as_i64).unwrap_or(0)
            + num(&r["n"]).as_i64().unwrap();
        counts.insert(id, json!(n));
    }
    counts.retain(|_, v| v.as_i64() != Some(0));
    let mut deks = Map::new();
    for r in query(url, "SELECT dek_id, n FROM sts_ldap_dek_counts").await {
        let id = r["dek_id"].as_str().unwrap().to_string();
        let n = deks.get(&id).and_then(Json::as_i64).unwrap_or(0)
            + num(&r["n"]).as_i64().unwrap();
        deks.insert(id, json!(n));
    }
    deks.retain(|_, v| v.as_i64() != Some(0));
    let mut entry_keys: Vec<String> = if mariadb(url) {
        query(
            url,
            "SELECT realm, kind, k, dn_key FROM sts_ldap_entry_keys",
        )
        .await
        .iter()
        .map(|r| {
            format!(
                "{}|{}|{}|{}",
                r["realm"].as_str().unwrap(),
                r["kind"].as_str().unwrap(),
                r["k"].as_str().unwrap(),
                r["dn_key"].as_str().unwrap()
            )
        })
        .collect()
    } else {
        Vec::new()
    };
    entry_keys.sort();
    let mut changes = query(
        url,
        &format!("SELECT seq, kind, realm, {} AS k FROM sts_changes WHERE kind LIKE 'minted%'", k),
    )
    .await;
    changes.sort_by_key(|r| num(&r["seq"]).as_i64());
    let changes: Vec<String> = changes
        .iter()
        .map(|r| {
            format!(
                "{}|{}|{}",
                r["kind"].as_str().unwrap(),
                r["realm"].as_str().unwrap(),
                r["k"].as_str().unwrap()
            )
        })
        .collect();
    let claims: Vec<Json> = query(
        url,
        &format!(
            "SELECT {} AS k, reservation, origin FROM sts_cluster_claims WHERE scope = 'persistence.origin'",
            k
        ),
    )
    .await
    .iter()
    .map(|r| json!({ "key": r["k"], "reservation": r["reservation"], "origin": r["origin"] }))
    .collect();
    let mut locks: Vec<String> =
        query(url, "SELECT name FROM sts_cluster_locks")
            .await
            .iter()
            .map(|r| r["name"].as_str().unwrap().to_string())
            .collect();
    locks.sort();
    json!({ "sessions": sessions, "index": index, "counts": counts, "dekCounts": deks,
            "entryKeys": entry_keys, "changes": changes, "claims": claims, "locks": locks })
}

/// `countsCalledFor()`: the counts the stored entries call for.
fn counts_called_for(rows: &[Json]) -> (Json, Json) {
    let mut counts = Map::new();
    let mut deks = Map::new();
    for row in rows {
        let key = row["key"].as_str().unwrap();
        let parent = key.split_once(',').map_or("", |(_, p)| p);
        let names: Vec<&str> = row["attrNames"]
            .as_array()
            .map(|a| a.iter().filter_map(Json::as_str).collect())
            .unwrap_or_default();
        let held: Vec<&str> = sts_store::mariadb::COUNTED_ATTRIBUTES
            .iter()
            .filter(|a| names.contains(a))
            .copied()
            .collect();
        for base in bases_of(parent) {
            for attribute in std::iter::once("").chain(held.iter().copied()) {
                let id = format!(
                    "{}|{}|{}",
                    row["realm"].as_str().unwrap(),
                    base,
                    attribute
                );
                let n = counts.get(&id).and_then(Json::as_i64).unwrap_or(0) + 1;
                counts.insert(id, json!(n));
            }
        }
        if let Some(d) = row["dekKeys"].as_object() {
            for (id, n) in d {
                let total = deks.get(id).and_then(Json::as_i64).unwrap_or(0)
                    + n.as_i64().unwrap_or(0);
                deks.insert(id.clone(), json!(total));
            }
        }
    }
    (Json::Object(counts), Json::Object(deks))
}

/// MariaDB's key rows the stored entries call for.
fn key_rows_called_for(codec: &EntryCodec, rows: &[Json]) -> Vec<String> {
    let mut out = std::collections::BTreeSet::new();
    for row in rows {
        let key = row["key"].as_str().unwrap();
        let attrs = codec
            .open_attributes(key, &row["attrs"])
            .unwrap_or_default();
        for (kind, k) in entry_key_rows(codec, &attrs, &row["dekKeys"]) {
            out.insert(format!(
                "{}|{}|{}|{}",
                row["realm"].as_str().unwrap(),
                kind,
                k,
                key
            ));
        }
    }
    out.into_iter().collect()
}

/// The index rows an indexed row calls for.
fn index_rows_called_for(keys: &DataKeys, one: &Json) -> Vec<String> {
    let values: Vec<Json> = one["lookups"].as_array().unwrap().clone();
    let hooks = IndexHooks {
        lookups_of: Some(Arc::new(move |_: &Json, _: &str| values.clone())),
        sort_of: Some(Arc::new(|v: &Json, _: &str| v.get("sortAt").cloned())),
        ..IndexHooks::default()
    };
    let (realm, key) =
        (one["realm"].as_str().unwrap(), one["key"].as_str().unwrap());
    let lookups = hooks.lookups(keys, INDEXED, realm, key, one).unwrap();
    let mut out: Vec<String> =
        filed(INDEXED, realm, key, &lookups, hooks.sort_at(one, key))
            .iter()
            .map(|r| {
                format!(
                    "{}|{}|{}|{}|{}",
                    r.handle,
                    r.realm,
                    r.index_key,
                    r.key,
                    r.sort_at.map_or(String::new(), |n| n.to_string())
                )
            })
            .collect();
    out.sort();
    out.dedup();
    out
}

/// `mintedChangeRow()`'s key.
fn change_key(handle: &str, key: &str) -> String {
    sts_store::driver::minted_change_key(handle, key, "")
}

/// The session index as `sideRows()` normalises a row.
fn session_json(realm: &str, key: &str, i: &SessionIndex) -> Json {
    let i = i.params();
    json!({ "realm": realm, "key": key, "expiresAt": i.expires_at, "lastSeenAt": i.last_seen_at,
            "startedAt": i.started_at, "subjectKey": i.subject_key, "usernameKey": i.username_key,
            "chosen": i.chosen, "authenticated": i.authenticated, "kind": i.kind,
            "rpSurface": i.rp_surface, "parentKey": i.parent_key, "backsConsole": i.backs_console,
            "credentialKey": i.credential_key, "partnerRelationship": i.partner_relationship })
}

/// The side-table checks both directions make of the other's writes.
async fn side_differences(
    url: &str,
    store: &Store,
    keys: &Arc<DataKeys>,
    minted: &Json,
    out: &mut Vec<String>,
) {
    let side = side_rows(url).await;
    let driver = store.driver();
    let codec = EntryCodec::new(keys.clone());
    let sessions = minted["sessions"].as_array().unwrap();
    let mut refs: Vec<(String, String, String)> = sessions
        .iter()
        .map(|s| {
            (
                SESSIONS.to_string(),
                s["realm"].as_str().unwrap().into(),
                s["key"].as_str().unwrap().into(),
            )
        })
        .collect();
    refs.push((
        SESSIONS.into(),
        minted["ended"]["realm"].as_str().unwrap().into(),
        minted["ended"]["key"].as_str().unwrap().into(),
    ));
    let bodies = driver.read_minted_many(refs).await.unwrap();
    if bodies.len() != sessions.len() {
        out.push(format!(
            "{} live sessions read back, {} written",
            bodies.len(),
            sessions.len()
        ));
    }
    for one in sessions {
        let (realm, key) =
            (one["realm"].as_str().unwrap(), one["key"].as_str().unwrap());
        let opened = bodies
            .iter()
            .find(|b| b.realm == realm && b.key == key)
            .and_then(|b| keys.open(&b.body, "minted-rows"))
            .and_then(|t| serde_json::from_str::<Json>(&t).ok());
        if opened.as_ref().map(canonical) != Some(canonical(&one["value"])) {
            out.push(format!(
                "the session {} does not open as written: {:?}",
                key, opened
            ));
        }
        let mine = SessionIndex::of(keys, &one["value"])
            .map(|i| session_json(realm, key, &i));
        let row = side["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["realm"] == realm && r["key"] == key)
            .cloned();
        if row.as_ref().map(canonical) != mine.as_ref().map(canonical) {
            out.push(format!(
                "sts_sessions {}: stored {:?}, Rust computes {:?}",
                key, row, mine
            ));
        }
    }
    if side["sessions"].as_array().unwrap().len() != sessions.len() {
        out.push(format!(
            "sts_sessions holds {} rows; the ended session's is not gone",
            side["sessions"]
        ));
    }
    let index = index_rows_called_for(keys, &minted["indexed"]);
    if side["index"] != json!(index) {
        out.push(format!(
            "sts_minted_index: stored {}, Rust computes {:?}",
            side["index"], index
        ));
    }
    let changes: Vec<String> = side["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    for one in sessions.iter().chain(std::iter::once(&minted["ended"])) {
        let want = format!(
            "minted|{}|{}",
            one["realm"].as_str().unwrap(),
            change_key(SESSIONS, one["key"].as_str().unwrap())
        );
        if !changes.contains(&want) {
            out.push(format!("the change log does not name {}", want));
        }
    }
    let rows = columns(url).await;
    let (counts, deks) = counts_called_for(&rows);
    if canonical(&side["counts"]) != canonical(&counts) {
        out.push(format!(
            "sts_ldap_counts: stored {}, the entries call for {}",
            side["counts"], counts
        ));
    }
    if canonical(&side["dekCounts"]) != canonical(&deks) {
        out.push(format!(
            "sts_ldap_dek_counts: stored {}, the entries call for {}",
            side["dekCounts"], deks
        ));
    }
    // The kept count, as a reader asks it, for every base the entries
    // name.
    for (id, n) in counts.as_object().unwrap() {
        let parts: Vec<&str> = id.split('|').collect();
        if parts[2].is_empty() {
            let got = store.count(parts[0], parts[1]).await;
            if json!(got) != *n {
                out.push(format!(
                    "the count under {:?} reads {}, the entries call for {}",
                    parts, got, n
                ));
            }
        }
    }
    if mariadb(url) {
        let keyed = key_rows_called_for(&codec, &rows);
        if side["entryKeys"] != json!(keyed) {
            out.push(format!(
                "sts_ldap_entry_keys: stored {}, Rust computes {:?}",
                side["entryKeys"], keyed
            ));
        }
    }
    let _ = table_key("");
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
    let (store, keys) = store(&url, &dir).await;
    let driver = store.driver();
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
    let sets = KeySets::new(driver.clone(), keys.clone());
    sets.load().await.unwrap();
    let kid = sets.open("default").and_then(|s| s.kid());
    if kid.as_deref() != v["signing"]["kid"].as_str() {
        failures.push(format!("the signing key set: {:?}", kid));
    }
    // THE SIDE TABLES NODE KEPT, against what this side computes.
    side_differences(&url, &store, &keys, &v["minted"], &mut failures).await;
    // THE ORIGIN NODE HOLDS: its claim and fence lock in the form this
    // side writes, and refused to this side while it is held.
    let side = side_rows(&url).await;
    let held = side["claims"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["key"] == format!("n:{}", NODE_ORIGIN))
        .cloned();
    let lock = held.as_ref().map(|h| {
        format!(
            "fence:origin:n:{}:{}",
            NODE_ORIGIN,
            h["reservation"].as_str().unwrap()
        )
    });
    if held.is_none()
        || !side["locks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| Some(l.as_str().unwrap().to_string()) == lock)
    {
        failures.push(format!(
            "Node's origin claim and fence lock: {:?} {}",
            held, side["locks"]
        ));
    }
    let refused = store.adopt(NODE_ORIGIN).await;
    if refused.adopted {
        failures.push(format!(
            "this side was given the origin Node holds: {:?}",
            refused
        ));
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
    let mut tables = vec![
        "sts_ldap_entries",
        "sts_realms",
        "sts_appconfig",
        "sts_keys",
        "sts_changes",
        "sts_minted",
        "sts_sessions",
        "sts_minted_index",
        "sts_ldap_counts",
        "sts_ldap_dek_counts",
        "sts_cluster_claims",
        "sts_cluster_locks",
    ];
    if mariadb(&url) {
        tables.push("sts_ldap_entry_keys");
    }
    for table in tables {
        query(&url, &format!("DELETE FROM {}", table)).await;
    }
    let (store, keys) = store(&url, &dir).await;
    let driver = store.driver();
    // THE STABLE ORIGIN, held while this side writes, so every write below
    // passes its fence, and left held for Node to find (#617).
    let adopted = store.adopt(RUST_ORIGIN).await;
    assert!(adopted.adopted, "{:?}", adopted);
    let sets = KeySets::new(driver.clone(), keys.clone());
    let set = sets.open_or_make("default").await.unwrap();
    let cert = set.cert_b64().unwrap().to_string();
    let totp = keys.seal("JBSWY3DPEHPK3PXP", "totp-secret", "").unwrap();
    let mut entries = [
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
    let mut first = change.clone();
    // One entry more, deleted by the second flush: what it added to the
    // counts must be taken away again.
    first.upserts.push(DirectoryUpsert {
        realm: "default".into(),
        key: "uid=erin,ou=people,dc=example,dc=com".into(),
        entry: stored(
            "uid=erin,ou=people,dc=example,dc=com",
            &[
                ("objectClass", &["top", "inetOrgPerson"]),
                ("uid", &["erin"]),
                ("userPassword", &["{SSHA}e"]),
            ],
            None,
            None,
        ),
        base: None,
    });
    driver.save_directory(&first).await.unwrap();
    // THE SECOND FLUSH REPLACES A ROW AND DELETES ONE: carol gains a
    // counted attribute (`userpassword`) against the base she was written
    // as, and erin goes.
    let carol = entries[1].2.clone();
    let mut carol2 = carol.clone();
    carol2
        .attributes
        .insert("userPassword".into(), vec!["{SSHA}c".into()]);
    let second = DirectoryChange {
        upserts: vec![DirectoryUpsert {
            realm: "default".into(),
            key: entries[1].1.to_string(),
            entry: carol2.clone(),
            base: Some(sts_store::merge::canonical_json(&carol)),
        }],
        deletes: vec![DirectoryDelete {
            realm: "default".into(),
            key: "uid=erin,ou=people,dc=example,dc=com".into(),
        }],
        touched: vec!["default".into()],
        ..DirectoryChange::default()
    };
    let outcomes = driver.save_directory(&second).await.unwrap();
    assert!(outcomes.is_empty(), "{:?}", outcomes);
    entries[1].2 = carol2;
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
    // THE MINTED ROWS AND THEIR SIDE TABLES, as the minted flush hands
    // them to the driver.
    let minted = json!({
        "sessions": [
            { "realm": "default", "key": "sid-Rust-1", "value": {
                "subjectId": "urn:uuid:0f8a2c6e-1111-4222-8333-944455556666",
                "user": { "username": "alice" }, "expires": 1893456000123.9_f64,
                "lastSeenAt": 1767225600456_i64, "startedAt": 1767225600000_i64,
                "authenticated": true, "rpSurface": "portal", "backsConsole": true,
                "written": "Rust" } },
            { "realm": "acme", "key": "sid-Rust-2", "value": {
                "subjectId": "urn:uuid:7d9e0000-1111-4222-8333-944455556666",
                "user": { "username": "Dave Ünïcode" }, "derivedFrom": "sid-parent",
                "credentialKey": "cred-1", "chosen": false,
                "fedPartnerSession": { "relationship": "partner-1" },
                "lastSeenAt": "1767225600789", "written": "Rust" } }
        ],
        "ended": { "realm": "default", "key": "sid-Rust-ended",
                   "value": { "subjectId": "urn:uuid:ended", "user": { "username": "x" },
                              "written": "Rust" } },
        "indexed": { "realm": "acme", "key": "row-Rust", "value": { "who": "Rust" },
                     "lookups": ["alpha", "Béta", "alpha"], "sortAt": 1767225600123_i64 }
    });
    let write = |handle: &str, one: &Json| MintedWrite {
        handle: handle.to_string(),
        realm: one["realm"].as_str().unwrap().to_string(),
        key: one["key"].as_str().unwrap().to_string(),
        key_sealed: String::new(),
        journal_key: one["key"].as_str().unwrap().to_string(),
        body: keys
            .seal(
                &one["value"].to_string(),
                "minted-rows",
                one["realm"].as_str().unwrap(),
            )
            .unwrap_or_default(),
        expires_at: None,
        own: false,
        tombstone: handle == SESSIONS,
        merge: None,
        session_index: if handle == SESSIONS {
            SessionIndex::of(&keys, &one["value"])
        } else {
            None
        },
        lookups: None,
        sort_at: None,
        indexed: handle == INDEXED,
    };
    let mut upserts: Vec<MintedWrite> = minted["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .chain(std::iter::once(&minted["ended"]))
        .map(|one| write(SESSIONS, one))
        .collect();
    let mut indexed = write(INDEXED, &minted["indexed"]);
    let values = minted["indexed"]["lookups"].as_array().unwrap().clone();
    let hooks = IndexHooks {
        lookups_of: Some(Arc::new(move |_: &Json, _: &str| values.clone())),
        sort_of: Some(Arc::new(|v: &Json, _: &str| v.get("sortAt").cloned())),
        ..IndexHooks::default()
    };
    indexed.lookups =
        hooks.lookups(&keys, INDEXED, "acme", "row-Rust", &minted["indexed"]);
    indexed.sort_at = hooks.sort_at(&minted["indexed"], "row-Rust");
    upserts.push(indexed);
    keys.settle().await;
    driver.save_minted(upserts, Vec::new()).await.unwrap();
    let mut ended = write(SESSIONS, &minted["ended"]);
    ended.body = String::new();
    ended.session_index = None;
    driver.save_minted(Vec::new(), vec![ended]).await.unwrap();
    // This side's own checks of what it kept, before Node makes them.
    let mut own = Vec::new();
    side_differences(&url, &store, &keys, &minted, &mut own).await;
    assert!(
        own.is_empty(),
        "{} differences in this side's own writes:\n{}",
        own.len(),
        own.join("\n")
    );
    let out = json!({
        "minted": minted, "origin": { "adopted": adopted.adopted, "origin": adopted.origin },
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
