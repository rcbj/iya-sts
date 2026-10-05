// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `persistence.mode=postgres` (`persistence/persistence_postgres.js`): the
//! shared store, and the cluster's tables.
//!
//! * **Never dialled in the clear.** TLS is required; whether the server's
//!   certificate is verified is `persistence.databaseTlsRejectUnauthorized`.
//! * **The schema is `postgres/schema.sql`**, applied by the database
//!   container with a least-privilege role that cannot change it. A store
//!   missing a table is refused at open rather than half used.
//! * **Two nodes writing one entry merge** (#46 section 3): every row a
//!   flush writes is read under `SELECT … FOR UPDATE` in the flush's own
//!   transaction, in key order so two flushes cannot deadlock, and what is
//!   written is [`crate::merge::merge_entry`]'s answer against the base the
//!   change was made on. What the store decided differently comes back as
//!   outcomes, which the live directory takes.
//! * **The realm registry and the overrides are written as deltas**: the
//!   keys a change set and cleared, a name or description only when it
//!   changed, the retiring mark only ever set — so two nodes changing
//!   different settings of one realm keep both.
//! * **The cluster's time is the database's** (`clock_timestamp()` in
//!   milliseconds), for membership, leases and claims alike.
//!
//! Not yet here: the change log other processes replay, the minted stores,
//! the sealed entry form, and the queries a windowed worker asks. Until the
//! change log is, one node writes and the others read at start only.

use std::sync::Arc;

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use postgres_openssl::MakeTlsConnector;
use serde_json::{json, Map, Value as Json};
use sts_cluster::membership::{
    ClaimAnswer, ClusterStore, LeaseAnswer, Renewal,
};
use sts_cluster::schedule::BoxFuture;
use sts_core::errors::codes;
use sts_core::log::tag;
use tokio_postgres::Row;

use crate::codec;
use crate::driver::{
    ChangeLog, ChangeRow, Directory, Driver, KeyMerge, StoreError, StoreFuture,
    StoreResult,
};
use crate::merge::{merge_entry, Outcome};
use crate::model::{
    DirectoryChange, DirectoryOutcome, DirectoryUpsert, StoredEntry,
};
use crate::shadow::{AppconfigDelta, RealmsDelta};

/// The database's clock, in milliseconds.
const DB_NOW: &str = "(extract(epoch from clock_timestamp()) * 1000)::bigint";

/// The tables this driver reads and writes.
const TABLES: &[&str] = &[
    "sts_ldap_entries",
    "sts_realms",
    "sts_appconfig",
    "sts_minted",
    "sts_cluster_nodes",
    "sts_cluster_leases",
    "sts_cluster_claims",
];

const ENTRY_COLUMNS: &str =
    "realm, dn_key, dn, attrs, origin, created_at, modified_at";

fn err(e: impl std::fmt::Display) -> StoreError {
    StoreError::new(e.to_string())
}

/// The postgres store.
pub struct PostgresDriver {
    pool: Pool,
    /// This process's name in the change log.
    origin: String,
}

/// The channel a commit's NOTIFY goes out on, so another process pulls at
/// once; the poll is the contract, the nudge only makes it prompt.
const CHANNEL: &str = "sts_ldap_change";

/// Change-log rows per INSERT statement.
const CHANGE_ROWS_PER_STATEMENT: usize = 500;

impl PostgresDriver {
    /// A pool of at most `pool_max` connections to `url`, over TLS.
    pub fn new(
        url: &str,
        verify_tls: bool,
        pool_max: usize,
    ) -> StoreResult<PostgresDriver> {
        let mut config: tokio_postgres::Config = url.parse().map_err(err)?;
        config.ssl_mode(tokio_postgres::config::SslMode::Require);
        let mut tls = SslConnector::builder(SslMethod::tls()).map_err(err)?;
        if !verify_tls {
            tls.set_verify(SslVerifyMode::NONE);
        }
        let mut connector = MakeTlsConnector::new(tls.build());
        if !verify_tls {
            connector.set_callback(|c, _| {
                c.set_verify_hostname(false);
                Ok(())
            });
        }
        let manager = Manager::from_config(
            config,
            connector,
            ManagerConfig {
                recycling_method: RecyclingMethod::Fast,
            },
        );
        let pool = Pool::builder(manager)
            .max_size(pool_max.max(2))
            .build()
            .map_err(err)?;
        let mut id = [0u8; 9];
        openssl::rand::rand_bytes(&mut id).map_err(err)?;
        let origin = format!(
            "rs-{}-{}",
            std::process::id(),
            id.iter().map(|b| format!("{:02x}", b)).collect::<String>()
        );
        Ok(PostgresDriver { pool, origin })
    }

    /// Records what a transaction changed in the change log, and nudges the
    /// other processes (`recordChanges()`): `(kind, realm, key)` rows.
    async fn record_changes(
        &self,
        tx: &deadpool_postgres::Transaction<'_>,
        rows: &[(&str, &str, &str)],
    ) -> StoreResult<()> {
        if rows.is_empty() {
            return Ok(());
        }
        for chunk in rows.chunks(CHANGE_ROWS_PER_STATEMENT) {
            let kinds: Vec<&str> = chunk.iter().map(|r| r.0).collect();
            let realms: Vec<&str> = chunk.iter().map(|r| r.1).collect();
            let keys: Vec<&str> = chunk.iter().map(|r| r.2).collect();
            tx.execute(
                "INSERT INTO sts_changes (origin, kind, realm, key) SELECT $1, k, r, y FROM unnest($2::text[], \
                 $3::text[], $4::text[]) WITH ORDINALITY AS u(k, r, y, n) ORDER BY n",
                &[&self.origin, &kinds, &realms, &keys],
            )
            .await
            .map_err(err)?;
        }
        let mut kinds: Vec<&str> = rows.iter().map(|r| r.0).collect();
        kinds.dedup();
        let payload =
            json!({ "from": self.origin, "kinds": kinds, "rows": rows.len() })
                .to_string();
        tx.execute("SELECT pg_notify($1, $2)", &[&CHANNEL, &payload])
            .await
            .map_err(err)?;
        Ok(())
    }

    async fn client(&self) -> StoreResult<deadpool_postgres::Object> {
        self.pool.get().await.map_err(err)
    }

    fn entry_of(row: &Row) -> Option<StoredEntry> {
        let attrs: Json = row.get("attrs");
        let attributes = codec::open_attributes(&attrs)?;
        let created: Option<String> = row.get("created_at");
        let modified: Option<String> = row.get("modified_at");
        let origin: Option<String> = row.get("origin");
        let created = created.filter(|c| !c.is_empty());
        Some(StoredEntry {
            dn: row.get("dn"),
            attributes,
            origin: origin.filter(|o| !o.is_empty()),
            modified_at: modified
                .filter(|m| !m.is_empty())
                .or_else(|| created.clone()),
            created_at: created,
        })
    }

    async fn write_entry(
        tx: &deadpool_postgres::Transaction<'_>,
        realm: &str,
        key: &str,
        entry: &StoredEntry,
        insert_only: bool,
    ) -> StoreResult<u64> {
        let index = codec::index_of(&entry.attributes);
        let attrs = codec::seal_attributes(&entry.attributes);
        let conflict = if insert_only {
            "ON CONFLICT (realm, dn_key) DO NOTHING"
        } else {
            "ON CONFLICT (realm, dn_key) DO UPDATE SET dn = EXCLUDED.dn, attrs = EXCLUDED.attrs, origin = \
             EXCLUDED.origin, created_at = EXCLUDED.created_at, modified_at = EXCLUDED.modified_at, name_keys = \
             EXCLUDED.name_keys, mail_keys = EXCLUDED.mail_keys, uuid_keys = EXCLUDED.uuid_keys, class_keys = \
             EXCLUDED.class_keys, value_keys = EXCLUDED.value_keys, attr_names = EXCLUDED.attr_names"
        };
        let sql = format!(
            "INSERT INTO sts_ldap_entries (realm, dn_key, dn, attrs, origin, created_at, modified_at, name_keys, \
             mail_keys, uuid_keys, class_keys, value_keys, attr_names) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, \
             $10, $11, $12, $13) {}",
            conflict
        );
        tx.execute(
            &sql,
            &[
                &realm,
                &key,
                &entry.dn,
                &attrs,
                &entry.origin,
                &entry.created_at,
                &entry.modified_at,
                &json!(index.name_keys),
                &json!(index.mail_keys),
                &json!(index.uuid_keys),
                &json!(index.class_keys),
                &json!(index.value_keys),
                &json!(index.attr_names),
            ],
        )
        .await
        .map_err(err)
    }

    /// One upsert, merged against what the store holds (`settle()`).
    async fn settle(
        tx: &deadpool_postgres::Transaction<'_>,
        row: &DirectoryUpsert,
        theirs: Option<StoredEntry>,
        again: bool,
        outcomes: &mut Vec<DirectoryOutcome>,
    ) -> StoreResult<()> {
        let base = row
            .base
            .as_deref()
            .and_then(|b| serde_json::from_str::<Json>(b).ok())
            .and_then(|b| crate::merge::entry_of_json(&b));
        let verdict =
            merge_entry(base.as_ref(), Some(&row.entry), theirs.as_ref());
        let record = |outcomes: &mut Vec<DirectoryOutcome>| {
            outcomes.push(DirectoryOutcome {
                realm: row.realm.clone(),
                key: row.key.clone(),
                outcome: verdict.outcome,
                entry: verdict.entry.clone(),
            })
        };
        match verdict.outcome {
            Outcome::Theirs | Outcome::Deleted => {
                record(outcomes);
                return Ok(());
            }
            Outcome::Merged => record(outcomes),
            Outcome::Mine => {}
        }
        let Some(entry) = verdict.entry.as_ref() else {
            return Ok(());
        };
        if theirs.is_some() {
            PostgresDriver::write_entry(tx, &row.realm, &row.key, entry, false)
                .await?;
            return Ok(());
        }
        let inserted =
            PostgresDriver::write_entry(tx, &row.realm, &row.key, entry, true)
                .await?;
        if inserted > 0 {
            return Ok(());
        }
        if !again {
            PostgresDriver::write_entry(tx, &row.realm, &row.key, entry, false)
                .await?;
            return Ok(());
        }
        // Another node inserted it since the lock was asked for: merged
        // against what it wrote, once.
        let found = tx
            .query_opt(
                &format!("SELECT {} FROM sts_ldap_entries WHERE realm = $1 AND dn_key = $2 FOR UPDATE", ENTRY_COLUMNS),
                &[&row.realm, &row.key],
            )
            .await
            .map_err(err)?;
        outcomes.retain(|o| !(o.realm == row.realm && o.key == row.key));
        let now = found.as_ref().and_then(PostgresDriver::entry_of);
        Box::pin(PostgresDriver::settle(tx, row, now, false, outcomes)).await
    }
}

impl Driver for PostgresDriver {
    fn name(&self) -> &'static str {
        "postgres"
    }

    fn load_keys(&self) -> StoreFuture<'_, Vec<(String, String)>> {
        Box::pin(async move {
            let client = self.client().await?;
            let rows = client
                .query("SELECT realm, material FROM sts_keys", &[])
                .await
                .map_err(err)?;
            Ok(rows.iter().map(|r| (r.get(0), r.get(1))).collect())
        })
    }

    // A TRANSACTION WITH A CHANGE ROW (#46): a node that never heard of a
    // key write went on using what it had.
    fn save_keys<'a>(
        &'a self,
        realm: &'a str,
        material: &'a str,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            let mut client = self.client().await?;
            let tx = client.transaction().await.map_err(err)?;
            tx.execute(
                "INSERT INTO sts_keys (realm, material, written_at) VALUES ($1, $2, now()) ON CONFLICT (realm) DO \
                 UPDATE SET material = EXCLUDED.material, written_at = now()",
                &[&realm, &material],
            )
            .await
            .map_err(err)?;
            self.record_changes(&tx, &[("keys", realm, "")]).await?;
            tx.commit().await.map_err(err)
        })
    }

    fn merges_keys(&self) -> bool {
        true
    }

    // Under the row's lock: two processes making a data key for one class
    // at once keep both. A row nobody has yet is locked by inserting it, and
    // the loser of that race merges against the winner's.
    fn merge_keys<'a>(
        &'a self,
        realm: &'a str,
        merge: KeyMerge,
    ) -> StoreFuture<'a, Option<String>> {
        Box::pin(async move {
            let mut client = self.client().await?;
            let tx = client.transaction().await.map_err(err)?;
            let current: Option<String> = tx
                .query_opt(
                    "SELECT material FROM sts_keys WHERE realm = $1 FOR UPDATE",
                    &[&realm],
                )
                .await
                .map_err(err)?
                .map(|r| r.get(0));
            let next = merge(current.as_deref()).map_err(StoreError::new)?;
            let Some(next) = next.filter(|n| Some(n) != current.as_ref())
            else {
                tx.commit().await.map_err(err)?;
                return Ok(current);
            };
            if current.is_some() {
                tx.execute(
                    "UPDATE sts_keys SET material = $2, written_at = now() WHERE realm = $1",
                    &[&realm, &next],
                )
                .await
                .map_err(err)?;
            } else {
                let inserted = tx
                    .execute(
                        "INSERT INTO sts_keys (realm, material, written_at) VALUES ($1, $2, now()) ON CONFLICT \
                         (realm) DO NOTHING",
                        &[&realm, &next],
                    )
                    .await
                    .map_err(err)?;
                if inserted == 0 {
                    // Another process inserted it first: nothing written
                    // here; the caller reads again and merges once more.
                    tx.rollback().await.map_err(err)?;
                    return Err(StoreError::new(format!(
                        "the \"{}\" key row was written by another process at the same moment; try again",
                        realm
                    )));
                }
            }
            self.record_changes(&tx, &[("keys", realm, "")]).await?;
            tx.commit().await.map_err(err)?;
            Ok(Some(next))
        })
    }

    fn change_log(&self) -> Option<&dyn ChangeLog> {
        Some(self)
    }

    fn open(&self) -> StoreFuture<'_, ()> {
        Box::pin(async move {
            let client = self.client().await?;
            let probes: Vec<String> = TABLES
                .iter()
                .map(|t| format!("to_regclass('{}') IS NOT NULL", t))
                .collect();
            let row = client
                .query_one(&format!("SELECT {}", probes.join(", ")), &[])
                .await
                .map_err(err)?;
            let missing: Vec<&str> = TABLES
                .iter()
                .enumerate()
                .filter(|(i, _)| !row.get::<_, bool>(*i))
                .map(|(_, t)| *t)
                .collect();
            if !missing.is_empty() {
                return Err(StoreError::new(format!(
                    "the postgres store is missing {} — apply postgres/schema.sql to it (the database container \
                     does, with the least-privilege role this service connects as)",
                    missing.join(", ")
                )));
            }
            tracing::info!("persistence: the postgres store is open and its schema is in place.");
            Ok(())
        })
    }

    fn close(&self) -> StoreFuture<'_, ()> {
        Box::pin(async move {
            self.pool.close();
            Ok(())
        })
    }

    fn load_directory(&self) -> StoreFuture<'_, Option<Directory>> {
        Box::pin(async move {
            let client = self.client().await?;
            let rows = client
                .query(&format!("SELECT {} FROM sts_ldap_entries ORDER BY realm, dn_key", ENTRY_COLUMNS), &[])
                .await
                .map_err(err)?;
            if rows.is_empty() {
                return Ok(None);
            }
            let mut out = Directory::new();
            let mut unreadable = 0;
            for row in &rows {
                match PostgresDriver::entry_of(row) {
                    Some(entry) => out
                        .entry(row.get::<_, String>("realm"))
                        .or_default()
                        .push(entry),
                    None => unreadable += 1,
                }
            }
            if unreadable > 0 {
                tracing::error!(
                    "{}persistence: {} directory entry/entries are sealed and did not open in this process, and were \
                     not restored.",
                    tag(codes::STS_STORE_0072),
                    unreadable
                );
            }
            Ok(Some(out))
        })
    }

    fn load_realms(&self) -> StoreFuture<'_, Option<Vec<Json>>> {
        Box::pin(async move {
            let client = self.client().await?;
            let rows = client
                .query(
                    "SELECT id, name, description, created_at, overrides, domain, retiring_at FROM sts_realms ORDER \
                     BY created_at NULLS FIRST, id",
                    &[],
                )
                .await
                .map_err(err)?;
            if rows.is_empty() {
                return Ok(None);
            }
            Ok(Some(
                rows.iter()
                    .map(|r| {
                        json!({
                            "id": r.get::<_, String>("id"),
                            "name": r.get::<_, Option<String>>("name"),
                            "description": r.get::<_, Option<String>>("description"),
                            "domain": r.get::<_, Option<String>>("domain").unwrap_or_default(),
                            "createdAt": r.get::<_, Option<i64>>("created_at"),
                            "overrides": r.get::<_, Option<Json>>("overrides").unwrap_or_else(|| json!({})),
                            "retiringSince": r.get::<_, Option<i64>>("retiring_at"),
                        })
                    })
                    .collect(),
            ))
        })
    }

    fn load_overrides(&self) -> StoreFuture<'_, Option<Map<String, Json>>> {
        Box::pin(async move {
            let client = self.client().await?;
            let rows = client
                .query("SELECT key, value FROM sts_appconfig", &[])
                .await
                .map_err(err)?;
            if rows.is_empty() {
                return Ok(None);
            }
            let mut out = Map::new();
            for r in rows {
                let value: Json = r.get("value");
                let raw = value.get("raw").cloned().unwrap_or(value);
                out.insert(r.get("key"), raw);
            }
            Ok(Some(out))
        })
    }

    fn save_directory<'a>(
        &'a self,
        change: &'a DirectoryChange,
    ) -> StoreFuture<'a, Vec<DirectoryOutcome>> {
        Box::pin(async move {
            let mut client = self.client().await?;
            let tx = client.transaction().await.map_err(err)?;
            let id = |realm: &str, key: &str| format!("{}\n{}", realm, key);
            // Every row this flush changes is locked, in key order.
            let mut locking: Vec<(String, String)> = change
                .upserts
                .iter()
                .map(|u| (u.realm.clone(), u.key.clone()))
                .chain(
                    change
                        .deletes
                        .iter()
                        .map(|d| (d.realm.clone(), d.key.clone())),
                )
                .collect();
            locking.sort_by_key(|(r, k)| id(r, k));
            let mut stored: std::collections::HashMap<String, StoredEntry> =
                std::collections::HashMap::new();
            for chunk in locking.chunks(500) {
                let realms: Vec<&str> =
                    chunk.iter().map(|(r, _)| r.as_str()).collect();
                let keys: Vec<&str> =
                    chunk.iter().map(|(_, k)| k.as_str()).collect();
                let rows = tx
                    .query(
                        &format!(
                            "SELECT {} FROM sts_ldap_entries WHERE (realm, dn_key) IN (SELECT r, k FROM \
                             unnest($1::text[], $2::text[]) AS u(r, k)) ORDER BY realm, dn_key FOR UPDATE",
                            ENTRY_COLUMNS
                        ),
                        &[&realms, &keys],
                    )
                    .await
                    .map_err(err)?;
                for row in &rows {
                    let key = id(row.get("realm"), row.get("dn_key"));
                    match PostgresDriver::entry_of(row) {
                        Some(entry) => {
                            stored.insert(key, entry);
                        }
                        None => {
                            return Err(StoreError::new(format!(
                                "{}the directory entry {} is sealed and does not open in this process",
                                tag(codes::STS_STORE_0072),
                                key.replace('\n', " in ")
                            )))
                        }
                    }
                }
            }
            let mut upserts: Vec<&DirectoryUpsert> =
                change.upserts.iter().collect();
            upserts.sort_by_key(|u| id(&u.realm, &u.key));
            let mut outcomes = Vec::new();
            for row in upserts {
                let theirs = stored.get(&id(&row.realm, &row.key)).cloned();
                PostgresDriver::settle(&tx, row, theirs, true, &mut outcomes)
                    .await?;
            }
            for d in &change.deletes {
                tx.execute("DELETE FROM sts_ldap_entries WHERE realm = $1 AND dn_key = $2", &[&d.realm, &d.key])
                    .await
                    .map_err(err)?;
            }
            let decided_elsewhere = |realm: &str, key: &str| {
                outcomes.iter().any(|o: &DirectoryOutcome| {
                    o.realm == realm
                        && o.key == key
                        && matches!(
                            o.outcome,
                            Outcome::Theirs | Outcome::Deleted
                        )
                })
            };
            let mut moved: Vec<(&str, &str, &str)> = change
                .upserts
                .iter()
                .filter(|u| !decided_elsewhere(&u.realm, &u.key))
                .map(|u| ("directory", u.realm.as_str(), u.key.as_str()))
                .collect();
            moved.extend(
                change
                    .deletes
                    .iter()
                    .map(|d| ("directory", d.realm.as_str(), d.key.as_str())),
            );
            self.record_changes(&tx, &moved).await?;
            for realm in &change.removed_realms {
                for table in ["sts_ldap_entries", "sts_minted"] {
                    tx.execute(
                        &format!("DELETE FROM {} WHERE realm = $1", table),
                        &[realm],
                    )
                    .await
                    .map_err(err)?;
                }
                tx.execute("DELETE FROM sts_realms WHERE id = $1", &[realm])
                    .await
                    .map_err(err)?;
            }
            tx.commit().await.map_err(err)?;
            Ok(outcomes)
        })
    }

    fn save_realms<'a>(&'a self, rows: &'a [Json]) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            let delta = RealmsDelta {
                upserts: rows
                    .iter()
                    .map(|row| crate::shadow::RealmChange {
                        row: row.clone(),
                        name: true,
                        description: true,
                        set: row
                            .get("overrides")
                            .and_then(Json::as_object)
                            .cloned()
                            .unwrap_or_default(),
                        cleared: Vec::new(),
                        retiring: false,
                    })
                    .collect(),
                ..RealmsDelta::default()
            };
            self.write_realms(&delta, true).await
        })
    }

    fn save_realms_delta<'a>(
        &'a self,
        _rows: &'a [Json],
        delta: &'a RealmsDelta,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move { self.write_realms(delta, false).await })
    }

    fn save_overrides<'a>(
        &'a self,
        overrides: &'a Map<String, Json>,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            let delta = AppconfigDelta {
                set: overrides.clone(),
                cleared: Vec::new(),
            };
            self.write_overrides(&delta).await
        })
    }

    fn save_overrides_delta<'a>(
        &'a self,
        _overrides: &'a Map<String, Json>,
        delta: &'a AppconfigDelta,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move { self.write_overrides(delta).await })
    }
}

impl PostgresDriver {
    async fn write_realms(
        &self,
        delta: &RealmsDelta,
        whole: bool,
    ) -> StoreResult<()> {
        let mut client = self.client().await?;
        let tx = client.transaction().await.map_err(err)?;
        for id in &delta.removed {
            tx.execute("DELETE FROM sts_realms WHERE id = $1", &[id])
                .await
                .map_err(err)?;
        }
        for one in &delta.upserts {
            let row = &one.row;
            let text =
                |k: &str| row.get(k).and_then(Json::as_str).map(str::to_string);
            let overrides =
                row.get("overrides").cloned().unwrap_or_else(|| json!({}));
            let retiring = row
                .get("retiringSince")
                .and_then(Json::as_f64)
                .filter(|n| *n > 0.0)
                .map(|n| n as i64);
            let domain = text("domain").filter(|d| !d.is_empty());
            tx.execute(
                "INSERT INTO sts_realms (id, name, description, created_at, overrides, domain, retiring_at) VALUES \
                 ($1, $2, $3, $4, $5, $11, $12) ON CONFLICT (id) DO UPDATE SET retiring_at = \
                 COALESCE(sts_realms.retiring_at, EXCLUDED.retiring_at), domain = COALESCE(sts_realms.domain, \
                 EXCLUDED.domain), name = CASE WHEN $6 THEN EXCLUDED.name ELSE sts_realms.name END, description = \
                 CASE WHEN $7 THEN EXCLUDED.description ELSE sts_realms.description END, created_at = \
                 COALESCE(sts_realms.created_at, EXCLUDED.created_at), overrides = CASE WHEN $10 THEN \
                 EXCLUDED.overrides ELSE (COALESCE(sts_realms.overrides, '{}'::jsonb) - $8::text[]) || $9 END",
                &[
                    &text("id").unwrap_or_default(),
                    &text("name"),
                    &text("description"),
                    &row.get("createdAt").and_then(Json::as_i64),
                    &overrides,
                    &one.name,
                    &one.description,
                    &one.cleared,
                    &Json::Object(one.set.clone()),
                    &whole,
                    &domain,
                    &retiring,
                ],
            )
            .await
            .map_err(err)?;
        }
        if !delta.upserts.is_empty() || !delta.removed.is_empty() {
            self.record_changes(&tx, &[("realms", "", "")]).await?;
        }
        tx.commit().await.map_err(err)
    }

    async fn write_overrides(&self, delta: &AppconfigDelta) -> StoreResult<()> {
        let mut client = self.client().await?;
        let tx = client.transaction().await.map_err(err)?;
        if !delta.cleared.is_empty() {
            tx.execute(
                "DELETE FROM sts_appconfig WHERE key = ANY($1::text[])",
                &[&delta.cleared],
            )
            .await
            .map_err(err)?;
        }
        for (key, value) in &delta.set {
            tx.execute(
                "INSERT INTO sts_appconfig (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = \
                 EXCLUDED.value",
                &[key, &json!({ "raw": value })],
            )
            .await
            .map_err(err)?;
        }
        if !delta.set.is_empty() || !delta.cleared.is_empty() {
            self.record_changes(&tx, &[("appconfig", "", "")]).await?;
        }
        tx.commit().await.map_err(err)
    }

    fn pending<'a, T: Send + 'a>(
        &'a self,
        f: impl std::future::Future<Output = StoreResult<T>> + Send + 'a,
    ) -> BoxFuture<'a, Result<T, String>> {
        Box::pin(async move { f.await.map_err(|e| e.to_string()) })
    }
}

impl ClusterStore for PostgresDriver {
    fn now(&self) -> BoxFuture<'_, Result<f64, String>> {
        self.pending(async move {
            let row = self
                .client()
                .await?
                .query_one(&format!("SELECT {} AS now", DB_NOW), &[])
                .await
                .map_err(err)?;
            Ok(row.get::<_, i64>("now") as f64)
        })
    }

    fn join(
        &self,
        node: &str,
        ttl_ms: f64,
        info: Json,
    ) -> BoxFuture<'_, Result<(), String>> {
        let node = node.to_string();
        self.pending(async move {
            let name = info.get("name").and_then(Json::as_str).unwrap_or("").to_string();
            self.client()
                .await?
                .execute(
                    &format!(
                        "INSERT INTO sts_cluster_nodes (node_id, name, mode, started_at, heartbeat_at, expires_at, \
                         info) VALUES ($1, $2, 'active-active', {now}, {now}, {now} + $3, $4) ON CONFLICT (node_id) \
                         DO UPDATE SET heartbeat_at = {now}, expires_at = {now} + $3, left_at = 0",
                        now = DB_NOW
                    ),
                    &[&node, &name, &(ttl_ms as i64), &info],
                )
                .await
                .map_err(err)?;
            Ok(())
        })
    }

    fn heartbeat(
        &self,
        node: &str,
        ttl_ms: f64,
    ) -> BoxFuture<'_, Result<Renewal, String>> {
        let node = node.to_string();
        self.pending(async move {
            let row = self
                .client()
                .await?
                .query_one(
                    &format!(
                        "WITH n AS (UPDATE sts_cluster_nodes SET heartbeat_at = {now}, expires_at = {now} + $2 \
                         WHERE node_id = $1 AND left_at = 0 AND expires_at > {now} RETURNING node_id), l AS (UPDATE \
                         sts_cluster_leases SET expires_at = {now} + $2 WHERE holder = $1 AND expires_at > {now} AND \
                         EXISTS (SELECT 1 FROM n) RETURNING name, token) SELECT (SELECT count(*) FROM n) AS alive, \
                         COALESCE((SELECT json_agg(json_build_object('name', name, 'token', token) ORDER BY name) \
                         FROM l), '[]'::json) AS leases",
                        now = DB_NOW
                    ),
                    &[&node, &(ttl_ms as i64)],
                )
                .await
                .map_err(err)?;
            let leases: Json = row.get("leases");
            Ok(Renewal {
                alive: row.get::<_, i64>("alive") > 0,
                leases: leases
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .map(|l| {
                                (l["name"].as_str().unwrap_or("").to_string(), l["token"].as_u64().unwrap_or(0))
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            })
        })
    }

    fn acquire_lease(
        &self,
        name: &str,
        node: &str,
        ttl_ms: f64,
    ) -> BoxFuture<'_, Result<LeaseAnswer, String>> {
        let (name, node) = (name.to_string(), node.to_string());
        self.pending(async move {
            let client = self.client().await?;
            let won = client
                .query_opt(
                    &format!(
                        "INSERT INTO sts_cluster_leases (name, holder, token, acquired_at, expires_at) SELECT $1, $2, \
                         1, {now}, {now} + $3 WHERE EXISTS (SELECT 1 FROM sts_cluster_nodes WHERE node_id = $2 AND \
                         left_at = 0 AND expires_at > {now}) ON CONFLICT (name) DO UPDATE SET holder = \
                         EXCLUDED.holder, token = CASE WHEN sts_cluster_leases.holder = EXCLUDED.holder AND \
                         sts_cluster_leases.expires_at > {now} THEN sts_cluster_leases.token ELSE \
                         sts_cluster_leases.token + 1 END, acquired_at = CASE WHEN sts_cluster_leases.holder = \
                         EXCLUDED.holder AND sts_cluster_leases.expires_at > {now} THEN \
                         sts_cluster_leases.acquired_at ELSE EXCLUDED.acquired_at END, expires_at = \
                         EXCLUDED.expires_at WHERE sts_cluster_leases.expires_at <= {now} OR \
                         sts_cluster_leases.holder = EXCLUDED.holder RETURNING holder, token",
                        now = DB_NOW
                    ),
                    &[&name, &node, &(ttl_ms as i64)],
                )
                .await
                .map_err(err)?;
            if let Some(row) = won.filter(|r| r.get::<_, String>("holder") == node) {
                return Ok(LeaseAnswer { held: true, token: row.get::<_, i64>("token") as u64, holder: node });
            }
            let other = client
                .query_opt("SELECT holder, token FROM sts_cluster_leases WHERE name = $1", &[&name])
                .await
                .map_err(err)?;
            Ok(LeaseAnswer {
                held: false,
                token: other.as_ref().map_or(0, |r| r.get::<_, i64>("token") as u64),
                holder: other.map(|r| r.get("holder")).unwrap_or_default(),
            })
        })
    }

    fn release_lease(
        &self,
        name: &str,
        node: &str,
        token: u64,
    ) -> BoxFuture<'_, Result<bool, String>> {
        let (name, node) = (name.to_string(), node.to_string());
        self.pending(async move {
            let n = self
                .client()
                .await?
                .execute(
                    "UPDATE sts_cluster_leases SET expires_at = 0 WHERE name = $1 AND holder = $2 AND token = $3",
                    &[&name, &node, &(token as i64)],
                )
                .await
                .map_err(err)?;
            Ok(n > 0)
        })
    }

    fn leave(&self, node: &str) -> BoxFuture<'_, Result<(), String>> {
        let node = node.to_string();
        self.pending(async move {
            let client = self.client().await?;
            client
                .execute(
                    &format!(
                        "UPDATE sts_cluster_nodes SET left_at = {now}, expires_at = LEAST(expires_at, {now}) WHERE \
                         node_id = $1",
                        now = DB_NOW
                    ),
                    &[&node],
                )
                .await
                .map_err(err)?;
            client
                .execute("UPDATE sts_cluster_leases SET expires_at = 0 WHERE holder = $1", &[&node])
                .await
                .map_err(err)?;
            Ok(())
        })
    }

    fn claim_once(
        &self,
        scope: &str,
        realm: &str,
        key: &str,
        ttl_ms: f64,
        reservation: &str,
        origin: &str,
    ) -> BoxFuture<'_, Result<ClaimAnswer, String>> {
        let args = [scope, realm, key, reservation, origin].map(str::to_string);
        self.pending(async move {
            let [scope, realm, key, reservation, origin] = args;
            let client = self.client().await?;
            let won = client
                .query_opt(
                    &format!(
                        "INSERT INTO sts_cluster_claims (scope, realm, key, reservation, origin, claimed_at, \
                         expires_at) VALUES ($1, $2, $3, $4, $5, {now}, {now} + $6) ON CONFLICT (scope, realm, key) \
                         DO UPDATE SET reservation = EXCLUDED.reservation, origin = EXCLUDED.origin, claimed_at = \
                         EXCLUDED.claimed_at, expires_at = EXCLUDED.expires_at WHERE sts_cluster_claims.expires_at \
                         <= EXCLUDED.claimed_at RETURNING claimed_at",
                        now = DB_NOW
                    ),
                    &[&scope, &realm, &key, &reservation, &origin, &(ttl_ms.max(1.0) as i64)],
                )
                .await
                .map_err(err)?;
            if let Some(row) = won {
                return Ok(ClaimAnswer::Claimed { claimed_at: row.get::<_, i64>("claimed_at") as f64 });
            }
            let held = client
                .query_opt(
                    "SELECT origin, claimed_at, expires_at FROM sts_cluster_claims WHERE scope = $1 AND realm = $2 \
                     AND key = $3",
                    &[&scope, &realm, &key],
                )
                .await
                .map_err(err)?;
            Ok(match held {
                Some(r) => ClaimAnswer::Used {
                    origin: r.get("origin"),
                    claimed_at: r.get::<_, i64>("claimed_at") as f64,
                    expires_at: r.get::<_, i64>("expires_at") as f64,
                },
                None => ClaimAnswer::Used { origin: String::new(), claimed_at: 0.0, expires_at: 0.0 },
            })
        })
    }

    fn release_claim(
        &self,
        scope: &str,
        realm: &str,
        key: &str,
        reservation: &str,
    ) -> BoxFuture<'_, Result<bool, String>> {
        let args = [scope, realm, key, reservation].map(str::to_string);
        self.pending(async move {
            let [scope, realm, key, reservation] = args;
            let n = self
                .client()
                .await?
                .execute(
                    "DELETE FROM sts_cluster_claims WHERE scope = $1 AND realm = $2 AND key = $3 AND reservation = $4",
                    &[&scope, &realm, &key, &reservation],
                )
                .await
                .map_err(err)?;
            Ok(n > 0)
        })
    }
}

/// A shared handle to the driver, as both the store and the cluster's.
pub type SharedPostgres = Arc<PostgresDriver>;

fn change_row(r: &Row) -> ChangeRow {
    ChangeRow {
        seq: r.get("seq"),
        origin: r.get("origin"),
        kind: r.get("kind"),
        realm: r.get("realm"),
        key: r.get("key"),
    }
}

impl ChangeLog for PostgresDriver {
    fn origin(&self) -> String {
        self.origin.clone()
    }

    fn latest_change_seq(&self) -> StoreFuture<'_, i64> {
        Box::pin(async move {
            let row = self
                .client()
                .await?
                .query_one("SELECT COALESCE(MAX(seq), 0)::bigint AS seq FROM sts_changes", &[])
                .await
                .map_err(err)?;
            Ok(row.get("seq"))
        })
    }

    fn changes_since(
        &self,
        after: i64,
        limit: i64,
    ) -> StoreFuture<'_, Vec<ChangeRow>> {
        Box::pin(async move {
            let rows = self
                .client()
                .await?
                .query(
                    "SELECT seq, origin, kind, realm, key FROM sts_changes WHERE seq > $1 ORDER BY seq ASC LIMIT $2",
                    &[&after, &limit],
                )
                .await
                .map_err(err)?;
            Ok(rows.iter().map(change_row).collect())
        })
    }

    fn changes_at(&self, seqs: Vec<i64>) -> StoreFuture<'_, Vec<ChangeRow>> {
        Box::pin(async move {
            let rows = self
                .client()
                .await?
                .query(
                    "SELECT seq, origin, kind, realm, key FROM sts_changes WHERE seq = ANY($1) ORDER BY seq",
                    &[&seqs],
                )
                .await
                .map_err(err)?;
            Ok(rows.iter().map(change_row).collect())
        })
    }

    fn read_entry<'a>(
        &'a self,
        realm: &'a str,
        key: &'a str,
    ) -> StoreFuture<'a, Option<StoredEntry>> {
        Box::pin(async move {
            let row = self
                .client()
                .await?
                .query_opt(
                    &format!("SELECT {} FROM sts_ldap_entries WHERE realm = $1 AND dn_key = $2", ENTRY_COLUMNS),
                    &[&realm, &key],
                )
                .await
                .map_err(err)?;
            match row {
                None => Ok(None),
                Some(r) => PostgresDriver::entry_of(&r).map(Some).ok_or_else(|| {
                    StoreError::new(format!(
                        "{}the directory entry {} is sealed and does not open in this process",
                        tag(codes::STS_STORE_0072),
                        key
                    ))
                }),
            }
        })
    }
}
