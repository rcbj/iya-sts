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
//! * **Entries are sealed where a durable key is held** (#391): the driver
//!   adopts the process's data keys when the keystore starts and writes
//!   through [`EntryCodec`], `dek_keys` included, exactly as Node does.
//! * **The schema is Node's, version [`SCHEMA_VERSION`]**: a store a 1.x
//!   install wrote is opened as it is (the cutover upgrades in place).
//!
//! Not yet here: the side tables a windowed process reads
//! (`sts_sessions`, `sts_minted_index`, the counts), and the queries a
//! windowed worker asks.

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
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

use crate::codec::EntryCodec;
use crate::driver::{
    ChangeLog, ChangeRow, Directory, Driver, KeyMerge, MintedDecided,
    MintedFilter, MintedRow, MintedWrite, PurgeKind, StoreError, StoreFuture,
    StoreResult,
};
use crate::merge::{merge_entry, Outcome};
use crate::model::{
    DirectoryChange, DirectoryOutcome, DirectoryUpsert, StoredEntry,
};
use crate::origin::{
    fence_lock_name, fenced, AdoptOptions, Adopted, Holder, Origin,
    OriginClaim, OriginEngine, ScopeClaim, ORIGIN_SCOPE,
};
use crate::schema::POSTGRES;
use crate::shadow::{AppconfigDelta, RealmsDelta};
use crate::side::{filed, IndexRow, SessionIndex, SESSIONS_HANDLE};

/// The database's clock, in milliseconds.
const DB_NOW: &str = "(extract(epoch from clock_timestamp()) * 1000)::bigint";

/// The schema this driver speaks: `postgres/schema.sql` as the Node
/// service of the same release creates it, read from the model
/// (`schema.rs`), so a store a 1.x install wrote is the store this runtime
/// opens (rcbj, 2026-11-14: the cutover upgrades in place). Its version is
/// written to `sts_schema` on every open, as Node writes it; `ON CONFLICT
/// DO NOTHING` makes the script's row and this one harmless together.
pub const SCHEMA_VERSION: i32 = POSTGRES.version;

const ENTRY_COLUMNS: &str = crate::columns!(
    POSTGRES,
    "sts_ldap_entries",
    realm,
    dn_key,
    dn,
    attrs,
    origin,
    created_at,
    modified_at
);

/// What a statement writes to `sts_changes`.
const CHANGE_WRITE: &str =
    crate::written!(POSTGRES, "sts_changes", origin, kind, realm, key);
/// What a statement writes to `sts_ldap_entries`.
const ENTRY_WRITE: &str = crate::written!(
    POSTGRES,
    "sts_ldap_entries",
    realm,
    dn_key,
    dn,
    attrs,
    origin,
    created_at,
    modified_at,
    name_keys,
    mail_keys,
    uuid_keys,
    class_keys,
    value_keys,
    attr_names,
    dek_keys
);
/// What a statement writes to `sts_keys`.
const KEY_WRITE: &str =
    crate::written!(POSTGRES, "sts_keys", realm, material, written_at);
/// What a statement writes to `sts_minted`.
const MINTED_WRITE: &str = crate::written!(
    POSTGRES,
    "sts_minted",
    handle,
    realm,
    key,
    body,
    written_at,
    expires_at,
    key_sealed
);
/// What a statement writes to `sts_schema`.
const SCHEMA_WRITE: &str = crate::written!(POSTGRES, "sts_schema", version);
/// What a statement writes to `sts_realms`.
const REALM_WRITE: &str = crate::written!(
    POSTGRES,
    "sts_realms",
    id,
    name,
    description,
    created_at,
    overrides,
    domain,
    retiring_at
);
/// What a statement writes to `sts_appconfig`.
const APPCONFIG_WRITE: &str =
    crate::written!(POSTGRES, "sts_appconfig", key, value);
/// What a statement writes to `sts_cluster_nodes`.
const NODE_WRITE: &str = crate::written!(
    POSTGRES,
    "sts_cluster_nodes",
    node_id,
    name,
    mode,
    started_at,
    heartbeat_at,
    expires_at,
    info
);
/// What a statement writes to `sts_cluster_leases`.
const LEASE_WRITE: &str = crate::written!(
    POSTGRES,
    "sts_cluster_leases",
    name,
    holder,
    token,
    acquired_at,
    expires_at
);
/// What a statement writes to `sts_cluster_claims`.
const CLAIM_WRITE: &str = crate::written!(
    POSTGRES,
    "sts_cluster_claims",
    scope,
    realm,
    key,
    reservation,
    origin,
    claimed_at,
    expires_at
);

/// The triggers that keep the directory's counts (`postgres/schema.sql`).
const COUNT_TRIGGERS: [&str; 10] = [
    "sts_ldap_entries_count_insert",
    "sts_ldap_entries_count_update",
    "sts_ldap_entries_count_delete",
    "sts_ldap_entries_count_truncate",
    "sts_ldap_count_deltas_fold_sharded",
    "sts_ldap_entries_dek_insert",
    "sts_ldap_entries_dek_update",
    "sts_ldap_entries_dek_delete",
    "sts_ldap_entries_dek_truncate",
    "sts_ldap_dek_deltas_fold_sharded",
];

/// `sts_sessions`' fifteen columns (`SESSION_INDEX_UPSERT`).
pub(crate) const SESSION_COLUMNS: &str = crate::written!(
    POSTGRES,
    "sts_sessions",
    realm,
    key,
    expires_at,
    last_seen_at,
    started_at,
    subject_key,
    username_key,
    chosen,
    authenticated,
    kind,
    rp_surface,
    parent_key,
    backs_console,
    credential_key,
    partner_relationship
);

/// `sts_minted_index`'s five (`MINTED_INDEX_INSERT`).
pub(crate) const INDEX_COLUMNS: &str = crate::written!(
    POSTGRES,
    "sts_minted_index",
    handle,
    realm,
    index_key,
    key,
    sort_at
);

fn err(e: impl std::fmt::Display) -> StoreError {
    StoreError::new(e.to_string())
}

/// The postgres store.
pub struct PostgresDriver {
    pool: Pool,
    /// This process's name in the change log, and the claim on a stable
    /// one (`origin.rs`).
    origin: Origin,
    /// The data keys entries are sealed under (#391), adopted when the
    /// keystore starts; held weakly, because the keystore holds this
    /// driver. Until then, and where nothing durable seals, the plaintext
    /// form.
    keys: std::sync::RwLock<std::sync::Weak<crate::keystore::DataKeys>>,
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
        Ok(PostgresDriver {
            pool,
            origin: Origin::new()?,
            keys: std::sync::RwLock::new(std::sync::Weak::new()),
        })
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
                &format!("INSERT INTO sts_changes ({change_write}) SELECT $1, k, r, y FROM unnest($2::text[], \
                 $3::text[], $4::text[]) WITH ORDINALITY AS u(k, r, y, n) ORDER BY n",
                change_write = CHANGE_WRITE
            ),
                &[&self.origin.id(), &kinds, &realms, &keys],
            )
            .await
            .map_err(err)?;
        }
        let mut kinds: Vec<&str> = rows.iter().map(|r| r.0).collect();
        kinds.dedup();
        let payload =
            json!({ "from": self.origin.id(), "kinds": kinds, "rows": rows.len() })
                .to_string();
        tx.execute("SELECT pg_notify($1, $2)", &[&CHANNEL, &payload])
            .await
            .map_err(err)?;
        Ok(())
    }

    async fn client(&self) -> StoreResult<deadpool_postgres::Object> {
        self.pool.get().await.map_err(err)
    }

    /// The codec over the adopted data keys (`entryCodec`).
    fn codec(&self) -> EntryCodec {
        self.keys
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .upgrade()
            .map_or_else(EntryCodec::plain, EntryCodec::new)
    }

    fn entry_of(codec: &EntryCodec, row: &Row) -> Option<StoredEntry> {
        let attrs: Json = row.get("attrs");
        let key: String = row.get("dn_key");
        let attributes = codec.open_attributes(&key, &attrs)?;
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

    /// One entry written (`entryParams()`): the attributes sealed, the six
    /// lookups, and `dek_keys` (#623) from the attributes as written and
    /// the blob they were sealed in.
    async fn write_entry(
        codec: &EntryCodec,
        tx: &deadpool_postgres::Transaction<'_>,
        realm: &str,
        key: &str,
        entry: &StoredEntry,
        insert_only: bool,
    ) -> StoreResult<u64> {
        let index = codec.index_of(&entry.attributes);
        let attrs = codec.seal_attributes(realm, key, &entry.attributes);
        let dek_keys = EntryCodec::dek_keys_of(&entry.attributes, &attrs);
        let conflict = if insert_only {
            "ON CONFLICT (realm, dn_key) DO NOTHING"
        } else {
            "ON CONFLICT (realm, dn_key) DO UPDATE SET dn = EXCLUDED.dn, attrs = EXCLUDED.attrs, origin = \
             EXCLUDED.origin, created_at = EXCLUDED.created_at, modified_at = EXCLUDED.modified_at, name_keys = \
             EXCLUDED.name_keys, mail_keys = EXCLUDED.mail_keys, uuid_keys = EXCLUDED.uuid_keys, class_keys = \
             EXCLUDED.class_keys, value_keys = EXCLUDED.value_keys, attr_names = EXCLUDED.attr_names, dek_keys = \
             EXCLUDED.dek_keys"
        };
        let sql = format!(
            "INSERT INTO sts_ldap_entries ({entry_write}) VALUES ($1, $2, $3, $4, $5, $6, $7, \
             $8, $9, $10, $11, $12, $13, $14) {}",
            conflict,
                        entry_write = ENTRY_WRITE
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
                &dek_keys,
            ],
        )
        .await
        .map_err(err)
    }

    /// One upsert, merged against what the store holds (`settle()`).
    async fn settle(
        codec: &EntryCodec,
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
            PostgresDriver::write_entry(
                codec, tx, &row.realm, &row.key, entry, false,
            )
            .await?;
            return Ok(());
        }
        let inserted = PostgresDriver::write_entry(
            codec, tx, &row.realm, &row.key, entry, true,
        )
        .await?;
        if inserted > 0 {
            return Ok(());
        }
        if !again {
            PostgresDriver::write_entry(
                codec, tx, &row.realm, &row.key, entry, false,
            )
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
        let now = found
            .as_ref()
            .and_then(|f| PostgresDriver::entry_of(codec, f));
        Box::pin(PostgresDriver::settle(codec, tx, row, now, false, outcomes))
            .await
    }
}

impl PostgresDriver {
    /// One `sts_sessions` row upserted (`SESSION_INDEX_UPSERT`), in the
    /// flush's transaction.
    async fn index_session(
        tx: &deadpool_postgres::Transaction<'_>,
        realm: &str,
        key: &str,
        index: &SessionIndex,
    ) -> StoreResult<()> {
        let i = index.params();
        let sql = format!(
            "INSERT INTO sts_sessions ({}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
             $15) ON CONFLICT (realm, key) DO UPDATE SET expires_at = EXCLUDED.expires_at, last_seen_at = \
             EXCLUDED.last_seen_at, started_at = EXCLUDED.started_at, subject_key = EXCLUDED.subject_key, \
             username_key = EXCLUDED.username_key, chosen = EXCLUDED.chosen, authenticated = \
             EXCLUDED.authenticated, kind = EXCLUDED.kind, rp_surface = EXCLUDED.rp_surface, parent_key = \
             EXCLUDED.parent_key, backs_console = EXCLUDED.backs_console, credential_key = \
             EXCLUDED.credential_key, partner_relationship = EXCLUDED.partner_relationship",
            SESSION_COLUMNS
        );
        tx.execute(
            &sql,
            &[
                &realm,
                &key,
                &i.expires_at,
                &i.last_seen_at,
                &i.started_at,
                &i.subject_key,
                &i.username_key,
                &i.chosen,
                &i.authenticated,
                &i.kind,
                &i.rp_surface,
                &i.parent_key,
                &i.backs_console,
                &i.credential_key,
                &i.partner_relationship,
            ],
        )
        .await
        .map_err(err)?;
        Ok(())
    }

    /// An ended session's row removed (`SESSION_INDEX_DELETE`).
    async fn unindex_session(
        tx: &deadpool_postgres::Transaction<'_>,
        realm: &str,
        key: &str,
    ) -> StoreResult<()> {
        tx.execute(
            "DELETE FROM sts_sessions WHERE realm = $1 AND key = $2",
            &[&realm, &key],
        )
        .await
        .map_err(err)?;
        Ok(())
    }

    /// A row's index rows replaced by `rows` (MINTED_FLUSH's `ixd` and
    /// `ixi`): a row filed again is KEPT, its `sort_at` updated in place
    /// where it moved, and the rest deleted. An empty `rows` removes them.
    async fn refile(
        tx: &deadpool_postgres::Transaction<'_>,
        at: (&str, &str, &str),
        rows: &[IndexRow],
    ) -> StoreResult<()> {
        let (handle, realm, key) = at;
        let keep: Vec<&str> =
            rows.iter().map(|r| r.index_key.as_str()).collect();
        tx.execute(
            "DELETE FROM sts_minted_index WHERE handle = $1 AND realm = $2 AND key = $3 AND NOT (index_key = \
             ANY($4::text[]))",
            &[&handle, &realm, &key, &keep],
        )
        .await
        .map_err(err)?;
        if rows.is_empty() {
            return Ok(());
        }
        let mut sorted: Vec<&IndexRow> = rows.iter().collect();
        sorted.sort();
        let h: Vec<&str> = sorted.iter().map(|r| r.handle.as_str()).collect();
        let r: Vec<&str> = sorted.iter().map(|r| r.realm.as_str()).collect();
        let i: Vec<&str> =
            sorted.iter().map(|r| r.index_key.as_str()).collect();
        let k: Vec<&str> = sorted.iter().map(|r| r.key.as_str()).collect();
        let at: Vec<Option<i64>> = sorted.iter().map(|r| r.sort_at).collect();
        let sql = format!(
            "INSERT INTO sts_minted_index ({}) SELECT u.h, u.r, u.i, u.k, u.s FROM unnest($1::text[], \
             $2::text[], $3::text[], $4::text[], $5::bigint[]) AS u(h, r, i, k, s) ORDER BY u.h, u.r, u.i, u.k \
             ON CONFLICT (handle, realm, index_key, key) DO UPDATE SET sort_at = EXCLUDED.sort_at WHERE \
             sts_minted_index.sort_at IS DISTINCT FROM EXCLUDED.sort_at",
            INDEX_COLUMNS
        );
        tx.execute(&sql, &[&h, &r, &i, &k, &at])
            .await
            .map_err(err)?;
        Ok(())
    }
}

/// What the store lacks of the model: a table named once, a column as
/// `table.column`.
#[tracing::instrument(level = "debug", skip_all)]
pub(crate) fn missing_of(
    schema: &crate::schema::Schema,
    held: &std::collections::HashSet<(String, String)>,
) -> Vec<String> {
    let mut out = Vec::new();
    for table in schema.tables {
        if !held.iter().any(|(t, _)| t == table.name) {
            out.push(table.name.to_string());
            continue;
        }
        for column in table.columns {
            if !held
                .contains(&(table.name.to_string(), column.name.to_string()))
            {
                out.push(format!("{}.{}", table.name, column.name));
            }
        }
    }
    out
}

/// How long a liveness renewal may take (`renewalBoundMs()`): a third of
/// the lifetime, between a quarter of a second and two seconds.
fn renewal_bound_ms(ttl_ms: f64) -> u64 {
    let ttl = if ttl_ms > 0.0 { ttl_ms } else { 30_000.0 }.max(1000.0);
    ((ttl / 3.0).floor()).clamp(250.0, 2000.0) as u64
}

/// What a delete leaves in a tombstoned store's row.
pub const TOMBSTONE: &str = "$tombstone$1";

fn minted_row(row: &Row) -> MintedRow {
    let key_sealed: Option<String> = row.get("key_sealed");
    MintedRow {
        handle: row.get("handle"),
        realm: row.get("realm"),
        key: row.get("key"),
        key_sealed: key_sealed.unwrap_or_default(),
        body: row.get("body"),
        written_at: row.get::<_, Option<i64>>("written_ms").unwrap_or(0),
        expires_at: row.get("expires_at"),
    }
}

impl Driver for PostgresDriver {
    fn name(&self) -> &'static str {
        "postgres"
    }

    fn adopt_data_keys(&self, keys: &Arc<crate::keystore::DataKeys>) {
        *self
            .keys
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Arc::downgrade(keys);
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
            self.check_origin_fence(&tx).await?;
            tx.execute(
                &format!("INSERT INTO sts_keys ({key_write}) VALUES ($1, $2, now()) ON CONFLICT (realm) DO \
                 UPDATE SET material = EXCLUDED.material, written_at = now()",
                key_write = KEY_WRITE
            ),
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

    fn mints(&self) -> bool {
        true
    }

    // ONLY WHAT IS STILL WORTH HAVING (#333): the realms that exist, a
    // row's own expiry against the caller's clock (the stores computed it
    // on theirs), and a short-lived store's row with no expiry by its age.
    fn load_minted(
        &self,
        filter: MintedFilter,
    ) -> StoreFuture<'_, Vec<MintedRow>> {
        Box::pin(async move {
            let client = self.client().await?;
            let aged =
                filter.stale_before > 0 && !filter.age_handles.is_empty();
            let base = "SELECT handle, realm, key, body, (extract(epoch from written_at) * 1000)::bigint AS \
                        written_ms, expires_at, key_sealed FROM sts_minted WHERE body <> $1 AND realm = \
                        ANY($2::text[]) AND (expires_at IS NULL OR expires_at > $3)";
            let rows = if aged {
                client
                    .query(
                        &format!(
                            "{} AND NOT (expires_at IS NULL AND handle = ANY($4::text[]) AND written_at < \
                             to_timestamp($5::float8 / 1000.0))",
                            base
                        ),
                        &[
                            &TOMBSTONE,
                            &filter.realms,
                            &filter.now_ms,
                            &filter.age_handles,
                            &(filter.stale_before as f64),
                        ],
                    )
                    .await
            } else {
                client
                    .query(base, &[&TOMBSTONE, &filter.realms, &filter.now_ms])
                    .await
            }
            .map_err(err)?;
            Ok(rows.iter().map(minted_row).collect())
        })
    }

    // ONE TRANSACTION FOR THE WHOLE BATCH, IN ONE ORDER BY PRIMARY KEY,
    // upserts and deletes interleaved: every transaction takes its row
    // locks in the same order, which makes a deadlock impossible rather
    // than rare. A tombstoned store's delete leaves TOMBSTONE behind and an
    // upsert of it is refused; a merging store's row is read FOR UPDATE
    // and handed to its merge.
    fn save_minted(
        &self,
        upserts: Vec<MintedWrite>,
        deletes: Vec<MintedWrite>,
    ) -> StoreFuture<'_, MintedDecided> {
        Box::pin(async move {
            let mut statements: Vec<(MintedWrite, bool)> = upserts
                .into_iter()
                .map(|w| (w, true))
                .chain(deletes.into_iter().map(|w| (w, false)))
                .collect();
            statements.sort_by(|a, b| {
                (&a.0.handle, &a.0.realm, &a.0.key).cmp(&(
                    &b.0.handle,
                    &b.0.realm,
                    &b.0.key,
                ))
            });
            let mut decided = MintedDecided::default();
            let mut client = self.client().await?;
            let tx = client.transaction().await.map_err(err)?;
            self.check_origin_fence(&tx).await?;
            let mut changes: Vec<(String, String, String)> = Vec::new();
            for (mut row, upsert) in statements {
                let change_key = format!(
                    "{}.{}",
                    URL_SAFE_NO_PAD.encode(row.handle.as_bytes()),
                    if row.key_sealed.is_empty() {
                        URL_SAFE_NO_PAD.encode(row.key.as_bytes())
                    } else {
                        row.key_sealed.clone()
                    }
                );
                let kind = if row.own { "minted-own" } else { "minted" };
                if !upsert {
                    if row.tombstone {
                        // A TOMBSTONE HAS NO EXPIRY OF ITS OWN: it lives for
                        // persistence.mintedRetention.
                        tx.execute(
                            &format!("INSERT INTO sts_minted ({minted_write}) \
                             VALUES ($1, $2, $3, $4, now(), NULL, $5) ON CONFLICT (handle, realm, key) DO UPDATE \
                             SET body = EXCLUDED.body, written_at = now(), expires_at = NULL, key_sealed = \
                             EXCLUDED.key_sealed",
                minted_write = MINTED_WRITE
            ),
                            &[&row.handle, &row.realm, &row.key, &TOMBSTONE, &row.key_sealed],
                        )
                        .await
                        .map_err(err)?;
                    } else {
                        tx.execute(
                            "DELETE FROM sts_minted WHERE handle = $1 AND realm = $2 AND key = $3",
                            &[&row.handle, &row.realm, &row.key],
                        )
                        .await
                        .map_err(err)?;
                    }
                    // THE SIDE ROWS GO WITH THE BODY (#350, #820).
                    if row.handle == SESSIONS_HANDLE {
                        PostgresDriver::unindex_session(
                            &tx, &row.realm, &row.key,
                        )
                        .await?;
                    }
                    if row.indexed {
                        PostgresDriver::refile(
                            &tx,
                            (&row.handle, &row.realm, &row.key),
                            &[],
                        )
                        .await?;
                    }
                    changes.push((
                        kind.to_string(),
                        row.realm.clone(),
                        change_key,
                    ));
                    continue;
                }
                let mut guarded = row.tombstone;
                if let Some(merge) = row.merge.take() {
                    guarded = true;
                    let found: Option<String> = tx
                        .query_opt(
                            "SELECT body FROM sts_minted WHERE handle = $1 AND realm = $2 AND key = $3 FOR UPDATE",
                            &[&row.handle, &row.realm, &row.key],
                        )
                        .await
                        .map_err(err)?
                        .map(|r| r.get(0));
                    if found.as_deref() == Some(TOMBSTONE) {
                        decided.refused.push((
                            row.handle,
                            row.realm,
                            row.journal_key,
                        ));
                        continue;
                    }
                    if let Some(stored) = found.filter(|f| *f != row.body) {
                        if let Some(merged) = merge(&stored) {
                            if merged.body != row.body {
                                row.body = merged.body;
                                row.expires_at = merged.expires_at;
                                row.session_index = merged.session_index;
                                row.lookups = merged.lookups;
                                row.sort_at = merged.sort_at;
                                decided.merged.push((
                                    row.handle.clone(),
                                    row.realm.clone(),
                                    row.journal_key.clone(),
                                    row.body.clone(),
                                ));
                            }
                        }
                    }
                }
                let expires = row.expires_at.filter(|e| *e > 0);
                let sql = format!(
                    "INSERT INTO sts_minted ({minted_write}) VALUES \
                     ($1, $2, $3, $4, now(), $5, $6) ON CONFLICT (handle, realm, key) DO UPDATE SET body = \
                     EXCLUDED.body, written_at = now(), expires_at = EXCLUDED.expires_at, key_sealed = \
                     EXCLUDED.key_sealed{}",
                    if guarded { " WHERE sts_minted.body <> $7" } else { "" },
                        minted_write = MINTED_WRITE
                );
                let written = if guarded {
                    tx.execute(
                        &sql,
                        &[
                            &row.handle,
                            &row.realm,
                            &row.key,
                            &row.body,
                            &expires,
                            &row.key_sealed,
                            &TOMBSTONE,
                        ],
                    )
                    .await
                } else {
                    tx.execute(
                        &sql,
                        &[
                            &row.handle,
                            &row.realm,
                            &row.key,
                            &row.body,
                            &expires,
                            &row.key_sealed,
                        ],
                    )
                    .await
                }
                .map_err(err)?;
                if guarded && written == 0 {
                    // A REFUSED UPSERT CHANGED NOTHING, so it tells nobody.
                    decided.refused.push((
                        row.handle,
                        row.realm,
                        row.journal_key,
                    ));
                    continue;
                }
                // THE SIDE TABLES, after the body and only for a body that
                // was written (MINTED_FLUSH's `ses` and `ixi` read `ins`).
                if row.handle == SESSIONS_HANDLE {
                    if let Some(index) = row.session_index.as_ref() {
                        PostgresDriver::index_session(
                            &tx, &row.realm, &row.key, index,
                        )
                        .await?;
                    }
                }
                if let Some(lookups) = row.lookups.as_ref() {
                    let rows = filed(
                        &row.handle,
                        &row.realm,
                        &row.key,
                        lookups,
                        row.sort_at,
                    );
                    PostgresDriver::refile(
                        &tx,
                        (&row.handle, &row.realm, &row.key),
                        &rows,
                    )
                    .await?;
                }
                changes.push((kind.to_string(), row.realm.clone(), change_key));
            }
            let refs: Vec<(&str, &str, &str)> = changes
                .iter()
                .map(|(k, r, y)| (k.as_str(), r.as_str(), y.as_str()))
                .collect();
            self.record_changes(&tx, &refs).await?;
            tx.commit().await.map_err(err)?;
            Ok(decided)
        })
    }

    fn read_minted_many(
        &self,
        refs: Vec<(String, String, String)>,
    ) -> StoreFuture<'_, Vec<MintedRow>> {
        Box::pin(async move {
            if refs.is_empty() {
                return Ok(Vec::new());
            }
            let handles: Vec<&str> =
                refs.iter().map(|r| r.0.as_str()).collect();
            let realms: Vec<&str> = refs.iter().map(|r| r.1.as_str()).collect();
            let keys: Vec<&str> = refs.iter().map(|r| r.2.as_str()).collect();
            let client = self.client().await?;
            let rows = client
                .query(
                    "SELECT m.handle, m.realm, m.key, m.body, (extract(epoch from m.written_at) * 1000)::bigint AS \
                     written_ms, m.expires_at, m.key_sealed FROM sts_minted m JOIN unnest($1::text[], $2::text[], \
                     $3::text[]) AS w(handle, realm, key) ON m.handle = w.handle AND m.realm = w.realm AND m.key = \
                     w.key WHERE m.body <> $4",
                    &[&handles, &realms, &keys, &TOMBSTONE],
                )
                .await
                .map_err(err)?;
            Ok(rows.iter().map(minted_row).collect())
        })
    }

    fn purge_tombstones(&self, before_ms: i64) -> StoreFuture<'_, u64> {
        Box::pin(async move {
            let client = self.client().await?;
            client
                .execute(
                    "DELETE FROM sts_minted WHERE body = $1 AND written_at < to_timestamp($2::float8 / 1000.0)",
                    &[&TOMBSTONE, &(before_ms as f64)],
                )
                .await
                .map_err(err)
        })
    }

    // BOUNDED: one batch of `limit` rows by ctid, so a backlog is a few
    // short statements over several runs, never one delete holding locks
    // on the busiest table here.
    fn purge_expired_minted(
        &self,
        kind: PurgeKind,
        limit: i64,
    ) -> StoreFuture<'_, u64> {
        Box::pin(async move {
            let client = self.client().await?;
            let limit = limit.max(1);
            let wrap = |filter: &str| {
                format!(
                    "DELETE FROM sts_minted WHERE ctid = ANY(ARRAY(SELECT ctid FROM sts_minted WHERE {} LIMIT {}))",
                    filter, limit
                )
            };
            match kind {
                PurgeKind::Expired { now_ms } => {
                    client
                        .execute(&wrap("expires_at IS NOT NULL AND expires_at <= $1"), &[&now_ms])
                        .await
                }
                PurgeKind::Orphan { default_realm, before_ms } => {
                    client
                        .execute(
                            &wrap(
                                "realm <> '' AND realm <> $1 AND written_at < to_timestamp($2::float8 / 1000.0) AND NOT \
                                 EXISTS (SELECT 1 FROM sts_realms r WHERE r.id = sts_minted.realm)",
                            ),
                            &[&default_realm, &(before_ms as f64)],
                        )
                        .await
                }
                PurgeKind::Stale { handles, before_ms } => {
                    if handles.is_empty() || before_ms <= 0 {
                        return Ok(0);
                    }
                    client
                        .execute(
                            &wrap(
                                "expires_at IS NULL AND body <> $1 AND handle = ANY($2::text[]) AND written_at < \
                                 to_timestamp($3::float8 / 1000.0)",
                            ),
                            &[&TOMBSTONE, &handles, &(before_ms as f64)],
                        )
                        .await
                }
            }
            .map_err(err)
        })
    }

    fn purge_minted(&self, before_ms: i64) -> StoreFuture<'_, u64> {
        Box::pin(async move {
            let client = self.client().await?;
            client
                .execute(
                    "DELETE FROM sts_minted WHERE written_at < to_timestamp($1::float8 / 1000.0)",
                    &[&(before_ms as f64)],
                )
                .await
                .map_err(err)
        })
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
            self.check_origin_fence(&tx).await?;
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
                        &format!("INSERT INTO sts_keys ({key_write}) VALUES ($1, $2, now()) ON CONFLICT \
                         (realm) DO NOTHING",
                key_write = KEY_WRITE
            ),
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
            // EVERY TABLE AND COLUMN OF THE MODEL, asked of the catalogue
            // in one read: a store the script has not brought level is
            // refused whole, rather than half used.
            let names: Vec<&str> = POSTGRES.table_names();
            let rows = client
                .query(
                    "SELECT table_name::text, column_name::text FROM information_schema.columns WHERE \
                     table_schema = current_schema() AND table_name = ANY($1::text[])",
                    &[&names],
                )
                .await
                .map_err(err)?;
            let held: std::collections::HashSet<(String, String)> = rows
                .iter()
                .map(|r| (r.get::<_, String>(0), r.get::<_, String>(1)))
                .collect();
            let missing = missing_of(&POSTGRES, &held);
            if !missing.is_empty() {
                // Node creates what is missing where its role may, and says
                // STS-STORE-0029 where it may not; this runtime never
                // changes the schema, so it is always the second case.
                return Err(StoreError::new(format!(
                    "{}persistence: the postgres store could not be opened — it is missing {}. This role may \
                     not create what is missing, which is how it is meant to be: build the schema once with \
                     postgres/schema.sql (and postgres/upgrade-1.0.0.sql), run by a superuser or by the owner of \
                     the database. If the objects ARE there, check the search path: this driver names them \
                     unqualified, and the script sets it on the database.",
                    tag(codes::STS_STORE_0029),
                    missing.join(", ")
                )));
            }
            // THE COUNTS ARE THE DATABASE'S ON THIS ENGINE (#618, #623):
            // `sts_ldap_counts` and `sts_ldap_dek_counts` are kept by the
            // statement triggers `postgres/schema.sql` installs, and this
            // driver writes entries counting on them, as Node does. Node's
            // open() installs a missing one where its role may; this runtime
            // changes no schema, so a store without them is refused.
            let triggers = client
                .query(
                    "SELECT tgname::text FROM pg_trigger WHERE NOT tgisinternal AND tgname = ANY($1::text[])",
                    &[&COUNT_TRIGGERS.as_slice()],
                )
                .await
                .map_err(err)?;
            let found: Vec<String> =
                triggers.iter().map(|r| r.get(0)).collect();
            let absent: Vec<&str> = COUNT_TRIGGERS
                .iter()
                .filter(|t| !found.iter().any(|f| f == *t))
                .copied()
                .collect();
            if !absent.is_empty() {
                return Err(StoreError::new(format!(
                    "{}persistence: the postgres store could not be opened — it is missing the counting \
                     trigger(s) {}. Build them with postgres/schema.sql, run by the owner of the database.",
                    tag(codes::STS_STORE_0029),
                    absent.join(", ")
                )));
            }
            // A DIRECTORY TABLE FROM BEFORE SCHEMA VERSION 14 has its lookups
            // GENERATED from plaintext attributes, beside a sealed blob the
            // database cannot read: refused, as Node refuses it (#391's
            // rule is that such a store is recreated, not migrated).
            let generated = client
                .query_opt(
                    "SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND \
                     table_name = 'sts_ldap_entries' AND column_name = 'name_keys' AND upper(is_generated) = \
                     'ALWAYS'",
                    &[],
                )
                .await
                .map_err(err)?;
            if generated.is_some() {
                return Err(StoreError::new(format!(
                    "{}the store's sts_ldap_entries was built before schema version 14: its lookup columns are \
                     generated from plaintext attributes, and this build seals every entry (#391). Recreate the \
                     database (and run postgres/schema.sql as its owner); it is not migrated.",
                    tag(codes::STS_STORE_0074)
                )));
            }
            // `dek_keys` (#623, version 17) is the newest column this driver
            // writes; a store without it is one the script has not brought
            // level.
            let dek_keys = client
                .query_opt(
                    "SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND \
                     table_name = 'sts_ldap_entries' AND column_name = 'dek_keys'",
                    &[],
                )
                .await
                .map_err(err)?;
            if dek_keys.is_none() {
                return Err(StoreError::new(format!(
                    "{}persistence: the postgres store could not be opened — sts_ldap_entries has no dek_keys \
                     column (schema version 17). Bring it level with postgres/schema.sql and \
                     postgres/upgrade-1.0.0.sql, run by the owner of the database.",
                    tag(codes::STS_STORE_0029)
                )));
            }
            client
                .execute(
                    &format!("INSERT INTO sts_schema ({schema_write}) VALUES ($1) ON CONFLICT (version) DO NOTHING",
                schema_write = SCHEMA_WRITE
            ),
                    &[&SCHEMA_VERSION],
                )
                .await
                .map_err(err)?;
            tracing::info!(
                "persistence: the postgres store is open; schema version {} is present.",
                SCHEMA_VERSION
            );
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
            let codec = self.codec();
            for row in &rows {
                match PostgresDriver::entry_of(&codec, row) {
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
            // THE KEYS FIRST (`prepareKeys()`, 2026-10-27): each realm's
            // `directory` data key made, and its row written, before any
            // entry sealed under it — a key first made inside the write
            // would commit after the entries, and every other process's
            // reader would drop them (STS-STORE-0042/0072).
            let codec = self.codec();
            if codec.sealing() {
                let mut realms: Vec<String> =
                    change.upserts.iter().map(|u| u.realm.clone()).collect();
                realms.sort();
                realms.dedup();
                codec.prepare_keys(&realms);
                codec.keys().settle().await;
            }
            let mut client = self.client().await?;
            let tx = client.transaction().await.map_err(err)?;
            self.check_origin_fence(&tx).await?;
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
                    match PostgresDriver::entry_of(&codec, row) {
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
                PostgresDriver::settle(
                    &codec,
                    &tx,
                    row,
                    theirs,
                    true,
                    &mut outcomes,
                )
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
        self.check_origin_fence(&tx).await?;
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
                &format!("INSERT INTO sts_realms ({realm_write}) VALUES \
                 ($1, $2, $3, $4, $5, $11, $12) ON CONFLICT (id) DO UPDATE SET retiring_at = \
                 COALESCE(sts_realms.retiring_at, EXCLUDED.retiring_at), domain = COALESCE(sts_realms.domain, \
                 EXCLUDED.domain), name = CASE WHEN $6 THEN EXCLUDED.name ELSE sts_realms.name END, description = \
                 CASE WHEN $7 THEN EXCLUDED.description ELSE sts_realms.description END, created_at = \
                 COALESCE(sts_realms.created_at, EXCLUDED.created_at), overrides = CASE WHEN $10 THEN \
                 EXCLUDED.overrides ELSE (COALESCE(sts_realms.overrides, '{{}}'::jsonb) - $8::text[]) || $9 END",
                realm_write = REALM_WRITE
            ),
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
        self.check_origin_fence(&tx).await?;
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
                &format!("INSERT INTO sts_appconfig ({appconfig_write}) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = \
                 EXCLUDED.value",
                appconfig_write = APPCONFIG_WRITE
            ),
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
                        "INSERT INTO sts_cluster_nodes ({node_write}) VALUES ($1, $2, 'active-active', {now}, {now}, {now} + $3, $4) ON CONFLICT (node_id) \
                         DO UPDATE SET heartbeat_at = {now}, expires_at = {now} + $3, left_at = 0",
                        node_write = NODE_WRITE,
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
            // BOUNDED (#770, `renewalBoundMs()`): a lock wait the renewal
            // meets — a takeover's UPDATE of the lease row — fails inside
            // the bound instead of holding the heartbeat for the lifetime,
            // and the next heartbeat tries again.
            let bound = std::time::Duration::from_millis(
                renewal_bound_ms(ttl_ms),
            );
            let client = self.client().await?;
            let ttl = ttl_ms as i64;
            let sql = format!(
                        "WITH n AS (UPDATE sts_cluster_nodes SET heartbeat_at = {now}, expires_at = {now} + $2 \
                         WHERE node_id = $1 AND left_at = 0 AND expires_at > {now} RETURNING node_id), l AS (UPDATE \
                         sts_cluster_leases SET expires_at = {now} + $2 WHERE holder = $1 AND expires_at > {now} AND \
                         EXISTS (SELECT 1 FROM n) RETURNING name, token) SELECT (SELECT count(*) FROM n) AS alive, \
                         COALESCE((SELECT json_agg(json_build_object('name', name, 'token', token) ORDER BY name) \
                         FROM l), '[]'::json) AS leases",
                        now = DB_NOW
                    );
            let params: [&(dyn tokio_postgres::types::ToSql + Sync); 2] =
                [&node, &ttl];
            let asked = client.query_one(&sql, &params);
            let row = tokio::time::timeout(bound, asked)
                .await
                .map_err(|_| {
                    err(format!(
                        "the heartbeat did not finish within its bound of {} ms",
                        bound.as_millis()
                    ))
                })?
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
                        "INSERT INTO sts_cluster_leases ({lease_write}) SELECT $1, $2, \
                         1, {now}, {now} + $3 WHERE EXISTS (SELECT 1 FROM sts_cluster_nodes WHERE node_id = $2 AND \
                         left_at = 0 AND expires_at > {now}) ON CONFLICT (name) DO UPDATE SET holder = \
                         EXCLUDED.holder, token = CASE WHEN sts_cluster_leases.holder = EXCLUDED.holder AND \
                         sts_cluster_leases.expires_at > {now} THEN sts_cluster_leases.token ELSE \
                         sts_cluster_leases.token + 1 END, acquired_at = CASE WHEN sts_cluster_leases.holder = \
                         EXCLUDED.holder AND sts_cluster_leases.expires_at > {now} THEN \
                         sts_cluster_leases.acquired_at ELSE EXCLUDED.acquired_at END, expires_at = \
                         EXCLUDED.expires_at WHERE sts_cluster_leases.expires_at <= {now} OR \
                         sts_cluster_leases.holder = EXCLUDED.holder RETURNING holder, token",
                        lease_write = LEASE_WRITE,
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
                        "INSERT INTO sts_cluster_claims ({claim_write}) VALUES ($1, $2, $3, $4, $5, {now}, {now} + $6) ON CONFLICT (scope, realm, key) \
                         DO UPDATE SET reservation = EXCLUDED.reservation, origin = EXCLUDED.origin, claimed_at = \
                         EXCLUDED.claimed_at, expires_at = EXCLUDED.expires_at WHERE sts_cluster_claims.expires_at \
                         <= EXCLUDED.claimed_at RETURNING claimed_at",
                        claim_write = CLAIM_WRITE,
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
        self.origin.id()
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
                Some(r) => PostgresDriver::entry_of(&self.codec(), &r).map(Some).ok_or_else(|| {
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

impl PostgresDriver {
    /// `checkOriginFence()`: in every write transaction, before it writes —
    /// the fence lock share-locked, then the claim read. A lock that is
    /// gone is a successor's claim; a claim that lapsed under our lock is
    /// extended on another connection and read again.
    async fn check_origin_fence(
        &self,
        tx: &deadpool_postgres::Transaction<'_>,
    ) -> StoreResult<()> {
        let Some(held) = self.origin.held() else {
            return Ok(());
        };
        let lock = fence_lock_name("origin", &held.key, &held.reservation);
        let locked = tx
            .query_opt(
                "SELECT 1 FROM sts_cluster_locks WHERE name = $1 FOR SHARE",
                &[&lock],
            )
            .await
            .map_err(err)?;
        if locked.is_none() {
            return Err(fenced(&format!(
                "this process no longer holds its origin {} (its fence lock is gone, so another process took \
                 the claim), so it may not write.",
                held.key
            )));
        }
        let live = format!(
            "SELECT 1 FROM sts_cluster_claims WHERE scope = $1 AND realm = '' AND key = $2 AND reservation = \
             $3 AND expires_at > {}",
            DB_NOW
        );
        let args: [&(dyn tokio_postgres::types::ToSql + Sync); 3] =
            [&ORIGIN_SCOPE, &held.key, &held.reservation];
        if tx.query_opt(&live, &args).await.map_err(err)?.is_some() {
            return Ok(());
        }
        // LAPSED IS NOT TAKEN: the lock is still ours, so nobody wrote
        // under this origin in between.
        if !OriginEngine::reassert(self, &held).await? {
            return Err(fenced(&format!(
                "this process no longer holds its origin {} (another process took it after the claim \
                 lapsed), so it may not write.",
                held.key
            )));
        }
        if tx.query_opt(&live, &args).await.map_err(err)?.is_none() {
            return Err(fenced(&format!(
                "this process no longer holds its origin {} (the claim was not live after it was extended), \
                 so it may not write.",
                held.key
            )));
        }
        Ok(())
    }

    /// `swapOriginLock()`: this reservation's fence lock in, every other
    /// of the key's out.
    async fn swap_origin_lock(
        tx: &deadpool_postgres::Transaction<'_>,
        claim: &OriginClaim,
    ) -> StoreResult<()> {
        let name = fence_lock_name("origin", &claim.key, &claim.reservation);
        let prefix = format!("fence:origin:{}:", claim.key);
        tx.execute(
            "INSERT INTO sts_cluster_locks (name) VALUES ($1) ON CONFLICT (name) DO NOTHING",
            &[&name],
        )
        .await
        .map_err(err)?;
        tx.execute(
            "DELETE FROM sts_cluster_locks WHERE left(name, char_length($1)) = $1 AND name <> $2",
            &[&prefix, &name],
        )
        .await
        .map_err(err)?;
        Ok(())
    }

    /// `adoptOrigin()` (`origin.rs`).
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn adopt_origin(
        &self,
        opts: &AdoptOptions,
    ) -> StoreResult<Adopted> {
        self.origin.adopt(self, opts).await
    }

    /// `renewOrigin()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn renew_origin(&self, ttl_ms: i64) -> StoreResult<bool> {
        self.origin.renew(self, ttl_ms).await
    }

    /// `releaseOrigin()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn release_origin(&self) -> StoreResult<bool> {
        self.origin.release(self).await
    }

    /// `claimsOfScope()` (#884): the live claims of one scope, every realm.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn claims_of_scope(
        &self,
        scope: &str,
    ) -> StoreResult<Vec<ScopeClaim>> {
        let rows = self
            .client()
            .await?
            .query(
                &format!(
                    "SELECT scope, realm, key, reservation, origin FROM sts_cluster_claims WHERE scope = $1 AND \
                     expires_at > {}",
                    DB_NOW
                ),
                &[&scope],
            )
            .await
            .map_err(err)?;
        Ok(rows
            .iter()
            .map(|r| ScopeClaim {
                scope: r.get("scope"),
                realm: r.get("realm"),
                key: r.get("key"),
                reservation: r.get("reservation"),
                origin: r
                    .get::<_, Option<String>>("origin")
                    .unwrap_or_default(),
            })
            .collect())
    }
}

impl OriginEngine for PostgresDriver {
    fn claim_origin<'a>(
        &'a self,
        claim: &'a OriginClaim,
        holder: &'a str,
    ) -> StoreFuture<'a, Result<(), Holder>> {
        Box::pin(async move {
            let mut client = self.client().await?;
            let tx = client.transaction().await.map_err(err)?;
            let won = tx
                .query_opt(
                    &format!(
                        "INSERT INTO sts_cluster_claims ({claim_write}) VALUES ($1, '', $2, $3, $4, {now}, \
                         {now} + $5) ON CONFLICT (scope, realm, key) DO UPDATE SET reservation = \
                         EXCLUDED.reservation, origin = EXCLUDED.origin, claimed_at = EXCLUDED.claimed_at, \
                         expires_at = EXCLUDED.expires_at WHERE sts_cluster_claims.expires_at <= \
                         EXCLUDED.claimed_at RETURNING claimed_at",
                        claim_write = CLAIM_WRITE,
                        now = DB_NOW
                    ),
                    &[&ORIGIN_SCOPE, &claim.key, &claim.reservation, &holder, &claim.ttl_ms],
                )
                .await
                .map_err(err)?;
            if won.is_some() {
                PostgresDriver::swap_origin_lock(&tx, claim).await?;
                tx.commit().await.map_err(err)?;
                return Ok(Ok(()));
            }
            let row = tx
                .query_opt(
                    "SELECT origin, expires_at FROM sts_cluster_claims WHERE scope = $1 AND realm = '' AND key = \
                     $2",
                    &[&ORIGIN_SCOPE, &claim.key],
                )
                .await
                .map_err(err)?;
            tx.commit().await.map_err(err)?;
            Ok(Err(row.map_or_else(Holder::default, |r| Holder {
                origin: r
                    .get::<_, Option<String>>("origin")
                    .unwrap_or_default(),
                expires_at: r.get("expires_at"),
            })))
        })
    }

    fn take_over_from_gone<'a>(
        &'a self,
        claim: &'a OriginClaim,
        holder: &'a str,
        node_id: &'a str,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            let mut client = self.client().await?;
            let tx = client.transaction().await.map_err(err)?;
            let n = tx
                .execute(
                    &format!(
                        "UPDATE sts_cluster_claims c SET reservation = $3, origin = $4, claimed_at = {now}, \
                         expires_at = {now} + $5 WHERE c.scope = $1 AND c.realm = '' AND c.key = $2 AND \
                         position('@' in c.origin) > 0 AND split_part(c.origin, '@', 2) <> $6 AND EXISTS \
                         (SELECT 1 FROM sts_cluster_nodes n WHERE n.node_id = split_part(c.origin, '@', 2) AND \
                         (n.left_at > 0 OR n.expires_at <= {now}))",
                        now = DB_NOW
                    ),
                    &[&ORIGIN_SCOPE, &claim.key, &claim.reservation, &holder, &claim.ttl_ms, &node_id],
                )
                .await
                .map_err(err)?;
            if n == 0 {
                tx.commit().await.map_err(err)?;
                return Ok(false);
            }
            PostgresDriver::swap_origin_lock(&tx, claim).await?;
            tx.commit().await.map_err(err)?;
            Ok(true)
        })
    }

    fn renew_live<'a>(
        &'a self,
        claim: &'a OriginClaim,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            let n = self
                .client()
                .await?
                .execute(
                    &format!(
                        "UPDATE sts_cluster_claims SET expires_at = {now} + $4 WHERE scope = $1 AND realm = '' \
                         AND key = $2 AND reservation = $3 AND expires_at > {now}",
                        now = DB_NOW
                    ),
                    &[&ORIGIN_SCOPE, &claim.key, &claim.reservation, &claim.ttl_ms],
                )
                .await
                .map_err(err)?;
            Ok(n > 0)
        })
    }

    fn reassert<'a>(&'a self, claim: &'a OriginClaim) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            let n = self
                .client()
                .await?
                .execute(
                    &format!(
                        "UPDATE sts_cluster_claims SET expires_at = {} + $4 WHERE scope = $1 AND realm = '' AND \
                         key = $2 AND reservation = $3",
                        DB_NOW
                    ),
                    &[&ORIGIN_SCOPE, &claim.key, &claim.reservation, &claim.ttl_ms],
                )
                .await
                .map_err(err)?;
            if n > 0 {
                tracing::debug!(
                    "persistence: the claim on origin {} had lapsed with nobody else taking it, and was extended.",
                    claim.key
                );
            }
            Ok(n > 0)
        })
    }

    fn release<'a>(&'a self, claim: &'a OriginClaim) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            let mut client = self.client().await?;
            let tx = client.transaction().await.map_err(err)?;
            let n = tx
                .execute(
                    "DELETE FROM sts_cluster_claims WHERE scope = $1 AND realm = '' AND key = $2 AND reservation = \
                     $3",
                    &[&ORIGIN_SCOPE, &claim.key, &claim.reservation],
                )
                .await
                .map_err(err)?;
            if n > 0 {
                tx.execute(
                    "DELETE FROM sts_cluster_locks WHERE name = $1",
                    &[&fence_lock_name(
                        "origin",
                        &claim.key,
                        &claim.reservation,
                    )],
                )
                .await
                .map_err(err)?;
            }
            tx.commit().await.map_err(err)?;
            Ok(n > 0)
        })
    }

    fn clock(&self) -> StoreFuture<'_, i64> {
        Box::pin(async move {
            let row = self
                .client()
                .await?
                .query_one(&format!("SELECT {} AS now", DB_NOW), &[])
                .await
                .map_err(err)?;
            Ok(row.get("now"))
        })
    }
}
