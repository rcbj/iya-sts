// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `persistence.mode=mariadb` (#677): the shared store on the second engine,
//! as `persistence_postgres.js` keeps it there through
//! `directory_portable.js`, `store_portable.js`, `minted_portable.js`,
//! `cluster_portable.js` and `open_mariadb.js`. The schema is
//! `mariadb/schema.sql`, the model's (`schema.rs`), and a store Node wrote
//! on MariaDB is the store this opens, and the reverse.
//!
//! WHAT IS THE SAME AS POSTGRESQL: the contract [`Driver`] states, the
//! sealed entry blob and its keyed lookups (`codec.rs`), the three-way merge
//! (`merge.rs`), the minted rows and their side tables (`side.rs`), the
//! change log's rows, the cluster's tables, the origin claim and its fence
//! (`origin.rs`).
//!
//! WHAT THIS ENGINE DOES DIFFERENTLY, each as Node does it:
//!
//! * **NO NUDGE.** There is no LISTEN/NOTIFY, so the change log is polled
//!   (`dialect.rs`, `POLL_WITHOUT_NUDGE_MS`); a commit writes its rows and
//!   nothing else.
//! * **`sts_ldap_entry_keys` IN PLACE OF GIN.** Every entry written or
//!   deleted has its key rows deleted and its current ones inserted in the
//!   same transaction, from the same index the JSON lookup columns are
//!   filled from: names, mails, UUIDs, group classes, values, the asked
//!   attribute names and the data keys, a value over 344 characters
//!   digested (`tableKey()`).
//! * **THE COUNTS ARE KEPT HERE.** No statement trigger exists, so what each
//!   write replaced is counted in the transaction — per base of the entry's
//!   parent and per counted attribute, and per data key — and folded last,
//!   in key order, into one shard chosen per transaction; a missing count
//!   row is made to exist first by an autocommit `INSERT IGNORE … n = 0` on
//!   another connection, so the fold's UPDATE is the only lock it takes.
//! * **CLAIMS, LEASES AND THE CLOCK** in MariaDB's text
//!   (`cluster_portable.js`): `SYSDATE(6)` as the statement clock, an
//!   expired claim deleted and the claim inserted-or-nothing, a lease
//!   renewed or taken by one UPDATE whose SET writes `holder` last.
//! * **THE RESTORE IS PAGED**, a primary-key page at a time in key order
//!   (`loadRows()`), and so is a removed realm's walk.
//! * **TLS, ALWAYS** (#273): a string that asks for the clear is refused
//!   (STS-STORE-0078); whether the server's chain and name are verified is
//!   `persistence.databaseTlsRejectUnauthorized` or the string's own
//!   `sslmode=verify-ca|verify-full`, against the operator's CA where given.
//! * **WIDTHS.** A DN key over 352 characters or a realm over 64 cannot be
//!   a key here, and a minted value longer than its column is refused rather
//!   than truncated (STS-STORE-0140, STS-STORE-0120).
//! * **EVERY SESSION** is UTC, binary NO PAD comparison, READ COMMITTED,
//!   strict, and counts the rows an UPDATE matched (`FOUND_ROWS`), as
//!   `knex_store.js` sets each connection.
//!
//! WHY `mysql_async`: it is the asynchronous MySQL/MariaDB protocol client
//! of the tokio ecosystem (the runtime's), maintained, with a connection
//! pool, server-side prepared statements, transactions and TLS through
//! `native-tls` — OpenSSL on Linux, the library the postgres connection
//! already uses — without `sqlx`'s compile-time database and macro layer,
//! which a driver whose statements are checked against the model rather
//! than against a live database does not want.
//!
//! A WRITE NAMES ITS ROWS BY COLUMN EQUALITIES (Node's `whereKeys()`,
//! develop 7b4af8837): 11.8 plans a DELETE or UPDATE whose WHERE is a
//! one-tuple row constructor as a table scan, which deadlocked concurrent
//! flushes. Each minted, session, index and claim row is removed here by
//! `a = ? AND b = ?`; the two row constructors Node keeps in its directory
//! flush are kept with it, and `tests/mariadb_write_keys.rs` holds the line.
//!
//! Not here, as on PostgreSQL: a deadlocked transaction is reported rather
//! than run again (Node's `withTransaction()` retries it), and the queries a
//! windowed worker asks beyond [`MariadbDriver::directory_children_page`]
//! and [`MariadbDriver::directory_count`]. So the same commit's other fix —
//! `saveDirectory()` clearing `outcomes` on a retry — has nothing to port:
//! a flush's outcomes are made inside the one attempt that commits them.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use mysql_async::prelude::Queryable;
use mysql_async::{
    Conn, Opts, OptsBuilder, Pool, PoolConstraints, PoolOpts, Row, SslOpts,
    TxOpts, Value,
};
use serde_json::{json, Map, Value as Json};
use sts_cluster::membership::{
    ClaimAnswer, ClusterStore, LeaseAnswer, Renewal,
};
use sts_cluster::schedule::BoxFuture;
use sts_core::errors::codes;
use sts_core::log::tag;

use crate::codec::EntryCodec;
use crate::dialect::MARIADB_NOW as NOW;
use crate::driver::{
    minted_change_key, ChangeLog, ChangeRow, Directory, Driver, KeyMerge,
    MintedDecided, MintedFilter, MintedRow, MintedWrite, PurgeKind, StoreError,
    StoreFuture, StoreResult,
};
use crate::merge::{merge_entry, Outcome};
use crate::model::{
    DirectoryChange, DirectoryOutcome, DirectoryUpsert, StoredEntry,
};
use crate::origin::{
    fence_lock_name, fenced, AdoptOptions, Adopted, Holder, Origin,
    OriginClaim, OriginEngine, ScopeClaim, ORIGIN_SCOPE,
};
use crate::postgres::{missing_of, TOMBSTONE};
use crate::schema::MARIADB;
use crate::shadow::{AppconfigDelta, RealmsDelta};
use crate::side::{filed, IndexRow, SessionIndex, SESSIONS_HANDLE};

/// The schema this driver speaks: `mariadb/schema.sql`'s, from the model.
pub const SCHEMA_VERSION: i32 = MARIADB.version;

/// The widths `mariadb/CLAUDE.md` gives the keyed columns.
const DN_KEY_LIMIT: usize = 352;
const REALM_LIMIT: usize = 64;
/// A lookup value longer than this is digested (`KEY_LIMIT`).
const KEY_LIMIT: usize = 344;
/// A page of the restore and of a removed realm's walk.
const PAGE: usize = 1000;
/// `COUNT_SHARDS`, PostgreSQL's.
const COUNT_SHARDS: u64 = 16;
/// Change-log rows one INSERT carries.
const CHANGE_ROWS_PER_STATEMENT: usize = 500;
/// Count rows one fold statement carries.
const COUNT_ROWS_PER_STATEMENT: usize = 200;
/// Key rows one INSERT carries.
const KEY_ROWS_PER_STATEMENT: usize = 1000;

/// `directory_queries.js`'s ASKED_ATTRIBUTES: the attribute names a holder
/// question asks, which alone are filed as `attr` key rows.
pub const ASKED_ATTRIBUTES: &[&str] = &[
    "federationlink",
    "hobapublickey",
    "memberof",
    "oauthconsent",
    "pwdaccountlockedtime",
    "stsacmeeabkey",
    "stsandroidattestedcredential",
    "stsassertionissuer",
    "stsassertionkeypair",
    "stsbackupcodes",
    "stscertificatehostname",
    "stsclaimsourcetokens",
    "stsdefaultdelegationsemantics",
    "stsdelegationsemantics",
    "stsdeviceandroidkey",
    "stsdevicekey",
    "stsenrolledcertificate",
    "stsenrolledprivatekey",
    "stskrb5keyinfo",
    "stskrb5keys",
    "stsmailfactor",
    "stsmayact",
    "stsnotdelegated",
    "stssamlassertionissuer",
    "stssamlassertionkeypair",
    "stsscepchallenge",
    "stsselfissuedsubject",
    "stsserviceaccount",
    "ststotpcredential",
    "stswebauthncredential",
    "stswebauthnuserhandle",
];

/// `COUNTED_ATTRIBUTES`: the attributes whose holders are counted.
pub const COUNTED_ATTRIBUTES: &[&str] = &["userpassword"];

/// The connection settings every session takes (`MARIADB_SESSION`).
const SESSION: &[&str] = &[
    "SET NAMES utf8mb4 COLLATE utf8mb4_nopad_bin",
    "SET time_zone = '+00:00'",
    "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED",
    "SET SESSION sql_mode = 'STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ENGINE_SUBSTITUTION,PIPES_AS_CONCAT,\
     ERROR_FOR_DIVISION_BY_ZERO'",
];

const ENTRY_READ: &str = crate::columns!(
    MARIADB,
    "sts_ldap_entries",
    realm,
    dn_key,
    dn,
    attrs,
    origin,
    created_at,
    modified_at
);
const ENTRY_LOCK: &str = crate::columns!(
    MARIADB,
    "sts_ldap_entries",
    realm,
    dn_key,
    dn,
    attrs,
    origin,
    created_at,
    modified_at,
    attr_names,
    dek_keys
);
const ENTRY_WRITE: &str = crate::written!(
    MARIADB,
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
const ENTRY_KEY_WRITE: &str =
    crate::written!(MARIADB, "sts_ldap_entry_keys", realm, kind, k, dn_key);
const COUNT_KEY: &str =
    crate::columns!(MARIADB, "sts_ldap_counts", realm, base_key, attribute);
const COUNT_WRITE: &str = crate::written!(
    MARIADB,
    "sts_ldap_counts",
    realm,
    base_key,
    attribute,
    shard,
    n
);
const DEK_COUNT_KEY: &str =
    crate::columns!(MARIADB, "sts_ldap_dek_counts", dek_id);
const DEK_COUNT_WRITE: &str =
    crate::written!(MARIADB, "sts_ldap_dek_counts", dek_id, shard, n);
const CHANGE_WRITE: &str =
    crate::written!(MARIADB, "sts_changes", origin, kind, realm, key);
const CHANGE_READ: &str =
    crate::columns!(MARIADB, "sts_changes", seq, origin, kind, realm, key);
const KEY_WRITE: &str =
    crate::written!(MARIADB, "sts_keys", realm, material, written_at);
const REALM_COLUMNS: &str = crate::written!(
    MARIADB,
    "sts_realms",
    id,
    name,
    description,
    created_at,
    overrides,
    domain,
    retiring_at
);
const APPCONFIG_WRITE: &str =
    crate::written!(MARIADB, "sts_appconfig", key, value);
const MINTED_WRITE: &str = crate::written!(
    MARIADB,
    "sts_minted",
    handle,
    realm,
    key,
    body,
    written_at,
    expires_at,
    key_sealed
);
const SESSION_WRITE: &str = crate::written!(
    MARIADB,
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
const INDEX_WRITE: &str = crate::written!(
    MARIADB,
    "sts_minted_index",
    handle,
    realm,
    index_key,
    key,
    sort_at
);
const NODE_WRITE: &str = crate::written!(
    MARIADB,
    "sts_cluster_nodes",
    node_id,
    name,
    mode,
    version,
    fingerprint,
    started_at,
    heartbeat_at,
    expires_at,
    info
);
const LEASE_WRITE: &str = crate::written!(
    MARIADB,
    "sts_cluster_leases",
    name,
    holder,
    token,
    acquired_at,
    expires_at
);
const CLAIM_WRITE: &str = crate::written!(
    MARIADB,
    "sts_cluster_claims",
    scope,
    realm,
    key,
    reservation,
    origin,
    claimed_at,
    expires_at
);
const LOCK_WRITE: &str = crate::written!(MARIADB, "sts_cluster_locks", name);

/// The bounded columns a minted flush writes (`minted_portable.js`
/// LIMITS), in characters.
const MINTED_LIMITS: &[(&str, usize)] =
    &[("handle", 64), ("realm", 64), ("key", 512)];

fn err(e: impl std::fmt::Display) -> StoreError {
    StoreError::new(e.to_string())
}

/// The server's error number, for the dialect's questions.
fn server_code(e: &mysql_async::Error) -> Option<u16> {
    match e {
        mysql_async::Error::Server(s) => Some(s.code),
        _ => None,
    }
}

fn is_duplicate(e: &mysql_async::Error) -> bool {
    server_code(e) == Some(1062)
}

/// A string bound, `NULL` for none.
fn opt(v: Option<&str>) -> Value {
    v.map_or(Value::NULL, Value::from)
}

/// A column as text, `None` for NULL or a column the row lacks.
fn text(row: &Row, name: &str) -> Option<String> {
    let at = row
        .columns_ref()
        .iter()
        .position(|c| c.name_str() == name)?;
    match row.as_ref(at)? {
        Value::NULL => None,
        Value::Bytes(b) => Some(String::from_utf8_lossy(b).into_owned()),
        other => Some(other.as_sql(true).trim_matches('\'').to_string()),
    }
}

/// A column as a whole number.
fn int(row: &Row, name: &str) -> Option<i64> {
    let at = row
        .columns_ref()
        .iter()
        .position(|c| c.name_str() == name)?;
    match row.as_ref(at)? {
        Value::NULL => None,
        Value::Int(n) => Some(*n),
        Value::UInt(n) => i64::try_from(*n).ok(),
        Value::Bytes(b) => String::from_utf8_lossy(b).trim().parse().ok(),
        Value::Double(d) => Some(*d as i64),
        Value::Float(f) => Some(*f as i64),
        _ => None,
    }
}

/// A JSON column, parsed; a text that is not JSON as the string it is.
fn json_of(row: &Row, name: &str) -> Option<Json> {
    let t = text(row, name)?;
    Some(serde_json::from_str(&t).unwrap_or(Json::String(t)))
}

/// Characters, as a VARCHAR counts them.
fn chars(s: &str) -> usize {
    s.chars().count()
}

/// `tableKey()`: a lookup value as a key row holds it, digested past
/// KEY_LIMIT characters.
// Hot path (every entry written, every beat): no span.
pub fn table_key(form: &str) -> String {
    if chars(form) <= KEY_LIMIT {
        return form.to_string();
    }
    let digest = sts_crypto::jws_alg::Hash::Sha256.digest(form.as_bytes());
    format!(
        "#{}",
        digest
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    )
}

/// `parentOf()`: what follows the first comma, or ''.
fn parent_of(key: &str) -> &str {
    key.find(',').map_or("", |at| &key[at + 1..])
}

/// `basesOf()`: the parent, every suffix after a comma, and '' unless the
/// parent is '' — `sts_ldap_count_bases()`, a duplicate included.
// Hot path (every entry written, every beat): no span.
pub fn bases_of(parent: &str) -> Vec<String> {
    let mut out = vec![parent.to_string()];
    for (i, c) in parent.char_indices() {
        if c == ',' {
            out.push(parent[i + 1..].to_string());
        }
    }
    if !parent.is_empty() {
        out.push(String::new());
    }
    out
}

/// What `dialOptions()` decided of a MariaDB string (#273).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dial {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub database: String,
    pub verify_chain: bool,
    pub verify_hostname: bool,
}

fn decoded(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 3 <= bytes.len() {
            let pair = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(b) = pair.and_then(|p| u8::from_str_radix(p, 16).ok()) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl Dial {
    /// `dialOptions(url, verifyTls, ca, 'mariadb')`: refused where the
    /// string asks for the clear or is not `mariadb://` / `mysql://`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn parse(url: &str, verify_tls: bool) -> StoreResult<Dial> {
        let refuse = |why: &str| {
            StoreError::new(format!(
                "{}persistence: the database connection string is not dialled: {} (#273).",
                tag(codes::STS_STORE_0078),
                why
            ))
        };
        let lower = url.to_ascii_lowercase();
        let (head, query) = match lower.find('?') {
            Some(at) => (&url[..at], &lower[at + 1..]),
            None => (url, ""),
        };
        let mut sslmode = String::new();
        for pair in query.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let (k, v) = (k.trim(), v.trim());
            if (k == "sslmode" && (v == "disable" || v == "allow"))
                || (k == "ssl" && (v == "false" || v == "0"))
                || (k == "ssl-mode" && v == "disabled")
            {
                return Err(refuse(
                    "its sslmode asks for a connection in the clear, which this service never opens; use \
                     sslmode=require, or leave sslmode out",
                ));
            }
            if k == "sslmode" {
                sslmode = v.to_string();
            }
        }
        let rest = if let Some(r) = head.strip_prefix("mariadb://") {
            r
        } else if let Some(r) = head.strip_prefix("mysql://") {
            r
        } else if head.len() > 10
            && (head[..10].eq_ignore_ascii_case("mariadb://")
                || head[..8].eq_ignore_ascii_case("mysql://"))
        {
            head.split_once("://").map_or("", |(_, r)| r)
        } else {
            return Err(refuse(
                "persistence.mode is mariadb and it is not a mariadb:// URL",
            ));
        };
        let (auth, place) = match rest.rfind('@') {
            Some(at) => (&rest[..at], &rest[at + 1..]),
            None => ("", rest),
        };
        let (user, password) = auth.split_once(':').unwrap_or((auth, ""));
        let (hostport, database) = place.split_once('/').unwrap_or((place, ""));
        let (host, port) = if let Some(h) = hostport.strip_prefix('[') {
            let (h, p) = h.split_once(']').unwrap_or((h, ""));
            (h.to_string(), p.trim_start_matches(':').to_string())
        } else {
            let (h, p) = hostport.split_once(':').unwrap_or((hostport, ""));
            (h.to_string(), p.to_string())
        };
        let verify_chain =
            sslmode == "verify-ca" || sslmode == "verify-full" || verify_tls;
        Ok(Dial {
            host: if host.is_empty() {
                "localhost".to_string()
            } else {
                host
            },
            port: port.parse().unwrap_or(3306),
            user: decoded(user),
            password: decoded(password),
            database: decoded(database),
            verify_chain,
            verify_hostname: sslmode != "verify-ca" && verify_chain,
        })
    }
}

/// A transaction's pending count changes (`freshTally()`).
#[derive(Default)]
struct Tally {
    counts: BTreeMap<(String, String, String), i64>,
    deks: BTreeMap<String, i64>,
    removed: HashSet<String>,
}

/// What `contribute()` reads of a row.
struct EntryState {
    realm: String,
    key: String,
    attr_names: Vec<String>,
    dek_keys: Option<Json>,
}

impl Tally {
    /// `contribute()`: one row's part of the counts, added or taken away.
    fn contribute(&mut self, state: &EntryState, sign: i64) {
        let held: Vec<&str> = COUNTED_ATTRIBUTES
            .iter()
            .filter(|a| state.attr_names.iter().any(|n| n == *a))
            .copied()
            .collect();
        for base in bases_of(parent_of(&state.key)) {
            for attribute in std::iter::once("").chain(held.iter().copied()) {
                *self
                    .counts
                    .entry((
                        state.realm.clone(),
                        base.clone(),
                        attribute.to_string(),
                    ))
                    .or_default() += sign;
            }
        }
        if let Some(Json::Object(deks)) = &state.dek_keys {
            for (id, n) in deks {
                let n = n.as_f64().map_or(0, |f| f.floor() as i64);
                if !id.is_empty() && n != 0 {
                    *self.deks.entry(id.clone()).or_default() += sign * n;
                }
            }
        }
    }
}

/// One entry as it is written (`entryWrite()`): its fourteen values, its
/// key rows and its part of the counts.
struct EntryWrite {
    values: Vec<Value>,
    keys: Vec<(String, String)>,
    state: EntryState,
}

fn entry_write(
    codec: &EntryCodec,
    realm: &str,
    key: &str,
    entry: &StoredEntry,
) -> EntryWrite {
    let index = codec.index_of(&entry.attributes);
    let sealed = codec.seal_attributes(realm, key, &entry.attributes);
    let dek_keys = EntryCodec::dek_keys_of(&entry.attributes, &sealed);
    let keys = entry_key_rows(codec, &entry.attributes, &dek_keys);
    let values = vec![
        Value::from(realm),
        Value::from(key),
        Value::from(entry.dn.as_str()),
        Value::from(sealed.to_string()),
        opt(entry.origin.as_deref()),
        opt(entry.created_at.as_deref()),
        opt(entry.modified_at.as_deref()),
        Value::from(json!(index.name_keys).to_string()),
        Value::from(json!(index.mail_keys).to_string()),
        Value::from(json!(index.uuid_keys).to_string()),
        Value::from(json!(index.class_keys).to_string()),
        Value::from(json!(index.value_keys).to_string()),
        Value::from(json!(index.attr_names).to_string()),
        Value::from(dek_keys.to_string()),
    ];
    EntryWrite {
        values,
        keys,
        state: EntryState {
            realm: realm.to_string(),
            key: key.to_string(),
            attr_names: index.attr_names.clone(),
            dek_keys: Some(dek_keys),
        },
    }
}

/// An entry's `sts_ldap_entry_keys` rows (`entryWrite()`'s keys): its
/// names, mails, UUIDs, group classes and values, the asked attribute
/// names and the data keys its blob names, each once, as `(kind, k)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn entry_key_rows(
    codec: &EntryCodec,
    attributes: &indexmap::IndexMap<String, Vec<String>>,
    dek_keys: &Json,
) -> Vec<(String, String)> {
    let index = codec.index_of(attributes);
    let mut keys = Vec::new();
    let mut seen = HashSet::new();
    let mut add = |kind: &str, k: String| {
        if seen.insert(format!("{}\n{}", kind, k)) {
            keys.push((kind.to_string(), k));
        }
    };
    for (kind, list) in [
        ("name", &index.name_keys),
        ("mail", &index.mail_keys),
        ("uuid", &index.uuid_keys),
        ("class", &index.class_keys),
        ("value", &index.value_keys),
    ] {
        for one in list {
            add(kind, table_key(one));
        }
    }
    for name in &index.attr_names {
        if ASKED_ATTRIBUTES.contains(&name.as_str()) {
            add("attr", table_key(name));
        }
    }
    if let Json::Object(deks) = dek_keys {
        for id in deks.keys() {
            add("dek", table_key(id));
        }
    }
    keys
}

/// A locked row as `contribute()` reads it (`stateOfRow()`).
fn state_of_row(row: &Row) -> EntryState {
    EntryState {
        realm: text(row, "realm").unwrap_or_default(),
        key: text(row, "dn_key").unwrap_or_default(),
        attr_names: json_of(row, "attr_names")
            .and_then(|j| {
                j.as_array().map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
            })
            .unwrap_or_default(),
        dek_keys: json_of(row, "dek_keys"),
    }
}

/// `?, ?, …`.
fn marks(n: usize) -> String {
    vec!["?"; n].join(", ")
}

/// `directory_portable.js`'s `keysMatch()` (#1788): the WHERE text naming
/// `count` rows by their key columns, `((a = ? AND b = ?) OR …)`, the values
/// tuple by tuple in the order a row-constructor IN list took them. MariaDB
/// 11.8 plans a DELETE or UPDATE whose WHERE is `(a, b) IN ((?, ?), …)` as a
/// scan (`type ALL`, or `type index` for the counts' fold) though the tuple
/// is the whole key, and a scanning write at READ COMMITTED waits on every
/// row another transaction holds; this plans a range on the key. A SELECT
/// keeps the row constructor, which MariaDB plans on the key.
fn keys_match(columns: &[&str], count: usize) -> String {
    if count == 0 {
        // An empty OR would match every row.
        return "(1 = 0)".to_string();
    }
    let one = format!(
        "({})",
        columns
            .iter()
            .map(|c| format!("{c} = ?"))
            .collect::<Vec<_>>()
            .join(" AND ")
    );
    format!("({})", vec![one.as_str(); count].join(" OR "))
}

/// The MariaDB store.
pub struct MariadbDriver {
    pool: Pool,
    origin: Origin,
    keys: std::sync::RwLock<std::sync::Weak<crate::keystore::DataKeys>>,
}

type Tx = mysql_async::Transaction<'static>;

impl MariadbDriver {
    /// A pool of at most `pool_max` connections to `url`, over TLS; `ca` is
    /// the PEM of the database's own trust anchors, or empty for the
    /// platform's.
    #[tracing::instrument(level = "debug", skip(url, ca))]
    pub fn new(
        url: &str,
        verify_tls: bool,
        ca: &str,
        pool_max: usize,
    ) -> StoreResult<MariadbDriver> {
        let dial = Dial::parse(url, verify_tls)?;
        let mut ssl = SslOpts::default()
            .with_danger_accept_invalid_certs(!dial.verify_chain)
            .with_danger_skip_domain_validation(!dial.verify_hostname);
        if !ca.trim().is_empty() {
            ssl = ssl.with_root_certs(vec![ca.as_bytes().to_vec().into()]);
        }
        let constraints = PoolConstraints::new(0, pool_max.max(2))
            .ok_or_else(|| err("the pool's bounds are not a range"))?;
        let opts = OptsBuilder::default()
            .ip_or_hostname(dial.host.clone())
            .tcp_port(dial.port)
            .user(Some(dial.user.clone()))
            .pass(Some(dial.password.clone()))
            .db_name(Some(dial.database.clone()))
            .prefer_socket(false)
            .client_found_rows(true)
            .ssl_opts(Some(ssl))
            .init(SESSION.iter().map(|s| s.to_string()).collect())
            .pool_opts(PoolOpts::default().with_constraints(constraints));
        Ok(MariadbDriver {
            pool: Pool::new(Opts::from(opts)),
            origin: Origin::new()?,
            keys: std::sync::RwLock::new(std::sync::Weak::new()),
        })
    }

    async fn conn(&self) -> StoreResult<Conn> {
        self.pool.get_conn().await.map_err(err)
    }

    /// A write transaction, its origin fence checked first.
    async fn begin(&self) -> StoreResult<Tx> {
        let mut tx = self
            .pool
            .start_transaction(TxOpts::default())
            .await
            .map_err(err)?;
        self.check_origin_fence(&mut tx).await?;
        Ok(tx)
    }

    fn codec(&self) -> EntryCodec {
        self.keys
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .upgrade()
            .map_or_else(EntryCodec::plain, EntryCodec::new)
    }

    fn entry_of(codec: &EntryCodec, row: &Row) -> Option<StoredEntry> {
        let attrs = json_of(row, "attrs")?;
        let key = text(row, "dn_key")?;
        let attributes = codec.open_attributes(&key, &attrs)?;
        let created = text(row, "created_at").filter(|c| !c.is_empty());
        Some(StoredEntry {
            dn: text(row, "dn").unwrap_or_default(),
            attributes,
            origin: text(row, "origin").filter(|o| !o.is_empty()),
            modified_at: text(row, "modified_at")
                .filter(|m| !m.is_empty())
                .or_else(|| created.clone()),
            created_at: created,
        })
    }

    /// `recordChanges()`: the transaction's rows in the change log, in
    /// order. No nudge: this engine is polled.
    async fn record_changes(
        &self,
        tx: &mut Tx,
        rows: &[(&str, &str, &str)],
    ) -> StoreResult<()> {
        let origin = self.origin.id();
        for chunk in rows.chunks(CHANGE_ROWS_PER_STATEMENT) {
            let mut values = Vec::with_capacity(chunk.len() * 4);
            for (kind, realm, key) in chunk {
                values.push(Value::from(origin.as_str()));
                values.push(Value::from(*kind));
                values.push(Value::from(*realm));
                values.push(Value::from(*key));
            }
            let sql = format!(
                "INSERT INTO sts_changes ({}) VALUES {}",
                CHANGE_WRITE,
                vec!["(?, ?, ?, ?)"; chunk.len()].join(", ")
            );
            tx.exec_drop(sql, values).await.map_err(err)?;
        }
        Ok(())
    }

    /// Locks and reads the rows at some keys, in key order.
    async fn lock_rows(
        tx: &mut Tx,
        keys: &[(String, String)],
    ) -> StoreResult<HashMap<(String, String), Row>> {
        let mut found = HashMap::new();
        for chunk in keys.chunks(500) {
            let mut values = Vec::new();
            for (r, k) in chunk {
                values.push(Value::from(r.as_str()));
                values.push(Value::from(k.as_str()));
            }
            let sql = format!(
                "SELECT {} FROM sts_ldap_entries WHERE (realm, dn_key) IN ({}) ORDER BY realm, dn_key FOR UPDATE",
                ENTRY_LOCK,
                vec!["(?, ?)"; chunk.len()].join(", ")
            );
            let rows: Vec<Row> = tx.exec(sql, values).await.map_err(err)?;
            for row in rows {
                found.insert(
                    (
                        text(&row, "realm").unwrap_or_default(),
                        text(&row, "dn_key").unwrap_or_default(),
                    ),
                    row,
                );
            }
        }
        Ok(found)
    }

    /// One entry written: replacing the row this transaction holds, or
    /// inserted where it holds none. `Ok(false)`: another node inserted
    /// the key since the lock.
    async fn put_entry(
        tx: &mut Tx,
        write: &EntryWrite,
        replace: bool,
    ) -> StoreResult<bool> {
        let mut sql = format!(
            "INSERT INTO sts_ldap_entries ({}) VALUES ({})",
            ENTRY_WRITE,
            marks(14)
        );
        if replace {
            sql.push_str(
                " ON DUPLICATE KEY UPDATE dn = VALUES(dn), attrs = VALUES(attrs), origin = VALUES(origin), \
                 created_at = VALUES(created_at), modified_at = VALUES(modified_at), name_keys = \
                 VALUES(name_keys), mail_keys = VALUES(mail_keys), uuid_keys = VALUES(uuid_keys), class_keys = \
                 VALUES(class_keys), value_keys = VALUES(value_keys), attr_names = VALUES(attr_names), dek_keys \
                 = VALUES(dek_keys)",
            );
        }
        match tx.exec_drop(sql, write.values.clone()).await {
            Ok(()) => Ok(true),
            Err(e) if !replace && is_duplicate(&e) => Ok(false),
            Err(e) => Err(err(e)),
        }
    }

    /// Every written or deleted entry's key rows replaced by its current
    /// ones (`rewriteKeys()`).
    async fn rewrite_keys(
        tx: &mut Tx,
        entries: &BTreeMap<(String, String), Vec<(String, String)>>,
    ) -> StoreResult<()> {
        let ids: Vec<&(String, String)> = entries.keys().collect();
        for chunk in ids.chunks(500) {
            let mut values = Vec::new();
            for (r, k) in chunk {
                values.push(Value::from(r.as_str()));
                values.push(Value::from(k.as_str()));
            }
            tx.exec_drop(
                format!(
                    "DELETE FROM sts_ldap_entry_keys WHERE {}",
                    keys_match(&["realm", "dn_key"], chunk.len())
                ),
                values,
            )
            .await
            .map_err(err)?;
        }
        let mut rows = Vec::new();
        for ((realm, key), keys) in entries {
            for (kind, k) in keys {
                rows.push([
                    realm.as_str(),
                    kind.as_str(),
                    k.as_str(),
                    key.as_str(),
                ]);
            }
        }
        for chunk in rows.chunks(KEY_ROWS_PER_STATEMENT) {
            let values: Vec<Value> = chunk
                .iter()
                .flat_map(|r| r.iter().map(|v| Value::from(*v)))
                .collect();
            tx.exec_drop(
                format!(
                    "INSERT INTO sts_ldap_entry_keys ({}) VALUES {}",
                    ENTRY_KEY_WRITE,
                    vec!["(?, ?, ?, ?)"; chunk.len()].join(", ")
                ),
                values,
            )
            .await
            .map_err(err)?;
        }
        Ok(())
    }

    /// `foldInto()`: one table's changes into one shard, in key order — the
    /// rows made to exist on another connection first, then one UPDATE a
    /// chunk under the transaction.
    async fn fold_into(
        &self,
        tx: &mut Tx,
        table: &str,
        key_columns: &str,
        write_columns: &str,
        rows: &[(Vec<String>, i64)],
        shard: i64,
    ) -> StoreResult<()> {
        let columns: Vec<&str> = key_columns.split(", ").collect();
        let width = columns.len();
        let matching = key_columns
            .split(", ")
            .map(|c| format!("{} = ?", c))
            .collect::<Vec<_>>()
            .join(" AND ");
        for chunk in rows.chunks(COUNT_ROWS_PER_STATEMENT) {
            let keys: Vec<Value> = chunk
                .iter()
                .flat_map(|(k, _)| k.iter().map(|v| Value::from(v.as_str())))
                .collect();
            // MADE TO EXIST OUTSIDE THE TRANSACTION, so the UPDATE below is
            // the only lock taken on them, in key order with the rest.
            let mut ensure = vec![];
            for (k, _) in chunk {
                ensure.extend(k.iter().map(|v| Value::from(v.as_str())));
                ensure.push(Value::from(shard));
            }
            let mut side = self.conn().await?;
            side.exec_drop(
                format!(
                    "INSERT IGNORE INTO {} ({}) VALUES {}",
                    table,
                    write_columns,
                    vec![format!("({}, 0)", marks(width + 1)); chunk.len()]
                        .join(", ")
                ),
                ensure,
            )
            .await
            .map_err(err)?;
            drop(side);
            let mut values = Vec::new();
            let mut cases = Vec::new();
            for (k, n) in chunk {
                cases.push(format!("WHEN {} THEN ?", matching));
                values.extend(k.iter().map(|v| Value::from(v.as_str())));
                values.push(Value::from(*n));
            }
            values.push(Value::from(shard));
            values.extend(keys);
            tx.exec_drop(
                format!(
                    "UPDATE {} SET n = n + CASE {} ELSE 0 END WHERE shard = ? AND {}",
                    table,
                    cases.join(" "),
                    keys_match(&columns, chunk.len())
                ),
                values,
            )
            .await
            .map_err(err)?;
            if tx.affected_rows() != chunk.len() as u64 {
                return Err(StoreError::new(format!(
                    "{}directory_portable: {}: {} count row(s) vanished between their insert and the fold",
                    tag(codes::STS_STORE_0141),
                    table,
                    chunk.len() as u64 - tx.affected_rows()
                )));
            }
        }
        Ok(())
    }

    /// `foldTally()`: last, before COMMIT.
    async fn fold_tally(&self, tx: &mut Tx, tally: &Tally) -> StoreResult<()> {
        let counts: Vec<(Vec<String>, i64)> = tally
            .counts
            .iter()
            .filter(|((realm, _, _), n)| {
                **n != 0 && !tally.removed.contains(realm)
            })
            .map(|((r, b, a), n)| (vec![r.clone(), b.clone(), a.clone()], *n))
            .collect();
        let deks: Vec<(Vec<String>, i64)> = tally
            .deks
            .iter()
            .filter(|(_, n)| **n != 0)
            .map(|(id, n)| (vec![id.clone()], *n))
            .collect();
        if counts.is_empty() && deks.is_empty() {
            return Ok(());
        }
        let shard = sts_crypto::random::random_int(0, COUNT_SHARDS)
            .map_err(|e| StoreError::new(e.to_string()))?
            as i64;
        self.fold_into(
            tx,
            "sts_ldap_counts",
            COUNT_KEY,
            COUNT_WRITE,
            &counts,
            shard,
        )
        .await?;
        self.fold_into(
            tx,
            "sts_ldap_dek_counts",
            DEK_COUNT_KEY,
            DEK_COUNT_WRITE,
            &deks,
            shard,
        )
        .await
    }

    /// `removeRealm()`: what its rows hold under each data key subtracted, a
    /// locked page at a time, then its rows, key rows, counts, registry
    /// row and minted rows deleted.
    async fn remove_realm(
        tx: &mut Tx,
        realm: &str,
        tally: &mut Tally,
    ) -> StoreResult<()> {
        let mut after = String::new();
        loop {
            let rows: Vec<Row> = tx
                .exec(
                    "SELECT realm, dn_key, dek_keys FROM sts_ldap_entries WHERE realm = ? AND dn_key > ? ORDER BY \
                     dn_key LIMIT ? FOR UPDATE",
                    (realm, after.as_str(), PAGE as u64),
                )
                .await
                .map_err(err)?;
            for row in &rows {
                tally.contribute(
                    &EntryState {
                        realm: realm.to_string(),
                        key: text(row, "dn_key").unwrap_or_default(),
                        attr_names: Vec::new(),
                        dek_keys: json_of(row, "dek_keys"),
                    },
                    -1,
                );
            }
            if rows.len() < PAGE {
                break;
            }
            after = rows
                .last()
                .and_then(|r| text(r, "dn_key"))
                .unwrap_or_default();
        }
        tally.removed.insert(realm.to_string());
        for sql in [
            "DELETE FROM sts_ldap_entries WHERE realm = ?",
            "DELETE FROM sts_ldap_entry_keys WHERE realm = ?",
            "DELETE FROM sts_ldap_counts WHERE realm = ?",
            "DELETE FROM sts_realms WHERE id = ?",
            "DELETE FROM sts_minted WHERE realm = ?",
        ] {
            tx.exec_drop(sql, (realm,)).await.map_err(err)?;
        }
        Ok(())
    }

    /// `checkSizes()`: keys MariaDB cannot hold refused before anything is
    /// written.
    fn check_sizes(change: &DirectoryChange) -> StoreResult<()> {
        for u in &change.upserts {
            if chars(&u.key) > DN_KEY_LIMIT || chars(&u.realm) > REALM_LIMIT {
                return Err(StoreError::new(format!(
                    "{}the directory entry {}… in the \"{}\" realm cannot be stored on MariaDB: its DN key is {} \
                     characters (at most {}) or its realm over {}.",
                    tag(codes::STS_STORE_0140),
                    u.key.chars().take(80).collect::<String>(),
                    u.realm.chars().take(64).collect::<String>(),
                    chars(&u.key),
                    DN_KEY_LIMIT,
                    REALM_LIMIT
                )));
            }
        }
        Ok(())
    }

    /// One upsert merged against what the store holds and written, its
    /// key rows and counts noted. A row another node inserted since the
    /// lock is locked and merged against, once.
    async fn settle(
        codec: &EntryCodec,
        tx: &mut Tx,
        row: &DirectoryUpsert,
        mut old: Option<Row>,
        outcomes: &mut Vec<DirectoryOutcome>,
        tally: &mut Tally,
        keyed: &mut BTreeMap<(String, String), Vec<(String, String)>>,
    ) -> StoreResult<bool> {
        let base = row
            .base
            .as_deref()
            .and_then(|b| serde_json::from_str::<Json>(b).ok())
            .and_then(|b| crate::merge::entry_of_json(&b));
        for attempt in 0..2 {
            let theirs = match old.as_ref() {
                Some(r) => Some(MariadbDriver::entry_of(codec, r).ok_or_else(|| {
                    StoreError::new(format!(
                        "{}the directory entry {} in {} is sealed and does not open in this process",
                        tag(codes::STS_STORE_0072),
                        row.key,
                        row.realm
                    ))
                })?),
                None => None,
            };
            outcomes.retain(|o| !(o.realm == row.realm && o.key == row.key));
            let verdict =
                merge_entry(base.as_ref(), Some(&row.entry), theirs.as_ref());
            match verdict.outcome {
                Outcome::Theirs | Outcome::Deleted => {
                    outcomes.push(DirectoryOutcome {
                        realm: row.realm.clone(),
                        key: row.key.clone(),
                        outcome: verdict.outcome,
                        entry: verdict.entry,
                    });
                    return Ok(false);
                }
                Outcome::Merged => outcomes.push(DirectoryOutcome {
                    realm: row.realm.clone(),
                    key: row.key.clone(),
                    outcome: verdict.outcome,
                    entry: verdict.entry.clone(),
                }),
                Outcome::Mine => {}
            }
            let Some(entry) = verdict.entry.as_ref() else {
                return Ok(false);
            };
            let write = entry_write(codec, &row.realm, &row.key, entry);
            let replace = old.is_some();
            if MariadbDriver::put_entry(tx, &write, replace).await? {
                if let Some(o) = old.as_ref() {
                    tally.contribute(&state_of_row(o), -1);
                }
                tally.contribute(&write.state, 1);
                keyed.insert((row.realm.clone(), row.key.clone()), write.keys);
                return Ok(true);
            }
            if attempt == 1 {
                break;
            }
            // Another node inserted it since the lock was asked for: the
            // engine rolled back that statement alone; locked and merged
            // against what it wrote.
            old = MariadbDriver::lock_rows(
                tx,
                &[(row.realm.clone(), row.key.clone())],
            )
            .await?
            .remove(&(row.realm.clone(), row.key.clone()));
        }
        Err(StoreError::new(format!(
            "the directory entry {} in {} was inserted by another writer twice while this flush wrote it",
            row.key, row.realm
        )))
    }

    /// One `sts_sessions` row upserted.
    async fn index_session(
        tx: &mut Tx,
        realm: &str,
        key: &str,
        index: &SessionIndex,
    ) -> StoreResult<()> {
        let i = index.params();
        if chars(realm) > 64
            || chars(key) > 512
            || [
                &i.subject_key,
                &i.username_key,
                &i.rp_surface,
                &i.credential_key,
                &i.partner_relationship,
            ]
            .iter()
            .any(|v| chars(v) > 255)
            || chars(&i.parent_key) > 512
        {
            return Err(StoreError::new(format!(
                "{}persistence: a minted flush holds an sts_sessions value longer than its MariaDB column; the \
                 flush is refused rather than truncated (realm {}).",
                tag(codes::STS_STORE_0120),
                realm
            )));
        }
        tx.exec_drop(
            format!(
                "INSERT INTO sts_sessions ({}) VALUES ({}) ON DUPLICATE KEY UPDATE expires_at = VALUES(expires_at), \
                 last_seen_at = VALUES(last_seen_at), started_at = VALUES(started_at), subject_key = \
                 VALUES(subject_key), username_key = VALUES(username_key), chosen = VALUES(chosen), authenticated \
                 = VALUES(authenticated), kind = VALUES(kind), rp_surface = VALUES(rp_surface), parent_key = \
                 VALUES(parent_key), backs_console = VALUES(backs_console), credential_key = \
                 VALUES(credential_key), partner_relationship = VALUES(partner_relationship)",
                SESSION_WRITE,
                marks(15)
            ),
            vec![
                Value::from(realm),
                Value::from(key),
                Value::from(i.expires_at),
                Value::from(i.last_seen_at),
                Value::from(i.started_at),
                Value::from(i.subject_key.as_str()),
                Value::from(i.username_key.as_str()),
                Value::from(i.chosen),
                Value::from(i.authenticated),
                Value::from(i.kind.as_str()),
                Value::from(i.rp_surface.as_str()),
                Value::from(i.parent_key.as_str()),
                Value::from(i.backs_console),
                Value::from(i.credential_key.as_str()),
                Value::from(i.partner_relationship.as_str()),
            ],
        )
        .await
        .map_err(err)
    }

    /// A row's index rows replaced: those filed again kept (their
    /// `sort_at` updated in place), the rest deleted.
    async fn refile(
        tx: &mut Tx,
        at: (&str, &str, &str),
        rows: &[IndexRow],
    ) -> StoreResult<()> {
        let (handle, realm, key) = at;
        let mut values =
            vec![Value::from(handle), Value::from(realm), Value::from(key)];
        let mut sql = "DELETE FROM sts_minted_index WHERE handle = ? AND realm = ? AND `key` = ?".to_string();
        if !rows.is_empty() {
            sql.push_str(&format!(
                " AND index_key NOT IN ({})",
                marks(rows.len())
            ));
            values
                .extend(rows.iter().map(|r| Value::from(r.index_key.as_str())));
        }
        tx.exec_drop(sql, values).await.map_err(err)?;
        if rows.is_empty() {
            return Ok(());
        }
        if rows.iter().any(|r| chars(&r.index_key) > 128)
            || chars(handle) > 64
            || chars(key) > 512
        {
            return Err(StoreError::new(format!(
                "{}persistence: a minted flush holds an sts_minted_index value longer than its MariaDB column; \
                 the flush is refused rather than truncated (handle {}).",
                tag(codes::STS_STORE_0120),
                handle
            )));
        }
        let mut sorted: Vec<&IndexRow> = rows.iter().collect();
        sorted.sort();
        let values: Vec<Value> = sorted
            .iter()
            .flat_map(|r| {
                [
                    Value::from(r.handle.as_str()),
                    Value::from(r.realm.as_str()),
                    Value::from(r.index_key.as_str()),
                    Value::from(r.key.as_str()),
                    Value::from(r.sort_at),
                ]
            })
            .collect();
        tx.exec_drop(
            format!(
                "INSERT INTO sts_minted_index ({}) VALUES {} ON DUPLICATE KEY UPDATE sort_at = VALUES(sort_at)",
                INDEX_WRITE,
                vec!["(?, ?, ?, ?, ?)"; sorted.len()].join(", ")
            ),
            values,
        )
        .await
        .map_err(err)
    }

    /// One minted body written over whatever is there.
    async fn put_minted(
        tx: &mut Tx,
        at: (&str, &str, &str, &str),
        body: &str,
        expires: Option<i64>,
    ) -> StoreResult<()> {
        let (handle, realm, key, key_sealed) = at;
        tx.exec_drop(
            format!(
                "INSERT INTO sts_minted ({}) VALUES (?, ?, ?, ?, NOW(6), ?, ?) ON DUPLICATE KEY UPDATE body = \
                 VALUES(body), written_at = VALUES(written_at), expires_at = VALUES(expires_at), key_sealed = \
                 VALUES(key_sealed)",
                MINTED_WRITE
            ),
            vec![
                Value::from(handle),
                Value::from(realm),
                Value::from(key),
                Value::from(body),
                Value::from(expires),
                Value::from(key_sealed),
            ],
        )
        .await
        .map_err(err)
    }

    /// `checkOriginFence()` on this engine (`originFence()`).
    async fn check_origin_fence(&self, tx: &mut Tx) -> StoreResult<()> {
        let Some(held) = self.origin.held() else {
            return Ok(());
        };
        let lock = fence_lock_name("origin", &held.key, &held.reservation);
        let locked: Option<i64> = tx
            .exec_first("SELECT 1 FROM sts_cluster_locks WHERE name = ? LOCK IN SHARE MODE", (lock,))
            .await
            .map_err(err)?;
        if locked.is_none() {
            return Err(self.origin.lost(fenced(&format!(
                "this process no longer holds its origin {} (its fence lock is gone, so another process took the \
                 claim), so it may not write.",
                held.key
            ))));
        }
        let live = format!(
            "SELECT 1 FROM sts_cluster_claims WHERE scope = ? AND realm = '' AND `key` = ? AND reservation = ? AND \
             expires_at > {}",
            NOW
        );
        let args = (ORIGIN_SCOPE, held.key.as_str(), held.reservation.as_str());
        if tx
            .exec_first::<i64, _, _>(live.as_str(), args)
            .await
            .map_err(err)?
            .is_some()
        {
            return Ok(());
        }
        if !OriginEngine::reassert(self, &held).await? {
            return Err(self.origin.lost(fenced(&format!(
                "this process no longer holds its origin {} (another process took it after the claim lapsed), \
                 so it may not write.",
                held.key
            ))));
        }
        if tx
            .exec_first::<i64, _, _>(live.as_str(), args)
            .await
            .map_err(err)?
            .is_none()
        {
            return Err(self.origin.lost(fenced(&format!(
                "this process no longer holds its origin {} (the claim was not live after it was extended), so \
                 it may not write.",
                held.key
            ))));
        }
        Ok(())
    }

    /// `installOriginLock()`.
    async fn install_origin_lock(
        tx: &mut Tx,
        claim: &OriginClaim,
    ) -> StoreResult<()> {
        let name = fence_lock_name("origin", &claim.key, &claim.reservation);
        let prefix = format!("fence:origin:{}:", claim.key);
        tx.exec_drop(
            format!(
                "INSERT IGNORE INTO sts_cluster_locks ({}) VALUES (?)",
                LOCK_WRITE
            ),
            (name.as_str(),),
        )
        .await
        .map_err(err)?;
        tx.exec_drop(
            "DELETE FROM sts_cluster_locks WHERE LEFT(name, CHAR_LENGTH(?)) = ? AND name <> ?",
            (prefix.as_str(), prefix.as_str(), name.as_str()),
        )
        .await
        .map_err(err)
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

    /// `setOriginLost()`: who is told when a write is refused because
    /// this process's origin was taken ([`Origin::set_lost`]).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn set_origin_lost(&self, f: Option<crate::origin::OriginLost>) {
        self.origin.set_lost(f);
    }

    /// `releaseOrigin()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn release_origin(&self) -> StoreResult<bool> {
        self.origin.release(self).await
    }

    /// `claimsOfScope()` (#884).
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn claims_of_scope(
        &self,
        scope: &str,
    ) -> StoreResult<Vec<ScopeClaim>> {
        let rows: Vec<Row> = self
            .conn()
            .await?
            .exec(
                format!(
                    "SELECT scope, realm, `key`, reservation, origin FROM sts_cluster_claims WHERE scope = ? AND \
                     expires_at > {}",
                    NOW
                ),
                (scope,),
            )
            .await
            .map_err(err)?;
        Ok(rows
            .iter()
            .map(|r| ScopeClaim {
                scope: text(r, "scope").unwrap_or_default(),
                realm: text(r, "realm").unwrap_or_default(),
                key: text(r, "key").unwrap_or_default(),
                reservation: text(r, "reservation").unwrap_or_default(),
                origin: text(r, "origin").unwrap_or_default(),
            })
            .collect())
    }

    /// One page of a parent's children in key order after `after`
    /// (`directory_queries_mariadb.js`'s one-level `page`), opened.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn directory_children_page(
        &self,
        realm: &str,
        parent: &str,
        after: &str,
        limit: u64,
    ) -> StoreResult<Vec<StoredEntry>> {
        let rows: Vec<Row> = self
            .conn()
            .await?
            .exec(
                format!(
                    "SELECT {} FROM sts_ldap_entries AS e FORCE INDEX (sts_ldap_entries_parent) WHERE e.realm = ? \
                     AND e.parent_key = ? AND e.dn_key > ? ORDER BY e.dn_key LIMIT ?",
                    ENTRY_READ
                ),
                (realm, parent, after, limit.max(1)),
            )
            .await
            .map_err(err)?;
        let codec = self.codec();
        Ok(rows
            .iter()
            .filter_map(|r| MariadbDriver::entry_of(&codec, r))
            .collect())
    }

    /// How many entries are strictly under a base, '' for the realm
    /// (`count`): the kept counter rows, summed.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn directory_count(
        &self,
        realm: &str,
        base: &str,
    ) -> StoreResult<i64> {
        let n: Option<i64> = self
            .conn()
            .await?
            .exec_first(
                "SELECT CAST(COALESCE(SUM(n), 0) AS SIGNED) AS n FROM sts_ldap_counts WHERE realm = ? AND base_key \
                 = ? AND attribute = ''",
                (realm, base),
            )
            .await
            .map_err(err)?;
        Ok(n.unwrap_or(0))
    }
}

fn minted_row(row: &Row) -> MintedRow {
    MintedRow {
        handle: text(row, "handle").unwrap_or_default(),
        realm: text(row, "realm").unwrap_or_default(),
        key: text(row, "key").unwrap_or_default(),
        key_sealed: text(row, "key_sealed").unwrap_or_default(),
        body: text(row, "body").unwrap_or_default(),
        written_at: int(row, "written_ms").unwrap_or(0),
        expires_at: int(row, "expires_at"),
    }
}

/// The epoch-millisecond form of `written_at` (`epochMs()`).
const WRITTEN_MS: &str =
    "CAST(ROUND(UNIX_TIMESTAMP(written_at) * 1000) AS SIGNED) AS written_ms";

impl Driver for MariadbDriver {
    fn name(&self) -> &'static str {
        "mariadb"
    }

    fn dialect(&self) -> Option<&'static dyn crate::dialect::Dialect> {
        Some(&crate::dialect::Mariadb)
    }

    fn adopt_data_keys(&self, keys: &Arc<crate::keystore::DataKeys>) {
        *self
            .keys
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Arc::downgrade(keys);
    }

    fn change_log(&self) -> Option<&dyn ChangeLog> {
        Some(self)
    }

    // `open_mariadb.js`: what exists asked of information_schema, the
    // change log's density checked, the schema version recorded. This
    // runtime creates nothing: a missing table or column is STS-STORE-0029.
    fn open(&self) -> StoreFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self.conn().await?;
            let rows: Vec<(String, String)> = conn
                .query(
                    "SELECT CAST(TABLE_NAME AS CHAR), CAST(COLUMN_NAME AS CHAR) FROM information_schema.COLUMNS \
                     WHERE TABLE_SCHEMA = DATABASE()",
                )
                .await
                .map_err(err)?;
            let held: HashSet<(String, String)> = rows.into_iter().collect();
            let missing = missing_of(&MARIADB, &held);
            if !missing.is_empty() {
                return Err(StoreError::new(format!(
                    "{}persistence: the mariadb store could not be opened — it is missing {}. This role may not \
                     create what is missing, which is how it is meant to be: build the schema once with \
                     mariadb/schema.sql, run by the database's owner.",
                    tag(codes::STS_STORE_0029),
                    missing.join(", ")
                )));
            }
            // THE CHANGE LOG MUST BE DENSE (rcbj on #677), refused on
            // evidence only.
            let dense: Option<(i64, i64)> = conn
                .query_first("SELECT @@auto_increment_increment, @@innodb_autoinc_lock_mode")
                .await
                .map_err(err)?;
            if let Some((increment, lockmode)) = dense {
                if increment != 1 || !(lockmode == 0 || lockmode == 1) {
                    return Err(StoreError::new(format!(
                        "{}the change log's sequence (sts_changes.seq, AUTO_INCREMENT) is not dense on this \
                         server: auto_increment_increment is {} and innodb_autoinc_lock_mode is {}. It must be \
                         auto_increment_increment = 1 and innodb_autoinc_lock_mode = 1 (or 0) in the server's \
                         configuration: an interleaved or stepped sequence leaves gaps every reader would wait \
                         for.",
                        tag(codes::STS_STORE_0091),
                        increment,
                        lockmode
                    )));
                }
            }
            conn.exec_drop(
                "INSERT IGNORE INTO sts_schema (version) VALUES (?)",
                (SCHEMA_VERSION,),
            )
            .await
            .map_err(err)?;
            tracing::info!(
                "persistence: the mariadb store is open; schema version {} is present and this process created \
                 none of it.",
                SCHEMA_VERSION
            );
            Ok(())
        })
    }

    fn close(&self) -> StoreFuture<'_, ()> {
        Box::pin(
            async move { self.pool.clone().disconnect().await.map_err(err) },
        )
    }

    // A PRIMARY-KEY PAGE AT A TIME, in key order (`loadRows()`).
    fn load_directory(&self) -> StoreFuture<'_, Option<Directory>> {
        Box::pin(async move {
            let mut conn = self.conn().await?;
            let codec = self.codec();
            let mut out = Directory::new();
            let mut any = false;
            let mut unreadable = 0;
            let mut after: Option<(String, String)> = None;
            loop {
                let rows: Vec<Row> = match after.as_ref() {
                    None => conn
                        .exec(
                            format!("SELECT {} FROM sts_ldap_entries ORDER BY realm, dn_key LIMIT ?", ENTRY_READ),
                            (PAGE as u64,),
                        )
                        .await,
                    Some((r, k)) => conn
                        .exec(
                            format!(
                                "SELECT {} FROM sts_ldap_entries WHERE realm > ? OR (realm = ? AND dn_key > ?) ORDER \
                                 BY realm, dn_key LIMIT ?",
                                ENTRY_READ
                            ),
                            (r.as_str(), r.as_str(), k.as_str(), PAGE as u64),
                        )
                        .await,
                }
                .map_err(err)?;
                for row in &rows {
                    any = true;
                    match MariadbDriver::entry_of(&codec, row) {
                        Some(entry) => out
                            .entry(text(row, "realm").unwrap_or_default())
                            .or_default()
                            .push(entry),
                        None => unreadable += 1,
                    }
                }
                if rows.len() < PAGE {
                    break;
                }
                after = rows.last().map(|r| {
                    (
                        text(r, "realm").unwrap_or_default(),
                        text(r, "dn_key").unwrap_or_default(),
                    )
                });
            }
            if unreadable > 0 {
                tracing::error!(
                    "{}persistence: {} directory entry/entries are sealed and did not open in this process, and were \
                     not restored.",
                    tag(codes::STS_STORE_0072),
                    unreadable
                );
            }
            Ok(any.then_some(out))
        })
    }

    fn load_realms(&self) -> StoreFuture<'_, Option<Vec<Json>>> {
        Box::pin(async move {
            let rows: Vec<Row> = self
                .conn()
                .await?
                .query(format!(
                    "SELECT {} FROM sts_realms ORDER BY (created_at IS NULL) DESC, created_at ASC, id ASC",
                    REALM_COLUMNS
                ))
                .await
                .map_err(err)?;
            if rows.is_empty() {
                return Ok(None);
            }
            Ok(Some(
                rows.iter()
                    .map(|r| {
                        json!({
                            "id": text(r, "id").unwrap_or_default(),
                            "name": text(r, "name"),
                            "description": text(r, "description"),
                            "domain": text(r, "domain").unwrap_or_default(),
                            "createdAt": int(r, "created_at"),
                            "overrides": json_of(r, "overrides").filter(Json::is_object).unwrap_or_else(|| json!({})),
                            "retiringSince": int(r, "retiring_at"),
                        })
                    })
                    .collect(),
            ))
        })
    }

    fn load_overrides(&self) -> StoreFuture<'_, Option<Map<String, Json>>> {
        Box::pin(async move {
            let rows: Vec<Row> = self
                .conn()
                .await?
                .query("SELECT `key`, value FROM sts_appconfig")
                .await
                .map_err(err)?;
            if rows.is_empty() {
                return Ok(None);
            }
            let mut out = Map::new();
            for r in &rows {
                let value = json_of(r, "value").unwrap_or(Json::Null);
                let raw = match value.get("raw") {
                    Some(raw) if value.is_object() => raw.clone(),
                    _ => value,
                };
                out.insert(text(r, "key").unwrap_or_default(), raw);
            }
            Ok(Some(out))
        })
    }

    // THE FLUSH IS ONE TRANSACTION (`flushBody()`): every row it touches
    // locked first in key order, each upsert merged and written, the
    // deletes, the key rows, the removed realms, the counts folded and the
    // change log last.
    fn save_directory<'a>(
        &'a self,
        change: &'a DirectoryChange,
    ) -> StoreFuture<'a, Vec<DirectoryOutcome>> {
        Box::pin(async move {
            MariadbDriver::check_sizes(change)?;
            let codec = self.codec();
            if codec.sealing() {
                let mut realms: Vec<String> =
                    change.upserts.iter().map(|u| u.realm.clone()).collect();
                realms.sort();
                realms.dedup();
                codec.prepare_keys(&realms);
                codec.keys().settle().await;
            }
            let mut tx = self.begin().await?;
            let id = |realm: &str, key: &str| format!("{}\n{}", realm, key);
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
            locking.dedup();
            let mut locked =
                MariadbDriver::lock_rows(&mut tx, &locking).await?;
            let mut tally = Tally::default();
            let mut keyed = BTreeMap::new();
            let mut outcomes = Vec::new();
            // Each key once: its last upsert.
            let mut chosen: BTreeMap<String, &DirectoryUpsert> =
                BTreeMap::new();
            for u in &change.upserts {
                chosen.insert(id(&u.realm, &u.key), u);
            }
            let mut moved: Vec<(String, String)> = Vec::new();
            for row in chosen.values() {
                let old = locked.remove(&(row.realm.clone(), row.key.clone()));
                if MariadbDriver::settle(
                    &codec,
                    &mut tx,
                    row,
                    old,
                    &mut outcomes,
                    &mut tally,
                    &mut keyed,
                )
                .await?
                {
                    moved.push((row.realm.clone(), row.key.clone()));
                }
            }
            // A ROW BEING DELETED is deleted only if this transaction holds
            // it: one the first lock did not find is read again under a
            // lock, so what is subtracted is what was removed.
            let mut misses: Vec<(String, String)> = change
                .deletes
                .iter()
                .map(|d| (d.realm.clone(), d.key.clone()))
                .filter(|k| !locked.contains_key(k))
                .collect();
            misses.sort_by_key(|(r, k)| id(r, k));
            let late = MariadbDriver::lock_rows(&mut tx, &misses).await?;
            locked.extend(late);
            for d in &change.deletes {
                let at = (d.realm.clone(), d.key.clone());
                if let Some(row) = locked.remove(&at) {
                    tx.exec_drop(
                        "DELETE FROM sts_ldap_entries WHERE realm = ? AND dn_key = ?",
                        (d.realm.as_str(), d.key.as_str()),
                    )
                    .await
                    .map_err(err)?;
                    tally.contribute(&state_of_row(&row), -1);
                }
                keyed.insert(at.clone(), Vec::new());
                moved.push(at);
            }
            MariadbDriver::rewrite_keys(&mut tx, &keyed).await?;
            for realm in &change.removed_realms {
                MariadbDriver::remove_realm(&mut tx, realm, &mut tally).await?;
            }
            self.fold_tally(&mut tx, &tally).await?;
            let rows: Vec<(&str, &str, &str)> = moved
                .iter()
                .map(|(r, k)| ("directory", r.as_str(), k.as_str()))
                .collect();
            self.record_changes(&mut tx, &rows).await?;
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

    fn load_keys(&self) -> StoreFuture<'_, Vec<(String, String)>> {
        Box::pin(async move {
            let rows: Vec<(String, String)> = self
                .conn()
                .await?
                .query("SELECT realm, material FROM sts_keys")
                .await
                .map_err(err)?;
            Ok(rows)
        })
    }

    fn save_keys<'a>(
        &'a self,
        realm: &'a str,
        material: &'a str,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            if chars(realm) > REALM_LIMIT {
                return Err(StoreError::new(format!(
                    "{}sts_keys.realm is {} characters, and the MariaDB column holds {}",
                    tag(codes::STS_STORE_0120),
                    chars(realm),
                    REALM_LIMIT
                )));
            }
            let mut tx = self.begin().await?;
            tx.exec_drop(
                format!(
                    "INSERT INTO sts_keys ({}) VALUES (?, ?, NOW(6)) ON DUPLICATE KEY UPDATE material = \
                     VALUES(material), written_at = VALUES(written_at)",
                    KEY_WRITE
                ),
                (realm, material),
            )
            .await
            .map_err(err)?;
            self.record_changes(&mut tx, &[("keys", realm, "")]).await?;
            tx.commit().await.map_err(err)
        })
    }

    fn merges_keys(&self) -> bool {
        true
    }

    // `mergeKeys()`: the row locked, the merge deciding; a row nobody has
    // yet inserted first-writer-wins and the loser goes round again.
    fn merge_keys<'a>(
        &'a self,
        realm: &'a str,
        merge: KeyMerge,
    ) -> StoreFuture<'a, Option<String>> {
        Box::pin(async move {
            let mut tx = self.begin().await?;
            let current: Option<String> = tx
                .exec_first(
                    "SELECT material FROM sts_keys WHERE realm = ? FOR UPDATE",
                    (realm,),
                )
                .await
                .map_err(err)?;
            let next = merge(current.as_deref()).map_err(StoreError::new)?;
            let Some(next) = next.filter(|n| Some(n) != current.as_ref())
            else {
                tx.commit().await.map_err(err)?;
                return Ok(current);
            };
            if current.is_some() {
                tx.exec_drop("UPDATE sts_keys SET material = ?, written_at = NOW(6) WHERE realm = ?", (next.as_str(), realm))
                    .await
                    .map_err(err)?;
            } else {
                tx.exec_drop(
                    format!("INSERT IGNORE INTO sts_keys ({}) VALUES (?, ?, NOW(6))", KEY_WRITE),
                    (realm, next.as_str()),
                )
                .await
                .map_err(err)?;
                if tx.affected_rows() == 0 {
                    tx.rollback().await.map_err(err)?;
                    return Err(StoreError::new(format!(
                        "the \"{}\" key row was written by another process at the same moment; try again",
                        realm
                    )));
                }
            }
            self.record_changes(&mut tx, &[("keys", realm, "")]).await?;
            tx.commit().await.map_err(err)?;
            Ok(Some(next))
        })
    }

    fn mints(&self) -> bool {
        true
    }

    fn load_minted(
        &self,
        filter: MintedFilter,
    ) -> StoreFuture<'_, Vec<MintedRow>> {
        Box::pin(async move {
            if filter.realms.is_empty() {
                return Ok(Vec::new());
            }
            let mut values: Vec<Value> = vec![Value::from(TOMBSTONE)];
            values
                .extend(filter.realms.iter().map(|r| Value::from(r.as_str())));
            values.push(Value::from(filter.now_ms));
            let mut sql = format!(
                "SELECT handle, realm, `key`, body, {}, expires_at, key_sealed FROM sts_minted WHERE body <> ? AND \
                 realm IN ({}) AND (expires_at IS NULL OR expires_at > ?)",
                WRITTEN_MS,
                marks(filter.realms.len())
            );
            if filter.stale_before > 0 && !filter.age_handles.is_empty() {
                sql.push_str(&format!(
                    " AND NOT (expires_at IS NULL AND handle IN ({}) AND written_at < FROM_UNIXTIME(? / 1000))",
                    marks(filter.age_handles.len())
                ));
                values.extend(
                    filter.age_handles.iter().map(|h| Value::from(h.as_str())),
                );
                values.push(Value::from(filter.stale_before));
            }
            if !filter.null_expiry_handles.is_empty() {
                sql.push_str(&format!(
                    " AND NOT (handle IN ({}) AND expires_at IS NOT NULL)",
                    marks(filter.null_expiry_handles.len())
                ));
                values.extend(
                    filter
                        .null_expiry_handles
                        .iter()
                        .map(|h| Value::from(h.as_str())),
                );
            }
            let rows: Vec<Row> =
                self.conn().await?.exec(sql, values).await.map_err(err)?;
            Ok(rows.iter().map(minted_row).collect())
        })
    }

    // ONE TRANSACTION, IN ONE ORDER BY PRIMARY KEY, upserts and deletes
    // interleaved; a tombstoned store's delete leaves TOMBSTONE behind and
    // an upsert of it is refused; the side tables follow each body written.
    fn save_minted(
        &self,
        upserts: Vec<MintedWrite>,
        deletes: Vec<MintedWrite>,
    ) -> StoreFuture<'_, MintedDecided> {
        Box::pin(async move {
            for row in upserts.iter().chain(deletes.iter()) {
                for (column, limit) in MINTED_LIMITS {
                    let value = match *column {
                        "handle" => &row.handle,
                        "realm" => &row.realm,
                        _ => &row.key,
                    };
                    if chars(value) > *limit {
                        return Err(StoreError::new(format!(
                            "{}persistence: a minted flush holds a sts_minted.{} of {} characters, and the MariaDB \
                             column holds {}; the flush is refused rather than truncated (handle {}, realm {}).",
                            tag(codes::STS_STORE_0120),
                            column,
                            chars(value),
                            limit,
                            row.handle,
                            row.realm
                        )));
                    }
                }
            }
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
            let mut tx = self.begin().await?;
            let mut changes: Vec<(String, String, String)> = Vec::new();
            for (mut row, upsert) in statements {
                let change_key =
                    minted_change_key(&row.handle, &row.key, &row.key_sealed);
                let kind = if row.own { "minted-own" } else { "minted" };
                if !upsert {
                    if row.tombstone {
                        MariadbDriver::put_minted(
                            &mut tx,
                            (
                                &row.handle,
                                &row.realm,
                                &row.key,
                                &row.key_sealed,
                            ),
                            TOMBSTONE,
                            None,
                        )
                        .await?;
                    } else {
                        tx.exec_drop(
                            "DELETE FROM sts_minted WHERE handle = ? AND realm = ? AND `key` = ?",
                            (row.handle.as_str(), row.realm.as_str(), row.key.as_str()),
                        )
                        .await
                        .map_err(err)?;
                    }
                    if row.handle == SESSIONS_HANDLE {
                        tx.exec_drop(
                            "DELETE FROM sts_sessions WHERE realm = ? AND `key` = ?",
                            (row.realm.as_str(), row.key.as_str()),
                        )
                        .await
                        .map_err(err)?;
                    }
                    if row.indexed {
                        MariadbDriver::refile(
                            &mut tx,
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
                let guarded = row.tombstone || row.merge.is_some();
                let mut stored: Option<String> = None;
                if guarded {
                    stored = tx
                        .exec_first(
                            "SELECT body FROM sts_minted WHERE handle = ? AND realm = ? AND `key` = ? FOR UPDATE",
                            (row.handle.as_str(), row.realm.as_str(), row.key.as_str()),
                        )
                        .await
                        .map_err(err)?;
                }
                if guarded && stored.as_deref() == Some(TOMBSTONE) {
                    decided.refused.push((
                        row.handle,
                        row.realm,
                        row.journal_key,
                    ));
                    continue;
                }
                if let Some(merge) = row.merge.take() {
                    if let Some(s) = stored.as_ref().filter(|s| **s != row.body)
                    {
                        if let Some(merged) = merge(s) {
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
                if guarded && stored.is_none() {
                    // A KEY NO ROW HELD AT THE LOCK: inserted or nothing,
                    // and one another flush got to first judged by the rule
                    // under its lock (`freshRun()`).
                    tx.exec_drop(
                        format!("INSERT IGNORE INTO sts_minted ({}) VALUES (?, ?, ?, ?, NOW(6), ?, ?)", MINTED_WRITE),
                        vec![
                            Value::from(row.handle.as_str()),
                            Value::from(row.realm.as_str()),
                            Value::from(row.key.as_str()),
                            Value::from(row.body.as_str()),
                            Value::from(expires),
                            Value::from(row.key_sealed.as_str()),
                        ],
                    )
                    .await
                    .map_err(err)?;
                    if tx.affected_rows() == 0 {
                        let now: Option<String> = tx
                            .exec_first(
                                "SELECT body FROM sts_minted WHERE handle = ? AND realm = ? AND `key` = ? FOR UPDATE",
                                (row.handle.as_str(), row.realm.as_str(), row.key.as_str()),
                            )
                            .await
                            .map_err(err)?;
                        if now.as_deref() == Some(TOMBSTONE) {
                            decided.refused.push((
                                row.handle,
                                row.realm,
                                row.journal_key,
                            ));
                            continue;
                        }
                        MariadbDriver::put_minted(
                            &mut tx,
                            (
                                &row.handle,
                                &row.realm,
                                &row.key,
                                &row.key_sealed,
                            ),
                            &row.body,
                            expires,
                        )
                        .await?;
                    }
                } else {
                    MariadbDriver::put_minted(
                        &mut tx,
                        (&row.handle, &row.realm, &row.key, &row.key_sealed),
                        &row.body,
                        expires,
                    )
                    .await?;
                }
                if row.handle == SESSIONS_HANDLE {
                    if let Some(index) = row.session_index.as_ref() {
                        MariadbDriver::index_session(
                            &mut tx, &row.realm, &row.key, index,
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
                    MariadbDriver::refile(
                        &mut tx,
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
            self.record_changes(&mut tx, &refs).await?;
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
            let mut out = Vec::new();
            let mut conn = self.conn().await?;
            for chunk in refs.chunks(500) {
                let mut values: Vec<Value> = Vec::new();
                for (h, r, k) in chunk {
                    values.push(Value::from(h.as_str()));
                    values.push(Value::from(r.as_str()));
                    values.push(Value::from(k.as_str()));
                }
                values.push(Value::from(TOMBSTONE));
                let rows: Vec<Row> = conn
                    .exec(
                        format!(
                            "SELECT handle, realm, `key`, body, {}, expires_at, key_sealed FROM sts_minted WHERE \
                             (handle, realm, `key`) IN ({}) AND body <> ?",
                            WRITTEN_MS,
                            vec!["(?, ?, ?)"; chunk.len()].join(", ")
                        ),
                        values,
                    )
                    .await
                    .map_err(err)?;
                out.extend(rows.iter().map(minted_row));
            }
            Ok(out)
        })
    }

    // `minted_queries.js`'s MariaDB `minted.newest`: a plain JOIN, since
    // InnoDB walks `sts_minted_index_sort` and probes the primary key for
    // each of its rows either way.
    fn read_minted_newest<'a>(
        &'a self,
        handle: &'a str,
        realm: &'a str,
        now_ms: i64,
        limit: i64,
    ) -> StoreFuture<'a, Vec<MintedRow>> {
        Box::pin(async move {
            let mut conn = self.conn().await?;
            let rows: Vec<Row> = conn
                .exec(
                    "SELECT m.handle, m.realm, m.`key`, m.body, CAST(ROUND(UNIX_TIMESTAMP(m.written_at) * 1000) AS \
                     SIGNED) AS written_ms, m.expires_at, m.key_sealed FROM sts_minted_index i JOIN sts_minted m ON \
                     m.handle = i.handle AND m.realm = i.realm AND m.`key` = i.`key` WHERE i.handle = ? AND \
                     i.realm = ? AND i.sort_at IS NOT NULL AND m.body <> ? AND (m.expires_at IS NULL OR \
                     m.expires_at > ?) ORDER BY i.sort_at DESC, i.`key` DESC LIMIT ?",
                    (
                        handle,
                        realm,
                        TOMBSTONE,
                        now_ms,
                        crate::driver::newest_limit(limit),
                    ),
                )
                .await
                .map_err(err)?;
            Ok(rows.iter().map(minted_row).collect())
        })
    }

    fn purge_tombstones(&self, before_ms: i64) -> StoreFuture<'_, u64> {
        Box::pin(async move {
            let mut conn = self.conn().await?;
            conn.exec_drop(
                "DELETE FROM sts_minted WHERE body = ? AND written_at < FROM_UNIXTIME(? / 1000)",
                (TOMBSTONE, before_ms),
            )
            .await
            .map_err(err)?;
            Ok(conn.affected_rows())
        })
    }

    // BOUNDED: MariaDB deletes with LIMIT (it refuses a LIMIT inside IN).
    fn purge_expired_minted(
        &self,
        kind: PurgeKind,
        limit: i64,
    ) -> StoreFuture<'_, u64> {
        Box::pin(async move {
            let limit = limit.max(1);
            let mut conn = self.conn().await?;
            match kind {
                PurgeKind::Expired { now_ms } => {
                    conn.exec_drop(
                        "DELETE FROM sts_minted WHERE expires_at IS NOT NULL AND expires_at <= ? LIMIT ?",
                        (now_ms, limit),
                    )
                    .await
                }
                PurgeKind::Orphan { default_realm, before_ms } => {
                    conn.exec_drop(
                        "DELETE FROM sts_minted WHERE realm <> '' AND realm <> ? AND written_at < FROM_UNIXTIME(? / \
                         1000) AND NOT EXISTS (SELECT 1 FROM sts_realms r WHERE r.id = sts_minted.realm) LIMIT ?",
                        (default_realm.as_str(), before_ms, limit),
                    )
                    .await
                }
                PurgeKind::Stale { handles, before_ms } => {
                    if handles.is_empty() || before_ms <= 0 {
                        return Ok(0);
                    }
                    let mut values: Vec<Value> = vec![Value::from(TOMBSTONE)];
                    values.extend(handles.iter().map(|h| Value::from(h.as_str())));
                    values.push(Value::from(before_ms));
                    values.push(Value::from(limit));
                    conn.exec_drop(
                        format!(
                            "DELETE FROM sts_minted WHERE expires_at IS NULL AND body <> ? AND handle IN ({}) AND \
                             written_at < FROM_UNIXTIME(? / 1000) LIMIT ?",
                            marks(handles.len())
                        ),
                        values,
                    )
                    .await
                }
            }
            .map_err(err)?;
            Ok(conn.affected_rows())
        })
    }

    fn purge_minted(&self, before_ms: i64) -> StoreFuture<'_, u64> {
        Box::pin(async move {
            let mut conn = self.conn().await?;
            conn.exec_drop("DELETE FROM sts_minted WHERE written_at < FROM_UNIXTIME(? / 1000)", (before_ms,))
                .await
                .map_err(err)?;
            Ok(conn.affected_rows())
        })
    }
}

impl MariadbDriver {
    // `writeRealm()`: each row under its lock, as the native upsert writes
    // it — the retiring mark, the domain and the creation time kept once
    // set, the name and description replaced only when the delta says, the
    // overrides replaced whole or merged with the cleared keys removed.
    async fn write_realms(
        &self,
        delta: &RealmsDelta,
        whole: bool,
    ) -> StoreResult<()> {
        let mut tx = self.begin().await?;
        for id in &delta.removed {
            tx.exec_drop("DELETE FROM sts_realms WHERE id = ?", (id.as_str(),))
                .await
                .map_err(err)?;
        }
        for one in &delta.upserts {
            let row = &one.row;
            let get =
                |k: &str| row.get(k).and_then(Json::as_str).map(str::to_string);
            let id = get("id").unwrap_or_default();
            if chars(&id) > REALM_LIMIT {
                return Err(StoreError::new(format!(
                    "{}sts_realms.id is {} characters, and the MariaDB column holds {}",
                    tag(codes::STS_STORE_0120),
                    chars(&id),
                    REALM_LIMIT
                )));
            }
            let retiring = row
                .get("retiringSince")
                .and_then(Json::as_f64)
                .filter(|n| *n > 0.0)
                .map(|n| n as i64);
            let domain = get("domain").filter(|d| !d.is_empty());
            let created = row.get("createdAt").and_then(Json::as_i64);
            let mut inserted = false;
            for _ in 0..2 {
                let stored: Option<Row> = tx
                    .exec_first(
                        "SELECT name, description, created_at, overrides, domain, retiring_at FROM sts_realms WHERE \
                         id = ? FOR UPDATE",
                        (id.as_str(),),
                    )
                    .await
                    .map_err(err)?;
                if let Some(s) = stored {
                    let overrides = if whole {
                        row.get("overrides")
                            .cloned()
                            .unwrap_or_else(|| json!({}))
                    } else {
                        let mut held = json_of(&s, "overrides")
                            .and_then(|j| j.as_object().cloned())
                            .unwrap_or_default();
                        for k in &one.cleared {
                            held.remove(k);
                        }
                        for (k, v) in &one.set {
                            held.insert(k.clone(), v.clone());
                        }
                        Json::Object(held)
                    };
                    let mut sets = vec!["overrides = ?".to_string()];
                    let mut values: Vec<Value> =
                        vec![Value::from(overrides.to_string())];
                    if one.name {
                        sets.push("name = ?".into());
                        values.push(opt(get("name").as_deref()));
                    }
                    if one.description {
                        sets.push("description = ?".into());
                        values.push(opt(get("description").as_deref()));
                    }
                    if int(&s, "created_at").is_none() {
                        sets.push("created_at = ?".into());
                        values.push(Value::from(created));
                    }
                    if text(&s, "domain").is_none() {
                        sets.push("domain = ?".into());
                        values.push(opt(domain.as_deref()));
                    }
                    if int(&s, "retiring_at").is_none() {
                        sets.push("retiring_at = ?".into());
                        values.push(Value::from(retiring));
                    }
                    values.push(Value::from(id.as_str()));
                    tx.exec_drop(
                        format!(
                            "UPDATE sts_realms SET {} WHERE id = ?",
                            sets.join(", ")
                        ),
                        values,
                    )
                    .await
                    .map_err(err)?;
                    inserted = true;
                    break;
                }
                tx.exec_drop(
                    format!("INSERT IGNORE INTO sts_realms ({}) VALUES (?, ?, ?, ?, ?, ?, ?)", REALM_COLUMNS),
                    vec![
                        Value::from(id.as_str()),
                        opt(get("name").as_deref()),
                        opt(get("description").as_deref()),
                        Value::from(created),
                        Value::from(row.get("overrides").cloned().unwrap_or_else(|| json!({})).to_string()),
                        opt(domain.as_deref()),
                        Value::from(retiring),
                    ],
                )
                .await
                .map_err(err)?;
                if tx.affected_rows() > 0 {
                    inserted = true;
                    break;
                }
            }
            if !inserted {
                return Err(StoreError::new(format!(
                    "{}the \"{}\" row of sts_realms was inserted and removed by other writers while this one waited, \
                     twice; nothing was written.",
                    tag(codes::STS_STORE_0101),
                    id
                )));
            }
        }
        if !delta.upserts.is_empty() || !delta.removed.is_empty() {
            self.record_changes(&mut tx, &[("realms", "", "")]).await?;
        }
        tx.commit().await.map_err(err)
    }

    async fn write_overrides(&self, delta: &AppconfigDelta) -> StoreResult<()> {
        let mut tx = self.begin().await?;
        if !delta.cleared.is_empty() {
            tx.exec_drop(
                format!(
                    "DELETE FROM sts_appconfig WHERE `key` IN ({})",
                    marks(delta.cleared.len())
                ),
                delta
                    .cleared
                    .iter()
                    .map(|k| Value::from(k.as_str()))
                    .collect::<Vec<_>>(),
            )
            .await
            .map_err(err)?;
        }
        for (key, value) in &delta.set {
            if chars(key) > 255 {
                return Err(StoreError::new(format!(
                    "{}sts_appconfig.key is {} characters, and the MariaDB column holds 255",
                    tag(codes::STS_STORE_0120),
                    chars(key)
                )));
            }
            tx.exec_drop(
                format!(
                    "INSERT INTO sts_appconfig ({}) VALUES (?, ?) ON DUPLICATE KEY UPDATE value = VALUES(value)",
                    APPCONFIG_WRITE
                ),
                (key.as_str(), json!({ "raw": value }).to_string()),
            )
            .await
            .map_err(err)?;
        }
        if !delta.is_empty() {
            self.record_changes(&mut tx, &[("appconfig", "", "")])
                .await?;
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

fn change_row(r: &Row) -> ChangeRow {
    ChangeRow {
        seq: int(r, "seq").unwrap_or(0),
        origin: text(r, "origin").unwrap_or_default(),
        kind: text(r, "kind").unwrap_or_default(),
        realm: text(r, "realm").unwrap_or_default(),
        key: text(r, "key").unwrap_or_default(),
    }
}

impl ChangeLog for MariadbDriver {
    fn origin(&self) -> String {
        self.origin.id()
    }

    fn latest_change_seq(&self) -> StoreFuture<'_, i64> {
        Box::pin(async move {
            let n: Option<i64> = self
                .conn()
                .await?
                .query_first("SELECT CAST(COALESCE(MAX(seq), 0) AS SIGNED) FROM sts_changes")
                .await
                .map_err(err)?;
            Ok(n.unwrap_or(0))
        })
    }

    fn changes_since(
        &self,
        after: i64,
        limit: i64,
    ) -> StoreFuture<'_, Vec<ChangeRow>> {
        Box::pin(async move {
            let rows: Vec<Row> = self
                .conn()
                .await?
                .exec(
                    format!("SELECT {} FROM sts_changes WHERE seq > ? ORDER BY seq ASC LIMIT ?", CHANGE_READ),
                    (after, limit.max(1)),
                )
                .await
                .map_err(err)?;
            Ok(rows.iter().map(change_row).collect())
        })
    }

    fn changes_at(&self, seqs: Vec<i64>) -> StoreFuture<'_, Vec<ChangeRow>> {
        Box::pin(async move {
            if seqs.is_empty() {
                return Ok(Vec::new());
            }
            let rows: Vec<Row> = self
                .conn()
                .await?
                .exec(
                    format!("SELECT {} FROM sts_changes WHERE seq IN ({}) ORDER BY seq", CHANGE_READ, marks(seqs.len())),
                    seqs.iter().map(|s| Value::from(*s)).collect::<Vec<_>>(),
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
            let row: Option<Row> = self
                .conn()
                .await?
                .exec_first(
                    format!("SELECT {} FROM sts_ldap_entries WHERE realm = ? AND dn_key = ?", ENTRY_READ),
                    (realm, key),
                )
                .await
                .map_err(err)?;
            match row {
                None => Ok(None),
                Some(r) => MariadbDriver::entry_of(&self.codec(), &r).map(Some).ok_or_else(|| {
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

impl ClusterStore for MariadbDriver {
    fn now(&self) -> BoxFuture<'_, Result<f64, String>> {
        self.pending(async move {
            let n: Option<i64> = self
                .conn()
                .await?
                .query_first(format!("SELECT {}", NOW))
                .await
                .map_err(err)?;
            Ok(n.unwrap_or(0) as f64)
        })
    }

    // JOINING (`joinCluster()` on this engine): the join serialised on a
    // row of `sts_cluster_locks` (`portable.serialize('cluster.join')`),
    // the dead swept, every live node of another mode a refusal
    // (STS-CLUSTER-0002), and the row inserted; the postgres driver's join
    // says the rest.
    fn join(
        &self,
        node: &str,
        ttl_ms: f64,
        info: Json,
    ) -> BoxFuture<'_, Result<(), String>> {
        let node = node.to_string();
        self.pending(async move {
            let field = |k: &str| info.get(k).and_then(Json::as_str).unwrap_or("").to_string();
            let (name, version) = (field("name"), field("version"));
            let mode = Some(field("mode")).filter(|m| !m.is_empty()).unwrap_or_else(|| "active-active".to_string());
            let mut tx = self.pool.start_transaction(TxOpts::default()).await.map_err(err)?;
            tx.exec_drop(format!("INSERT IGNORE INTO sts_cluster_locks ({}) VALUES (?)", LOCK_WRITE), ("cluster.join",))
                .await
                .map_err(err)?;
            tx.exec_drop("SELECT name FROM sts_cluster_locks WHERE name = ? FOR UPDATE", ("cluster.join",))
                .await
                .map_err(err)?;
            tx.exec_drop(
                format!("DELETE FROM sts_cluster_nodes WHERE expires_at < {} - ?", NOW),
                (crate::postgres::DEAD_NODE_RETENTION_MS,),
            )
            .await
            .map_err(err)?;
            let live: Vec<Row> = tx
                .exec(
                    format!(
                        "SELECT node_id, name, mode, version FROM sts_cluster_nodes WHERE left_at = 0 AND expires_at > \
                         {} AND node_id <> ?",
                        NOW
                    ),
                    (node.as_str(),),
                )
                .await
                .map_err(err)?;
            let differing: Vec<String> = live
                .iter()
                .filter(|r| text(r, "mode").as_deref() != Some(mode.as_str()))
                .map(|r| {
                    crate::postgres::differing_of(
                        &text(r, "name").unwrap_or_default(),
                        &text(r, "node_id").unwrap_or_default(),
                        &text(r, "mode").unwrap_or_default(),
                        &text(r, "version").unwrap_or_default(),
                    )
                })
                .collect();
            if !differing.is_empty() {
                tx.rollback().await.map_err(err)?;
                return Err(StoreError::new(crate::postgres::refused_join(&mode, &differing)));
            }
            tx.exec_drop(
                format!(
                    "INSERT INTO sts_cluster_nodes ({w}) VALUES (?, ?, ?, ?, '', {now}, {now}, {now} + ?, ?)",
                    w = NODE_WRITE,
                    now = NOW
                ),
                vec![
                    Value::from(node.as_str()),
                    Value::from(name.as_str()),
                    Value::from(mode.as_str()),
                    Value::from(version.as_str()),
                    Value::from(ttl_ms as i64),
                    Value::from(info.to_string()),
                ],
            )
            .await
            .map_err(err)?;
            tx.commit().await.map_err(err)?;
            tracing::info!("cluster: node {} ({}) joined in {} mode; {} other live node(s).", node, name, mode, live.len());
            Ok(())
        })
    }

    // Three bounded statements, not one transaction: wrapping them would
    // put the heartbeat behind a lock it holds itself (`heartbeat()`).
    fn heartbeat(
        &self,
        node: &str,
        ttl_ms: f64,
    ) -> BoxFuture<'_, Result<Renewal, String>> {
        let node = node.to_string();
        self.pending(async move {
            let bound = std::time::Duration::from_millis(crate::postgres::renewal_bound_ms(ttl_ms));
            let ttl = ttl_ms as i64;
            let work = async {
                let mut conn = self.conn().await?;
                conn.exec_drop(
                    format!(
                        "UPDATE sts_cluster_nodes SET heartbeat_at = {now}, expires_at = {now} + ? WHERE node_id = ? \
                         AND left_at = 0 AND expires_at > {now}",
                        now = NOW
                    ),
                    (ttl, node.as_str()),
                )
                .await
                .map_err(err)?;
                if conn.affected_rows() == 0 {
                    return Ok(Renewal { alive: false, leases: Vec::new() });
                }
                conn.exec_drop(
                    format!(
                        "UPDATE sts_cluster_leases SET expires_at = {now} + ? WHERE holder = ? AND expires_at > {now}",
                        now = NOW
                    ),
                    (ttl, node.as_str()),
                )
                .await
                .map_err(err)?;
                let held: Vec<(String, i64)> = conn
                    .exec(
                        format!(
                            "SELECT name, token FROM sts_cluster_leases WHERE holder = ? AND expires_at > {} ORDER BY \
                             name",
                            NOW
                        ),
                        (node.as_str(),),
                    )
                    .await
                    .map_err(err)?;
                Ok::<Renewal, StoreError>(Renewal {
                    alive: true,
                    leases: held.into_iter().map(|(n, t)| (n, t.max(0) as u64)).collect(),
                })
            };
            tokio::time::timeout(bound, work).await.map_err(|_| {
                err(format!("the heartbeat did not finish within its bound of {} ms", bound.as_millis()))
            })?
        })
    }

    // Kept by the same holder within its lifetime, otherwise a new token;
    // the SET writes `holder` LAST, because MariaDB's later assignments
    // read the earlier ones' new values.
    fn acquire_lease(
        &self,
        name: &str,
        node: &str,
        ttl_ms: f64,
    ) -> BoxFuture<'_, Result<LeaseAnswer, String>> {
        let (name, node) = (name.to_string(), node.to_string());
        self.pending(async move {
            let ttl = ttl_ms as i64;
            let mut tx = self.pool.start_transaction(TxOpts::default()).await.map_err(err)?;
            let live = format!(
                "SELECT 1 FROM sts_cluster_nodes WHERE node_id = ? AND left_at = 0 AND expires_at > {}",
                NOW
            );
            tx.exec_drop(
                format!(
                    "UPDATE sts_cluster_leases SET token = CASE WHEN holder = ? AND expires_at > {now} THEN token ELSE \
                     token + 1 END, acquired_at = CASE WHEN holder = ? AND expires_at > {now} THEN acquired_at ELSE \
                     {now} END, expires_at = {now} + ?, holder = ? WHERE name = ? AND (expires_at <= {now} OR holder = \
                     ?) AND EXISTS ({live})",
                    now = NOW,
                    live = live
                ),
                vec![
                    Value::from(node.as_str()),
                    Value::from(node.as_str()),
                    Value::from(ttl),
                    Value::from(node.as_str()),
                    Value::from(name.as_str()),
                    Value::from(node.as_str()),
                    Value::from(node.as_str()),
                ],
            )
            .await
            .map_err(err)?;
            if tx.affected_rows() == 0 {
                let alive: Option<i64> = tx.exec_first(live.as_str(), (node.as_str(),)).await.map_err(err)?;
                if alive.is_some() {
                    tx.exec_drop(
                        format!(
                            "INSERT IGNORE INTO sts_cluster_leases ({}) VALUES (?, ?, 1, {now}, {now} + ?)",
                            LEASE_WRITE,
                            now = NOW
                        ),
                        (name.as_str(), node.as_str(), ttl),
                    )
                    .await
                    .map_err(err)?;
                }
            }
            let row: Option<(String, i64)> = tx
                .exec_first("SELECT holder, token FROM sts_cluster_leases WHERE name = ?", (name.as_str(),))
                .await
                .map_err(err)?;
            tx.commit().await.map_err(err)?;
            Ok(match row {
                Some((holder, token)) if holder == node => {
                    LeaseAnswer { held: true, token: token.max(0) as u64, holder }
                }
                Some((holder, token)) => LeaseAnswer { held: false, token: token.max(0) as u64, holder },
                None => LeaseAnswer { held: false, token: 0, holder: String::new() },
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
            let mut conn = self.conn().await?;
            conn.exec_drop(
                "UPDATE sts_cluster_leases SET expires_at = 0 WHERE name = ? AND holder = ? AND token = ?",
                (name.as_str(), node.as_str(), token as i64),
            )
            .await
            .map_err(err)?;
            Ok(conn.affected_rows() > 0)
        })
    }

    fn leave(&self, node: &str) -> BoxFuture<'_, Result<(), String>> {
        let node = node.to_string();
        self.pending(async move {
            let mut conn = self.conn().await?;
            // `expires_at` before `left_at`: MariaDB reads a later
            // assignment's new value, and neither reads the other column.
            conn.exec_drop(
                format!(
                    "UPDATE sts_cluster_nodes SET expires_at = LEAST(expires_at, {now}), left_at = {now} WHERE node_id \
                     = ?",
                    now = NOW
                ),
                (node.as_str(),),
            )
            .await
            .map_err(err)?;
            conn.exec_drop("UPDATE sts_cluster_leases SET expires_at = 0 WHERE holder = ?", (node.as_str(),))
                .await
                .map_err(err)
        })
    }

    // The expired row deleted, then insert-or-nothing, then the row.
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
            let mut conn = self.conn().await?;
            conn.exec_drop(
                format!(
                    "DELETE FROM sts_cluster_claims WHERE scope = ? AND realm = ? AND `key` = ? AND expires_at <= {}",
                    NOW
                ),
                (scope.as_str(), realm.as_str(), key.as_str()),
            )
            .await
            .map_err(err)?;
            conn.exec_drop(
                format!(
                    "INSERT IGNORE INTO sts_cluster_claims ({}) VALUES (?, ?, ?, ?, ?, {now}, {now} + ?)",
                    CLAIM_WRITE,
                    now = NOW
                ),
                vec![
                    Value::from(scope.as_str()),
                    Value::from(realm.as_str()),
                    Value::from(key.as_str()),
                    Value::from(reservation.as_str()),
                    Value::from(origin.as_str()),
                    Value::from(ttl_ms.max(1.0) as i64),
                ],
            )
            .await
            .map_err(err)?;
            let won = conn.affected_rows() > 0;
            let row: Option<Row> = conn
                .exec_first(
                    "SELECT origin, reservation, claimed_at, expires_at FROM sts_cluster_claims WHERE scope = ? AND \
                     realm = ? AND `key` = ?",
                    (scope.as_str(), realm.as_str(), key.as_str()),
                )
                .await
                .map_err(err)?;
            Ok(match row {
                Some(r) if won && text(&r, "reservation").as_deref() == Some(reservation.as_str()) => {
                    ClaimAnswer::Claimed { claimed_at: int(&r, "claimed_at").unwrap_or(0) as f64 }
                }
                Some(r) => ClaimAnswer::Used {
                    origin: text(&r, "origin").unwrap_or_default(),
                    claimed_at: int(&r, "claimed_at").unwrap_or(0) as f64,
                    expires_at: int(&r, "expires_at").unwrap_or(0) as f64,
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
            let mut conn = self.conn().await?;
            conn.exec_drop(
                "DELETE FROM sts_cluster_claims WHERE scope = ? AND realm = ? AND `key` = ? AND reservation = ?",
                (scope.as_str(), realm.as_str(), key.as_str(), reservation.as_str()),
            )
            .await
            .map_err(err)?;
            Ok(conn.affected_rows() > 0)
        })
    }
}

impl OriginEngine for MariadbDriver {
    fn claim_origin<'a>(
        &'a self,
        claim: &'a OriginClaim,
        holder: &'a str,
    ) -> StoreFuture<'a, Result<(), Holder>> {
        Box::pin(async move {
            let mut tx = self
                .pool
                .start_transaction(TxOpts::default())
                .await
                .map_err(err)?;
            tx.exec_drop(
                format!(
                    "DELETE FROM sts_cluster_claims WHERE scope = ? AND realm = '' AND `key` = ? AND expires_at <= {}",
                    NOW
                ),
                (ORIGIN_SCOPE, claim.key.as_str()),
            )
            .await
            .map_err(err)?;
            tx.exec_drop(
                format!(
                    "INSERT IGNORE INTO sts_cluster_claims ({}) VALUES (?, '', ?, ?, ?, {now}, {now} + ?)",
                    CLAIM_WRITE,
                    now = NOW
                ),
                (ORIGIN_SCOPE, claim.key.as_str(), claim.reservation.as_str(), holder, claim.ttl_ms),
            )
            .await
            .map_err(err)?;
            let won = tx.affected_rows() > 0;
            let row: Option<Row> = tx
                .exec_first(
                    "SELECT origin, reservation, expires_at FROM sts_cluster_claims WHERE scope = ? AND realm = '' AND \
                     `key` = ?",
                    (ORIGIN_SCOPE, claim.key.as_str()),
                )
                .await
                .map_err(err)?;
            let mine = won
                && row.as_ref().and_then(|r| text(r, "reservation")).as_deref()
                    == Some(claim.reservation.as_str());
            if mine {
                MariadbDriver::install_origin_lock(&mut tx, claim).await?;
            }
            tx.commit().await.map_err(err)?;
            if mine {
                return Ok(Ok(()));
            }
            Ok(Err(row.map_or_else(Holder::default, |r| Holder {
                origin: text(&r, "origin").unwrap_or_default(),
                expires_at: int(&r, "expires_at").unwrap_or(0),
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
            let mut tx = self
                .pool
                .start_transaction(TxOpts::default())
                .await
                .map_err(err)?;
            let row: Option<(Option<String>, String)> = tx
                .exec_first(
                    "SELECT origin, reservation FROM sts_cluster_claims WHERE scope = ? AND realm = '' AND `key` = ? FOR \
                     UPDATE",
                    (ORIGIN_SCOPE, claim.key.as_str()),
                )
                .await
                .map_err(err)?;
            let Some((origin, old)) = row else {
                tx.commit().await.map_err(err)?;
                return Ok(false);
            };
            let origin = origin.unwrap_or_default();
            let named =
                origin.split_once('@').map_or("", |(_, n)| n).to_string();
            if named.is_empty() || named == node_id {
                tx.commit().await.map_err(err)?;
                return Ok(false);
            }
            let gone: Option<i64> = tx
                .exec_first(
                    format!(
                        "SELECT 1 FROM sts_cluster_nodes WHERE node_id = ? AND (left_at > 0 OR expires_at <= {})",
                        NOW
                    ),
                    (named.as_str(),),
                )
                .await
                .map_err(err)?;
            if gone.is_none() {
                tx.commit().await.map_err(err)?;
                return Ok(false);
            }
            tx.exec_drop(
                format!(
                    "UPDATE sts_cluster_claims SET reservation = ?, origin = ?, claimed_at = {now}, expires_at = {now} \
                     + ? WHERE scope = ? AND realm = '' AND `key` = ? AND reservation = ?",
                    now = NOW
                ),
                vec![
                    Value::from(claim.reservation.as_str()),
                    Value::from(holder),
                    Value::from(claim.ttl_ms),
                    Value::from(ORIGIN_SCOPE),
                    Value::from(claim.key.as_str()),
                    Value::from(old.as_str()),
                ],
            )
            .await
            .map_err(err)?;
            if tx.affected_rows() == 0 {
                tx.commit().await.map_err(err)?;
                return Ok(false);
            }
            MariadbDriver::install_origin_lock(&mut tx, claim).await?;
            tx.commit().await.map_err(err)?;
            Ok(true)
        })
    }

    fn renew_live<'a>(
        &'a self,
        claim: &'a OriginClaim,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            let mut conn = self.conn().await?;
            conn.exec_drop(
                format!(
                    "UPDATE sts_cluster_claims SET expires_at = {now} + ? WHERE scope = ? AND realm = '' AND `key` = ? \
                     AND reservation = ? AND expires_at > {now}",
                    now = NOW
                ),
                (claim.ttl_ms, ORIGIN_SCOPE, claim.key.as_str(), claim.reservation.as_str()),
            )
            .await
            .map_err(err)?;
            Ok(conn.affected_rows() > 0)
        })
    }

    fn reassert<'a>(&'a self, claim: &'a OriginClaim) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            let mut conn = self.conn().await?;
            conn.exec_drop(
                format!(
                    "UPDATE sts_cluster_claims SET expires_at = {} + ? WHERE scope = ? AND realm = '' AND `key` = ? AND \
                     reservation = ?",
                    NOW
                ),
                (claim.ttl_ms, ORIGIN_SCOPE, claim.key.as_str(), claim.reservation.as_str()),
            )
            .await
            .map_err(err)?;
            let n = conn.affected_rows();
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
            let mut tx = self
                .pool
                .start_transaction(TxOpts::default())
                .await
                .map_err(err)?;
            tx.exec_drop(
                "DELETE FROM sts_cluster_claims WHERE scope = ? AND realm = '' AND `key` = ? AND reservation = ?",
                (ORIGIN_SCOPE, claim.key.as_str(), claim.reservation.as_str()),
            )
            .await
            .map_err(err)?;
            let n = tx.affected_rows();
            if n > 0 {
                tx.exec_drop(
                    "DELETE FROM sts_cluster_locks WHERE name = ?",
                    (fence_lock_name("origin", &claim.key, &claim.reservation),),
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
            let n: Option<i64> = self
                .conn()
                .await?
                .query_first(format!("SELECT {}", NOW))
                .await
                .map_err(err)?;
            Ok(n.unwrap_or(0))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_string_asking_for_the_clear_is_refused() {
        assert!(Dial::parse("mariadb://u:p@h/db?ssl=false", false).is_err());
        assert!(Dial::parse("mysql://u:p@h/db?sslmode=disable", false).is_err());
        assert!(Dial::parse("postgres://u@h/db", false).is_err());
        let d = Dial::parse("mariadb://sts%40x:p%3Aw@db.example:3307/sts_store?sslmode=verify-ca", false).unwrap();
        assert_eq!((d.user.as_str(), d.password.as_str()), ("sts@x", "p:w"));
        assert_eq!(
            (d.host.as_str(), d.port, d.database.as_str()),
            ("db.example", 3307, "sts_store")
        );
        assert!(d.verify_chain && !d.verify_hostname);
        let v = Dial::parse("mariadb://u@h/db", true).unwrap();
        assert!(v.verify_chain && v.verify_hostname);
    }

    #[test]
    fn the_bases_and_keys_are_node_s() {
        assert_eq!(
            bases_of("ou=users,dc=x"),
            vec!["ou=users,dc=x", "dc=x", ""]
        );
        assert_eq!(bases_of(""), vec![""]);
        assert_eq!(table_key("short"), "short");
        let long = "é".repeat(345);
        assert!(table_key(&long).starts_with('#'));
        assert_eq!(table_key(&long).len(), 65);
        assert_eq!(parent_of("uid=a,ou=users,dc=x"), "ou=users,dc=x");
    }

    /// `keysMatch()`'s text, byte for byte (`tests/directory_portable.js`
    /// A6's pattern).
    #[test]
    fn keys_match_is_node_text() {
        assert_eq!(
            keys_match(&["realm", "dn_key"], 2),
            "((realm = ? AND dn_key = ?) OR (realm = ? AND dn_key = ?))"
        );
        assert_eq!(keys_match(&["a"], 1), "((a = ?))");
        assert_eq!(keys_match(&["a", "b"], 0), "(1 = 0)");
    }
}
