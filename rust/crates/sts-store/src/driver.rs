// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The driver contract `persistence.js` calls: `open`, `close`, the three
//! loads and the three saves. A load answers `None` for "nothing has ever
//! been written", which is not the same as empty. The driver is chosen at
//! run time by `persistence.mode`, so the trait is object-safe: each
//! method answers a boxed future.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use serde_json::{Map, Value as Json};

use crate::model::{DirectoryChange, StoredEntry};

/// A store failure: a sentence, and the error code its log line carries.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct StoreError {
    pub message: String,
}

impl StoreError {
    pub fn new(message: impl Into<String>) -> StoreError {
        StoreError {
            message: message.into(),
        }
    }
}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> StoreError {
        StoreError::new(e.to_string())
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(e: serde_json::Error) -> StoreError {
        StoreError::new(e.to_string())
    }
}

pub type StoreResult<T> = Result<T, StoreError>;

/// A driver's answer to one call.
pub type StoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = StoreResult<T>> + Send + 'a>>;

/// Realm id to its entries, as `loadDirectory()` answers.
pub type Directory = BTreeMap<String, Vec<StoredEntry>>;

/// One row of the change log: what kind of thing changed, where, and which
/// process committed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangeRow {
    pub seq: i64,
    pub origin: String,
    /// `directory`, `realms`, `appconfig`.
    pub kind: String,
    pub realm: String,
    pub key: String,
}

/// The change log several processes coordinate through: STATE, not
/// sockets. A store that has one answers [`Driver::change_log`].
pub trait ChangeLog: Send + Sync {
    /// This process's name in the log's `origin` column.
    fn origin(&self) -> String;
    fn latest_change_seq(&self) -> StoreFuture<'_, i64>;
    fn changes_since(
        &self,
        after: i64,
        limit: i64,
    ) -> StoreFuture<'_, Vec<ChangeRow>>;
    /// The rows at these sequence numbers that are visible now.
    fn changes_at(&self, seqs: Vec<i64>) -> StoreFuture<'_, Vec<ChangeRow>>;
    /// One directory entry as the store holds it now.
    fn read_entry<'a>(
        &'a self,
        realm: &'a str,
        key: &'a str,
    ) -> StoreFuture<'a, Option<StoredEntry>>;
}

/// A minted row's change-log key (`mintedChangeRow()`): the handle and the
/// name, each base64url, joined by '.'; a sealed name is its own half.
// Hot path (every row a flush writes): no span.
pub fn minted_change_key(handle: &str, key: &str, key_sealed: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(handle.as_bytes()),
        if key_sealed.is_empty() {
            URL_SAFE_NO_PAD.encode(key.as_bytes())
        } else {
            key_sealed.to_string()
        }
    )
}

/// The contract every store implements.
pub trait Driver: Send + Sync {
    /// The engine a database store runs on, for a caller choosing how
    /// often to poll its change log (`dialect.rs`); `None` for a store that
    /// is not a database.
    fn dialect(&self) -> Option<&'static dyn crate::dialect::Dialect> {
        None
    }

    /// The change log, for a store several processes share.
    fn change_log(&self) -> Option<&dyn ChangeLog> {
        None
    }

    /// The process's data keys, handed over the moment the keystore has
    /// started (`persistence.start()`): a driver that seals what it writes
    /// (the postgres driver's directory entries, #391) takes them; the rest
    /// ignore them. A late binding, because the keystore reads its rows
    /// through the driver it is handed to.
    fn adopt_data_keys(
        &self,
        _keys: &std::sync::Arc<crate::keystore::DataKeys>,
    ) {
    }

    /// `memory`, `ldif` or `postgres`.
    fn name(&self) -> &'static str;
    /// Opens the store. A failure here is FATAL to the service, where every
    /// listener's is recorded: a service that cannot read what it wrote
    /// down does not start.
    fn open(&self) -> StoreFuture<'_, ()>;
    fn close(&self) -> StoreFuture<'_, ()>;
    fn load_directory(&self) -> StoreFuture<'_, Option<Directory>>;
    /// The realm registry's rows; the default realm is never one.
    fn load_realms(&self) -> StoreFuture<'_, Option<Vec<Json>>>;
    /// The runtime appconfig overrides.
    fn load_overrides(&self) -> StoreFuture<'_, Option<Map<String, Json>>>;
    /// Writes a flush of the directory, and answers what the store decided
    /// for rows another node had changed meanwhile (a snapshot driver
    /// decides nothing and answers none).
    fn save_directory<'a>(
        &'a self,
        change: &'a DirectoryChange,
    ) -> StoreFuture<'a, Vec<crate::model::DirectoryOutcome>>;
    fn save_realms<'a>(&'a self, rows: &'a [Json]) -> StoreFuture<'a, ()>;
    fn save_overrides<'a>(
        &'a self,
        overrides: &'a Map<String, Json>,
    ) -> StoreFuture<'a, ()>;
    /// The realm registry written as the changes the delta names, so two
    /// nodes changing different settings of one realm do not overwrite each
    /// other. A snapshot driver writes the whole registry.
    fn save_realms_delta<'a>(
        &'a self,
        rows: &'a [Json],
        _delta: &'a crate::shadow::RealmsDelta,
    ) -> StoreFuture<'a, ()> {
        self.save_realms(rows)
    }
    /// The overrides written as the keys the delta sets and clears.
    fn save_overrides_delta<'a>(
        &'a self,
        overrides: &'a Map<String, Json>,
        _delta: &'a crate::shadow::AppconfigDelta,
    ) -> StoreFuture<'a, ()> {
        self.save_overrides(overrides)
    }

    /// Every key row (`sts_keys`): `(realm, material)`. A store that keeps
    /// no keys answers none.
    fn load_keys(&self) -> StoreFuture<'_, Vec<(String, String)>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    /// Replaces one key row.
    fn save_keys<'a>(
        &'a self,
        realm: &'a str,
        _material: &'a str,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            Err(StoreError::new(format!(
                "the {} store keeps no keys (\"{}\" was not written)",
                self.name(),
                realm
            )))
        })
    }
    /// Whether this store can hold minted rows: the ldif one cannot, since
    /// it writes whole files.
    fn mints(&self) -> bool {
        false
    }
    /// Every minted row the filter keeps.
    fn load_minted(
        &self,
        _filter: MintedFilter,
    ) -> StoreFuture<'_, Vec<MintedRow>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    /// One transaction for a flush: upserts and deletes in one lock order.
    fn save_minted(
        &self,
        _upserts: Vec<MintedWrite>,
        _deletes: Vec<MintedWrite>,
    ) -> StoreFuture<'_, MintedDecided> {
        Box::pin(async move {
            Err(StoreError::new(format!(
                "the {} store holds no minted rows",
                self.name()
            )))
        })
    }
    /// The rows `(handle, realm, key)` names, in one round trip; a
    /// tombstone is not a row.
    fn read_minted_many(
        &self,
        _refs: Vec<(String, String, String)>,
    ) -> StoreFuture<'_, Vec<MintedRow>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    /// `minted.newest` (#820): the live rows of one store in one realm with
    /// the highest sort value first, walked through the store's sort rows
    /// in `sts_minted_index`, at most `limit` (`NEWEST_LIMIT` caps it) —
    /// what a console list of the newest of a store shows. Only a store
    /// that declares a sort value has sort rows; a tombstone or an expired
    /// row is passed over.
    fn read_minted_newest<'a>(
        &'a self,
        _handle: &'a str,
        _realm: &'a str,
        _now_ms: i64,
        _limit: i64,
    ) -> StoreFuture<'a, Vec<MintedRow>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    /// Removes the tombstones written before `before_ms`.
    fn purge_tombstones(&self, _before_ms: i64) -> StoreFuture<'_, u64> {
        Box::pin(async { Ok(0) })
    }
    /// Removes at most `limit` rows of one kind no restore will read again.
    fn purge_expired_minted(
        &self,
        _kind: PurgeKind,
        _limit: i64,
    ) -> StoreFuture<'_, u64> {
        Box::pin(async { Ok(0) })
    }
    /// Removes every minted row written before `before_ms`.
    fn purge_minted(&self, _before_ms: i64) -> StoreFuture<'_, u64> {
        Box::pin(async { Ok(0) })
    }
    /// `ensureSharedSecret(name, material)` (#46): a shared secret, first
    /// writer wins — `material` is already sealed by the caller, the offer
    /// is `INSERT … ON CONFLICT DO NOTHING`, and what the table holds
    /// afterwards (this offer or an earlier one) is answered. A store that
    /// cannot share (memory, ldif) has no such method in Node, and says so
    /// with [`Driver::shares_secrets`].
    fn ensure_shared_secret<'a>(
        &'a self,
        _name: &'a str,
        _material: &'a str,
    ) -> StoreFuture<'a, Option<SharedSecretRow>> {
        Box::pin(async { Ok(None) })
    }
    /// Whether this store shares secrets ([`Driver::ensure_shared_secret`]).
    fn shares_secrets(&self) -> bool {
        false
    }
    /// `countWindow(scope, realm, key, windowMs)` (#46,
    /// `cluster/cluster_counters.js`): one attempt counted in a fixed
    /// window every process shares (`sts_cluster_windows`), a window that
    /// has passed reset to a fresh one at 1. Answers the count including
    /// this attempt and what is left of the window; `None` where this
    /// store shares no windows ([`Driver::shares_windows`]).
    fn count_window<'a>(
        &'a self,
        _scope: &'a str,
        _realm: &'a str,
        _key: &'a str,
        _window_ms: i64,
    ) -> StoreFuture<'a, Option<WindowCount>> {
        Box::pin(async { Ok(None) })
    }
    /// `peekWindow(scope, realm, key)`: the count of a window still
    /// running, counting nothing; a passed one is a count of zero.
    fn peek_window<'a>(
        &'a self,
        _scope: &'a str,
        _realm: &'a str,
        _key: &'a str,
    ) -> StoreFuture<'a, Option<WindowCount>> {
        Box::pin(async { Ok(None) })
    }
    /// `clearWindow(scope, realm, key)`: a window forgotten — what a
    /// success does to its bucket. Whether there was one.
    fn clear_window<'a>(
        &'a self,
        _scope: &'a str,
        _realm: &'a str,
        _key: &'a str,
    ) -> StoreFuture<'a, bool> {
        Box::pin(async { Ok(false) })
    }
    /// `claimUsedAssertion(row, { cap, now })` (`common/used_assertions.js`,
    /// `sts_used_assertions`): one document's use claimed ONCE, the
    /// primary key arbitrating — an expired row with the key is replaced,
    /// a live one refuses, and a realm already holding `cap` live rows
    /// refuses too. `None` where this store holds no such table
    /// ([`Driver::holds_used_assertions`]).
    fn claim_used_assertion<'a>(
        &'a self,
        _row: &'a UsedAssertionRow,
        _cap: i64,
        _now_ms: i64,
    ) -> StoreFuture<'a, Option<UsedClaim>> {
        Box::pin(async { Ok(None) })
    }
    /// `settleUsedAssertion(realm, key, reservation, spent, at)`: a
    /// reservation made `spent`, or deleted while still `reserved`, both
    /// pinned to the reservation. The rows touched.
    fn settle_used_assertion<'a>(
        &'a self,
        _realm: &'a str,
        _key: &'a str,
        _reservation: &'a str,
        _spent: bool,
        _at_ms: i64,
    ) -> StoreFuture<'a, u64> {
        Box::pin(async { Ok(0) })
    }
    /// `findUsedAssertion(realm, key, now)`: one live row by its key.
    fn find_used_assertion<'a>(
        &'a self,
        _realm: &'a str,
        _key: &'a str,
        _now_ms: i64,
    ) -> StoreFuture<'a, Option<UsedAssertionRow>> {
        Box::pin(async { Ok(None) })
    }
    /// `purgeUsedAssertions(now)`: the expired rows swept.
    fn purge_used_assertions(&self, _now_ms: i64) -> StoreFuture<'_, u64> {
        Box::pin(async { Ok(0) })
    }
    /// Whether this store holds `sts_used_assertions`.
    fn holds_used_assertions(&self) -> bool {
        false
    }
    /// Whether this store shares the rate windows (`windowStore()` found
    /// `countWindow`, `peekWindow` and `clearWindow`).
    fn shares_windows(&self) -> bool {
        false
    }
    /// Whether [`Driver::merge_keys`] decides under the row's lock.
    fn merges_keys(&self) -> bool {
        false
    }
    /// One key row merged under its lock: `merge` is handed what is stored
    /// and answers the row to write, or `None` to leave it. Answers what the
    /// store holds afterwards.
    fn merge_keys<'a>(
        &'a self,
        realm: &'a str,
        _merge: KeyMerge,
    ) -> StoreFuture<'a, Option<String>> {
        Box::pin(async move {
            Err(StoreError::new(format!(
                "the {} store does not merge keys (\"{}\" was not written)",
                self.name(),
                realm
            )))
        })
    }
}

/// One `sts_used_assertions` row, in `used_assertions.js`' shape. The
/// four text columns (`issuer`, `identifier`, `client_id`, `subject`) are
/// as the caller sealed them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UsedAssertionRow {
    pub realm: String,
    pub key: String,
    pub format: String,
    pub used_as: String,
    pub issuer: String,
    pub identifier: String,
    pub client_id: String,
    pub subject: String,
    pub state: String,
    pub reservation: String,
    pub origin: String,
    pub used_at: i64,
    pub spent_at: i64,
    pub expires_at: i64,
}

/// What a claim answers: claimed, or the realm's live count and the row
/// that holds the key (none: the cap refused).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UsedClaim {
    pub claimed: bool,
    pub live: i64,
    pub existing: Option<UsedAssertionRow>,
}

/// A shared window's count, as `countWindow()` and `peekWindow()` answer
/// it: `{ count, remainingMs }`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowCount {
    pub count: i64,
    pub remaining_ms: i64,
}

/// One `sts_cluster_secrets` row, as `ensureSharedSecret()` answers it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedSecretRow {
    /// The sealed value.
    pub material: String,
    pub created_by: String,
    pub created_at: i64,
    /// Whether this caller's offer was the one kept.
    pub offered: bool,
}

/// One stored minted row (`loadMinted()`), its body sealed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintedRow {
    pub handle: String,
    pub realm: String,
    /// The keyed digest of the name, or the name where nothing seals.
    pub key: String,
    /// The name, sealed (#222); empty for a row whose key is its name.
    pub key_sealed: String,
    pub body: String,
    /// When it was written, in milliseconds.
    pub written_at: i64,
    pub expires_at: Option<i64>,
}

/// `minted_queries.NEWEST_LIMIT`: the most rows `minted.newest` answers,
/// a console list and not a walk.
pub const NEWEST_LIMIT: i64 = 1000;

/// `buildPostgres('minted.newest')`'s limit: `Math.max(1,
/// Math.min(NEWEST_LIMIT, Math.floor(Number(limit) || 1)))`.
// Hot path (one comparison): no span.
pub fn newest_limit(limit: i64) -> i64 {
    limit.clamp(1, NEWEST_LIMIT)
}

/// What `loadMinted()` reads: only what is still worth having (#333).
#[derive(Clone, Debug, Default)]
pub struct MintedFilter {
    /// The realm partitions that exist.
    pub realms: Vec<String>,
    /// The instant a row's own expiry is compared with.
    pub now_ms: i64,
    /// A short-lived store's row with no expiry written before this is
    /// dropped; 0 keeps every one.
    pub stale_before: i64,
    pub age_handles: Vec<String>,
    /// The stores whose expiring rows a start does not read
    /// (`nullExpiryHandles`, #883): only their rows with a NULL expiry.
    pub null_expiry_handles: Vec<String>,
}

/// What an in-place edit's merge answers: the merged body sealed, and the
/// columns `mergerFor()` takes from the merged record rather than from this
/// process's copy — its expiry, its session index, its lookups and its sort
/// value (another node may have extended or refiled it).
#[derive(Clone, Debug, Default)]
pub struct MergedRow {
    pub body: String,
    pub expires_at: Option<i64>,
    pub session_index: Option<crate::side::SessionIndex>,
    pub lookups: Option<Vec<String>>,
    pub sort_at: Option<i64>,
}

/// An in-place edit's merge (`mergerFor()`): handed the stored body, it
/// answers the merged row, or `None` to write this process's copy as it is.
pub type MintedMerge = Box<dyn FnOnce(&str) -> Option<MergedRow> + Send>;

/// One minted row to write or delete.
pub struct MintedWrite {
    pub handle: String,
    pub realm: String,
    pub key: String,
    pub key_sealed: String,
    /// The name the journal holds it under, for the caller.
    pub journal_key: String,
    /// The sealed body; empty for a delete.
    pub body: String,
    pub expires_at: Option<i64>,
    /// A `merge: own` store's row: a change row of its own kind.
    pub own: bool,
    /// A delete leaves a tombstone, and an upsert of a key holding one is
    /// refused.
    pub tombstone: bool,
    pub merge: Option<MintedMerge>,
    /// `sts_sessions`' columns for an `authn.sessions` upsert (#350), or
    /// `None`, which writes no index row.
    pub session_index: Option<crate::side::SessionIndex>,
    /// An on-demand store's index digests (#820): `Some` replaces the row's
    /// index rows (an empty list removes them), `None` leaves them.
    pub lookups: Option<Vec<String>>,
    /// The store's `sortBy` value, filed as the row's sort row while
    /// `lookups` is written.
    pub sort_at: Option<i64>,
    /// A delete of an indexed store's row removes its index rows.
    pub indexed: bool,
}

/// What the store decided for rows another node had changed.
#[derive(Clone, Debug, Default)]
pub struct MintedDecided {
    /// `(handle, realm, journal key)` of an upsert a tombstone refused.
    pub refused: Vec<(String, String, String)>,
    /// `(handle, realm, journal key, body)` of an upsert merged with the
    /// stored row.
    pub merged: Vec<(String, String, String, String)>,
}

/// The three kinds of minted row nothing will read again (#333).
#[derive(Clone, Debug)]
pub enum PurgeKind {
    /// Past its own expiry.
    Expired { now_ms: i64 },
    /// Of a realm no longer defined, written before `before_ms`.
    Orphan {
        default_realm: String,
        before_ms: i64,
    },
    /// A short-lived store's row with no expiry, written before `before_ms`.
    Stale {
        handles: Vec<String>,
        before_ms: i64,
    },
}

/// What [`Driver::merge_keys`] decides with.
pub type KeyMerge =
    Box<dyn FnOnce(Option<&str>) -> Result<Option<String>, String> + Send>;
