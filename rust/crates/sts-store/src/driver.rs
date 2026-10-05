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

/// The contract every store implements.
pub trait Driver: Send + Sync {
    /// The change log, for a store several processes share.
    fn change_log(&self) -> Option<&dyn ChangeLog> {
        None
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
}

/// An in-place edit's merge (`mergerFor()`): handed the stored body, it
/// answers the body to write and its expiry, or `None` to write this
/// process's copy as it is.
pub type MintedMerge =
    Box<dyn FnOnce(&str) -> Option<(String, Option<i64>)> + Send>;

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
