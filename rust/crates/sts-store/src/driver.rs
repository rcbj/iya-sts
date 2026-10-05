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

/// The contract every store implements.
pub trait Driver: Send + Sync {
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
}
