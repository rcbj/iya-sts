// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Where a certificate authority's `pki:<scope>` row is held: the
//! keystore's `pkiFor()`, `attachPki()` and `pkiAll()`.
//!
//! **The row is Node's JSON, carried WHOLE** — every member this port does
//! not read (a pinned signer, a stored object, a generation's slot) is
//! kept as Node wrote it and written back, so a row Rust saved is a row
//! Node reads and the reverse. One row per scope: `*service` holds the
//! Root, `*process` the process branch, and each realm (`default` for the
//! default realm) its Intermediate, its Issuing CAs, the certificates they
//! issued and the revocation lists.
//!
//! [`MemoryRows`] is development's arrangement — the hierarchy lives as
//! long as the process, as Node's does when nothing persists — and every
//! test's. The runtime's store-backed implementation seals each row under
//! the realm's `pki-hierarchy` data key and merges it under the row's lock
//! (`sts-store`'s `KeySets::save_pki`).

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use serde_json::Value as Json;

/// The keystore's three calls for a certificate authority row.
pub trait RowStore: Send + Sync {
    /// `pkiFor(scope)`: the row, or `None`.
    fn get(&self, scope: &str) -> Option<Json>;
    /// `attachPki(scope, row)`: hold it, and write it where rows persist;
    /// `None` REMOVES it everywhere.
    fn attach(&self, scope: &str, row: Option<&Json>);
    /// `pkiAll()`'s scope ids.
    fn scopes(&self) -> Vec<String>;
    /// Whether the rows survive a restart (`keystore.persists()`).
    fn persists(&self) -> bool {
        false
    }
}

/// Rows held in this process only.
#[derive(Default)]
pub struct MemoryRows {
    rows: Mutex<BTreeMap<String, Json>>,
}

impl MemoryRows {
    #[tracing::instrument(level = "debug")]
    pub fn new() -> MemoryRows {
        MemoryRows::default()
    }
}

impl std::fmt::Debug for MemoryRows {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryRows").finish()
    }
}

impl RowStore for MemoryRows {
    fn get(&self, scope: &str) -> Option<Json> {
        self.rows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(scope)
            .cloned()
    }

    fn attach(&self, scope: &str, row: Option<&Json>) {
        let mut rows = self.rows.lock().unwrap_or_else(PoisonError::into_inner);
        match row {
            Some(row) => {
                rows.insert(scope.to_string(), row.clone());
            }
            None => {
                rows.remove(scope);
            }
        }
    }

    fn scopes(&self) -> Vec<String> {
        self.rows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .cloned()
            .collect()
    }
}
