// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What a driver is handed and hands back.

use std::collections::BTreeMap;

use indexmap::IndexMap;

/// One directory entry as it is stored: its DN as typed (the directory
/// normalises it on load), its attributes in the order they were written,
/// and `origin`, this service's marker for how it came to exist.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoredEntry {
    pub dn: String,
    /// Attribute name (lower case once read back) to its values.
    pub attributes: IndexMap<String, Vec<String>>,
    pub origin: Option<String>,
    /// Rebuilt on load from `createTimestamp`.
    pub created_at: Option<String>,
    /// Rebuilt on load from `modifyTimestamp`, else `createTimestamp`.
    pub modified_at: Option<String>,
}

/// One entry a flush writes: where, what, and what the change was based on
/// (the shadow's JSON, or `None` when this process believed the DN held
/// nothing). A database merges against the base; a snapshot driver ignores
/// it.
#[derive(Clone, Debug, PartialEq)]
pub struct DirectoryUpsert {
    pub realm: String,
    /// The normalised DN.
    pub key: String,
    pub entry: StoredEntry,
    pub base: Option<String>,
}

/// One entry a flush deletes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryDelete {
    pub realm: String,
    pub key: String,
}

/// One flush of the directory: the per-entry diff a database uses, and the
/// whole picture of the touched realms a snapshot driver writes from.
#[derive(Clone, Debug, Default)]
pub struct DirectoryChange {
    pub upserts: Vec<DirectoryUpsert>,
    pub deletes: Vec<DirectoryDelete>,
    /// The realms something happened in.
    pub touched: Vec<String>,
    /// The realms that are gone, every row of them.
    pub removed_realms: Vec<String>,
    /// Realm id to every entry it holds now, for the touched realms.
    pub all: BTreeMap<String, Vec<StoredEntry>>,
}

/// What the store decided for a row another node had changed
/// (`directory_merge.js`'s outcomes): the live directory takes it.
#[derive(Clone, Debug, PartialEq)]
pub struct DirectoryOutcome {
    pub realm: String,
    pub key: String,
    pub outcome: crate::merge::Outcome,
    /// The entry the store now holds; `None` when deleted.
    pub entry: Option<StoredEntry>,
}
