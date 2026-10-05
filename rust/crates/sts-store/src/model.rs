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

/// One flush of the directory: the per-entry diff a database uses, and the
/// whole live picture a snapshot driver writes from.
#[derive(Clone, Debug, Default)]
pub struct DirectoryChange {
    /// Realm id to the entries written or changed, keyed by DN.
    pub upserts: BTreeMap<String, Vec<StoredEntry>>,
    /// Realm id to the DNs deleted.
    pub deletes: BTreeMap<String, Vec<String>>,
    /// The realms something happened in.
    pub touched: Vec<String>,
    /// The realms that are gone, every row of them.
    pub removed_realms: Vec<String>,
    /// Realm id to every entry it holds now.
    pub all: BTreeMap<String, Vec<StoredEntry>>,
}
