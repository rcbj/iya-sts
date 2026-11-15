// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! One stored entry: `sts_store::StoredEntry`, the store's own row, so the
//! directory loads from and saves to every driver without a conversion —
//! the DN exactly as written, the attributes keyed by LOWER-CASED name with
//! every value a string, and the three facts about the row (`origin`,
//! `createdAt`, `modifiedAt`) that are not attributes.
//!
//! The attribute map is an `IndexMap` and that is not a detail: a JS object
//! keeps its keys in insertion order, a search returns the attributes in
//! that order, and an overwrite of an existing key keeps its place while a
//! `delete` and a re-add moves it to the end. `insert` and `shift_remove`
//! are those two operations.

use indexmap::IndexMap;

pub use sts_store::StoredEntry as Entry;

/// The attributes of an entry: lower-cased name to values.
pub type Attributes = IndexMap<String, Vec<String>>;

/// What the handlers read of an entry. Each is asked for every attribute
/// every rule reads: a hot path, so no span.
pub trait EntryExt {
    /// The values of a lower-cased attribute, empty when it holds none.
    fn values(&self, lower: &str) -> &[String];
    /// The first value of a lower-cased attribute (`firstValueOf()`).
    fn first(&self, lower: &str) -> Option<&str>;
    /// `entryUuidOf()`: the entry's `entryUUID`, lower-cased, or "".
    fn entry_uuid(&self) -> String;
}

impl EntryExt for Entry {
    fn values(&self, lower: &str) -> &[String] {
        self.attributes.get(lower).map(Vec::as_slice).unwrap_or(&[])
    }

    fn first(&self, lower: &str) -> Option<&str> {
        self.values(lower).first().map(String::as_str)
    }

    fn entry_uuid(&self) -> String {
        self.first("entryuuid")
            .map(|s| s.to_lowercase())
            .unwrap_or_default()
    }
}
