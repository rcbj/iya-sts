// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! One stored entry, as `ldap_server.js`'s store holds it: the DN exactly
//! as written, the attributes keyed by LOWER-CASED name with every value a
//! string, and the three facts about the row (`origin`, `createdAt`,
//! `modifiedAt`) that are not attributes.
//!
//! The attribute map is an [`IndexMap`] and that is not a detail: a JS
//! object keeps its keys in insertion order, a search returns the
//! attributes in that order, and an overwrite of an existing key keeps its
//! place while a `delete` and a re-add moves it to the end. `insert` and
//! `shift_remove` are those two operations.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// The attributes of an entry: lower-cased name to values.
pub type Attributes = IndexMap<String, Vec<String>>;

/// One entry of a realm's tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub dn: String,
    pub attributes: Attributes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(rename = "modifiedAt", default, skip_serializing_if = "Option::is_none")]
    pub modified_at: Option<String>,
}

impl Entry {
    /// An entry's values for a lower-cased attribute, empty when it holds
    /// none.
    // A HOT PATH: asked for every attribute every rule reads, so no span.
    pub fn values(&self, lower: &str) -> &[String] {
        self.attributes.get(lower).map(Vec::as_slice).unwrap_or(&[])
    }

    /// The first value of a lower-cased attribute (`firstValueOf()`).
    // A HOT PATH, as `values()`.
    pub fn first(&self, lower: &str) -> Option<&str> {
        self.values(lower).first().map(String::as_str)
    }

    /// `entryUuidOf()`: the entry's `entryUUID`, lower-cased, or "".
    // A HOT PATH, as `values()`.
    pub fn entry_uuid(&self) -> String {
        self.first("entryuuid")
            .map(|s| s.to_lowercase())
            .unwrap_or_default()
    }
}
