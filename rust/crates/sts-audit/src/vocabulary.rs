// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE VOCABULARY (`common/audit.js`'s `CATEGORIES`, `ACTIONS` and
//! `OUTCOMES`), read from `tables/audit_vocabulary.json`, which
//! `tests/tools/export-rust-tables.js` writes from the Node table and
//! `tests/rust_tables.js` holds to it. The console's filters, the API's
//! `categories` and `actions` members and the category an action is filed
//! under all come from it, so an action cannot occur and be unfilterable,
//! nor be offered and never occur. A new action is a row in the Node table
//! and a re-export.

use std::collections::HashMap;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

const TABLE: &str = include_str!("../tables/audit_vocabulary.json");

/// One category: its id, label and the sentence on what it covers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Category {
    pub category: String,
    pub label: String,
    pub what: String,
}

/// One action: its id, the category it is filed under, its label.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Action {
    pub action: String,
    pub category: String,
    pub label: String,
}

#[derive(Debug, Deserialize)]
struct Table {
    categories: Vec<Category>,
    actions: Vec<Action>,
    outcomes: Vec<String>,
}

static VOCABULARY: LazyLock<Table> = LazyLock::new(|| {
    serde_json::from_str(TABLE).unwrap_or(Table {
        categories: Vec::new(),
        actions: Vec::new(),
        outcomes: Vec::new(),
    })
});

static CATEGORY_OF: LazyLock<HashMap<String, String>> = LazyLock::new(|| {
    VOCABULARY
        .actions
        .iter()
        .map(|a| (a.action.clone(), a.category.clone()))
        .collect()
});

/// The categories, in the table's order.
#[tracing::instrument(level = "debug")]
pub fn categories() -> &'static [Category] {
    &VOCABULARY.categories
}

/// The actions, in the table's order.
#[tracing::instrument(level = "debug")]
pub fn actions() -> &'static [Action] {
    &VOCABULARY.actions
}

/// `success`, `refused`, `error`: three rather than two, because a refusal
/// is this service working and an error is this service failing.
#[tracing::instrument(level = "debug")]
pub fn outcomes() -> &'static [String] {
    &VOCABULARY.outcomes
}

/// `CATEGORY_OF_ACTION[action]`. A hot path (every row): no span.
pub fn category_of(action: &str) -> Option<&'static str> {
    CATEGORY_OF.get(action).map(String::as_str)
}

/// Whether `name` is one of the outcomes. A hot path: no span.
pub fn is_outcome(name: &str) -> bool {
    VOCABULARY.outcomes.iter().any(|o| o == name)
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_table_is_read() {
        assert!(super::categories().len() >= 12);
        assert!(super::actions().len() > 100);
        assert_eq!(super::outcomes(), ["success", "refused", "error"]);
        assert_eq!(super::category_of("session.start"), Some("session"));
    }
}
