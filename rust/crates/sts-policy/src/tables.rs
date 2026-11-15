// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The policy kinds' tables, read from the model: what Node's
//! `ModelTables.fields()`, `.selectors()`, `.schema()` and `.facts()` hand
//! each kind at load, from the same generated rows
//! (`src/generated/policy_tables.json`, written by
//! `models/lib/rust_lib.mjs`'s `renderRustPolicyTables()`).
//!
//! What a Node kind COMPUTES and passes in — a bound `crypto.js` owns, the
//! rows built from the model's facts — is computed by the kind's Rust
//! module in the same place, so it has one writing in each runtime, as in
//! Node.

use std::sync::LazyLock;

use serde_json::Value;

/// One row of a kind's `FIELDS`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Field {
    pub key: String,
    pub attribute: String,
    /// `int`, `bool`, `enum`, `list`, `locale`, `attribute`, `attributes`,
    /// `text`, `clientRules` or `attributeList`.
    pub kind: String,
    pub dflt: Value,
    pub min: Option<i64>,
    pub max: Option<i64>,
    pub values: Vec<String>,
    pub optional: bool,
    pub label: String,
    pub unit: Option<String>,
    pub what: String,
    /// A `list` row's word for the empty list (#940).
    pub empty: Option<String>,
    /// A `list` row's longest (#940).
    pub max_items: Option<usize>,
    /// A computed authentication row's mechanism and role (#64).
    pub mechanism: Option<String>,
    pub role: Option<String>,
    pub email: bool,
    /// A computed service-account row's door id (#221).
    pub door: Option<String>,
}

/// What a named policy carries beside its rows: `SELECTORS`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Selector {
    pub key: String,
    pub attribute: String,
    pub what: String,
}

/// One policy object's tables.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Table {
    pub id: String,
    pub schema: Value,
    pub fields: Vec<Field>,
    pub selectors: Vec<Selector>,
    pub facts: Value,
}

impl Table {
    /// What the schema says an attribute is (`TABLE_WHAT`, the sentence a
    /// computed row carries).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn attribute_what(&self, name: &str) -> String {
        self.schema
            .get("attributes")
            .and_then(Value::as_array)
            .and_then(|rows| {
                rows.iter()
                    .find(|r| r.get("name").and_then(Value::as_str) == Some(name))
            })
            .and_then(|r| r.get("what"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    }
}

const SOURCE: &str = include_str!("generated/policy_tables.json");

fn string(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

fn field_of(row: &Value) -> Field {
    Field {
        key: string(row, "key"),
        attribute: string(row, "attribute"),
        kind: string(row, "type"),
        dflt: row.get("dflt").cloned().unwrap_or(Value::Null),
        min: row.get("min").and_then(Value::as_i64),
        max: row.get("max").and_then(Value::as_i64),
        values: row
            .get("values")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
            .unwrap_or_default(),
        optional: row.get("optional").and_then(Value::as_bool).unwrap_or(false),
        label: string(row, "label"),
        unit: row.get("unit").and_then(Value::as_str).map(String::from),
        what: string(row, "what"),
        empty: row.get("empty").and_then(Value::as_str).map(String::from),
        max_items: row.get("maxItems").and_then(Value::as_u64).map(|n| n as usize),
        mechanism: None,
        role: None,
        email: false,
        door: None,
    }
}

static TABLES: LazyLock<Vec<Table>> = LazyLock::new(|| {
    // A table that does not parse is a build that did not regenerate it;
    // tests/model_domain.js and this crate's own tests refuse that, so the
    // empty answer here is never what a service runs on.
    let all: Value = serde_json::from_str(SOURCE).unwrap_or(Value::Null);
    all.as_object()
        .map(|o| {
            o.iter()
                .map(|(id, t)| Table {
                    id: id.clone(),
                    schema: t.get("schema").cloned().unwrap_or(Value::Null),
                    fields: t
                        .get("fields")
                        .and_then(Value::as_array)
                        .map(|a| a.iter().map(field_of).collect())
                        .unwrap_or_default(),
                    selectors: t
                        .get("selectors")
                        .and_then(Value::as_array)
                        .map(|a| {
                            a.iter()
                                .map(|r| Selector {
                                    key: string(r, "key"),
                                    attribute: string(r, "attribute"),
                                    what: string(r, "what"),
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                    facts: t.get("facts").cloned().unwrap_or(Value::Null),
                })
                .collect()
        })
        .unwrap_or_default()
});

/// One object's tables (`policy.password` and the rest); an empty table
/// for an id the model does not hold.
#[tracing::instrument(level = "debug")]
pub fn table(id: &str) -> Table {
    TABLES
        .iter()
        .find(|t| t.id == id)
        .cloned()
        .unwrap_or_default()
}

/// Every object id the tables hold.
#[tracing::instrument(level = "debug")]
pub fn ids() -> Vec<String> {
    TABLES.iter().map(|t| t.id.clone()).collect()
}

/// `ModelTables.fields(id, bound, computed)`: the rows, each bound value
/// applied by key, and the computed rows put before the row `before`
/// names (at the end where none does, as `splice(-1)` would not: Node's
/// `findIndex()` of a missing key is -1, and a splice there inserts before
/// the LAST row — kept, since every kind names a key it has).
#[tracing::instrument(level = "debug", skip(bind, computed))]
pub fn fields(
    id: &str,
    bind: impl Fn(&mut Field),
    computed: Option<(&str, Vec<Field>)>,
) -> Vec<Field> {
    let mut rows = table(id).fields;
    rows.iter_mut().for_each(&bind);
    if let Some((before, extra)) = computed {
        let at = rows
            .iter()
            .position(|r| r.key == before)
            .unwrap_or(rows.len().saturating_sub(1));
        rows.splice(at..at, extra);
    }
    rows
}
