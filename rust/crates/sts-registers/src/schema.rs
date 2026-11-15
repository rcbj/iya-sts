// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The directory objects' SCHEMA tables, as `ModelTables.schema(id)` gives
//! them to the Node registers: generated from `models/directory/*.tsp` into
//! `generated/schemas.rs` by `models/lib/rust_lib.mjs`'s
//! `renderRustSchemas()`, never written by hand.

/// One attribute row: its name and whether it is `single` or `multi`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributeRow {
    pub name: &'static str,
    pub kind: &'static str,
}

/// One object's table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectSchema {
    pub id: &'static str,
    pub container: &'static str,
    pub object_classes: &'static [&'static str],
    pub attributes: &'static [AttributeRow],
}

#[rustfmt::skip]
mod generated {
    use super::{AttributeRow, ObjectSchema};
    include!("generated/schemas.rs");
}

pub use generated::SCHEMAS;

/// The table of one object, by its model id (`role`, `application`, …).
#[tracing::instrument(level = "debug")]
pub fn schema(id: &str) -> Option<&'static ObjectSchema> {
    SCHEMAS.iter().find(|one| one.id == id)
}

/// `['top'].concat(SCHEMA.objectClasses.map(name))`: the object classes an
/// entry of this object is written with.
#[tracing::instrument(level = "debug")]
pub fn object_classes_with_top(id: &str) -> Vec<String> {
    let mut out = vec!["top".to_string()];
    if let Some(found) = schema(id) {
        out.extend(found.object_classes.iter().map(|c| (*c).to_string()));
    }
    out
}
