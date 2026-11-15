// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Every operation `/admin-api` serves, as the model states them
//! (`models/api/management.tsp`, `console.tsp`), generated into
//! `generated/operations.rs` by `models/lib/rust_lib.mjs`.
//!
//! Node keeps its route table in code (`buildRoutes()`) and builds the
//! document from it; the model has been the document since #1390 and the
//! table is now the half the model does not hold. Here the model comes
//! FIRST: an [`Operation`] exists because the model has it, and the router
//! ([`crate::routing`]) is an exhaustive `match` over it, so an operation
//! the model adds does not compile until it is routed or listed as not yet
//! ported, and nothing can be routed that the model does not have.

/// Which of the two documents an operation is in (#454).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Management,
    Console,
}

impl Kind {
    /// The word the index and the routing rows use.
    pub const fn as_str(self) -> &'static str {
        match self {
            Kind::Management => "management",
            Kind::Console => "console",
        }
    }
}

/// One operation of the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationRow {
    pub operation: Operation,
    /// Its operationId.
    pub id: &'static str,
    pub method: &'static str,
    /// Its concrete path, `/admin-api/realms/create`.
    pub path: &'static str,
    pub kind: Kind,
}

#[rustfmt::skip]
#[allow(clippy::all, clippy::pedantic, non_camel_case_types, missing_docs)]
mod generated {
    use super::{Kind, OperationRow};
    include!("generated/operations.rs");
}

pub use generated::{Operation, OPERATIONS};

static BY_KEY: std::sync::LazyLock<
    std::collections::HashMap<String, &'static OperationRow>,
> = std::sync::LazyLock::new(|| {
    OPERATIONS
        .iter()
        .map(|row| (format!("{} {}", row.method, row.path), row))
        .collect()
});

static BY_ID: std::sync::LazyLock<
    std::collections::HashMap<&'static str, &'static OperationRow>,
> = std::sync::LazyLock::new(|| {
    OPERATIONS.iter().map(|row| (row.id, row)).collect()
});

/// The operation at a method and a concrete path. A hot path: asked once
/// per request, so it carries no span.
pub fn find(method: &str, path: &str) -> Option<&'static OperationRow> {
    let verb = if method.eq_ignore_ascii_case("HEAD") {
        "GET".to_string()
    } else {
        method.to_ascii_uppercase()
    };
    BY_KEY.get(&format!("{} {}", verb, path)).copied()
}

/// The operation an operationId names.
#[tracing::instrument(level = "debug")]
pub fn by_id(id: &str) -> Option<&'static OperationRow> {
    BY_ID.get(id).copied()
}

impl Operation {
    /// This operation's row.
    #[tracing::instrument(level = "debug")]
    pub fn row(self) -> &'static OperationRow {
        // Every variant has exactly one row: both are generated from one
        // list, in one order.
        &OPERATIONS[self as usize]
    }
}
