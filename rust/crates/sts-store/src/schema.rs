// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The store's tables and columns, FROM THE MODEL (#1390; #444 phase 3).
//!
//! `models/persistence/*.tsp` is the one source of every table, column and
//! index both engines hold. The Node service compiles it into the statements
//! `persistence_postgres.js` and `schema_mariadb.js` run and into
//! `postgres/schema.sql` / `mariadb/schema.sql`; for this crate
//! `models/lib/rust_lib.mjs`'s `renderRustPersistence()` writes the same
//! tables as the constants in `generated/persistence.rs`, committed by
//! `tests/tools/regenerate-model-docs.sh` and held to the model by
//! `tests/model_domain.js`, as `sts-model`'s files are.
//!
//! **What a driver names is checked against them WHEN THE CRATE BUILDS.**
//! A column list is written with [`columns!`], which expands to the
//! comma-separated list and to a `const` assertion that every name is a
//! column of that table in that engine's model; a name that is not refuses
//! to compile, with the table named in the message. So a column renamed or
//! dropped in the model breaks this crate's build the day it is
//! regenerated, rather than its first query against a store.
//!
//! The DDL stays Node's (rcbj, 2026-11-14): this crate creates no table and
//! carries no `CREATE`. What it takes from the model is the names, the
//! schema version it writes to `sts_schema`, and the tables `open()`
//! refuses a store without.

/// One column as the model declares it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Column {
    pub name: &'static str,
    /// The SQL type, as the engine spells it.
    pub sql: &'static str,
    pub required: bool,
    /// Computed by the database (`GENERATED ALWAYS … STORED`): read, never
    /// written.
    pub generated: bool,
    pub primary_key: bool,
    /// Added after the table first shipped (`ALTER TABLE … ADD COLUMN`).
    pub added: bool,
}

/// One table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Table {
    pub name: &'static str,
    pub columns: &'static [Column],
}

/// One object the Node driver makes, in its order: a table or an index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaObject {
    pub name: &'static str,
    pub table: bool,
}

/// One engine's schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schema {
    /// `postgres` or `mariadb`.
    pub engine: &'static str,
    /// What `sts_schema` records (`SCHEMA_VERSION`).
    pub version: i32,
    pub tables: &'static [Table],
    pub objects: &'static [SchemaObject],
    /// `(table, column)` of every column added after its table shipped.
    pub added: &'static [(&'static str, &'static str)],
}

#[rustfmt::skip]
#[allow(clippy::all, clippy::pedantic, missing_docs)]
mod generated {
    include!("generated/persistence.rs");
}

pub use generated::{MARIADB, POSTGRES};

/// `a == b`, in a const context.
pub const fn same(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

impl Schema {
    /// The table the model calls `name`, in a const context.
    pub const fn table(&self, name: &str) -> Option<&'static Table> {
        let mut i = 0;
        while i < self.tables.len() {
            if same(self.tables[i].name, name) {
                return Some(&self.tables[i]);
            }
            i += 1;
        }
        None
    }

    /// Whether `table` has every one of `columns`. Evaluated when the crate
    /// builds, by [`columns!`].
    pub const fn has_columns(&self, table: &str, columns: &[&str]) -> bool {
        self.holds(table, columns, false)
    }

    /// Whether `table` has every one of `columns` and none of them is
    /// computed by the database, which refuses a statement that writes
    /// one. Evaluated when the crate builds, by [`written!`].
    pub const fn writes_columns(&self, table: &str, columns: &[&str]) -> bool {
        self.holds(table, columns, true)
    }

    const fn holds(
        &self,
        table: &str,
        columns: &[&str],
        writing: bool,
    ) -> bool {
        let Some(t) = self.table(table) else {
            return false;
        };
        let mut i = 0;
        while i < columns.len() {
            let mut found = false;
            let mut j = 0;
            while j < t.columns.len() {
                if same(t.columns[j].name, columns[i])
                    && !(writing && t.columns[j].generated)
                {
                    found = true;
                }
                j += 1;
            }
            if !found {
                return false;
            }
            i += 1;
        }
        true
    }

    /// The names of every table, in the model's order.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn table_names(&self) -> Vec<&'static str> {
        self.tables.iter().map(|t| t.name).collect()
    }
}

/// A column list of one table, checked against one engine's model when the
/// crate builds: `columns!(POSTGRES, "sts_sessions", realm, key)` is
/// `"realm, key"`, and a name the model's `sts_sessions` has not got is a
/// compile error.
#[macro_export]
macro_rules! columns {
    // MariaDB's names in backticks, every one: `key` is a reserved word
    // there, and a quoted identifier is the same column on that engine.
    (MARIADB, $table:literal, $first:ident $(, $rest:ident)* $(,)?) => {{
        const _: () = assert!(
            $crate::schema::MARIADB.has_columns(
                $table,
                &[stringify!($first) $(, stringify!($rest))*]
            ),
            concat!(
                "a column named here is not in the model's MariaDB ",
                $table,
                " (models/persistence/; run tests/tools/",
                "regenerate-model-docs.sh)"
            )
        );
        concat!("`", stringify!($first), "`" $(, ", `", stringify!($rest), "`")*)
    }};
    ($schema:ident, $table:literal, $first:ident $(, $rest:ident)* $(,)?) => {{
        const _: () = assert!(
            $crate::schema::$schema.has_columns(
                $table,
                &[stringify!($first) $(, stringify!($rest))*]
            ),
            concat!(
                "a column named here is not in the model's ",
                $table,
                " (models/persistence/; run tests/tools/",
                "regenerate-model-docs.sh)"
            )
        );
        concat!(stringify!($first) $(, ", ", stringify!($rest))*)
    }};
}

/// The columns a statement WRITES, as [`columns!`], and none of them one
/// the database computes.
#[macro_export]
macro_rules! written {
    // MariaDB's names in backticks, every one: `key` is a reserved word
    // there, and a quoted identifier is the same column on that engine.
    (MARIADB, $table:literal, $first:ident $(, $rest:ident)* $(,)?) => {{
        const _: () = assert!(
            $crate::schema::MARIADB.writes_columns(
                $table,
                &[stringify!($first) $(, stringify!($rest))*]
            ),
            concat!(
                "a column named here is not in the model's MariaDB ",
                $table,
                " (models/persistence/; run tests/tools/",
                "regenerate-model-docs.sh)"
            )
        );
        concat!("`", stringify!($first), "`" $(, ", `", stringify!($rest), "`")*)
    }};
    ($schema:ident, $table:literal, $first:ident $(, $rest:ident)* $(,)?) => {{
        const _: () = assert!(
            $crate::schema::$schema.writes_columns(
                $table,
                &[stringify!($first) $(, stringify!($rest))*]
            ),
            concat!(
                "a column written here is not a writable column of the ",
                "model's ",
                $table,
                " (models/persistence/; run tests/tools/",
                "regenerate-model-docs.sh)"
            )
        );
        concat!(stringify!($first) $(, ", ", stringify!($rest))*)
    }};
}

/// A table's name, checked against one engine's model when the crate
/// builds.
#[macro_export]
macro_rules! table {
    ($schema:ident, $table:literal) => {{
        const _: () = assert!(
            $crate::schema::$schema.table($table).is_some(),
            concat!("the model has no table ", $table)
        );
        $table
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_engines_come_from_the_model() {
        assert_eq!(POSTGRES.engine, "postgres");
        assert_eq!(MARIADB.engine, "mariadb");
        const { assert!(POSTGRES.version >= 32) };
        assert_eq!(POSTGRES.version, MARIADB.version);
        // The tables only MariaDB has: its stand-in for GIN.
        assert!(MARIADB.table("sts_ldap_entry_keys").is_some());
        assert!(POSTGRES.table("sts_ldap_entry_keys").is_none());
        let c = columns!(POSTGRES, "sts_sessions", realm, key, expires_at);
        assert_eq!(c, "realm, key, expires_at");
        assert!(!POSTGRES.has_columns("sts_sessions", &["nope"]));
        let m = columns!(MARIADB, "sts_sessions", realm, key);
        assert_eq!(m, "`realm`, `key`");
        assert!(!POSTGRES.has_columns("sts_nothing", &["realm"]));
        assert!(POSTGRES.has_columns("sts_ldap_entries", &["parent_key"]));
        assert!(!POSTGRES.writes_columns("sts_ldap_entries", &["parent_key"]));
    }

    #[test]
    fn every_object_is_a_table_or_an_index_of_one() {
        for schema in [POSTGRES, MARIADB] {
            for object in schema.objects {
                assert_eq!(
                    object.table,
                    schema.table(object.name).is_some(),
                    "{} {}",
                    schema.engine,
                    object.name
                );
            }
            for (table, column) in schema.added {
                assert!(schema.has_columns(table, &[column]));
            }
        }
    }
}
