// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! ONE STORE, TWO DATABASES: WHAT DIFFERS BETWEEN THEM, IN ONE PLACE
//! (`persistence/sql_dialect.js`, #677).
//!
//! rcbj's decisions on #677 (2026-11-03): PostgreSQL is and stays the
//! primary store; MariaDB is a second engine. Node splits the store's SQL
//! three ways — ordinary statements compiled per engine by Knex, statements
//! that need one engine's feature written per engine, and the places where
//! the DESIGN differs (counting triggers, GIN, LISTEN) given code of their
//! own, which `capabilities` names. Here the two drivers
//! (`postgres.rs`, `mariadb.rs`) are the per-engine code, and this trait is
//! what they, and a caller choosing how to run one, ask of an engine:
//!
//! * the statement clock, in the milliseconds every cluster table stores —
//!   evaluated when it runs, never the transaction's start;
//! * the capabilities a design leans on, a missing one being a fallback the
//!   driver takes, never a feature it pretends;
//! * how often the change log is polled where nothing nudges
//!   (`POLL_WITHOUT_NUDGE_MS`: one indexed read a process a second);
//! * the schema the model gives that engine (`schema.rs`);
//! * which server errors a transaction runs again for, and which are a key
//!   another writer took first.
//!
//! What replaced Knex: nothing does. Each driver writes its statements in
//! its engine's own text, every column list through `schema.rs`'s
//! model-checked macros, so the one thing Knex gave the Node driver that
//! this would otherwise lose — one list of columns for both engines — is
//! the model's instead.

use crate::schema::{Schema, MARIADB, POSTGRES};

/// The two engines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    Postgres,
    Mariadb,
}

/// What an engine can do that a driver's design leans on (`CAPABILITIES`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    /// LISTEN/NOTIFY: the nudge that wakes the change-log poll early.
    pub nudge: bool,
    /// Statement-level triggers over transition tables (the counts).
    pub transition_triggers: bool,
    /// `synchronous_commit = off` for a statement.
    pub async_commit: bool,
    /// A transaction-scoped advisory lock.
    pub transaction_locks: bool,
    /// `UPDATE … RETURNING`.
    pub update_returning: bool,
    /// GIN indexes over JSON arrays.
    pub json_indexes: bool,
}

/// The change-log poll where an engine has no nudge (rcbj on #677).
pub const POLL_WITHOUT_NUDGE_MS: u64 = 1000;

/// What a driver asks of its engine.
pub trait Dialect: Send + Sync {
    fn engine(&self) -> Engine;
    /// `postgres` or `mariadb`, as `persistence.mode` names the engine.
    fn name(&self) -> &'static str;
    /// The tables and columns the model gives this engine.
    fn schema(&self) -> &'static Schema;
    /// The statement clock, in milliseconds (`NOW`).
    fn now(&self) -> &'static str;
    fn capabilities(&self) -> Capabilities;
    /// How often the change log must be polled: `None` where a nudge makes
    /// the poll a backstop the caller times as it likes.
    fn poll_without_nudge_ms(&self) -> Option<u64> {
        if self.capabilities().nudge {
            None
        } else {
            Some(POLL_WITHOUT_NUDGE_MS)
        }
    }
    /// A deadlock or a lock wait, which running the transaction again
    /// resolves (`isRetryable()`): the server's code or SQLSTATE.
    fn is_retryable(&self, code: &str) -> bool;
    /// Another writer took the key first (`isUniqueViolation()`).
    fn is_unique_violation(&self, code: &str) -> bool;
}

/// PostgreSQL, the reference engine.
pub struct Postgres;

/// MariaDB, the second engine (#677).
pub struct Mariadb;

/// PostgreSQL's statement clock (`DB_NOW`).
pub const POSTGRES_NOW: &str =
    "(extract(epoch from clock_timestamp()) * 1000)::bigint";

/// MariaDB's: `SYSDATE(6)` is evaluated when it runs; `NOW(6)` is fixed at
/// the start of the statement. Microseconds, rounded to the millisecond.
pub const MARIADB_NOW: &str =
    "CAST(ROUND(UNIX_TIMESTAMP(SYSDATE(6)) * 1000) AS SIGNED)";

impl Dialect for Postgres {
    fn engine(&self) -> Engine {
        Engine::Postgres
    }

    fn name(&self) -> &'static str {
        "postgres"
    }

    fn schema(&self) -> &'static Schema {
        &POSTGRES
    }

    fn now(&self) -> &'static str {
        POSTGRES_NOW
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            nudge: true,
            transition_triggers: true,
            async_commit: true,
            transaction_locks: true,
            update_returning: true,
            json_indexes: true,
        }
    }

    fn is_retryable(&self, code: &str) -> bool {
        code == "40P01" || code == "40001"
    }

    fn is_unique_violation(&self, code: &str) -> bool {
        code == "23505"
    }
}

impl Dialect for Mariadb {
    fn engine(&self) -> Engine {
        Engine::Mariadb
    }

    fn name(&self) -> &'static str {
        "mariadb"
    }

    fn schema(&self) -> &'static Schema {
        &MARIADB
    }

    fn now(&self) -> &'static str {
        MARIADB_NOW
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            nudge: false,
            transition_triggers: false,
            async_commit: false,
            transaction_locks: false,
            update_returning: false,
            json_indexes: false,
        }
    }

    fn is_retryable(&self, code: &str) -> bool {
        code == "1213" || code == "1205"
    }

    fn is_unique_violation(&self, code: &str) -> bool {
        code == "1062"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mariadb_polls_where_postgres_is_nudged() {
        assert_eq!(Postgres.poll_without_nudge_ms(), None);
        assert_eq!(Mariadb.poll_without_nudge_ms(), Some(1000));
        assert_eq!(Mariadb.schema().engine, "mariadb");
        assert!(Mariadb.is_unique_violation("1062"));
        assert!(Postgres.is_retryable("40P01"));
    }
}
