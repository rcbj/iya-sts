// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A MariaDB write names its rows by column equalities, never by a row
//! constructor — Node's `sql_dialect.whereKeys()` (develop 7b4af8837,
//! 2026-11-14). MariaDB 11.8 plans a single-table DELETE or UPDATE whose
//! WHERE is `(a, b) IN ((?, ?))` with ONE tuple as a full table scan
//! (`EXPLAIN`: `type ALL`, `possible_keys NULL`) although the tuple is the
//! whole key, and a scanning write at READ COMMITTED waits on, and
//! deadlocks with, every row another transaction holds; `a = ? AND b = ?`
//! is a range on the key. Node moved its minted flush's three DELETEs, the
//! claims' release and the risk engine's stalled-import UPDATE onto it.
//! This driver already wrote each of those as one statement per row with
//! equalities (`sts_minted`, `sts_sessions`, `sts_minted_index`,
//! `sts_cluster_claims`; the risk tables are not ported), so the port is
//! this pin: no DELETE or UPDATE in `src/mariadb.rs` may hold `) IN (`.
//!
//! EXCEPT THE TWO NODE STILL WRITES THAT WAY, kept for parity and listed
//! here by their statement's start: `directory_portable.js`'s
//! `rewriteKeys()` (`DELETE FROM sts_ldap_entry_keys WHERE (realm,
//! dn_key) IN (…)`) and its counts fold (`UPDATE <counts> SET n = n +
//! CASE … WHERE shard = ? AND (<key>) IN (…)`). Both scan on 11.8 with one
//! tuple, measured: a Node defect, reported, not fixed here.

use std::path::PathBuf;

/// The statements Node writes with a row constructor too.
const AS_NODE: [&str; 2] = [
    "DELETE FROM sts_ldap_entry_keys WHERE (realm, dn_key) IN (",
    "UPDATE {} SET n = n + CASE {} ELSE 0 END WHERE shard = ? AND ({}) IN (",
];

/// Every string literal in `source` that starts with `head`.
fn literals<'a>(source: &'a str, head: &str) -> Vec<&'a str> {
    let open = format!("\"{head}");
    let mut out = Vec::new();
    let mut rest = source;
    while let Some(i) = rest.find(&open) {
        let body = &rest[i + 1..];
        let end = body.find('"').unwrap_or(body.len());
        out.push(&body[..end]);
        rest = &body[end..];
    }
    out
}

#[test]
fn mariadb_writes_name_keys_by_equalities() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/mariadb.rs");
    let source = std::fs::read_to_string(&path).expect("src/mariadb.rs");
    let mut writes = literals(&source, "DELETE ");
    writes.extend(literals(&source, "UPDATE "));
    assert!(writes.len() > 20, "found only {} writes", writes.len());
    let mut kept = 0;
    for sql in writes {
        if !sql.contains(") IN (") {
            continue;
        }
        assert!(
            AS_NODE.iter().any(|n| sql.starts_with(n)),
            "a MariaDB write names its rows by a row constructor, which \
             11.8 plans as a table scan with one tuple: {sql}"
        );
        kept += 1;
    }
    assert_eq!(kept, AS_NODE.len(), "Node's two row constructors moved");
}
