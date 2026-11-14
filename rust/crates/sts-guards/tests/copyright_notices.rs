// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! GUARD 6. EVERY SOURCE FILE STARTS WITH ITS TWO SPDX LINES (root
//! `CLAUDE.md`, *Code style*, 2026-09-27; BUSL-1.1 since 2026-09-30).
//!
//! Mirrors `tests/copyright_notices.js`, which walks the whole repository
//! and so reads `rust/` today — but only the `.rs` files: its `COMMENTED`
//! extensions have `rs` and not `toml`, so the workspace's `Cargo.toml`,
//! `rustfmt.toml` and `clippy.toml` were covered only by `REUSE.toml`'s
//! catch-all, never checked for a header. This guard reads every `.rs`
//! (build scripts and tests included) and every `.toml` under `rust/`, in
//! the first eight lines as Node does (any year, Node's `HOLDER`), and
//! stays when Node's goes (D12).
//!
//! Not read: `target/` (cargo's output), `Cargo.lock` (cargo writes it and
//! would drop a comment; REUSE.toml's catch-all covers it), and files that
//! cannot carry a comment (`.json` tables, `DESIGN.md`), which REUSE.toml
//! covers the same way.

use std::fs;

use sts_guards::{listed, Workspace};

// REUSE-IgnoreStart
const COPYRIGHT: &str = "SPDX-FileCopyrightText:";
const HOLDER: &str = "Iya CyberSecurity Solutions, LLC";
const LICENCE: &str = "SPDX-License-Identifier: BUSL-1.1";
// REUSE-IgnoreEnd
const WINDOW: usize = 8;

#[test]
fn every_rust_and_toml_file_carries_its_header() {
    let ws = Workspace::here();
    let mut missing = Vec::new();
    let mut read = 0;
    for rel in ws.files().unwrap() {
        if !(rel.ends_with(".rs") || rel.ends_with(".toml")) {
            continue;
        }
        read += 1;
        let text = fs::read_to_string(ws.root().join(&rel)).unwrap();
        let head: Vec<&str> = text.lines().take(WINDOW).collect();
        let holder = head
            .iter()
            .any(|l| l.contains(COPYRIGHT) && l.contains(HOLDER));
        let licence = head.iter().any(|l| l.contains(LICENCE));
        if !(holder && licence) {
            missing.push(rel);
        }
    }
    assert!(read > 100, "the walk found the files it checks");
    assert!(
        missing.is_empty(),
        "every source file this repository owns starts with its two SPDX \
         lines (root CLAUDE.md, *Code style*; LICENSE.md shows the form): {}",
        listed(&missing)
    );
}
