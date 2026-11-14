// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! GUARD 7. EVERY CRATE TAKES THE WORKSPACE'S LINTS (rust/DESIGN.md section
//! 4.5: no swallowed error and no panic in service code — `unwrap_used`,
//! `expect_used` and `let_underscore_must_use` denied, `unsafe_code`
//! denied — in `[workspace.lints]`).
//!
//! The lints are the workspace's, and a member that does not say
//! `[lints] workspace = true` silently has none of them: Cargo applies a
//! workspace's lint table only to the packages that opt in. Node's
//! counterpart is its style rule's "No swallowed exception", held by the
//! sweep. Two claims:
//!
//!   1. every package `cargo metadata` lists opts in;
//!   2. every directory under `crates/` and `bins/` with a `Cargo.toml` is a
//!      member, so a crate cannot leave the workspace — and with it every
//!      lint and every guard here — unnoticed.
//!
//! Exceptions: none.

use std::collections::BTreeSet;
use std::fs;

use regex::Regex;
use sts_guards::{listed, Workspace};

#[test]
fn every_member_opts_into_the_workspace_lints() {
    let ws = Workspace::here();
    let opted =
        Regex::new(r"(?m)^\[lints\]\s*\n\s*workspace\s*=\s*true\b").unwrap();
    let packages = ws.packages().unwrap();
    assert!(packages.len() > 10, "cargo metadata listed the members");
    let mut missing = Vec::new();
    for p in &packages {
        let text = fs::read_to_string(&p.manifest).unwrap();
        if !opted.is_match(&text) {
            missing.push(p.dir.clone());
        }
    }
    assert!(
        missing.is_empty(),
        "a member without `[lints] workspace = true` has none of the \
         workspace's lints (rust/DESIGN.md section 4.5): {}",
        listed(&missing)
    );
}

#[test]
fn every_crate_directory_is_a_member() {
    let ws = Workspace::here();
    let members: BTreeSet<String> =
        ws.packages().unwrap().into_iter().map(|p| p.dir).collect();
    let mut outside = Vec::new();
    for rel in ws.files().unwrap() {
        let parts: Vec<&str> = rel.split('/').collect();
        if parts.len() == 3
            && (parts[0] == "crates" || parts[0] == "bins")
            && parts[2] == "Cargo.toml"
        {
            let dir = format!("{}/{}", parts[0], parts[1]);
            if !members.contains(&dir) {
                outside.push(dir);
            }
        }
    }
    assert!(
        outside.is_empty(),
        "a crate directory that is not a workspace member escapes every \
         lint and every guard: {}",
        listed(&outside)
    );
}
