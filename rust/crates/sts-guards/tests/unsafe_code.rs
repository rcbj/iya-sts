// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! GUARD 4. `unsafe` ONLY IN `sts-crypto`'S `pq.rs` (rust/DESIGN.md section
//! 6: where the `openssl` crate has no safe binding — ML-DSA, SLH-DSA,
//! ML-KEM, HPKE — `sts-crypto` holds a small wrapper over `openssl-sys`,
//! and "that wrapper is the only `unsafe` code in the workspace").
//!
//! Node has no counterpart: JavaScript has no `unsafe`. Three claims:
//!
//!   1. every library and binary root says `#![forbid(unsafe_code)]`, which
//!      no `allow` beneath it can undo — except `sts-crypto`'s, which says
//!      `#![deny(unsafe_code)]`, because a `forbid` would refuse `pq.rs`'s
//!      own `#![allow(unsafe_code)]`;
//!   2. no file but `pq.rs` says `allow(unsafe_code)` (or `expect`);
//!   3. no file but `pq.rs` uses the keyword `unsafe` at all — read over
//!      EVERY `.rs` in the workspace, tests and build scripts included,
//!      whose crates get the workspace's `unsafe_code = "deny"` and no
//!      `forbid` of their own.

use regex::Regex;
use sts_guards::{listed, SourceFile, Workspace};

const THE_WRAPPER: &str = "crates/sts-crypto/src/pq.rs";

#[test]
fn every_crate_root_forbids_unsafe_code() {
    let ws = Workspace::here();
    let forbid = Regex::new(r"(?m)^#!\[forbid\(unsafe_code\)\]").unwrap();
    let deny = Regex::new(r"(?m)^#!\[deny\(unsafe_code\)\]").unwrap();
    let mut missing = Vec::new();
    let mut roots = 0;
    for p in ws.packages().unwrap() {
        for t in &p.targets {
            if !t.kinds.iter().any(|k| k == "lib" || k == "bin") {
                continue;
            }
            roots += 1;
            let text = std::fs::read_to_string(ws.root().join(&t.src)).unwrap();
            let ok = if p.name == "sts-crypto" {
                deny.is_match(&text) && !forbid.is_match(&text)
            } else {
                forbid.is_match(&text)
            };
            if !ok {
                missing.push(t.src.clone());
            }
        }
    }
    assert!(roots > 10, "cargo metadata listed the crate roots");
    assert!(
        missing.is_empty(),
        "every crate root forbids unsafe code, and sts-crypto's denies it \
         (rust/DESIGN.md section 6): {}",
        listed(&missing)
    );
}

#[test]
fn no_unsafe_outside_the_post_quantum_wrapper() {
    let keyword = Regex::new(r"\bunsafe\b").unwrap();
    let allow =
        Regex::new(r"\b(?:allow|expect)\s*\(\s*unsafe_code\s*\)").unwrap();
    let mut offenders = Vec::new();
    let mut wrapper_seen = false;
    for f in Workspace::here().sources().unwrap() {
        if f.rel == THE_WRAPPER {
            wrapper_seen = true;
            continue;
        }
        // Read with its test code: a test is not exempt here.
        let code = SourceFile::with_tests(f.rel.clone(), f.raw.clone()).code;
        for m in keyword.find_iter(&code).chain(allow.find_iter(&code)) {
            offenders.push(format!("{}:{}", f.rel, f.line_of(m.start())));
        }
    }
    assert!(
        wrapper_seen,
        "{} is where the design says it is",
        THE_WRAPPER
    );
    assert!(
        offenders.is_empty(),
        "`unsafe` is sts-crypto's pq.rs alone (rust/DESIGN.md section 6): {}",
        listed(&offenders)
    );
}
