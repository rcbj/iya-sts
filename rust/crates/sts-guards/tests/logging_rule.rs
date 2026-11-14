// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! GUARD 5. EVERY NAMED FUNCTION IS ENTERED AND LEFT OUT LOUD (root
//! `CLAUDE.md`, *Code style*, the parent project's rule; rust/DESIGN.md D3
//! and section 4.5).
//!
//! In Node every named function's first statement is `log.debug("Entering
//! NAME().")` and every exit logs `Leaving` — held by the 2026-09-12 sweep
//! and by review rather than by one test. In Rust it is
//! `#[tracing::instrument(level = "debug")]` on the function, which
//! `sts-core`'s logging layer writes as the same two lines (D3, decided on
//! the condition that the end result stays intact). This guard holds it for
//! every `pub` and `pub(…)` function in service code.
//!
//! THE EXEMPTIONS, as Node's:
//!   * **a hot path, which must say so**: a comment above the function (in
//!     its doc comment or the lines between it and the previous item)
//!     saying "hot path", or a file whose `//!` header says its functions
//!     are a hot path and carry no span (`sts-xacml`'s `pdp.rs`,
//!     `sts-store`'s `merge.rs`). An exemption without the words is
//!     indistinguishable from an oversight, which is the population this
//!     exists to catch;
//!   * a `const fn`, which `instrument` cannot wrap (its span is not a
//!     constant expression);
//!   * a declaration with no body (a trait's required method);
//!   * test code, build scripts and this crate, which are not the service.
//!
//! THE RATCHET. The rule was adopted after most of the Rust crates were
//! written: on 2026-11-14 the first run of this guard found 1,080 of the
//! 1,105 public functions in service code with neither the attribute nor a
//! hot-path comment — far too many to instrument in one mechanical edit,
//! most of them in crates other slices are changing. (`sts-runtime`'s four
//! were instrumented the same day, leaving 1,076.) So the violations are
//! a COMMITTED LIST, `allow/uninstrumented.txt`, one `file function` per
//! line, which may only SHRINK: a new function without the attribute
//! fails, and so does a line whose function has been instrumented, exempted
//! or removed — delete the line in the same change. Regenerate the list
//! only to remove lines:
//! `STS_GUARDS_WRITE=1 cargo test -p sts-guards --test logging_rule`
//! writes what is found now, and a diff that ADDS a line is the failure
//! this guard exists to report.

use std::fs;

use regex::Regex;
use sts_guards::{is_service_code, listed, ratchet, Workspace};

const LIST: &str = "crates/sts-guards/allow/uninstrumented.txt";

#[test]
fn every_public_function_is_instrumented_or_says_why_not() {
    let ws = Workspace::here();
    let hot = Regex::new(r"(?i)\bhot[ -]path\b").unwrap();
    let no_span =
        Regex::new(r"(?i)\b(instrument|span|logs?|tracing|entering)\b")
            .unwrap();
    let mut found = Vec::new();
    let mut public = 0;
    for f in ws.sources().unwrap() {
        if !is_service_code(&f.rel) {
            continue;
        }
        let header = f.module_doc();
        let file_exempt = hot.is_match(&header) && no_span.is_match(&header);
        for g in f.functions() {
            if g.visibility.is_none() || g.body.is_none() {
                continue;
            }
            public += 1;
            if g.is_const
                || file_exempt
                || g.preamble_code.contains("instrument")
                || hot.is_match(&g.preamble_raw)
            {
                continue;
            }
            found.push(format!("{} {}", f.rel, g.name));
        }
    }
    assert!(public > 100, "the scan found the functions it checks");
    if std::env::var("STS_GUARDS_WRITE").is_ok_and(|v| v == "1") {
        let mut text = String::from(
            "# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC\n\
             # SPDX-License-Identifier: BUSL-1.1\n\
             #\n\
             # Guard 5's ratchet (tests/logging_rule.rs): public functions in\n\
             # service code with no #[tracing::instrument] and no hot-path\n\
             # comment. This list may only shrink.\n",
        );
        let mut sorted = found.clone();
        sorted.sort();
        for line in &sorted {
            text.push_str(line);
            text.push('\n');
        }
        fs::write(ws.root().join(LIST), text).unwrap();
    }
    let allowed = fs::read_to_string(ws.root().join(LIST)).unwrap_or_default();
    let allowed: Vec<&str> = allowed
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .collect();
    let total = found.len();
    let (new, stale) = ratchet(found, allowed.iter().copied());
    assert!(
        new.is_empty() && stale.is_empty(),
        "every public function carries #[tracing::instrument(level = \
         \"debug\")], or a comment above it saying it is a hot path \
         (rust/DESIGN.md D3, section 4.5). {} public functions, {} \
         uninstrumented.\n  new, not on {}: {}\n  on the list but \
         instrumented, exempted or gone (delete the lines): {}",
        public,
        total,
        LIST,
        listed(&new),
        listed(&stale)
    );
}
