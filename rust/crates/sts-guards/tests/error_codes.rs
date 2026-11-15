// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! GUARD 1. EVERY FAILURE HAS AN ERROR CODE, AND NO CLIENT EVER SEES ONE
//! (root `CLAUDE.md`, *Every failure has an error code*).
//!
//! Mirrors `tests/error_codes.js`. Its claims 1–3 (the table well formed,
//! every code used registered, `docs/error-codes.md` current) are the
//! COMPILER's here: `sts-core`'s `build.rs` turns the one table into a
//! constant per code, so a code missing from the table does not compile,
//! and Node's scan already counts a `codes::STS_…` constant as a use. What
//! the compiler cannot see is a code written as TEXT, which compiles
//! whatever it says, and a refusal whose code is a bare `&str`. So:
//!
//!   1. no string literal in service code holds a code
//!      (`STS-<SUBSYSTEM>-<NNNN>`): a code is named by its constant,
//!      `codes::STS_XPEP_0013`, and only the generated table spells one;
//!   2. every refusal type — a struct or enum named `…Refusal`, `…Refusals`
//!      or `…Refused` — carries an `ErrorCode`: a field of that type, or,
//!      for an enum, a method of its `impl` answering one. A `&'static str`
//!      field is a code the compiler cannot check;
//!   3. claim 5, "no code reaches a client", is held by the TYPE: an
//!      `ErrorCode` is not `Serialize`, so it cannot be put into a JSON
//!      answer by accident, and `sts-http::mark()` carries it in the
//!      response's extensions, which no client receives. The wire half of
//!      claim 5 stays where Node's protocol jobs assert it, over HTTP.
//!
//! Not read, as Node does not read `tests/`: integration tests,
//! `#[cfg(test)]` items, build scripts, and this crate.
//!
//! THE EXCEPTIONS are the two tables below, keyed by file and what was
//! found, each with its reason. Both may only SHRINK: an entry that no
//! longer matches anything fails, so a fixed site cannot leave its
//! permission behind.

use regex::Regex;
use sts_guards::{is_service_code, listed, ratchet, Workspace};

/// Literals that still spell a code, `file|code`. Each is in a crate
/// another phase-2b slice is changing (rust/DESIGN.md section 11), where
/// it is listed rather than edited, or in the XACML engine, which depends
/// on nothing of the service's and so has no `ErrorCode` to name.
const LITERALS: &[(&str, &str)] = &[
    // sts-xacml is the ENGINE, shared by the runtime and the remote PEP,
    // and depends on no crate of the service's — `ErrorCode` is sts-core's.
    // Whether the engine takes sts-core (and its tokio and tracing
    // dependencies) for three codes is the xacml slice's decision.
    (
        "crates/sts-xacml/src/access.rs|STS-XACML-0044",
        "engine has no sts-core",
    ),
    (
        "crates/sts-xacml/src/access.rs|STS-XACML-0045",
        "engine has no sts-core",
    ),
    (
        "crates/sts-xacml/src/access.rs|STS-XACML-0046",
        "engine has no sts-core",
    ),
];

/// Refusal types without an `ErrorCode`, `file|Type`.
const REFUSAL_TYPES: &[(&str, &str)] = &[
    // A claim's outcome inside the scheduler, not a refusal anybody is
    // answered with: the scheduler records the code (STS-SCHED-…) when it
    // acts on one. Its name says "refused" because Node's does.
    (
        "crates/sts-cluster/src/scheduler.rs|ClaimRefused",
        "an internal outcome",
    ),
    // The XACML engine's `Refused::code()` answers `&'static str`, for the
    // reason LITERALS gives.
    (
        "crates/sts-xacml/src/access.rs|Refused",
        "engine has no sts-core",
    ),
];

#[test]
fn no_literal_spells_an_error_code() {
    let code_re = Regex::new(r"STS-[A-Z][A-Z0-9]{1,9}-[0-9]{4}").unwrap();
    let mut found = Vec::new();
    let mut at = Vec::new();
    for f in Workspace::here().sources().unwrap() {
        if !is_service_code(&f.rel) {
            continue;
        }
        for l in &f.literals {
            for m in code_re.find_iter(&l.text) {
                found.push(format!("{}|{}", f.rel, m.as_str()));
                at.push(format!(
                    "{}:{} {}",
                    f.rel,
                    f.line_of(l.start),
                    m.as_str()
                ));
            }
        }
    }
    assert!(found.len() + LITERALS.len() > 0);
    let (new, stale) = ratchet(found, LITERALS.iter().map(|(k, _)| *k));
    assert!(
        new.is_empty() && stale.is_empty(),
        "an error code is named by its constant, codes::STS_SUB_NNNN — the \
         compiler checks a constant against the one table and cannot check \
         text (root CLAUDE.md, *Every failure has an error code*).\n  \
         literals not allowed: {}\n  entries matching nothing (remove \
         them): {}\n  every literal found: {}",
        listed(&new),
        listed(&stale),
        listed(&at)
    );
}

#[test]
fn every_refusal_type_carries_an_error_code() {
    let decl = Regex::new(
        r"\bpub(?:\([^)]*\))?\s+(struct|enum)\s+([A-Za-z0-9_]*Refus(?:al|als|ed))\b",
    )
    .unwrap();
    let mut found = Vec::new();
    let mut seen = 0;
    for f in Workspace::here().sources().unwrap() {
        if !is_service_code(&f.rel) {
            continue;
        }
        for c in decl.captures_iter(&f.code) {
            seen += 1;
            let (kind, name) = (&c[1], c[2].to_string());
            let at = c.get(0).map(|m| m.end()).unwrap_or(0);
            let body = f.code[at..]
                .find('{')
                .and_then(|o| {
                    let open = at + o;
                    f.close_of(open).map(|close| &f.code[open..close])
                })
                .unwrap_or("");
            let mut ok = body.contains("ErrorCode");
            if !ok && kind == "enum" {
                // An enum's code is a method of its own `impl`.
                let imp =
                    Regex::new(&format!(r"\bimpl\s+{}\s*\{{", name)).unwrap();
                for m in imp.find_iter(&f.code) {
                    let open = m.end() - 1;
                    if let Some(close) = f.close_of(open) {
                        ok |= f.code[open..close].contains("-> ErrorCode");
                    }
                }
            }
            if !ok {
                found.push(format!("{}|{}", f.rel, name));
            }
        }
    }
    assert!(seen > 5, "the scan found the refusal types it checks");
    let (new, stale) = ratchet(found, REFUSAL_TYPES.iter().map(|(k, _)| *k));
    assert!(
        new.is_empty() && stale.is_empty(),
        "a refusal carries an ErrorCode (rust/DESIGN.md section 4.5), not \
         text the compiler cannot check.\n  without one: {}\n  entries \
         matching nothing (remove them): {}",
        listed(&new),
        listed(&stale)
    );
}

#[test]
fn an_error_code_cannot_be_serialized_into_an_answer() {
    let ws = Workspace::here();
    let errors = std::fs::read_to_string(
        ws.root().join("crates/sts-core/src/errors.rs"),
    )
    .unwrap();
    let derive =
        Regex::new(r"#\[derive\(([^)]*)\)\]\s*pub struct ErrorCode\b").unwrap();
    let derived = derive
        .captures(&errors)
        .map(|c| c[1].to_string())
        .expect("sts-core declares ErrorCode with a derive");
    assert!(
        !derived.contains("Serialize"),
        "ErrorCode derives Serialize: a code could be written into an \
         answer (root CLAUDE.md: RECORDED, NEVER SENT)"
    );
    let imp =
        Regex::new(r"\bimpl\b[^{;]*\bSerialize\s+for\s+ErrorCode\b").unwrap();
    let mut offenders = Vec::new();
    for f in ws.sources().unwrap() {
        if imp.is_match(&f.code) {
            offenders.push(f.rel.clone());
        }
    }
    assert!(
        offenders.is_empty(),
        "Serialize is implemented for ErrorCode in {}",
        listed(&offenders)
    );
}
