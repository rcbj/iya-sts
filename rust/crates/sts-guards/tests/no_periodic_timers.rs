// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! GUARD 2. ANYTHING PERIODIC IS A SCHEDULER JOB (root `CLAUDE.md`, *Anything
//! periodic is a scheduler job*; rcbj's directive of 2026-09-21, #49).
//!
//! Mirrors `tests/no_periodic_timers.js`. No module starts a repeating timer
//! of its own: work that repeats is a job on `sts-cluster`'s scheduler,
//! which runs each job on exactly one node. This reads the service's own
//! source — not the tests, not the build script, not this crate — and
//! finds every REPEATING timer:
//!
//!   * every `interval(` / `interval_at(` (`tokio::time::interval`), which
//!     exists only to repeat;
//!   * every `sleep(` / `sleep_until(` (tokio's or `std::thread`'s) inside a
//!     `loop`, `while` or `for` of the same function — the Rust spelling of
//!     `setInterval`, however the task around it is spawned;
//!   * every `sleep(` in a function that calls itself — the `setTimeout`
//!     chain Node's guard catches by recursion.
//!
//! A one-shot delay — a debounce, a retry delay inside one operation, a
//! timeout — is none of these and is not reported, as the directive leaves
//! it where it is. `tokio::time::timeout()` is not a timer here at all.
//!
//! Each timer found must be on ALLOWED, keyed by `file|function|kind`, with
//! why it is PERMANENT (Node's permanent exceptions, translated) or the
//! scheduler job it BECOMES. An entry whose timer has gone fails too — THE
//! LIST ONLY EVER SHRINKS.
//!
//! NOT READ, each for Node's reason:
//!   * the scheduler itself (`sts-cluster/src/scheduler.rs` and
//!     `scheduler/`), the one place a repeating timer belongs (Node's
//!     `THE_SCHEDULER`);
//!   * `bins/xacml-pep`, the remote PEP: a second container with no
//!     scheduler, which Node's guard skips (`xacml-pep` in its `SKIP`). Its
//!     policy pull, heartbeat and certificate reload are its own loops.

use sts_guards::{is_service_code, listed, ratchet, Workspace};

/// `file|function|kind` → why it stays.
const ALLOWED: &[(&str, &str)] = &[
    // Node's 'cluster/cluster.js|scheduleHeartbeat|timeout': the cluster
    // heartbeat. The scheduler's own leadership is a lease this renews, so
    // it cannot run on the scheduler.
    (
        "crates/sts-cluster/src/membership.rs|join|loop",
        "the heartbeat",
    ),
];

fn skipped(rel: &str) -> bool {
    rel == "crates/sts-cluster/src/scheduler.rs"
        || rel.starts_with("crates/sts-cluster/src/scheduler/")
        || rel.starts_with("bins/xacml-pep/")
}

#[test]
fn no_module_starts_a_repeating_timer() {
    let mut found = Vec::new();
    let mut at = Vec::new();
    let mut read = 0;
    for f in Workspace::here().sources().unwrap() {
        if !is_service_code(&f.rel) || skipped(&f.rel) {
            continue;
        }
        read += 1;
        for t in f.repeating_timers() {
            found.push(format!("{}|{}|{}", f.rel, t.function, t.kind));
            at.push(format!(
                "{}:{} {}() {}",
                f.rel,
                f.line_of(t.at),
                t.function,
                t.kind
            ));
        }
    }
    assert!(read > 50, "the walk found the source files it checks");
    let (new, stale) = ratchet(found, ALLOWED.iter().map(|(k, _)| *k));
    assert!(
        new.is_empty() && stale.is_empty(),
        "anything this service does periodically is a job on sts-cluster's \
         scheduler, and no module starts a repeating timer of its own (root \
         CLAUDE.md, *Anything periodic is a scheduler job*; cluster/CLAUDE.md \
         has the table of jobs).\n  repeating timers not on ALLOWED: {}\n  \
         ALLOWED entries whose timer has gone (remove them): {}\n  every \
         timer found: {}",
        listed(&new),
        listed(&stale),
        listed(&at)
    );
}
