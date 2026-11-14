// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! An unexpected error is written down and contained, and no process
//! exits over one (#355) — the request half of `common/fault_boundary.ts`.
//!
//! Express catches a handler that throws and answers it through
//! `finalhandler` as a 500 (`<pre>Internal Server Error</pre>` in
//! production); `guardExpress()` extended that to a rejected promise. The
//! Rust counterpart of both is a handler that PANICS: [`contain`] runs the
//! route under `catch_unwind`, answers `finalhandler`'s 500 page, and logs
//! the fault under `STS-CORE-0143` — the first three occurrences of each
//! distinct fault in full, then the 10th, 100th, 1000th… with the running
//! count, so nothing is silent and nothing floods the log. No timer
//! summarises the rest: a repeating timer is a scheduler job (#49).
//!
//! **WHAT REPLACED WHAT.** The process half (`uncaughtException`,
//! `unhandledRejection`) has no Rust counterpart to install: an `Err` is a
//! value, and a panic in a spawned task ends that task, not the process
//! (tokio catches it at the task boundary). The workspace denies
//! `unwrap()` and `expect()` in service code so that the panics left are
//! defects, which is what this boundary writes down.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use axum::response::Response;
use sts_core::errors::codes;
use sts_core::log::tag;

/// Distinct faults remembered for the throttle; past it the oldest is
/// forgotten, and a forgotten fault that recurs is logged in full again.
const REMEMBERED: usize = 256;

fn seen() -> &'static Mutex<HashMap<String, u64>> {
    static SEEN: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();
    SEEN.get_or_init(|| Mutex::new(HashMap::new()))
}

/// How many times this fault has been met, counting this one.
fn count(fault: &str) -> u64 {
    let Ok(mut map) = seen().lock() else {
        return 1;
    };
    if map.len() >= REMEMBERED && !map.contains_key(fault) {
        map.clear();
    }
    let n = map.entry(fault.to_string()).or_insert(0);
    *n += 1;
    *n
}

fn worth_logging(n: u64) -> bool {
    if n <= 3 {
        return true;
    }
    let mut p = 10;
    while p < n {
        p *= 10;
    }
    p == n
}

/// The panic's message, as text.
fn message_of(panic: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = panic.downcast_ref::<&str>() {
        return (*s).to_string();
    }
    if let Some(s) = panic.downcast_ref::<String>() {
        return s.clone();
    }
    "a panic with no message".to_string()
}

/// Runs a route's future; a panic is contained and answered 500.
#[tracing::instrument(level = "debug", skip_all)]
pub async fn contain<F>(method: &str, path: &str, work: F) -> Response
where
    F: std::future::Future<Output = Response> + Send,
{
    use futures_util::FutureExt;
    match std::panic::AssertUnwindSafe(work).catch_unwind().await {
        Ok(response) => response,
        Err(panic) => {
            let message = message_of(&*panic);
            let n = count(&message);
            if worth_logging(n) {
                tracing::error!(
                    "{}fault_boundary: {} {} met an unexpected error, and \
                     the request was answered 500 rather than the process \
                     ending: {} (seen {} time{}).",
                    tag(codes::STS_CORE_0143),
                    method,
                    path,
                    message,
                    n,
                    if n == 1 { "" } else { "s" }
                );
            }
            crate::mark(crate::express::error_page(500), codes::STS_CORE_0143)
        }
    }
}
