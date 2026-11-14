// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Where a cluster run's body runs, and how busy that is (#408).
//!
//! **In Node** the leader handed a cluster run's body to the least-loaded
//! ready protocol-pool `worker_threads` Worker (`Scheduler.leastLoaded()`:
//! fewest requests in flight, then the shortest event-loop delay, then the
//! lowest id) so that the front process's thread, which owns every
//! listener, never ran a job body; and a due SCHEDULED run was HELD while
//! even that worker was heavy (`holdForLoad()`), for at most
//! min(`scheduler.niceMaxDeferS` × nice / 19, half the job's interval).
//!
//! **In Rust there is one process on a multi-threaded tokio runtime.** A
//! body is a task the runtime places on whichever of its worker threads is
//! free — work stealing does what `leastLoaded()` did, and no thread owns
//! the listeners, so nothing has to be kept free of job bodies. What stands
//! for the pool is [`Loads`]: what the process can say about how busy that
//! runtime is, as one or more [`WorkerLoad`]s. [`RuntimeLoad`] is the
//! runtime's own: requests in flight (an [`InFlight`] guard per request,
//! taken by the HTTP layer) and the scheduler loops' own lateness waking
//! from a sleep, which is the event-loop delay's equivalent: how long a
//! ready task waited for a thread. The hold rule is Node's, unchanged, and
//! reads those two signals.
//!
//! With no [`Loads`] at all the scheduler behaves as Node with no worker:
//! the body "runs on the front" (`ranIn: "front"`) and nothing is held.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

/// One worker's load, as `leastLoaded()` reads it.
#[derive(Clone, Debug, PartialEq)]
pub struct WorkerLoad {
    pub id: u64,
    /// Requests and operations in flight there now.
    pub in_flight: f64,
    /// Its recent scheduling delay in milliseconds, or `None` when it has
    /// not reported one lately.
    pub lag_ms: Option<f64>,
}

/// How busy the threads a cluster run's body would run on are.
pub trait Loads: Send + Sync {
    /// The ready workers and their load; empty when there are none.
    fn workers(&self) -> Vec<WorkerLoad>;
    /// A scheduler loop woke `ms` after it meant to. The runtime's own
    /// [`RuntimeLoad`] keeps it as its lag; a test's stand-in ignores it.
    fn note_lag(&self, _ms: f64) {}
}

/// The worker with the fewest requests in flight, then the shortest recent
/// delay, then the lowest id (`Scheduler.leastLoaded()`).
#[tracing::instrument(level = "debug", skip_all)]
pub fn least_loaded(loads: &[WorkerLoad]) -> Option<u64> {
    let mut list = loads.to_vec();
    list.sort_by(|a, b| {
        a.in_flight
            .total_cmp(&b.in_flight)
            .then(a.lag_ms.unwrap_or(0.0).total_cmp(&b.lag_ms.unwrap_or(0.0)))
            .then(a.id.cmp(&b.id))
    });
    list.first().map(|w| w.id)
}

/// How long a reported lag counts as recent: past this it is `None`, as a
/// Node worker that has not reported lately.
const LAG_FRESH_MS: i64 = 30_000;

/// The tokio runtime's load, as one worker (id 1).
#[derive(Default)]
pub struct RuntimeLoad {
    in_flight: AtomicU64,
    lag_ms: AtomicU64,
    lag_at_ms: AtomicI64,
}

/// One request in flight; dropping it ends it.
pub struct InFlight(Arc<RuntimeLoad>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

impl RuntimeLoad {
    #[tracing::instrument(level = "debug")]
    pub fn new() -> Arc<RuntimeLoad> {
        Arc::new(RuntimeLoad::default())
    }

    /// A request begins. A HOT PATH (every request): no instrument.
    pub fn enter(self: &Arc<Self>) -> InFlight {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        InFlight(self.clone())
    }
}

impl Loads for RuntimeLoad {
    fn workers(&self) -> Vec<WorkerLoad> {
        let at = self.lag_at_ms.load(Ordering::Relaxed);
        let now = sts_core::time::now_ms_f64() as i64;
        let lag_ms = (at > 0 && now - at <= LAG_FRESH_MS)
            .then(|| self.lag_ms.load(Ordering::Relaxed) as f64);
        vec![WorkerLoad {
            id: 1,
            in_flight: self.in_flight.load(Ordering::Relaxed) as f64,
            lag_ms,
        }]
    }

    fn note_lag(&self, ms: f64) {
        self.lag_ms.store(ms.max(0.0) as u64, Ordering::Relaxed);
        self.lag_at_ms
            .store(sts_core::time::now_ms_f64() as i64, Ordering::Relaxed);
    }
}
