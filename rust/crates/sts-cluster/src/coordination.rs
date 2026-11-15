// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What the Node worker pool guaranteed, in a runtime that has no pool
//! (`common/request_pool.js`, `cluster/cluster_barrier.js`, the root
//! CLAUDE.md's *One front process, and what a socket cannot share*; the
//! argument is rust/DESIGN.md's *The concurrency model*).
//!
//! Node ran one front process owning every listener and N `worker_threads`
//! Workers, each with ITS OWN COPY of the store's state, kept current from
//! the change log. So it needed tickets (a write answered by a worker), a
//! generation per worker, a read barrier that made a reader wait until its
//! worker had applied the writes answered before it, and `readYourWrite`
//! to narrow that wait to the reader's own session. **Rust runs one process
//! on one tokio runtime, and its state is ONE copy shared by every task**:
//! a write a handler made is in that copy before its response is sent, so
//! the next request of the same session — on any task, on any thread — reads
//! it. Inside one process read-your-write holds by construction, and the
//! tickets, generations and per-worker barrier have nothing left to guard.
//!
//! **Between processes it does not hold by construction**, and the two rules
//! of `cluster_barrier.js` carry over unchanged, here:
//!
//! 1. [`ReadBarrier`]: a request is served only after this process has
//!    applied everything another process committed BEFORE the request
//!    arrived — proved by a change-log pull that STARTED after the request
//!    did and finished CAUGHT UP. One pull serves every reader that arrived
//!    before it started.
//! 2. [`CommitGate`]: a request that wrote is answered only once its writes
//!    have committed, so a client that is answered and asks another node
//!    finds the write in that node's pull.
//!
//! Together they are read-your-write across nodes, which is what Node's
//! active-active barrier gave and what its pool gave between workers.
//!
//! **A BARRIER THAT RUNS OUT IS A REFUSAL, NEVER A STALE ANSWER**
//! (develop's 057998e08, 2026-11-14). Node served a reader "from what that
//! worker has" after a hard-coded 5,000 ms, and separately stamped a worker
//! current on a round answered `ok` with `caughtUp: false`; GitHub Actions run
//! 43622250478 answered a just-created realm 404 and a just-declared scope
//! 403 through both. Here a pull counts only when it says it caught up, a
//! reader asks again round after round (one shared pull at a time, spaced
//! [`ROUND_SPACING_MS`] apart after a miss) for `workers.readBarrierTimeoutMs`
//! in all, and is then REFUSED with [`codes::STS_WORKER_0053`]. Each of those
//! three properties has a test that fails when it is broken
//! (`tests/coordination.rs`).
//!
//! **And the cross-cutting rule** — a store is shared by coordination, and a
//! socket, a timer or a listener is held by one process — is [`Topology`]:
//! more than one process serving one store without a change log is refused
//! before anything binds, because it answers wrongly rather than slowly.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use sts_core::errors::{codes, ErrorCode};
use sts_core::log::tag;
use tokio::sync::Notify;
use tokio::time::{Duration, Instant};

use crate::schedule::BoxFuture;

/// The least time between two rounds one reader starts after a round that
/// did not catch up (`BARRIER_ROUND_SPACING_MS`), so a store that answers
/// "not caught up" at once is not asked in a tight loop.
pub const ROUND_SPACING_MS: u64 = 250;
/// `workers.readBarrierTimeoutMs`'s default, for a caller with no settings.
pub const READ_BARRIER_TIMEOUT_DEFAULT_MS: f64 = 30_000.0;

/// One change-log pull and apply: what another process committed since the
/// last, applied here. `Ok(true)` only when it CAUGHT UP — every row visible
/// when it started is applied; `Ok(false)` is a pull that gave up before
/// that (Node's `syncNow()` answering `caughtUp: false`), and never counts.
pub trait ChangePull: Send + Sync {
    fn pull(&self) -> BoxFuture<'_, Result<bool, String>>;
    /// Whether this process coordinates through a change log at all; a
    /// barrier over a store that does not has nothing to wait for.
    fn coordinates(&self) -> bool {
        true
    }
}

/// A reader the barrier refused rather than answer from a stale copy.
#[derive(Clone, Debug, PartialEq)]
pub struct BarrierRefusal {
    /// [`codes::STS_WORKER_0053`].
    pub code: ErrorCode,
    pub waited_ms: f64,
    pub rounds_missed: u64,
}

#[derive(Default)]
struct PullState {
    /// Pulls started so far; a pull's number is this when it starts.
    started: u64,
    /// The highest number of a pull that finished caught up.
    good: u64,
    /// A pull is running now.
    running: bool,
    /// A reader that arrived during the running pull wants another after.
    again: bool,
}

/// What `stats().barrier` counts.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BarrierStats {
    pub pulls: u64,
    pub refused: u64,
    pub rounds_missed: u64,
}

/// Rule 1: a request is served after this process has applied everything
/// committed before it arrived.
pub struct ReadBarrier {
    puller: Arc<dyn ChangePull>,
    timeout_ms: Arc<dyn Fn() -> f64 + Send + Sync>,
    state: Mutex<PullState>,
    settled: Notify,
    refused: AtomicU64,
    missed: AtomicU64,
}

impl ReadBarrier {
    /// A barrier over `puller`, bounded by `timeout_ms` (read per request:
    /// `workers.readBarrierTimeoutMs`, 1,000 to 600,000; never 0, because
    /// "never wait" is the stale answer, so anything below 1 is the
    /// default).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(
        puller: Arc<dyn ChangePull>,
        timeout_ms: Arc<dyn Fn() -> f64 + Send + Sync>,
    ) -> Arc<ReadBarrier> {
        Arc::new(ReadBarrier {
            puller,
            timeout_ms,
            state: Mutex::new(PullState::default()),
            settled: Notify::new(),
            refused: AtomicU64::new(0),
            missed: AtomicU64::new(0),
        })
    }

    fn st(&self) -> std::sync::MutexGuard<'_, PullState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn bound_ms(&self) -> f64 {
        let n = (self.timeout_ms)();
        if n >= 1.0 {
            n
        } else {
            READ_BARRIER_TIMEOUT_DEFAULT_MS
        }
    }

    /// What the barrier has done, for the pool's status.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn stats(&self) -> BarrierStats {
        BarrierStats {
            pulls: self.st().started,
            refused: self.refused.load(Ordering::Relaxed),
            rounds_missed: self.missed.load(Ordering::Relaxed),
        }
    }

    /// Makes sure a pull numbered `need` or higher will run: nothing when the
    /// running one already is, the next one asked for when the running one
    /// started too early, and one started when none runs. Every reader that
    /// arrived before a pull started is answered by it: one pull per batch,
    /// never one per reader.
    fn kick(self: &Arc<Self>, need: u64) {
        {
            let mut st = self.st();
            if st.running {
                if st.started < need {
                    st.again = true;
                }
                return;
            }
            st.running = true;
            st.started += 1;
        }
        let me = self.clone();
        tokio::spawn(async move { me.run_pulls().await });
    }

    async fn run_pulls(self: Arc<Self>) {
        loop {
            let number = self.st().started;
            let answer = self.puller.pull().await;
            {
                let mut st = self.st();
                match &answer {
                    Ok(true) => st.good = st.good.max(number),
                    Ok(false) => tracing::debug!(
                        "barrier: pull {} gave up before it caught up",
                        number
                    ),
                    Err(e) => {
                        tracing::debug!(
                            "barrier: pull {} failed: {}",
                            number,
                            e
                        )
                    }
                }
                if st.again {
                    st.again = false;
                    st.started += 1;
                } else {
                    st.running = false;
                }
            }
            self.settled.notify_waiters();
            if !self.st().running {
                return;
            }
        }
    }

    /// Waits until a pull that STARTED after this call has finished caught
    /// up, round after round, for `workers.readBarrierTimeoutMs` in all; then
    /// refuses ([`codes::STS_WORKER_0053`]). Never answers early and never
    /// stale. A store that does not coordinate has nothing to wait for. A
    /// caller whose client went away drops the future, which ends its wait.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn wait(self: &Arc<Self>) -> Result<(), BarrierRefusal> {
        if !self.puller.coordinates() {
            return Ok(());
        }
        let began = Instant::now();
        let deadline =
            began + Duration::from_millis(self.bound_ms().max(1.0) as u64);
        // THE PULL THAT PROVES THIS READER is one numbered higher than every
        // pull started before it arrived: one already running started too
        // early, because a row committed after it read its page is not in it.
        let need = self.st().started + 1;
        let mut missed = 0u64;
        loop {
            let notified = self.settled.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let round_began = Instant::now();
            {
                if self.st().good >= need {
                    return Ok(());
                }
            }
            self.kick(need);
            // A WAIT FOR AN EVENT, bounded by the request's deadline — not a
            // timer: the round ends when a pull settles.
            let good = tokio::time::timeout_at(deadline, &mut notified)
                .await
                .is_ok()
                && self.st().good >= need;
            if good {
                return Ok(());
            }
            // A ROUND THAT SETTLED WITHOUT PROVING THIS READER: either the
            // pull that settled started before it (and the next is already
            // asked for), or one that started after it did not catch up.
            let st_running = self.st().running;
            if Instant::now() >= deadline {
                break;
            }
            if !st_running {
                missed += 1;
                self.missed.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    "{}barrier: this process had not caught up with other processes' commits after read-barrier \
                     round {}; the request keeps waiting, for up to {}ms in all (workers.readBarrierTimeoutMs), \
                     and is refused rather than served from what this process has.",
                    tag(codes::STS_WORKER_0027),
                    missed,
                    self.bound_ms()
                );
                let spent = round_began.elapsed();
                let spacing = Duration::from_millis(ROUND_SPACING_MS);
                if spent < spacing {
                    // The spacing is a wait for ANOTHER pull to settle — a
                    // reader's that may prove this one too — for at most
                    // the spacing, never past the deadline.
                    let pause =
                        (Instant::now() + (spacing - spent)).min(deadline);
                    let other = self.settled.notified();
                    let _spaced =
                        tokio::time::timeout_at(pause, other).await.is_ok();
                }
            }
        }
        if self.st().good >= need {
            return Ok(());
        }
        self.refused.fetch_add(1, Ordering::Relaxed);
        let waited_ms = began.elapsed().as_secs_f64() * 1000.0;
        tracing::warn!(
            "{}barrier: a request was REFUSED: this process had not caught up with the writes other processes \
             committed before it after {}ms (workers.readBarrierTimeoutMs), and serving it from what this \
             process has could answer wrongly. The change-log pull's own {} line says where its time is \
             going.",
            tag(codes::STS_WORKER_0053),
            waited_ms as u64,
            codes::STS_STORE_0039
        );
        Err(BarrierRefusal {
            code: codes::STS_WORKER_0053,
            waited_ms,
            rounds_missed: missed,
        })
    }
}

/// Where this process's writes are: a position that moves with every write,
/// and the wait for everything up to a position to be committed.
pub trait CommitLog: Send + Sync {
    fn position(&self) -> u64;
    /// Resolves once every write up to `position` is committed; `Err` when
    /// the commit failed.
    fn through(&self, position: u64) -> BoxFuture<'_, Result<(), String>>;
}

/// A response refused because the write it would report did not commit.
#[derive(Clone, Debug, PartialEq)]
pub struct CommitRefusal {
    /// [`codes::STS_STORE_0066`]: answered 503 with `Retry-After`, never
    /// the success the handler wrote.
    pub code: ErrorCode,
    pub why: String,
}

/// Rule 2: a request that wrote is answered only once its writes have
/// committed (`cluster_barrier.js`, and #351 everywhere the store is
/// postgres).
pub struct CommitGate {
    log: Arc<dyn CommitLog>,
}

impl CommitGate {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(log: Arc<dyn CommitLog>) -> CommitGate {
        CommitGate { log }
    }

    /// Where the writes are now, taken as a request begins.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn mark(&self) -> u64 {
        self.log.position()
    }

    /// Holds a response until the writes made since `before` have
    /// committed. A request whose handling moved nothing is answered at
    /// once: holding every read for a commit is the cost #46's follow-up
    /// removed.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn hold(&self, before: u64) -> Result<(), CommitRefusal> {
        let now = self.log.position();
        if now == before {
            return Ok(());
        }
        self.log.through(now).await.map_err(|why| {
            tracing::error!(
                "{}persistence: a response was held for its writes, and they did not commit ({}); it is \
                 answered 503 rather than with the success its handler wrote.",
                tag(codes::STS_STORE_0066),
                why
            );
            CommitRefusal {
                code: codes::STS_STORE_0066,
                why,
            }
        })
    }
}

/// How many processes serve one store, and whether they coordinate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Topology {
    /// More than one process (a cluster mode other than off).
    pub several: bool,
    /// The store carries a change log every process pulls.
    pub coordinates: bool,
}

/// Several processes on one store without coordination
/// (`coordinationRefusal()`, `STS-WORKER-0024`).
#[derive(Clone, Debug, PartialEq)]
pub struct TopologyRefusal {
    pub code: ErrorCode,
    pub why: String,
}

impl Topology {
    /// **A store is shared by coordination; a socket, a timer or a listener
    /// is held by one process.** Several processes serving one store with no
    /// change log would each keep a private copy of the directory, the
    /// sessions and the settings, and answer wrongly and intermittently —
    /// so that is refused before anything binds. One process needs nothing.
    #[tracing::instrument(level = "debug")]
    pub fn check(self) -> Result<(), TopologyRefusal> {
        if !self.several || self.coordinates {
            return Ok(());
        }
        Err(TopologyRefusal {
            code: codes::STS_WORKER_0024,
            why: "Several processes are configured to serve one store and THIS PROCESS IS NOT COORDINATING: \
                  each would hold its own private copy of the directory, the sessions and the settings, \
                  and a request answered by one would not see what another had written — which does not \
                  fail, it answers wrongly and intermittently. Configure a coordinating store \
                  (persistence.mode postgres with persistence.coordinate on), or run one process."
                .to_string(),
        })
    }
}
