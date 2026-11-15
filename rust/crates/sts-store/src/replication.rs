// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Several processes coordinated through one change log
//! (`persistence/persistence_replication.js`): STATE, not sockets.
//!
//! * **The log is the contract.** Every committed write leaves rows naming
//!   what changed (`directory` realm+key, `realms`, `appconfig`); every
//!   other process pulls the rows after the last it saw and re-reads what
//!   they name. The NOTIFY a commit sends only makes the pull prompt;
//!   losing it costs latency, never a change.
//! * **A sequence number can be invisible for a while** — taken by a
//!   transaction that has not committed yet — so a gap in a page is a HOLE,
//!   asked for again on every pull until it appears or ten minutes pass (a
//!   rolled-back transaction leaves one for ever, `STS-STORE-0049`). The
//!   watermark only moves past the oldest hole.
//! * **A process skips its own rows**, and a page names each (kind, realm,
//!   key) once: re-reading the store twice for one key in one page is the
//!   same answer twice.
//! * **One failed row does not stop the page** (`STS-STORE-0042`); a failed
//!   pull leaves this process serving its own copy, BEHIND until the next
//!   one succeeds (`STS-STORE-0038`).
//! * **A read barrier is a pull that STARTED after it was asked**
//!   (`syncNow()`): every row committed before the call is visible to that
//!   pull's snapshots, so when it finishes the reader is caught up; a pull
//!   already in flight is waited out and a new one run. Within
//!   SYNC_DEADLINE_MS, or the caller is told it did NOT catch up
//!   (STS-STORE-0039) — never answered as if it had (develop's 057998e08) —
//!   with where the latest pull's time went: reading pages, each kind's
//!   rows, each kind's prepare, the turns this runtime was yielded for, the
//!   remainder nothing timed, and the hole re-check.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::{Duration, Instant};

use serde_json::{json, Value as Json};
use sts_core::errors::codes;
use sts_core::log::tag;

use crate::driver::{ChangeRow, Driver};

/// Rows per page.
const PAGE: i64 = 500;
/// A hole older than this is a rolled-back transaction.
const HOLE_EXPIRE: Duration = Duration::from_secs(600);
const MAX_HOLES: usize = 10_000;
/// How long a read barrier waits for a pull that started after it
/// (`SYNC_DEADLINE_MS`).
const SYNC_DEADLINE: Duration = Duration::from_millis(4600);
/// Rows applied between two yields of the runtime (`APPLY_YIELD_EVERY`).
const APPLY_YIELD_EVERY: usize = 25;

/// Where one pull's time went (`pullCost`): the parts add up to its
/// applying time, and what nothing timed is named as such.
#[derive(Clone, Debug)]
struct PullCost {
    started_at: Instant,
    query_ms: u64,
    apply_ms: u64,
    rows: u64,
    kinds: BTreeMap<String, u64>,
    kind_ms: BTreeMap<String, u64>,
    applying_since: Option<Instant>,
    current: Option<(String, String, Instant)>,
    prepare_ms: BTreeMap<String, u64>,
    preparing: Option<(String, Instant)>,
    turns: u64,
    turn_ms: u64,
    turn_max_ms: u64,
    turning: Option<Instant>,
    holes_ms: u64,
    holing: Option<Instant>,
}

fn ms_since(at: Instant) -> u64 {
    at.elapsed().as_millis() as u64
}

impl PullCost {
    fn new() -> PullCost {
        PullCost {
            started_at: Instant::now(),
            query_ms: 0,
            apply_ms: 0,
            rows: 0,
            kinds: BTreeMap::new(),
            kind_ms: BTreeMap::new(),
            applying_since: None,
            current: None,
            prepare_ms: BTreeMap::new(),
            preparing: None,
            turns: 0,
            turn_ms: 0,
            turn_max_ms: 0,
            turning: None,
            holes_ms: 0,
            holing: None,
        }
    }

    /// `pullCostText()`, after the 2026-11-14 split.
    fn text(&self, in_flight: bool) -> String {
        let mut rows_ms = 0;
        let kinds: Vec<String> = self
            .kinds
            .iter()
            .map(|(kind, n)| {
                let ms = self.kind_ms.get(kind).copied().unwrap_or(0)
                    + self
                        .current
                        .as_ref()
                        .filter(|c| &c.0 == kind)
                        .map_or(0, |c| ms_since(c.2));
                rows_ms += ms;
                format!("{}={}/{}ms", kind, n, ms)
            })
            .collect();
        let mut prepared_ms = 0;
        let mut names: Vec<String> = self.prepare_ms.keys().cloned().collect();
        if let Some((k, _)) = &self.preparing {
            if !self.prepare_ms.contains_key(k) {
                names.push(k.clone());
            }
        }
        let prepared: Vec<String> = names
            .iter()
            .map(|kind| {
                let ms = self.prepare_ms.get(kind).copied().unwrap_or(0)
                    + self
                        .preparing
                        .as_ref()
                        .filter(|p| &p.0 == kind)
                        .map_or(0, |p| ms_since(p.1));
                prepared_ms += ms;
                format!("{}={}ms", kind, ms)
            })
            .collect();
        let turning = self.turning.map_or(0, ms_since);
        let turn_ms = self.turn_ms + turning;
        let turn_max = self.turn_max_ms.max(turning);
        let apply_ms = self.apply_ms + self.applying_since.map_or(0, ms_since);
        let other = apply_ms.saturating_sub(rows_ms + prepared_ms + turn_ms);
        let holes = self.holes_ms + self.holing.map_or(0, ms_since);
        let mut out = format!(
            " The {} began {} ms ago: {} ms reading pages, {} ms applying {} row(s)",
            if in_flight { "pull in flight" } else { "latest pull" },
            ms_since(self.started_at),
            self.query_ms,
            apply_ms,
            self.rows
        );
        if !kinds.is_empty() {
            out.push_str(&format!(" (rows/time by kind: {})", kinds.join(",")));
        }
        out.push_str(&format!(
            "; of the applying, {} ms in the rows, {} ms preparing",
            rows_ms, prepared_ms
        ));
        if !prepared.is_empty() {
            out.push_str(&format!(" ({})", prepared.join(",")));
        }
        out.push_str(&format!(
            ", {} ms waiting for {} turn(s) of this thread's event loop (the longest {} ms: time other work on \
             this thread held it), {} ms otherwise",
            turn_ms, self.turns, turn_max, other
        ));
        if holes > 0 {
            out.push_str(&format!("; {} ms re-reading holes", holes));
        }
        if let Some((kind, key, since)) = &self.current {
            out.push_str(&format!(
                "; applying a \"{}\" row ({}) for {} ms",
                kind,
                key.chars().take(40).collect::<String>(),
                ms_since(*since)
            ));
        }
        if let Some((kind, since)) = &self.preparing {
            out.push_str(&format!(
                "; preparing \"{}\" rows for {} ms",
                kind,
                ms_since(*since)
            ));
        }
        if self.turning.is_some() {
            out.push_str(&format!(
                "; waiting for a turn of the event loop for {} ms",
                turning
            ));
        }
        out.push('.');
        out
    }
}

/// What a read barrier answers (`syncNow()`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Synced {
    pub caught_up: bool,
    pub applied: i64,
    pub target: i64,
    /// False where the store has no change log (nothing to coordinate).
    pub coordinating: bool,
}

/// What applies another process's change here.
pub trait Applier: Send + Sync {
    fn apply<'a>(
        &'a self,
        row: &'a ChangeRow,
    ) -> crate::driver::StoreFuture<'a, ()>;

    /// Reads ahead what a page of changes names, before any is applied.
    fn prefetch<'a>(
        &'a self,
        _rows: &'a [&'a ChangeRow],
    ) -> crate::driver::StoreFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    /// Forgets what [`Applier::prefetch`] read.
    fn end_prefetch(&self) {}
}

#[derive(Default)]
struct State {
    highest: i64,
    applied: i64,
    holes: BTreeMap<i64, Instant>,
    holes_abandoned: u64,
    pulls: u64,
    failures: u64,
    rows_applied: u64,
    last_error: String,
    /// Pulls begun, and the start number of the newest that finished.
    pulls_started: u64,
    last_completed_start_no: u64,
    in_flight: bool,
    cost: Option<PullCost>,
}

/// The change-log puller of one process.
pub struct Replication {
    driver: Arc<dyn Driver>,
    applier: Weak<dyn Applier>,
    state: Mutex<State>,
    running: tokio::sync::Mutex<()>,
}

impl Replication {
    /// A puller from `from`, the last sequence number this process has
    /// already seen (taken before its store was read).
    pub fn new(
        driver: Arc<dyn Driver>,
        applier: Weak<dyn Applier>,
        from: i64,
    ) -> Arc<Replication> {
        Arc::new(Replication {
            driver,
            applier,
            state: Mutex::new(State {
                highest: from,
                applied: from,
                ..State::default()
            }),
            running: tokio::sync::Mutex::new(()),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The last sequence number every row up to which is applied.
    pub fn applied(&self) -> i64 {
        self.state().applied
    }

    /// Pulls and applies everything after the last row seen. One pull at a
    /// time: a pull asked for while one runs waits for it, then runs.
    pub async fn pull(&self) -> Result<i64, String> {
        let _one = self.running.lock().await;
        let Some(log) = self.driver.change_log() else {
            return Ok(0);
        };
        let start_no = {
            let mut st = self.state();
            st.pulls_started += 1;
            st.in_flight = true;
            st.cost = Some(PullCost::new());
            st.pulls_started
        };
        let result = async {
            loop {
                let highest = self.state().highest;
                let asked = Instant::now();
                let rows = log
                    .changes_since(highest, PAGE)
                    .await
                    .map_err(|e| e.to_string())?;
                self.cost(|c| c.query_ms += ms_since(asked));
                if rows.is_empty() {
                    break;
                }
                {
                    let now = Instant::now();
                    let mut st = self.state();
                    let mut expect = highest + 1;
                    for row in &rows {
                        while expect < row.seq {
                            st.holes.entry(expect).or_insert(now);
                            expect += 1;
                        }
                        expect = row.seq + 1;
                    }
                }
                self.cost(|c| {
                    for row in &rows {
                        *c.kinds.entry(row.kind.clone()).or_default() += 1;
                    }
                    c.rows += rows.len() as u64;
                    c.applying_since = Some(Instant::now());
                });
                self.apply_rows(&rows, &log.origin()).await;
                self.cost(|c| {
                    if let Some(at) = c.applying_since.take() {
                        c.apply_ms += ms_since(at);
                    }
                });
                let full = rows.len() as i64 == PAGE;
                {
                    let mut st = self.state();
                    st.highest = rows.last().map_or(highest, |r| r.seq);
                    st.rows_applied += rows.len() as u64;
                }
                if !full {
                    break;
                }
            }
            self.cost(|c| c.holing = Some(Instant::now()));
            let holes = self.recheck_holes(log).await;
            self.cost(|c| {
                if let Some(at) = c.holing.take() {
                    c.holes_ms += ms_since(at);
                }
            });
            holes
        }
        .await;
        let mut st = self.state();
        st.in_flight = false;
        match result {
            Ok(()) => {
                st.pulls += 1;
                st.last_completed_start_no =
                    st.last_completed_start_no.max(start_no);
                st.last_error.clear();
                Ok(st.applied)
            }
            Err(e) => {
                st.failures += 1;
                st.last_error = e.clone();
                tracing::error!(
                    "{}persistence: could not apply another process's changes: {}. This process is serving its own \
                     copy and will retry; it is BEHIND until it succeeds.",
                    tag(codes::STS_STORE_0038),
                    e
                );
                Err(e)
            }
        }
    }

    async fn recheck_holes(
        &self,
        log: &dyn crate::driver::ChangeLog,
    ) -> Result<(), String> {
        let asked: Vec<i64> = self.state().holes.keys().copied().collect();
        if !asked.is_empty() {
            let found =
                log.changes_at(asked).await.map_err(|e| e.to_string())?;
            self.apply_rows(&found, &log.origin()).await;
            let mut st = self.state();
            for row in &found {
                st.holes.remove(&row.seq);
            }
            st.rows_applied += found.len() as u64;
        }
        let mut st = self.state();
        let now = Instant::now();
        let mut gone: Vec<i64> = st
            .holes
            .iter()
            .filter(|(_, at)| now - **at >= HOLE_EXPIRE)
            .map(|(s, _)| *s)
            .collect();
        let excess = st
            .holes
            .len()
            .saturating_sub(gone.len())
            .saturating_sub(MAX_HOLES);
        gone.extend(
            st.holes
                .keys()
                .filter(|s| !gone.contains(s))
                .take(excess)
                .copied()
                .collect::<Vec<_>>(),
        );
        if !gone.is_empty() {
            for s in &gone {
                st.holes.remove(s);
            }
            st.holes_abandoned += gone.len() as u64;
            tracing::warn!(
                "{}persistence: {} change-log sequence number(s) never became visible (the oldest was {}) and are no \
                 longer asked for; they were transactions that rolled back. {} hole(s) are still being asked for.",
                tag(codes::STS_STORE_0049),
                gone.len(),
                gone.iter().min().copied().unwrap_or(0),
                st.holes.len()
            );
        }
        st.applied = match st.holes.keys().next() {
            Some(oldest) => st.applied.max(oldest - 1),
            None => st.highest,
        };
        Ok(())
    }

    /// Applies a page: this process's own rows skipped, each (kind, realm,
    /// key) once, one failure not stopping the rest.
    async fn apply_rows(&self, rows: &[ChangeRow], origin: &str) {
        let Some(applier) = self.applier.upgrade() else {
            return;
        };
        let mut seen = HashSet::new();
        let mut wanted: Vec<&ChangeRow> = Vec::new();
        for row in rows.iter().rev() {
            if row.origin == origin {
                continue;
            }
            if seen.insert((
                row.kind.as_str(),
                row.realm.as_str(),
                row.key.as_str(),
            )) {
                wanted.push(row);
            }
        }
        wanted.reverse();
        // EACH KIND'S PREPARE, timed (`prepareMs`): Node prepares a page by
        // kind, so the time is said by kind here too.
        let mut kinds: Vec<&str> = Vec::new();
        for row in &wanted {
            if !kinds.contains(&row.kind.as_str()) {
                kinds.push(row.kind.as_str());
            }
        }
        for kind in kinds {
            let of_kind: Vec<&ChangeRow> =
                wanted.iter().copied().filter(|r| r.kind == kind).collect();
            let began = Instant::now();
            self.cost(|c| c.preparing = Some((kind.to_string(), began)));
            if let Err(e) = applier.prefetch(&of_kind).await {
                tracing::warn!(
                    "{}replication: preparing {} \"{}\" row(s) failed ({}); they are applied one at a time.",
                    tag(codes::STS_STORE_0041),
                    of_kind.len(),
                    kind,
                    e
                );
            }
            self.cost(|c| {
                *c.prepare_ms.entry(kind.to_string()).or_default() +=
                    ms_since(began);
                c.preparing = None;
            });
        }
        for (i, row) in wanted.iter().copied().enumerate() {
            // A TURN OF THE RUNTIME every APPLY_YIELD_EVERY rows, as Node
            // yields its event loop, and timed: what other work held this
            // thread meanwhile is the turn's time.
            if i > 0 && i % APPLY_YIELD_EVERY == 0 {
                let at = Instant::now();
                self.cost(|c| c.turning = Some(at));
                tokio::task::yield_now().await;
                self.cost(|c| {
                    let ms = ms_since(at);
                    c.turns += 1;
                    c.turn_ms += ms;
                    c.turn_max_ms = c.turn_max_ms.max(ms);
                    c.turning = None;
                });
            }
            let since = Instant::now();
            self.cost(|c| {
                c.current = Some((row.kind.clone(), row.key.clone(), since))
            });
            let applied = applier.apply(row).await;
            self.cost(|c| {
                *c.kind_ms.entry(row.kind.clone()).or_default() +=
                    ms_since(since);
                c.current = None;
            });
            if let Err(e) = applied {
                tracing::error!(
                    "{}persistence: a \"{}\" change for \"{}\" in realm \"{}\" could not be applied: {}. The rest of \
                     the page is unaffected.",
                    tag(codes::STS_STORE_0042),
                    row.kind,
                    row.key,
                    if row.realm.is_empty() { "default" } else { &row.realm },
                    e
                );
            }
        }
        applier.end_prefetch();
    }

    fn cost(&self, f: impl FnOnce(&mut PullCost)) {
        if let Some(c) = self.state().cost.as_mut() {
            f(c);
        }
    }

    /// `pullCostText()`: where the latest pull's time went, '' before any.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn cost_text(&self) -> String {
        let st = self.state();
        st.cost
            .as_ref()
            .map_or_else(String::new, |c| c.text(st.in_flight))
    }

    /// `syncNow()`: caught up when a pull that STARTED after this call has
    /// finished; otherwise, at SYNC_DEADLINE, told it did not catch up
    /// (STS-STORE-0039), with where the pull's time went. A pull in flight
    /// is waited out and a new one run; a run of failing pulls is bounded
    /// by the deadline, not a count.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn sync_now(&self) -> Synced {
        if self.driver.change_log().is_none() {
            return Synced {
                caught_up: false,
                applied: self.applied(),
                target: self.state().highest,
                coordinating: false,
            };
        }
        let need = self.state().pulls_started;
        let deadline = Instant::now() + SYNC_DEADLINE;
        loop {
            let (done, applied, highest) = {
                let st = self.state();
                (st.last_completed_start_no > need, st.applied, st.highest)
            };
            if done {
                return Synced {
                    caught_up: true,
                    applied,
                    target: highest,
                    coordinating: true,
                };
            }
            let now = Instant::now();
            if now >= deadline {
                tracing::warn!(
                    "{}persistence: a read barrier gave up at {}: no change pull started after it completed, and \
                     its caller is told it did not catch up (a request pool barrier asks again, and refuses once \
                     workers.readBarrierTimeoutMs has passed).{}",
                    tag(codes::STS_STORE_0039),
                    highest,
                    self.cost_text()
                );
                return Synced {
                    caught_up: false,
                    applied,
                    target: highest,
                    coordinating: true,
                };
            }
            // The pull goes on; only the reader stops waiting at the
            // deadline. A failed pull is the pull's to report.
            if let Ok(Err(e)) =
                tokio::time::timeout(deadline - now, self.pull()).await
            {
                tracing::debug!("a pull under a read barrier failed: {}", e);
            }
        }
    }

    /// What `/admin/database` reports of the coordination.
    pub fn status(&self) -> Json {
        let st = self.state();
        json!({ "applied": st.applied, "highest": st.highest, "holes": st.holes.len(),
                "holesAbandoned": st.holes_abandoned, "pulls": st.pulls, "failures": st.failures,
                "rowsApplied": st.rows_applied, "lastError": st.last_error })
    }
}
