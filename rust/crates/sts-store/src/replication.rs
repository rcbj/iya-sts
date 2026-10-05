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

/// What applies another process's change here.
pub trait Applier: Send + Sync {
    fn apply<'a>(
        &'a self,
        row: &'a ChangeRow,
    ) -> crate::driver::StoreFuture<'a, ()>;
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
        let result = async {
            loop {
                let highest = self.state().highest;
                let rows = log
                    .changes_since(highest, PAGE)
                    .await
                    .map_err(|e| e.to_string())?;
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
                self.apply_rows(&rows, &log.origin()).await;
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
            self.recheck_holes(log).await
        }
        .await;
        let mut st = self.state();
        match result {
            Ok(()) => {
                st.pulls += 1;
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
        for row in wanted {
            if let Err(e) = applier.apply(row).await {
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
    }

    /// What `/admin/database` reports of the coordination.
    pub fn status(&self) -> Json {
        let st = self.state();
        json!({ "applied": st.applied, "highest": st.highest, "holes": st.holes.len(),
                "holesAbandoned": st.holes_abandoned, "pulls": st.pulls, "failures": st.failures,
                "rowsApplied": st.rows_applied, "lastError": st.last_error })
    }
}
