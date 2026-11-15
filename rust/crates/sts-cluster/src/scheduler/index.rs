// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What the leader remembers so that a tick never reads the run history
//! (`cluster/scheduler.ts`'s `pendingRows`, `runningRows`, `finishedSlots`,
//! `slotAsked`, `unknownSlots`, `heldFinished` and `latestRun`; #623 and
//! #883).
//!
//! * **THE ROWS A TICK HAS TO SEE, INDEXED (#623)**: every queued or running
//!   MANUAL run and every queued COMMAND. A tick read every row of
//!   `scheduler.runs` in every realm to find the few a person had queued —
//!   13–19 s of the front process's thread at some ticks on 8081, whose
//!   history was some 42,000 rows. Now a tick reads the index and one row per
//!   entry: O(queued), not O(history). **Kept on write, checked on read**: an
//!   entry is ADDED wherever a row enters the store (the scheduler's own
//!   writes, and [`super::Scheduler::note_admitted`] for a row read back at a
//!   start or brought by the change log from another node) and is dropped
//!   only by the read that finds its row gone or no longer pending, so no path
//!   that ENDS a row needs to know the index exists.
//! * **THE RUNS SOMEBODY LEFT RUNNING** (2026-11-03): the same, for every run
//!   row seen `running`, so `abandon_orphans()` reads O(running).
//! * **FINISHED INTERVAL SLOTS THE TICK ALREADY KNOWS (#883)**: a start does
//!   not restore a finished interval run's body, so the row that says the
//!   current slot already ran is not in the map. The set holds the current
//!   slot and the one before it, pruned every tick — one id per job and realm,
//!   never the history. `slot_asked` is an id looked up and found absent;
//!   `unknown_slots` the current slots this tick's read could not answer,
//!   held back for this tick only; `held_finished` a finished body this
//!   process wrote and has not yet dropped; `latest_run` one row per job and
//!   realm for the page's last-run figure.
//!
//! Every method here is on a hot path (every row written or admitted), so
//! none carries `#[tracing::instrument]`, as Node's carry no Entering/Leaving
//! pair.

use std::collections::{HashMap, HashSet};

use indexmap::{IndexMap, IndexSet};
use serde_json::Value as Json;

use crate::schedule::FINAL;

fn text<'a>(row: &'a Json, key: &str) -> &'a str {
    row.get(key).and_then(Json::as_str).unwrap_or("")
}

fn num(row: &Json, key: &str) -> f64 {
    match row.get(key) {
        Some(Json::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(Json::String(s)) => s.trim().parse().unwrap_or(0.0),
        _ => 0.0,
    }
}

/// `Number(row.endedAt) || Number(row.startedAt) || Number(row.queuedAt)
/// || 0`, the instant `noteLatest()` orders by.
fn ended_or_started(row: &Json) -> f64 {
    ["endedAt", "startedAt", "queuedAt"]
        .iter()
        .map(|k| num(row, k))
        .find(|v| *v != 0.0 && !v.is_nan())
        .unwrap_or(0.0)
}

/// Whether a row is one a tick has to see: a manual run not yet ended, or a
/// command not yet obeyed (`Scheduler.isPending()`).
pub(crate) fn is_pending(row: &Json) -> bool {
    match text(row, "kind") {
        "run" => {
            text(row, "trigger") == "manual"
                && matches!(text(row, "state"), "queued" | "running")
        }
        "command" => text(row, "state") == "queued",
        _ => false,
    }
}

/// `realm\nrunId`, the key every set here uses for a (realm, run).
pub(crate) fn key_of(realm: &str, run_id: &str) -> String {
    format!("{}\n{}", realm, run_id)
}

/// The leader's memory of the rows a tick has to see.
#[derive(Default)]
pub(crate) struct RunIndex {
    /// `realm\nrunId` → (realm, runId), in the order rows were first noted.
    pub pending: IndexMap<String, (String, String)>,
    pub running: IndexMap<String, (String, String)>,
    pub finished_slots: HashSet<String>,
    pub slot_asked: HashSet<String>,
    pub unknown_slots: HashSet<String>,
    pub held_finished: IndexSet<String>,
    /// `jobId|realm` → the latest finished row.
    pub latest_run: HashMap<String, Json>,
}

impl RunIndex {
    /// ADDS a row to the indexes it belongs in (`notePending()`). Never
    /// removes: the reads do that.
    pub fn note(&mut self, realm: &str, row: &Json) {
        let run_id = text(row, "runId");
        if run_id.is_empty() {
            return;
        }
        let key = key_of(realm, run_id);
        let kind = text(row, "kind");
        let state = text(row, "state");
        if kind == "run" && state == "running" {
            self.running
                .insert(key.clone(), (realm.to_string(), run_id.to_string()));
        }
        if kind == "run" && FINAL.contains(&state) {
            self.finished_slots.insert(run_id.to_string());
            self.note_latest(realm, row);
        }
        if is_pending(row) {
            self.pending
                .insert(key, (realm.to_string(), run_id.to_string()));
        }
    }

    /// THE LATEST FINISHED RUN OF ONE JOB IN ONE REALM (`noteLatest()`):
    /// kept when the body is not; a later or equal end replaces it.
    pub fn note_latest(&mut self, realm: &str, row: &Json) {
        let job = text(row, "jobId");
        if text(row, "kind") != "run" || job.is_empty() {
            return;
        }
        let row_realm = match text(row, "realm") {
            "" => realm,
            r => r,
        };
        let key = format!("{}|{}", job, row_realm);
        let ended = ended_or_started(row);
        let replace = self
            .latest_run
            .get(&key)
            .is_none_or(|held| ended >= ended_or_started(held));
        if replace {
            self.latest_run.insert(key, row.clone());
        }
    }

    /// Drops slot ids the clock has moved past (`pruneSlotMemory()`).
    pub fn prune_slots(&mut self, keep: &HashSet<String>) {
        self.finished_slots.retain(|id| keep.contains(id));
        self.slot_asked.retain(|id| keep.contains(id));
    }

    /// A removed realm's entries (`forgetRealm()`'s share).
    pub fn forget_realm(&mut self, realm: &str) {
        let prefix = format!("{}\n", realm);
        let suffix = format!("|{}", realm);
        self.pending.retain(|k, _| !k.starts_with(&prefix));
        self.running.retain(|k, _| !k.starts_with(&prefix));
        self.latest_run.retain(|k, _| !k.ends_with(&suffix));
        self.held_finished.retain(|k| !k.starts_with(&prefix));
    }
}
