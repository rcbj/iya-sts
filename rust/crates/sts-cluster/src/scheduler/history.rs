// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The run history, bounded per job (#338).
//!
//! A run row is KEPT while it is one of its job's last
//! `scheduler.runHistoryCount` finished runs in its realm (or the latest,
//! whatever the setting says), while it ended within
//! `scheduler.runHistoryHours`, or while it is not finished — whichever of
//! the first two keeps more. A run of a job no process here registers keeps
//! only the time rule. A command goes once finished and past the window; a
//! per-process row once unwritten for the window or three of its intervals;
//! the leader's never; and a row naming a realm no longer defined goes
//! whatever its age.
//!
//! The purge is the cluster job `scheduler.history`: deletes in batches,
//! each written down before the next, at most so many a run — the rest is
//! the next run's. A KEPT row whose expiry is near is PINNED (rewritten with
//! `keepUntil` a day ahead), so a start that skips expired rows never skips
//! one the purge would keep.

use std::collections::HashSet;
use std::sync::Arc;

use indexmap::IndexMap;
use serde_json::{json, Value as Json};

use super::{assign, num, text, Scheduler, LEADER_KEY};
use crate::schedule::{ended_of, JobSpec, Schedule, FINAL};

/// The history job's interval.
pub const HISTORY_PURGE_MS: f64 = 10.0 * 60.0 * 1000.0;
/// Deletes per batch, and batches per run.
pub const HISTORY_BATCH: usize = 2000;
pub const HISTORY_MAX_BATCHES: usize = 25;
/// A kept row whose expiry is closer than this is pinned, for this long.
pub const PIN_AHEAD_MS: f64 = 60.0 * 60.0 * 1000.0;
pub const PIN_FOR_MS: f64 = 24.0 * 60.0 * 60.0 * 1000.0;

/// One row the plan names.
#[derive(Clone, Debug)]
pub(super) struct Planned {
    pub realm: String,
    pub key: String,
    pub row: Json,
}

/// What a purge did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Purged {
    pub removed: usize,
    /// Of those, rows naming a removed realm.
    pub orphaned: usize,
    pub pinned: usize,
    /// More is left for the next run.
    pub more: bool,
    pub batches: usize,
}

impl Purged {
    pub fn to_json(&self) -> Json {
        json!({ "removed": self.removed, "orphaned": self.orphaned, "pinned": self.pinned,
                "more": self.more, "batches": self.batches })
    }
}

impl Scheduler {
    /// What the purge would do now, without doing it: the rows to delete and
    /// the kept rows to pin, in the order the purge takes them.
    pub(super) fn history_plan(
        &self,
        now: f64,
    ) -> (Vec<Planned>, Vec<Planned>) {
        let schedules = self.schedules();
        let bounds = schedules.history_bounds();
        let defined: Vec<String> = self.deps.realms.ids();
        let defined_set: HashSet<&str> =
            defined.iter().map(String::as_str).collect();
        let mut deletes = Vec::new();
        let mut pins = Vec::new();
        let mut keep = |realm: &str, key: &str, row: &Json| {
            if let Some(expiry) = schedules.expiry_of(row) {
                if expiry < now + PIN_AHEAD_MS {
                    pins.push(Planned {
                        realm: realm.to_string(),
                        key: key.to_string(),
                        row: row.clone(),
                    });
                }
            }
        };
        for realm_id in &defined {
            let mut by_job: IndexMap<String, Vec<(String, Json, f64)>> =
                IndexMap::new();
            for row in self.deps.rows.rows(realm_id) {
                let key = text(&row, "runId").to_string();
                let kind = text(&row, "kind");
                if kind == "leader" || key == LEADER_KEY {
                    continue;
                }
                let ended = ended_of(&row);
                let named = text(&row, "realm");
                let delete = |deletes: &mut Vec<Planned>, row: Json| {
                    deletes.push(Planned {
                        realm: realm_id.clone(),
                        key: key.clone(),
                        row,
                    });
                };
                // The orphans: a row naming a realm that is gone.
                if !named.is_empty()
                    && !defined_set.contains(named)
                    && (kind == "process"
                        || FINAL.contains(&text(&row, "state")))
                {
                    delete(&mut deletes, row);
                    continue;
                }
                match kind {
                    "command" => {
                        if text(&row, "state") != "queued"
                            && now - ended > bounds.keep_ms
                        {
                            delete(&mut deletes, row);
                        } else {
                            keep(realm_id, &key, &row);
                        }
                    }
                    "process" => {
                        let window = schedules.job(text(&row, "jobId")).map_or(
                            bounds.keep_ms,
                            |job| {
                                bounds
                                    .keep_ms
                                    .max(3.0 * schedules.process_every_ms(job))
                            },
                        );
                        if now - ended > window {
                            delete(&mut deletes, row);
                        } else {
                            keep(realm_id, &key, &row);
                        }
                    }
                    "run" if FINAL.contains(&text(&row, "state")) => {
                        let group = format!(
                            "{}|{}",
                            text(&row, "jobId"),
                            if named.is_empty() { realm_id } else { named }
                        );
                        by_job
                            .entry(group)
                            .or_default()
                            .push((key, row, ended));
                    }
                    _ => {}
                }
            }
            for (_, mut rows) in by_job {
                rows.sort_by(|a, b| {
                    let by_end = b.2 - a.2;
                    let d = if by_end != 0.0 {
                        by_end
                    } else {
                        num(&b.1, "updatedAt") - num(&a.1, "updatedAt")
                    };
                    // JavaScript's comparator: positive puts `a` after `b`.
                    d.partial_cmp(&0.0).unwrap_or(std::cmp::Ordering::Equal)
                });
                let registered = rows.first().is_some_and(|r| {
                    schedules.job(text(&r.1, "jobId")).is_some()
                });
                for (i, (key, row, ended)) in rows.into_iter().enumerate() {
                    let by_count = registered && (i as f64) < bounds.count;
                    let by_time = now - ended <= bounds.keep_ms;
                    if by_count || by_time {
                        keep(realm_id, &key, &row);
                    } else {
                        deletes.push(Planned {
                            realm: realm_id.clone(),
                            key,
                            row,
                        });
                    }
                }
            }
        }
        (deletes, pins)
    }

    /// Deletes what the bound no longer keeps, `batch` rows at a time and at
    /// most `max_batches` batches, each written down before the next; then
    /// pins up to a batch of kept rows near their expiry.
    pub async fn purge_history(
        &self,
        at: Option<f64>,
        batch: Option<usize>,
        max_batches: Option<usize>,
        still_owner: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    ) -> Purged {
        let now = at.unwrap_or_else(|| self.now_ms());
        let batch = batch.filter(|b| *b > 0).unwrap_or(HISTORY_BATCH);
        let max_batches = max_batches
            .filter(|b| *b > 0)
            .unwrap_or(HISTORY_MAX_BATCHES);
        let owner = || still_owner.as_ref().is_none_or(|f| f());
        let (deletes, pins) = self.history_plan(now);
        let defined: HashSet<String> =
            self.deps.realms.ids().into_iter().collect();
        let mut out = Purged::default();
        for slice in deletes.chunks(batch) {
            if out.batches >= max_batches || !owner() {
                out.more = true;
                break;
            }
            out.batches += 1;
            for one in slice {
                self.deps.rows.delete(&one.realm, &one.key);
                out.removed += 1;
                let named = text(&one.row, "realm");
                if !named.is_empty() && !defined.contains(named) {
                    out.orphaned += 1;
                }
            }
            // One batch per flush: no transaction carries the whole backlog.
            self.deps.rows.settle().await;
        }
        for one in pins.into_iter().take(batch) {
            if !owner() {
                continue;
            }
            self.write_row(
                &one.realm,
                assign(&one.row, json!({ "keepUntil": now + PIN_FOR_MS })),
            );
            out.pinned += 1;
        }
        if out.pinned > 0 {
            self.deps.rows.settle().await;
        }
        out
    }

    /// The scheduler's own housekeeping, a job like any other.
    pub fn register_history_job(&self) -> Result<(), String> {
        let me = self.me.clone();
        let mut spec = JobSpec::new(
            "scheduler.history",
            "Scheduler run history",
            &format!(
                "Keeps, per job, its last scheduler.runHistoryCount runs or its last scheduler.runHistoryHours, \
                 whichever is more, and always its latest run; deletes the rest — and every row naming a realm \
                 that was removed — in batches of {}, at most {} a run.",
                HISTORY_BATCH, HISTORY_MAX_BATCHES
            ),
            "cluster/scheduler.ts",
            Schedule::Every(Arc::new(|| HISTORY_PURGE_MS)),
        );
        spec.run = Some(Arc::new(move |ctx| {
            let me = me.clone();
            Box::pin(async move {
                let Some(me) = me.upgrade() else {
                    return Err("the scheduler is gone".to_string());
                };
                let result = me
                    .purge_history(
                        None,
                        None,
                        None,
                        Some(ctx.still_owner.clone()),
                    )
                    .await;
                if result.removed > 0 || result.pinned > 0 {
                    tracing::info!(
                        "scheduler: {} run row(s) past the history bound deleted ({} of removed realms), {} kept \
                         row(s) pinned{}.",
                        result.removed,
                        result.orphaned,
                        result.pinned,
                        if result.more { "; more remain for the next run" } else { "" }
                    );
                }
                Ok(result.to_json())
            })
        }));
        self.register(spec)
    }
}
