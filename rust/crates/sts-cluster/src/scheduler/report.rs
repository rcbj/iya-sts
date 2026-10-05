// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The report `/admin/scheduler` draws and `GET /admin-api/scheduler`
//! answers field for field. Read from the STORE, with the next run worked
//! out from the DATABASE's clock, so every process on every node draws the
//! same figures. Confined to a realm, it shows that realm's realm-scoped
//! rows and the service jobs read-only (a realm administrator's view).
//!
//! The shapes are Node's, `undefined` included: a field Node would leave
//! out of its JSON is left out here.

use chrono::{TimeZone, Utc};
use serde_json::{json, Map, Value as Json};
use sts_core::realm::DEFAULT_ID;

use super::{num, text, Scheduler, LEADER_KEY};
use crate::schedule::{
    run_id_for, JobSpec, Kind, Schedule, Scope, FINAL, LEADER_LEASE,
    OVERDUE_FLOOR_MS, QUIET_RECORD_MS,
};

/// `new Date(ms).toISOString()`.
pub fn iso(ms: f64) -> Json {
    match Utc.timestamp_millis_opt(ms.trunc() as i64).single() {
        Some(t) => json!(t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()),
        None => Json::Null,
    }
}

/// JavaScript truthiness of a field.
fn truthy(v: Option<&Json>) -> bool {
    match v {
        None | Some(Json::Null) => false,
        Some(Json::Bool(b)) => *b,
        Some(Json::Number(n)) => {
            n.as_f64().is_some_and(|x| x != 0.0 && !x.is_nan())
        }
        Some(Json::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// `row.x || fallback`.
fn or(row: &Json, key: &str, fallback: Json) -> Json {
    let v = row.get(key);
    if truthy(v) {
        v.cloned().unwrap_or(fallback)
    } else {
        fallback
    }
}

/// `Number(ms) ? iso(ms) : null`.
fn iso_of(row: &Json, key: &str) -> Json {
    let n = num(row, key);
    if n != 0.0 {
        iso(n)
    } else {
        Json::Null
    }
}

/// Sets a key only when the value is not JavaScript's `undefined`.
fn put(out: &mut Map<String, Json>, key: &str, value: Option<&Json>) {
    if let Some(v) = value {
        out.insert(key.to_string(), v.clone());
    }
}

/// `String(x)` of a view's field.
fn js_string(v: Option<&Json>) -> String {
    match v {
        None => "undefined".to_string(),
        Some(Json::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// A run row as the page and the API see it.
pub fn run_view(row: &Json) -> Json {
    let mut out = Map::new();
    put(&mut out, "runId", row.get("runId"));
    out.insert("jobId".into(), or(row, "jobId", Json::Null));
    out.insert("realm".into(), or(row, "realm", Json::Null));
    out.insert("trigger".into(), or(row, "trigger", json!("schedule")));
    put(&mut out, "state", row.get("state"));
    out.insert("attempt".into(), json!(num(row, "attempt")));
    out.insert("fenceAt".into(), json!(num(row, "fenceAt")));
    out.insert("node".into(), or(row, "node", json!("")));
    out.insert("nodeName".into(), or(row, "nodeName", json!("")));
    out.insert("host".into(), or(row, "host", json!("")));
    out.insert("pid".into(), or(row, "pid", Json::Null));
    out.insert("worker".into(), json!(truthy(row.get("worker"))));
    out.insert("dueAt".into(), iso_of(row, "dueAt"));
    out.insert("queuedAt".into(), iso_of(row, "queuedAt"));
    let queued = num(row, "queuedAt");
    out.insert(
        "queuedAtMs".into(),
        if queued != 0.0 {
            json!(queued)
        } else {
            Json::Null
        },
    );
    out.insert("startedAt".into(), iso_of(row, "startedAt"));
    out.insert("endedAt".into(), iso_of(row, "endedAt"));
    out.insert(
        "durationMs".into(),
        match row.get("durationMs") {
            None => Json::Null,
            Some(_) => json!(num(row, "durationMs")),
        },
    );
    out.insert("requestedBy".into(), or(row, "requestedBy", json!("")));
    out.insert("requestedVia".into(), or(row, "requestedVia", json!("")));
    out.insert("params".into(), or(row, "params", Json::Null));
    out.insert("takenOver".into(), json!(truthy(row.get("takenOver"))));
    out.insert("abandonedOf".into(), or(row, "abandonedOf", Json::Null));
    out.insert("errorCode".into(), or(row, "errorCode", json!("")));
    out.insert("why".into(), or(row, "why", json!("")));
    out.insert(
        "result".into(),
        row.get("result").cloned().unwrap_or(Json::Null),
    );
    Json::Object(out)
}

impl Scheduler {
    /// The whole report, or one realm's.
    pub async fn status(&self, realm: Option<&str>) -> Json {
        if let Err(e) = self.refresh_clock().await {
            tracing::debug!("scheduler: the clock could not be read: {}", e);
        }
        let at = self.now_ms();
        let only = realm.unwrap_or("");
        let leader_row = self.deps.rows.get(DEFAULT_ID, LEADER_KEY);
        let leader = self.leader_view(leader_row.as_ref(), at).await;
        let mut jobs = Vec::new();
        for id in self.job_ids() {
            let Some(job) = self.job(&id) else {
                continue;
            };
            for realm_id in self.realm_ids_for(&job) {
                if only.is_empty()
                    || job.scope == Scope::Service
                    || realm_id == only
                {
                    jobs.push(
                        self.job_view(&job, &realm_id, at, &leader, only),
                    );
                }
            }
        }
        let (node, name) = self.who();
        let schedules = self.schedules();
        let unknown: Vec<String> = schedules
            .disabled_ids()
            .into_iter()
            .filter(|id| schedules.job(id).is_none())
            .collect();
        json!({
            "generatedAt": iso(at),
            "nowMs": at,
            "clock": self.deps.clock.source(),
            "answeredBy": { "node": node, "nodeName": name, "host": self.deps.host, "pid": self.deps.pid },
            "leader": leader,
            "tickS": schedules.setting_number("scheduler.tickS"),
            "enabled": schedules.setting_flag("scheduler.enabled"),
            "unknownDisabledIds": unknown,
            "jobs": jobs,
            "runs": self.recent_runs(None, realm, None),
            "commands": self.command_views(),
        })
    }

    async fn leader_view(&self, row: Option<&Json>, at: f64) -> Json {
        let clustered = self.deps.cluster.enabled();
        let lease = if clustered {
            self.deps.cluster.lease(LEADER_LEASE).await
        } else {
            None
        };
        let (node, _) = self.who();
        let tick = self.schedules().tick_ms();
        let mut out = Map::new();
        out.insert("clustered".into(), json!(clustered));
        out.insert("known".into(), json!(row.is_some()));
        let field = |k: &str| row.and_then(|r| r.get(k));
        match row {
            Some(_) => {
                put(&mut out, "node", field("node"));
                put(&mut out, "nodeName", field("nodeName"));
                put(&mut out, "host", field("host"));
                put(&mut out, "pid", field("pid"));
            }
            None => {
                out.insert("node".into(), json!(""));
                out.insert("nodeName".into(), json!(""));
                out.insert("host".into(), json!(""));
                out.insert("pid".into(), Json::Null);
            }
        }
        out.insert(
            "since".into(),
            if truthy(field("since")) {
                iso(row.map_or(0.0, |r| num(r, "since")))
            } else {
                Json::Null
            },
        );
        match (&lease, row) {
            (Some(l), _) => {
                out.insert("token".into(), json!(num(l, "token")));
            }
            (None, Some(_)) => put(&mut out, "token", field("token")),
            (None, None) => {
                out.insert("token".into(), json!(0));
            }
        }
        let lease_iso = |k: &str| match &lease {
            Some(l) if truthy(l.get(k)) => iso(num(l, k)),
            _ => Json::Null,
        };
        out.insert(
            "leaseHolder".into(),
            lease.as_ref().map_or(json!(""), |l| {
                l.get("holder").cloned().unwrap_or(Json::Null)
            }),
        );
        out.insert("leaseAcquiredAt".into(), lease_iso("acquiredAt"));
        out.insert("leaseExpiresAt".into(), lease_iso("expiresAt"));
        let ticked = truthy(field("lastTickAt"));
        let last = row.map_or(0.0, |r| num(r, "lastTickAt"));
        out.insert(
            "lastTickAt".into(),
            if ticked { iso(last) } else { Json::Null },
        );
        out.insert(
            "lastTickAgoMs".into(),
            if ticked {
                json!((at - last).max(0.0))
            } else {
                Json::Null
            },
        );
        let mine = row.is_some_and(|r| {
            r.get("pid") == Some(&json!(self.deps.pid))
                && (if truthy(r.get("node")) {
                    js_string(r.get("node"))
                } else {
                    String::new()
                }) == node
        });
        out.insert("thisProcess".into(), json!(mine && self.is_leading()));
        match row {
            None => {
                out.insert("live".into(), json!(false));
            }
            Some(_) if ticked => {
                out.insert(
                    "live".into(),
                    json!(at - last <= (3.0 * tick).max(OVERDUE_FLOOR_MS)),
                );
            }
            Some(_) => put(&mut out, "live", field("lastTickAt")),
        }
        Json::Object(out)
    }

    /// Every run row of one job in one realm, newest first.
    fn runs_of(&self, job_id: &str, realm_id: &str) -> Vec<Json> {
        let mut out: Vec<Json> = self
            .deps
            .rows
            .rows(realm_id)
            .into_iter()
            .filter(|r| {
                text(r, "kind") == "run"
                    && text(r, "jobId") == job_id
                    && text(r, "realm") == realm_id
            })
            .collect();
        let started = |r: &Json| {
            let s = num(r, "startedAt");
            if s != 0.0 {
                s
            } else {
                num(r, "queuedAt")
            }
        };
        out.sort_by(|a, b| {
            (started(b) - started(a))
                .partial_cmp(&0.0)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        out
    }

    fn job_view(
        &self,
        job: &JobSpec,
        realm_id: &str,
        at: f64,
        leader: &Json,
        only: &str,
    ) -> Json {
        let schedules = self.schedules();
        let off = schedules.off_reason(job, realm_id);
        let timed =
            !matches!(job.schedule, Schedule::Cron(_) | Schedule::ManualOnly);
        let mut view = json!({
            "id": job.id, "title": job.title, "describe": job.describe, "owner": job.owner,
            "kind": if job.kind == Kind::PerProcess { "per-process" } else { "cluster" },
            "scope": if job.scope == Scope::Realm { "realm" } else { "service" },
            "realm": realm_id,
            "readOnly": !only.is_empty() && job.scope == Scope::Service,
            "schedule": {
                "text": schedules.schedule_text(job),
                "everyMs": if timed { json!(schedules.interval_ms(job)) } else { Json::Null },
                "setting": match &job.schedule { Schedule::EverySetting { key, .. } => json!(key), _ => Json::Null },
                "cron": match &job.schedule { Schedule::Cron(c) => json!(c), _ => Json::Null },
                "manualOnly": matches!(job.schedule, Schedule::ManualOnly),
            },
            "state": if off.is_empty() { "enabled" } else { "off" },
            "offReason": if off.is_empty() { Json::Null } else { json!(off) },
            "manual": job.manual && job.kind != Kind::PerProcess,
            "timeoutMs": schedules.timeout_ms_of(job),
        });
        let next = schedules.slot_at(job, at as i64);
        drop(schedules);
        if job.kind == Kind::PerProcess {
            view["processes"] = json!(self.process_views(job, realm_id, at));
            view["lastRun"] = Json::Null;
            view["running"] = Json::Null;
            view["queued"] = json!([]);
            let next_at =
                next.and_then(|n| n.next_at).filter(|_| off.is_empty());
            let shown = off.is_empty() && next.is_some();
            view["nextRunAt"] = if shown {
                iso(next_at.unwrap_or(0.0))
            } else {
                Json::Null
            };
            view["nextRunInMs"] = if shown {
                json!((next_at.unwrap_or(0.0) - at).max(0.0))
            } else {
                Json::Null
            };
            view["nextRunState"] = json!(if !off.is_empty() {
                "off"
            } else if next.is_some() {
                "scheduled"
            } else {
                "manual-only"
            });
            return view;
        }
        let runs = self.runs_of(&job.id, realm_id);
        let mut finished: Vec<&Json> = runs
            .iter()
            .filter(|r| FINAL.contains(&text(r, "state")))
            .collect();
        finished.sort_by(|a, b| {
            (num(b, "endedAt") - num(a, "endedAt"))
                .partial_cmp(&0.0)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let running = runs.iter().find(|r| text(r, "state") == "running");
        let queued: Vec<Json> = runs
            .iter()
            .filter(|r| {
                text(r, "state") == "queued" && text(r, "trigger") == "manual"
            })
            .map(run_view)
            .collect();
        view["lastRun"] = finished.first().map_or(Json::Null, |r| run_view(r));
        view["running"] = running.map_or(Json::Null, run_view);
        view["queued"] = json!(queued);
        self.next_run_of(job, realm_id, at, leader, &mut view, &off);
        view
    }

    /// The next run, and the one word that says what kind of figure it is.
    fn next_run_of(
        &self,
        job: &JobSpec,
        realm_id: &str,
        at: f64,
        leader: &Json,
        view: &mut Json,
        off: &str,
    ) {
        view["nextRunAt"] = Json::Null;
        view["nextRunInMs"] = Json::Null;
        view["overdueSince"] = Json::Null;
        if !off.is_empty() {
            view["nextRunState"] = json!("off");
            return;
        }
        if let Some(first) =
            view["queued"].as_array().and_then(|q| q.first()).cloned()
        {
            let ms = first["queuedAtMs"]
                .as_f64()
                .filter(|n| *n != 0.0)
                .unwrap_or(at);
            view["nextRunState"] = json!("queued");
            view["nextRunAt"] = iso(ms);
            view["nextRunInMs"] = json!(0);
            return;
        }
        let (slot, tick) = {
            let s = self.schedules();
            (s.slot_at(job, at as i64), s.tick_ms())
        };
        let Some(slot) = slot else {
            view["nextRunState"] = json!("manual-only");
            return;
        };
        let current = slot.slot.and_then(|n| {
            self.deps
                .rows
                .get(realm_id, &run_id_for(&job.id, realm_id, n))
        });
        if slot.slot.is_none()
            || current
                .as_ref()
                .is_some_and(|c| text(c, "state") != "queued")
        {
            let running = current
                .as_ref()
                .is_some_and(|c| text(c, "state") == "running");
            view["nextRunState"] =
                json!(if running { "running" } else { "scheduled" });
            view["nextRunAt"] = slot.next_at.map_or(Json::Null, iso);
            view["nextRunInMs"] = slot
                .next_at
                .map_or(Json::Null, |n| json!((n - at).max(0.0)));
            return;
        }
        // Due in this slot and not run yet.
        let starts = slot.starts_at.unwrap_or(0.0);
        view["nextRunAt"] = iso(starts);
        view["nextRunInMs"] = json!(0);
        if at - starts > (3.0 * tick).max(OVERDUE_FLOOR_MS) {
            view["nextRunState"] = json!("overdue");
            view["overdueSince"] = iso(starts);
            view["overdueWhy"] = json!(if truthy(leader.get("live")) {
                "the leader is ticking; a previous run may still be going, or its claim has not lapsed".to_string()
            } else {
                format!(
                    "no leader has ticked since {}",
                    leader
                        .get("lastTickAt")
                        .and_then(Json::as_str)
                        .unwrap_or("this service started")
                )
            });
        } else {
            view["nextRunState"] = json!("due");
        }
    }

    fn process_views(
        &self,
        job: &JobSpec,
        realm_id: &str,
        at: f64,
    ) -> Vec<Json> {
        let (every, tick) = {
            let s = self.schedules();
            let interval = s.interval_ms(job);
            let tick = s.tick_ms();
            (
                if job.quiet {
                    QUIET_RECORD_MS
                } else if interval != 0.0 {
                    interval
                } else {
                    tick
                },
                tick,
            )
        };
        let mut out: Vec<Json> = self
            .deps
            .rows
            .rows(DEFAULT_ID)
            .into_iter()
            .filter(|r| {
                text(r, "kind") == "process"
                    && text(r, "jobId") == job.id
                    && text(r, "realm") == realm_id
            })
            .map(|row| {
                let mut view = run_view(&row);
                let next = num(&row, "nextAt");
                view["nextRunAt"] =
                    if next != 0.0 { iso(next) } else { Json::Null };
                view["nextRunInMs"] = if next != 0.0 {
                    json!((next - at).max(0.0))
                } else {
                    Json::Null
                };
                view["stale"] =
                    json!(at - num(&row, "endedAt") > 2.0 * every + 2.0 * tick);
                view
            })
            .collect();
        let name = |v: &Json| {
            format!(
                "{}{}",
                js_string(v.get("nodeName")),
                js_string(v.get("pid"))
            )
        };
        out.sort_by_key(name);
        out
    }

    fn command_views(&self) -> Vec<Json> {
        let mut out: Vec<Json> = self
            .deps
            .rows
            .rows(DEFAULT_ID)
            .into_iter()
            .filter(|r| text(r, "kind") == "command")
            .map(|row| {
                let mut v = Map::new();
                put(&mut v, "id", row.get("runId"));
                put(&mut v, "command", row.get("command"));
                put(&mut v, "state", row.get("state"));
                v.insert(
                    "requestedBy".into(),
                    or(&row, "requestedBy", json!("")),
                );
                v.insert(
                    "queuedAt".into(),
                    if truthy(row.get("queuedAt")) {
                        iso(num(&row, "queuedAt"))
                    } else {
                        Json::Null
                    },
                );
                v.insert(
                    "endedAt".into(),
                    if truthy(row.get("endedAt")) {
                        iso(num(&row, "endedAt"))
                    } else {
                        Json::Null
                    },
                );
                v.insert(
                    "leaderAtRequest".into(),
                    or(&row, "leaderAtRequest", Json::Null),
                );
                v.insert("obeyedBy".into(), or(&row, "obeyedBy", Json::Null));
                Json::Object(v)
            })
            .collect();
        out.sort_by(|a, b| {
            js_string(b.get("queuedAt")).cmp(&js_string(a.get("queuedAt")))
        });
        out.truncate(20);
        out
    }

    /// Recent runs, newest first, by job, realm and outcome.
    pub fn recent_runs(
        &self,
        job: Option<&str>,
        realm: Option<&str>,
        outcome: Option<&str>,
    ) -> Vec<Json> {
        let realm = realm.filter(|r| !r.is_empty());
        let mut out = Vec::new();
        for id in self.deps.realms.ids() {
            if realm.is_some_and(|r| id != r && id != DEFAULT_ID) {
                continue;
            }
            for row in self.deps.rows.rows(&id) {
                if text(&row, "kind") != "run" {
                    continue;
                }
                if let Some(r) = realm {
                    if id == DEFAULT_ID && r != DEFAULT_ID {
                        let scoped = self
                            .job(text(&row, "jobId"))
                            .is_some_and(|j| j.scope == Scope::Realm);
                        if scoped {
                            continue;
                        }
                    }
                }
                if job.is_some_and(|j| text(&row, "jobId") != j)
                    || outcome.is_some_and(|o| text(&row, "state") != o)
                {
                    continue;
                }
                out.push(run_view(&row));
            }
        }
        let when = |v: &Json| {
            ["startedAt", "queuedAt"]
                .iter()
                .find_map(|k| {
                    v.get(*k).and_then(Json::as_str).filter(|s| !s.is_empty())
                })
                .unwrap_or("")
                .to_string()
        };
        out.sort_by_key(|v| std::cmp::Reverse(when(v)));
        out
    }

    /// One run by id, in whichever realm holds it.
    pub fn find_run(&self, run_id: &str) -> Option<Json> {
        self.deps.realms.ids().iter().find_map(|id| {
            self.deps
                .rows
                .get(id, run_id)
                .filter(|r| matches!(text(r, "kind"), "run" | "process"))
                .map(|r| run_view(&r))
        })
    }
}
