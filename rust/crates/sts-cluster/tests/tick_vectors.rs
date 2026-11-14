// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The leader's tick against Node: `scheduler-tick-node.json`, which
//! `tests/tools/crypto-vectors.js` writes by driving `cluster/scheduler.ts`'s
//! own `tick()` through scenarios — a patient run held for load and forced
//! through at its bound (#408), the rows a tick has to see read from the
//! index and never from the map (#623), the current slots learnt from the
//! durable store with a failing read holding back only its own jobs and an
//! absence remembered (#883), and a global job's run claimed under the
//! global scope and not asked again while another cell holds it (#98). Per
//! tick the claims asked, the reads asked and the bodies dropped, and at the
//! end every run row's state, where it ran and how long it was held, must
//! all be Node's. Also the default concurrency cap with request workers and
//! `leastLoaded()`.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed; with it unset
//! this test says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use indexmap::IndexMap;
use serde_json::{json, Value as Json};
use sts_cluster::schedule::{
    BoxFuture, JobSpec, Kind, Schedule, SchedulerSettings, Schedules, Scope,
};
use sts_cluster::scheduler::{
    least_loaded, Audit, Claim, ClaimRefused, Claims, Clock, Cluster, Deps,
    Extras, LeaseHandler, Loads, Realms, RunHistory, RunRows, Scheduler,
    WorkerLoad,
};
use sts_core::realm::Realm;

struct Settings(HashMap<String, Json>);

impl SchedulerSettings for Settings {
    fn number(&self, key: &str) -> f64 {
        self.0.get(key).and_then(Json::as_f64).unwrap_or(0.0)
    }
    fn flag(&self, key: &str) -> bool {
        self.0.get(key).and_then(Json::as_bool).unwrap_or(false)
    }
    fn list(&self, key: &str) -> Vec<String> {
        self.0
            .get(key)
            .and_then(Json::as_array)
            .map(|a| {
                a.iter().map(|x| x.as_str().unwrap().to_string()).collect()
            })
            .unwrap_or_default()
    }
}

#[derive(Default)]
struct Inner {
    clock: f64,
    tick: Json,
    events: Vec<Json>,
    rows: IndexMap<String, IndexMap<String, Json>>,
}

struct World {
    realms: Vec<String>,
    stored: Vec<Json>,
    inner: Mutex<Inner>,
}

impl World {
    fn tick(&self) -> Json {
        self.inner.lock().unwrap().tick.clone()
    }
    fn event(&self, e: Json) {
        self.inner.lock().unwrap().events.push(e);
    }
}

impl Cluster for World {
    fn enabled(&self) -> bool {
        true
    }
    fn node_id(&self) -> String {
        "n1".to_string()
    }
    fn node_name(&self) -> String {
        "node-one".to_string()
    }
    fn lead(&self, _: &str, _: Arc<dyn LeaseHandler>) {}
    fn step_down(&self, _: &str) -> BoxFuture<'_, Result<(), String>> {
        self.event(json!({ "stepDown": true }));
        Box::pin(async { Ok(()) })
    }
}

impl Claims for World {
    fn claim(
        &self,
        scope: &str,
        value: &str,
        realm: &str,
        _: f64,
    ) -> BoxFuture<'_, Result<Claim, ClaimRefused>> {
        self.event(json!({ "claim": [scope, value, realm] }));
        let used = self.tick()["claimUsed"]
            .as_array()
            .is_some_and(|a| a.iter().any(|s| s == scope));
        let clock = self.inner.lock().unwrap().clock;
        let value = value.to_string();
        Box::pin(async move {
            if used {
                Err(ClaimRefused::Held)
            } else {
                Ok(Claim {
                    claimed_at: clock,
                    handle: json!({ "v": value }),
                })
            }
        })
    }
    fn release(&self, _: &Json) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
}

impl RunRows for World {
    fn get(&self, realm: &str, key: &str) -> Option<Json> {
        self.inner.lock().unwrap().rows.get(realm)?.get(key).cloned()
    }
    fn set(&self, realm: &str, key: &str, row: Json) {
        self.inner
            .lock()
            .unwrap()
            .rows
            .entry(realm.to_string())
            .or_default()
            .insert(key.to_string(), row);
    }
    fn rows(&self, realm: &str) -> Vec<Json> {
        self.inner
            .lock()
            .unwrap()
            .rows
            .get(realm)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }
    fn delete(&self, realm: &str, key: &str) {
        if let Some(m) = self.inner.lock().unwrap().rows.get_mut(realm) {
            m.shift_remove(key);
        }
    }
}

impl Realms for World {
    fn ids(&self) -> Vec<String> {
        self.realms.clone()
    }
    fn get(&self, id: &str) -> Option<Arc<Realm>> {
        self.realms.iter().any(|r| r == id).then(|| {
            let mut r = Realm::default_realm();
            r.id = id.to_string();
            Arc::new(r)
        })
    }
}

impl Audit for World {
    fn record(&self, _: Json) {}
}

impl Clock for World {
    fn now(&self) -> f64 {
        self.inner.lock().unwrap().clock
    }
    fn db_now(&self) -> BoxFuture<'_, Result<f64, String>> {
        let now = self.now();
        Box::pin(async move { Ok(now) })
    }
}

impl Loads for World {
    fn workers(&self) -> Vec<WorkerLoad> {
        loads_of(&self.tick()["loads"])
    }
}

fn loads_of(v: &Json) -> Vec<WorkerLoad> {
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|w| WorkerLoad {
                    id: w["id"].as_u64().unwrap(),
                    in_flight: w["inFlight"].as_f64().unwrap(),
                    lag_ms: w["lagMs"].as_f64(),
                })
                .collect()
        })
        .unwrap_or_default()
}

impl RunHistory for World {
    fn persisted(&self) -> bool {
        true
    }
    fn read_runs(
        &self,
        realm: &str,
        ids: Vec<String>,
    ) -> BoxFuture<'_, Result<Option<HashMap<String, Json>>, String>> {
        self.event(json!({ "read": [realm, ids] }));
        let how = self.tick()["reads"][realm].clone();
        let fails = how == "fail"
            || (how == "fail-batch" && ids.len() > 2)
            || how
                .as_array()
                .is_some_and(|a| ids.iter().any(|id| a.contains(&json!(id))));
        let answer = if fails {
            Err("the store is unwell".to_string())
        } else if how == "none" {
            Ok(None)
        } else {
            Ok(Some(
                self.stored
                    .iter()
                    .filter(|r| {
                        r["realm"] == realm
                            && ids.iter().any(|id| r["runId"] == *id)
                    })
                    .map(|r| (r["runId"].as_str().unwrap().to_string(), r.clone()))
                    .collect(),
            ))
        };
        Box::pin(async move { answer })
    }
    fn drop_held(&self, realm: &str, key: &str) -> bool {
        self.event(json!({ "drop": [realm, key] }));
        self.delete(realm, key);
        true
    }
    fn restore_row(&self, realm: &str, key: &str, row: Json) {
        self.set(realm, key, row);
    }
}

/// The Arc a trait object of World needs, for each of the deps.
struct Shared(Arc<World>);

fn spec_of(d: &Json) -> JobSpec {
    let id = d["id"].as_str().unwrap();
    let schedule = if let Some(ms) = d["everyMs"].as_f64() {
        Schedule::Every(Arc::new(move || ms))
    } else {
        Schedule::ManualOnly
    };
    let mut spec = JobSpec::new(id, &format!("T {}", id), "D", "O", schedule);
    spec.run = Some(Arc::new(|_| Box::pin(async { Ok(Json::Null) })));
    if d["kind"] == "per-process" {
        spec.kind = Kind::PerProcess;
    }
    if d["scope"] == "realm" {
        spec.scope = Scope::Realm;
    }
    spec.on_front = d["onFront"].as_str().map(str::to_string);
    spec.nice = d["nice"].as_f64();
    spec
}

fn norm(v: Json) -> Json {
    match v {
        Json::Number(n) => match n.as_f64() {
            Some(f) if f.fract() == 0.0 && f.abs() < 9e15 => json!(f as i64),
            _ => Json::Number(n),
        },
        Json::Array(a) => Json::Array(a.into_iter().map(norm).collect()),
        Json::Object(o) => {
            Json::Object(o.into_iter().map(|(k, x)| (k, norm(x))).collect())
        }
        other => other,
    }
}

/// A claim list in a stable order: both sides start a claim per attempt,
/// and which of two claims a runtime asks first is not the behaviour.
fn sorted(events: Vec<Json>) -> Vec<Json> {
    let mut claims: Vec<Json> = events
        .iter()
        .filter(|e| e.get("claim").is_some())
        .cloned()
        .collect();
    claims.sort_by_key(|c| c.to_string());
    let mut rest: Vec<Json> = events
        .into_iter()
        .filter(|e| e.get("claim").is_none())
        .collect();
    rest.extend(claims);
    rest
}

async fn run_scenario(
    sc: &Json,
    base: &HashMap<String, Json>,
) -> (Vec<Vec<Json>>, Vec<Json>) {
    let mut settings = base.clone();
    if let Some(o) = sc["settings"].as_object() {
        for (k, v) in o {
            settings.insert(k.clone(), v.clone());
        }
    }
    let realms: Vec<String> = sc["realms"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap().to_string())
        .collect();
    let ticks = sc["ticks"].as_array().unwrap();
    let world = Arc::new(World {
        realms,
        stored: sc["stored"].as_array().cloned().unwrap_or_default(),
        inner: Mutex::new(Inner {
            clock: ticks[0]["at"].as_f64().unwrap(),
            tick: ticks[0].clone(),
            ..Inner::default()
        }),
    });
    let shared = Shared(world.clone());
    let w = &shared.0;
    let cells = sc["cells"].as_bool().unwrap_or(false);
    let extras = Extras {
        loads: Some(w.clone()),
        history: sc["history"]
            .as_bool()
            .unwrap_or(false)
            .then(|| w.clone() as Arc<dyn RunHistory>),
        cells_multi: Some(Arc::new(move || cells)),
    };
    let mut schedules = Schedules::new(Arc::new(Settings(settings)));
    for d in sc["jobs"].as_array().unwrap() {
        schedules.register(spec_of(d)).unwrap();
    }
    let s = Scheduler::with_extras(
        schedules,
        Deps {
            cluster: w.clone(),
            claims: w.clone(),
            rows: w.clone(),
            realms: w.clone(),
            audit: w.clone(),
            clock: w.clone(),
            host: "h1".to_string(),
            pid: 41,
            thread: None,
            is_request_worker: false,
        },
        extras,
    );
    for one in sc["admitted"].as_array().cloned().unwrap_or_default() {
        let realm = one["realm"].as_str().unwrap();
        let row = one["row"].clone();
        w.set(realm, row["runId"].as_str().unwrap(), row.clone());
        if one["watched"] == true {
            s.note_admitted(realm, &row);
        }
    }
    s.assume_leadership_for_tests();
    let mut out = Vec::new();
    for t in ticks {
        {
            let mut inner = w.inner.lock().unwrap();
            inner.clock = t["at"].as_f64().unwrap();
            inner.tick = t.clone();
            inner.events.clear();
        }
        s.tick().await;
        for _ in 0..200 {
            tokio::task::yield_now().await;
        }
        let events = std::mem::take(&mut w.inner.lock().unwrap().events);
        out.push(sorted(events));
    }
    let mut rows = Vec::new();
    for (realm, m) in w.inner.lock().unwrap().rows.iter() {
        for row in m.values() {
            if row["kind"] != "run" {
                continue;
            }
            rows.push(json!({ "realm": realm, "runId": row["runId"], "jobId": row["jobId"],
                              "state": row["state"], "trigger": row["trigger"],
                              "attempt": row["attempt"],
                              "ranIn": row.get("ranIn").cloned().unwrap_or(Json::Null),
                              "deferredMs": row.get("deferredMs").cloned().unwrap_or(Json::Null) }));
        }
    }
    rows.sort_by_key(|r| {
        format!("{}{}", r["realm"].as_str().unwrap(), r["runId"].as_str().unwrap())
    });
    (out, rows)
}

#[tokio::test(flavor = "current_thread")]
async fn the_tick_is_nodes() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!("STS_CRYPTO_VECTORS is not set; nothing to compare");
        return;
    };
    let path = format!("{}/scheduler-tick-node.json", dir);
    let Ok(text) = std::fs::read_to_string(&path) else {
        eprintln!("{} is not there; nothing to compare", path);
        return;
    };
    let v: Json = serde_json::from_str(&text).unwrap();
    let base: HashMap<String, Json> = v["settings"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, x)| (k.clone(), x.clone()))
        .collect();
    let mut failures = Vec::new();
    let mut checks = 0;
    for one in v["scenarios"].as_array().unwrap() {
        let name = one["name"].as_str().unwrap();
        let (ticks, rows) = run_scenario(&one["scenario"], &base).await;
        let want_ticks: Vec<Vec<Json>> = one["ticks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| sorted(t.as_array().unwrap().clone()))
            .collect();
        for (i, (got, want)) in ticks.iter().zip(&want_ticks).enumerate() {
            checks += 1;
            if norm(json!(got)) != norm(json!(want)) {
                failures.push(format!(
                    "{} tick {}:\n  rust {}\n  node {}",
                    name,
                    i,
                    json!(got),
                    json!(want)
                ));
            }
        }
        checks += 1;
        // The same order on both sides: Node sorted by localeCompare,
        // which no byte order reproduces, and the order is not behaviour.
        let mut want_rows = one["rows"].as_array().unwrap().clone();
        want_rows.sort_by_key(|r| {
            format!("{}{}", r["realm"].as_str().unwrap(), r["runId"].as_str().unwrap())
        });
        if norm(json!(rows)) != norm(json!(want_rows)) {
            failures.push(format!(
                "{} rows:\n  rust {}\n  node {}",
                name,
                json!(rows),
                one["rows"]
            ));
        }
    }
    for c in v["caps"].as_array().unwrap() {
        checks += 1;
        let mut settings = base.clone();
        settings.insert("scheduler.maxConcurrentRuns".into(), json!(0));
        let (workers, pool) =
            (c["workers"].as_f64().unwrap(), c["pool"].as_f64().unwrap());
        let s = Schedules::new(Arc::new(Settings(settings)))
            .with_request_workers(Arc::new(move || workers))
            .with_store_connections(Arc::new(move || pool));
        if s.max_concurrent_runs() != c["cap"].as_f64().unwrap() {
            failures.push(format!("cap {}: {}", c, s.max_concurrent_runs()));
        }
    }
    for c in v["leastLoaded"].as_array().unwrap() {
        checks += 1;
        let got = least_loaded(&loads_of(&c["loads"]));
        if json!(got) != c["id"] {
            failures.push(format!("leastLoaded {}: {:?}", c, got));
        }
    }
    eprintln!("tick vectors: {} checks", checks);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
