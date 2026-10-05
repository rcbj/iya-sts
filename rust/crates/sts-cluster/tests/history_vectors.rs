// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The run history's bound and the report against Node:
//! `scheduler-history-node.json`, which `tests/tools/crypto-vectors.js`
//! writes with `cluster/scheduler.ts`'s own Scheduler over a store it
//! carries — runs old and new, finished, running and queued, per-process
//! rows, commands, the leader's row and rows of a removed realm. The purge
//! plan, the status (whole and confined to a realm), recent runs by
//! filter, a run by id, each row's expiry, and a purge in small batches —
//! what it removed, what it pinned, what is left and what was written down
//! between batches — must all be Node's.
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
    Audit, Claim, ClaimRefused, Claims, Clock, Cluster, Deps, LeaseHandler,
    Realms, RunRows, Scheduler,
};
use sts_core::realm::Realm;

struct World {
    now: f64,
    settings: HashMap<String, Json>,
    realms: Vec<String>,
    rows: Mutex<IndexMap<String, IndexMap<String, Json>>>,
    settles: Mutex<Vec<usize>>,
}

impl SchedulerSettings for World {
    fn number(&self, key: &str) -> f64 {
        self.settings.get(key).and_then(Json::as_f64).unwrap_or(0.0)
    }
    fn flag(&self, key: &str) -> bool {
        self.settings
            .get(key)
            .and_then(Json::as_bool)
            .unwrap_or(false)
    }
    fn list(&self, key: &str) -> Vec<String> {
        self.settings[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect()
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
        Box::pin(async { Ok(()) })
    }
    fn lease(&self, _: &str) -> BoxFuture<'_, Option<Json>> {
        let h = 3_600_000.0;
        let lease = json!({ "holder": "node-n1", "token": 12, "acquiredAt": self.now - h,
                            "expiresAt": self.now + 30000.0 });
        Box::pin(async move { Some(lease) })
    }
}

impl Claims for World {
    fn claim(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: f64,
    ) -> BoxFuture<'_, Result<Claim, ClaimRefused>> {
        Box::pin(async { Err(ClaimRefused::Held) })
    }
    fn release(&self, _: &Json) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
}

impl RunRows for World {
    fn get(&self, realm: &str, key: &str) -> Option<Json> {
        self.rows.lock().unwrap().get(realm)?.get(key).cloned()
    }
    fn set(&self, realm: &str, key: &str, row: Json) {
        self.rows
            .lock()
            .unwrap()
            .entry(realm.to_string())
            .or_default()
            .insert(key.to_string(), row);
    }
    fn rows(&self, realm: &str) -> Vec<Json> {
        self.rows
            .lock()
            .unwrap()
            .get(realm)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }
    fn delete(&self, realm: &str, key: &str) {
        if let Some(m) = self.rows.lock().unwrap().get_mut(realm) {
            m.shift_remove(key);
        }
    }
    fn settle(&self) -> BoxFuture<'_, ()> {
        let n = self
            .rows
            .lock()
            .unwrap()
            .get("default")
            .map_or(0, IndexMap::len);
        self.settles.lock().unwrap().push(n);
        Box::pin(async {})
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
        self.now
    }
    fn db_now(&self) -> BoxFuture<'_, Result<f64, String>> {
        let now = self.now;
        Box::pin(async move { Ok(now) })
    }
}

/// Integral floats as integers, so `30000.0` is Node's `30000`.
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

fn spec_of(d: &Json) -> JobSpec {
    let id = d["id"].as_str().unwrap();
    let schedule = if let Some(ms) = d["everyMs"].as_f64() {
        Schedule::Every(Arc::new(move || ms))
    } else if let Some(expr) = d["cron"].as_str() {
        Schedule::Cron(expr.to_string())
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
    spec.quiet = d["quiet"].as_bool().unwrap_or(false);
    spec
}

/// Each difference as a path, for a readable failure.
fn diff(path: &str, a: &Json, b: &Json, out: &mut Vec<String>) {
    match (a, b) {
        (Json::Object(x), Json::Object(y)) => {
            for k in x.keys().chain(y.keys().filter(|k| !x.contains_key(*k))) {
                diff(
                    &format!("{}.{}", path, k),
                    x.get(k).unwrap_or(&json!("<absent>")),
                    y.get(k).unwrap_or(&json!("<absent>")),
                    out,
                );
            }
        }
        (Json::Array(x), Json::Array(y)) if x.len() == y.len() => {
            for (i, (p, q)) in x.iter().zip(y).enumerate() {
                diff(&format!("{}[{}]", path, i), p, q, out);
            }
        }
        _ if a != b => out.push(format!("{}: rust {} node {}", path, a, b)),
        _ => {}
    }
}

#[tokio::test]
async fn the_history_and_the_report_are_nodes() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!("STS_CRYPTO_VECTORS is not set: scheduler-history-node.json is not checked");
        return;
    };
    let v: Json = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(&dir).join("scheduler-history-node.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let mut rows: IndexMap<String, IndexMap<String, Json>> = IndexMap::new();
    for r in ["default", "acme", "gone"] {
        rows.insert(r.to_string(), IndexMap::new());
    }
    for one in v["rows"].as_array().unwrap() {
        let row = one["row"].clone();
        rows.get_mut(one["realm"].as_str().unwrap())
            .unwrap()
            .insert(row["runId"].as_str().unwrap().to_string(), row);
    }
    let world = Arc::new(World {
        now: v["now"].as_f64().unwrap(),
        settings: v["settings"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, x)| (k.clone(), x.clone()))
            .collect(),
        realms: v["realms"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap().to_string())
            .collect(),
        rows: Mutex::new(rows),
        settles: Mutex::new(Vec::new()),
    });
    let sched = Scheduler::new(
        Schedules::new(world.clone()),
        Deps {
            cluster: world.clone(),
            claims: world.clone(),
            rows: world.clone(),
            realms: world.clone(),
            audit: world.clone(),
            clock: world.clone(),
            host: "h1".to_string(),
            pid: 41,
            thread: None,
            is_request_worker: false,
        },
    );
    for d in v["descriptors"].as_array().unwrap() {
        sched.register(spec_of(d)).unwrap();
    }
    sched.assume_leadership_for_tests();
    let mut failures = Vec::new();

    let status = norm(sched.status(None).await);
    diff("status", &status, &v["status"], &mut failures);
    let acme = norm(sched.status(Some("acme")).await);
    diff("acme", &acme, &v["acme"], &mut failures);
    for q in v["recent"].as_array().unwrap() {
        let query = &q["query"];
        let ids: Vec<Json> = sched
            .recent_runs(
                query["job"].as_str(),
                query["realm"].as_str(),
                query["outcome"].as_str(),
            )
            .into_iter()
            .map(|r| r["runId"].clone())
            .collect();
        diff(
            &format!("recent {}", query),
            &json!(ids),
            &q["runs"],
            &mut failures,
        );
    }
    for (id, want) in ["e1", "process|p.pull|default|n1|41", "leader", "nope"]
        .iter()
        .zip(v["found"].as_array().unwrap())
    {
        diff(
            &format!("find {}", id),
            &norm(sched.find_run(id).unwrap_or(Json::Null)),
            want,
            &mut failures,
        );
    }
    for (one, want) in v["rows"]
        .as_array()
        .unwrap()
        .iter()
        .zip(v["expiries"].as_array().unwrap())
    {
        diff(
            &format!("expiry of {}", one["row"]["runId"]),
            &norm(json!(sched.expiry_of(&one["row"]))),
            want,
            &mut failures,
        );
    }
    let now = v["now"].as_f64().unwrap();
    let purged = sched.purge_history(Some(now), Some(3), Some(2), None).await;
    diff("purged", &purged.to_json(), &v["purged"], &mut failures);
    let remaining: serde_json::Map<String, Json> = world
        .rows
        .lock()
        .unwrap()
        .iter()
        .map(|(r, m)| (r.clone(), json!(m.keys().collect::<Vec<_>>())))
        .collect();
    diff(
        "remaining",
        &Json::Object(remaining),
        &v["remaining"],
        &mut failures,
    );
    let mut pinned = Vec::new();
    for (realm, m) in world.rows.lock().unwrap().iter() {
        for row in m.values() {
            if let Some(k) = row.get("keepUntil") {
                pinned.push(json!(format!(
                    "{}|{}|{}",
                    realm,
                    row["runId"].as_str().unwrap(),
                    norm(k.clone())
                )));
            }
        }
    }
    diff("pinned", &json!(pinned), &v["pinned"], &mut failures);
    diff(
        "settles",
        &json!(*world.settles.lock().unwrap()),
        &v["settles"],
        &mut failures,
    );

    assert!(
        failures.is_empty(),
        "{} differences:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
