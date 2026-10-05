// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The scheduler's runner, against stand-ins for the cluster, the claims,
//! the run store, the realms and the clock — `tests/scheduler.js`'s kit in
//! small. Each test is one rule `cluster/scheduler.ts` states: registering
//! starts nothing, a slot runs once however many leaders reach it, the
//! fence decides whose outcome is written, a time limit fails a run and
//! fences it out, a manual run is queued once and run once, the
//! concurrency limit holds and frees itself, per-process jobs remember
//! their slot and record quietly, a removed realm runs nothing, and a
//! step-down command is obeyed.

#![allow(clippy::unwrap_used)] // a test file

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use indexmap::IndexMap;
use serde_json::{json, Value as Json};
use sts_cluster::schedule::{
    BoxFuture, JobRun, JobSpec, Kind, RunContext, Schedule, SchedulerSettings,
    Schedules, Scope,
};
use sts_cluster::scheduler::{
    Audit, Claim, ClaimRefused, Claims, Clock, Cluster, Deps, LeaseHandler,
    Realms, RunRows, Scheduler,
};
use sts_core::realm::Realm;

#[derive(Default)]
struct World {
    db: Mutex<f64>,
    rows: Mutex<HashMap<String, IndexMap<String, Json>>>,
    claims: Mutex<HashMap<String, f64>>,
    realms: Mutex<Vec<String>>,
    audits: Mutex<Vec<Json>>,
    settings: Mutex<HashMap<String, Json>>,
    step_downs: AtomicUsize,
}

impl World {
    fn new() -> Arc<World> {
        let w = World::default();
        *w.realms.lock().unwrap() = vec!["default".to_string()];
        *w.db.lock().unwrap() = 1_800_000_000_000.0;
        let mut s = w.settings.lock().unwrap();
        for (k, v) in [
            ("scheduler.enabled", json!(true)),
            ("scheduler.tickS", json!(15)),
            ("scheduler.maxConcurrentRuns", json!(8)),
            ("scheduler.runTimeoutS", json!(300)),
            ("scheduler.disabledJobs", json!([])),
        ] {
            s.insert(k.to_string(), v);
        }
        drop(s);
        Arc::new(w)
    }

    fn advance(&self, ms: f64) {
        *self.db.lock().unwrap() += ms;
    }

    fn rows_of(&self, realm: &str) -> Vec<Json> {
        self.rows
            .lock()
            .unwrap()
            .get(realm)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    fn runs(&self, realm: &str, job: &str) -> Vec<Json> {
        self.rows_of(realm)
            .into_iter()
            .filter(|r| r["kind"] == "run" && r["jobId"] == job)
            .collect()
    }
}

struct Node {
    world: Arc<World>,
    clustered: bool,
}

impl SchedulerSettings for Node {
    fn number(&self, key: &str) -> f64 {
        self.world
            .settings
            .lock()
            .unwrap()
            .get(key)
            .and_then(Json::as_f64)
            .unwrap_or(0.0)
    }
    fn flag(&self, key: &str) -> bool {
        self.world
            .settings
            .lock()
            .unwrap()
            .get(key)
            .and_then(Json::as_bool)
            .unwrap_or(false)
    }
    fn list(&self, key: &str) -> Vec<String> {
        self.world
            .settings
            .lock()
            .unwrap()
            .get(key)
            .and_then(Json::as_array)
            .map(|a| {
                a.iter().map(|x| x.as_str().unwrap().to_string()).collect()
            })
            .unwrap_or_default()
    }
}

impl Cluster for Node {
    fn enabled(&self) -> bool {
        self.clustered
    }
    fn node_id(&self) -> String {
        "n1".to_string()
    }
    fn node_name(&self) -> String {
        String::new()
    }
    fn lead(&self, _lease: &str, _handler: Arc<dyn LeaseHandler>) {}
    fn step_down(&self, _lease: &str) -> BoxFuture<'_, Result<(), String>> {
        self.world.step_downs.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}

impl Claims for Node {
    fn claim(
        &self,
        scope: &str,
        value: &str,
        _realm: &str,
        ttl_ms: f64,
    ) -> BoxFuture<'_, Result<Claim, ClaimRefused>> {
        let now = *self.world.db.lock().unwrap();
        let key = format!("{}|{}", scope, value);
        let mut claims = self.world.claims.lock().unwrap();
        let answer = match claims.get(&key) {
            Some(until) if *until > now => Err(ClaimRefused::Held),
            _ => {
                claims.insert(key.clone(), now + ttl_ms);
                Ok(Claim {
                    claimed_at: now,
                    handle: json!(key),
                })
            }
        };
        Box::pin(async move { answer })
    }
    fn release(&self, handle: &Json) -> BoxFuture<'_, ()> {
        self.world
            .claims
            .lock()
            .unwrap()
            .remove(handle.as_str().unwrap());
        Box::pin(async {})
    }
}

impl RunRows for Node {
    fn get(&self, realm: &str, key: &str) -> Option<Json> {
        self.world
            .rows
            .lock()
            .unwrap()
            .get(realm)?
            .get(key)
            .cloned()
    }
    fn set(&self, realm: &str, key: &str, row: Json) {
        self.world
            .rows
            .lock()
            .unwrap()
            .entry(realm.to_string())
            .or_default()
            .insert(key.to_string(), row);
    }
    fn rows(&self, realm: &str) -> Vec<Json> {
        self.world.rows_of(realm)
    }
    fn delete(&self, realm: &str, key: &str) {
        if let Some(m) = self.world.rows.lock().unwrap().get_mut(realm) {
            m.shift_remove(key);
        }
    }
}

impl Realms for Node {
    fn ids(&self) -> Vec<String> {
        self.world.realms.lock().unwrap().clone()
    }
    fn get(&self, id: &str) -> Option<Arc<Realm>> {
        self.world
            .realms
            .lock()
            .unwrap()
            .iter()
            .any(|r| r == id)
            .then(|| {
                let mut r = Realm::default_realm();
                r.id = id.to_string();
                Arc::new(r)
            })
    }
}

impl Audit for Node {
    fn record(&self, event: Json) {
        self.world.audits.lock().unwrap().push(event);
    }
}

impl Clock for Node {
    fn now(&self) -> f64 {
        *self.world.db.lock().unwrap()
    }
    fn db_now(&self) -> BoxFuture<'_, Result<f64, String>> {
        let now = *self.world.db.lock().unwrap();
        Box::pin(async move { Ok(now) })
    }
}

fn node(world: &Arc<World>, worker: bool) -> Arc<Scheduler> {
    let n = Arc::new(Node {
        world: world.clone(),
        clustered: true,
    });
    Scheduler::new(
        Schedules::new(n.clone()),
        Deps {
            cluster: n.clone(),
            claims: n.clone(),
            rows: n.clone(),
            realms: n.clone(),
            audit: n.clone(),
            clock: n.clone(),
            host: "host".to_string(),
            pid: 7,
            thread: worker.then(|| "3".to_string()),
            is_request_worker: worker,
        },
    )
}

/// A job counting its runs, doing `work` each time.
fn job<F>(
    id: &str,
    schedule: Schedule,
    count: &Arc<AtomicUsize>,
    work: F,
) -> JobSpec
where
    F: Fn(RunContext) -> BoxFuture<'static, Result<Json, String>>
        + Send
        + Sync
        + 'static,
{
    let count = count.clone();
    let run: JobRun = Arc::new(move |ctx| {
        count.fetch_add(1, Ordering::SeqCst);
        work(ctx)
    });
    let mut spec = JobSpec::new(id, "T", "D", "O", schedule);
    spec.run = Some(run);
    spec
}

fn ok_job(id: &str, every_ms: f64, count: &Arc<AtomicUsize>) -> JobSpec {
    job(
        id,
        Schedule::Every(Arc::new(move || every_ms)),
        count,
        |ctx| Box::pin(async move { Ok(json!({ "realm": ctx.realm })) }),
    )
}

async fn settle(s: &Scheduler) {
    for _ in 0..10_000 {
        tokio::task::yield_now().await;
        if s.in_flight() == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("runs never settled");
}

async fn lead(s: &Arc<Scheduler>) {
    assert!(s.start(false));
    s.gain_leadership(1).await;
}

#[tokio::test(start_paused = true)]
async fn registering_starts_nothing_and_a_worker_never_leads() {
    let w = World::new();
    let count = Arc::new(AtomicUsize::new(0));
    let s = node(&w, false);
    s.register(ok_job("test.job", 1000.0, &count)).unwrap();
    tokio::time::sleep(Duration::from_secs(300)).await;
    assert_eq!(count.load(Ordering::SeqCst), 0);

    let worker = node(&w, true);
    worker.register(ok_job("test.job", 1000.0, &count)).unwrap();
    assert!(worker.start(false));
    worker.gain_leadership(1).await;
    worker.tick().await;
    assert!(!worker.is_leading());
    assert_eq!(count.load(Ordering::SeqCst), 0);
    // A job without a run() is refused whole.
    let mut bare =
        JobSpec::new("test.bare", "T", "D", "O", Schedule::ManualOnly);
    bare.run = None;
    assert!(s.register(bare).unwrap_err().contains("a run() function"));
}

#[tokio::test(start_paused = true)]
async fn a_slot_runs_once_however_many_leaders_reach_it() {
    let w = World::new();
    let count = Arc::new(AtomicUsize::new(0));
    let (a, b) = (node(&w, false), node(&w, false));
    for s in [&a, &b] {
        s.register(ok_job("test.job", 60_000.0, &count)).unwrap();
        lead(s).await;
    }
    for _ in 0..3 {
        a.tick().await;
        b.tick().await;
        settle(&a).await;
        settle(&b).await;
    }
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "two leaders, one slot, one run"
    );
    let runs = w.runs("default", "test.job");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0]["state"], "succeeded");
    assert_eq!(runs[0]["result"], json!(r#"{"realm":"default"}"#));
    assert!(runs[0]["fenceAt"].as_f64().unwrap() > 0.0);

    w.advance(60_000.0);
    a.tick().await;
    settle(&a).await;
    assert_eq!(count.load(Ordering::SeqCst), 2, "the next slot runs");
    assert!(w.rows_of("default").iter().any(|r| r["kind"] == "leader"));
}

#[tokio::test(start_paused = true)]
async fn a_failure_and_a_time_limit_are_recorded_and_fenced() {
    let w = World::new();
    let count = Arc::new(AtomicUsize::new(0));
    let s = node(&w, false);
    s.register(job(
        "test.fails",
        Schedule::Every(Arc::new(|| 60_000.0)),
        &count,
        |_| Box::pin(async { Err("no luck".to_string()) }),
    ))
    .unwrap();
    let late_owner = Arc::new(Mutex::new(None));
    let seen = late_owner.clone();
    let mut slow = job(
        "test.slow",
        Schedule::Every(Arc::new(|| 60_000.0)),
        &count,
        move |ctx| {
            let seen = seen.clone();
            Box::pin(async move {
                tokio::time::sleep(Duration::from_secs(10)).await;
                *seen.lock().unwrap() = Some((ctx.still_owner)());
                Ok(json!("late"))
            })
        },
    );
    slow.timeout_s = Some(Arc::new(|| 2.0));
    s.register(slow).unwrap();
    lead(&s).await;
    s.tick().await;
    settle(&s).await;
    let failed = &w.runs("default", "test.fails")[0];
    assert_eq!(
        (failed["state"].as_str(), failed["errorCode"].as_str()),
        (Some("failed"), Some("STS-SCHED-0001"))
    );
    assert_eq!(failed["why"], "no luck");
    let slow = &w.runs("default", "test.slow")[0];
    assert_eq!(slow["errorCode"], "STS-SCHED-0002");
    assert!(slow["why"].as_str().unwrap().contains("time limit of 2 s"));
    // The run went on in its own task, was told it no longer owns the run,
    // and its late answer was not written.
    tokio::time::sleep(Duration::from_secs(20)).await;
    assert_eq!(*late_owner.lock().unwrap(), Some(false));
    assert_eq!(w.runs("default", "test.slow")[0]["state"], "failed");
}

#[tokio::test(start_paused = true)]
async fn an_outcome_is_written_only_under_its_fence() {
    let w = World::new();
    let count = Arc::new(AtomicUsize::new(0));
    let s = node(&w, false);
    let world = w.clone();
    s.register(job(
        "test.raced",
        Schedule::Every(Arc::new(|| 60_000.0)),
        &count,
        move |ctx| {
            let world = world.clone();
            Box::pin(async move {
                // Another attempt takes the run over while this one works.
                let mut rows = world.rows.lock().unwrap();
                let row = rows
                    .get_mut("default")
                    .unwrap()
                    .get_mut(&ctx.run_id)
                    .unwrap();
                row["fenceAt"] = json!(1);
                row["attempt"] = json!(9);
                drop(rows);
                assert!(!(ctx.still_owner)());
                Ok(json!("mine"))
            })
        },
    ))
    .unwrap();
    lead(&s).await;
    s.tick().await;
    settle(&s).await;
    let row = &w.runs("default", "test.raced")[0];
    assert_eq!(row["state"], "running", "the other attempt's row stands");
    assert_eq!(row["attempt"], 9);
}

#[tokio::test(start_paused = true)]
async fn a_manual_run_is_queued_once_and_run_once() {
    let w = World::new();
    let count = Arc::new(AtomicUsize::new(0));
    let s = node(&w, false);
    s.register(job("test.manual", Schedule::ManualOnly, &count, |ctx| {
        Box::pin(async move { Ok(ctx.params) })
    }))
    .unwrap();
    let mut off = ok_job("test.offjob", 60_000.0, &count);
    off.off = Some(Arc::new(|_| Ok("its store is not configured".to_string())));
    s.register(off).unwrap();
    let mut per_realm = ok_job("test.realm", 60_000.0, &count);
    per_realm.scope = Scope::Realm;
    per_realm.manual = true;
    s.register(per_realm).unwrap();
    lead(&s).await;
    s.tick().await;
    settle(&s).await;
    let ran = count.load(Ordering::SeqCst);

    let first = s
        .request_run(
            "test.manual",
            None,
            json!({ "x": 1 }),
            "alice",
            "/admin/scheduler",
        )
        .unwrap();
    let again = s
        .request_run(
            "test.manual",
            None,
            json!({ "x": 1 }),
            "alice",
            "/admin/scheduler",
        )
        .unwrap();
    assert!(
        !first.already_queued
            && again.already_queued
            && again.run_id == first.run_id
    );
    s.tick().await;
    settle(&s).await;
    s.tick().await;
    settle(&s).await;
    assert_eq!(
        count.load(Ordering::SeqCst),
        ran + 1,
        "run once, and never again"
    );
    let row = w
        .rows_of("default")
        .into_iter()
        .find(|r| r["runId"] == json!(first.run_id))
        .unwrap();
    assert_eq!(row["state"], "succeeded");
    assert_eq!(row["result"], json!(r#"{"x":1}"#));

    let code = |r: Result<_, sts_cluster::scheduler::Refusal>| {
        r.err().map(|e| e.error_code)
    };
    assert_eq!(
        code(s.request_run("test.nosuch", None, Json::Null, "", "")),
        Some("STS-SCHED-0004")
    );
    assert_eq!(
        code(s.request_run("test.offjob", None, Json::Null, "", "")),
        Some("STS-SCHED-0006")
    );
    assert_eq!(
        code(s.request_run("test.realm", Some("gone"), Json::Null, "", "")),
        Some("STS-SCHED-0012")
    );
}

#[tokio::test(start_paused = true)]
async fn the_concurrency_limit_holds_and_frees_itself() {
    let w = World::new();
    w.settings
        .lock()
        .unwrap()
        .insert("scheduler.maxConcurrentRuns".to_string(), json!(2));
    *w.realms.lock().unwrap() = ["default", "a", "b", "c", "d"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let count = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let going = Arc::new(AtomicUsize::new(0));
    let s = node(&w, false);
    let (p, g) = (peak.clone(), going.clone());
    let mut spec = job(
        "test.each",
        Schedule::Every(Arc::new(|| 60_000.0)),
        &count,
        move |_| {
            let (p, g) = (p.clone(), g.clone());
            Box::pin(async move {
                let now = g.fetch_add(1, Ordering::SeqCst) + 1;
                p.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(100)).await;
                g.fetch_sub(1, Ordering::SeqCst);
                Ok(Json::Null)
            })
        },
    );
    spec.scope = Scope::Realm;
    s.register(spec).unwrap();
    lead(&s).await;
    s.tick().await;
    for _ in 0..50 {
        settle(&s).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        count.load(Ordering::SeqCst),
        5,
        "every realm ran, without waiting for the next tick"
    );
    assert_eq!(peak.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn per_process_jobs_remember_their_slot_and_record_quietly() {
    let w = World::new();
    let count = Arc::new(AtomicUsize::new(0));
    let s = node(&w, true);
    let mut pull = ok_job("test.pull", 1000.0, &count);
    pull.kind = Kind::PerProcess;
    pull.quiet = true;
    s.register(pull).unwrap();
    s.process_tick().await;
    s.process_tick().await;
    assert_eq!(count.load(Ordering::SeqCst), 1, "one slot, one run");
    let rows: Vec<Json> = w
        .rows_of("default")
        .into_iter()
        .filter(|r| r["kind"] == "process")
        .collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["runId"], "process|test.pull|default|n1|7.3");
    let first_end = rows[0]["endedAt"].clone();
    w.advance(1000.0);
    s.process_tick().await;
    assert_eq!(count.load(Ordering::SeqCst), 2);
    let row = w
        .rows_of("default")
        .into_iter()
        .find(|r| r["kind"] == "process")
        .unwrap();
    assert_eq!(
        row["endedAt"], first_end,
        "an unchanged outcome inside a minute is not written"
    );
    w.advance(60_000.0);
    s.process_tick().await;
    let row = w
        .rows_of("default")
        .into_iter()
        .find(|r| r["kind"] == "process")
        .unwrap();
    assert_ne!(row["endedAt"], first_end, "and is once a minute");
}

#[tokio::test(start_paused = true)]
async fn a_removed_realm_runs_nothing() {
    let w = World::new();
    // Each run sorted by realm after the fact: the order of two runs of one
    // slot is the claims', not the test's.
    *w.realms.lock().unwrap() = vec!["default".to_string(), "gone".to_string()];
    let count = Arc::new(AtomicUsize::new(0));
    let realms_seen = Arc::new(Mutex::new(Vec::new()));
    let seen = realms_seen.clone();
    let s = node(&w, false);
    let mut spec = job(
        "test.per-realm",
        Schedule::Every(Arc::new(|| 60_000.0)),
        &count,
        move |_| {
            let seen = seen.clone();
            // The realm is ambient while the run is polled.
            Box::pin(async move {
                seen.lock().unwrap().push(sts_core::realm::current_id());
                Ok(Json::Null)
            })
        },
    );
    spec.scope = Scope::Realm;
    s.register(spec).unwrap();
    lead(&s).await;
    s.tick().await;
    settle(&s).await;
    w.realms.lock().unwrap().retain(|r| r != "gone");
    assert_eq!(s.forget_realm("gone"), 0);
    w.advance(60_000.0);
    s.tick().await;
    settle(&s).await;
    assert_eq!(count.load(Ordering::SeqCst), 3);
    assert_eq!(
        w.runs("gone", "test.per-realm").len(),
        1,
        "nothing after the removal"
    );
    let mut seen = realms_seen.lock().unwrap().clone();
    seen.sort();
    assert_eq!(seen, ["default", "default", "gone"]);
}

#[tokio::test(start_paused = true)]
async fn a_step_down_is_obeyed_at_the_next_tick() {
    let w = World::new();
    let count = Arc::new(AtomicUsize::new(0));
    let s = node(&w, false);
    s.register(ok_job("test.job", 60_000.0, &count)).unwrap();
    lead(&s).await;
    let answer = s.request_step_down("bob", "/admin/scheduler").unwrap();
    assert!(answer["command"].as_str().unwrap().starts_with("command|"));
    s.tick().await;
    settle(&s).await;
    assert_eq!(w.step_downs.load(Ordering::SeqCst), 1);
    // The tick that obeyed it started nothing; the lease itself goes when
    // the cluster takes it, which this stand-in never does.
    assert!(w
        .audits
        .lock()
        .unwrap()
        .iter()
        .any(|a| a["action"] == "scheduler.step-down"));
    let command = w
        .rows_of("default")
        .into_iter()
        .find(|r| r["kind"] == "command")
        .unwrap();
    assert_eq!(command["state"], "succeeded");
}
