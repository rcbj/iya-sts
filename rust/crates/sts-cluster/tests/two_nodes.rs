// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Two PROCESSES on one PostgreSQL store, through the store's own driver and
//! Node's schema (`postgres/schema.sql`), named by `STS_TEST_DATABASE_URL`
//! (unset: this test says so and passes). The test re-runs its own binary
//! twice as two nodes, each joining the cluster, campaigning for the
//! scheduler's lease and running one cluster job every second whose body
//! records `(slot, node)` as a claim row. It shows:
//!
//! * exactly one node leads, and every slot of the job runs on exactly one
//!   node — the leader — while both are up;
//! * when the leader is KILLED (no clean stop: its rows simply expire by the
//!   database's clock), the other takes the lease at the next token within a
//!   lifetime, and the job's slots run there, still once each;
//! * a socket, a timer or a listener belongs to one process: each node's
//!   heartbeat and scheduler loop are its own, and only rows in the store are
//!   shared.

#![allow(clippy::unwrap_used)] // a test file

use std::collections::{BTreeMap, HashMap};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use indexmap::IndexMap;
use serde_json::{json, Value as Json};
use sts_cluster::membership::{ClaimAnswer, ClusterNode, ClusterStore};
use sts_cluster::schedule::{JobSpec, Schedule, SchedulerSettings, Schedules};
use sts_cluster::scheduler::{Audit, Deps, Realms, RunRows, Scheduler};
use sts_core::realm::Realm;
use sts_store::postgres::PostgresDriver;

const JOB: &str = "two.nodes";
const RAN: &str = "two-nodes.ran";
const HEARTBEAT_MS: f64 = 250.0;
const TTL_MS: f64 = 1500.0;

struct Settings;
impl SchedulerSettings for Settings {
    fn number(&self, key: &str) -> f64 {
        match key {
            "scheduler.tickS" => 1.0,
            "scheduler.maxConcurrentRuns" => 4.0,
            "scheduler.runTimeoutS" => 30.0,
            "scheduler.runHistoryCount" => 50.0,
            "scheduler.runHistoryHours" => 1.0,
            _ => 0.0,
        }
    }
    fn flag(&self, key: &str) -> bool {
        key == "scheduler.enabled"
    }
    fn list(&self, _: &str) -> Vec<String> {
        Vec::new()
    }
}

/// Each process's own run rows: what is shared is the lease and the claims.
#[derive(Default)]
struct Rows(Mutex<IndexMap<String, IndexMap<String, Json>>>);
impl RunRows for Rows {
    fn get(&self, realm: &str, key: &str) -> Option<Json> {
        self.0.lock().unwrap().get(realm)?.get(key).cloned()
    }
    fn set(&self, realm: &str, key: &str, row: Json) {
        self.0
            .lock()
            .unwrap()
            .entry(realm.to_string())
            .or_default()
            .insert(key.to_string(), row);
    }
    fn rows(&self, realm: &str) -> Vec<Json> {
        self.0
            .lock()
            .unwrap()
            .get(realm)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }
    fn delete(&self, realm: &str, key: &str) {
        if let Some(m) = self.0.lock().unwrap().get_mut(realm) {
            m.shift_remove(key);
        }
    }
}

struct OneRealm;
impl Realms for OneRealm {
    fn ids(&self) -> Vec<String> {
        vec!["default".to_string()]
    }
    fn get(&self, id: &str) -> Option<Arc<Realm>> {
        (id == "default").then(|| Arc::new(Realm::default_realm()))
    }
}

struct NoAudit;
impl Audit for NoAudit {
    fn record(&self, _: Json) {}
}

fn url() -> Option<String> {
    std::env::var("STS_TEST_DATABASE_URL").ok()
}

/// ONE NODE, run as its own process by the parent test below. Runs until
/// it is killed.
#[test]
#[ignore = "a node process the two-node test starts; not a test by itself"]
fn node_process() {
    let (Some(url), Ok(id)) = (url(), std::env::var("TWO_NODES_ID")) else {
        return;
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        let driver = Arc::new(PostgresDriver::new(&url, false, 4).unwrap());
        let node = ClusterNode::new(
            driver.clone(),
            &id,
            &format!("node-{}", id),
            HEARTBEAT_MS,
            TTL_MS,
            Arc::new(|code, why| {
                eprintln!("node stops: {} {}", code, why);
                std::process::exit(3);
            }),
        );
        node.join().await.unwrap();
        let mut schedules = Schedules::new(Arc::new(Settings));
        let mut job = JobSpec::new(
            JOB,
            "Two nodes",
            "Records which node ran each second's slot.",
            "sts-cluster/tests/two_nodes.rs",
            Schedule::Every(Arc::new(|| 1000.0)),
        );
        let (store, me) = (driver.clone(), id.clone());
        job.run = Some(Arc::new(move |ctx| {
            let (store, me) = (store.clone(), me.clone());
            Box::pin(async move {
                let slot = ((ctx.now_ms)() / 1000.0).floor() as i64;
                store
                    .claim_once(
                        RAN,
                        "",
                        &format!("{}|{}", slot, me),
                        600_000.0,
                        "r",
                        &me,
                    )
                    .await?;
                Ok(json!({ "slot": slot }))
            })
        }));
        schedules.register(job).unwrap();
        let scheduler = Scheduler::new(
            schedules,
            Deps {
                cluster: node.clone(),
                claims: node.clone(),
                rows: Arc::new(Rows::default()),
                realms: Arc::new(OneRealm),
                audit: Arc::new(NoAudit),
                clock: node.clone(),
                host: "two-nodes".to_string(),
                pid: std::process::id(),
                thread: None,
                is_request_worker: false,
            },
        );
        scheduler.start(false);
        std::future::pending::<()>().await;
    });
}

struct Killed(Child);
impl Drop for Killed {
    fn drop(&mut self) {
        let _killed = self.0.kill().is_ok();
        let _reaped = self.0.wait().is_ok();
    }
}

fn spawn(id: &str) -> Killed {
    let me = std::env::current_exe().unwrap();
    Killed(
        Command::new(me)
            .args(["node_process", "--exact", "--ignored", "--nocapture"])
            .env("TWO_NODES_ID", id)
            .spawn()
            .unwrap(),
    )
}

/// The scheduler's lease as the store holds it: asked by a non-member,
/// which is never granted it and is told who holds it at which token.
async fn leader(store: &PostgresDriver) -> (String, u64) {
    let a = store
        .acquire_lease("ops.scheduler", "observer", 1000.0)
        .await
        .unwrap();
    assert!(!a.held);
    (a.holder, a.token)
}

/// Which nodes ran each slot in `[from, to)`.
async fn ran(
    store: &PostgresDriver,
    nodes: &[&str],
    from: i64,
    to: i64,
) -> BTreeMap<i64, Vec<String>> {
    let mut out = BTreeMap::new();
    for slot in from..to {
        let mut by = Vec::new();
        for n in nodes {
            let key = format!("{}|{}", slot, n);
            // A probe claim: Used when the node recorded the slot. One that
            // was not recorded is claimed by the probe (origin "probe"),
            // which a later probe also reads as Used — told apart by origin.
            match store
                .claim_once(RAN, "", &key, 600_000.0, "p", "probe")
                .await
                .unwrap()
            {
                ClaimAnswer::Used { origin, .. } if origin == *n => {
                    by.push(n.to_string())
                }
                _ => {}
            }
        }
        out.insert(slot, by);
    }
    out
}

async fn db_second(store: &PostgresDriver) -> i64 {
    (store.now().await.unwrap() / 1000.0).floor() as i64
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_job_runs_on_exactly_one_of_two_nodes_and_moves_when_it_dies() {
    let Some(url) = url() else {
        eprintln!("STS_TEST_DATABASE_URL is not set; nothing to run against");
        return;
    };
    let store = PostgresDriver::new(&url, false, 2).unwrap();
    // Distinct node ids per run, so an earlier run's rows cannot answer.
    let tag = format!("{}", std::process::id());
    let (a_id, b_id) = (format!("a{}", tag), format!("b{}", tag));
    let a = spawn(&a_id);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let b = spawn(&b_id);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let (holder, token_a) = leader(&store).await;
    assert_eq!(holder, a_id, "the first node up leads");
    let from = db_second(&store).await;
    tokio::time::sleep(Duration::from_millis(4000)).await;
    let to = db_second(&store).await;
    let both = ran(&store, &[&a_id, &b_id], from, to).await;
    eprintln!("both up: {:?}", both);
    let mut per_node: HashMap<String, usize> = HashMap::new();
    for (slot, by) in &both {
        assert!(by.len() <= 1, "slot {} ran on {:?}", slot, by);
        for n in by {
            *per_node.entry(n.clone()).or_default() += 1;
        }
    }
    assert!(per_node.get(&a_id).copied().unwrap_or(0) >= 2, "{:?}", both);
    assert_eq!(per_node.get(&b_id), None, "the standby ran nothing");

    // The leader dies without a word; its rows expire by the database's
    // clock and B takes the lease at the next token.
    drop(a);
    tokio::time::sleep(Duration::from_millis(3000)).await;
    let (holder, token_b) = leader(&store).await;
    assert_eq!(holder, b_id, "the lease moved");
    assert!(
        token_b > token_a,
        "the token moved on: {} {}",
        token_a,
        token_b
    );
    let from = db_second(&store).await;
    tokio::time::sleep(Duration::from_millis(4000)).await;
    let to = db_second(&store).await;
    let after = ran(&store, &[&a_id, &b_id], from, to).await;
    eprintln!("after the leader died: {:?}", after);
    let mut b_ran = 0;
    for (slot, by) in &after {
        assert!(by.len() <= 1, "slot {} ran on {:?}", slot, by);
        assert!(!by.contains(&a_id), "a dead node ran slot {}", slot);
        b_ran += by.len();
    }
    assert!(b_ran >= 2, "the job moved: {:?}", after);
    drop(b);
}
