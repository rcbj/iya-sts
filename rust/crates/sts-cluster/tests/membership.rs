// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Several nodes against one store, each rule `cluster/cluster.js` and
//! `cluster/cluster_claims.js` state: one node leads, the lease moves to
//! another when the leader's membership lapses and its token moves on; the
//! old leader, renewing late, stops rather than coming back; a lease taken
//! away is noticed and its role told; standing down hands over and holds
//! off; a store that cannot be reached for a lifetime stops the node; and a
//! claim is single-use, released only by its holder.

#![allow(clippy::unwrap_used)] // a test file

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sts_cluster::membership::{ClusterNode, ClusterStore, MemoryClusterStore};
use sts_cluster::scheduler::{ClaimRefused, Claims, Cluster, LeaseHandler};

#[derive(Default)]
struct Role {
    gains: Mutex<Vec<u64>>,
    loses: AtomicU64,
}

impl LeaseHandler for Role {
    fn on_gain(&self, token: u64) {
        self.gains.lock().unwrap().push(token);
    }
    fn on_lose(&self) {
        self.loses.fetch_add(1, Ordering::SeqCst);
    }
}

struct World {
    store: Arc<MemoryClusterStore>,
    stops: Arc<Mutex<Vec<String>>>,
}

fn world() -> World {
    let start = tokio::time::Instant::now();
    let store = MemoryClusterStore::new(Arc::new(move || {
        1_800_000_000_000.0 + start.elapsed().as_millis() as f64
    }));
    World {
        store,
        stops: Arc::new(Mutex::new(Vec::new())),
    }
}

fn node(w: &World, id: &str) -> Arc<ClusterNode> {
    let stops = w.stops.clone();
    let id_owned = id.to_string();
    ClusterNode::new(
        w.store.clone(),
        id,
        &format!("node-{}", id),
        1000.0,
        3000.0,
        Arc::new(move |code, _why| {
            stops.lock().unwrap().push(format!("{}:{}", id_owned, code))
        }),
    )
}

async fn settle() {
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn the_lease_moves_when_the_leader_lapses_and_the_old_leader_stops() {
    let w = world();
    let (a, b) = (node(&w, "a"), node(&w, "b"));
    a.join().await.unwrap();
    b.join().await.unwrap();
    let (ra, rb) = (Arc::new(Role::default()), Arc::new(Role::default()));
    a.lead("ops.scheduler", ra.clone());
    settle().await;
    b.lead("ops.scheduler", rb.clone());
    settle().await;
    assert_eq!(*ra.gains.lock().unwrap(), vec![1]);
    assert!(rb.gains.lock().unwrap().is_empty(), "one leader");
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(
        a.holds("ops.scheduler") && !b.holds("ops.scheduler"),
        "renewed by the heartbeat"
    );

    // A stops beating; past its lifetime, B's next beat takes the lease at
    // the next token.
    a.halt_heartbeat_for_tests();
    tokio::time::sleep(Duration::from_millis(4000)).await;
    assert_eq!(*rb.gains.lock().unwrap(), vec![2]);
    // A, renewing late, finds its row expired and stops.
    a.beat().await;
    assert!(a.stopped());
    assert_eq!(*w.stops.lock().unwrap(), vec!["a:STS-CLUSTER-0005"]);
}

#[tokio::test(start_paused = true)]
async fn a_lease_taken_away_is_noticed() {
    let w = world();
    let (a, b) = (node(&w, "a"), node(&w, "b"));
    a.join().await.unwrap();
    b.join().await.unwrap();
    let role = Arc::new(Role::default());
    a.lead("ops.x", role.clone());
    settle().await;
    let token = a.token_of("ops.x").unwrap();
    assert!(w.store.release_lease("ops.x", "a", token).await.unwrap());
    assert!(b.acquire("ops.x").await.held);
    a.beat().await;
    assert_eq!(role.loses.load(Ordering::SeqCst), 1);
    assert!(!a.holds("ops.x"));
}

#[tokio::test(start_paused = true)]
async fn standing_down_hands_over_and_holds_off() {
    let w = world();
    let (a, b) = (node(&w, "a"), node(&w, "b"));
    a.join().await.unwrap();
    b.join().await.unwrap();
    let (ra, rb) = (Arc::new(Role::default()), Arc::new(Role::default()));
    a.lead("ops.scheduler", ra.clone());
    settle().await;
    b.lead("ops.scheduler", rb.clone());
    settle().await;
    a.step_down("ops.scheduler").await.unwrap();
    assert_eq!(ra.loses.load(Ordering::SeqCst), 1);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(
        *rb.gains.lock().unwrap(),
        vec![2],
        "B took it at the next token"
    );
    assert!(!a.holds("ops.scheduler"));
    assert!(
        a.step_down("ops.scheduler").await.is_err(),
        "not held any more"
    );
}

#[tokio::test(start_paused = true)]
async fn a_store_out_of_reach_for_a_lifetime_stops_the_node() {
    let w = world();
    let a = node(&w, "a");
    a.join().await.unwrap();
    w.store.fail_with(Some("connection refused"));
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(!a.stopped(), "one failure is a warning");
    tokio::time::sleep(Duration::from_millis(2000)).await;
    assert!(a.stopped());
    assert_eq!(*w.stops.lock().unwrap(), vec!["a:STS-CLUSTER-0004"]);
}

#[tokio::test(start_paused = true)]
async fn a_claim_is_single_use_and_released_only_by_its_holder() {
    let w = world();
    let (a, b) = (node(&w, "a"), node(&w, "b"));
    a.join().await.unwrap();
    b.join().await.unwrap();
    let first = a
        .claim("scheduler.run", "s-abc", "default", 5000.0)
        .await
        .unwrap();
    assert!(matches!(
        b.claim("scheduler.run", "s-abc", "default", 5000.0).await,
        Err(ClaimRefused::Held)
    ));
    assert!(
        b.claim("scheduler.run", "s-abc", "acme", 5000.0)
            .await
            .is_ok(),
        "another realm's value"
    );
    // B cannot release A's claim with a handle of its own making.
    let mut forged = first.handle.clone();
    forged["reservation"] = serde_json::json!("not-yours");
    b.release(&forged).await;
    assert!(b
        .claim("scheduler.run", "s-abc", "default", 5000.0)
        .await
        .is_err());
    a.release(&first.handle).await;
    assert!(b
        .claim("scheduler.run", "s-abc", "default", 5000.0)
        .await
        .is_ok());
    // A claim lapses with its lifetime (at least a second).
    let short = a.claim("t.once", "v", "", 10.0).await.unwrap();
    assert!(short.claimed_at > 0.0);
    tokio::time::sleep(Duration::from_millis(1001)).await;
    assert!(b.claim("t.once", "v", "", 10.0).await.is_ok());
    w.store.fail_with(Some("down"));
    assert!(matches!(
        a.claim("t.x", "v", "", 1000.0).await,
        Err(ClaimRefused::Store(_))
    ));
}

mod with_the_scheduler {
    use std::collections::HashMap;

    use indexmap::IndexMap;
    use serde_json::{json, Value as Json};
    use sts_cluster::schedule::{
        JobSpec, Schedule, SchedulerSettings, Schedules,
    };
    use sts_cluster::scheduler::{Audit, Deps, Realms, RunRows, Scheduler};
    use sts_core::realm::Realm;

    use super::*;

    struct Shared {
        rows: Mutex<HashMap<String, IndexMap<String, Json>>>,
    }

    impl RunRows for Shared {
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
    }

    struct Fixed;

    impl SchedulerSettings for Fixed {
        fn number(&self, key: &str) -> f64 {
            match key {
                "scheduler.tickS" => 15.0,
                "scheduler.maxConcurrentRuns" => 4.0,
                "scheduler.runTimeoutS" => 30.0,
                _ => 0.0,
            }
        }
        fn flag(&self, _: &str) -> bool {
            true
        }
        fn list(&self, _: &str) -> Vec<String> {
            Vec::new()
        }
    }

    struct OneRealm;

    impl Realms for OneRealm {
        fn ids(&self) -> Vec<String> {
            vec!["default".to_string()]
        }
        fn get(&self, _: &str) -> Option<Arc<Realm>> {
            Some(Arc::new(Realm::default_realm()))
        }
    }

    struct Quiet;

    impl Audit for Quiet {
        fn record(&self, _: Json) {}
    }

    fn scheduler(
        node: &Arc<ClusterNode>,
        rows: &Arc<Shared>,
        runs: &Arc<Mutex<Vec<String>>>,
    ) -> Arc<Scheduler> {
        let s = Scheduler::new(
            Schedules::new(Arc::new(Fixed)),
            Deps {
                cluster: node.clone(),
                claims: node.clone(),
                rows: rows.clone(),
                realms: Arc::new(OneRealm),
                audit: Arc::new(Quiet),
                clock: node.clone(),
                host: "h".to_string(),
                pid: 1,
                thread: None,
                is_request_worker: false,
            },
        );
        let runs = runs.clone();
        let who = node.node_id();
        let mut spec = JobSpec::new(
            "test.minute",
            "T",
            "D",
            "O",
            Schedule::Every(Arc::new(|| 60_000.0)),
        );
        spec.run = Some(Arc::new(move |ctx| {
            runs.lock().unwrap().push(format!("{}@{}", who, ctx.run_id));
            Box::pin(async { Ok(json!(null)) })
        }));
        s.register(spec).unwrap();
        s
    }

    #[tokio::test(start_paused = true)]
    async fn each_slot_runs_once_across_a_failover() {
        let w = world();
        let (a, b) = (node(&w, "a"), node(&w, "b"));
        a.join().await.unwrap();
        b.join().await.unwrap();
        let rows = Arc::new(Shared {
            rows: Mutex::new(HashMap::new()),
        });
        let runs = Arc::new(Mutex::new(Vec::new()));
        let (sa, sb) =
            (scheduler(&a, &rows, &runs), scheduler(&b, &rows, &runs));
        assert!(sa.start(false));
        settle().await;
        assert!(sb.start(false));
        tokio::time::sleep(Duration::from_secs(185)).await;
        // A crashed process: no heartbeat, no tick.
        a.halt_heartbeat_for_tests();
        sa.stop();
        tokio::time::sleep(Duration::from_secs(240)).await;
        let runs = runs.lock().unwrap().clone();
        let mut ids: Vec<&str> =
            runs.iter().map(|r| r.split('@').nth(1).unwrap()).collect();
        let total = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), total, "no slot ran twice: {:?}", runs);
        assert!(
            runs.iter().any(|r| r.starts_with("a@"))
                && runs.iter().any(|r| r.starts_with("b@")),
            "{:?}",
            runs
        );
        assert!(
            total >= 6,
            "a run per minute through the failover: {:?}",
            runs
        );
    }
}
