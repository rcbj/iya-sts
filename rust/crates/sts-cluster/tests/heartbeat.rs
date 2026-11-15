// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The heartbeat's time limit and what it is kept apart from
//! (`cluster/cluster.js` since #770 and its review), the active-passive
//! service lease, the fence a lease-guarded write carries, and `resolve()`'s
//! refusals:
//!
//! * a renewal that hangs is a beat that did not land (STS-CLUSTER-0003) and,
//!   past the lifetime, a node that stops (STS-CLUSTER-0004) — never a node
//!   that waits for ever;
//! * a takeover that waits on the old holder does not hold the heartbeat: the
//!   membership is renewed meanwhile and the node stays up;
//! * the service lease lost in active-passive mode stops the node
//!   (STS-CLUSTER-0006); in active-active a role's loss does not;
//! * `with_lease` adds its token to the fence, and a fenced role write fails
//!   the operation only.

#![allow(clippy::unwrap_used)] // a test file

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value as Json;
use sts_cluster::membership::{
    resolve_mode, ClaimAnswer, ClusterMode, ClusterNode, ClusterStore,
    FenceReason, LeaseAnswer, MemoryClusterStore, ModeSettings, Renewal,
    SERVICE_LEASE,
};
use sts_cluster::schedule::BoxFuture;
use sts_cluster::scheduler::{Cluster, LeaseHandler};
use sts_core::errors::codes;

/// The memory store, with a heartbeat or an acquire that can be made to
/// hang as a statement waiting on a lock would.
struct Hanging {
    inner: Arc<MemoryClusterStore>,
    hang_heartbeat: AtomicBool,
    hang_acquire: AtomicBool,
}

fn never<T: Send + 'static>() -> BoxFuture<'static, T> {
    Box::pin(std::future::pending())
}

impl ClusterStore for Hanging {
    fn now(&self) -> BoxFuture<'_, Result<f64, String>> {
        self.inner.now()
    }
    fn join(
        &self,
        n: &str,
        t: f64,
        i: Json,
    ) -> BoxFuture<'_, Result<(), String>> {
        self.inner.join(n, t, i)
    }
    fn heartbeat(
        &self,
        n: &str,
        t: f64,
    ) -> BoxFuture<'_, Result<Renewal, String>> {
        if self.hang_heartbeat.load(Ordering::SeqCst) {
            return never();
        }
        self.inner.heartbeat(n, t)
    }
    fn acquire_lease(
        &self,
        l: &str,
        n: &str,
        t: f64,
    ) -> BoxFuture<'_, Result<LeaseAnswer, String>> {
        if self.hang_acquire.load(Ordering::SeqCst) {
            return never();
        }
        self.inner.acquire_lease(l, n, t)
    }
    fn release_lease(
        &self,
        l: &str,
        n: &str,
        t: u64,
    ) -> BoxFuture<'_, Result<bool, String>> {
        self.inner.release_lease(l, n, t)
    }
    fn leave(&self, n: &str) -> BoxFuture<'_, Result<(), String>> {
        self.inner.leave(n)
    }
    fn claim_once(
        &self,
        s: &str,
        r: &str,
        k: &str,
        t: f64,
        v: &str,
        o: &str,
    ) -> BoxFuture<'_, Result<ClaimAnswer, String>> {
        self.inner.claim_once(s, r, k, t, v, o)
    }
    fn release_claim(
        &self,
        s: &str,
        r: &str,
        k: &str,
        v: &str,
    ) -> BoxFuture<'_, Result<bool, String>> {
        self.inner.release_claim(s, r, k, v)
    }
}

struct Nothing;
impl LeaseHandler for Nothing {
    fn on_gain(&self, _: u64) {}
    fn on_lose(&self) {}
}

fn setup() -> (Arc<Hanging>, Arc<Mutex<Vec<String>>>) {
    let start = tokio::time::Instant::now();
    let inner = MemoryClusterStore::new(Arc::new(move || {
        1_800_000_000_000.0 + start.elapsed().as_millis() as f64
    }));
    (
        Arc::new(Hanging {
            inner,
            hang_heartbeat: AtomicBool::new(false),
            hang_acquire: AtomicBool::new(false),
        }),
        Arc::new(Mutex::new(Vec::new())),
    )
}

fn node(
    store: &Arc<Hanging>,
    stops: &Arc<Mutex<Vec<String>>>,
    id: &str,
) -> Arc<ClusterNode> {
    let stops = stops.clone();
    ClusterNode::new(
        store.clone(),
        id,
        id,
        1000.0,
        6000.0,
        Arc::new(move |code, _| stops.lock().unwrap().push(code.to_string())),
    )
}

#[tokio::test(start_paused = true)]
async fn a_renewal_that_hangs_stops_the_node_at_its_lifetime() {
    let (store, stops) = setup();
    let a = node(&store, &stops, "a");
    a.join().await.unwrap();
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(stops.lock().unwrap().is_empty());
    store.hang_heartbeat.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(3000)).await;
    assert!(!a.stopped(), "within its lifetime it only says so");
    tokio::time::sleep(Duration::from_millis(4000)).await;
    assert!(
        a.stopped(),
        "a hung renewal is not a node that waits for ever"
    );
    assert_eq!(*stops.lock().unwrap(), vec!["STS-CLUSTER-0004"]);
}

#[tokio::test(start_paused = true)]
async fn a_takeover_that_waits_does_not_hold_the_heartbeat() {
    let (store, stops) = setup();
    let a = node(&store, &stops, "a");
    a.join().await.unwrap();
    store.hang_acquire.store(true, Ordering::SeqCst);
    a.lead("ops.scheduler", Arc::new(Nothing));
    // Many lifetimes: every acquire hangs, and the membership is renewed
    // by beats that do not wait for it.
    tokio::time::sleep(Duration::from_millis(30_000)).await;
    assert!(!a.stopped(), "{:?}", stops.lock().unwrap());
    assert!(!a.holds("ops.scheduler"));
    store.hang_acquire.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(3000)).await;
    assert!(a.holds("ops.scheduler"), "asked again once it can answer");
}

#[tokio::test(start_paused = true)]
async fn the_service_lease_lost_in_active_passive_mode_stops_the_node() {
    let (store, stops) = setup();
    let (a, b) = (node(&store, &stops, "a"), node(&store, &stops, "b"));
    a.set_mode(ClusterMode::ActivePassive);
    a.join().await.unwrap();
    b.join().await.unwrap();
    assert!(a.acquire(SERVICE_LEASE).await.held);
    let fence = a.fence_for().unwrap();
    assert_eq!(fence.leases, vec![(SERVICE_LEASE.to_string(), 1)]);
    let token = a.token_of(SERVICE_LEASE).unwrap();
    store
        .inner
        .release_lease(SERVICE_LEASE, "a", token)
        .await
        .unwrap();
    assert!(b.acquire(SERVICE_LEASE).await.held);
    a.beat().await;
    assert_eq!(*stops.lock().unwrap(), vec!["STS-CLUSTER-0006"]);
}

#[tokio::test(start_paused = true)]
async fn a_standby_waits_for_the_service_lease_and_takes_it_on_release() {
    // `waitForServiceLease()`: the active node holds the lease at once; a
    // second waits, its membership renewed meanwhile, and becomes active
    // within a heartbeat of the first leaving.
    let (store, stops) = setup();
    let (a, b) = (node(&store, &stops, "a"), node(&store, &stops, "b"));
    a.set_mode(ClusterMode::ActivePassive);
    b.set_mode(ClusterMode::ActivePassive);
    a.join().await.unwrap();
    assert!(a.wait_for_service_lease().await.unwrap().held);
    b.join().await.unwrap();
    let waiting = {
        let b = b.clone();
        tokio::spawn(async move { b.wait_for_service_lease().await })
    };
    tokio::time::sleep(Duration::from_millis(20_000)).await;
    assert!(!waiting.is_finished(), "a standby while the lease is held");
    assert!(!b.stopped() && !b.holds(SERVICE_LEASE));
    a.leave().await.unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let answer = waiting.await.unwrap().unwrap();
    assert!(answer.held && b.holds(SERVICE_LEASE));
    assert!(
        stops.lock().unwrap().is_empty(),
        "{:?}",
        stops.lock().unwrap()
    );
}

#[tokio::test(start_paused = true)]
async fn a_lease_guarded_write_carries_its_token_and_fails_alone() {
    let (store, stops) = setup();
    let (a, b) = (node(&store, &stops, "a"), node(&store, &stops, "b"));
    assert!(a.fence_for().is_none(), "no fence before the join");
    a.join().await.unwrap();
    b.join().await.unwrap();
    let fence = a
        .with_lease("ops.rotate", async { a.fence_for().unwrap() })
        .await
        .unwrap();
    assert_eq!(fence.leases, vec![("ops.rotate".to_string(), 1)]);
    assert!(a.fence_for().unwrap().leases.is_empty(), "only inside it");
    // Another node holds it: the work is not run.
    assert_eq!(
        b.with_lease("ops.rotate", async { 1 }).await.unwrap_err(),
        "a"
    );
    a.when_fenced(FenceReason::Lease, &[("ops.rotate".to_string(), 1)], "lost");
    assert!(!a.stopped() && !a.holds("ops.rotate"));
    a.when_fenced(FenceReason::Node, &[], "dead");
    assert_eq!(*stops.lock().unwrap(), vec!["STS-CLUSTER-0011"]);
}

#[test]
fn the_mode_and_its_refusals_are_cluster_js_resolve() {
    let base = ModeSettings {
        cluster_mode: "auto".into(),
        persistence_mode: "postgres".into(),
        product: true,
        global_mode: "product".into(),
        keys_source: "auto".into(),
        public_base_url: "https://sts.example".into(),
        minted: true,
    };
    let mode = |f: &dyn Fn(&mut ModeSettings)| {
        let mut s = base.clone();
        f(&mut s);
        resolve_mode(&s).map(|(m, _)| m).map_err(|r| r.code)
    };
    assert_eq!(mode(&|_| {}), Ok(ClusterMode::ActivePassive));
    assert_eq!(mode(&|s| s.product = false), Ok(ClusterMode::Off));
    assert_eq!(
        mode(&|s| s.persistence_mode = "memory".into()),
        Ok(ClusterMode::Off)
    );
    assert_eq!(
        mode(&|s| {
            s.cluster_mode = "active-active".into();
            s.persistence_mode = "ldif".into();
        }),
        Err(codes::STS_CLUSTER_0007)
    );
    assert_eq!(
        mode(&|s| {
            s.cluster_mode = "active-active".into();
            s.product = false;
        }),
        Err(codes::STS_CLUSTER_0008)
    );
    assert_eq!(
        mode(&|s| {
            s.cluster_mode = "active-active".into();
            s.public_base_url = " ".into();
        }),
        Err(codes::STS_CLUSTER_0026)
    );
    assert_eq!(
        mode(&|s| {
            s.cluster_mode = "active-passive".into();
            s.minted = false;
        }),
        Err(codes::STS_CLUSTER_0040)
    );
    assert_eq!(
        mode(&|s| s.cluster_mode = "active-active".into()),
        Ok(ClusterMode::ActiveActive)
    );
}
