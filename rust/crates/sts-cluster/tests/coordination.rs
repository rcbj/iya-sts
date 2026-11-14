// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The guarantees the Node worker pool gave, held in a runtime with no pool
//! (`sts_cluster::coordination`; rust/DESIGN.md, *The concurrency model*).
//! Each test names what breaking the rule does to it:
//!
//! * a pull that started BEFORE a reader arrived does not prove it (the
//!   reader would read a copy missing a row committed just before it);
//! * one pull serves every reader that arrived before it started;
//! * a pull that did not catch up never counts, and a reader whose bound ran
//!   out is REFUSED with STS-WORKER-0053 — never served stale (develop's
//!   057998e08: the two ways Node answered stale);
//! * a request that wrote is held for its commit, refused STS-STORE-0066
//!   when the commit fails, and one that wrote nothing is not held;
//! * read-your-write across two processes on one store holds with both
//!   rules and fails without either (the controls, as cluster/CLAUDE.md's
//!   *Run the off control before believing a probe*);
//! * several processes on one store without coordination are refused.

#![allow(clippy::unwrap_used)] // a test file

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sts_cluster::coordination::{
    ChangePull, CommitGate, CommitLog, ReadBarrier, Topology,
};
use sts_cluster::schedule::BoxFuture;
use sts_core::errors::codes;
use tokio::sync::Notify;

/// One store's change log: committed rows, in order.
#[derive(Default)]
struct Store {
    rows: Mutex<Vec<(String, String)>>,
}

/// One process: its own copy, and how far into the store's log it is.
struct Process {
    store: Arc<Store>,
    copy: Mutex<HashMap<String, String>>,
    applied: AtomicU64,
    pulls: AtomicU64,
    /// How long a pull takes after it has read its page.
    apply_ms: u64,
    /// Answers "not caught up" whatever it applied.
    gives_up: bool,
    /// Writes not yet committed, and the position every write moves.
    pending: Mutex<Vec<(String, String)>>,
    position: AtomicU64,
    committed: AtomicU64,
    committed_now: Notify,
    commit_ms: u64,
    commit_fails: bool,
}

impl Process {
    fn new(store: &Arc<Store>) -> Arc<Process> {
        Process::with(store, 0, false, 0, false)
    }
    fn with(
        store: &Arc<Store>,
        apply_ms: u64,
        gives_up: bool,
        commit_ms: u64,
        commit_fails: bool,
    ) -> Arc<Process> {
        Arc::new(Process {
            store: store.clone(),
            copy: Mutex::new(HashMap::new()),
            applied: AtomicU64::new(0),
            pulls: AtomicU64::new(0),
            apply_ms,
            gives_up,
            pending: Mutex::new(Vec::new()),
            position: AtomicU64::new(0),
            committed: AtomicU64::new(0),
            committed_now: Notify::new(),
            commit_ms,
            commit_fails,
        })
    }

    /// A handler's write: into this process's copy at once, and committed
    /// to the store by a flush that lands `commit_ms` later.
    fn write(self: &Arc<Self>, k: &str, v: &str) {
        self.copy.lock().unwrap().insert(k.into(), v.into());
        self.pending.lock().unwrap().push((k.into(), v.into()));
        let at = self.position.fetch_add(1, Ordering::SeqCst) + 1;
        let me = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(me.commit_ms)).await;
            if me.commit_fails {
                me.committed_now.notify_waiters();
                return;
            }
            let rows: Vec<_> = me.pending.lock().unwrap().drain(..).collect();
            me.store.rows.lock().unwrap().extend(rows);
            me.committed.fetch_max(at, Ordering::SeqCst);
            me.committed_now.notify_waiters();
        });
    }

    fn read(&self, k: &str) -> Option<String> {
        self.copy.lock().unwrap().get(k).cloned()
    }
}

impl ChangePull for Process {
    fn pull(&self) -> BoxFuture<'_, Result<bool, String>> {
        Box::pin(async move {
            self.pulls.fetch_add(1, Ordering::SeqCst);
            // The page is read when the pull starts: a row committed after
            // this line is not in it.
            let page: Vec<_> = self.store.rows.lock().unwrap().clone();
            tokio::time::sleep(Duration::from_millis(self.apply_ms)).await;
            let mut copy = self.copy.lock().unwrap();
            for (k, v) in &page {
                copy.insert(k.clone(), v.clone());
            }
            self.applied.store(page.len() as u64, Ordering::SeqCst);
            Ok(!self.gives_up)
        })
    }
}

impl CommitLog for Process {
    fn position(&self) -> u64 {
        self.position.load(Ordering::SeqCst)
    }
    fn through(&self, position: u64) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            loop {
                let woken = self.committed_now.notified();
                tokio::pin!(woken);
                woken.as_mut().enable();
                if self.committed.load(Ordering::SeqCst) >= position {
                    return Ok(());
                }
                if self.commit_fails && self.pending.lock().unwrap().len() > 0 {
                    woken.await;
                    return Err("the store refused the commit".to_string());
                }
                woken.await;
            }
        })
    }
}

fn barrier(p: &Arc<Process>, bound_ms: f64) -> Arc<ReadBarrier> {
    ReadBarrier::new(p.clone(), Arc::new(move || bound_ms))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pull_that_started_before_the_reader_does_not_prove_it() {
    let store = Arc::new(Store::default());
    let b = Process::with(&store, 200, false, 0, false);
    let rb = barrier(&b, 5000.0);
    // A pull is running: started by an earlier reader, its page read.
    let early = {
        let rb = rb.clone();
        tokio::spawn(async move { rb.wait().await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    // Another process commits, and THEN this reader arrives.
    store
        .rows
        .lock()
        .unwrap()
        .push(("realm".into(), "acme".into()));
    rb.wait().await.unwrap();
    assert_eq!(
        b.read("realm").as_deref(),
        Some("acme"),
        "a reader was answered by a pull that started before it arrived"
    );
    early.await.unwrap().unwrap();
    assert_eq!(b.pulls.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_pull_serves_every_reader_that_arrived_before_it_started() {
    let store = Arc::new(Store::default());
    let b = Process::with(&store, 100, false, 0, false);
    let rb = barrier(&b, 5000.0);
    let mut all = Vec::new();
    for _ in 0..50 {
        let rb = rb.clone();
        all.push(tokio::spawn(async move { rb.wait().await }));
    }
    for one in all {
        one.await.unwrap().unwrap();
    }
    // The first reader's pull, and at most one queued behind it for every
    // reader that arrived while it ran: two, however many readers.
    assert!(b.pulls.load(Ordering::SeqCst) <= 2, "{:?}", rb.stats());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pull_that_did_not_catch_up_never_counts_and_the_reader_is_refused() {
    let store = Arc::new(Store::default());
    store
        .rows
        .lock()
        .unwrap()
        .push(("scope".into(), "declared".into()));
    let b = Process::with(&store, 0, true, 0, false);
    let rb = barrier(&b, 1000.0);
    let refused = rb.wait().await.unwrap_err();
    assert_eq!(refused.code, codes::STS_WORKER_0053);
    assert!(refused.waited_ms >= 1000.0);
    assert!(refused.rounds_missed >= 2, "{:?}", refused);
    // Spaced, not a tight loop: about one round per 250 ms.
    assert!(b.pulls.load(Ordering::SeqCst) <= 6, "{:?}", rb.stats());
    assert_eq!(rb.stats().refused, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pull_slower_than_the_bound_is_a_refusal_not_a_stale_answer() {
    let store = Arc::new(Store::default());
    let b = Process::with(&store, 3000, false, 0, false);
    let rb = barrier(&b, 1000.0);
    store
        .rows
        .lock()
        .unwrap()
        .push(("realm".into(), "acme".into()));
    let began = std::time::Instant::now();
    let refused = rb.wait().await.unwrap_err();
    assert_eq!(refused.code, codes::STS_WORKER_0053);
    assert!(began.elapsed() < Duration::from_millis(2500));
    assert_eq!(b.read("realm"), None, "nothing was answered from it");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bound_of_zero_is_the_default_not_never_wait() {
    let store = Arc::new(Store::default());
    let b = Process::with(&store, 300, false, 0, false);
    let rb = barrier(&b, 0.0);
    store.rows.lock().unwrap().push(("k".into(), "v".into()));
    rb.wait().await.unwrap();
    assert_eq!(b.read("k").as_deref(), Some("v"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_write_is_held_for_its_commit_and_a_failed_commit_is_refused() {
    let store = Arc::new(Store::default());
    let a = Process::with(&store, 0, false, 150, false);
    let gate = CommitGate::new(a.clone());
    // Nothing written: answered at once.
    let before = gate.mark();
    let began = std::time::Instant::now();
    gate.hold(before).await.unwrap();
    assert!(began.elapsed() < Duration::from_millis(50));
    // Written: held until the store has it.
    let before = gate.mark();
    a.write("user", "alice");
    gate.hold(before).await.unwrap();
    assert_eq!(store.rows.lock().unwrap().len(), 1);
    // A commit that fails is a refusal, not the handler's success.
    let bad = Process::with(&store, 0, false, 50, true);
    let gate = CommitGate::new(bad.clone());
    let before = gate.mark();
    bad.write("user", "bob");
    let refused = gate.hold(before).await.unwrap_err();
    assert_eq!(refused.code, codes::STS_STORE_0066);
}

/// What one request does on node B straight after node A answered a write.
async fn cross_node(hold_on_a: bool, barrier_on_b: bool) -> Option<String> {
    let store = Arc::new(Store::default());
    let a = Process::with(&store, 0, false, 100, false);
    let b = Process::with(&store, 20, false, 0, false);
    let gate = CommitGate::new(a.clone());
    let rb = barrier(&b, 5000.0);
    // B pulled once before, as the change-log job would have.
    rb.wait().await.unwrap();
    // A's request: write, and answer.
    let before = gate.mark();
    a.write("realm", "acme");
    if hold_on_a {
        gate.hold(before).await.unwrap();
    }
    // The client is answered and its next request lands on B.
    if barrier_on_b {
        rb.wait().await.unwrap();
    }
    b.read("realm")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_your_write_across_two_processes_needs_both_rules() {
    assert_eq!(cross_node(true, true).await.as_deref(), Some("acme"));
    // The controls: without either rule the probe sees the old copy, so it
    // measures what it claims to.
    assert_eq!(
        cross_node(false, true).await,
        None,
        "answered before commit"
    );
    assert_eq!(cross_node(true, false).await, None, "read without a pull");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_your_write_inside_one_process_holds_by_construction() {
    // One process, one copy: the write a handler made is in the copy the
    // next request reads, whichever task or thread serves it.
    let store = Arc::new(Store::default());
    let p = Process::new(&store);
    for i in 0..200 {
        let (k, v) = (format!("k{}", i), format!("v{}", i));
        let w = p.clone();
        let (k2, v2) = (k.clone(), v.clone());
        tokio::spawn(async move { w.write(&k2, &v2) })
            .await
            .unwrap();
        let r = p.clone();
        let got = tokio::spawn(async move { r.read(&k) }).await.unwrap();
        assert_eq!(got.as_deref(), Some(v.as_str()));
    }
}

#[test]
fn several_processes_on_a_store_that_does_not_coordinate_are_refused() {
    let refused = Topology {
        several: true,
        coordinates: false,
    }
    .check()
    .unwrap_err();
    assert_eq!(refused.code, codes::STS_WORKER_0024);
    assert!(Topology {
        several: true,
        coordinates: true
    }
    .check()
    .is_ok());
    assert!(Topology {
        several: false,
        coordinates: false
    }
    .check()
    .is_ok());
}
