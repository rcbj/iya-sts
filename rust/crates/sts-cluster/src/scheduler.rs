// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The scheduler's runner (`cluster/scheduler.ts`, #49): one scheduler for
//! every periodic job, each job run on exactly one node.
//!
//! * **The leader is a lease, and a lease alone is not enough.** One front
//!   process holds `ops.scheduler` and only it looks for due cluster jobs.
//!   A lease can change hands while a run is in progress, so a run is ALSO
//!   claimed (scope `scheduler.run`, value the run's id, for the run's time
//!   limit) and the claim's database time is written on the run row as its
//!   FENCE. An outcome is written only while the row still carries that
//!   fence: a node that paused past its claim and wakes to report loses to
//!   the attempt that took over.
//! * **Never at registration, never in a standby, never a cluster job in a
//!   request worker.** Registering starts nothing; [`Scheduler::start`] is
//!   called once the service's state is restored, and in a request worker
//!   it runs per-process jobs only.
//! * **Everything the page says is in the store**: runs, the leader's own
//!   row, each process's latest per-process run and the queued commands are
//!   rows of the run store, so any process on any node reports the same.
//! * **At most `scheduler.maxConcurrentRuns` runs at once**, a person's Run
//!   now first and then scheduled runs oldest-due first; the rest are not
//!   claimed, so they are still due at the next tick, and a run that ends
//!   asks for that tick at once.
//! * **It never holds the thread**: a run past its time limit is recorded as
//!   failed and fenced out, and the scheduler does not wait on it.
//!
//! The history purge (#338) and the page's view of a run are later pieces.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Map, Value as Json};
use sts_core::errors::codes;
use sts_core::log::tag;
use sts_core::realm::{self, Realm, RealmRegistry, DEFAULT_ID};

use crate::schedule::{
    compare_rows, run_id_for, span, BoxFuture, JobSpec, Kind, RunContext,
    Schedules, Scope, Slot, FINAL, LEADER_LEASE, QUIET_RECORD_MS, RUN_SCOPE,
};

/// The store's key for the leader's own row.
pub const LEADER_KEY: &str = "leader";
pub const PROCESS_PREFIX: &str = "process|";
pub const COMMAND_PREFIX: &str = "command|";
/// How many (job, realm) pairs a tick asks about before it yields.
const TICK_YIELD_EVERY: usize = 50;

/// Called by the cluster when this process gains or loses a lease.
pub trait LeaseHandler: Send + Sync {
    fn on_gain(&self, token: u64);
    fn on_lose(&self);
}

/// The cluster as the scheduler sees it.
pub trait Cluster: Send + Sync {
    fn enabled(&self) -> bool;
    fn node_id(&self) -> String;
    fn node_name(&self) -> String;
    /// Campaigns for a lease; with clustering off it is granted at once.
    fn lead(&self, lease: &str, handler: Arc<dyn LeaseHandler>);
    /// Gives a held lease up, so another node takes it.
    fn step_down(&self, lease: &str) -> BoxFuture<'_, Result<(), String>>;
}

/// A claim taken: the database's time it was taken at, and what releases it.
#[derive(Clone, Debug)]
pub struct Claim {
    pub claimed_at: f64,
    pub handle: Json,
}

/// Why a claim was not taken.
#[derive(Clone, Debug)]
pub enum ClaimRefused {
    /// Somebody else holds it.
    Held,
    /// The claim store could not be asked.
    Store(String),
}

/// Atomic claims (`cluster_claims.js`).
pub trait Claims: Send + Sync {
    fn claim(
        &self,
        scope: &str,
        value: &str,
        realm: &str,
        ttl_ms: f64,
    ) -> BoxFuture<'_, Result<Claim, ClaimRefused>>;
    fn release(&self, handle: &Json) -> BoxFuture<'_, ()>;
}

/// The run store: a persisted, tombstoned, per-realm map whose replicas
/// merge by [`compare_rows`].
pub trait RunRows: Send + Sync {
    fn get(&self, realm: &str, key: &str) -> Option<Json>;
    fn set(&self, realm: &str, key: &str, row: Json);
    /// Every row of a realm, in the store's order.
    fn rows(&self, realm: &str) -> Vec<Json>;
}

/// The realms a realm job runs in, and the realm a run is entered in.
pub trait Realms: Send + Sync {
    fn ids(&self) -> Vec<String>;
    fn get(&self, id: &str) -> Option<Arc<Realm>>;
}

impl Realms for RealmRegistry {
    fn ids(&self) -> Vec<String> {
        self.list().iter().map(|r| r.id.clone()).collect()
    }
    fn get(&self, id: &str) -> Option<Arc<Realm>> {
        RealmRegistry::get(self, id)
    }
}

pub trait Audit: Send + Sync {
    fn record(&self, event: Json);
}

/// This process's clock and the database's.
pub trait Clock: Send + Sync {
    fn now(&self) -> f64;
    fn db_now(&self) -> BoxFuture<'_, Result<f64, String>>;
}

/// What the scheduler stands on.
pub struct Deps {
    pub cluster: Arc<dyn Cluster>,
    pub claims: Arc<dyn Claims>,
    pub rows: Arc<dyn RunRows>,
    pub realms: Arc<dyn Realms>,
    pub audit: Arc<dyn Audit>,
    pub clock: Arc<dyn Clock>,
    pub host: String,
    pub pid: u32,
    /// A request worker's thread id, which shares the process's pid.
    pub thread: Option<String>,
    pub is_request_worker: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Started {
    No,
    Front,
    PerProcess,
}

struct Flight {
    realm: String,
    timed_out: AtomicBool,
    realm_gone: AtomicBool,
}

struct State {
    started: Started,
    leading: bool,
    leading_since: f64,
    leader_token: u64,
    in_flight: HashMap<String, Arc<Flight>>,
    waiting: bool,
    process_slots: HashMap<String, i64>,
    quiet_recorded: HashMap<String, (String, f64)>,
    leader_row_at: f64,
    clock_offset: f64,
    leader_loop: Option<tokio::task::JoinHandle<()>>,
    process_loop: Option<tokio::task::JoinHandle<()>>,
}

/// A refusal of a request to the scheduler, for a 4xx answer.
#[derive(Clone, Debug, PartialEq)]
pub struct Refusal {
    pub error_code: &'static str,
    pub status: u16,
    pub why: String,
}

/// A manual run queued, or found already queued.
#[derive(Clone, Debug, PartialEq)]
pub struct Queued {
    pub run_id: String,
    pub already_queued: bool,
    pub run: Json,
}

/// The one scheduler for every periodic job.
pub struct Scheduler {
    schedules: RwLock<Schedules>,
    deps: Deps,
    state: Mutex<State>,
    tick_lock: tokio::sync::Mutex<()>,
    me: Weak<Scheduler>,
}

fn random_id(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    if openssl::rand::rand_bytes(&mut buf).is_err() {
        tracing::error!("scheduler: no random bytes for an id");
    }
    URL_SAFE_NO_PAD.encode(buf)
}

fn num(row: &Json, key: &str) -> f64 {
    row.get(key).and_then(Json::as_f64).unwrap_or(0.0)
}

fn text<'a>(row: &'a Json, key: &str) -> &'a str {
    row.get(key).and_then(Json::as_str).unwrap_or("")
}

/// `Object.assign({}, row, fields)`.
fn assign(row: &Json, fields: Json) -> Json {
    let mut out = row.as_object().cloned().unwrap_or_default();
    if let Json::Object(more) = fields {
        for (k, v) in more {
            out.insert(k, v);
        }
    }
    Json::Object(out)
}

/// `JSON.stringify(row.params || null) === JSON.stringify(params)`: key
/// order counts, as it does there, so the text is compared.
fn same_params(held: Option<&Json>, params: &Json) -> bool {
    let held = held.filter(|h| !h.is_null()).unwrap_or(&Json::Null);
    held.to_string().as_str() == params.to_string().as_str()
}

/// A job's answer, kept small: the row is replicated and drawn on a page.
pub fn summary_of(result: &Json) -> Json {
    let text = match result {
        Json::Null => return Json::Null,
        Json::String(s) => s.clone(),
        other => other.to_string(),
    };
    if text.chars().count() > 500 {
        Json::String(format!(
            "{}...",
            text.chars().take(497).collect::<String>()
        ))
    } else {
        Json::String(text)
    }
}

impl Scheduler {
    pub fn new(schedules: Schedules, deps: Deps) -> Arc<Scheduler> {
        Arc::new_cyclic(|me| Scheduler {
            schedules: RwLock::new(schedules),
            deps,
            state: Mutex::new(State {
                started: Started::No,
                leading: false,
                leading_since: 0.0,
                leader_token: 0,
                in_flight: HashMap::new(),
                waiting: false,
                process_slots: HashMap::new(),
                quiet_recorded: HashMap::new(),
                leader_row_at: f64::NEG_INFINITY,
                clock_offset: 0.0,
                leader_loop: None,
                process_loop: None,
            }),
            tick_lock: tokio::sync::Mutex::new(()),
            me: me.clone(),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn schedules(&self) -> std::sync::RwLockReadGuard<'_, Schedules> {
        self.schedules
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn arc(&self) -> Option<Arc<Scheduler>> {
        self.me.upgrade()
    }

    /// Registers a job ([`Schedules::register`]'s rules).
    pub fn register(&self, spec: JobSpec) -> Result<(), String> {
        self.schedules
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .register(spec)
    }

    pub fn job(&self, id: &str) -> Option<JobSpec> {
        self.schedules().job(id).cloned()
    }

    pub fn job_ids(&self) -> Vec<String> {
        self.schedules().job_ids()
    }

    pub fn is_leading(&self) -> bool {
        self.state().leading
    }

    /// The time by the database's clock, carried between readings by its
    /// offset from this process's clock.
    pub fn now_ms(&self) -> f64 {
        self.deps.clock.now() + self.state().clock_offset
    }

    async fn refresh_clock(&self) -> Result<f64, String> {
        let db = self.deps.clock.db_now().await?;
        self.state().clock_offset = db - self.deps.clock.now();
        Ok(db)
    }

    fn who(&self) -> (String, String) {
        let node = self.deps.cluster.node_id();
        let name = self.deps.cluster.node_name();
        let name = if name.is_empty() {
            self.deps.host.clone()
        } else {
            name
        };
        (node, name)
    }

    fn realm_defined(&self, realm_id: &str) -> bool {
        realm_id.is_empty()
            || realm_id == DEFAULT_ID
            || self.deps.realms.get(realm_id).is_some()
    }

    fn realm_ids_for(&self, job: &JobSpec) -> Vec<String> {
        match job.scope {
            Scope::Realm => self.deps.realms.ids(),
            Scope::Service => vec![DEFAULT_ID.to_string()],
        }
    }

    /// Writes a row unless the store already holds a newer copy, and never
    /// into a realm that is gone (it would put the realm's history back).
    /// Answers what the store holds after.
    fn write_row(&self, realm_id: &str, row: Json) -> Json {
        if !self.realm_defined(realm_id) {
            return row;
        }
        let key = text(&row, "runId").to_string();
        let held = self.deps.rows.get(realm_id, &key);
        let floor = held.as_ref().map_or(0.0, |h| num(h, "updatedAt") + 1.0);
        let row =
            assign(&row, json!({ "updatedAt": self.now_ms().max(floor) }));
        if let Some(held) = held {
            if compare_rows(&row, &held).is_lt() {
                return held;
            }
        }
        self.deps.rows.set(realm_id, &key, row.clone());
        row
    }

    // ---------------------------------------------------------------------
    // Starting and leading.
    // ---------------------------------------------------------------------

    /// Starts the scheduler: `front` campaigns for the lease; `per-process`
    /// (and any request worker) runs per-process jobs only. Idempotent:
    /// false when already started.
    pub fn start(&self, per_process_only: bool) -> bool {
        let per_process_only = per_process_only || self.deps.is_request_worker;
        {
            let mut st = self.state();
            if st.started != Started::No {
                return false;
            }
            st.started = if per_process_only {
                Started::PerProcess
            } else {
                Started::Front
            };
        }
        self.spawn_process_loop();
        if per_process_only {
            tracing::info!(
                "scheduler: running {} per-process job(s) in this process. Cluster jobs run on the \
                 scheduler's leader, which a request worker never is.",
                self.jobs_of(Kind::PerProcess).len()
            );
            return true;
        }
        if let Some(me) = self.arc() {
            self.deps.cluster.lead(LEADER_LEASE, me);
        }
        true
    }

    pub fn stop(&self) {
        let mut st = self.state();
        st.started = Started::No;
        st.leading = false;
        for handle in [st.leader_loop.take(), st.process_loop.take()]
            .into_iter()
            .flatten()
        {
            handle.abort();
        }
    }

    fn jobs_of(&self, kind: Kind) -> Vec<JobSpec> {
        self.schedules()
            .jobs()
            .filter(|j| j.kind == kind)
            .cloned()
            .collect()
    }

    /// The lease was granted. The catch-up is the first tick: runs claimed
    /// or running on a node that went are re-claimed once their claims
    /// lapse, and every job due in its current slot runs once, whatever was
    /// missed.
    pub async fn gain_leadership(&self, token: u64) {
        {
            let mut st = self.state();
            if st.started != Started::Front {
                return;
            }
            st.leading = true;
            st.leader_token = token;
        }
        let since = self.now_ms();
        self.state().leading_since = since;
        tracing::info!(
            "scheduler: this process ({}) leads the scheduler{}. {} cluster job(s), {} per-process.",
            self.deps.pid,
            if token > 0 {
                format!(" (lease token {})", token)
            } else {
                ", and nothing else could: this service is not clustered".to_string()
            },
            self.jobs_of(Kind::Cluster).len(),
            self.jobs_of(Kind::PerProcess).len()
        );
        match self.refresh_clock().await {
            Ok(_) => self.write_leader_row("gained"),
            Err(e) => {
                tracing::debug!("scheduler: the clock could not be read: {}", e)
            }
        }
        self.spawn_leader_loop();
    }

    /// The lease was lost: runs still going here are fenced out from now.
    pub fn lose_leadership(&self) {
        let mut st = self.state();
        if !st.leading {
            return;
        }
        st.leading = false;
        if let Some(handle) = st.leader_loop.take() {
            handle.abort();
        }
        tracing::warn!(
            "scheduler: this process ({}) no longer leads the scheduler. {} run(s) still going here are fenced \
             out from now on.",
            self.deps.pid,
            st.in_flight.len()
        );
    }

    fn write_leader_row(&self, event: &str) {
        let (node, name) = self.who();
        let (token, since) = {
            let st = self.state();
            (st.leader_token, st.leading_since)
        };
        self.write_row(
            DEFAULT_ID,
            json!({ "runId": LEADER_KEY, "kind": "leader", "node": node, "nodeName": name,
                    "host": self.deps.host, "pid": self.deps.pid, "token": token, "since": since,
                    "lastTickAt": self.now_ms(), "event": event,
                    "clustered": self.deps.cluster.enabled() }),
        );
    }

    /// The leader's timer: the one timer every periodic job hangs off.
    fn spawn_leader_loop(&self) {
        let Some(me) = self.arc() else {
            return;
        };
        let handle = tokio::spawn(async move {
            let mut delay = 0.0;
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(
                    delay as u64,
                ))
                .await;
                if !me.is_leading() {
                    return;
                }
                me.tick().await;
                delay = me.next_delay(Kind::Cluster);
            }
        });
        let mut st = self.state();
        if let Some(old) = st.leader_loop.replace(handle) {
            old.abort();
        }
    }

    fn spawn_process_loop(&self) {
        if self.jobs_of(Kind::PerProcess).is_empty() {
            return;
        }
        let Some(me) = self.arc() else {
            return;
        };
        let handle = tokio::spawn(async move {
            let mut delay = 0.0;
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(
                    delay as u64,
                ))
                .await;
                if me.state().started == Started::No {
                    return;
                }
                me.process_tick().await;
                delay = me.next_delay(Kind::PerProcess);
            }
        });
        let mut st = self.state();
        if let Some(old) = st.process_loop.replace(handle) {
            old.abort();
        }
    }

    fn next_delay(&self, kind: Kind) -> f64 {
        let at = self.now_ms() as i64;
        self.schedules().next_delay_ms(kind, at, DEFAULT_ID)
    }

    // ---------------------------------------------------------------------
    // The leader's tick.
    // ---------------------------------------------------------------------

    /// One tick of the leader. Serialised: a tick asked for while one is
    /// going is answered by that one.
    pub async fn tick(&self) {
        let Ok(_guard) = self.tick_lock.try_lock() else {
            let _wait = self.tick_lock.lock().await;
            return;
        };
        if let Err(e) = self.tick_once().await {
            tracing::error!(
                "{}scheduler: a tick failed: {}. It is tried again at the next one.",
                tag(codes::STS_SCHED_0013),
                e
            );
        }
    }

    async fn tick_once(&self) -> Result<(), String> {
        if !self.is_leading() {
            return Ok(());
        }
        self.refresh_clock().await?;
        let tick_ms = self.schedules().tick_ms();
        let due_row = {
            let mut st = self.state();
            let now = self.deps.clock.now();
            let due = now - st.leader_row_at >= tick_ms - 50.0;
            if due {
                st.leader_row_at = now;
            }
            due
        };
        if due_row {
            self.write_leader_row("tick");
        }
        if self.obey_commands().await {
            return Ok(());
        }
        let at = self.now_ms();
        let mut line: Vec<(JobSpec, String, Json)> = Vec::new();
        for (realm, row) in self.queued_manual_runs() {
            if let Some(job) = self.job(text(&row, "jobId")) {
                line.push((job, realm, row));
            }
        }
        let mut scheduled: Vec<(JobSpec, String, Json)> = Vec::new();
        let mut since = 0usize;
        for job in self.jobs_of(Kind::Cluster) {
            let slot = {
                let s = self.schedules();
                if !s.service_off_reason(&job).is_empty() {
                    continue;
                }
                s.slot_at(&job, at as i64)
            };
            let Some(Slot {
                slot: Some(slot),
                starts_at,
                ..
            }) = slot
            else {
                continue;
            };
            for realm_id in self.realm_ids_for(&job) {
                since += 1;
                if since >= TICK_YIELD_EVERY {
                    since = 0;
                    tokio::task::yield_now().await;
                }
                if !self.schedules().own_off_reason(&job, &realm_id).is_empty()
                {
                    continue;
                }
                let run_id = run_id_for(&job.id, &realm_id, slot);
                let row = self.deps.rows.get(&realm_id, &run_id);
                if row
                    .as_ref()
                    .is_some_and(|r| FINAL.contains(&text(r, "state")))
                {
                    continue;
                }
                let row = row.unwrap_or_else(|| {
                    json!({ "runId": run_id, "kind": "run", "jobId": job.id, "realm": realm_id,
                            "slot": slot, "dueAt": starts_at, "trigger": "schedule", "params": null,
                            "requestedBy": "", "state": "queued", "attempt": 0, "fenceAt": 0,
                            "queuedAt": at })
                });
                scheduled.push((job.clone(), realm_id, row));
            }
        }
        scheduled
            .sort_by(|a, b| num(&a.2, "dueAt").total_cmp(&num(&b.2, "dueAt")));
        let cap = self.schedules().max_concurrent_runs();
        self.state().waiting = false;
        for (job, realm, row) in line.into_iter().chain(scheduled) {
            let run_id = text(&row, "runId").to_string();
            {
                let mut st = self.state();
                if st.in_flight.contains_key(&run_id) {
                    continue;
                }
                if st.in_flight.len() as f64 >= cap {
                    st.waiting = true;
                    continue;
                }
            }
            self.attempt(job, realm, row);
        }
        Ok(())
    }

    /// Every queued manual run in every realm, oldest first.
    fn queued_manual_runs(&self) -> Vec<(String, Json)> {
        let mut out = Vec::new();
        for realm in self.deps.realms.ids() {
            for row in self.deps.rows.rows(&realm) {
                if text(&row, "kind") == "run"
                    && text(&row, "trigger") == "manual"
                    && matches!(text(&row, "state"), "queued" | "running")
                {
                    out.push((realm.clone(), row));
                }
            }
        }
        out.sort_by(|a, b| {
            num(&a.1, "queuedAt").total_cmp(&num(&b.1, "queuedAt"))
        });
        out
    }

    /// One attempt at one run: claim it, write it running with the claim's
    /// time as its fence, run it with a time limit, write the outcome only
    /// if the fence still stands. Not awaited by the tick.
    fn attempt(&self, job: JobSpec, realm_id: String, row: Json) {
        let run_id = text(&row, "runId").to_string();
        let timeout_ms = self.schedules().timeout_ms_of(&job);
        {
            let mut st = self.state();
            if st.in_flight.contains_key(&run_id) {
                return;
            }
            // Held while the claim is asked, so the next tick does not ask.
            st.in_flight.insert(
                run_id.clone(),
                Arc::new(Flight {
                    realm: realm_id.clone(),
                    timed_out: AtomicBool::new(false),
                    realm_gone: AtomicBool::new(false),
                }),
            );
        }
        let Some(me) = self.arc() else {
            return;
        };
        tokio::spawn(async move {
            let answer = me
                .deps
                .claims
                .claim(RUN_SCOPE, &run_id, &realm_id, timeout_ms + 1000.0)
                .await;
            match answer {
                Err(refused) => {
                    me.state().in_flight.remove(&run_id);
                    if let ClaimRefused::Store(why) = refused {
                        tracing::warn!(
                            "{}scheduler: the claim store could not be asked about run {} of {} ({}). It is not \
                             started until it can be.",
                            tag(codes::STS_SCHED_0008),
                            run_id,
                            job.id,
                            why
                        );
                    }
                }
                Ok(claim) => {
                    me.run_claimed(job, realm_id, row, claim, timeout_ms).await
                }
            }
        });
    }

    async fn run_claimed(
        &self,
        job: JobSpec,
        realm_id: String,
        row: Json,
        claim: Claim,
        timeout_ms: f64,
    ) {
        let run_id = text(&row, "runId").to_string();
        // A realm removed between the tick and the claim: nothing is run
        // for it (it once ran in the default realm instead).
        if !self.realm_defined(&realm_id) {
            self.state().in_flight.remove(&run_id);
            self.deps.claims.release(&claim.handle).await;
            tracing::info!(
                "{}scheduler: run {} of {} was not started: the realm \"{}\" has been removed.",
                tag(codes::STS_SCHED_0018),
                run_id,
                job.id,
                realm_id
            );
            return;
        }
        let fence = if claim.claimed_at != 0.0 {
            claim.claimed_at
        } else {
            self.now_ms()
        };
        let stored = self
            .deps
            .rows
            .get(&realm_id, &run_id)
            .unwrap_or_else(|| row.clone());
        let (node, name) = self.who();
        // A row still marked running by somebody else whose claim this
        // attempt could take: that attempt lost its claim before it
        // finished. Recorded as ABANDONED, under a row of its own.
        if text(&stored, "state") == "running"
            && num(&stored, "fenceAt") != 0.0
            && num(&stored, "fenceAt") != fence
        {
            let attempt = num(&stored, "attempt").max(1.0);
            let by = [text(&stored, "nodeName"), text(&stored, "node")]
                .into_iter()
                .find(|s| !s.is_empty())
                .unwrap_or("?")
                .to_string();
            self.write_row(
                &realm_id,
                assign(
                    &stored,
                    json!({ "runId": format!("{}:{}", run_id, attempt), "state": "abandoned",
                            "endedAt": self.now_ms(), "errorCode": "STS-SCHED-0011",
                            "why": format!("The attempt on {} (pid {}) stopped holding its claim before it \
                                            finished; attempt {} took it over.", by,
                                           stored.get("pid").cloned().unwrap_or(Json::Null), attempt + 1.0),
                            "abandonedOf": run_id }),
                ),
            );
            self.deps.audit.record(json!({
                "action": "scheduler.run", "protocol": "scheduler", "channel": "internal",
                "target": job.id, "errorCode": "STS-SCHED-0011", "outcome": "failure", "summarised": true,
                "summary": format!("Scheduler run {} of {} was abandoned and taken over.", run_id, job.id),
                "detail": { "runId": run_id, "realm": realm_id, "node": stored.get("node"),
                            "pid": stored.get("pid") } }));
        }
        let running = assign(
            &stored,
            json!({ "state": "running", "fenceAt": fence, "attempt": num(&stored, "attempt") + 1.0,
                    "node": node, "nodeName": name, "host": self.deps.host, "pid": self.deps.pid,
                    "startedAt": self.now_ms(), "endedAt": 0, "errorCode": "", "why": "",
                    "result": null, "takenOver": text(&stored, "state") == "running" }),
        );
        self.write_row(&realm_id, running.clone());
        let flight = Arc::new(Flight {
            realm: realm_id.clone(),
            timed_out: AtomicBool::new(false),
            realm_gone: AtomicBool::new(false),
        });
        self.state()
            .in_flight
            .insert(run_id.clone(), flight.clone());
        let started_local = self.deps.clock.now();
        let Some(me) = self.arc() else {
            return;
        };
        let ctx = RunContext {
            realm: realm_id.clone(),
            run_id: run_id.clone(),
            trigger: text(&running, "trigger").to_string(),
            params: running.get("params").cloned().unwrap_or(Json::Null),
            still_owner: {
                let (me, flight, realm_id, run_id) = (
                    me.clone(),
                    flight.clone(),
                    realm_id.clone(),
                    run_id.clone(),
                );
                Arc::new(move || {
                    let live = me.deps.rows.get(&realm_id, &run_id);
                    me.is_leading()
                        && !flight.timed_out.load(Ordering::SeqCst)
                        && !flight.realm_gone.load(Ordering::SeqCst)
                        && live.is_some_and(|l| num(&l, "fenceAt") == fence)
                })
            },
            now_ms: {
                let me = me.clone();
                Arc::new(move || me.now_ms())
            },
        };
        let realm = self
            .deps
            .realms
            .get(&realm_id)
            .or_else(|| self.deps.realms.get(DEFAULT_ID))
            .unwrap_or_else(|| Arc::new(Realm::default_realm()));
        let Some(run) = job.run.clone() else {
            self.state().in_flight.remove(&run_id);
            return;
        };
        // Its own task: a run past its time limit is fenced out, not
        // cancelled mid-step, and the scheduler does not wait on it.
        let work = tokio::spawn(realm::run(realm, run(ctx)));
        let outcome = match tokio::time::timeout(
            std::time::Duration::from_millis(timeout_ms as u64),
            work,
        )
        .await
        {
            Err(elapsed) => Err(elapsed),
            Ok(Ok(answer)) => Ok(answer),
            Ok(Err(join)) => Ok(Err(format!("it panicked: {}", join))),
        };
        if outcome.is_err() {
            flight.timed_out.store(true, Ordering::SeqCst);
        }
        let waiting = {
            let mut st = self.state();
            st.in_flight.remove(&run_id);
            st.waiting && st.leading
        };
        // A place is free: start what the last tick left waiting, now.
        if waiting {
            let me = me.clone();
            tokio::spawn(async move { me.tick().await });
        }
        let ended_at = self.now_ms();
        if flight.realm_gone.load(Ordering::SeqCst)
            || !self.realm_defined(&realm_id)
        {
            tracing::info!(
                "{}scheduler: the outcome of run {} of {} is not written: the realm \"{}\" was removed while it ran.",
                tag(codes::STS_SCHED_0018),
                run_id,
                job.id,
                realm_id
            );
            return;
        }
        let live = self.deps.rows.get(&realm_id, &run_id);
        let Some(live) = live.filter(|l| num(l, "fenceAt") == fence) else {
            tracing::warn!(
                "{}scheduler: the outcome of run {} of {} was fenced out — another attempt took it over — and is \
                 not written.",
                tag(codes::STS_SCHED_0003),
                run_id,
                job.id
            );
            return;
        };
        let mut fields = Map::new();
        fields.insert("endedAt".into(), json!(ended_at));
        fields.insert(
            "durationMs".into(),
            json!(self.deps.clock.now() - started_local),
        );
        let error_code = match outcome {
            Err(_) => {
                self.deps.claims.release(&claim.handle).await;
                fields.insert("state".into(), json!("failed"));
                fields.insert(
                    "why".into(),
                    json!(format!(
                        "It was still running after its time limit of {}.",
                        span(timeout_ms)
                    )),
                );
                "STS-SCHED-0002"
            }
            Ok(Err(why)) => {
                fields.insert("state".into(), json!("failed"));
                fields.insert(
                    "why".into(),
                    json!(if why.is_empty() {
                        "it failed".to_string()
                    } else {
                        why
                    }),
                );
                "STS-SCHED-0001"
            }
            Ok(Ok(result)) => {
                fields.insert("state".into(), json!("succeeded"));
                fields.insert("result".into(), summary_of(&result));
                ""
            }
        };
        fields.insert("errorCode".into(), json!(error_code));
        let last = assign(&live, Json::Object(fields));
        let last = self.write_row(&realm_id, last);
        let state = text(&last, "state").to_string();
        self.deps.audit.record(json!({
            "action": "scheduler.run", "protocol": "scheduler", "channel": "internal", "target": job.id,
            "errorCode": error_code, "outcome": if error_code.is_empty() { "success" } else { "failure" },
            "summarised": !error_code.is_empty(),
            "summary": format!("Scheduler run {} of {}{} {} ({}, attempt {}).", run_id, job.id,
                               if realm_id != DEFAULT_ID { format!(" in \"{}\"", realm_id) } else { String::new() },
                               state, text(&last, "trigger"), num(&last, "attempt")),
            "detail": { "runId": run_id, "realm": realm_id, "trigger": last.get("trigger"),
                        "attempt": last.get("attempt"), "durationMs": last.get("durationMs"),
                        "why": text(&last, "why") } }));
        if !error_code.is_empty() {
            tracing::warn!(
                "{}scheduler: {} failed: {}",
                tag(error_code),
                job.id,
                text(&last, "why")
            );
        }
    }

    /// A removed realm: forget this process's memory of it and fence out
    /// any run of it still going here. Answers how many were fenced.
    pub fn forget_realm(&self, realm_id: &str) -> usize {
        let mut st = self.state();
        let mut fenced = 0;
        for flight in st.in_flight.values() {
            if flight.realm == realm_id {
                flight.realm_gone.store(true, Ordering::SeqCst);
                fenced += 1;
            }
        }
        let suffix = format!("|{}", realm_id);
        st.process_slots.retain(|k, _| !k.ends_with(&suffix));
        st.quiet_recorded.retain(|k, _| !k.ends_with(&suffix));
        fenced
    }

    /// How many runs this process has going.
    pub fn in_flight(&self) -> usize {
        self.state().in_flight.len()
    }

    // ---------------------------------------------------------------------
    // Per-process jobs.
    // ---------------------------------------------------------------------

    /// Every process runs its per-process jobs itself, keeps the last slot
    /// it ran, and writes its latest run under a key naming the node and the
    /// process, so the page drawn anywhere shows every process's row.
    pub async fn process_tick(&self) {
        if let Err(e) = self.refresh_clock().await {
            tracing::debug!("scheduler: the clock could not be read: {}", e);
        }
        let at = self.now_ms() as i64;
        for job in self.jobs_of(Kind::PerProcess) {
            for realm_id in self.realm_ids_for(&job) {
                let slot = {
                    let s = self.schedules();
                    if !s.off_reason(&job, &realm_id).is_empty() {
                        continue;
                    }
                    s.slot_at(&job, at)
                };
                let Some(slot @ Slot { slot: Some(n), .. }) = slot else {
                    continue;
                };
                let key = format!("{}|{}", job.id, realm_id);
                if self.state().process_slots.insert(key, n) == Some(n) {
                    continue;
                }
                self.run_in_this_process(&job, &realm_id, slot).await;
            }
        }
    }

    async fn run_in_this_process(
        &self,
        job: &JobSpec,
        realm_id: &str,
        slot: Slot,
    ) {
        let (node, name) = self.who();
        let key = format!(
            "{}{}|{}|{}|{}{}",
            PROCESS_PREFIX,
            job.id,
            realm_id,
            if node.is_empty() {
                &self.deps.host
            } else {
                &node
            },
            self.deps.pid,
            self.deps
                .thread
                .as_ref()
                .map(|t| format!(".{}", t))
                .unwrap_or_default()
        );
        let started_at = self.now_ms();
        let started_local = self.deps.clock.now();
        let realm = self
            .deps
            .realms
            .get(realm_id)
            .or_else(|| self.deps.realms.get(DEFAULT_ID))
            .unwrap_or_else(|| Arc::new(Realm::default_realm()));
        let Some(me) = self.arc() else {
            return;
        };
        let ctx = RunContext {
            realm: realm_id.to_string(),
            run_id: key.clone(),
            trigger: "schedule".to_string(),
            params: Json::Null,
            still_owner: {
                let me = me.clone();
                Arc::new(move || me.state().started != Started::No)
            },
            now_ms: Arc::new(move || me.now_ms()),
        };
        let Some(run) = &job.run else {
            return;
        };
        let (state, error_code, why, result) = match realm::run(realm, run(ctx))
            .await
        {
            Ok(result) => ("succeeded", "", String::new(), summary_of(&result)),
            Err(e) => {
                tracing::warn!(
                    "{}scheduler: the per-process job {} failed in this process: {}.",
                    tag(codes::STS_SCHED_0015),
                    job.id,
                    e
                );
                ("failed", "STS-SCHED-0015", e, Json::Null)
            }
        };
        if job.quiet {
            let record = format!("{}|{}", job.id, realm_id);
            let now = self.deps.clock.now();
            let mut st = self.state();
            if let Some((last, at)) = st.quiet_recorded.get(&record) {
                if last == state && now - at < QUIET_RECORD_MS {
                    return;
                }
            }
            st.quiet_recorded.insert(record, (state.to_string(), now));
        }
        let worker = self.state().started == Started::PerProcess;
        self.write_row(
            DEFAULT_ID,
            json!({ "runId": key, "kind": "process", "jobId": job.id, "realm": realm_id,
                    "slot": slot.slot, "dueAt": slot.starts_at, "nextAt": slot.next_at,
                    "trigger": "schedule", "node": node, "nodeName": name, "host": self.deps.host,
                    "pid": self.deps.pid, "worker": worker, "startedAt": started_at,
                    "endedAt": self.now_ms(), "durationMs": self.deps.clock.now() - started_local,
                    "attempt": 0, "fenceAt": 0, "state": state, "errorCode": error_code, "why": why,
                    "result": result }),
        );
    }

    // ---------------------------------------------------------------------
    // Manual runs and stepping down: rows written by whichever process
    // served the request, picked up by the leader at its next tick.
    // ---------------------------------------------------------------------

    /// Queues a run of a job by hand. A second request for the same job,
    /// realm and parameters while one is queued is the same run.
    pub fn request_run(
        &self,
        job_id: &str,
        realm: Option<&str>,
        params: Json,
        requested_by: &str,
        via: &str,
    ) -> Result<Queued, Refusal> {
        let Some(job) = self.job(job_id) else {
            return Err(Refusal {
                error_code: "STS-SCHED-0004",
                status: 404,
                why: format!(
                    "No job \"{}\" is registered. The jobs are {}.",
                    job_id,
                    self.job_ids().join(", ")
                ),
            });
        };
        if !job.manual || job.kind == Kind::PerProcess {
            return Err(Refusal {
                error_code: "STS-SCHED-0005",
                status: 400,
                why: format!(
                    "{} runs on its schedule only{}",
                    job.id,
                    if job.kind == Kind::PerProcess {
                        ": it is a per-process job, which every process runs for itself."
                    } else {
                        "."
                    }
                ),
            });
        }
        let realm_id = match job.scope {
            Scope::Realm => realm
                .filter(|r| !r.is_empty())
                .unwrap_or(DEFAULT_ID)
                .to_string(),
            Scope::Service => DEFAULT_ID.to_string(),
        };
        if job.scope == Scope::Realm
            && self.deps.realms.get(&realm_id).is_none()
        {
            return Err(Refusal {
                error_code: "STS-SCHED-0012",
                status: 400,
                why: format!("There is no realm \"{}\".", realm_id),
            });
        }
        let off = self.schedules().off_reason(&job, &realm_id);
        if !off.is_empty() {
            return Err(Refusal {
                error_code: "STS-SCHED-0006",
                status: 400,
                why: format!("{} is off: {}.", job.id, off),
            });
        }
        let params = if params.is_object() {
            params
        } else {
            Json::Null
        };
        let existing = self.deps.rows.rows(&realm_id).into_iter().find(|row| {
            text(row, "kind") == "run"
                && text(row, "trigger") == "manual"
                && text(row, "jobId") == job.id
                && text(row, "state") == "queued"
                && same_params(row.get("params"), &params)
        });
        if let Some(row) = existing {
            return Ok(Queued {
                run_id: text(&row, "runId").to_string(),
                already_queued: true,
                run: row,
            });
        }
        let now = self.now_ms();
        let row = self.write_row(
            &realm_id,
            json!({ "runId": format!("m-{}", random_id(12)), "kind": "run", "jobId": job.id,
                    "realm": realm_id, "slot": null, "dueAt": now, "trigger": "manual", "params": params,
                    "requestedBy": requested_by, "requestedVia": via, "state": "queued", "attempt": 0,
                    "fenceAt": 0, "queuedAt": now }),
        );
        let run_id = text(&row, "runId").to_string();
        self.deps.audit.record(json!({
            "action": "scheduler.run", "protocol": "scheduler", "channel": "console", "actor": requested_by,
            "target": job.id,
            "summary": format!("A run of {} was queued by hand{}.", job.id,
                               if via.is_empty() { String::new() } else { format!(" at {}", via) }),
            "detail": { "runId": run_id, "realm": realm_id } }));
        Ok(Queued {
            run_id,
            already_queued: false,
            run: row,
        })
    }

    /// Asks the leader, wherever it is, to stand down at its next tick.
    pub fn request_step_down(
        &self,
        requested_by: &str,
        via: &str,
    ) -> Result<Json, Refusal> {
        if !self.deps.cluster.enabled() {
            return Err(Refusal {
                error_code: "STS-SCHED-0010",
                status: 400,
                why: "This service is not clustered, so there is no other node to hand the scheduler to.".to_string(),
            });
        }
        let leader = self.deps.rows.get(DEFAULT_ID, LEADER_KEY);
        let at_request = leader
            .map(|l| json!({ "node": l.get("node"), "pid": l.get("pid"), "token": l.get("token") }))
            .unwrap_or(Json::Null);
        let row = self.write_row(
            DEFAULT_ID,
            json!({ "runId": format!("{}{}", COMMAND_PREFIX, random_id(9)), "kind": "command",
                    "command": "step-down", "state": "queued", "requestedBy": requested_by,
                    "requestedVia": via, "queuedAt": self.now_ms(), "leaderAtRequest": at_request,
                    "attempt": 0, "fenceAt": 0 }),
        );
        self.deps.audit.record(json!({
            "action": "scheduler.step-down", "protocol": "scheduler", "channel": "console",
            "actor": requested_by, "target": LEADER_LEASE,
            "summary": format!("The scheduler's leader was asked to stand down{}.",
                               if via.is_empty() { String::new() } else { format!(" at {}", via) }),
            "detail": { "command": row.get("runId") } }));
        Ok(
            json!({ "command": row.get("runId"), "leaderAtRequest": row.get("leaderAtRequest") }),
        )
    }

    /// True when this process stood down, so the tick stops there.
    async fn obey_commands(&self) -> bool {
        let queued: Vec<Json> = self
            .deps
            .rows
            .rows(DEFAULT_ID)
            .into_iter()
            .filter(|r| {
                text(r, "kind") == "command" && text(r, "state") == "queued"
            })
            .collect();
        if queued.is_empty() {
            return false;
        }
        let (node, name) = self.who();
        for row in queued {
            self.write_row(
                DEFAULT_ID,
                assign(
                    &row,
                    json!({ "state": "succeeded", "endedAt": self.now_ms(),
                            "obeyedBy": { "node": node, "nodeName": name, "host": self.deps.host,
                                          "pid": self.deps.pid } }),
                ),
            );
        }
        match self.deps.cluster.step_down(LEADER_LEASE).await {
            Ok(()) => {
                tracing::info!(
                    "scheduler: this process stood down as the scheduler's leader, as asked; another node takes it \
                     at its next heartbeat."
                );
                true
            }
            Err(why) => {
                tracing::warn!(
                    "{}scheduler: asked to stand down, and could not ({}).",
                    tag(codes::STS_SCHED_0014),
                    why
                );
                false
            }
        }
    }
}

impl LeaseHandler for Scheduler {
    fn on_gain(&self, token: u64) {
        if let Some(me) = self.arc() {
            tokio::spawn(async move { me.gain_leadership(token).await });
        }
    }

    fn on_lose(&self) {
        self.lose_leadership();
    }
}
