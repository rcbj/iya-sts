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
//! The run history's bound is `history`'s; what the page and the API read
//! is `report`'s.

use std::collections::HashMap;

use indexmap::IndexMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Map, Value as Json};
use sts_core::errors::{codes, ErrorCode};
use sts_core::log::tag;
use sts_core::realm::{self, Realm, RealmRegistry, DEFAULT_ID};

use crate::schedule::{
    compare_rows, run_id_for, span, BoxFuture, JobSpec, Kind, RunContext,
    Schedules, Scope, Slot, FINAL, LEADER_LEASE, QUIET_RECORD_MS, RUN_SCOPE,
};

mod history;
mod index;
mod load;
mod report;

pub use history::Purged;
pub use load::{least_loaded, InFlight, Loads, RuntimeLoad, WorkerLoad};

use index::RunIndex;

/// The store's key for the leader's own row.
pub const LEADER_KEY: &str = "leader";
pub const PROCESS_PREFIX: &str = "process|";
pub const COMMAND_PREFIX: &str = "command|";
/// How many (job, realm) pairs a tick asks about before it yields.
const TICK_YIELD_EVERY: usize = 50;
/// `nice`'s top (`MAX_NICE`): the most patient a job can be.
const MAX_NICE: f64 = 19.0;

/// THE JOBS WHOSE WORK IS THE GLOBAL TIER'S (`persistence/tiers.js`'s
/// `GLOBAL_JOBS`, #98, #695): deployed as cells, one cell runs each slot of
/// these — claimed under [`GLOBAL_RUN_SCOPE`], which the tiered store keeps
/// in the global database — rather than every cell rotating the same key.
pub const GLOBAL_JOBS: &[&str] = &[
    "signing.rotate",
    "signing.retire",
    "signing.rotate-now",
    "krb5.krbtgt-rotate",
    "krb5.krbtgt-rotate-now",
    "oidfed.key-rotate",
    "oidfed.key-rotate-now",
    "oidfed.collection-crawl",
    "oidfed.registrations-expire",
    "federation.encryption-key-retire",
    "federation.client-certificate-renew",
    "spiffe.authority-rotation",
    "spiffe.sigstore-tuf-refresh",
    "oauth2.client-secret-expiry",
    "oauth2.used-assertion-purge",
    "saml2.sp-metadata-refresh",
    "ssf.stream-maintenance",
    "ssf.foreign-poll",
    "persistence.minted-expiry-purge-global",
];
/// The claim scope a global job's run is claimed under when deployed as
/// cells (`tiers.GLOBAL_RUN_SCOPE`).
pub const GLOBAL_RUN_SCOPE: &str = "scheduler.run.global";

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
    /// A lease as the cluster knows it: `{ holder, token, acquiredAt,
    /// expiresAt }`, or `None`.
    fn lease(&self, _name: &str) -> BoxFuture<'_, Option<Json>> {
        Box::pin(async { None })
    }
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
    /// Removes a row (journalled like any other write).
    fn delete(&self, realm: &str, key: &str);
    /// Resolves once what this process journalled is written down; the
    /// history purge waits on it between batches.
    fn settle(&self) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
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
    /// Whose clock `db_now()` reads, for the report.
    fn source(&self) -> &'static str {
        "this process"
    }
}

/// What the DURABLE run store can say that the in-memory map cannot (#883):
/// a start does not restore a finished interval run, so the row saying the
/// current slot already ran is asked of the store (`readRuns`), and a
/// finished body this process wrote is dropped from memory once written
/// down (`persisted`, `dropHeld`). Absent, every row is kept and nothing is
/// asked — a test's store, and development, where the map is the only copy.
pub trait RunHistory: Send + Sync {
    /// True when a finished interval run has a durable copy to drop from
    /// memory against.
    fn persisted(&self) -> bool;
    /// The rows of `ids` in a realm, by run id, from the durable store.
    /// `Ok(None)` is no store: an absence all the same. `Err` is a read
    /// that failed, which holds back only the jobs it could not answer.
    fn read_runs(
        &self,
        realm: &str,
        ids: Vec<String>,
    ) -> BoxFuture<'_, Result<Option<HashMap<String, Json>>, String>>;
    /// Drops a held key without journalling a delete; false while the key
    /// is still journalled (that absence would be written as a delete).
    fn drop_held(&self, realm: &str, key: &str) -> bool;
    /// Admits a row the tick read back, without journalling it.
    fn restore_row(&self, realm: &str, key: &str, row: Json);
    /// The newest run rows of the named realms, at most `limit` a realm,
    /// for the page (#883's window, the store's sort index). `Ok(None)`
    /// means the list is whatever the map holds.
    fn newest_runs(
        &self,
        _realms: Vec<String>,
        _limit: usize,
    ) -> BoxFuture<'_, Result<Option<Vec<Json>>, String>> {
        Box::pin(async { Ok(None) })
    }
}

/// What the scheduler may stand on beyond [`Deps`], each optional: how busy
/// the runtime is (#408), the durable run history (#883), and whether this
/// service is deployed as cells (#98). Separate from [`Deps`] so that a
/// composition root that has none of them builds the scheduler as before.
#[derive(Clone, Default)]
pub struct Extras {
    pub loads: Option<Arc<dyn Loads>>,
    pub history: Option<Arc<dyn RunHistory>>,
    /// True when the service is deployed as more than one cell
    /// (`common/cells.js`'s `isMulti()`), read when a run is claimed.
    pub cells_multi: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
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
    /// The reason the job was switched off while this ran, or `''` (#1305):
    /// latched by the run's watch, read by `still_owner` and by the row.
    switched_off: Mutex<String>,
}

impl Flight {
    fn new(realm: &str) -> Flight {
        Flight {
            realm: realm.to_string(),
            timed_out: AtomicBool::new(false),
            realm_gone: AtomicBool::new(false),
            switched_off: Mutex::new(String::new()),
        }
    }

    fn switched_off(&self) -> String {
        self.switched_off
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

/// A row's `pid` as JavaScript's `'' + pid` writes it.
fn pid_text(row: &Json) -> String {
    match row.get("pid") {
        None => "undefined".to_string(),
        Some(Json::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// How often a run in flight is looked at for a switch-off (`RUN_CHECK_MS`,
/// #1305).
const RUN_CHECK_MS: u64 = 5_000;

/// The `why` a body that succeeded answered beside its result (#1313,
/// `whyOf()`): a string member `why` of an object result, at most 500
/// characters, or `''`.
pub fn why_of(result: &Json) -> String {
    match result.get("why") {
        Some(Json::String(text)) if !text.is_empty() => {
            if text.chars().count() > 500 {
                format!("{}...", text.chars().take(497).collect::<String>())
            } else {
                text.clone()
            }
        }
        _ => String::new(),
    }
}

struct State {
    started: Started,
    leading: bool,
    leading_since: f64,
    leader_token: u64,
    in_flight: HashMap<String, Arc<Flight>>,
    /// The runIds an orphan's claim is out for (`orphanClaims`).
    orphan_claims: std::collections::HashSet<String>,
    waiting: bool,
    process_slots: HashMap<String, i64>,
    quiet_recorded: HashMap<String, (String, f64)>,
    leader_row_at: f64,
    clock_offset: f64,
    leader_loop: Option<tokio::task::JoinHandle<()>>,
    process_loop: Option<tokio::task::JoinHandle<()>>,
    /// The rows a tick has to see (#623, #883).
    index: RunIndex,
    /// #408'S BOOKKEEPING, none of it a row: on the leader, runId → when a
    /// due scheduled run was first held for load (the runId names the slot,
    /// so a new slot is a new entry); runId → how long it was held, written
    /// on its running row.
    held_since: HashMap<String, f64>,
    deferred_ms: HashMap<String, f64>,
    /// A global job's run another cell holds the claim of: its runId, and
    /// the instant that claim cannot outlast (`claimedByAnotherCell`).
    claimed_by_another_cell: HashMap<String, f64>,
    /// ONE RUN OF A JOB IN A REALM AT A TIME (Node's #1757): `job|realm` →
    /// the runId this process is attempting or running for it, so a second
    /// attempt here waits without a round trip (`exclusiveHolders`).
    exclusive_holders: HashMap<String, String>,
    /// The runIds already recorded as waiting (STS-SCHED-0024), so a run
    /// that waits through many ticks says so once (`exclusiveNoted`).
    exclusive_noted: std::collections::HashSet<String>,
}

/// A refusal of a request to the scheduler, for a 4xx answer.
#[derive(Clone, Debug, PartialEq)]
pub struct Refusal {
    pub error_code: ErrorCode,
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
    extras: Extras,
    state: Mutex<State>,
    tick_lock: tokio::sync::Mutex<()>,
    me: Weak<Scheduler>,
}

fn random_id(bytes: usize) -> String {
    match sts_crypto::random::random_bytes(bytes) {
        Ok(buf) => URL_SAFE_NO_PAD.encode(buf),
        Err(e) => {
            tracing::error!("scheduler: no random bytes for an id: {}", e);
            URL_SAFE_NO_PAD.encode(vec![0u8; bytes])
        }
    }
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
        Scheduler::with_extras(schedules, deps, Extras::default())
    }

    /// A scheduler that also stands on [`Extras`].
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn with_extras(
        schedules: Schedules,
        deps: Deps,
        extras: Extras,
    ) -> Arc<Scheduler> {
        Arc::new_cyclic(|me| Scheduler {
            schedules: RwLock::new(schedules),
            deps,
            extras,
            state: Mutex::new(State {
                started: Started::No,
                leading: false,
                leading_since: 0.0,
                leader_token: 0,
                in_flight: HashMap::new(),
                orphan_claims: std::collections::HashSet::new(),
                waiting: false,
                process_slots: HashMap::new(),
                quiet_recorded: HashMap::new(),
                leader_row_at: f64::NEG_INFINITY,
                clock_offset: 0.0,
                leader_loop: None,
                process_loop: None,
                index: RunIndex::default(),
                held_since: HashMap::new(),
                deferred_ms: HashMap::new(),
                claimed_by_another_cell: HashMap::new(),
                exclusive_holders: HashMap::new(),
                exclusive_noted: std::collections::HashSet::new(),
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

    /// For tests: lead without campaigning, writing nothing and starting no
    /// timer (Node's tests set `leading` the same way).
    #[doc(hidden)]
    pub fn assume_leadership_for_tests(&self) {
        let mut st = self.state();
        st.started = Started::Front;
        st.leading = true;
    }

    /// When a run-store row is past every bound the history keeps, for the
    /// store's expiry hook ([`Schedules::expiry_of`]).
    pub fn expiry_of(&self, row: &Json) -> Option<f64> {
        self.schedules().expiry_of(row)
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
        let realm = if realm_id.is_empty() {
            DEFAULT_ID
        } else {
            realm_id
        };
        let mut st = self.state();
        st.index.note(realm, &row);
        // A finished interval body stays until the flush has it, then the
        // tick drops it (#883). Dropping it while it is still journalled
        // would delete the durable row.
        if text(&row, "kind") == "run"
            && FINAL.contains(&text(&row, "state"))
            && self.schedules().expiry_of(&row).is_some()
        {
            st.index.held_finished.insert(index::key_of(realm, &key));
        }
        drop(st);
        row
    }

    /// A run row the store ADMITTED from outside this process — read back
    /// at a start, or brought by the change log from another node — shown
    /// to the index of the rows a tick has to see (#623, the store's
    /// `watch()`). The store's reconcile hook calls this for every run row
    /// it admits. A HOT PATH (every row restored or replicated): no
    /// instrument.
    pub fn note_admitted(&self, realm_id: &str, row: &Json) {
        let realm = if realm_id.is_empty() {
            DEFAULT_ID
        } else {
            realm_id
        };
        self.state().index.note(realm, row);
    }

    /// Whether a run row is a FINISHED INTERVAL RUN, whose body the front
    /// does not keep (#883, `expiringRun()`): the store's restore drops it
    /// once [`Scheduler::note_admitted`] has seen it. A hot path.
    pub fn is_expiring_run(&self, row: &Json) -> bool {
        text(row, "kind") == "run"
            && FINAL.contains(&text(row, "state"))
            && self.schedules().expiry_of(row).is_some()
    }

    /// The rows a tick has to see, read through the index (#623): each
    /// entry's row as the store holds it now. An entry whose row has gone
    /// or is no longer pending is dropped; one whose realm is not defined
    /// here is kept and skipped.
    fn pending(&self) -> Vec<(String, Json)> {
        let entries: Vec<(String, (String, String))> = self
            .state()
            .index
            .pending
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let mut out = Vec::new();
        let mut gone = Vec::new();
        for (key, (realm, run_id)) in entries {
            if !self.realm_defined(&realm) {
                continue;
            }
            match self.deps.rows.get(&realm, &run_id) {
                Some(row) if index::is_pending(&row) => out.push((realm, row)),
                _ => gone.push(key),
            }
        }
        if !gone.is_empty() {
            let mut st = self.state();
            for key in gone {
                st.index.pending.shift_remove(&key);
            }
        }
        out
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
        // A NEW LEADER MEASURES ITS OWN HOLDS (#408).
        st.held_since.clear();
        st.deferred_ms.clear();
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
                let woke = tokio::time::Instant::now()
                    + std::time::Duration::from_millis(delay as u64);
                tokio::time::sleep_until(woke).await;
                // HOW LATE IT WOKE is the runtime's scheduling delay: the
                // event-loop delay a Node worker reported (#408).
                if let Some(loads) = &me.extras.loads {
                    loads.note_lag(woke.elapsed().as_secs_f64() * 1000.0);
                }
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
        // THE CURRENT SLOT, LEARNT WITHOUT HOLDING THE HISTORY (#883).
        self.recall_finished_slots(at).await;
        self.release_finished_history();
        let mut line: Vec<(JobSpec, String, Json)> = Vec::new();
        for (realm, row) in self.queued_manual_runs() {
            if let Some(job) = self.job(text(&row, "jobId")) {
                line.push((job, realm, row));
            }
        }
        let mut scheduled: Vec<(JobSpec, String, Json, f64)> = Vec::new();
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
                next_at,
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
                if row.is_none() {
                    let st = self.state();
                    if st.index.finished_slots.contains(&run_id)
                        || st.index.unknown_slots.contains(&run_id)
                    {
                        continue;
                    }
                }
                let row = row.unwrap_or_else(|| {
                    json!({ "runId": run_id, "kind": "run", "jobId": job.id, "realm": realm_id,
                            "slot": slot, "dueAt": starts_at, "trigger": "schedule", "params": null,
                            "requestedBy": "", "state": "queued", "attempt": 0, "fenceAt": 0,
                            "queuedAt": at })
                });
                scheduled.push((
                    job.clone(),
                    realm_id,
                    row,
                    next_at.unwrap_or(f64::INFINITY),
                ));
            }
        }
        // THE RUN WHOSE SLOT ENDS FIRST GOES FIRST (2026-11-13), then the
        // lower `nice`, then the older. Oldest-due first starved every job
        // with a short interval once the line was longer than the cap could
        // clear: a run not started before its slot ends is never started, so
        // the slot's end is the deadline the order is for.
        scheduled.sort_by(|a, b| {
            a.3.total_cmp(&b.3)
                .then(a.0.nice_of().total_cmp(&b.0.nice_of()))
                .then(num(&a.2, "dueAt").total_cmp(&num(&b.2, "dueAt")))
        });
        let scheduled = scheduled.into_iter().map(|(j, r, row, _)| (j, r, row));
        let cap = self.schedules().max_concurrent_runs();
        self.state().waiting = false;
        let mut seen = std::collections::HashSet::new();
        for (job, realm, row) in line.into_iter().chain(scheduled) {
            let run_id = text(&row, "runId").to_string();
            seen.insert(run_id.clone());
            {
                let mut st = self.state();
                if st.in_flight.contains_key(&run_id) {
                    continue;
                }
                if st
                    .claimed_by_another_cell
                    .get(&run_id)
                    .is_some_and(|until| *until > at)
                {
                    continue;
                }
                // THE CAP FIRST, THEN THE HOLD (#408): a run waiting for the
                // cap is not asked about load, so the instant it was first
                // held is kept.
                if st.in_flight.len() as f64 >= cap {
                    st.waiting = true;
                    continue;
                }
            }
            // HELD FOR LOAD (#408), BEFORE THE CLAIM.
            if self.hold_for_load(&job, &row) {
                continue;
            }
            self.attempt(job, realm, row);
        }
        // A HELD RUN NO TICK SAW AGAIN is forgotten: its slot moved on, its
        // job was switched off, or its realm went.
        {
            let mut st = self.state();
            st.held_since.retain(|id, _| seen.contains(id));
            let in_flight: Vec<String> = st.in_flight.keys().cloned().collect();
            st.deferred_ms
                .retain(|id, _| seen.contains(id) || in_flight.contains(id));
            st.claimed_by_another_cell.retain(|id, _| seen.contains(id));
            let in_flight: Vec<String> = st.in_flight.keys().cloned().collect();
            st.exclusive_noted
                .retain(|id| seen.contains(id) || in_flight.contains(id));
        }
        self.abandon_orphans(at);
        Ok(())
    }

    /// A RUN A DEAD NODE LEFT RUNNING IN A SLOT THAT HAS PASSED
    /// (`abandonOrphans()`, 2026-11-03). A takeover happens only when a tick
    /// attempts the row again, and a tick attempts only the CURRENT slot's
    /// run; a crash's claim outlives many short slots, so such a row stayed
    /// `running` for good. So the leader looks at every scheduled run of a
    /// cluster job left running, attempted by nobody here, whose slot is not
    /// the current one and which is past its expected end; its claim is
    /// asked for — the proof that the runner's claim has lapsed — and, if
    /// the row is still that attempt, it is recorded ABANDONED
    /// (`STS-SCHED-0011`) and the claim given back. The slot is not run
    /// again. It reads the index of the rows seen running (#623's
    /// `runningRows`), never the history: an entry whose row has left the
    /// running state is dropped here.
    fn abandon_orphans(&self, at: f64) {
        let mut found: Vec<(String, Json, JobSpec)> = Vec::new();
        let entries: Vec<(String, (String, String))> = self
            .state()
            .index
            .running
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (key, (realm_id, entry_run)) in entries {
            if !self.realm_defined(&realm_id) {
                continue;
            }
            {
                let row = match self.deps.rows.get(&realm_id, &entry_run) {
                    Some(row)
                        if text(&row, "kind") == "run"
                            && text(&row, "state") == "running" =>
                    {
                        row
                    }
                    _ => {
                        self.state().index.running.shift_remove(&key);
                        continue;
                    }
                };
                if text(&row, "trigger") != "schedule" {
                    continue;
                }
                let run_id = text(&row, "runId").to_string();
                {
                    let st = self.state();
                    if st.in_flight.contains_key(&run_id)
                        || st.orphan_claims.contains(&run_id)
                    {
                        continue;
                    }
                }
                let Some(job) = self.job(text(&row, "jobId")) else {
                    continue;
                };
                if job.kind != Kind::Cluster {
                    continue;
                }
                let schedules = self.schedules();
                if at
                    < num(&row, "startedAt")
                        + schedules.timeout_ms_of(&job)
                        + 1000.0
                {
                    continue;
                }
                if let Some(Slot {
                    slot: Some(slot), ..
                }) = schedules.slot_at(&job, at as i64)
                {
                    if run_id_for(&job.id, &realm_id, slot) == run_id {
                        continue;
                    }
                }
                drop(schedules);
                found.push((realm_id.clone(), row, job));
            }
        }
        for (realm_id, row, job) in found {
            let run_id = text(&row, "runId").to_string();
            self.state().orphan_claims.insert(run_id.clone());
            let Some(me) = self.arc() else {
                return;
            };
            tokio::spawn(async move {
                let answer = me
                    .deps
                    .claims
                    .claim(me.run_scope_of(&job), &run_id, &realm_id, 30_000.0)
                    .await;
                match answer {
                    Ok(claim) => {
                        let stored = me.deps.rows.get(&realm_id, &run_id);
                        if let Some(stored) = stored.filter(|s| {
                            text(s, "state") == "running"
                                && num(s, "fenceAt") == num(&row, "fenceAt")
                        }) {
                            me.record_orphan(&realm_id, &job, &stored);
                        }
                        me.deps.claims.release(&claim.handle).await;
                    }
                    Err(ClaimRefused::Held) => {}
                    Err(ClaimRefused::Store(why)) => tracing::error!(
                        "{}scheduler: run {} of {} could not be checked for an abandoned attempt ({}).",
                        tag(codes::STS_SCHED_0013),
                        run_id,
                        job.id,
                        why
                    ),
                }
                me.state().orphan_claims.remove(&run_id);
            });
        }
    }

    /// Records an orphaned run abandoned, as `abandonOrphans()` does.
    fn record_orphan(&self, realm_id: &str, job: &JobSpec, stored: &Json) {
        let by = [text(stored, "nodeName"), text(stored, "node")]
            .into_iter()
            .find(|s| !s.is_empty())
            .unwrap_or("?")
            .to_string();
        let run_id = text(stored, "runId").to_string();
        self.write_row(
            realm_id,
            assign(
                stored,
                json!({ "state": "abandoned", "endedAt": self.now_ms(),
                        "errorCode": codes::STS_SCHED_0011.as_str(),
                        "why": format!("The attempt on {} (pid {}) stopped holding its claim before it finished, \
                                        and its slot passed; the job's next slot runs instead.", by,
                                       pid_text(stored)),
                        "abandonedOf": run_id }),
            ),
        );
        self.deps.audit.record(json!({
            "action": "scheduler.run", "protocol": "scheduler", "channel": "internal",
            "target": job.id, "errorCode": codes::STS_SCHED_0011.as_str(), "outcome": "failure", "summarised": true,
            "summary": format!("Scheduler run {} of {} was abandoned: its node stopped and its slot passed.",
                               run_id, job.id),
            "detail": { "runId": run_id, "realm": realm_id, "node": stored.get("node"),
                        "pid": stored.get("pid") } }));
        tracing::warn!(
            "{}scheduler: run {} of {} was left running on {} and its slot has passed; it is recorded abandoned.",
            tag(codes::STS_SCHED_0011),
            run_id,
            job.id,
            by
        );
    }

    // ---------------------------------------------------------------------
    // Where a run is claimed, where its body runs, and whether it waits.
    // ---------------------------------------------------------------------

    /// THE SCOPE A RUN IS CLAIMED UNDER (#98, `runScopeOf()`): a job whose
    /// work is the global tier's claims its run under [`GLOBAL_RUN_SCOPE`]
    /// when the service is deployed as cells, so one cell runs each slot.
    fn run_scope_of(&self, job: &JobSpec) -> &'static str {
        let multi = self.extras.cells_multi.as_ref().is_some_and(|f| f());
        if multi && GLOBAL_JOBS.contains(&job.id.as_str()) {
            GLOBAL_RUN_SCOPE
        } else {
            RUN_SCOPE
        }
    }

    /// The loads a cluster run's body would meet (`runnerFor()` and its
    /// `workers()`): none for a per-process job, a job on the front, or a
    /// process with no [`Loads`] — then the run is "on the front" and never
    /// held.
    fn loads_for(&self, job: &JobSpec) -> Option<Vec<WorkerLoad>> {
        if job.kind == Kind::PerProcess || job.on_front.is_some() {
            return None;
        }
        let loads = self.extras.loads.as_ref()?.workers();
        (!loads.is_empty()).then_some(loads)
    }

    /// Whether a worker is too busy for a patient run (`isHeavy()`): either
    /// signal will do, and 0 switches a signal off (read directly — 0 is
    /// legal, the root CLAUDE.md's `|| n` rule).
    fn is_heavy(&self, load: &WorkerLoad) -> bool {
        let s = self.schedules();
        let busy = s.setting_number("scheduler.niceBusyThreshold");
        let lag = s.setting_number("scheduler.niceLagMs");
        (busy > 0.0 && load.in_flight >= busy)
            || (lag > 0.0 && load.lag_ms.is_some_and(|l| l >= lag))
    }

    /// The longest a run of this job is held (`holdBoundMs()`): its share
    /// of `scheduler.niceMaxDeferS`, and never more than half its interval
    /// — a job held longer could meet its next slot still waiting.
    fn hold_bound_ms(&self, job: &JobSpec, nice: f64) -> f64 {
        let s = self.schedules();
        let max = s.setting_number("scheduler.niceMaxDeferS").max(0.0) * 1000.0;
        let mut bound = (max * nice.min(MAX_NICE) / MAX_NICE).floor();
        if let Some(slot) = s.slot_at(job, self.now_ms() as i64) {
            if let (Some(next), Some(start)) = (slot.next_at, slot.starts_at) {
                if next > start {
                    bound = bound.min(((next - start) / 2.0).floor());
                }
            }
        }
        bound
    }

    /// A RUN HELD FOR LOAD, AND NEVER FOR LONG — "nice" (#408,
    /// `holdForLoad()`). A due SCHEDULED run waits while even the
    /// least-loaded worker is heavy, for at most [`Self::hold_bound_ms`]
    /// measured from when it was FIRST held; past that it runs whatever the
    /// load, because a job that never ran because the service was always
    /// busy would be a security control silently off. Never held: a manual
    /// run, an on-demand job, a job of nice 0, a job on the front, and every
    /// run where there is no [`Loads`]. The hold happens BEFORE the claim,
    /// so a held run is still due at the next tick.
    fn hold_for_load(&self, job: &JobSpec, row: &Json) -> bool {
        let nice = job.nice_of();
        if text(row, "trigger") != "schedule"
            || job.manual_only()
            || nice <= 0.0
        {
            return false;
        }
        let Some(loads) = self.loads_for(job) else {
            return false;
        };
        let best_id = least_loaded(&loads);
        let Some(best) = loads.iter().find(|w| Some(w.id) == best_id) else {
            return false;
        };
        let run_id = text(row, "runId").to_string();
        let now = self.deps.clock.now();
        let held = self.state().held_since.get(&run_id).copied();
        let job_id = &job.id;
        let lag_clause = best
            .lag_ms
            .map_or(String::new(), |l| format!(", a {} ms loop delay", l));
        if !self.is_heavy(best) {
            if let Some(since) = held {
                let mut st = self.state();
                st.held_since.remove(&run_id);
                st.deferred_ms
                    .insert(run_id.clone(), (now - since).max(0.0));
                drop(st);
                tracing::info!(
                    "scheduler: run {} of {} was held {} ms for load and now runs.",
                    run_id,
                    job_id,
                    now - since
                );
            }
            return false;
        }
        let bound = self.hold_bound_ms(job, nice);
        let since = held.unwrap_or(now);
        if held.is_none() {
            self.state().held_since.insert(run_id.clone(), since);
        }
        let waited = now - since;
        if waited >= bound {
            let mut st = self.state();
            st.held_since.remove(&run_id);
            st.deferred_ms.insert(run_id.clone(), waited.max(0.0));
            drop(st);
            // NOT A FAILURE, so no code: the bound doing its job.
            tracing::info!(
                "scheduler: run {} of {} runs although every request worker is busy (the least loaded has {} \
                 in flight{}): it was held {} ms, its bound (nice {}).",
                run_id,
                job_id,
                best.in_flight,
                lag_clause,
                waited,
                nice
            );
            return false;
        }
        if held.is_none() {
            tracing::info!(
                "scheduler: run {} of {} is held for load: the least loaded request worker has {} in \
                 flight{}. It runs when one is lighter, or in {} ms at most (nice {}).",
                run_id,
                job_id,
                best.in_flight,
                lag_clause,
                bound,
                nice
            );
        }
        true
    }

    // ---------------------------------------------------------------------
    // The current slots, learnt without holding the history (#883).
    // ---------------------------------------------------------------------

    /// Each realm's current and previous interval slot ids, ONE GROUP PER
    /// JOB, so a read that fails can be asked again job by job
    /// (`slotIdsAt()`). A cron job's rows have no expiry and stay restored,
    /// so it is not asked.
    fn slot_ids_at(&self, at: f64) -> IndexMap<String, Vec<Vec<String>>> {
        let mut by_realm: IndexMap<String, Vec<Vec<String>>> = IndexMap::new();
        for job in self.jobs_of(Kind::Cluster) {
            let slot = {
                let s = self.schedules();
                if job.cron().is_some()
                    || job.manual_only()
                    || !s.service_off_reason(&job).is_empty()
                {
                    continue;
                }
                s.slot_at(&job, at as i64)
            };
            let Some(Slot { slot: Some(n), .. }) = slot else {
                continue;
            };
            if n < 0 {
                continue;
            }
            for realm_id in self.realm_ids_for(&job) {
                if !self.schedules().own_off_reason(&job, &realm_id).is_empty()
                {
                    continue;
                }
                let mut ids = vec![run_id_for(&job.id, &realm_id, n)];
                if n > 0 {
                    ids.push(run_id_for(&job.id, &realm_id, n - 1));
                }
                by_realm.entry(realm_id).or_default().push(ids);
            }
        }
        by_realm
    }

    /// WHAT THE STORE SAYS OF THE CURRENT SLOTS, ONE JOB'S FAILURE ITS OWN
    /// (#883 and its review, `recallFinishedSlots()`). An absence is
    /// remembered whatever said it; a read that fails holds back its own
    /// jobs, not the tick: a realm's batch that fails is asked again one job
    /// at a time, a job whose read still fails is held back this tick
    /// (neither run twice nor taken as finished), and two job reads failing
    /// in a row is an outage — the rest of the tick asks nothing more.
    async fn recall_finished_slots(&self, at: f64) {
        self.state().index.unknown_slots.clear();
        let needed = self.slot_ids_at(at);
        let keep: std::collections::HashSet<String> =
            needed.values().flatten().flatten().cloned().collect();
        self.state().index.prune_slots(&keep);
        // No reader: the map is the only copy. Do not touch it here.
        let Some(history) = self.extras.history.clone() else {
            return;
        };
        let mut held_back: Vec<String> = Vec::new();
        let mut first_why = String::new();
        let mut outage = false;
        for (realm_id, groups) in needed {
            let groups: Vec<Vec<String>> = {
                let st = self.state();
                groups
                    .into_iter()
                    .map(|ids| {
                        ids.into_iter()
                            .filter(|id| {
                                !(self.deps.rows.get(&realm_id, id).is_some()
                                    || st.index.finished_slots.contains(id)
                                    || st.index.slot_asked.contains(id))
                            })
                            .collect::<Vec<_>>()
                    })
                    .filter(|ids| !ids.is_empty())
                    .collect()
            };
            if groups.is_empty() {
                continue;
            }
            if outage {
                for ids in &groups {
                    self.hold_back_slot(ids, &mut held_back);
                }
                continue;
            }
            let ask: Vec<String> = groups.iter().flatten().cloned().collect();
            match history.read_runs(&realm_id, ask.clone()).await {
                Ok(got) => {
                    self.learn_slots(&realm_id, &ask, got);
                    continue;
                }
                Err(e) => {
                    if first_why.is_empty() {
                        first_why = e.trim_end_matches('.').to_string();
                    }
                }
            }
            if groups.len() == 1 {
                self.hold_back_slot(&groups[0], &mut held_back);
                continue;
            }
            let mut failed_in_a_row = 0;
            for ids in &groups {
                if failed_in_a_row >= 2 {
                    self.hold_back_slot(ids, &mut held_back);
                    continue;
                }
                match history.read_runs(&realm_id, ids.clone()).await {
                    Ok(got) => {
                        self.learn_slots(&realm_id, ids, got);
                        failed_in_a_row = 0;
                    }
                    Err(e) => {
                        if first_why.is_empty() {
                            first_why = e.trim_end_matches('.').to_string();
                        }
                        failed_in_a_row += 1;
                        self.hold_back_slot(ids, &mut held_back);
                    }
                }
            }
            if failed_in_a_row >= 2 {
                outage = true;
            }
        }
        if !held_back.is_empty() {
            tracing::error!(
                "{}scheduler: the store could not say whether {} run(s) of the current slot had already run \
                 ({}), so they were held back this tick and are asked about again at the next; every other \
                 run went on. Held back: {}{}.",
                tag(codes::STS_SCHED_0023),
                held_back.len(),
                first_why,
                held_back.iter().take(10).cloned().collect::<Vec<_>>().join(", "),
                if held_back.len() > 10 { ", and more" } else { "" }
            );
        }
    }

    /// What one read answered about some slot ids (`learnSlots()`). `None`
    /// is no store: an absence all the same, remembered for the slot.
    fn learn_slots(
        &self,
        realm_id: &str,
        ask: &[String],
        got: Option<HashMap<String, Json>>,
    ) {
        let Some(got) = got else {
            let mut st = self.state();
            for id in ask {
                st.index.slot_asked.insert(id.clone());
            }
            return;
        };
        for id in ask {
            match got.get(id) {
                None => {
                    self.state().index.slot_asked.insert(id.clone());
                }
                Some(row)
                    if text(row, "kind") == "run"
                        && FINAL.contains(&text(row, "state")) =>
                {
                    let mut st = self.state();
                    st.index.finished_slots.insert(id.clone());
                    st.index.note_latest(realm_id, row);
                }
                Some(row) => self.admit_recalled(realm_id, id, row),
            }
        }
    }

    /// A running or queued row the read found (`admitRecalled()`): not
    /// journalled, it is already in the store.
    fn admit_recalled(&self, realm_id: &str, run_id: &str, row: &Json) {
        let mut copy = row.clone();
        if text(&copy, "runId").is_empty() {
            copy = assign(&copy, json!({ "runId": run_id }));
        }
        match &self.extras.history {
            Some(h) => h.restore_row(realm_id, run_id, copy.clone()),
            None => self.deps.rows.set(realm_id, run_id, copy.clone()),
        }
        self.state().index.note(realm_id, &copy);
    }

    /// One job's current slot held back for this tick (`holdBackSlot()`).
    /// The previous slot's id only feeds the page, so it is neither held nor
    /// named.
    fn hold_back_slot(&self, ids: &[String], held_back: &mut Vec<String>) {
        if let Some(first) = ids.first() {
            self.state().index.unknown_slots.insert(first.clone());
            held_back.push(first.clone());
        }
    }

    /// A finished interval body this process wrote, once the flush has it
    /// (`releaseFinishedHistory()`). A key still journalled stays.
    fn release_finished_history(&self) {
        let Some(history) = self.extras.history.clone() else {
            return;
        };
        if !history.persisted() {
            return;
        }
        let keys: Vec<String> =
            self.state().index.held_finished.iter().cloned().collect();
        for key in keys {
            let Some((realm_id, run_id)) = key.split_once('\n') else {
                self.state().index.held_finished.shift_remove(&key);
                continue;
            };
            if self.deps.rows.get(realm_id, run_id).is_none()
                || history.drop_held(realm_id, run_id)
            {
                self.state().index.held_finished.shift_remove(&key);
            }
        }
    }

    /// The latest finished run of each job in each realm the index holds
    /// (#883's `latestRun`), for the page's last-run figure.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn latest_runs(&self) -> Vec<Json> {
        self.state().index.latest_run.values().cloned().collect()
    }

    /// Every queued manual run in every realm, oldest first — from the
    /// index of the rows a tick has to see (#623), never a read of the
    /// history.
    fn queued_manual_runs(&self) -> Vec<(String, Json)> {
        let mut out: Vec<(String, Json)> = self
            .pending()
            .into_iter()
            .filter(|(_, row)| text(row, "kind") == "run")
            .collect();
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
        // ONE RUN OF A JOB IN A REALM AT A TIME (Node's #1757, rcbj
        // 2026-11-15). A manual run and the scheduled run of the same job in
        // the same realm have different ids, so each won its own claim and
        // the two bodies overlapped. Beside the run's own claim a run holds
        // one more of the same kind, `exclusive|<job>|<realm>`, for its time
        // limit, and gives it back when it ends. A run that cannot have it
        // WAITS: it is not claimed, so it is still due at the next tick.
        // Here first, with no round trip, for a run this process is already
        // attempting or running; the claim decides between nodes.
        let exclusive_key = format!("{}|{}", job.id, realm_id);
        {
            let mut st = self.state();
            if st.in_flight.contains_key(&run_id) {
                return;
            }
            let holder = st.exclusive_holders.get(&exclusive_key).cloned();
            if let Some(holder) = holder.filter(|h| *h != run_id) {
                drop(st);
                self.note_exclusive_wait(&job, &realm_id, &row, &holder);
                return;
            }
            st.exclusive_holders
                .insert(exclusive_key.clone(), run_id.clone());
            // Held while the claim is asked, so the next tick does not ask.
            st.in_flight
                .insert(run_id.clone(), Arc::new(Flight::new(&realm_id)));
        }
        let Some(me) = self.arc() else {
            return;
        };
        let scope = self.run_scope_of(&job);
        tokio::spawn(async move {
            let answer = me
                .deps
                .claims
                .claim(scope, &run_id, &realm_id, timeout_ms + 1000.0)
                .await;
            let drop_holder = |me: &Scheduler| {
                let mut st = me.state();
                if st.exclusive_holders.get(&exclusive_key) == Some(&run_id) {
                    st.exclusive_holders.remove(&exclusive_key);
                }
            };
            match answer {
                Err(refused) => {
                    drop_holder(&me);
                    me.state().in_flight.remove(&run_id);
                    // THE CELL THAT LOSES A GLOBAL JOB'S CLAIM NEVER SEES THE
                    // RUN END (#98): the winner writes the run's row in its
                    // OWN database, so here it stays due, first in every
                    // tick's line, each ask holding a place under the cap.
                    // The claim cannot be won before its lifetime ends, so
                    // it is not asked for until then.
                    if matches!(refused, ClaimRefused::Held)
                        && scope != RUN_SCOPE
                    {
                        let until = me.now_ms() + timeout_ms + 1000.0;
                        me.state()
                            .claimed_by_another_cell
                            .insert(run_id.clone(), until);
                    }
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
                    let exclusive = me
                        .deps
                        .claims
                        .claim(
                            scope,
                            &format!("exclusive|{}", exclusive_key),
                            &realm_id,
                            timeout_ms + 1000.0,
                        )
                        .await;
                    match exclusive {
                        Err(refused) => {
                            // The run's own claim goes back, so the run can
                            // be attempted again once the other one ended.
                            drop_holder(&me);
                            me.state().in_flight.remove(&run_id);
                            me.deps.claims.release(&claim.handle).await;
                            if let ClaimRefused::Store(why) = refused {
                                tracing::warn!(
                                    "{}scheduler: the claim store could not \
                                     be asked about run {} of {} ({}). It is \
                                     not started until it can be.",
                                    tag(codes::STS_SCHED_0008),
                                    run_id,
                                    job.id,
                                    why
                                );
                            } else {
                                me.note_exclusive_wait(
                                    &job, &realm_id, &row, "",
                                );
                            }
                        }
                        Ok(held) => {
                            me.run_claimed(
                                job,
                                realm_id,
                                row,
                                claim,
                                timeout_ms,
                                Some(held.handle),
                            )
                            .await
                        }
                    }
                }
            }
        });
    }

    /// `noteExclusiveWait(job, realm, row, holder)` (Node's #1757): a run
    /// that waits for another run of its job in its realm, recorded once
    /// per run — one info line with STS-SCHED-0024, and on a manual run's
    /// queued row the code and the reason, until it runs. A scheduled run's
    /// row is not written while it waits: it is not stored until it starts.
    fn note_exclusive_wait(
        &self,
        job: &JobSpec,
        realm_id: &str,
        row: &Json,
        holder: &str,
    ) {
        let run_id = text(row, "runId").to_string();
        self.state().waiting = true;
        let why = format!(
            "Another run of {}{}{} was still running; this run waits until \
             it ends.",
            job.id,
            if realm_id != DEFAULT_ID {
                format!(" in \"{}\"", realm_id)
            } else {
                String::new()
            },
            if holder.is_empty() {
                " on another node".to_string()
            } else {
                format!(" ({})", holder)
            }
        );
        if text(row, "trigger") == "manual" && text(row, "state") == "queued" {
            if let Some(stored) = self.deps.rows.get(realm_id, &run_id) {
                if text(&stored, "state") == "queued"
                    && text(&stored, "errorCode")
                        != codes::STS_SCHED_0024.as_str()
                {
                    self.write_row(
                        realm_id,
                        assign(
                            &stored,
                            json!({ "errorCode": codes::STS_SCHED_0024.as_str(),
                                    "why": why }),
                        ),
                    );
                }
            }
        }
        if self.state().exclusive_noted.insert(run_id.clone()) {
            tracing::info!(
                "{}scheduler: run {} of {} waits: {}",
                tag(codes::STS_SCHED_0024),
                run_id,
                job.id,
                why
            );
        }
    }

    /// The run's hold on its job in its realm (#1757), given back however
    /// the run ends, so the run that waited for it starts at the next tick.
    async fn give_back_exclusive(
        &self,
        job: &JobSpec,
        realm_id: &str,
        run_id: &str,
        handle: &Option<Json>,
    ) {
        let key = format!("{}|{}", job.id, realm_id);
        {
            let mut st = self.state();
            if st.exclusive_holders.get(&key).map(String::as_str)
                == Some(run_id)
            {
                st.exclusive_holders.remove(&key);
            }
        }
        if let Some(h) = handle {
            self.deps.claims.release(h).await;
        }
    }

    async fn run_claimed(
        &self,
        job: JobSpec,
        realm_id: String,
        row: Json,
        claim: Claim,
        timeout_ms: f64,
        exclusive: Option<Json>,
    ) {
        let run_id = text(&row, "runId").to_string();
        // A realm removed between the tick and the claim: nothing is run
        // for it (it once ran in the default realm instead).
        if !self.realm_defined(&realm_id) {
            self.state().in_flight.remove(&run_id);
            self.deps.claims.release(&claim.handle).await;
            self.give_back_exclusive(&job, &realm_id, &run_id, &exclusive)
                .await;
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
                            "endedAt": self.now_ms(), "errorCode": codes::STS_SCHED_0011.as_str(),
                            "why": format!("The attempt on {} (pid {}) stopped holding its claim before it \
                                            finished; attempt {} took it over.", by,
                                           stored.get("pid").cloned().unwrap_or(Json::Null), attempt + 1.0),
                            "abandonedOf": run_id }),
                ),
            );
            self.deps.audit.record(json!({
                "action": "scheduler.run", "protocol": "scheduler", "channel": "internal",
                "target": job.id, "errorCode": codes::STS_SCHED_0011.as_str(), "outcome": "failure", "summarised": true,
                "summary": format!("Scheduler run {} of {} was abandoned and taken over.", run_id, job.id),
                "detail": { "runId": run_id, "realm": realm_id, "node": stored.get("node"),
                            "pid": stored.get("pid") } }));
        }
        // WHERE THE BODY RUNS (#408), decided now rather than at the tick,
        // so the load it is decided on is the load the run meets. In Rust a
        // body is always a task on the runtime's worker threads; `worker` is
        // written when the runtime said how busy they are, as Node writes it
        // for a body handed to a worker, and `front` otherwise.
        let target = self.loads_for(&job).and_then(|l| least_loaded(&l));
        let held_ms = self.state().deferred_ms.remove(&run_id).unwrap_or(0.0);
        let running = assign(
            &stored,
            json!({ "state": "running", "fenceAt": fence, "attempt": num(&stored, "attempt") + 1.0,
                    "node": node, "nodeName": name, "host": self.deps.host, "pid": self.deps.pid,
                    "startedAt": self.now_ms(), "endedAt": 0, "errorCode": "", "why": "",
                    "result": null, "takenOver": text(&stored, "state") == "running",
                    "ranIn": if target.is_some() { "worker" } else { "front" },
                    "deferredMs": held_ms }),
        );
        self.write_row(&realm_id, running.clone());
        let flight = Arc::new(Flight::new(&realm_id));
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
                        && flight.switched_off().is_empty()
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
            self.give_back_exclusive(&job, &realm_id, &run_id, &exclusive)
                .await;
            return;
        };
        // Its own task: a run past its time limit is fenced out, not
        // cancelled mid-step, and the scheduler does not wait on it.
        let work = tokio::spawn(realm::run(realm, run(ctx)));
        // THE RUN'S WATCH (#1305, `watchRun()`): every RUN_CHECK_MS, whether
        // the job was switched off while it runs. Not a failure: the body is
        // told it no longer owns the run (`still_owner`) and stops at its
        // next step, and the row says why it may have done less. A check
        // inside one operation, which ends with it, not a periodic job.
        let watch = {
            let (me, job, flight, run_id) =
                (me.clone(), job.clone(), flight.clone(), run_id.clone());
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(
                        RUN_CHECK_MS,
                    ))
                    .await;
                    if !flight.switched_off().is_empty() {
                        continue;
                    }
                    let off = me.schedules().service_off_reason(&job);
                    if !off.is_empty() {
                        tracing::info!(
                            "scheduler: {} was switched off ({}) while run {} ran; it no longer owns the run, \
                             and stops at its next step.",
                            job.id,
                            off.trim_end_matches('.'),
                            run_id
                        );
                        *flight
                            .switched_off
                            .lock()
                            .unwrap_or_else(|p| p.into_inner()) = off;
                    }
                }
            })
        };
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
        watch.abort();
        if outcome.is_err() {
            flight.timed_out.store(true, Ordering::SeqCst);
        }
        {
            self.state().in_flight.remove(&run_id);
        }
        self.give_back_exclusive(&job, &realm_id, &run_id, &exclusive)
            .await;
        let waiting = {
            let st = self.state();
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
                codes::STS_SCHED_0002.as_str()
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
                codes::STS_SCHED_0001.as_str()
            }
            Ok(Ok(result)) => {
                fields.insert("state".into(), json!("succeeded"));
                fields.insert("result".into(), summary_of(&result));
                // A SUCCESS THAT DID LESS THAN A WHOLE RUN SAYS SO (#1313).
                fields.insert("why".into(), json!(why_of(&result)));
                ""
            }
        };
        // SWITCHED OFF WHILE IT RAN (#1305): not a failure, but the row says
        // why it may have done less than a whole run.
        let switched = flight.switched_off();
        if !switched.is_empty() {
            let why = fields.get("why").and_then(Json::as_str).unwrap_or("");
            if why.is_empty() || error_code.is_empty() {
                let text = format!(
                    "It was switched off while it ran ({}), and its body was told it no longer owned the run.{}",
                    switched.trim_end_matches('.'),
                    if why.is_empty() {
                        String::new()
                    } else {
                        format!(" {}", why)
                    }
                );
                fields.insert("why".into(), json!(text));
            }
        }
        fields.insert("errorCode".into(), json!(error_code));
        let last = assign(&live, Json::Object(fields));
        let last = self.write_row(&realm_id, last);
        let state = text(&last, "state").to_string();
        // A success is the run row (#1263): the audit row is what the syslog
        // destination exports, so a run that succeeded writes none. A
        // failure does, and an abandonment is recorded where it is found.
        if error_code.is_empty() {
            return;
        }
        self.deps.audit.record(json!({
            "action": "scheduler.run", "protocol": "scheduler", "channel": "internal", "target": job.id,
            "errorCode": error_code, "outcome": "failure",
            "summarised": true,
            "summary": format!("Scheduler run {} of {}{} {} ({}, attempt {}).", run_id, job.id,
                               if realm_id != DEFAULT_ID { format!(" in \"{}\"", realm_id) } else { String::new() },
                               state, text(&last, "trigger"), num(&last, "attempt")),
            "detail": { "runId": run_id, "realm": realm_id, "trigger": last.get("trigger"),
                        "attempt": last.get("attempt"), "durationMs": last.get("durationMs"),
                        "why": text(&last, "why") } }));
        tracing::warn!(
            "{}scheduler: {} failed: {}",
            tag(error_code),
            job.id,
            text(&last, "why")
        );
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
        st.index.forget_realm(realm_id);
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
                ("failed", codes::STS_SCHED_0015.as_str(), e, Json::Null)
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
                error_code: codes::STS_SCHED_0004,
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
                error_code: codes::STS_SCHED_0005,
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
                error_code: codes::STS_SCHED_0012,
                status: 400,
                why: format!("There is no realm \"{}\".", realm_id),
            });
        }
        let off = self.schedules().off_reason(&job, &realm_id);
        if !off.is_empty() {
            return Err(Refusal {
                error_code: codes::STS_SCHED_0006,
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
                error_code: codes::STS_SCHED_0010,
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
        // From the index (#623): this read the default realm's whole
        // partition — every service job's run history — at every tick.
        let queued: Vec<Json> = self
            .pending()
            .into_iter()
            .filter(|(realm, r)| {
                realm == DEFAULT_ID && text(r, "kind") == "command"
            })
            .map(|(_, r)| r)
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
