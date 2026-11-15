// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Several nodes against one store (`cluster/cluster.js` and
//! `cluster/cluster_claims.js`, #46): membership, leases with a fencing
//! token, and atomic single-use claims.
//!
//! * **Membership is a row with a lifetime, renewed by a heartbeat.** A node
//!   whose row had already expired when it renewed may have had its leases
//!   taken; it does not come back from that — it STOPS (`STS-CLUSTER-0005`).
//!   Nor does one that has not renewed for its lifetime less a heartbeat
//!   (`STS-CLUSTER-0004`): the others may already treat it as dead.
//! * **A lease is held by a live member, with a token that moves on every
//!   change of hands**, so a write fenced by the token is refused once
//!   another node holds it. A renewal that comes back without a lease this
//!   node held means it was lost: the role's `on_lose` is called. Every
//!   heartbeat campaigns for every role not held.
//! * **Standing down** releases a lease at this node's token and does not
//!   ask for it again for a hold-off (three heartbeats by default).
//! * **A claim is single-use for its lifetime**: the first taker wins, a
//!   later one is told who holds it, and only the holder's reservation can
//!   release it. Its time is the DATABASE's, which is what a run's fence is.
//!
//! [`ClusterStore`] is the contract the store answers; [`MemoryClusterStore`]
//! keeps the postgres driver's SQL rules in memory, for one process and for
//! tests of several. The postgres driver is a later piece.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError, Weak};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value as Json};
use sts_core::errors::{codes, ErrorCode};
use sts_core::log::tag;
use sts_crypto::jws_alg::Hash;
use sts_crypto::random::random_bytes;
use tokio::time::{Duration, Instant};

use crate::schedule::BoxFuture;
use crate::scheduler::{
    Claim, ClaimRefused, Claims, Clock, Cluster, LeaseHandler,
};

/// The longest a claim may be held.
pub const MAX_CLAIM_TTL_MS: f64 = 30.0 * 24.0 * 60.0 * 60.0 * 1000.0;

/// What a heartbeat found.
#[derive(Clone, Debug, PartialEq)]
pub struct Renewal {
    /// The membership row was live when renewed.
    pub alive: bool,
    /// The leases this node still holds, by name, at their tokens.
    pub leases: Vec<(String, u64)>,
}

/// What asking for a lease found.
#[derive(Clone, Debug, PartialEq)]
pub struct LeaseAnswer {
    pub held: bool,
    pub token: u64,
    pub holder: String,
}

/// What asking for a claim found.
#[derive(Clone, Debug, PartialEq)]
pub enum ClaimAnswer {
    Claimed {
        claimed_at: f64,
    },
    Used {
        origin: String,
        claimed_at: f64,
        expires_at: f64,
    },
}

/// What the store answers for the cluster.
pub trait ClusterStore: Send + Sync {
    /// The database's clock.
    fn now(&self) -> BoxFuture<'_, Result<f64, String>>;
    fn join(
        &self,
        node: &str,
        ttl_ms: f64,
        info: Json,
    ) -> BoxFuture<'_, Result<(), String>>;
    fn heartbeat(
        &self,
        node: &str,
        ttl_ms: f64,
    ) -> BoxFuture<'_, Result<Renewal, String>>;
    fn acquire_lease(
        &self,
        name: &str,
        node: &str,
        ttl_ms: f64,
    ) -> BoxFuture<'_, Result<LeaseAnswer, String>>;
    fn release_lease(
        &self,
        name: &str,
        node: &str,
        token: u64,
    ) -> BoxFuture<'_, Result<bool, String>>;
    fn leave(&self, node: &str) -> BoxFuture<'_, Result<(), String>>;
    fn claim_once(
        &self,
        scope: &str,
        realm: &str,
        key: &str,
        ttl_ms: f64,
        reservation: &str,
        origin: &str,
    ) -> BoxFuture<'_, Result<ClaimAnswer, String>>;
    fn release_claim(
        &self,
        scope: &str,
        realm: &str,
        key: &str,
        reservation: &str,
    ) -> BoxFuture<'_, Result<bool, String>>;
}

/// (scope, realm, key) of a claim.
type ClaimKey = (String, String, String);
/// (reservation, origin, claimed_at, expires_at) of a claim.
type ClaimRow = (String, String, f64, f64);

#[derive(Default)]
struct Tables {
    /// node → (expires_at, left)
    nodes: HashMap<String, (f64, bool)>,
    /// lease → (holder, token, expires_at)
    leases: HashMap<String, (String, u64, f64)>,
    /// (scope, realm, key) → (reservation, origin, claimed_at, expires_at)
    claims: HashMap<ClaimKey, ClaimRow>,
}

/// The postgres driver's cluster tables, in memory, on a clock the caller
/// gives (a test moves it; a single process passes the wall clock).
pub struct MemoryClusterStore {
    tables: Mutex<Tables>,
    clock: Arc<dyn Fn() -> f64 + Send + Sync>,
    failing: Mutex<Option<String>>,
}

impl MemoryClusterStore {
    pub fn new(
        clock: Arc<dyn Fn() -> f64 + Send + Sync>,
    ) -> Arc<MemoryClusterStore> {
        Arc::new(MemoryClusterStore {
            tables: Mutex::new(Tables::default()),
            clock,
            failing: Mutex::new(None),
        })
    }

    /// For tests: every call fails with `why` until cleared.
    pub fn fail_with(&self, why: Option<&str>) {
        *self.failing.lock().unwrap_or_else(PoisonError::into_inner) =
            why.map(str::to_string);
    }

    fn check(&self) -> Result<(), String> {
        match self
            .failing
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            Some(why) => Err(why.clone()),
            None => Ok(()),
        }
    }

    fn tables(&self) -> std::sync::MutexGuard<'_, Tables> {
        self.tables.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn answer<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Tables, f64) -> T,
    ) -> BoxFuture<'_, Result<T, String>> {
        let out = self.check().map(|()| {
            let now = (self.clock)();
            f(&mut self.tables(), now)
        });
        Box::pin(async move { out })
    }
}

impl ClusterStore for MemoryClusterStore {
    fn now(&self) -> BoxFuture<'_, Result<f64, String>> {
        self.answer(|_, now| now)
    }

    fn join(
        &self,
        node: &str,
        ttl_ms: f64,
        _info: Json,
    ) -> BoxFuture<'_, Result<(), String>> {
        let node = node.to_string();
        self.answer(move |t, now| {
            t.nodes.insert(node, (now + ttl_ms, false));
        })
    }

    fn heartbeat(
        &self,
        node: &str,
        ttl_ms: f64,
    ) -> BoxFuture<'_, Result<Renewal, String>> {
        let node = node.to_string();
        self.answer(move |t, now| {
            let alive = match t.nodes.get_mut(&node) {
                Some((expires, left)) if !*left && *expires > now => {
                    *expires = now + ttl_ms;
                    true
                }
                _ => false,
            };
            let mut leases = Vec::new();
            if alive {
                for (name, (holder, token, expires)) in t.leases.iter_mut() {
                    if *holder == node && *expires > now {
                        *expires = now + ttl_ms;
                        leases.push((name.clone(), *token));
                    }
                }
            }
            leases.sort();
            Renewal { alive, leases }
        })
    }

    fn acquire_lease(
        &self,
        name: &str,
        node: &str,
        ttl_ms: f64,
    ) -> BoxFuture<'_, Result<LeaseAnswer, String>> {
        let (name, node) = (name.to_string(), node.to_string());
        self.answer(move |t, now| {
            let member = t
                .nodes
                .get(&node)
                .is_some_and(|(e, left)| !*left && *e > now);
            let current = t.leases.get(&name).cloned();
            let free = current.as_ref().is_none_or(|(holder, _, expires)| {
                *expires <= now || *holder == node
            });
            if member && free {
                let token = match &current {
                    None => 1,
                    Some((holder, token, expires))
                        if *holder == node && *expires > now =>
                    {
                        *token
                    }
                    Some((_, token, _)) => token + 1,
                };
                t.leases.insert(name, (node.clone(), token, now + ttl_ms));
                return LeaseAnswer {
                    held: true,
                    token,
                    holder: node,
                };
            }
            let (holder, token, _) = current.unwrap_or_default();
            LeaseAnswer {
                held: false,
                token,
                holder,
            }
        })
    }

    fn release_lease(
        &self,
        name: &str,
        node: &str,
        token: u64,
    ) -> BoxFuture<'_, Result<bool, String>> {
        let (name, node) = (name.to_string(), node.to_string());
        self.answer(move |t, _| match t.leases.get_mut(&name) {
            Some((holder, held, expires))
                if *holder == node && *held == token =>
            {
                *expires = 0.0;
                true
            }
            _ => false,
        })
    }

    fn leave(&self, node: &str) -> BoxFuture<'_, Result<(), String>> {
        let node = node.to_string();
        self.answer(move |t, now| {
            if let Some((expires, left)) = t.nodes.get_mut(&node) {
                *left = true;
                *expires = expires.min(now);
            }
            for (holder, _, expires) in t.leases.values_mut() {
                if *holder == node {
                    *expires = 0.0;
                }
            }
        })
    }

    fn claim_once(
        &self,
        scope: &str,
        realm: &str,
        key: &str,
        ttl_ms: f64,
        reservation: &str,
        origin: &str,
    ) -> BoxFuture<'_, Result<ClaimAnswer, String>> {
        let id = (scope.to_string(), realm.to_string(), key.to_string());
        let (reservation, origin) =
            (reservation.to_string(), origin.to_string());
        self.answer(move |t, now| match t.claims.get(&id) {
            Some((_, by, at, expires)) if *expires > now => ClaimAnswer::Used {
                origin: by.clone(),
                claimed_at: *at,
                expires_at: *expires,
            },
            _ => {
                t.claims.insert(
                    id,
                    (reservation, origin, now, now + ttl_ms.max(1.0)),
                );
                ClaimAnswer::Claimed { claimed_at: now }
            }
        })
    }

    fn release_claim(
        &self,
        scope: &str,
        realm: &str,
        key: &str,
        reservation: &str,
    ) -> BoxFuture<'_, Result<bool, String>> {
        let id = (scope.to_string(), realm.to_string(), key.to_string());
        let reservation = reservation.to_string();
        self.answer(move |t, _| {
            let ours =
                t.claims.get(&id).is_some_and(|(r, ..)| *r == reservation);
            if ours {
                t.claims.remove(&id);
            }
            ours
        })
    }
}

/// How a node stops when it must (`failStop()`): the runtime exits; a test
/// records it.
pub type FailStop = Arc<dyn Fn(&'static str, String) + Send + Sync>;

/// The service lease (`SERVICE_LEASE`): held by the one node that serves in
/// active-passive mode.
pub const SERVICE_LEASE: &str = "service";

/// What a node is (`cluster.js`'s `mode()`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClusterMode {
    Off,
    ActivePassive,
    ActiveActive,
}

impl ClusterMode {
    /// The mode's name. A hot path (every status read): no span.
    pub fn as_str(self) -> &'static str {
        match self {
            ClusterMode::Off => "off",
            ClusterMode::ActivePassive => "active-passive",
            ClusterMode::ActiveActive => "active-active",
        }
    }
}

/// The settings `resolve()` reads, as text and flags.
#[derive(Clone, Debug, Default)]
pub struct ModeSettings {
    /// `cluster.mode`: `auto`, `off`, `active-passive` or `active-active`.
    pub cluster_mode: String,
    /// `persistence.mode`.
    pub persistence_mode: String,
    /// `global.mode` is `product`.
    pub product: bool,
    /// `global.mode` as written, for the sentence.
    pub global_mode: String,
    /// `keys.source`.
    pub keys_source: String,
    /// `global.publicBaseUrl`.
    pub public_base_url: String,
    /// `persistence.minted`.
    pub minted: bool,
}

/// A cluster mode the configuration cannot run (`resolve()`'s `refused`).
#[derive(Clone, Debug, PartialEq)]
pub struct ModeRefusal {
    pub code: ErrorCode,
    pub why: String,
}

/// Whether a store mode is a database (`storeModes.isDatabase()`).
fn is_database(store: &str) -> bool {
    matches!(store, "postgres" | "mariadb")
}

/// WHAT MODE THIS NODE IS IN, and the refusals that are about configuration
/// rather than about other nodes (`resolve()`): pure, reads the settings and
/// answers. `auto` is active-passive in product mode on a database store and
/// off everywhere else; a cluster needs a database store (STS-CLUSTER-0007);
/// active-active needs persisted keys (0008) and one public name (0026); any
/// cluster needs minted state persisted (0040).
#[tracing::instrument(level = "debug")]
pub fn resolve_mode(
    s: &ModeSettings,
) -> Result<(ClusterMode, String), ModeRefusal> {
    let configured = if s.cluster_mode.is_empty() {
        "auto"
    } else {
        s.cluster_mode.as_str()
    };
    let store = if s.persistence_mode.is_empty() {
        "memory"
    } else {
        s.persistence_mode.as_str()
    };
    if configured == "off" {
        return Ok((ClusterMode::Off, "cluster.mode is off".to_string()));
    }
    if configured == "auto" {
        if s.product && is_database(store) {
            return Ok((
                ClusterMode::ActivePassive,
                "cluster.mode is auto, and this is product mode on a database store".to_string(),
            ));
        }
        return Ok((
            ClusterMode::Off,
            "cluster.mode is auto, which is off outside product mode on a postgres store".to_string(),
        ));
    }
    let refuse = |code: ErrorCode, why: String| {
        Err(ModeRefusal {
            code,
            why: format!("{}{}", tag(code), why),
        })
    };
    if !is_database(store) {
        return refuse(
            codes::STS_CLUSTER_0007,
            format!(
                "cluster.mode is \"{}\" and persistence.mode is \"{}\". Only a database store (postgres, or \
                 mariadb) can hold a membership table, leases and atomic claims that several containers agree \
                 on. Set persistence.mode=postgres, or cluster.mode=off for one node.",
                configured, store
            ),
        );
    }
    let active_active = configured == "active-active";
    if active_active
        && s.keys_source != "persisted"
        && !(s.keys_source == "auto" && s.product)
    {
        return refuse(
            codes::STS_CLUSTER_0008,
            format!(
                "cluster.mode is active-active and keys are not persisted under an operator key-encryption key \
                 (keys.source={}, global.mode={}). Every node has to sign with the same keys and open the same \
                 sealed rows, and a key generated per process — or a key-encryption key generated per \
                 container, which is what development mode shares between its own workers — is a different \
                 key on every node.",
                s.keys_source, s.global_mode
            ),
        );
    }
    if active_active && s.public_base_url.trim().is_empty() {
        return refuse(
            codes::STS_CLUSTER_0026,
            "cluster.mode is active-active and global.publicBaseUrl is empty. Every node must issue under ONE \
             name — the address clients reach the cluster at (the load balancer) — or a token minted on one \
             node names an issuer and an audience the next node does not answer to. Set \
             global.publicBaseUrl (STS_PUBLIC_BASE_URL) to that address on every node."
                .to_string(),
        );
    }
    if !s.minted {
        return refuse(
            codes::STS_CLUSTER_0040,
            format!(
                "cluster.mode is {} and persistence.minted is off, so every node would keep its own sessions, \
                 pending sign-ins, codes and tokens and a flow whose hops land on two nodes would fail. Turn \
                 persistence.minted on, or run one node with cluster.mode=off.",
                configured
            ),
        );
    }
    let mode = if active_active {
        ClusterMode::ActiveActive
    } else {
        ClusterMode::ActivePassive
    };
    Ok((mode, format!("cluster.mode is {}", configured)))
}

/// How long one heartbeat or lease statement may take (`renewalBoundMs()`):
/// a third of the lifetime, at most two seconds, at least a quarter second.
/// A renewal that waits longer is a beat that did not land
/// (STS-CLUSTER-0003), not a membership found dead (#770).
#[tracing::instrument(level = "debug")]
pub fn renewal_bound_ms(ttl_ms: f64) -> f64 {
    let ttl = if ttl_ms > 0.0 { ttl_ms } else { 30000.0 }.max(1000.0);
    (ttl / 3.0).floor().clamp(250.0, 2000.0)
}

tokio::task_local! {
    /// The leases a lease-guarded write in progress is fenced by
    /// (`leaseContext`, an AsyncLocalStorage in Node).
    static LEASE_CONTEXT: Vec<(String, u64)>;
}

/// The fence a write transaction is checked against (`fenceFor()`): the
/// membership row must be live, and every lease named still held at its
/// token.
#[derive(Clone, Debug, PartialEq)]
pub struct Fence {
    pub node_id: String,
    pub leases: Vec<(String, u64)>,
}

/// Why a write was fenced (`err.reason`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FenceReason {
    /// The membership row was dead.
    Node,
    /// A lease the write named had changed hands.
    Lease,
}

#[derive(Default)]
struct NodeState {
    roles: HashMap<String, Arc<dyn LeaseHandler>>,
    held: HashMap<String, u64>,
    standing_down_until: HashMap<String, Instant>,
    last_renew_ok: Option<Instant>,
    stopping: bool,
    joined: bool,
    clock_offset: f64,
    heartbeat: Option<tokio::task::JoinHandle<()>>,
    /// A renewal is still running (`heartbeatInFlight`).
    renewing: bool,
    /// A contention is still asking (`contending`).
    contending: bool,
    /// The last stall of a heartbeat or more: how long, and when.
    last_stall: Option<(f64, Instant)>,
    /// Leases whose takeover waits on the previous holder's writes, so
    /// STS-CLUSTER-0165 is said once per wait.
    pending_takeovers: std::collections::HashSet<String>,
    /// What else renews on the heartbeat ([`ClusterNode::on_beat`]).
    beat_hooks: Vec<BeatHook>,
}

/// A renewal that rides on the heartbeat: run beside each beat, never
/// awaited by it.
pub type BeatHook = Arc<dyn Fn() -> BoxFuture<'static, ()> + Send + Sync>;

/// One node of a clustered service.
pub struct ClusterNode {
    store: Arc<dyn ClusterStore>,
    node_id: String,
    name: String,
    heartbeat_ms: f64,
    ttl_ms: f64,
    mode: Mutex<ClusterMode>,
    fail_stop: FailStop,
    state: Mutex<NodeState>,
    me: Weak<ClusterNode>,
}

/// A single-use value's stored form: SHA-256 of `scope \n value`.
pub fn claim_digest(scope: &str, value: &str) -> String {
    URL_SAFE_NO_PAD
        .encode(Hash::Sha256.digest(format!("{}\n{}", scope, value).as_bytes()))
}

fn random_reservation() -> String {
    match random_bytes(12) {
        Ok(buf) => URL_SAFE_NO_PAD.encode(buf),
        Err(e) => {
            tracing::error!(
                "cluster: no random bytes for a claim's reservation: {}",
                e
            );
            URL_SAFE_NO_PAD.encode([0u8; 12])
        }
    }
}

impl ClusterNode {
    /// A node of `name`; `heartbeat_ms` floored at 250 and `ttl_ms` at three
    /// heartbeats, as Node floors them.
    pub fn new(
        store: Arc<dyn ClusterStore>,
        node_id: &str,
        name: &str,
        heartbeat_ms: f64,
        ttl_ms: f64,
        fail_stop: FailStop,
    ) -> Arc<ClusterNode> {
        let heartbeat_ms = heartbeat_ms.max(250.0);
        Arc::new_cyclic(|me| ClusterNode {
            store,
            node_id: node_id.to_string(),
            name: name.to_string(),
            heartbeat_ms,
            ttl_ms: ttl_ms.max(3.0 * heartbeat_ms),
            mode: Mutex::new(ClusterMode::ActiveActive),
            fail_stop,
            state: Mutex::new(NodeState::default()),
            me: me.clone(),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, NodeState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn heartbeat_ms(&self) -> f64 {
        self.heartbeat_ms
    }

    pub fn ttl_ms(&self) -> f64 {
        self.ttl_ms
    }

    /// Joins the cluster and starts the heartbeat.
    pub async fn join(&self) -> Result<(), String> {
        self.store
            // The mode is written on the row and compared with every live
            // node's under the store's join lock (`joinCluster()`).
            .join(
                &self.node_id,
                self.ttl_ms,
                json!({ "name": self.name, "mode": self.mode().as_str() }),
            )
            .await?;
        {
            let mut st = self.state();
            st.last_renew_ok = Some(Instant::now());
            st.joined = true;
        }
        self.refresh_clock().await;
        let Some(me) = self.me.upgrade() else {
            return Ok(());
        };
        let every = Duration::from_millis(self.heartbeat_ms as u64);
        // THE NEXT BEAT IS ARMED WHEN THE PREVIOUS FIRES, whether or not it
        // has settled (#770): a renewal that waited on a lock used to be the
        // whole lifetime, unseen. The renewal is the beat; the contention it
        // asks for runs beside the next beats, one at a time (#770's review).
        let handle = tokio::spawn(async move {
            loop {
                let due = Instant::now() + every;
                tokio::time::sleep_until(due).await;
                if me.state().stopping {
                    return;
                }
                me.note_lateness(due.elapsed().as_secs_f64() * 1000.0);
                if std::mem::replace(&mut me.state().renewing, true) {
                    me.note_unsettled_renewal();
                    continue;
                }
                let hooks = me.state().beat_hooks.clone();
                for hook in hooks {
                    tokio::spawn(hook());
                }
                let one = me.clone();
                tokio::spawn(async move {
                    let member = one.renew().await;
                    one.state().renewing = false;
                    if member {
                        one.contend_once();
                    }
                });
            }
        });
        self.state().heartbeat = Some(handle);
        Ok(())
    }

    /// Adds a renewal that rides on the heartbeat (`persistence.js`'s origin
    /// claim, renewed in Node by a timer of its own — one of
    /// `tests/no_periodic_timers.js`' permanent exceptions beside the
    /// heartbeat, which in Rust is one timer, this one): started beside
    /// every beat once this node has joined, and never awaited by it, so a
    /// slow renewal cannot make a beat late. The hook owns its own bounds.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn on_beat(&self, hook: BeatHook) {
        self.state().beat_hooks.push(hook);
    }

    /// Sets the mode this node runs in (`resolve_mode()`'s answer): in
    /// active-passive mode a lost service lease is fatal.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn set_mode(&self, mode: ClusterMode) {
        *self.mode.lock().unwrap_or_else(PoisonError::into_inner) = mode;
    }

    fn mode(&self) -> ClusterMode {
        *self.mode.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A HEARTBEAT THAT DID NOT RUN IS NOT A HEARTBEAT THAT FAILED
    /// (`noteLateness()`): a beat a heartbeat or more late means nothing ran
    /// here — in Rust, every runtime thread was busy or blocked. Said
    /// (STS-CLUSTER-0025), and named by a fail-stop it likely caused.
    fn note_lateness(&self, late_ms: f64) {
        if late_ms < self.heartbeat_ms {
            return;
        }
        self.state().last_stall = Some((late_ms, Instant::now()));
        tracing::warn!(
            "{}cluster: this node's heartbeat ran {}ms late — the runtime was busy and nothing on it ran, the \
             heartbeat included. The membership lifetime is {}ms by the database clock; a stall longer than {}ms \
             costs this node its membership and it exits.",
            tag(codes::STS_CLUSTER_0025),
            late_ms as u64,
            self.ttl_ms,
            self.ttl_ms - self.heartbeat_ms
        );
    }

    /// The clause a fail-stop adds when a recent stall is the likely reason
    /// the row expired (`stallClause()`).
    fn stall_clause(&self) -> String {
        match self.state().last_stall {
            Some((ms, at))
                if at.elapsed().as_secs_f64() * 1000.0 <= 2.0 * self.ttl_ms
                    && ms >= self.ttl_ms - self.heartbeat_ms =>
            {
                format!(
                    " The likely cause is THIS NODE, not the store: its runtime was blocked for {}ms, past its {}ms \
                     lifetime, so no heartbeat could run.",
                    ms as u64, self.ttl_ms
                )
            }
            _ => String::new(),
        }
    }

    /// A beat was still running when the next was due
    /// (`noteUnsettledRenewal()`): STS-CLUSTER-0003, and past the lifetime
    /// STS-CLUSTER-0004, hung statement or not.
    fn note_unsettled_renewal(&self) {
        let since = self
            .state()
            .last_renew_ok
            .map_or(f64::MAX, |t| t.elapsed().as_secs_f64() * 1000.0);
        if since >= self.ttl_ms - self.heartbeat_ms {
            self.fail(
                codes::STS_CLUSTER_0004.as_ref(),
                format!(
                    "It has not renewed its membership for {}ms against a lifetime of {}ms (the previous renewal \
                     has not finished). The other nodes may already treat it as dead and take over its leases.",
                    since as u64, self.ttl_ms
                ),
            );
            return;
        }
        tracing::warn!(
            "{}cluster: a heartbeat has not landed (the previous renewal is still running); {}ms since the last \
             renewal, {}ms of lifetime left.",
            tag(codes::STS_CLUSTER_0003),
            since as u64,
            (self.ttl_ms - since) as u64
        );
    }

    /// One contention at a time (`contendOnce()`): a beat whose contention
    /// is still asking starts none.
    fn contend_once(&self) {
        if std::mem::replace(&mut self.state().contending, true) {
            return;
        }
        let Some(me) = self.me.upgrade() else {
            return;
        };
        tokio::spawn(async move {
            me.campaign().await;
            me.state().contending = false;
        });
    }

    /// The fence a write transaction is checked against (`fenceFor()`):
    /// `None` before the join (the join is itself a transaction), otherwise
    /// this node and the leases the write needs — the service lease in
    /// active-passive mode, and those of the [`ClusterNode::with_lease`] it
    /// runs inside. A HOT PATH (every write): no instrument.
    pub fn fence_for(&self) -> Option<Fence> {
        let st = self.state();
        if !st.joined {
            return None;
        }
        let mut leases = Vec::new();
        if self.mode() == ClusterMode::ActivePassive {
            if let Some(token) = st.held.get(SERVICE_LEASE) {
                leases.push((SERVICE_LEASE.to_string(), *token));
            }
        }
        drop(st);
        let _found = LEASE_CONTEXT.try_with(|outer| {
            leases.extend(outer.iter().cloned());
        });
        Some(Fence {
            node_id: self.node_id.clone(),
            leases,
        })
    }

    /// Runs `work` with `name` held, every transaction it opens fenced by
    /// that lease's token (`withLease()`). `Err(holder)` without running it
    /// when another node holds the lease.
    #[tracing::instrument(level = "debug", skip(self, work))]
    pub async fn with_lease<F, T>(
        &self,
        name: &str,
        work: F,
    ) -> Result<T, String>
    where
        F: std::future::Future<Output = T>,
    {
        let answer = self.acquire(name).await;
        if !answer.held {
            return Err(answer.holder);
        }
        let mut leases =
            LEASE_CONTEXT.try_with(Clone::clone).unwrap_or_default();
        leases.push((name.to_string(), answer.token));
        Ok(LEASE_CONTEXT.scope(leases, work).await)
    }

    /// What the store calls when a transaction was fenced (`whenFenced()`):
    /// a lease that guarded ONE operation fails that operation and the node
    /// stays up; a dead membership, or the service lease in active-passive
    /// mode, is fatal (STS-CLUSTER-0011).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn when_fenced(
        &self,
        reason: FenceReason,
        lost: &[(String, u64)],
        message: &str,
    ) {
        let service_lost = lost.iter().any(|(n, _)| n == SERVICE_LEASE);
        if reason == FenceReason::Lease && !service_lost {
            tracing::warn!(
                "cluster: a write guarded by {} was fenced; the operation fails and this node stays up: {}",
                lost.iter()
                    .map(|(n, t)| format!("{}@{}", n, t))
                    .collect::<Vec<_>>()
                    .join(", "),
                message
            );
            let mut st = self.state();
            for (name, token) in lost {
                if st.held.get(name) == Some(token) {
                    st.held.remove(name);
                }
            }
            return;
        }
        let clause = self.stall_clause();
        self.fail(
            codes::STS_CLUSTER_0011.as_ref(),
            format!("A write was fenced: {}{}", message, clause),
        );
    }

    async fn refresh_clock(&self) {
        if let Ok(db) = self.store.now().await {
            self.state().clock_offset = db - sts_core::time::now_ms_f64();
        }
    }

    fn fail(&self, code: &'static str, why: String) {
        {
            let mut st = self.state();
            if st.stopping {
                return;
            }
            st.stopping = true;
            if let Some(h) = st.heartbeat.take() {
                h.abort();
            }
        }
        tracing::error!(
            "{}cluster: node {} ({}) is EXITING. {}",
            tag(code),
            self.node_id,
            self.name,
            why
        );
        (self.fail_stop)(code, why);
    }

    /// Whether this node has stopped (fail-stop or leave).
    pub fn stopped(&self) -> bool {
        self.state().stopping
    }

    /// Renews the membership and the leases once, notices leases lost, and
    /// campaigns for every role not held (`beat()`: the renewal, then the
    /// contention, both awaited — the heartbeat itself runs them apart).
    pub async fn beat(&self) {
        if self.renew().await {
            self.campaign().await;
        }
    }

    /// The renewal half of a beat (`renew()`): the heartbeat statement,
    /// bounded by [`renewal_bound_ms`], and what its answer means. True when
    /// the node is still a member and should contend.
    async fn renew(&self) -> bool {
        if self.state().stopping {
            return false;
        }
        let started = Instant::now();
        let bound = Duration::from_millis(renewal_bound_ms(self.ttl_ms) as u64);
        let answer = match tokio::time::timeout(
            bound,
            self.store.heartbeat(&self.node_id, self.ttl_ms),
        )
        .await
        {
            Ok(answer) => answer,
            Err(_) => Err(format!(
                "the heartbeat did not answer within {}ms",
                bound.as_millis()
            )),
        };
        match answer {
            Ok(renewal) => {
                if !renewal.alive {
                    let clause = self.stall_clause();
                    self.fail(
                        codes::STS_CLUSTER_0005.as_ref(),
                        format!(
                            "Its membership row had already expired when it was renewed, so another node may \
                             have taken over what it held. A node does not come back from that; it is \
                             restarted.{}",
                            clause
                        ),
                    );
                    return false;
                }
                let lost: Vec<(String, Option<Arc<dyn LeaseHandler>>)> = {
                    let mut st = self.state();
                    st.last_renew_ok = Some(started);
                    let renewed: HashMap<&str, u64> = renewal
                        .leases
                        .iter()
                        .map(|(n, t)| (n.as_str(), *t))
                        .collect();
                    let gone: Vec<String> = st
                        .held
                        .iter()
                        .filter(|(name, token)| {
                            renewed.get(name.as_str()) != Some(token)
                        })
                        .map(|(name, _)| name.clone())
                        .collect();
                    gone.into_iter()
                        .map(|name| {
                            st.held.remove(&name);
                            let handler = st.roles.get(&name).cloned();
                            (name, handler)
                        })
                        .collect()
                };
                let passive = self.mode() == ClusterMode::ActivePassive;
                for (name, handler) in lost {
                    if name == SERVICE_LEASE && passive {
                        self.fail(
                            codes::STS_CLUSTER_0006.as_ref(),
                            "It lost the service lease, so another node may be serving.".to_string(),
                        );
                        return false;
                    }
                    tracing::warn!(
                        "cluster: node {} lost the \"{}\" lease.",
                        self.node_id,
                        name
                    );
                    if let Some(h) = handler {
                        h.on_lose();
                    }
                }
                !self.state().stopping
            }
            Err(e) => {
                let since = self
                    .state()
                    .last_renew_ok
                    .map_or(f64::MAX, |t| t.elapsed().as_millis() as f64);
                if since >= self.ttl_ms - self.heartbeat_ms {
                    self.fail(
                        codes::STS_CLUSTER_0004.as_ref(),
                        format!(
                            "It has not renewed its membership for {}ms against a lifetime of {}ms ({}). The \
                             other nodes may already treat it as dead and take over its leases.",
                            since as u64, self.ttl_ms, e
                        ),
                    );
                    return false;
                }
                tracing::warn!(
                    "{}cluster: a heartbeat failed ({}); {}ms since the last renewal, {}ms of lifetime left.",
                    tag(codes::STS_CLUSTER_0003),
                    e,
                    since as u64,
                    (self.ttl_ms - since) as u64
                );
                false
            }
        }
    }

    async fn campaign(&self) {
        let wanted: Vec<(String, Arc<dyn LeaseHandler>)> = {
            let st = self.state();
            let now = Instant::now();
            st.roles
                .iter()
                .filter(|(name, _)| !st.held.contains_key(*name))
                .filter(|(name, _)| {
                    st.standing_down_until
                        .get(*name)
                        .is_none_or(|until| *until <= now)
                })
                .map(|(n, h)| (n.clone(), h.clone()))
                .collect()
        };
        for (name, handler) in wanted {
            let answer = self.acquire(&name).await;
            if answer.held {
                handler.on_gain(answer.token);
            }
        }
    }

    /// Asks for a lease; never fails (a store that cannot be asked is "not
    /// held", `STS-CLUSTER-0012`).
    pub async fn acquire(&self, name: &str) -> LeaseAnswer {
        // THE ACQUIRE HAS THE HEARTBEAT'S BOUND (#770's review): a takeover
        // waits for the previous holder's fences, and an ask that waited
        // with them held the beat in flight until the node taking over
        // exited. Past the bound it is "not yet" and asked again next beat.
        let bound = Duration::from_millis(renewal_bound_ms(self.ttl_ms) as u64);
        let asked = tokio::time::timeout(
            bound,
            self.store.acquire_lease(name, &self.node_id, self.ttl_ms),
        )
        .await;
        let Ok(asked) = asked else {
            if self.state().pending_takeovers.insert(name.to_string()) {
                tracing::info!(
                    "{}cluster: taking over the \"{}\" lease is waiting for writes the previous holder still has \
                     in flight; asking again every {}ms.",
                    tag(codes::STS_CLUSTER_0165),
                    name,
                    self.heartbeat_ms
                );
            }
            return LeaseAnswer {
                held: false,
                token: 0,
                holder: String::new(),
            };
        };
        self.state().pending_takeovers.remove(name);
        match asked {
            Ok(answer) => {
                if answer.held {
                    let was = self
                        .state()
                        .held
                        .insert(name.to_string(), answer.token);
                    if was != Some(answer.token) {
                        tracing::info!(
                            "cluster: node {} holds the \"{}\" lease at token {}.",
                            self.node_id,
                            name,
                            answer.token
                        );
                    }
                }
                answer
            }
            Err(e) => {
                tracing::warn!(
                    "{}cluster: asking for the \"{}\" lease failed: {}",
                    tag(codes::STS_CLUSTER_0012),
                    name,
                    e
                );
                LeaseAnswer {
                    held: false,
                    token: 0,
                    holder: String::new(),
                }
            }
        }
    }

    /// Whether this node holds a lease.
    pub fn holds(&self, name: &str) -> bool {
        self.state().held.contains_key(name)
    }

    /// The token this node holds a lease at.
    pub fn token_of(&self, name: &str) -> Option<u64> {
        self.state().held.get(name).copied()
    }

    /// Hands a held role over: released at this node's token, `on_lose`
    /// called, and not asked for again for `hold_off_ms` (three heartbeats
    /// when `None`, never less than one).
    pub async fn step_down_for(
        &self,
        name: &str,
        hold_off_ms: Option<f64>,
    ) -> Result<u64, String> {
        let hold = self.heartbeat_ms.max(
            hold_off_ms
                .filter(|h| *h > 0.0)
                .unwrap_or(3.0 * self.heartbeat_ms),
        );
        let (token, handler) = {
            let mut st = self.state();
            let Some(token) = st.held.remove(name) else {
                return Err("not-held".to_string());
            };
            st.standing_down_until.insert(
                name.to_string(),
                Instant::now() + Duration::from_millis(hold as u64),
            );
            (token, st.roles.get(name).cloned())
        };
        if let Some(h) = handler {
            h.on_lose();
        }
        match self.store.release_lease(name, &self.node_id, token).await {
            Ok(_) => {
                tracing::info!(
                    "cluster: node {} stood down from the \"{}\" lease (token {}); it will not ask for it again for \
                     {}ms.",
                    self.node_id,
                    name,
                    token,
                    hold
                );
                Ok(token)
            }
            Err(e) => {
                tracing::warn!(
                    "{}cluster: standing down from the \"{}\" lease failed ({}); it expires on its own within {}ms, \
                     and this node does not renew it.",
                    tag(codes::STS_CLUSTER_0041),
                    name,
                    e,
                    self.ttl_ms
                );
                Err(format!("store: {}", e))
            }
        }
    }

    /// For tests: the heartbeat stops as a crashed or paused process's
    /// would, leaving its rows to expire.
    #[doc(hidden)]
    pub fn halt_heartbeat_for_tests(&self) {
        if let Some(h) = self.state().heartbeat.take() {
            h.abort();
        }
    }

    /// Leaves the cluster: its membership and leases end at once.
    pub async fn leave(&self) -> Result<(), String> {
        {
            let mut st = self.state();
            st.stopping = true;
            if let Some(h) = st.heartbeat.take() {
                h.abort();
            }
            st.held.clear();
        }
        self.store.leave(&self.node_id).await
    }
}

impl Cluster for ClusterNode {
    fn enabled(&self) -> bool {
        true
    }
    fn node_id(&self) -> String {
        self.node_id.clone()
    }
    fn node_name(&self) -> String {
        self.name.clone()
    }
    fn lead(&self, lease: &str, handler: Arc<dyn LeaseHandler>) {
        self.state().roles.insert(lease.to_string(), handler);
        if let Some(me) = self.me.upgrade() {
            tokio::spawn(async move { me.campaign().await });
        }
    }
    fn step_down(&self, lease: &str) -> BoxFuture<'_, Result<(), String>> {
        let lease = lease.to_string();
        Box::pin(
            async move { self.step_down_for(&lease, None).await.map(|_| ()) },
        )
    }
}

impl Claims for ClusterNode {
    fn claim(
        &self,
        scope: &str,
        value: &str,
        realm: &str,
        ttl_ms: f64,
    ) -> BoxFuture<'_, Result<Claim, ClaimRefused>> {
        let ttl = ttl_ms.floor().clamp(1000.0, MAX_CLAIM_TTL_MS);
        let digest = claim_digest(scope, value);
        let reservation = random_reservation();
        let (scope, realm) = (scope.to_string(), realm.to_string());
        Box::pin(async move {
            match self
                .store
                .claim_once(
                    &scope,
                    &realm,
                    &digest,
                    ttl,
                    &reservation,
                    &self.node_id,
                )
                .await
            {
                Ok(ClaimAnswer::Claimed { claimed_at }) => Ok(Claim {
                    claimed_at,
                    handle: json!({ "scope": scope, "realm": realm, "key": digest, "reservation": reservation }),
                }),
                Ok(ClaimAnswer::Used { .. }) => Err(ClaimRefused::Held),
                Err(e) => {
                    tracing::error!(
                        "{}cluster claims: the store could not be asked about a \"{}\" value: {}. It is refused.",
                        tag(codes::STS_CLUSTER_0013),
                        scope,
                        e
                    );
                    Err(ClaimRefused::Store(e))
                }
            }
        })
    }

    fn release(&self, handle: &Json) -> BoxFuture<'_, ()> {
        let field = |k: &str| {
            handle
                .get(k)
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_string()
        };
        let (scope, realm, key, reservation) = (
            field("scope"),
            field("realm"),
            field("key"),
            field("reservation"),
        );
        Box::pin(async move {
            if key.is_empty() {
                return;
            }
            if let Err(e) = self
                .store
                .release_claim(&scope, &realm, &key, &reservation)
                .await
            {
                tracing::warn!(
                    "{}cluster claims: releasing a \"{}\" claim failed: {}. It stays held until it expires.",
                    tag(codes::STS_CLUSTER_0014),
                    scope,
                    e
                );
            }
        })
    }
}

impl Clock for ClusterNode {
    fn now(&self) -> f64 {
        sts_core::time::now_ms_f64()
    }
    fn db_now(&self) -> BoxFuture<'_, Result<f64, String>> {
        self.store.now()
    }
    fn source(&self) -> &'static str {
        "the database"
    }
}
