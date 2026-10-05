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
use openssl::hash::{hash, MessageDigest};
use serde_json::{json, Value as Json};
use sts_core::errors::codes;
use sts_core::log::tag;
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

#[derive(Default)]
struct NodeState {
    roles: HashMap<String, Arc<dyn LeaseHandler>>,
    held: HashMap<String, u64>,
    standing_down_until: HashMap<String, Instant>,
    last_renew_ok: Option<Instant>,
    stopping: bool,
    clock_offset: f64,
    heartbeat: Option<tokio::task::JoinHandle<()>>,
}

/// One node of a clustered service.
pub struct ClusterNode {
    store: Arc<dyn ClusterStore>,
    node_id: String,
    name: String,
    heartbeat_ms: f64,
    ttl_ms: f64,
    fail_stop: FailStop,
    state: Mutex<NodeState>,
    me: Weak<ClusterNode>,
}

/// A single-use value's stored form: SHA-256 of `scope \n value`.
pub fn claim_digest(scope: &str, value: &str) -> String {
    hash(
        MessageDigest::sha256(),
        format!("{}\n{}", scope, value).as_bytes(),
    )
    .map(|d| URL_SAFE_NO_PAD.encode(d))
    .unwrap_or_default()
}

fn random_reservation() -> String {
    let mut buf = [0u8; 12];
    if openssl::rand::rand_bytes(&mut buf).is_err() {
        tracing::error!("cluster: no random bytes for a claim's reservation");
    }
    URL_SAFE_NO_PAD.encode(buf)
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
            .join(&self.node_id, self.ttl_ms, json!({ "name": self.name }))
            .await?;
        self.state().last_renew_ok = Some(Instant::now());
        self.refresh_clock().await;
        let Some(me) = self.me.upgrade() else {
            return Ok(());
        };
        let every = Duration::from_millis(self.heartbeat_ms as u64);
        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                if me.state().stopping {
                    return;
                }
                me.beat().await;
            }
        });
        self.state().heartbeat = Some(handle);
        Ok(())
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
    /// campaigns for every role not held.
    pub async fn beat(&self) {
        if self.state().stopping {
            return;
        }
        let started = Instant::now();
        match self.store.heartbeat(&self.node_id, self.ttl_ms).await {
            Ok(renewal) => {
                if !renewal.alive {
                    self.fail(
                        codes::STS_CLUSTER_0005.as_ref(),
                        "Its membership row had already expired when it was renewed, so another node may have \
                         taken over what it held. A node does not come back from that; it is restarted."
                            .to_string(),
                    );
                    return;
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
                for (name, handler) in lost {
                    tracing::warn!(
                        "cluster: node {} lost the \"{}\" lease.",
                        self.node_id,
                        name
                    );
                    if let Some(h) = handler {
                        h.on_lose();
                    }
                }
                self.campaign().await;
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
                    return;
                }
                tracing::warn!(
                    "{}cluster: a heartbeat failed ({}); {}ms since the last renewal, {}ms of lifetime left.",
                    tag(codes::STS_CLUSTER_0003),
                    e,
                    since as u64,
                    (self.ttl_ms - since) as u64
                );
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
        match self
            .store
            .acquire_lease(name, &self.node_id, self.ttl_ms)
            .await
        {
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
