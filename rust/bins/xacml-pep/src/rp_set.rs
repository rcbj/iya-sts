// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE SESSION MECHANISM'S RELYING PARTIES (#1760, D5 revised, D10): the
//! proxy is the OpenID Connect relying party OF THE APPLICATION BEHIND IT,
//! with rcbj's crate `oidc-caep-risc` — one `RelyingParty` per client a
//! session route resolved to, and, when any of that client's routes keeps
//! `signals` on, one CAEP/RISC `SignalsReceiver` on the library's poll
//! stream, which removes the session a `session-revoked` names.
//!
//! **THE LIBRARY'S ASYNC API** (its `tokio` feature, 0.3.0): every call
//! that may touch the network — `create_async` (discovery), `start_async`,
//! `stop_async`, `authorize_async`, `complete_session_async`,
//! `session_access_token_async` — is awaited, and the library runs it on
//! tokio's blocking pool, never on the runtime's threads (its HTTP client is
//! still `ureq`: one blocking-pool thread per call in flight). The receiver
//! polls on one thread of its own. Asking whether a session is still there
//! (`session()`) and the receiver's `health()` are map reads and run where
//! they are asked.
//!
//! **THE LIBRARY'S SESSION STORE IS BOUNDED** (`MemorySessionStore::new`):
//! twice `PEP_PROXY_MAX_SESSIONS` entries, each kept
//! `PEP_PROXY_SESSION_TTL_MS` after it was last written. The proxy's own
//! store is the admission rule (it REFUSES past its bound); the library's is
//! a memory bound behind it, with headroom so that an entry the proxy let
//! expire without removing never pushes a live one out.
//!
//! **A STREAM THAT STOPS ANSWERING IS NOTICED** (`ReceiverHealth`): a
//! receiver with no successful poll within `PEP_PROXY_SIGNALS_STALE_MS` is
//! not trusted to end sessions, and its routes ask the service's session
//! endpoint instead (`STS-XPEP-0099`, logged once when it goes stale and once
//! when it recovers) — otherwise a sign-out signalled while the stream is
//! down would end nothing.
//!
//! **BUILT FROM THE PULL, REBUILT WHEN IT CHANGES.** An entry is keyed by
//! a digest of everything it was built from (the issuer, the client, its
//! secret, auth method, redirect URI and scopes, the service's chain,
//! whether signals are on, and the registered PEP name); a pull that
//! changes any of them — a secret rotated, a chain re-issued, registration
//! completing — builds a new relying party and stops the old receiver. The
//! library's session store is kept across rebuilds (`set_session_store`),
//! so a rotation signs nobody out. **No secret is logged or reported**:
//! the digest is not either.
//!
//! **THE DPOP KEY OUTLIVES A REBUILD TOO** (run #543). The library makes a
//! DPoP key of its own when it is given none (`Dpop::generate`), so every
//! rebuild used to change it — and a sign-in in flight across a rebuild
//! had pushed its request with the OLD key's `dpop_jkt` and redeemed its
//! code, at the callback, through the NEW party with the new key: the
//! service refused the code (`invalid_grant`, `STS-OAUTH-0205`) and the
//! browser got 401 `STS-XPEP-0083`. The access and refresh tokens the
//! library's session store holds are bound to the key the same way. So
//! one P-256 key per client is made here, once, and handed to every party
//! built for that client as `dpopKey`; it is NOT in the digest (a secret,
//! and nothing a pull changes), and it is never logged or reported.
//!
//! **THE REGISTERED NAME IS THE MEMBER'S STREAM** (#1760 phase 3). Once
//! registration has succeeded, every transmitter call carries
//! `X-Iya-Pep-Name` with that name, and the service answers the list with
//! that member's stream only. The name is in the digest because the
//! library lists once, when the receiver starts, and does not list again
//! when a poll fails: a receiver built before the name was known would
//! keep the untagged stream. A name that is not known yet sends no header.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use oidc_caep_risc::{
    MemorySessionStore, ReceiverOptions, RelyingParty, SessionStore,
    SignalEvent, SignalsReceiver,
};
use serde_json::{json, Map, Value};
use sts_core::log::tag;

use crate::proxy_config::{Mechanism, Pulled, RpClient};

/// What ends a proxy session when the receiver ends a library session.
pub type OnEnd = Arc<dyn Fn(Vec<String>) + Send + Sync>;

/// One client's relying party, and its receiver when signals are on and it
/// started.
#[derive(Clone)]
pub struct Party {
    pub rp: Arc<RelyingParty>,
    pub receiver: Option<Arc<SignalsReceiver>>,
    /// Signals were asked for. With no receiver running, the fallback
    /// (`validation.session`) decides liveness instead.
    pub signals: bool,
    /// The client this party is for, for the log only.
    client_id: String,
    /// How long a receiver may go without a successful poll.
    stale_ms: u64,
    /// The receiver was last seen stale, so a change is logged once.
    stale: Arc<AtomicBool>,
}

impl Party {
    /// The library's own answer about a session is the liveness check
    /// only while a receiver is there to end sessions AND its stream has
    /// answered within `PEP_PROXY_SIGNALS_STALE_MS`.
    pub fn signals_live(&self) -> bool {
        if !self.signals {
            return false;
        }
        let Some(receiver) = &self.receiver else {
            return false;
        };
        let healthy =
            receiver.health().is_healthy(self.stale_ms as f64 / 1000.0);
        let was_stale = self.stale.swap(!healthy, Ordering::SeqCst);
        if !healthy && !was_stale {
            let health = receiver.health();
            tracing::warn!(
                "{}xacml-pep: proxy: the CAEP/RISC stream of client {} has \
                 not answered a poll within {} ms ({} failed in a row: {}); \
                 sessions of its routes are checked with the service's \
                 session endpoint until it does.",
                tag("STS-XPEP-0099"),
                self.client_id,
                self.stale_ms,
                health.consecutive_failures,
                if health.last_error.is_empty() {
                    "no error recorded"
                } else {
                    health.last_error.as_str()
                }
            );
        } else if healthy && was_stale {
            tracing::info!(
                "xacml-pep: proxy: the CAEP/RISC stream of client {} answers \
                 again; its signals decide session liveness once more.",
                self.client_id
            );
        }
        healthy
    }
}

struct Entry {
    digest: String,
    party: Party,
}

/// Every relying party the pull calls for.
pub struct RpSet {
    /// The bounds in force, moved by a settings pull (#1760,
    /// `set_limits()`). A party built under other bounds is rebuilt on the
    /// next reconcile; a library session store keeps the bounds it was
    /// built with, since it outlives rebuilds and holds signed-in people.
    limits: Mutex<Bounds>,
    on_end: OnEnd,
    entries: Mutex<HashMap<String, Entry>>,
    /// The library's session stores, one per client, outliving rebuilds.
    stores: Mutex<HashMap<String, Arc<MemorySessionStore>>>,
    /// The DPoP key of each client, PKCS #8 PEM, outliving rebuilds (see
    /// the module's comment). A secret: never logged or reported.
    dpop_keys: Mutex<HashMap<String, String>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

/// The issuer's discovery document (OpenID Connect Discovery 1.0 section 4).
pub fn metadata_url(issuer: &str) -> String {
    format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    )
}

/// The scopes the library is given: the application's, `openid` first.
pub fn scopes_of(client: &RpClient) -> String {
    let mut out = vec!["openid".to_string()];
    for one in &client.scopes {
        if !out.contains(one) {
            out.push(one.clone());
        }
    }
    out.join(" ")
}

/// The configuration `RelyingParty::create` takes, in the library's keys.
pub fn library_config(
    issuer: &str,
    client_id: &str,
    client: &RpClient,
    tls_ca: &str,
    signals: bool,
    allow_insecure: bool,
) -> Map<String, Value> {
    let mut config = Map::new();
    config.insert("issuer".into(), json!(issuer));
    config.insert("metadataUrl".into(), json!(metadata_url(issuer)));
    config.insert("clientId".into(), json!(client_id));
    config.insert("clientSecret".into(), json!(client.client_secret));
    let method = if client.token_endpoint_auth_method.is_empty() {
        "client_secret_basic"
    } else {
        client.token_endpoint_auth_method.as_str()
    };
    config.insert("tokenEndpointAuthMethod".into(), json!(method));
    config.insert("redirectUri".into(), json!(client.redirect_uri));
    config.insert("scopes".into(), json!(scopes_of(client)));
    if !tls_ca.is_empty() {
        config.insert("tlsCa".into(), json!(tls_ca));
    }
    if !signals {
        config.insert("signals".into(), json!(false));
    }
    config.insert("allowInsecure".into(), json!(allow_insecure));
    config
}

fn digest_of(config: &Map<String, Value>) -> String {
    let text = Value::Object(config.clone()).to_string();
    openssl::sha::sha256(text.as_bytes())
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// The clients the active configuration's usable session routes call for,
/// and whether any route of each keeps signals on.
pub fn wanted(pulled: &Pulled) -> HashMap<String, bool> {
    let mut out: HashMap<String, bool> = HashMap::new();
    if let Some(config) = pulled.active() {
        for route in &config.routes {
            if route.allows(Mechanism::Session) && route.resolved.usable {
                let signals = out
                    .entry(route.resolved.client_id.clone())
                    .or_insert(false);
                *signals = *signals || route.signals;
            }
        }
    }
    out
}

/// `RpLimits` as the set holds them, normalised.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Bounds {
    allow_insecure: bool,
    poll_ms: u64,
    stale_ms: u64,
    store_max: usize,
    store_ttl_sec: u64,
}

impl Bounds {
    fn of(limits: &RpLimits) -> Bounds {
        let poll_ms = limits.poll_ms.max(10);
        Bounds {
            allow_insecure: limits.allow_insecure,
            poll_ms,
            // Never shorter than three polls, or one slow answer would
            // flip a working stream to stale.
            stale_ms: limits.stale_ms.max(poll_ms * 3),
            store_max: limits.max_sessions.max(1).saturating_mul(2),
            store_ttl_sec: limits.session_ttl_ms.div_ceil(1000).max(1),
        }
    }
}

/// What `RpSet::new` is given, from `Options::now()`.
pub struct RpLimits {
    pub allow_insecure: bool,
    pub poll_ms: u64,
    pub stale_ms: u64,
    pub max_sessions: usize,
    pub session_ttl_ms: u64,
}

impl RpSet {
    pub fn new(limits: RpLimits, on_end: OnEnd) -> RpSet {
        RpSet {
            limits: Mutex::new(Bounds::of(&limits)),
            on_end,
            entries: Mutex::new(HashMap::new()),
            stores: Mutex::new(HashMap::new()),
            dpop_keys: Mutex::new(HashMap::new()),
        }
    }

    /// The bounds from now on; true when they changed.
    pub fn set_limits(&self, limits: RpLimits) -> bool {
        let next = Bounds::of(&limits);
        let mut held = lock(&self.limits);
        let changed = *held != next;
        *held = next;
        changed
    }

    fn bounds(&self) -> Bounds {
        *lock(&self.limits)
    }

    fn store_for(&self, client_id: &str) -> Arc<MemorySessionStore> {
        let bounds = self.bounds();
        lock(&self.stores)
            .entry(client_id.to_string())
            .or_insert_with(|| {
                Arc::new(MemorySessionStore::new(
                    bounds.store_max,
                    bounds.store_ttl_sec,
                ))
            })
            .clone()
    }

    /// The DPoP key every party of `client_id` signs its proofs with, made
    /// the first time it is asked for. None when no key could be made: the
    /// library then makes one of its own, as it always did, and only a
    /// sign-in in flight across a rebuild is lost.
    fn dpop_key_for(&self, client_id: &str) -> Option<String> {
        let mut keys = lock(&self.dpop_keys);
        if let Some(pem) = keys.get(client_id) {
            return Some(pem.clone());
        }
        match new_dpop_key() {
            Ok(pem) => {
                keys.insert(client_id.to_string(), pem.clone());
                Some(pem)
            }
            Err(why) => {
                tracing::warn!(
                    "{}xacml-pep: proxy: no DPoP key could be made for \
                     client {} ({}); the library makes one per relying \
                     party, so a sign-in in flight when it is rebuilt \
                     fails.",
                    tag("STS-XPEP-0090"),
                    client_id,
                    why
                );
                None
            }
        }
    }

    /// The relying party of `client_id` as the pull describes it: the one
    /// held when nothing changed, else a new one (and its receiver),
    /// built off the runtime's threads.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn party(
        &self,
        client_id: &str,
        pulled: &Pulled,
        signals: bool,
        pep_name: Option<&str>,
    ) -> Result<Party, String> {
        let client = pulled
            .realm
            .clients
            .get(client_id)
            .ok_or_else(|| "the pull carries no such client".to_string())?;
        let bounds = self.bounds();
        let config = library_config(
            &pulled.realm.issuer,
            client_id,
            client,
            &pulled.realm.tls_ca_chain,
            signals,
            bounds.allow_insecure,
        );
        // The poll and stale bounds are the receiver's and the party's, not
        // the library's configuration, so they go in the digest beside it,
        // with the registered PEP name (#1760 phase 3): a change of any of
        // them rebuilds the party on the next reconcile.
        let member = member_name(pep_name);
        let digest = party_digest(
            &config,
            bounds.poll_ms,
            bounds.stale_ms,
            member.as_deref(),
        );
        if let Some(entry) = lock(&self.entries).get(client_id) {
            if entry.digest == digest {
                return Ok(entry.party.clone());
            }
        }
        let store = self.store_for(client_id);
        // After the digest: the key is a secret and the same for every
        // build of this client, so it neither belongs in nor changes it.
        let mut config = config;
        if let Some(pem) = self.dpop_key_for(client_id) {
            config.insert("dpopKey".into(), json!(pem));
        }
        let on_end = self.on_end.clone();
        let issuer = pulled.realm.issuer.clone();
        let tls_ca =
            Some(pulled.realm.tls_ca_chain.clone()).filter(|c| !c.is_empty());
        let poll_ms = bounds.poll_ms as i64;
        let described =
            format!("iya-sts xacml-pep reverse proxy ({})", client_id);
        let rp = Arc::new(
            RelyingParty::create_async(config)
                .await
                .map_err(|e| e.to_string())?,
        );
        rp.set_session_store(store as Arc<dyn SessionStore>);
        let (receiver, receiver_problem) = if !signals {
            (None, None)
        } else {
            let reporting = client_id.to_string();
            // Sent on every transmitter call, including the list the
            // library does once at start. None until registration has
            // named this PEP, so an unregistered PEP keeps the untagged
            // stream.
            let headers = member.clone().map(|name| {
                Arc::new(move || {
                    vec![("X-Iya-Pep-Name".to_string(), name.clone())]
                })
                    as Arc<dyn Fn() -> Vec<(String, String)> + Send + Sync>
            });
            let made = SignalsReceiver::new(
                &issuer,
                Arc::new(move |ended: Vec<String>, _: SignalEvent| {
                    on_end(ended)
                }),
                ReceiverOptions {
                    tls_ca,
                    relying_party: Some(rp.clone()),
                    scope: "ssf.manage".into(),
                    description: described,
                    poll_interval_ms: poll_ms,
                    headers,
                    // The library's own lines (a failed poll, a refused
                    // SET) go to this log, at debug: the state change
                    // that matters is logged once by `signals_live()`.
                    on_error: Some(Arc::new(move |line: &str| {
                        tracing::debug!(
                            "xacml-pep: proxy: client {}: {}",
                            reporting,
                            line
                        );
                    })),
                    ..ReceiverOptions::default()
                },
            );
            match made {
                Err(error) => (None, Some(error.to_string())),
                Ok(made) => {
                    let made = Arc::new(made);
                    match made.start_async().await {
                        Ok(()) => (Some(made), None),
                        Err(error) => (None, Some(error.to_string())),
                    }
                }
            }
        };
        if let Some(problem) = receiver_problem {
            tracing::warn!(
                "{}xacml-pep: proxy: the CAEP/RISC receiver for client {} \
                 would not start ({}); sessions of its routes are checked \
                 with the service's session endpoint instead.",
                tag("STS-XPEP-0094"),
                client_id,
                problem
            );
        }
        let party = Party {
            rp,
            receiver,
            signals,
            client_id: client_id.to_string(),
            stale_ms: bounds.stale_ms,
            stale: Arc::new(AtomicBool::new(false)),
        };
        let replaced = lock(&self.entries).insert(
            client_id.to_string(),
            Entry {
                digest,
                party: party.clone(),
            },
        );
        if let Some(old) = replaced.and_then(|e| e.party.receiver) {
            stop_detached(old);
        }
        tracing::info!(
            "xacml-pep: proxy: the relying party for client {} is built{}.",
            client_id,
            if party.receiver.is_some() {
                ", with a CAEP/RISC receiver on the service's poll stream"
            } else {
                ""
            }
        );
        Ok(party)
    }

    /// EVERY RECEIVER STOPPED, NOW, and every party dropped (#1935): what a
    /// test harness does when it is dropped. A receiver polls on a thread
    /// of the library's own (`SignalsReceiver::start`), which nothing but
    /// `stop()` ends — not the drop of this set, of the proxy, or of the
    /// runtime the test ran on, and this set is never dropped anyway (the
    /// proxy's reporters hold it). So a harness left a thread polling its
    /// mock service's port for the rest of the test binary, and when the
    /// kernel gave that port to a later harness's mock application, that
    /// application saw a `POST /ssf/poll` nobody sent it. The product
    /// builds one proxy for the life of the process and stops a receiver
    /// whenever it replaces or drops one (`party()`, `reconcile()`), so
    /// only a test needs this.
    ///
    /// `stop()` waits for a poll in flight, which here may be a poll of a
    /// mock served by the very runtime the caller is blocking, so it runs
    /// on a thread of its own; what this waits for is the first thing
    /// `stop()` does, marking the receiver not running, after which its
    /// loop starts no other poll.
    #[cfg(test)]
    pub fn stop_all(&self) {
        let parties: Vec<Entry> =
            lock(&self.entries).drain().map(|(_, e)| e).collect();
        for receiver in parties.into_iter().filter_map(|e| e.party.receiver) {
            let stopping = receiver.clone();
            std::thread::spawn(move || stopping.stop());
            while receiver.health().running {
                std::thread::yield_now();
            }
        }
    }

    /// The party held for a client, whatever the pull says now (a callback
    /// finishes the sign-in it started).
    pub fn held(&self, client_id: &str) -> Option<Party> {
        lock(&self.entries).get(client_id).map(|e| e.party.clone())
    }

    /// After a pull: every client the configuration calls for built (or
    /// kept), every other one dropped and its receiver stopped.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn reconcile(&self, pulled: &Pulled, pep_name: Option<&str>) {
        let want = wanted(pulled);
        let gone: Vec<String> = lock(&self.entries)
            .keys()
            .filter(|k| !want.contains_key(*k))
            .cloned()
            .collect();
        for client_id in gone {
            let removed = lock(&self.entries).remove(&client_id);
            if let Some(receiver) = removed.and_then(|e| e.party.receiver) {
                stop_detached(receiver);
            }
        }
        let mut done = HashSet::new();
        for (client_id, signals) in want {
            if !done.insert(client_id.clone()) {
                continue;
            }
            if let Err(why) =
                self.party(&client_id, pulled, signals, pep_name).await
            {
                tracing::warn!(
                    "{}xacml-pep: proxy: the relying party for client {} \
                     could not be built: {}.",
                    tag("STS-XPEP-0090"),
                    client_id,
                    why
                );
            }
        }
    }

    /// The CAEP/RISC streams' and the library session stores' state, for
    /// `GET /`: COUNTS and ages only — no client id, no URL, no error text
    /// (an error can carry the service's address), since `GET /` answers
    /// whoever reaches the container.
    pub fn signals_json(&self) -> Value {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        let bounds = self.bounds();
        let entries = lock(&self.entries);
        let (mut receivers, mut healthy) = (0u64, 0u64);
        let (mut worst_failures, mut accepted, mut refused, mut ended) =
            (0u64, 0u64, 0u64, 0u64);
        let mut oldest_success_ms: Option<u64> = None;
        for entry in entries.values() {
            let Some(receiver) = &entry.party.receiver else {
                continue;
            };
            receivers += 1;
            let h = receiver.health();
            if h.is_healthy_at(now, bounds.stale_ms as f64 / 1000.0) {
                healthy += 1;
            }
            worst_failures = worst_failures.max(h.consecutive_failures);
            accepted += h.sets_accepted;
            refused += h.sets_refused;
            ended += h.sessions_ended;
            if let Some(at) = h.last_success_at.or(h.started_at) {
                let age = ((now - at).max(0.0) * 1000.0) as u64;
                oldest_success_ms =
                    Some(oldest_success_ms.map_or(age, |o| o.max(age)));
            }
        }
        drop(entries);
        let (mut held, mut evicted, mut expired) = (0usize, 0u64, 0u64);
        for store in lock(&self.stores).values() {
            let stats = store.stats();
            held += stats.entries;
            evicted += stats.evicted;
            expired += stats.expired;
        }
        json!({
            "receivers": receivers,
            "healthy": healthy,
            "stale": receivers - healthy,
            "staleAfterMs": bounds.stale_ms,
            "pollIntervalMs": bounds.poll_ms,
            "oldestSuccessAgeMs": oldest_success_ms,
            "mostConsecutiveFailures": worst_failures,
            "setsAccepted": accepted,
            "setsRefused": refused,
            "sessionsEnded": ended,
            "librarySessions": {
                "held": held,
                "max": bounds.store_max,
                "ttlSec": bounds.store_ttl_sec,
                "evicted": evicted,
                "expired": expired
            }
        })
    }

    /// One row per CAEP/RISC stream, for the HEARTBEAT only (#1760): the
    /// client it serves (so the service can say which application), the
    /// transmitter's stream id, whether it runs and is healthy, the AGES of
    /// its start, last poll and last success (the service turns them into
    /// times by when the report arrived, so no clock here is believed) and
    /// its counters. Never an error text or a URL. `GET /`, which answers
    /// whoever reaches the container, keeps the counts of `signals_json()`.
    pub fn streams_json(&self) -> Value {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        let bounds = self.bounds();
        let age =
            |at: Option<f64>| at.map(|t| ((now - t).max(0.0) * 1000.0) as u64);
        let entries = lock(&self.entries);
        let mut rows: Vec<(String, Value)> = entries
            .iter()
            .filter_map(|(client_id, entry)| {
                let receiver = entry.party.receiver.as_ref()?;
                let h = receiver.health();
                Some((
                    client_id.clone(),
                    json!({
                        "clientId": client_id,
                        "streamId": h.stream_id,
                        "running": h.running,
                        "healthy": h.is_healthy_at(
                            now, bounds.stale_ms as f64 / 1000.0),
                        "startedAgeMs": age(h.started_at),
                        "lastPollAgeMs": age(h.last_poll_at),
                        "lastSuccessAgeMs": age(h.last_success_at),
                        "consecutiveFailures": h.consecutive_failures,
                        "polls": h.polls,
                        "failedPolls": h.failed_polls,
                        "setsAccepted": h.sets_accepted,
                        "setsRefused": h.sets_refused,
                        "sessionsEnded": h.sessions_ended
                    }),
                ))
            })
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        Value::Array(rows.into_iter().map(|(_, v)| v).collect())
    }

    /// How many relying parties and receivers are held, for `GET /`.
    pub fn counts(&self) -> (usize, usize) {
        let entries = lock(&self.entries);
        (
            entries.len(),
            entries
                .values()
                .filter(|e| e.party.receiver.is_some())
                .count(),
        )
    }
}

/// The registered name a cluster member puts on `X-Iya-Pep-Name`, or
/// none when there is nothing to send (#1760 phase 3). Blank is none:
/// an unregistered PEP, and a registration that named nothing, keep the
/// untagged stream.
fn member_name(name: Option<&str>) -> Option<String> {
    name.map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_string)
}

/// What an entry was built from. The registered name is the fourth
/// field so registration completing rebuilds the receiver (#1760
/// phase 3). `member` is already `member_name`'s answer.
fn party_digest(
    config: &Map<String, Value>,
    poll_ms: u64,
    stale_ms: u64,
    member: Option<&str>,
) -> String {
    format!(
        "{}|{}|{}|{}",
        digest_of(config),
        poll_ms,
        stale_ms,
        member.unwrap_or("")
    )
}

/// A new P-256 private key in PKCS #8 PEM: the one curve the library signs
/// DPoP proofs with (`DPOP_ALG`, ES256).
fn new_dpop_key() -> Result<String, String> {
    let group = openssl::ec::EcGroup::from_curve_name(
        openssl::nid::Nid::X9_62_PRIME256V1,
    )
    .map_err(|e| e.to_string())?;
    let key = openssl::ec::EcKey::generate(&group)
        .and_then(openssl::pkey::PKey::from_ec_key)
        .map_err(|e| e.to_string())?;
    let pem = key.private_key_to_pem_pkcs8().map_err(|e| e.to_string())?;
    String::from_utf8(pem).map_err(|e| e.to_string())
}

/// A receiver's `stop()` waits for a transmitter call in flight (at most
/// the library's 15 s HTTP timeout), so it is never awaited on a request:
/// it runs as a task of its own, on the blocking pool.
fn stop_detached(receiver: Arc<SignalsReceiver>) {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            handle.spawn(async move { receiver.stop_async().await });
        }
        Err(_) => {
            std::thread::spawn(move || receiver.stop());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_library_is_given_the_pull_and_a_change_is_a_new_digest() {
        let client = RpClient {
            client_secret: "s1".into(),
            token_endpoint_auth_method: String::new(),
            redirect_uri: "https://pep.example/.iya-pep/callback".into(),
            scopes: vec!["profile".into(), "openid".into()],
        };
        let one =
            library_config("https://sts/r", "app", &client, "", true, false);
        assert_eq!(
            one["metadataUrl"],
            "https://sts/r/.well-known/openid-configuration"
        );
        assert_eq!(one["tokenEndpointAuthMethod"], "client_secret_basic");
        assert_eq!(one["scopes"], "openid profile");
        assert!(one.get("signals").is_none() && one.get("tlsCa").is_none());
        let mut rotated = client.clone();
        rotated.client_secret = "s2".into();
        let two =
            library_config("https://sts/r", "app", &rotated, "", true, false);
        assert_ne!(
            digest_of(&one),
            digest_of(&two),
            "a rotated secret rebuilds"
        );
        let off = library_config(
            "https://sts/r",
            "app",
            &client,
            "PEM",
            false,
            false,
        );
        assert_eq!(off["signals"], false);
        assert_eq!(off["tlsCa"], "PEM");
    }

    #[test]
    fn the_registered_name_is_its_own_stream_and_a_blank_sends_nothing() {
        assert_eq!(member_name(Some(" pep-1 ")).as_deref(), Some("pep-1"));
        assert_eq!(member_name(Some("")), None);
        assert_eq!(member_name(Some("   ")), None);
        assert_eq!(member_name(None), None);
        let client = RpClient {
            client_secret: "s1".into(),
            token_endpoint_auth_method: String::new(),
            redirect_uri: "https://pep.example/.iya-pep/callback".into(),
            scopes: vec!["openid".into()],
        };
        let config =
            library_config("https://sts/r", "app", &client, "", true, false);
        let named = party_digest(
            &config,
            1000,
            2000,
            member_name(Some("pep-1")).as_deref(),
        );
        let other = party_digest(
            &config,
            1000,
            2000,
            member_name(Some("pep-2")).as_deref(),
        );
        let bare =
            party_digest(&config, 1000, 2000, member_name(None).as_deref());
        let blank = party_digest(
            &config,
            1000,
            2000,
            member_name(Some("   ")).as_deref(),
        );
        assert_ne!(named, other, "two members do not share a digest");
        assert_ne!(named, bare, "a name rebuilds an untagged receiver");
        assert_eq!(bare, blank, "a blank name sends no header");
    }

    #[test]
    fn a_client_keeps_one_dpop_key_across_rebuilds() {
        // Run #543: a party rebuilt between a sign-in's PAR and its
        // callback redeemed the code with a new DPoP key, and the service
        // refused it (STS-OAUTH-0205). Every build of a client must sign
        // with the key the first one did.
        let set = RpSet::new(
            RpLimits {
                allow_insecure: false,
                poll_ms: 1000,
                stale_ms: 3000,
                max_sessions: 4,
                session_ttl_ms: 60_000,
            },
            Arc::new(|_| {}),
        );
        let first = set.dpop_key_for("app").expect("a key is made");
        let again = set.dpop_key_for("app").expect("and kept");
        assert_eq!(first, again, "a rebuild signs with the same key");
        let other = set.dpop_key_for("other").expect("a key per client");
        assert_ne!(first, other, "two clients do not share a key");
        let one = oidc_caep_risc::Dpop::from_pem(&first)
            .expect("the library reads the key");
        let two = oidc_caep_risc::Dpop::from_pem(&again).expect("again");
        assert_eq!(one.jkt(), two.jkt(), "the same dpop_jkt every build");
    }
}
