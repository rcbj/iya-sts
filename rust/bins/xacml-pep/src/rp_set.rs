// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE SESSION MECHANISM'S RELYING PARTIES (#1760, D5 revised, D10): the
//! proxy is the OpenID Connect relying party OF THE APPLICATION BEHIND IT,
//! with rcbj's crate `oidc-caep-risc` — one `RelyingParty` per client a
//! session route resolved to, and, when any of that client's routes keeps
//! `signals` on, one CAEP/RISC `SignalsReceiver` on the library's poll
//! stream, which removes the session a `session-revoked` names.
//!
//! **THE LIBRARY IS BLOCKING** (ureq): every call that may touch the
//! network — `create` (discovery), `start`, `stop`, `authorize`,
//! `complete_session` — runs on `spawn_blocking`, never on the runtime's
//! threads, and the receiver polls on a thread of its own the library
//! spawns. Asking whether a session is still there (`session()`) is a map
//! lookup and runs where it is asked.
//!
//! **BUILT FROM THE PULL, REBUILT WHEN IT CHANGES.** An entry is keyed by
//! a digest of everything it was built from (the issuer, the client, its
//! secret, auth method, redirect URI and scopes, the service's chain,
//! whether signals are on); a pull that changes any of them — a secret
//! rotated, a chain re-issued — builds a new relying party and stops the
//! old receiver. The library's session store is kept across rebuilds
//! (`set_session_store`), so a rotation signs nobody out. **No secret is
//! logged or reported**: the digest is not either.

use std::collections::{HashMap, HashSet};
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
}

impl Party {
    /// The library's own answer about a session is the liveness check
    /// only while a receiver is there to end sessions.
    pub fn signals_live(&self) -> bool {
        self.signals && self.receiver.is_some()
    }
}

struct Entry {
    digest: String,
    party: Party,
}

/// Every relying party the pull calls for.
pub struct RpSet {
    allow_insecure: bool,
    poll_ms: u64,
    on_end: OnEnd,
    entries: Mutex<HashMap<String, Entry>>,
    /// The library's session stores, one per client, outliving rebuilds.
    stores: Mutex<HashMap<String, Arc<MemorySessionStore>>>,
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

impl RpSet {
    pub fn new(allow_insecure: bool, poll_ms: u64, on_end: OnEnd) -> RpSet {
        RpSet {
            allow_insecure,
            poll_ms: poll_ms.max(10),
            on_end,
            entries: Mutex::new(HashMap::new()),
            stores: Mutex::new(HashMap::new()),
        }
    }

    fn store_for(&self, client_id: &str) -> Arc<MemorySessionStore> {
        lock(&self.stores)
            .entry(client_id.to_string())
            .or_insert_with(|| Arc::new(MemorySessionStore::default()))
            .clone()
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
    ) -> Result<Party, String> {
        let client = pulled
            .realm
            .clients
            .get(client_id)
            .ok_or_else(|| "the pull carries no such client".to_string())?;
        let config = library_config(
            &pulled.realm.issuer,
            client_id,
            client,
            &pulled.realm.tls_ca_chain,
            signals,
            self.allow_insecure,
        );
        let digest = digest_of(&config);
        if let Some(entry) = lock(&self.entries).get(client_id) {
            if entry.digest == digest {
                return Ok(entry.party.clone());
            }
        }
        let store = self.store_for(client_id);
        let on_end = self.on_end.clone();
        let issuer = pulled.realm.issuer.clone();
        let tls_ca =
            Some(pulled.realm.tls_ca_chain.clone()).filter(|c| !c.is_empty());
        let poll_ms = self.poll_ms as i64;
        let described =
            format!("iya-sts xacml-pep reverse proxy ({})", client_id);
        let built = tokio::task::spawn_blocking(move || {
            let rp = Arc::new(
                RelyingParty::create(config).map_err(|e| e.to_string())?,
            );
            rp.set_session_store(store as Arc<dyn SessionStore>);
            if !signals {
                return Ok::<_, String>((rp, None, None));
            }
            let receiver = SignalsReceiver::new(
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
                    ..ReceiverOptions::default()
                },
            );
            let started = receiver.and_then(|r| r.start().map(|_| r));
            match started {
                Ok(receiver) => Ok((rp, Some(Arc::new(receiver)), None)),
                Err(error) => Ok((rp, None, Some(error.to_string()))),
            }
        })
        .await
        .map_err(|e| {
            format!("the relying party could not be built: {}", e)
        })??;
        let (rp, receiver, receiver_problem) = built;
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

    /// The party held for a client, whatever the pull says now (a callback
    /// finishes the sign-in it started).
    pub fn held(&self, client_id: &str) -> Option<Party> {
        lock(&self.entries).get(client_id).map(|e| e.party.clone())
    }

    /// After a pull: every client the configuration calls for built (or
    /// kept), every other one dropped and its receiver stopped.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn reconcile(&self, pulled: &Pulled) {
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
            if let Err(why) = self.party(&client_id, pulled, signals).await {
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

/// A receiver's `stop()` waits up to twenty seconds for its poll thread,
/// so it is never awaited on a request.
fn stop_detached(receiver: Arc<SignalsReceiver>) {
    std::thread::spawn(move || receiver.stop());
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
}
