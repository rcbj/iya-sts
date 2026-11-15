// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE SESSION MECHANISM'S TWO STORES (#1760, D5): sign-ins in flight,
//! keyed by `state`, and the proxy sessions they become, keyed by a random
//! 256-bit id the `iya_pep_session` cookie carries.
//!
//! **The sign-in itself is the library's** (`rp_set.rs`, `oidc-caep-risc`):
//! a sign-in in flight holds its `Transaction` (state, nonce, PKCE
//! verifier), and a proxy session is made under the SAME id the library
//! keeps its own session under (`complete_session`), so a CAEP
//! `session-revoked` that ends the one ends the other.
//!
//! **In memory, in this process, and nothing else.** A proxy session is a
//! projection of a sign-on session at the service, which ends it through
//! the library's CAEP/RISC receiver, or — on a route with `signals: false`
//! — is asked whether it is still live (`POST /xacml/pep/session`) whenever
//! its last answer is older than `PEP_PROXY_SESSION_RECHECK_MS`; a restart of this container
//! only sends each browser through a sign-in it will not see (the service's
//! session is still there). Several instances behind a balancer would each
//! hold their own — *Several instances are NOT a cluster* in
//! `xacml-pep/CLAUDE.md`.
//!
//! **BOUNDED, AND PURGED AT THE INSERT, NEVER ON A TIMER.** A sign-in in
//! flight lives ten minutes and the oldest is dropped when the store is
//! full (anybody can start one, so refusing new ones would let anybody stop
//! everybody signing in; dropping the oldest costs a stale tab one more
//! trip). A proxy session lives `PEP_PROXY_SESSION_TTL_MS`, and when
//! `PEP_PROXY_MAX_SESSIONS` live ones are held a new one is REFUSED —
//! evicting would sign somebody else out.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::jwt::b64url_encode;

/// How long a sign-in may take.
pub const PENDING_TTL: Duration = Duration::from_secs(600);

/// A sign-in in flight. Not `Debug`: the transaction holds the PKCE
/// verifier.
#[derive(Clone)]
pub struct Pending {
    /// The library's transaction: state, nonce, PKCE verifier.
    pub transaction: oidc_caep_risc::Transaction,
    /// The client (D10's `resolved.clientId`) the sign-in is for.
    pub client_id: String,
    /// Where to send the browser afterwards: the normalised path and the
    /// original query, ALWAYS relative to the proxy. Never a value the
    /// callback brought.
    pub return_to: String,
    pub created: Instant,
}

/// A proxy session.
#[derive(Debug, Clone)]
pub struct Session {
    /// The client the session was made by, whose relying party holds the
    /// library's session under the same id.
    pub client_id: String,
    pub sid: String,
    pub sub: String,
    pub username: String,
    /// The ID Token, kept for RP-initiated logout's `id_token_hint`.
    pub id_token: String,
    pub created: Instant,
    pub last_checked: Instant,
}

/// A random value of `bytes` octets, base64url.
pub fn random_token(bytes: usize) -> Option<String> {
    let mut buffer = vec![0u8; bytes];
    openssl::rand::rand_bytes(&mut buffer).ok()?;
    Some(b64url_encode(&buffer))
}

struct Inner {
    pending: HashMap<String, Pending>,
    sessions: HashMap<String, Session>,
}

/// Both stores.
pub struct Stores {
    inner: Mutex<Inner>,
    /// Both bounds follow the settings the service sets (#1760,
    /// `set_limits()`): a lower bound refuses the next session rather than
    /// ending any held, and a shorter life ends a held one at its next use.
    max_sessions: AtomicUsize,
    ttl_ms: AtomicU64,
}

/// Why a session could not be made.
#[derive(Debug, PartialEq)]
pub enum Full {
    Full,
}

impl Stores {
    pub fn new(max_sessions: usize, ttl_ms: u64) -> Stores {
        Stores {
            inner: Mutex::new(Inner {
                pending: HashMap::new(),
                sessions: HashMap::new(),
            }),
            max_sessions: AtomicUsize::new(max_sessions.max(1)),
            ttl_ms: AtomicU64::new(ttl_ms.max(1)),
        }
    }

    /// The bounds in force from now on.
    pub fn set_limits(&self, max_sessions: usize, ttl_ms: u64) {
        self.max_sessions
            .store(max_sessions.max(1), Ordering::Relaxed);
        self.ttl_ms.store(ttl_ms.max(1), Ordering::Relaxed);
    }

    fn max(&self) -> usize {
        self.max_sessions.load(Ordering::Relaxed)
    }

    fn ttl(&self) -> Duration {
        Duration::from_millis(self.ttl_ms.load(Ordering::Relaxed))
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Holds a sign-in, dropping the expired and, when full, the oldest.
    pub fn begin(&self, state: String, pending: Pending) {
        let mut inner = self.lock();
        inner
            .pending
            .retain(|_, p| p.created.elapsed() < PENDING_TTL);
        while inner.pending.len() >= self.max() {
            let oldest = inner
                .pending
                .iter()
                .min_by_key(|(_, p)| p.created)
                .map(|(k, _)| k.clone());
            match oldest {
                Some(key) => {
                    inner.pending.remove(&key);
                }
                None => break,
            }
        }
        inner.pending.insert(state, pending);
    }

    /// Takes a sign-in back, ONCE: a second callback with the same state
    /// finds nothing.
    pub fn take(&self, state: &str) -> Option<Pending> {
        let mut inner = self.lock();
        inner
            .pending
            .remove(state)
            .filter(|p| p.created.elapsed() < PENDING_TTL)
    }

    /// Makes a proxy session under `id` (drawn with [`random_token`]
    /// before the library's sign-in completes, which keeps its own session
    /// under it).
    pub fn create(&self, id: &str, session: Session) -> Result<(), Full> {
        let mut inner = self.lock();
        let ttl = self.ttl();
        inner.sessions.retain(|_, s| s.created.elapsed() < ttl);
        if inner.sessions.len() >= self.max() {
            return Err(Full::Full);
        }
        inner.sessions.insert(id.to_string(), session);
        Ok(())
    }

    /// Whether another proxy session may be made now — asked before the
    /// library's sign-in completes, so a full store refuses before a code
    /// is spent.
    pub fn has_room(&self) -> bool {
        let mut inner = self.lock();
        let ttl = self.ttl();
        inner.sessions.retain(|_, s| s.created.elapsed() < ttl);
        inner.sessions.len() < self.max()
    }

    /// The live session a cookie names.
    pub fn get(&self, id: &str) -> Option<Session> {
        let mut inner = self.lock();
        match inner.sessions.get(id) {
            Some(s) if s.created.elapsed() < self.ttl() => Some(s.clone()),
            Some(_) => {
                inner.sessions.remove(id);
                None
            }
            None => None,
        }
    }

    /// The service said the session is live now.
    pub fn checked(&self, id: &str, sub: &str, username: &str) {
        if let Some(s) = self.lock().sessions.get_mut(id) {
            s.last_checked = Instant::now();
            if !sub.is_empty() {
                s.sub = sub.to_string();
            }
            if !username.is_empty() {
                s.username = username.to_string();
            }
        }
    }

    pub fn end(&self, id: &str) -> Option<Session> {
        self.lock().sessions.remove(id)
    }

    /// (live sessions, sign-ins in flight), for `GET /`.
    pub fn counts(&self) -> (usize, usize) {
        let inner = self.lock();
        (
            inner
                .sessions
                .values()
                .filter(|s| s.created.elapsed() < self.ttl())
                .count(),
            inner
                .pending
                .values()
                .filter(|p| p.created.elapsed() < PENDING_TTL)
                .count(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(to: &str) -> Pending {
        Pending {
            transaction: oidc_caep_risc::Transaction::default(),
            client_id: "c".into(),
            return_to: to.into(),
            created: Instant::now(),
        }
    }

    fn session() -> Session {
        Session {
            client_id: "c".into(),
            sid: "sid".into(),
            sub: "urn:uuid:1".into(),
            username: String::new(),
            id_token: "t".into(),
            created: Instant::now(),
            last_checked: Instant::now(),
        }
    }

    #[test]
    fn a_state_is_spent_once_and_the_store_is_bounded() {
        let stores = Stores::new(2, 60_000);
        stores.begin("a".into(), pending("/a"));
        stores.begin("b".into(), pending("/b"));
        stores.begin("c".into(), pending("/c"));
        assert!(stores.take("a").is_none(), "the oldest was dropped");
        assert_eq!(stores.take("c").unwrap().return_to, "/c");
        assert!(stores.take("c").is_none(), "spent");
        let one = random_token(32).unwrap();
        stores.create(&one, session()).unwrap();
        assert!(stores.has_room());
        stores.create("two", session()).unwrap();
        assert!(!stores.has_room());
        assert_eq!(stores.create("three", session()), Err(Full::Full));
        assert_eq!(stores.get(&one).unwrap().sub, "urn:uuid:1");
        stores.checked(&one, "", "alice");
        let checked = stores.get(&one).unwrap();
        assert_eq!(
            (checked.sub.as_str(), checked.username.as_str()),
            ("urn:uuid:1", "alice"),
            "an empty answer keeps sub"
        );
        assert!(stores.end(&one).is_some());
        assert!(stores.get(&one).is_none());
        assert_eq!(stores.counts().0, 1);
        assert_eq!(one.len(), 43, "256 bits, base64url");
    }

    #[test]
    fn a_session_expires() {
        let stores = Stores::new(5, 1);
        stores.create("one", session()).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert!(stores.get("one").is_none());
    }
}
