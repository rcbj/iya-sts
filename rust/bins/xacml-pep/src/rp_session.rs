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
    /// On a route with `multipleAccounts` (#1760): the browser's account
    /// set the sign-in joins (`Some("")` for a browser with none yet), so
    /// the callback adds an account rather than setting the single
    /// session cookie. None is today's single sign-in.
    pub account_set: Option<String>,
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

/// SEVERAL ACCOUNTS IN ONE BROWSER (#1760, rcbj 2026-11-14): one account
/// of a browser's set — a proxy session of its own, for one application's
/// client, under an id that is stable while the account stays signed in.
#[derive(Debug, Clone, PartialEq)]
pub struct Account {
    /// The account's id in the set: what the chooser's forms name, never a
    /// session id.
    pub account: String,
    pub session_id: String,
    pub client_id: String,
    pub sub: String,
    pub username: String,
}

/// A browser's account set: its accounts in the order they joined, and,
/// per application client, the ACTIVE one — the only identity a request on
/// that application's routes is ever forwarded as. No active account for a
/// client is a choice the person makes on the chooser, never one made for
/// them.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AccountSet {
    pub accounts: Vec<Account>,
    pub active: HashMap<String, String>,
}

impl AccountSet {
    /// The active account for `client_id`, if one is chosen.
    pub fn active_for(&self, client_id: &str) -> Option<&Account> {
        let account = self.active.get(client_id)?;
        self.accounts.iter().find(|a| &a.account == account)
    }

    /// The accounts of one client.
    pub fn of_client(&self, client_id: &str) -> Vec<&Account> {
        self.accounts
            .iter()
            .filter(|a| a.client_id == client_id)
            .collect()
    }
}

/// Why an account could not be added.
#[derive(Debug, PartialEq)]
pub enum AddRefused {
    /// The set already holds `PEP_PROXY_MAX_ACCOUNTS` accounts.
    Full(usize),
    /// No random value could be drawn for a set or an account.
    NoRandom,
}

/// What adding an account did: the set's id (new when the browser had
/// none), the account's id, and a session it REPLACED — the same person
/// signing in again — which the caller ends.
#[derive(Debug, PartialEq)]
pub struct Added {
    pub set_id: String,
    pub account: String,
    pub replaced: Option<String>,
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
    /// The account sets, by the id the `iya_pep_accounts` cookie carries,
    /// and which set each of their sessions is in — so a session's end
    /// (a sign-out, a CAEP signal, an expiry) finds its account by key.
    sets: HashMap<String, AccountSet>,
    set_of_session: HashMap<String, String>,
}

impl Inner {
    /// Drops an ended session's account from its set: ONLY that account,
    /// and, where it was the active one, no other is made active.
    fn forget_account_of(&mut self, session_id: &str) {
        let Some(set_id) = self.set_of_session.remove(session_id) else {
            return;
        };
        let empty = match self.sets.get_mut(&set_id) {
            Some(set) => {
                if let Some(at) = set
                    .accounts
                    .iter()
                    .position(|a| a.session_id == session_id)
                {
                    let gone = set.accounts.remove(at);
                    if set.active.get(&gone.client_id) == Some(&gone.account) {
                        set.active.remove(&gone.client_id);
                    }
                }
                set.accounts.is_empty()
            }
            None => false,
        };
        if empty {
            self.sets.remove(&set_id);
        }
    }
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
                sets: HashMap::new(),
                set_of_session: HashMap::new(),
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

    /// Ends a proxy session, and the account it was in a set (only that
    /// one).
    pub fn end(&self, id: &str) -> Option<Session> {
        let mut inner = self.lock();
        inner.forget_account_of(id);
        inner.sessions.remove(id)
    }

    /// A browser's set as it is now: accounts whose session has ended or
    /// expired are dropped first, so nothing answered names a dead one.
    pub fn account_set(&self, set_id: &str) -> Option<AccountSet> {
        if set_id.is_empty() {
            return None;
        }
        let mut inner = self.lock();
        let ttl = self.ttl();
        let dead: Vec<String> = inner
            .sets
            .get(set_id)?
            .accounts
            .iter()
            .filter(|a| {
                inner
                    .sessions
                    .get(&a.session_id)
                    .is_none_or(|s| s.created.elapsed() >= ttl)
            })
            .map(|a| a.session_id.clone())
            .collect();
        for id in dead {
            inner.forget_account_of(&id);
            inner.sessions.remove(&id);
        }
        inner.sets.get(set_id).cloned()
    }

    /// Adds a signed-in account to a browser's set (making one when
    /// `set_id` names none), and makes it the active one for its client.
    /// The same person already in the set for that client is the same
    /// account signed in again: its session is replaced (and handed back
    /// to be ended) and its id kept. A set already holding `max` accounts
    /// refuses a new one: evicting would sign somebody out.
    pub fn add_account(
        &self,
        set_id: &str,
        session_id: &str,
        client_id: &str,
        sub: &str,
        username: &str,
        max: usize,
    ) -> Result<Added, AddRefused> {
        let mut inner = self.lock();
        let set_id = if !set_id.is_empty() && inner.sets.contains_key(set_id)
        {
            set_id.to_string()
        } else {
            random_token(24).ok_or(AddRefused::NoRandom)?
        };
        let set = inner.sets.entry(set_id.clone()).or_default();
        let same = set
            .accounts
            .iter()
            .position(|a| a.client_id == client_id && a.sub == sub);
        let (account, replaced) = match same {
            Some(at) => {
                let one = &mut set.accounts[at];
                let old = std::mem::replace(
                    &mut one.session_id,
                    session_id.to_string(),
                );
                one.username = username.to_string();
                (one.account.clone(), Some(old))
            }
            None => {
                if set.accounts.len() >= max.max(1) {
                    let held = set.accounts.len();
                    if held == 0 {
                        inner.sets.remove(&set_id);
                    }
                    return Err(AddRefused::Full(held));
                }
                let account =
                    random_token(9).ok_or(AddRefused::NoRandom)?;
                set.accounts.push(Account {
                    account: account.clone(),
                    session_id: session_id.to_string(),
                    client_id: client_id.to_string(),
                    sub: sub.to_string(),
                    username: username.to_string(),
                });
                (account, None)
            }
        };
        set.active.insert(client_id.to_string(), account.clone());
        if let Some(old) = &replaced {
            inner.set_of_session.remove(old);
        }
        inner
            .set_of_session
            .insert(session_id.to_string(), set_id.clone());
        Ok(Added {
            set_id,
            account,
            replaced,
        })
    }

    /// Makes `account` the active one for its client; None when the set
    /// does not hold it.
    pub fn switch_account(
        &self,
        set_id: &str,
        account: &str,
    ) -> Option<Account> {
        let mut inner = self.lock();
        let set = inner.sets.get_mut(set_id)?;
        let one = set.accounts.iter().find(|a| a.account == account)?.clone();
        set.active.insert(one.client_id.clone(), one.account.clone());
        Some(one)
    }

    /// The account `account` of a set, without changing anything.
    pub fn account_of(&self, set_id: &str, account: &str) -> Option<Account> {
        let inner = self.lock();
        inner
            .sets
            .get(set_id)?
            .accounts
            .iter()
            .find(|a| a.account == account)
            .cloned()
    }

    /// Every session of a set, for signing them all out.
    pub fn sessions_of_set(&self, set_id: &str) -> Vec<Account> {
        let inner = self.lock();
        inner
            .sets
            .get(set_id)
            .map(|s| s.accounts.clone())
            .unwrap_or_default()
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

    fn held(stores: &Stores, id: &str, sub: &str) {
        stores.create(id, Session {
            client_id: "app".into(), sid: format!("sid-{}", id),
            sub: sub.into(), username: sub.into(), id_token: String::new(),
            created: Instant::now(), last_checked: Instant::now(),
        }).unwrap();
    }

    #[test]
    fn several_accounts_one_active_switched_and_ended_alone() {
        let stores = Stores::new(100, 60_000);
        held(&stores, "s1", "alice");
        let a = stores.add_account("", "s1", "app", "alice", "alice", 3)
            .unwrap();
        held(&stores, "s2", "bob");
        let b = stores.add_account(&a.set_id, "s2", "app", "bob", "bob", 3)
            .unwrap();
        assert_eq!(a.set_id, b.set_id, "one set for the browser");
        let set = stores.account_set(&a.set_id).unwrap();
        assert_eq!(set.accounts.len(), 2);
        // The account added last is the active one, and only one is.
        assert_eq!(set.active_for("app").unwrap().sub, "bob");
        // Switching makes the other active.
        assert_eq!(stores.switch_account(&a.set_id, &a.account).unwrap().sub,
                   "alice");
        assert_eq!(stores.account_set(&a.set_id).unwrap()
                     .active_for("app").unwrap().sub, "alice");
        assert!(stores.switch_account(&a.set_id, "nobody").is_none());
        // A session ended (a CAEP signal, a sign-out) ends ITS account
        // only, and no other account is made active in its place.
        stores.end("s1");
        let set = stores.account_set(&a.set_id).unwrap();
        assert_eq!(set.accounts.len(), 1);
        assert_eq!(set.accounts[0].sub, "bob");
        assert!(set.active_for("app").is_none(),
                "never switched silently");
        assert!(stores.get("s2").is_some(), "bob's session is untouched");
        // The last one ended: the set is gone.
        stores.end("s2");
        assert!(stores.account_set(&a.set_id).is_none());
    }

    #[test]
    fn the_set_is_bounded_and_the_same_person_is_replaced() {
        let stores = Stores::new(100, 60_000);
        held(&stores, "s1", "alice");
        let a = stores.add_account("", "s1", "app", "alice", "alice", 2)
            .unwrap();
        held(&stores, "s2", "bob");
        stores.add_account(&a.set_id, "s2", "app", "bob", "bob", 2).unwrap();
        held(&stores, "s3", "carol");
        assert_eq!(
            stores.add_account(&a.set_id, "s3", "app", "carol", "carol", 2),
            Err(AddRefused::Full(2)),
            "a full set refuses rather than evicting"
        );
        // Alice again: her account, a new session, the old one handed back.
        held(&stores, "s4", "alice");
        let again = stores
            .add_account(&a.set_id, "s4", "app", "alice", "alice", 2)
            .unwrap();
        assert_eq!(again.account, a.account);
        assert_eq!(again.replaced.as_deref(), Some("s1"));
        // Ending the replaced session does not take the account with it.
        stores.end("s1");
        let set = stores.account_set(&a.set_id).unwrap();
        assert_eq!(set.accounts.len(), 2);
        assert_eq!(set.active_for("app").unwrap().session_id, "s4");
    }

    #[test]
    fn an_expired_session_leaves_the_set() {
        let stores = Stores::new(100, 1);
        held(&stores, "s1", "alice");
        let a = stores.add_account("", "s1", "app", "alice", "alice", 3)
            .unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert!(stores.account_set(&a.set_id).is_none());
    }

    fn pending(to: &str) -> Pending {
        Pending {
            transaction: oidc_caep_risc::Transaction::default(),
            client_id: "c".into(),
            return_to: to.into(),
            created: Instant::now(),
            account_set: None,
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
