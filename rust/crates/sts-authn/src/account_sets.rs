// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A BROWSER'S ACCOUNT SET (#561): WHICH SIGN-ON SESSIONS ONE BROWSER HOLDS
//! — a port of `authn/account_sets.ts` (`AccountSets`).
//!
//! With `authn.multipleAccounts` on (the default in both modes since
//! 2026-10-20), a browser may be signed in as several people at once. The
//! sessions are the ordinary sign-on sessions of [`crate::Sessions`], each
//! with its own clocks and sign-out, and this is the LIST of them, kept on
//! the server: a row per browser in `authn.accountSets`, named by the
//! `sts_accounts` cookie, holding
//!
//! * `sessions` — sid → `{ sub, username, displayName, addedAt }`; a row
//!   lists sids and never decides whether one is live (the session store
//!   does, every time);
//! * `remembered` — key → `{ sub, username, displayName, signedOutAt }`, an
//!   account that signed out here, offered by the picker until forgotten or
//!   `authn.rememberedAccountDays` passes;
//! * `lastActiveSid`, and the merge's memory: `endedSids`, `forgotten`.
//!
//! **THE COOKIE IS `<setId>.<handle>`, AND ONLY THE HANDLE IS A SECRET**:
//! the row holds its SHA-256. Outside the default realm it is
//! `sts_accounts_<realm>`. The handle rotates when a session is added and
//! at every selection, never where no response reaches the browser.
//!
//! **A SELECTION IS PER FLOW**: a ticket (`sts_account=` on the address a
//! flow resumes on), single use, two minutes, bound to the set and the
//! path, kept in `authn.accountTickets`.
//!
//! COMPATIBILITY (D11). Both stores are Node's handles, rows member for
//! member in Node's order, so a 1.x install's sets are a browser's sets
//! here and Node reads this runtime's. WHAT REPLACED WHAT: Node's
//! `onDemand` reading of `authn.accountSets` (#820 part 2) is a read
//! strategy for a store too large to hold, and this runtime holds the full
//! map, as it does the sessions; the row's `expiresAt` hook — its last
//! write plus [`AccountSets::keep_ms`] — is kept, so the store's expiry
//! purge treats a row as Node's does. `sweepInSlices()`' yielding is
//! `tokio::task::yield_now()` between slices of [`SWEEP_SLICE_MS`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use serde_json::{json, Value};
use sts_core::errors::codes;
use sts_core::log::tag;
use sts_core::realm;
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{
    expiry_field, RealmMap, RealmView, Retain, StoreHandles, StoreSpec,
};

use crate::cookie;
use crate::js::{self, Object};
use crate::ports::{Clock, Response, Settings};

/// The cookie naming the default realm's account set.
pub const COOKIE: &str = "sts_accounts";
/// The query parameter a selection ticket rides on.
pub const TICKET_PARAM: &str = "sts_account";
/// The store of sets.
pub const SETS_HANDLE: &str = "authn.accountSets";
/// The store of tickets.
pub const TICKETS_HANDLE: &str = "authn.accountTickets";
/// How long a ticket lives: the redirect it rides on is followed at once.
const TICKET_TTL_MS: f64 = 2.0 * 60.0 * 1000.0;
/// How many ended sids and forgotten keys a row keeps for the merge.
const MERGE_MEMORY: usize = 40;
const DAY_MS: f64 = 24.0 * 60.0 * 60.0 * 1000.0;
/// How long one slice of a sweep may hold its thread before it yields.
pub const SWEEP_SLICE_MS: u128 = 25;
/// How much sweeping one run of the job may do (#784).
pub const SWEEP_RUN_BUDGET_MS: u128 = 1000;

/// What a sweep did: `{ sets, ended, expired, deleted }`, and for the
/// budgeted one the slices and how far through the pass it is.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SweepCounts {
    pub sets: u64,
    pub ended: u64,
    pub expired: u64,
    pub deleted: u64,
    pub slices: u64,
    pub at: u64,
    pub of: u64,
}

impl SweepCounts {
    /// `{ sets, ended, expired, deleted }`, Node's answer of `sweep()`.
    // A hot path: every sweep's answer; no span.
    pub fn plain(&self) -> Value {
        json!({"sets": self.sets, "ended": self.ended,
               "expired": self.expired, "deleted": self.deleted})
    }

    /// `sweepBudgeted()`'s answer, `slices`, `at` and `of` with it.
    // A hot path: every run's answer; no span.
    pub fn budgeted(&self) -> Value {
        json!({"sets": self.sets, "ended": self.ended,
               "expired": self.expired, "deleted": self.deleted,
               "slices": self.slices, "at": self.at, "of": self.of})
    }
}

/// A sweep pass in one realm (#784): the ids it began with, and how far.
#[derive(Default)]
struct Pass {
    ids: Option<Vec<String>>,
    at: usize,
}

/// The two stores and the operations on a row.
pub struct AccountSets {
    sets: RealmMap<Value>,
    tickets: RealmMap<Value>,
    settings: Arc<dyn Settings>,
    clock: Arc<dyn Clock>,
    passes: Mutex<HashMap<String, Pass>>,
}

/// `Number(x) || 0` of a member of an object value.
fn n(v: &Value, k: &str) -> f64 {
    js::number_or_zero(v.get(k))
}

/// A member as an object, inserted (empty) where it is absent or not one.
fn table<'a>(row: &'a mut Object, k: &str) -> &'a mut Object {
    if !matches!(row.get(k), Some(Value::Object(_))) {
        row.insert(k.to_string(), Value::Object(Object::new()));
    }
    match row.get_mut(k) {
        Some(Value::Object(o)) => o,
        _ => unreachable!("inserted just above"),
    }
}

/// The keys of a member object, in its order.
fn keys_of(row: &Object, k: &str) -> Vec<String> {
    match row.get(k) {
        Some(Value::Object(o)) => o.keys().cloned().collect(),
        _ => Vec::new(),
    }
}

/// Whether a member object holds a key, with a truthy value.
fn holds(row: &Object, k: &str, key: &str) -> bool {
    js::truthy(row.get(k).and_then(|t| t.get(key)))
}

impl AccountSets {
    /// Declares the two stores, Node's declarations.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(
        settings: Arc<dyn Settings>,
        clock: Arc<dyn Clock>,
        lifecycle: &Arc<RealmLifecycle>,
        handles: &Arc<StoreHandles>,
    ) -> AccountSets {
        let mut spec = StoreSpec::persisted(SETS_HANDLE);
        spec.tombstone = true;
        spec.merge_row = Some(Arc::new(|mine: &Value, theirs: &Value| {
            AccountSets::merge(mine, theirs)
        }));
        let keep = settings.clone();
        spec.expires_at = Some(Arc::new(move |row: &Value, _key: &str| {
            let at = n(row, "updatedAt");
            (at > 0.0).then(|| at + keep_ms_of(keep.as_ref()))
        }));
        let mut tickets = StoreSpec::persisted(TICKETS_HANDLE);
        tickets.retain = Retain::Age;
        tickets.expires_at = Some(expiry_field(Some("expires"), 1.0));
        AccountSets {
            sets: RealmMap::new(lifecycle, handles, spec),
            tickets: RealmMap::new(lifecycle, handles, tickets),
            settings,
            clock,
            passes: Mutex::new(HashMap::new()),
        }
    }

    fn here(&self) -> RealmView<Value> {
        self.sets.in_realm(&realm::current_id())
    }

    fn tickets_here(&self) -> RealmView<Value> {
        self.tickets.in_realm(&realm::current_id())
    }

    /// The store of sets, for the vectors and the console.
    // A hot path: a borrow; no span.
    pub fn store(&self) -> &RealmMap<Value> {
        &self.sets
    }

    /// The store of tickets.
    // A hot path: a borrow; no span.
    pub fn ticket_store(&self) -> &RealmMap<Value> {
        &self.tickets
    }

    /// `enabled()`: `authn.multipleAccounts === true` in the ambient realm.
    // A hot path: asked by every session read; no span.
    pub fn enabled(&self) -> bool {
        self.settings.value("authn.multipleAccounts") == Value::Bool(true)
    }

    /// `maxAccounts()`: `authn.maxBrowserAccounts`, 10 where it is not a
    /// positive number.
    // A hot path: asked by every sign-in; no span.
    pub fn max_accounts(&self) -> f64 {
        let v =
            js::number(Some(&self.settings.value("authn.maxBrowserAccounts")))
                .floor();
        if v > 0.0 {
            v
        } else {
            10.0
        }
    }

    /// `keepMs()`: how long after its last write a set can still matter.
    // A hot path (every row a flush writes); no span.
    pub fn keep_ms(&self) -> f64 {
        keep_ms_of(self.settings.as_ref())
    }

    /// `rememberMs()`: `authn.rememberedAccountDays` in milliseconds.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn remember_ms(&self) -> f64 {
        remember_ms_of(self.settings.as_ref())
    }

    /// `cookieName()`: `sts_accounts`, or `sts_accounts_<realm>`.
    // A hot path: every session read names it; no span.
    pub fn cookie_name(&self) -> String {
        let id = realm::current_id();
        if id.is_empty() || id == "default" {
            COOKIE.to_string()
        } else {
            format!("{}_{}", COOKIE, id)
        }
    }

    /// `cookieLine(value)`: an empty value clears the cookie.
    #[tracing::instrument(level = "debug", skip(self, value))]
    pub fn cookie_line(&self, value: &str) -> String {
        format!(
            "{}={}; Path=/; HttpOnly; SameSite=Lax{}{}{}",
            self.cookie_name(),
            value,
            if value.is_empty() { "; Max-Age=0" } else { "" },
            self.settings.cookie_domain_attribute(),
            if js::truthy(Some(&self.settings.value("global.https"))) {
                "; Secure"
            } else {
                ""
            }
        )
    }

    /// `writeCookie(res, value)`: APPENDED, beside any cookie already on it.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn write_cookie(&self, response: &mut Response, value: &str) {
        response.append_cookie(self.cookie_line(value));
    }

    /// `setOf(cookies)`: the set a request's cookie names, if it carries
    /// the current handle; a copy.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn set_of(&self, cookies: &Object) -> Option<Object> {
        let value = js::or_empty(cookies.get(&self.cookie_name()));
        let dot = value.find('.')?;
        if dot == 0 || dot == value.len() - 1 {
            return None;
        }
        let row = js::object_of(self.here().get(&value[..dot]).as_ref());
        let hash = js::or_empty(row.get("handleHash"));
        if hash.is_empty() || !cookie::holds_handle(&row, &value[dot + 1..]) {
            return None;
        }
        Some(row)
    }

    /// `byId(id)`: a set by its id, with no cookie check; a copy.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn by_id(&self, id: &str) -> Option<Object> {
        if id.is_empty() {
            return None;
        }
        self.here().get(id).map(|v| js::object_of(Some(&v)))
    }

    /// `fresh()`: a new, empty set, not yet saved.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn fresh(&self) -> Object {
        let now = js::num(self.clock.now_ms());
        let id = self.clock.random_id(18);
        js::object_of(Some(&json!({
            "id": id, "handleHash": "", "createdAt": now, "updatedAt": now,
            "lastActiveSid": "", "sessions": {}, "remembered": {},
            "endedSids": {}, "forgotten": {},
        })))
    }

    /// `rotate(row)`: a fresh handle; answers the cookie value. The caller
    /// saves the row and writes the cookie.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn rotate(&self, row: &mut Object) -> String {
        let handle = self.clock.random_id(32);
        row.insert("handleHash".into(), json!(cookie::handle_hash_of(&handle)));
        row.insert("handleIssuedAt".into(), js::num(self.clock.now_ms()));
        format!("{}.{}", js::string_of(row.get("id")), handle)
    }

    /// `save(row)`: stamped, trimmed, written back.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn save(&self, row: &mut Object) {
        row.insert("updatedAt".into(), js::num(self.clock.now_ms()));
        Self::trim(row);
        let id = js::string_of(row.get("id"));
        self.here().set(&id, Value::Object(row.clone()));
    }

    /// `remove(id)`: an empty set, at the expiry job.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn remove(&self, id: &str) {
        self.here().delete(id);
    }

    /// `keyOf(account)`: its subject, or `name:<username>`. Never a sid.
    // A hot path: every account drawn; no span.
    pub fn key_of(account: &Value) -> String {
        if js::truthy(account.get("sub")) {
            js::text(&account["sub"])
        } else {
            format!("name:{}", js::or_empty(account.get("username")))
        }
    }

    /// `size(row)`: its sessions and its remembered accounts.
    // A hot path; no span.
    pub fn size(row: &Object) -> usize {
        keys_of(row, "sessions").len() + keys_of(row, "remembered").len()
    }

    /// `addSession(row, sid, account)`: a remembered entry for the same
    /// account replaced; at the cap the account that signed out longest
    /// ago dropped; refused only when every place is a session. Answers
    /// `(ok, dropped)`.
    #[tracing::instrument(level = "debug", skip(self, row, account))]
    pub fn add_session(
        &self,
        row: &mut Object,
        sid: &str,
        account: &Value,
    ) -> (bool, u64) {
        let key = Self::key_of(account);
        table(row, "sessions");
        table(row, "remembered");
        if holds(row, "sessions", sid) {
            row.insert("lastActiveSid".into(), json!(sid));
            return (true, 0);
        }
        table(row, "remembered").shift_remove(&key);
        let mut dropped = 0;
        let cap = self.max_accounts();
        while Self::size(row) as f64 >= cap {
            let remembered = table(row, "remembered");
            let mut keys: Vec<(String, f64)> = remembered
                .iter()
                .map(|(k, v)| (k.clone(), n(v, "signedOutAt")))
                .collect();
            // Array.prototype.sort is stable, as sort_by is.
            keys.sort_by(|a, b| {
                a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal)
            });
            let Some((oldest, _)) = keys.into_iter().next() else {
                return (false, dropped);
            };
            remembered.shift_remove(&oldest);
            dropped += 1;
        }
        let entry = json!({
            "sub": js::or_empty(account.get("sub")),
            "username": js::or_empty(account.get("username")),
            "displayName": js::or_empty(account.get("displayName")),
            "addedAt": js::num(self.clock.now_ms()),
        });
        table(row, "sessions").insert(sid.to_string(), entry);
        if let Some(Value::Object(e)) = row.get_mut("endedSids") {
            e.shift_remove(sid);
        }
        if let Some(Value::Object(f)) = row.get_mut("forgotten") {
            f.shift_remove(&key);
        }
        row.insert("lastActiveSid".into(), json!(sid));
        (true, dropped)
    }

    /// `endSession(row, sid, at)`: the session taken out, its account
    /// remembered as signed out; `None` where the sid was not there.
    #[tracing::instrument(level = "debug", skip(self, row))]
    pub fn end_session(
        &self,
        row: &mut Object,
        sid: &str,
        at: f64,
    ) -> Option<Value> {
        let entry = row
            .get("sessions")
            .and_then(|s| s.get(sid))
            .filter(|e| js::truthy(Some(e)))
            .cloned()?;
        table(row, "sessions").shift_remove(sid);
        let now = self.clock.now_ms();
        table(row, "endedSids").insert(sid.to_string(), js::num(now));
        table(row, "remembered");
        let key = Self::key_of(&entry);
        let still_live = row
            .get("sessions")
            .and_then(Value::as_object)
            .is_some_and(|s| s.values().any(|o| Self::key_of(o) == key));
        let mut remembered = Object::new();
        put(&mut remembered, "sub", entry.get("sub"));
        put(&mut remembered, "username", entry.get("username"));
        put(&mut remembered, "displayName", entry.get("displayName"));
        remembered.insert(
            "signedOutAt".into(),
            js::num(if at.is_nan() || at == 0.0 { now } else { at }),
        );
        let remembered = Value::Object(remembered);
        if !still_live {
            table(row, "remembered").insert(key, remembered.clone());
        }
        if js::string_of(row.get("lastActiveSid")) == sid {
            row.insert("lastActiveSid".into(), json!(""));
        }
        Some(remembered)
    }

    /// `forget(row, key)`: a remembered account forgotten; a live one is
    /// not touched.
    #[tracing::instrument(level = "debug", skip(self, row))]
    pub fn forget(&self, row: &mut Object, key: &str) -> bool {
        if !holds(row, "remembered", key) {
            return false;
        }
        table(row, "remembered").shift_remove(key);
        let now = js::num(self.clock.now_ms());
        table(row, "forgotten").insert(key.to_string(), now);
        true
    }

    /// `prune(row, isLive, nowMs)`: ended sessions to remembered, old
    /// remembered accounts dropped. Answers `(ended, expired)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn prune(
        &self,
        row: &mut Object,
        is_live: &mut dyn FnMut(&str) -> bool,
        now_ms: Option<f64>,
    ) -> (u64, u64) {
        let now = match now_ms {
            Some(t) if t != 0.0 && !t.is_nan() => t,
            _ => self.clock.now_ms(),
        };
        let mut ended = 0;
        let mut expired = 0;
        for sid in keys_of(row, "sessions") {
            if !is_live(&sid) {
                self.end_session(row, &sid, now);
                ended += 1;
            }
        }
        let keep = self.remember_ms();
        for key in keys_of(row, "remembered") {
            let at = row["remembered"]
                .get(&key)
                .map(|e| n(e, "signedOutAt"))
                .unwrap_or(0.0);
            if now - at >= keep {
                table(row, "remembered").shift_remove(&key);
                expired += 1;
            }
        }
        (ended, expired)
    }

    /// `trim(row)`: the newest [`MERGE_MEMORY`] of each merge table.
    fn trim(row: &mut Object) {
        for field in ["endedSids", "forgotten"] {
            let Some(Value::Object(t)) = row.get_mut(field) else {
                continue;
            };
            if t.len() <= MERGE_MEMORY {
                continue;
            }
            let mut keys: Vec<(String, f64)> = t
                .iter()
                .map(|(k, v)| (k.clone(), js::number_or_zero(Some(v))))
                .collect();
            keys.sort_by(|a, b| {
                b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal)
            });
            for (k, _) in keys.into_iter().skip(MERGE_MEMORY) {
                t.shift_remove(&k);
            }
        }
    }

    /// `merge(mine, theirs)`: what two nodes' copies of one set become.
    /// Pure, and convergent: the copy whose handle was issued later is the
    /// base; `sessions` the union less every sid either ended;
    /// `remembered` the union, each account's latest sign-out, less one
    /// forgotten after it signed out or live again; the merge tables
    /// unions with the latest instant.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn merge(mine: &Value, theirs: &Value) -> Value {
        let Some(m) = mine.as_object() else {
            return theirs.clone();
        };
        let Some(t) = theirs.as_object() else {
            return mine.clone();
        };
        let mine_ahead =
            n(mine, "handleIssuedAt") >= n(theirs, "handleIssuedAt");
        let mut out = if mine_ahead { m.clone() } else { t.clone() };
        let latest = |field: &str| {
            let mut table = Object::new();
            for one in [m.get(field), t.get(field)] {
                for (k, v) in js::object_of(one) {
                    let have = js::number_or_zero(table.get(&k));
                    let max = have.max(js::number_or_zero(Some(&v)));
                    table.insert(k, js::num(max));
                }
            }
            table
        };
        let ended = latest("endedSids");
        let forgotten = latest("forgotten");
        let mut sessions = Object::new();
        for one in [t.get("sessions"), m.get("sessions")] {
            for (sid, v) in js::object_of(one) {
                if !js::truthy(ended.get(&sid)) {
                    sessions.insert(sid, v);
                }
            }
        }
        let live: Vec<String> = sessions.values().map(Self::key_of).collect();
        let mut remembered = Object::new();
        for one in [t.get("remembered"), m.get("remembered")] {
            for (k, v) in js::object_of(one) {
                let better = match remembered.get(&k) {
                    None => true,
                    Some(have) => n(&v, "signedOutAt") > n(have, "signedOutAt"),
                };
                if better {
                    remembered.insert(k, v);
                }
            }
        }
        for k in remembered.keys().cloned().collect::<Vec<_>>() {
            let forgot = js::number_or_zero(forgotten.get(&k));
            let at = n(&remembered[&k], "signedOutAt");
            if live.contains(&k) || (forgot != 0.0 && forgot >= at) {
                remembered.shift_remove(&k);
            }
        }
        out.insert("endedSids".into(), Value::Object(ended));
        out.insert("forgotten".into(), Value::Object(forgotten));
        out.insert("sessions".into(), Value::Object(sessions));
        out.insert("remembered".into(), Value::Object(remembered));
        let last = js::or_empty(out.get("lastActiveSid"));
        if !last.is_empty() && !holds(&out, "sessions", &last) {
            out.insert("lastActiveSid".into(), json!(""));
        }
        out.insert(
            "updatedAt".into(),
            js::num(n(mine, "updatedAt").max(n(theirs, "updatedAt"))),
        );
        Value::Object(out)
    }

    // --- selection tickets ---------------------------------------------

    /// `mintTicket(setId, sid, path, pendingId)`: a single-use ticket that
    /// resumes one flow as one session, the account's name kept on it
    /// (#731) for a session that ends in flight.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn mint_ticket(
        &self,
        set_id: &str,
        sid: &str,
        path: &str,
        pending_id: &str,
    ) -> String {
        let ticket = self.clock.random_id(24);
        let username = self
            .here()
            .get(set_id)
            .and_then(|r| r.get("sessions").and_then(|s| s.get(sid)).cloned())
            .filter(|e| js::truthy(Some(e)))
            .map(|e| js::or_empty(e.get("username")))
            .unwrap_or_default();
        self.tickets_here().set(
            &ticket,
            json!({"setId": set_id, "sid": sid, "path": path,
                   "pendingId": pending_id, "username": username,
                   "expires": js::num(self.clock.now_ms() + TICKET_TTL_MS)}),
        );
        ticket
    }

    /// `withTicket(target, ticket)`.
    // A hot path: every ticket minted; no span.
    pub fn with_ticket(target: &str, ticket: &str) -> String {
        format!(
            "{}{}{}={}",
            target,
            if target.contains('?') { '&' } else { '?' },
            TICKET_PARAM,
            encode_uri_component(ticket)
        )
    }

    /// `spendTicket(ticket)`: deleted whatever it held, answered only while
    /// it has not expired.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn spend_ticket(&self, ticket: &str) -> Option<Value> {
        if ticket.is_empty() {
            return None;
        }
        let view = self.tickets_here();
        let row = view.get(ticket);
        view.delete(ticket);
        let row = row.filter(|r| js::truthy(Some(r)))?;
        if js::number(row.get("expires")) > self.clock.now_ms() {
            Some(row)
        } else {
            None
        }
    }

    /// `stripTicket(req)` over an address: the address without the
    /// ticket, and the ticket (' ' for one that is not URI-encoded, '' for
    /// none). The caller also takes it off its parsed query.
    // A hot path: every request's address; no span.
    pub fn strip_ticket(url: &str) -> (String, String) {
        let found = Self::ticket_in(url);
        if found.is_empty() {
            return (url.to_string(), found);
        }
        (Self::without_ticket(url), found)
    }

    fn ticket_in(url: &str) -> String {
        let Some(at) = url.find('?') else {
            return String::new();
        };
        let prefix = format!("{}=", TICKET_PARAM);
        for part in url[at + 1..].split('&') {
            if let Some(raw) = part.strip_prefix(&prefix) {
                let value = decode_uri_component(raw).unwrap_or_default();
                return if value.is_empty() { " ".into() } else { value };
            }
        }
        String::new()
    }

    fn without_ticket(url: &str) -> String {
        let Some(at) = url.find('?') else {
            return url.to_string();
        };
        let prefix = format!("{}=", TICKET_PARAM);
        let kept: Vec<&str> = url[at + 1..]
            .split('&')
            .filter(|p| !p.starts_with(&prefix))
            .collect();
        if kept.is_empty() {
            url[..at].to_string()
        } else {
            format!("{}?{}", &url[..at], kept.join("&"))
        }
    }

    // --- the expiry job ------------------------------------------------

    /// `sweep(isLive)`: every set of the ambient realm pruned, an empty
    /// one deleted.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn sweep(&self, is_live: &mut dyn FnMut(&str) -> bool) -> SweepCounts {
        let now = self.clock.now_ms();
        let mut out = SweepCounts::default();
        for (_, stored) in self.swept_rows() {
            self.sweep_one(&stored, is_live, now, &mut out);
        }
        out
    }

    /// `sweepBudgeted(isLive, budgetMs)` (#784): at most `budget_ms` of
    /// work from where the last run in this realm stopped, yielding
    /// between slices of [`SWEEP_SLICE_MS`]; a pass ends when every set it
    /// began with has been visited.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn sweep_budgeted(
        &self,
        is_live: &mut (dyn FnMut(&str) -> bool + Send),
        budget_ms: Option<u128>,
    ) -> SweepCounts {
        let budget =
            budget_ms.filter(|b| *b > 0).unwrap_or(SWEEP_RUN_BUDGET_MS);
        let realm = realm::current_id();
        let ids = {
            let mut passes =
                self.passes.lock().unwrap_or_else(PoisonError::into_inner);
            let pass = passes.entry(realm.clone()).or_default();
            if pass.ids.as_ref().is_none_or(|ids| pass.at >= ids.len()) {
                pass.ids = Some(
                    self.swept_rows().into_iter().map(|(k, _)| k).collect(),
                );
                pass.at = 0;
            }
            pass.ids.clone().unwrap_or_default()
        };
        let now = self.clock.now_ms();
        let started = Instant::now();
        let mut slice = Instant::now();
        let mut out = SweepCounts {
            slices: 1,
            of: ids.len() as u64,
            ..SweepCounts::default()
        };
        loop {
            let at = self
                .passes
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&realm)
                .map_or(ids.len(), |p| p.at);
            if at >= ids.len() || started.elapsed().as_millis() >= budget {
                out.at = at as u64;
                break;
            }
            if slice.elapsed().as_millis() >= SWEEP_SLICE_MS {
                tokio::task::yield_now().await;
                out.slices += 1;
                slice = Instant::now();
            }
            if let Some(p) = self
                .passes
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get_mut(&realm)
            {
                p.at += 1;
            }
            if let Some(stored) = self.here().get(&ids[at]) {
                if js::truthy(stored.get("id")) {
                    self.sweep_one(&stored, is_live, now, &mut out);
                }
            }
        }
        out
    }

    fn swept_rows(&self) -> Vec<(String, Value)> {
        self.here()
            .entries()
            .into_iter()
            .filter(|(_, r)| js::truthy(r.get("id")))
            .collect()
    }

    fn sweep_one(
        &self,
        stored: &Value,
        is_live: &mut dyn FnMut(&str) -> bool,
        now: f64,
        out: &mut SweepCounts,
    ) {
        out.sets += 1;
        let Some(o) = stored.as_object() else {
            tracing::error!(
                "{}authn: the account-set expiry could not prune a set: \
                 it is not an object",
                tag(codes::STS_AUTHN_0344.as_str())
            );
            return;
        };
        let mut row = o.clone();
        let (ended, expired) = self.prune(&mut row, is_live, Some(now));
        out.ended += ended;
        out.expired += expired;
        if Self::size(&row) == 0 {
            self.remove(&js::string_of(row.get("id")));
            out.deleted += 1;
        } else if ended > 0 || expired > 0 {
            self.save(&mut row);
        }
    }
}

/// A member copied where it is defined (`JSON.stringify` drops undefined).
fn put(o: &mut Object, k: &str, v: Option<&Value>) {
    if let Some(v) = v {
        o.insert(k.to_string(), v.clone());
    }
}

fn remember_ms_of(settings: &dyn Settings) -> f64 {
    let days = js::number(Some(&settings.value("authn.rememberedAccountDays")))
        .floor();
    (if days > 0.0 { days } else { 30.0 }) * DAY_MS
}

fn keep_ms_of(settings: &dyn Settings) -> f64 {
    let lifetime =
        js::number(Some(&settings.value("authn.sessionLifetimeS"))).floor();
    remember_ms_of(settings)
        + 2.0 * (if lifetime > 0.0 { lifetime } else { 3600.0 }) * 1000.0
}

/// `encodeURIComponent()`.
// A hot path: every ticket and address; no span.
pub fn encode_uri_component(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        let keep = b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'')
            || matches!(b, b'(' | b')');
        if keep {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

/// `decodeURIComponent()`; `None` where JavaScript throws `URIError`.
// A hot path: asked on every session read or sign-in; the door's
// span covers it, no span of its own.
pub(crate) fn decode_uri_component(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        let hex = text.get(i + 1..i + 3)?;
        out.push(u8::from_str_radix(hex, 16).ok()?);
        i += 3;
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ticket_comes_off_an_address_and_leaves_the_rest() {
        let (url, t) = AccountSets::strip_ticket("/a?x=1&sts_account=T%2B&y");
        assert_eq!((url.as_str(), t.as_str()), ("/a?x=1&y", "T+"));
        let (url, t) = AccountSets::strip_ticket("/a?sts_account=T");
        assert_eq!((url.as_str(), t.as_str()), ("/a", "T"));
        assert_eq!(AccountSets::strip_ticket("/a?sts_account=%E0").1, " ");
        assert_eq!(AccountSets::strip_ticket("/a").1, "");
        assert_eq!(
            AccountSets::with_ticket("/a?x", "t/1"),
            "/a?x&sts_account=t%2F1"
        );
    }

    #[test]
    fn a_key_is_the_subject_or_the_name() {
        assert_eq!(AccountSets::key_of(&json!({"sub": "s"})), "s");
        assert_eq!(
            AccountSets::key_of(&json!({"sub": "", "username": "u"})),
            "name:u"
        );
    }
}
