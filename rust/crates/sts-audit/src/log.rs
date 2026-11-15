// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE AUDIT LOG (`common/audit.js`): what happened here, in the order it
//! happened, as a ring of discrete events per trust realm.
//!
//! What replaced what (rust/DESIGN.md section 4):
//!
//! * `realms.arr()` and `realms.obj()` → a map of realm id to
//!   [`RealmRing`] inside [`AuditLog`]; the ambient realm is
//!   `sts_core::realm::current_id()`. Persisting the ring
//!   (`audit.events`, `audit.nums`, `merge: 'own'`) is the store's: every
//!   change is handed to [`RingSink`], and [`AuditLog::restore`] takes back
//!   what the store kept. The rows and the counters are Node's JSON, so a
//!   1.x ring reads back unchanged.
//! * `seq_allocator.ts` → [`SeqSource`]; `None` (no shared store) is the
//!   realm's own counter, as in Node.
//! * `keystore.keyedDigest()` → [`KeyedDigest`]; `sts-store`'s `DataKeys`
//!   is the real one.
//! * the replication fan-in (`remoteSegmentedRows`, `remoteRows`) →
//!   [`Replication`]; none is one process.
//! * `AsyncLocalStorage` sources → [`AuditLog::with_source`] (a thread's
//!   synchronous work) and [`AuditLog::scope_source`] (a task's).
//! * `setActorResolver()` / `setActorSessionResolver()` → the HTTP layer
//!   resolves both and hands them in on the [`HttpExchange`]; the contract
//!   (no side effect, never fails a request) is that layer's.
//! * `errorCodes.mark(res)` → [`HttpExchange::marked`];
//!   `reserveIncident(res)` → [`AuditLog::reserve_incident`], whose number
//!   the caller carries on [`HttpExchange::incident`].
//!
//! The three load-bearing properties stay: recording CANNOT fail an
//! operation (every entry point answers `Option`, never an error), NO
//! CREDENTIAL is recorded (the one field read out of a body is `action`),
//! and the VOCABULARY is a table ([`crate::vocabulary`]).

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value as Json};
use sts_core::errors::{self, codes};
use sts_core::settings::{keys, Settings};

use crate::js;
use crate::row::AuditRow;
use crate::vocabulary;

const MAX_DETAIL_KEYS: usize = 12;
const MAX_DETAIL_LENGTH: usize = 200;
const MAX_SUMMARY_LENGTH: usize = 400;
const MAX_ACTION_LENGTH: usize = 60;
const QUIET_WHEN_OK: &[&str] = &["/healthcheck"];
const REDACTED_CAPABILITIES: &[&str] =
    &["authn", "mfa", "state", "response_code", "change", "t", "consent"];
const REDACTED_QUERY_KEYS: &[&str] = &[
    "code",
    "id_token_hint",
    "access_token",
    "token",
    "assertion",
    "client_secret",
    "password",
    "credential",
    "vp_token",
    "response",
];

/// The actions an application's or a person's Authentication attempts tab
/// counts (#954).
const ATTEMPT_ACTIONS: &[&str] = &[
    "authentication",
    "authentication.refused",
    "session.refuse",
    "session.refused",
    "session.presented",
];

/// A keyed checksum: `keystore.keyedDigest(label, text)`, `None` with no
/// key-encryption key in the process.
pub trait KeyedDigest: Send + Sync {
    fn keyed_digest(&self, label: &str, text: &str) -> Option<String>;
}

impl<F> KeyedDigest for F
where
    F: Fn(&str, &str) -> Option<String> + Send + Sync,
{
    fn keyed_digest(&self, label: &str, text: &str) -> Option<String> {
        self(label, text)
    }
}

/// `seq_allocator.next('audit', local)`: a number unique across every
/// process of a shared store, or `None` where there is none, when the
/// realm's own counter numbers the row.
pub trait SeqSource: Send + Sync {
    fn next(&self, name: &str) -> Option<i64>;
}

/// The other processes' contributions (`persistence_replication`): their
/// segmented rows of `audit.events` and their `recorded` counters.
pub trait Replication: Send + Sync {
    fn remote_segmented_rows(&self) -> Vec<Vec<AuditRow>>;
    fn remote_recorded(&self) -> i64;
}

/// The store's half of `realms.arr({ persist: 'audit.events' })`: told of
/// every change to a realm's ring and counters.
pub trait RingSink: Send + Sync {
    fn changed(&self, realm: &str, rows: &VecDeque<AuditRow>, nums: &Nums);
}

/// `Date.now()`.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> i64;
}

/// The system clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        chrono::Utc::now().timestamp_millis()
    }
}

/// What the log is built with.
pub struct AuditPorts {
    pub settings: Arc<Settings>,
    pub clock: Arc<dyn Clock>,
    pub digest: Option<Arc<dyn KeyedDigest>>,
    pub seq: Option<Arc<dyn SeqSource>>,
    /// `persistence.originId()`: this process's stable origin, or `''`.
    pub origin: Arc<dyn Fn() -> String + Send + Sync>,
    pub replication: Option<Arc<dyn Replication>>,
    pub sink: Option<Arc<dyn RingSink>>,
}

impl AuditPorts {
    /// One process, no shared store, the system clock.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn local(settings: Arc<Settings>) -> AuditPorts {
        AuditPorts {
            settings,
            clock: Arc::new(SystemClock),
            digest: None,
            seq: None,
            origin: Arc::new(String::new),
            replication: None,
            sink: None,
        }
    }
}

/// `audit.nums`: the realm's counter, what it recorded, and the head of
/// the chain (ASVS 5.0.0 16.4.2), as the store keeps them.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Nums {
    #[serde(default)]
    pub seq: i64,
    #[serde(default)]
    pub recorded: i64,
    #[serde(default)]
    pub head: String,
    #[serde(rename = "headSeq", default)]
    pub head_seq: i64,
    #[serde(rename = "headMac", default)]
    pub head_mac: String,
}

/// One realm's ring and counters.
#[derive(Debug, Default)]
pub struct RealmRing {
    pub events: VecDeque<AuditRow>,
    pub nums: Nums,
}

/// The management API's verified caller (`res.locals.apiCaller`).
#[derive(Debug, Clone, Default)]
pub struct ApiCaller {
    pub name: String,
    pub owner: bool,
}

/// One answered HTTP request, as `recordHttp(req, res, detail)` reads it.
#[derive(Debug, Clone, Default)]
pub struct HttpExchange {
    pub method: String,
    /// `req.originalUrl`, with its query.
    pub original_url: String,
    /// `req.query`, in its order.
    pub query: Map<String, Json>,
    /// The raw body, where the app kept it as text.
    pub body: Option<String>,
    pub content_type: String,
    pub status: u16,
    /// The code the handler marked (`errorCodes.mark(res, …)`).
    pub marked: Option<String>,
    pub route: String,
    pub matched: bool,
    pub duration_ms: f64,
    /// `client_address.clientAddressOf(req)`.
    pub address: String,
    /// The signed-in user the actor resolver names, or `''`.
    pub actor: String,
    /// The session the actor-session resolver names, or `''` (#561).
    pub session: String,
    pub api_caller: Option<ApiCaller>,
    /// `res.locals.auditQuietWhenOk`.
    pub quiet_when_ok: bool,
    /// The number `reserve_incident()` gave the error page (#1326).
    pub incident: Option<i64>,
}

tokio::task_local! {
    static TASK_SOURCE: String;
}

thread_local! {
    static SOURCES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

static REDACTED_PATHS: std::sync::LazyLock<Option<Regex>> =
    std::sync::LazyLock::new(|| {
        Regex::new(
            r"(/authn-api/(?:pending|password-change|wallet|mfa|consent)/)[^/?#]+",
        )
        .ok()
    });

static REDACTED_QUERY_VALUES: std::sync::LazyLock<Option<Regex>> =
    std::sync::LazyLock::new(|| {
        Regex::new(&format!(
            "([?&](?:{})=)[^&#]*",
            REDACTED_CAPABILITIES.join("|")
        ))
        .ok()
    });

static COMMA_SPACE: std::sync::LazyLock<Option<Regex>> =
    std::sync::LazyLock::new(|| Regex::new(r"\s*,\s*").ok());

/// `trimmed(value, limit)`: the text, or its first `limit` UTF-16 units
/// and how long it was. A hot path (every field of every row): no span.
pub(crate) fn trimmed(text: &str, limit: usize) -> String {
    let length = js::len16(text);
    if length <= limit {
        return text.to_string();
    }
    format!("{}… ({} characters)", js::head16(text, limit), length)
}

/// `detailOf(source)`: at most twelve members, each a number, a boolean
/// or a trimmed text; empty ones dropped. A hot path: no span.
fn detail_of(source: &Json) -> Map<String, Json> {
    let mut out = Map::new();
    let entries = js::entries_of(source);
    for (key, value) in entries.iter().take(MAX_DETAIL_KEYS) {
        match value {
            Json::Null => {}
            Json::String(s) if s.is_empty() => {}
            Json::Number(_) | Json::Bool(_) => {
                out.insert(key.clone(), value.clone());
            }
            other => {
                out.insert(
                    key.clone(),
                    Json::from(trimmed(&js::text_of(other), MAX_DETAIL_LENGTH)),
                );
            }
        }
    }
    if entries.len() > MAX_DETAIL_KEYS {
        out.insert(
            "(more)".to_string(),
            Json::from(format!(
                "{} further field(s) not kept",
                entries.len() - MAX_DETAIL_KEYS
            )),
        );
    }
    out
}

/// `client_address.normalise()` and `'unknown'` as `''`. A hot path: no
/// span.
fn address_text(raw: &str) -> String {
    let text = raw.trim();
    let mapped = text.len() > 7
        && text[..7].eq_ignore_ascii_case("::ffff:")
        && is_dotted_quad(&text[7..]);
    let out = if mapped { &text[7..] } else { text };
    if out == "unknown" {
        String::new()
    } else {
        out.to_string()
    }
}

fn is_dotted_quad(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// `outcomeOfStatus()`: 501 is a refusal (a feature switched off), any
/// other 5xx an error, a 4xx a refusal.
#[tracing::instrument(level = "debug")]
pub fn outcome_of_status(status: u16) -> &'static str {
    match status {
        501 => "refused",
        500..=u16::MAX => "error",
        400..=499 => "refused",
        _ => "success",
    }
}

/// `httpActionFor()`: `/admin-api` before `/admin`, which it starts with.
#[tracing::instrument(level = "debug")]
pub fn http_action_for(path: &str, method: &str) -> &'static str {
    let write = method != "GET" && method != "HEAD" && method != "OPTIONS";
    if path == "/admin-api" || path.starts_with("/admin-api/") {
        return if write { "api.change" } else { "api.read" };
    }
    if path == "/admin" || path.starts_with("/admin/") {
        return if write { "admin.change" } else { "admin.view" };
    }
    "protocol.call"
}

/// `quietWhenOk()`: a `GET` or `HEAD` of `/healthcheck` answered 200. A
/// hot path (every answered request, twice): no span.
pub fn quiet_when_ok(method: &str, path: &str, status: &str) -> bool {
    let m = method.to_uppercase();
    QUIET_WHEN_OK.contains(&path)
        && (m == "GET" || m == "HEAD")
        && js::parse_int(status) == Some(200)
}

/// `redactedPath()`: a capability in a path or a query replaced.
#[tracing::instrument(level = "debug")]
pub fn redacted_path(path: &str) -> String {
    let mut out = path.to_string();
    if let Some(re) = REDACTED_PATHS.as_ref() {
        out = re.replace_all(&out, "${1}(redacted)").into_owned();
    }
    if let Some(re) = REDACTED_QUERY_VALUES.as_ref() {
        out = re.replace_all(&out, "${1}(redacted)").into_owned();
    }
    out
}

/// `redactedQuery()`: every capability's value replaced, for a log line.
#[tracing::instrument(level = "debug", skip(query))]
pub fn redacted_query(query: &Map<String, Json>) -> Map<String, Json> {
    let mut out = Map::new();
    for key in js::keys_of(query) {
        let value = if REDACTED_CAPABILITIES
            .contains(&key.to_lowercase().as_str())
        {
            Json::from("(redacted)")
        } else {
            query.get(&key).cloned().unwrap_or(Json::Null)
        };
        out.insert(key, value);
    }
    out
}

/// `queryText()`: the query as one short line, credentials redacted.
fn query_text(query: &Map<String, Json>) -> String {
    js::keys_of(query)
        .into_iter()
        .take(MAX_DETAIL_KEYS)
        .map(|key| {
            let lower = key.to_lowercase();
            let redact = REDACTED_QUERY_KEYS.contains(&lower.as_str())
                || REDACTED_CAPABILITIES.contains(&lower.as_str());
            let value = if redact {
                "(redacted)".to_string()
            } else {
                trimmed(&js::text_or_empty(query.get(&key)), 60)
            };
            format!("{}={}", key, value)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// `actionOf(req)`: the `action` a form or a JSON body names, capped, and
/// nothing else out of that body.
fn action_of(body: Option<&str>, content_type: &str) -> String {
    let raw = match body {
        Some(b) if !b.is_empty() => b,
        _ => return String::new(),
    };
    if content_type.to_lowercase().contains("json") {
        return match serde_json::from_str::<Json>(raw) {
            Ok(parsed) => trimmed(
                &js::text_or_empty(parsed.get("action")),
                MAX_ACTION_LENGTH,
            ),
            Err(e) => {
                tracing::debug!("actionOf: not a body this can read: {}", e);
                String::new()
            }
        };
    }
    let found = url::form_urlencoded::parse(raw.as_bytes())
        .find(|(k, _)| k == "action")
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default();
    trimmed(&found, MAX_ACTION_LENGTH)
}

/// `errorCodes.fallbackFor(status, matched)`: the generic code for a
/// failed response nothing marked.
fn fallback_for(status: u16, matched: bool) -> &'static str {
    if status == 404 && !matched {
        return codes::STS_HTTP_0001.as_str();
    }
    if status == 413 {
        return codes::STS_HTTP_0004.as_str();
    }
    if status >= 500 {
        return codes::STS_HTTP_0003.as_str();
    }
    if status >= 400 {
        return codes::STS_HTTP_0002.as_str();
    }
    ""
}

fn normalised_dn(text: &str) -> String {
    let lower = text.to_lowercase();
    match COMMA_SPACE.as_ref() {
        Some(re) => re.replace_all(&lower, ",").into_owned(),
        None => lower,
    }
}

/// `objectKindOf()`: `user`, `group` or `entry`, by where the entry sits.
#[tracing::instrument(level = "debug")]
pub fn object_kind_of(dn: &str, users: &str, groups: &str) -> &'static str {
    let lower = normalised_dn(dn);
    let users = normalised_dn(users);
    let groups = normalised_dn(groups);
    if !users.is_empty()
        && lower != users
        && lower.ends_with(&format!(",{}", users))
    {
        return "user";
    }
    if !groups.is_empty()
        && lower != groups
        && lower.ends_with(&format!(",{}", groups))
    {
        return "group";
    }
    "entry"
}

/// `directoryActionFor()`: `user.delete` and the like.
#[tracing::instrument(level = "debug")]
pub fn directory_action_for(
    operation: &str,
    dn: &str,
    users: &str,
    groups: &str,
) -> String {
    format!("{}.{}", object_kind_of(dn, users, groups), operation)
}

/// The audit log of one process: a ring per realm.
pub struct AuditLog {
    ports: AuditPorts,
    rings: Mutex<HashMap<String, RealmRing>>,
    dropped: AtomicI64,
}

impl AuditLog {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(ports: AuditPorts) -> AuditLog {
        AuditLog {
            ports,
            rings: Mutex::new(HashMap::new()),
            dropped: AtomicI64::new(0),
        }
    }

    fn rings(&self) -> MutexGuard<'_, HashMap<String, RealmRing>> {
        match self.rings.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn max_events(&self) -> i64 {
        self.ports.settings.value(keys::AUDIT_MAX_EVENTS).as_int()
    }

    fn protocol_calls_recorded(&self) -> bool {
        self.ports.settings.value(keys::AUDIT_PROTOCOL_CALLS).as_bool()
    }

    fn cap(&self) -> usize {
        self.max_events().max(1) as usize
    }

    fn origin(&self) -> String {
        (self.ports.origin)()
    }

    /// Takes back what the store kept for a realm (`audit.events`,
    /// `audit.nums`), when the store is opened.
    #[tracing::instrument(level = "debug", skip(self, rows, nums))]
    pub fn restore(&self, realm: &str, rows: Vec<AuditRow>, nums: Nums) {
        let mut rings = self.rings();
        let ring = rings.entry(realm.to_string()).or_default();
        ring.events = rows.into();
        ring.nums = nums;
    }

    fn next_seq(&self, ring: &mut RealmRing) -> i64 {
        if let Some(n) = self.ports.seq.as_ref().and_then(|s| s.next("audit"))
        {
            return n;
        }
        ring.nums.seq += 1;
        ring.nums.seq
    }

    /// `reserveIncident(res)`: the `seq` the response's row will carry,
    /// the incident ID an error page prints (#1326). The caller carries it
    /// on [`HttpExchange::incident`] in the same synchronous run.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn reserve_incident(&self) -> i64 {
        let realm = sts_core::realm::current_id();
        let mut rings = self.rings();
        let ring = rings.entry(realm).or_default();
        self.next_seq(ring)
    }

    /// `withSource({ address }, fn)` for synchronous work: every row
    /// written inside carries this address unless the event names one.
    #[tracing::instrument(level = "debug", skip(work))]
    pub fn with_source<R>(address: &str, work: impl FnOnce() -> R) -> R {
        SOURCES.with(|s| s.borrow_mut().push(address.to_string()));
        let out = work();
        SOURCES.with(|s| {
            s.borrow_mut().pop();
        });
        out
    }

    /// The same for a task and everything it awaits.
    #[tracing::instrument(level = "debug", skip(work))]
    pub async fn scope_source<F: std::future::Future>(
        address: String,
        work: F,
    ) -> F::Output {
        TASK_SOURCE.scope(address, work).await
    }

    /// `currentAddress()`: the ambient source's address, or `''`.
    #[tracing::instrument(level = "debug")]
    pub fn current_address() -> String {
        let task = TASK_SOURCE.try_with(|a| a.clone()).ok();
        let raw = task.or_else(|| SOURCES.with(|s| s.borrow().last().cloned()));
        raw.map(|a| address_text(&a)).unwrap_or_default()
    }

    /// `audit(event)`: records one event, given as the object Node's
    /// callers pass. Never fails: a row that could not be made is `None`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn audit(&self, event: &Json) -> Option<AuditRow> {
        let realm = sts_core::realm::current_id();
        let row = {
            let mut rings = self.rings();
            let ring = rings.entry(realm.clone()).or_default();
            let row = self.record(ring, event);
            let cap = self.cap();
            while ring.events.len() > cap {
                ring.events.pop_front();
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            if let Some(sink) = &self.ports.sink {
                sink.changed(&realm, &ring.events, &ring.nums);
            }
            row
        };
        let summarised = event
            .get("summarised")
            .is_some_and(|v| v == &Json::Bool(true));
        if !row.error_code.is_empty() && !summarised {
            log_failure(&row);
        }
        Some(row)
    }

    fn record(&self, ring: &mut RealmRing, info: &Json) -> AuditRow {
        let action = if js::truthy(info.get("action")) {
            js::text_of(&info["action"])
        } else {
            "protocol.call".to_string()
        };
        let category = match vocabulary::category_of(&action) {
            Some(c) => c.to_string(),
            None if js::truthy(info.get("category")) => {
                js::text_of(&info["category"])
            }
            None => "protocol".to_string(),
        };
        let now = self.ports.clock.now_ms();
        let error_code = if js::truthy(info.get("errorCode")) {
            trimmed(&js::text_of(&info["errorCode"]), 40)
        } else {
            String::new()
        };
        if !error_code.is_empty() && !errors::is_known(&error_code) {
            tracing::warn!(
                "an audit event carried an unregistered error code, {}; it \
                 is recorded as given. Add it to common/error_codes.js.",
                error_code
            );
        }
        let given = info.get("outcome").and_then(Json::as_str).unwrap_or("");
        let outcome = if vocabulary::is_outcome(given) {
            given.to_string()
        } else if error_code.is_empty() {
            "success".to_string()
        } else {
            "refused".to_string()
        };
        ring.nums.recorded += 1;
        let seq = match info.get("seq").and_then(Json::as_f64) {
            Some(n) if n.fract() == 0.0 && n > 0.0 => n as i64,
            _ => self.next_seq(ring),
        };
        let text = |key: &str, limit: usize| {
            trimmed(&js::text_if_truthy(info.get(key)), limit)
        };
        let address = if js::truthy(info.get("address")) {
            address_text(&js::text_of(&info["address"]))
        } else {
            AuditLog::current_address()
        };
        let detail_is_text = info.get("detail").is_some_and(Json::is_string);
        let summary_given = js::truthy(info.get("summary"));
        let summary_text = if summary_given {
            js::text_of(&info["summary"])
        } else if detail_is_text {
            js::text_of(&info["detail"])
        } else {
            String::new()
        };
        let tag = if error_code.is_empty() {
            String::new()
        } else {
            sts_core::log::tag(&error_code)
        };
        let detail = if detail_is_text {
            if summary_given {
                detail_of(&json!({ "note": info["detail"].clone() }))
            } else {
                Map::new()
            }
        } else {
            detail_of(info.get("detail").unwrap_or(&Json::Null))
        };
        let mut row = AuditRow {
            seq,
            origin: self.origin(),
            at: now,
            category,
            action,
            outcome,
            error_code,
            actor: text("actor", MAX_DETAIL_LENGTH),
            actor_form: text("actorForm", MAX_DETAIL_LENGTH),
            target: text("target", MAX_DETAIL_LENGTH),
            protocol: text("protocol", 60),
            channel: text("channel", 40),
            address: trimmed(&address, 64),
            summary: trimmed(
                &format!("{}{}", tag, summary_text),
                MAX_SUMMARY_LENGTH,
            ),
            detail,
            prev: Some(ring.nums.head.clone()),
            mac: None,
        };
        let mac = self.row_mac(&row);
        if mac.is_empty() {
            ring.nums.head = String::new();
            ring.nums.head_seq = 0;
            ring.nums.head_mac = String::new();
        } else {
            ring.nums.head = mac.clone();
            ring.nums.head_seq = row.seq;
            ring.nums.head_mac = self.head_mac(&row.origin, row.seq, &mac);
        }
        row.mac = Some(mac);
        ring.events.push_back(row.clone());
        row
    }

    fn row_mac(&self, row: &AuditRow) -> String {
        self.ports
            .digest
            .as_ref()
            .and_then(|d| d.keyed_digest("audit-row", &row.mac_text()))
            .unwrap_or_default()
    }

    fn head_mac(&self, origin: &str, seq: i64, mac: &str) -> String {
        let text = json!([origin, seq, mac]).to_string();
        self.ports
            .digest
            .as_ref()
            .and_then(|d| d.keyed_digest("audit-head", &text))
            .unwrap_or_default()
    }

    /// `failure(code, event)`: a row whose whole point is its error code;
    /// `action` defaults to `protocol.failure`.
    #[tracing::instrument(level = "debug", skip(self, event))]
    pub fn failure(&self, code: &str, event: &Json) -> Option<AuditRow> {
        let mut info = event.as_object().cloned().unwrap_or_default();
        info.insert("errorCode".to_string(), Json::from(code));
        if !js::truthy(info.get("action")) {
            info.insert("action".to_string(), Json::from("protocol.failure"));
        }
        self.audit(&Json::Object(info))
    }

    /// `recordDirectory(event)`: one directory operation, LDAP by default.
    #[tracing::instrument(level = "debug", skip(self, event))]
    pub fn record_directory(&self, event: &Json) -> Option<AuditRow> {
        let or = |key: &str, fallback: &str| {
            if js::truthy(event.get(key)) {
                event[key].clone()
            } else {
                Json::from(fallback)
            }
        };
        let mut info = Map::new();
        info.insert(
            "action".into(),
            event.get("action").cloned().unwrap_or(Json::Null),
        );
        info.insert(
            "outcome".into(),
            event.get("outcome").cloned().unwrap_or(Json::Null),
        );
        for (key, fallback) in [
            ("actor", ""),
            ("actorForm", ""),
            ("target", ""),
            ("protocol", "LDAP"),
            ("channel", "ldap"),
            ("address", ""),
            ("summary", ""),
            ("errorCode", ""),
        ] {
            info.insert(key.into(), or(key, fallback));
        }
        info.insert(
            "detail".into(),
            event.get("detail").cloned().unwrap_or(Json::Null),
        );
        self.audit(&Json::Object(info))
    }

    /// `recordHttp(req, res, detail)`: one answered request, from the call
    /// log. Every failure is recorded and carries a code, even with
    /// `audit.protocolCalls` off; a healthcheck answered 200 is not.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn record_http(&self, x: &HttpExchange) -> Option<AuditRow> {
        let bare = x.original_url.split('?').next().unwrap_or("");
        let path = redacted_path(if x.original_url.is_empty() {
            "/"
        } else {
            bare
        });
        if quiet_when_ok(&x.method, &path, &x.status.to_string()) {
            return None;
        }
        let action = http_action_for(&path, &x.method);
        let marked = x.marked.clone().unwrap_or_default();
        let error_code = if marked.is_empty() {
            fallback_for(x.status, x.matched).to_string()
        } else {
            marked.clone()
        };
        let status_outcome = outcome_of_status(x.status);
        if x.quiet_when_ok
            && error_code.is_empty()
            && status_outcome == "success"
        {
            return None;
        }
        if action == "protocol.call"
            && !self.protocol_calls_recorded()
            && error_code.is_empty()
        {
            return None;
        }
        let caller = x.api_caller.as_ref();
        let actor = match caller {
            Some(c) if !c.name.is_empty() => c.name.clone(),
            _ => x.actor.clone(),
        };
        let session = if caller.is_some() {
            String::new()
        } else {
            x.session.clone()
        };
        let posted = if action == "admin.change" || action == "api.change" {
            action_of(x.body.as_deref(), &x.content_type)
        } else {
            String::new()
        };
        let owner = caller.is_some_and(|c| c.owner);
        let outcome = if !marked.is_empty() && status_outcome == "success" {
            "refused"
        } else {
            status_outcome
        };
        let mut summary =
            format!("{} {} → {}", x.method, path, x.status);
        if !posted.is_empty() {
            summary.push_str(&format!(" ({})", posted));
        }
        if owner {
            summary.push_str(" as an owner");
        }
        let duration = serde_json::Number::from_f64(x.duration_ms)
            .map(|n| match n.as_f64() {
                Some(f) if f.fract() == 0.0 => Json::from(f as i64),
                _ => Json::Number(n),
            })
            .unwrap_or(Json::from(0));
        let mut detail = json!({
            "method": x.method,
            "status": x.status,
            "route": x.route,
            "matched": x.matched,
            "durationMs": duration,
            "query": query_text(&x.query),
            "postedAction": posted,
            "via": if owner { "owner" } else { "" },
        });
        if !session.is_empty() {
            detail["sessionId"] = Json::from(session);
        }
        let mut event = json!({
            "action": action,
            "outcome": outcome,
            "errorCode": error_code,
            "actor": actor,
            "target": path,
            "channel": "http",
            "address": x.address,
            "protocol": "",
            "summary": summary,
            "detail": detail,
        });
        if let Some(seq) = x.incident.filter(|n| *n > 0) {
            event["seq"] = Json::from(seq);
        }
        self.audit(&event)
    }

    fn merged(&self) -> Vec<AuditRow> {
        let realm = sts_core::realm::current_id();
        let mine: Vec<AuditRow> = self
            .rings()
            .get(&realm)
            .map(|r| r.events.iter().cloned().collect())
            .unwrap_or_default();
        let cap = self.cap();
        let others: Vec<Vec<AuditRow>> = self
            .ports
            .replication
            .as_ref()
            .map(|r| r.remote_segmented_rows())
            .unwrap_or_default()
            .into_iter()
            .map(|rows| {
                if rows.len() > cap {
                    rows[rows.len() - cap..].to_vec()
                } else {
                    rows
                }
            })
            .collect();
        if others.is_empty() {
            return mine;
        }
        let mut all = mine;
        for rows in others {
            all.extend(rows);
        }
        all.sort_by(|a, b| {
            a.at.cmp(&b.at)
                .then_with(|| a.origin.cmp(&b.origin))
                .then_with(|| a.seq.cmp(&b.seq))
        });
        all
    }

    /// `list()`: every process's events of the realm, newest first.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn list(&self) -> Vec<AuditRow> {
        let mut all = self.merged();
        all.reverse();
        all
    }

    /// `localEvents()`: this process's own ring, oldest first — what the
    /// export delivers (#641).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn local_events(&self) -> Vec<AuditRow> {
        let realm = sts_core::realm::current_id();
        self.rings()
            .get(&realm)
            .map(|r| r.events.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// `authenticationEventsFor(names)`: the attempts naming one of the
    /// application's names in `detail.client_id` or `detail.application`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn authentication_events_for(&self, names: &[String]) -> Vec<AuditRow> {
        let wanted = wanted_of(names);
        if wanted.is_empty() {
            return Vec::new();
        }
        self.list()
            .into_iter()
            .filter(|row| {
                ATTEMPT_ACTIONS.contains(&row.action.as_str())
                    && (named(&row.detail, "client_id", &wanted)
                        || named(&row.detail, "application", &wanted))
            })
            .collect()
    }

    /// `authenticationEventsForPerson(names, since)`: the attempts by one
    /// of a person's names, at or after `since` when it is above zero.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn authentication_events_for_person(
        &self,
        names: &[String],
        since: f64,
    ) -> Vec<AuditRow> {
        let wanted = wanted_of(names);
        if wanted.is_empty() {
            return Vec::new();
        }
        let windowed = since.is_finite() && since > 0.0;
        self.list()
            .into_iter()
            .filter(|row| {
                if !ATTEMPT_ACTIONS.contains(&row.action.as_str()) {
                    return false;
                }
                if windowed && (row.at as f64) < since {
                    return false;
                }
                let hit = |text: &str| {
                    let t = text.trim();
                    !t.is_empty() && wanted.iter().any(|w| w == t)
                };
                hit(&row.actor)
                    || hit(&row.actor_form)
                    || named(&row.detail, "sub", &wanted)
                    || named(&row.detail, "presented", &wanted)
            })
            .collect()
    }

    /// `summary()`: every process's events counted by category, action and
    /// outcome, with what is held, recorded and dropped.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn summary(&self) -> Json {
        let all = self.merged();
        let realm = sts_core::realm::current_id();
        let (here, mut recorded) = {
            let rings = self.rings();
            rings
                .get(&realm)
                .map(|r| (r.events.len(), r.nums.recorded))
                .unwrap_or((0, 0))
        };
        let remote = self.ports.replication.as_ref();
        recorded += remote.map(|r| r.remote_recorded()).unwrap_or(0);
        let mut by_category = Map::new();
        for c in vocabulary::categories() {
            by_category.insert(c.category.clone(), Json::from(0));
        }
        let mut by_outcome = Map::new();
        for o in vocabulary::outcomes() {
            by_outcome.insert(o.clone(), Json::from(0));
        }
        let mut by_action = Map::new();
        let bump = |map: &mut Map<String, Json>, key: &str| {
            let n = map.get(key).and_then(Json::as_i64).unwrap_or(0);
            map.insert(key.to_string(), Json::from(n + 1));
        };
        for row in &all {
            bump(&mut by_category, &row.category);
            bump(&mut by_action, &row.action);
            bump(&mut by_outcome, &row.outcome);
        }
        let first = all.first();
        let last = all.last();
        json!({
            "held": all.len(),
            "recorded": recorded,
            "heldHere": here,
            "processes": 1 + remote
                .map(|r| r.remote_segmented_rows().len())
                .unwrap_or(0),
            "dropped": self.dropped.load(Ordering::Relaxed),
            "maxEvents": self.max_events(),
            "protocolCalls": self.protocol_calls_recorded(),
            "oldestAt": first.map(|r| r.at).unwrap_or(0),
            "newestAt": last.map(|r| r.at).unwrap_or(0),
            "oldestSeq": first.map(|r| r.seq).unwrap_or(0),
            "newestSeq": last.map(|r| r.seq).unwrap_or(0),
            "byCategory": by_category,
            "byAction": by_action,
            "byOutcome": by_outcome,
        })
    }

    /// `verifyIntegrity(held)` (ASVS 5.0.0 16.4.2): which rows no longer
    /// match their checksum, where a row is missing between two held ones,
    /// and whether this process's newest row is still there. `held` is
    /// this realm's ring when `None`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn verify_integrity(&self, held: Option<&[AuditRow]>) -> Json {
        let rows: Vec<AuditRow> = match held {
            Some(rows) => rows.to_vec(),
            None => self.list(),
        };
        let mut checked = 0;
        let mut unsigned = 0;
        let mut altered: Vec<i64> = Vec::new();
        let mut by_origin: Vec<(String, Vec<AuditRow>)> = Vec::new();
        for row in rows {
            let mac = row.mac.clone().unwrap_or_default();
            if mac.is_empty() {
                unsigned += 1;
                continue;
            }
            checked += 1;
            let again = self.row_mac(&row);
            if !again.is_empty() && again != mac {
                altered.push(row.seq);
            }
            match by_origin.iter_mut().find(|(o, _)| *o == row.origin) {
                Some((_, list)) => list.push(row),
                None => by_origin.push((row.origin.clone(), vec![row])),
            }
        }
        let mut missing: Vec<Json> = Vec::new();
        for (origin, list) in by_origin.iter_mut() {
            list.sort_by_key(|r| r.seq);
            for i in 1..list.len() {
                if let Some(prev) = &list[i].prev {
                    if Some(prev) != list[i - 1].mac.as_ref() {
                        missing.push(json!({ "origin": origin,
                            "after": list[i - 1].seq,
                            "before": list[i].seq }));
                    }
                }
            }
        }
        let nums = {
            let realm = sts_core::realm::current_id();
            self.rings()
                .get(&realm)
                .map(|r| r.nums.clone())
                .unwrap_or_default()
        };
        let mut head = "none";
        if !nums.head.is_empty() {
            let origin = self.origin();
            let newest = by_origin
                .iter()
                .find(|(o, _)| *o == origin)
                .and_then(|(_, list)| list.last());
            head = if self.head_mac(&origin, nums.head_seq, &nums.head)
                != nums.head_mac
            {
                "altered"
            } else if newest.and_then(|r| r.mac.as_ref()) != Some(&nums.head)
            {
                "truncated"
            } else {
                "intact"
            };
        }
        json!({ "checked": checked, "unsigned": unsigned,
                "altered": altered, "missing": missing, "head": head })
    }
}

fn wanted_of(names: &[String]) -> Vec<String> {
    names
        .iter()
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .collect()
}

fn named(detail: &Map<String, Json>, key: &str, wanted: &[String]) -> bool {
    let text = js::text_or_empty(detail.get(key));
    let t = text.trim();
    !t.is_empty() && wanted.iter().any(|w| w == t)
}

/// `logFailure(row)`: the one log line a row with a code writes; `info`
/// for a refusal, `error` for an error.
fn log_failure(row: &AuditRow) {
    let mut line = row.summary.clone();
    if !row.target.is_empty() {
        line.push_str(&format!(" ({})", row.target));
    }
    if !row.actor.is_empty() {
        line.push_str(&format!(" actor={}", row.actor));
    }
    if !row.address.is_empty() {
        line.push_str(&format!(" from={}", row.address));
    }
    line.push_str(&format!(" action={} outcome={}", row.action, row.outcome));
    if row.outcome == "error" {
        tracing::error!("{}", line);
    } else {
        tracing::info!("{}", line);
    }
}
