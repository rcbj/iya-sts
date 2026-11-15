// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! AUDIT EXPORT (`common/audit_export.ts`, #641; `common/CLAUDE.md` 3da):
//! one process delivers its OWN audit rows to the destinations an
//! administrator configured for the realm, at least once.
//!
//! What a maintainer must not undo is Node's, and the module header there
//! argues it; the short form:
//!
//! * THE RING IS THE RECORD. A tick reads [`AuditSink::local_events`],
//!   this process's ring, oldest first; nothing is copied to an outbox.
//! * DESTINATIONS ARE SHARED, CURSORS ARE THIS PROCESS'S
//!   (`audit.export.destinations`, `audit.export.cursors` with
//!   `merge: 'own'`): [`ExportMaps`], whose JSON is Node's, so a 1.x
//!   install's destinations and cursors read back unchanged.
//! * A NEW ENABLED DESTINATION BACKFILLS ONCE; a gap is a missing
//!   bookmark (`nextSeq`), never `seq` arithmetic; the cursor moves on
//!   success and on a permanent rejection; give-up drops one batch, then
//!   waits; rows this subsystem writes carry `detail.exportSkip`.
//! * Every destination kind's bytes are Node's: the canonical event, the
//!   RFC 5424 line and its RFC 6587 frame, the webhook body and template,
//!   the Splunk HEC payload and its acknowledgement poll, the NDJSON line.
//!
//! What replaced what: the per-process scheduler job is registered with
//! `sts-cluster`'s [`Scheduler`] ([`AuditExport::register_jobs`]); the
//! `deps` Node's tests replace are [`ExportPorts`]; `realms.map()` is
//! [`ExportMaps`]; `keystore.seal()`/`open()` is [`SecretBox`]; node's
//! modules are [`transport`]'s ports. A destination's tick runs its events
//! in order, and destinations run one after another (Node's
//! `Promise.all` interleaves them, which changes no destination's own
//! order or outcome).

pub mod address;
pub mod event;
pub mod outbound;
pub mod transport;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value as Json};
use sts_cluster::schedule::{JobSpec, Kind, Schedule, Scope, Unit};
use sts_cluster::scheduler::{Realms, Scheduler};
use sts_core::errors::codes;
use sts_core::mode::Mode;
use sts_core::settings::{keys, Settings};

use crate::js;
use crate::log::{AuditLog, Clock};
use event::{CanonicalOptions, Posted, SendResult};
use outbound::Outbound;
use transport::{
    AppendFile, Files, HttpRequest, HttpTransport, Resolver, SendError,
    SyslogPipe, SyslogTransport,
};

/// The job's id.
pub const JOB_ID: &str = "audit.export";
const TYPES: &[&str] = &["syslog", "file", "webhook", "splunk", "logrhythm"];
const SECRET_LABEL: &str = "audit-export-secret";

fn verb_of(action: &str) -> &'static str {
    match action {
        "admin.audit-export.add" => "added",
        "admin.audit-export.update" => "updated",
        "admin.audit-export.remove" => "removed",
        "admin.audit-export.enable" => "enabled",
        "admin.audit-export.disable" => "disabled",
        "admin.audit-export.test" => "tested",
        _ => "changed",
    }
}

/// What the exporter reads from and writes to the audit log.
pub trait AuditSink: Send + Sync {
    /// `audit.localEvents()`: this process's ring, oldest first, as JSON.
    fn local_events(&self) -> Vec<Json>;
    fn audit(&self, event: &Json);
    fn failure(&self, code: &str, event: &Json);
}

impl AuditSink for AuditLog {
    fn local_events(&self) -> Vec<Json> {
        AuditLog::local_events(self).iter().map(|r| r.to_json()).collect()
    }

    fn audit(&self, event: &Json) {
        if AuditLog::audit(self, event).is_none() {
            tracing::debug!("audit export: a row was not recorded");
        }
    }

    fn failure(&self, code: &str, event: &Json) {
        if AuditLog::failure(self, code, event).is_none() {
            tracing::debug!("audit export: a failure row was not recorded");
        }
    }
}

/// The ambient realm's `audit.export.destinations` and
/// `audit.export.cursors`, each in insertion order (a `Map`'s).
pub trait ExportMaps: Send + Sync {
    fn destinations(&self) -> Vec<(String, Json)>;
    fn destination(&self, id: &str) -> Option<Json>;
    fn put_destination(&self, id: &str, dest: Json);
    fn delete_destination(&self, id: &str);
    fn cursor(&self, id: &str) -> Option<Json>;
    fn put_cursor(&self, id: &str, cursor: Json);
    fn delete_cursor(&self, id: &str);
}

type MapPair = (Vec<(String, Json)>, Vec<(String, Json)>);

/// [`ExportMaps`] in memory, per realm: development, and the tests.
#[derive(Default)]
pub struct MemoryMaps {
    maps: Mutex<HashMap<String, MapPair>>,
}

impl MemoryMaps {
    fn with<R>(&self, f: impl FnOnce(&mut MapPair) -> R) -> R {
        let mut guard = match self.maps.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        f(guard.entry(sts_core::realm::current_id()).or_default())
    }
}

fn set_in(list: &mut Vec<(String, Json)>, id: &str, value: Json) {
    match list.iter_mut().find(|(k, _)| k == id) {
        Some(one) => one.1 = value,
        None => list.push((id.to_string(), value)),
    }
}

fn get_in(list: &[(String, Json)], id: &str) -> Option<Json> {
    list.iter().find(|(k, _)| k == id).map(|(_, v)| v.clone())
}

impl ExportMaps for MemoryMaps {
    fn destinations(&self) -> Vec<(String, Json)> {
        self.with(|m| m.0.clone())
    }
    fn destination(&self, id: &str) -> Option<Json> {
        self.with(|m| get_in(&m.0, id))
    }
    fn put_destination(&self, id: &str, dest: Json) {
        self.with(|m| set_in(&mut m.0, id, dest))
    }
    fn delete_destination(&self, id: &str) {
        self.with(|m| m.0.retain(|(k, _)| k != id))
    }
    fn cursor(&self, id: &str) -> Option<Json> {
        self.with(|m| get_in(&m.1, id))
    }
    fn put_cursor(&self, id: &str, cursor: Json) {
        self.with(|m| set_in(&mut m.1, id, cursor))
    }
    fn delete_cursor(&self, id: &str) {
        self.with(|m| m.1.retain(|(k, _)| k != id))
    }
}

/// `keystore.persists()`, `seal()` and `open()` under the export's label.
pub trait SecretBox: Send + Sync {
    fn persists(&self) -> bool;
    fn seal(&self, plain: &str, label: &str) -> Option<String>;
    fn open(&self, sealed: &str, label: &str) -> Option<String>;
}

/// A keystore that does not persist: a box holds its value unsealed, as
/// development's in-memory keystore does (a view still never shows it).
pub struct NoSealing;

impl SecretBox for NoSealing {
    fn persists(&self) -> bool {
        false
    }
    fn seal(&self, _plain: &str, _label: &str) -> Option<String> {
        None
    }
    fn open(&self, _sealed: &str, _label: &str) -> Option<String> {
        None
    }
}

/// What the exporter is built with.
pub struct ExportPorts {
    pub settings: Arc<Settings>,
    pub mode: Arc<Mode>,
    pub outbound: Arc<Outbound>,
    pub clock: Arc<dyn Clock>,
    pub audit: Arc<dyn AuditSink>,
    pub maps: Arc<dyn ExportMaps>,
    pub dns: Arc<dyn Resolver>,
    pub http: Arc<dyn HttpTransport>,
    pub syslog: Arc<dyn SyslogTransport>,
    pub files: Arc<dyn Files>,
    pub secrets: Arc<dyn SecretBox>,
    /// `crypto.randomUuid()`, for a Splunk acknowledgement channel.
    pub uuid: Arc<dyn Fn() -> String + Send + Sync>,
    /// `os.hostname()` and `process.pid`, for an RFC 5424 line.
    pub hostname: String,
    pub pid: u32,
    /// `version.userAgent('audit-export')`.
    pub user_agent: String,
    /// `persistence.originId()`, or `''`.
    pub origin: Arc<dyn Fn() -> String + Send + Sync>,
    /// The realms, for the job's off check (run outside every realm).
    pub realms: Option<Arc<dyn Realms>>,
}

/// One destination's cursor, as `emptyCursor()` lays it out and the store
/// keeps it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Cursor {
    pub seq: i64,
    pub origin: String,
    pub primed: bool,
    #[serde(rename = "pausedUntil")]
    pub paused_until: i64,
    #[serde(rename = "retryMs")]
    pub retry_ms: i64,
    #[serde(rename = "failingSince")]
    pub failing_since: i64,
    #[serde(rename = "lastSuccessAt")]
    pub last_success_at: i64,
    #[serde(rename = "lastFailureAt")]
    pub last_failure_at: i64,
    #[serde(rename = "lastFailure")]
    pub last_failure: String,
    #[serde(rename = "lastDisposition")]
    pub last_disposition: String,
    pub delivered: i64,
    #[serde(rename = "failedPermanent")]
    pub failed_permanent: i64,
    #[serde(rename = "droppedGap")]
    pub dropped_gap: i64,
    pub retries: i64,
    #[serde(rename = "latencyMs")]
    pub latency_ms: i64,
    pub samples: i64,
    #[serde(rename = "ackId")]
    pub ack_id: Json,
    #[serde(rename = "ackChannel")]
    pub ack_channel: String,
    #[serde(rename = "inFlightId")]
    pub in_flight_id: String,
    #[serde(rename = "inFlightSeq")]
    pub in_flight_seq: i64,
    #[serde(rename = "nextSeq")]
    pub next_seq: Option<i64>,
}

impl Default for Cursor {
    fn default() -> Cursor {
        Cursor {
            seq: 0,
            origin: String::new(),
            primed: false,
            paused_until: 0,
            retry_ms: 0,
            failing_since: 0,
            last_success_at: 0,
            last_failure_at: 0,
            last_failure: String::new(),
            last_disposition: String::new(),
            delivered: 0,
            failed_permanent: 0,
            dropped_gap: 0,
            retries: 0,
            latency_ms: 0,
            samples: 0,
            ack_id: Json::Null,
            ack_channel: String::new(),
            in_flight_id: String::new(),
            in_flight_seq: 0,
            next_seq: None,
        }
    }
}

impl Cursor {
    fn has_ack(&self) -> bool {
        !(self.ack_id.is_null() || self.ack_id == Json::from(""))
    }
}

/// What an act answers: Node's result, and the code it was marked with
/// (recorded, never sent).
#[derive(Debug, Clone, PartialEq)]
pub struct ActResult {
    pub json: Json,
    pub code: String,
}

impl ActResult {
    fn refusal(code: &str, why: &str) -> ActResult {
        ActResult {
            json: json!({ "ok": false, "errors": [why] }),
            code: code.to_string(),
        }
    }

    fn ok(json: Json) -> ActResult {
        ActResult { json, code: String::new() }
    }
}

/// A screen's answer (`screenHost()`, `screenUrl()`): Node's JSON, and the
/// parsed URL and addresses for a send.
#[derive(Debug, Clone)]
pub struct Screened {
    pub json: Json,
    pub ok: bool,
    pub code: String,
    pub why: String,
    pub addresses: Vec<String>,
    pub url: Option<url::Url>,
}

impl Screened {
    fn refused(code: &str, why: &str, with_addresses: bool) -> Screened {
        let mut j = json!({ "ok": false, "code": code, "why": why });
        if with_addresses {
            j["addresses"] = json!([]);
        }
        Screened {
            json: j,
            ok: false,
            code: code.to_string(),
            why: why.to_string(),
            addresses: Vec::new(),
            url: None,
        }
    }
}

struct Held {
    path: String,
    file: Box<dyn AppendFile>,
}

type Pipe = Option<(String, Box<dyn SyslogPipe>)>;

/// The outcome of a Splunk acknowledgement poll.
struct Polled {
    kind: &'static str,
    code: String,
    why: String,
    retry_after_ms: f64,
}

impl Polled {
    fn is(kind: &'static str) -> Polled {
        Polled { kind, code: String::new(), why: String::new(),
                 retry_after_ms: 0.0 }
    }

    fn failed(code: &str, why: &str, retry_after_ms: f64) -> Polled {
        Polled { kind: "failed", code: code.to_string(), why: why.to_string(),
                 retry_after_ms }
    }
}

/// The exporter of one process.
pub struct AuditExport {
    ports: ExportPorts,
    files: Mutex<HashMap<String, Held>>,
    warned: Mutex<HashSet<String>>,
}

fn text_of(v: Option<&Json>) -> String {
    js::text_or_empty(v)
}

fn first_or(text: String, fallback: &str) -> String {
    if text.is_empty() {
        fallback.to_string()
    } else {
        text
    }
}

/// `picked(body, existing, key, fallback)`.
fn picked(
    body: &Json,
    existing: Option<&Json>,
    key: &str,
    fallback: Json,
) -> Json {
    match body.get(key) {
        Some(v) if !v.is_null() => return v.clone(),
        _ => {}
    }
    if let Some(v) = existing.and_then(|e| e.get(key)) {
        return v.clone();
    }
    fallback
}

/// `path.resolve()` of an absolute path: `.` and empty segments dropped,
/// `..` taken back.
fn resolve(text: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in text.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    format!("/{}", parts.join("/"))
}

/// `parseHeaderLines()`.
fn parse_header_lines(text: &str) -> Result<Map<String, Json>, String> {
    let mut headers = Map::new();
    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw).trim();
        if line.is_empty() {
            continue;
        }
        let Some(cut) = line.find(':').filter(|c| *c > 0) else {
            return Err("A header must be \"Name: value\".".to_string());
        };
        let name = line[..cut].trim();
        let usable = !name.is_empty()
            && name.len() <= 64
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !usable {
            return Err("A header name is not usable.".to_string());
        }
        headers.insert(name.to_string(), Json::from(line[cut + 1..].trim()));
    }
    Ok(headers)
}

/// `headerText()`: stored plain headers as lines.
fn header_text(headers: Option<&Json>) -> String {
    match headers {
        Some(Json::Object(m)) => js::keys_of(m)
            .iter()
            .map(|k| format!("{}: {}", k, text_of(m.get(k))))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

fn is_sensitive(name: &str) -> bool {
    let lower = name.to_lowercase();
    ["authorization", "token", "api-key", "secret"]
        .iter()
        .any(|s| lower.contains(s))
}

fn or_text(value: Option<&Json>, fallback: &str) -> String {
    if js::truthy(value) {
        text_of(value)
    } else {
        fallback.to_string()
    }
}

fn sealing_refused() -> ActResult {
    ActResult::refusal(
        codes::STS_AUDIT_0003.as_str(),
        "The secret could not be sealed.",
    )
}

impl AuditExport {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(ports: ExportPorts) -> Arc<AuditExport> {
        Arc::new(AuditExport {
            ports,
            files: Mutex::new(HashMap::new()),
            warned: Mutex::new(HashSet::new()),
        })
    }

    fn files(&self) -> MutexGuard<'_, HashMap<String, Held>> {
        match self.files.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    fn now(&self) -> i64 {
        self.ports.clock.now_ms()
    }

    fn int(&self, key: sts_core::settings::Key) -> i64 {
        self.ports.settings.value(key).as_int()
    }

    fn origin_id(&self) -> String {
        (self.ports.origin)()
    }

    fn timeout(&self) -> u64 {
        self.int(keys::AUDIT_EXPORT_TIMEOUT_MS).max(0) as u64
    }

    // -------------------------------------------------------------------
    // THE JOB.
    // -------------------------------------------------------------------

    /// The job's description: per process, per realm, quiet, every
    /// `auditExport.intervalS` (0 is off).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn job_spec(self: &Arc<Self>) -> JobSpec {
        let mut spec = JobSpec::new(
            JOB_ID,
            "Audit export",
            "In every process, for each realm: delivers this process's own \
             new audit events to that realm's enabled destinations. One \
             destination's failure does not hold the others. Delivery is at \
             least once.",
            "common/audit_export.ts",
            Schedule::EverySetting {
                key: "auditExport.intervalS".to_string(),
                unit: Unit::S,
            },
        );
        spec.kind = Kind::PerProcess;
        spec.scope = Scope::Realm;
        spec.quiet = true;
        spec.manual = true;
        spec.timeout_s = Some(Arc::new(|| 120.0));
        let me = self.clone();
        spec.off = Some(Arc::new(move |realm: &str| Ok(me.off_in(realm))));
        let me = self.clone();
        spec.run = Some(Arc::new(move |ctx| {
            let me = me.clone();
            Box::pin(async move {
                let owner = ctx.still_owner.clone();
                Ok(me.run_async(&move || owner()).await)
            })
        }));
        spec
    }

    /// `registerJobs()`: `audit.export` with the scheduler, once.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn register_jobs(self: &Arc<Self>, scheduler: &Scheduler) -> bool {
        if scheduler.job(JOB_ID).is_some() {
            return false;
        }
        match scheduler.register(self.job_spec()) {
            Ok(()) => true,
            Err(why) => {
                tracing::error!(
                    "{}audit export: the job was not registered: {}",
                    sts_core::log::tag(codes::STS_AUDIT_0007),
                    why
                );
                false
            }
        }
    }

    /// `offIn(realmId)`: why the job is off in a realm, or `''`; said once
    /// per realm in product (`STS-AUDIT-0017`, ASVS 5.0.0 16.4.3).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn off_in(&self, realm_id: &str) -> String {
        let realm = self
            .ports
            .realms
            .as_ref()
            .and_then(|r| r.get(realm_id).or_else(|| r.get("default")));
        let why = match realm {
            Some(realm) => {
                sts_core::realm::run_sync(realm, || self.off_here())
            }
            None => self.off_here(),
        };
        if !why.is_empty() && self.ports.mode.warns_without_audit_destination()
        {
            let first = match self.warned.lock() {
                Ok(mut w) => w.insert(realm_id.to_string()),
                Err(p) => p.into_inner().insert(realm_id.to_string()),
            };
            if first {
                tracing::warn!(
                    "{}audit export: realm \"{}\" sends its audit log \
                     nowhere ({}) A compromise of this service could alter \
                     it. Add a destination under Audit export.",
                    sts_core::log::tag(codes::STS_AUDIT_0017),
                    realm_id,
                    why
                );
            }
        }
        why
    }

    /// `offHere()`: the off reason in the ambient realm.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn off_here(&self) -> String {
        if !self.ports.settings.value(keys::AUDIT_EXPORT_ENABLED).as_bool() {
            return "Audit export is off.".to_string();
        }
        let enabled = self
            .ports
            .maps
            .destinations()
            .iter()
            .any(|(_, d)| js::truthy(d.get("enabled")));
        if !enabled {
            return "No audit export destination is enabled.".to_string();
        }
        String::new()
    }

    /// `runAsync(ctx)`: one tick for the ambient realm.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn run_async(
        &self,
        still_owner: &(dyn Fn() -> bool + Sync),
    ) -> Json {
        let ids: Vec<String> = self
            .ports
            .maps
            .destinations()
            .into_iter()
            .filter(|(_, d)| js::truthy(d.get("enabled")))
            .map(|(id, _)| id)
            .collect();
        for id in &ids {
            self.walk_destination(id, still_owner).await;
        }
        json!({ "destinations": ids.len() })
    }

    fn read_cursor(&self, id: &str) -> Cursor {
        self.ports
            .maps
            .cursor(id)
            .and_then(|c| serde_json::from_value(c).ok())
            .unwrap_or_default()
    }

    fn put_cursor(&self, id: &str, cursor: &Cursor) {
        let value = serde_json::to_value(cursor).unwrap_or(Json::Null);
        self.ports.maps.put_cursor(id, value);
    }

    fn local_rows(&self) -> Vec<Json> {
        let mut rows = self.ports.audit.local_events();
        rows.sort_by_key(Self::seq_of);
        rows
    }

    fn seq_of(row: &Json) -> i64 {
        row.get("seq").and_then(Json::as_f64).unwrap_or(0.0) as i64
    }

    fn skipped(row: &Json) -> bool {
        js::truthy(row.get("detail").and_then(|d| d.get("exportSkip")))
    }

    fn event_id(&self, row: &Json) -> String {
        let held = js::text_if_truthy(row.get("origin"));
        let origin = if held.is_empty() {
            first_or(self.origin_id(), "local")
        } else {
            held
        };
        format!("{}:{}", origin, text_of(row.get("seq")))
    }

    async fn walk_destination(
        &self,
        id: &str,
        still_owner: &(dyn Fn() -> bool + Sync),
    ) {
        let Some(dest) = self.ports.maps.destination(id) else {
            return;
        };
        if !js::truthy(dest.get("enabled")) {
            return;
        }
        let mut cursor = self.read_cursor(id);
        let rows = self.local_rows();
        let mut pipe: Pipe = None;
        let now = self.now();
        if cursor.has_ack() {
            let polled = self.poll_ack(&dest, &mut cursor).await;
            match polled.kind {
                "pending" => {
                    if cursor.in_flight_seq != 0 {
                        cursor.next_seq = Some(cursor.in_flight_seq);
                    }
                    self.put_cursor(id, &cursor);
                    return;
                }
                "failed" => {
                    self.hold(&mut cursor, id, &polled.code, &polled.why,
                              polled.retry_after_ms);
                    cursor.next_seq = if cursor.in_flight_seq != 0 {
                        Some(cursor.in_flight_seq)
                    } else {
                        None
                    };
                    self.put_cursor(id, &cursor);
                    return;
                }
                "acked" => {
                    if cursor.in_flight_seq != 0 {
                        cursor.seq = cursor.in_flight_seq;
                    }
                    cursor.delivered += 1;
                    cursor.last_disposition = "acknowledged".to_string();
                    cursor.last_success_at = now;
                    cursor.ack_id = Json::Null;
                    cursor.in_flight_id = String::new();
                    cursor.in_flight_seq = 0;
                    self.recover(&mut cursor, id);
                }
                _ => {
                    // The collector no longer knows the id: send again.
                    cursor.ack_id = Json::Null;
                    cursor.in_flight_id = String::new();
                }
            }
        }
        if !cursor.primed {
            cursor.seq =
                rows.first().map(|r| Self::seq_of(r) - 1).unwrap_or(0);
            cursor.primed = true;
            cursor.origin = self.origin_id();
        } else if let Some(next) = cursor.next_seq {
            let held = rows.iter().any(|r| Self::seq_of(r) == next);
            if !held && cursor.seq < next {
                cursor.dropped_gap += 1;
                self.note_delivery(
                    codes::STS_AUDIT_0009.as_str(),
                    &format!(
                        "Audit events were trimmed before destination {} \
                         delivered them.",
                        id
                    ),
                    json!({ "destinationId": id, "bookmark": next }),
                );
                if let Some(first) = rows.first() {
                    cursor.seq = Self::seq_of(first) - 1;
                }
            }
        }
        if cursor.paused_until > now {
            Self::note_bookmark(&mut cursor, &rows);
            self.put_cursor(id, &cursor);
            return;
        }
        let batch = self.int(keys::AUDIT_EXPORT_BATCH);
        let budget = self.int(keys::AUDIT_EXPORT_BUDGET_MS);
        let max_period = self.int(keys::AUDIT_EXPORT_RETRY_MAX_PERIOD_MS);
        let started = self.now();
        let mut dropped: Vec<String> = Vec::new();
        let mut offered = 0i64;
        let mut giving_up = false;
        for row in &rows {
            let seq = Self::seq_of(row);
            if seq <= cursor.seq {
                continue;
            }
            if !still_owner() {
                break;
            }
            if offered >= batch || self.now() - started >= budget {
                break;
            }
            if Self::skipped(row) {
                cursor.seq = seq;
                continue;
            }
            let expired = cursor.failing_since > 0
                && now - cursor.failing_since >= max_period;
            if expired && giving_up && (dropped.len() as i64) < batch {
                dropped.push(self.event_id(row));
                cursor.failed_permanent += 1;
                cursor.seq = seq;
                cursor.last_disposition = "failed".to_string();
                offered += 1;
                continue;
            }
            let event = self.build_event(row, &dest);
            let event_id = text_of(event.get("id"));
            let began = self.now();
            let result = self.offer_event(&dest, &event, &mut pipe).await;
            if result.kind == "ack-wait" {
                cursor.ack_id = result.ack_id.clone();
                if cursor.ack_channel.is_empty() {
                    cursor.ack_channel = (self.ports.uuid)();
                }
                cursor.in_flight_id = event_id;
                cursor.in_flight_seq = seq;
                cursor.last_disposition = "accepted".to_string();
                cursor.next_seq = Some(seq);
                break;
            }
            if result.ok {
                cursor.seq = seq;
                cursor.delivered += 1;
                cursor.last_success_at = self.now();
                cursor.last_disposition =
                    first_or(result.disposition.clone(), "accepted");
                Self::note_latency(&mut cursor, self.now() - began);
                self.recover(&mut cursor, id);
                offered += 1;
                continue;
            }
            if result.kind == "permanent" {
                cursor.seq = seq;
                cursor.failed_permanent += 1;
                cursor.last_disposition = "failed".to_string();
                let code = first_or(result.code.clone(),
                                    codes::STS_AUDIT_0015.as_str());
                self.note_delivery(
                    &code,
                    &format!("Destination {} rejected event {}.", id,
                             event_id),
                    json!({ "destinationId": id, "eventId": event_id }),
                );
                offered += 1;
                continue;
            }
            if expired {
                giving_up = true;
                dropped.push(event_id);
                cursor.failed_permanent += 1;
                cursor.seq = seq;
                cursor.last_disposition = "failed".to_string();
                cursor.last_failure = event::safe_why(&result.why);
                cursor.last_failure_at = self.now();
                cursor.retries += 1;
                offered += 1;
                continue;
            }
            self.hold(&mut cursor, id, &result.code, &result.why,
                      result.retry_after_ms);
            break;
        }
        if !dropped.is_empty() {
            self.note_delivery(
                codes::STS_AUDIT_0011.as_str(),
                &format!(
                    "Destination {} dropped {} event(s) after \
                     auditExport.retryMaxPeriodMs.",
                    id,
                    dropped.len()
                ),
                json!({ "destinationId": id, "count": dropped.len(),
                        "firstId": dropped[0],
                        "lastId": dropped[dropped.len() - 1] }),
            );
            cursor.paused_until =
                self.now() + self.int(keys::AUDIT_EXPORT_RETRY_INITIAL_MS);
        }
        Self::note_bookmark(&mut cursor, &rows);
        self.put_cursor(id, &cursor);
        if let Some((_, mut p)) = pipe.take() {
            p.close();
        }
    }

    fn note_bookmark(cursor: &mut Cursor, rows: &[Json]) {
        if cursor.has_ack() {
            if cursor.in_flight_seq != 0 {
                cursor.next_seq = Some(cursor.in_flight_seq);
            }
            return;
        }
        cursor.next_seq = rows
            .iter()
            .find(|r| Self::seq_of(r) > cursor.seq && !Self::skipped(r))
            .map(Self::seq_of);
    }

    fn hold(&self, cursor: &mut Cursor, id: &str, code: &str, why: &str,
            retry_after_ms: f64) {
        let initial = self.int(keys::AUDIT_EXPORT_RETRY_INITIAL_MS);
        let max = self.int(keys::AUDIT_EXPORT_RETRY_MAX_MS);
        if cursor.failing_since == 0 {
            cursor.failing_since = self.now();
            let code = first_or(code.to_string(),
                                codes::STS_AUDIT_0007.as_str());
            self.note_delivery(
                &code,
                &format!("Audit export destination {} is failing.", id),
                json!({ "destinationId": id }),
            );
        }
        cursor.retries += 1;
        let base = if cursor.retry_ms != 0 { cursor.retry_ms } else { initial };
        let wait = if retry_after_ms > 0.0 {
            retry_after_ms as i64
        } else {
            base
        };
        cursor.paused_until = self.now() + wait;
        cursor.retry_ms = (base * 2).min(max);
        cursor.last_failure_at = self.now();
        cursor.last_failure = event::safe_why(why);
        cursor.last_disposition = "failed".to_string();
    }

    fn recover(&self, cursor: &mut Cursor, id: &str) {
        if cursor.failing_since != 0 {
            self.ports.audit.audit(&json!({
                "action": "service.failure",
                "outcome": "success",
                "summarised": true,
                "target": id,
                "summary": format!(
                    "Audit export destination {} is delivering again.", id),
                "detail": { "exportSkip": true },
            }));
        }
        cursor.failing_since = 0;
        cursor.retry_ms = self.int(keys::AUDIT_EXPORT_RETRY_INITIAL_MS);
        cursor.paused_until = 0;
        cursor.last_failure = String::new();
    }

    fn note_delivery(&self, code: &str, summary: &str, detail: Json) {
        let known = [
            codes::STS_AUDIT_0004,
            codes::STS_AUDIT_0005,
            codes::STS_AUDIT_0006,
            codes::STS_AUDIT_0007,
            codes::STS_AUDIT_0008,
            codes::STS_AUDIT_0009,
            codes::STS_AUDIT_0011,
            codes::STS_AUDIT_0014,
            codes::STS_AUDIT_0015,
            codes::STS_CORE_0104,
        ]
        .iter()
        .any(|c| c.as_str() == code);
        let code = if known { code } else { codes::STS_AUDIT_0007.as_str() };
        let mut d = Map::new();
        d.insert("exportSkip".into(), Json::Bool(true));
        if let Json::Object(m) = &detail {
            for (k, v) in m {
                d.insert(k.clone(), v.clone());
            }
        }
        let target = detail.get("destinationId").cloned();
        self.ports.audit.failure(code, &json!({
            "action": "service.failure",
            "outcome": "error",
            "summarised": true,
            "summary": summary,
            "target": target.unwrap_or(Json::Null),
            "detail": d,
        }));
    }

    fn note_latency(cursor: &mut Cursor, ms: i64) {
        let n = cursor.samples;
        cursor.latency_ms = if n == 0 {
            ms
        } else {
            (((cursor.latency_ms * n + ms) as f64) / ((n + 1) as f64)).round()
                as i64
        };
        cursor.samples = n + 1;
    }

    /// `buildEvent(row, dest)`: the canonical event for one row.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn build_event(&self, row: &Json, dest: &Json) -> Json {
        let configured =
            self.ports.settings.value(keys::AUDIT_EXPORT_REDACT_KEYS);
        let names = event::redact_names(
            configured.as_str(),
            &text_of(dest.get("excludeAttributes")),
        );
        event::canonical(row, &CanonicalOptions {
            realm: sts_core::realm::current_id(),
            origin: self.origin_id(),
            source: self.ports.user_agent.clone(),
            names,
            now: self.now(),
        })
    }

    async fn offer_event(&self, dest: &Json, event: &Json, pipe: &mut Pipe)
        -> SendResult {
        match dest.get("type").and_then(Json::as_str).unwrap_or("") {
            "file" => self.send_file(dest, event),
            "syslog" | "logrhythm" => {
                self.send_syslog(dest, event, pipe).await
            }
            "webhook" | "splunk" => self.send_http(dest, event).await,
            _ => SendResult::failed(
                "pause",
                codes::STS_AUDIT_0001.as_str(),
                "The destination type is not usable.",
            ),
        }
    }

    fn file_key(id: &str) -> String {
        format!("{}\0{}", sts_core::realm::current_id(), id)
    }

    fn send_file(&self, dest: &Json, event: &Json) -> SendResult {
        let checked = match self.check_path(dest.get("path")) {
            Ok(p) => p,
            Err(why) => {
                return SendResult::failed(
                    "pause",
                    codes::STS_AUDIT_0004.as_str(),
                    &why,
                )
            }
        };
        match self.append_line(dest, event, &checked) {
            Ok(()) => SendResult::accepted("accepted"),
            Err(why) => SendResult::failed(
                "transient",
                codes::STS_AUDIT_0008.as_str(),
                &why,
            ),
        }
    }

    fn append_line(&self, dest: &Json, event: &Json, path: &str)
        -> Result<(), String> {
        let key = Self::file_key(&text_of(dest.get("id")));
        let mode = event::parse_mode(dest.get("mode")).max(0) as u32;
        let mut files = self.files();
        if files.get(&key).is_some_and(|h| h.path != path) {
            files.remove(&key);
        }
        if !files.contains_key(&key) {
            let file = self.ports.files.open_append(path, mode)?;
            files.insert(key.clone(), Held { path: path.to_string(), file });
        }
        let rotate = event::js_number(dest.get("rotateBytes"));
        let rotate = if rotate.is_finite() { rotate as i64 } else { 0 };
        let held = files.get_mut(&key).ok_or("the file is not open")?;
        if rotate > 0 && held.file.size()? as i64 >= rotate {
            let stamp = js::iso(self.now()).replace([':', '.'], "-");
            let base = format!("{}.{}", path, stamp);
            let with_pid = format!("{}-{}", base, self.ports.pid);
            let rotated = if !self.ports.files.exists(&base) {
                base
            } else if !self.ports.files.exists(&with_pid) {
                with_pid
            } else {
                format!("{}-{}", with_pid, self.now())
            };
            self.ports.files.rename(path, &rotated)?;
            held.file = self.ports.files.open_append(path, mode)?;
        }
        held.file.append(format!("{}\n", event).as_bytes())
    }

    fn close_file(&self, id: &str) {
        self.files().remove(&Self::file_key(id));
    }

    /// Forgets every open file handle (`resetForTests()`'s half that is
    /// this process's).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn close_files(&self) {
        self.files().clear();
    }

    async fn send_syslog(&self, dest: &Json, event: &Json, pipe: &mut Pipe)
        -> SendResult {
        let screened =
            self.screen_host(&text_of(dest.get("host")), true).await;
        if !screened.ok {
            return SendResult::failed(
                "pause",
                codes::STS_AUDIT_0005.as_str(),
                &screened.why,
            );
        }
        let transport = event::transport_of(dest);
        let port = event::port_of(dest);
        let message = event::syslog_line(
            event,
            dest,
            &self.ports.hostname,
            self.ports.pid,
            self.now(),
        );
        let ip = screened.addresses.first().cloned().unwrap_or_default();
        let timeout = self.timeout();
        let sent = if transport == "udp" {
            self.ports
                .syslog
                .send_udp(message.as_bytes(), &ip, port, timeout)
                .await
        } else {
            self.send_framed(dest, &message, &ip, port, transport, pipe)
                .await
        };
        match sent {
            Ok(()) => SendResult::accepted("transmitted"),
            Err(e) => {
                if let Some((_, mut p)) = pipe.take() {
                    p.close();
                }
                let code = e
                    .code
                    .unwrap_or_else(|| codes::STS_AUDIT_0006.as_str().into());
                let kind = if code == codes::STS_AUDIT_0006.as_str() {
                    "transient"
                } else {
                    "pause"
                };
                SendResult::failed(kind, &code, &e.why)
            }
        }
    }

    async fn send_framed(&self, dest: &Json, message: &str, ip: &str,
                         port: u16, transport: &str, pipe: &mut Pipe)
        -> Result<(), SendError> {
        let key = format!("{}:{}:{}", transport, ip, port);
        let timeout = self.timeout();
        if pipe.as_ref().is_none_or(|(k, _)| *k != key) {
            if let Some((_, mut p)) = pipe.take() {
                p.close();
            }
            let host = address::bare_host(&text_of(dest.get("host")));
            let policy = if transport == "tls" {
                let policy = self
                    .ports
                    .outbound
                    .tls_verdict(&format!("{}:{}", host, port));
                if !policy.ok {
                    return Err(SendError {
                        code: Some(first_or(
                            policy.error_code.clone(),
                            codes::STS_AUDIT_0006.as_str(),
                        )),
                        why: first_or(policy.why.clone(), "TLS was refused"),
                    });
                }
                Some(policy)
            } else {
                None
            };
            let servername =
                if address::is_ip(&host) { None } else { Some(host) };
            let opened = self
                .ports
                .syslog
                .open(transport, ip, port, servername.as_deref(),
                      policy.as_ref(), timeout)
                .await?;
            *pipe = Some((key, opened));
        }
        let body = message.as_bytes();
        let mut frame = format!("{} ", body.len()).into_bytes();
        frame.extend_from_slice(body);
        match pipe.as_mut() {
            Some((_, p)) => p.write(&frame, timeout).await,
            None => Err(SendError::plain("the syslog socket is closed")),
        }
    }

    fn open_box(&self, held: Option<&Json>) -> String {
        let Some(b) = held.filter(|b| js::truthy(Some(b))) else {
            return String::new();
        };
        if js::truthy(b.get("sealed")) {
            return self
                .ports
                .secrets
                .open(&text_of(b.get("value")), SECRET_LABEL)
                .unwrap_or_default();
        }
        js::text_if_truthy(b.get("value"))
    }

    fn seal_box(&self, plain: &str) -> Option<Json> {
        if self.ports.secrets.persists() {
            let sealed = self.ports.secrets.seal(plain, SECRET_LABEL)?;
            return Some(json!({ "sealed": true, "value": sealed }));
        }
        Some(json!({ "sealed": false, "value": plain }))
    }

    async fn send_http(&self, dest: &Json, event: &Json) -> SendResult {
        let target = text_of(dest.get("url"));
        let screened = self.screen_url(&target, true).await;
        let url = match (&screened.url, screened.ok) {
            (Some(url), true) => url.clone(),
            _ => {
                let code = first_or(screened.code.clone(),
                                    codes::STS_AUDIT_0005.as_str());
                return SendResult::failed("pause", &code, &screened.why);
            }
        };
        let mut headers = Map::new();
        let body;
        let content_type;
        let splunk = dest.get("type").and_then(Json::as_str) == Some("splunk");
        if splunk {
            let token = self.open_box(dest.get("token"));
            if token.is_empty() {
                return SendResult::failed(
                    "pause",
                    codes::STS_AUDIT_0007.as_str(),
                    "the collector token is not held",
                );
            }
            headers.insert(
                "Authorization".into(),
                Json::from(format!("Splunk {}", token)),
            );
            let at = event::js_number(event.get("at"));
            let mut payload = json!({
                "time": event::js_num(at / 1000.0),
                "host": event::host_token(&self.ports.hostname),
                "source": or_text(dest.get("source"), "iya-sts"),
                "sourcetype": or_text(dest.get("sourcetype"), "iya:audit"),
                "event": event,
            });
            if js::truthy(dest.get("index")) {
                payload["index"] = dest["index"].clone();
            }
            body = payload.to_string();
            content_type = "application/json".to_string();
        } else {
            let template = text_of(dest.get("template"));
            if !template.is_empty() {
                body = event::fill_template(&template, event);
                content_type = or_text(
                    dest.get("contentType"),
                    "text/plain; charset=utf-8",
                );
            } else {
                body = event.to_string();
                content_type =
                    or_text(dest.get("contentType"), "application/json");
            }
            let skip = ["host", "content-length", "transfer-encoding",
                        "content-type", "user-agent"];
            if let Some(Json::Object(plain)) = dest.get("headers") {
                for name in js::keys_of(plain) {
                    if skip.contains(&name.to_lowercase().as_str()) {
                        continue;
                    }
                    let value = text_of(plain.get(&name));
                    headers.insert(name, Json::from(value));
                }
            }
            if let Some(Json::Object(secret)) = dest.get("secretHeaders") {
                for name in js::keys_of(secret) {
                    let value = self.open_box(secret.get(&name));
                    if !value.is_empty() {
                        headers.insert(name, Json::from(value));
                    }
                }
            }
        }
        headers.insert("Content-Type".into(), Json::from(content_type));
        let posted =
            self.post_http(&url, headers, body, &screened.addresses).await;
        if !posted.ok
            && posted.status == 0
            && posted.code == codes::STS_CORE_0104.as_str()
        {
            return SendResult::failed(
                "pause",
                codes::STS_CORE_0104.as_str(),
                &posted.why,
            );
        }
        event::classify_http(&posted, splunk && js::truthy(dest.get("ack")))
    }

    async fn poll_ack(&self, dest: &Json, cursor: &mut Cursor) -> Polled {
        let token = self.open_box(dest.get("token"));
        if token.is_empty() {
            return Polled::failed(
                codes::STS_AUDIT_0007.as_str(),
                "the collector token is not held",
                0.0,
            );
        }
        let Ok(ack_to) = event::ack_url(&text_of(dest.get("url"))) else {
            return Polled::failed(
                codes::STS_AUDIT_0005.as_str(),
                "the acknowledgement URL is not usable",
                0.0,
            );
        };
        let screened = self.screen_url(&ack_to, true).await;
        let url = match (&screened.url, screened.ok) {
            (Some(url), true) => url.clone(),
            _ => {
                let code = first_or(screened.code.clone(),
                                    codes::STS_AUDIT_0005.as_str());
                return Polled::failed(&code, &screened.why, 0.0);
            }
        };
        if cursor.ack_channel.is_empty() {
            cursor.ack_channel = (self.ports.uuid)();
        }
        let mut headers = Map::new();
        headers.insert(
            "Authorization".into(),
            Json::from(format!("Splunk {}", token)),
        );
        headers.insert("Content-Type".into(), Json::from("application/json"));
        headers.insert(
            "X-Splunk-Request-Channel".into(),
            Json::from(cursor.ack_channel.clone()),
        );
        let body = json!({ "acks": [cursor.ack_id.clone()] }).to_string();
        let posted =
            self.post_http(&url, headers, body, &screened.addresses).await;
        if !posted.ok && posted.status == 0 {
            let code =
                first_or(posted.code.clone(), codes::STS_AUDIT_0007.as_str());
            return Polled::failed(&code, &posted.why, posted.retry_after_ms);
        }
        let classified = event::classify_http(&posted, false);
        if !classified.ok {
            return Polled::failed(
                &classified.code,
                &classified.why,
                classified.retry_after_ms,
            );
        }
        let key = js::text_of(&cursor.ack_id);
        match posted.json.get("acks").and_then(|a| a.get(&key)) {
            None => Polled::is("missing"),
            Some(Json::Bool(true)) => Polled::is("acked"),
            Some(_) => Polled::is("pending"),
        }
    }

    async fn post_http(&self, target: &url::Url, headers: Map<String, Json>,
                       body: String, addresses: &[String]) -> Posted {
        let secure = target.scheme() == "https";
        let hostname = target.host_str().unwrap_or("").to_string();
        let refused = |code: String, why: String| Posted {
            ok: false,
            status: 0,
            code,
            why,
            retry_after_ms: 0.0,
            json: Json::Null,
        };
        let mut tls = None;
        if !secure {
            let verdict = self.ports.outbound.http_verdict(&hostname);
            if !verdict.ok {
                return refused(
                    first_or(verdict.error_code,
                             codes::STS_AUDIT_0005.as_str()),
                    first_or(verdict.why, "plain http is refused"),
                );
            }
        } else {
            let policy = self.ports.outbound.tls_verdict(&hostname);
            if !policy.ok {
                return refused(
                    first_or(policy.error_code.clone(),
                             codes::STS_AUDIT_0007.as_str()),
                    first_or(policy.why.clone(), "TLS was refused"),
                );
            }
            tls = Some(policy);
        }
        let mut sent = headers;
        sent.insert("Content-Length".into(), Json::from(body.len()));
        sent.insert(
            "User-Agent".into(),
            Json::from(self.ports.user_agent.clone()),
        );
        let port = match target.port() {
            Some(p) => Json::from(p.to_string()),
            None => Json::from(if secure { 443 } else { 80 }),
        };
        let mut path = target.path().to_string();
        if let Some(q) = target.query().filter(|q| !q.is_empty()) {
            path.push('?');
            path.push_str(q);
        }
        let request = HttpRequest {
            protocol: format!("{}:", target.scheme()),
            hostname,
            port,
            path,
            method: "POST".into(),
            headers: sent,
            body,
            pinned: addresses.first().cloned(),
            tls,
            timeout_ms: self.timeout(),
        };
        let answer = match self.ports.http.post(&request).await {
            Ok(a) => a,
            Err(why) => {
                return refused(codes::STS_AUDIT_0007.as_str().into(), why)
            }
        };
        let status = answer.status;
        let retry = event::retry_after(
            answer.headers.get("retry-after").map(String::as_str),
            self.now(),
        );
        if (300..400).contains(&status) {
            return Posted {
                ok: false,
                status,
                code: codes::STS_AUDIT_0014.as_str().into(),
                why: format!(
                    "it answered {}, and a redirect is not followed",
                    status
                ),
                retry_after_ms: retry,
                json: Json::Null,
            };
        }
        let text = String::from_utf8_lossy(&answer.body).to_string();
        let parsed = if text.is_empty() {
            Json::Null
        } else {
            serde_json::from_str(&text).unwrap_or(Json::Null)
        };
        Posted {
            ok: (200..300).contains(&status),
            status,
            code: String::new(),
            why: if answer.overflow {
                format!(
                    "the response was longer than {} bytes",
                    event::BODY_CAP
                )
            } else {
                String::new()
            },
            retry_after_ms: retry,
            json: parsed,
        }
    }

    // -------------------------------------------------------------------
    // THE SCREENS.
    // -------------------------------------------------------------------

    /// `checkPath()`: absolute, no `..`, under `auditExport.fileRoots`.
    fn check_path(&self, raw: Option<&Json>) -> Result<String, String> {
        let text = text_of(raw);
        if text.is_empty() || text.contains('\0') || !text.starts_with('/') {
            return Err("The path must be absolute.".into());
        }
        if text.split(['/', '\\']).any(|p| p == "..") {
            return Err("The path climbs out of its directory.".into());
        }
        let resolved = resolve(&text);
        let roots_text =
            self.ports.settings.value(keys::AUDIT_EXPORT_FILE_ROOTS);
        let roots: Vec<String> = roots_text
            .as_str()
            .split(',')
            .map(|r| r.trim().to_string())
            .filter(|r| !r.is_empty())
            .collect();
        if !roots.is_empty() {
            let under = roots.iter().any(|root| {
                let base = resolve(root);
                resolved == base
                    || resolved.starts_with(&format!("{}/", base))
            });
            if !under {
                return Err(
                    "The path is outside the allowed filesystem roots."
                        .into(),
                );
            }
        }
        Ok(resolved)
    }

    /// `screenHost(host, atSend)`: the host checked, and at a send every
    /// address it resolves to.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn screen_host(&self, host: &str, at_send: bool) -> Screened {
        let bare = address::bare_host(host);
        if bare.is_empty()
            || js::len16(&bare) > 255
            || bare.chars().any(|c| c.is_whitespace() || "@/\\".contains(c))
        {
            return Screened::refused(
                codes::STS_AUDIT_0001.as_str(),
                "The host is not usable.",
                true,
            );
        }
        if address::is_metadata(&bare) {
            return Screened::refused(
                codes::STS_AUDIT_0005.as_str(),
                "Cloud metadata addresses are refused.",
                true,
            );
        }
        let unresolved = || {
            Screened::refused(
                codes::STS_AUDIT_0005.as_str(),
                "The host could not be resolved.",
                true,
            )
        };
        let (addresses, looked) = match self.ports.dns.lookup(&bare).await {
            Ok(found) => (found, true),
            Err(e) => {
                tracing::debug!("audit export: {} did not resolve: {}", bare,
                                e);
                if at_send {
                    return unresolved();
                }
                (Vec::new(), false)
            }
        };
        if at_send && addresses.is_empty() {
            return unresolved();
        }
        let denied = self.address_denied(
            &bare,
            if looked { Some(&addresses) } else { None },
            at_send,
        );
        if !denied.is_empty() {
            return Screened::refused(
                codes::STS_AUDIT_0005.as_str(),
                &denied,
                true,
            );
        }
        let addresses =
            if addresses.is_empty() { vec![bare] } else { addresses };
        Screened {
            json: json!({ "ok": true, "addresses": addresses }),
            ok: true,
            code: String::new(),
            why: String::new(),
            addresses,
            url: None,
        }
    }

    /// `screenUrl(raw, atSend)`: a webhook's or a collector's URL.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn screen_url(&self, raw: &str, at_send: bool) -> Screened {
        let Ok(url) = url::Url::parse(raw) else {
            return Screened::refused(
                codes::STS_AUDIT_0001.as_str(),
                "The URL is not usable.",
                false,
            );
        };
        if !url.username().is_empty() || url.password().is_some() {
            return Screened::refused(
                codes::STS_AUDIT_0005.as_str(),
                "The URL must not carry user information.",
                false,
            );
        }
        if url.scheme() != "https" && url.scheme() != "http" {
            return Screened::refused(
                codes::STS_AUDIT_0005.as_str(),
                "The URL must be http or https.",
                false,
            );
        }
        let hostname = url.host_str().unwrap_or("").to_string();
        if url.scheme() == "http" {
            let verdict = self.ports.outbound.http_verdict(&hostname);
            if !verdict.ok {
                let code = first_or(verdict.error_code,
                                    codes::STS_AUDIT_0005.as_str());
                return Screened::refused(
                    &code,
                    "Plain http is not allowed for this destination.",
                    false,
                );
            }
        }
        let host = self.screen_host(&hostname, at_send).await;
        if !host.ok {
            return host;
        }
        Screened {
            json: json!({ "ok": true, "url": url.as_str(),
                          "addresses": host.addresses }),
            ok: true,
            code: String::new(),
            why: String::new(),
            addresses: host.addresses,
            url: Some(url),
        }
    }

    fn address_denied(&self, host: &str, addresses: Option<&Vec<String>>,
                      at_send: bool) -> String {
        let answers: Vec<String> = addresses.cloned().unwrap_or_default();
        if address::is_metadata(host)
            || answers.iter().any(|a| address::is_metadata(a))
        {
            return "Cloud metadata addresses are refused.".into();
        }
        let private = |h: &str| {
            address::is_loopback_host(h) || address::is_private(h)
        };
        if !private(host) && !answers.iter().any(|a| private(a)) {
            return String::new();
        }
        if self
            .ports
            .settings
            .value(keys::AUDIT_EXPORT_ALLOW_PRIVATE_DESTINATIONS)
            .as_bool()
        {
            return String::new();
        }
        let all_loop = !answers.is_empty()
            && answers.iter().all(|a| address::is_loopback_host(a));
        if self.ports.mode.dials_plain_http_outbound()
            && address::is_loopback_host(host)
            && (!at_send || all_loop)
        {
            return String::new();
        }
        "Private and loopback addresses are refused.".into()
    }

    // -------------------------------------------------------------------
    // THE ACTS.
    // -------------------------------------------------------------------

    /// `act(body)`: add, update, remove, enable, disable or test.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn act(&self, body: &Json) -> ActResult {
        let action = text_of(body.get("action"));
        match action.as_str() {
            "add" => self.add_dest(body).await,
            "update" => self.update_dest(body).await,
            "remove" => self.remove_dest(body),
            "enable" => self.set_enabled(body, true),
            "disable" => self.set_enabled(body, false),
            "test" => self.test_destination(body).await,
            _ => ActResult::refusal(
                codes::STS_AUDIT_0001.as_str(),
                &format!(
                    "Unknown action \"{}\". The six are: add, update, \
                     remove, enable, disable, test.",
                    action
                ),
            ),
        }
    }

    fn id_of(body: &Json) -> String {
        js::text_if_truthy(body.get("id"))
    }

    fn unknown() -> ActResult {
        ActResult::refusal(
            codes::STS_AUDIT_0002.as_str(),
            "No destination has that id.",
        )
    }

    fn answered(dest: &Json) -> ActResult {
        ActResult::ok(json!({ "ok": true,
                              "destination": Self::public_dest(dest) }))
    }

    async fn add_dest(&self, body: &Json) -> ActResult {
        let dest = match self.prepare(body, None).await {
            Ok(d) => d,
            Err(r) => return r,
        };
        let id = text_of(dest.get("id"));
        if self.ports.maps.destination(&id).is_some() {
            return ActResult::refusal(
                codes::STS_AUDIT_0001.as_str(),
                "A destination already has that id.",
            );
        }
        self.ports.maps.put_destination(&id, dest.clone());
        self.changed("admin.audit-export.add", &dest);
        Self::answered(&dest)
    }

    async fn update_dest(&self, body: &Json) -> ActResult {
        let id = Self::id_of(body);
        let Some(existing) = self.ports.maps.destination(&id) else {
            return Self::unknown();
        };
        let dest = match self.prepare(body, Some(&existing)).await {
            Ok(d) => d,
            Err(r) => return r,
        };
        if existing.get("type").and_then(Json::as_str) == Some("file")
            && existing.get("path") != dest.get("path")
        {
            self.close_file(&id);
        }
        self.ports.maps.put_destination(&id, dest.clone());
        self.changed("admin.audit-export.update", &dest);
        Self::answered(&dest)
    }

    fn remove_dest(&self, body: &Json) -> ActResult {
        let id = Self::id_of(body);
        let Some(existing) = self.ports.maps.destination(&id) else {
            return Self::unknown();
        };
        self.close_file(&id);
        self.ports.maps.delete_destination(&id);
        self.ports.maps.delete_cursor(&id);
        self.changed("admin.audit-export.remove", &existing);
        Self::answered(&existing)
    }

    fn set_enabled(&self, body: &Json, enabled: bool) -> ActResult {
        let id = Self::id_of(body);
        let Some(mut next) = self.ports.maps.destination(&id) else {
            return Self::unknown();
        };
        next["enabled"] = Json::Bool(enabled);
        self.ports.maps.put_destination(&id, next.clone());
        self.changed(
            if enabled {
                "admin.audit-export.enable"
            } else {
                "admin.audit-export.disable"
            },
            &next,
        );
        Self::answered(&next)
    }

    async fn test_destination(&self, body: &Json) -> ActResult {
        let id = Self::id_of(body);
        let Some(dest) = self.ports.maps.destination(&id) else {
            return Self::unknown();
        };
        let event = self.test_event(&dest);
        let mut pipe: Pipe = None;
        let sent = self.offer_event(&dest, &event, &mut pipe).await;
        if let Some((_, mut p)) = pipe.take() {
            p.close();
        }
        let kind = dest.get("type").cloned().unwrap_or(Json::Null);
        let summary = format!("Audit export destination {} was tested.", id);
        if !sent.ok {
            self.ports.audit.audit(&json!({
                "action": "admin.audit-export.test",
                "target": id,
                "outcome": "error",
                "errorCode": codes::STS_AUDIT_0010.as_str(),
                "summarised": true,
                "summary": summary,
                "detail": { "type": kind },
            }));
            let why = first_or(sent.why, "The test event was not delivered.");
            return ActResult::refusal(codes::STS_AUDIT_0010.as_str(), &why);
        }
        self.ports.audit.audit(&json!({
            "action": "admin.audit-export.test",
            "target": id,
            "outcome": "success",
            "summary": summary,
            "detail": { "type": kind,
                        "enabled": js::truthy(dest.get("enabled")) },
        }));
        ActResult::ok(json!({
            "ok": true,
            "destination": Self::public_dest(&dest),
            "diagnostic": { "disposition": sent.disposition, "test": true },
        }))
    }

    /// `testEvent(dest)`: the synthetic event a test sends; never a row.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn test_event(&self, dest: &Json) -> Json {
        let at = self.now();
        let id = text_of(dest.get("id"));
        json!({
            "id": format!("test:{}:{}", id, at),
            "seq": 0,
            "origin": self.origin_id(),
            "timestamp": js::iso(at),
            "at": at,
            "severity": "notice",
            "category": "service",
            "action": "audit.export.test",
            "outcome": "success",
            "errorCode": "",
            "source": self.ports.user_agent,
            "realm": sts_core::realm::current_id(),
            "subject": "audit-export",
            "subjectForm": "",
            "client": "",
            "address": "",
            "target": dest.get("id").cloned().unwrap_or(Json::Null),
            "protocol": "",
            "channel": "audit-export",
            "message": "IYA-STS audit export test",
            "attributes": { "test": true },
        })
    }

    fn changed(&self, action: &str, dest: &Json) {
        let id = text_of(dest.get("id"));
        self.ports.audit.audit(&json!({
            "action": action,
            "target": dest.get("id").cloned().unwrap_or(Json::Null),
            "outcome": "success",
            "summary": format!("Audit export destination {} {}.", id,
                               verb_of(action)),
            "detail": { "type": dest.get("type").cloned().unwrap_or(Json::Null),
                        "enabled": js::truthy(dest.get("enabled")) },
        }));
    }

    /// `publicDest(dest)`: the destination as a page may show it — no
    /// secret value, only whether one is set.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn public_dest(dest: &Json) -> Json {
        let mut copy = dest.as_object().cloned().unwrap_or_default();
        let set = dest.get("token").is_some_and(|t| {
            js::truthy(t.get("sealed")) || js::truthy(t.get("value"))
        });
        copy.insert("tokenSet".into(), Json::Bool(set));
        copy.shift_remove("token");
        let names: Vec<Json> = match dest.get("secretHeaders") {
            Some(Json::Object(m)) => {
                js::keys_of(m).into_iter().map(Json::from).collect()
            }
            _ => Vec::new(),
        };
        copy.insert("secretHeaderSet".into(), Json::Array(names));
        copy.shift_remove("secretHeaders");
        if !copy.get("headers").is_some_and(Json::is_string) {
            let text = header_text(copy.get("headers"));
            copy.insert("headerText".into(), Json::from(text));
        }
        Json::Object(copy)
    }

    async fn prepare(&self, body: &Json, existing: Option<&Json>)
        -> Result<Json, ActResult> {
        let refuse = |why: &str| {
            ActResult::refusal(codes::STS_AUDIT_0001.as_str(), why)
        };
        let id = match existing {
            Some(e) => text_of(e.get("id")),
            None => Self::id_of(body),
        };
        let id_ok = !id.is_empty()
            && id.len() <= 63
            && id
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && id.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'
            });
        if !id_ok {
            return Err(refuse(
                "The id must start with a letter or a digit and use only \
                 lower-case letters, digits and hyphens.",
            ));
        }
        let kind = if js::truthy(body.get("type")) {
            text_of(body.get("type"))
        } else {
            js::text_if_truthy(existing.and_then(|e| e.get("type")))
        };
        if !TYPES.contains(&kind.as_str()) {
            return Err(refuse(
                "The type must be syslog, file, webhook, splunk or logrhythm.",
            ));
        }
        let name = text_of(Some(&picked(body, existing, "name",
                                        Json::from(id.clone()))));
        if name.trim().is_empty() || js::len16(&name) > 128 {
            return Err(refuse(
                "The destination needs a name of at most 128 characters.",
            ));
        }
        let enabled = match body.get("enabled") {
            Some(v) => js::truthy(Some(v)),
            None => existing.is_none_or(|e| js::truthy(e.get("enabled"))),
        };
        let excluded = text_of(Some(&picked(body, existing,
                                            "excludeAttributes",
                                            Json::from(""))));
        if js::len16(&excluded) > 1000 {
            return Err(refuse("The excluded attributes are too long."));
        }
        let mut dest = Map::new();
        dest.insert("id".into(), Json::from(id));
        dest.insert("name".into(), Json::from(name.trim()));
        dest.insert("type".into(), Json::from(kind));
        dest.insert("enabled".into(), Json::Bool(enabled));
        dest.insert("excludeAttributes".into(), Json::from(excluded));
        self.fill_typed(&mut dest, body, existing).await?;
        Ok(Json::Object(dest))
    }

    async fn fill_typed(&self, dest: &mut Map<String, Json>, body: &Json,
                        existing: Option<&Json>) -> Result<(), ActResult> {
        let refuse = |why: &str| {
            ActResult::refusal(codes::STS_AUDIT_0001.as_str(), why)
        };
        let pick = |key: &str, fallback: Json| {
            picked(body, existing, key, fallback)
        };
        let kind = text_of(dest.get("type"));
        match kind.as_str() {
            "syslog" | "logrhythm" => {
                for (k, f) in [
                    ("host", Json::from("")),
                    ("port", Json::from(0)),
                    ("transport", Json::from("tcp")),
                    ("facility", Json::from(16)),
                    ("appName", Json::from("iya-sts")),
                ] {
                    dest.insert(k.into(), pick(k, f));
                }
                let host = text_of(dest.get("host"));
                if !js::truthy(dest.get("host")) || js::len16(&host) > 255 {
                    return Err(refuse("A syslog destination needs a host."));
                }
                if js::len16(&text_of(dest.get("appName"))) > 48 {
                    return Err(refuse("The application name is too long."));
                }
                let transport =
                    dest.get("transport").and_then(Json::as_str);
                if !matches!(transport, Some("udp" | "tcp" | "tls")) {
                    return Err(refuse(
                        "The transport must be udp, tcp or tls.",
                    ));
                }
                if transport != Some("tls")
                    && self.ports.mode.refuses_plain_syslog()
                {
                    return Err(ActResult::refusal(
                        codes::STS_AUDIT_0016.as_str(),
                        "Product mode sends syslog over tls only, unless \
                         audit.allowPlainSyslog is on.",
                    ));
                }
                let facility = event::js_number(dest.get("facility"));
                if !facility.is_finite() || !(0.0..=23.0).contains(&facility)
                {
                    return Err(refuse("The facility must be from 0 to 23."));
                }
                dest.insert("facility".into(), event::js_num(facility));
                let port = event::js_number(dest.get("port"));
                let port =
                    if port.is_finite() && port != 0.0 { port } else { 0.0 };
                if port != 0.0 && !(1.0..=65535.0).contains(&port) {
                    return Err(refuse("The port must be from 1 to 65535."));
                }
                dest.insert("port".into(), event::js_num(port));
                let screened = self.screen_host(&host, false).await;
                if !screened.ok {
                    return Err(ActResult::refusal(&screened.code,
                                                  &screened.why));
                }
            }
            "file" => {
                dest.insert("path".into(), pick("path", Json::from("")));
                if js::len16(&text_of(dest.get("path"))) > 1024 {
                    return Err(refuse("The path is too long."));
                }
                dest.insert("mode".into(), pick("mode", Json::from("")));
                let rotate = event::js_number(Some(&pick("rotateBytes",
                                                         Json::from(0))));
                let rotate = if rotate.is_finite() { rotate } else { 0.0 };
                dest.insert("rotateBytes".into(), event::js_num(rotate));
                if event::parse_mode(dest.get("mode")) < 0 {
                    return Err(refuse(
                        "The mode must be three octal digits, such as 640.",
                    ));
                }
                if rotate < 0.0 {
                    return Err(refuse(
                        "The rotation size cannot be negative.",
                    ));
                }
                match self.check_path(dest.get("path")) {
                    Ok(p) => {
                        dest.insert("path".into(), Json::from(p));
                    }
                    Err(why) => {
                        return Err(ActResult::refusal(
                            codes::STS_AUDIT_0004.as_str(),
                            &why,
                        ));
                    }
                }
            }
            "webhook" => {
                for k in ["url", "template", "contentType"] {
                    dest.insert(k.into(), pick(k, Json::from("")));
                }
                let long = js::len16(&text_of(dest.get("url"))) > 2048
                    || js::len16(&text_of(dest.get("template"))) > 4000
                    || js::len16(&text_of(dest.get("contentType"))) > 200;
                if long {
                    return Err(refuse("A webhook field is too long."));
                }
                let plain = self.take_headers(body, existing, false)?;
                dest.insert("headers".into(), plain);
                let secret = self.take_headers(body, existing, true)?;
                dest.insert("secretHeaders".into(), secret);
                self.seal_sensitive(dest)?;
                let url = text_of(dest.get("url"));
                let screened = self.screen_url(&url, false).await;
                if !screened.ok {
                    return Err(ActResult::refusal(&screened.code,
                                                  &screened.why));
                }
            }
            "splunk" => {
                dest.insert("url".into(), pick("url", Json::from("")));
                if js::len16(&text_of(dest.get("url"))) > 2048 {
                    return Err(refuse("The collector URL is too long."));
                }
                dest.insert("index".into(), pick("index", Json::from("")));
                dest.insert("sourcetype".into(),
                            pick("sourcetype", Json::from("iya:audit")));
                dest.insert("source".into(),
                            pick("source", Json::from("iya-sts")));
                let ack = match body.get("ack") {
                    Some(v) => js::truthy(Some(v)),
                    None => js::truthy(existing.and_then(|e| e.get("ack"))),
                };
                dest.insert("ack".into(), Json::Bool(ack));
                let token = self.take_secret(body, existing, "token")?;
                dest.insert("token".into(), token.clone());
                if !js::truthy(Some(&token)) {
                    return Err(refuse("A Splunk destination needs a token."));
                }
                let url = text_of(dest.get("url"));
                let screened = self.screen_url(&url, false).await;
                if !screened.ok {
                    return Err(ActResult::refusal(&screened.code,
                                                  &screened.why));
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn take_secret(&self, body: &Json, existing: Option<&Json>, key: &str)
        -> Result<Json, ActResult> {
        let submitted = body.get(key);
        let empty = match submitted {
            None => true,
            Some(Json::String(s)) => s.is_empty(),
            _ => false,
        };
        if empty {
            return Ok(existing
                .and_then(|e| e.get(key))
                .cloned()
                .unwrap_or(Json::Null));
        }
        let text = text_of(submitted);
        if js::len16(&text) > 4096 {
            return Err(ActResult::refusal(
                codes::STS_AUDIT_0001.as_str(),
                "The secret is too long.",
            ));
        }
        self.seal_box(&text).ok_or_else(sealing_refused)
    }

    fn take_headers(&self, body: &Json, existing: Option<&Json>,
                    secret: bool) -> Result<Json, ActResult> {
        let key = if secret { "secretHeaders" } else { "headers" };
        let prior = existing
            .and_then(|e| e.get(key))
            .filter(|p| js::truthy(Some(p)))
            .cloned()
            .unwrap_or(Json::Object(Map::new()));
        let Some(submitted) = body.get(key) else {
            return Ok(prior);
        };
        let text = match submitted {
            Json::String(s) => s.clone(),
            other => header_text(Some(other)),
        };
        if secret && text.trim().is_empty() {
            return Ok(prior);
        }
        if js::len16(&text) > 8000 {
            return Err(ActResult::refusal(
                codes::STS_AUDIT_0001.as_str(),
                "The headers are too long.",
            ));
        }
        let parsed = parse_header_lines(&text).map_err(|why| {
            ActResult::refusal(codes::STS_AUDIT_0001.as_str(), &why)
        })?;
        if !secret {
            return Ok(Json::Object(parsed));
        }
        let mut merged = prior.as_object().cloned().unwrap_or_default();
        for (name, value) in parsed {
            let value = text_of(Some(&value));
            if value.is_empty() {
                continue;
            }
            let sealed = self.seal_box(&value).ok_or_else(sealing_refused)?;
            merged.insert(name, sealed);
        }
        Ok(Json::Object(merged))
    }

    fn seal_sensitive(&self, dest: &mut Map<String, Json>)
        -> Result<(), ActResult> {
        let mut plain = dest
            .get("headers")
            .and_then(Json::as_object)
            .cloned()
            .unwrap_or_default();
        let mut secret = dest
            .get("secretHeaders")
            .and_then(Json::as_object)
            .cloned()
            .unwrap_or_default();
        for name in js::keys_of(&plain.clone()) {
            if !is_sensitive(&name) {
                continue;
            }
            let value = plain.shift_remove(&name);
            if !js::truthy(value.as_ref()) || js::truthy(secret.get(&name)) {
                continue;
            }
            let sealed = self
                .seal_box(&text_of(value.as_ref()))
                .ok_or_else(sealing_refused)?;
            secret.insert(name, sealed);
        }
        dest.insert("headers".into(), Json::Object(plain));
        dest.insert("secretHeaders".into(), Json::Object(secret));
        Ok(())
    }

    // -------------------------------------------------------------------
    // THE PAGE.
    // -------------------------------------------------------------------

    fn queue_depth(cursor: &Cursor, rows: &[Json]) -> i64 {
        let floor = if cursor.primed {
            cursor.seq
        } else {
            rows.first().map(|r| Self::seq_of(r) - 1).unwrap_or(0)
        };
        rows.iter()
            .filter(|r| Self::seq_of(r) > floor && !Self::skipped(r))
            .count() as i64
    }

    /// `view()`: the destinations, this process's counters, each queue.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn view(&self) -> Json {
        let rows = self.local_rows();
        let now = self.now();
        let mut destinations: Vec<Json> = Vec::new();
        for (id, dest) in self.ports.maps.destinations() {
            let cursor = self.read_cursor(&id);
            let status = if !js::truthy(dest.get("enabled")) {
                "disabled"
            } else if cursor.paused_until > now {
                "paused"
            } else if cursor.failing_since != 0 {
                "failing"
            } else {
                "healthy"
            };
            let mut one = Self::public_dest(&dest);
            let extra = json!({
                "status": status,
                "queueDepth": Self::queue_depth(&cursor, &rows),
                "delivered": cursor.delivered,
                "failedPermanent": cursor.failed_permanent,
                "droppedGap": cursor.dropped_gap,
                "retries": cursor.retries,
                "lastSuccessAt": cursor.last_success_at,
                "lastFailureAt": cursor.last_failure_at,
                "lastFailure": cursor.last_failure,
                "lastDisposition": cursor.last_disposition,
                "pausedUntil": cursor.paused_until,
                "failingSince": cursor.failing_since,
                "latencyMs": cursor.latency_ms,
                "cursorSeq": cursor.seq,
                "primed": cursor.primed,
            });
            if let (Json::Object(m), Json::Object(e)) = (&mut one, extra) {
                m.extend(e);
            }
            destinations.push(one);
        }
        destinations
            .sort_by(|a, b| text_of(a.get("id")).cmp(&text_of(b.get("id"))));
        let n = |d: &Json, k: &str| d.get(k).and_then(Json::as_i64).unwrap_or(0);
        let (mut delivered, mut awaiting, mut retrying) = (0, 0, 0);
        let (mut failed, mut dropped) = (0, 0);
        let (mut latency_total, mut latency_count) = (0i64, 0i64);
        let (mut enabled, mut healthy) = (0i64, 0i64);
        for d in &destinations {
            delivered += n(d, "delivered");
            awaiting += n(d, "queueDepth");
            failed += n(d, "failedPermanent");
            dropped += n(d, "droppedGap");
            if n(d, "latencyMs") != 0 {
                latency_total += n(d, "latencyMs");
                latency_count += 1;
            }
            if js::truthy(d.get("enabled")) {
                enabled += 1;
                if n(d, "failingSince") == 0 {
                    healthy += 1;
                }
                if n(d, "pausedUntil") > now || n(d, "failingSince") != 0 {
                    retrying += 1;
                }
            }
        }
        let latency = if latency_count > 0 {
            ((latency_total as f64) / (latency_count as f64)).round() as i64
        } else {
            0
        };
        let availability = if enabled > 0 {
            event::js_num(healthy as f64 / enabled as f64)
        } else {
            Json::from(1)
        };
        json!({
            "thisProcess": true,
            "enabled":
                self.ports.settings.value(keys::AUDIT_EXPORT_ENABLED).as_bool(),
            "job": { "id": JOB_ID, "kind": "per-process", "scope": "realm" },
            "destinations": destinations,
            "stats": {
                "delivered": delivered,
                "awaiting": awaiting,
                "retrying": retrying,
                "permanentlyFailed": failed,
                "dropped": dropped,
                "latencyMs": latency,
                "availability": availability,
                "generated": delivered + awaiting + dropped + failed,
            },
        })
    }
}
