// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE DECISION RECORDS GO TO THE SERVICE (#1827). Every decision this
//! process MAKES — a `/protected` enforcement, an AuthZEN evaluation decided
//! here — is queued as a record and shipped to the service it is
//! registered with, which writes each one as an audit row in the PEP's
//! realm. Until #1827 a decision's only record was a log line on this
//! container's stdout, and a container that was removed took its history
//! with it.
//!
//! * **The transport is `/admin-api`, not `/xacml/pep`** (rcbj, 2026-11-16:
//!   every log event pushed to the service goes through an authenticated
//!   request on the management API). `POST /admin-api/pep-audit`
//!   needs the scope `xacml:pep-audit`, which only the built-in REMOTE_PEPS
//!   role authorizes and nothing else on `/admin-api` accepts.
//! * **The token is the shared credential's** (`credential.rs`): a
//!   DPoP-bound token for the resource `<PDP>/admin-api` and the scope
//!   `xacml:pep-audit`, from the RFC 7523 self-assertion grant, cached and
//!   renewed there, and asked again once on a 401 by
//!   [`PdpClient::call_authorized`]. A 401 that survives that retry keeps
//!   the batch for the next tick.
//! * **At least once, in order.** A record leaves the queue only when the
//!   service ACKNOWLEDGES its `seq`; a failure keeps it for the next tick.
//!   `seq` counts from 1 in this process, beside an `instance` drawn at
//!   start, so a restart that counts from 1 again is not mistaken for old
//!   records by the service's deduplication mark.
//! * **The queue is bounded and never blocks a decision.** Full, the OLDEST
//!   record is dropped and counted (`STS-XPEP-0122`); a batch the service
//!   refuses as malformed (400) is dropped too (`STS-XPEP-0125`), rather
//!   than sent forever.
//! * **THE REVERSE PROXY'S REQUESTS ARE QUEUED TOO** (#1760): one record,
//!   `kind: "proxy"` with `route` and `status`, per request that reached its
//!   route's authorization (`proxy.rs`, `Noted`).
//! * **A FORWARDED AuthZEN evaluation is not queued** (#564): the service
//!   decided it and wrote its own row under the same request id.
//! * **An AuthZEN record carries exactly what its log line carries** — no
//!   property value, no id the caller sent, no credential (decision 9 on
//!   #563).
//! * **What a restart loses**: every record not yet acknowledged. The log
//!   line on stdout is still there. A disk spool is a separate decision.

use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard};

use reqwest::Method;
use serde::Serialize;
use serde_json::{json, Value};
use sts_core::log::tag;
use sts_core::time::iso_now;

use crate::credential::{random_hex, Resource};
use crate::options::Options;
use crate::pdp_client::{Answer, Body, PdpClient};

/// Where the records go, under the PDP URL (a realm prefix included).
pub const AUDIT_PATH: &str = "/admin-api/pep-audit";
/// The most records one batch carries: the service's own bound.
pub const MAX_BATCH: usize = 500;

/// One decision record, in the member names the service reads. Nothing is
/// ever left out: an absent value is `""`, `[]` or `false`.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub seq: u64,
    /// When it was DECIDED, UTC to the millisecond — the service keeps it
    /// apart from when it received it.
    pub at: String,
    /// `enforcement`, `authzen` or `proxy`.
    pub kind: String,
    /// The XACML decision; `""` for an AuthZEN fault.
    pub decision: String,
    pub allowed: bool,
    pub fault: bool,
    /// The `STS-` code the PEP logged for it, or `""`.
    pub code: String,
    pub subject: String,
    pub resource: String,
    pub action: String,
    pub bias: String,
    pub why: String,
    /// Applicable policies, `id` or `id vVERSION`.
    pub policies: Vec<String>,
    pub discharged: Vec<String>,
    pub undischargeable: Vec<String>,
    pub caller: String,
    pub application: String,
    pub subject_type: String,
    pub endpoint: String,
    pub request_id: String,
    /// The reverse proxy's (`kind: "proxy"`, #1760) alone: the route the
    /// request matched and the HTTP status the proxy answered. Absent from
    /// the other kinds rather than empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
}

/// A policy identifier as a record names it.
pub fn policy_name(id: &str, version: &str) -> String {
    if version.is_empty() {
        id.to_string()
    } else {
        format!("{} v{}", id, version)
    }
}

/// What one batch's answer meant for the queue.
#[derive(Debug, Clone, PartialEq)]
pub enum Settled {
    /// 200: this many records were acknowledged and left the queue.
    Acknowledged(usize),
    /// 401: the token was refused even after the client asked a new one
    /// (or none could be had); kept for the next tick.
    Unauthorized,
    /// 400: the batch was refused as malformed and dropped.
    Refused(String),
    /// Anything else: kept for the next tick.
    Kept(String),
}

#[derive(Default)]
struct State {
    queue: VecDeque<Record>,
    next_seq: u64,
    shipped: u64,
    dropped: u64,
    last_ship_at: String,
    last_ship_ok: Option<bool>,
    last_ship_why: String,
    /// The last delivery failure's reason, so a repeated one is logged at
    /// debug and only a CHANGE at warn.
    last_ship_reason: String,
    last_token_reason: String,
    /// Whether the last batch went with a token, for `GET /`.
    token_held: bool,
}

/// The queue, the token and the shipping.
pub struct Audit {
    /// The options, read through `now()` at every use: the switch, the
    /// interval, the batch and the bound are managed settings (#1760), so
    /// a change made on the PEP's console page applies while this runs.
    options: Options,
    instance: String,
    state: Mutex<State>,
}

/// 1, 2, 3, then each power of ten: often enough to be seen, rarely
/// enough not to drown the log — the fault handler's rule.
fn worth_logging(count: u64) -> bool {
    if count <= 3 {
        return true;
    }
    let mut v = count;
    while v % 10 == 0 {
        v /= 10;
    }
    v == 1
}

impl Audit {
    pub fn new(options: &Options) -> Audit {
        let instance = random_hex(16).unwrap_or_else(|| {
            // Not random, but still apart from every earlier start, which
            // is all the service's mark needs of it.
            format!(
                "{:032x}",
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
            )
        });
        Audit {
            options: options.clone(),
            instance,
            state: Mutex::new(State {
                next_seq: 1,
                last_ship_why: "Nothing has been sent yet.".into(),
                ..State::default()
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // Poisoned means a panic while holding it; the queue is still the
        // best this PEP has.
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// `auditEnabled` now: the service's value, else `PEP_AUDIT`.
    pub fn enabled(&self) -> bool {
        self.options.now().audit
    }

    /// `auditIntervalMs` now, read by the loop before each wait.
    pub fn interval_ms(&self) -> u64 {
        self.options.now().audit_interval_ms
    }

    fn batch(&self) -> usize {
        self.options.now().audit_batch.clamp(1, MAX_BATCH)
    }

    /// Queues one record, numbering it. On the hot path: never blocks on
    /// anything but the queue's own lock, and a full queue drops its oldest.
    ///
    /// A LOWERED `auditBuffer` APPLIES TO NEW RECORDS: nothing already
    /// queued is dropped for it, and each new record displaces the oldest
    /// until the queue has drained below the new bound.
    pub fn record(&self, mut record: Record) {
        let now = self.options.now();
        if !now.audit {
            return;
        }
        let buffer = now.audit_buffer.max(1);
        let mut state = self.lock();
        record.seq = state.next_seq;
        state.next_seq += 1;
        if state.queue.len() >= buffer {
            state.queue.pop_front();
            state.dropped += 1;
            if worth_logging(state.dropped) {
                tracing::warn!(
                    "{}xacml-pep: the queue of decision records waiting for \
                     the service is full (PEP_AUDIT_BUFFER, {}), so the \
                     oldest was dropped; {} dropped so far. Enforcement goes \
                     on, and each dropped decision is still on this log.",
                    tag("STS-XPEP-0122"),
                    buffer,
                    state.dropped
                );
            }
        }
        state.queue.push_back(record);
    }

    /// The oldest records, up to a batch, still queued.
    fn take(&self) -> Vec<Record> {
        let batch = self.batch();
        self.lock().queue.iter().take(batch).cloned().collect()
    }

    /// What the service's answer to `batch` means, applied to the queue.
    fn settle(&self, batch: &[Record], answer: &Answer) -> Settled {
        if let Some(error) = &answer.error {
            return Settled::Kept(format!("no answer: {}", error));
        }
        let first = batch.first().map_or(0, |r| r.seq);
        let last = batch.last().map_or(0, |r| r.seq);
        match answer.status {
            200 => {
                let said = answer.json.as_ref();
                let Some(acknowledged) =
                    said.and_then(|j| j["acknowledged"].as_u64())
                else {
                    return Settled::Kept(
                        "the service answered 200 without acknowledged"
                            .to_string(),
                    );
                };
                let mut state = self.lock();
                let before = state.queue.len();
                state.queue.retain(|r| r.seq > acknowledged);
                let removed = before - state.queue.len();
                state.shipped += removed as u64;
                // THE SERVICE MAY ACKNOWLEDGE AND RECORD NOTHING
                // (xacml.remotePepAudit off): said, so a reader of GET /
                // is not left believing the rows exist.
                if said.and_then(|j| j["recording"].as_bool()) == Some(false) {
                    state.last_ship_why = format!(
                        "Acknowledged up to {}, and the service is not \
                         recording them: {}",
                        acknowledged,
                        said.and_then(|j| j["why"].as_str())
                            .unwrap_or("it gave no reason.")
                    );
                } else {
                    state.last_ship_why =
                        format!("Acknowledged up to {}.", acknowledged);
                }
                Settled::Acknowledged(removed)
            }
            401 => Settled::Unauthorized,
            400 => {
                let mut state = self.lock();
                let before = state.queue.len();
                state.queue.retain(|r| r.seq < first || r.seq > last);
                let removed = before - state.queue.len();
                state.dropped += removed as u64;
                let said = answer
                    .json
                    .as_ref()
                    .and_then(|j| {
                        j["message"]
                            .as_str()
                            .or_else(|| j["error_description"].as_str())
                            .or_else(|| j["error"].as_str())
                    })
                    .map(str::to_string)
                    .unwrap_or_else(|| answer.text.clone());
                Settled::Refused(said)
            }
            status => {
                let said = answer.error_description().unwrap_or_else(|| {
                    answer
                        .json
                        .as_ref()
                        .and_then(|j| j["message"].as_str())
                        .map(str::to_string)
                        .unwrap_or_default()
                });
                Settled::Kept(if said.is_empty() {
                    format!("the service answered {}", status)
                } else {
                    format!("the service answered {}: {}", status, said)
                })
            }
        }
    }

    /// A delivery's outcome, on `GET /` and in the log: a failure at warn
    /// the first time and when its reason changes, at debug otherwise.
    fn note(&self, ok: bool, why: &str) {
        let mut state = self.lock();
        state.last_ship_at = iso_now();
        state.last_ship_ok = Some(ok);
        if ok {
            if !state.last_ship_reason.is_empty() {
                tracing::info!(
                    "xacml-pep: decision records are reaching the service \
                     again."
                );
            }
            state.last_ship_reason.clear();
            return;
        }
        state.last_ship_why = why.to_string();
        if state.last_ship_reason != why {
            tracing::warn!(
                "{}xacml-pep: decision records not delivered to POST {}: {}. \
                 They stay queued and are sent again.",
                tag("STS-XPEP-0124"),
                AUDIT_PATH,
                why
            );
        } else {
            tracing::debug!(
                "{}xacml-pep: decision records still not delivered: {}",
                tag("STS-XPEP-0124"),
                why
            );
        }
        state.last_ship_reason = why.to_string();
    }

    /// A batch that went without a token: `STS-XPEP-0123` at warn the
    /// first time and when the reason changes (the credential logs the
    /// grant's own refusal, `STS-XPEP-0129`).
    fn note_token_failure(&self, why: &str) {
        let mut state = self.lock();
        state.token_held = false;
        if state.last_token_reason != why {
            tracing::warn!(
                "{}xacml-pep: decision records went to the management API \
                 without an access token: {}. They stay queued.",
                tag("STS-XPEP-0123"),
                why
            );
        } else {
            tracing::debug!(
                "{}xacml-pep: still no access token for the management API: \
                 {}",
                tag("STS-XPEP-0123"),
                why
            );
        }
        state.last_token_reason = why.to_string();
    }

    /// One tick: batches of the oldest records, sent while the queue holds
    /// more and the last one was taken. `false` when something failed.
    pub async fn ship(&self, client: &PdpClient) -> bool {
        loop {
            let batch = self.take();
            if batch.is_empty() {
                return true;
            }
            let answer = client
                .call_authorized(
                    Resource::AdminApi,
                    Method::POST,
                    AUDIT_PATH,
                    Some(Body::Json(json!({
                        "instance": self.instance,
                        "events": batch
                    }))),
                )
                .await;
            match &answer.no_token {
                Some(why) => self.note_token_failure(why),
                None => {
                    let mut state = self.lock();
                    state.token_held = true;
                    if !state.last_token_reason.is_empty() {
                        tracing::info!(
                            "xacml-pep: holds an access token for the \
                             management API again."
                        );
                        state.last_token_reason.clear();
                    }
                }
            }
            match self.settle(&batch, &answer) {
                Settled::Acknowledged(removed) => {
                    self.note(true, "");
                    if removed == 0 {
                        // Nothing taken: sending it again this tick would
                        // only be refused the same way.
                        return true;
                    }
                }
                Settled::Unauthorized => {
                    self.note(
                        false,
                        &match &answer.no_token {
                            Some(why) => format!(
                                "refused (401) without an access token \
                                 (STS-XPEP-0123): {}",
                                why
                            ),
                            None => "the service refused a newly issued \
                                     token (401)"
                                .to_string(),
                        },
                    );
                    return false;
                }
                Settled::Refused(said) => {
                    tracing::warn!(
                        "{}xacml-pep: the service refused a batch of {} \
                         decision record(s) as malformed, so they were \
                         dropped; each is still on this log. It said: {}",
                        tag("STS-XPEP-0125"),
                        batch.len(),
                        said
                    );
                    self.note(
                        false,
                        &format!("a batch refused (400): {}", said),
                    );
                    return false;
                }
                Settled::Kept(why) => {
                    self.note(false, &why);
                    return false;
                }
            }
        }
    }

    /// `audit` on `GET /`. Never the token, only whether one is held.
    pub fn overview(&self) -> Value {
        let enabled = self.enabled();
        let state = self.lock();
        json!({
            "enabled": enabled,
            "queued": state.queue.len(),
            "shipped": state.shipped,
            "dropped": state.dropped,
            "lastShipAt": if state.last_ship_at.is_empty() {
                Value::Null
            } else {
                Value::from(state.last_ship_at.clone())
            },
            "lastShipOk": state.last_ship_ok,
            "lastShipWhy": if enabled {
                state.last_ship_why.clone()
            } else {
                "auditEnabled (PEP_AUDIT) is false, so nothing is queued; \
                 records already queued are still sent."
                    .into()
            },
            "tokenHeld": state.token_held,
            "instance": self.instance,
            "what": "Each decision made HERE — a /protected enforcement, an \
                     AuthZEN evaluation not forwarded, a reverse proxy \
                     request its route decided — is queued and sent \
                     to the service's audit log through POST /admin-api/\
                     pep-audit, with the DPoP-bound token for /admin-api \
                     that credential describes. Delivery is at least once: a record \
                     leaves the queue only when the service acknowledges \
                     its seq, and one not yet acknowledged is lost if the \
                     container restarts. dropped counts records lost to a \
                     full queue (PEP_AUDIT_BUFFER) or to a batch the service \
                     refused as malformed."
        })
    }

    #[cfg(test)]
    fn seqs(&self) -> Vec<u64> {
        self.lock().queue.iter().map(|r| r.seq).collect()
    }

    #[cfg(test)]
    pub fn queued_for_test(&self) -> Vec<Record> {
        self.lock().queue.iter().cloned().collect()
    }

    #[cfg(test)]
    fn dropped(&self) -> u64 {
        self.lock().dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::tests::{decoded, key_file, p256_pem, verifies};

    fn audit(buffer: usize, batch: usize) -> Audit {
        let mut options = Options::from_env("0.0.0");
        options.audit_enabled = true;
        options.audit_buffer = buffer;
        options.audit_batch = batch;
        Audit::new(&options)
    }

    fn one(audit: &Audit, n: usize) {
        for _ in 0..n {
            audit.record(Record {
                kind: "enforcement".into(),
                ..Record::default()
            });
        }
    }

    fn answered(status: u16, body: Value) -> Answer {
        Answer {
            status,
            text: body.to_string(),
            json: Some(body),
            ..Answer::default()
        }
    }

    #[test]
    fn a_full_queue_drops_its_oldest_and_counts_them() {
        let a = audit(3, 200);
        one(&a, 5);
        assert_eq!(a.seqs(), [3, 4, 5]);
        assert_eq!(a.dropped(), 2);
        assert_eq!(a.overview()["queued"], 3);
        assert_eq!(a.overview()["dropped"], 2);
        assert!(worth_logging(1) && worth_logging(3) && worth_logging(100));
        assert!(!worth_logging(4) && !worth_logging(20));
    }

    #[test]
    fn nothing_is_queued_when_it_is_off() {
        let mut options = Options::from_env("0.0.0");
        options.audit_enabled = false;
        let a = Audit::new(&options);
        one(&a, 2);
        assert!(a.seqs().is_empty());
        assert_eq!(a.overview()["enabled"], false);
    }

    #[test]
    fn an_acknowledgement_removes_exactly_what_it_names() {
        let a = audit(100, 3);
        one(&a, 5);
        let batch = a.take();
        assert_eq!(batch.iter().map(|r| r.seq).collect::<Vec<_>>(), [1, 2, 3]);
        let settled = a.settle(
            &batch,
            &answered(
                200,
                json!({ "acknowledged": 2, "recorded": 2,
                                   "duplicates": 0, "ignored": 0,
                                   "recording": true }),
            ),
        );
        assert_eq!(settled, Settled::Acknowledged(2));
        assert_eq!(a.seqs(), [3, 4, 5]);
        assert_eq!(a.overview()["shipped"], 2);
        let kept = a.settle(&a.take(), &answered(503, json!({})));
        assert!(matches!(kept, Settled::Kept(_)));
        assert_eq!(a.seqs(), [3, 4, 5]);
        assert_eq!(
            a.settle(&a.take(), &answered(401, json!({}))),
            Settled::Unauthorized
        );
        assert_eq!(a.seqs(), [3, 4, 5]);
    }

    #[test]
    fn a_refused_batch_is_dropped_alone() {
        let a = audit(100, 2);
        one(&a, 5);
        let batch = a.take();
        let settled = a.settle(
            &batch,
            &answered(400, json!({ "message": "events is not an array" })),
        );
        assert_eq!(settled, Settled::Refused("events is not an array".into()));
        assert_eq!(a.seqs(), [3, 4, 5]);
        assert_eq!(a.dropped(), 2);
    }

    /// The whole tick against a mock service: the grant's form and its
    /// DPoP proof, the DPoP-bound token and proof on the push, a 401
    /// `invalid_token` answered by a new token and the batch sent once
    /// more, and batches sent while the queue holds more.
    #[tokio::test]
    async fn ships_with_a_token_and_retries_a_refused_one_once() {
        use axum::http::{HeaderMap, StatusCode};
        use axum::routing::post;
        use std::sync::{Arc, Mutex};

        #[derive(Default)]
        struct Seen {
            forms: Vec<String>,
            proofs: Vec<String>,
            pushes: Vec<(String, Value)>,
        }
        let seen: Arc<Mutex<Seen>> = Arc::new(Mutex::new(Seen::default()));
        let (on_token, on_push) = (seen.clone(), seen.clone());
        let router = axum::Router::new()
            .route(
                "/realm/r1/oauth2/token",
                post(move |headers: HeaderMap, body: String| {
                    let seen = on_token.clone();
                    async move {
                        let mut seen = seen.lock().unwrap();
                        seen.forms.push(body);
                        seen.proofs.push(
                            headers
                                .get("dpop")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string(),
                        );
                        let n = seen.forms.len();
                        axum::Json(json!({
                            "access_token": format!("token-{}", n),
                            "token_type": "DPoP", "expires_in": 300
                        }))
                    }
                }),
            )
            .route(
                "/realm/r1/admin-api/pep-audit",
                post(move |headers: HeaderMap, body: String| {
                    let seen = on_push.clone();
                    async move {
                        let auth = headers
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string();
                        let proof = headers
                            .get("dpop")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string();
                        assert!(!proof.is_empty(), "a proof on every push");
                        let claims = decoded(proof.split('.').nth(1).unwrap());
                        assert_eq!(claims["htm"], "POST");
                        assert_eq!(
                            claims["ath"],
                            crate::credential::ath(
                                auth.strip_prefix("DPoP ").unwrap_or("")
                            )
                        );
                        let body: Value = serde_json::from_str(&body).unwrap();
                        seen.lock()
                            .unwrap()
                            .pushes
                            .push((auth.clone(), body.clone()));
                        if auth == "DPoP token-1" {
                            return (
                                StatusCode::UNAUTHORIZED,
                                [(
                                    "www-authenticate",
                                    "DPoP error=\"invalid_token\"",
                                )],
                                axum::Json(json!({})),
                            );
                        }
                        let last = body["events"]
                            .as_array()
                            .and_then(|e| e.last())
                            .and_then(|e| e["seq"].as_u64())
                            .unwrap_or(0);
                        (
                            StatusCode::OK,
                            [("www-authenticate", "")],
                            axum::Json(json!({
                                "acknowledged": last, "recorded": 1,
                                "duplicates": 0, "ignored": 0,
                                "recording": true
                            })),
                        )
                    }
                }),
            );
        let socket =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        tokio::spawn(async move {
            // Lives as long as the test; a failure shows as the asserts
            // below failing, so it is only reported.
            if let Err(error) = axum::serve(socket, router).await {
                eprintln!("the mock service stopped: {}", error);
            }
        });
        let mut options = Options::from_env("0.0.0");
        options.pdp_url = format!("http://127.0.0.1:{}/realm/r1/", port);
        options.name = "remote-pep-1".into();
        options.audit_enabled = true;
        options.audit_batch = 2;
        options.client_id = "sts-remote-pep".into();
        let file = key_file(&p256_pem());
        options.assertion_key = crate::credential::KeySource::choose(
            Some(file.to_str().unwrap()),
            None,
        );
        let client = PdpClient::new(&options).unwrap();
        std::fs::remove_file(&file).unwrap();
        let jwk = client.credential().overview()["jwkThumbprint"].clone();
        assert!(jwk.is_string());
        let a = Audit::new(&options);
        one(&a, 3);

        assert!(a.ship(&client).await);
        assert!(a.seqs().is_empty());
        let overview = a.overview();
        let credential = client.credential().overview();
        assert_eq!(credential["tokens"]["admin-api"]["held"], true);
        assert!(!credential.to_string().contains("token-2"));
        assert_eq!(overview["shipped"], 3);
        assert_eq!(overview["tokenHeld"], true);
        assert_eq!(overview["lastShipOk"], true);
        assert!(!overview.to_string().contains("token-2"));
        let seen = seen.lock().unwrap();
        assert_eq!(seen.forms.len(), 2, "a 401 fetches one new token");
        let form = &seen.forms[0];
        assert!(form.contains("scope=xacml%3Apep-audit"));
        let token_proof = decoded(seen.proofs[0].split('.').next().unwrap());
        assert_eq!(token_proof["typ"], "dpop+jwt");
        assert!(verifies(&seen.proofs[0], &token_proof["jwk"]));
        let token_claims = decoded(seen.proofs[0].split('.').nth(1).unwrap());
        assert!(token_claims.get("ath").is_none());
        assert_eq!(
            token_claims["htu"],
            format!("http://127.0.0.1:{}/realm/r1/oauth2/token", port)
        );
        assert!(form.contains(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"
        ));
        assert!(form.contains("client_id=sts-remote-pep"));
        assert!(form.contains("scope=xacml%3Apep-audit"));
        assert!(form.contains(&format!(
            "resource={}",
            crate::sync::encode(&format!(
                "http://127.0.0.1:{}/realm/r1/admin-api",
                port
            ))
        )));
        let auds: Vec<&str> = form
            .split('&')
            .filter_map(|p| p.strip_prefix("assertion="))
            .collect();
        let claims = decoded(auds[0].split('.').nth(1).unwrap());
        assert_eq!(
            claims["aud"],
            format!("http://127.0.0.1:{}/realm/r1/oauth2/token", port)
        );
        let pushes: Vec<(String, Vec<u64>)> = seen
            .pushes
            .iter()
            .map(|(auth, body)| {
                assert_eq!(body["instance"], a.instance);
                (
                    auth.clone(),
                    body["events"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|e| e["seq"].as_u64().unwrap())
                        .collect(),
                )
            })
            .collect();
        assert_eq!(
            pushes,
            [
                ("DPoP token-1".to_string(), vec![1, 2]),
                ("DPoP token-2".to_string(), vec![1, 2]),
                ("DPoP token-2".to_string(), vec![3]),
            ]
        );
        let event = &seen.pushes[1].1["events"][0];
        for member in [
            "seq",
            "at",
            "kind",
            "decision",
            "allowed",
            "fault",
            "code",
            "subject",
            "resource",
            "action",
            "bias",
            "why",
            "policies",
            "discharged",
            "undischargeable",
            "caller",
            "application",
            "subjectType",
            "endpoint",
            "requestId",
        ] {
            assert!(event.get(member).is_some(), "{} is sent", member);
        }
        assert_eq!(event.as_object().unwrap().len(), 20);
    }
}
