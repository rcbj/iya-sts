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
//! * **The token is an RFC 7523 self-assertion**: a JWT naming this PEP as
//!   `iss` and `sub`, signed with the key of its client certificate,
//!   presented as a `jwt-bearer` grant through the public client
//!   `sts-remote-pep` over the same mutual TLS as every other call — which
//!   is what binds the token (RFC 8705). Cached until 30 s before it
//!   expires, and fetched again on a 401.
//! * **At least once, in order.** A record leaves the queue only when the
//!   service ACKNOWLEDGES its `seq`; a failure keeps it for the next tick.
//!   `seq` counts from 1 in this process, beside an `instance` drawn at
//!   start, so a restart that counts from 1 again is not mistaken for old
//!   records by the service's deduplication mark.
//! * **The queue is bounded and never blocks a decision.** Full, the OLDEST
//!   record is dropped and counted (`STS-XPEP-0119`); a batch the service
//!   refuses as malformed (400) is dropped too (`STS-XPEP-0122`), rather
//!   than sent forever.
//! * **A FORWARDED AuthZEN evaluation is not queued** (#564): the service
//!   decided it and wrote its own row under the same request id.
//! * **An AuthZEN record carries exactly what its log line carries** — no
//!   property value, no id the caller sent, no credential (decision 9 on
//!   #563).
//! * **What a restart loses**: every record not yet acknowledged. The log
//!   line on stdout is still there. A disk spool is a separate decision.

use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey};
use openssl::sign::Signer;
use reqwest::Method;
use serde::Serialize;
use serde_json::{json, Value};
use sts_core::log::tag;
use sts_core::time::iso_now;

use crate::options::Options;
use crate::pdp_client::{Answer, Body, PdpClient};

/// Where the records go, under the PDP URL (a realm prefix included).
pub const AUDIT_PATH: &str = "/admin-api/pep-audit";
/// Where the token comes from.
pub const TOKEN_PATH: &str = "/oauth2/token";
/// The one scope the operation accepts, and the only one asked for.
pub const SCOPE: &str = "xacml:pep-audit";
const JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/// The self-assertion's lifetime: long enough for a slow token endpoint,
/// short enough that one seen in a log is useless soon after.
const ASSERTION_LIFETIME_S: i64 = 120;
/// A token is fetched again this long before it expires.
const RENEW_BEFORE_S: u64 = 30;
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
    /// `enforcement` or `authzen`.
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
    /// 401: the token was refused; fetch another and send again once.
    Unauthorized,
    /// 400: the batch was refused as malformed and dropped.
    Refused(String),
    /// Anything else: kept for the next tick.
    Kept(String),
}

struct Token {
    value: String,
    renew_at: Instant,
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
    token: Option<Token>,
    /// The last delivery failure's reason, so a repeated one is logged at
    /// debug and only a CHANGE at warn.
    last_ship_reason: String,
    last_token_reason: String,
}

/// The queue, the token and the shipping.
pub struct Audit {
    /// The options, read through `now()` at every use: the switch, the
    /// interval, the batch and the bound are managed settings (#1760), so
    /// a change made on the PEP's console page applies while this runs.
    options: Options,
    instance: String,
    client_id: String,
    name: String,
    pdp_url: String,
    key: Option<Vec<u8>>,
    state: Mutex<State>,
}

/// `bytes` random bytes as lower-case hex, or `None` when OpenSSL cannot
/// draw them.
fn random_hex(bytes: usize) -> Option<String> {
    let mut buffer = vec![0u8; bytes];
    openssl::rand::rand_bytes(&mut buffer).ok()?;
    Some(buffer.iter().map(|b| format!("{:02x}", b)).collect())
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

/// The RFC 7523 self-assertion: a compact JWS naming `name` as `iss` and
/// `sub`, for `audience` (the token endpoint), signed with the key of this
/// PEP's client certificate — RS256 for an RSA key, ES256 for an EC P-256
/// one, anything else refused by name. No `kid`: the service finds the
/// key by the subject's registered certificate.
pub fn self_assertion(
    key_pem: &[u8],
    name: &str,
    audience: &str,
    now: i64,
) -> Result<String, String> {
    let key = PKey::private_key_from_pem(key_pem)
        .map_err(|e| format!("the key at PEP_TLS_KEY would not load: {}", e))?;
    let alg = match key.id() {
        Id::RSA => "RS256",
        Id::EC => {
            let curve =
                key.ec_key().ok().and_then(|ec| ec.group().curve_name());
            if curve != Some(Nid::X9_62_PRIME256V1) {
                return Err("the key at PEP_TLS_KEY is an EC key on a curve \
                     other than P-256, and the self-assertion is signed only \
                     with RS256 or ES256"
                    .to_string());
            }
            "ES256"
        }
        other => {
            return Err(format!(
                "the key at PEP_TLS_KEY is of type {:?}, and the \
                 self-assertion is signed only with an RSA key (RS256) or an \
                 EC P-256 key (ES256)",
                other
            ))
        }
    };
    let jti = random_hex(16)
        .ok_or_else(|| "no random bytes for the assertion's jti".to_string())?;
    let header = json!({ "alg": alg, "typ": "JWT" });
    let claims = json!({
        "iss": name,
        "sub": name,
        "aud": audience,
        "iat": now,
        "exp": now + ASSERTION_LIFETIME_S,
        "jti": jti
    });
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let failed = |e: openssl::error::ErrorStack| {
        format!("the self-assertion could not be signed: {}", e)
    };
    let mut signer =
        Signer::new(MessageDigest::sha256(), &key).map_err(failed)?;
    signer.update(input.as_bytes()).map_err(failed)?;
    let der = signer.sign_to_vec().map_err(failed)?;
    let signature = if alg == "ES256" {
        // JWS wants r || s, 32 bytes each (RFC 7518 section 3.4), and
        // OpenSSL writes the DER SEQUENCE.
        let sig = EcdsaSig::from_der(&der).map_err(failed)?;
        let mut raw = sig.r().to_vec_padded(32).map_err(failed)?;
        raw.extend(sig.s().to_vec_padded(32).map_err(failed)?);
        raw
    } else {
        der
    };
    Ok(format!("{}.{}", input, URL_SAFE_NO_PAD.encode(signature)))
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
            client_id: options.audit_client_id.clone(),
            name: options.name.clone(),
            pdp_url: options.pdp_url.trim_end_matches('/').to_string(),
            key: options.client_key.clone(),
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
                    tag("STS-XPEP-0119"),
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
                tag("STS-XPEP-0121"),
                AUDIT_PATH,
                why
            );
        } else {
            tracing::debug!(
                "{}xacml-pep: decision records still not delivered: {}",
                tag("STS-XPEP-0121"),
                why
            );
        }
        state.last_ship_reason = why.to_string();
    }

    fn note_token_failure(&self, why: &str) {
        let mut state = self.lock();
        if state.last_token_reason != why {
            tracing::warn!(
                "{}xacml-pep: no access token for the management API: {}. \
                 This PEP's entry must hold its client certificate as an \
                 assertion key and be in the remote PEPs group. The decision \
                 records stay queued.",
                tag("STS-XPEP-0120"),
                why
            );
        } else {
            tracing::debug!(
                "{}xacml-pep: still no access token: {}",
                tag("STS-XPEP-0120"),
                why
            );
        }
        state.last_token_reason = why.to_string();
    }

    /// The token held, or a new one from the self-assertion grant.
    async fn token(&self, client: &PdpClient) -> Option<String> {
        {
            let state = self.lock();
            if let Some(token) = &state.token {
                if Instant::now() < token.renew_at {
                    return Some(token.value.clone());
                }
            }
        }
        let Some(key) = &self.key else {
            self.note_token_failure(
                "there is no PEP_TLS_KEY to sign the self-assertion with",
            );
            return None;
        };
        let audience = format!("{}{}", self.pdp_url, TOKEN_PATH);
        let assertion = match self_assertion(
            key,
            &self.name,
            &audience,
            chrono::Utc::now().timestamp(),
        ) {
            Ok(assertion) => assertion,
            Err(why) => {
                self.note_token_failure(&why);
                return None;
            }
        };
        let form = vec![
            ("grant_type".to_string(), JWT_BEARER.to_string()),
            ("assertion".to_string(), assertion),
            ("client_id".to_string(), self.client_id.clone()),
            ("scope".to_string(), SCOPE.to_string()),
            (
                "resource".to_string(),
                format!("{}/admin-api", self.pdp_url),
            ),
        ];
        let answer = client
            .call(Method::POST, TOKEN_PATH, Some(Body::Form(form)))
            .await;
        let token = answer
            .json
            .as_ref()
            .and_then(|j| j["access_token"].as_str())
            .filter(|t| !t.is_empty());
        let (value, expires_in) = match (&answer.error, answer.status, token) {
            (None, 200, Some(token)) => (
                token.to_string(),
                answer
                    .json
                    .as_ref()
                    .and_then(|j| j["expires_in"].as_u64())
                    .unwrap_or(60),
            ),
            (Some(error), _, _) => {
                self.note_token_failure(&format!(
                    "the token endpoint did not answer: {}",
                    error
                ));
                return None;
            }
            (None, 200, None) => {
                self.note_token_failure(
                    "the token endpoint answered 200 without an access_token",
                );
                return None;
            }
            (None, status, _) => {
                let said = answer.error_description().unwrap_or_else(|| {
                    answer
                        .json
                        .as_ref()
                        .and_then(|j| j["error"].as_str())
                        .map(str::to_string)
                        .unwrap_or_default()
                });
                self.note_token_failure(&format!(
                    "the token endpoint answered {}{}",
                    status,
                    if said.is_empty() {
                        String::new()
                    } else {
                        format!(": {}", said)
                    }
                ));
                return None;
            }
        };
        let mut state = self.lock();
        if !state.last_token_reason.is_empty() {
            tracing::info!(
                "xacml-pep: holds an access token for the management API \
                 again."
            );
            state.last_token_reason.clear();
        }
        state.token = Some(Token {
            value: value.clone(),
            renew_at: Instant::now()
                + Duration::from_secs(
                    expires_in.saturating_sub(RENEW_BEFORE_S),
                ),
        });
        Some(value)
    }

    /// One tick: batches of the oldest records, sent while the queue holds
    /// more and the last one was taken. `false` when something failed.
    pub async fn ship(&self, client: &PdpClient) -> bool {
        let mut retried = false;
        loop {
            let batch = self.take();
            if batch.is_empty() {
                return true;
            }
            let Some(token) = self.token(client).await else {
                self.note(false, "no access token (STS-XPEP-0120)");
                return false;
            };
            let answer = client
                .call_with(
                    Method::POST,
                    AUDIT_PATH,
                    Some(Body::Json(json!({
                        "instance": self.instance,
                        "events": batch
                    }))),
                    &[("Authorization", format!("Bearer {}", token))],
                    None,
                )
                .await;
            match self.settle(&batch, &answer) {
                Settled::Acknowledged(removed) => {
                    self.note(true, "");
                    retried = false;
                    if removed == 0 {
                        // Nothing taken: sending it again this tick would
                        // only be refused the same way.
                        return true;
                    }
                }
                Settled::Unauthorized if !retried => {
                    // THE TOKEN WAS REFUSED: expired early, revoked, or the
                    // service restarted with new keys. One more, once.
                    self.lock().token = None;
                    retried = true;
                }
                Settled::Unauthorized => {
                    self.lock().token = None;
                    self.note(
                        false,
                        "the service refused a newly issued token (401)",
                    );
                    return false;
                }
                Settled::Refused(said) => {
                    tracing::warn!(
                        "{}xacml-pep: the service refused a batch of {} \
                         decision record(s) as malformed, so they were \
                         dropped; each is still on this log. It said: {}",
                        tag("STS-XPEP-0122"),
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
            "tokenHeld": state.token.is_some(),
            "instance": self.instance,
            "what": "Each decision made HERE — a /protected enforcement, an \
                     AuthZEN evaluation not forwarded — is queued and sent \
                     to the service's audit log through POST /admin-api/\
                     pep-audit, with a token this PEP obtains by an \
                     RFC 7523 self-assertion signed with its client \
                     certificate's key. Delivery is at least once: a record \
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
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::rsa::Rsa;
    use openssl::sign::Verifier;

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

    fn decoded(part: &str) -> Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
    }

    #[test]
    fn the_self_assertion_is_rs256_and_verifies() {
        let rsa = Rsa::generate(2048).unwrap();
        let key = PKey::from_rsa(rsa).unwrap();
        let pem = key.private_key_to_pem_pkcs8().unwrap();
        let aud = "https://pdp.example/realm/r1/oauth2/token";
        let jws = self_assertion(&pem, "remote-pep-1", aud, 1_000_000).unwrap();
        let parts: Vec<&str> = jws.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header = decoded(parts[0]);
        assert_eq!(header, json!({ "alg": "RS256", "typ": "JWT" }));
        assert!(header.get("kid").is_none());
        let claims = decoded(parts[1]);
        assert_eq!(claims["iss"], "remote-pep-1");
        assert_eq!(claims["sub"], "remote-pep-1");
        assert_eq!(claims["aud"], aud);
        assert_eq!(claims["iat"], 1_000_000);
        assert_eq!(
            claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
            120
        );
        assert_eq!(claims["jti"].as_str().unwrap().len(), 32);
        let public =
            PKey::public_key_from_pem(&key.public_key_to_pem().unwrap())
                .unwrap();
        let mut verifier =
            Verifier::new(MessageDigest::sha256(), &public).unwrap();
        verifier
            .update(format!("{}.{}", parts[0], parts[1]).as_bytes())
            .unwrap();
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert!(verifier.verify(&signature).unwrap());
        let again = self_assertion(&pem, "remote-pep-1", aud, 1).unwrap();
        assert_ne!(
            decoded(again.split('.').nth(1).unwrap())["jti"],
            claims["jti"],
            "a fresh jti every time"
        );
    }

    #[test]
    fn the_self_assertion_is_es256_raw_on_p256_and_refused_otherwise() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec = EcKey::generate(&group).unwrap();
        let key = PKey::from_ec_key(ec.clone()).unwrap();
        let pem = key.private_key_to_pem_pkcs8().unwrap();
        let jws = self_assertion(&pem, "p", "a", 5).unwrap();
        let parts: Vec<&str> = jws.split('.').collect();
        assert_eq!(decoded(parts[0])["alg"], "ES256");
        let raw = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert_eq!(raw.len(), 64);
        let sig = EcdsaSig::from_private_components(
            BigNum::from_slice(&raw[..32]).unwrap(),
            BigNum::from_slice(&raw[32..]).unwrap(),
        )
        .unwrap();
        let digest = openssl::hash::hash(
            MessageDigest::sha256(),
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
        )
        .unwrap();
        assert!(sig.verify(&digest, &ec).unwrap());

        let p384 = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let other = PKey::from_ec_key(EcKey::generate(&p384).unwrap())
            .unwrap()
            .private_key_to_pem_pkcs8()
            .unwrap();
        assert!(self_assertion(&other, "p", "a", 5)
            .unwrap_err()
            .contains("P-256"));
        let ed = PKey::generate_ed25519()
            .unwrap()
            .private_key_to_pem_pkcs8()
            .unwrap();
        assert!(self_assertion(&ed, "p", "a", 5)
            .unwrap_err()
            .contains("RS256"));
    }

    /// The whole tick against a mock service: the grant's form, the
    /// bearer token on the push, a 401 answered by a new token and the
    /// batch sent once more, and batches sent while the queue holds more.
    #[tokio::test]
    async fn ships_with_a_token_and_retries_a_refused_one_once() {
        use axum::http::{HeaderMap, StatusCode};
        use axum::routing::post;
        use std::sync::{Arc, Mutex};

        #[derive(Default)]
        struct Seen {
            forms: Vec<String>,
            pushes: Vec<(String, Value)>,
        }
        let seen: Arc<Mutex<Seen>> = Arc::new(Mutex::new(Seen::default()));
        let (on_token, on_push) = (seen.clone(), seen.clone());
        let router = axum::Router::new()
            .route(
                "/realm/r1/oauth2/token",
                post(move |body: String| {
                    let seen = on_token.clone();
                    async move {
                        let mut seen = seen.lock().unwrap();
                        seen.forms.push(body);
                        let n = seen.forms.len();
                        axum::Json(json!({
                            "access_token": format!("token-{}", n),
                            "token_type": "Bearer", "expires_in": 300
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
                        let body: Value = serde_json::from_str(&body).unwrap();
                        seen.lock()
                            .unwrap()
                            .pushes
                            .push((auth.clone(), body.clone()));
                        if auth == "Bearer token-1" {
                            return (
                                StatusCode::UNAUTHORIZED,
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
        options.audit_client_id = "sts-remote-pep".into();
        let rsa = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        options.client_key = Some(rsa.private_key_to_pem_pkcs8().unwrap());
        let client = PdpClient::new(&options).unwrap();
        let a = Audit::new(&options);
        one(&a, 3);

        assert!(a.ship(&client).await);
        assert!(a.seqs().is_empty());
        let overview = a.overview();
        assert_eq!(overview["shipped"], 3);
        assert_eq!(overview["tokenHeld"], true);
        assert_eq!(overview["lastShipOk"], true);
        assert!(!overview.to_string().contains("token-2"));
        let seen = seen.lock().unwrap();
        assert_eq!(seen.forms.len(), 2, "a 401 fetches one new token");
        let form = &seen.forms[0];
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
                ("Bearer token-1".to_string(), vec![1, 2]),
                ("Bearer token-2".to_string(), vec![1, 2]),
                ("Bearer token-2".to_string(), vec![3]),
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
