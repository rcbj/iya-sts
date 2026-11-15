// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! WHAT A WEBAUTHN CEREMONY RECORDS (#943): a port of
//! `authn/webauthn_ceremonies.ts` — ONE audit row, `webauthn.ceremony`, for
//! every registration and assertion at the doors that run one, successful
//! or not; `webauthn.algorithm-mismatch` where a person holding an ML-DSA
//! passkey signed in with a classical one that was not required; and
//! `webauthn.key.possibly-replaced`. The row's shape is the one `/report`'s
//! passkey ceremony source reads, member for member.
//!
//! WHAT REPLACED WHAT. The audit log is the [`AuditSink`] handed in (the
//! runtime's audit, `sts-audit`). `clientOf()` reads the User-Agent with
//! `bowser`; here [`client_of`] reads the same few families by their
//! tokens — the browser and the system, family and major version only, as
//! Node keeps them, and `a browser on another system` for anything else.
//! `passkeyClients.observe()` (#1112's learned clients) is not in this
//! runtime: with `webauthn.clientLearning` off, the default, Node's
//! observation learns nothing either.

use std::sync::Arc;

use serde_json::{json, Value as Json};

use super::ceremony::cose_name;
use super::policy::is_post_quantum;
use crate::js;

/// `DOORS`.
const DOORS: [&str; 7] = [
    "sign-in-step",
    "usernameless",
    "portal",
    "activation",
    "upgrade",
    "admin-enrolment",
    "device-link",
];

/// `CLIENT_ERRORS`: the DOMException names a page may report.
const CLIENT_ERRORS: [&str; 13] = [
    "NotAllowedError",
    "NotSupportedError",
    "InvalidStateError",
    "SecurityError",
    "AbortError",
    "ConstraintError",
    "UnknownError",
    "TimeoutError",
    "OperationError",
    "EncodingError",
    "NotReadableError",
    "DataError",
    "TypeError",
];

/// `MAX_DURATION_MS`: a day.
const MAX_DURATION_MS: f64 = 24.0 * 60.0 * 60.0 * 1000.0;

/// Where a row goes: `audit.audit(row)`.
pub trait AuditSink: Send + Sync {
    fn audit(&self, row: &Json);
}

/// `WebauthnCeremonies.clientErrorName(raw)`.
#[tracing::instrument(level = "trace", skip_all)]
pub fn client_error_name(raw: &Json) -> String {
    match raw {
        Json::Null => String::new(),
        Json::String(s) if s.is_empty() => String::new(),
        other => {
            let name = js::string(other);
            if CLIENT_ERRORS.contains(&name.as_str()) {
                name
            } else {
                "other".into()
            }
        }
    }
}

/// `WebauthnCeremonies.durationOf(issuedAt, now)`.
#[tracing::instrument(level = "trace")]
pub fn duration_of(issued_at: f64, now: f64) -> Option<f64> {
    if issued_at == 0.0 || !issued_at.is_finite() {
        return None;
    }
    let ms = (now - issued_at).round();
    if !(0.0..=MAX_DURATION_MS).contains(&ms) {
        return None;
    }
    Some(ms)
}

/// `WebauthnCeremonies.clientOf(userAgent)`: `Chrome 141 on macOS 15`.
#[tracing::instrument(level = "trace", skip_all)]
pub fn client_of(user_agent: &str) -> String {
    let ua: String = user_agent.chars().take(512).collect();
    if ua.is_empty() {
        return String::new();
    }
    let major = |after: &str| -> String {
        ua.split(after)
            .nth(1)
            .map(|rest| {
                rest.chars()
                    .take_while(char::is_ascii_digit)
                    .take(4)
                    .collect::<String>()
            })
            .filter(|d| !d.is_empty())
            .map(|d| format!(" {d}"))
            .unwrap_or_default()
    };
    let browser = if ua.contains("Edg/") {
        format!("Microsoft Edge{}", major("Edg/"))
    } else if ua.contains("HeadlessChrome/") {
        format!("Chrome Headless{}", major("HeadlessChrome/"))
    } else if ua.contains("Chrome/") {
        format!("Chrome{}", major("Chrome/"))
    } else if ua.contains("Firefox/") {
        format!("Firefox{}", major("Firefox/"))
    } else if ua.contains("Safari/") && ua.contains("Version/") {
        format!("Safari{}", major("Version/"))
    } else {
        "a browser".to_string()
    };
    let os = if ua.contains("Android") {
        format!("Android{}", major("Android "))
    } else if ua.contains("iPhone") || ua.contains("iPad") {
        format!("iOS{}", major("OS "))
    } else if ua.contains("Mac OS X") {
        format!("macOS{}", major("Mac OS X "))
    } else if ua.contains("Windows") {
        "Windows".to_string()
    } else if ua.contains("Linux") {
        "Linux".to_string()
    } else {
        "another system".to_string()
    };
    format!("{browser} on {os}")
}

/// `WebauthnCeremonies.namesOf(list)`.
fn names_of(list: &Json) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for one in list.as_array().into_iter().flatten().take(32) {
        let name = match one {
            Json::Number(n) => {
                let id = n.as_i64().unwrap_or(0);
                cose_name(id)
                    .map(String::from)
                    .unwrap_or_else(|| format!("COSE {}", js::string(one)))
            }
            other => js::string_or(Some(other), ""),
        };
        let ok = !name.is_empty()
            && name.len() <= 40
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || " _.-".contains(c));
        if ok && !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

fn fold_authenticator(
    attachment: &str,
    transports: &str,
    attestation: &str,
) -> String {
    if attachment.is_empty() && transports.is_empty() && attestation.is_empty()
    {
        return String::new();
    }
    format!(
        "{}|{}|{}",
        attachment.replace('|', "/"),
        transports.replace('|', "/"),
        attestation
    )
}

fn attestation_text(rec: &Json) -> String {
    let lead = if rec["enterpriseDowngraded"] == json!(true) {
        "enterprise not listed, asked direct"
    } else {
        ""
    };
    let a = &rec["algorithms"];
    if !js::truthy(a) {
        return lead.to_string();
    }
    let mut chain: Vec<String> = a["certificates"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|c| js::string_or(c.get("algorithm"), ""))
        .collect();
    if js::truthy(&a["anchor"]) {
        chain.push(js::string_or(a["anchor"].get("algorithm"), ""));
    }
    chain.retain(|c| !c.is_empty());
    let mut parts = vec![js::string_or(a.get("statement"), "")];
    if !chain.is_empty() {
        parts.push(chain.join(" > "));
    }
    parts.retain(|p| !p.is_empty());
    let text = parts.join("; ");
    let tail = if text.is_empty() {
        String::new()
    } else if a["postQuantum"] == json!(true) {
        format!("{text} (PQ)")
    } else {
        text
    };
    [lead.to_string(), tail]
        .into_iter()
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("; ")
}

/// The ceremony log.
pub struct Ceremonies {
    audit: Arc<dyn AuditSink>,
}

impl Ceremonies {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(audit: Arc<dyn AuditSink>) -> Ceremonies {
        Ceremonies { audit }
    }

    /// `record(event)`: the one `webauthn.ceremony` row. `event` carries
    /// Node's members (`ceremony`, `door`, `username`, `role`, `lane`,
    /// `outcome`, `errorCode`, `offered`, `algorithm`, `posted`,
    /// `attestation`, `narrowed`, `application`, `issuedAt`) and
    /// `userAgent` for the request's.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn record(&self, e: &Json, now_ms: f64) -> Json {
        let posted = if e["posted"].is_object() {
            e["posted"].clone()
        } else {
            json!({})
        };
        let response = if posted["response"].is_object() {
            posted["response"].clone()
        } else {
            json!({})
        };
        let listed = if response["transports"].is_array() {
            &response["transports"]
        } else {
            &posted["transports"]
        };
        let transports: Vec<String> = listed
            .as_array()
            .into_iter()
            .flatten()
            .map(js::string)
            .filter(|t| {
                !t.is_empty()
                    && t.len() <= 20
                    && t.chars().all(|c| c.is_ascii_lowercase() || c == '-')
            })
            .take(8)
            .collect();
        let attachment =
            match js::string_or_empty(posted.get("authenticatorAttachment"))
                .as_str()
            {
                a @ ("platform" | "cross-platform") => a.to_string(),
                _ => String::new(),
            };
        let algorithm: String = js::string_or(e.get("algorithm"), "")
            .chars()
            .take(40)
            .collect();
        let ceremony = if e["ceremony"] == json!("registration") {
            "registration"
        } else {
            "assertion"
        };
        let asked_door = js::string_or_empty(e.get("door"));
        let door = if DOORS.contains(&asked_door.as_str()) {
            asked_door
        } else {
            "sign-in-step".to_string()
        };
        let client_error = client_error_name(&posted["error"]);
        let capabilities = [
            "conditionalCreate",
            "conditionalGet",
            "hybridTransport",
            "userVerifyingPlatformAuthenticator",
            "relatedOrigin",
            "signalAllAcceptedCredentials",
            "signalCurrentUserDetails",
            "signalUnknownCredential",
        ]
        .iter()
        .filter(|n| posted["capabilities"][**n] == json!(true))
        .copied()
        .collect::<Vec<_>>()
        .join(",");
        let refused = e["outcome"] != json!("success");
        let duration = duration_of(js::number_opt(e.get("issuedAt")), now_ms);
        let narrowed = js::string_or(e.get("narrowed"), "");
        let mut offered = names_of(&e["offered"]).join(",");
        if !narrowed.is_empty() {
            offered.push('|');
            offered.extend(narrowed.chars().take(120));
        }
        let mut detail = serde_json::Map::new();
        detail.insert("ceremony".into(), json!(ceremony));
        detail.insert("door".into(), json!(door));
        detail.insert("role".into(), json!(js::string_or(e.get("role"), "")));
        detail.insert("lane".into(), json!(js::string_or(e.get("lane"), "")));
        detail.insert(
            "application".into(),
            json!(js::string_or(e.get("application"), "")
                .chars()
                .take(120)
                .collect::<String>()),
        );
        if let Some(ms) = duration {
            detail.insert("durationMs".into(), js::num(ms));
        }
        detail.insert("offered".into(), json!(offered));
        detail.insert("algorithm".into(), json!(algorithm));
        detail.insert(
            "client".into(),
            json!(client_of(&js::string_or(e.get("userAgent"), ""))),
        );
        detail.insert("clientError".into(), json!(client_error));
        detail.insert("capabilities".into(), json!(capabilities));
        detail.insert(
            "authenticator".into(),
            json!(fold_authenticator(
                &attachment,
                &transports.join(","),
                &if ceremony == "registration" {
                    attestation_text(&e["attestation"])
                } else {
                    String::new()
                }
            )),
        );
        let summary = format!(
            "a WebAuthn {} at the {} door {}{}",
            ceremony,
            door,
            if refused {
                format!(
                    "did not complete{}",
                    if client_error.is_empty() {
                        String::new()
                    } else {
                        format!(" (the browser reported {client_error})")
                    }
                )
            } else {
                "completed".to_string()
            },
            if algorithm.is_empty() {
                String::new()
            } else {
                format!(" with {algorithm}")
            }
        );
        let row = json!({
            "action": "webauthn.ceremony", "category": "authentication",
            "outcome": if refused { "refused" } else { "success" },
            "errorCode": if refused {
                js::string_or(e.get("errorCode"), "") } else { String::new() },
            "summarised": true,
            "actor": js::string_or(e.get("username"), ""), "channel": "http",
            "protocol": "WebAuthn", "summary": summary,
            "detail": detail });
        self.audit.audit(&row);
        row
    }

    /// `algorithmMismatch(input)`: a row where a person holding an ML-DSA
    /// passkey signed in with a classical one that was not required.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn algorithm_mismatch(&self, given: &Json) -> Option<Json> {
        let used = js::string_or(given.get("used"), "");
        let mut pq: Vec<String> = Vec::new();
        for one in given["held"].as_array().into_iter().flatten() {
            let name = js::string(one);
            if is_post_quantum(&name) && !pq.contains(&name) {
                pq.push(name);
            }
        }
        if used.is_empty()
            || is_post_quantum(&used)
            || pq.is_empty()
            || given["required"] == json!(true)
        {
            return None;
        }
        let username = js::string_or(given.get("username"), "");
        let row = json!({
            "action": "webauthn.algorithm-mismatch",
            "category": "authentication", "outcome": "success",
            "actor": username, "channel": "http", "protocol": "WebAuthn",
            "summary": format!("{} holds a post-quantum passkey ({}) and \
                signed in with a classical one ({})", username, pq.join(", "),
                used),
            "detail": { "used": used, "held": pq.join(","),
                "door": js::string_or(given.get("door"), ""),
                "client": client_of(&js::string_or(given.get("userAgent"),
                                                   "")) } });
        self.audit.audit(&row);
        Some(row)
    }

    /// `possiblyReplaced(input)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn possibly_replaced(&self, given: &Json) -> Json {
        let username = js::string_or(given.get("username"), "");
        let row = json!({
            "action": "webauthn.key.possibly-replaced",
            "category": "authentication", "outcome": "success",
            "actor": username, "target": username, "channel": "http",
            "protocol": "WebAuthn",
            "summary": format!("a passkey of {} may have been replaced on \
                its authenticator by one registered later under the same \
                user handle", username),
            "detail": {
                "credentialId": js::string_or(given.get("credentialId"), ""),
                "by": js::string_or(given.get("by"), ""),
                "aaguid": js::string_or(given.get("aaguid"), "") } });
        self.audit.audit(&row);
        row
    }
}
