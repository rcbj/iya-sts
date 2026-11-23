// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE AUTHZEN EDGE PDP (#1179): AuthZEN Authorization API 1.0 Access
//! Evaluation, answered HERE, over the policy this container pulled.
//!
//! ```text
//! POST /access/v1/evaluation                 one evaluation (section 6)
//! POST /access/v1/evaluations                a batch (section 7)
//! GET  /.well-known/authzen-configuration    the metadata (section 9)
//! POST /access/v1/search/{subject,resource,action}
//!                                            501: the service's Search APIs
//! POST /access/v1/access-requests and the
//!   task, schema and cancel paths            501: the service's profile
//! ```
//!
//! A token-exchange binding tuple is 501 on the evaluation endpoints, as
//! an item error inside a batch. `signed_metadata` is omitted. Obligations
//! are handed when the PEP declared every type and the realm's profile is
//! on. `context.approval` is recognized and not used.
//!
//! **THE SERVICE'S CONTRACT, NOT A SECOND ONE.** A request is read and
//! mapped by `authzen_map.rs` against the catalogue pulled from the
//! service (`sync.rs`), built by the port of the one builder, decided by
//! this container's engine against the root policy it pulled, enforced
//! deny-biased and mapped back fail-closed — the same identifiers, value
//! rules, codes and statuses as `authzen/authzen.ts`, the same batch
//! semantics and bounds (taken from the realm's settings, which travel with
//! the catalogue), and `X-Request-ID` echoed by the same rule. A denial is
//! a 200 with `decision: false`; an error is never one.
//!
//! **WHO MAY ASK is the SERVICE'S ANSWER, pulled** (#1189, rcbj's
//! decision): the door is mutual TLS only, on the HTTPS listener — a
//! certificate that verifies against `PEP_AUTHZEN_CLIENT_CA` — and the
//! caller is the one the pulled list (`GET /xacml/pep/authzen-callers`)
//! names by that certificate's SHA-256: the name a policy sees, its
//! application scope and the endpoints the service's access-control policy
//! admits it to, so the outcome of AUTHZEN_PEPS and `stsAuthzenApplication`
//! rather than a second copy of them. `PEP_AUTHZEN_CALLERS`, when set,
//! NARROWS it (a pulled caller must be on it too) and decides alone only
//! until the first pull. No bearer door, no revocation check of an outside
//! authority, no audit row (a log line instead): `xacml-pep/CLAUDE.md`
//! states each.
//!
//! **AN APPLICATION THAT ENFORCES FINE-GRAINED AUTHORIZATION IS NOT DECIDED
//! HERE** (#564, P7; rcbj's decision of 2026-10-30, extending #564's
//! decision 4). Its policy is the application's own, which the pull
//! withholds, and FGA is decided only in the service. So an evaluation
//! whose application — resolved exactly as for any other — is on the
//! catalogue's `fgaApplications` is FORWARDED, as one single evaluation, to
//! the realm's `POST /access/v1/evaluation` on the service, over the client
//! (and the client certificate) this container pulls with, carrying the
//! application explicitly in `context.application`. The service's decision
//! is the answer. Anything else — the service's error, its refusal of this
//! PEP, an answer that is not a decision, no answer in
//! `PEP_AUTHZEN_FORWARD_TIMEOUT_MS` — is an ERROR to the caller (a status,
//! or a batch item's `context.error`), never `false` and never the root's
//! answer.

use regex::Regex;
use serde_json::{json, Map, Value};
use sts_core::log::tag;
use sts_xacml::model::{Decision, StatusCode};
use sts_xacml::pdp::{AttributeResolver, EvaluationOptions};
use sts_xacml::request::{Response, Status};

use crate::audit::{self, Record};
use crate::authzen_catalogue::BINDING_CONTEXT;
use crate::authzen_map::{self, Trusted};
use crate::enforce::Enforcer;
use crate::listener::Transport;
use crate::options::{AuthzenCaller, Bias, Options};
use crate::pdp_client::{Answer, Body, PdpClient};
use crate::service::Pep;
use crate::sync::{Callers, Catalogue};

pub const EVALUATION_PATH: &str = "/access/v1/evaluation";
pub const EVALUATIONS_PATH: &str = "/access/v1/evaluations";
pub const METADATA_PATH: &str = "/.well-known/authzen-configuration";

/// The Search APIs (#1175). The edge does not hold the directory or the
/// catalogues, so each POST is 501 and the metadata does not name them.
pub const SEARCH_SUBJECT_PATH: &str = "/access/v1/search/subject";
pub const SEARCH_RESOURCE_PATH: &str = "/access/v1/search/resource";
pub const SEARCH_ACTION_PATH: &str = "/access/v1/search/action";

/// The Access Request and Approval Profile (#1180). The edge does not hold
/// the approval store. These paths are 501; a POST to the item path
/// without `/cancel` stays 404, as does every method not listed.
pub const ACCESS_REQUESTS_PATH: &str = "/access/v1/access-requests";
// The path scan (`tests/model_pep.js`) reads a `*_PATH` literal only when
// it sits on the same line as `=`. The dispatch parses the item and cancel
// tails, so those two constants are for the scan.
pub const ACCESS_REQUEST_SCHEMA_PATH: &str = "/access/v1/access-requests/schema";
#[allow(dead_code)]
pub const ACCESS_REQUEST_PATH: &str = "/access/v1/access-requests/{id}";
#[allow(dead_code)]
pub const ACCESS_REQUEST_CANCEL_PATH: &str = "/access/v1/access-requests/{id}/cancel";

const SEARCH_MESSAGE: &str = "The Search APIs are answered by the service, \
    which holds the directory and the resource and action catalogues. This \
    edge PDP does not.";

const ACCESS_REQUEST_MESSAGE: &str = "The Access Request and Approval \
    Profile is answered by the service, which holds the approval store. \
    This edge PDP does not.";

/// The three batch semantics (section 7.1.2), the first the default.
pub const SEMANTICS: [&str; 3] = [
    "execute_all",
    "deny_on_first_deny",
    "permit_on_first_permit",
];

/// An answer the handler writes: status, body, and whether it is written
/// indented (the service writes its errors and its metadata indented and
/// its decisions compact).
#[derive(Debug, Clone, PartialEq)]
pub struct Reply {
    pub status: u16,
    pub body: Value,
    pub pretty: bool,
}

impl Reply {
    fn decision(body: Value) -> Reply {
        Reply {
            status: 200,
            body,
            pretty: false,
        }
    }

    /// `{ error: { status, message } }`, the shape `authzen_caller.ts`'s
    /// `send()` writes. The code is LOGGED, never sent.
    pub fn error(status: u16, code: &str, message: &str) -> Reply {
        tracing::info!(
            "{}xacml-pep: authzen: answered {}: {}",
            tag(code),
            status,
            message
        );
        Reply {
            status,
            body: json!({ "error": { "status": status,
                                     "message": message } }),
            pretty: true,
        }
    }
}

/// Whether a `Content-Type` value names `application/json`, with or without
/// parameters, compared case-insensitively (RFC 9110 section 8.3.1) —
/// `authzen.ts`'s `isJsonType()`. An absent header is not JSON: AuthZEN 1.0
/// section 10.1's MUST is to include it (#936).
pub fn is_json_type(value: Option<&str>) -> bool {
    value
        .and_then(|v| v.split(';').next())
        .map(|t| t.trim().eq_ignore_ascii_case("application/json"))
        .unwrap_or(false)
}

/// A caller this container admitted.
#[derive(Debug, Clone, PartialEq)]
pub struct Caller {
    pub name: String,
    pub applications: Vec<String>,
}

/// One evaluation's result.
#[derive(Debug, Clone, PartialEq)]
struct ItemResult {
    status: u16,
    decision: bool,
    context: Option<Value>,
    error: Option<(u16, String)>,
    code: &'static str,
}

impl ItemResult {
    fn failed(status: u16, code: &'static str, message: String) -> ItemResult {
        ItemResult {
            status,
            decision: false,
            context: None,
            error: Some((status, message)),
            code,
        }
    }
}

/// The `X-Request-ID` this PDP will echo: a printable token of at most
/// 128 characters, or none — a header value reflected is never arbitrary
/// text (section 10.1, and `authzen.ts`'s rule).
pub fn request_id(sent: Option<&str>) -> Option<String> {
    let sent = sent?;
    let ok = Regex::new(r"^[\x21-\x7e]{1,128}$")
        .map(|re| re.is_match(sent))
        .unwrap_or(false);
    ok.then(|| sent.to_string())
}

/// The name `PulledCaller.endpoints` gives an endpoint path.
pub fn endpoint_name(path: &str) -> &'static str {
    if path == EVALUATIONS_PATH {
        "evaluations"
    } else {
        "evaluation"
    }
}

/// The tail after `/access/v1/access-requests/`, when there is one. The
/// prefix is a variable so a path scan does not read it as `{name}`.
fn access_requests_tail(path: &str) -> Option<&str> {
    let prefix = "/access/v1/access-requests/";
    let tail = path.strip_prefix(prefix)?;
    if tail.is_empty() {
        return None;
    }
    Some(tail)
}

fn access_request_item(path: &str) -> bool {
    match access_requests_tail(path) {
        Some(tail) => tail != "schema" && !tail.contains('/'),
        None => false,
    }
}

fn access_request_cancel(path: &str) -> bool {
    let Some(tail) = access_requests_tail(path) else {
        return false;
    };
    let Some(id) = tail.strip_suffix("/cancel") else {
        return false;
    };
    !id.is_empty() && !id.contains('/')
}

fn search_path(path: &str) -> bool {
    path == SEARCH_SUBJECT_PATH
        || path == SEARCH_RESOURCE_PATH
        || path == SEARCH_ACTION_PATH
}

/// Which service-only path this method hits, if it hits one. `None` for
/// HEAD and for every method the profile does not answer, so those stay
/// the generic 404.
fn refusal_of(method: &str, path: &str) -> Option<(&'static str, &'static str)> {
    if method == "POST" && search_path(path) {
        return Some(("STS-XPEP-0138", SEARCH_MESSAGE));
    }
    let access_request = (method == "POST" && path == ACCESS_REQUESTS_PATH)
        || (method == "GET" && path == ACCESS_REQUEST_SCHEMA_PATH)
        || (method == "GET" && access_request_item(path))
        || ((method == "POST" || method == "DELETE")
            && access_request_cancel(path));
    if access_request {
        return Some(("STS-XPEP-0139", ACCESS_REQUEST_MESSAGE));
    }
    None
}

/// A 501 for a Search or Access Request path, after the caller has already
/// checked that the edge PDP is on. The body is the evaluation error
/// object. The code is logged here and never sent.
pub fn refused_here(method: &str, path: &str) -> Option<Reply> {
    let (code, message) = refusal_of(method, path)?;
    Some(Reply::error(501, code, message))
}

/// HEAD of a path that some other method answers 501. Those HEADs are not
/// rewritten to GET, so a monitor is not told the edge answers them.
pub fn head_is_absent(path: &str) -> bool {
    ["GET", "POST", "DELETE"]
        .iter()
        .any(|method| refusal_of(method, path).is_some())
}

fn entity_str<'a>(body: &'a Value, entity: &str, member: &str) -> &'a str {
    body.get(entity)
        .and_then(Value::as_object)
        .and_then(|object| object.get(member))
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// `issue:<token type>:<grant>`, each segment `[a-z][a-z0-9_]{0,20}`. Any
/// grant, including one this edge has never heard of: it does not hold the
/// grant registry, and a gate is still the service's.
fn is_gate_action(name: &str) -> bool {
    let mut parts = name.split(':');
    if parts.next() != Some("issue") {
        return false;
    }
    let Some(grant) = parts.next() else {
        return false;
    };
    let Some(kind) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    gate_segment(grant) && gate_segment(kind)
}

fn gate_segment(text: &str) -> bool {
    let mut chars = text.chars();
    if !matches!(chars.next(), Some(c) if c.is_ascii_lowercase()) {
        return false;
    }
    let mut rest = 0usize;
    for c in chars {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
            return false;
        }
        rest += 1;
        if rest > 20 {
            return false;
        }
    }
    true
}

/// An audience resource whose action is a gate.
pub(crate) fn is_gate(body: &Value) -> bool {
    entity_str(body, "resource", "type") == "audience"
        && is_gate_action(entity_str(body, "action", "name"))
}

fn has_binding_context(body: &Value) -> bool {
    let Some(context) = body.get("context").and_then(Value::as_object) else {
        return false;
    };
    BINDING_CONTEXT
        .iter()
        .any(|name| context.contains_key(*name))
}

/// Why this body is a token-exchange tuple, if it is. Order: a gate, then
/// a binding context member, then a scope beside a gate, then any other
/// non-audience resource type beside a gate. A lone scope or detail, and
/// an audience whose action is not a gate, are ordinary evaluations.
fn binding_why(body: &Value, beside_gate: bool) -> Option<&'static str> {
    if is_gate(body) {
        return Some("a gate");
    }
    if has_binding_context(body) {
        return Some("a context member");
    }
    if !beside_gate {
        return None;
    }
    let resource_type = entity_str(body, "resource", "type");
    if resource_type == "protected_resource" {
        return Some("a scope");
    }
    if !resource_type.is_empty() && resource_type != "audience" {
        return Some("a detail");
    }
    None
}

fn binding_message(body: &Value, beside_gate: bool) -> Option<String> {
    let why = binding_why(body, beside_gate)?;
    Some(format!(
        "The OAuth token-exchange binding is answered by the service, \
         which holds delegation and the directory. This edge PDP does not \
         answer its tuples ({}).",
        why
    ))
}

/// WHO IS ASKING, by the one door: a certificate presented on the HTTPS
/// listener, verified against `PEP_AUTHZEN_CLIENT_CA`, found by its SHA-256
/// on the caller list pulled from the service (#1189) and admitted there to
/// `endpoint` — narrowed, when `PEP_AUTHZEN_CALLERS` is set, to the
/// certificates it names. Before the first pull the local list decides
/// alone when it is set, and nothing is answered (503) when it is not.
/// Each refusal is the service's status for the same situation — 401 for a
/// caller that is nobody, 403 for one that may not ask — and, the door
/// being certificates alone, carries no `WWW-Authenticate` (there is no
/// HTTP scheme to name).
pub fn admit(
    options: &Options,
    verifies_certificates: bool,
    transport: &Transport,
    callers: &Callers,
    endpoint: &str,
) -> Result<Caller, Reply> {
    if !verifies_certificates {
        return Err(Reply::error(
            401,
            "STS-XPEP-0039",
            "This edge PDP authenticates its caller by a client certificate \
             (mutual TLS), and the listener this request arrived on asks \
             for none it can verify (no PEP_AUTHZEN_CLIENT_CA or trust \
             anchors, or its tuning asks for no certificate), so it admits \
             nobody here.",
        ));
    }
    let peer = match (&transport.peer, transport.https) {
        (Some(peer), true) => peer,
        _ => {
            return Err(Reply::error(
                401,
                "STS-XPEP-0035",
                "This edge PDP authenticates its caller by a client \
                 certificate (mutual TLS) on its HTTPS listener, and none \
                 was presented.",
            ))
        }
    };
    if !peer.verified {
        return Err(Reply::error(
            401,
            "STS-XPEP-0036",
            &format!(
                "The client certificate did not verify against this edge \
                 PDP's PEP_AUTHZEN_CLIENT_CA: {}",
                peer.why
            ),
        ));
    }
    let local: Option<&AuthzenCaller> = options
        .authzen_callers
        .iter()
        .find(|c| c.sha256 == peer.sha256);
    if !callers.loaded {
        if !options.authzen_callers_configured {
            return Err(Reply::error(
                503,
                "STS-XPEP-0050",
                "This edge PDP has not yet pulled from its PDP the callers \
                 the service admits to its AuthZEN API, and has no \
                 PEP_AUTHZEN_CALLERS to decide meanwhile.",
            ));
        }
        // BEFORE THE FIRST PULL, THE LOCAL LIST ALONE (#1179's door), so an
        // edge an operator configured keeps answering while its PDP is
        // unreachable or older than #1189.
        let Some(found) = local else {
            return Err(Reply::error(
                403,
                "STS-XPEP-0037",
                "The client certificate verified, and it is not one this \
                 edge PDP admits: PEP_AUTHZEN_CALLERS names the certificates \
                 that may ask, by the SHA-256 of each.",
            ));
        };
        return Ok(Caller {
            name: found.name.clone(),
            applications: found.applications.clone(),
        });
    }
    if callers.door != "mtls" {
        return Err(Reply::error(
            401,
            "STS-XPEP-0052",
            &format!(
                "The service's realm authenticates its AuthZEN callers by \
                 {} (authzen.callerAuthentication), which a certificate \
                 alone does not meet and this edge PDP cannot check, so it \
                 admits nobody.",
                if callers.door.is_empty() {
                    "an unnamed door"
                } else {
                    callers.door.as_str()
                }
            ),
        ));
    }
    let Some(pulled) = callers
        .callers
        .iter()
        .find(|c| c.sha256.contains(&peer.sha256))
    else {
        return Err(Reply::error(
            403,
            "STS-XPEP-0051",
            "The client certificate verified, and it is not one the service \
             admits to its AuthZEN API: no caller on the list this edge PDP \
             pulled presents it.",
        ));
    };
    if !pulled.endpoints.iter().any(|e| e == endpoint) {
        return Err(Reply::error(
            403,
            "STS-XPEP-0053",
            &format!(
                "The service's access-control policy does not admit this \
                 caller to /access/v1/{}.",
                endpoint
            ),
        ));
    }
    if options.authzen_callers_configured && local.is_none() {
        return Err(Reply::error(
            403,
            "STS-XPEP-0054",
            "The client certificate is one the service admits, and this \
             edge PDP's PEP_AUTHZEN_CALLERS, which narrows who may ask \
             here, does not name it.",
        ));
    }
    Ok(Caller {
        name: pulled.name.clone(),
        applications: pulled.applications.clone(),
    })
}

/// The application an evaluation is about: `context.application` if it
/// is in the caller's scope; the only one when there is one; refused
/// otherwise — `authzen_caller.ts`'s `applicationOf()`, codes and all.
pub fn application_of(
    caller: &Caller,
    asked: &str,
) -> Result<String, (u16, &'static str, String)> {
    let scope = &caller.applications;
    if !asked.is_empty() {
        if !scope.iter().any(|a| a == asked) {
            return Err((
                403,
                "STS-AUTHZEN-0025",
                format!(
                    "context.application \"{}\" is not one this caller may \
                     ask about.",
                    crate::authzen_catalogue::js_slice(asked, 120)
                ),
            ));
        }
        return Ok(asked.to_string());
    }
    match scope.len() {
        1 => Ok(scope[0].clone()),
        0 => Err((
            403,
            "STS-AUTHZEN-0026",
            "This caller is scoped to no application. An administrator \
             names the applications a caller may ask about on its entry."
                .to_string(),
        )),
        n => Err((
            400,
            "STS-AUTHZEN-0027",
            format!(
                "This caller may ask about {} applications, so the request \
                 must name one in context.application.",
                n
            ),
        )),
    }
}

/// One batch item's request: the top-level defaults, each overridden
/// WHOLE by the item's own member (section 7.1.1), and the item's other
/// members kept so the mapping refuses them for that item alone.
pub fn merged(defaults: &Map<String, Value>, item: &Value) -> Option<Value> {
    let given = item.as_object()?;
    let mut out = Map::new();
    for key in ["subject", "action", "resource", "context"] {
        if let Some(value) = given.get(key).or_else(|| defaults.get(key)) {
            out.insert(key.to_string(), value.clone());
        }
    }
    for (key, value) in given {
        if !out.contains_key(key) {
            out.insert(key.clone(), value.clone());
        }
    }
    Some(Value::Object(out))
}

/// The JSON a body carries, as `bodyOf()` reads it: the bytes as text,
/// parsed; anything that is not JSON is `null`, which the mapping refuses.
pub fn body_of(bytes: &[u8]) -> Value {
    serde_json::from_str(&String::from_utf8_lossy(bytes)).unwrap_or(Value::Null)
}

/// Whether an evaluation about `application` is the SERVICE'S to decide
/// (#564, P7): the application enforces fine-grained authorization, by the
/// catalogue pulled last. Asked after the application is resolved, so the
/// question is about the application the service would resolve too.
pub fn forwards(catalogue: &Catalogue, application: &str) -> bool {
    catalogue.fga_applications.iter().any(|a| a == application)
}

/// The body forwarded for one evaluation: the caller's request for it —
/// the batch item with the top-level defaults merged in, which is the
/// request the service would have read for that item — with
/// `context.application` set to the application resolved here. Set always,
/// even when the caller left it to the scope: the service scopes the
/// question by THIS PEP's scope there, which may name several applications.
/// The cost, stated in `xacml-pep/CLAUDE.md`: the service's
/// `urn:sts:xacml:authzen:supplied` bag names `context.application` though
/// the caller did not send it.
pub fn forwarded_body(body: &Value, application: &str) -> Value {
    let mut out = body.clone();
    if let Some(map) = out.as_object_mut() {
        let context = map
            .entry("context")
            .or_insert_with(|| Value::Object(Map::new()));
        if let Some(context) = context.as_object_mut() {
            context.insert("application".into(), json!(application));
        }
    }
    out
}

/// The service's message from an AuthZEN error body, or what to say
/// instead.
fn service_message(answer: &Answer) -> String {
    answer
        .json
        .as_ref()
        .and_then(|j| j["error"]["message"].as_str())
        .map(str::to_string)
        .unwrap_or_else(|| {
            format!("The service answered HTTP {}.", answer.status)
        })
}

/// What the service's answer to a forwarded evaluation is to the caller
/// (#564, P7). A decision is passed on, `context` and all. EVERYTHING ELSE
/// IS AN ERROR, never `false`:
///
/// * no answer: 504 when the time ran out, 502 otherwise (`STS-XPEP-0055`);
/// * 401 or 403: the service refused THIS PEP, which is the operator's to
///   mend and not the caller's — 502, saying what the PEP's entry needs
///   (`STS-XPEP-0056`);
/// * 400, 413, 500, 501, 503: the service's own status and message, which
///   are about the request or the application's policy
///   (`STS-XPEP-0057`; a 500 is `STS-AUTHZEN-0046`'s "the policy cannot be
///   used" there);
/// * any other status, or a 200 with no boolean `decision`: 502
///   (`STS-XPEP-0057`, `-0058`).
fn forwarded_result(
    answer: &Answer,
    application: &str,
    timeout_ms: u64,
) -> ItemResult {
    if let Some(why) = &answer.error {
        return if answer.timed_out {
            ItemResult::failed(
                504,
                "STS-XPEP-0055",
                format!(
                    "\"{}\" enforces fine-grained authorization, which only \
                     the service decides, and the service did not answer \
                     the forwarded evaluation within {} ms \
                     (PEP_AUTHZEN_FORWARD_TIMEOUT_MS).",
                    application, timeout_ms
                ),
            )
        } else {
            ItemResult::failed(
                502,
                "STS-XPEP-0055",
                format!(
                    "\"{}\" enforces fine-grained authorization, which only \
                     the service decides, and the service could not be \
                     reached: {}",
                    application, why
                ),
            )
        };
    }
    match answer.status {
        200 => {
            let decision = answer
                .json
                .as_ref()
                .and_then(|j| j.get("decision"))
                .and_then(Value::as_bool);
            let Some(decision) = decision else {
                return ItemResult::failed(
                    502,
                    "STS-XPEP-0058",
                    format!(
                        "The service answered the evaluation forwarded for \
                         \"{}\" with something that is not an AuthZEN \
                         decision.",
                        application
                    ),
                );
            };
            ItemResult {
                status: 200,
                decision,
                context: answer
                    .json
                    .as_ref()
                    .and_then(|j| j.get("context"))
                    .filter(|c| c.is_object())
                    .cloned(),
                error: None,
                code: "",
            }
        }
        401 | 403 => ItemResult::failed(
            502,
            "STS-XPEP-0056",
            format!(
                "\"{}\" enforces fine-grained authorization, which only the \
                 service decides, and the service refused this edge PDP \
                 when it forwarded the evaluation (HTTP {}): the remote \
                 PEP's own directory entry, the one its client certificate \
                 is stored on, must hold AUTHZEN_PEPS and have \"{}\" in \
                 its application scope (stsAuthzenApplication). The service \
                 said: {}",
                application,
                answer.status,
                application,
                service_message(answer)
            ),
        ),
        400 | 413 | 500 | 501 | 503 => ItemResult::failed(
            answer.status,
            "STS-XPEP-0057",
            service_message(answer),
        ),
        other => ItemResult::failed(
            502,
            "STS-XPEP-0057",
            format!(
                "\"{}\" enforces fine-grained authorization, which only the \
                 service decides, and the service answered HTTP {} to the \
                 forwarded evaluation.",
                application, other
            ),
        ),
    }
}

/// Forwards one evaluation to the service's `POST /access/v1/evaluation`
/// in the realm the PDP URL names, with `X-Request-ID` when there is one,
/// bounded by `timeout_ms`, and reads what came back. The body is never
/// logged: it carries the caller's property values.
async fn forward_to(
    client: &PdpClient,
    body: &Value,
    application: &str,
    request_id: &str,
    timeout_ms: u64,
) -> ItemResult {
    let mut headers: Vec<(&str, String)> =
        vec![("Content-Type", "application/json".to_string())];
    if let Some(id) = self::request_id(Some(request_id)) {
        headers.push(("X-Request-ID", id));
    }
    let answer = client
        .call_authorized_with(
            crate::credential::Resource::Access,
            reqwest::Method::POST,
            EVALUATION_PATH,
            Some(Body::Json(forwarded_body(body, application))),
            &headers,
            Some(std::time::Duration::from_millis(timeout_ms)),
        )
        .await;
    forwarded_result(&answer, application, timeout_ms)
}

impl Pep {
    /// Whether the edge PDP answers at all, before anything is read: this
    /// container's switch, a catalogue and a policy pull held, and the
    /// realm's own `authzen.enabled` (with the API's object).
    pub(crate) fn authzen_off(&self, catalogue: &Catalogue) -> Option<Reply> {
        if !self.options.now().authzen {
            return Some(Reply::error(
                501,
                "STS-XPEP-0044",
                "The AuthZEN API is turned off on this edge PDP \
                 (PEP_AUTHZEN).",
            ));
        }
        if !catalogue.loaded || !self.sync.ever_loaded() {
            return Some(Reply::error(
                503,
                "STS-XPEP-0043",
                "This edge PDP has not yet pulled the policies and the \
                 AuthZEN attribute catalogue from its PDP, so it cannot map \
                 a request as the service maps it.",
            ));
        }
        if !catalogue.settings.enabled {
            return Some(if catalogue.api_object {
                Reply::error(
                    501,
                    "STS-AUTHZEN-0013",
                    "The AuthZEN API is turned off in this realm \
                     (authzen.enabled, or xacml.enabled, whose engine it \
                     decides with).",
                )
            } else {
                Reply::error(
                    501,
                    "STS-AUTHZEN-0014",
                    "This realm has no sts-authzen-api application, the \
                     AuthZEN API's resource object, so the API is off here.",
                )
            });
        }
        None
    }

    /// The metadata (section 9), naming only what answers: the single
    /// endpoint, the batch one while the realm has it on, and
    /// `supported_obligations` while the realm's obligations profile is on.
    /// No search endpoint, no access-request endpoint, no `capabilities`,
    /// no `jwks_uri`, no `signed_metadata` — this edge holds no realm
    /// signing key, and republishing the service's JWT would name the
    /// wrong issuer.
    pub(crate) fn authzen_metadata(
        &self,
        transport: &Transport,
        host: Option<&str>,
    ) -> Reply {
        let catalogue = self.sync.catalogue();
        if let Some(off) = self.authzen_off(&catalogue) {
            return off;
        }
        let configured = &self.options.now().authzen_pdp_identifier;
        let host_ok =
            Regex::new(r"^([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(:\d+)?$")
                .ok()
                .zip(host)
                .is_some_and(|(re, h)| re.is_match(h));
        let base = if !configured.is_empty() {
            configured.clone()
        } else if transport.https && host_ok {
            format!("https://{}", host.unwrap_or_default())
        } else {
            return Reply::error(
                404,
                "STS-XPEP-0045",
                "This edge PDP names its identifier from the origin an HTTPS \
                 request arrives at, or from PEP_AUTHZEN_PDP_IDENTIFIER; ask \
                 over HTTPS, or set it.",
            );
        };
        let mut out = json!({
            "policy_decision_point": base,
            "access_evaluation_endpoint": format!("{}{}", base, EVALUATION_PATH)
        });
        if let Some(map) = out.as_object_mut() {
            if catalogue.settings.batch_enabled {
                map.insert(
                    "access_evaluations_endpoint".into(),
                    json!(format!("{}{}", base, EVALUATIONS_PATH)),
                );
            }
            if catalogue.settings.obligations_profile {
                let types = authzen_map::SUPPORTED_OBLIGATION_TYPES
                    .iter()
                    .map(|name| Value::String((*name).to_string()))
                    .collect();
                map.insert("supported_obligations".into(), Value::Array(types));
            }
        }
        Reply {
            status: 200,
            body: out,
            pretty: true,
        }
    }

    /// `POST /access/v1/evaluation` and `POST /access/v1/evaluations`, after
    /// the request id: the switches, the caller, the media type, the body,
    /// the answer.
    pub(crate) async fn authzen_post(
        &self,
        batch: bool,
        transport: &Transport,
        content_type: Option<&str>,
        body: Result<Vec<u8>, ()>,
        id: &str,
    ) -> Reply {
        let catalogue = self.sync.catalogue();
        if let Some(off) = self.authzen_off(&catalogue) {
            return off;
        }
        if batch && !catalogue.settings.batch_enabled {
            return Reply::error(
                501,
                "STS-AUTHZEN-0039",
                &format!(
                    "The batch endpoint is turned off in this realm \
                     (authzen.batchEnabled); {} still answers.",
                    EVALUATION_PATH
                ),
            );
        }
        let callers = self.sync.callers();
        // THE LISTENER THE REQUEST ARRIVED ON (#1830): an HTTPS listener
        // admits by a certificate only if ITS acceptor asked for one and
        // verifies it — the environment's listener's client CA says
        // nothing about a listener the service defined, or one whose tuning
        // asks for none. A plain-HTTP request has no certificate to ask
        // about, and is answered as it always was: by whether the
        // environment's HTTPS listener could admit it (0035), or not (0039).
        let verifies = if transport.https {
            transport.verifies_client_certificates
        } else {
            self.listener.verifies_client_certificates()
        };
        let caller = match admit(
            &self.options,
            verifies,
            transport,
            &callers,
            endpoint_name(if batch {
                EVALUATIONS_PATH
            } else {
                EVALUATION_PATH
            }),
        ) {
            Ok(caller) => caller,
            Err(refused) => return refused,
        };
        // SECTION 10.1: "Requests MUST include a Content-Type header with
        // the value application/json"; RFC 9110 section 15.5.16 says what
        // a server answers otherwise. After the caller is admitted, so a
        // stranger is told 401 first, and before the body is read — the
        // service's `notJson()`, with its code (#936). Until then this PDP
        // read a `text/plain` body as JSON and answered it.
        if !is_json_type(content_type) {
            return Reply::error(
                415,
                "STS-AUTHZEN-0117",
                "The request must carry Content-Type: application/json \
                 (AuthZEN 1.0 section 10.1).",
            );
        }
        if batch {
            return self.authzen_batch(&caller, &catalogue, body, id).await;
        }
        let Ok(bytes) = body else {
            return Reply::error(
                413,
                "STS-XPEP-0046",
                &format!(
                    "The request is larger than this edge PDP reads \
                     (PEP_MAX_BODY_BYTES, {} bytes).",
                    self.options.now().max_body_bytes
                ),
            );
        };
        let parsed = body_of(&bytes);
        let item = self
            .evaluate_one(
                &parsed,
                &caller,
                &catalogue,
                id,
                EVALUATION_PATH,
                is_gate(&parsed),
            )
            .await;
        reply_of(item)
    }

    /// One batch (section 7): its bounds, its semantic, each item decided in
    /// order and answered in order — `authzen.ts`'s `batch()`.
    async fn authzen_batch(
        &self,
        caller: &Caller,
        catalogue: &Catalogue,
        body: Result<Vec<u8>, ()>,
        id: &str,
    ) -> Reply {
        let settings = &catalogue.settings;
        let too_large = Reply::error(
            400,
            "STS-AUTHZEN-0037",
            &format!(
                "The request is larger than this realm's \
                 authzen.maxBodyBytes ({} bytes).",
                settings.max_body_bytes
            ),
        );
        let bytes = match body {
            Ok(bytes) if bytes.len() <= settings.max_body_bytes => bytes,
            _ => return too_large,
        };
        let parsed = body_of(&bytes);
        let Some(given) = parsed.as_object() else {
            return Reply::error(
                400,
                "STS-AUTHZEN-0001",
                "An access evaluations request is a JSON object.",
            );
        };
        // A member AuthZEN 1.0 does not define is ignored (section 10.1.1;
        // #936). It was refused with STS-AUTHZEN-0009, which is retired.
        let items = match given.get("evaluations") {
            None => Vec::new(),
            Some(Value::Array(items)) => items.clone(),
            Some(_) => {
                return Reply::error(
                    400,
                    "STS-AUTHZEN-0003",
                    "evaluations must be an array.",
                )
            }
        };
        let semantic = match given.get("options") {
            None => SEMANTICS[0].to_string(),
            Some(Value::Object(options)) => {
                match options.get("evaluations_semantic") {
                    None => SEMANTICS[0].to_string(),
                    Some(Value::String(s)) => s.clone(),
                    Some(other) => other.to_string(),
                }
            }
            Some(_) => {
                return Reply::error(
                    400,
                    "STS-AUTHZEN-0003",
                    "options must be a JSON object.",
                )
            }
        };
        if !SEMANTICS.contains(&semantic.as_str()) {
            return Reply::error(
                400,
                "STS-AUTHZEN-0036",
                &format!(
                    "options.evaluations_semantic must be one of {}.",
                    SEMANTICS.join(", ")
                ),
            );
        }
        if items.len() > settings.max_evaluations {
            return Reply::error(
                400,
                "STS-AUTHZEN-0038",
                &format!(
                    "The request carries {} evaluations, and this realm \
                     answers at most {} in one (authzen.maxEvaluations).",
                    items.len(),
                    settings.max_evaluations
                ),
            );
        }
        // NO ITEMS IS ONE EVALUATION, answered as the single endpoint would.
        if items.is_empty() {
            let single = merged(given, &json!({})).unwrap_or(Value::Null);
            let one = self
                .evaluate_one(
                    &single,
                    caller,
                    catalogue,
                    id,
                    EVALUATIONS_PATH,
                    is_gate(&single),
                )
                .await;
            return reply_of(one);
        }
        // THE BATCH ID ON EVERY RECORD: the caller's, or one made here, so
        // the lines of one batch are found together (decision 9).
        let batch_id = if id.is_empty() {
            let mut bytes = [0u8; 9];
            let made = openssl::rand::rand_bytes(&mut bytes).is_ok();
            format!(
                "authzen-{}",
                if made {
                    bytes.iter().map(|b| format!("{:02x}", b)).collect()
                } else {
                    sts_core::time::iso_now()
                }
            )
        } else {
            id.to_string()
        };
        // A gate anywhere in the batch makes every item stand beside one,
        // classified on the merged item, as the service classifies.
        let prepared: Vec<Option<Value>> = items
            .iter()
            .map(|item| merged(given, item))
            .collect();
        let beside_gate = prepared
            .iter()
            .any(|item| item.as_ref().is_some_and(is_gate));
        let mut out = Vec::new();
        for (i, request) in prepared.into_iter().enumerate() {
            let one = match request {
                None => ItemResult::failed(
                    400,
                    "STS-AUTHZEN-0001",
                    "An evaluation is a JSON object.".to_string(),
                ),
                Some(request) => {
                    self.evaluate_one(
                        &request,
                        caller,
                        catalogue,
                        &format!("{}#{}", batch_id, i),
                        EVALUATIONS_PATH,
                        beside_gate,
                    )
                    .await
                }
            };
            // AN ITEM'S FAILURE IS ITS OWN, in its own context.error, and
            // still false — the fail-closed reading of an undecided item.
            match &one.error {
                Some((status, message)) => out.push(json!({
                    "decision": false,
                    "context": { "error": { "status": status,
                                            "message": message } }
                })),
                None => out.push(answer_of(one.decision, one.context.clone())),
            }
            let denied = one.error.is_some() || !one.decision;
            if (semantic == "deny_on_first_deny" && denied)
                || (semantic == "permit_on_first_permit"
                    && one.error.is_none()
                    && one.decision)
            {
                break;
            }
        }
        Reply::decision(json!({ "evaluations": out }))
    }

    /// Decides one evaluation for an admitted caller, and records it — a
    /// log line, and (unless it was FORWARDED, which the service recorded
    /// itself) a decision record sent to the service's audit log (#1827).
    async fn evaluate_one(
        &self,
        body: &Value,
        caller: &Caller,
        catalogue: &Catalogue,
        batch_id: &str,
        endpoint: &str,
        beside_gate: bool,
    ) -> ItemResult {
        // BEFORE THE READ (#1181, #1205). A binding tuple is the service's:
        // this edge holds neither delegation nor the directory. Logged
        // here, and the single-response path does not log it again.
        // `may_act` with no catalogue row is still 0004 when this is not a
        // binding tuple — the shared table's V30.
        if let Some(message) = binding_message(body, beside_gate) {
            tracing::info!(
                "{}xacml-pep: authzen: {}",
                tag("STS-XPEP-0140"),
                message
            );
            return ItemResult::failed(501, "STS-XPEP-0140", message);
        }
        let evaluation = match authzen_map::read(body, &catalogue.rows) {
            Ok(evaluation) => evaluation,
            Err(refusal) => {
                return ItemResult::failed(
                    refusal.status,
                    refusal.code,
                    refusal.message,
                )
            }
        };
        let application = match application_of(caller, &evaluation.application)
        {
            Ok(application) => application,
            Err((status, code, message)) => {
                return ItemResult::failed(status, code, message)
            }
        };
        // THE SERVICE'S TO DECIDE (#564, P7): forwarded, never answered
        // from the root, and counted and logged here like any other — but
        // NOT queued for the service's audit log (#1827): the service
        // decided it and wrote its own row under the same request id.
        if forwards(catalogue, &application) {
            let timeout = self.options.now().authzen_forward_timeout_ms;
            let one = forward_to(
                self.sync.client(),
                body,
                &application,
                batch_id,
                timeout,
            )
            .await;
            self.sync.count_forwarded();
            self.sync
                .count_authzen(one.error.is_none().then_some(one.decision));
            let line = format!(
                "xacml-pep: authzen: {} forwarded to the service, for a {} to \
                 {} a {}, caller \"{}\", application \"{}\" (it enforces \
                 fine-grained authorization){}",
                endpoint,
                evaluation.subject_type,
                evaluation.action_name,
                evaluation.resource_type,
                caller.name,
                application,
                if batch_id.is_empty() {
                    String::new()
                } else {
                    format!(", request {}", batch_id)
                }
            );
            match &one.error {
                None => tracing::info!(
                    "{}; the service decided {}.",
                    line,
                    one.decision
                ),
                Some((status, message)) => tracing::warn!(
                    "{}{}; an error, {}: {}",
                    tag(one.code),
                    line,
                    status,
                    message
                ),
            }
            return one;
        }
        let request = authzen_map::request(
            &evaluation,
            &Trusted {
                realm: &catalogue.realm,
                caller: &caller.name,
                application: &application,
            },
        );
        let (policies, _) = self.sync.current();
        let answer = match (&policies.root, policies.root_refused) {
            (_, true) => Response {
                decision: Decision::Indeterminate,
                status: Status {
                    code: StatusCode::SyntaxError,
                    message: Some(
                        "The root policy the PDP sent would not load here."
                            .to_string(),
                    ),
                },
                obligations: Vec::new(),
                advice: Vec::new(),
                policy_identifiers: Vec::new(),
            },
            (None, false) => Response {
                decision: Decision::NotApplicable,
                status: Status::ok(),
                obligations: Vec::new(),
                advice: Vec::new(),
                policy_identifiers: Vec::new(),
            },
            (Some(root), false) => {
                // THE PIP ONLY FOR A SUBJECT TYPE THE REALM RESOLVES
                // (authzen.resolveSubjectTypes): another type's id that
                // happens to match a person's name is not that person.
                let resolves = catalogue
                    .settings
                    .resolve_subject_types
                    .contains(&evaluation.subject_type);
                let resolution = if resolves {
                    Some(
                        self.pip
                            .resolver_for(&request, root, &policies.repository)
                            .await,
                    )
                } else {
                    None
                };
                let options = EvaluationOptions {
                    resolver: resolution
                        .as_ref()
                        .and_then(|r| r.resolver.as_ref())
                        .map(|r| r as &dyn AttributeResolver),
                    repository: Some(&policies.repository),
                    now: None,
                };
                self.pdp.evaluate(root, &request, &options)
            }
        };
        let enforcement = Enforcer::new(Bias::DenyBiased)
            .enforce(answer.decision, &answer.obligations);
        // The profile off, or no declaration, hands nothing: a realm that
        // turned obligations off must not be wider at the edge.
        let declared = if catalogue.settings.obligations_profile {
            evaluation.supported_obligations.as_deref()
        } else {
            None
        };
        let outcome = authzen_map::outcome(
            &answer,
            &enforcement,
            policies.root_refused,
            declared,
        );
        self.sync
            .count_authzen((!outcome.fault).then_some(outcome.decision));
        // THE RECORD: who asked, about which application, the two types and
        // the action, the request id, the decision — never a property value,
        // an id the caller sent, or a credential (decision 9 on #563).
        // A presented approval is not a refusal of the decision: the
        // service still decides, and so does this edge, without using it.
        let code = if outcome.fault {
            "STS-AUTHZEN-0028"
        } else if !outcome.obligation_problems.is_empty() {
            "STS-AUTHZEN-0041"
        } else if !outcome.undischargeable.is_empty() {
            "STS-AUTHZEN-0029"
        } else if evaluation.approval_present {
            "STS-AUTHZEN-0084"
        } else {
            ""
        };
        let line = format!(
            "xacml-pep: authzen: {} decided {} for a {} to {} a {}, caller \
             \"{}\", application \"{}\"{}{}{}{}{}{}.",
            endpoint,
            if outcome.fault {
                "nothing (a fault)".to_string()
            } else {
                format!(
                    "{} (XACML {})",
                    outcome.decision, outcome.xacml_decision
                )
            },
            evaluation.subject_type,
            evaluation.action_name,
            evaluation.resource_type,
            caller.name,
            application,
            if batch_id.is_empty() {
                String::new()
            } else {
                format!(", request {}", batch_id)
            },
            if outcome.discharged.is_empty() {
                String::new()
            } else {
                format!("; discharged {}", outcome.discharged.join(", "))
            },
            if outcome.undischargeable.is_empty() {
                String::new()
            } else {
                format!(
                    "; refused for the obligation {}",
                    outcome.undischargeable.join(", ")
                )
            },
            if outcome.obligations.is_empty() {
                String::new()
            } else {
                let types = outcome
                    .obligations
                    .iter()
                    .filter_map(|one| one.get("type").and_then(Value::as_str))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("; handed {}", types)
            },
            if outcome.obligation_problems.is_empty() {
                String::new()
            } else {
                format!(
                    "; obligation problems: {}",
                    outcome.obligation_problems.join("; ")
                )
            },
            if evaluation.approval_present {
                "; an approval was presented and not used"
            } else {
                ""
            }
        );
        // THE RECORD FOR THE SERVICE carries what the line carries and
        // nothing more: the subject is "" because its id is the caller's.
        self.audit.record(Record {
            at: sts_core::time::iso_now(),
            kind: "authzen".into(),
            decision: if outcome.fault {
                String::new()
            } else {
                outcome.xacml_decision.clone()
            },
            allowed: outcome.decision,
            fault: outcome.fault,
            code: code.to_string(),
            resource: evaluation.resource_type.clone(),
            action: evaluation.action_name.clone(),
            bias: Bias::DenyBiased.as_str().to_string(),
            why: if outcome.fault {
                outcome.why.clone()
            } else {
                String::new()
            },
            policies: answer
                .policy_identifiers
                .iter()
                .map(|p| audit::policy_name(&p.id, &p.version))
                .collect(),
            discharged: outcome.discharged.clone(),
            undischargeable: outcome.undischargeable.clone(),
            caller: caller.name.clone(),
            application: application.clone(),
            subject_type: evaluation.subject_type.clone(),
            endpoint: endpoint.to_string(),
            request_id: batch_id.to_string(),
            ..Record::default()
        });
        if outcome.fault {
            tracing::error!("{}{} {}", tag(code), line, outcome.why);
            return ItemResult::failed(
                500,
                "STS-AUTHZEN-0028",
                "The PDP could not evaluate the request.".to_string(),
            );
        }
        if code.is_empty() {
            tracing::info!("{}", line);
        } else {
            tracing::info!("{}{}", tag(code), line);
        }
        let mut context = if catalogue.settings.return_reasons {
            Some(authzen_map::reasons(&outcome))
        } else {
            None
        };
        // Obligations travel even when reasons are off. When both are
        // present they share the one context object.
        if !outcome.obligations.is_empty() {
            let mut map = context
                .as_ref()
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            map.insert(
                "obligations".into(),
                Value::Array(outcome.obligations.clone()),
            );
            context = Some(Value::Object(map));
        }
        ItemResult {
            status: 200,
            decision: outcome.decision,
            context,
            error: None,
            code: "",
        }
    }
}

/// A single evaluation's reply. A binding 501 was already logged in
/// `evaluate_one`; every other error is logged here.
fn reply_of(item: ItemResult) -> Reply {
    match item.error {
        Some((status, message)) if item.code == "STS-XPEP-0140" => Reply {
            status,
            body: json!({ "error": { "status": status,
                                     "message": message } }),
            pretty: true,
        },
        Some((status, message)) => Reply::error(status, item.code, &message),
        None => Reply::decision(answer_of(item.decision, item.context)),
    }
}

/// `{ decision }`, or `{ decision, context }`.
fn answer_of(decision: bool, context: Option<Value>) -> Value {
    match context {
        Some(context) => json!({ "decision": decision, "context": context }),
        None => json!({ "decision": decision }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listener::Peer;

    fn options_with(callers: Vec<AuthzenCaller>) -> Options {
        let mut options = Options::from_env("0.0.0");
        options.authzen_callers = callers;
        options.authzen_callers_configured = false;
        options
    }

    fn peer(sha256: &str, verified: bool) -> Transport {
        Transport {
            https: true,
            remote: None,
            crl_only: false,
            verifies_client_certificates: true,
            peer: Some(Peer {
                sha256: sha256.to_string(),
                subject: "CN=pep".into(),
                verified,
                why: if verified {
                    String::new()
                } else {
                    "nope".into()
                },
            }),
        }
    }

    fn pulled(door: &str, fp: &str, endpoints: &[&str]) -> Callers {
        Callers {
            loaded: true,
            door: door.into(),
            callers: std::sync::Arc::new(vec![crate::sync::PulledCaller {
                name: "uid=azpep,ou=users,dc=example".into(),
                sha256: vec![fp.to_string()],
                applications: vec!["todo-app".into()],
                endpoints: endpoints.iter().map(|e| e.to_string()).collect(),
            }]),
            ..Callers::default()
        }
    }

    fn code(r: Result<Caller, Reply>) -> Option<(u16, String)> {
        r.err().map(|e| {
            let message = e.body["error"]["message"]
                .as_str()
                .unwrap_or("")
                .to_string();
            (e.status, message)
        })
    }

    /// The door before the pull, and the transport: no client CA admits
    /// nobody; plain HTTP or no certificate is 401; one that did not verify
    /// is 401; with no list pulled and none configured, 503; with only the
    /// local list, #1179's door — on it is the caller it names, off it 403.
    #[test]
    fn admits_by_certificate_alone() {
        let fp = "ab".repeat(32);
        let none = Callers::default();
        let mut options = options_with(vec![AuthzenCaller {
            name: "cn=pep-a".into(),
            sha256: fp.clone(),
            applications: vec!["todo-app".into()],
        }]);
        options.authzen_callers_configured = true;
        let e = "evaluation";
        let status = |r: Result<Caller, Reply>| r.err().map(|e| e.status);
        assert_eq!(
            status(admit(&options, false, &peer(&fp, true), &none, e)),
            Some(401)
        );
        assert_eq!(
            status(admit(&options, true, &Transport::default(), &none, e)),
            Some(401)
        );
        let mut plain = peer(&fp, true);
        plain.https = false;
        assert_eq!(status(admit(&options, true, &plain, &none, e)), Some(401));
        assert_eq!(
            status(admit(&options, true, &peer(&fp, false), &none, e)),
            Some(401)
        );
        let other = "cd".repeat(32);
        assert_eq!(
            status(admit(&options, true, &peer(&other, true), &none, e)),
            Some(403)
        );
        let caller = admit(&options, true, &peer(&fp, true), &none, e).unwrap();
        assert_eq!(caller.name, "cn=pep-a");
        let refused =
            admit(&options, true, &Transport::default(), &none, e).unwrap_err();
        assert!(refused.body["error"]["message"].is_string());
        assert!(refused.body.get("code").is_none(), "a code is never sent");
        let bare = options_with(Vec::new());
        assert_eq!(
            status(admit(&bare, true, &peer(&fp, true), &none, e)),
            Some(503),
            "nothing pulled and nothing configured answers nothing"
        );
    }

    /// The door once the list is pulled (#1189): the pulled caller's name
    /// and scope, whatever the local list says of it; a certificate the
    /// list does not name 403; an endpoint the policy does not admit the
    /// caller to 403; a realm whose door is a token 401; and a local list,
    /// when set, narrowing the pulled one.
    #[test]
    fn admits_by_the_pulled_list() {
        let fp = "ab".repeat(32);
        let other = "cd".repeat(32);
        let both = ["evaluation", "evaluations"];
        let list = pulled("mtls", &fp, &both);
        let open = options_with(Vec::new());
        let caller =
            admit(&open, true, &peer(&fp, true), &list, "evaluation").unwrap();
        assert_eq!(caller.name, "uid=azpep,ou=users,dc=example");
        assert_eq!(caller.applications, ["todo-app"]);
        assert_eq!(
            code(admit(&open, true, &peer(&other, true), &list, "evaluation"))
                .map(|c| c.0),
            Some(403)
        );
        let single = pulled("mtls", &fp, &["evaluation"]);
        assert!(
            admit(&open, true, &peer(&fp, true), &single, "evaluation").is_ok()
        );
        let batch =
            code(admit(&open, true, &peer(&fp, true), &single, "evaluations"))
                .unwrap();
        assert_eq!(batch.0, 403);
        assert!(batch.1.contains("/access/v1/evaluations"));
        let token = code(admit(
            &open,
            true,
            &peer(&fp, true),
            &pulled("bearer", &fp, &both),
            "evaluation",
        ))
        .unwrap();
        assert_eq!(token.0, 401);
        assert!(token.1.contains("bearer"));
        // THE NARROWING: a local entry for another certificate leaves this
        // one out; one for this certificate lets the PULLED caller through,
        // under the pulled name and scope.
        let mut narrow = options_with(vec![AuthzenCaller {
            name: "local-name".into(),
            sha256: other.clone(),
            applications: vec!["wiki".into()],
        }]);
        narrow.authzen_callers_configured = true;
        assert_eq!(
            code(admit(&narrow, true, &peer(&fp, true), &list, "evaluation"))
                .map(|c| c.0),
            Some(403)
        );
        narrow.authzen_callers[0].sha256 = fp.clone();
        let through =
            admit(&narrow, true, &peer(&fp, true), &list, "evaluation")
                .unwrap();
        assert_eq!(through.name, "uid=azpep,ou=users,dc=example");
        assert_eq!(through.applications, ["todo-app"]);
        // SET AND EMPTY NARROWS TO NOBODY: a configured list that admits
        // nobody is not read as "not set".
        let mut empty = options_with(Vec::new());
        empty.authzen_callers_configured = true;
        assert_eq!(
            code(admit(&empty, true, &peer(&fp, true), &list, "evaluation"))
                .map(|c| c.0),
            Some(403)
        );
        assert_eq!(endpoint_name(EVALUATIONS_PATH), "evaluations");
        assert_eq!(endpoint_name(EVALUATION_PATH), "evaluation");
    }

    /// The scope, as `applicationOf()` answers it.
    #[test]
    fn scopes_as_the_service_does() {
        let caller = |apps: &[&str]| Caller {
            name: "c".into(),
            applications: apps.iter().map(|a| a.to_string()).collect(),
        };
        let code = |r: Result<String, (u16, &'static str, String)>| {
            r.map_err(|(s, c, _)| (s, c))
        };
        assert_eq!(
            code(application_of(&caller(&["a", "b"]), "a")),
            Ok("a".to_string())
        );
        assert_eq!(
            code(application_of(&caller(&["a"]), "z")),
            Err((403, "STS-AUTHZEN-0025"))
        );
        assert_eq!(
            code(application_of(&caller(&["a"]), "")),
            Ok("a".to_string())
        );
        assert_eq!(
            code(application_of(&caller(&[]), "")),
            Err((403, "STS-AUTHZEN-0026"))
        );
        assert_eq!(
            code(application_of(&caller(&["a", "b"]), "")),
            Err((400, "STS-AUTHZEN-0027"))
        );
    }

    #[test]
    fn reads_only_application_json_as_json() {
        assert!(is_json_type(Some("application/json")));
        assert!(is_json_type(Some("Application/JSON; charset=utf-8")));
        assert!(is_json_type(Some(" application/json ;charset=UTF-8")));
        assert!(!is_json_type(Some("text/plain")));
        assert!(!is_json_type(Some("application/json-patch+json")));
        assert!(!is_json_type(Some("")));
        assert!(!is_json_type(None));
    }

    #[test]
    fn merges_an_item_over_the_defaults_whole() {
        let defaults = json!({ "subject": { "type": "user", "id": "a" },
                               "resource": { "type": "doc", "id": "1",
                                             "properties": { "x": 1 } },
                               "evaluations": [] });
        let item = json!({ "action": { "name": "read" },
                           "resource": { "type": "doc", "id": "2" },
                           "extra": true });
        let out = merged(defaults.as_object().unwrap(), &item).unwrap();
        assert_eq!(out["subject"]["id"], "a");
        assert_eq!(out["resource"]["id"], "2");
        assert!(
            out["resource"].get("properties").is_none(),
            "replaced whole"
        );
        assert_eq!(out["extra"], true);
        assert!(out.get("evaluations").is_none());
        assert!(merged(defaults.as_object().unwrap(), &json!([1])).is_none());
    }

    /// Classification (#564, P7): an application on the pulled
    /// `fgaApplications` is forwarded, another is not, and nothing is
    /// forwarded by a catalogue that names none.
    #[test]
    fn forwards_only_an_enforcing_application() {
        let mut catalogue = Catalogue::default();
        assert!(!forwards(&catalogue, "todo-app"));
        catalogue.fga_applications =
            std::sync::Arc::new(vec!["payments".to_string()]);
        assert!(forwards(&catalogue, "payments"));
        assert!(!forwards(&catalogue, "todo-app"));
        assert!(!forwards(&catalogue, "Payments"), "identifiers are exact");
    }

    /// The forwarded body is the caller's, with `context.application` set
    /// whether or not the caller named it, and every other member kept.
    #[test]
    fn forwards_the_callers_body_with_the_application_named() {
        let bare = json!({ "subject": { "type": "user", "id": "a" },
                           "action": { "name": "read" },
                           "resource": { "type": "doc", "id": "1",
                                         "properties": { "x": 1 } } });
        let out = forwarded_body(&bare, "payments");
        assert_eq!(out["context"]["application"], "payments");
        assert_eq!(out["resource"]["properties"]["x"], 1);
        let named = json!({ "subject": { "type": "user", "id": "a" },
                            "context": { "application": "payments",
                                         "region": "eu" } });
        let out = forwarded_body(&named, "payments");
        assert_eq!(out["context"]["application"], "payments");
        assert_eq!(out["context"]["region"], "eu");
    }

    /// THE WIRE IS THE MODEL'S (#1830): every request the shared cases say
    /// this edge accepts reads as `models/pep/pep_authzen.tsp`'s
    /// `EvaluationRequest`, and the decision, a batch's failed item and an
    /// error, as this file builds them, read as its answers.
    #[test]
    fn the_wire_is_the_model_s() {
        use crate::authzen_map::{outcome, reasons};
        use crate::enforce::Enforcer;
        use crate::options::Bias;
        use sts_model_pep::pep_authzen::{components, read_answer, read_body};
        use sts_xacml::request::{Response, Status};
        let cases = crate::authzen_map::tests::shared_cases();
        let mut accepted = 0;
        for case in cases["requests"].as_array().unwrap() {
            if case["code"] != "" {
                continue;
            }
            accepted += 1;
            let read = read_body("postEvaluation", &case["body"]);
            assert!(
                matches!(read, Some(Ok(()))),
                "{}: {:?}",
                case["what"],
                read
            );
        }
        assert!(accepted > 0, "the shared cases accept some requests");
        let answer = Response {
            decision: Decision::Permit,
            status: Status {
                code: sts_xacml::model::StatusCode::Ok,
                message: None,
            },
            obligations: Vec::new(),
            advice: Vec::new(),
            policy_identifiers: Vec::new(),
        };
        let enforced = Enforcer::new(Bias::DenyBiased)
            .enforce(answer.decision, &answer.obligations);
        let decided = outcome(&answer, &enforced, false, None);
        for body in [
            answer_of(decided.decision, None),
            answer_of(decided.decision, Some(reasons(&decided))),
        ] {
            let read = read_answer("postEvaluation", 200, &body);
            assert!(matches!(read, Some(Ok(()))), "{}: {:?}", body, read);
        }
        let failed = Reply::error(400, "STS-AUTHZEN-0001", "not an object");
        let batch = json!({ "evaluations": [
            answer_of(true, Some(reasons(&decided))),
            { "decision": false, "context": { "error": failed.body["error"] } }
        ] });
        let read = read_answer("postEvaluations", 200, &batch);
        assert!(matches!(read, Some(Ok(()))), "{}: {:?}", batch, read);
        let error: Result<components::Error, _> =
            serde_json::from_value(failed.body.clone());
        assert!(error.is_ok(), "{}", failed.body);
    }

    fn answered(status: u16, body: Value) -> Answer {
        Answer {
            status,
            text: body.to_string(),
            json: Some(body),
            error: None,
            timed_out: false,
            ..Answer::default()
        }
    }

    /// What the service answered, to the caller: a decision passed on with
    /// its context; every failure an error with its own status and code —
    /// never `false`.
    #[test]
    fn maps_the_services_answer_and_never_reads_a_failure_as_false() {
        let yes = forwarded_result(
            &answered(
                200,
                json!({ "decision": true,
                                   "context": { "reason": "r" } }),
            ),
            "payments",
            5000,
        );
        assert_eq!(
            (yes.status, yes.decision, yes.error.is_none()),
            (200, true, true)
        );
        assert_eq!(yes.context, Some(json!({ "reason": "r" })));
        let no = forwarded_result(
            &answered(200, json!({ "decision": false })),
            "payments",
            5000,
        );
        assert_eq!(
            (no.status, no.decision, no.context.is_none()),
            (200, false, true)
        );
        let cases: Vec<(Answer, u16, &str)> = vec![
            (
                answered(
                    500,
                    json!({ "error": { "status": 500,
                    "message": "The application's policy cannot be used." } }),
                ),
                500,
                "STS-XPEP-0057",
            ),
            (
                answered(
                    400,
                    json!({ "error": { "status": 400,
                    "message": "bad" } }),
                ),
                400,
                "STS-XPEP-0057",
            ),
            (
                answered(
                    403,
                    json!({ "error": { "status": 403,
                    "message": "not admitted" } }),
                ),
                502,
                "STS-XPEP-0056",
            ),
            (answered(401, json!({})), 502, "STS-XPEP-0056"),
            (answered(404, json!({})), 502, "STS-XPEP-0057"),
            (
                answered(200, json!({ "decision": "yes" })),
                502,
                "STS-XPEP-0058",
            ),
            (
                Answer {
                    error: Some("connection refused".into()),
                    ..Answer::default()
                },
                502,
                "STS-XPEP-0055",
            ),
            (
                Answer {
                    error: Some("late".into()),
                    timed_out: true,
                    ..Answer::default()
                },
                504,
                "STS-XPEP-0055",
            ),
        ];
        for (answer, status, code) in cases {
            let one = forwarded_result(&answer, "payments", 5000);
            assert_eq!(one.status, status, "{:?}", answer.json);
            assert_eq!(one.code, code, "{:?}", answer.json);
            assert!(one.error.is_some() && !one.decision);
        }
        let refused =
            forwarded_result(&answered(403, json!({})), "payments", 5000);
        let message = refused.error.unwrap().1;
        assert!(message.contains("AUTHZEN_PEPS"), "{}", message);
        assert!(message.contains("stsAuthzenApplication"), "{}", message);
        let passed = forwarded_result(
            &answered(
                500,
                json!({ "error": { "status": 500,
                "message": "The application's policy cannot be used." } }),
            ),
            "payments",
            5000,
        );
        assert_eq!(
            passed.error.unwrap().1,
            "The application's policy cannot be used."
        );
    }

    /// THE FORWARD OVER A REAL SOCKET (#564, P7), against a mock service on
    /// a loopback port standing in for the realm's AuthZEN endpoint: the
    /// realm's path is the PDP URL's, the body arrives with
    /// `context.application` and the caller's members, `X-Request-ID`
    /// travels, the service's decision comes back, its 500 and its refusal
    /// of the PEP are errors, a slow service is a 504 within the bound, and
    /// nobody listening is a 502.
    #[tokio::test]
    async fn forwards_to_the_realms_evaluation_endpoint() {
        use axum::extract::Json;
        use axum::http::{HeaderMap, StatusCode};
        use axum::routing::post;
        use std::sync::{Arc, Mutex};

        let seen: Arc<Mutex<Vec<(Value, String)>>> =
            Arc::new(Mutex::new(Vec::new()));
        let kept = seen.clone();
        let handler = move |headers: HeaderMap, Json(body): Json<Value>| {
            let kept = kept.clone();
            async move {
                let id = headers
                    .get("x-request-id")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                kept.lock().unwrap().push((body.clone(), id));
                match body["action"]["name"].as_str().unwrap_or("") {
                    "read" => {
                        (StatusCode::OK, Json(json!({ "decision": true })))
                    }
                    "write" => {
                        (StatusCode::OK, Json(json!({ "decision": false })))
                    }
                    "refused" => (
                        StatusCode::FORBIDDEN,
                        Json(json!({ "error": { "status": 403,
                            "message": "no" } })),
                    ),
                    "slow" => {
                        tokio::time::sleep(std::time::Duration::from_millis(
                            1500,
                        ))
                        .await;
                        (StatusCode::OK, Json(json!({ "decision": true })))
                    }
                    _ => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": { "status": 500,
                            "message": "unusable" } })),
                    ),
                }
            }
        };
        let router = axum::Router::new()
            .route("/realm/r1/access/v1/evaluation", post(handler));
        let socket =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        tokio::spawn(async move {
            // The mock lives as long as the test; a failure to serve shows
            // up as every forward below failing, so it is only reported.
            if let Err(error) = axum::serve(socket, router).await {
                eprintln!("the mock service stopped: {}", error);
            }
        });
        let mut options = Options::from_env("0.0.0");
        options.pdp_url = format!("http://127.0.0.1:{}/realm/r1", port);
        let client = PdpClient::new(&options).unwrap();
        let ask = |action: &str| {
            json!({ "subject": { "type": "user", "id": "alice" },
                    "action": { "name": action },
                    "resource": { "type": "payment", "id": "p1",
                                  "properties": { "amount": 10 } } })
        };

        let one =
            forward_to(&client, &ask("read"), "payments", "az-1#0", 1000).await;
        assert_eq!(
            (one.status, one.decision, one.error.is_none()),
            (200, true, true)
        );
        {
            let seen = seen.lock().unwrap();
            let (body, id) = seen.last().unwrap();
            assert_eq!(body["context"]["application"], "payments");
            assert_eq!(body["resource"]["properties"]["amount"], 10);
            assert_eq!(id, "az-1#0");
        }
        let no = forward_to(&client, &ask("write"), "payments", "", 1000).await;
        assert_eq!(
            (no.status, no.decision, no.error.is_none()),
            (200, false, true)
        );
        assert_eq!(
            seen.lock().unwrap().last().unwrap().1,
            "",
            "no id is sent when the caller sent none"
        );
        let broken =
            forward_to(&client, &ask("other"), "payments", "", 1000).await;
        assert_eq!((broken.status, broken.code), (500, "STS-XPEP-0057"));
        assert!(!broken.decision);
        let refused =
            forward_to(&client, &ask("refused"), "payments", "", 1000).await;
        assert_eq!((refused.status, refused.code), (502, "STS-XPEP-0056"));
        let slow = forward_to(&client, &ask("slow"), "payments", "", 200).await;
        assert_eq!((slow.status, slow.code), (504, "STS-XPEP-0055"));

        // NOBODY LISTENING: a port bound and not listening, held to the
        // end, so the kernel cannot hand it to another test's listener
        // in between (a port bound and RELEASED could be, #1935).
        let held = tokio::net::TcpSocket::new_v4().unwrap();
        held.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let dead = held.local_addr().unwrap().port();
        options.pdp_url = format!("http://127.0.0.1:{}/realm/r1", dead);
        let nowhere = PdpClient::new(&options).unwrap();
        let down =
            forward_to(&nowhere, &ask("read"), "payments", "", 1000).await;
        assert_eq!((down.status, down.code), (502, "STS-XPEP-0055"));
        assert!(!down.decision);
    }

    /// The decision records (#1827): an evaluation decided HERE is queued
    /// with what its log line carries and no id the caller sent; one
    /// FORWARDED to the service is not, because the service recorded it.
    #[tokio::test]
    async fn queues_what_it_decides_and_not_what_it_forwards() {
        use axum::routing::post;
        use std::sync::Arc;

        let router = axum::Router::new().route(
            "/access/v1/evaluation",
            post(|| async { axum::Json(json!({ "decision": true })) }),
        );
        let socket =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        tokio::spawn(async move {
            // A failure to serve shows as the forward below failing.
            if let Err(error) = axum::serve(socket, router).await {
                eprintln!("the mock service stopped: {}", error);
            }
        });
        let mut options = Options::from_env("0.0.0");
        options.pdp_url = format!("http://127.0.0.1:{}", port);
        options.audit_enabled = true;
        let client = PdpClient::new(&options).unwrap();
        let sync =
            Arc::new(crate::sync::Sync::new(client.clone(), options.clone()));
        let pep = crate::service::Pep::new(
            options.clone(),
            sts_core::version::load(std::path::Path::new(".")),
            sync,
            crate::pip::RemotePip::new(client, false),
            Arc::new(crate::listener::HttpsListener::new(
                "", "", 0, 5000, None,
            )),
        );
        let audit = pep.audit.clone();
        let catalogue = Catalogue {
            fga_applications: Arc::new(vec!["payments".to_string()]),
            ..Catalogue::default()
        };
        let caller = Caller {
            name: "edge-caller".into(),
            applications: vec!["payments".into(), "todo-app".into()],
        };
        let ask = |application: &str| {
            json!({ "subject": { "type": "user", "id": "alice" },
                    "action": { "name": "read" },
                    "resource": { "type": "document", "id": "d1" },
                    "context": { "application": application } })
        };
        let forwarded = pep
            .evaluate_one(
                &ask("payments"),
                &caller,
                &catalogue,
                "r-1",
                EVALUATION_PATH,
                false,
            )
            .await;
        assert!(forwarded.error.is_none() && forwarded.decision);
        assert_eq!(audit.overview()["queued"], 0, "a forward is not queued");
        let here = pep
            .evaluate_one(
                &ask("todo-app"),
                &caller,
                &catalogue,
                "r-2",
                EVALUATION_PATH,
                false,
            )
            .await;
        assert!(here.error.is_none() && !here.decision);
        assert_eq!(audit.overview()["queued"], 1);
        let record = audit.queued_for_test();
        assert_eq!(record.len(), 1);
        let one = &record[0];
        assert_eq!(
            (one.kind.as_str(), one.decision.as_str(), one.allowed),
            ("authzen", "NotApplicable", false)
        );
        assert_eq!(
            (
                one.subject.as_str(),
                one.resource.as_str(),
                one.action.as_str()
            ),
            ("", "document", "read")
        );
        assert_eq!(
            (
                one.caller.as_str(),
                one.application.as_str(),
                one.subject_type.as_str(),
                one.request_id.as_str(),
                one.endpoint.as_str(),
                one.bias.as_str()
            ),
            (
                "edge-caller",
                "todo-app",
                "user",
                "r-2",
                EVALUATION_PATH,
                "deny-biased"
            )
        );
        let sent = serde_json::to_string(one).unwrap();
        assert!(!sent.contains("alice") && !sent.contains("d1"));
    }

    fn edge_pep() -> crate::service::Pep {
        let mut options = Options::from_env("0.0.0");
        options.pdp_url = "http://127.0.0.1:9".into();
        options.audit_enabled = true;
        let client = PdpClient::new(&options).unwrap();
        let sync =
            std::sync::Arc::new(crate::sync::Sync::new(client.clone(), options.clone()));
        crate::service::Pep::new(
            options.clone(),
            sts_core::version::load(std::path::Path::new(".")),
            sync,
            crate::pip::RemotePip::new(client, false),
            std::sync::Arc::new(crate::listener::HttpsListener::new(
                "", "", 0, 5000, None,
            )),
        )
    }

    /// A binding tuple is 501 before it is read or forwarded. A lone scope,
    /// and an audience whose action is not a gate, stay ordinary. An
    /// approval is decided, and recorded as presented and not used.
    #[tokio::test]
    async fn a_binding_tuple_is_refused_before_it_is_read() {
        let pep = edge_pep();
        let audit = pep.audit.clone();
        let catalogue = Catalogue::default();
        let caller = Caller {
            name: "edge-caller".into(),
            applications: vec!["todo-app".into()],
        };
        let person = || json!({ "type": "user", "id": "alice" });
        let gate = json!({
            "subject": person(),
            "action": { "name": "issue:access_token:token_exchange" },
            "resource": { "type": "audience", "id": "https://api.example" },
            "context": { "application": "todo-app", "may_act": { "sub": "g" } }
        });
        let one = pep
            .evaluate_one(&gate, &caller, &catalogue, "b-1", EVALUATION_PATH, true)
            .await;
        assert_eq!(one.code, "STS-XPEP-0140");
        assert_eq!(one.error.as_ref().unwrap().0, 501);
        assert!(one.error.unwrap().1.contains("(a gate)"));
        assert_eq!(audit.overview()["queued"], 0);
        let act = json!({ "context": { "act": { "sub": "gateway" } } });
        let one = pep
            .evaluate_one(&act, &caller, &catalogue, "", EVALUATION_PATH, false)
            .await;
        assert_eq!(one.code, "STS-XPEP-0140");
        assert!(one.error.unwrap().1.contains("(a context member)"));
        let scope = json!({
            "subject": person(),
            "action": { "name": "read" },
            "resource": { "type": "protected_resource", "id": "documents.read" }
        });
        let beside = pep
            .evaluate_one(&scope, &caller, &catalogue, "", EVALUATION_PATH, true)
            .await;
        assert!(beside.error.unwrap().1.contains("(a scope)"));
        let alone = pep
            .evaluate_one(&scope, &caller, &catalogue, "", EVALUATION_PATH, false)
            .await;
        assert_ne!(alone.code, "STS-XPEP-0140");
        assert!(alone.error.is_none());
        let audience = json!({
            "subject": person(),
            "action": { "name": "read" },
            "resource": { "type": "audience", "id": "https://api.example" }
        });
        let ordinary = pep
            .evaluate_one(
                &audience, &caller, &catalogue, "", EVALUATION_PATH, true,
            )
            .await;
        assert_ne!(ordinary.code, "STS-XPEP-0140");
        let detail = json!({
            "subject": person(),
            "action": { "name": "read" },
            "resource": { "type": "document", "id": "d1" }
        });
        let detail = pep
            .evaluate_one(&detail, &caller, &catalogue, "", EVALUATION_PATH, true)
            .await;
        assert!(detail.error.unwrap().1.contains("(a detail)"));
        let other_grant = json!({
            "subject": person(),
            "action": { "name": "issue:access_token:other_grant" },
            "resource": { "type": "audience", "id": "https://api.example" }
        });
        assert!(is_gate(&other_grant));
        assert!(!is_gate(&json!({
            "action": { "name": "issue:access-token:token_exchange" },
            "resource": { "type": "audience", "id": "https://api.example" }
        })));
        let approval = json!({
            "subject": person(),
            "action": { "name": "read" },
            "resource": { "type": "document", "id": "d1" },
            "context": { "approval": { "id": "t1", "state": "signed" } }
        });
        let decided = pep
            .evaluate_one(
                &approval, &caller, &catalogue, "b-2", EVALUATION_PATH, false,
            )
            .await;
        assert!(decided.error.is_none() && !decided.decision);
        let queued = audit.queued_for_test();
        assert_eq!(queued.last().unwrap().code, "STS-AUTHZEN-0084");
    }

    #[test]
    fn echoes_only_a_printable_token() {
        assert_eq!(request_id(Some("az-req-1")).as_deref(), Some("az-req-1"));
        assert!(request_id(Some("two words")).is_none());
        assert!(request_id(Some(&"x".repeat(129))).is_none());
        assert!(request_id(None).is_none());
    }
}
