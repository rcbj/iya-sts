// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE AUTHZEN EDGE PDP (#1179): AuthZEN Authorization API 1.0 Access
//! Evaluation, answered HERE, over the policy this container pulled.
//!
//! ```text
//! POST /access/v1/evaluation                 one evaluation (section 6)
//! POST /access/v1/evaluations                a batch (section 7)
//! GET  /.well-known/authzen-configuration    the metadata (section 9)
//! ```
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

/// The three batch semantics (section 7.1.2), the first the default.
pub const SEMANTICS: [&str; 3] = [
    "execute_all",
    "deny_on_first_deny",
    "permit_on_first_permit",
];

/// The members a batch request may carry.
const BATCH_MEMBERS: [&str; 6] = [
    "subject",
    "action",
    "resource",
    "context",
    "evaluations",
    "options",
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
    asks_for_certificates: bool,
    transport: &Transport,
    callers: &Callers,
    endpoint: &str,
) -> Result<Caller, Reply> {
    if !asks_for_certificates {
        return Err(Reply::error(
            401,
            "STS-XPEP-0039",
            "This edge PDP authenticates its caller by a client certificate \
             (mutual TLS) on its HTTPS listener, and it is configured with \
             no authority to verify one against (PEP_AUTHZEN_CLIENT_CA), so \
             it admits nobody.",
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
        .call_with(
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
        if !self.options.authzen_enabled {
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
    /// endpoint, and the batch one while the realm has it on. No search
    /// endpoint, no `capabilities`, no `signed_metadata` — as the service.
    pub(crate) fn authzen_metadata(
        &self,
        transport: &Transport,
        host: Option<&str>,
    ) -> Reply {
        let catalogue = self.sync.catalogue();
        if let Some(off) = self.authzen_off(&catalogue) {
            return off;
        }
        let configured = &self.options.authzen_pdp_identifier;
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
        if catalogue.settings.batch_enabled {
            if let Some(map) = out.as_object_mut() {
                map.insert(
                    "access_evaluations_endpoint".into(),
                    json!(format!("{}{}", base, EVALUATIONS_PATH)),
                );
            }
        }
        Reply {
            status: 200,
            body: out,
            pretty: true,
        }
    }

    /// `POST /access/v1/evaluation` and `POST /access/v1/evaluations`, after
    /// the request id: the switches, the caller, the body, the answer.
    pub(crate) async fn authzen_post(
        &self,
        batch: bool,
        transport: &Transport,
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
        let caller = match admit(
            &self.options,
            self.listener.asks_for_client_certificates(),
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
                    self.options.max_body_bytes
                ),
            );
        };
        let item = self
            .evaluate_one(
                &body_of(&bytes),
                &caller,
                &catalogue,
                id,
                EVALUATION_PATH,
            )
            .await;
        match item.error {
            Some((status, message)) => {
                Reply::error(status, item.code, &message)
            }
            None => Reply::decision(answer_of(item.decision, item.context)),
        }
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
        if let Some(stray) = crate::authzen_catalogue::js_keys(given)
            .into_iter()
            .find(|key| !BATCH_MEMBERS.contains(&key.as_str()))
        {
            return Reply::error(
                400,
                "STS-AUTHZEN-0009",
                &format!(
                    "An access evaluations request has no member \"{}\"; it \
                     takes {}.",
                    crate::authzen_catalogue::js_slice(stray, 64),
                    BATCH_MEMBERS.join(", ")
                ),
            );
        }
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
                .evaluate_one(&single, caller, catalogue, id, EVALUATIONS_PATH)
                .await;
            return match one.error {
                Some((status, message)) => {
                    Reply::error(status, one.code, &message)
                }
                None => Reply::decision(answer_of(one.decision, one.context)),
            };
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
        let mut out = Vec::new();
        for (i, item) in items.iter().enumerate() {
            let one = match merged(given, item) {
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

    /// Decides one evaluation for an admitted caller, and records it — the
    /// container's record being a log line, since it has no audit log.
    async fn evaluate_one(
        &self,
        body: &Value,
        caller: &Caller,
        catalogue: &Catalogue,
        batch_id: &str,
        endpoint: &str,
    ) -> ItemResult {
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
        // from the root, and counted and logged here like any other.
        if forwards(catalogue, &application) {
            let timeout = self.options.authzen_forward_timeout_ms;
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
        let outcome =
            authzen_map::outcome(&answer, &enforcement, policies.root_refused);
        self.sync
            .count_authzen((!outcome.fault).then_some(outcome.decision));
        // THE RECORD: who asked, about which application, the two types and
        // the action, the request id, the decision — never a property value,
        // an id the caller sent, or a credential (decision 9 on #563).
        let code = if outcome.fault {
            "STS-AUTHZEN-0028"
        } else if !outcome.undischargeable.is_empty() {
            "STS-AUTHZEN-0029"
        } else {
            ""
        };
        let line = format!(
            "xacml-pep: authzen: {} decided {} for a {} to {} a {}, caller \
             \"{}\", application \"{}\"{}{}{}.",
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
            }
        );
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
        ItemResult {
            status: 200,
            decision: outcome.decision,
            context: catalogue
                .settings
                .return_reasons
                .then(|| authzen_map::reasons(&outcome)),
            error: None,
            code: "",
        }
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

    fn answered(status: u16, body: Value) -> Answer {
        Answer {
            status,
            text: body.to_string(),
            json: Some(body),
            error: None,
            timed_out: false,
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

        // NOBODY LISTENING: a port bound and released.
        let gone = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead = gone.local_addr().unwrap().port();
        drop(gone);
        options.pdp_url = format!("http://127.0.0.1:{}/realm/r1", dead);
        let nowhere = PdpClient::new(&options).unwrap();
        let down =
            forward_to(&nowhere, &ask("read"), "payments", "", 1000).await;
        assert_eq!((down.status, down.code), (502, "STS-XPEP-0055"));
        assert!(!down.decision);
    }

    #[test]
    fn echoes_only_a_printable_token() {
        assert_eq!(request_id(Some("az-req-1")).as_deref(), Some("az-req-1"));
        assert!(request_id(Some("two words")).is_none());
        assert!(request_id(Some(&"x".repeat(129))).is_none());
        assert!(request_id(None).is_none());
    }
}
