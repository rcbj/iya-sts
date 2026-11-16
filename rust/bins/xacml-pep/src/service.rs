// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The PEP's endpoints, decided by ONE handler whatever the transport — two
//! listeners that answered differently would be two enforcement points
//! sharing a process.
//!
//! ```text
//! GET  /              what this PEP is, what it holds, what it has enforced
//! GET  /protected     THE RESOURCE. 200 or 403, decided here
//! POST /notify        the PDP's nudge: pull now (HTTPS only)
//! GET  /healthcheck   liveness, never whether the policy is current
//! GET  /crl/<name>    this PEP's own credential's CRLs (#174)
//! POST /access/v1/evaluation, /access/v1/evaluations,
//! GET  /.well-known/authzen-configuration
//!                     the AuthZEN edge PDP (#1179), `authzen.rs`
//! ```
//!
//! `GET /protected` IS THE DEMONSTRATION PEP since #596: the service's own
//! `GET /xacml/protected` and its `xacml.pepBias` were deleted (the runtime
//! ships no demonstration code), and this is the same thing in the place a
//! PEP lives — the request built from `subject`, `resource` and `action`
//! through the one builder, the bias as this PEP's option (`PEP_BIAS`), and
//! section 7.2's obligation rule (`enforce.rs`).

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{header, HeaderValue, Method, Request, Response, StatusCode};
use indexmap::IndexMap;
use regex::Regex;
use serde_json::{json, Value};
use sts_core::log::tag;
use sts_core::version::VersionInfo;
use sts_xacml::builder::{vocabulary, AuthorizationRequest};
use sts_xacml::model::{attribute, category, types, Decision};
use sts_xacml::pdp::{AttributeResolver, EvaluationOptions, Pdp};
use sts_xacml::policy::PolicyNode;
use sts_xacml::request::{ResolvedObligation, Status};

use crate::audit::{self, Audit, Record};
use crate::authzen::{self, Reply};
use crate::enforce::Enforcer;
use crate::listener::{HttpsListener, Transport};
use crate::options::Options;
use crate::pip::RemotePip;
use crate::sync::{Policies, Sync};

/// The attribute prefix the service's PIP answers beside the bare name.
const PIP_PREFIX: &str = "urn:sts:xacml:attribute:";

/// A decision as `/protected` reports it.
struct Answer {
    decision: Decision,
    status: Status,
    obligations: Vec<ResolvedObligation>,
    advice: Vec<ResolvedObligation>,
    policy_identifiers: Vec<Value>,
    note: Option<&'static str>,
    pip: Option<Value>,
}

/// The PEP: what it holds, how it decides, and what it reports.
pub struct Pep {
    pub options: Options,
    pub version: VersionInfo,
    pub sync: Arc<Sync>,
    pub(crate) pip: RemotePip,
    pub(crate) pdp: Pdp,
    pub listener: Arc<HttpsListener>,
    /// The decision records' queue (#1827).
    pub audit: Arc<Audit>,
    last_pip_report: Mutex<Option<Value>>,
    crl_name: Option<Regex>,
}

fn json_response(status: StatusCode, body: &Value) -> Response<Body> {
    let text =
        serde_json::to_string_pretty(body).unwrap_or_else(|_| "{}".to_string());
    let mut response = Response::new(Body::from(text));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// An AuthZEN reply as a response: indented where the service indents.
fn reply_response(reply: &Reply) -> Response<Body> {
    let text = if reply.pretty {
        serde_json::to_string_pretty(&reply.body)
    } else {
        serde_json::to_string(&reply.body)
    }
    .unwrap_or_else(|_| "{}".to_string());
    let mut response = Response::new(Body::from(text));
    *response.status_mut() =
        StatusCode::from_u16(reply.status).unwrap_or(StatusCode::OK);
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn status_json(status: &Status) -> Value {
    match &status.message {
        Some(message) => json!({ "code": status.code.uri(),
                                 "message": message }),
        None => json!({ "code": status.code.uri() }),
    }
}

impl Pep {
    /// The enforcement rule with the bias in force now (#1760: the service
    /// may set it while this PEP runs).
    pub(crate) fn enforcer(&self) -> Enforcer {
        Enforcer::new(self.options.now().bias)
    }
}

impl Pep {
    pub fn new(
        options: Options,
        version: VersionInfo,
        sync: Arc<Sync>,
        pip: RemotePip,
        listener: Arc<HttpsListener>,
    ) -> Pep {
        // The decision records' queue (#1827), built from the same options
        // so it reads the same managed settings.
        let audit = Arc::new(Audit::new(&options));
        Pep {
            options,
            version,
            sync,
            pip,
            pdp: Pdp::new(),
            listener,
            audit,
            last_pip_report: Mutex::new(None),
            crl_name: Regex::new(r"(?i)^[a-z0-9-]+\.crl$").ok(),
        }
    }

    /// ONE HANDLER FOR BOTH LISTENERS. No `instrument` on it: it is the hot
    /// path of the container and would drown its log.
    ///
    /// **HEAD IS GET WITHOUT THE BODY (#1830)** for `/`, `/healthcheck`,
    /// `/crl/<name>` and the AuthZEN metadata: the same status and headers,
    /// `Content-Length` the GET's, no body. **Not for `/protected`**, whose
    /// GET is a DECISION — the PIP asked at the PDP, the enforcement counted
    /// and reported on the heartbeat — and a HEAD is what a monitor or a
    /// link checker sends without meaning one; it stays the generic 404, as
    /// every other method this handler does not answer.
    pub async fn handle(
        self: Arc<Self>,
        mut request: Request<Body>,
    ) -> Response<Body> {
        if request.method() != Method::HEAD {
            return self.answer(request).await;
        }
        if request.uri().path() != "/protected" {
            *request.method_mut() = Method::GET;
        }
        let response = self.answer(request).await;
        let (mut parts, body) = response.into_parts();
        // Every answer here is a small document already in memory (a CRL
        // file read whole), so it is measured rather than streamed.
        let length = axum::body::to_bytes(body, usize::MAX)
            .await
            .map(|b| b.len())
            .unwrap_or(0);
        if parts.status != StatusCode::NO_CONTENT {
            parts
                .headers
                .insert(header::CONTENT_LENGTH, HeaderValue::from(length));
        }
        Response::from_parts(parts, Body::empty())
    }

    /// Every method but HEAD, which [`Self::handle`] answers through this.
    async fn answer(self: Arc<Self>, request: Request<Body>) -> Response<Body> {
        let method = request.method().clone();
        let uri = request.uri().clone();
        let path = uri.path().to_string();
        let transport = request
            .extensions()
            .get::<Transport>()
            .cloned()
            .unwrap_or_default();
        if transport.crl_only
            && !(method == Method::GET && path.starts_with("/crl/"))
        {
            // THE CRL-ONLY LISTENER (2026-11-14) answers this PEP's own
            // credential's lists and nothing else: the decision API, the
            // nudge and the AuthZEN edge PDP are on HTTPS.
            tracing::info!(
                "{}xacml-pep: {} {} reached the CRL-only plain-HTTP \
                 listener, which serves GET /crl/<name> alone.",
                tag("STS-XPEP-0114"),
                method,
                path
            );
            return json_response(
                StatusCode::NOT_FOUND,
                &json!({
                    "error": "not_found",
                    "error_description": "This plain-HTTP port serves only \
                        this PEP's own credential's CRLs, GET /crl/<name>. \
                        The decision API, POST /notify and the AuthZEN edge \
                        PDP answer on the HTTPS listener."
                }),
            );
        }
        if method == Method::POST
            && (path == authzen::EVALUATION_PATH
                || path == authzen::EVALUATIONS_PATH)
        {
            // `X-Request-ID` ECHOED on every answer, a refusal included,
            // when it is a token this PDP will reflect (section 10.1).
            let id = authzen::request_id(
                request
                    .headers()
                    .get("x-request-id")
                    .and_then(|v| v.to_str().ok()),
            );
            let batch = path == authzen::EVALUATIONS_PATH;
            let limit = if batch {
                self.options
                    .now()
                    .max_body_bytes
                    .max(self.sync.catalogue().settings.max_body_bytes + 1)
            } else {
                self.options.now().max_body_bytes
            };
            let body = axum::body::to_bytes(request.into_body(), limit)
                .await
                .map(|b| b.to_vec())
                .map_err(|_| ());
            let reply = self
                .authzen_post(
                    batch,
                    &transport,
                    body,
                    id.as_deref().unwrap_or(""),
                )
                .await;
            let mut response = reply_response(&reply);
            if let Some(id) = id.and_then(|i| HeaderValue::from_str(&i).ok()) {
                response.headers_mut().insert("x-request-id", id);
            }
            return response;
        }
        if method == Method::GET && path == authzen::METADATA_PATH {
            // `Host`, else the URI's authority (#1830): an HTTP/2 client
            // sends `:authority` and no `Host`, and hyper puts it in the URI.
            let host = request
                .headers()
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
                .or_else(|| uri.authority().map(|a| a.as_str().to_string()));
            let reply = self.authzen_metadata(&transport, host.as_deref());
            return reply_response(&reply);
        }
        let mut query: IndexMap<String, String> = IndexMap::new();
        if let Some(raw) = uri.query() {
            let url = format!("http://localhost/?{}", raw);
            if let Ok(parsed) = reqwest::Url::parse(&url) {
                for (key, value) in parsed.query_pairs() {
                    query.insert(key.into_owned(), value.into_owned());
                }
            }
        }
        if method == Method::GET && path == "/healthcheck" {
            // LIVENESS ONLY: a stale PEP is working, and a healthcheck that
            // failed on staleness would turn a PDP outage into a restart
            // loop.
            return json_response(
                StatusCode::OK,
                &json!({ "message": "Success" }),
            );
        }
        if method == Method::GET && (path == "/" || path.is_empty()) {
            return json_response(StatusCode::OK, &self.overview());
        }
        if method == Method::GET && path == "/protected" {
            let (status, body) = self.protected_resource(&query).await;
            return json_response(status, &body);
        }
        if method == Method::GET {
            if let Some(name) = path.strip_prefix("/crl/") {
                return match self.crl_document(name) {
                    Some(document) => {
                        let mut response = Response::new(Body::from(document));
                        response.headers_mut().insert(
                            header::CONTENT_TYPE,
                            HeaderValue::from_static("application/pkix-crl"),
                        );
                        response
                    }
                    None => {
                        tracing::info!(
                            "{}xacml-pep: no such CRL: {}",
                            tag("STS-XPEP-0009"),
                            path
                        );
                        json_response(
                            StatusCode::NOT_FOUND,
                            &json!({ "error": "not_found" }),
                        )
                    }
                };
            }
        }
        if method == Method::POST && path == "/notify" && !transport.https {
            // THE NUDGE IS HTTPS ONLY (2026-11-14, rcbj: "Let's assume
            // always HTTPS"). The service never dials an http:// notify
            // URL, so a nudge over plain HTTP is not the PDP's; refused
            // where a PEP that still answered it would be answering anybody
            // on the network.
            tracing::info!(
                "{}xacml-pep: POST /notify over plain HTTP was refused; the \
                 nudge is answered on the HTTPS listener only.",
                tag("STS-XPEP-0112")
            );
            return json_response(
                StatusCode::NOT_FOUND,
                &json!({
                    "error": "not_found",
                    "error_description": "POST /notify is answered on this \
                        PEP's HTTPS listener only; the PDP nudges over https."
                }),
            );
        }
        if method == Method::POST && path == "/notify" {
            // THE NUDGE: answered 204 IMMEDIATELY and pulled after. What
            // changed is discovered by pulling from this PEP's own
            // configured PDP; the body is TRUSTED FOR NOTHING. One member is
            // read since 2026-11-16, `full`, which a Sync from the console
            // sends: it asks for every document whole rather than answered
            // 304, and carries nothing a pull does not fetch. Because anybody
            // reaching this listener can send it, a full pull is honoured at
            // most once a poll interval; another is an ordinary pull.
            let body = axum::body::to_bytes(request.into_body(), 4096)
                .await
                .map(|b| b.to_vec())
                .unwrap_or_default();
            let asked_full = serde_json::from_slice::<Value>(&body)
                .ok()
                .and_then(|v| v.get("full").and_then(Value::as_bool))
                .unwrap_or(false);
            let full = asked_full && self.sync.claim_full_pull();
            if asked_full && !full {
                tracing::info!(
                    "{}xacml-pep: a full pull was asked for within a poll \
                     interval of the last one; pulling as usual instead.",
                    tag("STS-XPEP-0120")
                );
            }
            tracing::info!(
                "xacml-pep: nudged by the PDP; pulling {}now rather than \
                 waiting up to {}ms for the next poll.",
                if full { "every document whole " } else { "" },
                self.options.now().poll_interval_ms
            );
            let sync = self.sync.clone();
            tokio::spawn(async move {
                let pulled = if full {
                    sync.pull_full("nudge").await
                } else {
                    sync.pull("nudge").await
                };
                if !pulled {
                    tracing::warn!(
                        "{}xacml-pep: the nudged pull failed. The scheduled \
                         poll will try again.",
                        tag("STS-XPEP-0010")
                    );
                }
            });
            // NO CONTENT-TYPE ON A 204 (#1830): there is no content to
            // type. Cache-Control stays, as on every answer here.
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::NO_CONTENT;
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("no-store"),
            );
            return response;
        }
        tracing::info!(
            "{}xacml-pep: no such endpoint: {} {}",
            tag("STS-XPEP-0009"),
            method,
            path
        );
        json_response(
            StatusCode::NOT_FOUND,
            &json!({
                "error": "not_found",
                "error_description": "This PEP answers GET /, GET /protected, \
                    POST /notify, GET /healthcheck, GET /crl/<name> for its \
                    own credential's lists, and the AuthZEN edge PDP: POST \
                    /access/v1/evaluation, POST /access/v1/evaluations and \
                    GET /.well-known/authzen-configuration. HEAD is answered \
                    for each GET but /protected."
            }),
        )
    }

    /// The CRLs of this PEP's own credential: public signed documents, and
    /// only a name of the form `<word>.crl` is ever looked up.
    fn crl_document(&self, name: &str) -> Option<Vec<u8>> {
        let dir = self.options.crl_dir.as_ref()?;
        if !self.crl_name.as_ref().is_some_and(|re| re.is_match(name)) {
            return None;
        }
        std::fs::read(dir.join(name)).ok()
    }

    /// The subject, resource and action a `/protected` request names, the
    /// last two with their defaults — what the decision is about, and what
    /// its record says it was about.
    fn named(
        &self,
        query: &IndexMap<String, String>,
    ) -> (String, String, String) {
        let subject = query.get("subject").cloned().unwrap_or_default();
        let resource = query
            .get("resource")
            .filter(|r| !r.is_empty())
            .cloned()
            .or_else(|| {
                Some(self.options.now().resource).filter(|r| !r.is_empty())
            })
            .unwrap_or_else(|| "urn:xacml-pep:protected".to_string());
        let action = query
            .get("action")
            .filter(|a| !a.is_empty())
            .cloned()
            .unwrap_or_else(|| "GET".to_string());
        (subject, resource, action)
    }

    /// A decision here, with what was pulled — and the remote PIP asked
    /// BEFORE evaluation, because the engine's resolver is synchronous.
    async fn decide(&self, query: &IndexMap<String, String>) -> Answer {
        let (subject, resource, action) = self.named(query);
        // THROUGH THE ONE BUILDER (#306), the four categories named first
        // so an empty subject is still sent as the empty category it was.
        let mut req = AuthorizationRequest::default();
        for id in [
            category::ACCESS_SUBJECT,
            category::RESOURCE,
            category::ACTION,
            category::ENVIRONMENT,
        ] {
            req.category(id);
        }
        if !subject.is_empty() {
            req.subject(attribute::SUBJECT_ID, [subject.as_str()]);
        }
        if let Some(kind) = query.get("subjectKind") {
            let kind = if kind == "application" {
                "application"
            } else {
                "user"
            };
            req.subject(vocabulary::SUBJECT_KIND, [kind]);
        }
        // Every other parameter is a subject attribute under BOTH spellings,
        // because the service's PIP answers both from one directory
        // attribute and a policy may use either.
        for (key, value) in query {
            if matches!(
                key.as_str(),
                "subject" | "resource" | "action" | "subjectKind"
            ) {
                continue;
            }
            req.subject(key, [value.as_str()]);
            req.subject(&format!("{}{}", PIP_PREFIX, key), [value.as_str()]);
        }
        req.target(&resource, Some(types::ANYURI))
            .requested_action(&action);
        let request = req.build();
        self.evaluate(request).await
    }

    /// The reverse proxy's decision (#1760, D8): subject, resource and
    /// action through the ONE builder exactly as `/protected` builds its
    /// request — the four categories named first, the subject as
    /// `subject-id`, the resource typed anyURI, the action as `action-id` —
    /// evaluated by the same path (the PIP asked first), enforced by the
    /// same rule and counted with the same counters.
    ///
    /// **AGAINST THE POLICY THE ROUTE NAMES, NEVER THE ROOT** (rcbj's
    /// decision on #1760): `policy` is an entry's NAME in what this PEP
    /// last pulled, and the PIP walks that policy (the repository answering
    /// its references). `None` is "not held" — never pulled, withheld,
    /// disabled, renamed, failed to load, or a name two entries carry — and
    /// is NOT a NotApplicable for the bias to settle: a permit-biased PEP
    /// would otherwise open every route whose policy went missing. Nothing
    /// is counted then, there having been no decision. It does not ask
    /// whether a ROOT is held (`loaded`): a route needs only its own.
    ///
    /// An empty `subject` is the ANONYMOUS subject of a public route: the
    /// access-subject category is sent with no attribute in it, as
    /// `/protected` sends a request with no `subject`, so a policy matches
    /// it by `subject-id` being absent (`MustBePresent="false"`).
    pub(crate) async fn decide_proxy(
        &self,
        subject: &str,
        resource: &str,
        action: &str,
        policy: &str,
    ) -> Option<(Decision, crate::enforce::Outcome)> {
        let (policies, _) = self.sync.current();
        let named = policies.by_name.get(policy)?;
        let mut req = AuthorizationRequest::default();
        for id in [
            category::ACCESS_SUBJECT,
            category::RESOURCE,
            category::ACTION,
            category::ENVIRONMENT,
        ] {
            req.category(id);
        }
        if !subject.is_empty() {
            req.subject(attribute::SUBJECT_ID, [subject]);
        }
        req.target(resource, Some(types::ANYURI))
            .requested_action(action);
        let answer = self.evaluate_against(named, &policies, req.build()).await;
        let outcome = self
            .enforcer()
            .enforce(answer.decision, &answer.obligations);
        self.sync.count_decision(&outcome);
        Some((answer.decision, outcome))
    }

    /// One built request evaluated against what was pulled, from the root.
    async fn evaluate(&self, request: sts_xacml::request::Request) -> Answer {
        let (policies, loaded) = self.sync.current();
        let Some(root) = policies.root.as_ref().filter(|_| loaded) else {
            tracing::warn!(
                "{}xacml-pep: a decision was asked for and this PEP holds no \
                 root policy, so it is NotApplicable and the {} bias settles \
                 it.",
                tag("STS-XPEP-0005"),
                self.options.now().bias.as_str()
            );
            return Answer {
                decision: Decision::NotApplicable,
                status: Status::ok(),
                obligations: Vec::new(),
                advice: Vec::new(),
                policy_identifiers: Vec::new(),
                note: Some(
                    "This PEP holds no root policy — it has never pulled one \
                     successfully, or what it pulled had no root. There is \
                     nothing to evaluate, so the decision is NotApplicable \
                     and the bias below is what actually decided.",
                ),
                pip: None,
            };
        };
        self.evaluate_against(root, &policies, request).await
    }

    /// One built request evaluated from `start` — the root, or a proxy
    /// route's own policy — with the PIP asked first and the repository
    /// answering references.
    async fn evaluate_against(
        &self,
        start: &PolicyNode,
        policies: &Policies,
        request: sts_xacml::request::Request,
    ) -> Answer {
        let resolution = self
            .pip
            .resolver_for(&request, start, &policies.repository)
            .await;
        if let Ok(mut last) = self.last_pip_report.lock() {
            *last = Some(resolution.report.clone());
        }
        let options = EvaluationOptions {
            resolver: resolution
                .resolver
                .as_ref()
                .map(|r| r as &dyn AttributeResolver),
            repository: Some(&policies.repository),
            now: None,
        };
        let response = self.pdp.evaluate(start, &request, &options);
        if response.decision == Decision::Indeterminate {
            tracing::warn!(
                "{}xacml-pep: the engine answered Indeterminate ({}{}), so \
                 the {} bias settles it.",
                tag("STS-XPEP-0006"),
                response.status.code.uri(),
                response
                    .status
                    .message
                    .as_ref()
                    .map(|m| format!(": {}", m))
                    .unwrap_or_default(),
                self.options.now().bias.as_str()
            );
        }
        let identifiers = response
            .policy_identifiers
            .iter()
            .map(|p| json!({
                "kind": if p.is_policy_set { "PolicySet" } else { "Policy" },
                "id": p.id,
                "version": p.version
            }))
            .collect();
        Answer {
            decision: response.decision,
            status: response.status,
            obligations: response.obligations,
            advice: response.advice,
            policy_identifiers: identifiers,
            note: None,
            pip: Some(resolution.report),
        }
    }

    async fn protected_resource(
        &self,
        query: &IndexMap<String, String>,
    ) -> (StatusCode, Value) {
        let answer = self.decide(query).await;
        let outcome = self
            .enforcer()
            .enforce(answer.decision, &answer.obligations);
        self.sync.count_decision(&outcome);
        if self.audit.enabled() {
            let (subject, resource, action) = self.named(query);
            let policies = answer
                .policy_identifiers
                .iter()
                .map(|p| {
                    audit::policy_name(
                        p["id"].as_str().unwrap_or(""),
                        p["version"].as_str().unwrap_or(""),
                    )
                })
                .collect();
            self.audit.record(Record {
                at: sts_core::time::iso_now(),
                kind: "enforcement".into(),
                decision: answer.decision.as_str().to_string(),
                allowed: outcome.allowed,
                code: if answer.decision == Decision::Indeterminate {
                    "STS-XPEP-0006".into()
                } else {
                    String::new()
                },
                subject,
                resource,
                action,
                bias: outcome.bias.as_str().to_string(),
                why: outcome.why.clone(),
                policies,
                discharged: outcome.discharged.clone(),
                undischargeable: outcome.undischargeable.clone(),
                ..Record::default()
            });
        }
        let obligations: Vec<Value> = answer
            .obligations
            .iter()
            .map(|o| {
                json!({ "id": o.id,
                             "discharged": outcome.discharged.contains(&o.id) })
            })
            .collect();
        let advice: Vec<Value> =
            answer.advice.iter().map(|a| json!(a.id)).collect();
        let mut body = json!({
            "decision": answer.decision.as_str(),
            "allowed": outcome.allowed,
            "bias": outcome.bias.as_str(),
            "why": outcome.why,
            "status": status_json(&answer.status),
            "obligations": obligations,
            "advice": advice,
            "applicablePolicies": answer.policy_identifiers,
            "decidedBy": {
                "pep": self.options.name,
                "syncToken": self.sync.sync_token(),
                "note": "Decided IN THIS PROCESS, against the policy this PEP \
                         last pulled. The PDP did not see this request."
            },
            "pip": answer.pip.unwrap_or_else(
                || json!({ "used": false, "why": "nothing was asked." }))
        });
        if let (Some(note), Some(map)) = (answer.note, body.as_object_mut()) {
            map.insert("note".into(), json!(note));
        }
        let status = if outcome.allowed {
            StatusCode::OK
        } else {
            StatusCode::FORBIDDEN
        };
        (status, body)
    }

    /// `authzen` on `GET /` (#1179): what the edge PDP answers, to whom,
    /// with which catalogue, and what it cannot do that the service can.
    fn authzen_overview(&self) -> Value {
        let o = &self.options;
        let mut out = self.sync.authzen_json();
        if let Some(map) = out.as_object_mut() {
            // THE VALUES IN FORCE (#1830), the service's managed ones when
            // it set them — what the edge PDP actually does — and never the
            // environment's alone; `settings.values` says where each came
            // from.
            let now = o.now();
            map.insert("enabled".into(), json!(now.authzen));
            map.insert(
                "endpoints".into(),
                json!([
                    authzen::EVALUATION_PATH,
                    authzen::EVALUATIONS_PATH,
                    authzen::METADATA_PATH
                ]),
            );
            // THE LOCAL NARROWING, COUNTED (#1189): who may ask is the
            // service's list, pulled, and `pulledCallers` above counts it
            // without naming anybody, for the reason given there.
            map.insert(
                "localCallers".into(),
                json!({
                    "configured": o.authzen_callers_configured,
                    "certificates": o.authzen_callers.len(),
                    "role": if o.authzen_callers_configured {
                        "narrows the pulled list; decides alone until the \
                         first pull"
                    } else {
                        "not set: the pulled list alone decides"
                    }
                }),
            );
            map.insert(
                "clientCertificatesAsked".into(),
                json!(self.listener.asks_for_client_certificates()),
            );
            map.insert(
                "pdpIdentifier".into(),
                if now.authzen_pdp_identifier.is_empty() {
                    Value::Null
                } else {
                    json!(now.authzen_pdp_identifier)
                },
            );
            map.insert(
                "what".into(),
                json!(
                    "An AuthZEN edge PDP: the service's mapping contract \
                       — the catalogue and settings pulled beside the \
                       policies — decided here against the pulled root \
                       policy. Callers authenticate by mutual TLS only and \
                       are admitted by the caller list pulled from the \
                       service (who holds AUTHZEN_PEPS as its policy decides \
                       it, and each caller's application scope), narrowed by \
                       PEP_AUTHZEN_CALLERS when that is set; an outside \
                       authority's revocation is not checked. Each decision \
                       made here is a log line, and a record sent to the \
                       service's audit log (audit, below; #1827)."
                ),
            );
        }
        out
    }

    /// `GET /`. Staleness is computed HERE and separately from the PDP's
    /// verdict on purpose: this PEP counts missed polls and the PDP counts
    /// missed heartbeats, and the two can disagree.
    fn overview(&self) -> Value {
        let o = &self.options;
        let now = o.now();
        let stale_after_ms = now.poll_interval_ms * 3;
        let last_pull =
            chrono::DateTime::parse_from_rfc3339(&self.sync.last_pull_at());
        let stale = match last_pull {
            Ok(at) => {
                let age = chrono::Utc::now()
                    .signed_duration_since(at)
                    .num_milliseconds();
                age > stale_after_ms as i64
            }
            Err(_) => true,
        };
        let last_query = self
            .last_pip_report
            .lock()
            .ok()
            .and_then(|r| r.clone())
            .unwrap_or(Value::Null);
        let pip_what = if self.pip.enabled() {
            "This PEP resolves attribute designators the request did not \
             carry against the PDP's embedded directory, in ONE batched query \
             before each evaluation, in XACML's own XML both ways. So a \
             policy that reads employeeType off a person's entry decides HERE \
             the way it decides at the PDP. The endpoint requires a client \
             certificate whose subject holds the built-in REMOTE_PEPS role; \
             without one every query is refused and this PEP falls back to \
             deciding on what the request asserts."
        } else {
            "PEP_PIP is off, so this PEP has NO Policy Information Point: a \
             designator the request did not carry produces an empty bag. Pass \
             extra query parameters to /protected and each becomes a subject \
             attribute — asserted by the caller about itself, which no real \
             deployment would believe and which is exactly what a mock is for."
        };
        let v = &self.version;
        json!({
            "what": "A REMOTE XACML Policy Enforcement Point. It holds its \
                     own copy of the engine, PULLS the policy repository \
                     from the PDP below, and decides here. The PDP saw none \
                     of the decisions counted on this page, which is what a \
                     remote PEP is.",
            "pip": {
                "enabled": self.pip.enabled(),
                "endpoint": if self.pip.enabled() {
                    Value::from(format!("{}/xacml/pip", o.pdp_url))
                } else {
                    Value::Null
                },
                "credentialed": self.sync.client().credential().has_key(),
                "lastQuery": last_query,
                "what": pip_what
            },
            "version": v.version,
            "build": {
                "number": if v.build.is_empty() { Value::Null }
                          else { Value::from(v.build.clone()) },
                "release": v.release,
                "commit": if v.commit.is_empty() { Value::Null }
                          else { Value::from(v.commit.clone()) },
                "at": v.built_at,
                "stamped": v.stamped,
                "what": "The version is M.N.O.<build> (#1317): the release, \
                         read from the same VERSION file the PDP's is, and \
                         the build number. A difference in the RELEASE is \
                         a PEP left behind across a release. The build \
                         number is per IMAGE — the UTC instant it was \
                         built, unless it is a release build, which names \
                         its own — so two images of one tree differ there \
                         unless both were built as the same release."
            },
            "pdp": o.pdp_url,
            "bias": now.bias.as_str(),
            "protectedAt": "/protected",
            "https": self.listener.overview(),
            "authzen": self.authzen_overview(),
            "proxy": self.sync.proxy_json(),
            "audit": self.audit.overview(),
            "credential": self.sync.client().credential().overview(),
            "holding": self.sync.holding_json(),
            "stale": stale,
            "staleAfterMs": stale_after_ms,
            "registration": self.sync.registration_json(),
            "enforced": self.sync.counters_json(),
            "notify": match crate::options::advertised_notify_url(
                &now.notify_url) {
                url if url.is_empty() => Value::Null,
                url => Value::from(url),
            },
            "poll": { "intervalMs": now.poll_interval_ms,
                      "heartbeatMs": now.heartbeat_interval_ms },
            // EVERY SETTING IN FORCE AND WHERE IT CAME FROM (#1760): the
            // service, the environment or the default, and the settings
            // pull's own state.
            "settings": self.sync.settings_json(),
            "contract": "THE PULL IS THE CONTRACT. This PEP polls the PDP on \
                         its own interval and converges whether or not a \
                         nudge ever arrives. A PDP that is unreachable leaves \
                         this PEP enforcing what it last pulled rather than \
                         denying everything — which is a deliberate trade, \
                         and it means a policy change made during an outage \
                         is not enforced here until the next successful \
                         pull."
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::options::Bias;
    use crate::pdp_client::PdpClient;
    use crate::settings::Managed;

    /// A bias the service sets (#1760) is the one a decision is enforced
    /// with, from the next decision on, and clearing it puts the
    /// environment's back.
    #[test]
    fn the_bias_in_force_is_the_service_s() {
        let mut options = Options::from_env("0.0.0");
        options.pdp_url = "http://127.0.0.1:9".into();
        options.bias = Bias::DenyBiased;
        options.pip_enabled = false;
        let client = PdpClient::new(&options).unwrap();
        let sync = Arc::new(Sync::new(client.clone(), options.clone()));
        let pep = Pep::new(
            options.clone(),
            sts_core::version::load(std::path::Path::new(".")),
            sync,
            RemotePip::new(client, false).governed_by(options.clone()),
            Arc::new(HttpsListener::new("", "", 0, 1000, None)),
        );
        let na = Decision::NotApplicable;
        assert!(!pep.enforcer().enforce(na, &[]).allowed);
        assert!(!pep.pip.enabled());
        options.managed.apply(Managed::parse(
            "t",
            true,
            &serde_json::json!({ "bias": "permit-biased", "pip": true }),
        ));
        assert!(pep.enforcer().enforce(na, &[]).allowed);
        assert!(pep.pip.enabled());
        options.managed.apply(Managed::default());
        assert!(!pep.enforcer().enforce(na, &[]).allowed);
    }

    fn a_pep() -> Arc<Pep> {
        let mut options = Options::from_env("0.0.0");
        options.pdp_url = "http://127.0.0.1:9".into();
        options.pip_enabled = false;
        let client = PdpClient::new(&options).unwrap();
        let sync = Arc::new(Sync::new(client.clone(), options.clone()));
        Arc::new(Pep::new(
            options.clone(),
            sts_core::version::load(std::path::Path::new(".")),
            sync,
            RemotePip::new(client, false).governed_by(options.clone()),
            Arc::new(HttpsListener::new("", "", 0, 1000, None)),
        ))
    }

    fn ask(
        pep: &Arc<Pep>,
        method: Method,
        path: &str,
        transport: Transport,
    ) -> (StatusCode, String) {
        let (status, _, body) = answer(pep, method, path, transport, &[], "");
        (status, body)
    }

    /// One request with `headers`, answered whole: status, headers, body.
    fn answer(
        pep: &Arc<Pep>,
        method: Method,
        path: &str,
        transport: Transport,
        headers: &[(&str, &str)],
        body: &str,
    ) -> (StatusCode, axum::http::HeaderMap, String) {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let mut builder = Request::builder().method(method).uri(path);
            for (name, value) in headers {
                builder = builder.header(*name, *value);
            }
            let mut request =
                builder.body(Body::from(body.to_string())).unwrap();
            request.extensions_mut().insert(transport);
            let response = pep.clone().handle(request).await;
            let status = response.status();
            let headers = response.headers().clone();
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap_or_default();
            (status, headers, String::from_utf8_lossy(&bytes).to_string())
        })
    }

    /// THE ANSWERS ARE THE MODEL'S (#1830): every JSON answer this handler
    /// gives is read by the type `models/pep/pep_service.tsp` generates into
    /// `sts-model-pep`, whose objects are closed, so a member the code adds,
    /// drops or retypes and the model does not fails here.
    #[test]
    fn the_answers_are_the_model_s() {
        use sts_model_pep::pep_service::{components, read_answer};
        let pep = a_pep();
        let https = Transport {
            https: true,
            ..Transport::default()
        };
        let json = |text: &str| -> serde_json::Value {
            serde_json::from_str(text).unwrap()
        };
        for (operation, path) in
            [("getOverview", "/"), ("getHealthcheck", "/healthcheck")]
        {
            let (status, body) = ask(&pep, Method::GET, path, https.clone());
            assert_eq!(status, StatusCode::OK, "{}", path);
            let read = read_answer(operation, 200, &json(&body));
            assert!(
                matches!(read, Some(Ok(()))),
                "{}: {:?}\n{}",
                path,
                read,
                body
            );
        }
        let (status, body) = ask(
            &pep,
            Method::GET,
            "/protected?subject=alice&employeeType=staff",
            https.clone(),
        );
        assert_eq!(status, StatusCode::FORBIDDEN, "no policy is held");
        let decision: components::Decision =
            serde_json::from_value(json(&body)).unwrap();
        assert!(!decision.allowed && decision.note.is_some());
        for (method, path, transport) in [
            (Method::GET, "/nowhere", https.clone()),
            (Method::GET, "/crl/root.crl", https.clone()),
            (Method::POST, "/notify", Transport::default()),
            (
                Method::GET,
                "/",
                Transport {
                    crl_only: true,
                    ..Transport::default()
                },
            ),
        ] {
            let (status, body) = ask(&pep, method, path, transport);
            assert_eq!(status, StatusCode::NOT_FOUND, "{}", path);
            let refusal: Result<components::NotFound, _> =
                serde_json::from_value(json(&body));
            assert!(refusal.is_ok(), "{}: {}", path, body);
        }
    }

    /// THE NUDGE IS HTTPS ONLY (2026-11-14): over plain HTTP it is refused
    /// with a sentence naming the HTTPS listener; over HTTPS it is 204.
    #[test]
    fn the_nudge_is_answered_on_https_only() {
        let pep = a_pep();
        let (plain, body) =
            ask(&pep, Method::POST, "/notify", Transport::default());
        assert_eq!(plain, StatusCode::NOT_FOUND);
        assert!(body.contains("HTTPS listener only"), "{}", body);
        let https = Transport {
            https: true,
            ..Transport::default()
        };
        // The service's nudge, `full` included (#1829), is the model's
        // `Nudge`, and is answered as any nudge is.
        let sent = r#"{"event":"policy-repository-changed","at":"2026-11-16T00:00:00.000Z","pdp":"","full":true}"#;
        let nudge: sts_model_pep::pep_service::components::Nudge =
            serde_json::from_str(sent).unwrap();
        assert_eq!(nudge.full, Some(true));
        let (secure, headers, body) =
            answer(&pep, Method::POST, "/notify", https, &[], sent);
        assert_eq!(secure, StatusCode::NO_CONTENT);
        // A 204 has no content, so no Content-Type (#1830).
        assert!(body.is_empty());
        assert!(headers.get(header::CONTENT_TYPE).is_none(), "{:?}", headers);
        assert_eq!(
            headers.get(header::CACHE_CONTROL).map(|v| v.as_bytes()),
            Some(&b"no-store"[..])
        );
    }

    /// A PEP that has pulled (no policies) and holds an AuthZEN catalogue,
    /// its env listener asking for no client certificate and no identifier
    /// set: the edge PDP reaches its admission and its metadata.
    fn a_ready_pep() -> Arc<Pep> {
        let mut options = Options::from_env("0.0.0");
        options.pdp_url = "http://127.0.0.1:9".into();
        options.pip_enabled = false;
        options.authzen_enabled = true;
        options.authzen_pdp_identifier = String::new();
        options.authzen_callers_configured = false;
        let client = PdpClient::new(&options).unwrap();
        let sync = Arc::new(Sync::new(client.clone(), options.clone()));
        sync.load_for_test(&json!({ "syncToken": "p1", "policies": [] }));
        sync.load_catalogue_for_test(&json!({
            "syncToken": "c1", "realm": "", "apiObject": "sts-authzen-api",
            "rows": [], "settings": { "enabled": true, "batchEnabled": true }
        }));
        Arc::new(Pep::new(
            options.clone(),
            sts_core::version::load(std::path::Path::new(".")),
            sync,
            RemotePip::new(client, false).governed_by(options.clone()),
            Arc::new(HttpsListener::new("", "", 0, 1000, None)),
        ))
    }

    /// GET / REPORTS THE VALUES IN FORCE (#1830): the managed `authzen` and
    /// `authzenPdpIdentifier` once the service sets them, and the
    /// environment's again when it clears them.
    #[test]
    fn the_overview_reports_the_authzen_values_in_force() {
        let pep = a_pep();
        let https = Transport {
            https: true,
            ..Transport::default()
        };
        let env = pep.options.authzen_enabled;
        let overview = |pep: &Arc<Pep>| -> Value {
            let (_, body) = ask(pep, Method::GET, "/", https.clone());
            serde_json::from_str(&body).unwrap()
        };
        let before = overview(&pep);
        assert_eq!(before["authzen"]["enabled"], json!(env));
        pep.options.managed.apply(Managed::parse(
            "t",
            true,
            &json!({ "authzen": !env,
                     "authzenPdpIdentifier": "https://pdp.example" }),
        ));
        let after = overview(&pep);
        assert_eq!(after["authzen"]["enabled"], json!(!env));
        assert_eq!(after["authzen"]["pdpIdentifier"], "https://pdp.example");
        assert_eq!(
            after["settings"]["values"]["authzen"]["value"],
            json!(!env),
            "the same value settings.values reports"
        );
        pep.options.managed.apply(Managed::default());
        assert_eq!(overview(&pep)["authzen"]["enabled"], json!(env));
    }

    /// HEAD IS GET WITHOUT THE BODY (#1830) for every GET but /protected,
    /// whose GET is a decision; HEAD /protected is the generic 404.
    #[test]
    fn head_is_get_without_the_body() {
        let pep = a_ready_pep();
        let https = Transport {
            https: true,
            ..Transport::default()
        };
        for path in [
            "/",
            "/healthcheck",
            "/crl/root.crl",
            "/.well-known/authzen-configuration",
        ] {
            let (get, get_headers, body) = answer(
                &pep,
                Method::GET,
                path,
                https.clone(),
                &[("host", "pep.example:9443")],
                "",
            );
            let (head, headers, empty) = answer(
                &pep,
                Method::HEAD,
                path,
                https.clone(),
                &[("host", "pep.example:9443")],
                "",
            );
            assert_eq!(head, get, "{}", path);
            assert!(empty.is_empty(), "{}: {}", path, empty);
            assert_eq!(
                headers.get(header::CONTENT_TYPE),
                get_headers.get(header::CONTENT_TYPE),
                "{}",
                path
            );
            if path != "/" {
                // The overview's clock moves between the two requests.
                assert_eq!(
                    headers
                        .get(header::CONTENT_LENGTH)
                        .and_then(|v| v.to_str().ok()),
                    Some(body.len().to_string().as_str()),
                    "{}",
                    path
                );
            }
        }
        let (status, _, body) =
            answer(&pep, Method::HEAD, "/protected", https.clone(), &[], "");
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.is_empty());
        let (status, _) = ask(&pep, Method::HEAD, "/notify", https);
        assert_eq!(status, StatusCode::NOT_FOUND);
        // The CRL-only listener answers a HEAD of a CRL path as its GET.
        let crl = Transport {
            crl_only: true,
            ..Transport::default()
        };
        let (status, body) = ask(&pep, Method::HEAD, "/healthcheck", crl);
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.is_empty());
    }

    /// THE METADATA OVER HTTP/2 (#1830): no `Host`, the authority in the
    /// URI, as hyper hands an h2 request's `:authority` over; `Host` wins
    /// when both are there; neither is still STS-XPEP-0045's 404.
    #[test]
    fn the_metadata_names_the_authority_an_h2_client_sends() {
        use sts_model_pep::pep_authzen::read_answer;
        let pep = a_ready_pep();
        let https = Transport {
            https: true,
            ..Transport::default()
        };
        let url = "https://pep.example:9443/.well-known/authzen-configuration";
        let (status, _, body) =
            answer(&pep, Method::GET, url, https.clone(), &[], "");
        assert_eq!(status, StatusCode::OK, "{}", body);
        let said: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(said["policy_decision_point"], "https://pep.example:9443");
        let read = read_answer("getAuthzenConfiguration", 200, &said);
        assert!(matches!(read, Some(Ok(()))), "{:?}", read);
        let (_, _, body) = answer(
            &pep,
            Method::GET,
            url,
            https.clone(),
            &[("host", "front.example")],
            "",
        );
        let said: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(said["policy_decision_point"], "https://front.example");
        let (status, _) = ask(
            &pep,
            Method::GET,
            "/.well-known/authzen-configuration",
            https,
        );
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// ADMISSION ASKS THE LISTENER THE REQUEST ARRIVED ON (#1830): the
    /// environment's listener here verifies nothing, and a request that
    /// came in on a listener that does is admitted past STS-XPEP-0039 (to
    /// 0050, no caller list pulled yet); one on a listener that does not is
    /// 0039, and plain HTTP is answered by the environment's as before.
    #[test]
    fn admission_asks_the_listener_the_request_arrived_on() {
        let pep = a_ready_pep();
        let body = r#"{"subject":{"type":"user","id":"a"},"action":{"name":"r"},"resource":{"type":"t","id":"1"}}"#;
        let peer = Some(crate::listener::Peer {
            sha256: "ab".repeat(32),
            subject: "CN=caller".into(),
            verified: true,
            why: String::new(),
        });
        let on = |verifies: bool| Transport {
            https: true,
            peer: peer.clone(),
            verifies_client_certificates: verifies,
            ..Transport::default()
        };
        let path = "/access/v1/evaluation";
        let (status, _, said) =
            answer(&pep, Method::POST, path, on(true), &[], body);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{}", said);
        assert!(said.contains("not yet pulled"), "{}", said);
        let (status, _, said) =
            answer(&pep, Method::POST, path, on(false), &[], body);
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(said.contains("arrived on asks"), "{}", said);
        let (status, _, said) =
            answer(&pep, Method::POST, path, Transport::default(), &[], body);
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(said.contains("arrived on asks"), "{}", said);
    }

    /// THE CRL-ONLY LISTENER answers GET /crl/<name> and nothing else.
    #[test]
    fn the_crl_only_listener_serves_crls_alone() {
        let pep = a_pep();
        let crl = Transport {
            crl_only: true,
            ..Transport::default()
        };
        for (method, path) in [
            (Method::GET, "/"),
            (Method::GET, "/protected"),
            (Method::GET, "/healthcheck"),
            (Method::POST, "/notify"),
        ] {
            let (status, body) = ask(&pep, method, path, crl.clone());
            assert_eq!(status, StatusCode::NOT_FOUND, "{}", path);
            assert!(
                body.contains("only this PEP's own credential's CRLs"),
                "{}: {}",
                path,
                body
            );
        }
        let (status, body) = ask(&pep, Method::GET, "/crl/root.crl", crl);
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(
            !body.contains("only this PEP's own credential's CRLs"),
            "a CRL path is the CRL lookup's to answer: {}",
            body
        );
    }
}
