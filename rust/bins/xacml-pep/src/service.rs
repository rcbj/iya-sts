// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The PEP's endpoints, decided by ONE handler whatever the transport — two
//! listeners that answered differently would be two enforcement points
//! sharing a process.
//!
//! ```text
//! GET  /              what this PEP is, what it holds, what it has enforced
//! GET  /protected     THE RESOURCE. 200 or 403, decided here
//! POST /notify        the PDP's nudge: pull now
//! GET  /healthcheck   liveness, never whether the policy is current
//! GET  /crl/<name>    this PEP's own credential's CRLs (#174)
//! ```

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
use sts_xacml::request::{ResolvedObligation, Status};

use crate::enforce::Enforcer;
use crate::listener::HttpsListener;
use crate::options::Options;
use crate::pip::RemotePip;
use crate::sync::Sync;

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
    pip: RemotePip,
    enforcer: Enforcer,
    pdp: Pdp,
    pub listener: Arc<HttpsListener>,
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

fn status_json(status: &Status) -> Value {
    match &status.message {
        Some(message) => json!({ "code": status.code.uri(),
                                 "message": message }),
        None => json!({ "code": status.code.uri() }),
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
        Pep {
            enforcer: Enforcer::new(options.bias),
            options,
            version,
            sync,
            pip,
            pdp: Pdp::new(),
            listener,
            last_pip_report: Mutex::new(None),
            crl_name: Regex::new(r"(?i)^[a-z0-9-]+\.crl$").ok(),
        }
    }

    /// ONE HANDLER FOR BOTH LISTENERS. No `instrument` on it: it is the hot
    /// path of the container and would drown its log.
    pub async fn handle(
        self: Arc<Self>,
        request: Request<Body>,
    ) -> Response<Body> {
        let method = request.method().clone();
        let uri = request.uri().clone();
        let path = uri.path().to_string();
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
        if method == Method::POST && path == "/notify" {
            // THE NUDGE: answered 204 IMMEDIATELY and pulled after, and its
            // body is neither read nor trusted — what changed is discovered
            // by pulling from this PEP's own configured PDP.
            tracing::info!(
                "xacml-pep: nudged by the PDP; pulling now rather than \
                 waiting up to {}ms for the next poll. Nothing in the nudge \
                 was read — what changed is discovered by pulling.",
                self.options.poll_interval_ms
            );
            let sync = self.sync.clone();
            tokio::spawn(async move {
                if !sync.pull("nudge").await {
                    tracing::warn!(
                        "{}xacml-pep: the nudged pull failed. The scheduled \
                         poll will try again.",
                        tag("STS-XPEP-0010")
                    );
                }
            });
            let mut response =
                json_response(StatusCode::NO_CONTENT, &json!({}));
            *response.body_mut() = Body::empty();
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
                    POST /notify, GET /healthcheck and GET /crl/<name> for its \
                    own credential's lists."
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

    /// A decision here, with what was pulled — and the remote PIP asked
    /// BEFORE evaluation, because the engine's resolver is synchronous.
    async fn decide(&self, query: &IndexMap<String, String>) -> Answer {
        let (policies, loaded) = self.sync.current();
        let Some(root) = policies.root.as_ref().filter(|_| loaded) else {
            tracing::warn!(
                "{}xacml-pep: a decision was asked for and this PEP holds no \
                 root policy, so it is NotApplicable and the {} bias settles \
                 it.",
                tag("STS-XPEP-0005"),
                self.options.bias.as_str()
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
        let get = |k: &str| query.get(k).cloned().unwrap_or_default();
        let subject = get("subject");
        let resource = query
            .get("resource")
            .filter(|r| !r.is_empty())
            .cloned()
            .or_else(|| {
                Some(self.options.resource.clone()).filter(|r| !r.is_empty())
            })
            .unwrap_or_else(|| "urn:xacml-pep:protected".to_string());
        let action = query
            .get("action")
            .filter(|a| !a.is_empty())
            .cloned()
            .unwrap_or_else(|| "GET".to_string());
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
        let resolution = self
            .pip
            .resolver_for(&request, root, &policies.repository)
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
        let response = self.pdp.evaluate(root, &request, &options);
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
                self.options.bias.as_str()
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
        let outcome =
            self.enforcer.enforce(answer.decision, &answer.obligations);
        self.sync.count_decision(&outcome);
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

    /// `GET /`. Staleness is computed HERE and separately from the PDP's
    /// verdict on purpose: this PEP counts missed polls and the PDP counts
    /// missed heartbeats, and the two can disagree.
    fn overview(&self) -> Value {
        let o = &self.options;
        let stale_after_ms = o.poll_interval_ms * 3;
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
                "credentialed": o.client_certificate.is_some(),
                "lastQuery": last_query,
                "what": pip_what
            },
            "version": v.version,
            "build": {
                "number": v.build,
                "commit": if v.commit.is_empty() { Value::Null }
                          else { Value::from(v.commit.clone()) },
                "at": v.built_at,
                "stamped": v.stamped,
                "what": "M.N comes from the same VERSION file the PDP's \
                         does, so a difference THERE is a PEP left behind \
                         across a release. The build number is per IMAGE: \
                         these are two artifacts and they differ unless the \
                         same BUILD_NUMBER was passed to both builds."
            },
            "pdp": o.pdp_url,
            "bias": o.bias.as_str(),
            "protectedAt": "/protected",
            "https": self.listener.overview(),
            "holding": self.sync.holding_json(),
            "stale": stale,
            "staleAfterMs": stale_after_ms,
            "registration": self.sync.registration_json(),
            "enforced": self.sync.counters_json(),
            "notify": if o.notify_url.is_empty() { Value::Null }
                      else { Value::from(o.notify_url.clone()) },
            "poll": { "intervalMs": o.poll_interval_ms,
                      "heartbeatMs": o.heartbeat_interval_ms },
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
