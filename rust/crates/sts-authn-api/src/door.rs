// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE DOOR (`authn/authn_api.ts`'s `AuthnApi`): the operation table, the
//! binding of an act, the ids, the bodies and queries held to the model,
//! and the answers held to it — the logic is [`crate::flow`]'s, as Node's
//! is `authn.ts`'s.
//!
//! EVERY ACT IS BOUND THREE WAYS (rcbj's decision 2 on #571), asked BEFORE
//! the pending id is looked up, so a request that is not bound learns
//! nothing about which ids are live:
//!
//! 1. the pending id in the path — the capability;
//! 2. `X-CSRF-Token`: `websecurity.tokenFor()` of the `sts_session`
//!    cookie's session id, HMAC-SHA256 under the cluster's `csrf` secret
//!    (`STS_CSRF_SECRET`, or one made for this process, as
//!    `cluster/cluster_secrets.ts` makes it), base64url — derived, never
//!    stored; a request with NO session is refused;
//! 3. `Content-Type: application/json` and an `Origin` this service
//!    answers on (`cors.ownOrigins()`).
//!
//! THE ORDER A REQUEST MEETS THINGS IN IS EXPRESS'S: the step id moved
//! from `X-Step-Id` into the path (#1454), the step claimed for the first
//! browser that asks (product), the route, the query and headers held to
//! the operation's declared parameters (#1483), the handler, and the
//! answer held to its model (#1353). A path no row routes is Express's 404.
//! An operation whose logic is not ported here yet answers that 404 too,
//! as `/admin-api`'s do (sts-mgmt-api), and the miss is logged.

use std::sync::Arc;

use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use serde_json::{json, Map, Value as Json};
use sts_authn::ports::Request;
use sts_core::errors::{codes, ErrorCode};

use crate::body;
use crate::flow::{Answer, Call, Fields, Outcome, SignIn, LOGIN_PATH};
use crate::model;
use crate::operations::{self, Access, Handler, Operation, OPERATIONS};

/// The API's base path (`authn.AUTHN_API_PATH`).
pub const API: &str = "/authn-api";
/// The header an act's CSRF token travels in.
pub const CSRF_HEADER: &str = "x-csrf-token";
/// The sign-on cookie (`authn.SESSION_COOKIE`).
pub const SESSION_COOKIE: &str = "sts_session";
/// The cookie a page's step id is left in where a link carries no header
/// (#1487, `common/step_address.ts`).
pub const STEP_COOKIE: &str = "sts_signin_step";

/// One request, as the door reads it. The realm prefix is already off
/// the path (the HTTP layer's first step), and `prefix` is it.
#[derive(Debug, Clone, Default)]
pub struct Arrived {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: HeaderMap,
    pub body: String,
    /// `baseUrlOf(req)`.
    pub base: String,
    pub prefix: String,
    /// `cors.ownOrigins(req)`.
    pub own_origins: Vec<String>,
    /// `clientAddress.of(req)`.
    pub address: String,
}

/// What the door answers before the HTTP layer's flush: the status, the
/// headers, the body and the code recorded.
#[derive(Debug, Clone)]
pub struct Sent {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub code: Option<ErrorCode>,
    /// The route did not answer: Express's 404.
    pub unrouted: bool,
}

/// `/authn-api`.
pub struct AuthnApi {
    pub signin: Arc<SignIn>,
    /// The `csrf` secret's text, as `clusterSecrets.get('csrf')` reads it.
    pub csrf_secret: String,
    /// The build's version, for the document.
    pub version: String,
    /// `global.https`, for the step cookie.
    pub https: bool,
    /// The sign-out's page operations, filled by the logout crate once it
    /// is built (a late binding: Node reaches the module by a lazy
    /// `require()`); empty, they are not answered here (Express's 404).
    pub sign_out: std::sync::OnceLock<Arc<dyn crate::ports::SignOutPages>>,
    /// The consent screen's operations, filled by the OAuth crate once it
    /// is built (a late binding, as the sign-out's); empty, they are not
    /// answered here.
    pub consent: std::sync::OnceLock<Arc<dyn crate::ports::ConsentPages>>,
}

fn header_of(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn text(v: Option<&Json>) -> String {
    match v {
        None | Some(Json::Null) => String::new(),
        Some(Json::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// `encodeURIComponent()`.
fn encode_component(s: &str) -> String {
    sts_credentials::totp::encode_uri_component(s)
}

/// `decodeURIComponent()`, or the text where it does not decode.
fn decode_component(s: &str) -> String {
    sts_http::cors::percent_decode_strict(s).unwrap_or_else(|| s.to_string())
}

impl Sent {
    /// An answer of the API: JSON, `no-store` (`answerJson()`).
    fn json(answer: &Answer) -> Sent {
        let mut headers = vec![
            (
                "content-type".to_string(),
                "application/json; charset=utf-8".to_string(),
            ),
            ("cache-control".to_string(), "no-store".to_string()),
        ];
        headers.extend(answer.headers.iter().cloned());
        for line in &answer.cookies {
            headers.push(("set-cookie".to_string(), line.clone()));
        }
        Sent {
            status: answer.status,
            headers,
            body: serde_json::to_string(&answer.body).unwrap_or_default(),
            code: answer.code,
            unrouted: false,
        }
    }

    fn unrouted() -> Sent {
        Sent {
            status: 404,
            headers: Vec::new(),
            body: String::new(),
            code: None,
            unrouted: true,
        }
    }

    /// The answer as axum sends it, marked with its code.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn into_response(self) -> Response {
        let mut response = Response::new(axum::body::Body::from(self.body));
        *response.status_mut() = StatusCode::from_u16(self.status)
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        for (name, value) in &self.headers {
            if let (Ok(n), Ok(v)) = (
                header::HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                response.headers_mut().append(n, v);
            }
        }
        match self.code {
            Some(code) => sts_http::mark(response, code),
            None => response,
        }
    }
}

/// `refuse(res, status, why)`: a refusal of the request itself, in the
/// vocabulary every refusal at these doors uses.
fn refuse(status: u16, why: &str, code: ErrorCode) -> Answer {
    Answer::json(
        status,
        json!({ "ok": false, "errors": [why], "error": "invalid_request",
                "error_description": why }),
    )
    .marked(code)
}

/// The id's schema (`SignInId`, #1579).
fn id_schema() -> Json {
    model::components()
        .pointer("/schemas/SignInId")
        .cloned()
        .unwrap_or(json!({ "type": "string" }))
}

/// A path id held to `SignInId`.
fn id_fits(id: &str) -> bool {
    let schema = json!({ "type": "object", "properties": { "id": id_schema() },
                         "required": ["id"] });
    body::check_parsed(&json!({ "id": id }), "params", &schema).is_ok()
}

impl AuthnApi {
    /// Fills the sign-out's page operations (once; a second fill is
    /// ignored and logged).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn set_sign_out(&self, pages: Arc<dyn crate::ports::SignOutPages>) {
        if self.sign_out.set(pages).is_err() {
            tracing::warn!("authn-api: the sign-out was filled twice.");
        }
    }

    /// Fills the consent screen's operations (once).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn set_consent(&self, pages: Arc<dyn crate::ports::ConsentPages>) {
        if self.consent.set(pages).is_err() {
            tracing::warn!("authn-api: the consent screen was filled twice.");
        }
    }

    /// `AuthnApi.consent()`: `GET` and `POST /authn-api/consent/{id}` — the
    /// id's shape, the binding of an act, the body; the record's three
    /// checks and what an answer does are the screen's.
    async fn consent_door(
        &self,
        op: &Operation,
        id: &str,
        arrived: &Arrived,
        call: &Call,
    ) -> Outcome {
        let done = Outcome::Answered;
        let Some(pages) = self.consent.get() else {
            return Outcome::Unported("consent");
        };
        if !id_fits(id) {
            return done(refuse(
                400,
                "That is not the id of a consent.",
                codes::STS_OAUTH_0148,
            ));
        }
        if arrived.method.eq_ignore_ascii_case("GET") {
            return done(match pages.view(call, id) {
                Err((code, why)) => refuse(400, &why, code),
                Ok((view, ui, username)) => {
                    let mut out = json!({ "ok": true, "view": view,
                                          "csrf": self.csrf_of(&call.request),
                                          "uiLocales": ui });
                    if let Some(own) =
                        self.signin.facts.preferred_language_of(&username)
                    {
                        out["preferredLanguage"] = own;
                    }
                    Answer::json(200, out)
                }
            });
        }
        if let Err(a) = self.bound(arrived, &call.request) {
            return done(a);
        }
        let body = match self.body_of(arrived, op) {
            Ok(b) => b,
            Err(mut a) => {
                a.code = Some(codes::STS_OAUTH_0148);
                return done(a);
            }
        };
        let action = text(body.get("action"));
        let acted = pages.act(call, id, &action);
        pages.settle().await;
        done(match acted {
            crate::ports::ConsentAnswer::Refused { code, why } => Answer::json(
                400,
                json!({ "ok": false, "next": "refused", "errors": [why],
                            "error": "invalid_request",
                            "error_description": why }),
            )
            .marked(code),
            crate::ports::ConsentAnswer::Back {
                target,
                username,
                code,
            } => {
                let target = self.signin.sessions.account_ticket_for(
                    &call.request,
                    &target,
                    &json!({ "loginHint": username }),
                );
                let mut a = Answer::json(
                    200,
                    json!({ "ok": true, "next": "redirect",
                            "location": self.signin.location_of(call, &target) }),
                );
                a.code = code;
                a
            }
        })
    }

    /// `logoutView()` / `logoutAccountsView()`: the query held to the
    /// model, then the sign-out's view, with the CSRF token and, for the
    /// inventory, the person's preferred language.
    fn logout_view(
        &self,
        op: &Operation,
        query: &str,
        call: &Call,
        pages: &Arc<dyn crate::ports::SignOutPages>,
    ) -> Answer {
        let schema = query_schema(op);
        let asked = sts_mgmt_api::request::parse_query(query);
        let asked = Json::Object(asked.into_iter().collect());
        let value = match body::check_parsed(&asked, "query", &schema) {
            Ok(v) => v,
            Err(p) => {
                let why = if p.detail.is_empty() {
                    "The query is refused.".to_string()
                } else {
                    p.detail
                };
                return refuse(400, &why, codes::STS_LOGOUT_0003);
            }
        };
        let accounts = op.handler == Handler::LogoutAccountsView;
        let mut seen = if accounts {
            pages.accounts_view(call, &value)
        } else {
            pages.view(call, &value)
        };
        if let Some(o) = seen.body.as_object_mut() {
            o.insert("csrf".into(), json!(self.csrf_of(&call.request)));
        }
        if !accounts {
            let username =
                text(seen.body.get("view").and_then(|v| v.get("username")));
            if !username.is_empty() {
                if let Some(own) =
                    self.signin.facts.preferred_language_of(&username)
                {
                    seen.body["preferredLanguage"] = own;
                }
            }
        }
        seen
    }

    /// `csrfOf(req)`: the token of the session behind the cookie, or ''.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn csrf_of(&self, request: &Request) -> String {
        match self
            .signin
            .sessions
            .cookie_session(Some(request), SESSION_COOKIE)
        {
            Some((id, _)) if !id.is_empty() => self.token_for(&id),
            _ => String::new(),
        }
    }

    /// `websecurity.tokenFor(sessionId)`.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn token_for(&self, id: &str) -> String {
        match sts_crypto::raw_sig::hmac_sha256(
            self.csrf_secret.as_bytes(),
            id.as_bytes(),
        ) {
            Ok(mac) => sts_crypto::b64::encode(&mac),
            Err(e) => {
                tracing::error!(
                    "{}authn-api: a CSRF token could not be made: {}",
                    sts_core::log::tag(codes::STS_AUTHN_0328),
                    e
                );
                String::new()
            }
        }
    }

    /// `bound(req, res)`: JSON, an origin of this service, and the token
    /// of the cookie's session.
    fn bound(
        &self,
        arrived: &Arrived,
        request: &Request,
    ) -> Result<(), Answer> {
        let kind = header_of(&arrived.headers, "content-type");
        let json_type = {
            let lower = kind.to_ascii_lowercase();
            lower.strip_prefix("application/json").is_some_and(|rest| {
                let rest = rest.trim_start();
                rest.is_empty() || rest.starts_with(';')
            })
        };
        if !json_type {
            return Err(refuse(
                415,
                "This operation takes a JSON body (Content-Type: application/json).",
                codes::STS_AUTHN_0325,
            ));
        }
        let origin = header_of(&arrived.headers, "origin");
        if origin.is_empty() || !arrived.own_origins.contains(&origin) {
            return Err(refuse(
                403,
                &format!(
                    "This operation is sent by a page of this service: the \
                     request carried {}.",
                    if origin.is_empty() {
                        "no Origin"
                    } else {
                        "another origin"
                    }
                ),
                codes::STS_AUTHN_0326,
            ));
        }
        let expected = self.csrf_of(request);
        let presented = header_of(&arrived.headers, CSRF_HEADER);
        // NO SESSION BECAUSE THE REALM IS FULL (Node's fix of 2026-11-14,
        // #444 D12): a browser arriving at `authn.maxSessions` was given no
        // session, so "Load the sign-in page again" was untrue — a reload
        // is refused the same way until a session ends. Said as it is,
        // under the cap's code, with the status every operation declares.
        if expected.is_empty() && self.signin.sessions.realm_at_session_cap() {
            return Err(refuse(
                403,
                "This realm is holding as many sign-in sessions as it \
                 allows, so no new one can start in this browser now. Try \
                 again later.",
                codes::STS_AUTHN_0337,
            ));
        }
        if expected.is_empty()
            || presented.is_empty()
            || !sts_crypto::secrets::constant_time_equals(
                presented.as_bytes(),
                expected.as_bytes(),
            )
        {
            return Err(refuse(
                403,
                if expected.is_empty() {
                    "This browser holds no session for this sign-in. Load the \
                     sign-in page again."
                } else {
                    "The x-csrf-token header is missing or is not this \
                     browser's. Load the sign-in page again."
                },
                codes::STS_AUTHN_0327,
            ));
        }
        Ok(())
    }

    /// `bodyOf(req, res, op)`: the body held to the operation's model.
    fn body_of(
        &self,
        arrived: &Arrived,
        op: &Operation,
    ) -> Result<Map<String, Json>, Answer> {
        let parsed: Json = serde_json::from_str(if arrived.body.is_empty() {
            "{}"
        } else {
            &arrived.body
        })
        .ok()
        .filter(Json::is_object)
        .unwrap_or_else(|| json!({}));
        let empty = json!({ "type": "object", "properties": {},
                            "additionalProperties": false });
        let schema = model::body_schema(op).cloned().unwrap_or(empty);
        body::check_parsed(&parsed, "body", &schema).map_err(|refused| {
            let code = op.refused_code.unwrap_or(match op.access {
                Access::Step => codes::STS_AUTHN_0145,
                Access::Mfa => codes::STS_AUTHN_0330,
                _ => codes::STS_AUTHN_0002,
            });
            refuse(400, &refused.detail, code)
        })
    }

    /// `idOf(req, res)`.
    fn id_of(id: &str) -> Result<String, Answer> {
        if id_fits(id) {
            Ok(id.to_string())
        } else {
            Err(refuse(
                400,
                "That is not the id of a sign-in.",
                codes::STS_AUTHN_0001,
            ))
        }
    }

    /// `pendingOf(req, res)`.
    fn pending_of(&self, id: &str) -> Result<Json, Answer> {
        let id = AuthnApi::id_of(id)?;
        self.signin.pending_for(&id).ok_or_else(|| {
            refuse(
                400,
                "There is no sign-in waiting under that id, or it has expired. \
                 Start the request again from the application that sent you \
                 here.",
                codes::STS_AUTHN_0003,
            )
        })
    }

    /// `stepOf(req, res)`: the forced password change's step.
    fn step_of(&self, id: &str) -> Result<Json, Answer> {
        if !id_fits(id) {
            return Err(refuse(
                400,
                "That is not the id of a password change.",
                codes::STS_AUTHN_0145,
            ));
        }
        self.signin.password_change_step(id)
    }

    /// `flagOf(value)`: a JSON flag as the form's `'1'`.
    fn flag_of(value: Option<&Json>) -> String {
        let t = text(value).to_ascii_lowercase();
        if ["true", "1", "on", "yes"].contains(&t.as_str()) {
            "1".into()
        } else {
            String::new()
        }
    }

    fn call_of(&self, arrived: &Arrived) -> Call {
        let mut request = Request {
            cookie: header_of(&arrived.headers, "cookie"),
            user_agent: header_of(&arrived.headers, "user-agent"),
            address: arrived.address.clone(),
            url: if arrived.query.is_empty() {
                arrived.path.clone()
            } else {
                format!("{}?{}", arrived.path, arrived.query)
            },
            ..Request::default()
        };
        request.accounts.lock().response_open = true;
        // A SELECTION TICKET IS TAKEN OFF EVERY REQUEST FIRST (#561),
        // before any route reads the query.
        self.signin.sessions.spend_account_ticket(&mut request);
        if request.address.is_empty() {
            request.address = "unknown".into();
        }
        Call {
            request,
            base: arrived.base.clone(),
            prefix: arrived.prefix.clone(),
        }
    }

    /// The step id a page sent in `X-Step-Id` put into the path, and the
    /// three names `X-Step-Query` carries put into the query (#1454).
    fn rewritten(arrived: &Arrived) -> (String, String) {
        let mut path = arrived.path.clone();
        let id = header_of(&arrived.headers, "x-step-id");
        if !id.is_empty() {
            for kind in ["mfa", "pending", "password-change", "consent"] {
                let at = format!("{}/{}/-", API, kind);
                if let Some(rest) = path.strip_prefix(&at) {
                    if rest.is_empty()
                        || rest.starts_with('/')
                        || rest.starts_with('?')
                    {
                        path = format!(
                            "{}/{}/{}{}",
                            API,
                            kind,
                            encode_component(&id),
                            rest
                        );
                        break;
                    }
                }
            }
        }
        let mut query = arrived.query.clone();
        let asked = header_of(&arrived.headers, "x-step-query");
        if !asked.is_empty() {
            let given = sts_mgmt_api::request::parse_query(&asked);
            let mut present = sts_mgmt_api::request::parse_query(&query);
            for name in ["authn", "mfa", "enrol"] {
                if let Some(v) = given.get(name) {
                    let value = match v {
                        Json::Array(l) => {
                            l.last().cloned().unwrap_or(Json::Null)
                        }
                        one => one.clone(),
                    };
                    present.insert(name.to_string(), value);
                }
            }
            query = present
                .iter()
                .map(|(k, v)| {
                    let one = |x: &Json| {
                        format!(
                            "{}={}",
                            encode_component(k),
                            encode_component(&text(Some(x)))
                        )
                    };
                    match v {
                        Json::Array(l) => {
                            l.iter().map(one).collect::<Vec<_>>().join("&")
                        }
                        x => one(x),
                    }
                })
                .collect::<Vec<_>>()
                .join("&");
        }
        (path, query)
    }

    /// The browser binding of a step (#1454), in product: `None` to go on,
    /// or the refusal; a pending view also leaves the id in the step
    /// cookie (#1487).
    fn browser_binding(
        &self,
        path: &str,
        query: &str,
        arrived: &Arrived,
        call: &Call,
    ) -> (Option<Answer>, Vec<String>) {
        let mut cookies = Vec::new();
        let rest = match path.strip_prefix(&format!("{}/", API)) {
            Some(r) => r,
            None => return (None, cookies),
        };
        let mut parts = rest.splitn(3, '/');
        let kind = parts.next().unwrap_or("");
        let Some(id_raw) = parts.next().filter(|i| !i.is_empty()) else {
            return (None, cookies);
        };
        if !["mfa", "pending", "password-change", "consent"].contains(&kind) {
            return (None, cookies);
        }
        let id = decode_component(id_raw);
        let q = sts_mgmt_api::request::parse_query(query);
        let opened = path.ends_with("/email-link/open")
            || q.get("page").map(|p| text(Some(p)))
                == Some("email-link-open".into());
        if opened || !self.signin.facts.predicate("bindsSignInSteps") {
            return (None, cookies);
        }
        if kind == "pending"
            && arrived.method.eq_ignore_ascii_case("GET")
            && self.signin.facts.predicate("hidesStepIds")
            && id != "-"
        {
            cookies.push(format!(
                "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600{}",
                STEP_COOKIE,
                encode_component(&id),
                if self.https { "; Secure" } else { "" }
            ));
        }
        let sid = self
            .signin
            .sessions
            .cookie_session(Some(&call.request), SESSION_COOKIE)
            .map(|(id, _)| id)
            .unwrap_or_default();
        // THE CONSENT SCREEN'S CLAIM is the screen's own
        // (`consent_screen.claimForBrowser()`).
        let held = if kind == "consent" {
            match self.consent.get() {
                Some(pages) => pages.claim(&id, &sid, call),
                None => return (None, cookies),
            }
        } else {
            self.signin.claim_step_for_browser(&id, &sid, kind)
        };
        if !held {
            return (
                Some(refuse(
                    400,
                    "That sign-in was started in another browser.",
                    codes::STS_AUTHN_0552,
                )),
                cookies,
            );
        }
        (None, cookies)
    }

    /// `shapeRefused(req, res, op)`: a query name the operation does not
    /// declare, a value its type does not hold, a custom header nobody
    /// defined (#1483).
    fn shape_refused(
        op: &Operation,
        query: &str,
        headers: &HeaderMap,
    ) -> Option<Answer> {
        let parameters = model::parameters_of(op);
        let parsed = sts_mgmt_api::request::parse_query(query);
        if let Some((code, sentence)) =
            sts_mgmt_api::request::check_declared(&parameters, &parsed)
        {
            let ours = if code == codes::STS_API_0142 {
                codes::STS_AUTHN_0553
            } else {
                codes::STS_AUTHN_0554
            };
            return Some(refuse(400, &sentence, ours));
        }
        let names: Vec<String> =
            headers.keys().map(|k| k.as_str().to_string()).collect();
        if let Some(sentence) = sts_mgmt_api::request::check_headers(
            &parameters,
            names.iter().map(String::as_str),
        ) {
            return Some(refuse(400, &sentence, codes::STS_AUTHN_0555));
        }
        None
    }

    /// One request under `/authn-api`, answered as Node answers it.
    #[tracing::instrument(level = "debug", skip_all, fields(method = %arrived.method, path = %arrived.path))]
    pub async fn serve(&self, arrived: &Arrived) -> Sent {
        // The passkey profile a door selects is the request's own (Node's
        // `byRequest`): nothing selected by the previous one is read.
        sts_credentials::webauthn::policy::clear_selection();
        let call = self.call_of(arrived);
        let mut arrived = arrived.clone();
        arrived.query = without_ticket(&arrived.query);
        let arrived = &arrived;
        let (path, query) = AuthnApi::rewritten(arrived);
        let (bound, mut cookies) =
            self.browser_binding(&path, &query, arrived, &call);
        let answer = match bound {
            Some(refused) => Some(refused),
            None => match operations::matching(&arrived.method, &path) {
                None => None,
                Some((op, param)) => {
                    let param = param.ok().flatten().unwrap_or_default();
                    match AuthnApi::shape_refused(op, &query, &arrived.headers)
                    {
                        Some(refused) => Some(refused),
                        None => match self
                            .handle(op, &param, &query, arrived, &call)
                            .await
                        {
                            Outcome::Answered(a) => Some(a),
                            Outcome::Unported(what) => {
                                tracing::info!(
                                    "authn-api: {} ({}) is not answered by \
                                     this runtime yet; Express's 404.",
                                    op.id,
                                    what
                                );
                                None
                            }
                        },
                    }
                }
            },
        };
        let Some(mut answer) = answer else {
            return Sent::unrouted();
        };
        cookies.append(&mut answer.cookies);
        cookies.append(&mut call.request.accounts.take_appended());
        answer.cookies = cookies;
        let sent = Sent::json(&answer);
        // EVERY ANSWER IS HELD TO ITS MODEL (#1353).
        if let Some(problem) = model::problem_of(
            &arrived.method,
            &path,
            sent.status,
            "application/json",
            sent.body.as_bytes(),
        ) {
            model::report(&problem);
            return Sent {
                status: 500,
                headers: vec![
                    (
                        "content-type".into(),
                        "application/json; charset=utf-8".into(),
                    ),
                    ("cache-control".into(), "no-store".into()),
                ],
                body: model::FAILED_BODY.into(),
                code: Some(codes::STS_API_0139),
                unrouted: false,
            };
        }
        sent
    }

    async fn handle(
        &self,
        op: &Operation,
        id: &str,
        query: &str,
        arrived: &Arrived,
        call: &Call,
    ) -> Outcome {
        let done = |a: Answer| Outcome::Answered(a);
        match op.handler {
            Handler::Index => done(self.index()),
            Handler::OpenApi => done(Answer::json(
                200,
                model::served(&arrived.base, &self.version),
            )),
            Handler::Screen => match self.pending_of(id) {
                Err(a) => done(a),
                Ok(record) => {
                    let problem = SignIn::screen_problem(&record);
                    let mut out = json!({ "ok": true,
                        "view": self.signin.screen_view(call, &record, &problem),
                        "csrf": self.csrf_of(&call.request),
                        "uiLocales": text(record.get("uiLocales")) });
                    if let Some(own) = self.signin.facts.preferred_language_of(
                        &text(record.get("lockedUsername")),
                    ) {
                        out["preferredLanguage"] = own;
                    }
                    done(Answer::json(200, out))
                }
            },
            Handler::Partners => match self.pending_of(id) {
                Err(a) => done(a),
                Ok(record) => {
                    // The federation partners are the federation slice's;
                    // with none configured fewer than two are left, and
                    // Node sends the browser to the screen.
                    let partners = record
                        .get("federation")
                        .and_then(|f| f.get("partners"))
                        .and_then(Json::as_array)
                        .map_or(0, Vec::len);
                    if partners >= 2 {
                        return Outcome::Unported("selectIdpView");
                    }
                    done(Answer::json(
                        200,
                        json!({ "ok": true,
                        "go": format!("{}?authn={}", LOGIN_PATH, encode_component(&text(record.get("id")))) }),
                    ))
                }
            },
            Handler::Act => {
                if let Err(a) = AuthnApi::id_of(id) {
                    return done(a);
                }
                if let Err(a) = self.bound(arrived, &call.request) {
                    return done(a);
                }
                let body = match self.body_of(arrived, op) {
                    Ok(b) => b,
                    Err(a) => return done(a),
                };
                let record = match self.pending_of(id) {
                    Ok(r) => r,
                    Err(a) => return done(a),
                };
                let action = if op.action == Some("email") {
                    if text(body.get("kind")) == "link" {
                        "email-link"
                    } else {
                        "email-code"
                    }
                    .to_string()
                } else {
                    op.action.unwrap_or("").to_string()
                };
                let fields = Fields {
                    action,
                    username: text(body.get("username")),
                    password: text(body.get("password")),
                    use_webauthn: AuthnApi::flag_of(body.get("use_webauthn")),
                    webauthn_only: AuthnApi::flag_of(body.get("webauthn_only")),
                    remember_browser: AuthnApi::flag_of(
                        body.get("remember_browser"),
                    ),
                    device_fp: text(body.get("device_fp")),
                    passkey_credential: text(body.get("credential")),
                };
                let mut call = call.clone();
                call.request.device_fp = fields.device_fp.clone();
                self.signin.screen_act(&call, record, &fields).await
            }
            Handler::PasskeyOptions => {
                if let Err(a) = AuthnApi::id_of(id) {
                    return done(a);
                }
                if let Err(a) = self.bound(arrived, &call.request) {
                    return done(a);
                }
                if let Err(a) = self.body_of(arrived, op) {
                    return done(a);
                }
                let record = match self.pending_of(id) {
                    Ok(r) => r,
                    Err(a) => return done(a),
                };
                // EVERY CHALLENGE MINTED IS COUNTED, PER ADDRESS: a door of
                // its own (`passkey-options`), naming nobody.
                let allowed = self.signin.limits.attempt(
                    "passkey-options",
                    &call.request.address,
                    "",
                    &sts_credentials::limits::Limit::from_json(&Json::Null),
                );
                if !allowed.ok() {
                    let mut a = Answer::json(
                        429,
                        json!({ "ok": false, "next": "refused",
                                "errors": [text(allowed.value.get("detail"))] }),
                    )
                    .marked(codes::STS_AUTHN_0332);
                    let retry = text(allowed.value.get("retryAfterS"));
                    a.headers.push((
                        "retry-after".into(),
                        if retry.is_empty() || retry == "0" {
                            "60".into()
                        } else {
                            retry
                        },
                    ));
                    return done(a);
                }
                match self.signin.passkey_options(call, record) {
                    Ok(armed) => done(Answer::json(
                        200,
                        json!({ "ok": true, "challenge": armed["challenge"],
                                "rpId": armed["rpId"],
                                "options": armed["options"] }),
                    )),
                    Err((code, why)) => done(
                        Answer::json(
                            400,
                            json!({ "ok": false, "next": "refused",
                                    "errors": [why] }),
                        )
                        .marked(code),
                    ),
                }
            }
            Handler::PasswordChange => match self.step_of(id) {
                Err(a) => done(a),
                Ok(step) => {
                    let mut out = json!({ "ok": true,
                        "view": SignIn::password_change_view(id, &step),
                        "csrf": self.csrf_of(&call.request),
                        "uiLocales": step.get("authn").map(|a| text(a.get("uiLocales"))).unwrap_or_default() });
                    if let Some(own) = self
                        .signin
                        .facts
                        .preferred_language_of(&text(step.get("username")))
                    {
                        out["preferredLanguage"] = own;
                    }
                    done(Answer::json(200, out))
                }
            },
            Handler::ChangePassword | Handler::PasswordChangeStartOver => {
                if !id_fits(id) {
                    return done(refuse(
                        400,
                        "That is not the id of a password change.",
                        codes::STS_AUTHN_0145,
                    ));
                }
                if let Err(a) = self.bound(arrived, &call.request) {
                    return done(a);
                }
                let body = match self.body_of(arrived, op) {
                    Ok(b) => b,
                    Err(a) => return done(a),
                };
                let step = match self.step_of(id) {
                    Ok(s) => s,
                    Err(a) => return done(a),
                };
                if op.handler == Handler::PasswordChangeStartOver {
                    return done(
                        self.signin.password_change_start_over(call, id),
                    );
                }
                done(self.signin.password_change_act(
                    call,
                    id,
                    step,
                    &text(body.get("new_password")),
                    &text(body.get("confirm_password")),
                ))
            }
            Handler::MfaStep => self.mfa_step(op, id, query, call),
            Handler::MfaAct => {
                if let Err(a) = AuthnApi::id_of(id) {
                    return done(a);
                }
                if let Err(a) = self.bound(arrived, &call.request) {
                    return done(a);
                }
                let body = match self.body_of(arrived, op) {
                    Ok(b) => b,
                    Err(a) => return done(a),
                };
                match op.id {
                    "checkCode" => self.signin.mfa_totp_act(
                        call,
                        id,
                        &text(body.get("code")),
                    ),
                    "spendRecoveryCode" => self.signin.mfa_backup_code_act(
                        call,
                        id,
                        &text(body.get("code")),
                    ),
                    "checkFactorPassword" => {
                        self.signin
                            .mfa_password_act(
                                call,
                                id,
                                &text(body.get("password")),
                            )
                            .await
                    }
                    "startOver" => done(self.signin.mfa_start_over(call, id)),
                    "passkeyStepOptions" => self.signin.mfa_webauthn_options(
                        call,
                        id,
                        &text(body.get("key")),
                        &text(body.get("lane")),
                        &text(body.get("algorithms")),
                    ),
                    "finishPasskeyStep" => self.signin.mfa_webauthn_act(
                        call,
                        id,
                        &text(body.get("credential")),
                    ),
                    "beginAppEnrolment" => {
                        self.signin.mfa_setup_act(call, id, "totp", "")
                    }
                    "confirmAppEnrolment" => self.signin.mfa_setup_act(
                        call,
                        id,
                        "confirm",
                        &text(body.get("code")),
                    ),
                    "beginKeyEnrolment" => {
                        self.signin.mfa_setup_act(call, id, "webauthn", "")
                    }
                    "ignoreOffer" => {
                        self.signin.mfa_setup_act(call, id, "skip", "")
                    }
                    "registerPostLoginPasskey" => {
                        self.signin.post_login_act(call, id, "register")
                    }
                    "skipPostLoginActivity" => {
                        self.signin.post_login_act(call, id, "skip")
                    }
                    other => Outcome::Unported(
                        operations::by_id(other).map_or("mfaAct", |o| o.id),
                    ),
                }
            }
            Handler::AccountsList => {
                let sessions = &self.signin.sessions;
                let listed = sessions.browser_accounts(&call.request);
                let mut out = json!({ "ok": true });
                if let (Some(o), Some(l)) =
                    (out.as_object_mut(), listed.as_object())
                {
                    for (k, v) in l {
                        o.insert(k.clone(), v.clone());
                    }
                }
                if listed.get("enabled") == Some(&Json::Bool(true)) {
                    out["anotherAccount"] =
                        json!(format!("{}/portal?accounts=another", call.base));
                }
                out["csrf"] = json!(self.csrf_of(&call.request));
                done(Answer::json(200, out))
            }
            Handler::AccountsGet | Handler::AccountsPost => {
                self.accounts_door(op, id, arrived, call)
            }
            // The wallet's operations are OpenID4VP's (phase 9), the
            // sign-out's the logout slice's, the consent screen's the
            // OAuth slice's.
            Handler::Wallet => Outcome::Unported("wallet"),
            Handler::LogoutView
            | Handler::LogoutAct
            | Handler::LogoutAccountsView
            | Handler::LogoutAccountsAct => {
                let Some(pages) = self.sign_out.get() else {
                    return Outcome::Unported("logout");
                };
                if matches!(
                    op.handler,
                    Handler::LogoutView | Handler::LogoutAccountsView
                ) {
                    return done(self.logout_view(op, query, call, pages));
                }
                if let Err(a) = self.bound(arrived, &call.request) {
                    return done(a);
                }
                let body = match self.body_of(arrived, op) {
                    Ok(b) => b,
                    Err(a) => return done(a),
                };
                let asked = sts_mgmt_api::request::parse_query(query);
                let asked: Map<String, Json> = asked.into_iter().collect();
                done(if op.handler == Handler::LogoutAct {
                    pages.act(call, &asked, &body)
                } else {
                    pages.accounts_act(call, &asked, &body)
                })
            }
            Handler::Consent => self.consent_door(op, id, arrived, call).await,
        }
    }

    /// The account picker (#561): `accountsGet()` and `accountsPost()`.
    fn accounts_door(
        &self,
        op: &Operation,
        id: &str,
        arrived: &Arrived,
        call: &Call,
    ) -> Outcome {
        let done = |a: Answer| Outcome::Answered(a);
        if let Err(a) = AuthnApi::id_of(id) {
            return done(a);
        }
        let mut body = Map::new();
        if op.handler == Handler::AccountsPost {
            if let Err(a) = self.bound(arrived, &call.request) {
                return done(a);
            }
            body = match self.body_of(arrived, op) {
                Ok(b) => b,
                Err(a) => return done(a),
            };
        }
        let sessions = &self.signin.sessions;
        let stores = &self.signin.stores;
        let enabled = sessions.multiple_accounts();
        let record = if enabled {
            stores.pending.get(id)
        } else {
            None
        };
        let waiting = enabled
            && sts_authn::sessions::accounts::awaits_account_choice(
                record.as_ref(),
                self.signin.facts.now_ms(),
            );
        let Some(record) = record.filter(|_| waiting) else {
            return done(refuse(
                400,
                "There is no sign-in waiting on an account choice under that \
                 id, or it has expired. Start the request again from the \
                 application that sent you here.",
                if enabled {
                    codes::STS_AUTHN_0003
                } else {
                    codes::STS_AUTHN_0343
                },
            ));
        };
        if op.handler == Handler::AccountsGet {
            if let Some(refused) =
                sessions.refuse_accounts_unread(&call.request)
            {
                return done(picker_answer(refused));
            }
            return done(Answer::json(
                200,
                json!({ "ok": true,
                "view": sessions.accounts_view(&call.request, &record, &call.base),
                "csrf": self.csrf_of(&call.request),
                "uiLocales": text(record.get("uiLocales")) }),
            ));
        }
        let mut response = sts_authn::ports::Response::default();
        let asked = json!({ "action": op.action.unwrap_or(""),
                            "account": body.get("account").cloned().unwrap_or(Json::Null) });
        let location = |target: &str| self.signin.location_of(call, target);
        let outcome = sessions.accounts_act(
            &call.request,
            &mut response,
            &record,
            &asked,
            &location,
        );
        match outcome.record {
            sts_authn::sessions::accounts::RecordChange::Keep => {}
            sts_authn::sessions::accounts::RecordChange::Delete(k) => {
                stores.pending.delete(&k);
            }
            sts_authn::sessions::accounts::RecordChange::Set(r) => {
                let key = text(r.get("id"));
                stores.pending.set(&key, Json::Object(r));
            }
        }
        let mut answer = picker_answer(outcome.answer);
        answer.cookies = response.cookies;
        done(answer)
    }

    /// `GET /authn-api/mfa/{id}`.
    fn mfa_step(
        &self,
        op: &Operation,
        id: &str,
        query: &str,
        call: &Call,
    ) -> Outcome {
        if let Err(a) = AuthnApi::id_of(id) {
            return Outcome::Answered(a);
        }
        let schema = query_schema(op);
        let asked = sts_mgmt_api::request::parse_query(query);
        let asked = Json::Object(asked.into_iter().collect());
        let value = match body::check_parsed(&asked, "query", &schema) {
            Ok(v) => v,
            Err(_) => {
                return Outcome::Answered(refuse(
                    400,
                    "That is not a page of a sign-in step.",
                    codes::STS_AUTHN_0330,
                ))
            }
        };
        let page = match text(value.get("page")) {
            p if p.is_empty() => self.signin.page_of(id),
            p => p,
        };
        if page.starts_with("email-") {
            return Outcome::Unported("emailFactor.view");
        }
        match self
            .signin
            .mfa_view(call, &page, id, &text(value.get("key")))
        {
            Err(what) => Outcome::Unported(what),
            Ok(Err((code, why))) => Outcome::Answered(refuse(400, &why, code)),
            Ok(Ok(seen)) => {
                let mut out = json!({ "ok": true, "view": seen["view"],
                                      "csrf": self.csrf_of(&call.request),
                                      "uiLocales": seen["uiLocales"] });
                if !seen["preferredLanguage"].is_null() {
                    out["preferredLanguage"] =
                        seen["preferredLanguage"].clone();
                }
                Outcome::Answered(Answer::json(200, out))
            }
        }
    }

    /// `GET /authn-api`: the index.
    fn index(&self) -> Answer {
        let operations: Vec<Json> = OPERATIONS
            .iter()
            .map(|op| {
                let (summary, mirrors) = model::summary_of(op);
                json!({ "method": op.method, "path": op.document_path(),
                        "operationId": op.id, "access": op.access.as_str(),
                        "mirrors": mirrors, "action": op.action,
                        "summary": summary })
            })
            .collect();
        Answer::json(
            200,
            json!({ "api": "IYA STS sign-in",
                    "openapi": format!("{}/openapi.json", API),
                    "operations": operations }),
        )
    }
}

/// An answer of the account set's doors, as `answerJson()` sends it.
fn picker_answer(a: sts_authn::sessions::accounts::PickerAnswer) -> Answer {
    let mut answer = Answer::json(a.status, a.body);
    if a.retry_after {
        answer.headers.push(("retry-after".into(), "5".into()));
    }
    answer.code = a.code.and_then(sts_core::errors::known);
    answer
}

/// The query without the selection ticket (`sts_account`), which
/// `spend_account_ticket()` took off the request's address.
fn without_ticket(query: &str) -> String {
    query
        .split('&')
        .filter(|p| !p.is_empty() && p.split('=').next() != Some("sts_account"))
        .collect::<Vec<_>>()
        .join("&")
}

/// The query an operation declares, as an object schema (`ModelZod.query()`).
fn query_schema(op: &Operation) -> Json {
    let mut properties = Map::new();
    for p in model::parameters_of(op) {
        if p.get("in").and_then(Json::as_str) == Some("query") {
            if let Some(name) = p.get("name").and_then(Json::as_str) {
                properties.insert(
                    name.to_string(),
                    p.get("schema").cloned().unwrap_or(json!({})),
                );
            }
        }
    }
    json!({ "type": "object", "properties": properties })
}
