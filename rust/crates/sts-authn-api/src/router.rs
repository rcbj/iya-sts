// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The two things the composition root mounts: `/authn-api` as an axum
//! router behind the HTTP layer (it reads a body), and the sign-in
//! surface's shells as Express-matched routes (`sts_http::Routes`) — the
//! screen (`GET /authn/login`), the chooser (`/authn/select-idp`), the
//! forced password change (`/authn/password-change`) and each step's page
//! (`STEP_PAGES`: `/authn/totp`, `/authn/webauthn`, `/authn/backup-code`,
//! `/authn/password-factor`, `/authn/mfa-setup`, `/authn/post-login`).
//!
//! A SHELL IS A FRONT DOOR (`ARRIVAL_PATHS`): a browser that arrives with
//! no `sts_session` is given an arrival session, so every act on
//! `/authn-api` has a cookie to bind its CSRF token to; one that arrives
//! with a live arrival session has it slid (`touchArrivalSession()`).
//! Then the shell's own question — the pending sign-in or the step exists —
//! and the one document the bundle (`/authn/signin.js`, the TypeScript
//! build's) draws everything in.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request as AxumRequest, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::Response;
use axum::routing::any;
use axum::Router;
use serde_json::{json, Value as Json};
use sts_core::errors::{codes, ErrorCode};
use sts_http::shell::ServeOptions;
use sts_http::surfaces::{express_match, Shells};
use sts_http::{Ask, HttpLayer, Routes};

use crate::body;
use crate::door::{Arrived, AuthnApi, API};
use crate::flow::SignIn;

/// The router: every path under `/authn-api`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn router(
    api: Arc<AuthnApi>,
    http: Arc<HttpLayer>,
    settings: Arc<sts_core::settings::Settings>,
) -> Router {
    let state = Arc::new(Mounted {
        api,
        http,
        settings,
    });
    Router::new()
        .route(API, any(serve))
        .route(&format!("{}/{{*rest}}", API), any(serve))
        .with_state(state)
}

struct Mounted {
    api: Arc<AuthnApi>,
    http: Arc<HttpLayer>,
    settings: Arc<sts_core::settings::Settings>,
}

fn header_of(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// `baseUrlOf(req)`: `global.publicBaseUrl` where pinned, otherwise the
/// scheme and host the request arrived on (the forwarded ones where
/// `global.trustProxy` believes them), and the ambient realm's prefix.
#[tracing::instrument(level = "trace", skip_all)]
pub fn base_of(
    settings: &sts_core::settings::Settings,
    headers: &HeaderMap,
    over_tls: bool,
    prefix: &str,
) -> String {
    let pinned = settings
        .value_of("global.publicBaseUrl")
        .as_str()
        .trim()
        .trim_end_matches('/')
        .to_string();
    if !pinned.is_empty() {
        return format!("{}{}", pinned, prefix);
    }
    let trust = settings.value_of("global.trustProxy").as_bool();
    let first =
        |v: String| v.split(',').next().unwrap_or("").trim().to_string();
    let scheme = Some(header_of(headers, "x-forwarded-proto"))
        .filter(|_| trust)
        .map(first)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            if over_tls {
                "https".into()
            } else {
                "http".into()
            }
        });
    let host = Some(header_of(headers, "x-forwarded-host"))
        .filter(|_| trust)
        .map(first)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            let h = header_of(headers, "host");
            if h.is_empty() {
                "localhost".into()
            } else {
                h
            }
        });
    format!("{}://{}{}", scheme, host, prefix)
}

async fn serve(
    State(mounted): State<Arc<Mounted>>,
    request: AxumRequest,
) -> Response {
    let over_tls = request
        .extensions()
        .get::<sts_http::cookie_wire::OverTls>()
        .is_some();
    let peer = request
        .extensions()
        .get::<sts_http::client_address::Peer>()
        .copied();
    let original = request
        .extensions()
        .get::<sts_http::OriginalPath>()
        .map(|p| p.0.clone())
        .unwrap_or_default();
    let body_text = request
        .extensions()
        .get::<sts_http::body::ParsedBody>()
        .and_then(|b| b.text.clone())
        .unwrap_or_default();
    let prefix = mounted.http.registry().current_prefix();
    let headers = request.headers().clone();
    let arrived = Arrived {
        method: request.method().to_string(),
        path: request.uri().path().to_string(),
        query: request.uri().query().unwrap_or("").to_string(),
        base: base_of(&mounted.settings, &headers, over_tls, &prefix),
        prefix,
        own_origins: mounted.http.own_origins(
            &headers,
            peer.as_ref(),
            over_tls,
        ),
        address: mounted.http.client_address_of(&headers, peer.as_ref()),
        headers,
        body: body_text,
    };
    let sent = mounted.api.serve(&arrived).await;
    if sent.unrouted {
        let path = if original.is_empty() {
            arrived.path.clone()
        } else {
            original
        };
        let method = Method::from_bytes(arrived.method.as_bytes())
            .unwrap_or(Method::GET);
        let uri = path.parse().unwrap_or_default();
        return sts_http::not_found(method, uri, None).await;
    }
    sent.into_response()
}

/// The sign-in surface's shells, as Express-matched routes.
pub struct SignInShells {
    pub signin: Arc<SignIn>,
    pub shells: Arc<ShellsSource>,
}

/// Where the shells' builder is: the static surfaces' host's.
pub struct ShellsSource(pub Arc<sts_http::surfaces::SurfaceHost>);

impl ShellsSource {
    fn shells(&self) -> &Shells {
        self.0.shells()
    }
}

const STEP_PAGES: &[(&str, &str)] = &[
    ("totp", "/authn/totp"),
    ("webauthn", "/authn/webauthn"),
    ("backup-code", "/authn/backup-code"),
    ("password", "/authn/password-factor"),
    ("setup", "/authn/mfa-setup"),
    ("post-login", "/authn/post-login"),
];

const SHELLS: &[&str] = &[
    "/authn/login",
    "/authn/select-idp",
    "/authn/password-change",
];

fn query_value(query: &str, name: &str) -> Json {
    let parsed = sts_mgmt_api::request::parse_query(query);
    parsed.get(name).cloned().unwrap_or(Json::Null)
}

/// `vt.opt(vt.base64url)` under `name`, as a plain object: the other names
/// a query carries are dropped.
fn opt_base64url(
    query: &str,
    names: &[&str],
) -> Result<serde_json::Map<String, Json>, String> {
    let mut properties = serde_json::Map::new();
    for name in names {
        properties.insert(
            (*name).to_string(),
            json!({ "anyOf": [{ "type": "string", "const": "" },
                    { "type": "string", "minLength": 1, "maxLength": 4096,
                      "pattern": "^[A-Za-z0-9_-]+$",
                      "x-message": "must be base64url with no padding" }] }),
        );
    }
    let mut asked = serde_json::Map::new();
    for (k, v) in sts_mgmt_api::request::parse_query(query) {
        asked.insert(k, v);
    }
    body::check_parsed(
        &Json::Object(asked),
        "query",
        &json!({ "type": "object", "properties": properties }),
    )
    .map_err(|r| r.detail)
}

fn oauth_error(why: &str, code: ErrorCode) -> Response {
    let mut response = Response::new(Body::from(
        serde_json::to_string(&json!({ "error": "invalid_request",
                                        "error_description": why }))
        .unwrap_or_default(),
    ));
    *response.status_mut() = StatusCode::BAD_REQUEST;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    sts_http::mark(response, code)
}

impl SignInShells {
    /// `signInShell(req, res, application, person)`.
    fn shell(
        &self,
        headers: &HeaderMap,
        application: &str,
        person: &str,
    ) -> Response {
        let shown = self.signin.facts.client_display(application);
        let logo = shown
            .get("logoOrigin")
            .and_then(Json::as_str)
            .filter(|o| !o.is_empty());
        let html = self.shells.shells().signin(headers, application, person);
        let options: ServeOptions = Shells::signin_options(logo);
        sts_http::shell::serve(headers, html, &options)
    }

    fn answer_shell(&self, ask: &Ask<'_>, path: &str) -> Response {
        let hides = self.signin.facts.predicate("hidesStepIds");
        let named = ["authn", "mfa", "change"].iter().any(|n| {
            let v = query_value(ask.query, n);
            !v.is_null() && v != Json::String(String::new())
        });
        if hides && !named {
            let asked = query_value(ask.query, "app");
            let asked = asked.as_str().unwrap_or("");
            let fits = !asked.is_empty()
                && asked.len() <= 256
                && asked
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_.:~-".contains(c));
            return self.shell(ask.headers, if fits { asked } else { "" }, "");
        }
        if path == "/authn/password-change" {
            let value = match opt_base64url(ask.query, &["change"]) {
                Ok(v) => v,
                Err(why) => return oauth_error(&why, codes::STS_AUTHN_0145),
            };
            let id = value.get("change").and_then(Json::as_str).unwrap_or("");
            return match self.signin.password_change_step(id) {
                Err(answer) => oauth_error(
                    answer.body["error_description"].as_str().unwrap_or(""),
                    answer.code.unwrap_or(codes::STS_AUTHN_0144),
                ),
                Ok(step) => {
                    let application = step["authn"]["application"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    let person =
                        step["username"].as_str().unwrap_or("").to_string();
                    self.shell(ask.headers, &application, &person)
                }
            };
        }
        if let Some((page, _)) = STEP_PAGES.iter().find(|(_, p)| *p == path) {
            let value = match opt_base64url(ask.query, &["mfa", "key"]) {
                Ok(v) => v,
                Err(why) => {
                    return oauth_error(
                        &why,
                        if *page == "setup" {
                            codes::STS_AUTHN_0174
                        } else {
                            codes::STS_AUTHN_0018
                        },
                    )
                }
            };
            let id = value.get("mfa").and_then(Json::as_str).unwrap_or("");
            return match self.signin.step_problem(page, id) {
                Err((code, why)) => oauth_error(&why, code),
                Ok(step) => {
                    let application = step["authn"]["application"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    let person =
                        step["username"].as_str().unwrap_or("").to_string();
                    self.shell(ask.headers, &application, &person)
                }
            };
        }
        let value = match opt_base64url(ask.query, &["authn"]) {
            Ok(v) => v,
            Err(why) => return oauth_error(&why, codes::STS_AUTHN_0001),
        };
        let id = value.get("authn").and_then(Json::as_str).unwrap_or("");
        let Some(record) = self.signin.pending_for(id) else {
            return oauth_error(
                "There is no sign-in waiting under that id, or it has expired. \
                 Start the request again from the application that sent you \
                 here.",
                codes::STS_AUTHN_0003,
            );
        };
        if path == "/authn/select-idp" {
            let partners = record
                .get("federation")
                .and_then(|f| f.get("partners"))
                .and_then(Json::as_array)
                .map_or(0, Vec::len);
            if partners < 2 {
                return sts_http::redirect_with(
                    StatusCode::SEE_OTHER,
                    &format!(
                        "/authn/login?authn={}",
                        sts_credentials::totp::encode_uri_component(id)
                    ),
                );
            }
        }
        let application =
            record["application"].as_str().unwrap_or("").to_string();
        let person =
            record["lockedUsername"].as_str().unwrap_or("").to_string();
        self.shell(ask.headers, &application, &person)
    }

    /// The arrival session (`ARRIVAL_PATHS`): minted for a browser with no
    /// `sts_session`, slid for one with a live arrival.
    fn arrival(&self, ask: &Ask<'_>) -> Vec<String> {
        let request = sts_authn::ports::Request {
            cookie: header_of(ask.headers, "cookie"),
            user_agent: header_of(ask.headers, "user-agent"),
            ..sts_authn::ports::Request::default()
        };
        self.signin.sessions.touch_arrival_session(&request);
        let mut response = sts_authn::ports::Response::default();
        if self
            .signin
            .sessions
            .cookie_session(Some(&request), crate::door::SESSION_COOKIE)
            .is_none()
        {
            if self
                .signin
                .sessions
                .start_arrival_session(&request, &mut response, "arrival")
                .is_none()
            {
                tracing::debug!("authn: no arrival session was started.");
            }
        }
        response.cookies
    }
}

impl Routes for SignInShells {
    fn answer(&self, ask: &Ask<'_>) -> Option<Response> {
        if *ask.method != Method::GET && *ask.method != Method::HEAD {
            return None;
        }
        let path = SHELLS
            .iter()
            .chain(STEP_PAGES.iter().map(|(_, p)| p))
            .find(|p| express_match(p, ask.path).is_some())?;
        let cookies = self.arrival(ask);
        let mut response = self.answer_shell(ask, path);
        for line in cookies {
            if let Ok(v) = HeaderValue::from_str(&line) {
                response.headers_mut().append(header::SET_COOKIE, v);
            }
        }
        Some(response)
    }
}
