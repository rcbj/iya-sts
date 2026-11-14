// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE REVERSE PROXY (#1760): this PEP in front of ONE application.
//!
//! ```text
//! PEP_PROXY_PORT        (9180)  plain HTTP
//! PEP_PROXY_HTTPS_PORT  (9543)  the PEP_HTTPS_CERT/KEY pair 9443 serves,
//!                               asking every client for a certificate
//! GET  /.iya-pep/callback       the session mechanism's redirect URI
//! GET  /.iya-pep/logout         ends the proxy session, then the service's
//! everything else               the route table
//! ```
//!
//! **DENY BY DEFAULT.** No configuration, a configuration switched off, a
//! path that matches no route: 404, and the application is never reached.
//! A request is answered in this order, and each step's refusal is the
//! first one it meets: the path normalised (400), the route found (404),
//! the method (405 with `Allow`), the declared body size (413), then —
//! unless the route is public — the mechanism (401, with a challenge per
//! mechanism the route allows, or a 302 to sign in for a browser on a
//! `session` route), then the decision (403), then the application (502,
//! 504, or a streamed body over the bound: 413).
//!
//! **THE DESTINATION IS NEVER THE REQUEST'S.** The upstream URL is the
//! configured upstream base, the NORMALISED path and the original query;
//! the result is checked to still be on the upstream's origin and under its
//! path (`STS-XPEP-0091`). No redirect the application answers is followed
//! — it is the client's to follow, through this proxy again.
//!
//! **THE DECISION IS THE ONE `/protected` MAKES** (D8): `service.rs`'s
//! `decide_proxy()` — the subject (the username when known, else `sub`),
//! the route's resource or the path, the route's action or the method,
//! through the one builder, the PIP, `enforce.rs`, and the same counters.
//!
//! `proxy_request.rs` holds the path and header rules, `proxy_auth.rs` the
//! mechanisms, `rp_session.rs` the session stores, `proxy_config.rs` the
//! pulled configuration.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::http::{
    header, HeaderMap, HeaderValue, Request, Response, StatusCode,
};
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use serde_json::json;
use sts_core::log::tag;
use tokio::net::TcpListener;

use crate::listener::{peer_of, HttpsListener, Transport};
use crate::pdp_client::PdpClient;
use crate::proxy_auth::{Authenticator, Identity, Refusal};
use crate::proxy_config::{Mechanism, ProxyConfig, Pulled, Route};
use crate::proxy_request::{
    cookie_value, forward_headers, is_browser, normalise_path,
    response_headers, SESSION_COOKIE,
};
use crate::rp_session::{self, Pending, Session};
use crate::rp_set::{self, RpSet};
use crate::service::Pep;
use oidc_caep_risc::EndSessionOptions;

pub const CALLBACK_PATH: &str = "/.iya-pep/callback";
pub const LOGOUT_PATH: &str = "/.iya-pep/logout";

/// The reverse proxy: the PEP it decides with, the mechanisms, and one
/// client to the upstream per timeout.
pub struct Proxy {
    pep: Arc<Pep>,
    auth: Authenticator,
    upstream: Mutex<Option<(u64, reqwest::Client)>>,
    /// The session mechanism's relying parties (`rp_set.rs`).
    rps: RpSet,
}

/// What a request was, for its log line and its refusal.
struct Asked<'a> {
    method: &'a str,
    path: &'a str,
    route: Option<&'a Route>,
}

/// A mechanism's outcome.
enum Established {
    Who(Identity),
    Refused(Refusal),
    /// A finished answer: the sign-in redirect.
    Answer(Response<Body>),
}

/// A request body that counts what passes and fails past `limit` — the
/// streamed half of `maxBodyBytes`. The flag tells a 413 from an upstream
/// that went away. The body sits in a `Mutex` only to be `Sync`, which the
/// client library asks of a body; it is reached through `get_mut()`, so
/// nothing ever waits on the lock.
struct LimitedBody {
    inner: Mutex<Body>,
    seen: u64,
    limit: u64,
    over: Arc<AtomicBool>,
}

impl HttpBody for LimitedBody {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    // A hot path (every frame of every body): no Entering/Leaving pair.
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let LimitedBody {
            inner,
            seen,
            limit,
            over,
        } = self.get_mut();
        let body = match inner.get_mut() {
            Ok(body) => body,
            Err(poisoned) => poisoned.into_inner(),
        };
        match Pin::new(body).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    *seen += data.len() as u64;
                    if *seen > *limit {
                        over.store(true, Ordering::SeqCst);
                        return Poll::Ready(Some(Err(
                            "the request body is larger than maxBodyBytes"
                                .into(),
                        )));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                Poll::Ready(Some(Err(Box::new(error))))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self.inner.lock() {
            Ok(body) => body.size_hint(),
            Err(poisoned) => poisoned.into_inner().size_hint(),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self.inner.lock() {
            Ok(body) => body.is_end_stream(),
            Err(poisoned) => poisoned.into_inner().is_end_stream(),
        }
    }
}

fn error_name(status: u16, token_refused: bool) -> &'static str {
    match status {
        400 => "invalid_request",
        401 if token_refused => "invalid_token",
        401 => "unauthorized",
        403 => "access_denied",
        404 => "not_found",
        405 => "method_not_allowed",
        413 => "payload_too_large",
        429 => "too_many_requests",
        503 => "temporarily_unavailable",
        504 => "gateway_timeout",
        _ => "bad_gateway",
    }
}

fn json_answer(status: u16, body: serde_json::Value) -> Response<Body> {
    let mut response = Response::new(Body::from(body.to_string()));
    *response.status_mut() =
        StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn redirect(location: &str) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::FOUND;
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn session_cookie(id: &str, https: bool, clear: bool) -> Option<HeaderValue> {
    let mut text = if clear {
        format!(
            "{}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax",
            SESSION_COOKIE
        )
    } else {
        format!("{}={}; Path=/; HttpOnly; SameSite=Lax", SESSION_COOKIE, id)
    };
    if https {
        text.push_str("; Secure");
    }
    HeaderValue::from_str(&text).ok()
}

fn query_pairs(query: Option<&str>) -> Vec<(String, String)> {
    let Some(raw) = query else {
        return Vec::new();
    };
    reqwest::Url::parse(&format!("http://localhost/?{}", raw))
        .map(|u| {
            u.query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect()
        })
        .unwrap_or_default()
}

impl Proxy {
    pub fn new(pep: Arc<Pep>, client: PdpClient) -> Proxy {
        let ttl = pep.options.proxy_jwks_ttl_ms;
        // A session the library's receiver ends is ended here too.
        let sync = pep.sync.clone();
        let on_end: rp_set::OnEnd = Arc::new(move |ended: Vec<String>| {
            for id in ended {
                if sync.proxy_sessions.end(&id).is_some() {
                    sync.count_session_ended();
                    tracing::info!(
                        "{}xacml-pep: proxy: a CAEP/RISC signal from the \
                         service ended a proxy session.",
                        tag("STS-XPEP-0084")
                    );
                }
            }
        });
        let rps = RpSet::new(
            pep.options.proxy_rp_allow_insecure,
            pep.options.proxy_signals_poll_ms,
            on_end,
        );
        Proxy {
            pep,
            auth: Authenticator::new(client, ttl),
            upstream: Mutex::new(None),
            rps,
        }
    }

    /// ONE HANDLER FOR BOTH PROXY LISTENERS, and the hot path: no
    /// Entering/Leaving pair, for `Pep::handle()`'s reason.
    pub async fn handle(
        self: Arc<Self>,
        request: Request<Body>,
    ) -> Response<Body> {
        let (response, forwarded) = self.answer(request).await;
        self.pep
            .sync
            .count_proxy(response.status().as_u16(), forwarded);
        response
    }

    /// A refusal as an answer, logged under its code. A 5xx's body is a
    /// generic sentence: the reason may name the service's addresses.
    fn refuse(
        &self,
        refusal: &Refusal,
        asked: &Asked,
        pulled: &Pulled,
    ) -> Response<Body> {
        let route = asked
            .route
            .map(|r| format!(" (route {})", r.id))
            .unwrap_or_default();
        let shown: String = asked.path.chars().take(200).collect();
        if refusal.status >= 500 {
            tracing::warn!(
                "{}xacml-pep: proxy answered {} to {} {:?}{}: {}.",
                tag(refusal.code),
                refusal.status,
                asked.method,
                shown,
                route,
                refusal.why
            );
        } else {
            tracing::info!(
                "{}xacml-pep: proxy refused {} {:?}{} with {}: {}.",
                tag(refusal.code),
                asked.method,
                shown,
                route,
                refusal.status,
                refusal.why
            );
        }
        let description = match refusal.status {
            502 => "The application or the identity service could not be \
                    reached, or did not answer usably."
                .to_string(),
            503 => "This proxy cannot take the request now.".to_string(),
            504 => "The application did not answer in time.".to_string(),
            _ => refusal.why.clone(),
        };
        let mut response = json_answer(
            refusal.status,
            json!({ "error": error_name(refusal.status, refusal.token_refused),
                    "error_description": description }),
        );
        let headers = response.headers_mut();
        if refusal.status == 401 {
            if let Some(route) = asked.route {
                self.challenges(route, pulled, refusal.token_refused, headers);
            }
        }
        if refusal.status == 405 {
            if let Some(route) = asked.route {
                if let Ok(v) = HeaderValue::from_str(&route.methods.join(", "))
                {
                    headers.insert(header::ALLOW, v);
                }
            }
        }
        if let Some(after) = refusal
            .retry_after
            .as_ref()
            .and_then(|a| HeaderValue::from_str(a).ok())
        {
            headers.insert(header::RETRY_AFTER, after);
        }
        response
    }

    /// One `WWW-Authenticate` per mechanism the route allows that has an
    /// HTTP scheme (the session mechanism has none: it is a cookie).
    fn challenges(
        &self,
        route: &Route,
        pulled: &Pulled,
        token_refused: bool,
        headers: &mut HeaderMap,
    ) {
        let realm = if pulled.pep.is_empty() {
            self.pep.options.name.clone()
        } else {
            pulled.pep.clone()
        };
        let realm: String = realm
            .chars()
            .filter(|c| *c != '"' && *c != '\\' && !c.is_control())
            .collect();
        for mechanism in &route.mechanisms {
            let value = match mechanism {
                Mechanism::OAuth2 if token_refused => format!(
                    "Bearer realm=\"{}\", error=\"invalid_token\"",
                    realm
                ),
                Mechanism::OAuth2 => format!("Bearer realm=\"{}\"", realm),
                Mechanism::Basic => {
                    format!("Basic realm=\"{}\", charset=\"UTF-8\"", realm)
                }
                Mechanism::Saml2 => format!("SAML realm=\"{}\"", realm),
                Mechanism::Session => continue,
            };
            if let Ok(v) = HeaderValue::from_str(&value) {
                headers.append(header::WWW_AUTHENTICATE, v);
            }
        }
    }

    async fn answer(&self, request: Request<Body>) -> (Response<Body>, bool) {
        let (parts, body) = request.into_parts();
        let transport = parts
            .extensions
            .get::<Transport>()
            .cloned()
            .unwrap_or_default();
        let method = parts.method.as_str().to_string();
        let raw_path = parts.uri.path().to_string();
        let query = parts.uri.query().map(str::to_string);
        let pulled = self.pep.sync.proxy();
        let mut asked = Asked {
            method: &method,
            path: &raw_path,
            route: None,
        };
        let path = match normalise_path(&raw_path) {
            Ok(path) => path,
            Err(why) => {
                let refusal = Refusal::new(400, "STS-XPEP-0064", why);
                return (self.refuse(&refusal, &asked, &pulled), false);
            }
        };
        asked.path = &path;
        let Some(config) = pulled.active() else {
            let refusal = Refusal::new(
                404,
                "STS-XPEP-0065",
                "this proxy holds no configuration that is switched on",
            );
            return (self.refuse(&refusal, &asked, &pulled), false);
        };
        if path == CALLBACK_PATH {
            let answer = self
                .callback(query.as_deref(), &pulled, &transport, &asked)
                .await;
            return (answer, false);
        }
        if path == LOGOUT_PATH {
            return (self.logout(&parts.headers, &pulled, &transport), false);
        }
        let Some(route) = config.route_for(&path) else {
            let refusal = Refusal::new(
                404,
                "STS-XPEP-0065",
                "no route matches this path",
            );
            return (self.refuse(&refusal, &asked, &pulled), false);
        };
        asked.route = Some(route);
        if !route.takes(&method) {
            let refusal = Refusal::new(
                405,
                "STS-XPEP-0066",
                "the route does not take this method",
            );
            return (self.refuse(&refusal, &asked, &pulled), false);
        }
        // D10: the route's application as the service resolved it at the
        // pull. Not usable (deleted, or no longer qualifying) is refused,
        // never admitted on what an earlier pull said.
        if !route.public && !route.resolved.usable {
            let refusal = Refusal::new(
                403,
                "STS-XPEP-0093",
                &format!(
                    "the route's application {} is not usable now{}{}{}",
                    route.application,
                    if route.resolved.why.is_empty() {
                        ""
                    } else {
                        ": "
                    },
                    route.resolved.why,
                    // The service's own code for why (an STS-XACML code):
                    // logged, never sent.
                    if route.resolved.code.is_empty() {
                        String::new()
                    } else {
                        format!(" (the service says {})", route.resolved.code)
                    }
                ),
            );
            let mut refused = self.refuse(&refusal, &asked, &pulled);
            *refused.body_mut() = Body::from(
                json!({ "error": "access_denied",
                        "error_description": "This route cannot be used now." })
                .to_string(),
            );
            return (refused, false);
        }
        let declared = parts
            .headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok());
        if declared.is_some_and(|n| n > config.max_body_bytes) {
            let refusal = Refusal::new(
                413,
                "STS-XPEP-0067",
                "the request body is larger than maxBodyBytes",
            );
            return (self.refuse(&refusal, &asked, &pulled), false);
        }
        let identity = if route.public {
            None
        } else {
            let established = self
                .establish(
                    route,
                    &pulled,
                    config,
                    &parts.headers,
                    &transport,
                    &method,
                    &path,
                    query.as_deref(),
                )
                .await;
            match established {
                Established::Who(identity) => Some(identity),
                Established::Refused(refusal) => {
                    return (self.refuse(&refusal, &asked, &pulled), false)
                }
                Established::Answer(response) => return (response, false),
            }
        };
        if let Some(identity) = &identity {
            let resource = if route.resource.is_empty() {
                path.as_str()
            } else {
                route.resource.as_str()
            };
            let action = if route.action.is_empty() {
                method.as_str()
            } else {
                route.action.as_str()
            };
            let (decision, outcome) = self
                .pep
                .decide_proxy(identity.subject(), resource, action)
                .await;
            if !outcome.allowed {
                let refusal = Refusal::new(
                    403,
                    "STS-XPEP-0086",
                    &format!(
                        "the policy this PEP holds said {} for this \
                         subject, resource and action ({} bias)",
                        decision.as_str(),
                        outcome.bias.as_str()
                    ),
                );
                return (self.refuse(&refusal, &asked, &pulled), false);
            }
        }
        match self
            .forward(
                route,
                config,
                &parts,
                body,
                &path,
                query.as_deref(),
                &transport,
                identity.as_ref(),
            )
            .await
        {
            Ok(response) => (response, true),
            Err(refusal) => (self.refuse(&refusal, &asked, &pulled), false),
        }
    }

    /// The route's mechanism, chosen by the `Authorization` scheme, else
    /// the session cookie.
    #[allow(clippy::too_many_arguments)]
    async fn establish(
        &self,
        route: &Route,
        pulled: &Pulled,
        config: &ProxyConfig,
        headers: &HeaderMap,
        transport: &Transport,
        method: &str,
        path: &str,
        query: Option<&str>,
    ) -> Established {
        let authorization = headers
            .get(header::AUTHORIZATION)
            .map(|v| v.to_str().map(str::trim));
        if let Some(value) = authorization {
            let Ok(value) = value else {
                return Established::Refused(Refusal::new(
                    401,
                    "STS-XPEP-0089",
                    "the Authorization header is not text",
                ));
            };
            let (scheme, credential) = value
                .split_once(char::is_whitespace)
                .map(|(s, c)| (s.to_ascii_lowercase(), c.trim()))
                .unwrap_or_else(|| (value.to_ascii_lowercase(), ""));
            let wanted = match scheme.as_str() {
                "bearer" | "dpop" => Some(Mechanism::OAuth2),
                "saml" => Some(Mechanism::Saml2),
                "basic" => Some(Mechanism::Basic),
                _ => None,
            };
            match wanted.filter(|m| route.allows(*m)) {
                Some(_) if credential.is_empty() => {
                    return Established::Refused(Refusal::new(
                        401,
                        "STS-XPEP-0089",
                        "the Authorization header carries no credential",
                    ))
                }
                Some(Mechanism::OAuth2) if scheme == "dpop" => {
                    return Established::Refused(Refusal {
                        token_refused: true,
                        ..Refusal::new(
                            401,
                            "STS-XPEP-0072",
                            "a DPoP-bound token, which this proxy does not \
                             prove",
                        )
                    })
                }
                Some(Mechanism::OAuth2) => {
                    return match self
                        .auth
                        .oauth2(credential, route, pulled, transport)
                        .await
                    {
                        Ok(who) => Established::Who(who),
                        Err(refusal) => Established::Refused(refusal),
                    }
                }
                Some(Mechanism::Saml2) => {
                    return match self
                        .auth
                        .saml2(credential, route, pulled)
                        .await
                    {
                        Ok(who) => Established::Who(who),
                        Err(refusal) => Established::Refused(refusal),
                    }
                }
                Some(Mechanism::Basic) => {
                    return match self.auth.basic(credential, pulled).await {
                        Ok(who) => Established::Who(who),
                        Err(refusal) => Established::Refused(refusal),
                    }
                }
                _ if !route.allows(Mechanism::Session) => {
                    return Established::Refused(Refusal::new(
                        401,
                        "STS-XPEP-0089",
                        "the Authorization scheme is not one this route \
                         takes",
                    ))
                }
                // A session route ignores a scheme it does not take, and
                // asks for the cookie.
                _ => {}
            }
        }
        if !route.allows(Mechanism::Session) {
            return Established::Refused(Refusal::new(
                401,
                "STS-XPEP-0070",
                "the request carries no credential",
            ));
        }
        self.session(
            route, pulled, config, headers, transport, method, path, query,
        )
        .await
    }

    /// A request on a `session` route: the proxy session the cookie names,
    /// still alive by the library's receiver (signals) or by the service's
    /// session endpoint (`signals: false`, or a receiver that would not
    /// start).
    #[allow(clippy::too_many_arguments)]
    async fn session(
        &self,
        route: &Route,
        pulled: &Pulled,
        config: &ProxyConfig,
        headers: &HeaderMap,
        transport: &Transport,
        method: &str,
        path: &str,
        query: Option<&str>,
    ) -> Established {
        let stores = &self.pep.sync.proxy_sessions;
        let browser = is_browser(method, headers);
        let id = cookie_value(headers, SESSION_COOKIE).unwrap_or_default();
        let held = if id.is_empty() { None } else { stores.get(&id) };
        // A session made by another application's client is not this
        // route's: the proxy session is the application's sign-in.
        let held = held.filter(|s| s.client_id == route.resolved.client_id);
        let Some(session) = held else {
            return self
                .no_session(
                    route, pulled, config, transport, browser, path, query,
                    false,
                )
                .await;
        };
        let party = self.rps.held(&session.client_id);
        let by_signals = route.signals
            && party.as_ref().is_some_and(rp_set::Party::signals_live);
        let alive = if by_signals {
            // THE LIBRARY'S ANSWER: its receiver removes the session a
            // CAEP session-revoked names, so the session still being in
            // its cache is the session still being live. A map lookup.
            party.as_ref().is_some_and(|p| p.rp.session(&id).is_some())
        } else {
            let recheck = Duration::from_millis(
                self.pep.options.proxy_session_recheck_ms,
            );
            if session.last_checked.elapsed() < recheck {
                true
            } else {
                match self.auth.session_live(&session.sid, pulled).await {
                    Err(refusal) => return Established::Refused(refusal),
                    Ok(Some((sub, username))) => {
                        stores.checked(&id, &sub, &username);
                        true
                    }
                    Ok(None) => false,
                }
            }
        };
        if !alive {
            self.end_session(&id, &session.client_id);
            tracing::info!(
                "{}xacml-pep: proxy: the sign-on session behind a proxy \
                 session has ended at the service ({}, route {}); the proxy \
                 session is ended.",
                tag("STS-XPEP-0084"),
                if by_signals {
                    "a CAEP/RISC signal"
                } else {
                    "its session endpoint"
                },
                route.id
            );
            return self
                .no_session(
                    route, pulled, config, transport, browser, path, query,
                    true,
                )
                .await;
        }
        let current = stores.get(&id).unwrap_or(session);
        Established::Who(Identity {
            sub: current.sub.clone(),
            username: current.username.clone(),
            mechanism: Mechanism::Session,
        })
    }

    /// Ends a proxy session here and in the library (its cache, and the
    /// receiver's index).
    fn end_session(&self, id: &str, client_id: &str) {
        if self.pep.sync.proxy_sessions.end(id).is_some() {
            self.pep.sync.count_session_ended();
        }
        if let Some(party) = self.rps.held(client_id) {
            party.rp.remove_session(id);
            if let Some(receiver) = &party.receiver {
                receiver.untrack(id);
            }
        }
    }

    /// No live proxy session: a browser is sent to sign in through the
    /// library's `authorize()`, anything else is a 401. `ended` clears the
    /// cookie on the way.
    #[allow(clippy::too_many_arguments)]
    async fn no_session(
        &self,
        route: &Route,
        pulled: &Pulled,
        config: &ProxyConfig,
        transport: &Transport,
        browser: bool,
        path: &str,
        query: Option<&str>,
        ended: bool,
    ) -> Established {
        let _ = config;
        if !browser {
            let why = if ended {
                "the sign-on session behind the proxy session has ended"
            } else {
                "there is no proxy session (sign in through a browser)"
            };
            let code = if ended {
                "STS-XPEP-0084"
            } else {
                "STS-XPEP-0081"
            };
            return Established::Refused(Refusal::new(401, code, why));
        }
        let client_id = route.resolved.client_id.clone();
        let party =
            match self.rps.party(&client_id, pulled, route.signals).await {
                Ok(party) => party,
                Err(why) => {
                    return Established::Refused(Refusal::new(
                        503,
                        "STS-XPEP-0090",
                        &format!(
                        "the relying party for client {} could not be built: \
                         {}",
                        client_id, why
                    ),
                    ))
                }
            };
        let rp = party.rp.clone();
        let authorized =
            tokio::task::spawn_blocking(move || rp.authorize()).await;
        let transaction = match authorized {
            Ok(Ok(transaction)) => transaction,
            Ok(Err(error)) => {
                return Established::Refused(Refusal::new(
                    502,
                    "STS-XPEP-0075",
                    &format!("the sign-in could not be started: {}", error),
                ))
            }
            Err(error) => {
                return Established::Refused(Refusal::new(
                    502,
                    "STS-XPEP-0075",
                    &format!("the sign-in could not be started: {}", error),
                ))
            }
        };
        let return_to = match query {
            Some(q) => format!("{}?{}", path, q),
            None => path.to_string(),
        };
        let location = transaction.url.clone();
        self.pep.sync.proxy_sessions.begin(
            transaction.state.clone(),
            Pending {
                transaction,
                client_id,
                return_to,
                created: Instant::now(),
            },
        );
        tracing::info!(
            "xacml-pep: proxy: a browser with no proxy session on route {} \
             is sent to sign in.",
            route.id
        );
        let mut response = redirect(&location);
        if ended {
            if let Some(cookie) = session_cookie("", transport.https, true) {
                response.headers_mut().insert(header::SET_COOKIE, cookie);
            }
        }
        Established::Answer(response)
    }

    /// `GET /.iya-pep/callback`: the library's `complete_session()` under
    /// a new proxy session id — the code redeemed with the application's
    /// client authentication, the ID Token verified (signature, `iss`,
    /// `aud`, nonce, `iat`, `exp`, `typ`, `at_hash`) — then a proxy session
    /// under the same id, and the browser sent where it was going.
    #[tracing::instrument(level = "debug", skip_all)]
    async fn callback(
        &self,
        query: Option<&str>,
        pulled: &Pulled,
        transport: &Transport,
        asked: &Asked<'_>,
    ) -> Response<Body> {
        let refused = |code: &'static str, why: &str| {
            self.refuse(&Refusal::new(401, code, why), asked, pulled)
        };
        let pairs: HashMap<String, String> =
            query_pairs(query).into_iter().collect();
        let state = pairs.get("state").cloned().unwrap_or_default();
        let pending = if state.is_empty() {
            None
        } else {
            self.pep.sync.proxy_sessions.take(&state)
        };
        let Some(pending) = pending else {
            return refused(
                "STS-XPEP-0082",
                "the sign-in is unknown, already used or expired",
            );
        };
        let Some(party) = self.rps.held(&pending.client_id) else {
            return refused(
                "STS-XPEP-0082",
                "the sign-in's relying party is no longer held",
            );
        };
        if !self.pep.sync.proxy_sessions.has_room() {
            return self.refuse(
                &Refusal::new(
                    503,
                    "STS-XPEP-0085",
                    "this proxy holds PEP_PROXY_MAX_SESSIONS live sessions",
                ),
                asked,
                pulled,
            );
        }
        let Some(id) = rp_session::random_token(32) else {
            return self.refuse(
                &Refusal::new(
                    503,
                    "STS-XPEP-0085",
                    "no random value could be drawn for a proxy session",
                ),
                asked,
                pulled,
            );
        };
        let rp = party.rp.clone();
        let transaction = pending.transaction.clone();
        let session_id = id.clone();
        let completed = tokio::task::spawn_blocking(move || {
            rp.complete_session(&pairs, &transaction, &session_id)
        })
        .await;
        let login = match completed {
            Ok(Ok(login)) => login,
            Ok(Err(error)) => {
                return refused(
                    "STS-XPEP-0083",
                    &format!(
                        "the sign-in was refused ({}): {}",
                        error.code, error.message
                    ),
                )
            }
            Err(error) => {
                return refused(
                    "STS-XPEP-0083",
                    &format!("the sign-in could not be completed: {}", error),
                )
            }
        };
        let username = if login.preferred_username.is_empty() {
            login
                .claims
                .get("username")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        } else {
            login.preferred_username.clone()
        };
        let now = Instant::now();
        let created = self.pep.sync.proxy_sessions.create(
            &id,
            Session {
                client_id: pending.client_id.clone(),
                sid: login.sid.clone(),
                sub: login.subject.clone(),
                username,
                id_token: login.id_token.clone(),
                created: now,
                last_checked: now,
            },
        );
        if created.is_err() {
            party.rp.remove_session(&id);
            return self.refuse(
                &Refusal::new(
                    503,
                    "STS-XPEP-0085",
                    "this proxy holds PEP_PROXY_MAX_SESSIONS live sessions",
                ),
                asked,
                pulled,
            );
        }
        // The receiver finds a session by the service's session id (a
        // CAEP session-revoked names it), by the person, or by the mail.
        if let Some(receiver) = &party.receiver {
            let mut tracked = serde_json::Map::new();
            tracked.insert("local_id".into(), json!(id));
            tracked.insert("person".into(), json!(login.subject));
            if !login.email.is_empty() {
                tracked.insert("email".into(), json!(login.email));
            }
            if !login.sid.is_empty() {
                tracked.insert("idp_session".into(), json!(login.sid));
            }
            receiver.track(tracked);
        }
        self.pep.sync.count_sign_in();
        let mut response = redirect(&pending.return_to);
        if let Some(cookie) = session_cookie(&id, transport.https, false) {
            response.headers_mut().insert(header::SET_COOKIE, cookie);
        }
        response
    }

    /// `/.iya-pep/logout`: the proxy session ended here and in the library
    /// (`remove_session`), then the service's RP-initiated logout through
    /// the library's `end_session_url()`.
    fn logout(
        &self,
        headers: &HeaderMap,
        pulled: &Pulled,
        transport: &Transport,
    ) -> Response<Body> {
        let _ = pulled;
        let id = cookie_value(headers, SESSION_COOKIE).unwrap_or_default();
        let held = if id.is_empty() {
            None
        } else {
            self.pep.sync.proxy_sessions.get(&id)
        };
        let mut location = String::new();
        if let Some(session) = &held {
            if let Some(party) = self.rps.held(&session.client_id) {
                location = party.rp.end_session_url(EndSessionOptions {
                    id_token: session.id_token.clone(),
                    ..EndSessionOptions::default()
                });
            }
            self.end_session(&id, &session.client_id);
        }
        let mut response = if location.is_empty() {
            json_answer(200, json!({ "signedOut": held.is_some() }))
        } else {
            redirect(&location)
        };
        if let Some(cookie) = session_cookie("", transport.https, true) {
            response.headers_mut().insert(header::SET_COOKIE, cookie);
        }
        response
    }

    /// After every poll (`main.rs`): the relying parties the pull calls
    /// for built, the rest dropped.
    /// A test's way to have the library drop a session on its own (a
    /// refresh refused, an entry evicted), the proxy's store untouched.
    #[cfg(test)]
    pub fn library_forgets(&self, client_id: &str, id: &str) {
        if let Some(party) = self.rps.held(client_id) {
            party.rp.remove_session(id);
        }
    }

    pub async fn reconcile(&self) {
        let pulled = self.pep.sync.proxy();
        self.rps.reconcile(&pulled).await;
        self.pep.sync.set_relying_parties(self.rps.counts());
    }

    fn upstream_client(
        &self,
        timeout_ms: u64,
    ) -> Result<reqwest::Client, Refusal> {
        let mut slot = match self.upstream.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if let Some((held, client)) = slot.as_ref() {
            if *held == timeout_ms {
                return Ok(client.clone());
            }
        }
        let o = &self.pep.options;
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_millis(timeout_ms))
            .no_proxy();
        if o.proxy_upstream_insecure {
            builder = builder
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true);
        }
        if let Some(bundle) = &o.proxy_upstream_ca {
            match reqwest::Certificate::from_pem_bundle(bundle) {
                Ok(anchors) => {
                    for anchor in anchors {
                        builder = builder.add_root_certificate(anchor);
                    }
                }
                Err(error) => tracing::error!(
                    "{}xacml-pep: PEP_PROXY_UPSTREAM_CA would not load ({}); \
                     the system's anchors alone are used.",
                    tag("STS-XPEP-0092"),
                    error
                ),
            }
        }
        let client = builder.build().map_err(|error| {
            Refusal::new(
                502,
                "STS-XPEP-0092",
                &format!("the upstream client would not build: {}", error),
            )
        })?;
        *slot = Some((timeout_ms, client.clone()));
        Ok(client)
    }

    /// The request, to the application: streamed both ways, bounded.
    #[allow(clippy::too_many_arguments)]
    async fn forward(
        &self,
        route: &Route,
        config: &ProxyConfig,
        parts: &axum::http::request::Parts,
        body: Body,
        path: &str,
        query: Option<&str>,
        transport: &Transport,
        identity: Option<&Identity>,
    ) -> Result<Response<Body>, Refusal> {
        let target = format!(
            "{}{}{}",
            config.upstream,
            path,
            query.map(|q| format!("?{}", q)).unwrap_or_default()
        );
        let off_origin = || {
            Refusal::new(
                502,
                "STS-XPEP-0091",
                "the request would not stay on the configured upstream",
            )
        };
        let base =
            reqwest::Url::parse(&config.upstream).map_err(|_| off_origin())?;
        let url = reqwest::Url::parse(&target).map_err(|_| off_origin())?;
        let base_path = base.path().trim_end_matches('/');
        if url.scheme() != base.scheme()
            || url.host_str() != base.host_str()
            || url.port_or_known_default() != base.port_or_known_default()
            || !url.path().starts_with(base_path)
        {
            return Err(off_origin());
        }
        let mut headers = forward_headers(&parts.headers, route);
        if let Some(remote) = transport.remote.map(|r: SocketAddr| r.ip()) {
            if let Ok(v) = HeaderValue::from_str(&remote.to_string()) {
                headers.insert("x-forwarded-for", v);
            }
        }
        headers.insert(
            "x-forwarded-proto",
            HeaderValue::from_static(if transport.https {
                "https"
            } else {
                "http"
            }),
        );
        let host = parts.headers.get(header::HOST).cloned().or_else(|| {
            parts
                .uri
                .authority()
                .and_then(|a| HeaderValue::from_str(a.as_str()).ok())
        });
        if let Some(host) = host {
            headers.insert("x-forwarded-host", host);
        }
        if let Some(identity) = identity {
            if let Some(name) = &route.subject_header {
                let Ok(value) = HeaderValue::from_str(identity.subject())
                else {
                    return Err(Refusal::new(
                        403,
                        "STS-XPEP-0087",
                        "the subject cannot be carried in the route's \
                         subject header",
                    ));
                };
                headers.insert(name.clone(), value);
            }
            if let Some(name) = &route.mechanism_header {
                headers.insert(
                    name.clone(),
                    HeaderValue::from_static(identity.mechanism.as_str()),
                );
            }
        }
        let client = self.upstream_client(config.upstream_timeout_ms)?;
        let has_body = parts.headers.contains_key(header::CONTENT_LENGTH)
            || parts.headers.contains_key(header::TRANSFER_ENCODING);
        let over = Arc::new(AtomicBool::new(false));
        let mut request = client
            .request(parts.method.clone(), url)
            .headers(headers)
            .timeout(Duration::from_millis(config.upstream_timeout_ms));
        if has_body {
            request = request.body(reqwest::Body::wrap(LimitedBody {
                inner: Mutex::new(body),
                seen: 0,
                limit: config.max_body_bytes,
                over: over.clone(),
            }));
        }
        let answered = request.send().await;
        let upstream = match answered {
            Ok(upstream) => upstream,
            Err(_) if over.load(Ordering::SeqCst) => {
                return Err(Refusal::new(
                    413,
                    "STS-XPEP-0067",
                    "the request body is larger than maxBodyBytes",
                ))
            }
            Err(error) if error.is_timeout() => {
                return Err(Refusal::new(
                    504,
                    "STS-XPEP-0068",
                    &format!(
                        "the application did not answer in {}ms",
                        config.upstream_timeout_ms
                    ),
                ))
            }
            Err(error) => {
                return Err(Refusal::new(
                    502,
                    "STS-XPEP-0069",
                    &format!("the application could not be reached: {}", error),
                ))
            }
        };
        let status = upstream.status();
        let headers = response_headers(upstream.headers());
        let mut response =
            Response::new(Body::new(reqwest::Body::from(upstream)));
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        Ok(response)
    }
}

fn tower_service(
    proxy: Arc<Proxy>,
    transport: Transport,
) -> TowerToHyperService<axum::routing::Router> {
    let router =
        axum::Router::new().fallback(move |mut request: Request<Body>| {
            let proxy = proxy.clone();
            request.extensions_mut().insert(transport.clone());
            async move { proxy.handle(request).await }
        });
    TowerToHyperService::new(router)
}

/// The plain listener. A port that will not bind is logged and the PEP
/// goes on: the proxy is a feature of this container, not its purpose.
pub async fn serve_http(proxy: Arc<Proxy>, port: u16) {
    let listener = match TcpListener::bind(("0.0.0.0", port)).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(
                "{}xacml-pep: the reverse proxy could not listen on {}: {}. \
                 The PEP's own endpoints and enforcement are unaffected.",
                tag("STS-XPEP-0063"),
                port,
                error
            );
            return;
        }
    };
    serve_on(proxy, listener).await;
}

/// The accept loop over a bound listener (the tests bind port 0).
pub async fn serve_on(proxy: Arc<Proxy>, listener: TcpListener) {
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    tracing::info!(
        "xacml-pep: the reverse proxy listens on {} (plain HTTP).",
        port
    );
    loop {
        let Ok((stream, remote)) = listener.accept().await else {
            continue;
        };
        let proxy = proxy.clone();
        tokio::spawn(async move {
            let transport = Transport {
                https: false,
                peer: None,
                remote: Some(remote),
            };
            let served = Builder::new(TokioExecutor::new())
                .serve_connection(
                    TokioIo::new(stream),
                    tower_service(proxy, transport),
                )
                .await;
            if let Err(error) = served {
                tracing::debug!("proxy connection ended: {}", error);
            }
        });
    }
}

/// The HTTPS listener: started the first time a usable pair appears.
pub async fn serve_https(proxy: Arc<Proxy>, https: Arc<HttpsListener>) {
    let listener = match TcpListener::bind(("0.0.0.0", https.port())).await {
        Ok(listener) => listener,
        Err(error) => {
            https.mark_bind_failed(&error.to_string());
            return;
        }
    };
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    https.mark_listening(port);
    loop {
        let Ok((stream, remote)) = listener.accept().await else {
            continue;
        };
        let Some(acceptor) = https.current() else {
            continue;
        };
        let proxy = proxy.clone();
        tokio::spawn(async move {
            let Ok(ssl) = openssl::ssl::Ssl::new(acceptor.context()) else {
                return;
            };
            let Ok(mut tls) = tokio_openssl::SslStream::new(ssl, stream) else {
                return;
            };
            if let Err(error) = Pin::new(&mut tls).accept().await {
                tracing::debug!("proxy TLS handshake failed: {}", error);
                return;
            }
            let transport = Transport {
                https: true,
                peer: peer_of(tls.ssl()),
                remote: Some(remote),
            };
            let served = Builder::new(TokioExecutor::new())
                .serve_connection(
                    TokioIo::new(tls),
                    tower_service(proxy, transport),
                )
                .await;
            if let Err(error) = served {
                tracing::debug!("proxy connection ended: {}", error);
            }
        });
    }
}
