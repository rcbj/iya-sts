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
use reqwest::Method;
use serde_json::json;
use sts_core::log::tag;
use tokio::net::TcpListener;

use crate::jwt;
use crate::listener::{peer_of, HttpsListener, Transport};
use crate::pdp_client::{Body as CallBody, PdpClient};
use crate::proxy_auth::{now_s, Authenticator, Identity, Refusal};
use crate::proxy_config::{Mechanism, ProxyConfig, Pulled, Route};
use crate::proxy_request::{
    cookie_value, forward_headers, is_browser, normalise_path,
    response_headers, SESSION_COOKIE,
};
use crate::rp_session::{self, Pending, Session};
use crate::service::Pep;
use crate::sync::encode;

pub const CALLBACK_PATH: &str = "/.iya-pep/callback";
pub const LOGOUT_PATH: &str = "/.iya-pep/logout";

/// The reverse proxy: the PEP it decides with, the mechanisms, and one
/// client to the upstream per timeout.
pub struct Proxy {
    pep: Arc<Pep>,
    auth: Authenticator,
    upstream: Mutex<Option<(u64, reqwest::Client)>>,
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

fn with_query(base: &str, pairs: &[(&str, &str)]) -> String {
    let query = pairs
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let separator = if base.contains('?') { '&' } else { '?' };
    format!("{}{}{}", base, separator, query)
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
        Proxy {
            pep,
            auth: Authenticator::new(client, ttl),
            upstream: Mutex::new(None),
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
                .callback(query.as_deref(), &pulled, config, &transport, &asked)
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
        let Some(session) = held else {
            return self.no_session(
                route, pulled, config, transport, browser, path, query, false,
            );
        };
        let recheck =
            Duration::from_millis(self.pep.options.proxy_session_recheck_ms);
        if session.last_checked.elapsed() >= recheck {
            match self.auth.session_live(&session.sid, pulled).await {
                Err(refusal) => return Established::Refused(refusal),
                Ok(Some((sub, username))) => {
                    stores.checked(&id, &sub, &username);
                }
                Ok(None) => {
                    stores.end(&id);
                    self.pep.sync.count_session_ended();
                    tracing::info!(
                        "{}xacml-pep: proxy: the service says a proxy \
                         session's sign-on session has ended (route {}); \
                         the proxy session is ended.",
                        tag("STS-XPEP-0084"),
                        route.id
                    );
                    return self.no_session(
                        route, pulled, config, transport, browser, path, query,
                        true,
                    );
                }
            }
        }
        let current = stores.get(&id).unwrap_or(session);
        Established::Who(Identity {
            sub: current.sub.clone(),
            username: current.username.clone(),
            mechanism: Mechanism::Session,
        })
    }

    /// No live proxy session: a browser is sent to sign in, anything else
    /// is a 401. `ended` clears the cookie on the way.
    #[allow(clippy::too_many_arguments)]
    fn no_session(
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
        let realm = &pulled.realm;
        let redirect_uri = realm.redirect_uri.clone().unwrap_or_else(|| {
            format!("{}{}", config.public_base_url, CALLBACK_PATH)
        });
        let Some(client_id) = realm
            .client_id
            .as_deref()
            .filter(|_| !realm.authorization_endpoint.is_empty())
        else {
            return Established::Refused(Refusal::new(
                503,
                "STS-XPEP-0090",
                "the session mechanism is not set up: the service named no \
                 client or no authorization endpoint for this PEP",
            ));
        };
        let (Some(state), Some(nonce), Some(verifier)) = (
            rp_session::random_token(32),
            rp_session::random_token(32),
            rp_session::random_token(32),
        ) else {
            return Established::Refused(Refusal::new(
                503,
                "STS-XPEP-0085",
                "no random value could be drawn for a sign-in",
            ));
        };
        let return_to = match query {
            Some(q) => format!("{}?{}", path, q),
            None => path.to_string(),
        };
        let location = with_query(
            &realm.authorization_endpoint,
            &[
                ("response_type", "code"),
                ("client_id", client_id),
                ("redirect_uri", &redirect_uri),
                ("scope", "openid"),
                ("state", &state),
                ("nonce", &nonce),
                ("code_challenge", &rp_session::code_challenge(&verifier)),
                ("code_challenge_method", "S256"),
            ],
        );
        self.pep.sync.proxy_sessions.begin(
            state,
            Pending {
                code_verifier: verifier,
                nonce,
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

    /// `GET /.iya-pep/callback`: the code redeemed, the ID Token verified
    /// here, a proxy session made, the browser sent where it was going.
    #[tracing::instrument(level = "debug", skip_all)]
    async fn callback(
        &self,
        query: Option<&str>,
        pulled: &Pulled,
        config: &ProxyConfig,
        transport: &Transport,
        asked: &Asked<'_>,
    ) -> Response<Body> {
        let refused = |why: &str| {
            self.refuse(&Refusal::new(401, "STS-XPEP-0082", why), asked, pulled)
        };
        let pairs = query_pairs(query);
        let get = |k: &str| {
            pairs
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        let state = get("state");
        let pending = if state.is_empty() {
            None
        } else {
            self.pep.sync.proxy_sessions.take(&state)
        };
        if !get("error").is_empty() {
            return refused(
                "the identity service answered the sign-in with an \
                            error",
            );
        }
        let Some(pending) = pending else {
            return refused("the sign-in is unknown, already used or expired");
        };
        let code = get("code");
        if code.is_empty() {
            return refused("the sign-in came back with no code");
        }
        let realm = &pulled.realm;
        let (Some(client_id), false) =
            (realm.client_id.as_deref(), realm.token_endpoint.is_empty())
        else {
            return self.refuse(
                &Refusal::new(
                    503,
                    "STS-XPEP-0090",
                    "the session mechanism is not set up: no client or no \
                     token endpoint",
                ),
                asked,
                pulled,
            );
        };
        let redirect_uri = realm.redirect_uri.clone().unwrap_or_else(|| {
            format!("{}{}", config.public_base_url, CALLBACK_PATH)
        });
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("client_id", client_id),
            ("code_verifier", pending.code_verifier.as_str()),
        ]
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect::<Vec<_>>()
        .join("&");
        let answer = self
            .auth
            .client()
            .call_url(
                Method::POST,
                &realm.token_endpoint,
                Some(CallBody::Form(form)),
                &[],
                None,
            )
            .await;
        if answer.error.is_some() {
            return self.refuse(
                &Refusal::new(
                    502,
                    "STS-XPEP-0075",
                    "the token endpoint could not be reached",
                ),
                asked,
                pulled,
            );
        }
        let id_token = answer
            .json
            .as_ref()
            .filter(|_| answer.status == 200)
            .and_then(|j| j["id_token"].as_str())
            .map(str::to_string);
        let Some(id_token) = id_token else {
            return refused(&format!(
                "the token endpoint did not redeem the code (HTTP {})",
                answer.status
            ));
        };
        let id_refused = |why: &str| {
            self.refuse(
                &Refusal::new(
                    401,
                    "STS-XPEP-0083",
                    &format!("the ID Token was refused: {}", why),
                ),
                asked,
                pulled,
            )
        };
        let claims =
            match self.auth.verified_claims(&id_token, &realm.jwks_uri).await {
                Ok(Some(claims)) => claims,
                Ok(None) => {
                    return id_refused(
                        "it could not be verified here (unknown key or \
                     algorithm)",
                    )
                }
                Err(why) => return id_refused(why),
            };
        if let Some(why) =
            jwt::claims_problem(&claims, &realm.issuer, client_id, now_s())
        {
            return id_refused(why);
        }
        let several = claims["aud"].as_array().is_some_and(|a| a.len() > 1);
        if several && claims["azp"].as_str() != Some(client_id) {
            return id_refused("it has several audiences and azp is not ours");
        }
        let nonce = claims["nonce"].as_str().unwrap_or("");
        if nonce.len() != pending.nonce.len()
            || !openssl::memcmp::eq(nonce.as_bytes(), pending.nonce.as_bytes())
        {
            return id_refused("its nonce is not the one this sign-in sent");
        }
        let sid = claims["sid"].as_str().unwrap_or("").to_string();
        let sub = claims["sub"].as_str().unwrap_or("").to_string();
        if sid.is_empty() || sub.is_empty() {
            return id_refused(
                "it carries no sid or no sub, so its liveness cannot be asked",
            );
        }
        let username = claims["preferred_username"]
            .as_str()
            .or_else(|| claims["username"].as_str())
            .unwrap_or("")
            .to_string();
        let now = Instant::now();
        let created = self.pep.sync.proxy_sessions.create(Session {
            sid,
            sub,
            username,
            id_token,
            created: now,
            last_checked: now,
        });
        let Ok(id) = created else {
            return self.refuse(
                &Refusal::new(
                    503,
                    "STS-XPEP-0085",
                    "this proxy holds PEP_PROXY_MAX_SESSIONS live sessions",
                ),
                asked,
                pulled,
            );
        };
        self.pep.sync.count_sign_in();
        let mut response = redirect(&pending.return_to);
        if let Some(cookie) = session_cookie(&id, transport.https, false) {
            response.headers_mut().insert(header::SET_COOKIE, cookie);
        }
        response
    }

    /// `/.iya-pep/logout`: the proxy session ended, then the service's
    /// RP-initiated logout when it named one.
    fn logout(
        &self,
        headers: &HeaderMap,
        pulled: &Pulled,
        transport: &Transport,
    ) -> Response<Body> {
        let id = cookie_value(headers, SESSION_COOKIE).unwrap_or_default();
        let ended = if id.is_empty() {
            None
        } else {
            self.pep.sync.proxy_sessions.end(&id)
        };
        if ended.is_some() {
            self.pep.sync.count_session_ended();
        }
        let realm = &pulled.realm;
        let mut response = if realm.end_session_endpoint.is_empty() {
            json_answer(200, json!({ "signedOut": ended.is_some() }))
        } else {
            let mut pairs: Vec<(&str, &str)> = Vec::new();
            if let Some(client) = realm.client_id.as_deref() {
                pairs.push(("client_id", client));
            }
            if let Some(session) = &ended {
                pairs.push(("id_token_hint", session.id_token.as_str()));
            }
            redirect(&if pairs.is_empty() {
                realm.end_session_endpoint.clone()
            } else {
                with_query(&realm.end_session_endpoint, &pairs)
            })
        };
        if let Some(cookie) = session_cookie("", transport.https, true) {
            response.headers_mut().insert(header::SET_COOKIE, cookie);
        }
        response
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
