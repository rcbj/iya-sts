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
//! GET  /.iya-pep/accounts       the account chooser (multipleAccounts)
//! GET  /.iya-pep/accounts/add   sign in another account (prompt=login)
//! POST /.iya-pep/accounts/switch, /logout, /logout-all
//! GET  /                        the start page, when no route matches /
//! GET  /.iya-pep/logo.png       the product logo that page draws
//! everything else               the route table
//! ```
//!
//! **DENY BY DEFAULT.** No configuration, a configuration switched off, a
//! path that matches no route: 404, and the application is never reached.
//! A browser's GET or HEAD of `/` is the exception once a configuration
//! has been received: the start page (`proxy_page::front_document`),
//! because that is where *Go to the start page* goes. A route mounted at
//! `/` is that route. A client that does not accept HTML still gets the
//! 404. Until the first configuration, `/` is the 503 with every other
//! path.
//!
//! A request is answered in this order, and each step's refusal is the
//! first one it meets: the path normalised (400), the route found (404),
//! the method (405 with `Allow`, when the route's list is not empty), the
//! declared body size (413), then — unless the route is public — the
//! mechanism (401, with a challenge per mechanism the route allows, or a
//! 302 to sign in for a browser on a `session` route), then the decision,
//! public routes included (403; `STS-XPEP-0117` when the route's policy is
//! not held), then deny-all for an empty method list (403), then the
//! application (502, 504, or a streamed body over the bound: 413).
//!
//! **THE DESTINATION IS NEVER THE REQUEST'S.** The upstream URL is the
//! configured upstream base, the NORMALISED path and the original query;
//! the result is checked to still be on the upstream's origin and under its
//! path (`STS-XPEP-0091`). No redirect the application answers is followed
//! — it is the client's to follow, through this proxy again.
//!
//! **THE DECISION IS THE ONE `/protected` MAKES** (D8): `service.rs`'s
//! `decide_proxy()` — the subject (the username when known, else `sub`;
//! none on a public route), `authorization.resource` or the path, the
//! action its `actionModel` names, through the one builder, the PIP,
//! `enforce.rs`, and the same counters — **evaluated against the policy
//! the route NAMES, never the root** (#1760).
//!
//! `proxy_request.rs` holds the path and header rules, `proxy_auth.rs` the
//! mechanisms, `rp_session.rs` the session stores, `proxy_config.rs` the
//! pulled configuration.

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::http::{
    header, HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode,
};
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use hyper_util::service::TowerToHyperService;
use serde_json::{json, Value};
use sts_core::log::tag;
use tokio::net::TcpListener;

use crate::identity::{self, Jar, Jars, Tokens};
use crate::listener::{peer_of, ClientAuth, HttpsListener, Transport};
use crate::listener_pool::{drive, ListenerRuntime};
use crate::pdp_client::PdpClient;
use crate::proxy_auth::{self, Authenticator, Identity, Refusal};
use crate::proxy_config::{
    IdentityMode, Mechanism, ProxyConfig, Pulled, Route,
};
use crate::proxy_page::{self, Action, ErrorPage, Row};
use crate::proxy_request::{
    cookie_value, forward_headers, is_browser, normalise_path,
    response_headers, strip_list, wants_html, ACCOUNTS_COOKIE, SESSION_COOKIE,
};
use crate::rp_session::{self, Pending, Session};
use crate::rp_set::{self, RpLimits, RpSet};
use crate::service::Pep;
use crate::sync::encode;
use oidc_caep_risc::{AuthorizeOptions, EndSessionOptions};

/// Every path under it is the proxy's own (#1830): its pages, or 404.
pub const RESERVED_PREFIX: &str = crate::proxy_config::RESERVED_PREFIX;
pub const CALLBACK_PATH: &str = "/.iya-pep/callback";
pub const LOGOUT_PATH: &str = "/.iya-pep/logout";
/// SEVERAL ACCOUNTS IN ONE BROWSER (#1760): the chooser and its acts.
pub const ACCOUNTS_PATH: &str = "/.iya-pep/accounts";
pub const ACCOUNTS_ADD_PATH: &str = "/.iya-pep/accounts/add";
pub const ACCOUNTS_SWITCH_PATH: &str = "/.iya-pep/accounts/switch";
pub const ACCOUNTS_LOGOUT_PATH: &str = "/.iya-pep/accounts/logout";
pub const ACCOUNTS_LOGOUT_ALL_PATH: &str = "/.iya-pep/accounts/logout-all";

/// The reverse proxy: the PEP it decides with, and the mechanisms.
pub struct Proxy {
    pep: Arc<Pep>,
    auth: Authenticator,
    /// The session mechanism's relying parties (`rp_set.rs`).
    rps: Arc<RpSet>,
    /// Mode `jwt`'s tokens and mode `saml`'s jars (D11, `identity.rs`).
    tokens: Tokens,
    jars: Jars,
}

/// What a route sends the application about who is asking (D11).
enum Delivery {
    /// A public route, or mode `headers` with none configured.
    Nothing,
    Headers(Vec<(HeaderName, HeaderValue)>),
    /// The service's access token for the route's application.
    Bearer(String),
    /// The application's own session, established at its ACS.
    Jar {
        key: String,
        jar: Jar,
    },
}

/// What a request was, for its log line and its refusal.
struct Asked<'a> {
    method: &'a str,
    path: &'a str,
    query: Option<&'a str>,
    route: Option<&'a Route>,
    /// It accepts HTML: a refusal is the error page (`proxy_page.rs`).
    html: bool,
    /// Who the request was established as, once it was: the page's
    /// *Signed in as*.
    who: String,
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

/// The `error_description` a refusal is answered with — the JSON answer's
/// and the error page's alike. A 5xx's is a generic sentence (the reason
/// may name the service's or the application's addresses), and so are a
/// route whose application is not usable (its reason carries the service's
/// own code) and a route whose policy is not held: those are logged.
fn shown_description(refusal: &Refusal) -> String {
    match (refusal.status, refusal.code) {
        (502, _) => "The application or the identity service could not be \
                     reached, or did not answer usably."
            .to_string(),
        (503, "STS-XPEP-0118") => "This proxy has not yet received its \
                                   configuration since it started."
            .to_string(),
        (503, _) => "This proxy cannot take the request now.".to_string(),
        (504, _) => "The application did not answer in time.".to_string(),
        (_, "STS-XPEP-0093") => "This route cannot be used now.".to_string(),
        (_, "STS-XPEP-0117") => "This route cannot be decided now.".to_string(),
        _ => refusal.why.clone(),
    }
}

/// What the person can do about a refusal of WHO they are: on a session
/// route that holds several accounts, the account chooser; on any other
/// session route, sign out. A refusal of the request itself offers only
/// the start page, which every page carries. The chooser is where another
/// account is added, so this page does not offer that itself.
fn refusal_actions(refusal: &Refusal, asked: &Asked) -> Vec<Action> {
    let about_who = refusal.status == 403
        && matches!(refusal.code, "STS-XPEP-0086" | "STS-XPEP-0095");
    let Some(route) = asked.route.filter(|r| {
        about_who && !asked.who.is_empty() && r.allows(Mechanism::Session)
    }) else {
        return Vec::new();
    };
    let here = match asked.query {
        Some(q) => format!("{}?{}", asked.path, q),
        None => asked.path.to_string(),
    };
    if route.multiple_accounts {
        vec![Action {
            href: format!("{}?return={}", ACCOUNTS_PATH, encode(&here)),
            label: "Use a different account".into(),
        }]
    } else {
        vec![Action {
            href: LOGOUT_PATH.into(),
            label: "Sign out, to sign in with another account".into(),
        }]
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

/// A 303 after a form: the browser asks for the page with GET.
fn see_other(location: &str) -> Response<Body> {
    let mut response = redirect(location);
    *response.status_mut() = StatusCode::SEE_OTHER;
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

fn accounts_cookie(
    set_id: &str,
    https: bool,
    clear: bool,
) -> Option<HeaderValue> {
    let mut text = if clear {
        format!(
            "{}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax",
            ACCOUNTS_COOKIE
        )
    } else {
        format!(
            "{}={}; Path=/; HttpOnly; SameSite=Lax",
            ACCOUNTS_COOKIE, set_id
        )
    };
    if https {
        text.push_str("; Secure");
    }
    HeaderValue::from_str(&text).ok()
}

/// A browser asking for `/`: the start page, when no route is mounted
/// there. Anything else that matches no route stays a 404, and a client
/// that does not accept HTML keeps the JSON.
fn front_door(method: &str, path: &str, html: bool) -> bool {
    (method == "GET" || method == "HEAD") && path == "/" && html
}

/// A page of the proxy's own. The account chooser is the one caller: the
/// error page's document shell (`proxy_page::document_shell`), so the same
/// style sheet, the same hash in `style-src`, and the same footer. `body`
/// is HTML the caller has already escaped. The chooser is not an error
/// page; it has no diagnostics and no incident ID. The start page is
/// `proxy_page::front_document`, which uses that shell itself.
fn own_page(
    status: u16,
    title: &str,
    body: &str,
    version: &str,
) -> Response<Body> {
    proxy_page::html_response(
        status,
        proxy_page::document_shell(title, body, version),
    )
}

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Where an account act sends the browser back to: a path on THIS proxy
/// that one of its configured routes matches (normalised, with its query).
/// Anything else — not a path, off this proxy, or no route — is `/`.
fn return_path(config: &ProxyConfig, asked: Option<&str>) -> String {
    let Some(raw) =
        asked.filter(|r| r.starts_with('/') && !r.starts_with("//"))
    else {
        return "/".into();
    };
    let (path, query) = match raw.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (raw, None),
    };
    let Ok(path) = normalise_path(path) else {
        return "/".into();
    };
    if path.starts_with("/.iya-pep/") || config.route_for(&path).is_none() {
        return "/".into();
    }
    match query {
        Some(q) if !q.contains('#') => format!("{}?{}", path, q),
        _ => path,
    }
}

/// An account act's form is this proxy's own page: a cross-site POST is
/// refused whatever the cookie (it is SameSite=Lax as well).
fn same_origin(headers: &HeaderMap) -> bool {
    if let Some(site) =
        headers.get("sec-fetch-site").and_then(|v| v.to_str().ok())
    {
        if site != "same-origin" && site != "none" {
            return false;
        }
    }
    let Some(origin) =
        headers.get(header::ORIGIN).and_then(|v| v.to_str().ok())
    else {
        return true;
    };
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    reqwest::Url::parse(origin)
        .ok()
        .and_then(|u| {
            u.host_str().map(|h| match u.port() {
                Some(p) => format!("{}:{}", h, p),
                None => h.to_string(),
            })
        })
        .is_some_and(|o| o.eq_ignore_ascii_case(host))
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

/// The relying parties' bounds from the settings in force.
fn rp_limits(now: &crate::options::Now) -> RpLimits {
    RpLimits {
        allow_insecure: now.proxy_rp_allow_insecure,
        poll_ms: now.proxy_signals_poll_ms,
        stale_ms: now.proxy_signals_stale_ms,
        max_sessions: now.proxy_max_sessions,
        session_ttl_ms: now.proxy_session_ttl_ms,
    }
}

// One upstream client per worker thread, keyed by (timeout, verify-off).
//
// Each listener worker owns a current-thread runtime and polls it only
// inside `block_on` (`listener_pool.rs`). reqwest parks an idle
// connection on the runtime that opened it. One client shared by every
// worker checks that connection out on a worker that is not polling it:
// `send` waits out `upstreamTimeoutMs`, the application never sees the
// request, and the caller gets 504 `STS-XPEP-0068`. The proxy pool
// starts sixteen workers, so the second proxied request is the one that
// meets this. A client per worker thread keeps the pool on the runtime
// that drives it. Either half of the key moving builds a new client, as
// the old shared slot did; a CA change with neither moving keeps the
// client already built.
thread_local! {
    static UPSTREAM_CLIENT: RefCell<Option<((u64, bool), reqwest::Client)>> =
        const { RefCell::new(None) };
}

impl Proxy {
    pub fn new(pep: Arc<Pep>, client: PdpClient) -> Proxy {
        let now = pep.options.now();
        let ttl = now.proxy_jwks_ttl_ms;
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
        let rps = Arc::new(RpSet::new(rp_limits(&now), on_end));
        // `GET /` reports the streams' health as it is when asked.
        let reporting = rps.clone();
        pep.sync
            .set_signals_reporter(Arc::new(move || reporting.signals_json()));
        // And the heartbeat each stream on its own (#1760).
        let streaming = rps.clone();
        pep.sync
            .set_streams_reporter(Arc::new(move || streaming.streams_json()));
        Proxy {
            pep,
            auth: Authenticator::new(client, ttl),
            rps,
            tokens: Tokens::default(),
            jars: Jars::default(),
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

    /// A refusal as an answer, logged under its code: the JSON answer, or
    /// for a request that accepts HTML the error page (`proxy_page.rs`),
    /// whose incident ID the log line carries. A 5xx's description is a
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
        // The page's incident ID, in the line an operator finds it by.
        let incident = if asked.html {
            proxy_page::incident_id()
        } else {
            String::new()
        };
        let noted = if asked.html {
            format!(
                ", page incident {}",
                if incident.is_empty() {
                    "none"
                } else {
                    &incident
                }
            )
        } else {
            String::new()
        };
        // A 5xx, and a route whose policy is not held, are the operator's
        // to see; a refusal of the request itself is information.
        let warn = refusal.status >= 500 || refusal.code == "STS-XPEP-0117";
        let line = if warn {
            format!(
                "{}xacml-pep: proxy answered {} to {} {:?}{}{}: {}.",
                tag(refusal.code),
                refusal.status,
                asked.method,
                shown,
                route,
                noted,
                refusal.why
            )
        } else {
            format!(
                "{}xacml-pep: proxy refused {} {:?}{} with {}{}: {}.",
                tag(refusal.code),
                asked.method,
                shown,
                route,
                refusal.status,
                noted,
                refusal.why
            )
        };
        if refusal.code == "STS-XPEP-0118" {
            // One line per request would flood the log while the PEP waits
            // for its first pull: `Sync::note_waiting()` writes the state
            // change and a count a minute at warn, and this line, with the
            // page's incident ID, is at debug.
            tracing::debug!("{}", line);
        } else if warn {
            tracing::warn!("{}", line);
        } else {
            tracing::info!("{}", line);
        }
        #[cfg(test)]
        logged::note(&line);
        let description = shown_description(refusal);
        let error = error_name(refusal.status, refusal.token_refused);
        let mut response = if asked.html {
            self.error_page(
                refusal,
                asked,
                &description,
                incident,
                refusal_actions(refusal, asked),
            )
        } else {
            json_answer(
                refusal.status,
                json!({ "error": error,
                        "error_description": description }),
            )
        };
        let headers = response.headers_mut();
        if refusal.status == 401 {
            if let Some(route) = asked.route {
                self.challenges(route, pulled, refusal.token_refused, headers);
            }
        }
        if refusal.status == 405 {
            if let Some(allow) = refusal.allow {
                headers.insert(header::ALLOW, HeaderValue::from_static(allow));
            } else if let Some(route) = asked.route {
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

    /// The start page. Not a refusal, so nothing is logged under a code.
    fn front_page(&self) -> Response<Body> {
        proxy_page::html_response(
            200,
            proxy_page::front_document(&self.pep.version.version),
        )
    }

    /// THE ERROR PAGE A PERSON SEES (`proxy_page.rs`): the wording of the
    /// refusal's kind, what they can do, and the Diagnostics box — the
    /// time, the incident ID, and only what an API client of the same
    /// request is answered (the `error` and its description) beside the
    /// application, the address and who is signed in. **Never the code.**
    #[tracing::instrument(level = "debug", skip_all)]
    fn error_page(
        &self,
        refusal: &Refusal,
        asked: &Asked,
        description: &str,
        incident: String,
        actions: Vec<Action>,
    ) -> Response<Body> {
        let (title, message, background) =
            proxy_page::wording(refusal.status, refusal.code);
        let row = |label: &'static str, value: &str| Row {
            label,
            value: value.to_string(),
        };
        let shown: String = asked.path.chars().take(200).collect();
        let error = error_name(refusal.status, refusal.token_refused);
        ErrorPage {
            status: refusal.status,
            title: title.into(),
            error: error.into(),
            message: message.into(),
            actions,
            background: background.into(),
            incident,
            time: proxy_page::now_utc(),
            diagnostics: vec![
                row(
                    "Application",
                    asked.route.map_or("", |r| r.application.as_str()),
                ),
                row("Address", &shown),
                row("Signed in as", &asked.who),
                row("error", error),
                row("error_description", description),
            ],
            version: self.pep.version.version.clone(),
        }
        .response()
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
        let (pulled, received) = self.pep.sync.proxy_received();
        let mut asked = Asked {
            method: &method,
            path: &raw_path,
            query: query.as_deref(),
            route: None,
            html: wants_html(&parts.headers),
            who: String::new(),
        };
        let path = match normalise_path(&raw_path) {
            Ok(path) => path,
            Err(why) => {
                let refusal = Refusal::new(400, "STS-XPEP-0064", why);
                return (self.refuse(&refusal, &asked, &pulled), false);
            }
        };
        asked.path = &path;
        // NOT CONFIGURED YET IS NOT "NOTHING HERE" (rcbj, 2026-11-15): until
        // the first configuration answer since the start is loaded, every
        // path — `/.iya-pep/*` included, which needs the configuration's
        // realm and routes — is 503 with Retry-After, the poll interval,
        // so a browser and a client try again rather than conclude the page
        // does not exist. A configuration RECEIVED and empty or switched
        // off is the deny-by-default 404 below, except a browser's `/`,
        // which is the start page.
        if !received {
            let mut refusal = Refusal::new(
                503,
                "STS-XPEP-0118",
                "no proxy configuration has been received since this PEP \
                 started",
            );
            let poll = self.pep.options.now().poll_interval_ms;
            refusal.retry_after = Some(poll.div_ceil(1000).max(1).to_string());
            self.pep.sync.note_waiting();
            return (self.refuse(&refusal, &asked, &pulled), false);
        }
        // The logo is the proxy's own path, like the account pages. It is
        // answered once a configuration has been received; before that the
        // 503 above covers it with every other path.
        if (method == "GET" || method == "HEAD")
            && path == proxy_page::LOGO_PATH
        {
            return (proxy_page::logo_response(), false);
        }
        let Some(config) = pulled.active() else {
            if front_door(&method, &path, asked.html) {
                return (self.front_page(), false);
            }
            let refusal = Refusal::new(
                404,
                "STS-XPEP-0065",
                "this proxy holds no configuration that is switched on",
            );
            return (self.refuse(&refusal, &asked, &pulled), false);
        };
        // THE CALLBACK AND THE SIGN-OUT ARE GET (#1830): what a provider
        // redirects with and what a link sends, and HEAD with it. Any other
        // method is 405 with `Allow`, through the refusal envelope; the
        // callback's state is not looked up, so it is not spent.
        let gets = method == "GET" || method == "HEAD";
        if path == CALLBACK_PATH && !gets {
            let refusal = Refusal {
                allow: Some("GET, HEAD"),
                ..Refusal::new(
                    405,
                    "STS-XPEP-0126",
                    "the sign-in callback takes GET and HEAD only",
                )
            };
            return (self.refuse(&refusal, &asked, &pulled), false);
        }
        if path == CALLBACK_PATH {
            let answer = self
                .callback(query.as_deref(), &pulled, &transport, &asked)
                .await;
            return (answer, false);
        }
        if path == LOGOUT_PATH && !gets {
            let refusal = Refusal {
                allow: Some("GET, HEAD"),
                ..Refusal::new(
                    405,
                    "STS-XPEP-0127",
                    "the sign-out takes GET and HEAD only",
                )
            };
            return (self.refuse(&refusal, &asked, &pulled), false);
        }
        if path == LOGOUT_PATH {
            return (self.logout(&parts.headers, &pulled, &transport), false);
        }
        if path == ACCOUNTS_PATH || path.starts_with("/.iya-pep/accounts/") {
            let form = if method == "POST" {
                axum::body::to_bytes(body, 4096)
                    .await
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .unwrap_or_default()
            } else {
                String::new()
            };
            let answer = self
                .accounts(
                    config,
                    &pulled,
                    &parts.headers,
                    &transport,
                    &method,
                    &path,
                    query.as_deref(),
                    &form,
                    &asked,
                )
                .await;
            return (answer, false);
        }
        // `/.iya-pep/` IS THE PROXY'S, WHOLE (#1830): a path under it that
        // is none of the proxy's own is 404 here and never reaches the route
        // table, so a prefix route at `/` cannot forward it upstream. The
        // configuration refuses a route there too (`proxy_config.rs`).
        if path == RESERVED_PREFIX.trim_end_matches('/')
            || path.starts_with(RESERVED_PREFIX)
        {
            let refusal = Refusal::new(
                404,
                "STS-XPEP-0128",
                "the path is under /.iya-pep/, which is the proxy's own, and \
                 is none of its pages",
            );
            return (self.refuse(&refusal, &asked, &pulled), false);
        }
        let Some(route) = config.route_for(&path) else {
            if front_door(&method, &path, asked.html) {
                return (self.front_page(), false);
            }
            let refusal = Refusal::new(
                404,
                "STS-XPEP-0065",
                "no route matches this path",
            );
            return (self.refuse(&refusal, &asked, &pulled), false);
        };
        asked.route = Some(route);
        // A non-empty list without the method is route MATCHING, not
        // authorization: 405 with the list as `Allow`. An EMPTY list is
        // not a 405 — there is nothing to put in `Allow` — so the request
        // goes on to be decided and is refused after it (0116, below).
        if !route.methods.is_empty() && !route.takes(&method) {
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
        if !route.is_public() && !route.resolved.usable {
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
        let identity = if route.is_public() {
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
        // EVERY ROUTE IS DECIDED IN XACML, BY ITS OWN POLICY (#1760), a
        // public one too: for the anonymous subject (no subject-id), with
        // the resource-id and action-id the route's authorization says.
        let authorization = &route.authorization;
        let subject = identity.as_ref().map_or("", |i| i.subject());
        asked.who = subject.to_string();
        let resource = if authorization.resource.is_empty() {
            path.as_str()
        } else {
            authorization.resource.as_str()
        };
        let action = authorization.action_model.action_for(&method);
        let decided = self
            .pep
            .decide_proxy(subject, resource, action, &authorization.policy)
            .await;
        let Some((decision, outcome)) = decided else {
            // Whatever the bias: a route whose policy is missing is not a
            // NotApplicable, and a permit-biased PEP admitting it would
            // open the route the moment its policy was withheld.
            let refusal = Refusal::new(
                403,
                "STS-XPEP-0117",
                &format!(
                    "the route's policy {:?} is not held by this PEP (never \
                     pulled, withheld, disabled, renamed, failed to load, or \
                     a name two pulled entries carry), so nothing decided it",
                    authorization.policy
                ),
            );
            return (self.refuse(&refusal, &asked, &pulled), false);
        };
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
        // DENY-ALL: a route that states no method was decided and counted
        // above — every decision is XACML's — and is refused now whatever
        // the policy said, so a policy that permits too much cannot open a
        // route the administrator closed.
        if route.methods.is_empty() {
            let refusal = Refusal::new(
                403,
                "STS-XPEP-0116",
                "the route allows no method: deny-all",
            );
            return (self.refuse(&refusal, &asked, &pulled), false);
        }
        // D11: the identity the route sends, established BEFORE anything is
        // forwarded — a request is never sent without it.
        let delivery = match self
            .deliver(route, &pulled, config, identity.as_ref())
            .await
        {
            Ok(delivery) => delivery,
            Err(refusal) => {
                if let Some(ended) = self
                    .ended_behind(
                        &refusal,
                        route,
                        &pulled,
                        config,
                        identity.as_ref(),
                        &parts.headers,
                        &transport,
                        &method,
                        &path,
                        query.as_deref(),
                    )
                    .await
                {
                    return (ended, false);
                }
                return (self.refuse(&refusal, &asked, &pulled), false);
            }
        };
        let replayable = !parts.headers.contains_key(header::CONTENT_LENGTH)
            && !parts.headers.contains_key(header::TRANSFER_ENCODING);
        let forwarded = self
            .forward(
                route,
                config,
                &pulled,
                &parts,
                body,
                &path,
                query.as_deref(),
                &transport,
                &delivery,
            )
            .await;
        match forwarded {
            // The application's session ended (a 401, or a redirect to its
            // ACS or the identity provider): established again ONCE, and a
            // request with no body sent again. One with a body cannot be
            // replayed; its answer goes back and the next request starts
            // with the new session.
            Ok((_, true))
                if replayable && matches!(delivery, Delivery::Jar { .. }) =>
            {
                let again = self
                    .deliver(route, &pulled, config, identity.as_ref())
                    .await;
                let retried = match again {
                    Ok(delivery) => {
                        self.forward(
                            route,
                            config,
                            &pulled,
                            &parts,
                            Body::empty(),
                            &path,
                            query.as_deref(),
                            &transport,
                            &delivery,
                        )
                        .await
                    }
                    Err(refusal) => Err(refusal),
                };
                match retried {
                    Ok((response, _)) => (response, true),
                    Err(refusal) => {
                        (self.refuse(&refusal, &asked, &pulled), false)
                    }
                }
            }
            Ok((response, _)) => (response, true),
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
        if route.multiple_accounts {
            return self
                .session_of_account(
                    route, pulled, config, headers, transport, method, path,
                    query,
                )
                .await;
        }
        let stores = &self.pep.sync.proxy_sessions;
        let browser = is_browser(method, headers);
        let id = cookie_value(headers, SESSION_COOKIE).unwrap_or_default();
        let held = if id.is_empty() { None } else { stores.get(&id) };
        // A session made by another application's client is not this
        // route's: the proxy session is the application's sign-in.
        let held = held.filter(|s| s.client_id == route.resolved.client_id);
        let Some(session) = held else {
            // A COOKIE NAMING A SESSION THIS PROXY NO LONGER HOLDS IS
            // CLEARED (2026-11-14). A CAEP session-revoked removes the
            // session before the browser's next request arrives, so that
            // request found no session and was sent to sign in with the
            // dead `iya_pep_session` still set — the clearing `ended`
            // gives was only reached when THIS request found the session
            // ended. A cookie of another application's client is that
            // client's and is left alone.
            let stale = !id.is_empty() && stores.get(&id).is_none();
            return self
                .no_session(
                    route,
                    pulled,
                    config,
                    transport,
                    browser,
                    path,
                    query,
                    stale,
                    None,
                    AuthorizeOptions::default(),
                )
                .await;
        };
        let (alive, by_signals) =
            match self.alive(route, pulled, &id, &session).await {
                Ok(answer) => answer,
                Err(refusal) => return Established::Refused(refusal),
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
                    route,
                    pulled,
                    config,
                    transport,
                    browser,
                    path,
                    query,
                    true,
                    None,
                    AuthorizeOptions::default(),
                )
                .await;
        }
        let current = stores.get(&id).unwrap_or(session);
        let mut who = proxy_auth::identity(
            &current.sub,
            &current.username,
            Mechanism::Session,
        );
        who.session_id = Some(id.clone());
        Established::Who(who)
    }

    /// Whether a proxy session is still live, and whether the library's
    /// signals said so: its receiver's cache (a CAEP session-revoked removes
    /// the session from it), or the service's session endpoint when its
    /// last answer is older than `proxySessionRecheckMs`.
    async fn alive(
        &self,
        route: &Route,
        pulled: &Pulled,
        id: &str,
        session: &Session,
    ) -> Result<(bool, bool), Refusal> {
        let party = self.rps.held(&session.client_id);
        let by_signals = route.signals
            && party.as_ref().is_some_and(rp_set::Party::signals_live);
        if by_signals {
            // THE LIBRARY'S ANSWER: a map lookup.
            return Ok((
                party.as_ref().is_some_and(|p| p.rp.session(id).is_some()),
                true,
            ));
        }
        let recheck = Duration::from_millis(
            self.pep.options.now().proxy_session_recheck_ms,
        );
        if session.last_checked.elapsed() < recheck {
            return Ok((true, false));
        }
        match self.auth.session_live(&session.sid, pulled).await? {
            Some((sub, username, name)) => {
                let stores = &self.pep.sync.proxy_sessions;
                stores.checked(id, &sub, &username);
                stores.named(id, "", &name);
                Ok((true, false))
            }
            None => Ok((false, false)),
        }
    }

    /// THE SESSION MECHANISM WITH SEVERAL ACCOUNTS (#1760): the browser's
    /// account set (the `iya_pep_accounts` cookie) holds one proxy session
    /// per account, and the request is the ACTIVE account's for the
    /// route's application — the one identity forwarded, held to the same
    /// liveness check, header stripping and decision as a single sign-in.
    /// No active account while others are held sends a browser to the
    /// chooser: an identity is never picked for the person.
    #[allow(clippy::too_many_arguments)]
    async fn session_of_account(
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
        let client = route.resolved.client_id.clone();
        let set_id = cookie_value(headers, ACCOUNTS_COOKIE).unwrap_or_default();
        let set = stores.account_set(&set_id);
        let here = match query {
            Some(q) => format!("{}?{}", path, q),
            None => path.to_string(),
        };
        let chooser = || {
            Established::Answer(redirect(&format!(
                "{}?return={}",
                ACCOUNTS_PATH,
                encode(&here)
            )))
        };
        let active = set.as_ref().and_then(|s| s.active_for(&client).cloned());
        let Some(account) = active else {
            let others = set
                .as_ref()
                .map(|s| s.of_client(&client).len())
                .unwrap_or(0);
            if others > 0 && browser {
                return chooser();
            }
            return self
                .no_session(
                    route,
                    pulled,
                    config,
                    transport,
                    browser,
                    path,
                    query,
                    false,
                    Some(set_id),
                    AuthorizeOptions::default(),
                )
                .await;
        };
        let Some(session) = stores.get(&account.session_id) else {
            stores.end(&account.session_id);
            return if browser {
                chooser()
            } else {
                Established::Refused(Refusal::new(
                    401,
                    "STS-XPEP-0084",
                    "the active account's proxy session has ended",
                ))
            };
        };
        let (alive, by_signals) = match self
            .alive(route, pulled, &account.session_id, &session)
            .await
        {
            Ok(answer) => answer,
            Err(refusal) => return Established::Refused(refusal),
        };
        if !alive {
            // THAT account ends, and only that one.
            self.end_session(&account.session_id, &session.client_id);
            tracing::info!(
                "{}xacml-pep: proxy: the sign-on session behind one account \
                 of a browser's set has ended at the service ({}, route {}); \
                 that account is signed out and the others are kept.",
                tag("STS-XPEP-0084"),
                if by_signals {
                    "a CAEP/RISC signal"
                } else {
                    "its session endpoint"
                },
                route.id
            );
            return if browser {
                chooser()
            } else {
                Established::Refused(Refusal::new(
                    401,
                    "STS-XPEP-0084",
                    "the active account's sign-on session has ended",
                ))
            };
        }
        let current = stores.get(&account.session_id).unwrap_or(session);
        let mut who = proxy_auth::identity(
            &current.sub,
            &current.username,
            Mechanism::Session,
        );
        who.session_id = Some(account.session_id.clone());
        Established::Who(who)
    }

    /// THE WINDOW BEFORE THE SIGNAL (2026-11-14). A sign-out at the service
    /// revokes the session's access tokens at once, while the CAEP
    /// session-revoked that ends the proxy session arrives up to a second
    /// later — so in between, the identity door refused the token and a
    /// browser got a 403 "the service refused the identity" where it
    /// should have been sent to sign in. When the identity door refuses a
    /// PROXY SESSION's identity, the service is asked whether that sign-on
    /// session is still live; if it is not, the proxy session ends here as
    /// a signal would have ended it: a browser is sent to sign in with the
    /// cookie cleared, anything else is a 401. Any other refusal is
    /// answered as it was.
    #[allow(clippy::too_many_arguments)]
    async fn ended_behind(
        &self,
        refusal: &Refusal,
        route: &Route,
        pulled: &Pulled,
        config: &ProxyConfig,
        identity: Option<&Identity>,
        headers: &HeaderMap,
        transport: &Transport,
        method: &str,
        path: &str,
        query: Option<&str>,
    ) -> Option<Response<Body>> {
        if refusal.status != 403 || refusal.code != "STS-XPEP-0095" {
            return None;
        }
        let who = identity?;
        if who.mechanism != Mechanism::Session {
            return None;
        }
        let id = who.session_id.clone()?;
        let stores = &self.pep.sync.proxy_sessions;
        let session = stores.get(&id)?;
        match self.auth.session_live(&session.sid, pulled).await {
            Ok(None) => {}
            _ => return None,
        }
        self.end_session(&id, &session.client_id);
        tracing::info!(
            "{}xacml-pep: proxy: the identity endpoint refused a proxy \
             session's identity and its sign-on session has ended at the \
             service (route {}); the proxy session is ended before the \
             signal arrives.",
            tag("STS-XPEP-0084"),
            route.id
        );
        let browser = is_browser(method, headers);
        if route.multiple_accounts && browser {
            let here = match query {
                Some(q) => format!("{}?{}", path, q),
                None => path.to_string(),
            };
            return Some(redirect(&format!(
                "{}?return={}",
                ACCOUNTS_PATH,
                encode(&here)
            )));
        }
        let ended = self
            .no_session(
                route,
                pulled,
                config,
                transport,
                browser,
                path,
                query,
                true,
                None,
                AuthorizeOptions::default(),
            )
            .await;
        match ended {
            Established::Answer(response) => Some(response),
            Established::Refused(refused) => Some(self.refuse(
                &refused,
                &Asked {
                    method,
                    path,
                    query,
                    route: Some(route),
                    html: wants_html(headers),
                    who: String::new(),
                },
                pulled,
            )),
            Established::Who(_) => None,
        }
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
        account_set: Option<String>,
        options: AuthorizeOptions,
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
        let member = self.pep.sync.registered_name();
        let party = match self
            .rps
            .party(&client_id, pulled, route.signals, member.as_deref())
            .await
        {
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
        let authorized = rp.authorize_async(options).await;
        let transaction = match authorized {
            Ok(transaction) => transaction,
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
                account_set,
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
        let completed = rp
            .complete_session_async(pairs, transaction, session_id)
            .await;
        let login = match completed {
            Ok(login) => login,
            Err(error) => {
                return refused(
                    "STS-XPEP-0083",
                    &format!(
                        "the sign-in was refused ({}): {}",
                        error.code, error.message
                    ),
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
        let unnamed = username.is_empty();
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
        // WHO SIGNED IN, BY NAME (2026-11-14). The service's ID Token
        // carries no `preferred_username` (#395), so a session made from it
        // alone was labelled by its `urn:uuid` subject on the account
        // chooser. The ID Token's `name` is taken where it has one, and the
        // service's session endpoint — asked once, here — names the person.
        let display = login
            .claims
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let learned = if unnamed && !login.sid.is_empty() {
            self.auth
                .session_live(&login.sid, pulled)
                .await
                .ok()
                .flatten()
        } else {
            None
        };
        let (learned_name, learned_display) =
            learned.map(|(_, u, n)| (u, n)).unwrap_or_default();
        self.pep.sync.proxy_sessions.named(&id, &learned_name, "");
        let display = if display.is_empty() {
            learned_display
        } else {
            display
        };
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
        // SEVERAL ACCOUNTS (#1760): the sign-in joins the browser's set and
        // becomes its active account; the same person again replaces their
        // own account's session; a full set refuses the new one.
        if let Some(set_id) = &pending.account_set {
            let max = self.pep.options.now().proxy_max_accounts;
            let stores = &self.pep.sync.proxy_sessions;
            let username =
                stores.get(&id).map(|s| s.username).unwrap_or_default();
            match stores.add_account(
                set_id,
                &id,
                &pending.client_id,
                &login.subject,
                &username,
                max,
            ) {
                Ok(added) => {
                    stores.named(&id, "", &display);
                    if let Some(old) = &added.replaced {
                        self.end_session(old, &pending.client_id);
                    }
                    tracing::info!(
                        "xacml-pep: proxy: an account joined a browser's \
                         set and is its active one."
                    );
                    let mut response = redirect(&pending.return_to);
                    if let Some(cookie) =
                        accounts_cookie(&added.set_id, transport.https, false)
                    {
                        response
                            .headers_mut()
                            .insert(header::SET_COOKIE, cookie);
                    }
                    return response;
                }
                Err(refused) => {
                    self.end_session(&id, &pending.client_id);
                    let held = match refused {
                        rp_session::AddRefused::Full(n) => n,
                        rp_session::AddRefused::NoRandom => 0,
                    };
                    // Always the page: the callback is a browser's
                    // navigation, and this refusal was a page before.
                    let incident = proxy_page::incident_id();
                    let line = format!(
                        "{}xacml-pep: proxy: a sign-in was refused: the \
                         browser's set already holds {} account(s) \
                         (proxyMaxAccounts {}), page incident {}.",
                        tag("STS-XPEP-0108"),
                        held,
                        max,
                        if incident.is_empty() {
                            "none"
                        } else {
                            &incident
                        }
                    );
                    tracing::warn!("{}", line);
                    #[cfg(test)]
                    logged::note(&line);
                    let why = format!(
                        "this browser is already signed in to {} account(s) \
                         here, the most this proxy allows",
                        held
                    );
                    return self.error_page(
                        &Refusal::new(403, "STS-XPEP-0108", &why),
                        asked,
                        &why,
                        incident,
                        vec![Action {
                            href: format!(
                                "{}?return={}",
                                ACCOUNTS_PATH,
                                encode(&pending.return_to)
                            ),
                            label: "Choose an account".into(),
                        }],
                    );
                }
            }
        }
        let mut response = redirect(&pending.return_to);
        if let Some(cookie) = session_cookie(&id, transport.https, false) {
            response.headers_mut().insert(header::SET_COOKIE, cookie);
        }
        response
    }

    /// THE ACCOUNT CHOOSER AND ITS ACTS (#1760), the multipleAccounts
    /// routes' pages, under `/.iya-pep/accounts`. GET draws the browser's
    /// accounts (HTML, or JSON with `?format=json`); the active account's
    /// *Continue with this user* goes to `return`. `add` starts a sign-in
    /// of another account with `prompt=login` (or of a held account again,
    /// with its `login_hint` and the subject the ID Token must name); the
    /// three POSTs switch, sign one out, or sign all out — HERE: the
    /// service's sign-on sessions are the person's to end there. `return`
    /// is followed only when its path matches a configured route.
    #[allow(clippy::too_many_arguments)]
    async fn accounts(
        &self,
        config: &ProxyConfig,
        pulled: &Pulled,
        headers: &HeaderMap,
        transport: &Transport,
        method: &str,
        path: &str,
        query: Option<&str>,
        form: &str,
        asked: &Asked<'_>,
    ) -> Response<Body> {
        let stores = &self.pep.sync.proxy_sessions;
        let set_id = cookie_value(headers, ACCOUNTS_COOKIE).unwrap_or_default();
        let given: HashMap<String, String> = query_pairs(query)
            .into_iter()
            .chain(query_pairs(Some(form)))
            .collect();
        let back = return_path(config, given.get("return").map(String::as_str));
        let refuse = |status: u16, code: &'static str, why: &str| {
            self.refuse(&Refusal::new(status, code, why), asked, pulled)
        };
        if method == "POST" && !same_origin(headers) {
            return refuse(
                403,
                "STS-XPEP-0109",
                "an account act from another site is refused",
            );
        }
        let application_of = |client: &str| -> String {
            config
                .routes
                .iter()
                .find(|r| r.resolved.client_id == client)
                .map(|r| r.application.clone())
                .unwrap_or_default()
        };
        match (method, path) {
            ("GET", ACCOUNTS_PATH) | ("HEAD", ACCOUNTS_PATH) => {
                let set = stores.account_set(&set_id).unwrap_or_default();
                if given.get("format").map(String::as_str) == Some("json") {
                    let accounts: Vec<Value> = set
                        .accounts
                        .iter()
                        .map(|a| {
                            json!({
                                "account": a.account,
                                "username": a.username,
                                "name": a.name,
                                "application": application_of(&a.client_id),
                                "active": set.active.get(&a.client_id)
                                    == Some(&a.account)
                            })
                        })
                        .collect();
                    return json_answer(
                        200,
                        json!({
                            "accounts": accounts,
                            "max": self.pep.options.now().proxy_max_accounts
                        }),
                    );
                }
                own_page(
                    200,
                    "Accounts",
                    &self.chooser_html(&set, &back, &application_of),
                    &self.pep.version.version,
                )
            }
            ("GET", ACCOUNTS_ADD_PATH) => {
                let Some(route) = config
                    .route_for(back.split('?').next().unwrap_or("/"))
                    .filter(|r| {
                        r.multiple_accounts
                            && r.mechanisms.contains(&Mechanism::Session)
                            && !r.is_public()
                    })
                else {
                    return refuse(
                        404,
                        "STS-XPEP-0110",
                        "the page to return to is not on a route \
                                   that holds several accounts",
                    );
                };
                let again = given
                    .get("account")
                    .and_then(|a| stores.account_of(&set_id, a));
                let options = AuthorizeOptions {
                    prompt: "login".into(),
                    login_hint: again
                        .as_ref()
                        .map(|a| a.username.clone())
                        .unwrap_or_default(),
                    expected_sub: again
                        .as_ref()
                        .map(|a| a.sub.clone())
                        .unwrap_or_default(),
                    ..AuthorizeOptions::default()
                };
                let (path_part, query_part) = match back.split_once('?') {
                    Some((p, q)) => (p.to_string(), Some(q.to_string())),
                    None => (back.clone(), None),
                };
                match self
                    .no_session(
                        route,
                        pulled,
                        config,
                        transport,
                        true,
                        &path_part,
                        query_part.as_deref(),
                        false,
                        Some(set_id),
                        options,
                    )
                    .await
                {
                    Established::Answer(response) => response,
                    Established::Refused(refusal) => {
                        self.refuse(&refusal, asked, pulled)
                    }
                    Established::Who(_) => {
                        refuse(500, "STS-XPEP-0110", "no sign-in was started")
                    }
                }
            }
            ("POST", ACCOUNTS_SWITCH_PATH) => {
                let account = given.get("account").cloned().unwrap_or_default();
                if stores.switch_account(&set_id, &account).is_none() {
                    return refuse(
                        404,
                        "STS-XPEP-0111",
                        "this browser holds no such account",
                    );
                }
                tracing::info!(
                    "xacml-pep: proxy: a browser switched its active account."
                );
                see_other(&back)
            }
            ("POST", ACCOUNTS_LOGOUT_PATH) => {
                let account = given.get("account").cloned().unwrap_or_default();
                let Some(one) = stores.account_of(&set_id, &account) else {
                    return refuse(
                        404,
                        "STS-XPEP-0111",
                        "this browser holds no such account",
                    );
                };
                self.end_session(&one.session_id, &one.client_id);
                tracing::info!(
                    "xacml-pep: proxy: one account of a browser's set signed \
                     out here; the others are kept."
                );
                see_other(&format!(
                    "{}?return={}",
                    ACCOUNTS_PATH,
                    encode(&back)
                ))
            }
            ("POST", ACCOUNTS_LOGOUT_ALL_PATH) => {
                for one in stores.sessions_of_set(&set_id) {
                    self.end_session(&one.session_id, &one.client_id);
                }
                let mut response = see_other(&back);
                if let Some(cookie) = accounts_cookie("", transport.https, true)
                {
                    response.headers_mut().insert(header::SET_COOKIE, cookie);
                }
                response
            }
            _ => refuse(404, "STS-XPEP-0110", "no such account page"),
        }
    }

    /// The chooser: each account by its name and application, the active
    /// one marked. The active account offers *Continue with this user*, a
    /// GET form to `back` (it changes nothing). Every other account offers
    /// *Switch to this account*. Each offers *Sign out*, then *Add another*
    /// and *Sign out of all*. `back` already matches a configured route,
    /// or is `/`. Plain forms: no script. The classes are the error page's
    /// (`portal`) and this page's own (`accounts`, `hint`); the document
    /// shell supplies the style sheet.
    fn chooser_html(
        &self,
        set: &rp_session::AccountSet,
        back: &str,
        application_of: &dyn Fn(&str) -> String,
    ) -> String {
        let back_html = html_escape(back);
        let rows: String = set
            .accounts
            .iter()
            .map(|a| {
                let active = set.active.get(&a.client_id) == Some(&a.account);
                let name = if a.username.is_empty() {
                    &a.sub
                } else {
                    &a.username
                };
                let shown = if a.name.is_empty() || a.name == *name {
                    html_escape(name)
                } else {
                    format!("{} — {}", html_escape(name), html_escape(&a.name))
                };
                let act = if active {
                    let (path, query) = match back.split_once('?') {
                        Some((p, q)) => (p, q),
                        None => (back, ""),
                    };
                    let fields: String =
                        query_pairs((!query.is_empty()).then_some(query))
                            .into_iter()
                            .map(|(k, v)| {
                                format!(
                                    "<input type=\"hidden\" name=\"{}\" \
                             value=\"{}\">",
                                    html_escape(&k),
                                    html_escape(&v)
                                )
                            })
                            .collect();
                    format!(
                        "<form method=\"get\" action=\"{}\">{}<button \
                         class=\"portal\" type=\"submit\">Continue with \
                         this user</button></form>",
                        html_escape(path),
                        fields
                    )
                } else {
                    format!(
                        "<form method=\"post\" action=\"{}\"><input \
                         type=\"hidden\" name=\"account\" value=\"{}\">\
                         <input type=\"hidden\" name=\"return\" \
                         value=\"{}\"><button class=\"portal\" \
                         type=\"submit\">Switch to this account</button>\
                         </form>",
                        ACCOUNTS_SWITCH_PATH,
                        html_escape(&a.account),
                        back_html
                    )
                };
                format!(
                    "<li><strong>{}</strong> <span class=\"app\">({})\
                     </span>{}<div class=\"next\">{}<form method=\"post\" \
                     action=\"{}\"><input type=\"hidden\" name=\"account\" \
                     value=\"{}\"><input type=\"hidden\" name=\"return\" \
                     value=\"{}\"><button class=\"portal\" \
                     type=\"submit\">Sign out</button></form></div></li>",
                    shown,
                    html_escape(&application_of(&a.client_id)),
                    if active {
                        " <span class=\"mark\">— active</span>"
                    } else {
                        ""
                    },
                    act,
                    ACCOUNTS_LOGOUT_PATH,
                    html_escape(&a.account),
                    back_html
                )
            })
            .collect();
        let max = self.pep.options.now().proxy_max_accounts;
        let list = if rows.is_empty() {
            "<p class=\"hint\">No account is signed in here.</p>".to_string()
        } else {
            format!("<ul class=\"accounts\">{}</ul>", rows)
        };
        let all = if set.accounts.is_empty() {
            String::new()
        } else {
            format!(
                "<form method=\"post\" action=\"{}\"><input \
                 type=\"hidden\" name=\"return\" value=\"{}\"><button \
                 class=\"portal\" type=\"submit\">Sign out of all accounts\
                 </button></form>",
                ACCOUNTS_LOGOUT_ALL_PATH, back_html
            )
        };
        // The bound sits on its own line. Beside a portal button it read
        // as a label between the two actions.
        format!(
            "<h1>Accounts in this browser</h1>{}<p class=\"hint\">At most \
             {} accounts can be signed in here.</p><div class=\"next\">\
             <a class=\"portal\" href=\"{}?return={}\">Add another account\
             </a>{}</div>",
            list,
            max,
            ACCOUNTS_ADD_PATH,
            html_escape(&encode(back)),
            all
        )
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
        // THE SETTINGS IN FORCE (#1760), handed to the two parts that hold
        // a bound of their own: a relying party built under other bounds
        // is rebuilt by the reconcile below.
        let now = self.pep.options.now();
        self.auth.set_jwks_ttl(now.proxy_jwks_ttl_ms);
        if self.rps.set_limits(rp_limits(&now)) {
            tracing::info!(
                "xacml-pep: proxy: the relying parties' bounds changed with \
                 the settings; each is rebuilt."
            );
        }
        let pulled = self.pep.sync.proxy();
        let member = self.pep.sync.registered_name();
        self.rps.reconcile(&pulled, member.as_deref()).await;
        self.pep.sync.set_relying_parties(self.rps.counts());
    }

    fn upstream_client(
        &self,
        timeout_ms: u64,
    ) -> Result<reqwest::Client, Refusal> {
        let o = &self.pep.options;
        let insecure = o.now().proxy_upstream_insecure;
        let key = (timeout_ms, insecure);
        let cached = UPSTREAM_CLIENT.with(|slot| {
            slot.borrow()
                .as_ref()
                .filter(|(held, _)| *held == key)
                .map(|(_, client)| client.clone())
        });
        if let Some(client) = cached {
            return Ok(client);
        }
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_millis(timeout_ms))
            .no_proxy();
        if insecure {
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
        UPSTREAM_CLIENT.with(|slot| {
            *slot.borrow_mut() = Some((key, client.clone()));
        });
        Ok(client)
    }

    /// What the subject was established from, for the identity endpoint:
    /// the credential's own evidence, or — for a proxy session — the
    /// access token the library holds for it (`session_access_token`,
    /// which refreshes it when it is near its end).
    async fn evidence(
        &self,
        who: &Identity,
        route: &Route,
    ) -> Result<(&'static str, String), Refusal> {
        if let Some((kind, value)) = &who.evidence {
            return Ok((kind, value.clone()));
        }
        let none = |why: &str| Refusal::new(502, "STS-XPEP-0098", why);
        let Some(id) = who.session_id.clone() else {
            return Err(none(
                "the credential gave no evidence the identity endpoint takes \
                 (a Basic answer without a ticket)",
            ));
        };
        let Some(party) = self.rps.held(&route.resolved.client_id) else {
            return Err(none("the session's relying party is no longer held"));
        };
        let rp = party.rp.clone();
        match rp.session_access_token_async(id).await {
            Ok(access) if !access.access_token.is_empty() => {
                Ok(("access_token", access.access_token))
            }
            Ok(_) => Err(none("the session holds no access token")),
            Err(error) => Err(none(&format!(
                "the session's access token could not be had ({})",
                error.code
            ))),
        }
    }

    /// The identity a route sends (D11), or the refusal that stops the
    /// request: NEVER forwarded without the identity it was configured to
    /// send.
    async fn deliver(
        &self,
        route: &Route,
        pulled: &Pulled,
        config: &ProxyConfig,
        identity: Option<&Identity>,
    ) -> Result<Delivery, Refusal> {
        let Some(who) = identity else {
            return Ok(Delivery::Nothing);
        };
        let spec = &route.identity;
        match spec.mode {
            IdentityMode::Headers => {
                if spec.headers.is_empty() {
                    return Ok(Delivery::Nothing);
                }
                let mut claims = who.claims.clone();
                claims
                    .insert("mechanism".into(), json!(who.mechanism.as_str()));
                let want = identity::missing(spec, &claims);
                if !want.is_empty() {
                    let evidence = self.evidence(who, route).await?;
                    let said = self
                        .auth
                        .identity(
                            route,
                            (evidence.0, &evidence.1),
                            Some(&want),
                            pulled,
                        )
                        .await?;
                    let Some(given) =
                        said.get("claims").and_then(Value::as_object)
                    else {
                        return Err(Refusal::new(
                            502,
                            "STS-XPEP-0095",
                            "the identity endpoint answered no claims",
                        ));
                    };
                    for name in &want {
                        if let Some(value) = given.get(name) {
                            claims.insert(name.clone(), value.clone());
                        }
                    }
                }
                identity::render(spec, &claims)
                    .map(Delivery::Headers)
                    .map_err(|why| {
                        Refusal::new(
                            502,
                            "STS-XPEP-0096",
                            &format!(
                                "an identity header was not sent: {}",
                                why
                            ),
                        )
                    })
            }
            IdentityMode::Jwt => {
                let key = who.cache_key(&route.application);
                if let Some(token) = self.tokens.get(&key) {
                    return Ok(Delivery::Bearer(token));
                }
                let evidence = self.evidence(who, route).await?;
                let said = self
                    .auth
                    .identity(route, (evidence.0, &evidence.1), None, pulled)
                    .await?;
                let token = said["accessToken"].as_str().unwrap_or("");
                let bearer = said["tokenType"]
                    .as_str()
                    .is_some_and(|t| t.eq_ignore_ascii_case("bearer"));
                let lifetime = said["expiresIn"].as_u64().filter(|s| *s > 0);
                let (false, true, Some(lifetime)) =
                    (token.is_empty(), bearer, lifetime)
                else {
                    return Err(Refusal::new(
                        502,
                        "STS-XPEP-0095",
                        "the identity endpoint answered no usable Bearer \
                         token for the route",
                    ));
                };
                self.tokens.put(
                    &key,
                    token.to_string(),
                    Duration::from_secs(lifetime),
                );
                Ok(Delivery::Bearer(token.to_string()))
            }
            IdentityMode::Saml => {
                let key = who.cache_key(&route.application);
                if let Some(jar) = self.jars.get(&key) {
                    return Ok(Delivery::Jar { key, jar });
                }
                let jar =
                    self.establish_saml(route, pulled, config, who).await?;
                self.jars.put(&key, jar.clone());
                Ok(Delivery::Jar { key, jar })
            }
        }
    }

    /// Mode `saml`: an assertion the service issues for the route's
    /// application, POSTed to its ACS SERVER-SIDE as the HTTP-POST binding
    /// would, and the cookies it sets kept in a jar of our own.
    async fn establish_saml(
        &self,
        route: &Route,
        pulled: &Pulled,
        config: &ProxyConfig,
        who: &Identity,
    ) -> Result<Jar, Refusal> {
        let failed = |why: String| Refusal::new(502, "STS-XPEP-0097", &why);
        let evidence = self.evidence(who, route).await?;
        let said = self
            .auth
            .identity(route, (evidence.0, &evidence.1), None, pulled)
            .await?;
        let response = said["samlResponse"].as_str().unwrap_or("");
        let acs_url = said["acsUrl"].as_str().unwrap_or("").to_string();
        let until = said["notOnOrAfter"]
            .as_str()
            .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
            .map(|t| t.with_timezone(&chrono::Utc));
        let (false, Some(until)) = (response.is_empty(), until) else {
            return Err(Refusal::new(
                502,
                "STS-XPEP-0095",
                "the identity endpoint answered no samlResponse or \
                 notOnOrAfter",
            ));
        };
        let acs = reqwest::Url::parse(&acs_url).ok().filter(|u| {
            (u.scheme() == "http" || u.scheme() == "https")
                && u.host_str().is_some()
        });
        let Some(acs) = acs else {
            return Err(failed(
                "the identity endpoint named an ACS that is not an absolute \
                 http(s) URL"
                    .into(),
            ));
        };
        let client = self.upstream_client(config.upstream_timeout_ms)?;
        let posted = client
            .post(acs)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!("SAMLResponse={}", encode(response)))
            .timeout(Duration::from_millis(config.upstream_timeout_ms))
            .send()
            .await
            .map_err(|e| {
                failed(format!(
                    "the application's ACS could not be reached: {}",
                    e
                ))
            })?;
        if posted.status().as_u16() >= 400 {
            return Err(failed(format!(
                "the application's ACS answered {} to the assertion",
                posted.status().as_u16()
            )));
        }
        let cookies = identity::set_cookies(posted.headers());
        if cookies.is_empty() {
            return Err(failed(
                "the application's ACS set no cookie, so there is no session \
                 to forward with"
                    .into(),
            ));
        }
        tracing::info!(
            "xacml-pep: proxy: an application session was established at its \
             ACS for route {} ({} cookie(s) kept here).",
            route.id,
            cookies.len()
        );
        Ok(Jar {
            cookies,
            not_on_or_after: until,
            acs_url,
        })
    }

    /// The request, to the application: streamed both ways, bounded, with
    /// the route's identity. Answers the response and whether the
    /// application said its session (a jar's) ended.
    #[allow(clippy::too_many_arguments)]
    async fn forward(
        &self,
        route: &Route,
        config: &ProxyConfig,
        pulled: &Pulled,
        parts: &axum::http::request::Parts,
        body: Body,
        path: &str,
        query: Option<&str>,
        transport: &Transport,
        delivery: &Delivery,
    ) -> Result<(Response<Body>, bool), Refusal> {
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
        let strip = strip_list(
            &pulled.realm.service_cookie_prefixes,
            &self.pep.options.now().proxy_strip_cookies,
        );
        let mut headers = forward_headers(
            &parts.headers,
            route.forward_credentials,
            &config.identity_header_names(),
            &strip,
        );
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
        match delivery {
            Delivery::Nothing => {}
            Delivery::Headers(list) => {
                for (name, value) in list {
                    headers.insert(name.clone(), value.clone());
                }
            }
            Delivery::Bearer(token) => {
                // The client's own Authorization goes whatever
                // forwardCredentials says: the token is the identity.
                headers.remove(header::AUTHORIZATION);
                let value = HeaderValue::from_str(&format!("Bearer {}", token))
                    .map_err(|_| {
                        Refusal::new(
                            502,
                            "STS-XPEP-0096",
                            "the access token is not a header value",
                        )
                    })?;
                headers.insert(header::AUTHORIZATION, value);
            }
            Delivery::Jar { jar, .. } => {
                let client: Vec<String> = headers
                    .get_all(header::COOKIE)
                    .iter()
                    .filter_map(|v| v.to_str().ok().map(str::to_string))
                    .collect();
                headers.remove(header::COOKIE);
                let joined = client.join("; ");
                let text = identity::cookie_header(
                    Some(joined.as_str()).filter(|t| !t.is_empty()),
                    jar,
                );
                let value = HeaderValue::from_str(&text).map_err(|_| {
                    Refusal::new(
                        502,
                        "STS-XPEP-0096",
                        "the application's cookies are not a header value",
                    )
                })?;
                headers.insert(header::COOKIE, value);
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
        let mut headers = response_headers(upstream.headers());
        let mut ended = false;
        if let Delivery::Jar { key, jar } = delivery {
            // THE JAR NEVER REACHES THE BROWSER: the application's
            // Set-Cookie for a jar cookie updates the jar and is removed.
            let names = jar.names();
            let set: Vec<(String, String)> = identity::set_cookies(&headers)
                .into_iter()
                .filter(|(n, _)| names.contains(n))
                .collect();
            self.jars.update(key, &set);
            headers = identity::without_set_cookies(&headers, &names);
            let location =
                headers.get(header::LOCATION).and_then(|v| v.to_str().ok());
            ended = identity::session_ended(
                status.as_u16(),
                location,
                &jar.acs_url,
                &pulled.realm.issuer,
            );
            if ended {
                self.jars.forget(key);
            }
        }
        let mut response =
            Response::new(Body::new(reqwest::Body::from(upstream)));
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        Ok((response, ended))
    }
}

pub(crate) fn tower_service(
    proxy: Arc<Proxy>,
    transport: Transport,
) -> TowerToHyperService<axum::routing::Router> {
    let router = axum::Router::new()
        .fallback(move |mut request: Request<Body>| {
            let proxy = proxy.clone();
            request.extensions_mut().insert(transport.clone());
            async move { proxy.handle(request).await }
        })
        .layer(axum::middleware::from_fn(crate::listener_pool::observe));
    TowerToHyperService::new(router)
}

/// The plain listener's accept loop over a socket `main.rs` bound (it
/// records whether the bind succeeded, #1760; the tests bind port 0). A
/// port that will not bind is logged there and the PEP goes on: the proxy
/// is a feature of this container, not its purpose.
pub async fn serve_on(
    proxy: Arc<Proxy>,
    listener: TcpListener,
    runtime: ListenerRuntime,
) {
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    tracing::info!(
        "xacml-pep: the reverse proxy listens on {} (plain HTTP).",
        port
    );
    runtime.start();
    loop {
        let Ok((stream, remote)) = listener.accept().await else {
            continue;
        };
        let proxy = proxy.clone();
        let job = runtime.clone();
        runtime.hand_off(stream, move |stream| async move {
            let transport = Transport {
                https: false,
                peer: None,
                remote: Some(remote),
                crl_only: false,
                verifies_client_certificates: false,
            };
            let cfg = job.http();
            drive(stream, tower_service(proxy, transport), cfg, false, job)
                .await;
        });
    }
}

/// The HTTPS listener: started the first time a usable pair appears.
pub async fn serve_https(
    proxy: Arc<Proxy>,
    https: Arc<HttpsListener>,
    runtime: ListenerRuntime,
) {
    let listener = match TcpListener::bind(("0.0.0.0", https.port())).await {
        Ok(listener) => listener,
        Err(error) => {
            https.mark_bind_failed_for(&error);
            return;
        }
    };
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    https.mark_listening(port);
    runtime.start();
    loop {
        let Ok((stream, remote)) = listener.accept().await else {
            continue;
        };
        let Some((acceptor, client_auth)) = https.current_served() else {
            continue;
        };
        let proxy = proxy.clone();
        let job = runtime.clone();
        runtime.hand_off(stream, move |stream| async move {
            let Some(tls) =
                HttpsListener::accept_tls(stream, &acceptor, &job).await
            else {
                return;
            };
            let alpn_h2 = tls.ssl().selected_alpn_protocol() == Some(b"h2");
            let cfg = job.http();
            // HttpCfg is moved into drive, so the ALPN decision is taken
            // before that move.
            let offer_h2 = cfg.http2 && alpn_h2;
            let transport = Transport {
                https: true,
                peer: peer_of(tls.ssl()),
                remote: Some(remote),
                crl_only: false,
                verifies_client_certificates: client_auth
                    == ClientAuth::Verifying,
            };
            drive(tls, tower_service(proxy, transport), cfg, offer_h2, job)
                .await;
        });
    }
}

/// THE REFUSALS' LOG LINES, AS LOGGED, for the tests: a thread-local
/// subscriber does not see every task's events reliably (the callsite
/// interest is cached across the suite's threads), so the line is recorded
/// beside the macro that writes it.
#[cfg(test)]
pub mod logged {
    use std::sync::Mutex;

    static LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());

    pub fn note(line: &str) {
        let mut held = match LINES.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        held.push(line.to_string());
    }

    /// Every line recorded that holds `needle`.
    pub fn holding(needle: &str) -> Vec<String> {
        let held = match LINES.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        held.iter()
            .filter(|l| l.contains(needle))
            .cloned()
            .collect()
    }
}
