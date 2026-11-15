// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The HTTP layer every route sits behind (`common/app.js` and the
//! middleware it installs), and the static surfaces' host.
//!
//! [`HttpLayer::wrap`] puts a router behind Node's middleware, in Node's
//! order (outermost first):
//!
//! 1. **The flush** — what Node does in its `writeHead()` hooks and in
//!    Express's `res.send()`: the weak `ETag`, a 304 for a fresh
//!    conditional GET, no body for a HEAD ([`express::finish`]); then the
//!    CSP re-check, the narrowing of a response that is not a page, the
//!    charset, HSTS and the cookie prefixes ([`cookie_wire`]).
//! 2. **The realm, first of all and with nothing above it.** A path under
//!    `/<segment>/<id>` is served in that realm with the prefix stripped,
//!    and the prefix is put back on a redirect and on every root-relative
//!    link of an HTML page sent as a string. A path naming a realm that
//!    does not exist is not stripped and answers the 404 every unrouted
//!    path answers.
//! 3. **The CDN edge's secret** (`refuseForeignEdge`, #1336), the slot
//!    where the layers other slices port sit between the realm and the
//!    security headers ([`PreRoute`]: the listener map, cell placement,
//!    the cluster barrier), and **the per-address ceiling**
//!    (`common/request_budget.ts`, ASVS 5.0.0 2.4.1).
//! 4. **The security headers**: `X-Content-Type-Options`, the base CSP,
//!    `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy` — set
//!    before the route in Node, so here a route's own value wins.
//! 5. **Chrome's private-network preflight header, the CORS preflight**
//!    (204 here, GNAP's discovery excepted), **the body** (five
//!    megabytes, [`body`]), **CORS on every other answer** ([`cors`]),
//!    **SAML's and WS-Federation's repeated parameters** (product,
//!    `common/protocol_repeats.ts`), **the validation guard** ([`guard`]),
//!    and **the fault boundary** ([`fault`], #355) around the route.
//! 6. **The 404 is Express's** — `Cannot GET /path` — because the endpoint
//!    drift check tells an unrouted path from an endpoint answering 404 by
//!    it. Do not make it prettier.
//!
//! A refusal carries its error code on the response ([`mark`]); it is
//! recorded, never sent. **The call log** ([`call_log`]) writes one audit
//! row per answered request in the request's realm, carrying that code or
//! the generic code of a failed status, once [`HttpLayer::set_audit`] has
//! been given the log.

#![forbid(unsafe_code)]

pub mod assets;
pub mod body;
pub mod branding;
pub mod call_log;
pub mod client_address;
pub mod cookie_wire;
pub mod cors;
pub mod csp;
pub mod error_page;
pub mod express;
pub mod fault;
pub mod files;
pub mod footer;
pub mod guard;
pub mod i18n;
pub mod shell;
pub mod surfaces;

use std::sync::{Arc, Mutex, RwLock};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sts_core::errors::{codes, ErrorCode};
use sts_core::mode::Mode;
use sts_core::realm::{self, RealmRegistry};
use sts_core::settings::Settings;

pub use express::{escape_html, Sent};

/// The path as it arrived, before a realm prefix was stripped: what a 404
/// names.
#[derive(Clone, Debug)]
pub struct OriginalPath(pub String);

/// Marks an answer Express gives before its CORS step runs (a route
/// parameter that does not decode): it carries no `Vary: Origin`.
#[derive(Clone, Copy, Debug)]
pub struct BeforeCors;

/// The realm a request was entered in.
#[derive(Clone, Debug)]
pub struct RequestRealm(pub Arc<sts_core::realm::Realm>);

/// Marks a response with the error code of the refusal it carries.
// A hot path: every refusal; no span.
pub fn mark(mut response: Response, code: ErrorCode) -> Response {
    response.extensions_mut().insert(code);
    response
}

/// The error code a response was marked with.
// A hot path: every response at the flush; no span.
pub fn code_of(response: &Response) -> Option<ErrorCode> {
    response.extensions().get::<ErrorCode>().copied()
}

/// `res.redirect(url)`: a 302 with Express's plain-text body, `Vary:
/// Accept` (Express 4 answers it through `res.format()`).
#[tracing::instrument(level = "debug")]
pub fn redirect(location: &str) -> Response {
    redirect_with(StatusCode::FOUND, location)
}

/// `res.redirect(status, url)`.
#[tracing::instrument(level = "debug")]
pub fn redirect_with(status: StatusCode, location: &str) -> Response {
    let address = encode_url(location);
    let mut response = (
        status,
        format!(
            "{}. Redirecting to {}",
            express::status_message(status.as_u16()),
            address
        ),
    )
        .into_response();
    if let Ok(v) = HeaderValue::from_str(&address) {
        response.headers_mut().insert(header::LOCATION, v);
    }
    express::vary(response.headers_mut(), "Accept");
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

/// An HTML string, sent as `res.send(string)` sends one.
// A hot path: every page; no span.
pub fn html(body: impl Into<String>) -> Response {
    typed_text("text/html", body)
}

/// Plain text, as `res.type('text/plain').send(string)` sends it.
// A hot path: every refusal; no span.
pub fn text(body: impl Into<String>) -> Response {
    typed_text("text/plain", body)
}

/// A string sent with a type, as `res.type(t).send(string)`.
// A hot path: every answer; no span.
pub fn typed_text(content_type: &str, body: impl Into<String>) -> Response {
    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&express::typed(content_type)) {
        headers.insert(header::CONTENT_TYPE, v);
    }
    express::send(StatusCode::OK, headers, body.into(), true)
}

/// `encodeurl`: percent-encodes what is not allowed in a URL, leaving
/// existing `%XX` escapes alone.
// A hot path: every 404; no span.
pub fn encode_url(url: &str) -> String {
    let bytes = url.as_bytes();
    let mut out = String::with_capacity(url.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        let hex = |b: Option<&u8>| b.is_some_and(u8::is_ascii_hexdigit);
        let allowed = matches!(c, 0x21 | 0x23..=0x3B | 0x3D | 0x3F..=0x5B
            | 0x5D | 0x5F | 0x61..=0x7A | 0x7E);
        if c == b'%' && hex(bytes.get(i + 1)) && hex(bytes.get(i + 2)) {
            out.push_str(&url[i..i + 3]);
            i += 3;
            continue;
        }
        if allowed {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{:02X}", c));
        }
        i += 1;
    }
    out
}

/// The 404 every unrouted path answers: Express's own body, naming the path
/// as it arrived.
pub async fn not_found(
    method: Method,
    uri: Uri,
    original: Option<axum::Extension<OriginalPath>>,
) -> Response {
    let path =
        original.map_or_else(|| uri.path().to_string(), |o| o.0 .0.clone());
    let body = express::error_document(&format!(
        "Cannot {} {}",
        method,
        encode_url(&path)
    ));
    let mut response = Response::new(Body::from(body.clone()));
    *response.status_mut() = StatusCode::NOT_FOUND;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
    // finalhandler's own policy, which the flush puts the base back over
    // (Express's 404 replacing the header is why the flush re-checks).
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'"),
    );
    response.extensions_mut().insert(call_log::Unrouted);
    response
}

/// Every root-relative `href`, `action`, `formaction` and `src` of an HTML
/// page, prefixed (`withRealmLinks()`); `//host` is not root-relative.
///
/// A LINK THAT ALREADY CARRIES THE PREFIX IS LEFT ALONE (Node's fix of
/// 2026-11-14, #444 D12), as `realms.href()` leaves a redirect alone: a page
/// that drew `currentPrefix() + '/portal'` came out
/// `/realm/<id>/realm/<id>/portal`, a 404.
#[tracing::instrument(level = "debug", skip_all)]
pub fn with_realm_links(html: &str, prefix: &str) -> String {
    if prefix.is_empty() {
        return html.to_string();
    }
    let own = prefix.get(1..).unwrap_or("");
    let carries_prefix = |rest: &str| {
        rest.strip_prefix(own).is_some_and(|after| {
            matches!(after.chars().next(), Some('/' | '?' | '#' | '"'))
        })
    };
    let Ok(pattern) = regex::Regex::new(r#"\b(href|action|formaction|src)="/"#)
    else {
        return html.to_string();
    };
    let mut out = String::with_capacity(html.len() + 64);
    let mut last = 0;
    for m in pattern.find_iter(html) {
        let rest = &html[m.end()..];
        if rest.starts_with('/') || carries_prefix(rest) {
            continue;
        }
        out.push_str(&html[last..m.end() - 1]);
        out.push_str(prefix);
        out.push('/');
        last = m.end();
    }
    out.push_str(&html[last..]);
    out
}

/// The browser features a page of this service may use (Qualys QID 150248,
/// `PERMISSIONS_POLICY`): WebAuthn, the Digital Credentials API, the
/// clipboard and full screen for this origin, nothing else for anybody.
pub const PERMISSIONS_POLICY: &str = "publickey-credentials-get=(self), \
     publickey-credentials-create=(self), digital-credentials-get=(self), \
     clipboard-write=(self), fullscreen=(self), camera=(), microphone=(), \
     geolocation=(), payment=(), usb=(), serial=(), hid=(), bluetooth=(), \
     midi=(), display-capture=(), accelerometer=(), gyroscope=(), \
     magnetometer=(), browsing-topics=()";

/// What a response carries before anything decided what it is
/// (`EARLY_POLICY`), for a refusal written above the security headers.
pub const EARLY_POLICY: &str = "default-src 'none'; frame-ancestors 'none'; \
     base-uri 'none'; object-src 'none'";

/// The headers `enterRealm()` sets first, for a refusal a layer above the
/// security headers writes (a realm's listener, the CDN edge).
// A hot path: every early refusal; no span.
pub fn early_headers(headers: &mut HeaderMap) {
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(EARLY_POLICY),
    );
}

/// Whether a `Content-Type` is owed `; charset=utf-8` (`CHARSET_TYPES`):
/// a `text/*`, `application/xml` or `*/*+xml` type that names none.
fn charset_owed(content_type: &str) -> bool {
    let mut parts = content_type.split(';');
    let essence = parts.next().unwrap_or("").trim().to_ascii_lowercase();
    if parts.any(|p| p.trim().to_ascii_lowercase().starts_with("charset=")) {
        return false;
    }
    let Some((top, sub)) = essence.split_once('/') else {
        return false;
    };
    let plain = |s: &str| {
        !s.is_empty() && !s.contains(char::is_whitespace) && !s.contains('/')
    };
    if !plain(top) || !plain(sub) {
        return false;
    }
    top == "text"
        || essence == "application/xml"
        || (sub.ends_with("+xml") && sub.len() > 4)
}

/// The writeHead hooks: the CSP re-check, the narrowing of a response that
/// is not a page, and the charset.
fn flush_headers(response: &mut Response) {
    let headers = response.headers_mut();
    let base = csp::base_policy();
    let current = headers
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if !current.contains("frame-ancestors") {
        if let Ok(v) = HeaderValue::from_str(&base) {
            headers.insert(header::CONTENT_SECURITY_POLICY, v);
        }
        headers
            .insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    }
    // NOT A PAGE: read after the line above, so a policy just put back is
    // narrowed too; a route's own policy is left alone.
    let shown = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let holds_base = headers
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|p| p == base);
    if holds_base && csp::not_a_page_type(&shown) {
        if let Ok(v) = HeaderValue::from_str(&csp::not_a_page_policy()) {
            headers.insert(header::CONTENT_SECURITY_POLICY, v);
        }
    }
    if charset_owed(&shown) {
        if let Ok(v) =
            HeaderValue::from_str(&format!("{}; charset=utf-8", shown))
        {
            headers.insert(header::CONTENT_TYPE, v);
        }
    }
}

/// The security headers a route answers with unless it set its own.
fn security_defaults(headers: &mut HeaderMap) {
    let mut default = |name: header::HeaderName, value: HeaderValue| {
        if !headers.contains_key(&name) {
            headers.insert(name, value);
        }
    };
    default(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if let Ok(v) = HeaderValue::from_str(&csp::base_policy()) {
        default(header::CONTENT_SECURITY_POLICY, v);
    }
    default(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    default(
        header::HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(PERMISSIONS_POLICY),
    );
    let policy = headers
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    // A page that narrowed `frame-ancestors` to named origins (the OP
    // iframe) took X-Frame-Options away; every other keeps DENY.
    let framed = policy.contains("frame-ancestors")
        && !csp::frame_ancestors_none(&policy);
    if !framed && !headers.contains_key(header::X_FRAME_OPTIONS) {
        headers
            .insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    }
}

/// The prefix put back on a redirect, its body and an HTML string's links.
async fn put_prefix_back(
    registry: &RealmRegistry,
    mut response: Response,
) -> Response {
    let prefix = registry.current_prefix();
    if prefix.is_empty() {
        return response;
    }
    let old = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let mut redirect_body: Option<(String, String)> = None;
    if let Some(old) = old {
        let new = registry.href(&old);
        if new != old {
            if let Ok(v) = HeaderValue::from_str(&new) {
                response.headers_mut().insert(header::LOCATION, v);
            }
            redirect_body = Some((old, new));
        }
    }
    let sent_text = response.extensions().get::<Sent>().is_some_and(|s| s.text);
    let is_html = content_type.contains("html") && sent_text;
    if !is_html && redirect_body.is_none() {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, usize::MAX).await else {
        return Response::from_parts(parts, Body::empty());
    };
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if let Some((old, new)) = redirect_body {
        let suffix = format!(". Redirecting to {}", old);
        if let Some(word) = text.strip_suffix(&suffix) {
            text = format!("{}. Redirecting to {}", word, new);
        }
    }
    if is_html {
        text = with_realm_links(&text, &prefix);
    }
    parts
        .headers
        .insert(header::CONTENT_LENGTH, HeaderValue::from(text.len()));
    Response::from_parts(parts, Body::from(text))
}

/// A layer another slice ports, run between the realm and the security
/// headers (Node's listener map, cell placement, the resumed chain, the
/// request pool, the cluster barrier, the cell sessions): it may answer
/// the request itself, or let it through.
pub trait PreRoute: Send + Sync {
    /// An answer, or `None` to go on.
    fn answer(&self, request: &Request) -> Option<Response>;
}

/// What a [`Routes`] handler is asked with: the request as the router
/// sees it (the realm's prefix gone).
pub struct Ask<'a> {
    pub method: &'a Method,
    pub path: &'a str,
    pub query: &'a str,
    pub headers: &'a HeaderMap,
}

/// Routes matched as Express matches them — case-insensitively, with an
/// optional trailing slash — consulted, in the order added, before the
/// axum router. The static surfaces' host is one ([`surfaces`]).
pub trait Routes: Send + Sync {
    /// An answer, or `None` for a path these routes do not hold.
    fn answer(&self, ask: &Ask<'_>) -> Option<Response>;
}

/// A list setting, trimmed, without empty entries.
fn setting_list(settings: &Settings, key: &str) -> Vec<String> {
    settings
        .value_of(key)
        .as_list()
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// The per-address ceiling's window (`RequestBudget`): one map per
/// minute, capped, so nothing runs in the background.
struct Budget {
    window_start: u128,
    counts: std::collections::HashMap<String, i64>,
    told: std::collections::HashSet<String>,
}

const BUDGET_WINDOW_MS: u128 = 60_000;
const BUDGET_MAX_ADDRESSES: usize = 200_000;

impl Budget {
    fn allowed(&mut self, address: &str, limit: i64, now: u128) -> bool {
        if now.saturating_sub(self.window_start) >= BUDGET_WINDOW_MS {
            self.window_start = now;
            self.counts.clear();
            self.told.clear();
        }
        match self.counts.get_mut(address) {
            None => {
                if self.counts.len() < BUDGET_MAX_ADDRESSES {
                    self.counts.insert(address.to_string(), 1);
                }
                true
            }
            Some(seen) => {
                let before = *seen;
                *seen += 1;
                before < limit
            }
        }
    }
}

/// The HTTP layer: the realm registry, the settings and mode it reads,
/// and the slots later phases fill.
pub struct HttpLayer {
    registry: Arc<RealmRegistry>,
    settings: Option<Arc<Settings>>,
    mode: Option<Arc<Mode>>,
    applications: RwLock<Arc<dyn cors::CorsApplications>>,
    pre_route: RwLock<Vec<Arc<dyn PreRoute>>>,
    routes: RwLock<Vec<Arc<dyn Routes>>>,
    budget: Mutex<Budget>,
    /// The audit log the call log writes to (`call_log.rs`); none is no
    /// row, as before the audit slice.
    audit: RwLock<Option<Arc<sts_audit::AuditLog>>>,
    actors: RwLock<Option<Arc<dyn call_log::ActorResolver>>>,
}

impl HttpLayer {
    /// The layer over the service's settings and mode.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(
        registry: Arc<RealmRegistry>,
        settings: Arc<Settings>,
        mode: Arc<Mode>,
    ) -> Arc<HttpLayer> {
        Arc::new(HttpLayer::build(registry, Some(settings), Some(mode)))
    }

    /// The layer with no settings: the realm, the headers and the 404, as
    /// `layered()` gave before the rest was ported.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn minimal(registry: Arc<RealmRegistry>) -> Arc<HttpLayer> {
        Arc::new(HttpLayer::build(registry, None, None))
    }

    fn build(
        registry: Arc<RealmRegistry>,
        settings: Option<Arc<Settings>>,
        mode: Option<Arc<Mode>>,
    ) -> HttpLayer {
        HttpLayer {
            registry,
            settings,
            mode,
            applications: RwLock::new(Arc::new(cors::NoApplications)),
            pre_route: RwLock::new(Vec::new()),
            routes: RwLock::new(Vec::new()),
            budget: Mutex::new(Budget {
                window_start: 0,
                counts: std::collections::HashMap::new(),
                told: std::collections::HashSet::new(),
            }),
            audit: RwLock::new(None),
            actors: RwLock::new(None),
        }
    }

    /// Fills the audit log every answered request is recorded in.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn set_audit(&self, log: Arc<sts_audit::AuditLog>) {
        if let Ok(mut slot) = self.audit.write() {
            *slot = Some(log);
        }
    }

    /// Fills the actor resolver (`setActorResolver()`).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn set_actor_resolver(&self, r: Arc<dyn call_log::ActorResolver>) {
        if let Ok(mut slot) = self.actors.write() {
            *slot = Some(r);
        }
    }

    /// The audit log the layer writes to, where it was given one.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn audit_log(&self) -> Option<Arc<sts_audit::AuditLog>> {
        self.audit.read().ok().and_then(|a| a.clone())
    }

    /// Fills the applications' half of the CORS decision.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn set_cors_applications(&self, apps: Arc<dyn cors::CorsApplications>) {
        if let Ok(mut slot) = self.applications.write() {
            *slot = apps;
        }
    }

    /// Adds a layer between the realm and the security headers.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn add_pre_route(&self, layer: Arc<dyn PreRoute>) {
        if let Ok(mut list) = self.pre_route.write() {
            list.push(layer);
        }
    }

    /// Adds Express-matched routes, ahead of the axum router.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn add_routes(&self, routes: Arc<dyn Routes>) {
        if let Ok(mut list) = self.routes.write() {
            list.push(routes);
        }
    }

    /// The realm registry.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn registry(&self) -> &Arc<RealmRegistry> {
        &self.registry
    }

    fn bool_of(&self, key: &str) -> bool {
        self.settings
            .as_ref()
            .is_some_and(|s| s.value_of(key).as_bool())
    }

    fn address_rules(&self) -> client_address::AddressRules {
        let Some(settings) = &self.settings else {
            return client_address::AddressRules::default();
        };
        client_address::AddressRules {
            trust_proxy: settings.value_of("global.trustProxy").as_bool(),
            trusted_proxies: setting_list(settings, "global.trustedProxies"),
            requires_ranges: self
                .mode
                .as_ref()
                .is_some_and(|m| m.requires_trusted_proxy_ranges()),
            edge_proxies: setting_list(settings, "global.edgeProxies"),
            edge_secret: settings
                .value_of("global.edgeSecret")
                .as_str()
                .to_string(),
        }
    }

    fn cors_context(
        &self,
        peer: Option<&client_address::Peer>,
    ) -> cors::CorsContext {
        let applications = self
            .applications
            .read()
            .map(|a| a.clone())
            .unwrap_or_else(|_| Arc::new(cors::NoApplications));
        let Some(settings) = &self.settings else {
            return cors::CorsContext {
                pinned_base: String::new(),
                forwarded_believed: false,
                https: false,
                debugger: None,
                listener_origins: None,
                configured: Vec::new(),
                cookie_domain: false,
                authorization_endpoint_withheld: false,
                applications,
            };
        };
        let embeds = self
            .mode
            .as_ref()
            .is_some_and(|m| m.embeds_protocol_debugger());
        cors::CorsContext {
            pinned_base: settings
                .value_of("global.publicBaseUrl")
                .as_str()
                .trim()
                .to_string(),
            forwarded_believed: self.address_rules().forwarded_believed(peer),
            https: settings.value_of("global.https").as_bool(),
            debugger: embeds.then(|| {
                (
                    settings.value_of("debugger.port").as_int(),
                    settings
                        .value_of("debugger.publicBaseUrl")
                        .as_str()
                        .to_string(),
                )
            }),
            listener_origins: None,
            configured: setting_list(settings, "global.corsOrigins"),
            cookie_domain: !settings
                .value_of("authn.cookieDomain")
                .as_str()
                .is_empty(),
            authorization_endpoint_withheld: settings
                .value_of("oauth2.rfc9700")
                .as_bool()
                || settings.value_of("oauth2.oauth21").as_bool(),
            applications,
        }
    }

    /// `cors.ownOrigins(req)`: the origins this service calls its own for
    /// a request — what `/authn-api` holds an act's `Origin` to.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn own_origins(
        &self,
        headers: &HeaderMap,
        peer: Option<&client_address::Peer>,
        over_tls: bool,
    ) -> Vec<String> {
        let request = cors::CorsRequest {
            method: String::new(),
            path: String::new(),
            query: String::new(),
            headers: headers.clone(),
            scheme: if over_tls { "https" } else { "http" }.to_string(),
            body: String::new(),
        };
        cors::own_origins(&request, &self.cors_context(peer))
    }

    /// `clientAddress.of(req)`: the address a request came from, as the
    /// rate limits and the audit log name it.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn client_address_of(
        &self,
        headers: &HeaderMap,
        peer: Option<&client_address::Peer>,
    ) -> String {
        self.address_rules().client_address(peer, headers)
    }

    fn wire_rules(&self, over_tls: bool) -> cookie_wire::WireRules {
        let Some(mode) = &self.mode else {
            return cookie_wire::WireRules {
                over_tls,
                ..Default::default()
            };
        };
        cookie_wire::WireRules {
            over_tls,
            prefixes: mode.prefixes_cookies(),
            hsts: !mode.omits_strict_transport_security(),
            include_sub_domains: self.bool_of("security.hstsIncludeSubDomains"),
            shared_domain: self.settings.as_ref().is_some_and(|s| {
                !s.value_of("authn.cookieDomain").as_str().is_empty()
            }),
        }
    }

    /// Puts `routes` behind the layer. The routes are wrapped FROM
    /// OUTSIDE: a layer on a router runs after it routed, and the realm
    /// prefix has to be gone before routing.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn wrap(self: &Arc<Self>, routes: axum::Router) -> axum::Router {
        axum::Router::new()
            .fallback_service(routes.fallback(not_found))
            .layer(axum::middleware::from_fn_with_state(self.clone(), serve))
    }

    /// The per-address ceiling: the 429 for an address over it.
    fn over_budget(&self, request: &Request) -> Option<Response> {
        let limit = self.settings.as_ref().map_or(0, |s| {
            s.value_of("security.requestsPerAddressPerMinute").as_int()
        });
        let url = request
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let exempt = url == "/healthcheck" || url.starts_with("/healthcheck?");
        if limit <= 0 || exempt {
            return None;
        }
        let peer = request.extensions().get::<client_address::Peer>();
        let address =
            self.address_rules().client_address(peer, request.headers());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let Ok(mut budget) = self.budget.lock() else {
            return None;
        };
        if budget.allowed(&address, limit, now) {
            return None;
        }
        if !budget.told.contains(&address) && budget.told.len() <= 1000 {
            budget.told.insert(address.clone());
            tracing::warn!(
                "{}request ceiling: {} is over its requests per minute.",
                sts_core::log::tag(codes::STS_CORE_0172),
                address
            );
        }
        let mut response = text("Too many requests from this address.\n");
        *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        Some(mark(response, codes::STS_CORE_0172))
    }
}

/// `protocolRepeats()`: in product, SAML's and WS-Federation's parameters
/// may be given once (ASVS 5.0.0 15.3.7).
fn repeated_parameter(path: &str, query: &str, body: Option<&str>) -> bool {
    let family = ["/saml2", "/saml11", "/wsfed"]
        .iter()
        .any(|p| path == *p || path.starts_with(&format!("{}/", p)));
    if !family {
        return false;
    }
    let names = |text: &str| -> Vec<String> {
        text.split('&')
            .filter(|p| !p.is_empty())
            .map(|p| cors::form_decode(p.split('=').next().unwrap_or("")))
            .collect()
    };
    let q = names(query);
    let b = body.map(names).unwrap_or_default();
    let repeated = |list: &[String], n: &String| {
        list.iter().filter(|x| *x == n).count() > 1
    };
    q.iter().any(|n| repeated(&q, n) || b.contains(n))
        || b.iter().any(|n| repeated(&b, n))
}

/// The whole of the middleware, in Node's order, inside the request's
/// call-log state (`call_log.rs`); the row is written once the answer is
/// final.
async fn serve(
    State(layer): State<Arc<HttpLayer>>,
    request: Request,
    next: Next,
) -> Response {
    let log = layer.audit_log();
    let Some(log) = log else {
        return serve_inner(layer, request, next).await;
    };
    let started = std::time::Instant::now();
    let method = request.method().to_string();
    let original_url = request
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let query = call_log::query_map(request.uri().query().unwrap_or(""));
    let peer = request.extensions().get::<client_address::Peer>().copied();
    let address = layer.client_address_of(request.headers(), peer.as_ref());
    let (actor, session) = layer
        .actors
        .read()
        .ok()
        .and_then(|a| a.clone())
        .map(|r| r.actor_of(request.headers()))
        .unwrap_or_default();
    let realm = layer
        .registry
        .match_path(request.uri().path())
        .map(|found| found.realm.clone());
    let state = call_log::CallState::new(Some(log.clone()));
    let response = call_log::CALL
        .scope(
            state.clone(),
            sts_audit::AuditLog::scope_source(
                address.clone(),
                serve_inner(layer, request, next),
            ),
        )
        .await;
    let (content_type, body) = state
        .body
        .lock()
        .ok()
        .and_then(|b| b.clone())
        .map_or((String::new(), None), |(t, b)| (t, Some(b)));
    let exchange = sts_audit::HttpExchange {
        method,
        original_url,
        query,
        body,
        content_type,
        status: response.status().as_u16(),
        marked: code_of(&response).map(|c| c.as_str().to_string()),
        route: String::new(),
        matched: response.extensions().get::<call_log::Unrouted>().is_none(),
        duration_ms: started.elapsed().as_millis() as f64,
        address,
        actor,
        session,
        api_caller: state.caller.lock().ok().and_then(|c| c.clone()),
        quiet_when_ok: false,
        incident: Some(state.take_incident()).filter(|n| *n > 0),
    };
    match realm {
        Some(r) => realm::run_sync(r, || log.record_http(&exchange)),
        None => log.record_http(&exchange),
    };
    response
}

/// The middleware itself.
async fn serve_inner(
    layer: Arc<HttpLayer>,
    mut request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let request_headers = request.headers().clone();
    let over_tls = request.extensions().get::<cookie_wire::OverTls>().is_some();
    let rules = layer.wire_rules(over_tls);
    cookie_wire::on_request(request.headers_mut(), rules);
    let path = request.uri().path().to_string();
    request.extensions_mut().insert(OriginalPath(path.clone()));
    let found = layer.registry.match_path(&path);
    let response = match found {
        None => inner(layer.clone(), request, next).await,
        Some(found) => {
            let query = request
                .uri()
                .query()
                .map(|q| format!("?{}", q))
                .unwrap_or_default();
            let rest = if found.rest.is_empty() {
                "/".to_string()
            } else {
                found.rest.clone()
            };
            if let Ok(uri) = format!("{}{}", rest, query).parse::<Uri>() {
                *request.uri_mut() = uri;
            }
            request
                .extensions_mut()
                .insert(RequestRealm(found.realm.clone()));
            let realm = found.realm.clone();
            let registry = layer.registry.clone();
            let layer = layer.clone();
            realm::run(realm, async move {
                let response = inner(layer, request, next).await;
                put_prefix_back(&registry, response).await
            })
            .await
        }
    };
    let mut response =
        express::finish(&method, &request_headers, response).await;
    flush_headers(&mut response);
    cookie_wire::on_response(response.headers_mut(), rules);
    if let Some(code) = code_of(&response) {
        tracing::debug!("{}http: refused.", sts_core::log::tag(code));
    }
    response
}

/// Everything below the realm.
async fn inner(
    layer: Arc<HttpLayer>,
    mut request: Request,
    next: Next,
) -> Response {
    let peer = request.extensions().get::<client_address::Peer>().copied();
    if layer
        .address_rules()
        .edge_refused(peer.as_ref(), request.headers_mut())
    {
        let mut response = text("Forbidden\n");
        *response.status_mut() = StatusCode::FORBIDDEN;
        early_headers(response.headers_mut());
        let headers = response.headers_mut();
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        );
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
            ),
        );
        return mark(response, codes::STS_CORE_0165);
    }
    let pre: Vec<Arc<dyn PreRoute>> = layer
        .pre_route
        .read()
        .map(|l| l.clone())
        .unwrap_or_default();
    for one in pre {
        if let Some(answer) = one.answer(&request) {
            return answer;
        }
    }
    if let Some(mut answer) = layer.over_budget(&request) {
        early_headers(answer.headers_mut());
        return answer;
    }
    let mut response = below_security(layer, request, next).await;
    security_defaults(response.headers_mut());
    response
}

/// Puts `Origin` (and `also`) first in `Vary`, as Node sets them before
/// the route adds its own fields.
fn vary_first(headers: &mut HeaderMap, first: &[&str]) {
    let current = headers
        .get(header::VARY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    headers.remove(header::VARY);
    for one in first {
        express::vary(headers, one);
    }
    for f in current.split(',').map(str::trim).filter(|f| !f.is_empty()) {
        express::vary(headers, f);
    }
}

/// The CORS preflight's answer, or the GNAP route's with its headers.
async fn preflight(
    layer: &HttpLayer,
    request: Request,
    next: Next,
    cors_request: &cors::CorsRequest,
    ctx: &cors::CorsContext,
) -> Response {
    let mut headers = HeaderMap::new();
    let (onward, code) =
        cors::preflight_headers(cors_request, ctx, &mut headers);
    if !onward {
        let mut answered = Response::new(Body::empty());
        *answered.status_mut() = StatusCode::NO_CONTENT;
        *answered.headers_mut() = headers;
        answered
            .headers_mut()
            .insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        return match code {
            Some(code) => mark(answered, code),
            None => answered,
        };
    }
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let mut answered = route(layer, request, next, &method, &path).await;
    let fields: Vec<String> = headers
        .get(header::VARY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    for (name, value) in headers.iter() {
        if name != header::VARY && !answered.headers().contains_key(name) {
            answered.headers_mut().insert(name.clone(), value.clone());
        }
    }
    let first: Vec<&str> = fields.iter().map(String::as_str).collect();
    vary_first(answered.headers_mut(), &first);
    answered
}

/// From the private-network header to the route.
async fn below_security(
    layer: Arc<HttpLayer>,
    request: Request,
    next: Next,
) -> Response {
    let private_network = request
        .headers()
        .contains_key("access-control-request-private-network");
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let query = request.uri().query().unwrap_or("").to_string();
    let peer = request.extensions().get::<client_address::Peer>().copied();
    let ctx = layer.cors_context(peer.as_ref());
    let over_tls = request.extensions().get::<cookie_wire::OverTls>().is_some();
    let mut cors_request = cors::CorsRequest {
        method: method.to_string(),
        path: path.clone(),
        query: query.clone(),
        headers: request.headers().clone(),
        scheme: if over_tls { "https" } else { "http" }.to_string(),
        body: String::new(),
    };
    let mut response = if method == Method::OPTIONS {
        preflight(&layer, request, next, &cors_request, &ctx).await
    } else {
        match body::parse(request, &path).await {
            Err(refused) => body::refusal(&refused.0, &method, &path),
            Ok(request) => {
                cors_request.body = request
                    .extensions()
                    .get::<body::ParsedBody>()
                    .and_then(|p| p.text.clone())
                    .unwrap_or_default();
                if !cors_request.body.is_empty() {
                    let content_type = request
                        .headers()
                        .get(header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    call_log::keep_body(content_type, &cors_request.body);
                }
                let refuses_repeats = layer
                    .mode
                    .as_ref()
                    .is_some_and(|m| m.refuses_repeated_token_parameters());
                let posted = (method == Method::POST)
                    .then_some(cors_request.body.as_str());
                let mut answered = if refuses_repeats
                    && repeated_parameter(&path, &query, posted)
                {
                    let mut r = text("A parameter may be given only once.\n");
                    *r.status_mut() = StatusCode::BAD_REQUEST;
                    mark(r, codes::STS_CORE_0173)
                } else if let Some(refused) =
                    guard::refusal(method.as_str(), &path, &query)
                {
                    refused
                } else {
                    route(&layer, request, next, &method, &path).await
                };
                if answered.extensions().get::<BeforeCors>().is_none() {
                    vary_first(answered.headers_mut(), &["Origin"]);
                    cors::response_headers(&cors_request, &ctx, &mut answered);
                }
                answered
            }
        }
    };
    if private_network {
        response.headers_mut().insert(
            "access-control-allow-private-network",
            HeaderValue::from_static("true"),
        );
    }
    response
}

/// The route, inside the fault boundary: the Express-matched routes
/// first, then the axum router.
async fn route(
    layer: &HttpLayer,
    request: Request,
    next: Next,
    method: &Method,
    path: &str,
) -> Response {
    let routes: Vec<Arc<dyn Routes>> =
        layer.routes.read().map(|l| l.clone()).unwrap_or_default();
    let work = async move {
        let query = request.uri().query().unwrap_or("").to_string();
        let ask = Ask {
            method: request.method(),
            path: request.uri().path(),
            query: &query,
            headers: request.headers(),
        };
        for one in &routes {
            if let Some(answer) = one.answer(&ask) {
                return answer;
            }
        }
        next.run(request).await
    };
    fault::contain(method.as_str(), path, work).await
}

/// Wraps a router in the minimal layer: the realm, the security headers,
/// the 404. [`HttpLayer::wrap`] is the whole of it.
#[tracing::instrument(level = "debug", skip_all)]
pub fn layered(
    router: axum::Router,
    registry: Arc<RealmRegistry>,
) -> axum::Router {
    HttpLayer::minimal(registry).wrap(router)
}

#[cfg(test)]
mod realm_link_tests {
    use super::with_realm_links;

    // Node's `withRealmLinks()` since 2026-11-14 (#444 D12): a root-relative
    // link is prefixed once, and one that already carries the prefix, or
    // is protocol-relative, is left alone.
    #[test]
    fn a_link_is_prefixed_once() {
        let page = "<a href=\"/portal\">p</a><a href=\"/realm/acme/portal\">\
                    q</a><a href=\"/realm/acmex/x\">r</a><img src=\"//h/i\">\
                    <form action=\"/realm/acme?x=1\"></form>";
        assert_eq!(
            with_realm_links(page, "/realm/acme"),
            "<a href=\"/realm/acme/portal\">p</a><a \
             href=\"/realm/acme/portal\">q</a><a \
             href=\"/realm/acme/realm/acmex/x\">r</a><img src=\"//h/i\">\
             <form action=\"/realm/acme?x=1\"></form>"
        );
        assert_eq!(with_realm_links(page, ""), page);
    }
}
