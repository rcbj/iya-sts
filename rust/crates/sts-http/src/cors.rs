// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Which browser pages may read what this service answers — a port of
//! `common/cors.js`, the allowlist on every path (2026-09-13).
//!
//! An origin is allowed when it is this service's own (the pinned base,
//! the request's `Host`, the embedded debugger's listener, the origins
//! `global.corsOrigins` names), else when the application the request
//! NAMES lists it in `appCorsOrigin` (a `client_id` in the query or the
//! body, a client assertion's `sub`, a GNAP instance, a registration path,
//! a Basic user name, an access token's `client_id`), else — when the
//! request names nobody — when any application in the realm lists it.
//! RFC 9700 section 2.6 withholds CORS from the authorization endpoint in
//! RFC 9700 mode. A preflight is answered 204 here (GNAP's grant endpoint
//! continues to its route, RFC 9635 section 9); every other request gets
//! `Vary: Origin` and, where allowed, the two headers — it never REFUSES
//! anything, it decides a header.
//!
//! **WHAT REPLACED WHAT.** The applications are the directory's, which a
//! later phase ports: they arrive through [`CorsApplications`], and an
//! empty slot knows no application — the answer Node gives in a realm
//! where none lists an origin, which is every realm the seed makes. The
//! listener map (#472) is the TLS slice's: [`CorsContext::listener_origins`]
//! carries its origins when it is not trivial. `oauth2_bcp.corsForbidden()`
//! is [`CorsContext::authorization_endpoint_withheld`].

use std::sync::Arc;

use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::Response;
use base64::Engine;
use serde_json::Value as Json;
use sts_core::errors::{codes, ErrorCode};
use sts_core::log::tag;

/// The headers a cross-origin page may read (`EXPOSED_HEADERS`).
pub const EXPOSED_HEADERS: &[&str] = &[
    "WWW-Authenticate",
    "DPoP-Nonce",
    "Location",
    "Link",
    "Replay-Nonce",
    "Retry-After",
];

const CLIENT_ID_ATTRIBUTES: &[&str] = &["oauthClientId"];
const BASIC_ATTRIBUTES: &[&str] = &["oauthClientId", "scimClientId"];
const TOKEN_ATTRIBUTES: &[&str] = &["oauthClientId", "gnapInstanceId"];
const GNAP_INSTANCE_ATTRIBUTES: &[&str] = &["gnapInstanceId"];

const DEFAULT_PREFLIGHT_METHODS: &str = "GET,HEAD,PUT,PATCH,POST,DELETE";
const GNAP_PREFLIGHT_METHODS: &str = "GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS";

/// What `applications.corsOriginsForClient()` answers.
#[derive(Clone, Debug, Default)]
pub struct ClientOrigins {
    pub known: bool,
    pub identifier: String,
    pub origins: Vec<String>,
}

/// The applications' half of the decision, in the ambient realm: the
/// directory's, ported by a later phase.
pub trait CorsApplications: Send + Sync {
    /// The application one of `attributes` names `name` with.
    fn origins_for_client(
        &self,
        name: &str,
        attributes: &[&str],
    ) -> ClientOrigins;
    /// Every origin any application in the realm lists.
    fn origins_of_realm(&self) -> Vec<String>;
}

/// No application at all: what an empty directory answers.
pub struct NoApplications;

impl CorsApplications for NoApplications {
    fn origins_for_client(&self, _: &str, _: &[&str]) -> ClientOrigins {
        ClientOrigins::default()
    }
    fn origins_of_realm(&self) -> Vec<String> {
        Vec::new()
    }
}

/// The facts of the request the decision reads, gathered by the layer.
#[derive(Clone, Debug, Default)]
pub struct CorsRequest {
    pub method: String,
    /// The path the router sees (the realm's prefix gone).
    pub path: String,
    pub query: String,
    pub headers: HeaderMap,
    /// `req.protocol`: `https` on a TLS socket.
    pub scheme: String,
    /// The body as text, once parsed; empty for a preflight.
    pub body: String,
}

/// The settings and slots the decision reads, per request.
pub struct CorsContext {
    /// `global.publicBaseUrl` (or the advertised listener's base).
    pub pinned_base: String,
    /// `global.trustProxy`, with the peer believed
    /// (`clientAddress.forwardedBelieved()`).
    pub forwarded_believed: bool,
    /// `global.https`.
    pub https: bool,
    /// `mode.embedsProtocolDebugger()`, `debugger.port`,
    /// `debugger.publicBaseUrl`.
    pub debugger: Option<(i64, String)>,
    /// `global.port`, and the listener map's own origins where it is not
    /// trivial (`None` when it is).
    pub listener_origins: Option<(i64, Vec<String>)>,
    /// `global.corsOrigins`.
    pub configured: Vec<String>,
    /// `authn.cookieDomain` is set.
    pub cookie_domain: bool,
    /// RFC 9700 mode is on in the ambient realm.
    pub authorization_endpoint_withheld: bool,
    pub applications: Arc<dyn CorsApplications>,
}

/// What [`decide`] answers.
#[derive(Clone, Debug)]
pub struct Decision {
    pub allowed: bool,
    pub origin: String,
    pub code: Option<ErrorCode>,
    pub why: String,
}

/// `validation.readOrigin()`: the serialised origin, or why it is not one.
#[tracing::instrument(level = "debug")]
pub fn read_origin(value: &str) -> Result<String, String> {
    let text = value.trim();
    if text.is_empty() {
        return Err("is empty".to_string());
    }
    if text.chars().count() > 2048 {
        return Err("is longer than 2048 characters".to_string());
    }
    if text.contains('*') {
        return Err("is a wildcard, and CORS here is an allowlist of exact \
                    origins — list each origin a page is served from"
            .to_string());
    }
    if text.eq_ignore_ascii_case("null") {
        return Err("is the opaque origin, which every sandboxed frame, \
                    data: document and local file shares — allowing it \
                    would allow all of them"
            .to_string());
    }
    let shape_refusal = || {
        "is not an origin: it must be scheme://host or scheme://host:port \
         with no path, query or fragment, such as https://app.example.com"
            .to_string()
    };
    let Some((scheme, rest)) = text.split_once("://") else {
        return Err(shape_refusal());
    };
    let scheme_ok = scheme
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'));
    let host = rest.strip_suffix('/').unwrap_or(rest);
    if !scheme_ok
        || host.is_empty()
        || host
            .chars()
            .any(|c| matches!(c, '/' | '?' | '#') || c.is_whitespace())
    {
        return Err(shape_refusal());
    }
    if host.contains('@') {
        return Err(
            "carries a user name, which an origin never does".to_string()
        );
    }
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Ok(format!("{}://{}", scheme, host.to_ascii_lowercase()));
    }
    match url::Url::parse(text) {
        Ok(u) if u.host_str().is_some_and(|h| !h.is_empty()) => {
            Ok(u.origin().ascii_serialization())
        }
        Ok(_) => Err(format!("is an {} origin with no host", scheme)),
        Err(_) => {
            Err("is not an origin: its host or port does not parse".to_string())
        }
    }
}

/// `originOfUrl()`: an http(s) URL's origin, or ''.
fn origin_of_url(url: &str) -> String {
    let text = url.trim();
    if text.is_empty() {
        return String::new();
    }
    match url::Url::parse(text) {
        Ok(u) if u.scheme() == "http" || u.scheme() == "https" => {
            u.origin().ascii_serialization()
        }
        _ => String::new(),
    }
}

/// `hostnameOf()`: the host without its port, a bracketed IPv6 kept.
fn hostname_of(host: &str) -> String {
    let text = host.trim().to_ascii_lowercase();
    if text.starts_with('[') {
        if let Some(end) = text.find(']') {
            let rest = &text[end + 1..];
            if rest.is_empty()
                || (rest.starts_with(':')
                    && rest.len() > 1
                    && rest[1..].bytes().all(|b| b.is_ascii_digit()))
            {
                return text[..=end].to_string();
            }
        }
    }
    match text.rfind(':') {
        Some(at)
            if at + 1 < text.len()
                && text[at + 1..].bytes().all(|b| b.is_ascii_digit()) =>
        {
            text[..at].to_string()
        }
        _ => text,
    }
}

fn header_of(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// `ownOrigins()`: the origins this service calls its own for a request.
#[tracing::instrument(level = "debug", skip_all)]
pub fn own_origins(req: &CorsRequest, ctx: &CorsContext) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |origin: String| {
        if !origin.is_empty() && !out.contains(&origin) {
            out.push(origin);
        }
    };
    add(origin_of_url(ctx.pinned_base.trim_end_matches('/')));
    let host = header_of(&req.headers, "host");
    let (proto, from_host) = if ctx.forwarded_believed {
        let proto = header_of(&req.headers, "x-forwarded-proto");
        let proto = proto.split(',').next().unwrap_or("").trim();
        let proto = if proto.is_empty() {
            req.scheme.clone()
        } else {
            proto.to_ascii_lowercase()
        };
        let fh = header_of(&req.headers, "x-forwarded-host");
        let fh = fh.split(',').next().unwrap_or("").trim().to_string();
        (proto, if fh.is_empty() { host.clone() } else { fh })
    } else {
        (req.scheme.clone(), host.clone())
    };
    add(origin_of_url(&format!("{}://{}", proto, from_host)));
    if !host.is_empty() {
        add(origin_of_url(&format!("{}://{}", req.scheme, host)));
    }
    let mut hostnames = vec![hostname_of(&from_host)];
    if !host.is_empty() && !hostnames.contains(&hostname_of(&host)) {
        hostnames.push(hostname_of(&host));
    }
    hostnames.retain(|h| !h.is_empty());
    let scheme = if ctx.https { "https" } else { "http" };
    if let Some((port, public)) = &ctx.debugger {
        for h in &hostnames {
            add(origin_of_url(&format!("{}://{}:{}", scheme, h, port)));
        }
        add(origin_of_url(public));
    }
    if let Some((port, origins)) = &ctx.listener_origins {
        for o in origins {
            add(o.clone());
        }
        for h in &hostnames {
            add(origin_of_url(&format!("{}://{}:{}", scheme, h, port)));
        }
    }
    for value in &ctx.configured {
        match read_origin(value) {
            Ok(origin) => add(origin),
            Err(problem) => tracing::warn!(
                "{}cors: global.corsOrigins carries \"{}\", which {}. It is \
                 ignored — an origin that does not parse is never widened \
                 into one that does.",
                tag(codes::STS_HTTP_0023),
                value,
                problem
            ),
        }
    }
    out
}

fn unverified_claims(token: &str) -> Option<serde_json::Map<String, Json>> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1].trim_end_matches('='))
        .ok()?;
    match serde_json::from_slice::<Json>(&bytes).ok()? {
        Json::Object(map) => Some(map),
        _ => None,
    }
}

/// `stringsOf()`: the non-empty trimmed strings of a value or a list.
fn strings_of(value: Option<&Json>) -> Vec<String> {
    let list: Vec<&Json> = match value {
        Some(Json::Array(items)) => items.iter().collect(),
        Some(one) => vec![one],
        None => Vec::new(),
    };
    list.into_iter()
        .filter_map(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// `URLSearchParams` decoding: `+` a space, `%XX` a byte, a stray `%` kept.
pub fn form_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len()
                && bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit) =>
            {
                let hex = &text[i + 1..i + 3];
                out.push(u8::from_str_radix(hex, 16).unwrap_or(b'?'));
                i += 2;
            }
            other => out.push(other),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `bodyParameters()`: a JSON object, a form, or nothing.
fn body_parameters(req: &CorsRequest) -> serde_json::Map<String, Json> {
    let content_type = header_of(&req.headers, "content-type");
    if req.body.is_empty() {
        return serde_json::Map::new();
    }
    if content_type.to_ascii_lowercase().contains("json") {
        return match serde_json::from_str::<Json>(&req.body) {
            Ok(Json::Object(map)) => map,
            _ => serde_json::Map::new(),
        };
    }
    if content_type
        .to_ascii_lowercase()
        .starts_with("application/x-www-form-urlencoded")
    {
        let mut out = serde_json::Map::new();
        for pair in req.body.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let key = form_decode(k);
            let entry =
                out.entry(key).or_insert_with(|| Json::Array(Vec::new()));
            if let Json::Array(list) = entry {
                list.push(Json::String(form_decode(v)));
            }
        }
        return out;
    }
    serde_json::Map::new()
}

/// One client a request names: who, by which attributes, where.
#[derive(Clone, Debug)]
pub struct Named {
    pub name: String,
    pub attributes: &'static [&'static str],
    pub where_: &'static str,
    pub optional: bool,
}

/// The query's values of one parameter, as express's parser hands them.
fn query_values(query: &str, wanted: &str) -> Vec<String> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (form_decode(k) == wanted).then(|| form_decode(v))
        })
        .collect()
}

/// `namedClients()`: every client a request names, in Node's order.
#[tracing::instrument(level = "debug", skip_all)]
pub fn named_clients(req: &CorsRequest) -> Vec<Named> {
    let path = req.path.as_str();
    let oauth_path = path.split('/').any(|segment| segment == "oauth2");
    let mut names: Vec<Named> = Vec::new();
    let mut add = |name: String,
                   attributes: &'static [&'static str],
                   where_: &'static str,
                   optional: bool| {
        let already = names.iter().any(|one| {
            one.name == name && std::ptr::eq(one.attributes, attributes)
        });
        if !already {
            names.push(Named {
                name,
                attributes,
                where_,
                optional,
            });
        }
    };
    for name in query_values(&req.query, "client_id")
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        add(
            name,
            CLIENT_ID_ATTRIBUTES,
            "the client_id query parameter",
            false,
        );
    }
    let body = body_parameters(req);
    for name in strings_of(body.get("client_id")) {
        add(
            name,
            CLIENT_ID_ATTRIBUTES,
            "the client_id in the body",
            false,
        );
    }
    for assertion in strings_of(body.get("client_assertion")) {
        if let Some(claims) = unverified_claims(&assertion) {
            for name in strings_of(claims.get("sub")) {
                add(
                    name,
                    CLIENT_ID_ATTRIBUTES,
                    "the client assertion's sub",
                    false,
                );
            }
        }
    }
    if path == "gnap" || path.ends_with("/gnap") {
        for name in strings_of(body.get("client")) {
            add(
                name,
                GNAP_INSTANCE_ATTRIBUTES,
                "the GNAP instance reference",
                false,
            );
        }
    }
    if let Some(at) = path.find("oauth2/register/") {
        let before_ok = at == 0 || path.as_bytes()[at - 1] == b'/';
        let id = &path[at + "oauth2/register/".len()..];
        if before_ok && !id.is_empty() && !id.contains('/') {
            if let Some(decoded) = percent_decode_strict(id) {
                add(
                    decoded,
                    CLIENT_ID_ATTRIBUTES,
                    "the registration path",
                    false,
                );
            }
        }
    }
    let authorization = header_of(&req.headers, "authorization");
    let authorization = authorization.trim();
    let mut words = authorization.splitn(2, char::is_whitespace);
    let scheme = words.next().unwrap_or("").to_ascii_lowercase();
    let credential = words.next().unwrap_or("").trim();
    let single =
        !credential.is_empty() && !credential.contains(char::is_whitespace);
    if scheme == "basic" && single {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(credential.trim_end_matches('='))
            .or_else(|_| {
                base64::engine::general_purpose::STANDARD_NO_PAD
                    .decode(credential.trim_end_matches('='))
            })
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default();
        if let Some(colon) = decoded.find(':').filter(|c| *c > 0) {
            let raw = &decoded[..colon];
            let user = percent_decode_strict(&raw.replace('+', " "))
                .unwrap_or_else(|| raw.to_string());
            if !user.is_empty() {
                add(user, BASIC_ATTRIBUTES, "the Basic user name", !oauth_path);
            }
        }
    }
    if matches!(scheme.as_str(), "bearer" | "dpop" | "gnap") && single {
        if let Some(claims) = unverified_claims(credential) {
            let mut found = strings_of(claims.get("client_id"));
            if found.is_empty() {
                found = strings_of(claims.get("azp"));
            }
            if let Some(name) = found.into_iter().next() {
                add(
                    name,
                    TOKEN_ATTRIBUTES,
                    "the access token's client_id",
                    false,
                );
            }
        }
    }
    names
}

/// `decodeURIComponent()`, refusing a malformed escape.
pub fn percent_decode_strict(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = text.get(i + 1..i + 3).ok_or(()).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// `decide()`: whether a page on the request's `Origin` may read the
/// answer, and why.
#[tracing::instrument(level = "debug", skip_all)]
pub fn decide(
    req: &CorsRequest,
    ctx: &CorsContext,
    preflight: bool,
) -> Decision {
    let header = header_of(&req.headers, "origin").trim().to_string();
    let refused =
        |origin: String, code: Option<ErrorCode>, why: String| Decision {
            allowed: false,
            origin,
            code,
            why,
        };
    if header.is_empty() {
        return refused(String::new(), None, "not cross-origin".into());
    }
    if ctx.authorization_endpoint_withheld && req.path == "/oauth2/authorize" {
        return refused(
            header,
            None,
            "RFC 9700 section 2.6 withholds CORS from the authorization \
             endpoint"
                .into(),
        );
    }
    let either = if preflight {
        codes::STS_HTTP_0019
    } else {
        codes::STS_HTTP_0020
    };
    let origin = match read_origin(&header) {
        Ok(o) => o,
        Err(problem) => {
            let why = format!("the Origin \"{}\" {}", header, problem);
            return refused(header, Some(either), why);
        }
    };
    if own_origins(req, ctx).contains(&origin) {
        return Decision {
            allowed: true,
            origin,
            code: None,
            why: "this service's own origin".into(),
        };
    }
    let names = if preflight {
        Vec::new()
    } else {
        named_clients(req)
    };
    let resolved: Vec<(Named, ClientOrigins)> = names
        .into_iter()
        .map(|one| {
            let found = ctx
                .applications
                .origins_for_client(&one.name, one.attributes);
            (one, found)
        })
        .filter(|(one, found)| found.known || !one.optional)
        .collect();
    if resolved.is_empty() {
        if ctx.applications.origins_of_realm().contains(&origin) {
            return Decision {
                allowed: true,
                origin,
                code: None,
                why: "no client named, and an application in the realm \
                      lists it"
                    .into(),
            };
        }
        let why = format!(
            "no application in the realm lists {} in appCorsOrigin{}",
            origin,
            if preflight {
                ""
            } else {
                ", and the request named no client"
            }
        );
        return refused(origin, Some(either), why);
    }
    if let Some((one, _)) = resolved.iter().find(|(_, f)| !f.known) {
        let why = format!(
            "{} names \"{}\", which no application in the realm answers to",
            one.where_, one.name
        );
        return refused(origin, Some(codes::STS_HTTP_0021), why);
    }
    if let Some((one, found)) =
        resolved.iter().find(|(_, f)| !f.origins.contains(&origin))
    {
        let why = format!(
            "the application \"{}\" ({}) does not list {} in appCorsOrigin",
            found.identifier, one.where_, origin
        );
        return refused(origin, Some(codes::STS_HTTP_0022), why);
    }
    let why = format!(
        "listed by {}",
        resolved
            .iter()
            .map(|(_, f)| f.identifier.clone())
            .collect::<Vec<_>>()
            .join(", ")
    );
    Decision {
        allowed: true,
        origin,
        code: None,
        why,
    }
}

/// `continuesToRoute()`: GNAP's grant endpoint, whose OPTIONS is RFC 9635
/// section 9's discovery request, and not a published API's page.
pub fn continues_to_route(path: &str) -> bool {
    let gnap = path == "gnap" || path.ends_with("/gnap");
    let api_page = path
        .strip_prefix('/')
        .and_then(|rest| rest.split_once('/'))
        .is_some_and(|(first, _)| first.ends_with("-api"));
    gnap && !api_page
}

fn set(headers: &mut HeaderMap, name: &'static str, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        headers.insert(name, v);
    }
}

/// The preflight's answer: the CORS headers where allowed, and whether
/// the request continues to its route (GNAP) rather than being answered
/// 204 here. A refused origin is logged under its code, and the code is
/// returned for the 204's mark.
#[tracing::instrument(level = "debug", skip_all)]
pub fn preflight_headers(
    req: &CorsRequest,
    ctx: &CorsContext,
    headers: &mut HeaderMap,
) -> (bool, Option<ErrorCode>) {
    crate::express::vary(headers, "Origin");
    let decision = decide(req, ctx, true);
    let onward = continues_to_route(&req.path);
    if decision.allowed {
        set(headers, "access-control-allow-origin", &decision.origin);
        set(
            headers,
            "access-control-allow-methods",
            if onward {
                GNAP_PREFLIGHT_METHODS
            } else {
                DEFAULT_PREFLIGHT_METHODS
            },
        );
        crate::express::vary(headers, "Access-Control-Request-Headers");
        let asked = header_of(&req.headers, "access-control-request-headers");
        if !asked.is_empty() {
            set(headers, "access-control-allow-headers", &asked);
        }
        set(
            headers,
            "access-control-expose-headers",
            &EXPOSED_HEADERS.join(","),
        );
        return (onward, None);
    }
    if let Some(code) = decision.code {
        tracing::info!(
            "{}cors: the preflight for {} {} from {} was answered without \
             CORS headers — {}.",
            tag(code),
            req.method,
            req.path,
            decision.origin,
            decision.why
        );
    }
    (onward, decision.code)
}

/// `response()`'s work on an answer that is not a preflight: `Vary:
/// Origin`, and the two headers where the origin is allowed. A navigation
/// is never decided.
#[tracing::instrument(level = "debug", skip_all)]
pub fn response_headers(
    req: &CorsRequest,
    ctx: &CorsContext,
    response: &mut Response,
) {
    let headers = response.headers_mut();
    crate::express::vary(headers, "Origin");
    let origin = header_of(&req.headers, "origin");
    let mode = header_of(&req.headers, "sec-fetch-mode");
    if origin.is_empty() || mode == "navigate" || mode == "nested-navigate" {
        return;
    }
    let decision = decide(req, ctx, false);
    if decision.allowed {
        set(headers, "access-control-allow-origin", &decision.origin);
        set(
            headers,
            "access-control-expose-headers",
            &EXPOSED_HEADERS.join(", "),
        );
    } else if let Some(code) = decision.code {
        tracing::info!(
            "{}cors: {} {} from {} is answered without \
             Access-Control-Allow-Origin — {}.",
            tag(code),
            req.method,
            req.path,
            decision.origin,
            decision.why
        );
    }
}

/// `header::ORIGIN`, for the layer.
pub const ORIGIN: header::HeaderName = header::ORIGIN;
