// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The HTTP layer every route sits behind (`common/app.js`).
//!
//! * **The realm is entered first and nothing is above it.** A path under
//!   `/<segment>/<id>` is served in that realm with the prefix stripped, so
//!   a handler is written once for every realm; the prefix is put back on a
//!   redirect and on every root-relative link of an HTML page. A path
//!   naming a realm that does not exist is not stripped and answers the
//!   404 every unrouted path answers.
//! * **`frame-ancestors` is the one CSP clause a page may not drop** (RFC
//!   9700 section 4.14), and it has no fallback from `default-src`. Every
//!   response carries the base policy; a page relaxes it through
//!   [`csp::content_security_policy`], which re-adds `frame-ancestors` and
//!   `base-uri` whatever it was asked; and the policy is re-checked on the
//!   way out — a header without the clause is REPLACED by the base policy,
//!   so a page that set its own carelessly is not framable. The one framed
//!   page (the OP iframe) narrows the clause through
//!   [`csp::framed_content_security_policy`] instead.
//! * **The 404 body is Express's** — `Cannot GET /path` — because the
//!   endpoint drift check tells an unrouted path from an endpoint answering
//!   404 by it. Do not make it prettier.
//! * **A refusal carries its error code on the response** ([`mark`]); it
//!   is recorded, never sent.

#![forbid(unsafe_code)]

pub mod csp;

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sts_core::errors::ErrorCode;
use sts_core::realm::{self, RealmRegistry};

/// The path as it arrived, before a realm prefix was stripped: what a 404
/// names.
#[derive(Clone, Debug)]
pub struct OriginalPath(pub String);

/// The realm a request was entered in.
#[derive(Clone, Debug)]
pub struct RequestRealm(pub Arc<sts_core::realm::Realm>);

/// Marks a response with the error code of the refusal it carries.
pub fn mark(mut response: Response, code: ErrorCode) -> Response {
    response.extensions_mut().insert(code);
    response
}

/// The error code a response was marked with.
pub fn code_of(response: &Response) -> Option<ErrorCode> {
    response.extensions().get::<ErrorCode>().copied()
}

/// `res.redirect(url)`: a 302 with Express's plain-text body.
pub fn redirect(location: &str) -> Response {
    let mut response = (
        StatusCode::FOUND,
        format!("Found. Redirecting to {}", location),
    )
        .into_response();
    if let Ok(v) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, v);
    }
    set_type(&mut response, "text/plain; charset=utf-8");
    response
}

fn set_type(response: &mut Response, value: &'static str) {
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(value));
}

/// An HTML response, typed as Express types it.
pub fn html(body: impl Into<String>) -> Response {
    let mut response = Body::from(body.into()).into_response();
    set_type(&mut response, "text/html; charset=utf-8");
    response
}

/// A plain-text response, typed as Express types it.
pub fn text(body: impl Into<String>) -> Response {
    let mut response = Body::from(body.into()).into_response();
    set_type(&mut response, "text/plain; charset=utf-8");
    response
}

/// `encodeurl`: percent-encodes what is not allowed in a URL, leaving
/// existing `%XX` escapes alone.
pub fn encode_url(url: &str) -> String {
    let bytes = url.as_bytes();
    let mut out = String::with_capacity(url.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        let hex = |b: Option<&u8>| b.is_some_and(u8::is_ascii_hexdigit);
        let allowed = matches!(c, 0x21 | 0x26..=0x3B | 0x3D | 0x3F..=0x5B | 0x5D | 0x5F | 0x61..=0x7A | 0x7E);
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

/// `escape-html`.
pub fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
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
    let body = format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>Error</title>\n</head>\n\
         <body>\n<pre>Cannot {} {}</pre>\n</body>\n</html>\n",
        method,
        escape_html(&encode_url(&path))
    );
    let mut response = html(body);
    *response.status_mut() = StatusCode::NOT_FOUND;
    response
}

/// Every root-relative `href`, `action`, `formaction` and `src` of an HTML
/// page, prefixed (`withRealmLinks()`); `//host` is not root-relative.
pub fn with_realm_links(html: &str, prefix: &str) -> String {
    if prefix.is_empty() {
        return html.to_string();
    }
    let Ok(pattern) = regex::Regex::new(r#"\b(href|action|formaction|src)="/"#)
    else {
        return html.to_string();
    };
    let mut out = String::with_capacity(html.len() + 64);
    let mut last = 0;
    for m in pattern.find_iter(html) {
        if html[m.end()..].starts_with('/') {
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

/// Enters the realm a request's path names (`enterRealm`).
pub async fn enter_realm(
    State(registry): State<Arc<RealmRegistry>>,
    mut request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();
    request.extensions_mut().insert(OriginalPath(path.clone()));
    let Some(found) = registry.match_path(&path) else {
        return next.run(request).await;
    };
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
    let response = realm::run(realm.clone(), next.run(request)).await;
    realm::run(realm, put_prefix_back(&registry, response)).await
}

/// The prefix put back on a redirect, its body and an HTML page's links.
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
    let is_html = content_type.contains("html");
    if !is_html && redirect_body.is_none() {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, usize::MAX).await else {
        return Response::from_parts(parts, Body::empty());
    };
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if let Some((old, new)) = redirect_body {
        if text == format!("Found. Redirecting to {}", old) {
            text = format!("Found. Redirecting to {}", new);
        }
    }
    if is_html {
        text = with_realm_links(&text, &prefix);
    }
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(text))
}

/// The security headers every response carries, and the CSP re-checked on
/// the way out.
pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    let base = HeaderValue::from_str(&csp::base_policy());
    let own = headers
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    match own {
        Some(policy) if policy.contains("frame-ancestors") => {
            // A page's own policy, kept. It is framable only where it
            // narrowed the clause itself (the OP iframe), which also takes
            // X-Frame-Options away.
            if csp::frame_ancestors_none(&policy)
                && !headers.contains_key(header::X_FRAME_OPTIONS)
            {
                headers.insert(
                    header::X_FRAME_OPTIONS,
                    HeaderValue::from_static("DENY"),
                );
            }
        }
        _ => {
            if let Ok(v) = base {
                headers.insert(header::CONTENT_SECURITY_POLICY, v);
            }
            headers.insert(
                header::X_FRAME_OPTIONS,
                HeaderValue::from_static("DENY"),
            );
        }
    }
    if let Some(code) = code_of(&response) {
        tracing::debug!("{}http: refused.", sts_core::log::tag(code));
    }
    response
}

/// Wraps a router in the layer every route sits behind, in Node's order:
/// the security headers outermost, then the realm.
///
/// The routes are wrapped FROM OUTSIDE: a layer on a router runs after it
/// routed, and the realm prefix has to be gone before routing.
pub fn layered(
    router: axum::Router,
    registry: Arc<RealmRegistry>,
) -> axum::Router {
    axum::Router::new()
        .fallback_service(router.fallback(not_found))
        .layer(axum::middleware::from_fn_with_state(registry, enter_realm))
        .layer(axum::middleware::from_fn(security_headers))
}
