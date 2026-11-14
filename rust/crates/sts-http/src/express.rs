// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What Express itself does to an answer, which a client of this service
//! sees and the Node runtime never wrote down: `res.send()`'s weak `ETag`
//! and `Content-Length`, the conditional GET it answers 304 (`req.fresh`),
//! a HEAD answered without its body, `res.type()`'s charset, `res.vary()`,
//! and `finalhandler`'s error document — the `Cannot GET /path` the root
//! `CLAUDE.md` says never to make prettier, and the `Payload Too Large` a
//! body parser's refusal ends in.
//!
//! **A BODY IS "SENT" OR IT IS NOT.** Express computes an ETag only in
//! `res.send()` (and `res.json()`, which calls it); a redirect, a 204 and
//! `finalhandler`'s page end through `res.end()` and carry none. So a
//! response built by [`send`] (or the helpers in `lib.rs` that call it)
//! carries a [`Sent`] marker, and [`finish`] — run outermost, where the
//! body is final — computes the ETag and the freshness for exactly those.
//! The marker also says whether the body was a STRING, which is what
//! `common/app.js`'s realm and listener rewrites of `res.send()` read: a
//! Buffer of HTML (a compressed shell) is not rewritten.

use axum::body::{Body, Bytes};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::Response;

/// A body sent through `res.send()`: an ETag is owed, and `text` says
/// whether it was a string (rewritable) rather than a Buffer.
#[derive(Clone, Copy, Debug)]
pub struct Sent {
    pub text: bool,
}

/// The message `statuses` (finalhandler's) gives a status code.
pub fn status_message(code: u16) -> &'static str {
    match code {
        100 => "Continue",
        101 => "Switching Protocols",
        102 => "Processing",
        103 => "Early Hints",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        208 => "Already Reported",
        226 => "IM Used",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Payload Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Range Not Satisfiable",
        417 => "Expectation Failed",
        418 => "I'm a Teapot",
        421 => "Misdirected Request",
        422 => "Unprocessable Entity",
        423 => "Locked",
        424 => "Failed Dependency",
        425 => "Too Early",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        506 => "Variant Also Negotiates",
        507 => "Insufficient Storage",
        508 => "Loop Detected",
        509 => "Bandwidth Limit Exceeded",
        510 => "Not Extended",
        511 => "Network Authentication Required",
        _ => "",
    }
}

/// `escape-html`, as `finalhandler` and Express escape.
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

/// `finalhandler`'s `createHtmlDocument()`: the message escaped, a newline
/// a `<br>`, a double space ` &nbsp;`.
pub fn error_document(message: &str) -> String {
    let body = escape_html(message)
        .replace("\r\n", "<br>")
        .replace(['\n', '\r'], "<br>")
        .replace("  ", " &nbsp;");
    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta \
         charset=\"utf-8\">\n<title>Error</title>\n</head>\n<body>\n\
         <pre>{}</pre>\n</body>\n</html>\n",
        body
    )
}

/// `finalhandler`'s answer to an error with this status, in production
/// (`NODE_ENV=production`, which the image sets): the status message, and
/// the headers it sets. What an earlier middleware set (`Vary`, a cache
/// policy) stays, as on the Node response, because it is the outer layers
/// that add theirs here; the content headers it removes were never set on
/// this fresh response.
#[tracing::instrument(level = "debug")]
pub fn error_page(status: u16) -> Response {
    let body = error_document(status_message(status));
    let mut response = Response::new(Body::from(body.clone()));
    *response.status_mut() = StatusCode::from_u16(status)
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
    response
}

/// `mime.charsets.lookup()` as Express 4's `res.set('Content-Type')` asks
/// it: UTF-8 for `text/*`, `application/javascript` and
/// `application/json` (and anything under them, `application/json-seq`).
fn charset_of(essence: &str) -> bool {
    let e = essence.to_ascii_lowercase();
    e.starts_with("text/")
        || e.starts_with("application/javascript")
        || e.starts_with("application/json")
}

/// `res.type(t)` / `res.set('Content-Type', t)`: a bare extension looked
/// up (only the few this service names), and `; charset=utf-8` added where
/// `mime` names one and the value carries no charset.
pub fn typed(value: &str) -> String {
    let full = if value.contains('/') {
        value.to_string()
    } else {
        match value.trim_start_matches('.') {
            "html" => "text/html",
            "txt" | "text" => "text/plain",
            "json" => "application/json",
            "js" => "application/javascript",
            "css" => "text/css",
            "xml" => "application/xml",
            "bin" => "application/octet-stream",
            _ => "application/octet-stream",
        }
        .to_string()
    };
    let has_charset = full
        .split(';')
        .skip(1)
        .any(|p| p.trim().to_ascii_lowercase().starts_with("charset"));
    let essence = full.split(';').next().unwrap_or("").trim().to_string();
    if !has_charset && charset_of(&essence) {
        format!("{}; charset=utf-8", full)
    } else {
        full
    }
}

/// `setCharset(type, 'utf-8')`: what `res.send(string)` does to a type
/// already set — the charset parameter replaced, or added.
fn with_utf8(value: &str) -> String {
    let mut parts = value.split(';');
    let essence = parts.next().unwrap_or("").trim().to_string();
    let mut params: Vec<String> = parts
        .map(|p| p.trim().to_string())
        .filter(|p| {
            !p.is_empty() && !p.to_ascii_lowercase().starts_with("charset=")
        })
        .collect();
    params.push("charset=utf-8".to_string());
    format!("{}; {}", essence, params.join("; "))
}

/// `res.send(body)`: the type (HTML for a string with none, a Buffer's
/// `application/octet-stream`), `; charset=utf-8` on a string's type, and
/// the [`Sent`] marker that owes it an ETag at the flush.
pub fn send(
    status: StatusCode,
    mut headers: HeaderMap,
    body: impl Into<Bytes>,
    text: bool,
) -> Response {
    let current = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let content_type = match (current, text) {
        (Some(t), true) => with_utf8(&t),
        (Some(t), false) => t,
        (None, true) => "text/html; charset=utf-8".to_string(),
        (None, false) => "application/octet-stream".to_string(),
    };
    if let Ok(v) = HeaderValue::from_str(&content_type) {
        headers.insert(header::CONTENT_TYPE, v);
    }
    let bytes: Bytes = body.into();
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(bytes.len()));
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response.extensions_mut().insert(Sent { text });
    response
}

/// `res.vary(field)` (the `vary` package): the field appended to `Vary`
/// unless it is there (case-insensitively) or `Vary` is `*`.
pub fn vary(headers: &mut HeaderMap, field: &str) {
    let current = headers
        .get(header::VARY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let mut fields: Vec<String> = current
        .split(',')
        .map(|f| f.trim().to_string())
        .filter(|f| !f.is_empty())
        .collect();
    if fields.iter().any(|f| f == "*") {
        return;
    }
    if fields.iter().any(|f| f.eq_ignore_ascii_case(field)) {
        return;
    }
    fields.push(field.to_string());
    if let Ok(v) = HeaderValue::from_str(&fields.join(", ")) {
        headers.insert(header::VARY, v);
    }
}

/// The `etag` package's weak tag of a body: `W/"<length in hex>-<the
/// first 27 characters of the base64 SHA-1>"`.
pub fn weak_etag(body: &[u8]) -> String {
    if body.is_empty() {
        return "W/\"0-2jmj7l5rSw0yVb/vlWAYkK/YBwk\"".to_string();
    }
    use base64::Engine;
    let digest = sts_crypto::digest::sha1(body);
    let b64 = base64::engine::general_purpose::STANDARD.encode(digest);
    format!("W/\"{:x}-{}\"", body.len(), &b64[..27.min(b64.len())])
}

/// `fresh` 0.5.2: whether a conditional GET's validators still match.
pub fn fresh(request: &HeaderMap, response: &HeaderMap) -> bool {
    let get = |h: &HeaderMap, n: header::HeaderName| {
        h.get(n).and_then(|v| v.to_str().ok()).map(str::to_string)
    };
    let modified_since = get(request, header::IF_MODIFIED_SINCE);
    let none_match = get(request, header::IF_NONE_MATCH);
    if modified_since.is_none() && none_match.is_none() {
        return false;
    }
    if let Some(cc) = get(request, header::CACHE_CONTROL) {
        let no_cache = cc
            .split(',')
            .any(|d| d.trim().eq_ignore_ascii_case("no-cache"));
        if no_cache {
            return false;
        }
    }
    if let Some(none_match) = none_match.filter(|n| n != "*") {
        let Some(etag) = get(response, header::ETAG) else {
            return false;
        };
        let matched = none_match
            .split([' ', ','])
            .filter(|t| !t.is_empty())
            .any(|m| {
                m == etag
                    || format!("W/{}", etag) == m
                    || format!("W/{}", m) == etag
            });
        if !matched {
            return false;
        }
    }
    if modified_since.is_some() {
        // No answer here carries Last-Modified, so `fresh` reads the
        // date as stale.
        if get(response, header::LAST_MODIFIED).is_none() {
            return false;
        }
    }
    true
}

/// What `res.send()` finishes with, once the body is final: the ETag of a
/// sent body, 304 for a fresh conditional GET (its content headers and
/// body gone), and no body for a HEAD.
pub async fn finish(
    method: &Method,
    request: &HeaderMap,
    response: Response,
) -> Response {
    let sent = response.extensions().get::<Sent>().copied();
    let (mut parts, body) = response.into_parts();
    let Some(_sent) = sent else {
        if method == Method::HEAD {
            return Response::from_parts(parts, Body::empty());
        }
        return Response::from_parts(parts, body);
    };
    let Ok(bytes) = axum::body::to_bytes(body, usize::MAX).await else {
        return Response::from_parts(parts, Body::empty());
    };
    if !parts.headers.contains_key(header::ETAG) {
        if let Ok(v) = HeaderValue::from_str(&weak_etag(&bytes)) {
            parts.headers.insert(header::ETAG, v);
        }
    }
    parts
        .headers
        .insert(header::CONTENT_LENGTH, HeaderValue::from(bytes.len()));
    let status = parts.status.as_u16();
    let conditional = (*method == Method::GET || *method == Method::HEAD)
        && ((200..300).contains(&status) || status == 304);
    if conditional && fresh(request, &parts.headers) {
        parts.status = StatusCode::NOT_MODIFIED;
    }
    if parts.status == StatusCode::NO_CONTENT
        || parts.status == StatusCode::NOT_MODIFIED
    {
        parts.headers.remove(header::CONTENT_TYPE);
        parts.headers.remove(header::CONTENT_LENGTH);
        parts.headers.remove(header::TRANSFER_ENCODING);
        return Response::from_parts(parts, Body::empty());
    }
    if *method == Method::HEAD {
        return Response::from_parts(parts, Body::empty());
    }
    Response::from_parts(parts, Body::from(bytes))
}
