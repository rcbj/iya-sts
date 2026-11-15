// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE REQUEST EVERY FAMILY READS AND THE ANSWER IT WRITES, and the routes
//! (`registerRoutes()` of `acme/acme.ts`, `est/est.ts`, `scep/scep.ts`).
//!
//! [`Req`] is what Express hands a handler — the method, the path with the
//! realm's prefix gone, the query, the headers, the body (the raw parser's
//! bytes for the binary types, the text parser's string for the rest),
//! `baseUrlOf(req)` (with the realm's prefix), the client address, whether
//! it arrived over TLS and the TLS client certificate's chain. [`Reply`] is
//! the status, the headers in the order set, the body and the code marked
//! on it; it becomes an axum response marked with that code, which the
//! HTTP layer records and never sends.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use sts_core::errors::ErrorCode;
use sts_core::settings::Settings;

/// A request as a handler reads it.
#[derive(Debug, Clone, Default)]
pub struct Req {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    /// The text parser's string, for a type the raw parser does not take.
    pub text: Option<String>,
    /// `baseUrlOf(req)`: scheme, host and the realm's prefix.
    pub base: String,
    pub address: String,
    pub over_tls: bool,
    /// The TLS client certificate's chain as sent, DER, leaf first.
    pub peer_chain: Vec<Vec<u8>>,
}

impl Req {
    /// A header's value, `''` when absent.
    // A hot path: every check of every request; no span.
    pub fn header(&self, name: &str) -> String {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    }

    /// `req.query` as Express's parser builds it: the first value of each
    /// name, decoded.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn query_map(&self) -> serde_json::Map<String, serde_json::Value> {
        let mut out = serde_json::Map::new();
        for (k, v) in url::form_urlencoded::parse(self.query.as_bytes()) {
            out.entry(k.into_owned())
                .or_insert_with(|| serde_json::Value::String(v.into_owned()));
        }
        out
    }

    /// The leaf of the TLS client certificate, where one was presented.
    // A hot path: every authentication asks; no span.
    pub fn peer_leaf(&self) -> Option<&[u8]> {
        self.peer_chain.first().map(Vec::as_slice)
    }
}

/// An answer.
#[derive(Debug, Clone, Default)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub code: Option<ErrorCode>,
}

impl Reply {
    /// An answer with a status.
    // A hot path: every answer; no span.
    pub fn new(status: u16) -> Reply {
        Reply {
            status,
            ..Default::default()
        }
    }

    /// `res.set(name, value)`: replaces.
    // A hot path: every header of every answer; no span.
    pub fn set(&mut self, name: &str, value: &str) {
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
        self.headers.push((name.to_string(), value.to_string()));
    }

    /// `res.append(name, value)`.
    // A hot path: every Link of every ACME answer; no span.
    pub fn append(&mut self, name: &str, value: &str) {
        self.headers.push((name.to_string(), value.to_string()));
    }

    /// A header's value as set.
    // A hot path: tests and the flush ask; no span.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .rev()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// `errorCodes.mark(res, code)`.
    // A hot path: every refusal; no span.
    pub fn mark(&mut self, code: ErrorCode) {
        self.code = Some(code);
    }

    /// The axum response, marked with its code.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn into_response(self) -> Response {
        let mut response = Response::new(Body::from(self.body));
        *response.status_mut() = StatusCode::from_u16(self.status)
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let headers = response.headers_mut();
        for (k, v) in &self.headers {
            let (Ok(name), Ok(value)) =
                (HeaderName::try_from(k.as_str()), HeaderValue::from_str(v))
            else {
                continue;
            };
            if k.eq_ignore_ascii_case("link")
                || k.eq_ignore_ascii_case("set-cookie")
            {
                headers.append(name, value);
            } else {
                headers.insert(name, value);
            }
        }
        match self.code {
            Some(code) => sts_http::mark(response, code),
            None => response,
        }
    }
}

/// `baseUrlOf(req)`: `global.publicBaseUrl` where pinned, otherwise the
/// scheme and host the request arrived on (the forwarded ones where
/// `global.trustProxy` believes them), and the ambient realm's prefix.
#[tracing::instrument(level = "trace", skip_all)]
pub fn base_of(
    settings: &Settings,
    headers: &HeaderMap,
    over_tls: bool,
    prefix: &str,
) -> String {
    let header = |n: &str| {
        headers
            .get(n)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
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
    let scheme = trust
        .then(|| header("x-forwarded-proto"))
        .map(first)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            if over_tls {
                "https".into()
            } else {
                "http".into()
            }
        });
    let host = trust
        .then(|| header("x-forwarded-host"))
        .map(first)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            let h = header("host");
            if h.is_empty() {
                "localhost".into()
            } else {
                h
            }
        });
    format!("{}://{}{}", scheme, host, prefix)
}

/// Reads an axum request into a [`Req`].
#[tracing::instrument(level = "trace", skip_all)]
pub async fn read(
    http: &Arc<sts_http::HttpLayer>,
    settings: &Settings,
    request: Request,
) -> Req {
    let over_tls = request
        .extensions()
        .get::<sts_http::cookie_wire::OverTls>()
        .is_some();
    let peer = request
        .extensions()
        .get::<sts_http::client_address::Peer>()
        .copied();
    let peer_chain = request
        .extensions()
        .get::<sts_tls::ConnectionFacts>()
        .and_then(|c| c.tls.as_ref())
        .map(|t| t.peer_chain.clone())
        .unwrap_or_default();
    let parsed = request
        .extensions()
        .get::<sts_http::body::ParsedBody>()
        .cloned();
    let prefix = http.registry().current_prefix();
    let headers = request.headers().clone();
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let query = request.uri().query().unwrap_or("").to_string();
    let (body, text) = match parsed {
        Some(p) => (p.bytes.to_vec(), p.text),
        None => {
            let bytes = axum::body::to_bytes(
                request.into_body(),
                sts_http::body::LIMIT,
            )
            .await
            .map(|b| b.to_vec())
            .unwrap_or_default();
            (bytes, None)
        }
    };
    Req {
        method,
        path,
        query,
        base: base_of(settings, &headers, over_tls, &prefix),
        address: http.client_address_of(&headers, peer.as_ref()),
        headers,
        body,
        text,
        over_tls,
        peer_chain,
    }
}
