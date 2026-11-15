// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What an endpoint of the authorization server answers, before it is an
//! HTTP response: the status, the headers in the order Node sets them, the
//! body, and the error code the answer is recorded under
//! (`errorCodes.mark(res, …)`), which is never sent.
//!
//! The endpoints here build an [`Answer`] rather than an axum response so
//! that a vector can hold one to what Node sent, member by member, and the
//! runtime turns it into a response in one place ([`Answer::into_response`]).
//!
//! `oauthError()` (`oauth2.ts`) and `helpers.oauthError()` are
//! [`Answer::oauth_error`]: `Cache-Control: no-store`, a JSON body of
//! `error` and `error_description`, the description held to RFC 6749's
//! character set by `oauth21.sanitizeDescription()` in every mode
//! ([`sanitize_description`]).
//!
//! The builder methods of [`Answer`] are a hot path, called for every
//! response, and carry no span; `oauth_error` and `sanitize_description`
//! are instrumented.

use serde_json::{Map, Value as Json};
use sts_core::errors::ErrorCode;

/// The body of an answer.
#[derive(Debug, Clone, PartialEq)]
pub enum Body {
    /// Nothing (a redirect).
    Empty,
    /// `application/json`, serialised as `JSON.stringify` does.
    Json(Json),
    /// `text/html`.
    Html(String),
}

/// One endpoint's answer.
#[derive(Debug, Clone, PartialEq)]
pub struct Answer {
    pub status: u16,
    /// Lower-case names, in the order they were set; a later set of the same
    /// name replaces the earlier value in place, as `res.set()` does.
    pub headers: Vec<(String, String)>,
    pub body: Body,
    /// What the answer is recorded under; never sent.
    pub code: Option<ErrorCode>,
}

/// Section 3.2.4 / 4.1.2.1's character set: the replacements for the
/// punctuation this service writes, so a sentence stays readable.
fn replacement(ch: char) -> Option<&'static str> {
    Some(match ch {
        '\u{2014}' | '\u{2013}' => "-",
        '\u{2018}' | '\u{2019}' | '\u{201C}' | '\u{201D}' | '"' => "'",
        '\u{2026}' => "...",
        '\\' => "/",
        '\u{00A0}' => " ",
        _ => return None,
    })
}

/// `oauth21.sanitizeDescription()`: runs of CR, LF and TAB become one
/// space, the common punctuation is replaced readably and anything else
/// outside `%x20-21 / %x23-5B / %x5D-7E` becomes `?` — one `?` per UTF-16
/// unit, as the JavaScript regular expression replaces them.
#[tracing::instrument(level = "debug", skip_all)]
pub fn sanitize_description(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_space_run = false;
    for ch in text.chars() {
        if ch == '\r' || ch == '\n' || ch == '\t' {
            if !in_space_run {
                out.push(' ');
                in_space_run = true;
            }
            continue;
        }
        in_space_run = false;
        let code = ch as u32;
        let allowed = code == 0x20
            || code == 0x21
            || (0x23..=0x5B).contains(&code)
            || (0x5D..=0x7E).contains(&code);
        if allowed {
            out.push(ch);
        } else if let Some(r) = replacement(ch) {
            out.push_str(r);
        } else {
            for _ in 0..ch.len_utf16() {
                out.push('?');
            }
        }
    }
    out
}

impl Answer {
    /// An answer with a status and nothing else yet.
    pub fn new(status: u16, body: Body) -> Answer {
        Answer {
            status,
            headers: Vec::new(),
            body,
            code: None,
        }
    }

    /// `res.set(name, value)`: replaces a header already set, in place.
    pub fn set(&mut self, name: &str, value: &str) -> &mut Answer {
        let lower = name.to_ascii_lowercase();
        if let Some(held) = self.headers.iter_mut().find(|(n, _)| *n == lower) {
            held.1 = value.to_string();
        } else {
            self.headers.push((lower, value.to_string()));
        }
        self
    }

    /// The value of a header, if set.
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(n, _)| *n == lower)
            .map(|(_, v)| v.as_str())
    }

    /// `errorCodes.mark(res, code)`.
    pub fn marked(mut self, code: ErrorCode) -> Answer {
        self.code = Some(code);
        self
    }

    /// `oauthError(res, status, error, description)`: the description is
    /// sanitised; a missing one is left out, as `JSON.stringify` drops an
    /// `undefined` member.
    #[tracing::instrument(level = "debug", skip(description))]
    pub fn oauth_error(
        status: u16,
        error: &str,
        description: Option<&str>,
    ) -> Answer {
        let mut body = Map::new();
        body.insert("error".into(), Json::from(error));
        if let Some(d) = description {
            body.insert(
                "error_description".into(),
                Json::from(sanitize_description(d)),
            );
        }
        let mut out = Answer::new(status, Body::Json(Json::Object(body)));
        out.set("Content-Type", "application/json; charset=utf-8");
        out.set("Cache-Control", "no-store");
        out
    }

    /// The same, recorded under `code`.
    pub fn refusal(
        code: ErrorCode,
        status: u16,
        error: &str,
        description: &str,
    ) -> Answer {
        Answer::oauth_error(status, error, Some(description)).marked(code)
    }

    /// A 200 JSON answer (`res.status(200).type('application/json')`).
    pub fn json(value: Json) -> Answer {
        let mut out = Answer::new(200, Body::Json(value));
        out.set("Content-Type", "application/json; charset=utf-8");
        out
    }

    /// `res.redirect(302, location)`.
    pub fn redirect(location: &str) -> Answer {
        let mut out = Answer::new(302, Body::Empty);
        out.set("Location", location);
        out
    }

    /// The body as JSON, when it is JSON.
    pub fn json_body(&self) -> Option<&Json> {
        match &self.body {
            Body::Json(j) => Some(j),
            _ => None,
        }
    }

    /// The answer as an axum response; the code rides as an extension the
    /// HTTP layer records and never sends ([`sts_http::mark`]'s shape).
    pub fn into_response(self) -> axum::response::Response {
        use axum::http::{HeaderName, HeaderValue, StatusCode};
        // `res.redirect()`: Express's body and `Vary: Accept`.
        if self.status == 302 && self.body == Body::Empty {
            if let Some(location) = self.header("location").map(str::to_string)
            {
                let mut response = sts_http::redirect(&location);
                for (name, value) in &self.headers {
                    if name == "location" {
                        continue;
                    }
                    if let (Ok(n), Ok(v)) = (
                        HeaderName::from_bytes(name.as_bytes()),
                        HeaderValue::from_str(value),
                    ) {
                        response.headers_mut().insert(n, v);
                    }
                }
                return match self.code {
                    Some(code) => sts_http::mark(response, code),
                    None => response,
                };
            }
        }
        let bytes = match &self.body {
            Body::Empty => Vec::new(),
            Body::Json(j) => j.to_string().into_bytes(),
            Body::Html(h) => h.clone().into_bytes(),
        };
        let mut response =
            axum::response::Response::new(axum::body::Body::from(bytes));
        *response.status_mut() = StatusCode::from_u16(self.status)
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        for (name, value) in &self.headers {
            if let (Ok(n), Ok(v)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                response.headers_mut().insert(n, v);
            }
        }
        match self.code {
            Some(code) => sts_http::mark(response, code),
            None => response,
        }
    }
}
