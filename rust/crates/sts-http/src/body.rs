// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The request body, read once and bounded — `common/app.js`'s two
//! body-parser instances and the error middleware below them.
//!
//! * **Binary bodies first** (`bodyParser.raw`): `application/kerberos`
//!   (MS-KKDCP), `application/octet-stream`, `application/ocsp-request`,
//!   `application/pkcs10` (EST) and `application/x-pki-message` (SCEP)
//!   are kept as the bytes the client sent — a DER body decoded as UTF-8
//!   is corrupted, which is how MS-KKDCP never worked until 2026-09-05.
//! * **Everything else as text** (`bodyParser.text` with `type: () =>
//!   true`), decoded in the charset the `Content-Type` names (UTF-8 when
//!   it names none), with the bytes kept beside the string for GNAP's
//!   `Content-Digest` (`req.rawBody`).
//! * **Five megabytes, after inflation**, and a `Content-Encoding` of
//!   gzip, deflate or br inflated first. A body over the limit is a 413, a
//!   charset or coding nobody reads a 415, a body that does not inflate or
//!   whose length disagrees a 400 — each `finalhandler`'s page, each
//!   marked with its code (`STS-HTTP-0004`, `-0012`, `-0013`, `-0014`) and
//!   logged, since that refusal reaches no route.
//! * **The two dataset uploads are exempt** (#215): a POST to
//!   `/admin/risk/upload` or `/admin-api/risk/upload` (case-insensitive,
//!   an optional trailing slash, the realm's prefix gone) keeps its body in
//!   the stream for the handler, which writes it to disk.
//!
//! A request with no body (no `Content-Length`, no `Transfer-Encoding`) is
//! not read at all, as `type-is`'s `hasBody()` decides.

use std::io::Read;

use axum::body::{Body, Bytes};
use axum::extract::Request;
use axum::http::{header, HeaderMap, Method};
use axum::response::Response;
use sts_core::errors::{codes, ErrorCode};
use sts_core::log::tag;

/// The limit both parsers apply: `'5mb'`.
pub const LIMIT: usize = 5 * 1024 * 1024;

/// The media types the raw parser takes.
const RAW_TYPES: &[&str] = &[
    "application/kerberos",
    "application/octet-stream",
    "application/ocsp-request",
    "application/pkcs10",
    "application/x-pki-message",
];

/// A body as the parsers left it: `req.body` and `req.rawBody`.
#[derive(Clone, Debug)]
pub struct ParsedBody {
    /// The bytes as received, inflated.
    pub bytes: Bytes,
    /// The body as text, for every type but the raw ones.
    pub text: Option<String>,
}

/// `isStreamedUpload()`: one of the two dataset uploads.
// A hot path — every request asks it — so no span.
pub fn is_streamed_upload(method: &Method, path: &str) -> bool {
    if method != Method::POST {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    let lower = lower.strip_suffix('/').unwrap_or(&lower);
    lower == "/admin/risk/upload" || lower == "/admin-api/risk/upload"
}

/// `type-is`'s `hasBody()`.
fn has_body(headers: &HeaderMap) -> bool {
    headers.contains_key(header::TRANSFER_ENCODING)
        || headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| !v.trim().is_empty())
}

fn essence_of(headers: &HeaderMap) -> String {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

/// `content-type`'s charset parameter, lower-cased.
fn charset_of(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::CONTENT_TYPE)?.to_str().ok()?;
    value.split(';').skip(1).find_map(|p| {
        let (k, v) = p.split_once('=')?;
        k.trim()
            .eq_ignore_ascii_case("charset")
            .then(|| v.trim().trim_matches('"').to_ascii_lowercase())
    })
}

/// Why a body was refused: the status, the code, the `err.type`.
#[derive(Clone, Debug)]
pub struct Refused {
    pub status: u16,
    pub code: ErrorCode,
    pub kind: &'static str,
}

impl Refused {
    fn new(status: u16, kind: &'static str) -> Refused {
        let code = match kind {
            "entity.too.large" => codes::STS_HTTP_0004,
            "charset.unsupported" | "encoding.unsupported" => {
                codes::STS_HTTP_0012
            }
            "request.aborted" | "request.size.invalid" => codes::STS_HTTP_0013,
            _ => codes::STS_HTTP_0014,
        };
        Refused { status, code, kind }
    }
}

/// A charset `iconv-lite` reads, as the decoder for it: its own names
/// (`utf8`, `binary`, `ucs2`, …) and every WHATWG label.
fn decoder_for(charset: &str) -> Option<&'static encoding_rs::Encoding> {
    let name = charset.trim().to_ascii_lowercase();
    match name.as_str() {
        "utf8" | "utf-8" | "unicode-1-1-utf-8" | "cesu8" => {
            Some(encoding_rs::UTF_8)
        }
        "binary" | "latin1" | "iso88591" | "iso-8859-1" | "l1" => {
            Some(encoding_rs::WINDOWS_1252)
        }
        "ascii" | "us-ascii" => Some(encoding_rs::WINDOWS_1252),
        "ucs2" | "ucs-2" | "utf16le" | "utf-16le" | "utf16" | "utf-16" => {
            Some(encoding_rs::UTF_16LE)
        }
        "utf16be" | "utf-16be" => Some(encoding_rs::UTF_16BE),
        other => encoding_rs::Encoding::for_label(other.as_bytes()),
    }
}

/// The body inflated per its `Content-Encoding`, bounded by [`LIMIT`].
fn inflate(headers: &HeaderMap, bytes: Bytes) -> Result<Bytes, Refused> {
    let coding = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("identity")
        .trim()
        .to_ascii_lowercase();
    let mut out = Vec::new();
    let read = |reader: &mut dyn Read, out: &mut Vec<u8>| {
        let mut limited = reader.take(LIMIT as u64 + 1);
        match limited.read_to_end(out) {
            Ok(_) if out.len() > LIMIT => {
                Err(Refused::new(413, "entity.too.large"))
            }
            Ok(_) => Ok(()),
            Err(_) => Err(Refused::new(400, "encoding.failed")),
        }
    };
    match coding.as_str() {
        "identity" => return Ok(bytes),
        "gzip" => {
            read(&mut flate2::read::GzDecoder::new(&bytes[..]), &mut out)?
        }
        "deflate" => {
            read(&mut flate2::read::ZlibDecoder::new(&bytes[..]), &mut out)?
        }
        "br" => {
            read(&mut brotli::Decompressor::new(&bytes[..], 4096), &mut out)?
        }
        _ => return Err(Refused::new(415, "encoding.unsupported")),
    }
    Ok(Bytes::from(out))
}

/// Reads and parses a request's body, or says why it was refused. The
/// request comes back with its body in place, for a handler that reads
/// the stream, and the [`ParsedBody`] in its extensions.
#[tracing::instrument(level = "debug", skip_all)]
pub async fn parse(
    request: Request,
    path: &str,
) -> Result<Request, Box<(Refused, Request)>> {
    if is_streamed_upload(request.method(), path)
        || !has_body(request.headers())
    {
        return Ok(request);
    }
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<usize>().ok());
    let identity = request
        .headers()
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_none_or(|v| v.trim().eq_ignore_ascii_case("identity"));
    let (parts, body) = request.into_parts();
    let rebuild = |parts: axum::http::request::Parts| {
        Request::from_parts(parts, Body::empty())
    };
    if identity && declared.is_some_and(|n| n > LIMIT) {
        // `finalhandler` reads the rest of the body before it answers
        // (`onFinished(req, write)`, `req.resume()`), so a client still
        // writing it is not cut off before it can read the 413. Drained to
        // a bound here, not without one.
        let drained = axum::body::to_bytes(body, LIMIT * 4).await.is_ok();
        tracing::debug!("http: an oversized body drained: {}", drained);
        return Err(Box::new((
            Refused::new(413, "entity.too.large"),
            rebuild(parts),
        )));
    }
    let raw = match axum::body::to_bytes(body, LIMIT * 4 + 1).await {
        Ok(b) => b,
        Err(_) => {
            return Err(Box::new((
                Refused::new(413, "entity.too.large"),
                rebuild(parts),
            )));
        }
    };
    if declared.is_some_and(|n| n != raw.len()) {
        return Err(Box::new((
            Refused::new(400, "request.size.invalid"),
            rebuild(parts),
        )));
    }
    let inflated = match inflate(&parts.headers, raw) {
        Ok(b) => b,
        Err(r) => return Err(Box::new((r, rebuild(parts)))),
    };
    if inflated.len() > LIMIT {
        return Err(Box::new((
            Refused::new(413, "entity.too.large"),
            rebuild(parts),
        )));
    }
    let raw_type = RAW_TYPES.contains(&essence_of(&parts.headers).as_str());
    let text = if raw_type {
        None
    } else {
        let charset =
            charset_of(&parts.headers).unwrap_or_else(|| "utf-8".to_string());
        let Some(decoder) = decoder_for(&charset) else {
            return Err(Box::new((
                Refused::new(415, "charset.unsupported"),
                rebuild(parts),
            )));
        };
        // iconv-lite strips a byte-order mark, and so does this decoder.
        let (decoded, _, _) = decoder.decode(&inflated);
        Some(decoded.into_owned())
    };
    let mut request = Request::from_parts(parts, Body::from(inflated.clone()));
    request.extensions_mut().insert(ParsedBody {
        bytes: inflated,
        text,
    });
    Ok(request)
}

/// The answer to a refused body — `finalhandler`'s page with its status,
/// marked — after the failure is written down (the error middleware's
/// audit row; the audit log is a later phase's, so it is the log line).
#[tracing::instrument(level = "debug", skip_all)]
pub fn refusal(refused: &Refused, method: &Method, path: &str) -> Response {
    tracing::info!(
        "{}http: the request body of {} {} was refused before any endpoint \
         saw it ({}, HTTP {}).",
        tag(refused.code),
        method,
        path,
        refused.kind,
        refused.status
    );
    crate::mark(crate::express::error_page(refused.status), refused.code)
}
