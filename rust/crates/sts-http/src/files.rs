// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A static surface's files and how they are sent — `ShellDocument`'s
//! `readFile()`, `sendFile()`, `sendCompressed()` and
//! `acceptedEncoding()` (#570).
//!
//! **THE BUNDLES ARE THE TYPESCRIPT BUILD'S OUTPUT, AND THIS RUNTIME
//! SERVES THEM AS BUILT.** `build-typescript.sh`'s `bundle_surface` writes
//! each surface's runtime (`home/home-spa.js`, `admin-ui/console.js`, …)
//! with the `.br` and `.gz` beside it inside the image build; the Rust
//! runtime's image copies that tree — the same `/usr/src/sts` the Node
//! image runs from, its `version.json` and `common/locales/` with it —
//! and [`WebRoot`] names it (`STS_WEB_ROOT`, `/usr/src/sts` by default).
//! A tree that was never built has no bundle, and the placeholder script
//! a surface names says so, as Node's does.
//!
//! Only a surface's own static files are compressed: an API or protocol
//! answer often carries a secret beside text the caller chose, which is
//! what BREACH reads through compression.

use std::io::Write;
use std::path::{Path, PathBuf};

use axum::body::Bytes;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;

use crate::express;

/// The tree a surface's built files are read from.
#[derive(Clone, Debug)]
pub struct WebRoot(pub PathBuf);

impl WebRoot {
    /// `STS_WEB_ROOT`, or `/usr/src/sts`, the image's tree.
    #[tracing::instrument(level = "debug")]
    pub fn from_env() -> WebRoot {
        WebRoot(PathBuf::from(
            std::env::var("STS_WEB_ROOT")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "/usr/src/sts".to_string()),
        ))
    }

    /// A path inside the tree.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn join(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }
}

/// A surface's file as built: its bytes and their precompressed forms.
#[derive(Clone, Debug)]
pub struct BuiltFile {
    pub raw: Bytes,
    pub br: Option<Bytes>,
    pub gzip: Option<Bytes>,
    /// Whether the build wrote it, or `raw` is the placeholder.
    pub built: bool,
}

/// `ShellDocument.readFile()`: the file and the `.br` and `.gz` beside
/// it, or the placeholder for a tree that was never built.
#[tracing::instrument(level = "debug", skip(placeholder))]
pub fn read_file(dir: &Path, name: &str, placeholder: &str) -> BuiltFile {
    let read = |file: &str| std::fs::read(dir.join(file)).ok().map(Bytes::from);
    match read(name) {
        Some(raw) => BuiltFile {
            raw,
            br: read(&format!("{}.br", name)),
            gzip: read(&format!("{}.gz", name)),
            built: true,
        },
        None => BuiltFile {
            raw: Bytes::from(placeholder.to_string()),
            br: None,
            gzip: None,
            built: false,
        },
    }
}

/// `acceptedEncoding()`: `br` where the request accepts it, else `gzip`,
/// else none — `q=0` refusing one.
#[tracing::instrument(level = "trace")]
pub fn accepted_encoding(header: &str) -> &'static str {
    let mut offered: Vec<(String, f64)> = Vec::new();
    for part in header.split(',') {
        let mut bits = part.trim().split(';');
        let name = bits.next().unwrap_or("").trim().to_ascii_lowercase();
        let rest: Vec<&str> = bits.collect();
        let joined = rest.join(";");
        let q = joined.find("q=").map(|at| {
            let digits: String = joined[at + 2..]
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            digits.parse::<f64>().unwrap_or(f64::NAN)
        });
        if !name.is_empty() {
            offered.retain(|(n, _)| *n != name);
            offered.push((name, q.unwrap_or(1.0)));
        }
    }
    let takes = |name: &str| {
        let q = offered
            .iter()
            .find(|(n, _)| n == name)
            .or_else(|| offered.iter().find(|(n, _)| n == "*"))
            .map(|(_, q)| *q);
        q.is_some_and(|q| q > 0.0)
    };
    if takes("br") {
        "br"
    } else if takes("gzip") {
        "gzip"
    } else {
        ""
    }
}

/// Brotli at quality 5 with the length as its size hint, Node's
/// `brotliCompressSync()` parameters.
fn brotli(bytes: &[u8]) -> Bytes {
    let params = brotli::enc::BrotliEncoderParams {
        quality: 5,
        size_hint: bytes.len(),
        ..Default::default()
    };
    let mut out = Vec::new();
    let mut input = bytes;
    if brotli::BrotliCompress(&mut input, &mut out, &params).is_err() {
        return Bytes::new();
    }
    Bytes::from(out)
}

/// Gzip at level 6, Node's `gzipSync()`: no name, no time, the Unix
/// operating system byte.
fn gzip(bytes: &[u8]) -> Bytes {
    let mut encoder = flate2::GzBuilder::new()
        .operating_system(3)
        .write(Vec::new(), flate2::Compression::new(6));
    if encoder.write_all(bytes).is_err() {
        return Bytes::new();
    }
    encoder.finish().map(Bytes::from).unwrap_or_default()
}

/// `sendCompressed()`: the body in the coding the request accepts,
/// `packed` used where the build wrote it, `Vary: Accept-Encoding`. The
/// headers are the caller's (its type and caching). An uncompressed
/// string stays a string, for the realm's rewrite.
#[tracing::instrument(level = "debug", skip_all)]
pub fn send_compressed(
    request: &HeaderMap,
    mut headers: HeaderMap,
    text: Bytes,
    is_text: bool,
    packed: Option<&BuiltFile>,
    finish: Option<&dyn Fn(&str) -> String>,
) -> Response {
    express::vary(&mut headers, "Accept-Encoding");
    let asked = request
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let encoding = accepted_encoding(asked);
    if encoding.is_empty() {
        return express::send(StatusCode::OK, headers, text, is_text);
    }
    let prebuilt = packed.and_then(|p| {
        if encoding == "br" {
            p.br.clone()
        } else {
            p.gzip.clone()
        }
    });
    let bytes = match prebuilt {
        Some(b) => b,
        None => {
            let final_text: Bytes = match (finish, is_text) {
                (Some(f), true) => {
                    Bytes::from(f(&String::from_utf8_lossy(&text)))
                }
                _ => text,
            };
            if encoding == "br" {
                brotli(&final_text)
            } else {
                gzip(&final_text)
            }
        }
    };
    headers
        .insert(header::CONTENT_ENCODING, HeaderValue::from_static(encoding));
    express::send(StatusCode::OK, headers, bytes, false)
}

/// `sendFile()`: a built file, `no-cache`, its type, in the coding the
/// request accepts.
#[tracing::instrument(level = "debug", skip_all)]
pub fn send_file(
    request: &HeaderMap,
    file: &BuiltFile,
    content_type: &str,
) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    if let Ok(v) = HeaderValue::from_str(&express::typed(content_type)) {
        headers.insert(header::CONTENT_TYPE, v);
    }
    send_compressed(request, headers, file.raw.clone(), false, Some(file), None)
}
