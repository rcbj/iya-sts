// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The files every static public surface shares, under `/web` (#570) — a
//! port of `common/public_assets.ts`:
//!
//! * `GET /favicon.ico` — the service's icon, kept a day.
//! * `GET /web/card.css` — the card and the chooser's rules.
//! * `GET /web/footer.css` — the page footer every shell draws.
//! * `GET /web/locales/catalogs.json` — the catalog index.
//! * `GET /web/locales/<ns>/<catalog>.json` — one namespace's messages in
//!   one catalog, as the catalogs were loaded; `console-all` every console
//!   namespace merged (#1333); anything else a 404 (`STS-I18N-0012`).
//!   NOTHING IS READ FROM DISK BY A REQUESTED NAME.
//!
//! An address carrying `?v=` equal to this build's identifier is the same
//! bytes for the life of the build — `public, max-age=31536000,
//! immutable` — and any other `no-cache`. Compressed where the request
//! accepts it: static text with no secret beside it, which BREACH needs.
//! `/web` belongs to no one application and is answered on every listener.

use std::sync::Arc;

use axum::body::Bytes;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use serde_json::{json, Value as Json};
use sts_core::errors::codes;

use crate::files::{self, BuiltFile};
use crate::i18n::Catalogs;

/// `/web/card.css` (`WebCardCss.CARD_CSS`), held to Node's bytes by the
/// differential harness.
pub const CARD_CSS: &str = include_str!("../assets/web_card.css");

const IMMUTABLE: &str = "public, max-age=31536000, immutable";

/// The first value of a query parameter, decoded as Express's parser
/// decodes it.
// A hot path: every request for a /web file; no span.
pub fn query_value(query: &str, name: &str) -> Option<String> {
    query.split('&').filter(|p| !p.is_empty()).find_map(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        (crate::cors::form_decode(k) == name)
            .then(|| crate::cors::form_decode(v))
    })
}

/// Whether a query names this one parameter more than once (Express hands
/// the handler a list, and `typeof req.query.v === 'string'` is false).
fn single_value(query: &str, name: &str) -> Option<String> {
    let count = query
        .split('&')
        .filter(|p| {
            crate::cors::form_decode(p.split('=').next().unwrap_or("")) == name
        })
        .count();
    if count == 1 {
        query_value(query, name)
    } else {
        None
    }
}

/// The shared files of the public surfaces.
pub struct PublicAssets {
    catalogs: Arc<Catalogs>,
    version: String,
    build_id: String,
    favicon: BuiltFile,
}

impl PublicAssets {
    /// Over the catalogs, the build and the tree's `common/favicon.ico`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(
        catalogs: Arc<Catalogs>,
        version: &sts_core::version::VersionInfo,
        root: &crate::files::WebRoot,
    ) -> PublicAssets {
        PublicAssets {
            catalogs,
            version: version.version.clone(),
            build_id: crate::footer::build_id(version),
            favicon: files::read_file(&root.join("common"), "favicon.ico", ""),
        }
    }

    /// `cachingFor()`: for good when the address names this build.
    fn caching_for(&self, query: &str) -> &'static str {
        match single_value(query, "v") {
            Some(v) if !v.is_empty() && v == self.build_id => IMMUTABLE,
            _ => "no-cache",
        }
    }

    /// The catalog index as the browser reads it.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn index(&self) -> Json {
        json!({
            "source": crate::i18n::SOURCE,
            "version": self.version,
            "catalogs": self.catalogs.catalogs(),
            "offered": self.catalogs.offered(),
        })
    }

    /// One namespace's messages in one catalog, or `None`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn catalog(&self, ns: &str, file: &str) -> Option<Json> {
        let tag = file.strip_suffix(".json").filter(|t| {
            !t.is_empty()
                && t.len() <= 64
                && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })?;
        if ns == "console-all" && self.catalogs.has_catalog(tag) {
            return Some(Json::Object(self.catalogs.merged(tag, "console")));
        }
        let known = self.catalogs.namespaces().iter().any(|n| n == ns)
            && self.catalogs.has_catalog(tag);
        known.then(|| Json::Object(self.catalogs.messages_of(ns, tag)))
    }

    fn send_text(
        &self,
        request: &HeaderMap,
        content_type: &'static str,
        cache: &'static str,
        body: String,
    ) -> Response {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(content_type),
        );
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
        files::send_compressed(
            request,
            headers,
            Bytes::from(body),
            true,
            None,
            None,
        )
    }

    fn not_found(text: &str, code: sts_core::errors::ErrorCode) -> Response {
        let mut r = crate::text(text);
        *r.status_mut() = StatusCode::NOT_FOUND;
        r.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        );
        crate::mark(r, code)
    }

    /// `GET /favicon.ico`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn favicon(&self) -> Response {
        if !self.favicon.built {
            return PublicAssets::not_found(
                "There is no icon.",
                codes::STS_CORE_0166,
            );
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("image/x-icon"),
        );
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=86400"),
        );
        crate::express::send(
            StatusCode::OK,
            headers,
            self.favicon.raw.clone(),
            false,
        )
    }

    /// `GET /web/card.css`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn card(&self, request: &HeaderMap, query: &str) -> Response {
        self.send_text(
            request,
            "text/css; charset=utf-8",
            self.caching_for(query),
            CARD_CSS.into(),
        )
    }

    /// `GET /web/footer.css`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn footer(&self, request: &HeaderMap, query: &str) -> Response {
        self.send_text(
            request,
            "text/css; charset=utf-8",
            self.caching_for(query),
            crate::footer::CSS.into(),
        )
    }

    /// `GET /web/locales/catalogs.json`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn index_response(&self, request: &HeaderMap, query: &str) -> Response {
        self.send_text(
            request,
            "application/json; charset=utf-8",
            self.caching_for(query),
            self.index().to_string(),
        )
    }

    /// `GET /web/locales/<ns>/<file>`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn catalog_response(
        &self,
        request: &HeaderMap,
        query: &str,
        ns: &str,
        file: &str,
    ) -> Response {
        match self.catalog(ns, file) {
            None => PublicAssets::not_found(
                "There is no such catalog file.",
                codes::STS_I18N_0012,
            ),
            Some(found) => self.send_text(
                request,
                "application/json; charset=utf-8",
                self.caching_for(query),
                found.to_string(),
            ),
        }
    }
}
