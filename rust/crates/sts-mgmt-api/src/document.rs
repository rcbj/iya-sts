// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The two documents `/admin-api` serves — the Management API OpenAPI
//! document and the Admin Console API OpenAPI document — as the model
//! generates them (`generated/openapi.*.json`), and the answer
//! `GET /admin-api/openapi.json` makes of one (`AdminApiSpec.buildSpec()`).
//!
//! **SERVED AS GENERATED.** What depends on the request — the base URL in
//! `servers` and the security schemes, the version, and whether the gate
//! is on — is the frame `export-admin-api-tables.js` exported with marks
//! in its place; the paths and the schemas are the model's, unchanged. So
//! the document describes every operation the model has, ported or not,
//! which is what Node answers too: an integrator reads one document.
//!
//! **One Node defect is not ported.** `buildSpec()` with the gate off
//! deletes `security` from the model's own cached operation objects, so
//! once the off document has been asked for, every later document — the
//! gate on again — lacks per-operation `security`. Here the off document
//! leaves it out of its copy only.

use std::sync::LazyLock;

use serde_json::{Map, Value as Json};

use crate::operations::Kind;
use crate::tables::{tables, BASE_MARK, VERSION_MARK};

static MANAGEMENT: LazyLock<Json> =
    LazyLock::new(|| parse(include_str!("generated/openapi.management.json")));

static CONSOLE: LazyLock<Json> =
    LazyLock::new(|| parse(include_str!("generated/openapi.console.json")));

static EVERY: LazyLock<Json> =
    LazyLock::new(|| parse(include_str!("generated/openapi.every.json")));

fn parse(text: &str) -> Json {
    // The file is this crate's own, written by the model's build; one that
    // does not parse is a corrupted build, answered as an empty document.
    serde_json::from_str(text).unwrap_or_else(|e| {
        tracing::error!("a generated document does not parse: {}", e);
        Json::Object(Map::new())
    })
}

/// The model's document of a kind. A hot path: read on every request.
pub fn model(kind: Kind) -> &'static Json {
    match kind {
        Kind::Management => &MANAGEMENT,
        Kind::Console => &CONSOLE,
    }
}

/// The model's operation object.
#[tracing::instrument(level = "debug")]
pub fn operation(
    kind: Kind,
    method: &str,
    path: &str,
) -> Option<&'static Json> {
    model(kind)
        .get("paths")
        .and_then(|p| p.get(path))
        .and_then(|p| p.get(method.to_ascii_lowercase()))
}

/// The component schemas of a kind's document. A hot path: read per
/// request, so it carries no span.
pub fn components(kind: Kind) -> &'static Json {
    static EMPTY: LazyLock<Json> = LazyLock::new(|| Json::Object(Map::new()));
    model(kind).get("components").unwrap_or(&EMPTY)
}

/// What every operation takes without saying so (#1476): `DPoP` and
/// `cell` (`openapi.every.json`'s `management`). A hot path: read per
/// request, so it carries no span.
pub fn implicit_parameters() -> &'static [Json] {
    EVERY
        .get("management")
        .and_then(Json::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

/// The model of every refusal (`AdminApiSpec.refusalSchema()`): what an
/// undocumented path under the prefix may answer.
#[tracing::instrument(level = "debug")]
pub fn refusal_schema() -> Json {
    MANAGEMENT
        .pointer(
            "/paths/~1admin-api/get/responses/default/content/\
             application~1json/schema",
        )
        .cloned()
        .unwrap_or(Json::Null)
}

fn substitute(value: &Json, base: &str, version: &str) -> Json {
    match value {
        Json::String(s) => Json::String(
            s.replace(BASE_MARK, base).replace(VERSION_MARK, version),
        ),
        Json::Array(list) => Json::Array(
            list.iter().map(|v| substitute(v, base, version)).collect(),
        ),
        Json::Object(map) => Json::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), substitute(v, base, version)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// `buildSpec(routesOfKind(kind), specOptions(req))`: the document for a
/// kind, at a base URL and a version, with the gate on or off.
#[tracing::instrument(level = "debug", skip_all)]
pub fn served(
    kind: Kind,
    base: &str,
    version: &str,
    auth_required: bool,
) -> Json {
    let pair = match kind {
        Kind::Management => &tables().frames.management,
        Kind::Console => &tables().frames.console,
    };
    let frame = if auth_required { &pair.on } else { &pair.off };
    let doc = model(kind);
    let mut out = Map::new();
    for (key, value) in frame.as_object().into_iter().flatten() {
        match key.as_str() {
            "paths" => {
                let mut paths = Map::new();
                for entry in value.as_array().into_iter().flatten() {
                    let path = entry
                        .get("path")
                        .and_then(Json::as_str)
                        .unwrap_or_default();
                    let mut methods = Map::new();
                    for m in entry
                        .get("methods")
                        .and_then(Json::as_array)
                        .into_iter()
                        .flatten()
                    {
                        let m = m.as_str().unwrap_or_default();
                        let Some(op) = doc
                            .get("paths")
                            .and_then(|p| p.get(path))
                            .and_then(|p| p.get(m))
                        else {
                            continue;
                        };
                        let mut op = op.clone();
                        if !auth_required {
                            if let Some(o) = op.as_object_mut() {
                                o.shift_remove("security");
                            }
                        }
                        methods.insert(m.to_string(), op);
                    }
                    paths.insert(path.to_string(), Json::Object(methods));
                }
                out.insert(key.clone(), Json::Object(paths));
            }
            "components" => {
                let mut components = Map::new();
                components.insert(
                    "schemas".to_string(),
                    doc.pointer("/components/schemas")
                        .cloned()
                        .unwrap_or(Json::Object(Map::new())),
                );
                for (k, v) in value.as_object().into_iter().flatten() {
                    components.insert(k.clone(), substitute(v, base, version));
                }
                out.insert(key.clone(), Json::Object(components));
            }
            _ => {
                out.insert(key.clone(), substitute(value, base, version));
            }
        }
    }
    Json::Object(out)
}
