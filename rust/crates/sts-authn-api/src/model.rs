// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE MODEL OF THE API: the OpenAPI document `models/api/authn.tsp`
//! compiles to (`src/generated/openapi.authn.json`, the file Node serves at
//! `/authn-api/openapi.json` and validates against), and EVERY ANSWER HELD
//! TO IT, ALWAYS (#1353, `common/response_models.ts`'s `install()`, which
//! `AuthnApi.registerRoutes()` puts in front of every route).
//!
//! The check is sts-mgmt-api's (`answer.rs`), over this API's document: an
//! answer about to leave is checked against the closed model its operation
//! declares for its status, and one that does not match is NOT SENT — the
//! caller gets a 500 `server_error` saying nothing of the shape, and the
//! operator `STS-API-0139`, once per distinct failure, naming the
//! operation, the status and where (keyword names, never a value). A path
//! no operation documents may answer a refusal shaped as every refusal is;
//! anything else in JSON is a violation. Draft 7, as ajv's default class.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock, Mutex};

use serde_json::{Map, Value as Json};
use sts_core::errors::codes;

use crate::operations::{self, Operation};

/// The document, as the model wrote it.
pub const DOCUMENT_TEXT: &str = include_str!("generated/openapi.authn.json");

/// The body every violation is answered with (`FAILED_BODY`).
pub const FAILED_BODY: &str =
    "{\"error\":\"server_error\",\"error_description\":\"The service could not produce a valid answer.\"}";

static DOCUMENT: LazyLock<Json> = LazyLock::new(|| {
    serde_json::from_str(DOCUMENT_TEXT).unwrap_or_else(|e| {
        tracing::error!(
            "authn-api: the model's document does not parse: {}",
            e
        );
        Json::Object(Map::new())
    })
});

static VALIDATORS: LazyLock<
    Mutex<HashMap<String, Option<Arc<jsonschema::Validator>>>>,
> = LazyLock::new(|| Mutex::new(HashMap::new()));

static LOGGED: LazyLock<Mutex<HashSet<String>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// The document.
#[tracing::instrument(level = "trace")]
pub fn document() -> &'static Json {
    &DOCUMENT
}

/// `AuthnApi.document(options)`: the document with the build's version
/// and the realm's base as its one server.
#[tracing::instrument(level = "debug")]
pub fn served(base_url: &str, version: &str) -> Json {
    let mut doc = DOCUMENT.clone();
    if let Some(info) = doc.get_mut("info").and_then(Json::as_object_mut) {
        info.insert(
            "version".into(),
            Json::String(if version.is_empty() {
                "0.0.0".into()
            } else {
                version.to_string()
            }),
        );
    }
    if let Some(root) = doc.as_object_mut() {
        root.insert("servers".into(), serde_json::json!([{ "url": base_url }]));
    }
    doc
}

/// One operation's entry in the document.
#[tracing::instrument(level = "trace", skip(op))]
pub fn entry(op: &Operation) -> Option<&'static Json> {
    DOCUMENT
        .get("paths")?
        .get(op.document_path())?
        .get(op.method.to_ascii_lowercase())
}

/// The operation's summary and what it mirrors (`x-mirrors`).
#[tracing::instrument(level = "trace", skip(op))]
pub fn summary_of(op: &Operation) -> (String, Option<String>) {
    let entry = entry(op);
    let text = |k: &str| {
        entry
            .and_then(|e| e.get(k))
            .and_then(Json::as_str)
            .map(str::to_string)
    };
    (text("summary").unwrap_or_default(), text("x-mirrors"))
}

/// The operation's declared parameters (path, query and headers — the
/// implicit ones are in the document: `X-CSRF-Token` on an act, and
/// `openapi.every.json`'s `authn` list).
#[tracing::instrument(level = "trace", skip(op))]
pub fn parameters_of(op: &Operation) -> Vec<Json> {
    entry(op)
        .and_then(|e| e.get("parameters"))
        .and_then(Json::as_array)
        .cloned()
        .unwrap_or_default()
}

/// The request body's schema, where the operation takes one.
#[tracing::instrument(level = "trace", skip(op))]
pub fn body_schema(op: &Operation) -> Option<&'static Json> {
    entry(op)?.pointer("/requestBody/content/application~1json/schema")
}

/// The components a `$ref` resolves in.
#[tracing::instrument(level = "trace")]
pub fn components() -> &'static Json {
    static EMPTY: LazyLock<Json> = LazyLock::new(|| Json::Object(Map::new()));
    DOCUMENT.get("components").unwrap_or(&EMPTY)
}

/// `AuthnApi.refusalSchema()`: the body every refusal is held to — the
/// index's 400.
#[tracing::instrument(level = "trace")]
pub fn refusal_schema() -> Json {
    DOCUMENT
        .pointer(
            "/paths/~1authn-api/get/responses/400/content/application~1json/schema",
        )
        .cloned()
        .unwrap_or(Json::Object(Map::new()))
}

fn validator(key: String, schema: &Json) -> Option<Arc<jsonschema::Validator>> {
    let mut cache = match VALIDATORS.lock() {
        Ok(c) => c,
        Err(p) => p.into_inner(),
    };
    if let Some(found) = cache.get(&key) {
        return found.clone();
    }
    let mut root = Map::new();
    root.insert("allOf".into(), Json::Array(vec![schema.clone()]));
    root.insert("components".into(), components().clone());
    let built = jsonschema::options()
        .with_draft(jsonschema::Draft::Draft7)
        .should_validate_formats(true)
        .build(&Json::Object(root))
        .map(Arc::new)
        .map_err(|e| tracing::debug!("a model does not compile: {}", e))
        .ok();
    cache.insert(key, built.clone());
    built
}

/// What is wrong with an answer, `None` where it is what the model says
/// (`problemOf()`).
#[tracing::instrument(level = "debug", skip(body))]
pub fn problem_of(
    method: &str,
    path: &str,
    status: u16,
    media: &str,
    body: &[u8],
) -> Option<String> {
    let media = media
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let name = format!("{} {}", method, path);
    let found = operations::matching(method, path).map(|(op, _)| op);
    let Some(op) = found else {
        // undocumentedProblem()
        if !media.contains("json") {
            return None;
        }
        let nothing = Some(format!(
            "{} answered {}: no operation in the document",
            name, status
        ));
        if status < 400 {
            return nothing;
        }
        let Ok(parsed) = serde_json::from_slice::<Json>(body) else {
            return nothing;
        };
        let v = validator("refusal".into(), &refusal_schema())?;
        return (!v.is_valid(&parsed))
            .then(|| describe(&name, status, &v, &parsed));
    };
    let entry = entry(op)?;
    let responses = entry.get("responses")?;
    let declared = responses
        .get(status.to_string())
        .or_else(|| responses.get("default"));
    let Some(declared) = declared else {
        return Some(format!(
            "{} answered {}: a status the operation does not declare",
            op.id, status
        ));
    };
    if body.is_empty() {
        return None;
    }
    let Some(model) = declared.get("content").and_then(|c| c.get(&media))
    else {
        return Some(format!(
            "{} answered {}: a media type the status does not declare: {}",
            op.id, status, media
        ));
    };
    if !media.contains("json") {
        return None;
    }
    let Ok(parsed) = serde_json::from_slice::<Json>(body) else {
        return Some(format!(
            "{} answered {}: the body is not JSON",
            op.id, status
        ));
    };
    let schema = model
        .get("schema")
        .cloned()
        .unwrap_or(Json::Object(Map::new()));
    let key = format!("{} {} {}", op.id, status, media);
    let Some(v) = validator(key, &schema) else {
        return Some(format!(
            "{} answered {}: the model does not compile",
            op.id, status
        ));
    };
    (!v.is_valid(&parsed)).then(|| describe(op.id, status, &v, &parsed))
}

/// `describeErrors()`: the deepest first, each said once, eight at most.
fn describe(
    name: &str,
    status: u16,
    v: &jsonschema::Validator,
    value: &Json,
) -> String {
    let mut said: Vec<(usize, String)> = v
        .iter_errors(value)
        .map(|e| {
            let at = e.instance_path().to_string();
            let depth = at.split('/').count();
            (
                depth,
                format!(
                    "{} {:?}",
                    if at.is_empty() { "/".to_string() } else { at },
                    e.kind()
                ),
            )
        })
        .collect();
    said.sort_by_key(|b| std::cmp::Reverse(b.0));
    let mut seen = Vec::new();
    for (_, text) in said {
        let short: String = text.chars().take(160).collect();
        if !seen.contains(&short) {
            seen.push(short);
        }
    }
    format!(
        "{} answered {}: {}",
        name,
        status,
        seen.into_iter().take(8).collect::<Vec<_>>().join("; ")
    )
}

/// `report()`: the code, and the line once per distinct failure.
#[tracing::instrument(level = "debug")]
pub fn report(line: &str) {
    let mut logged = match LOGGED.lock() {
        Ok(l) => l,
        Err(p) => p.into_inner(),
    };
    if logged.len() < 2000 && logged.insert(line.to_string()) {
        tracing::error!(
            "{}An answer does not match its model and was not sent: {}",
            sts_core::log::tag(codes::STS_API_0139),
            line
        );
    }
}
