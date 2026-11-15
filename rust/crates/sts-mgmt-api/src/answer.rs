// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! EVERY ANSWER IS HELD TO ITS MODEL, ALWAYS (#1353,
//! `common/response_models.ts`). The answer about to leave is checked
//! against the closed model its operation declares for its status — the
//! gate's refusals included, since the check is the router's last step and
//! not one per handler — and one that does not match is NOT SENT: the
//! caller gets a 500 `server_error` saying nothing of the shape, and the
//! operator `STS-API-0139`, once per distinct failure, naming the
//! operation, the status and where it failed (keyword names, never a
//! value: these bodies hold tokens and personal data).
//!
//! A path no operation documents may answer a refusal shaped as every
//! refusal is (an action nobody defined); anything else it answers in JSON
//! is a violation. The model's own validator is the `jsonschema` crate's,
//! draft 7, as ajv's default class (`{ allOf: [schema], components }`).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock, Mutex};

use serde_json::{Map, Value as Json};
use sts_core::errors::codes;

use crate::document;
use crate::operations::{self, Kind};

/// The body every violation is answered with (`FAILED_BODY`).
pub const FAILED_BODY: &str =
    "{\"error\":\"server_error\",\"error_description\":\"The service could not produce a valid answer.\"}";

static VALIDATORS: LazyLock<Mutex<HashMap<String, Option<Arc<jsonschema::Validator>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

static LOGGED: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

fn validator(key: String, kind: Kind, schema: &Json) -> Option<Arc<jsonschema::Validator>> {
    let mut cache = match VALIDATORS.lock() {
        Ok(c) => c,
        Err(p) => p.into_inner(),
    };
    if let Some(found) = cache.get(&key) {
        return found.clone();
    }
    let mut root = Map::new();
    root.insert("allOf".into(), Json::Array(vec![schema.clone()]));
    root.insert("components".into(), document::components(kind).clone());
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
/// (`problemOf()`): the operation, the status and where.
#[tracing::instrument(level = "debug", skip(body))]
pub fn problem_of(method: &str, path: &str, status: u16, media: &str, body: &[u8]) -> Option<String> {
    let trimmed = if path.len() > 1 { path.trim_end_matches('/') } else { path };
    let found = operations::find(method, trimmed);
    let name = format!("{} {}", method, path);
    let media = media.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    let Some(row) = found else {
        // undocumentedProblem()
        if !media.contains("json") {
            return None;
        }
        let nothing = Some(format!("{} answered {}: no operation in the document", name, status));
        if status < 400 {
            return nothing;
        }
        let Ok(parsed) = serde_json::from_slice::<Json>(body) else {
            return nothing;
        };
        let refusal = document::refusal_schema();
        let v = validator("refusal".into(), Kind::Management, &refusal)?;
        return (!v.is_valid(&parsed)).then(|| describe(&name, status, &v, &parsed));
    };
    let Some(op) = document::operation(row.kind, row.method, row.path) else {
        return None;
    };
    let responses = op.get("responses")?;
    let declared = responses.get(status.to_string()).or_else(|| responses.get("default"));
    let Some(declared) = declared else {
        return Some(format!("{} answered {}: a status the operation does not declare", row.id, status));
    };
    if body.is_empty() {
        return None;
    }
    let content = declared.get("content");
    let Some(model) = content.and_then(|c| c.get(&media)) else {
        return Some(format!("{} answered {}: a media type the status does not declare: {}", row.id, status, media));
    };
    if !media.contains("json") {
        return None;
    }
    let Ok(parsed) = serde_json::from_slice::<Json>(body) else {
        return Some(format!("{} answered {}: the body is not JSON", row.id, status));
    };
    let schema = model.get("schema").cloned().unwrap_or(Json::Object(Map::new()));
    let key = format!("{} {} {}", row.id, status, media);
    let Some(v) = validator(key, row.kind, &schema) else {
        return Some(format!("{} answered {}: the model does not compile", row.id, status));
    };
    (!v.is_valid(&parsed)).then(|| describe(row.id, status, &v, &parsed))
}

/// `describeErrors()`: the deepest first, each said once, eight at most.
fn describe(name: &str, status: u16, v: &jsonschema::Validator, value: &Json) -> String {
    let mut said: Vec<(usize, String)> = v
        .iter_errors(value)
        .map(|e| {
            let at = e.instance_path().to_string();
            let depth = at.split('/').count();
            (depth, format!("{} {:?}", if at.is_empty() { "/".to_string() } else { at }, e.kind()))
        })
        .collect();
    said.sort_by(|a, b| b.0.cmp(&a.0));
    let mut seen = Vec::new();
    for (_, text) in said {
        let short: String = text.chars().take(160).collect();
        if !seen.contains(&short) {
            seen.push(short);
        }
    }
    format!("{} answered {}: {}", name, status, seen.into_iter().take(8).collect::<Vec<_>>().join("; "))
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
