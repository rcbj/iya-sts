// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What a request may name and hold, checked before any handler runs —
//! `registerRoutes()`'s wrapper in `mgmt-api/admin_api.ts`, with
//! `common/closed_sets.ts` and `common/request_headers.ts`:
//!
//! * a query parameter outside its declared enum (STS-API-0124), a name
//!   the operation does not declare (0142) and a value its type does not
//!   hold (0143), in that order (#86, #1476);
//! * a custom header nobody defined (0144);
//! * a body that does not fit the operation's schema (0009), in ajv's
//!   words ([`crate::schema`]).
//!
//! The parameters are the model's (the document is the route table's
//! since #1390; `tests/admin_api_request_names.js` holds them equal), with
//! `DPoP` and `cell` added as `declareImplicitParameters()` adds them.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use serde_json::{Map, Value as Json};
use sts_core::errors::{codes, ErrorCode};

use crate::document;
use crate::operations::{Kind, OperationRow};
use crate::schema::{structure_only, AjvError, Walker};

/// A query string as Express's `qs` reads the plain forms: a name once is
/// a string, a name repeated is the list of its values, in arrival order
/// of first appearance.
pub type Query = indexmap::IndexMap<String, Json>;

/// `qs.parse()` of the forms a caller sends: `a=1&a=2&b`.
#[tracing::instrument(level = "debug")]
pub fn parse_query(raw: &str) -> Query {
    let mut out = Query::new();
    for pair in raw.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let key = decode(k);
        let value = Json::String(decode(v));
        match out.get_mut(&key) {
            Some(Json::Array(list)) => list.push(value),
            Some(existing) => {
                let first = existing.clone();
                *existing = Json::Array(vec![first, value]);
            }
            None => {
                out.insert(key, value);
            }
        }
    }
    out
}

fn decode(text: &str) -> String {
    let bytes = text.replace('+', " ").into_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            if let Ok(b) = u8::from_str_radix(hex, 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A refusal before the handler.
#[derive(Debug, Clone, PartialEq)]
pub struct Refused {
    pub status: u16,
    pub code: ErrorCode,
    pub errors: Vec<String>,
}

/// The operation's parameters, the implicit ones added.
#[tracing::instrument(level = "debug")]
pub fn parameters_of(row: &OperationRow) -> Vec<Json> {
    let own: Vec<Json> = document::operation(row.kind, row.method, row.path)
        .and_then(|op| op.get("parameters"))
        .and_then(Json::as_array)
        .cloned()
        .unwrap_or_default();
    let mut out = own.clone();
    for one in document::implicit_parameters() {
        let same = own.iter().any(|p| {
            p.get("in") == one.get("in") && p.get("name") == one.get("name")
        });
        if !same {
            out.push(one.clone());
        }
    }
    out
}

/// `ClosedSets.sentence()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn closed_sentence(field: &str, value: &Json, values: &[Json]) -> String {
    let shown: Vec<String> = values.iter().map(js_stringify).collect();
    format!(
        "\"{}\" is {}, which is not one of the {} value{} it accepts: {}.",
        field,
        js_stringify(value),
        values.len(),
        if values.len() == 1 { "" } else { "s" },
        shown.join(", ")
    )
}

/// `JSON.stringify()` of a value, as a sentence names it. A hot path:
/// called per value of a sentence, so it carries no span.
pub fn js_stringify(value: &Json) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

fn text_of(v: &Json) -> String {
    match v {
        Json::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// `checkQuery()`: the first value outside a declared enum.
fn check_enums(parameters: &[Json], query: &Query) -> Option<String> {
    for p in parameters {
        if p.get("in").and_then(Json::as_str) != Some("query") {
            continue;
        }
        let (Some(name), Some(schema)) =
            (p.get("name").and_then(Json::as_str), p.get("schema"))
        else {
            continue;
        };
        if schema.get("x-refused-by-handler") == Some(&Json::Bool(true)) {
            continue;
        }
        let values = schema
            .get("enum")
            .and_then(Json::as_array)
            .or_else(|| schema.pointer("/items/enum").and_then(Json::as_array));
        let Some(values) = values else { continue };
        let Some(raw) = query.get(name) else { continue };
        let each: Vec<Json> = match raw {
            Json::String(s)
                if schema.get("type").and_then(Json::as_str)
                    == Some("array") =>
            {
                s.split(',')
                    .map(|x| Json::String(x.trim().to_string()))
                    .collect()
            }
            Json::Array(list) => list.clone(),
            other => vec![other.clone()],
        };
        for one in each {
            if one.is_null() || one == Json::String(String::new()) {
                continue;
            }
            let hit = values
                .iter()
                .any(|v| v == &one || text_of(v) == text_of(&one));
            if !hit {
                return Some(closed_sentence(name, &one, values));
            }
        }
    }
    None
}

/// `ClosedSets.fitsQueryType()`.
fn fits(schema: Option<&Json>, raw: &Json) -> bool {
    let kind = schema.and_then(|s| s.get("type")).and_then(Json::as_str);
    if raw == &Json::String(String::new()) {
        return true;
    }
    if kind.is_none() {
        if let Some(branches) =
            schema.and_then(|s| s.get("anyOf")).and_then(Json::as_array)
        {
            return branches.iter().any(|b| fits(Some(b), raw));
        }
    }
    let Some(kind) = kind else { return true };
    if kind == "object" {
        return true;
    }
    if let Json::Array(list) = raw {
        return list.iter().all(|one| fits(schema, one));
    }
    let Json::String(text) = raw else {
        return false;
    };
    let t = text.trim();
    match kind {
        "array" => {
            let items = schema
                .and_then(|s| s.get("items"))
                .filter(|i| i.get("type").is_some());
            items.is_none_or(|items| {
                text.split(',').all(|one| {
                    fits(Some(items), &Json::String(one.trim().to_string()))
                })
            })
        }
        "integer" => {
            let digits = t.strip_prefix(['+', '-']).unwrap_or(t);
            !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
        }
        "number" => !t.is_empty() && t.parse::<f64>().is_ok_and(f64::is_finite),
        "boolean" => matches!(
            t.to_ascii_lowercase().as_str(),
            "true" | "false" | "1" | "0" | "yes" | "no" | "on" | "off"
        ),
        _ => true,
    }
}

/// `encodeURIComponent()`.
fn encode_uri_component(text: &str) -> String {
    let mut out = String::new();
    for b in text.as_bytes() {
        let c = *b as char;
        if c.is_ascii_alphanumeric() || "-_.!~*'()".contains(c) {
            out.push(c);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

/// `ClosedSets.saidName()`: quoted, encoded where it carries markup.
#[tracing::instrument(level = "debug")]
pub fn said_name(name: &str) -> String {
    // MAX_NAME_SAID is in UTF-16 code units; a pair the cut would split is
    // dropped whole.
    let mut units = 0;
    let mut text = String::new();
    for c in name.chars() {
        let n = c.len_utf16();
        if units + n > 128 {
            break;
        }
        units += n;
        text.push(c);
    }
    let plain = !text.chars().any(|c| {
        "\"'<>`\\".contains(c) || (c as u32) < 0x20 || c as u32 == 0x7f
    });
    js_stringify(&Json::String(if plain {
        text.clone()
    } else {
        encode_uri_component(&text)
    }))
}

/// `checkQueryDeclared()`: a query name the parameters do not declare
/// (STS-API-0142), or a value its type does not hold (0143). `/authn-api`
/// asks it too (`RequestHeaders.checkRequest()`).
#[tracing::instrument(level = "debug", skip_all)]
pub fn check_declared(
    parameters: &[Json],
    query: &Query,
) -> Option<(ErrorCode, String)> {
    let declared: HashMap<&str, &Json> = parameters
        .iter()
        .filter(|p| p.get("in").and_then(Json::as_str) == Some("query"))
        .filter_map(|p| p.get("name").and_then(Json::as_str).map(|n| (n, p)))
        .collect();
    for (name, value) in query {
        let said = said_name(name);
        let Some(p) = declared.get(name.as_str()) else {
            return Some((
                codes::STS_API_0142,
                format!(
                    "The query parameter {} is not one this operation takes. Its parameters in the \
                     OpenAPI document list the ones it does.",
                    said
                ),
            ));
        };
        let schema = p.get("schema");
        if schema.and_then(|s| s.get("x-refused-by-handler"))
            == Some(&Json::Bool(true))
        {
            continue;
        }
        if !fits(schema, value) {
            let kind = schema
                .and_then(|s| s.get("type"))
                .and_then(Json::as_str)
                .unwrap_or("declared");
            return Some((
                codes::STS_API_0143,
                format!(
                    "The query parameter {} must be {}.",
                    said,
                    if kind == "integer" {
                        "an integer".to_string()
                    } else {
                        format!("a value of type {}", kind)
                    }
                ),
            ));
        }
    }
    None
}

const STANDARD: &[&str] = &[
    "accept",
    "accept-charset",
    "accept-datetime",
    "accept-encoding",
    "accept-language",
    "accept-signature",
    "access-control-request-headers",
    "access-control-request-method",
    "access-control-request-private-network",
    "alt-used",
    "authorization",
    "cache-control",
    "cdn-loop",
    "connection",
    "content-digest",
    "content-disposition",
    "content-encoding",
    "content-language",
    "content-length",
    "content-location",
    "content-md5",
    "content-range",
    "content-type",
    "cookie",
    "date",
    "device-memory",
    "dnt",
    "downlink",
    "dpr",
    "early-data",
    "ect",
    "expect",
    "from",
    "host",
    "http2-settings",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-range",
    "if-unmodified-since",
    "keep-alive",
    "link",
    "max-forwards",
    "mime-version",
    "origin",
    "pragma",
    "prefer",
    "priority",
    "proxy-authorization",
    "proxy-connection",
    "purpose",
    "range",
    "referer",
    "repr-digest",
    "rtt",
    "save-data",
    "service-worker",
    "signature",
    "signature-input",
    "te",
    "timing-allow-origin",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "upgrade-insecure-requests",
    "user-agent",
    "viewport-width",
    "want-content-digest",
    "want-repr-digest",
    "warning",
    "width",
    // ADDED_IN_TRANSIT's exact names.
    "forwarded",
    "via",
    "x-real-ip",
    "x-request-id",
    "traceparent",
    "tracestate",
    "baggage",
    "x-client-cert",
    "x-origin-verify",
    "x-cloud-trace-context",
    // INTERNAL.
    "x-sts-cell-client",
    "x-sts-cell-from",
    "x-sts-cell-hops",
    "x-sts-cell-reason",
    "x-sts-ldap-drop",
    "x-sts-listener",
    "x-sts-peer-authorized",
    "x-sts-peer-certificate",
    "x-sts-pool-phases",
    "x-sts-pool-phases-wanted",
    "x-sts-pool-protocol-worker",
    "x-sts-pool-revoking",
    "x-sts-pool-ticket",
    "x-sts-tls-client-hello",
];

const FAMILIES: &[&str] = &[
    "x-forwarded-",
    "sec-",
    "x-ssl-client-",
    "cloudfront-",
    "x-amz-",
    "x-amzn-",
    "x-goog-",
    "x-appgw-",
    "x-arr-",
    "x-azure-",
    "x-fd-",
    "x-ms-",
    "x-original-",
];

/// `RequestHeaders.check()`: the first header neither declared nor
/// defined anywhere, by its lower-cased name.
#[tracing::instrument(level = "debug", skip_all)]
pub fn check_headers<'a>(
    parameters: &[Json],
    names: impl Iterator<Item = &'a str>,
) -> Option<String> {
    let declared: Vec<String> = parameters
        .iter()
        .filter(|p| p.get("in").and_then(Json::as_str) == Some("header"))
        .filter_map(|p| {
            p.get("name")
                .and_then(Json::as_str)
                .map(str::to_ascii_lowercase)
        })
        .collect();
    for name in names {
        let lower = name.to_ascii_lowercase();
        let accepted = lower.starts_with(':')
            || declared.contains(&lower)
            || STANDARD.contains(&lower.as_str())
            || FAMILIES.iter().any(|f| lower.starts_with(f));
        if !accepted {
            let shown: String = lower.chars().take(128).collect();
            return Some(format!(
                "The request header {} is not one this operation takes: it is not declared in the OpenAPI \
                 document and no specification defines it.",
                js_stringify(&Json::String(shown))
            ));
        }
    }
    None
}

/// The query and header checks, in the wrapper's order.
#[tracing::instrument(level = "debug", skip_all)]
pub fn check_shape<'a>(
    row: &OperationRow,
    query: &Query,
    headers: impl Iterator<Item = &'a str>,
) -> Result<(), Refused> {
    let parameters = parameters_of(row);
    if let Some(sentence) = check_enums(&parameters, query) {
        return Err(Refused {
            status: 400,
            code: codes::STS_API_0124,
            errors: vec![sentence],
        });
    }
    if let Some((code, sentence)) = check_declared(&parameters, query) {
        return Err(Refused {
            status: 400,
            code,
            errors: vec![sentence],
        });
    }
    if let Some(sentence) = check_headers(&parameters, headers) {
        return Err(Refused {
            status: 400,
            code: codes::STS_API_0144,
            errors: vec![sentence],
        });
    }
    Ok(())
}

struct Compiled {
    schema: Json,
    validator: Option<jsonschema::Validator>,
}

static STRUCTURED: LazyLock<
    Mutex<HashMap<&'static str, std::sync::Arc<Json>>>,
> = LazyLock::new(|| Mutex::new(HashMap::new()));

static COMPILED: LazyLock<
    Mutex<HashMap<&'static str, std::sync::Arc<Compiled>>>,
> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn structured_components(kind: Kind) -> std::sync::Arc<Json> {
    let mut cache = match STRUCTURED.lock() {
        Ok(c) => c,
        Err(p) => p.into_inner(),
    };
    cache
        .entry(kind.as_str())
        .or_insert_with(|| {
            std::sync::Arc::new(structure_only(document::components(kind)))
        })
        .clone()
}

/// The request body's schema, as `validatorFor()` compiles it, once.
fn compiled(row: &'static OperationRow) -> Option<std::sync::Arc<Compiled>> {
    let schema = document::operation(row.kind, row.method, row.path)?
        .pointer("/requestBody/content/application~1json/schema")?;
    let mut cache = match COMPILED.lock() {
        Ok(c) => c,
        Err(p) => p.into_inner(),
    };
    if let Some(found) = cache.get(row.id) {
        return Some(found.clone());
    }
    let components = structured_components(row.kind);
    let schema = structure_only(schema);
    let mut root = match &schema {
        Json::Object(m) => m.clone(),
        _ => Map::new(),
    };
    root.insert("components".into(), (*components).clone());
    let root = Json::Object(root);
    // Draft 7, as ajv's default class; a schema that does not compile is
    // a maintainer's mistake and leaves the operation unvalidated
    // (STS-API-0010), as Node does.
    let validator = jsonschema::options()
        .with_draft(jsonschema::Draft::Draft7)
        .build(&root)
        .map_err(|e| {
            tracing::error!(
                "{}admin-api: the request schema for {} would not compile and that operation is \
                 unvalidated: {}",
                sts_core::log::tag(codes::STS_API_0010),
                row.id,
                e
            );
        })
        .ok();
    let made = std::sync::Arc::new(Compiled {
        schema: root,
        validator,
    });
    cache.insert(row.id, made.clone());
    Some(made)
}

/// `errorsFromAjv()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn sentences(errors: &[AjvError]) -> Vec<String> {
    let out: Vec<String> = errors
        .iter()
        .map(|e| {
            let where_ = e.instance_path.trim_start_matches('/').replace('/', ".");
            if e.keyword == "enum" {
                let allowed: Vec<Json> = e
                    .allowed
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|v| v != &Json::String(String::new()))
                    .collect();
                return closed_sentence(if where_.is_empty() { "the request" } else { &where_ }, &e.data, &allowed);
            }
            if let Some(extra) = &e.additional_property {
                return format!(
                    "\"{}\" is not a member of this request. The operation's schema in the OpenAPI document \
                     lists what is.",
                    extra
                );
            }
            if where_.is_empty() {
                format!("the request {}.", e.message)
            } else {
                format!("\"{}\" {}.", where_, e.message)
            }
        })
        .collect();
    if out.is_empty() {
        vec!["The request body did not match this operation's schema."
            .to_string()]
    } else {
        out
    }
}

/// `checkRequestBody()`: the body, `action` taken out, against the
/// operation's schema. `None` where it fits or the operation has none.
#[tracing::instrument(level = "debug", skip_all)]
pub fn check_body(row: &'static OperationRow, body: &Json) -> Option<Refused> {
    if crate::tables::row(row.id).is_some_and(|r| r.handler_owns_body) {
        return None;
    }
    let compiled = compiled(row)?;
    let validator = compiled.validator.as_ref()?;
    let mut subject = match body {
        Json::Object(m) => m.clone(),
        _ => Map::new(),
    };
    subject.shift_remove("action");
    let subject = Json::Object(subject);
    if validator.is_valid(&subject) {
        return None;
    }
    let components = structured_components(row.kind);
    let errors = Walker::new(&components).errors(&compiled.schema, &subject);
    Some(Refused {
        status: 400,
        code: codes::STS_API_0009,
        errors: sentences(&errors),
    })
}
