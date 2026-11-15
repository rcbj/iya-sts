// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE CERTIFICATE-ENROLLMENT MODEL, AS THE THREE FAMILIES READ IT
//! (`common/enrollment_model.ts`, #1579).
//!
//! `generated/enrollment.json` is the very file the image build writes into
//! `models/generated/` (`tests/tools/regenerate-model-docs.sh` copies it
//! here; `tests/model_domain.js` holds the copy to the model). Node builds a
//! zod validator from each `@body` and quotes zod's FIRST issue in a
//! refusal's sentence, so what [`Body::check`] answers is that issue as
//! zod 4 words it — path and message — for the shapes the model uses:
//! strings with their bounds and pattern, integers, booleans, literals,
//! enums, `any`, arrays and objects (strict, loose or stripping), and the
//! `opt()` form (absent or `''` accepted) of a query parameter. The issue
//! ORDER is zod's: an object's members in the shape's order, an array's
//! elements before its size, an object's unknown keys after its members.
//!
//! The registers, the operations and the answers' closed member lists are
//! read from the same file ([`rows`], [`names`], [`operations`],
//! [`undeclared`]).

use std::sync::LazyLock;

use serde_json::{Map, Value as Json};

static MODEL: LazyLock<Json> = LazyLock::new(|| {
    serde_json::from_str(include_str!("generated/enrollment.json"))
        .unwrap_or(Json::Null)
});

fn list<'a>(v: &'a Json, key: &str) -> &'a [Json] {
    v.get(key)
        .and_then(Json::as_array)
        .map_or(&[], |a| a.as_slice())
}

fn text<'a>(v: &'a Json, key: &str) -> &'a str {
    v.get(key).and_then(Json::as_str).unwrap_or("")
}

/// One issue, as zod reports it: where, what, and whether the value was
/// missing (`validation.js`'s `fromZod()` says "is required" for that).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub path: Vec<String>,
    pub message: String,
    /// `invalid_type` with an undefined input.
    pub missing: bool,
    /// A pattern check's, which does not abort a union branch.
    pub refinement: bool,
}

/// A `@body` of the model, by family and id.
#[derive(Debug, Clone)]
pub struct Body {
    spec: Json,
}

/// The type zod says it received.
fn received(v: Option<&Json>) -> &'static str {
    match v {
        None => "undefined",
        Some(Json::Null) => "null",
        Some(Json::String(_)) => "string",
        Some(Json::Number(_)) => "number",
        Some(Json::Bool(_)) => "boolean",
        Some(Json::Array(_)) => "array",
        Some(Json::Object(_)) => "object",
    }
}

fn number_text(n: &Json) -> String {
    match n.as_f64() {
        Some(f) if f.fract() == 0.0 && f.abs() < 1e15 => {
            format!("{}", f as i64)
        }
        Some(f) => format!("{}", f),
        None => n.to_string(),
    }
}

fn invalid_type(path: &[String], expected: &str, got: Option<&Json>) -> Issue {
    Issue {
        path: path.to_vec(),
        message: format!(
            "Invalid input: expected {}, received {}",
            expected,
            received(got)
        ),
        missing: got.is_none(),
        refinement: false,
    }
}

fn issue(path: &[String], message: String) -> Issue {
    Issue {
        path: path.to_vec(),
        message,
        missing: false,
        refinement: false,
    }
}

/// The length JavaScript gives a string: UTF-16 code units.
fn js_length(s: &str) -> usize {
    s.encode_utf16().count()
}

fn check_field(
    field: &Json,
    value: Option<&Json>,
    path: &[String],
    query: bool,
    out: &mut Vec<Issue>,
) {
    match text(field, "json") {
        "string" => {
            let Some(Json::String(s)) = value else {
                out.push(invalid_type(path, "string", value));
                return;
            };
            let n = js_length(s);
            if let Some(min) = field.get("minLength") {
                if (n as f64) < min.as_f64().unwrap_or(0.0) {
                    out.push(issue(
                        path,
                        format!(
                            "Too small: expected string to have >={} characters",
                            number_text(min)
                        ),
                    ));
                }
            }
            if let Some(max) = field.get("maxLength") {
                if (n as f64) > max.as_f64().unwrap_or(f64::MAX) {
                    out.push(issue(
                        path,
                        format!(
                            "Too big: expected string to have <={} characters",
                            number_text(max)
                        ),
                    ));
                }
            }
            if let Some(pattern) = field.get("pattern").and_then(Json::as_str) {
                let matched = regex::Regex::new(pattern)
                    .map(|re| re.is_match(s))
                    .unwrap_or(false);
                if !matched {
                    let message = field
                        .get("patternMessage")
                        .and_then(Json::as_str)
                        .map(str::to_string)
                        .unwrap_or_else(|| {
                            format!(
                                "Invalid string: must match pattern /{}/",
                                pattern
                            )
                        });
                    out.push(Issue {
                        path: path.to_vec(),
                        message,
                        missing: false,
                        refinement: true,
                    });
                }
            }
        }
        "integer" => {
            // A query's integer is `z.coerce.number().int()`: the text is
            // read as a number first.
            let coerced;
            let value = if query {
                coerced = value.map(|v| match v {
                    Json::String(s) => s
                        .trim()
                        .parse::<f64>()
                        .ok()
                        .or_else(|| s.trim().is_empty().then_some(0.0))
                        .and_then(serde_json::Number::from_f64)
                        .map(Json::Number)
                        .unwrap_or(Json::Null),
                    other => other.clone(),
                });
                coerced.as_ref()
            } else {
                value
            };
            let Some(Json::Number(n)) = value else {
                if query && value == Some(&Json::Null) {
                    out.push(issue(
                        path,
                        "Invalid input: expected number, received NaN"
                            .to_string(),
                    ));
                } else {
                    out.push(invalid_type(path, "number", value));
                }
                return;
            };
            let f = n.as_f64().unwrap_or(0.0);
            if f.fract() != 0.0 {
                out.push(issue(
                    path,
                    "Invalid input: expected int, received number".to_string(),
                ));
            }
            if let Some(min) = field.get("minimum") {
                if f < min.as_f64().unwrap_or(f64::MIN) {
                    out.push(issue(
                        path,
                        format!(
                            "Too small: expected number to be >={}",
                            number_text(min)
                        ),
                    ));
                }
            }
            if let Some(max) = field.get("maximum") {
                if f > max.as_f64().unwrap_or(f64::MAX) {
                    out.push(issue(
                        path,
                        format!(
                            "Too big: expected number to be <={}",
                            number_text(max)
                        ),
                    ));
                }
            }
        }
        "boolean" => {
            if !matches!(value, Some(Json::Bool(_))) {
                out.push(invalid_type(path, "boolean", value));
            }
        }
        "any" => {}
        "literal" => {
            let wanted = field.get("value").cloned().unwrap_or(Json::Null);
            if value != Some(&wanted) {
                out.push(Issue {
                    path: path.to_vec(),
                    message: format!("Invalid input: expected {}", wanted),
                    missing: false,
                    refinement: false,
                });
            }
        }
        "enum" => {
            let values: Vec<&str> = list(field, "values")
                .iter()
                .filter_map(Json::as_str)
                .collect();
            let ok = matches!(value, Some(Json::String(s))
                if values.contains(&s.as_str()));
            if !ok {
                out.push(issue(
                    path,
                    format!(
                        "Invalid option: expected one of {}",
                        values
                            .iter()
                            .map(|v| format!("\"{}\"", v))
                            .collect::<Vec<_>>()
                            .join("|")
                    ),
                ));
            }
        }
        "array" => {
            let Some(Json::Array(items)) = value else {
                out.push(invalid_type(path, "array", value));
                return;
            };
            let item_spec = field.get("items").cloned().unwrap_or(Json::Null);
            for (i, item) in items.iter().enumerate() {
                let mut at = path.to_vec();
                at.push(i.to_string());
                check_field(&item_spec, Some(item), &at, query, out);
            }
            if let Some(min) = field.get("minItems") {
                if (items.len() as f64) < min.as_f64().unwrap_or(0.0) {
                    out.push(issue(
                        path,
                        format!(
                            "Too small: expected array to have >={} items",
                            number_text(min)
                        ),
                    ));
                }
            }
            if let Some(max) = field.get("maxItems") {
                if (items.len() as f64) > max.as_f64().unwrap_or(f64::MAX) {
                    out.push(issue(
                        path,
                        format!(
                            "Too big: expected array to have <={} items",
                            number_text(max)
                        ),
                    ));
                }
            }
        }
        "object" => {
            let shape = field.get("shape").cloned().unwrap_or(Json::Null);
            check_object(
                text(&shape, "others"),
                list(&shape, "fields"),
                value,
                path,
                query,
                out,
            );
        }
        _ => out.push(issue(path, "Invalid input".to_string())),
    }
}

/// Whether an issue is a refinement's, which does not abort zod's parse:
/// a size, a bound, a pattern.
fn refinement(message: &str) -> bool {
    message.starts_with("Too small:")
        || message.starts_with("Too big:")
        || message.starts_with("Invalid string:")
}

fn check_object(
    others: &str,
    fields: &[Json],
    value: Option<&Json>,
    path: &[String],
    query: bool,
    out: &mut Vec<Issue>,
) {
    let Some(Json::Object(obj)) = value else {
        out.push(invalid_type(path, "object", value));
        return;
    };
    for field in fields {
        let name = text(field, "name");
        let mut at = path.to_vec();
        at.push(name.to_string());
        let member = obj.get(name);
        let empty = field.get("empty").and_then(Json::as_bool) == Some(true);
        let required =
            field.get("required").and_then(Json::as_bool) == Some(true);
        if member.is_none() && (empty || !required) {
            continue;
        }
        if empty && member == Some(&Json::String(String::new())) {
            continue;
        }
        if empty {
            // `opt()`: a union of `''` and the type; a value neither is is
            // zod's union refusal.
            //
            // zod 4's union reports the ONE branch that did not abort: the
            // `''` literal always aborts on another value, so a value of
            // the right type that fails only a refinement (`'0'` under a
            // minimum of 1) is that refinement's issue, and a value of the
            // wrong type (`'x'`, NaN) aborts both branches and is the
            // union's own "Invalid input". A type issue aborts; a size or
            // pattern check does not.
            let mut inner = Vec::new();
            check_field(field, member, &at, query, &mut inner);
            if inner.is_empty() {
                continue;
            }
            if inner.iter().all(|i| i.refinement || refinement(&i.message)) {
                out.extend(inner);
            } else {
                out.push(issue(&at, "Invalid input".to_string()));
            }
            continue;
        }
        check_field(field, member, &at, query, out);
    }
    if others == "strict" {
        let known: Vec<&str> = fields.iter().map(|f| text(f, "name")).collect();
        let unknown: Vec<&String> = obj
            .keys()
            .filter(|k| !known.contains(&k.as_str()))
            .collect();
        if !unknown.is_empty() {
            let names = unknown
                .iter()
                .map(|k| format!("\"{}\"", k))
                .collect::<Vec<_>>()
                .join(", ");
            out.push(issue(
                path,
                format!(
                    "Unrecognized key{}: {}",
                    if unknown.len() == 1 { "" } else { "s" },
                    names
                ),
            ));
        }
    }
}

impl Body {
    /// `EnrollmentModel.body(family, id)`; `None` for a body the model
    /// does not have.
    #[tracing::instrument(level = "debug")]
    pub fn of(family: &str, id: &str) -> Option<Body> {
        list(&MODEL, "bodies")
            .iter()
            .find(|b| text(b, "family") == family && text(b, "id") == id)
            .map(|spec| Body { spec: spec.clone() })
    }

    /// `safeParse()`: the first issue, or the value as zod hands it back
    /// (a stripping or loose object keeps what it keeps; only a strip
    /// object loses its unknown members).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn check(&self, value: &Json) -> Result<Json, Issue> {
        let query = text(&self.spec, "input") == "query";
        let mut issues = Vec::new();
        check_object(
            text(&self.spec, "others"),
            list(&self.spec, "fields"),
            Some(value),
            &[],
            query,
            &mut issues,
        );
        if let Some(first) = issues.into_iter().next() {
            return Err(first);
        }
        let mut out = value.clone();
        if query {
            // `z.coerce.number().int()` hands back the NUMBER: a page of
            // `'2'` is parsed as `2`, and `''` (the `opt()` side of the
            // union) stays the empty text.
            if let Json::Object(o) = &mut out {
                for f in list(&self.spec, "fields") {
                    if text(f, "json") != "integer" {
                        continue;
                    }
                    let Some(Json::String(s)) = o.get(text(f, "name")) else {
                        continue;
                    };
                    if s.is_empty() {
                        continue;
                    }
                    if let Ok(n) = s.trim().parse::<i64>() {
                        o.insert(text(f, "name").to_string(), Json::from(n));
                    }
                }
            }
        }
        if text(&self.spec, "others") == "strip" {
            if let Json::Object(o) = &mut out {
                let known: Vec<String> = list(&self.spec, "fields")
                    .iter()
                    .map(|f| text(f, "name").to_string())
                    .collect();
                o.retain(|k, _| known.contains(k));
            }
        }
        Ok(out)
    }

    /// The members' names, in the model's order.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn field_names(&self) -> Vec<String> {
        list(&self.spec, "fields")
            .iter()
            .map(|f| text(f, "name").to_string())
            .collect()
    }
}

/// `EnrollmentModel.rows(family, id)`.
#[tracing::instrument(level = "debug")]
pub fn rows(family: &str, id: &str) -> Vec<Json> {
    list(&MODEL, "registers")
        .iter()
        .find(|r| text(r, "family") == family && text(r, "id") == id)
        .map(|r| list(r, "rows").to_vec())
        .unwrap_or_default()
}

/// `EnrollmentModel.names(family, id)`.
#[tracing::instrument(level = "debug")]
pub fn names(family: &str, id: &str) -> Vec<String> {
    rows(family, id)
        .iter()
        .map(|r| text(r, "name").to_string())
        .collect()
}

/// `EnrollmentModel.map(family, id)`: name to value.
#[tracing::instrument(level = "debug")]
pub fn value_of(family: &str, id: &str, name: &str) -> String {
    rows(family, id)
        .iter()
        .find(|r| text(r, "name") == name)
        .map(|r| text(r, "value").to_string())
        .unwrap_or_default()
}

/// `EnrollmentModel.map(family, id, true)`: code to name.
#[tracing::instrument(level = "debug")]
pub fn name_of_code(family: &str, id: &str, code: i64) -> Option<String> {
    rows(family, id)
        .iter()
        .find(|r| r.get("code").and_then(Json::as_i64) == Some(code))
        .map(|r| text(r, "name").to_string())
}

/// One operation of a family: its name, path (ACME) and methods.
#[derive(Debug, Clone)]
pub struct Operation {
    pub name: String,
    pub path: String,
    pub methods: Vec<String>,
}

/// `EnrollmentModel.operations(family)`.
#[tracing::instrument(level = "debug")]
pub fn operations(family: &str) -> Vec<Operation> {
    list(&MODEL, "operations")
        .iter()
        .find(|o| text(o, "family") == family)
        .map(|o| {
            list(o, "list")
                .iter()
                .map(|op| Operation {
                    name: text(op, "name").to_string(),
                    path: text(op, "path").to_string(),
                    methods: list(op, "methods")
                        .iter()
                        .filter_map(Json::as_str)
                        .map(str::to_string)
                        .collect(),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn fits(value: &Json, types: &[Json]) -> bool {
    types.iter().filter_map(Json::as_str).any(|t| match t {
        "any" => true,
        "array" => value.is_array(),
        "object" => value.is_object(),
        "integer" => value.as_f64().is_some_and(|f| f.fract() == 0.0),
        "number" => value.is_number(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        _ => false,
    })
}

fn types_text(types: &[Json]) -> String {
    types
        .iter()
        .filter_map(Json::as_str)
        .collect::<Vec<_>>()
        .join(" or ")
}

fn walk(
    at: &str,
    members: &[Json],
    closed: bool,
    value: &Map<String, Json>,
    problems: &mut Vec<String>,
) {
    for (key, one) in value {
        let Some(member) = members.iter().find(|m| text(m, "name") == key)
        else {
            if closed {
                problems.push(format!("{}.{} is not a member", at, key));
            }
            continue;
        };
        let types = list(member, "types");
        if !fits(one, types) {
            problems.push(format!(
                "{}.{} is not {}",
                at,
                key,
                types_text(types)
            ));
            continue;
        }
        if let Some(values) = member.get("values").and_then(Json::as_array) {
            if !values.contains(one) {
                let shown: String = match one {
                    Json::String(s) => s.chars().take(64).collect(),
                    other => other.to_string(),
                };
                problems.push(format!(
                    "{}.{} is \"{}\", not one of {}",
                    at,
                    key,
                    shown,
                    values
                        .iter()
                        .map(|v| v
                            .as_str()
                            .map_or(v.to_string(), str::to_string))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
        if let (Some(vt), Some(obj)) = (
            member.get("valueTypes").and_then(Json::as_array),
            one.as_object(),
        ) {
            for (inner, v) in obj {
                if !fits(v, vt) {
                    problems.push(format!(
                        "{}.{}.{} is not {}",
                        at,
                        key,
                        inner,
                        types_text(vt)
                    ));
                }
            }
        }
        let items: Vec<(String, &Json)> = match one {
            Json::Array(a) => a
                .iter()
                .enumerate()
                .map(|(i, v)| (format!("{}.{}.{}", at, key, i), v))
                .collect(),
            other => vec![(format!("{}.{}", at, key), other)],
        };
        for (where_, item) in items {
            if let (Some(item_types), true) =
                (member.get("items").and_then(Json::as_array), one.is_array())
            {
                if !fits(item, item_types) {
                    problems.push(format!(
                        "{} is not {}",
                        where_,
                        types_text(item_types)
                    ));
                    continue;
                }
            }
            if let (Some(shape), Some(obj)) =
                (member.get("shape"), item.as_object())
            {
                walk(
                    &where_,
                    list(shape, "list"),
                    text(shape, "members") == "closed",
                    obj,
                    problems,
                );
            }
        }
    }
    for member in members {
        if member.get("required").and_then(Json::as_bool) == Some(true)
            && !value.contains_key(text(member, "name"))
        {
            problems.push(format!(
                "{}.{} is required",
                at,
                text(member, "name")
            ));
        }
    }
}

/// `EnrollmentModel.undeclared(family, id, value)`: what an answer carries
/// that its closed model does not allow. Empty for an answer the model
/// does not name, which `held()`'s callers never ask about.
#[tracing::instrument(level = "debug", skip(value))]
pub fn undeclared(family: &str, id: &str, value: &Json) -> Vec<String> {
    let Some(answer) = list(&MODEL, "answers")
        .iter()
        .find(|a| text(a, "family") == family && text(a, "id") == id)
    else {
        return Vec::new();
    };
    let mut problems = Vec::new();
    if let Some(obj) = value.as_object() {
        walk(
            id,
            list(answer, "list"),
            text(answer, "members") == "closed",
            obj,
            &mut problems,
        );
    }
    problems
}

/// `EnrollmentModel.unknownTerm(family, id, name)`.
#[tracing::instrument(level = "debug")]
pub fn unknown_term(family: &str, id: &str, name: &str) -> bool {
    !names(family, id).iter().any(|n| n == name)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)] // tests

    use serde_json::json;

    use super::*;

    fn first(family: &str, id: &str, v: Json) -> String {
        let issue = Body::of(family, id).unwrap().check(&v).unwrap_err();
        format!("{}: {}", issue.path.join("."), issue.message)
    }

    #[test]
    fn zods_first_issue_as_the_snapshot_records_it() {
        assert_eq!(
            first("acme", "new-account", json!({ "contact": "x" })),
            "contact: Invalid input: expected array, received string"
        );
        assert_eq!(
            first("acme", "new-account", json!({ "contact": [""] })),
            "contact.0: Too small: expected string to have >=1 characters"
        );
        assert_eq!(
            first(
                "acme",
                "new-order",
                json!({ "identifiers": [{ "type": "dns", "value": "a",
                                          "extra": 1 }] })
            ),
            "identifiers.0: Unrecognized key: \"extra\""
        );
        assert_eq!(
            first(
                "acme",
                "revoke",
                json!({ "certificate": "x", "reason": 1.5 })
            ),
            "reason: Invalid input: expected int, received number"
        );
        assert_eq!(
            first("est", "nonce-request", json!({ "len": 7 })),
            "len: Too small: expected number to be >=8"
        );
        assert_eq!(
            first("scep", "query", json!({})),
            "operation: Invalid option: expected one of \
             \"GetCACaps\"|\"GetCACert\"|\"GetNextCACert\"|\"PKIOperation\""
        );
        assert_eq!(
            Body::of("scep", "query")
                .unwrap()
                .check(&json!({ "operation": "GetCACaps", "x": "1" }))
                .unwrap(),
            json!({ "operation": "GetCACaps" })
        );
        assert_eq!(names("acme", "account-algorithms").len(), 10);
        assert_eq!(operations("est").len(), 7);
    }
}
