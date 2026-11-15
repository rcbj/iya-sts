// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A REQUEST'S BODY OR QUERY HELD TO ITS OPERATION'S MODEL, WITH NODE'S
//! REFUSALS: `common/validation.js`'s `checkParsed()` over the zod schema
//! `common/model_zod.ts` builds from the document (`ModelZod.body()`,
//! `ModelZod.query()`).
//!
//! **TWO STEPS, AS NODE TAKES THEM.**
//!
//! 1. `flatten()`: every member a scalar (an array only where the schema
//!    declares one), no polluting key, no control character (a line break
//!    is allowed in a body), and every scalar TURNED INTO A STRING — so a
//!    JSON `5` is the text `"5"` by the time the schema sees it, which is
//!    why no type error is ever said of a scalar here.
//! 2. The schema, and the FIRST issue zod v4 reports, in its words
//!    (`fromZod()`): the shape's members in declaration order, then the
//!    keys a strict object does not name. A union (`anyOf`) answers the
//!    one option that failed only on its checks (`too_big`, `too_small`,
//!    `invalid_format` — zod's non-aborting issues), and `Invalid input`
//!    where none or several did. A member missing where it is required and
//!    typed `string` is "required"; one whose schema is a literal or an
//!    enum is said as zod says it (`Invalid option: …`).
//!
//! The keywords handled are the ones the model's request bodies and
//! queries use (`type`, `properties`, `required`, `additionalProperties`,
//! `anyOf`, `const`, `enum`, `minLength`, `maxLength`, `pattern`, `items`,
//! `maxItems`); `tests/node_vectors.rs` holds the sentences to Node's.

use indexmap::IndexMap;
use regex::Regex;
use serde_json::{Map, Value as Json};

/// `validation.js`'s refusal: `code`, the field and the sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: &'static str,
    pub field: String,
    pub detail: String,
}

const POLLUTING: &[&str] = &["__proto__", "constructor", "prototype"];

/// `CONTROL_STRICT` (`[\x00-\x1F\x7F]`) and `CONTROL_TEXT`, which lets a
/// tab, a line feed and a carriage return through.
fn has_control(text: &str, allow_text: bool) -> bool {
    text.chars().any(|c| {
        let n = c as u32;
        if allow_text && (n == 0x09 || n == 0x0A || n == 0x0D) {
            return false;
        }
        n <= 0x1F || n == 0x7F
    })
}

/// `String(value)` of a JSON scalar.
fn text_of(value: &Json) -> String {
    match value {
        Json::String(s) => s.clone(),
        Json::Bool(b) => b.to_string(),
        Json::Number(n) => {
            let f = n.as_f64().unwrap_or(0.0);
            if f.fract() == 0.0 && f.abs() < 1e21 {
                format!("{}", f as i64)
            } else {
                n.to_string()
            }
        }
        _ => String::new(),
    }
}

/// `scalar()`.
fn scalar(
    value: &Json,
    field: &str,
    allow_text: bool,
) -> Result<Option<String>, Refusal> {
    match value {
        Json::Null => Ok(None),
        Json::Array(list) => Err(Refusal {
            code: "repeated",
            field: field.into(),
            detail: format!(
                "the parameter \"{}\" was given {} times and this endpoint \
                 takes it once. It is refused rather than resolved to one of \
                 them, because choosing silently is how two readers of the \
                 same request come to disagree.",
                field,
                list.len()
            ),
        }),
        Json::Object(_) => Err(Refusal {
            code: "structured",
            field: field.into(),
            detail: format!(
                "the parameter \"{}\" arrived as a structure rather than a \
                 value. Express parses \"{}[key]=...\" into an object; this \
                 endpoint takes a single value.",
                field, field
            ),
        }),
        other => {
            let text = text_of(other);
            if has_control(&text, allow_text) {
                return Err(Refusal {
                    code: "control-character",
                    field: field.into(),
                    detail: format!(
                        "the value of \"{}\" contains a control character. {}",
                        field,
                        if allow_text {
                            "A line break is allowed in this field; the \
                             other control characters are not."
                        } else {
                            "A carriage return or newline here would reach \
                             a response header, a log line or a directory \
                             query as a second instruction rather than as \
                             text."
                        }
                    ),
                });
            }
            Ok(Some(text))
        }
    }
}

fn is_array_schema(schema: &Json) -> bool {
    if schema.get("type").and_then(Json::as_str) == Some("array") {
        return true;
    }
    for k in ["anyOf", "oneOf"] {
        if let Some(list) = schema.get(k).and_then(Json::as_array) {
            if list.iter().any(is_array_schema) {
                return true;
            }
        }
    }
    false
}

/// `flatten()`: the members as strings (or lists of strings), in arrival
/// order.
fn flatten(
    input: &Json,
    properties: Option<&Map<String, Json>>,
    allow_text: bool,
) -> Result<IndexMap<String, Json>, Refusal> {
    let mut out = IndexMap::new();
    let Some(source) = input.as_object() else {
        return Ok(out);
    };
    for (key, value) in source {
        if POLLUTING.contains(&key.as_str()) {
            tracing::warn!(
                "validation: a request carried the parameter \"{}\", which \
                 is refused everywhere in this service.",
                key
            );
            return Err(Refusal {
                code: "polluting-key",
                field: key.clone(),
                detail: format!(
                    "the parameter name \"{}\" is refused. It is a property \
                     of every object in javascript, and a request that sets \
                     it is not asking for anything this service offers.",
                    key
                ),
            });
        }
        let repeats = properties
            .and_then(|p| p.get(key))
            .is_some_and(is_array_schema);
        if repeats {
            let list: Vec<Json> = match value {
                Json::Array(l) => l.clone(),
                one => vec![one.clone()],
            };
            let mut cleaned = Vec::new();
            for one in &list {
                if let Some(t) = scalar(one, key, allow_text)? {
                    cleaned.push(Json::String(t));
                }
            }
            out.insert(key.clone(), Json::Array(cleaned));
            continue;
        }
        if let Some(t) = scalar(value, key, allow_text)? {
            out.insert(key.clone(), Json::String(t));
        }
    }
    Ok(out)
}

/// One zod issue: its code, the member it is at (none for the object) and
/// zod's message.
#[derive(Debug, Clone)]
struct Issue {
    code: &'static str,
    path: Option<String>,
    message: String,
    /// `invalid_type` of an absent value.
    missing: bool,
    /// A check's issue, which does not abort (`continue: true`).
    continues: bool,
}

/// JavaScript's `String(regex)` of the pattern: `/source/`.
fn shown_pattern(pattern: &str) -> String {
    format!("/{}/", pattern.replace('/', "\\/"))
}

fn length(text: &str) -> usize {
    text.encode_utf16().count()
}

/// The issues of a string schema (`stringOf()`), for a present value.
fn string_issues(schema: &Json, value: &str, at: &str) -> Vec<Issue> {
    let issue = |code, message: String, continues| Issue {
        code,
        path: Some(at.to_string()),
        message,
        missing: false,
        continues,
    };
    if let Some(c) = schema.get("const") {
        return if c.as_str() == Some(value) {
            Vec::new()
        } else {
            vec![issue(
                "invalid_value",
                format!(
                    "Invalid input: expected {}",
                    serde_json::to_string(c).unwrap_or_default()
                ),
                false,
            )]
        };
    }
    if let Some(values) = schema.get("enum").and_then(Json::as_array) {
        let allowed: Vec<&Json> =
            values.iter().filter(|v| !v.is_null()).collect();
        return if allowed.iter().any(|v| v.as_str() == Some(value)) {
            Vec::new()
        } else {
            vec![issue(
                "invalid_value",
                format!(
                    "Invalid option: expected one of {}",
                    allowed
                        .iter()
                        .map(|v| serde_json::to_string(v).unwrap_or_default())
                        .collect::<Vec<_>>()
                        .join("|")
                ),
                false,
            )]
        };
    }
    let mut out = Vec::new();
    let n = length(value);
    if let Some(min) = schema.get("minLength").and_then(Json::as_u64) {
        if (n as u64) < min {
            out.push(issue(
                "too_small",
                format!(
                    "Too small: expected string to have >={} characters",
                    min
                ),
                true,
            ));
        }
    }
    if let Some(max) = schema.get("maxLength").and_then(Json::as_u64) {
        if (n as u64) > max {
            out.push(issue(
                "too_big",
                format!(
                    "Too big: expected string to have <={} characters",
                    max
                ),
                true,
            ));
        }
    }
    if let Some(p) = schema.get("pattern").and_then(Json::as_str) {
        let fits = Regex::new(p).map(|r| r.is_match(value)).unwrap_or(true);
        if !fits {
            // A pattern with a message of its own (`vt.base64url`'s) says
            // that, as zod's `regex(pattern, message)` does.
            let message = schema
                .get("x-message")
                .and_then(Json::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| {
                    format!(
                        "Invalid string: must match pattern {}",
                        shown_pattern(p)
                    )
                });
            out.push(issue("invalid_format", message, true));
        }
    }
    out
}

/// The issues of one member's schema for its (flattened) value.
fn member_issues(schema: &Json, value: Option<&Json>, at: &str) -> Vec<Issue> {
    if let Some(options) = schema.get("anyOf").and_then(Json::as_array) {
        let Some(value) = value else {
            return Vec::new();
        };
        let mut results = Vec::new();
        for option in options {
            let found = member_issues(option, Some(value), at);
            if found.is_empty() {
                return Vec::new();
            }
            results.push(found);
        }
        let continuing: Vec<&Vec<Issue>> = results
            .iter()
            .filter(|r| r.iter().all(|i| i.continues))
            .collect();
        if continuing.len() == 1 {
            return continuing[0].clone();
        }
        return vec![Issue {
            code: "invalid_union",
            path: Some(at.to_string()),
            message: "Invalid input".into(),
            missing: false,
            continues: false,
        }];
    }
    let kind = schema.get("type").and_then(Json::as_str).unwrap_or("");
    match (kind, value) {
        ("array", Some(Json::Array(list))) => {
            let mut out = Vec::new();
            if let Some(max) = schema.get("maxItems").and_then(Json::as_u64) {
                if list.len() as u64 > max {
                    out.push(Issue {
                        code: "too_big",
                        path: Some(at.to_string()),
                        message: format!(
                            "Too big: expected array to have <={} items",
                            max
                        ),
                        missing: false,
                        continues: true,
                    });
                }
            }
            if let Some(items) = schema.get("items") {
                for (i, one) in list.iter().enumerate() {
                    let mut found =
                        member_issues(items, Some(one), &i.to_string());
                    out.append(&mut found);
                }
            }
            out
        }
        (_, Some(Json::String(text))) => string_issues(schema, text, at),
        (_, Some(_)) => vec![Issue {
            code: "invalid_type",
            path: Some(at.to_string()),
            message: format!(
                "Invalid input: expected {}, received array",
                kind
            ),
            missing: false,
            continues: false,
        }],
        (_, None) => {
            // A required member that is absent. A literal or an enum says
            // so in its own words, a string as an invalid type.
            if schema.get("const").is_some() || schema.get("enum").is_some() {
                string_issues(schema, "\u{0}\u{0}absent", at)
                    .into_iter()
                    .map(|mut i| {
                        i.continues = false;
                        i
                    })
                    .collect()
            } else {
                vec![Issue {
                    code: "invalid_type",
                    path: Some(at.to_string()),
                    message: format!(
                        "Invalid input: expected {}, received undefined",
                        if kind.is_empty() { "string" } else { kind }
                    ),
                    missing: true,
                    continues: false,
                }]
            }
        }
    }
}

/// The first issue of an object schema over the flattened members.
fn first_issue(
    schema: &Json,
    members: &IndexMap<String, Json>,
) -> Option<Issue> {
    let empty = Map::new();
    let properties = schema
        .get("properties")
        .and_then(Json::as_object)
        .unwrap_or(&empty);
    let required: Vec<&str> = schema
        .get("required")
        .and_then(Json::as_array)
        .map(|r| r.iter().filter_map(Json::as_str).collect())
        .unwrap_or_default();
    for (name, member) in properties {
        let value = members.get(name);
        if value.is_none() && !required.contains(&name.as_str()) {
            continue;
        }
        if let Some(first) =
            member_issues(member, value, name).into_iter().next()
        {
            return Some(first);
        }
    }
    let patterns: Vec<(Regex, &Json)> = schema
        .get("patternProperties")
        .and_then(Json::as_object)
        .map(|p| {
            p.iter()
                .filter_map(|(k, v)| Regex::new(k).ok().map(|r| (r, v)))
                .collect()
        })
        .unwrap_or_default();
    if schema.get("additionalProperties") == Some(&Json::Bool(false)) {
        let unknown: Vec<&String> = members
            .keys()
            .filter(|k| !properties.contains_key(*k))
            .filter(|k| !patterns.iter().any(|(r, _)| r.is_match(k)))
            .collect();
        if !unknown.is_empty() {
            let named = unknown
                .iter()
                .map(|k| serde_json::to_string(k).unwrap_or_default())
                .collect::<Vec<_>>()
                .join(", ");
            return Some(Issue {
                code: "unrecognized_keys",
                path: None,
                message: if unknown.len() == 1 {
                    format!("Unrecognized key: {}", named)
                } else {
                    format!("Unrecognized keys: {}", named)
                },
                missing: false,
                continues: false,
            });
        }
    }
    None
}

/// `checkParsed(value, where, schema)`: the members as the schema keeps
/// them (`parsed.data`: strings, the ones it names), or the refusal.
#[tracing::instrument(level = "debug", skip_all, fields(where_ = where_))]
pub fn check_parsed(
    value: &Json,
    where_: &str,
    schema: &Json,
) -> Result<Map<String, Json>, Refusal> {
    let properties = schema.get("properties").and_then(Json::as_object);
    let members = flatten(value, properties, where_ == "body")?;
    if let Some(issue) = first_issue(schema, &members) {
        let field = issue.path.clone().unwrap_or_else(|| "(request)".into());
        let missing = issue.missing && issue.code == "invalid_type";
        return Err(Refusal {
            code: if missing { "missing" } else { "invalid" },
            field: field.clone(),
            detail: if missing {
                format!("the {} parameter \"{}\" is required.", where_, field)
            } else {
                format!(
                    "the {} parameter \"{}\" is not acceptable: {}.",
                    where_, field, issue.message
                )
            },
        });
    }
    // zod's strict object keeps what it names; the patterned one keeps
    // what a pattern names too; a plain object drops the rest.
    let mut out = Map::new();
    let empty = Map::new();
    let named = properties.unwrap_or(&empty);
    for (k, v) in members {
        if named.contains_key(&k) || schema.get("patternProperties").is_some() {
            out.insert(k, v);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)] // tests

    use serde_json::json;

    use super::*;

    fn schema() -> Json {
        json!({ "type": "object", "additionalProperties": false,
          "required": ["kind"],
          "properties": {
            "username": { "anyOf": [{ "type": "string", "const": "" },
              { "type": "string", "minLength": 1, "maxLength": 256 }] },
            "use": { "anyOf": [{ "type": "string", "const": "" },
              { "type": "string", "enum": ["0", "1"] }] },
            "fp": { "type": "string", "maxLength": 4,
                    "pattern": "^[A-Za-z0-9]*$" },
            "kind": { "type": "string", "enum": ["code", "link"] } } })
    }

    fn said(v: Json) -> String {
        check_parsed(&v, "body", &schema())
            .err()
            .map(|r| r.detail)
            .unwrap()
    }

    #[test]
    fn the_sentences_are_zods_through_fromzod() {
        assert_eq!(
            said(json!({})),
            "the body parameter \"kind\" is not acceptable: Invalid option: \
             expected one of \"code\"|\"link\"."
        );
        assert_eq!(
            said(json!({ "kind": "code", "zzz": 1, "aaa": 2 })),
            "the body parameter \"(request)\" is not acceptable: \
             Unrecognized keys: \"zzz\", \"aaa\"."
        );
        assert_eq!(
            said(json!({ "kind": "code", "username": "x".repeat(300) })),
            "the body parameter \"username\" is not acceptable: Too big: \
             expected string to have <=256 characters."
        );
        assert_eq!(
            said(json!({ "kind": "code", "use": "2" })),
            "the body parameter \"use\" is not acceptable: Invalid input."
        );
        assert_eq!(
            said(json!({ "kind": "code", "fp": "ab-" })),
            "the body parameter \"fp\" is not acceptable: Invalid string: \
             must match pattern /^[A-Za-z0-9]*$/."
        );
        // A number is a string by the time the schema sees it.
        assert!(check_parsed(
            &json!({ "kind": "code", "username": 5 }),
            "body",
            &schema()
        )
        .is_ok());
        assert!(said(json!({ "kind": "code", "username": {} }))
            .contains("arrived as a structure"));
    }
}
