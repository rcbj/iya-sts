// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A request body held to its operation's schema, with Node's refusals
//! (`AdminApi.structureOnly()`, `checkRequestBody()`, `errorsFromAjv()`).
//!
//! **TWO HALVES.** The VERDICT is the `jsonschema` crate's, on the schema
//! as Node compiles it (`structureOnly()`: `required` taken out, `""` added
//! to every enum, the ±2^53−1 integer backstop of #1347), draft 7 as ajv's
//! default class is. The SENTENCES are ajv's: `allErrors` reports every
//! failing keyword, in the order ajv's compiled code meets them, and the
//! caller reads those words (`"name" must NOT have more than 64
//! characters.`). The crate's errors come in its own order and words, so
//! the sentences are made here by a walk in ajv's order — the untyped
//! keywords (`const`, `enum`, `not`, `anyOf`, `oneOf`, `allOf`), then the
//! number, string, array and object groups, each keyword in its
//! vocabulary's order — over the keywords the model's request schemas use.
//! Where the walk finds nothing for a body the crate refused, the caller
//! gets Node's generic sentence.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use regex::Regex;
use serde_json::{Map, Value as Json};

/// `Number.MAX_SAFE_INTEGER`.
const MAX_SAFE: i64 = 9_007_199_254_740_991;

/// `structureOnly()`: the copy ajv compiles.
#[tracing::instrument(level = "debug", skip_all)]
pub fn structure_only(node: &Json) -> Json {
    match node {
        Json::Array(list) => Json::Array(list.iter().map(structure_only).collect()),
        Json::Object(map) => {
            let refused = map.get("x-refused-by-handler") == Some(&Json::Bool(true));
            let mut out = Map::new();
            for (key, value) in map {
                if key == "required" {
                    continue;
                }
                if key == "enum" && refused {
                    continue;
                }
                if key == "enum" {
                    if let Json::Array(values) = value {
                        let mut values = values.clone();
                        if !values.contains(&Json::String(String::new())) {
                            values.push(Json::String(String::new()));
                        }
                        out.insert(key.clone(), Json::Array(values));
                        continue;
                    }
                }
                out.insert(key.clone(), structure_only(value));
            }
            let integer = match out.get("type") {
                Some(Json::String(t)) => t == "integer",
                Some(Json::Array(ts)) => ts.iter().any(|t| t == "integer"),
                _ => false,
            };
            if integer {
                if !out.get("maximum").is_some_and(Json::is_number) {
                    out.insert("maximum".into(), Json::from(MAX_SAFE));
                }
                if !out.get("minimum").is_some_and(Json::is_number) {
                    out.insert("minimum".into(), Json::from(-MAX_SAFE));
                }
            }
            Json::Object(out)
        }
        other => other.clone(),
    }
}

/// One error, as ajv reports it.
#[derive(Debug, Clone, PartialEq)]
pub struct AjvError {
    pub instance_path: String,
    pub keyword: &'static str,
    pub message: String,
    pub additional_property: Option<String>,
    /// The enum's values and the data, for the closed-set sentence.
    pub allowed: Option<Vec<Json>>,
    pub data: Json,
}

fn type_ok(t: &str, data: &Json) -> bool {
    match t {
        "string" => data.is_string(),
        "number" => data.is_number(),
        "integer" => match data {
            Json::Number(n) => {
                n.is_i64() || n.is_u64() || n.as_f64().is_some_and(|f| f.fract() == 0.0)
            }
            _ => false,
        },
        "boolean" => data.is_boolean(),
        "null" => data.is_null(),
        "array" => data.is_array(),
        "object" => data.is_object(),
        _ => true,
    }
}

const GROUP_KEYWORDS: &[(&str, &[&str])] = &[
    (
        "number",
        &["maximum", "minimum", "exclusiveMaximum", "exclusiveMinimum", "multipleOf"],
    ),
    ("string", &["maxLength", "minLength", "pattern", "format"]),
    (
        "array",
        &["maxItems", "minItems", "uniqueItems", "additionalItems", "items", "contains"],
    ),
    (
        "object",
        &[
            "maxProperties",
            "minProperties",
            "required",
            "propertyNames",
            "additionalProperties",
            "dependencies",
            "properties",
            "patternProperties",
        ],
    ),
];

fn number_text(v: &Json) -> String {
    match v {
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.to_string()
            } else if let Some(f) = n.as_f64() {
                if f.fract() == 0.0 && f.abs() < 1e21 {
                    format!("{}", f as i64)
                } else {
                    f.to_string()
                }
            } else {
                n.to_string()
            }
        }
        other => other.to_string(),
    }
}

static REGEXES: LazyLock<Mutex<HashMap<String, Option<Regex>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn pattern_matches(pattern: &str, text: &str) -> bool {
    let mut cache = match REGEXES.lock() {
        Ok(c) => c,
        Err(p) => p.into_inner(),
    };
    let re = cache
        .entry(pattern.to_string())
        .or_insert_with(|| Regex::new(pattern).ok());
    re.as_ref().is_none_or(|re| re.is_match(text))
}

/// ajv-formats' `uri` (full mode): `NOT_URI_FRAGMENT` and `URI`.
static URI: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)^(?:[a-z][a-z0-9+\-.]*:)(?:/?/(?:(?:[a-z0-9\-._~!$&'()*+,;=:]|%[0-9a-f]{2})*@)?",
        r"(?:\[(?:(?:(?:(?:[0-9a-f]{1,4}:){6}|::(?:[0-9a-f]{1,4}:){5}|(?:[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){4}",
        r"|(?:(?:[0-9a-f]{1,4}:){0,1}[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){3}",
        r"|(?:(?:[0-9a-f]{1,4}:){0,2}[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){2}",
        r"|(?:(?:[0-9a-f]{1,4}:){0,3}[0-9a-f]{1,4})?::[0-9a-f]{1,4}:",
        r"|(?:(?:[0-9a-f]{1,4}:){0,4}[0-9a-f]{1,4})?::)(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}",
        r"|(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))",
        r"|(?:(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4})?::[0-9a-f]{1,4}",
        r"|(?:(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4})?::)|[Vv][0-9a-f]+\.[a-z0-9\-._~!$&'()*+,;=:]+)\]",
        r"|(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)",
        r"|(?:[a-z0-9\-._~!$&'()*+,;=]|%[0-9a-f]{2})*)(?::\d*)?(?:/(?:[a-z0-9\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})*)*",
        r"|/(?:(?:[a-z0-9\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})+(?:/(?:[a-z0-9\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})*)*)?",
        r"|(?:[a-z0-9\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})+(?:/(?:[a-z0-9\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})*)*)",
        r"(?:\?(?:[a-z0-9\-._~!$&'()*+,;=:@/?]|%[0-9a-f]{2})*)?(?:#(?:[a-z0-9\-._~!$&'()*+,;=:@/?]|%[0-9a-f]{2})*)?$"
    ))
    .ok()
});

fn format_ok(format: &str, text: &str) -> bool {
    match format {
        "uri" => {
            (text.contains('/') || text.contains(':'))
                && URI.as_ref().is_none_or(|re| re.is_match(text))
        }
        // `binary` and every format the model's requests do not use are
        // ajv-formats' `true`, or unknown and so not checked.
        _ => true,
    }
}

/// The walk: ajv's errors for `data` against `schema`, in ajv's order.
pub struct Walker<'a> {
    components: &'a Json,
    errors: Vec<AjvError>,
}

impl<'a> Walker<'a> {
    /// A walk whose `$ref`s resolve in `components` (the document's
    /// `components`, already `structureOnly()`).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(components: &'a Json) -> Walker<'a> {
        Walker {
            components,
            errors: Vec::new(),
        }
    }

    /// Every error, in order.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn errors(mut self, schema: &Json, data: &Json) -> Vec<AjvError> {
        self.walk(schema, data, "", 0);
        self.errors
    }

    fn push(&mut self, path: &str, keyword: &'static str, message: String, data: &Json) {
        self.errors.push(AjvError {
            instance_path: path.to_string(),
            keyword,
            message,
            additional_property: None,
            allowed: None,
            data: data.clone(),
        });
    }

    fn resolve(&self, reference: &str) -> Option<&'a Json> {
        let name = reference.strip_prefix("#/components/schemas/")?;
        self.components.get("schemas")?.get(name)
    }

    fn walk(&mut self, schema: &Json, data: &Json, path: &str, depth: usize) {
        if depth > 64 {
            return;
        }
        let Some(s) = schema.as_object() else {
            if schema == &Json::Bool(false) {
                self.push(path, "false schema", "boolean schema is false".into(), data);
            }
            return;
        };
        if let Some(Json::String(reference)) = s.get("$ref") {
            if let Some(target) = self.resolve(reference) {
                self.walk(target, data, path, depth + 1);
            }
            return;
        }
        let types: Vec<String> = match s.get("type") {
            Some(Json::String(t)) => vec![t.clone()],
            Some(Json::Array(ts)) => ts.iter().filter_map(|t| t.as_str().map(String::from)).collect(),
            _ => Vec::new(),
        };
        // ajv's `schemaHasRulesForType()`: only the four group types have
        // rules; `integer`, `boolean` and `null` are `true` in its table.
        let has_rules_for = |t: &str| {
            GROUP_KEYWORDS
                .iter()
                .find(|(name, _)| *name == t)
                .is_some_and(|(_, kws)| kws.iter().any(|k| s.contains_key(*k)))
        };
        let type_error = || {
            format!("must be {}", types.join(","))
        };
        // coerceAndCheckDataType(): several types, or one type with no
        // rules of its own, is checked up front.
        let up_front = !types.is_empty() && !(types.len() == 1 && has_rules_for(&types[0]));
        if up_front && !types.iter().any(|t| type_ok(t, data)) {
            self.push(path, "type", type_error(), data);
        }
        // The untyped group.
        if let Some(c) = s.get("const") {
            if c != data {
                self.push(path, "const", "must be equal to constant".into(), data);
            }
        }
        if let Some(Json::Array(values)) = s.get("enum") {
            if !values.contains(data) {
                self.errors.push(AjvError {
                    instance_path: path.to_string(),
                    keyword: "enum",
                    message: "must be equal to one of the allowed values".into(),
                    additional_property: None,
                    allowed: Some(values.clone()),
                    data: data.clone(),
                });
            }
        }
        if let Some(not) = s.get("not") {
            let mut inner = Walker::new(self.components);
            inner.walk(not, data, path, depth + 1);
            if inner.errors.is_empty() {
                self.push(path, "not", "must NOT be valid".into(), data);
            }
        }
        for (keyword, message) in [
            ("anyOf", "must match a schema in anyOf"),
            ("oneOf", "must match exactly one schema in oneOf"),
        ] {
            let Some(Json::Array(branches)) = s.get(keyword) else {
                continue;
            };
            let mut collected = Vec::new();
            let mut passing = 0;
            for branch in branches {
                let mut inner = Walker::new(self.components);
                inner.walk(branch, data, path, depth + 1);
                if inner.errors.is_empty() {
                    passing += 1;
                    if keyword == "anyOf" {
                        break;
                    }
                } else {
                    collected.extend(inner.errors);
                }
            }
            let ok = if keyword == "anyOf" { passing > 0 } else { passing == 1 };
            if !ok {
                self.errors.extend(collected);
                self.push(
                    path,
                    if keyword == "anyOf" { "anyOf" } else { "oneOf" },
                    message.into(),
                    data,
                );
            }
        }
        if let Some(Json::Array(parts)) = s.get("allOf") {
            for part in parts {
                self.walk(part, data, path, depth + 1);
            }
        }
        // The typed groups, in RULES order.
        for (group, _) in GROUP_KEYWORDS {
            let applies = match *group {
                "number" => data.is_number(),
                "string" => data.is_string(),
                "array" => data.is_array(),
                "object" => data.is_object(),
                _ => false,
            };
            let single_typed = types.len() == 1 && types[0] == *group;
            if !applies {
                if single_typed && has_rules_for(group) {
                    self.push(path, "type", type_error(), data);
                }
                continue;
            }
            match *group {
                "number" => self.number_group(s, data, path),
                "string" => self.string_group(s, data, path),
                "array" => self.array_group(s, data, path, depth),
                _ => self.object_group(s, data, path, depth),
            }
        }
    }

    fn number_group(&mut self, s: &Map<String, Json>, data: &Json, path: &str) {
        let x = data.as_f64().unwrap_or(0.0);
        for (keyword, op) in [
            ("maximum", "<="),
            ("minimum", ">="),
            ("exclusiveMaximum", "<"),
            ("exclusiveMinimum", ">"),
        ] {
            let Some(limit) = s.get(keyword) else { continue };
            let Some(l) = limit.as_f64() else { continue };
            let ok = match op {
                "<=" => x <= l,
                ">=" => x >= l,
                "<" => x < l,
                _ => x > l,
            };
            if !ok {
                let kw: &'static str = match keyword {
                    "maximum" => "maximum",
                    "minimum" => "minimum",
                    "exclusiveMaximum" => "exclusiveMaximum",
                    _ => "exclusiveMinimum",
                };
                self.push(path, kw, format!("must be {} {}", op, number_text(limit)), data);
            }
        }
    }

    fn string_group(&mut self, s: &Map<String, Json>, data: &Json, path: &str) {
        let text = data.as_str().unwrap_or_default();
        let length = text.chars().count() as u64;
        if let Some(n) = s.get("maxLength").and_then(Json::as_u64) {
            if length > n {
                self.push(path, "maxLength", format!("must NOT have more than {} characters", n), data);
            }
        }
        if let Some(n) = s.get("minLength").and_then(Json::as_u64) {
            if length < n {
                self.push(path, "minLength", format!("must NOT have fewer than {} characters", n), data);
            }
        }
        if let Some(Json::String(p)) = s.get("pattern") {
            if !pattern_matches(p, text) {
                self.push(path, "pattern", format!("must match pattern \"{}\"", p), data);
            }
        }
        if let Some(Json::String(f)) = s.get("format") {
            if !format_ok(f, text) {
                self.push(path, "format", format!("must match format \"{}\"", f), data);
            }
        }
    }

    fn array_group(&mut self, s: &Map<String, Json>, data: &Json, path: &str, depth: usize) {
        let items = data.as_array().cloned().unwrap_or_default();
        if let Some(n) = s.get("maxItems").and_then(Json::as_u64) {
            if items.len() as u64 > n {
                self.push(path, "maxItems", format!("must NOT have more than {} items", n), data);
            }
        }
        if let Some(n) = s.get("minItems").and_then(Json::as_u64) {
            if (items.len() as u64) < n {
                self.push(path, "minItems", format!("must NOT have fewer than {} items", n), data);
            }
        }
        if let Some(schema) = s.get("items") {
            if schema.is_object() || schema.is_boolean() {
                for (i, item) in items.iter().enumerate() {
                    self.walk(schema, item, &format!("{}/{}", path, i), depth + 1);
                }
            }
        }
    }

    fn object_group(&mut self, s: &Map<String, Json>, data: &Json, path: &str, depth: usize) {
        let Some(object) = data.as_object() else { return };
        let properties = s.get("properties").and_then(Json::as_object);
        let patterns = s.get("patternProperties").and_then(Json::as_object);
        if let Some(extra) = s.get("additionalProperties") {
            for (key, value) in object {
                let named = properties.is_some_and(|p| p.contains_key(key));
                let patterned = patterns.is_some_and(|p| p.keys().any(|re| pattern_matches(re, key)));
                if named || patterned {
                    continue;
                }
                match extra {
                    Json::Bool(false) => self.errors.push(AjvError {
                        instance_path: path.to_string(),
                        keyword: "additionalProperties",
                        message: "must NOT have additional properties".into(),
                        additional_property: Some(key.clone()),
                        allowed: None,
                        data: data.clone(),
                    }),
                    Json::Object(_) => {
                        self.walk(extra, value, &format!("{}/{}", path, escape(key)), depth + 1);
                    }
                    _ => {}
                }
            }
        }
        if let Some(properties) = properties {
            for (key, schema) in properties {
                if let Some(value) = object.get(key) {
                    self.walk(schema, value, &format!("{}/{}", path, escape(key)), depth + 1);
                }
            }
        }
        if let Some(patterns) = patterns {
            for (re, schema) in patterns {
                for (key, value) in object {
                    if pattern_matches(re, key) {
                        self.walk(schema, value, &format!("{}/{}", path, escape(key)), depth + 1);
                    }
                }
            }
        }
    }
}

fn escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}
