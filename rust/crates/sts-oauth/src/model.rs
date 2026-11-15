// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The OAuth 2.0 and OpenID Connect model as the endpoints read it
//! (`oauth-oidc/oauth_model.ts`): every endpoint's request validator, built
//! from `models/generated/oauth.json` — the same generated file Node reads,
//! copied here by `tests/tools/regenerate-model-docs.sh` — and checked the
//! way `common/validation.js` checks a request, so that a refusal reads
//! word for word as Node's.
//!
//! `validation.check()` is two steps, ported as they are:
//!
//! 1. `flatten()`: every parameter, in the order the request carried them,
//!    is one string — a parameter given twice is `repeated`, a structure is
//!    `structured`, a control character is refused (a line break is allowed
//!    in a body) and a polluting name is refused everywhere; a parameter
//!    the model declares repeatable is a list of strings;
//! 2. the zod object the model's `@param`s generate (`OAuthModel.request()`),
//!    whose first issue, in the declared order, is the refusal — with zod
//!    4's messages (`Too small: expected string to have >=43 characters`,
//!    `Invalid string: must match pattern /…/`, a shared type's own
//!    sentence). An `empty` parameter is `opt()`, a union with `''`: a
//!    value that fails the inner type's TYPE is `Invalid input`, one that
//!    passes it and fails a bound is that bound's message.
//!
//! A pass-through endpoint (the authorization and token requests) keeps
//! the parameters it does not declare; the others drop them.

use std::sync::LazyLock;

use serde_json::{Map, Value as Json};

static MODEL: LazyLock<Json> = LazyLock::new(|| {
    serde_json::from_str(include_str!("generated/oauth.json"))
        .unwrap_or(Json::Null)
});

/// The model, as generated.
#[tracing::instrument(level = "debug", skip_all)]
pub fn model() -> &'static Json {
    &MODEL
}

/// `validation.CAP`.
fn cap(name: &str) -> usize {
    match name {
        "IDENTIFIER" | "NAME" => 256,
        "TOKEN" | "DEFAULT" => 4096,
        "URI" | "SCOPE" => 2048,
        "TEXT" => 65536,
        "LARGE" => 1_048_576,
        _ => 4096,
    }
}

const POLLUTING_KEYS: [&str; 3] = ["__proto__", "constructor", "prototype"];

/// Why a request does not validate: `{ ok: false, code, field, detail }`
/// — a verdict, not a refusal: the endpoint that asked records the code.
#[derive(Debug, Clone, PartialEq)]
pub struct Invalid {
    pub code: &'static str,
    pub field: String,
    pub detail: String,
}

/// `refusal()`.
fn refusal(code: &'static str, field: &str, detail: String) -> Invalid {
    Invalid {
        code,
        field: field.to_string(),
        detail,
    }
}

/// `scalar()`: one value as text, or why it is refused.
fn scalar(
    value: &Json,
    field: &str,
    allow_text: bool,
) -> Result<Option<String>, Invalid> {
    match value {
        Json::Null => Ok(None),
        Json::Array(list) => Err(refusal(
            "repeated",
            field,
            format!(
                "the parameter \"{}\" was given {} times and this endpoint \
                 takes it once. It is refused rather than resolved to one of \
                 them, because choosing silently is how two readers of the \
                 same request come to disagree.",
                field,
                list.len()
            ),
        )),
        Json::Object(_) => Err(refusal(
            "structured",
            field,
            format!(
                "the parameter \"{}\" arrived as a structure rather than a \
                 value. Express parses \"{}[key]=...\" into an object; this \
                 endpoint takes a single value.",
                field, field
            ),
        )),
        other => {
            let text = match other {
                Json::String(s) => s.clone(),
                o => crate::js::string_of(Some(o)),
            };
            let forbidden = text.chars().any(|c| {
                let n = c as u32;
                if allow_text {
                    (n <= 0x08)
                        || n == 0x0B
                        || n == 0x0C
                        || (0x0E..=0x1F).contains(&n)
                        || n == 0x7F
                } else {
                    n <= 0x1F || n == 0x7F
                }
            });
            if forbidden {
                return Err(refusal(
                    "control-character",
                    field,
                    format!(
                        "the value of \"{}\" contains a control character. {}",
                        field,
                        if allow_text {
                            "A line break is allowed in this field; the \
                             other control characters are not."
                        } else {
                            "A carriage return or newline here would reach a \
                             response header, a log line or a directory \
                             query as a second instruction rather than as \
                             text."
                        }
                    ),
                ));
            }
            Ok(Some(text))
        }
    }
}

fn js_len(text: &str) -> usize {
    text.encode_utf16().count()
}

/// `validation.redirectUriProblem()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn redirect_uri_problem(text: &str, private_use: bool) -> Option<String> {
    if text.is_empty() {
        return Some("is empty".into());
    }
    if js_len(text) > cap("URI") {
        return Some(format!("is longer than {} characters", cap("URI")));
    }
    if text.contains('#') {
        return Some(
            "must not contain a fragment (RFC 6749 section 3.1.2)".into(),
        );
    }
    let Ok(parsed) = url::Url::parse(text) else {
        return Some("is not an absolute URI".into());
    };
    let scheme = parsed.scheme().to_ascii_lowercase();
    if scheme == "http" || scheme == "https" {
        let after = &text[scheme.len()..];
        let has_host_text = after.starts_with("://")
            && after.len() > 3
            && !after[3..].starts_with('/');
        if !has_host_text || parsed.host_str().is_none_or(str::is_empty) {
            return Some(format!("is an {} URL with no host", scheme));
        }
        return None;
    }
    let private = {
        let mut parts = scheme.split('.');
        let first = parts.next().unwrap_or("");
        let rest: Vec<&str> = parts.collect();
        first.chars().next().is_some_and(|c| c.is_ascii_lowercase())
            && first.chars().all(|c| {
                c.is_ascii_lowercase()
                    || c.is_ascii_digit()
                    || c == '+'
                    || c == '-'
            })
            && !rest.is_empty()
            && rest.iter().all(|p| {
                !p.is_empty()
                    && p.chars().all(|c| {
                        c.is_ascii_lowercase()
                            || c.is_ascii_digit()
                            || c == '+'
                            || c == '-'
                    })
            })
    };
    if private_use && private {
        return None;
    }
    Some(if private_use {
        format!(
            "must be an http or https URL, or a native application's \
             private-use scheme named for a domain in reverse order, such \
             as com.example.app:/callback (RFC 8252 section 7.1; a scheme \
             with no period, like \"{}:\", is refused)",
            scheme
        )
    } else {
        "must be an http or https URL".into()
    })
}

/// `validation.isPrivateUseRedirect()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn is_private_use_redirect(value: &str) -> bool {
    match url::Url::parse(value) {
        Ok(u) => u.scheme() != "http" && u.scheme() != "https",
        Err(_) => false,
    }
}

const DANGEROUS_SCHEMES: [&str; 5] =
    ["javascript", "data", "vbscript", "file", "blob"];

/// One issue zod would report, and whether it aborts (fails the type).
struct Issue {
    message: String,
    aborts: bool,
}

fn too_small(n: usize) -> Issue {
    Issue {
        message: format!(
            "Too small: expected string to have >={} characters",
            n
        ),
        aborts: false,
    }
}

fn too_big(n: usize) -> Issue {
    Issue {
        message: format!("Too big: expected string to have <={} characters", n),
        aborts: false,
    }
}

fn custom(message: &str) -> Issue {
    Issue {
        message: message.to_string(),
        aborts: false,
    }
}

fn matches(pattern: &str, text: &str) -> bool {
    regex::Regex::new(pattern).is_ok_and(|re| re.is_match(text))
}

/// The first issue of one value under a parameter's inner type.
fn first_issue(param: &Json, text: &str) -> Option<Issue> {
    let kind = param.get("kind").and_then(Json::as_str).unwrap_or("string");
    let len = js_len(text);
    let bounded = |min: usize, max: usize| -> Option<Issue> {
        if len < min {
            return Some(too_small(min));
        }
        if len > max {
            return Some(too_big(max));
        }
        None
    };
    match kind {
        "identifier" => bounded(1, 256).or_else(|| {
            (!matches(r"^[\x21-\x7E]+$", text))
                .then(|| custom("must be printable ASCII with no spaces"))
        }),
        "name" => bounded(1, 256),
        "opaque" => bounded(1, 4096),
        "base64url" => bounded(1, 4096).or_else(|| {
            (!matches(r"^[A-Za-z0-9_-]+$", text))
                .then(|| custom("must be base64url with no padding"))
        }),
        "scope" => {
            if len > 2048 {
                return Some(too_big(2048));
            }
            (!matches(
                r"^[\x21\x23-\x5B\x5D-\x7E]+(?: +[\x21\x23-\x5B\x5D-\x7E]+)*$",
                text,
            ))
            .then(|| {
                custom(
                    "must be a space-delimited scope list (RFC 6749 section \
                     3.3)",
                )
            })
        }
        "uri" => bounded(1, 2048).or_else(|| {
            let ok = url::Url::parse(text).is_ok_and(|u| {
                !DANGEROUS_SCHEMES
                    .contains(&u.scheme().to_ascii_lowercase().as_str())
            });
            (!ok).then(|| {
                custom(
                    "must be an absolute URI with a scheme that is not \
                     executable",
                )
            })
        }),
        "redirectUri" => bounded(1, 2048)
            .or_else(|| redirect_uri_problem(text, true).map(|p| custom(&p))),
        "integer" => {
            let n = crate::js::to_number(&Json::from(text));
            if n.is_nan() {
                return Some(Issue {
                    message: "Invalid input: expected number, received NaN"
                        .into(),
                    aborts: true,
                });
            }
            if n.fract() != 0.0 || n.is_infinite() {
                return Some(Issue {
                    message: "Invalid input: expected int, received number"
                        .into(),
                    aborts: true,
                });
            }
            let min = param.get("minimum").and_then(Json::as_f64);
            let max = param.get("maximum").and_then(Json::as_f64);
            if let Some(m) = min.filter(|m| n < *m) {
                return Some(custom(&format!(
                    "Too small: expected number to be >={}",
                    m as i64
                )));
            }
            if let Some(m) = max.filter(|m| n > *m) {
                return Some(custom(&format!(
                    "Too big: expected number to be <={}",
                    m as i64
                )));
            }
            None
        }
        _ => {
            let get = |k: &str| param.get(k).and_then(Json::as_u64);
            if let Some(m) = get("minLength").filter(|m| (len as u64) < *m) {
                return Some(too_small(m as usize));
            }
            if let Some(m) = get("maxLength").filter(|m| (len as u64) > *m) {
                return Some(too_big(m as usize));
            }
            if let Some(c) = param.get("cap").and_then(Json::as_str) {
                if len > cap(c) {
                    return Some(too_big(cap(c)));
                }
            }
            if let Some(p) = param.get("pattern").and_then(Json::as_str) {
                if !matches(p, text) {
                    return Some(custom(&format!(
                        "Invalid string: must match pattern /{}/",
                        p
                    )));
                }
            }
            None
        }
    }
}

/// The value the zod type produces: a number for an integer.
fn parsed_value(param: &Json, text: &str) -> Json {
    if param.get("kind").and_then(Json::as_str) == Some("integer")
        && !text.is_empty()
    {
        let n = crate::js::to_number(&Json::from(text));
        return serde_json::Number::from_f64(n)
            .map(|v| {
                if n.fract() == 0.0 && n.abs() < 9.0e15 {
                    Json::from(n as i64)
                } else {
                    Json::Number(v)
                }
            })
            .unwrap_or(Json::Null);
    }
    Json::from(text)
}

/// One value checked as the parameter's whole type: `opt()` when `empty`.
fn check_value(param: &Json, text: &str) -> Result<Json, String> {
    let empty = param.get("empty").and_then(Json::as_bool).unwrap_or(false);
    if empty && text.is_empty() {
        return Ok(Json::from(""));
    }
    match first_issue(param, text) {
        None => Ok(parsed_value(param, text)),
        Some(issue) if empty && issue.aborts => Err("Invalid input".into()),
        Some(issue) => Err(issue.message),
    }
}

/// `validation.check()` / `checkParsed()` against the model's endpoint
/// `id`: the parameters as the endpoint reads them, or the refusal.
#[tracing::instrument(level = "debug", skip(input))]
pub fn check(
    id: &str,
    input: &Map<String, Json>,
    where_: &str,
) -> Result<Map<String, Json>, Invalid> {
    let allow_text = where_ == "body";
    let endpoint = MODEL
        .get("endpoints")
        .and_then(Json::as_array)
        .and_then(|list| {
            list.iter()
                .find(|e| e.get("id").and_then(Json::as_str) == Some(id))
        })
        .cloned()
        .unwrap_or(Json::Null);
    let params: Vec<Json> = endpoint
        .get("params")
        .and_then(Json::as_array)
        .cloned()
        .unwrap_or_default();
    let declared = |name: &str| {
        params
            .iter()
            .find(|p| p.get("name").and_then(Json::as_str) == Some(name))
    };
    let mut flat: Map<String, Json> = Map::new();
    for (key, value) in input {
        if POLLUTING_KEYS.contains(&key.as_str()) {
            tracing::warn!(
                "validation: a request carried the parameter \"{}\", which \
                 is refused everywhere in this service.",
                key
            );
            return Err(refusal(
                "polluting-key",
                key,
                format!(
                    "the parameter name \"{}\" is refused. It is a property \
                     of every object in javascript, and a request that sets \
                     it is not asking for anything this service offers.",
                    key
                ),
            ));
        }
        let repeats = declared(key)
            .and_then(|p| p.get("repeatable").and_then(Json::as_bool))
            .unwrap_or(false);
        if repeats {
            let list = match value {
                Json::Array(l) => l.clone(),
                other => vec![other.clone()],
            };
            let mut cleaned = Vec::new();
            for one in &list {
                if let Some(text) = scalar(one, key, allow_text)? {
                    cleaned.push(Json::from(text));
                }
            }
            flat.insert(key.clone(), Json::Array(cleaned));
            continue;
        }
        if let Some(text) = scalar(value, key, allow_text)? {
            flat.insert(key.clone(), Json::from(text));
        }
    }
    let pass_through = endpoint
        .get("passThrough")
        .and_then(Json::as_bool)
        .unwrap_or(false);
    let mut out: Map<String, Json> = Map::new();
    if pass_through {
        out = flat.clone();
    }
    for param in &params {
        let name = param.get("name").and_then(Json::as_str).unwrap_or("");
        let required = param
            .get("required")
            .and_then(Json::as_bool)
            .unwrap_or(false);
        let repeatable = param
            .get("repeatable")
            .and_then(Json::as_bool)
            .unwrap_or(false);
        let Some(value) = flat.get(name) else {
            if required {
                return Err(refusal(
                    "missing",
                    name,
                    format!(
                        "the {} parameter \"{}\" is required.",
                        where_, name
                    ),
                ));
            }
            continue;
        };
        let invalid = |field: &str, message: String| {
            refusal(
                "invalid",
                field,
                format!(
                    "the {} parameter \"{}\" is not acceptable: {}.",
                    where_, field, message
                ),
            )
        };
        if repeatable {
            let mut kept = Vec::new();
            for (i, one) in value.as_array().into_iter().flatten().enumerate() {
                let text = one.as_str().unwrap_or("");
                match check_value(param, text) {
                    Ok(v) => kept.push(v),
                    Err(m) => return Err(invalid(&i.to_string(), m)),
                }
            }
            out.insert(name.to_string(), Json::Array(kept));
        } else {
            let text = value.as_str().unwrap_or("");
            match check_value(param, text) {
                Ok(v) => {
                    out.insert(name.to_string(), v);
                }
                Err(m) => return Err(invalid(name, m)),
            }
        }
    }
    Ok(out)
}

/// `OAuthModel.unknownError()`: an error code the model does not declare.
#[tracing::instrument(level = "debug", skip_all)]
pub fn unknown_error(code: &str) -> bool {
    !MODEL
        .get("errors")
        .and_then(Json::as_array)
        .into_iter()
        .flatten()
        .any(|one| one.get("code").and_then(Json::as_str) == Some(code))
}
