// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The handful of JavaScript conversions the Node credential modules lean
//! on, written once so that each port reads as its Node line does:
//! `String(x)`, `Number(x)`, truthiness, and `numberOr()`. A setting read
//! through `config.value()` arrives as JSON (a number, a string, a boolean,
//! a list), and Node converts it at the call site, so the conversion is the
//! behaviour and has to be the same one.
//!
//! Every function here is a hot path (called per field of a verdict), so
//! none carries a span: the logging rule's stated exemption.

use serde_json::{Map, Value as Json};

/// A JSON object, as the verdicts are built.
pub type Object = Map<String, Json>;

/// `String(x)` for a JSON value (`null` is JavaScript's `undefined` as
/// often as its `null`, so callers that care write `x == null ? '' : x`).
pub fn string(value: &Json) -> String {
    match value {
        Json::Null => "null".to_string(),
        Json::Bool(b) => b.to_string(),
        Json::String(s) => s.clone(),
        Json::Number(n) => number_text(n.as_f64().unwrap_or(f64::NAN)),
        Json::Array(list) => list
            .iter()
            .map(|v| match v {
                Json::Null => String::new(),
                other => string(other),
            })
            .collect::<Vec<_>>()
            .join(","),
        Json::Object(_) => "[object Object]".to_string(),
    }
}

/// `String(x == null ? '' : x)` — and `String(x || '')` for a value that is
/// never `0` or `false`.
pub fn string_or_empty(value: Option<&Json>) -> String {
    match value {
        None | Some(Json::Null) => String::new(),
        Some(v) => string(v),
    }
}

/// `String(x || '')`.
pub fn string_or(value: Option<&Json>, fallback: &str) -> String {
    match value {
        Some(v) if truthy(v) => string(v),
        _ => fallback.to_string(),
    }
}

/// How JavaScript prints a number.
pub fn number_text(n: f64) -> String {
    if n.is_nan() {
        "NaN".to_string()
    } else if n.is_infinite() {
        if n > 0.0 {
            "Infinity".to_string()
        } else {
            "-Infinity".to_string()
        }
    } else if n == n.trunc() && n.abs() < 1e21 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

/// JavaScript's whitespace, as `trim()` and `Number()` strip it.
pub fn is_space(c: char) -> bool {
    matches!(
        c,
        '\u{9}'
            | '\u{a}'
            | '\u{b}'
            | '\u{c}'
            | '\u{d}'
            | ' '
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

/// `String.prototype.trim()`.
pub fn trim(text: &str) -> &str {
    text.trim_matches(is_space)
}

/// `Number(x)` of a string.
pub fn number_of_text(text: &str) -> f64 {
    let t = trim(text);
    if t.is_empty() {
        return 0.0;
    }
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return i64::from_str_radix(hex, 16).map_or(f64::NAN, |v| v as f64);
    }
    match t {
        "Infinity" | "+Infinity" => return f64::INFINITY,
        "-Infinity" => return f64::NEG_INFINITY,
        _ => {}
    }
    let ok = t.chars().all(|c| {
        c.is_ascii_digit() || matches!(c, '.' | 'e' | 'E' | '+' | '-')
    });
    if !ok {
        return f64::NAN;
    }
    t.parse::<f64>().unwrap_or(f64::NAN)
}

/// `Number(x)`.
pub fn number(value: &Json) -> f64 {
    match value {
        Json::Null => 0.0,
        Json::Bool(b) => f64::from(u8::from(*b)),
        Json::Number(n) => n.as_f64().unwrap_or(f64::NAN),
        Json::String(s) => number_of_text(s),
        Json::Array(list) => match list.as_slice() {
            [] => 0.0,
            [one] => number(one),
            _ => f64::NAN,
        },
        Json::Object(_) => f64::NAN,
    }
}

/// `Number(x)` of a member that may be absent (`undefined` is NaN).
pub fn number_opt(value: Option<&Json>) -> f64 {
    value.map_or(f64::NAN, number)
}

/// `Number(x || fallback)`.
pub fn number_or_fallback(value: Option<&Json>, fallback: f64) -> f64 {
    match value {
        Some(v) if truthy(v) => number(v),
        _ => fallback,
    }
}

/// The private `numberOr()` of `totp.ts` and `backup_codes.ts`: a legal
/// zero is kept, only an empty, absent or non-finite value falls back.
pub fn number_or(value: Option<&Json>, fallback: f64) -> f64 {
    let Some(v) = value else {
        return fallback;
    };
    if v.is_null() || v.as_str() == Some("") {
        return fallback;
    }
    let n = number(v);
    if n.is_finite() {
        n
    } else {
        fallback
    }
}

/// JavaScript truthiness.
pub fn truthy(value: &Json) -> bool {
    match value {
        Json::Null => false,
        Json::Bool(b) => *b,
        Json::Number(n) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Json::String(s) => !s.is_empty(),
        Json::Array(_) | Json::Object(_) => true,
    }
}

/// Truthiness of a member that may be absent.
pub fn truthy_opt(value: Option<&Json>) -> bool {
    value.is_some_and(truthy)
}

/// A JSON number from an f64, as `JSON.stringify` writes it: an integer
/// where it is one.
pub fn num(n: f64) -> Json {
    if n.is_finite() && n == n.trunc() && n.abs() < 9.0e15 {
        Json::from(n as i64)
    } else if n.is_finite() {
        serde_json::Number::from_f64(n).map_or(Json::Null, Json::Number)
    } else {
        Json::Null
    }
}

/// `{ a: 1, b: 2 }`, in the order written.
pub fn object(pairs: Vec<(&str, Json)>) -> Json {
    let mut out = Map::new();
    for (k, v) in pairs {
        out.insert(k.to_string(), v);
    }
    Json::Object(out)
}

/// A list of strings.
pub fn strings(list: &[String]) -> Json {
    Json::Array(list.iter().map(|s| Json::String(s.clone())).collect())
}

/// `/[\u0000-\u001f\u007f]/.test(text)`.
pub fn has_control(text: &str) -> bool {
    text.chars().any(|c| (c as u32) < 0x20 || c as u32 == 0x7f)
}

/// The `.replace(/[\s-]/g, '')` the code readers share: JavaScript's `\s`
/// and the dash.
pub fn without_spaces_and_dashes(text: &str) -> String {
    text.chars()
        .filter(|c| !is_space(*c) && *c != '-')
        .collect()
}

/// `toUpperCase()` as JavaScript does it for the strings these modules
/// see: the full Unicode mapping.
pub fn upper(text: &str) -> String {
    text.to_uppercase()
}

/// A JavaScript string's `length`: UTF-16 code units.
pub fn length(text: &str) -> usize {
    text.encode_utf16().count()
}
