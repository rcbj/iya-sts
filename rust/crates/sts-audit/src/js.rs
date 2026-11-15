// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What the audit log reads the way JavaScript does, because Node's rows
//! were written that way and Rust's must be the same bytes: a string's
//! LENGTH and a cut are in UTF-16 code units (`text.length`,
//! `text.slice()`), `String(value)` of any JSON value, JavaScript's
//! truthiness, `parseInt()`, and the order `Object.keys()` lists an
//! object's members in (array indices first, ascending, then the rest in
//! insertion order).
//!
//! A cut that falls between the two halves of a surrogate pair leaves a
//! lone surrogate in JavaScript, which a Rust `String` cannot hold; the
//! half pair is dropped here instead. No vector cuts one, and the
//! difference is one character of an over-long value that is already
//! marked as cut.

use serde_json::{Map, Value as Json};

/// `text.length`. A hot path (every field of every row): no span.
pub(crate) fn len16(text: &str) -> usize {
    text.encode_utf16().count()
}

/// `text.slice(0, n)`, in code units. A hot path: no span.
pub(crate) fn head16(text: &str, n: usize) -> String {
    let mut out = String::new();
    let mut used = 0;
    for c in text.chars() {
        let w = c.len_utf16();
        if used + w > n {
            break;
        }
        used += w;
        out.push(c);
    }
    out
}

/// `String(n)` for a number. A hot path: no span.
pub(crate) fn number_text(n: &serde_json::Number) -> String {
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    let f = n.as_f64().unwrap_or(0.0);
    if f.is_finite() && f.fract() == 0.0 && f.abs() < 1e21 {
        return format!("{:.0}", f);
    }
    format!("{}", f)
}

/// `String(value)`: `null` is `"null"`, an array its members joined with
/// commas (a `null` member empty), an object `[object Object]`. A hot
/// path: no span.
pub(crate) fn text_of(value: &Json) -> String {
    match value {
        Json::Null => "null".to_string(),
        Json::Bool(b) => b.to_string(),
        Json::Number(n) => number_text(n),
        Json::String(s) => s.clone(),
        Json::Array(items) => items
            .iter()
            .map(|one| match one {
                Json::Null => String::new(),
                other => text_of(other),
            })
            .collect::<Vec<_>>()
            .join(","),
        Json::Object(_) => "[object Object]".to_string(),
    }
}

/// `String(value == null ? '' : value)`, for a member that may be absent.
/// A hot path: no span.
pub(crate) fn text_or_empty(value: Option<&Json>) -> String {
    match value {
        None | Some(Json::Null) => String::new(),
        Some(v) => text_of(v),
    }
}

/// JavaScript's truthiness. A hot path: no span.
pub(crate) fn truthy(value: Option<&Json>) -> bool {
    match value {
        None | Some(Json::Null) => false,
        Some(Json::Bool(b)) => *b,
        Some(Json::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(Json::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// `value || ''` then `String()`: the member when truthy, else `''`. A
/// hot path: no span.
pub(crate) fn text_if_truthy(value: Option<&Json>) -> String {
    if truthy(value) {
        text_or_empty(value)
    } else {
        String::new()
    }
}

/// `parseInt(text, 10)`, or `None` for `NaN`. A hot path: no span.
pub(crate) fn parse_int(text: &str) -> Option<i64> {
    let t = text.trim_start();
    let (sign, rest) = match t.strip_prefix('-') {
        Some(r) => (-1, r),
        None => (1, t.strip_prefix('+').unwrap_or(t)),
    };
    let digits: String =
        rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse::<i64>().ok().map(|n| sign * n)
}

/// Whether a key is an array index, which `Object.keys()` lists first.
fn array_index(key: &str) -> Option<u32> {
    if key.is_empty() || (key.len() > 1 && key.starts_with('0')) {
        return None;
    }
    if !key.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    key.parse::<u32>().ok().filter(|n| *n != u32::MAX)
}

/// An object's keys in `Object.keys()` order. A hot path: no span.
pub(crate) fn keys_of(map: &Map<String, Json>) -> Vec<String> {
    let mut indices: Vec<(u32, String)> = Vec::new();
    let mut rest: Vec<String> = Vec::new();
    for key in map.keys() {
        match array_index(key) {
            Some(n) => indices.push((n, key.clone())),
            None => rest.push(key.clone()),
        }
    }
    indices.sort_by_key(|one| one.0);
    indices.into_iter().map(|one| one.1).chain(rest).collect()
}

/// `Object.keys(value)` of any value: an object's keys, an array's
/// indices, nothing for anything else (a string is handled by the
/// caller). A hot path: no span.
pub(crate) fn entries_of(value: &Json) -> Vec<(String, Json)> {
    match value {
        Json::Object(map) => keys_of(map)
            .into_iter()
            .map(|k| {
                let v = map.get(&k).cloned().unwrap_or(Json::Null);
                (k, v)
            })
            .collect(),
        Json::Array(items) => items
            .iter()
            .enumerate()
            .map(|(i, v)| (i.to_string(), v.clone()))
            .collect(),
        _ => Vec::new(),
    }
}

/// `new Date(at).toISOString()`. A hot path: no span.
pub(crate) fn iso(at: i64) -> String {
    match chrono::DateTime::<chrono::Utc>::from_timestamp_millis(at) {
        Some(when) => {
            when.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
        }
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn javascript_semantics() {
        assert_eq!(len16("é😀"), 3);
        assert_eq!(head16("ab😀c", 3), "ab");
        assert_eq!(text_of(&serde_json::json!([1, "two", null, [3, 4]])),
                   "1,two,,3,4");
        assert_eq!(parse_int(" 12abc"), Some(12));
        assert_eq!(parse_int("abc"), None);
        let map = serde_json::json!({"b": 1, "2": 2, "1": 1, "01": 0});
        let keys = keys_of(map.as_object().unwrap_or(&Map::new()));
        assert_eq!(keys, vec!["1", "2", "b", "01"]);
        assert_eq!(iso(1763100000000), "2025-11-14T06:00:00.000Z");
    }
}
