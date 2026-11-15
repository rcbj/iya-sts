// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What the Node kinds do to a value without saying so: `String(x)`,
//! `.trim()`, `.slice(0, n)` and an entry's attribute looked up by name.
//!
//! The kinds are written against loosely typed bodies and entries, and their
//! sentences quote what was sent (`"12.5" is not one`), so the port has to
//! turn a JSON value into text the way JavaScript does, or a refusal reads
//! differently. Every function here is called per field of every read and
//! save: a hot path, so they carry no span (the logging rule's exemption).

use serde_json::{Map, Value};

/// An entry's attributes or a request body, as Node holds them.
pub type Object = Map<String, Value>;

/// `String(value)` for a JSON value, with `undefined` and `null` as ''
/// where the Node code says `value === undefined || value === null ? '' :`.
/// An array is its elements joined by commas, each `null` as '' (what
/// `Array.prototype.join` does); an object is `[object Object]`.
pub fn text(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => number_text(n),
        Value::String(s) => s.clone(),
        Value::Array(items) => items.iter().map(text).collect::<Vec<_>>().join(","),
        Value::Object(_) => "[object Object]".to_string(),
    }
}

/// `String(n)` for a number: an integer without a point, anything else in
/// the shortest form that reads back, as JavaScript writes it.
pub fn number_text(n: &serde_json::Number) -> String {
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    let f = n.as_f64().unwrap_or(0.0);
    if f.fract() == 0.0 && f.abs() < 1e21 {
        return format!("{}", f as i64);
    }
    format!("{f}")
}

/// Whether a character is one `String.prototype.trim()` removes: the
/// ECMAScript WhiteSpace and LineTerminator sets, which differ from Rust's
/// `char::is_whitespace` (U+FEFF is trimmed there, U+0085 is not).
pub fn is_js_space(c: char) -> bool {
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
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
            | '\u{feff}'
    )
}

/// `text.trim()`.
pub fn trim(text: &str) -> &str {
    text.trim_matches(is_js_space)
}

/// `text.slice(0, n)`: the first `n` UTF-16 code units. A character a cut
/// would split is left out (JavaScript keeps its first half, a lone
/// surrogate no Rust string can hold).
pub fn slice(text: &str, n: usize) -> String {
    let mut used = 0;
    let mut out = String::new();
    for c in text.chars() {
        used += c.len_utf16();
        if used > n {
            break;
        }
        out.push(c);
    }
    out
}

/// `text.length`, in UTF-16 code units.
pub fn length(text: &str) -> usize {
    text.chars().map(char::len_utf16).sum()
}

/// `PolicySelection.fold()`: trimmed and lower-case; '' for nothing.
pub fn fold(value: &Value) -> String {
    trim(&text(value)).to_lowercase()
}

/// `fold()` of a string.
pub fn fold_str(value: &str) -> String {
    trim(value).to_lowercase()
}

/// The member an attribute is held under, whatever case the entry's keys
/// are in: the exact name first, as `valuesOf()` asks.
pub fn member<'a>(attributes: &'a Object, name: &str) -> Option<&'a Value> {
    if let Some(found) = attributes.get(name) {
        return Some(found);
    }
    let wanted = name.to_lowercase();
    attributes
        .iter()
        .find(|(k, _)| k.to_lowercase() == wanted)
        .map(|(_, v)| v)
}

/// `PolicySelection.valuesOf()`: every value of an attribute as strings,
/// empty ones dropped.
pub fn values_of(attributes: &Object, name: &str) -> Vec<String> {
    match member(attributes, name) {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| match v {
                Value::Null => "null".to_string(),
                other => text(other),
            })
            .filter(|s| !s.is_empty())
            .collect(),
        Some(one) => {
            let s = text(one);
            if s.is_empty() {
                Vec::new()
            } else {
                vec![s]
            }
        }
    }
}

/// `DomainMap.valuesOf()`: every value, `null` ones dropped and empty ones
/// kept, under a key matched in any case.
pub fn domain_values(attributes: &Object, name: &str) -> Vec<String> {
    let wanted = name.to_lowercase();
    let held = attributes
        .iter()
        .find(|(k, _)| k.to_lowercase() == wanted)
        .map(|(_, v)| v);
    match held {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .filter(|v| !v.is_null())
            .map(text)
            .collect(),
        Some(one) => vec![text(one)],
    }
}

/// A kind's `firstValue()`: the attribute under its own name or its
/// lower-cased one (no other spelling), its first value, or '' — as a JSON
/// value, so a caller can tell `""` from a value that is not a string.
pub fn first_value(attributes: &Object, name: &str) -> Value {
    let found = match attributes.get(name) {
        Some(v) => Some(v),
        None => attributes.get(&name.to_lowercase()),
    };
    match found {
        None | Some(Value::Null) => Value::String(String::new()),
        Some(Value::Array(items)) => items
            .first()
            .cloned()
            .unwrap_or(Value::String(String::new())),
        Some(one) => one.clone(),
    }
}

/// Whether a value is `''` as `raw === ''` asks.
pub fn is_empty_string(value: &Value) -> bool {
    matches!(value, Value::String(s) if s.is_empty())
}

/// JavaScript truthiness, for `x || y` over a body member.
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Value::String(s) => !s.is_empty(),
        _ => true,
    }
}

/// `String(x || '')` over a body member.
pub fn or_empty(value: Option<&Value>) -> String {
    match value {
        Some(v) if truthy(v) => text(v),
        _ => String::new(),
    }
}

/// `Number(text)` where the text is digits only: the value, or `None`.
pub fn digits(text: &str, max_len: usize) -> Option<i64> {
    if text.is_empty() || text.len() > max_len || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<i64>().ok()
}

/// A list of strings as a JSON array.
pub fn strings(list: &[String]) -> Value {
    Value::Array(list.iter().cloned().map(Value::String).collect())
}

/// A JSON object from pairs, in order.
pub fn object(pairs: Vec<(&str, Value)>) -> Value {
    let mut out = Map::new();
    for (k, v) in pairs {
        out.insert(k.to_string(), v);
    }
    Value::Object(out)
}

/// `String(x === undefined ? '' : x)` over a body member: `null` is the
/// text `null`, as JavaScript writes it.
pub fn string_of(value: Option<&Value>) -> String {
    match value {
        None => String::new(),
        Some(Value::Null) => "null".to_string(),
        Some(v) => text(v),
    }
}

/// `String(x === undefined || x === null ? '' : x)`.
pub fn string_or_empty(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => String::new(),
        Some(v) => text(v),
    }
}
