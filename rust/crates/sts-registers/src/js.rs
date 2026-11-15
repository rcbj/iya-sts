// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The few JavaScript coercions the Node registers lean on, so that a
//! sentence built from a value reads as Node's does: `String(x)`, `x || ''`,
//! truthiness, and `String.prototype.localeCompare`'s order.
//!
//! Each is a hot path — called for every comparison and coercion — and
//! carries no span.

use serde_json::Value;
use std::cmp::Ordering;

/// `String(value)`, as JavaScript writes a JSON value.
pub fn string(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => number(n),
        Value::String(s) => s.clone(),
        Value::Array(list) => list
            .iter()
            .map(|one| match one {
                Value::Null => String::new(),
                other => string(other),
            })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".to_string(),
    }
}

fn number(n: &serde_json::Number) -> String {
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    if let Some(f) = n.as_f64() {
        if f.fract() == 0.0 && f.abs() < 1e21 {
            return format!("{f:.0}");
        }
        return f.to_string();
    }
    n.to_string()
}

/// JavaScript truthiness of a JSON value.
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// `String(x || '')` for an optional member.
pub fn or_empty(value: Option<&Value>) -> String {
    match value {
        Some(v) if truthy(v) => string(v),
        _ => String::new(),
    }
}

/// `String(x == null ? '' : x)` for an optional member.
pub fn unless_null(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => String::new(),
        Some(v) => string(v),
    }
}

/// `(x || []).map(String)`: a member that is a list of anything.
pub fn strings(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(list)) => list.iter().map(string).collect(),
        Some(v) if truthy(v) => {
            // A string is iterable in JavaScript, but Node's callers never
            // pass one where a list belongs; treat it as one value.
            vec![string(v)]
        }
        _ => Vec::new(),
    }
}

/// JavaScript's `\s` (ASCII whitespace and the Unicode spaces).
pub fn is_space(c: char) -> bool {
    c.is_whitespace() || c == '\u{feff}'
}

/// `String.prototype.trim()`.
pub fn trim(text: &str) -> &str {
    text.trim_matches(is_space)
}

/// `text.split(/<chars>+/).filter(Boolean)` for a set of separators.
pub fn split_on(text: &str, separator: impl Fn(char) -> bool) -> Vec<String> {
    text.split(separator)
        .filter(|one| !one.is_empty())
        .map(str::to_string)
        .collect()
}

/// JavaScript's `toLowerCase()` (Unicode default case mapping).
pub fn lower(text: &str) -> String {
    text.to_lowercase()
}

// ---------------------------------------------------------------------------
// localeCompare. Node sorts role and application names with
// `a.localeCompare(b)`, which is ICU's root collation: letters compared
// without case first (primary), and only when every character ties does
// case decide, lower before upper (tertiary). Punctuation and symbols are
// not ignorable and sort before digits, which sort before letters, in
// DUCET's order. This reproduces that for ASCII exactly — every name the
// registers accept is ASCII (`checkName`'s pattern) — and orders anything
// else after the letters by code point, which is where ICU puts most
// scripts relative to Latin.
// ---------------------------------------------------------------------------

const PUNCTUATION: &str = "\t\n\u{b}\u{c}\r _-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$";

fn primary(c: char) -> (u32, u32) {
    if let Some(at) = PUNCTUATION.find(c) {
        return (0, at as u32);
    }
    if c.is_ascii_digit() {
        return (1, c as u32);
    }
    if c.is_ascii_alphabetic() {
        return (2, c.to_ascii_lowercase() as u32);
    }
    let folded = c.to_lowercase().next().unwrap_or(c);
    (3, folded as u32)
}

fn tertiary(c: char) -> u32 {
    u32::from(c.is_uppercase())
}

/// `a.localeCompare(b)` as an `Ordering`.
pub fn locale_compare(a: &str, b: &str) -> Ordering {
    let pa: Vec<(u32, u32)> = a.chars().map(primary).collect();
    let pb: Vec<(u32, u32)> = b.chars().map(primary).collect();
    match pa.cmp(&pb) {
        Ordering::Equal => {}
        other => return other,
    }
    let ta: Vec<u32> = a.chars().map(tertiary).collect();
    let tb: Vec<u32> = b.chars().map(tertiary).collect();
    ta.cmp(&tb)
}

/// The numbers `helpers.numberWord()` spells.
const NUMBER_WORDS: [&str; 16] = [
    "zero", "one", "two", "three", "four", "five", "six", "seven", "eight",
    "nine", "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen",
];

/// `helpers.numberWord(count)`: a small count as a word.
pub fn number_word(count: usize) -> String {
    NUMBER_WORDS
        .get(count)
        .map(|w| (*w).to_string())
        .unwrap_or_else(|| count.to_string())
}

/// `text.slice(0, n)` in UTF-16 code units, as JavaScript cuts a string.
pub fn slice_utf16(text: &str, n: usize) -> String {
    let mut units = 0;
    let mut out = String::new();
    for c in text.chars() {
        units += c.len_utf16();
        if units > n {
            break;
        }
        out.push(c);
    }
    out
}

/// The length of a string as JavaScript counts it.
pub fn len_utf16(text: &str) -> usize {
    text.chars().map(char::len_utf16).sum()
}
