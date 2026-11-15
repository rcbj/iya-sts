// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What JavaScript's strings do that Rust's do not, where the mail channel's
//! answer depends on it: a length and a slice counted in UTF-16 code units
//! (`subject.length > 250`), `String(value)` of a JSON value, and `trim()`
//! (which also takes U+FEFF away). Every function here is a hot path of the
//! renderer and carries no span.

use serde_json::Value as Json;

/// `text.length`: UTF-16 code units. A hot path: no span.
pub fn len(text: &str) -> usize {
    text.encode_utf16().count()
}

/// `String(value)` for what a caller hands the renderer: a string as it
/// is, `null` as `'null'` (the renderer maps null to `''` itself), a number
/// as JavaScript writes it, an array joined by commas, an object as
/// `[object Object]`. A hot path: no span.
pub fn string_of(value: &Json) -> String {
    match value {
        Json::String(text) => text.clone(),
        Json::Null => "null".to_string(),
        Json::Bool(b) => b.to_string(),
        Json::Number(n) => number_text(n),
        Json::Array(items) => items
            .iter()
            .map(|one| match one {
                Json::Null => String::new(),
                other => string_of(other),
            })
            .collect::<Vec<_>>()
            .join(","),
        Json::Object(_) => "[object Object]".to_string(),
    }
}

/// A number as JavaScript's `String()` writes the ones JSON can carry:
/// an integer without a fraction, anything else in Rust's shortest form.
fn number_text(n: &serde_json::Number) -> String {
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
    format!("{}", f)
}

/// `String(value == null ? '' : value)`. A hot path: no span.
pub fn text_or_empty(value: Option<&Json>) -> String {
    match value {
        None | Some(Json::Null) => String::new(),
        Some(other) => string_of(other),
    }
}

/// JavaScript's white space and line terminators, as `trim()` and `\s`
/// read them.
pub fn is_space(c: char) -> bool {
    matches!(
        c,
        '\u{0009}'..='\u{000d}'
            | ' '
            | '\u{00a0}'
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

/// `text.trim()`. A hot path: no span.
pub fn trim(text: &str) -> &str {
    text.trim_matches(is_space)
}
