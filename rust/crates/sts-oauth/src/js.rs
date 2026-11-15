// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The few JavaScript behaviours the ported sentences and values depend on:
//! `JSON.stringify` of a value, `Number()` of one, `Date#toISOString()`,
//! V8's `JSON.parse` message for the common failures, and reading a JWT's
//! header or payload segment without verifying it (`Buffer.from(segment,
//! 'base64url')`, which is lenient, then `JSON.parse`).
//!
//! THESE ARE A HOT PATH: every request reads its values through them, so
//! they carry no span (no Entering/Leaving pair); `tracing` here would
//! drown the log.

use serde_json::Value as Json;

/// `JSON.stringify(value)`.
pub fn stringify(value: &Json) -> String {
    value.to_string()
}

/// `Number(value)` for a JSON value: a number as is, a numeric string
/// parsed, `true` 1, anything else `NaN`.
pub fn to_number(value: &Json) -> f64 {
    match value {
        Json::Number(n) => n.as_f64().unwrap_or(f64::NAN),
        Json::String(s) => {
            let t = s.trim();
            if t.is_empty() {
                0.0
            } else {
                t.parse::<f64>().unwrap_or(f64::NAN)
            }
        }
        Json::Bool(b) => f64::from(u8::from(*b)),
        Json::Null => 0.0,
        _ => f64::NAN,
    }
}

/// `new Date(ms).toISOString()`.
pub fn iso_instant(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|t| t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        .unwrap_or_default()
}

/// V8's `JSON.parse` message for `text` (node 24's wording), for the
/// shapes a client sends: nothing, a body that ends early, a property name
/// missing, a separator missing, trailing characters and an unexpected
/// token. The position is serde's, made zero-based.
pub fn json_parse_message(text: &str, error: &serde_json::Error) -> String {
    if text.trim().is_empty() || error.is_eof() {
        return "Unexpected end of JSON input".to_string();
    }
    let line = error.line();
    let column = error.column();
    let offset: usize = text
        .split('\n')
        .take(line.saturating_sub(1))
        .map(|l| l.chars().count() + 1)
        .sum::<usize>()
        + column.saturating_sub(1);
    let at = format!(
        "in JSON at position {} (line {} column {})",
        offset, line, column
    );
    let message = error.to_string();
    if message.starts_with("key must be a string") {
        return format!("Expected property name or '}}' {}", at);
    }
    if message.starts_with("expected `,` or `}`") {
        return format!("Expected ',' or '}}' after property value {}", at);
    }
    if message.starts_with("expected `,` or `]`") {
        return format!("Expected ',' or ']' after array element {}", at);
    }
    if message.starts_with("expected `:`") {
        return format!("Expected ':' after property name {}", at);
    }
    if message.starts_with("trailing characters") {
        return format!(
            "Unexpected non-whitespace character after JSON at \
                        position {} (line {} column {})",
            offset, line, column
        );
    }
    let ch = text.chars().nth(offset).unwrap_or(' ');
    let snippet = if text.chars().count() < 32 {
        format!("\"{}\"", text)
    } else {
        let start = offset.saturating_sub(10);
        let piece: String = text.chars().skip(start).take(20).collect();
        format!(
            "\"{}{}{}\"",
            if start > 0 { "..." } else { "" },
            piece,
            if start + 20 < text.chars().count() {
                "..."
            } else {
                ""
            }
        )
    };
    format!("Unexpected token '{}', {} is not valid JSON", ch, snippet)
}

/// `Buffer.from(text, 'base64url')`: lenient — a character outside the
/// alphabets (either one) is skipped, padding ends the input, and trailing
/// bits that make no whole byte are dropped.
pub fn node_base64url(text: &str) -> Vec<u8> {
    let mut bits: u32 = 0;
    let mut count = 0;
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            b'=' => break,
            _ => continue,
        };
        bits = (bits << 6) | u32::from(v);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    out
}

/// `JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'))`: the
/// value, or V8's message.
pub fn node_segment_json(segment: &str) -> Result<Json, String> {
    let text = String::from_utf8_lossy(&node_base64url(segment)).to_string();
    serde_json::from_str::<Json>(&text).map_err(|e| json_parse_message(&text, &e))
}

/// A compact JWT's segment `index`, decoded leniently and parsed, or the
/// parse failure's message.
pub fn segment_json(compact: &str, index: usize) -> Result<Json, String> {
    let segment = compact.split('.').nth(index).unwrap_or("");
    let bytes = sts_crypto::b64::decode_loose(segment).unwrap_or_default();
    let text = String::from_utf8_lossy(&bytes).to_string();
    serde_json::from_str::<Json>(&text)
        .map_err(|e| json_parse_message(&text, &e))
}

/// One member of a compact JWT's header, as text, or empty.
pub fn header_member(compact: &str, name: &str) -> String {
    segment_json(compact, 0)
        .ok()
        .and_then(|h| h.get(name).and_then(Json::as_str).map(str::to_string))
        .unwrap_or_default()
}

/// `String(value)` for a JSON value.
pub fn string_of(value: Option<&Json>) -> String {
    match value {
        None | Some(Json::Null) => String::new(),
        Some(Json::String(s)) => s.clone(),
        Some(Json::Bool(b)) => b.to_string(),
        Some(Json::Number(n)) => n.to_string(),
        Some(Json::Array(list)) => list
            .iter()
            .map(|one| match one {
                Json::Null => String::new(),
                other => string_of(Some(other)),
            })
            .collect::<Vec<_>>()
            .join(","),
        Some(Json::Object(_)) => "[object Object]".to_string(),
    }
}

/// `URLSearchParams#toString()`: application/x-www-form-urlencoded, space
/// as `+`, and only `*-._` and alphanumerics left as they are.
pub fn form_encode(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", form_component(k), form_component(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn form_component(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.as_bytes() {
        match byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'*'
            | b'-'
            | b'.'
            | b'_' => out.push(*byte as char),
            b' ' => out.push('+'),
            other => out.push_str(&format!("%{:02X}", other)),
        }
    }
    out
}

/// `new URLSearchParams(text)`: the pairs of a form body, in order.
pub fn form_decode(text: &str) -> Vec<(String, String)> {
    url::form_urlencoded::parse(text.trim_start_matches('?').as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// The form, folded as Express's `qs`-less body parser and Node's
/// authorize endpoint fold it: a name given twice becomes an array.
pub fn fold(pairs: &[(String, String)]) -> serde_json::Map<String, Json> {
    let mut out = serde_json::Map::new();
    for (k, v) in pairs {
        match out.get_mut(k) {
            None => {
                out.insert(k.clone(), Json::from(v.as_str()));
            }
            Some(Json::Array(list)) => list.push(Json::from(v.as_str())),
            Some(held) => {
                let first = held.clone();
                *held = Json::Array(vec![first, Json::from(v.as_str())]);
            }
        }
    }
    out
}
