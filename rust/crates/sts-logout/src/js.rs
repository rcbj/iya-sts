// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The JavaScript coercions `logout.ts` builds its rows and sentences
//! with, beyond `sts_authn::js`'s: `x + ''` of a member that may be
//! `undefined`, `x.slice(0, n)` by UTF-16 unit, `new Date(ms)
//! .toISOString()`, and an `Object.assign()` whose `undefined` members
//! are left off the JSON.
//!
//! Every function here is a hot path — called for every field of every
//! row — and carries no span.

use serde_json::{Map, Value};
pub use sts_authn::js::{
    num, number, number_or_zero, object_of, or_empty, string_of, strings,
    text, truthy,
};

/// A row, a context, a result: Node's JSON object.
pub type Object = Map<String, Value>;

/// `'' + x` of a member: `undefined` is the word, as JavaScript writes it.
pub fn concat(value: Option<&Value>) -> String {
    match value {
        None => "undefined".to_string(),
        Some(v) => text(v),
    }
}

/// `String(x).slice(0, n)`, by UTF-16 code unit as JavaScript counts.
pub fn slice16(s: &str, n: usize) -> String {
    let units: Vec<u16> = s.encode_utf16().take(n).collect();
    String::from_utf16_lossy(&units)
}

/// `new Date(ms).toISOString()`; `RangeError` (an invalid date) is an
/// `Err`, as Node throws.
pub fn iso(ms: f64) -> Result<String, String> {
    if !ms.is_finite() {
        return Err("Invalid time value".into());
    }
    let whole = ms.trunc() as i64;
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(whole)
        .map(|d| d.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        .ok_or_else(|| "Invalid time value".into())
}

/// `Date.parse(iso)` of an instant a port answered, in ms; NaN otherwise.
pub fn parse_iso(value: &Value) -> f64 {
    value
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map_or(f64::NAN, |d| d.timestamp_millis() as f64)
}

/// `Object.assign(target, { key: value })` where the value may be
/// `undefined`: the member is then left off what `JSON.stringify` writes,
/// so it is removed rather than set to null.
pub fn put(target: &mut Object, key: &str, value: Option<Value>) {
    match value {
        Some(v) => {
            target.insert(key.to_string(), v);
        }
        None => {
            target.shift_remove(key);
        }
    }
}

/// `Array.isArray(x) ? x : [x]`, then `.filter(Boolean)`.
pub fn listed(value: Option<&Value>) -> Vec<Value> {
    match value {
        None => Vec::new(),
        Some(Value::Array(list)) => {
            list.iter().filter(|v| truthy(Some(v))).cloned().collect()
        }
        Some(other) => {
            if truthy(Some(other)) {
                vec![other.clone()]
            } else {
                Vec::new()
            }
        }
    }
}

/// `encodeURIComponent()`.
pub fn encode_uri_component(text: &str) -> String {
    sts_authn::account_sets::encode_uri_component(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn javascript_words() {
        assert_eq!(concat(None), "undefined");
        assert_eq!(concat(Some(&json!(null))), "null");
        assert_eq!(slice16("abcdefghij", 8), "abcdefgh");
        assert_eq!(iso(0.0).unwrap(), "1970-01-01T00:00:00.000Z");
        assert!(iso(f64::NAN).is_err());
        assert_eq!(listed(Some(&json!("a"))), vec![json!("a")]);
        assert_eq!(listed(Some(&json!(["a", "", null]))), vec![json!("a")]);
    }
}
