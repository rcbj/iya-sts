// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! How JavaScript reads the loosely typed fields of a certificate spec —
//! `String(x)`, `parseInt(x, radix)`, truthiness — so a spec the console
//! sends means here what it meant to `x509.js`.

use serde_json::Value as Json;

/// `String(x)` of a JSON value; `None` (undefined) is `"undefined"`.
pub fn string_of(v: Option<&Json>) -> String {
    match v {
        None => "undefined".to_string(),
        Some(Json::String(s)) => s.clone(),
        Some(Json::Null) => "null".to_string(),
        Some(Json::Bool(b)) => b.to_string(),
        Some(Json::Number(n)) => number_text(n.as_f64().unwrap_or(0.0)),
        Some(Json::Array(a)) => a
            .iter()
            .map(|x| {
                if x.is_null() {
                    String::new()
                } else {
                    string_of(Some(x))
                }
            })
            .collect::<Vec<_>>()
            .join(","),
        Some(Json::Object(_)) => "[object Object]".to_string(),
    }
}

/// A JavaScript number's text, for the integers a spec carries.
fn number_text(x: f64) -> String {
    if x.fract() == 0.0 && x.abs() < 1e21 {
        format!("{}", x as i64)
    } else {
        format!("{}", x)
    }
}

/// `parseInt(text, radix)`: leading whitespace, a sign, `0x` for radix 16,
/// then as many digits as there are; `None` is NaN.
pub fn parse_int(text: &str, radix: u32) -> Option<i64> {
    let t = text.trim_start();
    let (negative, t) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let t = if radix == 16 && (t.starts_with("0x") || t.starts_with("0X")) {
        &t[2..]
    } else {
        t
    };
    let digits: String = t.chars().take_while(|c| c.is_digit(radix)).collect();
    if digits.is_empty() {
        return None;
    }
    let magnitude = i64::from_str_radix(&digits, radix).ok()?;
    Some(if negative { -magnitude } else { magnitude })
}

/// JavaScript truthiness.
pub fn truthy(v: Option<&Json>) -> bool {
    match v {
        None | Some(Json::Null) => false,
        Some(Json::Bool(b)) => *b,
        Some(Json::Number(n)) => n.as_f64().is_some_and(|x| x != 0.0),
        Some(Json::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// A field that is "set" in x509.js's sense: not undefined, null or `''`.
pub fn is_set(v: Option<&Json>) -> bool {
    !matches!(v, None | Some(Json::Null))
        && v != Some(&Json::String(String::new()))
}

/// `parseInt(x, 10)` of a field that is set, or `None`.
pub fn int_field(v: Option<&Json>) -> Option<Option<i64>> {
    is_set(v).then(|| parse_int(&string_of(v), 10))
}
