// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The JavaScript coercions `authn/authn.ts` writes its session rows with:
//! `Number(x)`, `String(x)`, `x || ''`, truthiness, and the two ways a
//! number goes back into JSON. A session row is held as Node's JSON object,
//! member for member, so every reader of a field asks it the way Node does.
//!
//! Every function here is a hot path — called for every field of every
//! session read — and carries no span.

use serde_json::{Map, Number, Value};

/// A session row, or any object a door hands in: Node's JSON object.
pub type Object = Map<String, Value>;

/// `Number(x)` for a member: a number, a numeric string, a boolean, or NaN.
pub fn number(value: Option<&Value>) -> f64 {
    match value {
        None => f64::NAN,
        Some(Value::Null) => 0.0,
        Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
        Some(Value::Bool(b)) => f64::from(u8::from(*b)),
        Some(Value::String(s)) => {
            let t = s.trim();
            if t.is_empty() {
                0.0
            } else {
                t.parse::<f64>().unwrap_or(f64::NAN)
            }
        }
        Some(Value::Array(a)) if a.is_empty() => 0.0,
        Some(_) => f64::NAN,
    }
}

/// `Number(x) || 0`.
pub fn number_or_zero(value: Option<&Value>) -> f64 {
    let n = number(value);
    if n.is_nan() {
        0.0
    } else {
        n
    }
}

/// JavaScript truthiness.
pub fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// `String(x)` of a JSON value, as JavaScript writes it.
pub fn text(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => number_text(n),
        Value::String(s) => s.clone(),
        Value::Array(list) => list
            .iter()
            .map(|one| match one {
                Value::Null => String::new(),
                other => text(other),
            })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".to_string(),
    }
}

fn number_text(n: &Number) -> String {
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    match n.as_f64() {
        Some(f) if f.fract() == 0.0 && f.abs() < 1e21 => format!("{f:.0}"),
        Some(f) => f.to_string(),
        None => n.to_string(),
    }
}

/// `String(x || '')` of a member.
pub fn or_empty(value: Option<&Value>) -> String {
    match value {
        Some(v) if truthy(Some(v)) => text(v),
        _ => String::new(),
    }
}

/// `String(x)` of a member that may be absent (`undefined` reads as '').
pub fn string_of(value: Option<&Value>) -> String {
    match value {
        None => String::new(),
        Some(v) => text(v),
    }
}

/// A millisecond or second count as JSON, an integer where it is one, as
/// `JSON.stringify` writes a JavaScript number.
pub fn num(n: f64) -> Value {
    if n.is_finite() && n.fract() == 0.0 && n.abs() < 9.007_199_254_740_992e15 {
        Value::from(n as i64)
    } else if n.is_finite() {
        Number::from_f64(n).map_or(Value::Null, Value::Number)
    } else {
        Value::Null
    }
}

/// An array of strings, `(x || []).map(String)`.
pub fn strings(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(a)) => a.iter().map(text).collect(),
        _ => Vec::new(),
    }
}

/// A list of strings as a JSON array.
pub fn string_array(list: &[String]) -> Value {
    Value::Array(list.iter().cloned().map(Value::String).collect())
}

/// `Object.assign({}, a, b)` for two objects.
pub fn assign(base: &Object, more: &Object) -> Object {
    let mut out = base.clone();
    for (k, v) in more {
        out.insert(k.clone(), v.clone());
    }
    out
}

/// A member as an object, or an empty one.
pub fn object_of(value: Option<&Value>) -> Object {
    match value {
        Some(Value::Object(o)) => o.clone(),
        _ => Object::new(),
    }
}

/// `JSON.stringify` of a value, for the set comparisons Node makes with it.
pub fn stringify(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn number_reads_as_javascript_does() {
        assert_eq!(number(Some(&json!("12"))), 12.0);
        assert!(number(Some(&json!("x"))).is_nan());
        assert!(number(None).is_nan());
        assert_eq!(number(Some(&json!(null))), 0.0);
        assert_eq!(number_or_zero(Some(&json!("x"))), 0.0);
    }

    #[test]
    fn numbers_go_back_as_integers() {
        assert_eq!(num(3.0), json!(3));
        assert_eq!(num(1.5), json!(1.5));
        assert_eq!(num(f64::NAN), json!(null));
    }
}
