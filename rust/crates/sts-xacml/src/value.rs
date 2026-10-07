// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A parsed XACML value. One variant per datatype shape; what a value MEANS
//! (how it is written, when two are equal, how they order) is the datatype's
//! business and lives in `datatypes.rs`.

use std::collections::BTreeMap;

use num_bigint::BigInt;

/// Which of the three date/time grammars a [`Temporal`] came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemporalShape {
    Date,
    Time,
    DateTime,
}

/// An xs:date, xs:time or xs:dateTime, in its LOCAL components.
///
/// `tz` is minutes east of UTC, and `None` is a DIFFERENT fact from
/// `Some(0)`: a value with no timezone is not in UTC, it is a value whose
/// timezone is unknown. XML Schema orders it against a zoned value only when
/// the answer is the same across the whole [-14:00, +14:00] range — see
/// `datatypes::compare_temporal`.
#[derive(Debug, Clone, PartialEq)]
pub struct Temporal {
    pub shape: TemporalShape,
    pub year: i64,
    pub month: i64,
    pub day: i64,
    pub hour: i64,
    pub minute: i64,
    /// May be fractional.
    pub second: f64,
    pub tz: Option<i64>,
}

/// One relative distinguished name of an x500Name. The attribute type is
/// held lower-cased; the value as written.
#[derive(Debug, Clone, PartialEq)]
pub struct Rdn {
    pub attribute: String,
    pub value: String,
}

/// The optional port range on a dnsName or ipAddress. `None` on either end
/// means unbounded on that end.
#[derive(Debug, Clone, PartialEq)]
pub struct PortRange {
    pub low: Option<i64>,
    pub high: Option<i64>,
}

/// A parsed value. Integers are unbounded (`BigInt`): xs:integer has no upper
/// limit, and two large identifiers that rounded to the same double would
/// otherwise compare equal.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    String(String),
    Boolean(bool),
    Integer(BigInt),
    Double(f64),
    Temporal(Temporal),
    /// A yearMonthDuration, in months. Kept apart from dayTimeDuration on
    /// purpose: a month is not a fixed number of days, so the two do not
    /// compare.
    YearMonthDuration(i64),
    /// A dayTimeDuration, in seconds (fractional).
    DayTimeDuration(f64),
    AnyUri(String),
    /// Upper-case hex: hexBinary's canonical form, so `ff` equals `FF`.
    HexBinary(String),
    /// Held as the DECODED octets in lower-case hex, so two base64 spellings
    /// of the same bytes are equal by construction.
    Base64Binary(String),
    /// The domain is lower-cased at parse time and the local part is NOT
    /// (section A.3.14): `Bob@x` and `bob@x` are different addresses.
    Rfc822Name {
        local: String,
        domain: String,
    },
    X500Name(Vec<Rdn>),
    DnsName {
        host: String,
        ports: PortRange,
    },
    IpAddress {
        address: String,
        mask: Option<String>,
        ports: PortRange,
    },
    /// An XPath, with the category and namespace bindings the XML reader
    /// captured. No XPath is evaluated by this crate.
    XPathExpression {
        xpath: String,
        category: Option<String>,
        namespaces: BTreeMap<String, String>,
    },
}

impl Value {
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_integer(&self) -> Option<&BigInt> {
        match self {
            Value::Integer(i) => Some(i),
            _ => None,
        }
    }

    pub fn as_double(&self) -> Option<f64> {
        match self {
            Value::Double(d) => Some(*d),
            _ => None,
        }
    }

    /// The text of a string or anyURI value, which several functions treat
    /// alike (the `-contains` / `-starts-with` families).
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::String(s) | Value::AnyUri(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_temporal(&self) -> Option<&Temporal> {
        match self {
            Value::Temporal(t) => Some(t),
            _ => None,
        }
    }
}

/// JavaScript's `Number.prototype.toString()` for a double, which is what the
/// Node engine writes a double (or a fractional second) with. Reproduced
/// rather than replaced by Rust's `Display`, because the two differ on large
/// and small magnitudes (`1e21` against `1000000000000000000000`) and a value
/// written back into a policy or an obligation must read the same from both
/// implementations.
pub fn js_number_string(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity" } else { "-Infinity" }.to_string();
    }
    if value == 0.0 {
        return "0".to_string();
    }
    let sign = if value < 0.0 { "-" } else { "" };
    // `{:e}` gives the shortest round-trip digits, as ECMAScript requires.
    let scientific = format!("{:e}", value.abs());
    let (mantissa, exponent) = match scientific.split_once('e') {
        Some(parts) => parts,
        None => return format!("{}{}", sign, scientific),
    };
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let exponent: i64 = exponent.parse().unwrap_or(0);
    let k = digits.len() as i64;
    let n = exponent + 1;
    let body = if k <= n && n <= 21 {
        format!("{}{}", digits, "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{}", "0".repeat((-n) as usize), digits)
    } else {
        let e = n - 1;
        let e_sign = if e >= 0 { "+" } else { "-" };
        if k == 1 {
            format!("{}e{}{}", digits, e_sign, e.abs())
        } else {
            format!("{}.{}e{}{}", &digits[..1], &digits[1..], e_sign, e.abs())
        }
    };
    format!("{}{}", sign, body)
}

#[cfg(test)]
mod tests {
    use super::js_number_string;

    #[test]
    fn matches_javascript_number_to_string() {
        assert_eq!(js_number_string(1.0), "1");
        assert_eq!(js_number_string(1.5), "1.5");
        assert_eq!(js_number_string(-0.25), "-0.25");
        assert_eq!(js_number_string(1e21), "1e+21");
        assert_eq!(js_number_string(1e20), "100000000000000000000");
        assert_eq!(js_number_string(1.5e-7), "1.5e-7");
        assert_eq!(js_number_string(0.000001), "0.000001");
        assert_eq!(js_number_string(123.456), "123.456");
    }
}
