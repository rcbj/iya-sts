// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The seventeen datatypes: how a lexical form becomes a value, when two
//! values are equal, and how they order. A port of
//! `xacml/xacml_datatypes.js`.
//!
//! The function library is generated over this table (`functions/`), because
//! 210 of XACML's function identifiers are twenty-odd operations
//! parameterised by type. So a [`DataType`] is the whole of what a type is,
//! and no function knows anything about a type except through it.
//!
//! **Five places where "equal" is not string equality**, each a defect that
//! looks like a working implementation:
//!
//! 1. `integer` is unbounded (`BigInt`).
//! 2. `double`: `INF`, `-INF` and `NaN` are legal, and **NaN equals NaN** —
//!    XML Schema's value space has one NaN and XACML A.3.4 defers to it
//!    (cases IIC350 and IIC358).
//! 3. `rfc822Name`: the domain folds case and the local part does not.
//! 4. `x500Name` compares parsed RDN sequences, in order.
//! 5. `anyURI` is plain string equality, with no normalisation (A.3.3).
//!
//! Dates and times keep whether they HAVE a timezone, and an ordering that
//! differs across the range a missing timezone could be is reported as
//! incomparable (`None`), which the comparison functions turn into an
//! Indeterminate rather than a `false` that would be a claim about the world.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::LazyLock;

use base64::Engine;
use num_bigint::BigInt;
use regex::Regex;

use crate::model::{canonical_type, types, XacmlError, XacmlResult};
use crate::value::{
    js_number_string, PortRange, Rdn, Temporal, TemporalShape, Value,
};

/// What a datatype is: its identifiers, its lexical space, its equality and
/// (for the types that have one) its order. A type whose `compare` is never
/// offered has no ordering functions in the library at all, which is how
/// `boolean-greater-than` fails to exist rather than existing and being
/// wrong.
pub trait DataType: Send + Sync {
    /// The datatype URI.
    fn uri(&self) -> &'static str;
    /// The short name the function identifiers are built from
    /// (`dayTimeDuration-equal`).
    fn name(&self) -> &'static str;
    /// A lexical form to a value, or a syntax-error Indeterminate.
    fn parse(&self, lexical: &str) -> XacmlResult<Value>;
    /// A value back to its lexical form.
    fn write(&self, value: &Value) -> String;
    /// Equality over the VALUE space.
    fn equal(&self, left: &Value, right: &Value) -> XacmlResult<bool>;
    /// Whether this type has an order relation.
    fn is_ordered(&self) -> bool {
        false
    }
    /// The order relation; `None` when the two values are genuinely
    /// incomparable. Only called when [`DataType::is_ordered`] is true.
    fn compare(&self, _left: &Value, _right: &Value) -> Option<Ordering> {
        None
    }
}

/// XML Schema allows leading and trailing whitespace on every lexical form.
/// None of these types permits internal whitespace, so nothing collapses it.
fn trimmed(text: &str) -> &str {
    text.trim()
}

fn invalid(name: &str, lexical: &str) -> XacmlError {
    XacmlError::syntax(format!("\"{}\" is not a valid {}.", lexical, name))
}

fn pad2(value: i64) -> String {
    format!("{:02}", value)
}

/// JavaScript's `String(n).padStart(4, '0')`, which is what the Node engine
/// writes a year with — including its odd output for a negative year.
fn pad_year(year: i64) -> String {
    let text = year.to_string();
    if text.len() >= 4 {
        text
    } else {
        format!("{}{}", "0".repeat(4 - text.len()), text)
    }
}

// ---------------------------------------------------------------------------
// Date and time. One parser for all three shapes, because they are three
// slices of one grammar. The year may be negative and longer than four
// digits, and the seconds may be fractional.
// ---------------------------------------------------------------------------
static DATE_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"^(-?\d{4,})-(\d{2})-(\d{2})(Z|[+-]\d{2}:\d{2})?$").ok()
});
static TIME_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"^(\d{2}):(\d{2}):(\d{2}(?:\.\d+)?)(Z|[+-]\d{2}:\d{2})?$").ok()
});
static DATETIME_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r"^(-?\d{4,})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2}(?:\.\d+)?)(Z|[+-]\d{2}:\d{2})?$",
    )
    .ok()
});

/// Minutes east of UTC, or `None` when the value carries no timezone.
fn timezone_minutes(text: Option<&str>) -> Option<i64> {
    let text = text?;
    if text == "Z" {
        return Some(0);
    }
    let sign = if text.starts_with('-') { -1 } else { 1 };
    let hours: i64 = text.get(1..3)?.parse().ok()?;
    let minutes: i64 = text.get(4..6)?.parse().ok()?;
    Some(sign * (hours * 60 + minutes))
}

/// A timezone back to its lexical form: `Z`, `+hh:mm`, or nothing at all.
pub fn timezone_text(minutes: Option<i64>) -> String {
    match minutes {
        None => String::new(),
        Some(0) => "Z".to_string(),
        Some(m) => {
            let sign = if m < 0 { '-' } else { '+' };
            let absolute = m.abs();
            format!("{}{}:{}", sign, pad2(absolute / 60), pad2(absolute % 60))
        }
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date — computed, because a
/// calendar library would clamp distant years or apply a local timezone.
pub fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = year - if month <= 2 { 1 } else { 0 };
    let era = (if y >= 0 { y } else { y - 399 }).div_euclid(400);
    let yoe = y - era * 400;
    let doy =
        (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// The inverse of [`days_from_civil`]; only date arithmetic needs it.
pub fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }).div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    (y + if m <= 2 { 1 } else { 0 }, m, d)
}

fn parse_temporal(lexical: &str, shape: TemporalShape) -> Option<Temporal> {
    let text = trimmed(lexical);
    let re = match shape {
        TemporalShape::Date => DATE_RE.as_ref(),
        TemporalShape::Time => TIME_RE.as_ref(),
        TemporalShape::DateTime => DATETIME_RE.as_ref(),
    }?;
    let caps = re.captures(text)?;
    let int = |i: usize| -> Option<i64> { caps.get(i)?.as_str().parse().ok() };
    let float =
        |i: usize| -> Option<f64> { caps.get(i)?.as_str().parse().ok() };
    let tz_of = |i: usize| timezone_minutes(caps.get(i).map(|m| m.as_str()));
    let mut value = Temporal {
        shape,
        year: 1970,
        month: 1,
        day: 1,
        hour: 0,
        minute: 0,
        second: 0.0,
        tz: None,
    };
    match shape {
        TemporalShape::Date => {
            value.year = int(1)?;
            value.month = int(2)?;
            value.day = int(3)?;
            value.tz = tz_of(4);
        }
        TemporalShape::Time => {
            value.hour = int(1)?;
            value.minute = int(2)?;
            value.second = float(3)?;
            value.tz = tz_of(4);
        }
        TemporalShape::DateTime => {
            value.year = int(1)?;
            value.month = int(2)?;
            value.day = int(3)?;
            value.hour = int(4)?;
            value.minute = int(5)?;
            value.second = float(6)?;
            value.tz = tz_of(7);
        }
    }
    if value.month < 1
        || value.month > 12
        || value.day < 1
        || value.day > 31
        || value.hour > 24
        || value.minute > 59
        || value.second >= 61.0
    {
        return None;
    }
    Some(value)
}

/// Seconds from an epoch with the value's own offset applied, or
/// `assumed_tz` where it has none. A `time` has no date part to disagree
/// about.
pub fn instant_seconds(value: &Temporal, assumed_tz: i64) -> f64 {
    let tz = value.tz.unwrap_or(assumed_tz);
    let mut seconds = 0.0;
    if value.shape != TemporalShape::Time {
        seconds += (days_from_civil(value.year, value.month, value.day) * 86400)
            as f64;
    }
    seconds += (value.hour * 3600 + value.minute * 60) as f64 + value.second;
    seconds - (tz * 60) as f64
}

fn order_of(a: f64, b: f64) -> Ordering {
    if a < b {
        Ordering::Less
    } else if a > b {
        Ordering::Greater
    } else {
        Ordering::Equal
    }
}

/// The order XML Schema defines: two zoned (or two unzoned) values compare
/// ordinarily; a zoned against an unzoned one compares at BOTH ends of
/// [-14:00, +14:00] and is ordered only if both ends agree. `None` means
/// incomparable, which is Indeterminate rather than "equal".
pub fn compare_temporal(left: &Temporal, right: &Temporal) -> Option<Ordering> {
    let both_known = left.tz.is_some() && right.tz.is_some();
    let both_unknown = left.tz.is_none() && right.tz.is_none();
    if both_known || both_unknown {
        return Some(order_of(
            instant_seconds(left, 0),
            instant_seconds(right, 0),
        ));
    }
    let first = order_of(
        instant_seconds(left, 14 * 60),
        instant_seconds(right, 14 * 60),
    );
    let second = order_of(
        instant_seconds(left, -14 * 60),
        instant_seconds(right, -14 * 60),
    );
    if first == second {
        Some(first)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// The other parsers.
// ---------------------------------------------------------------------------
static YEARMONTH_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^(-?)P(?:(\d+)Y)?(?:(\d+)M)?$").ok());
static DAYTIME_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r"^(-?)P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$",
    )
    .ok()
});

fn parse_year_month(lexical: &str) -> Option<i64> {
    let text = trimmed(lexical);
    let caps = YEARMONTH_RE.as_ref()?.captures(text)?;
    if caps.get(2).is_none() && caps.get(3).is_none() {
        return None;
    }
    let part = |i: usize| -> Option<i64> {
        caps.get(i).map_or(Some(0), |m| m.as_str().parse().ok())
    };
    let months = part(2)? * 12 + part(3)?;
    Some(if &caps[1] == "-" { -months } else { months })
}

fn parse_day_time(lexical: &str) -> Option<f64> {
    let text = trimmed(lexical);
    let caps = DAYTIME_RE.as_ref()?.captures(text)?;
    if (2..=5).all(|i| caps.get(i).is_none()) {
        return None;
    }
    // A `T` with nothing after it is not a duration, and the pattern above
    // accepts it.
    if text.ends_with('T') {
        return None;
    }
    let whole = |i: usize| -> Option<f64> {
        caps.get(i).map_or(Some(0.0), |m| {
            m.as_str().parse::<i64>().ok().map(|v| v as f64)
        })
    };
    let fraction =
        caps.get(5).map_or(Some(0.0), |m| m.as_str().parse().ok())?;
    let seconds =
        whole(2)? * 86400.0 + whole(3)? * 3600.0 + whole(4)? * 60.0 + fraction;
    Some(if &caps[1] == "-" { -seconds } else { seconds })
}

fn has_space_or_at(text: &str) -> bool {
    text.chars().any(|c| c.is_whitespace() || c == '@')
}

fn parse_rfc822(lexical: &str) -> Option<Value> {
    let text = trimmed(lexical);
    let at = text.rfind('@')?;
    if at == 0 || at == text.len() - 1 {
        return None;
    }
    let (local, domain) = (&text[..at], &text[at + 1..]);
    if has_space_or_at(domain) || has_space_or_at(local) {
        return None;
    }
    Some(Value::Rfc822Name {
        local: local.to_string(),
        domain: domain.to_lowercase(),
    })
}

/// RFC 2253, parsed far enough to compare: a comma inside a quoted or
/// escaped value is not a separator.
fn parse_x500(lexical: &str) -> Option<Value> {
    let text = trimmed(lexical);
    if text.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    let mut quoted = false;
    for character in text.chars() {
        if escaped {
            current.push(character);
            escaped = false;
        } else if character == '\\' {
            current.push(character);
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
            current.push(character);
        } else if character == ',' && !quoted {
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(character);
        }
    }
    parts.push(current);
    let mut rdns = Vec::new();
    for part in parts {
        let piece = part.trim();
        let equals = piece.find('=')?;
        if equals == 0 {
            return None;
        }
        rdns.push(Rdn {
            attribute: piece[..equals].trim().to_lowercase(),
            value: piece[equals + 1..].trim().to_string(),
        });
    }
    Some(Value::X500Name(rdns))
}

/// Equality over the parsed RDNs, in order, with the VALUE compared
/// case-insensitively too (X.500's caseIgnoreMatch, which covers the string
/// attribute types essentially every DN is made of).
pub fn x500_equal(left: &[Rdn], right: &[Rdn]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(a, b)| {
            a.attribute == b.attribute
                && a.value.to_lowercase() == b.value.to_lowercase()
        })
}

/// JavaScript's `parseInt(text, 10)`: leading digits after an optional sign,
/// or `None` (NaN) when there are none.
fn js_parse_int(text: &str) -> Option<i64> {
    let text = text.trim_start();
    let (sign, rest) = match text.strip_prefix('-') {
        Some(rest) => (-1, rest),
        None => (1, text.strip_prefix('+').unwrap_or(text)),
    };
    let digits: String =
        rest.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse::<i64>().ok().map(|v| sign * v)
}

fn parse_port_range(text: &str) -> Option<PortRange> {
    if text.is_empty() {
        return Some(PortRange {
            low: None,
            high: None,
        });
    }
    match text.find('-') {
        None => {
            let single = js_parse_int(text)?;
            Some(PortRange {
                low: Some(single),
                high: Some(single),
            })
        }
        Some(dash) => {
            // JavaScript's `parseInt` of a malformed end is NaN, which the
            // Node engine keeps; `None` is the closest an Option can say.
            let low = &text[..dash];
            let high = &text[dash + 1..];
            Some(PortRange {
                low: if low.is_empty() {
                    None
                } else {
                    js_parse_int(low)
                },
                high: if high.is_empty() {
                    None
                } else {
                    js_parse_int(high)
                },
            })
        }
    }
}

fn parse_dns(lexical: &str) -> Option<Value> {
    let text = trimmed(lexical);
    let (host, ports) = match text.find(':') {
        None => (text, ""),
        Some(colon) => (&text[..colon], &text[colon + 1..]),
    };
    if host.is_empty() || host.chars().any(char::is_whitespace) {
        return None;
    }
    Some(Value::DnsName {
        host: host.to_lowercase(),
        ports: parse_port_range(ports)?,
    })
}

/// An IPv6 literal is bracketed, which is what makes its colons
/// distinguishable from the port separator's.
fn parse_ip(lexical: &str) -> Option<Value> {
    let text = trimmed(lexical);
    if text.is_empty() {
        return None;
    }
    let (mut address, rest) = if let Some(inner) = text.strip_prefix('[') {
        let close = inner.find(']')?;
        (&inner[..close], &inner[close + 1..])
    } else {
        match text.find(':') {
            Some(colon) => (&text[..colon], &text[colon..]),
            None => (text, ""),
        }
    };
    let mut mask = None;
    if let Some(slash) = address.find('/') {
        mask = Some(address[slash + 1..].to_string());
        address = &address[..slash];
    }
    let ports = parse_port_range(rest.strip_prefix(':').unwrap_or(""))?;
    Some(Value::IpAddress {
        address: address.to_lowercase(),
        mask,
        ports,
    })
}

fn write_ports(host: &str, ports: &PortRange) -> String {
    if ports.low.is_none() && ports.high.is_none() {
        return host.to_string();
    }
    let show = |p: Option<i64>| p.map(|v| v.to_string()).unwrap_or_default();
    let tail = if ports.low == ports.high {
        String::new()
    } else {
        format!("-{}", show(ports.high))
    };
    format!("{}:{}{}", host, show(ports.low), tail)
}

fn write_temporal(value: &Temporal) -> String {
    let seconds = format!(
        "{}{}",
        if value.second < 10.0 { "0" } else { "" },
        js_number_string(value.second)
    );
    let date = || {
        format!(
            "{}-{}-{}",
            pad_year(value.year),
            pad2(value.month),
            pad2(value.day)
        )
    };
    let time =
        || format!("{}:{}:{}", pad2(value.hour), pad2(value.minute), seconds);
    let body = match value.shape {
        TemporalShape::Date => date(),
        TemporalShape::Time => time(),
        TemporalShape::DateTime => format!("{}T{}", date(), time()),
    };
    format!("{}{}", body, timezone_text(value.tz))
}

/// UTF-16 code-unit order, which is what JavaScript's `<` on strings is and
/// therefore what the Node engine's `string-less-than` answers.
pub fn utf16_order(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

// ---------------------------------------------------------------------------
// THE TYPES. One struct each: the row of the Node engine's TYPES table.
// ---------------------------------------------------------------------------
struct StringType;
struct BooleanType;
struct IntegerType;
struct DoubleType;
struct AnyUriType;
struct HexBinaryType;
struct Base64BinaryType;
struct TemporalType {
    uri: &'static str,
    name: &'static str,
    shape: TemporalShape,
}
struct YearMonthDurationType;
struct DayTimeDurationType;
struct Rfc822NameType;
struct X500NameType;
struct DnsNameType;
struct IpAddressType;
struct XPathExpressionType;

impl DataType for StringType {
    fn uri(&self) -> &'static str {
        types::STRING
    }
    fn name(&self) -> &'static str {
        "string"
    }
    /// NOT trimmed: xs:string preserves whitespace, and
    /// `string-normalize-space` would have nothing to do otherwise.
    fn parse(&self, lexical: &str) -> XacmlResult<Value> {
        Ok(Value::String(lexical.to_string()))
    }
    fn write(&self, value: &Value) -> String {
        value.as_text().unwrap_or_default().to_string()
    }
    fn equal(&self, l: &Value, r: &Value) -> XacmlResult<bool> {
        Ok(l == r)
    }
    fn is_ordered(&self) -> bool {
        true
    }
    fn compare(&self, l: &Value, r: &Value) -> Option<Ordering> {
        Some(utf16_order(l.as_text()?, r.as_text()?))
    }
}

impl DataType for BooleanType {
    fn uri(&self) -> &'static str {
        types::BOOLEAN
    }
    fn name(&self) -> &'static str {
        "boolean"
    }
    fn parse(&self, lexical: &str) -> XacmlResult<Value> {
        match trimmed(lexical) {
            "true" | "1" => Ok(Value::Boolean(true)),
            "false" | "0" => Ok(Value::Boolean(false)),
            _ => Err(invalid("boolean", lexical)),
        }
    }
    fn write(&self, value: &Value) -> String {
        if value.as_bool() == Some(true) {
            "true"
        } else {
            "false"
        }
        .to_string()
    }
    fn equal(&self, l: &Value, r: &Value) -> XacmlResult<bool> {
        Ok(l == r)
    }
}

static INTEGER_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^[+-]?\d+$").ok());

impl DataType for IntegerType {
    fn uri(&self) -> &'static str {
        types::INTEGER
    }
    fn name(&self) -> &'static str {
        "integer"
    }
    fn parse(&self, lexical: &str) -> XacmlResult<Value> {
        let text = trimmed(lexical);
        let ok = INTEGER_RE.as_ref().is_some_and(|re| re.is_match(text));
        if !ok {
            return Err(invalid("integer", lexical));
        }
        let digits = text.strip_prefix('+').unwrap_or(text);
        digits
            .parse::<BigInt>()
            .map(Value::Integer)
            .map_err(|_| invalid("integer", lexical))
    }
    fn write(&self, value: &Value) -> String {
        value
            .as_integer()
            .map(|i| i.to_string())
            .unwrap_or_default()
    }
    fn equal(&self, l: &Value, r: &Value) -> XacmlResult<bool> {
        Ok(l == r)
    }
    fn is_ordered(&self) -> bool {
        true
    }
    fn compare(&self, l: &Value, r: &Value) -> Option<Ordering> {
        Some(l.as_integer()?.cmp(r.as_integer()?))
    }
}

static DOUBLE_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?$").ok()
});

impl DataType for DoubleType {
    fn uri(&self) -> &'static str {
        types::DOUBLE
    }
    fn name(&self) -> &'static str {
        "double"
    }
    fn parse(&self, lexical: &str) -> XacmlResult<Value> {
        let text = trimmed(lexical);
        match text {
            "INF" | "+INF" => return Ok(Value::Double(f64::INFINITY)),
            "-INF" => return Ok(Value::Double(f64::NEG_INFINITY)),
            "NaN" => return Ok(Value::Double(f64::NAN)),
            _ => {}
        }
        let ok = DOUBLE_RE.as_ref().is_some_and(|re| re.is_match(text));
        if !ok {
            return Err(invalid("double", lexical));
        }
        text.parse::<f64>()
            .map(Value::Double)
            .map_err(|_| invalid("double", lexical))
    }
    /// xs:double's canonical form always carries a point or an exponent, so
    /// an integral double is `1.0`.
    fn write(&self, value: &Value) -> String {
        let v = value.as_double().unwrap_or(f64::NAN);
        if v == f64::INFINITY {
            "INF".to_string()
        } else if v == f64::NEG_INFINITY {
            "-INF".to_string()
        } else if v.is_nan() {
            "NaN".to_string()
        } else if v.fract() == 0.0 && v.abs() < 1e21 {
            if v == 0.0 {
                "0.0".to_string()
            } else {
                format!("{:.1}", v)
            }
        } else {
            js_number_string(v)
        }
    }
    /// NaN EQUALS NaN here — XML Schema's value space holds one NaN, and
    /// XACML A.3.4 defers to XML Schema rather than IEEE 754. `-0 == 0`
    /// agrees with both.
    fn equal(&self, l: &Value, r: &Value) -> XacmlResult<bool> {
        match (l.as_double(), r.as_double()) {
            (Some(a), Some(b)) => Ok((a.is_nan() && b.is_nan()) || a == b),
            _ => Ok(false),
        }
    }
    fn is_ordered(&self) -> bool {
        true
    }
    fn compare(&self, l: &Value, r: &Value) -> Option<Ordering> {
        let (a, b) = (l.as_double()?, r.as_double()?);
        if a.is_nan() || b.is_nan() {
            return None;
        }
        Some(order_of(a, b))
    }
}

impl DataType for AnyUriType {
    fn uri(&self) -> &'static str {
        types::ANYURI
    }
    fn name(&self) -> &'static str {
        "anyURI"
    }
    fn parse(&self, lexical: &str) -> XacmlResult<Value> {
        Ok(Value::AnyUri(trimmed(lexical).to_string()))
    }
    fn write(&self, value: &Value) -> String {
        value.as_text().unwrap_or_default().to_string()
    }
    fn equal(&self, l: &Value, r: &Value) -> XacmlResult<bool> {
        Ok(l == r)
    }
}

impl DataType for HexBinaryType {
    fn uri(&self) -> &'static str {
        types::HEXBINARY
    }
    fn name(&self) -> &'static str {
        "hexBinary"
    }
    fn parse(&self, lexical: &str) -> XacmlResult<Value> {
        let text = trimmed(lexical);
        if text.len() % 2 != 0 || !text.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(invalid("hexBinary", lexical));
        }
        Ok(Value::HexBinary(text.to_uppercase()))
    }
    fn write(&self, value: &Value) -> String {
        match value {
            Value::HexBinary(h) => h.clone(),
            _ => String::new(),
        }
    }
    fn equal(&self, l: &Value, r: &Value) -> XacmlResult<bool> {
        Ok(l == r)
    }
}

impl DataType for Base64BinaryType {
    fn uri(&self) -> &'static str {
        types::BASE64BINARY
    }
    fn name(&self) -> &'static str {
        "base64Binary"
    }
    fn parse(&self, lexical: &str) -> XacmlResult<Value> {
        let text: String =
            lexical.chars().filter(|c| !c.is_whitespace()).collect();
        let shape_ok = text.len() % 4 == 0 && {
            let body = text.trim_end_matches('=');
            text.len() - body.len() <= 2
                && body
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
        };
        if !shape_ok {
            return Err(invalid("base64Binary", lexical));
        }
        // Node's Buffer.from(…, 'base64') does not insist on canonical
        // padding bits, so neither does this.
        let engine = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new()
                .with_decode_allow_trailing_bits(true),
        );
        let bytes = engine
            .decode(text.as_bytes())
            .map_err(|_| invalid("base64Binary", lexical))?;
        let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        Ok(Value::Base64Binary(hex))
    }
    fn write(&self, value: &Value) -> String {
        let hex = match value {
            Value::Base64Binary(h) => h.as_str(),
            _ => "",
        };
        let bytes: Vec<u8> = (0..hex.len() / 2)
            .filter_map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok())
            .collect();
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }
    fn equal(&self, l: &Value, r: &Value) -> XacmlResult<bool> {
        Ok(l == r)
    }
}

impl DataType for TemporalType {
    fn uri(&self) -> &'static str {
        self.uri
    }
    fn name(&self) -> &'static str {
        self.name
    }
    fn parse(&self, lexical: &str) -> XacmlResult<Value> {
        parse_temporal(lexical, self.shape)
            .map(Value::Temporal)
            .ok_or_else(|| invalid(self.name, lexical))
    }
    fn write(&self, value: &Value) -> String {
        value.as_temporal().map(write_temporal).unwrap_or_default()
    }
    fn equal(&self, l: &Value, r: &Value) -> XacmlResult<bool> {
        Ok(self.compare(l, r) == Some(Ordering::Equal))
    }
    fn is_ordered(&self) -> bool {
        true
    }
    fn compare(&self, l: &Value, r: &Value) -> Option<Ordering> {
        compare_temporal(l.as_temporal()?, r.as_temporal()?)
    }
}

impl DataType for YearMonthDurationType {
    fn uri(&self) -> &'static str {
        types::YEARMONTH_DURATION
    }
    fn name(&self) -> &'static str {
        "yearMonthDuration"
    }
    fn parse(&self, lexical: &str) -> XacmlResult<Value> {
        parse_year_month(lexical)
            .map(Value::YearMonthDuration)
            .ok_or_else(|| invalid("yearMonthDuration", lexical))
    }
    fn write(&self, value: &Value) -> String {
        let months = match value {
            Value::YearMonthDuration(m) => *m,
            _ => 0,
        };
        let sign = if months < 0 { "-" } else { "" };
        let m = months.abs();
        format!("{}P{}Y{}M", sign, m / 12, m % 12)
    }
    fn equal(&self, l: &Value, r: &Value) -> XacmlResult<bool> {
        Ok(l == r)
    }
    fn is_ordered(&self) -> bool {
        true
    }
    fn compare(&self, l: &Value, r: &Value) -> Option<Ordering> {
        match (l, r) {
            (Value::YearMonthDuration(a), Value::YearMonthDuration(b)) => {
                Some(a.cmp(b))
            }
            _ => None,
        }
    }
}

impl DataType for DayTimeDurationType {
    fn uri(&self) -> &'static str {
        types::DAYTIME_DURATION
    }
    fn name(&self) -> &'static str {
        "dayTimeDuration"
    }
    fn parse(&self, lexical: &str) -> XacmlResult<Value> {
        parse_day_time(lexical)
            .map(Value::DayTimeDuration)
            .ok_or_else(|| invalid("dayTimeDuration", lexical))
    }
    fn write(&self, value: &Value) -> String {
        let total = match value {
            Value::DayTimeDuration(s) => *s,
            _ => 0.0,
        };
        let sign = if total < 0.0 { "-" } else { "" };
        let mut seconds = total.abs();
        let days = (seconds / 86400.0).floor();
        seconds -= days * 86400.0;
        let hours = (seconds / 3600.0).floor();
        seconds -= hours * 3600.0;
        let minutes = (seconds / 60.0).floor();
        seconds -= minutes * 60.0;
        format!(
            "{}P{}DT{}H{}M{}S",
            sign,
            js_number_string(days),
            js_number_string(hours),
            js_number_string(minutes),
            js_number_string(seconds)
        )
    }
    fn equal(&self, l: &Value, r: &Value) -> XacmlResult<bool> {
        Ok(l == r)
    }
    fn is_ordered(&self) -> bool {
        true
    }
    fn compare(&self, l: &Value, r: &Value) -> Option<Ordering> {
        match (l, r) {
            (Value::DayTimeDuration(a), Value::DayTimeDuration(b)) => {
                Some(order_of(*a, *b))
            }
            _ => None,
        }
    }
}

impl DataType for Rfc822NameType {
    fn uri(&self) -> &'static str {
        types::RFC822NAME
    }
    fn name(&self) -> &'static str {
        "rfc822Name"
    }
    fn parse(&self, lexical: &str) -> XacmlResult<Value> {
        parse_rfc822(lexical).ok_or_else(|| invalid("rfc822Name", lexical))
    }
    fn write(&self, value: &Value) -> String {
        match value {
            Value::Rfc822Name { local, domain } => {
                format!("{}@{}", local, domain)
            }
            _ => String::new(),
        }
    }
    /// The domain was folded at parse time and the local part was not.
    fn equal(&self, l: &Value, r: &Value) -> XacmlResult<bool> {
        Ok(l == r)
    }
}

impl DataType for X500NameType {
    fn uri(&self) -> &'static str {
        types::X500NAME
    }
    fn name(&self) -> &'static str {
        "x500Name"
    }
    fn parse(&self, lexical: &str) -> XacmlResult<Value> {
        parse_x500(lexical).ok_or_else(|| invalid("x500Name", lexical))
    }
    fn write(&self, value: &Value) -> String {
        match value {
            Value::X500Name(rdns) => rdns
                .iter()
                .map(|r| format!("{}={}", r.attribute.to_uppercase(), r.value))
                .collect::<Vec<_>>()
                .join(","),
            _ => String::new(),
        }
    }
    fn equal(&self, l: &Value, r: &Value) -> XacmlResult<bool> {
        match (l, r) {
            (Value::X500Name(a), Value::X500Name(b)) => Ok(x500_equal(a, b)),
            _ => Ok(false),
        }
    }
}

impl DataType for DnsNameType {
    fn uri(&self) -> &'static str {
        types::DNSNAME
    }
    fn name(&self) -> &'static str {
        "dnsName"
    }
    fn parse(&self, lexical: &str) -> XacmlResult<Value> {
        parse_dns(lexical).ok_or_else(|| invalid("dnsName", lexical))
    }
    fn write(&self, value: &Value) -> String {
        match value {
            Value::DnsName { host, ports } => write_ports(host, ports),
            _ => String::new(),
        }
    }
    fn equal(&self, l: &Value, r: &Value) -> XacmlResult<bool> {
        Ok(l == r)
    }
}

impl DataType for IpAddressType {
    fn uri(&self) -> &'static str {
        types::IPADDRESS
    }
    fn name(&self) -> &'static str {
        "ipAddress"
    }
    fn parse(&self, lexical: &str) -> XacmlResult<Value> {
        parse_ip(lexical).ok_or_else(|| invalid("ipAddress", lexical))
    }
    /// The address and mask only — the port range is not written back, as in
    /// the Node engine.
    fn write(&self, value: &Value) -> String {
        match value {
            Value::IpAddress { address, mask, .. } => match mask {
                Some(m) if !m.is_empty() => format!("{}/{}", address, m),
                _ => address.clone(),
            },
            _ => String::new(),
        }
    }
    fn equal(&self, l: &Value, r: &Value) -> XacmlResult<bool> {
        Ok(l == r)
    }
}

impl DataType for XPathExpressionType {
    fn uri(&self) -> &'static str {
        types::XPATH_EXPRESSION
    }
    fn name(&self) -> &'static str {
        "xpathExpression"
    }
    /// The category and namespace bindings are not in the lexical form; the
    /// XML reader attaches them. A value built from a bare string is
    /// incomplete on purpose.
    fn parse(&self, lexical: &str) -> XacmlResult<Value> {
        Ok(Value::XPathExpression {
            xpath: trimmed(lexical).to_string(),
            category: None,
            namespaces: BTreeMap::new(),
        })
    }
    fn write(&self, value: &Value) -> String {
        match value {
            Value::XPathExpression { xpath, .. } => xpath.clone(),
            _ => String::new(),
        }
    }
    /// Section A.3.15 defines no xpathExpression equality at all, so this
    /// refuses rather than guessing.
    fn equal(&self, _l: &Value, _r: &Value) -> XacmlResult<bool> {
        Err(XacmlError::processing(
            "xpathExpression values cannot be compared for equality. XACML \
             defines no such function; a policy that needs one is asking for \
             xpath-node-count or one of the XPath-based match functions.",
        ))
    }
}

/// The datatype table: every [`DataType`], by URI, in a stable order.
pub struct DataTypes {
    by_uri: BTreeMap<&'static str, Box<dyn DataType>>,
}

static REGISTRY: LazyLock<DataTypes> = LazyLock::new(DataTypes::build);

impl DataTypes {
    fn build() -> DataTypes {
        let rows: Vec<Box<dyn DataType>> = vec![
            Box::new(StringType),
            Box::new(BooleanType),
            Box::new(IntegerType),
            Box::new(DoubleType),
            Box::new(AnyUriType),
            Box::new(HexBinaryType),
            Box::new(Base64BinaryType),
            Box::new(TemporalType {
                uri: types::DATE,
                name: "date",
                shape: TemporalShape::Date,
            }),
            Box::new(TemporalType {
                uri: types::TIME,
                name: "time",
                shape: TemporalShape::Time,
            }),
            Box::new(TemporalType {
                uri: types::DATETIME,
                name: "dateTime",
                shape: TemporalShape::DateTime,
            }),
            Box::new(YearMonthDurationType),
            Box::new(DayTimeDurationType),
            Box::new(Rfc822NameType),
            Box::new(X500NameType),
            Box::new(DnsNameType),
            Box::new(IpAddressType),
            Box::new(XPathExpressionType),
        ];
        let by_uri = rows.into_iter().map(|row| (row.uri(), row)).collect();
        DataTypes { by_uri }
    }

    /// The one table.
    pub fn standard() -> &'static DataTypes {
        &REGISTRY
    }

    /// The row for a URI, the two legacy duration spellings included.
    pub fn get(&self, uri: &str) -> Option<&dyn DataType> {
        self.by_uri.get(canonical_type(uri)).map(|row| row.as_ref())
    }

    /// Every row.
    pub fn all(&self) -> impl Iterator<Item = &dyn DataType> {
        self.by_uri.values().map(|row| row.as_ref())
    }

    /// A lexical form at a named type. An UNKNOWN datatype and a bad lexical
    /// form at a known one are both syntax errors, and say which.
    pub fn parse(&self, uri: &str, lexical: &str) -> XacmlResult<Value> {
        self.require(uri)?.parse(lexical)
    }

    pub fn write(&self, uri: &str, value: &Value) -> XacmlResult<String> {
        Ok(self.require(uri)?.write(value))
    }

    fn require(&self, uri: &str) -> XacmlResult<&dyn DataType> {
        self.get(uri).ok_or_else(|| {
            XacmlError::syntax(format!("Unknown datatype \"{}\".", uri))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dt() -> &'static DataTypes {
        DataTypes::standard()
    }

    #[test]
    fn nan_equals_nan() {
        let double = dt().get(types::DOUBLE).unwrap();
        let nan = double.parse("NaN").unwrap();
        assert!(double.equal(&nan, &nan).unwrap());
    }

    #[test]
    fn rfc822_local_part_is_case_sensitive() {
        let a = dt().parse(types::RFC822NAME, "Bob@example.com");
        let b = dt().parse(types::RFC822NAME, "bob@EXAMPLE.com");
        let c = dt().parse(types::RFC822NAME, "Bob@EXAMPLE.COM");
        assert_ne!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn unzoned_dates_can_be_incomparable() {
        let a = parse_temporal("2002-03-22T08:23:47", TemporalShape::DateTime);
        let b = parse_temporal("2002-03-22T08:23:47Z", TemporalShape::DateTime);
        match (a, b) {
            (Some(a), Some(b)) => assert_eq!(compare_temporal(&a, &b), None),
            _ => panic!("both parse"),
        }
    }

    #[test]
    fn civil_round_trip() {
        for days in [-800_000, -1, 0, 1, 11_000, 19_000, 2_000_000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
    }

    #[test]
    fn durations_write_like_node() {
        let v = dt().parse(types::DAYTIME_DURATION, "P1DT2H").ok();
        let written = v.map(|v| dt().write(types::DAYTIME_DURATION, &v).ok());
        assert_eq!(written, Some(Some("P1DT2H0M0S".to_string())));
    }
}
