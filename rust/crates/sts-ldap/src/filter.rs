// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Search filters as `@ldapjs/filter` 2.1.1 reads them from BER, prints
//! them (RFC 4515's string form, nearly), parses that string form, and
//! writes them back.
//!
//! The order matters. A search request's filter reaches a handler by way
//! of all four: `SearchRequest.parseToPojo()` reads the BER, prints it,
//! and the constructor PARSES THE PRINTED STRING — so a filter is refused
//! when its string form does not parse back (`(cn;lang-en=v)`, an empty
//! equality value, a `>=` with no value), an empty substring becomes a
//! presence filter, and the values a handler sees are the ESCAPED text
//! (`\28x\29` for a value `(x)`: the string parser never unescapes), which
//! is also what the request's own `toBer()` writes. The escaper
//! (`escapeFilterValue()`) passes `\XX` sequences through by reading them
//! with `parseInt`, escapes `* ( )` and control bytes, writes each byte of
//! a 2- or 3-byte UTF-8 sequence as `\xx` (unpadded), and turns any other
//! byte above 0x7f into the Latin-1 character of that code point.
//!
//! The string parser counts positions in UTF-16 code units, as JavaScript
//! does; the BER reader is [`crate::ber::Reader`]. Its functions are a hot
//! path — every search request — and carry no span (rust/DESIGN.md D3,
//! section 4.5).

use crate::ber::{Reader, Writer};
use crate::fault::{pass_limit, too_deep, Fault, Outcome, MAX_FILTER_DEPTH};
use crate::js;

/// A JavaScript value that is a string, `null` or `undefined` — the three
/// a field read from BER can be, which print and encode differently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsStr {
    Undefined,
    Null,
    Str(String),
}

impl JsStr {
    /// A non-empty string: what `if (x)` lets through.
    pub fn truthy(&self) -> Option<&str> {
        match self {
            JsStr::Str(s) if !s.is_empty() => Some(s),
            _ => None,
        }
    }

    fn from_opt(v: Option<String>) -> JsStr {
        match v {
            Some(s) => JsStr::Str(s),
            None => JsStr::Null,
        }
    }
}

/// A search filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    And(Vec<Filter>),
    Or(Vec<Filter>),
    Not(Box<Filter>),
    Equality {
        attribute: String,
        raw: Vec<u8>,
    },
    Presence {
        attribute: String,
    },
    Substring {
        attribute: String,
        initial: JsStr,
        any: Vec<Option<String>>,
        last: JsStr,
    },
    GreaterOrEqual {
        attribute: String,
        value: String,
    },
    LessOrEqual {
        attribute: String,
        value: String,
    },
    Approximate {
        attribute: String,
        value: String,
    },
    Extensible {
        /// `None` is `null` (read from BER as such); an absent type is "".
        attribute: Option<String>,
        rule: JsStr,
        value: String,
        dn_attributes: bool,
    },
}

const AT_LEAST_ONE: &str =
    "attribute must be a string of at least one character";
const VALUE_AT_LEAST_ONE: &str =
    "value must be a string of at least one character";

fn attribute_of(a: Option<String>) -> Outcome<String> {
    match a {
        Some(s) if !s.is_empty() => Ok(s),
        _ => Err(Fault::thrown(AT_LEAST_ONE)),
    }
}

fn value_of(v: Option<String>) -> Outcome<String> {
    match v {
        Some(s) if !s.is_empty() => Ok(s),
        _ => Err(Fault::thrown(VALUE_AT_LEAST_ONE)),
    }
}

fn wrong_sequence(what: &str, tag: u8, found: Option<u8>) -> Fault {
    match found {
        Some(f) => Fault::thrown(format!(
            "expected {what} sequence 0x{tag:02x}, got 0x{f:02x}"
        )),
        None => Fault::null_read("toString"),
    }
}

impl Filter {
    /// The filter's type name, as node-ldapjs gives it.
    pub fn type_name(&self) -> &'static str {
        match self {
            Filter::And(_) => "AndFilter",
            Filter::Or(_) => "OrFilter",
            Filter::Not(_) => "NotFilter",
            Filter::Equality { .. } => "EqualityFilter",
            Filter::Presence { .. } => "PresenceFilter",
            Filter::Substring { .. } => "SubstringFilter",
            Filter::GreaterOrEqual { .. } => "GreaterThanEqualsFilter",
            Filter::LessOrEqual { .. } => "LessThanEqualsFilter",
            Filter::Approximate { .. } => "ApproximateFilter",
            Filter::Extensible { .. } => "ExtensibleFilter",
        }
    }

    fn tag(&self) -> u8 {
        match self {
            Filter::And(_) => 0xa0,
            Filter::Or(_) => 0xa1,
            Filter::Not(_) => 0xa2,
            Filter::Equality { .. } => 0xa3,
            Filter::Substring { .. } => 0xa4,
            Filter::GreaterOrEqual { .. } => 0xa5,
            Filter::LessOrEqual { .. } => 0xa6,
            Filter::Presence { .. } => 0x87,
            Filter::Approximate { .. } => 0xa8,
            Filter::Extensible { .. } => 0xa9,
        }
    }

    /// An equality filter's value as the library's getter gives it.
    pub fn equality_value(raw: &[u8]) -> String {
        js::utf8(raw)
    }

    // ---- BER ---------------------------------------------------------

    /// `parseBer()`: a filter from the reader's position.
    pub fn parse_ber(ber: &mut Reader<'_>) -> Outcome<Filter> {
        Filter::parse_ber_at(ber, 0)
    }

    fn parse_ber_at(ber: &mut Reader<'_>, depth: usize) -> Outcome<Filter> {
        if depth > MAX_FILTER_DEPTH {
            return Err(too_deep());
        }
        let start = ber.offset();
        let ty = ber.read_sequence(None)?;
        match ty {
            Some(t @ (0xa0 | 0xa1)) => {
                let end = ber.offset() + ber.length();
                let mut clauses = Vec::new();
                let limit = pass_limit(ber.buffer().len());
                while ber.offset() < end {
                    if clauses.len() > limit {
                        return Err(Fault::Stalled);
                    }
                    clauses.push(Filter::parse_ber_at(ber, depth + 1)?);
                }
                Ok(if t == 0xa0 {
                    Filter::And(clauses)
                } else {
                    Filter::Or(clauses)
                })
            }
            Some(0xa2) => {
                Ok(Filter::Not(Box::new(Filter::parse_ber_at(ber, depth + 1)?)))
            }
            Some(t @ (0xa8 | 0xa3 | 0xa9 | 0xa5 | 0xa6 | 0x87 | 0xa4)) => {
                ber.set_offset(start);
                let tag = ber.peek();
                let raw = ber.read_raw_buffer(tag)?;
                let Some(raw) = raw else {
                    return Err(Fault::thrown(
                        "Must supply a Buffer instance to read.",
                    ));
                };
                Filter::parse_leaf(t, raw)
            }
            Some(t) => Err(Fault::thrown(format!(
                "invalid search filter type: 0x{t:02x}"
            ))),
            None => Err(Fault::null_read("toString")),
        }
    }

    fn parse_leaf(kind: u8, raw: &[u8]) -> Outcome<Filter> {
        let mut r = Reader::new(raw);
        match kind {
            0x87 => {
                let tag = r.peek();
                if tag != Some(0x87) {
                    return Err(wrong_sequence("presence filter", 0x87, tag));
                }
                let attribute = attribute_of(r.read_string(0x87)?)?;
                Ok(Filter::Presence { attribute })
            }
            0xa3 => {
                let tag = r.read_sequence(None)?;
                if tag != Some(0xa3) {
                    return Err(wrong_sequence("equality filter", 0xa3, tag));
                }
                let attribute = r.read_string(0x04)?;
                let value = r.read_bytes(0x04)?;
                let attribute = attribute_of(attribute)?;
                let Some(raw) = value else {
                    return Err(Fault::thrown(
                        "must either provide a buffer via `raw` or some `value`",
                    ));
                };
                Ok(Filter::Equality { attribute, raw })
            }
            0xa5 | 0xa6 | 0xa8 => {
                let what = match kind {
                    0xa5 => "greater-than-equals filter",
                    0xa6 => "less-than-equals filter",
                    _ => "approximate filter",
                };
                let tag = r.read_sequence(None)?;
                if tag != Some(kind) {
                    return Err(wrong_sequence(what, kind, tag));
                }
                let attribute = r.read_string(0x04)?;
                let value = r.read_string(0x04)?;
                let attribute = attribute_of(attribute)?;
                let value = value_of(value)?;
                Ok(match kind {
                    0xa5 => Filter::GreaterOrEqual { attribute, value },
                    0xa6 => Filter::LessOrEqual { attribute, value },
                    _ => Filter::Approximate { attribute, value },
                })
            }
            0xa4 => {
                let tag = r.read_sequence(None)?;
                if tag != Some(0xa4) {
                    return Err(wrong_sequence("substring filter", 0xa4, tag));
                }
                let mut initial = JsStr::Undefined;
                let mut any = Vec::new();
                let mut last = JsStr::Undefined;
                let attribute = r.read_string(0x04)?;
                r.read_sequence(None)?;
                let end = r.offset() + r.length();
                let limit = pass_limit(raw.len());
                let mut passes = 0;
                while r.offset() < end {
                    passes += 1;
                    if passes > limit {
                        return Err(Fault::Stalled);
                    }
                    match r.peek() {
                        Some(0x80) => {
                            initial = JsStr::from_opt(r.read_string(0x80)?)
                        }
                        Some(0x81) => any.push(r.read_string(0x81)?),
                        Some(0x82) => {
                            last = JsStr::from_opt(r.read_string(0x82)?)
                        }
                        Some(t) => {
                            return Err(Fault::thrown(format!(
                                "Invalid substrings filter type: 0x{t:x}"
                            )))
                        }
                        None => return Err(Fault::null_read("toString")),
                    }
                }
                let attribute = attribute_of(attribute)?;
                Ok(Filter::Substring {
                    attribute,
                    initial,
                    any,
                    last,
                })
            }
            _ => {
                let tag = r.read_sequence(None)?;
                if tag != Some(0xa9) {
                    return Err(wrong_sequence("extensible filter", 0xa9, tag));
                }
                let mut rule = JsStr::Undefined;
                let mut attribute = JsStr::Undefined;
                let mut value = JsStr::Undefined;
                let mut dn = false;
                let end = raw.len() as i64;
                let limit = pass_limit(raw.len());
                let mut passes = 0;
                while r.offset() < end {
                    passes += 1;
                    if passes > limit {
                        return Err(Fault::Stalled);
                    }
                    match r.peek() {
                        Some(0x81) => {
                            rule = JsStr::from_opt(r.read_string(0x81)?)
                        }
                        Some(0x82) => {
                            attribute = JsStr::from_opt(r.read_string(0x82)?);
                        }
                        Some(0x83) => {
                            value = JsStr::from_opt(r.read_string(0x83)?)
                        }
                        Some(0x84) => dn = r.read_boolean(0x84)?,
                        Some(t) => {
                            return Err(Fault::thrown(format!(
                                "invalid extensible filter type: 0x{t:02x}"
                            )))
                        }
                        None => return Err(Fault::null_read("toString")),
                    }
                }
                Ok(Filter::Extensible {
                    attribute: match attribute {
                        JsStr::Undefined => Some(String::new()),
                        JsStr::Null => None,
                        JsStr::Str(s) => Some(s),
                    },
                    rule,
                    value: match value {
                        JsStr::Str(s) => s,
                        _ => String::new(),
                    },
                    dn_attributes: dn,
                })
            }
        }
    }

    /// `toBer()`.
    pub fn to_ber(&self) -> Outcome<Vec<u8>> {
        let mut w = Writer::new();
        self.write(&mut w, 0)?;
        Ok(w.into_bytes())
    }

    fn write(&self, w: &mut Writer, depth: usize) -> Outcome<()> {
        if depth > MAX_FILTER_DEPTH {
            return Err(too_deep());
        }
        w.start_sequence(self.tag());
        match self {
            Filter::And(c) | Filter::Or(c) => {
                for f in c {
                    f.write(w, depth + 1)?;
                }
            }
            Filter::Not(f) => f.write(w, depth + 1)?,
            Filter::Equality { attribute, raw } => {
                w.write_string(attribute, 0x04)?;
                w.write_buffer(raw, 0x04)?;
            }
            Filter::Presence { attribute } => {
                // `writeByte(attribute.charCodeAt(i))`: each UTF-16 code
                // unit's low byte, so a non-ASCII type is mangled.
                for u in attribute.encode_utf16() {
                    w.write_byte(u as u8);
                }
            }
            Filter::Substring {
                attribute,
                initial,
                any,
                last,
            } => {
                w.write_string(attribute, 0x04)?;
                w.start_sequence(0x30);
                if let Some(s) = initial.truthy() {
                    w.write_string(s, 0x80)?;
                }
                for a in any {
                    match a {
                        Some(s) => w.write_string(s, 0x81)?,
                        None => {
                            return Err(Fault::thrown(
                                "stringToWrite must be a string",
                            ))
                        }
                    }
                }
                if let Some(s) = last.truthy() {
                    w.write_string(s, 0x82)?;
                }
                w.end_sequence()?;
            }
            Filter::GreaterOrEqual { attribute, value }
            | Filter::LessOrEqual { attribute, value }
            | Filter::Approximate { attribute, value } => {
                w.write_string(attribute, 0x04)?;
                w.write_string(value, 0x04)?;
            }
            Filter::Extensible {
                attribute,
                rule,
                value,
                dn_attributes,
            } => {
                if let Some(r) = rule.truthy() {
                    w.write_string(r, 0x81)?;
                }
                if let Some(a) = attribute.as_deref().filter(|a| !a.is_empty())
                {
                    w.write_string(a, 0x82)?;
                }
                w.write_string(value, 0x83)?;
                if *dn_attributes {
                    w.write_boolean(true, 0x84);
                }
            }
        }
        w.end_sequence()
    }

    // ---- the string form ---------------------------------------------

    /// `toString()`.
    pub fn to_text(&self) -> Outcome<String> {
        self.text_at(0)
    }

    fn text_at(&self, depth: usize) -> Outcome<String> {
        if depth > MAX_FILTER_DEPTH {
            return Err(too_deep());
        }
        Ok(match self {
            Filter::And(c) | Filter::Or(c) => {
                let mut s = String::from(if matches!(self, Filter::And(_)) {
                    "(&"
                } else {
                    "(|"
                });
                for f in c {
                    s.push_str(&f.text_at(depth + 1)?);
                }
                s.push(')');
                s
            }
            Filter::Not(f) => format!("(!{})", f.text_at(depth + 1)?),
            Filter::Presence { attribute } => {
                format!("({}=*)", escape_str(attribute)?)
            }
            Filter::Equality { attribute, raw } => {
                let decoded = js::utf8(raw);
                let value = if decoded.len() == raw.len() {
                    escape_str(&decoded)?
                } else {
                    escape_bytes(raw)?
                };
                format!("({}={value})", escape_str(attribute)?)
            }
            Filter::Substring {
                attribute,
                initial,
                any,
                last,
            } => {
                let mut s = format!("({}=", escape_str(attribute)?);
                if let Some(i) = initial.truthy() {
                    s.push_str(&escape_str(i)?);
                }
                s.push('*');
                for a in any {
                    match a {
                        Some(a) => s.push_str(&escape_str(a)?),
                        None => {
                            return Err(Fault::thrown(
                                "toEscape must be a string or a Buffer",
                            ))
                        }
                    }
                    s.push('*');
                }
                if let Some(f) = last.truthy() {
                    s.push_str(&escape_str(f)?);
                }
                s.push(')');
                s
            }
            Filter::GreaterOrEqual { attribute, value } => {
                format!("({}>={})", escape_str(attribute)?, escape_str(value)?)
            }
            Filter::LessOrEqual { attribute, value } => {
                format!("({}<={})", escape_str(attribute)?, escape_str(value)?)
            }
            Filter::Approximate { attribute, value } => {
                format!("({}~={})", escape_str(attribute)?, escape_str(value)?)
            }
            Filter::Extensible {
                attribute,
                rule,
                value,
                dn_attributes,
            } => {
                let mut s = String::from("(");
                if let Some(a) = attribute.as_deref().filter(|a| !a.is_empty())
                {
                    s.push_str(a);
                }
                s.push(':');
                if *dn_attributes {
                    s.push_str("dn:");
                }
                if let Some(r) = rule.truthy() {
                    s.push_str(r);
                    s.push(':');
                }
                s.push('=');
                s.push_str(value);
                s.push(')');
                s
            }
        })
    }

    /// `parseString()`.
    pub fn parse(input: &str) -> Outcome<Filter> {
        if input.is_empty() {
            return Err(Fault::thrown("input string cannot be empty"));
        }
        let u = js::units(input);
        let normalized = if u[0] != u16::from(b'(') {
            let mut n = vec![u16::from(b'(')];
            n.extend_from_slice(&u);
            n.push(u16::from(b')'));
            n
        } else {
            u.clone()
        };
        let (end, filter) = parse_filter(&normalized, 0, 0)?;
        if (end as i64) < u.len() as i64 - 1 {
            return Err(Fault::thrown("unbalanced parentheses"));
        }
        Ok(filter)
    }
}

const fn ch(c: u8) -> u16 {
    c as u16
}

fn parse_filter(
    s: &[u16],
    start: usize,
    depth: usize,
) -> Outcome<(usize, Filter)> {
    if depth > MAX_FILTER_DEPTH {
        return Err(too_deep());
    }
    let len = s.len();
    let mut cur = start;
    if s.get(cur) != Some(&ch(b'(')) {
        return Err(Fault::thrown("missing opening parentheses"));
    }
    cur += 1;
    let output;
    match s.get(cur) {
        Some(&c) if c == ch(b'&') || c == ch(b'|') => {
            cur += 1;
            let and = c == ch(b'&');
            if and && s.get(cur) == Some(&ch(b')')) {
                output = Filter::And(Vec::new());
            } else {
                let mut children = Vec::new();
                loop {
                    let (end, f) = parse_filter(s, cur, depth + 1)?;
                    children.push(f);
                    cur = end + 1;
                    if !(cur < len && s[cur] != ch(b')')) {
                        break;
                    }
                }
                output = if and {
                    Filter::And(children)
                } else {
                    Filter::Or(children)
                };
            }
        }
        Some(&c) if c == ch(b'!') => {
            let (end, f) = parse_filter(s, cur + 1, depth + 1)?;
            output = Filter::Not(Box::new(f));
            cur = end + 1;
            if s.get(cur) != Some(&ch(b')')) {
                return Err(Fault::thrown("unbalanced parentheses"));
            }
        }
        _ => {
            let Some(end) = js::index_of(s, &[ch(b')')], cur) else {
                return Err(Fault::thrown("unbalanced parentheses"));
            };
            output = parse_expression(&s[cur..end])?;
            cur = end;
        }
    }
    Ok((cur, output))
}

fn parse_expression(input: &[u16]) -> Outcome<Filter> {
    if input.first() == Some(&ch(b':'))
        || js::index_of(input, &[ch(b':'), ch(b'=')], 0).is_some_and(|i| i > 0)
    {
        return parse_extensible(input);
    }
    let n = input
        .iter()
        .take_while(|&&u| {
            u < 0x80 && {
                let c = u as u8;
                c == b'-' || c == b'_' || c.is_ascii_alphanumeric()
            }
        })
        .count();
    if n == 0 {
        return Err(Fault::thrown("invalid attribute name"));
    }
    let attribute = js::from_units(&input[..n]);
    let rem = &input[n..];
    if rem == js::units("=*").as_slice() {
        return Ok(Filter::Presence { attribute });
    }
    let at = |i: usize| rem.get(i).copied();
    if at(0) == Some(ch(b'=')) {
        let rest = &rem[1..];
        if rest.contains(&ch(b'*')) {
            let (initial, any, last) = escape_substring(rest)?;
            return Ok(Filter::Substring {
                attribute,
                initial: JsStr::Str(initial),
                any: any.into_iter().map(Some).collect(),
                last: JsStr::Str(last),
            });
        }
        if rest.is_empty() {
            return Err(Fault::thrown(
                "must either provide a buffer via `raw` or some `value`",
            ));
        }
        return Ok(Filter::Equality {
            attribute,
            raw: js::from_units(rest).into_bytes(),
        });
    }
    let two = |a: u8| at(0) == Some(ch(a)) && at(1) == Some(ch(b'='));
    let value = || value_of(Some(js::from_units(rem.get(2..).unwrap_or(&[]))));
    if two(b'>') {
        return Ok(Filter::GreaterOrEqual {
            attribute,
            value: value()?,
        });
    }
    if two(b'<') {
        return Ok(Filter::LessOrEqual {
            attribute,
            value: value()?,
        });
    }
    if two(b'~') {
        return Ok(Filter::Approximate {
            attribute,
            value: value()?,
        });
    }
    Err(Fault::thrown("invalid expression"))
}

fn escape_substring(s: &[u16]) -> Outcome<(String, Vec<String>, String)> {
    let mut fields = js::split_units(s, ch(b'*'));
    if fields.len() <= 1 {
        return Err(Fault::thrown("extensible filter delimiter missing"));
    }
    let initial = escape_str(&js::from_units(&fields.remove(0)))?;
    let last = escape_str(&js::from_units(&fields.pop().unwrap_or_default()))?;
    let any = fields
        .iter()
        .map(|f| escape_str(&js::from_units(f)))
        .collect::<Outcome<Vec<_>>>()?;
    Ok((initial, any, last))
}

fn parse_extensible(input: &[u16]) -> Outcome<Filter> {
    let mut fields = js::split_units(input, ch(b':'));
    let attribute = escape_str(&js::from_units(&fields.remove(0)))?;
    let mut dn = false;
    let mut rule = JsStr::Undefined;
    if fields
        .first()
        .is_some_and(|f| js::from_units(f).to_lowercase() == "dn")
    {
        dn = true;
        fields.remove(0);
    }
    if !fields.is_empty() && fields[0].first() != Some(&ch(b'=')) {
        rule = JsStr::Str(js::from_units(&fields.remove(0)));
    }
    if fields.is_empty() || fields[0].first() != Some(&ch(b'=')) {
        return Err(Fault::thrown("missing := in extensible filter string"));
    }
    let joined = fields.join(&ch(b':'));
    let value = escape_str(&js::from_units(&joined[1..]))?;
    Ok(Filter::Extensible {
        attribute: Some(attribute),
        rule,
        value,
        dn_attributes: dn,
    })
}

/// `escapeFilterValue(string)`.
pub fn escape_str(s: &str) -> Outcome<String> {
    escape_bytes(s.as_bytes())
}

/// `escapeFilterValue(buffer)`.
pub fn escape_bytes(buf: &[u8]) -> Outcome<String> {
    let at = |i: usize| buf.get(i).copied();
    let undefined = || Fault::undefined_read("toString");
    let mut out = String::with_capacity(buf.len());
    let mut i = 0usize;
    while i < buf.len() {
        let b = buf[i];
        if (0xc0..=0xdf).contains(&b) {
            let n = at(i + 1).ok_or_else(undefined)?;
            out.push_str(&format!("\\{b:x}\\{n:x}"));
            i += 2;
            continue;
        }
        if (0xe0..=0xef).contains(&b) {
            let n1 = at(i + 1).ok_or_else(undefined)?;
            let n2 = at(i + 2).ok_or_else(undefined)?;
            out.push_str(&format!("\\{b:x}\\{n1:x}\\{n2:x}"));
            i += 3;
            continue;
        }
        if b <= 31 {
            out.push_str(&format!("\\{b:02x}"));
            i += 1;
            continue;
        }
        match b {
            b'*' => out.push_str("\\2a"),
            b'(' => out.push_str("\\28"),
            b')' => out.push_str("\\29"),
            b'\\' => {
                let chars = read_escaped(buf, i);
                i += chars.len();
                out.push_str(&chars.concat());
            }
            _ => out.push(char::from(b)),
        }
        i += 1;
    }
    Ok(out)
}

/// `readEscapedCharacters()`: what follows a backslash, as the pieces the
/// caller both joins and counts (the count is how far it skips).
fn read_escaped(buf: &[u8], start: usize) -> Vec<String> {
    let at = |i: usize| buf.get(i).copied();
    let mut chars = Vec::new();
    let mut i = start;
    // At the end of the buffer Node sets `chars[-1] = '\\5c'`: a
    // property, not an element, so nothing is added.
    while let Some(b) = at(i) {
        if b == 0x5c {
            chars.push("\\".to_string());
            i += 1;
            continue;
        }
        let pair: String =
            [js::from_char_code(Some(b)), js::from_char_code(at(i + 1))]
                .iter()
                .collect();
        let Some(code) = js::parse_int_hex(&pair) else {
            chars.push(format!("5c{pair}"));
            break;
        };
        if (0xc0..=0xdf).contains(&code) {
            chars.push(format!("{:0<2}", js::hex_js(code)));
            for x in i + 2..i + 4 {
                chars.push(js::from_char_code(at(x)).to_string());
            }
            break;
        }
        if (0xe0..=0xef).contains(&code) {
            chars.push(format!("{:0>2}", js::hex_js(code)));
            for x in i + 2..i + 8 {
                chars.push(js::from_char_code(at(x)).to_string());
            }
            break;
        }
        chars.push(format!("{:0>2}", js::hex_js(code)));
        break;
    }
    chars
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_as_node() {
        let f =
            Filter::parse("(&(objectClass=person)(|(uid=al*)(mail=*@x.com)))")
                .unwrap();
        assert_eq!(
            f.to_text().unwrap(),
            "(&(objectClass=person)(|(uid=al*)(mail=*@x.com)))"
        );
        assert_eq!(escape_str("a*b(c)d").unwrap(), "a\\2ab\\28c\\29d");
        assert_eq!(escape_str("x\\").unwrap(), "x\\");
        assert!(Filter::parse("(|)").is_err());
        assert!(Filter::parse("(&(a=1)").is_ok());
    }
}
