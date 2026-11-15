// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Distinguished names as `@ldapjs/dn` 1.1.0 parses, prints and compares
//! them — which is what decides whether a bind, add, compare, delete,
//! modify or modify-DN is answered `invalidDNSyntax` and what DN string a
//! handler sees. RFC 4514 is the reference this is NOT: the library
//!
//! * parses the UTF-8 bytes of the string: leading spaces and commas are
//!   skipped before a name, `;` separates RDNs as `,` does, a value is
//!   trimmed with JavaScript's white space, `"…"` quotes a value, `#…` is
//!   hex (kept as bytes), and `\XX` escapes are decoded through
//!   `parseInt(…, 16)`, which reads a leading hex run (`\4,` is 0x04);
//! * orders a multi-valued RDN as a JavaScript object orders its keys —
//!   names that are array indices (`1`, `12`) first, ascending, then the
//!   rest as written — and keeps the last value of a repeated name;
//! * prints with `escapeValue()`: `" + , ; < >`, a leading space or `#`,
//!   a trailing space, controls and every non-ASCII byte as `\xx`, but
//!   NOT `\` or `=`, so `cn=back\\slash` prints as `cn=back\slash`;
//! * compares names and values case-sensitively, and a `#…` value equal
//!   to nothing (it is an object, compared by identity);
//! * skips spaces between a `#…` value (which ends at a space) and the
//!   separator, and throws on anything else there (`cn=#4142 x`): the
//!   `rcbj/node-ldapjs` fork's fix (#1784) of a loop that never finished.
//!
//! Its functions are a hot path — every DN of every request — and carry
//! no span (rust/DESIGN.md D3, section 4.5).

use crate::fault::{Fault, Outcome};
use crate::js;

/// One attribute value of an RDN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RdnValue {
    /// A string value, unescaped and trimmed.
    Text(String),
    /// A `#…` value: the bytes the hex spelled (a `BerReader` in Node).
    Hex(Vec<u8>),
}

/// A relative distinguished name: its attributes in the library's order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Rdn {
    attrs: Vec<(String, RdnValue)>,
}

/// A distinguished name.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Dn {
    rdns: Vec<Rdn>,
}

/// Whether a key is an array index, which a JavaScript object enumerates
/// first and in numeric order.
fn is_array_index(k: &str) -> bool {
    if k == "0" {
        return true;
    }
    let b = k.as_bytes();
    if b.is_empty()
        || !(b'1'..=b'9').contains(&b[0])
        || !b.iter().all(u8::is_ascii_digit)
    {
        return false;
    }
    k.parse::<u64>().map(|n| n < 4_294_967_295).unwrap_or(false)
}

/// The plain object `{ ...rdn, ...pair }` builds, in the order
/// `Object.entries()` will give back.
#[derive(Default)]
struct PlainObject {
    entries: Vec<(String, RdnValue)>,
}

impl PlainObject {
    fn set(&mut self, k: String, v: RdnValue) {
        if let Some(e) = self.entries.iter_mut().find(|e| e.0 == k) {
            e.1 = v;
        } else {
            self.entries.push((k, v));
        }
    }

    fn into_entries(self) -> Vec<(String, RdnValue)> {
        let (mut idx, rest): (Vec<_>, Vec<_>) =
            self.entries.into_iter().partition(|e| is_array_index(&e.0));
        idx.sort_by_key(|e| e.0.parse::<u64>().unwrap_or(0));
        idx.extend(rest);
        idx
    }
}

fn is_dotted_decimal(v: &str) -> bool {
    v.split('.')
        .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

impl Rdn {
    /// `setAttribute()`'s check on a name, the one `new RDN()` makes.
    fn from_entries(entries: Vec<(String, RdnValue)>) -> Outcome<Rdn> {
        let mut rdn = Rdn::default();
        for (name, value) in entries {
            let alpha =
                name.as_bytes().first().is_some_and(u8::is_ascii_alphabetic);
            if !alpha && !is_dotted_decimal(&name) {
                return Err(Fault::thrown(
                    "attribute name must start with an ASCII alpha character \
                     or be a numeric OID",
                ));
            }
            if let Some(e) = rdn.attrs.iter_mut().find(|e| e.0 == name) {
                e.1 = value;
            } else {
                rdn.attrs.push((name, value));
            }
        }
        Ok(rdn)
    }

    /// An RDN of one attribute, as `new RDN({ cn: 'anonymous' })`.
    pub fn single(name: &str, value: &str) -> Rdn {
        Rdn {
            attrs: vec![(name.to_string(), RdnValue::Text(value.to_string()))],
        }
    }

    /// The attributes, in order.
    pub fn attributes(&self) -> &[(String, RdnValue)] {
        &self.attrs
    }

    pub fn size(&self) -> usize {
        self.attrs.len()
    }

    /// `RDN.equals()`: the same names with strictly equal values; a hex
    /// value equals nothing.
    pub fn equals(&self, other: &Rdn) -> bool {
        if self.size() != other.size() {
            return false;
        }
        self.attrs.iter().all(|(k, v)| {
            other.attrs.iter().any(|(ok, ov)| {
                ok == k
                    && matches!((v, ov),
                        (RdnValue::Text(a), RdnValue::Text(b)) if a == b)
            })
        })
    }

    /// `RDN.toString()`.
    pub fn to_text(&self) -> String {
        let mut parts = Vec::with_capacity(self.attrs.len());
        for (name, value) in &self.attrs {
            let v = match value {
                RdnValue::Text(t) if is_hex_encoded(t) => t.clone(),
                RdnValue::Hex(b) => format!("#{}", js::hex(b)),
                RdnValue::Text(t) => escape_value(t),
            };
            parts.push(format!("{name}={v}"));
        }
        parts.join("+")
    }
}

/// `/^#([0-9a-fA-F]{2})+$/`.
fn is_hex_encoded(v: &str) -> bool {
    let b = v.as_bytes();
    b.len() >= 3
        && b[0] == b'#'
        && (b.len() - 1) % 2 == 0
        && b[1..].iter().all(u8::is_ascii_hexdigit)
}

/// `@ldapjs/dn`'s `escapeValue()`.
pub fn escape_value(value: &str) -> String {
    let b = value.as_bytes();
    let n = b.len();
    let mut out = String::with_capacity(n);
    let esc = |out: &mut String, c: u8| out.push_str(&format!("\\{c:02x}"));
    let mut i = 0;
    while i < n {
        let c = b[i];
        if i == 0 && (c == 0x20 || c == 0x23) {
            esc(&mut out, c);
            i += 1;
            continue;
        }
        if i == n - 1 && c == 0x20 {
            esc(&mut out, c);
            i += 1;
            continue;
        }
        if matches!(c, 0x22 | 0x2b | 0x2c | 0x3b | 0x3c | 0x3e) {
            esc(&mut out, c);
            i += 1;
            continue;
        }
        let width = match c {
            0xc0..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf7 => 4,
            _ => 0,
        };
        if width > 0 {
            // A Rust string is valid UTF-8, so the continuation bytes are
            // there (Node's `toEscapedHexString(undefined)` is not
            // reachable from a string).
            for k in 0..width {
                if let Some(&x) = b.get(i + k) {
                    esc(&mut out, x);
                }
            }
            i += width;
            continue;
        }
        if c <= 31 {
            esc(&mut out, c);
            i += 1;
            continue;
        }
        out.push(char::from(c));
        i += 1;
    }
    out
}

fn is_value_end(c: Option<u8>) -> bool {
    matches!(c, Some(0x2b | 0x2c | 0x3b))
}

struct Parser<'a> {
    b: &'a [u8],
}

impl Parser<'_> {
    fn len(&self) -> i64 {
        self.b.len() as i64
    }

    fn at(&self, i: i64) -> Option<u8> {
        if i >= 0 && i < self.len() {
            Some(self.b[i as usize])
        } else {
            None
        }
    }

    fn find_name_start(&self, mut pos: i64) -> i64 {
        while pos < self.len() {
            let c = self.b[pos as usize];
            if c == 0x20 || c == 0x2c {
                pos += 1;
                continue;
            }
            if c.is_ascii_alphanumeric() {
                return pos;
            }
            break;
        }
        -1
    }

    fn find_name_end(&self, mut pos: i64) -> i64 {
        while pos < self.len() {
            let c = self.b[pos as usize];
            if c == 0x20 || c == 0x3d {
                break;
            }
            if c.is_ascii_alphanumeric() || c == 0x2d || c == 0x2e {
                pos += 1;
                continue;
            }
            return -1;
        }
        pos
    }

    fn read_attribute_pair(
        &self,
        pos: i64,
    ) -> Outcome<(i64, String, RdnValue)> {
        let start = self.find_name_start(pos);
        if start < 0 {
            return Err(Fault::thrown(
                "invalid attribute name leading character encountered",
            ));
        }
        // Node checks the start a second time where it meant the end, so
        // an invalid character leaves the end at -1: the name runs to the
        // last byte but one, and the value is read from -1, which fails.
        let end = self.find_name_end(start);
        let name = js::utf8(js::subarray(self.b, start, end));
        if !valid_attribute_type_name(&name) {
            return Err(Fault::thrown(format!(
                "invalid attribute type name: {name}"
            )));
        }
        let (end_pos, value) = self.read_attribute_value(end)?;
        Ok((end_pos, name, value))
    }

    fn read_attribute_value(&self, start: i64) -> Outcome<(i64, RdnValue)> {
        let mut pos = start;
        while pos < self.len() && self.at(pos) == Some(0x20) {
            pos += 1;
        }
        if pos >= self.len() || self.at(pos) != Some(0x3d) {
            return Err(Fault::thrown(
                "attribute value does not start with equals sign",
            ));
        }
        pos += 1;
        while pos <= self.len() && self.at(pos) == Some(0x20) {
            pos += 1;
        }
        if pos >= self.len() {
            return Ok((pos, RdnValue::Text(String::new())));
        }
        if self.at(pos) == Some(0x23) {
            let (end, bytes) = self.read_hex_string(pos + 1)?;
            return Ok((end, RdnValue::Hex(bytes)));
        }
        let (end, bytes) = self.read_value_string(pos)?;
        Ok((end, RdnValue::Text(js::trim(&js::utf8(&bytes)).to_string())))
    }

    fn read_hex_string(&self, start: i64) -> Outcome<(i64, Vec<u8>)> {
        let mut pos = start;
        let mut bytes = Vec::new();
        while pos < self.len() {
            if matches!(self.at(pos), Some(0x20 | 0x2b | 0x2c | 0x3b)) {
                break;
            }
            let pair: String = [
                js::from_char_code(self.at(pos)),
                js::from_char_code(self.at(pos + 1)),
            ]
            .iter()
            .collect();
            if !pair.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(Fault::thrown(format!(
                    "invalid hex pair encountered: 0x{pair}"
                )));
            }
            bytes.push(js::to_uint8(js::parse_int_hex(&pair)));
            pos += 2;
        }
        Ok((pos, bytes))
    }

    fn read_value_string(&self, start: i64) -> Outcome<(i64, Vec<u8>)> {
        let mut pos = start;
        let mut in_quotes = false;
        // Node's `endQuotePresent`: set only on the way out of the loop.
        let end_quote = false;
        let mut bytes = Vec::new();
        while pos <= self.len() {
            if pos == self.len() {
                if in_quotes && !end_quote {
                    return Err(Fault::thrown(
                        "missing ending double quote for attribute value",
                    ));
                }
                break;
            }
            let c = self.b[pos as usize];
            if c == 0x22 {
                if in_quotes {
                    pos += 1;
                    while pos < self.len() {
                        let n = self.at(pos);
                        if is_value_end(n) {
                            break;
                        }
                        if n != Some(0x20) {
                            return Err(Fault::thrown(format!(
                                "significant rdn character found outside of \
                                 quotes at position {pos}"
                            )));
                        }
                        pos += 1;
                    }
                    break;
                }
                if pos != start {
                    return Err(Fault::thrown(format!(
                        "unexpected quote (\") in rdn string at position {pos}"
                    )));
                }
                in_quotes = true;
                pos += 1;
                continue;
            }
            if is_value_end(Some(c)) && !in_quotes {
                break;
            }
            if c == 0x5c {
                let (end, parsed) = self.read_escape_sequence(pos)?;
                pos = end;
                bytes.extend(parsed);
                continue;
            }
            bytes.push(c);
            pos += 1;
        }
        Ok((pos, bytes))
    }

    fn hex_at(&self, a: i64) -> Option<i64> {
        let s: String = [
            js::from_char_code(self.at(a)),
            js::from_char_code(self.at(a + 1)),
        ]
        .iter()
        .collect();
        js::parse_int_hex(&s)
    }

    fn read_escape_sequence(&self, start: i64) -> Outcome<(i64, Vec<u8>)> {
        let mut pos = start;
        let mut out = Vec::new();
        while pos < self.len() {
            if self.at(pos) != Some(0x5c) {
                break;
            }
            let next = self.at(pos + 1);
            let Some(code) = self.hex_at(pos + 1) else {
                match next {
                    Some(n) if n <= 0x7f => {
                        out.push(n);
                        pos += 2;
                        continue;
                    }
                    _ => {
                        return Err(Fault::thrown(
                            "invalid hex code in escape sequence",
                        ))
                    }
                }
            };
            let extra: &[i64] = match code {
                0xc0..=0xdf => &[4],
                0xe0..=0xef => &[4, 7],
                0xf0..=0xf7 => &[4, 7, 10],
                _ => &[],
            };
            out.push(js::to_uint8(Some(code)));
            for &k in extra {
                out.push(js::to_uint8(self.hex_at(pos + k)));
            }
            pos += 3 + 3 * extra.len() as i64;
        }
        Ok((pos, out))
    }
}

/// `isValidAttributeTypeName()`. `name[0]` of an empty name is
/// `undefined`, which `/[a-zA-Z]/` reads as the string "undefined" and
/// passes.
fn valid_attribute_type_name(name: &str) -> bool {
    match name.chars().next() {
        Some(c) if c.is_ascii_digit() => {
            !name.chars().any(|c| c.is_ascii_alphabetic() || c == '-')
        }
        Some(c) if !c.is_ascii_alphabetic() => false,
        _ => !name
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || c == '-')),
    }
}

impl Dn {
    /// `DN.fromString()`.
    pub fn parse(input: &str) -> Outcome<Dn> {
        let p = Parser {
            b: input.as_bytes(),
        };
        let length = p.len();
        let mut rdns: Vec<PlainObject> = Vec::new();
        if length == 0 {
            return Ok(Dn::default());
        }
        let mut pos: i64 = 0;
        let mut rdn = PlainObject::default();
        'rdns: while pos <= length {
            if pos == length {
                let c = p.at(pos - 1).unwrap_or(0);
                if matches!(c, 0x2b | 0x2c | 0x3b) {
                    return Err(Fault::thrown(format!(
                        "rdn string ends abruptly with character: {}",
                        char::from(c)
                    )));
                }
            }
            while pos < length && p.at(pos) == Some(0x20) {
                pos += 1;
            }
            let (end, name, value) = p.read_attribute_pair(pos)?;
            pos = end;
            rdn.set(name, value);
            if pos >= length {
                rdns.push(rdn);
                break;
            }
            // The fork's inner loop (`iya-sts:` in `parse-string/index.js`):
            // a separator, a space before one, or a throw. `pos < length`
            // holds on every pass, so a byte is always there.
            loop {
                match p.at(pos) {
                    Some(0x2b) => {
                        pos += 1;
                        continue 'rdns;
                    }
                    Some(0x2c | 0x3b) => {
                        rdns.push(std::mem::take(&mut rdn));
                        pos += 1;
                        continue 'rdns;
                    }
                    Some(0x20) => {
                        pos += 1;
                        if pos == length {
                            rdns.push(std::mem::take(&mut rdn));
                            break 'rdns;
                        }
                    }
                    // `String.fromCharCode()` of the byte: Latin-1.
                    c => {
                        return Err(Fault::thrown(format!(
                            "unexpected character after attribute value at \
                             position {pos}: {}",
                            char::from(c.unwrap_or(0))
                        )))
                    }
                }
            }
        }
        let rdns = rdns
            .into_iter()
            .map(|o| Rdn::from_entries(o.into_entries()))
            .collect::<Outcome<Vec<_>>>()?;
        Ok(Dn { rdns })
    }

    /// `DN.fromString()` of what may be `null`: Node throws
    /// `input must be a string`.
    pub fn parse_nullable(input: Option<&str>) -> Outcome<Dn> {
        match input {
            Some(s) => Dn::parse(s),
            None => Err(Fault::thrown("input must be a string")),
        }
    }

    /// The anonymous DN the server binds a connection as, `cn=anonymous`.
    pub fn anonymous() -> Dn {
        Dn {
            rdns: vec![Rdn::single("cn", "anonymous")],
        }
    }

    pub fn len(&self) -> usize {
        self.rdns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rdns.is_empty()
    }

    pub fn rdns(&self) -> &[Rdn] {
        &self.rdns
    }

    /// `DN.toString()`.
    pub fn to_text(&self) -> String {
        self.rdns
            .iter()
            .map(Rdn::to_text)
            .collect::<Vec<_>>()
            .join(",")
    }

    pub fn equals(&self, other: &Dn) -> bool {
        self.len() == other.len()
            && self.rdns.iter().zip(&other.rdns).all(|(a, b)| a.equals(b))
    }

    /// `parentOf()`: a proper suffix, RDN by RDN.
    pub fn parent_of(&self, other: &Dn) -> bool {
        if self.len() >= other.len() {
            return false;
        }
        let diff = other.len() - self.len();
        (0..self.len()).all(|i| self.rdns[i].equals(&other.rdns[i + diff]))
    }

    pub fn child_of(&self, other: &Dn) -> bool {
        other.parent_of(self)
    }
}

impl std::fmt::Display for Dn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_text())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prints_as_node_does() {
        let dn = Dn::parse("  cn = a , dc=x  ").unwrap();
        assert_eq!(dn.to_text(), "cn=a,dc=x");
        let dn = Dn::parse("cn=back\\\\slash").unwrap();
        assert_eq!(dn.to_text(), "cn=back\\slash");
        assert_eq!(
            Dn::parse("1=a+cn=b+0=c").unwrap().to_text(),
            "0=c+1=a+cn=b"
        );
        assert_eq!(
            Dn::parse("cn=#4142 ,o=x").unwrap().to_text(),
            "cn=#4142,o=x"
        );
        assert_eq!(
            Dn::parse("cn=#4142  ").unwrap().to_text(),
            Dn::parse("cn=#4142").unwrap().to_text()
        );
        assert_eq!(
            Dn::parse("cn=#4142 x"),
            Err(Fault::thrown(
                "unexpected character after attribute value at position 9: x"
            ))
        );
    }
}
