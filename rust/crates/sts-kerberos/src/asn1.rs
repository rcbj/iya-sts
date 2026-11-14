// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The DER subset Kerberos v5 uses: `kerberos/krb5_asn1.js`, ported as
//! the hand-written coder it is.
//!
//! **WHY NOT `rasn-kerberos`, which rust/DESIGN.md's Kerberos row names.**
//! The compatible-upgrade rule makes Node's verdicts the specification, and
//! a schema-driven decoder disagrees with this coder on inputs that occur:
//!
//! * a KerberosString may arrive as an IA5String (some encoders write one)
//!   and is read; a name that is not UTF-8 is read as Latin-1 rather than
//!   refused;
//! * the context-tagged fields of a SEQUENCE are read into a map by tag
//!   number, so their order is not checked and a duplicate's later copy
//!   wins;
//! * an INTEGER is at most six bytes, a length field at most four, the
//!   nesting at most 32 deep and a message at most 2 MiB — Node's limits,
//!   each with Node's sentence;
//! * an unknown field is skipped, not refused.
//!
//! Each of those would be a refusal (or a different refusal) in `rasn`,
//! and the KDC proxy and the debugger pages answer with the sentence. The
//! encoder side is the same story in reverse: a re-encode must be Node's
//! bytes, field for field. So the coder is ported, and the structures over
//! it are in [`crate::messages`].
//!
//! A HOT PATH: every field of every message passes through `read_tlv()`,
//! `tlv()` and the `dec_*` helpers, so they carry no `tracing::instrument`
//! — Node measured a 13x cost for logging them (`krb5_primitives.js`).

use std::collections::BTreeMap;

use serde::Serialize;

use crate::error::{Krb5Error, Krb5Result};
use crate::primitives;
use crate::time::KrbTime;

/// The largest input the readers will look at, as in Node: a TGS-REQ
/// with a large PAC is tens of kilobytes, so two megabytes is generous.
pub const MAX_INPUT_BYTES: usize = 2 * 1024 * 1024;
/// The deepest nesting a reader follows.
pub const MAX_DEPTH: usize = 32;

/// The universal tags this coder writes and reads.
pub mod tag {
    pub const BOOLEAN: u8 = 0x01;
    pub const INTEGER: u8 = 0x02;
    pub const BIT_STRING: u8 = 0x03;
    pub const OCTET_STRING: u8 = 0x04;
    pub const NULL: u8 = 0x05;
    pub const OBJECT_IDENTIFIER: u8 = 0x06;
    pub const ENUMERATED: u8 = 0x0a;
    pub const UTF8_STRING: u8 = 0x0c;
    pub const SEQUENCE: u8 = 0x30;
    pub const GENERAL_STRING: u8 = 0x1b;
    pub const IA5_STRING: u8 = 0x16;
    pub const GENERALIZED_TIME: u8 = 0x18;
}

/// `[n]` constructed, n 0–30: Node's `contextTag()`.
pub fn context_tag(n: u8) -> Krb5Result<u8> {
    if n > 30 {
        return Err(Krb5Error::new(format!(
            "krb5: context tag {} out of range for this coder",
            n
        )));
    }
    Ok(0xa0 | n)
}

/// `[APPLICATION n]` constructed: Node's `applicationTag()`.
pub fn application_tag(n: u8) -> Krb5Result<u8> {
    if n > 30 {
        return Err(Krb5Error::new(format!(
            "krb5: application tag {} out of range for this coder",
            n
        )));
    }
    Ok(0x60 | n)
}

/// A DER definite length: Node's `encodeLength()`. A value over four
/// gigabytes cannot reach it (nothing builds one), so it does not refuse.
pub fn encode_length(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let mut bytes = Vec::new();
    let mut v = n;
    while v > 0 {
        bytes.insert(0, (v & 0xff) as u8);
        v >>= 8;
    }
    let mut out = vec![0x80 | bytes.len() as u8];
    out.extend(bytes);
    out
}

/// One tag-length-value: Node's `tlv()`.
pub fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(encode_length(value.len()));
    out.extend_from_slice(value);
    out
}

/// The content octets of an INTEGER, minimal two's complement: Node's
/// `integerContent()`.
pub fn integer_content(value: i64) -> Vec<u8> {
    if value == 0 {
        return vec![0];
    }
    if value > 0 {
        let mut bytes = Vec::new();
        let mut v = value;
        while v > 0 {
            bytes.insert(0, (v & 0xff) as u8);
            v >>= 8;
        }
        if bytes[0] & 0x80 != 0 {
            bytes.insert(0, 0);
        }
        return bytes;
    }
    let mut n: u32 = 1;
    while n < 8 && (value as i128) < -(1i128 << (8 * n - 1)) {
        n += 1;
    }
    let m = (value as i128) + (1i128 << (8 * n));
    (0..n)
        .rev()
        .map(|i| ((m >> (8 * i)) & 0xff) as u8)
        .collect()
}

pub fn enc_integer(value: i64) -> Vec<u8> {
    tlv(tag::INTEGER, &integer_content(value))
}

pub fn enc_octet_string(bytes: &[u8]) -> Vec<u8> {
    tlv(tag::OCTET_STRING, bytes)
}

pub fn enc_general_string(text: &str) -> Vec<u8> {
    tlv(tag::GENERAL_STRING, &primitives::utf8(text))
}

/// KerberosFlags: a 32-bit BIT STRING with no unused bits, bit 0 the most
/// significant bit of the first byte: Node's `encFlags()`.
pub fn enc_flags(bits: &[u32]) -> Krb5Result<Vec<u8>> {
    let mut bytes = [0u8; 4];
    for &bit in bits {
        if bit > 31 {
            return Err(Krb5Error::new(format!(
                "krb5: flag bit {} out of range",
                bit
            )));
        }
        bytes[(bit >> 3) as usize] |= 0x80 >> (bit & 7);
    }
    let mut v = vec![0];
    v.extend_from_slice(&bytes);
    Ok(tlv(tag::BIT_STRING, &v))
}

/// The four flag bytes for some bit numbers: Node's `flagsFromBits()`.
pub fn flags_from_bits(bits: &[u32]) -> [u8; 4] {
    let mut bytes = [0u8; 4];
    for &bit in bits.iter().filter(|b| **b < 32) {
        bytes[(bit >> 3) as usize] |= 0x80 >> (bit & 7);
    }
    bytes
}

/// The bit numbers set in some flag bytes: Node's `bitsFromFlags()`.
pub fn bits_from_flags(bytes: &[u8]) -> Vec<u32> {
    (0..bytes.len() * 8)
        .filter(|i| bytes[i >> 3] & (0x80 >> (i & 7)) != 0)
        .map(|i| i as u32)
        .collect()
}

pub fn enc_kerberos_time(t: KrbTime) -> Vec<u8> {
    tlv(tag::GENERALIZED_TIME, t.format().as_bytes())
}

pub fn enc_sequence(items: &[Vec<u8>]) -> Vec<u8> {
    tlv(tag::SEQUENCE, &items.concat())
}

/// A SEQUENCE of explicitly context-tagged fields, absent ones skipped:
/// Node's `encTaggedSequence()`. The tag numbers are the callers' own
/// constants, all below 31.
pub fn enc_tagged_sequence(fields: &[(u8, Option<Vec<u8>>)]) -> Vec<u8> {
    let parts: Vec<Vec<u8>> = fields
        .iter()
        .filter_map(|(n, v)| v.as_ref().map(|v| tlv(0xa0 | (n & 0x1f), v)))
        .collect();
    enc_sequence(&parts)
}

pub fn enc_application(n: u8, inner: &[u8]) -> Vec<u8> {
    tlv(0x60 | (n & 0x1f), inner)
}

pub fn enc_context(n: u8, inner: &[u8]) -> Vec<u8> {
    tlv(0xa0 | (n & 0x1f), inner)
}

/// One element read: Node's `readTlv()` result, offsets into the buffer
/// it was read from.
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub length: usize,
    pub header_length: usize,
    pub start: usize,
    pub value_start: usize,
    pub end: usize,
    pub value: &'a [u8],
    pub raw: &'a [u8],
}

/// Node's `readTlv()`: one element at `at`, refusing the indefinite form
/// and a length past the end of the buffer.
pub fn read_tlv(b: &[u8], at: usize, depth: usize) -> Krb5Result<Tlv<'_>> {
    if depth > MAX_DEPTH {
        return Err(Krb5Error::new(format!(
            "krb5: ASN.1 nested deeper than {}",
            MAX_DEPTH
        )));
    }
    if at + 2 > b.len() {
        return Err(Krb5Error::new(format!(
            "krb5: truncated ASN.1 at offset {} (need a tag and a length)",
            at
        )));
    }
    let tag = b[at];
    let len_byte = b[at + 1];
    let (len, header_length) = if len_byte < 0x80 {
        (usize::from(len_byte), 2)
    } else if len_byte == 0x80 {
        return Err(Krb5Error::new(format!(
            "krb5: indefinite ASN.1 length at offset {} — DER requires a \
             definite length",
            at
        )));
    } else {
        let n = usize::from(len_byte & 0x7f);
        if n > 4 {
            return Err(Krb5Error::new(format!(
                "krb5: ASN.1 length field of {} bytes at offset {}",
                n, at
            )));
        }
        if at + 2 + n > b.len() {
            return Err(Krb5Error::new(format!(
                "krb5: truncated ASN.1 length at offset {}",
                at
            )));
        }
        let len = b[at + 2..at + 2 + n]
            .iter()
            .fold(0usize, |acc, x| acc * 256 + usize::from(*x));
        (len, 2 + n)
    };
    let value_start = at + header_length;
    let value_end = value_start + len;
    if value_end > b.len() {
        return Err(Krb5Error::new(format!(
            "krb5: ASN.1 element at offset {} claims {} bytes but only {} \
             remain",
            at,
            len,
            b.len() as i64 - value_start as i64
        )));
    }
    Ok(Tlv {
        tag,
        length: len,
        header_length,
        start: at,
        value_start,
        end: value_end,
        value: &b[value_start..value_end],
        raw: &b[at..value_end],
    })
}

/// Every element in some content octets: Node's `readChildren()`.
pub fn read_children(value: &[u8], depth: usize) -> Krb5Result<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < value.len() {
        let t = read_tlv(value, at, depth + 1)?;
        at = t.end;
        out.push(t);
    }
    Ok(out)
}

/// A SEQUENCE's context-tagged fields by number, each unwrapped to the one
/// element it carries: Node's `readTaggedSequence()`. A later duplicate
/// wins, as it does in Node's object.
#[derive(Debug, Clone, Default)]
pub struct Fields<'a> {
    map: BTreeMap<u8, Tlv<'a>>,
}

impl<'a> Fields<'a> {
    /// The field, if present.
    pub fn get(&self, n: u8) -> Option<&Tlv<'a>> {
        self.map.get(&n)
    }

    /// A required field whose reader first reads its `tag` (every `dec_*`
    /// helper); absent, Node's `TypeError`.
    pub fn tag_of(&self, n: u8) -> Krb5Result<&Tlv<'a>> {
        self.map.get(&n).ok_or_else(|| Krb5Error::missing("tag"))
    }

    /// A required field whose reader first reads its `value` (every
    /// structure reader).
    pub fn value_of(&self, n: u8) -> Krb5Result<&Tlv<'a>> {
        self.map.get(&n).ok_or_else(|| Krb5Error::missing("value"))
    }

    /// The tag numbers present.
    pub fn numbers(&self) -> Vec<u8> {
        self.map.keys().copied().collect()
    }
}

pub fn read_tagged_sequence(
    value: &[u8],
    depth: usize,
) -> Krb5Result<Fields<'_>> {
    let mut map = BTreeMap::new();
    for child in read_children(value, depth)? {
        if child.tag & 0xc0 != 0x80 {
            return Err(Krb5Error::new(format!(
                "krb5: expected a context tag in this SEQUENCE, saw 0x{:x}",
                child.tag
            )));
        }
        let n = child.tag & 0x1f;
        let inner = read_children(child.value, depth + 1)?;
        if inner.len() != 1 {
            return Err(Krb5Error::new(format!(
                "krb5: context tag [{}] wraps {} elements, expected 1",
                n,
                inner.len()
            )));
        }
        map.insert(n, inner[0]);
    }
    Ok(Fields { map })
}

/// Node's `expectTag()`.
pub fn expect_tag<'a>(t: &Tlv<'a>, tag: u8, what: &str) -> Krb5Result<()> {
    if t.tag != tag {
        return Err(Krb5Error::new(format!(
            "krb5: expected {} (tag 0x{:x}) but found tag 0x{:x}",
            what, tag, t.tag
        )));
    }
    Ok(())
}

/// The value of INTEGER content octets, at most six (Node's range).
fn integer_of(b: &[u8]) -> Krb5Result<i64> {
    if b.is_empty() {
        return Err(Krb5Error::new("krb5: zero-length INTEGER"));
    }
    if b.len() > 6 {
        return Err(Krb5Error::new(format!(
            "krb5: INTEGER of {} bytes is out of range for this coder",
            b.len()
        )));
    }
    let v = b.iter().fold(0i64, |acc, x| acc * 256 + i64::from(*x));
    Ok(if b[0] & 0x80 != 0 {
        v - (1i64 << (8 * b.len()))
    } else {
        v
    })
}

/// Node's `decInteger()`.
pub fn dec_integer(t: &Tlv<'_>) -> Krb5Result<i64> {
    expect_tag(t, tag::INTEGER, "an INTEGER")?;
    integer_of(t.value)
}

/// `decInteger()` over content read under another tag — what Node does
/// for an ENUMERATED by handing it `{tag: INTEGER, value}`.
pub fn dec_integer_content(value: &[u8]) -> Krb5Result<i64> {
    integer_of(value)
}

/// Node's `decOctetString()`.
pub fn dec_octet_string<'a>(t: &Tlv<'a>) -> Krb5Result<&'a [u8]> {
    expect_tag(t, tag::OCTET_STRING, "an OCTET STRING")?;
    Ok(t.value)
}

/// Node's `decGeneralString()`: a GeneralString or an IA5String, UTF-8
/// when it is UTF-8 and Latin-1 when it is not.
pub fn dec_general_string(t: &Tlv<'_>) -> Krb5Result<String> {
    if t.tag != tag::GENERAL_STRING && t.tag != tag::IA5_STRING {
        expect_tag(t, tag::GENERAL_STRING, "a KerberosString")?;
    }
    Ok(primitives::from_utf8(t.value)
        .unwrap_or_else(|| primitives::latin1(t.value)))
}

/// Node's `decKerberosTime()`.
pub fn dec_kerberos_time(t: &Tlv<'_>) -> Krb5Result<KrbTime> {
    expect_tag(t, tag::GENERALIZED_TIME, "a KerberosTime")?;
    KrbTime::parse(&primitives::latin1(t.value))
}

/// Node's `decFlags()`: the bytes after the unused-bits octet.
pub fn dec_flags<'a>(t: &Tlv<'a>) -> Krb5Result<&'a [u8]> {
    expect_tag(t, tag::BIT_STRING, "a KerberosFlags BIT STRING")?;
    if t.value.is_empty() {
        return Err(Krb5Error::new("krb5: empty BIT STRING"));
    }
    Ok(&t.value[1..])
}

/// Node's `decSequenceOf()`. Its children are read at depth one, as
/// Node's `readChildren(t.value)` reads them with no depth given.
pub fn dec_sequence_of<'a>(t: &Tlv<'a>) -> Krb5Result<Vec<Tlv<'a>>> {
    expect_tag(t, tag::SEQUENCE, "a SEQUENCE")?;
    read_children(t.value, 0)
}

/// An `[APPLICATION n]` message unwrapped: Node's `readApplication()`.
#[derive(Debug, Clone, Copy)]
pub struct Application<'a> {
    pub number: u8,
    pub sequence: Tlv<'a>,
    pub outer: Tlv<'a>,
}

pub fn read_application(
    b: &[u8],
    expected: Option<u8>,
) -> Krb5Result<Application<'_>> {
    if b.len() > MAX_INPUT_BYTES {
        return Err(Krb5Error::new(format!(
            "krb5: refusing to parse {} bytes (limit {})",
            b.len(),
            MAX_INPUT_BYTES
        )));
    }
    let outer = read_tlv(b, 0, 0)?;
    if outer.tag & 0xe0 != 0x60 {
        return Err(Krb5Error::new(format!(
            "krb5: not a Kerberos message — the outermost tag is 0x{:x}, \
             expected an [APPLICATION n] constructed tag (0x60-0x7e)",
            outer.tag
        )));
    }
    let number = outer.tag & 0x1f;
    if let Some(e) = expected {
        if number != e {
            return Err(Krb5Error::new(format!(
                "krb5: expected [APPLICATION {}] but found [APPLICATION {}]",
                e, number
            )));
        }
    }
    let inner = read_children(outer.value, 1)?;
    if inner.len() != 1 {
        return Err(Krb5Error::new(format!(
            "krb5: [APPLICATION {}] wraps {} elements, expected 1",
            number,
            inner.len()
        )));
    }
    expect_tag(
        &inner[0],
        tag::SEQUENCE,
        &format!("the SEQUENCE inside [APPLICATION {}]", number),
    )?;
    Ok(Application {
        number,
        sequence: inner[0],
        outer,
    })
}

/// The application number of the outermost tag, or `None`: Node's
/// `peekApplicationNumber()`.
pub fn peek_application_number(b: &[u8]) -> Option<u8> {
    if b.len() < 2 || b[0] & 0xe0 != 0x60 {
        return None;
    }
    Some(b[0] & 0x1f)
}

fn tag_name(tag: u8) -> Option<&'static str> {
    Some(match tag {
        0x01 => "BOOLEAN",
        0x02 => "INTEGER",
        0x03 => "BIT STRING",
        0x04 => "OCTET STRING",
        0x05 => "NULL",
        0x06 => "OBJECT IDENTIFIER",
        0x0c => "UTF8String",
        0x10 | 0x30 => "SEQUENCE",
        0x11 | 0x31 => "SET",
        0x13 => "PrintableString",
        0x16 => "IA5String",
        0x17 => "UTCTime",
        0x18 => "GeneralizedTime",
        0x1b => "GeneralString",
        _ => return None,
    })
}

/// A tag for a human: Node's `describeTag()`.
pub fn describe_tag(tag: u8) -> String {
    let number = tag & 0x1f;
    match tag & 0xc0 {
        0x00 => tag_name(tag)
            .or_else(|| tag_name(number))
            .map(str::to_string)
            .unwrap_or_else(|| format!("universal {}", number)),
        0x40 => format!("[APPLICATION {}]", number),
        0x80 => format!("[{}]", number),
        _ => format!(
            "[PRIVATE {}]{}",
            number,
            if tag & 0x20 != 0 { "" } else { " primitive" }
        ),
    }
}

fn looks_constructed(t: &Tlv<'_>) -> bool {
    if t.tag & 0x20 == 0 || t.length == 0 {
        return false;
    }
    match read_children(t.value, 0) {
        Ok(children) => children
            .last()
            .map(|c| c.end == t.value.len())
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// One node of [`tree()`]: Node's shape, `children` or `text`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeNode {
    pub tag: u8,
    pub tag_name: String,
    pub offset: usize,
    pub length: usize,
    #[serde(serialize_with = "crate::hex::ser")]
    pub bytes: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children: Option<Vec<TreeNode>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth_limited: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// The generic TLV tree a debugger draws when no message reader applies:
/// Node's `tree()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn tree(b: &[u8], depth: usize) -> Krb5Result<Vec<TreeNode>> {
    if b.len() > MAX_INPUT_BYTES {
        return Err(Krb5Error::new(format!(
            "krb5: refusing to parse {} bytes (limit {})",
            b.len(),
            MAX_INPUT_BYTES
        )));
    }
    let mut out = Vec::new();
    let mut at = 0;
    while at < b.len() {
        let t = read_tlv(b, at, depth)?;
        let mut node = TreeNode {
            tag: t.tag,
            tag_name: describe_tag(t.tag),
            offset: t.start,
            length: t.length,
            bytes: t.value.to_vec(),
            children: None,
            depth_limited: None,
            text: None,
        };
        if looks_constructed(&t) {
            if depth < MAX_DEPTH {
                node.children = Some(tree(t.value, depth + 1)?);
            } else {
                node.depth_limited = Some(true);
                node.text = Some(format!(
                    "(nesting deeper than {} levels — not expanded; {} \
                     bytes)",
                    MAX_DEPTH, t.length
                ));
            }
        } else {
            node.text = Some(render_primitive(&t));
        }
        out.push(node);
        at = t.end;
    }
    Ok(out)
}

fn render_primitive(t: &Tlv<'_>) -> String {
    let rendered = match t.tag {
        tag::INTEGER => dec_integer(t).ok().map(|v| v.to_string()),
        tag::GENERAL_STRING | tag::IA5_STRING => Some(
            primitives::from_utf8(t.value)
                .unwrap_or_else(|| primitives::latin1(t.value)),
        ),
        tag::GENERALIZED_TIME => Some(primitives::latin1(t.value)),
        tag::BIT_STRING if t.value.len() == 5 => {
            let bits: Vec<String> = bits_from_flags(&t.value[1..])
                .iter()
                .map(u32::to_string)
                .collect();
            Some(format!(
                "bits set: {}",
                if bits.is_empty() {
                    "(none)".to_string()
                } else {
                    bits.join(", ")
                }
            ))
        }
        _ => None,
    };
    if let Some(r) = rendered {
        return r;
    }
    let hex = primitives::to_hex(t.value);
    if hex.len() > 128 {
        format!("{}… ({} bytes)", &hex[..128], t.value.len())
    } else {
        hex
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_round_trip_as_node_writes_them() {
        for (v, want) in [
            (0i64, "00"),
            (127, "7f"),
            (128, "0080"),
            (-1, "ff"),
            (-128, "80"),
            (-129, "ff7f"),
            (-138, "ff76"),
            (0x7fff_ffff, "7fffffff"),
            (0xffff_ffff, "00ffffffff"),
        ] {
            assert_eq!(primitives::to_hex(&integer_content(v)), want, "{}", v);
            let enc = enc_integer(v);
            let t = read_tlv(&enc, 0, 0).unwrap();
            assert_eq!(dec_integer(&t).unwrap(), v);
        }
    }

    #[test]
    fn lengths_and_refusals() {
        assert_eq!(encode_length(300), vec![0x82, 0x01, 0x2c]);
        assert!(read_tlv(&[0x30, 0x80], 0, 0).is_err());
        assert_eq!(
            read_tlv(&[0x30, 0x05, 0x00], 0, 0).unwrap_err().message(),
            "krb5: ASN.1 element at offset 0 claims 5 bytes but only 1 remain"
        );
    }
}
