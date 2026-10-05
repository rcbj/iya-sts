// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The few DER shapes the key encodings here need — a SEQUENCE, an OBJECT
//! IDENTIFIER, an INTEGER, a BIT STRING, an OCTET STRING, a NULL and a
//! context tag — written and read, and nothing else. DER is canonical, so
//! what this writes is byte for byte what any correct encoder writes (the
//! vectors hold it to asn1js's); certificates and the rest of X.509 belong
//! to `sts-pki` and its libraries.

use crate::error::{CryptoError, CryptoResult};

pub const SEQUENCE: u8 = 0x30;
pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const NULL: u8 = 0x05;
pub const OID: u8 = 0x06;

fn length(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let bytes: Vec<u8> = n
        .to_be_bytes()
        .iter()
        .copied()
        .skip_while(|&b| b == 0)
        .collect();
    let mut out = vec![0x80 | bytes.len() as u8];
    out.extend(bytes);
    out
}

/// One TLV.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(length(content.len()));
    out.extend_from_slice(content);
    out
}

pub fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(SEQUENCE, &parts.concat())
}

/// A non-negative INTEGER from big-endian magnitude bytes.
pub fn integer_bytes(magnitude: &[u8]) -> Vec<u8> {
    let trimmed: Vec<u8> = {
        let start = magnitude
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(magnitude.len());
        magnitude[start..].to_vec()
    };
    let mut content = if trimmed.is_empty() { vec![0] } else { trimmed };
    if content[0] & 0x80 != 0 {
        content.insert(0, 0);
    }
    tlv(INTEGER, &content)
}

pub fn small_integer(n: u64) -> Vec<u8> {
    integer_bytes(&n.to_be_bytes())
}

pub fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut content = vec![0];
    content.extend_from_slice(bytes);
    tlv(BIT_STRING, &content)
}

pub fn octet_string(bytes: &[u8]) -> Vec<u8> {
    tlv(OCTET_STRING, bytes)
}

pub fn null() -> Vec<u8> {
    vec![NULL, 0]
}

/// An OBJECT IDENTIFIER from its dotted form.
pub fn oid(dotted: &str) -> CryptoResult<Vec<u8>> {
    let arcs: Vec<u64> = dotted
        .split('.')
        .map(|a| {
            a.parse::<u64>().map_err(|_| {
                CryptoError::new(format!("not an OID: {}", dotted))
            })
        })
        .collect::<CryptoResult<_>>()?;
    if arcs.len() < 2 {
        return Err(CryptoError::new(format!("not an OID: {}", dotted)));
    }
    let mut content = Vec::new();
    for arc in
        std::iter::once(arcs[0] * 40 + arcs[1]).chain(arcs[2..].iter().copied())
    {
        let mut chunk = vec![(arc & 0x7f) as u8];
        let mut rest = arc >> 7;
        while rest > 0 {
            chunk.push(0x80 | (rest & 0x7f) as u8);
            rest >>= 7;
        }
        chunk.reverse();
        content.extend(chunk);
    }
    Ok(tlv(OID, &content))
}

/// A context-specific tag: `[n]` primitive or constructed.
pub fn context(n: u8, constructed: bool, content: &[u8]) -> Vec<u8> {
    tlv(0x80 | if constructed { 0x20 } else { 0 } | n, content)
}

/// One element read: its first tag octet, its class, form and number, its
/// content, the whole encoding, and what followed it.
#[derive(Clone, Copy, Debug)]
pub struct Element<'a> {
    /// The identifier's first octet (the whole tag for numbers below 31).
    pub tag: u8,
    /// 0 universal, 1 application, 2 context-specific, 3 private.
    pub class: u8,
    pub constructed: bool,
    pub number: u32,
    pub content: &'a [u8],
    /// The element's own encoding, tag and length included.
    pub raw: &'a [u8],
    pub rest: &'a [u8],
}

impl Element<'_> {
    /// A context-specific `[n]`.
    pub fn is_context(&self, n: u32) -> bool {
        self.class == 2 && self.number == n
    }
}

/// Reads one DER element (definite lengths; tag numbers of any size).
pub fn read(input: &[u8]) -> Option<Element<'_>> {
    let (&tag, mut after) = input.split_first()?;
    let mut number = u32::from(tag & 0x1f);
    if number == 0x1f {
        number = 0;
        loop {
            let (&b, next) = after.split_first()?;
            after = next;
            number = number.checked_mul(128)? | u32::from(b & 0x7f);
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    let (&first, mut after) = after.split_first()?;
    let len = if first < 0x80 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 8 || after.len() < n {
            return None;
        }
        let mut len = 0usize;
        for &b in &after[..n] {
            len = len.checked_mul(256)?.checked_add(b as usize)?;
        }
        after = &after[n..];
        len
    };
    if after.len() < len {
        return None;
    }
    let header = input.len() - after.len();
    Some(Element {
        tag,
        class: tag >> 6,
        constructed: tag & 0x20 != 0,
        number,
        content: &after[..len],
        raw: &input[..header + len],
        rest: &after[len..],
    })
}

/// A DER INTEGER's content as an i64, two's complement; `None` when it
/// does not fit.
pub fn integer_value(content: &[u8]) -> Option<i64> {
    if content.is_empty() || content.len() > 8 {
        return None;
    }
    let mut v: i64 = if content[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in content {
        v = (v << 8) | i64::from(b);
    }
    Some(v)
}

/// The elements inside a constructed element's content.
pub fn children(content: &[u8]) -> Option<Vec<Element<'_>>> {
    let mut out = Vec::new();
    let mut rest = content;
    while !rest.is_empty() {
        let e = read(rest)?;
        rest = e.rest;
        out.push(e);
    }
    Some(out)
}

/// An OBJECT IDENTIFIER's content in dotted form.
pub fn oid_string(content: &[u8]) -> Option<String> {
    let mut arcs = Vec::new();
    let mut value: u64 = 0;
    for &b in content {
        value = value.checked_mul(128)? | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            arcs.push(value);
            value = 0;
        }
    }
    let first = *arcs.first()?;
    let (a, b) = if first < 40 {
        (0, first)
    } else if first < 80 {
        (1, first - 40)
    } else {
        (2, first - 80)
    };
    let mut parts = vec![a.to_string(), b.to_string()];
    parts.extend(arcs[1..].iter().map(u64::to_string));
    Some(parts.join("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oids_round_trip() {
        for o in [
            "1.2.840.113549.1.1.1",
            "2.16.840.1.101.3.4.3.17",
            "1.3.6.1.5.5.7.6.54",
            "1.3.101.112",
        ] {
            let der = oid(o).unwrap();
            let e = read(&der).unwrap();
            assert_eq!(oid_string(e.content).unwrap(), o);
        }
        assert_eq!(
            oid("1.2.840.113549.1.1.1").unwrap(),
            [6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1]
        );
    }

    #[test]
    fn long_lengths() {
        let big = octet_string(&[7u8; 300]);
        assert_eq!(&big[..4], &[4, 0x82, 1, 44]);
        assert_eq!(read(&big).unwrap().content.len(), 300);
        assert_eq!(small_integer(0), [2, 1, 0]);
        assert_eq!(small_integer(128), [2, 2, 0, 128]);
        assert_eq!(integer_value(&[0xff]), Some(-1));
        assert_eq!(integer_value(&[0, 0x80]), Some(128));
    }

    #[test]
    fn high_tag_numbers() {
        // [702] EXPLICIT INTEGER 1: bf 85 3e 03 02 01 01
        let e = read(&[0xbf, 0x85, 0x3e, 0x03, 0x02, 0x01, 0x01]).unwrap();
        assert!(e.is_context(702) && e.constructed);
        assert_eq!(e.content, &[2, 1, 1]);
    }
}
