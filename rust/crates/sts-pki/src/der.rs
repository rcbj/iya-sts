// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! DER, written and read, as asn1js writes it for pkijs.
//!
//! The writers are `sts_crypto::der_lite`'s with what X.509 needs beside
//! them: a BIT STRING with unused bits, the three string types a name uses,
//! a BOOLEAN, an INTEGER from a JavaScript number, the two times. Where
//! asn1js has an encoding of its own — an INTEGER written from the bytes it
//! was handed, unminimised; a string type written from UTF-16 code units —
//! this module does what asn1js does, because the certificate's bytes are
//! what a signature covers.

pub use sts_crypto::der_lite::{
    children, context, integer_value, null, octet_string, oid_string, read,
    sequence, tlv, Element,
};

use crate::error::{PkiError, PkiResult};

pub const BOOLEAN: u8 = 0x01;
pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const NULL: u8 = 0x05;
pub const OID: u8 = 0x06;
pub const UTF8_STRING: u8 = 0x0c;
pub const PRINTABLE_STRING: u8 = 0x13;
pub const IA5_STRING: u8 = 0x16;
pub const UTC_TIME: u8 = 0x17;
pub const GENERALIZED_TIME: u8 = 0x18;
pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;

/// An OBJECT IDENTIFIER, or the error Node's would be.
pub fn oid(dotted: &str) -> PkiResult<Vec<u8>> {
    Ok(sts_crypto::der_lite::oid(dotted)?)
}

/// A SET of the parts, in the order given (a DN's SET holds one).
pub fn set(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(SET, &parts.concat())
}

pub fn boolean(value: bool) -> Vec<u8> {
    vec![BOOLEAN, 1, if value { 0xff } else { 0 }]
}

/// A BIT STRING with `unused` bits at the end of the last octet.
pub fn bit_string_with_unused(bytes: &[u8], unused: u8) -> Vec<u8> {
    let mut content = vec![unused];
    content.extend_from_slice(bytes);
    tlv(BIT_STRING, &content)
}

/// A BIT STRING whose every bit is used: a signature, a key.
pub fn bit_string(bytes: &[u8]) -> Vec<u8> {
    bit_string_with_unused(bytes, 0)
}

/// An INTEGER as asn1js writes `new Integer({ value: n })`: the minimal
/// two's complement of a JavaScript number.
pub fn integer(n: i64) -> Vec<u8> {
    let bytes = n.to_be_bytes();
    let mut start = 0;
    while start < 7 {
        let (b, next) = (bytes[start], bytes[start + 1]);
        if (b == 0 && next & 0x80 == 0) || (b == 0xff && next & 0x80 != 0) {
            start += 1;
        } else {
            break;
        }
    }
    tlv(INTEGER, &bytes[start..])
}

/// An INTEGER from the bytes asn1js was handed (`valueHex`), as they are.
pub fn integer_raw(content: &[u8]) -> Vec<u8> {
    tlv(INTEGER, content)
}

/// A string type asn1js writes one octet per UTF-16 code unit
/// (PrintableString, IA5String): the low byte of each.
pub fn latin_string(tag: u8, value: &str) -> Vec<u8> {
    let bytes: Vec<u8> = value.encode_utf16().map(|u| u as u8).collect();
    tlv(tag, &bytes)
}

pub fn utf8_string(value: &str) -> Vec<u8> {
    tlv(UTF8_STRING, value.as_bytes())
}

/// A context tag of number `n` over an already-encoded element's CONTENT:
/// IMPLICIT tagging, primitive or constructed as the element was.
pub fn implicit(n: u8, element: &[u8]) -> PkiResult<Vec<u8>> {
    let e = read(element)
        .ok_or_else(|| PkiError::new("an element to retag does not parse"))?;
    Ok(context(n, e.constructed, e.content))
}

/// A whole element read from the front of `input`, refusing trailing bytes.
pub fn read_whole(input: &[u8]) -> Option<Element<'_>> {
    read(input).filter(|e| e.rest.is_empty())
}

/// The value of an element read as asn1js reads a string: UTF-8 for a
/// UTF8String, one code unit per octet for the others.
pub fn string_value(e: &Element<'_>) -> String {
    if e.tag == UTF8_STRING {
        String::from_utf8_lossy(e.content).into_owned()
    } else if e.tag == 0x1e {
        // BMPString: UTF-16BE.
        let units: Vec<u16> = e
            .content
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        e.content.iter().map(|&b| char::from(b)).collect()
    }
}

/// Lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_as_asn1js_writes_them() {
        assert_eq!(integer(0), vec![2, 1, 0]);
        assert_eq!(integer(127), vec![2, 1, 0x7f]);
        assert_eq!(integer(128), vec![2, 2, 0, 0x80]);
        assert_eq!(integer(-1), vec![2, 1, 0xff]);
        assert_eq!(integer(-129), vec![2, 2, 0xff, 0x7f]);
        assert_eq!(integer(65536), vec![2, 3, 1, 0, 0]);
    }
}
