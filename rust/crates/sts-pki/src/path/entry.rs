// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! One certificate as `pki.js`'s `certificateFromDer()` reads it — OpenSSL
//! must parse it, as node's `X509Certificate` must — and its subject as a
//! sentence names it.
//!
//! The subject is printed as node prints `X509Certificate.subject`
//! (`X509_NAME_print_ex()` with RFC 2253 and control-character escaping,
//! UTF-8 conversion, short field names, one attribute per line) and the
//! lines joined with ", ", which is `pki.js`'s `oneLineName()`.

use openssl::asn1::Asn1Object;
use openssl::hash::{hash, MessageDigest};
use openssl::x509::X509;
use std::cell::OnceCell;

use super::facts::{self, PathFacts};
use crate::der::{self, Element};

/// `certificateFromDer()`'s `{ der, pem, x509, sha1 }`, with the path facts
/// read once beside it.
pub struct Entry {
    pub der: Vec<u8>,
    pub pem: String,
    pub x509: X509,
    /// SPIRE's fingerprint: lower-case hex SHA-1 of the DER.
    pub sha1: String,
    facts: OnceCell<PathFacts>,
}

impl Entry {
    /// `certificateFromDer()`: `None` when OpenSSL cannot read it.
    pub fn from_der(input: &[u8]) -> Option<Entry> {
        let x509 = X509::from_der(input).ok()?;
        let der = x509.to_der().ok()?;
        let pem = String::from_utf8(x509.to_pem().ok()?).ok()?;
        let sha1 = hash(MessageDigest::sha1(), &der)
            .ok()
            .map(|d| crate::der::hex(&d))?;
        Some(Entry {
            der,
            pem,
            x509,
            sha1,
            facts: OnceCell::new(),
        })
    }

    /// The facts the path rules are asked of, read on first use.
    pub fn facts(&self) -> &PathFacts {
        self.facts.get_or_init(|| facts::path_facts_of(&self.der))
    }

    /// `pathSubjectOf()`: the subject for a sentence.
    pub fn subject_text(&self) -> String {
        let text = facts::subject_name_der(&self.der)
            .map(|name| one_line_name(&name))
            .unwrap_or_default();
        if text.is_empty() {
            "the certificate with an empty subject".to_string()
        } else {
            text
        }
    }
}

/// `oneLineName(new X509Certificate(der).subject)`.
pub fn one_line_name(name_der: &[u8]) -> String {
    name_lines(name_der).join(", ")
}

/// `X509Certificate.subject`'s lines: one RDN each.
pub fn name_lines(name_der: &[u8]) -> Vec<String> {
    let Some(name) = der::read(name_der) else {
        return Vec::new();
    };
    let mut lines = Vec::new();
    for rdn in der::children(name.content).unwrap_or_default() {
        let mut parts = Vec::new();
        for atv in der::children(rdn.content).unwrap_or_default() {
            let fields = der::children(atv.content).unwrap_or_default();
            let (Some(oid), Some(value)) = (fields.first(), fields.get(1))
            else {
                continue;
            };
            parts.push(format!("{}={}", field_name(oid), printed_value(value)));
        }
        if !parts.is_empty() {
            lines.push(parts.join(" + "));
        }
    }
    lines.into_iter().filter(|l| !l.is_empty()).collect()
}

/// `XN_FLAG_FN_SN`: OpenSSL's short name, the dotted OID for one it does
/// not know.
fn field_name(oid: &Element<'_>) -> String {
    let dotted = der::oid_string(oid.content).unwrap_or_default();
    match Asn1Object::from_str(&dotted) {
        Ok(obj) if obj.nid() != openssl::nid::Nid::UNDEF => {
            obj.nid().short_name().map(str::to_string).unwrap_or(dotted)
        }
        _ => dotted,
    }
}

/// The characters of a value as `do_print_ex()` reads them with
/// `ASN1_STRFLGS_UTF8_CONVERT`: a UTF8String one octet at a time (it is
/// already UTF-8), a BMPString or UniversalString decoded, anything else
/// one octet per character.
enum Units {
    Bytes(Vec<u8>),
    Chars(Vec<char>),
}

fn units_of(value: &Element<'_>) -> Units {
    match value.tag {
        der::UTF8_STRING => Units::Bytes(value.content.to_vec()),
        0x1e => Units::Chars(
            value
                .content
                .chunks(2)
                .filter(|c| c.len() == 2)
                .map(|c| {
                    char::from_u32(u32::from(u16::from_be_bytes([c[0], c[1]])))
                        .unwrap_or('\u{fffd}')
                })
                .collect(),
        ),
        0x1c => Units::Chars(
            value
                .content
                .chunks(4)
                .filter(|c| c.len() == 4)
                .map(|c| {
                    char::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                        .unwrap_or('\u{fffd}')
                })
                .collect(),
        ),
        _ => {
            Units::Chars(value.content.iter().map(|&b| char::from(b)).collect())
        }
    }
}

/// A Name as node prints a DirName alternative name
/// (`kX509NameFlagsRFC2253WithinUtf8JSON`): the RDNs REVERSED, `,` between
/// them and `+` inside one, RFC 2253 escaping but not of control or
/// non-ASCII characters, and an attribute OpenSSL does not know dumped as
/// `#` and the hex of its DER.
pub fn rfc2253_name(name_der: &[u8]) -> String {
    let Some(name) = der::read(name_der) else {
        return String::new();
    };
    let mut rdns = Vec::new();
    for rdn in der::children(name.content).unwrap_or_default() {
        let mut parts = Vec::new();
        for atv in der::children(rdn.content).unwrap_or_default() {
            let fields = der::children(atv.content).unwrap_or_default();
            let (Some(oid), Some(value)) = (fields.first(), fields.get(1))
            else {
                continue;
            };
            let field = field_name(oid);
            // `field_name()` answers the dotted OID for one OpenSSL does not
            // know.
            let known = !field.chars().all(|c| c.is_ascii_digit() || c == '.');
            let text = if known {
                escaped(value, false)
            } else {
                format!("#{}", crate::der::hex(value.raw).to_uppercase())
            };
            parts.push(format!("{}={}", field, text));
        }
        rdns.push(parts.join("+"));
    }
    rdns.reverse();
    rdns.join(",")
}

/// RFC 2253 and control-character escaping, as `do_esc_char()` does it.
fn printed_value(value: &Element<'_>) -> String {
    escaped(value, true)
}

/// `do_esc_char()` with RFC 2253 escaping, and control characters escaped
/// only when `control` is set.
fn escaped(value: &Element<'_>, control: bool) -> String {
    let codes: Vec<u32> = match units_of(value) {
        Units::Bytes(b) => b.into_iter().map(u32::from).collect(),
        Units::Chars(c) => c.into_iter().map(|c| c as u32).collect(),
    };
    let raw_utf8 = value.tag == der::UTF8_STRING;
    let mut out: Vec<u8> = Vec::new();
    let last = codes.len().saturating_sub(1);
    for (i, &c) in codes.iter().enumerate() {
        let first_or_last_space = c == 0x20 && (i == 0 || i == last);
        let escape =
            matches!(c, 0x2c | 0x2b | 0x22 | 0x5c | 0x3c | 0x3e | 0x3b)
                || (i == 0 && c == 0x23)
                || first_or_last_space;
        if control && (c < 0x20 || c == 0x7f) {
            out.extend(format!("\\{:02X}", c).as_bytes());
        } else if escape {
            out.push(b'\\');
            out.push(c as u8);
        } else if raw_utf8 || c < 0x80 {
            out.push(c as u8);
        } else {
            let ch = char::from_u32(c).unwrap_or('\u{fffd}');
            let mut buf = [0u8; 4];
            out.extend(ch.encode_utf8(&mut buf).as_bytes());
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
