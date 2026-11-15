// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE FOUR WIRE SHAPES EST ADDS (`est/est_codec.ts`): a request body
//! decoded strictly (RFC 8951 section 3), a certs-only CMS message (RFC
//! 7030 section 4.1.3), the CSR attributes document (section 4.5.2) and the
//! `multipart/mixed` server-key response (section 4.4.2).
//!
//! **THE DER IS WRITTEN BY HAND**: a certs-only message carries every
//! certificate VERBATIM, as the CA signed it — Node's codec does the same
//! for the same reason, byte for byte (`tests/est_codec_vectors.rs`).

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// The OIDs this codec writes.
pub mod oids {
    pub const DATA: &str = "1.2.840.113549.1.7.1";
    pub const SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
    pub const EXTENSION_REQUEST: &str = "1.2.840.113549.1.9.14";
    pub const SUBJECT_ALT_NAME: &str = "2.5.29.17";
    pub const EXT_KEY_USAGE: &str = "2.5.29.37";
    pub const DECRYPT_KEY_IDENTIFIER: &str = "1.2.840.113549.1.9.16.2.37";
    pub const ASYMMETRIC_DECRYPT_KEY_IDENTIFIER: &str =
        "1.2.840.113549.1.9.16.2.54";
}

/// The signature algorithms `csrattrs` names, in Node's order.
pub const SIGNATURE_ALGORITHMS: &[&str] = &[
    "1.2.840.10045.4.3.2",
    "1.2.840.10045.4.3.3",
    "1.2.840.113549.1.1.11",
    "1.3.101.112",
    "2.16.840.1.101.3.4.3.17",
    "2.16.840.1.101.3.4.3.18",
    "2.16.840.1.101.3.4.3.19",
];

/// `lengthOctets()` and `tlv()`.
#[tracing::instrument(level = "trace", skip(content))]
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes: Vec<u8> = n
            .to_be_bytes()
            .iter()
            .copied()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}

/// `oid(dotted)`.
#[tracing::instrument(level = "trace")]
pub fn oid(dotted: &str) -> Vec<u8> {
    sts_pki::der::oid(dotted).unwrap_or_default()
}

/// `utf8String(text)`.
#[tracing::instrument(level = "trace")]
pub fn utf8_string(text: &str) -> Vec<u8> {
    tlv(0x0c, text.as_bytes())
}

/// `pemToDer(pem)`: every PEM armour line removed, the rest base64.
#[tracing::instrument(level = "trace", skip_all)]
pub fn pem_to_der(pem: &str) -> Vec<u8> {
    let mut body = String::new();
    let mut rest = pem;
    // `/-----[^-]+-----/g` removed, then whitespace.
    while let Some(start) = rest.find("-----") {
        body.push_str(&rest[..start]);
        let after = &rest[start + 5..];
        match after.find("-----") {
            Some(end) if !after[..end].contains('-') => {
                rest = &after[end + 5..]
            }
            _ => {
                body.push_str("-----");
                rest = after;
            }
        }
    }
    body.push_str(rest);
    let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    lenient_base64(&compact)
}

/// node's `Buffer.from(text, 'base64')`: what it does not recognise is
/// skipped.
#[tracing::instrument(level = "trace", skip_all)]
pub fn lenient_base64(text: &str) -> Vec<u8> {
    let kept: String = text
        .chars()
        .filter(|c| {
            c.is_ascii_alphanumeric()
                || *c == '+'
                || *c == '/'
                || *c == '-'
                || *c == '_'
        })
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    let cut = if kept.len() % 4 == 1 {
        kept.len() - 1
    } else {
        kept.len()
    };
    let trimmed = &kept[..cut];
    base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(
                base64::engine::DecodePaddingMode::Indifferent,
            )
            .with_decode_allow_trailing_bits(true),
    )
    .decode(trimmed)
    .unwrap_or_default()
}

/// `decodeBody(bytes)`: the alphabet, `=` at the end, SP/HTAB/CR/LF
/// anywhere, a length that is a multiple of four, canonical.
#[tracing::instrument(level = "debug", skip_all)]
pub fn decode_body(bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
    let text: String = bytes.iter().map(|&b| char::from(b)).collect();
    let compact: String = text
        .chars()
        .filter(|c| !matches!(c, ' ' | '\t' | '\r' | '\n'))
        .collect();
    if compact.is_empty() {
        return Err("The request body is empty.");
    }
    let body = compact.trim_end_matches('=');
    let pad = compact.len() - body.len();
    if pad > 2
        || body.is_empty()
        || !body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
    {
        return Err(
            "The request body is not base64: it contains a character outside the base64 \
             alphabet, padding and whitespace (RFC 8951 section 3).",
        );
    }
    if compact.len() % 4 != 0 {
        return Err(
            "The request body is not base64: its length is not a multiple of four, so it was \
             cut off or padded wrongly.",
        );
    }
    let der = lenient_base64(&compact);
    if STANDARD.encode(&der) != compact {
        return Err("The request body is not canonical base64.");
    }
    Ok(der)
}

/// `base64Lines(der)`: 64 a line, CRLF, a CRLF at the end.
#[tracing::instrument(level = "trace", skip_all)]
pub fn base64_lines(der: &[u8]) -> String {
    let text = STANDARD.encode(der);
    let lines: Vec<&str> = text
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect();
    format!("{}\r\n", lines.join("\r\n"))
}

/// `certsOnly(pems)`: ContentInfo { signedData, [0] SignedData { 1, {},
/// { id-data }, [0] { certs as they are }, {} } }.
#[tracing::instrument(level = "debug", skip_all)]
pub fn certs_only(pems: &[String]) -> Vec<u8> {
    let certificates: Vec<u8> = pems
        .iter()
        .map(|p| pem_to_der(p))
        .filter(|d| !d.is_empty())
        .flatten()
        .collect();
    let signed_data = tlv(
        0x30,
        &[
            tlv(0x02, &[1]),
            tlv(0x31, &[]),
            tlv(0x30, &oid(oids::DATA)),
            tlv(0xa0, &certificates),
            tlv(0x31, &[]),
        ]
        .concat(),
    );
    tlv(
        0x30,
        &[oid(oids::SIGNED_DATA), tlv(0xa0, &signed_data)].concat(),
    )
}

/// One item of a CSR attributes answer.
#[derive(Debug, Clone)]
pub enum AttrOrOid {
    Oid(String),
    Attribute {
        kind: String,
        values: Vec<AttrValue>,
    },
}

/// A value of a CSR attribute.
#[derive(Debug, Clone)]
pub enum AttrValue {
    Oid(String),
    Utf8(String),
}

/// `csrAttrs(items)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn csr_attrs(items: &[AttrOrOid]) -> Vec<u8> {
    let encoded: Vec<u8> = items
        .iter()
        .flat_map(|item| match item {
            AttrOrOid::Oid(o) => oid(o),
            AttrOrOid::Attribute { kind, values } => {
                let set: Vec<u8> = values
                    .iter()
                    .flat_map(|v| match v {
                        AttrValue::Oid(o) => oid(o),
                        AttrValue::Utf8(t) => utf8_string(t),
                    })
                    .collect();
                tlv(0x30, &[oid(kind), tlv(0x31, &set)].concat())
            }
        })
        .collect();
    tlv(0x30, &encoded)
}

/// `multipartMixed(parts)`: a random boundary, each part base64 ending in
/// its own CRLF (#209).
#[tracing::instrument(level = "debug", skip_all)]
pub fn multipart_mixed(parts: &[(&str, Vec<u8>)]) -> (String, Vec<u8>) {
    let boundary = format!(
        "est-{}",
        sts_pki::der::hex(
            &sts_crypto::random::random_bytes(12).unwrap_or_default()
        )
    );
    let mut out = String::new();
    for (content_type, der) in parts {
        out.push_str(&format!(
            "--{}\r\nContent-Type: {}\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",
            boundary,
            content_type,
            base64_lines(der)
        ));
    }
    out.push_str(&format!("--{}--\r\n", boundary));
    (boundary, out.into_bytes())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)] // tests

    use super::*;

    #[test]
    fn a_body_is_decoded_strictly() {
        assert_eq!(decode_body(b"AAEC\r\nAw==").unwrap(), vec![0, 1, 2, 3]);
        assert!(decode_body(b"AA=C").is_err());
        assert!(decode_body(b"AAE").is_err());
        assert!(decode_body(b"AAF=").is_err());
    }
}
