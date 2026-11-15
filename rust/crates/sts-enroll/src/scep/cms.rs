// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE CMS ENVELOPE SCEP SPEAKS (RFC 8894 section 3 over RFC 5652, read
//! and written — `scep/scep_cms.ts`). A pkiMessage is a SignedData whose
//! signed attributes say what the message is and whose content is an
//! EnvelopedData encrypted to the realm's RA. This file turns bytes into
//! those facts and facts back into bytes, and DECIDES NOTHING; every
//! cryptographic operation inside it is `sts-crypto`'s ([`sts_crypto::cms`]).
//!
//! Node's four codec decisions, each a refusal somebody meets: SHA-256/384/
//! 512 only (`badAlg` for SHA-1 and MD5); AES-128/192/256-CBC only
//! (`badAlg` for DES and 3DES); RSA key transport, PKCS#1 v1.5 with
//! implicit rejection or OAEP, a failed unwrap replaced by random bytes of
//! the right length so a padding error and a wrong key are one answer
//! (`STS-SCEP-0030`); signed attributes verified over the bytes that
//! ARRIVED, tag swapped to SET; the ones this file signs are DER-sorted.
//!
//! The reader is BER, as asn1js reads it: OpenSSL streams an
//! indefinite-length constructed OCTET STRING for encapsulated content.

use serde_json::Value as Json;
use sts_core::errors::{codes, ErrorCode};

use crate::est::codec::{oid, tlv};
use crate::model;

/// The OIDs a pkiMessage carries.
pub mod oids {
    pub const DATA: &str = "1.2.840.113549.1.7.1";
    pub const SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
    pub const ENVELOPED_DATA: &str = "1.2.840.113549.1.7.3";
    pub const CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
    pub const MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
    pub const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
    pub const RSAES_OAEP: &str = "1.2.840.113549.1.1.7";
    pub const SUBJECT_KEY_IDENTIFIER: &str = "2.5.29.14";
    pub const MESSAGE_TYPE: &str = "2.16.840.1.113733.1.9.2";
    pub const PKI_STATUS: &str = "2.16.840.1.113733.1.9.3";
    pub const FAIL_INFO: &str = "2.16.840.1.113733.1.9.4";
    pub const SENDER_NONCE: &str = "2.16.840.1.113733.1.9.5";
    pub const RECIPIENT_NONCE: &str = "2.16.840.1.113733.1.9.6";
    pub const TRANSACTION_ID: &str = "2.16.840.1.113733.1.9.7";
}

const DIGESTS: &[(&str, &str, &str)] = &[
    ("2.16.840.1.101.3.4.2.1", "sha256", "SHA-256"),
    ("2.16.840.1.101.3.4.2.2", "sha384", "SHA-384"),
    ("2.16.840.1.101.3.4.2.3", "sha512", "SHA-512"),
];
const REFUSED_DIGESTS: &[(&str, &str)] =
    &[("1.3.14.3.2.26", "SHA-1"), ("1.2.840.113549.2.5", "MD5")];
/// `(oid, key, digest, label)`; an empty digest is "the digestAlgorithm's".
const SIGNATURES: &[(&str, &str, &str, &str)] = &[
    ("1.2.840.113549.1.1.1", "rsa", "", "RSA"),
    (
        "1.2.840.113549.1.1.11",
        "rsa",
        "sha256",
        "sha256WithRSAEncryption",
    ),
    (
        "1.2.840.113549.1.1.12",
        "rsa",
        "sha384",
        "sha384WithRSAEncryption",
    ),
    (
        "1.2.840.113549.1.1.13",
        "rsa",
        "sha512",
        "sha512WithRSAEncryption",
    ),
    ("1.2.840.10045.4.3.2", "ec", "sha256", "ecdsa-with-SHA256"),
    ("1.2.840.10045.4.3.3", "ec", "sha384", "ecdsa-with-SHA384"),
    ("1.2.840.10045.4.3.4", "ec", "sha512", "ecdsa-with-SHA512"),
];
const CIPHERS: &[(&str, &str, usize, &str)] = &[
    ("2.16.840.1.101.3.4.1.2", "aes-128-cbc", 16, "AES-128-CBC"),
    ("2.16.840.1.101.3.4.1.22", "aes-192-cbc", 24, "AES-192-CBC"),
    ("2.16.840.1.101.3.4.1.42", "aes-256-cbc", 32, "AES-256-CBC"),
];
const REFUSED_CIPHERS: &[(&str, &str)] = &[
    ("1.2.840.113549.3.7", "DES-EDE3-CBC"),
    ("1.3.14.3.2.7", "DES-CBC"),
];
const OAEP_HASHES: &[(&str, &str)] = &[
    ("1.3.14.3.2.26", "sha1"),
    ("2.16.840.1.101.3.4.2.1", "sha256"),
    ("2.16.840.1.101.3.4.2.2", "sha384"),
    ("2.16.840.1.101.3.4.2.3", "sha512"),
];
const NONCE_BYTES: usize = 16;
const MAX_TRANSACTION_ID: usize = 128;

/// A failInfo value (`FAIL_INFO`), by its name.
#[tracing::instrument(level = "trace")]
pub fn fail_info(name: &str) -> String {
    model::value_of("scep", "fail-info", name)
}

/// A pkiStatus value, by its name.
#[tracing::instrument(level = "trace")]
pub fn pki_status(name: &str) -> String {
    model::value_of("scep", "pki-status", name)
}

/// A failInfo's name, by its value (`FAIL_NAMES`).
#[tracing::instrument(level = "trace")]
pub fn fail_name(value: &str) -> String {
    model::rows("scep", "fail-info")
        .iter()
        .find(|r| r.get("value").and_then(Json::as_str) == Some(value))
        .and_then(|r| r.get("name").and_then(Json::as_str).map(str::to_string))
        .unwrap_or_default()
}

/// A digest's id (`sha256`) by OID.
#[tracing::instrument(level = "trace")]
pub fn digest_id(oid: &str) -> Option<&'static str> {
    DIGESTS
        .iter()
        .find(|(o, _, _)| *o == oid)
        .map(|(_, id, _)| *id)
}

/// A refusal: `stage` is `http` when too little was read to build a
/// CertRep, `certrep` when the reply can be a signed FAILURE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmsRefusal {
    pub code: ErrorCode,
    pub why: String,
    pub fail_info: String,
    pub http: bool,
}

fn refusal(
    code: ErrorCode,
    why: impl Into<String>,
    fail: &str,
    http: bool,
) -> CmsRefusal {
    CmsRefusal {
        code,
        why: why.into(),
        fail_info: if fail.is_empty() {
            String::new()
        } else {
            fail_info(fail)
        },
        http,
    }
}

/// One BER element.
#[derive(Debug, Clone)]
pub struct Ber<'a> {
    pub class: u8,
    pub constructed: bool,
    pub number: u32,
    /// The whole encoding, as received.
    pub raw: &'a [u8],
    /// The content (an indefinite one's without its end-of-contents).
    pub content: &'a [u8],
    pub children: Vec<Ber<'a>>,
}

impl Ber<'_> {
    fn universal(&self, n: u32) -> bool {
        self.class == 0 && self.number == n
    }
    fn context(&self, n: u32) -> bool {
        self.class == 2 && self.number == n
    }
}

fn read_ber(input: &[u8], depth: usize) -> Option<(Ber<'_>, &[u8])> {
    if depth > 64 {
        return None;
    }
    let (&tag, mut after) = input.split_first()?;
    let class = tag >> 6;
    let constructed = tag & 0x20 != 0;
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
    let (&first, rest) = after.split_first()?;
    after = rest;
    if first == 0x80 {
        if !constructed {
            return None;
        }
        let start = input.len() - after.len();
        let mut children = Vec::new();
        let mut cursor = after;
        loop {
            if cursor.len() >= 2 && cursor[0] == 0 && cursor[1] == 0 {
                let content_len = (input.len() - cursor.len()) - start;
                let end = input.len() - cursor.len() + 2;
                return Some((
                    Ber {
                        class,
                        constructed,
                        number,
                        raw: &input[..end],
                        content: &input[start..start + content_len],
                        children,
                    },
                    &cursor[2..],
                ));
            }
            let (child, next) = read_ber(cursor, depth + 1)?;
            children.push(child);
            cursor = next;
        }
    }
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
    let content = &after[..len];
    let mut children = Vec::new();
    if constructed {
        let mut cursor = content;
        while !cursor.is_empty() {
            let (child, next) = read_ber(cursor, depth + 1)?;
            children.push(child);
            cursor = next;
        }
    }
    Some((
        Ber {
            class,
            constructed,
            number,
            raw: &input[..header + len],
            content,
            children,
        },
        &after[len..],
    ))
}

/// `readOne(bytes)`: one complete BER value and nothing after it.
#[tracing::instrument(level = "trace", skip_all)]
pub fn read_one(bytes: &[u8]) -> Option<Ber<'_>> {
    if bytes.is_empty() {
        return None;
    }
    let (one, rest) = read_ber(bytes, 0)?;
    rest.is_empty().then_some(one)
}

fn oid_of(node: Option<&Ber<'_>>) -> String {
    node.filter(|n| n.universal(6))
        .and_then(|n| sts_pki::der::oid_string(n.content))
        .unwrap_or_default()
}

/// `octetsOf(node)`: an OCTET STRING's octets, primitive or constructed.
fn octets_of(node: Option<&Ber<'_>>) -> Option<Vec<u8>> {
    let n = node?;
    if n.constructed {
        let mut out = Vec::new();
        for c in &n.children {
            out.extend(octets_of(Some(c))?);
        }
        return Some(out);
    }
    Some(n.content.to_vec())
}

fn string_of(node: Option<&Ber<'_>>) -> String {
    node.filter(|n| {
        !n.constructed
            && n.class == 0
            && matches!(n.number, 12 | 19 | 22 | 20 | 26 | 30)
    })
    .map(|n| {
        if n.number == 12 {
            String::from_utf8_lossy(n.content).into_owned()
        } else {
            n.content.iter().map(|&b| char::from(b)).collect()
        }
    })
    .unwrap_or_default()
}

/// A certificate described as the codec compares it.
#[derive(Debug, Clone)]
pub struct Described {
    pub der: Vec<u8>,
    pub pem: String,
    pub serial_raw: Vec<u8>,
    pub issuer_raw: Vec<u8>,
    pub subject_raw: Vec<u8>,
    pub ski: Option<Vec<u8>>,
    /// `rsa`, `ec`, `ed25519`, ...
    pub key_type: String,
    pub spki: Vec<u8>,
    pub spki_sha256: String,
    pub self_issued: bool,
    pub serial_hex: String,
    pub not_before_ms: f64,
    pub not_after_ms: f64,
    pub valid_from: String,
    pub valid_to: String,
}

/// `describeCertificate(der)`: the issuer, serial and subject read out of
/// the certificate's own bytes; a version 1 certificate has six TBS fields
/// (#249).
#[tracing::instrument(level = "trace", skip_all)]
pub fn describe_certificate(der: &[u8]) -> Option<Described> {
    let node = read_one(der)?;
    let tbs = node.children.first()?;
    let parts = &tbs.children;
    let offset = usize::from(parts.first().is_some_and(|p| p.context(0)));
    if !node.universal(16) || !tbs.universal(16) || parts.len() < offset + 6 {
        return None;
    }
    let cert = sts_pki::x509::read::Certificate::from_der(der).ok()?;
    let ski = cert
        .extension(oids::SUBJECT_KEY_IDENTIFIER)
        .and_then(|e| read_one(&e.value).and_then(|n| octets_of(Some(&n))));
    let key_type = match sts_pki::x509::keys::describe_spki(&cert.spki) {
        Some(sts_pki::x509::keys::KeyDesc::Rsa { .. }) => "rsa",
        Some(sts_pki::x509::keys::KeyDesc::Ec { .. }) => "ec",
        Some(sts_pki::x509::keys::KeyDesc::Ed25519) => "ed25519",
        Some(sts_pki::x509::keys::KeyDesc::Pqc(_)) => "ml-dsa",
        None => "",
    }
    .to_string();
    let issuer_raw = parts[offset + 2].raw.to_vec();
    let subject_raw = parts[offset + 4].raw.to_vec();
    Some(Described {
        der: der.to_vec(),
        pem: sts_pki::x509::keys::der_to_pem(der, "CERTIFICATE"),
        serial_raw: octets_of(Some(&parts[offset]))?,
        self_issued: issuer_raw == subject_raw,
        issuer_raw,
        subject_raw,
        ski,
        key_type,
        spki_sha256: sts_pki::der::hex(
            &sts_crypto::jws_alg::Hash::Sha256.digest(&cert.spki),
        ),
        spki: cert.spki.clone(),
        serial_hex: sts_pki::der::hex(&cert.serial),
        not_before_ms: cert.not_before.timestamp_millis() as f64,
        not_after_ms: cert.not_after.timestamp_millis() as f64,
        valid_from: cert.not_before.format("%b %e %H:%M:%S %Y GMT").to_string(),
        valid_to: cert.not_after.format("%b %e %H:%M:%S %Y GMT").to_string(),
    })
}

fn identifies(sid: &Ber<'_>, cert: &Described) -> bool {
    if sid.context(0) {
        return octets_of(Some(sid))
            .is_some_and(|w| cert.ski.as_ref() == Some(&w));
    }
    if !sid.universal(16) || sid.children.len() != 2 {
        return false;
    }
    sid.children[0].raw == cert.issuer_raw.as_slice()
        && octets_of(Some(&sid.children[1]))
            .is_some_and(|s| s == cert.serial_raw)
}

/// What `parsePkiMessage()` answers.
#[derive(Debug, Clone, Default)]
pub struct Message {
    pub transaction_id: String,
    pub sender_nonce: Vec<u8>,
    pub message_type_text: String,
    pub message_type: Option<i64>,
    /// `pkiStatus` and `failInfo` (a CertRep's).
    pub pki_status: String,
    pub fail_info: String,
    pub recipient_nonce: Option<Vec<u8>>,
    pub content_type_attr: String,
    pub message_digest_attr: Option<Vec<u8>>,
    pub e_content_type: String,
    pub content: Option<Vec<u8>>,
    pub certificates: Vec<Described>,
    pub signer: Option<Described>,
    pub signer_matches: usize,
    pub digest_alg: String,
    pub signature_alg: String,
    pub signature: Vec<u8>,
    pub signed_attrs_raw: Vec<u8>,
}

/// `parsePkiMessage(bytes)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn parse_pki_message(bytes: &[u8]) -> Result<Message, CmsRefusal> {
    let http = |code: ErrorCode, why: &str| refusal(code, why, "", true);
    let Some(outer) = read_one(bytes) else {
        return Err(http(codes::STS_SCEP_0010, "The message is not one complete CMS ContentInfo carrying SignedData."));
    };
    if !outer.universal(16)
        || outer.children.len() != 2
        || oid_of(outer.children.first()) != oids::SIGNED_DATA
        || !outer.children[1].context(0)
    {
        return Err(http(codes::STS_SCEP_0010, "The message is not one complete CMS ContentInfo carrying SignedData."));
    }
    let Some(sd) = outer.children[1].children.first() else {
        return Err(http(codes::STS_SCEP_0010, "The SignedData is malformed."));
    };
    let parts = &sd.children;
    if !sd.universal(16) || parts.len() < 4 {
        return Err(http(codes::STS_SCEP_0010, "The SignedData is malformed."));
    }
    let mut at = 1;
    let digest_set = &parts[at];
    at += 1;
    let encap = &parts[at];
    at += 1;
    let mut certs_node = None;
    if parts.get(at).is_some_and(|p| p.context(0)) {
        certs_node = parts.get(at);
        at += 1;
    }
    if parts.get(at).is_some_and(|p| p.context(1)) {
        at += 1;
    }
    let signer_set = parts.get(at);
    if !digest_set.universal(17)
        || !encap.universal(16)
        || !signer_set.is_some_and(|s| s.universal(17))
        || at != parts.len() - 1
    {
        return Err(http(codes::STS_SCEP_0010, "The SignedData fields are not in the order RFC 5652 section 5.1 defines."));
    }
    let e_content_type = oid_of(encap.children.first());
    let mut content = None;
    if encap.children.len() == 2 {
        if !encap.children[1].context(0) {
            return Err(http(
                codes::STS_SCEP_0010,
                "The encapsulated content is malformed.",
            ));
        }
        let Some(octets) = octets_of(encap.children[1].children.first()) else {
            return Err(http(
                codes::STS_SCEP_0010,
                "The encapsulated content is not an OCTET STRING.",
            ));
        };
        content = Some(octets);
    }
    let certificates: Vec<Described> = certs_node
        .map(|c| {
            c.children
                .iter()
                .filter(|one| one.universal(16))
                .filter_map(|one| describe_certificate(one.raw))
                .collect()
        })
        .unwrap_or_default();
    let signers = &signer_set.map(|s| s.children.clone()).unwrap_or_default();
    if signers.len() != 1 {
        return Err(http(
            codes::STS_SCEP_0011,
            &format!(
                "A SCEP message has exactly one signer, and this one has {}.",
                signers.len()
            ),
        ));
    }
    let si = &signers[0].children;
    if !signers[0].universal(16) || si.len() < 5 {
        return Err(http(codes::STS_SCEP_0011, "The SignerInfo is malformed."));
    }
    let mut s = 1;
    let sid = &si[s];
    s += 1;
    let digest_alg = oid_of(si[s].children.first());
    s += 1;
    let signed_attrs = if si.get(s).is_some_and(|n| n.context(0)) {
        s += 1;
        si.get(s - 1)
    } else {
        None
    };
    let sig_alg_node = si.get(s);
    let signature_node = si.get(s + 1);
    let Some(signed_attrs) = signed_attrs else {
        return Err(http(
            codes::STS_SCEP_0012,
            "The signer carries no signed attributes, so the message has no messageType, transactionID or senderNonce (RFC 8894 section 3.2.1).",
        ));
    };
    let mut attrs: Vec<(String, Ber<'_>)> = Vec::new();
    for attr in &signed_attrs.children {
        let p = &attr.children;
        let kind = oid_of(p.first());
        if !attr.universal(16)
            || p.len() != 2
            || kind.is_empty()
            || !p[1].universal(17)
            || attrs.iter().any(|(k, _)| *k == kind)
            || p[1].children.len() != 1
        {
            return Err(http(
                codes::STS_SCEP_0012,
                "The signed attributes are malformed or repeat an attribute.",
            ));
        }
        attrs.push((kind, p[1].children[0].clone()));
    }
    let attr = |o: &str| attrs.iter().find(|(k, _)| k == o).map(|(_, v)| v);
    let transaction_id = string_of(attr(oids::TRANSACTION_ID));
    let sender_nonce = octets_of(attr(oids::SENDER_NONCE));
    let type_text = string_of(attr(oids::MESSAGE_TYPE));
    let tid_ok = !transaction_id.is_empty()
        && transaction_id.len() <= MAX_TRANSACTION_ID
        && transaction_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " '()+,-./:=?".contains(c));
    if !tid_ok {
        return Err(http(
            codes::STS_SCEP_0012,
            &format!("The transactionID is missing, is not a PrintableString, or is longer than {} characters.", MAX_TRANSACTION_ID),
        ));
    }
    let Some(sender_nonce) = sender_nonce.filter(|n| n.len() == NONCE_BYTES)
    else {
        return Err(http(
            codes::STS_SCEP_0012,
            &format!("The senderNonce is missing or is not {} octets (RFC 8894 section 3.2.1.5).", NONCE_BYTES),
        ));
    };
    let matching: Vec<Described> = certificates
        .iter()
        .filter(|c| identifies(sid, c))
        .cloned()
        .collect();
    let message_type = (!type_text.is_empty()
        && type_text.len() <= 3
        && type_text.chars().all(|c| c.is_ascii_digit()))
    .then(|| type_text.parse::<i64>().ok())
    .flatten();
    Ok(Message {
        transaction_id,
        sender_nonce,
        message_type,
        message_type_text: type_text,
        pki_status: string_of(attr(oids::PKI_STATUS)),
        fail_info: string_of(attr(oids::FAIL_INFO)),
        recipient_nonce: attr(oids::RECIPIENT_NONCE)
            .and_then(|n| octets_of(Some(n))),
        content_type_attr: oid_of(attr(oids::CONTENT_TYPE)),
        message_digest_attr: attr(oids::MESSAGE_DIGEST)
            .and_then(|n| octets_of(Some(n))),
        e_content_type,
        content,
        signer_matches: matching.len(),
        signer: (matching.len() == 1).then(|| matching[0].clone()),
        certificates,
        digest_alg,
        signature_alg: oid_of(sig_alg_node.and_then(|n| n.children.first())),
        signature: octets_of(signature_node).unwrap_or_default(),
        signed_attrs_raw: signed_attrs.raw.to_vec(),
    })
}

/// `verifySigner(message)`: every failure a CertRep FAILURE. The digest's
/// id on success.
#[tracing::instrument(level = "debug", skip_all)]
pub fn verify_signer(message: &Message) -> Result<&'static str, CmsRefusal> {
    let Some(signer) = &message.signer else {
        return Err(refusal(
            codes::STS_SCEP_0011,
            format!(
                "The signer's certificate is not among the certificates in the SignedData ({} match), so the signature cannot be checked.",
                message.signer_matches
            ),
            "badMessageCheck",
            false,
        ));
    };
    let Some(digest) = digest_id(&message.digest_alg) else {
        let named = REFUSED_DIGESTS
            .iter()
            .find(|(o, _)| *o == message.digest_alg)
            .map(|(_, n)| n.to_string())
            .unwrap_or_else(|| {
                format!("an unknown digest ({})", message.digest_alg)
            });
        return Err(refusal(
            codes::STS_SCEP_0020,
            format!("The message is signed over {}. This server accepts SHA-256, SHA-384 and SHA-512.", named),
            "badAlg",
            false,
        ));
    };
    let sig = SIGNATURES
        .iter()
        .find(|(o, _, _, _)| *o == message.signature_alg);
    let fits = sig.is_some_and(|(_, key, d, _)| {
        (d.is_empty() || *d == digest) && *key == signer.key_type
    });
    if !fits {
        return Err(refusal(
            codes::STS_SCEP_0021,
            format!(
                "The signature algorithm ({}) is not one this server verifies, or does not agree with the digest algorithm or the signer's key.",
                message.signature_alg
            ),
            "badAlg",
            false,
        ));
    }
    if message.content_type_attr != message.e_content_type
        || message.e_content_type != oids::DATA
    {
        return Err(refusal(
            codes::STS_SCEP_0024,
            "The contentType signed attribute does not name id-data, or does not agree with the encapsulated content.",
            "badMessageCheck",
            false,
        ));
    }
    let content = message.content.clone().unwrap_or_default();
    if !sts_crypto::cms::cms_message_digest_matches(
        digest,
        &content,
        message.message_digest_attr.as_deref(),
    ) {
        return Err(refusal(
            codes::STS_SCEP_0022,
            "The messageDigest signed attribute is not the digest of the encapsulated content.",
            "badMessageCheck",
            false,
        ));
    }
    let mut signed = message.signed_attrs_raw.clone();
    if let Some(first) = signed.first_mut() {
        *first = 0x31;
    }
    if !sts_crypto::cms::signature_valid(
        digest,
        &signed,
        &signer.spki,
        &message.signature,
    ) {
        return Err(refusal(
            codes::STS_SCEP_0023,
            "The signature over the signed attributes does not verify with the signer's certificate.",
            "badMessageCheck",
            false,
        ));
    }
    let now = crate::core::now_ms();
    if signer.not_before_ms > now + 300_000.0 || signer.not_after_ms < now {
        return Err(refusal(
            codes::STS_SCEP_0046,
            format!(
                "The signer's certificate is not valid now ({} to {}).",
                signer.valid_from, signer.valid_to
            ),
            "badTime",
            false,
        ));
    }
    Ok(digest)
}

/// `openEnvelope()`'s answer.
#[derive(Debug, Clone)]
pub struct Opened {
    pub content: Vec<u8>,
    pub cipher: String,
    pub transport: String,
}

fn random(n: usize) -> Vec<u8> {
    sts_crypto::random::random_bytes(n).unwrap_or_else(|_| vec![0; n])
}

/// `openEnvelope(bytes, raCertificatePem, raPrivateKeyPem)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn open_envelope(
    bytes: &[u8],
    ra_certificate_pem: &str,
    ra_private_pem: &str,
) -> Result<Opened, CmsRefusal> {
    let unreadable = || {
        refusal(codes::STS_SCEP_0026, "The content of the message is not a CMS ContentInfo carrying EnvelopedData.", "badMessageCheck", false)
    };
    let Some(outer) = read_one(bytes) else {
        return Err(unreadable());
    };
    if !outer.universal(16)
        || outer.children.len() != 2
        || oid_of(outer.children.first()) != oids::ENVELOPED_DATA
        || !outer.children[1].context(0)
    {
        return Err(unreadable());
    }
    let malformed = || {
        refusal(
            codes::STS_SCEP_0026,
            "The EnvelopedData is malformed or has no encrypted content.",
            "badMessageCheck",
            false,
        )
    };
    let ed = outer.children[1].children.first().ok_or_else(malformed)?;
    let p = &ed.children;
    let mut at = 1;
    if p.get(at).is_some_and(|n| n.context(0)) {
        at += 1;
    }
    let (Some(recipients), Some(eci)) = (p.get(at), p.get(at + 1)) else {
        return Err(malformed());
    };
    if !ed.universal(16)
        || !recipients.universal(17)
        || !eci.universal(16)
        || eci.children.len() != 3
        || !eci.children[2].context(0)
    {
        return Err(malformed());
    }
    let ra = describe_certificate(&crate::est::codec::pem_to_der(
        ra_certificate_pem,
    ));
    let mine = recipients.children.iter().find(|one| {
        one.universal(16)
            && one.children.len() == 4
            && one.children[0].universal(2)
            && ra.as_ref().is_some_and(|r| identifies(&one.children[1], r))
    });
    let Some(mine) = mine else {
        return Err(refusal(
            codes::STS_SCEP_0027,
            "The envelope is not encrypted to this realm's current RA certificate. Fetch it again with GetCACert.",
            "badMessageCheck",
            false,
        ));
    };
    let cipher_oid = oid_of(eci.children[1].children.first());
    let Some((_, cipher_id, key_bytes, _)) =
        CIPHERS.iter().find(|(o, _, _, _)| *o == cipher_oid)
    else {
        let named = REFUSED_CIPHERS
            .iter()
            .find(|(o, _)| *o == cipher_oid)
            .map(|(_, n)| n.to_string())
            .unwrap_or_else(|| format!("an unknown cipher ({})", cipher_oid));
        return Err(refusal(
            codes::STS_SCEP_0029,
            format!("The content is encrypted with {}. This server accepts AES-128-CBC, AES-192-CBC and AES-256-CBC.", named),
            "badAlg",
            false,
        ));
    };
    let iv = octets_of(eci.children[1].children.get(1));
    let ciphertext = octets_of(eci.children.get(2));
    let (Some(iv), Some(ciphertext)) = (
        iv.filter(|v| v.len() == 16),
        ciphertext.filter(|c| !c.is_empty() && c.len() % 16 == 0),
    ) else {
        return Err(refusal(
            codes::STS_SCEP_0026,
            "The content encryption parameters or the ciphertext are malformed.",
            "badMessageCheck",
            false,
        ));
    };
    let wrapped = octets_of(mine.children.get(3)).unwrap_or_default();
    let alg = &mine.children[2];
    let transport_oid = oid_of(alg.children.first());
    let (key, transport) = if transport_oid == oids::RSA_ENCRYPTION {
        let key = sts_crypto::cms::cms_key_transport_decrypt(
            "rsaes-pkcs1-v1_5",
            ra_private_pem,
            &wrapped,
            None,
        )
        .ok()
        .filter(|k| k.len() == *key_bytes)
        .unwrap_or_else(|| random(*key_bytes));
        (key, "rsaEncryption".to_string())
    } else if transport_oid == oids::RSAES_OAEP {
        let mut hash = "sha1";
        for param in alg
            .children
            .get(1)
            .map(|p| p.children.clone())
            .unwrap_or_default()
        {
            if param.context(0) {
                let named = param
                    .children
                    .first()
                    .and_then(|a| a.children.first())
                    .map(|o| oid_of(Some(o)))
                    .and_then(|o| {
                        OAEP_HASHES
                            .iter()
                            .find(|(oid, _)| *oid == o)
                            .map(|(_, n)| *n)
                    });
                match named {
                    Some(n) => hash = n,
                    None => {
                        return Err(refusal(
                            codes::STS_SCEP_0028,
                            "The content key is transported with an algorithm this server does not accept (rsaesOaep). It accepts RSAES-PKCS1-v1_5 and RSAES-OAEP.",
                            "badAlg",
                            false,
                        ))
                    }
                }
            }
        }
        let key = sts_crypto::cms::cms_key_transport_decrypt(
            "rsaes-oaep",
            ra_private_pem,
            &wrapped,
            Some(hash),
        )
        .ok()
        .filter(|k| k.len() == *key_bytes)
        .unwrap_or_else(|| random(*key_bytes));
        (key, format!("rsaesOaep-{}", hash))
    } else {
        return Err(refusal(
            codes::STS_SCEP_0028,
            format!(
                "The content key is transported with an algorithm this server does not accept ({}). It accepts RSAES-PKCS1-v1_5 and RSAES-OAEP.",
                transport_oid
            ),
            "badAlg",
            false,
        ));
    };
    let plain = sts_crypto::cms::scep_content_decrypt(
        cipher_id,
        &key,
        &iv,
        &ciphertext,
    )
    .ok()
    .filter(|p| read_one(p).is_some());
    let Some(plain) = plain else {
        return Err(refusal(
            codes::STS_SCEP_0030,
            "The content did not decrypt with this realm's RA key.",
            "badMessageCheck",
            false,
        ));
    };
    Ok(Opened {
        content: plain,
        cipher: cipher_oid,
        transport,
    })
}

/// `readIssuerAndSerial(bytes)`: `(issuerRaw, serialHex)`.
#[tracing::instrument(level = "trace", skip_all)]
pub fn read_issuer_and_serial(bytes: &[u8]) -> Option<(Vec<u8>, String)> {
    let node = read_one(bytes)?;
    let p = &node.children;
    (node.universal(16)
        && p.len() == 2
        && p[0].universal(16)
        && p[1].universal(2))
    .then(|| (p[0].raw.to_vec(), sts_pki::der::hex(p[1].content)))
}

/// `readIssuerAndSubject(bytes)`.
#[tracing::instrument(level = "trace", skip_all)]
pub fn read_issuer_and_subject(bytes: &[u8]) -> bool {
    read_one(bytes).is_some_and(|n| {
        n.universal(16)
            && n.children.len() == 2
            && n.children[0].universal(16)
            && n.children[1].universal(16)
    })
}

fn issuer_and_serial_of(cert: &Described) -> Vec<u8> {
    tlv(
        0x30,
        &[cert.issuer_raw.clone(), tlv(0x02, &cert.serial_raw)].concat(),
    )
}

fn algorithm_identifier(o: &str, with_null: bool) -> Vec<u8> {
    let mut v = oid(o);
    if with_null {
        v.extend([0x05, 0x00]);
    }
    tlv(0x30, &v)
}

fn content_info(type_oid: &str, inner: &[u8]) -> Vec<u8> {
    tlv(0x30, &[oid(type_oid), tlv(0xa0, inner)].concat())
}

/// `certsOnly(pems, crls)`: the degenerate SignedData GetCACert answers and
/// a successful CertRep's envelope holds.
#[tracing::instrument(level = "debug", skip_all)]
pub fn certs_only(pems: &[String], crls: &[Vec<u8>]) -> Vec<u8> {
    let certs: Vec<u8> = pems
        .iter()
        .flat_map(|p| crate::est::codec::pem_to_der(p))
        .collect();
    let mut value =
        [tlv(0x02, &[1]), tlv(0x31, &[]), tlv(0x30, &oid(oids::DATA))].concat();
    if !certs.is_empty() {
        value.extend(tlv(0xa0, &certs));
    }
    if !crls.is_empty() {
        value.extend(tlv(0xa1, &crls.concat()));
    }
    value.extend(tlv(0x31, &[]));
    content_info(oids::SIGNED_DATA, &tlv(0x30, &value))
}

/// `envelope(content, recipientCertificatePem, cipherOid)`: to one RSA
/// recipient, RSAES-PKCS1-v1_5, the AES-CBC the request used.
#[tracing::instrument(level = "debug", skip_all)]
pub fn envelope(
    content: &[u8],
    recipient_pem: &str,
    cipher_oid: &str,
) -> Option<Vec<u8>> {
    let (o, id, key_bytes, _) = CIPHERS
        .iter()
        .find(|(o, _, _, _)| *o == cipher_oid)
        .or_else(|| {
            CIPHERS
                .iter()
                .find(|(o, _, _, _)| *o == "2.16.840.1.101.3.4.1.42")
        })?;
    let recipient =
        describe_certificate(&crate::est::codec::pem_to_der(recipient_pem))
            .filter(|r| r.key_type == "rsa")?;
    let key = random(*key_bytes);
    let iv = random(16);
    let ciphertext =
        sts_crypto::cms::scep_content_encrypt(id, &key, &iv, content).ok()?;
    let wrapped =
        sts_crypto::cms::cms_key_transport_encrypt(&recipient.spki, &key)
            .ok()?;
    let recipient_info = tlv(
        0x30,
        &[
            tlv(0x02, &[0]),
            issuer_and_serial_of(&recipient),
            algorithm_identifier(oids::RSA_ENCRYPTION, true),
            tlv(0x04, &wrapped),
        ]
        .concat(),
    );
    let eci = tlv(
        0x30,
        &[
            oid(oids::DATA),
            tlv(0x30, &[oid(o), tlv(0x04, &iv)].concat()),
            tlv(0x80, &ciphertext),
        ]
        .concat(),
    );
    let ed = tlv(
        0x30,
        &[tlv(0x02, &[0]), tlv(0x31, &recipient_info), eci].concat(),
    );
    Some(content_info(oids::ENVELOPED_DATA, &ed))
}

fn attribute(o: &str, value: Vec<u8>) -> Vec<u8> {
    tlv(0x30, &[oid(o), tlv(0x31, &value)].concat())
}

fn printable(text: &str) -> Vec<u8> {
    tlv(0x13, text.as_bytes())
}

/// What `certRep()` is asked.
#[derive(Debug, Clone, Default)]
pub struct CertRepSpec {
    pub ra_certificate_pem: String,
    pub ra_private_key_pem: String,
    pub transaction_id: String,
    pub recipient_nonce: Vec<u8>,
    pub pki_status: String,
    pub fail_info: String,
    pub content: Option<Vec<u8>>,
    pub digest: String,
}

/// `certRep(spec)`: a CertRep signed by the RA (RFC 8894 section 3.3.2).
#[tracing::instrument(level = "debug", skip_all)]
pub fn cert_rep(spec: &CertRepSpec) -> Option<Vec<u8>> {
    let ra = describe_certificate(&crate::est::codec::pem_to_der(
        &spec.ra_certificate_pem,
    ))?;
    let digest =
        if ["sha256", "sha384", "sha512"].contains(&spec.digest.as_str()) {
            spec.digest.as_str()
        } else {
            "sha256"
        };
    let digest_oid = DIGESTS
        .iter()
        .find(|(_, id, _)| *id == digest)
        .map(|(o, _, _)| *o)?;
    let signature_oid = SIGNATURES
        .iter()
        .find(|(_, k, d, _)| *k == "rsa" && *d == digest)
        .map(|(o, _, _, _)| *o)?;
    let content = spec.content.clone();
    let md = match digest {
        "sha384" => sts_crypto::jws_alg::Hash::Sha384,
        "sha512" => sts_crypto::jws_alg::Hash::Sha512,
        _ => sts_crypto::jws_alg::Hash::Sha256,
    }
    .digest(content.as_deref().unwrap_or(&[]));
    let mut attrs = vec![
        attribute(oids::CONTENT_TYPE, oid(oids::DATA)),
        attribute(oids::MESSAGE_DIGEST, tlv(0x04, &md)),
        attribute(oids::MESSAGE_TYPE, printable("3")),
        attribute(oids::PKI_STATUS, printable(&spec.pki_status)),
        attribute(oids::TRANSACTION_ID, printable(&spec.transaction_id)),
        attribute(oids::SENDER_NONCE, tlv(0x04, &random(NONCE_BYTES))),
        attribute(oids::RECIPIENT_NONCE, tlv(0x04, &spec.recipient_nonce)),
    ];
    if spec.pki_status == pki_status("FAILURE") {
        let fail = if spec.fail_info.is_empty() {
            fail_info("badRequest")
        } else {
            spec.fail_info.clone()
        };
        attrs.push(attribute(oids::FAIL_INFO, printable(&fail)));
    }
    attrs.sort();
    let set = tlv(0x31, &attrs.concat());
    let signature =
        sts_crypto::cms::sign_bytes(digest, &set, &spec.ra_private_key_pem)
            .ok()?;
    let mut implicit = set.clone();
    implicit[0] = 0xa0;
    let signer_info = tlv(
        0x30,
        &[
            tlv(0x02, &[1]),
            issuer_and_serial_of(&ra),
            algorithm_identifier(digest_oid, false),
            implicit,
            algorithm_identifier(signature_oid, true),
            tlv(0x04, &signature),
        ]
        .concat(),
    );
    let mut encap = oid(oids::DATA);
    if let Some(c) = &content {
        encap.extend(tlv(0xa0, &tlv(0x04, c)));
    }
    let sd = tlv(
        0x30,
        &[
            tlv(0x02, &[1]),
            tlv(0x31, &algorithm_identifier(digest_oid, false)),
            tlv(0x30, &encap),
            tlv(0xa0, &ra.der),
            tlv(0x31, &signer_info),
        ]
        .concat(),
    );
    Some(content_info(oids::SIGNED_DATA, &sd))
}
