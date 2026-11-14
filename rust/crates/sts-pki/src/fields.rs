// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Certificate field checks: `common/crypto.js` section 18 (#1360,
//! 2026-11-06).
//!
//! Everything decidable from the bytes of ONE certificate and the role it is
//! asked to play. The door (`common/certificate_trust.ts`) composes these
//! with a path, a truststore and revocation; the path rules ask them as
//! their last rule (`pathRuleProblem()`'s `opts.leaf`, [`crate::path`]) and
//! a truststore asks them of who may enter it (`anchorProblem()`), so there
//! is one reading of what a keyUsage bit or an extendedKeyUsage means.
//!
//! **THE CHECKS ARE THE CHECK, NOT THE MODE**: the RSA size and the curve
//! are asked here outright, because a caller reaches this only when somebody
//! decided these checks apply.
//!
//! The facts are read as Node reads them: the names, the serial, the times
//! and the key as node's `X509Certificate` (OpenSSL) prints them, the
//! extensions as pkijs reads them. Held to Node's answers for every
//! certificate `tests/x509_vectors.rs` issues, under thirteen option sets.

use openssl::hash::MessageDigest;
use openssl::pkey::Id;
use openssl::x509::X509;
use serde::Serialize;
use sts_core::errors::{codes, ErrorCode};
use sts_crypto::keys::{rsa_key_problem, KeyPolicy};
use sts_crypto::pq_x509;

use crate::der;
use crate::path::entry::name_lines;

/// `CERTIFICATE_ROLES`.
pub const CERTIFICATE_ROLES: [&str; 3] = ["leaf", "intermediate", "anchor"];

/// `KEY_USAGE_BITS`: the names of keyUsage's bits, bit 0 first.
pub const KEY_USAGE_BITS: [&str; 9] = [
    "digitalSignature",
    "nonRepudiation",
    "keyEncipherment",
    "dataEncipherment",
    "keyAgreement",
    "keyCertSign",
    "cRLSign",
    "encipherOnly",
    "decipherOnly",
];

/// `EKU`: the one table of the extended key usages a use case asks by name.
pub mod eku {
    pub const ANY: &str = "2.5.29.37.0";
    pub const SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";
    pub const CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
    pub const CODE_SIGNING: &str = "1.3.6.1.5.5.7.3.3";
    pub const OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";
    pub const PKINIT_CLIENT_AUTH: &str = "1.3.6.1.5.2.3.4";
    pub const MS_SMART_CARD_LOGON: &str = "1.3.6.1.4.1.311.20.2.2";
    pub const TCG_AIK: &str = "2.23.133.8.3";
    pub const MDOC_DS: &str = "1.0.18013.5.1.2";
}

/// `CERTIFICATE_UNDERSTOOD_CRITICAL`: every extension a path rule reads, and
/// so may be accepted marked critical. The path rules read this same list.
pub const CERTIFICATE_UNDERSTOOD_CRITICAL: [&str; 11] = [
    "2.5.29.14",
    "2.5.29.15",
    "2.5.29.17",
    "2.5.29.19",
    "2.5.29.30",
    "2.5.29.35",
    "2.5.29.37",
    "2.5.29.32",
    "2.5.29.33",
    "2.5.29.36",
    "2.5.29.54",
];

/// `FIELD_CHECK_CODES`: one code per check, so an operator learns WHICH
/// field refused. Validity has two.
pub fn field_check_code(check: &str) -> Option<ErrorCode> {
    Some(match check {
        "expired" => codes::STS_KEYS_0168,
        "not-yet-valid" => codes::STS_KEYS_0169,
        "basic-constraints" => codes::STS_KEYS_0170,
        "key-usage" => codes::STS_KEYS_0171,
        "extended-key-usage" => codes::STS_KEYS_0172,
        "signature-strength" => codes::STS_KEYS_0173,
        "key-strength" => codes::STS_KEYS_0174,
        "critical-extensions" => codes::STS_KEYS_0175,
        _ => return None,
    })
}

const CERT_MD_SIGNATURES: [&str; 2] =
    ["1.2.840.113549.1.1.2", "1.2.840.113549.1.1.4"];
const CERT_SHA1_SIGNATURES: [&str; 4] = [
    "1.2.840.113549.1.1.5",
    "1.3.14.3.2.29",
    "1.2.840.10045.4.1",
    "1.2.840.10040.4.3",
];
const CERT_RSASSA_PSS: &str = "1.2.840.113549.1.1.10";
const CERT_SHA1: &str = "1.3.14.3.2.26";
const CERT_MINIMUM_RSA_BITS: u32 = 2048;
const CERT_EDWARDS_KEYS: [&str; 2] = ["ed25519", "ed448"];
/// `XML_ECDSA_CURVES`: the curves this service relies on, by OpenSSL's name.
const RELIED_CURVES: [&str; 8] = [
    "prime256v1",
    "secp384r1",
    "secp521r1",
    "secp256k1",
    "brainpoolP256r1",
    "brainpoolP320r1",
    "brainpoolP384r1",
    "brainpoolP512r1",
];

/// The subjectAltName forms the facts collect.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct SanFacts {
    pub dns: Vec<String>,
    pub email: Vec<String>,
    pub uri: Vec<String>,
    pub ip: Vec<String>,
}

/// `certificateFacts()`: the one reader every page, the inventory and the
/// field checks use. `key_usage` and `eku` are `None` where the extension is
/// absent, which is not the same as empty.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateFacts {
    pub subject: String,
    pub issuer: String,
    pub serial_hex: String,
    pub not_before: i64,
    pub not_after: i64,
    pub self_issued: bool,
    pub ca: bool,
    pub has_basic_constraints: bool,
    pub path_len: Option<i64>,
    pub key_usage: Option<Vec<&'static str>>,
    pub eku: Option<Vec<String>>,
    pub san: SanFacts,
    pub critical: Vec<String>,
    pub fingerprint256: String,
    pub spki_sha256: String,
    pub sig_alg: String,
    pub weak_signature: &'static str,
    pub key_alg: String,
    pub key_bits: u32,
    pub curve: String,
    pub spki_oid: String,
    /// node's `validFrom` / `validTo` (`ASN1_TIME_print()`), for sentences.
    #[serde(skip)]
    pub valid_from: String,
    #[serde(skip)]
    pub valid_to: String,
}

/// One field check that failed: `{ check, code, why }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldProblem {
    pub check: &'static str,
    pub code: ErrorCode,
    pub why: String,
}

/// What a use case asks of the extendedKeyUsage.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EkuRule {
    pub oids: Vec<String>,
    /// The use case's specification requires the extension to be present.
    pub required: bool,
}

/// `certificateFieldProblems()`'s options.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FieldOptions {
    /// `leaf` (the default), `intermediate` or `anchor`.
    pub role: Option<String>,
    /// Milliseconds since the epoch; `None` is the wall clock.
    pub now_ms: Option<i64>,
    pub skew_ms: i64,
    /// Any one of these bits; empty asks nothing.
    pub key_usage: Vec<String>,
    pub eku: Option<EkuRule>,
    pub may_be_ca: bool,
    pub allow_sha1: bool,
    /// OIDs a caller reads itself.
    pub allow_critical: Vec<String>,
    /// Replaces `now` for the window alone: sigstore's rule.
    pub validity_at_ms: Option<i64>,
}

/// `certificateExtensionNode()`: the value of an extension's OCTET STRING.
fn extension_node<'a>(
    oid: &str,
    value: &'a [u8],
) -> Result<der::Element<'a>, String> {
    der::read(value).ok_or_else(|| format!("the extension {} is not DER", oid))
}

/// `certificateIpText()`: what an IP address in a subjectAltName reads as.
fn ip_text(raw: &[u8]) -> String {
    if raw.len() == 4 {
        return raw.iter().map(u8::to_string).collect::<Vec<_>>().join(".");
    }
    raw.chunks(2)
        .filter(|c| c.len() == 2)
        .map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]])))
        .collect::<Vec<_>>()
        .join(":")
}

fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| char::from(b)).collect()
}

/// `certificateWeakSignature()`: `md`, `sha1` or empty. RSASSA-PSS names its
/// hash in its parameters, and SHA-1 when they name none (RFC 4055 section
/// 3.1).
fn weak_signature(oid: &str, params: &[u8]) -> &'static str {
    if CERT_MD_SIGNATURES.contains(&oid) {
        return "md";
    }
    if CERT_SHA1_SIGNATURES.contains(&oid) {
        return "sha1";
    }
    if oid != CERT_RSASSA_PSS {
        return "";
    }
    let mut hash = CERT_SHA1.to_string();
    let fields = der::read(params)
        .and_then(|p| der::children(p.content))
        .unwrap_or_default();
    for field in fields {
        if field.number != 0 || field.class != 2 {
            continue;
        }
        let named = der::read(field.content)
            .and_then(|a| der::children(a.content))
            .and_then(|a| a.first().and_then(|o| der::oid_string(o.content)));
        if let Some(h) = named {
            hash = h;
        }
    }
    if hash == CERT_SHA1 {
        "sha1"
    } else {
        ""
    }
}

/// node's `X509Certificate.serialNumber` (`BN_bn2hex()`), lower-cased.
fn serial_hex(x509: &X509) -> String {
    x509.serial_number()
        .to_bn()
        .ok()
        .and_then(|bn| bn.to_hex_str().ok().map(|s| s.to_string()))
        .unwrap_or_default()
        .to_lowercase()
}

/// `fingerprint256`: upper-case hex, a colon between octets.
fn fingerprint256(x509: &X509) -> String {
    x509.digest(MessageDigest::sha256())
        .map(|d| {
            d.iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(":")
        })
        .unwrap_or_default()
}

/// `certificateIdentifiers()`'s order: node's lines (one RDN each),
/// reversed, joined with `,`.
fn rfc4514(name_der: &[u8]) -> String {
    let mut lines = name_lines(name_der);
    lines.reverse();
    lines.join(",")
}

/// node's `asymmetricKeyType` of a key OpenSSL read, named from its OID the
/// way node names it, with its size and curve; `None` where OpenSSL cannot
/// read the key at all (a composite), which node answers by throwing.
fn key_of(
    x509: &X509,
    spki_oid: &str,
) -> Option<(String, u32, String, Vec<u8>)> {
    let key = x509.public_key().ok()?;
    let spki = key.public_key_to_der().ok()?;
    let (alg, bits, curve) = match key.id() {
        Id::RSA => ("rsa".to_string(), key.rsa().ok()?.n().num_bits(), ""),
        Id::RSA_PSS => {
            ("rsa-pss".to_string(), key.rsa().ok()?.n().num_bits(), "")
        }
        Id::EC => {
            let nid = key.ec_key().ok()?.group().curve_name();
            let name = nid.and_then(|n| n.short_name().ok()).unwrap_or("");
            return Some(("ec".to_string(), 0, name.to_string(), spki));
        }
        Id::ED25519 => ("ed25519".to_string(), 0, ""),
        Id::ED448 => ("ed448".to_string(), 0, ""),
        Id::X25519 => ("x25519".to_string(), 0, ""),
        Id::X448 => ("x448".to_string(), 0, ""),
        Id::DSA => ("dsa".to_string(), 0, ""),
        Id::DH => ("dh".to_string(), 0, ""),
        _ => match pq_x509::alg_for_oid(spki_oid) {
            Some(a) if a.composite.is_none() => (a.id.to_lowercase(), 0, ""),
            _ => return None,
        },
    };
    Some((alg, bits.max(0) as u32, curve.to_string(), spki))
}

/// `certificateFacts()`: one certificate's facts, or why the bytes are not
/// one.
pub fn certificate_facts(cert_der: &[u8]) -> Result<CertificateFacts, String> {
    let x509 = X509::from_der(cert_der).map_err(|e| e.to_string())?;
    let cert = crate::x509::Certificate::from_der(cert_der)
        .map_err(|e| e.0.clone())?;
    let subject_lines = name_lines(&cert.subject_der);
    let issuer_lines = name_lines(&cert.issuer_der);
    let spki_oid = der::read(&cert.spki)
        .and_then(|s| der::children(s.content))
        .and_then(|c| c.first().and_then(|a| der::children(a.content)))
        .and_then(|a| a.first().and_then(|o| der::oid_string(o.content)))
        .unwrap_or_default();
    let mut facts = CertificateFacts {
        subject: rfc4514(&cert.subject_der),
        issuer: rfc4514(&cert.issuer_der),
        serial_hex: serial_hex(&x509),
        not_before: cert.not_before.timestamp_millis(),
        not_after: cert.not_after.timestamp_millis(),
        self_issued: subject_lines == issuer_lines,
        ca: false,
        has_basic_constraints: false,
        path_len: None,
        key_usage: None,
        eku: None,
        san: SanFacts::default(),
        critical: Vec::new(),
        fingerprint256: fingerprint256(&x509),
        spki_sha256: String::new(),
        sig_alg: cert.signature_oid.clone(),
        weak_signature: weak_signature(
            &cert.signature_oid,
            &cert.signature_params,
        ),
        key_alg: String::new(),
        key_bits: 0,
        curve: String::new(),
        spki_oid: spki_oid.clone(),
        valid_from: x509.not_before().to_string(),
        valid_to: x509.not_after().to_string(),
    };
    for ext in &cert.extensions {
        if ext.critical {
            facts.critical.push(ext.oid.clone());
        }
        match ext.oid.as_str() {
            "2.5.29.19" => {
                let node = extension_node(&ext.oid, &ext.value)?;
                facts.has_basic_constraints = true;
                for field in der::children(node.content).unwrap_or_default() {
                    if field.tag == der::BOOLEAN {
                        facts.ca =
                            field.content.first().is_some_and(|b| *b != 0);
                    } else if field.tag == der::INTEGER {
                        facts.path_len = der::integer_value(field.content);
                    }
                }
            }
            "2.5.29.15" => {
                let node = extension_node(&ext.oid, &ext.value)?;
                let raw = node.content.get(1..).unwrap_or_default();
                facts.key_usage = Some(
                    KEY_USAGE_BITS
                        .iter()
                        .enumerate()
                        .filter(|(bit, _)| {
                            raw.get(bit >> 3).is_some_and(|b| {
                                (b >> (7 - (bit & 7))) & 1 == 1
                            })
                        })
                        .map(|(_, name)| *name)
                        .collect(),
                );
            }
            "2.5.29.37" => {
                let node = extension_node(&ext.oid, &ext.value)?;
                facts.eku = Some(
                    der::children(node.content)
                        .unwrap_or_default()
                        .iter()
                        .map(|p| der::oid_string(p.content).unwrap_or_default())
                        .collect(),
                );
            }
            "2.5.29.17" => {
                let node = extension_node(&ext.oid, &ext.value)?;
                for name in der::children(node.content).unwrap_or_default() {
                    match name.number {
                        1 => facts.san.email.push(latin1(name.content)),
                        2 => facts.san.dns.push(latin1(name.content)),
                        6 => facts.san.uri.push(latin1(name.content)),
                        7 => facts.san.ip.push(ip_text(name.content)),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    // A key node's OpenSSL cannot read (a composite) is named by its OID,
    // and the strength check asks the post-quantum registry about it.
    if let Some((alg, bits, curve, spki)) = key_of(&x509, &spki_oid) {
        facts.key_alg = alg;
        facts.key_bits = bits;
        facts.curve = curve;
        facts.spki_sha256 = openssl::hash::hash(MessageDigest::sha256(), &spki)
            .map(|d| der::hex(&d))
            .unwrap_or_default();
    }
    Ok(facts)
}

/// `certificateKeyStrengthProblem()`: whether the key is strong enough to
/// rely on, in every mode — empty, or a sentence.
fn key_strength_problem(x509: &X509, facts: &CertificateFacts) -> String {
    let alg = facts.key_alg.as_str();
    if alg.is_empty() {
        if pq_x509::alg_for_oid(&facts.spki_oid).is_none() {
            return format!(
                "its public key ({}) is not one this service can read",
                facts.spki_oid
            );
        }
        return String::new();
    }
    if alg == "rsa" || alg == "rsa-pss" {
        let problem = x509
            .public_key()
            .ok()
            .and_then(|k| rsa_key_problem(&k, 0, KeyPolicy::LENIENT));
        if let Some(p) = problem {
            return p;
        }
        if facts.key_bits < CERT_MINIMUM_RSA_BITS {
            return format!(
                "a {}-bit RSA key, where {} bits or more are required",
                facts.key_bits, CERT_MINIMUM_RSA_BITS
            );
        }
        return String::new();
    }
    if alg == "ec" {
        if !RELIED_CURVES.contains(&facts.curve.as_str()) {
            return format!(
                "an EC key on the curve \"{}\", which is not one this service relies on",
                facts.curve
            );
        }
        return String::new();
    }
    if !CERT_EDWARDS_KEYS.contains(&alg)
        && pq_x509::alg_for_oid(&facts.spki_oid).is_none()
    {
        return format!(
            "a {} key, which is not one this service relies on",
            alg
        );
    }
    String::new()
}

/// `certificateFieldProblems()`: holds one certificate to the role it is
/// asked to play and answers every check that failed, in order — validity,
/// basicConstraints, keyUsage, extendedKeyUsage, the signature's hash, the
/// key, critical extensions. A keyUsage absent permits everything (RFC 5280
/// section 4.2.1.3); an extendedKeyUsage absent is refused only where the
/// use case requires it, and present it must name a purpose asked, or
/// anyExtendedKeyUsage where presence is not what is required.
#[tracing::instrument(level = "debug", skip_all)]
pub fn certificate_field_problems(
    cert_der: &[u8],
    options: &FieldOptions,
) -> Result<Vec<FieldProblem>, String> {
    let x509 = X509::from_der(cert_der).map_err(|e| e.to_string())?;
    let facts = certificate_facts(cert_der)?;
    let role = options.role.as_deref().unwrap_or("leaf");
    let mut problems = Vec::new();
    let mut refuse = |check: &'static str, code: ErrorCode, why: String| {
        problems.push(FieldProblem {
            check,
            code,
            why: format!("\"{}\" {}", facts.subject, why),
        });
    };
    let mut now = options
        .now_ms
        .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());
    if let Some(at) = options.validity_at_ms {
        now = at;
    }
    // A certificate's times are whole seconds, so it is valid through the
    // whole second its notAfter names: `pathValidityProblem()`'s rule.
    now = now.div_euclid(1000) * 1000;
    if now - options.skew_ms > facts.not_after {
        refuse(
            "validity",
            codes::STS_KEYS_0168,
            format!("expired at {}", facts.valid_to),
        );
    } else if now + options.skew_ms < facts.not_before {
        refuse(
            "validity",
            codes::STS_KEYS_0169,
            format!("is not valid until {}", facts.valid_from),
        );
    }
    if role != "leaf" && !facts.ca {
        refuse(
            "basic-constraints",
            codes::STS_KEYS_0170,
            "is not a certificate authority (basicConstraints cA)".to_string(),
        );
    } else if role == "leaf" && facts.ca && !options.may_be_ca {
        refuse(
            "basic-constraints",
            codes::STS_KEYS_0170,
            "is a certificate authority used as an end entity".to_string(),
        );
    }
    if let Some(held) = &facts.key_usage {
        let asked = &options.key_usage;
        if !asked.is_empty()
            && !asked.iter().any(|bit| held.contains(&bit.as_str()))
        {
            let shown = if held.is_empty() {
                "empty".to_string()
            } else {
                held.join(", ")
            };
            refuse(
                "key-usage",
                codes::STS_KEYS_0171,
                format!(
                    "does not permit {} (keyUsage: {})",
                    asked.join(" or "),
                    shown
                ),
            );
        }
    }
    if let Some(rule) = options.eku.as_ref().filter(|r| !r.oids.is_empty()) {
        let named = rule
            .oids
            .iter()
            .any(|oid| facts.eku.as_ref().is_some_and(|e| e.contains(oid)));
        let any_purpose = !rule.required
            && facts
                .eku
                .as_ref()
                .is_some_and(|e| e.iter().any(|o| o == eku::ANY));
        if facts.eku.is_none() && rule.required {
            refuse(
                "extended-key-usage",
                codes::STS_KEYS_0172,
                format!(
                    "carries no extendedKeyUsage, where {} is required",
                    rule.oids.join(" or ")
                ),
            );
        } else if facts.eku.is_some() && !named && !any_purpose {
            refuse(
                "extended-key-usage",
                codes::STS_KEYS_0172,
                format!(
                    "has an extendedKeyUsage that does not name {}",
                    rule.oids.join(" or ")
                ),
            );
        }
    }
    if facts.weak_signature == "md"
        || (facts.weak_signature == "sha1" && !options.allow_sha1)
    {
        refuse(
            "signature-strength",
            codes::STS_KEYS_0173,
            format!("is signed with a broken hash ({})", facts.sig_alg),
        );
    }
    let weak_key = key_strength_problem(&x509, &facts);
    if !weak_key.is_empty() {
        refuse(
            "key-strength",
            codes::STS_KEYS_0174,
            format!("holds {}", weak_key),
        );
    }
    let unread: Vec<&str> = facts
        .critical
        .iter()
        .map(String::as_str)
        .filter(|oid| {
            !CERTIFICATE_UNDERSTOOD_CRITICAL.contains(oid)
                && !options.allow_critical.iter().any(|a| a == oid)
        })
        .collect();
    if !unread.is_empty() {
        refuse(
            "critical-extensions",
            codes::STS_KEYS_0175,
            format!(
                "carries a critical extension nothing here reads ({})",
                unread.join(", ")
            ),
        );
    }
    Ok(problems)
}

/// `certificateFieldProblem()`: the first of them.
pub fn certificate_field_problem(
    cert_der: &[u8],
    options: &FieldOptions,
) -> Result<Option<FieldProblem>, String> {
    Ok(certificate_field_problems(cert_der, options)?
        .into_iter()
        .next())
}

/// What a caller expects a certificate to name (RFC 9525: never the common
/// name). Every member given must match.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExpectedNames {
    pub dns: Option<String>,
    pub ip: Option<String>,
    pub uri: Option<String>,
    pub email: Option<String>,
}

/// The subjectAltName entries of one context tag, as their raw octets.
fn san_entries(cert: &crate::x509::Certificate, tag: u32) -> Vec<Vec<u8>> {
    cert.extension("2.5.29.17")
        .and_then(|e| der::read(&e.value))
        .and_then(|s| der::children(s.content))
        .unwrap_or_default()
        .iter()
        .filter(|g| g.class == 2 && g.number == tag)
        .map(|g| g.content.to_vec())
        .collect()
}

/// OpenSSL's `equal_nocase()`, with `skip_prefix()` for a name that begins
/// with a dot (`_X509_CHECK_FLAG_DOT_SUBDOMAINS`).
fn equal_nocase(pattern: &[u8], subject: &[u8], dot_subdomains: bool) -> bool {
    let mut p = pattern;
    if dot_subdomains {
        let mut skipped = p;
        while skipped.len() > subject.len() && skipped.first() != Some(&0) {
            skipped = &skipped[1..];
        }
        if skipped.len() == subject.len() {
            p = skipped;
        }
    }
    p.len() == subject.len()
        && p.iter()
            .zip(subject)
            .all(|(&l, &r)| l != 0 && l.eq_ignore_ascii_case(&r))
}

/// OpenSSL's `valid_star()`: the one legal wildcard of a pattern, at the
/// start or end of a non-IDNA first label that is not the last, with at
/// least two dots after it; partial wildcards allowed (node's default).
fn valid_star(p: &[u8]) -> Option<usize> {
    const START: u8 = 1;
    const IDNA: u8 = 2;
    const HYPHEN: u8 = 4;
    let mut star = None;
    let mut state = START;
    let mut dots = 0;
    for i in 0..p.len() {
        let c = p[i];
        if c == b'*' {
            let at_start = state & START != 0;
            let at_end = i == p.len() - 1 || p[i + 1] == b'.';
            if star.is_some() || state & IDNA != 0 || dots > 0 {
                return None;
            }
            if !at_start && !at_end {
                return None;
            }
            star = Some(i);
            state &= !START;
        } else if c.is_ascii_alphanumeric() {
            if state & START != 0
                && p.len() - i >= 4
                && p[i..i + 4].eq_ignore_ascii_case(b"xn--")
            {
                state |= IDNA;
            }
            state &= !(HYPHEN | START);
        } else if c == b'.' {
            if state & (HYPHEN | START) != 0 {
                return None;
            }
            state = START;
            dots += 1;
        } else if c == b'-' {
            if state & START != 0 {
                return None;
            }
            state |= HYPHEN;
        } else {
            return None;
        }
    }
    if state & (START | HYPHEN) != 0 || dots < 2 {
        return None;
    }
    star
}

/// OpenSSL's `wildcard_match()`.
fn wildcard_match(prefix: &[u8], suffix: &[u8], subject: &[u8]) -> bool {
    if subject.len() < prefix.len() + suffix.len() {
        return false;
    }
    if !equal_nocase(prefix, &subject[..prefix.len()], false) {
        return false;
    }
    let (start, end) = (prefix.len(), subject.len() - suffix.len());
    if !equal_nocase(&subject[end..], suffix, false) {
        return false;
    }
    let mut allow_idna = false;
    if prefix.is_empty() && suffix.first() == Some(&b'.') {
        if start == end {
            return false;
        }
        allow_idna = true;
    }
    if !allow_idna
        && subject.len() >= 4
        && subject[..4].eq_ignore_ascii_case(b"xn--")
    {
        return false;
    }
    if end == start + 1 && subject[start] == b'*' {
        return true;
    }
    subject[start..end]
        .iter()
        .all(|c| c.is_ascii_alphanumeric() || *c == b'-')
}

/// OpenSSL's `equal_wildcard()`, the pattern being the certificate's.
fn equal_wildcard(
    pattern: &[u8],
    subject: &[u8],
    dot_subdomains: bool,
) -> bool {
    let star = if subject.len() > 1 && subject[0] == b'.' {
        None
    } else {
        valid_star(pattern)
    };
    match star {
        None => equal_nocase(pattern, subject, dot_subdomains),
        Some(at) => wildcard_match(&pattern[..at], &pattern[at + 1..], subject),
    }
}

/// OpenSSL's `equal_email()`: the domain compared without case, the local
/// part with it.
fn equal_email(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = a.len();
    while i > 0 {
        i -= 1;
        if a[i] == b'@' || b[i] == b'@' {
            if !equal_nocase(&a[i..], &b[i..], false) {
                return false;
            }
            break;
        }
    }
    if i == 0 {
        i = a.len();
    }
    a[..i] == b[..i]
}

/// `certificateNameMatches()`: whether a certificate's subjectAltName names
/// what a caller expects — node's `checkHost()`, `checkIP()` and
/// `checkEmail()` with `subject: 'never'`, and a URI exactly. False when
/// nothing was given; an `ip` that is not an address is node's "Invalid
/// name".
pub fn certificate_name_matches(
    cert_der: &[u8],
    expected: &ExpectedNames,
) -> Result<bool, String> {
    let cert = crate::x509::Certificate::from_der(cert_der)
        .map_err(|e| e.0.clone())?;
    let mut any = false;
    if let Some(dns) = expected.dns.as_deref().filter(|d| !d.is_empty()) {
        any = true;
        let name = dns.as_bytes();
        let dot = name.len() > 1 && name[0] == b'.';
        if !san_entries(&cert, 2)
            .iter()
            .any(|p| !p.is_empty() && equal_wildcard(p, name, dot))
        {
            return Ok(false);
        }
    }
    if let Some(ip) = expected.ip.as_deref().filter(|i| !i.is_empty()) {
        any = true;
        let wanted: Vec<u8> = match ip.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(a)) => a.octets().to_vec(),
            Ok(std::net::IpAddr::V6(a)) => a.octets().to_vec(),
            Err(_) => return Err("Invalid name".to_string()),
        };
        if !san_entries(&cert, 7).contains(&wanted) {
            return Ok(false);
        }
    }
    if let Some(uri) = expected.uri.as_deref().filter(|u| !u.is_empty()) {
        any = true;
        if !san_entries(&cert, 6).iter().any(|p| latin1(p) == uri) {
            return Ok(false);
        }
    }
    if let Some(email) = expected.email.as_deref().filter(|e| !e.is_empty()) {
        any = true;
        if !san_entries(&cert, 1)
            .iter()
            .any(|p| !p.is_empty() && equal_email(p, email.as_bytes()))
        {
            return Ok(false);
        }
    }
    Ok(any)
}
