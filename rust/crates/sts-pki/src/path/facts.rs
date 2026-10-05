// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The facts of one certificate the path rules are asked of, read once
//! (`pki.js`'s `pathFactsOf()`). `problem` is set when the certificate
//! cannot be held to the rules at all — it does not parse, it repeats an
//! extension, or an extension read here is malformed — and every rule
//! question then refuses it.

use crate::der::{self, Element};
use crate::x509::read::Certificate;

pub const SUBJECT_KEY_IDENTIFIER: &str = "2.5.29.14";
pub const KEY_USAGE: &str = "2.5.29.15";
pub const SUBJECT_ALT_NAME: &str = "2.5.29.17";
pub const BASIC_CONSTRAINTS: &str = "2.5.29.19";
pub const NAME_CONSTRAINTS: &str = "2.5.29.30";
pub const AUTHORITY_KEY_IDENTIFIER: &str = "2.5.29.35";
pub const EXT_KEY_USAGE: &str = "2.5.29.37";
pub const CERTIFICATE_POLICIES: &str = "2.5.29.32";
pub const POLICY_MAPPINGS: &str = "2.5.29.33";
pub const POLICY_CONSTRAINTS: &str = "2.5.29.36";
pub const INHIBIT_ANY_POLICY: &str = "2.5.29.54";

/// `PATH_EXTENSION_OIDS` by name, for `allowCritical`.
pub const PATH_EXTENSION_OIDS: &[(&str, &str)] = &[
    ("subjectKeyIdentifier", SUBJECT_KEY_IDENTIFIER),
    ("keyUsage", KEY_USAGE),
    ("subjectAltName", SUBJECT_ALT_NAME),
    ("basicConstraints", BASIC_CONSTRAINTS),
    ("nameConstraints", NAME_CONSTRAINTS),
    ("authorityKeyIdentifier", AUTHORITY_KEY_IDENTIFIER),
    ("extKeyUsage", EXT_KEY_USAGE),
    ("certificatePolicies", CERTIFICATE_POLICIES),
    ("policyMappings", POLICY_MAPPINGS),
    ("policyConstraints", POLICY_CONSTRAINTS),
    ("inhibitAnyPolicy", INHIBIT_ANY_POLICY),
];

pub const KEY_USAGE_BITS: &[&str] = &[
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

const EMAIL_ADDRESS_OID: &str = "1.2.840.113549.1.9.1";
const COMMON_NAME_OID: &str = "2.5.4.3";
const MD_SIGNATURES: &[&str] =
    &["1.2.840.113549.1.1.2", "1.2.840.113549.1.1.4"];
const SHA1_SIGNATURES: &[&str] = &[
    "1.2.840.113549.1.1.5",
    "1.3.14.3.2.29",
    "1.2.840.10045.4.1",
    "1.2.840.10040.4.3",
];
const RSASSA_PSS: &str = "1.2.840.113549.1.1.10";
const SHA1: &str = "1.3.14.3.2.26";
const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";

/// A GeneralName's form, by its CHOICE tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    OtherName,
    Email,
    Dns,
    X400Address,
    Dn,
    EdiPartyName,
    Uri,
    Ip,
    RegisteredId,
}

impl Form {
    fn from_tag(tag: u32) -> Option<Form> {
        Some(match tag {
            0 => Form::OtherName,
            1 => Form::Email,
            2 => Form::Dns,
            3 => Form::X400Address,
            4 => Form::Dn,
            5 => Form::EdiPartyName,
            6 => Form::Uri,
            7 => Form::Ip,
            8 => Form::RegisteredId,
            _ => return None,
        })
    }

    /// `x509.js`'s word for it in a sentence.
    pub fn word(self) -> &'static str {
        match self {
            Form::OtherName => "otherName",
            Form::Email => "email",
            Form::Dns => "dns",
            Form::X400Address => "x400Address",
            Form::Dn => "dn",
            Form::EdiPartyName => "ediPartyName",
            Form::Uri => "uri",
            Form::Ip => "ip",
            Form::RegisteredId => "registeredID",
        }
    }

    /// The forms a name constraint is evaluated in.
    pub fn evaluated(self) -> bool {
        matches!(
            self,
            Form::Email | Form::Dns | Form::Uri | Form::Ip | Form::Dn
        )
    }
}

/// A GeneralName's value: a string for email, dns and uri (`None` when not
/// printable ASCII), the bytes of an ip, the RDN list of a dn, nothing for
/// a form not evaluated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameValue {
    Text(Option<String>),
    Bytes(Vec<u8>),
    Rdns(Vec<String>),
    None,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneralName {
    pub form: Form,
    pub value: NameValue,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subtree {
    pub form: Form,
    pub value: NameValue,
    /// A minimum other than 0 or any maximum: not evaluated.
    pub bounded: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NameConstraints {
    pub permitted: Option<Vec<Subtree>>,
    pub excluded: Option<Vec<Subtree>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyMapping {
    pub issuer: String,
    pub subject: String,
}

/// `pathFactsOf()`'s record.
#[derive(Clone, Debug, Default)]
pub struct PathFacts {
    pub problem: String,
    pub extensions: Vec<String>,
    pub critical: Vec<String>,
    pub ca: bool,
    pub has_basic_constraints: bool,
    pub path_len: Option<i64>,
    pub key_usage: Option<Vec<&'static str>>,
    pub ekus: Option<Vec<String>>,
    pub names: Vec<GeneralName>,
    pub subject_rdns: Vec<String>,
    pub issuer_rdns: Vec<String>,
    pub name_constraints: Option<NameConstraints>,
    pub san_critical: bool,
    pub has_san: bool,
    pub self_issued: bool,
    pub spki_oid: String,
    pub key_identifier: String,
    pub authority_key_identifier: String,
    pub not_before_ms: i64,
    pub not_after_ms: i64,
    pub cert: Option<Certificate>,
    pub common_names: Vec<String>,
    /// `md`, `sha1` or empty.
    pub weak_signature: &'static str,
    pub policies: Option<Vec<String>>,
    pub policy_mappings: Option<Vec<PolicyMapping>>,
    pub require_explicit_policy: Option<i64>,
    pub inhibit_policy_mapping: Option<i64>,
    pub inhibit_any_policy: Option<i64>,
}

type R<T> = Result<T, String>;

/// `derValueOf()`: one value, refusing trailing bytes.
fn der_value_of(bytes: &[u8]) -> R<Element<'_>> {
    match der::read(bytes) {
        Some(e) if e.rest.is_empty() => Ok(e),
        Some(_) => Err("not one DER value".to_string()),
        // asn1js's sentence for a length past the end of the input.
        None if declared_length_overruns(bytes) => Err(
            "not one DER value (End of input reached before message was fully decoded (inconsistent offset and length values))"
                .to_string(),
        ),
        None => Err("not one DER value".to_string()),
    }
}

/// Whether the first element's declared length runs past the input.
fn declared_length_overruns(bytes: &[u8]) -> bool {
    let Some(&first_len) = bytes.get(1) else {
        return false;
    };
    let (len, header) = if first_len & 0x80 == 0 {
        (usize::from(first_len), 2)
    } else {
        let n = usize::from(first_len & 0x7f);
        if n == 0 || n > 8 || bytes.len() < 2 + n {
            return false;
        }
        (
            bytes[2..2 + n]
                .iter()
                .fold(0usize, |a, &b| (a << 8) | usize::from(b)),
            2 + n,
        )
    };
    header + len > bytes.len()
}

/// JavaScript's `\s`.
fn js_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n'
            | '\u{b}'
            | '\u{c}'
            | '\r'
            | ' '
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

/// The universal string types asn1js models as a `BaseStringBlock`.
pub fn is_string_type(tag: u8) -> bool {
    matches!(
        tag,
        0x0c | 0x12
            | 0x13
            | 0x14
            | 0x15
            | 0x16
            | 0x19
            | 0x1a
            | 0x1b
            | 0x1c
            | 0x1d
            | 0x1e
    )
}

/// `getValue()` of an asn1js string: UTF-8, UTF-16BE, UTF-32BE, else one
/// character per octet.
pub fn string_of(e: &Element<'_>) -> String {
    match e.tag {
        0x0c => String::from_utf8_lossy(e.content).into_owned(),
        0x1e => {
            let units: Vec<u16> = e
                .content
                .chunks(2)
                .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                .collect();
            String::from_utf16_lossy(&units)
        }
        0x1c => e
            .content
            .chunks(4)
            .filter(|c| c.len() == 4)
            .map(|c| {
                char::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                    .unwrap_or('\u{fffd}')
            })
            .collect(),
        _ => e.content.iter().map(|&b| char::from(b)).collect(),
    }
}

/// `rdnsOfName()`: each RDN the sorted `oid=value` of its attributes, a
/// string compared as RFC 5280 section 7.1 asks.
pub fn rdns_of_name(node: &Element<'_>) -> R<Vec<String>> {
    if node.tag != der::SEQUENCE {
        return Err("a Name is not a SEQUENCE".to_string());
    }
    let mut out = Vec::new();
    for set in der::children(node.content).ok_or("a Name does not parse")? {
        if set.tag == der::SET && set.content.is_empty() {
            continue;
        }
        if set.tag != der::SET {
            return Err("a RelativeDistinguishedName is not a SET".to_string());
        }
        let mut attrs = Vec::new();
        for atv in der::children(set.content).ok_or("an RDN does not parse")? {
            let parts = if atv.constructed {
                der::children(atv.content)
            } else {
                None
            };
            let parts = parts.unwrap_or_default();
            if parts.len() != 2 || parts[0].tag != der::OID {
                return Err(
                    "an attribute is not a type and a value".to_string()
                );
            }
            let oid = der::oid_string(parts[0].content).unwrap_or_default();
            let value = &parts[1];
            let text = if is_string_type(value.tag) {
                let s = string_of(value);
                let trimmed = s.trim_matches(js_space);
                let mut collapsed = String::new();
                let mut space = false;
                for c in trimmed.chars() {
                    if js_space(c) {
                        if !space {
                            collapsed.push(' ');
                        }
                        space = true;
                    } else {
                        collapsed.push(c);
                        space = false;
                    }
                }
                collapsed.to_lowercase()
            } else {
                format!("#{}", der::hex(value.raw))
            };
            attrs.push(format!("{}={}", oid, text));
        }
        attrs.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
        out.push(attrs.join("+"));
    }
    Ok(out)
}

fn ascii_of(content: &[u8]) -> Option<String> {
    content
        .iter()
        .all(|&b| (0x20..=0x7e).contains(&b))
        .then(|| content.iter().map(|&b| char::from(b)).collect())
}

/// `generalNameOf()`.
pub fn general_name_of(node: &Element<'_>) -> R<GeneralName> {
    if node.class != 2 {
        return Err("a GeneralName is not context-tagged".to_string());
    }
    let form = Form::from_tag(node.number)
        .ok_or_else(|| format!("a GeneralName has tag {}", node.number))?;
    let value = match form {
        Form::Email | Form::Dns | Form::Uri => {
            if node.constructed {
                return Err(format!(
                    "a {} GeneralName is constructed",
                    form.word()
                ));
            }
            NameValue::Text(ascii_of(node.content))
        }
        Form::Ip => {
            if node.constructed {
                return Err(
                    "an iPAddress GeneralName is constructed".to_string()
                );
            }
            NameValue::Bytes(node.content.to_vec())
        }
        Form::Dn => {
            let inner = if node.constructed {
                der::children(node.content)
            } else {
                None
            };
            match inner.as_deref() {
                Some([one]) => NameValue::Rdns(rdns_of_name(one)?),
                _ => {
                    return Err(
                        "a directoryName holds no single Name".to_string()
                    )
                }
            }
        }
        _ => NameValue::None,
    };
    Ok(GeneralName { form, value })
}

fn general_names_of(bytes: &[u8]) -> R<Vec<GeneralName>> {
    let node = der_value_of(bytes)?;
    let kids = (node.tag == der::SEQUENCE)
        .then(|| der::children(node.content))
        .flatten();
    match kids {
        Some(k) if !k.is_empty() => k.iter().map(general_name_of).collect(),
        _ => Err("GeneralNames is not a non-empty SEQUENCE".to_string()),
    }
}

fn name_constraints_of(bytes: &[u8]) -> R<NameConstraints> {
    let node = der_value_of(bytes)?;
    if node.tag != der::SEQUENCE {
        return Err("NameConstraints is not a SEQUENCE".to_string());
    }
    let mut out = NameConstraints::default();
    for part in
        der::children(node.content).ok_or("NameConstraints does not parse")?
    {
        if part.class != 2 || part.number > 1 || !part.constructed {
            return Err("NameConstraints holds something other than permittedSubtrees [0] and excludedSubtrees [1]".to_string());
        }
        let key = if part.number == 0 {
            "permitted"
        } else {
            "excluded"
        };
        let slot = if part.number == 0 {
            &mut out.permitted
        } else {
            &mut out.excluded
        };
        if slot.is_some() {
            return Err(format!("NameConstraints names {}Subtrees twice", key));
        }
        let subtrees = der::children(part.content).unwrap_or_default();
        if subtrees.is_empty() {
            return Err(format!("{}Subtrees is an empty sequence", key));
        }
        let mut list = Vec::new();
        for subtree in subtrees {
            let fields = (subtree.tag == der::SEQUENCE)
                .then(|| der::children(subtree.content))
                .flatten()
                .filter(|f| !f.is_empty())
                .ok_or("a GeneralSubtree is not a SEQUENCE")?;
            let base = general_name_of(&fields[0])?;
            let bounded = fields[1..].iter().any(|f| {
                let bytes = if f.constructed { &[][..] } else { f.content };
                !(f.number == 0 && bytes == [0])
            });
            list.push(Subtree {
                form: base.form,
                value: base.value,
                bounded,
            });
        }
        *slot = Some(list);
    }
    if out.permitted.is_none() && out.excluded.is_none() {
        return Err("NameConstraints has neither permittedSubtrees nor excludedSubtrees".to_string());
    }
    Ok(out)
}

fn certificate_policies_of(bytes: &[u8]) -> R<Vec<String>> {
    let node = der_value_of(bytes)?;
    let infos = (node.tag == der::SEQUENCE)
        .then(|| der::children(node.content))
        .flatten()
        .filter(|k| !k.is_empty())
        .ok_or("certificatePolicies is not a non-empty SEQUENCE")?;
    let mut out: Vec<String> = Vec::new();
    for info in infos {
        let parts = (info.tag == der::SEQUENCE)
            .then(|| der::children(info.content))
            .flatten();
        let parts = match parts {
            Some(p)
                if !p.is_empty() && p.len() <= 2 && p[0].tag == der::OID =>
            {
                p
            }
            _ => {
                return Err(
                    "a PolicyInformation is not a policy and qualifiers"
                        .to_string(),
                )
            }
        };
        let oid = der::oid_string(parts[0].content).unwrap_or_default();
        if out.contains(&oid) {
            return Err(format!(
                "certificatePolicies names {} twice (RFC 5280 section 4.2.1.4)",
                oid
            ));
        }
        out.push(oid);
    }
    Ok(out)
}

fn policy_mappings_of(bytes: &[u8]) -> R<Vec<PolicyMapping>> {
    let node = der_value_of(bytes)?;
    let pairs = (node.tag == der::SEQUENCE)
        .then(|| der::children(node.content))
        .flatten()
        .filter(|k| !k.is_empty())
        .ok_or("policyMappings is not a non-empty SEQUENCE")?;
    pairs
        .iter()
        .map(|pair| {
            let parts = (pair.tag == der::SEQUENCE)
                .then(|| der::children(pair.content))
                .flatten();
            match parts.as_deref() {
                Some([a, b]) if a.tag == der::OID && b.tag == der::OID => {
                    Ok(PolicyMapping {
                        issuer: der::oid_string(a.content).unwrap_or_default(),
                        subject: der::oid_string(b.content).unwrap_or_default(),
                    })
                }
                _ => Err("a policy mapping is not two policy OIDs".to_string()),
            }
        })
        .collect()
}

fn policy_constraints_of(bytes: &[u8]) -> R<(Option<i64>, Option<i64>)> {
    let node = der_value_of(bytes)?;
    let fields = (node.tag == der::SEQUENCE)
        .then(|| der::children(node.content))
        .flatten()
        .filter(|k| !k.is_empty())
        .ok_or("policyConstraints is not a non-empty SEQUENCE")?;
    let (mut require, mut inhibit) = (None, None);
    for f in fields {
        let raw = if f.constructed { &[][..] } else { f.content };
        if f.class != 2
            || f.number > 1
            || f.constructed
            || raw.is_empty()
            || raw.len() > 4
            || raw[0] & 0x80 != 0
        {
            return Err(
                "policyConstraints holds something other than two SkipCerts"
                    .to_string(),
            );
        }
        let (slot, key) = if f.number == 0 {
            (&mut require, "requireExplicitPolicy")
        } else {
            (&mut inhibit, "inhibitPolicyMapping")
        };
        if slot.is_some() {
            return Err(format!("policyConstraints names {} twice", key));
        }
        *slot =
            Some(raw.iter().fold(0i64, |acc, &b| (acc << 8) | i64::from(b)));
    }
    Ok((require, inhibit))
}

/// The subject Name's DER as it is encoded in the certificate.
pub fn subject_name_der(cert_der: &[u8]) -> Option<Vec<u8>> {
    Certificate::from_der(cert_der).ok().map(|c| c.subject_der)
}

/// The facts of one certificate.
pub fn path_facts_of(cert_der: &[u8]) -> PathFacts {
    let mut facts = PathFacts::default();
    if let Err(why) = read_facts(cert_der, &mut facts) {
        facts.problem = format!("it cannot be held to RFC 5280: {}", why);
    }
    facts
}

fn read_facts(cert_der: &[u8], facts: &mut PathFacts) -> R<()> {
    let cert = Certificate::from_der(cert_der).map_err(|e| e.0)?;
    // Kept even when a rule below refuses the certificate: the builder
    // still names it by its key (`identityOf()`).
    facts.cert = Some(cert.clone());
    let subject = der_value_of(&cert.subject_der)?;
    facts.subject_rdns = rdns_of_name(&subject)?;
    facts.issuer_rdns = rdns_of_name(&der_value_of(&cert.issuer_der)?)?;
    facts.self_issued =
        facts.subject_rdns.join(",") == facts.issuer_rdns.join(",");
    for set in der::children(subject.content).unwrap_or_default() {
        for atv in der::children(set.content).unwrap_or_default() {
            let parts = der::children(atv.content).unwrap_or_default();
            if parts.len() < 2 {
                continue;
            }
            let oid = der::oid_string(parts[0].content).unwrap_or_default();
            if oid == EMAIL_ADDRESS_OID && is_string_type(parts[1].tag) {
                facts.names.push(GeneralName {
                    form: Form::Email,
                    value: NameValue::Text(Some(string_of(&parts[1]))),
                });
            }
        }
    }
    if !facts.subject_rdns.is_empty() {
        facts.names.push(GeneralName {
            form: Form::Dn,
            value: NameValue::Rdns(facts.subject_rdns.clone()),
        });
    }
    for set in der::children(subject.content).unwrap_or_default() {
        for atv in der::children(set.content).unwrap_or_default() {
            let parts = der::children(atv.content).unwrap_or_default();
            if parts.len() >= 2
                && der::oid_string(parts[0].content).as_deref()
                    == Some(COMMON_NAME_OID)
                && is_string_type(parts[1].tag)
            {
                facts.common_names.push(string_of(&parts[1]));
            }
        }
    }
    let spki = der::read(&cert.spki).ok_or("the key does not parse")?;
    let alg = der::children(spki.content)
        .and_then(|c| c.first().and_then(|a| der::children(a.content)))
        .unwrap_or_default();
    facts.spki_oid = alg
        .first()
        .and_then(|o| der::oid_string(o.content))
        .unwrap_or_default();
    if facts.spki_oid == EC_PUBLIC_KEY
        && alg.get(1).is_none_or(|p| p.tag != der::OID)
    {
        return Err("its EC key names no named curve (RFC 5480 section 2.1.1 forbids specifiedCurve and implicitCurve)".to_string());
    }
    let signed_with = cert.signature_oid.as_str();
    facts.weak_signature = if MD_SIGNATURES.contains(&signed_with) {
        "md"
    } else if SHA1_SIGNATURES.contains(&signed_with) {
        "sha1"
    } else if signed_with == RSASSA_PSS {
        let hash = der::read(&cert.signature_params)
            .and_then(|p| der::children(p.content))
            .and_then(|f| {
                f.iter()
                    .find(|x| x.class == 2 && x.number == 0)
                    .and_then(|h| der::read(h.content))
                    .and_then(|a| der::children(a.content))
                    .and_then(|a| {
                        a.first().and_then(|o| der::oid_string(o.content))
                    })
            })
            .unwrap_or_else(|| SHA1.to_string());
        if hash == SHA1 {
            "sha1"
        } else {
            ""
        }
    } else {
        ""
    };
    facts.not_before_ms = cert.not_before.timestamp_millis();
    facts.not_after_ms = cert.not_after.timestamp_millis();
    for ext in &cert.extensions {
        let oid = ext.oid.as_str();
        if facts.extensions.iter().any(|e| e == oid) {
            return Err(format!(
                "the extension {} appears twice (RFC 5280 section 4.2)",
                oid
            ));
        }
        facts.extensions.push(oid.to_string());
        if ext.critical {
            facts.critical.push(oid.to_string());
        }
        let bytes = ext.value.as_slice();
        match oid {
            BASIC_CONSTRAINTS => {
                let node = der_value_of(bytes)?;
                if node.tag != der::SEQUENCE {
                    return Err(
                        "basicConstraints is not a SEQUENCE".to_string()
                    );
                }
                facts.has_basic_constraints = true;
                for field in der::children(node.content)
                    .ok_or("basicConstraints does not parse")?
                {
                    match field.tag {
                        der::BOOLEAN => {
                            facts.ca =
                                field.content.first().is_some_and(|b| *b != 0)
                        }
                        der::INTEGER => {
                            facts.path_len = der::integer_value(field.content)
                        }
                        _ => {
                            return Err(
                                "basicConstraints holds an unexpected field"
                                    .to_string(),
                            )
                        }
                    }
                }
            }
            KEY_USAGE => {
                let node = der_value_of(bytes)?;
                if node.tag != der::BIT_STRING {
                    return Err("keyUsage is not a BIT STRING".to_string());
                }
                let raw = node.content.get(1..).unwrap_or_default();
                facts.key_usage = Some(
                    KEY_USAGE_BITS
                        .iter()
                        .enumerate()
                        .filter(|(bit, _)| {
                            raw.len() > bit >> 3
                                && (raw[bit >> 3] >> (7 - (bit & 7))) & 1 == 1
                        })
                        .map(|(_, name)| *name)
                        .collect(),
                );
            }
            EXT_KEY_USAGE => {
                let node = der_value_of(bytes)?;
                let purposes = (node.tag == der::SEQUENCE)
                    .then(|| der::children(node.content))
                    .flatten()
                    .filter(|k| !k.is_empty())
                    .ok_or("extKeyUsage is not a non-empty SEQUENCE")?;
                let mut ekus = Vec::new();
                for p in purposes {
                    if p.tag != der::OID {
                        return Err(
                            "extKeyUsage holds something not a purpose"
                                .to_string(),
                        );
                    }
                    ekus.push(der::oid_string(p.content).unwrap_or_default());
                }
                facts.ekus = Some(ekus);
            }
            SUBJECT_ALT_NAME => {
                facts.has_san = true;
                facts.san_critical = ext.critical;
                facts.names.extend(general_names_of(bytes)?);
            }
            NAME_CONSTRAINTS => {
                facts.name_constraints = Some(name_constraints_of(bytes)?)
            }
            CERTIFICATE_POLICIES => {
                facts.policies = Some(certificate_policies_of(bytes)?)
            }
            POLICY_MAPPINGS => {
                facts.policy_mappings = Some(policy_mappings_of(bytes)?)
            }
            POLICY_CONSTRAINTS => {
                let (r, i) = policy_constraints_of(bytes)?;
                facts.require_explicit_policy = r;
                facts.inhibit_policy_mapping = i;
            }
            INHIBIT_ANY_POLICY => {
                let node = der_value_of(bytes)?;
                let value = (node.tag == der::INTEGER
                    && node.content.len() <= 6)
                    .then(|| der::integer_value(node.content))
                    .flatten()
                    .filter(|v| *v >= 0)
                    .ok_or("inhibitAnyPolicy is not a SkipCerts INTEGER")?;
                facts.inhibit_any_policy = Some(value);
            }
            SUBJECT_KEY_IDENTIFIER => {
                let node = der_value_of(bytes)?;
                facts.key_identifier = if node.tag == der::OCTET_STRING {
                    der::hex(node.content)
                } else {
                    String::new()
                };
            }
            AUTHORITY_KEY_IDENTIFIER => {
                let node = der_value_of(bytes)?;
                facts.authority_key_identifier = if node.tag == der::SEQUENCE {
                    der::children(node.content)
                        .unwrap_or_default()
                        .iter()
                        .find(|f| f.class == 2 && f.number == 0)
                        .map(|f| {
                            if f.constructed {
                                String::new()
                            } else {
                                der::hex(f.content)
                            }
                        })
                        .unwrap_or_default()
                } else {
                    String::new()
                };
            }
            _ => {}
        }
    }
    Ok(())
}
