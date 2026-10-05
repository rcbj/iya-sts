// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Distinguished names and general names (`x509.js`'s "Distinguished
//! names" and "General names").
//!
//! A Name is an RDNSequence with ONE attribute per SET, in the order given
//! — the order IS the name. Each attribute has the string type its table
//! row says: `C` a PrintableString, `emailAddress` and `DC` IA5Strings,
//! everything else UTF8String, because a country in UTF8String is a
//! certificate several validators refuse with a message about the
//! signature.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::Value as Json;

use super::js;
use crate::der::{self, Element};
use crate::error::{PkiError, PkiResult};

/// How an attribute's value is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StringType {
    Utf8,
    Printable,
    Ia5,
}

impl StringType {
    fn from_name(name: &str) -> StringType {
        match name {
            "printable" => StringType::Printable,
            "ia5" => StringType::Ia5,
            _ => StringType::Utf8,
        }
    }

    fn encode(self, value: &str) -> Vec<u8> {
        match self {
            StringType::Utf8 => der::utf8_string(value),
            StringType::Printable => {
                der::latin_string(der::PRINTABLE_STRING, value)
            }
            StringType::Ia5 => der::latin_string(der::IA5_STRING, value),
        }
    }
}

/// A row of `DN_ATTRS`.
#[derive(Clone, Copy, Debug)]
pub struct DnAttr {
    pub name: &'static str,
    pub oid: &'static str,
    pub string_type: StringType,
    pub label: &'static str,
}

const fn attr(
    name: &'static str,
    oid: &'static str,
    string_type: StringType,
    label: &'static str,
) -> DnAttr {
    DnAttr {
        name,
        oid,
        string_type,
        label,
    }
}

use StringType::{Ia5, Printable, Utf8};

/// Every attribute a page offers, in `DN_ATTRS`'s order.
pub const DN_ATTRS: &[DnAttr] = &[
    attr("CN", "2.5.4.3", Utf8, "Common Name"),
    attr("SN", "2.5.4.4", Utf8, "Surname"),
    attr("serialNumber", "2.5.4.5", Printable, "Serial Number (DN)"),
    attr("C", "2.5.4.6", Printable, "Country"),
    attr("L", "2.5.4.7", Utf8, "Locality"),
    attr("ST", "2.5.4.8", Utf8, "State or Province"),
    attr("STREET", "2.5.4.9", Utf8, "Street Address"),
    attr("O", "2.5.4.10", Utf8, "Organization"),
    attr("OU", "2.5.4.11", Utf8, "Organizational Unit"),
    attr("title", "2.5.4.12", Utf8, "Title"),
    attr("description", "2.5.4.13", Utf8, "Description"),
    attr("businessCategory", "2.5.4.15", Utf8, "Business Category"),
    attr("postalCode", "2.5.4.17", Utf8, "Postal Code"),
    attr("GN", "2.5.4.42", Utf8, "Given Name"),
    attr("initials", "2.5.4.43", Utf8, "Initials"),
    attr(
        "generationQualifier",
        "2.5.4.44",
        Utf8,
        "Generation Qualifier",
    ),
    attr("dnQualifier", "2.5.4.46", Printable, "DN Qualifier"),
    attr("pseudonym", "2.5.4.65", Utf8, "Pseudonym"),
    attr("DC", "0.9.2342.19200300.100.1.25", Ia5, "Domain Component"),
    attr("UID", "0.9.2342.19200300.100.1.1", Utf8, "User ID"),
    attr("emailAddress", "1.2.840.113549.1.9.1", Ia5, "Email Address"),
    attr(
        "jurisdictionC",
        "1.3.6.1.4.1.311.60.2.1.3",
        Printable,
        "Jurisdiction Country (EV)",
    ),
    attr(
        "jurisdictionST",
        "1.3.6.1.4.1.311.60.2.1.2",
        Utf8,
        "Jurisdiction State (EV)",
    ),
    attr(
        "jurisdictionL",
        "1.3.6.1.4.1.311.60.2.1.1",
        Utf8,
        "Jurisdiction Locality (EV)",
    ),
];

pub fn dn_attr(name: &str) -> Option<&'static DnAttr> {
    DN_ATTRS.iter().find(|a| a.name == name)
}

fn dn_attr_by_oid(oid: &str) -> Option<&'static DnAttr> {
    DN_ATTRS.iter().find(|a| a.oid == oid)
}

/// `buildDn()`: the Name's DER from `[{ name | oid, value, type }]`,
/// skipping an attribute with no value.
pub fn build_dn(attributes: &[Json]) -> PkiResult<Vec<u8>> {
    let mut rdns = Vec::new();
    for a in attributes {
        let value = a.get("value");
        if !js::truthy(Some(a))
            || matches!(value, None | Some(Json::Null))
            || js::string_of(value).is_empty()
        {
            continue;
        }
        let name = a.get("name");
        let known = name.and_then(Json::as_str).and_then(dn_attr);
        let oid = if js::truthy(a.get("oid")) {
            js::string_of(a.get("oid"))
        } else if let Some(k) = known {
            k.oid.to_string()
        } else {
            return Err(PkiError::new(format!(
                "Unknown DN attribute: {}",
                js::string_of(name)
            )));
        };
        let string_type = if js::truthy(a.get("type")) {
            StringType::from_name(&js::string_of(a.get("type")))
        } else {
            known.map(|k| k.string_type).unwrap_or(StringType::Utf8)
        };
        rdns.push(der::set(&[der::sequence(&[
            der::oid(&oid)?,
            string_type.encode(&js::string_of(value)),
        ])]));
    }
    Ok(der::sequence(&rdns))
}

/// `parseDnString()`: "CN=x, O=y, C=US" as the list `build_dn` takes.
/// A comma inside parentheses does not split.
pub fn parse_dn_string(text: &str) -> Vec<Json> {
    let mut pieces = Vec::new();
    let mut start = 0;
    let bytes = text.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b != b',' {
            continue;
        }
        // `,(?![^(]*\))`: a ')' before any '(' after it means inside.
        let inside = text[i + 1..]
            .chars()
            .find(|&c| c == '(' || c == ')')
            .is_some_and(|c| c == ')');
        if !inside {
            pieces.push(&text[start..i]);
            start = i + 1;
        }
    }
    pieces.push(&text[start..]);
    let mut out = Vec::new();
    for piece in pieces {
        let trimmed = piece.trim();
        let Some(eq) = trimmed.find('=') else {
            continue;
        };
        let name = trimmed[..eq].trim();
        let value = trimmed[eq + 1..].trim();
        if dn_attr(name).is_some() {
            out.push(serde_json::json!({ "name": name, "value": value }));
        } else if is_dotted_oid(name) {
            out.push(serde_json::json!({ "oid": name, "value": value }));
        }
    }
    out
}

fn is_dotted_oid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() >= 2
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

/// The attributes of a Name, flattened across its SETs: `(oid, value)`.
pub fn name_attributes(name: &Element<'_>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for rdn in der::children(name.content).unwrap_or_default() {
        for tv in der::children(rdn.content).unwrap_or_default() {
            let parts = der::children(tv.content).unwrap_or_default();
            if parts.len() < 2 {
                continue;
            }
            let oid = der::oid_string(parts[0].content).unwrap_or_default();
            out.push((oid, der::string_value(&parts[1])));
        }
    }
    out
}

/// `dnToString()`: "CN=x, O=y", an unknown attribute by its OID.
pub fn dn_to_string(name: &Element<'_>) -> String {
    name_attributes(name)
        .into_iter()
        .map(|(oid, value)| {
            let label = dn_attr_by_oid(&oid).map(|a| a.name.to_string());
            format!("{}={}", label.unwrap_or(oid), value)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------------------------------------------------------------------------
// General names.

pub const GN_OTHER_NAME: u8 = 0;
pub const GN_EMAIL: u8 = 1;
pub const GN_DNS: u8 = 2;
pub const GN_DIR_NAME: u8 = 4;
pub const GN_URI: u8 = 6;
pub const GN_IP: u8 = 7;
pub const GN_REGISTERED_ID: u8 = 8;

/// Microsoft's userPrincipalName and RFC 4556's Kerberos principal.
pub const OTHERNAME_UPN: &str = "1.3.6.1.4.1.311.20.2.3";
pub const OTHERNAME_KRB5: &str = "1.3.6.1.5.2.2";

fn ipv4_bytes(text: &str) -> Option<Vec<u8>> {
    let parts: Vec<&str> = text.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = Vec::with_capacity(4);
    for part in parts {
        let n = js::parse_int(part, 10)?;
        // `String(n) !== part.replace(/^0+(?=\d)/, '')`.
        let stripped = {
            let lead = part.len() - part.trim_start_matches('0').len();
            let rest = &part[lead..];
            if lead > 0 && !rest.starts_with(|c: char| c.is_ascii_digit()) {
                &part[lead - 1..]
            } else {
                rest
            }
        };
        if !(0..=255).contains(&n) || n.to_string() != stripped {
            return None;
        }
        out.push(n as u8);
    }
    Some(out)
}

fn ipv6_bytes(text: &str) -> Option<Vec<u8>> {
    if !text.contains(':') {
        return None;
    }
    let halves: Vec<&str> = text.split("::").collect();
    if halves.len() > 2 {
        return None;
    }
    let groups = |part: &str| -> Vec<String> {
        part.split(':')
            .filter(|g| !g.is_empty())
            .map(str::to_string)
            .collect()
    };
    let head = groups(halves[0]);
    let tail = if halves.len() == 2 {
        groups(halves[1])
    } else {
        Vec::new()
    };
    if halves.len() == 1 && head.len() != 8 {
        return None;
    }
    let fill = 8_i64 - head.len() as i64 - tail.len() as i64;
    if fill < 0 {
        return None;
    }
    let mut all = head;
    if halves.len() == 2 {
        all.extend(std::iter::repeat_n("0".to_string(), fill as usize));
    }
    all.extend(tail);
    let mut out = Vec::with_capacity(16);
    for g in all.iter().take(8) {
        let v = js::parse_int(g, 16)?;
        if !(0..=65535).contains(&v) {
            return None;
        }
        out.push((v >> 8) as u8);
        out.push(v as u8);
    }
    (out.len() == 16).then_some(out)
}

/// `ipBytes()`: four octets or sixteen.
pub fn ip_bytes(text: &str) -> PkiResult<Vec<u8>> {
    ipv4_bytes(text)
        .or_else(|| ipv6_bytes(text))
        .ok_or_else(|| PkiError::new(format!("Not an IP address: {}", text)))
}

/// `ipConstraintBytes()`: the address followed by its mask.
pub fn ip_constraint_bytes(text: &str) -> PkiResult<Vec<u8>> {
    let (addr_text, prefix) = match text.find('/') {
        None => (text, None),
        Some(i) => (&text[..i], Some(js::parse_int(&text[i + 1..], 10))),
    };
    let addr = ip_bytes(addr_text)?;
    let bits = (addr.len() * 8) as i64;
    let prefix = match prefix {
        None => bits,
        Some(Some(p)) if (0..=bits).contains(&p) => p,
        Some(_) => {
            return Err(PkiError::new(format!(
                "Prefix length out of range for {}",
                text
            )))
        }
    };
    let mut out = addr.clone();
    for i in 0..addr.len() as i64 {
        let take = (prefix - i * 8).clamp(0, 8);
        out.push(if take == 0 {
            0
        } else {
            (0xff_u32 << (8 - take)) as u8
        });
    }
    Ok(out)
}

/// `derFromBase64()`: one complete DER element from base64 or base64url,
/// saying which of the two ways it was wrong. The element's own bytes.
pub fn der_from_base64(text: &str, what: &str) -> PkiResult<Vec<u8>> {
    let normalised: String = text
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    let body = normalised.trim_end_matches('=');
    let padding = normalised.len() - body.len();
    let alphabet_ok = body
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/');
    if !alphabet_ok
        || padding > 2
        || normalised.len() % 4 == 1
        || normalised.is_empty()
    {
        return Err(PkiError::new(format!(
            "{}: the value is not base64. It must be the DER encoding of the \
             value, base64 or base64url.",
            what
        )));
    }
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(body)
        .or_else(|_| STANDARD.decode(&normalised))
        .unwrap_or_default();
    match der::read(&bytes) {
        Some(e) => Ok(e.raw.to_vec()),
        None => Err(PkiError::new(format!(
            "{}: the value decoded from base64 but is not DER — it must be \
             one complete ASN.1 element.",
            what
        ))),
    }
}

/// `buildGeneralName()`: `{ kind, value }` — `dns`, `email`, `uri`, `ip`,
/// `dirName`, `registeredID`, `upn`, `krb5` or `otherName` (with `oid` and
/// base64 DER). `constraint` writes an IP as address and mask.
pub fn build_general_name(spec: &Json, constraint: bool) -> PkiResult<Vec<u8>> {
    let kind = js::string_of(spec.get("kind"));
    let value = js::string_of(spec.get("value"));
    match kind.as_str() {
        "dns" | "email" | "uri" => {
            let n = match kind.as_str() {
                "dns" => GN_DNS,
                "email" => GN_EMAIL,
                _ => GN_URI,
            };
            Ok(der::implicit(
                n,
                &der::latin_string(der::IA5_STRING, &value),
            )?)
        }
        "ip" => {
            let bytes = if constraint {
                ip_constraint_bytes(&value)?
            } else {
                ip_bytes(&value)?
            };
            Ok(der::context(GN_IP, false, &bytes))
        }
        "dirName" => Ok(der::context(
            GN_DIR_NAME,
            true,
            &build_dn(&parse_dn_string(&value))?,
        )),
        "registeredID" => {
            Ok(der::implicit(GN_REGISTERED_ID, &der::oid(&value)?)?)
        }
        "upn" | "krb5" | "otherName" => other_name(spec, &kind, &value),
        _ => Err(PkiError::new(format!(
            "Unknown general name kind: {}",
            if spec.get("kind").is_none() {
                "undefined".to_string()
            } else {
                kind
            }
        ))),
    }
}

/// An otherName: `[0] { OID, [0] EXPLICIT value }`, built here because
/// pkijs's would wrap it in a further `[0]` OpenSSL refuses.
fn other_name(spec: &Json, kind: &str, value: &str) -> PkiResult<Vec<u8>> {
    let oid = match kind {
        "upn" => OTHERNAME_UPN.to_string(),
        "krb5" => OTHERNAME_KRB5.to_string(),
        _ if js::truthy(spec.get("oid")) => js::string_of(spec.get("oid")),
        _ => String::new(),
    };
    if oid.is_empty() {
        return Err(PkiError::new("An otherName needs an OID."));
    }
    let inner = if kind == "otherName" {
        der_from_base64(value, &format!("otherName {}", oid))?
    } else {
        der::utf8_string(value)
    };
    Ok(der::context(
        GN_OTHER_NAME,
        true,
        &[der::oid(&oid)?, der::context(0, true, &inner)].concat(),
    ))
}

fn describe_ip(bytes: &[u8]) -> String {
    if bytes.len() == 4 || bytes.len() == 8 {
        let mut out = bytes[..4]
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(".");
        if bytes.len() == 8 {
            out.push('/');
            out.push_str(
                &bytes[4..]
                    .iter()
                    .map(u8::to_string)
                    .collect::<Vec<_>>()
                    .join("."),
            );
        }
        return out;
    }
    let limit = bytes.len().min(16);
    let mut groups = Vec::new();
    let mut i = 0;
    while i + 1 < limit {
        groups.push(format!(
            "{:x}",
            (u16::from(bytes[i]) << 8) | u16::from(bytes[i + 1])
        ));
        i += 2;
    }
    let mut out = groups.join(":");
    if bytes.len() == 32 {
        out.push_str("/…");
    }
    out
}

/// `describeGeneralName()`: "DNS:x", "IP:1.2.3.4", "otherName:UPN:x".
pub fn describe_general_name(gn: &Element<'_>) -> String {
    let n = gn.number as u8;
    match n {
        GN_DNS => format!("DNS:{}", der::string_value(gn)),
        GN_EMAIL => format!("email:{}", der::string_value(gn)),
        GN_URI => format!("URI:{}", der::string_value(gn)),
        GN_IP => format!("IP:{}", describe_ip(gn.content)),
        GN_DIR_NAME => match der::read(gn.content) {
            Some(name) => format!("DirName:{}", dn_to_string(&name)),
            None => "DirName:".to_string(),
        },
        GN_REGISTERED_ID => {
            format!("RID:{}", der::oid_string(gn.content).unwrap_or_default())
        }
        GN_OTHER_NAME => describe_other_name(gn),
        _ => format!("type {}", n),
    }
}

fn describe_other_name(gn: &Element<'_>) -> String {
    let parts = der::children(gn.content).unwrap_or_default();
    let (Some(oid), Some(holder)) = (parts.first(), parts.get(1)) else {
        return "otherName".to_string();
    };
    let oid = der::oid_string(oid.content).unwrap_or_default();
    let name = match oid.as_str() {
        OTHERNAME_UPN => "UPN".to_string(),
        OTHERNAME_KRB5 => "Kerberos principal".to_string(),
        _ => oid,
    };
    let inner = der::read(holder.content);
    let text = match inner {
        Some(e) if is_string_tag(e.tag) => der::string_value(&e),
        _ => "(DER)".to_string(),
    };
    format!("otherName:{}:{}", name, text)
}

/// The universal string types asn1js gives a `valueBlock.value` string.
fn is_string_tag(tag: u8) -> bool {
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
            | 0x1e
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        assert_eq!(ip_bytes("10.0.0.1").ok(), Some(vec![10, 0, 0, 1]));
        assert_eq!(ip_bytes("010.0.0.1").ok(), Some(vec![10, 0, 0, 1]));
        assert!(ip_bytes("256.0.0.1").is_err());
        assert!(ip_bytes("1.2.3.4a").is_err());
        let v6 = ip_bytes("::1").unwrap_or_default();
        assert_eq!(v6.len(), 16);
        assert_eq!(v6[15], 1);
        assert_eq!(
            ip_constraint_bytes("10.0.0.0/8").ok(),
            Some(vec![10, 0, 0, 0, 255, 0, 0, 0])
        );
        assert_eq!(
            ip_constraint_bytes("10.0.0.0/12").ok(),
            Some(vec![10, 0, 0, 0, 255, 0xf0, 0, 0])
        );
    }

    #[test]
    fn a_dn_round_trips() {
        let attrs = parse_dn_string("CN=a, O=b (x, y), C=US, 1.2.3=z, bogus=q");
        assert_eq!(attrs.len(), 4);
        let dn = build_dn(&attrs).unwrap_or_default();
        let e = der::read(&dn).map(|e| dn_to_string(&e));
        assert_eq!(e.as_deref(), Some("CN=a, O=b (x, y), C=US, 1.2.3=z"));
    }
}
