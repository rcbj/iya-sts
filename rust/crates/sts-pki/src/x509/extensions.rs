// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Extensions, and the certificate profiles each starts from (`x509.js`'s
//! "Extensions" and "Certificate profiles").
//!
//! The spec is the JSON object `defaultExtensions()` returns and the
//! console edits — every member `{ present, critical, … }` — read as
//! `x509.js` reads it, so the criticality defaults, the empty lists that
//! write nothing and the integers given as strings mean what they meant
//! there. Each builder returns `None` when it has nothing to encode.

use openssl::hash::{hash, MessageDigest};
use serde_json::{json, Value as Json};

use super::js;
use super::names;
use crate::der;
use crate::error::{PkiError, PkiResult};

pub const SUBJECT_KEY_IDENTIFIER: &str = "2.5.29.14";
pub const KEY_USAGE: &str = "2.5.29.15";
pub const PRIVATE_KEY_USAGE_PERIOD: &str = "2.5.29.16";
pub const SUBJECT_ALT_NAME: &str = "2.5.29.17";
pub const ISSUER_ALT_NAME: &str = "2.5.29.18";
pub const BASIC_CONSTRAINTS: &str = "2.5.29.19";
pub const NAME_CONSTRAINTS: &str = "2.5.29.30";
pub const CRL_DISTRIBUTION_POINTS: &str = "2.5.29.31";
pub const CERTIFICATE_POLICIES: &str = "2.5.29.32";
pub const POLICY_MAPPINGS: &str = "2.5.29.33";
pub const AUTHORITY_KEY_IDENTIFIER: &str = "2.5.29.35";
pub const POLICY_CONSTRAINTS: &str = "2.5.29.36";
pub const EXT_KEY_USAGE: &str = "2.5.29.37";
pub const FRESHEST_CRL: &str = "2.5.29.46";
pub const INHIBIT_ANY_POLICY: &str = "2.5.29.54";
pub const AUTHORITY_INFO_ACCESS: &str = "1.3.6.1.5.5.7.1.1";
pub const SUBJECT_INFO_ACCESS: &str = "1.3.6.1.5.5.7.1.11";
pub const TLS_FEATURE: &str = "1.3.6.1.5.5.7.1.24";
pub const OCSP_NO_CHECK: &str = "1.3.6.1.5.5.7.48.1.5";
pub const NETSCAPE_CERT_TYPE: &str = "2.16.840.1.113730.1.1";
pub const NETSCAPE_COMMENT: &str = "2.16.840.1.113730.1.13";
/// ITU-T X.509 (2019) clause 9.8: the hybrid-certificate trio.
pub const SUBJECT_ALT_PUBLIC_KEY_INFO: &str = "2.5.29.72";
pub const ALT_SIGNATURE_ALGORITHM: &str = "2.5.29.73";
pub const ALT_SIGNATURE_VALUE: &str = "2.5.29.74";

/// `EXT_OIDS`, by the name `x509.js` gives each.
pub const EXT_OIDS: &[(&str, &str)] = &[
    ("subjectKeyIdentifier", SUBJECT_KEY_IDENTIFIER),
    ("keyUsage", KEY_USAGE),
    ("privateKeyUsagePeriod", PRIVATE_KEY_USAGE_PERIOD),
    ("subjectAltName", SUBJECT_ALT_NAME),
    ("issuerAltName", ISSUER_ALT_NAME),
    ("basicConstraints", BASIC_CONSTRAINTS),
    ("nameConstraints", NAME_CONSTRAINTS),
    ("cRLDistributionPoints", CRL_DISTRIBUTION_POINTS),
    ("certificatePolicies", CERTIFICATE_POLICIES),
    ("policyMappings", POLICY_MAPPINGS),
    ("authorityKeyIdentifier", AUTHORITY_KEY_IDENTIFIER),
    ("policyConstraints", POLICY_CONSTRAINTS),
    ("extKeyUsage", EXT_KEY_USAGE),
    ("freshestCRL", FRESHEST_CRL),
    ("inhibitAnyPolicy", INHIBIT_ANY_POLICY),
    ("authorityInfoAccess", AUTHORITY_INFO_ACCESS),
    ("subjectInfoAccess", SUBJECT_INFO_ACCESS),
    ("tlsFeature", TLS_FEATURE),
    ("ocspNoCheck", OCSP_NO_CHECK),
    ("netscapeCertType", NETSCAPE_CERT_TYPE),
    ("netscapeComment", NETSCAPE_COMMENT),
    ("subjectAltPublicKeyInfo", SUBJECT_ALT_PUBLIC_KEY_INFO),
    ("altSignatureAlgorithm", ALT_SIGNATURE_ALGORITHM),
    ("altSignatureValue", ALT_SIGNATURE_VALUE),
];

pub fn ext_name(oid: &str) -> Option<&'static str> {
    EXT_OIDS.iter().find(|(_, o)| *o == oid).map(|(n, _)| *n)
}

/// RFC 5280 section 4.2.1.3's bits: bit 0 is the MOST significant bit of
/// the first octet.
pub const KEY_USAGE_BITS: &[(&str, u8)] = &[
    ("digitalSignature", 0),
    ("nonRepudiation", 1),
    ("keyEncipherment", 2),
    ("dataEncipherment", 3),
    ("keyAgreement", 4),
    ("keyCertSign", 5),
    ("cRLSign", 6),
    ("encipherOnly", 7),
    ("decipherOnly", 8),
];

pub const NS_CERT_TYPE_BITS: &[(&str, u8)] = &[
    ("sslClient", 0),
    ("sslServer", 1),
    ("sslCA", 5),
    ("emailCA", 6),
    ("objectSigningCA", 7),
];

/// Extended key usages, by the name a page shows.
pub const EKU_OIDS: &[(&str, &str)] = &[
    ("serverAuth", "1.3.6.1.5.5.7.3.1"),
    ("clientAuth", "1.3.6.1.5.5.7.3.2"),
    ("codeSigning", "1.3.6.1.5.5.7.3.3"),
    ("emailProtection", "1.3.6.1.5.5.7.3.4"),
    ("ipsecEndSystem", "1.3.6.1.5.5.7.3.5"),
    ("ipsecTunnel", "1.3.6.1.5.5.7.3.6"),
    ("ipsecUser", "1.3.6.1.5.5.7.3.7"),
    ("timeStamping", "1.3.6.1.5.5.7.3.8"),
    ("ocspSigning", "1.3.6.1.5.5.7.3.9"),
    ("ipsecIKE", "1.3.6.1.5.5.7.3.17"),
    ("anyExtendedKeyUsage", "2.5.29.37.0"),
    ("msSmartcardLogon", "1.3.6.1.4.1.311.20.2.2"),
    ("msDocumentSigning", "1.3.6.1.4.1.311.10.3.12"),
    ("msEncryptingFileSystem", "1.3.6.1.4.1.311.10.3.4"),
    ("kdcAuthentication", "1.3.6.1.5.2.3.5"),
    ("pkinitClientAuth", "1.3.6.1.5.2.3.4"),
];

pub fn eku_name(oid: &str) -> Option<&'static str> {
    EKU_OIDS.iter().find(|(_, o)| *o == oid).map(|(n, _)| *n)
}

/// Authority and subject information access methods.
pub const AIA_METHODS: &[(&str, &str)] = &[
    ("ocsp", "1.3.6.1.5.5.7.48.1"),
    ("caIssuers", "1.3.6.1.5.5.7.48.2"),
    ("timeStamping", "1.3.6.1.5.5.7.48.3"),
    ("caRepository", "1.3.6.1.5.5.7.48.5"),
];

pub fn aia_name(oid: &str) -> Option<&'static str> {
    AIA_METHODS.iter().find(|(_, o)| *o == oid).map(|(n, _)| *n)
}

fn lookup<'a>(table: &'a [(&'a str, &'a str)], name: &str) -> Option<&'a str> {
    table.iter().find(|(n, _)| *n == name).map(|(_, o)| *o)
}

/// One Extension: `SEQUENCE { OID, [critical,] OCTET STRING }`, the BOOLEAN
/// omitted when false (its DEFAULT).
pub fn extension(
    oid: &str,
    critical: bool,
    value: &[u8],
) -> PkiResult<Vec<u8>> {
    let mut parts = vec![der::oid(oid)?];
    if critical {
        parts.push(der::boolean(true));
    }
    parts.push(der::octet_string(value));
    Ok(der::sequence(&parts))
}

/// `critical` as `x509.js` reads it: `!!spec.critical`, or `default` when
/// the member is undefined.
fn critical(spec: &Json, default: bool) -> bool {
    match spec.get("critical") {
        None => default,
        v => js::truthy(v),
    }
}

fn list<'a>(spec: &'a Json, member: &str) -> Vec<&'a Json> {
    match spec.get(member) {
        Some(Json::Array(a)) => a.iter().collect(),
        _ => Vec::new(),
    }
}

/// `bitStringFor()`: the named bits set, trailing zero bits dropped.
fn bit_string_for(bits: &[&Json], table: &[(&str, u8)]) -> Option<Vec<u8>> {
    let wanted: Vec<String> =
        bits.iter().map(|b| js::string_of(Some(b))).collect();
    let numbers: Vec<u8> = table
        .iter()
        .filter(|(name, _)| wanted.iter().any(|w| w == name))
        .map(|(_, bit)| *bit)
        .collect();
    let highest = *numbers.iter().max()?;
    let byte_count = usize::from(highest / 8) + 1;
    let mut bytes = vec![0u8; byte_count];
    for bit in &numbers {
        bytes[usize::from(bit / 8)] |= 0x80 >> (bit % 8);
    }
    let unused = (byte_count * 8) as u8 - (highest + 1);
    Some(der::bit_string_with_unused(&bytes, unused))
}

/// The SHA-1 of the subjectPublicKey BIT STRING's bits: RFC 5280 section
/// 4.2.1.2's method (1), which every implementation computes.
pub fn key_identifier(spki: &[u8]) -> PkiResult<Vec<u8>> {
    let bad = || {
        PkiError::new("Object's schema was not verified against input data for PublicKeyInfo")
    };
    let outer = der::read(spki).ok_or_else(bad)?;
    let parts = der::children(outer.content).ok_or_else(bad)?;
    let bits = parts
        .get(1)
        .filter(|p| p.tag == der::BIT_STRING)
        .ok_or_else(bad)?;
    let content = bits.content.get(1..).unwrap_or_default();
    Ok(hash(MessageDigest::sha1(), content)?.to_vec())
}

pub fn build_basic_constraints(spec: &Json) -> PkiResult<Vec<u8>> {
    let ca = js::truthy(spec.get("ca"));
    let mut parts = Vec::new();
    if ca {
        parts.push(der::boolean(true));
        if let Some(path_len) = js::int_field(spec.get("pathLen")) {
            parts.push(der::integer(path_len.unwrap_or(0)));
        }
    }
    extension(
        BASIC_CONSTRAINTS,
        critical(spec, ca),
        &der::sequence(&parts),
    )
}

pub fn build_key_usage(spec: &Json) -> PkiResult<Option<Vec<u8>>> {
    let Some(bits) = bit_string_for(&list(spec, "usages"), KEY_USAGE_BITS)
    else {
        return Ok(None);
    };
    Ok(Some(extension(KEY_USAGE, critical(spec, true), &bits)?))
}

pub fn build_ext_key_usage(spec: &Json) -> PkiResult<Option<Vec<u8>>> {
    let oids: Vec<String> = list(spec, "usages")
        .into_iter()
        .filter_map(|u| {
            let name = js::string_of(Some(u));
            let oid =
                lookup(EKU_OIDS, &name).map(str::to_string).unwrap_or(name);
            js::truthy(Some(&Json::String(oid.clone()))).then_some(oid)
        })
        .collect();
    if oids.is_empty() {
        return Ok(None);
    }
    let encoded: PkiResult<Vec<Vec<u8>>> =
        oids.iter().map(|o| der::oid(o)).collect();
    Ok(Some(extension(
        EXT_KEY_USAGE,
        critical(spec, false),
        &der::sequence(&encoded?),
    )?))
}

pub fn build_alt_name(oid: &str, spec: &Json) -> PkiResult<Option<Vec<u8>>> {
    let names: PkiResult<Vec<Vec<u8>>> = list(spec, "names")
        .into_iter()
        .map(|n| names::build_general_name(n, false))
        .collect();
    let names = names?;
    if names.is_empty() {
        return Ok(None);
    }
    Ok(Some(extension(
        oid,
        critical(spec, false),
        &der::sequence(&names),
    )?))
}

/// The URI GeneralName pkijs writes: `[6]` over the IA5String's bytes.
fn uri_general_name(url: &Json) -> PkiResult<Vec<u8>> {
    der::implicit(
        names::GN_URI,
        &der::latin_string(der::IA5_STRING, &js::string_of(Some(url))),
    )
}

pub fn build_crl_distribution_points(
    oid: &str,
    spec: &Json,
) -> PkiResult<Option<Vec<u8>>> {
    let mut points = Vec::new();
    for url in list(spec, "urls") {
        let full_name = der::context(0, true, &uri_general_name(url)?);
        points.push(der::sequence(&[der::context(0, true, &full_name)]));
    }
    if points.is_empty() {
        return Ok(None);
    }
    Ok(Some(extension(
        oid,
        critical(spec, false),
        &der::sequence(&points),
    )?))
}

pub fn build_info_access(oid: &str, spec: &Json) -> PkiResult<Option<Vec<u8>>> {
    let mut descriptions = Vec::new();
    for entry in list(spec, "entries") {
        let method = js::string_of(entry.get("method"));
        let method = lookup(AIA_METHODS, &method)
            .map(str::to_string)
            .unwrap_or(method);
        descriptions.push(der::sequence(&[
            der::oid(&method)?,
            uri_general_name(entry.get("url").unwrap_or(&Json::Null))?,
        ]));
    }
    if descriptions.is_empty() {
        return Ok(None);
    }
    Ok(Some(extension(
        oid,
        critical(spec, false),
        &der::sequence(&descriptions),
    )?))
}

pub fn build_certificate_policies(spec: &Json) -> PkiResult<Option<Vec<u8>>> {
    let mut infos = Vec::new();
    for policy in list(spec, "policies") {
        let mut qualifiers = Vec::new();
        if js::truthy(policy.get("cps")) {
            qualifiers.push(der::sequence(&[
                der::oid("1.3.6.1.5.5.7.2.1")?,
                der::latin_string(
                    der::IA5_STRING,
                    &js::string_of(policy.get("cps")),
                ),
            ]));
        }
        if js::truthy(policy.get("notice")) {
            qualifiers.push(der::sequence(&[
                der::oid("1.3.6.1.5.5.7.2.2")?,
                der::sequence(&[der::utf8_string(&js::string_of(
                    policy.get("notice"),
                ))]),
            ]));
        }
        let mut info = vec![der::oid(&js::string_of(policy.get("oid")))?];
        if !qualifiers.is_empty() {
            info.push(der::sequence(&qualifiers));
        }
        infos.push(der::sequence(&info));
    }
    if infos.is_empty() {
        return Ok(None);
    }
    Ok(Some(extension(
        CERTIFICATE_POLICIES,
        critical(spec, false),
        &der::sequence(&infos),
    )?))
}

pub fn build_policy_mappings(spec: &Json) -> PkiResult<Option<Vec<u8>>> {
    let mut mappings = Vec::new();
    for m in list(spec, "mappings") {
        mappings.push(der::sequence(&[
            der::oid(&js::string_of(m.get("issuer")))?,
            der::oid(&js::string_of(m.get("subject")))?,
        ]));
    }
    if mappings.is_empty() {
        return Ok(None);
    }
    Ok(Some(extension(
        POLICY_MAPPINGS,
        critical(spec, true),
        &der::sequence(&mappings),
    )?))
}

pub fn build_policy_constraints(spec: &Json) -> PkiResult<Option<Vec<u8>>> {
    let mut parts = Vec::new();
    for (n, member) in
        [(0u8, "requireExplicitPolicy"), (1, "inhibitPolicyMapping")]
    {
        if let Some(v) = js::int_field(spec.get(member)) {
            parts.push(der::implicit(n, &der::integer(v.unwrap_or(0)))?);
        }
    }
    if parts.is_empty() {
        return Ok(None);
    }
    Ok(Some(extension(
        POLICY_CONSTRAINTS,
        critical(spec, true),
        &der::sequence(&parts),
    )?))
}

fn subtrees(spec: &Json, member: &str) -> PkiResult<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for entry in list(spec, member) {
        let mut tree = vec![names::build_general_name(entry, true)?];
        if let Some(Some(min)) = js::int_field(entry.get("minimum")) {
            if min != 0 {
                tree.push(der::context(0, true, &der::integer(min)));
            }
        }
        if let Some(max) = js::int_field(entry.get("maximum")) {
            tree.push(der::context(1, true, &der::integer(max.unwrap_or(0))));
        }
        out.push(der::sequence(&tree));
    }
    Ok(out)
}

pub fn build_name_constraints(spec: &Json) -> PkiResult<Option<Vec<u8>>> {
    let permitted = subtrees(spec, "permitted")?;
    let excluded = subtrees(spec, "excluded")?;
    if permitted.is_empty() && excluded.is_empty() {
        return Ok(None);
    }
    let mut parts = Vec::new();
    if !permitted.is_empty() {
        parts.push(der::context(0, true, &permitted.concat()));
    }
    if !excluded.is_empty() {
        parts.push(der::context(1, true, &excluded.concat()));
    }
    Ok(Some(extension(
        NAME_CONSTRAINTS,
        critical(spec, true),
        &der::sequence(&parts),
    )?))
}

/// `generalizedTime()`: YYYYMMDDHHMMSSZ, the date read as `new Date(x)`.
fn generalized_time_text(value: &Json) -> PkiResult<String> {
    let at = super::time::js_date(value)?;
    Ok(at.format("%Y%m%d%H%M%SZ").to_string())
}

pub fn build_private_key_usage_period(
    spec: &Json,
) -> PkiResult<Option<Vec<u8>>> {
    let mut values = Vec::new();
    for (n, member) in [(0u8, "notBefore"), (1, "notAfter")] {
        if js::truthy(spec.get(member)) {
            let text =
                generalized_time_text(spec.get(member).unwrap_or(&Json::Null))?;
            values.push(der::context(n, false, text.as_bytes()));
        }
    }
    if values.is_empty() {
        return Ok(None);
    }
    Ok(Some(extension(
        PRIVATE_KEY_USAGE_PERIOD,
        critical(spec, false),
        &der::sequence(&values),
    )?))
}

pub fn build_inhibit_any_policy(spec: &Json) -> PkiResult<Option<Vec<u8>>> {
    let Some(skip) = js::int_field(spec.get("skipCerts")) else {
        return Ok(None);
    };
    Ok(Some(extension(
        INHIBIT_ANY_POLICY,
        critical(spec, true),
        &der::integer(skip.unwrap_or(0)),
    )?))
}

pub fn build_tls_feature(spec: &Json) -> PkiResult<Option<Vec<u8>>> {
    let features: Vec<i64> = list(spec, "features")
        .into_iter()
        .filter_map(|f| js::parse_int(&js::string_of(Some(f)), 10))
        .collect();
    if features.is_empty() {
        return Ok(None);
    }
    let encoded: Vec<Vec<u8>> =
        features.into_iter().map(der::integer).collect();
    Ok(Some(extension(
        TLS_FEATURE,
        critical(spec, false),
        &der::sequence(&encoded),
    )?))
}

pub fn build_ocsp_no_check(spec: &Json) -> PkiResult<Option<Vec<u8>>> {
    if !js::truthy(spec.get("present")) {
        return Ok(None);
    }
    Ok(Some(extension(
        OCSP_NO_CHECK,
        critical(spec, false),
        &der::null(),
    )?))
}

pub fn build_netscape_cert_type(spec: &Json) -> PkiResult<Option<Vec<u8>>> {
    let Some(bits) = bit_string_for(&list(spec, "types"), NS_CERT_TYPE_BITS)
    else {
        return Ok(None);
    };
    Ok(Some(extension(
        NETSCAPE_CERT_TYPE,
        critical(spec, false),
        &bits,
    )?))
}

pub fn build_netscape_comment(spec: &Json) -> PkiResult<Option<Vec<u8>>> {
    if !js::truthy(spec.get("text")) {
        return Ok(None);
    }
    Ok(Some(extension(
        NETSCAPE_COMMENT,
        critical(spec, false),
        &der::latin_string(der::IA5_STRING, &js::string_of(spec.get("text"))),
    )?))
}

/// An OID, a critical flag and base64 DER: anything at all.
pub fn build_custom_extension(spec: &Json) -> PkiResult<Option<Vec<u8>>> {
    if !js::truthy(spec.get("oid")) || !js::truthy(spec.get("value")) {
        return Ok(None);
    }
    let oid = js::string_of(spec.get("oid"));
    let value = names::der_from_base64(
        &js::string_of(spec.get("value")),
        &format!("Extension {}", oid),
    )?;
    Ok(Some(extension(&oid, critical(spec, false), &value)?))
}

// ---------------------------------------------------------------------------
// Profiles.

/// One row of `PROFILES`.
#[derive(Clone, Copy, Debug)]
pub struct Profile {
    pub id: &'static str,
    pub label: &'static str,
    pub cn: &'static str,
    pub ca: bool,
    pub self_signed: bool,
    pub years: i32,
    pub key_usage: &'static [&'static str],
    /// `None` is `null` (no constraint); a leaf has no pathLen at all.
    pub path_len: Option<i64>,
    pub ext_key_usage: &'static [&'static str],
    pub ocsp_no_check: bool,
    pub eku_critical: bool,
}

const CA_USAGE: &[&str] = &["keyCertSign", "cRLSign", "digitalSignature"];
const TLS_USAGE: &[&str] = &["digitalSignature", "keyEncipherment"];

const fn leaf(
    id: &'static str,
    label: &'static str,
    cn: &'static str,
    years: i32,
    key_usage: &'static [&'static str],
    ext_key_usage: &'static [&'static str],
) -> Profile {
    Profile {
        id,
        label,
        cn,
        ca: false,
        self_signed: false,
        years,
        key_usage,
        path_len: None,
        ext_key_usage,
        ocsp_no_check: false,
        eku_critical: false,
    }
}

const fn ca(
    id: &'static str,
    label: &'static str,
    cn: &'static str,
    years: i32,
    path_len: Option<i64>,
    self_signed: bool,
) -> Profile {
    Profile {
        id,
        label,
        cn,
        ca: true,
        self_signed,
        years,
        key_usage: CA_USAGE,
        path_len,
        ext_key_usage: &[],
        ocsp_no_check: false,
        eku_critical: false,
    }
}

/// The fourteen profiles, in `PROFILE_ORDER`.
pub const PROFILES: &[Profile] = &[
    ca("root-ca", "Root CA (self-signed)", "RootCA", 20, None, true),
    ca(
        "intermediate-ca",
        "Intermediate CA",
        "IntermediateCA",
        10,
        Some(1),
        false,
    ),
    ca("issuing-ca", "Issuing CA", "IssuingCA", 5, Some(0), false),
    leaf(
        "tls-server",
        "TLS Server",
        "server",
        1,
        TLS_USAGE,
        &["serverAuth"],
    ),
    leaf(
        "tls-client",
        "TLS Client (mutual auth)",
        "client",
        1,
        TLS_USAGE,
        &["clientAuth"],
    ),
    leaf(
        "tls-server-client",
        "TLS Server + Client",
        "server",
        1,
        TLS_USAGE,
        &["serverAuth", "clientAuth"],
    ),
    leaf(
        "digital-signature",
        "Digital Signature / non-repudiation",
        "Signer",
        3,
        &["digitalSignature", "nonRepudiation"],
        &[],
    ),
    leaf(
        "key-encipherment",
        "Key Encipherment (encryption)",
        "Recipient",
        3,
        &["keyEncipherment", "dataEncipherment"],
        &[],
    ),
    leaf(
        "code-signing",
        "Code Signing",
        "CodeSigner",
        3,
        &["digitalSignature"],
        &["codeSigning"],
    ),
    leaf(
        "email",
        "S/MIME (email protection)",
        "EmailUser",
        3,
        &["digitalSignature", "keyEncipherment", "nonRepudiation"],
        &["emailProtection"],
    ),
    Profile {
        ocsp_no_check: true,
        ..leaf(
            "ocsp-responder",
            "OCSP Responder",
            "OCSPResponder",
            1,
            &["digitalSignature"],
            &["ocspSigning"],
        )
    },
    Profile {
        eku_critical: true,
        ..leaf(
            "timestamping",
            "Time Stamping",
            "TimeStampingAuthority",
            5,
            &["digitalSignature", "nonRepudiation"],
            &["timeStamping"],
        )
    },
    leaf(
        "smartcard-logon",
        "Smartcard Logon",
        "SmartcardUser",
        2,
        TLS_USAGE,
        &["clientAuth", "msSmartcardLogon"],
    ),
    leaf(
        "kdc",
        "Kerberos KDC (PKINIT)",
        "kdc",
        2,
        TLS_USAGE,
        &["kdcAuthentication"],
    ),
];

pub fn profile(id: &str) -> Option<&'static Profile> {
    PROFILES.iter().find(|p| p.id == id)
}

pub fn profile_ids() -> Vec<&'static str> {
    PROFILES.iter().map(|p| p.id).collect()
}

/// The subject CN a profile starts from.
pub fn default_subject_cn(profile_id: &str) -> &'static str {
    profile(profile_id).map(|p| p.cn).unwrap_or("")
}

/// Whether a CN is one this table wrote.
pub fn is_default_subject_cn(value: &str) -> bool {
    let wanted = value.trim();
    PROFILES.iter().any(|p| p.cn == wanted)
}

/// The rest of the subject DN, which does not vary by profile.
pub const DEFAULT_DN: &[(&str, &str)] = &[
    ("O", "Example Corp"),
    ("OU", "Information Technology"),
    ("L", "Austin"),
    ("ST", "Texas"),
    ("C", "US"),
];

/// The subjectAltName a serverAuth profile starts from: `dns:` + its CN.
pub fn default_subject_alt_name(profile_id: &str) -> String {
    match profile(profile_id) {
        Some(p)
            if p.ext_key_usage.contains(&"serverAuth") && !p.cn.is_empty() =>
        {
            format!("dns:{}", p.cn)
        }
        _ => String::new(),
    }
}

pub fn is_default_subject_alt_name(value: &str) -> bool {
    let wanted = value.trim();
    wanted.is_empty()
        || PROFILES.iter().any(|p| {
            let mine = default_subject_alt_name(p.id);
            !mine.is_empty() && mine == wanted
        })
}

/// `defaultExtensions()`: the spec a profile starts from, which the page
/// then edits.
pub fn default_extensions(profile_id: &str) -> Json {
    let p = profile(profile_id);
    let ca = p.is_some_and(|p| p.ca);
    let path_len = match p {
        Some(p) if p.ca => p.path_len.map_or(Json::Null, Json::from),
        Some(_) => Json::Null,
        None => Json::Null,
    };
    let key_usage: Vec<&str> =
        p.map(|p| p.key_usage.to_vec()).unwrap_or_default();
    let eku: Vec<&str> =
        p.map(|p| p.ext_key_usage.to_vec()).unwrap_or_default();
    json!({
        "basicConstraints": { "present": true, "ca": ca, "pathLen": path_len,
                              "critical": true },
        "keyUsage": { "present": true, "usages": key_usage, "critical": true },
        "extKeyUsage": { "present": !eku.is_empty(), "usages": eku,
                         "critical": p.is_some_and(|p| p.eku_critical) },
        "subjectKeyIdentifier": { "present": true, "critical": false },
        "authorityKeyIdentifier": { "present": true, "critical": false,
                                    "includeIssuerAndSerial": false },
        "subjectAltName": { "present": false, "names": [], "critical": false },
        "issuerAltName": { "present": false, "names": [], "critical": false },
        "cRLDistributionPoints": { "present": false, "urls": [], "critical": false },
        "freshestCRL": { "present": false, "urls": [], "critical": false },
        "authorityInfoAccess": { "present": false, "entries": [], "critical": false },
        "subjectInfoAccess": { "present": false, "entries": [], "critical": false },
        "certificatePolicies": { "present": false, "policies": [], "critical": false },
        "policyMappings": { "present": false, "mappings": [], "critical": true },
        "policyConstraints": { "present": false, "critical": true },
        "nameConstraints": { "present": false, "permitted": [], "excluded": [],
                             "critical": true },
        "inhibitAnyPolicy": { "present": false, "critical": true },
        "privateKeyUsagePeriod": { "present": false, "critical": false },
        "tlsFeature": { "present": false, "features": [], "critical": false },
        "ocspNoCheck": { "present": p.is_some_and(|p| p.ocsp_no_check), "critical": false },
        "netscapeCertType": { "present": false, "types": [], "critical": false },
        "netscapeComment": { "present": false, "text": "", "critical": false },
        "custom": []
    })
}

/// The AuthorityKeyIdentifier: the issuer's key, the subject's own when
/// self-signed — and, when asked, the issuer's ISSUER name and its serial,
/// which is what `x509.js` writes (`issuerCert.issuer`).
pub fn build_authority_key_identifier(
    spec: &Json,
    subject_spki: &[u8],
    issuer: Option<&super::read::Certificate>,
) -> PkiResult<Vec<u8>> {
    let spki = issuer.map_or(subject_spki, |c| c.spki.as_slice());
    let kid = key_identifier(spki)?;
    let mut parts = vec![der::context(0, false, &kid)];
    if let (true, Some(issuer)) =
        (js::truthy(spec.get("includeIssuerAndSerial")), issuer)
    {
        parts.push(der::context(
            1,
            true,
            &der::context(names::GN_DIR_NAME, true, &issuer.issuer_der),
        ));
        parts.push(der::context(2, false, &issuer.serial));
    }
    extension(
        AUTHORITY_KEY_IDENTIFIER,
        critical(spec, false),
        &der::sequence(&parts),
    )
}

/// `buildExtensions()`: every member that is `present`, in `x509.js`'s
/// order, then the custom ones.
pub fn build_extensions(
    ext: &Json,
    subject_spki: &[u8],
    issuer: Option<&super::read::Certificate>,
) -> PkiResult<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let present = |name: &str| -> Option<&Json> {
        ext.get(name)
            .filter(|m| js::truthy(Some(m)) && js::truthy(m.get("present")))
    };
    if let Some(s) = present("basicConstraints") {
        out.push(build_basic_constraints(s)?);
    }
    let mut add = |built: Option<Vec<u8>>| {
        if let Some(b) = built {
            out.push(b);
        }
    };
    if let Some(s) = present("keyUsage") {
        add(build_key_usage(s)?);
    }
    if let Some(s) = present("extKeyUsage") {
        add(build_ext_key_usage(s)?);
    }
    if let Some(s) = present("subjectAltName") {
        add(build_alt_name(SUBJECT_ALT_NAME, s)?);
    }
    if let Some(s) = present("issuerAltName") {
        add(build_alt_name(ISSUER_ALT_NAME, s)?);
    }
    if let Some(s) = present("subjectKeyIdentifier") {
        let skid = key_identifier(subject_spki)?;
        add(Some(extension(
            SUBJECT_KEY_IDENTIFIER,
            js::truthy(s.get("critical")),
            &der::octet_string(&skid),
        )?));
    }
    if let Some(s) = present("authorityKeyIdentifier") {
        add(Some(build_authority_key_identifier(
            s,
            subject_spki,
            issuer,
        )?));
    }
    if let Some(s) = present("cRLDistributionPoints") {
        add(build_crl_distribution_points(CRL_DISTRIBUTION_POINTS, s)?);
    }
    if let Some(s) = present("freshestCRL") {
        add(build_crl_distribution_points(FRESHEST_CRL, s)?);
    }
    if let Some(s) = present("authorityInfoAccess") {
        add(build_info_access(AUTHORITY_INFO_ACCESS, s)?);
    }
    if let Some(s) = present("subjectInfoAccess") {
        add(build_info_access(SUBJECT_INFO_ACCESS, s)?);
    }
    if let Some(s) = present("certificatePolicies") {
        add(build_certificate_policies(s)?);
    }
    if let Some(s) = present("policyMappings") {
        add(build_policy_mappings(s)?);
    }
    if let Some(s) = present("policyConstraints") {
        add(build_policy_constraints(s)?);
    }
    if let Some(s) = present("nameConstraints") {
        add(build_name_constraints(s)?);
    }
    if let Some(s) = present("inhibitAnyPolicy") {
        add(build_inhibit_any_policy(s)?);
    }
    if let Some(s) = present("privateKeyUsagePeriod") {
        add(build_private_key_usage_period(s)?);
    }
    if let Some(s) = present("tlsFeature") {
        add(build_tls_feature(s)?);
    }
    if let Some(s) = present("ocspNoCheck") {
        add(build_ocsp_no_check(s)?);
    }
    if let Some(s) = present("netscapeCertType") {
        add(build_netscape_cert_type(s)?);
    }
    if let Some(s) = present("netscapeComment") {
        add(build_netscape_comment(s)?);
    }
    for custom in list(ext, "custom") {
        add(build_custom_extension(custom)?);
    }
    Ok(out)
}
