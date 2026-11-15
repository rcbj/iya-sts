// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The attestation STATEMENTS of WebAuthn Level 3 section 8, as
//! `authn/webauthn_attestation.ts`'s `verifyStatement()` verifies them
//! (#105): steps 21 and 22 of section 7.1 — the format's shape, its
//! signature, and what it requires of its certificate.
//!
//! Ported: `packed` (Self, and Basic/AttCA through x5c, section 8.2),
//! `tpm` (AttCA through an AIK certificate, 8.3), `fido-u2f` (8.6) and
//! `none` (8.7), and the refusal of a format section 8 does not define.
//! `android-key`, `android-safetynet`, `apple` and `compound` answer
//! [`Statement::Unported`]; a caller refuses such a registration until
//! they are ported. What follows the statement in `assess()` — the FIDO
//! Metadata Service, the trust path to the realm's anchors, revocation,
//! the policy that demands trust — is not here either (see the crate's
//! report).

use serde_json::Value as Json;
use sts_core::errors::{codes, ErrorCode};
use sts_crypto::jws_alg::Hash;
use sts_crypto::raw_sig::public_key_from_spki;
use sts_crypto::webauthn::{
    cose_signature_alg, fido_aaguid_extension, tpm_name, tpm_parse_attest,
    tpm_parse_public, tpm_parse_signature, verify_cose_signature, CoseKey,
    CoseOptions, TPM_GENERATED_VALUE, TPM_ST_ATTEST_CERTIFY,
};
use sts_pki::foreign::{
    attestation_certificate_facts, attestation_key_identifier,
};
use sts_pki::x509::read::Certificate;

use super::cbor::Cbor;
use super::ceremony::hex;

/// Section 8's formats, in Node's order.
pub const FORMATS: [&str; 8] = [
    "packed",
    "tpm",
    "android-key",
    "android-safetynet",
    "fido-u2f",
    "none",
    "apple",
    "compound",
];

const OID_FIDO_AAGUID: &str = "1.3.6.1.4.1.45724.1.1.4";
const OID_TCG_AIK: &str = "2.23.133.8.3";
const OID_TPM_MANUFACTURER: &str = "2.23.133.2.1";
const OID_TPM_MODEL: &str = "2.23.133.2.2";
const OID_TPM_VERSION: &str = "2.23.133.2.3";

/// What a statement is verified over (`Context` in Node).
#[derive(Debug, Clone)]
pub struct Context {
    pub auth_data: Vec<u8>,
    pub client_data_hash: Vec<u8>,
    pub cose: Option<Cbor>,
    pub cose_alg: Option<i64>,
    pub credential_jwk: Json,
    pub aaguid: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub rp_id_hash: Vec<u8>,
    /// `webauthn.insecureAlgorithms`, through the policy.
    pub allow_insecure: bool,
}

/// `verifyStatement()`'s answer.
#[derive(Debug, Clone, PartialEq)]
pub enum Statement {
    Verified {
        format: String,
        kind: &'static str,
        trust_path: Vec<Vec<u8>>,
        acki: Option<String>,
    },
    Refused {
        code: ErrorCode,
        format: String,
        why: String,
    },
    /// A section 8 format this crate does not verify yet.
    Unported { format: String },
}

impl Statement {
    /// As Node's object (`trustPath` as the number of certificates).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn to_json(&self) -> Json {
        match self {
            Statement::Verified {
                format,
                kind,
                trust_path,
                acki,
            } => {
                let mut out = serde_json::json!({ "ok": true, "format": format,
                    "type": kind, "trustPath": trust_path.len() });
                if let Some(a) = acki {
                    out["acki"] = Json::String(a.clone());
                }
                out
            }
            Statement::Refused { code, format, why } => serde_json::json!({
                "ok": false, "code": code.as_str(), "why": why,
                "format": format }),
            Statement::Unported { format } => {
                serde_json::json!({ "ok": false, "unported": format })
            }
        }
    }
}

fn fail(code: ErrorCode, format: &str, why: String) -> Statement {
    Statement::Refused {
        code,
        format: format.to_string(),
        why: format!("{format}: {why}"),
    }
}

/// `shapeProblem(attStmt, required, optional)`: a map with exactly the
/// members the format's CDDL allows, each of its type. Empty when it is.
fn shape_problem(st: &Cbor, required: &[&str], optional: &[&str]) -> String {
    let Cbor::Map(entries) = st else {
        return "attStmt is not a map with text keys".to_string();
    };
    let mut members: Vec<(&str, &Cbor)> = Vec::new();
    for (k, v) in entries {
        let Cbor::Text(t) = k else {
            return "attStmt is not a map with text keys".to_string();
        };
        members.push((t, v));
    }
    let allowed: Vec<&str> = required.iter().chain(optional).copied().collect();
    let extra: Vec<&str> = members
        .iter()
        .map(|(k, _)| *k)
        .filter(|k| !allowed.contains(k))
        .collect();
    if !extra.is_empty() {
        return format!(
            "attStmt carries {}, which the format does not define",
            extra.join(", ")
        );
    }
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|k| !members.iter().any(|(m, _)| m == k))
        .collect();
    if !missing.is_empty() {
        return format!("attStmt has no {}", missing.join(", "));
    }
    let bad: Vec<&str> =
        members
            .iter()
            .filter(|(k, v)| match *k {
                "alg" => !matches!(v, Cbor::Int(_)),
                "ver" => !matches!(v, Cbor::Text(t) if !t.is_empty()),
                "x5c" => match v {
                    Cbor::Array(items) => items.is_empty()
                        || !items.iter().all(
                            |i| matches!(i, Cbor::Bytes(b) if !b.is_empty()),
                        ),
                    _ => true,
                },
                _ => !matches!(v, Cbor::Bytes(_)),
            })
            .map(|(k, _)| *k)
            .collect();
    if !bad.is_empty() {
        return format!(
            "{} {} not of the type the format defines",
            bad.join(", "),
            if bad.len() == 1 { "is" } else { "are" }
        );
    }
    String::new()
}

fn member<'a>(st: &'a Cbor, name: &str) -> Option<&'a Cbor> {
    st.get_text(name)
}

fn bytes_of(st: &Cbor, name: &str) -> Vec<u8> {
    member(st, name)
        .and_then(Cbor::bytes)
        .map(<[u8]>::to_vec)
        .unwrap_or_default()
}

fn x5c(st: &Cbor) -> Vec<Vec<u8>> {
    match member(st, "x5c") {
        Some(Cbor::Array(items)) => items
            .iter()
            .filter_map(|i| i.bytes().map(<[u8]>::to_vec))
            .collect(),
        _ => Vec::new(),
    }
}

/// `certificateKey(der)`: a certificate's public key, ML-DSA included.
fn verify_with_certificate(
    der: &[u8],
    alg: i64,
    data: &[u8],
    sig: &[u8],
    allow_insecure: bool,
) -> bool {
    let Ok(cert) = Certificate::from_der(der) else {
        return false;
    };
    let key = public_key_from_spki(&cert.spki);
    verify_cose_signature(
        alg,
        CoseKey::Spki(&key),
        data,
        sig,
        &CoseOptions {
            allow_insecure,
            ..CoseOptions::default()
        },
    )
}

/// `aaguidExtensionProblem(facts, ctx)`.
fn aaguid_extension_problem(facts: &Json, ctx: &Context) -> String {
    let Some(ext) = facts["extensions"].get(OID_FIDO_AAGUID) else {
        return String::new();
    };
    if ext["critical"] == Json::Bool(true) {
        return "the certificate's id-fido-gen-ce-aaguid extension is marked \
                critical, which section 8.2.1 forbids"
            .to_string();
    }
    let value = ext["value"]
        .as_str()
        .and_then(|v| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.decode(v).ok()
        })
        .unwrap_or_default();
    let aaguid = fido_aaguid_extension(&value);
    if aaguid.as_deref() != Some(&ctx.aaguid[..]) {
        return format!(
            "the certificate's id-fido-gen-ce-aaguid extension names {} and \
             the authenticator data {}",
            aaguid.map_or("no readable AAGUID".to_string(), |a| hex(&a)),
            hex(&ctx.aaguid)
        );
    }
    String::new()
}

fn text(v: &Json) -> String {
    match v {
        Json::Null => String::new(),
        other => crate::js::string(other),
    }
}

/// `packedCertificateProblem(facts)`: section 8.2.1.
#[tracing::instrument(level = "debug", skip_all)]
pub fn packed_certificate_problem(facts: &Json) -> String {
    let s = &facts["subject"];
    let c = text(&s["C"]);
    if facts["version"] != serde_json::json!(3) {
        format!(
            "the attestation certificate is version {}, not 3",
            text(&facts["version"])
        )
    } else if !(c.len() == 2 && c.chars().all(|x| x.is_ascii_alphabetic())) {
        "the attestation certificate's subject has no ISO 3166 country (C)"
            .to_string()
    } else if !crate::js::truthy(&s["O"]) {
        "the attestation certificate's subject has no vendor (O)".to_string()
    } else if s["OU"] != serde_json::json!("Authenticator Attestation") {
        format!(
            "the attestation certificate's subject OU is \"{}\", not \
             \"Authenticator Attestation\"",
            text(&s["OU"])
        )
    } else if !crate::js::truthy(&s["CN"]) {
        "the attestation certificate's subject has no CN".to_string()
    } else if facts["ca"] != Json::Bool(false) {
        format!(
            "the attestation certificate's basicConstraints {}; section 8.2.1 \
             requires CA false",
            if facts["ca"].is_null() {
                "is absent"
            } else {
                "says it is a CA"
            }
        )
    } else {
        String::new()
    }
}

/// `tpmCertificateProblem(facts)`: section 8.3.1.
#[tracing::instrument(level = "debug", skip_all)]
pub fn tpm_certificate_problem(facts: &Json) -> String {
    let san: Vec<String> = facts["sanDirectoryTypes"]
        .as_array()
        .map(|l| l.iter().map(text).collect())
        .unwrap_or_default();
    let eku: Vec<String> = facts["eku"]
        .as_array()
        .map(|l| l.iter().map(text).collect())
        .unwrap_or_default();
    if facts["version"] != serde_json::json!(3) {
        format!(
            "the AIK certificate is version {}, not 3",
            text(&facts["version"])
        )
    } else if facts["subjectEmpty"] != Json::Bool(true) {
        "the AIK certificate's subject is not empty".to_string()
    } else if facts["extensions"].get("2.5.29.17").is_none()
        || [OID_TPM_MANUFACTURER, OID_TPM_MODEL, OID_TPM_VERSION]
            .iter()
            .any(|o| !san.iter().any(|x| x == o))
    {
        "the AIK certificate's subjectAltName does not name the TPM \
         manufacturer, model and version (TCG EK Credential Profile section \
         3.2.9)"
            .to_string()
    } else if !eku.iter().any(|e| e == OID_TCG_AIK) {
        "the AIK certificate's extended key usage lacks tcg-kp-AIKCertificate \
         (2.23.133.8.3)"
            .to_string()
    } else if facts["ca"] != Json::Bool(false) {
        format!(
            "the AIK certificate's basicConstraints {}",
            if facts["ca"].is_null() {
                "is absent"
            } else {
                "says it is a CA"
            }
        )
    } else {
        String::new()
    }
}

/// `sameKey(a, b)`: the same public key, leading zero bytes aside.
#[tracing::instrument(level = "debug", skip_all)]
pub fn same_key(a: &Json, b: &Json) -> bool {
    let kty = a.get("kty");
    if a.is_null() || b.is_null() || kty != b.get("kty") {
        return false;
    }
    // Node strips whole "00" pairs from the front of the hex.
    let trim_pairs = |v: &Json| {
        let mut h = hex(&super::ceremony::from_base64url(&text(v)));
        while h.starts_with("00") {
            h.drain(..2);
        }
        h
    };
    let members: &[&str] = match kty.and_then(Json::as_str) {
        Some("RSA") => &["n", "e"],
        Some("EC") => &["crv", "x", "y"],
        Some("OKP") => &["crv", "x"],
        _ => &["pub"],
    };
    members.iter().all(|k| {
        if *k == "crv" {
            a.get("crv") == b.get("crv")
        } else {
            trim_pairs(&a[*k]) == trim_pairs(&b[*k])
        }
    })
}

fn packed(st: &Cbor, ctx: &Context) -> Statement {
    let shape = shape_problem(st, &["alg", "sig"], &["x5c"]);
    if !shape.is_empty() {
        return fail(codes::STS_AUTHN_0232, "packed", shape);
    }
    let alg = member(st, "alg").and_then(Cbor::int).unwrap_or(0);
    let sig = bytes_of(st, "sig");
    let mut signed = ctx.auth_data.clone();
    signed.extend(&ctx.client_data_hash);
    let chain = x5c(st);
    if member(st, "x5c").is_none() {
        if Some(alg) != ctx.cose_alg {
            return fail(
                codes::STS_AUTHN_0234,
                "packed",
                format!(
                    "a self attestation names alg {alg} and the credential \
                     key is {}",
                    ctx.cose_alg
                        .map_or("undefined".to_string(), |a| a.to_string())
                ),
            );
        }
        let ok = verify_cose_signature(
            alg,
            CoseKey::Jwk(&ctx.credential_jwk),
            &signed,
            &sig,
            &CoseOptions {
                allow_insecure: ctx.allow_insecure,
                ..CoseOptions::default()
            },
        );
        if !ok {
            return fail(
                codes::STS_AUTHN_0233,
                "packed",
                "the self attestation signature does not verify under the \
                 credential key"
                    .to_string(),
            );
        }
        return Statement::Verified {
            format: "packed".to_string(),
            kind: "self",
            trust_path: Vec::new(),
            acki: None,
        };
    }
    if !verify_with_certificate(
        &chain[0],
        alg,
        &signed,
        &sig,
        ctx.allow_insecure,
    ) {
        return fail(
            codes::STS_AUTHN_0233,
            "packed",
            format!(
                "the signature does not verify under the attestation \
                 certificate's key with alg {alg}"
            ),
        );
    }
    let problem = match attestation_certificate_facts(&chain[0]) {
        None => "the attestation certificate cannot be read".to_string(),
        Some(facts) => {
            let p = packed_certificate_problem(&facts);
            if p.is_empty() {
                aaguid_extension_problem(&facts, ctx)
            } else {
                p
            }
        }
    };
    if !problem.is_empty() {
        return fail(codes::STS_AUTHN_0234, "packed", problem);
    }
    Statement::Verified {
        format: "packed".to_string(),
        kind: "basic",
        trust_path: chain,
        acki: None,
    }
}

fn tpm(st: &Cbor, ctx: &Context) -> Statement {
    let shape = shape_problem(
        st,
        &["ver", "alg", "x5c", "sig", "certInfo", "pubArea"],
        &[],
    );
    if !shape.is_empty() {
        return fail(codes::STS_AUTHN_0232, "tpm", shape);
    }
    let ver = member(st, "ver").map(Cbor::text_of).unwrap_or_default();
    if ver != "2.0" {
        return fail(
            codes::STS_AUTHN_0232,
            "tpm",
            format!("ver is \"{ver}\", and only \"2.0\" is defined"),
        );
    }
    let alg = member(st, "alg").and_then(Cbor::int).unwrap_or(0);
    let pub_area = bytes_of(st, "pubArea");
    let cert_info = bytes_of(st, "certInfo");
    let parsed = tpm_parse_public(&pub_area)
        .and_then(|p| tpm_parse_attest(&cert_info).map(|a| (p, a)));
    let (public, attest) = match parsed {
        Ok(pa) => pa,
        Err(e) => {
            return fail(
                codes::STS_AUTHN_0234,
                "tpm",
                format!("pubArea or certInfo cannot be read: {e}"),
            )
        }
    };
    if !same_key(&public.jwk, &ctx.credential_jwk) {
        return fail(
            codes::STS_AUTHN_0234,
            "tpm",
            "the key in pubArea is not the credential public key".to_string(),
        );
    }
    let chain = x5c(st);
    let problem = match attestation_certificate_facts(&chain[0]) {
        None => "the AIK certificate cannot be read".to_string(),
        Some(facts) => {
            let p = tpm_certificate_problem(&facts);
            if p.is_empty() {
                aaguid_extension_problem(&facts, ctx)
            } else {
                p
            }
        }
    };
    if !problem.is_empty() {
        return fail(codes::STS_AUTHN_0234, "tpm", problem);
    }
    let raw = bytes_of(st, "sig");
    let signature = tpm_parse_signature(&raw).map_or(raw, |p| p.signature);
    if !verify_with_certificate(
        &chain[0],
        alg,
        &cert_info,
        &signature,
        ctx.allow_insecure,
    ) {
        return fail(
            codes::STS_AUTHN_0233,
            "tpm",
            format!(
                "the signature over certInfo does not verify under the AIK \
                 certificate's key with alg {alg}"
            ),
        );
    }
    let spec = cose_signature_alg(alg);
    let mut signed = ctx.auth_data.clone();
    signed.extend(&ctx.client_data_hash);
    let expected = spec.and_then(|s| s.hash).map(|h| match h {
        "sha384" => Hash::Sha384.digest(&signed),
        "sha512" => Hash::Sha512.digest(&signed),
        "sha1" => sts_crypto::content_hash::sha1(&signed).to_vec(),
        _ => Hash::Sha256.digest(&signed),
    });
    let why = if attest.magic != TPM_GENERATED_VALUE {
        "certInfo's magic is not TPM_GENERATED_VALUE".to_string()
    } else if attest.attest_type != TPM_ST_ATTEST_CERTIFY {
        "certInfo is not a TPM_ST_ATTEST_CERTIFY".to_string()
    } else if expected.as_deref() != Some(&attest.extra_data[..]) {
        format!(
            "certInfo's extraData is not the {} hash of authenticatorData ‖ \
             clientDataHash",
            spec.and_then(|s| s.hash).unwrap_or("alg's")
        )
    } else {
        match tpm_name(&public) {
            Ok(name) if Some(&name) == attest.name.as_ref() => String::new(),
            _ => "certInfo's attested name is not the Name of pubArea"
                .to_string(),
        }
    };
    if !why.is_empty() {
        return fail(codes::STS_AUTHN_0234, "tpm", why);
    }
    Statement::Verified {
        format: "tpm".to_string(),
        kind: "attca",
        trust_path: chain,
        acki: None,
    }
}

fn fido_u2f(st: &Cbor, ctx: &Context) -> Statement {
    let shape = shape_problem(st, &["x5c", "sig"], &[]);
    if !shape.is_empty() {
        return fail(codes::STS_AUTHN_0232, "fido-u2f", shape);
    }
    let chain = x5c(st);
    if chain.len() != 1 {
        return fail(
            codes::STS_AUTHN_0232,
            "fido-u2f",
            format!("x5c has {} certificates, and must have one", chain.len()),
        );
    }
    let facts = attestation_certificate_facts(&chain[0]);
    let p256 = facts.as_ref().is_some_and(|f| {
        f["keyType"] == serde_json::json!("ec")
            && f["curve"] == serde_json::json!("prime256v1")
    });
    if !p256 {
        return fail(
            codes::STS_AUTHN_0234,
            "fido-u2f",
            "the attestation certificate's key is not EC P-256".to_string(),
        );
    }
    let coordinate = |k: i64| {
        ctx.cose
            .as_ref()
            .and_then(|c| c.get_int(k))
            .and_then(Cbor::bytes)
            .filter(|b| b.len() == 32)
            .map(<[u8]>::to_vec)
    };
    let (Some(x), Some(y)) = (coordinate(-2), coordinate(-3)) else {
        return fail(
            codes::STS_AUTHN_0234,
            "fido-u2f",
            "the credential key is not a P-256 point with 32-byte coordinates"
                .to_string(),
        );
    };
    let mut data = vec![0u8];
    data.extend(&ctx.rp_id_hash);
    data.extend(&ctx.client_data_hash);
    data.extend(&ctx.credential_id);
    data.push(0x04);
    data.extend(&x);
    data.extend(&y);
    if !verify_with_certificate(
        &chain[0],
        -7,
        &data,
        &bytes_of(st, "sig"),
        false,
    ) {
        return fail(
            codes::STS_AUTHN_0233,
            "fido-u2f",
            "the signature over the U2F registration message does not verify"
                .to_string(),
        );
    }
    let acki = attestation_key_identifier(&chain[0]);
    Statement::Verified {
        format: "fido-u2f".to_string(),
        kind: "basic",
        trust_path: chain,
        acki: Some(acki),
    }
}

/// `verifyStatement(format, attStmt, ctx)`.
#[tracing::instrument(level = "debug", skip(st, ctx))]
pub fn verify_statement(format: &str, st: &Cbor, ctx: &Context) -> Statement {
    if !FORMATS.contains(&format) {
        return fail(
            codes::STS_AUTHN_0231,
            format,
            format!(
                "the format \"{format}\" is not one of WebAuthn Level 3 \
                 section 8's ({})",
                FORMATS.join(", ")
            ),
        );
    }
    match format {
        "packed" => packed(st, ctx),
        "tpm" => tpm(st, ctx),
        "fido-u2f" => fido_u2f(st, ctx),
        "none" => {
            let shape = shape_problem(st, &[], &[]);
            if shape.is_empty() {
                Statement::Verified {
                    format: "none".to_string(),
                    kind: "none",
                    trust_path: Vec::new(),
                    acki: None,
                }
            } else {
                fail(codes::STS_AUTHN_0232, "none", shape)
            }
        }
        other => Statement::Unported {
            format: other.to_string(),
        },
    }
}
