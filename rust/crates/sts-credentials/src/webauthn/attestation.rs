// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The attestation STATEMENTS of WebAuthn Level 3 section 8, as
//! `authn/webauthn_attestation.ts`'s `verifyStatement()` verifies them
//! (#105): steps 21 and 22 of section 7.1 — the format's shape, its
//! signature, and what it requires of its certificate.
//!
//! All eight formats: `packed` (Self, and Basic/AttCA through x5c,
//! section 8.2), `tpm` (AttCA through an AIK certificate, 8.3),
//! `android-key` (Basic, its KeyDescription read from the hardware-enforced
//! list, 8.4), `android-safetynet` (Basic, a JWS from attest.android.com,
//! 8.5), `fido-u2f` (8.6), `none` (8.7), `apple` (AnonCA, 8.8) and
//! `compound` (8.9, every member verified, one level deep), and the refusal
//! of a format section 8 does not define. What follows the statement in
//! `assess()` — the FIDO Metadata Service, the trust path to the anchors,
//! revocation, the policy that demands trust — is [`super::trust`].

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value as Json;
use sts_core::errors::{codes, ErrorCode};
use sts_crypto::jws;
use sts_crypto::jws_alg::Hash;
use sts_crypto::keys::{JwsKey, KeyPolicy};
use sts_crypto::raw_sig::public_key_from_spki;
use sts_crypto::webauthn::{
    android_key_description, apple_attestation_nonce, cose_signature_alg,
    fido_aaguid_extension, tpm_name, tpm_parse_attest, tpm_parse_public,
    tpm_parse_signature, verify_cose_signature, CoseKey, CoseOptions,
    TPM_GENERATED_VALUE, TPM_ST_ATTEST_CERTIFY,
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
const OID_ANDROID_KEY: &str = "1.3.6.1.4.1.11129.2.1.17";
const OID_APPLE_NONCE: &str = "1.2.840.113635.100.8.2";
/// Android Keymaster's constants (section 8.4).
const KM_ORIGIN_GENERATED: i64 = 0;
const KM_PURPOSE_SIGN: i64 = 2;
/// A SafetyNet response older than this, or this far in the future, is
/// refused: the specification defers to Google, which checks `timestampMs`
/// against the time of the request.
const SAFETYNET_WINDOW_MS: f64 = 60.0 * 1000.0;
/// How deep a compound statement may nest: one level.
const MAX_COMPOUND_DEPTH: usize = 1;
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
    /// `webauthn.attestationAndroidSoftwareKeys` (`settings.
    /// androidSoftwareKeys`): android-key reads both authorization lists.
    pub android_software_keys: bool,
    /// The verifier's clock (`deps.now()`), for SafetyNet's `timestampMs`.
    pub now_ms: f64,
}

/// `verifyStatement()`'s answer.
#[derive(Debug, Clone, PartialEq)]
pub enum Statement {
    Verified {
        format: String,
        kind: &'static str,
        trust_path: Vec<Vec<u8>>,
        acki: Option<String>,
        /// android-safetynet's: trusted only where the realm allows it.
        safetynet: bool,
        /// A compound statement's members, each verified.
        subs: Vec<Statement>,
    },
    Refused {
        code: ErrorCode,
        format: String,
        why: String,
    },
}

/// A verified statement with no SafetyNet flag and no members.
fn verified(
    format: &str,
    kind: &'static str,
    trust_path: Vec<Vec<u8>>,
    acki: Option<String>,
) -> Statement {
    Statement::Verified {
        format: format.to_string(),
        kind,
        trust_path,
        acki,
        safetynet: false,
        subs: Vec::new(),
    }
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
                ..
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
        return verified("packed", "self", Vec::new(), None);
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
    verified("packed", "basic", chain, None)
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
    verified("tpm", "attca", chain, None)
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
    verified("fido-u2f", "basic", chain, Some(acki))
}

fn extension_value(facts: &Json, oid: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let ext = facts["extensions"].get(oid)?;
    base64::engine::general_purpose::STANDARD
        .decode(ext["value"].as_str().unwrap_or(""))
        .ok()
}

/// Section 8.4: Basic, the credential key certified with a KeyDescription.
fn android_key(st: &Cbor, ctx: &Context) -> Statement {
    let f = "android-key";
    let shape = shape_problem(st, &["alg", "sig", "x5c"], &[]);
    if !shape.is_empty() {
        return fail(codes::STS_AUTHN_0232, f, shape);
    }
    let alg = member(st, "alg").and_then(Cbor::int).unwrap_or(0);
    let chain = x5c(st);
    let mut signed = ctx.auth_data.clone();
    signed.extend(&ctx.client_data_hash);
    if !verify_with_certificate(
        &chain[0],
        alg,
        &signed,
        &bytes_of(st, "sig"),
        ctx.allow_insecure,
    ) {
        return fail(
            codes::STS_AUTHN_0233,
            f,
            "the signature does not verify under the first certificate's key"
                .to_string(),
        );
    }
    let facts = attestation_certificate_facts(&chain[0]);
    let Some(facts) =
        facts.filter(|fa| same_key(&fa["publicKeyJwk"], &ctx.credential_jwk))
    else {
        return fail(
            codes::STS_AUTHN_0234,
            f,
            "the first certificate's key is not the credential public key"
                .to_string(),
        );
    };
    let description = match extension_value(&facts, OID_ANDROID_KEY) {
        None => None,
        Some(v) => match android_key_description(&v) {
            Ok(d) => Some(d),
            Err(e) => return fail(codes::STS_AUTHN_0234, f, e),
        },
    };
    let Some(d) = description else {
        return fail(
            codes::STS_AUTHN_0234,
            f,
            format!(
                "the certificate carries no key attestation extension \
                 ({OID_ANDROID_KEY})"
            ),
        );
    };
    let lists = if ctx.android_software_keys {
        vec![&d.tee_enforced, &d.software_enforced]
    } else {
        vec![&d.tee_enforced]
    };
    let origin = lists.iter().find_map(|l| l.origin);
    let purposes: Vec<i64> = lists
        .iter()
        .flat_map(|l| l.purpose.iter().copied())
        .collect();
    let why = if d.attestation_challenge != ctx.client_data_hash {
        "the attestationChallenge is not the client data hash".to_string()
    } else if d.software_enforced.all_applications
        || d.tee_enforced.all_applications
    {
        "the key is usable by all applications (allApplications), and a \
         credential must be scoped to its RP ID"
            .to_string()
    } else if origin != Some(KM_ORIGIN_GENERATED) {
        format!(
            "the key's origin is {} in the {}, not KM_ORIGIN_GENERATED",
            origin.map_or("not stated".to_string(), |o| o.to_string()),
            if ctx.android_software_keys {
                "authorization lists"
            } else {
                "hardware-enforced list"
            }
        )
    } else if purposes.is_empty()
        || purposes.iter().any(|p| *p != KM_PURPOSE_SIGN)
    {
        let listed: Vec<String> = purposes.iter().map(i64::to_string).collect();
        format!(
            "the key's purpose is {}, not KM_PURPOSE_SIGN alone",
            if listed.is_empty() {
                "not stated".to_string()
            } else {
                listed.join(", ")
            }
        )
    } else {
        String::new()
    };
    if !why.is_empty() {
        return fail(codes::STS_AUTHN_0234, f, why);
    }
    verified(f, "basic", chain, None)
}

static GOOGLE_SAN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(^|,\s*)DNS:attest\.android\.com(,|$)").expect("a literal")
});
static GOOGLE_CN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(^|\n)CN=attest\.android\.com(\n|$)").expect("a literal")
});

/// Section 8.5: Basic, a SafetyNet JWS. Verified, and TRUSTED only where
/// `webauthn.attestationAllowSafetynet` says (`trustOf()`).
fn safetynet(st: &Cbor, ctx: &Context) -> Statement {
    let f = "android-safetynet";
    let shape = shape_problem(st, &["ver", "response"], &[]);
    if !shape.is_empty() {
        return fail(codes::STS_AUTHN_0232, f, shape);
    }
    let jws = String::from_utf8_lossy(&bytes_of(st, "response")).to_string();
    let header: Option<Json> = serde_json::from_slice(
        &super::ceremony::from_base64url(jws.split('.').next().unwrap_or("")),
    )
    .ok();
    let chain: Vec<Vec<u8>> = header
        .as_ref()
        .and_then(|h| h.get("x5c"))
        .and_then(Json::as_array)
        .map(|l| {
            l.iter()
                .map(|one| {
                    sts_pki::foreign::node_base64(&crate::js::string(one))
                })
                .collect()
        })
        .unwrap_or_default();
    let facts = chain.first().and_then(|d| attestation_certificate_facts(d));
    let Some(facts) = facts else {
        return fail(
            codes::STS_AUTHN_0232,
            f,
            "the response is not a JWS carrying an x5c chain".to_string(),
        );
    };
    if !GOOGLE_SAN.is_match(facts["subjectAltName"].as_str().unwrap_or(""))
        && !GOOGLE_CN.is_match(facts["subjectText"].as_str().unwrap_or(""))
    {
        return fail(
            codes::STS_AUTHN_0234,
            f,
            "the response is not signed by attest.android.com".to_string(),
        );
    }
    let checked = JwsKey::from_pem(facts["pem"].as_str().unwrap_or(""))
        .and_then(|key| {
            jws::verify_compact(
                &jws,
                &key,
                &jws::VerifyOptions {
                    algorithms: &["RS256", "ES256"],
                    empty_payload: false,
                    policy: KeyPolicy::STRICT,
                },
            )
        });
    let claims = match checked {
        Ok(v) => v.claims.unwrap_or(Json::Null),
        Err(e) => {
            return fail(
                codes::STS_AUTHN_0233,
                f,
                format!("the response's signature does not verify: {}", e.0),
            )
        }
    };
    let mut signed = ctx.auth_data.clone();
    signed.extend(&ctx.client_data_hash);
    let nonce = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        Hash::Sha256.digest(&signed),
    );
    let at = crate::js::number_opt(claims.get("timestampMs"));
    let now = ctx.now_ms;
    let window = SAFETYNET_WINDOW_MS;
    let why = if claims.get("nonce") != Some(&Json::String(nonce)) {
        "the nonce is not the base64 SHA-256 of authenticatorData ‖ \
         clientDataHash"
            .to_string()
    } else if claims.get("ctsProfileMatch") != Some(&Json::Bool(true)) {
        "ctsProfileMatch is not true: the device failed Android compatibility"
            .to_string()
    } else if !at.is_finite() || at > now + window || at < now - window {
        "the response's timestampMs is not within a minute of now".to_string()
    } else {
        String::new()
    };
    if !why.is_empty() {
        return fail(codes::STS_AUTHN_0234, f, why);
    }
    Statement::Verified {
        format: f.to_string(),
        kind: "basic",
        trust_path: chain,
        acki: None,
        safetynet: true,
        subs: Vec::new(),
    }
}

/// Section 8.8: AnonCA, a certificate for the credential key with the nonce
/// in it.
fn apple(st: &Cbor, ctx: &Context) -> Statement {
    let f = "apple";
    let shape = shape_problem(st, &["x5c"], &[]);
    if !shape.is_empty() {
        return fail(codes::STS_AUTHN_0232, f, shape);
    }
    let chain = x5c(st);
    let facts = attestation_certificate_facts(&chain[0]);
    let nonce = facts
        .as_ref()
        .and_then(|fa| extension_value(fa, OID_APPLE_NONCE))
        .and_then(|v| apple_attestation_nonce(&v));
    let mut signed = ctx.auth_data.clone();
    signed.extend(&ctx.client_data_hash);
    let expected = Hash::Sha256.digest(&signed);
    if nonce.as_deref() != Some(&expected[..]) {
        return fail(
            codes::STS_AUTHN_0234,
            f,
            if nonce.is_some() {
                "the certificate's nonce is not the SHA-256 of \
                 authenticatorData ‖ clientDataHash"
                    .to_string()
            } else {
                format!(
                    "the certificate carries no nonce extension \
                     ({OID_APPLE_NONCE})"
                )
            },
        );
    }
    let jwk = facts.map_or(Json::Null, |fa| fa["publicKeyJwk"].clone());
    if !same_key(&jwk, &ctx.credential_jwk) {
        return fail(
            codes::STS_AUTHN_0234,
            f,
            "the certificate's key is not the credential public key"
                .to_string(),
        );
    }
    verified(f, "anonca", chain, None)
}

/// Section 8.9: two or more statements, each verified by its own procedure;
/// "Relying Party policy" here is that every member must verify.
fn compound(st: &Cbor, ctx: &Context, depth: usize) -> Statement {
    let f = "compound";
    if depth >= MAX_COMPOUND_DEPTH {
        return fail(
            codes::STS_AUTHN_0232,
            f,
            "a compound statement may not contain another".to_string(),
        );
    }
    let items = match st {
        Cbor::Array(items) if items.len() >= 2 => items,
        _ => {
            return fail(
                codes::STS_AUTHN_0232,
                f,
                "attStmt is not an array of at least two statements"
                    .to_string(),
            )
        }
    };
    let mut subs = Vec::new();
    for (i, one) in items.iter().enumerate() {
        let pair = match one {
            Cbor::Map(entries) if entries.len() == 2 => {
                match (one.get_text("fmt"), one.get_text("attStmt")) {
                    (Some(Cbor::Text(fmt)), Some(inner))
                        if fmt != "compound" =>
                    {
                        Some((fmt.clone(), inner))
                    }
                    _ => None,
                }
            }
            _ => None,
        };
        let Some((fmt, inner)) = pair else {
            return fail(
                codes::STS_AUTHN_0232,
                f,
                format!(
                    "member {i} is not a {{ fmt, attStmt }} pair of another \
                     format"
                ),
            );
        };
        match statement_at(&fmt, inner, ctx, depth + 1) {
            Statement::Refused { code, why, .. } => {
                return fail(code, f, format!("member {i} — {why}"));
            }
            ok => subs.push(ok),
        }
    }
    Statement::Verified {
        format: f.to_string(),
        kind: "compound",
        trust_path: Vec::new(),
        acki: None,
        safetynet: false,
        subs,
    }
}

/// `verifyStatement(format, attStmt, ctx, 0)`.
#[tracing::instrument(level = "debug", skip(st, ctx))]
pub fn verify_statement(format: &str, st: &Cbor, ctx: &Context) -> Statement {
    statement_at(format, st, ctx, 0)
}

/// `verifyStatement(format, attStmt, ctx, depth)`.
fn statement_at(
    format: &str,
    st: &Cbor,
    ctx: &Context,
    depth: usize,
) -> Statement {
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
        "android-key" => android_key(st, ctx),
        "android-safetynet" => safetynet(st, ctx),
        "fido-u2f" => fido_u2f(st, ctx),
        "apple" => apple(st, ctx),
        "compound" => compound(st, ctx, depth),
        _ => {
            let shape = shape_problem(st, &[], &[]);
            if shape.is_empty() {
                verified("none", "none", Vec::new(), None)
            } else {
                fail(codes::STS_AUTHN_0232, "none", shape)
            }
        }
    }
}
