// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Issuing a certificate and making a PKCS#10 request (`x509.js`'s
//! `issueCertificate()` and `certificationRequest()`), and the one place
//! that turns a (signature algorithm, private key) into a signature.
//!
//! The TBSCertificate is written as pkijs writes it — the version `[0]`,
//! the serial INTEGER from the bytes given, the signature AlgorithmIdentifier
//! pkijs chooses (RSA and ECDSA with no parameters), the times as RFC 5280
//! section 4.1.2.5 says — so a certificate issued here with a
//! deterministic signer is Node's byte for byte.
//!
//! A hybrid certificate (ITU-T X.509 (2019) clause 9.8) is signed TWICE: the
//! alternative signature over the preTBSCertificate — the TBS without its
//! `signature` field and without the altSignatureValue extension — then the
//! conventional one over everything, the three extensions included.

use chrono::{DateTime, Datelike, Utc};
use openssl::pkey::Id;
use openssl::rand::rand_bytes;
use openssl::rsa::Padding;
use openssl::sign::{RsaPssSaltlen, Signer};
use serde_json::{json, Value as Json};
use sts_crypto::pq_x509::{self, Use};

use super::algorithms::{self, SigAlg, SigKind};
use super::extensions::{self as ext, extension};
use super::js;
use super::keys::{self, SigningKey};
use super::names;
use super::read::{self, Certificate};
use super::time;
use crate::der;
use crate::error::{PkiError, PkiResult};

/// What `issueCertificate()` returns.
#[derive(Clone, Debug)]
pub struct IssuedCertificate {
    pub der: Vec<u8>,
    pub pem: String,
    pub serial_hex: String,
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub signature_alg: String,
}

/// What `certificationRequest()` returns.
#[derive(Clone, Debug)]
pub struct CertificationRequest {
    pub der: Vec<u8>,
    pub pem: String,
    pub base64: String,
    pub subject: String,
    pub signature_alg: String,
}

/// `randomSerialHex()`: a positive random integer whose top octet is
/// neither 0 nor ≥ 0x80.
pub fn random_serial_hex(bytes: usize) -> PkiResult<String> {
    let mut raw = vec![0u8; bytes.max(1)];
    rand_bytes(&mut raw)?;
    raw[0] &= 0x7f;
    if raw[0] == 0 {
        raw[0] = 1;
    }
    Ok(der::hex(&raw))
}

/// `serialFromHex()`: the bytes of the hex given (non-hex dropped, an odd
/// digit padded), a zero octet in front of one that would read negative.
fn serial_from_hex(hex: &str) -> Vec<u8> {
    let mut clean: String =
        hex.chars().filter(char::is_ascii_hexdigit).collect();
    if clean.len() % 2 == 1 {
        clean.insert(0, '0');
    }
    let mut bytes: Vec<u8> = (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap_or(0))
        .collect();
    if bytes.first().is_some_and(|b| *b >= 0x80) {
        bytes.insert(0, 0);
    }
    bytes
}

/// `minimalDerInteger()`: leading zero octets dropped, one added where the
/// top bit would make it negative.
pub fn minimal_der_integer(bytes: &[u8]) -> Vec<u8> {
    let mut start = 0;
    while start + 1 < bytes.len()
        && bytes[start] == 0
        && bytes[start + 1] & 0x80 == 0
    {
        start += 1;
    }
    let mut out = bytes[start..].to_vec();
    if out.first().is_some_and(|b| b & 0x80 != 0) {
        out.insert(0, 0);
    }
    out
}

/// `ecdsaRawToDer()`: fixed-width r || s as a minimal Ecdsa-Sig-Value.
pub fn ecdsa_raw_to_der(raw: &[u8]) -> Vec<u8> {
    let half = raw.len() / 2;
    der::sequence(&[
        der::integer_raw(&minimal_der_integer(&raw[..half])),
        der::integer_raw(&minimal_der_integer(&raw[half..half * 2])),
    ])
}

/// `ecdsaDerToRaw()`: an Ecdsa-Sig-Value as fixed-width r || s.
pub fn ecdsa_der_to_raw(sig: &[u8], field_len: usize) -> PkiResult<Vec<u8>> {
    let refused =
        || PkiError::new("This ECDSA signature is not a DER Ecdsa-Sig-Value.");
    let seq = der::read(sig).ok_or_else(refused)?;
    let parts = der::children(seq.content).ok_or_else(refused)?;
    if parts.len() != 2 {
        return Err(refused());
    }
    let mut out = vec![0u8; field_len * 2];
    for (i, part) in parts.iter().enumerate() {
        let mut value = part.content;
        while value.len() > field_len && value[0] == 0 {
            value = &value[1..];
        }
        if value.len() > field_len {
            return Err(PkiError::new("offset is out of bounds"));
        }
        let at = i * field_len + (field_len - value.len());
        out[at..at + value.len()].copy_from_slice(value);
    }
    Ok(out)
}

/// `signBytes()`: one signature by a private key in a row's scheme — an
/// ECDSA one as a minimal DER Ecdsa-Sig-Value, a PSS one with a salt as
/// long as the digest.
pub fn sign_bytes(
    sig: &SigAlg,
    key: &SigningKey,
    data: &[u8],
) -> PkiResult<Vec<u8>> {
    match (sig.kind, key) {
        (SigKind::Pqc(wanted), SigningKey::Pqc { id, seed }) => {
            if *id != wanted {
                return Err(PkiError::new(format!(
                    "This is a {} private key and the signature algorithm asked for is {}. \
                     Unlike RSA, a post-quantum key can produce exactly one algorithm.",
                    id, wanted
                )));
            }
            let seed = seed.as_ref().ok_or_else(|| {
                PkiError::new(format!(
                    "This {} key was written in the expandedKey arm of RFC 9881 section 6. \
                     Signing from an expanded key is possible in principle and is not \
                     implemented here: this build signs from the seed, which is the arm the \
                     RFC recommends and the only one an AKP JWK can carry.",
                    id
                ))
            })?;
            Ok(pq_x509::sign(id, data, seed)?)
        }
        (SigKind::Pqc(_), SigningKey::Classical(_)) => Err(PkiError::new(format!(
            "This private key is not a post-quantum key, and {} can only be produced by one.",
            sig.id
        ))),
        (_, SigningKey::Pqc { id, .. }) => Err(PkiError::new(format!(
            "A {} private key cannot make a {} signature.",
            id, sig.id
        ))),
        (kind, SigningKey::Classical(pkey)) => {
            let fits = matches!(
                (kind, pkey.id()),
                (SigKind::Rsa { .. }, Id::RSA) | (SigKind::Ec { .. }, Id::EC) | (SigKind::Ed25519, Id::ED25519)
            );
            if !fits {
                return Err(PkiError::new(format!(
                    "This private key cannot make a {} signature.",
                    sig.id
                )));
            }
            Ok(match kind {
                SigKind::Ed25519 => Signer::new_without_digest(pkey)?.sign_oneshot_to_vec(data)?,
                SigKind::Ec { hash } => {
                    let der = Signer::new(hash.digest(), pkey)?.sign_oneshot_to_vec(data)?;
                    read::minimal_ecdsa_signature(&der)
                }
                SigKind::Rsa { hash, pss } => {
                    let mut s = Signer::new(hash.digest(), pkey)?;
                    if pss {
                        s.set_rsa_padding(Padding::PKCS1_PSS)?;
                        s.set_rsa_mgf1_md(hash.digest())?;
                        s.set_rsa_pss_saltlen(RsaPssSaltlen::custom(hash.digest_len() as i32))?;
                    }
                    s.sign_oneshot_to_vec(data)?
                }
                SigKind::Pqc(_) => Vec::new(),
            })
        }
    }
}

/// A spec's subject: a DN string or an attribute list.
fn subject_attributes(subject: Option<&Json>) -> Vec<Json> {
    match subject {
        Some(Json::String(s)) => names::parse_dn_string(s),
        Some(Json::Array(a)) => a.clone(),
        _ => Vec::new(),
    }
}

/// `Date.prototype.setUTCFullYear(year + n)`: Feb 29 into a common year
/// becomes Mar 1.
fn add_years(t: DateTime<Utc>, years: i32) -> DateTime<Utc> {
    match t.with_year(t.year() + years) {
        Some(moved) => moved,
        None => t
            .with_day(1)
            .and_then(|d| d.with_month(3))
            .and_then(|d| d.with_year(t.year() + years))
            .unwrap_or(t),
    }
}

/// The signature algorithm a spec names, or why there is none.
fn signature_algorithm(name: &str) -> PkiResult<SigAlg> {
    if let Some(sig) = algorithms::sig_alg(name) {
        return Ok(sig);
    }
    match pq_x509::alg(name) {
        Some(kem) if kem.usage == Use::Kem => Err(PkiError::new(format!(
            "{} is a key-encapsulation mechanism: it cannot sign a certificate. \
             An ML-KEM key is certified BY an issuer with a signing key.",
            kem.name
        ))),
        _ => Err(PkiError::new(format!("Unknown signature algorithm: {}", name))),
    }
}

/// `issueCertificate()`. `spec` is `x509.js`'s: `subject`,
/// `subjectPublicKey`, `issuer` (`{ certificatePem, privateKeyPem, keyAlg }`
/// or none for self-signed with `issuerPrivateKey`), `signatureAlg`,
/// `serial`, `notBefore` / `notAfter`, `profile`, `extensions`, and the
/// hybrid's `altSignature` and `subjectAltPublicKey`.
pub fn issue_certificate(spec: &Json) -> PkiResult<IssuedCertificate> {
    let subject_attrs = subject_attributes(spec.get("subject"));
    if subject_attrs.is_empty() {
        return Err(PkiError::new("A certificate needs a subject."));
    }
    let subject_spki =
        keys::pem_to_der(&js::string_of(spec.get("subjectPublicKey")))?;
    let sig = signature_algorithm(&js::string_of(spec.get("signatureAlg")))?;
    let issuer_spec = spec.get("issuer").filter(|i| js::truthy(Some(i)));
    let issuer_cert = match issuer_spec
        .and_then(|i| i.get("certificatePem"))
        .filter(|p| js::truthy(Some(p)))
    {
        Some(pem) => Some(Certificate::from_pem(&js::string_of(Some(pem)))?),
        None => None,
    };
    let issuer_private = match issuer_spec {
        Some(i) => i.get("privateKeyPem"),
        None => spec.get("issuerPrivateKey"),
    };
    if !js::truthy(issuer_private) {
        return Err(PkiError::new(
            "No issuer private key: nothing can sign this certificate.",
        ));
    }
    let signer = SigningKey::from_pem(&js::string_of(issuer_private))?;

    let serial = serial_from_hex(&if js::truthy(spec.get("serial")) {
        js::string_of(spec.get("serial"))
    } else {
        random_serial_hex(16)?
    });
    let subject = names::build_dn(&subject_attrs)?;
    let issuer_name = issuer_cert
        .as_ref()
        .map_or(subject.clone(), |c| c.subject_der.clone());

    let not_before = match spec.get("notBefore").filter(|v| js::truthy(Some(v)))
    {
        Some(v) => time::js_date(v)?,
        None => Utc::now(),
    };
    let not_after = match spec.get("notAfter").filter(|v| js::truthy(Some(v))) {
        Some(v) => time::js_date(v)?,
        None => {
            let years = spec
                .get("profile")
                .and_then(Json::as_str)
                .and_then(ext::profile)
                .map_or(1, |p| p.years);
            add_years(not_before, years)
        }
    };

    let ext_spec = match spec.get("extensions").filter(|e| js::truthy(Some(e)))
    {
        Some(e) => e.clone(),
        None => ext::default_extensions(
            spec.get("profile").and_then(Json::as_str).unwrap_or(""),
        ),
    };
    let mut extensions =
        ext::build_extensions(&ext_spec, &subject_spki, issuer_cert.as_ref())?;

    let tbs_with = |signature_alg: &[u8], extensions: &[Vec<u8>]| -> Vec<u8> {
        let mut fields = vec![
            der::context(0, true, &der::integer(2)),
            der::integer_raw(&serial),
            signature_alg.to_vec(),
            issuer_name.clone(),
            der::sequence(&[
                time::validity_time(&not_before),
                time::validity_time(&not_after),
            ]),
            subject.clone(),
            subject_spki.clone(),
        ];
        if !extensions.is_empty() {
            fields.push(der::context(3, true, &der::sequence(extensions)));
        }
        der::sequence(&fields)
    };

    let alt = spec.get("altSignature").filter(|a| js::truthy(Some(a)));
    if alt.is_some() || js::truthy(spec.get("subjectAltPublicKey")) {
        let alt_critical = alt.is_some_and(|a| js::truthy(a.get("critical")));
        if js::truthy(spec.get("subjectAltPublicKey")) {
            let alt_spki = keys::pem_to_der(&js::string_of(
                spec.get("subjectAltPublicKey"),
            ))?;
            let element = der::read(&alt_spki)
                .ok_or_else(|| PkiError::new("The alternative public key is not a readable SubjectPublicKeyInfo."))?;
            extensions.push(extension(
                ext::SUBJECT_ALT_PUBLIC_KEY_INFO,
                alt_critical,
                element.raw,
            )?);
        }
        if let Some(alt) = alt {
            let alt_sig =
                algorithms::sig_alg(&js::string_of(alt.get("signatureAlg")))
                    .ok_or_else(|| {
                        PkiError::new(format!(
                            "Unknown alternative signature algorithm: {}",
                            js::string_of(alt.get("signatureAlg"))
                        ))
                    })?;
            if !js::truthy(alt.get("privateKeyPem")) {
                return Err(PkiError::new(
                    "An alternative signature is made with the ISSUER's alternative private key \
                     — the one matching the alternative public key in the issuer's own \
                     certificate. There is none here.",
                ));
            }
            extensions.push(extension(
                ext::ALT_SIGNATURE_ALGORITHM,
                alt_critical,
                &algorithms::signature_algorithm_identifier(&alt_sig)?,
            )?);
            // The `signature` field is removed by the preTBS, so what it holds
            // here does not matter.
            let pre_tbs = read::pre_tbs_from_tbs(&tbs_with(
                &der::sequence(&[]),
                &extensions,
            ))?;
            let alt_key =
                SigningKey::from_pem(&js::string_of(alt.get("privateKeyPem")))?;
            let value = sign_bytes(&alt_sig, &alt_key, &pre_tbs)?;
            extensions.push(extension(
                ext::ALT_SIGNATURE_VALUE,
                alt_critical,
                &der::bit_string(&value),
            )?);
        }
    }

    let signature_alg = algorithms::certificate_signature_identifier(&sig)?;
    let tbs = tbs_with(&signature_alg, &extensions);
    let signature = sign_bytes(&sig, &signer, &tbs)?;
    let der_bytes =
        der::sequence(&[tbs, signature_alg, der::bit_string(&signature)]);
    let issued = Certificate::from_der(&der_bytes)?;
    Ok(IssuedCertificate {
        pem: keys::der_to_pem(&der_bytes, "CERTIFICATE"),
        serial_hex: der::hex(&serial),
        subject: issued.subject(),
        issuer: issued.issuer(),
        not_before: time::iso(&not_before),
        not_after: time::iso(&not_after),
        signature_alg: sig.id,
        der: der_bytes,
    })
}

/// `certificationRequest()`: a PKCS#10 request signed by the key it asks
/// to have certified — the proof of possession the format exists for.
pub fn certification_request(spec: &Json) -> PkiResult<CertificationRequest> {
    let subject_attrs = subject_attributes(spec.get("subject"));
    if subject_attrs.is_empty() {
        return Err(PkiError::new(
            "A certification request needs a subject. SPIFFE puts no meaning in it — C=US, \
             O=SPIRE is what SPIRE itself issues — but PKCS#10 has nowhere to leave it out.",
        ));
    }
    if !js::truthy(spec.get("publicKeyPem")) {
        return Err(PkiError::new("A certification request carries the public key it is asking to have certified."));
    }
    if !js::truthy(spec.get("privateKeyPem")) {
        return Err(PkiError::new(
            "A certification request is SIGNED by the private key matching its public key: that \
             signature is the proof of possession the whole format exists for.",
        ));
    }
    let public_pem = js::string_of(spec.get("publicKeyPem"));
    let key_desc = keys::describe_public_pem(&public_pem);
    let wanted = if js::truthy(spec.get("signatureAlg")) {
        js::string_of(spec.get("signatureAlg"))
    } else {
        let d = key_desc.as_ref();
        algorithms::default_signature_algorithm(
            d.map_or("", |k| k.kind()),
            d.and_then(|k| k.curve()),
            d.and_then(|k| k.pqc()),
        )
    };
    if let Some(id) = key_desc.as_ref().and_then(|k| k.pqc()) {
        if !keys::pq_signs(id) {
            return Err(PkiError::new(format!(
                "{} is a key-encapsulation mechanism and cannot sign, so it cannot make the \
                 proof of possession a PKCS#10 request IS. RFC 9935 section 7 says the same: a \
                 CSR for an ML-KEM key needs another mechanism entirely.",
                id
            )));
        }
    }
    let sig = algorithms::sig_alg(&wanted).ok_or_else(|| {
        PkiError::new(format!(
            "Unknown signature algorithm: {}",
            js::string_of(spec.get("signatureAlg"))
        ))
    })?;

    let subject = names::build_dn(&subject_attrs)?;
    let spki = keys::pem_to_der(&public_pem)?;
    let mut extensions = Vec::new();
    let non_empty = |member: &str| {
        spec.get(member)
            .and_then(Json::as_array)
            .filter(|a| !a.is_empty())
            .cloned()
    };
    if let Some(names_list) = non_empty("subjectAltName") {
        extensions.extend(ext::build_alt_name(
            ext::SUBJECT_ALT_NAME,
            &json!({ "names": names_list }),
        )?);
    }
    if let Some(usages) = non_empty("keyUsage") {
        extensions.extend(ext::build_key_usage(&json!({ "usages": usages }))?);
    }
    if let Some(usages) = non_empty("extKeyUsage") {
        extensions
            .extend(ext::build_ext_key_usage(&json!({ "usages": usages }))?);
    }
    if let Some(bc) =
        spec.get("basicConstraints").filter(|b| js::truthy(Some(b)))
    {
        extensions.push(ext::build_basic_constraints(bc)?);
    }
    let attributes = if extensions.is_empty() {
        Vec::new()
    } else {
        der::sequence(&[
            der::oid("1.2.840.113549.1.9.14")?,
            der::set(&[der::sequence(&extensions)]),
        ])
    };
    let info = der::sequence(&[
        der::integer(0),
        subject,
        spki,
        der::context(0, true, &attributes),
    ]);
    let signature_alg = algorithms::certificate_signature_identifier(&sig)?;
    let key = SigningKey::from_pem(&js::string_of(spec.get("privateKeyPem")))?;
    let signature = sign_bytes(&sig, &key, &info)?;
    let der_bytes =
        der::sequence(&[info, signature_alg, der::bit_string(&signature)]);
    let pem = keys::der_to_pem(&der_bytes, "CERTIFICATE REQUEST");
    Ok(CertificationRequest {
        base64: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &der_bytes,
        ),
        subject: der::read(&names::build_dn(&subject_attrs)?)
            .map(|e| names::dn_to_string(&e))
            .unwrap_or_default(),
        signature_alg: sig.id,
        der: der_bytes,
        pem,
    })
}

/// `selfSignedCertPem()`: a throwaway certificate for a key pair that
/// needs one only as a wrapper (PKCS#12), on a fixed window.
pub fn self_signed_cert_pem(options: &Json) -> PkiResult<String> {
    let public_pem = js::string_of(options.get("publicPem"));
    let signature_alg = if js::truthy(options.get("signatureAlg")) {
        js::string_of(options.get("signatureAlg"))
    } else {
        let d = keys::describe_public_pem(&public_pem);
        algorithms::default_signature_algorithm(
            d.as_ref().map_or("", |k| k.kind()),
            d.as_ref().and_then(|k| k.curve()),
            d.as_ref().and_then(|k| k.pqc()),
        )
    };
    let or = |member: &str, default: &str| {
        if js::truthy(options.get(member)) {
            js::string_of(options.get(member))
        } else {
            default.to_string()
        }
    };
    let issued = issue_certificate(&json!({
        "subject": or("subject", "CN=generated key"),
        "subjectPublicKey": public_pem,
        "issuerPrivateKey": options.get("privatePem"),
        "signatureAlg": signature_alg,
        "serial": or("serial", "01"),
        "notBefore": "2020-01-01T00:00:00.000Z",
        "notAfter": "2035-01-01T00:00:00.000Z",
        "extensions": ext::default_extensions(&or("profile", "tls-server")),
    }))?;
    Ok(issued.pem)
}
