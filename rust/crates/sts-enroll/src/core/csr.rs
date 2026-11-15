// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! PKCS#10 (`parseCsr()`, `readGeneralName()`, `ipText()`,
//! `keyAlgName()`, and `pki.csrProofOfPossession()`).
//!
//! **THE PROOF OF POSSESSION IS VERIFIED**: the CSR is the only thing
//! binding the key to the request, so its signature is checked with the
//! request's own key — RSA, ECDSA, Ed25519, ML-DSA, SLH-DSA and the
//! composites, through `sts-pki`'s `verify_bytes()`, after the realm's
//! accepted-signature list (`SignaturePolicy.acceptX509Cause()`). A
//! KEY-ENCAPSULATION key cannot sign and is refused unless the request is
//! only a TEMPLATE (EST `/serverkeygen`).
//!
//! The DER is read as pkijs reads it: ONE complete value, nothing after
//! it, `CertificationRequestInfo`'s four fields; a subject is
//! `type=value` by OID in encoded order (`out.subject`).

use sts_core::errors::codes;
use sts_pki::der::{self, Element};
use sts_pki::x509::keys::{der_to_pem, describe_spki, KeyDesc};

use super::{normal_host_name, Core, Outcome, Refusal};

const UPN_OID: &str = "1.3.6.1.4.1.311.20.2.3";
const ATTESTATION_OID: &str = "1.2.840.113549.1.9.16.2.59";
const CHALLENGE_PASSWORD_OID: &str = "1.2.840.113549.1.9.7";
const EXTENSION_REQUEST_OID: &str = "1.2.840.113549.1.9.14";
const SUBJECT_ALT_NAME_OID: &str = "2.5.29.17";

/// The names a request asks for (`requested`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Requested {
    pub uris: Vec<String>,
    pub dns: Vec<String>,
    pub ips: Vec<String>,
    pub emails: Vec<String>,
    pub upns: Vec<String>,
}

/// `parseCsr()`'s answer.
#[derive(Debug, Clone, Default)]
pub struct Csr {
    pub der: Vec<u8>,
    pub public_key_pem: String,
    pub spki: Vec<u8>,
    /// `/admin/pki`'s vocabulary: `rsa-2048`, `ec-p256`, `ml-dsa-44`.
    pub key_alg: String,
    /// `rsa`, `ec`, `okp` or `pqc`.
    pub key_kind: String,
    pub subject: String,
    pub common_name: String,
    pub challenge_password: String,
    pub attribute_types: Vec<String>,
    pub attestations: Vec<Vec<u8>>,
    pub requested: Requested,
}

fn unreadable() -> Refusal {
    Refusal::new(
        codes::STS_ENROLL_0030,
        400,
        "The certificate request is not a readable PKCS#10 CertificationRequest.",
    )
}

/// `keyAlgName(desc)`.
#[tracing::instrument(level = "trace")]
pub fn key_alg_name(desc: &KeyDesc) -> String {
    match desc {
        KeyDesc::Rsa { bits } => format!("rsa-{}", bits),
        KeyDesc::Ec { curve } => {
            format!("ec-{}", curve.replacen('-', "", 1).to_lowercase())
        }
        KeyDesc::Ed25519 => "ed25519".into(),
        KeyDesc::Pqc(id) => id.to_lowercase(),
    }
}

/// Whether a post-quantum key is a key-encapsulation key.
#[tracing::instrument(level = "trace")]
pub fn is_kem(desc: &KeyDesc) -> bool {
    match desc {
        KeyDesc::Pqc(id) => sts_crypto::pq_x509::alg(id)
            .is_some_and(|a| a.usage != sts_crypto::pq_x509::Use::Sig),
        _ => false,
    }
}

/// `ipText(raw)`: four octets dotted, sixteen as node writes them.
#[tracing::instrument(level = "trace")]
pub fn ip_text(raw: &[u8]) -> String {
    match raw.len() {
        4 => raw
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join("."),
        16 => {
            let groups: Vec<String> = raw
                .chunks(2)
                .map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]])))
                .collect();
            let joined = groups.join(":");
            // `/(^|:)0(:0)+(:|$)/` replaced by `::`, the first run only.
            normal_host_name(&compress_first_zero_run(&joined))
        }
        _ => "invalid-address".into(),
    }
}

fn compress_first_zero_run(joined: &str) -> String {
    let parts: Vec<&str> = joined.split(':').collect();
    let mut i = 0;
    while i < parts.len() {
        if parts[i] == "0" {
            let mut j = i;
            while j < parts.len() && parts[j] == "0" {
                j += 1;
            }
            if j - i >= 2 {
                let head = parts[..i].join(":");
                let tail = parts[j..].join(":");
                return format!("{}::{}", head, tail);
            }
            i = j;
        } else {
            i += 1;
        }
    }
    joined.to_string()
}

/// `readGeneralName(name, requested)`.
fn read_general_name(name: &Element<'_>, out: &mut Requested) {
    let number = name.tag & 0x1f;
    let latin = || {
        name.content
            .iter()
            .map(|&b| char::from(b))
            .collect::<String>()
    };
    match number {
        1 => out.emails.push(latin()),
        2 => out.dns.push(latin()),
        6 => out.uris.push(latin()),
        7 => out.ips.push(ip_text(name.content)),
        0 => {
            let parts = der::children(name.content).unwrap_or_default();
            let id = parts
                .first()
                .and_then(|o| der::oid_string(o.content))
                .unwrap_or_else(|| "unknown".into());
            if id == UPN_OID {
                let text = parts
                    .get(1)
                    .and_then(|explicit| der::read(explicit.content))
                    .map(|inner| der::string_value(&inner))
                    .unwrap_or_default();
                out.upns.push(text);
            } else {
                out.uris.push(format!("otherName:{}", id));
            }
        }
        other => out.uris.push(format!("generalName:{}", other)),
    }
}

struct Parts {
    tbs: Vec<u8>,
    subject: Vec<u8>,
    spki: Vec<u8>,
    attributes: Option<Vec<u8>>,
    sig_oid: String,
    sig_params: Vec<u8>,
    signature: Vec<u8>,
}

fn read_parts(bytes: &[u8]) -> Option<Parts> {
    let outer = der::read_whole(bytes)?;
    if outer.tag != der::SEQUENCE {
        return None;
    }
    let top = der::children(outer.content)?;
    if top.len() != 3 {
        return None;
    }
    let (info, alg, sig) = (&top[0], &top[1], &top[2]);
    if info.tag != der::SEQUENCE
        || alg.tag != der::SEQUENCE
        || sig.tag != der::BIT_STRING
    {
        return None;
    }
    let fields = der::children(info.content)?;
    if fields.len() < 3
        || fields[0].tag != der::INTEGER
        || fields[1].tag != der::SEQUENCE
    {
        return None;
    }
    if fields[2].tag != der::SEQUENCE {
        return None;
    }
    let attributes = match fields.get(3) {
        Some(a) if a.tag == 0xa0 => Some(a.content.to_vec()),
        Some(_) => return None,
        None => None,
    };
    let alg_parts = der::children(alg.content)?;
    let sig_oid = der::oid_string(alg_parts.first()?.content)?;
    let sig_params =
        alg_parts.get(1).map(|p| p.raw.to_vec()).unwrap_or_default();
    let signature = sig.content.get(1..)?.to_vec();
    Some(Parts {
        tbs: info.raw.to_vec(),
        subject: fields[1].raw.to_vec(),
        spki: fields[2].raw.to_vec(),
        attributes,
        sig_oid,
        sig_params,
        signature,
    })
}

fn pss_hash_oid(params: &[u8]) -> Option<String> {
    let seq = der::read(params)?;
    for item in der::children(seq.content)? {
        if item.tag == 0xa0 {
            let alg = der::read(item.content)?;
            let c = der::children(alg.content)?;
            return der::oid_string(c.first()?.content);
        }
    }
    Some("1.3.14.3.2.26".into())
}

/// The subject as pkijs's `typesAndValues` reads it: `oid=value` in the
/// encoded order, every attribute of every RDN; and the first CN.
#[tracing::instrument(level = "trace", skip_all)]
pub fn subject_text(name_der: &[u8]) -> Option<(String, String)> {
    let name = der::read(name_der)?;
    let mut parts = Vec::new();
    let mut cn = String::new();
    for rdn in der::children(name.content)? {
        for atv in der::children(rdn.content)? {
            let f = der::children(atv.content)?;
            let oid = der::oid_string(f.first()?.content)?;
            let value = f.get(1).map(der::string_value).unwrap_or_default();
            if oid == "2.5.4.3" && cn.is_empty() {
                cn = value.clone();
            }
            parts.push(format!("{}={}", oid, value));
        }
    }
    Some((parts.join(","), cn))
}

impl Core {
    /// `pki.csrProofOfPossession()`.
    fn proof_of_possession(&self, parts: &Parts) -> bool {
        let accepted = sts_pki::path::accept::parse_list(
            &self.setting_text("pki.acceptedSignatureAlgorithms"),
        );
        let hash = pss_hash_oid(&parts.sig_params)
            .and_then(|o| sts_pki::x509::algorithms::Hash::from_oid(&o))
            .map(|h| h.name().to_lowercase().replace('-', ""))
            .unwrap_or_default();
        if let Some(cause) = sts_pki::path::accept::accept_x509_cause(
            &parts.sig_oid,
            if parts.sig_oid == "1.2.840.113549.1.1.10" {
                &hash
            } else {
                ""
            },
            &accepted,
        ) {
            tracing::warn!(
                "{}{}",
                sts_core::log::tag(sts_pki::path::accept::ACCEPT_CODE.as_str()),
                cause
            );
            return false;
        }
        let pss_hash = (parts.sig_oid == "1.2.840.113549.1.1.10")
            .then(|| pss_hash_oid(&parts.sig_params))
            .flatten();
        let Some(sig) = sts_pki::x509::algorithms::sig_alg_for_oid(
            &parts.sig_oid,
            pss_hash.as_deref(),
        ) else {
            return false;
        };
        sts_pki::x509::read::verify_bytes(
            &sig,
            &parts.spki,
            &parts.signature,
            &parts.tbs,
        )
    }

    /// `parseCsr(bytes, { template })`.
    #[tracing::instrument(level = "debug", skip(self, bytes))]
    pub fn parse_csr(&self, bytes: &[u8], template: bool) -> Outcome<Csr> {
        if bytes.is_empty() {
            return Err(Refusal::new(
                codes::STS_ENROLL_0030,
                400,
                "The certificate request is empty.",
            ));
        }
        let parts = read_parts(bytes).ok_or_else(unreadable)?;
        let Some(desc) = describe_spki(&parts.spki) else {
            return Err(Refusal::new(
                codes::STS_ENROLL_0031,
                400,
                "The public key in the request is not one this certificate authority can \
                 certify.",
            ));
        };
        let kem = is_kem(&desc);
        if kem && !template {
            let name = desc.pqc().unwrap_or("key-encapsulation");
            return Err(Refusal::new(
                codes::STS_ENROLL_0032,
                400,
                format!(
                    "The request carries a {} key, which cannot sign and so cannot prove \
                     possession (RFC 9935 section 7). Ask EST /serverkeygen for one instead.",
                    name
                ),
            ));
        }
        if !kem && !self.proof_of_possession(&parts) {
            return Err(Refusal::new(
                codes::STS_ENROLL_0033,
                400,
                "The certificate request's signature does not verify with the public key it \
                 carries, so it does not prove possession of that key.",
            ));
        }
        let mut out = Csr {
            der: bytes.to_vec(),
            public_key_pem: der_to_pem(&parts.spki, "PUBLIC KEY"),
            spki: parts.spki.clone(),
            key_alg: key_alg_name(&desc),
            key_kind: desc.kind().to_string(),
            ..Default::default()
        };
        let attribute_refusal = || {
            Refusal::new(
                codes::STS_ENROLL_0034,
                400,
                "The certificate request's subject or requested extensions could not be read.",
            )
        };
        let (subject, cn) =
            subject_text(&parts.subject).ok_or_else(attribute_refusal)?;
        out.subject = subject;
        out.common_name = cn;
        if let Some(attributes) = &parts.attributes {
            for attribute in
                der::children(attributes).ok_or_else(attribute_refusal)?
            {
                let f = der::children(attribute.content)
                    .ok_or_else(attribute_refusal)?;
                let oid = f
                    .first()
                    .and_then(|o| der::oid_string(o.content))
                    .ok_or_else(attribute_refusal)?;
                let values = f
                    .get(1)
                    .and_then(|s| der::children(s.content))
                    .unwrap_or_default();
                out.attribute_types.push(oid.clone());
                if oid == ATTESTATION_OID {
                    out.attestations
                        .extend(values.iter().map(|v| v.raw.to_vec()));
                }
                if oid == CHALLENGE_PASSWORD_OID {
                    out.challenge_password = values
                        .first()
                        .map(der::string_value)
                        .unwrap_or_default();
                }
                if oid == EXTENSION_REQUEST_OID {
                    let list = values.first().ok_or_else(attribute_refusal)?;
                    for ext in der::children(list.content)
                        .ok_or_else(attribute_refusal)?
                    {
                        let e = der::children(ext.content)
                            .ok_or_else(attribute_refusal)?;
                        let id =
                            e.first().and_then(|o| der::oid_string(o.content));
                        if id.as_deref() != Some(SUBJECT_ALT_NAME_OID) {
                            continue;
                        }
                        let value = e.last().ok_or_else(attribute_refusal)?;
                        let names = der::read(value.content)
                            .ok_or_else(attribute_refusal)?;
                        for name in der::children(names.content)
                            .ok_or_else(attribute_refusal)?
                        {
                            read_general_name(&name, &mut out.requested);
                        }
                    }
                }
            }
        }
        Ok(out)
    }
}
