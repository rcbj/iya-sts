// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Reading a certificate back, describing it, and checking a chain
//! (`x509.js`'s "Reading one back").
//!
//! The describer covers the extensions the builder writes, which is what
//! makes the pair testable, and reports one it does not know by OID with
//! its bytes rather than skipping it. A chain is checked link by link and
//! every link is reported — "the chain is broken" is not an answer anybody
//! can act on — with the alternative signature of a hybrid certificate
//! reported BESIDE the conventional one and never folded into it.

use chrono::{DateTime, Utc};
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::{hash, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Padding;
use openssl::sign::{RsaPssSaltlen, Verifier};
use serde_json::{json, Map, Value as Json};
use sts_crypto::pq_x509;

use super::algorithms::{self, Hash, SigAlg, SigKind, ED25519_OID};
use super::extensions::{self as ext, KEY_USAGE_BITS, NS_CERT_TYPE_BITS};
use super::keys::{self, KeyDesc};
use super::names;
use super::time;
use crate::der::{self, Element};
use crate::error::{PkiError, PkiResult};

/// One extension as it sits in a certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extension {
    pub oid: String,
    pub critical: bool,
    /// The OCTET STRING's content.
    pub value: Vec<u8>,
}

/// A certificate taken apart, every part kept as the bytes it was.
#[derive(Clone, Debug)]
pub struct Certificate {
    pub der: Vec<u8>,
    /// The TBSCertificate's whole encoding: what the signature covers.
    pub tbs: Vec<u8>,
    /// The `version` field (2 for v3).
    pub version: i64,
    /// The serial INTEGER's content octets, as they are.
    pub serial: Vec<u8>,
    pub issuer_der: Vec<u8>,
    pub subject_der: Vec<u8>,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub spki: Vec<u8>,
    pub extensions: Vec<Extension>,
    /// The outer signatureAlgorithm's OID, and a PSS one's hash OID.
    pub signature_oid: String,
    pub signature_params: Vec<u8>,
    /// The signature BIT STRING's bits.
    pub signature: Vec<u8>,
}

fn bad(what: &str) -> PkiError {
    PkiError::new(format!(
        "Object's schema was not verified against input data for {}",
        what
    ))
}

impl Certificate {
    pub fn from_der(input: &[u8]) -> PkiResult<Certificate> {
        let outer = der::read(input).ok_or_else(|| bad("Certificate"))?;
        let top =
            der::children(outer.content).ok_or_else(|| bad("Certificate"))?;
        if top.len() < 3 {
            return Err(bad("Certificate"));
        }
        let tbs = &top[0];
        let mut fields = der::children(tbs.content)
            .ok_or_else(|| bad("Certificate"))?
            .into_iter()
            .peekable();
        let mut version = 0;
        if fields.peek().is_some_and(|f| f.tag == 0xa0) {
            let v = fields.next().ok_or_else(|| bad("Certificate"))?;
            version = der::read(v.content)
                .and_then(|i| der::integer_value(i.content))
                .unwrap_or(0);
        }
        let mut next = || fields.next().ok_or_else(|| bad("Certificate"));
        let serial = next()?.content.to_vec();
        let _signature = next()?;
        let issuer = next()?.raw.to_vec();
        let validity = next()?;
        let subject = next()?.raw.to_vec();
        let spki = next()?.raw.to_vec();
        let times = der::children(validity.content)
            .ok_or_else(|| bad("Certificate"))?;
        let read_time = |i: usize| {
            times
                .get(i)
                .and_then(time::read_time)
                .ok_or_else(|| bad("Certificate"))
        };
        let (not_before, not_after) = (read_time(0)?, read_time(1)?);
        let mut extensions = Vec::new();
        for f in fields {
            if f.tag != 0xa3 {
                continue;
            }
            let holder =
                der::read(f.content).ok_or_else(|| bad("Certificate"))?;
            for e in der::children(holder.content).unwrap_or_default() {
                let parts = der::children(e.content).unwrap_or_default();
                let oid = parts
                    .first()
                    .and_then(|p| der::oid_string(p.content))
                    .unwrap_or_default();
                let critical = parts
                    .get(1)
                    .is_some_and(|p| p.tag == der::BOOLEAN && p.content != [0]);
                let value = parts
                    .last()
                    .filter(|p| p.tag == der::OCTET_STRING)
                    .map(|p| p.content.to_vec())
                    .unwrap_or_default();
                extensions.push(Extension {
                    oid,
                    critical,
                    value,
                });
            }
        }
        let alg =
            der::children(top[1].content).ok_or_else(|| bad("Certificate"))?;
        let signature_oid = alg
            .first()
            .and_then(|a| der::oid_string(a.content))
            .unwrap_or_default();
        let signature_params =
            alg.get(1).map(|p| p.raw.to_vec()).unwrap_or_default();
        let signature = top[2].content.get(1..).unwrap_or_default().to_vec();
        Ok(Certificate {
            der: outer.raw.to_vec(),
            tbs: tbs.raw.to_vec(),
            version,
            serial,
            issuer_der: issuer,
            subject_der: subject,
            not_before,
            not_after,
            spki,
            extensions,
            signature_oid,
            signature_params,
            signature,
        })
    }

    pub fn from_pem(pem: &str) -> PkiResult<Certificate> {
        Certificate::from_der(&keys::pem_to_der(pem)?)
    }

    pub fn subject(&self) -> String {
        der::read(&self.subject_der)
            .map(|e| names::dn_to_string(&e))
            .unwrap_or_default()
    }

    pub fn issuer(&self) -> String {
        der::read(&self.issuer_der)
            .map(|e| names::dn_to_string(&e))
            .unwrap_or_default()
    }

    pub fn extension(&self, oid: &str) -> Option<&Extension> {
        self.extensions.iter().find(|e| e.oid == oid)
    }

    /// The hash OID inside a PSS AlgorithmIdentifier's parameters.
    fn pss_hash_oid(&self) -> Option<String> {
        pss_params(&self.signature_params)
            .0
            .map(|h| h.oid().to_string())
    }
}

/// A PSS parameter block's hash (SHA-1 when absent, as its DEFAULT) and
/// salt length (20 when absent).
fn pss_params(params: &[u8]) -> (Option<Hash>, usize) {
    let mut hash_alg = Some(Hash::Sha1);
    let mut salt = 20;
    let Some(seq) = der::read(params) else {
        return (hash_alg, salt);
    };
    for item in der::children(seq.content).unwrap_or_default() {
        match item.tag {
            0xa0 => {
                hash_alg = der::read(item.content)
                    .and_then(|a| der::children(a.content))
                    .and_then(|c| {
                        c.first().and_then(|o| der::oid_string(o.content))
                    })
                    .and_then(|o| Hash::from_oid(&o));
            }
            0xa2 => {
                salt = der::read(item.content)
                    .and_then(|i| der::integer_value(i.content))
                    .unwrap_or(20) as usize;
            }
            _ => {}
        }
    }
    (hash_alg, salt)
}

/// `ecdsaDerToRaw()` and back: the (r, s) of an Ecdsa-Sig-Value however it
/// was encoded, so a verifier reads what pkijs reads.
fn ecdsa_pair(sig: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let seq = der::read(sig)?;
    let parts = der::children(seq.content)?;
    if parts.len() != 2 || parts.iter().any(|p| p.tag != der::INTEGER) {
        return None;
    }
    Some((parts[0].content.to_vec(), parts[1].content.to_vec()))
}

/// The signature re-encoded minimally (`minimalEcdsaSignature()`), for
/// OpenSSL, which refuses anything else.
pub fn minimal_ecdsa_signature(sig: &[u8]) -> Vec<u8> {
    let Some((r, s)) = ecdsa_pair(sig) else {
        return sig.to_vec();
    };
    let (Ok(r), Ok(s)) = (BigNum::from_slice(&r), BigNum::from_slice(&s))
    else {
        return sig.to_vec();
    };
    EcdsaSig::from_private_components(r, s)
        .and_then(|e| e.to_der())
        .unwrap_or_else(|_| sig.to_vec())
}

/// `verifyBytes()`: one signature under an SPKI with a row's scheme.
pub fn verify_bytes(
    sig: &SigAlg,
    spki: &[u8],
    signature: &[u8],
    data: &[u8],
) -> bool {
    if let SigKind::Pqc(id) = sig.kind {
        return match pq_x509::decode_spki(spki) {
            Some((alg, public)) if alg.id == id => {
                pq_x509::verify(id, signature, data, &public).unwrap_or(false)
            }
            _ => false,
        };
    }
    let Ok(key) = PKey::public_key_from_der(spki) else {
        return false;
    };
    let attempt = || -> PkiResult<bool> {
        Ok(match sig.kind {
            SigKind::Ed25519 => {
                let mut v = Verifier::new_without_digest(&key)?;
                v.verify_oneshot(signature, data)?
            }
            SigKind::Ec { hash } => {
                // Web Crypto's three curves and no other: pkijs verifies
                // there, so a P-192 or secp256k1 certificate signature is
                // refused as it is in Node (x509-limbo
                // `webpki::forbidden-p192-root`).
                let curve =
                    key.ec_key().ok().and_then(|k| k.group().curve_name());
                if !matches!(
                    curve,
                    Some(
                        Nid::X9_62_PRIME256V1 | Nid::SECP384R1 | Nid::SECP521R1
                    )
                ) {
                    return Ok(false);
                }
                let mut v = Verifier::new(hash.digest(), &key)?;
                v.verify_oneshot(&minimal_ecdsa_signature(signature), data)?
            }
            SigKind::Rsa { hash, pss } => {
                let mut v = Verifier::new(hash.digest(), &key)?;
                if pss {
                    v.set_rsa_padding(Padding::PKCS1_PSS)?;
                    v.set_rsa_mgf1_md(hash.digest())?;
                    v.set_rsa_pss_saltlen(RsaPssSaltlen::custom(
                        hash.digest_len() as i32,
                    ))?;
                }
                v.verify_oneshot(signature, data)?
            }
            SigKind::Pqc(_) => false,
        })
    };
    attempt().unwrap_or(false)
}

/// `verifySignature()`: the certificate's signature under the issuer's key,
/// with the scheme its signatureAlgorithm names (a PSS salt read from the
/// parameters, as pkijs reads it).
pub fn verify_signature(
    cert: &Certificate,
    issuer: &Certificate,
) -> PkiResult<bool> {
    if pq_x509::alg_for_oid(&cert.signature_oid).is_some()
        || cert.signature_oid == ED25519_OID
    {
        let sig = algorithms::sig_alg_for_oid(&cert.signature_oid, None)
            .ok_or_else(|| PkiError::new("Unsupported signature algorithm"))?;
        return Ok(verify_bytes(
            &sig,
            &issuer.spki,
            &cert.signature,
            &cert.tbs,
        ));
    }
    let hash_oid = cert.pss_hash_oid();
    let sig =
        algorithms::sig_alg_for_oid(&cert.signature_oid, hash_oid.as_deref())
            .ok_or_else(|| {
            PkiError::new(format!(
                "Unsupported signature algorithm: {}",
                cert.signature_oid
            ))
        })?;
    if let SigKind::Rsa { hash, pss: true } = sig.kind {
        let (_, salt) = pss_params(&cert.signature_params);
        let key = PKey::public_key_from_der(&issuer.spki)?;
        let mut v = Verifier::new(hash.digest(), &key)?;
        v.set_rsa_padding(Padding::PKCS1_PSS)?;
        v.set_rsa_mgf1_md(hash.digest())?;
        v.set_rsa_pss_saltlen(RsaPssSaltlen::custom(salt as i32))?;
        return Ok(v
            .verify_oneshot(&cert.signature, &cert.tbs)
            .unwrap_or(false));
    }
    Ok(verify_bytes(&sig, &issuer.spki, &cert.signature, &cert.tbs))
}

/// The hybrid trio read back: the alternative public key's SPKI, the
/// alternative algorithm's OID, the alternative signature.
#[derive(Clone, Debug, Default)]
pub struct AlternativeParts {
    pub alt_public_key: Option<Vec<u8>>,
    pub alt_algorithm_oid: Option<String>,
    pub alt_signature: Option<Vec<u8>>,
}

pub fn alternative_parts(cert: &Certificate) -> AlternativeParts {
    let mut out = AlternativeParts::default();
    for e in &cert.extensions {
        match e.oid.as_str() {
            ext::SUBJECT_ALT_PUBLIC_KEY_INFO => {
                out.alt_public_key = Some(e.value.clone())
            }
            ext::ALT_SIGNATURE_ALGORITHM => {
                out.alt_algorithm_oid = der::read(&e.value)
                    .and_then(|a| der::children(a.content))
                    .and_then(|c| {
                        c.first().and_then(|o| der::oid_string(o.content))
                    });
            }
            ext::ALT_SIGNATURE_VALUE => {
                out.alt_signature = der::read(&e.value)
                    .map(|b| b.content.get(1..).unwrap_or_default().to_vec());
            }
            _ => {}
        }
    }
    out
}

/// `preTbsFromTbs()`: the TBSCertificate without its `signature` field and
/// without the altSignatureValue extension — what an alternative signature
/// covers.
pub fn pre_tbs_from_tbs(tbs: &[u8]) -> PkiResult<Vec<u8>> {
    let unparseable =
        || PkiError::new("This certificate's TBSCertificate does not parse.");
    let seq = der::read(tbs).ok_or_else(unparseable)?;
    let mut items: Vec<Vec<u8>> = Vec::new();
    let children = der::children(seq.content).ok_or_else(unparseable)?;
    let signature_index = if children.first().is_some_and(|c| c.tag == 0xa0) {
        2
    } else {
        1
    };
    for (i, item) in children.iter().enumerate() {
        if i == signature_index {
            continue;
        }
        if item.tag == 0xa3 {
            let kept: Vec<Vec<u8>> = der::read(item.content)
                .and_then(|h| der::children(h.content))
                .unwrap_or_default()
                .into_iter()
                .filter(|e| {
                    der::children(e.content)
                        .and_then(|p| {
                            p.first().and_then(|o| der::oid_string(o.content))
                        })
                        .as_deref()
                        != Some(ext::ALT_SIGNATURE_VALUE)
                })
                .map(|e| e.raw.to_vec())
                .collect();
            items.push(der::context(3, true, &der::sequence(&kept)));
        } else {
            items.push(item.raw.to_vec());
        }
    }
    Ok(der::sequence(&items))
}

/// `verifyAlternativeSignature()`: a verdict, because "there is none" and
/// "it is wrong" are different answers.
pub fn verify_alternative_signature(
    cert: &Certificate,
    issuer: &Certificate,
) -> PkiResult<Json> {
    let parts = alternative_parts(cert);
    let (Some(signature), Some(oid)) =
        (parts.alt_signature, parts.alt_algorithm_oid)
    else {
        return Ok(json!({ "present": false, "valid": null,
            "reason": "This certificate carries no alternative signature." }));
    };
    let Some(alt_key) = alternative_parts(issuer).alt_public_key else {
        return Ok(
            json!({ "present": true, "valid": null, "algorithmOid": oid,
            "reason": "The issuer's certificate carries no subjectAltPublicKeyInfo, so there is no key to check this alternative signature with. A hybrid chain has to be hybrid the whole way up." }),
        );
    };
    let Some(alg) = algorithms::sig_alg_for_oid(&oid, None) else {
        return Ok(
            json!({ "present": true, "valid": null, "algorithmOid": oid,
            "reason": format!("This build does not know the alternative signature algorithm {}.", oid) }),
        );
    };
    let pre_tbs = pre_tbs_from_tbs(&cert.tbs)?;
    let ok = verify_bytes(&alg, &alt_key, &signature, &pre_tbs);
    Ok(
        json!({ "present": true, "valid": ok, "algorithm": alg.id, "algorithmOid": oid }),
    )
}

/// The named bits set in a BIT STRING.
fn bits_set(
    bits: &Element<'_>,
    table: &[(&'static str, u8)],
) -> Vec<&'static str> {
    let view = bits.content.get(1..).unwrap_or_default();
    table
        .iter()
        .filter(|(_, bit)| {
            let byte = usize::from(bit / 8);
            byte < view.len() && view[byte] & (0x80 >> (bit % 8)) != 0
        })
        .map(|(name, _)| *name)
        .collect()
}

/// `keyUsageOf()`: `present` beside the list, because an absent KeyUsage
/// permits everything and a present empty one permits nothing.
pub fn key_usage_of(cert: &Certificate) -> Json {
    if let Some(e) = cert.extension(ext::KEY_USAGE) {
        if let Some(bits) = der::read(&e.value) {
            return json!({ "present": true, "critical": e.critical,
                           "usages": bits_set(&bits, KEY_USAGE_BITS) });
        }
    }
    json!({ "present": false, "critical": false, "usages": [] })
}

/// `keyUsagePermits()`.
pub fn key_usage_permits(key_usage: &Json, usage: &str) -> bool {
    if !key_usage
        .get("present")
        .and_then(Json::as_bool)
        .unwrap_or(false)
    {
        return true;
    }
    key_usage
        .get("usages")
        .and_then(Json::as_array)
        .is_some_and(|u| u.iter().any(|x| x == usage))
}

fn general_names(content: &[u8]) -> Vec<String> {
    der::children(content)
        .unwrap_or_default()
        .iter()
        .map(names::describe_general_name)
        .collect()
}

fn sig_oid_name(oid: &str) -> String {
    let classical = match oid {
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.113549.1.1.10" => "rsassaPss",
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        ED25519_OID => "Ed25519",
        _ => "",
    };
    if !classical.is_empty() {
        return classical.to_string();
    }
    match pq_x509::alg_for_oid(oid) {
        Some(a) if a.usage == pq_x509::Use::Sig => a.name.to_string(),
        _ => oid.to_string(),
    }
}

fn pubkey_oid_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.1" => "rsaEncryption".to_string(),
        "1.2.840.10045.2.1" => "id-ecPublicKey".to_string(),
        ED25519_OID => "Ed25519".to_string(),
        _ => pq_x509::alg_for_oid(oid)
            .map_or(oid.to_string(), |a| a.name.to_string()),
    }
}

fn spki_algorithm_oid(spki: &[u8]) -> String {
    der::read(spki)
        .and_then(|s| der::children(s.content))
        .and_then(|c| c.first().and_then(|a| der::children(a.content)))
        .and_then(|a| a.first().and_then(|o| der::oid_string(o.content)))
        .unwrap_or_default()
}

/// `describeExtension()`.
pub fn describe_extension(e: &Extension) -> Json {
    let name = ext::ext_name(&e.oid).map_or(e.oid.clone(), str::to_string);
    let mut out = Map::new();
    out.insert("oid".into(), json!(e.oid));
    out.insert("name".into(), json!(name));
    out.insert("critical".into(), json!(e.critical));
    let value = describe_extension_value(&name, &e.value);
    out.insert(
        "value".into(),
        value.unwrap_or_else(|| json!(der::hex(&e.value))),
    );
    Json::Object(out)
}

fn describe_extension_value(name: &str, value: &[u8]) -> Option<Json> {
    let asn1 = der::read(value)?;
    let kids = || der::children(asn1.content).unwrap_or_default();
    Some(match name {
        "basicConstraints" => {
            let k = kids();
            let ca =
                k.iter().any(|p| p.tag == der::BOOLEAN && p.content != [0]);
            let path_len = k
                .iter()
                .find(|p| p.tag == der::INTEGER)
                .and_then(|p| der::integer_value(p.content));
            json!({ "ca": ca, "pathLen": path_len })
        }
        "keyUsage" => json!(bits_set(&asn1, KEY_USAGE_BITS)),
        "netscapeCertType" => json!(bits_set(&asn1, NS_CERT_TYPE_BITS)),
        "extKeyUsage" => json!(kids()
            .iter()
            .map(|o| {
                let oid = der::oid_string(o.content).unwrap_or_default();
                ext::eku_name(&oid).map_or(oid, str::to_string)
            })
            .collect::<Vec<_>>()),
        "subjectAltName" | "issuerAltName" => {
            json!(general_names(asn1.content))
        }
        "subjectAltPublicKeyInfo" => {
            let oid = spki_algorithm_oid(asn1.raw);
            let bits = kids()
                .get(1)
                .map_or(0, |b| b.content.len().saturating_sub(1));
            json!({ "algorithm": pubkey_oid_name(&oid), "oid": oid, "bytes": bits })
        }
        "altSignatureAlgorithm" => {
            let oid = kids()
                .first()
                .and_then(|o| der::oid_string(o.content))
                .unwrap_or_default();
            json!({ "algorithm": sig_oid_name(&oid), "oid": oid })
        }
        "altSignatureValue" => {
            let sig = asn1.content.get(1..).unwrap_or_default();
            json!({ "bytes": sig.len(), "starts": der::hex(&sig[..sig.len().min(16)]) })
        }
        "subjectKeyIdentifier" => json!(der::hex(asn1.content)),
        "authorityKeyIdentifier" => {
            let k = kids();
            let field =
                |n: u32| k.iter().find(|p| p.class == 2 && p.number == n);
            json!({
                "keyIdentifier": field(0).map(|p| der::hex(p.content)),
                "issuer": field(1).map(|p| general_names_of(p.content)),
                "serial": field(2).map(|p| der::hex(p.content)),
            })
        }
        "cRLDistributionPoints" | "freshestCRL" => json!(kids()
            .iter()
            .map(|point| {
                der::children(point.content)
                    .unwrap_or_default()
                    .iter()
                    .find(|p| p.class == 2 && p.number == 0)
                    .and_then(|dp| der::read(dp.content))
                    .filter(|full| full.class == 2 && full.number == 0)
                    .map(|full| general_names_of(full.content).join(", "))
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>()),
        "authorityInfoAccess" | "subjectInfoAccess" => json!(kids()
            .iter()
            .map(|access| {
                let p = der::children(access.content).unwrap_or_default();
                let method = p
                    .first()
                    .and_then(|o| der::oid_string(o.content))
                    .unwrap_or_default();
                let label =
                    ext::aia_name(&method).map_or(method, str::to_string);
                let location = p
                    .get(1)
                    .map(names::describe_general_name)
                    .unwrap_or_default();
                format!("{}: {}", label, location)
            })
            .collect::<Vec<_>>()),
        "certificatePolicies" => json!(kids()
            .iter()
            .map(|info| {
                let p = der::children(info.content).unwrap_or_default();
                let oid = p
                    .first()
                    .and_then(|o| der::oid_string(o.content))
                    .unwrap_or_default();
                let qualifiers = p
                    .get(1)
                    .and_then(|q| der::children(q.content))
                    .map_or(0, |q| q.len());
                json!({ "oid": oid, "qualifiers": qualifiers })
            })
            .collect::<Vec<_>>()),
        "policyMappings" => json!(kids()
            .iter()
            .map(|m| {
                let p = der::children(m.content).unwrap_or_default();
                let oid = |i: usize| {
                    p.get(i)
                        .and_then(|o| der::oid_string(o.content))
                        .unwrap_or_default()
                };
                format!("{} -> {}", oid(0), oid(1))
            })
            .collect::<Vec<_>>()),
        "policyConstraints" => {
            let k = kids();
            let field = |n: u32| {
                k.iter()
                    .find(|p| p.class == 2 && p.number == n)
                    .and_then(|p| der::integer_value(p.content))
            };
            let mut m = Map::new();
            if let Some(v) = field(0) {
                m.insert("requireExplicitPolicy".into(), json!(v));
            }
            if let Some(v) = field(1) {
                m.insert("inhibitPolicyMapping".into(), json!(v));
            }
            Json::Object(m)
        }
        "nameConstraints" => {
            let k = kids();
            let trees = |n: u32| -> Vec<String> {
                k.iter()
                    .find(|p| p.class == 2 && p.number == n)
                    .map(|p| {
                        der::children(p.content)
                            .unwrap_or_default()
                            .iter()
                            .filter_map(|t| {
                                der::children(t.content).and_then(|c| {
                                    c.first().map(names::describe_general_name)
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            };
            json!({ "permitted": trees(0), "excluded": trees(1) })
        }
        "inhibitAnyPolicy" => json!(der::integer_value(asn1.content)),
        "ocspNoCheck" => json!("present"),
        "netscapeComment" => json!(der::string_value(&asn1)),
        "tlsFeature" => json!(kids()
            .iter()
            .filter_map(|v| der::integer_value(v.content))
            .collect::<Vec<_>>()),
        _ => return None,
    })
}

fn general_names_of(content: &[u8]) -> Vec<String> {
    general_names(content)
}

fn colon_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// What `describeCertificate()` says of a public key. Node says "Ed25519"
/// of a post-quantum key (its describer's kind is `pqc`, which the ternary
/// does not name); this says the algorithm.
fn public_key_text(spki: &[u8], fallback: &str) -> String {
    match keys::describe_spki(spki) {
        Some(KeyDesc::Rsa { bits }) => format!("RSA {}-bit", bits),
        Some(KeyDesc::Ec { curve }) => format!("ECDSA {}", curve),
        Some(KeyDesc::Ed25519) => "Ed25519".to_string(),
        Some(KeyDesc::Pqc(id)) => {
            pq_x509::alg(id).map_or(id.to_string(), |a| a.name.to_string())
        }
        None => fallback.to_string(),
    }
}

/// `describeCertificate()`.
pub fn describe_certificate(cert: &Certificate) -> PkiResult<Json> {
    let key_oid = spki_algorithm_oid(&cert.spki);
    let public_key_algorithm = pubkey_oid_name(&key_oid);
    Ok(json!({
        "version": cert.version + 1,
        "serialHex": der::hex(&cert.serial),
        "subject": cert.subject(),
        "issuer": cert.issuer(),
        "notBefore": time::iso(&cert.not_before),
        "notAfter": time::iso(&cert.not_after),
        "signatureAlgorithm": sig_oid_name(&cert.signature_oid),
        "signatureAlgorithmOid": cert.signature_oid,
        "publicKeyAlgorithm": public_key_algorithm,
        "selfSigned": cert.subject() == cert.issuer(),
        "extensions": cert.extensions.iter().map(describe_extension).collect::<Vec<_>>(),
        "fingerprints": {
            "sha1": colon_hex(&hash(MessageDigest::sha1(), &cert.der)?),
            "sha256": colon_hex(&hash(MessageDigest::sha256(), &cert.der)?),
        },
        "publicKey": public_key_text(&cert.spki, &public_key_algorithm),
    }))
}

/// `verifyChain()`: each certificate under the next, the last under
/// itself, every link reported.
pub fn verify_chain(pems: &[&str]) -> PkiResult<Vec<Json>> {
    let certs: Vec<Certificate> = pems
        .iter()
        .map(|p| Certificate::from_pem(p))
        .collect::<PkiResult<_>>()?;
    let now = Utc::now();
    let mut out = Vec::new();
    for (i, cert) in certs.iter().enumerate() {
        let issuer = certs.get(i + 1).unwrap_or(cert);
        let mut link = Map::new();
        link.insert("subject".into(), json!(cert.subject()));
        link.insert("issuer".into(), json!(cert.issuer()));
        link.insert("signedBy".into(), json!(issuer.subject()));
        link.insert(
            "namesMatch".into(),
            json!(cert.issuer() == issuer.subject()),
        );
        link.insert("selfSigned".into(), json!(certs.get(i + 1).is_none()));
        let verdict = verify_signature(cert, issuer);
        link.insert(
            "signatureValid".into(),
            json!(verdict.as_ref().is_ok_and(|ok| *ok)),
        );
        link.insert("keyUsage".into(), key_usage_of(cert));
        if let Err(e) = verdict {
            link.insert("error".into(), json!(e.0));
        }
        let alternative = verify_alternative_signature(cert, issuer)
            .unwrap_or_else(
                |e| json!({ "present": true, "valid": null, "reason": e.0 }),
            );
        link.insert("alternative".into(), alternative);
        link.insert("expired".into(), json!(cert.not_after < now));
        link.insert("notYetValid".into(), json!(cert.not_before > now));
        out.push(Json::Object(link));
    }
    Ok(out)
}
