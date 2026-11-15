// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `pki_revocation.js`'s CRL (RFC 5280 section 5): `signNewCrl()`,
//! `revokedEntryOf()`, `crlNumberAt()`, `serialBytes()`, `signCrl()`.
//!
//! Written as pkijs writes it — `version` v2, the AlgorithmIdentifier
//! pkijs's `getSignatureParameters()` chooses (the one a certificate
//! carries, so [`algorithms::certificate_signature_identifier`]), the
//! issuer's Name as its certificate holds it, the times UTCTime before 2050,
//! an entry's reason code only when it is not `unspecified` (RFC 5280 says
//! it SHOULD then be omitted), and two list extensions: the CRL number and
//! the authority key identifier (the issuer's own subject key identifier,
//! or SHA-1 of its key). So a list signed here with an RSA key over the
//! same entries at the same moment is Node's byte for byte
//! (`tests/pki_authority_vectors.rs`).
//!
//! **Built on demand, never cached**, as Node's is: a cached list would
//! go on claiming a freshness window it no longer has. The number is the
//! signing moment in milliseconds, never less than one more than the last
//! this process signed, so it only goes up.

use chrono::{DateTime, Utc};
use openssl::sha::sha1;
use serde_json::Value as Json;
use sts_core::errors::codes;
use sts_core::log::tag;

use super::catalog::{key_alg, scope_id};
use super::hierarchy::{certificate_instant, ms_of, Authority, Refusal};
use super::merge::normal_serial;
use crate::der;
use crate::error::{PkiError, PkiResult};
use crate::x509::algorithms::{self, Hash, SigAlg, SigKind};
use crate::x509::issue::sign_bytes;
use crate::x509::keys::SigningKey;
use crate::x509::read::Certificate;
use crate::x509::time;

/// A signed list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Crl {
    pub der: Vec<u8>,
    pub count: usize,
    pub crl_number: i64,
    pub this_update: String,
    pub next_update: String,
}

/// `signingParamsFor()` and `engineSigAlgOf()`: the algorithm a CA signs a
/// CRL or an OCSP response with — its key's own for Ed25519 and the
/// post-quantum keys, otherwise its key's family with the digest (and
/// PSS) of the algorithm its certificate was signed with.
#[tracing::instrument(level = "debug", skip_all)]
pub fn status_signature_alg(tier: &Json) -> PkiResult<SigAlg> {
    let key = tier.get("keyAlg").and_then(Json::as_str).unwrap_or("");
    if let Some(own) = algorithms::sig_alg(key) {
        if matches!(own.kind, SigKind::Pqc(_) | SigKind::Ed25519) {
            return Ok(own);
        }
    }
    let signed = tier
        .get("signatureAlg")
        .and_then(Json::as_str)
        .and_then(algorithms::sig_alg);
    let (hash, pss) = match signed.map(|s| s.kind) {
        Some(SigKind::Rsa { hash, pss }) => (hash, pss),
        Some(SigKind::Ec { hash }) => (hash, false),
        _ => (Hash::Sha256, false),
    };
    let prefix = match hash {
        Hash::Sha1 => "sha1",
        Hash::Sha256 => "sha256",
        Hash::Sha384 => "sha384",
        Hash::Sha512 => "sha512",
    };
    let kind = key_alg(key).map_or("rsa", |d| d.kind);
    let id = match kind {
        "ec" => format!("{}-ecdsa", prefix),
        "okp" => "ed25519".to_string(),
        _ if pss => format!("{}-rsapss", prefix),
        _ => format!("{}-rsa", prefix),
    };
    algorithms::sig_alg(&id).ok_or_else(|| {
        PkiError::new(format!("Unsupported signature algorithm: {}", id))
    })
}

/// `serialBytes()`: an INTEGER's content for a hex serial, a zero octet in
/// front of one that would read negative.
#[tracing::instrument(level = "debug")]
pub fn serial_bytes(serial_hex: &str) -> Vec<u8> {
    let mut hex = normal_serial(serial_hex);
    if hex.len() % 2 == 1 {
        hex.insert(0, '0');
    }
    let mut bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect();
    if bytes.first().is_some_and(|b| b & 0x80 != 0) {
        bytes.insert(0, 0);
    }
    bytes
}

/// `crlTime()`: whole seconds, UTCTime before 2050.
fn crl_time(t: &DateTime<Utc>) -> Vec<u8> {
    time::validity_time(&certificate_instant(Some(t.timestamp_millis())))
}

/// An Extension as pkijs writes it: the BOOLEAN only when critical.
#[tracing::instrument(level = "debug", skip_all)]
pub(super) fn extension(
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

/// The issuer's key identifier: its own subject key identifier, or SHA-1
/// of its public key's bits.
#[tracing::instrument(level = "debug", skip_all)]
pub(super) fn key_identifier(issuer: &Certificate) -> Vec<u8> {
    if let Some(ski) = issuer.extension("2.5.29.14") {
        if let Some(e) = der::read(&ski.value) {
            return e.content.to_vec();
        }
    }
    sha1(&spki_bits(issuer)).to_vec()
}

/// The subjectPublicKey BIT STRING's bits (asn1js's `valueHexView`).
#[tracing::instrument(level = "debug", skip_all)]
pub(super) fn spki_bits(cert: &Certificate) -> Vec<u8> {
    der::read(&cert.spki)
        .and_then(|e| der::children(e.content))
        .and_then(|c| c.get(1).map(|b| b.content.to_vec()))
        .map(|bits| bits.get(1..).unwrap_or_default().to_vec())
        .unwrap_or_default()
}

/// What a CRL is signed over.
#[derive(Debug, Clone)]
pub struct CrlInputs<'a> {
    pub issuer: &'a Certificate,
    pub signer_pem: &'a str,
    pub sig: SigAlg,
    /// The entries: `serialHex`, `revokedAt`, `reasonCode`.
    pub entries: &'a [Json],
    pub this_update: DateTime<Utc>,
    pub lifetime_ms: i64,
    pub number: i64,
}

/// The CRL's DER.
#[tracing::instrument(level = "debug", skip_all)]
pub fn sign_crl(inputs: &CrlInputs<'_>) -> PkiResult<Vec<u8>> {
    let alg = algorithms::certificate_signature_identifier(&inputs.sig)?;
    let this_update =
        certificate_instant(Some(inputs.this_update.timestamp_millis()));
    let next_update = DateTime::from_timestamp_millis(
        this_update.timestamp_millis() + inputs.lifetime_ms,
    )
    .ok_or_else(|| PkiError::new("Invalid time value"))?;
    let mut tbs = vec![
        der::integer(1),
        alg.clone(),
        inputs.issuer.subject_der.clone(),
        crl_time(&this_update),
        crl_time(&next_update),
    ];
    if !inputs.entries.is_empty() {
        let mut revoked = Vec::with_capacity(inputs.entries.len());
        for one in inputs.entries {
            let serial =
                one.get("serialHex").and_then(Json::as_str).unwrap_or("");
            let at = one
                .get("revokedAt")
                .and_then(Json::as_str)
                .and_then(ms_of)
                .and_then(DateTime::from_timestamp_millis)
                .ok_or_else(|| PkiError::new("Invalid time value"))?;
            let mut fields =
                vec![der::integer_raw(&serial_bytes(serial)), crl_time(&at)];
            let code =
                one.get("reasonCode").and_then(Json::as_i64).unwrap_or(0);
            if code != 0 {
                let reason = der::tlv(0x0a, &der::integer(code)[2..]);
                fields.push(der::sequence(&[extension(
                    "2.5.29.21",
                    false,
                    &reason,
                )?]));
            }
            revoked.push(der::sequence(&fields));
        }
        tbs.push(der::sequence(&revoked));
    }
    let akid = der::sequence(&[der::context(
        0,
        false,
        &key_identifier(inputs.issuer),
    )]);
    let extensions = der::sequence(&[
        extension("2.5.29.20", false, &der::integer(inputs.number))?,
        extension("2.5.29.35", false, &akid)?,
    ]);
    tbs.push(der::context(0, true, &extensions));
    let tbs = der::sequence(&tbs);
    let key = SigningKey::from_pem(inputs.signer_pem)?;
    let signature = sign_bytes(&inputs.sig, &key, &tbs)?;
    Ok(der::sequence(&[tbs, alg, der::bit_string(&signature)]))
}

impl Authority {
    /// `crlNumberAt()`: the moment, or one more than the last.
    fn crl_number_at(&self, scope: &str, ca: &str, when_ms: i64) -> i64 {
        let mut held = self
            .crl_numbers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = format!("{}/{}", scope, ca);
        let previous = held.get(&key).copied().unwrap_or(0);
        let number = when_ms.max(previous + 1);
        held.insert(key, number);
        number
    }

    /// `buildCrl()`: an authority's list, signed now.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn build_crl(&self, scope: &str, ca: &str) -> Result<Crl, Refusal> {
        self.build_crl_at(scope, ca, Utc::now())
    }

    /// The same at a given moment (a vector's).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn build_crl_at(
        &self,
        scope: &str,
        ca: &str,
        now: DateTime<Utc>,
    ) -> Result<Crl, Refusal> {
        // THE ROOT IS FOUND FROM ANY SCOPE, its list read from the scope
        // asked (`authorityFor()` and `listFor()` as Node has them): only
        // `service/root` names the Root's own list — `default/root` signs
        // an empty one, which is Node's answer too.
        let id = scope_id(scope);
        let Some(tier) = self.tier_for(&id, ca) else {
            return Err(Refusal::new(
                codes::STS_PKI_0055,
                format!(
                    "There is no \"{}\" certificate authority in that scope.",
                    ca
                ),
            ));
        };
        let entries = self.list_for(&id, ca);
        let now = certificate_instant(Some(now.timestamp_millis()));
        let number = self.crl_number_at(&id, ca, now.timestamp_millis());
        let lifetime = self.config().crl_lifetime_ms();
        let signed = (|| -> PkiResult<Vec<u8>> {
            let issuer = Certificate::from_pem(
                tier.get("certificatePem")
                    .and_then(Json::as_str)
                    .unwrap_or(""),
            )?;
            sign_crl(&CrlInputs {
                issuer: &issuer,
                signer_pem: tier
                    .get("privateKeyPem")
                    .and_then(Json::as_str)
                    .unwrap_or(""),
                sig: status_signature_alg(&tier)?,
                entries: &entries,
                this_update: now,
                lifetime_ms: lifetime,
                number,
            })
        })();
        let der = signed.map_err(|e| {
            tracing::error!(
                "{}pki_revocation: the \"{}\" CRL in \"{}\" could not be signed: {}",
                tag(codes::STS_PKI_0063),
                ca,
                id,
                e
            );
            Refusal::new(
                codes::STS_PKI_0063,
                format!("That CRL could not be signed: {}", e),
            )
        })?;
        let next =
            DateTime::from_timestamp_millis(now.timestamp_millis() + lifetime)
                .unwrap_or(now);
        Ok(Crl {
            der,
            count: entries.len(),
            crl_number: number,
            this_update: time::iso(&now),
            next_update: time::iso(&next),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_serial_is_positive_and_minimal() {
        assert_eq!(serial_bytes("00ff"), vec![0, 0xff]);
        assert_eq!(serial_bytes("7f"), vec![0x7f]);
        assert_eq!(serial_bytes("abc"), vec![0x0a, 0xbc]);
    }
}
