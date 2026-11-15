// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What a WebAuthn attestation's TRUST half asks of a certificate, beside
//! [`crate::foreign::attestation_certificate_facts`]: `common/pki.js`'s
//! `attestationDeviceSerial()` (#532), `attestationSignatureAlgorithm()`
//! (#941) and `certificateSerialHex()` (the key Google's Android
//! attestation status list is looked up by, #256). Each answers what Node
//! answers for the same DER, and none of them decides anything: the
//! verifier in `sts-credentials` does.

use serde_json::{json, Value as Json};
use sts_crypto::pq_x509;

use crate::der;
use crate::x509::algorithms::{sig_alg_for_oid, SigKind};
use crate::x509::read::Certificate;

/// Yubico's device serial extension (its enterprise attestation
/// documentation): a DER INTEGER.
const YUBICO_SERIAL_OID: &str = "1.3.6.1.4.1.41482.13.1";
/// RSASSA-PSS, whose hash is in parameters Node does not read here.
const RSASSA_PSS_OID: &str = "1.2.840.113549.1.1.10";
/// The families a post-quantum certificate signature is in.
const PQ_FAMILIES: [&str; 3] = ["ML-DSA", "SLH-DSA", "Composite ML-DSA"];

/// The decimal text of a big-endian non-negative integer (`BigInt('0x' +
/// hex).toString(10)`).
fn decimal(bytes: &[u8]) -> String {
    let mut digits: Vec<u8> = vec![0];
    for b in bytes {
        let mut carry = u32::from(*b);
        for d in digits.iter_mut() {
            let v = u32::from(*d) * 256 + carry;
            *d = (v % 10) as u8;
            carry = v / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    digits.iter().rev().map(|d| char::from(b'0' + d)).collect()
}

/// `attestationDeviceSerial(der)`: the device serial an enterprise
/// attestation certificate carries — the subject's serialNumber (2.5.4.5),
/// else Yubico's extension — as `{ serial, source }`, or none.
#[tracing::instrument(level = "debug", skip_all)]
pub fn attestation_device_serial(der_bytes: &[u8]) -> Option<Json> {
    let cert = Certificate::from_der(der_bytes).ok()?;
    if let Some(name) = der::read(&cert.subject_der) {
        let mut named: Option<String> = None;
        'outer: for set in der::children(name.content).unwrap_or_default() {
            for atv in der::children(set.content).unwrap_or_default() {
                let parts = der::children(atv.content).unwrap_or_default();
                if parts.len() >= 2
                    && der::oid_string(parts[0].content).as_deref()
                        == Some("2.5.4.5")
                {
                    named = Some(crate::path::facts::string_of(&parts[1]));
                    break 'outer;
                }
            }
        }
        let text = named.unwrap_or_default();
        let text = text.trim();
        if !text.is_empty()
            && text.len() <= 64
            && text.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Some(json!({ "serial": text,
                                "source": "subject-serialNumber" }));
        }
    }
    let ext = cert
        .extensions
        .iter()
        .find(|e| e.oid == YUBICO_SERIAL_OID)?;
    let node = der::read(&ext.value)?;
    if node.tag != der::INTEGER || node.content.is_empty() {
        return None;
    }
    let bytes = node.content;
    if bytes[0] & 0x80 != 0 || bytes.len() > 16 {
        return None;
    }
    Some(json!({ "serial": decimal(bytes), "source": "yubico-extension" }))
}

/// `attestationSignatureAlgorithm(der)`: `{ algorithm, oid, family,
/// postQuantum, composite }` of the certificate's outer signature — what
/// its ISSUER signed with — or none for what is not a certificate.
#[tracing::instrument(level = "debug", skip_all)]
pub fn attestation_signature_algorithm(der_bytes: &[u8]) -> Option<Json> {
    let cert = Certificate::from_der(der_bytes).ok()?;
    let oid = cert.signature_oid.clone();
    let (algorithm, family) = match sig_alg_for_oid(&oid, None) {
        Some(spec) => match spec.kind {
            SigKind::Pqc(id) => {
                let entry = pq_x509::alg(id);
                (
                    entry.map_or(id.to_string(), |e| e.name.to_string()),
                    entry.map_or("unknown", |e| e.family.name()).to_string(),
                )
            }
            kind => (spec.id.clone(), kind.family().to_string()),
        },
        None if oid == RSASSA_PSS_OID => {
            ("rsassa-pss".to_string(), "rsa".to_string())
        }
        None => (oid.clone(), "unknown".to_string()),
    };
    let post_quantum = PQ_FAMILIES.contains(&family.as_str());
    let composite = family == "Composite ML-DSA";
    Some(json!({
        "algorithm": algorithm,
        "oid": oid,
        "family": family,
        "postQuantum": post_quantum,
        "composite": composite,
    }))
}

/// `certificateSerialHex(der)`: the serial number in lower-case hex, its
/// leading zeros dropped; empty for what cannot be read.
#[tracing::instrument(level = "debug", skip_all)]
pub fn certificate_serial_hex(der_bytes: &[u8]) -> String {
    let Ok(cert) = Certificate::from_der(der_bytes) else {
        return String::new();
    };
    let hex = der::hex(&cert.serial);
    let trimmed = hex.trim_start_matches('0');
    if trimmed.is_empty() && !hex.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}
