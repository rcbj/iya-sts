// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The keys `x509.js` takes as PEM: what a public key is
//! (`key_material.js`'s `describePublicPem()`), and a private key ready to
//! sign — OpenSSL's for the classical families, the seed for the
//! post-quantum ones.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private, Public};
use sts_crypto::pq_x509::{self, Use};

use crate::error::{PkiError, PkiResult};

/// `pemToDer()`: the base64 between the armour lines, any label.
pub fn pem_to_der(pem: &str) -> PkiResult<Vec<u8>> {
    let mut body = String::new();
    let mut rest = pem;
    while let Some(start) = rest.find("-----") {
        body.push_str(&rest[..start]);
        let after = &rest[start + 5..];
        // `-----(?:BEGIN|END)[^\n]*?-----`
        if after.starts_with("BEGIN") || after.starts_with("END") {
            match after.find("-----") {
                Some(end) if !after[..end].contains('\n') => {
                    rest = &after[end + 5..];
                    continue;
                }
                _ => {}
            }
        }
        body.push_str("-----");
        rest = after;
    }
    body.push_str(rest);
    let body: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    STANDARD
        .decode(
            body.trim_end_matches('=').to_string()
                + &"=".repeat((4 - body.trim_end_matches('=').len() % 4) % 4),
        )
        .map_err(|_| {
            PkiError::new("The string to be decoded is not correctly encoded.")
        })
}

/// `derToPem()`: 64-column base64 between armour lines, a final newline.
pub fn der_to_pem(der: &[u8], label: &str) -> String {
    let b64 = STANDARD.encode(der);
    let lines: Vec<&str> = if b64.is_empty() {
        vec![""]
    } else {
        b64.as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap_or(""))
            .collect()
    };
    format!(
        "-----BEGIN {}-----\n{}\n-----END {}-----\n",
        label,
        lines.join("\n"),
        label
    )
}

/// What a public key is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyDesc {
    Rsa {
        bits: usize,
    },
    /// `P-256`, `P-384` or `P-521`.
    Ec {
        curve: &'static str,
    },
    Ed25519,
    /// A post-quantum key: `pq_x509`'s id.
    Pqc(&'static str),
}

impl KeyDesc {
    pub fn kind(&self) -> &'static str {
        match self {
            KeyDesc::Rsa { .. } => "rsa",
            KeyDesc::Ec { .. } => "ec",
            KeyDesc::Ed25519 => "okp",
            KeyDesc::Pqc(_) => "pqc",
        }
    }

    pub fn curve(&self) -> Option<&'static str> {
        match self {
            KeyDesc::Ec { curve } => Some(curve),
            _ => None,
        }
    }

    pub fn pqc(&self) -> Option<&'static str> {
        match self {
            KeyDesc::Pqc(id) => Some(id),
            _ => None,
        }
    }
}

fn web_curve(nid: Nid) -> Option<&'static str> {
    match nid {
        Nid::X9_62_PRIME256V1 => Some("P-256"),
        Nid::SECP384R1 => Some("P-384"),
        Nid::SECP521R1 => Some("P-521"),
        _ => None,
    }
}

/// `describePublicPem()` over the DER: the post-quantum families by OID,
/// then the keys Web Crypto imports — RSA, the three NIST curves, Ed25519.
/// Anything else (secp256k1, Ed448) is `None`, as Web Crypto refuses it.
pub fn describe_spki(spki: &[u8]) -> Option<KeyDesc> {
    if let Some((alg, _)) = pq_x509::decode_spki(spki) {
        return Some(KeyDesc::Pqc(alg.id));
    }
    let key = PKey::public_key_from_der(spki).ok()?;
    describe_public(&key)
}

pub fn describe_public(key: &PKey<Public>) -> Option<KeyDesc> {
    match key.id() {
        Id::RSA => {
            let rsa = key.rsa().ok()?;
            Some(KeyDesc::Rsa {
                bits: rsa.n().num_bytes() as usize * 8,
            })
        }
        Id::EC => {
            let ec = key.ec_key().ok()?;
            web_curve(ec.group().curve_name()?)
                .map(|curve| KeyDesc::Ec { curve })
        }
        Id::ED25519 => Some(KeyDesc::Ed25519),
        _ => None,
    }
}

pub fn describe_public_pem(pem: &str) -> Option<KeyDesc> {
    describe_spki(&pem_to_der(pem).ok()?)
}

/// A private key ready to sign.
pub enum SigningKey {
    Classical(PKey<Private>),
    /// A post-quantum key: its algorithm and seed (`None` when the PKCS#8
    /// held only the expanded key, which this build does not sign from).
    Pqc {
        id: &'static str,
        seed: Option<Vec<u8>>,
    },
}

impl SigningKey {
    /// A PKCS#8 PEM: post-quantum by OID, otherwise OpenSSL's.
    pub fn from_pem(pem: &str) -> PkiResult<SigningKey> {
        let der = pem_to_der(pem)?;
        if let Ok(Some(pq)) = pq_x509::decode_pkcs8(&der) {
            return Ok(SigningKey::Pqc {
                id: pq.alg.id,
                seed: pq.private,
            });
        }
        let key = PKey::private_key_from_der(&der)
            .or_else(|_| PKey::private_key_from_pem(pem.as_bytes()))?;
        Ok(SigningKey::Classical(key))
    }

    /// `describePrivatePem()`: a post-quantum key's algorithm, or `None`.
    pub fn pqc(&self) -> Option<&'static str> {
        match self {
            SigningKey::Pqc { id, .. } => Some(id),
            SigningKey::Classical(_) => None,
        }
    }
}

/// Whether a post-quantum id names a signature algorithm.
pub fn pq_signs(id: &str) -> bool {
    pq_x509::alg(id).is_some_and(|a| a.usage == Use::Sig)
}
