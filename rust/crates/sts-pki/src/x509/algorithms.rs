// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Signature algorithms: an issuer's key family crossed with a digest, and
//! the post-quantum algorithms, which are their key's kind as well
//! (`x509.js`'s `SIG_ALGS`).
//!
//! The two SHA-1 rows are deliberate and `weak`: "does my TLS stack refuse
//! a SHA-1 certificate?" is a question a debugger should be able to ask.
//! Nothing defaults to them.

use openssl::hash::MessageDigest;
use sts_crypto::pq_x509::{self, Use};

use crate::der;
use crate::error::{PkiError, PkiResult};

/// A digest named as Web Crypto names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    pub fn name(self) -> &'static str {
        match self {
            Hash::Sha1 => "SHA-1",
            Hash::Sha256 => "SHA-256",
            Hash::Sha384 => "SHA-384",
            Hash::Sha512 => "SHA-512",
        }
    }

    pub fn digest(self) -> MessageDigest {
        match self {
            Hash::Sha1 => MessageDigest::sha1(),
            Hash::Sha256 => MessageDigest::sha256(),
            Hash::Sha384 => MessageDigest::sha384(),
            Hash::Sha512 => MessageDigest::sha512(),
        }
    }

    /// The digest's length: RSASSA-PSS's salt (RFC 4055 section 3.1).
    pub fn digest_len(self) -> usize {
        match self {
            Hash::Sha1 => 20,
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
            Hash::Sha512 => 64,
        }
    }

    pub fn oid(self) -> &'static str {
        match self {
            Hash::Sha1 => "1.3.14.3.2.26",
            Hash::Sha256 => "2.16.840.1.101.3.4.2.1",
            Hash::Sha384 => "2.16.840.1.101.3.4.2.2",
            Hash::Sha512 => "2.16.840.1.101.3.4.2.3",
        }
    }

    pub fn from_oid(oid: &str) -> Option<Hash> {
        [Hash::Sha1, Hash::Sha256, Hash::Sha384, Hash::Sha512]
            .into_iter()
            .find(|h| h.oid() == oid)
    }
}

/// The family the SIGNER's key must have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigKind {
    Rsa {
        hash: Hash,
        pss: bool,
    },
    Ec {
        hash: Hash,
    },
    Ed25519,
    /// A post-quantum algorithm: `pq_x509`'s id.
    Pqc(&'static str),
}

impl SigKind {
    /// `rsa`, `ec`, `okp` or `pqc`, as `x509.js` says it.
    pub fn family(self) -> &'static str {
        match self {
            SigKind::Rsa { .. } => "rsa",
            SigKind::Ec { .. } => "ec",
            SigKind::Ed25519 => "okp",
            SigKind::Pqc(_) => "pqc",
        }
    }
}

/// One row of `SIG_ALGS`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigAlg {
    /// The lower-case id: `sha256-rsa`, `ml-dsa-65`.
    pub id: String,
    pub kind: SigKind,
    pub weak: bool,
    pub label: String,
}

const CLASSICAL: &[(&str, SigKind, bool, &str)] = &[
    (
        "sha256-rsa",
        SigKind::Rsa {
            hash: Hash::Sha256,
            pss: false,
        },
        false,
        "RSASSA-PKCS1-v1_5 with SHA-256",
    ),
    (
        "sha384-rsa",
        SigKind::Rsa {
            hash: Hash::Sha384,
            pss: false,
        },
        false,
        "RSASSA-PKCS1-v1_5 with SHA-384",
    ),
    (
        "sha512-rsa",
        SigKind::Rsa {
            hash: Hash::Sha512,
            pss: false,
        },
        false,
        "RSASSA-PKCS1-v1_5 with SHA-512",
    ),
    (
        "sha256-rsapss",
        SigKind::Rsa {
            hash: Hash::Sha256,
            pss: true,
        },
        false,
        "RSASSA-PSS with SHA-256",
    ),
    (
        "sha384-rsapss",
        SigKind::Rsa {
            hash: Hash::Sha384,
            pss: true,
        },
        false,
        "RSASSA-PSS with SHA-384",
    ),
    (
        "sha512-rsapss",
        SigKind::Rsa {
            hash: Hash::Sha512,
            pss: true,
        },
        false,
        "RSASSA-PSS with SHA-512",
    ),
    (
        "sha1-rsa",
        SigKind::Rsa {
            hash: Hash::Sha1,
            pss: false,
        },
        true,
        "RSASSA-PKCS1-v1_5 with SHA-1 (legacy, weak)",
    ),
    (
        "sha256-ecdsa",
        SigKind::Ec { hash: Hash::Sha256 },
        false,
        "ECDSA with SHA-256",
    ),
    (
        "sha384-ecdsa",
        SigKind::Ec { hash: Hash::Sha384 },
        false,
        "ECDSA with SHA-384",
    ),
    (
        "sha512-ecdsa",
        SigKind::Ec { hash: Hash::Sha512 },
        false,
        "ECDSA with SHA-512",
    ),
    (
        "sha1-ecdsa",
        SigKind::Ec { hash: Hash::Sha1 },
        true,
        "ECDSA with SHA-1 (legacy, weak)",
    ),
    ("ed25519", SigKind::Ed25519, false, "Ed25519 (EdDSA)"),
];

/// Every signature algorithm, in `SIG_ALG_ORDER`: the classical ones, then
/// the post-quantum ones in `pq_x509`'s order.
pub fn sig_algs() -> Vec<SigAlg> {
    let mut out: Vec<SigAlg> = CLASSICAL
        .iter()
        .map(|(id, kind, weak, label)| SigAlg {
            id: id.to_string(),
            kind: *kind,
            weak: *weak,
            label: label.to_string(),
        })
        .collect();
    for id in pq_x509::alg_ids(Some(Use::Sig)) {
        out.push(SigAlg {
            id: id.to_lowercase(),
            kind: SigKind::Pqc(id),
            weak: false,
            label: pq_x509::label_for(id),
        });
    }
    out
}

/// `sigAlg()`: the row for an id, any case.
pub fn sig_alg(id: &str) -> Option<SigAlg> {
    let wanted = id.to_lowercase();
    sig_algs().into_iter().find(|a| a.id == wanted)
}

/// `signatureAlgorithmsFor()`: the ids a key of this family can produce —
/// for a post-quantum key, its one algorithm, or none for a KEM.
pub fn signature_algorithms_for(kind: &str, pqc: Option<&str>) -> Vec<String> {
    if kind == "pqc" {
        return pqc
            .and_then(pq_x509::alg)
            .filter(|a| a.usage == Use::Sig)
            .map(|a| vec![a.id.to_lowercase()])
            .unwrap_or_default();
    }
    sig_algs()
        .into_iter()
        .filter(|a| {
            a.kind.family() == kind && !matches!(a.kind, SigKind::Pqc(_))
        })
        .map(|a| a.id)
        .collect()
}

/// `defaultSignatureAlgorithm()`: the strongest non-weak algorithm at the
/// digest size the key matches.
pub fn default_signature_algorithm(
    kind: &str,
    curve: Option<&str>,
    pqc: Option<&str>,
) -> String {
    match kind {
        "pqc" => pqc.unwrap_or("").to_lowercase(),
        "okp" => "ed25519".to_string(),
        "ec" => match curve {
            Some("P-384") => "sha384-ecdsa",
            Some("P-521") => "sha512-ecdsa",
            _ => "sha256-ecdsa",
        }
        .to_string(),
        _ => "sha256-rsa".to_string(),
    }
}

pub const ED25519_OID: &str = "1.3.101.112";
const RSA_PSS_OID: &str = "1.2.840.113549.1.1.10";
const MGF1_OID: &str = "1.2.840.113549.1.1.8";

/// The OID of a classical algorithm, and whether it carries NULL params.
fn classical_oid(id: &str) -> Option<(&'static str, bool)> {
    Some(match id {
        "sha1-rsa" => ("1.2.840.113549.1.1.5", true),
        "sha256-rsa" => ("1.2.840.113549.1.1.11", true),
        "sha384-rsa" => ("1.2.840.113549.1.1.12", true),
        "sha512-rsa" => ("1.2.840.113549.1.1.13", true),
        "sha256-rsapss" | "sha384-rsapss" | "sha512-rsapss" => {
            (RSA_PSS_OID, false)
        }
        "sha1-ecdsa" => ("1.2.840.10045.4.1", false),
        "sha256-ecdsa" => ("1.2.840.10045.4.3.2", false),
        "sha384-ecdsa" => ("1.2.840.10045.4.3.3", false),
        "sha512-ecdsa" => ("1.2.840.10045.4.3.4", false),
        "ed25519" => (ED25519_OID, false),
        _ => return None,
    })
}

fn digest_algorithm_identifier(hash: Hash) -> PkiResult<Vec<u8>> {
    Ok(der::sequence(&[der::oid(hash.oid())?, der::null()]))
}

/// RFC 4055 section 3.1's parameters with every field written, the
/// trailer included: `x509.js`'s `rsaPssParams()`, for an
/// altSignatureAlgorithm.
fn rsa_pss_params_full(hash: Hash) -> PkiResult<Vec<u8>> {
    Ok(der::sequence(&[
        der::context(0, true, &digest_algorithm_identifier(hash)?),
        der::context(
            1,
            true,
            &der::sequence(&[
                der::oid(MGF1_OID)?,
                digest_algorithm_identifier(hash)?,
            ]),
        ),
        der::context(2, true, &der::integer(hash.digest_len() as i64)),
        der::context(3, true, &der::integer(1)),
    ]))
}

/// `signatureAlgorithmIdentifier()`: the AlgorithmIdentifier `x509.js`
/// writes into an extension — RSA with NULL parameters, PSS with all four.
pub fn signature_algorithm_identifier(sig: &SigAlg) -> PkiResult<Vec<u8>> {
    if let SigKind::Pqc(id) = sig.kind {
        let alg = pq_x509::alg(id)
            .ok_or_else(|| PkiError::new("unknown algorithm"))?;
        return Ok(der::sequence(&[der::oid(alg.oid)?]));
    }
    let (oid, null_params) = classical_oid(&sig.id).ok_or_else(|| {
        PkiError::new(format!(
            "No AlgorithmIdentifier is known here for {}.",
            sig.id
        ))
    })?;
    let mut parts = vec![der::oid(oid)?];
    if null_params {
        parts.push(der::null());
    }
    if let SigKind::Rsa { hash, pss: true } = sig.kind {
        parts.push(rsa_pss_params_full(hash)?);
    }
    Ok(der::sequence(&parts))
}

/// The AlgorithmIdentifier pkijs writes when IT signs a certificate or a
/// request: RSA PKCS#1 v1.5 and ECDSA with NO parameters, PSS with the
/// hash, MGF1 and salt but no trailer, the trailer and a SHA-1 hash being
/// their defaults (pkijs's `getSignatureParameters()`). Ed25519 and the
/// post-quantum algorithms are the OID alone, which `x509.js` sets itself.
pub fn certificate_signature_identifier(sig: &SigAlg) -> PkiResult<Vec<u8>> {
    match sig.kind {
        SigKind::Pqc(_) => signature_algorithm_identifier(sig),
        SigKind::Rsa { hash, pss: true } => {
            let mut params = Vec::new();
            if hash != Hash::Sha1 {
                let h = digest_algorithm_identifier(hash)?;
                params.push(der::context(0, true, &h));
                params.push(der::context(
                    1,
                    true,
                    &der::sequence(&[der::oid(MGF1_OID)?, h]),
                ));
            }
            if hash.digest_len() != 20 {
                params.push(der::context(
                    2,
                    true,
                    &der::integer(hash.digest_len() as i64),
                ));
            }
            Ok(der::sequence(&[
                der::oid(RSA_PSS_OID)?,
                der::sequence(&params),
            ]))
        }
        _ => {
            let (oid, _) = classical_oid(&sig.id).ok_or_else(|| {
                PkiError::new(format!(
                    "Unsupported signature algorithm: {}",
                    sig.id
                ))
            })?;
            Ok(der::sequence(&[der::oid(oid)?]))
        }
    }
}

/// `sigAlgForOid()`: which row an AlgorithmIdentifier names — the digest
/// of a PSS one out of its parameters.
pub fn sig_alg_for_oid(
    oid: &str,
    params_hash_oid: Option<&str>,
) -> Option<SigAlg> {
    if let Some(pq) = pq_x509::alg_for_oid(oid) {
        return sig_alg(pq.id);
    }
    for (id, kind, _, _) in CLASSICAL {
        let Some((known, _)) = classical_oid(id) else {
            continue;
        };
        if known != oid {
            continue;
        }
        match kind {
            SigKind::Rsa { hash, pss: true } => {
                if params_hash_oid.and_then(Hash::from_oid) == Some(*hash) {
                    return sig_alg(id);
                }
            }
            _ => return sig_alg(id),
        }
    }
    None
}
