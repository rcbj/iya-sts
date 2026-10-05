// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Post-quantum keys in X.509: a port of `common/vendored/pqc_x509.js`
//! (this service's own since #363), on OpenSSL 3.5's ML-DSA, SLH-DSA and
//! ML-KEM.
//!
//! * **The registry**: ML-DSA (RFC 9881), all twelve SLH-DSA sets (RFC
//!   9909), ML-KEM (RFC 9935), and the sixteen composite ML-DSA signatures
//!   of draft-ietf-lamps-pq-composite-sigs this build implements — the two
//!   brainpool ones are recorded as missing, as in Node.
//! * **SubjectPublicKeyInfo and PKCS#8** for every one, the PKCS#8 CHOICE's
//!   three arms (`seed`, `expandedKey`, `both`) for ML-DSA and ML-KEM, the
//!   parameters ABSENT (RFC 9881 section 3 — an explicit NULL makes
//!   OpenSSL refuse the certificate).
//! * **Composite signatures**: M' = prefix || label || 0x00 || PH(M), the
//!   label the ML-DSA context as well, and BOTH halves verified, always.
//!   The traditional halves are in the encodings the draft pins: an
//!   uncompressed point and an ECPrivateKey without its public key, a raw
//!   Ed25519/Ed448 key, an RSAPublicKey / RSAPrivateKey.
//!
//! What differs from Node is only the randomness: an ECDSA half is OpenSSL's
//! randomized signature where noble's is RFC 6979's deterministic one —
//! both verify on either side — and ML-DSA is hedged on both.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, KeyType, PKey, PKeyRef, Private, Public};
use openssl::rsa::{Padding, Rsa};
use openssl::sign::{RsaPssSaltlen, Signer, Verifier};
use sha3::digest::{ExtendableOutput, Update};

use crate::der_lite as der;
use crate::error::{CryptoError, CryptoResult};
use crate::pq;
use crate::random::random_bytes;

fn err(m: impl Into<String>) -> CryptoError {
    CryptoError::new(m)
}

/// What an algorithm is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Use {
    Sig,
    Kem,
}

/// The family an algorithm is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    MlDsa,
    SlhDsa,
    MlKem,
    Composite,
}

impl Family {
    pub fn name(self) -> &'static str {
        match self {
            Family::MlDsa => "ML-DSA",
            Family::SlhDsa => "SLH-DSA",
            Family::MlKem => "ML-KEM",
            Family::Composite => "Composite ML-DSA",
        }
    }
}

/// A composite's pre-hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prehash {
    Sha256,
    Sha512,
    Shake256x64,
}

/// A digest a traditional half signs with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigHash {
    Sha256,
    Sha384,
    Sha512,
}

impl SigHash {
    fn md(self) -> MessageDigest {
        match self {
            SigHash::Sha256 => MessageDigest::sha256(),
            SigHash::Sha384 => MessageDigest::sha384(),
            SigHash::Sha512 => MessageDigest::sha512(),
        }
    }
}

/// A composite's traditional half.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trad {
    Rsa {
        bits: u32,
        pss: bool,
        sig_hash: SigHash,
        salt: usize,
    },
    Ec {
        curve: &'static str,
        sig_hash: SigHash,
    },
    Ed {
        ed448: bool,
    },
}

/// One composite of section 6 of the draft.
#[derive(Clone, Copy, Debug)]
pub struct Composite {
    pub id: &'static str,
    pub name: &'static str,
    pub oid: &'static str,
    pub label: &'static str,
    pub mldsa: &'static str,
    pub ph: Prehash,
    pub trad: Trad,
}

const fn rsa(bits: u32, pss: bool, sig_hash: SigHash, salt: usize) -> Trad {
    Trad::Rsa {
        bits,
        pss,
        sig_hash,
        salt,
    }
}

/// The sixteen composites this build implements, transcribed one entry at a
/// time as Node's are — the PSS parameters go by RSA SIZE and the pre-hash
/// by ALGORITHM, so neither is derived from the name.
pub const COMPOSITES: [Composite; 16] = [
    Composite {
        id: "mldsa44-rsa2048-pss-sha256",
        name: "id-MLDSA44-RSA2048-PSS-SHA256",
        oid: "1.3.6.1.5.5.7.6.37",
        label: "COMPSIG-MLDSA44-RSA2048-PSS-SHA256",
        mldsa: "ML-DSA-44",
        ph: Prehash::Sha256,
        trad: rsa(2048, true, SigHash::Sha256, 32),
    },
    Composite {
        id: "mldsa44-rsa2048-pkcs15-sha256",
        name: "id-MLDSA44-RSA2048-PKCS15-SHA256",
        oid: "1.3.6.1.5.5.7.6.38",
        label: "COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256",
        mldsa: "ML-DSA-44",
        ph: Prehash::Sha256,
        trad: rsa(2048, false, SigHash::Sha256, 0),
    },
    Composite {
        id: "mldsa44-ed25519-sha512",
        name: "id-MLDSA44-Ed25519-SHA512",
        oid: "1.3.6.1.5.5.7.6.39",
        label: "COMPSIG-MLDSA44-Ed25519-SHA512",
        mldsa: "ML-DSA-44",
        ph: Prehash::Sha512,
        trad: Trad::Ed { ed448: false },
    },
    Composite {
        id: "mldsa44-ecdsa-p256-sha256",
        name: "id-MLDSA44-ECDSA-P256-SHA256",
        oid: "1.3.6.1.5.5.7.6.40",
        label: "COMPSIG-MLDSA44-ECDSA-P256-SHA256",
        mldsa: "ML-DSA-44",
        ph: Prehash::Sha256,
        trad: Trad::Ec {
            curve: "P-256",
            sig_hash: SigHash::Sha256,
        },
    },
    Composite {
        id: "mldsa65-rsa3072-pss-sha512",
        name: "id-MLDSA65-RSA3072-PSS-SHA512",
        oid: "1.3.6.1.5.5.7.6.41",
        label: "COMPSIG-MLDSA65-RSA3072-PSS-SHA512",
        mldsa: "ML-DSA-65",
        ph: Prehash::Sha512,
        trad: rsa(3072, true, SigHash::Sha256, 32),
    },
    Composite {
        id: "mldsa65-rsa3072-pkcs15-sha512",
        name: "id-MLDSA65-RSA3072-PKCS15-SHA512",
        oid: "1.3.6.1.5.5.7.6.42",
        label: "COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512",
        mldsa: "ML-DSA-65",
        ph: Prehash::Sha512,
        trad: rsa(3072, false, SigHash::Sha256, 0),
    },
    Composite {
        id: "mldsa65-rsa4096-pss-sha512",
        name: "id-MLDSA65-RSA4096-PSS-SHA512",
        oid: "1.3.6.1.5.5.7.6.43",
        label: "COMPSIG-MLDSA65-RSA4096-PSS-SHA512",
        mldsa: "ML-DSA-65",
        ph: Prehash::Sha512,
        trad: rsa(4096, true, SigHash::Sha384, 48),
    },
    Composite {
        id: "mldsa65-rsa4096-pkcs15-sha512",
        name: "id-MLDSA65-RSA4096-PKCS15-SHA512",
        oid: "1.3.6.1.5.5.7.6.44",
        label: "COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512",
        mldsa: "ML-DSA-65",
        ph: Prehash::Sha512,
        trad: rsa(4096, false, SigHash::Sha384, 0),
    },
    Composite {
        id: "mldsa65-ecdsa-p256-sha512",
        name: "id-MLDSA65-ECDSA-P256-SHA512",
        oid: "1.3.6.1.5.5.7.6.45",
        label: "COMPSIG-MLDSA65-ECDSA-P256-SHA512",
        mldsa: "ML-DSA-65",
        ph: Prehash::Sha512,
        trad: Trad::Ec {
            curve: "P-256",
            sig_hash: SigHash::Sha256,
        },
    },
    Composite {
        id: "mldsa65-ecdsa-p384-sha512",
        name: "id-MLDSA65-ECDSA-P384-SHA512",
        oid: "1.3.6.1.5.5.7.6.46",
        label: "COMPSIG-MLDSA65-ECDSA-P384-SHA512",
        mldsa: "ML-DSA-65",
        ph: Prehash::Sha512,
        trad: Trad::Ec {
            curve: "P-384",
            sig_hash: SigHash::Sha384,
        },
    },
    Composite {
        id: "mldsa65-ed25519-sha512",
        name: "id-MLDSA65-Ed25519-SHA512",
        oid: "1.3.6.1.5.5.7.6.48",
        label: "COMPSIG-MLDSA65-Ed25519-SHA512",
        mldsa: "ML-DSA-65",
        ph: Prehash::Sha512,
        trad: Trad::Ed { ed448: false },
    },
    Composite {
        id: "mldsa87-ecdsa-p384-sha512",
        name: "id-MLDSA87-ECDSA-P384-SHA512",
        oid: "1.3.6.1.5.5.7.6.49",
        label: "COMPSIG-MLDSA87-ECDSA-P384-SHA512",
        mldsa: "ML-DSA-87",
        ph: Prehash::Sha512,
        trad: Trad::Ec {
            curve: "P-384",
            sig_hash: SigHash::Sha384,
        },
    },
    Composite {
        id: "mldsa87-ed448-shake256",
        name: "id-MLDSA87-Ed448-SHAKE256",
        oid: "1.3.6.1.5.5.7.6.51",
        label: "COMPSIG-MLDSA87-Ed448-SHAKE256",
        mldsa: "ML-DSA-87",
        ph: Prehash::Shake256x64,
        trad: Trad::Ed { ed448: true },
    },
    Composite {
        id: "mldsa87-rsa3072-pss-sha512",
        name: "id-MLDSA87-RSA3072-PSS-SHA512",
        oid: "1.3.6.1.5.5.7.6.52",
        label: "COMPSIG-MLDSA87-RSA3072-PSS-SHA512",
        mldsa: "ML-DSA-87",
        ph: Prehash::Sha512,
        trad: rsa(3072, true, SigHash::Sha256, 32),
    },
    Composite {
        id: "mldsa87-rsa4096-pss-sha512",
        name: "id-MLDSA87-RSA4096-PSS-SHA512",
        oid: "1.3.6.1.5.5.7.6.53",
        label: "COMPSIG-MLDSA87-RSA4096-PSS-SHA512",
        mldsa: "ML-DSA-87",
        ph: Prehash::Sha512,
        trad: rsa(4096, true, SigHash::Sha384, 48),
    },
    Composite {
        id: "mldsa87-ecdsa-p521-sha512",
        name: "id-MLDSA87-ECDSA-P521-SHA512",
        oid: "1.3.6.1.5.5.7.6.54",
        label: "COMPSIG-MLDSA87-ECDSA-P521-SHA512",
        mldsa: "ML-DSA-87",
        ph: Prehash::Sha512,
        trad: Trad::Ec {
            curve: "P-521",
            sig_hash: SigHash::Sha512,
        },
    },
];

/// The two the draft defines and this build does not implement, and why.
pub const COMPOSITE_MISSING: [(&str, &str, &str); 2] = [
    ("id-MLDSA65-ECDSA-brainpoolP256r1-SHA512", "1.3.6.1.5.5.7.6.47", "brainpoolP256r1 is in no library in this dependency tree and in no browser. Writing the curve here to fill the gap would be inventing cryptography, which this project does not do."),
    ("id-MLDSA87-ECDSA-brainpoolP384r1-SHA512", "1.3.6.1.5.5.7.6.50", "brainpoolP384r1, for the same reason as brainpoolP256r1 above."),
];

const SIG_OIDS: [(&str, &str); 15] = [
    ("ML-DSA-44", "2.16.840.1.101.3.4.3.17"),
    ("ML-DSA-65", "2.16.840.1.101.3.4.3.18"),
    ("ML-DSA-87", "2.16.840.1.101.3.4.3.19"),
    ("SLH-DSA-SHA2-128s", "2.16.840.1.101.3.4.3.20"),
    ("SLH-DSA-SHA2-128f", "2.16.840.1.101.3.4.3.21"),
    ("SLH-DSA-SHA2-192s", "2.16.840.1.101.3.4.3.22"),
    ("SLH-DSA-SHA2-192f", "2.16.840.1.101.3.4.3.23"),
    ("SLH-DSA-SHA2-256s", "2.16.840.1.101.3.4.3.24"),
    ("SLH-DSA-SHA2-256f", "2.16.840.1.101.3.4.3.25"),
    ("SLH-DSA-SHAKE-128s", "2.16.840.1.101.3.4.3.26"),
    ("SLH-DSA-SHAKE-128f", "2.16.840.1.101.3.4.3.27"),
    ("SLH-DSA-SHAKE-192s", "2.16.840.1.101.3.4.3.28"),
    ("SLH-DSA-SHAKE-192f", "2.16.840.1.101.3.4.3.29"),
    ("SLH-DSA-SHAKE-256s", "2.16.840.1.101.3.4.3.30"),
    ("SLH-DSA-SHAKE-256f", "2.16.840.1.101.3.4.3.31"),
];

const KEM_OIDS: [(&str, &str); 3] = [
    ("ML-KEM-512", "2.16.840.1.101.3.4.4.1"),
    ("ML-KEM-768", "2.16.840.1.101.3.4.4.2"),
    ("ML-KEM-1024", "2.16.840.1.101.3.4.4.3"),
];

/// FIPS 204: (public key, signature) lengths.
fn ml_dsa_lengths(name: &str) -> (usize, usize) {
    match name {
        "ML-DSA-44" => (1312, 2420),
        "ML-DSA-65" => (1952, 3309),
        _ => (2592, 4627),
    }
}

/// One algorithm of the registry.
#[derive(Clone, Copy, Debug)]
pub struct Alg {
    pub id: &'static str,
    pub name: &'static str,
    pub family: Family,
    pub usage: Use,
    pub oid: &'static str,
    pub spec: &'static str,
    pub composite: Option<&'static Composite>,
}

static ALGS: std::sync::LazyLock<Vec<Alg>> = std::sync::LazyLock::new(|| {
    let mut out = Vec::new();
    for (name, oid) in SIG_OIDS {
        let ml = name.starts_with("ML-DSA");
        out.push(Alg {
            id: name,
            name,
            family: if ml { Family::MlDsa } else { Family::SlhDsa },
            usage: Use::Sig,
            oid,
            spec: if ml { "RFC.9881" } else { "RFC.9909" },
            composite: None,
        });
    }
    for (name, oid) in KEM_OIDS {
        out.push(Alg {
            id: name,
            name,
            family: Family::MlKem,
            usage: Use::Kem,
            oid,
            spec: "RFC.9935",
            composite: None,
        });
    }
    for c in &COMPOSITES {
        out.push(Alg {
            id: c.id,
            name: c.name,
            family: Family::Composite,
            usage: Use::Sig,
            oid: c.oid,
            spec: "I-D.lamps-composite-sigs",
            composite: Some(c),
        });
    }
    out
});

/// Every algorithm, in Node's order.
pub fn algs() -> &'static [Alg] {
    &ALGS
}

/// An algorithm by id, in either spelling (`ML-DSA-44`, `ml-dsa-44`).
pub fn alg(id: &str) -> Option<&'static Alg> {
    ALGS.iter()
        .find(|a| a.id == id)
        .or_else(|| ALGS.iter().find(|a| a.id.eq_ignore_ascii_case(id)))
}

pub fn alg_for_oid(oid: &str) -> Option<&'static Alg> {
    ALGS.iter().find(|a| a.oid == oid)
}

pub fn is_pqc(id: &str) -> bool {
    alg(id).is_some()
}

/// The ids, optionally of one use.
pub fn alg_ids(usage: Option<Use>) -> Vec<&'static str> {
    ALGS.iter()
        .filter(|a| usage.is_none_or(|u| a.usage == u))
        .map(|a| a.id)
        .collect()
}

fn known(id: &str) -> CryptoResult<&'static Alg> {
    alg(id).ok_or_else(|| {
        err(format!(
            "Not a post-quantum algorithm this build knows: {}",
            id
        ))
    })
}

/// AlgorithmIdentifier with its parameters ABSENT.
pub fn algorithm_identifier(oid: &str) -> CryptoResult<Vec<u8>> {
    Ok(der::sequence(&[der::oid(oid)?]))
}

/// A SubjectPublicKeyInfo.
pub fn encode_spki(id: &str, public: &[u8]) -> CryptoResult<Vec<u8>> {
    let a = known(id)?;
    Ok(der::sequence(&[
        algorithm_identifier(a.oid)?,
        der::bit_string(public),
    ]))
}

/// `(algorithm, public key)` when a SubjectPublicKeyInfo is one of ours,
/// `None` otherwise — so a caller can try this first.
pub fn decode_spki(spki: &[u8]) -> Option<(&'static Alg, Vec<u8>)> {
    let outer = der::read(spki)?;
    let parts = der::children(outer.content)?;
    let alg_seq = der::children(parts.first()?.content)?;
    let oid = der::oid_string(alg_seq.first()?.content)?;
    let a = alg_for_oid(&oid)?;
    let bits = parts.get(1)?.content;
    Some((a, bits.get(1..)?.to_vec()))
}

/// The PKCS#8 CHOICE arm for ML-DSA and ML-KEM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateForm {
    Seed,
    ExpandedKey,
    Both,
}

fn seed_len(a: &Alg) -> usize {
    if a.family == Family::MlKem {
        64
    } else {
        32
    }
}

fn kem_key_type(name: &str) -> KeyType {
    match name {
        "ML-KEM-512" => KeyType::ML_KEM_512,
        "ML-KEM-768" => KeyType::ML_KEM_768,
        _ => KeyType::ML_KEM_1024,
    }
}

/// The private key of an ML-DSA (32-byte) or ML-KEM (64-byte) seed.
fn from_seed(a: &Alg, seed: &[u8]) -> CryptoResult<PKey<Private>> {
    if a.family == Family::MlKem {
        return Ok(PKey::private_key_from_seed(
            None,
            kem_key_type(a.id),
            None,
            seed,
        )?);
    }
    crate::jws::ml_dsa_private(a.id, seed)
}

/// The expanded secret key of a seed (FIPS 204 algorithm 6, FIPS 203
/// algorithm 16).
pub fn expand_private(id: &str, seed: &[u8]) -> CryptoResult<Vec<u8>> {
    Ok(from_seed(known(id)?, seed)?.raw_private_key()?)
}

/// A PKCS#8 OneAsymmetricKey: the seed arm by default; SLH-DSA and the
/// composites carry their raw serialization and ignore `form`.
pub fn encode_pkcs8(
    id: &str,
    private: &[u8],
    form: Option<PrivateForm>,
) -> CryptoResult<Vec<u8>> {
    let a = known(id)?;
    let content = match a.family {
        Family::SlhDsa | Family::Composite => private.to_vec(),
        _ => match form.unwrap_or(PrivateForm::Seed) {
            PrivateForm::Seed => {
                if private.len() != seed_len(a) {
                    return Err(err(format!(
                        "The seed arm of {} is {} bytes; this key is {}. Pass the seed, not the expanded key.",
                        a.id,
                        seed_len(a),
                        private.len()
                    )));
                }
                der::context(0, false, private)
            }
            PrivateForm::ExpandedKey => {
                der::octet_string(&expand_private(id, private)?)
            }
            PrivateForm::Both => der::sequence(&[
                der::octet_string(private),
                der::octet_string(&expand_private(id, private)?),
            ]),
        },
    };
    Ok(der::sequence(&[
        der::small_integer(0),
        algorithm_identifier(a.oid)?,
        der::octet_string(&content),
    ]))
}

/// A PKCS#8 read back: the key in the one form this module signs with —
/// the seed for ML-DSA and ML-KEM, the raw key otherwise — and the expanded
/// key where the file carried one.
#[derive(Clone, Debug)]
pub struct DecodedPrivate {
    pub alg: &'static Alg,
    pub private: Option<Vec<u8>>,
    pub expanded: Option<Vec<u8>>,
    pub form: &'static str,
}

/// `Ok(None)` when the key is not one of ours; an error for one of ours in
/// a shape RFC 9881 section 6 does not define.
pub fn decode_pkcs8(pkcs8: &[u8]) -> CryptoResult<Option<DecodedPrivate>> {
    let Some(parts) = der::read(pkcs8).and_then(|e| der::children(e.content))
    else {
        return Ok(None);
    };
    if parts.len() < 3 {
        return Ok(None);
    }
    let Some(a) = der::children(parts[1].content)
        .and_then(|s| s.first().and_then(|o| der::oid_string(o.content)))
        .and_then(|o| alg_for_oid(&o))
    else {
        return Ok(None);
    };
    let content = parts[2].content;
    if matches!(a.family, Family::SlhDsa | Family::Composite) {
        return Ok(Some(DecodedPrivate {
            alg: a,
            private: Some(content.to_vec()),
            expanded: None,
            form: "raw",
        }));
    }
    let bad = || {
        err(format!("The privateKey octets of this {} key are not one of the three CHOICE arms RFC 9881 section 6 defines.", a.id))
    };
    let inner = der::read(content).ok_or_else(bad)?;
    match inner.tag {
        0x80 => Ok(Some(DecodedPrivate {
            alg: a,
            private: Some(inner.content.to_vec()),
            expanded: None,
            form: "seed",
        })),
        der::OCTET_STRING => Ok(Some(DecodedPrivate {
            alg: a,
            private: None,
            expanded: Some(inner.content.to_vec()),
            form: "expandedKey",
        })),
        der::SEQUENCE => {
            let both = der::children(inner.content).ok_or_else(bad)?;
            if both.len() != 2 {
                return Err(err(format!("The \"both\" arm of an {} private key is a SEQUENCE of exactly two OCTET STRINGs.", a.id)));
            }
            Ok(Some(DecodedPrivate {
                alg: a,
                private: Some(both[0].content.to_vec()),
                expanded: Some(both[1].content.to_vec()),
                form: "both",
            }))
        }
        _ => Err(err(format!(
            "Unrecognised private key CHOICE arm for {}.",
            a.id
        ))),
    }
}

// ---------------------------------------------------------------------------
// The traditional halves.
// ---------------------------------------------------------------------------

fn curve_nid(curve: &str) -> Nid {
    match curve {
        "P-256" => Nid::X9_62_PRIME256V1,
        "P-384" => Nid::SECP384R1,
        _ => Nid::SECP521R1,
    }
}

fn curve_oid(curve: &str) -> &'static str {
    match curve {
        "P-256" => "1.2.840.10045.3.1.7",
        "P-384" => "1.3.132.0.34",
        _ => "1.3.132.0.35",
    }
}

fn field_len(curve: &str) -> usize {
    match curve {
        "P-256" => 32,
        "P-384" => 48,
        _ => 66,
    }
}

/// RFC 5915 ECPrivateKey WITHOUT the public key, as the draft pins.
fn ec_private_key_der(curve: &str, scalar: &[u8]) -> CryptoResult<Vec<u8>> {
    Ok(der::sequence(&[
        der::small_integer(1),
        der::octet_string(scalar),
        der::context(0, true, &der::oid(curve_oid(curve))?),
    ]))
}

fn ec_scalar_from_der(curve: &str, ec_der: &[u8]) -> CryptoResult<Vec<u8>> {
    let parts = der::read(ec_der)
        .and_then(|e| der::children(e.content))
        .ok_or_else(|| err("The ECDSA half of this composite private key is not an ECPrivateKey."))?;
    if parts.len() < 2 {
        return Err(err("An ECPrivateKey has at least a version and a key."));
    }
    let raw = parts[1].content;
    let want = field_len(curve);
    let mut out = vec![0u8; want.saturating_sub(raw.len())];
    out.extend_from_slice(raw);
    Ok(out)
}

fn ec_private(curve: &str, scalar: &[u8]) -> CryptoResult<PKey<Private>> {
    let group = EcGroup::from_curve_name(curve_nid(curve))?;
    let d = BigNum::from_slice(scalar)?;
    let mut ctx = BigNumContext::new()?;
    let mut point = EcPoint::new(&group)?;
    point.mul_generator2(&group, &d, &mut ctx)?;
    Ok(PKey::from_ec_key(EcKey::from_private_components(
        &group, &d, &point,
    )?)?)
}

fn ec_public(curve: &str, point: &[u8]) -> CryptoResult<PKey<Public>> {
    let group = EcGroup::from_curve_name(curve_nid(curve))?;
    let mut ctx = BigNumContext::new()?;
    let p = EcPoint::from_bytes(&group, point, &mut ctx)?;
    Ok(PKey::from_ec_key(EcKey::from_public_key(&group, &p)?)?)
}

fn ec_point<T: openssl::pkey::HasPublic>(
    key: &EcKey<T>,
) -> CryptoResult<Vec<u8>> {
    let mut ctx = BigNumContext::new()?;
    Ok(key.public_key().to_bytes(
        key.group(),
        PointConversionForm::UNCOMPRESSED,
        &mut ctx,
    )?)
}

fn ed_id(ed448: bool) -> Id {
    if ed448 {
        Id::ED448
    } else {
        Id::ED25519
    }
}

// ---------------------------------------------------------------------------
// Composites.
// ---------------------------------------------------------------------------

const COMPOSITE_PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";

/// M' (section 2.2): the 0x00 is len(ctx) for X.509's empty context.
pub fn composite_message(
    c: &Composite,
    message: &[u8],
) -> CryptoResult<Vec<u8>> {
    let mut out = COMPOSITE_PREFIX.to_vec();
    out.extend_from_slice(c.label.as_bytes());
    out.push(0);
    match c.ph {
        Prehash::Sha256 => out.extend(
            openssl::hash::hash(MessageDigest::sha256(), message)?.to_vec(),
        ),
        Prehash::Sha512 => out.extend(
            openssl::hash::hash(MessageDigest::sha512(), message)?.to_vec(),
        ),
        Prehash::Shake256x64 => {
            let mut h = sha3::Shake256::default();
            h.update(message);
            let mut d = [0u8; 64];
            h.finalize_xof_into(&mut d);
            out.extend_from_slice(&d);
        }
    }
    Ok(out)
}

fn split_at_checked<'a>(
    all: &'a [u8],
    at: usize,
    what: &str,
    c: &Composite,
) -> CryptoResult<(&'a [u8], &'a [u8])> {
    if all.len() <= at {
        return Err(err(format!(
            "A {} {} is {} bytes of ML-DSA followed by the traditional {}; this one is {} bytes in total.",
            c.name,
            what,
            at,
            if what == "signature" { "signature" } else { "key" },
            all.len()
        )));
    }
    Ok(all.split_at(at))
}

/// A composite's public key from its private serialization.
fn composite_public(c: &Composite, private: &[u8]) -> CryptoResult<Vec<u8>> {
    if private.len() <= 32 {
        return Err(err(format!(
            "A {} private key is a 32-byte ML-DSA seed followed by the traditional key; this one is {} bytes in total.",
            c.name,
            private.len()
        )));
    }
    let (seed, trad) = private.split_at(32);
    let mut out =
        crate::jws::ml_dsa_private(c.mldsa, seed)?.raw_public_key()?;
    match c.trad {
        Trad::Ec { curve, .. } => {
            let key = ec_private(curve, &ec_scalar_from_der(curve, trad)?)?;
            let ec = key.ec_key()?;
            out.extend(ec_point(&ec)?);
        }
        Trad::Ed { ed448 } => {
            out.extend(
                PKey::private_key_from_raw_bytes(trad, ed_id(ed448))?
                    .raw_public_key()?,
            );
        }
        Trad::Rsa { .. } => {
            out.extend(
                Rsa::private_key_from_der(trad)?.public_key_to_der_pkcs1()?,
            );
        }
    }
    Ok(out)
}

fn trad_sign(
    c: &Composite,
    trad: &[u8],
    m_prime: &[u8],
) -> CryptoResult<Vec<u8>> {
    Ok(match c.trad {
        Trad::Ec { curve, sig_hash } => {
            let key = ec_private(curve, &ec_scalar_from_der(curve, trad)?)?;
            Signer::new(sig_hash.md(), &key)?.sign_oneshot_to_vec(m_prime)?
        }
        Trad::Ed { ed448 } => {
            let key = PKey::private_key_from_raw_bytes(trad, ed_id(ed448))?;
            Signer::new_without_digest(&key)?.sign_oneshot_to_vec(m_prime)?
        }
        Trad::Rsa {
            pss,
            sig_hash,
            salt,
            ..
        } => {
            let key = PKey::from_rsa(Rsa::private_key_from_der(trad)?)?;
            let mut s = Signer::new(sig_hash.md(), &key)?;
            if pss {
                s.set_rsa_padding(Padding::PKCS1_PSS)?;
                s.set_rsa_pss_saltlen(RsaPssSaltlen::custom(salt as i32))?;
                s.set_rsa_mgf1_md(sig_hash.md())?;
            }
            s.sign_oneshot_to_vec(m_prime)?
        }
    })
}

fn trad_verify(
    c: &Composite,
    public: &[u8],
    sig: &[u8],
    m_prime: &[u8],
) -> bool {
    let attempt = || -> CryptoResult<bool> {
        Ok(match c.trad {
            Trad::Ec { curve, sig_hash } => {
                let k = ec_public(curve, public)?;
                let mut v = Verifier::new(sig_hash.md(), &k)?;
                v.verify_oneshot(sig, m_prime)?
            }
            Trad::Ed { ed448 } => {
                let key =
                    PKey::public_key_from_raw_bytes(public, ed_id(ed448))?;
                let mut v = Verifier::new_without_digest(&key)?;
                v.verify_oneshot(sig, m_prime)?
            }
            Trad::Rsa {
                pss,
                sig_hash,
                salt,
                ..
            } => {
                let key =
                    PKey::from_rsa(Rsa::public_key_from_der_pkcs1(public)?)?;
                let mut v = Verifier::new(sig_hash.md(), &key)?;
                if pss {
                    v.set_rsa_padding(Padding::PKCS1_PSS)?;
                    v.set_rsa_pss_saltlen(RsaPssSaltlen::custom(salt as i32))?;
                    v.set_rsa_mgf1_md(sig_hash.md())?;
                }
                v.verify_oneshot(sig, m_prime)?
            }
        })
    };
    attempt().unwrap_or(false)
}

fn generate_composite(c: &Composite) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    let seed = random_bytes(32)?;
    let trad = match c.trad {
        Trad::Ec { curve, .. } => {
            let key = {
                let g = EcGroup::from_curve_name(curve_nid(curve))?;
                EcKey::generate(&g)?
            };
            let scalar =
                key.private_key().to_vec_padded(field_len(curve) as i32)?;
            ec_private_key_der(curve, &scalar)?
        }
        Trad::Ed { ed448 } => {
            let key = if ed448 {
                PKey::generate_ed448()?
            } else {
                PKey::generate_ed25519()?
            };
            key.raw_private_key()?
        }
        Trad::Rsa { bits, .. } => Rsa::generate(bits)?.private_key_to_der()?,
    };
    let mut private = seed;
    private.extend(trad);
    let public = composite_public(c, &private)?;
    Ok((public, private))
}

// ---------------------------------------------------------------------------
// The public API: one keygen, one sign, one verify, whatever the family.
// ---------------------------------------------------------------------------

/// `(public, private)` in this module's forms: the seed for ML-DSA and
/// ML-KEM, the raw key for SLH-DSA, the serialization for a composite.
pub fn generate_key_pair(id: &str) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    let a = known(id)?;
    match a.family {
        Family::Composite => {
            generate_composite(a.composite.ok_or_else(|| err("no composite"))?)
        }
        Family::MlDsa | Family::MlKem => {
            let seed = random_bytes(seed_len(a))?;
            Ok((from_seed(a, &seed)?.raw_public_key()?, seed))
        }
        Family::SlhDsa => {
            let key = pq::generate(a.id)?;
            Ok((key.raw_public_key()?, key.raw_private_key()?))
        }
    }
}

/// The public key that goes with a private one.
pub fn public_from_private(id: &str, private: &[u8]) -> CryptoResult<Vec<u8>> {
    let a = known(id)?;
    match a.family {
        Family::MlKem | Family::MlDsa => {
            Ok(from_seed(a, private)?.raw_public_key()?)
        }
        // FIPS 205 section 9.1: PK.seed || PK.root is the second half.
        Family::SlhDsa => Ok(private[private.len() / 2..].to_vec()),
        Family::Composite => composite_public(
            a.composite.ok_or_else(|| err("no composite"))?,
            private,
        ),
    }
}

fn signing_alg(id: &str, verb: &str) -> CryptoResult<&'static Alg> {
    alg(id)
        .filter(|a| a.usage == Use::Sig)
        .ok_or_else(|| err(format!("{} is not a post-quantum signature algorithm this build can {} with.", id, verb)))
}

/// A signature in any family.
pub fn sign(id: &str, message: &[u8], private: &[u8]) -> CryptoResult<Vec<u8>> {
    let a = signing_alg(id, "sign")?;
    match a.family {
        Family::Composite => {
            let c = a.composite.ok_or_else(|| err("no composite"))?;
            if private.len() <= 32 {
                return Err(err(format!(
                    "A {} private key is a 32-byte ML-DSA seed followed by the traditional key; this one is {} bytes in total.",
                    c.name,
                    private.len()
                )));
            }
            let (seed, trad) = private.split_at(32);
            let m_prime = composite_message(c, message)?;
            let ml_key = crate::jws::ml_dsa_private(c.mldsa, seed)?;
            // The label is the ML-DSA context as well as part of M'.
            let mut out = pq::sign_message(
                &ml_key,
                c.mldsa,
                &m_prime,
                Some(c.label.as_bytes()),
            )?;
            out.extend(trad_sign(c, trad, &m_prime)?);
            Ok(out)
        }
        Family::MlDsa => {
            let key = from_seed(a, private)?;
            pq::sign_message(&key, a.id, message, None)
        }
        _ => {
            let key = pq::private_from_raw(a.id, private)?;
            pq::sign_message(&key, a.id, message, None)
        }
    }
}

/// Whether a signature verifies; `false` for anything malformed. A
/// composite verifies only when BOTH halves do.
pub fn verify(
    id: &str,
    sig: &[u8],
    message: &[u8],
    public: &[u8],
) -> CryptoResult<bool> {
    let a = signing_alg(id, "verify")?;
    if a.family != Family::Composite {
        let key = match pq::public_from_raw(a.id, public) {
            Ok(k) => k,
            Err(_) => return Ok(false),
        };
        return Ok(
            pq::verify_message(&key, a.id, message, sig, None).unwrap_or(false)
        );
    }
    let c = a.composite.ok_or_else(|| err("no composite"))?;
    let (pk_len, sig_len) = ml_dsa_lengths(c.mldsa);
    let (Ok((ml_pub, trad_pub)), Ok((ml_sig, trad_sig))) = (
        split_at_checked(public, pk_len, "public key", c),
        split_at_checked(sig, sig_len, "signature", c),
    ) else {
        return Ok(false);
    };
    let m_prime = composite_message(c, message)?;
    let ml_ok = pq::public_from_raw(c.mldsa, ml_pub)
        .and_then(|k| {
            pq::verify_message(
                &k,
                c.mldsa,
                &m_prime,
                ml_sig,
                Some(c.label.as_bytes()),
            )
        })
        .unwrap_or(false);
    let trad_ok = trad_verify(c, trad_pub, trad_sig, &m_prime);
    Ok(ml_ok && trad_ok)
}

fn pem(der: &[u8], label: &str) -> String {
    let b64 = STANDARD.encode(der);
    let lines: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect();
    format!(
        "-----BEGIN {}-----\n{}\n-----END {}-----\n",
        label,
        lines.join("\n"),
        label
    )
}

pub fn public_pem(id: &str, public: &[u8]) -> CryptoResult<String> {
    Ok(pem(&encode_spki(id, public)?, "PUBLIC KEY"))
}

pub fn private_pem(
    id: &str,
    private: &[u8],
    form: Option<PrivateForm>,
) -> CryptoResult<String> {
    Ok(pem(&encode_pkcs8(id, private, form)?, "PRIVATE KEY"))
}

/// The label a page shows.
pub fn label_for(id: &str) -> String {
    match alg(id) {
        None => id.to_string(),
        Some(a) => match a.family {
            Family::Composite => format!(
                "{} (composite, draft)",
                a.name.trim_start_matches("id-")
            ),
            Family::MlKem => format!("{} (key establishment)", a.name),
            _ => a.name.to_string(),
        },
    }
}

/// A public key's PKey for a plain ML-DSA or SLH-DSA key in a
/// SubjectPublicKeyInfo — what a caller verifying with OpenSSL needs.
pub fn openssl_public(id: &str, public: &[u8]) -> CryptoResult<PKey<Public>> {
    pq::public_from_raw(known(id)?.id, public)
}

/// The private key of a seed or raw key, for a caller that signs with
/// OpenSSL directly.
pub fn openssl_private(
    id: &str,
    private: &[u8],
) -> CryptoResult<PKey<Private>> {
    let a = known(id)?;
    match a.family {
        Family::MlDsa | Family::MlKem => from_seed(a, private),
        Family::SlhDsa => pq::private_from_raw(a.id, private),
        Family::Composite => Err(err("a composite has no single OpenSSL key")),
    }
}

/// Whether OpenSSL knows a key — for a caller holding a [`PKeyRef`].
pub fn is_pq_key<T>(key: &PKeyRef<T>) -> Option<&'static Alg> {
    ALGS.iter()
        .find(|a| a.family != Family::Composite && pq::is_a(key, a.id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_signature_algorithm_round_trips() {
        for a in algs().iter().filter(|a| a.usage == Use::Sig) {
            // The large RSA and SLH-DSA "s" keys are slow; one of each.
            if a.id.contains("rsa4096")
                || (a.family == Family::SlhDsa
                    && a.id.ends_with('s')
                    && a.id != "SLH-DSA-SHA2-128s")
            {
                continue;
            }
            let (public, private) = generate_key_pair(a.id).unwrap();
            assert_eq!(
                public_from_private(a.id, &private).unwrap(),
                public,
                "{}",
                a.id
            );
            let sig = sign(a.id, b"message", &private).unwrap();
            assert!(
                verify(a.id, &sig, b"message", &public).unwrap(),
                "{}",
                a.id
            );
            assert!(
                !verify(a.id, &sig, b"messagE", &public).unwrap(),
                "{}",
                a.id
            );
            let spki = encode_spki(a.id, &public).unwrap();
            let (back, key) = decode_spki(&spki).unwrap();
            assert_eq!((back.id, key), (a.id, public.clone()));
            let p8 = encode_pkcs8(a.id, &private, None).unwrap();
            assert_eq!(
                decode_pkcs8(&p8).unwrap().unwrap().private.unwrap(),
                private
            );
        }
    }

    #[test]
    fn a_composite_needs_both_halves() {
        let id = "mldsa44-ed25519-sha512";
        let (public, private) = generate_key_pair(id).unwrap();
        let mut sig = sign(id, b"m", &private).unwrap();
        let last = sig.len() - 1;
        sig[last] ^= 1; // the Ed25519 half
        assert!(!verify(id, &sig, b"m", &public).unwrap());
    }

    #[test]
    fn the_three_arms() {
        let (_, seed) = generate_key_pair("ML-KEM-768").unwrap();
        for (form, name) in [
            (PrivateForm::Seed, "seed"),
            (PrivateForm::ExpandedKey, "expandedKey"),
            (PrivateForm::Both, "both"),
        ] {
            let d = decode_pkcs8(
                &encode_pkcs8("ML-KEM-768", &seed, Some(form)).unwrap(),
            )
            .unwrap()
            .unwrap();
            assert_eq!(d.form, name);
        }
        assert!(encode_pkcs8("ML-DSA-44", &[0u8; 31], None).is_err());
    }
}
