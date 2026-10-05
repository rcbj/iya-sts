// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE ONE JWS ALGORITHM TABLE (`common/crypto.js`'s `JWS_ALGS` and
//! `common/pq_jose.js`'s `PQ_ALGS`): every algorithm this service signs with
//! or verifies, and what it is made of. Every module that touches a JWS reads
//! this rather than keeping a table of its own — `dpop.ts` once had a second
//! one and accepted a different set from everything else for no reason
//! anybody chose.

use openssl::hash::MessageDigest;
use openssl::nid::Nid;

/// A digest, named as the table names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    Sha256,
    Sha384,
    Sha512,
    /// SHAKE256 with this many bytes of output.
    Shake256(usize),
}

impl Hash {
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha256 => openssl::sha::sha256(data).to_vec(),
            Hash::Sha384 => openssl::sha::sha384(data).to_vec(),
            Hash::Sha512 => openssl::sha::sha512(data).to_vec(),
            Hash::Shake256(length) => {
                let mut out = vec![0u8; length];
                match openssl::hash::hash_xof(
                    MessageDigest::shake_256(),
                    data,
                    &mut out,
                ) {
                    Ok(()) => out,
                    // SHAKE256 is in every OpenSSL this links; an error here
                    // is a broken library, and an empty digest matches
                    // nothing.
                    Err(_) => Vec::new(),
                }
            }
        }
    }

    pub fn message_digest(self) -> MessageDigest {
        match self {
            Hash::Sha256 => MessageDigest::sha256(),
            Hash::Sha384 => MessageDigest::sha384(),
            Hash::Sha512 => MessageDigest::sha512(),
            Hash::Shake256(_) => MessageDigest::shake_256(),
        }
    }

    pub fn output_len(self) -> usize {
        match self {
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
            Hash::Sha512 => 64,
            Hash::Shake256(length) => length,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Hash::Sha256 => "sha256",
            Hash::Sha384 => "sha384",
            Hash::Sha512 => "sha512",
            Hash::Shake256(_) => "shake256",
        }
    }
}

/// The traditional half of a composite (draft-ietf-jose-pq-composite-sigs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Traditional {
    Es256,
    Es384,
    Ed25519,
    Ed448,
}

impl Traditional {
    /// The public key as the composite carries it: `x || y` for the EC
    /// curves (no 0x04 prefix), the raw key for EdDSA.
    pub fn public_len(self) -> usize {
        match self {
            Traditional::Es256 => 64,
            Traditional::Es384 => 96,
            Traditional::Ed25519 => 32,
            Traditional::Ed448 => 57,
        }
    }

    pub fn private_len(self) -> usize {
        match self {
            Traditional::Es256 => 32,
            Traditional::Es384 => 48,
            Traditional::Ed25519 => 32,
            Traditional::Ed448 => 57,
        }
    }

    pub fn signature_len(self) -> usize {
        match self {
            Traditional::Es256 => 64,
            Traditional::Es384 => 96,
            Traditional::Ed25519 => 64,
            Traditional::Ed448 => 114,
        }
    }
}

/// A composite: its ML-DSA half, its traditional half, the prehash and the
/// domain-separation label (which is also the ML-DSA context string).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Composite {
    pub ml_dsa: &'static str,
    pub traditional: Traditional,
    pub prehash: Hash,
    pub label: &'static str,
}

/// What a row is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Hmac(Hash),
    /// RSASSA-PKCS1-v1_5.
    Rsa(Hash),
    /// RSASSA-PSS, MGF1 with the same hash, salt the hash's length.
    RsaPss(Hash),
    /// ECDSA with the R||S signature of RFC 7518 section 3.4.
    Ec {
        hash: Hash,
        curve: Nid,
        crv: &'static str,
        signature_len: usize,
    },
    /// EdDSA (RFC 8037): Ed25519 or Ed448, by the key.
    EdDsa,
    /// ML-DSA (RFC 9964): the OpenSSL name, the public key and signature
    /// sizes.
    MlDsa {
        name: &'static str,
        public_len: usize,
        signature_len: usize,
    },
    /// SLH-DSA (RFC 9964): the OpenSSL name.
    SlhDsa {
        name: &'static str,
    },
    Composite(Composite),
}

/// A row of the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JwsAlg {
    pub name: &'static str,
    pub family: Family,
}

const fn row(name: &'static str, family: Family) -> JwsAlg {
    JwsAlg { name, family }
}

const fn ec(
    name: &'static str,
    hash: Hash,
    curve: Nid,
    crv: &'static str,
    signature_len: usize,
) -> JwsAlg {
    row(
        name,
        Family::Ec {
            hash,
            curve,
            crv,
            signature_len,
        },
    )
}

const fn ml(
    name: &'static str,
    public_len: usize,
    signature_len: usize,
) -> JwsAlg {
    row(
        name,
        Family::MlDsa {
            name,
            public_len,
            signature_len,
        },
    )
}

const fn composite(
    name: &'static str,
    ml_dsa: &'static str,
    traditional: Traditional,
    prehash: Hash,
    label: &'static str,
) -> JwsAlg {
    row(
        name,
        Family::Composite(Composite {
            ml_dsa,
            traditional,
            prehash,
            label,
        }),
    )
}

/// Every algorithm, in `crypto.js`'s order: the classical rows, then the
/// post-quantum ones as `pq_jose.js` lists them.
pub static ALGS: [JwsAlg; 25] = [
    row("HS256", Family::Hmac(Hash::Sha256)),
    row("HS384", Family::Hmac(Hash::Sha384)),
    row("HS512", Family::Hmac(Hash::Sha512)),
    row("RS256", Family::Rsa(Hash::Sha256)),
    row("RS384", Family::Rsa(Hash::Sha384)),
    row("RS512", Family::Rsa(Hash::Sha512)),
    row("PS256", Family::RsaPss(Hash::Sha256)),
    row("PS384", Family::RsaPss(Hash::Sha384)),
    row("PS512", Family::RsaPss(Hash::Sha512)),
    ec("ES256", Hash::Sha256, Nid::X9_62_PRIME256V1, "P-256", 64),
    ec("ES384", Hash::Sha384, Nid::SECP384R1, "P-384", 96),
    ec("ES512", Hash::Sha512, Nid::SECP521R1, "P-521", 132),
    ec("ES256K", Hash::Sha256, Nid::SECP256K1, "secp256k1", 64),
    row("EdDSA", Family::EdDsa),
    ml("ML-DSA-44", 1312, 2420),
    ml("ML-DSA-65", 1952, 3309),
    ml("ML-DSA-87", 2592, 4627),
    row(
        "SLH-DSA-SHA2-128s",
        Family::SlhDsa {
            name: "SLH-DSA-SHA2-128s",
        },
    ),
    row(
        "SLH-DSA-SHAKE-128s",
        Family::SlhDsa {
            name: "SLH-DSA-SHAKE-128s",
        },
    ),
    composite(
        "ML-DSA-44-ES256",
        "ML-DSA-44",
        Traditional::Es256,
        Hash::Sha256,
        "COMPSIG-MLDSA44-ECDSA-P256-SHA256",
    ),
    composite(
        "ML-DSA-65-ES256",
        "ML-DSA-65",
        Traditional::Es256,
        Hash::Sha512,
        "COMPSIG-MLDSA65-ECDSA-P256-SHA512",
    ),
    composite(
        "ML-DSA-87-ES384",
        "ML-DSA-87",
        Traditional::Es384,
        Hash::Sha512,
        "COMPSIG-MLDSA87-ECDSA-P384-SHA512",
    ),
    composite(
        "ML-DSA-44-Ed25519",
        "ML-DSA-44",
        Traditional::Ed25519,
        Hash::Sha512,
        "COMPSIG-MLDSA44-Ed25519-SHA512",
    ),
    composite(
        "ML-DSA-65-Ed25519",
        "ML-DSA-65",
        Traditional::Ed25519,
        Hash::Sha512,
        "COMPSIG-MLDSA65-Ed25519-SHA512",
    ),
    composite(
        "ML-DSA-87-Ed448",
        "ML-DSA-87",
        Traditional::Ed448,
        Hash::Shake256(64),
        "COMPSIG-MLDSA87-Ed448-SHAKE256",
    ),
];

impl JwsAlg {
    /// The row for a name, or `None` for one this service does not speak.
    pub fn by_name(name: &str) -> Option<&'static JwsAlg> {
        ALGS.iter().find(|alg| alg.name == name)
    }

    /// Never a MAC (and never `none`, which is not a row): what DPoP proofs,
    /// OID4VCI proofs and request objects must be signed with.
    pub fn is_asymmetric(&self) -> bool {
        !matches!(self.family, Family::Hmac(_))
    }

    /// ML-DSA, SLH-DSA or a composite: RFC 9964's `AKP` key type.
    pub fn is_post_quantum(&self) -> bool {
        matches!(
            self.family,
            Family::MlDsa { .. } | Family::SlhDsa { .. } | Family::Composite(_)
        )
    }

    /// The hash an ID Token's `at_hash`, `c_hash` and `s_hash` use (OIDC
    /// Core 3.1.3.6; #118): the alg's own, and where it names none, the hash
    /// of the same security level — Ed25519 SHA-512, ML-DSA by NIST
    /// category, SLH-DSA-128s SHA-256, a composite its traditional half's
    /// (Ed448's SHAKE256 with 114 bytes).
    pub fn id_token_hash(&self) -> Hash {
        match self.family {
            Family::Hmac(hash)
            | Family::Rsa(hash)
            | Family::RsaPss(hash)
            | Family::Ec { hash, .. } => hash,
            Family::EdDsa => Hash::Sha512,
            Family::MlDsa { name, .. } => match name {
                "ML-DSA-44" => Hash::Sha256,
                "ML-DSA-65" => Hash::Sha384,
                _ => Hash::Sha512,
            },
            Family::SlhDsa { .. } => Hash::Sha256,
            Family::Composite(c) => match c.traditional {
                Traditional::Es256 => Hash::Sha256,
                Traditional::Es384 => Hash::Sha384,
                Traditional::Ed25519 => Hash::Sha512,
                Traditional::Ed448 => Hash::Shake256(114),
            },
        }
    }
}

/// Every signing algorithm's name.
pub fn signing_algs() -> Vec<&'static str> {
    ALGS.iter().map(|alg| alg.name).collect()
}

/// The asymmetric ones.
pub fn asymmetric_algs() -> Vec<&'static str> {
    ALGS.iter()
        .filter(|alg| alg.is_asymmetric())
        .map(|alg| alg.name)
        .collect()
}

/// `at_hash` / `c_hash` / `s_hash`: the base64url of the left half of the
/// ID Token alg's hash of `value`'s ASCII octets. An unknown alg is SHA-256,
/// which every client can check.
pub fn id_token_half_hash(value: &str, alg: &str) -> String {
    let hash = JwsAlg::by_name(alg)
        .map(JwsAlg::id_token_hash)
        .unwrap_or(Hash::Sha256);
    let digest = hash.digest(value.as_bytes());
    crate::b64::encode(&digest[..digest.len() / 2])
}
