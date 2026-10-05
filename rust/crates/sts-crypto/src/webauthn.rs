// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! WebAuthn's COSE signatures and the attestation structures:
//! `common/crypto.js` section 10 (#105).
//!
//! * [`verify_cose_signature`] — one table for every COSE signature
//!   algorithm an authenticator can use (RFC 9053, 8230, 8812, 9864, 9964):
//!   ES256/384/512 and the fully specified ESP256/384/512 and ES256K, whose
//!   curve is CHECKED against the key; EdDSA, Ed25519 and Ed448; RS256/384/
//!   512 and PS256/384/512 at 2048 bits or more; ML-DSA-44/65/87; and RS1,
//!   refused unless the caller allows insecure algorithms.
//! * The TPM 2.0 structures a `tpm` statement carries (Library Part 2):
//!   TPMT_PUBLIC, TPMS_ATTEST, TPMT_SIGNATURE and an object's Name.
//! * The certificate extensions the formats read: FIDO's AAGUID, Apple's
//!   nonce, Android's KeyDescription; and draft-ietf-lamps-csr-attestation's
//!   AttestationBundle with the TCG tpm-certify statement.
//!
//! **ONE DIFFERENCE FROM NODE, AND IT IS A FIX.** Node builds a TPM ECDSA
//! signature's DER with asn1js from `0x00 || r` and `0x00 || s`, and asn1js
//! keeps the zero: whenever an integer's top bit is clear the encoding is
//! not minimal, and Node's own OpenSSL then refuses the signature — about
//! three TPM ECDSA signatures in four. Here the integers are minimal.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::{Id, PKey, Public};
use openssl::rsa::Padding;
use openssl::sign::{RsaPssSaltlen, Verifier};
use serde_json::{json, Value as Json};

use crate::der_lite as der;
use crate::keys::{JwsKey, KeyPolicy};
use crate::pq;
use crate::raw_sig::DescribedKey;

/// How a COSE algorithm signs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoseFamily {
    Ecdsa,
    EdDsa,
    RsaPkcs1,
    RsaPss,
    MlDsa,
}

/// One COSE signature algorithm.
#[derive(Clone, Copy, Debug)]
pub struct CoseAlg {
    pub id: i64,
    pub name: &'static str,
    pub family: CoseFamily,
    pub hash: Option<&'static str>,
    pub kty: &'static str,
    pub salt: usize,
    /// A fully specified ECDSA algorithm's curve (OpenSSL's short name).
    pub curve: Option<&'static str>,
    /// A fully specified EdDSA algorithm's key type.
    pub okp: Option<Id>,
    pub insecure: bool,
}

const fn alg(
    id: i64,
    name: &'static str,
    family: CoseFamily,
    hash: Option<&'static str>,
    kty: &'static str,
) -> CoseAlg {
    CoseAlg {
        id,
        name,
        family,
        hash,
        kty,
        salt: 0,
        curve: None,
        okp: None,
        insecure: false,
    }
}

/// The COSE signature algorithms WebAuthn verifies, in Node's order.
pub const COSE_SIGNATURE_ALGS: [CoseAlg; 20] = [
    alg(-7, "ES256", CoseFamily::Ecdsa, Some("sha256"), "EC"),
    alg(-35, "ES384", CoseFamily::Ecdsa, Some("sha384"), "EC"),
    alg(-36, "ES512", CoseFamily::Ecdsa, Some("sha512"), "EC"),
    alg(-8, "EdDSA", CoseFamily::EdDsa, None, "OKP"),
    alg(-257, "RS256", CoseFamily::RsaPkcs1, Some("sha256"), "RSA"),
    alg(-258, "RS384", CoseFamily::RsaPkcs1, Some("sha384"), "RSA"),
    alg(-259, "RS512", CoseFamily::RsaPkcs1, Some("sha512"), "RSA"),
    CoseAlg {
        salt: 32,
        ..alg(-37, "PS256", CoseFamily::RsaPss, Some("sha256"), "RSA")
    },
    CoseAlg {
        salt: 48,
        ..alg(-38, "PS384", CoseFamily::RsaPss, Some("sha384"), "RSA")
    },
    CoseAlg {
        salt: 64,
        ..alg(-39, "PS512", CoseFamily::RsaPss, Some("sha512"), "RSA")
    },
    alg(-48, "ML-DSA-44", CoseFamily::MlDsa, None, "AKP"),
    alg(-49, "ML-DSA-65", CoseFamily::MlDsa, None, "AKP"),
    alg(-50, "ML-DSA-87", CoseFamily::MlDsa, None, "AKP"),
    CoseAlg {
        curve: Some("prime256v1"),
        ..alg(-9, "ESP256", CoseFamily::Ecdsa, Some("sha256"), "EC")
    },
    CoseAlg {
        curve: Some("secp384r1"),
        ..alg(-51, "ESP384", CoseFamily::Ecdsa, Some("sha384"), "EC")
    },
    CoseAlg {
        curve: Some("secp521r1"),
        ..alg(-52, "ESP512", CoseFamily::Ecdsa, Some("sha512"), "EC")
    },
    CoseAlg {
        curve: Some("secp256k1"),
        ..alg(-47, "ES256K", CoseFamily::Ecdsa, Some("sha256"), "EC")
    },
    CoseAlg {
        okp: Some(Id::ED25519),
        ..alg(-19, "Ed25519", CoseFamily::EdDsa, None, "OKP")
    },
    CoseAlg {
        okp: Some(Id::ED448),
        ..alg(-53, "Ed448", CoseFamily::EdDsa, None, "OKP")
    },
    CoseAlg {
        insecure: true,
        ..alg(-65535, "RS1", CoseFamily::RsaPkcs1, Some("sha1"), "RSA")
    },
];

/// The COSE entry for an identifier.
pub fn cose_signature_alg(id: i64) -> Option<&'static CoseAlg> {
    COSE_SIGNATURE_ALGS.iter().find(|a| a.id == id)
}

/// A key to verify a COSE signature with, in the forms callers hold.
pub enum CoseKey<'a> {
    /// A certificate's key, as [`crate::raw_sig::public_key_from_spki`]
    /// reads it.
    Spki(&'a DescribedKey),
    /// A JWK (EC, RSA, OKP, or AKP with `pub`).
    Jwk(&'a Json),
    /// An OpenSSL key.
    Public(&'a PKey<Public>),
    /// An ML-DSA public key's raw bytes.
    Raw(&'a [u8]),
}

/// What the caller decides: the mode's RSA floor and RS1.
#[derive(Clone, Copy, Debug)]
pub struct CoseOptions {
    /// `webauthn.insecureAlgorithms` (development only): accept RS1.
    pub allow_insecure: bool,
    /// The mode's key policy: development accepts an RSA key under 2048.
    pub policy: KeyPolicy,
}

impl Default for CoseOptions {
    /// Product's answer: no RS1, and the 2048-bit floor.
    fn default() -> CoseOptions {
        CoseOptions {
            allow_insecure: false,
            policy: KeyPolicy::STRICT,
        }
    }
}

fn md_named(name: &str) -> MessageDigest {
    match name {
        "sha1" => MessageDigest::sha1(),
        "sha384" => MessageDigest::sha384(),
        "sha512" => MessageDigest::sha512(),
        _ => MessageDigest::sha256(),
    }
}

/// `verifyCoseSignature()`: whether `signature` verifies over `data` under
/// a COSE algorithm. A key of the wrong kind is `false`, never an error.
pub fn verify_cose_signature(
    cose_alg: i64,
    key: CoseKey,
    data: &[u8],
    signature: &[u8],
    o: &CoseOptions,
) -> bool {
    let Some(spec) = cose_signature_alg(cose_alg) else {
        return false;
    };
    if spec.insecure && !o.allow_insecure {
        return false;
    }
    if spec.family == CoseFamily::MlDsa {
        let public: Option<Vec<u8>> = match key {
            CoseKey::Spki(d) => crate::pq_x509::decode_spki(&d.spki)
                .filter(|(a, _)| a.id == spec.name)
                .map(|(_, p)| p),
            CoseKey::Jwk(j) => {
                j.get("pub").and_then(Json::as_str).and_then(|p| {
                    URL_SAFE_NO_PAD.decode(p.trim_end_matches('=')).ok()
                })
            }
            CoseKey::Raw(b) => Some(b.to_vec()),
            CoseKey::Public(k) => k.raw_public_key().ok(),
        };
        return public
            .and_then(|p| pq::public_from_raw(spec.name, &p).ok())
            .and_then(|k| {
                pq::verify_message(&k, spec.name, data, signature, None).ok()
            })
            .unwrap_or(false);
    }
    let public: Option<PKey<Public>> = match key {
        CoseKey::Spki(d) => d.key.clone(),
        CoseKey::Public(k) => Some(k.clone()),
        CoseKey::Jwk(j) => {
            let mut jwk = j.clone();
            if let Some(obj) = jwk.as_object_mut() {
                obj.remove("alg");
            }
            JwsKey::from_jwk(&jwk).and_then(|k| k.public_key()).ok()
        }
        CoseKey::Raw(b) => PKey::public_key_from_der(b).ok(),
    };
    let Some(public) = public else {
        return false;
    };
    if crate::keys::rsa_key_problem(&public, 2048, o.policy).is_some()
        && matches!(public.id(), Id::RSA | Id::RSA_PSS)
    {
        return false;
    }
    if let Some(curve) = spec.curve {
        let have = public
            .ec_key()
            .ok()
            .and_then(|e| e.group().curve_name())
            .and_then(|n| n.short_name().ok());
        if have != Some(curve) {
            return false;
        }
    }
    if spec.okp.is_some_and(|okp| public.id() != okp) {
        return false;
    }
    let attempt = || -> Result<bool, openssl::error::ErrorStack> {
        let md = md_named(spec.hash.unwrap_or("sha256"));
        Ok(match (spec.family, public.id()) {
            (CoseFamily::Ecdsa, Id::EC) => {
                Verifier::new(md, &public)?.verify_oneshot(signature, data)?
            }
            (CoseFamily::EdDsa, Id::ED25519 | Id::ED448) => {
                Verifier::new_without_digest(&public)?
                    .verify_oneshot(signature, data)?
            }
            (CoseFamily::RsaPkcs1, Id::RSA) => {
                let mut v = Verifier::new(md, &public)?;
                v.set_rsa_padding(Padding::PKCS1)?;
                v.verify_oneshot(signature, data)?
            }
            (CoseFamily::RsaPss, Id::RSA | Id::RSA_PSS) => {
                let mut v = Verifier::new(md, &public)?;
                v.set_rsa_padding(Padding::PKCS1_PSS)?;
                v.set_rsa_mgf1_md(md)?;
                v.set_rsa_pss_saltlen(RsaPssSaltlen::custom(spec.salt as i32))?;
                v.verify_oneshot(signature, data)?
            }
            _ => false,
        })
    };
    attempt().unwrap_or(false)
}

// ---------------------------------------------------------------------------
// TPM 2.0.
// ---------------------------------------------------------------------------

/// TPM_ALG_ID values the structures name.
pub mod tpm_alg {
    pub const RSA: u16 = 0x0001;
    pub const SHA1: u16 = 0x0004;
    pub const SHA256: u16 = 0x000b;
    pub const SHA384: u16 = 0x000c;
    pub const SHA512: u16 = 0x000d;
    pub const NULL: u16 = 0x0010;
    pub const RSASSA: u16 = 0x0014;
    pub const RSAPSS: u16 = 0x0016;
    pub const ECDSA: u16 = 0x0018;
    pub const ECDAA: u16 = 0x001a;
    pub const ECC: u16 = 0x0023;
}

/// TPM_GENERATED_VALUE, a TPMS_ATTEST's magic.
pub const TPM_GENERATED_VALUE: u32 = 0xff54_4347;
/// TPM_ST_ATTEST_CERTIFY.
pub const TPM_ST_ATTEST_CERTIFY: u16 = 0x8017;

struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

const TRUNCATED: &str = "the TPM structure is truncated";

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.at + n > self.buf.len() {
            return Err(TRUNCATED.to_string());
        }
        let out = &self.buf[self.at..self.at + n];
        self.at += n;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Result<u64, String> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }
    fn sized(&mut self) -> Result<Vec<u8>, String> {
        let n = self.u16()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn left(&self) -> usize {
        self.buf.len() - self.at
    }
}

/// OpenSSL's digest for a TPM hash algorithm.
pub fn tpm_hash(alg: u16) -> Result<MessageDigest, String> {
    Ok(match alg {
        tpm_alg::SHA1 => MessageDigest::sha1(),
        tpm_alg::SHA256 => MessageDigest::sha256(),
        tpm_alg::SHA384 => MessageDigest::sha384(),
        tpm_alg::SHA512 => MessageDigest::sha512(),
        _ => {
            return Err(format!(
                "the TPM hash algorithm 0x{:x} is not supported",
                alg
            ))
        }
    })
}

/// A TPMT_PUBLIC for an RSA or ECC object.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TpmPublic {
    pub object_type: u16,
    pub name_alg: u16,
    pub attributes: u32,
    pub auth_policy: Vec<u8>,
    pub symmetric: u16,
    pub scheme: u16,
    pub scheme_hash: u16,
    pub key_bits: u16,
    pub exponent: u32,
    pub curve_id: u16,
    pub kdf: u16,
    pub modulus: Vec<u8>,
    pub x: Vec<u8>,
    pub y: Vec<u8>,
    /// The bytes a Name hashes.
    pub raw: Vec<u8>,
    /// The public key as a JWK.
    pub jwk: Json,
}

/// `tpmParsePublic()`: a TPMT_PUBLIC, never with a TPM2B size prefix.
pub fn tpm_parse_public(bytes: &[u8]) -> Result<TpmPublic, String> {
    let mut r = Reader { buf: bytes, at: 0 };
    let mut out = TpmPublic {
        object_type: r.u16()?,
        name_alg: r.u16()?,
        attributes: r.u32()?,
        auth_policy: r.sized()?,
        raw: bytes.to_vec(),
        ..TpmPublic::default()
    };
    let symmetric = |r: &mut Reader| -> Result<u16, String> {
        let a = r.u16()?;
        if a != tpm_alg::NULL {
            r.u16()?;
            r.u16()?;
        }
        Ok(a)
    };
    let b64 = |b: &[u8]| URL_SAFE_NO_PAD.encode(b);
    if out.object_type == tpm_alg::RSA {
        out.symmetric = symmetric(&mut r)?;
        out.scheme = r.u16()?;
        if out.scheme != tpm_alg::NULL {
            out.scheme_hash = r.u16()?;
        }
        out.key_bits = r.u16()?;
        out.exponent = r.u32()?;
        out.modulus = r.sized()?;
        let e = if out.exponent == 0 {
            65537
        } else {
            out.exponent
        }
        .to_be_bytes();
        let start = e.iter().take(3).take_while(|&&b| b == 0).count();
        out.jwk = json!({ "kty": "RSA", "n": b64(&out.modulus), "e": b64(&e[start..]) });
    } else if out.object_type == tpm_alg::ECC {
        out.symmetric = symmetric(&mut r)?;
        out.scheme = r.u16()?;
        if out.scheme != tpm_alg::NULL {
            out.scheme_hash = r.u16()?;
            if out.scheme == tpm_alg::ECDAA {
                r.u16()?;
            }
        }
        out.curve_id = r.u16()?;
        out.kdf = r.u16()?;
        if out.kdf != tpm_alg::NULL {
            r.u16()?;
        }
        out.x = r.sized()?;
        out.y = r.sized()?;
        let (crv, size) = match out.curve_id {
            3 => ("P-256", 32),
            4 => ("P-384", 48),
            5 => ("P-521", 66),
            c => {
                return Err(format!("the TPM curve 0x{:x} is not supported", c))
            }
        };
        let pad = |b: &[u8]| {
            let mut v = vec![0u8; size];
            v.extend_from_slice(b);
            v[v.len() - size..].to_vec()
        };
        out.jwk = json!({ "kty": "EC", "crv": crv, "x": b64(&pad(&out.x)), "y": b64(&pad(&out.y)) });
    } else {
        return Err(format!(
            "the TPM object type 0x{:x} is not an RSA or ECC key",
            out.object_type
        ));
    }
    if r.left() > 0 {
        return Err(format!("{} byte(s) follow the TPMT_PUBLIC", r.left()));
    }
    Ok(out)
}

/// A TPMS_ATTEST; `name` and `qualified_name` for a certify.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TpmAttest {
    pub magic: u32,
    pub attest_type: u16,
    pub qualified_signer: Vec<u8>,
    pub extra_data: Vec<u8>,
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: u8,
    pub firmware_version: u64,
    pub name: Option<Vec<u8>>,
    pub qualified_name: Option<Vec<u8>>,
}

/// `tpmParseAttest()`.
pub fn tpm_parse_attest(bytes: &[u8]) -> Result<TpmAttest, String> {
    let mut r = Reader { buf: bytes, at: 0 };
    let mut out = TpmAttest {
        magic: r.u32()?,
        attest_type: r.u16()?,
        qualified_signer: r.sized()?,
        extra_data: r.sized()?,
        clock: r.u64()?,
        reset_count: r.u32()?,
        restart_count: r.u32()?,
        safe: r.u8()?,
        firmware_version: r.u64()?,
        ..TpmAttest::default()
    };
    if out.attest_type == TPM_ST_ATTEST_CERTIFY {
        out.name = Some(r.sized()?);
        out.qualified_name = Some(r.sized()?);
        if r.left() > 0 {
            return Err(format!(
                "{} byte(s) follow the TPMS_CERTIFY_INFO",
                r.left()
            ));
        }
    }
    Ok(out)
}

/// A TPMT_SIGNATURE: the signature as a verifier takes it (RSA's bytes, an
/// ECDSA signature as minimal DER).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TpmSignature {
    pub sig_alg: u16,
    pub hash: u16,
    pub signature: Vec<u8>,
}

/// `tpmParseSignature()`: `None` when `bytes` is not exactly one such
/// structure, which is how a verifier tells it from a bare signature.
pub fn tpm_parse_signature(bytes: &[u8]) -> Option<TpmSignature> {
    let mut r = Reader { buf: bytes, at: 0 };
    let sig_alg = r.u16().ok()?;
    let out = match sig_alg {
        tpm_alg::RSASSA | tpm_alg::RSAPSS => TpmSignature {
            sig_alg,
            hash: r.u16().ok()?,
            signature: r.sized().ok()?,
        },
        tpm_alg::ECDSA => {
            let hash = r.u16().ok()?;
            let rr = BigNum::from_slice(&r.sized().ok()?).ok()?;
            let ss = BigNum::from_slice(&r.sized().ok()?).ok()?;
            TpmSignature {
                sig_alg,
                hash,
                signature: EcdsaSig::from_private_components(rr, ss)
                    .ok()?
                    .to_der()
                    .ok()?,
            }
        }
        _ => return None,
    };
    (r.left() == 0).then_some(out)
}

/// `tpmName()`: nameAlg || H_nameAlg(TPMT_PUBLIC).
pub fn tpm_name(public: &TpmPublic) -> Result<Vec<u8>, String> {
    let mut out = public.name_alg.to_be_bytes().to_vec();
    out.extend(
        hash(tpm_hash(public.name_alg)?, &public.raw)
            .map_err(|e| e.to_string())?
            .to_vec(),
    );
    Ok(out)
}

// ---------------------------------------------------------------------------
// Certificate extensions and the CSR attestation bundle.
// ---------------------------------------------------------------------------

/// id-fido-gen-ce-aaguid: the 16-byte AAGUID in an OCTET STRING.
pub fn fido_aaguid_extension(extn_value: &[u8]) -> Option<Vec<u8>> {
    let e = der::read(extn_value)?;
    (e.tag == der::OCTET_STRING && e.content.len() == 16)
        .then(|| e.content.to_vec())
}

/// Apple's nonce: SEQUENCE { [1] EXPLICIT OCTET STRING }.
pub fn apple_attestation_nonce(extn_value: &[u8]) -> Option<Vec<u8>> {
    let e = der::read(extn_value)?;
    let tagged = der::children(e.content)?
        .into_iter()
        .find(|c| c.class == 2 && c.number == 1)?;
    let inner = der::children(tagged.content)?.into_iter().next()?;
    (inner.tag == der::OCTET_STRING).then(|| inner.content.to_vec())
}

/// An AuthorizationList's three fields section 8.4 reads.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthorizationList {
    pub purpose: Vec<i64>,
    pub all_applications: bool,
    pub origin: Option<i64>,
}

/// Android's KeyDescription.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyDescription {
    pub attestation_version: Option<i64>,
    pub attestation_security_level: Option<i64>,
    pub attestation_challenge: Vec<u8>,
    pub software_enforced: AuthorizationList,
    pub tee_enforced: AuthorizationList,
}

fn authorization_list(e: &der::Element) -> AuthorizationList {
    let mut out = AuthorizationList::default();
    for field in der::children(e.content).unwrap_or_default() {
        if field.class != 2 {
            continue;
        }
        let inner =
            der::children(field.content).and_then(|c| c.into_iter().next());
        match field.number {
            1 => {
                if let Some(set) = inner {
                    out.purpose = der::children(set.content)
                        .unwrap_or_default()
                        .iter()
                        .filter_map(|i| der::integer_value(i.content))
                        .collect();
                }
            }
            600 => out.all_applications = true,
            702 => {
                out.origin = inner.and_then(|i| der::integer_value(i.content))
            }
            _ => {}
        }
    }
    out
}

/// `androidKeyDescription()`.
pub fn android_key_description(
    extn_value: &[u8],
) -> Result<KeyDescription, String> {
    let items = der::read(extn_value)
        .and_then(|e| der::children(e.content))
        .unwrap_or_default();
    if items.len() < 8 {
        return Err(format!(
            "the Android key attestation extension is not a KeyDescription (it has {} field(s), not 8)",
            items.len()
        ));
    }
    if items[4].tag != der::OCTET_STRING {
        return Err(
            "the KeyDescription's attestationChallenge is not an OCTET STRING"
                .to_string(),
        );
    }
    Ok(KeyDescription {
        attestation_version: der::integer_value(items[0].content),
        attestation_security_level: der::integer_value(items[1].content),
        attestation_challenge: items[4].content.to_vec(),
        software_enforced: authorization_list(&items[6]),
        tee_enforced: authorization_list(&items[7]),
    })
}

/// The id-aa-attestation attribute's OID.
pub const ID_AA_ATTESTATION: &str = "1.2.840.113549.1.9.16.2.59";
/// The tcg-attest-tpm-certify statement type's OID.
pub const TCG_ATTEST_TPM_CERTIFY: &str = "2.23.133.20.1";

/// One AttestationStatement: its type and the DER of its value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationStatement {
    pub statement_type: String,
    pub stmt: Vec<u8>,
}

/// A certificate request's AttestationBundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationBundle {
    pub attestations: Vec<AttestationStatement>,
    pub certs: Vec<Vec<u8>>,
    pub other_certs: usize,
}

/// `csrAttestationBundle()`.
pub fn csr_attestation_bundle(
    bytes: &[u8],
) -> Result<AttestationBundle, String> {
    let not_bundle = || {
        "the id-aa-attestation value is not an AttestationBundle".to_string()
    };
    let top = der::read(bytes)
        .filter(|e| e.tag == der::SEQUENCE)
        .ok_or_else(not_bundle)?;
    let items = der::children(top.content).ok_or_else(not_bundle)?;
    if items.is_empty() || items.len() > 2 || items[0].tag != der::SEQUENCE {
        return Err(not_bundle());
    }
    let mut attestations = Vec::new();
    for one in der::children(items[0].content).ok_or_else(not_bundle)? {
        let pair = if one.tag == der::SEQUENCE {
            der::children(one.content).unwrap_or_default()
        } else {
            Vec::new()
        };
        if pair.len() != 2 || pair[0].tag != der::OID {
            return Err(
                "an AttestationStatement is not { type, stmt }".to_string()
            );
        }
        attestations.push(AttestationStatement {
            statement_type: der::oid_string(pair[0].content)
                .unwrap_or_default(),
            stmt: pair[1].raw.to_vec(),
        });
    }
    if attestations.is_empty() {
        return Err(
            "the AttestationBundle carries no attestation (SIZE (1..MAX))"
                .to_string(),
        );
    }
    let (mut certs, mut other_certs) = (Vec::new(), 0);
    if let Some(list) = items.get(1) {
        let entries = (list.tag == der::SEQUENCE)
            .then(|| der::children(list.content))
            .flatten()
            .unwrap_or_default();
        if entries.is_empty() {
            return Err(
                "the AttestationBundle's certs is not a non-empty SEQUENCE"
                    .to_string(),
            );
        }
        for one in entries {
            if one.tag == der::SEQUENCE {
                certs.push(one.raw.to_vec());
            } else if one.class == 2 && one.number == 3 {
                other_certs += 1;
            } else {
                return Err("a certificate in the AttestationBundle is neither a Certificate nor an other format (the draft forbids the attribute-certificate choices)".to_string());
            }
        }
    }
    Ok(AttestationBundle {
        attestations,
        certs,
        other_certs,
    })
}

/// `tpm2bContents()`: a TPM2B's contents when the bytes are exactly one.
pub fn tpm2b_contents(bytes: &[u8]) -> &[u8] {
    if bytes.len() >= 2
        && u16::from_be_bytes([bytes[0], bytes[1]]) as usize == bytes.len() - 2
    {
        &bytes[2..]
    } else {
        bytes
    }
}

/// Tcg-csr-tpm-certify, TPM2B prefixes taken off.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcgTpmCertify {
    pub tpms_attest: Vec<u8>,
    pub signature: Vec<u8>,
    pub tpmt_public: Option<Vec<u8>>,
}

/// `tcgTpmCertifyStatement()`.
pub fn tcg_tpm_certify_statement(
    bytes: &[u8],
) -> Result<TcgTpmCertify, String> {
    let items = der::read(bytes)
        .filter(|e| e.tag == der::SEQUENCE)
        .and_then(|e| der::children(e.content))
        .unwrap_or_default();
    if items.len() < 2
        || items.len() > 3
        || items.iter().any(|i| i.tag != der::OCTET_STRING)
    {
        return Err("the tcg-attest-tpm-certify statement is not SEQUENCE { tpmSAttest, signature, tpmTPublic OPTIONAL }".to_string());
    }
    Ok(TcgTpmCertify {
        tpms_attest: tpm2b_contents(items[0].content).to_vec(),
        signature: items[1].content.to_vec(),
        tpmt_public: items.get(2).map(|i| tpm2b_contents(i.content).to_vec()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::sign::Signer;

    #[test]
    fn a_fully_specified_algorithm_checks_the_curve() {
        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let public =
            PKey::public_key_from_der(&key.public_key_to_der().unwrap())
                .unwrap();
        let sig = Signer::new(MessageDigest::sha256(), &key)
            .unwrap()
            .sign_oneshot_to_vec(b"d")
            .unwrap();
        let o = CoseOptions::default();
        assert!(verify_cose_signature(
            -7,
            CoseKey::Public(&public),
            b"d",
            &sig,
            &o
        ));
        assert!(!verify_cose_signature(
            -9,
            CoseKey::Public(&public),
            b"d",
            &sig,
            &o
        ));
    }

    #[test]
    fn a_tpm_ecdsa_signature_is_minimal_der() {
        // r = 0x01 0x02, s = 0x7f: both under the top bit.
        let mut t = vec![
            0x00, 0x18, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x02, 0x00, 0x01, 0x7f,
        ];
        let s = tpm_parse_signature(&t).unwrap();
        assert_eq!(
            s.signature,
            [0x30, 0x07, 0x02, 0x02, 0x01, 0x02, 0x02, 0x01, 0x7f]
        );
        t.push(0);
        assert!(tpm_parse_signature(&t).is_none());
    }
}
