// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! COSE_Sign1, THE ONE DOOR (#1368) — `common/crypto.js`'s
//! `coseSign1Sign()` and `coseSign1Verify()`. RFC 9052 section 4.4's
//! Sig_structure, signed and checked. A status-list CWT, a `vc+cose`
//! credential and an mdoc's IssuerAuth and DeviceAuth come through here;
//! the CBOR container around the signature stays with their codec, which
//! has the rest of the format to read.
//!
//! **WEBAUTHN DOES NOT**: a passkey signs authenticatorData, which is no
//! Sig_structure, and WebAuthn keeps its own two lists, so it asks
//! [`crate::webauthn::verify_cose_signature`] directly.
//!
//! An ECDSA signature here is IEEE P1363 (RFC 9053 section 2.1), never DER.
//! Both doors ask the realm's [`SignaturePolicy`] first — the accept cause
//! before any key operation, the sign cause after the broken-algorithm
//! refusal — and a refusal carries the policy's code beside its sentence.

use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::pkey::{Id, PKeyRef, Private};
use openssl::rsa::Padding;
use openssl::sign::{RsaPssSaltlen, Signer};

use crate::algorithms::{SignaturePolicy, Surface};
use crate::error::{CryptoError, CryptoResult};
use crate::keys::{JwsKey, Material};
use crate::webauthn::{
    cose_signature_alg, verify_cose_signature, CoseFamily, CoseKey, CoseOptions,
};

/// `cborHead()`: a CBOR head (RFC 8949 section 3), shortest form.
fn cbor_head(major: u8, length: usize) -> Vec<u8> {
    let top = major << 5;
    match length {
        0..=23 => vec![top | length as u8],
        24..=255 => vec![top | 24, length as u8],
        256..=65535 => {
            let mut out = vec![top | 25];
            out.extend((length as u16).to_be_bytes());
            out
        }
        _ => {
            let mut out = vec![top | 26];
            out.extend((length as u32).to_be_bytes());
            out
        }
    }
}

/// `coseSigStructure()`: `[ "Signature1", protected, external_aad,
/// payload ]`.
pub fn sig_structure(
    protected: &[u8],
    external: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let bstr = |bytes: &[u8]| [cbor_head(2, bytes.len()), bytes.to_vec()];
    let context = b"Signature1";
    [
        cbor_head(4, 4),
        cbor_head(3, context.len()),
        context.to_vec(),
    ]
    .into_iter()
    .chain(bstr(protected))
    .chain(bstr(external))
    .chain(bstr(payload))
    .flatten()
    .collect()
}

/// What a COSE_Sign1 signs: its encoded protected header, its payload,
/// and the external additional authenticated data (empty when there is
/// none).
#[derive(Clone, Copy, Debug, Default)]
pub struct Sign1<'a> {
    pub protected: &'a [u8],
    pub payload: &'a [u8],
    pub external: &'a [u8],
}

impl Sign1<'_> {
    /// Its Sig_structure.
    pub fn to_be_signed(&self) -> Vec<u8> {
        sig_structure(self.protected, self.external, self.payload)
    }
}

/// The private key a COSE_Sign1 is signed with: an OpenSSL key for the
/// classical algorithms, or a post-quantum key's raw bytes
/// (`pqPrivateBytes()`: the ML-DSA seed).
pub enum CoseSigningKey<'a> {
    Private(&'a PKeyRef<Private>),
    PostQuantum(&'a [u8]),
}

fn refused(policy_cause: Option<crate::algorithms::Cause>) -> CryptoResult<()> {
    match policy_cause {
        Some(cause) => Err(CryptoError::coded(cause.message, cause.code)),
        None => Ok(()),
    }
}

fn md_named(name: &str) -> MessageDigest {
    match name {
        "sha384" => MessageDigest::sha384(),
        "sha512" => MessageDigest::sha512(),
        "sha1" => MessageDigest::sha1(),
        _ => MessageDigest::sha256(),
    }
}

/// `coseSign1Sign()`: the signature over the Sig_structure. A broken
/// algorithm (RS1) is never signed with, and the realm's sign cause is
/// asked after that. It blocks for a post-quantum signature;
/// `coseSign1SignAsync()` is this under `spawn_blocking`.
pub fn cose_sign1_sign(
    cose_alg: i64,
    key: CoseSigningKey,
    message: &Sign1,
    policy: &dyn SignaturePolicy,
) -> CryptoResult<Vec<u8>> {
    let spec = cose_signature_alg(cose_alg)
        .filter(|spec| !spec.insecure)
        .ok_or_else(|| {
            CryptoError::new(format!(
                "COSE: this service does not sign with algorithm {}.",
                cose_alg
            ))
        })?;
    refused(policy.sign_cause(Surface::Cose, &cose_alg.to_string()))?;
    let tbs = message.to_be_signed();
    let wrong = || {
        CryptoError::new(format!(
            "COSE: a key of the wrong kind for algorithm {}.",
            spec.name
        ))
    };
    if spec.family == CoseFamily::MlDsa {
        let CoseSigningKey::PostQuantum(seed) = key else {
            return Err(wrong());
        };
        let jwk = JwsKey::of(Material::Akp {
            alg: Some(spec.name.to_string()),
            public: Vec::new(),
            private: Some(seed.to_vec()),
        });
        return crate::jws::sign_input(spec.name, &jwk, &tbs);
    }
    let CoseSigningKey::Private(private) = key else {
        return Err(wrong());
    };
    let md = md_named(spec.hash.unwrap_or("sha256"));
    match (spec.family, private.id()) {
        (CoseFamily::Ecdsa, Id::EC) => {
            let der = Signer::new(md, private)?.sign_oneshot_to_vec(&tbs)?;
            let width = private.ec_key()?.group().degree().div_ceil(8) as i32;
            let sig = EcdsaSig::from_der(&der)?;
            let mut out = sig.r().to_vec_padded(width)?;
            out.extend(sig.s().to_vec_padded(width)?);
            Ok(out)
        }
        (CoseFamily::EdDsa, Id::ED25519 | Id::ED448) => {
            Ok(Signer::new_without_digest(private)?
                .sign_oneshot_to_vec(&tbs)?)
        }
        (CoseFamily::RsaPkcs1, Id::RSA) => {
            let mut signer = Signer::new(md, private)?;
            signer.set_rsa_padding(Padding::PKCS1)?;
            Ok(signer.sign_oneshot_to_vec(&tbs)?)
        }
        (CoseFamily::RsaPss, Id::RSA | Id::RSA_PSS) => {
            let mut signer = Signer::new(md, private)?;
            signer.set_rsa_padding(Padding::PKCS1_PSS)?;
            signer.set_rsa_mgf1_md(md)?;
            signer
                .set_rsa_pss_saltlen(RsaPssSaltlen::custom(spec.salt as i32))?;
            Ok(signer.sign_oneshot_to_vec(&tbs)?)
        }
        _ => Err(wrong()),
    }
}

/// `coseSign1Verify()`: whether `signature` verifies over the
/// Sig_structure, the ECDSA signature as r||s. The realm's accept cause is
/// asked first, before any key is used, and is an error with its code; a
/// signature that does not verify, or a key of the wrong kind, is `false`.
/// `options` carries the mode's RSA floor and RS1, as for WebAuthn.
pub fn cose_sign1_verify(
    cose_alg: i64,
    key: CoseKey,
    message: &Sign1,
    signature: &[u8],
    options: &CoseOptions,
    policy: &dyn SignaturePolicy,
) -> CryptoResult<bool> {
    refused(policy.accept_cause(Surface::Cose, &cose_alg.to_string()))?;
    let options = CoseOptions {
        ecdsa_p1363: true,
        ..*options
    };
    Ok(verify_cose_signature(
        cose_alg,
        key,
        &message.to_be_signed(),
        signature,
        &options,
    ))
}
