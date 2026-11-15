// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! SCEP'S CRYPTOGRAPHY (`common/crypto.js` section 17, group F, #453):
//! the content cipher (`scepContentEncrypt()` / `scepContentDecrypt()`,
//! AES-CBC only, the closed list `SCEP_CONTENT_CIPHERS`), the RSA key
//! transport (`cmsKeyTransportDecrypt()` for PKCS#1 v1.5 or OAEP,
//! `cmsKeyTransportEncrypt()` for the reply), the messageDigest check
//! (`cmsMessageDigestMatches()`), and the SignerInfo signature
//! (`signBytes()` / `signatureValid()` over a digest named by SCEP).
//!
//! Named `pkcs7` (the syntax CMS grew from) rather than `cms`: the guard
//! that holds every other crate to sts-crypto reads `cms::` as the RustCrypto
//! crate of that name, and a caller's `sts_crypto::cms::` would read as it.
//!
//! **PKCS#1 v1.5 IS UNWRAPPED WITH OPENSSL'S IMPLICIT REJECTION** (3.2 and
//! later, which this build vendors): a padding that does not check unwraps
//! to a deterministic random value in the same time rather than failing —
//! the Marvin attack's countermeasure, and why `scep_cms.ts`'s caller has
//! one refusal where it could have had three. The envelope (the ASN.1,
//! the attribute tables, the refusals) is `sts-enroll`'s.

use openssl::encrypt::{Decrypter, Encrypter};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Padding;
use openssl::sign::{Signer, Verifier};
use openssl::symm::{Cipher, Crypter, Mode};

use crate::error::{CryptoError, CryptoResult};

/// The content ciphers SCEP accepts, by `crypto.js`'s id.
pub const SCEP_CONTENT_CIPHERS: &[&str] =
    &["aes-128-cbc", "aes-192-cbc", "aes-256-cbc"];

fn cipher(id: &str) -> CryptoResult<Cipher> {
    match id {
        "aes-128-cbc" => Ok(Cipher::aes_128_cbc()),
        "aes-192-cbc" => Ok(Cipher::aes_192_cbc()),
        "aes-256-cbc" => Ok(Cipher::aes_256_cbc()),
        other => Err(CryptoError::new(format!(
            "\"{}\" is not a SCEP content cipher; they are {}.",
            other,
            SCEP_CONTENT_CIPHERS.join(", ")
        ))),
    }
}

fn digest(id: &str) -> CryptoResult<MessageDigest> {
    match id {
        "sha1" => Ok(MessageDigest::sha1()),
        "sha256" => Ok(MessageDigest::sha256()),
        "sha384" => Ok(MessageDigest::sha384()),
        "sha512" => Ok(MessageDigest::sha512()),
        other => Err(CryptoError::new(format!(
            "\"{}\" is not a digest SCEP names.",
            other
        ))),
    }
}

fn run(
    id: &str,
    mode: Mode,
    key: &[u8],
    iv: &[u8],
    data: &[u8],
) -> CryptoResult<Vec<u8>> {
    let c = cipher(id)?;
    let mut crypter = Crypter::new(c, mode, key, Some(iv))?;
    crypter.pad(true);
    let mut out = vec![0u8; data.len() + c.block_size()];
    let mut n = crypter.update(data, &mut out)?;
    n += crypter.finalize(&mut out[n..])?;
    out.truncate(n);
    Ok(out)
}

/// `scepContentDecrypt(id, key, iv, ciphertext)`: PKCS#7 padding checked.
#[tracing::instrument(level = "debug", skip_all)]
pub fn scep_content_decrypt(
    id: &str,
    key: &[u8],
    iv: &[u8],
    data: &[u8],
) -> CryptoResult<Vec<u8>> {
    run(id, Mode::Decrypt, key, iv, data)
}

/// `scepContentEncrypt(id, key, iv, plaintext)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn scep_content_encrypt(
    id: &str,
    key: &[u8],
    iv: &[u8],
    data: &[u8],
) -> CryptoResult<Vec<u8>> {
    run(id, Mode::Encrypt, key, iv, data)
}

/// `cmsKeyTransportDecrypt('rsaes-pkcs1-v1_5' | 'rsaes-oaep', key, data,
/// hash)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn cms_key_transport_decrypt(
    scheme: &str,
    private_pem: &str,
    data: &[u8],
    oaep_hash: Option<&str>,
) -> CryptoResult<Vec<u8>> {
    let key = PKey::private_key_from_pem(private_pem.as_bytes())?;
    let mut d = Decrypter::new(&key)?;
    match scheme {
        "rsaes-pkcs1-v1_5" => d.set_rsa_padding(Padding::PKCS1)?,
        "rsaes-oaep" => {
            d.set_rsa_padding(Padding::PKCS1_OAEP)?;
            let md = digest(oaep_hash.unwrap_or("sha1"))?;
            d.set_rsa_oaep_md(md)?;
            d.set_rsa_mgf1_md(md)?;
        }
        other => {
            return Err(CryptoError::new(format!(
                "\"{}\" is not a key transport.",
                other
            )))
        }
    }
    let mut out = vec![0u8; d.decrypt_len(data)?];
    let n = d.decrypt(data, &mut out)?;
    out.truncate(n);
    Ok(out)
}

/// `cmsKeyTransportEncrypt(publicKey, key)`: RSAES-PKCS1-v1_5, what every
/// SCEP client decrypts.
#[tracing::instrument(level = "debug", skip_all)]
pub fn cms_key_transport_encrypt(
    public_spki_der: &[u8],
    data: &[u8],
) -> CryptoResult<Vec<u8>> {
    let key = PKey::public_key_from_der(public_spki_der)?;
    let mut e = Encrypter::new(&key)?;
    e.set_rsa_padding(Padding::PKCS1)?;
    let mut out = vec![0u8; e.encrypt_len(data)?];
    let n = e.encrypt(data, &mut out)?;
    out.truncate(n);
    Ok(out)
}

/// `cmsMessageDigestMatches(digest, content, attribute)`, in constant time.
#[tracing::instrument(level = "debug", skip_all)]
pub fn cms_message_digest_matches(
    id: &str,
    content: &[u8],
    attribute: Option<&[u8]>,
) -> bool {
    let (Ok(md), Some(expected)) = (digest(id), attribute) else {
        return false;
    };
    openssl::hash::hash(md, content)
        .map(|d| d.len() == expected.len() && openssl::memcmp::eq(&d, expected))
        .unwrap_or(false)
}

/// `signBytes(digest, data, privateKeyPem)`: PKCS#1 v1.5 for RSA, DER
/// ECDSA for EC.
#[tracing::instrument(level = "debug", skip_all)]
pub fn sign_bytes(
    id: &str,
    data: &[u8],
    private_pem: &str,
) -> CryptoResult<Vec<u8>> {
    let key = PKey::private_key_from_pem(private_pem.as_bytes())?;
    let mut s = Signer::new(digest(id)?, &key)?;
    Ok(s.sign_oneshot_to_vec(data)?)
}

/// `signatureValid(digest, data, publicKey, signature)`; false for what
/// does not verify or will not load.
#[tracing::instrument(level = "debug", skip_all)]
pub fn signature_valid(
    id: &str,
    data: &[u8],
    public_spki_der: &[u8],
    signature: &[u8],
) -> bool {
    let attempt = || -> CryptoResult<bool> {
        let key = PKey::public_key_from_der(public_spki_der)?;
        let mut v = Verifier::new(digest(id)?, &key)?;
        Ok(v.verify_oneshot(signature, data)?)
    };
    attempt().unwrap_or(false)
}

/// An RSA key pair of `bits`: `(PKCS#8 PEM, SPKI PEM)` — the SCEP RA's.
#[tracing::instrument(level = "debug", skip_all)]
pub fn generate_rsa(bits: u32) -> CryptoResult<(String, String)> {
    let key = PKey::from_rsa(openssl::rsa::Rsa::generate(bits)?)?;
    let private = String::from_utf8(key.private_key_to_pem_pkcs8()?)
        .map_err(|e| CryptoError::new(e.to_string()))?;
    let public = String::from_utf8(key.public_key_to_pem()?)
        .map_err(|e| CryptoError::new(e.to_string()))?;
    Ok((private, public))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)] // tests

    use super::*;

    #[test]
    fn the_content_cipher_and_the_key_transport_round_trip() {
        let (private, public) = generate_rsa(2048).unwrap();
        let spki = PKey::public_key_from_pem(public.as_bytes())
            .unwrap()
            .public_key_to_der()
            .unwrap();
        let key = [7u8; 32];
        let iv = [1u8; 16];
        let sealed =
            scep_content_encrypt("aes-256-cbc", &key, &iv, b"hello").unwrap();
        assert_eq!(
            scep_content_decrypt("aes-256-cbc", &key, &iv, &sealed).unwrap(),
            b"hello"
        );
        let wrapped = cms_key_transport_encrypt(&spki, &key).unwrap();
        assert_eq!(
            cms_key_transport_decrypt(
                "rsaes-pkcs1-v1_5",
                &private,
                &wrapped,
                None
            )
            .unwrap(),
            key
        );
        let sig = sign_bytes("sha256", b"data", &private).unwrap();
        assert!(signature_valid("sha256", b"data", &spki, &sig));
        assert!(!signature_valid("sha256", b"other", &spki, &sig));
    }
}
