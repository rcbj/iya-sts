// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! **THE ONLY `unsafe` CODE IN THE WORKSPACE** (rust/DESIGN.md section 6):
//! the post-quantum operations OpenSSL 3.5 has and the `openssl` crate does
//! not yet bind, called through `openssl-sys`. The Node service makes the
//! same calls on the same library (`common/pq_native.js`, #363).
//!
//! * key generation and raw key import BY NAME (`EVP_PKEY_CTX_new_from_name`,
//!   `EVP_PKEY_new_raw_*_key_ex`) — the crate's `KeyType` has no SLH-DSA;
//! * message signing with a CONTEXT STRING (`EVP_PKEY_sign_message_init` with
//!   `context-string`), which a composite's ML-DSA half needs;
//! * ML-KEM encapsulation and decapsulation (`EVP_PKEY_encapsulate`).
//!
//! Every function here is small, owns what it allocates through a guard that
//! frees it on every path, checks every return code, and hands back a safe
//! `openssl` type or plain bytes. Nothing else in the crate is `unsafe`.

#![allow(unsafe_code)]

use std::ffi::CString;
use std::ptr;

use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::error::ErrorStack;
use openssl::pkey::{PKey, PKeyRef, Private, Public};
use openssl_sys as ffi;

use crate::error::{CryptoError, CryptoResult};

/// An `EVP_PKEY_CTX` freed when dropped.
struct Ctx(*mut ffi::EVP_PKEY_CTX);

impl Drop for Ctx {
    fn drop(&mut self) {
        // SAFETY: the pointer came from an EVP_PKEY_CTX constructor, was
        // checked non-null, and is freed exactly once.
        unsafe { ffi::EVP_PKEY_CTX_free(self.0) }
    }
}

/// An `EVP_SIGNATURE` freed when dropped.
struct Signature(*mut ffi::EVP_SIGNATURE);

impl Drop for Signature {
    fn drop(&mut self) {
        // SAFETY: as for `Ctx`.
        unsafe { ffi::EVP_SIGNATURE_free(self.0) }
    }
}

fn name(algorithm: &str) -> CryptoResult<CString> {
    CString::new(algorithm)
        .map_err(|_| CryptoError::new("an algorithm name holds a NUL byte"))
}

fn check(code: i32) -> CryptoResult<()> {
    if code > 0 {
        Ok(())
    } else {
        Err(ErrorStack::get().into())
    }
}

fn context_for(pkey: *mut ffi::EVP_PKEY) -> CryptoResult<Ctx> {
    // SAFETY: `pkey` is a live EVP_PKEY borrowed from a PKeyRef for the
    // duration of the caller; the context takes its own reference.
    let ctx = unsafe { ffi::EVP_PKEY_CTX_new(pkey, ptr::null_mut()) };
    if ctx.is_null() {
        return Err(ErrorStack::get().into());
    }
    Ok(Ctx(ctx))
}

/// A fresh key pair of the named algorithm (`ML-DSA-65`,
/// `SLH-DSA-SHAKE-128s`, `ML-KEM-768` …).
pub fn generate(algorithm: &str) -> CryptoResult<PKey<Private>> {
    let alg = name(algorithm)?;
    // SAFETY: a NUL-terminated name and null library context and properties
    // (the defaults); the result is checked before use.
    let ctx = unsafe {
        ffi::EVP_PKEY_CTX_new_from_name(
            ptr::null_mut(),
            alg.as_ptr(),
            ptr::null(),
        )
    };
    if ctx.is_null() {
        return Err(CryptoError::new(format!(
            "OpenSSL has no key type \"{}\"",
            algorithm
        )));
    }
    let ctx = Ctx(ctx);
    // SAFETY: `ctx` is live; the out pointer starts null and is owned by
    // the returned PKey once set.
    unsafe {
        check(ffi::EVP_PKEY_keygen_init(ctx.0))?;
        let mut key: *mut ffi::EVP_PKEY = ptr::null_mut();
        check(ffi::EVP_PKEY_generate(ctx.0, &mut key))?;
        if key.is_null() {
            return Err(ErrorStack::get().into());
        }
        Ok(PKey::from_ptr(key))
    }
}

/// A private key of the named algorithm from its raw encoding (SLH-DSA's
/// whole secret key; ML-DSA's expanded one).
pub fn private_from_raw(
    algorithm: &str,
    raw: &[u8],
) -> CryptoResult<PKey<Private>> {
    let alg = name(algorithm)?;
    // SAFETY: the buffer is read for `raw.len()` bytes and copied.
    let key = unsafe {
        ffi::EVP_PKEY_new_raw_private_key_ex(
            ptr::null_mut(),
            alg.as_ptr(),
            ptr::null(),
            raw.as_ptr(),
            raw.len(),
        )
    };
    if key.is_null() {
        return Err(CryptoError::new(format!(
            "a {} private key of {} bytes could not be read",
            algorithm,
            raw.len()
        )));
    }
    // SAFETY: a new, owned, non-null EVP_PKEY.
    Ok(unsafe { PKey::from_ptr(key) })
}

/// A public key of the named algorithm from its raw encoding.
pub fn public_from_raw(
    algorithm: &str,
    raw: &[u8],
) -> CryptoResult<PKey<Public>> {
    let alg = name(algorithm)?;
    // SAFETY: as for `private_from_raw`.
    let key = unsafe {
        ffi::EVP_PKEY_new_raw_public_key_ex(
            ptr::null_mut(),
            alg.as_ptr(),
            ptr::null(),
            raw.as_ptr(),
            raw.len(),
        )
    };
    if key.is_null() {
        return Err(CryptoError::new(format!(
            "a {} public key of {} bytes could not be read",
            algorithm,
            raw.len()
        )));
    }
    // SAFETY: a new, owned, non-null EVP_PKEY.
    Ok(unsafe { PKey::from_ptr(key) })
}

/// The parameters for one message operation: the context string, if any.
/// The returned array borrows `context`, which must outlive its use.
fn context_params(context: Option<&[u8]>) -> [ffi::OSSL_PARAM; 2] {
    let key = c"context-string";
    // SAFETY: constructing OSSL_PARAMs only records pointers; OpenSSL
    // reads the context through them during the call they are passed to,
    // while the caller's borrow is still alive.
    unsafe {
        match context {
            Some(bytes) => [
                ffi::OSSL_PARAM_construct_octet_string(
                    key.as_ptr(),
                    bytes.as_ptr() as *mut std::ffi::c_void,
                    bytes.len(),
                ),
                ffi::OSSL_PARAM_construct_end(),
            ],
            None => [
                ffi::OSSL_PARAM_construct_end(),
                ffi::OSSL_PARAM_construct_end(),
            ],
        }
    }
}

fn fetch_signature(algorithm: &str) -> CryptoResult<Signature> {
    let alg = name(algorithm)?;
    // SAFETY: a NUL-terminated name; the result is checked.
    let sig = unsafe {
        ffi::EVP_SIGNATURE_fetch(ptr::null_mut(), alg.as_ptr(), ptr::null())
    };
    if sig.is_null() {
        return Err(CryptoError::new(format!(
            "OpenSSL has no signature algorithm \"{}\"",
            algorithm
        )));
    }
    Ok(Signature(sig))
}

/// A signature over a MESSAGE (pure, never pre-hashed), with an optional
/// context string — ML-DSA (hedged, OpenSSL's default) and SLH-DSA.
pub fn sign_message(
    key: &PKeyRef<Private>,
    algorithm: &str,
    message: &[u8],
    context: Option<&[u8]>,
) -> CryptoResult<Vec<u8>> {
    let signature = fetch_signature(algorithm)?;
    let ctx = context_for(key.as_ptr())?;
    let params = context_params(context);
    // SAFETY: every pointer is live for the calls: the context and the
    // signature by their guards, the params and the context string by the
    // caller's borrows; `out` is sized by the first EVP_PKEY_sign call and
    // truncated to what the second wrote.
    unsafe {
        check(ffi::EVP_PKEY_sign_message_init(
            ctx.0,
            signature.0,
            params.as_ptr(),
        ))?;
        let mut length: usize = 0;
        check(ffi::EVP_PKEY_sign(
            ctx.0,
            ptr::null_mut(),
            &mut length,
            message.as_ptr(),
            message.len(),
        ))?;
        let mut out = vec![0u8; length];
        check(ffi::EVP_PKEY_sign(
            ctx.0,
            out.as_mut_ptr(),
            &mut length,
            message.as_ptr(),
            message.len(),
        ))?;
        out.truncate(length);
        Ok(out)
    }
}

/// Whether a signature over a message verifies. A malformed signature is
/// `false`, never an error: the caller refuses either way.
pub fn verify_message(
    key: &PKeyRef<Public>,
    algorithm: &str,
    message: &[u8],
    signature_bytes: &[u8],
    context: Option<&[u8]>,
) -> CryptoResult<bool> {
    let signature = fetch_signature(algorithm)?;
    let ctx = context_for(key.as_ptr())?;
    let params = context_params(context);
    // SAFETY: as for `sign_message`; the inputs are only read.
    let answer = unsafe {
        check(ffi::EVP_PKEY_verify_message_init(
            ctx.0,
            signature.0,
            params.as_ptr(),
        ))?;
        ffi::EVP_PKEY_verify(
            ctx.0,
            signature_bytes.as_ptr(),
            signature_bytes.len(),
            message.as_ptr(),
            message.len(),
        )
    };
    // A refused verification leaves an error on the thread's queue; it is
    // the answer, not a fault, so it is cleared rather than reported.
    let _cleared = ErrorStack::get();
    Ok(answer == 1)
}

/// Whether a key is of the named algorithm (`ML-DSA-44`,
/// `SLH-DSA-SHA2-128s`, ...). The `openssl` crate's `Id` has no value for a
/// post-quantum key, so its type can be asked only by name.
pub fn is_a<T>(key: &PKeyRef<T>, algorithm: &str) -> bool {
    let Ok(wanted) = name(algorithm) else {
        return false;
    };
    // SAFETY: the key is borrowed for the call and the name outlives it;
    // EVP_PKEY_is_a only reads both.
    unsafe { ffi::EVP_PKEY_is_a(key.as_ptr(), wanted.as_ptr()) == 1 }
}

/// ML-KEM encapsulation to a public key: `(ciphertext, shared secret)`.
pub fn encapsulate(key: &PKeyRef<Public>) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    let ctx = context_for(key.as_ptr())?;
    // SAFETY: as for `sign_message`; both buffers are sized by the first
    // call and truncated to what the second wrote.
    unsafe {
        check(ffi::EVP_PKEY_encapsulate_init(ctx.0, ptr::null()))?;
        let (mut wrapped_len, mut secret_len) = (0usize, 0usize);
        check(ffi::EVP_PKEY_encapsulate(
            ctx.0,
            ptr::null_mut(),
            &mut wrapped_len,
            ptr::null_mut(),
            &mut secret_len,
        ))?;
        let mut wrapped = vec![0u8; wrapped_len];
        let mut secret = vec![0u8; secret_len];
        check(ffi::EVP_PKEY_encapsulate(
            ctx.0,
            wrapped.as_mut_ptr(),
            &mut wrapped_len,
            secret.as_mut_ptr(),
            &mut secret_len,
        ))?;
        wrapped.truncate(wrapped_len);
        secret.truncate(secret_len);
        Ok((wrapped, secret))
    }
}

/// ML-KEM decapsulation: the shared secret. ML-KEM's implicit rejection
/// means a wrong ciphertext yields a pseudo-random secret, not an error.
pub fn decapsulate(
    key: &PKeyRef<Private>,
    ciphertext: &[u8],
) -> CryptoResult<Vec<u8>> {
    let ctx = context_for(key.as_ptr())?;
    // SAFETY: as for `encapsulate`.
    unsafe {
        check(ffi::EVP_PKEY_decapsulate_init(ctx.0, ptr::null()))?;
        let mut secret_len = 0usize;
        check(ffi::EVP_PKEY_decapsulate(
            ctx.0,
            ptr::null_mut(),
            &mut secret_len,
            ciphertext.as_ptr(),
            ciphertext.len(),
        ))?;
        let mut secret = vec![0u8; secret_len];
        check(ffi::EVP_PKEY_decapsulate(
            ctx.0,
            secret.as_mut_ptr(),
            &mut secret_len,
            ciphertext.as_ptr(),
            ciphertext.len(),
        ))?;
        secret.truncate(secret_len);
        Ok(secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public_of(key: &PKey<Private>, alg: &str) -> PKey<Public> {
        let raw = key.raw_public_key().unwrap();
        public_from_raw(alg, &raw).unwrap()
    }

    #[test]
    fn ml_dsa_with_and_without_a_context() {
        let key = generate("ML-DSA-65").unwrap();
        let public = public_of(&key, "ML-DSA-65");
        let sig =
            sign_message(&key, "ML-DSA-65", b"m", Some(b"label")).unwrap();
        assert_eq!(sig.len(), 3309);
        assert!(verify_message(
            &public,
            "ML-DSA-65",
            b"m",
            &sig,
            Some(b"label")
        )
        .unwrap());
        assert!(
            !verify_message(&public, "ML-DSA-65", b"m", &sig, None).unwrap()
        );
        assert!(!verify_message(
            &public,
            "ML-DSA-65",
            b"x",
            &sig,
            Some(b"label")
        )
        .unwrap());
    }

    #[test]
    fn slh_dsa_from_raw() {
        let key = generate("SLH-DSA-SHA2-128s").unwrap();
        let raw = key.raw_private_key().unwrap();
        let again = private_from_raw("SLH-DSA-SHA2-128s", &raw).unwrap();
        let sig =
            sign_message(&again, "SLH-DSA-SHA2-128s", b"m", None).unwrap();
        let public = public_of(&key, "SLH-DSA-SHA2-128s");
        assert!(
            verify_message(&public, "SLH-DSA-SHA2-128s", b"m", &sig, None)
                .unwrap()
        );
    }

    #[test]
    fn ml_kem_round_trip() {
        let key = generate("ML-KEM-768").unwrap();
        let public = public_of(&key, "ML-KEM-768");
        let (ct, ss) = encapsulate(&public).unwrap();
        assert_eq!(ct.len(), 1088);
        assert_eq!(decapsulate(&key, &ct).unwrap(), ss);
    }

    #[test]
    fn an_unknown_name_is_an_error() {
        assert!(generate("NOT-AN-ALGORITHM").is_err());
    }
}
