// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The Kerberos pseudo-random function and KRB-FX-CF2: `common/crypto.js`
//! section 9 (#173), which RFC 6113 FAST combines keys with.
//!
//! * aes128/256-cts-hmac-sha1-96 (RFC 3962 section 4): SHA-1 of the input,
//!   truncated to one block, encrypted under DK(key, "prf");
//! * aes128-cts-hmac-sha256-128 and aes256-cts-hmac-sha384-192 (RFC 8009
//!   section 5): KDF-HMAC-SHA2(key, "prf", input, 256 or 384);
//! * arcfour-hmac-md5 (RFC 4757 section 3): HMAC-SHA1(key, input).
//!
//! Held to RFC 3961's n-fold vectors here and to Node's answers — which are
//! held to MIT's `t_prf.c` and `t_cf2.expected` — by `tests/krb5_vectors.rs`.
//! `session_state_hash` (OpenID Connect Session Management) lives beside it
//! in Node and here.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::symm::{Cipher, Crypter, Mode};

use crate::error::{CryptoError, CryptoResult};
use crate::random::random_bytes;

#[derive(Clone, Copy)]
enum Family {
    AesSha1(Cipher),
    AesSha2(MessageDigest),
    Rc4,
}

/// One enctype's PRF: key size, output size, construction.
#[derive(Clone, Copy)]
struct Profile {
    key_bytes: usize,
    prf_bytes: usize,
    family: Family,
}

fn profile(etype: i32) -> CryptoResult<Profile> {
    let (key_bytes, prf_bytes, family) = match etype {
        17 => (16, 16, Family::AesSha1(Cipher::aes_128_cbc())),
        18 => (32, 16, Family::AesSha1(Cipher::aes_256_cbc())),
        19 => (16, 32, Family::AesSha2(MessageDigest::sha256())),
        20 => (32, 48, Family::AesSha2(MessageDigest::sha384())),
        23 => (16, 20, Family::Rc4),
        _ => {
            return Err(CryptoError::new(format!(
                "crypto: no Kerberos pseudo-random function is defined here \
                 for enctype {}",
                etype
            )))
        }
    };
    Ok(Profile {
        key_bytes,
        prf_bytes,
        family,
    })
}

/// RFC 3961 section 5.1's n-fold, in bytes (MIT's `krb5int_nfold`).
pub fn nfold(input: &[u8], out_bytes: usize) -> Vec<u8> {
    let in_len = input.len();
    let mut out = vec![0u8; out_bytes];
    if in_len == 0 || out_bytes == 0 {
        return out;
    }
    let (mut a, mut b) = (in_len, out_bytes);
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    let lcm = in_len * out_bytes / a;
    let bits = in_len << 3;
    let mut byte: u32 = 0;
    for i in (0..lcm).rev() {
        let msbit = ((bits - 1)
            + ((bits + 13) * (i / in_len))
            + ((in_len - (i % in_len)) << 3))
            % bits;
        let hi = u32::from(input[((in_len - 1) - (msbit >> 3)) % in_len]);
        let lo = u32::from(input[(in_len - (msbit >> 3)) % in_len]);
        byte += (((hi << 8) | lo) >> ((msbit & 7) + 1)) & 0xff;
        byte += u32::from(out[i % out_bytes]);
        out[i % out_bytes] = (byte & 0xff) as u8;
        byte >>= 8;
    }
    if byte != 0 {
        for i in (0..out_bytes).rev() {
            byte += u32::from(out[i]);
            out[i] = (byte & 0xff) as u8;
            byte >>= 8;
        }
    }
    out
}

/// AES-CBC with a zero IV and no padding: for one block, the block cipher.
fn aes_blocks(
    cipher: Cipher,
    key: &[u8],
    data: &[u8],
) -> CryptoResult<Vec<u8>> {
    let mut c = Crypter::new(cipher, Mode::Encrypt, key, Some(&[0u8; 16]))?;
    c.pad(false);
    let mut out = vec![0u8; data.len() + 16];
    let n = c.update(data, &mut out)?;
    let m = c.finalize(&mut out[n..])?;
    out.truncate(n + m);
    Ok(out)
}

fn hmac(md: MessageDigest, key: &[u8], data: &[u8]) -> CryptoResult<Vec<u8>> {
    let key = PKey::hmac(key)?;
    let mut s = Signer::new(md, &key)?;
    s.update(data)?;
    Ok(s.sign_to_vec()?)
}

/// RFC 3961 pseudo-random(key, octets) for an enctype.
pub fn prf(etype: i32, key: &[u8], octets: &[u8]) -> CryptoResult<Vec<u8>> {
    let p = profile(etype)?;
    if key.len() != p.key_bytes {
        return Err(CryptoError::new(format!(
            "crypto: a key for enctype {} is {} bytes, not {}",
            etype,
            p.key_bytes,
            key.len()
        )));
    }
    match p.family {
        Family::AesSha1(cipher) => {
            let tmp = hash(MessageDigest::sha1(), octets)?;
            // DK(key, "prf"): DR over the n-folded constant, then the
            // identity random-to-key.
            let mut block = nfold(b"prf", 16);
            let mut derived = Vec::new();
            while derived.len() < p.key_bytes {
                block = aes_blocks(cipher, key, &block)?;
                derived.extend_from_slice(&block);
            }
            derived.truncate(p.key_bytes);
            aes_blocks(cipher, &derived, &tmp[..16])
        }
        Family::AesSha2(md) => {
            let mut input = vec![0, 0, 0, 1];
            input.extend_from_slice(b"prf");
            input.push(0);
            input.extend_from_slice(octets);
            input.extend_from_slice(&((p.prf_bytes * 8) as u32).to_be_bytes());
            let mut out = hmac(md, key, &input)?;
            out.truncate(p.prf_bytes);
            Ok(out)
        }
        Family::Rc4 => hmac(MessageDigest::sha1(), key, octets),
    }
}

/// RFC 6113 section 5.1's PRF+, its counter one octet.
pub fn prf_plus(
    etype: i32,
    key: &[u8],
    info: &[u8],
    out_bytes: usize,
) -> CryptoResult<Vec<u8>> {
    let mut out = Vec::new();
    let mut counter: u32 = 1;
    while out.len() < out_bytes {
        if counter > 255 {
            return Err(CryptoError::new(
                "crypto: PRF+ ran out of one-octet counters",
            ));
        }
        let mut input = vec![counter as u8];
        input.extend_from_slice(info);
        out.extend(prf(etype, key, &input)?);
        counter += 1;
    }
    out.truncate(out_bytes);
    Ok(out)
}

/// RFC 6113 section 5.1's KRB-FX-CF2: the first key's enctype, and the key.
pub fn krb_fx_cf2(
    key1: (i32, &[u8]),
    key2: (i32, &[u8]),
    pepper1: &[u8],
    pepper2: &[u8],
) -> CryptoResult<(i32, Vec<u8>)> {
    let size = profile(key1.0)?.key_bytes;
    profile(key2.0)?;
    let a = prf_plus(key1.0, key1.1, pepper1, size)?;
    let b = prf_plus(key2.0, key2.1, pepper2, size)?;
    Ok((key1.0, a.iter().zip(&b).map(|(x, y)| x ^ y).collect()))
}

/// OpenID Connect Session Management 1.0 section 3's `session_state`:
/// SHA-256 over `client_id origin browser_state salt`, base64url, "." and
/// the salt; a fresh salt when none is given.
pub fn session_state_hash(
    client_id: &str,
    origin: &str,
    browser_state: &str,
    salt: Option<&str>,
) -> CryptoResult<String> {
    let salt = match salt.filter(|s| !s.is_empty()) {
        Some(s) => s.to_string(),
        None => URL_SAFE_NO_PAD.encode(random_bytes(16)?),
    };
    let digest = hash(
        MessageDigest::sha256(),
        format!("{} {} {} {}", client_id, origin, browser_state, salt)
            .as_bytes(),
    )?;
    Ok(format!("{}.{}", URL_SAFE_NO_PAD.encode(digest), salt))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    /// RFC 3961 section A.1.
    #[test]
    fn rfc3961_nfold() {
        for (input, bytes, want) in [
            ("012345", 8, "be072631276b1955"),
            ("password", 7, "78a07b6caf85fa"),
            ("Rough Consensus, and Running Code", 8, "bb6ed30870b7f0e0"),
            ("password", 21, "59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e"),
            (
                "MASSACHVSETTS INSTITVTE OF TECHNOLOGY",
                24,
                "db3b0d8f0b061e603282b308a50841229ad798fab9540c1b",
            ),
            ("Q", 21, "518a54a215a8452a518a54a215a8452a518a54a215"),
            ("ba", 21, "fb25d531ae8974499f52fd92ea9857c4ba24cf297e"),
            ("kerberos", 8, "6b65726265726f73"),
            ("kerberos", 16, "6b65726265726f737b9b5b2b93132b93"),
            ("kerberos", 21, "8372c236344e5f1550cd0747e15d62ca7a5a3bcea4"),
            (
                "kerberos",
                32,
                "6b65726265726f737b9b5b2b93132b935c9bdcdad95c9899c4cae4dee6d6cae4",
            ),
        ] {
            assert_eq!(hex(&nfold(input.as_bytes(), bytes)), want, "{}-fold({})", bytes * 8, input);
        }
    }

    #[test]
    fn unknown_enctypes_and_wrong_sizes_are_refused() {
        assert!(prf(16, &[0u8; 24], b"x").is_err());
        assert!(prf(17, &[0u8; 32], b"x").is_err());
    }
}
