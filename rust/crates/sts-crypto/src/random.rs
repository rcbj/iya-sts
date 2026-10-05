// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Random values: `common/crypto.js` section 13 (#65).
//!
//! **THE GENERATOR IS OPENSSL'S AND THIS MODULE ADDS NONE**, as Node's
//! section adds none: `RAND_bytes`, seeded from the operating system, the
//! FIPS DRBG under the FIPS provider. What the module is for is the three
//! mistakes it makes impossible — a modulo over an alphabet (every index is
//! rejection-sampled), a second generator (there is one), and a short
//! secret ([`random_token`] refuses fewer than 128 bits).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openssl::rand::rand_bytes;

use crate::error::{CryptoError, CryptoResult};

/// The fewest bits [`random_token`] makes.
pub const RANDOM_TOKEN_MIN_BITS: u32 = 128;

/// `n` bytes from OpenSSL's CSPRNG.
pub fn random_bytes(n: usize) -> CryptoResult<Vec<u8>> {
    let mut out = vec![0u8; n];
    rand_bytes(&mut out)?;
    Ok(out)
}

/// A uniform integer in `[min, max)`, rejection-sampled (node's
/// `randomInt`).
pub fn random_int(min: u64, max: u64) -> CryptoResult<u64> {
    if max <= min {
        return Err(CryptoError::new("crypto: randomInt() needs min < max"));
    }
    let range = max - min;
    // The largest multiple of `range` a u64 holds: a draw at or above it
    // would bias the low values, so it is drawn again.
    let limit = u64::MAX - (u64::MAX % range);
    loop {
        let bytes = random_bytes(8)?;
        let mut word = [0u8; 8];
        word.copy_from_slice(&bytes);
        let draw = u64::from_be_bytes(word);
        if draw < limit {
            return Ok(min + draw % range);
        }
    }
}

/// A random v4 UUID (RFC 9562 section 5.4), lower case.
pub fn random_uuid() -> CryptoResult<String> {
    let mut b = random_bytes(16)?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{:02x}", x)).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}

/// At least `bits` of randomness, rounded up to whole bytes, base64url;
/// 256 when `None`. Fewer than 128 bits is a programming error, refused.
pub fn random_token(bits: Option<u32>) -> CryptoResult<String> {
    let want = bits.unwrap_or(256);
    if want < RANDOM_TOKEN_MIN_BITS {
        return Err(CryptoError::new(format!(
            "crypto: randomToken() makes at least {} bits, not {}",
            RANDOM_TOKEN_MIN_BITS, want
        )));
    }
    Ok(URL_SAFE_NO_PAD.encode(random_bytes(want.div_ceil(8) as usize)?))
}

/// `length` characters, each drawn uniformly from `alphabet`; an alphabet
/// of fewer than two distinct characters, or with a repeat, is refused.
pub fn random_string(alphabet: &str, length: usize) -> CryptoResult<String> {
    let chars: Vec<char> = alphabet.chars().collect();
    let mut distinct = chars.clone();
    distinct.sort_unstable();
    distinct.dedup();
    if chars.len() < 2 || distinct.len() != chars.len() {
        return Err(CryptoError::new(
            "crypto: randomString() needs two or more distinct characters \
             and a whole length",
        ));
    }
    let mut out = String::with_capacity(length);
    for _ in 0..length {
        out.push(chars[random_int(0, chars.len() as u64)? as usize]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_refusals() {
        assert!(random_token(Some(127)).is_err());
        assert_eq!(random_token(Some(128)).unwrap().len(), 22);
        assert!(random_string("aa", 4).is_err());
        assert!(random_string("a", 4).is_err());
        assert!(random_int(3, 3).is_err());
    }

    #[test]
    fn a_uuid_is_version_4() {
        let u = random_uuid().unwrap();
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "4");
        assert!("89ab".contains(&u[19..20]));
    }

    /// A chi-square over many draws from a 31-character alphabet — GNAP's
    /// user-code alphabet, the one a modulo biased.
    #[test]
    fn draws_are_uniform() {
        let alphabet = "BCDFGHJKLMNPQRSTVWXZ23456789!@#";
        let n = 31 * 2000;
        let drawn = random_string(alphabet, n).unwrap();
        let mut counts = [0f64; 31];
        for c in drawn.chars() {
            counts[alphabet.find(c).unwrap()] += 1.0;
        }
        let expected = n as f64 / 31.0;
        let chi: f64 = counts
            .iter()
            .map(|o| (o - expected).powi(2) / expected)
            .sum();
        // 30 degrees of freedom: p = 0.0001 at about 67.6.
        assert!(chi < 67.6, "chi-square {}", chi);
    }
}
