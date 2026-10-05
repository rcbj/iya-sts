// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Base64url as RFC 7515 section 2 means it: no padding, and each segment
//! the ONE canonical encoding of its bytes (#202) — a character outside the
//! alphabet, padding, or unused bits that are not zero is refused, so a token
//! has exactly one spelling.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::error::{CryptoError, CryptoResult};

/// Base64url without padding.
pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The bytes of a canonical base64url segment; `what` names it in the
/// refusal.
// A hot path: every segment of every compact JWS and JWE.
pub fn decode_strict(segment: &str, what: &str) -> CryptoResult<Vec<u8>> {
    let refused = || {
        CryptoError::new(format!(
            "the {} is not canonical base64url (RFC 7515 section 2): it \
             carries a character outside the alphabet, padding, or unused \
             bits that are not zero.",
            what
        ))
    };
    let bytes = URL_SAFE_NO_PAD.decode(segment).map_err(|_| refused())?;
    if encode(&bytes) != segment {
        return Err(refused());
    }
    Ok(bytes)
}

/// Lenient base64url, for a JWK member: what a caller hands in, not what
/// a signature covers.
pub fn decode_loose(text: &str) -> CryptoResult<Vec<u8>> {
    let trimmed = text.trim_end_matches('=');
    URL_SAFE_NO_PAD
        .decode(trimmed)
        .map_err(|e| CryptoError::new(format!("not base64url: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_canonical_spelling() {
        assert_eq!(decode_strict("AQI", "x").ok(), Some(vec![1, 2]));
        assert!(decode_strict("AQJ", "x").is_err()); // unused bits set
        assert!(decode_strict("AQI=", "x").is_err());
        assert!(decode_strict("A QI", "x").is_err());
        assert!(decode_strict("AQ+I", "x").is_err());
        assert_eq!(decode_strict("", "x").ok(), Some(vec![]));
    }
}
