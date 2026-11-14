// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The pieces of Kerberos v5's cryptography and byte plumbing below the
//! enctypes: `kerberos/krb5_primitives.js`.
//!
//! Node writes MD4, MD5 and RC4 out by hand because the module was once
//! bundled into a browser, where Web Crypto has none of them. Here they
//! come from RustCrypto (`md4`, `md-5`, `rc4`), as rust/DESIGN.md's
//! Kerberos row says: OpenSSL 3 keeps MD4 and RC4 in its legacy provider,
//! and a dependency on that provider being loaded is a failure waiting for
//! a deployment that does not load it. HMAC-MD5 is RFC 2104 written over
//! `md-5`, the shape of Node's `hmacMd5()`.
//!
//! All three are broken and are here only because etype 23
//! (arcfour-hmac-md5) still uses them.
//!
//! A HOT PATH, as in Node: the byte helpers run once per field of every
//! message and carry no `tracing::instrument`; the derivations below do.

use md4::Md4;
use md5::{Digest, Md5};
use rc4::{KeyInit, Rc4, StreamCipher};

use crate::error::{Krb5Error, Krb5Result};

/// UTF-8 of a string: Node's `utf8()`. Node writes it out so that a lone
/// surrogate half still encodes (as three bytes); a Rust `str` cannot hold
/// one, so the standard encoding is the same function on every input it
/// can be given.
pub fn utf8(text: &str) -> Vec<u8> {
    text.as_bytes().to_vec()
}

/// Node's `fromUtf8()`: STRICT, `None` for anything that is not
/// well-formed UTF-8 (a truncated sequence, a stray continuation byte, an
/// overlong form, an encoded surrogate, a code point past U+10FFFF) — the
/// exact set `std::str::from_utf8` refuses — so a caller can fall back to
/// another reading rather than put U+FFFD in a principal name.
pub fn from_utf8(bytes: &[u8]) -> Option<String> {
    std::str::from_utf8(bytes).ok().map(str::to_string)
}

/// Each byte as the code point of the same number: Node's `decLatin1()`.
pub fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|b| char::from(*b)).collect()
}

/// UTF-16 little-endian, the NT hash's input: Node's `utf16le()`, which
/// walks a JavaScript string's UTF-16 code units.
pub fn utf16le(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// The XOR of the common prefix of two byte strings: Node's `xor()`.
pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}

/// Lowercase hex: Node's `toHex()`.
pub fn to_hex(bytes: &[u8]) -> String {
    crate::hex::encode(bytes)
}

/// Node's `fromHex()`: whitespace and colons ignored.
pub fn from_hex(text: &str) -> Krb5Result<Vec<u8>> {
    let s: Vec<char> = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    if s.len() % 2 != 0 {
        return Err(Krb5Error::new("krb5: hex string has an odd length"));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in 0..s.len() / 2 {
        let pair: String = s[i * 2..i * 2 + 2].iter().collect();
        // parseInt("0g", 16) is 0 in JavaScript — it stops at the first
        // non-digit — and NaN only when the FIRST character is not one.
        let digits: String =
            pair.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
        match u8::from_str_radix(&digits, 16) {
            Ok(v) => out.push(v),
            Err(_) => {
                return Err(Krb5Error::new(format!(
                    "krb5: not hex at offset {}",
                    i * 2
                )))
            }
        }
    }
    Ok(out)
}

/// Constant-time comparison, false on a length difference: Node's
/// `equalConstantTime()`. Every checksum verification goes through it.
pub fn equal_constant_time(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && openssl::memcmp::eq(a, b)
}

/// RFC 3961 section 5.1's n-fold, to `out_bits` bits: Node's `nfold()`,
/// with its two refusals, over `sts-crypto`'s n-fold (the one the PRF
/// uses), so there is one copy of the reference arithmetic.
pub fn nfold(input: &[u8], out_bits: usize) -> Krb5Result<Vec<u8>> {
    let out_len = out_bits >> 3;
    if out_len == 0 {
        return Err(Krb5Error::new("krb5: nfold output size must be positive"));
    }
    if input.is_empty() {
        return Err(Krb5Error::new("krb5: nfold input must not be empty"));
    }
    Ok(sts_crypto::krb5_prf::nfold(input, out_len))
}

/// MD4 (RFC 1320): the NT hash, etype 23's string-to-key.
#[tracing::instrument(level = "debug", skip_all)]
pub fn md4(input: &[u8]) -> Vec<u8> {
    Md4::digest(input).to_vec()
}

/// MD5 (RFC 1321): under etype 23's HMAC and its checksum.
#[tracing::instrument(level = "debug", skip_all)]
pub fn md5(input: &[u8]) -> Vec<u8> {
    Md5::digest(input).to_vec()
}

/// HMAC-MD5 (RFC 2104), block size 64: Node's `hmacMd5()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn hmac_md5(key: &[u8], message: &[u8]) -> Vec<u8> {
    let k = if key.len() > 64 {
        md5(key)
    } else {
        key.to_vec()
    };
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for (i, b) in k.iter().enumerate() {
        ipad[i] ^= b;
        opad[i] ^= b;
    }
    let mut inner = ipad.to_vec();
    inner.extend_from_slice(message);
    let mut outer = opad.to_vec();
    outer.extend(md5(&inner));
    md5(&outer)
}

/// RC4, etype 23's cipher; the same call encrypts and decrypts. A key
/// outside RC4's 1–256 bytes is refused (Node's loop would index past an
/// empty key and produce NaN-driven garbage; nothing here passes one).
#[tracing::instrument(level = "debug", skip_all)]
pub fn rc4(key: &[u8], data: &[u8]) -> Krb5Result<Vec<u8>> {
    let mut cipher = Rc4::new_from_slice(key).map_err(|_| {
        Krb5Error::new(format!(
            "krb5: an RC4 key of {} bytes is not usable",
            key.len()
        ))
    })?;
    let mut out = data.to_vec();
    cipher.apply_keystream(&mut out);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 1320 and RFC 1321's own vectors, and RFC 2202's HMAC-MD5.
    #[test]
    fn md4_md5_hmac_rc4() {
        assert_eq!(to_hex(&md4(b"abc")), "a448017aaf21d8525fc10ae87aa6729d");
        assert_eq!(to_hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            to_hex(&hmac_md5(b"Jefe", b"what do ya want for nothing?")),
            "750c783e6ab0b503eaa86e310a5db738"
        );
        assert_eq!(
            to_hex(&rc4(b"Key", b"Plaintext").unwrap()),
            "bbf316e8d940af0ad3"
        );
    }

    #[test]
    fn strict_utf8_and_hex() {
        assert_eq!(from_utf8(&[0xc3, 0xa9]).as_deref(), Some("é"));
        assert_eq!(from_utf8(&[0xc0, 0x80]), None);
        assert_eq!(from_utf8(&[0xed, 0xa0, 0x80]), None);
        assert_eq!(from_hex("de:ad be").unwrap(), vec![0xde, 0xad, 0xbe]);
        assert!(from_hex("abc").is_err());
        assert_eq!(utf16le("aé"), vec![0x61, 0, 0xe9, 0]);
    }
}
