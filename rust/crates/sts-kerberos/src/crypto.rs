// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The RFC 3961 encryption framework and the enctypes Kerberos meets in
//! 2026: `kerberos/krb5_crypto.js`.
//!
//! | id | name | RFC |
//! |---|---|---|
//! | 17 | aes128-cts-hmac-sha1-96 | RFC 3962 |
//! | 18 | aes256-cts-hmac-sha1-96 | RFC 3962 |
//! | 19 | aes128-cts-hmac-sha256-128 | RFC 8009 |
//! | 20 | aes256-cts-hmac-sha384-192 | RFC 8009 |
//! | 23 | arcfour-hmac-md5 | RFC 4757, legacy |
//!
//! DES (1, 2, 3, 5, 7, 16), arcfour-hmac-exp (24) and Camellia (25, 26)
//! are NAMED and refused, as in Node: a capture carrying one decodes and
//! says what it is, and nothing here performs one. rust/DESIGN.md's row
//! lists "decode-only DES … Camellia 25/26"; decode-only is exactly this —
//! the codec reads the EncryptedData and names the etype — and performing
//! Camellia would be behaviour Node does not have.
//!
//! **THE CRYPTOGRAPHY IS `sts-crypto`'S** (`sts_crypto::krb5`), because
//! every cryptographic operation is that crate's (#453; `sts-guards`'
//! `crypto_centralised.rs`): string-to-key, the derived keys, CTS,
//! encryption with its confounder, the checksums, HMAC, PBKDF2 and type
//! 23's MD4, RC4 and HMAC-MD5 all moved there on 2026-11-14, sentences
//! unchanged. What stays here is Kerberos's, not cryptography's: the
//! enctype table ([`Enctype`], Node's `ETYPES`), the names, the refusals
//! of the etypes that are only named, and the key usages; each method
//! below hands its profile to `sts_crypto::krb5::Profile`. This crate
//! depends on no crypto library.
//!
//! The PRF, PRF+ and KRB-FX-CF2 are `sts_crypto::krb5_prf`'s, as they are
//! `common/crypto.js`'s in Node; [`Enctype::prf`] hands over to it.

use sts_crypto::krb5;

use crate::error::{Krb5Error, Krb5Result};

pub use sts_crypto::krb5::Family;

/// Key usage numbers, RFC 4120 section 7.5.1 and RFC 4121 — named because
/// a wrong one is an integrity failure at the far end and no other symptom.
pub mod key_usage {
    pub const AS_REQ_PA_ENC_TIMESTAMP: u32 = 1;
    pub const KDC_REP_TICKET: u32 = 2;
    pub const AS_REP_ENCPART: u32 = 3;
    pub const TGS_REQ_AD_SESSKEY: u32 = 4;
    pub const TGS_REQ_AD_SUBKEY: u32 = 5;
    pub const TGS_REQ_AUTH_CKSUM: u32 = 6;
    pub const TGS_REQ_AUTH: u32 = 7;
    pub const TGS_REP_ENCPART_SESSKEY: u32 = 8;
    pub const TGS_REP_ENCPART_SUBKEY: u32 = 9;
    pub const AP_REQ_AUTH_CKSUM: u32 = 10;
    pub const AP_REQ_AUTH: u32 = 11;
    pub const AP_REP_ENCPART: u32 = 12;
    pub const KRB_PRIV_ENCPART: u32 = 13;
    pub const KRB_CRED_ENCPART: u32 = 14;
    pub const KRB_SAFE_CKSUM: u32 = 15;
    pub const KDC_REP_TICKET_ENCPART_ALT: u32 = 16;
    pub const PA_FOR_USER_CKSUM: u32 = 17;
    pub const KRB_ERROR_CKSUM: u32 = 18;
    pub const AD_KDCISSUED_CKSUM: u32 = 19;
    pub const AD_MTE: u32 = 20;
    pub const AD_ITE: u32 = 21;
    pub const GSS_ACCEPTOR_SEAL: u32 = 22;
    pub const GSS_ACCEPTOR_SIGN: u32 = 23;
    pub const GSS_INITIATOR_SEAL: u32 = 24;
    pub const GSS_INITIATOR_SIGN: u32 = 25;
}

/// The order offered in an AS-REQ by default: Node's
/// `DEFAULT_ETYPE_PREFERENCE`.
pub const DEFAULT_ETYPE_PREFERENCE: [i64; 5] = [18, 17, 20, 19, 23];

/// The etypes this codec performs.
pub const SUPPORTED: [i64; 5] = [17, 18, 19, 20, 23];

/// The names of etypes it decodes but will not perform.
fn unsupported_name(id: i64) -> Option<&'static str> {
    Some(match id {
        1 => "des-cbc-crc",
        2 => "des-cbc-md4",
        3 => "des-cbc-md5",
        5 => "des3-cbc-md5",
        7 => "des3-cbc-sha1",
        16 => "des3-cbc-sha1-kd",
        24 => "arcfour-hmac-exp",
        25 => "camellia128-cts-cmac",
        26 => "camellia256-cts-cmac",
        _ => return None,
    })
}

/// Node's `etypeName()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn etype_name(id: i64) -> String {
    match Enctype::find(id) {
        Some(e) => e.name.to_string(),
        None => unsupported_name(id)
            .map(str::to_string)
            .unwrap_or_else(|| format!("etype-{}", id)),
    }
}

/// Node's `isSupportedEtype()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn is_supported_etype(id: i64) -> bool {
    SUPPORTED.contains(&id)
}

/// One enctype's profile: Node's `ETYPES[id]` object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Enctype {
    pub id: i64,
    pub name: &'static str,
    pub key_bytes: usize,
    pub block_bytes: usize,
    pub confounder_bytes: usize,
    pub checksum_bytes: usize,
    pub checksum_type: i64,
    pub default_iterations: u32,
    pub rfc: &'static str,
    pub legacy: bool,
    pub family: Family,
}

const ETYPES: [Enctype; 5] = [
    Enctype {
        id: 17,
        name: "aes128-cts-hmac-sha1-96",
        key_bytes: 16,
        block_bytes: 16,
        confounder_bytes: 16,
        checksum_bytes: 12,
        checksum_type: 15,
        default_iterations: 4096,
        rfc: "RFC 3962",
        legacy: false,
        family: Family::AesSha1,
    },
    Enctype {
        id: 18,
        name: "aes256-cts-hmac-sha1-96",
        key_bytes: 32,
        block_bytes: 16,
        confounder_bytes: 16,
        checksum_bytes: 12,
        checksum_type: 16,
        default_iterations: 4096,
        rfc: "RFC 3962",
        legacy: false,
        family: Family::AesSha1,
    },
    Enctype {
        id: 19,
        name: "aes128-cts-hmac-sha256-128",
        key_bytes: 16,
        block_bytes: 16,
        confounder_bytes: 16,
        checksum_bytes: 16,
        checksum_type: 19,
        default_iterations: 32768,
        rfc: "RFC 8009",
        legacy: false,
        family: Family::AesSha2,
    },
    Enctype {
        id: 20,
        name: "aes256-cts-hmac-sha384-192",
        key_bytes: 32,
        block_bytes: 16,
        confounder_bytes: 16,
        checksum_bytes: 24,
        checksum_type: 20,
        default_iterations: 32768,
        rfc: "RFC 8009",
        legacy: false,
        family: Family::AesSha2,
    },
    Enctype {
        id: 23,
        name: "arcfour-hmac-md5",
        key_bytes: 16,
        block_bytes: 1,
        confounder_bytes: 8,
        checksum_bytes: 16,
        checksum_type: -138,
        default_iterations: 0,
        rfc: "RFC 4757",
        legacy: true,
        family: Family::Arcfour,
    },
];

/// Random bytes: Node's `randomBytes()`, `sts-crypto`'s.
#[tracing::instrument(level = "debug", skip_all)]
pub fn random_bytes(n: usize) -> Krb5Result<Vec<u8>> {
    Ok(krb5::random_bytes(n)?)
}

/// Unpadded AES-CBC encryption: Node's `cbcEncryptRaw()`, `sts-crypto`'s.
#[tracing::instrument(level = "debug", skip_all)]
pub fn cbc_encrypt_raw(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
) -> Krb5Result<Vec<u8>> {
    Ok(krb5::cbc_encrypt_raw(key, iv, data)?)
}

/// Unpadded AES-CBC decryption: Node's `cbcDecryptRaw()`, `sts-crypto`'s.
#[tracing::instrument(level = "debug", skip_all)]
pub fn cbc_decrypt_raw(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
) -> Krb5Result<Vec<u8>> {
    Ok(krb5::cbc_decrypt_raw(key, iv, data)?)
}

/// AES-CBC with ciphertext stealing as Kerberos uses it (CBC-CS3):
/// Node's `ctsEncrypt()`, `sts-crypto`'s.
#[tracing::instrument(level = "debug", skip_all)]
pub fn cts_encrypt(key: &[u8], iv: &[u8], plain: &[u8]) -> Krb5Result<Vec<u8>> {
    Ok(krb5::cts_encrypt(key, iv, plain)?)
}

/// The inverse: Node's `ctsDecrypt()`, `sts-crypto`'s.
#[tracing::instrument(level = "debug", skip_all)]
pub fn cts_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Krb5Result<Vec<u8>> {
    Ok(krb5::cts_decrypt(key, iv, data)?)
}

/// HMAC under a named hash (Web Crypto's names): Node's `hmac()`,
/// `sts-crypto`'s.
#[tracing::instrument(level = "debug", skip_all)]
pub fn hmac(
    hash_name: &str,
    key: &[u8],
    message: &[u8],
) -> Krb5Result<Vec<u8>> {
    Ok(krb5::hmac(hash_name, key, message)?)
}

/// PBKDF2, the length in bits: Node's `pbkdf2()`, `sts-crypto`'s.
#[tracing::instrument(level = "debug", skip_all)]
pub fn pbkdf2(
    hash_name: &str,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out_bits: usize,
) -> Krb5Result<Vec<u8>> {
    Ok(krb5::pbkdf2(
        hash_name, password, salt, iterations, out_bits,
    )?)
}

/// RFC 3961 section 5.1's DR: Node's `deriveRandom()`, `sts-crypto`'s.
#[tracing::instrument(level = "debug", skip_all)]
pub fn derive_random(
    base_key: &[u8],
    constant: &[u8],
    out_bytes: usize,
) -> Krb5Result<Vec<u8>> {
    Ok(krb5::derive_random(base_key, constant, out_bytes)?)
}

/// The derivation constant: the usage big-endian, then the purpose byte —
/// 0x99 checksum, 0xAA encryption, 0x55 integrity. Node's
/// `usageConstant()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn usage_constant(usage: u32, purpose: u8) -> [u8; 5] {
    krb5::usage_constant(usage, purpose)
}

/// RFC 8009 section 3's KDF-HMAC-SHA2: Node's `kdfHmacSha2()`,
/// `sts-crypto`'s.
#[tracing::instrument(level = "debug", skip_all)]
pub fn kdf_hmac_sha2(
    hash_name: &str,
    key: &[u8],
    label: &[u8],
    out_bits: u32,
) -> Krb5Result<Vec<u8>> {
    Ok(krb5::kdf_hmac_sha2(hash_name, key, label, out_bits)?)
}

/// RC4-HMAC's usage translation, a wart from an earlier draft: Node's
/// `translateArcfourUsage()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn translate_arcfour_usage(usage: u32) -> u32 {
    krb5::translate_arcfour_usage(usage)
}

impl Enctype {
    /// The profile for an id, if this codec performs it.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn find(id: i64) -> Option<&'static Enctype> {
        ETYPES.iter().find(|e| e.id == id)
    }

    /// Node's `etypeById()`, with its refusal for an etype that is only
    /// named.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn by_id(id: i64) -> Krb5Result<&'static Enctype> {
        if let Some(e) = Self::find(id) {
            return Ok(e);
        }
        let known = unsupported_name(id);
        Err(Krb5Error::new(format!(
            "krb5: encryption type {}{}{}",
            id,
            match known {
                Some(k) => format!(" ({}) is not implemented here", k),
                None => " is unknown".to_string(),
            },
            if (1..=7).contains(&id) {
                " — DES was removed from Windows Server 2025 and is \
                 decode-only here"
            } else {
                ""
            }
        )))
    }

    /// Node's `etypeByName()`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn by_name(name: &str) -> Krb5Result<&'static Enctype> {
        ETYPES.iter().find(|e| e.name == name).ok_or_else(|| {
            Krb5Error::new(format!("krb5: no encryption type named {}", name))
        })
    }

    /// Every profile, in Node's key order.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn all() -> &'static [Enctype] {
        &ETYPES
    }

    /// What `sts-crypto` needs of this profile to compute with it.
    fn cipher(&self) -> krb5::Profile {
        krb5::Profile {
            name: self.name,
            key_bytes: self.key_bytes,
            confounder_bytes: self.confounder_bytes,
            checksum_bytes: self.checksum_bytes,
            default_iterations: self.default_iterations,
            family: self.family,
        }
    }

    /// string-to-key: RFC 3962 section 4, RFC 8009 section 4, RFC 4757
    /// (unsalted, the NT hash). `sts-crypto`'s.
    #[tracing::instrument(level = "debug", skip_all, fields(etype = self.id))]
    pub fn string_to_key(
        &self,
        password: &str,
        salt: &[u8],
        params: Option<&[u8]>,
    ) -> Krb5Result<Vec<u8>> {
        Ok(self.cipher().string_to_key(password, salt, params)?)
    }

    /// Ke for a usage (the AES families).
    #[tracing::instrument(level = "debug", skip_all, fields(etype = self.id))]
    pub fn encryption_key(
        &self,
        base: &[u8],
        usage: u32,
    ) -> Krb5Result<Vec<u8>> {
        Ok(self.cipher().encryption_key(base, usage)?)
    }

    /// Ki for a usage (the AES families). For RFC 8009 it is the MAC
    /// length, not the key length — 192 bits against 256 for etype 20.
    #[tracing::instrument(level = "debug", skip_all, fields(etype = self.id))]
    pub fn integrity_key(
        &self,
        base: &[u8],
        usage: u32,
    ) -> Krb5Result<Vec<u8>> {
        Ok(self.cipher().integrity_key(base, usage)?)
    }

    /// Kc for a usage (the AES families).
    #[tracing::instrument(level = "debug", skip_all, fields(etype = self.id))]
    pub fn checksum_key(&self, base: &[u8], usage: u32) -> Krb5Result<Vec<u8>> {
        Ok(self.cipher().checksum_key(base, usage)?)
    }

    /// Encrypt under a usage, with a fresh confounder or the one given (a
    /// test's, or a parity vector's): Node's `encrypt(…, confounderForTest)`.
    #[tracing::instrument(level = "debug", skip_all, fields(etype = self.id))]
    pub fn encrypt(
        &self,
        base: &[u8],
        usage: u32,
        plain: &[u8],
        confounder: Option<&[u8]>,
    ) -> Krb5Result<Vec<u8>> {
        Ok(self.cipher().encrypt(base, usage, plain, confounder)?)
    }

    /// Decrypt and verify, the confounder stripped: Node's `decrypt()`.
    #[tracing::instrument(level = "debug", skip_all, fields(etype = self.id))]
    pub fn decrypt(
        &self,
        base: &[u8],
        usage: u32,
        cipher: &[u8],
    ) -> Krb5Result<Vec<u8>> {
        // The confounder is discarded, as in Node.
        let (_confounder, plain) =
            self.decrypt_with_confounder(base, usage, cipher)?;
        Ok(plain)
    }

    /// Decrypt and verify, returning the confounder beside the plaintext
    /// — so a token Node built with a random one can be rebuilt here byte
    /// for byte.
    #[tracing::instrument(level = "debug", skip_all, fields(etype = self.id))]
    pub fn decrypt_with_confounder(
        &self,
        base: &[u8],
        usage: u32,
        data: &[u8],
    ) -> Krb5Result<(Vec<u8>, Vec<u8>)> {
        Ok(self.cipher().decrypt_with_confounder(base, usage, data)?)
    }

    /// The keyed checksum of a message under a usage: Node's `checksum()`.
    #[tracing::instrument(level = "debug", skip_all, fields(etype = self.id))]
    pub fn checksum(
        &self,
        base: &[u8],
        usage: u32,
        message: &[u8],
    ) -> Krb5Result<Vec<u8>> {
        Ok(self.cipher().checksum(base, usage, message)?)
    }

    /// Node's `verifyChecksum()`.
    #[tracing::instrument(level = "debug", skip_all, fields(etype = self.id))]
    pub fn verify_checksum(
        &self,
        base: &[u8],
        usage: u32,
        message: &[u8],
        given: &[u8],
    ) -> Krb5Result<bool> {
        Ok(krb5::equal_constant_time(
            &self.checksum(base, usage, message)?,
            given,
        ))
    }

    /// RFC 3961's pseudo-random function, `sts-crypto`'s.
    #[tracing::instrument(level = "debug", skip_all, fields(etype = self.id))]
    pub fn prf(&self, key: &[u8], octets: &[u8]) -> Krb5Result<Vec<u8>> {
        Ok(sts_crypto::krb5_prf::prf(self.id as i32, key, octets)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{from_hex, to_hex};

    /// RFC 3962 appendix B: string-to-key and the CTS vectors.
    #[test]
    fn rfc3962() {
        let e = Enctype::by_id(17).unwrap();
        let k = e
            .string_to_key(
                "password",
                b"ATHENA.MIT.EDUraeburn",
                Some(&[0, 0, 0, 1]),
            )
            .unwrap();
        assert_eq!(to_hex(&k), "42263c6e89f4fc28b8df68ee09799f15");
        let key = from_hex("636869636b656e207465726979616b69").unwrap();
        let plain = from_hex("4920776f756c64206c696b652074686520").unwrap();
        let c = cts_encrypt(&key, &[0u8; 16], &plain).unwrap();
        assert_eq!(to_hex(&c), "c6353568f2bf8cb4d8a580362da7ff7f97");
        assert_eq!(cts_decrypt(&key, &[0u8; 16], &c).unwrap(), plain);
    }

    #[test]
    fn refusals_name_the_etype() {
        assert_eq!(
            Enctype::by_id(3).unwrap_err().message(),
            "krb5: encryption type 3 (des-cbc-md5) is not implemented here \
             — DES was removed from Windows Server 2025 and is decode-only \
             here"
        );
        assert_eq!(etype_name(26), "camellia256-cts-cmac");
        assert_eq!(etype_name(99), "etype-99");
    }
}
