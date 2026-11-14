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
//! CTS is written here over OpenSSL's unpadded AES-CBC (the design's
//! reason: no crate is trustworthy enough), in Node's shape — CBC-CS3, the
//! last two blocks swapped even for an exact multiple, one block or less
//! plain CBC. HMAC and PBKDF2 are OpenSSL's; HMAC-MD5, MD4 and RC4 are
//! [`crate::primitives`]'.
//!
//! The PRF, PRF+ and KRB-FX-CF2 are `sts_crypto::krb5_prf`'s, as they are
//! `common/crypto.js`'s in Node; [`Enctype::prf`] hands over to it.

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rand::rand_bytes;
use openssl::sign::Signer;
use openssl::symm::{Cipher, Crypter, Mode};

use crate::error::{Krb5Error, Krb5Result};
use crate::primitives;

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
pub fn etype_name(id: i64) -> String {
    match Enctype::find(id) {
        Some(e) => e.name.to_string(),
        None => unsupported_name(id)
            .map(str::to_string)
            .unwrap_or_else(|| format!("etype-{}", id)),
    }
}

/// Node's `isSupportedEtype()`.
pub fn is_supported_etype(id: i64) -> bool {
    SUPPORTED.contains(&id)
}

/// Which construction an enctype is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// RFC 3962: CTS, HMAC-SHA-1-96 over the PLAINTEXT.
    AesSha1,
    /// RFC 8009: CTS, HMAC-SHA-2 over IV | CIPHERTEXT.
    AesSha2,
    /// RFC 4757: RC4 and HMAC-MD5.
    Arcfour,
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

/// Random bytes: Node's `randomBytes()`.
pub fn random_bytes(n: usize) -> Krb5Result<Vec<u8>> {
    let mut out = vec![0u8; n];
    rand_bytes(&mut out)?;
    Ok(out)
}

fn aes_cbc(key: &[u8]) -> Krb5Result<Cipher> {
    Ok(match key.len() {
        16 => Cipher::aes_128_cbc(),
        24 => Cipher::aes_192_cbc(),
        32 => Cipher::aes_256_cbc(),
        n => {
            return Err(Krb5Error::new(format!(
                "krb5: an AES key is 16, 24 or 32 bytes, not {}",
                n
            )))
        }
    })
}

fn cbc(mode: Mode, key: &[u8], iv: &[u8], data: &[u8]) -> Krb5Result<Vec<u8>> {
    if data.len() % 16 != 0 {
        return Err(Krb5Error::new(
            "krb5: raw CBC needs a whole number of blocks",
        ));
    }
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let mut c = Crypter::new(aes_cbc(key)?, mode, key, Some(iv))?;
    c.pad(false);
    let mut out = vec![0u8; data.len() + 16];
    let n = c.update(data, &mut out)?;
    let m = c.finalize(&mut out[n..])?;
    out.truncate(n + m);
    Ok(out)
}

/// Unpadded AES-CBC encryption: Node's `cbcEncryptRaw()` (which drops
/// Web Crypto's padding block; OpenSSL is simply asked for none).
pub fn cbc_encrypt_raw(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
) -> Krb5Result<Vec<u8>> {
    cbc(Mode::Encrypt, key, iv, data)
}

/// Unpadded AES-CBC decryption: Node's `cbcDecryptRaw()`.
pub fn cbc_decrypt_raw(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
) -> Krb5Result<Vec<u8>> {
    cbc(Mode::Decrypt, key, iv, data)
}

/// AES-CBC with ciphertext stealing as Kerberos uses it (CBC-CS3):
/// Node's `ctsEncrypt()`.
pub fn cts_encrypt(key: &[u8], iv: &[u8], plain: &[u8]) -> Krb5Result<Vec<u8>> {
    if plain.len() < 16 {
        return Err(Krb5Error::new(format!(
            "krb5: CTS needs at least one block; got {}",
            plain.len()
        )));
    }
    if plain.len() == 16 {
        return cbc_encrypt_raw(key, iv, plain);
    }
    let m = match plain.len() % 16 {
        0 => 16,
        r => r,
    };
    let mut padded = plain.to_vec();
    padded.resize(plain.len() + (16 - m) % 16, 0);
    let c = cbc_encrypt_raw(key, iv, &padded)?;
    let n = c.len() / 16;
    let mut out = c[..(n - 2) * 16].to_vec();
    out.extend_from_slice(&c[(n - 1) * 16..n * 16]);
    out.extend_from_slice(&c[(n - 2) * 16..(n - 2) * 16 + m]);
    Ok(out)
}

/// The inverse: Node's `ctsDecrypt()`.
pub fn cts_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Krb5Result<Vec<u8>> {
    if data.len() < 16 {
        return Err(Krb5Error::new(
            "krb5: CTS ciphertext shorter than a block",
        ));
    }
    if data.len() == 16 {
        return cbc_decrypt_raw(key, iv, data);
    }
    let m = match data.len() % 16 {
        0 => 16,
        r => r,
    };
    let head = &data[..data.len() - 16 - m];
    let c_last = &data[data.len() - 16 - m..data.len() - m];
    let truncated = &data[data.len() - m..];
    // D(C_n) is (P_n | zeros) XOR C_{n-1}, so the bytes of C_{n-1} that
    // were dropped on the wire are the tail of D(C_n).
    let z = cbc_decrypt_raw(key, &[0u8; 16], c_last)?;
    let mut c_prev = truncated.to_vec();
    c_prev.extend_from_slice(&z[m..]);
    let p_last: Vec<u8> = primitives::xor(&z, &c_prev)[..m].to_vec();
    let mut body = head.to_vec();
    body.extend_from_slice(&c_prev);
    let mut rest = cbc_decrypt_raw(key, iv, &body)?;
    rest.extend(p_last);
    Ok(rest)
}

/// HMAC under a named hash, MD5 through [`primitives::hmac_md5`]: Node's
/// `hmac()`, whose names are Web Crypto's.
pub fn hmac(
    hash_name: &str,
    key: &[u8],
    message: &[u8],
) -> Krb5Result<Vec<u8>> {
    let md = match hash_name {
        "MD5" => return Ok(primitives::hmac_md5(key, message)),
        "SHA-1" => MessageDigest::sha1(),
        "SHA-256" => MessageDigest::sha256(),
        "SHA-384" => MessageDigest::sha384(),
        "SHA-512" => MessageDigest::sha512(),
        other => {
            return Err(Krb5Error::new(format!("krb5: no HMAC over {}", other)))
        }
    };
    let k = PKey::hmac(key)?;
    let mut s = Signer::new(md, &k)?;
    s.update(message)?;
    Ok(s.sign_to_vec()?)
}

/// PBKDF2: Node's `pbkdf2()`, the length in bits.
pub fn pbkdf2(
    hash_name: &str,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out_bits: usize,
) -> Krb5Result<Vec<u8>> {
    let md = match hash_name {
        "SHA-1" => MessageDigest::sha1(),
        "SHA-256" => MessageDigest::sha256(),
        "SHA-384" => MessageDigest::sha384(),
        other => {
            return Err(Krb5Error::new(format!(
                "krb5: no PBKDF2 over {}",
                other
            )))
        }
    };
    let mut out = vec![0u8; out_bits / 8];
    openssl::pkcs5::pbkdf2_hmac(
        password,
        salt,
        iterations as usize,
        md,
        &mut out,
    )?;
    Ok(out)
}

/// RFC 3961 section 5.1's DR: the folded constant encrypted in CBC, fed
/// back, until there are enough bytes. Node's `deriveRandom()`.
pub fn derive_random(
    base_key: &[u8],
    constant: &[u8],
    out_bytes: usize,
) -> Krb5Result<Vec<u8>> {
    let mut block = if constant.len() == 16 {
        constant.to_vec()
    } else {
        primitives::nfold(constant, 128)?
    };
    let mut out = Vec::new();
    while out.len() < out_bytes {
        block = cbc_encrypt_raw(base_key, &[0u8; 16], &block)?;
        out.extend_from_slice(&block);
    }
    out.truncate(out_bytes);
    Ok(out)
}

/// The derivation constant: the usage big-endian, then the purpose byte —
/// 0x99 checksum, 0xAA encryption, 0x55 integrity. Node's
/// `usageConstant()`.
pub fn usage_constant(usage: u32, purpose: u8) -> [u8; 5] {
    let u = usage.to_be_bytes();
    [u[0], u[1], u[2], u[3], purpose]
}

/// RFC 8009 section 3's KDF-HMAC-SHA2: Node's `kdfHmacSha2()`.
pub fn kdf_hmac_sha2(
    hash_name: &str,
    key: &[u8],
    label: &[u8],
    out_bits: u32,
) -> Krb5Result<Vec<u8>> {
    let mut input = vec![0, 0, 0, 1];
    input.extend_from_slice(label);
    input.push(0);
    input.extend_from_slice(&out_bits.to_be_bytes());
    let mut mac = hmac(hash_name, key, &input)?;
    mac.truncate(out_bits as usize / 8);
    Ok(mac)
}

/// RC4-HMAC's usage translation, a wart from an earlier draft: Node's
/// `translateArcfourUsage()`.
pub fn translate_arcfour_usage(usage: u32) -> u32 {
    match usage {
        3 | 9 => 8,
        23 => 13,
        u => u,
    }
}

impl Enctype {
    /// The profile for an id, if this codec performs it.
    pub fn find(id: i64) -> Option<&'static Enctype> {
        ETYPES.iter().find(|e| e.id == id)
    }

    /// Node's `etypeById()`, with its refusal for an etype that is only
    /// named.
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
    pub fn by_name(name: &str) -> Krb5Result<&'static Enctype> {
        ETYPES.iter().find(|e| e.name == name).ok_or_else(|| {
            Krb5Error::new(format!("krb5: no encryption type named {}", name))
        })
    }

    /// Every profile, in Node's key order.
    pub fn all() -> &'static [Enctype] {
        &ETYPES
    }

    fn sha2(&self) -> &'static str {
        if self.key_bytes == 16 {
            "SHA-256"
        } else {
            "SHA-384"
        }
    }

    fn iterations(&self, params: Option<&[u8]>) -> Krb5Result<u32> {
        match params {
            Some(p) if p.len() == 4 => {
                let n = u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
                // RFC 3962: all-zero means 2^32, which no sane KDC sends.
                if n == 0 {
                    return Err(Krb5Error::new(
                        "krb5: s2kparams asks for 2^32 iterations",
                    ));
                }
                Ok(n)
            }
            _ => Ok(self.default_iterations),
        }
    }

    /// string-to-key: RFC 3962 section 4, RFC 8009 section 4, RFC 4757
    /// (unsalted, the NT hash).
    #[tracing::instrument(level = "debug", skip_all, fields(etype = self.id))]
    pub fn string_to_key(
        &self,
        password: &str,
        salt: &[u8],
        params: Option<&[u8]>,
    ) -> Krb5Result<Vec<u8>> {
        match self.family {
            Family::AesSha1 => {
                let iterations = self.iterations(params)?;
                let tkey = pbkdf2(
                    "SHA-1",
                    &primitives::utf8(password),
                    salt,
                    iterations,
                    self.key_bytes * 8,
                )?;
                derive_random(&tkey, b"kerberos", self.key_bytes)
            }
            Family::AesSha2 => {
                let iterations = self.iterations(params)?;
                // saltp puts the enctype name in front of the salt.
                let mut saltp = self.name.as_bytes().to_vec();
                saltp.push(0);
                saltp.extend_from_slice(salt);
                let tkey = pbkdf2(
                    self.sha2(),
                    &primitives::utf8(password),
                    &saltp,
                    iterations,
                    self.key_bytes * 8,
                )?;
                kdf_hmac_sha2(
                    self.sha2(),
                    &tkey,
                    b"kerberos",
                    (self.key_bytes * 8) as u32,
                )
            }
            Family::Arcfour => {
                Ok(primitives::md4(&primitives::utf16le(password)))
            }
        }
    }

    /// Ke for a usage (the AES families).
    pub fn encryption_key(
        &self,
        base: &[u8],
        usage: u32,
    ) -> Krb5Result<Vec<u8>> {
        self.derived(base, usage, 0xaa, (self.key_bytes * 8) as u32)
    }

    /// Ki for a usage (the AES families). For RFC 8009 it is the MAC
    /// length, not the key length — 192 bits against 256 for etype 20.
    pub fn integrity_key(
        &self,
        base: &[u8],
        usage: u32,
    ) -> Krb5Result<Vec<u8>> {
        self.derived(base, usage, 0x55, (self.checksum_bytes * 8) as u32)
    }

    /// Kc for a usage (the AES families).
    pub fn checksum_key(&self, base: &[u8], usage: u32) -> Krb5Result<Vec<u8>> {
        self.derived(base, usage, 0x99, (self.checksum_bytes * 8) as u32)
    }

    fn derived(
        &self,
        base: &[u8],
        usage: u32,
        purpose: u8,
        sha2_bits: u32,
    ) -> Krb5Result<Vec<u8>> {
        let constant = usage_constant(usage, purpose);
        match self.family {
            Family::AesSha1 => derive_random(base, &constant, self.key_bytes),
            Family::AesSha2 => {
                kdf_hmac_sha2(self.sha2(), base, &constant, sha2_bits)
            }
            Family::Arcfour => Err(Krb5Error::new(format!(
                "krb5: {} has no derived keys",
                self.name
            ))),
        }
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
        let conf = match confounder {
            // Node tests `confounderForTest ? … : random`, and an empty
            // Uint8Array is truthy, so an empty confounder is used as is.
            Some(c) => c.to_vec(),
            None => random_bytes(self.confounder_bytes)?,
        };
        match self.family {
            Family::AesSha1 => {
                let ke = self.encryption_key(base, usage)?;
                let ki = self.integrity_key(base, usage)?;
                let mut p = conf;
                p.extend_from_slice(plain);
                let mut c = cts_encrypt(&ke, &[0u8; 16], &p)?;
                let h = hmac("SHA-1", &ki, &p)?;
                c.extend_from_slice(&h[..self.checksum_bytes]);
                Ok(c)
            }
            Family::AesSha2 => {
                let ke = self.encryption_key(base, usage)?;
                let ki = self.integrity_key(base, usage)?;
                let mut p = conf;
                p.extend_from_slice(plain);
                let mut c = cts_encrypt(&ke, &[0u8; 16], &p)?;
                let mut mac_input = vec![0u8; 16];
                mac_input.extend_from_slice(&c);
                let h = hmac(self.sha2(), &ki, &mac_input)?;
                c.extend_from_slice(&h[..self.checksum_bytes]);
                Ok(c)
            }
            Family::Arcfour => {
                let t = translate_arcfour_usage(usage).to_le_bytes();
                let k1 = primitives::hmac_md5(base, &t);
                let mut data = conf;
                data.extend_from_slice(plain);
                let cksum = primitives::hmac_md5(&k1, &data);
                let k3 = primitives::hmac_md5(&k1, &cksum);
                let mut out = cksum;
                out.extend(primitives::rc4(&k3, &data)?);
                Ok(out)
            }
        }
    }

    /// Decrypt and verify, the confounder stripped: Node's `decrypt()`.
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
        let integrity = || {
            Krb5Error::new(format!(
                "krb5: integrity check failed ({}, usage {})",
                self.name, usage
            ))
        };
        match self.family {
            Family::AesSha1 => {
                if data.len() < 16 + self.checksum_bytes {
                    return Err(self.too_short());
                }
                let ke = self.encryption_key(base, usage)?;
                let ki = self.integrity_key(base, usage)?;
                let (c, h) = data.split_at(data.len() - self.checksum_bytes);
                let plain = cts_decrypt(&ke, &[0u8; 16], c)?;
                let expect = hmac("SHA-1", &ki, &plain)?;
                if !primitives::equal_constant_time(
                    h,
                    &expect[..self.checksum_bytes],
                ) {
                    return Err(integrity());
                }
                Ok((plain[..16].to_vec(), plain[16..].to_vec()))
            }
            Family::AesSha2 => {
                if data.len() < 16 + self.checksum_bytes {
                    return Err(self.too_short());
                }
                let ke = self.encryption_key(base, usage)?;
                let ki = self.integrity_key(base, usage)?;
                let (c, h) = data.split_at(data.len() - self.checksum_bytes);
                // Verified BEFORE decrypting: encrypt-then-MAC.
                let mut mac_input = vec![0u8; 16];
                mac_input.extend_from_slice(c);
                let expect = hmac(self.sha2(), &ki, &mac_input)?;
                if !primitives::equal_constant_time(
                    h,
                    &expect[..self.checksum_bytes],
                ) {
                    return Err(integrity());
                }
                let plain = cts_decrypt(&ke, &[0u8; 16], c)?;
                Ok((plain[..16].to_vec(), plain[16..].to_vec()))
            }
            Family::Arcfour => {
                if data.len() < 16 + 8 {
                    return Err(Krb5Error::new(
                        "krb5: ciphertext too short for arcfour-hmac-md5",
                    ));
                }
                let t = translate_arcfour_usage(usage).to_le_bytes();
                let k1 = primitives::hmac_md5(base, &t);
                let cksum = &data[..16];
                let k3 = primitives::hmac_md5(&k1, cksum);
                let plain = primitives::rc4(&k3, &data[16..])?;
                let expect = primitives::hmac_md5(&k1, &plain);
                if !primitives::equal_constant_time(cksum, &expect) {
                    return Err(integrity());
                }
                Ok((plain[..8].to_vec(), plain[8..].to_vec()))
            }
        }
    }

    fn too_short(&self) -> Krb5Error {
        Krb5Error::new(format!("krb5: ciphertext too short for {}", self.name))
    }

    /// The keyed checksum of a message under a usage: Node's `checksum()`.
    #[tracing::instrument(level = "debug", skip_all, fields(etype = self.id))]
    pub fn checksum(
        &self,
        base: &[u8],
        usage: u32,
        message: &[u8],
    ) -> Krb5Result<Vec<u8>> {
        match self.family {
            Family::AesSha1 => {
                let kc = self.checksum_key(base, usage)?;
                let mut h = hmac("SHA-1", &kc, message)?;
                h.truncate(self.checksum_bytes);
                Ok(h)
            }
            Family::AesSha2 => {
                let kc = self.checksum_key(base, usage)?;
                let mut h = hmac(self.sha2(), &kc, message)?;
                h.truncate(self.checksum_bytes);
                Ok(h)
            }
            Family::Arcfour => {
                // RFC 4757 section 4: a signature key from a fixed string,
                // MD5 over the usage and the message, HMAC of that.
                let ksign = primitives::hmac_md5(base, b"signaturekey\0");
                let mut input =
                    translate_arcfour_usage(usage).to_le_bytes().to_vec();
                input.extend_from_slice(message);
                Ok(primitives::hmac_md5(&ksign, &primitives::md5(&input)))
            }
        }
    }

    /// Node's `verifyChecksum()`.
    pub fn verify_checksum(
        &self,
        base: &[u8],
        usage: u32,
        message: &[u8],
        given: &[u8],
    ) -> Krb5Result<bool> {
        Ok(primitives::equal_constant_time(
            &self.checksum(base, usage, message)?,
            given,
        ))
    }

    /// RFC 3961's pseudo-random function, `sts-crypto`'s.
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
