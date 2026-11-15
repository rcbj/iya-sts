// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The cryptography of Kerberos v5's enctypes: what `kerberos/krb5_crypto.js`
//! and `kerberos/krb5_primitives.js` compute, moved here from `sts-kerberos`
//! because every cryptographic operation is this crate's (#453; rcbj,
//! 2026-10-05, hashes and key handling included; `sts-guards`'
//! `crypto_centralised.rs`). `sts-kerberos` keeps the enctype TABLE, the
//! names and the refusals, and asks this module for every byte of
//! cryptography; it depends on no crypto crate.
//!
//! | Here | RFC | Node function |
//! |---|---|---|
//! | [`Profile::string_to_key`] | 3962 s4, 8009 s4, 4757 | `stringToKey()` |
//! | [`Profile::encryption_key`], `integrity_key`, `checksum_key` | 3961 s5.1, 8009 s3 | `deriveKey()` |
//! | [`Profile::encrypt`], [`Profile::decrypt_with_confounder`] | 3961 s5.3, 8009 s5, 4757 | `encrypt()`, `decrypt()` |
//! | [`Profile::checksum`] | 3961 s5.4, 8009 s5, 4757 s4 | `checksum()` |
//! | [`cts_encrypt`], [`cts_decrypt`] | 3962 s5 (CBC-CS3) | `ctsEncrypt()`, `ctsDecrypt()` |
//! | [`derive_random`], [`kdf_hmac_sha2`] | 3961 s5.1, 8009 s3 | `deriveRandom()`, `kdfHmacSha2()` |
//! | [`hmac`], [`pbkdf2`] | 2104, 8018 | `hmac()`, `pbkdf2()` |
//! | [`md4`], [`md5`], [`hmac_md5`], [`rc4`] | 1320, 1321, 2104 | `md4()`, `md5()`, `hmacMd5()`, `rc4()` |
//! | [`equal_constant_time`] | — | `equalConstantTime()` |
//!
//! The PRF, PRF+ and KRB-FX-CF2 stay in [`crate::krb5_prf`], as they are
//! `common/crypto.js` section 9's in Node.
//!
//! **THE SENTENCES ARE `sts-kerberos`'**: every refusal reads `krb5: …`,
//! exactly as it did when this code was that crate's, and an OpenSSL
//! failure reads `krb5: <stack>` (not this crate's usual `OpenSSL: …`),
//! because `Krb5Error::from(CryptoError)` passes the message through and
//! parity with Node is the sentence as well as the verdict.
//!
//! CTS is written here over OpenSSL's unpadded AES-CBC (rust/DESIGN.md
//! section 6's reason: no crate is trustworthy enough), in Node's shape —
//! CBC-CS3, the last two blocks swapped even for an exact multiple, one
//! block plain CBC. HMAC and PBKDF2 are OpenSSL's. MD4, MD5 and RC4 come
//! from RustCrypto (`md4`, `md-5`, `rc4`): OpenSSL 3 keeps MD4 and RC4 in
//! its legacy provider, and a dependency on that provider being loaded is a
//! failure waiting for a deployment that does not load it. HMAC-MD5 is
//! RFC 2104 written over `md-5`, the shape of Node's `hmacMd5()`. All three
//! are broken and are here only because etype 23 (arcfour-hmac-md5) still
//! uses them.

use md4::Md4;
use md5::{Digest, Md5};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::symm::{Cipher, Crypter, Mode};
use rc4::{KeyInit, Rc4, StreamCipher};

use crate::error::{CryptoError, CryptoResult};

/// An OpenSSL failure in `sts-kerberos`' words: `krb5: <stack>`.
fn ossl(e: ErrorStack) -> CryptoError {
    CryptoError::new(format!("krb5: {}", e))
}

fn refuse(message: impl Into<String>) -> CryptoError {
    CryptoError::new(message)
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

/// The parameters of one enctype that its cryptography needs. A LEAF's
/// shape: the table they come from is `sts-kerberos`' `Enctype` (Node's
/// `ETYPES[id]`), and arrives here as an argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    /// The enctype's name, which RFC 8009's saltp puts before the salt.
    pub name: &'static str,
    pub key_bytes: usize,
    pub confounder_bytes: usize,
    pub checksum_bytes: usize,
    /// PBKDF2's iterations when the KDC sends no s2kparams.
    pub default_iterations: u32,
    pub family: Family,
}

/// Random bytes, for a confounder or a key: Node's `randomBytes()`, over
/// [`crate::random`]'s one generator.
#[tracing::instrument(level = "debug", skip_all)]
pub fn random_bytes(n: usize) -> CryptoResult<Vec<u8>> {
    crate::random::random_bytes(n).map_err(|e| {
        // random.rs words an OpenSSL failure `OpenSSL: …`; this module's
        // callers have always read `krb5: …`.
        let m = e.to_string();
        CryptoError::new(format!(
            "krb5: {}",
            m.strip_prefix("OpenSSL: ").unwrap_or(&m)
        ))
    })
}

/// Constant-time comparison, false on a length difference: Node's
/// `equalConstantTime()`. Every checksum verification goes through it, and
/// it is [`crate::secrets::constant_time_equals`], so there is one.
#[tracing::instrument(level = "debug", skip_all)]
pub fn equal_constant_time(a: &[u8], b: &[u8]) -> bool {
    crate::secrets::constant_time_equals(a, b)
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
/// empty key and produce NaN-driven garbage; nothing passes one).
#[tracing::instrument(level = "debug", skip_all)]
pub fn rc4(key: &[u8], data: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut cipher = Rc4::new_from_slice(key).map_err(|_| {
        refuse(format!(
            "krb5: an RC4 key of {} bytes is not usable",
            key.len()
        ))
    })?;
    let mut out = data.to_vec();
    cipher.apply_keystream(&mut out);
    Ok(out)
}

fn aes_cbc(key: &[u8]) -> CryptoResult<Cipher> {
    Ok(match key.len() {
        16 => Cipher::aes_128_cbc(),
        24 => Cipher::aes_192_cbc(),
        32 => Cipher::aes_256_cbc(),
        n => {
            return Err(refuse(format!(
                "krb5: an AES key is 16, 24 or 32 bytes, not {}",
                n
            )))
        }
    })
}

fn cbc(
    mode: Mode,
    key: &[u8],
    iv: &[u8],
    data: &[u8],
) -> CryptoResult<Vec<u8>> {
    if data.len() % 16 != 0 {
        return Err(refuse("krb5: raw CBC needs a whole number of blocks"));
    }
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let mut c =
        Crypter::new(aes_cbc(key)?, mode, key, Some(iv)).map_err(ossl)?;
    c.pad(false);
    let mut out = vec![0u8; data.len() + 16];
    let n = c.update(data, &mut out).map_err(ossl)?;
    let m = c.finalize(&mut out[n..]).map_err(ossl)?;
    out.truncate(n + m);
    Ok(out)
}

/// Unpadded AES-CBC encryption: Node's `cbcEncryptRaw()` (which drops
/// Web Crypto's padding block; OpenSSL is simply asked for none).
#[tracing::instrument(level = "debug", skip_all)]
pub fn cbc_encrypt_raw(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
) -> CryptoResult<Vec<u8>> {
    cbc(Mode::Encrypt, key, iv, data)
}

/// Unpadded AES-CBC decryption: Node's `cbcDecryptRaw()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn cbc_decrypt_raw(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
) -> CryptoResult<Vec<u8>> {
    cbc(Mode::Decrypt, key, iv, data)
}

/// AES-CBC with ciphertext stealing as Kerberos uses it (CBC-CS3):
/// Node's `ctsEncrypt()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn cts_encrypt(
    key: &[u8],
    iv: &[u8],
    plain: &[u8],
) -> CryptoResult<Vec<u8>> {
    if plain.len() < 16 {
        return Err(refuse(format!(
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
#[tracing::instrument(level = "debug", skip_all)]
pub fn cts_decrypt(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
) -> CryptoResult<Vec<u8>> {
    if data.len() < 16 {
        return Err(refuse("krb5: CTS ciphertext shorter than a block"));
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
    let p_last: Vec<u8> =
        z.iter().zip(&c_prev).map(|(x, y)| x ^ y).take(m).collect();
    let mut body = head.to_vec();
    body.extend_from_slice(&c_prev);
    let mut rest = cbc_decrypt_raw(key, iv, &body)?;
    rest.extend(p_last);
    Ok(rest)
}

/// HMAC under a named hash, MD5 through [`hmac_md5`]: Node's `hmac()`,
/// whose names are Web Crypto's.
#[tracing::instrument(level = "debug", skip_all)]
pub fn hmac(
    hash_name: &str,
    key: &[u8],
    message: &[u8],
) -> CryptoResult<Vec<u8>> {
    let md = match hash_name {
        "MD5" => return Ok(hmac_md5(key, message)),
        "SHA-1" => MessageDigest::sha1(),
        "SHA-256" => MessageDigest::sha256(),
        "SHA-384" => MessageDigest::sha384(),
        "SHA-512" => MessageDigest::sha512(),
        other => return Err(refuse(format!("krb5: no HMAC over {}", other))),
    };
    let k = PKey::hmac(key).map_err(ossl)?;
    let mut s = Signer::new(md, &k).map_err(ossl)?;
    s.update(message).map_err(ossl)?;
    s.sign_to_vec().map_err(ossl)
}

/// PBKDF2: Node's `pbkdf2()`, the length in bits.
#[tracing::instrument(level = "debug", skip_all)]
pub fn pbkdf2(
    hash_name: &str,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out_bits: usize,
) -> CryptoResult<Vec<u8>> {
    let md = match hash_name {
        "SHA-1" => MessageDigest::sha1(),
        "SHA-256" => MessageDigest::sha256(),
        "SHA-384" => MessageDigest::sha384(),
        other => return Err(refuse(format!("krb5: no PBKDF2 over {}", other))),
    };
    let mut out = vec![0u8; out_bits / 8];
    openssl::pkcs5::pbkdf2_hmac(
        password,
        salt,
        iterations as usize,
        md,
        &mut out,
    )
    .map_err(ossl)?;
    Ok(out)
}

/// RFC 3961 section 5.1's DR: the folded constant encrypted in CBC, fed
/// back, until there are enough bytes. Node's `deriveRandom()`. An empty
/// constant is refused with n-fold's own sentence, as Node's `nfold()`
/// refuses it.
#[tracing::instrument(level = "debug", skip_all)]
pub fn derive_random(
    base_key: &[u8],
    constant: &[u8],
    out_bytes: usize,
) -> CryptoResult<Vec<u8>> {
    let mut block = if constant.len() == 16 {
        constant.to_vec()
    } else if constant.is_empty() {
        return Err(refuse("krb5: nfold input must not be empty"));
    } else {
        crate::krb5_prf::nfold(constant, 16)
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
#[tracing::instrument(level = "debug", skip_all)]
pub fn usage_constant(usage: u32, purpose: u8) -> [u8; 5] {
    let u = usage.to_be_bytes();
    [u[0], u[1], u[2], u[3], purpose]
}

/// RFC 8009 section 3's KDF-HMAC-SHA2: Node's `kdfHmacSha2()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn kdf_hmac_sha2(
    hash_name: &str,
    key: &[u8],
    label: &[u8],
    out_bits: u32,
) -> CryptoResult<Vec<u8>> {
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
#[tracing::instrument(level = "debug", skip_all)]
pub fn translate_arcfour_usage(usage: u32) -> u32 {
    match usage {
        3 | 9 => 8,
        23 => 13,
        u => u,
    }
}

impl Profile {
    fn sha2(&self) -> &'static str {
        if self.key_bytes == 16 {
            "SHA-256"
        } else {
            "SHA-384"
        }
    }

    fn iterations(&self, params: Option<&[u8]>) -> CryptoResult<u32> {
        match params {
            Some(p) if p.len() == 4 => {
                let n = u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
                // RFC 3962: all-zero means 2^32, which no sane KDC sends.
                if n == 0 {
                    return Err(refuse(
                        "krb5: s2kparams asks for 2^32 iterations",
                    ));
                }
                Ok(n)
            }
            _ => Ok(self.default_iterations),
        }
    }

    /// string-to-key: RFC 3962 section 4, RFC 8009 section 4, RFC 4757
    /// (unsalted, the NT hash). Node's `stringToKey()`; the password's
    /// bytes are its UTF-8 (AES) or UTF-16LE (the NT hash), as Node's
    /// `utf8()` and `utf16le()` make them.
    #[tracing::instrument(level = "debug", skip_all, fields(etype = self.name))]
    pub fn string_to_key(
        &self,
        password: &str,
        salt: &[u8],
        params: Option<&[u8]>,
    ) -> CryptoResult<Vec<u8>> {
        match self.family {
            Family::AesSha1 => {
                let iterations = self.iterations(params)?;
                let tkey = pbkdf2(
                    "SHA-1",
                    password.as_bytes(),
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
                    password.as_bytes(),
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
                let utf16le: Vec<u8> = password
                    .encode_utf16()
                    .flat_map(|u| u.to_le_bytes())
                    .collect();
                Ok(md4(&utf16le))
            }
        }
    }

    /// Ke for a usage (the AES families).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn encryption_key(
        &self,
        base: &[u8],
        usage: u32,
    ) -> CryptoResult<Vec<u8>> {
        self.derived(base, usage, 0xaa, (self.key_bytes * 8) as u32)
    }

    /// Ki for a usage (the AES families). For RFC 8009 it is the MAC
    /// length, not the key length — 192 bits against 256 for etype 20.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn integrity_key(
        &self,
        base: &[u8],
        usage: u32,
    ) -> CryptoResult<Vec<u8>> {
        self.derived(base, usage, 0x55, (self.checksum_bytes * 8) as u32)
    }

    /// Kc for a usage (the AES families).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn checksum_key(
        &self,
        base: &[u8],
        usage: u32,
    ) -> CryptoResult<Vec<u8>> {
        self.derived(base, usage, 0x99, (self.checksum_bytes * 8) as u32)
    }

    fn derived(
        &self,
        base: &[u8],
        usage: u32,
        purpose: u8,
        sha2_bits: u32,
    ) -> CryptoResult<Vec<u8>> {
        let constant = usage_constant(usage, purpose);
        match self.family {
            Family::AesSha1 => derive_random(base, &constant, self.key_bytes),
            Family::AesSha2 => {
                kdf_hmac_sha2(self.sha2(), base, &constant, sha2_bits)
            }
            Family::Arcfour => {
                Err(refuse(format!("krb5: {} has no derived keys", self.name)))
            }
        }
    }

    /// Encrypt under a usage, with a fresh confounder or the one given (a
    /// test's, or a parity vector's): Node's `encrypt(…, confounderForTest)`.
    #[tracing::instrument(level = "debug", skip_all, fields(etype = self.name))]
    pub fn encrypt(
        &self,
        base: &[u8],
        usage: u32,
        plain: &[u8],
        confounder: Option<&[u8]>,
    ) -> CryptoResult<Vec<u8>> {
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
                let k1 = hmac_md5(base, &t);
                let mut data = conf;
                data.extend_from_slice(plain);
                let cksum = hmac_md5(&k1, &data);
                let k3 = hmac_md5(&k1, &cksum);
                let mut out = cksum;
                out.extend(rc4(&k3, &data)?);
                Ok(out)
            }
        }
    }

    /// Decrypt and verify, returning the confounder beside the plaintext
    /// — so a token Node built with a random one can be rebuilt byte for
    /// byte. Node's `decrypt()`, which discards the confounder.
    #[tracing::instrument(level = "debug", skip_all, fields(etype = self.name))]
    pub fn decrypt_with_confounder(
        &self,
        base: &[u8],
        usage: u32,
        data: &[u8],
    ) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        let integrity = || {
            refuse(format!(
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
                if !equal_constant_time(h, &expect[..self.checksum_bytes]) {
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
                if !equal_constant_time(h, &expect[..self.checksum_bytes]) {
                    return Err(integrity());
                }
                let plain = cts_decrypt(&ke, &[0u8; 16], c)?;
                Ok((plain[..16].to_vec(), plain[16..].to_vec()))
            }
            Family::Arcfour => {
                if data.len() < 16 + 8 {
                    return Err(refuse(
                        "krb5: ciphertext too short for arcfour-hmac-md5",
                    ));
                }
                let t = translate_arcfour_usage(usage).to_le_bytes();
                let k1 = hmac_md5(base, &t);
                let cksum = &data[..16];
                let k3 = hmac_md5(&k1, cksum);
                let plain = rc4(&k3, &data[16..])?;
                let expect = hmac_md5(&k1, &plain);
                if !equal_constant_time(cksum, &expect) {
                    return Err(integrity());
                }
                Ok((plain[..8].to_vec(), plain[8..].to_vec()))
            }
        }
    }

    fn too_short(&self) -> CryptoError {
        refuse(format!("krb5: ciphertext too short for {}", self.name))
    }

    /// The keyed checksum of a message under a usage: Node's `checksum()`.
    #[tracing::instrument(level = "debug", skip_all, fields(etype = self.name))]
    pub fn checksum(
        &self,
        base: &[u8],
        usage: u32,
        message: &[u8],
    ) -> CryptoResult<Vec<u8>> {
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
                let ksign = hmac_md5(base, b"signaturekey\0");
                let mut input =
                    translate_arcfour_usage(usage).to_le_bytes().to_vec();
                input.extend_from_slice(message);
                Ok(hmac_md5(&ksign, &md5(&input)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    /// RFC 1320 and RFC 1321's own vectors, RFC 2202's HMAC-MD5, and the
    /// RC4 test vector everyone quotes.
    #[test]
    fn md4_md5_hmac_rc4() {
        assert_eq!(hex(&md4(b"abc")), "a448017aaf21d8525fc10ae87aa6729d");
        assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hex(&hmac_md5(b"Jefe", b"what do ya want for nothing?")),
            "750c783e6ab0b503eaa86e310a5db738"
        );
        assert_eq!(
            hex(&rc4(b"Key", b"Plaintext").unwrap()),
            "bbf316e8d940af0ad3"
        );
        assert!(equal_constant_time(b"ab", b"ab"));
        assert!(!equal_constant_time(b"ab", b"abc"));
    }

    /// RFC 3962 appendix B: string-to-key and a CTS vector.
    #[test]
    fn rfc3962() {
        let p = Profile {
            name: "aes128-cts-hmac-sha1-96",
            key_bytes: 16,
            confounder_bytes: 16,
            checksum_bytes: 12,
            default_iterations: 4096,
            family: Family::AesSha1,
        };
        let k = p
            .string_to_key(
                "password",
                b"ATHENA.MIT.EDUraeburn",
                Some(&[0, 0, 0, 1]),
            )
            .unwrap();
        assert_eq!(hex(&k), "42263c6e89f4fc28b8df68ee09799f15");
        let key = b"chicken teriyaki";
        let plain = b"I would like the ";
        let c = cts_encrypt(key, &[0u8; 16], plain).unwrap();
        assert_eq!(hex(&c), "c6353568f2bf8cb4d8a580362da7ff7f97");
        assert_eq!(cts_decrypt(key, &[0u8; 16], &c).unwrap(), plain);
    }
}
