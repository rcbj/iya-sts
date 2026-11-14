// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! JWE (RFC 7516 compact serialization) — a port of `common/crypto.js`
//! sections 4 and 4a's JWE half. Every `alg` reaches the two functions
//! [`encrypt_compact`] and [`decrypt_compact`], as every one reaches
//! `encryptJweCompact()` and `decryptJweCompact()` in Node (rule 3r):
//!
//! * RSA-OAEP, RSA-OAEP-256; ECDH-ES and ECDH-ES+A128/192/256KW on P-256,
//!   P-384 and P-521 (Concat KDF, RFC 7518 4.6);
//! * A128/192/256KW, A128/192/256GCMKW, PBES2-HS256+A128KW,
//!   PBES2-HS384+A192KW, PBES2-HS512+A256KW and `dir`;
//! * ML-KEM-512/768/1024 and their +A128/192/256KW forms
//!   (draft-ietf-jose-pqc-kem-05, KMAC256 KDF, the KEM ciphertext in `ek`,
//!   the private key the 64-octet `d || z`);
//! * HPKE-0 to HPKE-16, Integrated and `-KE` Key Encryption
//!   (draft-ietf-jose-hpke-encrypt-22; draft-reddy-cose-jose-pqc-hybrid-
//!   hpke-11 for 8 to 16), a pre-shared key by `psk_id`;
//! * content: A128/192/256GCM and A128CBC-HS256, A192CBC-HS384,
//!   A256CBC-HS512; `zip: DEF` when encrypting.
//!
//! **What is refused stays refused**: RSA1_5 (named, in every mode), a
//! compressed request (no `zip_values_supported` is advertised), a PBES2
//! iteration count above 1,000,000 (a caller choosing it would be choosing
//! how long the process blocks), a key of the wrong size for an AES key
//! wrap (RFC 7518 4.4 has no key derivation); and, unless the caller's
//! [`JwePolicy`] says its mode allows them, AES-CBC content encryption
//! (`mode.allowsCbcJwe()`, #1486) and RSA-OAEP over SHA-1
//! (`mode.allowsLegacyHashes()`, #1469).
//!
//! **PBES2 IS NEVER DERIVED BY THE TWO PLAIN DOORS** (ASVS 5.0.0 11.4.4).
//! Node's `encryptJweCompact()` and `decryptJweCompact()` refuse a PBES2 JWE
//! that arrives without a key derived beforehand, because 600,000 PBKDF2
//! iterations on the thread that answers every other request is a stall;
//! `encryptJweCompactAsync()` and `decryptJweCompactAsync()` derive on
//! libuv's thread pool and hand the key in. Here the same split is
//! [`encrypt_compact`] / [`decrypt_compact`], which refuse in Node's words,
//! and [`encrypt_compact_derived`] / [`decrypt_compact_derived`], which
//! derive and BLOCK: an async caller runs them under
//! `tokio::task::spawn_blocking`, never on a reactor thread.

use openssl::aes::{unwrap_key, wrap_key, AesKey};
use openssl::bn::BigNum;
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey};
use openssl::encrypt::{Decrypter, Encrypter};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Padding;
use openssl::symm::{decrypt, decrypt_aead, encrypt, encrypt_aead, Cipher};
use serde_json::{json, Map, Value as Json};

use crate::b64;
use crate::error::{CryptoError, CryptoResult};
use crate::hpke::{self, Suite};
use crate::keys::curve_of;

fn err(message: impl Into<String>) -> CryptoError {
    CryptoError::new(message)
}

fn random(length: usize) -> CryptoResult<Vec<u8>> {
    let mut bytes = vec![0u8; length];
    openssl::rand::rand_bytes(&mut bytes)?;
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// The tables.
// ---------------------------------------------------------------------------

/// A content encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Enc {
    pub name: &'static str,
    pub cek_bytes: usize,
    /// CBC-HMAC's hash; `None` for GCM.
    pub mac: Option<MacHash>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacHash {
    Sha256,
    Sha384,
    Sha512,
}

pub const ENCS: [Enc; 6] = [
    Enc {
        name: "A128GCM",
        cek_bytes: 16,
        mac: None,
    },
    Enc {
        name: "A192GCM",
        cek_bytes: 24,
        mac: None,
    },
    Enc {
        name: "A256GCM",
        cek_bytes: 32,
        mac: None,
    },
    Enc {
        name: "A128CBC-HS256",
        cek_bytes: 32,
        mac: Some(MacHash::Sha256),
    },
    Enc {
        name: "A192CBC-HS384",
        cek_bytes: 48,
        mac: Some(MacHash::Sha384),
    },
    Enc {
        name: "A256CBC-HS512",
        cek_bytes: 64,
        mac: Some(MacHash::Sha512),
    },
];

pub fn enc(name: &str) -> Option<Enc> {
    ENCS.iter().copied().find(|e| e.name == name)
}

/// How an `alg` establishes the content key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgKind {
    RsaOaep {
        sha256: bool,
    },
    /// `None`: direct ECDH-ES; `Some(n)`: a KEK of n bytes for AES-KW.
    EcdhEs(Option<usize>),
    AesKw(usize),
    AesGcmKw(usize),
    Pbes2 {
        kw: usize,
        sha: u16,
    },
    Dir,
    /// ML-KEM, direct (`kw` 0) or with key wrapping.
    MlKem {
        set: &'static str,
        kw: usize,
    },
    Hpke {
        suite: Suite,
        integrated: bool,
        key_type: &'static str,
        crv: &'static str,
    },
}

/// A JWE `alg`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JweAlg {
    pub name: String,
    pub kind: AlgKind,
}

impl JweAlg {
    pub fn is_symmetric(&self) -> bool {
        matches!(
            self.kind,
            AlgKind::AesKw(_)
                | AlgKind::AesGcmKw(_)
                | AlgKind::Pbes2 { .. }
                | AlgKind::Dir
        )
    }

    pub fn is_integrated(&self) -> bool {
        matches!(
            self.kind,
            AlgKind::Hpke {
                integrated: true,
                ..
            }
        )
    }
}

/// The HPKE rows: number, KEM, KDF, AEAD, key type, curve, and whether a
/// `-KE` form exists (jose-hpke-encrypt-22 removed HPKE-4-KE and -6-KE).
const HPKE_ROWS: [(u8, u16, u16, u16, &str, &str, bool); 17] = [
    (0, 0x0010, 0x0001, 0x0001, "EC", "P-256", true),
    (1, 0x0011, 0x0002, 0x0002, "EC", "P-384", true),
    (2, 0x0012, 0x0003, 0x0002, "EC", "P-521", true),
    (3, 0x0020, 0x0001, 0x0001, "OKP", "X25519", true),
    (4, 0x0020, 0x0001, 0x0003, "OKP", "X25519", false),
    (5, 0x0021, 0x0003, 0x0002, "OKP", "X448", true),
    (6, 0x0021, 0x0003, 0x0003, "OKP", "X448", false),
    (7, 0x0010, 0x0001, 0x0002, "EC", "P-256", true),
    (8, 0x0050, 0x0011, 0x0002, "AKP", "", true),
    (9, 0x0050, 0x0011, 0x0003, "AKP", "", true),
    (10, 0x647a, 0x0011, 0x0002, "AKP", "", true),
    (11, 0x647a, 0x0011, 0x0003, "AKP", "", true),
    (12, 0x0051, 0x0011, 0x0002, "AKP", "", true),
    (13, 0x0051, 0x0011, 0x0003, "AKP", "", true),
    (14, 0x0040, 0x0011, 0x0001, "AKP", "", true),
    (15, 0x0041, 0x0011, 0x0002, "AKP", "", true),
    (16, 0x0042, 0x0011, 0x0002, "AKP", "", true),
];

/// Every `alg`, in `crypto.js`'s `JWE_ALGS` order: RSA, ECDH, ML-KEM, HPKE,
/// then the symmetric ones.
pub fn algs() -> Vec<JweAlg> {
    let mut out = Vec::new();
    let mut add = |name: String, kind: AlgKind| {
        out.push(JweAlg { name, kind });
    };
    add("RSA-OAEP-256".into(), AlgKind::RsaOaep { sha256: true });
    add("RSA-OAEP".into(), AlgKind::RsaOaep { sha256: false });
    add("ECDH-ES".into(), AlgKind::EcdhEs(None));
    for (bits, bytes) in [(128, 16), (192, 24), (256, 32)] {
        add(format!("ECDH-ES+A{}KW", bits), AlgKind::EcdhEs(Some(bytes)));
    }
    for set in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"] {
        add(set.into(), AlgKind::MlKem { set, kw: 0 });
    }
    for (set, bits) in [
        ("ML-KEM-512", 128),
        ("ML-KEM-768", 192),
        ("ML-KEM-1024", 256),
    ] {
        add(
            format!("{}+A{}KW", set, bits),
            AlgKind::MlKem { set, kw: bits / 8 },
        );
    }
    for (n, kem, kdf, aead, key_type, crv, ke) in HPKE_ROWS {
        let suite = Suite { kem, kdf, aead };
        add(
            format!("HPKE-{}", n),
            AlgKind::Hpke {
                suite,
                integrated: true,
                key_type,
                crv,
            },
        );
        if ke {
            add(
                format!("HPKE-{}-KE", n),
                AlgKind::Hpke {
                    suite,
                    integrated: false,
                    key_type,
                    crv,
                },
            );
        }
    }
    for (bits, bytes) in [(128, 16), (192, 24), (256, 32)] {
        add(format!("A{}KW", bits), AlgKind::AesKw(bytes));
    }
    for (bits, bytes) in [(128, 16), (192, 24), (256, 32)] {
        add(format!("A{}GCMKW", bits), AlgKind::AesGcmKw(bytes));
    }
    for (sha, kw) in [(256, 16), (384, 24), (512, 32)] {
        add(
            format!("PBES2-HS{}+A{}KW", sha, kw * 8),
            AlgKind::Pbes2 { kw, sha },
        );
    }
    add("dir".into(), AlgKind::Dir);
    out
}

pub fn alg(name: &str) -> Option<JweAlg> {
    algs().into_iter().find(|a| a.name == name)
}

/// RFC 7518 section 4.8.1.2 gives no ceiling and says a recipient SHOULD
/// pick one (`PBES2_MAX_ITERATIONS`).
pub const PBES2_MAX_ITERATIONS: u64 = 1_000_000;
/// OWASP's figure for PBKDF2-HMAC-SHA256 (ASVS 5.0.0 11.4.4), what every
/// PBES2 JWE this service makes is stretched by (`PBES2_DEFAULT_ITERATIONS`,
/// 8192 until #1512).
pub const PBES2_DEFAULT_ITERATIONS: u64 = 600_000;
/// RFC 7518 section 4.8.1.2: "A minimum iteration count of 1000 is
/// RECOMMENDED" — the floor `security.pbes2MinIterations` cannot go below.
pub const PBES2_MIN_ITERATIONS: u64 = 1000;

/// What the caller's mode lets JWE do. sts-crypto reads no settings, so the
/// two `common/mode.js` questions are answered at the call site and handed
/// in: `cbc` is `mode.allowsCbcJwe()` (#1486, ASVS 5.0.0 11.3.2) and
/// `legacy_hashes` is `mode.allowsLegacyHashes()` (#1469, ASVS 5.0.0
/// 11.4.1). The default is product's answer with neither setting on, so a
/// caller that forgets to ask is refused rather than let through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JwePolicy {
    pub cbc: bool,
    pub legacy_hashes: bool,
}

impl JwePolicy {
    /// Product mode with `crypto.allowCbcJwe` and `crypto.allowLegacyHashes`
    /// both off, their defaults.
    pub const PRODUCT: JwePolicy = JwePolicy {
        cbc: false,
        legacy_hashes: false,
    };

    /// Development mode, where both answers are yes.
    pub const DEVELOPMENT: JwePolicy = JwePolicy {
        cbc: true,
        legacy_hashes: true,
    };
}

impl Default for JwePolicy {
    fn default() -> Self {
        JwePolicy::PRODUCT
    }
}

/// `refuseCbcJwe()`: an AES-CBC `enc` unless the mode allows it. Node tests
/// the name for `CBC`, so an unknown name containing it is refused here
/// before it is refused as unknown.
fn refuse_cbc(enc: &str, policy: JwePolicy) -> CryptoResult<()> {
    if enc.contains("CBC") && !policy.cbc {
        return Err(err(format!(
            "enc \"{}\" is AES-CBC, which needs crypto.allowCbcJwe on.",
            enc
        )));
    }
    Ok(())
}

/// The refusal of RSA-OAEP (OAEP over SHA-1) when legacy hashes are off.
fn refuse_legacy_oaep(alg: &JweAlg, policy: JwePolicy) -> CryptoResult<()> {
    if matches!(alg.kind, AlgKind::RsaOaep { sha256: false })
        && !policy.legacy_hashes
    {
        return Err(err("alg \"RSA-OAEP\" is OAEP over SHA-1, which needs \
             crypto.allowLegacyHashes on."));
    }
    Ok(())
}

/// A PBES2 key derived before the plain doors run — what Node's async
/// doors hand `symmetricKek()` as `options.pbes2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pbes2Key {
    pub alg: String,
    /// The `p2s` salt input (not the PBKDF2 salt, which prefixes the alg).
    pub salt: Vec<u8>,
    pub iterations: u64,
    pub key: Vec<u8>,
}

/// JavaScript's `Number(value)` over a JSON member, for the `p2c` a sender
/// wrote: a string of digits is a number to Node, so it is one here.
fn js_number(value: Option<&Json>) -> f64 {
    match value {
        None => f64::NAN,
        Some(Json::Null) => 0.0,
        Some(Json::Bool(b)) => f64::from(u8::from(*b)),
        Some(Json::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
        Some(Json::String(text)) => js_string_to_number(text),
        Some(Json::Array(items)) => match items.as_slice() {
            [] => 0.0,
            [one] => js_string_to_number(&js_string(Some(one))),
            _ => f64::NAN,
        },
        Some(Json::Object(_)) => f64::NAN,
    }
}

/// ECMAScript's StringToNumber: trimmed, empty is 0, decimal with an
/// optional sign and exponent, `Infinity`, or an unsigned 0x/0o/0b integer.
/// Rust's own float parser also takes `inf` and `NaN`, which Node does not.
fn js_string_to_number(text: &str) -> f64 {
    let t = text.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    if t.is_empty() {
        return 0.0;
    }
    for (prefix, radix) in [("0x", 16), ("0X", 16), ("0o", 8), ("0O", 8)]
        .into_iter()
        .chain([("0b", 2), ("0B", 2)])
    {
        if let Some(digits) = t.strip_prefix(prefix) {
            return if !digits.is_empty()
                && digits.chars().all(|c| c.is_digit(radix))
            {
                digits.chars().fold(0.0, |acc, c| {
                    acc * f64::from(radix)
                        + f64::from(c.to_digit(radix).unwrap_or(0))
                })
            } else {
                f64::NAN
            };
        }
    }
    let unsigned = t.strip_prefix(['+', '-']).unwrap_or(t);
    if unsigned == "Infinity" {
        return if t.starts_with('-') {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        };
    }
    let (mantissa, exponent) = match unsigned.find(['e', 'E']) {
        Some(at) => (&unsigned[..at], Some(&unsigned[at + 1..])),
        None => (unsigned, None),
    };
    let digits_ok = {
        let mut parts = mantissa.splitn(2, '.');
        let whole = parts.next().unwrap_or("");
        let fraction = parts.next().unwrap_or("");
        (!whole.is_empty() || !fraction.is_empty())
            && whole.chars().all(|c| c.is_ascii_digit())
            && fraction.chars().all(|c| c.is_ascii_digit())
    };
    let exponent_ok = exponent.is_none_or(|e| {
        let e = e.strip_prefix(['+', '-']).unwrap_or(e);
        !e.is_empty() && e.chars().all(|c| c.is_ascii_digit())
    });
    if !digits_ok || !exponent_ok {
        return f64::NAN;
    }
    t.parse::<f64>().unwrap_or(f64::NAN)
}

/// JavaScript's `String(value)` over a JSON member, for quoting what a
/// sender wrote in a refusal exactly as Node quotes it.
fn js_string(value: Option<&Json>) -> String {
    match value {
        None => "undefined".into(),
        Some(Json::Null) => "null".into(),
        Some(Json::Bool(b)) => b.to_string(),
        Some(Json::Number(n)) => match n.as_f64() {
            Some(f) => js_number_text(f),
            None => n.to_string(),
        },
        Some(Json::String(text)) => text.clone(),
        Some(Json::Array(items)) => items
            .iter()
            .map(|item| match item {
                Json::Null => String::new(),
                other => js_string(Some(other)),
            })
            .collect::<Vec<_>>()
            .join(","),
        Some(Json::Object(_)) => "[object Object]".into(),
    }
}

/// A number as JavaScript prints it, for the integers and plain decimals a
/// `p2c` holds (the exponent forms above 1e21 aside).
fn js_number_text(f: f64) -> String {
    if f.is_nan() {
        return "NaN".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "Infinity" } else { "-Infinity" }.into();
    }
    if f.fract() == 0.0 && f.abs() < 1e21 {
        return format!("{}", f as i128);
    }
    format!("{}", f)
}

// ---------------------------------------------------------------------------
// Content encryption.
// ---------------------------------------------------------------------------

fn mac_md(hash: MacHash) -> MessageDigest {
    match hash {
        MacHash::Sha256 => MessageDigest::sha256(),
        MacHash::Sha384 => MessageDigest::sha384(),
        MacHash::Sha512 => MessageDigest::sha512(),
    }
}

fn gcm_cipher(key_len: usize) -> CryptoResult<Cipher> {
    match key_len {
        16 => Ok(Cipher::aes_128_gcm()),
        24 => Ok(Cipher::aes_192_gcm()),
        32 => Ok(Cipher::aes_256_gcm()),
        n => Err(err(format!("no AES-GCM with a {}-bit key", n * 8))),
    }
}

fn cbc_cipher(key_len: usize) -> CryptoResult<Cipher> {
    match key_len {
        16 => Ok(Cipher::aes_128_cbc()),
        24 => Ok(Cipher::aes_192_cbc()),
        32 => Ok(Cipher::aes_256_cbc()),
        n => Err(err(format!("no AES-CBC with a {}-bit key", n * 8))),
    }
}

/// RFC 7518 5.2.2.1's tag: the MAC key is the first half of the CEK.
fn cbc_hmac_tag(
    hash: MacHash,
    cek: &[u8],
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> CryptoResult<Vec<u8>> {
    let half = cek.len() / 2;
    let al = (aad.len() as u64 * 8).to_be_bytes();
    let key = PKey::hmac(&cek[..half])?;
    let mut signer = openssl::sign::Signer::new(mac_md(hash), &key)?;
    let mac =
        signer.sign_oneshot_to_vec(&[aad, iv, ciphertext, &al].concat())?;
    Ok(mac[..half].to_vec())
}

/// `(ciphertext, tag)`.
pub fn seal_content(
    enc: Enc,
    cek: &[u8],
    iv: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    if let Some(hash) = enc.mac {
        let half = cek.len() / 2;
        let ciphertext =
            encrypt(cbc_cipher(half)?, &cek[half..], Some(iv), plaintext)?;
        let tag = cbc_hmac_tag(hash, cek, iv, aad, &ciphertext)?;
        return Ok((ciphertext, tag));
    }
    let mut tag = vec![0u8; 16];
    let ciphertext = encrypt_aead(
        gcm_cipher(cek.len())?,
        cek,
        Some(iv),
        aad,
        plaintext,
        &mut tag,
    )?;
    Ok((ciphertext, tag))
}

pub fn open_content(
    enc: Enc,
    cek: &[u8],
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> CryptoResult<Vec<u8>> {
    if let Some(hash) = enc.mac {
        let expected = cbc_hmac_tag(hash, cek, iv, aad, ciphertext)?;
        if expected.len() != tag.len() || !openssl::memcmp::eq(&expected, tag) {
            return Err(err("the authentication tag does not verify"));
        }
        let half = cek.len() / 2;
        return decrypt(cbc_cipher(half)?, &cek[half..], Some(iv), ciphertext)
            .map_err(|_| err("the ciphertext does not decrypt"));
    }
    if iv.len() != 12 || tag.len() != 16 {
        return Err(err(format!(
            "an AES-GCM JWE carries a 96-bit IV and a 128-bit authentication \
             tag (RFC 7518 section 5.3); this one has {} and {} bits",
            iv.len() * 8,
            tag.len() * 8
        )));
    }
    decrypt_aead(gcm_cipher(cek.len())?, cek, Some(iv), aad, ciphertext, tag)
        .map_err(|_| err("the authentication tag does not verify"))
}

// ---------------------------------------------------------------------------
// Key management.
// ---------------------------------------------------------------------------

fn u32_be(n: usize) -> [u8; 4] {
    (n as u32).to_be_bytes()
}

fn party_info(header: &Map<String, Json>, name: &str) -> Vec<u8> {
    header
        .get(name)
        .and_then(Json::as_str)
        .filter(|v| !v.is_empty())
        .and_then(|v| b64::decode_loose(v).ok())
        .unwrap_or_default()
}

/// RFC 7518 4.6.2's Concat KDF over SHA-256.
pub fn concat_kdf(
    z: &[u8],
    key_bytes: usize,
    alg_id: &str,
    header: &Map<String, Json>,
) -> Vec<u8> {
    let (apu, apv) = (party_info(header, "apu"), party_info(header, "apv"));
    let other = [
        &u32_be(alg_id.len())[..],
        alg_id.as_bytes(),
        &u32_be(apu.len()),
        &apu,
        &u32_be(apv.len()),
        &apv,
        &u32_be(key_bytes * 8),
    ]
    .concat();
    let mut out = Vec::new();
    let mut round = 1usize;
    while out.len() < key_bytes {
        out.extend(openssl::sha::sha256(
            &[&u32_be(round)[..], z, &other].concat(),
        ));
        round += 1;
    }
    out.truncate(key_bytes);
    out
}

/// RFC 3394 AES Key Wrap.
pub fn aes_key_wrap(kek: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() < 16 || key.len() % 8 != 0 {
        return Err(err(format!(
            "AES Key Wrap wraps a whole number of 64-bit semiblocks, at least \
             two (RFC 3394 section 2.2); this key is {} octets.",
            key.len()
        )));
    }
    let aes = AesKey::new_encrypt(kek).map_err(|_| err("a bad AES-KW key"))?;
    let mut out = vec![0u8; key.len() + 8];
    wrap_key(&aes, None, &mut out, key)
        .map_err(|_| err("AES Key Wrap failed"))?;
    Ok(out)
}

pub fn aes_key_unwrap(kek: &[u8], wrapped: &[u8]) -> CryptoResult<Vec<u8>> {
    if wrapped.len() < 24 || wrapped.len() % 8 != 0 {
        return Err(err(format!(
            "an AES-wrapped key is a whole number of 64-bit semiblocks, at \
             least three (RFC 3394 section 2.2); this one is {} octets.",
            wrapped.len()
        )));
    }
    let aes = AesKey::new_decrypt(kek).map_err(|_| err("a bad AES-KW key"))?;
    let mut out = vec![0u8; wrapped.len() - 8];
    unwrap_key(&aes, None, &mut out, wrapped)
        .map_err(|_| err("the AES-wrapped key does not unwrap"))?;
    Ok(out)
}

/// draft-ietf-jose-pqc-kem-05's KDF: KMAC256 over the KEM secret.
pub fn mlkem_jose_kdf(
    shared: &[u8],
    algorithm_id: &str,
    key_bytes: usize,
) -> Vec<u8> {
    let id = algorithm_id.as_bytes();
    let x = [&u32_be(id.len())[..], id, &u32_be(key_bytes * 8)].concat();
    hpke::kmac256(shared, &x, key_bytes)
}

/// The JOSE-HPKE Recipient_structure: the `info` of Key Encryption.
fn recipient_structure(enc: &str, extra: &[u8]) -> Vec<u8> {
    [
        b"JOSE-HPKE rcpt".as_slice(),
        &[0xff],
        enc.as_bytes(),
        &[0xff],
        extra,
    ]
    .concat()
}

fn pbes2_key(
    name: &str,
    kw: usize,
    sha: u16,
    password: &[u8],
    salt_input: &[u8],
    iterations: u64,
) -> CryptoResult<Vec<u8>> {
    let salt = [name.as_bytes(), &[0], salt_input].concat();
    let md = match sha {
        384 => MessageDigest::sha384(),
        512 => MessageDigest::sha512(),
        _ => MessageDigest::sha256(),
    };
    let mut out = vec![0u8; kw];
    openssl::pkcs5::pbkdf2_hmac(
        password,
        &salt,
        iterations as usize,
        md,
        &mut out,
    )?;
    Ok(out)
}

fn symmetric_kek(
    alg: &JweAlg,
    secret: &[u8],
    header: &mut Map<String, Json>,
    for_encrypt: bool,
    prepared: Option<&Pbes2Key>,
) -> CryptoResult<Vec<u8>> {
    match alg.kind {
        AlgKind::Pbes2 { .. } => {
            // THE KEY WAS DERIVED BEFORE THIS RAN (`symmetricKek()`): the
            // plain doors never stretch a password, and a PBES2 JWE that
            // reaches one without a derived key is refused in Node's words.
            let Some(prepared) = prepared else {
                return Err(err(format!(
                    "a {} JWE needs its key derived off the event loop: this \
                     caller must use encryptJweCompactAsync() or \
                     decryptJweCompactAsync().",
                    alg.name
                )));
            };
            if for_encrypt {
                header.insert(
                    "p2s".into(),
                    Json::from(b64::encode(&prepared.salt)),
                );
                header.insert("p2c".into(), Json::from(prepared.iterations));
            } else {
                let count = js_number(header.get("p2c")).floor();
                if js_string(header.get("p2s")) != b64::encode(&prepared.salt)
                    || count != prepared.iterations as f64
                    || prepared.alg != alg.name
                {
                    return Err(err(
                        "the PBES2 key derived for this JWE does not match \
                         its header.",
                    ));
                }
            }
            Ok(prepared.key.clone())
        }
        AlgKind::Dir => Ok(secret.to_vec()),
        AlgKind::AesKw(need) | AlgKind::AesGcmKw(need) => {
            if secret.len() != need {
                return Err(err(format!(
                    "{} wraps with a {}-bit key and the key given is {} bits. \
                     RFC 7518 section 4.4 has no key derivation in it — the \
                     key must be exactly that size, or use a PBES2 algorithm, \
                     which stretches a password on purpose.",
                    alg.name,
                    need * 8,
                    secret.len() * 8
                )));
            }
            Ok(secret.to_vec())
        }
        _ => Err(err("not a symmetric alg")),
    }
}

/// The recipient's KEM public key from a JWK, as the alg needs it.
fn kem_public_key(alg: &JweAlg, jwk: &Json) -> CryptoResult<Vec<u8>> {
    let (key_type, crv, want) = match alg.kind {
        AlgKind::MlKem { set, .. } => (
            "AKP",
            "",
            hpke::ml_kem_set(set).map(|s| s.public_len).unwrap_or(0),
        ),
        AlgKind::Hpke {
            suite,
            key_type,
            crv,
            ..
        } => (key_type, crv, hpke::kem(suite.kem)?.n_pk),
        _ => return Err(err("not a KEM alg")),
    };
    let kty = jwk.get("kty").and_then(Json::as_str).unwrap_or("");
    if kty != key_type {
        return Err(err(format!(
            "alg \"{}\" encrypts to a key of type \"{}\"{} and this key is \
             \"{}\"",
            alg.name,
            key_type,
            if crv.is_empty() {
                String::new()
            } else {
                format!(" ({})", crv)
            },
            if kty.is_empty() { "(none)" } else { kty }
        )));
    }
    let member = |name: &str| {
        b64::decode_loose(jwk.get(name).and_then(Json::as_str).unwrap_or(""))
    };
    let jwk_alg = jwk.get("alg").and_then(Json::as_str);
    if key_type == "AKP" {
        if jwk_alg != Some(alg.name.as_str()) {
            return Err(err(format!(
                "an AKP key names exactly one algorithm, and this one is for \
                 \"{}\", not \"{}\"",
                jwk_alg.unwrap_or("(none)"),
                alg.name
            )));
        }
        let public = member("pub")?;
        if public.len() != want {
            return Err(err(format!(
                "the AKP key's `pub` is {} octets and \"{}\" takes {}",
                public.len(),
                alg.name,
                want
            )));
        }
        return Ok(public);
    }
    if let Some(named) = jwk_alg {
        if named != alg.name {
            return Err(err(format!(
                "this key names alg \"{}\", not \"{}\"",
                named, alg.name
            )));
        }
    }
    let jwk_crv = jwk.get("crv").and_then(Json::as_str).unwrap_or("");
    if jwk_crv != crv {
        return Err(err(format!(
            "alg \"{}\" encrypts to a {} key and this one is \"{}\"",
            alg.name,
            crv,
            if jwk_crv.is_empty() {
                "(none)"
            } else {
                jwk_crv
            }
        )));
    }
    if key_type == "OKP" {
        return member("x");
    }
    let size = hpke::Nist::by_name(crv)
        .map(|c| c.scalar_len())
        .unwrap_or(0);
    let (x, y) = (member("x")?, member("y")?);
    if x.len() != size || y.len() != size {
        return Err(err(format!("a {} key has {}-octet x and y", crv, size)));
    }
    Ok([&[0x04u8][..], &x, &y].concat())
}

/// The recipient's KEM private key from a JWK: an AKP `priv`, or an EC or
/// OKP `d` (an EC one left-padded to the scalar's size).
fn kem_private_key(alg: &JweAlg, jwk: Option<&Json>) -> CryptoResult<Vec<u8>> {
    let jwk = jwk.ok_or_else(|| {
        err(format!(
            "alg \"{}\" is encrypted to a private key and this caller was \
             given none",
            alg.name
        ))
    })?;
    let text = |name: &str| jwk.get(name).and_then(Json::as_str).unwrap_or("");
    let (key_type, crv) = match alg.kind {
        AlgKind::MlKem { .. } => ("AKP", ""),
        AlgKind::Hpke { key_type, crv, .. } => (key_type, crv),
        _ => return Err(err("not a KEM alg")),
    };
    if key_type == "AKP" {
        if text("kty") != "AKP"
            || text("alg") != alg.name
            || text("priv").is_empty()
        {
            return Err(err(format!(
                "alg \"{}\" is decrypted with an AKP key for that algorithm, \
                 and the key held is {}",
                alg.name,
                // Each of the three ways this fails is named, rather than
                // an AKP key with no alg quoted as for "".
                if text("kty") == "AKP" && text("alg") == alg.name {
                    "that algorithm's, with no private part".to_string()
                } else if text("kty") == "AKP" && text("alg").is_empty() {
                    "an AKP key naming no algorithm".to_string()
                } else if text("kty") == "AKP" {
                    format!("for \"{}\"", text("alg"))
                } else {
                    format!(
                        "of type \"{}\"",
                        if text("kty").is_empty() {
                            "(none)"
                        } else {
                            text("kty")
                        }
                    )
                }
            )));
        }
        return b64::decode_loose(text("priv"));
    }
    if text("kty") != key_type || text("crv") != crv || text("d").is_empty() {
        return Err(err(format!(
            "alg \"{}\" is decrypted with a {} private key, and the key held \
             is {}",
            alg.name,
            crv,
            [text("crv"), text("kty"), "(none)"]
                .into_iter()
                .find(|s| !s.is_empty())
                .unwrap_or("(none)")
        )));
    }
    let d = b64::decode_loose(text("d"))?;
    if key_type == "EC" {
        let size = hpke::Nist::by_name(crv)
            .map(|c| c.scalar_len())
            .unwrap_or(0);
        if d.len() < size {
            return Ok([vec![0u8; size - d.len()], d].concat());
        }
    }
    Ok(d)
}

/// The PSK of a JWE: chosen by the sender, looked up by `psk_id` by the
/// recipient.
fn psk_for_encrypt<'a>(
    options: &'a EncryptOptions,
    header: &mut Map<String, Json>,
) -> (&'a [u8], &'a [u8]) {
    match options.psk {
        Some(psk) if !psk.is_empty() => {
            header.insert(
                "psk_id".into(),
                Json::from(b64::encode(options.psk_id)),
            );
            (psk, options.psk_id)
        }
        _ => (&[], &[]),
    }
}

fn psk_for_decrypt(
    options: &DecryptOptions,
    header: &Map<String, Json>,
) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    let Some(id) = header.get("psk_id") else {
        return Ok((Vec::new(), Vec::new()));
    };
    let id = b64::decode_loose(id.as_str().unwrap_or(""))?;
    let psk = options.psk.and_then(|lookup| lookup(&id)).ok_or_else(|| {
        err(
            "this JWE names an HPKE pre-shared key (psk_id) and this caller \
             holds none for it",
        )
    })?;
    Ok((psk, id))
}

fn ec_public_from_jwk(jwk: &Json) -> CryptoResult<PKey<Public>> {
    let crv = jwk.get("crv").and_then(Json::as_str).unwrap_or("");
    let nid = curve_of(crv)
        .filter(|_| matches!(crv, "P-256" | "P-384" | "P-521"))
        .ok_or_else(|| {
            err(format!(
                "the key names curve \"{}\", and this service agrees over \
                 P-256, P-384, P-521.",
                crv
            ))
        })?;
    let group = EcGroup::from_curve_name(nid)?;
    let member = |name: &str| -> CryptoResult<BigNum> {
        Ok(BigNum::from_slice(&b64::decode_loose(
            jwk.get(name).and_then(Json::as_str).unwrap_or(""),
        )?)?)
    };
    let (x, y) = (member("x")?, member("y")?);
    let key = EcKey::from_public_key_affine_coordinates(&group, &x, &y)?;
    key.check_key()?;
    Ok(PKey::from_ec_key(key)?)
}

fn rsa_public_from_jwk(jwk: &Json) -> CryptoResult<PKey<Public>> {
    crate::keys::JwsKey::from_jwk(jwk)?.public_key()
}

// ---------------------------------------------------------------------------
// Encrypt.
// ---------------------------------------------------------------------------

/// What to encrypt to, and how.
#[derive(Default, Clone)]
pub struct EncryptOptions<'a> {
    /// RSA-OAEP-256 when not given.
    pub alg: Option<&'a str>,
    pub enc: &'a str,
    /// `JWT` when not given.
    pub typ: Option<&'a str>,
    pub cty: Option<&'a str>,
    /// `DEF` or nothing.
    pub zip: Option<&'a str>,
    /// The recipient's public JWK, for every asymmetric alg; its `kid` goes
    /// in the header.
    pub jwk: Option<&'a Json>,
    /// The shared key or password, for the symmetric algs.
    pub secret: Option<&'a [u8]>,
    pub psk: Option<&'a [u8]>,
    pub psk_id: &'a [u8],
    /// Key Encryption's Recipient_structure extra info.
    pub recipient_extra_info: &'a [u8],
    /// Integrated Encryption's HPKE `info`.
    pub hpke_info: &'a [u8],
    /// A PBES2 key derived beforehand ([`encrypt_compact_derived`]).
    pub pbes2: Option<&'a Pbes2Key>,
    /// What the caller's mode allows.
    pub policy: JwePolicy,
}

fn deflate(body: &[u8]) -> CryptoResult<Vec<u8>> {
    use std::io::Write;
    let mut encoder = flate2::write::DeflateEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    );
    encoder
        .write_all(body)
        .map_err(|e| err(format!("deflate: {}", e)))?;
    encoder.finish().map_err(|e| err(format!("deflate: {}", e)))
}

fn base_header(
    alg: &str,
    enc: Option<&str>,
    options: &EncryptOptions,
    body: &mut Vec<u8>,
) -> CryptoResult<Map<String, Json>> {
    let mut header = Map::new();
    header.insert("alg".into(), Json::from(alg));
    if let Some(enc) = enc {
        header.insert("enc".into(), Json::from(enc));
    }
    header.insert("typ".into(), Json::from(options.typ.unwrap_or("JWT")));
    if let Some(cty) = options.cty {
        header.insert("cty".into(), Json::from(cty));
    }
    match options.zip {
        None | Some("") => {}
        Some("DEF") => {
            header.insert("zip".into(), Json::from("DEF"));
            *body = deflate(body)?;
        }
        Some(other) => {
            return Err(err(format!(
                "encryptJweCompact: unsupported zip \"{}\"; this service \
                 compresses with DEF only.",
                other
            )))
        }
    }
    if let Some(kid) = options
        .jwk
        .and_then(|j| j.get("kid"))
        .and_then(Json::as_str)
    {
        header.insert("kid".into(), Json::from(kid));
    }
    Ok(header)
}

/// `(cek, encrypted key)`.
fn wrap_cek(
    alg: &JweAlg,
    cek: Vec<u8>,
    header: &mut Map<String, Json>,
    options: &EncryptOptions,
    content: Enc,
) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    match alg.kind {
        AlgKind::MlKem { set, kw } => {
            let jwk = options.jwk.ok_or_else(|| err("no recipient key"))?;
            let public = kem_public_key(alg, jwk)?;
            let set =
                hpke::ml_kem_set(set).ok_or_else(|| err("no ML-KEM set"))?;
            let (shared, ct) = set.encaps(&public)?;
            header.insert("ek".into(), Json::from(b64::encode(&ct)));
            if kw == 0 {
                return Ok((
                    mlkem_jose_kdf(&shared, content.name, cek.len()),
                    Vec::new(),
                ));
            }
            let kek = mlkem_jose_kdf(&shared, &alg.name, kw);
            let wrapped = aes_key_wrap(&kek, &cek)?;
            Ok((cek, wrapped))
        }
        AlgKind::Hpke { suite, .. } => {
            let jwk = options.jwk.ok_or_else(|| err("no recipient key"))?;
            let public = kem_public_key(alg, jwk)?;
            let (psk, psk_id) = psk_for_encrypt(options, header);
            let info =
                recipient_structure(content.name, options.recipient_extra_info);
            let (enc, mut context) = hpke::setup_sender(
                suite,
                &public,
                &hpke::SetupOptions {
                    info: &info,
                    psk,
                    psk_id,
                },
            )?;
            header.insert("ek".into(), Json::from(b64::encode(&enc)));
            let wrapped = context.seal(b"", &cek)?;
            Ok((cek, wrapped))
        }
        AlgKind::AesKw(_)
        | AlgKind::AesGcmKw(_)
        | AlgKind::Pbes2 { .. }
        | AlgKind::Dir => {
            let secret = options.secret.unwrap_or(&[]);
            let kek = symmetric_kek(alg, secret, header, true, options.pbes2)?;
            match alg.kind {
                AlgKind::Dir => {
                    if kek.len() != content.cek_bytes {
                        return Err(err(format!(
                            "encryptJweCompact: alg \"dir\" uses the shared key \
                             AS the content encryption key, so it must be \
                             exactly {} bytes for {}; this one is {}.",
                            content.cek_bytes,
                            content.name,
                            kek.len()
                        )));
                    }
                    Ok((kek, Vec::new()))
                }
                AlgKind::AesGcmKw(_) => {
                    let iv = random(12)?;
                    let mut tag = vec![0u8; 16];
                    let wrapped = encrypt_aead(
                        gcm_cipher(kek.len())?,
                        &kek,
                        Some(&iv),
                        b"",
                        &cek,
                        &mut tag,
                    )?;
                    header.insert("iv".into(), Json::from(b64::encode(&iv)));
                    header.insert("tag".into(), Json::from(b64::encode(&tag)));
                    Ok((cek, wrapped))
                }
                _ => {
                    let wrapped = aes_key_wrap(&kek, &cek)?;
                    Ok((cek, wrapped))
                }
            }
        }
        AlgKind::RsaOaep { sha256 } => {
            let jwk = options.jwk.ok_or_else(|| err("no recipient key"))?;
            let public = rsa_public_from_jwk(jwk)?;
            refuse_legacy_oaep(alg, options.policy)?;
            let md = if sha256 {
                MessageDigest::sha256()
            } else {
                MessageDigest::sha1()
            };
            let mut encrypter = Encrypter::new(&public)?;
            encrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
            encrypter.set_rsa_oaep_md(md)?;
            encrypter.set_rsa_mgf1_md(md)?;
            let mut out = vec![0u8; encrypter.encrypt_len(&cek)?];
            let written = encrypter.encrypt(&cek, &mut out)?;
            out.truncate(written);
            Ok((cek, out))
        }
        AlgKind::EcdhEs(kw) => {
            let jwk = options.jwk.ok_or_else(|| err("no recipient key"))?;
            let recipient = ec_public_from_jwk(jwk)?;
            let group = recipient.ec_key()?.group().curve_name();
            let group = EcGroup::from_curve_name(
                group.ok_or_else(|| err("no curve"))?,
            )?;
            let ephemeral = PKey::from_ec_key(EcKey::generate(&group)?)?;
            let mut deriver = Deriver::new(&ephemeral)?;
            deriver.set_peer(&recipient)?;
            let z = deriver.derive_to_vec()?;
            drop(deriver);
            let epk = crate::keys::JwsKey::of(crate::keys::Material::Private(
                ephemeral,
            ))
            .public_jwk()?
            .unwrap_or(Json::Null);
            header.insert(
                "epk".into(),
                json!({"kty": epk["kty"], "crv": epk["crv"], "x": epk["x"], "y": epk["y"]}),
            );
            match kw {
                None => Ok((
                    concat_kdf(&z, cek.len(), content.name, header),
                    Vec::new(),
                )),
                Some(bytes) => {
                    let kek = concat_kdf(&z, bytes, &alg.name, header);
                    let wrapped = aes_key_wrap(&kek, &cek)?;
                    Ok((cek, wrapped))
                }
            }
        }
    }
}

/// Encrypts `plaintext` as a compact JWE.
pub fn encrypt_compact(
    plaintext: &[u8],
    options: &EncryptOptions,
) -> CryptoResult<String> {
    let alg_name = options.alg.unwrap_or("RSA-OAEP-256");
    let alg =
        alg(alg_name).ok_or_else(|| {
            err(format!(
            "encryptJweCompact: unsupported alg \"{}\"; this service encrypts \
             with {}.",
            alg_name,
            algs().iter().map(|a| a.name.clone()).collect::<Vec<_>>().join(", ")
        ))
        })?;
    let mut body = plaintext.to_vec();
    if alg.is_integrated() {
        let AlgKind::Hpke { suite, .. } = alg.kind else {
            return Err(err("unreachable"));
        };
        let mut header = base_header(alg_name, None, options, &mut body)?;
        let jwk = options.jwk.ok_or_else(|| err("no recipient key"))?;
        let public = kem_public_key(&alg, jwk)?;
        let (psk, psk_id) = psk_for_encrypt(options, &mut header);
        let header_b64 =
            b64::encode(Json::Object(header).to_string().as_bytes());
        let (enc, mut context) = hpke::setup_sender(
            suite,
            &public,
            &hpke::SetupOptions {
                info: options.hpke_info,
                psk,
                psk_id,
            },
        )?;
        let ct = context.seal(header_b64.as_bytes(), &body)?;
        return Ok(format!(
            "{}.{}..{}.",
            header_b64,
            b64::encode(&enc),
            b64::encode(&ct)
        ));
    }
    refuse_cbc(options.enc, options.policy)?;
    let content = enc(options.enc).ok_or_else(|| {
        err(format!(
            "encryptJweCompact: unsupported enc \"{}\"; this service encrypts \
             with {}.",
            options.enc,
            ENCS.iter().map(|e| e.name).collect::<Vec<_>>().join(", ")
        ))
    })?;
    let cek = random(content.cek_bytes)?;
    let iv = random(if content.mac.is_some() { 16 } else { 12 })?;
    let mut header =
        base_header(alg_name, Some(content.name), options, &mut body)?;
    let (cek, encrypted_key) =
        wrap_cek(&alg, cek, &mut header, options, content)?;
    let header_b64 = b64::encode(Json::Object(header).to_string().as_bytes());
    let (ciphertext, tag) =
        seal_content(content, &cek, &iv, header_b64.as_bytes(), &body)?;
    Ok([
        header_b64,
        b64::encode(&encrypted_key),
        b64::encode(&iv),
        b64::encode(&ciphertext),
        b64::encode(&tag),
    ]
    .join("."))
}

/// `encryptJweCompactAsync()`: [`encrypt_compact`], with a PBES2 key
/// derived first — a new 16-byte salt and [`PBES2_DEFAULT_ITERATIONS`].
/// Every other alg goes straight to [`encrypt_compact`].
///
/// **This blocks for the whole PBKDF2 stretch.** An async caller runs it
/// under `spawn_blocking`, as Node runs the derivation on libuv's pool.
#[tracing::instrument(level = "debug", skip_all)]
pub fn encrypt_compact_derived(
    plaintext: &[u8],
    options: &EncryptOptions,
) -> CryptoResult<String> {
    let alg_name = options.alg.unwrap_or("RSA-OAEP-256");
    let Some(found) = alg(alg_name) else {
        return encrypt_compact(plaintext, options);
    };
    let AlgKind::Pbes2 { kw, sha } = found.kind else {
        return encrypt_compact(plaintext, options);
    };
    // RFC 7518 section 4.8.1.1: a new salt for every encryption.
    let salt = random(16)?;
    let key = pbes2_key(
        &found.name,
        kw,
        sha,
        options.secret.unwrap_or(&[]),
        &salt,
        PBES2_DEFAULT_ITERATIONS,
    )?;
    let prepared = Pbes2Key {
        alg: found.name.clone(),
        salt,
        iterations: PBES2_DEFAULT_ITERATIONS,
        key,
    };
    let mut derived = options.clone();
    derived.pbes2 = Some(&prepared);
    encrypt_compact(plaintext, &derived)
}

// ---------------------------------------------------------------------------
// Decrypt.
// ---------------------------------------------------------------------------

/// Looks up a pre-shared key by its `psk_id`.
pub type PskLookup<'a> = &'a dyn Fn(&[u8]) -> Option<Vec<u8>>;

/// What to decrypt with, and what to accept.
#[derive(Default, Clone)]
pub struct DecryptOptions<'a> {
    /// RSA-OAEP and ECDH-ES.
    pub private_key: Option<&'a PKey<Private>>,
    /// ML-KEM and HPKE (an AKP, EC or OKP private JWK).
    pub private_jwk: Option<&'a Json>,
    /// The symmetric algs.
    pub secret: Option<&'a [u8]>,
    pub allowed_alg: Option<&'a [&'a str]>,
    pub allowed_enc: Option<&'a [&'a str]>,
    pub expected_kid: Option<&'a str>,
    pub psk: Option<PskLookup<'a>>,
    pub recipient_extra_info: &'a [u8],
    pub hpke_info: &'a [u8],
    /// A PBES2 key derived beforehand ([`decrypt_compact_derived`]).
    pub pbes2: Option<&'a Pbes2Key>,
    /// `security.pbes2MinIterations`: the fewest PBKDF2 iterations a PBES2
    /// JWE may name. 0 is RFC 7518's 1000, and the value is held to
    /// 1000..=1,000,000 as `pbes2MinIterations()` holds it.
    pub pbes2_min_iterations: u64,
    /// What the caller's mode allows.
    pub policy: JwePolicy,
}

/// What a JWE decrypted to.
#[derive(Debug, Clone, PartialEq)]
pub struct Decrypted {
    pub header: Map<String, Json>,
    pub plaintext: Vec<u8>,
}

const PART_NAMES: [&str; 5] = [
    "",
    "JWE encrypted key",
    "JWE IV",
    "JWE ciphertext",
    "JWE tag",
];

fn unwrap_cek(
    alg: &JweAlg,
    header: &Map<String, Json>,
    encrypted_key: &[u8],
    options: &DecryptOptions,
    content: Enc,
) -> CryptoResult<Vec<u8>> {
    if alg.is_symmetric() {
        let secret =
            options.secret.filter(|s| !s.is_empty()).ok_or_else(|| {
                err(format!(
                "alg \"{}\" is encrypted to a SHARED SECRET and this caller \
                 holds none for the sender. A client that encrypts to this \
                 service should use RSA-OAEP-256 against the key in its JWKS, \
                 or one of the symmetric algorithms with the client_secret as \
                 the key.",
                alg.name
            ))
            })?;
        let mut header = header.clone();
        let kek =
            symmetric_kek(alg, secret, &mut header, false, options.pbes2)?;
        return match alg.kind {
            AlgKind::Dir => Ok(kek),
            AlgKind::AesGcmKw(_) => {
                let (iv, tag) = (
                    header.get("iv").and_then(Json::as_str).unwrap_or(""),
                    header.get("tag").and_then(Json::as_str).unwrap_or(""),
                );
                if iv.is_empty() || tag.is_empty() {
                    return Err(err(format!(
                        "a {} JWE carries the key wrapping's IV and \
                         authentication tag in the header as `iv` and `tag` \
                         (RFC 7518 section 4.7.1); this one has {}.",
                        alg.name,
                        if !iv.is_empty() {
                            "no tag"
                        } else if !tag.is_empty() {
                            "no iv"
                        } else {
                            "neither"
                        }
                    )));
                }
                let (iv, tag) =
                    (b64::decode_loose(iv)?, b64::decode_loose(tag)?);
                if iv.len() != 12 || tag.len() != 16 {
                    return Err(err(format!(
                        "a {} JWE carries a 96-bit `iv` and a 128-bit `tag` \
                         (RFC 7518 section 4.7.1); this one has {} and {} bits.",
                        alg.name,
                        iv.len() * 8,
                        tag.len() * 8
                    )));
                }
                decrypt_aead(
                    gcm_cipher(kek.len())?,
                    &kek,
                    Some(&iv),
                    b"",
                    encrypted_key,
                    &tag,
                )
                .map_err(|_| err("the wrapped key does not open"))
            }
            _ => aes_key_unwrap(&kek, encrypted_key),
        };
    }
    match alg.kind {
        AlgKind::MlKem { set, kw } => {
            let ek = ek_of(alg, header)?;
            let private = kem_private_key(alg, options.private_jwk)?;
            let set =
                hpke::ml_kem_set(set).ok_or_else(|| err("no ML-KEM set"))?;
            let shared = set.decaps(&private, &ek)?;
            if kw == 0 {
                if !encrypted_key.is_empty() {
                    return Err(err(
                        "direct key agreement leaves the JWE Encrypted Key \
                         empty (pqc-kem-05 section 6.1), and this one is not",
                    ));
                }
                return Ok(mlkem_jose_kdf(
                    &shared,
                    content.name,
                    content.cek_bytes,
                ));
            }
            aes_key_unwrap(
                &mlkem_jose_kdf(&shared, &alg.name, kw),
                encrypted_key,
            )
        }
        AlgKind::Hpke { suite, .. } => {
            let ek = ek_of(alg, header)?;
            let private = kem_private_key(alg, options.private_jwk)?;
            let (psk, psk_id) = psk_for_decrypt(options, header)?;
            let info =
                recipient_structure(content.name, options.recipient_extra_info);
            let mut context = hpke::setup_receiver(
                suite,
                &ek,
                &private,
                &hpke::SetupOptions {
                    info: &info,
                    psk: &psk,
                    psk_id: &psk_id,
                },
            )?;
            context.open(b"", encrypted_key)
        }
        AlgKind::RsaOaep { sha256 } => {
            let key = options.private_key.ok_or_else(|| {
                err(format!(
                    "alg \"{}\" is encrypted to a PRIVATE KEY and this caller \
                     was given none.",
                    alg.name
                ))
            })?;
            refuse_legacy_oaep(alg, options.policy)?;
            let md = if sha256 {
                MessageDigest::sha256()
            } else {
                MessageDigest::sha1()
            };
            let mut decrypter = Decrypter::new(key)?;
            decrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
            decrypter.set_rsa_oaep_md(md)?;
            decrypter.set_rsa_mgf1_md(md)?;
            let mut out = vec![0u8; decrypter.decrypt_len(encrypted_key)?];
            let written = decrypter
                .decrypt(encrypted_key, &mut out)
                .map_err(|_| err("the RSA-OAEP key does not decrypt"))?;
            out.truncate(written);
            Ok(out)
        }
        AlgKind::EcdhEs(kw) => {
            let key = options.private_key.ok_or_else(|| {
                err(format!(
                    "alg \"{}\" is encrypted to a PRIVATE KEY and this caller \
                     was given none.",
                    alg.name
                ))
            })?;
            let epk = header.get("epk").filter(|e| e.get("crv").is_some()).ok_or_else(|| {
                err("an ECDH-ES JWE carries the sender's ephemeral public key in \
                     the header as `epk` (RFC 7518 section 4.6.1.1) and this one \
                     has none.")
            })?;
            let sender = ec_public_from_jwk(epk)?;
            let mut deriver = Deriver::new(key)?;
            deriver.set_peer(&sender)?;
            let z = deriver.derive_to_vec()?;
            match kw {
                None => {
                    Ok(concat_kdf(&z, content.cek_bytes, content.name, header))
                }
                Some(bytes) => aes_key_unwrap(
                    &concat_kdf(&z, bytes, &alg.name, header),
                    encrypted_key,
                ),
            }
        }
        _ => Err(err("unreachable alg kind")),
    }
}

fn ek_of(alg: &JweAlg, header: &Map<String, Json>) -> CryptoResult<Vec<u8>> {
    let ek = header
        .get("ek")
        .and_then(Json::as_str)
        .filter(|e| !e.is_empty());
    let ek = ek.ok_or_else(|| {
        err(format!(
            "an \"{}\" JWE carries the KEM ciphertext in the header as `ek` \
             and this one has none",
            alg.name
        ))
    })?;
    b64::decode_strict(ek, "JWE ek")
}

/// Decrypts a compact JWE.
pub fn decrypt_compact(
    compact: &str,
    options: &DecryptOptions,
) -> CryptoResult<Decrypted> {
    let parts: Vec<&str> = compact.trim().split('.').collect();
    if parts.len() != 5 {
        return Err(err(format!(
            "an encrypted request must be a JWE in compact serialization \
             (five dot-separated parts); this has {}.",
            parts.len()
        )));
    }
    let header: Map<String, Json> =
        b64::decode_strict(parts[0], "JWE protected header")
            .and_then(|bytes| {
                serde_json::from_slice(&bytes).map_err(|e| err(e.to_string()))
            })
            .map_err(|e| {
                err(format!(
                    "the JWE protected header is not valid base64url JSON: {}",
                    e
                ))
            })?;
    let alg_name = header.get("alg").and_then(Json::as_str).unwrap_or("");
    if alg_name == "RSA1_5" {
        return Err(err(
            "this service does not decrypt RSA1_5, deliberately: RFC 8017 \
             deprecated PKCS#1 v1.5 encryption, and implementing it safely \
             means making an unwrap failure indistinguishable from every \
             later failure, which is a property of a whole code path rather \
             than of one function. Use RSA-OAEP-256.",
        ));
    }
    let alg = alg(alg_name).ok_or_else(|| {
        err(format!(
            "this service decrypts with alg {}; the request used \"{}\".",
            algs()
                .iter()
                .map(|a| a.name.clone())
                .collect::<Vec<_>>()
                .join(", "),
            alg_name
        ))
    })?;
    if let Some(allowed) = options.allowed_alg {
        if !allowed.contains(&alg_name) {
            return Err(err(format!(
                "this endpoint accepts alg {}; the request used \"{}\".",
                allowed.join(", "),
                alg_name
            )));
        }
    }
    let check_rest = |header: &Map<String, Json>| -> CryptoResult<()> {
        if header.get("zip").is_some_and(|z| !z.is_null() && z != "") {
            return Err(err(
                "this service advertises no zip_values_supported, so a \
                 compressed request cannot be read.",
            ));
        }
        if let Some(kid) = options.expected_kid {
            let held = header.get("kid").and_then(Json::as_str);
            if held != Some(kid) {
                return Err(err(format!(
                    "the JWE kid \"{}\" is not this service's current \
                     encryption key \"{}\". Re-read the metadata — from the \
                     same trust realm, since each realm has a key of its own: \
                     this key is regenerated when the service restarts in \
                     development mode and when it is rotated.",
                    held.unwrap_or("(absent)"),
                    kid
                )));
            }
        }
        for i in 1..5 {
            b64::decode_strict(parts[i], PART_NAMES[i])?;
        }
        Ok(())
    };
    if alg.is_integrated() {
        check_rest(&header)?;
        let AlgKind::Hpke { suite, .. } = alg.kind else {
            return Err(err("unreachable"));
        };
        let opened = (|| {
            if header.get("enc").is_some() {
                return Err(err(format!(
                    "alg \"{}\" is HPKE Integrated Encryption, whose header \
                     MUST NOT carry `enc` (jose-hpke-encrypt-22 section 5)",
                    alg.name
                )));
            }
            if header.get("ek").is_some() {
                return Err(err(format!(
                    "alg \"{}\" carries the encapsulated secret as the JWE \
                     Encrypted Key, and its header MUST NOT carry `ek` \
                     (jose-hpke-encrypt-22 section 5)",
                    alg.name
                )));
            }
            if !parts[2].is_empty() || !parts[4].is_empty() {
                return Err(err(format!(
                    "HPKE Integrated Encryption leaves the JWE IV and \
                     Authentication Tag empty (jose-hpke-encrypt-22 section \
                     5), and this JWE carries {}",
                    if parts[2].is_empty() {
                        "a tag"
                    } else {
                        "an IV"
                    }
                )));
            }
            let private = kem_private_key(&alg, options.private_jwk)?;
            let (psk, psk_id) = psk_for_decrypt(options, &header)?;
            let mut context = hpke::setup_receiver(
                suite,
                &b64::decode_loose(parts[1])?,
                &private,
                &hpke::SetupOptions {
                    info: options.hpke_info,
                    psk: &psk,
                    psk_id: &psk_id,
                },
            )?;
            context.open(parts[0].as_bytes(), &b64::decode_loose(parts[3])?)
        })()
        .map_err(|e| {
            err(format!(
                "the HPKE Integrated Encryption JWE did not decrypt: {}",
                e
            ))
        })?;
        return Ok(Decrypted {
            header,
            plaintext: opened,
        });
    }
    let enc_name = header.get("enc").and_then(Json::as_str).unwrap_or("");
    refuse_cbc(&js_string(header.get("enc")), options.policy)?;
    let default_encs: Vec<&str> = ENCS.iter().map(|e| e.name).collect();
    let allowed = options.allowed_enc.unwrap_or(&default_encs);
    if !allowed.contains(&enc_name) {
        return Err(err(format!(
            "this service supports enc {}; the request used \"{}\".",
            allowed.join(" or "),
            header
                .get("enc")
                .and_then(Json::as_str)
                .unwrap_or("undefined")
        )));
    }
    check_rest(&header)?;
    let content = enc(enc_name).ok_or_else(|| err("unknown enc"))?;
    let cek = unwrap_cek(
        &alg,
        &header,
        &b64::decode_loose(parts[1])?,
        options,
        content,
    )
    .map_err(|e| {
        err(format!(
            "the content encryption key could not be unwrapped: {}",
            e
        ))
    })?;
    if cek.len() != content.cek_bytes {
        return Err(err(format!(
            "the unwrapped content encryption key is {} bytes; {} needs {}.",
            cek.len(),
            content.name,
            content.cek_bytes
        )));
    }
    let plaintext = open_content(
        content,
        &cek,
        &b64::decode_loose(parts[2])?,
        parts[0].as_bytes(),
        &b64::decode_loose(parts[3])?,
        &b64::decode_loose(parts[4])?,
    )
    .map_err(|e| {
        err(format!(
            "the ciphertext did not decrypt or its authentication tag did not \
             verify: {}",
            e
        ))
    })?;
    Ok(Decrypted { header, plaintext })
}

/// `pbes2MinIterations()`: the caller's floor, held to RFC 7518's
/// recommended minimum below and to the ceiling above.
fn pbes2_min_iterations(asked: u64) -> u64 {
    if asked < PBES2_MIN_ITERATIONS {
        PBES2_MIN_ITERATIONS
    } else {
        asked.min(PBES2_MAX_ITERATIONS)
    }
}

/// `decryptJweCompactAsync()`: [`decrypt_compact`], with a PBES2 key
/// derived first for a JWE this caller would open. Its refusals come first
/// and in Node's order: no `p2s`, a `p2c` below
/// [`DecryptOptions::pbes2_min_iterations`], one above
/// [`PBES2_MAX_ITERATIONS`]. A JWE it is going to refuse anyway (another
/// alg, one the caller does not allow, no secret to derive from) is not
/// derived for: the refusal is [`decrypt_compact`]'s.
///
/// **This blocks for the whole PBKDF2 stretch**; see
/// [`encrypt_compact_derived`].
#[tracing::instrument(level = "debug", skip_all)]
pub fn decrypt_compact_derived(
    compact: &str,
    options: &DecryptOptions,
) -> CryptoResult<Decrypted> {
    let parts: Vec<&str> = compact.trim().split('.').collect();
    // Node reads the header leniently here (`Buffer.from(…, 'base64url')`);
    // a header that does not parse is left to decrypt_compact() to refuse.
    let header: Option<Map<String, Json>> = b64::decode_loose(parts[0])
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Json>(&bytes).ok())
        .and_then(|value| match value {
            Json::Object(map) => Some(map),
            _ => None,
        });
    let alg_name = header
        .as_ref()
        .map(|h| js_string(h.get("alg")))
        .unwrap_or_default();
    let pbes2 = alg(&alg_name).and_then(|a| match a.kind {
        AlgKind::Pbes2 { kw, sha } => Some((a, kw, sha)),
        _ => None,
    });
    let allowed = options
        .allowed_alg
        .is_none_or(|list| list.contains(&alg_name.as_str()));
    let secret = options.secret.filter(|s| !s.is_empty());
    let (Some(header), Some((found, kw, sha)), true, Some(secret), 5) =
        (header, pbes2, allowed, secret, parts.len())
    else {
        return decrypt_compact(compact, options);
    };
    let p2s = header.get("p2s");
    let p2s_truthy = match p2s {
        None | Some(Json::Null) | Some(Json::Bool(false)) => false,
        Some(Json::String(text)) => !text.is_empty(),
        Some(Json::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(_) => true,
    };
    if !p2s_truthy {
        return Err(err(format!(
            "a {} JWE carries its PBKDF2 salt in the header as `p2s` (RFC \
             7518 section 4.8.1.1) and this one has none.",
            found.name
        )));
    }
    let salt = b64::decode_loose(&js_string(p2s)).unwrap_or_default();
    let iterations = js_number(header.get("p2c")).floor();
    let floor = pbes2_min_iterations(options.pbes2_min_iterations);
    if !iterations.is_finite() || iterations < floor as f64 {
        return Err(err(format!(
            "a {} JWE carries its PBKDF2 iteration count in the header as \
             `p2c`, and this service accepts at least {}; this one says \
             \"{}\".",
            found.name,
            floor,
            js_string(header.get("p2c"))
        )));
    }
    if iterations > PBES2_MAX_ITERATIONS as f64 {
        return Err(err(format!(
            "this JWE asks for {} PBKDF2 iterations and this service \
             performs at most {}. RFC 7518 section 4.8.1.2 leaves the \
             ceiling to the recipient.",
            js_number_text(iterations),
            PBES2_MAX_ITERATIONS
        )));
    }
    let iterations = iterations as u64;
    let key = pbes2_key(&found.name, kw, sha, secret, &salt, iterations)?;
    let prepared = Pbes2Key {
        alg: found.name.clone(),
        salt,
        iterations,
        key,
    };
    let mut derived = options.clone();
    derived.pbes2 = Some(&prepared);
    decrypt_compact(compact, &derived)
}

// ---------------------------------------------------------------------------
// Keys for the KEM algs.
// ---------------------------------------------------------------------------

/// A fresh key pair for an ML-KEM or HPKE alg: `(public JWK, private JWK)`,
/// each with `use: enc` and the alg (`generateJweKemKeyPair()`).
pub fn generate_kem_key_pair(
    alg_name: &str,
    kid: Option<&str>,
) -> CryptoResult<(Json, Json)> {
    let alg = alg(alg_name).ok_or_else(|| {
        err(format!(
            "generateJweKemKeyPair: \"{}\" is not an ML-KEM or HPKE JWE \
             algorithm",
            alg_name
        ))
    })?;
    let (kem_id, key_type, crv) = match alg.kind {
        AlgKind::MlKem { set, .. } => (
            match set {
                "ML-KEM-512" => 0x0040,
                "ML-KEM-768" => 0x0041,
                _ => 0x0042,
            },
            "AKP",
            "",
        ),
        AlgKind::Hpke {
            suite,
            key_type,
            crv,
            ..
        } => (suite.kem, key_type, crv),
        _ => {
            return Err(err(format!(
                "generateJweKemKeyPair: \"{}\" is not an ML-KEM or HPKE JWE \
                 algorithm",
                alg_name
            )))
        }
    };
    let (sk, pk) = hpke::kem(kem_id)?.generate_key_pair()?;
    let mut public = Map::new();
    let private_member = match key_type {
        "AKP" => {
            public.insert("kty".into(), Json::from("AKP"));
            public.insert("pub".into(), Json::from(b64::encode(&pk)));
            ("priv", sk)
        }
        "EC" => {
            let size = hpke::Nist::by_name(crv)
                .map(|c| c.scalar_len())
                .unwrap_or(0);
            public.insert("kty".into(), Json::from("EC"));
            public.insert("crv".into(), Json::from(crv));
            public
                .insert("x".into(), Json::from(b64::encode(&pk[1..1 + size])));
            public.insert("y".into(), Json::from(b64::encode(&pk[1 + size..])));
            ("d", sk)
        }
        _ => {
            public.insert("kty".into(), Json::from("OKP"));
            public.insert("crv".into(), Json::from(crv));
            public.insert("x".into(), Json::from(b64::encode(&pk)));
            ("d", sk)
        }
    };
    public.insert("use".into(), Json::from("enc"));
    public.insert("alg".into(), Json::from(alg_name));
    if let Some(kid) = kid {
        public.insert("kid".into(), Json::from(kid));
    }
    let mut private = public.clone();
    private.insert(
        private_member.0.into(),
        Json::from(b64::encode(&private_member.1)),
    );
    Ok((Json::Object(public), Json::Object(private)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kem_alg_round_trips() {
        for alg in algs() {
            if !matches!(alg.kind, AlgKind::MlKem { .. } | AlgKind::Hpke { .. })
            {
                continue;
            }
            let (public, private) =
                generate_kem_key_pair(&alg.name, Some("k")).unwrap();
            let compact = encrypt_compact(
                b"hello",
                &EncryptOptions {
                    alg: Some(&alg.name),
                    enc: "A256GCM",
                    jwk: Some(&public),
                    ..EncryptOptions::default()
                },
            )
            .unwrap_or_else(|e| panic!("{}: {}", alg.name, e));
            let out = decrypt_compact(
                &compact,
                &DecryptOptions {
                    private_jwk: Some(&private),
                    ..DecryptOptions::default()
                },
            )
            .unwrap_or_else(|e| panic!("{}: {}", alg.name, e));
            assert_eq!(out.plaintext, b"hello", "{}", alg.name);
        }
    }

    #[test]
    fn classical_and_symmetric_algs_with_every_enc() {
        let rsa =
            PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
        let rsa_jwk = crate::keys::JwsKey::of(crate::keys::Material::Private(
            rsa.clone(),
        ))
        .public_jwk()
        .unwrap()
        .unwrap();
        let group =
            EcGroup::from_curve_name(openssl::nid::Nid::SECP384R1).unwrap();
        let ec = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let ec_jwk =
            crate::keys::JwsKey::of(crate::keys::Material::Private(ec.clone()))
                .public_jwk()
                .unwrap()
                .unwrap();
        for alg in algs() {
            if matches!(alg.kind, AlgKind::MlKem { .. } | AlgKind::Hpke { .. })
            {
                continue;
            }
            for content in ENCS {
                let secret: Vec<u8> = match alg.kind {
                    AlgKind::AesKw(n) | AlgKind::AesGcmKw(n) => vec![3u8; n],
                    AlgKind::Dir => vec![4u8; content.cek_bytes],
                    _ => b"a password".to_vec(),
                };
                let (jwk, key) = match alg.kind {
                    AlgKind::RsaOaep { .. } => (Some(&rsa_jwk), Some(&rsa)),
                    AlgKind::EcdhEs(_) => (Some(&ec_jwk), Some(&ec)),
                    _ => (None, None),
                };
                let compact = encrypt_compact_derived(
                    b"payload",
                    &EncryptOptions {
                        alg: Some(&alg.name),
                        enc: content.name,
                        jwk,
                        secret: Some(&secret),
                        policy: JwePolicy::DEVELOPMENT,
                        ..EncryptOptions::default()
                    },
                )
                .unwrap_or_else(|e| {
                    panic!("{} {}: {}", alg.name, content.name, e)
                });
                let out = decrypt_compact_derived(
                    &compact,
                    &DecryptOptions {
                        private_key: key,
                        secret: Some(&secret),
                        policy: JwePolicy::DEVELOPMENT,
                        ..DecryptOptions::default()
                    },
                )
                .unwrap_or_else(|e| {
                    panic!("{} {}: {}", alg.name, content.name, e)
                });
                assert_eq!(out.plaintext, b"payload");
            }
        }
    }

    #[test]
    fn rsa1_5_is_refused_by_name() {
        let header = b64::encode(br#"{"alg":"RSA1_5","enc":"A128GCM"}"#);
        let refused = decrypt_compact(
            &format!("{}.a.b.c.d", header),
            &DecryptOptions::default(),
        );
        assert!(refused.is_err_and(|e| e.0.contains("does not decrypt RSA1_5")));
    }

    #[test]
    fn product_refuses_cbc_and_oaep_over_sha1() {
        let secret = [5u8; 32];
        let refused = encrypt_compact(
            b"x",
            &EncryptOptions {
                alg: Some("dir"),
                enc: "A128CBC-HS256",
                secret: Some(&secret),
                ..EncryptOptions::default()
            },
        );
        assert_eq!(
            refused.unwrap_err().0,
            "enc \"A128CBC-HS256\" is AES-CBC, which needs \
             crypto.allowCbcJwe on."
        );
        let rsa =
            PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
        let jwk = crate::keys::JwsKey::of(crate::keys::Material::Private(
            rsa.clone(),
        ))
        .public_jwk()
        .unwrap()
        .unwrap();
        let refused = encrypt_compact(
            b"x",
            &EncryptOptions {
                alg: Some("RSA-OAEP"),
                enc: "A256GCM",
                jwk: Some(&jwk),
                ..EncryptOptions::default()
            },
        );
        assert_eq!(
            refused.unwrap_err().0,
            "alg \"RSA-OAEP\" is OAEP over SHA-1, which needs \
             crypto.allowLegacyHashes on."
        );
        let made = encrypt_compact(
            b"x",
            &EncryptOptions {
                alg: Some("RSA-OAEP"),
                enc: "A256GCM",
                jwk: Some(&jwk),
                policy: JwePolicy::DEVELOPMENT,
                ..EncryptOptions::default()
            },
        )
        .unwrap();
        let refused = decrypt_compact(
            &made,
            &DecryptOptions {
                private_key: Some(&rsa),
                ..DecryptOptions::default()
            },
        );
        assert_eq!(
            refused.unwrap_err().0,
            "the content encryption key could not be unwrapped: alg \
             \"RSA-OAEP\" is OAEP over SHA-1, which needs \
             crypto.allowLegacyHashes on."
        );
    }

    #[test]
    fn pbes2_needs_the_derived_door_and_is_held_to_its_header() {
        let made = encrypt_compact_derived(
            b"x",
            &EncryptOptions {
                alg: Some("PBES2-HS256+A128KW"),
                enc: "A256GCM",
                secret: Some(b"pw"),
                ..EncryptOptions::default()
            },
        )
        .unwrap();
        let header: Json = serde_json::from_slice(
            &b64::decode_loose(made.split('.').next().unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(header["p2c"], 600_000);
        let opened = decrypt_compact_derived(
            &made,
            &DecryptOptions {
                secret: Some(b"pw"),
                ..DecryptOptions::default()
            },
        )
        .unwrap();
        assert_eq!(opened.plaintext, b"x");
        // A key derived for one salt does not open a header naming another.
        let other = Pbes2Key {
            alg: "PBES2-HS256+A128KW".into(),
            salt: vec![1; 16],
            iterations: 600_000,
            key: vec![0; 16],
        };
        let refused = decrypt_compact(
            &made,
            &DecryptOptions {
                secret: Some(b"pw"),
                pbes2: Some(&other),
                ..DecryptOptions::default()
            },
        );
        assert_eq!(
            refused.unwrap_err().0,
            "the content encryption key could not be unwrapped: the PBES2 \
             key derived for this JWE does not match its header."
        );
    }

    #[test]
    fn javascript_numbers_and_strings() {
        assert_eq!(js_number(Some(&json!("1500"))), 1500.0);
        assert_eq!(js_number(Some(&json!(" 0x10 "))), 16.0);
        assert!(js_number(Some(&json!("12x"))).is_nan());
        assert!(js_number(Some(&json!("inf"))).is_nan());
        assert!(js_number(None).is_nan());
        assert_eq!(js_number(Some(&json!(null))), 0.0);
        assert_eq!(js_string(Some(&json!(1000.0))), "1000");
        assert_eq!(js_string(None), "undefined");
        assert_eq!(js_string(Some(&json!([1, null, "a"]))), "1,,a");
    }
}
