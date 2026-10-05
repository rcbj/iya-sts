// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Secrets this service keeps: `common/crypto.js`'s one-time passwords,
//! password and client-secret hashing, envelope encryption at rest and the
//! derived credentials.
//!
//! * [`hotp_code`] — RFC 4226 section 5.3, with RFC 6238's three digests.
//! * [`hash_secret`] / [`verify_secret`] — scrypt in the self-describing
//!   `$scrypt$N$r$p$salt$hash` form, the cost from the settings and clamped
//!   to the floor this module promises, verification against the
//!   parameters the stored value names.
//! * Envelope encryption (#391): a value sealed under a DATA encryption key
//!   — `$aesgcm$2$<dek id>$<iv>$<tag>$<ciphertext>`, or AES-256-SIV
//!   (RFC 5297) as `$aessiv$2$…` for a 64-byte key — and each DEK wrapped
//!   under the KEY-ENCRYPTION key as `$dekwrap$1$<iv>$<tag>$<ciphertext>`,
//!   bound to its id, scope, realm and class; or, where nothing persists,
//!   derived from it. [`Envelope`] counts every operation for
//!   `/admin/encryption`, process-wide, as Node's tally does.
//! * [`derive_shared_credential`] — the credential several processes reach
//!   independently.
//!
//! **ONE DIFFERENCE FROM NODE, AND IT IS A FIX.** Node's `constantTimeEquals()`
//! converts both sides to UTF-8 strings, so `verifySecret()` compares the
//! scrypt output with every byte that is not valid UTF-8 collapsed to U+FFFD
//! — two different outputs can compare equal. Here the bytes are compared.

use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use openssl::hash::MessageDigest;
use openssl::md::Md;
use openssl::pkey::PKey;
use openssl::pkey_ctx::{HkdfMode, PkeyCtx};
use openssl::rand::rand_bytes;
use openssl::sign::Signer;
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher, Crypter, Mode};
use sts_core::errors::codes;

use crate::error::{CryptoError, CryptoResult};

fn err(message: impl Into<String>) -> CryptoError {
    CryptoError::new(message)
}

fn random(n: usize) -> CryptoResult<Vec<u8>> {
    let mut out = vec![0u8; n];
    rand_bytes(&mut out)?;
    Ok(out)
}

fn hmac(
    md: MessageDigest,
    key: &[u8],
    data: &[&[u8]],
) -> CryptoResult<Vec<u8>> {
    let key = PKey::hmac(key)?;
    let mut signer = Signer::new(md, &key)?;
    for d in data {
        signer.update(d)?;
    }
    Ok(signer.sign_to_vec()?)
}

/// Equal bytes, in time that does not depend on where they differ.
pub fn constant_time_equals(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && openssl::memcmp::eq(a, b)
}

// ---------------------------------------------------------------------------
// HOTP.
// ---------------------------------------------------------------------------

/// The digests an authenticator app may be asked for: `(name, hash)`.
pub const HOTP_ALGS: [&str; 3] = ["SHA1", "SHA256", "SHA512"];

fn hotp_md(algorithm: Option<&str>) -> CryptoResult<(String, MessageDigest)> {
    let name = algorithm.unwrap_or("SHA1").to_uppercase();
    let md = match name.as_str() {
        "SHA1" => MessageDigest::sha1(),
        "SHA256" => MessageDigest::sha256(),
        "SHA512" => MessageDigest::sha512(),
        _ => {
            return Err(err(format!(
                "hotp: \"{}\" is not one of {}.",
                algorithm.unwrap_or(""),
                HOTP_ALGS.join(", ")
            )))
        }
    };
    Ok((name, md))
}

/// `hotpCode()`: RFC 4226 section 5.3 over the shared secret's BYTES.
/// `digits` is clamped to 6–10, as Node clamps it.
pub fn hotp_code(
    key: &[u8],
    counter: u64,
    digits: Option<u32>,
    algorithm: Option<&str>,
) -> CryptoResult<String> {
    let (_, md) = hotp_md(algorithm)?;
    let digits = digits.unwrap_or(6).clamp(6, 10);
    if key.is_empty() {
        return Err(err(
            "hotp: the shared secret is empty, so no code can be derived from \
             it.",
        ));
    }
    let digest = hmac(md, key, &[&counter.to_be_bytes()])?;
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = (u64::from(digest[offset] & 0x7f) << 24)
        | (u64::from(digest[offset + 1]) << 16)
        | (u64::from(digest[offset + 2]) << 8)
        | u64::from(digest[offset + 3]);
    let code = binary % 10u64.pow(digits);
    Ok(format!("{:0width$}", code, width = digits as usize))
}

// ---------------------------------------------------------------------------
// scrypt.
// ---------------------------------------------------------------------------

pub const SCRYPT_KEYLEN: usize = 32;
pub const SCRYPT_SALT_BYTES: usize = 16;
pub const SCRYPT_MIN_LOG_N: u32 = 14;
pub const SCRYPT_MAX_LOG_N: u32 = 20;

/// The cost of a NEW hash, from `security.passwordHashLogN`, `…R` and
/// `…P`, clamped to the floor this module promises whatever the settings
/// say (`scryptParameters()`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScryptCost {
    pub n: u64,
    pub r: u32,
    pub p: u32,
}

impl Default for ScryptCost {
    fn default() -> ScryptCost {
        ScryptCost {
            n: 32768,
            r: 8,
            p: 1,
        }
    }
}

impl ScryptCost {
    /// The settings' values, clamped: logN 14–20, r 8–16, p 1–8; a value
    /// that is absent keeps the default.
    pub fn from_settings(
        log_n: Option<i64>,
        r: Option<i64>,
        p: Option<i64>,
    ) -> ScryptCost {
        let clamp = |v: Option<i64>, lo: i64, hi: i64, d: i64| {
            v.map_or(d, |v| v.clamp(lo, hi))
        };
        let log_n =
            clamp(log_n, SCRYPT_MIN_LOG_N as i64, SCRYPT_MAX_LOG_N as i64, 15);
        ScryptCost {
            n: 1u64 << log_n,
            r: clamp(r, 8, 16, 8) as u32,
            p: clamp(p, 1, 8, 1) as u32,
        }
    }

    fn maxmem(self) -> u64 {
        2 * 128 * u64::from(self.r) * (self.n + u64::from(self.p))
    }
}

fn scrypt(
    plain: &[u8],
    salt: &[u8],
    n: u64,
    r: u64,
    p: u64,
    maxmem: u64,
    len: usize,
) -> CryptoResult<Vec<u8>> {
    let mut out = vec![0u8; len];
    openssl::pkcs5::scrypt(plain, salt, n, r, p, maxmem, &mut out)?;
    Ok(out)
}

/// `hashSecret()`: the secret, hashed at `cost`, in the stored form.
pub fn hash_secret(plaintext: &str, cost: ScryptCost) -> CryptoResult<String> {
    let salt = random(SCRYPT_SALT_BYTES)?;
    let derived = scrypt(
        plaintext.as_bytes(),
        &salt,
        cost.n,
        u64::from(cost.r),
        u64::from(cost.p),
        cost.maxmem(),
        SCRYPT_KEYLEN,
    )?;
    Ok(format!(
        "$scrypt${}${}${}${}${}",
        cost.n,
        cost.r,
        cost.p,
        STANDARD.encode(&salt),
        STANDARD.encode(&derived)
    ))
}

/// Whether a stored value is one of this service's scrypt forms.
pub fn is_hashed_secret(stored: &str) -> bool {
    stored.starts_with("$scrypt$")
}

/// JavaScript's `parseInt(s, 10)` as a finite number.
fn parse_int(s: &str) -> Option<u64> {
    let digits: String = s
        .trim_start()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// Node's lenient `Buffer.from(text, 'base64')`.
fn lenient_b64(text: &str) -> Vec<u8> {
    use base64::alphabet;
    use base64::engine::{
        DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig,
    };
    let cleaned: String = text
        .chars()
        .filter(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '-' | '_')
        })
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    let keep = cleaned.len() - if cleaned.len() % 4 == 1 { 1 } else { 0 };
    GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::Indifferent)
            .with_decode_allow_trailing_bits(true),
    )
    .decode(&cleaned[..keep])
    .unwrap_or_default()
}

/// `verifySecret()`: whether a presented secret matches a stored scrypt
/// form, in constant time. `false` — never an error — for no match, a value
/// this service did not write, or parameters it cannot compute.
pub fn verify_secret(plaintext: &str, stored: &str) -> bool {
    let parts: Vec<&str> = stored.split('$').collect();
    if parts.len() != 7 || parts[1] != "scrypt" {
        return false;
    }
    let (Some(n), Some(r), Some(p)) = (
        parse_int(parts[2]),
        parse_int(parts[3]),
        parse_int(parts[4]),
    ) else {
        return false;
    };
    let salt = lenient_b64(parts[5]);
    let expected = lenient_b64(parts[6]);
    if expected.is_empty() {
        return false;
    }
    match scrypt(
        plaintext.as_bytes(),
        &salt,
        n,
        r,
        p,
        128u64.saturating_mul(n).saturating_mul(r).saturating_mul(2),
        expected.len(),
    ) {
        Ok(derived) => constant_time_equals(&derived, &expected),
        Err(e) => {
            tracing::warn!(
                "{}crypto: a stored secret names scrypt parameters this \
                 process cannot compute and is being treated as no match: {}",
                sts_core::log::tag(codes::STS_KEYS_0005),
                e
            );
            false
        }
    }
}

// ---------------------------------------------------------------------------
// The key-encryption key and the accounting.
// ---------------------------------------------------------------------------

pub const KEK_KEY_BYTES: usize = 32;
pub const KEK_IV_BYTES: usize = 12;
pub const SIV_KEY_BYTES: usize = 64;
pub const SIV_NONCE_BYTES: usize = 16;
const BLOCK: usize = 16;
pub const DEK_ENVELOPE_VERSION: &str = "2";
const DEK_WRAP_INFO: &str = "sts dek wrapping v1";
const DEK_DERIVE_INFO: &str = "sts derived dek v1|";
const DEK_ID_INFO: &str = "sts derived dek id v1";

/// A key-encryption key as a provider handed it back.
pub enum KekInput<'a> {
    Bytes(&'a [u8]),
    Text(&'a str),
}

fn kek_refused(message: String) -> CryptoError {
    err(format!(
        "{}{}",
        sts_core::log::tag(codes::STS_KEYS_0002),
        message
    ))
}

/// `kekBytes()`: raw bytes, else hex, else base64, else the text's UTF-8 —
/// at least 32 bytes, refused rather than stretched.
pub fn kek_bytes(value: KekInput) -> CryptoResult<Vec<u8>> {
    match value {
        KekInput::Bytes(b) => {
            if b.len() < KEK_KEY_BYTES {
                return Err(kek_refused(format!(
                    "the key-encryption key is {} bytes and at least {} are required",
                    b.len(),
                    KEK_KEY_BYTES
                )));
            }
            Ok(b.to_vec())
        }
        KekInput::Text(t) => {
            let text = t.trim();
            if text.is_empty() {
                return Err(kek_refused(
                    "the key-encryption key is empty".to_string(),
                ));
            }
            if text.len() >= KEK_KEY_BYTES * 2
                && text.chars().all(|c| c.is_ascii_hexdigit())
            {
                // Node's Buffer.from(hex) stops at an odd trailing digit.
                let even = &text[..text.len() - text.len() % 2];
                return Ok((0..even.len())
                    .step_by(2)
                    .map(|i| {
                        u8::from_str_radix(&even[i..i + 2], 16).unwrap_or(0)
                    })
                    .collect());
            }
            let body = text.trim_end_matches('=');
            let padding = text.len() - body.len();
            if padding <= 2
                && !body.is_empty()
                && body.chars().all(|c| {
                    c.is_ascii_alphanumeric()
                        || matches!(c, '+' | '/' | '_' | '-')
                })
            {
                let decoded = lenient_b64(text);
                if decoded.len() >= KEK_KEY_BYTES {
                    return Ok(decoded);
                }
            }
            let raw = text.as_bytes();
            if raw.len() < KEK_KEY_BYTES {
                return Err(kek_refused(format!(
                    "the key-encryption key decodes to {} bytes and at least {} \
                     are required. Generate one with `openssl rand -base64 32`.",
                    raw.len(),
                    KEK_KEY_BYTES
                )));
            }
            Ok(raw.to_vec())
        }
    }
}

/// One label's figures, and the totals.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KekCounts {
    pub label: String,
    pub encryptions: u64,
    pub decryptions: u64,
    pub failures: u64,
    pub plaintext_bytes: u64,
    pub ciphertext_bytes: u64,
    pub first_at: u64,
    pub last_at: u64,
}

/// `kekAccounting()`: what this process has sealed and opened.
#[derive(Clone, Debug, Default)]
pub struct KekAccounting {
    pub totals: KekCounts,
    pub started_at: u64,
    pub labels: Vec<KekCounts>,
}

#[derive(Clone, Copy)]
enum Op {
    Encryption,
    Decryption,
    Failure,
}

struct Tally {
    totals: KekCounts,
    started_at: u64,
    by_label: BTreeMap<String, KekCounts>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Process-wide, as the key-encryption key is the process's.
static TALLY: LazyLock<Mutex<Tally>> = LazyLock::new(|| {
    Mutex::new(Tally {
        totals: KekCounts::default(),
        started_at: now_ms(),
        by_label: BTreeMap::new(),
    })
});

const UNLABELLED: &str = "(unlabelled)";

fn count(label: Option<&str>, op: Op, plain: usize, cipher: usize) {
    let now = now_ms();
    let Ok(mut tally) = TALLY.lock() else {
        return;
    };
    let id = label
        .filter(|l| !l.is_empty())
        .unwrap_or(UNLABELLED)
        .to_string();
    bump(&mut tally.totals, op, plain, cipher, now);
    let row = tally
        .by_label
        .entry(id.clone())
        .or_insert_with(|| KekCounts {
            label: id,
            ..KekCounts::default()
        });
    bump(row, op, plain, cipher, now);
}

fn bump(c: &mut KekCounts, op: Op, plain: usize, cipher: usize, now: u64) {
    match op {
        Op::Encryption => c.encryptions += 1,
        Op::Decryption => c.decryptions += 1,
        Op::Failure => c.failures += 1,
    }
    c.plaintext_bytes += plain as u64;
    c.ciphertext_bytes += cipher as u64;
    if c.first_at == 0 {
        c.first_at = now;
    }
    c.last_at = now;
}

/// A copy of the tally, the labels busiest first.
pub fn kek_accounting() -> KekAccounting {
    let Ok(tally) = TALLY.lock() else {
        return KekAccounting::default();
    };
    let mut labels: Vec<KekCounts> = tally.by_label.values().cloned().collect();
    labels.sort_by(|a, b| {
        (b.encryptions + b.decryptions)
            .cmp(&(a.encryptions + a.decryptions))
            .then_with(|| a.label.cmp(&b.label))
    });
    KekAccounting {
        totals: tally.totals.clone(),
        started_at: tally.started_at,
        labels,
    }
}

// ---------------------------------------------------------------------------
// AES-SIV (RFC 5297) with a 512-bit key.
// ---------------------------------------------------------------------------

fn aes_ecb(key: &[u8], block: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut c = Crypter::new(Cipher::aes_256_ecb(), Mode::Encrypt, key, None)?;
    c.pad(false);
    let mut out = vec![0u8; block.len() + BLOCK];
    let n = c.update(block, &mut out)?;
    let m = c.finalize(&mut out[n..])?;
    out.truncate(n + m);
    Ok(out)
}

fn dbl(block: &[u8]) -> [u8; BLOCK] {
    let mut out = [0u8; BLOCK];
    let mut carry = 0u8;
    for i in (0..BLOCK).rev() {
        out[i] = (block[i] << 1) | carry;
        carry = block[i] >> 7;
    }
    if block[0] & 0x80 != 0 {
        out[BLOCK - 1] ^= 0x87;
    }
    out
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}

fn pad(bytes: &[u8]) -> [u8; BLOCK] {
    let mut out = [0u8; BLOCK];
    out[..bytes.len()].copy_from_slice(bytes);
    out[bytes.len()] = 0x80;
    out
}

/// AES-256-CMAC (RFC 4493).
fn cmac(key: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
    let k1 = dbl(&aes_ecb(key, &[0u8; BLOCK])?);
    let k2 = dbl(&k1);
    let n = message.len().div_ceil(BLOCK).max(1);
    let whole = !message.is_empty() && message.len() % BLOCK == 0;
    let last_start = (n - 1) * BLOCK;
    let last = if whole {
        xor(&message[last_start..last_start + BLOCK], &k1)
    } else {
        xor(&pad(&message[last_start..]), &k2)
    };
    let mut c = Crypter::new(
        Cipher::aes_256_cbc(),
        Mode::Encrypt,
        key,
        Some(&[0u8; BLOCK]),
    )?;
    c.pad(false);
    let mut input = message[..last_start].to_vec();
    input.extend(last);
    let mut out = vec![0u8; input.len() + BLOCK];
    let w = c.update(&input, &mut out)?;
    let f = c.finalize(&mut out[w..])?;
    out.truncate(w + f);
    Ok(out[out.len() - BLOCK..].to_vec())
}

fn s2v(
    key: &[u8],
    components: &[&[u8]],
    plaintext: &[u8],
) -> CryptoResult<Vec<u8>> {
    let mut d = cmac(key, &[0u8; BLOCK])?;
    for c in components {
        d = xor(&dbl(&d), &cmac(key, c)?);
    }
    let t = if plaintext.len() >= BLOCK {
        let mut t = plaintext.to_vec();
        let at = t.len() - BLOCK;
        let tail = xor(&t[at..], &d);
        t[at..].copy_from_slice(&tail);
        t
    } else {
        xor(&dbl(&d), &pad(plaintext))
    };
    cmac(key, &t)
}

fn siv_ctr(key: &[u8], siv: &[u8], bytes: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut q = siv.to_vec();
    q[8] &= 0x7f;
    q[12] &= 0x7f;
    Ok(openssl::symm::encrypt(
        Cipher::aes_256_ctr(),
        key,
        Some(&q),
        bytes,
    )?)
}

/// AES-SIV encryption under a 64-byte key: the synthetic IV, then the
/// ciphertext.
pub fn aes_siv_encrypt(
    key: &[u8],
    plaintext: &[u8],
    components: &[&[u8]],
) -> CryptoResult<Vec<u8>> {
    if key.len() != SIV_KEY_BYTES {
        return Err(err(format!(
            "an AES-256-SIV key is {} bytes",
            SIV_KEY_BYTES
        )));
    }
    let siv = s2v(&key[..32], components, plaintext)?;
    let mut out = siv.clone();
    out.extend(siv_ctr(&key[32..], &siv, plaintext)?);
    Ok(out)
}

/// AES-SIV decryption; an error when the synthetic IV does not verify.
pub fn aes_siv_decrypt(
    key: &[u8],
    sealed: &[u8],
    components: &[&[u8]],
) -> CryptoResult<Vec<u8>> {
    if key.len() != SIV_KEY_BYTES {
        return Err(err(format!(
            "an AES-256-SIV key is {} bytes",
            SIV_KEY_BYTES
        )));
    }
    if sealed.len() < BLOCK {
        return Err(err("an AES-SIV ciphertext is at least 16 bytes"));
    }
    let (siv, body) = sealed.split_at(BLOCK);
    let plain = siv_ctr(&key[32..], siv, body)?;
    let check = s2v(&key[..32], components, &plain)?;
    if !constant_time_equals(&check, siv) {
        return Err(err("the AES-SIV synthetic IV does not verify"));
    }
    Ok(plain)
}

// ---------------------------------------------------------------------------
// The envelope.
// ---------------------------------------------------------------------------

fn dek_id_ok(id: &str) -> bool {
    (8..=200).contains(&id.len())
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

fn envelope_aad(dek_id: &str) -> Vec<u8> {
    format!("sts envelope v{}|{}", DEK_ENVELOPE_VERSION, dek_id).into_bytes()
}

/// Whether a stored value is a sealed value this service wrote.
pub fn is_encrypted_with_kek(stored: &str) -> bool {
    stored.starts_with("$aesgcm$") || stored.starts_with("$aessiv$")
}

/// The DEK a version-2 envelope names, or `None`.
pub fn dek_id_of(stored: &str) -> Option<&str> {
    let parts: Vec<&str> = stored.split('$').collect();
    (parts.len() == 7
        && (parts[1] == "aesgcm" || parts[1] == "aessiv")
        && parts[2] == DEK_ENVELOPE_VERSION
        && dek_id_ok(parts[3]))
    .then_some(parts[3])
}

/// The cipher a DEK is for, from its length.
pub fn dek_alg_of(key: &[u8]) -> &'static str {
    if key.len() == SIV_KEY_BYTES {
        "aes-256-siv"
    } else {
        "aes-256-gcm"
    }
}

/// A random DEK: 32 bytes, or 64 for `aes-256-siv`.
pub fn generate_dek(alg: &str) -> CryptoResult<Vec<u8>> {
    random(if alg == "aes-256-siv" {
        SIV_KEY_BYTES
    } else {
        KEK_KEY_BYTES
    })
}

/// A random DEK id: 16 bytes, base64url.
pub fn generate_dek_id() -> CryptoResult<String> {
    Ok(URL_SAFE_NO_PAD.encode(random(16)?))
}

fn dek_len_ok(key: &[u8]) -> CryptoResult<()> {
    if key.len() != KEK_KEY_BYTES && key.len() != SIV_KEY_BYTES {
        return Err(err(format!(
            "a data encryption key must be {} or {} bytes",
            KEK_KEY_BYTES, SIV_KEY_BYTES
        )));
    }
    Ok(())
}

/// `encryptWithDek()`: a value sealed under a DEK, counted under `label`.
pub fn encrypt_with_dek(
    dek_id: &str,
    key: &[u8],
    plaintext: &str,
    label: Option<&str>,
) -> CryptoResult<String> {
    if !dek_id_ok(dek_id) {
        return Err(err("a data encryption key id must be base64url"));
    }
    dek_len_ok(key)?;
    let plain = plaintext.as_bytes();
    if key.len() == SIV_KEY_BYTES {
        let nonce = random(SIV_NONCE_BYTES)?;
        let sealed =
            aes_siv_encrypt(key, plain, &[&envelope_aad(dek_id), &nonce])?;
        count(label, Op::Encryption, plain.len(), sealed.len());
        return Ok(format!(
            "$aessiv${}${}${}${}${}",
            DEK_ENVELOPE_VERSION,
            dek_id,
            STANDARD.encode(&nonce),
            STANDARD.encode(&sealed[..BLOCK]),
            STANDARD.encode(&sealed[BLOCK..])
        ));
    }
    let iv = random(KEK_IV_BYTES)?;
    let mut tag = [0u8; 16];
    let body = encrypt_aead(
        Cipher::aes_256_gcm(),
        key,
        Some(&iv),
        &envelope_aad(dek_id),
        plain,
        &mut tag,
    )?;
    count(label, Op::Encryption, plain.len(), body.len());
    Ok(format!(
        "$aesgcm${}${}${}${}${}",
        DEK_ENVELOPE_VERSION,
        dek_id,
        STANDARD.encode(&iv),
        STANDARD.encode(tag),
        STANDARD.encode(&body)
    ))
}

/// `decryptWithDek()`: a value `encrypt_with_dek` wrote, under the DEK it
/// names. Every refusal is counted as a failure.
pub fn decrypt_with_dek(
    key: &[u8],
    stored: &str,
    label: Option<&str>,
) -> CryptoResult<String> {
    let parts: Vec<&str> = stored.split('$').collect();
    let fail = |message: String| {
        count(label, Op::Failure, 0, 0);
        err(message)
    };
    if parts.len() != 7 || (parts[1] != "aesgcm" && parts[1] != "aessiv") {
        return Err(fail(
            "this is not a record encrypted by this service".to_string(),
        ));
    }
    if parts[2] != DEK_ENVELOPE_VERSION {
        return Err(fail(format!(
            "the record names encryption version \"{}\", which this build \
             does not read (version 1 records were written before data \
             encryption keys, #391)",
            parts[2]
        )));
    }
    if parts[1] == "aessiv" {
        if key.len() != SIV_KEY_BYTES {
            return Err(fail(
                "an AES-256-SIV value needs a 64-byte key".to_string(),
            ));
        }
        let mut sealed = lenient_b64(parts[5]);
        sealed.extend(lenient_b64(parts[6]));
        let plain = aes_siv_decrypt(
            key,
            &sealed,
            &[&envelope_aad(parts[3]), &lenient_b64(parts[4])],
        )
        .map_err(|e| fail(e.to_string()))?;
        count(label, Op::Decryption, plain.len(), plain.len() + BLOCK);
        return String::from_utf8(plain)
            .map_err(|_| err("the value is not UTF-8"));
    }
    if key.len() != KEK_KEY_BYTES {
        return Err(fail(
            "an AES-256-GCM value needs a 32-byte key".to_string(),
        ));
    }
    let body = lenient_b64(parts[6]);
    let plain = decrypt_aead(
        Cipher::aes_256_gcm(),
        key,
        Some(&lenient_b64(parts[4])),
        &envelope_aad(parts[3]),
        &body,
        &lenient_b64(parts[5]),
    )
    .map_err(|_| {
        fail("Unsupported state or unable to authenticate data".to_string())
    })?;
    count(label, Op::Decryption, plain.len(), body.len());
    String::from_utf8(plain).map_err(|_| err("the value is not UTF-8"))
}

/// HKDF-SHA256 with no salt (RFC 5869), as node's `hkdfSync`.
fn hkdf_sha256(ikm: &[u8], info: &[u8], len: usize) -> CryptoResult<Vec<u8>> {
    let mut ctx = PkeyCtx::new_id(openssl::pkey::Id::HKDF)?;
    ctx.derive_init()?;
    ctx.set_hkdf_md(Md::sha256())?;
    ctx.set_hkdf_mode(HkdfMode::EXTRACT_THEN_EXPAND)?;
    ctx.set_hkdf_key(ikm)?;
    ctx.set_hkdf_salt(&[])?;
    ctx.add_hkdf_info(info)?;
    let mut out = vec![0u8; len];
    ctx.derive(Some(&mut out))?;
    Ok(out)
}

fn wrapping_key(kek: KekInput) -> CryptoResult<Vec<u8>> {
    hkdf_sha256(&kek_bytes(kek)?, DEK_WRAP_INFO.as_bytes(), KEK_KEY_BYTES)
}

/// `wrapDek()`: a DEK wrapped under the KEK, bound to `aad`.
pub fn wrap_dek(kek: KekInput, key: &[u8], aad: &str) -> CryptoResult<String> {
    dek_len_ok(key)?;
    let iv = random(KEK_IV_BYTES)?;
    let mut tag = [0u8; 16];
    let body = encrypt_aead(
        Cipher::aes_256_gcm(),
        &wrapping_key(kek)?,
        Some(&iv),
        aad.as_bytes(),
        key,
        &mut tag,
    )?;
    count(Some("data-keys"), Op::Encryption, key.len(), body.len());
    Ok(format!(
        "$dekwrap$1${}${}${}",
        STANDARD.encode(&iv),
        STANDARD.encode(tag),
        STANDARD.encode(&body)
    ))
}

/// `unwrapDek()`: a DEK `wrap_dek` wrote, with the AAD it was bound to.
pub fn unwrap_dek(
    kek: KekInput,
    wrapped: &str,
    aad: &str,
) -> CryptoResult<Vec<u8>> {
    let parts: Vec<&str> = wrapped.split('$').collect();
    let fail = |message: &str| {
        count(Some("data-keys"), Op::Failure, 0, 0);
        err(message)
    };
    if parts.len() != 6 || parts[1] != "dekwrap" || parts[2] != "1" {
        return Err(fail(
            "this is not a data encryption key wrapped by this service",
        ));
    }
    let key = wrapping_key(kek).map_err(|e| fail(&e.to_string()))?;
    let out = decrypt_aead(
        Cipher::aes_256_gcm(),
        &key,
        Some(&lenient_b64(parts[3])),
        aad.as_bytes(),
        &lenient_b64(parts[5]),
        &lenient_b64(parts[4]),
    )
    .map_err(|_| fail("Unsupported state or unable to authenticate data"))?;
    count(Some("data-keys"), Op::Decryption, out.len(), out.len());
    dek_len_ok(&out)?;
    Ok(out)
}

/// `deriveDek()`: a DEK and its id derived from the KEK, for a process that
/// stores none.
pub fn derive_dek(
    kek: KekInput,
    context: &str,
) -> CryptoResult<(String, Vec<u8>)> {
    let kek = kek_bytes(kek)?;
    let info = format!("{}{}", DEK_DERIVE_INFO, context);
    let key = hkdf_sha256(&kek, info.as_bytes(), KEK_KEY_BYTES)?;
    let id_key = hkdf_sha256(&kek, DEK_ID_INFO.as_bytes(), KEK_KEY_BYTES)?;
    let mac = hmac(MessageDigest::sha256(), &id_key, &[info.as_bytes()])?;
    let id = format!("x{}", &URL_SAFE_NO_PAD.encode(mac)[..22]);
    Ok((id, key))
}

/// `deriveSharedCredential()`: HMAC-SHA256 of the label and the parts, each
/// after a NUL, under the shared secret; base64url.
pub fn derive_shared_credential(
    secret: &str,
    label: &str,
    parts: &[&str],
) -> CryptoResult<String> {
    let mut data: Vec<&[u8]> = vec![label.as_bytes()];
    for p in parts {
        data.push(b"\0");
        data.push(p.as_bytes());
    }
    Ok(URL_SAFE_NO_PAD.encode(hmac(
        MessageDigest::sha256(),
        secret.as_bytes(),
        &data,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4226_appendix_d() {
        let key = b"12345678901234567890";
        let want = [
            "755224", "287082", "359152", "969429", "338314", "254676",
            "287922", "162583", "399871", "520489",
        ];
        for (i, w) in want.iter().enumerate() {
            assert_eq!(hotp_code(key, i as u64, None, None).unwrap(), *w);
        }
        assert!(hotp_code(b"", 0, None, None).is_err());
        assert!(hotp_code(key, 0, None, Some("MD5")).is_err());
    }

    #[test]
    fn scrypt_round_trip_and_floor() {
        let cost = ScryptCost::from_settings(Some(10), Some(8), Some(1));
        assert_eq!(cost.n, 1 << 14, "the floor holds whatever is set");
        let stored = hash_secret("s3cret", cost).unwrap();
        assert!(stored.starts_with("$scrypt$16384$8$1$"));
        assert!(verify_secret("s3cret", &stored));
        assert!(!verify_secret("s3cret!", &stored));
        assert!(!verify_secret("s3cret", "plain"));
    }

    #[test]
    fn envelopes_round_trip_and_bind_their_id() {
        for alg in ["aes-256-gcm", "aes-256-siv"] {
            let key = generate_dek(alg).unwrap();
            let id = generate_dek_id().unwrap();
            let sealed =
                encrypt_with_dek(&id, &key, "hello \u{e9}", Some("test"))
                    .unwrap();
            assert_eq!(dek_id_of(&sealed), Some(id.as_str()));
            assert_eq!(
                decrypt_with_dek(&key, &sealed, None).unwrap(),
                "hello \u{e9}"
            );
            let moved = sealed.replace(&id, "another-id-1234");
            assert!(decrypt_with_dek(&key, &moved, None).is_err(), "{}", alg);
        }
        let kek =
            KekInput::Text("an operator's passphrase that is long enough");
        let dek = generate_dek("aes-256-gcm").unwrap();
        let w = wrap_dek(kek, &dek, "id|realm|class").unwrap();
        let kek =
            KekInput::Text("an operator's passphrase that is long enough");
        assert_eq!(unwrap_dek(kek, &w, "id|realm|class").unwrap(), dek);
        let kek =
            KekInput::Text("an operator's passphrase that is long enough");
        assert!(unwrap_dek(kek, &w, "id|other|class").is_err());
        assert!(kek_bytes(KekInput::Text("short")).is_err());
    }
}
