// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! HPKE and the KEMs under it — a port of `common/crypto.js` section 4a's
//! primitives (#82). **Every one of these is a draft, and which text was
//! read is the record**; the Node section's header names each revision, and
//! this module implements the same ones:
//!
//! * the HPKE core of draft-ietf-hpke-hpke (RFC 9180's successor, which adds
//!   the one-stage KDFs the SHAKE suites need), modes base and psk;
//! * DHKEM over P-256, P-384, P-521, X25519 and X448;
//! * ML-KEM-512/768/1024 (FIPS 203), whose private key is the 64-octet seed
//!   `d || z`, with section 7.2's modulus check on every encapsulation key
//!   made HERE whatever the library does;
//! * the PQ/T hybrids of draft-ietf-hpke-pq-05 over
//!   draft-irtf-cfrg-concrete-hybrid-kems — MLKEM768-P256, MLKEM1024-P384
//!   and MLKEM768-X25519 (X-Wing);
//! * KDFs HKDF-SHA256/384/512, SHAKE128/256 and TurboSHAKE128/256; AEADs
//!   AES-128-GCM, AES-256-GCM, ChaCha20Poly1305 and export-only.
//!
//! OpenSSL does the curves, ML-KEM, SHA-3, SHAKE, HMAC and the AEADs; the
//! `sha3` crate does TurboSHAKE and cSHAKE (for KMAC256), which OpenSSL does
//! not offer. **ML-KEM encapsulation takes no caller randomness** — OpenSSL
//! does not accept it, as node's does not — so the published vectors are
//! checked from the receiving side, as `tests/jwe_pq_kem.js` checks them.

use openssl::bn::{BigNum, BigNumContext};
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, KeyType, PKey, Private};
use openssl::sign::Signer;
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};
use sha3::digest::{ExtendableOutput, Update, XofReader};

use crate::error::{CryptoError, CryptoResult};
use crate::pq;

fn err(message: impl Into<String>) -> CryptoError {
    CryptoError::new(message)
}

/// RFC 8017's I2OSP, big-endian.
pub fn i2osp(n: u64, width: usize) -> CryptoResult<Vec<u8>> {
    if width < 8 && n >> (8 * width) != 0 {
        return Err(err(format!(
            "i2osp: {} does not fit in {} octets",
            n, width
        )));
    }
    let bytes = n.to_be_bytes();
    let mut out = vec![0u8; width.saturating_sub(8)];
    out.extend_from_slice(&bytes[8usize.saturating_sub(width)..]);
    Ok(out)
}

/// draft-ietf-hpke-hpke section 3: two octets of length, then the bytes.
fn length_prefixed(bytes: &[u8]) -> CryptoResult<Vec<u8>> {
    if bytes.len() > 65535 {
        return Err(err(format!(
            "lengthPrefixed: {} octets is more than two octets can count",
            bytes.len()
        )));
    }
    let mut out = i2osp(bytes.len() as u64, 2)?;
    out.extend_from_slice(bytes);
    Ok(out)
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// SHAKE128 or SHAKE256 of `length` octets.
pub fn shake(bits: u16, input: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
    let md = if bits == 128 {
        MessageDigest::shake_128()
    } else {
        MessageDigest::shake_256()
    };
    let mut out = vec![0u8; length];
    openssl::hash::hash_xof(md, input, &mut out)?;
    Ok(out)
}

fn sha3_256(input: &[u8]) -> CryptoResult<Vec<u8>> {
    Ok(openssl::hash::hash(MessageDigest::sha3_256(), input)?.to_vec())
}

fn turboshake(bits: u16, input: &[u8], length: usize) -> Vec<u8> {
    let mut out = vec![0u8; length];
    if bits == 128 {
        let mut h =
            sha3::TurboShake128::from_core(sha3::TurboShake128Core::new(0x1f));
        h.update(input);
        h.finalize_xof().read(&mut out);
    } else {
        let mut h =
            sha3::TurboShake256::from_core(sha3::TurboShake256Core::new(0x1f));
        h.update(input);
        h.finalize_xof().read(&mut out);
    }
    out
}

fn left_encode(n: u64) -> Vec<u8> {
    let bytes = n.to_be_bytes();
    let skip = bytes.iter().take_while(|&&b| b == 0).count().min(7);
    let mut out = vec![(8 - skip) as u8];
    out.extend_from_slice(&bytes[skip..]);
    out
}

fn right_encode(n: u64) -> Vec<u8> {
    let bytes = n.to_be_bytes();
    let skip = bytes.iter().take_while(|&&b| b == 0).count().min(7);
    let mut out = bytes[skip..].to_vec();
    out.push((8 - skip) as u8);
    out
}

/// KMAC256 (NIST SP 800-185) with an empty customization string, over
/// cSHAKE256 — what draft-ietf-jose-pqc-kem-05's KDF is.
pub fn kmac256(key: &[u8], data: &[u8], length: usize) -> Vec<u8> {
    const RATE: usize = 136;
    let mut encoded_key = left_encode(key.len() as u64 * 8);
    encoded_key.extend_from_slice(key);
    let mut padded = left_encode(RATE as u64);
    padded.extend(encoded_key);
    while padded.len() % RATE != 0 {
        padded.push(0);
    }
    let mut h = sha3::CShake256::from_core(
        sha3::CShake256Core::new_with_function_name(b"KMAC", b""),
    );
    h.update(&padded);
    h.update(data);
    h.update(&right_encode(length as u64 * 8));
    let mut out = vec![0u8; length];
    h.finalize_xof().read(&mut out);
    out
}

// ---------------------------------------------------------------------------
// ML-KEM.
// ---------------------------------------------------------------------------

/// An ML-KEM parameter set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MlKemSet {
    pub name: &'static str,
    pub k: usize,
    pub public_len: usize,
    pub ciphertext_len: usize,
}

pub const ML_KEM_512: MlKemSet = MlKemSet {
    name: "ML-KEM-512",
    k: 2,
    public_len: 800,
    ciphertext_len: 768,
};
pub const ML_KEM_768: MlKemSet = MlKemSet {
    name: "ML-KEM-768",
    k: 3,
    public_len: 1184,
    ciphertext_len: 1088,
};
pub const ML_KEM_1024: MlKemSet = MlKemSet {
    name: "ML-KEM-1024",
    k: 4,
    public_len: 1568,
    ciphertext_len: 1568,
};

pub fn ml_kem_set(name: &str) -> Option<MlKemSet> {
    [ML_KEM_512, ML_KEM_768, ML_KEM_1024]
        .into_iter()
        .find(|set| set.name == name)
}

impl MlKemSet {
    fn key_type(&self) -> KeyType {
        match self.k {
            2 => KeyType::ML_KEM_512,
            3 => KeyType::ML_KEM_768,
            _ => KeyType::ML_KEM_1024,
        }
    }

    /// FIPS 203 section 7.2's checks on an encapsulation key: its length,
    /// and every coefficient below q = 3329.
    pub fn check_encapsulation_key(&self, ek: &[u8]) -> CryptoResult<()> {
        if ek.len() != self.public_len {
            return Err(err(format!(
                "an {} encapsulation key is {} octets; this one is {}",
                self.name,
                self.public_len,
                ek.len()
            )));
        }
        for i in (0..384 * self.k).step_by(3) {
            let a = u16::from(ek[i]) | (u16::from(ek[i + 1] & 0x0f) << 8);
            let b = u16::from(ek[i + 1] >> 4) | (u16::from(ek[i + 2]) << 4);
            if a >= 3329 || b >= 3329 {
                return Err(err(format!(
                    "the {} encapsulation key fails FIPS 203 section 7.2's \
                     modulus check: a coefficient is not below q = 3329",
                    self.name
                )));
            }
        }
        Ok(())
    }

    /// The key pair of a 64-octet seed `d || z`: `(ek, private key)`.
    pub fn from_seed(
        &self,
        seed: &[u8],
    ) -> CryptoResult<(Vec<u8>, PKey<Private>)> {
        if seed.len() != 64 {
            return Err(err(format!(
                "an ML-KEM private key is the 64-octet seed d || z (FIPS 203 \
                 KeyGen_internal); this one is {} octets",
                seed.len()
            )));
        }
        let key =
            PKey::private_key_from_seed(None, self.key_type(), None, seed)?;
        Ok((key.raw_public_key()?, key))
    }

    /// `(shared secret, ciphertext)` to an encapsulation key.
    pub fn encaps(&self, ek: &[u8]) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        self.check_encapsulation_key(ek)?;
        let public = pq::public_from_raw(self.name, ek)?;
        let (ct, ss) = pq::encapsulate(&public)?;
        Ok((ss, ct))
    }

    pub fn decaps(&self, seed: &[u8], ct: &[u8]) -> CryptoResult<Vec<u8>> {
        if ct.len() != self.ciphertext_len {
            return Err(err(format!(
                "an {} ciphertext is {} octets; this one is {}",
                self.name,
                self.ciphertext_len,
                ct.len()
            )));
        }
        let (_, key) = self.from_seed(seed)?;
        pq::decapsulate(&key, ct)
    }
}

// ---------------------------------------------------------------------------
// The classical groups.
// ---------------------------------------------------------------------------

/// A NIST curve as a DHKEM uses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nist {
    P256,
    P384,
    P521,
}

impl Nist {
    pub fn by_name(name: &str) -> Option<Nist> {
        match name {
            "P-256" => Some(Nist::P256),
            "P-384" => Some(Nist::P384),
            "P-521" => Some(Nist::P521),
            _ => None,
        }
    }

    fn nid(self) -> Nid {
        match self {
            Nist::P256 => Nid::X9_62_PRIME256V1,
            Nist::P384 => Nid::SECP384R1,
            Nist::P521 => Nid::SECP521R1,
        }
    }

    /// The scalar's and the shared value's octets.
    pub fn scalar_len(self) -> usize {
        match self {
            Nist::P256 => 32,
            Nist::P384 => 48,
            Nist::P521 => 66,
        }
    }

    /// An uncompressed point's octets.
    pub fn point_len(self) -> usize {
        1 + 2 * self.scalar_len()
    }

    fn order(self) -> CryptoResult<BigNum> {
        let group = EcGroup::from_curve_name(self.nid())?;
        let mut order = BigNum::new()?;
        let mut context = BigNumContext::new()?;
        group.order(&mut order, &mut context)?;
        Ok(order)
    }

    fn private_key(self, scalar: &[u8]) -> CryptoResult<PKey<Private>> {
        let group = EcGroup::from_curve_name(self.nid())?;
        let d = BigNum::from_slice(scalar)?;
        let mut point = EcPoint::new(&group)?;
        let mut context = BigNumContext::new()?;
        point.mul_generator2(&group, &d, &mut context)?;
        Ok(PKey::from_ec_key(EcKey::from_private_components(
            &group, &d, &point,
        )?)?)
    }

    /// The uncompressed public point of a scalar.
    pub fn public(self, scalar: &[u8]) -> CryptoResult<Vec<u8>> {
        let key = self.private_key(scalar)?;
        let ec = key.ec_key()?;
        let mut context = BigNumContext::new()?;
        Ok(ec.public_key().to_bytes(
            ec.group(),
            PointConversionForm::UNCOMPRESSED,
            &mut context,
        )?)
    }

    /// The x-coordinate of `scalar · point`.
    pub fn dh(self, scalar: &[u8], point: &[u8]) -> CryptoResult<Vec<u8>> {
        if point.len() != self.point_len() || point.first() != Some(&0x04) {
            return Err(err(format!(
                "a {:?} public key here is an uncompressed point of {} octets",
                self,
                self.point_len()
            )));
        }
        let group = EcGroup::from_curve_name(self.nid())?;
        let mut context = BigNumContext::new()?;
        let peer = EcPoint::from_bytes(&group, point, &mut context)?;
        let peer = PKey::from_ec_key(EcKey::from_public_key(&group, &peer)?)?;
        let private = self.private_key(scalar)?;
        let mut deriver = Deriver::new(&private)?;
        deriver.set_peer(&peer)?;
        Ok(deriver.derive_to_vec()?)
    }
}

/// X25519 or X448.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Montgomery {
    X25519,
    X448,
}

impl Montgomery {
    pub fn by_name(name: &str) -> Option<Montgomery> {
        match name {
            "X25519" => Some(Montgomery::X25519),
            "X448" => Some(Montgomery::X448),
            _ => None,
        }
    }

    fn id(self) -> Id {
        match self {
            Montgomery::X25519 => Id::X25519,
            Montgomery::X448 => Id::X448,
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Montgomery::X25519 => 32,
            Montgomery::X448 => 56,
        }
    }

    pub fn public(self, sk: &[u8]) -> CryptoResult<Vec<u8>> {
        Ok(
            PKey::private_key_from_raw_bytes(sk, self.id())?
                .raw_public_key()?,
        )
    }

    /// RFC 7748; the all-zero value is refused (section 6: a small-order
    /// public key).
    pub fn dh(self, sk: &[u8], pk: &[u8]) -> CryptoResult<Vec<u8>> {
        if pk.len() != self.key_len() {
            return Err(err(format!(
                "an {:?} public key is {} octets; this one is {}",
                self,
                self.key_len(),
                pk.len()
            )));
        }
        let private = PKey::private_key_from_raw_bytes(sk, self.id())?;
        let peer = PKey::public_key_from_raw_bytes(pk, self.id())?;
        let mut deriver = Deriver::new(&private)?;
        deriver.set_peer(&peer)?;
        let out = deriver.derive_to_vec().map_err(|_| {
            err(format!(
                "the {:?} exchange produced the all-zero value, which RFC \
                 7748 section 6 requires refusing (a small-order public key)",
                self
            ))
        })?;
        if out.iter().all(|&b| b == 0) {
            return Err(err(format!(
                "the {:?} exchange produced the all-zero value, which RFC \
                 7748 section 6 requires refusing (a small-order public key)",
                self
            )));
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// The KDFs.
// ---------------------------------------------------------------------------

/// An HPKE KDF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kdf {
    pub id: u16,
    pub name: &'static str,
    /// HKDF's extract-then-expand; the XOFs are one stage.
    pub two_stage: bool,
    pub nh: usize,
}

pub fn kdf(id: u16) -> CryptoResult<Kdf> {
    let (name, two_stage, nh) = match id {
        0x0001 => ("HKDF-SHA256", true, 32),
        0x0002 => ("HKDF-SHA384", true, 48),
        0x0003 => ("HKDF-SHA512", true, 64),
        0x0010 => ("SHAKE128", false, 32),
        0x0011 => ("SHAKE256", false, 64),
        0x0012 => ("TurboSHAKE128", false, 32),
        0x0013 => ("TurboSHAKE256", false, 64),
        _ => return Err(err(format!("no HPKE KDF 0x{:x}", id))),
    };
    Ok(Kdf {
        id,
        name,
        two_stage,
        nh,
    })
}

const HPKE_V1: &[u8] = b"HPKE-v1";

impl Kdf {
    fn md(&self) -> MessageDigest {
        match self.id {
            0x0002 => MessageDigest::sha384(),
            0x0003 => MessageDigest::sha512(),
            _ => MessageDigest::sha256(),
        }
    }

    fn hmac(&self, key: &[u8], data: &[u8]) -> CryptoResult<Vec<u8>> {
        let pkey = PKey::hmac(key)?;
        let mut signer = Signer::new(self.md(), &pkey)?;
        Ok(signer.sign_oneshot_to_vec(data)?)
    }

    pub fn extract(&self, salt: &[u8], ikm: &[u8]) -> CryptoResult<Vec<u8>> {
        let zeros = vec![0u8; self.nh];
        self.hmac(if salt.is_empty() { &zeros } else { salt }, ikm)
    }

    pub fn expand(
        &self,
        prk: &[u8],
        info: &[u8],
        length: usize,
    ) -> CryptoResult<Vec<u8>> {
        if length > 255 * self.nh {
            return Err(err(format!(
                "HKDF-Expand cannot produce {} octets",
                length
            )));
        }
        let mut out = Vec::new();
        let mut previous = Vec::new();
        let mut i = 1u8;
        while out.len() < length {
            previous = self.hmac(prk, &concat(&[&previous, info, &[i]]))?;
            out.extend_from_slice(&previous);
            i = i.wrapping_add(1);
        }
        out.truncate(length);
        Ok(out)
    }

    fn xof(&self, ikm: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
        match self.id {
            0x0010 => shake(128, ikm, length),
            0x0011 => shake(256, ikm, length),
            0x0012 => Ok(turboshake(128, ikm, length)),
            _ => Ok(turboshake(256, ikm, length)),
        }
    }

    fn labeled_extract(
        &self,
        suite_id: &[u8],
        salt: &[u8],
        label: &str,
        ikm: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        self.extract(salt, &concat(&[HPKE_V1, suite_id, label.as_bytes(), ikm]))
    }

    fn labeled_expand(
        &self,
        suite_id: &[u8],
        prk: &[u8],
        label: &str,
        info: &[u8],
        length: usize,
    ) -> CryptoResult<Vec<u8>> {
        let info = concat(&[
            &i2osp(length as u64, 2)?,
            HPKE_V1,
            suite_id,
            label.as_bytes(),
            info,
        ]);
        self.expand(prk, &info, length)
    }

    fn labeled_derive(
        &self,
        suite_id: &[u8],
        ikm: &[u8],
        label: &str,
        context: &[u8],
        length: usize,
    ) -> CryptoResult<Vec<u8>> {
        let input = concat(&[
            ikm,
            HPKE_V1,
            suite_id,
            &length_prefixed(label.as_bytes())?,
            &i2osp(length as u64, 2)?,
            context,
        ]);
        self.xof(&input, length)
    }
}

// ---------------------------------------------------------------------------
// The hybrid KEMs.
// ---------------------------------------------------------------------------

/// The traditional group of a hybrid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HybridGroup {
    Nist(Nist),
    X25519,
}

/// A PQ/T hybrid KEM (draft-irtf-cfrg-concrete-hybrid-kems).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hybrid {
    pub name: &'static str,
    pq: MlKemSet,
    group: HybridGroup,
    seed_len: usize,
    scalar_len: usize,
    element_len: usize,
    label: &'static [u8],
}

pub const MLKEM768_P256: Hybrid = Hybrid {
    name: "MLKEM768-P256",
    pq: ML_KEM_768,
    group: HybridGroup::Nist(Nist::P256),
    seed_len: 128,
    scalar_len: 32,
    element_len: 65,
    label: b"MLKEM768-P256",
};
pub const MLKEM768_X25519: Hybrid = Hybrid {
    name: "MLKEM768-X25519",
    pq: ML_KEM_768,
    group: HybridGroup::X25519,
    seed_len: 32,
    scalar_len: 32,
    element_len: 32,
    // X-Wing's label: the ASCII-art "\.//^\".
    label: &[0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c],
};
pub const MLKEM1024_P384: Hybrid = Hybrid {
    name: "MLKEM1024-P384",
    pq: ML_KEM_1024,
    group: HybridGroup::Nist(Nist::P384),
    seed_len: 48,
    scalar_len: 48,
    element_len: 97,
    label: b"MLKEM1024-P384",
};

/// A hybrid key pair expanded from its 32-octet seed.
pub struct HybridKeys {
    pub seed_pq: Vec<u8>,
    pub dk_t: Vec<u8>,
    pub ek_t: Vec<u8>,
    pub ek: Vec<u8>,
}

impl Hybrid {
    /// RandomScalar: the first window of the seed that is a valid scalar.
    fn random_scalar(&self, seed: &[u8]) -> CryptoResult<Vec<u8>> {
        let HybridGroup::Nist(curve) = self.group else {
            return Ok(seed.to_vec());
        };
        let order = curve.order()?;
        for window in seed.chunks_exact(self.scalar_len) {
            let sk = BigNum::from_slice(window)?;
            if sk.num_bits() > 0 && sk < order {
                return Ok(window.to_vec());
            }
        }
        Err(err(format!(
            "RandomScalar: rejection sampling failed for {:?}",
            curve
        )))
    }

    fn group_public(&self, scalar: &[u8]) -> CryptoResult<Vec<u8>> {
        match self.group {
            HybridGroup::Nist(curve) => curve.public(scalar),
            HybridGroup::X25519 => Montgomery::X25519.public(scalar),
        }
    }

    fn group_dh(&self, scalar: &[u8], element: &[u8]) -> CryptoResult<Vec<u8>> {
        match self.group {
            HybridGroup::Nist(curve) => curve.dh(scalar, element),
            HybridGroup::X25519 => Montgomery::X25519.dh(scalar, element),
        }
    }

    pub fn public_len(&self) -> usize {
        self.pq.public_len + self.element_len
    }

    pub fn ciphertext_len(&self) -> usize {
        self.pq.ciphertext_len + self.element_len
    }

    pub fn expand(&self, seed: &[u8]) -> CryptoResult<HybridKeys> {
        if seed.len() != 32 {
            return Err(err(format!(
                "a {} private key is a 32-octet seed; this one is {} octets",
                self.name,
                seed.len()
            )));
        }
        let full = shake(256, seed, 64 + self.seed_len)?;
        let (ek_pq, _) = self.pq.from_seed(&full[..64])?;
        let dk_t = self.random_scalar(&full[64..])?;
        let ek_t = self.group_public(&dk_t)?;
        Ok(HybridKeys {
            seed_pq: full[..64].to_vec(),
            ek: concat(&[&ek_pq, &ek_t]),
            dk_t,
            ek_t,
        })
    }

    fn combine(
        &self,
        ss_pq: &[u8],
        ss_t: &[u8],
        ct_t: &[u8],
        ek_t: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        sha3_256(&concat(&[ss_pq, ss_t, ct_t, ek_t, self.label]))
    }

    pub fn encaps(&self, ek: &[u8]) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        if ek.len() != self.public_len() {
            return Err(err(format!(
                "a {} encapsulation key is {} octets; this one is {}",
                self.name,
                self.public_len(),
                ek.len()
            )));
        }
        let (ek_pq, ek_t) = ek.split_at(self.pq.public_len);
        let (ss_pq, ct_pq) = self.pq.encaps(ek_pq)?;
        let mut randomness = vec![0u8; self.seed_len];
        openssl::rand::rand_bytes(&mut randomness)?;
        let sk_e = self.random_scalar(&randomness)?;
        let ct_t = self.group_public(&sk_e)?;
        let ss_t = self.group_dh(&sk_e, ek_t)?;
        Ok((
            self.combine(&ss_pq, &ss_t, &ct_t, ek_t)?,
            concat(&[&ct_pq, &ct_t]),
        ))
    }

    pub fn decaps(&self, seed: &[u8], ct: &[u8]) -> CryptoResult<Vec<u8>> {
        let keys = self.expand(seed)?;
        if ct.len() != self.ciphertext_len() {
            return Err(err(format!(
                "a {} ciphertext is {} octets; this one is {}",
                self.name,
                self.ciphertext_len(),
                ct.len()
            )));
        }
        let (ct_pq, ct_t) = ct.split_at(self.pq.ciphertext_len);
        let ss_pq = self.pq.decaps(&keys.seed_pq, ct_pq)?;
        let ss_t = self.group_dh(&keys.dk_t, ct_t)?;
        self.combine(&ss_pq, &ss_t, ct_t, &keys.ek_t)
    }
}

// ---------------------------------------------------------------------------
// The KEMs.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemKind {
    Nist(Nist),
    Montgomery(Montgomery),
    MlKem(MlKemSet),
    Hybrid(Hybrid),
}

/// An HPKE KEM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kem {
    pub id: u16,
    pub name: &'static str,
    pub kind: KemKind,
    /// The DHKEM's own KDF; the ML-KEM and hybrid KEMs derive with SHAKE256.
    pub kdf: u16,
    pub n_secret: usize,
    pub n_enc: usize,
    pub n_pk: usize,
    pub n_sk: usize,
}

pub fn kem(id: u16) -> CryptoResult<Kem> {
    let (name, kind, kdf, n_secret, n_enc, n_pk, n_sk) = match id {
        0x0010 => (
            "DHKEM(P-256, HKDF-SHA256)",
            KemKind::Nist(Nist::P256),
            0x0001,
            32,
            65,
            65,
            32,
        ),
        0x0011 => (
            "DHKEM(P-384, HKDF-SHA384)",
            KemKind::Nist(Nist::P384),
            0x0002,
            48,
            97,
            97,
            48,
        ),
        0x0012 => (
            "DHKEM(P-521, HKDF-SHA512)",
            KemKind::Nist(Nist::P521),
            0x0003,
            64,
            133,
            133,
            66,
        ),
        0x0020 => (
            "DHKEM(X25519, HKDF-SHA256)",
            KemKind::Montgomery(Montgomery::X25519),
            0x0001,
            32,
            32,
            32,
            32,
        ),
        0x0021 => (
            "DHKEM(X448, HKDF-SHA512)",
            KemKind::Montgomery(Montgomery::X448),
            0x0003,
            64,
            56,
            56,
            56,
        ),
        0x0040 => (
            "ML-KEM-512",
            KemKind::MlKem(ML_KEM_512),
            0x0011,
            32,
            768,
            800,
            64,
        ),
        0x0041 => (
            "ML-KEM-768",
            KemKind::MlKem(ML_KEM_768),
            0x0011,
            32,
            1088,
            1184,
            64,
        ),
        0x0042 => (
            "ML-KEM-1024",
            KemKind::MlKem(ML_KEM_1024),
            0x0011,
            32,
            1568,
            1568,
            64,
        ),
        0x0050 => (
            "MLKEM768-P256",
            KemKind::Hybrid(MLKEM768_P256),
            0x0011,
            32,
            1153,
            1249,
            32,
        ),
        0x0051 => (
            "MLKEM1024-P384",
            KemKind::Hybrid(MLKEM1024_P384),
            0x0011,
            32,
            1665,
            1665,
            32,
        ),
        0x647a => (
            "MLKEM768-X25519",
            KemKind::Hybrid(MLKEM768_X25519),
            0x0011,
            32,
            1120,
            1216,
            32,
        ),
        _ => return Err(err(format!("no HPKE KEM 0x{:x}", id))),
    };
    Ok(Kem {
        id,
        name,
        kind,
        kdf,
        n_secret,
        n_enc,
        n_pk,
        n_sk,
    })
}

/// A KEM key pair, as octets: `(sk, pk)`.
pub type KeyPair = (Vec<u8>, Vec<u8>);

impl Kem {
    fn suite_id(&self) -> CryptoResult<Vec<u8>> {
        Ok(concat(&[b"KEM", &i2osp(u64::from(self.id), 2)?]))
    }

    /// The public key of a private one.
    pub fn public_of(&self, sk: &[u8]) -> CryptoResult<Vec<u8>> {
        match self.kind {
            KemKind::Nist(curve) => curve.public(sk),
            KemKind::Montgomery(group) => group.public(sk),
            KemKind::MlKem(set) => Ok(set.from_seed(sk)?.0),
            KemKind::Hybrid(h) => Ok(h.expand(sk)?.ek),
        }
    }

    /// DeriveKeyPair.
    pub fn derive_key_pair(&self, ikm: &[u8]) -> CryptoResult<KeyPair> {
        let suite_id = self.suite_id()?;
        if matches!(self.kind, KemKind::MlKem(_) | KemKind::Hybrid(_)) {
            let shake256 = kdf(0x0011)?;
            let sk = shake256.labeled_derive(
                &suite_id,
                ikm,
                "DeriveKeyPair",
                b"",
                self.n_sk,
            )?;
            let pk = self.public_of(&sk)?;
            return Ok((sk, pk));
        }
        let kdf = kdf(self.kdf)?;
        let prk = kdf.labeled_extract(&suite_id, b"", "dkp_prk", ikm)?;
        match self.kind {
            KemKind::Montgomery(group) => {
                let sk =
                    kdf.labeled_expand(&suite_id, &prk, "sk", b"", self.n_sk)?;
                let pk = group.public(&sk)?;
                Ok((sk, pk))
            }
            KemKind::Nist(curve) => {
                let order = curve.order()?;
                for counter in 0u64..256 {
                    let mut bytes = kdf.labeled_expand(
                        &suite_id,
                        &prk,
                        "candidate",
                        &i2osp(counter, 1)?,
                        self.n_sk,
                    )?;
                    if curve == Nist::P521 {
                        bytes[0] &= 0x01;
                    }
                    let sk = BigNum::from_slice(&bytes)?;
                    if sk.num_bits() > 0 && sk < order {
                        let pk = curve.public(&bytes)?;
                        return Ok((bytes, pk));
                    }
                }
                Err(err("DeriveKeyPairError: no scalar in 256 candidates"))
            }
            _ => Err(err("unreachable KEM kind")),
        }
    }

    pub fn generate_key_pair(&self) -> CryptoResult<KeyPair> {
        let mut random = vec![0u8; self.n_sk];
        openssl::rand::rand_bytes(&mut random)?;
        if matches!(self.kind, KemKind::MlKem(_) | KemKind::Hybrid(_)) {
            let pk = self.public_of(&random)?;
            return Ok((random, pk));
        }
        self.derive_key_pair(&random)
    }

    fn extract_and_expand(
        &self,
        dh: &[u8],
        context: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let suite_id = self.suite_id()?;
        let kdf = kdf(self.kdf)?;
        let prk = kdf.labeled_extract(&suite_id, b"", "eae_prk", dh)?;
        kdf.labeled_expand(
            &suite_id,
            &prk,
            "shared_secret",
            context,
            self.n_secret,
        )
    }

    /// Encap: `(shared secret, enc)`. `ikm_e` derives the ephemeral key, for
    /// a DHKEM's published vectors; the ML-KEM KEMs take none.
    pub fn encap(
        &self,
        pk_r: &[u8],
        ikm_e: Option<&[u8]>,
    ) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        if pk_r.len() != self.n_pk {
            return Err(err(format!(
                "a {} public key is {} octets; this one is {}",
                self.name,
                self.n_pk,
                pk_r.len()
            )));
        }
        let refuse_randomness = || {
            err("ML-KEM encapsulation takes no caller randomness here: \
                 OpenSSL does not accept it")
        };
        match self.kind {
            KemKind::MlKem(set) => {
                if ikm_e.is_some() {
                    return Err(refuse_randomness());
                }
                set.encaps(pk_r)
            }
            KemKind::Hybrid(h) => {
                if ikm_e.is_some() {
                    return Err(refuse_randomness());
                }
                h.encaps(pk_r)
            }
            KemKind::Nist(_) | KemKind::Montgomery(_) => {
                let (sk_e, enc) = match ikm_e {
                    Some(ikm) => self.derive_key_pair(ikm)?,
                    None => self.generate_key_pair()?,
                };
                let dh = match self.kind {
                    KemKind::Montgomery(group) => group.dh(&sk_e, pk_r)?,
                    KemKind::Nist(curve) => curve.dh(&sk_e, pk_r)?,
                    _ => Vec::new(),
                };
                let ss =
                    self.extract_and_expand(&dh, &concat(&[&enc, pk_r]))?;
                Ok((ss, enc))
            }
        }
    }

    pub fn decap(&self, enc: &[u8], sk_r: &[u8]) -> CryptoResult<Vec<u8>> {
        if enc.len() != self.n_enc {
            return Err(err(format!(
                "a {} encapsulated secret is {} octets; this one is {}",
                self.name,
                self.n_enc,
                enc.len()
            )));
        }
        match self.kind {
            KemKind::MlKem(set) => set.decaps(sk_r, enc),
            KemKind::Hybrid(h) => h.decaps(sk_r, enc),
            KemKind::Montgomery(group) => {
                let dh = group.dh(sk_r, enc)?;
                let pk = group.public(sk_r)?;
                self.extract_and_expand(&dh, &concat(&[enc, &pk]))
            }
            KemKind::Nist(curve) => {
                let dh = curve.dh(sk_r, enc)?;
                let pk = curve.public(sk_r)?;
                self.extract_and_expand(&dh, &concat(&[enc, &pk]))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The AEADs and the key schedule.
// ---------------------------------------------------------------------------

/// An HPKE AEAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aead {
    pub id: u16,
    pub name: &'static str,
    pub nk: usize,
    pub nn: usize,
    pub nt: usize,
}

pub fn aead(id: u16) -> CryptoResult<Aead> {
    let (name, nk, nn, nt) = match id {
        0x0001 => ("AES-128-GCM", 16, 12, 16),
        0x0002 => ("AES-256-GCM", 32, 12, 16),
        0x0003 => ("ChaCha20Poly1305", 32, 12, 16),
        0xffff => ("Export-only", 0, 0, 0),
        _ => return Err(err(format!("no HPKE AEAD 0x{:x}", id))),
    };
    Ok(Aead {
        id,
        name,
        nk,
        nn,
        nt,
    })
}

impl Aead {
    fn cipher(&self) -> Cipher {
        match self.id {
            0x0001 => Cipher::aes_128_gcm(),
            0x0002 => Cipher::aes_256_gcm(),
            _ => Cipher::chacha20_poly1305(),
        }
    }

    pub fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        pt: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let mut tag = vec![0u8; self.nt];
        let mut ct =
            encrypt_aead(self.cipher(), key, Some(nonce), aad, pt, &mut tag)?;
        ct.extend(tag);
        Ok(ct)
    }

    pub fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        if ct.len() < self.nt {
            return Err(err(format!(
                "an HPKE ciphertext carries a {}-bit tag and this one is {} \
                 octets",
                self.nt * 8,
                ct.len()
            )));
        }
        let (body, tag) = ct.split_at(ct.len() - self.nt);
        decrypt_aead(self.cipher(), key, Some(nonce), aad, body, tag)
            .map_err(|_| err("the HPKE ciphertext does not open"))
    }
}

/// A suite: KEM, KDF and AEAD ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Suite {
    pub kem: u16,
    pub kdf: u16,
    pub aead: u16,
}

pub const MODE_BASE: u8 = 0x00;
pub const MODE_PSK: u8 = 0x01;

/// The options of a setup: `info`, and a PSK with its id.
#[derive(Debug, Clone, Default)]
pub struct SetupOptions<'a> {
    pub info: &'a [u8],
    pub psk: &'a [u8],
    pub psk_id: &'a [u8],
}

/// An encryption context.
pub struct Context {
    kdf: Kdf,
    aead: Aead,
    suite_id: Vec<u8>,
    pub key: Vec<u8>,
    pub base_nonce: Vec<u8>,
    pub exporter_secret: Vec<u8>,
    seq: u64,
}

impl Context {
    fn nonce(&self) -> CryptoResult<Vec<u8>> {
        let seq = i2osp(self.seq, self.aead.nn)?;
        Ok(self
            .base_nonce
            .iter()
            .zip(seq)
            .map(|(a, b)| a ^ b)
            .collect())
    }

    pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> CryptoResult<Vec<u8>> {
        if self.aead.nk == 0 {
            return Err(err("HPKE: an export-only suite cannot encrypt"));
        }
        let ct = self.aead.seal(&self.key, &self.nonce()?, aad, pt)?;
        self.seq += 1;
        Ok(ct)
    }

    pub fn open(&mut self, aad: &[u8], ct: &[u8]) -> CryptoResult<Vec<u8>> {
        if self.aead.nk == 0 {
            return Err(err("HPKE: an export-only suite cannot decrypt"));
        }
        let pt = self.aead.open(&self.key, &self.nonce()?, aad, ct)?;
        self.seq += 1;
        Ok(pt)
    }

    pub fn export(
        &self,
        context: &[u8],
        length: usize,
    ) -> CryptoResult<Vec<u8>> {
        if self.kdf.two_stage {
            self.kdf.labeled_expand(
                &self.suite_id,
                &self.exporter_secret,
                "sec",
                context,
                length,
            )
        } else {
            self.kdf.labeled_derive(
                &self.suite_id,
                &self.exporter_secret,
                "sec",
                context,
                length,
            )
        }
    }
}

fn suite_id(suite: Suite) -> CryptoResult<Vec<u8>> {
    Ok(concat(&[
        b"HPKE",
        &i2osp(u64::from(suite.kem), 2)?,
        &i2osp(u64::from(suite.kdf), 2)?,
        &i2osp(u64::from(suite.aead), 2)?,
    ]))
}

/// KeySchedule.
pub fn key_schedule(
    suite: Suite,
    mode: u8,
    shared_secret: &[u8],
    options: &SetupOptions,
) -> CryptoResult<Context> {
    let kdf = kdf(suite.kdf)?;
    let aead = aead(suite.aead)?;
    let suite_id = suite_id(suite)?;
    let (psk, psk_id) = (options.psk, options.psk_id);
    if psk.is_empty() != psk_id.is_empty() {
        return Err(err(
            "HPKE: a PSK and its psk_id go together or not at all",
        ));
    }
    if !psk.is_empty() && mode == MODE_BASE {
        return Err(err("HPKE: a PSK was given for mode_base"));
    }
    if psk.is_empty() && mode == MODE_PSK {
        return Err(err("HPKE: mode_psk needs a PSK and a psk_id"));
    }
    if mode == MODE_PSK && psk.len() < 32 {
        return Err(err("HPKE: a PSK is at least 32 octets"));
    }
    let (key, base_nonce, exporter_secret) = if kdf.two_stage {
        let psk_id_hash =
            kdf.labeled_extract(&suite_id, b"", "psk_id_hash", psk_id)?;
        let info_hash =
            kdf.labeled_extract(&suite_id, b"", "info_hash", options.info)?;
        let context = concat(&[&[mode], &psk_id_hash, &info_hash]);
        let secret =
            kdf.labeled_extract(&suite_id, shared_secret, "secret", psk)?;
        (
            kdf.labeled_expand(&suite_id, &secret, "key", &context, aead.nk)?,
            kdf.labeled_expand(
                &suite_id,
                &secret,
                "base_nonce",
                &context,
                aead.nn,
            )?,
            kdf.labeled_expand(&suite_id, &secret, "exp", &context, kdf.nh)?,
        )
    } else {
        let secrets =
            concat(&[&length_prefixed(psk)?, &length_prefixed(shared_secret)?]);
        let context = concat(&[
            &[mode],
            &length_prefixed(psk_id)?,
            &length_prefixed(options.info)?,
        ]);
        let secret = kdf.labeled_derive(
            &suite_id,
            &secrets,
            "secret",
            &context,
            aead.nk + aead.nn + kdf.nh,
        )?;
        (
            secret[..aead.nk].to_vec(),
            secret[aead.nk..aead.nk + aead.nn].to_vec(),
            secret[aead.nk + aead.nn..].to_vec(),
        )
    };
    Ok(Context {
        kdf,
        aead,
        suite_id,
        key,
        base_nonce,
        exporter_secret,
        seq: 0,
    })
}

fn mode_of(options: &SetupOptions) -> u8 {
    if options.psk.is_empty() {
        MODE_BASE
    } else {
        MODE_PSK
    }
}

/// SetupS: `(enc, context)`.
pub fn setup_sender(
    suite: Suite,
    pk_r: &[u8],
    options: &SetupOptions,
) -> CryptoResult<(Vec<u8>, Context)> {
    let (ss, enc) = kem(suite.kem)?.encap(pk_r, None)?;
    Ok((enc, key_schedule(suite, mode_of(options), &ss, options)?))
}

/// SetupR.
pub fn setup_receiver(
    suite: Suite,
    enc: &[u8],
    sk_r: &[u8],
    options: &SetupOptions,
) -> CryptoResult<Context> {
    let ss = kem(suite.kem)?.decap(enc, sk_r)?;
    key_schedule(suite, mode_of(options), &ss, options)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kem_round_trips() {
        for id in [
            0x0010, 0x0011, 0x0012, 0x0020, 0x0021, 0x0040, 0x0041, 0x0042,
            0x0050, 0x0051, 0x647a,
        ] {
            let kem = kem(id).unwrap();
            let (sk, pk) = kem.generate_key_pair().unwrap();
            assert_eq!(pk.len(), kem.n_pk, "{}", kem.name);
            let (ss, enc) = kem.encap(&pk, None).unwrap();
            assert_eq!(enc.len(), kem.n_enc, "{}", kem.name);
            assert_eq!(kem.decap(&enc, &sk).unwrap(), ss, "{}", kem.name);
        }
    }

    #[test]
    fn a_context_seals_and_opens() {
        let suite = Suite {
            kem: 0x647a,
            kdf: 0x0013,
            aead: 0x0003,
        };
        let (sk, pk) = kem(suite.kem).unwrap().generate_key_pair().unwrap();
        let options = SetupOptions {
            info: b"info",
            ..SetupOptions::default()
        };
        let (enc, mut sender) = setup_sender(suite, &pk, &options).unwrap();
        let mut receiver = setup_receiver(suite, &enc, &sk, &options).unwrap();
        let ct = sender.seal(b"aad", b"hello").unwrap();
        assert_eq!(receiver.open(b"aad", &ct).unwrap(), b"hello");
        assert!(receiver.open(b"aad", &ct).is_err(), "the nonce moved on");
    }
}
