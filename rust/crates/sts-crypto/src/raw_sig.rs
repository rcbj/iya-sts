// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Signatures over raw bytes, and the TPM 2.0 key derivation:
//! `common/crypto.js` section 8 (#40).
//!
//! SPIFFE's node attestors prove possession of a key by signing a challenge
//! in formats none of which is a JWS or an XML signature — SPIRE's x509pop,
//! OpenSSH signatures, a TPM's TPMT_SIGNATURE, a DevID's X.509 signature —
//! and the Data Integrity suites sign bytes too. **One primitive,
//! [`verify_raw_signature`], and the caller names the scheme**; a key of the
//! wrong kind for the family is `false`, never an error. The post-quantum
//! family (ML-DSA, SLH-DSA and composite ML-DSA) goes through
//! [`crate::pq_x509`], the engine that checks a post-quantum certificate.
//!
//! Beside it: TPM 2.0 KDFa and MakeCredential (go-tpm's
//! `credactivation.Generate()`), a CMS SignedData verifier for AWS's and
//! Azure's signed instance documents, and the streamed SHA-256 helpers.

use std::io::Read;

use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::encrypt::Encrypter;
use openssl::hash::{Hasher, MessageDigest};
use openssl::nid::Nid;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::pkey::{Id, PKey, PKeyRef, Private, Public};
use openssl::rsa::Padding;
use openssl::sign::{RsaPssSaltlen, Signer, Verifier};
use openssl::stack::Stack;
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::X509;

use crate::error::{CryptoError, CryptoResult};
use crate::keys::{rsa_key_problem, KeyPolicy};
use crate::pq_x509;
use crate::random::random_bytes;

/// The families [`verify_raw_signature`] understands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawFamily {
    RsaPkcs1,
    RsaPss,
    Ecdsa,
    EdDsa,
    PostQuantum,
}

/// The digest a signature was made over the data with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawHash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl RawHash {
    pub fn md(self) -> MessageDigest {
        match self {
            RawHash::Sha1 => MessageDigest::sha1(),
            RawHash::Sha256 => MessageDigest::sha256(),
            RawHash::Sha384 => MessageDigest::sha384(),
            RawHash::Sha512 => MessageDigest::sha512(),
        }
    }

    pub fn from_name(name: &str) -> Option<RawHash> {
        Some(match name {
            "sha1" => RawHash::Sha1,
            "sha256" => RawHash::Sha256,
            "sha384" => RawHash::Sha384,
            "sha512" => RawHash::Sha512,
            _ => return None,
        })
    }
}

/// An RSA-PSS salt: a length, or any (`'auto'`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Salt {
    Auto,
    Length(u32),
}

/// An ECDSA signature's encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcdsaEncoding {
    Der,
    /// `r||s`, each padded to the curve (IEEE P1363).
    P1363,
}

/// What the protocol says was done.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawScheme {
    pub family: RawFamily,
    /// Absent for EdDSA and the post-quantum family.
    pub hash: Option<RawHash>,
    /// ECDSA only. `None` is each side's default, as in Node: DER to
    /// verify, r||s to sign.
    pub encoding: Option<EcdsaEncoding>,
    /// RSA-PSS only.
    pub salt: Salt,
}

impl RawScheme {
    pub fn new(family: RawFamily, hash: Option<RawHash>) -> RawScheme {
        RawScheme {
            family,
            hash,
            encoding: None,
            salt: Salt::Auto,
        }
    }

    pub fn with_encoding(mut self, encoding: EcdsaEncoding) -> RawScheme {
        self.encoding = Some(encoding);
        self
    }

    pub fn with_salt(mut self, salt: Salt) -> RawScheme {
        self.salt = salt;
        self
    }
}

/// A SubjectPublicKeyInfo as a caller choosing a scheme needs it.
pub struct DescribedKey {
    /// `rsa`, `ec`, `ed25519`, `ed448`, `pq` — or empty for anything else.
    pub kind: &'static str,
    pub key: Option<PKey<Public>>,
    /// OpenSSL's short curve name (`prime256v1`) for an EC key.
    pub curve: String,
    /// The post-quantum algorithm id for a `pq` key.
    pub pq_algorithm: Option<&'static str>,
    pub spki: Vec<u8>,
}

/// `publicKeyFromSpki()`: never fails; `kind` is empty for a key of a kind
/// nothing here verifies.
pub fn public_key_from_spki(spki: &[u8]) -> DescribedKey {
    if let Some((alg, _)) =
        pq_x509::decode_spki(spki).filter(|(a, _)| a.usage == pq_x509::Use::Sig)
    {
        return DescribedKey {
            kind: "pq",
            key: None,
            curve: String::new(),
            pq_algorithm: Some(alg.id),
            spki: spki.to_vec(),
        };
    }
    match PKey::public_key_from_der(spki) {
        Ok(key) => {
            let kind = match key.id() {
                Id::RSA | Id::RSA_PSS => "rsa",
                Id::EC => "ec",
                Id::ED25519 => "ed25519",
                Id::ED448 => "ed448",
                _ => "",
            };
            let curve = key
                .ec_key()
                .ok()
                .and_then(|ec| ec.group().curve_name())
                .and_then(|n| n.short_name().ok().map(str::to_string))
                .unwrap_or_default();
            DescribedKey {
                kind,
                key: Some(key),
                curve,
                pq_algorithm: None,
                spki: spki.to_vec(),
            }
        }
        Err(_) => DescribedKey {
            kind: "",
            key: None,
            curve: String::new(),
            pq_algorithm: None,
            spki: spki.to_vec(),
        },
    }
}

fn ec_width<T: openssl::pkey::HasPublic>(key: &PKeyRef<T>) -> usize {
    key.ec_key()
        .map(|e| (e.group().order_bits() as usize).div_ceil(8))
        .unwrap_or(0)
}

fn p1363_to_der(sig: &[u8], width: usize) -> Option<Vec<u8>> {
    if width == 0 || sig.len() != 2 * width {
        return None;
    }
    let r = BigNum::from_slice(&sig[..width]).ok()?;
    let s = BigNum::from_slice(&sig[width..]).ok()?;
    EcdsaSig::from_private_components(r, s).ok()?.to_der().ok()
}

/// `verifyRawSignature()`: whether `signature` verifies over `data` under
/// the scheme. A malformed signature or a key of the wrong kind is `false`.
pub fn verify_raw_signature(
    scheme: &RawScheme,
    key: &DescribedKey,
    data: &[u8],
    signature: &[u8],
) -> bool {
    if scheme.family == RawFamily::PostQuantum {
        let Some((alg, public)) = (key.kind == "pq")
            .then(|| pq_x509::decode_spki(&key.spki))
            .flatten()
        else {
            return false;
        };
        return pq_x509::verify(alg.id, signature, data, &public)
            .unwrap_or(false);
    }
    let Some(public) = key.key.as_ref() else {
        return false;
    };
    if matches!(public.id(), Id::RSA | Id::RSA_PSS)
        && rsa_key_problem(public, 0, KeyPolicy::LENIENT).is_some()
    {
        return false;
    }
    let attempt = || -> Result<bool, openssl::error::ErrorStack> {
        let md = scheme.hash.map(RawHash::md);
        Ok(match (scheme.family, public.id()) {
            (RawFamily::RsaPkcs1, Id::RSA | Id::RSA_PSS) => {
                let Some(md) = md else { return Ok(false) };
                let mut v = Verifier::new(md, public)?;
                v.set_rsa_padding(Padding::PKCS1)?;
                v.verify_oneshot(signature, data)?
            }
            (RawFamily::RsaPss, Id::RSA | Id::RSA_PSS) => {
                let Some(md) = md else { return Ok(false) };
                let mut v = Verifier::new(md, public)?;
                v.set_rsa_padding(Padding::PKCS1_PSS)?;
                v.set_rsa_mgf1_md(md)?;
                v.set_rsa_pss_saltlen(match scheme.salt {
                    // RSA_PSS_SALTLEN_AUTO: any salt the signature carries.
                    Salt::Auto => RsaPssSaltlen::custom(-2),
                    Salt::Length(n) => RsaPssSaltlen::custom(n as i32),
                })?;
                v.verify_oneshot(signature, data)?
            }
            (RawFamily::Ecdsa, Id::EC) => {
                let Some(md) = md else { return Ok(false) };
                let der = if scheme.encoding == Some(EcdsaEncoding::P1363) {
                    match p1363_to_der(signature, ec_width(public)) {
                        Some(d) => d,
                        None => return Ok(false),
                    }
                } else {
                    signature.to_vec()
                };
                Verifier::new(md, public)?.verify_oneshot(&der, data)?
            }
            (RawFamily::EdDsa, Id::ED25519 | Id::ED448) => {
                Verifier::new_without_digest(public)?
                    .verify_oneshot(signature, data)?
            }
            _ => false,
        })
    };
    attempt().unwrap_or(false)
}

/// `signRawSignature()`: ECDSA (r||s unless DER is asked for) or EdDSA, for
/// the Data Integrity suites. A key of the wrong kind is an error: a signer
/// handed the wrong key is a bug, not an input.
pub fn sign_raw_signature(
    scheme: &RawScheme,
    private: &PKeyRef<Private>,
    data: &[u8],
) -> CryptoResult<Vec<u8>> {
    match (scheme.family, private.id()) {
        (RawFamily::Ecdsa, Id::EC) => {
            let md = scheme
                .hash
                .ok_or_else(|| {
                    CryptoError::new("an ECDSA signature needs a hash")
                })?
                .md();
            let der = Signer::new(md, private)?.sign_oneshot_to_vec(data)?;
            if scheme.encoding == Some(EcdsaEncoding::Der) {
                return Ok(der);
            }
            let width = ec_width(private) as i32;
            let sig = EcdsaSig::from_der(&der)?;
            let mut out = sig.r().to_vec_padded(width)?;
            out.extend(sig.s().to_vec_padded(width)?);
            Ok(out)
        }
        (RawFamily::EdDsa, Id::ED25519 | Id::ED448) => {
            Ok(Signer::new_without_digest(private)?
                .sign_oneshot_to_vec(data)?)
        }
        _ => Err(CryptoError::new(format!(
            "signRawSignature: a {} key does not sign {:?}.",
            crate::xmldsig::key_type(private),
            scheme.family
        ))),
    }
}

/// HMAC-SHA-256 (ecdsa-sd-2023's blank node labels).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> CryptoResult<Vec<u8>> {
    let k = PKey::hmac(key)?;
    let mut s = Signer::new(MessageDigest::sha256(), &k)?;
    s.update(data)?;
    Ok(s.sign_to_vec()?)
}

/// A fresh key pair: EC on a named curve (OpenSSL's short name) or Ed25519.
pub fn ephemeral_key_pair(curve: Option<&str>) -> CryptoResult<PKey<Private>> {
    match curve {
        None => Ok(PKey::generate_ed25519()?),
        Some(name) => {
            let nid = match name {
                "prime256v1" => Nid::X9_62_PRIME256V1,
                "secp384r1" => Nid::SECP384R1,
                "secp521r1" => Nid::SECP521R1,
                "secp256k1" => Nid::SECP256K1,
                other => {
                    return Err(CryptoError::new(format!("no curve {}", other)))
                }
            };
            let group = EcGroup::from_curve_name(nid)?;
            Ok(PKey::from_ec_key(EcKey::generate(&group)?)?)
        }
    }
}

/// `ecdsaIntegersToP1363()`: two big-endian integers as r||s for a curve
/// (OpenSSL's short name), or `None` when either is too long.
pub fn ecdsa_integers_to_p1363(
    curve: &str,
    r: &[u8],
    s: &[u8],
) -> Option<Vec<u8>> {
    let size = match curve {
        "prime256v1" => 32,
        "secp384r1" => 48,
        "secp521r1" => 66,
        _ => return None,
    };
    let trim = |b: &[u8]| {
        let start = b
            .iter()
            .position(|&x| x != 0)
            .unwrap_or(b.len().saturating_sub(1));
        b[start.min(b.len())..].to_vec()
    };
    let (rr, ss) = (trim(r), trim(s));
    if rr.len() > size || ss.len() > size {
        return None;
    }
    let mut out = vec![0u8; size - rr.len()];
    out.extend(rr);
    out.extend(vec![0u8; size - ss.len()]);
    out.extend(ss);
    Some(out)
}

// ---------------------------------------------------------------------------
// TPM 2.0.
// ---------------------------------------------------------------------------

/// TPM 2.0 KDFa (Library Part 1, section 11.4.10.2): counter-mode HMAC over
/// label || 0x00 || contextU || contextV || bits.
pub fn tpm_kdfa(
    hash: RawHash,
    key: &[u8],
    label: &str,
    context_u: &[u8],
    context_v: &[u8],
    bits: u32,
) -> CryptoResult<Vec<u8>> {
    let bytes = bits.div_ceil(8) as usize;
    let k = PKey::hmac(key)?;
    let mut out = Vec::new();
    let mut counter: u32 = 1;
    while out.len() < bytes {
        let mut s = Signer::new(hash.md(), &k)?;
        s.update(&counter.to_be_bytes())?;
        s.update(label.as_bytes())?;
        s.update(&[0])?;
        s.update(context_u)?;
        s.update(context_v)?;
        s.update(&bits.to_be_bytes())?;
        out.extend(s.sign_to_vec()?);
        counter += 1;
    }
    out.truncate(bytes);
    if bits % 8 != 0 {
        out[0] &= (1u8 << (bits % 8)) - 1;
    }
    Ok(out)
}

/// TPM2_MakeCredential's two outputs.
pub struct MadeCredential {
    /// TPM2B_ID_OBJECT's contents.
    pub credential: Vec<u8>,
    /// TPM2B_ENCRYPTED_SECRET's contents.
    pub secret: Vec<u8>,
}

/// TPM2_MakeCredential in software for an RSA endorsement key (go-tpm's
/// `credactivation.Generate()`): only a TPM holding the EK's private key,
/// activating for that AK, recovers `secret`.
pub fn tpm_make_credential(
    ak_name: &[u8],
    ek: &PKeyRef<Public>,
    seed_bytes: usize,
    secret: &[u8],
    hash: RawHash,
) -> CryptoResult<MadeCredential> {
    let seed = random_bytes(seed_bytes)?;
    make_credential_with_seed(ak_name, ek, &seed, secret, hash)
}

fn make_credential_with_seed(
    ak_name: &[u8],
    ek: &PKeyRef<Public>,
    seed: &[u8],
    secret: &[u8],
    hash: RawHash,
) -> CryptoResult<MadeCredential> {
    let mut enc = Encrypter::new(ek)?;
    enc.set_rsa_padding(Padding::PKCS1_OAEP)?;
    enc.set_rsa_oaep_md(hash.md())?;
    enc.set_rsa_mgf1_md(hash.md())?;
    enc.set_rsa_oaep_label(b"IDENTITY\0")?;
    let mut encrypted_seed = vec![0u8; enc.encrypt_len(seed)?];
    let n = enc.encrypt(seed, &mut encrypted_seed)?;
    encrypted_seed.truncate(n);
    let bits = (seed.len() * 8) as u32;
    let storage_key = tpm_kdfa(hash, seed, "STORAGE", ak_name, &[], bits)?;
    let mut plain = (secret.len() as u16).to_be_bytes().to_vec();
    plain.extend_from_slice(secret);
    let cfb = match seed.len() {
        16 => Cipher::aes_128_cfb128(),
        24 => Cipher::aes_192_cfb128(),
        _ => Cipher::aes_256_cfb128(),
    };
    let mut c =
        Crypter::new(cfb, Mode::Encrypt, &storage_key, Some(&[0u8; 16]))?;
    let mut enc_identity = vec![0u8; plain.len() + 16];
    let w = c.update(&plain, &mut enc_identity)?;
    let f = c.finalize(&mut enc_identity[w..])?;
    enc_identity.truncate(w + f);
    let mac_key = tpm_kdfa(
        hash,
        seed,
        "INTEGRITY",
        &[],
        &[],
        (hash.md().size() * 8) as u32,
    )?;
    let k = PKey::hmac(&mac_key)?;
    let mut s = Signer::new(hash.md(), &k)?;
    s.update(&enc_identity)?;
    s.update(ak_name)?;
    let integrity = s.sign_to_vec()?;
    let mut credential = (integrity.len() as u16).to_be_bytes().to_vec();
    credential.extend(integrity);
    credential.extend(enc_identity);
    Ok(MadeCredential {
        credential,
        secret: encrypted_seed,
    })
}

// ---------------------------------------------------------------------------
// CMS SignedData.
// ---------------------------------------------------------------------------

/// What [`verify_pkcs7_signed_data`] found.
pub struct SignedContent {
    pub content: Vec<u8>,
    pub signer_der: Vec<u8>,
    pub embedded_ders: Vec<Vec<u8>>,
}

/// `verifyPkcs7SignedData()`: a SignedData with its content attached, its
/// ONE SignerInfo's signature checked under the signer's certificate —
/// found among the embedded ones and `certificates` (AWS embeds none). The
/// signature only: whether to believe the signer is the caller's question.
pub fn verify_pkcs7_signed_data(
    der: &[u8],
    certificates: &[Vec<u8>],
) -> Result<SignedContent, String> {
    let p7 = Pkcs7::from_der(der)
        .map_err(|_| "the signature is not a PKCS#7 SignedData".to_string())?;
    let signed = p7
        .signed()
        .ok_or("the signature is not a PKCS#7 SignedData")?;
    let embedded: Vec<Vec<u8>> = signed
        .certificates()
        .map(|s| s.iter().filter_map(|c| c.to_der().ok()).collect())
        .unwrap_or_default();
    let mut extra = Stack::new().map_err(|e| e.to_string())?;
    for der in certificates {
        let cert = X509::from_der(der)
            .map_err(|e| format!("a certificate given is not DER: {}", e))?;
        extra.push(cert).map_err(|e| e.to_string())?;
    }
    let signers = p7.signers(&extra, Pkcs7Flags::empty()).map_err(|_| {
        "the signer's certificate is not among those given".to_string()
    })?;
    if signers.len() != 1 {
        return Err(format!(
            "expected exactly one signer, found {}",
            signers.len()
        ));
    }
    let signer_der = signers
        .get(0)
        .and_then(|c| c.to_der().ok())
        .ok_or("the signer's certificate cannot be read")?;
    let store = X509StoreBuilder::new().map_err(|e| e.to_string())?.build();
    let mut content = Vec::new();
    p7.verify(
        &extra,
        &store,
        None,
        Some(&mut content),
        Pkcs7Flags::NOVERIFY,
    )
    .map_err(|e| format!("the signature does not verify: {}", e))?;
    Ok(SignedContent {
        content,
        signer_der,
        embedded_ders: embedded,
    })
}

// ---------------------------------------------------------------------------
// SHA-256, streamed.
// ---------------------------------------------------------------------------

/// A SHA-256 fed as bytes arrive.
pub struct Sha256Digester(Hasher);

impl Sha256Digester {
    pub fn new() -> CryptoResult<Sha256Digester> {
        Ok(Sha256Digester(Hasher::new(MessageDigest::sha256())?))
    }

    pub fn update(&mut self, chunk: &[u8]) -> CryptoResult<()> {
        Ok(self.0.update(chunk)?)
    }

    /// Lower-case hex.
    pub fn hex(mut self) -> CryptoResult<String> {
        Ok(self
            .0
            .finish()?
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect())
    }
}

/// The SHA-256 of a file, lower-case hex, refusing one larger than `limit`
/// bytes when `limit` is above 0 (SPIRE's `util.GetSHA256Digest()`).
pub fn sha256_of_file(
    path: &std::path::Path,
    limit: u64,
) -> Result<String, String> {
    let size = std::fs::metadata(path).map_err(|e| e.to_string())?.len();
    if limit > 0 && size > limit {
        return Err(format!(
            "workload {} exceeds size limit ({} > {})",
            path.display(),
            size,
            limit
        ));
    }
    let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut d = Sha256Digester::new().map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        d.update(&buf[..n]).map_err(|e| e.to_string())?;
    }
    d.hex().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::rsa::Rsa;

    #[test]
    fn each_family_and_the_wrong_key() {
        let ec = ephemeral_key_pair(Some("secp384r1")).unwrap();
        let spki = ec.public_key_to_der().unwrap();
        let d = public_key_from_spki(&spki);
        assert_eq!((d.kind, d.curve.as_str()), ("ec", "secp384r1"));
        let scheme = RawScheme::new(RawFamily::Ecdsa, Some(RawHash::Sha384))
            .with_encoding(EcdsaEncoding::P1363);
        let sig = sign_raw_signature(&scheme, &ec, b"challenge").unwrap();
        assert_eq!(sig.len(), 96);
        assert!(verify_raw_signature(&scheme, &d, b"challenge", &sig));
        assert!(!verify_raw_signature(
            &RawScheme::new(RawFamily::EdDsa, None),
            &d,
            b"challenge",
            &sig
        ));
        let der = sign_raw_signature(
            &RawScheme::new(RawFamily::Ecdsa, Some(RawHash::Sha384))
                .with_encoding(EcdsaEncoding::Der),
            &ec,
            b"x",
        )
        .unwrap();
        assert!(verify_raw_signature(
            &RawScheme::new(RawFamily::Ecdsa, Some(RawHash::Sha384)),
            &d,
            b"x",
            &der
        ));

        let (public, private) =
            pq_x509::generate_key_pair("mldsa44-ecdsa-p256-sha256").unwrap();
        let pq = public_key_from_spki(
            &pq_x509::encode_spki("mldsa44-ecdsa-p256-sha256", &public)
                .unwrap(),
        );
        let sig =
            pq_x509::sign("mldsa44-ecdsa-p256-sha256", b"m", &private).unwrap();
        assert!(verify_raw_signature(
            &RawScheme::new(RawFamily::PostQuantum, None),
            &pq,
            b"m",
            &sig
        ));
    }

    #[test]
    fn integers_to_p1363() {
        let out =
            ecdsa_integers_to_p1363("prime256v1", &[0, 0, 1], &[2]).unwrap();
        assert_eq!(out.len(), 64);
        assert_eq!((out[31], out[63]), (1, 2));
        assert!(ecdsa_integers_to_p1363("prime256v1", &[1; 33], &[2]).is_none());
    }

    /// TPM2_ActivateCredential's arithmetic, to check MakeCredential.
    #[test]
    fn make_credential_activates() {
        let rsa = Rsa::generate(2048).unwrap();
        let private = PKey::from_rsa(rsa.clone()).unwrap();
        let public =
            PKey::public_key_from_der(&private.public_key_to_der().unwrap())
                .unwrap();
        let ak_name = [0u8, 0x0b, 1, 2, 3];
        let made = tpm_make_credential(
            &ak_name,
            &public,
            16,
            b"the secret",
            RawHash::Sha256,
        )
        .unwrap();
        let mut dec = openssl::encrypt::Decrypter::new(&private).unwrap();
        dec.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
        dec.set_rsa_oaep_md(MessageDigest::sha256()).unwrap();
        dec.set_rsa_mgf1_md(MessageDigest::sha256()).unwrap();
        dec.set_rsa_oaep_label(b"IDENTITY\0").unwrap();
        let mut seed = vec![0u8; dec.decrypt_len(&made.secret).unwrap()];
        let n = dec.decrypt(&made.secret, &mut seed).unwrap();
        seed.truncate(n);
        let storage =
            tpm_kdfa(RawHash::Sha256, &seed, "STORAGE", &ak_name, &[], 128)
                .unwrap();
        let body = &made.credential[2 + 32..];
        let plain = openssl::symm::decrypt(
            Cipher::aes_128_cfb128(),
            &storage,
            Some(&[0u8; 16]),
            body,
        )
        .unwrap();
        assert_eq!(&plain[2..], b"the secret");
    }
}
