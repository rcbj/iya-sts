// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! JWS: the signature over octets for every algorithm in [`crate::jws_alg`],
//! and the compact serialization around it. A port of `common/crypto.js`
//! section 3 and `common/pq_jose.js`.
//!
//! **THE CALLER NAMES THE ACCEPTABLE ALGORITHMS AND THE TOKEN DOES NOT**
//! (RFC 8725 section 3.1). [`verify_compact`] has no default list: a
//! verifier that let the token choose is the algorithm-confusion defect.
//!
//! **The order of the refusals is part of the contract**: a token whose
//! `alg` the caller did not name is refused for that and never for its
//! signature.
//!
//! The ECDSA signature is the R||S concatenation of RFC 7518 section 3.4,
//! converted here from the DER OpenSSL speaks; a ~70-byte one is refused by
//! name, because it is the DER a general-purpose API returns, sent without
//! converting it.

use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::pkey::{Id, KeyType, PKey, PKeyRef, Private, Public};
use openssl::rsa::Padding;
use openssl::sign::{RsaPssSaltlen, Signer, Verifier};
use serde_json::{Map, Value as Json};

use crate::b64;
use crate::error::{CryptoError, CryptoResult};
use crate::jws_alg::{Composite, Family, Hash, JwsAlg, Traditional};
use crate::keys::{
    curve_of, ec_point_of, hmac_key_problem, rsa_key_problem, JwsKey,
    KeyPolicy, Material,
};
use crate::pq;

fn alg_row(name: &str) -> CryptoResult<&'static JwsAlg> {
    JwsAlg::by_name(name).ok_or_else(|| {
        CryptoError::new(format!(
            "unsupported JWS algorithm \"{}\"; this service implements {}.",
            name,
            crate::jws_alg::signing_algs().join(", ")
        ))
    })
}

// ---------------------------------------------------------------------------
// The signature over octets.
// ---------------------------------------------------------------------------

fn hmac(hash: Hash, key: &[u8], input: &[u8]) -> CryptoResult<Vec<u8>> {
    let pkey = PKey::hmac(key)?;
    let mut signer = Signer::new(hash.message_digest(), &pkey)?;
    Ok(signer.sign_oneshot_to_vec(input)?)
}

fn rsa_sign(
    key: &PKeyRef<Private>,
    hash: Hash,
    pss: bool,
    input: &[u8],
) -> CryptoResult<Vec<u8>> {
    let mut signer = Signer::new(hash.message_digest(), key)?;
    if pss {
        signer.set_rsa_padding(Padding::PKCS1_PSS)?;
        signer.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
        signer.set_rsa_mgf1_md(hash.message_digest())?;
    }
    Ok(signer.sign_oneshot_to_vec(input)?)
}

fn rsa_verify(
    key: &PKeyRef<Public>,
    hash: Hash,
    pss: bool,
    input: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    let mut verifier = Verifier::new(hash.message_digest(), key)?;
    if pss {
        verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
        verifier.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
        verifier.set_rsa_mgf1_md(hash.message_digest())?;
    }
    Ok(verifier.verify_oneshot(signature, input).unwrap_or(false))
}

/// ECDSA, as R||S of `length` bytes.
fn ec_sign(
    key: &PKeyRef<Private>,
    hash: Hash,
    length: usize,
    input: &[u8],
) -> CryptoResult<Vec<u8>> {
    let mut signer = Signer::new(hash.message_digest(), key)?;
    let der = signer.sign_oneshot_to_vec(input)?;
    let signature = EcdsaSig::from_der(&der)?;
    let half = (length / 2) as i32;
    let mut out = signature.r().to_vec_padded(half)?;
    out.extend(signature.s().to_vec_padded(half)?);
    Ok(out)
}

fn ec_verify(
    key: &PKeyRef<Public>,
    hash: Hash,
    input: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    let half = signature.len() / 2;
    let r = BigNum::from_slice(&signature[..half])?;
    let s = BigNum::from_slice(&signature[half..])?;
    let der = EcdsaSig::from_private_components(r, s)?.to_der()?;
    let mut verifier = Verifier::new(hash.message_digest(), key)?;
    Ok(verifier.verify_oneshot(&der, input).unwrap_or(false))
}

fn eddsa_sign(key: &PKeyRef<Private>, input: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut signer = Signer::new_without_digest(key)?;
    Ok(signer.sign_oneshot_to_vec(input)?)
}

fn eddsa_verify(
    key: &PKeyRef<Public>,
    input: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    let mut verifier = Verifier::new_without_digest(key)?;
    Ok(verifier.verify_oneshot(signature, input).unwrap_or(false))
}

fn curve_matches<T: openssl::pkey::HasPublic>(
    key: &PKeyRef<T>,
    curve: openssl::nid::Nid,
) -> bool {
    key.ec_key()
        .ok()
        .and_then(|ec| ec.group().curve_name())
        .is_some_and(|nid| nid == curve)
}

// --- the post-quantum algorithms and the composites -----------------------

fn ml_dsa_key_type(name: &str) -> KeyType {
    match name {
        "ML-DSA-44" => KeyType::ML_DSA_44,
        "ML-DSA-87" => KeyType::ML_DSA_87,
        _ => KeyType::ML_DSA_65,
    }
}

/// An ML-DSA private key from RFC 9964's 32-byte seed.
fn ml_dsa_private(name: &str, seed: &[u8]) -> CryptoResult<PKey<Private>> {
    if seed.len() != 32 {
        return Err(CryptoError::new(format!(
            "an ML-DSA \"priv\" is the 32-byte seed of RFC 9964 section 3.2; \
             this one is {} bytes.",
            seed.len()
        )));
    }
    Ok(PKey::private_key_from_seed(
        None,
        ml_dsa_key_type(name),
        None,
        seed,
    )?)
}

const COMPOSITE_PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";

/// M' = prefix || label || 0x00 || PH(message), which both halves sign.
fn composite_message(composite: &Composite, message: &[u8]) -> Vec<u8> {
    let mut out = COMPOSITE_PREFIX.to_vec();
    out.extend_from_slice(composite.label.as_bytes());
    out.push(0x00);
    out.extend(composite.prehash.digest(message));
    out
}

fn traditional_curve(traditional: Traditional) -> openssl::nid::Nid {
    match traditional {
        Traditional::Es384 => openssl::nid::Nid::SECP384R1,
        _ => openssl::nid::Nid::X9_62_PRIME256V1,
    }
}

fn traditional_private(
    traditional: Traditional,
    raw: &[u8],
) -> CryptoResult<PKey<Private>> {
    match traditional {
        Traditional::Es256 | Traditional::Es384 => {
            let group =
                EcGroup::from_curve_name(traditional_curve(traditional))?;
            let scalar = BigNum::from_slice(raw)?;
            let point = ec_point_of(&group, &scalar)?;
            let key = EcKey::from_private_components(&group, &scalar, &point)?;
            Ok(PKey::from_ec_key(key)?)
        }
        Traditional::Ed25519 => {
            Ok(PKey::private_key_from_raw_bytes(raw, Id::ED25519)?)
        }
        Traditional::Ed448 => {
            Ok(PKey::private_key_from_raw_bytes(raw, Id::ED448)?)
        }
    }
}

fn traditional_public(
    traditional: Traditional,
    raw: &[u8],
) -> CryptoResult<PKey<Public>> {
    match traditional {
        Traditional::Es256 | Traditional::Es384 => {
            let group =
                EcGroup::from_curve_name(traditional_curve(traditional))?;
            let half = raw.len() / 2;
            let x = BigNum::from_slice(&raw[..half])?;
            let y = BigNum::from_slice(&raw[half..])?;
            let key =
                EcKey::from_public_key_affine_coordinates(&group, &x, &y)?;
            Ok(PKey::from_ec_key(key)?)
        }
        Traditional::Ed25519 => {
            Ok(PKey::public_key_from_raw_bytes(raw, Id::ED25519)?)
        }
        Traditional::Ed448 => {
            Ok(PKey::public_key_from_raw_bytes(raw, Id::ED448)?)
        }
    }
}

fn traditional_hash(traditional: Traditional) -> Hash {
    match traditional {
        Traditional::Es384 => Hash::Sha384,
        _ => Hash::Sha256,
    }
}

fn composite_sign(
    alg: &str,
    composite: &Composite,
    private: &[u8],
    message: &[u8],
) -> CryptoResult<Vec<u8>> {
    let trad_len = composite.traditional.private_len();
    if private.len() != 32 + trad_len {
        return Err(CryptoError::new(format!(
            "a {} private key is {} bytes — a 32-byte ML-DSA seed followed by \
             a {}-byte traditional key; this one is {}.",
            alg,
            32 + trad_len,
            trad_len,
            private.len()
        )));
    }
    let m_prime = composite_message(composite, message);
    let ml_key = ml_dsa_private(composite.ml_dsa, &private[..32])?;
    // The ML-DSA half signs M' WITH THE LABEL AS ITS CONTEXT STRING.
    let mut signature = pq::sign_message(
        &ml_key,
        composite.ml_dsa,
        &m_prime,
        Some(composite.label.as_bytes()),
    )?;
    let trad = traditional_private(composite.traditional, &private[32..])?;
    signature.extend(match composite.traditional {
        Traditional::Es256 | Traditional::Es384 => ec_sign(
            &trad,
            traditional_hash(composite.traditional),
            composite.traditional.signature_len(),
            &m_prime,
        )?,
        _ => eddsa_sign(&trad, &m_prime)?,
    });
    Ok(signature)
}

fn ml_dsa_sizes(name: &str) -> (usize, usize) {
    match JwsAlg::by_name(name).map(|alg| alg.family) {
        Some(Family::MlDsa {
            public_len,
            signature_len,
            ..
        }) => (public_len, signature_len),
        _ => (0, 0),
    }
}

fn composite_verify(
    composite: &Composite,
    public: &[u8],
    message: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    let (ml_pub, ml_sig) = ml_dsa_sizes(composite.ml_dsa);
    let trad = composite.traditional;
    if signature.len() != ml_sig + trad.signature_len()
        || public.len() != ml_pub + trad.public_len()
    {
        return Ok(false);
    }
    let m_prime = composite_message(composite, message);
    let ml_key = pq::public_from_raw(composite.ml_dsa, &public[..ml_pub])?;
    let ml_ok = pq::verify_message(
        &ml_key,
        composite.ml_dsa,
        &m_prime,
        &signature[..ml_sig],
        Some(composite.label.as_bytes()),
    )?;
    let trad_key = traditional_public(trad, &public[ml_pub..])?;
    let trad_sig = &signature[ml_sig..];
    let trad_ok = match trad {
        Traditional::Es256 | Traditional::Es384 => {
            ec_verify(&trad_key, traditional_hash(trad), &m_prime, trad_sig)?
        }
        _ => eddsa_verify(&trad_key, &m_prime, trad_sig)?,
    };
    Ok(ml_ok && trad_ok)
}

fn akp_parts(key: &JwsKey) -> CryptoResult<(&[u8], Option<&[u8]>)> {
    match &key.material {
        Material::Akp {
            public, private, ..
        } => Ok((public.as_slice(), private.as_deref())),
        _ => Err(CryptoError::new(
            "a post-quantum JWS needs an AKP key (RFC 9964)",
        )),
    }
}

fn private_of(key: &JwsKey) -> CryptoResult<&PKey<Private>> {
    match &key.material {
        Material::Private(private) => Ok(private),
        _ => Err(CryptoError::new("signing needs a private key")),
    }
}

/// The signature a JWS carries over `input`, for any algorithm.
pub fn sign_input(
    alg: &str,
    key: &JwsKey,
    input: &[u8],
) -> CryptoResult<Vec<u8>> {
    let row = alg_row(alg)?;
    match row.family {
        Family::Hmac(hash) => match &key.material {
            Material::Secret(secret) => hmac(hash, secret, input),
            _ => Err(CryptoError::new("an HMAC JWS needs a shared secret")),
        },
        Family::Rsa(hash) => rsa_sign(private_of(key)?, hash, false, input),
        Family::RsaPss(hash) => rsa_sign(private_of(key)?, hash, true, input),
        Family::Ec {
            hash,
            curve,
            signature_len,
            ..
        } => {
            let private = private_of(key)?;
            if !curve_matches(private, curve) {
                return Err(CryptoError::new(format!(
                    "an {} key must be on the alg's curve",
                    alg
                )));
            }
            ec_sign(private, hash, signature_len, input)
        }
        Family::EdDsa => eddsa_sign(private_of(key)?, input),
        Family::MlDsa { name, .. } => {
            let (_, private) = akp_parts(key)?;
            let seed = private.ok_or_else(|| {
                CryptoError::new("signing needs the AKP \"priv\"")
            })?;
            let private = ml_dsa_private(name, seed)?;
            pq::sign_message(&private, name, input, None)
        }
        Family::SlhDsa { name } => {
            let (_, private) = akp_parts(key)?;
            let raw = private.ok_or_else(|| {
                CryptoError::new("signing needs the AKP \"priv\"")
            })?;
            let private = pq::private_from_raw(name, raw)?;
            pq::sign_message(&private, name, input, None)
        }
        Family::Composite(composite) => {
            let (_, private) = akp_parts(key)?;
            let raw = private.ok_or_else(|| {
                CryptoError::new("signing needs the AKP \"priv\"")
            })?;
            composite_sign(alg, &composite, raw, input)
        }
    }
}

/// Whether `signature` over `input` verifies; an error where `crypto.js`
/// throws (an ECDSA signature of the wrong length, a key that will not load
/// or may not be used, an algorithm this service does not implement).
pub fn verify_input(
    alg: &str,
    key: &JwsKey,
    input: &[u8],
    signature: &[u8],
    policy: KeyPolicy,
) -> CryptoResult<bool> {
    let row = alg_row(alg)?;
    if row.is_post_quantum() {
        let (public, _) = akp_parts(key)?;
        return match row.family {
            Family::MlDsa { name, .. } | Family::SlhDsa { name } => {
                let public = pq::public_from_raw(name, public)?;
                pq::verify_message(&public, name, input, signature, None)
            }
            Family::Composite(composite) => {
                composite_verify(&composite, public, input, signature)
            }
            _ => Ok(false),
        };
    }
    if let Some(misuse) = key.use_problem() {
        return Err(CryptoError::new(format!(
            "this JWS cannot be verified with {}.",
            misuse
        )));
    }
    if let Family::Hmac(hash) = row.family {
        let Material::Secret(secret) = &key.material else {
            return Err(CryptoError::new("an HMAC JWS needs a shared secret"));
        };
        if let Some(weak) = hmac_key_problem(secret, hash, policy) {
            return Err(CryptoError::new(format!(
                "this JWS cannot be verified with {}.",
                weak
            )));
        }
        let expected = hmac(hash, secret, input)?;
        return Ok(expected.len() == signature.len()
            && openssl::memcmp::eq(&expected, signature));
    }
    if let Family::Ec { signature_len, .. } = row.family {
        if signature.len() != signature_len {
            return Err(CryptoError::new(format!(
                "an {} signature is {} bytes — the R||S concatenation of RFC \
                 7518 section 3.4 — and this one is {}. A ~70-byte one is the \
                 DER SEQUENCE a general-purpose crypto API returns, sent \
                 without converting it.",
                alg,
                signature_len,
                signature.len()
            )));
        }
    }
    let public = key.public_key().map_err(|e| {
        CryptoError::new(format!(
            "the verification key could not be read: {}",
            e
        ))
    })?;
    match row.family {
        Family::Rsa(hash) | Family::RsaPss(hash) => {
            if let Some(weak) = rsa_key_problem(&public, 2048, policy) {
                return Err(CryptoError::new(format!(
                    "this JWS cannot be verified with {}.",
                    weak
                )));
            }
            let pss = matches!(row.family, Family::RsaPss(_));
            rsa_verify(&public, hash, pss, input, signature)
        }
        Family::Ec { hash, curve, .. } => {
            if !curve_matches(&public, curve) {
                return Ok(false);
            }
            ec_verify(&public, hash, input, signature)
        }
        Family::EdDsa => eddsa_verify(&public, input, signature),
        _ => Ok(false),
    }
}

// ---------------------------------------------------------------------------
// A fresh key for an algorithm.
// ---------------------------------------------------------------------------

fn random(length: usize) -> CryptoResult<Vec<u8>> {
    let mut bytes = vec![0u8; length];
    openssl::rand::rand_bytes(&mut bytes)?;
    Ok(bytes)
}

/// The traditional half as a composite carries it: `(private, public)`.
fn traditional_pair(
    traditional: Traditional,
) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    match traditional {
        Traditional::Es256 | Traditional::Es384 => {
            let group =
                EcGroup::from_curve_name(traditional_curve(traditional))?;
            let key = EcKey::generate(&group)?;
            let half = traditional.private_len() as i32;
            let mut context = openssl::bn::BigNumContext::new()?;
            let (mut x, mut y) = (BigNum::new()?, BigNum::new()?);
            key.public_key().affine_coordinates(
                &group,
                &mut x,
                &mut y,
                &mut context,
            )?;
            let mut public = x.to_vec_padded(half)?;
            public.extend(y.to_vec_padded(half)?);
            Ok((key.private_key().to_vec_padded(half)?, public))
        }
        Traditional::Ed25519 => {
            let key = PKey::generate_ed25519()?;
            Ok((key.raw_private_key()?, key.raw_public_key()?))
        }
        Traditional::Ed448 => {
            let key = PKey::generate_ed448()?;
            Ok((key.raw_private_key()?, key.raw_public_key()?))
        }
    }
}

/// A fresh key for `alg`: an HMAC secret of the hash's size, RSA-2048, a key
/// on the alg's curve, Ed25519 for EdDSA, and the RFC 9964 AKP layouts —
/// an ML-DSA seed, an SLH-DSA secret key, a composite's seed followed by its
/// traditional key (`pq_jose.generate()`).
pub fn generate_key(alg: &str) -> CryptoResult<JwsKey> {
    let row = alg_row(alg)?;
    let material = match row.family {
        Family::Hmac(hash) => Material::Secret(random(hash.output_len())?),
        Family::Rsa(_) | Family::RsaPss(_) => Material::Private(
            PKey::from_rsa(openssl::rsa::Rsa::generate(2048)?)?,
        ),
        Family::Ec { curve, .. } => {
            let group = EcGroup::from_curve_name(curve)?;
            Material::Private(PKey::from_ec_key(EcKey::generate(&group)?)?)
        }
        Family::EdDsa => Material::Private(PKey::generate_ed25519()?),
        Family::MlDsa { name, .. } => {
            let seed = random(32)?;
            let key = ml_dsa_private(name, &seed)?;
            Material::Akp {
                alg: Some(alg.into()),
                public: key.raw_public_key()?,
                private: Some(seed),
            }
        }
        Family::SlhDsa { name } => {
            let key = pq::generate(name)?;
            Material::Akp {
                alg: Some(alg.into()),
                public: key.raw_public_key()?,
                private: Some(key.raw_private_key()?),
            }
        }
        Family::Composite(composite) => {
            let seed = random(32)?;
            let ml = ml_dsa_private(composite.ml_dsa, &seed)?;
            let (trad_private, trad_public) =
                traditional_pair(composite.traditional)?;
            let mut public = ml.raw_public_key()?;
            public.extend(trad_public);
            let mut private = seed;
            private.extend(trad_private);
            Material::Akp {
                alg: Some(alg.into()),
                public,
                private: Some(private),
            }
        }
    };
    Ok(JwsKey::of(material))
}

// ---------------------------------------------------------------------------
// The compact serialization.
// ---------------------------------------------------------------------------

/// What a signature may vary by — `crypto.js`'s `SIGN_OPTIONS`, a whitelist
/// so a caller cannot set `alg: none` or swap the key through it.
#[derive(Debug, Clone, Default)]
pub struct SignOptions {
    /// RS256 when not given.
    pub algorithm: Option<String>,
    /// Merged into the header; `alg` and `kid` are this function's.
    pub header: Map<String, Json>,
    pub keyid: Option<String>,
    /// Seconds after `iat`.
    pub expires_in: Option<i64>,
    pub no_timestamp: bool,
    pub issuer: Option<String>,
    pub audience: Option<Json>,
    pub subject: Option<String>,
    pub jwtid: Option<String>,
    /// The clock, for `iat`; the system's when not given.
    pub now: Option<i64>,
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The protected header: `typ: JWT` unless the caller's header says
/// otherwise, the caller's members, then `alg` and `kid`, which are what was
/// actually used. A Security Event Token's `typ: secevent+jwt` reaching every
/// algorithm alike is why it is one function (`protectedHeaderFor()`).
fn header_for(alg: &str, options: &SignOptions) -> Map<String, Json> {
    let mut header = Map::new();
    header.insert("typ".into(), Json::from("JWT"));
    for (key, value) in &options.header {
        header.insert(key.clone(), value.clone());
    }
    header.insert("alg".into(), Json::from(alg));
    if let Some(kid) = &options.keyid {
        header.insert("kid".into(), Json::from(kid.as_str()));
    }
    header
}

/// Signs a JWT payload as a compact JWS: `iat` added unless asked not to,
/// then `exp`, then the claim conveniences.
pub fn sign_jws(
    payload: &Map<String, Json>,
    key: &JwsKey,
    options: &SignOptions,
) -> CryptoResult<String> {
    let alg = options.algorithm.as_deref().unwrap_or("RS256");
    alg_row(alg)?;
    let header = header_for(alg, options);
    let mut body = payload.clone();
    let now = options.now.unwrap_or_else(unix_now);
    let iat = body.get("iat").and_then(Json::as_i64).unwrap_or(now);
    if options.no_timestamp {
        body.remove("iat");
    } else if !body.contains_key("iat") {
        body.insert("iat".into(), Json::from(iat));
    }
    if let Some(seconds) = options.expires_in {
        if body.contains_key("exp") {
            return Err(CryptoError::new(
                "Bad \"options.expiresIn\" option the payload already has an \
                 \"exp\" property.",
            ));
        }
        body.insert("exp".into(), Json::from(iat + seconds));
    }
    let claims = [
        ("aud", options.audience.clone()),
        ("iss", options.issuer.clone().map(Json::from)),
        ("sub", options.subject.clone().map(Json::from)),
        ("jti", options.jwtid.clone().map(Json::from)),
    ];
    for (name, value) in claims {
        if let Some(value) = value {
            body.insert(name.into(), value);
        }
    }
    let input = format!(
        "{}.{}",
        b64::encode(Json::Object(header).to_string().as_bytes()),
        b64::encode(Json::Object(body).to_string().as_bytes())
    );
    let signature = sign_input(alg, key, input.as_bytes())?;
    Ok(format!("{}.{}", input, b64::encode(&signature)))
}

/// What a verified JWS says.
#[derive(Debug, Clone, PartialEq)]
pub struct Verified {
    pub header: Map<String, Json>,
    /// `None` for an empty payload the caller allowed (RFC 8555's
    /// POST-as-GET).
    pub claims: Option<Json>,
}

/// How a compact JWS is verified.
#[derive(Debug, Clone)]
pub struct VerifyOptions<'a> {
    /// REQUIRED: the algorithms the caller accepts.
    pub algorithms: &'a [&'a str],
    /// An empty payload is a message, for the one caller that says so.
    pub empty_payload: bool,
    pub policy: KeyPolicy,
}

/// Verifies a compact JWS somebody else signed — a DPoP proof, a client
/// assertion, a request object — and checks no claims: each profile checks
/// its own.
pub fn verify_compact(
    token: &str,
    key: &JwsKey,
    options: &VerifyOptions,
) -> CryptoResult<Verified> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(CryptoError::new(format!(
            "a compact JWS has three dot-separated parts; this has {}.",
            parts.len()
        )));
    }
    let readable = (|| {
        b64::decode_strict(parts[1], "JWS payload")?;
        let signature = b64::decode_strict(parts[2], "JWS signature")?;
        let header_bytes =
            b64::decode_strict(parts[0], "JWS protected header")?;
        let header: Map<String, Json> =
            serde_json::from_slice(&header_bytes)
                .map_err(|e| CryptoError::new(e.to_string()))?;
        Ok::<_, CryptoError>((header, signature))
    })();
    let (header, signature) = readable.map_err(|e| {
        CryptoError::new(format!(
            "the JWS protected header is not readable base64url JSON: {}",
            e
        ))
    })?;
    if options.algorithms.is_empty() {
        return Err(CryptoError::new(
            "verifyCompactJws: the caller must name the acceptable \
             algorithms. A verifier that takes them from the token is the \
             algorithm-confusion defect (RFC 8725 section 3.1).",
        ));
    }
    let alg = header.get("alg").and_then(Json::as_str).unwrap_or("");
    if !options.algorithms.contains(&alg) {
        let shown = header
            .get("alg")
            .map(|a| a.as_str().map(str::to_string).unwrap_or(a.to_string()))
            .unwrap_or_else(|| "undefined".into());
        return Err(CryptoError::new(format!(
            "this JWS is signed with \"{}\" and only {} {} accepted here.",
            shown,
            options.algorithms.join(", "),
            if options.algorithms.len() == 1 {
                "is"
            } else {
                "are"
            }
        )));
    }
    alg_row(alg)?;
    let input = format!("{}.{}", parts[0], parts[1]);
    if !verify_input(alg, key, input.as_bytes(), &signature, options.policy)? {
        return Err(CryptoError::new(format!(
            "the {} signature does not verify.",
            alg
        )));
    }
    if options.empty_payload && parts[1].is_empty() {
        return Ok(Verified {
            header,
            claims: None,
        });
    }
    let claims = b64::decode_loose(parts[1])
        .and_then(|bytes| {
            serde_json::from_slice::<Json>(&bytes)
                .map_err(|e| CryptoError::new(e.to_string()))
        })
        .map_err(|e| {
            CryptoError::new(format!(
                "the JWS payload is not readable base64url JSON: {}",
                e
            ))
        })?;
    Ok(Verified {
        header,
        claims: Some(claims),
    })
}

/// The claim checks for one of this service's own tokens.
#[derive(Debug, Clone, Default)]
pub struct ClaimChecks {
    pub issuer: Option<String>,
    /// Any one of these in `aud` is a match (RFC 7519 section 4.1.3).
    pub audience: Vec<String>,
    /// Seconds of allowance; the caller passes `oauth2.clockSkewS` unless it
    /// deliberately wants the strict reading.
    pub clock_tolerance: i64,
    pub now: Option<i64>,
}

/// Why a JWT's claims are refused: `jwt expired`, `jwt not active` and the
/// rest in `jsonwebtoken`'s words, which callers distinguish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimError {
    Expired { expired_at: i64 },
    NotActive,
    Invalid(String),
}

impl std::fmt::Display for ClaimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClaimError::Expired { .. } => f.write_str("jwt expired"),
            ClaimError::NotActive => f.write_str("jwt not active"),
            ClaimError::Invalid(message) => f.write_str(message),
        }
    }
}

/// `exp`, `nbf`, `iss` and `aud`, with the clock allowance.
pub fn check_claims(
    claims: &Json,
    checks: &ClaimChecks,
) -> Result<(), ClaimError> {
    let now = checks.now.unwrap_or_else(unix_now);
    let skew = checks.clock_tolerance;
    if let Some(exp) = claims.get("exp") {
        let exp = exp
            .as_f64()
            .ok_or_else(|| ClaimError::Invalid("invalid exp value".into()))?;
        if now as f64 > exp + skew as f64 {
            return Err(ClaimError::Expired {
                expired_at: exp as i64,
            });
        }
    }
    if let Some(nbf) = claims.get("nbf") {
        let nbf = nbf
            .as_f64()
            .ok_or_else(|| ClaimError::Invalid("invalid nbf value".into()))?;
        if ((now + skew) as f64) < nbf {
            return Err(ClaimError::NotActive);
        }
    }
    if let Some(issuer) = &checks.issuer {
        if claims.get("iss").and_then(Json::as_str) != Some(issuer.as_str()) {
            return Err(ClaimError::Invalid(format!(
                "jwt issuer invalid. expected: {}",
                issuer
            )));
        }
    }
    if !checks.audience.is_empty() {
        let held: Vec<&str> = match claims.get("aud") {
            Some(Json::Array(list)) => {
                list.iter().filter_map(Json::as_str).collect()
            }
            Some(Json::String(one)) => vec![one.as_str()],
            _ => Vec::new(),
        };
        if !checks
            .audience
            .iter()
            .any(|want| held.contains(&want.as_str()))
        {
            return Err(ClaimError::Invalid(format!(
                "jwt audience invalid. expected: {}",
                checks.audience.join(" or ")
            )));
        }
    }
    Ok(())
}

/// Why one of this service's own JWTs is refused.
#[derive(Debug, Clone, PartialEq)]
pub enum JwtError {
    Signature(CryptoError),
    Claims(ClaimError),
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtError::Signature(e) => e.fmt(f),
            JwtError::Claims(e) => e.fmt(f),
        }
    }
}

/// Verifies a JWT and checks its claims — `verifyJws()`: the one entry
/// point for "verify a JWT", for every algorithm. With no `algorithms`, the
/// token's own alg is accepted for the algorithms `jsonwebtoken` could not
/// do (EdDSA, ES256K and the post-quantum ones) and RS256 alone otherwise,
/// as the Node module does. An RSA key under 2048 bits is refused here in
/// both modes, as `jsonwebtoken` refused it.
pub fn verify_jws(
    token: &str,
    key: &JwsKey,
    algorithms: Option<&[&str]>,
    checks: &ClaimChecks,
    policy: KeyPolicy,
) -> Result<Json, JwtError> {
    let peeked_alg = token
        .split('.')
        .next()
        .and_then(|h| b64::decode_loose(h).ok())
        .and_then(|bytes| serde_json::from_slice::<Json>(&bytes).ok())
        .and_then(|h| h.get("alg").and_then(Json::as_str).map(str::to_string));
    let own_signer = peeked_alg
        .as_deref()
        .and_then(JwsAlg::by_name)
        .is_some_and(|row| {
            row.is_post_quantum()
                || row.family == Family::EdDsa
                || row.name == "ES256K"
        });
    let fallback: Vec<&str> = match (&peeked_alg, own_signer) {
        (Some(alg), true) => vec![alg.as_str()],
        _ => vec!["RS256"],
    };
    let allowed = algorithms.unwrap_or(&fallback);
    let policy = KeyPolicy {
        weak_rsa_allowed: policy.weak_rsa_allowed && own_signer,
        ..policy
    };
    let verified = verify_compact(
        token,
        key,
        &VerifyOptions {
            algorithms: allowed,
            empty_payload: false,
            policy,
        },
    )
    .map_err(JwtError::Signature)?;
    let claims = verified.claims.unwrap_or(Json::Null);
    check_claims(&claims, checks).map_err(JwtError::Claims)?;
    Ok(claims)
}

/// A JWK's EC curve name, for a caller choosing an alg from a key.
pub fn ec_alg_for_crv(crv: &str) -> Option<&'static str> {
    curve_of(crv).and_then(|nid| {
        crate::jws_alg::ALGS
            .iter()
            .find_map(|row| match row.family {
                Family::Ec { curve, .. } if curve == nid => Some(row.name),
                _ => None,
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn generated(alg: &str) -> JwsKey {
        generate_key(alg).unwrap()
    }

    #[test]
    fn every_alg_signs_and_verifies() {
        for row in crate::jws_alg::ALGS.iter() {
            let key = generated(row.name);
            let mut payload = Map::new();
            payload.insert("sub".into(), json!("alice"));
            let options = SignOptions {
                algorithm: Some(row.name.into()),
                keyid: Some("k1".into()),
                now: Some(1000),
                ..SignOptions::default()
            };
            let token = sign_jws(&payload, &key, &options).unwrap();
            let verified = verify_compact(
                &token,
                &key,
                &VerifyOptions {
                    algorithms: &[row.name],
                    empty_payload: false,
                    policy: KeyPolicy::STRICT,
                },
            )
            .unwrap_or_else(|e| panic!("{}: {}", row.name, e));
            assert_eq!(verified.header["alg"], row.name);
            assert_eq!(verified.header["kid"], "k1");
            assert_eq!(verified.claims.unwrap()["iat"], 1000);
            // One flipped bit in the signature is refused.
            let mut tampered = token.clone().into_bytes();
            let last = tampered.len() - 3;
            tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
            let tampered = String::from_utf8(tampered).unwrap();
            let refused = verify_compact(
                &tampered,
                &key,
                &VerifyOptions {
                    algorithms: &[row.name],
                    empty_payload: false,
                    policy: KeyPolicy::STRICT,
                },
            );
            assert!(refused.is_err(), "{} accepted a tampered token", row.name);
        }
    }

    #[test]
    fn the_caller_names_the_algorithms() {
        let key = generated("HS256");
        let token = sign_jws(
            &Map::new(),
            &key,
            &SignOptions {
                algorithm: Some("HS256".into()),
                ..SignOptions::default()
            },
        )
        .unwrap();
        let refused = verify_compact(
            &token,
            &key,
            &VerifyOptions {
                algorithms: &["RS256"],
                empty_payload: false,
                policy: KeyPolicy::STRICT,
            },
        );
        assert_eq!(
            refused.err().map(|e| e.0),
            Some(
                "this JWS is signed with \"HS256\" and only RS256 is \
                 accepted here."
                    .to_string()
            )
        );
        // verify_jws with no list: an HMAC token is not the default RS256.
        assert!(verify_jws(
            &token,
            &key,
            None,
            &ClaimChecks::default(),
            KeyPolicy::STRICT
        )
        .is_err());
    }

    #[test]
    fn claims() {
        let claims = json!({"exp": 100, "iss": "a", "aud": ["x", "y"]});
        let checks = ClaimChecks {
            issuer: Some("a".into()),
            audience: vec!["y".into()],
            clock_tolerance: 30,
            now: Some(120),
        };
        assert!(check_claims(&claims, &checks).is_ok());
        let late = ClaimChecks {
            now: Some(131),
            ..checks.clone()
        };
        assert_eq!(
            check_claims(&claims, &late),
            Err(ClaimError::Expired { expired_at: 100 })
        );
        let wrong = ClaimChecks {
            audience: vec!["z".into()],
            ..checks
        };
        assert!(check_claims(&claims, &wrong).is_err());
    }

    #[test]
    fn an_ecdsa_der_signature_is_refused_by_name() {
        let key = generated("ES256");
        let input = b"x.y";
        let error =
            verify_input("ES256", &key, input, &[0u8; 70], KeyPolicy::STRICT);
        assert!(error.is_err_and(|e| e.0.contains("DER SEQUENCE")));
    }

    #[test]
    fn half_hashes() {
        // The left half of SHA-256, as node's crypto computes it.
        assert_eq!(
            crate::jws_alg::id_token_half_hash(
                "jHkWEdUXMU1BwAsC4vtUsZwnNdrmBQ6fFTvZsNYtl_0",
                "RS256"
            ),
            "dnI-Ky-fHTSREBAdNyebSA"
        );
    }
}
