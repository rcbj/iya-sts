// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A key a JWS is signed or verified with, read from what the service
//! actually holds: a JWK (a client's registration, a proof's own header), a
//! PEM (this service's certificate, a registered key) or a shared secret
//! (a client secret). `crypto.js`'s verifier takes all three, and so does
//! this.
//!
//! **And the keys a JWS may NOT be verified with** (#202, Wycheproof's
//! `json_web_key` vectors): an RSA public exponent below 3 or even and an RSA
//! modulus with the ROCA fingerprint are refused in EVERY mode — the first is
//! a forgery, the second factorable; an RSA modulus under 2048 bits and an
//! HMAC key shorter than its hash output are refused unless the caller's
//! [`KeyPolicy`] allows them (development, `usesBrokenAlgorithms()`); a JWK
//! whose `use` or `key_ops` say it is not for verifying is refused.

use openssl::bn::{BigNum, BigNumContext, BigNumRef};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private, Public};
use openssl::rsa::{Rsa, RsaPrivateKeyBuilder};
use openssl::x509::X509;
use serde_json::Value as Json;

use crate::b64;
use crate::error::{CryptoError, CryptoResult};

/// What the mode allows: the two size floors are refused in product and
/// accepted in development (`mode.usesBrokenAlgorithms()`), which this leaf
/// crate is told rather than asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyPolicy {
    pub weak_rsa_allowed: bool,
    pub short_hmac_allowed: bool,
}

impl KeyPolicy {
    /// Product's: neither floor relaxed.
    pub const STRICT: KeyPolicy = KeyPolicy {
        weak_rsa_allowed: false,
        short_hmac_allowed: false,
    };

    /// Development's.
    pub const LENIENT: KeyPolicy = KeyPolicy {
        weak_rsa_allowed: true,
        short_hmac_allowed: true,
    };
}

/// The key itself.
#[derive(Clone)]
pub enum Material {
    /// An HMAC key: the octets (a client_secret's UTF-8).
    Secret(Vec<u8>),
    Private(PKey<Private>),
    Public(PKey<Public>),
    /// RFC 9964 `AKP`: the raw public key and, to sign, the raw private one
    /// (an ML-DSA seed, an SLH-DSA secret key, a composite's concatenation).
    Akp {
        alg: Option<String>,
        public: Vec<u8>,
        private: Option<Vec<u8>>,
    },
}

/// A key, and what its JWK said it may be used for.
#[derive(Clone)]
pub struct JwsKey {
    pub material: Material,
    jwk_use: Option<String>,
    key_ops: Option<Vec<String>>,
}

fn member<'a>(jwk: &'a Json, name: &str) -> Option<&'a str> {
    jwk.get(name).and_then(Json::as_str)
}

fn bytes_of(jwk: &Json, name: &str) -> CryptoResult<Vec<u8>> {
    let text = member(jwk, name).ok_or_else(|| {
        CryptoError::new(format!("the JWK has no \"{}\"", name))
    })?;
    b64::decode_loose(text)
        .map_err(|e| CryptoError::new(format!("the JWK's \"{}\": {}", name, e)))
}

fn bignum(jwk: &Json, name: &str) -> CryptoResult<BigNum> {
    Ok(BigNum::from_slice(&bytes_of(jwk, name)?)?)
}

/// The curve of a JWK `crv`.
pub fn curve_of(crv: &str) -> Option<Nid> {
    match crv {
        "P-256" => Some(Nid::X9_62_PRIME256V1),
        "P-384" => Some(Nid::SECP384R1),
        "P-521" => Some(Nid::SECP521R1),
        "secp256k1" => Some(Nid::SECP256K1),
        _ => None,
    }
}

impl JwsKey {
    pub fn secret(bytes: impl Into<Vec<u8>>) -> JwsKey {
        JwsKey::of(Material::Secret(bytes.into()))
    }

    pub fn of(material: Material) -> JwsKey {
        JwsKey {
            material,
            jwk_use: None,
            key_ops: None,
        }
    }

    /// A JWK of any type this service reads: RSA, EC, OKP, oct and AKP.
    pub fn from_jwk(jwk: &Json) -> CryptoResult<JwsKey> {
        let material = match member(jwk, "kty") {
            Some("RSA") => JwsKey::rsa_from_jwk(jwk)?,
            Some("EC") => JwsKey::ec_from_jwk(jwk)?,
            Some("OKP") => JwsKey::okp_from_jwk(jwk)?,
            Some("oct") => Material::Secret(bytes_of(jwk, "k")?),
            Some("AKP") => Material::Akp {
                alg: member(jwk, "alg").map(str::to_string),
                public: bytes_of(jwk, "pub")?,
                private: match member(jwk, "priv") {
                    Some(_) => Some(bytes_of(jwk, "priv")?),
                    None => None,
                },
            },
            Some(other) => {
                return Err(CryptoError::new(format!(
                    "a JWK of kty \"{}\" is not one this service reads",
                    other
                )))
            }
            None => return Err(CryptoError::new("the JWK has no \"kty\"")),
        };
        Ok(JwsKey {
            material,
            jwk_use: member(jwk, "use").map(str::to_string),
            key_ops: jwk.get("key_ops").and_then(Json::as_array).map(|ops| {
                ops.iter()
                    .filter_map(Json::as_str)
                    .map(str::to_string)
                    .collect()
            }),
        })
    }

    fn rsa_from_jwk(jwk: &Json) -> CryptoResult<Material> {
        let (n, e) = (bignum(jwk, "n")?, bignum(jwk, "e")?);
        if jwk.get("d").is_none() {
            let rsa = Rsa::from_public_components(n, e)?;
            return Ok(Material::Public(PKey::from_rsa(rsa)?));
        }
        let mut builder = RsaPrivateKeyBuilder::new(n, e, bignum(jwk, "d")?)?;
        if jwk.get("p").is_some() && jwk.get("q").is_some() {
            builder =
                builder.set_factors(bignum(jwk, "p")?, bignum(jwk, "q")?)?;
        }
        if jwk.get("dp").is_some() {
            builder = builder.set_crt_params(
                bignum(jwk, "dp")?,
                bignum(jwk, "dq")?,
                bignum(jwk, "qi")?,
            )?;
        }
        Ok(Material::Private(PKey::from_rsa(builder.build())?))
    }

    fn ec_from_jwk(jwk: &Json) -> CryptoResult<Material> {
        let crv = member(jwk, "crv").unwrap_or("");
        let nid = curve_of(crv).ok_or_else(|| {
            CryptoError::new(format!("an EC JWK on curve \"{}\"", crv))
        })?;
        let group = EcGroup::from_curve_name(nid)?;
        let (x, y) = (bignum(jwk, "x")?, bignum(jwk, "y")?);
        let public = EcKey::from_public_key_affine_coordinates(&group, &x, &y)?;
        public.check_key()?;
        if jwk.get("d").is_none() {
            return Ok(Material::Public(PKey::from_ec_key(public)?));
        }
        let d = bignum(jwk, "d")?;
        let private =
            EcKey::from_private_components(&group, &d, public.public_key())?;
        private.check_key()?;
        Ok(Material::Private(PKey::from_ec_key(private)?))
    }

    fn okp_from_jwk(jwk: &Json) -> CryptoResult<Material> {
        let id = match member(jwk, "crv") {
            Some("Ed25519") => Id::ED25519,
            Some("Ed448") => Id::ED448,
            other => {
                return Err(CryptoError::new(format!(
                    "an OKP JWK on curve {:?} cannot sign",
                    other
                )))
            }
        };
        if jwk.get("d").is_some() {
            return Ok(Material::Private(PKey::private_key_from_raw_bytes(
                &bytes_of(jwk, "d")?,
                id,
            )?));
        }
        Ok(Material::Public(PKey::public_key_from_raw_bytes(
            &bytes_of(jwk, "x")?,
            id,
        )?))
    }

    /// A PEM: a private key, a public key, or a certificate whose key is
    /// meant.
    pub fn from_pem(pem: &str) -> CryptoResult<JwsKey> {
        let bytes = pem.as_bytes();
        if pem.contains("PRIVATE KEY") {
            return Ok(JwsKey::of(Material::Private(
                PKey::private_key_from_pem(bytes)?,
            )));
        }
        if pem.contains("CERTIFICATE") {
            let certificate = X509::from_pem(bytes)?;
            return Ok(JwsKey::of(Material::Public(certificate.public_key()?)));
        }
        Ok(JwsKey::of(Material::Public(PKey::public_key_from_pem(
            bytes,
        )?)))
    }

    /// Why a JWK says it is not for verifying signatures (RFC 7517 sections
    /// 4.2 and 4.3), or `None`.
    pub fn use_problem(&self) -> Option<String> {
        if let Some(used) = &self.jwk_use {
            if used != "sig" {
                return Some(format!(
                    "a JWK whose \"use\" is \"{}\" (RFC 7517 section 4.2)",
                    used
                ));
            }
        }
        if let Some(ops) = &self.key_ops {
            if !ops.iter().any(|op| op == "verify") {
                return Some(
                    "a JWK whose \"key_ops\" do not include \"verify\" (RFC \
                     7517 section 4.3)"
                        .to_string(),
                );
            }
        }
        None
    }

    /// The PUBLIC JWK of this key — what a JWKS publishes — or `None` for a
    /// shared secret, which is never published.
    pub fn public_jwk(&self) -> CryptoResult<Option<Json>> {
        let b64 = |bytes: &[u8]| Json::from(b64::encode(bytes));
        let public = match &self.material {
            Material::Secret(_) => return Ok(None),
            Material::Akp { alg, public, .. } => {
                let mut jwk = serde_json::Map::new();
                jwk.insert("kty".into(), Json::from("AKP"));
                if let Some(alg) = alg {
                    jwk.insert("alg".into(), Json::from(alg.as_str()));
                }
                jwk.insert("pub".into(), b64(public));
                return Ok(Some(Json::Object(jwk)));
            }
            _ => self.public_key()?,
        };
        if let Ok(rsa) = public.rsa() {
            return Ok(Some(serde_json::json!({
                "kty": "RSA",
                "n": b64(&rsa.n().to_vec()),
                "e": b64(&rsa.e().to_vec()),
            })));
        }
        if let Ok(ec) = public.ec_key() {
            let group = ec.group();
            let crv = match group.curve_name() {
                Some(Nid::X9_62_PRIME256V1) => "P-256",
                Some(Nid::SECP384R1) => "P-384",
                Some(Nid::SECP521R1) => "P-521",
                Some(Nid::SECP256K1) => "secp256k1",
                _ => {
                    return Err(CryptoError::new("an EC key on no JOSE curve"))
                }
            };
            let size = (group.degree() as i32 + 7) / 8;
            let mut context = BigNumContext::new()?;
            let (mut x, mut y) = (BigNum::new()?, BigNum::new()?);
            ec.public_key().affine_coordinates(
                group,
                &mut x,
                &mut y,
                &mut context,
            )?;
            return Ok(Some(serde_json::json!({
                "kty": "EC",
                "crv": crv,
                "x": b64(&x.to_vec_padded(size)?),
                "y": b64(&y.to_vec_padded(size)?),
            })));
        }
        let crv = match public.id() {
            Id::ED25519 => "Ed25519",
            Id::ED448 => "Ed448",
            _ => return Err(CryptoError::new("a key with no JWK form")),
        };
        Ok(Some(serde_json::json!({
            "kty": "OKP",
            "crv": crv,
            "x": b64(&public.raw_public_key()?),
        })))
    }

    /// The public half, for verifying.
    pub fn public_key(&self) -> CryptoResult<PKey<Public>> {
        match &self.material {
            Material::Public(key) => Ok(key.clone()),
            Material::Private(key) => {
                Ok(PKey::public_key_from_der(&key.public_key_to_der()?)?)
            }
            _ => Err(CryptoError::new(
                "this key has no public half an asymmetric JWS uses",
            )),
        }
    }
}

/// The primes and subgroups of the ROCA test (CVE-2017-15361): a modulus
/// whose residue modulo every one of these lies in the subgroup 65537
/// generates was made by Infineon's RSALib, and is factorable.
const ROCA_PRIMES: [u32; 38] = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167,
];

fn in_roca_subgroup(residue: u64, p: u32) -> bool {
    let p = u64::from(p);
    let g = 65537 % p;
    let mut x = 1u64;
    loop {
        if x == residue {
            return true;
        }
        x = (x * g) % p;
        if x == 1 {
            return false;
        }
    }
}

fn has_roca_fingerprint(n: &BigNumRef) -> bool {
    ROCA_PRIMES.iter().all(|&p| {
        n.mod_word(p)
            .map(|residue| in_roca_subgroup(residue, p))
            .unwrap_or(false)
    })
}

/// Why an RSA public key may not verify a JWS, or `None`. `minimum_bits`:
/// RFC 7518 section 3.3's 2048, relaxed where the policy allows.
pub fn rsa_key_problem(
    key: &PKey<Public>,
    minimum_bits: u32,
    policy: KeyPolicy,
) -> Option<String> {
    let rsa = key.rsa().ok()?;
    let e = rsa.e();
    let three = BigNum::from_u32(3).ok()?;
    if e < &three || !e.is_bit_set(0) {
        let shown = e.to_dec_str().map(|s| s.to_string()).unwrap_or_default();
        return Some(format!(
            "an RSA public exponent of {} (RFC 8017 section 3.1 requires an \
             odd e of at least 3)",
            shown
        ));
    }
    if has_roca_fingerprint(rsa.n()) {
        return Some(
            "an RSA modulus with the ROCA fingerprint (CVE-2017-15361), \
             which is factorable"
                .to_string(),
        );
    }
    let bits = rsa.n().num_bits().max(0) as u32;
    if bits < minimum_bits && !policy.weak_rsa_allowed {
        return Some(format!(
            "a {}-bit RSA key, where {} bits or more MUST be used (RFC 7518 \
             section 3.3, RFC 8230 section 5)",
            bits, minimum_bits
        ));
    }
    None
}

/// Why an HMAC key may not be used with a hash, or `None`: an empty key in
/// every mode, one shorter than the hash output where the policy says.
pub fn hmac_key_problem(
    key: &[u8],
    hash: crate::jws_alg::Hash,
    policy: KeyPolicy,
) -> Option<String> {
    if key.is_empty() {
        return Some("an empty HMAC key".to_string());
    }
    let need = hash.output_len();
    if key.len() < need && !policy.short_hmac_allowed {
        return Some(format!(
            "a {}-bit HMAC key for {}, where a key of the hash output's size \
             ({} bits) or larger MUST be used (RFC 7518 section 3.2)",
            key.len() * 8,
            hash.name(),
            need * 8
        ));
    }
    None
}

/// The public point of a private EC scalar, for a composite's key.
pub fn ec_point_of(
    group: &openssl::ec::EcGroupRef,
    scalar: &BigNumRef,
) -> CryptoResult<EcPoint> {
    let mut context = BigNumContext::new()?;
    let mut point = EcPoint::new(group)?;
    point.mul_generator2(group, scalar, &mut context)?;
    Ok(point)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn roca_and_exponents() {
        let weak = Rsa::from_public_components(
            BigNum::from_dec_str("3233").unwrap(),
            BigNum::from_u32(1).unwrap(),
        )
        .unwrap();
        let key = PKey::from_rsa(weak).unwrap();
        let problem = rsa_key_problem(&key, 2048, KeyPolicy::LENIENT);
        assert!(problem.is_some_and(|p| p.contains("exponent of 1")));
        let good = Rsa::generate(2048).unwrap();
        let public = PKey::public_key_from_der(
            &PKey::from_rsa(good).unwrap().public_key_to_der().unwrap(),
        )
        .unwrap();
        assert!(rsa_key_problem(&public, 2048, KeyPolicy::STRICT).is_none());
        let small = Rsa::generate(1024).unwrap();
        let small = PKey::public_key_from_der(
            &PKey::from_rsa(small).unwrap().public_key_to_der().unwrap(),
        )
        .unwrap();
        assert!(rsa_key_problem(&small, 2048, KeyPolicy::STRICT).is_some());
        assert!(rsa_key_problem(&small, 2048, KeyPolicy::LENIENT).is_none());
    }

    #[test]
    fn the_subgroup_test() {
        // 65537 mod 3 is 2, which generates {1, 2}; 0 is in no subgroup.
        assert!(in_roca_subgroup(1, 3) && in_roca_subgroup(2, 3));
        assert!(!in_roca_subgroup(0, 3));
    }

    #[test]
    fn jwk_use() {
        let enc =
            JwsKey::from_jwk(&json!({"kty":"oct","k":"AAAA","use":"enc"}))
                .unwrap();
        assert!(enc.use_problem().is_some());
        let ops = JwsKey::from_jwk(
            &json!({"kty":"oct","k":"AAAA","key_ops":["sign"]}),
        )
        .unwrap();
        assert!(ops.use_problem().is_some());
        let fine = JwsKey::from_jwk(&json!({"kty":"oct","k":"AAAA"})).unwrap();
        assert!(fine.use_problem().is_none());
    }
}
