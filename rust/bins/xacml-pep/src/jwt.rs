// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A JWS, VERIFIED HERE AGAINST THE REALM'S JWKS (#1760, D7): an RFC 9068
//! access token on an `oauth2` route, and the ID Token the session
//! mechanism's sign-in redeems. OpenSSL, as everything else in this binary
//! that touches a key (rust/DESIGN.md section 6).
//!
//! **WHAT IS VERIFIED HERE IS NARROW ON PURPOSE**: RS256/384/512,
//! PS256/384/512 and ES256/384/512 against an RSA or EC key in the JWKS.
//! Anything else this realm can sign with (EdDSA, ML-DSA, a composite) is
//! [`Local::Unsupported`], and for an access token that is a question to
//! the service's introspection, never a guess. `none` and a key of the
//! wrong type are refusals. The decoder is STRICT base64url — no padding,
//! no character outside the alphabet — so the signed text and the decoded
//! bytes cannot be two different things (`crypto.js`'s `strictBase64url()`
//! found that hole in the service).
//!
//! Pure: no I/O. The JWKS is fetched and cached by `proxy_auth.rs`.

use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Public};
use openssl::rsa::{Padding, Rsa};
use openssl::sign::{RsaPssSaltlen, Verifier};
use serde_json::Value;

/// How far a clock may disagree, in seconds, for `exp` and `nbf`.
pub const SKEW_S: i64 = 60;

/// Strict base64url (RFC 7515 section 2): the alphabet only, no padding.
pub fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    if text.len() % 4 == 1
        || !text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    let mut standard: String = text
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    while standard.len() % 4 != 0 {
        standard.push('=');
    }
    let bytes = openssl::base64::decode_block(&standard).ok()?;
    // The one canonical encoding: re-encoding must give the text back, so
    // non-zero unused bits are refused.
    (b64url_encode(&bytes) == text).then_some(bytes)
}

pub fn b64url_encode(bytes: &[u8]) -> String {
    openssl::base64::encode_block(bytes)
        .chars()
        .filter(|c| *c != '=')
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            other => other,
        })
        .collect()
}

/// One verification key out of a JWKS.
#[derive(Clone)]
pub struct Key {
    pub kid: Option<String>,
    pub key: PKey<Public>,
    /// The EC curve, for ES*.
    pub curve: Option<Nid>,
}

fn bn(jwk: &Value, member: &str) -> Option<BigNum> {
    let bytes = b64url_decode(jwk[member].as_str()?)?;
    BigNum::from_slice(&bytes).ok()
}

fn key_of(jwk: &Value) -> Option<Key> {
    if jwk["use"].as_str() == Some("enc") {
        return None;
    }
    let kid = jwk["kid"].as_str().map(str::to_string);
    match jwk["kty"].as_str()? {
        "RSA" => {
            let rsa = Rsa::from_public_components(bn(jwk, "n")?, bn(jwk, "e")?)
                .ok()?;
            Some(Key {
                kid,
                key: PKey::from_rsa(rsa).ok()?,
                curve: None,
            })
        }
        "EC" => {
            let nid = match jwk["crv"].as_str()? {
                "P-256" => Nid::X9_62_PRIME256V1,
                "P-384" => Nid::SECP384R1,
                "P-521" => Nid::SECP521R1,
                _ => return None,
            };
            let group = EcGroup::from_curve_name(nid).ok()?;
            let (x, y) = (bn(jwk, "x")?, bn(jwk, "y")?);
            let ec = EcKey::from_public_key_affine_coordinates(&group, &x, &y)
                .ok()?;
            ec.check_key().ok()?;
            Some(Key {
                kid,
                key: PKey::from_ec_key(ec).ok()?,
                curve: Some(nid),
            })
        }
        // OKP, AKP and anything newer is not verified here; a token signed
        // by one is the service's to answer.
        _ => None,
    }
}

/// Every key this binary can verify with; the rest are left out.
pub fn parse_jwks(said: &Value) -> Vec<Key> {
    said["keys"]
        .as_array()
        .map(|keys| keys.iter().filter_map(key_of).collect())
        .unwrap_or_default()
}

/// What a local verification established.
#[derive(Debug, Clone, PartialEq)]
pub enum Local {
    /// Not a JWS at all: an opaque token.
    NotAJwt,
    /// A JWS whose `alg` this binary does not verify.
    Unsupported(String),
    /// A JWS whose key is not in the JWKS held.
    UnknownKey,
    /// Refused here: `none`, a key of the wrong type, a bad signature.
    Refused(&'static str),
    /// The signature verifies; the payload is the claims.
    Verified(Value),
}

fn digest_of(alg: &str) -> Option<MessageDigest> {
    match &alg[2..] {
        "256" => Some(MessageDigest::sha256()),
        "384" => Some(MessageDigest::sha384()),
        "512" => Some(MessageDigest::sha512()),
        _ => None,
    }
}

const SUPPORTED: [&str; 9] = [
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384",
    "ES512",
];

fn signature_valid(alg: &str, key: &Key, input: &[u8], sig: &[u8]) -> bool {
    let Some(md) = digest_of(alg) else {
        return false;
    };
    let family = &alg[..2];
    let is_rsa = key.key.id() == Id::RSA;
    let der;
    let signature: &[u8] = match family {
        "RS" | "PS" if is_rsa => sig,
        "ES" => {
            let (want, size) = match &alg[2..] {
                "256" => (Nid::X9_62_PRIME256V1, 32),
                "384" => (Nid::SECP384R1, 48),
                _ => (Nid::SECP521R1, 66),
            };
            if key.curve != Some(want) || sig.len() != size * 2 {
                return false;
            }
            let (Ok(r), Ok(s)) = (
                BigNum::from_slice(&sig[..size]),
                BigNum::from_slice(&sig[size..]),
            ) else {
                return false;
            };
            let Ok(parsed) = EcdsaSig::from_private_components(r, s) else {
                return false;
            };
            let Ok(bytes) = parsed.to_der() else {
                return false;
            };
            der = bytes;
            &der
        }
        _ => return false,
    };
    let Ok(mut verifier) = Verifier::new(md, &key.key) else {
        return false;
    };
    if family == "PS"
        && (verifier.set_rsa_padding(Padding::PKCS1_PSS).is_err()
            || verifier
                .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                .is_err()
            || verifier.set_rsa_mgf1_md(md).is_err())
    {
        return false;
    }
    verifier.verify_oneshot(signature, input).unwrap_or(false)
}

/// The header of a compact JWS, when the text is one.
pub fn header_of(token: &str) -> Option<Value> {
    let mut parts = token.split('.');
    let header = parts.next()?;
    let (Some(_), Some(_), None) = (parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let value: Value = serde_json::from_slice(&b64url_decode(header)?).ok()?;
    value["alg"].is_string().then_some(value)
}

/// Verifies a compact JWS against `keys`.
pub fn verify(token: &str, keys: &[Key]) -> Local {
    let Some(header) = header_of(token) else {
        return Local::NotAJwt;
    };
    let alg = header["alg"].as_str().unwrap_or("").to_string();
    if alg == "none" {
        return Local::Refused("an unsigned JWT (alg none)");
    }
    if !SUPPORTED.contains(&alg.as_str()) {
        return Local::Unsupported(alg);
    }
    let parts: Vec<&str> = token.split('.').collect();
    let (Some(payload), Some(signature)) =
        (b64url_decode(parts[1]), b64url_decode(parts[2]))
    else {
        return Local::Refused("a JWT segment is not base64url");
    };
    let kid = header["kid"].as_str();
    let candidates: Vec<&Key> = keys
        .iter()
        .filter(|k| match kid {
            Some(kid) => k.kid.as_deref() == Some(kid),
            None => true,
        })
        .collect();
    if candidates.is_empty() {
        return Local::UnknownKey;
    }
    let input = format!("{}.{}", parts[0], parts[1]);
    if !candidates
        .iter()
        .any(|k| signature_valid(&alg, k, input.as_bytes(), &signature))
    {
        return Local::Refused("the signature does not verify");
    }
    match serde_json::from_slice::<Value>(&payload) {
        Ok(claims) if claims.is_object() => Local::Verified(claims),
        _ => Local::Refused("the payload is not a JSON object"),
    }
}

/// `aud`, a string or an array, contains `audience`.
pub fn audience_has(aud: &Value, audience: &str) -> bool {
    match aud {
        Value::String(s) => s == audience,
        Value::Array(list) => list.iter().any(|a| a.as_str() == Some(audience)),
        _ => false,
    }
}

/// The claims every token here is held to: the issuer, the audience, and
/// the time window, `exp` required.
pub fn claims_problem(
    claims: &Value,
    issuer: &str,
    audience: &str,
    now: i64,
) -> Option<&'static str> {
    if issuer.is_empty() || claims["iss"].as_str() != Some(issuer) {
        return Some("the issuer is not the realm's");
    }
    if !audience_has(&claims["aud"], audience) {
        return Some("the audience is not this route's");
    }
    let Some(exp) = claims["exp"].as_i64() else {
        return Some("there is no exp");
    };
    if exp + SKEW_S <= now {
        return Some("it has expired");
    }
    if let Some(nbf) = claims.get("nbf") {
        match nbf.as_i64() {
            Some(nbf) if nbf - SKEW_S <= now => {}
            _ => return Some("it is not valid yet (nbf)"),
        }
    }
    None
}

/// The confirmation (RFC 8705 section 3.1, RFC 9449 section 6): none, or an
/// `x5t#S256` equal to the certificate the caller presented on THIS
/// connection. A `jkt` (DPoP) is refused by name: this ticket proves no
/// DPoP key. Any other member cannot be checked, and is refused.
pub fn confirmation_problem(
    cnf: &Value,
    presented_sha256_hex: Option<&str>,
) -> Option<(&'static str, &'static str)> {
    let Some(map) = cnf.as_object() else {
        return if cnf.is_null() {
            None
        } else {
            Some(("STS-XPEP-0073", "the cnf claim is not an object"))
        };
    };
    if map.contains_key("jkt") {
        return Some((
            "STS-XPEP-0072",
            "it is DPoP-bound (cnf.jkt), which this proxy does not prove",
        ));
    }
    for key in map.keys() {
        if key != "x5t#S256" {
            return Some((
                "STS-XPEP-0073",
                "its cnf names a key it cannot check",
            ));
        }
    }
    let Some(want) = map.get("x5t#S256").and_then(Value::as_str) else {
        return if map.is_empty() {
            None
        } else {
            Some(("STS-XPEP-0073", "its cnf.x5t#S256 is not a string"))
        };
    };
    let Some(hex) = presented_sha256_hex else {
        return Some((
            "STS-XPEP-0073",
            "it is bound to a certificate (cnf.x5t#S256) and none was \
             presented on this connection",
        ));
    };
    let bytes: Option<Vec<u8>> = (0..hex.len())
        .step_by(2)
        .map(|i| {
            hex.get(i..i + 2)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        })
        .collect();
    let presented = bytes.map(|b| b64url_encode(&b)).unwrap_or_default();
    // `memcmp::eq` panics on two lengths, so the length is compared first
    // (a thumbprint's length is public).
    let same = !presented.is_empty()
        && presented.len() == want.len()
        && openssl::memcmp::eq(presented.as_bytes(), want.as_bytes());
    if !same {
        return Some((
            "STS-XPEP-0073",
            "it is bound to a certificate (cnf.x5t#S256) other than the one \
             presented",
        ));
    }
    None
}

#[cfg(test)]
pub mod testing {
    //! Keys and tokens for the tests, made at run time.
    use super::*;
    use openssl::ec::EcKey;
    use openssl::pkey::Private;
    use openssl::sign::Signer;
    use serde_json::json;

    pub fn rsa_key() -> PKey<Private> {
        PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()
    }

    pub fn ec_key() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
    }

    pub fn jwk_of(key: &PKey<Private>, kid: &str) -> Value {
        if let Ok(rsa) = key.rsa() {
            return json!({ "kty": "RSA", "kid": kid,
                "n": b64url_encode(&rsa.n().to_vec()),
                "e": b64url_encode(&rsa.e().to_vec()) });
        }
        let ec = key.ec_key().unwrap();
        let group = ec.group();
        let mut x = BigNum::new().unwrap();
        let mut y = BigNum::new().unwrap();
        let mut ctx = openssl::bn::BigNumContext::new().unwrap();
        ec.public_key()
            .affine_coordinates(group, &mut x, &mut y, &mut ctx)
            .unwrap();
        json!({ "kty": "EC", "crv": "P-256", "kid": kid,
            "x": b64url_encode(&x.to_vec_padded(32).unwrap()),
            "y": b64url_encode(&y.to_vec_padded(32).unwrap()) })
    }

    /// A compact JWS of `claims`, signed with `alg`.
    pub fn sign(
        key: &PKey<Private>,
        alg: &str,
        kid: &str,
        claims: &Value,
    ) -> String {
        let header = json!({ "alg": alg, "kid": kid, "typ": "at+jwt" });
        let input = format!(
            "{}.{}",
            b64url_encode(header.to_string().as_bytes()),
            b64url_encode(claims.to_string().as_bytes())
        );
        let md = digest_of(alg).unwrap();
        let mut signer = Signer::new(md, key).unwrap();
        if alg.starts_with("PS") {
            signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
            signer
                .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                .unwrap();
        }
        let mut sig = signer.sign_oneshot_to_vec(input.as_bytes()).unwrap();
        if alg.starts_with("ES") {
            let parsed = EcdsaSig::from_der(&sig).unwrap();
            let mut raw = parsed.r().to_vec_padded(32).unwrap();
            raw.extend(parsed.s().to_vec_padded(32).unwrap());
            sig = raw;
        }
        format!("{}.{}", input, b64url_encode(&sig))
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use serde_json::json;

    #[test]
    fn base64url_is_strict() {
        assert_eq!(b64url_decode("aGk").unwrap(), b"hi");
        assert!(b64url_decode("aGk=").is_none(), "padding");
        assert!(b64url_decode("aG k").is_none(), "a space");
        assert!(b64url_decode("aGl").is_none(), "non-zero unused bits");
        assert!(b64url_decode("a").is_none());
        assert_eq!(b64url_encode(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn every_supported_algorithm_verifies_and_a_wrong_key_does_not() {
        let rsa = rsa_key();
        let ec = ec_key();
        let keys = parse_jwks(&json!({ "keys": [
            jwk_of(&rsa, "r1"), jwk_of(&ec, "e1"),
            { "kty": "OKP", "crv": "Ed25519", "kid": "o1", "x": "AA" },
            { "kty": "RSA", "use": "enc", "kid": "enc1",
              "n": jwk_of(&rsa, "x")["n"], "e": "AQAB" } ] }));
        assert_eq!(keys.len(), 2, "OKP and an encryption key are left out");
        let claims = json!({ "sub": "alice" });
        for alg in ["RS256", "RS384", "RS512", "PS256", "PS512"] {
            let token = sign(&rsa, alg, "r1", &claims);
            assert_eq!(verify(&token, &keys), Local::Verified(claims.clone()));
        }
        let es = sign(&ec, "ES256", "e1", &claims);
        assert_eq!(verify(&es, &keys), Local::Verified(claims.clone()));
        let other = rsa_key();
        let forged = sign(&other, "RS256", "r1", &claims);
        assert!(matches!(verify(&forged, &keys), Local::Refused(_)));
        let wrong_type = sign(&rsa, "RS256", "e1", &claims);
        assert!(matches!(verify(&wrong_type, &keys), Local::Refused(_)));
        assert_eq!(
            verify(&sign(&rsa, "RS256", "nobody", &claims), &keys),
            Local::UnknownKey
        );
        assert_eq!(verify("opaque-token", &keys), Local::NotAJwt);
        let ed = format!(
            "{}.{}.AA",
            b64url_encode(br#"{"alg":"EdDSA","kid":"o1"}"#),
            b64url_encode(b"{}")
        );
        assert_eq!(verify(&ed, &keys), Local::Unsupported("EdDSA".into()));
        let none = format!(
            "{}.{}.",
            b64url_encode(br#"{"alg":"none"}"#),
            b64url_encode(b"{}")
        );
        assert!(matches!(verify(&none, &keys), Local::Refused(_)));
        // A signature altered by one character.
        let mut tampered = sign(&rsa, "RS256", "r1", &claims);
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'A' { 'B' } else { 'A' });
        assert!(matches!(verify(&tampered, &keys), Local::Refused(_)));
    }

    #[test]
    fn claims_and_confirmation() {
        let now = 1_800_000_000;
        let ok = json!({ "iss": "https://sts/r", "aud": ["x", "api"],
                         "exp": now + 10 });
        assert_eq!(claims_problem(&ok, "https://sts/r", "api", now), None);
        let mut bad = ok.clone();
        bad["iss"] = json!("https://other");
        assert!(claims_problem(&bad, "https://sts/r", "api", now).is_some());
        assert!(claims_problem(&ok, "https://sts/r", "other", now).is_some());
        assert!(claims_problem(&ok, "", "api", now).is_some());
        let mut expired = ok.clone();
        expired["exp"] = json!(now - SKEW_S - 1);
        assert!(claims_problem(&expired, "https://sts/r", "api", now).is_some());
        let mut early = ok.clone();
        early["nbf"] = json!(now + SKEW_S + 5);
        assert!(claims_problem(&early, "https://sts/r", "api", now).is_some());
        let mut no_exp = ok.clone();
        no_exp.as_object_mut().unwrap().remove("exp");
        assert!(claims_problem(&no_exp, "https://sts/r", "api", now).is_some());

        assert_eq!(confirmation_problem(&Value::Null, None), None);
        let hex = "ab".repeat(32);
        let thumb = b64url_encode(&[0xab; 32]);
        let bound = json!({ "x5t#S256": thumb });
        assert_eq!(confirmation_problem(&bound, Some(&hex)), None);
        assert!(confirmation_problem(&bound, None).is_some());
        assert!(confirmation_problem(&bound, Some(&"cd".repeat(32))).is_some());
        assert_eq!(
            confirmation_problem(&json!({ "jkt": "x" }), Some(&hex))
                .unwrap()
                .0,
            "STS-XPEP-0072"
        );
        assert!(confirmation_problem(&json!({ "jwk": {} }), None).is_some());
    }
}
