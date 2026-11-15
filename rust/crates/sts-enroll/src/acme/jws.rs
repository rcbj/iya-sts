// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE ACME ENVELOPE, READ STRICTLY (`acme/acme_jws.ts`, RFC 8555 section
//! 6): the media type, the flattened JWS, strict base64url, the protected
//! header, account keys and their RFC 7638 thumbprint, the signature, the
//! Replay-Nonce, the External Account Binding, the payload shapes (the
//! model's), contacts and RFC 9773's certificate identifier. A library
//! holding no state; every parse answers a refusal rather than failing.
//!
//! **THE REPLAY-NONCE CARRIES ITS OWN PROOF**: `version | expiry | 16
//! random bytes | MAC(realm, expiry, random)`, so any process can check it
//! with no lookup; single use is the store's ([`super::store`]). The
//! secret is the `acme-nonce` cluster secret, which reaches this process
//! as `STS_ACME_NONCE_SECRET` (an operator sets it on every node, or the
//! runtime's cluster secrets put it there) and is otherwise made for the
//! run: a nonce from before a restart fails its MAC and is answered
//! `badNonce` with a fresh one, which a client retries (section 6.5).

use std::sync::LazyLock;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value as Json};
use sts_core::errors::{codes, ErrorCode};
use sts_crypto::jws::VerifyOptions;
use sts_crypto::keys::{JwsKey, KeyPolicy};

use crate::model::{self, Body, Issue};

/// The media type every POST body is (section 6.2).
pub const MEDIA_TYPE: &str = "application/jose+json";
/// The prefix of every error type (section 6.7).
pub const ERROR_PREFIX: &str = "urn:ietf:params:acme:error:";
/// The smallest RSA account key.
pub const MIN_RSA_BITS: usize = 2048;

const REFUSED_HEADER_MEMBERS: &[&str] = &["crit", "b64", "jku", "x5u", "x5c"];
const PRIVATE_JWK_MEMBERS: &[&str] =
    &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
const NONCE_VERSION: u8 = 1;
/// Where the Replay-Nonce secret reaches a process.
pub const NONCE_SECRET_VAR: &str = "STS_ACME_NONCE_SECRET";

static NONCE_SECRET: LazyLock<String> = LazyLock::new(|| {
    if let Ok(text) = std::env::var(NONCE_SECRET_VAR) {
        if !text.is_empty() {
            return text;
        }
    }
    let random = sts_crypto::random::random_bytes(32).unwrap_or_default();
    base64::engine::general_purpose::STANDARD.encode(random)
});

/// An ACME refusal: the error type (without its prefix), the status, the
/// code and the problem's detail, and `algorithms` or `subproblems`.
#[derive(Debug, Clone, PartialEq)]
pub struct AcmeRefusal {
    pub kind: String,
    pub status: u16,
    pub code: ErrorCode,
    pub detail: String,
    /// The problem document's own members (`algorithms`), boxed so a
    /// `Result` carrying a refusal stays small.
    pub extra: Box<Json>,
}

/// `refusal(type, status, code, detail, extra)`.
#[tracing::instrument(level = "trace")]
pub fn refusal(
    kind: &str,
    status: u16,
    code: ErrorCode,
    detail: impl Into<String> + std::fmt::Debug,
) -> AcmeRefusal {
    AcmeRefusal {
        kind: kind.to_string(),
        status,
        code,
        detail: detail.into(),
        extra: Box::new(json!({})),
    }
}

/// `zodSentence(error, what)`.
#[tracing::instrument(level = "trace")]
pub fn zod_sentence(issue: &Issue, what: &str) -> String {
    let at = if issue.path.is_empty() {
        what.to_string()
    } else {
        issue.path.join(".")
    };
    let message: String = issue
        .message
        .encode_utf16()
        .take(200)
        .collect::<Vec<u16>>()
        .iter()
        .map(|&u| char::from_u32(u as u32).unwrap_or('\u{fffd}'))
        .collect();
    format!(
        "the {} member \"{}\" is not acceptable: {}.",
        what, at, message
    )
}

/// `isJoseJson(contentType)`.
#[tracing::instrument(level = "trace")]
pub fn is_jose_json(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_lowercase()
        == MEDIA_TYPE
}

/// `decodeB64url(text, allowEmpty)`: the URL-safe alphabet, no padding,
/// and bytes that encode back to exactly what was sent.
#[tracing::instrument(level = "trace", skip(text))]
pub fn decode_b64url(text: &str, allow_empty: bool) -> Option<Vec<u8>> {
    if text.is_empty() {
        return allow_empty.then(Vec::new);
    }
    if !text
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        || text.len() % 4 == 1
    {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .or_else(|_| {
            base64::engine::GeneralPurpose::new(
                &base64::alphabet::URL_SAFE,
                base64::engine::GeneralPurposeConfig::new()
                    .with_encode_padding(false)
                    .with_decode_padding_mode(
                        base64::engine::DecodePaddingMode::Indifferent,
                    )
                    .with_decode_allow_trailing_bits(true),
            )
            .decode(text)
        })
        .ok()?;
    (URL_SAFE_NO_PAD.encode(&bytes) == text).then_some(bytes)
}

/// `b64u(bytes)`.
// A hot path: every identifier and nonce; no span.
pub fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// `validation.checkDocument(value, what, { maxDepth, maxKeys })`.
fn check_document(
    value: &Json,
    what: &str,
    max_depth: usize,
    max_keys: usize,
) -> Result<(), String> {
    const POLLUTING: &[&str] = &["__proto__", "constructor", "prototype"];
    fn walk(
        node: &Json,
        depth: usize,
        path: &str,
        what: &str,
        max_depth: usize,
        max_keys: usize,
        keys: &mut usize,
    ) -> Result<(), String> {
        if depth > max_depth {
            return Err(format!(
                "the {} is nested more than {} levels deep. Nothing this service accepts is, \
                 and what reads it next would recurse as far as the document says.",
                what, max_depth
            ));
        }
        match node {
            Json::Array(a) => {
                for v in a {
                    walk(v, depth + 1, path, what, max_depth, max_keys, keys)?;
                }
                Ok(())
            }
            Json::Object(o) => {
                for (name, v) in o {
                    *keys += 1;
                    if *keys > max_keys {
                        return Err(format!(
                            "the {} carries more than {} members.",
                            what, max_keys
                        ));
                    }
                    if POLLUTING.contains(&name.as_str()) {
                        return Err(format!(
                            "the {} carries a member named \"{}\"{}. It is a property of every \
                             object in javascript, and a document that sets it is not \
                             describing anything this service offers.",
                            what,
                            name,
                            if path.is_empty() { String::new() } else { format!(" under \"{}\"", path) }
                        ));
                    }
                    let next = if path.is_empty() {
                        name.clone()
                    } else {
                        format!("{}.{}", path, name)
                    };
                    walk(v, depth + 1, &next, what, max_depth, max_keys, keys)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    let mut keys = 0;
    walk(value, 0, "", what, max_depth, max_keys, &mut keys)
}

/// `readJsonObject(bytes, what)`.
#[tracing::instrument(level = "trace", skip(bytes))]
pub fn read_json_object(bytes: &[u8], what: &str) -> Result<Json, String> {
    let text = String::from_utf8_lossy(bytes);
    let value: Json = serde_json::from_str(&text)
        .map_err(|_| format!("the {} is not JSON.", what))?;
    if !value.is_object() {
        return Err(format!("the {} is not a JSON object.", what));
    }
    check_document(&value, what, 8, 1024)?;
    Ok(value)
}

/// What `parseFlattenedObject()` answers.
#[derive(Debug, Clone, Default)]
pub struct Parts {
    pub protected_b64: String,
    pub payload_b64: String,
    pub signature_b64: String,
    pub header_bytes: Vec<u8>,
    pub payload_bytes: Vec<u8>,
}

fn body(id: &str) -> Body {
    Body::of("acme", id).unwrap_or_else(|| {
        tracing::error!("acme: the enrollment model has no body acme/{}", id);
        Body::of("acme", "challenge-response").unwrap_or_else(unreachable_body)
    })
}

#[allow(clippy::panic)] // the generated model is compiled in; its absence is a broken build
fn unreachable_body() -> Body {
    panic!("the enrollment model is missing")
}

/// `parseFlattenedObject(value, what)`.
#[tracing::instrument(level = "debug", skip(value))]
pub fn parse_flattened_object(
    value: &Json,
    what: &str,
) -> Result<Parts, AcmeRefusal> {
    if !value.is_object() {
        return Err(refusal(
            "malformed",
            400,
            codes::STS_ACME_0012,
            format!("The {} is not a flattened JWS JSON object (RFC 7515 section 7.2.2).", what),
        ));
    }
    if let Err(why) = check_document(value, what, 4, 16) {
        return Err(refusal(
            "malformed",
            400,
            codes::STS_ACME_0012,
            format!("The {} was refused: {}", what, why),
        ));
    }
    let checked = body("flattened").check(value).map_err(|issue| {
        refusal(
            "malformed",
            400,
            codes::STS_ACME_0012,
            format!(
                "The {} must carry exactly \"protected\", \"payload\" and \"signature\" (RFC 8555 \
                 section 6.2 allows no unprotected header): {}",
                what,
                zod_sentence(&issue, what)
            ),
        )
    })?;
    let text = |k: &str| {
        checked
            .get(k)
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_string()
    };
    let (p, l, s) = (text("protected"), text("payload"), text("signature"));
    let (Some(header), Some(payload), Some(_sig)) = (
        decode_b64url(&p, false),
        decode_b64url(&l, true),
        decode_b64url(&s, false),
    ) else {
        return Err(refusal(
            "malformed",
            400,
            codes::STS_ACME_0013,
            format!(
                "A member of the {} is not strict base64url: the URL-safe alphabet, no padding \
                 and no whitespace (RFC 7515 section 2).",
                what
            ),
        ));
    };
    Ok(Parts {
        protected_b64: p,
        payload_b64: l,
        signature_b64: s,
        header_bytes: header,
        payload_bytes: payload,
    })
}

/// `parseBody(text)`.
#[tracing::instrument(level = "debug", skip(text))]
pub fn parse_body(text: &str) -> Result<Parts, AcmeRefusal> {
    let value =
        read_json_object(text.as_bytes(), "request body").map_err(|why| {
            refusal(
                "malformed",
                400,
                codes::STS_ACME_0012,
                format!(
                    "The request body is not a flattened JWS JSON object: {}",
                    why
                ),
            )
        })?;
    parse_flattened_object(&value, "request body")
}

/// `parseProtectedHeader(parts)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn parse_protected_header(parts: &Parts) -> Result<Json, AcmeRefusal> {
    let value = read_json_object(&parts.header_bytes, "protected header")
        .map_err(|why| {
            refusal(
                "malformed",
                400,
                codes::STS_ACME_0014,
                format!("The JWS protected header is unreadable: {}", why),
            )
        })?;
    if let Some(name) = REFUSED_HEADER_MEMBERS
        .iter()
        .find(|n| value.get(**n).is_some())
    {
        return Err(refusal(
            "malformed",
            400,
            codes::STS_ACME_0014,
            format!(
                "The protected header carries \"{}\". An ACME request names its key with \"jwk\" \
                 or \"kid\" and nothing else (RFC 8555 section 6.2), and this server understands \
                 no critical extension.",
                name
            ),
        ));
    }
    body("protected-header").check(&value).map_err(|issue| {
        refusal(
            "malformed",
            400,
            codes::STS_ACME_0014,
            format!(
                "The JWS protected header is not acceptable: {}",
                zod_sentence(&issue, "protected header")
            ),
        )
    })
}

/// The account algorithms, in the order `badSignatureAlgorithm` lists.
#[tracing::instrument(level = "trace")]
pub fn account_algs() -> Vec<String> {
    model::names("acme", "account-algorithms")
}

/// The EAB MACs.
#[tracing::instrument(level = "trace")]
pub fn eab_algs() -> Vec<String> {
    model::names("acme", "eab-algorithms")
}

/// `checkAlgorithm(alg)`.
#[tracing::instrument(level = "debug")]
pub fn check_algorithm(alg: &str) -> Result<(), AcmeRefusal> {
    let algs = account_algs();
    if algs.iter().any(|a| a == alg) {
        return Ok(());
    }
    let shown: String = alg.chars().take(32).collect();
    let mut r = refusal(
        "badSignatureAlgorithm",
        400,
        codes::STS_ACME_0015,
        format!(
            "The JWS is signed with \"{}\", which this server does not accept for an account \
             key. It accepts {}.",
            shown,
            algs.join(", ")
        ),
    );
    r.extra = Box::new(json!({ "algorithms": algs }));
    Ok(()).and(Err(r))
}

fn ec_curve_for(alg: &str) -> Option<&'static str> {
    match alg {
        "ES256" => Some("P-256"),
        "ES384" => Some("P-384"),
        "ES512" => Some("P-521"),
        _ => None,
    }
}

fn rsa_or_pss(alg: &str) -> bool {
    alg.len() == 5
        && (alg.starts_with("RS") || alg.starts_with("PS"))
        && alg[2..].chars().all(|c| c.is_ascii_digit())
}

/// RFC 7638's thumbprint of a public JWK.
#[tracing::instrument(level = "trace", skip_all)]
pub fn jwk_thumbprint(jwk: &Json) -> Option<String> {
    let s = |k: &str| jwk.get(k).and_then(Json::as_str).map(str::to_string);
    let canonical = match s("kty")?.as_str() {
        "RSA" => format!(
            "{{\"e\":{},\"kty\":\"RSA\",\"n\":{}}}",
            Json::from(s("e")?),
            Json::from(s("n")?)
        ),
        "EC" => format!(
            "{{\"crv\":{},\"kty\":\"EC\",\"x\":{},\"y\":{}}}",
            Json::from(s("crv")?),
            Json::from(s("x")?),
            Json::from(s("y")?)
        ),
        "OKP" => format!(
            "{{\"crv\":{},\"kty\":\"OKP\",\"x\":{}}}",
            Json::from(s("crv")?),
            Json::from(s("x")?)
        ),
        "oct" => format!("{{\"k\":{},\"kty\":\"oct\"}}", Json::from(s("k")?)),
        _ => return None,
    };
    Some(b64u(
        &sts_crypto::jws_alg::Hash::Sha256.digest(canonical.as_bytes()),
    ))
}

/// `checkAccountKey(jwk, alg)`'s answer.
#[derive(Debug, Clone)]
pub struct AccountKey {
    pub jwk: Json,
    pub thumbprint: String,
}

/// `checkAccountKey(jwk, alg)`.
#[tracing::instrument(level = "debug", skip(jwk))]
pub fn check_account_key(
    jwk: &Json,
    alg: &str,
) -> Result<AccountKey, AcmeRefusal> {
    if !jwk.is_object() {
        return Err(refusal(
            "malformed",
            400,
            codes::STS_ACME_0021,
            "The \"jwk\" header is not a JSON Web Key.",
        ));
    }
    if let Some(m) = PRIVATE_JWK_MEMBERS.iter().find(|m| jwk.get(**m).is_some())
    {
        return Err(refusal(
            "badPublicKey",
            400,
            codes::STS_ACME_0021,
            format!(
                "The \"jwk\" header carries the private member \"{}\". An account key is sent as \
                 its PUBLIC half only.",
                m
            ),
        ));
    }
    let string_ok = |k: &str| {
        jwk.get(k).and_then(Json::as_str).is_some_and(|v| {
            !v.is_empty()
                && v.encode_utf16().count() <= 4096
                && decode_b64url(v, false).is_some()
        })
    };
    let text = |k: &str| jwk.get(k).cloned().unwrap_or(Json::Null);
    let kty = jwk.get("kty").and_then(Json::as_str).unwrap_or("");
    let crv = jwk.get("crv").and_then(Json::as_str).unwrap_or("");
    let public = if kty == "RSA"
        && rsa_or_pss(alg)
        && string_ok("n")
        && string_ok("e")
    {
        Some(json!({ "kty": "RSA", "n": text("n"), "e": text("e") }))
    } else if kty == "EC"
        && ec_curve_for(alg).is_some_and(|c| c == crv)
        && string_ok("x")
        && string_ok("y")
    {
        Some(json!({ "kty": "EC", "crv": crv, "x": text("x"), "y": text("y") }))
    } else if kty == "OKP"
        && alg == "EdDSA"
        && crv == "Ed25519"
        && string_ok("x")
    {
        Some(json!({ "kty": "OKP", "crv": "Ed25519", "x": text("x") }))
    } else {
        None
    };
    let Some(public) = public else {
        let shown: String = alg.chars().take(32).collect();
        return Err(refusal(
            "badPublicKey",
            400,
            codes::STS_ACME_0021,
            format!(
                "The \"jwk\" header is not a {} public key: an RS or PS algorithm takes an RSA \
                 key, ES256/ES384/ES512 an EC key on P-256/P-384/P-521, and EdDSA an Ed25519 key.",
                shown
            ),
        ));
    };
    let Some(spki) = spki_of_jwk(&public) else {
        return Err(refusal(
            "badPublicKey",
            400,
            codes::STS_ACME_0021,
            "The \"jwk\" header does not describe a usable public key.",
        ));
    };
    if kty == "RSA" {
        let bits = match sts_pki::x509::keys::describe_spki(&spki) {
            Some(sts_pki::x509::keys::KeyDesc::Rsa { bits }) => bits,
            _ => 0,
        };
        if bits < MIN_RSA_BITS {
            return Err(refusal(
                "badPublicKey",
                400,
                codes::STS_ACME_0021,
                format!(
                    "The RSA account key is {} bits; this server requires at least {}.",
                    bits, MIN_RSA_BITS
                ),
            ));
        }
    }
    let Some(thumbprint) = jwk_thumbprint(&public) else {
        return Err(refusal(
            "badPublicKey",
            400,
            codes::STS_ACME_0021,
            "No RFC 7638 thumbprint can be taken of the \"jwk\" header.",
        ));
    };
    Ok(AccountKey {
        jwk: public,
        thumbprint,
    })
}

/// `algorithmFitsKey(alg, jwk)`.
#[tracing::instrument(level = "trace", skip(jwk))]
pub fn algorithm_fits_key(alg: &str, jwk: &Json) -> bool {
    match jwk.get("kty").and_then(Json::as_str).unwrap_or("") {
        "RSA" => rsa_or_pss(alg),
        "EC" => ec_curve_for(alg)
            .is_some_and(|c| Some(c) == jwk.get("crv").and_then(Json::as_str)),
        "OKP" => alg == "EdDSA",
        _ => false,
    }
}

fn policy() -> KeyPolicy {
    KeyPolicy::LENIENT
}

/// `verifyFlattened(parts, key, alg)`: the compact form, verified with
/// the one algorithm the header named; an empty payload verifies.
#[tracing::instrument(level = "debug", skip_all)]
pub fn verify_flattened(
    parts: &Parts,
    jwk: &Json,
    alg: &str,
) -> Result<(), AcmeRefusal> {
    let compact = format!(
        "{}.{}.{}",
        parts.protected_b64, parts.payload_b64, parts.signature_b64
    );
    let ok = JwsKey::from_jwk(jwk).ok().is_some_and(|key| {
        sts_crypto::jws::verify_compact(
            &compact,
            &key,
            &VerifyOptions {
                algorithms: &[alg],
                empty_payload: true,
                policy: policy(),
            },
        )
        .is_ok()
    });
    if ok {
        Ok(())
    } else {
        Err(refusal(
            "malformed",
            400,
            codes::STS_ACME_0024,
            "The JWS signature does not verify with the account key.",
        ))
    }
}

/// `readPayload(parts)`: `None` for POST-as-GET.
#[tracing::instrument(level = "debug", skip_all)]
pub fn read_payload(parts: &Parts) -> Result<Option<Json>, AcmeRefusal> {
    if parts.payload_b64.is_empty() {
        return Ok(None);
    }
    read_json_object(&parts.payload_bytes, "payload")
        .map(Some)
        .map_err(|why| {
            refusal(
                "malformed",
                400,
                codes::STS_ACME_0025,
                format!("The JWS payload is unreadable: {}", why),
            )
        })
}

/// `checkPayload(value, schema, what)`.
#[tracing::instrument(level = "debug", skip(value))]
pub fn check_payload(
    value: &Json,
    id: &str,
    what: &str,
) -> Result<Json, AcmeRefusal> {
    body(id).check(value).map_err(|issue| {
        refusal(
            "malformed",
            400,
            codes::STS_ACME_0025,
            format!(
                "The {} payload is not acceptable: {}",
                what,
                zod_sentence(&issue, what)
            ),
        )
    })
}

/// `nonceMac(realmId, expiresS, random)`.
fn nonce_mac(realm_id: &str, expires_s: u32, random: &[u8]) -> Vec<u8> {
    let expires = expires_s.to_string();
    let random_text = b64u(random);
    let mac = sts_crypto::secrets::derive_shared_credential(
        &NONCE_SECRET,
        "acme-nonce",
        &[realm_id, &expires, &random_text],
    )
    .ok()
    .and_then(|m| URL_SAFE_NO_PAD.decode(m).ok())
    .unwrap_or_default();
    mac.into_iter().take(16).collect()
}

/// `mintNonce(realmId, lifetimeS)`.
#[tracing::instrument(level = "debug")]
pub fn mint_nonce(realm_id: &str, lifetime_s: i64) -> String {
    let now_s = (sts_core::time::now_ms_f64() / 1000.0).floor() as i64;
    let expires = (now_s + lifetime_s.max(1)) as u32;
    let random = sts_crypto::random::random_bytes(16).unwrap_or_default();
    let mut bytes = vec![NONCE_VERSION];
    bytes.extend_from_slice(&expires.to_be_bytes());
    bytes.extend_from_slice(&random);
    bytes.extend_from_slice(&nonce_mac(realm_id, expires, &random));
    b64u(&bytes)
}

/// `checkNonce(nonce, realmId)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonceCheck {
    Ok { id: String, expires_s: u32 },
    Malformed,
    Forged,
    Expired,
}

/// `checkNonce(nonce, realmId)`.
#[tracing::instrument(level = "debug")]
pub fn check_nonce(nonce: &str, realm_id: &str) -> NonceCheck {
    let Some(bytes) = decode_b64url(nonce, false)
        .filter(|b| b.len() == 37 && b[0] == NONCE_VERSION)
    else {
        return NonceCheck::Malformed;
    };
    let expires = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
    let random = &bytes[5..21];
    let presented = &bytes[21..37];
    let expected = nonce_mac(realm_id, expires, random);
    if !sts_crypto::secrets::constant_time_equals(presented, &expected) {
        return NonceCheck::Forged;
    }
    if (expires as f64) <= (sts_core::time::now_ms_f64() / 1000.0).floor() {
        return NonceCheck::Expired;
    }
    NonceCheck::Ok {
        id: b64u(random),
        expires_s: expires,
    }
}

/// `parseEab()`'s answer.
#[derive(Debug, Clone)]
pub struct Eab {
    pub kid: String,
    pub alg: String,
    pub parts: Parts,
}

/// `parseEab(eab, expectedUrl, accountThumbprint)`.
#[tracing::instrument(level = "debug", skip(eab))]
pub fn parse_eab(
    eab: &Json,
    expected_url: &str,
    thumbprint: &str,
) -> Result<Eab, AcmeRefusal> {
    let parts =
        parse_flattened_object(eab, "externalAccountBinding").map_err(|r| {
            refusal("malformed", 400, codes::STS_ACME_0032, r.detail)
        })?;
    let header = read_json_object(
        &parts.header_bytes,
        "externalAccountBinding protected header",
    )
    .map_err(|why| {
        refusal(
            "malformed",
            400,
            codes::STS_ACME_0032,
            format!("The externalAccountBinding header is unreadable: {}", why),
        )
    })?;
    let header = body("eab-header").check(&header).map_err(|issue| {
        refusal(
            "malformed",
            400,
            codes::STS_ACME_0032,
            format!(
                "The externalAccountBinding protected header must be exactly \"alg\", \"kid\" and \
                 \"url\" — no nonce (RFC 8555 section 7.3.4): {}",
                zod_sentence(&issue, "EAB header")
            ),
        )
    })?;
    let t = |k: &str| {
        header
            .get(k)
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_string()
    };
    let algs = eab_algs();
    if !algs.contains(&t("alg")) {
        let mut r = refusal(
            "badSignatureAlgorithm",
            400,
            codes::STS_ACME_0032,
            format!(
                "An external account binding is MACed with {}, and this one names \"{}\".",
                algs.join(", "),
                t("alg")
            ),
        );
        r.extra = Box::new(json!({ "algorithms": algs }));
        return Err(r);
    }
    if t("url") != expected_url {
        return Err(refusal(
            "malformed",
            400,
            codes::STS_ACME_0032,
            "The externalAccountBinding \"url\" must be the newAccount URL the outer JWS was sent \
             to.",
        ));
    }
    let bound = read_json_object(
        &parts.payload_bytes,
        "externalAccountBinding payload",
    )
    .ok()
    .and_then(|key| {
        let kty = key.get("kty").and_then(Json::as_str).unwrap_or("");
        let alg = match kty {
            "RSA" => "RS256",
            "OKP" => "EdDSA",
            _ => match key.get("crv").and_then(Json::as_str) {
                Some("P-384") => "ES384",
                Some("P-521") => "ES512",
                _ => "ES256",
            },
        };
        check_account_key(&key, alg).ok().map(|k| k.thumbprint)
    })
    .unwrap_or_default();
    if bound.is_empty() || bound != thumbprint {
        return Err(refusal(
            "malformed",
            400,
            codes::STS_ACME_0032,
            "The externalAccountBinding payload must be the account's own public key, the same \
             one the outer JWS carries in \"jwk\".",
        ));
    }
    Ok(Eab {
        kid: t("kid"),
        alg: t("alg"),
        parts,
    })
}

/// `verifyEabMac(parsed, hmacKey)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn verify_eab_mac(eab: &Eab, hmac_key: &[u8]) -> bool {
    let compact = format!(
        "{}.{}.{}",
        eab.parts.protected_b64, eab.parts.payload_b64, eab.parts.signature_b64
    );
    sts_crypto::jws::verify_compact(
        &compact,
        &JwsKey::secret(hmac_key.to_vec()),
        &VerifyOptions {
            algorithms: &[eab.alg.as_str()],
            empty_payload: false,
            policy: policy(),
        },
    )
    .is_ok()
}

/// `checkContacts(list)`: `mailto:` of one address each.
#[tracing::instrument(level = "debug", skip(list))]
pub fn check_contacts(list: &[String]) -> Result<Vec<String>, AcmeRefusal> {
    static ADDRESS: LazyLock<Option<regex::Regex>> = LazyLock::new(|| {
        regex::Regex::new(
            r"^[A-Za-z0-9.!#$%&'*+/=^_`{|}~-]{1,64}@[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$",
        )
        .ok()
    });
    for one in list {
        let shown: String = one
            .encode_utf16()
            .take(80)
            .collect::<Vec<u16>>()
            .iter()
            .map(|&u| char::from_u32(u as u32).unwrap_or('\u{fffd}'))
            .collect();
        if !one
            .get(..7)
            .is_some_and(|p| p.eq_ignore_ascii_case("mailto:"))
        {
            return Err(refusal(
                "unsupportedContact",
                400,
                codes::STS_ACME_0037,
                format!("Contact \"{}\" is not a mailto: URI, the only contact scheme this server supports.", shown),
            ));
        }
        let address = &one[7..];
        let ok = ADDRESS.as_ref().is_some_and(|re| re.is_match(address))
            && address.encode_utf16().count() <= 254;
        if !ok {
            return Err(refusal(
                "invalidContact",
                400,
                codes::STS_ACME_0037,
                format!("Contact \"{}\" is not one mailto: address with no header fields.", shown),
            ));
        }
    }
    Ok(list.to_vec())
}

/// `serialContentBytes(serialHex)`.
#[tracing::instrument(level = "trace")]
pub fn serial_content_bytes(serial: &str) -> Vec<u8> {
    let mut hex: String = serial
        .chars()
        .filter(char::is_ascii_hexdigit)
        .collect::<String>()
        .to_lowercase();
    while hex.len() > 2 && hex.starts_with("00") {
        hex = hex[2..].to_string();
    }
    if hex.len() % 2 == 1 {
        hex.insert(0, '0');
    }
    let mut bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect();
    if bytes.first().is_some_and(|b| b & 0x80 != 0) {
        bytes.insert(0, 0);
    }
    bytes
}

/// `certIdOf(aki, serialHex)`.
#[tracing::instrument(level = "trace", skip(aki))]
pub fn cert_id_of(aki: &[u8], serial: &str) -> String {
    format!("{}.{}", b64u(aki), b64u(&serial_content_bytes(serial)))
}

/// `parseCertId(text)`: `(serialHex, certId)`.
#[tracing::instrument(level = "trace")]
pub fn parse_cert_id(text: &str) -> Option<(String, String)> {
    let pieces: Vec<&str> = text.split('.').collect();
    if pieces.len() != 2 || text.encode_utf16().count() > 512 {
        return None;
    }
    decode_b64url(pieces[0], false)?;
    let serial = decode_b64url(pieces[1], false)?;
    let mut hex = sts_pki::der::hex(&serial);
    while hex.len() > 2 && hex.starts_with("00") {
        hex = hex[2..].to_string();
    }
    Some((hex, text.to_string()))
}

/// `certificateFacts(der)`'s answer.
#[derive(Debug, Clone)]
pub struct CertificateFacts {
    pub der: Vec<u8>,
    pub serial_hex: String,
    pub aki: Option<Vec<u8>>,
    pub spki: Vec<u8>,
}

/// `certificateFacts(der)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn certificate_facts(der: &[u8]) -> Option<CertificateFacts> {
    if der.is_empty() {
        return None;
    }
    let cert = sts_pki::x509::read::Certificate::from_der(der).ok()?;
    sts_pki::der::read_whole(der)?;
    let mut serial = sts_pki::der::hex(&cert.serial);
    while serial.len() > 2 && serial.starts_with("00") {
        serial = serial[2..].to_string();
    }
    let aki = cert.extension("2.5.29.35").and_then(|e| {
        let seq = sts_pki::der::read(&e.value)?;
        sts_pki::der::children(seq.content)?
            .into_iter()
            .find(|c| c.tag == 0x80)
            .map(|c| c.content.to_vec())
    });
    Some(CertificateFacts {
        der: der.to_vec(),
        serial_hex: serial,
        aki,
        spki: cert.spki.clone(),
    })
}

/// `pemToDer(pem)`: the first certificate's DER.
#[tracing::instrument(level = "trace", skip_all)]
pub fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let start = pem.find("-----BEGIN CERTIFICATE-----")? + 27;
    let end = pem[start..].find("-----END CERTIFICATE-----")? + start;
    let body: String = pem[start..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD.decode(body).ok()
}

/// `spkiOfJwk(jwk)`.
#[tracing::instrument(level = "trace", skip_all)]
pub fn spki_of_jwk(jwk: &Json) -> Option<Vec<u8>> {
    JwsKey::from_jwk(jwk)
        .ok()?
        .public_key()
        .ok()?
        .public_key_to_der()
        .ok()
}

/// `normalIdentifier(type, value)`.
#[tracing::instrument(level = "trace")]
pub fn normal_identifier(kind: &str, value: &str) -> String {
    match kind {
        "dns" => {
            let lower = value.to_lowercase();
            static RE: LazyLock<Option<regex::Regex>> = LazyLock::new(|| {
                regex::Regex::new(
                    r"^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$",
                )
                .ok()
            });
            let ok = RE.as_ref().is_some_and(|re| re.is_match(&lower))
                && lower.len() <= 253
                && !crate::core::is_ip(&lower);
            if ok {
                lower
            } else {
                String::new()
            }
        }
        "ip" => {
            if crate::core::is_ip(value) {
                value.to_lowercase()
            } else {
                String::new()
            }
        }
        "email" => {
            static RE: LazyLock<Option<regex::Regex>> = LazyLock::new(|| {
                regex::Regex::new(r"^[A-Za-z0-9.!#$%&'*+/=^_`{|}~-]{1,64}@[A-Za-z0-9.-]{1,253}$").ok()
            });
            if RE.as_ref().is_some_and(|re| re.is_match(value)) {
                value.to_string()
            } else {
                String::new()
            }
        }
        "permanent-identifier" => {
            if value.encode_utf16().count() <= 256
                && !value.chars().any(|c| (c as u32) < 0x20 || c == '\u{7f}')
            {
                value.to_string()
            } else {
                String::new()
            }
        }
        _ => String::new(),
    }
}

/// The subscriber's revocation reasons by RFC 5280 code.
#[tracing::instrument(level = "trace")]
pub fn revocation_reason(code: i64) -> Option<String> {
    model::name_of_code("acme", "revocation-reasons", code)
}

/// The codes a subscriber may give, in the model's order.
#[tracing::instrument(level = "trace")]
pub fn revocation_codes() -> Vec<i64> {
    let mut codes: Vec<i64> = model::rows("acme", "revocation-reasons")
        .iter()
        .filter_map(|r| r.get("code").and_then(Json::as_i64))
        .collect();
    // `Object.keys()` of an integer-keyed object: ascending.
    codes.sort();
    codes
}
