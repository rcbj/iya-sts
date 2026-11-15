// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE JWT-SECURED AUTHORIZATION RESPONSE (JARM, #139, #143; rule 3aw) —
//! `oauth-oidc/jarm.ts`: the four modes (`jwt`, `query.jwt`,
//! `fragment.jwt`, `form_post.jwt`), how the one `response` parameter
//! travels for each, and the response itself — the fields an authorization
//! response would have carried, with `iss`, `aud` and `exp`, signed under
//! the realm's key with the client's `authorization_signed_response_alg`
//! (RS256, JARM's own default, where none is registered).
//!
//! An HMAC algorithm signs with the client's secret; a registered
//! `authorization_encrypted_response_alg` encrypts the signed response to a
//! key in the client's inline `jwks` (`introspectionJwt.recipientKey()`:
//! one marked for encryption or for nothing, of the kind the algorithm
//! needs), `cty: JWT`, with the registered `_enc` or the realm's default
//! (A128CBC-HS256 where CBC is allowed, A256GCM otherwise). One that cannot
//! be made is a 400 rather than a response sent unsecured
//! (`STS-OAUTH-0588`).
//!
//! WHAT IS NOT HERE: a client whose keys are only at a `jwks_uri` (no key
//! to encrypt to, refused as above), a key's certificate under paranoid PKI
//! mode, and FAPI 1.0 Advanced's narrowing of the algorithms.

use serde_json::{Map, Value as Json};
use sts_core::errors::{codes, ErrorCode};

use crate::token_endpoint::Signer;

/// `MODES`.
pub const MODES: [&str; 4] =
    ["jwt", "query.jwt", "fragment.jwt", "form_post.jwt"];

/// `DEFAULT_SIGNING_ALG`.
pub const DEFAULT_SIGNING_ALG: &str = "RS256";

/// `isJarm(mode)`.
#[tracing::instrument(level = "trace")]
pub fn is_jarm(mode: &str) -> bool {
    MODES.contains(&mode)
}

/// `transportOf(mode, types)`: `query`, `fragment` or `form_post`; `jwt`
/// is a query for `code` and `none` and a fragment otherwise.
#[tracing::instrument(level = "trace")]
pub fn transport_of(mode: &str, types: &[String]) -> &'static str {
    match mode {
        "query.jwt" => "query",
        "fragment.jwt" => "fragment",
        "form_post.jwt" => "form_post",
        _ => {
            if types.iter().all(|t| t == "code" || t == "none") {
                "query"
            } else {
                "fragment"
            }
        }
    }
}

/// One refusal: the code and the sentence.
pub type Refusal = (ErrorCode, String);

/// `respond(fields, { registered, issuer, clientId })`: the compact JWT.
/// `fields` are in the order the response would have carried them.
#[tracing::instrument(level = "debug", skip_all)]
#[allow(clippy::too_many_arguments)]
pub fn respond(
    signer: &dyn Signer,
    fields: &[(String, String)],
    registered: &Json,
    issuer: &str,
    client_id: &str,
    now_s: i64,
    lifetime_s: i64,
    cbc_allowed: bool,
) -> Result<String, Refusal> {
    let text = |name: &str| -> String {
        crate::js::string_of(registered.get(name))
            .trim()
            .to_string()
    };
    let sign_alg = {
        let asked = text("authorization_signed_response_alg");
        if asked.is_empty() {
            DEFAULT_SIGNING_ALG.to_string()
        } else {
            asked
        }
    };
    let cannot = |why: String| -> Refusal {
        (
            codes::STS_OAUTH_0588,
            format!(
                "This client's JWT-secured authorization response cannot be \
                 made: {}",
                why
            ),
        )
    };
    let mut payload = Map::new();
    for (name, value) in fields {
        let v = if name == "expires_in" {
            value
                .parse::<f64>()
                .ok()
                .filter(|n| n.is_finite())
                .map(|n| serde_json::json!(n as i64))
                .unwrap_or_else(|| Json::from(value.clone()))
        } else {
            Json::from(value.clone())
        };
        payload.insert(name.clone(), v);
    }
    let iss = if issuer.is_empty() {
        crate::js::string_of(payload.get("iss"))
    } else {
        issuer.to_string()
    };
    payload.insert("iss".into(), Json::from(iss));
    payload.insert("aud".into(), Json::from(client_id));
    payload.insert("exp".into(), Json::from(now_s + lifetime_s));
    let signed = if sign_alg.starts_with("HS") {
        let secret = text("client_secret");
        if secret.is_empty() {
            return Err(cannot(format!(
                "{} is signed with the client_secret, and this client has \
                 none — a public client cannot use a symmetric algorithm.",
                sign_alg
            )));
        }
        let key = sts_crypto::keys::JwsKey::from_jwk(&serde_json::json!({
            "kty": "oct",
            "k": sts_crypto::b64::encode(secret.as_bytes()),
        }))
        .map_err(|e| (codes::STS_OAUTH_0588, e.to_string()))?;
        sts_crypto::jws::sign_jws(
            &payload,
            &key,
            &sts_crypto::jws::SignOptions {
                algorithm: Some(sign_alg.clone()),
                ..sts_crypto::jws::SignOptions::default()
            },
        )
        .map_err(|e| (codes::STS_OAUTH_0588, e.to_string()))?
    } else {
        signer
            .sign(&payload, "JWT", &sign_alg)
            .map_err(|e| (codes::STS_OAUTH_0588, e))?
    };
    let alg = text("authorization_encrypted_response_alg");
    if alg.is_empty() {
        return Ok(signed);
    }
    let enc = match text("authorization_encrypted_response_enc") {
        e if !e.is_empty() => e,
        _ if cbc_allowed => "A128CBC-HS256".to_string(),
        _ => "A256GCM".to_string(),
    };
    let jwk = recipient_key(registered, &alg, ENC_MEMBER)
        .map_err(|e| (codes::STS_OAUTH_0588, e))?;
    sts_crypto::jwe::encrypt_compact(
        signed.as_bytes(),
        &sts_crypto::jwe::EncryptOptions {
            alg: Some(&alg),
            enc: &enc,
            typ: Some("JWT"),
            cty: Some("JWT"),
            jwk: Some(&jwk),
            ..sts_crypto::jwe::EncryptOptions::default()
        },
    )
    .map_err(|e| (codes::STS_OAUTH_0588, e.to_string()))
}

/// `ENC_MEMBER`.
const ENC_MEMBER: &str = "authorization_encrypted_response_alg";

/// What kind of key an algorithm encrypts to (`jweRecipientKeyNeed()`).
fn key_need(alg: &str) -> (&'static [&'static str], &'static str) {
    if alg.starts_with("RSA") {
        (&["RSA"], "an RSA key")
    } else if alg.starts_with("ECDH") {
        (&["EC", "OKP"], "an EC or OKP key")
    } else {
        (&["AKP", "OKP", "EC", "RSA"], "a public key")
    }
}

/// `introspectionJwt.recipientKey(registered, alg, member)`: the client's
/// key to encrypt to.
#[tracing::instrument(level = "debug", skip(registered))]
pub fn recipient_key(
    registered: &Json,
    alg: &str,
    member: &str,
) -> Result<Json, String> {
    let jwks = match registered.get("jwks") {
        Some(Json::String(t)) if !t.trim().is_empty() => {
            serde_json::from_str::<Json>(t).map_err(|e| {
                format!(
                    "This client registered {}=\"{}\", and the \"jwks\" on \
                     its entry is not a JSON Web Key Set ({}), so there is no \
                     key to encrypt to.",
                    member, alg, e
                )
            })?
        }
        Some(o @ Json::Object(_)) => o.clone(),
        _ => Json::Null,
    };
    let keys = jwks
        .get("keys")
        .and_then(Json::as_array)
        .cloned()
        .unwrap_or_default();
    if keys.is_empty() {
        return Err(
            if crate::js::string_of(registered.get("jwks_uri")).is_empty() {
                format!(
                    "This client registered {}=\"{}\" and no \"jwks\" \
                     member, so there is no key to encrypt to.",
                    member, alg
                )
            } else {
                format!(
                    "This client registered {}=\"{}\" and a jwks_uri whose \
                     keys could not be fetched, so there is no key to \
                     encrypt to.",
                    member, alg
                )
            },
        );
    }
    let (kinds, need) = key_need(alg);
    keys.into_iter()
        .find(|k| {
            let usage = crate::js::string_of(k.get("use"));
            (usage.is_empty() || usage == "enc")
                && kinds.contains(&crate::js::string_of(k.get("kty")).as_str())
        })
        .ok_or_else(|| {
            format!(
                "This client registered {}=\"{}\", which needs {}, and its \
                 jwks has none that can be used for encryption.",
                member, alg, need
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_is_a_query_for_code_and_a_fragment_for_a_token() {
        assert_eq!(transport_of("jwt", &["code".into()]), "query");
        assert_eq!(
            transport_of("jwt", &["code".into(), "id_token".into()]),
            "fragment"
        );
        assert_eq!(transport_of("form_post.jwt", &[]), "form_post");
        assert!(is_jarm("query.jwt") && !is_jarm("query"));
    }
}
