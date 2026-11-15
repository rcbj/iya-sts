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
//! WHAT IS NOT HERE, and what is answered meanwhile: an ENCRYPTED response
//! (`authorization_encrypted_response_alg`) and an HMAC one (signed with the
//! client's secret): the response cannot be made, which Node answers as a
//! 400 rather than sending it unsecured (`STS-OAUTH-0588`), and so does
//! this; FAPI 1.0 Advanced's narrowing of the algorithms is FAPI's slice.

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
pub fn respond(
    signer: &dyn Signer,
    fields: &[(String, String)],
    registered: &Json,
    issuer: &str,
    client_id: &str,
    now_s: i64,
    lifetime_s: i64,
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
    if !text("authorization_encrypted_response_alg").is_empty() {
        return Err(cannot(
            "this authorization server does not yet encrypt a JWT-secured \
             authorization response (authorization_encrypted_response_alg)."
                .into(),
        ));
    }
    if sign_alg.starts_with("HS") {
        return Err(cannot(format!(
            "this authorization server does not yet sign a JWT-secured \
             authorization response with the client's secret ({}).",
            sign_alg
        )));
    }
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
    signer
        .sign(&payload, "JWT", &sign_alg)
        .map_err(|e| (codes::STS_OAUTH_0588, e))
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
