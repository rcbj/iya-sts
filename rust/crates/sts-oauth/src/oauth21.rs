// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! OAUTH 2.1 MODE'S RULES AT THE TOKEN ENDPOINT (`oauth21.js`'s
//! `repeatedParameterRefusal()`, `repeatedNames()`,
//! `multipleMethodsRefusal()`, `tokenClientDeclarationRefusal()`,
//! `assertionClientRefusal()` and `tokenClientAuthenticationRefusal()`),
//! with Node's codes and sentences. Every description is prefixed `OAuth
//! 2.1 (<draft>) `, as `refusal()` prefixes it. The authorization
//! endpoint's rules are [`crate::authorize`]'s.

use serde_json::Value as Json;
use sts_core::errors::{codes, ErrorCode};

/// `DRAFT`.
pub const DRAFT: &str = "draft-ietf-oauth-v2-1-16";

/// `AUDIENCE_DRAFT`.
const AUDIENCE_DRAFT: &str = "draft-ietf-oauth-rfc7523bis-11";

/// `REGISTERED_CLIENT_GRANTS`.
const REGISTERED_CLIENT_GRANTS: [&str; 4] = [
    "authorization_code",
    "refresh_token",
    "client_credentials",
    "urn:ietf:params:oauth:grant-type:token-exchange",
];

/// `ASSERTION_GRANTS`.
const ASSERTION_GRANTS: [&str; 2] = [
    "urn:ietf:params:oauth:grant-type:jwt-bearer",
    "urn:ietf:params:oauth:grant-type:saml2-bearer",
];

/// `REPEATABLE_PARAMETERS`.
const REPEATABLE_PARAMETERS: [&str; 2] = ["resource", "audience"];

/// A refusal: the code and the description (the error is the caller's).
pub type Refusal = (ErrorCode, String);

fn refusal(code: ErrorCode, description: String) -> Refusal {
    (code, format!("OAuth 2.1 ({}) {}", DRAFT, description))
}

fn s(v: Option<&Json>) -> String {
    crate::js::string_of(v)
}

/// `repeatedNames(null, rawBody)`: the names a form body carries more
/// than once, in the order their second appearance is met.
#[tracing::instrument(level = "trace", skip_all)]
pub fn repeated_names(raw: &str) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    let mut repeated: Vec<String> = Vec::new();
    for pair in raw.split('&') {
        let name = pair.split('=').next().unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let decoded = crate::js::form_decode(&format!("{}=", name))
            .into_iter()
            .next()
            .map(|(k, _)| k)
            .unwrap_or_else(|| name.to_string());
        if seen.contains(&decoded) && !repeated.contains(&decoded) {
            repeated.push(decoded.clone());
        }
        seen.push(decoded);
    }
    repeated
}

/// `repeatedNames(query)`: the names a parsed query holds as a list.
#[tracing::instrument(level = "trace", skip_all)]
pub fn repeated_in_query(query: &serde_json::Map<String, Json>) -> Vec<String> {
    query
        .iter()
        .filter(|(_, v)| v.is_array())
        .map(|(k, _)| k.clone())
        .collect()
}

/// `repeatedParameterRefusal(repeated, where, always)`, asked by a caller
/// that already knows the mode (or product) says to.
#[tracing::instrument(level = "trace", skip_all)]
pub fn repeated_refusal(repeated: &[String], at: &str) -> Option<Refusal> {
    let names: Vec<&String> = repeated
        .iter()
        .filter(|n| !REPEATABLE_PARAMETERS.contains(&n.as_str()))
        .collect();
    if names.is_empty() {
        return None;
    }
    Some(refusal(
        codes::STS_OAUTH_0285,
        format!(
            "sections 3.1 and 3.2: request parameters \"MUST NOT be included \
             more than once\", and this {} repeats {}.",
            if at.is_empty() { "request" } else { at },
            names
                .iter()
                .map(|n| n.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    ))
}

/// `multipleMethodsRefusal(presented)` (section 2.4).
#[tracing::instrument(level = "trace")]
pub fn multiple_methods_refusal(
    basic: bool,
    body_secret: bool,
    assertion: bool,
) -> Option<Refusal> {
    let mut methods: Vec<&str> = Vec::new();
    if basic {
        methods.push("an Authorization: Basic header");
    }
    if body_secret {
        methods.push("client_secret in the body");
    }
    if assertion {
        methods.push("a client_assertion");
    }
    if methods.len() < 2 {
        return None;
    }
    Some(refusal(
        codes::STS_OAUTH_0281,
        format!(
            "section 2.4: \"The client MUST NOT use more than one \
             authentication method in each request.\" This one carried {}. \
             Send one.",
            methods.join(" and ")
        ),
    ))
}

/// `tokenClientDeclarationRefusal({ grant, clientId, registered,
/// presented })`: SAML client authentication, a grant made in a client's
/// own name with no client, or by a client nothing declared.
#[tracing::instrument(level = "trace", skip(registered))]
pub fn token_client_declaration_refusal(
    enabled: bool,
    grant: &str,
    client_id: &str,
    registered: &Json,
    assertion_type: &str,
) -> Option<Refusal> {
    if !enabled {
        return None;
    }
    let mut declared: Vec<String> = match registered
        .get("token_endpoint_auth_methods")
        .and_then(Json::as_array)
    {
        Some(l) => l.iter().map(|m| s(Some(m))).collect(),
        None => vec![s(registered.get("token_endpoint_auth_method"))],
    };
    declared.retain(|m| !m.is_empty());
    let saml_presented = assertion_type
        == "urn:ietf:params:oauth:client-assertion-type:saml2-bearer";
    if declared.iter().any(|m| m == "saml2_bearer") || saml_presented {
        return Some(refusal(
            codes::STS_OAUTH_0282,
            format!(
                "section 2.4 requires {}, which says SAML Bearer Assertions \
                 \"MUST NOT be used for client authentication for any new \
                 applications.\" Authenticate with private_key_jwt, an RFC \
                 8705 certificate, or a client secret. An RFC 7522 assertion \
                 as the GRANT is unaffected.",
                AUDIENCE_DRAFT
            ),
        ));
    }
    let registered_grant = REGISTERED_CLIENT_GRANTS.contains(&grant);
    if client_id.is_empty() && registered_grant {
        return Some(refusal(
            codes::STS_OAUTH_0297,
            format!(
                "sections 2.3.1 and 2.5: the {} grant is made by a client in \
                 its own name, and this request named no client at all. Send \
                 client_id, and register the client at POST /oauth2/register \
                 or declare it on /admin/applications.",
                grant
            ),
        ));
    }
    if !client_id.is_empty()
        && registered_grant
        && registered.get("declared") != Some(&Json::Bool(true))
    {
        return Some(refusal(
            codes::STS_OAUTH_0278,
            format!(
                "sections 2.3.1 and 2.5: client \"{}\" {}. Register it at \
                 POST /oauth2/register, or declare it on /admin/applications \
                 (a redirect URI, an authentication method or a credential).",
                client_id,
                if registered.get("known") == Some(&Json::Bool(true)) {
                    "has an entry here that was only ever SIGHTED — nothing \
                     on it was registered or declared"
                } else {
                    "is not registered here"
                }
            ),
        ));
    }
    None
}

/// `assertionClientRefusal({ grant, clientId, registered })`.
#[tracing::instrument(level = "trace", skip(registered))]
pub fn assertion_client_refusal(
    enabled: bool,
    grant: &str,
    client_id: &str,
    registered: &Json,
) -> Option<Refusal> {
    if !enabled
        || client_id.is_empty()
        || !ASSERTION_GRANTS.contains(&grant)
        || registered.get("declared") == Some(&Json::Bool(true))
    {
        return None;
    }
    Some(refusal(
        codes::STS_OAUTH_0299,
        format!(
            "sections 2.3.1 and 2.5: client \"{}\" {}, and named itself on an \
             assertion grant. The assertion may speak for the subject; the \
             client naming itself still has to be one this server knows. \
             Register it, declare it on /admin/applications, or send no \
             client_id.",
            client_id,
            if registered.get("known") == Some(&Json::Bool(true)) {
                "has an entry here that was only ever SIGHTED"
            } else {
                "is not registered here"
            }
        ),
    ))
}

/// `tokenClientAuthenticationRefusal({ grant, observation, presented })`:
/// a credential that was included must verify (section 3.2.2), and the
/// client credentials grant needs an authenticated client (section 4.2).
#[tracing::instrument(level = "trace", skip(why))]
pub fn token_client_authentication_refusal(
    enabled: bool,
    grant: &str,
    authenticated: bool,
    why: &str,
    presented_something: bool,
) -> Option<Refusal> {
    if !enabled {
        return None;
    }
    if presented_something && !authenticated {
        return Some(refusal(
            codes::STS_OAUTH_0280,
            format!(
                "section 3.2.2: the authorization server MUST authenticate \
                 the client if client authentication is included, and this \
                 request included it — but {}",
                if why.is_empty() {
                    "it did not verify."
                } else {
                    why
                }
            ),
        ));
    }
    if grant == "client_credentials" && !authenticated {
        return Some(refusal(
            codes::STS_OAUTH_0279,
            format!(
                "section 4.2: the client credentials grant \"MUST only be \
                 used by confidential clients\" and the server \"MUST \
                 authenticate the client\". {}",
                if why.is_empty() {
                    "This request did not authenticate."
                } else {
                    why
                }
            ),
        ));
    }
    None
}
