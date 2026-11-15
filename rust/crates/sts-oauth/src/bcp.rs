// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! RFC 9700, the Security BCP (`oauth-oidc/oauth2_bcp.js`), in the parts the
//! token endpoint's core reads: whether the mode is on, what a registered
//! client is (`isConfidential()`, `declaredPublic()`, `credentialOnFile()`),
//! and the two questions about a client's credential —
//! `observeClientAuthentication()`, the FACT the role gate and product mode
//! read, and `checkClientAuthentication()`, the POLICY of section 2.5 in that
//! mode (`oauth-oidc/CLAUDE.md`, *observeClientAuthentication()*).
//!
//! The mode is a value here ([`BcpMode`]): `oauth2.rfc9700`, OAuth 2.1
//! mode, a FAPI profile or product mode turns it on (`enabled()`), and the
//! caller says which, since OAuth 2.1 and FAPI are read where they live.

use serde_json::Value as Json;
use sts_core::errors::{codes, ErrorCode};

use crate::client_auth::{
    self, ClientAuth, MethodHints, Presented, Verified, SYMMETRIC_METHODS,
};

/// Whether RFC 9700 mode is on in the ambient realm (`enabled()`).
#[derive(Debug, Clone, Copy, Default)]
pub struct BcpMode {
    pub enabled: bool,
}

fn text(registered: &Json, name: &str) -> String {
    crate::js::string_of(registered.get(name))
}

fn truthy(v: Option<&Json>) -> bool {
    match v {
        None | Some(Json::Null) => false,
        Some(Json::Bool(b)) => *b,
        Some(Json::String(s)) => !s.is_empty(),
        Some(Json::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(_) => true,
    }
}

/// `isConfidential()`: a method other than none is declared.
#[tracing::instrument(level = "debug", skip_all)]
pub fn is_confidential(registered: &Json) -> bool {
    let method = text(registered, "token_endpoint_auth_method");
    let method = method.trim();
    !method.is_empty() && method != "none"
}

/// `declaredPublic()`: a known client that declared `none`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn declared_public(registered: &Json) -> bool {
    truthy(registered.get("known"))
        && text(registered, "token_endpoint_auth_method").trim() == "none"
}

/// `credentialOnFile()`: whether the entry holds what `method` (or, with
/// none named, any declared method) is verified against.
#[tracing::instrument(level = "debug", skip_all)]
pub fn credential_on_file(registered: &Json, asked: Option<&str>) -> bool {
    if !is_confidential(registered) {
        return false;
    }
    let Some(method) = asked else {
        let listed = registered
            .get("token_endpoint_auth_methods")
            .and_then(Json::as_array)
            .filter(|l| !l.is_empty());
        let every: Vec<String> = match listed {
            Some(list) => list
                .iter()
                .map(|one| crate::js::string_of(Some(one)))
                .collect(),
            None => vec![text(registered, "token_endpoint_auth_method")],
        };
        return every
            .iter()
            .any(|one| credential_on_file(registered, Some(one.trim())));
    };
    let method = method.trim();
    (SYMMETRIC_METHODS.contains(&method)
        && truthy(registered.get("client_secret")))
        || (method == "private_key_jwt"
            && (truthy(registered.get("jwks"))
                || truthy(registered.get("jwks_uri"))
                || truthy(registered.get("assertion_jwks"))))
        || (method == "saml2_bearer"
            && (truthy(registered.get("saml_signing_certificate"))
                || truthy(registered.get("saml_assertion_certificate"))))
        || method == "tls_client_auth"
        || method == "self_signed_tls_client_auth"
        || method == "attest_jwt_client_auth"
        || method == "attest_jwt_client_auth_dpop"
}

/// What `observeClientAuthentication()` answers.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Observation {
    pub authenticated: bool,
    pub method: String,
    pub code: Option<ErrorCode>,
    pub why: String,
    pub alg: String,
    /// An OAuth error a method named; empty for `invalid_client`.
    pub oauth_error: String,
    pub status: u16,
}

/// What the request presented, for both questions.
pub struct Question<'a> {
    pub presented: &'a Presented,
    pub hints: &'a MethodHints,
    pub registered: &'a Json,
}

fn presented_for(q: &Question<'_>, method: &str) -> Presented {
    let mut out = q.presented.clone();
    out.method = method.to_string();
    out
}

/// `observeClientAuthentication()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn observe_client_authentication(
    auth: &ClientAuth,
    q: &Question<'_>,
    memo: &Verified,
) -> Observation {
    let registered = q.registered;
    if !truthy(registered.get("known")) {
        return Observation {
            code: Some(codes::STS_OAUTH_0193),
            why: "this service has no entry for this client, so there was \
                  nothing to authenticate it against."
                .into(),
            ..Observation::default()
        };
    }
    if !is_confidential(registered)
        && text(registered, "token_endpoint_auth_method")
            .trim()
            .is_empty()
    {
        return Observation {
            method: "none".into(),
            code: Some(codes::STS_OAUTH_0553),
            why: "its entry declares NO token_endpoint_auth_method. \
                  Development mode reads that as a public client; product \
                  mode reads it as RFC 7591 section 2's default, \
                  client_secret_basic, so it must present a credential, and \
                  it presented none. Set the application's \
                  oauthTokenEndpointAuthMethod to \"none\" for a public \
                  client (held to PKCE), or give it a credential and the \
                  method that presents it."
                .into(),
            ..Observation::default()
        };
    }
    if !is_confidential(registered) {
        return Observation {
            method: "none".into(),
            code: Some(codes::STS_OAUTH_0194),
            why: "this is a PUBLIC client: its entry declares \
                  token_endpoint_auth_method=\"none\", so it has no \
                  credential to present and presenting none is correct."
                .into(),
            ..Observation::default()
        };
    }
    let method = ClientAuth::method_for(registered, q.hints);
    if !credential_on_file(registered, Some(&method)) {
        return Observation {
            method: method.clone(),
            code: Some(codes::STS_OAUTH_0195),
            why: format!(
                "this client is configured as confidential \
                 (token_endpoint_auth_method={}) and has nothing on its \
                 entry to verify that method against, so nothing could be \
                 checked.",
                method
            ),
            ..Observation::default()
        };
    }
    match auth.verify(&presented_for(q, &method), registered, memo) {
        Ok(accepted) => Observation {
            authenticated: true,
            method: method.clone(),
            alg: accepted.alg,
            why: format!("it authenticated with {}.", method),
            ..Observation::default()
        },
        Err(refused) => Observation {
            method,
            code: Some(refused.code),
            why: refused.description,
            oauth_error: refused.error,
            status: refused.status,
            ..Observation::default()
        },
    }
}

/// What `checkClientAuthentication()` refuses.
#[derive(Debug, Clone, PartialEq)]
pub struct CheckRefusal {
    pub code: ErrorCode,
    pub error: String,
    pub status: u16,
    pub requirement: &'static str,
    pub description: String,
}

/// `declaredText()`.
fn declared_text(registered: &Json, method: &str) -> String {
    let declared = client_auth::declared_methods_of(registered);
    if declared.len() > 1 {
        format!("token_endpoint_auth_methods {}", declared.join(", "))
    } else {
        format!(
            "token_endpoint_auth_method={}",
            declared.first().map_or(method, String::as_str)
        )
    }
}

/// `checkClientAuthentication()`: in RFC 9700 mode, a client whose entry
/// declares a confidential method and holds its credential must
/// authenticate. `Ok(method)`, the empty string where nothing was asked.
#[tracing::instrument(level = "debug", skip_all)]
pub fn check_client_authentication(
    mode: BcpMode,
    auth: &ClientAuth,
    q: &Question<'_>,
    memo: &Verified,
) -> Result<String, CheckRefusal> {
    let registered = q.registered;
    if !mode.enabled || !truthy(registered.get("known")) {
        return Ok(String::new());
    }
    if !is_confidential(registered) {
        return Ok(String::new());
    }
    let method = ClientAuth::method_for(registered, q.hints);
    if !credential_on_file(registered, Some(&method)) {
        tracing::warn!(
            "RFC 9700 section 2.5: client \"{}\" is configured as \
             confidential (token_endpoint_auth_method={}) and has nothing on \
             its entry to verify that method against, so there is nothing \
             to check.",
            q.presented.client_id,
            method
        );
        return Ok(String::new());
    }
    match auth.verify(&presented_for(q, &method), registered, memo) {
        Ok(_) => Ok(method),
        Err(refused) => Err(CheckRefusal {
            code: refused.code,
            error: if refused.error.is_empty() {
                "invalid_client".into()
            } else {
                refused.error
            },
            status: if refused.status == 0 {
                401
            } else {
                refused.status
            },
            requirement: "client-authentication",
            description: format!(
                "RFC 9700 section 2.5: this client's entry in the \
                 application registry declares {}, so it must authenticate \
                 — and {}",
                declared_text(registered, &method),
                refused.description
            ),
        }),
    }
}
