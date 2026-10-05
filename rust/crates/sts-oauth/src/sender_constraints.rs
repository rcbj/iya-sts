// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `sender_constraints.js`'s resource-server half: a resource configured to
//! accept only a sender-constrained access token refuses one that is not
//! (`oauth2.accessTokenRequireDpop`, `oauth2.accessTokenRequireMtls`, both
//! off by default because neither OAuth 2.1 nor RFC 9700 asks for them).
//! The refresh-token half arrives with the token endpoint.

use sts_core::errors::{codes, ErrorCode};
use sts_core::settings::{keys, Settings};

/// What a resource knows of the token and the connection.
#[derive(Clone, Copy, Debug, Default)]
pub struct Presented<'a> {
    /// What to call the resource in a refusal.
    pub where_: &'a str,
    /// The token's `cnf.jkt`.
    pub bound_jkt: &'a str,
    /// A DPoP proof of that key was verified.
    pub proof_ok: bool,
    /// The token's `cnf["x5t#S256"]`.
    pub bound_thumbprint: &'a str,
    /// The connection presented a client certificate.
    pub certificate: bool,
    /// It verified and is the one the token is bound to.
    pub certificate_matches: bool,
    /// The port can ask for a client certificate.
    pub mtls_available: bool,
    /// The token was issued to a client [`dpop_bound_public_client`] names.
    pub client_bound: bool,
}

/// A refusal: the error, the code, the setting that asked for it, and why.
#[derive(Clone, Debug, PartialEq)]
pub struct Refusal {
    pub error: &'static str,
    pub code: ErrorCode,
    pub setting: &'static str,
    pub description: String,
}

/// The hosted clients that are DPoP-bound whenever they are public clients
/// (#446): the admin console. Not a setting.
pub const DPOP_BOUND_PUBLIC_CLIENTS: [&str; 1] = ["sts-admin-console"];

/// `dpopBoundPublicClient()`: the admin console running as a public client,
/// every token issued to which must be DPoP-bound — a key the browser
/// cannot export (#446, reversing #444's D9 for the console on that
/// condition). Not in force while the seeded entry is still confidential.
pub fn dpop_bound_public_client(client_id: &str, method: &str) -> bool {
    method == "none" && DPOP_BOUND_PUBLIC_CLIENTS.contains(&client_id)
}

/// `publicClientIssuanceRefusal()`: at the token endpoint, a request from
/// that client carrying no DPoP proof (STS-OAUTH-0938). `dpop_jkt` is the
/// proof key's thumbprint, `""` with no proof.
pub fn public_client_issuance_refusal(
    client_id: &str,
    method: &str,
    dpop_jkt: &str,
    grant: &str,
) -> Option<Refusal> {
    if !dpop_bound_public_client(client_id, method) || !dpop_jkt.is_empty() {
        return None;
    }
    Some(Refusal {
        error: "invalid_dpop_proof",
        code: codes::STS_OAUTH_0938,
        setting: "the admin console is a public client",
        description: format!(
            "the admin console is a public client, and every token issued to it is bound to a key it proves \
             possession of (RFC 9449). The {} request carried no DPoP proof. Send a DPoP header signed with the \
             key the tokens are to be bound to.",
            if grant.is_empty() { "token" } else { grant }
        ),
    })
}

/// `accessTokenDpopRequired()`.
pub fn access_token_dpop_required(settings: &Settings) -> bool {
    settings
        .value(keys::OAUTH2_ACCESS_TOKEN_REQUIRE_DPOP)
        .as_bool()
}

/// `accessTokenMtlsRequired()`.
pub fn access_token_mtls_required(settings: &Settings) -> bool {
    settings
        .value(keys::OAUTH2_ACCESS_TOKEN_REQUIRE_MTLS)
        .as_bool()
}

/// `accessTokenRefusal()`: `None` to accept.
pub fn access_token_refusal(
    settings: &Settings,
    o: &Presented,
) -> Option<Refusal> {
    let at = if o.where_.is_empty() {
        "this resource"
    } else {
        o.where_
    };
    let dpop = "oauth2.accessTokenRequireDpop";
    let mtls = "oauth2.accessTokenRequireMtls";
    // #446: whatever the two settings say, an unbound token issued to the
    // console as a public client was not issued by the token endpoint as it
    // stands, and is refused rather than believed.
    if o.client_bound && o.bound_jkt.is_empty() {
        return Some(Refusal { error: "invalid_token", code: codes::STS_OAUTH_0939,
            setting: "the admin console is a public client", description: format!(
            "{} accepts an access token issued to the admin console only when it is DPoP-bound (RFC 9449), \
             because the console is a public client, and this token carries no cnf.jkt.", at) });
    }
    if access_token_dpop_required(settings) {
        if o.bound_jkt.is_empty() {
            return Some(Refusal { error: "invalid_token", code: codes::STS_OAUTH_0528, setting: dpop, description: format!(
                "{} is configured to accept only a DPoP-bound access token (RFC 9449), and this token carries no \
                 cnf.jkt. Ask the authorization server for one with a DPoP proof on the token request.", at) });
        }
        if !o.proof_ok {
            return Some(Refusal { error: "invalid_token", code: codes::STS_OAUTH_0529, setting: dpop, description: format!(
                "{} is configured to accept only a DPoP-bound access token, and this request presented one \
                 without proving possession of its key. Send the token as Authorization: DPoP with a DPoP \
                 header.", at) });
        }
    }
    if access_token_mtls_required(settings) {
        if !o.mtls_available {
            return Some(Refusal { error: "invalid_request", code: codes::STS_OAUTH_0527, setting: mtls, description: format!(
                "{} is configured to accept only a certificate-bound access token (RFC 8705), but the port it \
                 answers on cannot ask for a client certificate.", at) });
        }
        if o.bound_thumbprint.is_empty() {
            return Some(Refusal { error: "invalid_token", code: codes::STS_OAUTH_0530, setting: mtls, description: format!(
                "{} is configured to accept only a certificate-bound access token (RFC 8705), and this token \
                 carries no cnf[\"x5t#S256\"]. Ask the authorization server for one over a connection presenting \
                 a client certificate.", at) });
        }
        if !o.certificate_matches {
            return Some(Refusal { error: "invalid_token", code: codes::STS_OAUTH_0531, setting: mtls, description: format!(
                "{} is configured to accept only a certificate-bound access token, and this connection presented \
                 {}.", at, if o.certificate { "a different certificate" } else { "no client certificate" }) });
        }
    }
    None
}
