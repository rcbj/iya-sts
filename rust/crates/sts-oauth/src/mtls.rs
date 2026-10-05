// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! RFC 8705 section 3.1, the RESOURCE server's half (`mtls.js`'s
//! `checkBinding()`): a certificate-bound token is usable only on a TLS
//! connection made with that certificate.
//!
//! * **The two failures are told apart**, because they send a client to
//!   different places: NO certificate is usually a client that configured
//!   none or a proxy that terminated TLS (STS-OAUTH-0091); a DIFFERENT one
//!   is the case the binding exists to catch (STS-OAUTH-0092).
//! * **A token this service did not issue is not checked**: its `cnf` is a
//!   claim anybody could have written, and enforcing it would be theatre
//!   performed on an unverified string — the same judgement the DPoP check
//!   makes about `cnf.jkt`.
//!
//! The certificate is the connection's, handed in as DER by whatever
//! accepted the connection (the resumed-session chain is that layer's
//! business, `tls/CLAUDE.md`). The client-authentication half
//! (`declaredRefusal()`) arrives with the token endpoint.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value as Json;
use sts_core::errors::codes;

use crate::jwt_access_token::Refusal;

/// The confirmation member RFC 8705 section 3.1 defines.
pub const CONFIRMATION_MEMBER: &str = "x5t#S256";

/// `certificateThumbprint()`: SHA-256 over the certificate's DER,
/// base64url without padding — `x5t#S256`'s form.
pub fn certificate_thumbprint(der: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(openssl::sha::sha256(der))
}

/// `boundThumbprintOf()`: the token's `cnf["x5t#S256"]`, or `""`.
pub fn bound_thumbprint_of(claims: &Json) -> String {
    match claims.get("cnf").and_then(|c| c.get(CONFIRMATION_MEMBER)) {
        Some(Json::String(s)) => s.clone(),
        Some(Json::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

/// `checkBinding()`: `None` when there is nothing to say. `presented` is
/// the connection's client certificate as DER; `verified` whether this
/// service verified the token; `noun` what to call it in a refusal (the
/// refresh grant checks a refresh token with this same function).
pub fn check_binding(
    claims: &Json,
    presented: Option<&[u8]>,
    verified: bool,
    noun: Option<&str>,
) -> Option<Refusal> {
    let what = noun.unwrap_or("access token");
    let bound = bound_thumbprint_of(claims);
    if bound.is_empty() {
        return None;
    }
    if !verified {
        tracing::warn!(
            "RFC 8705: this access token carries a {} confirmation and was NOT issued by this service, so \
             the binding is a claim anybody could have written and is not enforced. The same is true of \
             cnf.jkt on a foreign token.",
            CONFIRMATION_MEMBER
        );
        return None;
    }
    let Some(der) = presented.filter(|d| !d.is_empty()) else {
        return Some(Refusal {
            error: "invalid_token",
            code: codes::STS_OAUTH_0091,
            description: format!(
                "RFC 8705 section 3.1: this {} is bound to a client certificate (cnf[\"{}\"]), so it may \
                 only be used on a TLS connection made with that certificate. This request arrived with no \
                 client certificate at all — either none was configured, or something terminated TLS in \
                 front of this service.",
                what, CONFIRMATION_MEMBER
            ),
        });
    };
    let presented = certificate_thumbprint(der);
    if presented == bound {
        return None;
    }
    Some(Refusal {
        error: "invalid_token",
        code: codes::STS_OAUTH_0092,
        description: format!(
            "RFC 8705 section 3.1: this {} is bound to the client certificate whose SHA-256 thumbprint is \
             {}, and this connection was made with the one whose thumbprint is {}. A certificate-bound \
             token is usable only by the holder of that certificate's private key, which is the whole of \
             what sender-constraining buys.",
            what, bound, presented
        ),
    })
}
