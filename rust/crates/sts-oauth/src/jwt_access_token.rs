// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! RFC 9068 section 4 at a resource server here (`jwt_access_token.ts`).
//!
//! **Steps 1, 3 and 4 in the section's own order** — the type, the issuer,
//! the audience — for a token whose signature the caller has already
//! verified (steps 5 to 7: `KeySet::verify_own_jws()`). Step 2 does not
//! arise, since no access token here is encrypted, and step 8 is each
//! endpoint's own scope check.
//!
//! * **The type**: every token this service signs is signed with the same
//!   key, so the `typ` header is what tells an access token from an ID
//!   Token, a logout token or a SET. `at+jwt`, compared without case and
//!   with or without `application/` (RFC 7515 section 4.1.9).
//! * **The issuer is an address as well as a name**: the resource servers
//!   here trust every authorization server this process publishes at the
//!   address the request arrived on — the default one and each named one
//!   one path segment under it — and match `iss` exactly against those. A
//!   token minted at `localhost` and presented at `127.0.0.1` is refused;
//!   `global.publicBaseUrl` gives a deployment reached by several names one.
//! * **The audience is compared WHOLE**: a default resource indicator
//!   (`<as base>/resource`) of an authorization server published at this
//!   address. A test that the path ended in `/resource` accepted somebody
//!   else's server narrowed to by RFC 8707, which is the defect the Node
//!   module was written to end.

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value as Json;
use sts_core::errors::{codes, ErrorCode};
use sts_core::settings::{keys, Settings};

/// The `typ` every access token is minted with.
pub const TYP: &str = "at+jwt";
const MEDIA_TYPE: &str = "application/at+jwt";
/// What an authorization server's base is followed by to make its default
/// resource indicator.
pub const RESOURCE_PATH: &str = "/resource";

/// A refusal: always `invalid_token` (RFC 6750 section 3.1, as section 4's
/// last step says), with the sentence a client reads and the code an
/// operator does — recorded, never sent.
#[derive(Clone, Debug, PartialEq)]
pub struct Refusal {
    pub error: &'static str,
    pub description: String,
    pub code: ErrorCode,
}

/// A resource server that answers for something other than this service —
/// RFC 9470's stand-in answering for a registered application — names the
/// audiences it accepts; it replaces step 4 and nothing else.
pub struct AudienceRule<'a> {
    pub names: &'a dyn Fn(&[String]) -> bool,
    pub label: &'a str,
}

/// The checks, over the settings they read.
pub struct JwtAccessTokens {
    settings: Arc<Settings>,
}

/// `authorization_servers.ts`'s `ID_SHAPE`:
/// `^[A-Za-z0-9][A-Za-z0-9._~-]{0,63}$`.
pub fn is_server_id(id: &str) -> bool {
    let mut chars = id.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && id.len() <= 64
        && chars.all(|c| c.is_ascii_alphanumeric() || "._~-".contains(c))
}

impl JwtAccessTokens {
    pub fn new(settings: Arc<Settings>) -> JwtAccessTokens {
        JwtAccessTokens { settings }
    }

    /// `isAccessTokenType()`.
    pub fn is_access_token_type(typ: &str) -> bool {
        let text = typ.trim().to_lowercase();
        text == TYP || text == MEDIA_TYPE
    }

    /// `typOf()`: the protected header's `typ`, or `""` for anything that is
    /// not a compact JWS.
    pub fn typ_of(token: &str) -> String {
        token
            .split('.')
            .next()
            .and_then(|h| URL_SAFE_NO_PAD.decode(h.trim_end_matches('=')).ok())
            .and_then(|b| serde_json::from_slice::<Json>(&b).ok())
            .and_then(|h| {
                h.get("typ").and_then(Json::as_str).map(str::to_string)
            })
            .unwrap_or_default()
    }

    /// `issuerFor()`: a pinned `oauth2.issuer` wins — upgraded to `https://`
    /// on an HTTPS listener, since a client MUST reject a document whose
    /// issuer is not the identifier it fetched from — and otherwise the base.
    pub fn issuer_for(&self, base: &str) -> String {
        let pinned = self.settings.value(keys::OAUTH2_ISSUER);
        let pinned = pinned.as_str();
        if pinned.is_empty() {
            return base.to_string();
        }
        if self.settings.value(keys::GLOBAL_HTTPS).as_bool()
            && pinned.len() >= 7
            && pinned[..7].eq_ignore_ascii_case("http://")
        {
            let upgraded = format!("https://{}", &pinned[7..]);
            tracing::info!(
                "oauth2.issuer is pinned to {}, and this port is an HTTPS listener (global.https), so the \
                 issuer identifier is served as {}.",
                pinned,
                upgraded
            );
            return upgraded;
        }
        pinned.to_string()
    }

    /// `defaultAudienceFor()`.
    pub fn default_audience_for(as_base: &str) -> String {
        format!("{}{}", as_base, RESOURCE_PATH)
    }

    /// `hostedBaseOf()`: `value` when it is the base of an authorization
    /// server this process publishes at `base` — the default one, or a named
    /// one one segment below whose id has the shape a name is refused by.
    fn hosted_base_of<'v>(value: &'v str, base: &str) -> Option<&'v str> {
        if base.is_empty() {
            return None;
        }
        if value == base {
            return Some(value);
        }
        let id = value.strip_prefix(base)?.strip_prefix('/')?;
        is_server_id(id).then_some(value)
    }

    /// `isHostedIssuer()`: section 4 step 3.
    pub fn is_hosted_issuer(&self, iss: &str, base: &str) -> bool {
        if iss.is_empty() {
            return false;
        }
        if iss == self.issuer_for(base) {
            return true;
        }
        Self::hosted_base_of(iss, base)
            .is_some_and(|b| self.issuer_for(b) == iss)
    }

    /// `isOwnResourceAudience()`: section 4 step 4, compared whole.
    pub fn is_own_resource_audience(aud: &str, base: &str) -> bool {
        if aud.len() <= RESOURCE_PATH.len() || !aud.ends_with(RESOURCE_PATH) {
            return false;
        }
        Self::hosted_base_of(&aud[..aud.len() - RESOURCE_PATH.len()], base)
            .is_some()
    }

    fn audiences_of(aud: Option<&Json>) -> Vec<String> {
        match aud {
            None | Some(Json::Null) => Vec::new(),
            Some(Json::String(s)) if s.is_empty() => Vec::new(),
            Some(Json::Array(list)) => list.iter().map(text_of).collect(),
            Some(one) => vec![text_of(one)],
        }
    }

    fn quoted(held: &[String]) -> String {
        if held.is_empty() {
            return "no audience".to_string();
        }
        held.iter()
            .map(|one| format!("\"{}\"", one))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// `resourceServerRefusal()`: `None` to accept, or why not.
    pub fn resource_server_refusal(
        &self,
        token: &str,
        claims: &Json,
        base: &str,
        audience: Option<&AudienceRule>,
    ) -> Option<Refusal> {
        let typ = Self::typ_of(token);
        if !Self::is_access_token_type(&typ) {
            return Some(Refusal {
                error: "invalid_token",
                code: codes::STS_OAUTH_0247,
                description: format!(
                    "RFC 9068 section 4: a resource server MUST verify that the typ header of a JWT access token \
                     is \"at+jwt\", and this token's is {}. Every token this service signs is signed with the \
                     same key, so the header is what tells an access token apart from an ID Token, a logout \
                     token or a Security Event Token. An access token minted before this service issued at+jwt \
                     is refused too; ask the token endpoint for a new one.",
                    if typ.is_empty() { "absent".to_string() } else { format!("\"{}\"", typ) }
                ),
            });
        }
        let iss = claims.get("iss").map(text_of).unwrap_or_default();
        if !self.is_hosted_issuer(&iss, base) {
            return Some(Refusal {
                error: "invalid_token",
                code: codes::STS_OAUTH_0248,
                description: format!(
                    "RFC 9068 section 4: the iss claim MUST exactly match the issuer identifier of the \
                     authorization server, and this token names {} where the authorization servers this \
                     service publishes at {} are \"{}\" and the named ones under it. An issuer is an address as \
                     well as a name, so a token minted under one host name and presented under another is \
                     refused; global.publicBaseUrl gives a deployment reached by several names one.",
                    if iss.is_empty() { "no issuer".to_string() } else { format!("\"{}\"", iss) },
                    base,
                    self.issuer_for(base)
                ),
            });
        }
        let held = Self::audiences_of(claims.get("aud"));
        if let Some(rule) = audience {
            if (rule.names)(&held) {
                return None;
            }
            return Some(Refusal {
                error: "invalid_token",
                code: codes::STS_OAUTH_0506,
                description: format!(
                    "RFC 9068 section 4: an access token is audience-restricted, and this resource answers for \
                     {}. This token names {}. Ask for a token addressed to it — a resource parameter or a scope \
                     naming the application.",
                    rule.label,
                    Self::quoted(&held)
                ),
            });
        }
        if held
            .iter()
            .any(|one| Self::is_own_resource_audience(one, base))
        {
            return None;
        }
        Some(Refusal {
            error: "invalid_token",
            code: codes::STS_OAUTH_0114,
            description: format!(
                "RFC 9068 section 4 and RFC 9700 section 2.3: an access token is audience-restricted, and a \
                 resource server MUST refuse one whose aud does not name it. This token names {}, and the \
                 endpoints here are the resource server \"{}\" (or that of a named authorization server under \
                 {}). A token narrowed with RFC 8707's resource parameter, or addressed to an API by a scope \
                 naming it, is usable at THAT resource server and nowhere else.",
                Self::quoted(&held),
                Self::default_audience_for(base),
                base
            ),
        })
    }
}

/// `String(x)` for a claim: a string as itself, anything else as JSON.
fn text_of(value: &Json) -> String {
    match value {
        Json::String(s) => s.clone(),
        other => other.to_string(),
    }
}
