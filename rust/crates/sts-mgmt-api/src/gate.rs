// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The access-token half of `/admin-api`'s gate (`registerGate()`), in
//! Node's order and with Node's codes and answers.
//!
//! * **The SERVICE credential is verified against the DEFAULT realm's key**,
//!   wherever the API is reached: a realm's key minting the service
//!   administrator credential is the hole that key keeps shut. (A realm's
//!   OWN token, believed under its prefix only, is a later piece.)
//! * **RFC 9068 section 4's order**: the type before the issuer, both
//!   before the audience; an issuer is an address, matched against the
//!   authorization servers published at the API's base.
//! * **A sender-constrained token is held to its constraint here too** —
//!   the certificate (RFC 8705, STS-API-0110) and the DPoP proof (RFC 9449,
//!   STS-API-0120 and the proof's own code): this gate verifies its own
//!   token, so it has to ask for itself.
//! * **What it answers**: the claims and the scope the request needs
//!   (`admin:read` for a GET, `admin:write` otherwise, `device:compliance`
//!   for the MDM feed). The caller then makes the declared-scope, role and
//!   access-policy steps (STS-API-0123, 0125, 0005), which need the
//!   application and role registers.

use serde_json::Value as Json;
use sts_core::errors::{codes, ErrorCode};
use sts_core::settings::{keys, Settings, Source};
use sts_crypto::jws::ClaimChecks;
use sts_crypto::keys::KeyPolicy;
use sts_oauth::dpop::{verify_proof, ProofContext, ProofRequest};
use sts_oauth::jwt_access_token::JwtAccessTokens;
use sts_oauth::mtls::{
    bound_thumbprint_of, certificate_thumbprint, check_binding,
};
use sts_oauth::sender_constraints::{
    access_token_dpop_required, access_token_refusal, Presented,
};
use sts_store::key_sets::KeySet;

/// The API's path.
pub const BASE: &str = "/admin-api";

/// What arrived.
#[derive(Clone, Copy, Debug, Default)]
pub struct Arrived<'a> {
    pub method: &'a str,
    pub authorization: Option<&'a str>,
    pub dpop: Option<&'a str>,
    /// The URI a DPoP proof must name (`htuOf()`).
    pub htu: &'a str,
    /// The request's base URL as the DEFAULT realm sees it (`baseUrlOf()`).
    pub base: &'a str,
    /// The connection's client certificate, DER.
    pub certificate: Option<&'a [u8]>,
    pub certificate_verified: bool,
    pub mtls_available: bool,
    /// The device compliance feed, the one operation that is not an
    /// administrator's.
    pub mdm_feed: bool,
    pub now: i64,
}

/// What the gate reads besides the request.
pub struct Gate<'a> {
    pub settings: &'a Settings,
    /// The default realm's key set.
    pub keys: &'a KeySet,
    pub tokens: &'a JwtAccessTokens,
    /// The revoked-token register.
    pub revoked: &'a dyn Fn(&str) -> bool,
    /// Whether a person's account is disabled.
    pub disabled: &'a dyn Fn(&str) -> bool,
    pub dpop: &'a dyn ProofContext,
    pub eddsa_curve: &'a str,
}

/// A refusal, as the gate answers it.
#[derive(Clone, Debug, PartialEq)]
pub struct Refused {
    pub status: u16,
    pub error: &'static str,
    pub code: ErrorCode,
    pub www_authenticate: Option<String>,
    /// Answer with a fresh `DPoP-Nonce`.
    pub nonce_wanted: bool,
    pub message: String,
}

/// An admitted token.
#[derive(Clone, Debug, PartialEq)]
pub struct Admitted {
    pub claims: Json,
    /// The scope the request needs.
    pub needed_scope: &'static str,
    pub scheme: String,
}

/// `presentedTokenOf()`: the token and its scheme, Bearer or DPoP.
pub fn presented_token_of(authorization: Option<&str>) -> (String, String) {
    let said = authorization.unwrap_or("").trim();
    let mut parts = said.splitn(2, char::is_whitespace);
    let scheme = parts.next().unwrap_or("").to_lowercase();
    let token = parts.next().unwrap_or("").trim();
    if (scheme == "bearer" || scheme == "dpop")
        && !token.is_empty()
        && !token.contains(char::is_whitespace)
    {
        (token.to_string(), scheme)
    } else {
        (String::new(), String::new())
    }
}

/// `wantedAudiences()`: a pinned `adminApi.audience` alone; otherwise the
/// process's address of the API, and the request's.
pub fn wanted_audiences(settings: &Settings, base: &str) -> Vec<String> {
    let pinned = settings
        .value(keys::ADMIN_API_AUDIENCE)
        .as_str()
        .trim()
        .to_string();
    if !pinned.is_empty()
        && !matches!(
            settings.source_of(keys::ADMIN_API_AUDIENCE),
            Source::Defaults | Source::Default
        )
    {
        return vec![pinned];
    }
    let mut wanted = vec![if pinned.is_empty() {
        settings.management_api_base_url()
    } else {
        pinned
    }];
    let from_request = format!("{}{}", base, BASE);
    if !wanted.contains(&from_request) {
        wanted.push(from_request);
    }
    wanted
}

fn needed_scope(arrived: &Arrived) -> &'static str {
    if arrived.mdm_feed {
        "device:compliance"
    } else if arrived.method.eq_ignore_ascii_case("GET") {
        "admin:read"
    } else {
        "admin:write"
    }
}

fn invalid(code: ErrorCode, scope: &str, message: String) -> Refused {
    Refused {
        status: 401,
        error: "invalid_token",
        code,
        www_authenticate: Some(format!(
            "Bearer error=\"invalid_token\", scope=\"{}\"",
            scope
        )),
        nonce_wanted: false,
        message,
    }
}

impl Gate<'_> {
    fn issuer_accepted(&self, claims: &Json, base: &str) -> bool {
        let iss = claims.get("iss").and_then(Json::as_str).unwrap_or("");
        let mut bases: Vec<String> = Vec::new();
        let mut add = |url: String| {
            if url.len() > BASE.len() && url.ends_with(BASE) {
                let b = url[..url.len() - BASE.len()].to_string();
                if !bases.contains(&b) {
                    bases.push(b);
                }
            }
        };
        for one in wanted_audiences(self.settings, base) {
            add(one);
        }
        add(format!("{}{}", base, BASE));
        add(self.settings.management_api_base_url());
        bases.iter().any(|b| self.tokens.is_hosted_issuer(iss, b))
    }

    /// The gate's token half: `Ok` with the claims, or how to refuse.
    pub fn check(&self, arrived: &Arrived) -> Result<Admitted, Refused> {
        let scope = needed_scope(arrived);
        let (token, scheme) = presented_token_of(arrived.authorization);
        if token.is_empty() {
            let asked = if arrived.mdm_feed {
                scope
            } else {
                "admin:read admin:write"
            };
            return Err(Refused {
                status: 401,
                error: "unauthorized",
                code: codes::STS_API_0001,
                www_authenticate: Some(format!("Bearer realm=\"{}\", scope=\"{}\"", BASE, asked)),
                nonce_wanted: false,
                message: format!(
                    "This API requires an OAuth 2.0 access token. Ask /oauth2/token for one with \
                     `grant_type=client_credentials`, `scope={}` and `resource={}`, then send it as \
                     `Authorization: Bearer`. adminApi.authRequired turns this off.",
                    asked,
                    wanted_audiences(self.settings, arrived.base).last().cloned().unwrap_or_default()
                ),
            });
        }
        let checks = ClaimChecks {
            now: Some(arrived.now),
            ..Default::default()
        };
        let Ok(claims) = self.keys.verify_own_jws(
            &token,
            None,
            &checks,
            KeyPolicy::STRICT,
            self.eddsa_curve,
            arrived.now as f64 * 1000.0,
        ) else {
            return Err(invalid(codes::STS_API_0002, scope,
                "That access token was not issued by this service, or its signature does not verify. Tokens are \
                 signed with the key at /oauth2/jwks and that key is regenerated on every start in development mode."
                    .into()));
        };
        if let Some(exp) = claims.get("exp").and_then(Json::as_i64) {
            if exp <= arrived.now {
                return Err(invalid(
                    codes::STS_API_0003,
                    scope,
                    format!("That access token expired at {}.", exp),
                ));
            }
        }
        let jti = claims.get("jti").and_then(Json::as_str).unwrap_or("");
        let person = claims.get("sub").and_then(Json::as_str).unwrap_or("");
        let client =
            claims.get("client_id").and_then(Json::as_str).unwrap_or("");
        if (!jti.is_empty() && (self.revoked)(jti))
            || (!person.is_empty()
                && person != client
                && (self.disabled)(person))
        {
            return Err(invalid(codes::STS_API_0122, scope,
                "That access token has been revoked, or the account it was issued to is disabled.".into()));
        }
        let typ = JwtAccessTokens::typ_of(&token);
        if !JwtAccessTokens::is_access_token_type(&typ) {
            return Err(invalid(codes::STS_API_0082, scope, format!(
                "RFC 9068 section 4: a JWT access token's typ header must be \"at+jwt\", and this token's is {}. An ID \
                 Token or a refresh token is not an access token, and a token minted before this service issued at+jwt \
                 is refused too; ask /oauth2/token for a new one.",
                if typ.is_empty() { "absent".to_string() } else { format!("\"{}\"", typ) })));
        }
        if !self.issuer_accepted(&claims, arrived.base) {
            return Err(invalid(codes::STS_API_0083, scope, format!(
                "RFC 9068 section 4: the iss claim must exactly match an issuer this service publishes, and this token \
                 names {}. An issuer is an address, so a token minted under one host name is refused under another; \
                 mint it at the address you call this API at, or set global.publicBaseUrl.",
                claims.get("iss").cloned().unwrap_or(Json::Null))));
        }
        let wanted = wanted_audiences(self.settings, arrived.base);
        let held: Vec<String> = match claims.get("aud") {
            Some(Json::Array(list)) => list
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| v.to_string())
                })
                .collect(),
            Some(Json::String(s)) => vec![s.clone()],
            Some(Json::Null) | None => Vec::new(),
            Some(other) => vec![other.to_string()],
        };
        if !held.iter().any(|a| wanted.contains(a)) {
            return Err(Refused {
                status: 403,
                error: "forbidden",
                code: codes::STS_API_0004,
                www_authenticate: None,
                nonce_wanted: false,
                message: format!(
                    "That access token is for a different audience. It carries {} and this API answers to {}. A bearer \
                     token minted for another resource server must not be replayable here, which is what `aud` is for.",
                    claims.get("aud").cloned().unwrap_or(Json::Null),
                    wanted.iter().map(|a| format!("\"{}\"", a)).collect::<Vec<_>>().join(" or ")),
            });
        }
        if let Some(r) = check_binding(&claims, arrived.certificate, true, None)
        {
            return Err(invalid(codes::STS_API_0110, scope, r.description));
        }
        let bound_jkt = claims
            .pointer("/cnf/jkt")
            .and_then(Json::as_str)
            .unwrap_or("");
        let mut proof_ok = false;
        if !bound_jkt.is_empty() {
            if scheme != "dpop" {
                return Err(Refused {
                    status: 401,
                    error: "invalid_token",
                    code: codes::STS_API_0120,
                    www_authenticate: Some(format!("DPoP error=\"invalid_token\", scope=\"{}\"", scope)),
                    nonce_wanted: false,
                    message: "That access token is DPoP-bound (it carries cnf.jkt), so it must be sent as \
                              \"Authorization: DPoP <token>\" with a DPoP proof — not as a Bearer token. Presenting it \
                              as a bearer token would throw the binding away."
                        .into(),
                });
            }
            let request = ProofRequest {
                htm: arrived.method,
                htu: arrived.htu,
                access_token: Some(&token),
                expected_jkt: Some(bound_jkt),
                now: arrived.now,
            };
            if let Err(f) = verify_proof(arrived.dpop, &request, self.dpop) {
                return Err(Refused {
                    status: 401,
                    error: "invalid_dpop_proof",
                    code: f.code,
                    www_authenticate: Some(if f.need_nonce {
                        "DPoP error=\"use_dpop_nonce\"".to_string()
                    } else {
                        format!(
                            "DPoP error=\"invalid_dpop_proof\", scope=\"{}\"",
                            scope
                        )
                    }),
                    nonce_wanted: f.need_nonce,
                    message: f.description,
                });
            }
            proof_ok = true;
        }
        let bound_thumbprint = bound_thumbprint_of(&claims);
        let presented = Presented {
            where_: "the management API",
            bound_jkt,
            proof_ok,
            bound_thumbprint: &bound_thumbprint,
            certificate: arrived.certificate.is_some(),
            certificate_matches: !bound_thumbprint.is_empty()
                && arrived.certificate_verified
                && arrived.certificate.map(certificate_thumbprint).as_deref()
                    == Some(bound_thumbprint.as_str()),
            mtls_available: arrived.mtls_available,
        };
        if let Some(r) = access_token_refusal(self.settings, &presented) {
            return Err(Refused {
                status: 401,
                error: r.error,
                code: r.code,
                www_authenticate: Some(format!(
                    "{} error=\"{}\", scope=\"{}\"",
                    if access_token_dpop_required(self.settings) {
                        "DPoP"
                    } else {
                        "Bearer"
                    },
                    r.error,
                    scope
                )),
                nonce_wanted: false,
                message: r.description,
            });
        }
        Ok(Admitted {
            claims,
            needed_scope: scope,
            scheme,
        })
    }
}
