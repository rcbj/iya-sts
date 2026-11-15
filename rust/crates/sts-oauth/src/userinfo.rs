// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE USERINFO ENDPOINT (`oauth2.ts`'s `userinfoResponse()`, OIDC Core
//! section 5.3), GET and POST, and the check every protected endpoint of
//! this service shares in front of it (`dpop.ts`'s
//! `presentedAccessToken()`).
//!
//! THE TOKEN. From the `Authorization` header, `Bearer` or `DPoP`, or —
//! RFC 6750 section 2.2, which section 5.3.1 has this endpoint accept — a
//! form-encoded POST body's `access_token`; both at once, or two in the
//! body, is refused (`STS-OAUTH-0571`). A token in the QUERY is refused in
//! RFC 9700 mode only, as Node's is (`STS-OAUTH-0115`), and otherwise
//! simply not read. A token this realm signed is verified with any
//! generation of its key and held to RFC 9068 section 4 (`typ`, `iss`,
//! `aud`); its certificate binding (RFC 8705) and its DPoP binding are
//! checked, a bound token presented as `Bearer` is refused
//! (`STS-OAUTH-0117`), the two settings that REQUIRE a constraint are
//! applied, and a DPoP proof is verified against the nonce store and the
//! replay history with its `jti` reserved across the cluster — a resource
//! server's nonce request being a 401 `use_dpop_nonce`, never the
//! authorization server's 400.
//!
//! THE ANSWER. A token that did not verify is 401 with the reason in the
//! words a person debugging it needs (`tokenFailure()`); one that is not an
//! access token (`typ`), was revoked, or lacks `openid` is refused with
//! Node's sentence and challenge. The body is the scope claims of section
//! 5.4 — the person object first, then the person's directory entry
//! through the claim catalogue's rows (`claimsNamed()`), `updated_at`
//! from the entry's `modifyTimestamp` and `phone_number_verified: false`
//! beside a number — and `sub` LAST, the client's own (pairwise or
//! ephemeral, the one its ID Token carried). Plain JSON, pretty-printed as
//! `JSON.stringify(body, null, 2)`, unless the client registered
//! `userinfo_signed_response_alg` (a JWT with `iss`, `aud` and `typ:
//! "UserInfo"` first, HMAC under its secret) and/or
//! `userinfo_encrypted_response_alg` (a JWE to its key, `cty: JWT` over a
//! signed one, `enc` the registered one or the realm's default). A
//! registration that cannot be honoured is a 500 with its sentence
//! (`STS-OAUTH-0177`). `Cache-Control: no-store` throughout.
//!
//! WHAT IS NOT HERE, and how this endpoint answers meanwhile: the
//! configured UserInfo claim set (`/admin/userinfo-claims`,
//! `stats.jwtClaims('userinfo')`, which the claim-set slice owns), a claims
//! request sent on THIS request (its `claims` and `claim` parameters are
//! ignored rather than refused; the token's request is answered, through
//! [`crate::requested_claims`], `verified_claims` among it), the Claims
//! Providers, the `did` claim, a step-up
//! requirement on this service's own resource (RFC 9470, off unless
//! configured), FAPI 2.0 HTTP Signatures, opaque access tokens (#501, off
//! by default: a handle is read as a foreign token), and a claim the
//! directory entry does not hold, which Node INVENTS in a realm that
//! invents claim values (`vc_claims.ts`' persona) and this endpoint
//! leaves out.

use std::sync::Arc;

use serde_json::{json, Map, Value as Json};
use sts_core::errors::{codes, ErrorCode};

use crate::answer::{Answer, Body};
use crate::token_endpoint::TokenEndpoint;

/// The directory a person's claims are read from.
pub trait ClaimDirectory: Send + Sync {
    /// The values of one attribute (any case) of the person's entry under
    /// `ou=users` of the ambient realm; `None` where there is no entry or
    /// the entry does not hold it.
    fn values_of(&self, username: &str, attribute: &str)
        -> Option<Vec<String>>;
}

/// No directory: every claim the person object lacks is absent.
pub struct NoDirectory;

impl ClaimDirectory for NoDirectory {
    fn values_of(&self, _username: &str, _attr: &str) -> Option<Vec<String>> {
        None
    }
}

/// One UserInfo request.
#[derive(Debug, Clone, Default)]
pub struct UserinfoAsk {
    /// `baseUrlOf(req)`, the realm's prefix included.
    pub base: String,
    pub method: String,
    /// `dpop.htuOf(req)`.
    pub htu: String,
    pub authorization: String,
    pub dpop: Option<String>,
    pub content_type: String,
    pub body: String,
    /// The query held `access_token` or `token`.
    pub token_in_query: bool,
    /// The connection's client certificate, DER.
    pub peer_der: Option<Vec<u8>>,
}

/// The token a request presented, as `presentedAccessToken()` answers it.
#[derive(Debug, Clone)]
pub struct PresentedToken {
    pub access_token: String,
    pub claims: Json,
    /// `bearer` or `dpop`.
    pub scheme: String,
    pub jkt: String,
    pub verified: bool,
}

/// The catalogue rows OIDC Core section 5.4's claims are read through
/// (`vc_claims.ts`' `VC_ATTRIBUTES`, in catalogue order): the claim path
/// and the attribute.
pub(crate) const ROWS: [(&[&str], &str); 22] = [
    (&["given_name"], "givenname"),
    (&["family_name"], "sn"),
    (&["email"], "mail"),
    (&["birthdate"], "schacdateofbirth"),
    (&["address", "street_address"], "street"),
    (&["address", "locality"], "l"),
    (&["address", "region"], "st"),
    (&["address", "postal_code"], "postalcode"),
    (&["address", "country"], "c"),
    (&["address", "formatted"], "postaladdress"),
    (&["name"], "cn"),
    (&["nickname"], "displayname"),
    (&["preferred_username"], "uid"),
    (&["phone_number"], "telephonenumber"),
    (&["locale"], "preferredlanguage"),
    (&["website"], "labeleduri"),
    (&["middle_name"], "middlename"),
    (&["gender"], "schacgender"),
    (&["zoneinfo"], "timezone"),
    (&["picture"], "pictureurl"),
    (&["profile"], "profileurl"),
    (&["updated_at"], ""),
];

fn s(v: Option<&Json>) -> String {
    crate::js::string_of(v)
}

// A HOT PATH: read once per catalogue row of every answer, so no span.
pub(crate) fn first_value(
    directory: &dyn ClaimDirectory,
    username: &str,
    attr: &str,
) -> Option<String> {
    directory
        .values_of(username, attr)?
        .into_iter()
        .next()
        .filter(|v| !v.is_empty())
}

/// A row's `toClaim()`: `schacDateOfBirth`'s YYYYMMDD as YYYY-MM-DD, a
/// postal address's `$` as a newline.
// A HOT PATH: once per claim a row produces, so no span.
pub(crate) fn to_claim(attr: &str, value: String) -> String {
    match attr {
        "schacdateofbirth" => {
            let digits: String =
                value.chars().filter(char::is_ascii_digit).collect();
            if digits.len() < 8 {
                value
            } else {
                format!("{}-{}-{}", &digits[0..4], &digits[4..6], &digits[6..8])
            }
        }
        "postaladdress" => value.split('$').collect::<Vec<_>>().join("\n"),
        _ => value,
    }
}

/// `GeneralizedTime` (`20261115121314Z`) as seconds since the epoch.
fn generalized_seconds(text: &str) -> Option<i64> {
    let digits: String =
        text.chars().take_while(char::is_ascii_digit).collect();
    if digits.len() < 14 {
        return None;
    }
    let at =
        chrono::NaiveDateTime::parse_from_str(&digits[..14], "%Y%m%d%H%M%S")
            .ok()?;
    Some(at.and_utc().timestamp())
}

/// `headerSafe(text)`: an HTTP field value is ASCII, and a quote would
/// close the quoted-string early.
fn header_safe(text: &str) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        match ch {
            '\u{2018}' | '\u{2019}' | '\u{201C}' | '\u{201D}' | '"' => {
                out.push('\'')
            }
            '\u{2013}' | '\u{2014}' => out.push('-'),
            '\u{2026}' => out.push_str("..."),
            c if (' '..='~').contains(&c) => out.push(c),
            _ => {}
        }
    }
    out
}

/// `vciError(res, status, error, description)`: JSON, no `no-store`.
fn vci_error(
    code: ErrorCode,
    status: u16,
    error: &str,
    description: &str,
) -> Answer {
    let mut out = Answer::new(
        status,
        Body::Json(json!({ "error": error,
                           "error_description": description })),
    );
    out.set("Content-Type", "application/json; charset=utf-8");
    out.marked(code)
}

/// The UserInfo endpoint.
pub struct UserInfo {
    pub tokens: Arc<TokenEndpoint>,
    pub directory: Arc<dyn ClaimDirectory>,
    pub pairwise: Option<Arc<crate::pairwise::PairwiseSubjects>>,
}

impl UserInfo {
    fn bcp(&self) -> bool {
        let st = &self.tokens.settings;
        st.value_of("oauth2.rfc9700").as_bool()
            || st.value_of("oauth2.oauth21").as_bool()
            || self.tokens.mode.enforces_oauth_security_bcp()
    }

    /// `presentedAccessToken(req, res, where, { formBody: true })`: the
    /// token, or the answer that refused it.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn presented(
        &self,
        ask: &UserinfoAsk,
        r#where: &str,
    ) -> Result<PresentedToken, Answer> {
        if ask.token_in_query && self.bcp() {
            tracing::warn!(
                "RFC 9700 section 4.3.2: a request to {} carried an access \
                 token in the QUERY STRING. Refused. That URL is now in this \
                 client's browser history and in whatever logged the \
                 request.",
                r#where
            );
            let mut a = vci_error(
                codes::STS_OAUTH_0115,
                400,
                "invalid_request",
                "RFC 9700 section 4.3.2: an access token must not be sent in \
                 a URI query parameter. RFC 6750 section 2.3 defines that \
                 form and its own specification does not recommend it, \
                 because a URL ends up in browser history, in the address \
                 bar, in server logs and in the Referer header of anything \
                 the page goes on to fetch — so the token is in all of those \
                 too. This endpoint reads the Authorization header only, and \
                 treat the token you just sent as disclosed.",
            );
            a.set("WWW-Authenticate", "Bearer error=\"invalid_request\"");
            return Err(a);
        }
        let auth = ask.authorization.as_str();
        let mut found = scheme_and_token(auth);
        if ask.method == "POST"
            && ask
                .content_type
                .to_ascii_lowercase()
                .starts_with("application/x-www-form-urlencoded")
        {
            let in_body: Vec<String> =
                url::form_urlencoded::parse(ask.body.as_bytes())
                    .filter(|(k, _)| k == "access_token")
                    .map(|(_, v)| v.into_owned())
                    .collect();
            if !in_body.is_empty() && (!auth.is_empty() || in_body.len() > 1) {
                let mut a = vci_error(
                    codes::STS_OAUTH_0571,
                    400,
                    "invalid_request",
                    &format!(
                        "The access token was sent {}. RFC 6750 section 2: a \
                         client MUST NOT use more than one method to send it \
                         in one request.",
                        if auth.is_empty() {
                            "more than once in the body"
                        } else {
                            "in the Authorization header AND in the body"
                        }
                    ),
                );
                a.set("WWW-Authenticate", "Bearer error=\"invalid_request\"");
                return Err(a);
            }
            if in_body.len() == 1 && auth.is_empty() {
                found = Some(("bearer".to_string(), in_body[0].clone()));
            }
        }
        let Some((scheme, token)) = found else {
            let mut a = vci_error(
                codes::STS_OAUTH_0116,
                401,
                "invalid_token",
                "An access token is required, presented as \"Bearer \
                 <token>\" or, when it is DPoP-bound, as \"DPoP <token>\" \
                 with a DPoP proof.",
            );
            a.set(
                "WWW-Authenticate",
                &format!(
                    "DPoP algs=\"{}\", Bearer",
                    crate::dpop::signing_algs().join(" ")
                ),
            );
            return Err(a);
        };
        let now = self.tokens.clock.now_s();
        let (claims, verified) =
            match self.tokens.signer.verify_own(&token, now) {
                Ok(c) => (c, true),
                Err(e) => {
                    tracing::debug!(
                    "This access token is not one of ours, so its claims are \
                     read unverified: {}",
                    e
                );
                    (unverified_claims(&token), false)
                }
            };
        let bound = jkt_of(&claims);
        let invalid = |refusal_code: ErrorCode, error: &str, d: &str| {
            let mut a = vci_error(refusal_code, 401, error, d);
            a.set("WWW-Authenticate", "Bearer error=\"invalid_token\"");
            a
        };
        if verified {
            let rule = crate::jwt_access_token::JwtAccessTokens::new(
                self.tokens.settings.clone(),
            );
            if let Some(p) =
                rule.resource_server_refusal(&token, &claims, &ask.base, None)
            {
                return Err(invalid(p.code, p.error, &p.description));
            }
        }
        if let Some(p) = crate::mtls::check_binding(
            &claims,
            ask.peer_der.as_deref(),
            verified,
            None,
        ) {
            return Err(invalid(p.code, p.error, &p.description));
        }
        if !bound.is_empty() && scheme != "dpop" {
            let mut a = vci_error(
                codes::STS_OAUTH_0117,
                401,
                "invalid_token",
                "This access token is DPoP-bound (it carries cnf.jkt), so it \
                 must be presented as \"Authorization: DPoP <token>\" with a \
                 DPoP proof — not as a Bearer token.",
            );
            a.set(
                "WWW-Authenticate",
                "DPoP error=\"invalid_token\", error_description=\"the token \
                 is DPoP-bound and must be presented with the DPoP scheme\"",
            );
            return Err(a);
        }
        let bound_thumbprint = crate::mtls::bound_thumbprint_of(&claims);
        let presented_thumbprint = ask
            .peer_der
            .as_deref()
            .map(crate::mtls::certificate_thumbprint)
            .unwrap_or_default();
        let required = crate::sender_constraints::access_token_refusal(
            &self.tokens.settings,
            &crate::sender_constraints::Presented {
                where_: r#where,
                bound_jkt: &bound,
                proof_ok: ask.dpop.is_some(),
                bound_thumbprint: &bound_thumbprint,
                certificate: ask.peer_der.is_some(),
                certificate_matches: !bound_thumbprint.is_empty()
                    && presented_thumbprint == bound_thumbprint,
                mtls_available: false,
                client_bound:
                    crate::sender_constraints::dpop_bound_public_client(
                        &s(claims.get("client_id")),
                        "",
                    ),
            },
        );
        if let Some(r) = required {
            let scheme_word =
                if crate::sender_constraints::access_token_dpop_required(
                    &self.tokens.settings,
                ) {
                    "DPoP"
                } else {
                    "Bearer"
                };
            let mut a = vci_error(r.code, 401, r.error, &r.description);
            a.set(
                "WWW-Authenticate",
                &format!("{} error=\"{}\"", scheme_word, r.error),
            );
            return Err(a);
        }
        if bound.is_empty() && ask.dpop.is_none() {
            return Ok(PresentedToken {
                access_token: token,
                claims,
                scheme,
                jkt: String::new(),
                verified,
            });
        }
        let checked = self.proof(ask, &token, &bound).await;
        match checked {
            Ok(proof) => Ok(PresentedToken {
                access_token: token,
                claims,
                scheme,
                jkt: proof.jkt,
                verified,
            }),
            Err(f) if f.need_nonce => {
                let mut a = vci_error(
                    f.code,
                    401,
                    "use_dpop_nonce",
                    "Resource server requires nonce in DPoP proof",
                );
                if let Ok(n) = self.tokens.dpop.issue_nonce() {
                    a.set("DPoP-Nonce", &n);
                }
                a.set(
                    "WWW-Authenticate",
                    "DPoP error=\"use_dpop_nonce\", error_description=\
                     \"Resource server requires nonce in DPoP proof\"",
                );
                Err(a)
            }
            Err(f) => {
                let mut a = vci_error(
                    f.code,
                    401,
                    "invalid_dpop_proof",
                    &f.description,
                );
                a.set("WWW-Authenticate", "DPoP error=\"invalid_dpop_proof\"");
                Err(a)
            }
        }
    }

    /// `verifyProof()` for a resource request, its `jti` reserved first.
    async fn proof(
        &self,
        ask: &UserinfoAsk,
        token: &str,
        bound: &str,
    ) -> Result<crate::dpop::Proof, crate::dpop::Failure> {
        let tokens = &self.tokens;
        crate::dpop_reservation::verify_reserved(
            tokens.claims.as_ref(),
            tokens.dpop.as_ref(),
            ask.dpop.as_deref(),
            &crate::dpop::ProofRequest {
                htm: &ask.method,
                htu: &ask.htu,
                access_token: Some(token),
                expected_jkt: (!bound.is_empty()).then_some(bound),
                now: tokens.clock.now_s(),
            },
        )
        .await
    }

    /// `tokenFailure(token)`: why a token did not verify.
    fn token_failure(&self, token: &str, why: &str) -> String {
        let claims = unverified_claims(token);
        let now = self.tokens.clock.now_s();
        let exp = claims.get("exp").and_then(Json::as_f64);
        let nbf = claims.get("nbf").and_then(Json::as_f64);
        if let Some(exp) = exp.filter(|e| (*e as i64) <= now) {
            let at = chrono::DateTime::from_timestamp(exp as i64, 0)
                .map(|d| d.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
                .unwrap_or_default();
            return format!("This access token expired at {}.", at);
        }
        if nbf.is_some_and(|n| (n as i64) > now) {
            return "This access token is not valid yet (nbf is in the \
                    future)."
                .to_string();
        }
        format!(
            "This access token was not issued by this server, or its \
             signature does not verify against the key at /oauth2/jwks ({}). \
             Unlike the OID4VCI credential endpoints, UserInfo cannot accept \
             a token from a separate authorization server: it has nothing to \
             say about a subject it did not authenticate.",
            why
        )
    }

    /// `claimsNamed(user, wanted)`: the person object first, then the
    /// directory entry through the catalogue's rows.
    fn claims_named(&self, user: &Json, wanted: &[&str]) -> Map<String, Json> {
        let mut out = Map::new();
        let mut missing: Vec<&str> = Vec::new();
        for claim in wanted {
            match user.get(*claim) {
                None | Some(Json::Null) => missing.push(claim),
                Some(Json::String(t)) if t.is_empty() => missing.push(claim),
                Some(v) => {
                    out.insert(claim.to_string(), v.clone());
                }
            }
        }
        let username = s(user.get("username"));
        let directory = self.directory.as_ref();
        if !username.is_empty() && !missing.is_empty() {
            let mut address = Map::new();
            for (path, attr) in ROWS {
                if attr.is_empty() || !missing.contains(&path[0]) {
                    continue;
                }
                let Some(value) = first_value(directory, &username, attr)
                else {
                    continue;
                };
                let value = to_claim(attr, value);
                if path.len() > 1 {
                    address.insert(path[1].to_string(), json!(value));
                } else {
                    out.insert(path[0].to_string(), json!(value));
                }
            }
            if !address.is_empty() {
                out.insert("address".into(), Json::Object(address));
            }
            if missing.contains(&"updated_at") {
                if let Some(at) =
                    first_value(directory, &username, "modifyTimestamp")
                        .and_then(|t| generalized_seconds(&t))
                {
                    out.insert("updated_at".into(), json!(at));
                }
            }
        }
        if wanted.contains(&"phone_number_verified")
            && out.contains_key("phone_number")
            && !out.contains_key("phone_number_verified")
        {
            out.insert("phone_number_verified".into(), Json::Bool(false));
        }
        out
    }

    /// `scopeClaimsOf(user, scope)`: every claim of the section 5.4 scopes
    /// granted.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn scope_claims_of(
        &self,
        user: &Json,
        scope: &str,
    ) -> Map<String, Json> {
        let granted: Vec<&str> = scope.split_whitespace().collect();
        let mut wanted: Vec<&str> = Vec::new();
        for (name, claims) in crate::token_endpoint::SCOPE_CLAIMS {
            if granted.contains(&name) {
                wanted.extend_from_slice(claims);
            }
        }
        self.claims_named(user, &wanted)
    }

    /// `userinfoResponse(req, res)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn answer(&self, ask: &UserinfoAsk) -> Answer {
        let presented = match self.presented(ask, "the userinfo endpoint").await
        {
            Ok(p) => p,
            Err(a) => return a,
        };
        let challenge = |code: ErrorCode,
                         status: u16,
                         error: &str,
                         description: &str,
                         extra: &str| {
            let scheme = if presented.scheme == "dpop" {
                "DPoP"
            } else {
                "Bearer"
            };
            let mut a = Answer::refusal(code, status, error, description);
            a.set(
                "WWW-Authenticate",
                &format!(
                    "{} error=\"{}\", error_description=\"{}\"{}",
                    scheme,
                    error,
                    header_safe(description),
                    extra
                ),
            );
            a
        };
        if !presented.verified {
            let why = self
                .tokens
                .signer
                .verify_own(&presented.access_token, self.tokens.clock.now_s())
                .err()
                .unwrap_or_default();
            return challenge(
                codes::STS_OAUTH_0172,
                401,
                "invalid_token",
                &self.token_failure(&presented.access_token, &why),
                "",
            );
        }
        let claims = &presented.claims;
        let typ = s(claims.get("typ"));
        if typ != "Bearer" {
            return challenge(
                codes::STS_OAUTH_0173,
                401,
                "invalid_token",
                &format!(
                    "This is a \"{}\" token, not an access token. Every token \
                     this server issues is an RS256 JWT signed with the same \
                     key, so the typ claim is the only thing that tells a \
                     refresh token or an id_token apart from the access token \
                     UserInfo needs.",
                    if typ.is_empty() { "unknown" } else { &typ }
                ),
                "",
            );
        }
        let jti = s(claims.get("jti"));
        if self.tokens.register.is_revoked(&jti) {
            return challenge(
                codes::STS_OAUTH_0174,
                401,
                "invalid_token",
                "This access token was revoked at /oauth2/revoke. \
                 Introspection reports it inactive, and UserInfo answers the \
                 same way — a revocation that only some endpoints honoured \
                 would be worse than none.",
                "",
            );
        }
        let scope = s(claims.get("scope"));
        if !scope.split_whitespace().any(|one| one == "openid") {
            return challenge(
                codes::STS_OAUTH_0175,
                403,
                "insufficient_scope",
                &format!(
                    "UserInfo needs an access token issued with the \"openid\" \
                     scope; this one was issued with {}. A client_credentials \
                     or token-exchange token has no end-user behind it, so \
                     there is no profile to return.",
                    if scope.is_empty() {
                        "no scope at all".to_string()
                    } else {
                        format!("\"{}\"", scope)
                    }
                ),
                ", scope=\"openid\"",
            );
        }
        let sub = s(claims.get("sub"));
        let name = self
            .tokens
            .people
            .name_for_subject(&sub)
            .unwrap_or_else(|| s(claims.get("username")));
        let user = self.tokens.people.user_for(&name);
        let mut body = self.scope_claims_of(&user, &scope);
        // OIDC Core 5.5's `userinfo` member, as the access token carries
        // the request the authorization endpoint understood
        // (`mergedUserinfoRequest()`), `verified_claims` among it. A claim
        // named beats the scope's (`requestedClaimsOf()`).
        if let Some(requested) = &self.tokens.requested {
            let request =
                crate::requested_claims::RequestedClaims::merged_userinfo(
                    claims.get("claims").filter(|c| c.is_object()),
                    None,
                );
            if request.is_some() {
                for (k, v) in
                    requested.answer(request.as_ref(), "userinfo", &name, &user)
                {
                    body.insert(k, v);
                }
            }
        }
        let client_id = s(claims.get("client_id"));
        let local = if sub.is_empty() {
            s(user.get("sub"))
        } else {
            sub
        };
        let session = match s(claims.get("sid")) {
            sid if !sid.is_empty() => sid,
            _ => self.session_of(&jti),
        };
        let client_sub = match &self.pairwise {
            None => Ok(local.clone()),
            Some(p) => p.subject_for(&client_id, &local, &session),
        };
        let client_sub = match client_sub {
            Ok(v) => v,
            Err(why) => {
                tracing::error!(
                    "{}userinfoResponse(): {}",
                    sts_core::log::tag(codes::STS_OAUTH_0177),
                    why
                );
                return Answer::refusal(
                    codes::STS_OAUTH_0177,
                    500,
                    "server_error",
                    &why,
                );
            }
        };
        body.insert("sub".into(), json!(client_sub));
        let registered = self.tokens.clients.client_config_of(&client_id);
        match self.protect(
            Json::Object(body),
            &registered,
            &ask.base,
            &client_id,
        ) {
            Ok((content_type, text)) => {
                let mut a = Answer::new(200, Body::Raw(text));
                a.set("Content-Type", &content_type);
                a.set("Cache-Control", "no-store");
                a
            }
            Err(why) => {
                tracing::error!(
                    "{}userinfoResponse(): the registered response protection \
                     could not be applied: {}",
                    sts_core::log::tag(codes::STS_OAUTH_0177),
                    why
                );
                Answer::refusal(
                    codes::STS_OAUTH_0177,
                    500,
                    "server_error",
                    &why,
                )
            }
        }
    }

    /// `stats.sessionIdOfJti(jti)`.
    fn session_of(&self, jti: &str) -> String {
        self.tokens
            .register
            .get(&sts_core::realm::current_id(), jti)
            .map(|r| s(r.get("sessionId")))
            .unwrap_or_default()
    }

    /// `protectUserinfo(body, registered, base, claims)`: the content type
    /// and the body, or the sentence that refuses the registration.
    fn protect(
        &self,
        body: Json,
        registered: &Json,
        base: &str,
        client_id: &str,
    ) -> Result<(String, String), String> {
        let sign_alg = match s(registered.get("userinfo_signed_response_alg")) {
            a if a.is_empty() => "none".to_string(),
            a => a,
        };
        let enc_alg = s(registered.get("userinfo_encrypted_response_alg"));
        let mode = &self.tokens.mode;
        let enc_enc = if enc_alg.is_empty() {
            String::new()
        } else {
            match s(registered.get("userinfo_encrypted_response_enc")) {
                e if !e.is_empty() => e,
                _ if mode.allows_cbc_jwe() => "A128CBC-HS256".to_string(),
                _ => "A256GCM".to_string(),
            }
        };
        // `JSON.stringify(body, null, 2)`.
        let pretty = || serde_json::to_string_pretty(&body).unwrap_or_default();
        if sign_alg == "none" && enc_alg.is_empty() {
            return Ok(("application/json; charset=utf-8".into(), pretty()));
        }
        let signing = crate::metadata::USERINFO_SIGNING_ALG_VALUES_SUPPORTED;
        if sign_alg != "none"
            && (!signing.contains(&sign_alg.as_str())
                || !self.fapi_allows(&sign_alg))
        {
            return Err(format!(
                "This client registered userinfo_signed_response_alg=\"{}\" \
                 and this service signs with {} (see \
                 userinfo_signing_alg_values_supported).",
                sign_alg,
                signing.join(", ")
            ));
        }
        let offered: Vec<&str> =
            crate::metadata::AUTHORIZATION_ENCRYPTION_ALG_VALUES_SUPPORTED
                .iter()
                .copied()
                .filter(|a| mode.allows_legacy_hashes() || *a != "RSA-OAEP")
                .collect();
        if !enc_alg.is_empty() && !offered.contains(&enc_alg.as_str()) {
            return Err(format!(
                "This client registered userinfo_encrypted_response_alg=\"{}\" \
                 and this service encrypts a UserInfo response with {} (see \
                 userinfo_encryption_alg_values_supported). The symmetric \
                 algorithms in this service's JWE table are for a document \
                 encrypted TO it, where both ends hold the key; there is no \
                 shared key here, only the one you registered.",
                enc_alg,
                offered.join(", ")
            ));
        }
        let encs =
            crate::metadata::AUTHORIZATION_ENCRYPTION_ENC_VALUES_SUPPORTED;
        if !enc_alg.is_empty() && !encs.contains(&enc_enc.as_str()) {
            return Err(format!(
                "This client asked for userinfo_encrypted_response_enc=\"{}\" \
                 and this service encrypts with {} (see \
                 userinfo_encryption_enc_values_supported).",
                enc_enc,
                encs.join(", ")
            ));
        }
        let inner = if sign_alg == "none" {
            pretty()
        } else {
            self.sign(body, &sign_alg, registered, base, client_id)?
        };
        if enc_alg.is_empty() {
            return Ok(("application/jwt; charset=utf-8".into(), inner));
        }
        let jwk = crate::jarm::recipient_key(
            registered,
            &enc_alg,
            "userinfo_encrypted_response_alg",
        )?;
        let jwe = sts_crypto::jwe::encrypt_compact(
            inner.as_bytes(),
            &sts_crypto::jwe::EncryptOptions {
                alg: Some(&enc_alg),
                enc: &enc_enc,
                typ: Some("JWT"),
                cty: (sign_alg != "none").then_some("JWT"),
                jwk: Some(&jwk),
                ..sts_crypto::jwe::EncryptOptions::default()
            },
        )
        .map_err(|e| e.to_string())?;
        Ok(("application/jwt; charset=utf-8".into(), jwe))
    }

    /// `fapi.signingAlgAllowed(alg)`.
    fn fapi_allows(&self, alg: &str) -> bool {
        match crate::authorization_servers::fapi_profile(&self.tokens.settings)
            .as_str()
        {
            "1-advanced" => ["PS256", "ES256"].contains(&alg),
            "2-security" | "2-message-signing" => {
                ["PS256", "ES256", "EdDSA"].contains(&alg)
            }
            _ => true,
        }
    }

    /// `signUserinfo(body, alg, registered, base, claims)`: `iss`, `aud`
    /// and `typ: "UserInfo"` first, then the body.
    fn sign(
        &self,
        body: Json,
        alg: &str,
        registered: &Json,
        base: &str,
        client_id: &str,
    ) -> Result<String, String> {
        let mut payload = Map::new();
        payload.insert(
            "iss".into(),
            json!(crate::jwt_access_token::JwtAccessTokens::new(
                self.tokens.settings.clone()
            )
            .issuer_for(base)),
        );
        payload.insert("aud".into(), json!(client_id));
        payload.insert("typ".into(), json!("UserInfo"));
        if let Json::Object(m) = body {
            for (k, v) in m {
                payload.insert(k, v);
            }
        }
        if alg.starts_with("HS") {
            let secret = s(registered.get("client_secret"));
            if secret.is_empty() {
                return Err(format!(
                    "{} is signed with the client_secret, and this client has \
                     none — a public client cannot use a symmetric algorithm.",
                    alg
                ));
            }
            let key = sts_crypto::keys::JwsKey::from_jwk(&json!({
                "kty": "oct",
                "k": sts_crypto::b64::encode(secret.as_bytes()),
            }))
            .map_err(|e| e.to_string())?;
            return sts_crypto::jws::sign_jws(
                &payload,
                &key,
                &sts_crypto::jws::SignOptions {
                    algorithm: Some(alg.to_string()),
                    ..sts_crypto::jws::SignOptions::default()
                },
            )
            .map_err(|e| e.to_string());
        }
        self.tokens.signer.sign(&payload, "JWT", alg)
    }
}

/// `^(Bearer|DPoP)\s+(\S+)\s*$`, case-insensitively: the scheme lower-cased
/// and the token.
fn scheme_and_token(auth: &str) -> Option<(String, String)> {
    let trimmed = auth.trim_end();
    let (scheme, rest) = trimmed.split_once(|c: char| c.is_whitespace())?;
    let token = rest.trim_start();
    if token.is_empty() || token.contains(char::is_whitespace) {
        return None;
    }
    let lower = scheme.to_ascii_lowercase();
    (lower == "bearer" || lower == "dpop").then(|| (lower, token.to_string()))
}

/// `jktOf(claims)`: the token's `cnf.jkt`, or `""`.
fn jkt_of(claims: &Json) -> String {
    match claims.get("cnf").and_then(|c| c.get("jkt")) {
        Some(Json::String(t)) => t.clone(),
        _ => String::new(),
    }
}

/// The payload of a JWT read without verifying it, or `{}`.
fn unverified_claims(token: &str) -> Json {
    token
        .split('.')
        .nth(1)
        .and_then(|p| crate::js::node_segment_json(p).ok())
        .filter(Json::is_object)
        .unwrap_or_else(|| json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scheme_is_read_as_node_reads_it() {
        assert_eq!(
            scheme_and_token("bearer abc"),
            Some(("bearer".into(), "abc".into()))
        );
        assert_eq!(
            scheme_and_token("DPoP  abc  "),
            Some(("dpop".into(), "abc".into()))
        );
        assert_eq!(scheme_and_token("Bearer a b"), None);
        assert_eq!(scheme_and_token("Basic abc"), None);
        assert_eq!(scheme_and_token("Bearer"), None);
    }

    #[test]
    fn a_header_value_is_held_to_ascii() {
        assert_eq!(header_safe("a — “b” é"), "a - 'b' ");
    }

    #[test]
    fn the_catalogue_transforms_are_nodes() {
        assert_eq!(
            to_claim("schacdateofbirth", "19800102".into()),
            "1980-01-02"
        );
        assert_eq!(
            to_claim("postaladdress", "1 A St$Town".into()),
            "1 A St\nTown"
        );
        assert_eq!(generalized_seconds("19700101000100Z"), Some(60));
    }
}
