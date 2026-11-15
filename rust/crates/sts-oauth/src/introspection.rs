// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! TOKEN INTROSPECTION (RFC 7662, `oauth2.ts`'s `introspectRequest()`,
//! with RFC 9701's JWT answer, `introspection_jwt.ts`, rule 3ai) AND TOKEN
//! REVOCATION (RFC 7009, `revokeRequest()`, #102), both under the realm and
//! under a named authorization server.
//!
//! THE CALLER (`authenticateEndpointCaller()`). Introspection authenticates
//! its caller as a client where the realm does not open introspection
//! (`mode.opensIntrospection()`, development's) and whenever a JWT answer is
//! asked for (RFC 9701 section 5, `Accept:
//! application/token-introspection+jwt`): a failure is 401 with the Basic
//! challenge (`STS-OAUTH-0292`), or 400 for the JWT answer
//! (`STS-OAUTH-0291`). Revocation authenticates where the realm does not
//! open revocation, or whenever a credential was presented; a public client
//! is identified by its `client_id`, and in development a credential with
//! nothing to verify it against leaves the caller unidentified.
//!
//! THE ANSWER. A token this realm signed (a refresh token opened from its
//! seal first), not revoked, is `active` with Node's members in Node's
//! order; anything else is `{ "active": false }`. An authenticated caller
//! asking about a token not intended for it (not its own, not addressed to
//! it or to this service's own resource) is told it is inactive.
//!
//! REVOCATION revokes an access token's `jti`, or a refresh token's and
//! every member of its grant, the family marked revoked across the cluster;
//! another client's token is `invalid_grant` (`STS-OAUTH-0612`), an ID
//! Token or anything else this realm signed `unsupported_token_type`, and a
//! token that does not verify is answered 200 with nothing revoked.
//!
//! NOT PORTED, and how this answers meanwhile: UMA's gate (`uma_gate.ts`:
//! a PCT, a permission ticket's `permissions`) and Native SSO's device
//! secret at revocation, opaque access tokens (#501, off by default: a
//! handle is inactive), the per-client view of RFC 9396
//! `authorization_details`, a named server's advertised authentication
//! methods (the default advertises every method), and an x5c in a JWT
//! answer's header (`certificateHeader: 'introspection'`).

use serde_json::{json, Map, Value as Json};
use sts_core::errors::codes;

use crate::answer::{Answer, Body};
use crate::bcp::{self, Question};
use crate::client_auth::{MethodHints, PeerCertificate, Presented, Verified};
use crate::token_endpoint::{client_from, TokenEndpoint};

/// `introspection_jwt.MEDIA_TYPE`.
pub const MEDIA_TYPE: &str = "application/token-introspection+jwt";
const TYP: &str = "token-introspection+jwt";

fn s(v: Option<&Json>) -> String {
    crate::js::string_of(v)
}

/// One request to either endpoint.
#[derive(Debug, Clone, Default)]
pub struct EndpointAsk {
    /// `baseUrlOf(req)` (`asBaseOf(req)` under a named server).
    pub base: String,
    pub authorization: String,
    pub accept: String,
    pub body: String,
    pub address: String,
    pub peer: Option<PeerCertificate>,
}

/// How an endpoint words its refusal of a caller that did not
/// authenticate: the code, the status, whether the Basic challenge goes
/// with it, and the description — from the verifier's code and why.
pub(crate) type Refuse = dyn Fn(
        Option<sts_core::errors::ErrorCode>,
        &str,
    ) -> (sts_core::errors::ErrorCode, u16, bool, String)
    + Sync;

/// `authenticateEndpointCaller()`'s answer.
pub(crate) struct Caller {
    pub(crate) client_id: String,
    pub(crate) identified: bool,
}

/// `acceptRanges()` and `qualityOf()`, as `wantsJwt()` reads them.
#[tracing::instrument(level = "debug")]
pub fn wants_jwt(accept: &str) -> bool {
    let ranges: Vec<(String, f64)> = accept
        .split(',')
        .map(|part| {
            let mut pieces = part.split(';');
            let ty = pieces.next().unwrap_or("").trim().to_lowercase();
            let mut q = 1.0;
            for param in pieces {
                let (k, v) = param.split_once('=').unwrap_or((param, ""));
                if k.trim().eq_ignore_ascii_case("q") {
                    let n = crate::js::to_number(&json!(v.trim()));
                    q = if n.is_finite() {
                        n.clamp(0.0, 1.0)
                    } else {
                        0.0
                    };
                }
            }
            (ty, q)
        })
        .filter(|(t, _)| t.find('/').is_some_and(|at| at > 0))
        .collect();
    let Some((_, named)) = ranges.iter().find(|(t, _)| t == MEDIA_TYPE) else {
        return false;
    };
    if *named <= 0.0 {
        return false;
    }
    let mut best: Option<f64> = None;
    let mut rank = 0;
    for (t, q) in &ranges {
        let r = if t == "application/json" {
            3
        } else if t == "application/*" {
            2
        } else if t == "*/*" {
            1
        } else {
            0
        };
        if r > rank {
            rank = r;
            best = Some(*q);
        }
    }
    best.is_none_or(|json| *named >= json)
}

impl TokenEndpoint {
    /// `authenticateEndpointCaller(req, res, body, opts)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub(crate) async fn endpoint_caller(
        &self,
        ask: &EndpointAsk,
        body: &Map<String, Json>,
        path: &str,
        allow_public: bool,
        lenient: bool,
        refuse: &Refuse,
    ) -> Result<Caller, Answer> {
        let client = client_from(&ask.authorization, body);
        let registered = self.clients.client_config_of(&client.client_id);
        let secret_presented = crate::secret_limit::secret_presented(
            client.basic,
            !s(body.get("client_secret")).is_empty(),
            !client.assertion.is_empty(),
            &registered,
        );
        let secret_key = self.limits.as_ref().and_then(|l| {
            (!client.client_id.is_empty() && secret_presented).then(|| {
                l.secret_key(
                    &sts_core::realm::current_id(),
                    &client.client_id,
                    &ask.address,
                )
            })
        });
        if let (Some(l), Some((what, id))) = (&self.limits, &secret_key) {
            if let Some(locked) = l.blocked(what, &ask.address, id).await {
                return Err(self.secret_lockout(&client.client_id, &locked));
            }
        }
        let issuer = crate::jwt_access_token::JwtAccessTokens::new(
            self.settings.clone(),
        )
        .issuer_for(&ask.base);
        let strict = self.settings.value_of("oauth2.oauth21").as_bool()
            || crate::authorization_servers::fapi_profile(&self.settings)
                .starts_with('2');
        let presented = Presented {
            client_id: client.client_id.clone(),
            presented_secret: client.client_secret.clone(),
            assertion: client.assertion.clone(),
            assertion_type: client.assertion_type.clone(),
            audiences: vec![
                format!("{}{}", ask.base, path),
                format!("{}/oauth2/token", ask.base),
                issuer.clone(),
                ask.base.clone(),
            ],
            issuer: issuer.clone(),
            peer: ask.peer.clone(),
            strict_audience: if strict { issuer } else { String::new() },
            ..Presented::default()
        };
        let hints = MethodHints {
            assertion: client.assertion.clone(),
            assertion_type: client.assertion_type.clone(),
            client_secret: client.client_secret.clone(),
            basic: client.basic,
            certificate_self_issued: ask.peer.as_ref().map(|p| p.self_issued),
            ..MethodHints::default()
        };
        let q = Question {
            presented: &presented,
            hints: &hints,
            registered: &registered,
        };
        let memo = Verified::default();
        let observed =
            bcp::observe_client_authentication(&self.auth, &q, &memo);
        if !observed.authenticated {
            if allow_public && observed.code == Some(codes::STS_OAUTH_0194) {
                return Ok(Caller {
                    client_id: client.client_id.clone(),
                    identified: true,
                });
            }
            if lenient
                && [
                    codes::STS_OAUTH_0193,
                    codes::STS_OAUTH_0195,
                    codes::STS_OAUTH_0553,
                ]
                .iter()
                .any(|c| observed.code == Some(*c))
            {
                return Ok(Caller {
                    client_id: String::new(),
                    identified: false,
                });
            }
            if let (Some(l), Some((what, id))) = (&self.limits, &secret_key) {
                if let Some(over) = l.failed(what, &ask.address, id).await {
                    return Err(self.secret_lockout(&client.client_id, &over));
                }
            }
            let why = if client.client_id.is_empty() {
                "the request carried no client credential — no Authorization: \
                 Basic header, no client_id and client_secret, and no client \
                 assertion."
                    .to_string()
            } else {
                observed.why.clone()
            };
            let (code, status, challenge, description) =
                refuse(observed.code, &why);
            tracing::info!(
                "{}{}: client \"{}\" did not authenticate ({}): {}",
                sts_core::log::tag(code),
                path.trim_start_matches("/oauth2/"),
                if client.client_id.is_empty() {
                    "(none)"
                } else {
                    &client.client_id
                },
                observed
                    .code
                    .map(|c| c.as_str().to_string())
                    .unwrap_or_else(|| "no credential".into()),
                why
            );
            let a = self.refusal(code, status, "invalid_client", &description);
            return Err(if challenge {
                self.with_basic_challenge(a, client.basic)
            } else {
                a
            });
        }
        if let (Some(l), Some((what, id))) = (&self.limits, &secret_key) {
            if let Some(raced) =
                l.succeeded(what, &ask.address, id, true, true).await
            {
                return Err(self.secret_lockout(&client.client_id, &raced));
            }
        }
        Ok(Caller {
            client_id: client.client_id,
            identified: true,
        })
    }

    /// `introspectionAnswer(claims)`: Node's members, in Node's order,
    /// the absent ones dropped.
    fn introspection_answer(claims: &Json) -> Json {
        let refresh = s(claims.get("typ")) == "Refresh";
        let jkt = claims
            .get("cnf")
            .and_then(|c| c.get("jkt"))
            .and_then(Json::as_str)
            .is_some_and(|j| !j.is_empty());
        let mut out = Map::new();
        out.insert("active".into(), json!(true));
        out.insert(
            "scope".into(),
            claims
                .get("scope")
                .filter(|v| crate::js::truthy(Some(v)))
                .cloned()
                .unwrap_or(json!("")),
        );
        let mut put = |k: &str, v: Option<&Json>| {
            if let Some(v) = v {
                out.insert(k.into(), v.clone());
            }
        };
        put("client_id", claims.get("client_id"));
        put("username", claims.get("username"));
        let token_type = if refresh {
            "refresh_token"
        } else if jkt {
            "DPoP"
        } else {
            "Bearer"
        };
        put("token_type", Some(&json!(token_type)));
        put("cnf", claims.get("cnf"));
        put("authorization_details", claims.get("authorization_details"));
        if !refresh {
            put("grant_id", claims.get("grant_id"));
        }
        put("acr", claims.get("acr"));
        put("auth_time", claims.get("auth_time"));
        put("device_id", claims.get("device_id"));
        put("act", claims.get("act").filter(|a| a.is_object()));
        put("may_act", claims.get("may_act").filter(|a| a.is_object()));
        for k in ["exp", "iat", "nbf", "sub", "aud", "iss", "jti"] {
            put(k, claims.get(k));
        }
        Json::Object(out)
    }

    /// `introspectionOf(token)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn introspection_of(&self, token: &str) -> Json {
        let inactive = json!({ "active": false });
        if token.is_empty() || !token.contains('.') {
            return inactive;
        }
        let sealed = token.split('.').count() == 5;
        let jws = if sealed {
            match crate::refresh_crypto::open(
                token,
                &self.signer.refresh_keys(),
            ) {
                Ok(j) => j,
                Err(_) => return inactive,
            }
        } else {
            token.to_string()
        };
        let claims = match self.signer.verify_own(&jws, self.clock.now_s()) {
            Ok(c) => c,
            Err(_) => return inactive,
        };
        if (s(claims.get("typ")) == "Refresh") != sealed {
            return inactive;
        }
        if self.register.is_revoked(&s(claims.get("jti"))) {
            return inactive;
        }
        Self::introspection_answer(&claims)
    }

    /// `introspectionJwt.intendedFor(answer, clientId, base)`.
    fn intended_for(&self, answer: &Json, caller: &str, base: &str) -> bool {
        if answer.get("active") != Some(&Json::Bool(true)) || caller.is_empty()
        {
            return false;
        }
        if s(answer.get("client_id")) == caller {
            return true;
        }
        if s(answer.get("token_type")) == "refresh_token" {
            return false;
        }
        let audiences: Vec<String> = match answer.get("aud") {
            Some(Json::Array(a)) => a.iter().map(|v| s(Some(v))).collect(),
            Some(v) => vec![s(Some(v))],
            None => Vec::new(),
        }
        .into_iter()
        .filter(|a| !a.is_empty())
        .collect();
        let own =
            crate::jwt_access_token::JwtAccessTokens::default_audience_for(
                base,
            );
        if audiences.iter().any(|a| *a == own || a == base) {
            return true;
        }
        audiences.iter().any(|a| a == caller)
            || self
                .clients
                .client_audience_names(caller)
                .iter()
                .any(|n| audiences.contains(n))
    }

    /// `POST /oauth2/introspect` (`introspectRequest()`).
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn introspect(&self, ask: &EndpointAsk) -> Answer {
        let finish = |mut a: Answer| {
            a.set("Cache-Control", "no-store");
            a.set("Vary", "Accept");
            a
        };
        let folded = crate::js::fold(&crate::js::form_decode(&ask.body));
        let body = match crate::model::check("introspect", &folded, "body") {
            Ok(b) => b,
            Err(r) => {
                return finish(self.refusal(
                    codes::STS_OAUTH_0229,
                    400,
                    "invalid_request",
                    &r.detail,
                ))
            }
        };
        let jwt = wants_jwt(&ask.accept);
        if self.settings.value_of("oauth2.oauth21").as_bool() {
            let client = client_from(&ask.authorization, &body);
            if let Some((code, description)) =
                crate::oauth21::multiple_methods_refusal(
                    client.basic,
                    body.contains_key("client_secret"),
                    !s(body.get("client_assertion")).is_empty(),
                )
            {
                return finish(self.refusal(
                    code,
                    400,
                    "invalid_request",
                    &description,
                ));
            }
        }
        let mut client_id = client_from(&ask.authorization, &body).client_id;
        let mut authenticated = false;
        if jwt || !self.mode.opens_introspection() {
            let refuse = move |_: Option<sts_core::errors::ErrorCode>,
                               why: &str| {
                if !jwt {
                    (
                        codes::STS_OAUTH_0292,
                        401,
                        true,
                        format!(
                            "This realm is in product mode, where \
                             introspection requires the caller to \
                             authenticate as a client (RFC 7662 section \
                             2.1) — and {}",
                            why
                        ),
                    )
                } else {
                    (
                        codes::STS_OAUTH_0291,
                        400,
                        false,
                        format!(
                            "RFC 9701 section 5: a JWT introspection \
                             response is addressed to the resource server \
                             that asks for it, so the caller must \
                             authenticate as a client — and {}",
                            why
                        ),
                    )
                }
            };
            match self
                .endpoint_caller(
                    ask,
                    &body,
                    "/oauth2/introspect",
                    false,
                    false,
                    &refuse,
                )
                .await
            {
                Ok(c) => {
                    client_id = c.client_id;
                    authenticated = true;
                }
                Err(a) => return finish(a),
            }
        }
        let mut answer = self.introspection_of(&s(body.get("token")));
        if authenticated
            && answer.get("active") == Some(&Json::Bool(true))
            && !self.intended_for(&answer, &client_id, &ask.base)
        {
            tracing::info!(
                "introspection: client \"{}\" asked about a token not \
                 intended for it (client_id {}, aud {}), answered as \
                 inactive.",
                client_id,
                s(answer.get("client_id")),
                answer.get("aud").cloned().unwrap_or(Json::Null)
            );
            answer = json!({ "active": false });
        }
        if !jwt {
            let mut a = Answer::new(200, Body::Raw(answer.to_string()));
            a.set("Content-Type", "application/json; charset=utf-8");
            return finish(a);
        }
        let mut registered = self.clients.client_config_of(&client_id);
        if let Json::Object(m) = &mut registered {
            m.insert("client_id".into(), json!(client_id));
        }
        match self.introspection_jwt(&answer, &ask.base, &registered) {
            Ok(text) => {
                let mut a = Answer::new(200, Body::Raw(text));
                a.set("Content-Type", MEDIA_TYPE);
                finish(a)
            }
            Err((code, status, error, why)) => {
                tracing::error!(
                    "{}introspection: the JWT response registered by client \
                     \"{}\" could not be produced: {}",
                    sts_core::log::tag(code),
                    client_id,
                    why
                );
                finish(self.refusal(code, status, error, &why))
            }
        }
    }

    /// `introspectionJwt.respond()`: `{ iss, aud, iat, token_introspection }`
    /// signed with the client's registered algorithm (RS256 by default,
    /// PS256 under FAPI 1.0 Advanced), `typ: token-introspection+jwt`, and
    /// encrypted to the client's key where it registered an algorithm.
    fn introspection_jwt(
        &self,
        answer: &Json,
        base: &str,
        client: &Json,
    ) -> Result<String, (sts_core::errors::ErrorCode, u16, &'static str, String)>
    {
        let audience = s(client.get("client_id"));
        let fapi_default =
            if crate::authorization_servers::fapi_profile(&self.settings)
                == "1-advanced"
            {
                "PS256"
            } else {
                "RS256"
            };
        let sign_alg =
            match s(client.get("introspection_signed_response_alg")).trim() {
                "" => fapi_default.to_string(),
                a => a.to_string(),
            };
        let enc_alg = s(client.get("introspection_encrypted_response_alg"))
            .trim()
            .to_string();
        let enc_enc = if enc_alg.is_empty() {
            String::new()
        } else {
            match s(client.get("introspection_encrypted_response_enc")).trim() {
                "" if self.mode.allows_cbc_jwe() => "A128CBC-HS256".to_string(),
                "" => "A256GCM".to_string(),
                e => e.to_string(),
            }
        };
        let mut payload = Map::new();
        payload.insert(
            "iss".into(),
            json!(crate::jwt_access_token::JwtAccessTokens::new(
                self.settings.clone()
            )
            .issuer_for(base)),
        );
        payload.insert("aud".into(), json!(audience));
        payload.insert("iat".into(), json!(self.clock.now_s()));
        payload.insert(
            "token_introspection".into(),
            if answer.get("active") == Some(&Json::Bool(true)) {
                answer.clone()
            } else {
                json!({ "active": false })
            },
        );
        let signed = if sign_alg.starts_with("HS") {
            let secret = s(client.get("client_secret"));
            if secret.is_empty() {
                return Err((
                    codes::STS_OAUTH_0293,
                    500,
                    "server_error",
                    format!(
                        "{} is signed with the client_secret, and this \
                         client has none — a public client cannot use a \
                         symmetric algorithm.",
                        sign_alg
                    ),
                ));
            }
            let key = sts_crypto::keys::JwsKey::from_jwk(&json!({
                "kty": "oct",
                "k": sts_crypto::b64::encode(secret.as_bytes()),
            }))
            .map_err(|e| {
                (codes::STS_OAUTH_0293, 500, "server_error", e.to_string())
            })?;
            sts_crypto::jws::sign_jws(
                &payload,
                &key,
                &sts_crypto::jws::SignOptions {
                    algorithm: Some(sign_alg.clone()),
                    header: {
                        let mut h = Map::new();
                        h.insert("typ".into(), json!(TYP));
                        h
                    },
                    no_timestamp: true,
                    ..sts_crypto::jws::SignOptions::default()
                },
            )
            .map_err(|e| {
                (codes::STS_OAUTH_0293, 500, "server_error", e.to_string())
            })?
        } else {
            self.signer
                .sign(&payload, TYP, &sign_alg)
                .map_err(|e| (codes::STS_OAUTH_0293, 500, "server_error", e))?
        };
        if enc_alg.is_empty() {
            return Ok(signed);
        }
        let jwk = crate::jarm::recipient_key(
            client,
            &enc_alg,
            "introspection_encrypted_response_alg",
        )
        .map_err(|e| (codes::STS_OAUTH_0293, 500, "server_error", e))?;
        sts_crypto::jwe::encrypt_compact(
            signed.as_bytes(),
            &sts_crypto::jwe::EncryptOptions {
                alg: Some(&enc_alg),
                enc: &enc_enc,
                typ: Some(TYP),
                cty: Some("JWT"),
                jwk: Some(&jwk),
                ..sts_crypto::jwe::EncryptOptions::default()
            },
        )
        .map_err(|e| {
            (codes::STS_OAUTH_0293, 500, "server_error", e.to_string())
        })
    }

    /// `POST /oauth2/revoke` (`revokeRequest()`, RFC 7009).
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn revoke_request(&self, ask: &EndpointAsk) -> Answer {
        let finish = |mut a: Answer| {
            a.set("Cache-Control", "no-store");
            a
        };
        let ok = || finish(Answer::new(200, Body::Raw(String::new())));
        let folded = crate::js::fold(&crate::js::form_decode(&ask.body));
        let body = match crate::model::check("revoke", &folded, "body") {
            Ok(b) => b,
            Err(r) => {
                return finish(self.refusal(
                    codes::STS_OAUTH_0230,
                    400,
                    "invalid_request",
                    &r.detail,
                ))
            }
        };
        let token = s(body.get("token"));
        if token.is_empty() {
            return finish(self.refusal(
                codes::STS_OAUTH_0608,
                400,
                "invalid_request",
                "RFC 7009 section 2.1: the token parameter is REQUIRED — the \
                 request names nothing to revoke.",
            ));
        }
        let client = client_from(&ask.authorization, &body);
        let body_secret = body.contains_key("client_secret");
        let assertion = !s(body.get("client_assertion")).is_empty();
        if self.settings.value_of("oauth2.oauth21").as_bool() {
            if let Some((code, description)) =
                crate::oauth21::multiple_methods_refusal(
                    client.basic,
                    body_secret,
                    assertion,
                )
            {
                return finish(self.refusal(
                    code,
                    400,
                    "invalid_request",
                    &description,
                ));
            }
        }
        let presented_credential = client.basic || body_secret || assertion;
        let opens = self.mode.opens_revocation();
        let mut caller = Caller {
            client_id: String::new(),
            identified: false,
        };
        if !opens || presented_credential {
            let refuse = move |code: Option<sts_core::errors::ErrorCode>,
                               why: &str| {
                let unknown = code == Some(codes::STS_OAUTH_0193);
                (
                    if unknown {
                        codes::STS_OAUTH_0610
                    } else {
                        codes::STS_OAUTH_0609
                    },
                    401,
                    true,
                    format!(
                        "RFC 7009 section 2.1: the revocation endpoint \
                         validates the client before the token{} — and {}",
                        if opens {
                            ", and a credential was presented"
                        } else {
                            " — this realm is in product mode, where every \
                             revocation request comes from a client"
                        },
                        why
                    ),
                )
            };
            match self
                .endpoint_caller(
                    ask,
                    &body,
                    "/oauth2/revoke",
                    true,
                    opens,
                    &refuse,
                )
                .await
            {
                Ok(c) => caller = c,
                Err(a) => return finish(a),
            }
        }
        if !token.contains('.') {
            return ok();
        }
        let sealed = token.split('.').count() == 5;
        let jws = if sealed {
            crate::refresh_crypto::open(&token, &self.signer.refresh_keys())
                .ok()
        } else {
            Some(token.clone())
        };
        let claims = jws
            .as_ref()
            .and_then(|j| self.signer.verify_own(j, self.clock.now_s()).ok());
        let Some(claims) = claims else {
            return ok();
        };
        let typ = s(claims.get("typ"));
        let kind = if typ == "Refresh" || sealed {
            if (typ == "Refresh") == sealed {
                "refresh"
            } else {
                return ok();
            }
        } else if typ == "Bearer"
            || crate::js::header_member(jws.as_deref().unwrap_or(""), "typ")
                .eq_ignore_ascii_case(crate::jwt_access_token::TYP)
        {
            "access"
        } else {
            "other"
        };
        if kind == "other" {
            return finish(self.refusal(
                codes::STS_OAUTH_0611,
                400,
                "unsupported_token_type",
                &format!(
                    "RFC 7009 section 2.2.1: this authorization server \
                     revokes access tokens and refresh tokens, and the token \
                     presented is neither{} — an ID Token, for one, is not \
                     revocable here. Nothing was revoked.",
                    if typ.is_empty() {
                        String::new()
                    } else {
                        format!(" (typ \"{}\")", typ)
                    }
                ),
            ));
        }
        let owner = match s(claims.get("client_id")) {
            o if !o.is_empty() => o,
            _ => s(claims.get("azp")),
        };
        if caller.identified && owner != caller.client_id {
            sts_http::call_log::audit(&serde_json::json!({
                "action": "oauth.token.revoke",
                "actor": caller.client_id,
                "target": if owner.is_empty() { "(no client)" } else { &owner },
                "protocol": "OAuth 2.0 / OIDC",
                "channel": "http",
                "outcome": "refused",
                "errorCode": codes::STS_OAUTH_0612.as_str(),
                "detail": format!(
                    "client \"{}\" asked to revoke a {} token issued to \
                     \"{}\", jti {}",
                    caller.client_id,
                    kind,
                    if owner.is_empty() { "(no client)" } else { &owner },
                    match s(claims.get("jti")) {
                        j if j.is_empty() => "(none)".to_string(),
                        j => j,
                    }
                ),
            }));
            tracing::info!(
                "{}revocation: client \"{}\" asked to revoke a {} token \
                 issued to \"{}\". Refused; nothing was revoked.",
                sts_core::log::tag(codes::STS_OAUTH_0612),
                caller.client_id,
                kind,
                if owner.is_empty() {
                    "(no client)"
                } else {
                    &owner
                }
            );
            return finish(self.refusal(
                codes::STS_OAUTH_0612,
                400,
                "invalid_grant",
                "RFC 7009 section 2.1: this token was issued to another \
                 client, and a client may revoke only its own. Nothing was \
                 revoked.",
            ));
        }
        let via = "the RFC 7009 revocation endpoint";
        let jti = s(claims.get("jti"));
        let exp =
            crate::js::to_number(claims.get("exp").unwrap_or(&Json::Null));
        let mut revoked = 0usize;
        if !jti.is_empty() && self.revoke_jti(&jti, via, exp as i64) {
            revoked += 1;
        }
        if kind == "refresh" {
            let family = match s(claims.get(crate::grants::FAMILY_CLAIM)) {
                f if !f.is_empty() => f,
                _ => self
                    .grants
                    .refresh_record(&jti)
                    .map(|r| s(r.get("family")))
                    .filter(|f| !f.is_empty())
                    .unwrap_or_else(|| jti.clone()),
            };
            let (members, access) = self.grants.members_of(&family, &jti);
            for one in members.iter().chain(access.iter()) {
                if self.revoke_jti(
                    one,
                    &format!("{}, with the refresh token of its grant", via),
                    0,
                ) {
                    revoked += 1;
                }
            }
            // The grant's other tokens as the register filed them (Node's
            // `grantTokens` rows): every access and refresh token minted
            // under this family.
            if !family.is_empty() {
                revoked += self.register.revoke_where(
                    &sts_core::realm::current_id(),
                    &|r: &Json| s(r.get("grantId")) == family,
                    &format!("{}, with the refresh token of its grant", via),
                    self.clock.now_ms(),
                );
                self.revoke_family_by_id(&family, &owner).await;
            }
        }
        let detail =
            format!(
            "{} revoked a {} token issued to \"{}\"; {} jti(s) newly revoked",
            if caller.identified {
                format!("client \"{}\"", caller.client_id)
            } else {
                "an unidentified caller (development)".to_string()
            },
            kind,
            if owner.is_empty() { "(no client)" } else { &owner },
            revoked
        );
        // `audit.record()`: into the request's ring, else the log.
        if !sts_http::call_log::audit(&serde_json::json!({
            "action": "oauth.token.revoke",
            "actor": caller.client_id,
            "target": if owner.is_empty() { "(no client)" } else { &owner },
            "protocol": "OAuth 2.0 / OIDC",
            "channel": "http",
            "outcome": "success",
            "detail": detail,
        })) {
            tracing::info!("audit: oauth.token.revoke {}", detail);
        }
        ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_jwt_answer_is_asked_for_as_rfc_9701_section_4_says() {
        assert!(wants_jwt(MEDIA_TYPE));
        assert!(!wants_jwt("application/json"));
        assert!(wants_jwt(
            "application/token-introspection+jwt, application/json;q=0.5"
        ));
        assert!(!wants_jwt(
            "application/token-introspection+jwt;q=0.4, application/json"
        ));
        assert!(!wants_jwt("application/token-introspection+jwt;q=0"));
    }
}
