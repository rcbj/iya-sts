// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! RFC 8693 TOKEN EXCHANGE (`oauth2.ts`'s `tokenGrant()` branch for
//! `urn:ietf:params:oauth:grant-type:token-exchange`, #108, #130, #186,
//! #443, #471, #550).
//!
//! In Node's order: the subject_token is required; the token types are
//! read (section 2.1) — each present where its token is, each one this
//! service exchanges, and a verified token the type it was declared as
//! (`STS-OAUTH-0628`); the subject_token is verified under the realm's key
//! (an encrypted refresh token opened first) and, in product, refused when
//! it does not verify (`STS-OAUTH-0555`), while development reads a token
//! from anywhere for its name; a revoked one is refused (`STS-OAUTH-0557`);
//! an ID Token bound to a key needs a DPoP proof from it (Key Binding
//! section 7, `STS-OAUTH-0707`); the actor_token is held to the same rule
//! (`STS-OAUTH-0556`) and to #550's — it is the exchanging client's own and
//! addressed to it or to this server (`STS-OAUTH-0955`, `0956`); `act`
//! nests (section 4.1) with `iss` in every entry this server writes (#471)
//! and the original client beneath the first actor (#443); `may_act`
//! (section 4.4) is read off a verified subject_token; the audiences and
//! resources are unioned, audiences first; `requested_token_type` and
//! `oauth2.tokenExchangeRefreshToken` decide the refresh token; the
//! delegation policy decides who may act for whom and with what semantics
//! ([`crate::delegation_policy`], its refusals spoken by Node's table of
//! codes); the exchange stage of the scope policy narrows and never widens
//! the subject's scope in product (`STS-OAUTH-0621`) and drops a delegated
//! permission the caller was not granted in every mode (`STS-OAUTH-0954`);
//! the token set is issued by the one `issue()` every grant mints through,
//! `issued_token_type` naming the access token; and the act is written to
//! the delegation register ([`crate::delegation_acts`]).
//!
//! NOT HERE, and what this runtime answers meanwhile:
//!
//! * ASSERTIONS AS TOKENS (#114, `exchange_assertions.ts`): RFC 7523 and
//!   RFC 7522 verification is the jwt-bearer and saml2-bearer grants',
//!   which are not ported. A `saml2` or `saml1` type is not one this
//!   runtime exchanges (`STS-OAUTH-0627`, the list naming what it takes); a
//!   `jwt` this realm did not sign is the unverified token it would be with
//!   no issuer declared — refused `STS-OAUTH-0555` / `0556` in product, read
//!   in development.
//! * KERBEROS TOKENS (#658, `krb5_tokens.ts`): the six Kerberos Token
//!   Profile types are not taken (`STS-OAUTH-0627`), and one asked for is
//!   refused `STS-OAUTH-0994` as Node refuses it with the output off (its
//!   default).
//! * NATIVE SSO (#130, `nativeSsoExchange()`): the device secret is not a
//!   type taken (`STS-OAUTH-0627`).
//! * OPAQUE TOKENS (#501, off by default): a handle is not found, and reads
//!   as a token this realm cannot verify.
//! * A PERSON IN ANOTHER CELL (#98 D6): cells are not ported.
//! * RFC 9396 DETAILS AND THE FINE-GRAINED BOUND (#564): this token endpoint
//!   reads no `authorization_details`, and sts-xacml holds no fine-grained
//!   policy, so no detail is carried or refused.

use serde_json::{json, Map, Value as Json};
use sts_core::errors::{codes, ErrorCode};

use super::{s, values_of, Issuing, Mint, TokenEndpoint};
use crate::answer::Answer;
use crate::delegation_policy::{
    may_act_names, row_text, DelegationPolicy, NoDelegationDirectory, Question,
};

pub const GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
pub const ACCESS_TOKEN_TYPE: &str =
    "urn:ietf:params:oauth:token-type:access_token";
pub const REFRESH_TOKEN_TYPE: &str =
    "urn:ietf:params:oauth:token-type:refresh_token";
pub const ID_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:id_token";
pub const JWT_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";
pub const DEVICE_SECRET_TYPE: &str =
    "urn:openid:params:token-type:device-secret";

/// `EXCHANGE_TOKEN_TYPES`, the types this runtime exchanges: the four a
/// token of this service can be. Node's table also carries `saml2`,
/// `saml1` and the Kerberos Token Profile's six (see the module header).
pub const TOKEN_TYPES: [(&str, &str); 4] = [
    (ACCESS_TOKEN_TYPE, "access_token"),
    (REFRESH_TOKEN_TYPE, "refresh_token"),
    (ID_TOKEN_TYPE, "id_token"),
    (JWT_TYPE, "jwt"),
];

/// The Kerberos Token Profile 1.1's six value types (`krb5_tokens.ts`).
pub const KERBEROS_TYPES: [&str; 6] = [
    "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#Kerberosv5_AP_REQ",
    "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ",
    "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#Kerberosv5_AP_REQ1510",
    "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ1510",
    "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#Kerberosv5_AP_REQ4120",
    "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ4120",
];

fn kind_of_type(t: &str) -> &'static str {
    TOKEN_TYPES
        .iter()
        .find(|(u, _)| *u == t)
        .map_or("", |(_, k)| k)
}

/// `exchangeTypeProblem(body)`: `(code, sentence)` of an
/// `invalid_request`, or `None`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn exchange_type_problem(
    body: &Map<String, Json>,
) -> Option<(ErrorCode, String)> {
    let subject_type = s(body.get("subject_token_type")).trim().to_string();
    let actor_type = s(body.get("actor_token_type")).trim().to_string();
    let actor_token = crate::js::truthy(body.get("actor_token"));
    let supported = TOKEN_TYPES
        .iter()
        .map(|(u, _)| *u)
        .collect::<Vec<_>>()
        .join(", ");
    if subject_type.is_empty() {
        return Some((
            codes::STS_OAUTH_0626,
            "subject_token_type is required (RFC 8693 section 2.1).".into(),
        ));
    }
    if actor_token && actor_type.is_empty() {
        return Some((
            codes::STS_OAUTH_0626,
            "actor_token_type is required when actor_token is present (RFC \
             8693 section 2.1)."
                .into(),
        ));
    }
    if !actor_type.is_empty() && !actor_token {
        return Some((
            codes::STS_OAUTH_0626,
            "actor_token_type must not be sent without an actor_token (RFC \
             8693 section 2.1)."
                .into(),
        ));
    }
    if actor_type == DEVICE_SECRET_TYPE && subject_type != ID_TOKEN_TYPE {
        return Some((
            codes::STS_OAUTH_0627,
            format!(
                "a device secret is exchanged only beside an ID Token (OpenID \
                 Connect Native SSO section 4.1): subject_token_type must be \
                 {}.",
                ID_TOKEN_TYPE
            ),
        ));
    }
    if subject_type == DEVICE_SECRET_TYPE {
        return Some((
            codes::STS_OAUTH_0627,
            "a device secret is an actor_token, never the subject (OpenID \
             Connect Native SSO section 4.1)."
                .into(),
        ));
    }
    if kind_of_type(&subject_type).is_empty() {
        return Some((
            codes::STS_OAUTH_0627,
            format!(
                "subject_token_type \"{}\" is not a type this service \
                 exchanges; it takes {}.",
                subject_type, supported
            ),
        ));
    }
    if !actor_type.is_empty() && kind_of_type(&actor_type).is_empty() {
        return Some((
            codes::STS_OAUTH_0627,
            format!(
                "actor_token_type \"{}\" is not a type this service \
                 exchanges; it takes {}.",
                actor_type, supported
            ),
        ));
    }
    let requested = s(body.get("requested_token_type"));
    if KERBEROS_TYPES.contains(&requested.as_str()) {
        return Some((
            codes::STS_OAUTH_0994,
            "A Kerberos token is not issued here: \
             oauth2.tokenExchangeKerberosOutput is off."
                .into(),
        ));
    }
    None
}

/// `refreshTokenCrypto.isEncrypted(token)`: a compact JWE.
fn is_encrypted(token: &str) -> bool {
    token.trim().split('.').count() == 5
}

/// `ownTokenKind(token, claims)`: `access_token`, `refresh_token`,
/// `id_token` or `jwt`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn own_token_kind(token: &str, claims: &Json) -> &'static str {
    let header = if is_encrypted(token) {
        Json::Null
    } else {
        crate::js::segment_json(token, 0).unwrap_or(Json::Null)
    };
    let typ = s(claims.get("typ"));
    let header_typ = s(header.get("typ"));
    let truthy = |k: &str| crate::js::truthy(claims.get(k));
    if is_encrypted(token) || typ == "Refresh" {
        "refresh_token"
    } else if typ == "Bearer" || header_typ == "at+jwt" {
        "access_token"
    } else if !truthy("typ")
        && !truthy("events")
        && truthy("sub")
        && truthy("aud")
        && header_typ != "logout+jwt"
    {
        "id_token"
    } else {
        "jwt"
    }
}

/// `kindProblem(declaredType, kind, which)`: '' where a token of `kind`
/// may be exchanged as the type declared, else the sentence.
#[tracing::instrument(level = "debug")]
pub fn kind_problem(declared_type: &str, kind: &str, which: &str) -> String {
    let declared = kind_of_type(declared_type);
    let fits = if declared == "jwt" {
        kind != "refresh_token"
    } else {
        declared == kind
    };
    if fits {
        return String::new();
    }
    format!(
        "{} was declared {} and is {} (RFC 8693 section 2.1: the type says \
         what the token IS).",
        which,
        declared_type,
        match kind {
            "id_token" => "an ID Token",
            "access_token" => "an access token",
            "refresh_token" => "a refresh token",
            _ => "a JWT of another kind",
        }
    )
}

/// An `aud`-shaped value as a list of strings.
fn audience_list(v: Option<&Json>) -> Vec<String> {
    match v {
        None | Some(Json::Null) => Vec::new(),
        Some(Json::String(t)) if t.is_empty() => Vec::new(),
        Some(Json::Array(a)) => a.iter().map(|x| s(Some(x))).collect(),
        Some(one) => vec![s(Some(one))],
    }
}

/// `actorTokenProblem(claims, client, base)` (#550): `(code, sentence)`,
/// or `None` where the actor_token is the client's own and addressed to
/// it or to this server.
#[tracing::instrument(level = "debug", skip_all)]
pub fn actor_token_problem(
    claims: &Json,
    client_id: &str,
    client_names: &[String],
    issuer: &str,
    base: &str,
) -> Option<(ErrorCode, String)> {
    let client_id = client_id.trim();
    let aud = audience_list(claims.get("aud"));
    let mut issued_to = s(claims.get("client_id")).trim().to_string();
    if issued_to.is_empty() {
        issued_to = s(claims.get("azp")).trim().to_string();
    }
    let names_client = aud.iter().any(|a| client_names.contains(a));
    let not_own = if issued_to.is_empty() {
        !names_client
    } else {
        issued_to != client_id
    };
    if not_own {
        return Some((
            codes::STS_OAUTH_0955,
            format!(
                "The actor_token was not issued to this client: {}. An \
                 actor_token must be the exchanging client's own (RFC 8693 \
                 section 2.1: it represents the acting party).",
                if issued_to.is_empty() {
                    "it names no client, and its aud does not name this one"
                        .to_string()
                } else {
                    format!("it was issued to \"{}\"", issued_to)
                }
            ),
        ));
    }
    let sub = s(claims.get("sub"));
    if let Some(about) = sub.strip_prefix("urn:sts:client:") {
        if !about.is_empty() && about != client_id {
            return Some((
                codes::STS_OAUTH_0955,
                format!(
                    "The actor_token is a client's token about \"{}\", and \
                     the exchanging client is \"{}\".",
                    about, client_id
                ),
            ));
        }
    }
    let server = [
        issuer.to_string(),
        format!("{}/oauth2/token", issuer),
        format!("{}/oauth2/token", base),
    ];
    let addressed = aud.iter().any(|a| server.contains(a)) || names_client;
    if !addressed {
        return Some((
            codes::STS_OAUTH_0956,
            format!(
                "The actor_token is addressed to {}, which is neither this \
                 authorization server nor the client \"{}\". Use a token \
                 addressed to the client itself (a client_credentials token \
                 asking for nothing else is) or to this server.",
                if aud.is_empty() {
                    "nobody".to_string()
                } else {
                    aud.iter()
                        .map(|a| format!("\"{}\"", a))
                        .collect::<Vec<_>>()
                        .join(", ")
                },
                client_id
            ),
        ));
    }
    None
}

/// `clientActorSubject(clientId, namespaced)` (#471).
#[tracing::instrument(level = "trace")]
pub fn client_actor_subject(client_id: &str, namespaced: bool) -> String {
    if namespaced {
        format!("urn:sts:client:{}", client_id)
    } else {
        client_id.to_string()
    }
}

/// `actChainEntry(sub, issuer)` (#471).
#[tracing::instrument(level = "trace")]
pub fn act_chain_entry(sub: &str, issuer: &str) -> Json {
    let mut entry = Map::new();
    entry.insert("sub".into(), json!(sub));
    if !issuer.is_empty() {
        entry.insert("iss".into(), json!(issuer));
    }
    Json::Object(entry)
}

/// `priorActChain(chain, issuer)` (#471): a copy in which an entry with no
/// `iss` is given `issuer`, or the chain as it came where `issuer` is ''.
#[tracing::instrument(level = "trace", skip_all)]
pub fn prior_act_chain(chain: &Json, issuer: &str) -> Json {
    if !chain.is_object() && !chain.is_array() {
        return Json::Null;
    }
    if issuer.is_empty() {
        return chain.clone();
    }
    fn copy(level: &Json, depth: usize, issuer: &str) -> Json {
        let Some(m) = level.as_object() else {
            return level.clone();
        };
        if depth > 64 {
            return level.clone();
        }
        let mut out = m.clone();
        if !matches!(out.get("iss"), Some(Json::String(t)) if !t.is_empty()) {
            out.insert("iss".into(), json!(issuer));
        }
        if let Some(inner) = m.get("act").filter(|a| a.is_object()) {
            out.insert("act".into(), copy(inner, depth + 1, issuer));
        }
        Json::Object(out)
    }
    copy(chain, 0, issuer)
}

/// `originalClientAct(subject, ownVerified, actorName, namespaced,
/// issuer)` (#443): the nested entry naming the client a chain began with.
#[tracing::instrument(level = "trace", skip_all)]
pub fn original_client_act(
    subject: &Json,
    own_verified: bool,
    actor_name: &str,
    namespaced: bool,
    issuer: &str,
) -> Json {
    if !own_verified || !subject.is_object() {
        return Json::Null;
    }
    if subject
        .get("act")
        .is_some_and(|a| a.is_object() || a.is_array())
    {
        return Json::Null;
    }
    let mut client_id = s(subject.get("client_id"));
    if client_id.is_empty() {
        client_id = s(subject.get("azp"));
    }
    let client_id = client_id.trim();
    if client_id.is_empty() || client_id == actor_name {
        return Json::Null;
    }
    act_chain_entry(&client_actor_subject(client_id, namespaced), issuer)
}

/// `consumedInput(which, null, identifier, verified)`: a token this
/// realm verified or read.
#[tracing::instrument(level = "trace")]
pub fn consumed_input(which: &str, identifier: &str, verified: bool) -> Json {
    json!({
        "kind": which, "identifier": identifier,
        "note": if verified { "signed by this service and verified" }
                else { "NOT signed by this service; read without verifying" },
    })
}

/// A JavaScript object (not an array) — `x && typeof x === 'object'`
/// reads both; `act` and `may_act` are compared as Node compares them.
fn is_js_object(v: Option<&Json>) -> bool {
    matches!(v, Some(Json::Object(_)) | Some(Json::Array(_)))
}

/// The jti of a token just issued (`jtiOf()`), opening an encrypted
/// refresh token.
fn jti_of(endpoint: &TokenEndpoint, token: &str) -> String {
    if token.is_empty() || !token.contains('.') {
        return String::new();
    }
    let jws = if is_encrypted(token) {
        match crate::refresh_crypto::open(
            token,
            &endpoint.signer.refresh_keys(),
        ) {
            Ok(j) => j,
            Err(_) => return String::new(),
        }
    } else {
        token.to_string()
    };
    crate::js::segment_json(&jws, 1)
        .map(|c| s(c.get("jti")))
        .unwrap_or_default()
}

impl TokenEndpoint {
    fn delegation_policy(&self) -> std::sync::Arc<DelegationPolicy> {
        self.delegation.clone().unwrap_or_else(|| {
            std::sync::Arc::new(DelegationPolicy {
                directory: std::sync::Arc::new(NoDelegationDirectory),
                settings: self.settings.clone(),
                mode: self.mode.clone(),
            })
        })
    }

    fn invalid(&self, code: ErrorCode, description: &str) -> Answer {
        self.refusal(code, 400, "invalid_request", description)
    }

    /// The token exchange.
    #[tracing::instrument(level = "debug", skip_all)]
    pub(super) async fn token_exchange(&self, issuing: &Issuing<'_>) -> Answer {
        let body = issuing.body;
        let client_id = issuing.client.client_id.clone();
        let base = issuing.ask.base.clone();
        let subject_token = s(body.get("subject_token"));
        if subject_token.is_empty() {
            return self
                .invalid(codes::STS_OAUTH_0224, "subject_token is required.");
        }
        if let Some((code, description)) = exchange_type_problem(body) {
            return self.invalid(code, &description);
        }
        let issuer = crate::jwt_access_token::JwtAccessTokens::new(
            self.settings.clone(),
        )
        .issuer_for(&base);
        let strict = !self.mode.exchanges_unverified_tokens();
        let now = self.clock.now_s();
        // THE SUBJECT. A refresh token is opened first, and verified like
        // any other token this service issued.
        let mut subject_jws = subject_token.clone();
        if is_encrypted(&subject_token) {
            if let Ok(jws) = crate::refresh_crypto::open(
                &subject_token,
                &self.signer.refresh_keys(),
            ) {
                subject_jws = jws;
            }
        }
        let mut subject_verified = true;
        let mut subject = match self.signer.verify_own(&subject_jws, now) {
            Ok(c) => c,
            Err(why) => {
                if strict {
                    tracing::info!(
                        "oauth2: product mode refused a token exchange by \
                         \"{}\": the subject_token did not verify against \
                         this realm's signing key (not a token this realm \
                         signed, nor an assertion from an issuer it \
                         declared: {}).",
                        client_id,
                        why
                    );
                    return self.invalid(
                        codes::STS_OAUTH_0555,
                        "The subject_token is not a token this authorization \
                         server can verify.",
                    );
                }
                subject_verified = false;
                let read = subject_jws
                    .split('.')
                    .nth(1)
                    .ok_or_else(|| "no payload segment".to_string())
                    .and_then(crate::js::node_segment_json);
                match read {
                    Ok(Json::Object(mut m)) => {
                        if !matches!(m.get("sub"), Some(Json::String(_))) {
                            m.remove("sub");
                        }
                        Json::Object(m)
                    }
                    Ok(_) => json!({}),
                    Err(e) => {
                        tracing::error!(
                            "{}the subject_token could not be read at all: {}",
                            sts_core::log::tag(codes::STS_OAUTH_0225),
                            e
                        );
                        json!({})
                    }
                }
            }
        };
        if subject_verified
            && !crate::js::truthy(subject.get("username"))
            && s(subject.get("sub"))
                .to_lowercase()
                .starts_with("urn:uuid:")
        {
            if let Some(named) =
                self.people.name_for_subject(&s(subject.get("sub")))
            {
                subject["username"] = json!(named);
            }
        }
        if subject_verified {
            let kind = own_token_kind(&subject_token, &subject);
            let mismatch = kind_problem(
                s(body.get("subject_token_type")).trim(),
                kind,
                "subject_token",
            );
            if !mismatch.is_empty() {
                return self.invalid(codes::STS_OAUTH_0628, &mismatch);
            }
        }
        // Key Binding section 7 (#150), whether or not it verified.
        if let Some(jwk) = subject.pointer("/cnf/jwk").filter(|j| j.is_object())
        {
            let bound = crate::dpop::thumbprint(jwk).unwrap_or_default();
            let jkt = &issuing.dpop_jkt;
            if bound.is_empty() || jkt.is_empty() || bound != *jkt {
                return self.refusal(
                    codes::STS_OAUTH_0707,
                    400,
                    "invalid_dpop_proof",
                    &format!(
                        "The ID Token presented is bound to a key (cnf.jwk, \
                         OpenID Connect Key Binding), so it must be presented \
                         with a DPoP proof from that key{}.",
                        if jkt.is_empty() {
                            String::new()
                        } else {
                            format!("; this proof is from {}", jkt)
                        }
                    ),
                );
            }
        }
        let subject_jti = s(subject.get("jti"));
        if subject_verified
            && !subject_jti.is_empty()
            && self.register_revoked(&subject_jti)
        {
            tracing::info!(
                "oauth2: a token exchange by \"{}\" presented a subject_token \
                 this realm has revoked.",
                client_id
            );
            return self.invalid(
                codes::STS_OAUTH_0557,
                "The subject_token has been revoked.",
            );
        }
        // THE ACTOR, verified by the same rule (#550's rule after it).
        let actor_token = s(body.get("actor_token"));
        let mut actor_claims: Option<Json> = None;
        if crate::js::truthy(body.get("actor_token")) {
            let declared = s(body.get("actor_token_type")).trim().to_string();
            if strict {
                let claims = match self.signer.verify_own(&actor_token, now) {
                    Ok(c) => c,
                    Err(_) => {
                        tracing::info!(
                            "oauth2: product mode refused a token exchange by \
                             \"{}\": the actor_token did not verify against \
                             this realm's signing key.",
                            client_id
                        );
                        return self.invalid(
                            codes::STS_OAUTH_0556,
                            "The actor_token is not a token this \
                             authorization server can verify.",
                        );
                    }
                };
                let mismatch = kind_problem(
                    &declared,
                    own_token_kind(&actor_token, &claims),
                    "actor_token",
                );
                if !mismatch.is_empty() {
                    return self.invalid(codes::STS_OAUTH_0628, &mismatch);
                }
                let jti = s(claims.get("jti"));
                if !jti.is_empty() && self.register_revoked(&jti) {
                    return self.invalid(
                        codes::STS_OAUTH_0557,
                        "The actor_token has been revoked.",
                    );
                }
                actor_claims = Some(claims);
            } else {
                // #116: development holds this realm's own actor_token to
                // its declared type too — a TYPE check, not a trust check.
                if let Ok(own) = self.signer.verify_own(&actor_token, now) {
                    let mismatch = kind_problem(
                        &declared,
                        own_token_kind(&actor_token, &own),
                        "actor_token",
                    );
                    if !mismatch.is_empty() {
                        return self.invalid(codes::STS_OAUTH_0628, &mismatch);
                    }
                }
                let read = actor_token
                    .split('.')
                    .nth(1)
                    .ok_or_else(|| "no payload segment".to_string())
                    .and_then(crate::js::node_segment_json);
                actor_claims = match read {
                    Ok(Json::Null) | Ok(Json::Bool(false)) => Some(json!({})),
                    Ok(c) => Some(c),
                    Err(e) => {
                        tracing::error!(
                            "{}the actor_token could not be read: {}",
                            sts_core::log::tag(codes::STS_OAUTH_0226),
                            e
                        );
                        None
                    }
                };
            }
            if let Some(claims) = &actor_claims {
                let names = self.clients.client_audience_names(&client_id);
                if let Some((code, description)) = actor_token_problem(
                    claims, &client_id, &names, &issuer, &base,
                ) {
                    tracing::info!(
                        "oauth2: a token exchange by \"{}\" was refused: {}",
                        client_id,
                        description
                    );
                    return self.invalid(code, &description);
                }
            }
        }
        let prior_act = if is_js_object(subject.get("act")) {
            subject["act"].clone()
        } else {
            Json::Null
        };
        // WHO IS ASKING TO ACT (#471): the actor, else the client, in the
        // one subject form a client takes in the mode.
        let namespaced = self.bcp_mode().enabled;
        let actor_token_sub = actor_claims
            .as_ref()
            .map(|c| s(c.get("sub")))
            .unwrap_or_default();
        let actor_client_id = match &actor_claims {
            None => client_id.clone(),
            Some(c) => {
                let cid = s(c.get("client_id"));
                if crate::js::truthy(c.get("client_id"))
                    && (actor_token_sub == cid
                        || actor_token_sub == format!("urn:sts:client:{}", cid))
                {
                    cid
                } else {
                    String::new()
                }
            }
        };
        let actor_subject = if actor_claims.is_some() {
            actor_token_sub.clone()
        } else {
            client_actor_subject(&actor_client_id, namespaced)
        };
        let actor_iss = actor_claims
            .as_ref()
            .map(|c| s(c.get("iss")))
            .unwrap_or_default();
        let aliases: Vec<String> = if actor_client_id.is_empty() {
            Vec::new()
        } else {
            [
                actor_client_id.clone(),
                format!("urn:sts:client:{}", actor_client_id),
            ]
            .into_iter()
            .filter(|one| *one != actor_subject)
            .collect()
        };
        // `may_act` IS READ IN EVERY MODE, off a verified subject_token.
        let may_act = (subject_verified
            && is_js_object(subject.get("may_act")))
        .then(|| subject["may_act"].clone());
        let may_act_names_actor = may_act.as_ref().is_some_and(|m| {
            may_act_names(m, &actor_subject, &actor_iss, &aliases)
        });
        let subject_username = s(subject.get("username"));
        let subject_sub = s(subject.get("sub"));
        if let Some(records) = &self.records {
            records.record_authentication(
                &json!({
                    "presented": if !subject_username.is_empty() {
                        subject_username.clone()
                    } else if !subject_sub.is_empty() {
                        subject_sub.clone()
                    } else { "urn:sts:exchanged".into() },
                    "protocol": "OAuth 2.0",
                    "method": "token exchange (RFC 8693)",
                    "sub": subject_sub, "client_id": client_id,
                    "note": if subject_verified {
                        "The subject_token was signed by this service and \
                         verified, so this subject was authenticated here — \
                         earlier, by whatever grant produced that token."
                    } else {
                        "The subject_token was NOT signed by this service. \
                         The name was read out of it without verifying \
                         anything, so this is a subject this service has \
                         been TOLD about rather than one it authenticated."
                    },
                }),
                None,
            );
        }
        // WHAT THIS EXCHANGE IS FOR: `audience` and `resource`, unioned,
        // audiences first.
        let asked_audiences: Vec<String> = values_of(body.get("audience"))
            .into_iter()
            .map(|a| a.trim().to_string())
            .filter(|a| !a.is_empty())
            .collect();
        let mut exchange_audiences = asked_audiences.clone();
        for one in &issuing.resources {
            if !asked_audiences.contains(one) {
                exchange_audiences.push(one.clone());
            }
        }
        // AND WHETHER A REFRESH TOKEN COMES BACK BESIDE IT.
        let asked_for_refresh =
            s(body.get("requested_token_type")).trim() == REFRESH_TOKEN_TYPE;
        let refresh_policy = self
            .clients
            .setting_for(&client_id, "oauth2.tokenExchangeRefreshToken")
            .map(|v| s(Some(&v)))
            .unwrap_or_else(|| {
                self.settings
                    .value_of("oauth2.tokenExchangeRefreshToken")
                    .as_str()
                    .to_string()
            })
            .trim()
            .to_string();
        let wants_refresh = refresh_policy == "always"
            || (refresh_policy != "never" && asked_for_refresh);
        if asked_for_refresh && refresh_policy == "never" {
            tracing::info!(
                "oauth2: \"{}\" asked for a refresh token by \
                 requested_token_type and oauth2.tokenExchangeRefreshToken \
                 is \"never\" for it, so the exchange succeeded without one. \
                 Set that to \"when-requested\" service-wide, or put \
                 oauthTokenExchangeRefreshToken on this application's entry, \
                 to honour the ask.",
                client_id
            );
        }
        // WHO MAY ACT FOR WHOM, AND AS WHAT (#186).
        let asked_semantics: Vec<String> =
            values_of(body.get("exchange_semantics"))
                .into_iter()
                .map(|a| a.trim().to_lowercase())
                .filter(|a| !a.is_empty())
                .collect();
        if asked_semantics.len() > 1
            || asked_semantics
                .first()
                .is_some_and(|a| a != "delegation" && a != "impersonation")
        {
            return self.invalid(
                codes::STS_OAUTH_0795,
                "exchange_semantics is delegation or impersonation, sent \
                 once.",
            );
        }
        let subject_name = match subject_sub.strip_prefix("urn:sts:client:") {
            Some(rest) => rest.to_string(),
            None => {
                if subject_username.is_empty() {
                    subject_sub.clone()
                } else {
                    subject_username.clone()
                }
            }
        };
        let subject_audiences = audience_list(subject.get("aud"));
        let actor_name = if !actor_client_id.is_empty() {
            actor_client_id.clone()
        } else {
            match &actor_claims {
                None => String::new(),
                Some(c) => {
                    match actor_token_sub.strip_prefix("urn:sts:client:") {
                        Some(rest) => rest.to_string(),
                        None => {
                            let u = s(c.get("username"));
                            if u.is_empty() {
                                actor_token_sub.clone()
                            } else {
                                u
                            }
                        }
                    }
                }
            }
        };
        let mut source = subject_audiences.clone();
        source.push(s(subject.get("client_id")));
        source.push(s(subject.get("azp")));
        let policy = self.delegation_policy();
        let decision = policy.decide(&Question {
            protocol: "OAuth 2.0".into(),
            requested: asked_semantics.first().cloned().unwrap_or_default(),
            actor: actor_name.clone(),
            subject: subject_name,
            source,
            targets: exchange_audiences.clone(),
            target_kind: "audience".into(),
            may_act_present: may_act.is_some(),
            may_act_names_actor,
        });
        let issued_semantics = if !decision.semantics.is_empty() {
            decision.semantics.clone()
        } else if actor_claims.is_some() {
            "delegation".to_string()
        } else {
            "impersonation".to_string()
        };
        let own_subject_chain = subject_verified;
        let prior_chain = prior_act_chain(
            &prior_act,
            if own_subject_chain { &issuer } else { "" },
        );
        let act = if issued_semantics == "delegation" {
            let mut entry = act_chain_entry(&actor_subject, &issuer);
            let original = if prior_act.is_null() {
                original_client_act(
                    &subject,
                    own_subject_chain,
                    &actor_name,
                    namespaced,
                    &issuer,
                )
            } else {
                Json::Null
            };
            if !prior_chain.is_null() {
                entry["act"] = prior_chain.clone();
            } else if !original.is_null() {
                entry["act"] = original;
            }
            entry
        } else {
            prior_chain.clone()
        };
        let register_actor = if actor_claims.is_some() {
            actor_token_sub.clone()
        } else if issued_semantics == "delegation" {
            actor_subject.clone()
        } else {
            String::new()
        };
        let issued_audiences = if decision.allowed
            && exchange_audiences.is_empty()
            && decision.semantics == "self"
        {
            subject_audiences.clone()
        } else {
            exchange_audiences.clone()
        };
        let exchange_type = if issued_semantics == "impersonation" {
            "oauth-impersonation"
        } else {
            "oauth-delegation"
        };
        let subject_presented = if !subject_username.is_empty() {
            subject_username.clone()
        } else {
            subject_sub.clone()
        };
        let consumed_subject =
            consumed_input("subject_token", &subject_jti, subject_verified);
        let intermediary_what = if actor_claims.is_some() {
            format!(
                "the actor named in the actor_token, exchanging through \
                 client {}",
                client_id
            )
        } else {
            "the client performing the exchange".to_string()
        };
        if !decision.allowed && decision.enforced {
            let (code, error) = match decision.refusal.as_str() {
                "may-act" => (codes::STS_OAUTH_0620, "invalid_request"),
                "targets" => (codes::STS_OAUTH_0792, "invalid_target"),
                "unregistered-target" => {
                    (codes::STS_OAUTH_0793, "invalid_target")
                }
                "no-target" => (codes::STS_OAUTH_0794, "invalid_target"),
                "target" => (codes::STS_OAUTH_0619, "invalid_target"),
                "semantics" => (codes::STS_OAUTH_0790, "invalid_request"),
                "authority" => (codes::STS_OAUTH_0791, "invalid_request"),
                "policy" => (codes::STS_OAUTH_0622, "invalid_request"),
                _ => (codes::STS_OAUTH_0618, "invalid_request"),
            };
            let first = decision.targets.first().cloned().unwrap_or_default();
            if let Some(acts) = &self.acts {
                acts.record(&json!({
                    "protocol": "OAuth 2.0", "type": exchange_type,
                    "outcome": "refused",
                    "initial": { "presented": subject_presented,
                                 "what": "the subject of the token presented" },
                    "intermediary": { "presented": register_actor,
                                      "application": client_id,
                                      "what": intermediary_what },
                    "target": {
                        "application": if first.application.is_empty() {
                            first.asked.clone()
                        } else { first.application.clone() },
                        "what": if first.asked.is_empty() {
                            "unstated — neither audience nor resource was sent"
                                .to_string()
                        } else {
                            format!("the audience or resource asked for, \
                                     \"{}\"", first.asked)
                        },
                    },
                    "authorizedBy": row_text(&decision),
                    "reason": decision.why,
                    "consumed": [consumed_subject],
                    "produced": [], "sessionId": "",
                }));
            }
            return self.refusal(code, 400, error, &decision.why);
        }
        // AN EXCHANGE MAY NOT WIDEN WHAT THE SUBJECT GRANTED (#108, #186),
        // and a delegated permission is decided by delegation (#549).
        let mut exchange_scope: Option<String> = None;
        let body_scope = s(body.get("scope"));
        if crate::js::truthy(body.get("scope")) {
            let has_scope = subject_verified
                && subject.get("scope").is_some_and(|v| !v.is_null());
            let granted: Vec<String> = s(subject.get("scope"))
                .split_whitespace()
                .map(str::to_string)
                .collect();
            let asked: Vec<String> =
                body_scope.split_whitespace().map(str::to_string).collect();
            let reserved = crate::scopes::protocol_scopes(
                &self.settings,
                &self.scopes.credential_scopes,
            );
            let found = crate::scopes::audience_scopes(
                self.clients.as_ref(),
                &reserved,
                &body_scope,
                &client_id,
            );
            let permission_of = |one: &str| {
                found.permissions.iter().find(|p| p.scope == one).cloned()
            };
            let product = self.mode.current() == "product";
            let mut refused = Vec::new();
            let mut dropped = Vec::new();
            for one in &asked {
                let permission = permission_of(one);
                let in_subject = granted.contains(one)
                    || permission
                        .as_ref()
                        .is_some_and(|p| granted.contains(&p.permission));
                // `exchange-widens-scope`, then
                // `exchange-permission-not-delegated` (stage `exchange`).
                if product && has_scope && !in_subject && permission.is_none() {
                    refused.push(one.clone());
                } else if permission.as_ref().is_some_and(|p| !p.granted) {
                    dropped.push(one.clone());
                }
            }
            if !refused.is_empty() {
                tracing::info!(
                    "oauth2: a token exchange by \"{}\" asked for {}, which \
                     the subject_token does not carry.",
                    client_id,
                    refused.join(" ")
                );
                return self.refusal(
                    codes::STS_OAUTH_0621,
                    400,
                    "invalid_scope",
                    &format!(
                        "The requested scope is wider than the \
                         subject_token's ({} is not in it). An exchange may \
                         narrow a scope, never widen it.",
                        refused.join(" ")
                    ),
                );
            }
            if !dropped.is_empty() {
                tracing::info!(
                    "{}oauth2: a token exchange by \"{}\" asked for {}, \
                     which {} not delegated to it; left out of the issued \
                     token.",
                    sts_core::log::tag(codes::STS_OAUTH_0954),
                    client_id,
                    dropped.join(" "),
                    if dropped.len() == 1 {
                        "is a delegated permission"
                    } else {
                        "are delegated permissions"
                    }
                );
            }
            exchange_scope = Some(
                asked
                    .iter()
                    .filter(|one| !dropped.contains(one))
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" "),
            );
        }
        let user = {
            let mut u = self.people.user_for(&subject_username);
            if crate::js::truthy(subject.get("sub")) {
                u["sub"] = json!(subject_sub);
            }
            u
        };
        let opts = Mint {
            jkt: issuing.dpop_jkt.clone(),
            sub: if subject_sub.is_empty() {
                "urn:sts:exchanged".into()
            } else {
                subject_sub.clone()
            },
            username: s(user.get("username")),
            user,
            client_id: client_id.clone(),
            scope: exchange_scope
                .clone()
                .unwrap_or_else(|| s(subject.get("scope"))),
            id_token_follows_issued: true,
            audience: issued_audiences.clone(),
            act: act.clone(),
            with_refresh: wants_refresh,
            resources: if wants_refresh {
                issued_audiences.clone()
            } else {
                Vec::new()
            },
            grant: "token exchange".into(),
            ..Mint::default()
        };
        let mut exchanged = match self.issue(issuing, opts) {
            Ok(v) => v,
            Err(a) => return a,
        };
        exchanged["issued_token_type"] = json!(ACCESS_TOKEN_TYPE);
        // THE DELEGATION ACT, for /admin/delegation.
        let issued_jti = jti_of(self, &s(exchanged.get("access_token")));
        let issued_id_jti = jti_of(self, &s(exchanged.get("id_token")));
        let issued_refresh_jti =
            jti_of(self, &s(exchanged.get("refresh_token")));
        let audience = issued_audiences.first().cloned().unwrap_or_default();
        let audience_application = if audience.is_empty() {
            None
        } else {
            policy.directory.for_audience(&audience)
        };
        if let Some(acts) = &self.acts {
            let application_id = audience_application
                .as_ref()
                .map(|a| s(a.get("identifier")));
            let mut consumed = vec![consumed_subject];
            if let Some(c) = &actor_claims {
                consumed.push(json!({
                    "kind": "actor_token",
                    "identifier": s(c.get("jti")),
                    "note": format!("{} — its `sub` is what goes into the \
                                     `act` claim",
                                    if strict {
                                        "signed by this service and verified"
                                    } else { "read without verifying" }),
                }));
            }
            let act_sub = s(act.get("sub"));
            let mut produced = vec![json!({
                "kind": "access_token", "identifier": issued_jti,
                "note": if !act.is_null() {
                    format!("carries an `act` claim naming {}{}",
                        if act_sub.is_empty() { "(nobody)".to_string() }
                        else { act_sub },
                        if crate::js::truthy(act.get("act")) {
                            ", with the prior actors — back to the client \
                             the chain began with — nested beneath it (RFC \
                             8693 section 4.1)"
                        } else { "" })
                } else {
                    "carries nothing about the client that exchanged it"
                        .to_string()
                },
            })];
            if crate::js::truthy(exchanged.get("id_token")) {
                produced.push(json!({
                    "kind": "id_token", "identifier": issued_id_jti,
                    "note": "minted alongside because the requested scope \
                             carries `openid`. RFC 8693 returns ONE token — \
                             the `access_token` member above is what \
                             `issued_token_type` describes — and this one \
                             rides along because every grant here mints a \
                             token SET.",
                }));
            }
            if crate::js::truthy(exchanged.get("refresh_token")) {
                produced.push(json!({
                    "kind": "refresh_token", "identifier": issued_refresh_jti,
                    "note": format!(
                        "RFC 8693 section 2.2.1's optional `refresh_token`, \
                         minted because oauth2.tokenExchangeRefreshToken is \
                         \"{}\" for this client and the request {}. It is an \
                         ordinary refresh token of this service: redeemable \
                         at the refresh grant, revocable, and bound to the \
                         same key or certificate as the access token above. \
                         It OUTLIVES the exchange, which is the point of \
                         asking — the client can go on reaching the audience \
                         after the subject_token it was exchanged for has \
                         expired.",
                        refresh_policy,
                        if asked_for_refresh {
                            "asked for one with requested_token_type"
                        } else { "did not ask for one" }),
                }));
            }
            acts.record(&json!({
                "protocol": "OAuth 2.0", "type": exchange_type,
                "outcome": "issued",
                "initial": {
                    "presented": if subject_presented.is_empty() {
                        "urn:sts:exchanged".to_string()
                    } else { subject_presented.clone() },
                    "what": if subject_verified {
                        "the subject of the token presented, which this \
                         service signed and verified — so they were \
                         authenticated here, earlier, by whatever grant \
                         produced it"
                    } else {
                        "the subject named in a token this service did NOT \
                         sign. The name was read without verifying anything, \
                         so this is somebody this service has been TOLD about \
                         rather than one it authenticated"
                    },
                },
                "intermediary": {
                    "presented": register_actor, "application": client_id,
                    "what": if actor_claims.is_some() {
                        intermediary_what.clone()
                    } else if !register_actor.is_empty() {
                        "the client performing the exchange, named as the \
                         actor by its own subject — no actor_token was sent, \
                         and the issuance policy chose a delegation, so the \
                         client acts for the subject".to_string()
                    } else {
                        "the client performing the exchange. No actor_token \
                         was sent, so no identity is named — the client is \
                         the whole of the middle here".to_string()
                    },
                },
                "target": {
                    "application": application_id.clone()
                        .unwrap_or_else(|| audience.clone()),
                    "what": if audience.is_empty() {
                        "unstated — neither `audience` nor `resource` was \
                         sent, so the token that came back is not addressed \
                         to anything in particular".to_string()
                    } else if application_id.is_some() {
                        format!("the application registered for the audience \
                                 \"{}\", which is what the exchanged token is \
                                 addressed to. The request named the \
                                 audience; this registry named the \
                                 application", audience)
                    } else {
                        "the audience or resource the exchanged token is for. \
                         No application here has registered it on \
                         `oauthAudience`, so it is recorded exactly as it \
                         was asked for".to_string()
                    },
                },
                "authorizedBy": row_text(&decision),
                "consumed": consumed,
                "produced": produced,
                "sessionId": "",
            }));
        }
        self.respond(Ok(exchanged))
    }
}
