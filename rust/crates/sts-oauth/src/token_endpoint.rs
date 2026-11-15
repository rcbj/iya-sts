// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `POST /oauth2/token` (`oauth2.ts`'s `tokenGrant()`), for the three grants
//! of the authorization server's core: `client_credentials`,
//! `authorization_code` and `refresh_token`.
//!
//! The checks before any grant run in Node's order, each with its error,
//! status and code: the model's validation of the form; a client assertion
//! naming no client, or several; a client nobody registered, in product
//! mode; the grant the authorization server advertises; RFC 9700 section
//! 2.5's client authentication in that mode (`checkClientAuthentication()`);
//! the scope the client may be issued (`scopeRefusal()`, rule 3au) and the
//! audience plan (RFC 9068 section 3); `token_endpoint_auth_signing_alg`;
//! the observed authentication; the grant types the client declared (RFC
//! 7591 section 2); and product mode's confidential-client and public-client
//! rules. Then the grant, and `issue()` → `tokenSet()`: the RFC 9068 access
//! token (`accessTokenUnsigned()`), its record in the token register, and a
//! refresh token where the grant and the client allow one.
//!
//! NOT HERE, each a later slice or a port, and what this runtime answers
//! meanwhile: every other grant is `unsupported_grant_type`
//! (`STS-OAUTH-0227`), as Node answers one it does not know; FAPI's checks,
//! OAuth 2.1's declaration refusals, client attestation, the secret rate
//! limit, RFC 9396 details, delegated permissions (rule 3bq), RFC 8707's
//! registered targets, the issuance gate's policy (rule 3v: an empty decider
//! issues) and Grant Management do not run; the DPoP proof is verified by
//! the caller, which hands its `jkt` in ([`TokenAsk::dpop_jkt`]); the ID
//! Token of an `openid` grant is the OIDC slice's ([`IdTokens`]).

use std::sync::Arc;

use serde_json::{json, Map, Value as Json};
use sts_core::errors::codes;
use sts_core::mode::Mode;
use sts_core::settings::Settings;

use crate::answer::Answer;
use crate::bcp::{self, BcpMode, Question};
use crate::client_auth::{
    ClientAuth, Clock, MethodHints, PeerCertificate, Presented, Verified,
};
use crate::clients::Clients;
use crate::js;
use crate::jwt_access_token::{
    audience_plan, DetailAudience, PlannedScope, OIDC_SCOPES,
};
use crate::minted::{IssuedUnder, TokenRegister};

/// What a token request is.
#[derive(Debug, Clone, Default)]
pub struct TokenAsk {
    /// `asBaseOf(req)`: the authorization server's base URL, the realm's
    /// prefix included.
    pub base: String,
    /// The `application/x-www-form-urlencoded` body.
    pub body: String,
    pub authorization: String,
    /// The `jkt` of a DPoP proof the caller verified.
    pub dpop_jkt: String,
    pub peer: Option<PeerCertificate>,
    /// The `DPoP` header, where one was sent.
    pub dpop: Option<String>,
    /// `dpop.htuOf(req)`: the token endpoint's URL as the proof names it.
    pub htu: String,
}

/// An access token's status-list entry (draft-ietf-oauth-status-list,
/// `access_token_status.ts`'s allocation).
pub trait StatusList: Send + Sync {
    /// `{ idx, uri }` for a token about to be minted.
    fn allocate(
        &self,
        jti: &str,
        base: &str,
        expires_at_ms: i64,
    ) -> (u64, String);
}

/// One process's allocation: indexes counted up from a random start, the
/// list at `<base>/status-lists/access-tokens`.
pub struct LocalStatusList(std::sync::atomic::AtomicU64);

impl Default for LocalStatusList {
    fn default() -> Self {
        let start = sts_crypto::random::random_int(1, 1 << 24).unwrap_or(1);
        LocalStatusList(std::sync::atomic::AtomicU64::new(start))
    }
}

impl StatusList for LocalStatusList {
    fn allocate(
        &self,
        _jti: &str,
        base: &str,
        _expires_at_ms: i64,
    ) -> (u64, String) {
        let idx = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        (idx, format!("{}/status-lists/access-tokens", base))
    }
}

/// The realm's signer: a payload signed under the realm's key set with a
/// header Node's order (`alg`, `typ`, `kid`).
pub trait Signer: Send + Sync {
    fn sign(
        &self,
        payload: &Map<String, Json>,
        typ: &str,
        alg: &str,
    ) -> Result<String, String>;
    /// The realm's refresh-token encryption keys
    /// (`refreshTokenEncKeys` of the key set).
    fn refresh_keys(&self) -> Json {
        Json::Null
    }
    /// `helpers.verifyOwnJws(token)`: the claims of a JWS this realm
    /// signed, or the verifier's sentence.
    fn verify_own(&self, _token: &str, _now_s: i64) -> Result<Json, String> {
        Err("no key verified it".into())
    }
}

/// The OIDC slice's ID Token (`idToken()`), not minted here.
pub trait IdTokens: Send + Sync {
    fn id_token(&self, base: &str, issuing: &Json) -> Option<String>;
}

/// `accessTokenPlan(base, scope, clientId, explicit, details, req)`: the
/// audiences and the scope claim (RFC 9068 section 3, through
/// `audiencePlan()`), a scope naming a delegated permission or an
/// application read as an audience, and an audience naming nothing
/// registered refused (`STS-OAUTH-0986`). RFC 9396 details are a later
/// slice's.
#[tracing::instrument(level = "debug", skip(clients, settings, policy))]
pub fn plan_for(
    clients: &dyn Clients,
    settings: &Settings,
    policy: &crate::scopes::ScopePolicy,
    base: &str,
    scope: &str,
    client_id: &str,
    explicit: &[String],
) -> crate::jwt_access_token::AudiencePlan {
    let reserved =
        crate::scopes::protocol_scopes(settings, &policy.credential_scopes);
    let named =
        crate::scopes::audience_scopes(clients, &reserved, scope, client_id);
    let mut seen: Vec<String> = Vec::new();
    let mut scopes = Vec::new();
    for one in scope.split_whitespace() {
        if seen.iter().any(|s| s == one) {
            continue;
        }
        seen.push(one.to_string());
        if let Some(p) = named.permissions.iter().find(|p| p.scope == one) {
            scopes.push(PlannedScope::Permission {
                value: one.to_string(),
                name: p.permission.clone(),
                audience: p.audience.clone(),
            });
        } else if named.applications.iter().any(|a| a == one) {
            scopes.push(PlannedScope::Audience(one.to_string()));
        } else if OIDC_SCOPES.contains(&one) {
            scopes.push(PlannedScope::Oidc(one.to_string()));
        } else {
            scopes.push(PlannedScope::Ordinary(one.to_string()));
        }
    }
    let mut plan = audience_plan(
        &crate::jwt_access_token::JwtAccessTokens::default_audience_for(base),
        explicit,
        &scopes,
        &DetailAudience::default(),
    );
    if plan.refusal.is_none() {
        let own = clients.client_audience_names(client_id);
        let others: Vec<String> = plan
            .audiences
            .iter()
            .filter(|a| !own.contains(a))
            .cloned()
            .collect();
        let targets = crate::scopes::RegisteredTargets { clients, settings };
        let strangers = targets.unregistered(&others, &[base.to_string()]);
        if !strangers.is_empty() {
            plan.refusal = Some(crate::jwt_access_token::Refusal {
                error: "invalid_target",
                code: codes::STS_OAUTH_0986,
                description: format!(
                    "The access token would be addressed to {}",
                    crate::scopes::describe_unregistered(&strangers)
                ),
            });
        }
    }
    plan
}

/// The token endpoint's dependencies.
pub struct TokenEndpoint {
    pub settings: Arc<Settings>,
    pub mode: Arc<Mode>,
    pub clients: Arc<dyn Clients>,
    pub auth: Arc<ClientAuth>,
    pub register: Arc<TokenRegister>,
    pub status: Arc<dyn StatusList>,
    pub signer: Arc<dyn Signer>,
    pub clock: Arc<dyn Clock>,
    pub id_tokens: Option<Arc<dyn IdTokens>>,
    /// The scope policy (rule 3au), which also holds `credentialScopes()`.
    pub scopes: Arc<crate::scopes::ScopePolicy>,
    /// The codes, transactions and refresh families.
    pub grants: Arc<crate::grants::GrantStores>,
    /// The cluster's claims: a code, a refresh token and a family spent
    /// once across every node.
    pub claims: Arc<dyn sts_cluster::scheduler::Claims>,
    /// DPoP's nonces and replay history.
    pub dpop: Arc<crate::dpop_stores::DpopStores>,
    /// The scopes a resource gates by role.
    pub gated: Arc<dyn crate::authorize::GatedScopes>,
    /// The people a grant is issued for.
    pub people: Arc<dyn People>,
    /// The sign-on sessions a grant lasts as long as.
    pub sessions: Arc<dyn GrantSessions>,
}

/// The person a token is issued for (`userFor()`, `nameForSubject()`).
pub trait People: Send + Sync {
    /// `userFor(username)`: the person object, `{ username, sub, … }`.
    fn user_for(&self, username: &str) -> Json;
    /// `nameForSubject(sub)`: the username a `urn:uuid:` subject names now.
    fn name_for_subject(&self, sub: &str) -> Option<String>;
    /// `hasSubjectResolver()`: the directory answers subjects.
    fn has_subject_resolver(&self) -> bool;
}

/// The sessions a refresh asks about (`authn.sessionById()`,
/// `sessionEnded()`).
pub trait GrantSessions: Send + Sync {
    /// '' while the session is live, else why it is not (`ended` when it
    /// is gone).
    fn ended(&self, sid: &str) -> String;
}

impl GrantSessions for sts_authn::Sessions {
    fn ended(&self, sid: &str) -> String {
        match self.session_by_id(sid) {
            None => "ended".to_string(),
            Some(held) => self.session_ended(Some(&held), 0.0),
        }
    }
}

fn s(v: Option<&Json>) -> String {
    crate::js::string_of(v)
}

/// `clientFrom(req, body)`.
#[derive(Debug, Clone, Default)]
pub struct ClientPresented {
    pub client_id: String,
    pub client_secret: String,
    pub assertion: String,
    pub assertion_type: String,
    pub basic: bool,
}

fn decode_part(text: &str) -> String {
    url::form_urlencoded::parse(
        format!("x={}", text.replace('+', "%2B")).as_bytes(),
    )
    .next()
    .map(|(_, v)| v.into_owned())
    .unwrap_or_else(|| text.to_string())
}

/// `clientFrom()`: an `Authorization: Basic` credential, else the body's.
#[tracing::instrument(level = "debug", skip_all)]
pub fn client_from(
    authorization: &str,
    body: &Map<String, Json>,
) -> ClientPresented {
    let lower = authorization.to_ascii_lowercase();
    if lower.starts_with("basic ") || lower.starts_with("basic\t") {
        let raw = authorization[6..].trim();
        let decoded = sts_crypto::b64::decode_loose(raw).unwrap_or_default();
        let text = String::from_utf8_lossy(&decoded).to_string();
        let (id, secret) = match text.find(':') {
            Some(i) => (decode_part(&text[..i]), decode_part(&text[i + 1..])),
            None => (decode_part(&text), String::new()),
        };
        return ClientPresented {
            client_id: id,
            client_secret: secret,
            basic: true,
            ..ClientPresented::default()
        };
    }
    let mut asserted = String::new();
    let assertion = s(body.get("client_assertion"));
    if !assertion.is_empty() && s(body.get("client_id")).is_empty() {
        if let Ok(claims) = crate::js::segment_json(&assertion, 1) {
            asserted = s(claims.get("sub"));
        }
    }
    let id = s(body.get("client_id"));
    ClientPresented {
        client_id: if id.is_empty() { asserted } else { id },
        client_secret: s(body.get("client_secret")),
        assertion,
        assertion_type: s(body.get("client_assertion_type")),
        basic: false,
    }
}

impl TokenEndpoint {
    fn bcp_mode(&self) -> BcpMode {
        BcpMode {
            enabled: self.settings.value_of("oauth2.rfc9700").as_bool()
                || self.settings.value_of("oauth2.oauth21").as_bool()
                || self.mode.enforces_oauth_security_bcp(),
        }
    }

    /// `grant_types_supported` as the default authorization server
    /// advertises it (`asMetadata()`, then `bcp.applyToMetadata()`).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn grant_types_supported(&self) -> Vec<String> {
        let mut out: Vec<String> = [
            "authorization_code",
            "implicit",
            "refresh_token",
            "client_credentials",
            "password",
            "urn:ietf:params:oauth:grant-type:token-exchange",
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        ]
        .iter()
        .map(|one| one.to_string())
        .collect();
        let not_false = |k: &str| {
            !matches!(
                self.settings.value_of(k),
                sts_core::settings::SettingValue::Bool(false)
            )
        };
        if not_false("oauth2.jwtBearerGrant") {
            out.push("urn:ietf:params:oauth:grant-type:jwt-bearer".into());
        }
        if not_false("oauth2.saml2BearerGrant") {
            out.push("urn:ietf:params:oauth:grant-type:saml2-bearer".into());
        }
        if self.settings.value_of("oauth2.ciba").as_bool() {
            out.push("urn:openid:params:grant-type:ciba".into());
        }
        if self
            .settings
            .value_of("oauth2.deviceAuthorization")
            .as_bool()
        {
            out.push("urn:ietf:params:oauth:grant-type:device_code".into());
        }
        if self.bcp_mode().enabled {
            // The response types left after the mode drops `token` still
            // name an ID Token from the authorization endpoint, so
            // `implicit` stays (`impliesImplicitGrant()`).
            out.retain(|g| g != "password");
        }
        out
    }

    fn refusal(
        &self,
        code: sts_core::errors::ErrorCode,
        status: u16,
        error: &str,
        description: &str,
    ) -> Answer {
        Answer::refusal(code, status, error, description)
    }

    fn with_basic_challenge(&self, mut answer: Answer, basic: bool) -> Answer {
        if basic {
            let realm = self
                .settings
                .value_of("oauth2.basicAuthRealm")
                .as_str()
                .replace('\\', "\\\\")
                .replace('"', "\\\"");
            answer
                .set("WWW-Authenticate", &format!("Basic realm=\"{}\"", realm));
        }
        answer
    }

    fn access_token_alg(&self) -> String {
        let set = self.settings.value_of("oauth2.accessTokenSigningAlg");
        let set = set.as_str();
        if set.is_empty() || set == "default" {
            "RS256".into()
        } else {
            set.to_string()
        }
    }

    /// The token endpoint.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn answer(&self, ask: &TokenAsk) -> Answer {
        let pairs = crate::js::form_decode(&ask.body);
        let spent = self.spend_presented_code(&crate::js::fold(&pairs)).await;
        let folded = crate::js::fold(&pairs);
        let body = match crate::model::check("token", &folded, "body") {
            Ok(b) => b,
            Err(r) => {
                let mut a = self.refusal(
                    codes::STS_OAUTH_0196,
                    400,
                    "invalid_request",
                    &r.detail,
                );
                a.set("Cache-Control", "no-store");
                return a;
            }
        };
        let client = client_from(&ask.authorization, &body);
        let grant = s(body.get("grant_type"));
        if !client.assertion.is_empty() && client.client_id.is_empty() {
            return self.refusal(codes::STS_OAUTH_0675, 401, "invalid_client", "The client_assertion names no client: it carries no sub, and the request no client_id (RFC 7523 section 3).");
        }
        if client.assertion.split('.').count() == 3 {
            if let Ok(claims) = crate::js::segment_json(&client.assertion, 1) {
                let named: Vec<String> = [
                    s(claims.get("iss")),
                    s(claims.get("sub")),
                    s(body.get("client_id")),
                ]
                .into_iter()
                .filter(|n| !n.is_empty())
                .collect();
                if named.iter().any(|n| *n != named[0]) {
                    let client_id = s(body.get("client_id"));
                    return self.refusal(codes::STS_OAUTH_0677, 401, "invalid_client", &format!(
                        "The client_assertion names more than one client: iss \"{}\", sub \"{}\"{}. For client authentication each MUST be the client_id (RFC 7523 section 3, OpenID Connect Core section 9).",
                        s(claims.get("iss")), s(claims.get("sub")),
                        if client_id.is_empty() { String::new() } else { format!(", and the request's client_id \"{}\"", client_id) }));
                }
            }
        }
        let registered = self.clients.client_config_of(&client.client_id);
        let known = registered.get("known") == Some(&Json::Bool(true));
        if !client.client_id.is_empty()
            && !self.mode.issues_to_unregistered_applications()
            && !known
        {
            let a = self.refusal(codes::STS_OAUTH_0949, 401, "invalid_client", &format!(
                "The client \"{}\" is not registered in this realm. In product mode this authorization server serves only a client registered ahead of time (the console, /admin-api, RFC 7591, an LDAP add under ou=applications or an OpenID Federation); one that was only seen is not registered.",
                client.client_id.trim()));
            return self.with_basic_challenge(a, client.basic);
        }
        // THE DPoP PROOF (RFC 9449 section 4.3), verified here against the
        // nonce store and the replay history, the jti reserved across the
        // cluster first.
        let mut dpop_jkt = ask.dpop_jkt.clone();
        let mut dpop_jwk = Json::Null;
        if let Some(header) = ask.dpop.as_deref() {
            let skew = sts_oauth_dpop_skew(&self.dpop);
            let reservation = crate::dpop_reservation::Reservation::reserve(
                self.claims.as_ref(),
                Some(header),
                skew,
            )
            .await;
            // The proof's context is dropped before the reservation is
            // settled, so nothing held across the await is shared.
            let checked = {
                let ctx = crate::dpop_reservation::Reserved {
                    local: self.dpop.as_ref(),
                    reservation: reservation.as_ref(),
                };
                crate::dpop::verify_proof(
                    Some(header),
                    &crate::dpop::ProofRequest {
                        htm: "POST",
                        htu: &ask.htu,
                        access_token: None,
                        expected_jkt: None,
                        now: self.clock.now_s(),
                    },
                    &ctx,
                )
            };
            if let Some(r) = &reservation {
                r.settle(self.claims.as_ref()).await;
            }
            match checked {
                Ok(proof) => {
                    dpop_jkt = proof.jkt;
                    dpop_jwk = proof.jwk;
                }
                Err(f) if f.need_nonce => {
                    let mut a = self.refusal(
                        f.code,
                        400,
                        "use_dpop_nonce",
                        "Authorization server requires nonce in DPoP proof",
                    );
                    if let Ok(n) = self.dpop.issue_nonce() {
                        a.set("DPoP-Nonce", &n);
                    }
                    return a;
                }
                Err(f) => {
                    return self.refusal(
                        f.code,
                        400,
                        "invalid_dpop_proof",
                        &f.description,
                    );
                }
            }
        }
        let advertised = self.grant_types_supported();
        if !grant.is_empty() && !advertised.contains(&grant) {
            return self.refusal(codes::STS_OAUTH_0197, 400, "unsupported_grant_type", &format!(
                "The \"default\" authorization server advertises grant_types_supported {} and this request asks for \"{}\". What its metadata says is what it does.",
                json!(advertised), grant));
        }
        let audiences = vec![
            format!("{}/oauth2/token", ask.base),
            crate::jwt_access_token::JwtAccessTokens::new(
                self.settings.clone(),
            )
            .issuer_for(&ask.base),
            ask.base.clone(),
        ];
        let presented = Presented {
            client_id: client.client_id.clone(),
            presented_secret: client.client_secret.clone(),
            assertion: client.assertion.clone(),
            assertion_type: client.assertion_type.clone(),
            audiences,
            issuer: ask.base.clone(),
            peer: ask.peer.clone(),
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
        if let Err(r) = bcp::check_client_authentication(
            self.bcp_mode(),
            &self.auth,
            &q,
            &memo,
        ) {
            let a = self.refusal(r.code, r.status, &r.error, &r.description);
            return self.with_basic_challenge(a, client.basic);
        }
        let scope = s(body.get("scope"));
        let resources = match crate::scopes::parse_resource_indicators(
            &values_of(body.get("resource")),
        ) {
            Ok(r) => r,
            Err(e) => {
                return self.refusal(
                    codes::STS_OAUTH_0154,
                    400,
                    "invalid_target",
                    &e,
                )
            }
        };
        {
            let targets = crate::scopes::RegisteredTargets {
                clients: self.clients.as_ref(),
                settings: &self.settings,
            };
            let strangers = targets
                .unregistered(&resources, std::slice::from_ref(&ask.base));
            if !strangers.is_empty() {
                return self.refusal(
                    codes::STS_OAUTH_0951,
                    400,
                    "invalid_target",
                    &format!(
                        "RFC 8707 section 2: the resource {}",
                        crate::scopes::describe_unregistered(&strangers)
                    ),
                );
            }
        }
        if !scope.is_empty() {
            let reserved = crate::scopes::protocol_scopes(
                &self.settings,
                &self.scopes.credential_scopes,
            );
            let found = crate::scopes::audience_scopes(
                self.clients.as_ref(),
                &reserved,
                &scope,
                &client.client_id,
            );
            let refused = crate::scopes::permission_refusal(
                &found,
                &self.settings,
                &self.mode,
                &client.client_id,
                &grant,
            );
            if !refused.is_empty() {
                return self.refusal(
                    codes::STS_OAUTH_0155,
                    400,
                    "invalid_scope",
                    &refused,
                );
            }
            if let Some(r) = self.scopes.refusal(&scope, &client.client_id) {
                return self.refusal(
                    r.code,
                    400,
                    "invalid_scope",
                    &r.description,
                );
            }
        }
        if !scope.is_empty() || !resources.is_empty() {
            let plan = plan_for(
                self.clients.as_ref(),
                &self.settings,
                &self.scopes,
                &ask.base,
                &scope,
                &client.client_id,
                &resources,
            );
            if let Some(r) = plan.refusal {
                return self.refusal(r.code, 400, r.error, &r.description);
            }
        }
        let pinned = s(registered.get("token_endpoint_auth_signing_alg"));
        if !pinned.is_empty() && !client.assertion.is_empty() {
            let alg = crate::js::header_member(&client.assertion, "alg");
            if alg != pinned {
                return self.refusal(codes::STS_OAUTH_0570, 401, "invalid_client", &format!(
                    "Client \"{}\" registered token_endpoint_auth_signing_alg \"{}\", and its client_assertion is signed with \"{}\". OIDC Core section 9: an assertion signed with any other algorithm is rejected.",
                    client.client_id, pinned, if alg.is_empty() { "(none)" } else { &alg }));
            }
        }
        let observed =
            bcp::observe_client_authentication(&self.auth, &q, &memo);
        let flows = if client.client_id.is_empty() {
            None
        } else {
            self.clients.declared_flows_of(&client.client_id)
        };
        let declared_grants: Option<Vec<String>> = flows
            .as_ref()
            .and_then(|f| f.get("grant_types"))
            .and_then(Json::as_array)
            .map(|l| l.iter().map(|g| s(Some(g))).collect());
        if !client.client_id.is_empty()
            && declared_grants.is_none()
            && self.mode.narrows_undeclared_grants()
            && grant != "authorization_code"
            && grant != "refresh_token"
        {
            return self.refusal(codes::STS_OAUTH_0598, 400, "unauthorized_client", &format!(
                "Client \"{}\" declares no grant_types, so it may use authorization_code and refresh_token alone.", client.client_id));
        }
        if let Some(list) = &declared_grants {
            if !list.contains(&grant) {
                return self.refusal(codes::STS_OAUTH_0598, 400, "unauthorized_client", &format!(
                    "Client \"{}\" declares grant_types {}, and this request is the {} grant (RFC 7591 section 2).",
                    client.client_id, json!(list), grant));
            }
        }
        if self.mode.requires_confidential_client_authentication()
            && !bcp::declared_public(&registered)
            && !observed.authenticated
        {
            tracing::info!("oauth2: product mode refused the token request from \"{}\": {}", if client.client_id.is_empty() { "(unnamed)" } else { &client.client_id }, observed.why);
            let description = format!("This service is in product mode, where an application that registered a token_endpoint_auth_method other than \"none\" must present that credential and it must verify. A client registered token_endpoint_auth_method=\"none\" is public, is allowed, and is held to PKCE instead. {}", observed.why);
            let a = self.refusal(
                observed.code.unwrap_or(codes::STS_OAUTH_0192),
                401,
                "invalid_client",
                &description,
            );
            return self.with_basic_challenge(a, client.basic);
        }
        if self.mode.requires_confidential_client_authentication()
            && bcp::declared_public(&registered)
            && grant == "client_credentials"
        {
            return self.refusal(codes::STS_OAUTH_0552, 400, "unauthorized_client", "This client is PUBLIC (token_endpoint_auth_method=\"none\"), and in product mode a public client may use the authorization code and refresh grants only. RFC 6749 section 4.4 defines the client credentials grant for a client that HAS credentials, and OAuth 2.1 section 4.2 limits it to confidential clients outright; a public client using it would mint a token for anybody who knows the client_id. Register this client with a confidential token_endpoint_auth_method and a credential to use it.");
        }
        let issuing = Issuing {
            ask,
            client: &client,
            body: &body,
            grant: grant.clone(),
            observed_authenticated: observed.authenticated,
            observed_method: observed.method.clone(),
            dpop_jkt,
            dpop_jwk,
            flows,
            resources: resources.clone(),
        };
        match grant.as_str() {
            "client_credentials" => {
                self.client_credentials(&issuing, &scope, &resources)
            }
            "authorization_code" => {
                self.authorization_code(&issuing, spent).await
            }
            "refresh_token" => self.refresh_grant(&issuing).await,
            _ => self.refusal(
                codes::STS_OAUTH_0227,
                400,
                "unsupported_grant_type",
                &format!("grant_type \"{}\" is not supported.", grant),
            ),
        }
    }

    fn client_credentials(
        &self,
        issuing: &Issuing<'_>,
        scope: &str,
        resources: &[String],
    ) -> Answer {
        let id = if issuing.client.client_id.is_empty() {
            "unknown-client".to_string()
        } else {
            issuing.client.client_id.clone()
        };
        let subject = if self.bcp_mode().enabled {
            format!("urn:sts:client:{}", id)
        } else {
            id.clone()
        };
        let protected = crate::scopes::protected_scopes(&self.settings);
        let reserved = crate::scopes::protocol_scopes(
            &self.settings,
            &self.scopes.credential_scopes,
        );
        let audience: Vec<String> = if !resources.is_empty() {
            resources.to_vec()
        } else {
            let asked: Vec<&str> = scope.split_whitespace().collect();
            if asked.iter().any(|one| {
                protected.iter().any(|p| p == one)
                    || reserved.iter().any(|r| r == one)
            }) || issuing.client.client_id.is_empty()
            {
                Vec::new()
            } else {
                vec![issuing.client.client_id.clone()]
            }
        };
        let opts = Mint {
            sub: subject,
            client_id: issuing.client.client_id.clone(),
            scope: scope.to_string(),
            audience,
            grant: "client_credentials".into(),
            jkt: issuing.dpop_jkt.clone(),
            with_refresh: false,
            ..Mint::default()
        };
        self.respond(self.issue(issuing, opts))
    }

    fn respond(&self, built: Result<Json, Answer>) -> Answer {
        match built {
            Ok(payload) => {
                let mut a = Answer::json(payload);
                a.set("Cache-Control", "no-store");
                a
            }
            Err(a) => a,
        }
    }

    // -------------------------------------------------------------------
    // The authorization code grant.
    // -------------------------------------------------------------------

    /// `spendPresentedCode(raw)`: before anything else is read, a code
    /// presented is taken out of the store and claimed across the cluster,
    /// so it can be presented once whatever the request's outcome (#46).
    async fn spend_presented_code(
        &self,
        raw: &Map<String, Json>,
    ) -> Option<Spent> {
        let code = match raw.get("code") {
            Some(Json::String(c)) => c.clone(),
            _ => String::new(),
        };
        if s(raw.get("grant_type")) != "authorization_code"
            || code.is_empty()
            || self.code_redemption_relaxed()
        {
            return None;
        }
        let key =
            sts_crypto::secrets::credential_digest(&code).unwrap_or_default();
        let Some(record) = self.grants.codes.get(&key) else {
            return Some(Spent {
                code,
                record: None,
                claim: None,
            });
        };
        self.grants.codes.delete(&key);
        if !self.grants.redeemed.has(&key) {
            self.make_room_for_redemption();
            let expires = js::to_number(&record["expires"]);
            let ttl = ttl_of(&record);
            self.grants.redeemed.set(
                &key,
                json!({
                    "when": self.clock.now_ms(), "expires": record["expires"],
                    "forget": expires + ttl, "ttlMs": ttl,
                    "client_id": s(record.get("client_id")),
                    "fingerprint": null, "jtis": null,
                }),
            );
        }
        let claim = self
            .claims
            .claim(
                "oauth.code",
                &code,
                &sts_core::realm::current_id(),
                self.code_claim_ttl_ms(&record),
            )
            .await;
        Some(Spent {
            code,
            record: Some(record),
            claim: Some(claim),
        })
    }

    fn code_redemption_relaxed(&self) -> bool {
        !self.bcp_mode().enabled
            && self
                .settings
                .value_of("oauth2.codeReplayIdempotent")
                .as_bool()
    }

    fn code_claim_ttl_ms(&self, record: &Json) -> f64 {
        let rest = (js::to_number(&record["expires"])
            - self.clock.now_ms() as f64)
            .max(0.0);
        rest + self.settings.value_of("oauth2.clockSkewS").as_int() as f64
            * 1000.0
    }

    /// `cacheRegistry.makeRoom(redeemedCodes, oauth2.redeemedCodeCacheSize)`:
    /// the oldest redemption forgotten at the bound.
    fn make_room_for_redemption(&self) {
        let now = self.clock.now_ms() as f64;
        self.grants
            .redeemed
            .in_realm(&sts_core::realm::current_id())
            .retain(|_, v| js::to_number(&v["forget"]) >= now);
        let cap = self
            .settings
            .value_of("oauth2.redeemedCodeCacheSize")
            .as_int();
        if cap > 0 {
            let keys = self.grants.redeemed.keys();
            let over = keys.len() as i64 - cap + 1;
            for key in keys.iter().take(over.max(0) as usize) {
                self.grants.redeemed.delete(key);
            }
        }
    }

    fn fingerprint(&self, issuing: &Issuing<'_>) -> Json {
        let verifier = s(issuing.body.get("code_verifier"));
        json!({
            "client_id": issuing.client.client_id,
            "redirect_uri": s(issuing.body.get("redirect_uri")),
            "code_verifier": if verifier.is_empty() { String::new() }
                else { sts_crypto::secrets::credential_digest(&verifier).unwrap_or_default() },
            "dpop_jkt": issuing.dpop_jkt,
        })
    }

    fn uptime(&self) -> String {
        let seconds = ((self.clock.now_ms() - started_at_ms()) / 1000).max(0);
        if seconds < 120 {
            format!("{} second(s)", seconds)
        } else if seconds < 7200 {
            format!("{} minute(s)", (seconds as f64 / 60.0).round())
        } else {
            format!("{} hour(s)", (seconds as f64 / 3600.0).round())
        }
    }

    fn revoke(&self, jti: &str, via: &str, superseded: bool, exp: i64) {
        let realm = sts_core::realm::current_id();
        let _ = exp;
        self.register
            .revoke(&realm, jti, via, superseded, self.clock.now_ms());
    }

    /// `replayOrRefuseRedemption()`: a code with no record is unknown, or
    /// was presented before; a repeat is refused and what the code bought
    /// revoked (RFC 6749 section 10.5).
    async fn replay_or_refuse(&self, key: &str) -> Answer {
        let now = self.clock.now_ms() as f64;
        let done = self
            .grants
            .redeemed
            .get(key)
            .filter(|d| js::to_number(&d["forget"]) >= now);
        let Some(mut done) = done else {
            return self.refusal(codes::STS_OAUTH_0187, 400, "invalid_grant", &format!(
                "Unknown or already-used authorization code. Nothing is held here under that value and nothing was redeemed under it recently: this service keeps authorization codes in memory only, so a code issued before it was last restarted (it has been up {}) went with them, as did one issued by a different authorization server.",
                self.uptime()));
        };
        let ago = ((now - js::to_number(&done["when"])) / 1000.0)
            .round()
            .max(0.0) as i64;
        let client = s(done.get("client_id"));
        if done.get("jtis").is_none_or(Json::is_null) {
            done["presentedAgainAt"] = json!(now as i64);
            self.grants.redeemed.set(key, done);
            return self.refusal(codes::STS_OAUTH_0789, 400, "invalid_grant", &format!(
                "This authorization code was already presented {} second(s) ago{}, and that Token Request did not redeem it. An authorization code may be presented once, whatever that request's outcome (RFC 6749 section 4.1.2): start a new authorization request.",
                ago, if client.is_empty() { String::new() } else { format!(" for client \"{}\"", client) }));
        }
        let jtis: Vec<String> = done["jtis"]
            .as_array()
            .map(|l| {
                l.iter()
                    .map(|v| s(Some(v)))
                    .filter(|j| !j.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        tracing::warn!(
            "RFC 6749 section 4.1.2, RFC 9700 section 4.5: authorization code presented a second time by client \"{}\", {} second(s) after it was redeemed. Refusing it, and revoking the {} token(s) it bought (RFC 6749 section 10.5).",
            if client.is_empty() { "(none)" } else { &client }, ago, jtis.len());
        let family = s(done.get("family"));
        if !family.is_empty() {
            for jti in self.grants.grant_members_of(&family, "") {
                self.revoke(&jti, "RFC 9700 section 4.5: an authorization code was presented twice", false, 0);
            }
            self.revoke_family(&family, &client).await;
        }
        for jti in &jtis {
            self.revoke(jti, "RFC 9700 section 4.5: an authorization code was presented twice", false, 0);
        }
        self.refusal(codes::STS_OAUTH_0143, 400, "invalid_grant", &format!(
            "RFC 6749 section 4.1.2 and RFC 9700 section 4.5: an authorization code is single use. This one was redeemed {} second(s) ago by client \"{}\". A code presented twice means two holders and this server cannot tell which of them is the client, so the {} token(s) it bought have been revoked as well (RFC 6749 section 10.5). Start a new authorization request.",
            ago, if client.is_empty() { "(none)" } else { &client }, jtis.len()))
    }

    /// `bcp.revokeFamily(familyId, clientId)`: the family claimed as revoked
    /// across the cluster, for as long as a member of it could live.
    async fn revoke_family(&self, family: &str, client_id: &str) -> bool {
        if family.is_empty() {
            return false;
        }
        let per_client = self
            .clients
            .setting_for(client_id, "oauth2.refreshTokenTtlS")
            .map(|v| js::to_number(&v))
            .unwrap_or(f64::NAN);
        let ttl = self.grants.family_revocation_ttl_ms(per_client);
        match self
            .claims
            .claim(
                "oauth.refresh-family-revoked",
                family,
                &sts_core::realm::current_id(),
                ttl,
            )
            .await
        {
            Ok(_) | Err(sts_cluster::scheduler::ClaimRefused::Held) => true,
            Err(sts_cluster::scheduler::ClaimRefused::Store(why)) => {
                tracing::error!(
                    "{}RFC 9700 mode: refresh family {} could not be revoked by id, because the claim store could not be asked ({}). The members this node knows are revoked; one minted on another node at the same moment may not be.",
                    sts_core::log::tag(codes::STS_OAUTH_0518), family, why);
                false
            }
        }
    }

    /// `clusterClaims.isClaimed()`: asked as a claim taken and given back
    /// at once — the trait answers claims, and a claim that is held is the
    /// answer.
    async fn is_claimed(
        &self,
        scope: &str,
        value: &str,
    ) -> Result<bool, String> {
        match self
            .claims
            .claim(scope, value, &sts_core::realm::current_id(), 1000.0)
            .await
        {
            Ok(c) => {
                self.claims.release(&c.handle).await;
                Ok(false)
            }
            Err(sts_cluster::scheduler::ClaimRefused::Held) => Ok(true),
            Err(sts_cluster::scheduler::ClaimRefused::Store(why)) => Err(why),
        }
    }

    /// `grant === 'authorization_code'`.
    async fn authorization_code(
        &self,
        issuing: &Issuing<'_>,
        spent: Option<Spent>,
    ) -> Answer {
        let body = issuing.body;
        let code = s(body.get("code"));
        let key =
            sts_crypto::secrets::credential_digest(&code).unwrap_or_default();
        let ours = spent.filter(|sp| sp.code == code);
        let held_claim = ours.as_ref().and_then(|sp| sp.claim.clone());
        let record = match &ours {
            Some(sp) => sp.record.clone(),
            None => self.grants.codes.get(&key),
        };
        if let Some(Err(refused)) = &held_claim {
            return self.refuse_concurrent(&key, refused).await;
        }
        let Some(record) = record else {
            return self.replay_or_refuse(&key).await;
        };
        if js::to_number(&record["expires"]) < self.clock.now_ms() as f64 {
            self.grants.codes.delete(&key);
            return self.refusal(
                codes::STS_OAUTH_0199,
                400,
                "invalid_grant",
                "The authorization code has expired.",
            );
        }
        let server = match s(record.get("authorization_server")) {
            a if a.is_empty() => "default".to_string(),
            a => a,
        };
        let here = crate::authorization_servers::current();
        if server != here {
            return self.refusal(codes::STS_OAUTH_0200, 400, "invalid_grant", &format!(
                "This authorization code was issued by the \"{}\" authorization server and is being redeemed at the \"{}\" one. They are separate authorization servers that happen to share a process: they publish different capabilities and a credential does not cross between them. Redeem it at {}/oauth2/token.",
                server, here, crate::authorization_servers::path_of(&server)));
        }
        let asked_redirect = s(body.get("redirect_uri"));
        if !asked_redirect.is_empty()
            && asked_redirect != s(record.get("redirect_uri"))
        {
            return self.refusal(
                codes::STS_OAUTH_0201,
                400,
                "invalid_grant",
                "redirect_uri does not match the authorization request.",
            );
        }
        // bcp.checkTokenRequest(): the code's client, and its redirect_uri.
        let issued_to = s(record.get("client_id"));
        let presented = &issuing.client.client_id;
        if !issued_to.is_empty() && *presented != issued_to {
            return self.refusal(codes::STS_OAUTH_0146, 400, "invalid_grant", &format!(
                "RFC 6749 section 4.1.3 and OIDC Core section 3.1.3.2: this authorization code was issued to client \"{}\" and is being redeemed by {}.",
                issued_to, if presented.is_empty() { "a request that names no client".to_string() } else { format!("\"{}\"", presented) }));
        }
        // RFC 6749 section 4.1.3: redirect_uri is REQUIRED at the token
        // endpoint when it was in the authorization request, in every mode.
        // OAuth 2.1 removed it (section 10.2) — PKCE binds the code — and
        // asks it only of a code minted under the OpenID Connect nonce
        // exemption (`oauth21.tokenRedirectUriRequired()`).
        let required = !self.settings.value_of("oauth2.oauth21").as_bool()
            || js::truthy(record.get("pkce_exempt"));
        if !s(record.get("redirect_uri")).is_empty()
            && asked_redirect.is_empty()
            && required
        {
            return self.refusal(codes::STS_OAUTH_0147, 400, "invalid_grant", "RFC 6749 section 4.1.3: redirect_uri is required in the Token Request when it was present in the authorization request, and must be identical. It is missing.");
        }
        if self.bcp_mode().enabled
            && js::string_of(record.get("code_challenge")).is_empty()
            && !s(body.get("code_verifier")).is_empty()
        {
            return self.refusal(codes::STS_OAUTH_0145, 400, "invalid_grant", "RFC 9700 section 4.8.2: this authorization code was issued without a code_challenge, so a Token Request carrying a code_verifier is rejected. Accepting it is the PKCE downgrade attack — it lets an attacker who stripped code_challenge from the authorization request present any verifier here and be told nothing is wrong.");
        }
        let challenge = s(record.get("code_challenge"));
        if !challenge.is_empty() {
            let verifier = s(body.get("code_verifier"));
            if verifier.is_empty() {
                return self.refusal(
                    codes::STS_OAUTH_0202,
                    400,
                    "invalid_grant",
                    "PKCE was used, so code_verifier is required.",
                );
            }
            let computed = if s(record.get("code_challenge_method")) == "S256" {
                sts_crypto::secrets::credential_digest(&verifier)
                    .unwrap_or_default()
            } else {
                verifier
            };
            if computed != challenge {
                return self.refusal(
                    codes::STS_OAUTH_0203,
                    400,
                    "invalid_grant",
                    "The code_verifier does not match the code_challenge.",
                );
            }
        }
        let bound = s(record.get("dpop_jkt"));
        if !bound.is_empty() {
            if issuing.dpop_jkt.is_empty() {
                return self.refusal(codes::STS_OAUTH_0204, 400, "invalid_grant", "The authorization request bound this code to a DPoP key (dpop_jkt), so the Token Request must carry a DPoP proof from that key.");
            }
            if bound != issuing.dpop_jkt {
                return self.refusal(codes::STS_OAUTH_0205, 400, "invalid_grant", &format!(
                    "This authorization code is bound to DPoP key {}, but the proof was signed by {}.", bound, issuing.dpop_jkt));
            }
        }
        let granted: Vec<String> = values_of(record.get("resources"));
        let requested = &issuing.resources;
        let narrowed: Vec<String> = requested
            .iter()
            .filter(|r| granted.contains(r))
            .cloned()
            .collect();
        if !requested.is_empty() && narrowed.len() != requested.len() {
            let extra: Vec<String> = requested
                .iter()
                .filter(|r| !granted.contains(r))
                .cloned()
                .collect();
            return self.refusal(codes::STS_OAUTH_0206, 400, "invalid_target", &format!(
                "RFC 8707 section 2.2: a Token Request may narrow the resources the authorization request asked for and may not add to them. This authorization code carries {}, and the request asks additionally for: {}.",
                if granted.is_empty() { "no resource at all".to_string() } else { granted.join(", ") },
                extra.join(", ")));
        }
        let for_resources = if narrowed.is_empty() {
            granted.clone()
        } else {
            narrowed
        };
        if ours.is_none() {
            match self
                .claims
                .claim(
                    "oauth.code",
                    &code,
                    &sts_core::realm::current_id(),
                    self.code_claim_ttl_ms(&record),
                )
                .await
            {
                Ok(_) => {}
                Err(refused) => {
                    return self.refuse_concurrent(&key, &refused).await
                }
            }
        } else {
            self.grants.codes.delete(&key);
        }
        let user = record.get("user").cloned().unwrap_or(Json::Null);
        let opts = Mint {
            sub: s(user.get("sub")),
            username: s(user.get("username")),
            user: user.clone(),
            client_id: s(record.get("client_id")),
            scope: s(record.get("scope")),
            audience: for_resources.clone(),
            resources: for_resources,
            grant_resources: Some(granted.clone()).filter(|g| !g.is_empty()),
            grant: "authorization_code".into(),
            jkt: issuing.dpop_jkt.clone(),
            session_id: s(record.get("session_id")),
            session_authenticated: record.get("session_authenticated")
                != Some(&Json::Bool(false)),
            nonce: s(record.get("nonce")),
            auth_time: js::to_number(
                record.get("auth_time").unwrap_or(&Json::Null),
            ),
            amr: record.get("amr").cloned().unwrap_or(Json::Null),
            acr: record.get("acr").cloned().unwrap_or(Json::Null),
            grant_at: js::to_number(
                record.get("granted_at").unwrap_or(&Json::Null),
            ),
            with_refresh: true,
            ..Mint::default()
        };
        let issued = self.issue(issuing, opts);
        self.grants.codes.delete(&key);
        let answer = self.respond(issued.clone());
        if let Ok(payload) = &issued {
            self.remember_redemption(&key, &record, issuing, payload);
            self.grants.note_redeemed(self.bcp_mode().enabled, &record);
        }
        answer
    }

    /// `rememberRedemption()`: the jtis a code bought, so a repeat revokes
    /// them; one presented again while being answered revokes them now.
    fn remember_redemption(
        &self,
        key: &str,
        record: &Json,
        issuing: &Issuing<'_>,
        issued: &Json,
    ) {
        let prior = self.grants.redeemed.get(key);
        let again = prior.as_ref().is_some_and(|p| {
            p.get("presentedAgainAt").is_some_and(|v| !v.is_null())
        });
        if prior.is_none() {
            self.make_room_for_redemption();
        }
        let mut jtis: Vec<String> = Vec::new();
        for name in ["access_token", "refresh_token", "id_token"] {
            let token = s(issued.get(name));
            if token.is_empty() {
                continue;
            }
            let jti = if token.split('.').count() == 5 {
                self.refresh_jti_of(&token)
            } else {
                js::segment_json(&token, 1)
                    .ok()
                    .map(|c| s(c.get("jti")))
                    .unwrap_or_default()
            };
            if !jti.is_empty() {
                jtis.push(jti);
            }
        }
        let family = {
            let token = s(issued.get("refresh_token"));
            self.refresh_claims_of(&token)
                .map(|c| self.grants.family_of_refresh(&c))
                .unwrap_or_default()
        };
        let ttl = ttl_of(record);
        let expires = js::to_number(&record["expires"]);
        let mut row = json!({
            "when": self.clock.now_ms(), "expires": record["expires"],
            "forget": expires + ttl, "ttlMs": ttl,
            "client_id": issuing.client.client_id,
            "fingerprint": self.fingerprint(issuing),
            "jtis": jtis, "family": family,
        });
        if self.code_redemption_relaxed() {
            row["response"] = issued.clone();
        }
        self.grants.redeemed.set(key, row);
        self.grants.redeemed_recorded.notify_waiters();
        if again {
            for jti in &jtis {
                self.revoke(jti, "RFC 9700 section 4.5: an authorization code was presented twice", false, 0);
            }
            tracing::warn!("oauth2: an authorization code was presented again while its first presentation was being answered; the tokens that presentation issued are revoked (RFC 6749 section 10.5).");
        }
    }

    /// `refuseConcurrentRedemption()`: another request holds the code's
    /// claim, and this one is answered as its replay once it is recorded.
    async fn refuse_concurrent(
        &self,
        key: &str,
        refused: &sts_cluster::scheduler::ClaimRefused,
    ) -> Answer {
        if let sts_cluster::scheduler::ClaimRefused::Store(why) = refused {
            tracing::error!(
                "{}oauth2: an authorization code could not be spent because the claim store could not be asked ({}); the Token Request is refused and the code is left unspent.",
                sts_core::log::tag(codes::STS_OAUTH_0513), why);
            return self.refusal(codes::STS_OAUTH_0513, 500, "server_error", &format!(
                "This authorization server could not record that the authorization code is being redeemed, so it has not redeemed it. {}",
                if self.code_redemption_relaxed() { "The code has not been spent; retry the Token Request." }
                else { "An authorization code may be presented once, so start a new authorization request." }));
        }
        tracing::warn!("oauth2: an authorization code is being redeemed by another request at the same moment; this one waits for that redemption and is answered as a replay of it.");
        // `awaitRedemptionRecord()`: a bounded wait inside this one
        // request — CONCURRENT_REDEMPTION_WAIT_MS (5 s) in polls of
        // CONCURRENT_REDEMPTION_POLL_MS (50 ms) — not periodic work.
        let recorded = |me: &Self| {
            me.grants
                .redeemed
                .get(key)
                .is_some_and(|d| d.get("jtis").is_some_and(|j| !j.is_null()))
        };
        if !recorded(self) {
            // Woken by this process's redemption as it is recorded; a
            // redemption on another node arrives through the change log
            // within the same deadline, and is read once it has passed.
            let woken = self.grants.redeemed_recorded.notified();
            if tokio::time::timeout(
                std::time::Duration::from_millis(5000),
                woken,
            )
            .await
            .is_err()
            {
                tracing::debug!(
                    "oauth2: no redemption was recorded here within the \
                     wait; the record is read once more."
                );
            }
        }
        if !recorded(self) {
            return self.refusal(codes::STS_OAUTH_0512, 400, "invalid_grant", "This authorization code is being redeemed by another Token Request at the same moment, and that redemption had not completed within 5 second(s). An authorization code is single use (RFC 6749 section 4.1.2).");
        }
        self.replay_or_refuse(key).await
    }

    fn refresh_claims_of(&self, token: &str) -> Option<Json> {
        if token.is_empty() {
            return None;
        }
        let opened =
            crate::refresh_crypto::open(token, &self.signer.refresh_keys())
                .ok()?;
        js::segment_json(&opened, 1).ok()
    }

    fn refresh_jti_of(&self, token: &str) -> String {
        self.refresh_claims_of(token)
            .map(|c| s(c.get("jti")))
            .unwrap_or_default()
    }

    // -------------------------------------------------------------------
    // The refresh grant.
    // -------------------------------------------------------------------

    /// `refreshedPerson(claims)`: the person a refresh token's subject names
    /// NOW, or nobody — a person deleted, or deleted and re-created, is a
    /// different subject.
    fn refreshed_person(&self, claims: &Json) -> Option<Json> {
        let sub = s(claims.get("sub"));
        let personal = sub.to_ascii_lowercase().starts_with("urn:uuid:");
        if !personal || !self.people.has_subject_resolver() {
            return Some(self.people.user_for(&s(claims.get("username"))));
        }
        let name = self.people.name_for_subject(&sub)?;
        let mut user = self.people.user_for(&name);
        if s(user.get("sub")).is_empty() {
            return None;
        }
        user["sub"] = json!(sub);
        Some(user)
    }

    /// `grant === 'refresh_token'`.
    async fn refresh_grant(&self, issuing: &Issuing<'_>) -> Answer {
        let body = issuing.body;
        let opened = crate::refresh_crypto::open(
            &s(body.get("refresh_token")),
            &self.signer.refresh_keys(),
        )
        .map_err(|r| (r.code, r.message.clone()))
        .and_then(|jws| {
            self.signer
                .verify_own(&jws, self.clock.now_s())
                .map_err(|e| (codes::STS_OAUTH_0213, e))
        });
        let claims = match opened {
            Ok(c) => c,
            Err((code, why)) => {
                tracing::error!(
                    "{}the refresh token is not valid: {}",
                    sts_core::log::tag(code),
                    why
                );
                return self.refusal(
                    code,
                    400,
                    "invalid_grant",
                    &format!("The refresh token is not valid: {}", why),
                );
            }
        };
        let jti = s(claims.get("jti"));
        let claim_client = s(claims.get("client_id"));
        let presented = issuing.client.client_id.clone();
        let rotation = crate::sender_constraints::rotation_required(
            &self.settings,
            self.bcp_mode().enabled,
        );
        // bcp.checkRefreshRequest().
        let known = self.grants.refresh_record(&jti);
        let core_refusal = || -> Option<Answer> {
            if !presented.is_empty()
                && !claim_client.is_empty()
                && claim_client != presented
            {
                return Some(self.refusal(codes::STS_OAUTH_0141, 400, "invalid_grant", &format!(
                    "RFC 6749 section 6: this refresh token was issued to client \"{}\" and is being presented by \"{}\". A refresh token may only be used by the client it belongs to.",
                    claim_client, presented)));
            }
            let asked = s(body.get("scope"));
            if !asked.is_empty() {
                let granted = crate::scopes::split(&s(claims.get("scope")));
                let extra: Vec<String> = crate::scopes::split(&asked)
                    .into_iter()
                    .filter(|o| !granted.contains(o))
                    .collect();
                if !extra.is_empty() {
                    let held = s(claims.get("scope"));
                    return Some(self.refusal(codes::STS_OAUTH_0142, 400, "invalid_scope", &format!(
                        "RFC 6749 section 6: a refresh must not request a scope the original grant did not carry (and RFC 9700 section 2.3 restricts a token's privileges to the minimum). {}{}.",
                        if held.is_empty() { "This grant carries no scope, and the request asks for: ".to_string() }
                        else { format!("This grant carries \"{}\" and the request asks additionally for: ", held) },
                        extra.join(", "))));
                }
            }
            None
        };
        if self.bcp_mode().enabled || rotation {
            if let Some(k) = known
                .as_ref()
                .filter(|k| k.get("rotated") == Some(&Json::Bool(true)))
            {
                let family = s(k.get("family"));
                let (members, _) = self.grants.members_of(&family, &jti);
                tracing::warn!(
                    "RFC 9700 section 2.2.2: refresh token {} was already redeemed and has been presented again. Revoking all {} refresh token(s) in family {} — a replayed refresh token means the chain has been copied, and there is no way to tell which holder is the legitimate one.",
                    jti, members.len(), family);
                for m in &members {
                    self.revoke(m, "RFC 9700 section 2.2.2: a replayed refresh token revoked its family", false, 0);
                }
                self.revoke_family(&family, &claim_client).await;
                return self.refusal(codes::STS_OAUTH_0138, 400, "invalid_grant", &format!(
                    "RFC 9700 section 2.2.2: this refresh token was already redeemed. Presenting it again means the chain has been copied, and this server cannot tell the legitimate holder from the attacker — so all {} refresh token(s) descended from the original grant have been revoked. Start a new authorization request.",
                    members.len()));
            }
        }
        if self.bcp_mode().enabled {
            let idle = self
                .clients
                .setting_for(&presented, "oauth2.refreshIdleSeconds")
                .map(|v| js::to_number(&v))
                .unwrap_or(0.0);
            if idle > 0.0 {
                if let Some(family) = known
                    .as_ref()
                    .map(|k| s(k.get("family")))
                    .filter(|f| !f.is_empty())
                    .and_then(|f| self.grants.family(&f))
                {
                    let idle_for = ((self.clock.now_ms() as f64
                        - js::to_number(
                            family.get("lastUsedAt").unwrap_or(&json!(0)),
                        ))
                        / 1000.0)
                        .round();
                    if idle_for > idle {
                        return self.refusal(codes::STS_OAUTH_0139, 400, "invalid_grant", &format!(
                            "RFC 9700 section 2.2.2: this refresh token's grant has been unused for {} seconds and this server expires one after {} (oauth2.refreshIdleSeconds). It is an INACTIVITY timeout rather than the token's own expiry, so a client that refreshes regularly is never affected by it. Start a new authorization request.",
                            idle_for, idle));
                    }
                }
            }
            if presented.is_empty() {
                return self.refusal(codes::STS_OAUTH_0140, 400, "invalid_request", "RFC 6749 section 6: client_id is required on a refresh request, so that this server can check the refresh token is being used by the client it was issued to.");
            }
        }
        if let Some(a) = core_refusal() {
            return a;
        }
        if self.register_revoked(&jti) {
            return self.refusal(
                codes::STS_OAUTH_0214,
                400,
                "invalid_grant",
                "The refresh token was revoked.",
            );
        }
        let grant_session = s(claims.get("sid"));
        if !grant_session.is_empty()
            && !crate::scopes::split(&s(claims.get("scope")))
                .iter()
                .any(|w| w == "offline_access")
        {
            let ended = self.sessions.ended(&grant_session);
            if !ended.is_empty() {
                return self.refusal(codes::STS_OAUTH_0568, 400, "invalid_grant", &format!(
                    "This refresh token was granted without offline_access, so it lasts only as long as the sign-on session it came from, and that session has {}. Ask for offline_access with prompt=consent for access while the person is not signed in (OIDC Core section 11).",
                    ended));
            }
        }
        let bound_to = s(claims.get("cnf").and_then(|c| c.get("jkt")));
        if !bound_to.is_empty() {
            if issuing.dpop_jkt.is_empty() {
                return self.refusal(codes::STS_OAUTH_0215, 400, "invalid_grant", "This refresh token is bound to a DPoP key, so the Token Request must carry a DPoP proof from that key.");
            }
            if bound_to != issuing.dpop_jkt {
                return self.refusal(codes::STS_OAUTH_0216, 400, "invalid_grant", &format!(
                    "This refresh token is bound to DPoP key {}, but the proof was signed by {}.", bound_to, issuing.dpop_jkt));
            }
        }
        let kb = s(claims.get("kb_jkt"));
        if !kb.is_empty() && issuing.dpop_jkt != kb {
            return self.refusal(codes::STS_OAUTH_0706, 400, "invalid_dpop_proof", &format!(
                "This grant's ID Token is bound to DPoP key {} (bound_key), so a refresh must carry a DPoP proof from that key{}.",
                kb, if issuing.dpop_jkt.is_empty() { String::new() } else { format!(", and this one is from {}", issuing.dpop_jkt) }));
        }
        if crate::sender_constraints::refresh_dpop_required(&self.settings) {
            if issuing.dpop_jkt.is_empty() {
                return self.refusal(codes::STS_OAUTH_0524, 400, "invalid_dpop_proof", "this authorization server is configured to accept a refresh token only from the holder of the key it is bound to (RFC 9449 section 5), and this request carried no DPoP proof.");
            }
            if bound_to.is_empty() {
                return self.refusal(codes::STS_OAUTH_0523, 400, "invalid_grant", "this refresh token is not bound to a key. It was issued before oauth2.refreshTokenRequireDpop was turned on, or by a realm that does not have it on, and it is refused rather than bound to the key presenting it now — binding it here would let whoever holds it choose the key. Sign in again to be issued a bound one.");
            }
        }
        let granted_resources = values_of(claims.get("resources"));
        let extra: Vec<String> = issuing
            .resources
            .iter()
            .filter(|r| !granted_resources.contains(r))
            .cloned()
            .collect();
        if !extra.is_empty() {
            return self.refusal(codes::STS_OAUTH_0217, 400, "invalid_target", &format!(
                "RFC 9700 section 2.2.2: a refresh token is bound to the resource servers its grant was authorized for, and this one carries {}. The request asks additionally for: {}. A grant cannot widen itself by being renewed.",
                if granted_resources.is_empty() { "no resource at all".to_string() } else { granted_resources.join(", ") },
                extra.join(", ")));
        }
        let refresh_resources = if issuing.resources.is_empty() {
            granted_resources.clone()
        } else {
            issuing.resources.clone()
        };
        let Some(user) = self.refreshed_person(&claims) else {
            tracing::info!("oauth2: a refresh for \"{}\" was refused: its subject names nobody in this directory any more — the person was deleted, or deleted and re-created, which is a different subject.", s(claims.get("username")));
            return self.refusal(codes::STS_OAUTH_0511, 400, "invalid_grant", "The person this refresh token was issued for is no longer in this service's directory.");
        };
        // bcp.spendRefreshToken().
        if rotation && !jti.is_empty() {
            let family = known
                .as_ref()
                .map(|k| s(k.get("family")))
                .filter(|f| !f.is_empty())
                .unwrap_or_else(|| s(claims.get(crate::grants::FAMILY_CLAIM)));
            if !family.is_empty() {
                match self
                    .is_claimed("oauth.refresh-family-revoked", &family)
                    .await
                {
                    Err(why) => {
                        tracing::error!("{}RFC 9700 mode: whether refresh family {} was revoked could not be asked: {}. The refresh is refused.", sts_core::log::tag(codes::STS_OAUTH_0518), family, why);
                        return self.refusal(codes::STS_OAUTH_0518, 500, "server_error", "This authorization server could not record that the refresh token is being redeemed, so it has not redeemed it. The token has not been spent; retry.");
                    }
                    Ok(true) => {
                        tracing::warn!("RFC 9700 section 2.2.2: refresh token {} belongs to family {}, which a replay has already revoked. Refused, and revoked itself.", jti, family);
                        let (members, _) =
                            self.grants.members_of(&family, &jti);
                        for m in &members {
                            self.revoke(m, "RFC 9700 section 2.2.2: a replayed refresh token revoked its family", false, 0);
                        }
                        return self.refusal(codes::STS_OAUTH_0517, 400, "invalid_grant", "RFC 9700 section 2.2.2: this refresh token descends from a grant whose refresh chain was revoked after a refresh token in it was presented twice. Start a new authorization request.");
                    }
                    Ok(false) => {}
                }
            }
            let exp_ms = js::to_number(&claims["exp"]) * 1000.0;
            let skew = self.settings.value_of("oauth2.clockSkewS").as_int()
                as f64
                * 1000.0;
            let ttl = if exp_ms.is_finite() {
                (exp_ms - self.clock.now_ms() as f64).max(0.0)
            } else {
                3600.0 * 1000.0
            } + skew;
            match self
                .claims
                .claim(
                    "oauth.refresh",
                    &jti,
                    &sts_core::realm::current_id(),
                    ttl,
                )
                .await
            {
                Ok(_) => {}
                Err(sts_cluster::scheduler::ClaimRefused::Held) => {
                    let (members, _) = self.grants.members_of(&family, &jti);
                    tracing::warn!("RFC 9700 section 2.2.2: refresh token {} was redeemed by another request at the same moment, on this node or another. Revoking family {} by id and the {} member(s) known here — a refresh token redeemed twice means the chain has been copied.", jti, if family.is_empty() { "(unknown)" } else { &family }, members.len());
                    for m in &members {
                        self.revoke(m, "RFC 9700 section 2.2.2: a replayed refresh token revoked its family", false, 0);
                    }
                    self.revoke_family(&family, &claim_client).await;
                    return self.refusal(codes::STS_OAUTH_0516, 400, "invalid_grant", "RFC 9700 section 2.2.2: this refresh token was already redeemed. Presenting it again means the chain has been copied, and this server cannot tell the legitimate holder from the attacker — so the refresh tokens descended from the original grant have been revoked. Start a new authorization request.");
                }
                Err(sts_cluster::scheduler::ClaimRefused::Store(why)) => {
                    tracing::error!("{}RFC 9700 mode: refresh token {} could not be spent, because the claim store could not be asked ({}). Refused.", sts_core::log::tag(codes::STS_OAUTH_0518), jti, why);
                    return self.refusal(codes::STS_OAUTH_0518, 500, "server_error", "This authorization server could not record that the refresh token is being redeemed, so it has not redeemed it. The token has not been spent; retry.");
                }
            }
        }
        let asked_scope = s(body.get("scope"));
        let opts = Mint {
            parent_refresh_jti: jti.clone(),
            parent_refresh_family: s(claims.get(crate::grants::FAMILY_CLAIM)),
            sub: s(user.get("sub")),
            username: s(user.get("username")),
            user: user.clone(),
            client_id: claim_client.clone(),
            scope: if asked_scope.is_empty() {
                s(claims.get("scope"))
            } else {
                asked_scope
            },
            grant_scope: Some(s(claims.get("scope"))),
            audience: refresh_resources.clone(),
            resources: refresh_resources,
            grant_resources: Some(granted_resources),
            chain_iat: js::to_number(
                claims.get("chain_iat").unwrap_or(&Json::Null),
            ),
            jkt: if bound_to.is_empty() {
                issuing.dpop_jkt.clone()
            } else {
                bound_to
            },
            kb_jkt: kb,
            session_id: if grant_session.is_empty() {
                self.session_of_jti(&jti)
            } else {
                grant_session
            },
            session_authenticated: self.session_authenticated_of_jti(&jti),
            auth_time: js::to_number(
                claims.get("auth_time").unwrap_or(&Json::Null),
            ),
            amr: claims
                .get("amr")
                .filter(|a| a.is_array())
                .cloned()
                .unwrap_or(Json::Null),
            acr: claims
                .get("acr")
                .cloned()
                .filter(|a| !s(Some(a)).is_empty())
                .unwrap_or(Json::Null),
            grant: "refresh_token".into(),
            grant_at: js::to_number(
                claims.get("grant_at").unwrap_or(&Json::Null),
            ),
            origin_grant: s(claims.get("grant_type")),
            with_refresh: true,
            ..Mint::default()
        };
        let refreshed = self.issue(issuing, opts);
        if refreshed.is_ok() && rotation {
            self.grants.note_refresh_rotated(
                rotation,
                &jti,
                self.clock.now_ms() as f64,
            );
            let exp = js::to_number(&claims["exp"]) as i64;
            self.revoke(
                &jti,
                "RFC 9700 section 2.2.2: rotated on use",
                true,
                exp,
            );
        }
        self.respond(refreshed)
    }

    fn register_revoked(&self, jti: &str) -> bool {
        self.register.is_revoked(jti)
    }

    /// `stats.sessionIdOfJti(jti)`.
    fn session_of_jti(&self, jti: &str) -> String {
        self.register
            .get(&sts_core::realm::current_id(), jti)
            .map(|r| s(r.get("sessionId")))
            .unwrap_or_default()
    }

    /// `stats.sessionAuthenticatedOfJti(jti)`.
    fn session_authenticated_of_jti(&self, jti: &str) -> bool {
        self.register
            .get(&sts_core::realm::current_id(), jti)
            .is_none_or(|r| {
                r.get("sessionAuthenticated") != Some(&Json::Bool(false))
            })
    }

    // -------------------------------------------------------------------
    // issue() and tokenSet().
    // -------------------------------------------------------------------

    /// `issue(opts)`: a refresh token only where the client declared the
    /// grant, the admin console's tokens only DPoP-bound, then
    /// `tokenSet()`.
    fn issue(
        &self,
        issuing: &Issuing<'_>,
        mut opts: Mint,
    ) -> Result<Json, Answer> {
        let declared = issuing
            .flows
            .as_ref()
            .and_then(|f| f.get("grant_types"))
            .and_then(Json::as_array)
            .map(|l| l.iter().map(|v| s(Some(v))).collect::<Vec<_>>());
        if opts.with_refresh {
            if let Some(list) = &declared {
                if !list.iter().any(|g| g == "refresh_token") {
                    tracing::info!(
                        "{}oauth2: \"{}\" declares no refresh_token grant, so the {} grant is answered with no refresh token.",
                        sts_core::log::tag(codes::STS_OAUTH_0600), issuing.client.client_id, issuing.grant);
                    opts.with_refresh = false;
                }
            }
        }
        if let Some(r) =
            crate::sender_constraints::public_client_issuance_refusal(
                &opts.client_id,
                &issuing.observed_method,
                &issuing.dpop_jkt,
                &issuing.grant,
            )
        {
            return Err(self.refusal(
                r.code,
                if r.error == "invalid_client" {
                    401
                } else {
                    400
                },
                r.error,
                &r.description,
            ));
        }
        if opts.with_refresh
            && crate::sender_constraints::refresh_dpop_required(&self.settings)
            && issuing.dpop_jkt.is_empty()
        {
            return Err(self.refusal(codes::STS_OAUTH_0521, 400, "invalid_dpop_proof", &format!(
                "this authorization server is configured to issue refresh tokens only to a request that proves possession of a key (RFC 9449 section 5), and the {} request carried no DPoP proof. Send a DPoP header, or ask for a grant that mints no refresh token.",
                if issuing.grant.is_empty() { "token" } else { &issuing.grant })));
        }
        opts.client_authenticated = issuing.observed_authenticated;
        self.token_set(&issuing.ask.base, &opts, issuing)
    }

    /// `tokenSet()`: the access token, the refresh token, the ID Token.
    fn token_set(
        &self,
        base: &str,
        opts: &Mint,
        issuing: &Issuing<'_>,
    ) -> Result<Json, Answer> {
        let set_id = sts_crypto::b64::encode(
            &sts_crypto::random::random_bytes(12).unwrap_or_default(),
        );
        let mut scope =
            self.scopes
                .narrow(&opts.scope, &opts.client_id, &opts.grant);
        let key_binding = !matches!(
            self.settings.value_of("oauth2.keyBinding"),
            sts_core::settings::SettingValue::Bool(false)
        );
        if !key_binding && scope.split_whitespace().any(|w| w == "bound_key") {
            scope = scope
                .split_whitespace()
                .filter(|w| *w != "bound_key")
                .collect::<Vec<_>>()
                .join(" ");
        }
        if !opts.username.is_empty() && self.gated.asks_for_gated(&scope) {
            let narrowed = self.gated.narrow(
                &scope,
                &opts.username,
                true,
                &opts.client_id,
                &opts.grant,
            );
            if narrowed.get("emptied") == Some(&Json::Bool(true)) {
                return Err(self.refusal(
                    codes::STS_ADMIN_0822,
                    400,
                    "invalid_scope",
                    &s(narrowed.get("why")),
                ));
            }
            scope = s(narrowed.get("scope"));
        }
        let plan = plan_for(
            self.clients.as_ref(),
            &self.settings,
            &self.scopes,
            base,
            &scope,
            &opts.client_id,
            &opts.audience,
        );
        if let Some(r) = plan.refusal {
            return Err(self.refusal(r.code, 400, r.error, &r.description));
        }
        let refresh_jti = if opts.with_refresh {
            sts_crypto::b64::encode(
                &sts_crypto::random::random_bytes(16).unwrap_or_default(),
            )
        } else {
            String::new()
        };
        let family = if refresh_jti.is_empty() {
            String::new()
        } else {
            self.grants.family_for_issuance(
                &refresh_jti,
                &opts.parent_refresh_jti,
                &opts.parent_refresh_family,
            )
        };
        let under = IssuedUnder {
            grant: opts.grant.clone(),
            session_id: opts.session_id.clone(),
            session_authenticated: opts.session_authenticated,
            set_id: set_id.clone(),
            grant_id: if family.is_empty() {
                set_id.clone()
            } else {
                family.clone()
            },
            grant_refresh: !family.is_empty(),
            ..IssuedUnder::default()
        };
        let (access, payload) = self.access_token(
            base,
            opts,
            &plan.scope,
            &plan.audiences,
            &under,
        )?;
        let expires = js::to_number(&payload["exp"]) as i64
            - js::to_number(&payload["iat"]) as i64;
        let mut body = Map::new();
        body.insert("access_token".into(), json!(access));
        body.insert(
            "token_type".into(),
            json!(if opts.jkt.is_empty() {
                "Bearer"
            } else {
                "DPoP"
            }),
        );
        body.insert("expires_in".into(), json!(expires));
        if !plan.scope.is_empty() {
            body.insert("scope".into(), json!(plan.scope));
        }
        if opts.with_refresh {
            let refresh = self.refresh_token(
                base,
                opts,
                &refresh_jti,
                &family,
                &payload,
                &under,
                issuing,
            )?;
            body.insert("refresh_token".into(), json!(refresh));
        }
        if scope.split_whitespace().any(|w| w == "openid") {
            if let Some(ids) = &self.id_tokens {
                let issuing_facts = json!({
                    "user": opts.user, "client_id": opts.client_id,
                    "nonce": opts.nonce, "auth_time": opts.auth_time,
                    "amr": opts.amr, "acr": opts.acr,
                    "session_id": opts.session_id, "grant": opts.grant,
                    "set_id": set_id, "access_token": access, "scope": scope,
                    "sub": opts.sub,
                });
                if let Some(id) = ids.id_token(base, &issuing_facts) {
                    body.insert("id_token".into(), json!(id));
                }
            }
        }
        Ok(Json::Object(body))
    }

    /// `refreshTokenPlan()` + `refreshTokenNoted()`: the signed refresh
    /// token, sealed to the realm (`refresh_token_crypto.seal()`).
    #[allow(clippy::too_many_arguments)]
    fn refresh_token(
        &self,
        base: &str,
        opts: &Mint,
        jti: &str,
        family: &str,
        access: &Json,
        under: &IssuedUnder,
        issuing: &Issuing<'_>,
    ) -> Result<String, Answer> {
        let iat = self.clock.now_s();
        let chain_iat = if opts.chain_iat > 0.0 {
            opts.chain_iat as i64
        } else {
            iat
        };
        let exp = self.refresh_expiry(&opts.client_id, iat, chain_iat);
        let mut p = Map::new();
        p.insert(
            "iss".into(),
            json!(crate::jwt_access_token::JwtAccessTokens::new(
                self.settings.clone()
            )
            .issuer_for(base)),
        );
        p.insert("sub".into(), json!(opts.sub));
        p.insert("aud".into(), json!(base));
        p.insert("client_id".into(), json!(opts.client_id));
        p.insert(
            "scope".into(),
            json!(opts
                .grant_scope
                .clone()
                .unwrap_or_else(|| opts.scope.clone())),
        );
        p.insert("typ".into(), json!("Refresh"));
        p.insert("jti".into(), json!(jti));
        p.insert("username".into(), json!(opts.username));
        let resources = opts
            .grant_resources
            .clone()
            .unwrap_or_else(|| opts.resources.clone());
        if !resources.is_empty() {
            p.insert("resources".into(), json!(resources));
        }
        p.insert("iat".into(), json!(iat));
        p.insert("nbf".into(), json!(iat));
        p.insert("chain_iat".into(), json!(chain_iat));
        p.insert("exp".into(), json!(exp));
        let dpop_bound_refresh = !opts.jkt.is_empty()
            && (!issuing.observed_authenticated
                || crate::sender_constraints::refresh_dpop_required(
                    &self.settings,
                ));
        if dpop_bound_refresh {
            p.insert("cnf".into(), json!({ "jkt": opts.jkt }));
        }
        if opts.auth_time > 0.0 {
            p.insert("auth_time".into(), json!(opts.auth_time as i64));
        }
        if opts.amr.is_array() {
            p.insert("amr".into(), opts.amr.clone());
        }
        if !s(Some(&opts.acr)).is_empty() {
            p.insert("acr".into(), opts.acr.clone());
        }
        if !opts.session_id.is_empty() {
            p.insert("sid".into(), json!(opts.session_id));
        }
        p.insert(
            "grant_at".into(),
            json!(if opts.grant_at > 0.0 {
                opts.grant_at as i64
            } else {
                self.clock.now_ms()
            }),
        );
        let grant_type = if opts.origin_grant.is_empty() {
            opts.grant.clone()
        } else {
            opts.origin_grant.clone()
        };
        if !grant_type.is_empty() {
            p.insert("grant_type".into(), json!(grant_type));
        }
        if !opts.kb_jkt.is_empty() {
            p.insert("kb_jkt".into(), json!(opts.kb_jkt));
        }
        p.insert(crate::grants::FAMILY_CLAIM.into(), json!(family));
        let signed = self
            .signer
            .sign(&p, "JWT", &self.access_token_alg())
            .map_err(|e| {
                tracing::error!(
                    "{}the refresh token could not be signed: {}",
                    sts_core::log::tag(codes::STS_OAUTH_0184),
                    e
                );
                self.refusal(codes::STS_OAUTH_0184, 500, "server_error", &e)
            })?;
        let (alg, enc) = crate::refresh_crypto::configured(
            self.settings
                .value_of("oauth2.refreshTokenEncryptionAlg")
                .as_str(),
            self.settings
                .value_of("oauth2.refreshTokenEncryptionEnc")
                .as_str(),
        );
        let sealed = crate::refresh_crypto::seal(
            &signed,
            &self.signer.refresh_keys(),
            &alg,
            &enc,
        )
        .map_err(|r| self.refusal(r.code, 500, "server_error", &r.message))?;
        let payload = Json::Object(p);
        self.register.record_jwt(
            &sts_core::realm::current_id(),
            &payload,
            &signed,
            under,
            self.clock.now_ms(),
        );
        let rotation = crate::sender_constraints::rotation_required(
            &self.settings,
            self.bcp_mode().enabled,
        );
        let access_jti = s(access.get("jti"));
        let access_exp = js::to_number(&access["exp"]);
        let exp_s = (exp as f64).max(access_exp);
        let now = self.clock.now_ms() as f64;
        self.grants.note_refresh_issued(
            rotation,
            jti,
            &opts.parent_refresh_jti,
            &opts.client_id,
            &opts.parent_refresh_family,
            &access_jti,
            exp_s,
            now,
        );
        self.grants.note_grant_tokens(
            rotation,
            family,
            jti,
            &access_jti,
            &opts.client_id,
            exp_s,
            now,
        );
        Ok(sealed)
    }

    /// `refreshExpiry(clientId, iat, chainIat)`: the client's
    /// `oauth2.refreshTokenTtlS`, or the setting's.
    fn refresh_expiry(&self, client_id: &str, iat: i64, chain_iat: i64) -> i64 {
        let ttl = self
            .clients
            .setting_for(client_id, "oauth2.refreshTokenTtlS")
            .map(|v| js::to_number(&v) as i64)
            .unwrap_or_else(|| {
                self.settings.value_of("oauth2.refreshTokenTtlS").as_int()
            });
        let own = iat + ttl;
        let limit = crate::grants::setting_number(
            &self.settings,
            "oauth2.refreshTokenMaxChainS",
        );
        if limit > 0.0 {
            own.min(chain_iat + limit as i64)
        } else {
            own
        }
    }

    /// `accessTokenUnsigned()` and the signature.
    fn access_token(
        &self,
        base: &str,
        opts: &Mint,
        scope: &str,
        audiences: &[String],
        under: &IssuedUnder,
    ) -> Result<(String, Json), Answer> {
        let iat = self.clock.now_s();
        let jti = sts_crypto::b64::encode(
            &sts_crypto::random::random_bytes(16).unwrap_or_default(),
        );
        let ttl = self
            .clients
            .setting_for(&opts.client_id, "oauth2.accessTokenTtlS")
            .map(|v| js::to_number(&v) as i64)
            .unwrap_or_else(|| {
                self.settings.value_of("oauth2.accessTokenTtlS").as_int()
            });
        let (idx, uri) = self.status.allocate(&jti, base, (iat + ttl) * 1000);
        let aud = match audiences.len() {
            0 => json!(
                crate::jwt_access_token::JwtAccessTokens::default_audience_for(
                    base
                )
            ),
            1 => json!(audiences[0]),
            _ => json!(audiences),
        };
        let mut payload = Map::new();
        payload.insert(
            "iss".into(),
            json!(crate::jwt_access_token::JwtAccessTokens::new(
                self.settings.clone()
            )
            .issuer_for(base)),
        );
        payload.insert("sub".into(), json!(opts.sub));
        payload.insert("aud".into(), aud);
        payload.insert("client_id".into(), json!(opts.client_id));
        payload.insert("typ".into(), json!("Bearer"));
        payload.insert("jti".into(), json!(jti));
        payload.insert("iat".into(), json!(iat));
        payload.insert("nbf".into(), json!(iat));
        payload.insert("exp".into(), json!(iat + ttl));
        payload.insert(
            "status".into(),
            json!({ "status_list": { "idx": idx, "uri": uri } }),
        );
        if opts.grant != "client_credentials" {
            payload.insert("username".into(), json!(opts.username));
        }
        if !scope.is_empty() {
            payload.insert("scope".into(), json!(scope));
        }
        if opts.auth_time > 0.0 {
            payload.insert("auth_time".into(), json!(opts.auth_time as i64));
            if !opts.amr.is_null() {
                payload.insert("amr".into(), opts.amr.clone());
            }
            if !opts.acr.is_null() && !s(Some(&opts.acr)).is_empty() {
                payload.insert("acr".into(), opts.acr.clone());
            }
        }
        if !opts.jkt.is_empty() {
            payload.insert("cnf".into(), json!({ "jkt": opts.jkt }));
        }
        let signed = self
            .signer
            .sign(
                &payload,
                crate::jwt_access_token::TYP,
                &self.access_token_alg(),
            )
            .map_err(|e| {
                tracing::error!(
                    "{}the access token could not be signed: {}",
                    sts_core::log::tag(codes::STS_OAUTH_0184),
                    e
                );
                self.refusal(codes::STS_OAUTH_0184, 500, "server_error", &e)
            })?;
        let payload = Json::Object(payload);
        self.register.record_jwt(
            &sts_core::realm::current_id(),
            &payload,
            &signed,
            under,
            self.clock.now_ms(),
        );
        Ok((signed, payload))
    }
}

/// `spendPresentedCode()`'s answer.
struct Spent {
    code: String,
    record: Option<Json>,
    claim: Option<
        Result<
            sts_cluster::scheduler::Claim,
            sts_cluster::scheduler::ClaimRefused,
        >,
    >,
}

fn ttl_of(record: &Json) -> f64 {
    let t = js::to_number(record.get("ttlMs").unwrap_or(&Json::Null));
    if t.is_finite() && t > 0.0 {
        t
    } else {
        crate::grants::AUTH_CODE_TTL_MS
    }
}

fn values_of(v: Option<&Json>) -> Vec<String> {
    match v {
        None | Some(Json::Null) => Vec::new(),
        Some(Json::Array(list)) => list.iter().map(|x| s(Some(x))).collect(),
        Some(one) => vec![s(Some(one))],
    }
}

/// When this process started, for the unknown-code sentence's uptime.
fn started_at_ms() -> i64 {
    static STARTED: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
    *STARTED.get_or_init(|| chrono::Utc::now().timestamp_millis())
}

/// `oauth2.dpopIatSkewS`, for the reservation's lifetime.
fn sts_oauth_dpop_skew(stores: &crate::dpop_stores::DpopStores) -> i64 {
    crate::dpop::ProofContext::iat_skew_seconds(stores)
}

struct Issuing<'a> {
    ask: &'a TokenAsk,
    client: &'a ClientPresented,
    body: &'a Map<String, Json>,
    grant: String,
    observed_authenticated: bool,
    observed_method: String,
    dpop_jkt: String,
    #[allow(dead_code)]
    dpop_jwk: Json,
    flows: Option<Json>,
    resources: Vec<String>,
}

/// What `issue()` hands `tokenSet()`.
#[derive(Debug, Clone, Default)]
struct Mint {
    sub: String,
    username: String,
    user: Json,
    client_id: String,
    scope: String,
    grant_scope: Option<String>,
    audience: Vec<String>,
    resources: Vec<String>,
    grant_resources: Option<Vec<String>>,
    grant: String,
    origin_grant: String,
    jkt: String,
    kb_jkt: String,
    session_id: String,
    session_authenticated: bool,
    nonce: String,
    auth_time: f64,
    amr: Json,
    acr: Json,
    grant_at: f64,
    chain_iat: f64,
    parent_refresh_jti: String,
    parent_refresh_family: String,
    with_refresh: bool,
    client_authenticated: bool,
}

/// A [`Signer`] over a realm's key set: Node's header order, `alg`, `typ`,
/// `kid`.
pub struct KeySetSigner {
    pub set: Arc<sts_store::key_sets::KeySet>,
}

impl Signer for KeySetSigner {
    fn sign(
        &self,
        payload: &Map<String, Json>,
        typ: &str,
        alg: &str,
    ) -> Result<String, String> {
        let (key, kid) = self.set.signer_for(alg, "")?;
        let header = json!({ "alg": alg, "typ": typ, "kid": kid });
        let input = format!(
            "{}.{}",
            sts_crypto::b64::encode(header.to_string().as_bytes()),
            sts_crypto::b64::encode(
                Json::Object(payload.clone()).to_string().as_bytes()
            )
        );
        let signature =
            sts_crypto::jws::sign_input(alg, &key, input.as_bytes())
                .map_err(|e| e.to_string())?;
        Ok(format!("{}.{}", input, sts_crypto::b64::encode(&signature)))
    }

    fn refresh_keys(&self) -> Json {
        self.set.blob["refreshTokenEncKeys"].clone()
    }

    fn verify_own(&self, token: &str, now_s: i64) -> Result<Json, String> {
        let checks = sts_crypto::jws::ClaimChecks {
            now: Some(now_s),
            ..Default::default()
        };
        self.set
            .verify_own_jws(
                token,
                None,
                &checks,
                sts_crypto::keys::KeyPolicy::STRICT,
                "",
                (now_s * 1000) as f64,
            )
            .map_err(|e| e.to_string())
    }
}
