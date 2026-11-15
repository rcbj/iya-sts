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
}

/// The OIDC slice's ID Token (`idToken()`), not minted here.
pub trait IdTokens: Send + Sync {
    fn id_token(&self, base: &str, issuing: &Json) -> Option<String>;
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
    /// The scopes OID4VCI's configurations declare (`credentialScopes()`).
    pub credential_scopes: Vec<String>,
    /// `scopePolicy.protectedScopes()`.
    pub protected_scopes: Vec<String>,
}

fn s(v: Option<&Json>) -> String {
    crate::js::string_of(v)
}

fn quoted(list: &[String]) -> String {
    list.iter()
        .map(|one| format!("\"{}\"", one))
        .collect::<Vec<_>>()
        .join(", ")
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

    /// `scopePolicy.refusal()` under the default issuance policy (rule
    /// 3bt): a protected scope only to a client that declares it, in every
    /// mode; in product mode, a scope the client did not declare, or — for
    /// a client that declares none — one outside the default set.
    fn scope_refusal(
        &self,
        scope: &str,
        client_id: &str,
    ) -> Option<(sts_core::errors::ErrorCode, String)> {
        let asked: Vec<String> =
            scope.split_whitespace().map(str::to_string).collect();
        if asked.is_empty() {
            return None;
        }
        let declared: Option<Vec<String>> = None;
        let mut defaults: Vec<String> =
            OIDC_SCOPES.iter().map(|s| s.to_string()).collect();
        if matches!(
            self.settings.value_of("oauth2.keyBinding"),
            sts_core::settings::SettingValue::Bool(false)
        ) {
            defaults.retain(|d| d != "bound_key");
        }
        for one in &self.credential_scopes {
            if !defaults.contains(one) {
                defaults.push(one.clone());
            }
        }
        let client = if client_id.trim().is_empty() {
            "a client that named no client_id".to_string()
        } else {
            format!("the client \"{}\"", client_id.trim())
        };
        let protected: Vec<String> = asked
            .iter()
            .filter(|one| self.protected_scopes.contains(one))
            .cloned()
            .collect();
        let where_ = " A client's declared scopes are `oauthAllowedScope` on its entry in ou=applications — the application's page under /admin/applications, or POST /admin-api/applications/add.";
        if !protected.is_empty() {
            let one = protected.len() == 1;
            return Some((
                codes::STS_OAUTH_0577,
                format!(
                    "{}{} this service's own {}, issued in every mode only to a client that declares {}, and {} does not.{} An admin, owner, account or report scope is declared instead by a delegated permission grant on that API's object — urn:sts:admin-api:, urn:sts:account-api: or urn:sts:report-api: followed by the scope (POST /admin-api/permissions/grant-permission, #1141). A dynamic registration cannot declare one; an administrator does.",
                    quoted(&protected),
                    if one { " is" } else { " are" },
                    if one { "scope" } else { "scopes" },
                    if one { "it" } else { "them" },
                    client,
                    where_
                ),
            ));
        }
        if self.mode.current() != "product" {
            return None;
        }
        let undeclared: Vec<String> = asked
            .iter()
            .filter(|one| !defaults.contains(one))
            .cloned()
            .collect();
        if undeclared.is_empty() {
            return None;
        }
        Some((
            codes::STS_OAUTH_0578,
            format!(
                "{} has not declared {}, and in product mode a client is issued only the scopes it declared (RFC 7591 section 2) — {}{}",
                client,
                quoted(&undeclared),
                match &declared {
                    Some(list) => format!("its list is {}.", quoted(list)),
                    None => format!("it declares none, so it may have the default set: {}.", quoted(&defaults)),
                },
                where_
            ),
        ))
    }

    /// The access token's plan (`accessTokenPlan()`): with no application
    /// declaring a scope here yet, every scope is an OpenID Connect or an
    /// ordinary one.
    fn plan(
        &self,
        base: &str,
        scope: &str,
        explicit: &[String],
    ) -> crate::jwt_access_token::AudiencePlan {
        let mut seen: Vec<String> = Vec::new();
        let mut scopes = Vec::new();
        for one in scope.split_whitespace() {
            if seen.iter().any(|s| s == one) {
                continue;
            }
            seen.push(one.to_string());
            scopes.push(if OIDC_SCOPES.contains(&one) {
                PlannedScope::Oidc(one.to_string())
            } else {
                PlannedScope::Ordinary(one.to_string())
            });
        }
        audience_plan(
            &crate::jwt_access_token::JwtAccessTokens::default_audience_for(
                base,
            ),
            explicit,
            &scopes,
            &DetailAudience::default(),
        )
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
    pub fn answer(&self, ask: &TokenAsk) -> Answer {
        let pairs = crate::js::form_decode(&ask.body);
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
        let resources: Vec<String> = match body.get("resource") {
            Some(Json::String(r)) if !r.is_empty() => vec![r.clone()],
            _ => Vec::new(),
        };
        if !scope.is_empty() {
            if let Some((code, description)) =
                self.scope_refusal(&scope, &client.client_id)
            {
                return self.refusal(code, 400, "invalid_scope", &description);
            }
        }
        if !scope.is_empty() || !resources.is_empty() {
            let plan = self.plan(&ask.base, &scope, &resources);
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
            observed_authenticated: observed.authenticated,
        };
        match grant.as_str() {
            "client_credentials" => {
                self.client_credentials(&issuing, &scope, &resources)
            }
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
        let audience: Vec<String> = if !resources.is_empty() {
            resources.to_vec()
        } else {
            let asked: Vec<&str> = scope.split_whitespace().collect();
            if asked
                .iter()
                .any(|one| self.protected_scopes.iter().any(|p| p == one))
                || issuing.client.client_id.is_empty()
            {
                Vec::new()
            } else {
                vec![issuing.client.client_id.clone()]
            }
        };
        let opts = Mint {
            sub: subject,
            username: String::new(),
            client_id: issuing.client.client_id.clone(),
            scope: scope.to_string(),
            audience,
            grant: "client_credentials".into(),
            jkt: issuing.ask.dpop_jkt.clone(),
            session_id: String::new(),
            auth: None,
        };
        self.respond(self.token_set(&issuing.ask.base, &opts, false))
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

    /// `tokenSet()`: the access token, and the response around it.
    fn token_set(
        &self,
        base: &str,
        opts: &Mint,
        with_refresh: bool,
    ) -> Result<Json, Answer> {
        let plan = self.plan(base, &opts.scope, &opts.audience);
        if let Some(r) = plan.refusal {
            return Err(self.refusal(r.code, 400, r.error, &r.description));
        }
        let (access, payload) =
            self.access_token(base, opts, &plan.scope, &plan.audiences)?;
        let expires = crate::js::to_number(&payload["exp"]) as i64
            - crate::js::to_number(&payload["iat"]) as i64;
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
        let _ = with_refresh;
        Ok(Json::Object(body))
    }

    /// `accessTokenUnsigned()` and the signature.
    fn access_token(
        &self,
        base: &str,
        opts: &Mint,
        scope: &str,
        audiences: &[String],
    ) -> Result<(String, Json), Answer> {
        let iat = self.clock.now_s();
        let jti = sts_crypto::b64::encode(
            &sts_crypto::random::random_bytes(16).unwrap_or_default(),
        );
        let ttl = self.settings.value_of("oauth2.accessTokenTtlS").as_int();
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
        if let Some(auth) = &opts.auth {
            for k in ["auth_time", "amr", "acr"] {
                if let Some(v) = auth.get(k).filter(|v| !v.is_null()) {
                    payload.insert(k.into(), v.clone());
                }
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
            &IssuedUnder {
                grant: opts.grant.clone(),
                session_id: opts.session_id.clone(),
                session_authenticated: true,
                ..IssuedUnder::default()
            },
            self.clock.now_ms(),
        );
        Ok((signed, payload))
    }
}

struct Issuing<'a> {
    ask: &'a TokenAsk,
    client: &'a ClientPresented,
    #[allow(dead_code)]
    observed_authenticated: bool,
}

/// What `issue()` hands `tokenSet()`.
struct Mint {
    sub: String,
    username: String,
    client_id: String,
    scope: String,
    audience: Vec<String>,
    grant: String,
    jkt: String,
    session_id: String,
    auth: Option<Json>,
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
}
