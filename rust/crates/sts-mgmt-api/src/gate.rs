// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `/admin-api`'s gate (`registerGate()`), whole, in Node's order and with
//! Node's codes and sentences.
//!
//! * **The scope the operation needs** is read off it: `device:compliance`
//!   for the MDM feed, `admin:console` for the console's own operations
//!   (#454), `admin:security` for a security change (#645), `admin:read`
//!   for a GET and `admin:write` for anything else.
//! * **The SERVICE credential is verified against the DEFAULT realm's key**,
//!   wherever the API is reached; **a realm's OWN token** (#32) is tried
//!   only under that realm's prefix, against that realm's key, with that
//!   realm's issuer and audience, and is confined by the realm
//!   administrator's rules (STS-API-0112).
//! * **RFC 9068 section 4's order**, then the sender constraints (RFC 8705,
//!   RFC 9449, #34, #446's public console, #1050's declared certificate).
//! * **Then the decision**: the client must still declare the scope
//!   (STS-API-0123), the subject must still hold a role authorizing it
//!   (0125, held ∩ carried, #303), a security change needs the Security
//!   Administrator (0138), a console operation the console's scope (0127),
//!   and the access-control policy has the last word (0005).
//! * **With `adminApi.authRequired` off** — development only: the value in
//!   force reads `true` in product (#446) — the request goes through with
//!   no caller, and the policy is not asked.
//!
//! The registers the decision reads (applications, roles, the token and
//! session registers, the directory's disabled accounts) and the policy are
//! PORTS ([`GatePorts`], [`AccessPolicy`]): other slices own them, and the
//! runtime fills them. Not ported: opaque access tokens (#501, off by
//! default; a handle answers STS-API-0002 here) and an owner's operations
//! (#607: no operation this crate routes is one an owner may ask, so an
//! owner's token is refused STS-API-0132).

use serde_json::Value as Json;
use sts_core::errors::{codes, ErrorCode};
use sts_core::mode::Mode;
use sts_core::settings::{keys, Settings, Source};
use sts_crypto::jws::ClaimChecks;
use sts_crypto::keys::KeyPolicy;
use sts_oauth::dpop::{verify_proof, ProofContext, ProofRequest};
use sts_oauth::jwt_access_token::JwtAccessTokens;
use sts_oauth::mtls::{
    bound_thumbprint_of, certificate_thumbprint, check_binding,
};
use sts_oauth::sender_constraints::{
    access_token_dpop_required, access_token_refusal_with, Presented,
};
use sts_store::key_sets::KeySet;
use sts_xacml::access::{Answer, Question};

/// The API's path.
pub const BASE: &str = "/admin-api";

/// The default realm's id.
pub const DEFAULT_REALM: &str = "default";

/// What arrived.
#[derive(Clone, Copy, Debug, Default)]
pub struct Arrived<'a> {
    pub method: &'a str,
    /// The path under the API, `/config/set` (Express's `req.path` under
    /// `app.use(BASE)`).
    pub path: &'a str,
    /// What `req.originalUrl` names, for the sentences that quote it.
    pub original_url: &'a str,
    pub authorization: Option<&'a str>,
    pub dpop: Option<&'a str>,
    /// The URI a DPoP proof must name (`htuOf()`).
    pub htu: &'a str,
    /// The request's base URL as the DEFAULT realm sees it (`baseUrlOf()`).
    pub base: &'a str,
    /// The request's base URL as the AMBIENT realm sees it, its prefix
    /// included.
    pub realm_base: &'a str,
    /// The ambient realm.
    pub realm: &'a str,
    /// The body, parsed, for the security and realm confinement rules.
    pub body: Option<&'a Json>,
    /// The connection's client certificate, DER.
    pub certificate: Option<&'a [u8]>,
    pub certificate_verified: bool,
    pub mtls_available: bool,
    pub now: i64,
}

/// The console operation a request mirrors (`consoleOperationOf()`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsoleOperation {
    pub path: String,
    pub action: String,
}

/// What the subject of a token holds now (`effectiveRoles()`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Effective {
    pub roles: Vec<String>,
    pub withdrawn: Vec<String>,
    pub why: String,
    /// `application` or `user`.
    pub subject_kind: String,
    pub subject_name: String,
}

/// The registers the gate reads, each in the realm that issued the token.
pub trait GatePorts: Send + Sync {
    /// The revoked-token register.
    fn revoked(&self, realm: &str, jti: &str) -> bool;
    /// Whether a person's account is disabled.
    fn disabled(&self, realm: &str, sub: &str) -> bool;
    /// Whether the sign-on session the token was issued on has ENDED
    /// (#446): false for no session, or one the register forgot.
    fn session_ended(&self, realm: &str, jti: &str) -> bool;
    /// A client's `token_endpoint_auth_method`.
    fn client_method(&self, realm: &str, client: &str) -> String;
    /// `mtls.certificateDeclaration()` of a client's entry (#1050): what
    /// it declares that holds its tokens to a certificate, or empty.
    fn certificate_declaration(&self, realm: &str, client: &str) -> String;
    /// `scopePolicy.declares()`: whether the client still declares it.
    fn declares(&self, realm: &str, client: &str, scope: &str) -> bool;
    /// `rolePermissions.effectiveRoles()`.
    fn effective_roles(
        &self,
        realm: &str,
        claims: &Json,
        scopes: &[String],
    ) -> Effective;
    /// `SecurityOperations.classify()`'s detail for a write, or `None`. The
    /// configuration page's rule is the gate's own ([`setting_change`]);
    /// this answers the pages whose rules read the directory.
    fn security_change(
        &self,
        realm: &str,
        operation: &ConsoleOperation,
        body: &Json,
    ) -> Option<String>;
    /// `admin_scope.refusalFor()` for a realm administrator: why a realm's
    /// own token may not do this, or `None`.
    fn realm_refusal(
        &self,
        realm: &str,
        operation: &ConsoleOperation,
        body: Option<&Json>,
    ) -> Option<String>;
}

/// The access-control policy (`accessGate.check()`).
pub trait AccessPolicy: Send + Sync {
    fn check(
        &self,
        question: &Question,
        held: &[String],
        required: &[String],
    ) -> Answer;
}

/// The built-in `access-control` document with its default parameters,
/// for a process whose policy register is not wired yet, and for tests.
pub struct BuiltInAccess {
    policy: Option<sts_xacml::policy::PolicyNode>,
}

impl BuiltInAccess {
    /// The built-in policy.
    #[tracing::instrument(level = "debug")]
    pub fn new() -> BuiltInAccess {
        let params =
            sts_xacml::access::Parameters::from_answers(&Default::default());
        BuiltInAccess {
            policy: sts_xacml::access::built_in("access-control", &params).ok(),
        }
    }
}

impl Default for BuiltInAccess {
    fn default() -> Self {
        BuiltInAccess::new()
    }
}

impl AccessPolicy for BuiltInAccess {
    fn check(
        &self,
        question: &Question,
        held: &[String],
        required: &[String],
    ) -> Answer {
        // The embedded PEP's `rolesOf()` for the subject first — the gate
        // names no kind, so the built-ins of an authenticated user — then
        // the roles the caller established, unioned in
        // (`xacml_access_pep.ts`). The register's configured roles of that
        // name are the policy register's, which a later slice wires.
        let mut all: Vec<String> = vec!["EVERYBODY".into()];
        if question.authenticated {
            all.push("ALL_AUTHENTICATED_USERS".into());
        }
        for one in held {
            if !all.contains(one) {
                all.push(one.clone());
            }
        }
        match &self.policy {
            Some(policy) => {
                sts_xacml::access::decide(policy, question, &all, required)
            }
            None => Answer {
                allowed: false,
                decision: sts_xacml::model::Decision::Indeterminate,
                refused: Some(sts_xacml::access::Refused::Indeterminate),
                why: "the access policy could not be loaded.".into(),
            },
        }
    }
}

/// What the gate reads besides the request.
pub struct Gate<'a> {
    pub settings: &'a Settings,
    pub mode: &'a Mode,
    /// The default realm's key set.
    pub keys: &'a KeySet,
    /// The ambient realm's key set, under a realm's prefix.
    pub realm_keys: Option<&'a KeySet>,
    pub tokens: &'a JwtAccessTokens,
    pub ports: &'a dyn GatePorts,
    pub access: &'a dyn AccessPolicy,
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

/// Who the gate let in (`res.locals.apiCaller`, #446): the audit actor.
#[derive(Clone, Debug, PartialEq)]
pub struct Caller {
    /// `person` or `application`.
    pub kind: String,
    pub name: String,
    pub sub: String,
    pub auth_time: i64,
    pub client_id: String,
    /// The realm that issued the token.
    pub realm: String,
    pub scopes: Vec<String>,
    pub roles: Vec<String>,
    pub expires_at: Option<i64>,
    pub owner: bool,
    /// The one object an owner's token reaches (`ownedOperationOf()`),
    /// whose answer is projected for it.
    pub owned: Option<OwnedOperation>,
    pub claims: Json,
}

/// `ownedOperationOf(req)`'s answer: the object an owner's request would
/// administer.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct OwnedOperation {
    /// `role`, `group`, `service-account` or `application`.
    pub kind: String,
    pub id: String,
    /// `read`, or the action the path names.
    pub action: String,
    /// What an application action would write, by name.
    pub attributes: Vec<String>,
    /// The projection a read's answer is given (`role`, `group`,
    /// `application`, `uma`), or '' for none.
    pub project: String,
}

/// `OWNER_APPLICATION_FIELDS`: the fields an owner's read of an
/// application is shown.
pub const OWNER_APPLICATION_FIELDS: &[&str] = &[
    "appName",
    "appHomePageUrl",
    "appCorsOrigin",
    "oauthRedirectUri",
    "oauthPostLogoutRedirectUri",
    "oauthFrontchannelLogoutUri",
    "oauthBackchannelLogoutUri",
    "samlAssertionConsumerService",
    "samlSingleLogoutService",
    "oauthAllowedTokenResponseTypes",
];

// `/^\/<prefix>\/(<action>)$/` with `<action>` `[a-z][a-z-]*`, or the
// `owner-` actions of `/uma`.
fn action_under(path: &str, prefix: &str, owner_only: bool) -> Option<String> {
    let rest = path.strip_prefix(prefix)?.strip_prefix('/')?;
    let shaped = rest.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        && rest.chars().all(|c| c.is_ascii_lowercase() || c == '-');
    if !shaped || (owner_only && !rest.starts_with("owner-")) {
        return None;
    }
    Some(rest.to_string())
}

/// `ownedOperationOf(req)` (`OWNER_OPERATIONS`): the object an owner's
/// request names, or `None` for an operation no owner may ask or one that
/// names nothing. `path` is under the API.
#[tracing::instrument(level = "debug", skip(query, body))]
pub fn owned_operation_of(
    method: &str,
    path: &str,
    query: &crate::request::Query,
    body: &Json,
) -> Option<OwnedOperation> {
    let path = path.trim_end_matches('/');
    let q = |k: &str| match query.get(k) {
        Some(Json::String(s)) => s.clone(),
        Some(Json::Array(a)) => a
            .iter()
            .filter_map(Json::as_str)
            .collect::<Vec<_>>()
            .join(","),
        Some(Json::Null) | None => String::new(),
        Some(other) => other.to_string(),
    };
    let b = |k: &str| match body.get(k) {
        Some(Json::String(s)) => s.clone(),
        Some(Json::Null) | None => String::new(),
        Some(other) => other.to_string(),
    };
    let (kind, action, id, project) = match method {
        "GET" => match path {
            "/roles" => ("role", "read".to_string(), q("role"), "role"),
            "/groups" => ("group", "read".to_string(), q("group"), "group"),
            "/applications" => (
                "application",
                "read".to_string(),
                q("application"),
                "application",
            ),
            "/service-accounts" => {
                ("service-account", "read".to_string(), q("account"), "")
            }
            "/uma" => ("application", "read".to_string(), q("owner"), "uma"),
            _ => return None,
        },
        "POST" => {
            if let Some(a) = action_under(path, "/roles", false) {
                ("role", a, b("role"), "")
            } else if let Some(a) = action_under(path, "/groups", false) {
                ("group", a, b("group"), "")
            } else if let Some(a) = action_under(path, "/applications", false) {
                ("application", a, b("application"), "")
            } else if let Some(a) = action_under(path, "/uma", true) {
                ("application", a, b("owner"), "")
            } else {
                let a = action_under(path, "/users", false)?;
                let user = b("user");
                (
                    "service-account",
                    a,
                    if user.is_empty() { b("username") } else { user },
                    "",
                )
            }
        }
        _ => return None,
    };
    let id = id.trim().to_string();
    if id.is_empty() {
        return None;
    }
    let mut attributes: Vec<String> = Vec::new();
    if kind == "application" {
        if ["set", "add", "remove"].contains(&action.as_str()) {
            let one = b("attribute");
            if !one.is_empty() {
                attributes.push(one);
            }
        } else if action == "update-fields" {
            attributes =
                sts_registers::applications::actions::fields_covered_by(body);
            let named = body.get("protocolsPresent").is_some_and(|v| {
                !matches!(v, Json::Null | Json::Bool(false))
                    && v.as_str() != Some("")
            }) || body.get("protocols").is_some()
                || body.get("protocol").is_some();
            if named && !attributes.iter().any(|a| a == "appAllowedProtocol") {
                attributes.push("appAllowedProtocol".into());
            }
        }
    }
    Some(OwnedOperation {
        kind: kind.into(),
        id,
        action,
        attributes,
        project: project.into(),
    })
}

/// `row.project(answer)`: what an owner's read is shown of the answer.
#[tracing::instrument(level = "debug", skip(answer))]
pub fn owner_projection(project: &str, answer: &Json) -> Option<Json> {
    match project {
        "role" => Some(serde_json::json!({ "role": answer.get("role") })),
        "group" => {
            let g = answer.get("group").filter(|g| !g.is_null());
            Some(serde_json::json!({
                "found": answer.get("found").is_some_and(|f| f == &Json::Bool(true)),
                "group": g.map(|g| serde_json::json!({
                    "dn": g.get("dn"), "cn": g.get("cn"),
                    "description": g.get("description"),
                    "members": g.get("members"),
                    "memberCount": g.get("memberCount"),
                    "owners": g.get("owners"), "maxOwners": g.get("maxOwners"),
                })),
                "membersPaging": answer.get("membersPaging"),
            }))
        }
        "application" => {
            let mut fields = serde_json::Map::new();
            for name in OWNER_APPLICATION_FIELDS {
                if let Some(v) = answer.get("fields").and_then(|f| f.get(*name))
                {
                    fields.insert((*name).into(), v.clone());
                }
            }
            let page = answer.get("page");
            Some(serde_json::json!({
                "found": answer.get("found").is_some_and(|f| f == &Json::Bool(true)),
                "identifier": answer.get("identifier"),
                "name": answer.get("name"),
                "description": answer.get("description"),
                "kinds": answer.get("kinds"),
                "protocols": answer.get("protocols"),
                "fields": fields,
                "owners": page.and_then(|p| p.get("owners")).cloned()
                    .unwrap_or_else(|| serde_json::json!([])),
                "maxOwners": page.and_then(|p| p.get("maxOwners")),
            }))
        }
        "uma" => Some(serde_json::json!({
            "owner": answer.get("owner").filter(|o| !o.is_null())
        })),
        _ => None,
    }
}

/// What the gate decided.
#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    /// `adminApi.authRequired` is off (development only): no caller.
    Open,
    Admitted(Box<Caller>),
    Refused(Box<Refused>),
}

/// `presentedTokenOf()`: `/^(Bearer|DPoP)\s+(\S+)\s*$/i`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn presented_token_of(authorization: Option<&str>) -> (String, String) {
    let said = authorization.unwrap_or("");
    let lower = said.to_ascii_lowercase();
    let scheme = if lower.starts_with("bearer") {
        "bearer"
    } else if lower.starts_with("dpop") {
        "dpop"
    } else {
        return (String::new(), String::new());
    };
    let rest = &said[scheme.len()..];
    if !rest.starts_with(char::is_whitespace) {
        return (String::new(), String::new());
    }
    let token = rest.trim();
    if token.is_empty() || token.contains(char::is_whitespace) {
        return (String::new(), String::new());
    }
    (token.to_string(), scheme.to_string())
}

/// `wantedAudiences()`: a pinned `adminApi.audience` alone; otherwise the
/// process's address of the API, and the request's.
#[tracing::instrument(level = "debug", skip(settings))]
pub fn wanted_audiences(settings: &Settings, base: &str) -> Vec<String> {
    let pinned = settings
        .value(keys::ADMIN_API_AUDIENCE)
        .as_str()
        .trim()
        .to_string();
    if !pinned.is_empty()
        && settings.source_of(keys::ADMIN_API_AUDIENCE) != Source::Default
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

/// `consoleOperationOf()`: the `/admin` path and the action a request
/// under the API mirrors.
#[tracing::instrument(level = "debug")]
pub fn console_operation_of(path: &str) -> ConsoleOperation {
    let stripped = if path == "/console" {
        ""
    } else {
        path.strip_prefix("/console")
            .filter(|r| r.starts_with('/'))
            .unwrap_or(path)
    };
    let full = format!("{}{}", BASE, stripped);
    let mut resource = full.clone();
    let mut action = String::new();
    for route in &crate::tables::tables().routes {
        let Some(prefix) = route.route.strip_suffix(":action") else {
            continue;
        };
        if let Some(rest) = full.strip_prefix(prefix) {
            if !rest.is_empty() && !rest.contains('/') {
                action = rest.to_string();
                resource = prefix.trim_end_matches('/').to_string();
                break;
            }
        }
    }
    ConsoleOperation {
        path: format!("/admin{}", resource.get(BASE.len()..).unwrap_or("")),
        action,
    }
}

/// `SecurityOperations.settingChange()`: a write naming
/// `admin.securityGroup` grants the role.
#[tracing::instrument(level = "debug", skip_all)]
pub fn setting_change(body: &Json) -> Option<String> {
    const KEY: &str = "admin.securityGroup";
    let named = body.as_object().is_some_and(|b| b.contains_key(KEY))
        || body.get("key").and_then(Json::as_str).map(str::trim) == Some(KEY);
    named.then(|| format!("{} names the Security Administrator's group, so changing it grants the role", KEY))
}

fn invalid(code: ErrorCode, scope: &str, message: String) -> Box<Refused> {
    Box::new(Refused {
        status: 401,
        error: "invalid_token",
        code,
        www_authenticate: Some(format!(
            "Bearer error=\"invalid_token\", scope=\"{}\"",
            scope
        )),
        nonce_wanted: false,
        message,
    })
}

fn forbidden(code: ErrorCode, message: String) -> Box<Refused> {
    Box::new(Refused {
        status: 403,
        error: "forbidden",
        code,
        www_authenticate: None,
        nonce_wanted: false,
        message,
    })
}

fn iso_of(seconds: f64) -> String {
    chrono::DateTime::from_timestamp_millis((seconds * 1000.0) as i64)
        .map(sts_core::time::iso)
        .unwrap_or_else(|| seconds.to_string())
}

/// `JSON.stringify(x || null)`.
fn json_or_null(v: Option<&Json>) -> String {
    let falsy = match v {
        None | Some(Json::Null) => true,
        Some(Json::String(s)) => s.is_empty(),
        Some(Json::Bool(b)) => !b,
        Some(Json::Number(n)) => n.as_f64() == Some(0.0),
        _ => false,
    };
    if falsy {
        return "null".into();
    }
    serde_json::to_string(v.unwrap_or(&Json::Null)).unwrap_or_default()
}

/// `String(x || '')`.
fn text_or_empty(v: Option<&Json>) -> String {
    match v {
        None | Some(Json::Null) => String::new(),
        Some(Json::String(s)) => s.clone(),
        Some(Json::Bool(false)) => String::new(),
        Some(Json::Number(n)) if n.as_f64() == Some(0.0) => String::new(),
        Some(other) => other.to_string(),
    }
}

const ADMIN_SCOPES: &[&str] = &[
    "admin:read",
    "admin:write",
    "admin:security",
    "admin:console",
    "device:compliance",
    "owner:read",
    "owner:write",
];

impl Gate<'_> {
    /// `tokenRequired()`: `adminApi.authRequired` as the mode lets it be.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn token_required(&self) -> bool {
        self.mode.value_in_force("adminApi.authRequired").as_bool()
    }

    fn issuer_accepted(&self, claims: &Json, base: &str) -> bool {
        let iss = text_or_empty(claims.get("iss"));
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
        bases.iter().any(|b| self.tokens.is_hosted_issuer(&iss, b))
    }

    fn verify(&self, keys: &KeySet, token: &str, now: i64) -> Option<Json> {
        // `verifyOwnJws()` checks the clock too, so an expired token is
        // refused here as not verifying (STS-API-0002), as in Node; the
        // gate's own expiry check (0003) stands behind it.
        let checks = ClaimChecks {
            now: Some(now),
            ..Default::default()
        };
        keys.verify_own_jws(
            token,
            None,
            &checks,
            KeyPolicy::STRICT,
            self.eddsa_curve,
            now as f64 * 1000.0,
        )
        .ok()
    }

    /// The whole gate.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn check(&self, arrived: &Arrived) -> Outcome {
        if !self.token_required() {
            return Outcome::Open;
        }
        match self.decide(arrived) {
            Ok(caller) => Outcome::Admitted(Box::new(caller)),
            Err(refused) => Outcome::Refused(refused),
        }
    }

    fn decide(&self, arrived: &Arrived) -> Result<Caller, Box<Refused>> {
        let path = arrived.path.trim_end_matches('/');
        let mdm_feed = arrived.method == "POST" && path == "/device-compliance";
        let console_op = path == "/console" || path.starts_with("/console/");
        let operation = console_operation_of(arrived.path);
        let read = arrived.method == "GET" || arrived.method == "HEAD";
        let security_change = if mdm_feed || console_op || read {
            None
        } else if operation.path == "/admin/config" {
            setting_change(arrived.body.unwrap_or(&Json::Null))
        } else {
            self.ports.security_change(
                arrived.realm,
                &operation,
                arrived.body.unwrap_or(&Json::Null),
            )
        };
        let scope = if mdm_feed {
            "device:compliance"
        } else if console_op {
            "admin:console"
        } else if security_change.is_some() {
            "admin:security"
        } else if arrived.method == "GET" {
            "admin:read"
        } else {
            "admin:write"
        };
        let (token, scheme) = presented_token_of(arrived.authorization);
        if token.is_empty() {
            let hint = if mdm_feed || console_op || security_change.is_some() {
                scope
            } else {
                "admin:read admin:write"
            };
            return Err(Box::new(Refused {
                status: 401,
                error: "unauthorized",
                code: codes::STS_API_0001,
                www_authenticate: Some(format!("Bearer realm=\"{}\", scope=\"{}\"", BASE, hint)),
                nonce_wanted: false,
                message: format!(
                    "This API requires an OAuth 2.0 access token. Ask /oauth2/token for one with \
                     `grant_type=client_credentials`, `scope={}` and `resource={}`, then send it as \
                     `Authorization: Bearer`. adminApi.authRequired turns this off.",
                    hint,
                    wanted_audiences(self.settings, arrived.base).last().cloned().unwrap_or_default()
                ),
            }));
        }
        let mut token_realm = DEFAULT_REALM.to_string();
        let mut claims = self.verify(self.keys, &token, arrived.now);
        if claims.is_none() && arrived.realm != DEFAULT_REALM {
            if let Some(realm_keys) = self.realm_keys {
                claims = self.verify(realm_keys, &token, arrived.now);
                if claims.is_some() {
                    token_realm = arrived.realm.to_string();
                }
            }
        }
        let Some(claims) = claims else {
            return Err(invalid(
                codes::STS_API_0002,
                scope,
                "That access token was not issued by this service, or its signature does not verify. Tokens are \
                 signed with the key at /oauth2/jwks and that key is regenerated on every start in development mode."
                    .into(),
            ));
        };
        if let Some(exp) = claims.get("exp").and_then(Json::as_f64) {
            if exp != 0.0 && exp <= arrived.now as f64 {
                return Err(invalid(
                    codes::STS_API_0003,
                    scope,
                    format!("That access token expired at {}.", iso_of(exp)),
                ));
            }
        }
        let jti = text_or_empty(claims.get("jti"));
        let person = text_or_empty(claims.get("sub"));
        let client = text_or_empty(claims.get("client_id"));
        if (!jti.is_empty() && self.ports.revoked(&token_realm, &jti))
            || (!person.is_empty()
                && person != client
                && self.ports.disabled(&token_realm, &person))
        {
            return Err(invalid(
                codes::STS_API_0122,
                scope,
                "That access token has been revoked, or the account it was issued to is disabled.".into(),
            ));
        }
        if !jti.is_empty() && self.ports.session_ended(&token_realm, &jti) {
            return Err(invalid(
                codes::STS_API_0126,
                scope,
                "That access token was issued on a sign-on session that has since ended, by a sign-out or by \
                 running out. Sign in again to be issued another."
                    .into(),
            ));
        }
        let typ = JwtAccessTokens::typ_of(&token);
        if !JwtAccessTokens::is_access_token_type(&typ) {
            return Err(invalid(
                codes::STS_API_0082,
                scope,
                format!(
                    "RFC 9068 section 4: a JWT access token's typ header must be \"at+jwt\", and this token's is {}. \
                     An ID Token or a refresh token is not an access token, and a token minted before this service \
                     issued at+jwt is refused too; ask /oauth2/token for a new one.",
                    if typ.is_empty() { "absent".to_string() } else { format!("\"{}\"", typ) }
                ),
            ));
        }
        let default_token = token_realm == DEFAULT_REALM;
        let iss_ok = if default_token {
            self.issuer_accepted(&claims, arrived.base)
        } else {
            self.tokens.is_hosted_issuer(
                &text_or_empty(claims.get("iss")),
                arrived.realm_base,
            )
        };
        if !iss_ok {
            return Err(invalid(
                codes::STS_API_0083,
                scope,
                format!(
                    "RFC 9068 section 4: the iss claim must exactly match an issuer this service publishes, and \
                     this token names {}. An issuer is an address, so a token minted under one host name is \
                     refused under another; mint it at the address you call this API at, or set \
                     global.publicBaseUrl.",
                    json_or_null(claims.get("iss"))
                ),
            ));
        }
        let held_aud: Vec<String> = match claims.get("aud") {
            Some(Json::Array(list)) => {
                list.iter().map(|v| text_or_empty(Some(v))).collect()
            }
            Some(Json::Null) | None => Vec::new(),
            Some(other) => vec![text_or_empty(Some(other))],
        };
        let wanted = wanted_audiences(self.settings, arrived.base);
        let aud_ok = if default_token {
            held_aud.iter().any(|a| wanted.contains(a))
        } else {
            held_aud.contains(&format!("{}{}", arrived.realm_base, BASE))
        };
        if !aud_ok {
            return Err(forbidden(
                codes::STS_API_0004,
                format!(
                    "That access token is for a different audience. It carries {} and this API answers to {}. A \
                     bearer token minted for another resource server must not be replayable here, which is what \
                     `aud` is for.",
                    json_or_null(claims.get("aud")),
                    wanted.iter().map(|a| format!("\"{}\"", a)).collect::<Vec<_>>().join(" or ")
                ),
            ));
        }
        if let Some(r) = check_binding(&claims, arrived.certificate, true, None)
        {
            return Err(invalid(codes::STS_API_0110, scope, r.description));
        }
        let bound_thumbprint = bound_thumbprint_of(&claims);
        if bound_thumbprint.is_empty() && !client.is_empty() {
            let declaration =
                self.ports.certificate_declaration(&token_realm, &client);
            if !declaration.is_empty() {
                return Err(invalid(
                    codes::STS_API_0137,
                    scope,
                    format!(
                        "RFC 8705: client \"{}\" declares {}, so this API accepts its access tokens only bound to \
                         its TLS client certificate (cnf[\"x5t#S256\"]), and this one is not bound. Ask \
                         /oauth2/token for a new one over mutual TLS and present it on a connection made with the \
                         same certificate.",
                        client, declaration
                    ),
                ));
            }
        }
        let bound_jkt = claims
            .pointer("/cnf/jkt")
            .and_then(Json::as_str)
            .unwrap_or("");
        let mut proof_ok = false;
        if !bound_jkt.is_empty() {
            if scheme != "dpop" {
                return Err(Box::new(Refused {
                    status: 401,
                    error: "invalid_token",
                    code: codes::STS_API_0120,
                    www_authenticate: Some(format!("DPoP error=\"invalid_token\", scope=\"{}\"", scope)),
                    nonce_wanted: false,
                    message: "That access token is DPoP-bound (it carries cnf.jkt), so it must be sent as \
                              \"Authorization: DPoP <token>\" with a DPoP proof — not as a Bearer token. \
                              Presenting it as a bearer token would throw the binding away."
                        .into(),
                }));
            }
            let request = ProofRequest {
                htm: arrived.method,
                htu: arrived.htu,
                access_token: Some(&token),
                expected_jkt: Some(bound_jkt),
                now: arrived.now,
            };
            if let Err(f) = verify_proof(arrived.dpop, &request, self.dpop) {
                return Err(Box::new(Refused {
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
                }));
            }
            proof_ok = true;
        }
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
            client_bound:
                sts_oauth::sender_constraints::DPOP_BOUND_PUBLIC_CLIENTS
                    .contains(&client.as_str())
                    && sts_oauth::sender_constraints::dpop_bound_public_client(
                        &client,
                        &self.ports.client_method(&token_realm, &client),
                    ),
        };
        // `oauth2.accessTokenRequireDpop` IS THE ISSUING REALM'S (Node's
        // #28, rcbj, 2026-11-15). A realm's switch is about the tokens that
        // realm's own clients hold; asked in the ambient realm it also
        // refused the service-wide API client's bearer token — the default
        // realm's `sts-api-client`, which operators and automation use at
        // every realm's `/admin-api`. The default realm's value is the
        // process's (it has no realm layer); a realm's own token meets the
        // realm's rule. The WWW-Authenticate scheme follows the same answer.
        let dpop_required = if token_realm == DEFAULT_REALM {
            self.settings
                .process_value(keys::OAUTH2_ACCESS_TOKEN_REQUIRE_DPOP)
                .as_bool()
        } else {
            access_token_dpop_required(self.settings)
        };
        if let Some(r) =
            access_token_refusal_with(self.settings, &presented, dpop_required)
        {
            return Err(Box::new(Refused {
                status: 401,
                error: r.error,
                code: r.code,
                www_authenticate: Some(format!(
                    "{} error=\"{}\", scope=\"{}\"",
                    if dpop_required { "DPoP" } else { "Bearer" },
                    r.error,
                    scope
                )),
                nonce_wanted: false,
                message: r.description,
            }));
        }
        self.decision(
            arrived,
            &operation,
            scope,
            mdm_feed,
            console_op,
            security_change,
            claims,
            token_realm,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn decision(
        &self,
        arrived: &Arrived,
        operation: &ConsoleOperation,
        scope: &str,
        mdm_feed: bool,
        console_op: bool,
        security_change: Option<String>,
        claims: Json,
        token_realm: String,
    ) -> Result<Caller, Box<Refused>> {
        let path = arrived.path.trim_end_matches('/');
        let read = arrived.method == "GET";
        let person = text_or_empty(claims.get("sub"));
        let client = text_or_empty(claims.get("client_id"));
        let carried: Vec<String> = text_or_empty(claims.get("scope"))
            .split_whitespace()
            .map(str::to_string)
            .collect();
        let who = if !client.is_empty() {
            client.clone()
        } else if !person.is_empty() {
            person.clone()
        } else {
            "(a client)".to_string()
        };
        let undeclared: Vec<String> = carried
            .iter()
            .filter(|s| {
                ADMIN_SCOPES.contains(&s.as_str())
                    && !self.ports.declares(&token_realm, &client, s)
            })
            .cloned()
            .collect();
        let scopes: Vec<String> = carried
            .iter()
            .filter(|s| !undeclared.contains(s))
            .cloned()
            .collect();
        let effective =
            self.ports.effective_roles(&token_realm, &claims, &scopes);
        let owner_scope = if read { "owner:read" } else { "owner:write" };
        let owner_path = !mdm_feed
            && !console_op
            && security_change.is_none()
            && !carried.iter().any(|s| s == scope)
            && carried.iter().any(|s| s == owner_scope);
        // `ownedOperationOf(req)`, in the realm that issued the token.
        let owned = if owner_path {
            let query = crate::request::parse_query(
                arrived.original_url.split_once('?').map_or("", |(_, q)| q),
            );
            let empty = Json::Object(Default::default());
            let body = if read {
                &empty
            } else {
                arrived.body.unwrap_or(&empty)
            };
            owned_operation_of(arrived.method, path, &query, body)
        } else {
            None
        };
        if owner_path && (owned.is_none() || token_realm != arrived.realm) {
            return Err(forbidden(
                codes::STS_API_0132,
                format!(
                    "This access token carries {} and not {}, so it is an OWNER's token, and an owner's token \
                     reaches only the operations on one role, group, service account or application it names — \
                     GET {}/roles?role=, /groups?group=, /applications?application= or /service-accounts?account=, \
                     and POST {}/roles/{{action}}, /groups/{{action}}, /applications/{{action}} or /users/{{action}} \
                     naming the object{}. A list is not one: what you own is /account-api/owned/{{kind}}. {} {} is \
                     {}",
                    owner_scope, scope, BASE, BASE,
                    if owned.is_some() { ", in the realm that issued the token" } else { "" },
                    arrived.method, arrived.original_url,
                    if owned.is_some() { "in another realm." } else { "not one of these." }
                ),
            ));
        }
        let needed = if owner_path { owner_scope } else { scope };
        if undeclared.iter().any(|s| s == needed) {
            return Err(forbidden(
                codes::STS_API_0123,
                format!(
                    "This access token carries \"{}\", and the client it was issued to, {}, does not declare it: a \
                     token is honoured here only while its client still holds the scope it uses. {}",
                    needed,
                    json_or_null(claims.get("client_id")),
                    if mdm_feed {
                        "Declare device:compliance on the MDM feed's application's oauthAllowedScope.".to_string()
                    } else {
                        format!(
                            "An admin or owner scope is held by a delegated permission grant on sts-management-api \
                             (#1141): give the client a delegated permission grant of urn:sts:admin-api:{} (POST \
                             /admin-api/permissions/grant-permission), or use sts-api-client, which holds delegated \
                             permission grants of admin:read and admin:write.",
                            needed
                        )
                    }
                ),
            ));
        }
        if effective.withdrawn.iter().any(|s| s == needed) {
            let grant = if effective.subject_kind != "application"
                && needed != "device:compliance"
            {
                "Grant the console role on /admin/rbac (or POST /admin-api/rbac/grant)".to_string()
            } else {
                format!(
                    "Add the {} to {} on /admin/roles (or POST /admin-api/roles/add-member)",
                    if effective.subject_kind == "application" { "application" } else { "person" },
                    match needed {
                        "device:compliance" => "DEVICE_COMPLIANCE",
                        "admin:read" => "ADMIN_READ",
                        "admin:security" => "SECURITY_ADMIN",
                        _ => "ADMIN_WRITE",
                    }
                )
            };
            return Err(forbidden(
                codes::STS_API_0125,
                format!(
                    "This access token carries \"{}\", and its subject no longer holds a role authorizing it: {}. A \
                     token is honoured here only while its subject's roles authorize the scope it uses. {} and ask \
                     for a new token.",
                    needed, effective.why, grant
                ),
            ));
        }
        if let Some(detail) = &security_change {
            if !scopes.iter().any(|s| s == "admin:security")
                || !effective.roles.iter().any(|r| r == "SECURITY_ADMIN")
            {
                tracing::info!(
                    "admin-api: refusing {} {} for {}: {}.",
                    arrived.method,
                    arrived.original_url,
                    who,
                    detail
                );
                return Err(forbidden(
                    codes::STS_API_0138,
                    format!(
                        "Only a Security Administrator may make this change: {}. It needs a token carrying \
                         admin:security whose subject holds SECURITY_ADMIN — Admin Write does not reach it. This \
                         token carries {}. A Security Administrator grants the role on /admin/rbac (POST {}/rbac/grant \
                         with role=security).",
                        detail,
                        if scopes.is_empty() { "(no scope)".to_string() } else { scopes.join(", ") },
                        BASE
                    ),
                ));
            }
        }
        if token_realm != DEFAULT_REALM {
            // `adminScope.refusalFor()`: the port's answer where it has one,
            // else this crate's port of the classifier ([`admin_scope`]),
            // over the body with its action and the request's query.
            let query = arrived.original_url.split_once('?').map(|(_, q)| {
                Json::Object(
                    crate::request::parse_query(q).into_iter().collect(),
                )
            });
            let mut asked = arrived.body.cloned();
            if let Some(Json::Object(o)) = asked.as_mut() {
                if !operation.action.is_empty() && !o.contains_key("action") {
                    o.insert(
                        "action".into(),
                        Json::from(operation.action.as_str()),
                    );
                }
            }
            let refusal = self
                .ports
                .realm_refusal(arrived.realm, operation, arrived.body)
                .or_else(|| {
                    crate::admin_scope::refusal_for(
                        arrived.realm,
                        &operation.path,
                        asked.as_ref(),
                        query.as_ref(),
                    )
                    .map(|r| r.detail)
                });
            if let Some(detail) = refusal {
                return Err(forbidden(
                    codes::STS_API_0112,
                    format!(
                        "{} A realm's token reaches that realm's operations only; a service administrator's token, \
                         from the default realm, reaches this one.",
                        detail
                    ),
                ));
            }
        }
        if console_op && !carried.iter().any(|s| s == "admin:console") {
            return Err(forbidden(
                codes::STS_API_0127,
                format!(
                    "This is one of the admin console's own operations, under {}/console: they draw the console and \
                     are not part of the management API a client relies on ({}/openapi.json describes that). They \
                     take admin:console, which is issued only to the console's client, sts-admin-console, and this \
                     token does not carry it. A console client entry seeded before #454 declares no admin:console: \
                     add it to the entry's oauthAllowedScope and oauthGlobalConsent (POST {}/applications/add) and \
                     sign in again.",
                    BASE, BASE, BASE
                ),
            ));
        }
        let held = effective.roles.clone();
        let frame_only = path == "/console"
            || path == "/console/operations"
            || path == "/console/language";
        let required: Vec<String> = if mdm_feed {
            vec!["DEVICE_COMPLIANCE".into()]
        } else if console_op {
            vec!["ADMIN_CONSOLE".into()]
        } else if path == "/me" {
            vec!["ADMIN_READ".into(), "ADMIN_CONSOLE".into()]
        } else if security_change.is_some() {
            vec!["SECURITY_ADMIN".into()]
        } else if read {
            vec!["ADMIN_READ".into()]
        } else {
            vec!["ADMIN_WRITE".into()]
        };
        let required_all: Vec<String> = if console_op && !frame_only {
            vec![if read {
                "ADMIN_READ".into()
            } else {
                "ADMIN_WRITE".into()
            }]
        } else {
            Vec::new()
        };
        if self.settings.value_of("xacml.enforceAccess").as_bool() {
            let owned_object =
                owned.as_ref().map(|o| sts_xacml::access::OwnedObject {
                    kind: o.kind.clone(),
                    id: o.id.clone(),
                    action: o.action.clone(),
                    required_role: if read {
                        "OWNER_READ".into()
                    } else {
                        "OWNER_WRITE".into()
                    },
                    attributes: o.attributes.clone(),
                    person: effective.subject_name.clone(),
                });
            let question = Question {
                resource: "management-api".into(),
                action: if read { "read".into() } else { "write".into() },
                subject: who.clone(),
                authenticated: true,
                required_all_roles: required_all.clone(),
                owned_object: owned_object.clone(),
                ..Default::default()
            };
            let answer = self.access.check(&question, &held, &required);
            if let (false, Some(o)) = (answer.allowed, &owned_object) {
                tracing::info!(
                    "admin-api: the access policy's owner rule refused {} {} \
                     for {}. {}",
                    arrived.method,
                    arrived.original_url,
                    o.person,
                    answer.why
                );
                return Err(forbidden(
                    codes::STS_API_0133,
                    format!(
                        "The access policy's owner rule refused this request. An owner may {} the {} \"{}\" only \
                         when it names them, or a group they are in, as an owner; when it is not closed to its \
                         owners (a native or protected role, a group or application this service grants through, \
                         or one an administrator closed); when \"{}\" is an action its kind allows an owner{}; and \
                         never to take its last owner off. {}",
                        if read { "read" } else { "change" },
                        o.kind,
                        o.id,
                        o.action,
                        if o.attributes.is_empty() {
                            String::new()
                        } else {
                            format!(
                                ", and every attribute it writes ({}) is one an owner may write",
                                o.attributes.join(", ")
                            )
                        },
                        answer.why
                    ),
                ));
            }
            if !answer.allowed {
                tracing::info!(
                    "admin-api: the access policy refused {} {} for {}. {}",
                    arrived.method,
                    arrived.original_url,
                    who,
                    answer.why
                );
                let needs = if mdm_feed {
                    "The device compliance feed needs device:compliance (DEVICE_COMPLIANCE), and only that".to_string()
                } else if console_op {
                    format!(
                        "A console operation needs admin:console (ADMIN_CONSOLE){}",
                        if required_all.is_empty() {
                            ""
                        } else if read {
                            " and admin:read (ADMIN_READ)"
                        } else {
                            " and admin:write (ADMIN_WRITE)"
                        }
                    )
                } else if security_change.is_some() {
                    "This change needs admin:security (SECURITY_ADMIN)"
                        .to_string()
                } else if read {
                    "A read needs admin:read (ADMIN_READ)".to_string()
                } else {
                    "A write needs admin:write (ADMIN_WRITE)".to_string()
                };
                return Err(forbidden(
                    codes::STS_API_0005,
                    format!(
                        "The access policy refused this request. {} This token carries the scope(s) {}, which is the \
                         role(s) {}. {}. The document is on /admin/xacml and xacml.enforceAccess turns the layer off.",
                        answer.why,
                        if scopes.is_empty() { "(none)".to_string() } else { scopes.join(", ") },
                        if held.is_empty() { "(none)".to_string() } else { held.join(", ") },
                        needs
                    ),
                ));
            }
        }
        Ok(Caller {
            kind: if effective.subject_kind == "application" {
                "application".into()
            } else {
                "person".into()
            },
            name: effective.subject_name.clone(),
            sub: person,
            auth_time: claims
                .get("auth_time")
                .and_then(Json::as_f64)
                .map(|f| f as i64)
                .unwrap_or(0),
            client_id: client,
            realm: token_realm,
            scopes,
            roles: held,
            expires_at: claims
                .get("exp")
                .and_then(Json::as_f64)
                .map(|f| f as i64),
            owner: owned.is_some(),
            owned,
            claims,
        })
    }
}
