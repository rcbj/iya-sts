// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE REVERSE PROXY'S CONFIGURATION, AS PULLED (#1760, D2 and D3).
//!
//! `GET /xacml/pep/proxy` answers this PEP's `xacmlPepProxy` document, the
//! facts about its realm a mechanism needs (the issuer, the JWKS, the
//! sign-in endpoints, the SAML issuer and its signing certificates, the
//! public client the service registered for the session mechanism) and the
//! four validation endpoints. **Every member is read again here by D2's
//! own rules** — the service validated the document when it was written,
//! and this container still refuses to load one it would not have
//! accepted, WHOLE: a route table loaded in part is a route table that
//! forwards what the operator did not configure, or refuses what they did.
//!
//! **A ROUTE REFERENCES AN APPLICATION (D10).** A non-public route names
//! an application of the realm (`application`, for logs and nothing else
//! here), and the pull answers it RESOLVED: whether it is usable now, the
//! audiences an access token for it carries, its SAML SP entity, and its
//! OIDC client — whose secret, auth method, redirect URI and scopes come
//! in `realm.clients`, never in the route. A route the service says is not
//! usable is refused at request time, never admitted on a stale copy.
//!
//! **EVERY ROUTE IS DECIDED IN XACML, BY ITS OWN POLICY** (rcbj's decision
//! on #1760): `authorization` names the policy entry the route is decided
//! by, what resource-id and action-id the request carries, and whether the
//! route is public — which now means only that it establishes no identity,
//! never that it skips the decision. No route falls back to the realm's
//! root policy. `methods` is required, and an EMPTY list allows no method.
//!
//! Pure: no I/O, no clock. `parse_pulled()` is the one door.

use std::collections::{BTreeMap, HashSet};

use axum::http::HeaderName;
use openssl::x509::X509;
use serde_json::Value;

/// The most routes a document may carry.
pub const MAX_ROUTES: usize = 64;

/// The methods a route may name.
pub const METHODS: [&str; 7] =
    ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/// How a route establishes who is asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mechanism {
    Session,
    OAuth2,
    Saml2,
    Basic,
}

impl Mechanism {
    pub fn as_str(self) -> &'static str {
        match self {
            Mechanism::Session => "session",
            Mechanism::OAuth2 => "oauth2",
            Mechanism::Saml2 => "saml2",
            Mechanism::Basic => "basic",
        }
    }

    fn of(name: &str) -> Option<Mechanism> {
        match name {
            "session" => Some(Mechanism::Session),
            "oauth2" => Some(Mechanism::OAuth2),
            "saml2" => Some(Mechanism::Saml2),
            "basic" => Some(Mechanism::Basic),
            _ => None,
        }
    }
}

/// What a route's authorization is (#1760): the closed set the service
/// writes. `Policy` is an administrator's own policy entry; `Simple` the
/// one the service generated from the route's roles; `Public` a generated
/// policy too, and a route that establishes no identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationKind {
    Policy,
    Simple,
    Public,
}

/// Which action-id a request on the route is sent with (#1760).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionModel {
    /// The HTTP method itself.
    Method,
    /// read, create, update, delete.
    Crud,
    /// read, write.
    ReadWrite,
}

impl ActionModel {
    /// The action-id for `method`. A method outside `METHODS` (TRACE,
    /// CONNECT, an extension method) is sent as itself under every model:
    /// it can reach a decision only on a route whose `methods` is empty,
    /// and that route refuses it after the decision whatever was said.
    pub fn action_for(self, method: &str) -> &str {
        match (self, method) {
            (ActionModel::Method, _) => method,
            (_, "GET" | "HEAD" | "OPTIONS") => "read",
            (ActionModel::Crud, "POST") => "create",
            (ActionModel::Crud, "PUT" | "PATCH") => "update",
            (ActionModel::Crud, "DELETE") => "delete",
            (ActionModel::ReadWrite, "POST" | "PUT" | "PATCH" | "DELETE") => {
                "write"
            }
            _ => method,
        }
    }
}

/// A route's `authorization` (#1760), read strictly. `roles` is the
/// service's own (which roles its generated policy names) and is not kept:
/// the policy already says it, and a second copy here could only disagree.
#[derive(Debug, Clone, PartialEq)]
pub struct Authorization {
    pub kind: AuthorizationKind,
    /// The NAME of the policy entry (the `name` of a row of the policies
    /// pull), never its PolicyId: the entry is what the administrator
    /// picked, and two entries may carry one PolicyId.
    pub policy: String,
    /// The resource-id every request on the route is sent with; empty is
    /// the normalised request path.
    pub resource: String,
    pub action_model: ActionModel,
}

fn authorization_of(said: &Value, what: &str) -> Result<Authorization, String> {
    let at = format!("{}.authorization", what);
    if !said.is_object() {
        return Err(format!("{} is not an object", at));
    }
    let kind = match string_member(said, "kind", &at)?.as_str() {
        "policy" => AuthorizationKind::Policy,
        "simple" => AuthorizationKind::Simple,
        "public" => AuthorizationKind::Public,
        _ => {
            return Err(format!("{}.kind is not policy, simple or public", at))
        }
    };
    // Required for every kind: the service names the policy it generated
    // for a simple or public route as well, so a route never has nothing
    // to be decided by — and an empty name would otherwise have to mean
    // "the root", which is exactly the fall-back this design removed.
    let policy = string_member(said, "policy", &at)?;
    if policy.trim().is_empty() {
        return Err(format!("{}.policy names no policy", at));
    }
    let action_model =
        match string_member(said, "actionModel", &at)?.as_str() {
            "method" => ActionModel::Method,
            "crud" => ActionModel::Crud,
            "read-write" => ActionModel::ReadWrite,
            _ => {
                return Err(format!(
                    "{}.actionModel is not method, crud or read-write",
                    at
                ))
            }
        };
    match said.get("roles") {
        None | Some(Value::Null) | Some(Value::Object(_)) => {}
        Some(_) => return Err(format!("{}.roles is not an object", at)),
    }
    Ok(Authorization {
        kind,
        policy,
        resource: string_member(said, "resource", &at)?,
        action_model,
    })
}

/// Whether a route's path is a prefix (at a segment boundary) or exact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Match {
    Prefix,
    Exact,
}

/// One route, as D2 states it.
#[derive(Debug, Clone)]
pub struct Route {
    pub id: String,
    /// The path as configured, a trailing `/` removed (but `/` itself
    /// kept), so `/api/` and `/api` match alike.
    pub path: String,
    pub matching: Match,
    /// The methods the route takes. EMPTY MEANS NONE (#1760): a request
    /// on such a route is decided and then refused whatever the policy
    /// said. "Any" is the whole of `METHODS`, stated.
    pub methods: Vec<String>,
    /// How the route is decided, and whether it is public (#1760).
    pub authorization: Authorization,
    pub mechanisms: Vec<Mechanism>,
    /// The application the route fronts (D10), for logs: empty on a
    /// public route.
    pub application: String,
    /// The session mechanism's sign-out signals (D5): CAEP/RISC over the
    /// library's poll stream when true, `validation.session` when false.
    pub signals: bool,
    /// What the service resolved the application to, at the pull.
    pub resolved: Resolved,
    /// How the identity reaches the application (D11).
    pub identity: IdentitySpec,
    pub forward_credentials: bool,
    /// SEVERAL ACCOUNTS IN ONE BROWSER on this session route (#1760):
    /// absent or false is one sign-in per browser, as before.
    pub multiple_accounts: bool,
}

/// D11's three ways of telling the application who is asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityMode {
    /// Headers carrying claims of the subject.
    Headers,
    /// An assertion the service issues, POSTed to the application's ACS.
    Saml,
    /// An access token the service issues, as `Authorization: Bearer`.
    Jwt,
}

/// The claims an identity header may carry (D11).
pub const IDENTITY_CLAIMS: [&str; 10] = [
    "sub",
    "username",
    "email",
    "name",
    "given_name",
    "family_name",
    "groups",
    "mechanism",
    "acr",
    "amr",
];

/// The most identity headers a route may name.
pub const MAX_IDENTITY_HEADERS: usize = 16;

/// A route's `identity` (D11).
#[derive(Debug, Clone, PartialEq)]
pub struct IdentitySpec {
    pub mode: IdentityMode,
    /// (header, claim), for mode `headers`.
    pub headers: Vec<(HeaderName, String)>,
    /// Joins a list claim's members.
    pub separator: char,
}

impl Default for IdentitySpec {
    fn default() -> IdentitySpec {
        IdentitySpec {
            mode: IdentityMode::Headers,
            headers: Vec::new(),
            separator: ',',
        }
    }
}

/// A header name an identity header may not take: what frames or routes
/// the request, a credential, or a forwarding header (D11).
pub fn reserved_identity_name(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
            | "authorization"
            | "cookie"
            | "host"
            | "forwarded"
    ) || name.starts_with("x-forwarded-")
        || name.starts_with("proxy-")
}

fn identity_of(said: &Value, what: &str) -> Result<IdentitySpec, String> {
    let at = format!("{}.identity", what);
    if said.is_null() {
        return Ok(IdentitySpec::default());
    }
    if !said.is_object() {
        return Err(format!("{} is not an object", at));
    }
    let mode = match string_member(said, "mode", &at)?.as_str() {
        "" | "headers" => IdentityMode::Headers,
        "saml" => IdentityMode::Saml,
        "jwt" => IdentityMode::Jwt,
        _ => return Err(format!("{}.mode is not headers, saml or jwt", at)),
    };
    let separator_text = string_member(said, "separator", &at)?;
    let separator = if separator_text.is_empty() {
        ','
    } else {
        let mut chars = separator_text.chars();
        match (chars.next(), chars.next()) {
            (Some(c), None)
                if (' '..='~').contains(&c) && !c.is_ascii_alphanumeric() =>
            {
                c
            }
            _ => {
                return Err(format!(
                    "{}.separator is not one printable ASCII character other \
                     than a letter or digit",
                    at
                ))
            }
        }
    };
    let mut headers: Vec<(HeaderName, String)> = Vec::new();
    match said.get("headers") {
        None | Some(Value::Null) => {}
        Some(Value::Array(list)) => {
            if list.len() > MAX_IDENTITY_HEADERS {
                return Err(format!(
                    "{}.headers holds more than {}",
                    at, MAX_IDENTITY_HEADERS
                ));
            }
            for (i, one) in list.iter().enumerate() {
                let here = format!("{}.headers[{}]", at, i);
                let name = string_member(one, "name", &here)?;
                if !is_token(&name) {
                    return Err(format!("{}.name is not a header name", here));
                }
                let header =
                    HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                        format!("{}.name is not a header name", here)
                    })?;
                if reserved_identity_name(header.as_str()) {
                    return Err(format!(
                        "{}.name is a header an identity may not take",
                        here
                    ));
                }
                if headers.iter().any(|(h, _)| *h == header) {
                    return Err(format!("{}.name is named twice", here));
                }
                let claim = string_member(one, "claim", &here)?;
                if !IDENTITY_CLAIMS.contains(&claim.as_str()) {
                    return Err(format!(
                        "{}.claim is not one of {}",
                        here,
                        IDENTITY_CLAIMS.join(" ")
                    ));
                }
                headers.push((header, claim));
            }
        }
        Some(_) => return Err(format!("{}.headers is not an array", at)),
    }
    if mode != IdentityMode::Headers && !headers.is_empty() {
        return Err(format!("{} names headers and is not mode headers", at));
    }
    Ok(IdentitySpec {
        mode,
        headers,
        separator,
    })
}

impl Route {
    /// A public route establishes no identity and is decided for the
    /// anonymous subject — decided all the same.
    pub fn is_public(&self) -> bool {
        self.authorization.kind == AuthorizationKind::Public
    }

    pub fn allows(&self, mechanism: Mechanism) -> bool {
        self.mechanisms.contains(&mechanism)
    }

    /// Whether `path` — already normalised — is this route's.
    pub fn matches(&self, path: &str) -> bool {
        match self.matching {
            Match::Exact => path == self.path,
            Match::Prefix => {
                self.path == "/"
                    || path == self.path
                    || (path.starts_with(self.path.as_str())
                        && path.as_bytes().get(self.path.len()) == Some(&b'/'))
            }
        }
    }

    /// Membership only: an empty list takes nothing.
    pub fn takes(&self, method: &str) -> bool {
        self.methods.iter().any(|m| m == method)
    }
}

/// A route's application as the service resolved it (D10).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Resolved {
    pub usable: bool,
    /// Why not, for the log only.
    pub why: String,
    pub code: String,
    /// The audiences an access token for the application carries: one
    /// of them in `aud` admits (oauth2).
    pub audiences: Vec<String>,
    /// The application's SAML SP entity ID: the Audience (saml2).
    pub saml_audience: String,
    /// The application's OIDC client, a key of `realm.clients` (session).
    pub client_id: String,
}

/// The proxy's own document (D2).
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub enabled: bool,
    /// The upstream base, with no trailing `/`.
    pub upstream: String,
    pub upstream_timeout_ms: u64,
    pub max_body_bytes: u64,
    pub routes: Vec<Route>,
}

impl ProxyConfig {
    /// The route a normalised path belongs to: the FIRST whose path
    /// matches, whatever the method (a method it does not take is a 405,
    /// not a reason to try the next route).
    pub fn route_for(&self, path: &str) -> Option<&Route> {
        self.routes.iter().find(|r| r.matches(path))
    }

    /// Every identity header ANY route names: removed from every request
    /// whatever its route, so a client can inject none of them anywhere.
    pub fn identity_header_names(&self) -> Vec<HeaderName> {
        let mut out: Vec<HeaderName> = Vec::new();
        for route in &self.routes {
            for (name, _) in &route.identity.headers {
                if !out.contains(name) {
                    out.push(name.clone());
                }
            }
        }
        out
    }
}

/// What the PEP needs to know about its realm.
#[derive(Debug, Clone, Default)]
pub struct RealmFacts {
    pub issuer: String,
    pub jwks_uri: String,
    pub saml_issuer: String,
    pub signing_certificates: Vec<X509>,
    /// Per OIDC client a session route resolved to (D5, D10).
    pub clients: BTreeMap<String, RpClient>,
    /// The PEM chain of the service's listener: the library's `tlsCa`.
    pub tls_ca_chain: String,
    /// The service's own cookie names and prefixes (a trailing `*`), which
    /// the proxy never forwards upstream (2026-11-14). A service older than
    /// the member sends none, and `SERVICE_COOKIE_PREFIXES` stands in.
    pub service_cookie_prefixes: Vec<String>,
}

/// WHAT A SERVICE THAT PUBLISHES NO COOKIE NAMES IS TAKEN TO USE: every
/// cookie it writes is `sts_…` inside and `__Host-sts_…` or `__Secure-sts_…`
/// on the wire (`common/cookie_wire.ts`). Used only when the pull carries no
/// `realm.serviceCookiePrefixes` — an older service — so a name the service
/// adds tomorrow is still the service's to publish, not this table's.
pub const SERVICE_COOKIE_PREFIXES: &[&str] =
    &["sts_*", "__Host-sts_*", "__Secure-sts_*"];

/// What the relying party of one application needs (D5). The secret's
/// `Debug` is redacted, so no `{:?}` of a pull can log it.
#[derive(Clone, Default, PartialEq)]
pub struct RpClient {
    pub client_secret: String,
    pub token_endpoint_auth_method: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

impl std::fmt::Debug for RpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpClient")
            .field("client_secret", &"(redacted)")
            .field(
                "token_endpoint_auth_method",
                &self.token_endpoint_auth_method,
            )
            .field("redirect_uri", &self.redirect_uri)
            .field("scopes", &self.scopes)
            .finish()
    }
}

/// The four validation endpoints (D4), absolute.
#[derive(Debug, Clone, Default)]
pub struct ValidationUrls {
    pub introspect: String,
    pub basic: String,
    pub saml: String,
    pub session: String,
    /// `POST /xacml/pep/identity` (D11).
    pub identity: String,
}

/// One pull's answer, read whole.
#[derive(Debug, Clone, Default)]
pub struct Pulled {
    pub sync_token: String,
    pub pep: String,
    pub configured: bool,
    pub proxy: Option<ProxyConfig>,
    pub realm: RealmFacts,
    pub validation: ValidationUrls,
}

impl Pulled {
    /// The configuration in force: configured, present and enabled.
    pub fn active(&self) -> Option<&ProxyConfig> {
        self.proxy.as_ref().filter(|p| self.configured && p.enabled)
    }
}

/// An RFC 9110 `token`: one or more tchar.
pub fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// D2's rule for a route's path: starts with `/`, no `.` or `..` segment,
/// no `//`, no `%`, no `\` — and no control character, which no request
/// path that normalises can hold either.
pub fn path_problem(path: &str) -> Option<&'static str> {
    if !path.starts_with('/') {
        return Some("does not start with /");
    }
    if path.contains("//") {
        return Some("holds //");
    }
    if path.contains('%') {
        return Some("holds %");
    }
    if path.contains('\\') {
        return Some("holds \\");
    }
    if path.chars().any(char::is_control) {
        return Some("holds a control character");
    }
    if path.split('/').any(|s| s == "." || s == "..") {
        return Some("holds a . or .. segment");
    }
    None
}

/// An absolute http(s) URL with a host and no userinfo, query or fragment.
fn base_url_problem(text: &str) -> Option<&'static str> {
    let Ok(url) = reqwest::Url::parse(text) else {
        return Some("is not an absolute URL");
    };
    if url.scheme() != "http" && url.scheme() != "https" {
        return Some("is not http or https");
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Some("names no host");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Some("carries userinfo");
    }
    if url.query().is_some() {
        return Some("carries a query");
    }
    if url.fragment().is_some() {
        return Some("carries a fragment");
    }
    None
}

fn string_member(
    said: &Value,
    key: &str,
    what: &str,
) -> Result<String, String> {
    match said.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(s)) => Ok(s.clone()),
        Some(_) => Err(format!("{}.{} is not a string", what, key)),
    }
}

fn bool_member(
    said: &Value,
    key: &str,
    fallback: bool,
    what: &str,
) -> Result<bool, String> {
    match said.get(key) {
        None | Some(Value::Null) => Ok(fallback),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(format!("{}.{} is not a boolean", what, key)),
    }
}

fn integer_member(
    said: &Value,
    key: &str,
    low: u64,
    high: u64,
    fallback: u64,
) -> Result<u64, String> {
    match said.get(key) {
        None | Some(Value::Null) => Ok(fallback),
        Some(value) => value
            .as_u64()
            .filter(|n| (low..=high).contains(n))
            .ok_or_else(|| {
                format!(
                    "proxy.{} is not a whole number from {} to {}",
                    key, low, high
                )
            }),
    }
}

fn route_of(
    said: &Value,
    index: usize,
    seen: &mut HashSet<String>,
) -> Result<Route, String> {
    let what = format!("routes[{}]", index);
    if !said.is_object() {
        return Err(format!("{} is not an object", what));
    }
    let id = string_member(said, "id", &what)?;
    let id_ok = (1..=64).contains(&id.len())
        && id.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')
        });
    if !id_ok {
        return Err(format!("{}.id is not 1 to 64 of [A-Za-z0-9._-]", what));
    }
    if !seen.insert(id.clone()) {
        return Err(format!("{}.id \"{}\" is used twice", what, id));
    }
    let raw_path = string_member(said, "path", &what)?;
    if let Some(problem) = path_problem(&raw_path) {
        return Err(format!("{}.path {}", what, problem));
    }
    let path = if raw_path.len() > 1 {
        raw_path.trim_end_matches('/').to_string()
    } else {
        raw_path
    };
    let matching = match string_member(said, "match", &what)?.as_str() {
        "" | "prefix" => Match::Prefix,
        "exact" => Match::Exact,
        _ => return Err(format!("{}.match is not prefix or exact", what)),
    };
    // REQUIRED (#1760): an absent list used to mean "any", and an empty
    // one now means "none", so a document that says nothing cannot be
    // read either way without guessing.
    let methods = match said.get("methods") {
        None | Some(Value::Null) => {
            return Err(format!("{}.methods is required", what))
        }
        Some(Value::Array(list)) => {
            let mut out: Vec<String> = Vec::new();
            for one in list {
                let m = one
                    .as_str()
                    .filter(|m| METHODS.contains(m))
                    .ok_or_else(|| {
                        format!(
                            "{}.methods holds something that is not one of {}",
                            what,
                            METHODS.join(" ")
                        )
                    })?;
                if !out.iter().any(|o| o == m) {
                    out.push(m.to_string());
                }
            }
            out
        }
        Some(_) => return Err(format!("{}.methods is not an array", what)),
    };
    let authorization = match said.get("authorization") {
        None | Some(Value::Null) => {
            return Err(format!("{}.authorization is required", what))
        }
        Some(one) => authorization_of(one, &what)?,
    };
    let public = authorization.kind == AuthorizationKind::Public;
    let mechanisms = match said.get("mechanisms") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(list)) => {
            let mut out = Vec::new();
            for one in list {
                let m =
                    one.as_str().and_then(Mechanism::of).ok_or_else(|| {
                        format!(
                        "{}.mechanisms holds something that is not session, \
                         oauth2, saml2 or basic",
                        what
                    )
                    })?;
                if !out.contains(&m) {
                    out.push(m);
                }
            }
            out
        }
        Some(_) => return Err(format!("{}.mechanisms is not an array", what)),
    };
    if public && !mechanisms.is_empty() {
        return Err(format!("{} is public and names mechanisms", what));
    }
    if !public && mechanisms.is_empty() {
        return Err(format!("{} is not public and names no mechanism", what));
    }
    let application = string_member(said, "application", &what)?;
    if public && !application.is_empty() {
        return Err(format!("{} is public and names an application", what));
    }
    if !public && application.trim().is_empty() {
        return Err(format!("{} is not public and names no application", what));
    }
    let resolved = if public {
        Resolved::default()
    } else {
        resolved_of(&said["resolved"], &mechanisms, &what)?
    };
    Ok(Route {
        id,
        path,
        matching,
        methods,
        authorization,
        mechanisms,
        application,
        signals: bool_member(said, "signals", true, &what)?,
        resolved,
        identity: identity_of(&said["identity"], &what)?,
        forward_credentials: bool_member(
            said,
            "forwardCredentials",
            false,
            &what,
        )?,
        multiple_accounts: bool_member(
            said,
            "multipleAccounts",
            false,
            &what,
        )?,
    })
}

fn strings_of(said: &Value, what: &str) -> Result<Vec<String>, String> {
    match said {
        Value::Null => Ok(Vec::new()),
        Value::String(one) => {
            Ok(one.split_whitespace().map(str::to_string).collect())
        }
        Value::Array(list) => list
            .iter()
            .map(|one| {
                one.as_str()
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .ok_or_else(|| {
                        format!("{} holds something that is not a string", what)
                    })
            })
            .collect(),
        _ => Err(format!("{} is not a list of strings", what)),
    }
}

/// `routes[i].resolved` (D10), read strictly: an object with a boolean
/// `usable`, and — when usable — what each of the route's mechanisms needs.
fn resolved_of(
    said: &Value,
    mechanisms: &[Mechanism],
    what: &str,
) -> Result<Resolved, String> {
    let at = format!("{}.resolved", what);
    if !said.is_object() {
        return Err(format!("{} is not an object", at));
    }
    let usable = said["usable"]
        .as_bool()
        .ok_or_else(|| format!("{}.usable is not a boolean", at))?;
    let resolved = Resolved {
        usable,
        why: string_member(said, "why", &at)?,
        code: string_member(said, "code", &at)?,
        audiences: strings_of(
            &said["audiences"],
            &format!("{}.audiences", at),
        )?,
        saml_audience: string_member(said, "samlAudience", &at)?,
        client_id: string_member(said, "clientId", &at)?,
    };
    if usable {
        if mechanisms.contains(&Mechanism::OAuth2)
            && resolved.audiences.is_empty()
        {
            return Err(format!(
                "{} is usable for oauth2 and names no audience",
                at
            ));
        }
        if mechanisms.contains(&Mechanism::Saml2)
            && resolved.saml_audience.is_empty()
        {
            return Err(format!(
                "{} is usable for saml2 and names no samlAudience",
                at
            ));
        }
        if mechanisms.contains(&Mechanism::Session)
            && resolved.client_id.is_empty()
        {
            return Err(format!(
                "{} is usable for session and names no clientId",
                at
            ));
        }
    }
    Ok(resolved)
}

/// D2, read whole.
pub fn parse_config(said: &Value) -> Result<ProxyConfig, String> {
    if !said.is_object() {
        return Err("proxy is not an object".into());
    }
    let enabled = bool_member(said, "enabled", true, "proxy")?;
    let upstream = string_member(said, "upstream", "proxy")?;
    if let Some(problem) = base_url_problem(&upstream) {
        return Err(format!("proxy.upstream {}", problem));
    }
    let routes_said = match said.get("routes") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(list)) => list.clone(),
        Some(_) => return Err("proxy.routes is not an array".into()),
    };
    if routes_said.len() > MAX_ROUTES {
        return Err(format!("proxy.routes holds more than {}", MAX_ROUTES));
    }
    let mut seen = HashSet::new();
    let mut routes = Vec::new();
    for (i, one) in routes_said.iter().enumerate() {
        routes.push(route_of(one, i, &mut seen)?);
    }
    let public_base_url = string_member(said, "publicBaseUrl", "proxy")?;
    let uses_session = routes.iter().any(|r| r.allows(Mechanism::Session));
    if !public_base_url.is_empty() {
        if let Some(problem) = base_url_problem(&public_base_url) {
            return Err(format!("proxy.publicBaseUrl {}", problem));
        }
    } else if uses_session {
        return Err("proxy.publicBaseUrl is required when a route uses \
                    session"
            .into());
    }
    Ok(ProxyConfig {
        enabled,
        upstream: upstream.trim_end_matches('/').to_string(),
        upstream_timeout_ms: integer_member(
            said,
            "upstreamTimeoutMs",
            1,
            120_000,
            10_000,
        )?,
        max_body_bytes: integer_member(
            said,
            "maxBodyBytes",
            0,
            104_857_600,
            1_048_576,
        )?,
        routes,
    })
}

fn realm_of(said: &Value) -> Result<RealmFacts, String> {
    if said.is_null() {
        return Ok(RealmFacts::default());
    }
    if !said.is_object() {
        return Err("realm is not an object".into());
    }
    let mut certificates = Vec::new();
    match said.get("signingCertificates") {
        None | Some(Value::Null) => {}
        Some(Value::Array(list)) => {
            for (i, one) in list.iter().enumerate() {
                let pem = one.as_str().ok_or_else(|| {
                    format!("realm.signingCertificates[{}] is not a string", i)
                })?;
                let parsed = X509::from_pem(pem.as_bytes()).map_err(|_| {
                    format!(
                        "realm.signingCertificates[{}] is not a PEM \
                         certificate",
                        i
                    )
                })?;
                certificates.push(parsed);
            }
        }
        Some(_) => {
            return Err("realm.signingCertificates is not an array".into())
        }
    }
    let mut clients = BTreeMap::new();
    match said.get("clients") {
        None | Some(Value::Null) => {}
        Some(Value::Object(map)) => {
            for (id, one) in map {
                let at = format!("realm.clients[{}]", id);
                if id.is_empty() || !one.is_object() {
                    return Err(format!("{} is not an object", at));
                }
                let client = RpClient {
                    client_secret: string_member(one, "clientSecret", &at)?,
                    token_endpoint_auth_method: string_member(
                        one,
                        "tokenEndpointAuthMethod",
                        &at,
                    )?,
                    redirect_uri: string_member(one, "redirectUri", &at)?,
                    scopes: strings_of(
                        &one["scopes"],
                        &format!("{}.scopes", at),
                    )?,
                };
                if client.client_secret.is_empty()
                    || client.redirect_uri.is_empty()
                {
                    return Err(format!(
                        "{} names no clientSecret or redirectUri",
                        at
                    ));
                }
                clients.insert(id.clone(), client);
            }
        }
        Some(_) => return Err("realm.clients is not an object".into()),
    }
    Ok(RealmFacts {
        issuer: string_member(said, "issuer", "realm")?,
        jwks_uri: string_member(said, "jwksUri", "realm")?,
        saml_issuer: string_member(said, "samlIssuer", "realm")?,
        signing_certificates: certificates,
        clients,
        tls_ca_chain: string_member(said, "tlsCaChain", "realm")?,
        service_cookie_prefixes: match said.get("serviceCookiePrefixes") {
            None | Some(Value::Null) => SERVICE_COOKIE_PREFIXES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            Some(list) => strings_of(list, "realm.serviceCookiePrefixes")?,
        },
    })
}

fn validation_of(said: &Value) -> Result<ValidationUrls, String> {
    if said.is_null() {
        return Ok(ValidationUrls::default());
    }
    if !said.is_object() {
        return Err("validation is not an object".into());
    }
    let url = |key: &str| -> Result<String, String> {
        let text = string_member(said, key, "validation")?;
        if !text.is_empty() {
            if let Some(problem) = base_url_problem(&text) {
                return Err(format!("validation.{} {}", key, problem));
            }
        }
        Ok(text)
    };
    Ok(ValidationUrls {
        introspect: url("introspect")?,
        basic: url("basic")?,
        saml: url("saml")?,
        session: url("session")?,
        identity: url("identity")?,
    })
}

/// D3's answer, read whole: `Err` names the first thing refused, and then
/// nothing of it is used.
pub fn parse_pulled(said: &Value) -> Result<Pulled, String> {
    if !said.is_object() {
        return Err("the answer is not a JSON object".into());
    }
    let configured = said["configured"].as_bool().ok_or_else(|| {
        "the answer's configured member is not a boolean".to_string()
    })?;
    let sync_token = match &said["syncToken"] {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    };
    let pep = said["pep"].as_str().unwrap_or("").to_string();
    if !configured {
        return Ok(Pulled {
            sync_token,
            pep,
            configured: false,
            ..Pulled::default()
        });
    }
    let proxy = parse_config(&said["proxy"])?;
    let realm = realm_of(&said["realm"])?;
    let validation = validation_of(&said["validation"])?;
    // A usable session route's client must have come with it: a route that
    // names a client the pull carries no secret for could only fail later,
    // one sign-in at a time.
    for route in &proxy.routes {
        let wants = route.allows(Mechanism::Session) && route.resolved.usable;
        if wants && !realm.clients.contains_key(&route.resolved.client_id) {
            return Err(format!(
                "route {} names a client realm.clients does not carry",
                route.id
            ));
        }
    }
    Ok(Pulled {
        sync_token,
        pep,
        configured: true,
        proxy: Some(proxy),
        realm,
        validation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    pub fn sample() -> Value {
        json!({
            "enabled": true,
            "upstream": "http://companion:8090/pep-app",
            "publicBaseUrl": "https://xacml-pep:9543",
            "upstreamTimeoutMs": 10000,
            "maxBodyBytes": 1048576,
            "routes": [
                { "id": "public", "path": "/public", "match": "prefix",
                  "methods": ["GET", "HEAD"],
                  "authorization": { "kind": "public",
                    "policy": "pep-p-public", "resource": "",
                    "actionModel": "method" } },
                { "id": "api", "path": "/api", "match": "prefix",
                  "methods": ["GET", "POST"],
                  "mechanisms": ["oauth2", "basic"],
                  "application": "pep-app",
                  "resolved": { "usable": true,
                                "audiences": ["https://app.example/api"] },
                  "authorization": { "kind": "simple",
                    "policy": "pep-p-api",
                    "resource": "https://pep.example:9543/pep-app/api",
                    "actionModel": "crud",
                    "roles": { "read": ["reader"] } },
                  "identity": { "mode": "headers", "separator": ";",
                    "headers": [ { "name": "X-Remote-User", "claim": "username" },
                                 { "name": "X-Remote-Auth", "claim": "mechanism" } ] },
                  "forwardCredentials": false },
                { "id": "app", "path": "/app/", "match": "exact",
                  "methods": [],
                  "authorization": { "kind": "policy", "policy": "mine",
                                     "actionModel": "read-write" },
                  "mechanisms": ["session"], "application": "pep-app",
                  "signals": false,
                  "resolved": { "usable": true, "clientId": "app-client" } },
                { "id": "gone", "path": "/gone", "mechanisms": ["saml2"],
                  "methods": ["GET"],
                  "authorization": { "kind": "policy", "policy": "mine",
                                     "actionModel": "method" },
                  "application": "deleted-app",
                  "resolved": { "usable": false, "why": "deleted",
                                "code": "STS-XACML-0001" } }
            ]
        })
    }

    fn realm() -> Value {
        json!({ "issuer": "https://sts/realm/r", "signingCertificates": [],
                "tlsCaChain": "",
                "clients": { "app-client": { "clientSecret": "s3cret",
                    "tokenEndpointAuthMethod": "client_secret_basic",
                    "redirectUri": "https://xacml-pep:9543/.iya-pep/callback",
                    "scopes": ["openid", "profile"] } } })
    }

    #[test]
    fn the_contracts_example_is_accepted() {
        let config = parse_config(&sample()).unwrap();
        assert_eq!(config.upstream, "http://companion:8090/pep-app");
        assert_eq!(config.routes.len(), 4);
        let api = &config.routes[1];
        assert_eq!(api.mechanisms, [Mechanism::OAuth2, Mechanism::Basic]);
        assert_eq!(api.application, "pep-app");
        assert!(api.signals, "signals defaults to true");
        assert_eq!(api.resolved.audiences, ["https://app.example/api"]);
        assert_eq!(
            api.identity
                .headers
                .first()
                .map(|(h, c)| (h.as_str(), c.as_str())),
            Some(("x-remote-user", "username"))
        );
        assert_eq!(api.identity.separator, ';');
        assert_eq!(config.routes[2].identity, IdentitySpec::default());
        assert_eq!(
            config.identity_header_names(),
            [
                HeaderName::from_static("x-remote-user"),
                HeaderName::from_static("x-remote-auth")
            ]
        );
        assert_eq!(config.routes[2].path, "/app", "the trailing / is dropped");
        assert!(config.routes[2].methods.is_empty());
        assert!(config.routes[0].is_public() && !api.is_public());
        assert_eq!(
            api.authorization,
            Authorization {
                kind: AuthorizationKind::Simple,
                policy: "pep-p-api".into(),
                resource: "https://pep.example:9543/pep-app/api".into(),
                action_model: ActionModel::Crud,
            }
        );
        assert_eq!(config.routes[2].authorization.resource, "");
        assert_eq!(
            config.routes[2].authorization.action_model,
            ActionModel::ReadWrite
        );
        assert!(!config.routes[2].signals);
        assert_eq!(config.routes[2].resolved.client_id, "app-client");
        let gone = &config.routes[3].resolved;
        assert!(!gone.usable && gone.why == "deleted");
    }

    #[test]
    fn every_refusal_is_by_name() {
        let refused = |edit: &dyn Fn(&mut Value), needle: &str| {
            let mut doc = sample();
            edit(&mut doc);
            let problem = parse_config(&doc).unwrap_err();
            assert!(problem.contains(needle), "{} lacks {}", problem, needle);
        };
        refused(&|d| d["upstream"] = json!("ftp://x/"), "http or https");
        refused(&|d| d["upstream"] = json!("http://u:p@x/"), "userinfo");
        refused(&|d| d["upstream"] = json!("http://x/?q=1"), "query");
        refused(&|d| d["upstream"] = json!("http://x/#f"), "fragment");
        refused(&|d| d["upstream"] = json!("/relative"), "absolute");
        refused(&|d| d["upstreamTimeoutMs"] = json!(0), "upstreamTimeoutMs");
        refused(&|d| d["upstreamTimeoutMs"] = json!(120001), "from 1");
        refused(&|d| d["maxBodyBytes"] = json!(104857601), "maxBodyBytes");
        refused(&|d| d["maxBodyBytes"] = json!(-1), "maxBodyBytes");
        refused(&|d| d["routes"][0]["id"] = json!("a b"), ".id");
        refused(&|d| d["routes"][1]["id"] = json!("public"), "twice");
        refused(&|d| d["routes"][0]["path"] = json!("public"), "start");
        refused(&|d| d["routes"][0]["path"] = json!("/a//b"), "//");
        refused(&|d| d["routes"][0]["path"] = json!("/a/%2e"), "%");
        refused(&|d| d["routes"][0]["path"] = json!("/a\\b"), "\\");
        refused(&|d| d["routes"][0]["path"] = json!("/a/../b"), "segment");
        refused(&|d| d["routes"][0]["path"] = json!("/a/./b"), "segment");
        refused(&|d| d["routes"][0]["match"] = json!("glob"), "match");
        refused(&|d| d["routes"][0]["methods"] = json!(["TRACE"]), "methods");
        refused(&|d| d["routes"][0]["methods"] = json!("GET"), "methods");
        refused(
            &|d| d["routes"][0]["mechanisms"] = json!(["basic"]),
            "public and names",
        );
        refused(
            &|d| d["routes"][0]["application"] = json!("pep-app"),
            "public and names an application",
        );
        refused(
            &|d| d["routes"][1]["mechanisms"] = json!([]),
            "names no mechanism",
        );
        refused(
            &|d| d["routes"][1]["mechanisms"] = json!(["kerberos"]),
            "mechanisms holds",
        );
        // D10: a non-public route names an application and comes resolved.
        refused(
            &|d| d["routes"][1]["application"] = json!(""),
            "names no application",
        );
        refused(
            &|d| {
                d["routes"][1].as_object_mut().unwrap().remove("resolved");
            },
            "resolved is not an object",
        );
        refused(
            &|d| d["routes"][1]["resolved"]["usable"] = json!("yes"),
            "usable is not a boolean",
        );
        refused(
            &|d| d["routes"][1]["resolved"]["audiences"] = json!([]),
            "no audience",
        );
        refused(
            &|d| d["routes"][1]["resolved"]["audiences"] = json!([1]),
            "not a string",
        );
        refused(
            &|d| d["routes"][2]["resolved"]["clientId"] = json!(""),
            "no clientId",
        );
        refused(
            &|d| {
                d["routes"][3]["resolved"] = json!({ "usable": true });
            },
            "no samlAudience",
        );
        refused(&|d| d["routes"][2]["signals"] = json!("no"), "boolean");
        // D11: the identity, read strictly.
        let ident = |v: Value| {
            move |d: &mut Value| d["routes"][1]["identity"] = v.clone()
        };
        refused(&ident(json!({ "mode": "oidc" })), "mode is not");
        refused(
            &ident(
                json!({ "headers": [{ "name": "X Remote", "claim": "sub" }] }),
            ),
            "not a header name",
        );
        for reserved in [
            "Authorization",
            "Cookie",
            "Host",
            "Forwarded",
            "X-Forwarded-User",
            "Content-Length",
            "Connection",
            "Proxy-User",
            "Transfer-Encoding",
        ] {
            refused(
                &ident(
                    json!({ "headers": [{ "name": reserved, "claim": "sub" }] }),
                ),
                "may not take",
            );
        }
        refused(
            &ident(json!({ "headers": [{ "name": "X-A", "claim": "sub" },
                                       { "name": "x-a", "claim": "email" }] })),
            "named twice",
        );
        refused(
            &ident(
                json!({ "headers": [{ "name": "X-A", "claim": "password" }] }),
            ),
            "claim is not one of",
        );
        refused(
            &ident(
                json!({ "headers": (0..17).map(|i| json!({ "name": format!("x-{}", i), "claim": "sub" })).collect::<Vec<_>>() }),
            ),
            "more than 16",
        );
        refused(&ident(json!({ "separator": "a" })), "separator");
        refused(&ident(json!({ "separator": ",;" })), "separator");
        refused(
            &ident(
                json!({ "mode": "jwt", "headers": [{ "name": "X-A", "claim": "sub" }] }),
            ),
            "not mode headers",
        );
        // #1760: every route states its methods and its authorization.
        refused(
            &|d| {
                d["routes"][1].as_object_mut().unwrap().remove("methods");
            },
            "methods is required",
        );
        refused(&|d| d["routes"][1]["methods"] = Value::Null, "required");
        refused(
            &|d| {
                d["routes"][1].as_object_mut().unwrap().remove("authorization");
            },
            "authorization is required",
        );
        // The members it replaced do not stand in for it.
        refused(
            &|d| {
                let r = d["routes"][0].as_object_mut().unwrap();
                r.remove("authorization");
                r.insert("public".into(), json!(true));
            },
            "authorization is required",
        );
        let authz = |key: &'static str, v: Value| {
            move |d: &mut Value| {
                d["routes"][1]["authorization"][key] = v.clone()
            }
        };
        refused(&authz("kind", json!("open")), "kind is not");
        refused(&authz("kind", Value::Null), "kind is not");
        refused(&authz("actionModel", json!("rest")), "actionModel is not");
        refused(&authz("actionModel", Value::Null), "actionModel is not");
        refused(&authz("policy", json!("")), "names no policy");
        refused(&authz("policy", json!(" ")), "names no policy");
        refused(&authz("policy", json!(7)), "not a string");
        refused(&authz("resource", json!(true)), "not a string");
        refused(&authz("roles", json!(["reader"])), "roles is not");
        refused(
            &|d| d["routes"][1]["authorization"] = json!("simple"),
            "authorization is not an object",
        );
        // A public route takes no mechanism, whatever its kind used to be
        // spelled as.
        refused(
            &|d| d["routes"][1]["authorization"]["kind"] = json!("public"),
            "public and names mechanisms",
        );
        refused(&|d| d["publicBaseUrl"] = json!(""), "publicBaseUrl");
        refused(&|d| d["enabled"] = json!("yes"), "boolean");
        refused(
            &|d| {
                d["routes"] = json!((0..65)
                    .map(|i| json!({ "id": format!("r{}", i),
                        "path": "/x", "methods": ["GET"],
                        "authorization": { "kind": "public",
                            "policy": "p", "actionModel": "method" } }))
                    .collect::<Vec<_>>())
            },
            "more than 64",
        );
    }

    #[test]
    fn each_action_model_names_the_action() {
        let method = ActionModel::Method;
        let crud = ActionModel::Crud;
        let rw = ActionModel::ReadWrite;
        for (m, c, w) in [
            ("GET", "read", "read"),
            ("HEAD", "read", "read"),
            ("OPTIONS", "read", "read"),
            ("POST", "create", "write"),
            ("PUT", "update", "write"),
            ("PATCH", "update", "write"),
            ("DELETE", "delete", "write"),
        ] {
            assert_eq!(method.action_for(m), m);
            assert_eq!(crud.action_for(m), c, "crud {}", m);
            assert_eq!(rw.action_for(m), w, "read-write {}", m);
        }
        assert_eq!(crud.action_for("TRACE"), "TRACE");
    }

    #[test]
    fn routes_match_at_a_segment_boundary() {
        let config = parse_config(&sample()).unwrap();
        let id = |p: &str| config.route_for(p).map(|r| r.id.clone());
        assert_eq!(id("/public").as_deref(), Some("public"));
        assert_eq!(id("/public/a/b").as_deref(), Some("public"));
        assert_eq!(id("/publicity"), None, "not at a segment boundary");
        assert_eq!(id("/api/x").as_deref(), Some("api"));
        assert_eq!(id("/app").as_deref(), Some("app"));
        assert_eq!(id("/app/x"), None, "exact");
        assert_eq!(id("/"), None);
        let api = &config.routes[1];
        assert!(api.takes("GET") && !api.takes("DELETE"));
        let none = &config.routes[2];
        assert!(
            METHODS.iter().all(|m| !none.takes(m)),
            "an empty list takes no method"
        );
    }

    #[test]
    fn a_pull_is_read_whole() {
        let unconfigured =
            parse_pulled(&json!({ "configured": false, "pep": "p" })).unwrap();
        assert!(unconfigured.active().is_none());
        let mut doc = json!({ "syncToken": "t1", "pep": "p",
            "configured": true, "proxy": sample(), "realm": realm(),
            "validation": { "introspect": "https://sts/xacml/pep/introspect",
                            "basic": "", "saml": "", "session": "" } });
        let pulled = parse_pulled(&doc).unwrap();
        assert!(pulled.active().is_some());
        let client = &pulled.realm.clients["app-client"];
        assert_eq!(client.scopes, ["openid", "profile"]);
        assert!(
            !format!("{:?}", pulled).contains("s3cret"),
            "the secret never reaches a Debug line"
        );
        doc["realm"]["clients"]["app-client"]["clientSecret"] = json!("");
        assert!(parse_pulled(&doc).unwrap_err().contains("clientSecret"));
        doc["realm"] = realm();
        doc["realm"]["clients"] = json!({});
        assert!(
            parse_pulled(&doc).unwrap_err().contains("realm.clients"),
            "a usable session route's client must come with it"
        );
        doc["realm"] = realm();
        doc["realm"]["signingCertificates"] = json!(["not a pem"]);
        assert!(parse_pulled(&doc).unwrap_err().contains("PEM"));
        doc["realm"] = realm();
        doc["validation"]["basic"] = json!("not a url");
        assert!(parse_pulled(&doc).is_err());
        doc["validation"]["basic"] = json!("");
        doc["proxy"]["routes"][1]["path"] = json!("/a/..");
        assert!(parse_pulled(&doc).is_err(), "one bad route refuses all");
        assert!(parse_pulled(&json!({ "pep": "p" })).is_err());
        let mut off = parse_pulled(&json!({ "configured": true,
            "proxy": sample(), "realm": realm() }))
        .unwrap();
        if let Some(p) = off.proxy.as_mut() {
            p.enabled = false;
        }
        assert!(off.active().is_none(), "enabled: false answers nothing");
    }
}
