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
//! Pure: no I/O, no clock. `parse_pulled()` is the one door.

use std::collections::HashSet;

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
    /// Empty means any method.
    pub methods: Vec<String>,
    pub public: bool,
    pub mechanisms: Vec<Mechanism>,
    pub audience: String,
    pub resource: String,
    pub action: String,
    pub subject_header: Option<HeaderName>,
    pub mechanism_header: Option<HeaderName>,
    pub forward_credentials: bool,
}

impl Route {
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

    pub fn takes(&self, method: &str) -> bool {
        self.methods.is_empty() || self.methods.iter().any(|m| m == method)
    }
}

/// The proxy's own document (D2).
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub enabled: bool,
    /// The upstream base, with no trailing `/`.
    pub upstream: String,
    /// The origin a browser reaches the proxy at, with no trailing `/`;
    /// empty when no route uses `session`.
    pub public_base_url: String,
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
}

/// What the PEP needs to know about its realm.
#[derive(Debug, Clone, Default)]
pub struct RealmFacts {
    pub issuer: String,
    pub jwks_uri: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub end_session_endpoint: String,
    pub saml_issuer: String,
    pub signing_certificates: Vec<X509>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
}

/// The four validation endpoints (D4), absolute.
#[derive(Debug, Clone, Default)]
pub struct ValidationUrls {
    pub introspect: String,
    pub basic: String,
    pub saml: String,
    pub session: String,
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

fn header_member(
    said: &Value,
    key: &str,
    what: &str,
) -> Result<Option<HeaderName>, String> {
    let text = string_member(said, key, what)?;
    if text.is_empty() {
        return Ok(None);
    }
    if !is_token(&text) {
        return Err(format!(
            "{}.{} is not a header name (an RFC 9110 token)",
            what, key
        ));
    }
    HeaderName::from_bytes(text.as_bytes())
        .map(Some)
        .map_err(|_| format!("{}.{} is not a header name", what, key))
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
    let methods = match said.get("methods") {
        None | Some(Value::Null) => Vec::new(),
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
    let public = bool_member(said, "public", false, &what)?;
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
    let audience = string_member(said, "audience", &what)?;
    let needs_audience = mechanisms
        .iter()
        .any(|m| matches!(m, Mechanism::OAuth2 | Mechanism::Saml2));
    if needs_audience && audience.trim().is_empty() {
        return Err(format!(
            "{} uses oauth2 or saml2 and names no audience",
            what
        ));
    }
    Ok(Route {
        id,
        path,
        matching,
        methods,
        public,
        mechanisms,
        audience,
        resource: string_member(said, "resource", &what)?,
        action: string_member(said, "action", &what)?,
        subject_header: header_member(said, "subjectHeader", &what)?,
        mechanism_header: header_member(said, "mechanismHeader", &what)?,
        forward_credentials: bool_member(
            said,
            "forwardCredentials",
            false,
            &what,
        )?,
    })
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
        public_base_url: public_base_url.trim_end_matches('/').to_string(),
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
    let optional = |key: &str| -> Result<Option<String>, String> {
        string_member(said, key, "realm")
            .map(|s| Some(s).filter(|s| !s.is_empty()))
    };
    Ok(RealmFacts {
        issuer: string_member(said, "issuer", "realm")?,
        jwks_uri: string_member(said, "jwksUri", "realm")?,
        authorization_endpoint: string_member(
            said,
            "authorizationEndpoint",
            "realm",
        )?,
        token_endpoint: string_member(said, "tokenEndpoint", "realm")?,
        end_session_endpoint: string_member(
            said,
            "endSessionEndpoint",
            "realm",
        )?,
        saml_issuer: string_member(said, "samlIssuer", "realm")?,
        signing_certificates: certificates,
        client_id: optional("clientId")?,
        redirect_uri: optional("redirectUri")?,
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
                  "methods": ["GET", "HEAD"], "public": true },
                { "id": "api", "path": "/api", "match": "prefix",
                  "methods": ["GET", "POST"],
                  "mechanisms": ["oauth2", "basic"],
                  "audience": "https://app.example/api",
                  "resource": "", "action": "",
                  "subjectHeader": "X-Remote-User",
                  "mechanismHeader": "X-Remote-Auth",
                  "forwardCredentials": false },
                { "id": "app", "path": "/app/", "match": "exact",
                  "mechanisms": ["session"] }
            ]
        })
    }

    #[test]
    fn the_contracts_example_is_accepted() {
        let config = parse_config(&sample()).unwrap();
        assert_eq!(config.upstream, "http://companion:8090/pep-app");
        assert_eq!(config.routes.len(), 3);
        let api = &config.routes[1];
        assert_eq!(api.mechanisms, [Mechanism::OAuth2, Mechanism::Basic]);
        assert_eq!(
            api.subject_header.as_ref().map(HeaderName::as_str),
            Some("x-remote-user")
        );
        assert_eq!(config.routes[2].path, "/app", "the trailing / is dropped");
        assert!(config.routes[2].methods.is_empty());
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
            &|d| d["routes"][1]["mechanisms"] = json!([]),
            "names no mechanism",
        );
        refused(
            &|d| d["routes"][1]["mechanisms"] = json!(["kerberos"]),
            "mechanisms holds",
        );
        refused(&|d| d["routes"][1]["audience"] = json!(""), "audience");
        refused(
            &|d| d["routes"][1]["subjectHeader"] = json!("X Remote"),
            "header name",
        );
        refused(&|d| d["publicBaseUrl"] = json!(""), "publicBaseUrl");
        refused(&|d| d["enabled"] = json!("yes"), "boolean");
        refused(
            &|d| {
                d["routes"] = json!((0..65)
                    .map(|i| json!({ "id": format!("r{}", i),
                        "path": "/x", "public": true }))
                    .collect::<Vec<_>>())
            },
            "more than 64",
        );
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
        assert!(config.routes[2].takes("DELETE"), "no methods is any");
    }

    #[test]
    fn a_pull_is_read_whole() {
        let unconfigured =
            parse_pulled(&json!({ "configured": false, "pep": "p" })).unwrap();
        assert!(unconfigured.active().is_none());
        let mut doc = json!({ "syncToken": "t1", "pep": "p",
            "configured": true, "proxy": sample(),
            "realm": { "issuer": "https://sts/realm/r", "clientId": null,
                       "signingCertificates": [] },
            "validation": { "introspect": "https://sts/xacml/pep/introspect",
                            "basic": "", "saml": "", "session": "" } });
        let pulled = parse_pulled(&doc).unwrap();
        assert!(pulled.active().is_some());
        assert_eq!(pulled.realm.client_id, None);
        doc["realm"]["signingCertificates"] = json!(["not a pem"]);
        assert!(parse_pulled(&doc).unwrap_err().contains("PEM"));
        doc["realm"]["signingCertificates"] = json!([]);
        doc["validation"]["basic"] = json!("not a url");
        assert!(parse_pulled(&doc).is_err());
        doc["validation"]["basic"] = json!("");
        doc["proxy"]["routes"][1]["path"] = json!("/a/..");
        assert!(parse_pulled(&doc).is_err(), "one bad route refuses all");
        assert!(parse_pulled(&json!({ "pep": "p" })).is_err());
        let mut off = parse_pulled(&json!({ "configured": true,
            "proxy": sample() }))
        .unwrap();
        if let Some(p) = off.proxy.as_mut() {
            p.enabled = false;
        }
        assert!(off.active().is_none(), "enabled: false answers nothing");
    }
}
