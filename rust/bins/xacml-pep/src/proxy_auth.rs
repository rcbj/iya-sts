// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! WHO IS ASKING, ESTABLISHED BY A ROUTE'S MECHANISM (#1760, D7) — local
//! first, and back to the service for whatever cannot be established here.
//!
//! | Mechanism | Here | At the service |
//! |---|---|---|
//! | `oauth2` | a JWS against the realm's JWKS (cached, refetched once on an unknown `kid`): signature, `iss`, `aud` holding the route's audience, `exp`/`nbf`, `cnf.x5t#S256` against this connection's certificate; `cnf.jkt` refused | an opaque token, a JWS whose key is unknown after the refetch or whose algorithm is not verified here: `validation.introspect` |
//! | `saml2` | `saml_verify.rs` | ANY local failure: `validation.saml`, whose `valid: true` alone admits; an EncryptedAssertion is refused |
//! | `basic` | never | always `validation.basic`; its 429 is passed on |
//! | `session` | the ID Token at sign-in, the cookie | `validation.session` liveness (`proxy.rs`) |
//!
//! **Each validation call goes through the ONE client** (`PdpClient`), with
//! the PEP's DPoP-bound `/xacml/pep` token (and its certificate where it has
//! one), the PDP verified as for every pull. The realm's JWKS alone is
//! fetched anonymously. **No log line here carries a token, an assertion, a password or a
//! session id** — the refusal's reason and code only.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use reqwest::Method;
use serde_json::{json, Map, Value};
use sts_core::log::tag;

use crate::jwt::{self, Key, Local};
use crate::listener::Transport;
use crate::credential::Resource;
use crate::pdp_client::{Answer, Body, PdpClient};
use crate::proxy_config::{Mechanism, Pulled, Route};
use crate::saml_verify::{self, Outcome};

/// The least time between two FORCED fetches of the JWKS, so tokens naming
/// invented `kid`s cannot make this PEP fetch on every request. The first
/// forced fetch after an ordinary one is always made — that is a key
/// rotation being picked up.
const FORCED_REFETCH_FLOOR: Duration = Duration::from_secs(5);

/// Who the request is from, once established.
#[derive(Debug, Clone, PartialEq)]
pub struct Identity {
    pub sub: String,
    pub username: String,
    pub mechanism: Mechanism,
    /// The subject's claims the credential itself established (a verified
    /// JWT, an introspection answer, the service's SAML or Basic answer, the
    /// sign-in): what mode `headers` may use without asking (D11).
    pub claims: Map<String, Value>,
    /// What the subject was established from, for `POST
    /// /xacml/pep/identity` to re-validate (D11): (`access_token`,
    /// `saml_assertion` or `ticket`, the value). A session's access token is
    /// asked of the library when it is needed, so a session has none here.
    pub evidence: Option<(&'static str, String)>,
    /// The proxy session, on a `session` route: what the identity caches
    /// are keyed by.
    pub session_id: Option<String>,
}

impl Identity {
    /// The identity, with the evidence it was established from.
    pub fn with_evidence(
        mut self,
        kind: &'static str,
        value: &str,
    ) -> Identity {
        self.evidence = Some((kind, value.to_string()));
        self
    }

    /// The cache key of an identity delivered for `application`: the proxy
    /// session, else the subject and its mechanism.
    pub fn cache_key(&self, application: &str) -> String {
        match &self.session_id {
            Some(id) => format!("session|{}|{}", id, application),
            None => format!(
                "subject|{}|{}|{}",
                self.mechanism.as_str(),
                self.subject(),
                application
            ),
        }
    }

    /// D8: the username when known, else `sub`.
    pub fn subject(&self) -> &str {
        if self.username.is_empty() {
            &self.sub
        } else {
            &self.username
        }
    }
}

/// A refusal, ready to answer: the status, the code it is logged under,
/// the sentence for the log and the body, whether a token was refused
/// (`error="invalid_token"`), and a `Retry-After` for a 429 or a 503.
#[derive(Debug, Clone, PartialEq)]
pub struct Refusal {
    pub status: u16,
    pub code: &'static str,
    pub why: String,
    pub token_refused: bool,
    pub retry_after: Option<String>,
}

impl Refusal {
    pub fn new(status: u16, code: &'static str, why: &str) -> Refusal {
        Refusal {
            status,
            code,
            why: why.to_string(),
            token_refused: false,
            retry_after: None,
        }
    }

    fn token(code: &'static str, why: &str) -> Refusal {
        Refusal {
            token_refused: true,
            ..Refusal::new(401, code, why)
        }
    }
}

struct JwksCache {
    uri: String,
    keys: Arc<Vec<Key>>,
    fetched: Instant,
    /// The fetch was a forced one.
    forced: bool,
}

/// The mechanisms, and the JWKS they share.
pub struct Authenticator {
    client: PdpClient,
    /// Moved by a settings pull (#1760, `set_jwks_ttl()`).
    jwks_ttl_ms: std::sync::atomic::AtomicU64,
    jwks: Mutex<Option<JwksCache>>,
}

/// An empty string is no value. A session's identity is built from what
/// the ID Token gave (`identity(sub, username)` below), and the service's
/// ID Token carries no `preferred_username` (#395), so the username is ""
/// there. Held as "", it counted as a claim the subject HAS: mode
/// `headers` never asked the service for it and sent `X-Remote-User: ""`
/// (found on the 8081 demo, 2026-11-14). Left out, it is asked for.
fn text_of<'a>(said: &'a Value, name: &str) -> Option<&'a str> {
    said[name].as_str().filter(|s| !s.is_empty())
}

fn identity_of(said: &Value, mechanism: Mechanism) -> Option<Identity> {
    let sub = text_of(said, "sub")
        .or_else(|| text_of(said, "subject"))
        .unwrap_or("")
        .to_string();
    let username = text_of(said, "username")
        .or_else(|| text_of(said, "preferred_username"))
        .unwrap_or("")
        .to_string();
    let mut claims = Map::new();
    for name in crate::proxy_config::IDENTITY_CLAIMS {
        if let Some(value) = said
            .get(name)
            .filter(|v| !v.is_null() && v.as_str() != Some(""))
        {
            claims.insert(name.to_string(), value.clone());
        }
    }
    if !sub.is_empty() {
        claims.insert("sub".into(), json!(sub));
    }
    if !username.is_empty() {
        claims.insert("username".into(), json!(username));
    }
    (!sub.is_empty() || !username.is_empty()).then_some(Identity {
        sub,
        username,
        mechanism,
        claims,
        evidence: None,
        session_id: None,
    })
}

/// A blank identity of `mechanism`, for a builder.
pub fn identity(sub: &str, username: &str, mechanism: Mechanism) -> Identity {
    identity_of(&json!({ "sub": sub, "username": username }), mechanism)
        .unwrap_or(Identity {
            sub: String::new(),
            username: String::new(),
            mechanism,
            claims: Map::new(),
            evidence: None,
            session_id: None,
        })
}

/// The service's answer could not be used: unreachable, or not an answer.
fn service_failed(what: &str, answer: &Answer) -> Refusal {
    let why = match &answer.error {
        Some(error) => {
            format!("the service's {} could not be asked: {}", what, error)
        }
        None => format!(
            "the service's {} answered HTTP {}, which is not an answer",
            what, answer.status
        ),
    };
    Refusal::new(502, "STS-XPEP-0075", &why)
}

pub fn now_s() -> i64 {
    chrono::Utc::now().timestamp()
}

impl Authenticator {
    pub fn new(client: PdpClient, jwks_ttl_ms: u64) -> Authenticator {
        Authenticator {
            client,
            jwks_ttl_ms: std::sync::atomic::AtomicU64::new(jwks_ttl_ms),
            jwks: Mutex::new(None),
        }
    }

    /// How long a fetched JWKS is used from now on.
    pub fn set_jwks_ttl(&self, jwks_ttl_ms: u64) {
        self.jwks_ttl_ms
            .store(jwks_ttl_ms, std::sync::atomic::Ordering::Relaxed);
    }

    /// The realm's JWKS: the cached one while it is fresh, else fetched.
    /// `force` asks again whatever the age — once after an ordinary fetch,
    /// then at most once per [`FORCED_REFETCH_FLOOR`]. A failed fetch keeps
    /// what was held.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn keys(&self, uri: &str, force: bool) -> Arc<Vec<Key>> {
        let held = {
            let guard = match self.jwks.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            guard
                .as_ref()
                .filter(|c| c.uri == uri)
                .map(|c| (c.keys.clone(), c.fetched.elapsed(), c.forced))
        };
        if let Some((keys, age, was_forced)) = &held {
            let fresh = *age
                < Duration::from_millis(
                    self.jwks_ttl_ms.load(std::sync::atomic::Ordering::Relaxed),
                );
            let throttled = *was_forced && *age < FORCED_REFETCH_FLOOR;
            if (!force && fresh) || (force && throttled) {
                return keys.clone();
            }
        }
        if uri.is_empty() {
            return Arc::new(Vec::new());
        }
        let answer = self
            .client
            // THE JWKS IS ANONYMOUS: a public document, asked without a
            // token so a PEP whose grant is refused can still verify.
            .call_url(Method::GET, uri, None, &[], None)
            .await;
        let fetched = answer
            .json
            .as_ref()
            .filter(|_| answer.status == 200 && answer.error.is_none())
            .filter(|j| j["keys"].is_array())
            .map(jwt::parse_jwks);
        let Some(keys) = fetched else {
            tracing::warn!(
                "{}xacml-pep: the realm's JWKS could not be fetched ({}); \
                 {}.",
                tag("STS-XPEP-0088"),
                answer
                    .error
                    .clone()
                    .unwrap_or_else(|| format!("HTTP {}", answer.status)),
                if held.is_some() {
                    "the keys fetched before are kept"
                } else {
                    "a token is asked of the service's introspection instead"
                }
            );
            return held.map(|(k, _, _)| k).unwrap_or_default();
        };
        let keys = Arc::new(keys);
        let mut guard = match self.jwks.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *guard = Some(JwksCache {
            uri: uri.to_string(),
            keys: keys.clone(),
            fetched: Instant::now(),
            forced: force,
        });
        keys
    }

    /// A compact JWS verified here, refetching the keys once when its
    /// `kid` is unknown. `Ok(None)` means it could not be verified here.
    pub async fn verified_claims(
        &self,
        token: &str,
        jwks_uri: &str,
    ) -> Result<Option<Value>, &'static str> {
        let mut keys = self.keys(jwks_uri, false).await;
        let mut outcome = jwt::verify(token, &keys);
        if outcome == Local::UnknownKey {
            keys = self.keys(jwks_uri, true).await;
            outcome = jwt::verify(token, &keys);
        }
        match outcome {
            Local::Verified(claims) => Ok(Some(claims)),
            Local::Refused(why) => Err(why),
            Local::NotAJwt | Local::Unsupported(_) | Local::UnknownKey => {
                Ok(None)
            }
        }
    }

    /// `Authorization: Bearer` on an `oauth2` route.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn oauth2(
        &self,
        token: &str,
        route: &Route,
        pulled: &Pulled,
        transport: &Transport,
    ) -> Result<Identity, Refusal> {
        let presented = transport.peer.as_ref().map(|p| p.sha256.as_str());
        let realm = &pulled.realm;
        let local = if jwt::header_of(token).is_some() {
            self.verified_claims(token, &realm.jwks_uri).await
        } else {
            Ok(None)
        };
        match local {
            Err(why) => {
                return Err(Refusal::token(
                    "STS-XPEP-0071",
                    &format!("the access token was refused here: {}", why),
                ))
            }
            Ok(Some(claims)) => {
                if let Some(why) = jwt::claims_problem(
                    &claims,
                    &realm.issuer,
                    &route.resolved.audiences,
                    now_s(),
                ) {
                    return Err(Refusal::token(
                        "STS-XPEP-0071",
                        &format!("the access token was refused here: {}", why),
                    ));
                }
                if let Some((code, why)) =
                    jwt::confirmation_problem(&claims["cnf"], presented)
                {
                    return Err(Refusal::token(
                        code,
                        &format!("the access token was refused: {}", why),
                    ));
                }
                return identity_of(&claims, Mechanism::OAuth2)
                    .map(|i| i.with_evidence("access_token", token))
                    .ok_or_else(|| {
                        Refusal::token(
                            "STS-XPEP-0071",
                            "the access token names no subject",
                        )
                    });
            }
            Ok(None) => {}
        }
        // AT THE SERVICE: an opaque token, or one this binary cannot verify.
        let url = &pulled.validation.introspect;
        if url.is_empty() {
            return Err(Refusal::new(
                502,
                "STS-XPEP-0075",
                "the token cannot be verified here and the service named no \
                 introspection endpoint",
            ));
        }
        let answer = self
            .client
            .call_authorized_url(
                Resource::Pep,
                Method::POST,
                url,
                Some(Body::Json(json!({ "token": token }))),
                &[],
                None,
            )
            .await;
        let Some(said) = answer
            .json
            .as_ref()
            .filter(|_| answer.status == 200 && answer.error.is_none())
        else {
            return Err(service_failed("introspection", &answer));
        };
        if said["active"].as_bool() != Some(true) {
            return Err(Refusal::token(
                "STS-XPEP-0074",
                "the service's introspection says the token is not active",
            ));
        }
        if realm.issuer.is_empty()
            || said["iss"].as_str() != Some(&realm.issuer)
        {
            return Err(Refusal::token(
                "STS-XPEP-0074",
                "the introspected token's issuer is not the realm's",
            ));
        }
        let addressed = route
            .resolved
            .audiences
            .iter()
            .any(|a| jwt::audience_has(&said["aud"], a));
        if !addressed {
            return Err(Refusal::token(
                "STS-XPEP-0074",
                "the introspected token's audience is not this route's",
            ));
        }
        if let Some((code, why)) =
            jwt::confirmation_problem(&said["cnf"], presented)
        {
            return Err(Refusal::token(
                code,
                &format!("the introspected token was refused: {}", why),
            ));
        }
        identity_of(said, Mechanism::OAuth2)
            .map(|i| i.with_evidence("access_token", token))
            .ok_or_else(|| {
                Refusal::token(
                    "STS-XPEP-0074",
                    "the introspected token names no subject",
                )
            })
    }

    /// `Authorization: SAML <base64 assertion>` on a `saml2` route.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn saml2(
        &self,
        value: &str,
        route: &Route,
        pulled: &Pulled,
    ) -> Result<Identity, Refusal> {
        let encoded: String =
            value.chars().filter(|c| !c.is_whitespace()).collect();
        let Ok(bytes) = openssl::base64::decode_block(&encoded) else {
            return Err(Refusal::new(
                401,
                "STS-XPEP-0089",
                "the SAML credential is not base64",
            ));
        };
        let realm = &pulled.realm;
        let local = match std::str::from_utf8(&bytes) {
            Ok(xml) => saml_verify::verify_local(
                xml,
                &realm.signing_certificates,
                &realm.saml_issuer,
                &route.resolved.saml_audience,
                chrono::Utc::now(),
            ),
            Err(_) => Outcome::CannotEstablish("it is not UTF-8".into()),
        };
        match local {
            Outcome::Encrypted => {
                return Err(Refusal::new(
                    401,
                    "STS-XPEP-0076",
                    "the SAML credential is an EncryptedAssertion, which \
                     neither this proxy nor the service can read",
                ))
            }
            Outcome::Verified(found) => {
                return Ok(identity(
                    &found.subject,
                    &found.username.unwrap_or_default(),
                    Mechanism::Saml2,
                )
                .with_evidence("saml_assertion", &encoded))
            }
            Outcome::CannotEstablish(why) => {
                tracing::info!(
                    "{}xacml-pep: proxy: a SAML assertion on route {} could \
                     not be established here ({}); asking the service.",
                    tag("STS-XPEP-0077"),
                    route.id,
                    why
                );
            }
        }
        let url = &pulled.validation.saml;
        if url.is_empty() {
            return Err(Refusal::new(
                502,
                "STS-XPEP-0075",
                "the assertion cannot be verified here and the service named \
                 no SAML validation endpoint",
            ));
        }
        let answer = self
            .client
            .call_authorized_url(
                Resource::Pep,
                Method::POST,
                url,
                Some(Body::Json(json!({ "assertion": encoded,
                                        "audience": route.resolved.saml_audience }))),
                &[],
                None,
            )
            .await;
        let Some(said) = answer
            .json
            .as_ref()
            .filter(|_| answer.status == 200 && answer.error.is_none())
        else {
            return Err(service_failed("SAML validation", &answer));
        };
        if said["valid"].as_bool() != Some(true) {
            return Err(Refusal::new(
                401,
                "STS-XPEP-0078",
                "the service says the SAML assertion is not valid",
            ));
        }
        identity_of(said, Mechanism::Saml2)
            .map(|i| i.with_evidence("saml_assertion", &encoded))
            .ok_or_else(|| {
                Refusal::new(401, "STS-XPEP-0078", "the assertion names nobody")
            })
    }

    /// `Authorization: Basic` on a `basic` route: ALWAYS the service's.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn basic(
        &self,
        value: &str,
        pulled: &Pulled,
    ) -> Result<Identity, Refusal> {
        let malformed = || {
            Refusal::new(
                401,
                "STS-XPEP-0089",
                "the Basic credential is not base64 of user:password",
            )
        };
        let bytes = openssl::base64::decode_block(value.trim())
            .map_err(|_| malformed())?;
        let text = String::from_utf8(bytes).map_err(|_| malformed())?;
        let (username, password) =
            text.split_once(':').ok_or_else(malformed)?;
        if username.is_empty() {
            return Err(malformed());
        }
        let url = &pulled.validation.basic;
        if url.is_empty() {
            return Err(Refusal::new(
                502,
                "STS-XPEP-0075",
                "the service named no Basic validation endpoint",
            ));
        }
        let answer = self
            .client
            .call_authorized_url(
                Resource::Pep,
                Method::POST,
                url,
                Some(Body::Json(json!({ "username": username,
                                        "password": password }))),
                &[],
                None,
            )
            .await;
        if answer.status == 429 && answer.error.is_none() {
            let after = answer
                .json
                .as_ref()
                .and_then(|j| j["retryAfterS"].as_u64())
                .map(|s| s.to_string())
                .or_else(|| answer.retry_after.clone());
            return Err(Refusal {
                retry_after: after,
                ..Refusal::new(
                    429,
                    "STS-XPEP-0080",
                    "the service is refusing this account's sign-ins for \
                     now (its lockout and limits)",
                )
            });
        }
        let Some(said) = answer
            .json
            .as_ref()
            .filter(|_| answer.status == 200 && answer.error.is_none())
        else {
            return Err(service_failed("Basic validation", &answer));
        };
        if said["valid"].as_bool() != Some(true) {
            return Err(Refusal::new(
                401,
                "STS-XPEP-0079",
                "the service says the Basic credential is not valid",
            ));
        }
        let mut identity = identity_of(said, Mechanism::Basic)
            .unwrap_or_else(|| self::identity("", username, Mechanism::Basic));
        // The name the person signed in with is known, so it is the
        // decision's subject when the service did not say another.
        if identity.username.is_empty() {
            identity.username = username.to_string();
            identity.claims.insert("username".into(), json!(username));
        }
        // D11: the service's answer carries a TICKET — opaque, bound to
        // this PEP and this subject, short-lived — which is the evidence
        // the identity endpoint takes for a Basic sign-in. The password
        // itself is never sent there.
        if let Some(ticket) = said["ticket"].as_str().filter(|t| !t.is_empty())
        {
            identity = identity.with_evidence("ticket", ticket);
        }
        Ok(identity)
    }

    /// `POST validation.identity` (D11): the route, the evidence the
    /// subject was established from, and for mode `headers` the claims
    /// asked. The service's 403 is a 403 here; anything else that is not a
    /// 200 with a JSON object is a 502. Never logged: the evidence.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn identity(
        &self,
        route: &Route,
        evidence: (&str, &str),
        claims: Option<&[String]>,
        pulled: &Pulled,
    ) -> Result<Map<String, Value>, Refusal> {
        let url = &pulled.validation.identity;
        if url.is_empty() {
            return Err(Refusal::new(
                502,
                "STS-XPEP-0095",
                "the route sends an identity and the service named no \
                 identity endpoint",
            ));
        }
        let mut body = json!({ "route": route.id,
            "evidence": { "kind": evidence.0, "value": evidence.1 } });
        if let Some(claims) = claims {
            body["claims"] = json!(claims);
        }
        let answer = self
            .client
            .call_authorized_url(
                Resource::Pep,
                Method::POST,
                url,
                Some(Body::Json(body)),
                &[],
                None,
            )
            .await;
        if answer.error.is_none() && answer.status == 403 {
            return Err(Refusal::new(
                403,
                "STS-XPEP-0095",
                &format!(
                    "the service refused the identity for route {} (403{})",
                    route.id,
                    answer
                        .json
                        .as_ref()
                        .and_then(|j| j["code"].as_str())
                        .map(|c| format!(", {}", c))
                        .unwrap_or_default()
                ),
            ));
        }
        match answer.json.as_ref().and_then(Value::as_object) {
            Some(said) if answer.status == 200 && answer.error.is_none() => {
                Ok(said.clone())
            }
            _ => Err(Refusal::new(
                502,
                "STS-XPEP-0095",
                &format!(
                    "the service's identity endpoint did not answer usably \
                     for route {} ({})",
                    route.id,
                    answer
                        .error
                        .clone()
                        .unwrap_or_else(|| format!("HTTP {}", answer.status))
                ),
            )),
        }
    }

    /// `POST validation.session { sid }`: `Ok(Some((sub, username,
    /// name)))` when live, `Ok(None)` when the service says it is not.
    /// `name` is the person's display name where the service gives one.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn session_live(
        &self,
        sid: &str,
        pulled: &Pulled,
    ) -> Result<Option<(String, String, String)>, Refusal> {
        let url = &pulled.validation.session;
        if url.is_empty() {
            return Err(Refusal::new(
                502,
                "STS-XPEP-0075",
                "the service named no session liveness endpoint",
            ));
        }
        let answer = self
            .client
            .call_authorized_url(
                Resource::Pep,
                Method::POST,
                url,
                Some(Body::Json(json!({ "sid": sid }))),
                &[],
                None,
            )
            .await;
        let Some(said) = answer
            .json
            .as_ref()
            .filter(|_| answer.status == 200 && answer.error.is_none())
        else {
            return Err(service_failed("session liveness", &answer));
        };
        if said["live"].as_bool() != Some(true) {
            return Ok(None);
        }
        Ok(Some((
            said["sub"].as_str().unwrap_or("").to_string(),
            said["username"].as_str().unwrap_or("").to_string(),
            said["name"].as_str().unwrap_or("").to_string(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A session knows only `sub` from the ID Token: the username must be a
    // claim the subject LACKS, so mode `headers` asks the service for it.
    #[test]
    fn an_empty_username_is_not_a_held_claim() {
        let who = identity("urn:uuid:1", "", Mechanism::Session);
        assert_eq!(who.sub, "urn:uuid:1");
        assert_eq!(who.claims.get("sub"), Some(&json!("urn:uuid:1")));
        assert!(who.claims.get("username").is_none());
        let named = identity("urn:uuid:1", "alice", Mechanism::Session);
        assert_eq!(named.claims.get("username"), Some(&json!("alice")));
    }

    // An empty `username` falls back to `preferred_username`.
    #[test]
    fn an_empty_username_falls_back_to_preferred_username() {
        let said = json!({ "sub": "urn:uuid:1", "username": "",
                           "preferred_username": "alice", "email": "" });
        let who = identity_of(&said, Mechanism::OAuth2).expect("an identity");
        assert_eq!(who.username, "alice");
        assert!(who.claims.get("email").is_none());
    }
}
