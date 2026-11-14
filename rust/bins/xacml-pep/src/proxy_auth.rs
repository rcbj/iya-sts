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
//! **Each validation call goes through the ONE client** (`PdpClient`), so
//! the PEP's certificate is presented and the PDP verified as for every
//! pull. **No log line here carries a token, an assertion, a password or a
//! session id** — the refusal's reason and code only.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use reqwest::Method;
use serde_json::{json, Value};
use sts_core::log::tag;

use crate::jwt::{self, Key, Local};
use crate::listener::Transport;
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
}

impl Identity {
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
/// (`error="invalid_token"`), and a `Retry-After` for a 429.
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
    jwks_ttl: Duration,
    jwks: Mutex<Option<JwksCache>>,
}

fn identity_of(said: &Value, mechanism: Mechanism) -> Option<Identity> {
    let sub = said["sub"]
        .as_str()
        .or_else(|| said["subject"].as_str())
        .unwrap_or("")
        .to_string();
    let username = said["username"]
        .as_str()
        .or_else(|| said["preferred_username"].as_str())
        .unwrap_or("")
        .to_string();
    (!sub.is_empty() || !username.is_empty()).then_some(Identity {
        sub,
        username,
        mechanism,
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
            jwks_ttl: Duration::from_millis(jwks_ttl_ms),
            jwks: Mutex::new(None),
        }
    }

    pub fn client(&self) -> &PdpClient {
        &self.client
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
            let fresh = *age < self.jwks_ttl;
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
                    &route.audience,
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
                return identity_of(&claims, Mechanism::OAuth2).ok_or_else(
                    || {
                        Refusal::token(
                            "STS-XPEP-0071",
                            "the access token names no subject",
                        )
                    },
                );
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
            .call_url(
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
        if !jwt::audience_has(&said["aud"], &route.audience) {
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
        identity_of(said, Mechanism::OAuth2).ok_or_else(|| {
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
                &route.audience,
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
                return Ok(Identity {
                    sub: found.subject,
                    username: found.username.unwrap_or_default(),
                    mechanism: Mechanism::Saml2,
                })
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
            .call_url(
                Method::POST,
                url,
                Some(Body::Json(json!({ "assertion": encoded,
                                        "audience": route.audience }))),
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
        identity_of(said, Mechanism::Saml2).ok_or_else(|| {
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
            .call_url(
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
        let mut identity =
            identity_of(said, Mechanism::Basic).unwrap_or(Identity {
                sub: String::new(),
                username: String::new(),
                mechanism: Mechanism::Basic,
            });
        // The name the person signed in with is known, so it is the
        // decision's subject when the service did not say another.
        if identity.username.is_empty() {
            identity.username = username.to_string();
        }
        Ok(identity)
    }

    /// `POST validation.session { sid }`: `Ok(Some(identity))` when live,
    /// `Ok(None)` when the service says it is not.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn session_live(
        &self,
        sid: &str,
        pulled: &Pulled,
    ) -> Result<Option<(String, String)>, Refusal> {
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
            .call_url(
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
        )))
    }
}
