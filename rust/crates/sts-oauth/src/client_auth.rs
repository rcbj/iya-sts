// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! How a client proves who it is at the token endpoint
//! (`oauth-oidc/client_auth.js`): the methods, which of them a request is
//! using (`methodFor()`), and the verification (`verify()`), word for word.
//!
//! What is here: `none`; `client_secret_basic` and `client_secret_post`
//! against every secret on the entry, constant-time, with the expiry rule
//! (`mode.refusesExpiredClientSecrets()`); `client_secret_jwt` and
//! `private_key_jwt` — RFC 7523 section 3 in full (the algorithm family, the
//! registered keys by `kid`, `iss`/`sub`/`aud`/`exp`, the lifetime cap where
//! credentials are verified, the strict audience of OAuth 2.1 and FAPI 2.0,
//! the `jti` spent once through [`AssertionHistory`]); `tls_client_auth` and
//! `self_signed_tls_client_auth` over the connection's certificate as the
//! TLS layer describes it ([`PeerCertificate`]).
//!
//! What reaches outside the slice is a port, each argued where it is
//! declared: the used-assertion history (`common/used_assertions.js`), an
//! encrypted assertion's unwrap and an `x5c` header's chain
//! (`assertion_grant.js`), a registered key's certificate trust and
//! revocation (`certificate_trust.ts`, `revocation_status.js`) and a
//! `jwks_uri` fetch (`client_jwks.js`). `saml2_bearer` and the two
//! attestation methods are later slices; until they arrive a client
//! registered for one is answered [`unported`](ClientAuth::verify), never
//! accepted.
//!
//! Node verifies a client assertion ONCE PER REQUEST (`verifiedOnce()`): the
//! token endpoint asks twice, and a jti spent on the first question would
//! make the second a replay. [`Verified`] is that memo, held by the request.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::Value as Json;
use sts_core::errors::{codes, ErrorCode};
use sts_core::mode::Mode;
use sts_core::settings::Settings;
use sts_crypto::jws::{verify_jws, ClaimChecks};
use sts_crypto::jws_alg::Hash;
use sts_crypto::keys::{JwsKey, KeyPolicy};

/// RFC 7523 section 2.2's `client_assertion_type`.
pub const ASSERTION_TYPE: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
/// RFC 7522 section 2.2's.
pub const SAML_ASSERTION_TYPE: &str =
    "urn:ietf:params:oauth:client-assertion-type:saml2-bearer";

/// The methods resting on a shared secret.
pub const SYMMETRIC_METHODS: [&str; 3] = [
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
];
/// The methods resting on a key the server never holds.
pub const ASYMMETRIC_METHODS: [&str; 6] = [
    "private_key_jwt",
    "saml2_bearer",
    "tls_client_auth",
    "self_signed_tls_client_auth",
    "attest_jwt_client_auth",
    "attest_jwt_client_auth_dpop",
];

/// Every method, `token_endpoint_auth_methods_supported`'s source.
#[tracing::instrument(level = "debug", skip_all)]
pub fn methods() -> Vec<&'static str> {
    let mut out = vec!["none"];
    out.extend(SYMMETRIC_METHODS);
    out.extend(ASYMMETRIC_METHODS);
    out
}

/// `isAsymmetric()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn is_asymmetric(method: &str) -> bool {
    ASYMMETRIC_METHODS.contains(&method)
}

fn text(v: Option<&Json>) -> String {
    match v {
        None | Some(Json::Null) => String::new(),
        Some(Json::String(s)) => s.clone(),
        Some(Json::Bool(b)) => b.to_string(),
        Some(Json::Number(n)) => n.to_string(),
        Some(other) => other.to_string(),
    }
}

/// `declaredMethodsOf()`: the list an entry declares, or its one method.
#[tracing::instrument(level = "debug", skip_all)]
pub fn declared_methods_of(registered: &Json) -> Vec<String> {
    let listed = registered
        .get("token_endpoint_auth_methods")
        .and_then(Json::as_array)
        .filter(|l| !l.is_empty());
    let raw: Vec<String> = match listed {
        Some(list) => list.iter().map(|one| text(Some(one))).collect(),
        None => {
            let one = text(registered.get("token_endpoint_auth_method"));
            if one.is_empty() {
                Vec::new()
            } else {
                vec![one]
            }
        }
    };
    raw.into_iter()
        .map(|one| one.trim().to_string())
        .filter(|one| !one.is_empty())
        .collect()
}

fn presentation(method: &str) -> Option<&'static str> {
    Some(match method {
        "client_secret_basic" => {
            "client_secret_basic (an Authorization: Basic header)"
        }
        "client_secret_post" => {
            "client_secret_post (a client_secret form parameter)"
        }
        "client_secret_jwt" => {
            "client_secret_jwt (a client_assertion signed with the client \
             secret)"
        }
        "private_key_jwt" => {
            "private_key_jwt (a client_assertion signed with a registered \
             key)"
        }
        "saml2_bearer" => "saml2_bearer (a SAML 2.0 client_assertion)",
        "tls_client_auth" => "tls_client_auth (a client certificate)",
        "self_signed_tls_client_auth" => {
            "self_signed_tls_client_auth (a registered self-signed client \
             certificate)"
        }
        "attest_jwt_client_auth" => {
            "attest_jwt_client_auth (OAuth-Client-Attestation and \
             OAuth-Client-Attestation-PoP headers)"
        }
        "attest_jwt_client_auth_dpop" => {
            "attest_jwt_client_auth_dpop (OAuth-Client-Attestation and a \
             DPoP proof)"
        }
        _ => return None,
    })
}

/// `presentationSentence()`: how the declared method is presented.
#[tracing::instrument(level = "debug", skip_all)]
pub fn presentation_sentence(declared: &[String], method: &str) -> String {
    let methods: Vec<String> = if declared.is_empty() {
        if method.is_empty() {
            Vec::new()
        } else {
            vec![method.to_string()]
        }
    } else {
        declared.to_vec()
    };
    let described: Vec<String> = methods
        .iter()
        .map(|one| presentation(one).map_or(one.clone(), str::to_string))
        .collect();
    if described.len() <= 1 {
        return format!(
            "Send it by {}.",
            described
                .first()
                .map_or("the declared method", String::as_str)
        );
    }
    format!(
        "This client's entry declares {} methods; authenticate with one of \
         them: {} or {}.",
        described.len(),
        described[..described.len() - 1].join(", "),
        described[described.len() - 1]
    )
}

/// What the connection's TLS client certificate is, as the TLS layer
/// (`mtls.js`'s `peerCertificate()`, `peerVerified()`,
/// `issuedIdentityOf()`) describes it.
#[derive(Debug, Clone, Default)]
pub struct PeerCertificate {
    /// The leaf, DER.
    pub der: Vec<u8>,
    /// Whether the subject and issuer names are the same.
    pub self_issued: bool,
    /// Whether the chain verified against a trust anchor.
    pub verified: bool,
    /// Why it did not.
    pub error: String,
    /// The RFC 4514 subject (`subjectRfc4514()`).
    pub subject: String,
    /// The certificate as this realm issued it, if it did.
    pub issued: Option<IssuedIdentity>,
    /// A revocation refusal the handshake recorded:
    /// `(code, policy, why)`.
    pub revocation_refused: Option<(ErrorCode, String, String)>,
    /// RFC 8705 section 2.1.2's subject parameters this certificate
    /// matches, by member, with what it carries for each.
    pub subject_values: HashMap<String, Vec<String>>,
    /// Whether `certificate_trust` holds a pinned self-signed leaf
    /// (`tls-client-self-signed`), and why not.
    pub pinned_refusal: Option<(ErrorCode, String)>,
}

/// A certificate this realm issued as somebody's identity.
#[derive(Debug, Clone, Default)]
pub struct IssuedIdentity {
    pub issued_here: bool,
    pub accepted: bool,
    pub kind: String,
    pub username: String,
    pub serial_hex: String,
    pub why: String,
    /// Whether the holder's record still lists it.
    pub held: bool,
}

impl PeerCertificate {
    /// `mtls.thumbprintOf()`: base64url SHA-256 of the DER.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn thumbprint(&self) -> String {
        sts_crypto::b64::encode(&Hash::Sha256.digest(&self.der))
    }
}

/// What spending a client assertion's `jti` answered
/// (`usedAssertions.claim()`).
#[derive(Debug, Clone, PartialEq)]
pub enum Spent {
    Ok,
    /// Seen before; the phrase `usedAs()` writes about the earlier use.
    Replay(String),
    /// The history is full of unexpired rows.
    Full(i64),
    /// It could not be recorded.
    Failed,
}

/// One claim on the used-assertion history.
#[derive(Debug, Clone)]
pub struct AssertionClaim {
    pub issuer: String,
    pub identifier: String,
    pub client_id: String,
    /// When the row may go, ms.
    pub expires_at: i64,
}

/// `common/used_assertions.js`, the one history every assertion is spent
/// against: its own slice ports the store.
pub trait AssertionHistory: Send + Sync {
    fn claim(&self, claim: &AssertionClaim) -> Spent;
    /// `usedAssertions.summary().live`: the rows not yet past their time,
    /// for `GET /oauth2/rfc9700`.
    fn live(&self, _now_ms: i64) -> usize {
        0
    }
}

/// An in-process history: what one process remembers.
#[derive(Default)]
pub struct MemoryAssertionHistory {
    seen: Mutex<HashMap<String, i64>>,
}

impl AssertionHistory for MemoryAssertionHistory {
    fn claim(&self, claim: &AssertionClaim) -> Spent {
        let key = format!("jwt|{}|{}", claim.issuer, claim.identifier);
        let mut held = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        if held.contains_key(&key) {
            return Spent::Replay(" — as a client assertion".to_string());
        }
        held.insert(key, claim.expires_at);
        Spent::Ok
    }

    fn live(&self, now_ms: i64) -> usize {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .filter(|until| **until > now_ms)
            .count()
    }
}

/// A client secret on an entry, with its expiry (seconds; 0 never).
#[derive(Debug, Clone, PartialEq)]
pub struct Secret {
    pub id: String,
    pub secret: String,
    pub expires_at: i64,
}

/// `secretsOf()`: the entry's list of secrets, or its one secret with the
/// entry's expiry.
#[tracing::instrument(level = "debug", skip_all)]
pub fn secrets_of(registered: &Json) -> Vec<Secret> {
    let listed: Vec<Secret> = registered
        .get("client_secrets")
        .and_then(Json::as_array)
        .into_iter()
        .flatten()
        .filter(|one| !text(one.get("secret")).is_empty())
        .map(|one| Secret {
            id: text(one.get("id")),
            secret: text(one.get("secret")),
            expires_at: number(one.get("expiresAt")),
        })
        .collect();
    if !listed.is_empty() {
        return listed;
    }
    let one = text(registered.get("client_secret"));
    if one.is_empty() {
        return Vec::new();
    }
    vec![Secret {
        id: String::new(),
        secret: one,
        expires_at: number(registered.get("client_secret_expires_at")),
    }]
}

fn number(v: Option<&Json>) -> i64 {
    match v {
        Some(Json::Number(n)) => n.as_f64().map_or(0, |f| f as i64),
        Some(Json::String(s)) => {
            s.trim().parse::<f64>().map_or(0, |f| f as i64)
        }
        _ => 0,
    }
}

/// What a request presented, for [`ClientAuth::verify`].
#[derive(Debug, Clone, Default)]
pub struct Presented {
    pub method: String,
    pub client_id: String,
    pub presented_secret: String,
    pub assertion: String,
    pub assertion_type: String,
    pub audiences: Vec<String>,
    pub strict_audience: String,
    pub issuer: String,
    pub peer: Option<PeerCertificate>,
}

/// A refusal: `{ ok: false, errorCode, description }`.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthRefusal {
    pub code: ErrorCode,
    pub description: String,
    /// An OAuth error other than `invalid_client`, where one is named.
    pub error: String,
    /// A status other than 401, where one is named.
    pub status: u16,
}

/// What a verified credential says.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Accepted {
    pub method: String,
    pub alg: String,
    pub jti: String,
    pub secret_id: String,
    pub previous_secret: bool,
    pub subject: String,
    pub mapping: String,
    pub thumbprint: String,
}

pub type Verdict = Result<Accepted, AuthRefusal>;

fn refusal(code: ErrorCode, description: impl Into<String>) -> AuthRefusal {
    AuthRefusal {
        code,
        description: description.into(),
        error: String::new(),
        status: 0,
    }
}

/// The per-request memo of `verifiedOnce()`.
#[derive(Default)]
pub struct Verified(Mutex<HashMap<String, Verdict>>);

impl Verified {
    fn get_or(&self, parts: &[&str], run: impl FnOnce() -> Verdict) -> Verdict {
        let key = parts.join("\n");
        if let Some(held) = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
        {
            return held.clone();
        }
        let answer = run();
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key, answer.clone());
        answer
    }
}

/// `Date.now()` and its seconds: a clock a vector can pin.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> i64;
    fn now_s(&self) -> i64 {
        self.now_ms().div_euclid(1000)
    }
}

/// The system's clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as i64)
    }
}

/// A registered key, read from a JWKS (`assertionGrant.keysFrom()`).
#[derive(Clone)]
pub struct RegisteredKey {
    pub kid: String,
    pub jwk: Json,
    pub key: JwsKey,
}

/// `keysFrom()`: the keys a registered JWKS holds, or why none could be
/// read.
#[tracing::instrument(level = "debug", skip_all)]
pub fn keys_from(jwks_text: &str) -> Result<Vec<RegisteredKey>, AuthRefusal> {
    let document: Json = match serde_json::from_str(jwks_text) {
        Ok(d) => d,
        Err(e) => {
            return Err(refusal(
                codes::STS_OAUTH_0026,
                format!(
                    "the JWKS registered for this party is not valid JSON: {}",
                    crate::js::json_parse_message(jwks_text, &e)
                ),
            ))
        }
    };
    let jwks = document
        .get("keys")
        .and_then(Json::as_array)
        .cloned()
        .unwrap_or_default();
    if jwks.is_empty() {
        return Err(refusal(
            codes::STS_OAUTH_0027,
            "the JWKS registered for this party contains no keys",
        ));
    }
    let mut out = Vec::new();
    for jwk in jwks {
        let kid = text(jwk.get("kid"));
        match JwsKey::from_jwk(&jwk) {
            Ok(key) => out.push(RegisteredKey { kid, jwk, key }),
            Err(e) => tracing::warn!(
                "assertion_grant: a key in a registered JWKS could not be \
                 read and is ignored ({}): {}",
                if kid.is_empty() {
                    "no kid".to_string()
                } else {
                    format!("kid={}", kid)
                },
                e
            ),
        }
    }
    if out.is_empty() {
        return Err(refusal(
            codes::STS_OAUTH_0028,
            "none of the keys in the JWKS registered for this party could be \
             read",
        ));
    }
    Ok(out)
}

/// The parts of RFC 7523 that read beyond this slice: an encrypted
/// assertion, an `x5c` header, a `jwks_uri`, and a registered key's own
/// certificate. The defaults answer as Node does when none of them is in
/// play — an assertion of five parts is refused, since no unwrap is wired.
pub trait AssertionKeys: Send + Sync {
    /// `assertionGrant.unwrapAssertion()`: the JWS inside a JWE.
    fn unwrap(
        &self,
        compact: &str,
        _secret: &str,
    ) -> Result<String, AuthRefusal> {
        if compact.trim().split('.').count() == 5 {
            return Err(refusal(
                codes::STS_OAUTH_0029,
                "this assertion has five parts, so it is an encrypted JWT \
                 (RFC 7523 section 3, claim 10) — and this runtime does not \
                 open one yet.",
            ));
        }
        Ok(compact.trim().to_string())
    }
    /// The keys a `jwks_uri` names (`ensurePartyKeys()`), and why a fetch
    /// failed.
    fn jwks_uri_keys(
        &self,
        _uri: &str,
        _kid: &str,
    ) -> (Vec<RegisteredKey>, String) {
        (Vec::new(), "no fetch is wired".to_string())
    }
    /// A registered key's certificate chain and revocation, refused.
    fn registered_key_refusal(
        &self,
        _key: &RegisteredKey,
        _client_id: &str,
    ) -> Option<AuthRefusal> {
        None
    }
}

/// The defaults.
pub struct NoAssertionKeys;
impl AssertionKeys for NoAssertionKeys {}

/// `client_auth.js`, over the settings, the mode and its ports.
pub struct ClientAuth {
    settings: Arc<Settings>,
    mode: Arc<Mode>,
    history: Arc<dyn AssertionHistory>,
    keys: Arc<dyn AssertionKeys>,
    clock: Arc<dyn Clock>,
}

impl ClientAuth {
    /// `clientAuth.assertionsRemembered()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn assertions_remembered(&self) -> usize {
        self.history.live(self.clock.now_ms())
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(
        settings: Arc<Settings>,
        mode: Arc<Mode>,
        history: Arc<dyn AssertionHistory>,
        keys: Arc<dyn AssertionKeys>,
        clock: Arc<dyn Clock>,
    ) -> ClientAuth {
        ClientAuth {
            settings,
            mode,
            history,
            keys,
            clock,
        }
    }

    fn skew(&self) -> i64 {
        self.settings
            .value_of("oauth2.clientAssertionSkewS")
            .as_int()
    }

    /// `assertionLifetimeCap()`: `oauth2.jwtBearerMaxLifetimeS` where
    /// credentials are verified, else none.
    fn lifetime_cap(&self) -> i64 {
        if !self.mode.verifies_credentials() {
            return 0;
        }
        self.settings
            .value_of("oauth2.jwtBearerMaxLifetimeS")
            .as_int()
            .max(0)
    }

    /// `methodFor()`: which declared method this request is using.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn method_for(registered: &Json, presented: &MethodHints) -> String {
        let declared = declared_methods_of(registered);
        if declared.len() < 2 {
            return declared.into_iter().next().unwrap_or_default();
        }
        let mut wanted: Vec<&str> = Vec::new();
        if !presented.assertion.is_empty()
            && presented.assertion_type == SAML_ASSERTION_TYPE
        {
            wanted.push("saml2_bearer");
        } else if !presented.assertion.is_empty()
            && presented.assertion_type == ASSERTION_TYPE
        {
            let alg = crate::js::header_member(&presented.assertion, "alg");
            if alg.len() >= 2 && alg[..2].eq_ignore_ascii_case("HS") {
                wanted.extend(["client_secret_jwt", "private_key_jwt"]);
            } else {
                wanted.extend(["private_key_jwt", "client_secret_jwt"]);
            }
        } else if presented.attestation {
            if presented.attestation_pop {
                wanted.extend([
                    "attest_jwt_client_auth",
                    "attest_jwt_client_auth_dpop",
                ]);
            } else {
                wanted.extend([
                    "attest_jwt_client_auth_dpop",
                    "attest_jwt_client_auth",
                ]);
            }
        } else if !presented.client_secret.is_empty() {
            if presented.basic {
                wanted.extend(["client_secret_basic", "client_secret_post"]);
            } else {
                wanted.extend(["client_secret_post", "client_secret_basic"]);
            }
        } else if let Some(self_issued) = presented.certificate_self_issued {
            if self_issued {
                wanted
                    .extend(["self_signed_tls_client_auth", "tls_client_auth"]);
            } else {
                wanted
                    .extend(["tls_client_auth", "self_signed_tls_client_auth"]);
            }
        }
        wanted
            .into_iter()
            .find(|one| declared.iter().any(|d| d == one))
            .map(str::to_string)
            .unwrap_or_else(|| declared[0].clone())
    }

    /// `verify()`: the credential the method asks for, checked.
    #[tracing::instrument(level = "debug", skip_all, fields(method = %ask.method))]
    pub fn verify(
        &self,
        ask: &Presented,
        registered: &Json,
        memo: &Verified,
    ) -> Verdict {
        let method = ask.method.as_str();
        let declared = declared_methods_of(registered);
        match method {
            "client_secret_basic" | "client_secret_post" => {
                self.verify_secret(ask, registered, &declared)
            }
            "client_secret_jwt" | "private_key_jwt" => {
                if ask.assertion.is_empty() {
                    return Err(refusal(
                        codes::STS_OAUTH_0021,
                        format!(
                            "this client authenticates with {}, so the \
                             request must carry client_assertion and \
                             client_assertion_type={}.",
                            method, ASSERTION_TYPE
                        ),
                    ));
                }
                if ask.assertion_type != ASSERTION_TYPE {
                    return Err(refusal(
                        codes::STS_OAUTH_0022,
                        format!(
                            "client_assertion_type must be \"{}\" (RFC 7523 \
                             section 2.2). {}",
                            ASSERTION_TYPE,
                            if ask.assertion_type.is_empty() {
                                "This request names none.".to_string()
                            } else {
                                format!(
                                    "This request says \"{}\".",
                                    ask.assertion_type
                                )
                            }
                        ),
                    ));
                }
                let audiences = ask.audiences.join(" ");
                memo.get_or(
                    &[
                        method,
                        &ask.client_id,
                        &ask.assertion_type,
                        &ask.assertion,
                        &ask.strict_audience,
                        &audiences,
                    ],
                    || self.verify_assertion(ask, registered),
                )
            }
            "tls_client_auth" | "self_signed_tls_client_auth" => {
                self.verify_certificate(ask, registered)
            }
            "saml2_bearer"
            | "attest_jwt_client_auth"
            | "attest_jwt_client_auth_dpop" => Err(refusal(
                codes::STS_OAUTH_0025,
                format!(
                    "this client's entry says token_endpoint_auth_method=\"{}\", \
                     which this runtime does not verify yet.",
                    method
                ),
            )),
            _ => {
                let all = methods();
                Err(refusal(
                    codes::STS_OAUTH_0025,
                    format!(
                        "this client's entry says \
                         token_endpoint_auth_method=\"{}\", which this server \
                         cannot verify. The {} it can are: {}.",
                        method,
                        all.len(),
                        all.join(", ")
                    ),
                ))
            }
        }
    }

    fn verify_secret(
        &self,
        ask: &Presented,
        registered: &Json,
        declared: &[String],
    ) -> Verdict {
        if ask.presented_secret.is_empty() {
            return Err(refusal(
                codes::STS_OAUTH_0019,
                format!(
                    "no client_secret was presented. {}",
                    presentation_sentence(declared, &ask.method)
                ),
            ));
        }
        let secrets = secrets_of(registered);
        let index = secrets.iter().position(|one| {
            sts_crypto::secrets::constant_time_equals(
                ask.presented_secret.as_bytes(),
                one.secret.as_bytes(),
            )
        });
        let Some(index) = index else {
            return Err(refusal(
                codes::STS_OAUTH_0020,
                "the client_secret presented is not one of the secrets on \
                 this client's entry in the application registry.",
            ));
        };
        let matched = &secrets[index];
        if matched.expires_at > 0 && self.clock.now_s() >= matched.expires_at {
            let when = crate::js::iso_instant(matched.expires_at * 1000);
            if self.mode.refuses_expired_client_secrets() || index > 0 {
                return Err(refusal(
                    codes::STS_OAUTH_0558,
                    format!(
                        "the client_secret presented expired at {}; ask this \
                         service's administrator for a new one, or rotate it \
                         through RFC 7592 client registration management.",
                        when
                    ),
                ));
            }
            tracing::warn!(
                "{}client_auth: a client_secret of \"{}\" expired at {} and \
                 was ACCEPTED, because this is a development-mode service \
                 (mode.refusesExpiredClientSecrets()).",
                sts_core::log::tag(codes::STS_OAUTH_0559),
                ask.client_id,
                when
            );
        }
        Ok(Accepted {
            method: ask.method.clone(),
            secret_id: matched.id.clone(),
            previous_secret: secrets.len() > 1 && index > 0,
            ..Accepted::default()
        })
    }

    /// `verifyAssertion()`: RFC 7523 section 3.
    fn verify_assertion(&self, ask: &Presented, registered: &Json) -> Verdict {
        let client_id = ask.client_id.as_str();
        let client_secret = text(registered.get("client_secret"));
        let assertion = self.keys.unwrap(&ask.assertion, &client_secret)?;
        let header = match crate::js::segment_json(&assertion, 0) {
            Ok(h) => h,
            Err(message) => {
                return Err(refusal(
                    codes::STS_OAUTH_0001,
                    format!("client_assertion is not a JWT: {}", message),
                ))
            }
        };
        let alg = text(header.get("alg"));
        let kid = text(header.get("kid"));
        let entries: Vec<RegisteredKey> = if ask.method == "client_secret_jwt" {
            if !matches!(alg.as_str(), "HS256" | "HS384" | "HS512") {
                return Err(refusal(
                    codes::STS_OAUTH_0002,
                    format!(
                        "client_secret_jwt signs with an HMAC over the \
                         client_secret, so alg must be HS256, HS384 or \
                         HS512. This assertion says \"{}\".",
                        alg
                    ),
                ));
            }
            let now = self.clock.now_s();
            let refuses = self.mode.refuses_expired_client_secrets();
            let usable: Vec<RegisteredKey> = secrets_of(registered)
                .into_iter()
                .enumerate()
                .filter(|(i, one)| {
                    !(one.expires_at > 0
                        && one.expires_at <= now
                        && (refuses || *i > 0))
                })
                .map(|(_, one)| RegisteredKey {
                    kid: String::new(),
                    jwk: Json::Null,
                    key: JwsKey::secret(one.secret.into_bytes()),
                })
                .collect();
            if usable.is_empty() {
                return Err(refusal(
                    codes::STS_OAUTH_0003,
                    "this client has no usable client_secret on its entry, so \
                     there is nothing to verify a client_secret_jwt \
                     assertion with.",
                ));
            }
            usable
        } else {
            if alg.starts_with("HS") || alg == "none" {
                return Err(refusal(
                    codes::STS_OAUTH_0004,
                    format!(
                        "private_key_jwt is asymmetric, so alg must be an \
                         asymmetric one (RS256, PS256, ES256 and so on). This \
                         assertion says \"{}\", which would have this server \
                         verify a signature with a PUBLIC key used as an HMAC \
                         secret — a forgery anybody could produce, since the \
                         key is public.",
                        alg
                    ),
                ));
            }
            let mut found: Vec<RegisteredKey> = Vec::new();
            let mut reading: Option<AuthRefusal> = None;
            for member in ["jwks", "assertion_jwks"] {
                let raw = registered.get(member);
                let jwks_text = match raw {
                    Some(Json::String(s)) if !s.is_empty() => s.clone(),
                    Some(Json::Object(_)) => {
                        raw.map(Json::to_string).unwrap_or_default()
                    }
                    _ => continue,
                };
                match keys_from(&jwks_text) {
                    Ok(keys) => found.extend(keys),
                    Err(e) => reading = Some(e),
                }
            }
            let jwks_uri = text(registered.get("jwks_uri"));
            let has_jwks = !text(registered.get("jwks")).is_empty();
            let mut fetched_why = String::new();
            if !has_jwks && !jwks_uri.is_empty() {
                let (keys, why) = self.keys.jwks_uri_keys(&jwks_uri, &kid);
                fetched_why = why;
                found.extend(keys);
            }
            if found.is_empty() && !jwks_uri.is_empty() {
                return Err(refusal(
                    codes::STS_OAUTH_0005,
                    format!(
                        "this client registered a jwks_uri and its keys could \
                         not be fetched{}.",
                        if fetched_why.is_empty() {
                            String::new()
                        } else {
                            format!(": {}", fetched_why)
                        }
                    ),
                ));
            }
            if found.is_empty() {
                if let Some(mut problem) = reading {
                    problem.description.push('.');
                    return Err(problem);
                }
                return Err(refusal(
                    codes::STS_OAUTH_0006,
                    "this client registered no keys, so a private_key_jwt \
                     assertion cannot be verified. Register a `jwks` — by \
                     value — on its entry, or have this service issue it a \
                     signing key pair from /admin/pki.",
                ));
            }
            let candidates: Vec<RegisteredKey> = if kid.is_empty() {
                found.clone()
            } else {
                found.iter().filter(|one| one.kid == kid).cloned().collect()
            };
            if candidates.is_empty() {
                found
            } else {
                candidates
            }
        };
        let policy = KeyPolicy {
            weak_rsa_allowed: false,
            short_hmac_allowed: self.mode.uses_broken_algorithms(),
        };
        let checks = ClaimChecks {
            issuer: (!client_id.is_empty()).then(|| client_id.to_string()),
            audience: ask.audiences.clone(),
            clock_tolerance: self.skew(),
            now: Some(self.clock.now_s()),
        };
        let algs = [alg.as_str()];
        let mut last_error = String::new();
        let mut verified: Option<(Json, RegisteredKey)> = None;
        for entry in &entries {
            match verify_jws(
                &assertion,
                &entry.key,
                Some(&algs),
                &checks,
                policy,
            ) {
                Ok(claims) => {
                    verified = Some((claims, entry.clone()));
                    break;
                }
                // `verifyJwsAsync()` says `invalid signature` where the
                // bytes do not verify; its other messages are the same.
                Err(e) => last_error = jwt_error_text(&e),
            }
        }
        let Some((claims, used)) = verified else {
            return Err(refusal(
                codes::STS_OAUTH_0007,
                format!(
                    "the client_assertion did not verify: {}. It must be \
                     signed by a key this client registered, name this client \
                     as both `iss` and `sub`, name one of {} as `aud`, and be \
                     unexpired.",
                    last_error,
                    ask.audiences.join(" or ")
                ),
            ));
        };
        if !ask.strict_audience.is_empty() {
            let aud = claims.get("aud").cloned().unwrap_or(Json::Null);
            let named: Vec<Json> = match &aud {
                Json::Array(list) => list.clone(),
                other => vec![other.clone()],
            };
            if named.len() != 1 || text(named.first()) != ask.strict_audience {
                return Err(refusal(
                    codes::STS_OAUTH_0283,
                    format!(
                        "the client_assertion must name this authorization \
                         server's issuer identifier, \"{}\", as its SOLE \
                         audience (OAuth 2.1 section 2.4, \
                         draft-ietf-oauth-rfc7523bis-11 section 4) — the \
                         token endpoint URL may not be used — and it names \
                         {}.",
                        ask.strict_audience,
                        crate::js::stringify(&aud)
                    ),
                ));
            }
        }
        if used.jwk.is_object() {
            if let Some(refused) =
                self.keys.registered_key_refusal(&used, client_id)
            {
                return Err(refused);
            }
        }
        let sub = text(claims.get("sub"));
        if sub != client_id {
            return Err(refusal(
                codes::STS_OAUTH_0008,
                format!(
                    "RFC 7523 section 3: a client assertion names the client \
                     as both `iss` and `sub`. {} — an assertion a client made \
                     ABOUT somebody else is not that somebody authenticating.",
                    if sub.is_empty() {
                        format!(
                            "This one names no sub, and the client is \"{}\"",
                            client_id
                        )
                    } else {
                        format!(
                            "This one has sub=\"{}\" where the client is \
                             \"{}\"",
                            sub, client_id
                        )
                    }
                ),
            ));
        }
        let now = self.clock.now_s();
        let exp = claims.get("exp").filter(|v| !v.is_null());
        if exp.is_none() && self.mode.verifies_credentials() {
            return Err(refusal(
                codes::STS_OAUTH_0009,
                "RFC 7523 section 3 claim 4: a client assertion MUST carry an \
                 `exp`. One without it never expires, so it is a credential \
                 anybody who captures it can use for ever.",
            ));
        }
        let cap = self.lifetime_cap();
        if let (true, Some(exp)) = (cap > 0, exp) {
            let from = match claims.get("iat").filter(|v| !v.is_null()) {
                Some(iat) => (crate::js::to_number(iat) as i64).min(now),
                None => now,
            };
            let lifetime = crate::js::to_number(exp) as i64 - from;
            if lifetime > cap + self.skew() {
                return Err(refusal(
                    codes::STS_OAUTH_0010,
                    format!(
                        "this client assertion is valid for {} seconds and \
                         this authorization server accepts at most {} \
                         (oauth2.jwtBearerMaxLifetimeS), measured from `iat` \
                         or, where there is none, from now. Mint a \
                         short-lived assertion per request.",
                        lifetime, cap
                    ),
                ));
            }
        }
        let jti = text(claims.get("jti"));
        if jti.is_empty() {
            return Err(refusal(
                codes::STS_OAUTH_0011,
                "RFC 7523 section 3: a client assertion must carry a `jti`, \
                 so that this server can refuse a replay of it.",
            ));
        }
        let remembered = match exp {
            Some(exp) => (crate::js::to_number(exp) * 1000.0) as i64,
            None => {
                let s = self
                    .settings
                    .value_of("oauth2.jwtBearerMaxLifetimeS")
                    .as_int();
                self.clock.now_ms() + if s > 0 { s } else { 300 } * 1000
            }
        };
        let spent = self.history.claim(&AssertionClaim {
            issuer: client_id.to_string(),
            identifier: jti.clone(),
            client_id: client_id.to_string(),
            expires_at: remembered + self.skew() * 1000,
        });
        match spent {
            Spent::Ok => Ok(Accepted {
                method: ask.method.clone(),
                alg,
                jti,
                ..Accepted::default()
            }),
            Spent::Replay(used_as) => Err(refusal(
                codes::STS_OAUTH_0012,
                format!(
                    "this client_assertion has been used already{}. Its `jti` \
                     is remembered until the assertion expires, because a \
                     signed assertion captured off the wire is a credential \
                     until then. Mint a fresh one per request.",
                    used_as
                ),
            )),
            Spent::Full(_) => Err(refusal(
                codes::STS_OAUTH_0013,
                "this authorization server is holding as many unexpired \
                 client assertions as it is configured to remember \
                 (oauth2.assertionReplayCacheSize), and it will not forget \
                 one that could still be replayed in order to accept yours. \
                 Retry shortly, with a short-lived assertion.",
            )),
            Spent::Failed => Err(refusal(
                codes::STS_OAUTH_0243,
                "this client assertion verified, and this authorization \
                 server could not record that it has been used, so it is \
                 refused rather than accepted unrecorded. Retry with a fresh \
                 assertion.",
            )),
        }
    }

    /// `verifyCertificate()`: RFC 8705 section 2.
    fn verify_certificate(
        &self,
        ask: &Presented,
        registered: &Json,
    ) -> Verdict {
        let Some(cert) = &ask.peer else {
            return Err(refusal(
                codes::STS_OAUTH_0014,
                "RFC 8705 section 2: this client authenticates with its TLS \
                 client certificate, and this request arrived with none. The \
                 token endpoint has to be reached over a TLS connection that \
                 asked for one — set global.https, which RFC 9700 mode does \
                 by default.",
            ));
        };
        if let Some((code, policy, why)) = &cert.revocation_refused {
            return Err(refusal(
                *code,
                format!(
                    "RFC 8705 section 2: the client certificate on this \
                     connection was refused on revocation \
                     (pki.revocationCheck is {}). {}",
                    policy, why
                ),
            ));
        }
        let presented = cert.thumbprint();
        if ask.method == "self_signed_tls_client_auth" {
            let registered_tp = text(registered.get("certificate_thumbprint"));
            let in_jwks = registered_certificates_of(registered);
            if registered_tp.is_empty() && in_jwks.is_empty() {
                return Err(refusal(
                    codes::STS_OAUTH_0015,
                    "this client authenticates with a self-signed \
                     certificate (RFC 8705 section 2.2) and has none \
                     registered: no key in its jwks carries an x5c (section \
                     2.2.2), and there is no \
                     oauthTlsClientCertificateThumbprint on its entry.",
                ));
            }
            let by_thumbprint =
                !registered_tp.is_empty() && presented == registered_tp;
            let by_jwks = in_jwks.contains(&cert.der);
            if !by_thumbprint && !by_jwks {
                return Err(refusal(
                    codes::STS_OAUTH_0016,
                    format!(
                        "RFC 8705 section 2.2: this connection was made with \
                         the certificate whose SHA-256 thumbprint is {}, and \
                         it is neither the x5c of a key in this client's \
                         jwks ({} registered) nor {}.",
                        presented,
                        in_jwks.len(),
                        if registered_tp.is_empty() {
                            "a registered thumbprint".to_string()
                        } else {
                            format!(
                                "the registered thumbprint {}",
                                registered_tp
                            )
                        }
                    ),
                ));
            }
            if let Some((code, why)) = &cert.pinned_refusal {
                return Err(refusal(
                    *code,
                    format!(
                        "RFC 8705 section 2.2: the registered certificate is \
                         refused: {}.",
                        why
                    ),
                ));
            }
            return Ok(Accepted {
                method: ask.method.clone(),
                subject: cert.subject.clone(),
                thumbprint: presented,
                mapping: if by_jwks { "jwks" } else { "thumbprint" }.into(),
                ..Accepted::default()
            });
        }
        let issued = cert.issued.clone().unwrap_or_default();
        if !cert.verified && issued.issued_here {
            return Err(refusal(
                codes::STS_OAUTH_0481,
                format!(
                    "RFC 8705 section 2.1: the client certificate chains to \
                     this service's own Root and is not a TLS client \
                     identity in this realm: {}. Issue this application a \
                     TLS client certificate from its Credentials section.",
                    if issued.why.is_empty() {
                        &cert.error
                    } else {
                        &issued.why
                    }
                ),
            ));
        }
        if !cert.verified {
            return Err(refusal(
                codes::STS_OAUTH_0480,
                format!(
                    "RFC 8705 section 2.1: tls_client_auth authenticates a \
                     certificate whose chain is validated against a trust \
                     anchor, and this one did not verify{}. Install the \
                     issuing authority's root at /admin/tls/trust, send the \
                     intermediates with the certificate, or register the \
                     client for self_signed_tls_client_auth instead.",
                    if cert.error.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", cert.error)
                    }
                ),
            ));
        }
        let members = registered_subjects(registered);
        if members.len() > 1 {
            let names: Vec<&str> =
                members.iter().map(|(n, _)| n.as_str()).collect();
            return Err(refusal(
                codes::STS_OAUTH_0482,
                format!(
                    "RFC 8705 section 2.1.2: this client's entry registers {} \
                     certificate subject parameters ({}) where a client uses \
                     exactly one, so there is no single subject to expect. \
                     Clear all but one.",
                    members.len(),
                    names.join(", ")
                ),
            ));
        }
        if issued.issued_here && issued.accepted {
            let app = text(registered.get("identifier"));
            let mine = issued.kind == "application"
                && (issued.username == app || issued.username == ask.client_id);
            if !mine {
                return Err(refusal(
                    codes::STS_OAUTH_0484,
                    format!(
                        "RFC 8705 section 2.1: the client certificate was \
                         issued by this realm to the {} \"{}\", and a \
                         certificate this service issued as somebody's \
                         identity authenticates that holder and nobody else — \
                         whatever subject this client registered (section \
                         7.4).",
                        issued.kind, issued.username
                    ),
                ));
            }
            if !issued.held {
                return Err(refusal(
                    codes::STS_OAUTH_0483,
                    format!(
                        "RFC 8705 section 2.1: the client certificate was \
                         issued to this application (serial {}), and its \
                         record no longer lists it — it was taken off or \
                         replaced. A certificate the application's record \
                         does not hold is not its credential.",
                        issued.serial_hex
                    ),
                ));
            }
            return Ok(Accepted {
                method: ask.method.clone(),
                subject: cert.subject.clone(),
                thumbprint: presented,
                mapping: "implicit".into(),
                ..Accepted::default()
            });
        }
        let Some((member, value)) = members.into_iter().next() else {
            return Err(refusal(
                codes::STS_OAUTH_0486,
                "RFC 8705 section 2.1: the client certificate verified and \
                 was not issued by this realm to this application, and the \
                 client registers no certificate subject to match it against \
                 — one of tls_client_auth_subject_dn, tls_client_auth_san_dns, \
                 _san_uri, _san_ip or _san_email.",
            ));
        };
        let carried = cert
            .subject_values
            .get(&member)
            .cloned()
            .unwrap_or_default();
        if !carried.contains(&value) {
            let label = subject_label(&member);
            return Err(refusal(
                codes::STS_OAUTH_0485,
                format!(
                    "RFC 8705 section 2.1.2: this client registered {} \"{}\" \
                     and the certificate on this connection carries {}.",
                    member,
                    value,
                    if carried.is_empty() {
                        format!("no {}", label)
                    } else {
                        format!(
                            "{} {}",
                            label,
                            carried
                                .iter()
                                .map(|one| format!("\"{}\"", one))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    }
                ),
            ));
        }
        Ok(Accepted {
            method: ask.method.clone(),
            subject: cert.subject.clone(),
            thumbprint: presented,
            mapping: "explicit".into(),
            ..Accepted::default()
        })
    }
}

/// RFC 8705 section 2.1.2's five subject parameters, in
/// `certificate_subject.js`'s order, with the label its sentences use.
pub const SUBJECT_MEMBERS: [(&str, &str); 5] = [
    ("tls_client_auth_subject_dn", "subject DN"),
    ("tls_client_auth_san_dns", "dNSName"),
    ("tls_client_auth_san_uri", "uniformResourceIdentifier"),
    ("tls_client_auth_san_ip", "iPAddress"),
    ("tls_client_auth_san_email", "rfc822Name"),
];

fn subject_label(member: &str) -> &'static str {
    SUBJECT_MEMBERS
        .iter()
        .find(|(m, _)| *m == member)
        .map_or("subject", |(_, l)| l)
}

/// `certificateSubject.registeredOf()`: the subject parameters an entry
/// sets, each with its value.
#[tracing::instrument(level = "debug", skip_all)]
pub fn registered_subjects(registered: &Json) -> Vec<(String, String)> {
    SUBJECT_MEMBERS
        .iter()
        .filter_map(|(member, _)| {
            let value = text(registered.get(*member));
            (!value.trim().is_empty())
                .then(|| (member.to_string(), value.trim().to_string()))
        })
        .collect()
}

/// `registeredCertificatesOf()`: the leaf of each registered key's `x5c`.
fn registered_certificates_of(registered: &Json) -> Vec<Vec<u8>> {
    let jwks_text = text(registered.get("jwks"));
    if jwks_text.is_empty() {
        return Vec::new();
    }
    let Ok(keys) = keys_from(&jwks_text) else {
        return Vec::new();
    };
    keys.iter()
        .filter_map(|one| one.jwk.get("x5c")?.as_array()?.first()?.as_str())
        .filter(|b| !b.is_empty())
        .filter_map(|b| sts_crypto::b64::decode_loose(b).ok())
        .collect()
}

/// What `methodFor()` reads off the request.
#[derive(Debug, Clone, Default)]
pub struct MethodHints {
    pub assertion: String,
    pub assertion_type: String,
    pub client_secret: String,
    pub basic: bool,
    pub attestation: bool,
    pub attestation_pop: bool,
    /// `Some(self_issued)` when the connection carries a certificate.
    pub certificate_self_issued: Option<bool>,
}

/// A verification failure as `crypto.js`'s `verifyJwsAsync()` words it:
/// a signature that does not verify is `invalid signature`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn jwt_error_text(e: &sts_crypto::jws::JwtError) -> String {
    let text = e.to_string();
    if matches!(e, sts_crypto::jws::JwtError::Signature(_))
        && text.starts_with("the ")
        && text.ends_with(" signature does not verify.")
    {
        return "invalid signature".to_string();
    }
    text
}
