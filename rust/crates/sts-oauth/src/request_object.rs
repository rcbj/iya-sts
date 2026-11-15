// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! RFC 9101 JWT-SECURED AUTHORIZATION REQUESTS (`request_object.ts`'s
//! `resolve()`, `verifyObject()`, `verify()` and `parametersFrom()`), with
//! Node's checks in Node's order, its codes and its sentences.
//!
//! * **By value** (`request`): the object is verified with the client's own
//!   keys — its registered `jwks` (and `assertion_jwks`), or its secret for
//!   an HMAC algorithm — against its registered `request_object_signing_alg`;
//!   `alg: none` only where development accepts an unsigned object and none
//!   is required. Its `iss`, `aud`, `client_id`, the nested `request` and
//!   `request_uri` and a duplicated `response_type` are checked as Node
//!   checks them, and its claims become the request's parameters, the
//!   round-trip fields of the outer query kept.
//! * **A pushed reference** (`urn:ietf:params:oauth:request_uri:`) is a key
//!   into [`crate::par`]'s store, never fetched.
//! * **A `jti` is accepted once** (`oauth2.requestObjectJtiOnce`, on by
//!   default), per client.
//!
//! WHAT IS NOT HERE, and what is answered meanwhile: an ENCRYPTED request
//! object (five parts) is refused `invalid_request_object`
//! (`STS-OAUTH-0355`'s code, with a sentence saying this runtime opens none
//! yet), as is a client whose keys are only at a `jwks_uri`; a
//! `request_uri` that is not pushed is refused as unregistered
//! (`STS-OAUTH-0345`) or, when registered, as not fetched
//! (`STS-OAUTH-0346`) — this runtime dials no client's URL yet; the
//! certificate chain and revocation of a key carrying `x5c`, OpenID
//! Federation's proof claims and FAPI's lifetime rules are not asked. The
//! `jti` history is this process's (Node's is the used-assertion store).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Map, Value as Json};
use sts_core::errors::codes;
use sts_core::mode::Mode;
use sts_core::settings::Settings;

use crate::par::{PushedRequests, Refusal, Resolved as PushedResolved};

/// `TYP`.
const TYP: &str = "oauth-authz-req+jwt";

/// `ACCEPTED_TYPES`.
const ACCEPTED_TYPES: [&str; 3] = ["", "jwt", TYP];

/// `JWT_CLAIMS`: never parameters.
const JWT_CLAIMS: [&str; 6] = ["iss", "aud", "exp", "iat", "nbf", "jti"];

/// `ROUND_TRIP_FIELDS`.
pub const ROUND_TRIP_FIELDS: [&str; 5] = [
    "authn_error",
    "authn_error_description",
    "consent_error",
    "consent_error_description",
    "jar_prompt_honoured",
];

fn s(v: Option<&Json>) -> String {
    crate::js::string_of(v)
}

fn refusal(
    code: sts_core::errors::ErrorCode,
    error: &'static str,
    description: String,
) -> Refusal {
    (code, error, description)
}

/// What `verifyObject()` answers: the parameters, the algorithm, and the
/// `jti` it is known by.
pub type Verified = (Map<String, Json>, String, Option<(String, String, i64)>);

/// How an authorization request was secured (`req.stsJar`).
#[derive(Debug, Clone, Default)]
pub struct Jar {
    /// The query as it arrived.
    pub outer: Map<String, Json>,
    /// `request`, `request_uri` or `par`.
    pub source: String,
    pub alg: String,
    /// A pushed request's facts, for spending it.
    pub pushed: Option<Json>,
    /// `(client, jti, expires)` to note at issue.
    pub once: Option<(String, String, i64)>,
}

/// What a resolution answers: the parameters to read, and how they came.
#[derive(Debug, Clone, Default)]
pub struct Resolution {
    pub params: Map<String, Json>,
    pub jar: Jar,
}

/// The verifier.
pub struct RequestObjects {
    pub settings: Arc<Settings>,
    pub mode: Arc<Mode>,
    pub pushed: Arc<PushedRequests>,
    pub now_s: Arc<dyn Fn() -> i64 + Send + Sync>,
    /// The `jti`s accepted, `client jti` → expiry (s).
    pub seen: Mutex<HashMap<String, i64>>,
}

impl RequestObjects {
    /// `signedRequired(client, profile, clientId)`: the setting or the
    /// client's `require_signed_request_object`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn signed_required(&self, client: &Json) -> bool {
        self.settings
            .value_of("oauth2.requireSignedRequestObject")
            .as_bool()
            || client.get("require_signed_request_object")
                == Some(&Json::Bool(true))
    }

    fn skew(&self) -> i64 {
        self.settings
            .value_of("oauth2.clientAssertionSkewS")
            .as_int()
    }

    /// `typProblem(typ, required)`.
    fn typ_problem(typ: Option<&Json>, required: bool) -> String {
        let text = match typ {
            None | Some(Json::Null) => String::new(),
            Some(t) => {
                let lower = s(Some(t)).trim().to_lowercase();
                lower
                    .strip_prefix("application/")
                    .unwrap_or(&lower)
                    .to_string()
            }
        };
        if required && text != TYP {
            return format!(
                "its header is {}, and oauth2.requireRequestObjectType \
                 requires every request object to be explicitly typed \"{}\" \
                 (RFC 9101 section 10.8).",
                if text.is_empty() {
                    "not typed".to_string()
                } else {
                    format!("typed \"{}\"", s(typ))
                },
                TYP
            );
        }
        if typ.is_none_or(Json::is_null)
            || ACCEPTED_TYPES.contains(&text.as_str())
        {
            return String::new();
        }
        format!(
            "its header is typed \"{}\", which is another kind of JWT. A \
             request object is typed \"{}\" (RFC 9101 section 4), or not \
             typed at all; a JWT typed as something else is refused, so that \
             a token issued for another purpose cannot be replayed as an \
             authorization request (section 10.8).",
            s(typ),
            TYP
        )
    }

    /// The claims of an unsigned object, held to `exp` and `nbf`.
    fn unsigned_claims(&self, jws: &str) -> Result<Json, String> {
        let claims = crate::js::segment_json(jws, 1)
            .map_err(|_| "its payload is not a JSON object".to_string())?;
        if !claims.is_object() {
            return Err("its payload is not a JSON object".into());
        }
        let now = (self.now_s)();
        let skew = self.skew();
        if let Some(exp) = claims.get("exp") {
            if crate::js::to_number(exp) + (skew as f64) < now as f64 {
                return Err("jwt expired".into());
            }
        }
        if let Some(nbf) = claims.get("nbf") {
            if crate::js::to_number(nbf) - (skew as f64) > now as f64 {
                return Err("jwt not active".into());
            }
        }
        Ok(claims)
    }

    /// The keys a request object may be verified with.
    fn keys_of(
        &self,
        alg: &str,
        client: &Json,
    ) -> Result<Vec<(String, sts_crypto::keys::JwsKey)>, String> {
        if alg.starts_with("HS") {
            let secret = s(client.get("client_secret"));
            if secret.is_empty() {
                return Err(format!(
                    "it is signed with the HMAC algorithm \"{}\", which is \
                     keyed by the client secret, and this client has none",
                    alg
                ));
            }
            let key = sts_crypto::keys::JwsKey::from_jwk(&json!({
                "kty": "oct",
                "k": sts_crypto::b64::encode(secret.as_bytes()),
            }))
            .map_err(|e| e.to_string())?;
            return Ok(vec![(String::new(), key)]);
        }
        let mut found = Vec::new();
        let mut problems: Vec<String> = Vec::new();
        for member in ["jwks", "assertion_jwks"] {
            let text = match client.get(member) {
                Some(Json::String(t)) if !t.is_empty() => t.clone(),
                Some(o @ Json::Object(_)) => o.to_string(),
                _ => continue,
            };
            match crate::client_auth::keys_from(&text) {
                Ok(keys) => {
                    found.extend(keys.into_iter().map(|k| (k.kid, k.key)))
                }
                Err(e) => problems.push(e.description),
            }
        }
        if found.is_empty() {
            let uri = s(client.get("jwks_uri"));
            return Err(format!(
                "this client holds no key a request object could be verified \
                 with{}{}",
                if problems.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", problems.join("; "))
                },
                if uri.is_empty() {
                    ". Register its public keys as `jwks`, or issue it a key \
                     pair from /admin/pki"
                        .to_string()
                } else {
                    " — the keys at its jwks_uri could not be fetched: this \
                     runtime does not fetch a client's jwks_uri for a request \
                     object yet"
                        .to_string()
                }
            ));
        }
        Ok(found)
    }

    /// `verify(jws, client, clientId, profile, required)`: the claims and
    /// the algorithm.
    fn verify(
        &self,
        jws: &str,
        client: &Json,
        client_id: &str,
        required: bool,
    ) -> Result<(Json, String), Refusal> {
        let header = crate::js::segment_json(jws, 0).map_err(|e| {
            refusal(
                codes::STS_OAUTH_0355,
                "invalid_request_object",
                format!("the request object is not a JWT: {}", e),
            )
        })?;
        let type_required = self
            .settings
            .value_of("oauth2.requireRequestObjectType")
            .as_bool();
        let typ = Self::typ_problem(header.get("typ"), type_required);
        if !typ.is_empty() {
            let lower = s(header.get("typ")).trim().to_lowercase();
            let bare = lower.strip_prefix("application/").unwrap_or(&lower);
            return Err(refusal(
                if type_required && ACCEPTED_TYPES.contains(&bare) {
                    codes::STS_OAUTH_0368
                } else {
                    codes::STS_OAUTH_0356
                },
                "invalid_request_object",
                format!("the request object is refused: {}", typ),
            ));
        }
        let alg = s(header.get("alg"));
        if alg == "none"
            && (!self.mode.accepts_unsigned_request_objects() || required)
        {
            return Err(refusal(
                codes::STS_OAUTH_0357,
                "invalid_request_object",
                format!(
                    "the request object is unsigned (alg \"none\"), and {}.",
                    if required {
                        "a signed request object is required here — by oauth2.requireSignedRequestObject, this client's require_signed_request_object or this authorization server's metadata (RFC 9101 section 10.5)"
                    } else {
                        "this realm is in product mode, where RFC 9101 section 4's signed request object is required"
                    }
                ),
            ));
        }
        let registered_alg = s(client.get("request_object_signing_alg"));
        if !registered_alg.is_empty() && alg != registered_alg {
            return Err(refusal(codes::STS_OAUTH_0358, "invalid_request_object", format!(
                "the request object is signed \"{}\", and this client registered request_object_signing_alg \"{}\" — every request object from it must use that algorithm.",
                alg, registered_alg)));
        }
        if alg == "none" {
            return match self.unsigned_claims(jws) {
                Ok(claims) => {
                    tracing::info!(
                        "request_object: an UNSIGNED request object from \
                         \"{}\" was accepted, which development mode allows \
                         (OpenID Connect Core section 6.1) and product mode \
                         refuses.",
                        client_id
                    );
                    Ok((claims, alg))
                }
                Err(e) => Err(refusal(
                    codes::STS_OAUTH_0364,
                    "invalid_request_object",
                    format!(
                        "the unsigned request object is refused: {}.",
                        e.trim_end_matches('.')
                    ),
                )),
            };
        }
        if sts_crypto::jws_alg::JwsAlg::by_name(&alg).is_none() {
            return Err(refusal(codes::STS_OAUTH_0360, "invalid_request_object", format!(
                "the request object names the algorithm \"{}\", which this service does not verify. It verifies {}.",
                alg, sts_crypto::jws_alg::signing_algs().join(", "))));
        }
        let candidates = self.keys_of(&alg, client).map_err(|why| {
            refusal(
                codes::STS_OAUTH_0361,
                "invalid_request_object",
                format!("the request object cannot be verified: {}.", why),
            )
        })?;
        let kid = s(header.get("kid"));
        let attempts: Vec<&(String, sts_crypto::keys::JwsKey)> = if !kid
            .is_empty()
            && !alg.starts_with("HS")
        {
            let named: Vec<_> =
                candidates.iter().filter(|(k, _)| *k == kid).collect();
            if named.is_empty() {
                return Err(refusal(codes::STS_OAUTH_0370, "invalid_request_object", format!(
                        "the request object names the key \"{}\", which is not one of this client's keys ({}). RFC 9101 section 6.2: the key a kid identifies MUST be the key used and MUST be associated with the client.",
                        kid,
                        candidates.iter().map(|(k, _)| format!("\"{}\"", if k.is_empty() { "(no kid)" } else { k })).collect::<Vec<_>>().join(", "))));
            }
            named
        } else {
            candidates.iter().collect()
        };
        let mut last = String::new();
        for (_, key) in attempts {
            let algs = [alg.as_str()];
            let checked = sts_crypto::jws::verify_compact(
                jws,
                key,
                &sts_crypto::jws::VerifyOptions {
                    algorithms: &algs,
                    empty_payload: false,
                    policy: sts_crypto::keys::KeyPolicy::LENIENT,
                },
            );
            match checked {
                Ok(v) => {
                    let claims = v.claims.unwrap_or(Json::Null);
                    let times = sts_crypto::jws::check_claims(
                        &claims,
                        &sts_crypto::jws::ClaimChecks {
                            clock_tolerance: self.skew(),
                            now: Some((self.now_s)()),
                            ..sts_crypto::jws::ClaimChecks::default()
                        },
                    );
                    match times {
                        Ok(()) => return Ok((claims, alg)),
                        Err(e) => last = e.to_string(),
                    }
                }
                Err(e) => last = e.to_string(),
            }
        }
        Err(refusal(
            codes::STS_OAUTH_0362,
            "invalid_request_object",
            format!(
                "the request object did not verify with any key this client \
                 holds: {}.",
                last
            ),
        ))
    }

    /// `verifyObject(opts)`: the parameters the object verified to, the
    /// algorithm, and what its `jti` is known by.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn verify_object(
        &self,
        compact: &str,
        client: &Json,
        client_id: &str,
        query: &Map<String, Json>,
        issuer: &str,
        as_base: &str,
    ) -> Result<Verified, Refusal> {
        let required = self.signed_required(client);
        let compact = compact.trim();
        let parts = compact.split('.').count();
        if parts == 5 {
            return Err(refusal(
                codes::STS_OAUTH_0355,
                "invalid_request_object",
                "the request object is an encrypted JWT (five parts), and \
                 this authorization server does not yet decrypt one: send it \
                 signed and unencrypted."
                    .into(),
            ));
        }
        if parts != 3 {
            return Err(refusal(codes::STS_OAUTH_0355, "invalid_request_object", format!(
                "the request object is not a compact JWT: it has {} part(s), where a JWS has three and a JWE five.",
                parts)));
        }
        let enc_alg = s(client.get("request_object_encryption_alg"));
        if !enc_alg.is_empty() {
            return Err(refusal(codes::STS_OAUTH_0350, "invalid_request_object", format!(
                "the request object is not encrypted, and this client registered request_object_encryption_alg \"{}\" — every request object from it must be encrypted.",
                enc_alg)));
        }
        let (claims, alg) =
            self.verify(compact, client, client_id, required)?;
        let has = |n: &str| claims.get(n).is_some_and(|v| !v.is_null());
        if self
            .settings
            .value_of("oauth2.requireRequestObjectIssuerAudience")
            .as_bool()
            && (!has("iss") || !has("aud"))
        {
            let missing: Vec<&str> = [
                if has("iss") { "" } else { "`iss`" },
                if has("aud") { "" } else { "`aud`" },
            ]
            .into_iter()
            .filter(|m| !m.is_empty())
            .collect();
            return Err(refusal(codes::STS_OAUTH_0369, "invalid_request_object", format!(
                "the request object carries no {}, and oauth2.requireRequestObjectIssuerAudience requires both (RFC 9101 section 4: a signed request object SHOULD contain them).",
                missing.join(" and no "))));
        }
        if has("iss") && s(claims.get("iss")) != client_id {
            return Err(refusal(codes::STS_OAUTH_0365, "invalid_request_object", format!(
                "the request object's `iss` is \"{}\", and the client is \"{}\". A request object is issued by the client that sends it.",
                s(claims.get("iss")), client_id)));
        }
        if has("aud") {
            let auds: Vec<String> = match &claims["aud"] {
                Json::Array(l) => l.iter().map(|a| s(Some(a))).collect(),
                one => vec![s(Some(one))],
            };
            let accepted =
                [issuer.to_string(), format!("{}/oauth2/authorize", as_base)];
            if !auds.iter().any(|a| accepted.contains(a)) {
                return Err(refusal(codes::STS_OAUTH_0366, "invalid_request_object", format!(
                    "the request object's `aud` is {}, and it is addressed to this authorization server by its issuer identifier \"{}\" (RFC 9101 section 4) or its authorization endpoint.",
                    crate::js::stringify(&claims["aud"]), issuer)));
            }
        }
        if has("client_id") && s(claims.get("client_id")) != client_id {
            return Err(refusal(codes::STS_OAUTH_0367, "invalid_request_object", format!(
                "the request object's `client_id` is \"{}\" and the query parameter is \"{}\". RFC 9101 section 6.3 says the two MUST be identical.",
                s(claims.get("client_id")), client_id)));
        }
        let nested: Vec<&str> = ["request", "request_uri"]
            .into_iter()
            .filter(|n| claims.get(*n).is_some())
            .collect();
        if !nested.is_empty() {
            return Err(refusal(codes::STS_OAUTH_0676, "invalid_request_object", format!(
                "the request object carries {} as a claim. RFC 9101 section 4: the request and request_uri parameters MUST NOT be included in a request object.",
                nested.iter().map(|n| format!("`{}`", n)).collect::<Vec<_>>().join(" and "))));
        }
        if query.contains_key("response_type")
            && claims.get("response_type").is_some()
            && s(query.get("response_type")) != s(claims.get("response_type"))
        {
            return Err(refusal(codes::STS_OAUTH_0371, "invalid_request_object", format!(
                "the query says response_type \"{}\" and the request object says \"{}\". A client may duplicate a parameter in the query for backward compatibility (RFC 9101 section 5), and OpenID Connect Core section 6.1 says response_type MUST then match.",
                s(query.get("response_type")), s(claims.get("response_type")))));
        }
        let params = Self::parameters_from(&claims, query, client_id);
        let once = self.once_of(&claims, client_id);
        Ok((params, alg, once))
    }

    /// `parametersFrom(claims, outer, clientId)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn parameters_from(
        claims: &Json,
        outer: &Map<String, Json>,
        client_id: &str,
    ) -> Map<String, Json> {
        let mut params = Map::new();
        if let Some(o) = claims.as_object() {
            for (name, value) in o {
                if JWT_CLAIMS.contains(&name.as_str())
                    || name == "request"
                    || name == "request_uri"
                    || value.is_null()
                {
                    continue;
                }
                let v = match value {
                    Json::Array(l) if name == "resource" => Json::Array(
                        l.iter().map(|x| json!(s(Some(x)))).collect(),
                    ),
                    Json::Object(_) | Json::Array(_) => {
                        json!(crate::js::stringify(value))
                    }
                    other => json!(s(Some(other))),
                };
                params.insert(name.clone(), v);
            }
        }
        params.insert("client_id".into(), json!(client_id));
        Self::keep_round_trip(&mut params, outer);
        params
    }

    fn keep_round_trip(
        params: &mut Map<String, Json>,
        outer: &Map<String, Json>,
    ) {
        for name in ROUND_TRIP_FIELDS {
            if let Some(v) = outer.get(name) {
                params.insert(name.into(), v.clone());
            }
        }
        if params.contains_key("jar_prompt_honoured") {
            params.remove("prompt");
        }
    }

    /// `onceOf(claims, clientId)`.
    fn once_of(
        &self,
        claims: &Json,
        client_id: &str,
    ) -> Option<(String, String, i64)> {
        let jti = s(claims.get("jti"));
        if jti.is_empty()
            || !self
                .settings
                .value_of("oauth2.requestObjectJtiOnce")
                .as_bool()
        {
            return None;
        }
        let exp = claims
            .get("exp")
            .map(|e| crate::js::to_number(e) as i64)
            .unwrap_or_else(|| (self.now_s)() + 600);
        Some((client_id.to_string(), jti, exp))
    }

    /// `lookUp(once)`: a `jti` already spent is refused.
    fn look_up(&self, once: &Option<(String, String, i64)>) -> Option<Refusal> {
        let (client, jti, _) = once.as_ref()?;
        // THE SHARED HISTORY, where the door claimed this object on arrival
        // (`usedAssertions.peek()`'s look, answered by that claim): a row
        // another request or process holds is a replay.
        if let Some(Err(crate::used_assertions::NotClaimed::Replay(_))) =
            crate::used_assertions::arrival().and_then(|a| a.look(client, jti))
        {
            tracing::warn!(
                "request_object: client \"{}\" sent a request object \
                 whose jti {} has been used already; it is refused.",
                client,
                json!(jti)
            );
            return Some(refusal(codes::STS_OAUTH_0374, "invalid_request_object", "this request object has been used already. Its `jti` is remembered until the object expires, because a signed request object captured off the wire is a credential for the request inside it until then. Sign a fresh one, with a new `jti`, for each authorization request.".into()));
        }
        let now = (self.now_s)();
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        seen.retain(|_, exp| *exp >= now);
        if seen.contains_key(&format!("{} {}", client, jti)) {
            tracing::warn!(
                "request_object: client \"{}\" sent a request object whose \
                 jti {} has been used already; it is refused.",
                client,
                json!(jti)
            );
            return Some(refusal(codes::STS_OAUTH_0374, "invalid_request_object", "this request object has been used already. Its `jti` is remembered until the object expires, because a signed request object captured off the wire is a credential for the request inside it until then. Sign a fresh one, with a new `jti`, for each authorization request.".into()));
        }
        None
    }

    /// `spend(once)`: the `jti` noted when a response is issued on it.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn spend(&self, once: &(String, String, i64)) {
        // Kept in the shared history: the arrival claim is accepted.
        if let Some(a) = crate::used_assertions::arrival() {
            let _ = a.take(&once.0, &once.1);
        }
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        seen.insert(format!("{} {}", once.0, once.1), once.2);
    }

    /// `resolve(opts)`: `Ok(None)` for a request that is not JWT-secured.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn resolve(
        &self,
        query: &Map<String, Json>,
        client: &Json,
        issuer: &str,
        as_base: &str,
        server: &str,
    ) -> Result<Option<Resolution>, Refusal> {
        let required = self.signed_required(client);
        let by_value = !s(query.get("request")).is_empty();
        let by_reference = !s(query.get("request_uri")).is_empty();
        if !by_value && !by_reference {
            if required {
                let by: Vec<&str> = [
                    if self
                        .settings
                        .value_of("oauth2.requireSignedRequestObject")
                        .as_bool()
                    {
                        "oauth2.requireSignedRequestObject"
                    } else {
                        ""
                    },
                    if client.get("require_signed_request_object")
                        == Some(&Json::Bool(true))
                    {
                        "this client's require_signed_request_object"
                    } else {
                        ""
                    },
                ]
                .into_iter()
                .filter(|b| !b.is_empty())
                .collect();
                return Err(refusal(codes::STS_OAUTH_0340, "invalid_request", format!(
                    "this authorization request carries no request object, and a signed one is required here (RFC 9101 section 10.5) — by {}. Send the parameters in a signed JWT, as `request` or `request_uri`.",
                    by.join(" and "))));
            }
            return Ok(None);
        }
        if by_value && by_reference {
            return Err(refusal(codes::STS_OAUTH_0341, "invalid_request", "this authorization request carries both `request` and `request_uri`. RFC 9101 section 5 sends a request object by value or by reference, not both.".into()));
        }
        if query.get("request").is_some_and(Json::is_array)
            || query.get("request_uri").is_some_and(Json::is_array)
        {
            return Err(refusal(codes::STS_OAUTH_0341, "invalid_request", format!(
                "this authorization request repeats `{}`; there is one request object per request.",
                if by_value { "request" } else { "request_uri" })));
        }
        let client_id = s(query.get("client_id"));
        if client_id.is_empty() {
            return Err(refusal(codes::STS_OAUTH_0344, "invalid_request", format!(
                "this authorization request carries a request object and no `client_id` query parameter. RFC 9101 section 5 requires it: it is what says whose keys verify the object{}, and reading it out of an object nobody has verified yet would choose the verifier from the document being verified.",
                if by_reference { " and whose registered request_uris may be fetched" } else { "" })));
        }
        let uri = s(query.get("request_uri"));
        let compact = if by_value {
            s(query.get("request"))
        } else if uri.starts_with(crate::par::REQUEST_URI_PREFIX) {
            let PushedResolved {
                params,
                alg,
                pushed,
                ..
            } = self.pushed.resolve(&uri, &client_id, server)?;
            let mut params = params;
            params.insert("client_id".into(), json!(client_id));
            Self::keep_round_trip(&mut params, query);
            return Ok(Some(Resolution {
                params,
                jar: Jar {
                    outer: query.clone(),
                    source: "par".into(),
                    alg,
                    pushed: Some(pushed),
                    once: None,
                },
            }));
        } else {
            let wanted = uri.split('#').next().unwrap_or("").to_string();
            let registered = client
                .get("request_uris")
                .and_then(Json::as_array)
                .map(|l| {
                    l.iter().any(|r| {
                        s(Some(r)).split('#').next().unwrap_or("") == wanted
                    })
                })
                .unwrap_or(false);
            if !registered {
                tracing::warn!(
                    "request_object: client \"{}\" sent a request_uri it has \
                     not registered, which was refused and not fetched.",
                    client_id
                );
                return Err(refusal(codes::STS_OAUTH_0345, "invalid_request_uri", format!(
                    "the request_uri \"{}\" is not one client \"{}\" has registered (request_uris). This service fetches a request_uri only when the client registered it beforehand, so that it cannot be made to dial a URL a request chose (RFC 9101 section 10.4). Register it on the application, or send the request object by value.",
                    wanted, client_id)));
            }
            return Err(refusal(
                codes::STS_OAUTH_0346,
                "invalid_request_uri",
                "the registered request_uri cannot be fetched: this \
                 authorization server does not yet dial a request_uri; send \
                 the request object by value, or push it to /oauth2/par."
                    .into(),
            ));
        };
        let (params, alg, once) = self.verify_object(
            &compact, client, &client_id, query, issuer, as_base,
        )?;
        if let Some(r) = self.look_up(&once) {
            return Err(r);
        }
        Ok(Some(Resolution {
            params,
            jar: Jar {
                outer: query.clone(),
                source: if by_value { "request" } else { "request_uri" }.into(),
                alg,
                pushed: None,
                once,
            },
        }))
    }
}
