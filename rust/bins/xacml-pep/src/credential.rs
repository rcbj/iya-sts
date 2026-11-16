// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THIS PEP'S ONE CREDENTIAL TO THE SERVICE (#1827 follow-up): an RFC 7523
//! self-assertion grant for a DPoP-bound (RFC 9449) access token, on EVERY
//! call this process makes to the service, in place of the client
//! certificate the PDP used to identify it by.
//!
//! * **ONE KEY PAIR.** `PEP_ASSERTION_KEY` (a PEM private key) signs the
//!   assertion AND every DPoP proof, so the token is bound to the key the
//!   service registered for this PEP's entry. Unset, `PEP_TLS_KEY` is used
//!   with a notice (`STS-XPEP-0127`) — the key of the client certificate a
//!   PEP provisioned before this change already holds. RS256 for an RSA
//!   key, ES256 for EC P-256 (the signature as `r || s`), anything else
//!   refused by name (`STS-XPEP-0128`). The file is read again on the
//!   listener pair's reload interval; a changed key drops every token held,
//!   because each is bound to the key that asked for it.
//! * **THREE AUDIENCES, ONE TOKEN EACH** ([`Resource`]): `<PDP>/xacml/pep`
//!   (`xacml:pep`) for the pulls, the registration, the heartbeat, the
//!   validation doors and `POST /xacml/pip`; `<PDP>/admin-api`
//!   (`xacml:pep-audit`) for the decision records; `<PDP>/access/v1`
//!   (`authzen:evaluate`) for the AuthZEN forward. `<PDP>` is `PEP_PDP_URL`,
//!   a realm prefix included.
//! * **THE CACHE.** A token is used until 30 s before it expires, then
//!   fetched again. Concurrent callers for one resource wait for ONE fetch
//!   (a per-resource async gate, checked again once held). A 401
//!   `invalid_token` at a resource drops that token and the call is made
//!   once more with a new one (`pdp_client.rs`). A REFUSED grant is not
//!   asked again for five seconds, so a PEP with no registered key does not
//!   send a token request ahead of every PIP query.
//! * **DPOP NONCES.** `use_dpop_nonce` — a 400 at the token endpoint, a 401
//!   at a resource — is answered by ONE retry with the nonce handed; the
//!   latest `DPoP-Nonce` of every answer is remembered per origin and
//!   role (the token endpoint, and each resource) and put in the next
//!   proof. A second demand in a row is `STS-XPEP-0130`.
//! * **NEVER BLOCKING.** A call for which no token can be had goes WITHOUT
//!   one — with the client certificate where `PEP_TLS_CERT` is set, which
//!   the service still accepts — and the service's answer is what the
//!   caller records. Why there is no token is logged under
//!   `STS-XPEP-0129`, naming the provisioning step that is missing, at warn
//!   the first time and when the reason changes.
//! * **NO TOKEN, KEY OR PROOF IS EVER LOGGED OR REPORTED.** `GET /`'s
//!   `credential` says which file, the key type, its JWK thumbprint, whether
//!   a client certificate is presented too, and per resource whether a
//!   token is held and until when.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openssl::bn::BigNumContext;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private};
use openssl::sign::Signer;
use reqwest::Method;
use serde_json::{json, Value};
use sts_core::log::tag;

use crate::options::Options;
use crate::pdp_client::{Answer, Body, PdpClient};

/// Where the token comes from, under the PDP URL.
pub const TOKEN_PATH: &str = "/oauth2/token";
const JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/// The self-assertion's lifetime: long enough for a slow token endpoint,
/// short enough that one seen in a log is useless soon after.
const ASSERTION_LIFETIME_S: i64 = 120;
/// A token is fetched again this long before it expires.
pub const RENEW_BEFORE_S: u64 = 30;
/// A refused grant is not asked again for this long.
const REFUSED_HOLD: Duration = Duration::from_secs(5);

/// The three audiences a token is asked for (the contract's table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resource {
    /// `/xacml/pep/*` and `POST /xacml/pip`.
    Pep,
    /// `POST /admin-api/pep-audit`.
    AdminApi,
    /// The AuthZEN forward, `POST /access/v1/evaluation`.
    Access,
}

impl Resource {
    pub const ALL: [Resource; 3] =
        [Resource::Pep, Resource::AdminApi, Resource::Access];

    fn index(self) -> usize {
        match self {
            Resource::Pep => 0,
            Resource::AdminApi => 1,
            Resource::Access => 2,
        }
    }

    /// The resource indicator's path under the PDP URL.
    pub fn path(self) -> &'static str {
        match self {
            Resource::Pep => "/xacml/pep",
            Resource::AdminApi => "/admin-api",
            Resource::Access => "/access/v1",
        }
    }

    /// The one scope asked for it.
    pub fn scope(self) -> &'static str {
        match self {
            Resource::Pep => "xacml:pep",
            Resource::AdminApi => "xacml:pep-audit",
            Resource::Access => "authzen:evaluate",
        }
    }

    /// Its name on `GET /` and in the log.
    pub fn name(self) -> &'static str {
        match self {
            Resource::Pep => "xacml-pep",
            Resource::AdminApi => "admin-api",
            Resource::Access => "access-v1",
        }
    }
}

/// `bytes` random bytes as lower-case hex, or `None` when OpenSSL cannot
/// draw them.
pub fn random_hex(bytes: usize) -> Option<String> {
    let mut buffer = vec![0u8; bytes];
    openssl::rand::rand_bytes(&mut buffer).ok()?;
    Some(buffer.iter().map(|b| format!("{:02x}", b)).collect())
}

/// The assertion key, loaded: what it signs with and the public half as a
/// JWK for the DPoP header.
pub struct SigningKey {
    key: PKey<Private>,
    alg: &'static str,
    jwk: Value,
    thumbprint: String,
    label: String,
}

impl SigningKey {
    /// The key in `pem`, or why it is refused. `var` names the variable it
    /// came from, for the sentence.
    pub fn from_pem(pem: &[u8], var: &str) -> Result<SigningKey, String> {
        let key = PKey::private_key_from_pem(pem).map_err(|e| {
            format!("the key at {} would not load: {}", var, e)
        })?;
        let refused = |e: openssl::error::ErrorStack| {
            format!("the key at {} could not be read: {}", var, e)
        };
        let (alg, jwk, label) = match key.id() {
            Id::RSA => {
                let rsa = key.rsa().map_err(refused)?;
                let jwk = json!({
                    "e": URL_SAFE_NO_PAD.encode(rsa.e().to_vec()),
                    "kty": "RSA",
                    "n": URL_SAFE_NO_PAD.encode(rsa.n().to_vec()),
                });
                ("RS256", jwk, format!("RSA {}", rsa.size() * 8))
            }
            Id::EC => {
                let ec = key.ec_key().map_err(refused)?;
                if ec.group().curve_name() != Some(Nid::X9_62_PRIME256V1) {
                    return Err(format!(
                        "the key at {} is an EC key on a curve other than \
                         P-256, and the assertion and the DPoP proofs are \
                         signed only with RS256 or ES256",
                        var
                    ));
                }
                let mut ctx = BigNumContext::new().map_err(refused)?;
                let mut x = openssl::bn::BigNum::new().map_err(refused)?;
                let mut y = openssl::bn::BigNum::new().map_err(refused)?;
                ec.public_key()
                    .affine_coordinates(ec.group(), &mut x, &mut y, &mut ctx)
                    .map_err(refused)?;
                let jwk = json!({
                    "crv": "P-256",
                    "kty": "EC",
                    "x": URL_SAFE_NO_PAD
                        .encode(x.to_vec_padded(32).map_err(refused)?),
                    "y": URL_SAFE_NO_PAD
                        .encode(y.to_vec_padded(32).map_err(refused)?),
                });
                ("ES256", jwk, "EC P-256".to_string())
            }
            other => {
                return Err(format!(
                    "the key at {} is of type {:?}, and the assertion and \
                     the DPoP proofs are signed only with an RSA key (RS256) \
                     or an EC P-256 key (ES256)",
                    var, other
                ))
            }
        };
        // RFC 7638: the required members in lexicographic order, no
        // whitespace — which is how `jwk` was written.
        let digest =
            openssl::hash::hash(MessageDigest::sha256(), jwk.to_string().as_bytes())
                .map_err(refused)?;
        Ok(SigningKey {
            key,
            alg,
            jwk,
            thumbprint: URL_SAFE_NO_PAD.encode(digest),
            label,
        })
    }

    #[cfg(test)]
    pub fn alg(&self) -> &'static str {
        self.alg
    }

    /// The public key as a JWK (RFC 7517), never the private half.
    #[cfg(test)]
    pub fn jwk(&self) -> &Value {
        &self.jwk
    }

    /// A compact JWS of `header` and `claims`.
    fn jws(&self, header: &Value, claims: &Value) -> Result<String, String> {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let failed = |e: openssl::error::ErrorStack| {
            format!("could not be signed: {}", e)
        };
        let mut signer =
            Signer::new(MessageDigest::sha256(), &self.key).map_err(failed)?;
        signer.update(input.as_bytes()).map_err(failed)?;
        let der = signer.sign_to_vec().map_err(failed)?;
        let signature = if self.alg == "ES256" {
            // JWS wants r || s, 32 bytes each (RFC 7518 section 3.4), and
            // OpenSSL writes the DER SEQUENCE.
            let sig = EcdsaSig::from_der(&der).map_err(failed)?;
            let mut raw = sig.r().to_vec_padded(32).map_err(failed)?;
            raw.extend(sig.s().to_vec_padded(32).map_err(failed)?);
            raw
        } else {
            der
        };
        Ok(format!("{}.{}", input, URL_SAFE_NO_PAD.encode(signature)))
    }
}

/// The RFC 7523 self-assertion: a compact JWS naming `name` as `iss` and
/// `sub`, for `audience` (the token endpoint). No `kid`: the service finds
/// the key through the subject's registered one.
pub fn self_assertion(
    key: &SigningKey,
    name: &str,
    audience: &str,
    now: i64,
) -> Result<String, String> {
    let jti = random_hex(16)
        .ok_or_else(|| "no random bytes for the assertion's jti".to_string())?;
    let header = json!({ "alg": key.alg, "typ": "JWT" });
    let claims = json!({
        "iss": name,
        "sub": name,
        "aud": audience,
        "iat": now,
        "exp": now + ASSERTION_LIFETIME_S,
        "jti": jti
    });
    key.jws(&header, &claims)
        .map_err(|e| format!("the self-assertion {}", e))
}

/// `url` as a DPoP proof's `htu`: without its query and fragment (RFC 9449
/// section 4.2).
pub fn htu(url: &str) -> &str {
    let end = url.find(['?', '#']).unwrap_or(url.len());
    &url[..end]
}

/// `ath`: base64url of the SHA-256 of the access token.
pub fn ath(token: &str) -> String {
    let digest = openssl::hash::hash(MessageDigest::sha256(), token.as_bytes())
        .map(|d| d.to_vec())
        .unwrap_or_default();
    URL_SAFE_NO_PAD.encode(digest)
}

/// A DPoP proof (RFC 9449 section 4.2): `typ` `dpop+jwt`, the public JWK of
/// `key`, a fresh 128-bit `jti`, `htm`, `htu`, `iat`, and `ath` and
/// `nonce` when given.
pub fn proof(
    key: &SigningKey,
    method: &str,
    url: &str,
    access_token: Option<&str>,
    nonce: Option<&str>,
    now: i64,
) -> Result<String, String> {
    let jti = random_hex(16)
        .ok_or_else(|| "no random bytes for the proof's jti".to_string())?;
    let header = json!({ "typ": "dpop+jwt", "alg": key.alg, "jwk": key.jwk });
    let mut claims = json!({
        "jti": jti,
        "htm": method,
        "htu": htu(url),
        "iat": now
    });
    if let Some(token) = access_token {
        claims["ath"] = json!(ath(token));
    }
    if let Some(nonce) = nonce {
        claims["nonce"] = json!(nonce);
    }
    key.jws(&header, &claims)
        .map_err(|e| format!("the DPoP proof {}", e))
}

/// `scheme://host[:port]` of `url`, for keying the nonces.
fn origin(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(parsed) => parsed.origin().ascii_serialization(),
        Err(_) => url.to_string(),
    }
}

/// The `error` parameter of a `WWW-Authenticate` challenge, if any.
pub fn challenge_error(header: &str) -> Option<String> {
    let at = header.find("error=")? + "error=".len();
    let rest = &header[at..];
    let value = if let Some(quoted) = rest.strip_prefix('"') {
        quoted.split('"').next().unwrap_or("")
    } else {
        rest.split([',', ' ']).next().unwrap_or("")
    };
    (!value.is_empty()).then(|| value.to_string())
}

/// Where the assertion key comes from.
#[derive(Debug, Clone, PartialEq)]
pub struct KeySource {
    /// The file, empty for none.
    pub path: String,
    /// `PEP_ASSERTION_KEY`, `PEP_TLS_KEY`, or `""` for none.
    pub var: &'static str,
}

impl KeySource {
    /// `PEP_ASSERTION_KEY`, else `PEP_TLS_KEY`, else nothing — from the
    /// two values given, so a test does not touch the environment.
    pub fn choose(assertion: Option<&str>, tls: Option<&str>) -> KeySource {
        let set = |v: Option<&str>| {
            v.map(str::trim).filter(|v| !v.is_empty()).map(str::to_string)
        };
        if let Some(path) = set(assertion) {
            return KeySource {
                path,
                var: "PEP_ASSERTION_KEY",
            };
        }
        if let Some(path) = set(tls) {
            return KeySource {
                path,
                var: "PEP_TLS_KEY",
            };
        }
        KeySource {
            path: String::new(),
            var: "",
        }
    }

    pub fn fallback(&self) -> bool {
        self.var == "PEP_TLS_KEY"
    }
}

/// A token held for one resource.
#[derive(Clone)]
struct Held {
    value: String,
    renew_at: Instant,
    expires_at: String,
}

/// Per resource: the token, the last refusal and when it may be asked again.
#[derive(Default)]
struct Slot {
    token: Option<Held>,
    refused: String,
    refused_until: Option<Instant>,
}

/// The key as last read.
#[derive(Default)]
struct KeyState {
    /// The file's bytes when the key held was read from them.
    key_bytes: Option<Vec<u8>>,
    /// The bytes last refused, so the same bad file is not parsed again.
    refused_bytes: Option<Vec<u8>>,
    key: Option<Arc<SigningKey>>,
    problem: String,
}

/// The credential: the key, the tokens, the nonces.
pub struct Credential {
    name: String,
    client_id: String,
    base: String,
    source: KeySource,
    client_certificate: bool,
    key: RwLock<KeyState>,
    slots: Mutex<[Slot; 3]>,
    gates: [tokio::sync::Mutex<()>; 3],
    nonces: Mutex<HashMap<String, String>>,
    /// The last nonce-exhaustion or resource refusal logged, so a repeat is
    /// at debug.
    last_call_problem: Mutex<String>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // Poisoned means a panic while holding it; what it holds is still the
    // best this PEP has.
    match m.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl Credential {
    /// Built from the options, reading the key once — silently: `announce()`
    /// says what was found, at start.
    pub fn new(options: &Options) -> Credential {
        let credential = Credential {
            name: options.name.clone(),
            client_id: options.client_id.clone(),
            base: options.pdp_url.trim_end_matches('/').to_string(),
            source: options.assertion_key.clone(),
            client_certificate: options.client_certificate.is_some()
                && options.client_key.is_some(),
            key: RwLock::new(KeyState::default()),
            slots: Mutex::new(Default::default()),
            gates: Default::default(),
            nonces: Mutex::new(HashMap::new()),
            last_call_problem: Mutex::new(String::new()),
        };
        credential.read_key();
        credential
    }

    fn key_state(&self) -> std::sync::RwLockReadGuard<'_, KeyState> {
        match self.key.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Reads the file and installs what it holds; answers `Some(problem)`
    /// when the problem changed ("" for none left), `None` when it did
    /// not. An unreadable or refused file KEEPS the key already held.
    fn read_key(&self) -> Option<String> {
        let read = if self.source.path.is_empty() {
            None
        } else {
            Some(std::fs::read(&self.source.path))
        };
        let mut state = match self.key.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let mut installed = false;
        let problem = match read {
            None => "neither PEP_ASSERTION_KEY nor PEP_TLS_KEY is set, so \
                     this PEP has no key to sign its assertion with"
                .to_string(),
            Some(Err(error)) => format!(
                "{} names {} and it could not be read ({})",
                self.source.var, self.source.path, error
            ),
            Some(Ok(bytes)) => {
                if state.key_bytes.as_deref() == Some(bytes.as_slice()) {
                    String::new()
                } else if state.refused_bytes.as_deref() == Some(bytes.as_slice())
                {
                    // The same bad file: not parsed and refused again.
                    state.problem.clone()
                } else {
                    match SigningKey::from_pem(&bytes, self.source.var) {
                        Ok(key) => {
                            if state.key.is_some() {
                                tracing::info!(
                                    "xacml-pep: the assertion key at {} \
                                     changed; every access token held is \
                                     dropped, being bound to the old key.",
                                    self.source.path
                                );
                            }
                            state.key = Some(Arc::new(key));
                            state.key_bytes = Some(bytes);
                            state.refused_bytes = None;
                            installed = true;
                            String::new()
                        }
                        Err(why) => {
                            state.refused_bytes = Some(bytes);
                            why
                        }
                    }
                }
            }
        };
        if installed {
            for slot in lock(&self.slots).iter_mut() {
                *slot = Slot::default();
            }
        }
        if state.problem == problem {
            return None;
        }
        state.problem = problem.clone();
        Some(problem)
    }

    /// Says at start what key is in use, or why there is none.
    pub fn announce(&self) {
        let state = self.key_state();
        if self.source.fallback() {
            tracing::info!(
                "{}xacml-pep: no PEP_ASSERTION_KEY, so the assertion and the \
                 DPoP proofs are signed with the client certificate's key, \
                 PEP_TLS_KEY ({}). Set PEP_ASSERTION_KEY to give this PEP a \
                 key of its own.",
                tag("STS-XPEP-0127"),
                self.source.path
            );
        }
        match &state.key {
            Some(key) => tracing::info!(
                "xacml-pep: every call to the service carries a DPoP-bound \
                 access token from an RFC 7523 self-assertion signed with \
                 the {} key at {} ({}, JWK thumbprint {}), through client \
                 {} as {}{}.",
                key.label,
                self.source.path,
                key.alg,
                key.thumbprint,
                self.client_id,
                self.name,
                if self.client_certificate {
                    "; the client certificate is presented as well"
                } else {
                    ""
                }
            ),
            None => self.say_key_problem(&state.problem),
        }
    }

    fn say_key_problem(&self, problem: &str) {
        let code = if problem.contains("could not be read")
            || self.source.path.is_empty()
        {
            "STS-XPEP-0126"
        } else {
            "STS-XPEP-0128"
        };
        tracing::warn!(
            "{}xacml-pep: {}. Calls to the service go without an access \
             token{}.",
            tag(code),
            problem,
            if self.client_certificate {
                ", on the client certificate alone"
            } else {
                ", and the service refuses them"
            }
        );
    }

    /// Reads the key file again (the reload loop); logs a change of
    /// problem.
    pub fn reload(&self) {
        if let Some(problem) = self.read_key() {
            if problem.is_empty() {
                tracing::info!(
                    "xacml-pep: the assertion key at {} is loaded.",
                    self.source.path
                );
            } else {
                self.say_key_problem(&problem);
            }
        }
    }

    fn signing_key(&self) -> Result<Arc<SigningKey>, String> {
        let state = self.key_state();
        state.key.clone().ok_or_else(|| state.problem.clone())
    }

    /// A DPoP proof for a call, with the key held and the nonce last
    /// handed by `url`'s origin for `role`.
    pub fn dpop_proof(
        &self,
        method: &str,
        url: &str,
        access_token: Option<&str>,
        nonce: Option<&str>,
    ) -> Result<String, String> {
        let key = self.signing_key()?;
        proof(
            &key,
            method,
            url,
            access_token,
            nonce,
            chrono::Utc::now().timestamp(),
        )
    }

    fn nonce_key(url: &str, role: &str) -> String {
        format!("{} {}", origin(url), role)
    }

    /// The nonce last handed for `role` at `url`'s origin.
    pub fn nonce_for(&self, url: &str, role: &str) -> Option<String> {
        lock(&self.nonces).get(&Self::nonce_key(url, role)).cloned()
    }

    /// Remembers the `DPoP-Nonce` an answer carried, if any.
    pub fn remember_nonce(&self, url: &str, role: &str, answer: &Answer) {
        if let Some(nonce) = answer.dpop_nonce.as_ref().filter(|n| !n.is_empty())
        {
            lock(&self.nonces).insert(Self::nonce_key(url, role), nonce.clone());
        }
    }

    fn fresh(&self, resource: Resource) -> Option<String> {
        let slots = lock(&self.slots);
        slots[resource.index()]
            .token
            .as_ref()
            .filter(|t| Instant::now() < t.renew_at)
            .map(|t| t.value.clone())
    }

    /// Drops the token held for `resource` when it is still `token` — a
    /// newer one fetched meanwhile is kept.
    pub fn drop_token(&self, resource: Resource, token: &str) {
        let mut slots = lock(&self.slots);
        let slot = &mut slots[resource.index()];
        if slot.token.as_ref().map(|t| t.value.as_str()) == Some(token) {
            slot.token = None;
        }
    }

    /// The token for `resource`: the one held, or ONE fetch shared by every
    /// caller waiting. `Err` says why there is none.
    pub async fn token(
        &self,
        client: &PdpClient,
        resource: Resource,
    ) -> Result<String, String> {
        if let Some(token) = self.fresh(resource) {
            return Ok(token);
        }
        let _gate = self.gates[resource.index()].lock().await;
        if let Some(token) = self.fresh(resource) {
            return Ok(token);
        }
        {
            let slots = lock(&self.slots);
            let slot = &slots[resource.index()];
            if let Some(until) = slot.refused_until {
                if Instant::now() < until {
                    return Err(slot.refused.clone());
                }
            }
        }
        match self.fetch(client, resource).await {
            Ok(held) => {
                let value = held.value.clone();
                let mut slots = lock(&self.slots);
                let slot = &mut slots[resource.index()];
                if !slot.refused.is_empty() {
                    tracing::info!(
                        "xacml-pep: holds an access token for {} again.",
                        resource.name()
                    );
                }
                *slot = Slot {
                    token: Some(held),
                    ..Slot::default()
                };
                Ok(value)
            }
            Err(why) => {
                let mut slots = lock(&self.slots);
                let slot = &mut slots[resource.index()];
                if slot.refused != why {
                    tracing::warn!(
                        "{}xacml-pep: no access token for {} (scope {}): {}. \
                         Calls to it go without one{}.",
                        tag("STS-XPEP-0129"),
                        resource.name(),
                        resource.scope(),
                        why,
                        if self.client_certificate {
                            ", on the client certificate alone"
                        } else {
                            ", and the service refuses them"
                        }
                    );
                } else {
                    tracing::debug!(
                        "{}xacml-pep: still no access token for {}: {}",
                        tag("STS-XPEP-0129"),
                        resource.name(),
                        why
                    );
                }
                slot.refused = why.clone();
                slot.refused_until = Some(Instant::now() + REFUSED_HOLD);
                slot.token = None;
                Err(why)
            }
        }
    }

    /// The grant, once more with a nonce when the token endpoint asks.
    async fn fetch(
        &self,
        client: &PdpClient,
        resource: Resource,
    ) -> Result<Held, String> {
        let key = self.signing_key()?;
        let token_url = format!("{}{}", self.base, TOKEN_PATH);
        let mut retried = false;
        loop {
            let now = chrono::Utc::now().timestamp();
            let assertion = self_assertion(&key, &self.name, &token_url, now)?;
            let nonce = self.nonce_for(&token_url, "token");
            let dpop =
                proof(&key, "POST", &token_url, None, nonce.as_deref(), now)?;
            let form = vec![
                ("grant_type".to_string(), JWT_BEARER.to_string()),
                ("assertion".to_string(), assertion),
                ("client_id".to_string(), self.client_id.clone()),
                ("scope".to_string(), resource.scope().to_string()),
                (
                    "resource".to_string(),
                    format!("{}{}", self.base, resource.path()),
                ),
            ];
            let answer = client
                .call_url(
                    Method::POST,
                    &token_url,
                    Some(Body::Form(form)),
                    &[("DPoP", dpop)],
                    None,
                )
                .await;
            self.remember_nonce(&token_url, "token", &answer);
            if let Some(error) = &answer.error {
                return Err(format!("the token endpoint did not answer: {}", error));
            }
            let error = answer
                .json
                .as_ref()
                .and_then(|j| j["error"].as_str())
                .unwrap_or("")
                .to_string();
            if answer.status == 400 && error == "use_dpop_nonce" {
                if !retried && answer.dpop_nonce.is_some() {
                    retried = true;
                    continue;
                }
                self.note_call_problem(
                    "STS-XPEP-0130",
                    &format!(
                        "the token endpoint {} demanded a DPoP nonce again \
                         after the retry carrying the one it handed",
                        token_url
                    ),
                );
                return Err("the token endpoint demanded a DPoP nonce twice \
                            in a row (STS-XPEP-0130)"
                    .to_string());
            }
            if answer.status == 200 {
                return self.accepted(&answer);
            }
            return Err(self.explain(&token_url, resource, &answer, &error));
        }
    }

    /// A 200 from the token endpoint, read.
    fn accepted(&self, answer: &Answer) -> Result<Held, String> {
        let json = answer.json.as_ref();
        let Some(value) = json
            .and_then(|j| j["access_token"].as_str())
            .filter(|t| !t.is_empty())
        else {
            return Err(
                "the token endpoint answered 200 without an access_token"
                    .to_string(),
            );
        };
        let kind = json
            .and_then(|j| j["token_type"].as_str())
            .unwrap_or("");
        if !kind.eq_ignore_ascii_case("DPoP") {
            return Err(format!(
                "the token endpoint issued a token of type \"{}\", not a \
                 DPoP-bound one: the service is older than this PEP's \
                 credential, or did not read the DPoP proof",
                kind
            ));
        }
        let expires_in = json
            .and_then(|j| j["expires_in"].as_u64())
            .unwrap_or(60);
        Ok(Held {
            value: value.to_string(),
            renew_at: Instant::now()
                + Duration::from_secs(expires_in.saturating_sub(RENEW_BEFORE_S)),
            expires_at: (chrono::Utc::now()
                + chrono::Duration::seconds(expires_in as i64))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        })
    }

    /// A refused grant in a sentence, naming the provisioning step that is
    /// missing.
    fn explain(
        &self,
        token_url: &str,
        resource: Resource,
        answer: &Answer,
        error: &str,
    ) -> String {
        let said = answer
            .error_description()
            .map(|d| format!(" ({})", d))
            .unwrap_or_default();
        let thumbprint = self
            .signing_key()
            .map(|k| k.thumbprint.clone())
            .unwrap_or_default();
        match (answer.status, error) {
            (_, "invalid_grant") => format!(
                "the token endpoint refused the self-assertion \
                 (invalid_grant{}): most often no assertion key is \
                 registered on {}, or the one registered is not this PEP's \
                 (JWK thumbprint {}). Register it with POST \
                 /admin-api/pki/upload-certificate (target person, purpose \
                 jwt) or issue-pep-credential, in the realm PEP_PDP_URL \
                 names; PEP_NAME must be the entry's username",
                said, self.name, thumbprint
            ),
            (_, "invalid_client") | (_, "unauthorized_client") => format!(
                "the token endpoint refused the client {} ({}{}): \
                 PEP_CLIENT_ID must name the public client the service seeds \
                 for remote PEPs, sts-remote-pep unless the realm renamed it",
                self.client_id, error, said
            ),
            (_, "invalid_scope") | (_, "access_denied") => format!(
                "the token endpoint refused the scope {} for {} ({}{}): the \
                 entry must be in the remote PEPs group (REMOTE_PEPS, the \
                 group roles.remotePepGroup names)",
                resource.scope(),
                self.name,
                error,
                said
            ),
            (_, "invalid_target") => format!(
                "the token endpoint refused the resource {}{} ({}{}): the \
                 service does not accept a token for it yet",
                self.base,
                resource.path(),
                error,
                said
            ),
            (_, "invalid_dpop_proof") => format!(
                "the token endpoint refused the DPoP proof (invalid_dpop_proof{})",
                said
            ),
            (404, _) => format!(
                "the service has no token endpoint at {} (404): check \
                 PEP_PDP_URL",
                token_url
            ),
            (status, "") => format!("the token endpoint answered {}{}", status, said),
            (status, error) => format!(
                "the token endpoint answered {} {}{}",
                status, error, said
            ),
        }
    }

    /// A resource refusal or a nonce demanded twice: warn the first time
    /// and on a change, debug otherwise.
    pub fn note_call_problem(&self, code: &str, why: &str) {
        let mut last = lock(&self.last_call_problem);
        if *last != why {
            tracing::warn!("{}xacml-pep: {}.", tag(code), why);
        } else {
            tracing::debug!("{}xacml-pep: {}.", tag(code), why);
        }
        *last = why.to_string();
    }

    /// Whether a key is loaded.
    pub fn has_key(&self) -> bool {
        self.key_state().key.is_some()
    }

    /// `credential` on `GET /`: never a token, a proof or a key.
    pub fn overview(&self) -> Value {
        let state = self.key_state();
        let slots = lock(&self.slots);
        let mut tokens = serde_json::Map::new();
        for resource in Resource::ALL {
            let slot = &slots[resource.index()];
            tokens.insert(
                resource.name().to_string(),
                json!({
                    "resource": format!("{}{}", self.base, resource.path()),
                    "scope": resource.scope(),
                    "held": slot.token.is_some(),
                    "expiresAt": slot.token.as_ref().map(|t| t.expires_at.clone()),
                    "lastRefusal": if slot.refused.is_empty() {
                        Value::Null
                    } else {
                        Value::from(slot.refused.clone())
                    }
                }),
            );
        }
        json!({
            "keyFile": if self.source.path.is_empty() {
                Value::Null
            } else {
                Value::from(self.source.path.clone())
            },
            "keySource": if self.source.var.is_empty() {
                Value::Null
            } else {
                Value::from(self.source.var)
            },
            "fallback": self.source.fallback(),
            "keyType": state.key.as_ref().map(|k| k.label.clone()),
            "alg": state.key.as_ref().map(|k| k.alg),
            "jwkThumbprint": state.key.as_ref().map(|k| k.thumbprint.clone()),
            "keyProblem": if state.problem.is_empty() {
                Value::Null
            } else {
                Value::from(state.problem.clone())
            },
            "clientId": self.client_id,
            "subject": self.name,
            "clientCertificate": self.client_certificate,
            "tokens": tokens,
            "what": "Every call this PEP makes to the service carries a \
                     DPoP-bound access token (RFC 9449) from an RFC 7523 \
                     self-assertion signed with ONE key — PEP_ASSERTION_KEY, \
                     else PEP_TLS_KEY — which also signs every DPoP proof. \
                     One token per audience: /xacml/pep (xacml:pep), \
                     /admin-api (xacml:pep-audit), /access/v1 \
                     (authzen:evaluate). clientCertificate says whether \
                     PEP_TLS_CERT is presented as well. The key must be \
                     registered on this PEP's entry, whose username is \
                     PEP_NAME."
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::rsa::Rsa;
    use openssl::sign::Verifier;

    pub fn decoded(part: &str) -> Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
    }

    pub fn rsa_pem() -> Vec<u8> {
        PKey::from_rsa(Rsa::generate(2048).unwrap())
            .unwrap()
            .private_key_to_pem_pkcs8()
            .unwrap()
    }

    pub fn p256_pem() -> Vec<u8> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(EcKey::generate(&group).unwrap())
            .unwrap()
            .private_key_to_pem_pkcs8()
            .unwrap()
    }

    /// A key written to a file of its own, removed by the caller.
    pub fn key_file(pem: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir()
            .join(format!("xacml-pep-key-{}.pem", random_hex(8).unwrap()));
        std::fs::write(&path, pem).unwrap();
        path
    }

    /// The public key a JWK names.
    fn public_of(jwk: &Value) -> PKey<openssl::pkey::Public> {
        let b = |m: &str| {
            BigNum::from_slice(
                &URL_SAFE_NO_PAD.decode(jwk[m].as_str().unwrap()).unwrap(),
            )
            .unwrap()
        };
        if jwk["kty"] == "RSA" {
            PKey::from_rsa(
                Rsa::from_public_components(b("n"), b("e")).unwrap(),
            )
            .unwrap()
        } else {
            let group =
                EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
            let ec = EcKey::from_public_key_affine_coordinates(
                &group,
                &b("x"),
                &b("y"),
            )
            .unwrap();
            PKey::from_ec_key(ec).unwrap()
        }
    }

    /// Verifies a JWS against the JWK, the signature in JWS form.
    pub fn verifies(jws: &str, jwk: &Value) -> bool {
        let parts: Vec<&str> = jws.split('.').collect();
        let input = format!("{}.{}", parts[0], parts[1]);
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let public = public_of(jwk);
        if jwk["kty"] == "RSA" {
            let mut v = Verifier::new(MessageDigest::sha256(), &public).unwrap();
            v.update(input.as_bytes()).unwrap();
            v.verify(&signature).unwrap()
        } else {
            assert_eq!(signature.len(), 64);
            let sig = EcdsaSig::from_private_components(
                BigNum::from_slice(&signature[..32]).unwrap(),
                BigNum::from_slice(&signature[32..]).unwrap(),
            )
            .unwrap();
            let digest =
                openssl::hash::hash(MessageDigest::sha256(), input.as_bytes())
                    .unwrap();
            sig.verify(&digest, &public.ec_key().unwrap()).unwrap()
        }
    }

    #[test]
    fn the_self_assertion_is_rs256_and_verifies() {
        let key = SigningKey::from_pem(&rsa_pem(), "PEP_ASSERTION_KEY").unwrap();
        let aud = "https://pdp.example/realm/r1/oauth2/token";
        let jws = self_assertion(&key, "remote-pep-1", aud, 1_000_000).unwrap();
        let parts: Vec<&str> = jws.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header = decoded(parts[0]);
        assert_eq!(header, json!({ "alg": "RS256", "typ": "JWT" }));
        let claims = decoded(parts[1]);
        assert_eq!(claims["iss"], "remote-pep-1");
        assert_eq!(claims["sub"], "remote-pep-1");
        assert_eq!(claims["aud"], aud);
        assert_eq!(claims["iat"], 1_000_000);
        assert_eq!(
            claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
            120
        );
        assert_eq!(claims["jti"].as_str().unwrap().len(), 32);
        assert!(verifies(&jws, key.jwk()));
        let again = self_assertion(&key, "remote-pep-1", aud, 1).unwrap();
        assert_ne!(
            decoded(again.split('.').nth(1).unwrap())["jti"],
            claims["jti"],
            "a fresh jti every time"
        );
    }

    #[test]
    fn keys_other_than_rsa_and_p256_are_refused_by_name() {
        let key = SigningKey::from_pem(&p256_pem(), "PEP_ASSERTION_KEY").unwrap();
        let jws = self_assertion(&key, "p", "a", 5).unwrap();
        assert_eq!(decoded(jws.split('.').next().unwrap())["alg"], "ES256");
        assert!(verifies(&jws, key.jwk()));

        let p384 = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let other = PKey::from_ec_key(EcKey::generate(&p384).unwrap())
            .unwrap()
            .private_key_to_pem_pkcs8()
            .unwrap();
        assert!(SigningKey::from_pem(&other, "PEP_ASSERTION_KEY")
            .err()
            .unwrap()
            .contains("P-256"));
        let ed = PKey::generate_ed25519()
            .unwrap()
            .private_key_to_pem_pkcs8()
            .unwrap();
        assert!(SigningKey::from_pem(&ed, "PEP_TLS_KEY")
            .err()
            .unwrap()
            .contains("RS256"));
        assert!(SigningKey::from_pem(b"not a key", "PEP_ASSERTION_KEY")
            .err()
            .unwrap()
            .contains("would not load"));
    }

    #[test]
    fn a_proof_has_the_shape_rfc_9449_asks_and_verifies() {
        for pem in [p256_pem(), rsa_pem()] {
            let key = SigningKey::from_pem(&pem, "PEP_ASSERTION_KEY").unwrap();
            let url = "https://pdp.example/realm/r1/xacml/pep/policies?since=x#f";
            let jws =
                proof(&key, "GET", url, Some("the-token"), Some("n-1"), 77)
                    .unwrap();
            let parts: Vec<&str> = jws.split('.').collect();
            let header = decoded(parts[0]);
            assert_eq!(header["typ"], "dpop+jwt");
            assert_eq!(header["alg"], key.alg());
            assert_eq!(&header["jwk"], key.jwk());
            assert!(header["jwk"].get("d").is_none(), "never the private half");
            let claims = decoded(parts[1]);
            assert_eq!(claims["htm"], "GET");
            assert_eq!(
                claims["htu"],
                "https://pdp.example/realm/r1/xacml/pep/policies"
            );
            assert_eq!(claims["iat"], 77);
            assert_eq!(claims["nonce"], "n-1");
            assert_eq!(claims["jti"].as_str().unwrap().len(), 32);
            let digest = openssl::hash::hash(
                MessageDigest::sha256(),
                b"the-token",
            )
            .unwrap();
            assert_eq!(claims["ath"], URL_SAFE_NO_PAD.encode(digest));
            assert!(verifies(&jws, &header["jwk"]));
            let bare = proof(&key, "POST", "https://a/oauth2/token", None, None, 1)
                .unwrap();
            let claims = decoded(bare.split('.').nth(1).unwrap());
            assert!(claims.get("ath").is_none());
            assert!(claims.get("nonce").is_none());
        }
    }

    #[test]
    fn the_thumbprint_is_rfc_7638s() {
        // RFC 7638 section 3.1's example key and thumbprint.
        let jwk = json!({
            "e": "AQAB",
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt\
                  VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6\
                  4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD\
                  W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9\
                  1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH\
                  aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
        });
        let digest =
            openssl::hash::hash(MessageDigest::sha256(), jwk.to_string().as_bytes())
                .unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(digest),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
        let key = SigningKey::from_pem(&p256_pem(), "PEP_ASSERTION_KEY").unwrap();
        let members: Vec<&String> =
            key.jwk().as_object().unwrap().keys().collect();
        assert_eq!(members, ["crv", "kty", "x", "y"]);
    }

    #[test]
    fn the_key_falls_back_to_pep_tls_key_and_says_where_it_came_from() {
        assert_eq!(
            KeySource::choose(Some("/a.pem"), Some("/b.pem")),
            KeySource {
                path: "/a.pem".into(),
                var: "PEP_ASSERTION_KEY"
            }
        );
        let fallback = KeySource::choose(Some("  "), Some("/b.pem"));
        assert_eq!(fallback.var, "PEP_TLS_KEY");
        assert!(fallback.fallback());
        assert_eq!(KeySource::choose(None, None).var, "");

        let pem = p256_pem();
        let file = key_file(&pem);
        let mut options = Options::from_env("0.0.0");
        options.assertion_key =
            KeySource::choose(None, Some(file.to_str().unwrap()));
        let credential = Credential::new(&options);
        assert!(credential.has_key());
        let overview = credential.overview();
        assert_eq!(overview["keySource"], "PEP_TLS_KEY");
        assert_eq!(overview["fallback"], true);
        assert_eq!(overview["keyType"], "EC P-256");
        assert_eq!(overview["alg"], "ES256");
        assert!(!overview.to_string().contains("PRIVATE"));

        // A changed file is picked up and replaces the key.
        let before = overview["jwkThumbprint"].clone();
        std::fs::write(&file, rsa_pem()).unwrap();
        credential.reload();
        assert_eq!(credential.overview()["keyType"], "RSA 2048");
        assert_ne!(credential.overview()["jwkThumbprint"], before);
        // A file that goes bad keeps the key already held.
        std::fs::write(&file, b"garbage").unwrap();
        credential.reload();
        assert!(credential.has_key());
        assert!(credential.overview()["keyProblem"]
            .as_str()
            .unwrap()
            .contains("would not load"));
        std::fs::remove_file(&file).unwrap();

        options.assertion_key = KeySource::choose(None, None);
        let none = Credential::new(&options);
        assert!(!none.has_key());
        assert!(none.overview()["keyProblem"]
            .as_str()
            .unwrap()
            .contains("PEP_ASSERTION_KEY"));
    }

    #[test]
    fn a_challenge_s_error_is_read() {
        assert_eq!(
            challenge_error(r#"DPoP error="use_dpop_nonce", error_description="x""#)
                .as_deref(),
            Some("use_dpop_nonce")
        );
        assert_eq!(
            challenge_error("DPoP error=invalid_token, algs=\"ES256\"").as_deref(),
            Some("invalid_token")
        );
        assert_eq!(challenge_error("DPoP algs=\"ES256\""), None);
        assert_eq!(htu("https://a/b?c#d"), "https://a/b");
        assert_eq!(htu("https://a/b#d?c"), "https://a/b");
    }
}
