// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! One HTTP client to the PDP, shared by the pull, the registration, the
//! heartbeat and the PIP query — so a PEP cannot verify the PDP for one
//! request and not for another.
//!
//! **EVERY CALL TO THE SERVICE GOES THROUGH [`PdpClient::call_authorized`]**
//! (#1827 follow-up): a DPoP-bound access token from the shared
//! [`Credential`] for the call's [`Resource`], a fresh DPoP proof, one retry
//! on `use_dpop_nonce` and one on `invalid_token` with a new token. The
//! plain [`PdpClient::call_url`] is for what is not this PEP's API: the
//! token request itself and the realm's JWKS, which is anonymous.
//!
//! **NO CLIENT CERTIFICATE IS PRESENTED** (phase 4 of #1827's follow-up,
//! rcbj 2026-11-16). Through phase 3 the certificate in `PEP_TLS_CERT` went
//! on every call beside the token; it is retired for authenticating to the
//! service, the token is the one credential, and `PEP_TLS_CERT` is ignored
//! (`STS-XPEP-0135` at start, `options.rs`). The service is still
//! verified as before (`PEP_TLS_CA`, `PEP_TLS_INSECURE`).
//!
//! **A call never fails**: it answers an [`Answer`] whose `error` says what
//! went wrong, because every caller wants to RECORD what happened and carry
//! on.
//!
//! **ONE CONNECTION POOL PER THREAD, NOT ONE FOR THE PROCESS (2026-11-16).**
//! A member's first call to `/xacml/pep/basic` or `/xacml/pep/session`
//! after an idle spell sometimes waited out the whole timeout
//! (`STS-XPEP-0075`, a 502 to the user), now and then twice in a row, and
//! the next call took milliseconds. The proxy's upstream client met the
//! same thing first (`proxy.rs`, `UPSTREAM_CLIENT`): every listener worker
//! owns a current-thread runtime and polls it only while it serves a
//! connection, and reqwest parks an idle connection on the runtime that
//! opened it. One client shared by every worker checked that connection
//! out on another worker, whose request was handed to a connection task
//! nobody was driving — so it was not sent, nothing failed, and the call
//! waited for its timeout. Each thread now has its own client built from
//! the same recipe (the same anchors, the same verification), so a pooled
//! connection is only ever used by the runtime that drives it.
//!
//! **AN IDLE CONNECTION IS DROPPED BEFORE THE SERVICE DROPS IT**: after
//! [`POOL_IDLE`], below node's own 5 s keep-alive and far below this
//! service's 60 s (`http.keepAliveTimeoutS`), so a forwarder or a balancer
//! with a shorter one in between is not the one closing it. A connection
//! that dies anyway — a reset, or closed before an answer — is a failure at
//! once, not a hang, and the call is made ONCE more on a new connection
//! ([`stale`]); a timeout is never retried.

use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use reqwest::{Certificate, Client, Method};

use crate::credential::{challenge_error, Credential, Resource};
use crate::options::Options;

/// What came back.
#[derive(Debug, Clone, Default)]
pub struct Answer {
    /// 0 when nothing came back at all.
    pub status: u16,
    pub text: String,
    /// The body as JSON, when it was JSON.
    pub json: Option<serde_json::Value>,
    /// Why nothing (usable) came back.
    pub error: Option<String>,
    /// Nothing came back because the time ran out — told apart from a
    /// refused connection for the AuthZEN forward (#564), which answers 504
    /// for the one and 502 for the other.
    pub timed_out: bool,
    /// The answer's `ETag`, for the proxy pull's `If-None-Match` (#1760).
    pub etag: Option<String>,
    /// The answer's `Retry-After`, passed on with a 429 from the service's
    /// Basic door (#1760).
    pub retry_after: Option<String>,
    /// The answer's `WWW-Authenticate` and `DPoP-Nonce` (RFC 9449).
    pub www_authenticate: Option<String>,
    pub dpop_nonce: Option<String>,
    /// Why an authorized call went WITHOUT an access token, when it did.
    pub no_token: Option<String>,
}

impl Answer {
    fn failed(why: String) -> Answer {
        Answer {
            error: Some(why),
            ..Answer::default()
        }
    }

    fn failed_by(error: &reqwest::Error) -> Answer {
        Answer {
            error: Some(describe(error)),
            timed_out: error.is_timeout(),
            ..Answer::default()
        }
    }

    /// The PDP's `error_description`, when it sent one.
    pub fn error_description(&self) -> Option<String> {
        self.json
            .as_ref()
            .and_then(|j| j.get("error_description"))
            .and_then(|d| d.as_str())
            .map(str::to_string)
    }
}

/// How long a pooled connection to the service may stay idle: below
/// node's default keep-alive (5 s) and this service's (60 s).
const POOL_IDLE: Duration = Duration::from_secs(4);

/// The clients a thread holds, one per [`PdpClient`] recipe. A handful:
/// a process makes one `PdpClient` (tests make more).
const CLIENTS_PER_THREAD: usize = 8;

thread_local! {
    static PDP_CLIENTS: RefCell<Vec<(u64, Client)>> =
        const { RefCell::new(Vec::new()) };
}

/// Every `PdpClient::new` gets its own recipe id.
static RECIPES: AtomicU64 = AtomicU64::new(1);

/// What a thread's client is built from: everything `PdpClient::new` was
/// given, so every thread's verifies the service the same way.
struct Recipe {
    id: u64,
    timeout: Duration,
    user_agent: String,
    insecure: bool,
    anchors: Vec<Certificate>,
}

impl Recipe {
    fn build(&self) -> Result<Client, String> {
        let mut builder = Client::builder()
            .timeout(self.timeout)
            .pool_idle_timeout(POOL_IDLE)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(self.user_agent.clone());
        if self.insecure {
            // The ordinary setting against a development-mode PDP, whose
            // Root is regenerated on every start; logged on every start.
            builder = builder
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true);
        }
        for anchor in &self.anchors {
            builder = builder.add_root_certificate(anchor.clone());
        }
        builder
            .build()
            .map_err(|e| format!("the HTTP client would not build: {}", e))
    }
}

/// The client. Built once at start from the options; its timeout and its
/// answer bound follow the settings the service sets (#1760,
/// `set_limits()`), shared by every clone. The connections are not: each
/// thread has its own pool (see the module header).
#[derive(Clone)]
pub struct PdpClient {
    recipe: Arc<Recipe>,
    /// The client the recipe built at start, for a thread whose own will
    /// not build (it built once, so it will not fail; never a panic).
    fallback: Client,
    base: String,
    limits: Arc<Limits>,
    credential: Arc<Credential>,
}

/// `PEP_TIMEOUT_MS` and `PEP_MAX_BODY_BYTES`, or the service's values.
struct Limits {
    timeout_ms: AtomicU64,
    max_body_bytes: AtomicUsize,
}

impl PdpClient {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(options: &Options) -> Result<PdpClient, String> {
        let anchors = match &options.pdp_ca {
            Some(ca) => Certificate::from_pem_bundle(ca)
                .map_err(|e| format!("PEP_TLS_CA would not load: {}", e))?,
            None => Vec::new(),
        };
        let recipe = Recipe {
            id: RECIPES.fetch_add(1, Ordering::Relaxed),
            timeout: Duration::from_millis(options.timeout_ms),
            user_agent: format!("sts/{} (xacml-pep)", options.version),
            insecure: options.insecure,
            anchors,
        };
        let fallback = recipe.build()?;
        let base = options.pdp_url.trim_end_matches('/').to_string();
        Ok(PdpClient {
            recipe: Arc::new(recipe),
            fallback,
            base,
            credential: Arc::new(Credential::new(options)),
            limits: Arc::new(Limits {
                timeout_ms: AtomicU64::new(options.timeout_ms),
                max_body_bytes: AtomicUsize::new(options.max_body_bytes),
            }),
        })
    }

    /// The credential every clone shares.
    pub fn credential(&self) -> &Arc<Credential> {
        &self.credential
    }

    /// This thread's client: its pool's connections are driven by the
    /// runtime this thread runs, and no other. Hot path: no Entering or
    /// Leaving line, every call to the service passes here.
    fn http(&self) -> Client {
        let id = self.recipe.id;
        PDP_CLIENTS.with(|slot| {
            let mut held = slot.borrow_mut();
            if let Some((_, client)) = held.iter().find(|(i, _)| *i == id) {
                return client.clone();
            }
            let client = match self.recipe.build() {
                Ok(client) => client,
                Err(why) => {
                    tracing::debug!(
                        "xacml-pep: this thread's client to the service \
                         would not build ({}); the process's is used.",
                        why
                    );
                    return self.fallback.clone();
                }
            };
            if held.len() >= CLIENTS_PER_THREAD {
                held.remove(0);
            }
            held.push((id, client.clone()));
            client
        })
    }

    /// [`PdpClient::call_authorized_url`] for `path` under the PDP URL's own
    /// path (a realm prefix included).
    #[tracing::instrument(level = "debug", skip(self, body))]
    pub async fn call_authorized(
        &self,
        resource: Resource,
        method: Method,
        path: &str,
        body: Option<Body>,
    ) -> Answer {
        self.call_authorized_with(resource, method, path, body, &[], None)
            .await
    }

    /// [`PdpClient::call_authorized`] with extra request headers and a
    /// timeout of its own in place of `PEP_TIMEOUT_MS` — the AuthZEN
    /// forward (#564), which carries the caller's `X-Request-ID` and is
    /// bounded by `PEP_AUTHZEN_FORWARD_TIMEOUT_MS`, and a pull's
    /// `If-None-Match`.
    #[tracing::instrument(level = "debug", skip(self, body, headers))]
    pub async fn call_authorized_with(
        &self,
        resource: Resource,
        method: Method,
        path: &str,
        body: Option<Body>,
        headers: &[(&str, String)],
        timeout: Option<Duration>,
    ) -> Answer {
        let url = format!("{}{}", self.base, path);
        self.call_authorized_url(resource, method, &url, body, headers, timeout)
            .await
    }

    /// One call to the service carrying `Authorization: DPoP <token>` for
    /// `resource` and a `DPoP` proof for this method and URL. A 401
    /// `use_dpop_nonce` with a `DPoP-Nonce` is made once more with that
    /// nonce; any other 401 to a call that carried a token (the contract's
    /// `invalid_token`, and a bare 401, which can mean nothing else) drops
    /// the token and is made once more with a new one. No token to be had,
    /// the call goes without one — on the client certificate where there
    /// is one — and `no_token` says why.
    #[tracing::instrument(level = "debug", skip(self, body, headers))]
    pub async fn call_authorized_url(
        &self,
        resource: Resource,
        method: Method,
        url: &str,
        body: Option<Body>,
        headers: &[(&str, String)],
        timeout: Option<Duration>,
    ) -> Answer {
        let role = resource.name();
        let (mut nonce_retried, mut refetched) = (false, false);
        loop {
            let mut all: Vec<(&str, String)> = headers.to_vec();
            let token = self.credential.token(self, resource).await;
            let mut sent: Option<String> = None;
            let mut no_token: Option<String> = None;
            match &token {
                Ok(value) => {
                    let nonce = self.credential.nonce_for(url, role);
                    match self.credential.dpop_proof(
                        method.as_str(),
                        url,
                        Some(value),
                        nonce.as_deref(),
                    ) {
                        Ok(proof) => {
                            all.push((
                                "Authorization",
                                format!("DPoP {}", value),
                            ));
                            all.push(("DPoP", proof));
                            sent = Some(value.clone());
                        }
                        Err(why) => no_token = Some(why),
                    }
                }
                Err(why) => no_token = Some(why.clone()),
            }
            let mut answer = self
                .call_url(method.clone(), url, body.clone(), &all, timeout)
                .await;
            self.credential.remember_nonce(url, role, &answer);
            let Some(sent) = sent else {
                answer.no_token = no_token;
                return answer;
            };
            if answer.error.is_some() || answer.status != 401 {
                return answer;
            }
            let error = answer
                .www_authenticate
                .as_deref()
                .and_then(challenge_error)
                .unwrap_or_default();
            if error == "use_dpop_nonce" {
                if !nonce_retried && answer.dpop_nonce.is_some() {
                    nonce_retried = true;
                    continue;
                }
                self.credential.note_call_problem(
                    "STS-XPEP-0130",
                    &format!(
                        "{} {} demanded a DPoP nonce again after the retry \
                         carrying the one it handed",
                        method,
                        crate::credential::htu(url)
                    ),
                );
                return answer;
            }
            if !refetched {
                self.credential.drop_token(resource, &sent);
                refetched = true;
                continue;
            }
            self.credential.drop_token(resource, &sent);
            self.credential.note_call_problem(
                "STS-XPEP-0131",
                &format!(
                    "{} {} refused a newly issued access token for {} (401{}): \
                     the token endpoint issues it and the resource does not \
                     take it — the PEP's entry may have left the remote PEPs \
                     group, or the service does not yet accept a token there",
                    method,
                    crate::credential::htu(url),
                    resource.name(),
                    if error.is_empty() {
                        String::new()
                    } else {
                        format!(" {}", error)
                    }
                ),
            );
            return answer;
        }
    }

    /// The timeout every call without one of its own is given, and the
    /// largest answer read — moved by a settings pull (#1760).
    pub fn set_limits(&self, timeout_ms: u64, max_body_bytes: usize) {
        self.limits
            .timeout_ms
            .store(timeout_ms.max(1), Ordering::Relaxed);
        self.limits
            .max_body_bytes
            .store(max_body_bytes.max(1), Ordering::Relaxed);
    }

    /// The timeout and bound in force, for a test.
    #[cfg(test)]
    pub fn limits(&self) -> (u64, usize) {
        (
            self.limits.timeout_ms.load(Ordering::Relaxed),
            self.limits.max_body_bytes.load(Ordering::Relaxed),
        )
    }

    /// One call to an ABSOLUTE URL with NO access token: the token request
    /// itself (`credential.rs`) and the realm's JWKS, which the PDP named
    /// in a pull (#1760). Everything else is
    /// [`PdpClient::call_authorized_url`], which ends here. The same
    /// client, so the same certificate where there is one and the same
    /// verification of whoever answers. Never a URL from a request.
    #[tracing::instrument(level = "debug", skip(self, body, headers))]
    pub async fn call_url(
        &self,
        method: Method,
        url: &str,
        body: Option<Body>,
        headers: &[(&str, String)],
        timeout: Option<Duration>,
    ) -> Answer {
        match self
            .send_once(method.clone(), url, body.clone(), headers, timeout)
            .await
        {
            Ok(answer) => answer,
            Err(error) if stale(&error) => {
                // A pooled connection the far end had already closed, or
                // reset under the request: once more, on a new connection
                // (the pool has dropped the dead one). Nothing about the
                // request was answered, so nothing is doubled that the
                // service told this PEP about.
                tracing::debug!(
                    "xacml-pep: {} {} met a closed connection ({}); sent \
                     once more on a new one.",
                    method,
                    crate::credential::htu(url),
                    describe(&error)
                );
                match self.send_once(method, url, body, headers, timeout).await
                {
                    Ok(answer) => answer,
                    Err(error) => Answer::failed_by(&error),
                }
            }
            Err(error) => Answer::failed_by(&error),
        }
    }

    /// One attempt of [`PdpClient::call_url`]: the answer, or the
    /// transport's error for the caller to judge.
    async fn send_once(
        &self,
        method: Method,
        url: &str,
        body: Option<Body>,
        headers: &[(&str, String)],
        timeout: Option<Duration>,
    ) -> Result<Answer, reqwest::Error> {
        // ACCEPT FOLLOWS THE BODY (#1830): the one XML call is the PIP's,
        // `POST /xacml/pip`, whose answers are XACML's XML, so it asks for
        // XML; every other call is to a JSON endpoint. A caller's own Accept
        // wins over both.
        let accept = if headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("accept"))
        {
            None
        } else if matches!(body, Some(Body::Xml(_))) {
            Some("application/xml")
        } else {
            Some("application/json")
        };
        let mut request = self.http().request(method, url);
        if let Some(accept) = accept {
            request = request.header("Accept", accept);
        }
        for (name, value) in headers {
            request = request.header(*name, value.as_str());
        }
        // A call's own timeout wins; otherwise the one in force now, which
        // replaces the client's built-in `PEP_TIMEOUT_MS` per request.
        request = request.timeout(timeout.unwrap_or_else(|| {
            Duration::from_millis(
                self.limits.timeout_ms.load(Ordering::Relaxed),
            )
        }));
        let max_body_bytes = self.limits.max_body_bytes.load(Ordering::Relaxed);
        match body {
            Some(Body::Json(value)) => request = request.json(&value),
            Some(Body::Xml(text)) => {
                request =
                    request.header("Content-Type", "application/xml").body(text)
            }
            Some(Body::Form(pairs)) => {
                request = request
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(form_encoded(&pairs))
            }
            None => {}
        }
        let mut response = request.send().await?;
        let status = response.status().as_u16();
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let etag = header("etag");
        let retry_after = header("retry-after");
        let www_authenticate = header("www-authenticate");
        let dpop_nonce = header("dpop-nonce");
        let mut bytes = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    bytes.extend_from_slice(&chunk);
                    if bytes.len() > max_body_bytes {
                        return Ok(Answer::failed(format!(
                            "the PDP's answer was larger than {} bytes",
                            max_body_bytes
                        )));
                    }
                }
                Ok(None) => break,
                // The answer had begun: never sent again.
                Err(error) => return Ok(Answer::failed_by(&error)),
            }
        }
        let text = String::from_utf8_lossy(&bytes).into_owned();
        // Not JSON is fine: the raw text is what gets reported, which is what
        // a PDP answering an HTML error page or a proxy's message looks like.
        let json = serde_json::from_str(&text).ok();
        Ok(Answer {
            status,
            text,
            json,
            error: None,
            timed_out: false,
            etag,
            retry_after,
            www_authenticate,
            dpop_nonce,
            no_token: None,
        })
    }
}

/// A connection that was dead when the request went on it: reset, closed
/// before any answer, or a pooled one hyper found closed. Never a timeout
/// (the service may still be working on it) and never a refused connect
/// (a new connection would be refused as well).
fn stale(error: &reqwest::Error) -> bool {
    if error.is_timeout() || error.is_connect() {
        return false;
    }
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        if let Some(h) = cause.downcast_ref::<hyper::Error>() {
            if h.is_incomplete_message() || h.is_canceled() || h.is_closed() {
                return true;
            }
        }
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            if matches!(
                io.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::NotConnected
            ) {
                return true;
            }
        }
        source = cause.source();
    }
    false
}

/// A request body. Cloned for a call made once more (`call_authorized`).
#[derive(Clone)]
pub enum Body {
    Json(serde_json::Value),
    Xml(String),
    /// `application/x-www-form-urlencoded`, in the order given — the token
    /// request of the decision records' grant (#1827).
    Form(Vec<(String, String)>),
}

/// The pairs as a form body. `encodeURIComponent` leaves nothing a form
/// reader could misread (`&`, `=`, `+` are all escaped), so it serves.
pub fn form_encoded(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(name, value)| {
            format!(
                "{}={}",
                crate::sync::encode(name),
                crate::sync::encode(value)
            )
        })
        .collect::<Vec<String>>()
        .join("&")
}

/// A transport failure in a sentence, with its cause chain.
fn describe(error: &reqwest::Error) -> String {
    let mut text = error.to_string();
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    if error.is_timeout() {
        text = format!("the PDP did not answer in time ({})", text);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::tests::{decoded, key_file, p256_pem, rsa_pem};
    use crate::credential::KeySource;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::routing::post;
    use serde_json::{json, Value};
    use std::sync::Mutex;

    /// What the mock service saw: each token request's form and proof
    /// claims, and each resource call's `Authorization` and proof claims.
    #[derive(Default)]
    struct Seen {
        forms: Vec<String>,
        token_proofs: Vec<Value>,
        calls: Vec<(String, Value)>,
    }

    /// How the mock answers.
    #[derive(Clone, Copy, Default)]
    struct Script {
        /// `expires_in` of every token.
        expires_in: u64,
        /// The token endpoint asks for a nonce until it is given `as-1`.
        token_nonce: bool,
        /// The resource asks for a nonce until it is given `rs-1`.
        resource_nonce: bool,
        /// The resource refuses every token but this one (0: none).
        accept_only: usize,
        /// The resource refuses every token, always.
        refuse_all: bool,
        /// How long the token endpoint takes.
        token_delay_ms: u64,
        /// The resource asks for a nonce whatever it is given.
        nonce_always: bool,
    }

    fn claims_of(headers: &HeaderMap) -> Value {
        headers
            .get("dpop")
            .and_then(|v| v.to_str().ok())
            .and_then(|p| p.split('.').nth(1))
            .map(decoded)
            .unwrap_or(Value::Null)
    }

    async fn mock(script: Script) -> (String, Arc<Mutex<Seen>>) {
        let seen: Arc<Mutex<Seen>> = Arc::new(Mutex::new(Seen::default()));
        let (on_token, on_call) = (seen.clone(), seen.clone());
        let router = axum::Router::new()
            .route(
                "/realm/r1/oauth2/token",
                post(move |headers: HeaderMap, body: String| {
                    let seen = on_token.clone();
                    async move {
                        tokio::time::sleep(Duration::from_millis(
                            script.token_delay_ms,
                        ))
                        .await;
                        let claims = claims_of(&headers);
                        let n = {
                            let mut seen = seen.lock().unwrap();
                            seen.forms.push(body);
                            seen.token_proofs.push(claims.clone());
                            seen.forms.len()
                        };
                        if script.token_nonce && claims["nonce"] != "as-1" {
                            return (
                                StatusCode::BAD_REQUEST,
                                [("dpop-nonce", "as-1")],
                                axum::Json(
                                    json!({ "error": "use_dpop_nonce" }),
                                ),
                            )
                                .into_response();
                        }
                        axum::Json(json!({
                            "access_token": format!("t-{}", n),
                            "token_type": "DPoP",
                            "expires_in": script.expires_in
                        }))
                        .into_response()
                    }
                }),
            )
            .route(
                "/realm/r1/xacml/pep/heartbeat",
                post(move |headers: HeaderMap| {
                    let seen = on_call.clone();
                    async move {
                        let auth = headers
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string();
                        let claims = claims_of(&headers);
                        seen.lock()
                            .unwrap()
                            .calls
                            .push((auth.clone(), claims.clone()));
                        if script.nonce_always
                            || (script.resource_nonce
                                && claims["nonce"] != "rs-1")
                        {
                            return (
                                StatusCode::UNAUTHORIZED,
                                [
                                    (
                                        "www-authenticate",
                                        "DPoP error=\"use_dpop_nonce\"",
                                    ),
                                    ("dpop-nonce", "rs-1"),
                                ],
                            )
                                .into_response();
                        }
                        let refused = script.refuse_all
                            || (script.accept_only > 0
                                && auth
                                    != format!(
                                        "DPoP t-{}",
                                        script.accept_only
                                    ));
                        if refused {
                            let r: Response = (
                                StatusCode::UNAUTHORIZED,
                                [(
                                    "www-authenticate",
                                    "DPoP error=\"invalid_token\"",
                                )],
                            )
                                .into_response();
                            return r;
                        }
                        axum::Json(json!({ "ok": true })).into_response()
                    }
                }),
            );
        let socket =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        tokio::spawn(async move {
            // Lives as long as the test; a failure shows as the asserts
            // failing, so it is only reported.
            if let Err(error) = axum::serve(socket, router).await {
                eprintln!("the mock service stopped: {}", error);
            }
        });
        (format!("http://127.0.0.1:{}/realm/r1", port), seen)
    }

    fn client(base: &str, pem: Option<Vec<u8>>) -> PdpClient {
        let mut options = Options::from_env("0.0.0");
        options.pdp_url = format!("{}/", base);
        options.name = "remote-pep-1".into();
        options.client_id = "sts-remote-pep".into();
        let file = pem.map(|pem| key_file(&pem));
        options.assertion_key =
            KeySource::choose(file.as_ref().map(|f| f.to_str().unwrap()), None);
        let client = PdpClient::new(&options).unwrap();
        if let Some(file) = file {
            std::fs::remove_file(file).unwrap();
        }
        client
    }

    async fn heartbeat(client: &PdpClient) -> Answer {
        client
            .call_authorized(
                Resource::Pep,
                Method::POST,
                "/xacml/pep/heartbeat",
                Some(Body::Json(json!({}))),
            )
            .await
    }

    #[tokio::test]
    async fn concurrent_callers_share_one_fetch_and_renew_early() {
        let (base, seen) = mock(Script {
            expires_in: 31,
            token_delay_ms: 150,
            ..Script::default()
        })
        .await;
        let c = client(&base, Some(p256_pem()));
        let calls: Vec<_> = (0..8)
            .map(|_| {
                let c = c.clone();
                tokio::spawn(async move { heartbeat(&c).await.status })
            })
            .collect();
        for call in calls {
            assert_eq!(call.await.unwrap(), 200);
        }
        {
            let seen = seen.lock().unwrap();
            assert_eq!(seen.forms.len(), 1, "one fetch for eight callers");
            let form = &seen.forms[0];
            assert!(form.contains("scope=xacml%3Apep"));
            assert!(form.contains(&format!(
                "resource={}",
                crate::sync::encode(&format!("{}/xacml/pep", base))
            )));
            assert!(form.contains("client_id=sts-remote-pep"));
            for (auth, claims) in &seen.calls {
                assert_eq!(auth, "DPoP t-1");
                assert_eq!(claims["htm"], "POST");
                assert_eq!(
                    claims["htu"],
                    format!("{}/xacml/pep/heartbeat", base)
                );
                assert_eq!(claims["ath"], crate::credential::ath("t-1"));
            }
            let jtis: std::collections::HashSet<String> = seen
                .calls
                .iter()
                .map(|(_, c)| c["jti"].as_str().unwrap().to_string())
                .collect();
            assert_eq!(jtis.len(), 8, "a fresh proof on every call");
        }
        let overview = c.credential().overview();
        assert_eq!(overview["tokens"]["xacml-pep"]["held"], true);
        assert!(overview["tokens"]["xacml-pep"]["expiresAt"].is_string());
        assert_eq!(overview["tokens"]["admin-api"]["held"], false);
        assert!(!overview.to_string().contains("t-1"));
        // expires_in 31 is renewed 30 s early: after a second, a new one.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(heartbeat(&c).await.status, 200);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.forms.len(), 2);
        assert_eq!(seen.calls.last().unwrap().0, "DPoP t-2");
    }

    #[tokio::test]
    async fn invalid_token_is_fetched_again_and_retried_once() {
        let (base, seen) = mock(Script {
            expires_in: 300,
            accept_only: 2,
            ..Script::default()
        })
        .await;
        let c = client(&base, Some(rsa_pem()));
        assert_eq!(heartbeat(&c).await.status, 200);
        {
            let seen = seen.lock().unwrap();
            assert_eq!(seen.forms.len(), 2);
            let auths: Vec<&str> =
                seen.calls.iter().map(|(a, _)| a.as_str()).collect();
            assert_eq!(auths, ["DPoP t-1", "DPoP t-2"]);
        }

        // Refused again after the new token: once, no more.
        let (base, seen) = mock(Script {
            expires_in: 300,
            refuse_all: true,
            ..Script::default()
        })
        .await;
        let c = client(&base, Some(rsa_pem()));
        let answer = heartbeat(&c).await;
        assert_eq!(answer.status, 401);
        assert!(answer.no_token.is_none());
        let seen = seen.lock().unwrap();
        assert_eq!(seen.forms.len(), 2);
        assert_eq!(seen.calls.len(), 2);
        assert_eq!(
            c.credential().overview()["tokens"]["xacml-pep"]["held"],
            false
        );
    }

    #[tokio::test]
    async fn use_dpop_nonce_is_retried_once_at_both_ends_and_remembered() {
        let (base, seen) = mock(Script {
            expires_in: 300,
            token_nonce: true,
            resource_nonce: true,
            ..Script::default()
        })
        .await;
        let c = client(&base, Some(p256_pem()));
        assert_eq!(heartbeat(&c).await.status, 200);
        assert_eq!(heartbeat(&c).await.status, 200);
        let seen = seen.lock().unwrap();
        let token_nonces: Vec<&Value> =
            seen.token_proofs.iter().map(|c| &c["nonce"]).collect();
        assert_eq!(token_nonces, [&Value::Null, &json!("as-1")]);
        assert!(seen.token_proofs.iter().all(|c| c.get("ath").is_none()));
        assert_eq!(
            seen.token_proofs[1]["htu"],
            format!("{}/oauth2/token", base)
        );
        let resource_nonces: Vec<&Value> =
            seen.calls.iter().map(|(_, c)| &c["nonce"]).collect();
        // The first call is asked for one; its retry and the next call
        // carry it.
        assert_eq!(
            resource_nonces,
            [&Value::Null, &json!("rs-1"), &json!("rs-1")]
        );
        assert_eq!(
            c.credential()
                .nonce_for(&format!("{}/oauth2/token", base), "token"),
            Some("as-1".to_string())
        );
    }

    #[tokio::test]
    async fn a_nonce_demanded_twice_is_not_retried_again() {
        let (base, seen) = mock(Script {
            expires_in: 300,
            nonce_always: true,
            ..Script::default()
        })
        .await;
        let c = client(&base, Some(p256_pem()));
        assert_eq!(heartbeat(&c).await.status, 401);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.calls.len(), 2, "the call and one retry, no more");
        assert_eq!(seen.calls[1].1["nonce"], "rs-1");
        assert_eq!(seen.forms.len(), 1, "a nonce demand keeps the token");
    }

    #[tokio::test]
    async fn with_no_key_the_call_goes_without_a_token_and_says_why() {
        let (base, seen) = mock(Script {
            expires_in: 300,
            ..Script::default()
        })
        .await;
        let c = client(&base, None);
        let answer = heartbeat(&c).await;
        assert_eq!(answer.status, 200);
        assert!(answer
            .no_token
            .as_deref()
            .unwrap()
            .contains("PEP_ASSERTION_KEY"));
        let seen = seen.lock().unwrap();
        assert!(seen.forms.is_empty(), "no token request without a key");
        assert_eq!(seen.calls[0].0, "");
        assert_eq!(seen.calls[0].1, Value::Null);
    }

    /// ACCEPT FOLLOWS THE BODY (#1830): the PIP's XML query asks for XML,
    /// a JSON call for JSON, and a caller's own Accept is the only one sent.
    #[tokio::test]
    async fn asks_for_the_media_type_it_reads() {
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let record = seen.clone();
        let router = axum::Router::new().fallback(
            move |headers: axum::http::HeaderMap| {
                let record = record.clone();
                async move {
                    let all: Vec<String> = headers
                        .get_all("accept")
                        .iter()
                        .map(|v| v.to_str().unwrap_or("").to_string())
                        .collect();
                    record.lock().unwrap().push(all.join(" | "));
                    "ok"
                }
            },
        );
        let socket =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Err(error) = axum::serve(socket, router).await {
                panic!("stub: {}", error);
            }
        });
        let mut options = Options::from_env("0.0.0");
        options.pdp_url = format!("http://127.0.0.1:{}", port);
        let client = PdpClient::new(&options).unwrap();
        // The plain call every authorized one goes through (#1836), so the
        // rule holds whatever credential a call carries.
        let base = format!("http://127.0.0.1:{}", port);
        client
            .call_url(
                Method::POST,
                &format!("{}/xacml/pip", base),
                Some(Body::Xml("<x/>".into())),
                &[],
                None,
            )
            .await;
        client
            .call_url(
                Method::GET,
                &format!("{}/xacml/pep/policies", base),
                None,
                &[],
                None,
            )
            .await;
        client
            .call_url(
                Method::POST,
                &format!("{}/x", base),
                Some(Body::Json(serde_json::json!({}))),
                &[("accept", "text/plain".to_string())],
                None,
            )
            .await;
        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                "application/xml".to_string(),
                "application/json".to_string(),
                "text/plain".to_string()
            ]
        );
    }

    /// A keep-alive HTTP/1.1 server on plain threads (no runtime of its
    /// own to park anything): it answers `ok` and closes a connection idle
    /// for `idle`, as the service, a forwarder or a balancer does. With
    /// `drop_first`, the first connection's first request is read and the
    /// connection closed without an answer. Answers its port and the
    /// number of connections it accepted.
    fn idle_closing_server(
        idle: Duration,
        drop_first: bool,
    ) -> (u16, Arc<AtomicUsize>) {
        use std::io::{Read, Write};
        let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = accepted.clone();
        std::thread::spawn(move || {
            for stream in server.incoming() {
                let Ok(mut stream) = stream else {
                    continue;
                };
                let n = count.fetch_add(1, Ordering::SeqCst);
                std::thread::spawn(move || {
                    stream.set_read_timeout(Some(idle)).unwrap();
                    let mut seen = Vec::new();
                    let mut buf = [0u8; 4096];
                    loop {
                        // One request: its head, then Content-Length bytes.
                        let end = loop {
                            if let Some(at) =
                                seen.windows(4).position(|w| w == b"\r\n\r\n")
                            {
                                break at + 4;
                            }
                            match stream.read(&mut buf) {
                                Ok(0) | Err(_) => return,
                                Ok(k) => seen.extend_from_slice(&buf[..k]),
                            }
                        };
                        let head = String::from_utf8_lossy(&seen[..end])
                            .to_ascii_lowercase();
                        let length = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        while seen.len() < end + length {
                            match stream.read(&mut buf) {
                                Ok(0) | Err(_) => return,
                                Ok(k) => seen.extend_from_slice(&buf[..k]),
                            }
                        }
                        seen.drain(..end + length);
                        if drop_first && n == 0 {
                            return;
                        }
                        if stream
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\
                                  Connection: keep-alive\r\n\r\nok",
                            )
                            .is_err()
                        {
                            return;
                        }
                    }
                });
            }
        });
        (port, accepted)
    }

    fn plain_client(port: u16, timeout_ms: u64) -> PdpClient {
        let mut options = Options::from_env("0.0.0");
        options.pdp_url = format!("http://127.0.0.1:{}", port);
        options.timeout_ms = timeout_ms;
        PdpClient::new(&options).unwrap()
    }

    /// One call on a current-thread runtime, as a listener worker makes it.
    fn ask_basic(
        rt: &tokio::runtime::Runtime,
        c: &PdpClient,
        port: u16,
    ) -> Answer {
        rt.block_on(c.call_url(
            Method::POST,
            &format!("http://127.0.0.1:{}/xacml/pep/basic", port),
            Some(Body::Json(json!({}))),
            &[],
            None,
        ))
    }

    fn current_thread() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// THE INTERMITTENT 5 s TIMEOUT (STS-XPEP-0075, 2026-11-16),
    /// reproduced: worker A calls the service and goes idle — its runtime
    /// is not polled, as a listener worker's is not between connections —
    /// while the server closes the idle connection; then worker B calls.
    /// With one pool for the process, B was handed A's connection, whose
    /// task nobody drove, and waited out the whole timeout. Each thread has
    /// its own pool now, so B answers at once.
    #[test]
    fn a_call_after_an_idle_spell_does_not_wait_out_the_timeout() {
        let (port, accepted) =
            idle_closing_server(Duration::from_millis(200), false);
        let c = plain_client(port, 5000);
        let (park_tx, park_rx) = std::sync::mpsc::channel::<()>();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<u16>();
        let a = c.clone();
        let worker_a = std::thread::spawn(move || {
            let rt = current_thread();
            done_tx.send(ask_basic(&rt, &a, port).status).unwrap();
            // Idle, the runtime kept and not driven.
            park_rx.recv().unwrap();
            drop(rt);
        });
        assert_eq!(done_rx.recv().unwrap(), 200);
        std::thread::sleep(Duration::from_millis(600));
        let b = c.clone();
        let worker_b = std::thread::spawn(move || {
            let rt = current_thread();
            let started = std::time::Instant::now();
            let answer = ask_basic(&rt, &b, port);
            (answer.status, answer.error, started.elapsed())
        });
        let (status, error, took) = worker_b.join().unwrap();
        park_tx.send(()).unwrap();
        worker_a.join().unwrap();
        assert_eq!(status, 200, "{:?}", error);
        assert!(took < Duration::from_secs(1), "took {:?}", took);
        assert_eq!(accepted.load(Ordering::SeqCst), 2, "B opened its own");
    }

    /// A STALE CONNECTION ON ONE WORKER: the worker's runtime sleeps past
    /// the server's idle close (it is not polled, so the close is unseen),
    /// then calls again on the connection it pooled. That fails at once
    /// rather than hanging, and the call is made once more on a new
    /// connection.
    #[test]
    fn a_stale_pooled_connection_is_replaced_without_a_hang() {
        let (port, accepted) =
            idle_closing_server(Duration::from_millis(200), false);
        let c = plain_client(port, 5000);
        let rt = current_thread();
        assert_eq!(ask_basic(&rt, &c, port).status, 200);
        std::thread::sleep(Duration::from_millis(600));
        let started = std::time::Instant::now();
        let answer = ask_basic(&rt, &c, port);
        assert_eq!(answer.status, 200, "{:?}", answer.error);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(accepted.load(Ordering::SeqCst) >= 2);
    }

    /// A CONNECTION CLOSED UNDER THE REQUEST, before any answer: sent once
    /// more on a new one, answered, and a timeout is still a timeout.
    #[test]
    fn a_connection_closed_before_the_answer_is_sent_once_more() {
        let (port, accepted) =
            idle_closing_server(Duration::from_secs(5), true);
        let c = plain_client(port, 5000);
        let rt = current_thread();
        let started = std::time::Instant::now();
        let answer = ask_basic(&rt, &c, port);
        assert_eq!(answer.status, 200, "{:?}", answer.error);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(accepted.load(Ordering::SeqCst), 2);
    }
}
