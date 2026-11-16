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
//! **The client certificate goes on every call WHILE `PEP_TLS_CERT` IS
//! SET**, as it always did: the service accepts it or the token, so a PEP
//! that has both presents both, and one whose token cannot be had (no
//! registered key yet) is still identified by its certificate.
//!
//! **A call never fails**: it answers an [`Answer`] whose `error` says what
//! went wrong, because every caller wants to RECORD what happened and carry
//! on.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use openssl::pkey::PKey;
use reqwest::{Certificate, Client, Identity, Method};

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

/// The client. Built once at start from the options; its timeout and its
/// answer bound follow the settings the service sets (#1760,
/// `set_limits()`), shared by every clone.
#[derive(Clone)]
pub struct PdpClient {
    http: Client,
    base: String,
    limits: Arc<Limits>,
    credential: Arc<Credential>,
}

/// `PEP_TIMEOUT_MS` and `PEP_MAX_BODY_BYTES`, or the service's values.
struct Limits {
    timeout_ms: AtomicU64,
    max_body_bytes: AtomicUsize,
}

/// The client key in PKCS #8, whatever form it was written in — OpenSSL
/// reads PKCS #1, SEC 1 and PKCS #8 alike.
fn pkcs8(key: &[u8]) -> Result<Vec<u8>, String> {
    PKey::private_key_from_pem(key)
        .and_then(|k| k.private_key_to_pem_pkcs8())
        .map_err(|e| format!("the client key would not load: {}", e))
}

impl PdpClient {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(options: &Options) -> Result<PdpClient, String> {
        let mut builder = Client::builder()
            .timeout(Duration::from_millis(options.timeout_ms))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(format!("sts/{} (xacml-pep)", options.version));
        if options.insecure {
            // The ordinary setting against a development-mode PDP, whose
            // Root is regenerated on every start; logged on every start.
            builder = builder
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true);
        }
        if let Some(ca) = &options.pdp_ca {
            let anchors = Certificate::from_pem_bundle(ca)
                .map_err(|e| format!("PEP_TLS_CA would not load: {}", e))?;
            for anchor in anchors {
                builder = builder.add_root_certificate(anchor);
            }
        }
        if let (Some(cert), Some(key)) =
            (&options.client_certificate, &options.client_key)
        {
            let identity = Identity::from_pkcs8_pem(cert, &pkcs8(key)?)
                .map_err(|e| {
                    format!(
                        "the client certificate would not \
                                      load: {}",
                        e
                    )
                })?;
            builder = builder.identity(identity);
        }
        let http = builder
            .build()
            .map_err(|e| format!("the HTTP client would not build: {}", e))?;
        let base = options.pdp_url.trim_end_matches('/').to_string();
        Ok(PdpClient {
            http,
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
                            all.push(("Authorization", format!("DPoP {}", value)));
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
                        method, crate::credential::htu(url)
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
        let mut request = self
            .http
            .request(method, url)
            .header("Accept", "application/json");
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
        let mut response = match request.send().await {
            Ok(response) => response,
            Err(error) => return Answer::failed_by(&error),
        };
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
                        return Answer::failed(format!(
                            "the PDP's answer was larger than {} bytes",
                            max_body_bytes
                        ));
                    }
                }
                Ok(None) => break,
                Err(error) => return Answer::failed_by(&error),
            }
        }
        let text = String::from_utf8_lossy(&bytes).into_owned();
        // Not JSON is fine: the raw text is what gets reported, which is what
        // a PDP answering an HTML error page or a proxy's message looks like.
        let json = serde_json::from_str(&text).ok();
        Answer {
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
        }
    }
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
