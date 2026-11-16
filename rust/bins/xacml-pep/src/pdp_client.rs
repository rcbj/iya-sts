// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! One HTTP client to the PDP, shared by the pull, the registration, the
//! heartbeat and the PIP query — so a PEP cannot verify the PDP for one
//! request and not for another.
//!
//! **The client certificate goes on EVERY call**, not only the registration:
//! the PDP identifies a heartbeat by the certificate exactly as it does a
//! registration, and the pull and the PIP require it outright.
//!
//! **A call never fails**: it answers an [`Answer`] whose `error` says what
//! went wrong, because every caller wants to RECORD what happened and carry
//! on.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use openssl::pkey::PKey;
use reqwest::{Certificate, Client, Identity, Method};

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
            limits: Arc::new(Limits {
                timeout_ms: AtomicU64::new(options.timeout_ms),
                max_body_bytes: AtomicUsize::new(options.max_body_bytes),
            }),
        })
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

    /// `path` is appended to the PDP URL's own path (a realm prefix
    /// included).
    #[tracing::instrument(level = "debug", skip(self, body))]
    pub async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Body>,
    ) -> Answer {
        self.call_with(method, path, body, &[], None).await
    }

    /// [`PdpClient::call`] with extra request headers and a timeout of its
    /// own in place of `PEP_TIMEOUT_MS` — the AuthZEN forward (#564), which
    /// carries the caller's `X-Request-ID` and is bounded by
    /// `PEP_AUTHZEN_FORWARD_TIMEOUT_MS`. The same client, so the same
    /// certificate and the same verification of the PDP.
    #[tracing::instrument(level = "debug", skip(self, body, headers))]
    pub async fn call_with(
        &self,
        method: Method,
        path: &str,
        body: Option<Body>,
        headers: &[(&str, String)],
        timeout: Option<Duration>,
    ) -> Answer {
        let url = format!("{}{}", self.base, path);
        self.call_url(method, &url, body, headers, timeout).await
    }

    /// One call to an ABSOLUTE URL the PDP named in a pull (#1760: the
    /// realm's JWKS and token endpoint, the four validation endpoints) —
    /// through the same client, so the same certificate and the same
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
        let mut request = self.http.request(method, url);
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
        }
    }
}

/// A request body.
pub enum Body {
    Json(serde_json::Value),
    Xml(String),
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
    use std::sync::Mutex;

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
        client
            .call(Method::POST, "/xacml/pip", Some(Body::Xml("<x/>".into())))
            .await;
        client.call(Method::GET, "/xacml/pep/policies", None).await;
        client
            .call_with(
                Method::POST,
                "/x",
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
}
