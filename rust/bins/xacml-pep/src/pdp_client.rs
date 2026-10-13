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
}

impl Answer {
    fn failed(why: String) -> Answer {
        Answer {
            error: Some(why),
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

/// The client. Built once at start from the options.
#[derive(Clone)]
pub struct PdpClient {
    http: Client,
    base: String,
    max_body_bytes: usize,
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
            max_body_bytes: options.max_body_bytes,
        })
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
        let url = format!("{}{}", self.base, path);
        let mut request = self
            .http
            .request(method, &url)
            .header("Accept", "application/json");
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
            Err(error) => return Answer::failed(describe(&error)),
        };
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    bytes.extend_from_slice(&chunk);
                    if bytes.len() > self.max_body_bytes {
                        return Answer::failed(format!(
                            "the PDP's answer was larger than {} bytes",
                            self.max_body_bytes
                        ));
                    }
                }
                Ok(None) => break,
                Err(error) => return Answer::failed(describe(&error)),
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
