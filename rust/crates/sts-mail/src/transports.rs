// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The five ways a message leaves (`common/mail_transports.ts`): capture,
//! an SMTP relay, Amazon SES v2, Azure Communication Services Email and the
//! Gmail API, each behind [`Transport::send`].
//!
//! **WHAT IS PORTED AND WHAT IS A PORT.** The message (composed once,
//! [`crate::compose`]), its DKIM signature (`sts_crypto::dkim`, prepended),
//! what each provider is handed (SES's raw bytes, Gmail's base64url, Azure's
//! structured request), the build refusals and the failure classifiers are
//! here and proved against Node. The network half — an SMTP session that is
//! STARTTLS-required or implicit TLS with the relay's certificate verified
//! (TLS 1.2 at the least), and each provider's authenticated HTTPS call — is
//! a trait ([`SmtpRelay`], [`CloudMail`]) the runtime implements, with
//! `lettre` and `reqwest` (DESIGN.md section 7). Node's nodemailer and SDK
//! calls are what those traits stand for, one for one.

use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_core::errors::{codes, ErrorCode};

use crate::compose::{self, OutMessage};

static TLS_FAILURE: std::sync::LazyLock<Option<regex::Regex>> =
    std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)certificate|self.signed|unable to verify|CERT_|altnames",
        )
        .ok()
    });

/// A failure, its code, and whether another attempt is worth making
/// (`sendError()`).
#[derive(Debug, Clone, PartialEq)]
pub struct SendError {
    pub message: String,
    pub code: ErrorCode,
    pub retry: Option<bool>,
}

impl SendError {
    /// `sendError(message, code, retry)`.
    pub fn new(message: impl Into<String>, code: ErrorCode, retry: bool) -> Self {
        SendError {
            message: message.into(),
            code,
            retry: Some(retry),
        }
    }
}

/// What a transport answers: the provider's id for the message.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Sent {
    pub provider_id: String,
    pub detail: String,
}

/// A future a port answers.
pub type BoxFuture<'a, T> = sts_cluster::schedule::BoxFuture<'a, T>;

/// One way a message leaves.
pub trait Transport: Send + Sync {
    fn name(&self) -> &str;
    fn send<'a>(
        &'a self,
        message: &'a OutMessage,
    ) -> BoxFuture<'a, Result<Sent, SendError>>;
}

/// `addressProblem(address)`: what is wrong with an address a message may
/// carry, or `''` — one plain mailbox, RFC 5321's limits.
#[tracing::instrument(level = "debug")]
pub fn address_problem(address: &str) -> String {
    let a = address;
    let separators = |c: char| {
        crate::js::is_space(c) || "<>,;:\"()[]\\".contains(c)
    };
    if a.is_empty() || crate::js::len(a) > 254 || a.chars().any(separators) {
        return "is not one plain mailbox address".to_string();
    }
    let at = match a.rfind('@') {
        Some(at) => crate::js::len(&a[..at]),
        None => 0,
    };
    let domain = a.rfind('@').map(|i| &a[i + 1..]).unwrap_or("");
    let label_ok = |l: &str| {
        let b = l.as_bytes();
        !b.is_empty()
            && b[0].is_ascii_alphanumeric()
            && b[b.len() - 1].is_ascii_alphanumeric()
            && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
    };
    let labels: Vec<&str> = domain.split('.').collect();
    let domain_ok = labels.len() >= 2 && labels.iter().all(|l| label_ok(l));
    if a.rfind('@').is_none()
        || at < 1
        || at > 64
        || domain.is_empty()
        || !domain_ok
    {
        return "has no local part and domain".to_string();
    }
    String::new()
}

/// The capture transport: sends nothing; the outbox keeps the message.
pub struct Capture;

impl Transport for Capture {
    fn name(&self) -> &str {
        "capture"
    }
    fn send<'a>(
        &'a self,
        message: &'a OutMessage,
    ) -> BoxFuture<'a, Result<Sent, SendError>> {
        Box::pin(async move {
            Ok(Sent {
                provider_id: message.message_id.clone(),
                detail: "captured, not sent".to_string(),
            })
        })
    }
}

/// An SMTP failure as the session reports it (nodemailer's error).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SmtpFailure {
    /// `EAUTH`, `ETLS`, … or `''`.
    pub code: String,
    pub response_code: u16,
    pub response: String,
    pub message: String,
}

/// What a relay answered a delivered message.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SmtpAccepted {
    pub message_id: String,
    pub response: String,
    pub rejected: Vec<String>,
}

/// THE SMTP SESSION (nodemailer's `createTransport()` and `sendMail()`):
/// STARTTLS required (`requireTLS`) or implicit TLS, the relay's
/// certificate verified against the host name (or `mail.smtpServerName`)
/// and the system store plus `mail.smtpCaFile`, TLS 1.2 at the least, the
/// envelope as given and the raw bytes as they are. The runtime's
/// implementation is `lettre`'s.
pub trait SmtpRelay: Send + Sync {
    fn send<'a>(
        &'a self,
        from: &'a str,
        to: &'a str,
        raw: &'a [u8],
    ) -> BoxFuture<'a, Result<SmtpAccepted, SmtpFailure>>;
}

/// How the SMTP session is opened (`createTransport()`'s options).
#[derive(Debug, Clone, PartialEq)]
pub struct SmtpOptions {
    pub host: String,
    pub port: i64,
    pub implicit_tls: bool,
    pub server_name: String,
    pub timeout_ms: i64,
    /// `{ user, method }`, or `None` for no login.
    pub auth: Option<(String, String)>,
}

/// `classifySmtp(e)`: a refused login, a TLS failure or a 5xx is final, a
/// 4xx or anything else is worth repeating.
#[tracing::instrument(level = "debug")]
pub fn classify_smtp(e: &SmtpFailure) -> SendError {
    let why = if !e.response.is_empty() {
        e.response.clone()
    } else {
        e.message.clone()
    };
    let tlsish = TLS_FAILURE.as_ref().is_some_and(|re| re.is_match(&why));
    if e.code == "EAUTH" {
        SendError::new(format!("the relay refused the login: {}", why),
                       codes::STS_MAIL_0021, false)
    } else if e.code == "ETLS" || tlsish {
        SendError::new(
            format!("TLS with the relay failed, and nothing is sent in the \
                     clear: {}", why),
            codes::STS_MAIL_0014, false)
    } else if e.response_code >= 500 {
        SendError::new(
            format!("the relay refused the message ({}): {}", e.response_code,
                    why),
            codes::STS_MAIL_0008, false)
    } else if e.response_code >= 400 {
        SendError::new(
            format!("the relay deferred the message ({}): {}",
                    e.response_code, why),
            codes::STS_MAIL_0009, true)
    } else {
        SendError::new(format!("the SMTP transaction failed: {}", why),
                       codes::STS_MAIL_0009, true)
    }
}

/// A cloud SDK's failure, as the SDK reports it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CloudFailure {
    pub name: String,
    pub message: String,
    pub status: i64,
    pub retryable: bool,
}

/// `classifyCloud(e, who)`: the SDK's retryable flag, throttling, a 5xx
/// or a 429 is worth repeating; anything else is final.
#[tracing::instrument(level = "debug")]
pub fn classify_cloud(e: &CloudFailure, who: &str) -> SendError {
    let hay = format!("{} {}", e.name, e.message).to_lowercase();
    let words = ["throttl", "toomanyrequests", "serviceunavailable",
                 "requesttimeout", "econn", "etimedout", "enotfound",
                 "eai_again", "socket"];
    let retry = e.retryable
        || e.status == 429
        || e.status >= 500
        || words.iter().any(|w| hay.contains(w));
    let why = format!(
        "{} refused the message: {}{}",
        who,
        if e.name.is_empty() {
            String::new()
        } else {
            format!("{}: ", e.name)
        },
        e.message
    );
    SendError::new(
        why,
        if retry { codes::STS_MAIL_0009 } else { codes::STS_MAIL_0008 },
        retry,
    )
}

/// The DKIM signing configuration: the realm's domain, selector,
/// algorithm and key.
#[derive(Clone)]
pub struct Dkim {
    pub domain: String,
    pub selector: String,
    pub algorithm: String,
    pub private_key_pem: String,
}

/// The message as it leaves: composed, and DKIM-signed where configured,
/// the signature prepended (`smtp().send()`). `now_ms` is the signature's
/// `t=`; `boundary` is the composer's base boundary.
#[tracing::instrument(level = "debug", skip(message, dkim))]
pub fn raw_message(
    message: &OutMessage,
    dkim: Option<&Dkim>,
    boundary: &str,
    now_ms: i64,
) -> Result<Vec<u8>, SendError> {
    let raw = compose::compose(message, boundary);
    let Some(dkim) = dkim else {
        return Ok(raw);
    };
    let header = dkim_header(&raw, dkim, now_ms).map_err(|e| {
        SendError::new(
            format!("the message could not be DKIM-signed: {}", e),
            codes::STS_MAIL_0022,
            false,
        )
    })?;
    let mut out = format!("{}\r\n", header).into_bytes();
    out.extend_from_slice(&raw);
    Ok(out)
}

fn dkim_header(raw: &[u8], dkim: &Dkim, now_ms: i64) -> Result<String, String> {
    let key = sts_crypto::keys::JwsKey::from_pem(&dkim.private_key_pem)
        .map_err(|e| e.to_string())?;
    let sts_crypto::keys::Material::Private(private) = &key.material else {
        return Err("the DKIM key is not a private key".to_string());
    };
    let options = sts_crypto::dkim::DkimOptions {
        selector: &dkim.selector,
        domain: &dkim.domain,
        algorithm: Some(dkim.algorithm.as_str()).filter(|a| !a.is_empty()),
        timestamp: Some((now_ms.max(0) / 1000) as u64),
    };
    sts_crypto::dkim::dkim_sign(raw, private, &options)
        .map_err(|e| e.to_string())
}

/// The SMTP transport: the composed, signed message handed to the relay.
pub struct Smtp {
    relay: Arc<dyn SmtpRelay>,
    dkim: Option<Dkim>,
    clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    boundary: Arc<dyn Fn() -> String + Send + Sync>,
}

impl Smtp {
    /// From the session, the DKIM configuration, the clock the signature's
    /// `t=` is read from and the boundary source.
    pub fn new(
        relay: Arc<dyn SmtpRelay>,
        dkim: Option<Dkim>,
        clock: Arc<dyn Fn() -> i64 + Send + Sync>,
        boundary: Arc<dyn Fn() -> String + Send + Sync>,
    ) -> Smtp {
        Smtp {
            relay,
            dkim,
            clock,
            boundary,
        }
    }
}

impl Transport for Smtp {
    fn name(&self) -> &str {
        "smtp"
    }
    fn send<'a>(
        &'a self,
        message: &'a OutMessage,
    ) -> BoxFuture<'a, Result<Sent, SendError>> {
        Box::pin(self.deliver(message))
    }
}

impl Smtp {
    async fn deliver(&self, message: &OutMessage) -> Result<Sent, SendError> {
        let raw = raw_message(message, self.dkim.as_ref(), &(self.boundary)(),
                              (self.clock)())?;
        let info = self
            .relay
            .send(&message.from, &message.to, &raw)
            .await
            .map_err(|e| classify_smtp(&e))?;
        if !info.rejected.is_empty() {
            return Err(SendError::new(
                format!("the relay rejected the recipient: {}", info.response),
                codes::STS_MAIL_0008,
                false,
            ));
        }
        Ok(Sent {
            provider_id: if info.message_id.is_empty() {
                message.message_id.clone()
            } else {
                info.message_id
            },
            detail: info.response,
        })
    }
}

/// A cloud provider's send call: SES's `SendEmail`, Azure's `beginSend`
/// polled to a terminal status, Gmail's `users.messages.send`. The request
/// is the JSON this module builds; the answer is the provider's id.
pub trait CloudMail: Send + Sync {
    fn send<'a>(
        &'a self,
        request: &'a Json,
    ) -> BoxFuture<'a, Result<Json, CloudFailure>>;
}

/// The cloud transports' requests (`ses()`, `acs()`, `gmail()`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cloud {
    Ses,
    Acs,
    Gmail,
}

/// What a cloud transport hands its provider for one message.
#[tracing::instrument(level = "debug", skip(message, raw))]
pub fn cloud_request(
    cloud: Cloud,
    message: &OutMessage,
    raw: &[u8],
    configuration_set: &str,
) -> Json {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine;
    match cloud {
        Cloud::Ses => {
            let mut input = json!({
                "FromEmailAddress": message.from,
                "Destination": { "ToAddresses": [message.to] },
                "Content": { "Raw": { "Data": STANDARD.encode(raw) } }
            });
            if !configuration_set.is_empty() {
                input["ConfigurationSetName"] = json!(configuration_set);
            }
            input
        }
        Cloud::Acs => json!({
            "senderAddress": message.from,
            "content": { "subject": message.subject,
                         "plainText": message.text, "html": message.html },
            "recipients": { "to": [{ "address": message.to }] },
            "headers": { "Auto-Submitted": "auto-generated" },
            "userEngagementTrackingDisabled": true
        }),
        Cloud::Gmail => json!({
            "userId": "me",
            "requestBody": { "raw": URL_SAFE_NO_PAD.encode(raw) }
        }),
    }
}
