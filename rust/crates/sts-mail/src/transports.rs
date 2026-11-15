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
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(
        message: impl Into<String>,
        code: ErrorCode,
        retry: bool,
    ) -> Self {
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
    let separators =
        |c: char| crate::js::is_space(c) || "<>,;:\"()[]\\".contains(c);
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
        || !(1..=64).contains(&at)
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

/// How the SMTP session is opened (`createTransport()`'s options): never
/// in the clear — STARTTLS required where not implicit TLS — the relay's
/// certificate verified against `server_name` and the system store plus
/// `ca_pem`, TLS 1.2 at the least.
#[derive(Debug, Clone, PartialEq)]
pub struct SmtpOptions {
    pub host: String,
    pub port: i64,
    pub implicit_tls: bool,
    pub require_tls: bool,
    pub server_name: String,
    pub min_tls: String,
    pub timeout_ms: i64,
    pub ca_pem: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
    pub auth: Option<SmtpAuth>,
}

/// The SMTP login (`auth`).
#[derive(Debug, Clone, PartialEq)]
pub enum SmtpAuth {
    /// `PLAIN` or `LOGIN`, with the password.
    Password {
        user: String,
        pass: String,
        method: String,
    },
    /// XOAUTH2 with an access token, or the refresh parameters a token is
    /// fetched with.
    OAuth2 {
        user: String,
        access_token: String,
        refresh: Json,
    },
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
        SendError::new(
            format!("the relay refused the login: {}", why),
            codes::STS_MAIL_0021,
            false,
        )
    } else if e.code == "ETLS" || tlsish {
        SendError::new(
            format!(
                "TLS with the relay failed, and nothing is sent in the \
                     clear: {}",
                why
            ),
            codes::STS_MAIL_0014,
            false,
        )
    } else if e.response_code >= 500 {
        SendError::new(
            format!(
                "the relay refused the message ({}): {}",
                e.response_code, why
            ),
            codes::STS_MAIL_0008,
            false,
        )
    } else if e.response_code >= 400 {
        SendError::new(
            format!(
                "the relay deferred the message ({}): {}",
                e.response_code, why
            ),
            codes::STS_MAIL_0009,
            true,
        )
    } else {
        SendError::new(
            format!("the SMTP transaction failed: {}", why),
            codes::STS_MAIL_0009,
            true,
        )
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
    let words = [
        "throttl",
        "toomanyrequests",
        "serviceunavailable",
        "requesttimeout",
        "econn",
        "etimedout",
        "enotfound",
        "eai_again",
        "socket",
    ];
    let retry = e.retryable
        || e.status == 429
        || e.status >= 500
        || words.iter().any(|w| hay.contains(w));
    // `String(e.message || e)`: an error with no message is its name.
    let said = if e.message.is_empty() {
        &e.name
    } else {
        &e.message
    };
    let why = format!(
        "{} refused the message: {}{}",
        who,
        if e.name.is_empty() {
            String::new()
        } else {
            format!("{}: ", e.name)
        },
        said
    );
    SendError::new(
        why,
        if retry {
            codes::STS_MAIL_0009
        } else {
            codes::STS_MAIL_0008
        },
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
    #[tracing::instrument(level = "debug", skip_all)]
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
        let raw = raw_message(
            message,
            self.dkim.as_ref(),
            &(self.boundary)(),
            (self.clock)(),
        )?;
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

/// The mail secrets (`common/secrets.js`'s `MAIL_*` specs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Secret {
    SmtpPassword,
    DkimKey,
    AcsConnectionString,
    GmailKey,
}

/// `readSecret(spec)`: the secret's text, or `None` where its provider is
/// `none`.
pub trait MailSecrets: Send + Sync {
    fn read(&self, which: Secret) -> BoxFuture<'_, Option<String>>;
}

/// Opens the SMTP session `build()` describes (nodemailer's
/// `createTransport()`); the runtime's is `lettre`'s.
pub trait RelayFactory: Send + Sync {
    fn open(&self, options: &SmtpOptions) -> Arc<dyn SmtpRelay>;
}

/// A cloud provider's client, authenticated: SES by the default credential
/// chain, Azure by its connection string or a managed identity, Gmail by a
/// service account with domain-wide delegation impersonating `subject`.
pub trait CloudFactory: Send + Sync {
    fn client(
        &self,
        cloud: Cloud,
        cfg: &Json,
        credential: Option<&str>,
    ) -> Result<Arc<dyn CloudMail>, SendError>;
}

/// Reads a named file (`outbound_tls.assertNamedFile()` first).
pub trait FileReader: Send + Sync {
    fn read(&self, path: &str) -> Result<String, String>;
}

/// `MailTransports.build(cfg)` over its ports.
pub struct Builder {
    pub secrets: Arc<dyn MailSecrets>,
    pub relays: Arc<dyn RelayFactory>,
    pub clouds: Arc<dyn CloudFactory>,
    pub files: Arc<dyn FileReader>,
    pub clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    pub boundary: Arc<dyn Fn() -> String + Send + Sync>,
}

fn text(cfg: &Json, key: &str) -> String {
    match cfg.get(key) {
        Some(Json::String(s)) => s.clone(),
        Some(Json::Null) | None => String::new(),
        Some(other) => crate::js::string_of(other),
    }
}

impl crate::channel::TransportBuilder for Builder {
    fn build<'a>(
        &'a self,
        cfg: &'a Json,
    ) -> BoxFuture<'a, Result<Arc<dyn Transport>, SendError>> {
        Box::pin(self.build_one(cfg))
    }
}

impl Builder {
    async fn build_one(
        &self,
        cfg: &Json,
    ) -> Result<Arc<dyn Transport>, SendError> {
        match text(cfg, "transport").as_str() {
            "capture" => Ok(Arc::new(Capture)),
            "smtp" => self.smtp(cfg).await,
            "ses" => {
                let client = self.clouds.client(Cloud::Ses, cfg, None)?;
                Ok(Arc::new(CloudTransport::new(
                    Cloud::Ses,
                    client,
                    cfg,
                    self.boundary.clone(),
                )))
            }
            "acs" => {
                let credential = if text(cfg, "acsAuth") == "connection-string"
                {
                    let Some(c) = self
                        .secrets
                        .read(Secret::AcsConnectionString)
                        .await
                        .filter(|c| !c.is_empty())
                    else {
                        return Err(SendError::new(
                            "mail.acsAuth is \"connection-string\" and \
                             mail.acsConnectionStringProvider is \"none\"",
                            codes::STS_MAIL_0004,
                            false,
                        ));
                    };
                    Some(c)
                } else {
                    if !text(cfg, "acsEndpoint").starts_with("https://") {
                        return Err(SendError::new(
                            "managed-identity authentication needs \
                             mail.acsEndpoint, an https URL",
                            codes::STS_MAIL_0004,
                            false,
                        ));
                    }
                    None
                };
                let client = self.clouds.client(
                    Cloud::Acs,
                    cfg,
                    credential.as_deref(),
                )?;
                Ok(Arc::new(CloudTransport::new(
                    Cloud::Acs,
                    client,
                    cfg,
                    self.boundary.clone(),
                )))
            }
            "gmail" => {
                let Some(key) = self
                    .secrets
                    .read(Secret::GmailKey)
                    .await
                    .filter(|k| !k.is_empty())
                else {
                    return Err(SendError::new(
                        "the gmail transport needs the service account key \
                         (mail.gmailKeyProvider)",
                        codes::STS_MAIL_0004,
                        false,
                    ));
                };
                let parsed: Option<Json> = serde_json::from_str(&key).ok();
                let usable = parsed.as_ref().is_some_and(|k| {
                    k.get("client_email")
                        .and_then(Json::as_str)
                        .is_some_and(|s| !s.is_empty())
                        && k.get("private_key")
                            .and_then(Json::as_str)
                            .is_some_and(|s| !s.is_empty())
                });
                if !usable {
                    return Err(SendError::new(
                        "the Gmail service account key is not a JSON key with \
                         client_email and private_key",
                        codes::STS_MAIL_0004,
                        false,
                    ));
                }
                let client =
                    self.clouds.client(Cloud::Gmail, cfg, Some(&key))?;
                Ok(Arc::new(CloudTransport::new(
                    Cloud::Gmail,
                    client,
                    cfg,
                    self.boundary.clone(),
                )))
            }
            _ => Err(SendError::new(
                format!(
                    "no mail transport is configured (mail.transport is \
                         \"{}\")",
                    text(cfg, "setting")
                ),
                codes::STS_MAIL_0001,
                false,
            )),
        }
    }

    async fn smtp(&self, cfg: &Json) -> Result<Arc<dyn Transport>, SendError> {
        let host = text(cfg, "smtpHost");
        if host.is_empty() {
            return Err(SendError::new(
                "the smtp transport has no host (mail.smtpHost, or a preset)",
                codes::STS_MAIL_0004,
                false,
            ));
        }
        let server = text(cfg, "smtpServerName");
        let mut options = SmtpOptions {
            host: host.clone(),
            port: cfg.get("smtpPort").and_then(Json::as_i64).unwrap_or(0),
            implicit_tls: text(cfg, "smtpTls") == "implicit",
            require_tls: text(cfg, "smtpTls") != "implicit",
            server_name: if server.is_empty() {
                host.clone()
            } else {
                server
            },
            min_tls: "TLSv1.2".to_string(),
            timeout_ms: cfg
                .get("timeoutMs")
                .and_then(Json::as_i64)
                .unwrap_or(0),
            ca_pem: String::new(),
            client_cert_pem: String::new(),
            client_key_pem: String::new(),
            auth: None,
        };
        let mut files = || -> Result<(), String> {
            let ca = text(cfg, "smtpCaFile");
            if !ca.is_empty() {
                options.ca_pem = self.files.read(&ca)?;
            }
            let (cert, key) = (
                text(cfg, "smtpClientCertFile"),
                text(cfg, "smtpClientKeyFile"),
            );
            if !cert.is_empty() || !key.is_empty() {
                if cert.is_empty() || key.is_empty() {
                    return Err("mail.smtpClientCertFile and \
                                mail.smtpClientKeyFile are set together or \
                                not at all"
                        .to_string());
                }
                options.client_cert_pem = self.files.read(&cert)?;
                options.client_key_pem = self.files.read(&key)?;
            }
            Ok(())
        };
        if let Err(e) = files() {
            return Err(SendError::new(
                format!(
                    "the smtp transport's TLS files could not be read: {}",
                    e
                ),
                codes::STS_MAIL_0004,
                false,
            ));
        }
        let auth = text(cfg, "smtpAuth");
        if !auth.is_empty() && auth != "none" {
            let Some(secret) = self
                .secrets
                .read(Secret::SmtpPassword)
                .await
                .filter(|s| !s.is_empty())
            else {
                return Err(SendError::new(
                    format!(
                        "mail.smtpAuth is \"{}\" and \
                             mail.smtpPasswordProvider is \"none\", so there \
                             is nothing to log in with",
                        auth
                    ),
                    codes::STS_MAIL_0004,
                    false,
                ));
            };
            let user = text(cfg, "smtpUser");
            options.auth = Some(if auth == "xoauth2" {
                match serde_json::from_str::<Json>(&secret)
                    .ok()
                    .filter(Json::is_object)
                {
                    Some(refresh) => SmtpAuth::OAuth2 {
                        user,
                        access_token: String::new(),
                        refresh,
                    },
                    None => SmtpAuth::OAuth2 {
                        user,
                        access_token: secret,
                        refresh: Json::Null,
                    },
                }
            } else {
                SmtpAuth::Password {
                    user,
                    pass: secret,
                    method: if auth == "plain" { "PLAIN" } else { "LOGIN" }
                        .to_string(),
                }
            });
        }
        let mut dkim = None;
        let domain = text(cfg, "dkimDomain");
        if !domain.is_empty() {
            let key =
                self.secrets.read(Secret::DkimKey).await.unwrap_or_default();
            let selector = text(cfg, "dkimSelector");
            if key.is_empty() || selector.is_empty() {
                return Err(SendError::new(
                    format!(
                        "mail.dkimDomain is set, so every message must \
                             be signed, and {}",
                        if key.is_empty() {
                            "no DKIM key is configured \
                                  (mail.dkimKeyProvider)"
                        } else {
                            "mail.dkimSelector is empty"
                        }
                    ),
                    codes::STS_MAIL_0022,
                    false,
                ));
            }
            let made = Dkim {
                domain: domain.clone(),
                selector,
                algorithm: text(cfg, "dkimAlgorithm"),
                private_key_pem: key,
            };
            let probe = format!("From: probe@{}\r\n\r\n", domain);
            if let Err(e) = dkim_header(probe.as_bytes(), &made, (self.clock)())
            {
                return Err(SendError::new(
                    format!("the DKIM key cannot sign: {}", e),
                    codes::STS_MAIL_0022,
                    false,
                ));
            }
            dkim = Some(made);
        }
        let relay = self.relays.open(&options);
        Ok(Arc::new(Smtp::new(
            relay,
            dkim,
            self.clock.clone(),
            self.boundary.clone(),
        )))
    }
}

/// SES, Azure or Gmail: the request built here, the call the client's.
pub struct CloudTransport {
    cloud: Cloud,
    client: Arc<dyn CloudMail>,
    configuration_set: String,
    boundary: Arc<dyn Fn() -> String + Send + Sync>,
}

impl CloudTransport {
    /// From the client and the realm's settings.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(
        cloud: Cloud,
        client: Arc<dyn CloudMail>,
        cfg: &Json,
        boundary: Arc<dyn Fn() -> String + Send + Sync>,
    ) -> CloudTransport {
        CloudTransport {
            cloud,
            client,
            configuration_set: text(cfg, "sesConfigurationSet"),
            boundary,
        }
    }

    async fn deliver(&self, message: &OutMessage) -> Result<Sent, SendError> {
        let raw = compose::compose(message, &(self.boundary)());
        let request =
            cloud_request(self.cloud, message, &raw, &self.configuration_set);
        let who = match self.cloud {
            Cloud::Ses => "SES",
            Cloud::Acs => "Azure Communication Services",
            Cloud::Gmail => "the Gmail API",
        };
        let out = self
            .client
            .send(&request)
            .await
            .map_err(|e| classify_cloud(&e, who))?;
        let id = |v: Option<&Json>| {
            v.and_then(Json::as_str).unwrap_or("").to_string()
        };
        match self.cloud {
            Cloud::Ses => Ok(Sent {
                provider_id: id(out.get("MessageId")),
                detail: String::new(),
            }),
            Cloud::Gmail => Ok(Sent {
                provider_id: id(out.get("data").and_then(|d| d.get("id"))),
                detail: String::new(),
            }),
            Cloud::Acs => {
                let status = id(out.get("status"));
                if status != "Succeeded" {
                    let error = out.get("error").map(|e| {
                        let m = id(e.get("message"));
                        if m.is_empty() {
                            id(e.get("code"))
                        } else {
                            m
                        }
                    });
                    return Err(SendError::new(
                        format!(
                            "Azure Communication Services ended the send \
                                 as \"{}\"{}",
                            if status.is_empty() {
                                "unknown"
                            } else {
                                &status
                            },
                            error
                                .map(|e| format!(": {}", e))
                                .unwrap_or_default()
                        ),
                        codes::STS_MAIL_0008,
                        false,
                    ));
                }
                Ok(Sent {
                    provider_id: id(out.get("id")),
                    detail: String::new(),
                })
            }
        }
    }
}

impl Transport for CloudTransport {
    fn name(&self) -> &str {
        match self.cloud {
            Cloud::Ses => "ses",
            Cloud::Acs => "acs",
            Cloud::Gmail => "gmail",
        }
    }
    fn send<'a>(
        &'a self,
        message: &'a OutMessage,
    ) -> BoxFuture<'a, Result<Sent, SendError>> {
        Box::pin(self.deliver(message))
    }
}
