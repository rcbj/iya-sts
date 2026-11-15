// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The transport policy an audit export is sent under: the part of
//! `common/outbound_tls.ts` the exporter asks (`httpVerdict()`,
//! `skipsVerification()`, `tlsVerdict()`), for the one family it asks for
//! (`FAMILY`: `auditExport.allowHttp`, `auditExport.skipTlsVerification`,
//! `auditExport.caFile`, `STS-AUDIT-0005`, `STS-AUDIT-0012`).
//!
//! Plain http is development only; product refuses it whatever the
//! setting says. Skipping certificate verification is development only and
//! IGNORED in product, said once per process. A CA file is read through
//! [`CaFiles`], whose real implementation is the TLS slice's
//! (`OutboundTls.caFilePems()`, with its named-file rules); an unusable one
//! refuses the send with `STS-CORE-0104`.
//!
//! What a verified connection then checks — node's store plus the CA file
//! and the signer truststore (#1360), and `checkServerIdentity()`'s host
//! name and path rules — is the dialler's: [`TlsPolicy`] carries what Node
//! hands `https.request()` and `tls.connect()`.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use sts_core::errors::codes;
use sts_core::mode::Mode;
use sts_core::settings::{keys, Settings};

use super::address;

/// Reads a CA file: its certificates as PEM, or why it cannot be used.
pub trait CaFiles: Send + Sync {
    fn pems(&self, file: &str) -> Result<Vec<String>, String>;
}

/// No file can be read: every named one is refused.
pub struct NoCaFiles;

impl CaFiles for NoCaFiles {
    fn pems(&self, _file: &str) -> Result<Vec<String>, String> {
        Err("it cannot be read".to_string())
    }
}

/// `{ ok, why, errorCode }` of `httpVerdict()`.
#[derive(Debug, Clone, PartialEq)]
pub struct HttpVerdict {
    pub ok: bool,
    pub why: String,
    pub error_code: String,
}

/// What `tlsVerdict()` hands the dialler.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TlsPolicy {
    pub ok: bool,
    pub why: String,
    pub error_code: String,
    pub reject_unauthorized: bool,
    pub skipped: bool,
    /// The family's CA file's certificates, beside the platform's store.
    pub ca: Vec<String>,
}

const WHAT: &str = "an audit export";

/// The audit export's outbound policy.
pub struct Outbound {
    settings: Arc<Settings>,
    mode: Arc<Mode>,
    ca_files: Arc<dyn CaFiles>,
    announced: Mutex<HashSet<String>>,
}

impl Outbound {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(
        settings: Arc<Settings>,
        mode: Arc<Mode>,
        ca_files: Arc<dyn CaFiles>,
    ) -> Outbound {
        Outbound {
            settings,
            mode,
            ca_files,
            announced: Mutex::new(HashSet::new()),
        }
    }

    /// `httpVerdict(FAMILY, hostname)`: may this http:// URL be dialled?
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn http_verdict(&self, _hostname: &str) -> HttpVerdict {
        if !self.settings.value(keys::AUDIT_EXPORT_ALLOW_HTTP).as_bool() {
            return HttpVerdict {
                ok: false,
                error_code: String::new(),
                why: "it is an http:// URL and auditExport.allowHttp is off"
                    .to_string(),
            };
        }
        if self.mode.dials_plain_http_outbound() {
            return HttpVerdict {
                ok: true,
                why: String::new(),
                error_code: String::new(),
            };
        }
        HttpVerdict {
            ok: false,
            error_code: codes::STS_AUDIT_0005.as_str().to_string(),
            why: format!(
                "it is an http:// URL, and this realm is in product mode \
                 (global.mode=product), where {} goes over https only \
                 whatever auditExport.allowHttp says",
                WHAT
            ),
        }
    }

    /// `skipsVerification()`: only with the setting on AND the mode
    /// allowing it; product ignores it, said once per process.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn skips_verification(&self) -> bool {
        if !self
            .settings
            .value(keys::AUDIT_EXPORT_SKIP_TLS_VERIFICATION)
            .as_bool()
        {
            return false;
        }
        if self.mode.skips_outbound_tls_verification() {
            return true;
        }
        let first = match self.announced.lock() {
            Ok(mut set) => set.insert("auditExport.skipTlsVerification".into()),
            Err(poisoned) => poisoned
                .into_inner()
                .insert("auditExport.skipTlsVerification".into()),
        };
        if first {
            tracing::warn!(
                "{}outbound: auditExport.skipTlsVerification is on and is \
                 IGNORED, because this realm is in product mode \
                 (global.mode=product): {} verifies the certificate of \
                 whoever answers. Name a private CA in the family's CA file \
                 setting instead. Said once per process.",
                sts_core::log::tag(codes::STS_AUDIT_0012),
                WHAT
            );
        }
        false
    }

    /// `tlsVerdict(FAMILY, origin)`: verification skipped, the platform's
    /// store, or that store and the family's CA file.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn tls_verdict(&self, origin: &str) -> TlsPolicy {
        if self.skips_verification() {
            tracing::warn!(
                "outbound: {} to {} is sent WITHOUT verifying the \
                 certificate of whoever answers, because \
                 auditExport.skipTlsVerification is on (development mode \
                 only).",
                WHAT,
                origin
            );
            return TlsPolicy {
                ok: true,
                reject_unauthorized: false,
                skipped: true,
                ..TlsPolicy::default()
            };
        }
        let file = self.settings.value(keys::AUDIT_EXPORT_CA_FILE);
        let file = file.as_str();
        if file.is_empty() {
            return TlsPolicy {
                ok: true,
                reject_unauthorized: true,
                ..TlsPolicy::default()
            };
        }
        match self.ca_files.pems(file) {
            Ok(ca) => TlsPolicy {
                ok: true,
                reject_unauthorized: true,
                ca,
                ..TlsPolicy::default()
            },
            Err(why) => {
                tracing::warn!(
                    "{}outbound: {} to {} was not sent: {}",
                    sts_core::log::tag(codes::STS_CORE_0104),
                    WHAT,
                    origin,
                    why
                );
                TlsPolicy {
                    ok: false,
                    error_code: codes::STS_CORE_0104.as_str().to_string(),
                    reject_unauthorized: true,
                    why: format!(
                        "auditExport.caFile names \"{}\", and {}",
                        file, why
                    ),
                    ..TlsPolicy::default()
                }
            }
        }
    }

    /// `OutboundTls.isLoopbackHost()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn is_loopback_host(&self, host: &str) -> bool {
        address::is_loopback_host(host)
    }
}
