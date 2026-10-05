// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Configuration, all of it from the environment — the same variables, the
//! same defaults and the same meanings as `pep.js`. No appconfig file and no
//! settings table: this container is one component with a dozen knobs and no
//! console to change them while it runs.

use std::path::{Path, PathBuf};

use sts_core::log::tag;

/// What a non-Permit means. Deny-biased: only Permit allows. Permit-biased:
/// only Deny refuses. They differ on Indeterminate and NotApplicable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bias {
    DenyBiased,
    PermitBiased,
}

impl Bias {
    pub fn as_str(self) -> &'static str {
        match self {
            Bias::DenyBiased => "deny-biased",
            Bias::PermitBiased => "permit-biased",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Options {
    pub pdp_url: String,
    pub name: String,
    pub notify_url: String,
    pub resource: String,
    pub version: String,
    pub description: String,
    pub bias: Bias,
    pub port: u16,
    pub poll_interval_ms: u64,
    pub heartbeat_interval_ms: u64,
    /// The longest a poll or a heartbeat waits while the PDP refuses it.
    pub backoff_max_ms: u64,
    pub timeout_ms: u64,
    pub max_body_bytes: usize,
    pub client_certificate: Option<Vec<u8>>,
    pub client_key: Option<Vec<u8>>,
    /// Where this PEP's own credential's CRLs are, served at `/crl/<name>`.
    pub crl_dir: Option<PathBuf>,
    pub pdp_ca: Option<Vec<u8>>,
    pub insecure: bool,
    /// The remote PIP: on by default, and turning it off is a supported
    /// deployment rather than a degraded one.
    pub pip_enabled: bool,
    pub https_cert_path: String,
    pub https_key_path: String,
    pub https_port: u16,
    pub https_reload_interval_ms: u64,
}

/// `parseInt(raw, 10)`, falling back when it is not a number.
fn int_from_env<T: std::str::FromStr>(name: &str, fallback: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|raw| {
            let trimmed = raw.trim();
            let end = trimmed
                .char_indices()
                .find(|(i, c)| !(c.is_ascii_digit() || (*i == 0 && *c == '-')))
                .map_or(trimmed.len(), |(i, _)| i);
            trimmed[..end].parse().ok()
        })
        .unwrap_or(fallback)
}

/// A file named by an environment variable. A path that cannot be read is
/// named, loudly, and carried on WITHOUT: a PEP configured with a certificate
/// it cannot read would otherwise register unauthenticated and leave
/// somebody wondering why.
fn file_from_env(name: &str) -> Option<Vec<u8>> {
    let path = std::env::var(name).ok().filter(|p| !p.is_empty())?;
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            tracing::error!(
                "{}xacml-pep: {} names {} and it could not be read ({}). \
                 Carrying on WITHOUT it, which means this PEP registers \
                 unauthenticated if the PDP allows that and is refused if it \
                 does not.",
                tag("STS-XPEP-0003"),
                name,
                path,
                error
            );
            None
        }
    }
}

fn env_or(name: &str, fallback: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

impl Options {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn from_env(version: &str) -> Options {
        let cert_path = std::env::var("PEP_TLS_CERT").unwrap_or_default();
        let crl_dir = match std::env::var("PEP_CRL_DIR") {
            Ok(dir) if !dir.is_empty() => Some(PathBuf::from(dir)),
            _ if !cert_path.is_empty() => Path::new(&cert_path)
                .parent()
                .map(|parent| parent.join("crl")),
            _ => None,
        };
        Options {
            pdp_url: env_or("PEP_PDP_URL", "https://localhost:8081"),
            name: env_or("PEP_NAME", "pep-1"),
            notify_url: std::env::var("PEP_NOTIFY_URL").unwrap_or_default(),
            resource: std::env::var("PEP_RESOURCE").unwrap_or_default(),
            version: version.to_string(),
            description: env_or(
                "PEP_DESCRIPTION",
                "A remote XACML Policy Enforcement Point holding its own copy \
                 of the engine and pulling this repository.",
            ),
            bias: if std::env::var("PEP_BIAS").as_deref() == Ok("permit-biased")
            {
                Bias::PermitBiased
            } else {
                Bias::DenyBiased
            },
            port: int_from_env("PEP_PORT", 9090),
            poll_interval_ms: int_from_env("PEP_POLL_INTERVAL_MS", 15000),
            heartbeat_interval_ms: int_from_env(
                "PEP_HEARTBEAT_INTERVAL_MS",
                60000,
            ),
            backoff_max_ms: int_from_env("PEP_BACKOFF_MAX_MS", 300000),
            timeout_ms: int_from_env("PEP_TIMEOUT_MS", 5000),
            max_body_bytes: int_from_env("PEP_MAX_BODY_BYTES", 4 * 1024 * 1024),
            client_certificate: file_from_env("PEP_TLS_CERT"),
            client_key: file_from_env("PEP_TLS_KEY"),
            crl_dir,
            pdp_ca: file_from_env("PEP_TLS_CA"),
            insecure: std::env::var("PEP_TLS_INSECURE").as_deref()
                == Ok("true"),
            pip_enabled: std::env::var("PEP_PIP").as_deref() != Ok("false"),
            https_cert_path: std::env::var("PEP_HTTPS_CERT")
                .unwrap_or_default(),
            https_key_path: std::env::var("PEP_HTTPS_KEY").unwrap_or_default(),
            https_port: int_from_env("PEP_HTTPS_PORT", 9443),
            https_reload_interval_ms: int_from_env(
                "PEP_HTTPS_RELOAD_INTERVAL_MS",
                5000,
            ),
        }
    }
}
