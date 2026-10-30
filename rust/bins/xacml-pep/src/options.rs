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
    /// The AuthZEN edge PDP (#1179): on by default, reachable only over the
    /// HTTPS listener by a caller presenting a certificate this container
    /// verifies against `authzen_client_ca` and finds in `authzen_callers`.
    pub authzen_enabled: bool,
    pub authzen_client_ca: Option<Vec<u8>>,
    pub authzen_callers: Vec<AuthzenCaller>,
    /// The PDP identifier the metadata names, an `https` origin; empty means
    /// "the origin the HTTPS request arrived at".
    pub authzen_pdp_identifier: String,
}

/// One caller the edge PDP admits: the certificate it presents, by the
/// SHA-256 of its DER, under a name, scoped to applications. The
/// container's stand-in for an entry in the service's directory holding
/// AUTHZEN_PEPS and `stsAuthzenApplication` (`xacml-pep/CLAUDE.md`).
#[derive(Debug, Clone, PartialEq)]
pub struct AuthzenCaller {
    pub name: String,
    pub sha256: String,
    pub applications: Vec<String>,
}

/// A SHA-256 fingerprint as lower-case hex, colons and case ignored, or
/// `None` when it is not 64 hex digits.
pub fn fingerprint_of(text: &str) -> Option<String> {
    let hex: String = text
        .chars()
        .filter(|c| *c != ':')
        .collect::<String>()
        .to_ascii_lowercase();
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        .then_some(hex)
}

/// `PEP_AUTHZEN_CALLERS`: a JSON array of `{ "name", "sha256",
/// "applications" }`. A malformed entry is LEFT OUT and named, never
/// guessed at, so a typo admits nobody rather than somebody; a value that
/// is not a JSON array admits nobody at all. The bounds are the service's
/// `set-scope` bounds: 64 applications of at most 256 characters.
pub fn parse_callers(raw: &str) -> (Vec<AuthzenCaller>, Vec<String>) {
    let mut callers = Vec::new();
    let mut problems = Vec::new();
    if raw.trim().is_empty() {
        return (callers, problems);
    }
    let Ok(serde_json::Value::Array(entries)) =
        serde_json::from_str::<serde_json::Value>(raw)
    else {
        problems.push(
            "PEP_AUTHZEN_CALLERS is not a JSON array, so no caller is \
             admitted"
                .to_string(),
        );
        return (callers, problems);
    };
    for (i, entry) in entries.iter().enumerate() {
        let name = entry["name"].as_str().unwrap_or("").trim().to_string();
        let sha256 = entry["sha256"].as_str().and_then(fingerprint_of);
        let applications: Option<Vec<String>> = match &entry["applications"] {
            serde_json::Value::Null => Some(Vec::new()),
            serde_json::Value::Array(list) => list
                .iter()
                .map(|one| {
                    one.as_str()
                        .filter(|s| {
                            !s.is_empty()
                                && s.chars().count() <= 256
                                && !s.chars().any(char::is_control)
                        })
                        .map(str::to_string)
                })
                .collect::<Option<Vec<String>>>()
                .filter(|list| list.len() <= 64),
            _ => None,
        };
        match (name.is_empty(), sha256, applications) {
            (false, Some(sha256), Some(applications)) => {
                if callers.iter().any(|c: &AuthzenCaller| c.sha256 == sha256) {
                    problems.push(format!(
                        "entry {} names a certificate an earlier entry \
                         names; the first is used",
                        i
                    ));
                } else {
                    callers.push(AuthzenCaller {
                        name,
                        sha256,
                        applications,
                    });
                }
            }
            _ => problems.push(format!(
                "entry {} is not {{ \"name\": a non-empty string, \
                 \"sha256\": 64 hex digits, \"applications\": at most 64 \
                 strings }} and is left out",
                i
            )),
        }
    }
    (callers, problems)
}

/// `PEP_AUTHZEN_PDP_IDENTIFIER`: an `https` origin with no path, query or
/// fragment, or `None`. A path is refused because this container serves
/// `/access/v1/*` at its root, and section 9.2.3 has a PEP refuse a
/// document whose identifier is not the base it built the URL from.
pub fn pdp_identifier_of(raw: &str) -> Option<String> {
    let text = raw.trim().trim_end_matches('/');
    let parsed = reqwest::Url::parse(text).ok()?;
    let clean = parsed.scheme() == "https"
        && parsed.host_str().is_some()
        && (parsed.path().is_empty() || parsed.path() == "/")
        && parsed.query().is_none()
        && parsed.fragment().is_none()
        && parsed.username().is_empty()
        && parsed.password().is_none();
    clean.then(|| text.to_string())
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
            authzen_enabled: std::env::var("PEP_AUTHZEN").as_deref()
                != Ok("false"),
            authzen_client_ca: authzen_client_ca(),
            authzen_callers: authzen_callers(),
            authzen_pdp_identifier: authzen_pdp_identifier(),
        }
    }
}

/// The client CA bundle, read once. Unset or unreadable, the edge PDP
/// admits nobody, and says so.
fn authzen_client_ca() -> Option<Vec<u8>> {
    let path = std::env::var("PEP_AUTHZEN_CLIENT_CA")
        .ok()
        .filter(|p| !p.is_empty());
    let Some(path) = path else {
        tracing::warn!(
            "{}xacml-pep: no PEP_AUTHZEN_CLIENT_CA, so the HTTPS listener \
             asks no caller for a certificate and the AuthZEN endpoints \
             admit nobody: they authenticate by mutual TLS only. Set it to \
             the CA bundle the callers' certificates chain to.",
            tag("STS-XPEP-0039")
        );
        return None;
    };
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            tracing::error!(
                "{}xacml-pep: PEP_AUTHZEN_CLIENT_CA names {} and it could \
                 not be read ({}), so the AuthZEN endpoints admit nobody.",
                tag("STS-XPEP-0039"),
                path,
                error
            );
            None
        }
    }
}

fn authzen_callers() -> Vec<AuthzenCaller> {
    let raw = std::env::var("PEP_AUTHZEN_CALLERS").unwrap_or_default();
    let (callers, problems) = parse_callers(&raw);
    for problem in &problems {
        tracing::error!(
            "{}xacml-pep: PEP_AUTHZEN_CALLERS: {}.",
            tag("STS-XPEP-0038"),
            problem
        );
    }
    callers
}

fn authzen_pdp_identifier() -> String {
    let raw = std::env::var("PEP_AUTHZEN_PDP_IDENTIFIER").unwrap_or_default();
    if raw.trim().is_empty() {
        return String::new();
    }
    match pdp_identifier_of(&raw) {
        Some(identifier) => identifier,
        None => {
            tracing::error!(
                "{}xacml-pep: PEP_AUTHZEN_PDP_IDENTIFIER is \"{}\", which is \
                 not an https origin with no path; the metadata names the \
                 origin each HTTPS request arrives at instead.",
                tag("STS-XPEP-0045"),
                raw
            );
            String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callers_are_read_strictly() {
        let fp = "AB:".repeat(31) + "AB";
        let raw = format!(
            "[{{\"name\":\"pep-a\",\"sha256\":\"{}\",\
             \"applications\":[\"todo-app\"]}},\
             {{\"name\":\"\",\"sha256\":\"{}\"}},\
             {{\"name\":\"pep-b\",\"sha256\":\"nothex\"}},\
             {{\"name\":\"pep-c\",\"sha256\":\"{}\"}}]",
            fp, fp, fp
        );
        let (callers, problems) = parse_callers(&raw);
        assert_eq!(callers.len(), 1);
        assert_eq!(callers[0].sha256, "ab".repeat(32));
        assert_eq!(callers[0].applications, ["todo-app"]);
        assert_eq!(problems.len(), 3);
        let (none, refused) = parse_callers("{}");
        assert!(none.is_empty() && refused.len() == 1);
        assert!(parse_callers("").0.is_empty());
    }

    #[test]
    fn the_identifier_is_an_https_origin() {
        assert_eq!(
            pdp_identifier_of("https://pdp.example:9444/").as_deref(),
            Some("https://pdp.example:9444")
        );
        assert!(pdp_identifier_of("http://pdp.example").is_none());
        assert!(pdp_identifier_of("https://pdp.example/realm/x").is_none());
        assert!(pdp_identifier_of("not a url").is_none());
    }
}
