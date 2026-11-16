// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Configuration, from the environment — the same variables, the same
//! defaults and the same meanings as `pep.js` — and, since #1760, from the
//! service: every setting that is not needed to reach the service the first
//! time may be set on the PEP's console page and is pulled
//! (`settings.rs`). The fields below are the ENVIRONMENT's values (or the
//! defaults); `Options::now()` is what is in force, the service's value
//! where it set one. Read a managed setting through `now()`, never the
//! field, or a change made on the console never reaches the reader.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::settings::{self, Held};

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
    /// THE PLAIN-HTTP API LISTENER IS OFF BY DEFAULT (#1760, rcbj
    /// 2026-11-14): `PEP_HTTP=true` binds it on `port`. See
    /// [`plain_http`] for the precedence and the notices.
    pub http: PlainHttp,
    /// `PEP_CRL_HTTP` (2026-11-14): `Some(true)` or `Some(false)` as set,
    /// `None` unset (the default: bind the CRL-only listener when `http`
    /// is off and `crl_dir` exists), and the unreadable text, if any.
    pub crl_http: (Option<bool>, Option<String>),
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
    /// verifies against `authzen_client_ca` and finds on the caller list it
    /// pulled from the service (#1189) — narrowed, when
    /// `authzen_callers_configured`, to `authzen_callers`.
    pub authzen_enabled: bool,
    pub authzen_client_ca: Option<Vec<u8>>,
    pub authzen_callers: Vec<AuthzenCaller>,
    /// `PEP_AUTHZEN_CALLERS` was SET (non-empty), whatever it held: the
    /// operator asked for a narrowing, so a value that admits nobody
    /// narrows to nobody rather than being read as "not set" (#1189).
    pub authzen_callers_configured: bool,
    /// The PDP identifier the metadata names, an `https` origin; empty means
    /// "the origin the HTTPS request arrived at".
    pub authzen_pdp_identifier: String,
    /// How long the edge PDP waits for the service when it FORWARDS an
    /// evaluation about an application that enforces fine-grained
    /// authorization (#564): `PEP_AUTHZEN_FORWARD_TIMEOUT_MS`, apart from
    /// `PEP_TIMEOUT_MS` because the caller is waiting on this one, and a
    /// pull is not waited on by anybody. At least 1.
    pub authzen_forward_timeout_ms: u64,
    /// THE REVERSE PROXY (#1760): on by default, on ports of its own so
    /// every existing endpoint is untouched. It answers 404 to everything
    /// until the service sends a configuration for this PEP.
    pub proxy_enabled: bool,
    pub proxy_port: u16,
    /// The proxy's plain-HTTP listener, off by default the same way:
    /// `PEP_PROXY_HTTP=true` binds it on `proxy_port`.
    pub proxy_http: PlainHttp,
    /// Served with the same reloaded `PEP_HTTPS_CERT`/`KEY` pair as 9443,
    /// asking every client for a certificate (never requiring one) so a
    /// certificate-bound token's `cnf.x5t#S256` can be checked.
    pub proxy_https_port: u16,
    /// How old the service's last "live" answer about a proxy session may
    /// be before the next access asks again; 0 asks every time.
    pub proxy_session_recheck_ms: u64,
    pub proxy_session_ttl_ms: u64,
    /// The most proxy sessions (and, separately, sign-ins in flight) held.
    pub proxy_max_sessions: usize,
    /// The most accounts one browser's set holds on a route with
    /// `multipleAccounts` (#1760); a sign-in past it is refused.
    pub proxy_max_accounts: usize,
    /// How long a fetched JWKS is used before it is fetched again.
    pub proxy_jwks_ttl_ms: u64,
    /// Anchors for an https upstream, beside the system's; read once.
    pub proxy_upstream_ca: Option<Vec<u8>>,
    /// Do not verify an https upstream's certificate.
    pub proxy_upstream_insecure: bool,
    /// The session mechanism's relying party may talk to an `http` issuer
    /// (the library's `allowInsecure`): a development provider only. It
    /// does not relax the redirect URI, which stays https or loopback.
    pub proxy_rp_allow_insecure: bool,
    /// How often the CAEP/RISC receiver polls the service's stream.
    pub proxy_signals_poll_ms: u64,
    /// How long a receiver may go without a successful poll before its
    /// signals stop deciding session liveness (never less than three
    /// polls).
    pub proxy_signals_stale_ms: u64,
    /// `PEP_PROXY_STRIP_COOKIES` (2026-11-14): more cookie names (a
    /// trailing `*` is a prefix) the proxy never forwards upstream, beside
    /// the service's own the pull names.
    pub proxy_strip_cookies: String,
    /// `PEP_LOG_LEVEL` as given; the level in force is `now().log_level`.
    pub log_level: String,
    /// What the service set (#1760), shared by every clone.
    pub managed: Arc<Held>,
    /// The decision records shipped to the service (#1827): `PEP_AUDIT`,
    /// on by default; `false` queues nothing and starts no loop.
    pub audit_enabled: bool,
    /// How often the queue is shipped, `PEP_AUDIT_INTERVAL_MS`.
    pub audit_interval_ms: u64,
    /// The most records in one batch, `PEP_AUDIT_BATCH`, held to 1..=500
    /// (the service's bound) where it is used.
    pub audit_batch: usize,
    /// The most records held waiting, `PEP_AUDIT_BUFFER`; full, the
    /// oldest is dropped.
    pub audit_buffer: usize,
    /// The public client the self-assertion grant goes through,
    /// `PEP_AUDIT_CLIENT_ID`.
    pub audit_client_id: String,
}

/// THE SETTINGS IN FORCE NOW: the service's value where it set one, else
/// the environment's, else the default (`settings.rs`).
#[derive(Debug, Clone)]
pub struct Now {
    pub description: String,
    pub resource: String,
    /// The notify URL this PEP advertises: https, or empty for none.
    pub notify_url: String,
    /// The notify URL somebody SET that is REJECTED (not https), empty for
    /// none; while it is in force `notify_url` is empty (`STS-XPEP-0113`).
    pub notify_rejected: String,
    pub bias: Bias,
    pub pip: bool,
    pub poll_interval_ms: u64,
    pub heartbeat_interval_ms: u64,
    pub backoff_max_ms: u64,
    pub timeout_ms: u64,
    pub max_body_bytes: usize,
    pub https_reload_interval_ms: u64,
    pub log_level: String,
    pub authzen: bool,
    pub authzen_pdp_identifier: String,
    pub authzen_forward_timeout_ms: u64,
    pub proxy_session_recheck_ms: u64,
    pub proxy_session_ttl_ms: u64,
    pub proxy_max_sessions: usize,
    /// The most accounts one browser's set holds on a route with
    /// `multipleAccounts` (#1760); a sign-in past it is refused.
    pub proxy_max_accounts: usize,
    pub proxy_jwks_ttl_ms: u64,
    pub proxy_upstream_insecure: bool,
    pub proxy_rp_allow_insecure: bool,
    pub proxy_signals_poll_ms: u64,
    pub proxy_signals_stale_ms: u64,
    pub proxy_strip_cookies: String,
    /// The decision records (#1827): whether they are queued and sent, how
    /// often, how many to a batch, and how many may wait.
    pub audit: bool,
    pub audit_interval_ms: u64,
    pub audit_batch: usize,
    pub audit_buffer: usize,
}

impl Now {
    /// Each setting's value as JSON, by the service's member name.
    pub fn values(&self) -> serde_json::Map<String, serde_json::Value> {
        let value = serde_json::json!({
            "description": self.description, "resource": self.resource,
            "notifyUrl": self.notify_url, "bias": self.bias.as_str(),
            "pip": self.pip, "pollIntervalMs": self.poll_interval_ms,
            "heartbeatIntervalMs": self.heartbeat_interval_ms,
            "backoffMaxMs": self.backoff_max_ms,
            "timeoutMs": self.timeout_ms,
            "maxBodyBytes": self.max_body_bytes,
            "httpsReloadIntervalMs": self.https_reload_interval_ms,
            "logLevel": self.log_level, "authzen": self.authzen,
            "authzenPdpIdentifier": self.authzen_pdp_identifier,
            "authzenForwardTimeoutMs": self.authzen_forward_timeout_ms,
            "proxySessionRecheckMs": self.proxy_session_recheck_ms,
            "proxySessionTtlMs": self.proxy_session_ttl_ms,
            "proxyMaxSessions": self.proxy_max_sessions,
            "proxyMaxAccounts": self.proxy_max_accounts,
            "proxyJwksTtlMs": self.proxy_jwks_ttl_ms,
            "proxyUpstreamInsecure": self.proxy_upstream_insecure,
            "proxyRpAllowInsecure": self.proxy_rp_allow_insecure,
            "proxySignalsPollMs": self.proxy_signals_poll_ms,
            "proxySignalsStaleMs": self.proxy_signals_stale_ms,
            "proxyStripCookies": self.proxy_strip_cookies,
            "auditEnabled": self.audit,
            "auditIntervalMs": self.audit_interval_ms,
            "auditBatch": self.audit_batch,
            "auditBuffer": self.audit_buffer
        });
        match value {
            serde_json::Value::Object(map) => map,
            _ => serde_json::Map::new(),
        }
    }
}

/// A bunyan level name as the environment gives it, folded to one of the
/// closed set (`parse_level()` reads any other as `info`).
fn level_name(raw: &str) -> String {
    let folded = raw.trim().to_ascii_lowercase();
    if settings::LOG_LEVELS.contains(&folded.as_str()) {
        folded
    } else {
        "info".to_string()
    }
}

/// One caller `PEP_AUTHZEN_CALLERS` names: the certificate it presents, by
/// the SHA-256 of its DER, under a name, scoped to applications. Since
/// #1189 the list is an OPTIONAL NARROWING of the callers pulled from the
/// service (a pulled caller must also be on it), and decides alone only
/// until the first caller pull loads (`xacml-pep/CLAUDE.md`).
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

/// One plain-HTTP listener's switch, as read at start (#1760).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlainHttp {
    /// Whether the listener is bound.
    pub on: bool,
    /// The switch's name (`PEP_HTTP`, `PEP_PROXY_HTTP`).
    pub switch: &'static str,
    /// The port variable beside it (`PEP_PORT`, `PEP_PROXY_PORT`).
    pub port_var: &'static str,
    /// What to say at start, if anything: see [`plain_http`].
    pub notice: Option<PlainHttpNotice>,
}

/// Why a plain-HTTP listener's start deserves a line of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlainHttpNotice {
    /// The switch is unset and the port variable IS set: a deployment
    /// written when plain HTTP was on by default and relying on it
    /// (`STS-XPEP-0106`).
    Relied,
    /// The switch holds something other than `true` or `false`; the
    /// listener stays off (`STS-XPEP-0107`). The value is kept.
    Unreadable(String),
}

/// PLAIN HTTP IS OFF UNLESS IT IS ASKED FOR (#1760, rcbj 2026-11-14:
/// "Disable the HTTP listeners by default on the Remote XACML PEPs &
/// reverse proxy"). The precedence, highest first:
///
/// 1. **the switch** (`PEP_HTTP`, `PEP_PROXY_HTTP`): `true` binds the
///    listener, `false` does not; anything else does not either, and says
///    so (`STS-XPEP-0107`), because a typo that turned plaintext ON would
///    be the wrong way to fail;
/// 2. **unset, the listener is off.** The PORT variable alone does not
///    turn it on: a template that wrote `PEP_PORT=9090` down to document
///    the default would otherwise keep plaintext on without anybody
///    choosing it, which is the thing this default exists to stop. A port
///    variable set with no switch is a deployment that relied on the old
///    default, so it is told so once at start (`STS-XPEP-0106`), with the
///    one line that brings the listener back.
///
/// The service's equivalent is not a setting: these two are bound before
/// the first pull, which is why they are the environment's. A listener
/// DEFINED on the PEP's Listener tab (`xacmlPepListeners`) is the managed
/// way to serve plain HTTP, and binds at the next pull.
pub fn plain_http(
    switch: Option<&str>,
    port: Option<&str>,
) -> (bool, Option<PlainHttpNotice>) {
    match switch.map(str::trim) {
        Some("true") => (true, None),
        Some("false") => (false, None),
        Some("") | None => {
            let relied = port.map(|p| !p.trim().is_empty()).unwrap_or(false);
            (false, relied.then_some(PlainHttpNotice::Relied))
        }
        Some(other) => (false, Some(PlainHttpNotice::Unreadable(
            other.to_string()))),
    }
}

/// THE NOTIFY URL THIS PEP ADVERTISES (2026-11-14): only an https one. A
/// guard at the three places it is sent (the registration, the heartbeat,
/// `GET /`): `Now::notify_url` is already https or empty, because a value
/// that is not https is REJECTED where the URL in force is decided
/// (`Options::notify_in_force`, `STS-XPEP-0113`), and said there.
pub fn advertised_notify_url(url: &str) -> String {
    if settings::notify_rejected(url) {
        return String::new();
    }
    url.trim().to_string()
}

/// WHY A NOTIFY URL SOMEBODY SET IS REJECTED, said once per variable and
/// value at ERROR (`STS-XPEP-0113`): `variable` names where it was set.
/// Rejected means NONE is advertised — not the derived one either, because
/// a value was asked for and must be fixed, not guessed around.
fn say_notify_rejected(variable: &str, url: &str) {
    static SAID: std::sync::Mutex<Vec<String>> =
        std::sync::Mutex::new(Vec::new());
    let key = format!("{}={}", variable, url);
    let mut said = SAID.lock().unwrap_or_else(|e| e.into_inner());
    if said.iter().any(|one| *one == key) {
        return;
    }
    said.push(key);
    tracing::error!(
        "{}xacml-pep: {} is {}, which is not an https URL, so it is \
         REJECTED: the service nudges over https only and nothing allows \
         http. This PEP advertises NO notify URL, and does not fall back to \
         the one it would derive from its HTTPS listener certificate, \
         because a value was set and must be fixed. Set it to this PEP's \
         HTTPS listener, https://<host>:<PEP_HTTPS_PORT>/notify, or unset \
         it to let the PEP derive one. Until then it converges by polling.",
        sts_core::log::tag("STS-XPEP-0113"),
        variable,
        url
    );
}

/// Where a derived notify URL's host came from, best first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivedFrom {
    /// The HTTPS listener certificate's DNS name that equals the hostname
    /// (rcbj, 2026-11-14, "option 1"): a name in the certificate, so the
    /// service's host check passes, and the one the container is known by
    /// on its network, so it resolves. The first name alone was the PEP's
    /// registered name on the 8081 deploy (`remote-pep-1`), which the
    /// default certificate names first and nothing resolves.
    CertificateHostname,
    /// The first DNS name of the HTTPS listener certificate, when none of
    /// them is the hostname: the name the service's host check can pass,
    /// since it checks the notify host against that certificate.
    Certificate,
    /// `PEP_NAME`, being a DNS name.
    Name,
    /// The container's or system's hostname.
    Hostname,
}

impl DerivedFrom {
    fn describe(self) -> &'static str {
        match self {
            DerivedFrom::CertificateHostname =>
                "the HTTPS listener certificate's DNS name that is this \
                 PEP's hostname",
            DerivedFrom::Certificate =>
                "the first DNS name of the HTTPS listener certificate, none \
                 of its names being the hostname",
            DerivedFrom::Name => "PEP_NAME",
            DerivedFrom::Hostname => "the hostname",
        }
    }
}

/// A derived notify URL and where its host came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedNotify {
    pub url: String,
    pub from: DerivedFrom,
}

/// Whether `text` is a DNS host name a URL may carry: dot-separated labels
/// of letters, digits and hyphens, each 1–63 long and not starting or
/// ending with a hyphen, 253 at most in all, and not all digits at the end
/// (an IPv4 address is not a DNS name). A wildcard is not a host.
pub fn is_dns_name(text: &str) -> bool {
    let name = text.strip_suffix('.').unwrap_or(text);
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    let good = labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    good && labels
        .last()
        .is_some_and(|tld| !tld.bytes().all(|b| b.is_ascii_digit()))
}

/// THE NOTIFY URL THIS PEP DERIVES (2026-11-14, rcbj: "The PEP should
/// attempt to derive the notify URL"): `https://<host>:<https_port>/notify`,
/// or `None` while the HTTPS listener serves no certificate (`served` is
/// its DNS names, `None` for no certificate) — `POST /notify` is answered
/// on HTTPS alone, so there is nothing to advertise without one. The host,
/// best first (rcbj, 2026-11-14, "option 1"): the certificate's DNS name
/// equal to the hostname (case and a trailing dot aside), the
/// certificate's first DNS name, `PEP_NAME` where it is a DNS name, the
/// hostname. A name that is not a DNS name (a wildcard, an IP address) is
/// passed over.
pub fn derive_notify_url(
    served: Option<&[String]>,
    pep_name: Option<&str>,
    hostname: Option<&str>,
    https_port: u16,
) -> Option<DerivedNotify> {
    let names = served?;
    let bare = |n: &str| n.trim().trim_end_matches('.').to_ascii_lowercase();
    let own = hostname
        .map(str::trim)
        .filter(|h| is_dns_name(h))
        .map(bare);
    let pick = own
        .as_ref()
        .and_then(|own| {
            names
                .iter()
                .map(|n| n.trim())
                .find(|n| is_dns_name(n) && bare(n) == *own)
        })
        .map(|n| (n.to_string(), DerivedFrom::CertificateHostname))
        .or_else(|| {
            names
                .iter()
                .map(|n| n.trim())
                .find(|n| is_dns_name(n))
                .map(|n| (n.to_string(), DerivedFrom::Certificate))
        })
        .or_else(|| {
            pep_name
                .map(str::trim)
                .filter(|n| is_dns_name(n))
                .map(|n| (n.to_string(), DerivedFrom::Name))
        })
        .or_else(|| {
            hostname
                .map(str::trim)
                .filter(|n| is_dns_name(n))
                .map(|n| (n.to_string(), DerivedFrom::Hostname))
        })?;
    let host = pick.0.strip_suffix('.').unwrap_or(&pick.0).to_ascii_lowercase();
    Some(DerivedNotify {
        url: format!("https://{}:{}/notify", host, https_port),
        from: pick.1,
    })
}

/// The container's or system's hostname: `HOSTNAME`, else the kernel's,
/// else `/etc/hostname`.
fn system_hostname() -> Option<String> {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.trim().is_empty())
        .or_else(|| {
            ["/proc/sys/kernel/hostname", "/etc/hostname"]
                .iter()
                .find_map(|path| {
                    std::fs::read_to_string(path)
                        .ok()
                        .map(|h| h.trim().to_string())
                        .filter(|h| !h.is_empty())
                })
        })
}

/// THE HOSTNAME THIS PEP REPORTS (#1760) on its registration and
/// heartbeat as `hostname`: the one `derive_notify_url()` looks for in the
/// HTTPS listener certificate, so the service can put it in the realm's
/// default certificate. Before this, a fresh install's first certificate
/// named only the registered name (`remote-pep-1`), the PEP registered with
/// no notify URL (it had no certificate), and the derivation picked the
/// registered name, which nothing resolves. Only a DNS name is reported —
/// lower-cased, a trailing dot dropped, never an IP address — because the
/// service refuses anything else (`STS-XACML-0261`) and refusing a
/// registration over a hostname would cost the PEP its row. An older
/// service ignores the member.
pub fn reported_hostname_of(raw: Option<&str>) -> Option<String> {
    let text = raw?.trim();
    if !is_dns_name(text) {
        return None;
    }
    Some(text.strip_suffix('.').unwrap_or(text).to_ascii_lowercase())
}

/// `reported_hostname_of()` of this machine's hostname.
pub fn reported_hostname() -> Option<String> {
    reported_hostname_of(system_hostname().as_deref())
}

/// `PEP_CRL_HTTP` read: `true`, `false`, or unset (`None`); anything else
/// is unset with the text kept, so it is said once (`STS-XPEP-0115`).
pub fn crl_http_switch(said: Option<&str>) -> (Option<bool>, Option<String>) {
    match said.map(str::trim) {
        Some("true") => (Some(true), None),
        Some("false") => (Some(false), None),
        Some("") | None => (None, None),
        Some(other) => (None, Some(other.to_string())),
    }
}

/// THE CRL-ONLY PLAIN-HTTP LISTENER (2026-11-14), on `PEP_PORT` when the
/// decision API's plain HTTP is off. A CRL is fetched in the clear by
/// convention (RFC 5280 section 4.2.1.13: one behind TLS would have to be
/// validated with itself), and the credential tool points a PEP's
/// credential's CRL distribution point at `http://<pep>:9090/crl`, which
/// the service fetches under hard-fail in product — so with plain HTTP off
/// by default (#1760) and nothing on 9090, the credential stopped
/// verifying and every pull was refused as unauthenticated. Bound when
/// `PEP_CRL_HTTP=true`, or by default when there is a CRL directory to
/// serve; `PEP_CRL_HTTP=false` never. With `PEP_HTTP=true` the API's own
/// listener serves `/crl/` as it always did, and this is not bound.
pub fn crl_listener(options: &Options) -> bool {
    if let Some(text) = &options.crl_http.1 {
        tracing::error!(
            "{}xacml-pep: PEP_CRL_HTTP is \"{}\", which is neither true nor \
             false, so the CRL-only listener keeps its default.",
            sts_core::log::tag("STS-XPEP-0115"),
            text
        );
    }
    if options.http.on {
        return false;
    }
    match options.crl_http.0 {
        Some(on) => on,
        None => options.crl_dir.as_ref().is_some_and(|dir| dir.is_dir()),
    }
}

/// [`plain_http`] over the environment.
pub fn plain_http_from_env(switch: &'static str,
                           port_var: &'static str) -> PlainHttp {
    let said = std::env::var(switch).ok();
    let port = std::env::var(port_var).ok();
    let (on, notice) = plain_http(said.as_deref(), port.as_deref());
    PlainHttp { on, switch, port_var, notice }
}

impl PlainHttp {
    /// Logs what this switch means at start: always one line when the
    /// listener is off, and the coded notice when one is owed.
    pub fn announce(&self, what: &str, port: u16) {
        match &self.notice {
            Some(PlainHttpNotice::Relied) => tracing::warn!(
                "{}xacml-pep: {} is set ({}) but {} is not, and plain HTTP \
                 is OFF BY DEFAULT since #1760: the {} does not listen on \
                 {}. If you relied on it, add {}=true to this container's \
                 environment; otherwise remove {} to silence this.",
                tag("STS-XPEP-0106"),
                self.port_var,
                port,
                self.switch,
                what,
                port,
                self.switch,
                self.port_var
            ),
            Some(PlainHttpNotice::Unreadable(value)) => tracing::error!(
                "{}xacml-pep: {} is \"{}\", which is neither true nor \
                 false, so the {}'s plain-HTTP listener stays OFF. Set {}=true \
                 to bind it on {}.",
                tag("STS-XPEP-0107"),
                self.switch,
                value,
                what,
                self.switch,
                port
            ),
            None if !self.on => tracing::info!(
                "xacml-pep: the {}'s plain-HTTP listener is off (the default \
                 since #1760); {}=true binds it on {}.",
                what,
                self.switch,
                port
            ),
            None => tracing::info!(
                "xacml-pep: the {}'s plain-HTTP listener is on ({}=true), on \
                 {}.",
                what,
                self.switch,
                port
            ),
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
    /// The settings in force now (#1760). No `instrument`: every decision
    /// asks it, and a pair of lines per decision would drown the log.
    pub fn now(&self) -> Now {
        let m = self.managed.current();
        let int = |key: &str, env: u64| m.u64(key).unwrap_or(env);
        let flag = |key: &str, env: bool| m.bool(key).unwrap_or(env);
        let text = |key: &str, env: &str| {
            m.str(key).unwrap_or_else(|| env.to_string())
        };
        let notify = self.notify_in_force(&m);
        Now {
            description: text("description", &self.description),
            resource: text("resource", &self.resource),
            notify_url: notify.0,
            notify_rejected: notify.1,
            bias: match m.str("bias").as_deref() {
                Some("permit-biased") => Bias::PermitBiased,
                Some("deny-biased") => Bias::DenyBiased,
                _ => self.bias,
            },
            pip: flag("pip", self.pip_enabled),
            poll_interval_ms: int("pollIntervalMs", self.poll_interval_ms),
            heartbeat_interval_ms: int(
                "heartbeatIntervalMs",
                self.heartbeat_interval_ms,
            ),
            backoff_max_ms: int("backoffMaxMs", self.backoff_max_ms),
            timeout_ms: int("timeoutMs", self.timeout_ms),
            max_body_bytes: int("maxBodyBytes", self.max_body_bytes as u64)
                as usize,
            https_reload_interval_ms: int(
                "httpsReloadIntervalMs",
                self.https_reload_interval_ms,
            ),
            log_level: text("logLevel", &level_name(&self.log_level)),
            authzen: flag("authzen", self.authzen_enabled),
            authzen_pdp_identifier: text(
                "authzenPdpIdentifier",
                &self.authzen_pdp_identifier,
            ),
            authzen_forward_timeout_ms: int(
                "authzenForwardTimeoutMs",
                self.authzen_forward_timeout_ms,
            ),
            proxy_session_recheck_ms: int(
                "proxySessionRecheckMs",
                self.proxy_session_recheck_ms,
            ),
            proxy_session_ttl_ms: int(
                "proxySessionTtlMs",
                self.proxy_session_ttl_ms,
            ),
            proxy_max_sessions: int(
                "proxyMaxSessions",
                self.proxy_max_sessions as u64,
            ) as usize,
            proxy_max_accounts: int(
                "proxyMaxAccounts",
                self.proxy_max_accounts as u64,
            ) as usize,
            proxy_jwks_ttl_ms: int("proxyJwksTtlMs", self.proxy_jwks_ttl_ms),
            proxy_upstream_insecure: flag(
                "proxyUpstreamInsecure",
                self.proxy_upstream_insecure,
            ),
            proxy_rp_allow_insecure: flag(
                "proxyRpAllowInsecure",
                self.proxy_rp_allow_insecure,
            ),
            proxy_signals_poll_ms: int(
                "proxySignalsPollMs",
                self.proxy_signals_poll_ms,
            ),
            proxy_signals_stale_ms: int(
                "proxySignalsStaleMs",
                self.proxy_signals_stale_ms,
            ),
            proxy_strip_cookies: text(
                "proxyStripCookies",
                &self.proxy_strip_cookies,
            ),
            audit: flag("auditEnabled", self.audit_enabled),
            audit_interval_ms: int("auditIntervalMs", self.audit_interval_ms)
                .max(1),
            audit_batch: (int("auditBatch", self.audit_batch as u64) as usize)
                .clamp(1, 500),
            audit_buffer: (int("auditBuffer", self.audit_buffer as u64)
                as usize)
                .max(1),
        }
    }

    /// THE NOTIFY URL IN FORCE, as `(advertised, rejected)`: the service's,
    /// then `PEP_NOTIFY_URL`, then the one derived from the served HTTPS
    /// certificate, then none — the order `Held::source()` reports. A value
    /// SET at either of the first two that is not https is REJECTED (rcbj,
    /// 2026-11-14): it is still the one in force, so nothing is advertised
    /// — not the derived URL either, because somebody asked for something
    /// specific and must fix it — and it is said at ERROR once
    /// (`STS-XPEP-0113`) and reported `rejected` in `settingsInUse`.
    fn notify_in_force(&self, m: &settings::Managed) -> (String, String) {
        if let Some(bad) = m.rejected_notify.as_ref() {
            say_notify_rejected(
                "the service's notifyUrl setting (this PEP's Settings tab)",
                bad);
            return (String::new(), bad.clone());
        }
        if let Some(set) = m.str(settings::DERIVED_KEY)
            .filter(|s| !s.trim().is_empty())
        {
            return (set, String::new());
        }
        let env = self.notify_url.trim();
        if settings::notify_rejected(env) {
            say_notify_rejected("PEP_NOTIFY_URL", env);
            return (String::new(), env.to_string());
        }
        if !env.is_empty() {
            return (env.to_string(), String::new());
        }
        (self.managed.derived_notify(), String::new())
    }

    /// Derives the notify URL again from what the HTTPS listener serves
    /// now (`served`: its certificate's DNS names, `None` while it serves
    /// no certificate), records it, and logs it at INFO the first time and
    /// whenever it changes. Answers whether it changed. Called after every
    /// reload of the pair, which is cheap: nothing is logged or replaced
    /// when the URL is the same.
    pub fn refresh_derived_notify(&self, served: Option<&[String]>) -> bool {
        let name = std::env::var("PEP_NAME").ok();
        let host = system_hostname();
        self.refresh_derived_notify_as(served, name.as_deref(),
                                       host.as_deref())
    }

    /// `refresh_derived_notify()` with `PEP_NAME` and the hostname given,
    /// so a test does not depend on the machine it runs on.
    pub fn refresh_derived_notify_as(
        &self,
        served: Option<&[String]>,
        pep_name: Option<&str>,
        hostname: Option<&str>,
    ) -> bool {
        let derived = derive_notify_url(served, pep_name, hostname,
                                        self.https_port);
        let url = derived.as_ref().map(|d| d.url.as_str()).unwrap_or("");
        if !self.managed.set_derived_notify(url) {
            return false;
        }
        let now = self.now();
        let in_force = now.notify_url == url;
        match &derived {
            Some(d) => tracing::info!(
                "xacml-pep: the derived notify URL is {} (from {}). {}",
                d.url,
                d.from.describe(),
                if !now.notify_rejected.is_empty() {
                    "It is not advertised: a notify URL was set that is \
                     not https, and it is rejected (STS-XPEP-0113) with no \
                     fallback to this one."
                } else if in_force {
                    "It is advertised: neither the service's notifyUrl nor \
                     PEP_NOTIFY_URL is set. The service checks its host \
                     against the listener certificate, so set \
                     PEP_NOTIFY_URL if the service reaches this PEP by \
                     another name."
                } else {
                    "It is not advertised: the service's notifyUrl or \
                     PEP_NOTIFY_URL is set and wins."
                }
            ),
            None => tracing::info!(
                "xacml-pep: no notify URL is derived: the HTTPS listener \
                 serves no certificate yet{}.",
                if in_force { "" } else { " (an explicit one is in force)" }
            ),
        }
        true
    }

    /// `now()` as `GET /` and the heartbeat report it (`settings::report`).
    /// A REJECTED notify URL is reported as what was set, with its source
    /// and `rejected: true`, so the console can say it is rejected rather
    /// than show an empty value (`STS-XPEP-0113`).
    pub fn settings_report(&self) -> serde_json::Value {
        let now = self.now();
        let mut report = settings::report(&self.managed, &now.values());
        if !now.notify_rejected.is_empty() {
            if let Some(one) = report
                .get_mut("values")
                .and_then(|v| v.get_mut(settings::DERIVED_KEY))
                .and_then(serde_json::Value::as_object_mut)
            {
                one.insert("value".to_string(),
                           serde_json::Value::from(now.notify_rejected));
                one.insert("rejected".to_string(),
                           serde_json::Value::Bool(true));
            }
        }
        report
    }

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
            http: plain_http_from_env("PEP_HTTP", "PEP_PORT"),
            crl_http: crl_http_switch(
                std::env::var("PEP_CRL_HTTP").ok().as_deref()),
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
            authzen_callers_configured: !std::env::var("PEP_AUTHZEN_CALLERS")
                .unwrap_or_default()
                .trim()
                .is_empty(),
            authzen_pdp_identifier: authzen_pdp_identifier(),
            authzen_forward_timeout_ms: int_from_env(
                "PEP_AUTHZEN_FORWARD_TIMEOUT_MS",
                5000u64,
            )
            .max(1),
            proxy_enabled: std::env::var("PEP_PROXY").as_deref() != Ok("false"),
            proxy_port: int_from_env("PEP_PROXY_PORT", 9180),
            proxy_http: plain_http_from_env("PEP_PROXY_HTTP",
                                            "PEP_PROXY_PORT"),
            proxy_https_port: int_from_env("PEP_PROXY_HTTPS_PORT", 9543),
            proxy_session_recheck_ms: int_from_env(
                "PEP_PROXY_SESSION_RECHECK_MS",
                5000u64,
            ),
            proxy_session_ttl_ms: int_from_env(
                "PEP_PROXY_SESSION_TTL_MS",
                8 * 3600 * 1000u64,
            )
            .max(1),
            proxy_max_sessions: int_from_env(
                "PEP_PROXY_MAX_SESSIONS",
                10_000usize,
            )
            .max(1),
            proxy_max_accounts: int_from_env(
                "PEP_PROXY_MAX_ACCOUNTS",
                5usize,
            )
            .clamp(1, 32),
            proxy_jwks_ttl_ms: int_from_env(
                "PEP_PROXY_JWKS_TTL_MS",
                300_000u64,
            ),
            proxy_upstream_ca: proxy_upstream_ca(),
            proxy_upstream_insecure: std::env::var(
                "PEP_PROXY_UPSTREAM_INSECURE",
            )
            .as_deref()
                == Ok("true"),
            proxy_rp_allow_insecure: std::env::var(
                "PEP_PROXY_RP_ALLOW_INSECURE",
            )
            .as_deref()
                == Ok("true"),
            proxy_signals_poll_ms: int_from_env(
                "PEP_PROXY_SIGNALS_POLL_MS",
                5000u64,
            )
            .max(100),
            proxy_signals_stale_ms: int_from_env(
                "PEP_PROXY_SIGNALS_STALE_MS",
                60000u64,
            )
            .max(1),
            proxy_strip_cookies: std::env::var("PEP_PROXY_STRIP_COOKIES")
                .unwrap_or_default(),
            log_level: std::env::var("PEP_LOG_LEVEL").unwrap_or_default(),
            managed: Arc::new(Held::from_env()),
            audit_enabled: std::env::var("PEP_AUDIT").as_deref() != Ok("false"),
            audit_interval_ms: int_from_env("PEP_AUDIT_INTERVAL_MS", 5000u64)
                .max(1),
            audit_batch: int_from_env("PEP_AUDIT_BATCH", 200usize)
                .clamp(1, 500),
            audit_buffer: int_from_env("PEP_AUDIT_BUFFER", 10000usize).max(1),
            audit_client_id: env_or("PEP_AUDIT_CLIENT_ID", "sts-remote-pep"),
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

/// `PEP_PROXY_UPSTREAM_CA`, read once. Unreadable, an https upstream is
/// verified against the system's anchors alone — and says so.
fn proxy_upstream_ca() -> Option<Vec<u8>> {
    let path = std::env::var("PEP_PROXY_UPSTREAM_CA")
        .ok()
        .filter(|p| !p.is_empty())?;
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            tracing::error!(
                "{}xacml-pep: PEP_PROXY_UPSTREAM_CA names {} and it could \
                 not be read ({}); an https upstream is verified against the \
                 system's anchors alone.",
                tag("STS-XPEP-0092"),
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
    fn plain_http_is_off_unless_asked_for() {
        // The default: nothing set, nothing bound, nothing to say.
        assert_eq!(plain_http(None, None), (false, None));
        assert_eq!(plain_http(Some(""), None), (false, None));
        // An explicit enable, and an explicit disable.
        assert_eq!(plain_http(Some("true"), None), (true, None));
        assert_eq!(plain_http(Some(" true "), Some("9090")), (true, None));
        assert_eq!(plain_http(Some("false"), Some("9090")), (false, None));
        // The port alone does not turn it on, and is told so.
        assert_eq!(plain_http(None, Some("9090")),
                   (false, Some(PlainHttpNotice::Relied)));
        assert_eq!(plain_http(Some(""), Some("9180")),
                   (false, Some(PlainHttpNotice::Relied)));
        assert_eq!(plain_http(None, Some("  ")), (false, None));
        // A value that is neither stays off, never on.
        for odd in ["TRUE", "yes", "1", "on"] {
            assert_eq!(plain_http(Some(odd), None),
                       (false, Some(PlainHttpNotice::Unreadable(
                           odd.to_string()))), "{}", odd);
        }
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

    /// The CRL-only listener: bound by default where there is a CRL
    /// directory and the API's plain HTTP is off, never alongside it, and
    /// as `PEP_CRL_HTTP` says otherwise.
    #[test]
    fn the_crl_point_stays_up_with_http_off() {
        assert_eq!(crl_http_switch(None), (None, None));
        assert_eq!(crl_http_switch(Some("true")), (Some(true), None));
        assert_eq!(crl_http_switch(Some(" false ")), (Some(false), None));
        assert_eq!(crl_http_switch(Some("yes")),
                   (None, Some("yes".to_string())));
        let dir = std::env::temp_dir().join(format!(
            "pep-crl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut options = Options::from_env("0.0.0");
        options.http.on = false;
        options.crl_dir = Some(dir.clone());
        options.crl_http = (None, None);
        assert!(crl_listener(&options), "a CRL directory binds it");
        options.crl_dir = Some(dir.join("absent"));
        assert!(!crl_listener(&options), "nothing to serve, nothing bound");
        options.crl_http = (Some(true), None);
        assert!(crl_listener(&options), "PEP_CRL_HTTP=true binds it");
        options.crl_dir = Some(dir.clone());
        options.crl_http = (Some(false), None);
        assert!(!crl_listener(&options), "PEP_CRL_HTTP=false never");
        options.crl_http = (None, None);
        options.http.on = true;
        assert!(!crl_listener(&options),
                "with PEP_HTTP=true the API's listener serves /crl/");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// THE DERIVED NOTIFY URL'S HOST, best first ("option 1"): the served
    /// certificate's DNS name equal to the hostname, its first DNS name,
    /// `PEP_NAME` where it is one, the hostname — and nothing at all while
    /// no certificate is served.
    #[test]
    fn the_notify_host_is_derived_best_first() {
        let names = |list: &[&str]| -> Vec<String> {
            list.iter().map(|n| n.to_string()).collect()
        };
        let url = |d: Option<DerivedNotify>| d.map(|d| (d.url, d.from));
        // THE 8081 DEPLOY'S CERTIFICATE: the registered name first, which
        // nothing resolves, then the hostname — the hostname's is picked.
        let deployed = names(&["remote-pep-1", "xacml-pep", "localhost",
                               "127.0.0.1"]);
        assert_eq!(
            url(derive_notify_url(Some(&deployed), Some("remote-pep-1"),
                                  Some("xacml-pep"), 9443)),
            Some(("https://xacml-pep:9443/notify".to_string(),
                  DerivedFrom::CertificateHostname)));
        // Compared without case or a trailing dot, either side.
        let dotted = names(&["a.example", "Pep.Example."]);
        assert_eq!(
            url(derive_notify_url(Some(&dotted), None,
                                  Some("PEP.example"), 9443)),
            Some(("https://pep.example:9443/notify".to_string(),
                  DerivedFrom::CertificateHostname)));
        assert_eq!(
            url(derive_notify_url(Some(&dotted), None,
                                  Some("pep.example."), 9443)),
            Some(("https://pep.example:9443/notify".to_string(),
                  DerivedFrom::CertificateHostname)));
        // The hostname FIRST is still the hostname's rule.
        let first = names(&["xacml-pep", "other.example"]);
        assert_eq!(
            url(derive_notify_url(Some(&first), None, Some("xacml-pep"),
                                  9443)),
            Some(("https://xacml-pep:9443/notify".to_string(),
                  DerivedFrom::CertificateHostname)));
        // A hostname the certificate holds only as a wildcard or an IP
        // address is not matched: those stay skipped.
        let wild = names(&["*.example", "10.0.0.1", "pep-1.example"]);
        for host in ["*.example", "10.0.0.1"] {
            assert_eq!(
                url(derive_notify_url(Some(&wild), None, Some(host), 9443)),
                Some(("https://pep-1.example:9443/notify".to_string(),
                      DerivedFrom::Certificate)), "{}", host);
        }
        // From the certificate's first DNS name, when none is the
        // hostname: the first name a host can be.
        let served = names(&["*.example", "10.0.0.1", "PEP.Example.",
                             "other.example"]);
        assert_eq!(
            url(derive_notify_url(Some(&served), Some("pep-1"),
                                  Some("abc123"), 9443)),
            Some(("https://pep.example:9443/notify".to_string(),
                  DerivedFrom::Certificate)));
        // From PEP_NAME, when the certificate names no DNS host.
        let none: Vec<String> = Vec::new();
        assert_eq!(
            url(derive_notify_url(Some(&none), Some("xacml-pep"),
                                  Some("abc123"), 9443)),
            Some(("https://xacml-pep:9443/notify".to_string(),
                  DerivedFrom::Name)));
        // From the hostname, when PEP_NAME is not a DNS name or unset.
        for name in [Some("pep_1"), Some("a pep"), Some(""), None] {
            assert_eq!(
                url(derive_notify_url(Some(&none), name, Some("4f1c0de"),
                                      9555)),
                Some(("https://4f1c0de:9555/notify".to_string(),
                      DerivedFrom::Hostname)), "{:?}", name);
        }
        // Nothing usable at all, and no listener at all.
        assert_eq!(derive_notify_url(Some(&none), Some("-x"), None, 9443),
                   None);
        assert_eq!(derive_notify_url(None, Some("xacml-pep"),
                                     Some("host"), 9443), None,
                   "no HTTPS certificate served, nothing advertised");
    }

    /// THE FRESH INSTALL (#1760): the PEP reports its hostname, the
    /// service's default certificate names it beside the registered name
    /// (`xacml_pep_tls.ts`'s `derivedNames()`, held in
    /// `tests/pep_listener_certificate.js` E2), and the derived notify URL
    /// is then the hostname's rather than the registered name's.
    #[test]
    fn a_reported_hostname_makes_the_default_certificate_derive_it() {
        let reported = reported_hostname_of(Some("Xacml-Pep.")).unwrap();
        assert_eq!(reported, "xacml-pep");
        // What the service names by default for a PEP registered as
        // remote-pep-1 with no notify URL: its name, then the hostname.
        let defaults = vec!["remote-pep-1".to_string(), reported.clone()];
        let d = derive_notify_url(Some(&defaults), Some("remote-pep-1"),
                                  Some("xacml-pep"), 9443).unwrap();
        assert_eq!(d.url, "https://xacml-pep:9443/notify");
        assert_eq!(d.from, DerivedFrom::CertificateHostname);
        // Without it (an older service, or an older PEP) the defaults are
        // the name alone, and the derivation falls to it, as before.
        let before = vec!["remote-pep-1".to_string()];
        assert_eq!(derive_notify_url(Some(&before), Some("remote-pep-1"),
                                     Some("xacml-pep"), 9443).unwrap().url,
                   "https://remote-pep-1:9443/notify");
    }

    /// Only a DNS name is reported, as the service accepts.
    #[test]
    fn only_a_dns_hostname_is_reported() {
        assert_eq!(reported_hostname_of(Some(" 4f1c0de2a3b4\n")),
                   Some("4f1c0de2a3b4".to_string()));
        for bad in [None, Some(""), Some("10.0.0.1"), Some("::1"),
                    Some("a_b"), Some("123456"), Some("*.example")] {
            assert_eq!(reported_hostname_of(bad), None, "{:?}", bad);
        }
        let long = "a".repeat(254);
        assert_eq!(reported_hostname_of(Some(&long)), None);
    }

    #[test]
    fn a_dns_name_is_a_dns_name() {
        for good in ["a", "xacml-pep", "pep.example.com", "pep.example.",
                     "x1.y2"] {
            assert!(is_dns_name(good), "{}", good);
        }
        for bad in ["", "*.example", "-a", "a-", "a..b", "a_b", "1.2.3.4",
                    "a b", "pep:9443", "a".repeat(64).as_str()] {
            assert!(!is_dns_name(bad), "{}", bad);
        }
    }

    /// THE PRECEDENCE: the service's notifyUrl, then PEP_NOTIFY_URL, then
    /// the derived one, then none — reported as service, environment,
    /// derived and default.
    #[test]
    fn an_explicit_notify_url_wins_over_the_derived_one() {
        use crate::settings::{row_of, Managed};
        let row = row_of("notifyUrl").unwrap();
        let mut options = Options::from_env("0.0.0");
        options.https_port = 9443;
        options.notify_url = String::new();
        options.managed = Arc::new(Held::default());
        assert_eq!(options.now().notify_url, "");
        assert_eq!(options.managed.source(row), "default");
        let derived = vec!["pep.example".to_string()];
        assert!(options.refresh_derived_notify(Some(&derived)));
        assert_eq!(options.now().notify_url,
                   "https://pep.example:9443/notify");
        assert_eq!(options.managed.source(row), "derived");
        assert_eq!(options.settings_report()["values"]["notifyUrl"],
                   serde_json::json!({
                       "value": "https://pep.example:9443/notify",
                       "source": "derived" }));
        // PEP_NOTIFY_URL wins over the derived one.
        options.notify_url = "https://by-env:9443/notify".to_string();
        options.managed = Arc::new(Held::with_env_set(&["PEP_NOTIFY_URL"]));
        options.managed.set_derived_notify("https://pep.example:9443/notify");
        assert_eq!(options.now().notify_url, "https://by-env:9443/notify");
        assert_eq!(options.managed.source(row), "environment");
        // And the service's wins over both.
        options.managed.apply(Managed::parse("t", true, &serde_json::json!({
            "notifyUrl": "https://by-service:9443/notify" })));
        assert_eq!(options.now().notify_url,
                   "https://by-service:9443/notify");
        assert_eq!(options.managed.source(row), "service");
        // An empty one from the service is not set: the next one down.
        options.managed.apply(Managed::parse("t", true, &serde_json::json!({
            "notifyUrl": "" })));
        assert_eq!(options.now().notify_url, "https://by-env:9443/notify");
        assert_eq!(options.managed.source(row), "environment");
        // AN http PEP_NOTIFY_URL IS REJECTED: in force, so nothing is
        // advertised — not the derived one either — and reported as the
        // environment's, rejected.
        options.notify_url = "http://old:9090/notify".to_string();
        let now = options.now();
        assert_eq!(now.notify_url, "");
        assert_eq!(now.notify_rejected, "http://old:9090/notify");
        assert_eq!(options.managed.derived_notify(),
                   "https://pep.example:9443/notify",
                   "a derived one is held, and still not used");
        assert_eq!(options.managed.source(row), "environment");
        assert_eq!(options.settings_report()["values"]["notifyUrl"],
                   serde_json::json!({ "value": "http://old:9090/notify",
                                       "source": "environment",
                                       "rejected": true }));
        // An https one from the service still wins over it.
        options.managed.apply(Managed::parse("t", true, &serde_json::json!({
            "notifyUrl": "https://by-service:9443/notify" })));
        assert_eq!(options.now().notify_url,
                   "https://by-service:9443/notify");
        assert_eq!(options.now().notify_rejected, "");
        assert!(options.settings_report()["values"]["notifyUrl"]
            .get("rejected").is_none());
        // AN http notifyUrl FROM THE SERVICE IS REJECTED TOO: the service's,
        // in force over a good PEP_NOTIFY_URL and the derived one, and
        // advertised as nothing.
        options.notify_url = "https://by-env:9443/notify".to_string();
        options.managed.apply(Managed::parse("t", true, &serde_json::json!({
            "notifyUrl": "http://by-service:9090/notify" })));
        let now = options.now();
        assert_eq!(now.notify_url, "");
        assert_eq!(now.notify_rejected, "http://by-service:9090/notify");
        assert_eq!(options.managed.source(row), "service");
        assert_eq!(options.settings_report()["values"]["notifyUrl"],
                   serde_json::json!({
                       "value": "http://by-service:9090/notify",
                       "source": "service", "rejected": true }));
        // Unset at both, the derived one is advertised again.
        options.notify_url = String::new();
        options.managed = Arc::new(Held::default());
        options.managed.set_derived_notify("https://pep.example:9443/notify");
        assert_eq!(options.now().notify_url,
                   "https://pep.example:9443/notify");
        assert_eq!(options.now().notify_rejected, "");
    }

    /// WHAT IS REJECTED: a value set that is not an https URL; empty is
    /// "not set".
    #[test]
    fn a_notify_url_that_is_not_https_is_rejected() {
        use crate::settings::{notify_rejected, Managed};
        for bad in ["http://pep:9090/notify", "HTTP://pep/notify",
                    " http://pep/notify ", "ftp://pep/notify", "pep:9443",
                    "httpsx://pep/notify"] {
            assert!(notify_rejected(bad), "{}", bad);
        }
        for good in ["", "  ", "https://pep:9443/notify",
                     "HTTPS://pep:9443/notify"] {
            assert!(!notify_rejected(good), "{:?}", good);
        }
        // From the service: rejected, not refused (no fallback named).
        let managed = Managed::parse("t", true, &serde_json::json!({
            "notifyUrl": "http://pep:9090/notify" }));
        assert_eq!(managed.rejected_notify.as_deref(),
                   Some("http://pep:9090/notify"));
        assert!(managed.refused.is_empty());
        assert!(managed.str("notifyUrl").is_none());
        // An https one with a user name is still refused, as before.
        let managed = Managed::parse("t", true, &serde_json::json!({
            "notifyUrl": "https://u:p@pep/notify" }));
        assert!(managed.rejected_notify.is_none());
        assert_eq!(managed.refused.len(), 1);
    }

    /// Only an https notify URL is advertised (the guard).
    #[test]
    fn only_an_https_notify_url_is_advertised() {
        assert_eq!(advertised_notify_url(""), "");
        assert_eq!(advertised_notify_url("https://pep:9443/notify"),
                   "https://pep:9443/notify");
        assert_eq!(advertised_notify_url("HTTPS://pep:9443/notify"),
                   "HTTPS://pep:9443/notify");
        assert_eq!(advertised_notify_url("http://pep:9090/notify"), "");
        assert_eq!(advertised_notify_url("ftp://pep/notify"), "");
    }
}
