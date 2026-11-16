// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! One listener's tuning, as the service's pull sends it.
//!
//! The console stores the same knobs Server Settings → Listeners exposes,
//! plus a thread pool of that listener's own. The pull fills a complete
//! `tuning` for every defined listener and an `environmentTuning` object
//! for the four the environment binds, so a missing member means an older
//! service and the defaults below. A value outside a bound is clamped: the
//! service already refused a bad one (`STS-XACML-0281`), and a PEP that
//! cannot APPLY a TLS knob logs `STS-XPEP-0119` and keeps the acceptor it
//! had (`listener.rs`).
//!
//! THE REVERSE PROXY'S POOL IS THE LARGEST: api 4/32, proxy 16/128, crl
//! 1/4. The environment's `api-http` uses the API defaults even when this
//! process is serving CRLs only — the service does not know `PEP_CRL_HTTP`,
//! and an administrator sets 1/4 on that listener when that is what the
//! port is for.

use serde_json::Value;

/// The pool a purpose starts with. The reverse proxy's is the largest.
pub fn threads_for(purpose: &str) -> (usize, usize) {
    if purpose == "proxy" {
        (16, 128)
    } else if purpose == "crl" {
        (1, 4)
    } else {
        (4, 32)
    }
}

/// TLS, HTTP and the thread pool of one listener. HTTP forces HTTP/2 off
/// and does not ask for a client certificate; the TLS fields are still
/// filled, so turning the listener to HTTPS has them.
#[derive(Debug, Clone, PartialEq)]
pub struct Tuning {
    pub min_version: String,
    pub disable_tls12: bool,
    pub ciphers: String,
    pub tls13_cipher_suites: String,
    pub pqc_only: bool,
    pub groups: String,
    pub signature_algorithms: String,
    pub trust_anchors_file: String,
    pub trust_issued_client_certificates: bool,
    pub ask_client_certificate: bool,
    pub require_client_certificate: bool,
    pub session_timeout_s: u64,
    pub session_cache_size: u64,
    pub keep_alive_timeout_s: u64,
    pub headers_timeout_s: u64,
    pub max_requests_per_socket: u64,
    pub max_connections: u64,
    pub http2: bool,
    pub http2_max_concurrent_streams: u32,
    pub thread_pool_min: usize,
    pub thread_pool_max: usize,
}

const CIPHERS_DEFAULT: &str = "ECDHE-ECDSA-AES128-GCM-SHA256:\
ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:\
ECDHE-RSA-AES256-GCM-SHA384";
const TLS13_DEFAULT: &str = "TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,\
TLS_CHACHA20_POLY1305_SHA256";
const GROUPS_DEFAULT: &str = "X25519MLKEM768:SecP256r1MLKEM768:\
SecP384r1MLKEM1024 / X25519:P-256 / X448:P-384:P-521";
const SIGALGS_DEFAULT: &str = "mldsa65:mldsa87:mldsa44:\
ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:\
ed25519:ed448:rsa_pss_pss_sha256:rsa_pss_pss_sha384:rsa_pss_pss_sha512:\
rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:\
rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512";

impl Tuning {
    /// The built-in tuning for a purpose and a protocol.
    pub fn defaults(purpose: &str, https: bool) -> Tuning {
        let (min, max) = threads_for(purpose);
        let mut out = Tuning {
            min_version: "TLSv1.2".into(),
            disable_tls12: true,
            ciphers: CIPHERS_DEFAULT.into(),
            tls13_cipher_suites: TLS13_DEFAULT.into(),
            pqc_only: false,
            groups: GROUPS_DEFAULT.into(),
            signature_algorithms: SIGALGS_DEFAULT.into(),
            trust_anchors_file: String::new(),
            trust_issued_client_certificates: https && purpose == "api",
            ask_client_certificate: https,
            require_client_certificate: false,
            session_timeout_s: 300,
            session_cache_size: 2048,
            keep_alive_timeout_s: 60,
            headers_timeout_s: 0,
            max_requests_per_socket: 0,
            max_connections: 0,
            http2: https,
            http2_max_concurrent_streams: 100,
            thread_pool_min: min,
            thread_pool_max: max,
        };
        // disableTls12 forces TLS 1.3, as the service's effective() does,
        // before the value is stored.
        if out.disable_tls12 {
            out.min_version = "TLSv1.3".into();
        }
        if !https {
            out.http2 = false;
            out.ask_client_certificate = false;
            out.require_client_certificate = false;
        }
        out
    }

    /// `raw` over the defaults. Absent members keep the default. Numbers
    /// are clamped into the service's bounds; `threadPoolMax` is raised to
    /// `threadPoolMin` when a document has them the wrong way round.
    pub fn overlay(raw: &Value, purpose: &str, https: bool) -> Tuning {
        let mut out = Tuning::defaults(purpose, https);
        let Some(given) = raw.as_object() else {
            return out;
        };
        if let Some(v) = given.get("minVersion").and_then(|v| v.as_str()) {
            if matches!(v, "TLSv1" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3") {
                out.min_version = v.to_string();
            }
        }
        out.disable_tls12 = flag(given.get("disableTls12"), out.disable_tls12);
        if let Some(v) = text(given.get("ciphers")) {
            out.ciphers = v;
        }
        if let Some(v) = text(given.get("tls13CipherSuites")) {
            out.tls13_cipher_suites = v;
        }
        out.pqc_only = flag(given.get("pqcOnly"), out.pqc_only);
        if let Some(v) = text(given.get("groups")) {
            out.groups = v;
        }
        if let Some(v) = text(given.get("signatureAlgorithms")) {
            out.signature_algorithms = v;
        }
        if let Some(v) = given.get("trustAnchorsFile").and_then(|v| v.as_str())
        {
            out.trust_anchors_file = v.to_string();
        }
        out.trust_issued_client_certificates = flag(
            given.get("trustIssuedClientCertificates"),
            out.trust_issued_client_certificates,
        );
        out.ask_client_certificate = flag(
            given.get("askClientCertificate"),
            out.ask_client_certificate,
        );
        out.require_client_certificate = flag(
            given.get("requireClientCertificate"),
            out.require_client_certificate,
        );
        out.session_timeout_s = clamp_u64(
            given.get("sessionTimeoutS"),
            1,
            86400,
            out.session_timeout_s,
        );
        out.session_cache_size = clamp_u64(
            given.get("sessionCacheSize"),
            0,
            1_000_000,
            out.session_cache_size,
        );
        out.keep_alive_timeout_s = clamp_u64(
            given.get("keepAliveTimeoutS"),
            1,
            3600,
            out.keep_alive_timeout_s,
        );
        out.headers_timeout_s = clamp_u64(
            given.get("headersTimeoutS"),
            0,
            3600,
            out.headers_timeout_s,
        );
        out.max_requests_per_socket = clamp_u64(
            given.get("maxRequestsPerSocket"),
            0,
            1_000_000,
            out.max_requests_per_socket,
        );
        out.max_connections = clamp_u64(
            given.get("maxConnections"),
            0,
            1_000_000,
            out.max_connections,
        );
        out.http2 = flag(given.get("http2"), out.http2);
        out.http2_max_concurrent_streams = clamp_u64(
            given.get("http2MaxConcurrentStreams"),
            1,
            1000,
            out.http2_max_concurrent_streams as u64,
        ) as u32;
        out.thread_pool_min = clamp_u64(
            given.get("threadPoolMin"),
            1,
            256,
            out.thread_pool_min as u64,
        ) as usize;
        out.thread_pool_max = clamp_u64(
            given.get("threadPoolMax"),
            1,
            1024,
            out.thread_pool_max as u64,
        ) as usize;
        if out.thread_pool_max < out.thread_pool_min {
            out.thread_pool_max = out.thread_pool_min;
        }
        if out.disable_tls12 || out.pqc_only {
            out.min_version = "TLSv1.3".into();
        }
        if !https {
            out.http2 = false;
            out.ask_client_certificate = false;
            out.require_client_certificate = false;
        }
        out
    }
}

/// A posted bool. Anything that is not on or off keeps `fallback`.
fn flag(value: Option<&Value>, fallback: bool) -> bool {
    match value {
        Some(Value::Bool(v)) => *v,
        Some(Value::String(v)) => match v.as_str() {
            "true" | "on" | "1" => true,
            "false" | "off" | "0" => false,
            _ => fallback,
        },
        Some(Value::Number(n)) => {
            if n.as_i64() == Some(1) {
                true
            } else if n.as_i64() == Some(0) {
                false
            } else {
                fallback
            }
        }
        _ => fallback,
    }
}

fn text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn clamp_u64(value: Option<&Value>, min: u64, max: u64, fallback: u64) -> u64 {
    let n = match value {
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s)) => s.parse().ok(),
        _ => None,
    };
    n.map(|n| n.clamp(min, max)).unwrap_or(fallback)
}

/// The header timeout the service actually arms: at least one second past
/// the keep-alive, so a connection reused at the last moment is not the one
/// this end is closing (`tls/tls_server.js`).
pub fn headers_timeout_s(keep_alive: u64, asked: u64) -> u64 {
    if asked > keep_alive {
        asked
    } else {
        keep_alive.saturating_add(1)
    }
}

/// OpenSSL's groups list: colon-separated, no spaces. `pqc_only` keeps the
/// ML-KEM groups, or the three hybrids when the list names none.
pub fn groups_list(raw: &str, pqc_only: bool) -> String {
    let mut groups = Vec::new();
    for part in raw.split(|c: char| c.is_whitespace() || c == '/') {
        for group in part.split(':') {
            if !group.is_empty() {
                groups.push(group);
            }
        }
    }
    if pqc_only {
        groups.retain(|g| {
            let lower = g.to_ascii_lowercase();
            lower.contains("mlkem") || lower.contains("ml-kem")
        });
        if groups.is_empty() {
            return "X25519MLKEM768:SecP256r1MLKEM768:\
                    SecP384r1MLKEM1024"
                .into();
        }
    }
    groups.join(":")
}

/// TLS 1.3 suites as OpenSSL wants them (colons). Post-quantum mode is the
/// two 256-bit suites, whatever the list says.
pub fn tls13_suites(raw: &str, pqc_only: bool) -> String {
    if pqc_only {
        return "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256".into();
    }
    raw.replace([',', ' '], ":")
        .split(':')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_proxy_pool_is_the_largest_and_plain_http_forces_http2_off() {
        let api = Tuning::defaults("api", true);
        let proxy = Tuning::defaults("proxy", true);
        let crl = Tuning::defaults("crl", false);
        assert_eq!((api.thread_pool_min, api.thread_pool_max), (4, 32));
        assert_eq!((proxy.thread_pool_min, proxy.thread_pool_max), (16, 128));
        assert_eq!((crl.thread_pool_min, crl.thread_pool_max), (1, 4));
        assert!(api.http2);
        assert!(!crl.http2);
        assert!(!crl.ask_client_certificate);
        assert_eq!(api.min_version, "TLSv1.3");
        assert!(api.trust_issued_client_certificates);
        assert!(!proxy.trust_issued_client_certificates);
    }

    #[test]
    fn a_pool_is_clamped_and_max_is_at_least_min() {
        let tuned = Tuning::overlay(
            &json!({ "threadPoolMin": 400, "threadPoolMax": 2, "http2": true }),
            "api",
            false,
        );
        assert_eq!(tuned.thread_pool_min, 256);
        assert_eq!(tuned.thread_pool_max, 256);
        assert!(!tuned.http2, "plain HTTP does not offer HTTP/2");
    }

    #[test]
    fn headers_wait_past_the_keep_alive() {
        assert_eq!(headers_timeout_s(60, 0), 61);
        assert_eq!(headers_timeout_s(60, 120), 120);
    }
}
