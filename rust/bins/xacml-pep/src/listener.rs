// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The HTTPS listener, whose pair is re-read from disk (2026-09-13).
//!
//! **The files are watched because the order of events requires it.** The
//! certificate is issued by the realm this PEP REGISTERED to, which happens
//! after this process starts, so the pair does not exist when the container
//! does. The paths are re-read every `PEP_HTTPS_RELOAD_INTERVAL_MS`, the
//! listener starts the first time a usable pair appears, and a later pair is
//! swapped in without a restart — connections already open keep the
//! certificate they negotiated.
//!
//! **A bad pair never replaces a good one.** Files are written one at a
//! time, so between the writes they disagree; a pair is checked whole (both
//! parse, the key is the certificate's, OpenSSL accepts them) before it is
//! used. The change test is a digest of the two files, not their mtimes.
//!
//! OpenSSL rather than rustls (rust/DESIGN.md section 6): the realm's
//! `pep-tls` CA may issue an ML-DSA certificate, which only OpenSSL serves.
//!
//! **A CLIENT CERTIFICATE FOLLOWS THE LISTENER'S TUNING** (#1179, and the
//! same knobs Server Settings → Listeners exposes). The default is what
//! this file used to hard-code: with `PEP_AUTHZEN_CLIENT_CA` set, the API
//! listener ASKS and does not REQUIRE, and a certificate that does not
//! verify still completes the handshake (`requestCert`,
//! `rejectUnauthorized: false`). The reverse proxy asks everybody and
//! checks nobody. `requireClientCertificate` is the one setting that fails
//! the handshake when nothing is presented. A knob OpenSSL will not apply
//! is logged (`STS-XPEP-0119`); once a certificate is already served, that
//! failure keeps the previous acceptor. [`peer_of`] reads what was
//! presented and whether it verified.

use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use chrono::{DateTime, Utc};
use openssl::asn1::{Asn1Time, Asn1TimeRef};
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::PKey;
use openssl::ssl::{
    SslAcceptor, SslMethod, SslRef, SslSessionCacheMode, SslVerifyMode,
    SslVersion,
};
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509Name, X509NameRef, X509VerifyResult, X509};
use serde_json::{json, Value};
use sts_core::log::tag;

use crate::listener_pool::ListenerRuntime;
use crate::listener_tuning::{groups_list, tls13_suites, Tuning};

/// What `GET /` says about the listener.
#[derive(Debug, Clone, Default)]
struct Status {
    configured: bool,
    listening: bool,
    port: Option<u16>,
    digest: String,
    loaded_at: Option<String>,
    certificate: Option<Value>,
    /// The served certificate's subjectAltName DNS names, in its order —
    /// what the notify URL is derived from (`options::derive_notify_url`).
    dns_names: Vec<String>,
    last_problem: Option<String>,
    last_checked_at: Option<String>,
    last_logged_problem: String,
    /// Why the socket would not bind, from the closed set the heartbeat
    /// reports (#1760); `None` while it has not failed.
    bind_failed: Option<&'static str>,
}

/// The listener's pair and what is known about it.
pub struct HttpsListener {
    cert_path: String,
    key_path: String,
    port: u16,
    reload_interval_ms: u64,
    status: Mutex<Status>,
    acceptor: RwLock<Option<Arc<SslAcceptor>>>,
    /// The authorities a caller's certificate must chain to (#1179); none
    /// means no certificate is asked for — unless `ask_any`.
    client_ca: Vec<X509>,
    /// The reverse proxy's listener (#1760): ask EVERY client for a
    /// certificate, verify none against an authority, require none. The
    /// handshake alone proves possession of the key, which is all a
    /// certificate-bound token's `cnf.x5t#S256` asks.
    ask_any: bool,
    /// Its pair is installed, not read from files (#1760).
    in_memory: bool,
    /// TLS knobs in force. Rebuilt onto `pair` by [`Self::set_tuning`].
    tuning: Mutex<Tuning>,
    /// The PEM last installed, so a tuning change does not re-read the
    /// files or ask for another certificate. Empty until the first pair.
    pair: Mutex<Option<(Vec<u8>, Vec<u8>)>>,
}

/// Why a bind failed, from the closed set the heartbeat reports (#1760):
/// never the operating system's sentence, which goes to the log.
pub fn bind_reason(error: &std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::AddrInUse => "address-in-use",
        std::io::ErrorKind::PermissionDenied => "permission-denied",
        std::io::ErrorKind::AddrNotAvailable => "address-unavailable",
        _ => "other",
    }
}

/// The certificate a caller presented on an HTTPS connection: the SHA-256
/// of its DER as lower-case hex, its subject for a log line, and whether it
/// verified against `PEP_AUTHZEN_CLIENT_CA` — with why not, when it did not.
#[derive(Debug, Clone, PartialEq)]
pub struct Peer {
    pub sha256: String,
    pub subject: String,
    pub verified: bool,
    pub why: String,
}

/// What the handler knows about the connection a request came in on: a
/// request extension, set per connection by `main.rs`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Transport {
    pub https: bool,
    pub peer: Option<Peer>,
    /// The address the connection came from: the reverse proxy's
    /// `X-Forwarded-For` (#1760). Never a header a client sent.
    pub remote: Option<std::net::SocketAddr>,
    /// The CRL-only plain-HTTP listener (2026-11-14): it answers
    /// `GET /crl/<name>` and nothing else (`STS-XPEP-0114`).
    pub crl_only: bool,
}

/// The caller's certificate on an accepted connection, read with the
/// library that verified it.
pub fn peer_of(ssl: &SslRef) -> Option<Peer> {
    let leaf = ssl.peer_certificate()?;
    let sha256 = leaf
        .digest(MessageDigest::sha256())
        .map(|d| d.iter().map(|b| format!("{:02x}", b)).collect::<String>())
        .unwrap_or_default();
    let result = ssl.verify_result();
    Some(Peer {
        sha256,
        subject: name_text(leaf.subject_name()),
        verified: result == X509VerifyResult::OK,
        why: if result == X509VerifyResult::OK {
            String::new()
        } else {
            result.error_string().to_string()
        },
    })
}

/// The client CA bundle, parsed once. One that will not parse asks for no
/// certificate, which admits nobody to AuthZEN — and says so.
fn client_authorities(bundle: Option<&[u8]>) -> Vec<X509> {
    let Some(bundle) = bundle else {
        return Vec::new();
    };
    match X509::stack_from_pem(bundle) {
        Ok(list) if !list.is_empty() => list,
        Ok(_) | Err(_) => {
            tracing::error!(
                "{}xacml-pep: PEP_AUTHZEN_CLIENT_CA holds no certificate \
                 OpenSSL can read, so the HTTPS listener asks no caller for \
                 one and the AuthZEN endpoints admit nobody.",
                tag("STS-XPEP-0039")
            );
            Vec::new()
        }
    }
}

fn time_of(t: &Asn1TimeRef) -> Option<DateTime<Utc>> {
    let epoch = Asn1Time::from_unix(0).ok()?;
    let diff = epoch.diff(t).ok()?;
    let seconds = i64::from(diff.days) * 86400 + i64::from(diff.secs);
    DateTime::from_timestamp(seconds, 0)
}

/// A distinguished name as node's `X509Certificate` draws it with its line
/// breaks turned into `, `.
fn name_text(name: &X509NameRef) -> String {
    name.entries()
        .map(|entry| {
            let key = entry.object().nid().short_name().unwrap_or("?");
            let value =
                String::from_utf8_lossy(entry.data().as_slice()).into_owned();
            format!("{}={}", key, value)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// subjectAltName as node draws it: `DNS:a, IP Address:1.2.3.4`.
fn alt_names(x509: &X509) -> String {
    let Some(names) = x509.subject_alt_names() else {
        return String::new();
    };
    names
        .iter()
        .filter_map(|name| {
            if let Some(dns) = name.dnsname() {
                Some(format!("DNS:{}", dns))
            } else if let Some(ip) = name.ipaddress() {
                let address = match ip.len() {
                    4 => <[u8; 4]>::try_from(ip).ok().map(IpAddr::from),
                    16 => <[u8; 16]>::try_from(ip).ok().map(IpAddr::from),
                    _ => None,
                };
                address.map(|a| format!("IP Address:{}", a))
            } else if let Some(uri) = name.uri() {
                Some(format!("URI:{}", uri))
            } else {
                name.email().map(|e| format!("email:{}", e))
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// A certificate's subjectAltName DNS names, in the certificate's order.
fn dns_names_of(x509: &X509) -> Vec<String> {
    x509.subject_alt_names()
        .map(|names| {
            names
                .iter()
                .filter_map(|name| name.dnsname().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// What `GET /` says about the certificate being served — read with the
/// same library the handshake uses.
fn describe_served(
    x509: &X509,
) -> (Value, Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
    let from = time_of(x509.not_before());
    let to = time_of(x509.not_after());
    let serial = x509
        .serial_number()
        .to_bn()
        .and_then(|bn| bn.to_hex_str().map(|h| h.to_lowercase()))
        .unwrap_or_default();
    let fingerprint = x509
        .digest(MessageDigest::sha256())
        .map(|d| {
            d.iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(":")
        })
        .unwrap_or_default();
    let iso = |t: Option<DateTime<Utc>>| {
        t.map(sts_core::time::iso).unwrap_or_default()
    };
    (
        json!({
            "subject": name_text(x509.subject_name()),
            "issuer": name_text(x509.issuer_name()),
            "serialHex": serial,
            "subjectAltName": alt_names(x509),
            "validFrom": iso(from),
            "validTo": iso(to),
            "fingerprint256": fingerprint
        }),
        from,
        to,
    )
}

/// Why `acceptor_for` built nothing. A pair error is the certificate's
/// (`STS-XPEP-0030`). A tuning error is a knob (`STS-XPEP-0119`), and only
/// when `strict`: the caller keeps the acceptor it already serves.
enum AcceptorFault {
    Pair(String),
    Tuning,
}

/// Builds an acceptor from a pair, checked whole, then applies `tuning`.
/// `strict` is a listener that already serves a certificate: any knob that
/// OpenSSL refuses keeps that acceptor rather than serving a half-applied
/// one. The first pair is not strict, so a knob the library does not know
/// is logged and skipped and the certificate is still served.
fn acceptor_for(
    cert: &[u8],
    key: &[u8],
    client_ca: &[X509],
    ask_any: bool,
    tuning: &Tuning,
    strict: bool,
) -> Result<(SslAcceptor, X509), AcceptorFault> {
    let chain = X509::stack_from_pem(cert)
        .map_err(|e| AcceptorFault::Pair(e.to_string()))?;
    let mut chain = chain.into_iter();
    let leaf = chain.next().ok_or_else(|| {
        AcceptorFault::Pair(
            "the certificate file holds no certificate".to_string(),
        )
    })?;
    let private = PKey::private_key_from_pem(key)
        .map_err(|e| AcceptorFault::Pair(e.to_string()))?;
    let public = leaf
        .public_key()
        .map_err(|e| AcceptorFault::Pair(e.to_string()))?;
    if !public.public_eq(&private) {
        return Err(AcceptorFault::Pair(
            "the private key is not the key this certificate certifies — \
             most likely one file of the pair has been written and the \
             other not yet"
                .into(),
        ));
    }
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
        .map_err(|e| AcceptorFault::Pair(e.to_string()))?;
    builder
        .set_certificate(&leaf)
        .map_err(|e| AcceptorFault::Pair(e.to_string()))?;
    for extra in chain {
        builder
            .add_extra_chain_cert(extra)
            .map_err(|e| AcceptorFault::Pair(e.to_string()))?;
    }
    builder
        .set_private_key(&private)
        .map_err(|e| AcceptorFault::Pair(e.to_string()))?;
    builder
        .check_private_key()
        .map_err(|e| AcceptorFault::Pair(e.to_string()))?;
    let mut faults = Vec::new();
    apply_tls_knobs(&mut builder, tuning, &mut faults);
    apply_client_auth(
        &mut builder,
        client_ca,
        ask_any,
        tuning,
        &mut faults,
    );
    if !faults.is_empty() {
        tracing::error!(
            "{}xacml-pep: a listener's TLS settings were not all applied: \
             {}. {}",
            tag("STS-XPEP-0119"),
            faults.join("; "),
            if strict {
                "The certificate already served is kept."
            } else {
                "The certificate is served without those settings."
            }
        );
        if strict {
            return Err(AcceptorFault::Tuning);
        }
    }
    Ok((builder.build(), leaf))
}

/// Records one knob OpenSSL refused. The builder keeps what it had.
fn knob(
    faults: &mut Vec<String>,
    what: &str,
    result: Result<(), openssl::error::ErrorStack>,
) {
    if let Err(error) = result {
        faults.push(format!("{}: {}", what, error));
    }
}

/// Minimum version, suites, groups, session cache and ALPN.
fn apply_tls_knobs(
    builder: &mut openssl::ssl::SslAcceptorBuilder,
    tuning: &Tuning,
    faults: &mut Vec<String>,
) {
    let min = if tuning.pqc_only || tuning.min_version == "TLSv1.3" {
        SslVersion::TLS1_3
    } else if tuning.min_version == "TLSv1.1" {
        SslVersion::TLS1_1
    } else if tuning.min_version == "TLSv1" {
        SslVersion::TLS1
    } else {
        SslVersion::TLS1_2
    };
    knob(
        faults,
        "minimum version",
        builder.set_min_proto_version(Some(min)),
    );
    if !tuning.pqc_only && !tuning.ciphers.is_empty() {
        knob(faults, "ciphers", builder.set_cipher_list(&tuning.ciphers));
    }
    let suites = tls13_suites(&tuning.tls13_cipher_suites, tuning.pqc_only);
    if !suites.is_empty() {
        knob(
            faults,
            "TLS 1.3 suites",
            builder.set_ciphersuites(&suites),
        );
    }
    let groups = groups_list(&tuning.groups, tuning.pqc_only);
    if !groups.is_empty() {
        knob(faults, "groups", builder.set_groups_list(&groups));
    }
    if !tuning.signature_algorithms.is_empty() {
        knob(
            faults,
            "signature algorithms",
            builder.set_sigalgs_list(&tuning.signature_algorithms),
        );
    }
    if tuning.session_cache_size == 0 {
        builder.set_session_cache_mode(
            SslSessionCacheMode::SERVER
                | SslSessionCacheMode::NO_INTERNAL_STORE,
        );
    } else {
        builder.set_session_cache_mode(SslSessionCacheMode::SERVER);
        builder.set_session_cache_size(tuning.session_cache_size as i32);
    }
    // openssl 0.10 has no safe SSL_CTX_set_timeout, and this crate forbids
    // unsafe. OpenSSL's own default is 300s, which is this service's
    // default, so a listener left alone matches. A different value is
    // recorded and not applied; the other knobs still are.
    if tuning.session_timeout_s != 300 {
        tracing::error!(
            "{}xacml-pep: sessionTimeoutS {} is not applied. This PEP's \
             TLS library has no session-lifetime call, so a session lives \
             300 seconds. The listener's other settings are applied.",
            tag("STS-XPEP-0119"),
            tuning.session_timeout_s
        );
    }
    let alpn: &[u8] = if tuning.http2 {
        b"\x02h2\x08http/1.1"
    } else {
        b"\x08http/1.1"
    };
    knob(faults, "ALPN", builder.set_alpn_protos(alpn));
}

/// Who is asked for a certificate. Neither ask nor require sets nothing,
/// even when a client CA is configured. An authority list asks and checks
/// (`xacml-pep-authzen`); `ask_any` with no authorities asks everybody and
/// checks nobody (`xacml-pep-proxy`). Require fails the handshake when the
/// client presents nothing.
fn apply_client_auth(
    builder: &mut openssl::ssl::SslAcceptorBuilder,
    client_ca: &[X509],
    ask_any: bool,
    tuning: &Tuning,
    faults: &mut Vec<String>,
) {
    let want = tuning.ask_client_certificate
        || tuning.require_client_certificate;
    if !want {
        return;
    }
    let mut authorities = Vec::new();
    if tuning.trust_issued_client_certificates {
        authorities.extend(client_ca.iter().cloned());
    }
    if !tuning.trust_anchors_file.is_empty() {
        match std::fs::read(&tuning.trust_anchors_file) {
            Ok(pem) => match X509::stack_from_pem(&pem) {
                Ok(stack) => authorities.extend(stack),
                Err(error) => {
                    faults.push(format!("trust anchors: {}", error));
                }
            },
            Err(error) => {
                faults.push(format!(
                    "trust anchors file: {}",
                    error
                ));
            }
        }
    }
    if !authorities.is_empty() {
        if let Err(error) = client_store(builder, &authorities) {
            faults.push(error);
            return;
        }
        let require = tuning.require_client_certificate;
        let mut mode = SslVerifyMode::PEER;
        if require {
            mode |= SslVerifyMode::FAIL_IF_NO_PEER_CERT;
        }
        builder.set_verify_callback(mode, move |preverify, _| {
            if require {
                preverify
            } else {
                true
            }
        });
        knob(
            faults,
            "session context",
            builder.set_session_id_context(b"xacml-pep-authzen"),
        );
        return;
    }
    if !ask_any {
        // The API listener with no client CA asks nobody, which is how a
        // PEP without PEP_AUTHZEN_CLIENT_CA has always behaved.
        return;
    }
    let require = tuning.require_client_certificate;
    let mut mode = SslVerifyMode::PEER;
    if require {
        mode |= SslVerifyMode::FAIL_IF_NO_PEER_CERT;
    }
    builder.set_verify_callback(mode, move |preverify, _| {
        if require {
            preverify
        } else {
            true
        }
    });
    knob(
        faults,
        "session context",
        builder.set_session_id_context(b"xacml-pep-proxy"),
    );
}

/// The trust store and the CA names advertised to the client.
fn client_store(
    builder: &mut openssl::ssl::SslAcceptorBuilder,
    authorities: &[X509],
) -> Result<(), String> {
    let mut store = X509StoreBuilder::new().map_err(|e| e.to_string())?;
    let mut names = Stack::<X509Name>::new().map_err(|e| e.to_string())?;
    for authority in authorities {
        store
            .add_cert(authority.clone())
            .map_err(|e| e.to_string())?;
        if let Ok(name) = authority.subject_name().to_owned() {
            names.push(name).map_err(|e| e.to_string())?;
        }
    }
    builder
        .set_verify_cert_store(store.build())
        .map_err(|e| e.to_string())?;
    builder.set_client_ca_list(names);
    Ok(())
}

impl HttpsListener {
    pub fn new(
        cert_path: &str,
        key_path: &str,
        port: u16,
        reload_interval_ms: u64,
        client_ca: Option<&[u8]>,
    ) -> HttpsListener {
        HttpsListener {
            cert_path: cert_path.to_string(),
            key_path: key_path.to_string(),
            port,
            reload_interval_ms,
            status: Mutex::new(Status::default()),
            acceptor: RwLock::new(None),
            client_ca: client_authorities(client_ca),
            ask_any: false,
            in_memory: false,
            tuning: Mutex::new(Tuning::defaults("api", true)),
            pair: Mutex::new(None),
        }
    }

    /// The reverse proxy's HTTPS listener (#1760): the same pair, re-read
    /// on the same interval, on a port of its own, asking every client for
    /// a certificate and requiring none.
    pub fn for_proxy(
        cert_path: &str,
        key_path: &str,
        port: u16,
        reload_interval_ms: u64,
    ) -> HttpsListener {
        let mut listener = HttpsListener::new(
            cert_path,
            key_path,
            port,
            reload_interval_ms,
            None,
        );
        listener.ask_any = true;
        listener.store_tuning(Tuning::defaults("proxy", true));
        listener
    }

    /// Whether this listener asks callers for a certificate (#1179).
    pub fn asks_for_client_certificates(&self) -> bool {
        !self.client_ca.is_empty()
    }

    fn status(&self) -> MutexGuard<'_, Status> {
        match self.status.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    pub fn is_configured(&self) -> bool {
        !self.cert_path.is_empty() || !self.key_path.is_empty()
    }

    /// The acceptor for a new connection: the pair being served NOW.
    pub fn current(&self) -> Option<Arc<SslAcceptor>> {
        match self.acceptor.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// A problem, logged once per distinct sentence and always recorded.
    /// `waiting` is the ordinary state before a certificate exists, which
    /// is information rather than an error.
    fn problem(&self, code: &str, sentence: String, waiting: bool) {
        let mut status = self.status();
        status.last_problem = Some(sentence.clone());
        if sentence != status.last_logged_problem {
            status.last_logged_problem = sentence.clone();
            if waiting {
                tracing::info!("xacml-pep: {}", sentence);
            } else {
                tracing::error!("{}xacml-pep: {}", tag(code), sentence);
            }
        }
    }

    /// One reload. Answers whether the listener should be started now (the
    /// first usable pair).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn reload(&self) -> bool {
        {
            let mut status = self.status();
            status.last_checked_at = Some(sts_core::time::iso_now());
            status.configured =
                !self.cert_path.is_empty() && !self.key_path.is_empty();
        }
        if self.cert_path.is_empty() && self.key_path.is_empty() {
            return false;
        }
        if self.cert_path.is_empty() || self.key_path.is_empty() {
            self.problem(
                "STS-XPEP-0029",
                format!(
                "only {} is set, so there is no HTTPS listener. Both halves \
                 of the pair are needed.",
                if self.cert_path.is_empty() { "PEP_HTTPS_KEY" }
                else { "PEP_HTTPS_CERT" }),
                false,
            );
            return false;
        }
        let read = std::fs::read(&self.cert_path)
            .map_err(|e| (self.cert_path.clone(), e))
            .and_then(|cert| {
                std::fs::read(&self.key_path)
                    .map(|key| (cert, key))
                    .map_err(|e| (self.key_path.clone(), e))
            });
        let (cert, key) = match read {
            Ok(pair) => pair,
            Err((path, error)) => {
                let missing = error.kind() == std::io::ErrorKind::NotFound;
                let sentence = if missing {
                    format!(
                        "no HTTPS listener yet: {} does not exist. The \
                         certificate comes from the realm this PEP registered \
                         to (POST /admin-api/xacml/issue-pep-certificate); \
                         write the pair there and the listener starts within \
                         {}ms.",
                        path, self.reload_interval_ms
                    )
                } else {
                    format!(
                        "the HTTPS certificate or key could not be read \
                             ({}).",
                        error
                    )
                };
                self.problem("STS-XPEP-0030", sentence, missing);
                return false;
            }
        };
        let mut both = cert.clone();
        both.extend_from_slice(&key);
        let digest = hash(MessageDigest::sha256(), &both)
            .map(|d| d.iter().map(|b| format!("{:02x}", b)).collect::<String>())
            .unwrap_or_default();
        if digest == self.status().digest {
            return false;
        }
        let tuning = self.tuning_now();
        let (acceptor, leaf) = match acceptor_for(
            &cert,
            &key,
            &self.client_ca,
            self.ask_any,
            &tuning,
            false,
        ) {
            Ok(built) => built,
            Err(AcceptorFault::Pair(error)) => {
                let listening = self.status().listening;
                self.problem(
                    "STS-XPEP-0030",
                    format!(
                        "the HTTPS certificate and key were not used: {}. {}",
                        error,
                        if listening {
                            "The listener keeps serving the pair it has."
                        } else {
                            "The listener starts when a usable pair is written."
                        }
                    ),
                    false,
                );
                return false;
            }
            // strict is false on a reload: a knob is logged and skipped.
            Err(AcceptorFault::Tuning) => return false,
        };
        self.save_pair(&cert, &key);
        let (served, from, to) = describe_served(&leaf);
        let now = Utc::now();
        if from.is_some_and(|f| now < f) || to.is_some_and(|t| now > t) {
            tracing::warn!(
                "{}xacml-pep: the HTTPS certificate {} is valid from {} to \
                 {}, which does not include now. It is served anyway — a \
                 listener with an expired certificate is easier to diagnose \
                 than one that is not there — and every client that checks \
                 will refuse the handshake.",
                tag("STS-XPEP-0032"),
                served["serialHex"],
                served["validFrom"],
                served["validTo"]
            );
        }
        let first = self.current().is_none();
        match self.acceptor.write() {
            Ok(mut slot) => *slot = Some(Arc::new(acceptor)),
            Err(poisoned) => *poisoned.into_inner() = Some(Arc::new(acceptor)),
        }
        let mut status = self.status();
        status.digest = digest;
        status.loaded_at = Some(sts_core::time::iso_now());
        status.last_problem = None;
        status.last_logged_problem.clear();
        if !first {
            tracing::info!(
                "xacml-pep: the HTTPS listener on {} now serves certificate \
                 {} ({}), issued by {}. Connections already open keep the \
                 certificate they negotiated.",
                self.port,
                served["serialHex"],
                served["subjectAltName"],
                served["issuer"]
            );
        }
        status.certificate = Some(served);
        status.dns_names = dns_names_of(&leaf);
        first
    }

    /// The DNS names of the certificate being served, or `None` while it
    /// serves none.
    pub fn dns_names(&self) -> Option<Vec<String>> {
        let status = self.status();
        status.certificate.as_ref().map(|_| status.dns_names.clone())
    }

    pub fn mark_listening(&self, port: u16) {
        let mut status = self.status();
        status.listening = true;
        status.bind_failed = None;
        status.port = Some(port);
        if let Some(served) = &status.certificate {
            tracing::info!(
                "xacml-pep: HTTPS listening on {} with certificate {} ({}), \
                 issued by {}.",
                port,
                served["serialHex"],
                served["subjectAltName"],
                served["issuer"]
            );
        }
    }

    /// What the heartbeat reports about this listener (#1760): its state and
    /// reason from the closed sets, and the certificate it serves.
    pub fn state(&self) -> (&'static str, &'static str, Option<Value>) {
        let s = self.status().clone();
        let state = if s.listening {
            ("listening", "none")
        } else if let Some(reason) = s.bind_failed {
            ("failed", reason)
        } else if !s.configured && !self.in_memory {
            ("off", "not-configured")
        } else if s.certificate.is_none() {
            ("waiting", "no-certificate")
        } else {
            ("waiting", "none")
        };
        (state.0, state.1, s.certificate)
    }

    pub fn mark_bind_failed(&self, error: &str) {
        self.status().listening = false;
        self.problem(
            "STS-XPEP-0031",
            format!(
            "the HTTPS listener could not listen on {}: {}. Plain HTTP and \
             enforcement are unaffected.", self.port, error),
            false,
        );
    }

    /// A bind that failed, with its reason from the closed set.
    pub fn mark_bind_failed_for(&self, error: &std::io::Error) {
        self.status().bind_failed = Some(bind_reason(error));
        self.mark_bind_failed(&error.to_string());
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// A listener whose pair is HANDED to it rather than read from disk
    /// (#1760): a listener the service defined, whose key this process
    /// generated and whose certificate the service issued over it. Asks
    /// for a client certificate as the environment's listener of the same
    /// purpose does.
    pub fn in_memory(
        port: u16,
        client_ca: Option<&[u8]>,
        ask_any: bool,
    ) -> HttpsListener {
        let mut listener = HttpsListener::new("", "", port, 0, client_ca);
        listener.ask_any = ask_any;
        listener.in_memory = true;
        if ask_any {
            listener.store_tuning(Tuning::defaults("proxy", true));
        }
        listener
    }

    /// The TLS knobs to use the next time the acceptor is built, and — when
    /// a pair is already served — rebuilt now. A knob that will not apply
    /// leaves the acceptor that is serving.
    pub fn set_tuning(&self, tuning: Tuning) {
        self.store_tuning(tuning.clone());
        let pair = match self.pair.lock() {
            Ok(slot) => slot.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        let Some((cert, key)) = pair else {
            return;
        };
        let strict = self.current().is_some();
        match acceptor_for(
            &cert,
            &key,
            &self.client_ca,
            self.ask_any,
            &tuning,
            strict,
        ) {
            Ok((acceptor, _)) => self.swap_acceptor(acceptor),
            Err(AcceptorFault::Tuning) => {}
            Err(AcceptorFault::Pair(error)) => {
                tracing::error!(
                    "{}xacml-pep: the listener's TLS settings were not \
                     applied ({}). The certificate already served is kept.",
                    tag("STS-XPEP-0119"),
                    error
                );
            }
        }
    }

    fn store_tuning(&self, tuning: Tuning) {
        match self.tuning.lock() {
            Ok(mut slot) => *slot = tuning,
            Err(poisoned) => *poisoned.into_inner() = tuning,
        }
    }

    fn tuning_now(&self) -> Tuning {
        match self.tuning.lock() {
            Ok(slot) => slot.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn save_pair(&self, cert: &[u8], key: &[u8]) {
        let saved = Some((cert.to_vec(), key.to_vec()));
        match self.pair.lock() {
            Ok(mut slot) => *slot = saved,
            Err(poisoned) => *poisoned.into_inner() = saved,
        }
    }

    fn swap_acceptor(&self, acceptor: SslAcceptor) {
        let built = Some(Arc::new(acceptor));
        match self.acceptor.write() {
            Ok(mut slot) => *slot = built,
            Err(poisoned) => *poisoned.into_inner() = built,
        }
    }

    /// Installs a pair, checked whole as a pair read from disk is: a pair
    /// that does not build an acceptor is refused and the one served is
    /// kept. Answers the served certificate's description.
    pub fn install(&self, cert: &[u8], key: &[u8]) -> Result<Value, String> {
        let tuning = self.tuning_now();
        let (acceptor, leaf) = acceptor_for(
            cert,
            key,
            &self.client_ca,
            self.ask_any,
            &tuning,
            false,
        )
        .map_err(|fault| match fault {
            AcceptorFault::Pair(error) => error,
            AcceptorFault::Tuning => {
                "the listener's TLS settings were not applied".to_string()
            }
        })?;
        self.save_pair(cert, key);
        let (served, _, _) = describe_served(&leaf);
        match self.acceptor.write() {
            Ok(mut slot) => *slot = Some(Arc::new(acceptor)),
            Err(poisoned) => *poisoned.into_inner() = Some(Arc::new(acceptor)),
        }
        let mut status = self.status();
        status.configured = true;
        status.loaded_at = Some(sts_core::time::iso_now());
        status.last_problem = None;
        status.certificate = Some(served.clone());
        status.dns_names = dns_names_of(&leaf);
        Ok(served)
    }

    /// The handshake, on the worker that owns `stream`. `None` is a failure
    /// already counted on `runtime`; the connection is not served.
    pub async fn accept_tls(
        stream: tokio::net::TcpStream,
        acceptor: &SslAcceptor,
        runtime: &ListenerRuntime,
    ) -> Option<tokio_openssl::SslStream<tokio::net::TcpStream>> {
        let ssl = match openssl::ssl::Ssl::new(acceptor.context()) {
            Ok(ssl) => ssl,
            Err(error) => {
                tracing::debug!(
                    "TLS handshake was not started: {}",
                    error
                );
                runtime.note_handshake_failure();
                return None;
            }
        };
        let mut tls = match tokio_openssl::SslStream::new(ssl, stream) {
            Ok(tls) => tls,
            Err(error) => {
                tracing::debug!(
                    "TLS handshake was not started: {}",
                    error
                );
                runtime.note_handshake_failure();
                return None;
            }
        };
        if let Err(error) = Pin::new(&mut tls).accept().await {
            tracing::debug!("TLS handshake failed: {}", error);
            runtime.note_handshake_failure();
            return None;
        }
        runtime.note_handshake();
        Some(tls)
    }

    /// `https` on `GET /`.
    pub fn overview(&self) -> Value {
        let s = self.status().clone();
        let what = if s.configured {
            format!(
                "This PEP serves the same four endpoints over HTTPS with a \
                 certificate issued by the Remote PEP listeners Issuing CA of \
                 the realm it registered to. The pair is re-read from {} and \
                 {} every {}ms, so a certificate issued after this container \
                 started — which is the ordinary order, since the realm \
                 certifies a PEP only once it has registered — is picked up \
                 without a restart.",
                self.cert_path, self.key_path, self.reload_interval_ms
            )
        } else {
            "No HTTPS listener: PEP_HTTPS_CERT and PEP_HTTPS_KEY are not both \
             set. Issue a pair with POST /admin-api/xacml/\
             issue-pep-certificate on the PDP, write it to two files this \
             container can read, and name them."
                .to_string()
        };
        json!({
            "configured": s.configured,
            "listening": s.listening,
            "port": if s.listening { s.port.map(Value::from) } else { None },
            "certificate": s.certificate,
            "loadedAt": s.loaded_at,
            "lastCheckedAt": s.last_checked_at,
            "asksForClientCertificates": !self.client_ca.is_empty(),
            "problem": s.last_problem,
            "what": what
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Integer;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::x509::{X509Builder, X509NameBuilder};

    fn pair() -> (Vec<u8>, Vec<u8>) {
        pair_naming(&[])
    }

    /// A self-signed pair whose subjectAltName names `dns`, in order.
    fn pair_naming(dns: &[&str]) -> (Vec<u8>, Vec<u8>) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "xacml-pep").unwrap();
        let name = name.build();
        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        let serial =
            Asn1Integer::from_bn(&BigNum::from_u32(7).unwrap()).unwrap();
        builder.set_serial_number(&serial).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        if !dns.is_empty() {
            let mut san =
                openssl::x509::extension::SubjectAlternativeName::new();
            for name in dns {
                san.dns(name);
            }
            let extension =
                san.build(&builder.x509v3_context(None, None)).unwrap();
            builder.append_extension(extension).unwrap();
        }
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        (
            builder.build().to_pem().unwrap(),
            key.private_key_to_pem_pkcs8().unwrap(),
        )
    }

    fn temp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "pep-listener-{}-{}",
            std::process::id(),
            name
        ))
    }

    /// `tests/pep_listener_certificate.js`'s rules: nothing until a pair
    /// exists; a usable pair starts the listener; the same bytes again are
    /// not a change; a half-written pair never replaces a good one.
    #[test]
    fn reload_rules() {
        let (cert_path, key_path) = (temp("cert"), temp("key"));
        let listener = HttpsListener::new(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
            0,
            100,
            None,
        );
        assert!(!listener.reload(), "nothing on disk yet");
        assert!(listener.current().is_none());
        let (cert, key) = pair();
        std::fs::write(&cert_path, &cert).unwrap();
        std::fs::write(&key_path, &key).unwrap();
        assert!(listener.reload(), "the first usable pair starts it");
        assert!(!listener.reload(), "the same bytes are not a change");
        let served = listener.overview()["certificate"]["serialHex"].clone();
        assert_eq!(served, "07");
        let (other_cert, _) = pair();
        std::fs::write(&cert_path, &other_cert).unwrap();
        assert!(!listener.reload());
        assert!(listener.current().is_some(), "the good pair is kept");
        assert!(listener.overview()["problem"]
            .as_str()
            .unwrap()
            .contains("not the key"));
        std::fs::remove_file(&cert_path).unwrap();
        std::fs::remove_file(&key_path).unwrap();
    }

    /// THE NOTIFY URL FOLLOWS THE SERVED CERTIFICATE (2026-11-14): nothing
    /// is derived before a pair is served; the first served certificate's
    /// first DNS name is the host; a reload to a certificate naming
    /// another host derives again, and the same certificate again changes
    /// nothing. An installed pair (a listener the service defined) is read
    /// the same way.
    #[test]
    fn a_certificate_change_derives_the_notify_url_again() {
        let (cert_path, key_path) = (temp("dcert"), temp("dkey"));
        let listener = HttpsListener::new(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
            0,
            100,
            None,
        );
        // A hostname no certificate below names until the last one.
        const HOST: Option<&str> = Some("pep-e.example");
        let mut options = crate::options::Options::from_env("0.0.0");
        options.https_port = 9443;
        options.notify_url = String::new();
        options.managed = Arc::new(crate::settings::Held::default());
        assert!(!listener.reload());
        assert_eq!(listener.dns_names(), None, "no certificate, no names");
        assert!(!options.refresh_derived_notify_as(
            listener.dns_names().as_deref(), None, HOST));
        assert_eq!(options.now().notify_url, "", "no listener, none");
        let (cert, key) = pair_naming(&["*.pep.example", "pep-a.example",
                                        "pep-b.example"]);
        std::fs::write(&cert_path, &cert).unwrap();
        std::fs::write(&key_path, &key).unwrap();
        assert!(listener.reload());
        assert!(options.refresh_derived_notify_as(
            listener.dns_names().as_deref(), None, HOST));
        assert_eq!(options.now().notify_url,
                   "https://pep-a.example:9443/notify",
                   "the first DNS name a host can be; the wildcard is not");
        assert!(!options.refresh_derived_notify_as(
            listener.dns_names().as_deref(), None, HOST),
            "the same certificate");
        let (cert, key) = pair_naming(&["pep-c.example"]);
        std::fs::write(&cert_path, &cert).unwrap();
        std::fs::write(&key_path, &key).unwrap();
        assert!(!listener.reload(), "a reload, not a first start");
        assert!(options.refresh_derived_notify_as(
            listener.dns_names().as_deref(), None, HOST),
            "a new name derives again");
        assert_eq!(options.now().notify_url,
                   "https://pep-c.example:9443/notify");
        // OPTION 1 ON A RELOAD: a certificate naming the hostname, not
        // first, derives the hostname's name.
        let (cert, key) = pair_naming(&["pep-c.example", "PEP-E.example"]);
        std::fs::write(&cert_path, &cert).unwrap();
        std::fs::write(&key_path, &key).unwrap();
        assert!(!listener.reload());
        assert!(options.refresh_derived_notify_as(
            listener.dns_names().as_deref(), None, HOST),
            "the hostname's name, not the first");
        assert_eq!(options.now().notify_url,
                   "https://pep-e.example:9443/notify");
        let installed = HttpsListener::in_memory(0, None, false);
        assert_eq!(installed.dns_names(), None);
        let (cert, key) = pair_naming(&["pep-d.example"]);
        installed.install(&cert, &key).unwrap();
        assert_eq!(installed.dns_names(),
                   Some(vec!["pep-d.example".to_string()]));
        std::fs::remove_file(&cert_path).unwrap();
        std::fs::remove_file(&key_path).unwrap();
    }

    /// One mutual-TLS handshake against an acceptor built as `reload()`
    /// builds one: what the server reads of the caller's certificate.
    fn handshake(
        client_ca: &[X509],
        presented: Option<&(Vec<u8>, Vec<u8>)>,
    ) -> Option<Peer> {
        handshake_with(client_ca, presented, false)
    }

    fn handshake_with(
        client_ca: &[X509],
        presented: Option<&(Vec<u8>, Vec<u8>)>,
        ask_any: bool,
    ) -> Option<Peer> {
        use openssl::ssl::{SslConnector, SslVerifyMode};
        let (cert, key) = pair();
        let purpose = if ask_any { "proxy" } else { "api" };
        let tuning = Tuning::defaults(purpose, true);
        let (acceptor, _) = acceptor_for(
            &cert,
            &key,
            client_ca,
            ask_any,
            &tuning,
            false,
        )
        .unwrap_or_else(|fault| {
            panic!(
                "acceptor: {}",
                match fault {
                    AcceptorFault::Pair(error) => error,
                    AcceptorFault::Tuning => "tuning".to_string(),
                }
            )
        });
        let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let thread = std::thread::spawn(move || {
            let (stream, _) = server.accept().unwrap();
            let tls = acceptor.accept(stream).unwrap();
            peer_of(tls.ssl())
        });
        let mut connector =
            SslConnector::builder(SslMethod::tls_client()).unwrap();
        connector.set_verify(SslVerifyMode::NONE);
        if let Some((cert, key)) = presented {
            connector
                .set_certificate(&X509::from_pem(cert).unwrap())
                .unwrap();
            connector
                .set_private_key(&PKey::private_key_from_pem(key).unwrap())
                .unwrap();
        }
        let stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let tls = connector
            .build()
            .configure()
            .unwrap()
            .verify_hostname(false)
            .connect("localhost", stream)
            .unwrap();
        let peer = thread.join().unwrap();
        drop(tls);
        peer
    }

    /// The AuthZEN door's half of the listener (#1179): a certificate that
    /// chains to the client CA is read and verified; one that does not
    /// still completes the handshake and is read as not verified; none is
    /// none; and with no client CA nothing is asked for.
    #[test]
    fn reads_and_verifies_a_client_certificate() {
        let caller = pair();
        let stranger = pair();
        let authority = X509::from_pem(&caller.0).unwrap();
        let expected = authority
            .digest(MessageDigest::sha256())
            .unwrap()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        let ca = vec![authority];
        let peer = handshake(&ca, Some(&caller)).unwrap();
        assert!(peer.verified, "{}", peer.why);
        assert_eq!(peer.sha256, expected);
        let other = handshake(&ca, Some(&stranger)).unwrap();
        assert!(!other.verified);
        assert!(!other.why.is_empty());
        assert!(handshake(&ca, None).is_none());
        assert!(handshake(&[], Some(&caller)).is_none());
    }

    /// The reverse proxy's listener (#1760): it asks EVERY client for a
    /// certificate with no authority to check it against, reads the one
    /// presented (for `cnf.x5t#S256`), and lets a client with none in.
    #[test]
    fn the_proxy_listener_asks_everybody_and_requires_nobody() {
        let caller = pair();
        let peer = handshake_with(&[], Some(&caller), true).unwrap();
        let expected = X509::from_pem(&caller.0)
            .unwrap()
            .digest(MessageDigest::sha256())
            .unwrap()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        assert_eq!(peer.sha256, expected);
        assert!(handshake_with(&[], None, true).is_none());
        let proxy = HttpsListener::for_proxy("c", "k", 9543, 100);
        assert!(proxy.ask_any && !proxy.asks_for_client_certificates());
    }
}
