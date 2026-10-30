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
//! **IT ASKS FOR A CLIENT CERTIFICATE WHEN `PEP_AUTHZEN_CLIENT_CA` IS SET**
//! (#1179), the AuthZEN edge PDP's one door. It ASKS and does not REQUIRE,
//! and a certificate that does not verify still completes the handshake,
//! as the service's main port does (`requestCert`, `rejectUnauthorized:
//! false`): the other endpoints on this listener take no certificate, and
//! the AuthZEN handler is where a refusal can say why — a handshake alert
//! says nothing a PEP's operator can act on. [`peer_of`] reads what was
//! presented and whether it verified.

use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use openssl::asn1::{Asn1Time, Asn1TimeRef};
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::PKey;
use openssl::ssl::{SslAcceptor, SslMethod, SslRef, SslVerifyMode};
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509Name, X509NameRef, X509VerifyResult, X509};
use serde_json::{json, Value};
use sts_core::log::tag;

/// What `GET /` says about the listener.
#[derive(Debug, Clone, Default)]
struct Status {
    configured: bool,
    listening: bool,
    port: Option<u16>,
    digest: String,
    loaded_at: Option<String>,
    certificate: Option<Value>,
    last_problem: Option<String>,
    last_checked_at: Option<String>,
    last_logged_problem: String,
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
    /// means no certificate is asked for.
    client_ca: Vec<X509>,
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

/// Builds an acceptor from a pair, checked whole, asking for a client
/// certificate chaining to `client_ca` when there is one.
fn acceptor_for(
    cert: &[u8],
    key: &[u8],
    client_ca: &[X509],
) -> Result<(SslAcceptor, X509), String> {
    let chain = X509::stack_from_pem(cert).map_err(|e| e.to_string())?;
    let mut chain = chain.into_iter();
    let leaf = chain.next().ok_or_else(|| {
        "the certificate file holds no certificate".to_string()
    })?;
    let private = PKey::private_key_from_pem(key).map_err(|e| e.to_string())?;
    let public = leaf.public_key().map_err(|e| e.to_string())?;
    if !public.public_eq(&private) {
        return Err("the private key is not the key this certificate \
                    certifies — most likely one file of the pair has been \
                    written and the other not yet"
            .into());
    }
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
        .map_err(|e| e.to_string())?;
    builder.set_certificate(&leaf).map_err(|e| e.to_string())?;
    for extra in chain {
        builder
            .add_extra_chain_cert(extra)
            .map_err(|e| e.to_string())?;
    }
    builder
        .set_private_key(&private)
        .map_err(|e| e.to_string())?;
    builder.check_private_key().map_err(|e| e.to_string())?;
    if !client_ca.is_empty() {
        let mut store = X509StoreBuilder::new().map_err(|e| e.to_string())?;
        let mut names = Stack::<X509Name>::new().map_err(|e| e.to_string())?;
        for authority in client_ca {
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
        // ASKED, NOT REQUIRED, and a failure is the handler's to refuse:
        // the verify result is still recorded on the connection.
        builder.set_verify_callback(SslVerifyMode::PEER, |_, _| true);
        // A server that asks for a client certificate must name a session
        // context, or OpenSSL refuses every resumed session.
        builder
            .set_session_id_context(b"xacml-pep-authzen")
            .map_err(|e| e.to_string())?;
    }
    Ok((builder.build(), leaf))
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
        }
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
        let (acceptor, leaf) = match acceptor_for(&cert, &key, &self.client_ca)
        {
            Ok(built) => built,
            Err(error) => {
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
        };
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
        first
    }

    pub fn mark_listening(&self, port: u16) {
        let mut status = self.status();
        status.listening = true;
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

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn interval(&self) -> Duration {
        Duration::from_millis(self.reload_interval_ms.max(100))
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

    /// One mutual-TLS handshake against an acceptor built as `reload()`
    /// builds one: what the server reads of the caller's certificate.
    fn handshake(
        client_ca: &[X509],
        presented: Option<&(Vec<u8>, Vec<u8>)>,
    ) -> Option<Peer> {
        use openssl::ssl::{SslConnector, SslVerifyMode};
        let (cert, key) = pair();
        let (acceptor, _) = acceptor_for(&cert, &key, client_ca).unwrap();
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
}
