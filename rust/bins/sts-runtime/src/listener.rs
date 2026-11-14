// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE TLS LISTENERS (#444 phase 3, the `tls` slice): the main port when
//! `global.https` is on, and every custom listener (#472) — what
//! `server.js`'s `bind()` and `customListener()` build with node's
//! `http2.createSecureServer()`, and what `tls/tls_server.js`'s
//! `secureContextOptions()`, `applyAnchors()` and `observeConnectionsOn()`
//! and `tls/alert_close.ts` do to it.
//!
//! **The context is node's, option for option.** node's `SecureContext`
//! starts from a bare `SSL_CTX_new(TLS_server_method())` and adds
//! `SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3`; `honorCipherOrder` is
//! `SSL_OP_CIPHER_SERVER_PREFERENCE`; `secureOptions` is
//! `SSL_OP_NO_RENEGOTIATION` (#212); `minVersion`, the TLS 1.3 suites, the
//! TLS 1.2 list, `ecdhCurve` (groups) and `sigalgs` are the policy's
//! (`sts_tls::policy::ProtocolOptions`); `sessionTimeout` is
//! `SSL_CTX_set_timeout`; every `ca` entry goes into the verify store AND
//! the CertificateRequest's certificate_authorities (`SSL_CTX_add_client_CA`,
//! which is what node's `ca` does); `requestCert` is `SSL_VERIFY_PEER` with
//! a callback that accepts everything, and the verdict is read after the
//! handshake (`socket.authorized`, `authorizationError`) — which is how
//! node does it, so a certificate that chains to nothing still completes
//! the handshake and still binds an RFC 8705 token. `rejectUnauthorized`
//! adds `SSL_VERIFY_FAIL_IF_NO_PEER_CERT`, and an unverified certificate is
//! dropped after the handshake, as node's `tls.Server` destroys the socket.
//! `SslAcceptor::mozilla_*` is NOT used: its options and lists are not
//! node's.
//!
//! **ALPN is node's http2 secure server with `allowHTTP1`**: the server's
//! list `h2, http/1.1` (`http/1.1` alone where `http.http2` is off), chosen
//! in the SERVER's order (`SSL_select_next_proto` with the server's list
//! first), and a client offering only protocols the server lacks gets the
//! fatal `no_application_protocol` alert (RFC 7301 section 3.2), as node
//! sends since v17. A client offering no ALPN is served HTTP/1.1. The
//! protocol served is the one ALPN chose — never sniffed from the bytes.
//!
//! **A context is applied to the NEXT handshake** (`setSecureContext()`):
//! [`TlsListener::apply`] swaps it under a lock, so a truststore change, a
//! re-issued certificate or a changed policy re-keys no live connection and
//! rebinds nothing.
//!
//! **A connection that fails at the TLS layer keeps its alert**
//! (`tls/alert_close.ts`, 2026-11-13): the FIN is sent at once and the
//! descriptor is held, reading and discarding, for two seconds — closing
//! with unread data sends a TCP reset that can overtake the alert. At most
//! 256 are held per listener (`STS-TLS-0061`).
//!
//! **Not ported here, each with its home:** the PROXY protocol v2
//! (`common/proxy_protocol.ts`, off by default), the JA4 reader
//! (`tls/client_hello.ts`, risk scoring's, phase 9), the session-ID cache's
//! server-name rule and the TLS 1.2 ticket-name record (#429, #507: TLS 1.2
//! is off by default), the active-active shared ticket key
//! (`tls/session_tickets.ts`, which needs `SSL_CTX_set_tlsext_ticket_keys`
//! wrapped in `sts-crypto` and the cluster's store), the path-rule hold and
//! revocation of a presented chain (`holdToPathRules()`, `checkedSocket()`:
//! the validation door's, phase 6) and the sighting
//! (`recordClientCertificate()`: the directory's, phase 4).

// Some of what is here is the seam a later phase calls (the settings'
// change notification, the truststore doors, /admin-api/listeners); the
// binary does not call it yet.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use openssl::ssl::{
    select_next_proto, AlpnError, Ssl, SslContext, SslContextBuilder,
    SslMethod, SslOptions, SslRef, SslSessionCacheMode, SslVerifyMode,
    SslVersion,
};
use sts_core::errors::codes;
use sts_core::log::tag;
use sts_pki::listener::{
    chain_has_refused_curve, open_anchors, ListenerCertificate,
};
use sts_tls::policy::{
    ClientAuth, ListenerPolicy, ProtocolOptions, TlsVersion,
};
use sts_tls::{authorization_error_name, ConnectionFacts, TlsFacts};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tower::ServiceExt;

/// How long a connection that failed at the TLS layer is held.
const ALERT_HOLD: Duration = Duration::from_secs(2);
/// At most this many held per listener.
const ALERT_HOLD_MAX: usize = 256;

/// A built context and what the accept loop needs beside it.
pub struct Applied {
    pub context: SslContext,
    /// `rejectUnauthorized`: an unverified certificate is dropped after
    /// the handshake.
    pub require_verified: bool,
    /// What the policy was, so a re-application can tell what moved.
    pub policy: ListenerPolicy,
}

fn ssl_version(v: TlsVersion) -> SslVersion {
    match v {
        TlsVersion::Tls10 => SslVersion::TLS1,
        TlsVersion::Tls11 => SslVersion::TLS1_1,
        TlsVersion::Tls12 => SslVersion::TLS1_2,
        TlsVersion::Tls13 => SslVersion::TLS1_3,
    }
}

/// The server's ALPN list, wire format.
fn alpn_wire(http2: bool) -> Vec<u8> {
    let mut out = Vec::new();
    if http2 {
        out.extend_from_slice(b"\x02h2");
    }
    out.extend_from_slice(b"\x08http/1.1");
    out
}

/// A session id context, as node's `tls.Server` sets one (a SHA-1 of the
/// process's arguments, 32 hex characters): without one, OpenSSL refuses to
/// resume a session on a context that verifies peers.
fn session_id_context(label: &str) -> Vec<u8> {
    let digest = sts_crypto::jws_alg::Hash::Sha256
        .digest(format!("sts-runtime {}", label).as_bytes());
    digest
        .iter()
        .take(16)
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
        .into_bytes()
}

/// `secureContextOptions(policy)` and node's `createSecureContext()`: a
/// context from a policy, the certificates the listener presents (OpenSSL
/// picks per client among several), and the `ca` the truststore answers.
#[tracing::instrument(level = "debug", skip_all, fields(kind = %policy.kind))]
pub fn build_context(
    label: &str,
    policy: &ListenerPolicy,
    certificates: &[ListenerCertificate],
    ca: &[String],
    http2: bool,
) -> Result<Applied, String> {
    let options = ProtocolOptions::of(policy);
    let e = |what: &str, err: openssl::error::ErrorStack| {
        format!("{}: {}", what, err)
    };
    let mut b = SslContextBuilder::new(SslMethod::tls_server())
        .map_err(|err| e("SSL_CTX_new", err))?;
    // SSL_OP_LEGACY_EC_POINT_FORMATS (OpenSSL 3.6): node's OpenSSL 3.5
    // lists all three EC point formats in a TLS 1.2 ServerHello, and 3.6
    // lists `uncompressed` alone unless asked — the one default the two
    // library versions disagree on that a client can see
    // (tlsfuzzer's test-point-extension.py).
    let legacy_point_formats = SslOptions::from_bits_retain(1 << 36);
    let mut ops =
        SslOptions::NO_SSLV2 | SslOptions::NO_SSLV3 | legacy_point_formats;
    if options.server_preference {
        ops |= SslOptions::CIPHER_SERVER_PREFERENCE;
    }
    if options.no_renegotiation {
        ops |= SslOptions::NO_RENEGOTIATION;
    }
    b.set_options(ops);
    b.set_min_proto_version(Some(ssl_version(options.min_version)))
        .map_err(|err| e("minVersion", err))?;
    b.set_max_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|err| e("maxVersion", err))?;
    b.set_ciphersuites(&options.tls13_suites)
        .map_err(|err| e("tls.tls13CipherSuites", err))?;
    // node leaves OpenSSL's TLS 1.2 list in place when its own is empty
    // (SSL_R_NO_CIPHER_MATCH on "" is not an error there), which with TLS
    // 1.2 off is never offered anyway.
    if !options.tls12_ciphers.is_empty() {
        b.set_cipher_list(&options.tls12_ciphers)
            .map_err(|err| e("tls.ciphers", err))?;
    }
    if let Some(groups) = options.groups_for_openssl() {
        b.set_groups_list(&groups)
            .map_err(|err| e("tls.groups", err))?;
    }
    if let Some(sigalgs) = &options.sigalgs {
        b.set_sigalgs_list(sigalgs)
            .map_err(|err| e("tls.signatureAlgorithms", err))?;
    }
    sts_crypto::pq::set_session_timeout(&mut b, options.session_timeout_s);
    b.set_session_id_context(&session_id_context(label))
        .map_err(|err| e("sessionIdContext", err))?;
    // node keeps no internal cache: its own (`attachSessionCache()`) holds
    // TLS 1.2 session IDs, bounded by `sessionCacheSize`. OpenSSL's internal
    // server cache with the same bound stands in for it.
    if policy.session_cache_size > 0 {
        b.set_session_cache_mode(SslSessionCacheMode::SERVER);
        b.set_session_cache_size(
            i32::try_from(policy.session_cache_size).unwrap_or(i32::MAX),
        );
    } else {
        b.set_session_cache_mode(SslSessionCacheMode::OFF);
    }
    let mut chain_added = false;
    for certificate in certificates {
        let opened = certificate.open().map_err(|err| err.to_string())?;
        b.set_certificate(&opened.leaf)
            .map_err(|err| e("cert", err))?;
        b.set_private_key(&opened.key)
            .map_err(|err| e("key", err))?;
        b.check_private_key().map_err(|err| e("key", err))?;
        // The chain is shared by every certificate of one listener (the
        // ML-DSA leaf is issued by the same TLS Issuing CA as the RSA one),
        // so it is the context's extra chain.
        if !chain_added {
            for c in opened.chain {
                b.add_extra_chain_cert(c).map_err(|err| e("chain", err))?;
            }
            chain_added = true;
        }
    }
    let anchors = open_anchors(ca).map_err(|err| err.to_string())?;
    for anchor in &anchors {
        b.cert_store_mut()
            .add_cert(anchor.clone())
            .map_err(|err| e("ca", err))?;
        b.add_client_ca(anchor).map_err(|err| e("ca", err))?;
    }
    let client_auth = policy.client_auth.unwrap_or(ClientAuth::None);
    let (request, reject) = client_auth.request_and_reject();
    if request {
        let mut mode = SslVerifyMode::PEER;
        if reject {
            mode |= SslVerifyMode::FAIL_IF_NO_PEER_CERT;
        }
        // node's VerifyCallback: accept, and read the verdict afterwards.
        b.set_verify_callback(mode, |_preverified, _ctx| true);
    } else {
        b.set_verify(SslVerifyMode::NONE);
    }
    let server = alpn_wire(http2);
    b.set_alpn_select_callback(move |_ssl, client| {
        // The server's list FIRST: its order wins, as node's does.
        select_next_proto(&server, client)
            .map(|chosen| {
                if chosen == b"h2" {
                    &b"h2"[..]
                } else {
                    &b"http/1.1"[..]
                }
            })
            .ok_or(AlpnError::ALERT_FATAL)
    });
    Ok(Applied {
        context: b.build(),
        require_verified: reject,
        policy: policy.clone(),
    })
}

/// What a listener is doing (`tls/listeners.js`' `status()`).
#[derive(Debug, Clone)]
pub struct ListenerStatus {
    pub id: String,
    pub port: u16,
    /// `listening`, `failed`.
    pub state: String,
    pub why: String,
    pub code: Option<sts_core::errors::ErrorCode>,
}

/// One TLS listener.
pub struct TlsListener {
    pub id: String,
    pub label: String,
    pub realm_listener: Option<String>,
    applied: RwLock<Arc<Applied>>,
    held: AtomicUsize,
    told_full: AtomicBool,
    http2: bool,
    pub status: Mutex<ListenerStatus>,
}

/// The TLS facts of a finished handshake.
fn facts_of(ssl: &SslRef) -> TlsFacts {
    // On a SERVER, OpenSSL's peer chain leaves the leaf out; node's
    // `getPeerCertificate(true)` walks leaf first. A resumed session hands
    // the server the leaf alone, and the chain is then empty.
    let mut peer_chain: Vec<Vec<u8>> = ssl
        .peer_certificate()
        .and_then(|c| c.to_der().ok())
        .map(|d| vec![d])
        .unwrap_or_default();
    if let Some(chain) = ssl.peer_cert_chain() {
        for c in chain.iter() {
            if let Ok(der) = c.to_der() {
                if peer_chain.first() != Some(&der) {
                    peer_chain.push(der);
                }
            }
        }
    }
    let verify = ssl.verify_result();
    let presented = !peer_chain.is_empty();
    let authorized = presented && verify.as_raw() == 0;
    TlsFacts {
        version: ssl.version_str().to_string(),
        cipher: ssl
            .current_cipher()
            .and_then(|c| c.standard_name())
            .unwrap_or("")
            .to_string(),
        alpn: ssl
            .selected_alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).to_string()),
        server_name: ssl
            .servername(openssl::ssl::NameType::HOST_NAME)
            .map(str::to_string),
        resumed: ssl.session_reused(),
        peer_chain,
        authorized,
        authorization_error: if presented && !authorized {
            Some(authorization_error_name(verify.as_raw()))
        } else {
            None
        },
    }
}

/// `handshakeFailureOf()`: the certificate alerts the PEER sent (42-46,
/// 48) are a client refusing this service's certificate.
fn peer_refused_certificate(error: &str) -> Option<(u32, &'static str)> {
    const ALERTS: &[(u32, &str, &str)] = &[
        (42, "bad_certificate", "alert bad certificate"),
        (
            43,
            "unsupported_certificate",
            "alert unsupported certificate",
        ),
        (44, "certificate_revoked", "alert certificate revoked"),
        (45, "certificate_expired", "alert certificate expired"),
        (46, "certificate_unknown", "alert certificate unknown"),
        (48, "unknown_ca", "alert unknown ca"),
    ];
    ALERTS
        .iter()
        .find(|(n, _, text)| {
            error.contains(text)
                || error.contains(&format!("SSL alert number {}", n))
        })
        .map(|(n, name, _)| (*n, *name))
}

impl TlsListener {
    /// A listener with its first context.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(
        id: &str,
        label: &str,
        port: u16,
        applied: Applied,
        http2: bool,
    ) -> Arc<TlsListener> {
        Arc::new(TlsListener {
            id: id.to_string(),
            label: label.to_string(),
            realm_listener: None,
            applied: RwLock::new(Arc::new(applied)),
            held: AtomicUsize::new(0),
            told_full: AtomicBool::new(false),
            http2,
            status: Mutex::new(ListenerStatus {
                id: id.to_string(),
                port,
                state: "unbound".to_string(),
                why: String::new(),
                code: None,
            }),
        })
    }

    /// Whether the listener offers h2.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn offers_http2(&self) -> bool {
        self.http2
    }

    /// `setSecureContext()`: the next handshake uses `applied`.
    #[tracing::instrument(level = "debug", skip_all, fields(label = %self.label))]
    pub fn apply(&self, applied: Applied) {
        let mut held =
            self.applied.write().unwrap_or_else(PoisonError::into_inner);
        *held = Arc::new(applied);
    }

    /// The policy last applied.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn policy(&self) -> ListenerPolicy {
        self.current().policy.clone()
    }

    fn current(&self) -> Arc<Applied> {
        self.applied
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn record(
        &self,
        state: &str,
        why: String,
        code: Option<sts_core::errors::ErrorCode>,
    ) {
        let mut s = self.status.lock().unwrap_or_else(PoisonError::into_inner);
        s.state = state.to_string();
        s.why = why;
        s.code = code;
    }

    /// Binds the listener's port. A failure is RECORDED (`STS-TLS-0039` for
    /// a custom listener) and returned, never thrown into the start: the
    /// caller decides whether its socket is one the service cannot run
    /// without (the main port is).
    #[tracing::instrument(level = "debug", skip(self), fields(label = %self.label))]
    pub async fn bind(&self, address: &str) -> Result<TcpListener, String> {
        match TcpListener::bind(address).await {
            Ok(tcp) => {
                self.record("listening", String::new(), None);
                Ok(tcp)
            }
            Err(e) => {
                let why = format!("could not bind {}: {}", address, e);
                self.record("failed", why.clone(), Some(codes::STS_TLS_0039));
                Err(why)
            }
        }
    }

    /// The accept loop: every connection handshakes under the context in
    /// force when it arrived, and is served HTTP/2 or HTTP/1.1 as ALPN
    /// chose. Runs until the task is dropped.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn serve(
        self: Arc<Self>,
        tcp: TcpListener,
        router: axum::Router,
    ) {
        loop {
            let (stream, peer) = match tcp.accept().await {
                Ok(accepted) => accepted,
                Err(e) => {
                    tracing::debug!("{}: an accept failed: {}", self.label, e);
                    continue;
                }
            };
            let me = self.clone();
            let router = router.clone();
            tokio::spawn(async move {
                me.connection(stream, peer, router).await;
            });
        }
    }

    // A hot path: one call per connection, so no span of its own; what
    // matters is logged where it happens.
    async fn connection(
        self: Arc<Self>,
        stream: TcpStream,
        peer: SocketAddr,
        router: axum::Router,
    ) {
        let local = stream.local_addr().ok();
        let applied = self.current();
        // THE SERVER NAME, READ OFF THE CLIENTHELLO BEFORE OPENSSL SEES IT
        // (`installSessionNameSniffer()`): the bytes are read and replayed,
        // and the session id context is scoped to the name, so a TLS 1.2
        // session ID or ticket resumes only under the name it was made under
        // (RFC 6066 section 3). A name that cannot be read FAILS CLOSED: a
        // context of its own, which nothing resumes under.
        let (conn, offered) = Conn::sniffing(stream, self.clone()).await;
        let failed = conn.failed.clone();
        let mut ssl = match Ssl::new(&applied.context) {
            Ok(ssl) => ssl,
            Err(e) => {
                tracing::error!(
                    "{}tls: no TLS session could be made on {}: {}",
                    tag(codes::STS_TLS_0011),
                    self.label,
                    e
                );
                return;
            }
        };
        let scope = match &offered {
            Offered::Name(name) => format!("{}|{}", self.label, name),
            Offered::None => format!("{}|", self.label),
            Offered::Unreadable => format!(
                "{}|?{}",
                self.label,
                sts_crypto::random::random_token(None).unwrap_or_default()
            ),
        };
        if let Err(e) = sts_crypto::pq::set_connection_session_id_context(
            &mut ssl,
            &session_id_context(&scope),
        ) {
            tracing::debug!("{}: the session id context: {}", self.label, e);
        }
        let mut tls = match tokio_openssl::SslStream::new(ssl, conn) {
            Ok(tls) => tls,
            Err(e) => {
                tracing::debug!("{}: {}", self.label, e);
                return;
            }
        };
        if let Err(e) = Pin::new(&mut tls).accept().await {
            let text = e.to_string();
            self.handshake_failed(&text, peer);
            // An alert the PEER sent is not held: nothing is owed back.
            if !text.contains("SSL alert number") {
                failed.store(true, Ordering::SeqCst);
            }
            return;
        }
        let facts = facts_of(tls.ssl());
        if chain_has_refused_curve(&facts.peer_chain) {
            tracing::warn!(
                "{}tls: a connection from {} on {} was closed: its client certificate (or one in its chain) \
                 has an EC key on a curve outside the NIST set.",
                tag(codes::STS_TLS_0035),
                peer,
                self.label
            );
            return;
        }
        if applied.require_verified && !facts.authorized {
            tracing::debug!(
                "tls: {} requires a verified client certificate and {} presented {}.",
                self.label,
                peer,
                facts
                    .authorization_error
                    .as_deref()
                    .unwrap_or("none")
            );
            return;
        }
        let h2 = facts.alpn.as_deref() == Some("h2");
        let connection = ConnectionFacts {
            listener: self.id.clone(),
            realm_listener: self.realm_listener.clone(),
            peer: Some(peer),
            local,
            tls: Some(facts),
        };
        let service = hyper::service::service_fn(
            move |mut request: hyper::Request<hyper::body::Incoming>| {
                request.extensions_mut().insert(connection.clone());
                router.clone().oneshot(request.map(axum::body::Body::new))
            },
        );
        let mut builder = Builder::new(TokioExecutor::new());
        let watched = Watched { inner: tls, failed };
        let served = if h2 {
            builder = builder.http2_only();
            builder
                .serve_connection(TokioIo::new(watched), service)
                .await
        } else {
            builder = builder.http1_only();
            builder
                .serve_connection(TokioIo::new(watched), service)
                .await
        };
        if let Err(e) = served {
            tracing::debug!("{}: a connection ended: {}", self.label, e);
        }
    }

    fn handshake_failed(&self, error: &str, peer: SocketAddr) {
        if error.contains("unexpected eof")
            || error.contains("Connection reset")
        {
            tracing::debug!(
                "tls: a connection on {} closed before its TLS hello ({}) — a health check or a client that \
                 gave up.",
                self.label,
                error
            );
            return;
        }
        if let Some((number, name)) = peer_refused_certificate(error) {
            tracing::warn!(
                "{}tls: the client at {} REFUSED this service's certificate on {} (it sent the TLS alert {}, \
                 {}). From a browser this almost always means it does not trust this service's Root CA: \
                 install the Root from GET /tls/server-certificate (the last certificate) in its trust \
                 store, and reach the service by a name in the certificate (tls.hostnames, tls.ips). \
                 OpenSSL said: {}",
                tag(codes::STS_TLS_0034),
                peer,
                self.label,
                name,
                number,
                error
            );
            return;
        }
        tracing::warn!(
            "{}tls: a handshake failed on {} from {}: {}. A client certificate is asked for and never \
             required here, and the client sent no alert refusing this service's certificate, so this is \
             the handshake itself — a version, a cipher, or a client not speaking TLS.",
            tag(codes::STS_TLS_0021),
            self.label,
            peer,
            error
        );
    }

    /// `tls/alert_close.ts`: the FIN at once, the descriptor held two
    /// seconds while what the peer still sends is read and discarded, so
    /// the close sends no reset that could overtake the alert.
    async fn hold_close(&self, mut raw: TcpStream) {
        if self.held.fetch_add(1, Ordering::SeqCst) >= ALERT_HOLD_MAX {
            self.held.fetch_sub(1, Ordering::SeqCst);
            if !self.told_full.swap(true, Ordering::SeqCst) {
                tracing::warn!(
                    "{}tls: {} already holds {} connections that failed at the TLS layer; another is closed \
                     at once, and its TCP reset can discard the alert.",
                    tag(codes::STS_TLS_0061),
                    self.label,
                    ALERT_HOLD_MAX
                );
            }
            return;
        }
        if let Err(e) = raw.shutdown().await {
            tracing::debug!("{}: the FIN after an alert: {}", self.label, e);
        }
        let deadline = tokio::time::Instant::now() + ALERT_HOLD;
        let mut sink = [0u8; 4096];
        loop {
            match tokio::time::timeout_at(deadline, raw.read(&mut sink)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    tracing::debug!("{}: a held connection: {}", self.label, e);
                    break;
                }
            }
        }
        self.held.fetch_sub(1, Ordering::SeqCst);
    }
}

/// What a ClientHello said about the server name.
#[derive(Debug, Clone, PartialEq)]
enum Offered {
    Name(String),
    None,
    Unreadable,
}

/// The server name of a TLS ClientHello's first record
/// (`client_hello.ts`' `nameOfHello()`): `None` when it offers none,
/// `Unreadable` when the record or the extension is not well formed.
fn server_name_of(record: &[u8]) -> Offered {
    fn take<'a>(b: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
        if b.len() < n {
            return None;
        }
        let (head, rest) = b.split_at(n);
        *b = rest;
        Some(head)
    }
    fn len16(b: &mut &[u8]) -> Option<usize> {
        take(b, 2).map(|x| usize::from(x[0]) << 8 | usize::from(x[1]))
    }
    let parse = || -> Option<Offered> {
        let mut b = record;
        let head = take(&mut b, 5)?;
        if head[0] != 22 {
            return Some(Offered::None);
        }
        let mut hs =
            take(&mut b, usize::from(head[3]) << 8 | usize::from(head[4]))?;
        let kind = take(&mut hs, 4)?;
        if kind[0] != 1 {
            return Some(Offered::None);
        }
        take(&mut hs, 34)?;
        let sid = usize::from(take(&mut hs, 1)?[0]);
        take(&mut hs, sid)?;
        let suites = len16(&mut hs)?;
        take(&mut hs, suites)?;
        let comp = usize::from(take(&mut hs, 1)?[0]);
        take(&mut hs, comp)?;
        if hs.is_empty() {
            return Some(Offered::None);
        }
        let total = len16(&mut hs)?;
        let mut exts = take(&mut hs, total)?;
        while !exts.is_empty() {
            let t = len16(&mut exts)?;
            let n = len16(&mut exts)?;
            let mut body = take(&mut exts, n)?;
            if t != 0 {
                continue;
            }
            let list = len16(&mut body)?;
            let mut names = take(&mut body, list)?;
            if !body.is_empty() || names.is_empty() {
                return Some(Offered::Unreadable);
            }
            while !names.is_empty() {
                let kind = take(&mut names, 1)?[0];
                let n = len16(&mut names)?;
                let name = take(&mut names, n)?;
                if kind == 0 {
                    return match std::str::from_utf8(name) {
                        Ok(text) if !text.is_empty() => {
                            Some(Offered::Name(text.to_ascii_lowercase()))
                        }
                        _ => Some(Offered::Unreadable),
                    };
                }
            }
            return Some(Offered::Unreadable);
        }
        Some(Offered::None)
    };
    parse().unwrap_or(Offered::Unreadable)
}

/// The raw connection under the TLS engine: the ClientHello's bytes read
/// ahead and replayed, and — once the connection is dropped — a close held
/// for its alert when it failed at the TLS layer (`tls/alert_close.ts`).
struct Conn {
    replay: Vec<u8>,
    at: usize,
    tcp: Option<TcpStream>,
    failed: Arc<AtomicBool>,
    listener: Arc<TlsListener>,
}

impl Conn {
    /// Reads the first record, up to its declared length (bounded), with a
    /// deadline; whatever arrived is replayed whether or not it parsed.
    async fn sniffing(
        mut tcp: TcpStream,
        listener: Arc<TlsListener>,
    ) -> (Conn, Offered) {
        let mut buf = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut chunk = [0u8; 4096];
        let offered = loop {
            let want = if buf.len() >= 5 {
                5 + (usize::from(buf[3]) << 8 | usize::from(buf[4]))
            } else {
                5
            };
            if buf.len() >= want || buf.len() >= 16 * 1024 + 5 {
                break server_name_of(&buf);
            }
            if buf.first().is_some_and(|b| *b != 22) {
                break Offered::None;
            }
            match tokio::time::timeout_at(deadline, tcp.read(&mut chunk)).await
            {
                Ok(Ok(0)) | Err(_) => break Offered::Unreadable,
                Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
                Ok(Err(_)) => break Offered::Unreadable,
            }
        };
        (
            Conn {
                replay: buf,
                at: 0,
                tcp: Some(tcp),
                failed: Arc::new(AtomicBool::new(false)),
                listener,
            },
            offered,
        )
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        if !self.failed.load(Ordering::SeqCst) {
            return;
        }
        if let Some(tcp) = self.tcp.take() {
            let listener = self.listener.clone();
            tokio::spawn(async move { listener.hold_close(tcp).await });
        }
    }
}

impl AsyncRead for Conn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.at < self.replay.len() {
            let n = (self.replay.len() - self.at).min(out.remaining());
            let at = self.at;
            out.put_slice(&self.replay[at..at + n]);
            self.at += n;
            return std::task::Poll::Ready(Ok(()));
        }
        match self.tcp.as_mut() {
            Some(tcp) => Pin::new(tcp).poll_read(cx, out),
            None => std::task::Poll::Ready(Ok(())),
        }
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.tcp.as_mut() {
            Some(tcp) => Pin::new(tcp).poll_write(cx, data),
            None => std::task::Poll::Ready(Ok(0)),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.tcp.as_mut() {
            Some(tcp) => Pin::new(tcp).poll_flush(cx),
            None => std::task::Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.tcp.as_mut() {
            Some(tcp) => Pin::new(tcp).poll_shutdown(cx),
            None => std::task::Poll::Ready(Ok(())),
        }
    }
}

/// The TLS stream as HTTP reads it: a read that fails is a TLS-layer
/// failure after the handshake (a bad record, a CCS after Finished, a
/// record too big), and its connection's close is held for the alert
/// OpenSSL wrote — the second of `alert_close.ts`' two ways.
struct Watched {
    inner: tokio_openssl::SslStream<Conn>,
    failed: Arc<AtomicBool>,
}

impl AsyncRead for Watched {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let polled = Pin::new(&mut self.inner).poll_read(cx, out);
        if let std::task::Poll::Ready(Err(e)) = &polled {
            if !e.to_string().contains("SSL alert number") {
                self.failed.store(true, Ordering::SeqCst);
            }
        }
        polled
    }
}

impl AsyncWrite for Watched {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)] // tests

    use std::collections::HashMap;

    use serde_json::json;
    use sts_core::settings::Settings;
    use sts_pki::listener::{bootstrap, ListenerIdentity};
    use sts_tls::policy::{policy_for, ListenerKind};

    use super::*;

    fn certificate() -> ListenerCertificate {
        bootstrap(
            &ListenerIdentity {
                hostnames: vec!["localhost".into()],
                ips: vec!["127.0.0.1".into()],
                organisation: "iya-sts".into(),
                rsa_bits: 2048,
                self_signed_years: 1,
            },
            "rsa",
        )
        .unwrap()
    }

    #[test]
    fn the_default_policy_builds_a_context() {
        let s = Settings::new(json!({}), HashMap::new());
        let p = policy_for(&s, &ListenerKind::Main);
        let applied =
            build_context("t", &p, &[certificate()], &[], true).unwrap();
        assert!(!applied.require_verified);
    }

    #[test]
    fn a_cipher_list_that_matches_nothing_does_not_build() {
        let s = Settings::new(
            json!({ "tls": { "disableTls12": false, "ciphers": "NOT-A-CIPHER" } }),
            HashMap::new(),
        );
        let p = policy_for(&s, &ListenerKind::Main);
        let err = build_context("t", &p, &[certificate()], &[], true)
            .err()
            .unwrap();
        assert!(err.starts_with("tls.ciphers"), "{}", err);
    }

    #[test]
    fn the_certificate_alerts_are_told_apart() {
        assert_eq!(
            peer_refused_certificate(
                "ssl3_read_bytes:tlsv1 alert unknown ca:SSL alert number 48"
            ),
            Some((48, "unknown_ca"))
        );
        assert!(peer_refused_certificate("no shared cipher").is_none());
    }

    /// One request over a real handshake: what the request was told.
    async fn ask(
        port: u16,
        alpn: &[u8],
        client: Option<&ListenerCertificate>,
    ) -> (String, String) {
        use openssl::ssl::{SslConnector, SslVerifyMode};
        let mut c = SslConnector::builder(SslMethod::tls_client()).unwrap();
        c.set_verify(SslVerifyMode::NONE);
        c.set_alpn_protos(alpn).unwrap();
        if let Some(cert) = client {
            let opened = cert.open().unwrap();
            c.set_certificate(&opened.leaf).unwrap();
            c.set_private_key(&opened.key).unwrap();
        }
        let ssl = c
            .build()
            .configure()
            .unwrap()
            .into_ssl("localhost")
            .unwrap();
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut tls = tokio_openssl::SslStream::new(ssl, tcp).unwrap();
        Pin::new(&mut tls).connect().await.unwrap();
        let chosen = tls
            .ssl()
            .selected_alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).to_string())
            .unwrap_or_default();
        tls.write_all(
            b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        let mut answer = Vec::new();
        tls.read_to_end(&mut answer).await.unwrap_or_default();
        let text = String::from_utf8_lossy(&answer).to_string();
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        (chosen, body)
    }

    #[tokio::test]
    async fn a_request_is_told_its_connection_and_client_chain() {
        let s = Settings::new(json!({}), HashMap::new());
        let p = policy_for(&s, &ListenerKind::Main);
        let applied =
            build_context("t", &p, &[certificate()], &[], true).unwrap();
        let listener = TlsListener::new("main", "t", 0, applied, true);
        let tcp = listener.bind("127.0.0.1:0").await.unwrap();
        let port = tcp.local_addr().unwrap().port();
        let router = axum::Router::new().route(
            "/",
            axum::routing::get(
                |axum::Extension(f): axum::Extension<ConnectionFacts>| async move {
                    let t = f.tls.unwrap_or_default();
                    format!(
                        "{} {} {} {} {}",
                        f.listener,
                        t.version,
                        t.peer_chain.len(),
                        t.authorized,
                        t.authorization_error.unwrap_or_default()
                    )
                },
            ),
        );
        tokio::spawn(listener.clone().serve(tcp, router));
        // ALPN in the server's order: http/1.1 asked alone is served.
        let (alpn, body) = ask(port, b"\x08http/1.1", None).await;
        assert_eq!(alpn, "http/1.1");
        assert_eq!(body, "main TLSv1.3 0 false ");
        // A certificate that verifies to nothing completes the handshake,
        // unverified, as node's requestCert without rejectUnauthorized;
        // this one is a SERVER certificate, so OpenSSL's sslclient purpose
        // check names it first, in node's spelling.
        let (_, body) = ask(port, b"\x08http/1.1", Some(&certificate())).await;
        assert_eq!(body, "main TLSv1.3 1 false INVALID_PURPOSE");
        assert_eq!(
            listener.status.lock().unwrap().state,
            "listening".to_string()
        );
    }
}
