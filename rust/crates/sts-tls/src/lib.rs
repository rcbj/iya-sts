// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! TLS and the listeners, as data (#444 phase 3, the `tls` slice): what
//! `tls/tls_server.js` and `common/listener_map.js` DECIDE, with no OpenSSL
//! type in it.
//!
//! * [`policy`]: every listener's TLS policy and the write rules over it;
//! * [`definitions`]: the custom listeners an operator defines;
//! * [`truststore`]: the client truststore;
//! * [`ConnectionFacts`]: what a request is told about the connection it
//!   came on — the listener, the peer, and the TLS session with the client
//!   certificate chain OpenSSL was shown and its verdict. `GET
//!   /tls/sign-in` (phase 5), RFC 8705 (`oauth-oidc/mtls.js`), the XACML
//!   and SCIM certificate gates read it.
//!
//! The listener certificate and its hierarchy are `sts-pki::listener`;
//! the sockets, the context OpenSSL is given and the accept loop are
//! `sts-runtime`'s (`listener.rs`), which is where the workspace allows
//! `openssl::ssl` (the guard `crypto_centralised`).

#![forbid(unsafe_code)]

pub mod definitions;
pub mod policy;
pub mod truststore;

/// The TLS half of a connection, read once the handshake is done.
#[derive(Debug, Clone, Default)]
pub struct TlsFacts {
    /// `TLSv1.3`, `TLSv1.2`.
    pub version: String,
    /// The suite's IANA name.
    pub cipher: String,
    /// The ALPN protocol chosen, if any.
    pub alpn: Option<String>,
    /// The server name the client offered.
    pub server_name: Option<String>,
    /// Whether the session was resumed.
    pub resumed: bool,
    /// The client's chain as it SENT it, DER, leaf first; empty when it
    /// presented none. A resumed session carries the leaf alone.
    pub peer_chain: Vec<Vec<u8>>,
    /// `socket.authorized`: OpenSSL built a path to an anchor.
    pub authorized: bool,
    /// `socket.authorizationError`, node's spelling of OpenSSL's verify
    /// result (`UNABLE_TO_GET_ISSUER_CERT_LOCALLY`, …), when not authorized
    /// and a certificate was presented.
    pub authorization_error: Option<String>,
}

/// What every request is told about its connection (a request extension).
#[derive(Debug, Clone, Default)]
pub struct ConnectionFacts {
    /// `main`, or a custom listener's id (`stsListener`).
    pub listener: String,
    /// For a realm's own listener, its realm (`stsRealmListener`).
    pub realm_listener: Option<String>,
    pub peer: Option<std::net::SocketAddr>,
    pub local: Option<std::net::SocketAddr>,
    /// `None` on a plain-HTTP listener.
    pub tls: Option<TlsFacts>,
}

/// node's `authorizationError` for an OpenSSL `X509_V_ERR_*` number: the
/// constant's name without its prefix, as node's `X509ErrorCode()` spells
/// it. The common ones; any other is `UNSPECIFIED`'s spelling with the
/// number, which node does not produce but which names it.
#[tracing::instrument(level = "debug", skip_all)]
pub fn authorization_error_name(code: i32) -> String {
    match code {
        2 => "UNABLE_TO_GET_ISSUER_CERT",
        3 => "UNABLE_TO_GET_CRL",
        4 => "UNABLE_TO_DECRYPT_CERT_SIGNATURE",
        5 => "UNABLE_TO_DECRYPT_CRL_SIGNATURE",
        6 => "UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY",
        7 => "CERT_SIGNATURE_FAILURE",
        8 => "CRL_SIGNATURE_FAILURE",
        9 => "CERT_NOT_YET_VALID",
        10 => "CERT_HAS_EXPIRED",
        11 => "CRL_NOT_YET_VALID",
        12 => "CRL_HAS_EXPIRED",
        13 => "ERROR_IN_CERT_NOT_BEFORE_FIELD",
        14 => "ERROR_IN_CERT_NOT_AFTER_FIELD",
        15 => "ERROR_IN_CRL_LAST_UPDATE_FIELD",
        16 => "ERROR_IN_CRL_NEXT_UPDATE_FIELD",
        17 => "OUT_OF_MEM",
        18 => "DEPTH_ZERO_SELF_SIGNED_CERT",
        19 => "SELF_SIGNED_CERT_IN_CHAIN",
        20 => "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
        21 => "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
        22 => "CERT_CHAIN_TOO_LONG",
        23 => "CERT_REVOKED",
        24 => "INVALID_CA",
        25 => "PATH_LENGTH_EXCEEDED",
        26 => "INVALID_PURPOSE",
        27 => "CERT_UNTRUSTED",
        28 => "CERT_REJECTED",
        29 => "SUBJECT_ISSUER_MISMATCH",
        30 => "AKID_SKID_MISMATCH",
        31 => "AKID_ISSUER_SERIAL_MISMATCH",
        32 => "KEYUSAGE_NO_CERTSIGN",
        50 => "INVALID_EXTENSION",
        51 => "INVALID_POLICY_EXTENSION",
        52 => "NO_EXPLICIT_POLICY",
        65 => "HOSTNAME_MISMATCH",
        other => return format!("UNSPECIFIED_{}", other),
    }
    .to_string()
}
