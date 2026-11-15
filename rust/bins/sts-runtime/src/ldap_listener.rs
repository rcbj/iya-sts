// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE DIRECTORY'S TWO SOCKETS, 389 AND LDAPS 636 (`ldap/ldap_server.js`'s
//! `listen()`): socket owners started from `listen()` after the main port,
//! each a failure to bind RECORDED (`STS-LDAP-0027`, `STS-LDAP-0028`) and
//! never thrown — the root `CLAUDE.md`'s rule for every socket owner.
//!
//! Every accepted connection gets one `sts_ldap::Connection` (node-ldapjs'
//! parser and its own answers, the fork's behaviour byte for byte), and
//! every read is fed to it: `Write` is sent, `Destroy` and `Thrown`
//! close the socket, and `Dispatch` is a request for the
//! directory's handlers — **phase 4's**. Until they arrive [`Handlers`] is
//! the seam and [`NotYet`] answers each request `unwillingToPerform` (53)
//! with the response its operation takes, an unbind closing the connection
//! and an abandon answering nothing, as RFC 4511 says of both.
//!
//! LDAPS presents the listener certificate's FIRST certificate (the RSA
//! one: no LDAP client in reach speaks ML-DSA) under the `ldaps` policy,
//! with no ALPN (tlsfuzzer's `noAlpnOnLdaps`).

use std::pin::Pin;
use std::sync::Arc;

use openssl::ssl::Ssl;
use sts_core::errors::codes;
use sts_core::log::tag;
use sts_ldap::front::{Connection, Event, FrontOptions};
use sts_ldap::message::{Message, Operation, ResultMessage};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

/// What answers a dispatched request: the bytes to send, in order, and
/// whether the connection is then closed.
pub trait Handlers: Send + Sync {
    fn handle(&self, message: &Message) -> (Vec<Vec<u8>>, bool);
}

/// The response tag a request is answered with (RFC 4511 section 4.2 ff).
fn response_op(message: &Message) -> Option<u8> {
    Some(match &message.operation {
        Operation::Bind(_) => 0x61,
        Operation::Search(_) => 0x65,
        Operation::Modify(_) => 0x67,
        Operation::Add(_) => 0x69,
        Operation::Delete { .. } => 0x6b,
        Operation::ModifyDn(_) => 0x6d,
        Operation::Compare(_) => 0x6f,
        Operation::Extended(_) => 0x78,
        Operation::Abandon { .. }
        | Operation::Unbind
        | Operation::Response(_) => return None,
    })
}

/// THE TWO SOCKETS' STATE, AS THE DIRECTORY'S VIEWS PUBLISH IT
/// (`directoryState()`'s `port`, `listening`, `listenError`, `ldapsPort`
/// and `ldapsListening`): `ldap_server.js` keeps them as module state
/// written by `listen()`, and a view reads them whatever happened. Here
/// they are written by [`listen_plain`] and [`listen_tls`] and read by
/// `/admin-api/groups` (#444, phase 5, the `apis3` slice). The port starts
/// at the configured one, as Node's `boundPort` starts at `LDAP_PORT`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SocketState {
    pub port: Option<u16>,
    pub listening: bool,
    pub listen_error: String,
    /// `secureServer ? boundTlsPort : null`: set once LDAPS has a context.
    pub ldaps_port: Option<u16>,
    pub ldaps_listening: bool,
}

static STATE: std::sync::Mutex<SocketState> =
    std::sync::Mutex::new(SocketState {
        port: None,
        listening: false,
        listen_error: String::new(),
        ldaps_port: None,
        ldaps_listening: false,
    });

fn record(change: impl FnOnce(&mut SocketState)) {
    let mut held = STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    change(&mut held);
}

/// The sockets' state now.
#[tracing::instrument(level = "debug")]
pub fn state() -> SocketState {
    STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// The stand-in until the directory is ported (phase 4).
pub struct NotYet;

impl Handlers for NotYet {
    fn handle(&self, message: &Message) -> (Vec<Vec<u8>>, bool) {
        if matches!(message.operation, Operation::Unbind) {
            return (Vec::new(), true);
        }
        let Some(op) = response_op(message) else {
            return (Vec::new(), false);
        };
        let answer = ResultMessage {
            message_id: message.message_id,
            protocol_op: op,
            status: 53,
            diagnostic_message:
                "The embedded directory is not ported to this runtime yet."
                    .to_string(),
            ..ResultMessage::default()
        };
        match answer.to_ber() {
            Ok(bytes) => (vec![bytes], false),
            Err(e) => {
                tracing::debug!("ldap: an answer did not encode: {:?}", e);
                (Vec::new(), true)
            }
        }
    }
}

// A hot path (every LDAP connection): no span of its own.
async fn session<S>(mut stream: S, handlers: Arc<dyn Handlers>, label: String)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut parser = Connection::new(FrontOptions::default());
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match stream.read(&mut buf).await {
            Ok(0) => return,
            Ok(n) => n,
            Err(e) => {
                tracing::debug!("ldap: {}: a read ended: {}", label, e);
                return;
            }
        };
        for event in parser.feed(&buf[..n]) {
            let (writes, close) = match event {
                Event::Write(bytes) => (vec![bytes], false),
                Event::Dispatch(message) => handlers.handle(&message),
                Event::Destroy => (Vec::new(), true),
                Event::Thrown(why) => {
                    tracing::debug!(
                        "ldap: {}: the parser threw: {}",
                        label,
                        why
                    );
                    (Vec::new(), true)
                }
            };
            for bytes in writes {
                if let Err(e) = stream.write_all(&bytes).await {
                    tracing::debug!("ldap: {}: a write failed: {}", label, e);
                    return;
                }
            }
            if close {
                if let Err(e) = stream.shutdown().await {
                    tracing::debug!("ldap: {}: the close: {}", label, e);
                }
                return;
            }
        }
    }
}

/// Binds the plain listener; `None` (recorded) when it cannot.
#[tracing::instrument(level = "debug", skip(handlers))]
pub async fn listen_plain(
    host: &str,
    port: u16,
    handlers: Arc<dyn Handlers>,
) -> Option<tokio::task::JoinHandle<()>> {
    record(|s| s.port = Some(port));
    let tcp = match TcpListener::bind((host, port)).await {
        Ok(tcp) => tcp,
        Err(e) => {
            let why = e.to_string();
            record(|s| {
                s.listening = false;
                s.listen_error = why;
            });
            tracing::error!(
                "{}ldap: the plain LDAP listener could not bind {}:{}: {}; the directory does not answer on it.",
                tag(codes::STS_LDAP_0027),
                host,
                port,
                e
            );
            return None;
        }
    };
    let bound = tcp.local_addr().map(|a| a.port()).unwrap_or(port);
    record(|s| {
        s.port = Some(bound);
        s.listening = true;
        s.listen_error = String::new();
    });
    tracing::info!("ldap: listening on ldap://{}:{}", host, port);
    Some(tokio::spawn(async move {
        loop {
            match tcp.accept().await {
                Ok((stream, peer)) => {
                    let h = handlers.clone();
                    tokio::spawn(session(stream, h, peer.to_string()));
                }
                Err(e) => {
                    tracing::debug!("ldap: an accept failed: {}", e);
                }
            }
        }
    }))
}

/// Binds LDAPS over the context the listeners' registry builds for the
/// `ldaps` kind; `None` (recorded) when it cannot.
#[tracing::instrument(level = "debug", skip(handlers, context))]
pub async fn listen_tls(
    host: &str,
    port: u16,
    context: openssl::ssl::SslContext,
    handlers: Arc<dyn Handlers>,
) -> Option<tokio::task::JoinHandle<()>> {
    record(|s| s.ldaps_port = Some(port));
    let tcp = match TcpListener::bind((host, port)).await {
        Ok(tcp) => tcp,
        Err(e) => {
            record(|s| s.ldaps_listening = false);
            tracing::error!(
                "{}ldap: the LDAPS listener could not bind {}:{}: {}; LDAPS is not offered.",
                tag(codes::STS_LDAP_0028),
                host,
                port,
                e
            );
            return None;
        }
    };
    let bound = tcp.local_addr().map(|a| a.port()).unwrap_or(port);
    record(|s| {
        s.ldaps_port = Some(bound);
        s.ldaps_listening = true;
    });
    tracing::info!("ldap: listening on ldaps://{}:{}", host, port);
    let context = Arc::new(context);
    Some(tokio::spawn(async move {
        loop {
            let (stream, peer) = match tcp.accept().await {
                Ok(a) => a,
                Err(e) => {
                    tracing::debug!("ldap: an accept failed: {}", e);
                    continue;
                }
            };
            let (h, ctx) = (handlers.clone(), context.clone());
            tokio::spawn(async move {
                let Ok(ssl) = Ssl::new(&ctx) else {
                    return;
                };
                let Ok(mut tls) = tokio_openssl::SslStream::new(ssl, stream)
                else {
                    return;
                };
                if let Err(e) = Pin::new(&mut tls).accept().await {
                    tracing::debug!(
                        "ldap: an LDAPS handshake from {} failed: {}",
                        peer,
                        e
                    );
                    return;
                }
                session(tls, h, peer.to_string()).await;
            });
        }
    }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)] // tests

    use super::*;

    #[tokio::test]
    async fn a_bind_is_answered_unwilling_and_an_unbind_closes() {
        let handle = listen_plain("127.0.0.1", 0, Arc::new(NotYet)).await;
        assert!(handle.is_some());
        // Port 0 binds, but its number is not handed back; drive the
        // session directly over a duplex pipe instead.
        let (mut client, server) = tokio::io::duplex(4096);
        tokio::spawn(session(server, Arc::new(NotYet), "t".into()));
        // A simple anonymous bind, message id 1 (RFC 4511 section 4.2).
        let bind = [
            0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04,
            0x00, 0x80, 0x00,
        ];
        client.write_all(&bind).await.unwrap();
        let mut answer = [0u8; 512];
        let n = client.read(&mut answer).await.unwrap();
        // BindResponse (0x61) with resultCode 53.
        assert!(answer[..n].windows(3).any(|w| w == [0x0a, 0x01, 53]));
        assert!(answer[..n].contains(&0x61));
        // An unbind closes the connection.
        client
            .write_all(&[0x30, 0x05, 0x02, 0x01, 0x02, 0x42, 0x00])
            .await
            .unwrap();
        let n = client.read(&mut answer).await.unwrap();
        assert_eq!(n, 0, "{:02x?}", &answer[..n]);
        handle.unwrap().abort();
    }
}
