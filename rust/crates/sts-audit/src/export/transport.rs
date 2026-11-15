// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The sockets and files an export reaches, as ports: what Node handed
//! `AuditExport` as `deps.dns`, `deps.http`/`deps.https`, `deps.net`,
//! `deps.tls`, `deps.dgram` and `deps.fs`. The exporter decides WHAT is
//! sent and to which checked address; these only carry it.
//!
//! [`RealTransports`] is the production implementation: the system
//! resolver, `reqwest` for webhook and Splunk HEC (pinned to the checked
//! address, no redirect followed, the body read to 64 KiB), tokio's TCP
//! and UDP for syslog, and `std::fs` for a file destination (`O_APPEND`,
//! the mode at creation). **Syslog over TLS is not dialled here**: a raw
//! TLS stream needs the runtime's TLS connector (the TLS slice's, with the
//! host-name and path rules `outbound_tls.ts`'s `checkServerIdentity()`
//! applies), and until it is wired a `tls` destination's send fails with
//! `STS-AUDIT-0006`, which holds its cursor and loses nothing.

use std::collections::HashMap;
use std::io::Write as _;
use std::net::SocketAddr;
use std::time::Duration;

use serde_json::{Map, Value as Json};
use sts_cluster::schedule::BoxFuture;

use super::event::BODY_CAP;
use super::outbound::TlsPolicy;

/// A failed socket operation: the code Node put on the error
/// (`codeName`), when it put one, and the sentence.
#[derive(Debug, Clone, PartialEq)]
pub struct SendError {
    pub code: Option<String>,
    pub why: String,
}

impl SendError {
    #[tracing::instrument(level = "debug")]
    pub fn plain(why: &str) -> SendError {
        SendError {
            code: None,
            why: why.to_string(),
        }
    }
}

/// `dns.promises.lookup(host, { all: true, verbatim: true })`.
pub trait Resolver: Send + Sync {
    fn lookup<'a>(
        &'a self,
        host: &'a str,
    ) -> BoxFuture<'a, Result<Vec<String>, String>>;
}

/// One POST, as `postHttp()` builds it for `http.request()`.
#[derive(Debug, Clone, PartialEq)]
pub struct HttpRequest {
    /// `https:` or `http:`.
    pub protocol: String,
    pub hostname: String,
    /// `target.port || 443` — Node's text port, or the default number.
    pub port: Json,
    pub path: String,
    pub method: String,
    /// In the order Node assigns them.
    pub headers: Map<String, Json>,
    pub body: String,
    /// The checked address the connection is pinned to.
    pub pinned: Option<String>,
    /// The TLS options, for https.
    pub tls: Option<TlsPolicy>,
    pub timeout_ms: u64,
}

/// What came back: the status, the headers (lower-case names), the body
/// up to [`BODY_CAP`] and whether it was longer. A 3xx carries no body.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct HttpAnswer {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub overflow: bool,
}

/// `http.request()` / `https.request()`.
pub trait HttpTransport: Send + Sync {
    fn post<'a>(
        &'a self,
        request: &'a HttpRequest,
    ) -> BoxFuture<'a, Result<HttpAnswer, String>>;
}

/// An open syslog TCP or TLS socket, one per destination per tick.
pub trait SyslogPipe: Send {
    fn write<'a>(
        &'a mut self,
        frame: &'a [u8],
        timeout_ms: u64,
    ) -> BoxFuture<'a, Result<(), SendError>>;
    fn close(&mut self);
}

/// `net.connect()`, `tls.connect()` and `dgram`.
pub trait SyslogTransport: Send + Sync {
    /// Opens `tcp` or `tls` to an address already checked; TLS keeps the
    /// configured name as the server name.
    fn open<'a>(
        &'a self,
        transport: &'a str,
        ip: &'a str,
        port: u16,
        servername: Option<&'a str>,
        tls: Option<&'a TlsPolicy>,
        timeout_ms: u64,
    ) -> BoxFuture<'a, Result<Box<dyn SyslogPipe>, SendError>>;
    /// Sends one datagram; the call returning is transmission.
    fn send_udp<'a>(
        &'a self,
        message: &'a [u8],
        ip: &'a str,
        port: u16,
        timeout_ms: u64,
    ) -> BoxFuture<'a, Result<(), SendError>>;
}

/// A file opened for appending.
pub trait AppendFile: Send {
    fn size(&mut self) -> Result<u64, String>;
    fn append(&mut self, bytes: &[u8]) -> Result<(), String>;
}

/// `fs.promises`, as the file destination uses it.
pub trait Files: Send + Sync {
    fn open_append(
        &self,
        path: &str,
        mode: u32,
    ) -> Result<Box<dyn AppendFile>, String>;
    fn exists(&self, path: &str) -> bool;
    fn rename(&self, from: &str, to: &str) -> Result<(), String>;
}

/// The production transports.
pub struct RealTransports;

impl Resolver for RealTransports {
    fn lookup<'a>(
        &'a self,
        host: &'a str,
    ) -> BoxFuture<'a, Result<Vec<String>, String>> {
        Box::pin(async move {
            let found = tokio::net::lookup_host((host, 0))
                .await
                .map_err(|e| e.to_string())?;
            let mut out: Vec<String> = Vec::new();
            for addr in found {
                let ip = addr.ip().to_string();
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
            Ok(out)
        })
    }
}

impl HttpTransport for RealTransports {
    fn post<'a>(
        &'a self,
        request: &'a HttpRequest,
    ) -> BoxFuture<'a, Result<HttpAnswer, String>> {
        Box::pin(async move { real_post(request).await })
    }
}

async fn real_post(request: &HttpRequest) -> Result<HttpAnswer, String> {
    let port: u16 = match &request.port {
        Json::Number(n) => n.as_u64().unwrap_or(443) as u16,
        Json::String(s) => s.parse().unwrap_or(443),
        _ => 443,
    };
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_millis(request.timeout_ms));
    if let Some(ip) = &request.pinned {
        let addr: std::net::IpAddr = ip
            .parse()
            .map_err(|_| "the checked address is not an address".to_string())?;
        builder =
            builder.resolve(&request.hostname, SocketAddr::new(addr, port));
    }
    if let Some(tls) = &request.tls {
        builder = builder.danger_accept_invalid_certs(!tls.reject_unauthorized);
        for pem in &tls.ca {
            let cert = reqwest::Certificate::from_pem(pem.as_bytes())
                .map_err(|e| e.to_string())?;
            builder = builder.add_root_certificate(cert);
        }
    }
    let client = builder.build().map_err(|e| e.to_string())?;
    let scheme = request.protocol.trim_end_matches(':');
    let host = if request.hostname.contains(':') {
        format!("[{}]", request.hostname)
    } else {
        request.hostname.clone()
    };
    let url = format!("{}://{}:{}{}", scheme, host, port, request.path);
    let mut call = client.post(url).body(request.body.clone());
    for (name, value) in &request.headers {
        call = call.header(name.as_str(), value.as_str().unwrap_or(""));
    }
    let mut response = call.send().await.map_err(|e| e.to_string())?;
    let status = response.status().as_u16();
    let headers: HashMap<String, String> = response
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    if (300..400).contains(&status) {
        return Ok(HttpAnswer {
            status,
            headers,
            ..HttpAnswer::default()
        });
    }
    let mut body = Vec::new();
    let mut overflow = false;
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        if body.len() + chunk.len() > BODY_CAP {
            overflow = true;
            break;
        }
        body.extend_from_slice(&chunk);
    }
    if overflow {
        body.clear();
    }
    Ok(HttpAnswer {
        status,
        headers,
        body,
        overflow,
    })
}

struct TcpPipe(Option<tokio::net::TcpStream>);

impl SyslogPipe for TcpPipe {
    fn write<'a>(
        &'a mut self,
        frame: &'a [u8],
        timeout_ms: u64,
    ) -> BoxFuture<'a, Result<(), SendError>> {
        Box::pin(async move {
            use tokio::io::AsyncWriteExt;
            let Some(stream) = self.0.as_mut() else {
                return Err(SendError::plain("the syslog socket is closed"));
            };
            match tokio::time::timeout(
                Duration::from_millis(timeout_ms),
                stream.write_all(frame),
            )
            .await
            {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(SendError::plain(&e.to_string())),
                Err(_) => Err(SendError::plain("the syslog write timed out")),
            }
        })
    }

    fn close(&mut self) {
        self.0 = None;
    }
}

impl SyslogTransport for RealTransports {
    fn open<'a>(
        &'a self,
        transport: &'a str,
        ip: &'a str,
        port: u16,
        _servername: Option<&'a str>,
        _tls: Option<&'a TlsPolicy>,
        timeout_ms: u64,
    ) -> BoxFuture<'a, Result<Box<dyn SyslogPipe>, SendError>> {
        Box::pin(async move {
            if transport == "tls" {
                return Err(SendError::plain(
                    "the TLS syslog transport is not wired in this runtime",
                ));
            }
            let addr: std::net::IpAddr =
                ip.parse().map_err(|_| SendError::plain("not an address"))?;
            match tokio::time::timeout(
                Duration::from_millis(timeout_ms),
                tokio::net::TcpStream::connect(SocketAddr::new(addr, port)),
            )
            .await
            {
                Ok(Ok(stream)) => {
                    Ok(Box::new(TcpPipe(Some(stream))) as Box<dyn SyslogPipe>)
                }
                Ok(Err(e)) => Err(SendError::plain(&e.to_string())),
                Err(_) => Err(SendError::plain("the syslog connect timed out")),
            }
        })
    }

    fn send_udp<'a>(
        &'a self,
        message: &'a [u8],
        ip: &'a str,
        port: u16,
        timeout_ms: u64,
    ) -> BoxFuture<'a, Result<(), SendError>> {
        Box::pin(async move {
            let addr: std::net::IpAddr =
                ip.parse().map_err(|_| SendError::plain("not an address"))?;
            let local = if addr.is_ipv6() {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            };
            let socket = tokio::net::UdpSocket::bind(local)
                .await
                .map_err(|e| SendError::plain(&e.to_string()))?;
            match tokio::time::timeout(
                Duration::from_millis(timeout_ms),
                socket.send_to(message, SocketAddr::new(addr, port)),
            )
            .await
            {
                Ok(Ok(_)) => Ok(()),
                Ok(Err(e)) => Err(SendError::plain(&e.to_string())),
                Err(_) => Err(SendError::plain("the syslog send timed out")),
            }
        })
    }
}

struct StdAppend(std::fs::File);

impl AppendFile for StdAppend {
    fn size(&mut self) -> Result<u64, String> {
        self.0
            .metadata()
            .map(|m| m.len())
            .map_err(|e| e.to_string())
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.0.write_all(bytes).map_err(|e| e.to_string())
    }
}

impl Files for RealTransports {
    fn open_append(
        &self,
        path: &str,
        mode: u32,
    ) -> Result<Box<dyn AppendFile>, String> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(mode)
            .open(path)
            .map_err(|e| e.to_string())?;
        Ok(Box::new(StdAppend(file)))
    }

    fn exists(&self, path: &str) -> bool {
        std::fs::metadata(path).is_ok()
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), String> {
        std::fs::rename(from, to).map_err(|e| e.to_string())
    }
}
