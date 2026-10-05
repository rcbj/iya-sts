// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A REMOTE XACML POLICY ENFORCEMENT POINT (#444 phase 1; the Node
//! container it replaces is `xacml-pep/`, whose `CLAUDE.md` argues the
//! design). It holds its own copy of the engine (`sts-xacml`), PULLS the
//! policy repository from the PDP and decides here. Same container contract:
//! the same environment, ports, endpoints, JSON and log lines.
//!
//! `xacml-pep --stamp <dir>` writes `version.json` at image build time, and
//! `xacml-pep --healthcheck` is the image's HEALTHCHECK (there is no node
//! or curl in it): it asks `GET /healthcheck` on `PEP_PORT` and exits 0 on
//! a 200.

#![forbid(unsafe_code)]

mod enforce;
mod listener;
mod options;
mod pdp_client;
mod pip;
mod service;
mod sync;

use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use sts_core::errors::codes;

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use sts_core::log::{self, tag};
use sts_core::version;
use tokio::net::TcpListener;

use crate::listener::HttpsListener;
use crate::options::Options;
use crate::pdp_client::PdpClient;
use crate::pip::RemotePip;
use crate::service::Pep;
use crate::sync::Sync;

/// A timer that backs off while the PDP refuses: each failed round doubles
/// the wait up to `cap_ms`, the first success puts it back. A round never
/// overlaps itself.
fn on_backoff<F>(label: &'static str, base_ms: u64, cap_ms: u64, work: F)
where
    F: Fn() -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + 'static,
{
    let ceiling = base_ms.max(cap_ms);
    tokio::spawn(async move {
        let mut failures: u32 = 0;
        loop {
            let wait = base_ms
                .saturating_mul(2u64.saturating_pow(failures))
                .min(ceiling);
            tokio::time::sleep(Duration::from_millis(wait)).await;
            if work().await {
                if failures > 0 {
                    tracing::info!(
                        "xacml-pep: {} succeeded again; back to \
                                    every {}ms.",
                        label,
                        base_ms
                    );
                }
                failures = 0;
            } else {
                failures = (failures + 1).min(30);
            }
        }
    });
}

/// Once started, a panic is CONTAINED (#355): logged with where it
/// happened, at occurrences 1, 2, 3 and each power of ten, and the PEP
/// carries on enforcing what it last pulled. A task that panics is ended by
/// tokio; the process is not.
fn install_fault_handler() {
    let seen: Mutex<HashMap<String, u64>> = Mutex::new(HashMap::new());
    std::panic::set_hook(Box::new(move |info| {
        let signature = format!("{}", info);
        let count = match seen.lock() {
            Ok(mut map) => {
                if map.len() > 500 {
                    map.clear();
                }
                let entry = map.entry(signature.clone()).or_insert(0);
                *entry += 1;
                *entry
            }
            Err(_) => 1,
        };
        let mut v = count;
        while v >= 10 && v % 10 == 0 {
            v /= 10;
        }
        if count > 3 && v != 1 {
            return;
        }
        tracing::error!(
            "{}xacml-pep: an unexpected error (panic) was contained; the PEP \
             carries on. Seen {} time(s). {}",
            tag(codes::STS_XPEP_0033),
            count,
            signature
        );
    }));
}

async fn serve_http(pep: Arc<Pep>, port: u16) {
    let listener = match TcpListener::bind(("0.0.0.0", port)).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(
                "{}xacml-pep: could not start: cannot listen on \
                             {}: {}",
                tag(codes::STS_XPEP_0013),
                port,
                error
            );
            std::process::exit(1);
        }
    };
    tracing::info!(
        "xacml-pep: listening on {}. The protected resource is \
                    GET /protected.",
        port
    );
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let pep = pep.clone();
        tokio::spawn(async move {
            let service = tower_service(pep);
            let served = Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await;
            if let Err(error) = served {
                tracing::debug!("connection ended: {}", error);
            }
        });
    }
}

fn tower_service(pep: Arc<Pep>) -> TowerToHyperService<axum::routing::Router> {
    let router = axum::Router::new().fallback(move |request| {
        let pep = pep.clone();
        async move { pep.handle(request).await }
    });
    TowerToHyperService::new(router)
}

/// The HTTPS listener: started the first time a usable pair appears, and
/// each connection handed the pair being served at that moment.
async fn serve_https(pep: Arc<Pep>, https: Arc<HttpsListener>) {
    let listener = match TcpListener::bind(("0.0.0.0", https.port())).await {
        Ok(listener) => listener,
        Err(error) => {
            https.mark_bind_failed(&error.to_string());
            return;
        }
    };
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    https.mark_listening(port);
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let Some(acceptor) = https.current() else {
            continue;
        };
        let pep = pep.clone();
        tokio::spawn(async move {
            let Ok(ssl) = openssl::ssl::Ssl::new(acceptor.context()) else {
                return;
            };
            let Ok(mut tls) = tokio_openssl::SslStream::new(ssl, stream) else {
                return;
            };
            if let Err(error) = Pin::new(&mut tls).accept().await {
                tracing::debug!("TLS handshake failed: {}", error);
                return;
            }
            let served = Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls), tower_service(pep))
                .await;
            if let Err(error) = served {
                tracing::debug!("connection ended: {}", error);
            }
        });
    }
}

#[tracing::instrument(level = "debug", skip_all)]
async fn start(options: Options, info: version::VersionInfo) {
    tracing::info!(
        "xacml-pep: version {} (build {}{}, {}). M.N is the service's own \
         release; the build number is this image's.",
        info.version,
        info.build,
        if info.commit.is_empty() {
            String::new()
        } else {
            format!(", commit {}", info.commit)
        },
        if info.stamped {
            "stamped at image build time"
        } else {
            "COMPUTED AT STARTUP — this is not a built image, so the build \
             number is when this process started"
        }
    );
    tracing::info!(
        "xacml-pep: starting. PDP={} name={} bias={}",
        options.pdp_url,
        options.name,
        options.bias.as_str()
    );
    if options.insecure {
        tracing::warn!(
            "xacml-pep: PEP_TLS_INSECURE is on, so this PEP does NOT verify \
             the PDP's certificate. That is the ordinary setting against a \
             development-mode PDP — it regenerates its Root on every start, \
             so there is no anchor to verify against — and it is the wrong \
             setting against anything else."
        );
    }
    if options.client_certificate.is_none() {
        tracing::warn!(
            "xacml-pep: no PEP_TLS_CERT, so this PEP has no client \
             certificate. The PDP refuses the REGISTRATION unless \
             xacml.pepRequireCertificate is off — and it refuses the PULL \
             too, because GET /xacml/pep/policies requires a VERIFIED \
             certificate whose subject holds the built-in REMOTE_PEPS role. \
             This PEP will go on deciding against whatever policy it already \
             holds, which on a fresh start is NOTHING, so every decision will \
             be NotApplicable and the bias will settle it."
        );
    }
    let client = match PdpClient::new(&options) {
        Ok(client) => client,
        Err(error) => {
            tracing::error!(
                "{}xacml-pep: could not start: {}",
                tag(codes::STS_XPEP_0013),
                error
            );
            std::process::exit(1);
        }
    };
    let sync = Arc::new(Sync::new(client.clone(), options.clone()));
    let pip = RemotePip::new(client, options.pip_enabled);
    let https = Arc::new(HttpsListener::new(
        &options.https_cert_path,
        &options.https_key_path,
        options.https_port,
        options.https_reload_interval_ms,
    ));
    let pep = Arc::new(Pep::new(
        options.clone(),
        info,
        sync.clone(),
        pip,
        https.clone(),
    ));

    // REGISTER FIRST, PULL REGARDLESS — and both retried on the poll timer.
    sync.register().await;
    sync.pull("start").await;

    let poll_sync = sync.clone();
    on_backoff(
        "the poll",
        options.poll_interval_ms,
        options.backoff_max_ms,
        move || {
            let sync = poll_sync.clone();
            Box::pin(async move {
                sync.register_if_needed().await;
                sync.pull("poll").await
            })
        },
    );
    let beat_sync = sync.clone();
    on_backoff(
        "the heartbeat",
        options.heartbeat_interval_ms,
        options.backoff_max_ms,
        move || {
            let sync = beat_sync.clone();
            Box::pin(async move {
                let result = sync.heartbeat().await;
                if result.ok && !result.current {
                    sync.pull("heartbeat").await;
                }
                result.ok
            })
        },
    );

    if https.is_configured() {
        tracing::info!(
            "xacml-pep: HTTPS is configured on {} from {} and {}, re-read \
             every {}ms.",
            options.https_port,
            if options.https_cert_path.is_empty() {
                "(no PEP_HTTPS_CERT)"
            } else {
                options.https_cert_path.as_str()
            },
            if options.https_key_path.is_empty() {
                "(no PEP_HTTPS_KEY)"
            } else {
                options.https_key_path.as_str()
            },
            options.https_reload_interval_ms
        );
        let (watcher, served) = (https.clone(), pep.clone());
        tokio::spawn(async move {
            loop {
                if watcher.reload() {
                    tokio::spawn(serve_https(served.clone(), watcher.clone()));
                }
                tokio::time::sleep(watcher.interval()).await;
            }
        });
    }
    install_fault_handler();
    serve_http(pep, options.port).await;
}

/// The image's HEALTHCHECK: liveness only, as `/healthcheck` itself is.
fn healthcheck() -> i32 {
    use std::io::{Read, Write};
    let port = std::env::var("PEP_PORT").unwrap_or_else(|_| "9090".into());
    let address = format!("127.0.0.1:{}", port.trim());
    let Ok(mut stream) = std::net::TcpStream::connect(&address) else {
        return 1;
    };
    let timeout = Some(Duration::from_secs(4));
    if stream.set_read_timeout(timeout).is_err()
        || stream
            .write_all(
                b"GET /healthcheck HTTP/1.1\r\nHost: localhost\r\n\
                         Connection: close\r\n\r\n",
            )
            .is_err()
    {
        return 1;
    }
    let mut answer = String::new();
    if stream.read_to_string(&mut answer).is_err() && answer.is_empty() {
        return 1;
    }
    if answer.starts_with("HTTP/1.1 200") {
        0
    } else {
        1
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--healthcheck") {
        std::process::exit(healthcheck());
    }
    let level = std::env::var("PEP_LOG_LEVEL").unwrap_or_default();
    log::install("xacml-pep", log::parse_level(&level));
    if args.get(1).map(String::as_str) == Some("--stamp") {
        let dir = args.get(2).map(String::as_str).unwrap_or(".");
        let info = version::stamp(Path::new(dir));
        println!(
            "{}",
            serde_json::to_string_pretty(&info).unwrap_or_default()
        );
        return;
    }
    let here = std::env::current_dir().unwrap_or_else(|_| ".".into());
    let info = version::load(&here);
    let options = Options::from_env(&info.version);
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(
                "{}xacml-pep: could not start: {}",
                tag(codes::STS_XPEP_0013),
                error
            );
            std::process::exit(1);
        }
    };
    runtime.block_on(start(options, info));
}
