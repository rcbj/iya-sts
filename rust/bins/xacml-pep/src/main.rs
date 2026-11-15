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

mod authzen;
mod authzen_catalogue;
mod authzen_map;
mod enforce;
mod identity;
mod jwt;
mod listener;
mod listeners;
mod options;
mod pdp_client;
mod pip;
mod proxy;
mod proxy_auth;
mod proxy_config;
mod proxy_request;
#[cfg(test)]
mod proxy_tests;
mod rp_session;
mod rp_set;
mod saml_verify;
mod service;
mod settings;
mod sync;

use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use sts_core::log::{self, tag};
use sts_core::version;
use tokio::net::TcpListener;

use crate::listener::{peer_of, HttpsListener, Transport};
use crate::listeners::{EnvKind, ListenerSet, PlainStatus};
use crate::options::Options;
use crate::pdp_client::PdpClient;
use crate::pip::RemotePip;
use crate::proxy::Proxy;
use crate::service::Pep;
use crate::sync::Sync;

/// A timer that backs off while the PDP refuses: each failed round doubles
/// the wait up to the cap, the first success puts it back. A round never
/// overlaps itself. The interval and the cap are asked before EVERY wait
/// (`intervals`), so a setting the service changes (#1760) takes effect
/// from the next round.
fn on_backoff<F, I>(label: &'static str, intervals: I, work: F)
where
    F: Fn() -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + 'static,
    I: Fn() -> (u64, u64) + Send + 'static,
{
    tokio::spawn(async move {
        let mut failures: u32 = 0;
        loop {
            let (base_ms, cap_ms) = intervals();
            let ceiling = base_ms.max(cap_ms);
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
                        intervals().0
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
            tag("STS-XPEP-0033"),
            count,
            signature
        );
    }));
}

async fn serve_http(pep: Arc<Pep>, port: u16, status: Arc<PlainStatus>) {
    let listener = match TcpListener::bind(("0.0.0.0", port)).await {
        Ok(listener) => {
            status.set("listening", "none");
            listener
        }
        Err(error) => {
            tracing::error!(
                "{}xacml-pep: could not start: cannot listen on \
                             {}: {}",
                tag("STS-XPEP-0013"),
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
            let service = tower_service(pep, Transport::default());
            let served = Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await;
            if let Err(error) = served {
                tracing::debug!("connection ended: {}", error);
            }
        });
    }
}

/// The one handler, with what is known about the connection — the
/// transport, and on HTTPS the caller's certificate (#1179) — put on every
/// request it carries.
fn tower_service(
    pep: Arc<Pep>,
    transport: Transport,
) -> TowerToHyperService<axum::routing::Router> {
    let router = axum::Router::new().fallback(
        move |mut request: axum::http::Request<axum::body::Body>| {
            let pep = pep.clone();
            request.extensions_mut().insert(transport.clone());
            async move { pep.handle(request).await }
        },
    );
    TowerToHyperService::new(router)
}

/// The HTTPS listener: started the first time a usable pair appears, and
/// each connection handed the pair being served at that moment.
async fn serve_https(pep: Arc<Pep>, https: Arc<HttpsListener>) {
    let listener = match TcpListener::bind(("0.0.0.0", https.port())).await {
        Ok(listener) => listener,
        Err(error) => {
            https.mark_bind_failed_for(&error);
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
            let transport = Transport {
                https: true,
                peer: peer_of(tls.ssl()),
                remote: None,
            };
            let served = Builder::new(TokioExecutor::new())
                .serve_connection(
                    TokioIo::new(tls),
                    tower_service(pep, transport),
                )
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
        "xacml-pep: version {} ({}built {}{}, {}). The release is the \
         service's own; the build number is this image's.",
        info.version,
        if info.release {
            "a RELEASE build, "
        } else {
            ""
        },
        info.built_at,
        if info.commit.is_empty() {
            String::new()
        } else {
            format!(", commit {}", info.commit)
        },
        if info.stamped {
            "stamped at image build time"
        } else {
            "COMPUTED AT STARTUP — this is not a built image, so the build \
             time is when this process started"
        }
    );
    tracing::info!(
        "xacml-pep: starting. PDP={} name={} bias={}",
        options.pdp_url,
        options.name,
        options.now().bias.as_str()
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
                tag("STS-XPEP-0013"),
                error
            );
            std::process::exit(1);
        }
    };
    let sync = Arc::new(Sync::new(client.clone(), options.clone()));
    let proxy_client = client.clone();
    let pip = RemotePip::new(client, options.pip_enabled)
        .governed_by(options.clone());
    let https = Arc::new(HttpsListener::new(
        &options.https_cert_path,
        &options.https_key_path,
        options.https_port,
        options.https_reload_interval_ms,
        options.authzen_client_ca.as_deref(),
    ));
    let pep = Arc::new(Pep::new(
        options.clone(),
        info,
        sync.clone(),
        pip,
        https.clone(),
    ));

    // The reverse proxy (#1760) is built here so the poll can reconcile
    // its relying parties after every pull; its listeners start below.
    let proxy = options
        .proxy_enabled
        .then(|| Arc::new(Proxy::new(pep.clone(), proxy_client.clone())));

    // EVERY LISTENER (#1760): the environment's four, registered as each is
    // made below, and the ones the service defines, bound after each pull.
    let api_pep = pep.clone();
    let proxy_make = proxy.clone().map(|proxy| {
        Arc::new(move |transport: Transport| {
            proxy::tower_service(proxy.clone(), transport)
        }) as listeners::MakeService
    });
    let listener_set = Arc::new(ListenerSet::new(
        &options.name,
        Arc::new(move |transport: Transport| {
            tower_service(api_pep.clone(), transport)
        }),
        proxy_make,
        options.authzen_client_ca.clone(),
        listeners::certify_with(proxy_client),
    ));
    let api_http = Arc::new(PlainStatus::default());
    listener_set.environment("api-http", options.port,
                             EnvKind::Plain(api_http.clone()));
    listener_set.environment("api-https", options.https_port,
                             EnvKind::Tls(https.clone()));
    let reporting = listener_set.clone();
    sync.set_listeners_reporter(Arc::new(move || reporting.report()));

    // REGISTER FIRST, PULL REGARDLESS — and both retried on the poll timer.
    sync.register().await;
    sync.pull("start").await;
    {
        let (set, defs) = (listener_set.clone(), sync.listener_definitions());
        tokio::spawn(async move { set.apply(&defs).await });
    }
    if let Some(proxy) = proxy.clone() {
        // Off the start: building a relying party asks the service for its
        // discovery document, and the PEP decides without it.
        tokio::spawn(async move { proxy.reconcile().await });
    }

    let poll_sync = sync.clone();
    let poll_proxy = proxy.clone();
    let poll_listeners = listener_set.clone();
    let poll_options = options.clone();
    on_backoff(
        "the poll",
        move || {
            let now = poll_options.now();
            (now.poll_interval_ms, now.backoff_max_ms)
        },
        move || {
            let sync = poll_sync.clone();
            let proxy = poll_proxy.clone();
            let listeners = poll_listeners.clone();
            Box::pin(async move {
                sync.register_if_needed().await;
                let ok = sync.pull("poll").await;
                listeners.apply(&sync.listener_definitions()).await;
                if let Some(proxy) = proxy {
                    proxy.reconcile().await;
                }
                ok
            })
        },
    );
    let beat_sync = sync.clone();
    let beat_options = options.clone();
    on_backoff(
        "the heartbeat",
        move || {
            let now = beat_options.now();
            (now.heartbeat_interval_ms, now.backoff_max_ms)
        },
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
        let reload_options = options.clone();
        tokio::spawn(async move {
            loop {
                if watcher.reload() {
                    tokio::spawn(serve_https(served.clone(), watcher.clone()));
                }
                tokio::time::sleep(reload_interval(&reload_options)).await;
            }
        });
    }
    if options.now().authzen {
        tracing::info!(
            "xacml-pep: the AuthZEN edge PDP answers POST {} and {} on the \
             HTTPS listener, to the callers pulled from the PDP ({}) \
             presenting a certificate that verifies against \
             PEP_AUTHZEN_CLIENT_CA{}.",
            authzen::EVALUATION_PATH,
            authzen::EVALUATIONS_PATH,
            if options.authzen_callers_configured {
                format!(
                    "narrowed to the {} certificate(s) of \
                     PEP_AUTHZEN_CALLERS, which decides alone until the \
                     first pull",
                    options.authzen_callers.len()
                )
            } else {
                "PEP_AUTHZEN_CALLERS is not set; nothing is answered until \
                 the first pull"
                    .to_string()
            },
            if https.asks_for_client_certificates() {
                ""
            } else {
                " — which is not set, so nobody is admitted"
            }
        );
    }
    if let Some(proxy) = proxy {
        // THE REVERSE PROXY (#1760), on ports of its own: every endpoint
        // above is untouched by it. It answers 404 to everything until the
        // service sends a configuration for this PEP.
        let proxy_http = Arc::new(PlainStatus::default());
        listener_set.environment("proxy-http", options.proxy_port,
                                 EnvKind::Plain(proxy_http.clone()));
        let (plain, port) = (proxy.clone(), options.proxy_port);
        tokio::spawn(async move {
            match TcpListener::bind(("0.0.0.0", port)).await {
                Ok(socket) => {
                    proxy_http.set("listening", "none");
                    proxy::serve_on(plain, socket).await;
                }
                Err(error) => {
                    proxy_http.set("failed", listener::bind_reason(&error));
                    tracing::error!(
                        "{}xacml-pep: the reverse proxy could not listen on                          {}: {}. The PEP's own endpoints and enforcement                          are unaffected.",
                        tag("STS-XPEP-0063"),
                        port,
                        error
                    );
                }
            }
        });
        let proxy_https = Arc::new(HttpsListener::for_proxy(
            &options.https_cert_path,
            &options.https_key_path,
            options.proxy_https_port,
            options.https_reload_interval_ms,
        ));
        listener_set.environment("proxy-https", options.proxy_https_port,
                                 EnvKind::Tls(proxy_https.clone()));
        if proxy_https.is_configured() {
            let reload_options = options.clone();
            tokio::spawn(async move {
                loop {
                    if proxy_https.reload() {
                        tokio::spawn(proxy::serve_https(
                            proxy.clone(),
                            proxy_https.clone(),
                        ));
                    }
                    tokio::time::sleep(reload_interval(&reload_options))
                        .await;
                }
            });
        }
        tracing::info!(
            "xacml-pep: the reverse proxy answers on {} (plain) and {} \
             (HTTPS, with the pair 9443 serves), over the route table the \
             service sends for this PEP; deny by default.",
            options.proxy_port,
            options.proxy_https_port
        );
    }
    if !options.proxy_enabled {
        listener_set.environment("proxy-http", options.proxy_port,
                                 EnvKind::Off("proxy-off"));
        listener_set.environment("proxy-https", options.proxy_https_port,
                                 EnvKind::Off("proxy-off"));
    }
    install_fault_handler();
    serve_http(pep, options.port, api_http).await;
}

/// How long the HTTPS listeners wait before re-reading their pair: the
/// setting in force, so the service may change it (#1760).
fn reload_interval(options: &Options) -> Duration {
    Duration::from_millis(options.now().https_reload_interval_ms.max(100))
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
        // A release flag without a valid BUILD_NUMBER is refused (#1317):
        // the message names both variables, and the non-zero exit fails the
        // image build at its `RUN`, as `common/version.js --stamp` does.
        match version::stamp(Path::new(dir)) {
            Ok(info) => println!(
                "{}",
                serde_json::to_string_pretty(&info).unwrap_or_default()
            ),
            Err(refusal) => {
                eprintln!("{}", refusal);
                std::process::exit(1);
            }
        }
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
                tag("STS-XPEP-0013"),
                error
            );
            std::process::exit(1);
        }
    };
    runtime.block_on(start(options, info));
}
