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
//! or curl in it): it asks `GET /healthcheck` and exits 0 on a 200 — on
//! `PEP_PORT` in plain HTTP when `PEP_HTTP=true`, and otherwise (the
//! default since #1760, which turned plain HTTP off) over HTTPS on
//! `PEP_HTTPS_PORT`, not verifying the certificate: it is the process's
//! own loopback, and liveness is the question, not who answers.

mod audit;
mod authzen;
mod authzen_catalogue;
mod authzen_map;
mod enforce;
mod identity;
mod jwt;
mod listener;
mod listener_pool;
mod listener_tuning;
mod listeners;
mod options;
mod pdp_client;
mod pip;
mod proxy;
mod proxy_auth;
mod proxy_config;
mod proxy_page;
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

use hyper_util::service::TowerToHyperService;
use sts_core::log::{self, tag};
use sts_core::version;
use tokio::net::TcpListener;

use crate::listener::{peer_of, HttpsListener, Transport};
use crate::listener_pool::{drive, ListenerRuntime};
use crate::listeners::{plain_kind, EnvKind, ListenerSet, PlainStatus};
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

async fn serve_http(
    pep: Arc<Pep>,
    port: u16,
    status: Arc<PlainStatus>,
    crl_only: bool,
    runtime: ListenerRuntime,
) {
    let listener = match TcpListener::bind(("0.0.0.0", port)).await {
        Ok(listener) => {
            status.set("listening", if crl_only { "crl-only" } else { "none" });
            listener
        }
        Err(error) if crl_only => {
            // THE CRL POINT IS AUXILIARY: a PEP that cannot bind it still
            // enforces, so this is a failed listener on the tab, not an
            // exit. The service will fail to fetch the CRL and say so.
            tracing::error!(
                "{}xacml-pep: the CRL-only plain-HTTP listener cannot listen \
                 on {}: {}. The service cannot fetch this PEP's \
                 credential's CRLs from it.",
                tag("STS-XPEP-0013"),
                port,
                error
            );
            status.set("failed", "other");
            return;
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
    if crl_only {
        tracing::info!(
            "xacml-pep: listening on {} in plain HTTP for GET /crl/<name> \
             ONLY — this PEP's credential's CRLs, which the service fetches \
             in the clear as RFC 5280 expects. PEP_CRL_HTTP=false turns it \
             off; PEP_HTTP=true serves the whole decision API here instead.",
            port
        );
    } else {
        tracing::info!(
            "xacml-pep: listening on {}. The protected resource is \
                        GET /protected.",
            port
        );
    }
    runtime.start();
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let pep = pep.clone();
        let job = runtime.clone();
        runtime.hand_off(stream, move |stream| async move {
            let transport = Transport {
                crl_only,
                ..Transport::default()
            };
            let service = tower_service(pep, transport);
            let cfg = job.http();
            drive(stream, service, cfg, false, job).await;
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
    let router = axum::Router::new()
        .fallback(move |mut request: axum::http::Request<axum::body::Body>| {
            let pep = pep.clone();
            request.extensions_mut().insert(transport.clone());
            async move { pep.handle(request).await }
        })
        .layer(axum::middleware::from_fn(crate::listener_pool::observe));
    TowerToHyperService::new(router)
}

/// The HTTPS listener: started the first time a usable pair appears, and
/// each connection handed the pair being served at that moment.
async fn serve_https(
    pep: Arc<Pep>,
    https: Arc<HttpsListener>,
    runtime: ListenerRuntime,
) {
    let listener = match TcpListener::bind(("0.0.0.0", https.port())).await {
        Ok(listener) => listener,
        Err(error) => {
            https.mark_bind_failed_for(&error);
            return;
        }
    };
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    https.mark_listening(port);
    runtime.start();
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let Some(acceptor) = https.current() else {
            continue;
        };
        let pep = pep.clone();
        let job = runtime.clone();
        runtime.hand_off(stream, move |stream| async move {
            let Some(tls) =
                HttpsListener::accept_tls(stream, &acceptor, &job).await
            else {
                return;
            };
            let alpn_h2 = tls.ssl().selected_alpn_protocol() == Some(b"h2");
            let cfg = job.http();
            // HttpCfg is moved into drive, so the ALPN decision is taken
            // before that move.
            let offer_h2 = cfg.http2 && alpn_h2;
            let transport = Transport {
                https: true,
                peer: peer_of(tls.ssl()),
                remote: None,
                crl_only: false,
            };
            drive(tls, tower_service(pep, transport), cfg, offer_h2, job).await;
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
    let audit = pep.audit.clone();

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
    // PLAIN HTTP IS OFF BY DEFAULT (#1760): reported `off`/`http-off` so
    // the console can say how to turn it on (`options::plain_http`).
    let api_http = Arc::new(PlainStatus::default());
    options.http.announce("decision API", options.port);
    // THE CRL POINT STAYS REACHABLE WITH HTTP OFF (2026-11-14): a client
    // credential minted with `--crl-base=http://<pep>:9090/crl` names this
    // port, and the service fetches it under hard-fail in product, so with
    // the API's plain HTTP off by default the PEP could no longer
    // authenticate. The port serves the CRLs alone (`crl_listener`).
    let crl_only = options::crl_listener(&options);
    listener_set.environment(
        "api-http",
        options.port,
        if crl_only {
            EnvKind::Crl(api_http.clone())
        } else {
            plain_kind(options.http.on, api_http.clone())
        },
    );
    listener_set.environment(
        "api-https",
        options.https_port,
        EnvKind::Tls(https.clone()),
    );
    let reporting = listener_set.clone();
    sync.set_listeners_reporter(Arc::new(move || reporting.report()));

    // THE PAIR IS READ ONCE BEFORE THE REGISTRATION (2026-11-14), so a
    // notify URL derived from the certificate it serves goes out on the
    // registration rather than a heartbeat later (`refresh_derived_notify`).
    // The reload loop below goes on from there.
    let https_first = https.is_configured() && https.reload();
    options.refresh_derived_notify(https.dns_names().as_deref());

    // REGISTER FIRST, PULL REGARDLESS — and both retried on the poll timer.
    sync.register().await;
    sync.pull("start").await;
    {
        let (set, defs, env) = (
            listener_set.clone(),
            sync.listener_definitions(),
            sync.environment_tuning(),
        );
        tokio::spawn(async move { set.apply(&defs, &env).await });
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
                listeners
                    .apply(
                        &sync.listener_definitions(),
                        &sync.environment_tuning(),
                    )
                    .await;
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

    // THE DECISION RECORDS (#1827): on their own fixed interval — the
    // queue, not the timer, is what holds them while the service refuses,
    // so there is nothing to back off from. ALWAYS STARTED, because
    // `auditEnabled` is a managed setting (#1760) that may be switched on
    // while this runs; switched off, nothing new is queued, and what is
    // already queued is still sent.
    tracing::info!(
        "xacml-pep: decision records {} to POST {}{} every {}ms, with a \
         token from {}{} (client {}).",
        if audit.enabled() {
            "are sent"
        } else {
            "are NOT queued (auditEnabled / PEP_AUDIT is false) but would be \
             sent"
        },
        options.pdp_url.trim_end_matches('/'),
        audit::AUDIT_PATH,
        audit.interval_ms(),
        options.pdp_url.trim_end_matches('/'),
        audit::TOKEN_PATH,
        options.audit_client_id
    );
    let (shipper, client) = (audit.clone(), sync.client().clone());
    let timer = audit.clone();
    on_backoff(
        "sending the decision records",
        move || {
            let every = timer.interval_ms();
            (every, every)
        },
        move || {
            let (audit, client) = (shipper.clone(), client.clone());
            Box::pin(async move { audit.ship(&client).await })
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
        let reload_sync = sync.clone();
        let https_runtime = listener_set
            .runtime_of("api-https")
            .unwrap_or_else(|| ListenerRuntime::new("api-https", "api", true));
        if https_first {
            tokio::spawn(serve_https(
                served.clone(),
                watcher.clone(),
                https_runtime.clone(),
            ));
        }
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(reload_interval(&reload_options)).await;
                if watcher.reload() {
                    tokio::spawn(serve_https(
                        served.clone(),
                        watcher.clone(),
                        https_runtime.clone(),
                    ));
                }
                // A NEW CERTIFICATE MAY NAME ANOTHER HOST: derive the notify
                // URL again, and when the one in force changed, tell the
                // service now rather than at the next heartbeat.
                let before = reload_options.now().notify_url;
                if reload_options
                    .refresh_derived_notify(watcher.dns_names().as_deref())
                    && reload_options.now().notify_url != before
                {
                    let sync = reload_sync.clone();
                    tokio::spawn(async move {
                        sync.heartbeat().await;
                    });
                }
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
        options
            .proxy_http
            .announce("reverse proxy", options.proxy_port);
        listener_set.environment(
            "proxy-http",
            options.proxy_port,
            plain_kind(options.proxy_http.on, proxy_http.clone()),
        );
        let (plain, port) = (proxy.clone(), options.proxy_port);
        let bind_plain = options.proxy_http.on;
        let proxy_http_runtime =
            listener_set.runtime_of("proxy-http").unwrap_or_else(|| {
                ListenerRuntime::new("proxy-http", "proxy", false)
            });
        tokio::spawn(async move {
            if !bind_plain {
                return;
            }
            match TcpListener::bind(("0.0.0.0", port)).await {
                Ok(socket) => {
                    proxy_http.set("listening", "none");
                    proxy::serve_on(plain, socket, proxy_http_runtime).await;
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
        listener_set.environment(
            "proxy-https",
            options.proxy_https_port,
            EnvKind::Tls(proxy_https.clone()),
        );
        if proxy_https.is_configured() {
            let reload_options = options.clone();
            let proxy_https_runtime =
                listener_set.runtime_of("proxy-https").unwrap_or_else(|| {
                    ListenerRuntime::new("proxy-https", "proxy", true)
                });
            tokio::spawn(async move {
                loop {
                    if proxy_https.reload() {
                        tokio::spawn(proxy::serve_https(
                            proxy.clone(),
                            proxy_https.clone(),
                            proxy_https_runtime.clone(),
                        ));
                    }
                    tokio::time::sleep(reload_interval(&reload_options)).await;
                }
            });
        }
        tracing::info!(
            "xacml-pep: the reverse proxy answers on {} (HTTPS, with the \
             pair 9443 serves){}, over the route table the service sends \
             for this PEP; deny by default.",
            options.proxy_https_port,
            if options.proxy_http.on {
                format!(" and {} (plain)", options.proxy_port)
            } else {
                String::new()
            }
        );
    }
    if !options.proxy_enabled {
        listener_set.environment(
            "proxy-http",
            options.proxy_port,
            EnvKind::Off("proxy-off"),
        );
        listener_set.environment(
            "proxy-https",
            options.proxy_https_port,
            EnvKind::Off("proxy-off"),
        );
    }
    install_fault_handler();
    if options.http.on || crl_only {
        let api_http_runtime = listener_set
            .runtime_of("api-http")
            .unwrap_or_else(|| ListenerRuntime::new("api-http", "api", false));
        serve_http(pep, options.port, api_http, crl_only, api_http_runtime)
            .await;
        std::future::pending::<()>().await;
    } else {
        // Nothing left to await but the tasks above: the process lives as
        // long as they do, and a signal ends it as before.
        std::future::pending::<()>().await;
    }
}

/// How long the HTTPS listeners wait before re-reading their pair: the
/// setting in force, so the service may change it (#1760).
fn reload_interval(options: &Options) -> Duration {
    Duration::from_millis(options.now().https_reload_interval_ms.max(100))
}

/// The image's HEALTHCHECK: liveness only, as `/healthcheck` itself is.
/// Plain HTTP when `PEP_HTTP=true`, else HTTPS (the module header).
fn healthcheck() -> i32 {
    let (http, _) = options::plain_http(
        std::env::var("PEP_HTTP").ok().as_deref(),
        std::env::var("PEP_PORT").ok().as_deref(),
    );
    let (var, fallback) = probe_port(http);
    let port = std::env::var(var).unwrap_or_else(|_| fallback.into());
    let address = format!("127.0.0.1:{}", port.trim());
    let Ok(stream) = std::net::TcpStream::connect(&address) else {
        return 1;
    };
    let timeout = Some(Duration::from_secs(4));
    if stream.set_read_timeout(timeout).is_err()
        || stream.set_write_timeout(timeout).is_err()
    {
        return 1;
    }
    let answer = if http {
        ask_healthcheck(stream)
    } else {
        let Ok(mut connector) =
            openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())
        else {
            return 1;
        };
        // The process's own loopback: liveness, not identity.
        connector.set_verify(openssl::ssl::SslVerifyMode::NONE);
        match connector.build().connect("localhost", stream) {
            Ok(tls) => ask_healthcheck(tls),
            Err(_) => None,
        }
    };
    healthy(answer.as_deref())
}

/// Which port the healthcheck asks, by its variable and default: plain
/// HTTP's only when it is switched on.
fn probe_port(http: bool) -> (&'static str, &'static str) {
    if http {
        ("PEP_PORT", "9090")
    } else {
        ("PEP_HTTPS_PORT", "9443")
    }
}

/// `GET /healthcheck` over a connected stream, plain or TLS.
fn ask_healthcheck<S: std::io::Read + std::io::Write>(
    mut stream: S,
) -> Option<String> {
    stream
        .write_all(
            b"GET /healthcheck HTTP/1.1\r\nHost: localhost\r\n\
                     Connection: close\r\n\r\n",
        )
        .ok()?;
    let mut answer = String::new();
    if stream.read_to_string(&mut answer).is_err() && answer.is_empty() {
        return None;
    }
    Some(answer)
}

/// 0 for a 200, 1 for anything else or nothing.
fn healthy(answer: Option<&str>) -> i32 {
    match answer {
        Some(text) if text.starts_with("HTTP/1.1 200") => 0,
        _ => 1,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_healthcheck_asks_https_unless_plain_http_is_on() {
        assert_eq!(probe_port(false), ("PEP_HTTPS_PORT", "9443"));
        assert_eq!(probe_port(true), ("PEP_PORT", "9090"));
        assert_eq!(healthy(Some("HTTP/1.1 200 OK\r\n")), 0);
        assert_eq!(healthy(Some("HTTP/1.1 503 x\r\n")), 1);
        assert_eq!(healthy(None), 1);
    }
}
