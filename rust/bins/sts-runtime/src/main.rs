// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `sts-runtime`: the Rust runtime of iya-sts (#444, rust/DESIGN.md) —
//! `server.js`'s shell.
//!
//! THE ORDER IS `server.js`'s, and each step says what in Node it is:
//!
//! 1. the logger, then the appconfig layer `CONFIG_FILE` names (`env/*.json`,
//!    the data Node's `env/*.js` hold; a `.js` path is read as the `.json`
//!    beside it) over the compiled defaults (`common/config_file.js`);
//! 2. what `tls/tls_server.js` checks at REQUIRE time, each fatal: the TLS
//!    policy's write rules over the values the process was given
//!    (`checkProtocolOptions()`, `STS-TLS-0042`) and the client truststore's
//!    anchors file (`loadAnchorsFile()`, `STS-TLS-0019`/`0020`); the rule is
//!    installed on the settings for every later write
//!    (`config.addWriteRule(policyWriteRule)`);
//! 3. the composition root (`stack.rs`, `common/protocol_stack.ts`), and
//!    `persistence.start()` — **the one place where failing to open
//!    something stops the process** (`STS-CORE-0036`), before any listener
//!    binds (root `CLAUDE.md`, *Socket owners start their listeners from
//!    `listen()`*);
//! 4. the listener certificate, settled and certified as `pki.start()`
//!    does before `listen()` (`certificates.rs`), and every listener's
//!    policy shown to BUILD a context (`STS-TLS-0001`, `STS-TLS-0045`);
//! 5. the custom listeners' definitions, judged as a write would be
//!    (`STS-CORE-0157`, fatal);
//! 6. `bind()`: the main port, HTTPS when `global.https` is on (which
//!    `oauth2.rfc9700` turns on by default, `STS_HTTPS=false` the way back)
//!    — the main port failing to bind stops the process, as node's
//!    unhandled `EADDRINUSE` does; then every custom listener, each failure
//!    RECORDED (`STS-TLS-0039`) and never thrown;
//! 7. `listen()`'s socket owners — the KDC, LDAP, SPIFFE, the revocation
//!    listener, the cell channel and the debugger — whose binding failures
//!    are recorded rather than thrown, each when its phase ports it
//!    ([`SocketOwners`]);
//! 8. on SIGTERM or Ctrl-C, what is pending is written and the store closed.
//!
//! WHAT IS WIRED, AND WHAT IS A SEAM. The store, the scheduler (with this
//! module's `tls.listener-renew` job) and the HTTP layer are the phase-3
//! crates as they stand on `feature/444`. The settings' change notification
//! (`config.onOverridesChanged()`, the `config` slice) is to call
//! `Listeners::reapply(true)`; the truststore doors (`/admin-api/tls/trust`,
//! phase 4) call `Truststore::add`/`remove` and then `reapply(false)`; a
//! rebuilt hierarchy (`build-root`, phase 6) replaces `Listeners::material`
//! and calls `reapply(false)` — the front-process reconcile, with no worker
//! to tell.

#![forbid(unsafe_code)]

mod certificates;
mod listener;
mod listeners;
mod solo;
mod stack;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use serde_json::Value as Json;
use sts_core::errors::codes;
use sts_core::log::{self, tag};
use sts_core::settings::Settings;
use sts_tls::policy::{
    policy_for, ListenerKind, PolicyWriteRule, STARTUP_KINDS,
};
use sts_tls::truststore::{listener_file_anchors, Truststore};
use sts_tls::ConnectionFacts;
use tokio::net::TcpListener;
use tower::ServiceExt;

use crate::listener::TlsListener;
use crate::listeners::{certificate_for, Listeners};
use crate::stack::Stack;

/// The appconfig file `CONFIG_FILE` names, as JSON; `Null` when unset.
fn appconfig() -> Result<(Json, Option<PathBuf>), String> {
    let Ok(named) = std::env::var("CONFIG_FILE") else {
        return Ok((Json::Null, None));
    };
    let mut path = PathBuf::from(&named);
    if path.extension().is_some_and(|e| e == "js") {
        path.set_extension("json");
    }
    let text = std::fs::read_to_string(&path).map_err(|e| {
        format!(
            "CONFIG_FILE is \"{}\" and {} could not be read: {}",
            named,
            path.display(),
            e
        )
    })?;
    let parsed = serde_json::from_str(&text)
        .map_err(|e| format!("{} is not JSON: {}", path.display(), e))?;
    Ok((parsed, Some(path)))
}

/// A start that cannot go on: the code, Node's sentence, exit 1.
fn fatal(code: sts_core::errors::ErrorCode, message: &str) -> ! {
    tracing::error!("{}{}", tag(code), message);
    std::process::exit(1);
}

/// The sockets other families own (`krb5.listen()`, `ldapServer.listen()`,
/// `spiffeServer.listen()`, `pki_service.listen()`, `cell_channel.listen()`,
/// `debuggerServer.listen()`): each binds from here, AFTER the main port,
/// and a failure is recorded on the family's own view and logged under its
/// code — never thrown. None is ported yet; a family registers here when
/// its phase lands (DESIGN 4.2's `ProtocolFamily::listeners()`).
#[derive(Default)]
struct SocketOwners;

impl SocketOwners {
    #[tracing::instrument(level = "debug", skip_all)]
    async fn listen(&self, _listeners: &Arc<Listeners>) {
        tracing::debug!(
            "runtime: no family socket is ported yet (KDC 88, LDAP 389/636, SPIFFE, the revocation \
             listener, the cell channel, the debugger)."
        );
    }
}

/// A plain-HTTP listener: the main port with `global.https` off.
async fn serve_plain(tcp: TcpListener, router: axum::Router) {
    loop {
        let Ok((stream, peer)) = tcp.accept().await else {
            continue;
        };
        let router = router.clone();
        let local = stream.local_addr().ok();
        tokio::spawn(async move {
            let facts = ConnectionFacts {
                listener: sts_tls::definitions::MAIN.to_string(),
                realm_listener: None,
                peer: Some(peer),
                local,
                tls: None,
            };
            let service = hyper::service::service_fn(
                move |mut request: hyper::Request<hyper::body::Incoming>| {
                    request.extensions_mut().insert(facts.clone());
                    router.clone().oneshot(request.map(axum::body::Body::new))
                },
            );
            if let Err(e) = Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                tracing::debug!("runtime: a connection ended: {}", e);
            }
        });
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let Ok(mut term) = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        ) else {
            let _ignored = tokio::signal::ctrl_c().await.is_ok();
            return;
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ignored = tokio::signal::ctrl_c().await.is_ok();
    }
}

/// Step 2: what `tls_server.js` checks when it is required.
fn tls_at_require(settings: &Arc<Settings>, truststore: &Truststore) {
    PolicyWriteRule::install(settings);
    if let Some(problem) = sts_tls::policy::startup_problem(settings) {
        fatal(problem.code, &problem.message);
    }
    if let Err(problem) =
        truststore.load_file(settings.value_of("tls.trustAnchorsFile").as_str())
    {
        fatal(problem.code, &problem.message);
    }
}

/// Step 4's second half: every listener's own policy builds a context —
/// after the service-wide one, so an inherited bad value is named by its
/// service-wide setting — including its TLS 1.2 list while TLS 1.2 is off,
/// and every own anchors file reads (`checkProtocolOptions()`).
fn check_every_policy(settings: &Settings, listeners: &Listeners) {
    let certificates = listeners
        .material
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .certificates
        .clone();
    let mut kinds = vec![ListenerKind::Process];
    kinds.extend(STARTUP_KINDS.iter().cloned());
    for kind in kinds {
        let policy = policy_for(settings, &kind);
        let mut with_tls12 = policy.clone();
        with_tls12.disable_tls12 = false;
        with_tls12.pqc_only = false;
        for p in [&policy, &with_tls12] {
            if let Err(e) = listener::build_context(
                kind.name(),
                p,
                &certificates,
                &[],
                true,
            ) {
                let message = if kind == ListenerKind::Process {
                    format!(
                        "tls: NOT STARTING. tls.minVersion / tls.ciphers / tls.tls13CipherSuites / tls.groups / \
                         tls.signatureAlgorithms (STS_TLS_MIN_VERSION / STS_TLS_CIPHERS / \
                         STS_TLS_TLS13_CIPHER_SUITES / STS_TLS_GROUPS / STS_TLS_SIGALGS) cannot build a TLS \
                         context: {}. An OpenSSL cipher list names suites such as ECDHE-RSA-AES256-GCM-SHA384, \
                         a groups list names groups such as X25519MLKEM768:P-256, a signature list schemes \
                         such as rsa_pss_rsae_sha256, and an empty one means node's default.",
                        e
                    )
                } else {
                    let n = kind.name();
                    format!(
                        "tls: NOT STARTING. The {} listener's own TLS settings (listener{}{}.*) cannot build \
                         a TLS context: {}.",
                        n,
                        n[..1].to_ascii_uppercase(),
                        &n[1..],
                        e.trim_end_matches('.')
                    )
                };
                fatal(codes::STS_TLS_0001, &message);
            }
        }
        if !policy.trust_anchors_file.is_empty()
            && listener_file_anchors(&policy.trust_anchors_file).is_empty()
        {
            fatal(
                codes::STS_TLS_0045,
                &format!(
                    "tls: NOT STARTING. The {} listener's own trustAnchorsFile is \"{}\" and it could not be \
                     read or holds no -----BEGIN CERTIFICATE----- block, so that listener's client truststore \
                     would be empty while configured to be filled.",
                    kind.name(),
                    policy.trust_anchors_file
                ),
            );
        }
    }
}

/// The `tls.listener-renew` job (`tls/listeners.js`' `registerJob()`):
/// per process, hourly, quiet.
fn register_renew_job(
    stack: &Stack,
    listeners: &Arc<Listeners>,
) -> Result<(), String> {
    let mut job = sts_cluster::schedule::JobSpec::new(
        "tls.listener-renew",
        "Custom listener certificate renewal",
        "Re-issues the certificate a custom listener presents (#472, a realm's own among them) once two \
         thirds of its life are gone, from its owning realm's certificate authority, and applies it without \
         closing the listener. An operator's certificate (the definition's certificateFile) is the \
         operator's to renew.",
        "tls/listeners.js",
        sts_cluster::schedule::Schedule::Every(Arc::new(|| 3600.0 * 1000.0)),
    );
    job.kind = sts_cluster::schedule::Kind::PerProcess;
    job.quiet = true;
    let watched = Arc::downgrade(listeners);
    job.off = Some(Arc::new(move |_realm: &str| {
        Ok(match watched.upgrade() {
            Some(l) if l.has_custom() => String::new(),
            _ => "no custom listener is bound on this process".to_string(),
        })
    }));
    let owner = Arc::downgrade(listeners);
    job.run = Some(Arc::new(move |_ctx| {
        let owner = owner.clone();
        Box::pin(async move {
            let n = owner.upgrade().map_or(0, |l| l.renew_due());
            Ok(serde_json::json!({ "summary": format!("{} renewed", n) }))
        })
    }));
    stack.scheduler.register(job)
}

async fn run(settings: Arc<Settings>) -> Result<(), String> {
    // 2.
    let truststore = Arc::new(Truststore::default());
    tls_at_require(&settings, &truststore);
    // 3.
    let stack = Arc::new(Stack::build(settings.clone())?);
    if let Err(e) = stack.start().await {
        fatal(
            codes::STS_CORE_0036,
            &format!(
                "sts: NOT STARTING. {}\n\nThis service is configured to persist (persistence.mode={}), so it \
                 will not run without its store.",
                e,
                settings.value_of("persistence.mode").as_str()
            ),
        );
    }
    // 4.
    let material = match certificates::settle(&settings) {
        Ok(m) => m,
        Err(p) => fatal(p.code, &p.message),
    };
    let listeners = Listeners::new(settings.clone(), material, truststore);
    check_every_policy(&settings, &listeners);
    // 5.
    let custom = match sts_tls::definitions::service_listeners(&settings) {
        Ok(list) => list,
        Err(p) => fatal(
            codes::STS_CORE_0157,
            &format!(
                "sts: NOT STARTING. The custom listeners and their applications this process was given are \
                 refused: {} ({}).",
                p.message,
                p.code.as_str()
            ),
        ),
    };
    register_renew_job(&stack, &listeners)?;
    // 6.
    let host = settings.value_of("global.host").as_str().to_string();
    let host = if host.is_empty() {
        "0.0.0.0".to_string()
    } else {
        host
    };
    let port = settings.value_of("global.port").as_int();
    let https = settings.value_of("global.https").as_bool();
    let bind = format!("{}:{}", host, port);
    let router = stack.router();
    let mut tasks = tokio::task::JoinSet::new();
    let label = format!("the main port ({})", port);
    if https {
        let applied =
            listeners.context_for(&label, &ListenerKind::Main, None)?;
        let main = TlsListener::new(
            sts_tls::definitions::MAIN,
            &label,
            u16::try_from(port).unwrap_or(0),
            applied,
            listeners::http2_for(&settings, &ListenerKind::Main),
        );
        let tcp = match main.bind(&bind).await {
            Ok(tcp) => tcp,
            Err(why) => {
                fatal(codes::STS_CORE_0093, &format!("runtime: {}", why))
            }
        };
        listeners.register(main.clone(), ListenerKind::Main, None);
        tasks.spawn(main.serve(tcp, router.clone()));
    } else {
        let tcp = TcpListener::bind(&bind).await.map_err(|e| {
            format!(
                "{}runtime: could not bind {}: {}",
                tag(codes::STS_CORE_0093),
                bind,
                e
            )
        })?;
        tasks.spawn(serve_plain(tcp, router.clone()));
    }
    tracing::info!(
        "WS-Trust STS listening on {}://{}:{} (mode {}). The listener certificate is {}.",
        if https { "https" } else { "http" },
        host,
        port,
        stack.mode.current(),
        listeners
            .material
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .provenance()
    );
    // A custom listener is HTTPS whatever the main port is (#472).
    for one in custom {
        let kind = ListenerKind::Custom {
            id: one.id.clone(),
            tls: one.tls.clone(),
            client_auth: one.client_auth.clone(),
        };
        let label = format!("listener \"{}\" ({})", one.id, one.port);
        let certificate = {
            let material = listeners
                .material
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            certificate_for(&material, &one)
        };
        let certificate = match certificate {
            Ok(c) => vec![c],
            Err(why) => {
                tracing::warn!(
                    "{}tls: listener \"{}\" has no certificate to present: {}.",
                    tag(codes::STS_TLS_0040),
                    one.id,
                    why
                );
                continue;
            }
        };
        let applied =
            match listeners.context_for(&label, &kind, Some(&certificate)) {
                Ok(a) => a,
                Err(why) => {
                    tracing::warn!(
                        "{}tls: {} could not be built: {}",
                        tag(codes::STS_TLS_0039),
                        label,
                        why
                    );
                    continue;
                }
            };
        let l = TlsListener::new(
            &one.id,
            &label,
            one.port,
            applied,
            listeners::http2_for(&settings, &kind),
        );
        listeners.register(l.clone(), kind, Some(certificate));
        match l.bind(&format!("{}:{}", host, one.port)).await {
            Ok(tcp) => {
                tracing::info!("tls: {} is listening.", label);
                tasks.spawn(l.serve(tcp, router.clone()));
            }
            Err(why) => tracing::warn!(
                "{}tls: {} could not be bound on this node: {}. Its applications are still answered on the \
                 other listeners they are on.",
                tag(codes::STS_TLS_0039),
                label,
                why
            ),
        }
    }
    // 7.
    SocketOwners.listen(&listeners).await;
    tokio::select! {
        _ = async { while tasks.join_next().await.is_some() {} } => {}
        _ = shutdown_signal() => {
            tracing::info!("runtime: stopping; what is pending is written down first.");
        }
    }
    tasks.abort_all();
    stack.stop().await;
    Ok(())
}

fn main() {
    let level = std::env::var("STS_LOG_LEVEL").unwrap_or_default();
    log::install(
        "sts-runtime",
        log::parse_level(if level.is_empty() { "info" } else { &level }),
    );
    let (operator, from) = match appconfig() {
        Ok(found) => found,
        Err(e) => fatal(codes::STS_CORE_0093, &format!("runtime: {}", e)),
    };
    tracing::info!(
        "runtime: settings from {} over the compiled defaults.",
        from.as_deref()
            .map_or("no CONFIG_FILE".to_string(), |p: &Path| p
                .display()
                .to_string())
    );
    let settings = Arc::new(Settings::from_process(operator));
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => fatal(
            codes::STS_CORE_0093,
            &format!("runtime: could not start: {}", e),
        ),
    };
    if let Err(e) = runtime.block_on(run(settings)) {
        tracing::error!("{}", e);
        std::process::exit(1);
    }
}
