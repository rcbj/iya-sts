// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `sts-runtime`: the Rust runtime of iya-sts (#444, rust/DESIGN.md) —
//! `server.js`'s shell.
//!
//! THE ORDER IS `server.js`'s, and each step says what in Node it is:
//!
//! 1. the appconfig layer `CONFIG_FILE` names (`sts_core::appconfig`,
//!    `common/config_file.js`), the logger at its level (`STS_LOG_LEVEL`
//!    overrides), the settings, the secrets delivered as files, and every
//!    check `config.js` makes as it loads — each refusal exit 1;
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
//! WHAT IS WIRED, AND WHAT IS A SEAM. The store (memory, ldif, postgres
//! and mariadb, with the origin adopted at the store's opening, the run
//! history over minted persistence and the read barrier a `syncNow()` pull:
//! `store.rs`), the cluster, the scheduler (with this module's
//! `tls.listener-renew` job), the caches, the HTTP layer and the settings
//! are the phase-3 crates as merged on `feature/444`. `Settings` offers no change notification
//! (`config.onOverridesChanged()`): whoever writes a setting through
//! `set_override()` — the management API, phase 4 — calls
//! `Listeners::reapply(true)` after it; the truststore doors (`/admin-api/tls/trust`,
//! phase 4) call `Truststore::add`/`remove` and then `reapply(false)`; a
//! rebuilt hierarchy (`build-root`, phase 6) replaces `Listeners::material`
//! and calls `reapply(false)` — the front-process reconcile, with no worker
//! to tell.

#![forbid(unsafe_code)]

mod admin_api;
mod admin_families;
mod certificates;
mod identity_funnel;
mod ldap_listener;
mod listener;
mod listeners;
mod oauth;
mod pki;
mod solo;
mod stack;
mod store;

use std::collections::HashMap;
use std::sync::Arc;

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
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

/// A start that cannot go on, its sentence already tagged: exit 1.
fn fatal_line(message: &str) -> ! {
    tracing::error!("{}", message);
    std::process::exit(1);
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
struct SocketOwners {
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl SocketOwners {
    #[tracing::instrument(level = "debug", skip_all)]
    async fn listen(
        &mut self,
        settings: &Settings,
        listeners: &Arc<Listeners>,
        host: &str,
    ) {
        // THE DIRECTORY'S TWO SOCKETS: the wire is sts-ldap's, the
        // handlers phase 4's (`ldap_listener::NotYet` until then).
        let handlers: Arc<dyn ldap_listener::Handlers> =
            Arc::new(ldap_listener::NotYet);
        let port = |key: &str| {
            u16::try_from(settings.value_of(key).as_int()).unwrap_or(0)
        };
        // `ldap.plainListener` off (product's default): Node starts no
        // plain listener at all, and LDAPS is the only way in
        // (`ldapServer.listen()`); the view says so (`directoryState()`).
        if settings.value_of("ldap.plainListener").as_bool() {
            if let Some(t) = ldap_listener::listen_plain(
                host,
                port("ldap.port"),
                handlers.clone(),
            )
            .await
            {
                self.tasks.push(t);
            }
        } else {
            tracing::info!(
                "ldap: the plain listener on {} was NOT started \
                 (ldap.plainListener is off); LDAPS on {} is the only way in.",
                port("ldap.port"),
                port("ldap.tlsPort")
            );
        }
        let first = listeners
            .material
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .certificates
            .first()
            .cloned();
        let label = format!("LDAPS ({})", port("ldap.tlsPort"));
        let built = first
            .ok_or_else(|| "no listener certificate".to_string())
            .and_then(|c| {
                listeners.context_for(
                    &label,
                    &ListenerKind::Ldaps,
                    Some(&vec![c]),
                )
            });
        match built {
            Ok(applied) => {
                if let Some(t) = ldap_listener::listen_tls(
                    host,
                    port("ldap.tlsPort"),
                    applied.context,
                    handlers,
                )
                .await
                {
                    self.tasks.push(t);
                }
            }
            Err(why) => tracing::error!(
                "{}ldap: LDAPS could not be built ({}); LDAPS is not offered.",
                tag(codes::STS_LDAP_0028),
                why
            ),
        }
        tracing::debug!(
            "runtime: the other family sockets are not ported yet (KDC 88, SPIFFE, the revocation \
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
                    request
                        .extensions_mut()
                        .insert(sts_http::client_address::Peer(peer.ip()));
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
                Some(true),
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
    let material = match certificates::settle(
        &settings,
        stack.pki.get().map(|a| a.as_ref()),
        Some((&stack.listener_keys, stack.node_name.as_str())),
    ) {
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
    settings.set_advertised_base(Arc::new(listeners::AdvertisedListeners {
        definitions: custom.clone(),
    }));
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
    // A product process does not serve its main port in cleartext
    // (#1457): server.js's refusal, before anything binds.
    if let Some(refused) =
        sts_core::startup::cleartext_refusal(&stack.mode, https)
    {
        fatal_line(&refused);
    }
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
    // THE PLAIN-HTTP REVOCATION LISTENER (`pki_service.ts`'s `listen()`):
    // `/pki/`, SCEP and `/healthcheck` only, on the http:// address every
    // certificate names. Recorded rather than fatal, as Node's is.
    let revocation_port = settings.value_of("pki.httpPort").as_int();
    if revocation_port > 0 {
        let at = format!("{}:{}", host, revocation_port);
        match TcpListener::bind(&at).await {
            Ok(tcp) => {
                tracing::info!(
                    "pki: the revocation endpoints are also on plain HTTP port {} (/pki/ only), which is \
                     the address every certificate this service issues names for its CRL, its OCSP \
                     responder and its issuer's certificate.",
                    revocation_port
                );
                tasks.spawn(serve_plain(
                    tcp,
                    crate::pki::revocation_listener(router.clone()),
                ));
            }
            Err(e) => tracing::error!(
                "{}pki: the plain-HTTP revocation listener could not start: {}. Every http:// CRL and \
                 OCSP address in this service's certificates will answer nothing.",
                tag(codes::STS_CORE_0043),
                e
            ),
        }
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
    let mut owners = SocketOwners::default();
    owners.listen(&settings, &listeners, &host).await;
    tokio::select! {
        _ = async { while tasks.join_next().await.is_some() {} } => {}
        _ = shutdown_signal() => {
            tracing::info!("runtime: stopping; what is pending is written down first.");
        }
    }
    tasks.abort_all();
    for t in &owners.tasks {
        t.abort();
    }
    stack.stop().await;
    Ok(())
}

fn main() {
    // 1. The appconfig layer (`common/config_file.js`): CONFIG_FILE,
    // resolved against the package root and then the working directory,
    // evaluated as the module it is. A file that cannot be loaded is
    // config.js's STS-CORE-0001 on stderr, and exit 1.
    let root = std::env::current_dir().unwrap_or_default();
    let mut env: HashMap<String, String> = std::env::vars().collect();
    let app = match sts_core::appconfig::load(&root, &env) {
        Ok(app) => app,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };
    // The bootstrap logger at the file's level; STS_LOG_LEVEL overrides.
    let level = env
        .get("STS_LOG_LEVEL")
        .filter(|l| !l.is_empty())
        .cloned()
        .unwrap_or_else(|| app.log_level());
    log::install("sts-runtime", log::parse_level(&level));
    let settings = Arc::new(Settings::new(app.operator.clone(), env.clone()));
    // Secrets delivered as files (`*_FILE`), read and deleted before
    // anything reads them, then every check config.js makes as it loads.
    if let Err(e) = sts_core::startup::deliver_secrets(
        &settings,
        &mut env,
        &sts_core::startup::RealFiles,
    ) {
        fatal_line(&e);
    }
    if let Err(e) = sts_core::startup::check_settings(
        &settings,
        &sts_core::startup::Files::new(app.config_file.clone(), &root),
    ) {
        fatal_line(&e);
    }
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
