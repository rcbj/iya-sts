// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `sts-runtime`: the Rust runtime of iya-sts (#444, rust/DESIGN.md).
//!
//! `main()` reads the appconfig layer `CONFIG_FILE` names — `env/*.json`,
//! the data the Node runtime's `env/*.js` hold (a `.js` path is read as the
//! `.json` beside it) — builds the stack, opens the store BEFORE binding
//! (a store that cannot be read stops the process), binds `global.host`
//! and `global.port`, and on SIGTERM or Ctrl-C writes what is pending and
//! closes the store.
//!
//! The main port is HTTPS when `global.https` is on. Until the TLS module
//! is ported, its certificate is a self-signed stand-in made at start; the
//! certificate the Node runtime presents comes from the realm's PKI.

mod solo;
mod stack;

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use openssl::ssl::{SslAcceptor, SslMethod};
use serde_json::{json, Value as Json};
use sts_core::errors::codes;
use sts_core::log::{self, tag};
use sts_core::settings::Settings;
use tokio::net::TcpListener;

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

/// A self-signed stand-in for the listener's certificate.
fn stand_in_acceptor(host: &str) -> Result<SslAcceptor, String> {
    let group = openssl::ec::EcGroup::from_curve_name(
        openssl::nid::Nid::X9_62_PRIME256V1,
    )
    .map_err(|e| e.to_string())?;
    let key = openssl::pkey::PKey::from_ec_key(
        openssl::ec::EcKey::generate(&group).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let private_pem = String::from_utf8(
        key.private_key_to_pem_pkcs8().map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let public_pem =
        String::from_utf8(key.public_key_to_pem().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let pem = sts_pki::x509::issue::self_signed_cert_pem(&json!({
        "publicPem": public_pem, "privatePem": private_pem,
        "subject": format!("CN={}", if host.is_empty() || host == "0.0.0.0" { "localhost" } else { host }),
    }))
    .map_err(|e| e.to_string())?;
    let cert = openssl::x509::X509::from_pem(pem.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
        .map_err(|e| e.to_string())?;
    builder.set_private_key(&key).map_err(|e| e.to_string())?;
    builder.set_certificate(&cert).map_err(|e| e.to_string())?;
    builder.check_private_key().map_err(|e| e.to_string())?;
    Ok(builder.build())
}

async fn serve(
    stack: Arc<Stack>,
    listener: TcpListener,
    tls: Option<Arc<SslAcceptor>>,
) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let service = TowerToHyperService::new(stack.router());
        let tls = tls.clone();
        tokio::spawn(async move {
            let served = match tls {
                None => {
                    Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), service)
                        .await
                }
                Some(acceptor) => {
                    let Ok(ssl) = openssl::ssl::Ssl::new(acceptor.context())
                    else {
                        return;
                    };
                    let Ok(mut tls) =
                        tokio_openssl::SslStream::new(ssl, stream)
                    else {
                        return;
                    };
                    if let Err(e) = Pin::new(&mut tls).accept().await {
                        tracing::debug!(
                            "runtime: a TLS handshake failed: {}",
                            e
                        );
                        return;
                    }
                    Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls), service)
                        .await
                }
            };
            if let Err(e) = served {
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

async fn run(settings: Arc<Settings>) -> Result<(), String> {
    let stack = Arc::new(Stack::build(settings.clone())?);
    stack.start().await?;
    let host = settings.value_of("global.host").as_str().to_string();
    let port = settings.value_of("global.port").as_int();
    let https = settings.value_of("global.https").as_bool();
    let tls = if https {
        Some(Arc::new(stand_in_acceptor(&host)?))
    } else {
        None
    };
    let bind = format!(
        "{}:{}",
        if host.is_empty() { "0.0.0.0" } else { &host },
        port
    );
    let listener = TcpListener::bind(&bind).await.map_err(|e| {
        format!(
            "{}runtime: could not bind {}: {}",
            tag(codes::STS_CORE_0093),
            bind,
            e
        )
    })?;
    tracing::info!(
        "runtime: listening on {}://{} (mode {}). No protocol family is served yet (#444 phase 3); every path \
         answers 404.{}",
        if https { "https" } else { "http" },
        listener.local_addr().map(|a| a.to_string()).unwrap_or(bind),
        stack.mode.current(),
        if https { " The certificate is a self-signed stand-in until the TLS module is ported." } else { "" }
    );
    tokio::select! {
        _ = serve(stack.clone(), listener, tls) => {}
        _ = shutdown_signal() => {
            tracing::info!("runtime: stopping; what is pending is written down first.");
        }
    }
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
        Err(e) => {
            tracing::error!("{}runtime: {}", tag(codes::STS_CORE_0093), e);
            std::process::exit(1);
        }
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
        Err(e) => {
            tracing::error!(
                "{}runtime: could not start: {}",
                tag(codes::STS_CORE_0093),
                e
            );
            std::process::exit(1);
        }
    };
    if let Err(e) = runtime.block_on(run(settings)) {
        tracing::error!("{}", e);
        std::process::exit(1);
    }
}
