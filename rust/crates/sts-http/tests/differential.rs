// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The HTTP layer and the static surfaces against a RUNNING Node service
//! (rust/DESIGN.md section 10.2's differential test): this crate's layer
//! and surface host, served in-process on a loopback port, and the same
//! requests sent to both by `tests/tools/http-differential.js`, which
//! compares status, headers and bodies and fails on any difference that
//! is not on its list of what later phases own.
//!
//! **IN-PROCESS, NOT `sts-runtime`**: the runtime's `main.rs` is the TLS
//! slice's and does not wire this crate's routes yet, so the Rust half is
//! the layer wrapped round the [`SurfaceHost`] here, which is what
//! `main.rs` will mount.
//!
//! It needs three things, and passes saying so when any is missing:
//!
//! * `STS_HTTP_DIFF_NODE` — the Node probe's base URL, a FRESH container
//!   of this tree's image started with `STS_HTTPS=false`,
//!   `STS_PUBLIC_BASE_URL` equal to that URL, and
//!   `ADMIN_API_CLIENT_SECRET` set (the harness creates the realm `diff`
//!   through `/admin-api` to compare realm-prefixed paths);
//! * `STS_WEB_ROOT` — that image's `/usr/src/sts`, copied out
//!   (`docker cp <container>:/usr/src/sts/. <dir>`), so both serve the same
//!   bundles, catalogs and `version.json`;
//! * `STS_ADMIN_API_CLIENT_SECRET` — the secret above, for the harness.
//!
//! The test sets `STS_PUBLIC_BASE_URL` for its own settings to the Node
//! base, and the harness sends both the same `Host`, so both name the same
//! origin. The report is written to `tests/vectors/http/` (gitignored).

#![allow(clippy::unwrap_used, clippy::expect_used)] // a test file

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::Value as Json;
use sts_core::mode::Mode;
use sts_core::realm::{Realm, RealmRegistry, SettingsEnvironment};
use sts_core::settings::Settings;
use sts_http::files::WebRoot;
use sts_http::surfaces::SurfaceHost;
use sts_http::HttpLayer;

fn repository() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_layer_and_the_surfaces_answer_as_node_does() {
    let (Ok(node), Ok(root), Ok(secret)) = (
        std::env::var("STS_HTTP_DIFF_NODE"),
        std::env::var("STS_WEB_ROOT"),
        std::env::var("STS_ADMIN_API_CLIENT_SECRET"),
    ) else {
        eprintln!(
            "differential: STS_HTTP_DIFF_NODE, STS_WEB_ROOT and \
             STS_ADMIN_API_CLIENT_SECRET are not all set; nothing compared."
        );
        return;
    };
    let mut env: std::collections::HashMap<String, String> =
        std::env::vars().collect();
    env.insert(
        "STS_PUBLIC_BASE_URL".into(),
        node.trim_end_matches('/').into(),
    );
    env.insert("STS_HTTPS".into(), "false".into());
    let settings = Arc::new(Settings::new(Json::Null, env));
    let mode = Arc::new(Mode::new(settings.clone()));
    let registry = Arc::new(RealmRegistry::new(Arc::new(
        SettingsEnvironment::new(settings.clone(), Vec::new()),
    )));
    registry.insert(Realm {
        id: "diff".into(),
        name: "Differential".into(),
        description: String::new(),
        builtin: false,
        created_at: Some(0),
        domain: "diff.example.net".into(),
    });
    let layer =
        HttpLayer::new(registry.clone(), settings.clone(), mode.clone());
    let host =
        SurfaceHost::build(settings, mode, registry, WebRoot(root.into()));
    layer.add_routes(host);
    let app = layer.wrap(axum::Router::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rust = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let out = repository().join("tests/vectors/http");
    std::fs::create_dir_all(&out).unwrap();
    let status = tokio::process::Command::new("node")
        .current_dir(repository())
        .arg("tests/tools/http-differential.js")
        .arg("--node")
        .arg(&node)
        .arg("--rust")
        .arg(&rust)
        .arg("--admin-secret")
        .arg(&secret)
        .arg("--report")
        .arg(out.join("http-differential-report.json"))
        .status()
        .await
        .unwrap();
    assert!(
        status.success(),
        "the harness found differences; see tests/vectors/http/\
         http-differential-report.json"
    );
}
