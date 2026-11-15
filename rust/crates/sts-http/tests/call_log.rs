// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The call log (`call_log.rs`, `app.js`'s `recordTheCall()`): a marked
//! refusal is a row carrying its code IN THE REQUEST'S REALM, an unrouted
//! path is `STS-HTTP-0001`, and an error page's incident ID is the `seq`
//! of its own row (#1326).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::Value as Json;
use sts_audit::{AuditLog, AuditPorts};
use sts_core::errors::codes;
use sts_core::mode::Mode;
use sts_core::realm::{self, Realm, RealmRegistry, SettingsEnvironment};
use sts_core::settings::Settings;
use sts_http::HttpLayer;
use tower::ServiceExt;

fn stack() -> (Arc<RealmRegistry>, Arc<AuditLog>, axum::Router) {
    let settings =
        Arc::new(Settings::new(Json::Null, std::collections::HashMap::new()));
    let mode = Arc::new(Mode::new(settings.clone()));
    let registry = Arc::new(RealmRegistry::new(Arc::new(
        SettingsEnvironment::new(settings.clone(), Vec::new()),
    )));
    registry.insert(Realm {
        id: "acme".into(),
        name: "Acme".into(),
        description: String::new(),
        builtin: false,
        created_at: Some(0),
        domain: "acme.example.net".into(),
    });
    let log = Arc::new(AuditLog::new(AuditPorts::local(settings.clone())));
    let layer = HttpLayer::new(registry.clone(), settings, mode);
    layer.set_audit(log.clone());
    let routes = axum::Router::new()
        .route(
            "/oauth2/token",
            post(|| async {
                let mut r: Response = "refused".into_response();
                *r.status_mut() = StatusCode::BAD_REQUEST;
                sts_http::mark(r, codes::STS_OAUTH_0950)
            }),
        )
        .route(
            "/page",
            get(|| async {
                let n = sts_http::call_log::reserve_incident();
                let again = sts_http::call_log::reserve_incident();
                assert_eq!(n, again, "a second reservation is the same");
                let mut r: Response = format!("{}", n).into_response();
                *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                r
            }),
        );
    (registry, log, layer.wrap(routes))
}

async fn call(app: &axum::Router, method: &str, path: &str) -> (u16, String) {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .body(Body::empty())
        .unwrap_or_default();
    let response = app
        .clone()
        .oneshot(request)
        .await
        .unwrap_or_else(|never| match never {});
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap_or_default();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn rows_in(
    registry: &RealmRegistry,
    log: &AuditLog,
    id: &str,
) -> Vec<sts_audit::AuditRow> {
    match registry.get(id) {
        Some(r) if id != "default" => realm::run_sync(r, || log.list()),
        _ => log.list(),
    }
}

#[tokio::test]
async fn a_marked_refusal_is_a_row_in_its_realm() {
    let (registry, log, app) = stack();
    let (status, _) = call(&app, "POST", "/realm/acme/oauth2/token").await;
    assert_eq!(status, 400);
    let acme = rows_in(&registry, &log, "acme");
    assert_eq!(acme.len(), 1, "{:?}", acme);
    assert_eq!(acme[0].error_code, codes::STS_OAUTH_0950.as_str());
    assert_eq!(acme[0].outcome, "refused");
    assert_eq!(acme[0].channel, "http");
    assert_eq!(acme[0].target, "/realm/acme/oauth2/token");
    assert_eq!(acme[0].action, "protocol.call");
    assert!(
        rows_in(&registry, &log, "default").is_empty(),
        "nothing in the default realm"
    );
}

#[tokio::test]
async fn an_unrouted_path_is_http_0001() {
    let (registry, log, app) = stack();
    let (status, body) = call(&app, "GET", "/nowhere").await;
    assert_eq!(status, 404);
    assert!(body.contains("Cannot GET /nowhere"));
    let rows = rows_in(&registry, &log, "default");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].error_code, codes::STS_HTTP_0001.as_str());
}

#[tokio::test]
async fn the_incident_id_is_the_rows_seq() {
    let (registry, log, app) = stack();
    let (_, first) = call(&app, "GET", "/page").await;
    let (_, second) = call(&app, "GET", "/page").await;
    let rows = rows_in(&registry, &log, "default");
    assert_eq!(rows.len(), 2);
    // Newest first.
    assert_eq!(rows[0].seq.to_string(), second);
    assert_eq!(rows[1].seq.to_string(), first);
    assert_eq!(rows[0].error_code, codes::STS_HTTP_0003.as_str());
    assert_eq!(rows[0].outcome, "error");
}
