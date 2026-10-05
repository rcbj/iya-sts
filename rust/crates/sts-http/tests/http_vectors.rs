// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The HTTP layer against Node: `http-node.json`, which
//! `tests/tools/crypto-vectors.js` writes by asking the real express app
//! (`common/app.js`) over HTTP, with the same probe routes registered
//! behind its middleware. Status, the security headers, the Location, and
//! the body — the realm prefix put back on links and redirects, a page's
//! careless CSP replaced, the one framed page, Express's 404 — must be
//! Node's; so must the two CSP builders on their own.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed; with it unset
//! this test says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, HeaderValue, Request};
use axum::response::Response;
use axum::routing::get;
use serde_json::{json, Value as Json};
use sts_core::realm::{self, Realm, RealmEnvironment, RealmRegistry};
use sts_http::csp;
use tower::ServiceExt;

struct Env;

impl RealmEnvironment for Env {
    fn enabled(&self) -> bool {
        true
    }
    fn path_segment(&self) -> String {
        "realm".to_string()
    }
    fn global_domain(&self) -> String {
        "example.com".to_string()
    }
    fn reserved(&self) -> Vec<String> {
        Vec::new()
    }
    fn est_labels(&self) -> Vec<String> {
        Vec::new()
    }
}

fn with_csp(mut r: Response, policy: String) -> Response {
    r.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&policy).unwrap(),
    );
    r
}

fn app(registry: Arc<RealmRegistry>) -> axum::Router {
    let routes = axum::Router::new()
        .route(
            "/probe/html",
            get(|| async {
                sts_http::html(
                    "<a href=\"/x\">x</a> <form action=\"/y?q=1\"></form> <img src=\"//cdn.example/z\"> <a \
                     href=\"rel\">r</a>",
                )
            }),
        )
        .route("/probe/redirect", get(|| async { sts_http::redirect("/oauth2/authorize?x=1") }))
        .route(
            "/probe/own-csp",
            get(|| async { with_csp(sts_http::text("mine"), "default-src 'none'".to_string()) }),
        )
        .route(
            "/probe/relaxed",
            get(|| async {
                with_csp(
                    sts_http::text("relaxed"),
                    csp::content_security_policy(&[
                        ("script-src", Some("'self'")),
                        ("frame-ancestors", Some("*")),
                        ("base-uri", None),
                        ("connect-src", Some("'self'")),
                    ]),
                )
            }),
        )
        .route(
            "/probe/framed",
            get(|| async {
                with_csp(
                    sts_http::html("<p>framed</p>"),
                    csp::framed_content_security_policy(&["https://rp.example", "javascript:x", "http://a:8080"], &[]),
                )
            }),
        )
        .route("/probe/realm", get(|| async { sts_http::text(format!("realm={}", realm::current_id())) }));
    sts_http::layered(routes, registry)
}

#[tokio::test]
async fn the_http_layer_is_nodes() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: http-node.json is not checked"
        );
        return;
    };
    let v: Json = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(&dir).join("http-node.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let registry = Arc::new(RealmRegistry::new(Arc::new(Env)));
    let mut acme = Realm::default_realm();
    acme.id = "acme".to_string();
    acme.builtin = false;
    acme.domain = "acme.example.com".to_string();
    registry.insert(acme);
    let router = app(registry);
    let mut failures = Vec::new();
    for want in v["answers"].as_array().unwrap() {
        let path = want["path"]
            .as_str()
            .unwrap()
            .replace('<', "%3C")
            .replace('>', "%3E");
        let response = router
            .clone()
            .oneshot(Request::get(&path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status().as_u16();
        let mut headers = serde_json::Map::new();
        for k in [
            "content-type",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "location",
        ] {
            headers.insert(
                k.to_string(),
                response
                    .headers()
                    .get(k)
                    .map_or(Json::Null, |h| json!(h.to_str().unwrap())),
            );
        }
        let body = String::from_utf8(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        let got = json!({ "path": want["path"], "status": status, "headers": headers, "body": body });
        if got != *want {
            failures.push(format!(
                "{}:\n  rust {}\n  node {}",
                want["path"], got, want
            ));
        }
    }
    let pairs = |o: &Json| -> Vec<(String, Option<String>)> {
        o.as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().map(str::to_string)))
            .collect()
    };
    for c in v["csp"].as_array().unwrap() {
        let owned = pairs(&c["overrides"]);
        let args: Vec<(&str, Option<&str>)> = owned
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_deref()))
            .collect();
        let got = csp::content_security_policy(&args);
        if json!(got) != c["value"] {
            failures.push(format!("csp {}: {}", c["overrides"], got));
        }
    }
    for c in v["framed"].as_array().unwrap() {
        let origins: Vec<&str> = c["origins"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o.as_str().unwrap())
            .collect();
        let got = csp::framed_content_security_policy(&origins, &[]);
        if json!(got) != c["value"] {
            failures.push(format!("framed {}: {}", c["origins"], got));
        }
    }
    assert!(
        failures.is_empty(),
        "{} differences:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
