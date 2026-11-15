// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The `/admin-api/applications` operations through the router, over a
//! real application register and a real directory, in development's open
//! API: each answer is held to its closed model by the router itself
//! (#1353; a mismatch is a 500 marked STS-API-0139), so a 200 here is an
//! answer the model accepts — `getApplications`' page above all. What each
//! act answers, sentence for sentence, is `sts-registers`'
//! `applications_vectors` test, against Node.

#![allow(clippy::unwrap_used, clippy::expect_used)] // a test file

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::Request;
use serde_json::{json, Value as Json};
use sts_core::errors::ErrorCode;
use sts_core::mode::Mode;
use sts_core::realm::{RealmRegistry, SettingsEnvironment};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::StoreHandles;
use sts_core::settings::Settings;
use sts_core::version::VersionInfo;
use sts_directory::Directory;
use sts_mgmt_api::config_view::ProcessFacts;
use sts_mgmt_api::gate::{
    BuiltInAccess, ConsoleOperation, Effective, GatePorts,
};
use sts_mgmt_api::router::{router, KeySource, Services};
use sts_mgmt_api::setup::{Listener, Seeded, SetupPorts};
use sts_oauth::dpop_stores::DpopStores;
use sts_oauth::jwt_access_token::JwtAccessTokens;
use sts_registers::applications::env::{CoreEnv, NoEffects};
use sts_registers::applications::ApplicationRegistry;
use sts_store::key_sets::KeySet;
use tower::ServiceExt;

struct Fake {
    applications: Arc<ApplicationRegistry>,
}

impl GatePorts for Fake {
    fn revoked(&self, _: &str, _: &str) -> bool {
        false
    }
    fn disabled(&self, _: &str, _: &str) -> bool {
        false
    }
    fn session_ended(&self, _: &str, _: &str) -> bool {
        false
    }
    fn client_method(&self, _: &str, _: &str) -> String {
        String::new()
    }
    fn certificate_declaration(&self, _: &str, _: &str) -> String {
        String::new()
    }
    fn declares(&self, _: &str, _: &str, _: &str) -> bool {
        false
    }
    fn effective_roles(&self, _: &str, _: &Json, _: &[String]) -> Effective {
        Effective {
            roles: Vec::new(),
            withdrawn: Vec::new(),
            why: String::new(),
            subject_kind: String::new(),
            subject_name: String::new(),
        }
    }
    fn security_change(
        &self,
        _: &str,
        _: &ConsoleOperation,
        _: &Json,
    ) -> Option<String> {
        None
    }
    fn realm_refusal(
        &self,
        _: &str,
        _: &ConsoleOperation,
        _: Option<&Json>,
    ) -> Option<String> {
        None
    }
}

impl SetupPorts for Fake {
    fn seed_administrator(&self, _: &str) -> Seeded {
        Seeded::default()
    }
    fn kid_of(&self, _: &str) -> String {
        String::new()
    }
    fn listeners_of(&self, _: &str) -> Vec<Listener> {
        Vec::new()
    }
    fn advertised_base(&self, _: &str) -> String {
        String::new()
    }
    fn reserved(&self) -> Vec<String> {
        Vec::new()
    }
    fn totals(&self, _: &str) -> Json {
        json!({})
    }
    fn retire(&self, _: &str) -> Result<Json, (ErrorCode, Vec<String>)> {
        Ok(json!({ "ok": true }))
    }
    fn applications(&self) -> Option<Arc<ApplicationRegistry>> {
        Some(self.applications.clone())
    }
}

struct Keys;

impl KeySource for Keys {
    fn key_set(&self, _: &str) -> Option<KeySet> {
        None
    }
    fn issue_nonce(&self) -> String {
        "nonce".into()
    }
}

#[tokio::test]
async fn the_applications_operations_answer_within_their_models() {
    let settings = Arc::new(Settings::new(json!({}), HashMap::new()));
    settings
        .set_override("adminApi.authRequired", json!(false))
        .unwrap();
    let mode = Mode::shared(settings.clone());
    let registry = Arc::new(RealmRegistry::new(Arc::new(
        SettingsEnvironment::new(settings.clone(), Vec::new()),
    )));
    let lifecycle =
        RealmLifecycle::new(registry.clone(), settings.clone(), mode.clone());
    let dpop = DpopStores::new(
        &lifecycle,
        &StoreHandles::new(),
        settings.clone(),
        Arc::new(|| 1_794_657_600),
    );
    let directory = Arc::new(Mutex::new(Directory::new("dc=example,dc=com")));
    let applications = Arc::new(ApplicationRegistry::new(
        Some(directory),
        Arc::new(CoreEnv {
            settings: settings.clone(),
            mode: mode.clone(),
        }),
        Arc::new(NoEffects),
    ));
    let fake = Arc::new(Fake { applications });
    let services = Arc::new(Services {
        settings: settings.clone(),
        mode: mode.clone(),
        lifecycle,
        registry: registry.clone(),
        tokens: Arc::new(JwtAccessTokens::new(settings.clone())),
        keys: Arc::new(Keys),
        gate_ports: fake.clone(),
        access: Arc::new(BuiltInAccess::new()),
        dpop,
        setup_ports: fake.clone(),
        facts: ProcessFacts {
            config_file: None,
            defaults_file: String::new(),
            persists_appconfig: false,
            persists_realms: false,
            persistence_mode: String::new(),
            persistence_enabled: false,
        },
        version: serde_json::from_value::<VersionInfo>(json!({
            "version": "1.1.0", "major": "1", "minor": "1",
            "builtAt": "", "stamped": false, "release": false,
            "commit": ""
        }))
        .unwrap(),
        eddsa_curve: String::new(),
        now: Arc::new(|| 1_794_657_600),
    });
    let layer =
        sts_http::HttpLayer::new(registry.clone(), settings.clone(), mode);
    let app = layer.wrap(router(services));
    let send = |method: &str, url: &str, body: Option<Json>| {
        let mut r = Request::builder()
            .method(method)
            .uri(url)
            .header("host", "127.0.0.1:8081")
            .header("accept", "application/json");
        let body = match body {
            Some(b) => {
                let text = b.to_string();
                r = r
                    .header("content-type", "application/json")
                    .header("content-length", text.len());
                Body::from(text)
            }
            None => Body::empty(),
        };
        r.body(body).unwrap()
    };
    let cases = vec![
        (
            "POST",
            "/admin-api/applications/create",
            Some(json!({ "identifier": "router-app", "name": "Router app",
                      "protocols": ["oauth2", "oidc"],
                      "fields": { "oauthRedirectUri":
                                  ["https://router.example/cb"] } })),
            200,
        ),
        (
            "POST",
            "/admin-api/applications/create",
            Some(json!({ "identifier": "router-app" })),
            400,
        ),
        (
            "POST",
            "/admin-api/applications/set",
            Some(json!({ "application": "router-app", "attribute": "appName",
                      "value": "Renamed" })),
            200,
        ),
        (
            "POST",
            "/admin-api/applications/add-secret",
            Some(json!({ "application": "router-app" })),
            200,
        ),
        (
            "POST",
            "/admin-api/applications/update-fields",
            Some(json!({ "application": "router-app",
                      "fields": { "appHomePageUrl": "https://router.example/" } })),
            200,
        ),
        ("GET", "/admin-api/applications", None, 200),
        ("GET", "/admin-api/applications?q=router&per=1", None, 200),
        (
            "GET",
            "/admin-api/applications?application=router-app",
            None,
            404,
        ),
        (
            "POST",
            "/admin-api/applications/teleport",
            Some(json!({ "application": "router-app" })),
            400,
        ),
        (
            "POST",
            "/admin-api/applications/generate-did-key",
            Some(json!({ "application": "router-app" })),
            404,
        ),
        (
            "POST",
            "/admin-api/applications/forget",
            Some(json!({ "application": "router-app" })),
            200,
        ),
    ];
    for (method, url, body, status) in cases {
        let response =
            app.clone().oneshot(send(method, url, body)).await.unwrap();
        let got = response.status().as_u16();
        let code = sts_http::code_of(&response).map(|c| c.as_str().to_string());
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            got,
            status,
            "{method} {url}: {got} ({code:?}) {}",
            String::from_utf8_lossy(&bytes)
        );
    }
}
