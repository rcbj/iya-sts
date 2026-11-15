// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `/admin-api` against Node: `mgmt-api-node.json`, which
//! `tests/tools/mgmt-api-vectors.js` writes by asking Node's management API
//! in process — the gate's every refusal, the request checks, the setup
//! operations, an answer its model refuses and the open API of
//! development. Every request is sent here, in the same order, to this
//! crate's router behind `sts-http`'s layer, over settings built from the
//! same appconfig file and environment and a key set Node made; the status,
//! the error code it was marked with, the headers a caller reads and the
//! body must be Node's. The registers outside `sts-core` are ports, which
//! answer what Node's registers answered (`ports` in the vector).
//!
//! The committed routing rows (`tables/admin_api.json`) are held to the
//! table Node exports, so a change to `mgmt-api/admin_api.ts` that is not
//! exported fails here.
//!
//! With `STS_WRITE_VECTORS=1` the answers are written to
//! `mgmt-api-rust.json`, which `tests/rust_crypto_vectors.js` holds to
//! Node's answers and to Node's own response models.

#![allow(clippy::unwrap_used, clippy::expect_used)] // a test file

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::Request;
use serde_json::{json, Map, Value as Json};
use sts_core::errors::ErrorCode;
use sts_core::mode::Mode;
use sts_core::realm::{RealmRegistry, SettingsEnvironment};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::StoreHandles;
use sts_core::settings::Settings;
use sts_core::version::VersionInfo;
use sts_mgmt_api::config_view::ProcessFacts;
use sts_mgmt_api::gate::{BuiltInAccess, ConsoleOperation, Effective, GatePorts};
use sts_mgmt_api::router::{router, KeySource, Services};
use sts_mgmt_api::setup::{Listener, Seeded, SetupPorts};
use sts_oauth::dpop_stores::DpopStores;
use sts_oauth::jwt_access_token::JwtAccessTokens;
use sts_store::key_sets::KeySet;
use tower::ServiceExt;

/// The vector, and which case is being sent.
struct Fake {
    v: Json,
    case: Mutex<usize>,
}

impl Fake {
    fn port(&self, kind: &str, key: &str) -> Json {
        self.v["ports"][kind][key].clone()
    }

    fn case(&self) -> Json {
        let at = *self.case.lock().unwrap();
        self.v["cases"][at].clone()
    }

    /// The Node answer of the last case named `name`, parsed.
    fn answer_of(&self, name: &str) -> Json {
        let cases = self.v["cases"].as_array().unwrap();
        let found = cases.iter().filter(|c| c["name"] == name).last().unwrap();
        serde_json::from_str(found["answer"]["body"].as_str().unwrap()).unwrap()
    }
}

impl GatePorts for Fake {
    fn revoked(&self, _realm: &str, _jti: &str) -> bool {
        false
    }
    fn disabled(&self, _realm: &str, _sub: &str) -> bool {
        false
    }
    fn session_ended(&self, _realm: &str, _jti: &str) -> bool {
        false
    }
    fn client_method(&self, realm: &str, client: &str) -> String {
        self.port("clientMethod", &format!("{} {}", realm, client)).as_str().unwrap_or("").to_string()
    }
    fn certificate_declaration(&self, realm: &str, client: &str) -> String {
        self.port("certificate", &format!("{} {}", realm, client)).as_str().unwrap_or("").to_string()
    }
    fn declares(&self, realm: &str, client: &str, scope: &str) -> bool {
        self.port("declares", &format!("{} {}", realm, client))[scope].as_bool().unwrap_or(false)
    }
    fn effective_roles(&self, _realm: &str, claims: &Json, _scopes: &[String]) -> Effective {
        let e = self.port("effective", claims["jti"].as_str().unwrap_or(""));
        let list = |v: &Json| v.as_array().map(|a| a.iter().map(|x| x.as_str().unwrap_or("").to_string()).collect()).unwrap_or_default();
        Effective {
            roles: list(&e["roles"]),
            withdrawn: list(&e["withdrawn"]),
            why: e["why"].as_str().unwrap_or("").to_string(),
            subject_kind: e["subjectKind"].as_str().unwrap_or("").to_string(),
            subject_name: e["subjectName"].as_str().unwrap_or("").to_string(),
        }
    }
    fn security_change(&self, _realm: &str, _operation: &ConsoleOperation, _body: &Json) -> Option<String> {
        None
    }
    fn realm_refusal(&self, _realm: &str, operation: &ConsoleOperation, _body: Option<&Json>) -> Option<String> {
        self.port("realmRefusal", &operation.path).as_str().map(str::to_string)
    }
}

impl SetupPorts for Fake {
    fn seed_administrator(&self, _realm: &str) -> Seeded {
        let answer: Json = serde_json::from_str(self.case()["answer"]["body"].as_str().unwrap()).unwrap();
        let b = &answer["bootstrap"];
        Seeded {
            ran: b.is_object(),
            username: b["username"].as_str().unwrap_or("").to_string(),
            created: b["created"].as_bool().unwrap_or(false),
            password: answer["password"].as_str().map(str::to_string),
        }
    }
    fn kid_of(&self, realm: &str) -> String {
        self.v["kids"][realm].as_str().unwrap_or("").to_string()
    }
    fn listeners_of(&self, realm: &str) -> Vec<Listener> {
        let realms = self.answer_of("realms after the writes");
        realms["realms"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == realm)
            .map(|r| r["listeners"].as_array().unwrap().clone())
            .unwrap_or_default()
    }
    fn advertised_base(&self, _realm: &str) -> String {
        String::new()
    }
    fn reserved(&self) -> Vec<String> {
        self.answer_of("realms")["reserved"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap().to_string())
            .collect()
    }
    fn totals(&self, _realm: &str) -> Json {
        // The console's totals are the registers' (port-supplied); the
        // case that injects a member the model does not have asks for it.
        let case = self.case();
        let mut t = self.answer_of("status");
        if case["name"] == "an answer its model refuses" {
            t["bogus"] = json!(true);
        }
        t.as_object_mut().unwrap().remove("pages");
        t
    }
    fn retire(&self, _realm: &str) -> Result<Json, (ErrorCode, Vec<String>)> {
        Ok(json!({ "ok": true }))
    }
}

struct Keys(HashMap<String, KeySet>);

impl KeySource for Keys {
    fn key_set(&self, realm: &str) -> Option<KeySet> {
        self.0.get(realm).cloned()
    }
    fn issue_nonce(&self) -> String {
        "nonce".into()
    }
}

/// The first place two values differ, as a JSON pointer.
fn first_difference(a: &Json, b: &Json, at: &str) -> Option<String> {
    match (a, b) {
        (Json::Object(x), Json::Object(y)) => {
            let xk: Vec<_> = x.keys().collect();
            let yk: Vec<_> = y.keys().collect();
            if xk != yk {
                return Some(format!("{}: keys {:?} vs {:?}", at, xk, yk));
            }
            x.iter().find_map(|(k, v)| first_difference(v, &y[k], &format!("{}/{}", at, k)))
        }
        (Json::Array(x), Json::Array(y)) => {
            if x.len() != y.len() {
                return Some(format!("{}: length {} vs {}", at, x.len(), y.len()));
            }
            x.iter().zip(y).enumerate().find_map(|(i, (p, q))| first_difference(p, q, &format!("{}/{}", at, i)))
        }
        _ => (a != b).then(|| {
            let s = |v: &Json| v.to_string().chars().take(300).collect::<String>();
            format!("{}: {} vs {}", at, s(a), s(b))
        }),
    }
}

#[tokio::test]
async fn admin_api_answers_as_node_does() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!("STS_CRYPTO_VECTORS is not set; the /admin-api vectors were not checked.");
        return;
    };
    let path = std::path::Path::new(&dir).join("mgmt-api-node.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        eprintln!("{} is absent; the /admin-api vectors were not checked.", path.display());
        return;
    };
    let v: Json = serde_json::from_str(&text).unwrap();

    // The committed routing rows are Node's.
    let committed: Json = serde_json::from_str(sts_mgmt_api::tables::text()).unwrap();
    assert_eq!(
        first_difference(&committed, &v["tables"], ""),
        None,
        "tables/admin_api.json differs from Node's table: run tests/tools/export-admin-api-tables.js"
    );

    let env: HashMap<String, String> = v["env"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, x)| (k.clone(), x.as_str().unwrap_or("").to_string()))
        .collect();
    let settings = Arc::new(Settings::new(v["operator"].clone(), env));
    let mode = Mode::shared(settings.clone());
    let registry = Arc::new(RealmRegistry::new(Arc::new(SettingsEnvironment::new(settings.clone(), Vec::new()))));
    let lifecycle = RealmLifecycle::new(registry.clone(), settings.clone(), mode.clone());
    let now = v["now"].as_i64().unwrap();
    let dpop = DpopStores::new(&lifecycle, &StoreHandles::new(), settings.clone(), Arc::new(move || now));
    let keys: HashMap<String, KeySet> = v["keySets"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(realm, blob)| (realm.clone(), KeySet { realm: realm.clone(), blob: blob.clone() }))
        .collect();
    let f = &v["facts"];
    let facts = ProcessFacts {
        config_file: f["configFile"].as_str().map(str::to_string),
        defaults_file: f["defaultsFile"].as_str().unwrap_or("").to_string(),
        persists_appconfig: f["persistsAppconfig"].as_bool().unwrap_or(false),
        persists_realms: f["persistsRealms"].as_bool().unwrap_or(false),
        persistence_mode: f["persistenceMode"].as_str().unwrap_or("").to_string(),
        persistence_enabled: f["persistenceEnabled"].as_bool().unwrap_or(false),
    };
    let version: VersionInfo = serde_json::from_value(v["version"].clone()).unwrap();
    let fake = Arc::new(Fake { v: v.clone(), case: Mutex::new(0) });
    let services = Arc::new(Services {
        settings: settings.clone(),
        mode: mode.clone(),
        lifecycle: lifecycle.clone(),
        registry: registry.clone(),
        tokens: Arc::new(JwtAccessTokens::new(settings.clone())),
        keys: Arc::new(Keys(keys)),
        gate_ports: fake.clone(),
        access: Arc::new(BuiltInAccess::new()),
        dpop,
        setup_ports: fake.clone(),
        facts,
        version,
        eddsa_curve: String::new(),
        now: Arc::new(move || now),
    });
    let layer = sts_http::HttpLayer::new(registry.clone(), settings.clone(), mode.clone());
    let app = layer.wrap(router(services));
    let host = format!("127.0.0.1:{}", v["port"]);
    let tokens = v["tokens"].clone();
    let mut failures = Vec::new();
    let mut written = Vec::new();
    for (at, case) in v["cases"].as_array().unwrap().iter().enumerate() {
        *fake.case.lock().unwrap() = at;
        let name = case["name"].as_str().unwrap();
        if name.starts_with("open:") {
            settings.set_override("adminApi.authRequired", json!(false)).unwrap();
        }
        let mut request = Request::builder()
            .method(case["method"].as_str().unwrap())
            .uri(case["url"].as_str().unwrap())
            .header("host", &host)
            .header("accept", "application/json");
        if let Some(t) = case["token"].as_str() {
            request = request.header("authorization", format!("Bearer {}", tokens[t].as_str().unwrap()));
        }
        for (k, x) in case["headers"].as_object().unwrap() {
            request = request.header(k.as_str(), x.as_str().unwrap());
        }
        let body = match case["body"].as_str() {
            Some(b) => {
                request = request.header("content-type", "application/json").header("content-length", b.len());
                Body::from(b.to_string())
            }
            None => Body::empty(),
        };
        let response = app.clone().oneshot(request.body(body).unwrap()).await.unwrap();
        let status = response.status().as_u16();
        let code = sts_http::code_of(&response).map(|c| c.as_str().to_string()).unwrap_or_default();
        let header = |n: &str| response.headers().get(n).and_then(|h| h.to_str().ok()).map(str::to_string);
        let content_type = header("content-type");
        let www = header("www-authenticate");
        let cache = header("cache-control");
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8_lossy(&bytes).to_string();
        let node = &case["answer"];
        let mut problems = Vec::new();
        if status != node["status"].as_u64().unwrap() as u16 {
            problems.push(format!("status {} vs {}", status, node["status"]));
        }
        if code != node["code"].as_str().unwrap_or("") {
            problems.push(format!("code {:?} vs {}", code, node["code"]));
        }
        for (h, mine) in [("content-type", &content_type), ("www-authenticate", &www), ("cache-control", &cache)] {
            let theirs = node["headers"][h].as_str().map(str::to_string);
            if h == "cache-control" && theirs.is_none() {
                continue;
            }
            if *mine != theirs {
                problems.push(format!("{} {:?} vs {:?}", h, mine, theirs));
            }
        }
        let node_body = node["body"].as_str().unwrap_or("");
        match (serde_json::from_str::<Json>(&text), serde_json::from_str::<Json>(node_body)) {
            (Ok(mine), Ok(theirs)) => {
                if let Some(d) = first_difference(&mine, &theirs, "") {
                    problems.push(format!("body {}", d));
                } else if text != node_body {
                    problems.push("the same JSON in other bytes".into());
                }
            }
            _ => {
                if text != node_body {
                    problems.push(format!("text {:?} vs {:?}", text.chars().take(200).collect::<String>(),
                                          node_body.chars().take(200).collect::<String>()));
                }
            }
        }
        if name.starts_with("open:") {
            let _ = settings.reset_override("adminApi.authRequired");
        }
        if !problems.is_empty() {
            failures.push(format!("{}: {}", name, problems.join("; ")));
        }
        let mut one = Map::new();
        one.insert("name".into(), json!(name));
        one.insert("status".into(), json!(status));
        one.insert("code".into(), json!(code));
        one.insert("contentType".into(), json!(content_type));
        one.insert("body".into(), json!(text));
        written.push(Json::Object(one));
    }
    if std::env::var("STS_WRITE_VECTORS").is_ok() {
        std::fs::write(
            std::path::Path::new(&dir).join("mgmt-api-rust.json"),
            serde_json::to_string_pretty(&json!({ "cases": written })).unwrap(),
        )
        .unwrap();
    }
    let total = v["cases"].as_array().unwrap().len();
    assert!(failures.is_empty(), "{} of {} cases differ from Node:\n{}", failures.len(), total, failures.join("\n"));
    eprintln!("{} /admin-api cases answered as Node answers them.", total);
}
