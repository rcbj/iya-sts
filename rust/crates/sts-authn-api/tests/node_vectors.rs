// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `/authn-api` AND THE SIGN-IN SHELLS, REPLAYED: every browser step
//! `tests/tools/authn-api-vectors.js` sent to Node's whole stack is sent
//! here to the sign-in surface the runtime builds
//! (`sts_authn_api::wiring::SignInStack`, over a memory store and the
//! same person entries and pending records Node held), and each answer is
//! compared with Node's: the status, the error code recorded, the JSON
//! body and the `Set-Cookie` lines.
//!
//! Random values are each side's own: a step id, a CSRF token, a cookie
//! value is bound from that side's earlier answers, put into its later
//! requests, and replaced by a placeholder before the two answers are
//! compared. A shell's document is the static surfaces' host's (its own
//! vectors); here its status, type, policy and cookies are compared.
//!
//! `STS_CRYPTO_VECTORS` names the directory holding `authn-api-node.json`;
//! without it the test says so and passes, as every vector test here does.

#![allow(clippy::unwrap_used, clippy::expect_used)] // tests

use std::collections::HashMap;
use std::sync::Arc;

use axum::http::{HeaderMap, HeaderName, HeaderValue, Method};
use serde_json::{json, Value as Json};
use sts_authn_api::door::Arrived;
use sts_authn_api::router::{ShellsSource, SignInShells};
use sts_authn_api::wiring::{RuntimeParts, SignInStack};
use sts_core::mode::Mode;
use sts_core::realm::{RealmRegistry, SettingsEnvironment};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::StoreHandles;
use sts_core::settings::Settings;
use sts_http::Routes;
use sts_store::model::StoredEntry;
use sts_store::persistence::{MemoryDirectory, Persistence, StoreMode};

struct Built {
    stack: SignInStack,
    shells: SignInShells,
    directory: Arc<MemoryDirectory>,
}

fn build(version: &str) -> Built {
    // The harness's secret, so a token is the same function of a session.
    std::env::set_var("STS_CSRF_SECRET", "authn-api-vectors");
    let settings = Arc::new(Settings::new(
        json!({ "persistence": { "mode": "memory" } }),
        HashMap::new(),
    ));
    let mode = Mode::shared(settings.clone());
    let registry = Arc::new(RealmRegistry::new(Arc::new(
        SettingsEnvironment::new(settings.clone(), Vec::new()),
    )));
    let lifecycle =
        RealmLifecycle::new(registry.clone(), settings.clone(), mode.clone());
    let handles = StoreHandles::new();
    let directory = Arc::new(MemoryDirectory::default());
    let persistence = Persistence::new(
        StoreMode::Memory,
        None,
        settings.clone(),
        lifecycle.clone(),
        directory.clone(),
    );
    let stack = SignInStack::declare(RuntimeParts {
        settings: settings.clone(),
        mode: mode.clone(),
        registry: registry.clone(),
        lifecycle,
        handles,
        directory: directory.clone(),
        persistence,
        version: version.to_string(),
    });
    let surfaces = sts_http::surfaces::SurfaceHost::build(
        settings,
        mode,
        registry,
        sts_http::files::WebRoot(std::env::temp_dir().join("no-web-root")),
    );
    let shells = SignInShells {
        signin: stack.signin.clone(),
        shells: Arc::new(ShellsSource(surfaces)),
    };
    Built {
        stack,
        shells,
        directory,
    }
}

/// What one side's answers bound, for its later requests and for the
/// comparison.
#[derive(Default, Clone)]
struct Bound {
    values: HashMap<String, String>,
    cookies: Vec<String>,
}

impl Bound {
    fn learn(&mut self, body: &Json, cookies: &[String]) {
        if let Some(c) = body.get("csrf").and_then(Json::as_str) {
            if !c.is_empty() {
                self.values.insert("csrf".into(), c.into());
            }
        }
        match body.get("next").and_then(Json::as_str) {
            Some("mfa") => {
                self.values.insert(
                    "mfa".into(),
                    body["id"].as_str().unwrap_or("").into(),
                );
            }
            Some("password-change") => {
                self.values.insert(
                    "change".into(),
                    body["id"].as_str().unwrap_or("").into(),
                );
            }
            _ => {}
        }
        // A selection ticket on the address a sign-in returns to (#561).
        if let Some(at) = body.get("location").and_then(Json::as_str) {
            if let Some((_, t)) = at.split_once("sts_account=") {
                let t: String = t.chars().take_while(|c| *c != '&').collect();
                self.values.insert("ticket".into(), t);
            }
        }
        for line in cookies {
            let pair = line.split(';').next().unwrap_or("");
            if let Some((_, value)) = pair.split_once('=') {
                if value.len() > 8 {
                    self.cookies.push(value.to_string());
                }
            }
        }
    }

    fn fill(&self, text: &str, totp: &dyn Fn(f64) -> String) -> String {
        let mut out = text.to_string();
        for name in ["mfa", "change", "csrf", "authn"] {
            out = out.replace(
                &format!("{{{}}}", name),
                self.values.get(name).map(String::as_str).unwrap_or(""),
            );
        }
        if out.contains("{totpnext}") {
            out = out.replace("{totpnext}", &totp(30000.0));
        }
        if out.contains("{totp}") {
            out = out.replace("{totp}", &totp(0.0));
        }
        out
    }

    /// The text with every random value this side bound as its name, and
    /// the clock's readings (an account's `signedInAt`, `authTime`) as
    /// `<t>`.
    fn normalise(&self, text: &str) -> String {
        let times =
            regex::Regex::new(r#""(signedInAt|authTime|signedOutAt)":[0-9]+"#)
                .unwrap();
        let mut out = times.replace_all(text, "\"$1\":<t>").to_string();
        for (name, value) in &self.values {
            if value.len() > 6 {
                out = out.replace(value, &format!("<{}>", name));
            }
        }
        for value in &self.cookies {
            out = out.replace(value, "<cookie>");
        }
        out
    }
}

fn cookie_shape(line: &str, bound: &Bound) -> String {
    line.split(';')
        .map(str::trim)
        .filter(|p| !p.to_ascii_lowercase().starts_with("expires="))
        .map(|p| match p.split_once('=') {
            Some((k, v)) if !v.is_empty() && v.len() > 8 => {
                format!("{}=<v>", k)
            }
            _ => bound.normalise(p),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn headers_of(list: &[(String, String)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in list {
        h.append(
            HeaderName::from_bytes(k.as_bytes()).unwrap(),
            HeaderValue::from_str(v).unwrap(),
        );
    }
    h
}

#[tokio::test]
async fn rust_answers_every_step_as_node_did() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!("STS_CRYPTO_VECTORS is not set; no vectors to replay.");
        return;
    };
    let path = std::path::Path::new(&dir).join("authn-api-node.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        eprintln!("{} is not there; no vectors to replay.", path.display());
        return;
    };
    let doc: Json = serde_json::from_str(&text).unwrap();
    let base = doc["base"].as_str().unwrap().to_string();
    let origin = doc["origin"].as_str().unwrap().to_string();
    let host = base.trim_start_matches("http://").to_string();
    let version = doc["cases"][0]["steps"][1]["body"]["info"]["version"]
        .as_str()
        .unwrap_or("0.0.0")
        .to_string();
    let built = build(&version);
    let mut failures: Vec<String> = Vec::new();
    let mut compared = 0;
    for case in doc["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap_or("");
        if let Some(entry) = case["person"]["entry"].as_object() {
            let mut attributes = indexmap::IndexMap::new();
            for (k, v) in entry["attributes"].as_object().unwrap() {
                let values: Vec<String> = match v {
                    Json::Array(l) => l
                        .iter()
                        .map(|x| x.as_str().unwrap_or("").to_string())
                        .collect(),
                    one => vec![one.as_str().unwrap_or("").to_string()],
                };
                let values = if k == "ststotpcredential" {
                    values
                        .into_iter()
                        .map(|v| {
                            let mut t: Json = serde_json::from_str(&v).unwrap();
                            t["lastCounter"] = json!(
                                (sts_core::time::now_ms_f64() / 30_000.0)
                                    .floor()
                                    as i64
                            );
                            t.to_string()
                        })
                        .collect()
                } else {
                    values
                };
                attributes.insert(k.to_ascii_lowercase(), values);
            }
            built.directory.put(
                "default",
                StoredEntry {
                    dn: entry["dn"].as_str().unwrap().to_string(),
                    attributes,
                    origin: None,
                    created_at: None,
                    modified_at: None,
                },
            );
        }
        // The record as Node made it, its clock moved to now: the
        // recording may be older than a pending sign-in lives.
        let mut record = case["record"].clone();
        if record.is_object() {
            record["expires"] =
                json!(sts_core::time::now_ms_f64() as i64 + 600_000);
        }
        let id = record["id"].as_str().unwrap_or("").to_string();
        if !id.is_empty() {
            built.stack.signin.stores.pending.set(&id, record);
        }
        let secret =
            case["person"]["secret"].as_str().unwrap_or("").to_string();
        let signin = built.stack.signin.clone();
        // `{totp}` is the code the enrolment just spent, refused as a
        // replay; `{totpnext}` the next step's, accepted. Node's were made at
        // its clock; the entry's spent step is moved to this one, as the
        // record's expiry is, so the two codes mean here what they meant
        // there.
        let now_ms = sts_core::time::now_ms_f64();
        let totp = move |ahead: f64| {
            signin
                .credentials
                .totp()
                .code_at(&secret, Some(now_ms + ahead), None, None, None)
                .unwrap_or_default()
        };
        let mut mine = Bound::default();
        mine.values.insert("authn".into(), id.clone());
        let mut theirs = mine.clone();
        let mut jar: Vec<(String, String)> = Vec::new();
        for (n, step) in case["steps"].as_array().unwrap().iter().enumerate() {
            let request = &step["request"];
            let method = request["method"].as_str().unwrap();
            let raw_path = mine.fill(request["path"].as_str().unwrap(), &totp);
            let (path, query) = match raw_path.split_once('?') {
                Some((p, q)) => (p.to_string(), q.to_string()),
                None => (raw_path.clone(), String::new()),
            };
            let mut headers: Vec<(String, String)> =
                vec![("host".into(), host.clone())];
            for (k, v) in request["headers"].as_object().into_iter().flatten() {
                headers.push((
                    k.clone(),
                    mine.fill(v.as_str().unwrap_or(""), &totp),
                ));
            }
            if method == "POST" {
                if request["origin"] != json!(false) {
                    headers.push(("origin".into(), origin.clone()));
                }
                if request["json"] != json!(false) {
                    headers.push((
                        "content-type".into(),
                        "application/json".into(),
                    ));
                }
                if request["csrf"] != json!(false)
                    && !headers.iter().any(|(k, _)| k == "x-csrf-token")
                {
                    headers.push((
                        "x-csrf-token".into(),
                        mine.values.get("csrf").cloned().unwrap_or_default(),
                    ));
                }
            }
            if !jar.is_empty() {
                headers.push((
                    "cookie".into(),
                    jar.iter()
                        .map(|(k, v)| format!("{}={}", k, v))
                        .collect::<Vec<_>>()
                        .join("; "),
                ));
            }
            let body = if request["body"].is_null() {
                String::new()
            } else {
                mine.fill(
                    &serde_json::to_string(&request["body"]).unwrap(),
                    &totp,
                )
            };
            let header_map = headers_of(&headers);
            let (status, code, answer, cookies, csp) =
                if path.starts_with("/authn-api") {
                    let arrived = Arrived {
                        method: method.into(),
                        path: path.clone(),
                        query: query.clone(),
                        headers: header_map,
                        body,
                        base: base.clone(),
                        prefix: String::new(),
                        own_origins: vec![origin.clone()],
                        address: "127.0.0.1".into(),
                    };
                    let sent = built.stack.api.serve(&arrived).await;
                    let cookies: Vec<String> = sent
                        .headers
                        .iter()
                        .filter(|(k, _)| k == "set-cookie")
                        .map(|(_, v)| v.clone())
                        .collect();
                    let body: Json = if sent.unrouted {
                        Json::Null
                    } else {
                        serde_json::from_str(&sent.body).unwrap_or(Json::Null)
                    };
                    (
                        if sent.unrouted { 404 } else { sent.status },
                        sent.code
                            .map(|c| c.as_str().to_string())
                            .unwrap_or_default(),
                        body,
                        cookies,
                        String::new(),
                    )
                } else {
                    let m = Method::from_bytes(method.as_bytes()).unwrap();
                    let ask = sts_http::Ask {
                        method: &m,
                        path: &path,
                        query: &query,
                        headers: &header_map,
                    };
                    let response = built.shells.answer(&ask).unwrap();
                    let status = response.status().as_u16();
                    let code = sts_http::code_of(&response)
                        .map(|c| c.as_str().to_string())
                        .unwrap_or_default();
                    let cookies: Vec<String> = response
                        .headers()
                        .get_all("set-cookie")
                        .iter()
                        .map(|v| v.to_str().unwrap().to_string())
                        .collect();
                    let csp = response
                        .headers()
                        .get("content-security-policy")
                        .map(|v| v.to_str().unwrap().to_string())
                        .unwrap_or_default();
                    let bytes =
                        axum::body::to_bytes(response.into_body(), usize::MAX)
                            .await
                            .unwrap();
                    let body: Json =
                        serde_json::from_slice(&bytes).unwrap_or(Json::Null);
                    (status, code, body, cookies, csp)
                };
            for line in &cookies {
                let pair = line.split(';').next().unwrap_or("");
                if let Some((k, v)) = pair.split_once('=') {
                    jar.retain(|(name, _)| name != k);
                    if !v.is_empty() {
                        jar.push((k.to_string(), v.to_string()));
                    }
                }
            }
            mine.learn(&answer, &cookies);
            let node_cookies: Vec<String> = step["cookies"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| c.as_str().unwrap().to_string())
                .collect();
            theirs.learn(&step["body"], &node_cookies);
            let what = format!(
                "{} #{} {} {}",
                name,
                n,
                method,
                request["path"].as_str().unwrap_or("")
            );
            let node_status = step["status"].as_u64().unwrap_or(0) as u16;
            if status != node_status {
                failures.push(format!(
                    "{}: status {} where Node answered {} ({})",
                    what, status, node_status, answer
                ));
                continue;
            }
            let node_code = step["code"].as_str().unwrap_or("");
            if code != node_code {
                failures.push(format!(
                    "{}: code {:?} where Node recorded {:?}",
                    what, code, node_code
                ));
            }
            if path.starts_with("/authn-api") {
                let a = mine.normalise(&answer.to_string());
                let b = theirs.normalise(&step["body"].to_string());
                if status != 404 && a != b {
                    failures.push(format!(
                        "{}: body\n  rust {}\n  node {}",
                        what, a, b
                    ));
                }
            } else {
                let node_csp = step["csp"].as_str().unwrap_or("");
                if csp != node_csp && status == 200 {
                    failures.push(format!(
                        "{}: policy\n  rust {}\n  node {}",
                        what, csp, node_csp
                    ));
                }
            }
            let a: Vec<String> =
                cookies.iter().map(|c| cookie_shape(c, &mine)).collect();
            let b: Vec<String> = node_cookies
                .iter()
                .map(|c| cookie_shape(c, &theirs))
                .collect();
            if a != b {
                failures.push(format!(
                    "{}: cookies\n  rust {:?}\n  node {:?}",
                    what, a, b
                ));
            }
            compared += 1;
        }
    }
    eprintln!(
        "{} step(s) compared, {} difference(s)",
        compared,
        failures.len()
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
