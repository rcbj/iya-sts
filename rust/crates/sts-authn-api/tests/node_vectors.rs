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
        records: None,
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

/// The software authenticators the recording names: an ES256 key each,
/// signed with here as Node signed with it there.
struct Authenticators {
    keys: Json,
    origin: String,
    rp_id: String,
}

fn sha256(data: &[u8]) -> Vec<u8> {
    sts_crypto::jws_alg::Hash::Sha256.digest(data)
}

fn b64u(data: &[u8]) -> String {
    sts_crypto::b64::encode(data)
}

fn unb64u(text: &str) -> Vec<u8> {
    sts_crypto::b64::decode_loose(text).unwrap()
}

/// r||s as an ASN.1 `Ecdsa-Sig-Value`, as a WebAuthn authenticator sends
/// an ES256 signature.
fn der_of(raw: &[u8]) -> Vec<u8> {
    let int = |b: &[u8]| {
        let mut v: Vec<u8> = b.iter().copied().skip_while(|x| *x == 0).collect();
        if v.is_empty() || v[0] & 0x80 != 0 {
            v.insert(0, 0);
        }
        let mut out = vec![0x02, v.len() as u8];
        out.extend(v);
        out
    };
    let (r, s) = raw.split_at(raw.len() / 2);
    let mut body = int(r);
    body.extend(int(s));
    let mut out = vec![0x30, body.len() as u8];
    out.extend(body);
    out
}

/// The few CBOR shapes a registration carries.
enum Cbor {
    Int(i64),
    Text(String),
    Bytes(Vec<u8>),
    Map(Vec<(Cbor, Cbor)>),
}

fn cbor_head(major: u8, n: u64) -> Vec<u8> {
    let m = major << 5;
    if n < 24 {
        vec![m | n as u8]
    } else if n < 256 {
        vec![m | 24, n as u8]
    } else if n < 65536 {
        vec![m | 25, (n >> 8) as u8, n as u8]
    } else {
        let mut v = vec![m | 26];
        v.extend((n as u32).to_be_bytes());
        v
    }
}

fn cbor(value: &Cbor) -> Vec<u8> {
    match value {
        Cbor::Int(n) if *n >= 0 => cbor_head(0, *n as u64),
        Cbor::Int(n) => cbor_head(1, (-1 - *n) as u64),
        Cbor::Text(t) => {
            let mut v = cbor_head(3, t.len() as u64);
            v.extend(t.as_bytes());
            v
        }
        Cbor::Bytes(b) => {
            let mut v = cbor_head(2, b.len() as u64);
            v.extend(b);
            v
        }
        Cbor::Map(entries) => {
            let mut v = cbor_head(5, entries.len() as u64);
            for (k, x) in entries {
                v.extend(cbor(k));
                v.extend(cbor(x));
            }
            v
        }
    }
}

impl Authenticators {
    fn key(&self, who: &str) -> &Json {
        &self.keys[who]
    }

    fn assertion(&self, who: &str, count: u32, spoil: &str, bound: &Bound) -> String {
        let a = self.key(who);
        let flags: u8 = if spoil == "nouv" { 0x01 } else { 0x05 };
        let mut auth = sha256(self.rp_id.as_bytes());
        auth.push(flags);
        auth.extend(count.to_be_bytes());
        let client = serde_json::to_vec(&json!({
            "type": "webauthn.get",
            "challenge": bound.values.get("challenge").cloned().unwrap_or_default(),
            "origin": self.origin, "crossOrigin": false })).unwrap();
        let mut signed = auth.clone();
        signed.extend(sha256(&client));
        let key = sts_crypto::keys::JwsKey::from_jwk(&a["privateJwk"]).unwrap();
        let raw = sts_crypto::jws::sign_input("ES256", &key, &signed).unwrap();
        let mut signature = der_of(&raw);
        if spoil == "badsig" {
            let last = signature.len() - 1;
            signature[last] ^= 0x01;
        }
        let handle = match spoil {
            "stranger" => a["strangerHandle"].as_str().unwrap_or("").to_string(),
            "nohandle" => String::new(),
            _ => a["userHandle"].as_str().unwrap_or("").to_string(),
        };
        let id = a["credentialId"].as_str().unwrap_or("");
        json!({ "id": id, "rawId": id, "type": "public-key",
            "authenticatorAttachment": "platform",
            "response": { "authenticatorData": b64u(&auth),
                "clientDataJSON": b64u(&client),
                "signature": b64u(&signature), "userHandle": handle },
            "clientExtensionResults": {} })
        .to_string()
    }

    fn registration(&self, who: &str, bound: &Bound) -> String {
        let a = self.key(who);
        let jwk = &a["privateJwk"];
        let cose = Cbor::Map(vec![
            (Cbor::Int(1), Cbor::Int(2)),
            (Cbor::Int(3), Cbor::Int(-7)),
            (Cbor::Int(-1), Cbor::Int(1)),
            (Cbor::Int(-2), Cbor::Bytes(unb64u(jwk["x"].as_str().unwrap()))),
            (Cbor::Int(-3), Cbor::Bytes(unb64u(jwk["y"].as_str().unwrap()))),
        ]);
        let id_text = a["credentialId"].as_str().unwrap_or("");
        let id = unb64u(id_text);
        let mut auth = sha256(self.rp_id.as_bytes());
        auth.push(0x45);
        auth.extend([0u8; 4]);
        auth.extend([0u8; 16]);
        auth.extend((id.len() as u16).to_be_bytes());
        auth.extend(&id);
        auth.extend(cbor(&cose));
        let client = serde_json::to_vec(&json!({
            "type": "webauthn.create",
            "challenge": bound.values.get("challenge").cloned().unwrap_or_default(),
            "origin": self.origin, "crossOrigin": false })).unwrap();
        let object = cbor(&Cbor::Map(vec![
            (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
            (Cbor::Text("attStmt".into()), Cbor::Map(Vec::new())),
            (Cbor::Text("authData".into()), Cbor::Bytes(auth)),
        ]));
        json!({ "id": id_text, "rawId": id_text, "type": "public-key",
            "authenticatorAttachment": "platform",
            "response": { "attestationObject": b64u(&object),
                "clientDataJSON": b64u(&client), "transports": ["internal"] },
            "clientExtensionResults": { "credProps": { "rk": true } } })
        .to_string()
    }

    /// The ceremony placeholders filled, each a JSON text inside the JSON
    /// string the body carries.
    fn fill(&self, text: &str, bound: &Bound) -> String {
        let re = regex::Regex::new(
            r"\{assert:([a-z0-9]+):([0-9]+)(?::([a-z]+))?\}|\{register:([a-z0-9]+)\}",
        )
        .unwrap();
        re.replace_all(text, |c: &regex::Captures| {
            let made = match c.get(4) {
                Some(who) => self.registration(who.as_str(), bound),
                None => self.assertion(
                    &c[1],
                    c[2].parse().unwrap_or(0),
                    c.get(3).map_or("", |m| m.as_str()),
                    bound,
                ),
            };
            let quoted = serde_json::to_string(&Json::String(made)).unwrap();
            quoted[1..quoted.len() - 1].to_string()
        })
        .to_string()
    }
}

impl Bound {
    fn learn(&mut self, body: &Json, cookies: &[String]) {
        // A ceremony's challenge and the handle a registration is made
        // under; a set-up step's secret.
        let challenge = body
            .get("challenge")
            .or_else(|| body.get("view").and_then(|v| v.get("webauthn")).and_then(|w| w.get("challenge")))
            .and_then(Json::as_str)
            .unwrap_or("");
        if !challenge.is_empty() {
            self.values.insert("challenge".into(), challenge.into());
        }
        if let Some(id) = body.get("user").and_then(|u| u.get("id")).and_then(Json::as_str) {
            if !id.is_empty() {
                self.values.insert("userid".into(), id.into());
            }
        }
        if let Some(secret) = body
            .get("view")
            .and_then(|v| v.get("setup"))
            .and_then(|s| s.get("totp"))
            .and_then(|t| t.get("secret"))
            .and_then(Json::as_str)
        {
            self.values.insert("totpgrouped".into(), secret.into());
            self.values.insert("totpsecret".into(), secret.replace(' ', ""));
        }
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

    fn fill(
        &self,
        text: &str,
        totp: &dyn Fn(f64) -> String,
        setup: &dyn Fn(&str) -> String,
        keys: &Authenticators,
    ) -> String {
        let mut out = keys.fill(text, self);
        if out.contains("{totpsetup}") {
            out = out.replace(
                "{totpsetup}",
                &setup(self.values.get("totpsecret").map_or("", String::as_str)),
            );
        }
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
        let mut values: Vec<(&String, &String)> = self.values.iter().collect();
        values.sort_by_key(|(_, v)| std::cmp::Reverse(v.len()));
        for (name, value) in values {
            if value.len() > 6 {
                out = out.replace(value.as_str(), &format!("<{}>", name));
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
    let keys = Authenticators {
        keys: doc["authenticators"].clone(),
        origin: origin.clone(),
        rp_id: url::Url::parse(&base)
            .unwrap()
            .host_str()
            .unwrap()
            .to_string(),
    };
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
        let signin2 = built.stack.signin.clone();
        let setup = move |secret: &str| {
            signin2
                .credentials
                .totp()
                .code_at(secret, None, None, None, None)
                .unwrap_or_default()
        };
        let mut mine = Bound::default();
        mine.values.insert("authn".into(), id.clone());
        let mut theirs = mine.clone();
        let mut jar: Vec<(String, String)> = Vec::new();
        for (n, step) in case["steps"].as_array().unwrap().iter().enumerate() {
            let request = &step["request"];
            let method = request["method"].as_str().unwrap();
            let raw_path = mine.fill(
                request["path"].as_str().unwrap(),
                &totp,
                &setup,
                &keys,
            );
            let (path, query) = match raw_path.split_once('?') {
                Some((p, q)) => (p.to_string(), q.to_string()),
                None => (raw_path.clone(), String::new()),
            };
            let mut headers: Vec<(String, String)> =
                vec![("host".into(), host.clone())];
            for (k, v) in request["headers"].as_object().into_iter().flatten() {
                headers.push((
                    k.clone(),
                    mine.fill(v.as_str().unwrap_or(""), &totp, &setup, &keys),
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
                    &setup,
                    &keys,
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
