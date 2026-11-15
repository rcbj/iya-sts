// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The authorization server's core against Node
//! (`tests/tools/oauth-vectors.js`, `oauth-node.json`): every answer Node
//! recorded, reproduced here. `STS_CRYPTO_VECTORS` names the directory,
//! never committed; without it the set is not checked.

#![allow(clippy::unwrap_used, clippy::expect_used)] // a test file

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_core::mode::Mode;
use sts_core::settings::Settings;
use sts_oauth::answer::sanitize_description;
use sts_oauth::bcp::{self, BcpMode, Question};
use sts_oauth::client_auth::{
    AssertionHistory, ClientAuth, Clock, MemoryAssertionHistory, MethodHints,
    NoAssertionKeys, Presented, Verified,
};
use sts_oauth::jwks::{
    jwks_body, jwks_keys, CertificateSources, JwksInputs, JwksPolicy,
    PinnedSigner,
};

pub fn vectors() -> Option<Json> {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: oauth-node.json is not checked"
        );
        return None;
    };
    let path = std::path::Path::new(&dir).join("oauth-node.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        eprintln!("{} is missing: not checked", path.display());
        return None;
    };
    Some(serde_json::from_str(&text).unwrap())
}

struct Pinned(i64);
impl Clock for Pinned {
    fn now_ms(&self) -> i64 {
        self.0
    }
}

pub fn settings_with(overrides: &[(&str, Json)]) -> (Arc<Settings>, Arc<Mode>) {
    let settings = Arc::new(Settings::new(Json::Null, HashMap::new()));
    for (k, v) in overrides {
        if v.is_null() {
            continue;
        }
        settings
            .restore_override(k, v.clone())
            .unwrap_or_else(|e| panic!("{} = {}: {:?}", k, v, e.problem));
    }
    let mode = Mode::shared(settings.clone());
    (settings, mode)
}

#[test]
fn sanitized_descriptions() {
    let Some(v) = vectors() else { return };
    for one in v["sanitize"].as_array().unwrap() {
        assert_eq!(
            sanitize_description(one["text"].as_str().unwrap()),
            one["sanitized"].as_str().unwrap(),
            "{}",
            one["text"]
        );
    }
}

fn s(v: &Json) -> String {
    v.as_str().unwrap_or("").to_string()
}

#[test]
fn client_authentication() {
    let Some(v) = vectors() else { return };
    let history: Arc<dyn AssertionHistory> =
        Arc::new(MemoryAssertionHistory::default());
    let mut failures = Vec::new();
    for case in v["clientAuth"].as_array().unwrap() {
        let mode_name = s(&case["mode"]);
        let (settings, mode) =
            settings_with(&[("global.mode", json!(mode_name))]);
        let auth = ClientAuth::new(
            settings,
            mode,
            history.clone(),
            Arc::new(NoAssertionKeys),
            Arc::new(Pinned(case["nowMs"].as_i64().unwrap())),
        );
        let input = &case["input"];
        let presented = Presented {
            client_id: s(&input["clientId"]),
            presented_secret: s(&input["clientSecret"]),
            assertion: s(&input["assertion"]),
            assertion_type: s(&input["assertionType"]),
            audiences: input["audiences"]
                .as_array()
                .unwrap()
                .iter()
                .map(s)
                .collect(),
            strict_audience: s(&input["strictAudience"]),
            issuer: s(&input["issuer"]),
            ..Presented::default()
        };
        let hints = MethodHints {
            assertion: presented.assertion.clone(),
            assertion_type: presented.assertion_type.clone(),
            client_secret: presented.presented_secret.clone(),
            basic: s(&input["headers"]["authorization"]).starts_with("Basic "),
            ..MethodHints::default()
        };
        let q = Question {
            presented: &presented,
            hints: &hints,
            registered: &input["registered"],
        };
        let memo = Verified::default();
        let name = format!("{} [{}]", s(&case["name"]), mode_name);
        if !case["observed"].is_null() {
            let o = bcp::observe_client_authentication(&auth, &q, &memo);
            let got = json!({
                "authenticated": o.authenticated, "method": o.method,
                "errorCode": o.code.map(|c| c.to_string()),
                "why": o.why,
            });
            let want = &case["observed"];
            let wanted = json!({
                "authenticated": want["authenticated"],
                "method": want["method"],
                "errorCode": want.get("errorCode").cloned()
                    .unwrap_or(Json::Null),
                "why": want["why"],
            });
            if got != wanted {
                failures.push(format!(
                    "{} observed\n  rust {}\n  node {}",
                    name, got, wanted
                ));
            }
        }
        let checked = bcp::check_client_authentication(
            BcpMode {
                enabled: case["bcpEnabled"].as_bool().unwrap(),
            },
            &auth,
            &q,
            &memo,
        );
        let got = match checked {
            Ok(method) if method.is_empty() => json!({ "ok": true }),
            Ok(method) => json!({ "ok": true, "method": method }),
            Err(r) => json!({
                "ok": false, "errorCode": r.code.to_string(),
                "error": r.error, "status": r.status,
                "requirement": r.requirement, "description": r.description,
            }),
        };
        if got != case["checked"] {
            failures.push(format!(
                "{} checked\n  rust {}\n  node {}",
                name, got, case["checked"]
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

struct Recorded<'a>(&'a Json);

impl CertificateSources for Recorded<'_> {
    fn published(
        &self,
        _use_case: &str,
        slot: &str,
        kid: &str,
    ) -> Option<(String, Vec<String>)> {
        let held = self.0["published"].get(format!("{}@{}", slot, kid))?;
        Some((
            s(&held["certificatePem"]),
            held["chainPem"].as_array()?.iter().map(s).collect(),
        ))
    }
    fn service_root_pem(&self) -> Option<String> {
        self.0["rootPem"].as_str().map(str::to_string)
    }
    fn pinned_signers(&self, _use_case: &str) -> Vec<PinnedSigner> {
        self.0["pinned"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|one| PinnedSigner {
                kid: s(&one["kid"]),
                kind: s(&one["kind"]),
                certificate_pem: s(&one["certificatePem"]),
                chain_pem: one["chainPem"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(s)
                    .collect(),
                public_jwk: one.get("publicJwk").cloned(),
            })
            .collect()
    }
}

#[test]
fn jwks_documents() {
    let Some(v) = vectors() else { return };
    let mut failures = Vec::new();
    for case in v["jwks"].as_array().unwrap() {
        assert!(case.get("problem").is_none(), "{}", case);
        let overrides: Vec<(&str, Json)> = case["settings"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.as_str(), v.clone()))
            .collect();
        let (settings, mode) = settings_with(&overrides);
        let policy = JwksPolicy::from_settings(&settings, &mode);
        let sources = Recorded(&case["sources"]);
        let keys = jwks_keys(&JwksInputs {
            blob: &case["blob"],
            pq_keys: None,
            sources: &sources,
            policy: &policy,
            now_ms: case["nowMs"].as_f64().unwrap(),
        })
        .unwrap();
        let body = jwks_body(keys);
        if body != s(&case["body"]) {
            failures.push(format!(
                "{}\n  rust {}\n  node {}",
                s(&case["name"]),
                body,
                s(&case["body"])
            ));
        }
        assert_eq!(s(&case["cacheControl"]), "no-store");
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn request_validation() {
    let Some(v) = vectors() else { return };
    let mut failures = Vec::new();
    for case in v["validation"].as_array().unwrap() {
        let input = case["input"].as_object().unwrap();
        let got = match sts_oauth::model::check(
            &s(&case["id"]),
            input,
            &s(&case["where"]),
        ) {
            Ok(value) => json!({ "ok": true, "value": value }),
            Err(r) => json!({ "ok": false, "code": r.code, "field": r.field,
                              "detail": r.detail }),
        };
        if got != case["answer"] {
            failures.push(format!(
                "{}\n  rust {}\n  node {}",
                case["input"], got, case["answer"]
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// OpenID4VCI's credential scopes, as Node's default configurations name
/// them.
const CREDENTIAL_SCOPES: [&str; 5] = [
    "identity_credential",
    "identity_credential_jwt",
    "identity_credential_ldp",
    "identity_credential_did",
    "identity_credential_ldp_did",
];

/// Claims held in the test.
#[derive(Default)]
struct LocalClaims(std::sync::Mutex<std::collections::HashSet<String>>);

impl sts_cluster::scheduler::Claims for LocalClaims {
    fn claim(
        &self,
        scope: &str,
        value: &str,
        realm: &str,
        _ttl_ms: f64,
    ) -> sts_cluster::schedule::BoxFuture<
        '_,
        Result<
            sts_cluster::scheduler::Claim,
            sts_cluster::scheduler::ClaimRefused,
        >,
    > {
        let key = format!("{}|{}|{}", scope, realm, value);
        let fresh = self.0.lock().unwrap().insert(key.clone());
        Box::pin(async move {
            if fresh {
                Ok(sts_cluster::scheduler::Claim {
                    claimed_at: 0.0,
                    handle: json!(key),
                })
            } else {
                Err(sts_cluster::scheduler::ClaimRefused::Held)
            }
        })
    }
    fn release(
        &self,
        handle: &Json,
    ) -> sts_cluster::schedule::BoxFuture<'_, ()> {
        if let Some(k) = handle.as_str() {
            self.0.lock().unwrap().remove(k);
        }
        Box::pin(async {})
    }
}

struct NoPeople;
impl sts_oauth::token_endpoint::People for NoPeople {
    fn user_for(&self, username: &str) -> Json {
        json!({ "username": username })
    }
    fn name_for_subject(&self, _sub: &str) -> Option<String> {
        None
    }
    fn has_subject_resolver(&self) -> bool {
        false
    }
}

struct NoSessions;
impl sts_oauth::token_endpoint::GrantSessions for NoSessions {
    fn ended(&self, _sid: &str) -> String {
        "ended".into()
    }
}

struct RecordedClients(Json);

impl sts_oauth::clients::Clients for RecordedClients {
    // This service's own objects are seeded in every realm.
    fn seeded(&self, identifier: &str) -> bool {
        identifier.starts_with("sts-")
    }
    fn client_config_of(&self, client_id: &str) -> Json {
        self.0
            .get(client_id)
            .cloned()
            .unwrap_or_else(sts_oauth::clients::unknown_client)
    }
    fn declared_flows_of(&self, client_id: &str) -> Option<Json> {
        self.0
            .get(format!("{}:flows", client_id))
            .filter(|v| !v.is_null())
            .cloned()
    }
}

/// The parts of a token response that do not vary from run to run: the
/// claims with `jti`, the instants and the status index held to their
/// shape, and the signature dropped.
fn steady(decoded: &Json) -> Json {
    let mut out = decoded.clone();
    let claims = &mut out["claims"];
    if let Some(c) = claims.as_object_mut() {
        let iat = c.get("iat").and_then(Json::as_i64).unwrap_or(0);
        for k in ["iat", "nbf", "exp"] {
            if let Some(v) = c.get(k).and_then(Json::as_i64) {
                c.insert(k.into(), json!(v - iat));
            }
        }
        if let Some(jti) = c.get("jti").and_then(Json::as_str) {
            c.insert("jti".into(), json!(format!("<{} chars>", jti.len())));
        }
        if c.contains_key("status") {
            c["status"]["status_list"]["idx"] = json!("<idx>");
        }
    }
    out
}

fn decode(jwt: &str) -> Json {
    json!({
        "header": sts_oauth::js::segment_json(jwt, 0).unwrap(),
        "claims": sts_oauth::js::segment_json(jwt, 1).unwrap(),
    })
}

#[tokio::test]
async fn token_endpoint() {
    let Some(v) = vectors() else { return };
    let cases = v["token"].as_array().unwrap();
    let mut failures = Vec::new();
    let mut compared = 0;
    for realm_row in cases.iter().filter(|c| c.get("clients").is_some()) {
        let realm = s(&realm_row["realm"]);
        let mode_name = s(&realm_row["mode"]);
        let (settings, mode) =
            settings_with(&[("global.mode", json!(mode_name))]);
        let set = Arc::new(sts_store::key_sets::KeySet {
            realm: realm.clone(),
            blob: realm_row["blob"].clone(),
        });
        let registry = Arc::new(sts_core::realm::RealmRegistry::new(Arc::new(
            sts_core::realm::SettingsEnvironment::new(
                settings.clone(),
                Vec::new(),
            ),
        )));
        let lifecycle = sts_core::realm_lifecycle::RealmLifecycle::new(
            registry,
            settings.clone(),
            mode.clone(),
        );
        let handles = sts_core::realm_store::StoreHandles::new();
        let revoked = sts_oauth::revocation::RevokedTokens::new(
            &lifecycle,
            &handles,
            settings.clone(),
        );
        let register = sts_oauth::minted::TokenRegister::new(
            &lifecycle,
            &handles,
            settings.clone(),
            revoked,
        );
        let history: Arc<dyn AssertionHistory> =
            Arc::new(MemoryAssertionHistory::default());
        let clients: Arc<dyn sts_oauth::clients::Clients> =
            Arc::new(RecordedClients(realm_row["clients"].clone()));
        let grants = sts_oauth::grants::GrantStores::declare(
            &lifecycle,
            &handles,
            settings.clone(),
        );
        let dpop = sts_oauth::dpop_stores::DpopStores::new(
            &lifecycle,
            &handles,
            settings.clone(),
            Arc::new(|| chrono::Utc::now().timestamp()),
        );
        for case in cases
            .iter()
            .filter(|c| s(&c["realm"]) == realm && c.get("clients").is_none())
        {
            let clock = Arc::new(Pinned(case["nowMs"].as_i64().unwrap()));
            let auth = Arc::new(ClientAuth::new(
                settings.clone(),
                mode.clone(),
                history.clone(),
                Arc::new(NoAssertionKeys),
                clock.clone(),
            ));
            let endpoint = sts_oauth::token_endpoint::TokenEndpoint {
                settings: settings.clone(),
                mode: mode.clone(),
                clients: clients.clone(),
                auth,
                register: register.clone(),
                status: Arc::new(
                    sts_oauth::token_endpoint::LocalStatusList::default(),
                ),
                signer: Arc::new(sts_oauth::token_endpoint::KeySetSigner {
                    set: set.clone(),
                }),
                clock,
                id_tokens: None,
                scopes: Arc::new(sts_oauth::scopes::ScopePolicy {
                    settings: settings.clone(),
                    mode: mode.clone(),
                    clients: clients.clone(),
                    credential_scopes: CREDENTIAL_SCOPES
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                }),
                grants: grants.clone(),
                claims: Arc::new(LocalClaims::default()),
                dpop: dpop.clone(),
                gated: Arc::new(sts_oauth::authorize::NoGatedScopes),
                people: Arc::new(NoPeople),
                sessions: Arc::new(NoSessions),
                limits: None,
                passwords: None,
                used: None,
                records: None,
                requested: None,
                delegation: None,
                acts: None,
                devices: None,
            };
            let form: Vec<(String, String)> = case["form"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), s(v)))
                .collect();
            let ask = sts_oauth::token_endpoint::TokenAsk {
                base: s(&case["base"]),
                body: sts_oauth::js::form_encode(&form),
                authorization: s(&case["headers"]["authorization"]),
                ..Default::default()
            };
            let answer = endpoint.answer(&ask).await;
            compared += 1;
            let name = format!("{} [{}]", s(&case["name"]), mode_name);
            let mut got_headers = serde_json::Map::new();
            for h in ["content-type", "cache-control", "www-authenticate"] {
                if let Some(value) = answer.header(h) {
                    got_headers.insert(h.into(), json!(value));
                }
            }
            let mut want_headers = case["responseHeaders"].clone();
            want_headers.as_object_mut().unwrap().remove("pragma");
            let mut got_body =
                answer.json_body().cloned().unwrap_or(Json::Null);
            let mut want_body = case["body"].clone();
            let mut got_token = Json::Null;
            let mut want_token = Json::Null;
            if let Some(at) =
                got_body.get("access_token").and_then(Json::as_str)
            {
                got_token = steady(&decode(at));
                got_body["access_token"] = json!("<token>");
            }
            if let Some(at) =
                want_body.get("access_token").and_then(Json::as_str)
            {
                // Node's signature verifies under the realm's key, its
                // lifetime read at the instant the token was minted (a
                // vector set older than the token's life is not stale).
                let checks = sts_crypto::jws::ClaimChecks {
                    now: case["accessToken"]["claims"]["iat"]
                        .as_i64()
                        .or_else(|| case["nowMs"].as_i64().map(|ms| ms / 1000)),
                    ..sts_crypto::jws::ClaimChecks::default()
                };
                set.verify_own_jws(
                    at,
                    None,
                    &checks,
                    sts_crypto::keys::KeyPolicy::STRICT,
                    "",
                    0.0,
                )
                .unwrap_or_else(|e| panic!("{}: {}", name, e));
                want_token = steady(&case["accessToken"]);
                want_body["access_token"] = json!("<token>");
            }
            let got = json!({ "status": answer.status, "headers": got_headers,
                              "body": got_body, "token": got_token });
            let want = json!({ "status": case["status"], "headers": want_headers,
                               "body": want_body, "token": want_token });
            if got != want {
                failures
                    .push(format!("{}\n  rust {}\n  node {}", name, got, want));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert_eq!(compared, 22, "every recorded token request is compared");
}

/// Node's sealed refresh tokens open here; with `STS_WRITE_VECTORS=1`,
/// `oauth-rust.json` carries a refresh token sealed here and an access
/// token signed here, for `tests/rust_crypto_vectors.js` to read in Node.
#[test]
fn refresh_tokens_both_ways() {
    let Some(v) = vectors() else { return };
    let mut written = Vec::new();
    for row in v["token"].as_array().unwrap() {
        let Some(refresh) = row.get("refresh") else {
            continue;
        };
        let keys = &row["blob"]["refreshTokenEncKeys"];
        let opened =
            sts_oauth::refresh_crypto::open(&s(&refresh["sealed"]), keys)
                .unwrap();
        assert_eq!(opened, s(&refresh["jws"]));
        // A token of another realm is refused, with Node's code.
        let other = sts_oauth::refresh_crypto::open(&s(&refresh["jws"]), keys);
        assert_eq!(
            other.unwrap_err().code,
            sts_core::errors::codes::STS_OAUTH_0237
        );
        let jws =
            format!("{}.rust", s(&refresh["jws"]).rsplit_once('.').unwrap().0);
        let sealed =
            sts_oauth::refresh_crypto::seal(&jws, keys, "A256KW", "A256GCM")
                .unwrap();
        let set = sts_store::key_sets::KeySet {
            realm: s(&row["realm"]),
            blob: row["blob"].clone(),
        };
        let signer =
            sts_oauth::token_endpoint::KeySetSigner { set: Arc::new(set) };
        use sts_oauth::token_endpoint::Signer;
        let claims = json!({ "iss": "https://as.vectors.example",
                             "sub": "rust", "typ": "Bearer",
                             "jti": format!("rust-{}", s(&row["realm"])),
                             "iat": 1, "exp": 4_102_444_800i64 });
        let token = signer
            .sign(claims.as_object().unwrap(), "at+jwt", "RS256")
            .unwrap();
        written.push(json!({ "realm": row["realm"], "blob": row["blob"],
                             "jws": jws, "sealed": sealed,
                             "accessToken": token, "claims": claims }));
    }
    assert_eq!(written.len(), 2);
    if std::env::var("STS_WRITE_VECTORS").as_deref() == Ok("1") {
        let dir = std::env::var("STS_CRYPTO_VECTORS").unwrap();
        std::fs::write(
            std::path::Path::new(&dir).join("oauth-rust.json"),
            serde_json::to_string_pretty(&json!({ "realms": written }))
                .unwrap(),
        )
        .unwrap();
    }
}
