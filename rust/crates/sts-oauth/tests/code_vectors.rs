// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The code flow against Node (`tests/tools/oauth-vectors.js`'s
//! `codeVectors()`, the `code` set of `oauth-node.json`): every
//! authorization request Node answered is answered here over the same
//! session row and clients — the status, the address (with the code and
//! the pending id held to their shape), the body, the code's stored
//! record member for member and the pending sign-in; then every token
//! request, with Node's own DPoP proofs, and the tokens compared claim for
//! claim. Node's refresh token is opened and verified here. With
//! `STS_WRITE_VECTORS=1`, `oauth-code-rust.json` carries what Rust sealed
//! and signed for `tests/rust_crypto_vectors.js` to read in Node.
//!
//! What Node does that this runtime refuses instead (the consent screen,
//! a token from the authorization endpoint, the HTTP layer's query check)
//! is listed in `KNOWN`, and Rust is held to the documented answer.

#![allow(clippy::unwrap_used, clippy::expect_used)] // a test file

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Map, Value as Json};
use sts_authn::ports::Request;
use sts_core::mode::Mode;
use sts_core::settings::Settings;
use sts_oauth::authorize::{
    AuthorizationEndpoint, AuthorizeAsk, CatalogPages, NoGatedScopes, SignOn,
};
use sts_oauth::client_auth::{
    AssertionHistory, ClientAuth, Clock, MemoryAssertionHistory,
    NoAssertionKeys,
};
use sts_oauth::signin::{AccountChoices, EveryMechanism, PendingSignIns};

/// How long ago a code was redeemed, by each runtime's own clock.
static REDEEMED_AGO: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| {
        regex::Regex::new(r"redeemed \d+ second").unwrap()
    });

fn vectors() -> Option<Json> {
    let dir = std::env::var("STS_CRYPTO_VECTORS").ok()?;
    let text = std::fs::read_to_string(
        std::path::Path::new(&dir).join("oauth-node.json"),
    )
    .ok()?;
    Some(serde_json::from_str(&text).unwrap())
}

fn s(v: &Json) -> String {
    sts_oauth::js::string_of(Some(v))
}

/// What Node answers that this runtime answers otherwise, by design: the
/// case, and what Rust answers instead.
const KNOWN: [(&str, &str); 7] = [
    ("an unknown client", "consent"),
    ("a protected scope", "consent"),
    ("consent needed", "consent"),
    ("response_type token", "implicit"),
    ("a malformed query", "http"),
    ("code, public, no PKCE", "refusal-page"),
    ("code, plain PKCE", "refusal-page"),
];

struct Pinned(Arc<Mutex<i64>>);
impl Clock for Pinned {
    fn now_ms(&self) -> i64 {
        *self.0.lock().unwrap()
    }
}

struct VecSignOn {
    cookie: String,
    session: Json,
}

impl SignOn for VecSignOn {
    fn session_of(&self, request: &Request) -> Option<Json> {
        (!self.cookie.is_empty() && request.cookie == self.cookie)
            .then(|| self.session.clone())
    }
    fn note_presented(&self, _: &str, _: &Request, _: &str) {}
    fn hold_presentation(&self, _: &str) {}
    fn note_client(&self, _: &str, _: &str, _: &str, _: &str) {}
    fn hint_account(&self, _: &Request, _: &str) {}
    fn account_choice_needed(&self, _: &Request) -> Option<Json> {
        None
    }
    fn note_account_ambiguous(&self, _: &Request, _: &str) {}
}

/// Nobody has consented to anything, and nothing is written.
struct NoEntries;
impl sts_oauth::consent::ConsentDirectory for NoEntries {
    fn values_of(&self, _: &str, _: &str) -> Option<Vec<String>> {
        Some(Vec::new())
    }
    fn add_values(
        &self,
        _: &str,
        _: &str,
        _: &[String],
    ) -> Result<bool, String> {
        Ok(true)
    }
    fn name_for_subject(&self, _: &str) -> String {
        String::new()
    }
}

struct NoChoices(f64);
impl AccountChoices for NoChoices {
    fn pending_ttl_ms(&self) -> f64 {
        self.0
    }
    fn begin_account_choice(
        &self,
        _: &Request,
        _: &str,
        _: bool,
    ) -> Option<(String, Option<String>)> {
        None
    }
    fn route_to_accounts(
        &self,
        existing: Option<Map<String, Json>>,
        _: &Json,
        target: &str,
        _: &str,
        _: &Request,
    ) -> (Map<String, Json>, String) {
        (existing.unwrap_or_default(), target.to_string())
    }
}

/// The clients as Node answered for them.
struct Facts(Json);

impl Facts {
    fn of(&self, id: &str) -> &Json {
        &self.0[id]
    }
}

impl sts_oauth::clients::Clients for Facts {
    fn client_config_of(&self, client_id: &str) -> Json {
        match self.of(client_id).get("config") {
            Some(c) if c.get("known") == Some(&json!(true)) => c.clone(),
            _ => sts_oauth::clients::unknown_client(),
        }
    }
    fn declared_flows_of(&self, client_id: &str) -> Option<Json> {
        self.of(client_id)
            .get("flows")
            .filter(|f| !f.is_null())
            .cloned()
    }
    fn allowed_scopes_of(&self, client_id: &str) -> Option<Vec<String>> {
        self.of(client_id)
            .get("allowedScopes")
            .and_then(Json::as_array)
            .map(|l| l.iter().map(s).collect())
    }
    fn global_consents_of(&self, client_id: &str) -> Vec<String> {
        self.of(client_id)
            .get("globalConsents")
            .and_then(Json::as_array)
            .map(|l| l.iter().map(s).collect())
            .unwrap_or_default()
    }
    fn is_client_id(&self, name: &str) -> bool {
        self.of(name)
            .get("config")
            .is_some_and(|c| c["known"] == json!(true))
    }
    fn registered_by(&self, client_id: &str) -> String {
        s(&self.of(client_id)["entry"]["registeredBy"])
    }
    fn seeded(&self, identifier: &str) -> bool {
        identifier.starts_with("sts-")
    }
}

struct LocalClaims(Mutex<std::collections::HashSet<String>>);
impl sts_cluster::scheduler::Claims for LocalClaims {
    fn claim(
        &self,
        scope: &str,
        value: &str,
        realm: &str,
        _ttl: f64,
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

struct Person(Json);
impl sts_oauth::token_endpoint::People for Person {
    fn user_for(&self, _username: &str) -> Json {
        self.0.clone()
    }
    fn name_for_subject(&self, sub: &str) -> Option<String> {
        (s(&self.0["sub"]) == sub).then(|| s(&self.0["username"]))
    }
    fn has_subject_resolver(&self) -> bool {
        true
    }
}

struct Live;
impl sts_oauth::token_endpoint::GrantSessions for Live {
    fn ended(&self, _sid: &str) -> String {
        String::new()
    }
}

fn settings_for(mode: &str) -> (Arc<Settings>, Arc<Mode>) {
    let settings = Arc::new(Settings::new(Json::Null, HashMap::new()));
    settings
        .restore_override("global.mode", json!(mode))
        .unwrap();
    // `env/npm-tests.js`, the appconfig the vectors were made under.
    settings
        .restore_override("oauth2.allowConfidentialWithoutPkce", json!(true))
        .unwrap();
    if mode == "product" {
        settings
            .restore_override(
                "oauth2.consentAlwaysForPublicClients",
                json!(false),
            )
            .unwrap();
    }
    let m = Mode::shared(settings.clone());
    (settings, m)
}

/// The address with the code, the pending id and the realm's prefix held
/// to their shape.
fn steady_location(location: &str, realm: &str) -> String {
    let prefix = format!("/realm/{}", realm);
    let mut out = location
        .strip_prefix(&prefix)
        .unwrap_or(location)
        .to_string();
    for name in ["code=", "authn=", "consent="] {
        if let Some(at) = out.find(name) {
            let start = at + name.len();
            let end = out[start..]
                .find(['&', '#'])
                .map_or(out.len(), |e| start + e);
            out.replace_range(start..end, "<id>");
        }
    }
    out
}

fn steady_claims(claims: &Json) -> Json {
    let mut c = claims.clone();
    if let Some(o) = c.as_object_mut() {
        let iat = o.get("iat").and_then(Json::as_i64).unwrap_or(0);
        for k in ["iat", "nbf", "exp", "chain_iat"] {
            if let Some(v) = o.get(k).and_then(Json::as_i64) {
                o.insert(k.into(), json!(v - iat));
            }
        }
        for k in ["jti", "at_hash", "refresh_family", "sid"] {
            if let Some(v) = o.get(k).and_then(Json::as_str) {
                o.insert(k.into(), json!(format!("<{} chars>", v.len())));
            }
        }
        if o.contains_key("grant_at") {
            o.insert("grant_at".into(), json!("<ms>"));
        }
        if o.contains_key("status") {
            o["status"]["status_list"]["idx"] = json!("<idx>");
        }
    }
    c
}

fn steady_record(record: &Json) -> Json {
    let mut r = record.clone();
    if let Some(o) = r.as_object_mut() {
        // Node reads the clock once for each: `expires` may be a
        // millisecond past `granted_at` + `ttlMs`.
        let at = o.get("granted_at").and_then(Json::as_i64).unwrap_or(0);
        let ttl = o.get("ttlMs").and_then(Json::as_i64).unwrap_or(0);
        if let Some(e) = o.get("expires").and_then(Json::as_i64) {
            o.insert("expires".into(), json!((e - at - ttl).abs() <= 2));
        }
        o.insert("granted_at".into(), json!("<ms>"));
    }
    r
}

fn steady_pending(record: &Json) -> Json {
    let mut r = record.clone();
    if let Some(o) = r.as_object_mut() {
        o.insert("id".into(), json!("<id>"));
        o.insert("expires".into(), json!("<ms>"));
    }
    r
}

fn decode(jwt: &str) -> Json {
    sts_oauth::js::segment_json(jwt, 1).unwrap_or(Json::Null)
}

#[tokio::test]
async fn the_code_flow() {
    let Some(v) = vectors() else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: the code flow is not checked"
        );
        return;
    };
    let Some(cases) = v["code"].as_array() else {
        return;
    };
    let catalogs = Arc::new(sts_http::i18n::Catalogs::load(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../common/locales"),
    ));
    let mut failures: Vec<String> = Vec::new();
    let mut compared = 0;
    let mut written: Vec<Json> = Vec::new();
    for realm_row in cases.iter().filter(|c| c.get("facts").is_some()) {
        let realm = s(&realm_row["realm"]);
        let mode_name = s(&realm_row["mode"]);
        let (settings, mode) = settings_for(&mode_name);
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
        let clients: Arc<dyn sts_oauth::clients::Clients> =
            Arc::new(Facts(realm_row["facts"].clone()));
        let grants = sts_oauth::grants::GrantStores::declare(
            &lifecycle,
            &handles,
            settings.clone(),
        );
        let scopes = Arc::new(sts_oauth::scopes::ScopePolicy {
            settings: settings.clone(),
            mode: mode.clone(),
            clients: clients.clone(),
            credential_scopes: [
                "identity_credential",
                "identity_credential_jwt",
                "identity_credential_ldp",
                "identity_credential_did",
                "identity_credential_ldp_did",
            ]
            .iter()
            .map(|x| x.to_string())
            .collect(),
        });
        let pending: sts_core::realm_store::RealmMap<Json> =
            sts_core::realm_store::RealmMap::new(
                &lifecycle,
                &handles,
                sts_core::realm_store::StoreSpec::memory(),
            );
        let now = Arc::new(Mutex::new(0i64));
        let n1 = now.clone();
        let n2 = now.clone();
        let metadata = cases
            .iter()
            .find(|c| {
                c["kind"] == "metadata"
                    && s(&c["realm"]) == realm
                    && s(&c["name"])
                        == "/.well-known/oauth-authorization-server"
            })
            .map(|c| c["body"].clone())
            .unwrap_or(Json::Null);
        let endpoint = AuthorizationEndpoint {
            settings: settings.clone(),
            mode: mode.clone(),
            clients: clients.clone(),
            scopes: scopes.clone(),
            grants: grants.clone(),
            sign_on: Arc::new(VecSignOn {
                cookie: s(&realm_row["cookie"]),
                session: realm_row["session"].clone(),
            }),
            hand_off: Arc::new(PendingSignIns {
                sessions: Arc::new(NoChoices(10.0 * 60.0 * 1000.0)),
                pending: pending.clone(),
                settings: settings.clone(),
                mechanisms: Arc::new(EveryMechanism),
                random_id: Arc::new(|n| {
                    sts_crypto::b64::encode(
                        &sts_crypto::random::random_bytes(n).unwrap(),
                    )
                }),
                now_ms: Arc::new(move || *n1.lock().unwrap() as f64),
            }),
            gated: Arc::new(NoGatedScopes),
            consent: Some(Arc::new(sts_oauth::consent::ConsentScreen {
                register: Arc::new(sts_oauth::consent::ConsentRegister {
                    settings: settings.clone(),
                    clients: clients.clone(),
                    directory: Arc::new(NoEntries),
                    answers: sts_core::realm_store::RealmMap::new(
                        &lifecycle,
                        &handles,
                        sts_core::realm_store::StoreSpec::memory(),
                    ),
                    now_ms: Arc::new(|| 0.0),
                }),
                pending: sts_core::realm_store::RealmMap::new(
                    &lifecycle,
                    &handles,
                    sts_core::realm_store::StoreSpec::memory(),
                ),
                sign_on: Arc::new(VecSignOn {
                    cookie: s(&realm_row["cookie"]),
                    session: realm_row["session"].clone(),
                }),
                client_display: Arc::new(|_| Json::Null),
                random_id: Arc::new(|n| {
                    sts_crypto::b64::encode(
                        &sts_crypto::random::random_bytes(n).unwrap(),
                    )
                }),
            })),
            request_objects: None,
            tokens: None,
            pairwise: None,
            pages: Arc::new(CatalogPages {
                catalogs: catalogs.clone(),
                footer: sts_http::footer::Facts {
                    version: String::new(),
                    build_info: String::new(),
                    year: String::new(),
                },
                incident: Arc::new(|| 0),
            }),
            signer: None,
            capabilities: Arc::new(move |_base| metadata.clone()),
            now_ms: Arc::new(move || *n2.lock().unwrap() as f64),
            random_id: Arc::new(|n| {
                sts_crypto::b64::encode(
                    &sts_crypto::random::random_bytes(n).unwrap(),
                )
            }),
        };
        // ---- The authorization endpoint ----------------------------------
        let mut rust_codes: HashMap<String, String> = HashMap::new();
        for case in cases
            .iter()
            .filter(|c| c["kind"] == "authorize" && s(&c["realm"]) == realm)
        {
            let name = s(&case["name"]);
            *now.lock().unwrap() = case["nowMs"].as_i64().unwrap();
            let query: Vec<(String, String)> = case["query"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), s(v)))
                .collect();
            let ask = AuthorizeAsk {
                method: "GET".into(),
                query: sts_oauth::js::form_encode(&query),
                accept: "application/json".into(),
                base: s(&case["base"]),
                request: Request {
                    cookie: s(&case["cookie"]),
                    ..Request::default()
                },
                ..AuthorizeAsk::default()
            };
            let answer = endpoint.answer(&ask);
            compared += 1;
            let label = format!("{} [{}]", name, mode_name);
            let location = answer.header("location").unwrap_or("").to_string();
            if let Some((_, how)) = KNOWN.iter().find(|(n, _)| *n == name) {
                let node_location = s(&case["location"]);
                let known = match *how {
                    // The consent screen: Node's address carries the realm's
                    // prefix, which the HTTP layer puts on here.
                    "consent" if node_location.contains("/oauth2/consent") => {
                        location.contains("/oauth2/consent?consent=")
                            || location.contains("error=invalid_scope")
                    }
                    "implicit" => {
                        location.contains("error=unsupported_response_type")
                    }
                    "http" => true,
                    "refusal-page" => {
                        answer.status == case["status"].as_u64().unwrap() as u16
                            || location.contains("error=")
                    }
                    _ => false,
                };
                if !known
                    && steady_location(&location, &realm)
                        != steady_location(&node_location, &realm)
                {
                    failures.push(format!(
                        "{}: known difference, but\n  rust {} {}\n  node {} {}",
                        label,
                        answer.status,
                        location,
                        case["status"],
                        node_location
                    ));
                }
                continue;
            }
            let got_body = match &answer.body {
                sts_oauth::answer::Body::Json(j) => j.clone(),
                // The HTTP layer puts the realm's prefix on a page's links.
                sts_oauth::answer::Body::Html(h) => {
                    json!(sts_http::with_realm_links(
                        h,
                        &format!("/realm/{}", realm)
                    ))
                }
                sts_oauth::answer::Body::Raw(t) => json!(t),
                sts_oauth::answer::Body::Empty => Json::Null,
            };
            let mut want_body = case["body"].clone();
            if want_body == json!("") {
                want_body = Json::Null;
            }
            let mut got_body = got_body;
            let code = rust_location_code(&location, &got_body);
            if let (Some(c), true) = (&code, case["code"].is_string()) {
                rust_codes.insert(name.clone(), c.clone());
                let node_code = s(&case["code"]);
                if let Json::String(h) = &mut got_body {
                    *h = h.replace(c.as_str(), "<code>");
                }
                if let Json::String(h) = &mut want_body {
                    *h = h.replace(&node_code, "<code>");
                }
            }
            if let Json::String(h) = &want_body {
                if h.starts_with("Found.") || h.starts_with("Redirecting") {
                    want_body = Json::Null;
                }
            }
            let got = json!({ "status": answer.status,
                "location": steady_location(&location, &realm),
                "body": got_body });
            let want = json!({ "status": case["status"],
                "location": steady_location(&s(&case["location"]), &realm),
                "body": want_body });
            if got != want {
                failures.push(format!(
                    "{}\n  rust {}\n  node {}",
                    label, got, want
                ));
            }
            // The code's record, member for member.
            if let (Some(c), Some(node_record)) =
                (&code, case.get("record").filter(|r| !r.is_null()))
            {
                let key = sts_crypto::secrets::credential_digest(c).unwrap();
                let held = grants.codes.get(&key).unwrap_or(Json::Null);
                if steady_record(&held) != steady_record(node_record) {
                    failures.push(format!(
                        "{} (the record)\n  rust {}\n  node {}",
                        label,
                        steady_record(&held),
                        steady_record(node_record)
                    ));
                }
            }
            // The pending sign-in.
            if let Some(node_pending) =
                case.get("pending").filter(|p| !p.is_null())
            {
                let id = location
                    .split(['?', '#', '&'])
                    .find_map(|p| p.strip_prefix("authn="))
                    .unwrap_or("")
                    .to_string();
                let held = pending.get(&id).unwrap_or(Json::Null);
                if steady_pending(&held) != steady_pending(node_pending) {
                    failures.push(format!(
                        "{} (the pending sign-in)\n  rust {}\n  node {}",
                        label,
                        steady_pending(&held),
                        steady_pending(node_pending)
                    ));
                }
            }
        }
        // ---- The token endpoint -----------------------------------------
        let set = Arc::new(sts_store::key_sets::KeySet {
            realm: realm.clone(),
            blob: realm_row["blob"].clone(),
        });
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
        let clock = Arc::new(Pinned(now.clone()));
        let n3 = now.clone();
        let signer: Arc<dyn sts_oauth::token_endpoint::Signer> =
            Arc::new(sts_oauth::token_endpoint::KeySetSigner {
                set: set.clone(),
            });
        let tokens = sts_oauth::token_endpoint::TokenEndpoint {
            settings: settings.clone(),
            mode: mode.clone(),
            clients: clients.clone(),
            auth: Arc::new(ClientAuth::new(
                settings.clone(),
                mode.clone(),
                history,
                Arc::new(NoAssertionKeys),
                clock.clone(),
            )),
            register,
            status: Arc::new(
                sts_oauth::token_endpoint::LocalStatusList::default(),
            ),
            signer: signer.clone(),
            clock,
            id_tokens: Some(Arc::new(sts_oauth::id_token::CoreIdTokens {
                settings: settings.clone(),
                clients: clients.clone(),
                signer: signer.clone(),
                now_s: Arc::new(move || *n3.lock().unwrap() / 1000),
                pairwise: None,
            })),
            scopes,
            grants: grants.clone(),
            claims: Arc::new(LocalClaims(Mutex::new(Default::default()))),
            dpop: sts_oauth::dpop_stores::DpopStores::new(
                &lifecycle,
                &handles,
                settings.clone(),
                Arc::new(|| chrono::Utc::now().timestamp()),
            ),
            gated: Arc::new(NoGatedScopes),
            people: Arc::new(Person(realm_row["user"].clone())),
            sessions: Arc::new(Live),
            limits: None,
            passwords: None,
            used: None,
            records: None,
        };
        // ---- Discovery ---------------------------------------------------
        for case in cases
            .iter()
            .filter(|c| c["kind"] == "metadata" && s(&c["realm"]) == realm)
        {
            compared += 1;
            let ui: Vec<String> =
                catalogs.offered().iter().map(|o| s(&o["tag"])).collect();
            let inputs = sts_oauth::metadata::MetadataInputs {
                settings: &settings,
                mode: &mode,
                base: &s(&case["base"]),
                ui_locales: ui,
                grant_types: tokens.grant_types_supported(),
                mtls_available: true,
                realm_base: &s(&case["base"]),
            };
            // Both documents (#444 phase 5, the `oauth3` slice: the OpenID
            // Connect members of `oidcMetadata()`).
            let doc = if s(&case["name"]) == "/.well-known/openid-configuration"
            {
                sts_oauth::metadata::oidc_metadata(&inputs, None)
            } else {
                sts_oauth::metadata::as_metadata(&inputs)
            };
            let mut want = case["body"].clone();
            let signed = want
                .as_object_mut()
                .unwrap()
                .remove("signed_metadata")
                .unwrap_or(Json::Null);
            if doc != want {
                for (k, v) in want.as_object().unwrap() {
                    if doc.get(k) != Some(v) {
                        failures.push(format!(
                            "metadata [{} {}] {}\n  rust {}\n  node {}",
                            mode_name,
                            s(&case["name"]),
                            k,
                            doc.get(k).unwrap_or(&Json::Null),
                            v
                        ));
                    }
                }
                let extra: Vec<&String> = doc
                    .as_object()
                    .unwrap()
                    .keys()
                    .filter(|k| want.get(k.as_str()).is_none())
                    .collect();
                if !extra.is_empty() {
                    failures.push(format!(
                        "metadata [{} {}] extra {:?}",
                        mode_name,
                        s(&case["name"]),
                        extra
                    ));
                }
                let order: Vec<&String> =
                    doc.as_object().unwrap().keys().collect();
                let node_order: Vec<&String> =
                    want.as_object().unwrap().keys().collect();
                if order != node_order {
                    failures.push(format!(
                        "metadata [{} {}] order\n  rust {:?}\n  node {:?}",
                        mode_name,
                        s(&case["name"]),
                        order,
                        node_order
                    ));
                }
            }
            let claims = sts_oauth::metadata::signed_metadata_claims(&doc, 0);
            let node_claims = decode(&s(&signed));
            let mine: Vec<&String> = claims.keys().collect();
            let theirs: Vec<&String> = node_claims
                .as_object()
                .map(|o| o.keys().collect())
                .unwrap_or_default();
            if mine != theirs {
                failures.push(format!(
                    "signed_metadata [{}] members\n  rust {:?}\n  node {:?}",
                    mode_name, mine, theirs
                ));
            }
        }
        let mut swapped: HashMap<String, String> = HashMap::new();
        for case in cases
            .iter()
            .filter(|c| c["kind"] == "token" && s(&c["realm"]) == realm)
        {
            let name = s(&case["name"]);
            let label = format!("{} [{}]", name, mode_name);
            *now.lock().unwrap() = case["nowMs"].as_i64().unwrap();
            // Node's code record, seeded under its digest.
            if let Some(record) =
                case.get("codeRecord").filter(|r| !r.is_null())
            {
                let key = sts_crypto::secrets::credential_digest(&s(
                    &case["form"]["code"]
                ))
                .unwrap();
                grants.codes.set(&key, record.clone());
            }
            let mut form: Vec<(String, String)> = case["form"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), s(v)))
                .collect();
            for (k, val) in form.iter_mut() {
                if k == "refresh_token" {
                    if let Some(r) = swapped.get(val.as_str()) {
                        *val = r.clone();
                    }
                }
            }
            let dpop = case["headers"].get("dpop").map(s);
            let ask = sts_oauth::token_endpoint::TokenAsk {
                base: s(&case["base"]),
                body: sts_oauth::js::form_encode(&form),
                authorization: s(&case["headers"]["authorization"]),
                dpop,
                htu: format!("{}/oauth2/token", s(&case["base"])),
                ..Default::default()
            };
            let answer = tokens.answer(&ask).await;
            compared += 1;
            let got_body = answer.json_body().cloned().unwrap_or(Json::Null);
            let want_body = case["body"].clone();
            let mut got = got_body.clone();
            let mut want = want_body.clone();
            for b in [&mut got, &mut want] {
                if let Some(d) =
                    b.get("error_description").and_then(Json::as_str)
                {
                    if let Some(at) = d.find("(it has been up ") {
                        let end = d[at..].find(')').map_or(d.len(), |e| at + e);
                        let cut = format!("{}(uptime{}", &d[..at], &d[end..]);
                        b["error_description"] = json!(cut);
                    }
                }
                // How long ago is each runtime's own clock.
                if let Some(d) =
                    b.get("error_description").and_then(Json::as_str)
                {
                    let d = REDEEMED_AGO
                        .replace_all(d, "redeemed N second")
                        .to_string();
                    b["error_description"] = json!(d);
                }
                for k in ["access_token", "refresh_token", "id_token"] {
                    if b.get(k).is_some() {
                        b[k] = json!("<token>");
                    }
                }
            }
            if answer.status != case["status"].as_u64().unwrap() as u16
                || got != want
            {
                failures.push(format!(
                    "{}\n  rust {} {}\n  node {} {}",
                    label, answer.status, got, case["status"], want
                ));
                continue;
            }
            for (k, node_claims) in [
                (
                    "access_token",
                    case.get("accessToken").map(|t| t["claims"].clone()),
                ),
                ("id_token", case.get("idToken").map(|t| t["claims"].clone())),
            ] {
                let Some(node_claims) = node_claims.filter(|c| !c.is_null())
                else {
                    continue;
                };
                let rust_claims = decode(&s(&got_body[k]));
                if steady_claims(&rust_claims) != steady_claims(&node_claims) {
                    failures.push(format!(
                        "{} ({})\n  rust {}\n  node {}",
                        label,
                        k,
                        steady_claims(&rust_claims),
                        steady_claims(&node_claims)
                    ));
                }
            }
            if let (Some(node_rt), Some(rust_rt)) = (
                want_body.get("refresh_token").map(s),
                got_body.get("refresh_token").map(s),
            ) {
                swapped.insert(node_rt.clone(), rust_rt.clone());
                let keys = &realm_row["blob"]["refreshTokenEncKeys"];
                let rust_jws =
                    sts_oauth::refresh_crypto::open(&rust_rt, keys).unwrap();
                let rust_claims = decode(&rust_jws);
                let node_claims = case["refreshClaims"].clone();
                if steady_claims(&rust_claims) != steady_claims(&node_claims) {
                    failures.push(format!(
                        "{} (refresh_token)\n  rust {}\n  node {}",
                        label,
                        steady_claims(&rust_claims),
                        steady_claims(&node_claims)
                    ));
                }
                // NODE'S refresh token opens and verifies here.
                let node_jws =
                    sts_oauth::refresh_crypto::open(&node_rt, keys).unwrap();
                // Node signed it as it answered, a moment after the case's
                // instant was read.
                let verified = signer.verify_own(
                    &node_jws,
                    case["nowMs"].as_i64().unwrap() / 1000 + 5,
                );
                assert_eq!(
                    verified.as_ref().map(|c| c["jti"].clone()).ok(),
                    Some(node_claims["jti"].clone()),
                    "{}: Node's refresh token verifies here",
                    label
                );
                written.push(
                    json!({ "realm": realm, "blob": realm_row["blob"],
                    "jws": rust_jws, "sealed": rust_rt,
                    "accessToken": s(&got_body["access_token"]),
                    "claims": decode(&s(&got_body["access_token"])) }),
                );
            }
        }
    }
    if std::env::var("STS_WRITE_VECTORS").as_deref() == Ok("1") {
        let dir = std::env::var("STS_CRYPTO_VECTORS").unwrap();
        std::fs::write(
            std::path::Path::new(&dir).join("oauth-code-rust.json"),
            serde_json::to_string_pretty(&json!({ "realms": written }))
                .unwrap(),
        )
        .unwrap();
    }
    assert!(
        failures.is_empty(),
        "{} of {} differ:\n{}",
        failures.len(),
        compared,
        failures.join("\n")
    );
    assert!(
        compared > 50,
        "every recorded request is compared ({})",
        compared
    );
}

/// The code the answer carries: in its address, or a form_post's field.
fn rust_location_code(location: &str, body: &Json) -> Option<String> {
    for part in location.split(['?', '#', '&']) {
        if let Some(c) = part.strip_prefix("code=") {
            return Some(c.to_string());
        }
    }
    let html = body.as_str()?;
    let at =
        html.find("name=\"code\" value=\"")? + "name=\"code\" value=\"".len();
    let end = html[at..].find('"')? + at;
    Some(html[at..end].to_string())
}
