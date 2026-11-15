// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE AUTHORIZATION SERVER IN THE RUNTIME (`common/protocol_stack.ts`'s
//! `9`, `oauth-oidc/oauth2`): `sts-oauth`'s endpoints over what the runtime
//! holds, and their routes.
//!
//! | Route | Answered by |
//! |---|---|
//! | `GET`, `POST /oauth2/authorize` | [`AuthorizationEndpoint`] |
//! | `POST /oauth2/token` | [`TokenEndpoint`] |
//! | `GET /.well-known/oauth-authorization-server`, `/.well-known/openid-configuration` | [`sts_oauth::metadata`], with `signed_metadata` |
//! | `GET /oauth2/autopost.js` | the `form_post` page's one script |
//!
//! WHAT EACH PORT IS ANSWERED WITH:
//!
//! * the clients are the APPLICATION REGISTER (`sts-registers`) over the
//!   embedded directory's model (`sts-directory`), loaded from the live
//!   directory once the store has opened and again whenever the store
//!   applies a change — so what a 1.x install registered is what this
//!   authorization server serves;
//! * the session, its doors and the pending sign-in are the session core's
//!   and the sign-in surface's (`sts-authn`, `sts-authn-api`): the one
//!   `Sessions` and the one `authn.pending` store the sign-in stack built;
//! * the person is the live directory's (`userFor()`, the subject
//!   resolver) through the sign-in stack's `DirectoryPorts`;
//! * the codes, the transactions, the refresh families, the token register,
//!   the revoked-token register and DPoP's nonces and history are declared
//!   here, under Node's handles, before the store opens;
//! * every token is signed with the AMBIENT realm's key set, read as the
//!   JWKS reads it; the claims are the cluster's (one process here);
//! * the scopes a resource gates by role are not narrowed here yet (the
//!   role register is not in the runtime): `/admin-api`'s gate holds the
//!   person to a role authorizing each scope itself (`STS-API-0125`);
//!   nobody's consent is recorded but the applications' global consent.

use std::sync::{Arc, Mutex};

use axum::extract::Request as AxumRequest;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde_json::{json, Map, Value as Json};
use sts_core::mode::Mode;
use sts_core::realm::RealmRegistry;
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{RealmMap, StoreHandles};
use sts_core::settings::Settings;
use sts_directory::Directory;
use sts_oauth::authorize::{
    AuthorizationEndpoint, AuthorizeAsk, CatalogPages, NoConsents,
    NoGatedScopes,
};
use sts_oauth::client_auth::{ClientAuth, MemoryAssertionHistory, SystemClock};
use sts_oauth::clients::RegisterClients;
use sts_oauth::token_endpoint::{Signer, TokenAsk, TokenEndpoint};
use sts_registers::applications::AppEnv;
use sts_registers::applications::ApplicationRegistry;
use sts_store::key_sets::KeySets;
use sts_store::persistence::{LiveDirectory, MemoryDirectory, Persistence};

/// `AUTOPOST_SCRIPT`: submits the `form_post` page's form.
const AUTOPOST_SCRIPT: &str = "(function () {\n  var f = document.getElementById(\"oauth2-form\");\n  if (f) { f.submit(); }\n})();\n";

/// What the composition root hands [`OAuthStack::declare`].
pub struct OAuthParts {
    pub settings: Arc<Settings>,
    pub mode: Arc<Mode>,
    pub registry: Arc<RealmRegistry>,
    pub lifecycle: Arc<RealmLifecycle>,
    pub handles: Arc<StoreHandles>,
    pub persistence: Arc<Persistence>,
    pub live: Arc<MemoryDirectory>,
    pub sessions: Arc<sts_authn::Sessions>,
    /// The page footer's facts, for the error page (#1326).
    pub footer: sts_http::footer::Facts,
    pub pending: RealmMap<Json>,
    pub people: Arc<dyn sts_authn::ports::People>,
    pub catalogs: Arc<sts_http::i18n::Catalogs>,
    /// The token register the stack declared, which sign-out revokes in.
    pub tokens: Arc<sts_oauth::minted::TokenRegister>,
}

/// The authorization server, built.
pub struct OAuthStack {
    pub settings: Arc<Settings>,
    pub mode: Arc<Mode>,
    pub registry: Arc<RealmRegistry>,
    pub persistence: Arc<Persistence>,
    pub live: Arc<MemoryDirectory>,
    pub directory: Arc<Mutex<Directory>>,
    pub catalogs: Arc<sts_http::i18n::Catalogs>,
    pub authorize: Arc<AuthorizationEndpoint>,
    pub tokens: Arc<TokenEndpoint>,
    pub sessions: Arc<sts_authn::Sessions>,
}

/// The ambient realm's key set, as the JWKS reads it.
struct RealmSigner(Arc<Persistence>);

impl RealmSigner {
    fn set(&self) -> Result<sts_store::key_sets::KeySet, String> {
        let sets: Arc<KeySets> = self
            .0
            .key_sets()
            .ok_or_else(|| "no key set is held for this realm".to_string())?;
        sets.open(&sts_core::realm::current_id())
            .ok_or_else(|| "no key set is held for this realm".to_string())
    }
}

impl Signer for RealmSigner {
    fn sign(
        &self,
        payload: &Map<String, Json>,
        typ: &str,
        alg: &str,
    ) -> Result<String, String> {
        sts_oauth::token_endpoint::KeySetSigner {
            set: Arc::new(self.set()?),
        }
        .sign(payload, typ, alg)
    }

    fn refresh_keys(&self) -> Json {
        self.set()
            .map(|s| s.blob["refreshTokenEncKeys"].clone())
            .unwrap_or(Json::Null)
    }

    fn verify_own(&self, token: &str, now_s: i64) -> Result<Json, String> {
        sts_oauth::token_endpoint::KeySetSigner {
            set: Arc::new(self.set()?),
        }
        .verify_own(token, now_s)
    }
}

/// THE REGISTER'S ENVIRONMENT WITH THE STORE'S DATA KEYS. `CoreEnv` opens
/// nothing, and in product mode with persisted keys Node seals every client
/// secret it writes (`sealCredentialText()`): a client a Node beside this
/// one registered then had "nothing on its entry to verify" here, and its
/// secret was refused. The register only READS through this one — this
/// runtime writes no application yet — so `seal()` is the keystore's as well
/// for when it does.
struct SealingEnv {
    core: sts_registers::applications::env::CoreEnv,
    persistence: Arc<Persistence>,
}

impl AppEnv for SealingEnv {
    fn now_ms(&self) -> i64 {
        self.core.now_ms()
    }
    fn setting(&self, key: &str) -> Json {
        self.core.setting(key)
    }
    fn mode(&self, predicate: &str) -> bool {
        self.core.mode(predicate)
    }
    fn parse_as(&self, key: &str, raw: &str) -> Result<Json, String> {
        self.core.parse_as(key, raw)
    }
    fn allows_value(&self, key: &str, value: &Json) -> bool {
        self.core.allows_value(key, value)
    }
    fn write_refusal_reason(&self, key: &str) -> String {
        self.core.write_refusal_reason(key)
    }
    fn random_bytes(&self, n: usize) -> Vec<u8> {
        self.core.random_bytes(n)
    }
    fn sha256_hex(&self, text: &str) -> String {
        self.core.sha256_hex(text)
    }
    fn is_sealed(&self, value: &str) -> bool {
        self.core.is_sealed(value)
    }
    fn keystore_persists(&self) -> bool {
        sts_store::keystore::DataKeys::persists(
            &self.core.settings,
            &self.core.mode,
        )
    }
    fn seals_client_secrets(&self) -> bool {
        self.keystore_persists() && self.persistence.data_keys().sealed()
    }
    fn seal(&self, text: &str, label: &str) -> Option<String> {
        self.persistence.data_keys().seal(
            text,
            label,
            &sts_core::realm::current_id(),
        )
    }
    fn open(&self, text: &str, label: &str) -> Option<String> {
        self.persistence.data_keys().open(text, label)
    }
    fn in_force(&self, key: &str, value: &Json) -> Json {
        self.core.in_force(key, value)
    }
}

/// The person, from the live directory.
struct Directories(Arc<dyn sts_authn::ports::People>);

impl sts_oauth::token_endpoint::People for Directories {
    fn user_for(&self, username: &str) -> Json {
        self.0.user_for(username)
    }
    fn name_for_subject(&self, sub: &str) -> Option<String> {
        Some(self.0.name_for_subject(sub)).filter(|n| !n.is_empty())
    }
    fn has_subject_resolver(&self) -> bool {
        self.0.has_subject_resolver()
    }
}

/// The handed-in sessions, read by id.
struct GrantSessionsOf(Arc<sts_authn::Sessions>);

impl sts_oauth::token_endpoint::GrantSessions for GrantSessionsOf {
    fn ended(&self, sid: &str) -> String {
        sts_oauth::token_endpoint::GrantSessions::ended(self.0.as_ref(), sid)
    }
}

/// The cluster's claims of one process: held here until they lapse.
#[derive(Default)]
struct ProcessClaims(Mutex<std::collections::HashMap<String, f64>>);

impl sts_cluster::scheduler::Claims for ProcessClaims {
    fn claim(
        &self,
        scope: &str,
        value: &str,
        realm: &str,
        ttl_ms: f64,
    ) -> sts_cluster::schedule::BoxFuture<
        '_,
        Result<
            sts_cluster::scheduler::Claim,
            sts_cluster::scheduler::ClaimRefused,
        >,
    > {
        let now = sts_core::time::now_ms_f64();
        let key = format!("{}|{}|{}", scope, realm, value);
        let mut held = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        held.retain(|_, until| *until > now);
        let answer = if held.contains_key(&key) {
            Err(sts_cluster::scheduler::ClaimRefused::Held)
        } else {
            held.insert(key.clone(), now + ttl_ms.max(1.0));
            Ok(sts_cluster::scheduler::Claim {
                claimed_at: now,
                handle: Json::String(key),
            })
        };
        Box::pin(async move { answer })
    }

    fn release(
        &self,
        handle: &Json,
    ) -> sts_cluster::schedule::BoxFuture<'_, ()> {
        if let Some(key) = handle.as_str() {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(key);
        }
        Box::pin(async {})
    }
}

fn header_of(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// The random identifiers Node's `randomId()` mints: base64url.
fn random_id(n: usize) -> String {
    sts_crypto::b64::encode(
        &sts_crypto::random::random_bytes(n).unwrap_or_default(),
    )
}

impl OAuthStack {
    /// Builds the endpoints, declaring their stores (before the store
    /// opens).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn declare(parts: OAuthParts) -> Arc<OAuthStack> {
        let settings = parts.settings.clone();
        let mode = parts.mode.clone();
        let domain = settings.value_of("global.domain");
        let root = sts_core::realm::base_dn_of_domain(domain.as_str());
        let directory = Arc::new(Mutex::new(Directory::new(&root)));
        let apps = Arc::new(ApplicationRegistry::new(
            Some(directory.clone()),
            Arc::new(SealingEnv {
                core: sts_registers::applications::env::CoreEnv {
                    settings: settings.clone(),
                    mode: mode.clone(),
                },
                persistence: parts.persistence.clone(),
            }),
            Arc::new(sts_registers::applications::env::NoEffects),
        ));
        let accepts = mode.clone();
        let clients: Arc<dyn sts_oauth::clients::Clients> =
            Arc::new(RegisterClients {
                registry: apps,
                now_s: Arc::new(|| chrono::Utc::now().timestamp()),
                accepts_unregistered: Arc::new(move || {
                    accepts.accepts_unregistered_addresses()
                }),
            });
        let grants = sts_oauth::grants::GrantStores::declare(
            &parts.lifecycle,
            &parts.handles,
            settings.clone(),
        );
        // The stack's one token register (one declaration per handle):
        // the session core revokes through the same one at sign-out.
        let register = parts.tokens.clone();
        let dpop = sts_oauth::dpop_stores::DpopStores::new(
            &parts.lifecycle,
            &parts.handles,
            settings.clone(),
            Arc::new(|| chrono::Utc::now().timestamp()),
        );
        let scopes = Arc::new(sts_oauth::scopes::ScopePolicy {
            settings: settings.clone(),
            mode: mode.clone(),
            clients: clients.clone(),
            // OpenID4VCI's default configurations (phase 9's family).
            credential_scopes: [
                "identity_credential",
                "identity_credential_jwt",
                "identity_credential_ldp",
                "identity_credential_did",
                "identity_credential_ldp_did",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        });
        let signer: Arc<dyn Signer> =
            Arc::new(RealmSigner(parts.persistence.clone()));
        let tokens = Arc::new(TokenEndpoint {
            settings: settings.clone(),
            mode: mode.clone(),
            clients: clients.clone(),
            auth: Arc::new(ClientAuth::new(
                settings.clone(),
                mode.clone(),
                Arc::new(MemoryAssertionHistory::default()),
                Arc::new(sts_oauth::client_auth::NoAssertionKeys),
                Arc::new(SystemClock),
            )),
            register,
            status: Arc::new(
                sts_oauth::token_endpoint::LocalStatusList::default(),
            ),
            signer: signer.clone(),
            clock: Arc::new(SystemClock),
            id_tokens: Some(Arc::new(sts_oauth::id_token::CoreIdTokens {
                settings: settings.clone(),
                clients: clients.clone(),
                signer: signer.clone(),
                now_s: Arc::new(|| chrono::Utc::now().timestamp()),
            })),
            scopes: scopes.clone(),
            grants: grants.clone(),
            claims: Arc::new(ProcessClaims::default()),
            dpop,
            gated: Arc::new(NoGatedScopes),
            people: Arc::new(Directories(parts.people.clone())),
            sessions: Arc::new(GrantSessionsOf(parts.sessions.clone())),
        });
        let for_caps = (settings.clone(), mode.clone(), parts.catalogs.clone());
        let grant_list = tokens.grant_types_supported();
        let authorize = Arc::new(AuthorizationEndpoint {
            settings: settings.clone(),
            mode: mode.clone(),
            clients: clients.clone(),
            scopes,
            grants,
            sign_on: parts.sessions.clone(),
            hand_off: Arc::new(sts_oauth::signin::PendingSignIns {
                sessions: parts.sessions.clone(),
                pending: parts.pending.clone(),
                settings: settings.clone(),
                mechanisms: Arc::new(sts_oauth::signin::EveryMechanism),
                random_id: Arc::new(random_id),
                now_ms: Arc::new(sts_core::time::now_ms_f64),
            }),
            gated: Arc::new(NoGatedScopes),
            consents: Arc::new(NoConsents),
            pages: Arc::new(CatalogPages {
                catalogs: parts.catalogs.clone(),
                footer: parts.footer.clone(),
                // The runtime writes its audit rows to the log (`LogAudit`):
                // no ring, so no incident ID to reserve.
                incident: Arc::new(|| 0),
            }),
            signer: Some(signer.clone()),
            capabilities: Arc::new(move |base: &str| {
                let (settings, mode, catalogs) = &for_caps;
                sts_oauth::metadata::as_metadata(
                    &sts_oauth::metadata::MetadataInputs {
                        settings,
                        mode,
                        base,
                        ui_locales: offered(catalogs),
                        grant_types: grant_list.clone(),
                        mtls_available: settings
                            .value_of("global.https")
                            .as_bool(),
                    },
                )
            }),
            now_ms: Arc::new(sts_core::time::now_ms_f64),
            random_id: Arc::new(random_id),
        });
        Arc::new(OAuthStack {
            settings,
            mode,
            registry: parts.registry,
            persistence: parts.persistence,
            live: parts.live,
            directory,
            catalogs: parts.catalogs,
            authorize,
            tokens,
            sessions: parts.sessions,
        })
    }

    /// The application register's directory, refilled from the live one:
    /// every realm's tree, as the store restored it. Called once the store
    /// has opened, and before each request reads a client.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn reload_directory(&self) {
        let domain = self.settings.value_of("global.domain");
        let mut fresh = Directory::new(&sts_core::realm::base_dn_of_domain(
            domain.as_str(),
        ));
        for realm in self.registry.list() {
            if realm.id != sts_core::realm::DEFAULT_ID {
                fresh.add_realm(&realm.id, &self.registry.base_dn_of(&realm));
            }
            let entries: Vec<_> =
                self.live.realm_entries(&realm.id).into_values().collect();
            fresh.restore(&realm.id, entries);
        }
        *self
            .directory
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = fresh;
    }

    /// The ambient realm's key set, made where it has none yet, before an
    /// endpoint signs with it.
    async fn ensure_keys(&self) {
        if let Some(sets) = self.persistence.key_sets() {
            if let Err(e) =
                sets.open_or_make(&sts_core::realm::current_id()).await
            {
                tracing::error!(
                    "{}oauth2: the realm's key set could not be read: {}",
                    sts_core::log::tag(sts_core::errors::codes::STS_OAUTH_0184),
                    e
                );
            }
        }
    }
}

/// A method nobody routed on these paths: Express's `Cannot <METHOD>`
/// 404, as Node answers it (axum would say 405).
async fn unrouted(request: AxumRequest) -> Response {
    let (parts, _) = request.into_parts();
    sts_http::not_found(parts.method, parts.uri, None).await
}

impl OAuthStack {
    /// The routes, for the runtime's router.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn router(
        self: &Arc<Self>,
        http: Arc<sts_http::HttpLayer>,
    ) -> axum::Router {
        let routes = axum::Router::new();
        let me = self.clone();
        let h = http.clone();
        let routes = routes.route(
            "/oauth2/authorize",
            axum::routing::get({
                let (me, h) = (me.clone(), h.clone());
                move |r: AxumRequest| {
                    let (me, h) = (me.clone(), h.clone());
                    async move { me.authorize(h, r).await }
                }
            })
            .post({
                let (me, h) = (me.clone(), h.clone());
                move |r: AxumRequest| {
                    let (me, h) = (me.clone(), h.clone());
                    async move { me.authorize(h, r).await }
                }
            })
            .fallback(unrouted),
        );
        let routes = routes.route(
            "/oauth2/token",
            axum::routing::post({
                let (me, h) = (me.clone(), h.clone());
                move |r: AxumRequest| {
                    let (me, h) = (me.clone(), h.clone());
                    async move { me.token(h, r).await }
                }
            })
            .fallback(unrouted),
        );
        let routes = routes.route(
            "/.well-known/oauth-authorization-server",
            axum::routing::get({
                let (me, h) = (me.clone(), h.clone());
                move |r: AxumRequest| {
                    let (me, h) = (me.clone(), h.clone());
                    async move { me.metadata(h, r).await }
                }
            }),
        );
        let routes = routes.route(
            "/.well-known/openid-configuration",
            axum::routing::get({
                let (me, h) = (me.clone(), h.clone());
                move |r: AxumRequest| {
                    let (me, h) = (me.clone(), h.clone());
                    async move { me.metadata(h, r).await }
                }
            }),
        );
        routes.route(
            "/oauth2/autopost.js",
            axum::routing::get(|| async {
                let mut response = (
                    axum::http::StatusCode::OK,
                    [
                        (
                            axum::http::header::CONTENT_TYPE,
                            "application/javascript; charset=utf-8",
                        ),
                        (axum::http::header::CACHE_CONTROL, "no-store"),
                    ],
                    AUTOPOST_SCRIPT,
                )
                    .into_response();
                if let Ok(v) = axum::http::HeaderValue::from_str(
                    &sts_http::csp::content_security_policy(&[
                        ("style-src", None),
                        ("img-src", None),
                    ]),
                ) {
                    response.headers_mut().insert("content-security-policy", v);
                }
                response
            }),
        )
    }

    fn arrived(
        &self,
        http: &sts_http::HttpLayer,
        request: &AxumRequest,
    ) -> (String, HeaderMap, String, String) {
        let over_tls = request
            .extensions()
            .get::<sts_http::cookie_wire::OverTls>()
            .is_some();
        let peer = request
            .extensions()
            .get::<sts_http::client_address::Peer>()
            .copied();
        let headers = request.headers().clone();
        let prefix = http.registry().current_prefix();
        let base = sts_authn_api::router::base_of(
            &self.settings,
            &headers,
            over_tls,
            &prefix,
        );
        let address = http.client_address_of(&headers, peer.as_ref());
        let body = request
            .extensions()
            .get::<sts_http::body::ParsedBody>()
            .and_then(|b| b.text.clone())
            .unwrap_or_default();
        (base, headers, address, body)
    }

    async fn authorize(
        self: Arc<Self>,
        http: Arc<sts_http::HttpLayer>,
        request: AxumRequest,
    ) -> Response {
        self.reload_directory();
        self.ensure_keys().await;
        let (base, headers, address, body) = self.arrived(&http, &request);
        let url = match request.uri().query() {
            Some(q) => format!("{}?{}", request.uri().path(), q),
            None => request.uri().path().to_string(),
        };
        let mut session_request = sts_authn::ports::Request {
            cookie: header_of(&headers, "cookie"),
            user_agent: header_of(&headers, "user-agent"),
            address,
            url,
            ..sts_authn::ports::Request::default()
        };
        session_request.accounts.lock().response_open = true;
        self.sessions.spend_account_ticket(&mut session_request);
        let query = session_request
            .url
            .split_once('?')
            .map(|(_, q)| q.to_string())
            .unwrap_or_default();
        let ask = AuthorizeAsk {
            method: request.method().to_string(),
            content_type: header_of(&headers, "content-type"),
            query,
            body,
            accept: header_of(&headers, "accept"),
            accept_language: header_of(&headers, "accept-language"),
            base,
            prefix: http.registry().current_prefix(),
            request: session_request.clone(),
        };
        // `/oauth2/authorize` IS AN ARRIVAL PATH (`ARRIVAL_PATHS`): a
        // browser that arrives with no `sts_session` is given an arrival
        // session, which the sign-in it is sent to binds its step to.
        self.sessions.touch_arrival_session(&session_request);
        let mut arrival = sts_authn::ports::Response::default();
        if self
            .sessions
            .cookie_session(
                Some(&session_request),
                sts_authn_api::door::SESSION_COOKIE,
            )
            .is_none()
            && self
                .sessions
                .start_arrival_session(
                    &session_request,
                    &mut arrival,
                    "arrival",
                )
                .is_none()
        {
            tracing::debug!("oauth2: no arrival session was started.");
        }
        let answer = self.authorize.answer(&ask);
        let mut response = answer.into_response();
        for line in arrival.cookies {
            if let Ok(v) = axum::http::HeaderValue::from_str(&line) {
                response
                    .headers_mut()
                    .append(axum::http::header::SET_COOKIE, v);
            }
        }
        // What the session core queued on the request (an account set's
        // cookie, #561).
        for line in session_request.accounts.lock().appended.drain(..) {
            if let Ok(v) = axum::http::HeaderValue::from_str(&line) {
                response
                    .headers_mut()
                    .append(axum::http::header::SET_COOKIE, v);
            }
        }
        response
    }

    async fn token(
        self: Arc<Self>,
        http: Arc<sts_http::HttpLayer>,
        request: AxumRequest,
    ) -> Response {
        self.reload_directory();
        self.ensure_keys().await;
        let (base, headers, _address, body) = self.arrived(&http, &request);
        let ask = TokenAsk {
            base: base.clone(),
            body,
            authorization: header_of(&headers, "authorization"),
            dpop: headers
                .get("dpop")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string),
            htu: format!("{}/oauth2/token", base),
            ..TokenAsk::default()
        };
        fn sendable<T: Send>(t: T) -> T {
            t
        }
        sendable(self.tokens.answer(&ask)).await.into_response()
    }

    async fn metadata(
        self: Arc<Self>,
        http: Arc<sts_http::HttpLayer>,
        request: AxumRequest,
    ) -> Response {
        self.ensure_keys().await;
        let (base, _, _, _) = self.arrived(&http, &request);
        let mut doc = sts_oauth::metadata::as_metadata(
            &sts_oauth::metadata::MetadataInputs {
                settings: &self.settings,
                mode: &self.mode,
                base: &base,
                ui_locales: offered(&self.catalogs),
                grant_types: self.tokens.grant_types_supported(),
                mtls_available: self
                    .settings
                    .value_of("global.https")
                    .as_bool(),
            },
        );
        let claims = sts_oauth::metadata::signed_metadata_claims(
            &doc,
            chrono::Utc::now().timestamp(),
        );
        match RealmSigner(self.persistence.clone())
            .sign(&claims, "JWT", "RS256")
        {
            Ok(signed) => {
                doc["signed_metadata"] = json!(signed);
            }
            Err(e) => tracing::error!(
                "{}signed_metadata: {}",
                sts_core::log::tag(sts_core::errors::codes::STS_OAUTH_0183),
                e
            ),
        }
        let body = serde_json::to_string_pretty(&doc).unwrap_or_default();
        (
            axum::http::StatusCode::OK,
            [
                (
                    axum::http::header::CONTENT_TYPE,
                    "application/json; charset=utf-8",
                ),
                (axum::http::header::CACHE_CONTROL, "no-store"),
            ],
            body,
        )
            .into_response()
    }
}

/// `i18n.offered()`'s tags.
fn offered(catalogs: &sts_http::i18n::Catalogs) -> Vec<String> {
    catalogs
        .offered()
        .iter()
        .map(|o| sts_oauth::js::string_of(o.get("tag")))
        .collect()
}
