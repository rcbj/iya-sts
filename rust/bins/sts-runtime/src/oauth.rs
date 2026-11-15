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
use sts_oauth::authorization_servers::{self as named, AuthorizationServers};
use sts_oauth::authorize::{AuthorizationEndpoint, AuthorizeAsk, CatalogPages};
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
    /// The live directory's person doors, where a consent is filed.
    pub directory_ports: Arc<sts_authn_api::wiring::DirectoryPorts>,
    /// `authn.clientDisplay(clientId)` (#1300), for the consent view.
    pub client_display: Arc<dyn Fn(&str) -> Json + Send + Sync>,
    /// The credential store, for the password grant.
    pub credentials: Arc<sts_credentials::credentials::Credentials>,
    /// The identity funnel the session core records through, which the
    /// password grant records through too (`stats.recordAuthentication()`).
    pub records: Arc<dyn sts_authn::ports::Records>,
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
    /// The named authorization servers (rule 3j).
    pub servers: Arc<AuthorizationServers>,
    /// The consent register and screen (rule 4c).
    pub consent: Arc<sts_oauth::consent::ConsentScreen>,
    /// `/oauth2/userinfo` (OIDC Core section 5.3).
    pub userinfo: Arc<sts_oauth::userinfo::UserInfo>,
    /// The bootstrap administrator's claim at the authorization endpoint,
    /// handed its work when `/admin-api` is built.
    pub console_claim: Arc<crate::admin_api::ConsoleClaim>,
    /// `/oauth2/logout` (RP-Initiated Logout 1.0).
    pub logout: Arc<sts_oauth::logout_endpoint::LogoutEndpoint>,
    /// The shared used-assertion history (`common/used_assertions.js`).
    pub used: Arc<sts_oauth::used_assertions::UsedAssertions>,
}

/// The person's entry for UserInfo's claims: the live directory's person
/// doors (`DirectoryPorts::person_attribute`).
struct ClaimEntries(Arc<sts_authn_api::wiring::DirectoryPorts>);

impl sts_oauth::userinfo::ClaimDirectory for ClaimEntries {
    fn values_of(
        &self,
        username: &str,
        attribute: &str,
    ) -> Option<Vec<String>> {
        self.0.person_attribute(username, attribute)
    }
}

/// `ldap_server.js`'s consent hooks over the live directory: the person's
/// entry by its `uid`, a value added only where it is not there already
/// (`addValues()`).
struct ConsentEntries(Arc<sts_authn_api::wiring::DirectoryPorts>);

impl sts_oauth::consent::ConsentDirectory for ConsentEntries {
    fn values_of(&self, key: &str, attribute: &str) -> Option<Vec<String>> {
        // Every entry carries its objectClass; none is no entry.
        self.0.person_attribute(key, "objectClass")?;
        Some(self.0.person_attribute(key, attribute).unwrap_or_default())
    }

    fn add_values(
        &self,
        key: &str,
        attribute: &str,
        values: &[String],
    ) -> Result<bool, String> {
        let Some(mut held) = self.values_of(key, attribute) else {
            return Err("noEntry".into());
        };
        let before = held.len();
        for v in values {
            if !held.contains(v) {
                held.push(v.clone());
            }
        }
        if held.len() == before {
            return Ok(false);
        }
        match self.0.write_attribute(key, attribute, Some(held)) {
            Ok(true) => Ok(true),
            Ok(false) => Err("noEntry".into()),
            Err(e) => Err(e),
        }
    }

    fn name_for_subject(&self, sub: &str) -> String {
        use sts_authn::ports::People;
        self.0.name_for_subject(sub)
    }
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

    fn verify_own_signature(
        &self,
        token: &str,
        now_s: i64,
    ) -> Result<Json, String> {
        sts_oauth::token_endpoint::KeySetSigner {
            set: Arc::new(self.set()?),
        }
        .verify_own_signature(token, now_s)
    }
}

/// THE REGISTER'S ENVIRONMENT WITH THE STORE'S DATA KEYS. `CoreEnv` opens
/// nothing, and in product mode with persisted keys Node seals every client
/// secret it writes (`sealCredentialText()`): a client a Node beside this
/// one registered then had "nothing on its entry to verify" here, and its
/// secret was refused. The register only READS through this one — this
/// runtime writes no application yet — so `seal()` is the keystore's as well
/// for when it does.
pub(crate) struct SealingEnv {
    pub(crate) core: sts_registers::applications::env::CoreEnv,
    pub(crate) persistence: Arc<Persistence>,
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

/// `cluster_counters.js`' windows in the store every process shares
/// (`sts_cluster_windows`, realm `''`), where the driver shares them.
struct StoreWindows(Arc<Persistence>);

impl sts_oauth::secret_limit::SharedWindows for StoreWindows {
    fn shares(&self) -> bool {
        self.0.driver().is_some_and(|d| d.shares_windows())
    }

    fn count<'a>(
        &'a self,
        key: &'a str,
        window_ms: i64,
    ) -> sts_oauth::secret_limit::WindowFuture<
        'a,
        Result<sts_oauth::secret_limit::Window, String>,
    > {
        Box::pin(async move {
            let driver = self.0.driver().ok_or("no store")?;
            let w = driver
                .count_window(
                    sts_oauth::secret_limit::SHARED_SCOPE,
                    "",
                    key,
                    window_ms,
                )
                .await
                .map_err(|e| e.to_string())?
                .ok_or("unshared")?;
            Ok(sts_oauth::secret_limit::Window {
                count: w.count,
                remaining_ms: w.remaining_ms,
            })
        })
    }

    fn peek<'a>(
        &'a self,
        key: &'a str,
    ) -> sts_oauth::secret_limit::WindowFuture<
        'a,
        Result<sts_oauth::secret_limit::Window, String>,
    > {
        Box::pin(async move {
            let driver = self.0.driver().ok_or("no store")?;
            let w = driver
                .peek_window(sts_oauth::secret_limit::SHARED_SCOPE, "", key)
                .await
                .map_err(|e| e.to_string())?
                .ok_or("unshared")?;
            Ok(sts_oauth::secret_limit::Window {
                count: w.count,
                remaining_ms: w.remaining_ms,
            })
        })
    }

    fn clear<'a>(
        &'a self,
        key: &'a str,
    ) -> sts_oauth::secret_limit::WindowFuture<'a, Result<bool, String>> {
        Box::pin(async move {
            let driver = self.0.driver().ok_or("no store")?;
            driver
                .clear_window(sts_oauth::secret_limit::SHARED_SCOPE, "", key)
                .await
                .map_err(|e| e.to_string())
        })
    }
}

/// `sts_used_assertions` in the store every process shares, where the
/// driver holds it.
struct StoreUsed(Arc<Persistence>);

impl sts_oauth::used_assertions::UsedStore for StoreUsed {
    fn holds(&self) -> bool {
        self.0.driver().is_some_and(|d| d.holds_used_assertions())
    }

    fn origin(&self) -> String {
        self.0
            .driver()
            .and_then(|d| d.change_log().map(|log| log.origin()))
            .unwrap_or_else(|| "local".to_string())
    }

    fn claim<'a>(
        &'a self,
        row: &'a sts_oauth::used_assertions::Row,
        cap: i64,
        now_ms: i64,
    ) -> sts_oauth::used_assertions::UsedFuture<
        'a,
        Result<sts_store::driver::UsedClaim, String>,
    > {
        Box::pin(async move {
            let driver = self.0.driver().ok_or("no store")?;
            driver
                .claim_used_assertion(row, cap, now_ms)
                .await
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "the store holds no used assertions".into())
        })
    }

    fn settle<'a>(
        &'a self,
        realm: &'a str,
        key: &'a str,
        reservation: &'a str,
        spent: bool,
        at_ms: i64,
    ) -> sts_oauth::used_assertions::UsedFuture<'a, Result<u64, String>> {
        Box::pin(async move {
            let driver = self.0.driver().ok_or("no store")?;
            driver
                .settle_used_assertion(realm, key, reservation, spent, at_ms)
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn find<'a>(
        &'a self,
        realm: &'a str,
        key: &'a str,
        now_ms: i64,
    ) -> sts_oauth::used_assertions::UsedFuture<
        'a,
        Result<Option<sts_oauth::used_assertions::Row>, String>,
    > {
        Box::pin(async move {
            let driver = self.0.driver().ok_or("no store")?;
            driver
                .find_used_assertion(realm, key, now_ms)
                .await
                .map_err(|e| e.to_string())
        })
    }
}

/// The keystore's data keys for the history's four text columns
/// (`sealedRowOf()`: where the keystore persists and is sealed).
struct UsedSealer {
    settings: Arc<Settings>,
    mode: Arc<Mode>,
    persistence: Arc<Persistence>,
}

impl sts_oauth::used_assertions::Sealer for UsedSealer {
    fn seals(&self) -> bool {
        sts_store::keystore::DataKeys::persists(&self.settings, &self.mode)
            && self.persistence.data_keys().sealed()
    }
    fn seal(&self, text: &str, label: &str, realm: &str) -> Option<String> {
        self.persistence.data_keys().seal(text, label, realm)
    }
    fn open(&self, text: &str, label: &str) -> Option<String> {
        self.persistence.data_keys().open(text, label)
    }
}

/// The password grant's checks over the credential store (`door: 'ropc'`).
struct RopcChecks(Arc<sts_credentials::credentials::Credentials>);

impl sts_oauth::token_endpoint::PasswordChecks for RopcChecks {
    fn verify(
        &self,
        username: &str,
        password: &str,
    ) -> Result<String, (String, String)> {
        let opts = sts_credentials::credentials::VerifyOptions::from_json(
            &json!({ "via": "the OAuth 2.0 password grant", "door": "ropc" }),
        );
        let verdict = self.0.verify(username, password, &opts);
        let reason = verdict.reason().to_string();
        if verdict.ok() {
            Ok(reason)
        } else {
            let detail = verdict
                .value
                .get("detail")
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_string();
            Err((reason, detail))
        }
    }

    // `mechanismsFor(username)`: `webauthn` for a key that counts as a
    // second factor, else `totp` for an enrolment (`secondFactorDemand()`
    // reads the same two). The emailed factor (#64, off by default) is
    // not in this runtime yet.
    fn second_factor(&self, username: &str) -> String {
        let held = self.0.second_factor_demand(username);
        if held.get("key") == Some(&Json::Bool(true)) {
            "webauthn".into()
        } else if held.get("totp") == Some(&Json::Bool(true)) {
            "totp".into()
        } else {
            String::new()
        }
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
        let console_claim = Arc::new(crate::admin_api::ConsoleClaim::default());
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
        // The client-facing subject (OIDC Core section 8, #149).
        let pairwise = Arc::new(sts_oauth::pairwise::PairwiseSubjects {
            settings: settings.clone(),
            clients: clients.clone(),
            // Node's `oidc-pairwise` cluster secret, read at each
            // derivation: the store's value is known once it has started.
            secret: {
                let secrets = parts.persistence.cluster_secrets();
                Arc::new(move || {
                    secrets.text("oidc-pairwise").unwrap_or_default()
                })
            },
            ephemeral: sts_oauth::pairwise::PairwiseSubjects::declare_ephemeral(
                &parts.lifecycle,
                &parts.handles,
            ),
            now_ms: Arc::new(sts_core::time::now_ms_f64),
        });
        let used = Arc::new(sts_oauth::used_assertions::UsedAssertions::new(
            settings.clone(),
            Arc::new(StoreUsed(parts.persistence.clone())),
            Arc::new(UsedSealer {
                settings: settings.clone(),
                mode: mode.clone(),
                persistence: parts.persistence.clone(),
            }),
            Arc::new(|| chrono::Utc::now().timestamp_millis()),
        ));
        let tokens = Arc::new(TokenEndpoint {
            settings: settings.clone(),
            mode: mode.clone(),
            clients: clients.clone(),
            auth: Arc::new(ClientAuth::new(
                settings.clone(),
                mode.clone(),
                Arc::new(sts_oauth::used_assertions::SharedAssertionHistory {
                    local: MemoryAssertionHistory::default(),
                }),
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
                pairwise: Some(pairwise.clone()),
            })),
            scopes: scopes.clone(),
            grants: grants.clone(),
            claims: Arc::new(ProcessClaims::default()),
            dpop,
            gated: console_claim.clone(),
            people: Arc::new(Directories(parts.people.clone())),
            sessions: Arc::new(GrantSessionsOf(parts.sessions.clone())),
            limits: Some(Arc::new(sts_oauth::secret_limit::SharedLimits::new(
                settings.clone(),
                Arc::new(StoreWindows(parts.persistence.clone())),
                Arc::new(|| chrono::Utc::now().timestamp_millis()),
            ))),
            passwords: Some(Arc::new(RopcChecks(parts.credentials.clone()))),
            used: Some(used.clone()),
            records: Some(parts.records.clone()),
            requested: Some(Arc::new(
                sts_oauth::requested_claims::RequestedClaims {
                    directory: Arc::new(ClaimEntries(
                        parts.directory_ports.clone(),
                    )),
                    settings: settings.clone(),
                    invents: {
                        let mode = mode.clone();
                        Arc::new(move || {
                            mode.predicate("inventsClaimValues")
                                .unwrap_or(false)
                        })
                    },
                    now_ms: Arc::new(|| chrono::Utc::now().timestamp_millis()),
                },
            )),
        });
        let servers = AuthorizationServers::declare(
            &parts.lifecycle,
            &parts.handles,
            settings.clone(),
            Arc::new(sts_core::time::now_ms_f64),
        );
        let for_caps = (
            settings.clone(),
            mode.clone(),
            parts.catalogs.clone(),
            servers.clone(),
        );
        let grant_list = tokens.grant_types_supported();
        let consent = Arc::new(sts_oauth::consent::ConsentScreen {
            register: Arc::new(sts_oauth::consent::ConsentRegister {
                settings: settings.clone(),
                clients: clients.clone(),
                directory: Arc::new(ConsentEntries(
                    parts.directory_ports.clone(),
                )),
                answers: sts_oauth::consent::ConsentRegister::declare_answers(
                    &parts.lifecycle,
                    &parts.handles,
                ),
                now_ms: Arc::new(sts_core::time::now_ms_f64),
            }),
            pending: sts_oauth::consent::ConsentScreen::declare_pending(
                &parts.lifecycle,
                &parts.handles,
            ),
            sign_on: parts.sessions.clone(),
            client_display: parts.client_display.clone(),
            random_id: Arc::new(random_id),
        });
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
            gated: console_claim.clone(),
            consent: Some(consent.clone()),
            request_objects: Some(Arc::new(
                sts_oauth::request_object::RequestObjects {
                    settings: settings.clone(),
                    mode: mode.clone(),
                    pushed: sts_oauth::par::PushedRequests::declare(
                        &parts.lifecycle,
                        &parts.handles,
                        settings.clone(),
                        Arc::new(sts_core::time::now_ms_f64),
                    ),
                    now_s: Arc::new(|| chrono::Utc::now().timestamp()),
                    seen: Mutex::new(std::collections::HashMap::new()),
                },
            )),
            pairwise: Some(pairwise.clone()),
            tokens: Some(tokens.clone()),
            pages: Arc::new(CatalogPages {
                catalogs: parts.catalogs.clone(),
                footer: parts.footer.clone(),
                // The runtime writes its audit rows to the log (`LogAudit`):
                // no ring, so no incident ID to reserve.
                incident: Arc::new(|| 0),
            }),
            signer: Some(signer.clone()),
            // `capabilityFor(req, member)`: the document this request's
            // authorization server publishes, its profile applied.
            capabilities: Arc::new(move |base: &str| {
                let (settings, mode, catalogs, servers) = &for_caps;
                let id = named::current();
                let own = named::path_of(&id);
                let realm_base =
                    base.strip_suffix(own.as_str()).unwrap_or(base);
                servers.capabilities_of(
                    &id,
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
                            realm_base,
                        },
                    ),
                    "oauth",
                )
            }),
            now_ms: Arc::new(sts_core::time::now_ms_f64),
            random_id: Arc::new(random_id),
        });
        let userinfo = Arc::new(sts_oauth::userinfo::UserInfo {
            tokens: tokens.clone(),
            directory: Arc::new(ClaimEntries(parts.directory_ports.clone())),
            pairwise: Some(pairwise.clone()),
        });
        let logout = Arc::new(sts_oauth::logout_endpoint::LogoutEndpoint {
            settings: settings.clone(),
            mode: mode.clone(),
            clients: clients.clone(),
            sessions: parts.sessions.clone(),
            hints: authorize.clone(),
            catalogs: parts.catalogs.clone(),
            footer: parts.footer.clone(),
            // No audit ring here (`LogAudit`): no incident ID to reserve.
            incident: Arc::new(|| 0),
            channels: Arc::new(sts_oauth::logout_endpoint::NoChannels),
        });
        Arc::new(OAuthStack {
            console_claim,
            logout,
            used,
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
            servers,
            consent,
            userinfo,
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
            let realm = sts_core::realm::current_id();
            // THE POST-QUANTUM HALF TOO, where the realm signs with it
            // (`pqKeysForAsync()`): an ML-DSA or SLH-DSA ID Token, a
            // hybrid response's, is signed by a synchronous signer that
            // cannot wait for eleven keys to be made.
            let pq = sts_oauth::jwks::JwksPolicy::from_settings(
                &self.settings,
                &self.mode,
            )
            .post_quantum;
            let made = if pq {
                sets.with_pq_keys(&realm).await
            } else {
                sets.open_or_make(&realm).await
            };
            if let Err(e) = made {
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
        // The two mode reports (`GET /oauth2/rfc9700`, `/oauth2/oauth21`).
        let routes = routes.route(
            "/oauth2/rfc9700",
            axum::routing::get({
                let me = me.clone();
                move || {
                    let me = me.clone();
                    async move { me.report(true) }
                }
            })
            .fallback(unrouted),
        );
        let routes = routes.route(
            "/oauth2/oauth21",
            axum::routing::get({
                let me = me.clone();
                move || {
                    let me = me.clone();
                    async move { me.report(false) }
                }
            })
            .fallback(unrouted),
        );
        // `/oauth2/userinfo`, GET and POST (OIDC Core section 5.3.1).
        let routes = routes.route(
            "/oauth2/userinfo",
            axum::routing::get({
                let (me, h) = (me.clone(), h.clone());
                move |r: AxumRequest| {
                    let (me, h) = (me.clone(), h.clone());
                    async move { me.userinfo(h, r).await }
                }
            })
            .post({
                let (me, h) = (me.clone(), h.clone());
                move |r: AxumRequest| {
                    let (me, h) = (me.clone(), h.clone());
                    async move { me.userinfo(h, r).await }
                }
            })
            .fallback(unrouted),
        );
        // `/oauth2/logout`, GET and POST (RP-Initiated Logout 1.0 section
        // 2's MUST).
        let routes = routes.route(
            "/oauth2/logout",
            axum::routing::get({
                let (me, h) = (me.clone(), h.clone());
                move |r: AxumRequest| {
                    let (me, h) = (me.clone(), h.clone());
                    async move { me.logout(h, r).await }
                }
            })
            .post({
                let (me, h) = (me.clone(), h.clone());
                move |r: AxumRequest| {
                    let (me, h) = (me.clone(), h.clone());
                    async move { me.logout(h, r).await }
                }
            })
            .fallback(unrouted),
        );
        let routes = routes.route(
            "/oauth2/par",
            axum::routing::post({
                let (me, h) = (me.clone(), h.clone());
                move |r: AxumRequest| {
                    let (me, h) = (me.clone(), h.clone());
                    async move { me.par(h, r).await }
                }
            })
            .fallback(par_method_not_allowed),
        );
        let routes = routes.route(
            "/.well-known/oauth-authorization-server",
            axum::routing::get({
                let (me, h) = (me.clone(), h.clone());
                move |r: AxumRequest| {
                    let (me, h) = (me.clone(), h.clone());
                    async move { me.metadata(h, r, false, None).await }
                }
            }),
        );
        let routes = routes.route(
            "/.well-known/openid-configuration",
            axum::routing::get({
                let (me, h) = (me.clone(), h.clone());
                move |r: AxumRequest| {
                    let (me, h) = (me.clone(), h.clone());
                    async move { me.metadata(h, r, true, None).await }
                }
            }),
        );
        let routes = routes.route(
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
        );
        self.discovery_routes(routes, http)
    }

    /// The issuer-with-path forms (RFC 8414 section 3.1's inserted one and
    /// OpenID Connect Discovery section 4's appended one), the endpoints
    /// under every named authorization server's own name, and the
    /// documents the metadata links to.
    fn discovery_routes(
        self: &Arc<Self>,
        routes: axum::Router,
        http: Arc<sts_http::HttpLayer>,
    ) -> axum::Router {
        use axum::extract::Path;
        let me = self.clone();
        let h = http;
        let routes = routes.route(
            "/.well-known/oauth-authorization-server/{*rest}",
            axum::routing::get({
                let (me, h) = (me.clone(), h.clone());
                move |Path(rest): Path<String>, r: AxumRequest| {
                    let (me, h) = (me.clone(), h.clone());
                    async move { me.discovery_for_path(h, r, rest, false).await }
                }
            }),
        );
        let routes = routes.route(
            "/.well-known/openid-configuration/{*rest}",
            axum::routing::get({
                let (me, h) = (me.clone(), h.clone());
                move |Path(rest): Path<String>, r: AxumRequest| {
                    let (me, h) = (me.clone(), h.clone());
                    async move { me.discovery_for_path(h, r, rest, true).await }
                }
            }),
        );
        let routes = routes.route(
            "/{as}/.well-known/openid-configuration",
            axum::routing::get({
                let (me, h) = (me.clone(), h.clone());
                move |Path(server): Path<String>, r: AxumRequest| {
                    let (me, h) = (me.clone(), h.clone());
                    async move { me.appended_discovery(h, r, server).await }
                }
            }),
        );
        let authorize = {
            let (me, h) = (me.clone(), h.clone());
            move |Path(server): Path<String>, r: AxumRequest| {
                let (me, h) = (me.clone(), h.clone());
                async move {
                    let inner = me.clone();
                    me.for_profile(server, move || inner.authorize(h, r)).await
                }
            }
        };
        let routes = routes.route(
            "/{as}/oauth2/authorize",
            axum::routing::get(authorize.clone())
                .post(authorize)
                .fallback(unrouted),
        );
        let routes = routes.route(
            "/{as}/oauth2/token",
            axum::routing::post({
                let (me, h) = (me.clone(), h.clone());
                move |Path(server): Path<String>, r: AxumRequest| {
                    let (me, h) = (me.clone(), h.clone());
                    async move {
                        let inner = me.clone();
                        me.for_profile(server, move || inner.token(h, r)).await
                    }
                }
            })
            .fallback(unrouted),
        );
        let logout = {
            let (me, h) = (me.clone(), h.clone());
            move |Path(server): Path<String>, r: AxumRequest| {
                let (me, h) = (me.clone(), h.clone());
                async move {
                    let inner = me.clone();
                    me.for_profile(server, move || inner.logout(h, r)).await
                }
            }
        };
        let routes = routes.route(
            "/{as}/oauth2/logout",
            axum::routing::get(logout.clone())
                .post(logout)
                .fallback(unrouted),
        );
        let routes = routes.route(
            "/{as}/oauth2/par",
            axum::routing::post({
                let (me, h) = (me.clone(), h.clone());
                move |Path(server): Path<String>, r: AxumRequest| {
                    let (me, h) = (me.clone(), h.clone());
                    async move {
                        let inner = me.clone();
                        me.for_profile(server, move || inner.par(h, r)).await
                    }
                }
            })
            .fallback(par_method_not_allowed),
        );
        // `/docs`, `/policy`, `/tos`: the documents the metadata links to.
        let routes = routes.route(
            "/docs",
            axum::routing::get({
                let (me, h) = (me.clone(), h.clone());
                move |r: AxumRequest| {
                    let (me, h) = (me.clone(), h.clone());
                    async move {
                        let (base, _, _, _) = me.arrived(&h, &r);
                        text_document(&format!(
                            "Authorization server (service_documentation).\n\n\
                             Every endpoint in {}/.well-known/oauth-authorization-server \
                             answers.\nTokens are RS256 JWTs signed with the key at \
                             {}/oauth2/jwks.\nNo credential is ever verified: this \
                             server exists to exercise a client.\n",
                            base, base
                        ))
                    }
                }
            }),
        );
        let routes = routes.route(
            "/policy",
            axum::routing::get(|| async {
                text_document(
                    "Authorization server policy (op_policy_uri). Test data \
                     only.\n",
                )
            }),
        );
        routes.route(
            "/tos",
            axum::routing::get(|| async { text_document(&tos_text()) }),
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
        // `asBaseOf(req)`: a named authorization server is its own issuer.
        let base = format!(
            "{}{}",
            sts_authn_api::router::base_of(
                &self.settings,
                &headers,
                over_tls,
                &prefix,
            ),
            named::path_of(&named::current())
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
            ..AuthorizeAsk::default()
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
        // AN RFC 9101 REQUEST OBJECT'S jti, claimed in the shared history
        // on arrival (`lookUp()` reads it, `spend()` keeps it); a redirect
        // is the endpoint's success, so anything below 400 keeps a claim
        // the verifier spent.
        let input = if ask.method.eq_ignore_ascii_case("POST") {
            sts_oauth::js::fold(&sts_oauth::js::form_decode(&ask.body))
        } else {
            sts_oauth::js::fold(&sts_oauth::js::form_decode(&ask.query))
        };
        let claimed = sts_oauth::used_assertions::reserve_request_object(
            &self.used, &input,
        )
        .await;
        let answer = sts_oauth::used_assertions::ARRIVAL
            .sync_scope(claimed.clone(), || self.authorize.answer(&ask));
        claimed.settle(&self.used, answer.status, 400).await;
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

    /// `GET`/`POST /oauth2/logout` (RP-Initiated Logout 1.0): the page or
    /// the return, with the cookies the session core wrote.
    async fn logout(
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
        let ask = sts_oauth::logout_endpoint::LogoutAsk {
            method: request.method().to_string(),
            content_type: header_of(&headers, "content-type"),
            query,
            body,
            accept_language: header_of(&headers, "accept-language"),
            fetch_dest: header_of(&headers, "sec-fetch-dest"),
            fetch_mode: header_of(&headers, "sec-fetch-mode"),
            base,
            prefix: http.registry().current_prefix(),
            as_path: named::path_of(&named::current()),
            request: session_request.clone(),
        };
        let answered = self.logout.answer(&ask);
        let mut response = answered.answer.into_response();
        for line in answered
            .response
            .cookies
            .iter()
            .cloned()
            .chain(session_request.accounts.lock().appended.drain(..))
        {
            if let Ok(v) = axum::http::HeaderValue::from_str(&line) {
                response
                    .headers_mut()
                    .append(axum::http::header::SET_COOKIE, v);
            }
        }
        response
    }

    /// `POST /oauth2/par` (RFC 9126).
    async fn par(
        self: Arc<Self>,
        http: Arc<sts_http::HttpLayer>,
        request: AxumRequest,
    ) -> Response {
        self.reload_directory();
        self.ensure_keys().await;
        let (base, headers, address, body) = self.arrived(&http, &request);
        let ask = AuthorizeAsk {
            method: "POST".into(),
            content_type: header_of(&headers, "content-type"),
            body,
            accept: header_of(&headers, "accept"),
            base,
            prefix: http.registry().current_prefix(),
            request: sts_authn::ports::Request {
                address,
                ..sts_authn::ports::Request::default()
            },
            ..AuthorizeAsk::default()
        };
        let dpop = headers
            .get("dpop")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        fn sendable<T: Send>(t: T) -> T {
            t
        }
        // The client assertion and the request object, claimed on arrival
        // and settled by the answer (a push is answered 201).
        let folded =
            sts_oauth::js::fold(&sts_oauth::js::form_decode(&ask.body));
        let authorization = header_of(&headers, "authorization");
        let client_id =
            sts_oauth::token_endpoint::client_from(&authorization, &folded)
                .client_id;
        let arrival = sts_oauth::used_assertions::reserve_for_token(
            &self.used, &folded, &client_id,
        )
        .await;
        let objects = sts_oauth::used_assertions::reserve_request_object(
            &self.used, &folded,
        )
        .await;
        arrival.absorb(&objects);
        let answer = sts_oauth::used_assertions::ARRIVAL
            .scope(
                arrival.clone(),
                sendable(self.authorize.push(
                    &ask,
                    &self.tokens,
                    &authorization,
                    None,
                    dpop.as_deref(),
                )),
            )
            .await;
        arrival.settle(&self.used, answer.status, 300).await;
        answer.into_response()
    }

    /// `bcp.state()` or `oauth21.state()`, for the ambient realm.
    fn report(&self, rfc9700: bool) -> Response {
        let reports = sts_oauth::reports::Reports {
            settings: &self.settings,
            mode: &self.mode,
        };
        let grants = &self.tokens.grants;
        let state = if rfc9700 {
            reports.rfc9700(sts_oauth::reports::Remembered {
                transactions: grants.transactions.len(),
                client_assertions: self.tokens.auth.assertions_remembered(),
                refresh_tokens: grants.refresh_tokens.len(),
                refresh_families: grants.refresh_families.len(),
            })
        } else {
            reports.oauth21_state()
        };
        sts_oauth::reports::answer(&state).into_response()
    }

    /// `userinfoResponse()`: the base is `baseUrlOf(req)` — the realm's,
    /// never a named server's, since UserInfo is the realm's resource.
    async fn userinfo(
        self: Arc<Self>,
        http: Arc<sts_http::HttpLayer>,
        request: AxumRequest,
    ) -> Response {
        self.reload_directory();
        self.ensure_keys().await;
        let (base, headers, _address, body) = self.arrived(&http, &request);
        let token_in_query = request
            .uri()
            .query()
            .map(|q| {
                sts_oauth::js::form_decode(q)
                    .iter()
                    .any(|(k, _)| k == "access_token" || k == "token")
            })
            .unwrap_or(false);
        let ask = sts_oauth::userinfo::UserinfoAsk {
            htu: format!("{}/oauth2/userinfo", base),
            base,
            method: request.method().as_str().to_string(),
            authorization: header_of(&headers, "authorization"),
            dpop: headers
                .get("dpop")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string),
            content_type: header_of(&headers, "content-type"),
            body,
            token_in_query,
            peer_der: None,
        };
        fn sendable<T: Send>(t: T) -> T {
            t
        }
        sendable(self.userinfo.answer(&ask)).await.into_response()
    }

    async fn token(
        self: Arc<Self>,
        http: Arc<sts_http::HttpLayer>,
        request: AxumRequest,
    ) -> Response {
        self.reload_directory();
        self.ensure_keys().await;
        let (base, headers, address, body) = self.arrived(&http, &request);
        let ask = TokenAsk {
            base: base.clone(),
            address,
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

    /// `sendAsMetadata()` and `sendOidcMetadata()`: the document of the
    /// request's authorization server, its profile applied (twice for the
    /// OpenID one, as Node applies it: the OpenID members are merged after
    /// `asMetadata()` ran), signed.
    async fn metadata(
        self: Arc<Self>,
        http: Arc<sts_http::HttpLayer>,
        request: AxumRequest,
        oidc: bool,
        issuer: Option<String>,
    ) -> Response {
        self.ensure_keys().await;
        let (base, _, _, _) = self.arrived(&http, &request);
        let id = named::current();
        let own = named::path_of(&id);
        let realm_base =
            base.strip_suffix(own.as_str()).unwrap_or(&base).to_string();
        let inputs = sts_oauth::metadata::MetadataInputs {
            settings: &self.settings,
            mode: &self.mode,
            base: &base,
            ui_locales: offered(&self.catalogs),
            grant_types: self.tokens.grant_types_supported(),
            mtls_available: self.settings.value_of("global.https").as_bool(),
            realm_base: &realm_base,
        };
        let mut doc = if oidc {
            let applied =
                sts_oauth::metadata::oidc_metadata(&inputs, issuer.as_deref());
            self.servers.capabilities_of(&id, applied, "oauth")
        } else {
            self.servers.capabilities_of(
                &id,
                sts_oauth::metadata::as_metadata(&inputs),
                "oauth",
            )
        };
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

    /// `issuerPathTarget(raw)`: `[realm/<id>][/<server>]` — a realm that
    /// exists, named only where no realm is entered yet, and at most one
    /// server segment of the profile id's shape; `None` names nothing.
    fn issuer_path_target(
        &self,
        raw: &str,
    ) -> Option<(Arc<sts_core::realm::Realm>, String)> {
        let mut segments: Vec<&str> =
            raw.split('/').filter(|s| !s.is_empty()).collect();
        let mut realm = sts_core::realm::current();
        if segments.first() == Some(&"realm") {
            let named_realm = if segments.len() >= 2 && realm.is_default() {
                self.registry.get(segments[1])
            } else {
                None
            };
            match named_realm {
                Some(r) if segments[1] != sts_core::realm::DEFAULT_ID => {
                    realm = r;
                }
                _ => return None,
            }
            segments.drain(..2);
        }
        if segments.len() > 1
            || (segments.len() == 1 && !named::id_shape(segments[0]))
        {
            return None;
        }
        Some((realm, segments.first().unwrap_or(&"").to_string()))
    }

    /// `profileFromPath(raw)`: fetching the metadata is accessing the
    /// server, so a name that arrives here is created as at an endpoint.
    fn profile_from_path(&self, server: &str) -> String {
        if server.is_empty() || server == named::DEFAULT_ID {
            return named::DEFAULT_ID.to_string();
        }
        self.servers.ensure(server, true, true);
        server.to_string()
    }

    /// `discoveryForPath()`: the RFC 8414 inserted form, answered inside
    /// the realm and for the server the path names, or Express's 404
    /// (`STS-OAUTH-0594`).
    async fn discovery_for_path(
        self: Arc<Self>,
        http: Arc<sts_http::HttpLayer>,
        request: AxumRequest,
        rest: String,
        oidc: bool,
    ) -> Response {
        let Some((realm, server)) = self.issuer_path_target(&rest) else {
            tracing::debug!(
                "{}oauth2: the discovery path names nothing.",
                sts_core::log::tag(sts_core::errors::codes::STS_OAUTH_0594)
            );
            return unrouted(request).await;
        };
        let me = self.clone();
        sts_core::realm::run(realm, async move {
            let id = me.profile_from_path(&server);
            named::run(id, me.metadata(http, request, oidc, None)).await
        })
        .await
    }

    /// The path-appended form, `/<server>/.well-known/openid-configuration`:
    /// the issuer built back up from the path the request arrived on.
    async fn appended_discovery(
        self: Arc<Self>,
        http: Arc<sts_http::HttpLayer>,
        request: AxumRequest,
        server: String,
    ) -> Response {
        let target = self.issuer_path_target(&server);
        if target.is_none() || server == "realm" {
            tracing::debug!(
                "{}oauth2: the discovery path names nothing.",
                sts_core::log::tag(sts_core::errors::codes::STS_OAUTH_0594)
            );
            return unrouted(request).await;
        }
        let id = self.profile_from_path(&server);
        let me = self.clone();
        named::run(id, async move {
            let (base, _, _, _) = me.arrived(&http, &request);
            me.clone().metadata(http, request, true, Some(base)).await
        })
        .await
    }

    /// `forProfile(handler)`: a route under `/<as>/…` answered for that
    /// authorization server, created on first sight; a malformed name is
    /// refused `invalid_request` (`STS-OAUTH-0186`).
    async fn for_profile<F, Fut>(
        self: Arc<Self>,
        server: String,
        handler: F,
    ) -> Response
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Response>,
    {
        // `validation.checkParsed({ as }, 'params', AS_PROFILE_PARAMS)`:
        // the model bounds the segment; an unknown name is not refused.
        let mut params = Map::new();
        params.insert("as".into(), Json::from(server.clone()));
        let id = match sts_oauth::model::check(
            "authorization-server",
            &params,
            "params",
        ) {
            Ok(v) => sts_oauth::js::string_of(v.get("as")).trim().to_string(),
            Err(e) => {
                return sts_oauth::answer::Answer::refusal(
                    sts_core::errors::codes::STS_OAUTH_0186,
                    400,
                    "invalid_request",
                    &e.detail,
                )
                .into_response();
            }
        };
        self.servers.ensure(&id, true, true);
        // A NAMED SERVER'S OWN FAPI PROFILE (#138): in force for its
        // requests, the realm's where it names none.
        let own = self.servers.fapi_of(&id);
        named::run(id, named::with_fapi(own, handler())).await
    }
}

/// `parMethodNotAllowed()`: 405, `Allow: POST`.
async fn par_method_not_allowed() -> Response {
    let mut a = sts_oauth::answer::Answer::refusal(
        sts_core::errors::codes::STS_OAUTH_0401,
        405,
        "invalid_request",
        "The pushed authorization request endpoint accepts POST only (RFC \
         9126 section 2), with the authorization request in an \
         application/x-www-form-urlencoded body.",
    );
    a.set("Allow", "POST");
    a.set("Cache-Control", "no-store");
    a.into_response()
}

/// `res.type('text/plain').send(text)`.
fn text_document(text: &str) -> Response {
    (
        axum::http::StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )],
        text.to_string(),
    )
        .into_response()
}

/// `/tos`'s text.
fn tos_text() -> String {
    "Authorization server terms of service (op_tos_uri). Test data only.\n"
        .to_string()
}

/// `i18n.offered()`'s tags.
fn offered(catalogs: &sts_http::i18n::Catalogs) -> Vec<String> {
    catalogs
        .offered()
        .iter()
        .map(|o| sts_oauth::js::string_of(o.get("tag")))
        .collect()
}

/// The consent screen's operations behind `/authn-api/consent`
/// (`consent_screen.ts`'s, reached by the door's late binding).
struct ConsentDoor(Arc<sts_oauth::consent::ConsentScreen>, Arc<Persistence>);

impl sts_authn_api::ports::ConsentPages for ConsentDoor {
    fn claim(
        &self,
        id: &str,
        session_id: &str,
        call: &sts_authn_api::flow::Call,
    ) -> bool {
        self.0.claim_for_browser(id, session_id, &call.request)
    }

    fn view(
        &self,
        call: &sts_authn_api::flow::Call,
        id: &str,
    ) -> Result<(Json, String, String), (sts_core::errors::ErrorCode, String)>
    {
        let record = self.0.asked_of(&call.request, id, false)?;
        let text = |name: &str| sts_oauth::js::string_of(record.get(name));
        Ok((
            self.0.view(&call.base, &record),
            text("uiLocales"),
            text("username"),
        ))
    }

    fn act(
        &self,
        call: &sts_authn_api::flow::Call,
        id: &str,
        action: &str,
    ) -> sts_authn_api::ports::ConsentAnswer {
        use sts_authn_api::ports::ConsentAnswer;
        use sts_oauth::consent::ActOutcome;
        match self.0.act(&call.request, id, action) {
            ActOutcome::Refused { code, why } => {
                ConsentAnswer::Refused { code, why }
            }
            ActOutcome::Back {
                target,
                username,
                code,
            } => ConsentAnswer::Back {
                target,
                username,
                code,
            },
        }
    }

    fn settle(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>
    {
        Box::pin(async move {
            if let Err(e) = self.1.flush().await {
                tracing::warn!(
                    "consent: the answer's write was not committed before \
                     the answer was sent: {}",
                    e
                );
            }
        })
    }
}

impl OAuthStack {
    /// `ConsentScreen.registerRoutes()`: `GET /oauth2/consent` — the
    /// sign-in surface's shell once the three checks pass, refused as
    /// `invalid_request` otherwise — and the screen's operations behind
    /// `/authn-api/consent/{id}` (#576). The page's script,
    /// `/oauth2/consent.js`, is the static surfaces' host's.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn consent_router(
        self: &Arc<Self>,
        http: Arc<sts_http::HttpLayer>,
        surfaces: Arc<sts_http::surfaces::SurfaceHost>,
        api: &sts_authn_api::door::AuthnApi,
    ) -> axum::Router {
        api.set_consent(Arc::new(ConsentDoor(
            self.consent.clone(),
            self.persistence.clone(),
        )));
        let me = self.clone();
        axum::Router::new().route(
            sts_oauth::consent::CONSENT_PATH,
            axum::routing::get(move |r: AxumRequest| {
                let (me, h, surfaces) =
                    (me.clone(), http.clone(), surfaces.clone());
                async move { me.consent_shell(h, surfaces, r).await }
            })
            .fallback(unrouted),
        )
    }

    async fn consent_shell(
        self: Arc<Self>,
        http: Arc<sts_http::HttpLayer>,
        surfaces: Arc<sts_http::surfaces::SurfaceHost>,
        request: AxumRequest,
    ) -> Response {
        self.reload_directory();
        let (_, headers, address, _) = self.arrived(&http, &request);
        let query = request.uri().query().unwrap_or("").to_string();
        let shell = |client: &str, person: &str| {
            let shown = (self.consent.client_display)(client);
            let logo = shown
                .get("logoOrigin")
                .and_then(Json::as_str)
                .filter(|o| !o.is_empty())
                .map(str::to_string);
            let html = surfaces.shells().consent(&headers, "", client, person);
            let options = sts_http::shell::ServeOptions {
                csp: vec![("style-src".into(), Some("'self'".into()))],
                images: logo.into_iter().collect(),
                ..sts_http::shell::ServeOptions::default()
            };
            sts_http::shell::serve(&headers, html, &options)
        };
        let asked = sts_oauth::js::fold(&sts_oauth::js::form_decode(&query));
        let named = sts_oauth::js::string_of(asked.get("consent"));
        if self.mode.hides_step_ids() && named.is_empty() {
            return shell("", "");
        }
        let checked = match sts_oauth::model::check("consent", &asked, "query")
        {
            Ok(v) => v,
            Err(e) => {
                return sts_oauth::answer::Answer::refusal(
                    sts_core::errors::codes::STS_OAUTH_0148,
                    400,
                    "invalid_request",
                    &e.detail,
                )
                .into_response();
            }
        };
        let session_request = sts_authn::ports::Request {
            cookie: header_of(&headers, "cookie"),
            user_agent: header_of(&headers, "user-agent"),
            address,
            url: request.uri().to_string(),
            ..sts_authn::ports::Request::default()
        };
        let id = sts_oauth::js::string_of(checked.get("consent"));
        match self.consent.asked_of(&session_request, &id, false) {
            Err((code, why)) => sts_oauth::answer::Answer::refusal(
                code,
                400,
                "invalid_request",
                &why,
            )
            .into_response(),
            Ok(record) => shell(
                &sts_oauth::js::string_of(record.get("clientId")),
                &sts_oauth::js::string_of(record.get("username")),
            ),
        }
    }
}
