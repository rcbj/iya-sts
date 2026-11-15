// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! WHAT THE RUNTIME ANSWERS EACH PORT WITH, and the routes.
//!
//! * [`DirectoryEntries`] is `ldap/ldap_server.js`'s slot for the core —
//!   a person at `uid=<name>,ou=users,<base>`, an application the entry
//!   under `ou=applications` whose `appIdentifier` is its id — over the
//!   runtime's directory, every write told to persistence so it reaches
//!   the store and the change log as Node's do.
//! * [`DirectoryApplications`] reads an application's fields off its
//!   entry, and its client secret as `applications.js`'s
//!   `primaryClientSecretOf()` picks it (the newest unexpired record).
//! * [`CredentialPasswords`] is `credentials.verifyAsync()`, the
//!   `sts-credentials` instance the sign-in surface built.
//! * [`GroupRoster`] is `admin_rbac.rolesOf()`'s Admin Write: membership
//!   of the group `admin.writeGroup` names. The open-console bootstrap is
//!   not here, which is what the enrollment core asks of it anyway ("an
//!   empty roster grants nothing here").
//! * The issuance gate, the audit, the signals and the monitor are
//!   [`crate::ports::Quiet`] until their families are in the runtime.
//!
//! [`EnrollStack::declare`] declares the stores before the store opens;
//! [`EnrollStack::router`] builds the three families once the certificate
//! authority exists, and answers the router `stack.rs` merges.

use std::sync::Arc;

use axum::extract::Request;
use axum::response::Response;
use serde_json::{json, Value as Json};
use sts_core::mode::Mode;
use sts_core::realm::{self, RealmRegistry};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::StoreHandles;
use sts_core::settings::{SettingValue, Settings};
use sts_credentials::credentials::{Credentials, VerifyOptions};
use sts_credentials::limits::{MemoryBuckets, RateLimiter};
use sts_credentials::ports as cred_ports;
use sts_pki::authority::Authority;
use sts_store::model::StoredEntry;
use sts_store::persistence::{LiveDirectory, MemoryDirectory, Persistence};
use sts_store::shadow::EntryLookup;

use crate::acme::store::AcmeStore;
use crate::acme::Acme;
use crate::core::{Core, CoreDeps};
use crate::est::{Est, EstStore};
use crate::ports::{
    Application, Applications, Entries, EntryRead, PasswordVerdict, Passwords,
    Quiet, Roles, Roster,
};
use crate::scep::{Scep, ScepStore};

/// The settings, the mode and the clock, for the rate limiter.
pub struct EnrollEnv {
    pub settings: Arc<Settings>,
    pub mode: Arc<Mode>,
}

fn setting_json(value: SettingValue) -> Json {
    match value {
        SettingValue::Text(t) => Json::from(t),
        SettingValue::Int(i) => Json::from(i),
        SettingValue::Bool(b) => Json::from(b),
        SettingValue::List(l) => json!(l),
    }
}

impl cred_ports::Environment for EnrollEnv {
    fn setting(&self, key: &str) -> Json {
        setting_json(self.settings.value_of(key))
    }
    fn predicate(&self, name: &str) -> bool {
        self.mode.predicate(name).unwrap_or(false)
    }
    fn now_ms(&self) -> f64 {
        sts_core::time::now_ms_f64()
    }
    fn realm_id(&self) -> String {
        realm::current_id()
    }
    fn random_bytes(&self, n: usize) -> Vec<u8> {
        sts_crypto::random::random_bytes(n).unwrap_or_default()
    }
    fn random_int(&self, min: u64, max: u64) -> u64 {
        sts_crypto::random::random_int(min, max).unwrap_or(min)
    }
    fn hash_secret(&self, plaintext: &str) -> String {
        sts_crypto::secrets::hash_secret(
            plaintext,
            sts_crypto::secrets::ScryptCost::default(),
        )
        .unwrap_or_default()
    }
}

/// The directory slot over the runtime's directory.
pub struct DirectoryEntries {
    pub directory: Arc<MemoryDirectory>,
    pub persistence: Arc<Persistence>,
    pub registry: Arc<RealmRegistry>,
}

fn read_of(entry: &StoredEntry) -> EntryRead {
    EntryRead {
        dn: entry.dn.clone(),
        attributes: entry
            .attributes
            .iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
            .collect(),
    }
}

fn first(entry: &StoredEntry, name: &str) -> String {
    entry
        .attributes
        .get(&name.to_ascii_lowercase())
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_default()
}

impl DirectoryEntries {
    fn realm(&self) -> (String, String) {
        let here = realm::current();
        (here.id.clone(), self.registry.base_dn_of(&here))
    }

    fn located(&self, kind: &str, id: &str) -> Option<(String, StoredEntry)> {
        let (realm, base) = self.realm();
        match kind {
            "person" => {
                let key = format!("uid={},ou=users,{}", id.trim(), base)
                    .to_lowercase();
                self.directory.entry_at(&realm, &key).map(|e| (realm, e))
            }
            "application" => {
                let under = format!(",ou=applications,{}", base).to_lowercase();
                self.directory
                    .realm_entries(&realm)
                    .into_iter()
                    .find(|(k, e)| {
                        k.ends_with(&under) && first(e, "appIdentifier") == id
                    })
                    .map(|(_, e)| (realm, e))
            }
            _ => None,
        }
    }
}

impl Entries for DirectoryEntries {
    fn read(&self, kind: &str, id: &str) -> Option<EntryRead> {
        self.located(kind, id).map(|(_, e)| read_of(&e))
    }

    fn write(
        &self,
        kind: &str,
        id: &str,
        name: &str,
        values: &[String],
    ) -> bool {
        let Some((realm, mut entry)) = self.located(kind, id) else {
            tracing::warn!(
                "{}ldap: the {} \"{}\" has no entry in this realm, so no enrollment attribute was written.",
                sts_core::log::tag(sts_core::errors::codes::STS_LDAP_0040.as_str()),
                kind,
                id
            );
            return false;
        };
        let attribute = name.to_ascii_lowercase();
        if values.is_empty() {
            entry.attributes.shift_remove(&attribute);
        } else {
            entry.attributes.insert(attribute, values.to_vec());
        }
        let stamp = chrono::Utc::now().format("%Y%m%d%H%M%SZ").to_string();
        entry
            .attributes
            .insert("modifytimestamp".into(), vec![stamp]);
        let key = entry.dn.to_lowercase();
        self.directory.put(&realm, entry);
        self.persistence.directory_changed(Some(&key));
        true
    }

    fn holders_with_values(
        &self,
        kind: &str,
        name: &str,
    ) -> Vec<(String, Vec<String>)> {
        let (realm, base) = self.realm();
        let attribute = name.to_ascii_lowercase();
        let users = format!(",ou=users,{}", base).to_lowercase();
        let apps = format!(",ou=applications,{}", base).to_lowercase();
        self.directory
            .realm_entries(&realm)
            .into_iter()
            .filter_map(|(k, e)| {
                let values =
                    e.attributes.get(&attribute).cloned().unwrap_or_default();
                if values.is_empty() {
                    return None;
                }
                match kind {
                    "person" if k.ends_with(&users) => {
                        Some((first(&e, "uid"), values))
                    }
                    "application" if k.ends_with(&apps) => {
                        Some((first(&e, "appIdentifier"), values))
                    }
                    _ => None,
                }
            })
            .filter(|(id, _)| !id.is_empty())
            .collect()
    }

    fn subject_for_name(&self, name: &str) -> String {
        self.located("person", name)
            .map(|(_, e)| first(&e, "entryUUID"))
            .filter(|u| !u.is_empty())
            .map(|u| format!("urn:uuid:{}", u.to_lowercase()))
            .unwrap_or_default()
    }

    fn name_for_subject(&self, subject: &str) -> String {
        let wanted = subject.trim().to_lowercase();
        let wanted = wanted
            .strip_prefix("urn:uuid:")
            .unwrap_or(&wanted)
            .to_string();
        let (realm, base) = self.realm();
        let users = format!(",ou=users,{}", base).to_lowercase();
        self.directory
            .realm_entries(&realm)
            .into_iter()
            .find(|(k, e)| {
                k.ends_with(&users)
                    && first(e, "entryUUID").to_lowercase() == wanted
            })
            .map(|(_, e)| first(&e, "uid"))
            .unwrap_or_default()
    }
}

/// `common/applications.js`, as the core reads it, off the entries.
pub struct DirectoryApplications {
    pub directory: Arc<MemoryDirectory>,
    pub registry: Arc<RealmRegistry>,
    pub keystore: Arc<dyn cred_ports::Keystore>,
}

impl DirectoryApplications {
    fn all(&self) -> Vec<StoredEntry> {
        let here = realm::current();
        let under =
            format!(",ou=applications,{}", self.registry.base_dn_of(&here))
                .to_lowercase();
        self.directory
            .realm_entries(&here.id)
            .into_iter()
            .filter(|(k, _)| k.ends_with(&under))
            .map(|(_, e)| e)
            .collect()
    }

    fn view(entry: &StoredEntry) -> Application {
        Application {
            identifier: first(entry, "appIdentifier"),
            fields: entry
                .attributes
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        }
    }
}

impl Applications for DirectoryApplications {
    fn find(&self, id: &str) -> Option<Application> {
        let all = self.all();
        all.iter()
            .find(|e| first(e, "oauthClientId") == id)
            .or_else(|| all.iter().find(|e| first(e, "appIdentifier") == id))
            .map(DirectoryApplications::view)
    }

    fn get(&self, identifier: &str) -> Option<Application> {
        self.all()
            .iter()
            .find(|e| first(e, "appIdentifier") == identifier)
            .map(DirectoryApplications::view)
    }

    fn client_secret(&self, identifier: &str) -> String {
        let Some(app) = self.get(identifier) else {
            return String::new();
        };
        let now_s = sts_core::time::now_ms_f64() / 1000.0;
        let mut records: Vec<(f64, f64, String)> = Vec::new();
        for value in app.field("oauthClientSecret") {
            let opened = if sts_crypto::secrets::is_encrypted_with_kek(&value) {
                self.keystore
                    .open(&value, "client-secret")
                    .unwrap_or_default()
            } else {
                value.clone()
            };
            match serde_json::from_str::<Json>(&opened) {
                Ok(record) if record.get("secret").is_some() => records.push((
                    record
                        .get("createdAt")
                        .and_then(Json::as_f64)
                        .unwrap_or(0.0),
                    record
                        .get("expiresAt")
                        .and_then(Json::as_f64)
                        .unwrap_or(0.0),
                    record
                        .get("secret")
                        .and_then(Json::as_str)
                        .unwrap_or("")
                        .to_string(),
                )),
                _ => records.push((0.0, 0.0, opened)),
            }
        }
        records.sort_by(|a, b| b.0.total_cmp(&a.0));
        records
            .iter()
            .find(|(_, expires, _)| *expires == 0.0 || *expires > now_s)
            .or_else(|| records.first())
            .map(|(_, _, s)| s.clone())
            .unwrap_or_default()
    }
}

/// `credentials.verifyAsync()`.
pub struct CredentialPasswords {
    pub credentials: Arc<Credentials>,
}

impl Passwords for CredentialPasswords {
    fn verify(
        &self,
        name: &str,
        password: &str,
        via: &str,
        door: &str,
    ) -> PasswordVerdict {
        let verdict = self.credentials.verify(
            name,
            password,
            &VerifyOptions {
                via: Some(via.to_string()),
                door: Some(door.to_string()),
                ..Default::default()
            },
        );
        PasswordVerdict {
            ok: verdict.value.get("ok") == Some(&Json::Bool(true)),
            app_password: verdict
                .value
                .get("appPassword")
                .and_then(|a| a.get("name"))
                .and_then(Json::as_str)
                .map(str::to_string),
        }
    }
}

/// Admin Write: membership of the group `admin.writeGroup` names.
pub struct GroupRoster {
    pub directory: Arc<MemoryDirectory>,
    pub registry: Arc<RealmRegistry>,
    pub settings: Arc<Settings>,
}

impl Roster for GroupRoster {
    fn roles_of(&self, name: &str, realm_id: &str) -> Roles {
        let Some(r) = self.registry.get(realm_id) else {
            return Roles::default();
        };
        let base = self.registry.base_dn_of(&r);
        let group = realm::run_sync(r.clone(), || {
            self.settings
                .value_of("admin.writeGroup")
                .as_str()
                .to_string()
        });
        if group.is_empty() || name.is_empty() {
            return Roles::default();
        }
        let person =
            format!("uid={},ou=users,{}", name.trim(), base).to_lowercase();
        let groups = format!(",ou=groups,{}", base).to_lowercase();
        let write =
            self.directory
                .realm_entries(&r.id)
                .into_iter()
                .any(|(k, e)| {
                    k.ends_with(&groups)
                        && first(&e, "cn").eq_ignore_ascii_case(&group)
                        && e.attributes.get("member").is_some_and(|m| {
                            m.iter().any(|v| v.to_lowercase() == person)
                        })
                });
        Roles {
            write,
            open: false,
            claim_pending: false,
        }
    }
}

/// `keystore.persists()` / `seal()` / `open()` over the store's data keys.
pub struct DataKeysPort {
    pub persistence: Arc<Persistence>,
}

impl cred_ports::Keystore for DataKeysPort {
    fn persists(&self) -> bool {
        self.persistence.data_keys().sealed()
    }
    fn seal(&self, plain: &str, label: &str, scope: &str) -> Option<String> {
        self.persistence.data_keys().seal(plain, label, scope)
    }
    fn open(&self, sealed: &str, label: &str) -> Option<String> {
        self.persistence.data_keys().open(sealed, label)
    }
}

/// `replication.remoteRows(handle, undefined, key)` over the store's fan-in:
/// the `merge: own` rows every other process — and a previous run of this
/// one — wrote, which the monitor adds to its own.
struct StoreFanIn(Arc<Persistence>);

impl crate::monitor::RemoteRows for StoreFanIn {
    fn remote_rows(&self, handle: &str, key: &str) -> Vec<Json> {
        self.0
            .minted()
            .map(|m| m.fan_in().remote_rows(handle, None, key))
            .unwrap_or_default()
    }
}

/// What the runtime hands the stack.
pub struct RuntimeParts {
    pub settings: Arc<Settings>,
    pub mode: Arc<Mode>,
    pub registry: Arc<RealmRegistry>,
    pub lifecycle: Arc<RealmLifecycle>,
    pub directory: Arc<MemoryDirectory>,
    pub persistence: Arc<Persistence>,
    pub credentials: Arc<Credentials>,
    pub claims: Arc<dyn sts_cluster::scheduler::Claims>,
    pub http: Arc<sts_http::HttpLayer>,
}

/// The three families' stores, declared before the store opens.
pub struct EnrollStack {
    pub acme: AcmeStore,
    pub est: EstStore,
    pub scep: ScepStore,
    /// `enrollment_monitor.{acme,est,scep}`.
    pub monitor: crate::monitor::EnrollmentMonitor,
}

/// The three servers, once built.
pub struct Families {
    pub core: Arc<Core>,
    pub acme: Arc<Acme>,
    pub est: Arc<Est>,
    pub scep: Arc<Scep>,
    pub http: Arc<sts_http::HttpLayer>,
    pub settings: Arc<Settings>,
    /// What the three have done (`enrollment_monitor.ts`), for the monitor
    /// views; the same instance the core records through.
    pub monitor: Arc<crate::monitor::EnrollmentMonitor>,
}

impl EnrollStack {
    /// Declares the stores (`acme.*`, `devices.challenges`,
    /// `scep.transactions`, `enrollment_monitor.*`).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn declare(
        lifecycle: &Arc<RealmLifecycle>,
        handles: &Arc<StoreHandles>,
    ) -> EnrollStack {
        EnrollStack {
            acme: AcmeStore::declare(lifecycle, handles),
            est: EstStore::declare(lifecycle, handles),
            scep: ScepStore::declare(lifecycle, handles),
            monitor: crate::monitor::EnrollmentMonitor::declare(
                lifecycle, handles,
            ),
        }
    }

    /// The families over the authority.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn families(
        &self,
        parts: RuntimeParts,
        authority: Arc<Authority>,
    ) -> Arc<Families> {
        let keystore: Arc<dyn cred_ports::Keystore> = Arc::new(DataKeysPort {
            persistence: parts.persistence.clone(),
        });
        let env = Arc::new(EnrollEnv {
            settings: parts.settings.clone(),
            mode: parts.mode.clone(),
        });
        let quiet = Arc::new(Quiet);
        let monitor = Arc::new(
            self.monitor
                .clone()
                .with_remote(Arc::new(StoreFanIn(parts.persistence.clone()))),
        );
        let core = Core::new(CoreDeps {
            settings: parts.settings.clone(),
            mode: parts.mode.clone(),
            registry: parts.registry.clone(),
            lifecycle: Some(parts.lifecycle.clone()),
            authority,
            entries: Arc::new(DirectoryEntries {
                directory: parts.directory.clone(),
                persistence: parts.persistence.clone(),
                registry: parts.registry.clone(),
            }),
            applications: Arc::new(DirectoryApplications {
                directory: parts.directory.clone(),
                registry: parts.registry.clone(),
                keystore: keystore.clone(),
            }),
            passwords: Arc::new(CredentialPasswords {
                credentials: parts.credentials.clone(),
            }),
            roster: Arc::new(GroupRoster {
                directory: parts.directory.clone(),
                registry: parts.registry.clone(),
                settings: parts.settings.clone(),
            }),
            gate: quiet.clone(),
            audit: quiet.clone(),
            signals: quiet.clone(),
            monitor: monitor.clone(),
            keystore,
            claims: parts.claims.clone(),
            limits: Arc::new(RateLimiter::new(
                env,
                Arc::new(MemoryBuckets::default()),
            )),
        });
        Arc::new(Families {
            acme: Acme::new(core.clone(), self.acme.clone()),
            est: Est::new(core.clone(), self.est.clone()),
            scep: Scep::new(core.clone(), self.scep.clone()),
            core,
            http: parts.http,
            settings: parts.settings,
            monitor,
        })
    }
}

impl Families {
    /// One request, to whichever family's paths it names.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn serve(self: Arc<Self>, request: Request) -> Response {
        let original = request
            .extensions()
            .get::<sts_http::OriginalPath>()
            .map(|p| p.0.clone());
        let method = request.method().clone();
        let uri = request.uri().clone();
        let req = crate::http::read(&self.http, &self.settings, request).await;
        let lower = req.path.to_ascii_lowercase();
        let reply = if lower.starts_with("/enroll/acme") {
            self.acme.handle(&req).await
        } else if lower.starts_with("/.well-known/est") {
            self.est.handle(&req).await
        } else if lower.starts_with("/enroll/scep") {
            self.scep.handle(&req).await
        } else {
            None
        };
        match reply {
            Some(r) => r.into_response(),
            None => {
                let path = original.unwrap_or_else(|| uri.path().to_string());
                sts_http::not_found(method, path.parse().unwrap_or(uri), None)
                    .await
            }
        }
    }

    /// The routes `stack.rs` merges: every path under the three prefixes.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn router(self: &Arc<Self>) -> axum::Router {
        let mut router = axum::Router::new();
        for prefix in ["/enroll/acme", "/.well-known/est", "/enroll/scep"] {
            for path in [prefix.to_string(), format!("{}/{{*rest}}", prefix)] {
                let me = self.clone();
                router = router.route(
                    &path,
                    axum::routing::any(move |request: Request| {
                        let me = me.clone();
                        async move { me.serve(request).await }
                    }),
                );
            }
        }
        router
    }
}
