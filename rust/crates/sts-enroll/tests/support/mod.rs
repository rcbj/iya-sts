// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What the integration tests share: an in-memory directory, development's
//! password door, an empty roster, a keystore that seals nothing, local
//! claims, a certificate authority built for the run, and the three
//! families over them.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)] // tests

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value as Json};
use sts_cluster::scheduler::{Claim, ClaimRefused, Claims};
use sts_core::mode::Mode;
use sts_core::realm::{RealmRegistry, SettingsEnvironment};
use sts_core::settings::Settings;
use sts_credentials::limits::{MemoryBuckets, RateLimiter};
use sts_enroll::acme::store::AcmeStore;
use sts_enroll::acme::Acme;
use sts_enroll::core::{Core, CoreDeps};
use sts_enroll::est::{Est, EstStore};
use sts_enroll::http::Req;
use sts_enroll::ports::*;
use sts_enroll::scep::{Scep, ScepStore};
use sts_pki::authority::{Authority, MemoryRows, PkiConfig};

// ---------------------------------------------------------------------
// The fakes.
// ---------------------------------------------------------------------

/// An entry's attributes, by lower-cased name.
pub type Attributes = BTreeMap<String, Vec<String>>;

#[derive(Default)]
pub struct Directory {
    entries: Mutex<BTreeMap<(String, String), Attributes>>,
}

impl Directory {
    /// An entry with exactly these attributes (any case).
    pub fn put(
        &self,
        kind: &str,
        id: &str,
        attrs: &BTreeMap<String, Vec<String>>,
    ) {
        let held = attrs
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.clone()))
            .collect();
        self.entries
            .lock()
            .unwrap()
            .insert((kind.into(), id.into()), held);
    }

    /// An entry's attributes, by lower-cased name.
    pub fn attributes(
        &self,
        kind: &str,
        id: &str,
    ) -> BTreeMap<String, Vec<String>> {
        self.entries
            .lock()
            .unwrap()
            .get(&(kind.to_string(), id.to_string()))
            .cloned()
            .unwrap_or_default()
    }

    fn add(&self, kind: &str, id: &str, attrs: &[(&str, &[&str])]) {
        let mut map = BTreeMap::new();
        for (k, v) in attrs {
            map.insert(
                k.to_lowercase(),
                v.iter().map(|s| s.to_string()).collect(),
            );
        }
        self.entries
            .lock()
            .unwrap()
            .insert((kind.into(), id.into()), map);
    }
}

impl Entries for Directory {
    fn read(&self, kind: &str, id: &str) -> Option<EntryRead> {
        let held = self.entries.lock().unwrap();
        let attrs = held.get(&(kind.to_string(), id.to_string()))?;
        Some(EntryRead {
            dn: format!("uid={},ou=users,dc=test", id),
            attributes: attrs.clone(),
        })
    }
    fn write(
        &self,
        kind: &str,
        id: &str,
        name: &str,
        values: &[String],
    ) -> bool {
        let mut held = self.entries.lock().unwrap();
        let Some(attrs) = held.get_mut(&(kind.to_string(), id.to_string()))
        else {
            return false;
        };
        if values.is_empty() {
            attrs.remove(&name.to_lowercase());
        } else {
            attrs.insert(name.to_lowercase(), values.to_vec());
        }
        true
    }
    fn holders_with_values(
        &self,
        kind: &str,
        name: &str,
    ) -> Vec<(String, Vec<String>)> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter(|((k, _), _)| k == kind)
            .filter_map(|((_, id), a)| {
                a.get(&name.to_lowercase()).map(|v| (id.clone(), v.clone()))
            })
            .collect()
    }
    fn subject_for_name(&self, name: &str) -> String {
        format!("urn:uuid:{}", name)
    }
    fn name_for_subject(&self, subject: &str) -> String {
        subject.trim_start_matches("urn:uuid:").to_string()
    }
}

pub struct NoApplications;
impl Applications for NoApplications {
    fn find(&self, _id: &str) -> Option<Application> {
        None
    }
    fn get(&self, _id: &str) -> Option<Application> {
        None
    }
    fn client_secret(&self, _id: &str) -> String {
        String::new()
    }
}

/// Development's password door: anything but `invalid`.
pub struct AnyPassword;
impl Passwords for AnyPassword {
    fn verify(
        &self,
        _n: &str,
        password: &str,
        _via: &str,
        _door: &str,
    ) -> PasswordVerdict {
        PasswordVerdict {
            ok: password != "invalid",
            app_password: None,
        }
    }
}

pub struct NoRoster;
impl Roster for NoRoster {
    fn roles_of(&self, _n: &str, _r: &str) -> Roles {
        Roles::default()
    }
}

pub struct Plain;
impl sts_credentials::ports::Keystore for Plain {
    fn persists(&self) -> bool {
        false
    }
    fn seal(&self, plain: &str, _l: &str, _s: &str) -> Option<String> {
        Some(plain.into())
    }
    fn open(&self, sealed: &str, _l: &str) -> Option<String> {
        Some(sealed.into())
    }
}

#[derive(Default)]
pub struct HeldClaims(Mutex<std::collections::HashSet<String>>);
impl Claims for HeldClaims {
    fn claim(
        &self,
        scope: &str,
        value: &str,
        _realm: &str,
        _ttl: f64,
    ) -> sts_cluster::schedule::BoxFuture<'_, Result<Claim, ClaimRefused>> {
        let key = format!("{}|{}", scope, value);
        let fresh = self.0.lock().unwrap().insert(key.clone());
        Box::pin(async move {
            if fresh {
                Ok(Claim {
                    claimed_at: 0.0,
                    handle: Json::from(key),
                })
            } else {
                Err(ClaimRefused::Held)
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

pub struct Env(Arc<Settings>);
impl sts_credentials::ports::Environment for Env {
    fn setting(&self, key: &str) -> Json {
        Json::from(self.0.value_of(key).as_int())
    }
    fn predicate(&self, _name: &str) -> bool {
        false
    }
    fn now_ms(&self) -> f64 {
        sts_core::time::now_ms_f64()
    }
    fn realm_id(&self) -> String {
        "default".into()
    }
    fn random_bytes(&self, n: usize) -> Vec<u8> {
        sts_crypto::random::random_bytes(n).unwrap()
    }
    fn random_int(&self, min: u64, _max: u64) -> u64 {
        min
    }
    fn hash_secret(&self, p: &str) -> String {
        p.into()
    }
}

pub struct World {
    pub core: Arc<Core>,
    pub directory: Arc<Directory>,
    pub acme: Arc<Acme>,
    pub est: Arc<Est>,
    pub scep: Arc<Scep>,
}

pub fn world() -> World {
    let settings = Arc::new(Settings::new(json!({}), HashMap::new()));
    let mode = Arc::new(Mode::new(settings.clone()));
    let registry = Arc::new(RealmRegistry::new(Arc::new(
        SettingsEnvironment::new(settings.clone(), Vec::new()),
    )));
    let lifecycle = sts_core::realm_lifecycle::RealmLifecycle::new(
        registry.clone(),
        settings.clone(),
        mode.clone(),
    );
    let handles = sts_core::realm_store::StoreHandles::new();
    let authority = Authority::new(
        Arc::new(MemoryRows::default()),
        PkiConfig::development(),
    );
    let started = authority.start(&[]);
    assert!(started.built, "{:?}", started);
    let directory = Arc::new(Directory::default());
    directory.add(
        "person",
        "alicew",
        &[
            ("mail", &["alicew@example.test"]),
            ("stsCertificateHostName", &["www.alicew.test"]),
        ],
    );
    directory.add("person", "bobw", &[("mail", &["bobw@example.test"])]);
    let quiet = Arc::new(Quiet);
    let core = Core::new(CoreDeps {
        settings: settings.clone(),
        mode,
        registry,
        lifecycle: Some(lifecycle.clone()),
        authority,
        entries: directory.clone(),
        applications: Arc::new(NoApplications),
        passwords: Arc::new(AnyPassword),
        roster: Arc::new(NoRoster),
        gate: quiet.clone(),
        audit: quiet.clone(),
        signals: quiet.clone(),
        monitor: quiet,
        keystore: Arc::new(Plain),
        claims: Arc::new(HeldClaims::default()),
        limits: Arc::new(RateLimiter::new(
            Arc::new(Env(settings)),
            Arc::new(MemoryBuckets::default()),
        )),
    });
    World {
        acme: Acme::new(core.clone(), AcmeStore::declare(&lifecycle, &handles)),
        est: Est::new(core.clone(), EstStore::declare(&lifecycle, &handles)),
        scep: Scep::new(core.clone(), ScepStore::declare(&lifecycle, &handles)),
        core,
        directory,
    }
}

pub const BASE: &str = "http://localhost";

pub fn req(
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> Req {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let mut map = axum::http::HeaderMap::new();
    for (k, v) in headers {
        map.insert(
            axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
            v.parse().unwrap(),
        );
    }
    map.insert("content-length", body.len().to_string().parse().unwrap());
    Req {
        method: method.into(),
        path: path.into(),
        query: query.into(),
        headers: map,
        text: None,
        body,
        base: BASE.into(),
        address: "127.0.0.1".into(),
        over_tls: false,
        peer_chain: Vec::new(),
    }
}

pub fn json_of(reply: &sts_enroll::http::Reply) -> Json {
    serde_json::from_slice(&reply.body).unwrap_or(Json::Null)
}
