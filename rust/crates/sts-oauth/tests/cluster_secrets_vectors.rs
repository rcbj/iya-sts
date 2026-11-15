// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The `oidc-pairwise` cluster secret against Node (D11): Node's own
//! `ClusterSecrets.start()` sealed and stored it, and Node's
//! `PairwiseSubjects.subjectFor()` derived subjects from it
//! (`cluster-secrets-node.json`, `tests/tools/cluster-secrets-vectors.js`).
//! Here the same key rows and secret rows are handed to
//! `sts_store::cluster_secrets` under the same key-encryption key, and
//! [`PairwiseSubjects`] must derive every one of Node's subjects — which is
//! what keeps a client's view of a person the same across the upgrade.
//!
//! With `STS_WRITE_VECTORS=1`, `cluster-secrets-rust.json` carries the rows
//! Rust's `start()` wrote on an EMPTY store under that key and the subjects
//! it derived, for Node to open, keep and derive again
//! (`tests/rust_crypto_vectors.js`).
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed (the KEK is in
//! it); with it unset this test says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde_json::{json, Map, Value as Json};
use sts_core::mode::Mode;
use sts_core::realm::{Realm, RealmRegistry, SettingsEnvironment};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::StoreHandles;
use sts_core::settings::Settings;
use sts_oauth::clients::Clients;
use sts_oauth::pairwise::PairwiseSubjects;
use sts_store::cluster_secrets::ClusterSecrets;
use sts_store::driver::{Directory, KeyMerge, SharedSecretRow};
use sts_store::keystore::DataKeys;
use sts_store::ldif_driver::LdifDriver;
use sts_store::model::DirectoryOutcome;
use sts_store::{DirectoryChange, Driver, StoreFuture};

fn vectors() -> Option<(PathBuf, Json)> {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: cluster-secrets-node.json is \
             not checked"
        );
        return None;
    };
    let dir = PathBuf::from(dir);
    let text =
        std::fs::read_to_string(dir.join("cluster-secrets-node.json")).ok()?;
    Some((dir, serde_json::from_str(&text).unwrap()))
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sts-cluster-secrets-{}-{}",
        name,
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// An ldif store for the key rows, and `sts_cluster_secrets` as postgres
/// keeps it: first writer wins.
struct Sharing {
    inner: LdifDriver,
    secrets: Mutex<Vec<SharedSecretRow>>,
    names: Mutex<Vec<String>>,
}

impl Driver for Sharing {
    fn name(&self) -> &'static str {
        "postgres"
    }
    fn open(&self) -> StoreFuture<'_, ()> {
        self.inner.open()
    }
    fn close(&self) -> StoreFuture<'_, ()> {
        self.inner.close()
    }
    fn load_directory(&self) -> StoreFuture<'_, Option<Directory>> {
        self.inner.load_directory()
    }
    fn load_realms(&self) -> StoreFuture<'_, Option<Vec<Json>>> {
        self.inner.load_realms()
    }
    fn load_overrides(&self) -> StoreFuture<'_, Option<Map<String, Json>>> {
        self.inner.load_overrides()
    }
    fn save_directory<'a>(
        &'a self,
        change: &'a DirectoryChange,
    ) -> StoreFuture<'a, Vec<DirectoryOutcome>> {
        self.inner.save_directory(change)
    }
    fn save_realms<'a>(&'a self, rows: &'a [Json]) -> StoreFuture<'a, ()> {
        self.inner.save_realms(rows)
    }
    fn save_overrides<'a>(
        &'a self,
        overrides: &'a Map<String, Json>,
    ) -> StoreFuture<'a, ()> {
        self.inner.save_overrides(overrides)
    }
    fn load_keys(&self) -> StoreFuture<'_, Vec<(String, String)>> {
        self.inner.load_keys()
    }
    fn save_keys<'a>(
        &'a self,
        realm: &'a str,
        material: &'a str,
    ) -> StoreFuture<'a, ()> {
        self.inner.save_keys(realm, material)
    }
    fn merges_keys(&self) -> bool {
        self.inner.merges_keys()
    }
    fn merge_keys<'a>(
        &'a self,
        realm: &'a str,
        merge: KeyMerge,
    ) -> StoreFuture<'a, Option<String>> {
        self.inner.merge_keys(realm, merge)
    }
    fn shares_secrets(&self) -> bool {
        true
    }
    fn ensure_shared_secret<'a>(
        &'a self,
        name: &'a str,
        material: &'a str,
    ) -> StoreFuture<'a, Option<SharedSecretRow>> {
        Box::pin(async move {
            let mut names = self.names.lock().unwrap();
            let mut rows = self.secrets.lock().unwrap();
            let at = names.iter().position(|n| n == name);
            let offered = at.is_none();
            let i = match at {
                Some(i) => i,
                None => {
                    names.push(name.to_string());
                    rows.push(SharedSecretRow {
                        material: material.to_string(),
                        created_by: "rust".to_string(),
                        created_at: 1,
                        offered: true,
                    });
                    rows.len() - 1
                }
            };
            let mut row = rows[i].clone();
            row.offered = offered;
            Ok(Some(row))
        })
    }
}

async fn store_of(
    key_rows: &Json,
    secret_rows: &Json,
    name: &str,
) -> Arc<Sharing> {
    let sharing = Arc::new(Sharing {
        inner: LdifDriver::new(scratch(name)),
        secrets: Mutex::new(Vec::new()),
        names: Mutex::new(Vec::new()),
    });
    for row in key_rows.as_array().unwrap() {
        sharing
            .save_keys(
                row["realm"].as_str().unwrap(),
                row["material"].as_str().unwrap(),
            )
            .await
            .unwrap();
    }
    for row in secret_rows.as_array().unwrap() {
        sharing
            .names
            .lock()
            .unwrap()
            .push(row["name"].as_str().unwrap().to_string());
        sharing.secrets.lock().unwrap().push(SharedSecretRow {
            material: row["material"].as_str().unwrap().to_string(),
            created_by: "node".to_string(),
            created_at: 1,
            offered: false,
        });
    }
    sharing
}

/// The vector's clients, by id.
struct VectorClients(Json);

impl Clients for VectorClients {
    fn client_config_of(&self, client_id: &str) -> Json {
        self.0.get(client_id).cloned().unwrap_or_else(|| json!({}))
    }
    fn declared_flows_of(&self, _client_id: &str) -> Option<Json> {
        None
    }
}

fn subjects_of(v: &Json, secrets: Arc<ClusterSecrets>) -> Vec<Json> {
    let settings = Arc::new(Settings::new(json!({}), HashMap::new()));
    let registry = Arc::new(RealmRegistry::new(Arc::new(
        SettingsEnvironment::new(settings.clone(), Vec::new()),
    )));
    let lifecycle = RealmLifecycle::new(
        registry,
        settings.clone(),
        Arc::new(Mode::new(settings.clone())),
    );
    let pairwise = PairwiseSubjects {
        settings,
        clients: Arc::new(VectorClients(v["clients"].clone())),
        secret: Arc::new(move || secrets.text("oidc-pairwise").unwrap()),
        ephemeral: PairwiseSubjects::declare_ephemeral(
            &lifecycle,
            &StoreHandles::new(),
        ),
        now_ms: Arc::new(|| 0.0),
    };
    let mut out = Vec::new();
    for realm in v["realms"].as_array().unwrap() {
        let realm = realm.as_str().unwrap();
        let record = Arc::new(if realm.is_empty() {
            Realm::default_realm()
        } else {
            Realm {
                id: realm.to_string(),
                ..Realm::default_realm()
            }
        });
        for client in v["clients"].as_object().unwrap().keys() {
            for local in v["locals"].as_array().unwrap() {
                let local = local.as_str().unwrap();
                let sub = sts_core::realm::run_sync(record.clone(), || {
                    pairwise.subject_for(client, local, "").unwrap()
                });
                out.push(json!({ "realm": realm, "client": client,
                                 "local": local, "sub": sub }));
            }
        }
    }
    out
}

fn kek_of(dir: &std::path::Path, v: &Json) -> Vec<u8> {
    let (kek, text) = DataKeys::read_kek_file(
        dir.join(v["kekFile"].as_str().unwrap()).to_str().unwrap(),
    )
    .unwrap();
    assert!(text);
    kek
}

#[tokio::test]
async fn the_pairwise_subjects_node_derived_are_derived_here() {
    let Some((dir, v)) = vectors() else {
        return;
    };
    assert_eq!(v["started"]["shared"], true, "{}", v["started"]);
    let kek = kek_of(&dir, &v);
    let store = store_of(&v["keyRows"], &v["secretRows"], "node").await;
    let driver: Arc<dyn Driver> = store.clone();
    let keys = DataKeys::durable(kek, true, driver.clone(), None).unwrap();
    keys.load(true).await.unwrap();
    let secrets = Arc::new(ClusterSecrets::with_env(Arc::new(|_: &str| None)));
    let started = secrets.start(Some(&driver), &keys, false).await.unwrap();
    assert_eq!(started["shared"], true);
    // NODE'S ROWS ARE KEPT: Rust's own offers lost to them.
    assert_eq!(
        store.secrets.lock().unwrap().len(),
        v["secretRows"].as_array().unwrap().len()
    );
    assert_eq!(
        secrets.describe()["secrets"][3],
        json!({ "name": "oidc-pairwise", "source": "store",
                "what": "The key an OpenID Connect pairwise subject \
                         identifier is derived with \
                         (oauth-oidc/pairwise_subjects.ts, OIDC Core \
                         section 8.1)." })
    );
    let mine = subjects_of(&v, secrets);
    let theirs = v["subjects"].as_array().unwrap();
    assert_eq!(theirs.len(), 12);
    assert_eq!(&mine, theirs);
}

#[tokio::test]
async fn rust_offers_on_an_empty_store_for_node_to_keep() {
    let Some((dir, v)) = vectors() else {
        return;
    };
    let kek = kek_of(&dir, &v);
    let store = store_of(&json!([]), &json!([]), "rust").await;
    let driver: Arc<dyn Driver> = store.clone();
    let keys = DataKeys::durable(kek, true, driver.clone(), None).unwrap();
    keys.load(true).await.unwrap();
    let secrets = Arc::new(ClusterSecrets::with_env(Arc::new(|_: &str| None)));
    let started = secrets.start(Some(&driver), &keys, false).await.unwrap();
    assert_eq!(started["names"].as_array().unwrap().len(), 7);
    // A second process on the store keeps what the first offered.
    let again = Arc::new(ClusterSecrets::with_env(Arc::new(|_: &str| None)));
    again.start(Some(&driver), &keys, false).await.unwrap();
    assert_eq!(
        again.text("oidc-pairwise").unwrap(),
        secrets.text("oidc-pairwise").unwrap()
    );
    let subjects = subjects_of(&v, secrets);
    // A different secret, so different subjects from Node's.
    assert_ne!(&subjects, v["subjects"].as_array().unwrap());
    if std::env::var("STS_WRITE_VECTORS").as_deref() == Ok("1") {
        let key_rows: Vec<Json> = driver
            .load_keys()
            .await
            .unwrap()
            .into_iter()
            .map(|(realm, material)| {
                json!({ "realm": realm,
                                             "material": material })
            })
            .collect();
        let names = store.names.lock().unwrap().clone();
        let secret_rows: Vec<Json> = store
            .secrets
            .lock()
            .unwrap()
            .iter()
            .zip(names)
            .map(|(row, name)| {
                json!({ "name": name,
                                       "material": row.material,
                                       "createdBy": row.created_by,
                                       "createdAt": row.created_at })
            })
            .collect();
        std::fs::write(
            dir.join("cluster-secrets-rust.json"),
            serde_json::to_string(&json!({
                "kekFile": v["kekFile"],
                "keyRows": key_rows,
                "secretRows": secret_rows,
                "subjects": subjects,
            }))
            .unwrap(),
        )
        .unwrap();
    }
}

#[tokio::test]
async fn an_ephemeral_key_shares_nothing_and_active_active_refuses() {
    let store = store_of(&json!([]), &json!([]), "ephemeral").await;
    let driver: Arc<dyn Driver> = store.clone();
    let keys =
        DataKeys::ephemeral("a run's own key-encryption key, 32 bytes or more")
            .unwrap();
    let secrets = ClusterSecrets::with_env(Arc::new(|_: &str| None));
    let out = secrets.start(Some(&driver), &keys, false).await.unwrap();
    assert_eq!(out, json!({ "shared": false }));
    assert!(store.secrets.lock().unwrap().is_empty());
    let refused = ClusterSecrets::with_env(Arc::new(|_: &str| None))
        .start(Some(&driver), &keys, true)
        .await
        .unwrap_err();
    assert_eq!(
        refused,
        format!(
            "{}cluster secrets: active-active mode and no key-encryption \
             key is open to seal the shared secrets with.",
            sts_core::log::tag(sts_core::errors::codes::STS_CLUSTER_0017)
        )
    );
}
