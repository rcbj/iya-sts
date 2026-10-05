// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Persistence end to end over the real ldif driver, in a directory of its
//! own: a first start writes the seeded directory; an entry, a realm and an
//! override are written and waited for; a removed realm takes its file with
//! it; a failed write loses nothing and its retry lands; and a second start
//! reads everything back, primes the shadow so nothing is rewritten, and
//! refuses rows of a realm that is not defined.

#![allow(clippy::unwrap_used)] // a test file

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use indexmap::IndexMap;
use serde_json::{json, Map, Value as Json};
use sts_core::mode::Mode;
use sts_core::realm::{RealmEnvironment, RealmRegistry};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::settings::Settings;
use sts_store::driver::{Directory, Driver, StoreError, StoreFuture};
use sts_store::ldif_driver::LdifDriver;
use sts_store::persistence::{LiveDirectory, Persistence, StoreMode, Through};
use sts_store::shadow::EntryLookup;
use sts_store::{DirectoryChange, StoredEntry};

struct Env(Arc<Settings>);

impl RealmEnvironment for Env {
    fn enabled(&self) -> bool {
        true
    }
    fn path_segment(&self) -> String {
        "realm".to_string()
    }
    fn global_domain(&self) -> String {
        self.0.value_of("global.domain").as_str().to_string()
    }
    fn reserved(&self) -> Vec<String> {
        Vec::new()
    }
    fn est_labels(&self) -> Vec<String> {
        Vec::new()
    }
}

#[derive(Default)]
struct Dir(Mutex<IndexMap<String, IndexMap<String, StoredEntry>>>);

impl EntryLookup for Dir {
    fn entry_at(&self, realm: &str, key: &str) -> Option<StoredEntry> {
        self.0.lock().unwrap().get(realm)?.get(key).cloned()
    }
}

impl LiveDirectory for Dir {
    fn realm_entries(&self, realm: &str) -> IndexMap<String, StoredEntry> {
        self.0
            .lock()
            .unwrap()
            .get(realm)
            .cloned()
            .unwrap_or_default()
    }
    fn replace_realm(&self, realm: &str, entries: Vec<StoredEntry>) {
        let rows = entries
            .into_iter()
            .map(|e| (e.dn.to_lowercase(), e))
            .collect();
        self.0.lock().unwrap().insert(realm.to_string(), rows);
    }
}

impl Dir {
    fn put(&self, realm: &str, dn: &str, cn: &str) {
        let mut attributes = IndexMap::new();
        attributes.insert("cn".to_string(), vec![cn.to_string()]);
        let entry = StoredEntry {
            dn: dn.to_string(),
            attributes,
            ..StoredEntry::default()
        };
        self.0
            .lock()
            .unwrap()
            .entry(realm.to_string())
            .or_default()
            .insert(dn.to_lowercase(), entry);
    }
}

/// The ldif driver, made to fail on demand.
struct Flaky {
    inner: LdifDriver,
    failing: AtomicBool,
}

impl Driver for Flaky {
    fn name(&self) -> &'static str {
        "ldif"
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
    ) -> StoreFuture<'a, ()> {
        if self.failing.load(Ordering::SeqCst) {
            return Box::pin(async {
                Err(StoreError::new("the disk is full".to_string()))
            });
        }
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
}

struct World {
    persistence: Arc<Persistence>,
    lifecycle: Arc<RealmLifecycle>,
    settings: Arc<Settings>,
    dir: Arc<Dir>,
    driver: Arc<Flaky>,
}

fn world(path: &Path) -> World {
    let settings = Arc::new(Settings::new(Json::Null, HashMap::new()));
    let registry =
        Arc::new(RealmRegistry::new(Arc::new(Env(settings.clone()))));
    let lifecycle = RealmLifecycle::new(
        registry,
        settings.clone(),
        Arc::new(Mode::new(settings.clone())),
    );
    let dir = Arc::new(Dir::default());
    dir.put("default", "dc=example,dc=com", "seeded");
    let driver = Arc::new(Flaky {
        inner: LdifDriver::new(path.to_path_buf()),
        failing: AtomicBool::new(false),
    });
    let persistence = Persistence::new(
        StoreMode::Ldif,
        Some(driver.clone()),
        settings.clone(),
        lifecycle.clone(),
        dir.clone(),
    );
    World {
        persistence,
        lifecycle,
        settings,
        dir,
        driver,
    }
}

fn read(path: &Path, name: &str) -> String {
    std::fs::read_to_string(path.join(name)).unwrap_or_default()
}

#[tokio::test(start_paused = true)]
async fn what_is_written_is_read_back() {
    let path = std::env::temp_dir()
        .join(format!("sts-persistence-{}", std::process::id()));
    let _gone = std::fs::remove_dir_all(&path).is_ok();

    let w = world(&path);
    assert_eq!(w.persistence.start().await.unwrap(), Default::default());
    // The first flush writes the seeded directory.
    assert_eq!(
        w.persistence
            .directory_through(w.persistence.generation())
            .await,
        Through::Written
    );
    assert!(read(&path, "realm-default.ldif").contains("cn: seeded"));

    // An entry, a realm with an entry of its own, and an override.
    w.dir.put("default", "uid=alice,dc=example,dc=com", "Alice");
    w.persistence
        .directory_changed(Some("uid=alice,dc=example,dc=com"));
    w.lifecycle
        .create("acme", "Acme", "", "", &Map::new(), false)
        .unwrap();
    w.dir.put("acme", "dc=acme,dc=example,dc=com", "acme root");
    w.persistence
        .directory_changed(Some("dc=acme,dc=example,dc=com"));
    w.settings
        .set_override("saml2.entityId", json!("urn:process"))
        .unwrap();
    w.persistence.config_changed(None);
    assert_eq!(
        w.persistence
            .directory_through(w.persistence.generation())
            .await,
        Through::Written
    );
    assert!(read(&path, "realm-default.ldif").contains("cn: Alice"));
    assert!(read(&path, "realm-acme.ldif").contains("cn: acme root"));
    assert!(read(&path, "realms.json").contains("\"id\": \"acme\""));
    assert!(read(&path, "appconfig.json").contains("urn:process"));

    // A failed write loses nothing; its retry lands.
    w.driver.failing.store(true, Ordering::SeqCst);
    w.dir.put("default", "uid=bob,dc=example,dc=com", "Bob");
    w.persistence
        .directory_changed(Some("uid=bob,dc=example,dc=com"));
    let gen = w.persistence.generation();
    assert!(
        matches!(w.persistence.directory_through(gen).await, Through::Failed(e) if e.contains("disk is full"))
    );
    assert!(w.persistence.commit_backlog());
    assert!(!read(&path, "realm-default.ldif").contains("Bob"));
    w.driver.failing.store(false, Ordering::SeqCst);
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    assert!(
        read(&path, "realm-default.ldif").contains("cn: Bob"),
        "the retry wrote it"
    );
    assert!(!w.persistence.commit_backlog());
    w.persistence.stop().await.unwrap();

    // A second start reads it all back.
    let again = world(&path);
    let restored = again.persistence.start().await.unwrap();
    assert_eq!(
        (restored.entries, restored.realms, restored.overrides),
        (4, 1, 1)
    );
    assert_eq!(
        again.settings.value_of("saml2.entityId").as_str(),
        "urn:process"
    );
    assert_eq!(again.lifecycle.registry().get("acme").unwrap().name, "Acme");
    assert!(again
        .dir
        .entry_at("default", "uid=bob,dc=example,dc=com")
        .is_some());
    let before = read(&path, "realm-default.ldif");
    assert_eq!(
        again
            .persistence
            .directory_through(again.persistence.generation())
            .await,
        Through::Written
    );
    assert_eq!(
        read(&path, "realm-default.ldif"),
        before,
        "the shadow was primed: nothing to rewrite"
    );

    // A removed realm takes its file with it.
    again.lifecycle.remove("acme").unwrap();
    assert_eq!(
        again
            .persistence
            .directory_through(again.persistence.generation())
            .await,
        Through::Written
    );
    assert!(!path.join("realm-acme.ldif").exists());
    assert!(!read(&path, "realms.json").contains("\"acme\""));
    again.persistence.stop().await.unwrap();

    // Rows of a realm the store does not define are not loaded.
    std::fs::write(
        path.join("realm-ghost.ldif"),
        "version: 1\n\ndn: dc=ghost\ncn: ghost\n\n",
    )
    .unwrap();
    let third = world(&path);
    let restored = third.persistence.start().await.unwrap();
    assert_eq!(restored.realms, 0);
    assert!(third.dir.realm_entries("ghost").is_empty());
    assert_eq!(third.persistence.status()["mode"], "ldif");
    std::fs::remove_dir_all(&path).unwrap();
}
