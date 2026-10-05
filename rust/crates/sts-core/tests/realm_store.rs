// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The per-realm stores, one rule a test, each as `common/realms.js`
//! states it: a write lands in the ambient realm and a named view in its
//! own; the empty id is the default realm and an unknown id waits in its
//! own partition; every write of a declared store is reported, a delete
//! whether or not the key was held and a clear key by key; a restore is
//! not reported and is refused for a removed realm; a removal purges; a
//! handle declared twice is refused; a shared store reports under `''`.

#![allow(clippy::unwrap_used)] // a test file

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Map, Value as Json};
use sts_core::mode::Mode;
use sts_core::realm::{self, RealmEnvironment, RealmRegistry};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{
    expiry_field, RealmMap, Reconcile, SharedMap, StoreHandles, StoreSpec,
};
use sts_core::settings::Settings;

struct Env;

impl RealmEnvironment for Env {
    fn enabled(&self) -> bool {
        true
    }
    fn path_segment(&self) -> String {
        "realm".to_string()
    }
    fn global_domain(&self) -> String {
        "example.com".to_string()
    }
    fn reserved(&self) -> Vec<String> {
        Vec::new()
    }
    fn est_labels(&self) -> Vec<String> {
        Vec::new()
    }
}

struct World {
    life: Arc<RealmLifecycle>,
    registry: Arc<RealmRegistry>,
    handles: Arc<StoreHandles>,
    notes: Arc<Mutex<Vec<String>>>,
}

fn world() -> World {
    let settings = Arc::new(Settings::new(Json::Null, HashMap::new()));
    let registry = Arc::new(RealmRegistry::new(Arc::new(Env)));
    let life = RealmLifecycle::new(
        registry.clone(),
        settings.clone(),
        Arc::new(Mode::new(settings)),
    );
    life.create("acme", "", "", "", &Map::new(), false).unwrap();
    let handles = StoreHandles::new();
    let notes = Arc::new(Mutex::new(Vec::new()));
    let n = notes.clone();
    handles.set_persist_observer(Arc::new(move |h, r, k| {
        n.lock()
            .unwrap()
            .push(format!("{}|{}|{}", h, r, k.unwrap_or("*")))
    }));
    World {
        life,
        registry,
        handles,
        notes,
    }
}

#[test]
fn a_write_lands_in_the_ambient_realm() {
    let w = world();
    let sessions: RealmMap<String> = RealmMap::new(
        &w.life,
        &w.handles,
        StoreSpec::persisted("authn.sessions"),
    );
    sessions.set("s1", "default's".to_string());
    let acme = w.registry.get("acme").unwrap();
    realm::run_sync(acme, || {
        assert!(
            sessions.get("s1").is_none(),
            "acme does not see the default realm's row"
        );
        sessions.set("s1", "acme's".to_string());
    });
    assert_eq!(sessions.get("s1").unwrap(), "default's");
    assert_eq!(sessions.in_realm("acme").get("s1").unwrap(), "acme's");
    // The empty id is the default realm.
    assert_eq!(sessions.in_realm("").get("s1").unwrap(), "default's");
    // A named view journals under its realm, wherever it is used from.
    sessions.in_realm("acme").set("s2", "x".to_string());
    assert_eq!(
        *w.notes.lock().unwrap(),
        vec![
            "authn.sessions|default|s1",
            "authn.sessions|acme|s1",
            "authn.sessions|acme|s2"
        ]
    );
}

#[test]
fn deletes_and_clears_are_reported_whole() {
    let w = world();
    let m: RealmMap<i64> =
        RealmMap::new(&w.life, &w.handles, StoreSpec::persisted("t.counts"));
    m.set("a", 1);
    m.set("b", 2);
    w.notes.lock().unwrap().clear();
    assert!(!m.delete("never-held"));
    m.update("a", |v| *v += 1);
    assert_eq!(m.get("a"), Some(2));
    m.clear();
    assert!(m.is_empty());
    assert_eq!(
        *w.notes.lock().unwrap(),
        vec![
            "t.counts|default|never-held",
            "t.counts|default|a",
            "t.counts|default|a",
            "t.counts|default|b"
        ]
    );
}

#[test]
fn a_restore_is_not_reported_and_a_removed_realm_takes_no_rows() {
    let w = world();
    let m: RealmMap<Json> =
        RealmMap::new(&w.life, &w.handles, StoreSpec::persisted("t.rows"));
    let access = w.handles.handle_for("t.rows").unwrap().access.clone();
    access.restore("acme", "k", json!({ "v": 1 }));
    access.restore("not-yet", "k", json!({ "v": 2 }));
    assert!(
        w.notes.lock().unwrap().is_empty(),
        "a restore writes nothing back"
    );
    assert_eq!(m.in_realm("acme").get("k"), Some(json!({ "v": 1 })));
    // A realm not yet heard of waits in its own partition, not the default's.
    assert_eq!(m.in_realm("not-yet").get("k"), Some(json!({ "v": 2 })));
    assert!(m.get("k").is_none());
    assert_eq!(
        access.dump("acme"),
        vec![("k".to_string(), json!({ "v": 1 }))]
    );

    w.life.remove("acme").unwrap();
    assert!(
        m.in_realm("acme").get("k").is_none(),
        "the removal purged it"
    );
    access.restore("acme", "k", json!({ "v": 3 }));
    assert!(
        m.in_realm("acme").get("k").is_none(),
        "a late row does not rebuild it"
    );
    w.life
        .create("acme", "", "", "", &Map::new(), false)
        .unwrap();
    access.restore("acme", "k", json!({ "v": 4 }));
    assert_eq!(
        m.in_realm("acme").get("k"),
        Some(json!({ "v": 4 })),
        "defined again, it takes rows"
    );
    access.remove("acme", "k");
    assert!(m.in_realm("acme").get("k").is_none());
    // A row that does not read as the store's type is refused.
    let typed: RealmMap<i64> =
        RealmMap::new(&w.life, &w.handles, StoreSpec::persisted("t.typed"));
    w.handles.handle_for("t.typed").unwrap().access.restore(
        "",
        "k",
        json!("not a number"),
    );
    assert!(typed.get("k").is_none());
}

struct OnlyNewer;

impl Reconcile<i64> for OnlyNewer {
    fn restore(
        &self,
        _key: &str,
        incoming: i64,
        held: Option<&i64>,
        _realm: &str,
    ) -> Result<Option<i64>, String> {
        if incoming < 0 {
            return Err("negative".to_string());
        }
        Ok((held.is_none_or(|h| incoming > *h)).then_some(incoming))
    }
    fn remove(
        &self,
        key: &str,
        _held: Option<&i64>,
        _realm: &str,
    ) -> Result<bool, String> {
        Ok(key != "pinned")
    }
}

#[test]
fn a_reconciler_decides_what_other_processes_send() {
    let w = world();
    let m: RealmMap<i64> = RealmMap::with_reconcile(
        &w.life,
        &w.handles,
        StoreSpec::persisted("t.rec"),
        Some(Arc::new(OnlyNewer)),
    );
    let access = w.handles.handle_for("t.rec").unwrap().access.clone();
    access.restore("", "k", json!(5));
    access.restore("", "k", json!(3));
    assert_eq!(m.get("k"), Some(5));
    access.restore("", "k", json!(-1));
    assert_eq!(m.get("k"), Some(5), "a rule that fails applies nothing");
    m.set("pinned", 1);
    access.remove("", "pinned");
    access.remove("", "k");
    assert_eq!(m.entries(), vec![("pinned".to_string(), 1)]);
}

#[test]
fn a_handle_declared_twice_is_not_persisted_and_a_shared_store_reports_under_empty(
) {
    let w = world();
    let first: RealmMap<i64> =
        RealmMap::new(&w.life, &w.handles, StoreSpec::persisted("t.dup"));
    let second: RealmMap<i64> =
        RealmMap::new(&w.life, &w.handles, StoreSpec::persisted("t.dup"));
    assert_eq!(first.handle().as_deref(), Some("t.dup"));
    assert_eq!(second.handle(), None);
    second.set("k", 1);
    assert!(w.notes.lock().unwrap().is_empty());
    let unpersisted: RealmMap<i64> =
        RealmMap::new(&w.life, &w.handles, StoreSpec::memory());
    unpersisted.set("k", 1);
    assert!(w.notes.lock().unwrap().is_empty());

    let shared: SharedMap<String> =
        SharedMap::new(&w.handles, StoreSpec::persisted("krb5.shared"));
    realm::run_sync(w.registry.get("acme").unwrap(), || {
        shared.set("k", "v".to_string())
    });
    assert_eq!(
        shared.get("k").as_deref(),
        Some("v"),
        "one row set, whatever realm wrote it"
    );
    assert_eq!(*w.notes.lock().unwrap(), vec!["krb5.shared||k"]);
    let handles: Vec<(String, &str)> = w
        .handles
        .handles()
        .iter()
        .map(|h| (h.handle.clone(), h.scope))
        .collect();
    assert_eq!(
        handles,
        vec![
            ("t.dup".to_string(), "realm"),
            ("krb5.shared".to_string(), "shared")
        ]
    );
}

#[test]
fn an_expiry_is_the_rows_own_or_none() {
    let ms = expiry_field(Some("expiresAt"), 1.0);
    assert_eq!(ms(&json!({ "expiresAt": 1500 }), "k"), Some(1500.0));
    assert_eq!(
        ms(&json!({ "expiresAt": "2026-10-05T12:00:00Z" }), "k"),
        Some(1791201600000.0)
    );
    assert_eq!(ms(&json!({ "expiresAt": 0 }), "k"), None);
    assert_eq!(ms(&json!({}), "k"), None);
    let seconds = expiry_field(None, 1000.0);
    assert_eq!(seconds(&json!(1700000000), "k"), Some(1700000000000.0));
    assert_eq!(seconds(&json!("1700000000"), "k"), Some(1700000000000.0));
    assert_eq!(seconds(&json!(-5), "k"), None);
}
