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

#[test]
fn a_segmented_array_journals_only_the_segments_it_touches() {
    let w = world();
    let log: sts_core::realm_store::RealmVec<i64> =
        sts_core::realm_store::RealmVec::new(
            &w.life,
            &w.handles,
            StoreSpec::persisted("audit.events"),
            3,
        );
    for i in 0..7 {
        log.push(i);
    }
    let notes = |w: &World| -> Vec<String> {
        w.notes.lock().unwrap().drain(..).collect()
    };
    assert_eq!(
        notes(&w),
        ["0", "0", "0", "1", "1", "1", "2"]
            .iter()
            .map(|k| format!("audit.events|default|{}", k))
            .collect::<Vec<_>>()
    );
    // Shifting journals a segment only when the base leaves it.
    assert_eq!(log.shift(), Some(0));
    assert_eq!(log.shift(), Some(1));
    assert!(notes(&w).is_empty());
    assert_eq!(log.shift(), Some(2));
    assert_eq!(notes(&w), vec!["audit.events|default|0"]);
    assert_eq!(log.pop(), Some(6));
    assert_eq!(notes(&w), vec!["audit.events|default|2"]);
    let access = w.handles.handle_for("audit.events").unwrap().access.clone();
    let dumped = access.dump("");
    assert_eq!(
        dumped,
        vec![("1".to_string(), json!({ "start": 3, "rows": [3, 4, 5] }))],
        "segment 2 is empty again after the pop"
    );
    assert!(access.read("", "0").is_none());

    // Read back into a store of its own: the same rows, at the same base.
    let other = world();
    let again: sts_core::realm_store::RealmVec<i64> =
        sts_core::realm_store::RealmVec::new(
            &other.life,
            &other.handles,
            StoreSpec::persisted("audit.events"),
            3,
        );
    let back = other
        .handles
        .handle_for("audit.events")
        .unwrap()
        .access
        .clone();
    back.restore("", "2", json!({ "start": 6, "rows": [6, 7] }));
    back.restore("", "1", json!({ "start": 4, "rows": [4, 5] }));
    assert_eq!(again.to_vec(), vec![4, 5, 6, 7]);
    again.push(8);
    assert_eq!(
        notes(&other),
        vec!["audit.events|default|2"],
        "index 8 is in segment 2"
    );
    back.remove("", "1");
    assert_eq!(again.to_vec(), vec![6, 7]);
    assert!(
        other.notes.lock().unwrap().is_empty(),
        "a restore and a remove report nothing"
    );

    // Unsegmented: one row, every change reported without a key.
    let plain: sts_core::realm_store::RealmVec<i64> =
        sts_core::realm_store::RealmVec::new(
            &w.life,
            &w.handles,
            StoreSpec::persisted("t.list"),
            0,
        );
    plain.push(1);
    plain.retain(|v| *v > 5);
    assert_eq!(notes(&w), vec!["t.list|default|*", "t.list|default|*"]);
    assert_eq!(
        w.handles.handle_for("t.list").unwrap().access.dump(""),
        vec![(String::new(), json!([]))]
    );
}

#[derive(
    Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize,
)]
struct Counts {
    #[serde(default)]
    calls: i64,
    #[serde(default)]
    refused: i64,
}

#[test]
fn an_object_is_one_row_per_realm() {
    let w = world();
    let counts: sts_core::realm_store::RealmObj<Counts> =
        sts_core::realm_store::RealmObj::new(
            &w.life,
            &w.handles,
            StoreSpec::persisted("stats.counts"),
            Arc::new(|_| Counts::default()),
        );
    counts.update(|c| c.calls += 2);
    realm::run_sync(w.registry.get("acme").unwrap(), || {
        counts.update(|c| c.refused += 1)
    });
    assert_eq!(
        counts.get(),
        Counts {
            calls: 2,
            refused: 0
        }
    );
    assert_eq!(
        counts.get_in("acme"),
        Counts {
            calls: 0,
            refused: 1
        }
    );
    assert_eq!(
        *w.notes.lock().unwrap(),
        vec!["stats.counts|default|*", "stats.counts|acme|*"]
    );
    let access = w.handles.handle_for("stats.counts").unwrap().access.clone();
    // A stored row's fields over what is held.
    access.restore("", "", json!({ "refused": 9 }));
    assert_eq!(
        counts.get(),
        Counts {
            calls: 2,
            refused: 9
        }
    );
    access.remove("", "");
    assert_eq!(counts.get(), Counts::default());
    w.life.remove("acme").unwrap();
    assert_eq!(
        counts.get_in("acme"),
        Counts::default(),
        "the removal purged it"
    );
}
