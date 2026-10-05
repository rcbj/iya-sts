// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The shadow's rules, each as `persistence.js` states it: the diff against
//! what was written, the journalled walk, a realm removed here against one
//! merely not here yet, the shadow advanced only from what was sent, and
//! the realm and override deltas carrying only what changed.

#![allow(clippy::unwrap_used)] // a test file

use std::collections::HashMap;

use indexmap::IndexMap;
use serde_json::{json, Value as Json};
use sts_store::shadow::{EntryLookup, Shadow, Snapshot, Walk};
use sts_store::StoredEntry;

fn entry(dn: &str, cn: &str) -> StoredEntry {
    let mut attributes = IndexMap::new();
    attributes.insert("cn".to_string(), vec![cn.to_string()]);
    StoredEntry {
        dn: dn.to_string(),
        attributes,
        ..StoredEntry::default()
    }
}

fn snapshot(rows: &[(&str, &str, &str)]) -> Snapshot {
    let mut out = Snapshot::new();
    for (realm, key, cn) in rows {
        out.entry(realm.to_string())
            .or_default()
            .insert(key.to_string(), entry(key, cn));
    }
    out
}

struct Lookup(HashMap<(String, String), StoredEntry>);

impl EntryLookup for Lookup {
    fn entry_at(&self, realm: &str, key: &str) -> Option<StoredEntry> {
        self.0.get(&(realm.to_string(), key.to_string())).cloned()
    }
}

#[test]
fn a_full_walk_writes_what_changed_and_deletes_what_is_gone() {
    let mut shadow = Shadow::new();
    let live = snapshot(&[("default", "cn=a", "a"), ("default", "cn=b", "b")]);
    let first = shadow.diff(&Walk::Full(&live), &[]);
    assert_eq!(first.upserts.len(), 2);
    assert!(first.upserts.iter().all(|u| u.base.is_none()));
    assert_eq!(first.touched, vec!["default"]);
    shadow.advance(&first);

    // Nothing changed: nothing written, both found in the shadow.
    let again = shadow.diff(&Walk::Full(&live), &[]);
    assert!(again.is_empty());
    assert_eq!((again.hits, again.misses), (2, 0));

    // One changed, one gone: the base is what was written.
    let live = snapshot(&[("default", "cn=a", "a2")]);
    let next = shadow.diff(&Walk::Full(&live), &[]);
    assert_eq!(next.upserts.len(), 1);
    assert_eq!(
        next.upserts[0].base.as_deref(),
        shadow.entry("default", "cn=a")
    );
    assert_eq!(next.deletes.len(), 1);
    assert_eq!(next.deletes[0].key, "cn=b");
    shadow.advance(&next);
    assert_eq!(shadow.entry_count(), 1);
}

#[test]
fn the_shadow_takes_what_was_sent_not_what_is_live() {
    let mut shadow = Shadow::new();
    let live = snapshot(&[("default", "cn=a", "a")]);
    let sent = shadow.diff(&Walk::Full(&live), &[]);
    // The live entry moves while the write is out; the shadow is advanced
    // from the diff, so the newer value is still a difference.
    let moved = snapshot(&[("default", "cn=a", "a-newer")]);
    shadow.advance(&sent);
    let next = shadow.diff(&Walk::Full(&moved), &[]);
    assert_eq!(next.upserts.len(), 1);
    assert_eq!(
        next.upserts[0].base.as_deref(),
        Some(sent.upserts[0].json.as_str())
    );
}

#[test]
fn a_failed_write_is_recomputed_whole() {
    let shadow = Shadow::new();
    let live = snapshot(&[("default", "cn=a", "a")]);
    let one = shadow.diff(&Walk::Full(&live), &[]);
    // Not advanced: the write failed. The same work comes back.
    let two = shadow.diff(&Walk::Full(&live), &[]);
    assert_eq!(one, two);
}

#[test]
fn a_journalled_walk_looks_only_at_the_keys_named() {
    let mut shadow = Shadow::new();
    let live = snapshot(&[
        ("default", "cn=a", "a"),
        ("default", "cn=b", "b"),
        ("acme", "cn=c", "c"),
    ]);
    shadow.advance(&shadow.diff(&Walk::Full(&live), &[]));

    let mut held = HashMap::new();
    held.insert(
        ("default".to_string(), "cn=a".to_string()),
        entry("cn=a", "a2"),
    );
    // cn=b is gone and cn=c is not named.
    let lookup = Lookup(held);
    let realms = vec!["default".to_string(), "acme".to_string()];
    let wanted = vec!["cn=a".to_string(), "cn=b".to_string()];
    let d = shadow.diff(
        &Walk::Keys {
            realms: &realms,
            wanted: &wanted,
            lookup: &lookup,
        },
        &[],
    );
    assert_eq!(d.upserts.len(), 1);
    assert_eq!(d.upserts[0].key, "cn=a");
    // Gone from default, which had written it — and not a delete in acme,
    // which never had it.
    assert_eq!(d.deletes.len(), 1);
    assert_eq!(
        (d.deletes[0].realm.as_str(), d.deletes[0].key.as_str()),
        ("default", "cn=b")
    );
    assert_eq!(d.touched, vec!["default"]);
}

#[test]
fn only_a_realm_removed_here_is_deleted() {
    let mut shadow = Shadow::new();
    let live = snapshot(&[
        ("default", "cn=a", "a"),
        ("acme", "cn=c", "c"),
        ("beta", "cn=d", "d"),
    ]);
    shadow.advance(&shadow.diff(&Walk::Full(&live), &[]));
    let live = snapshot(&[("default", "cn=a", "a")]);
    // acme was removed here; beta is merely not in this process's registry
    // (another node's realm whose entries replicated first).
    let d = shadow.diff(&Walk::Full(&live), &["acme".to_string()]);
    assert_eq!(d.removed_realms, vec!["acme"]);
    assert_eq!(d.deletes.len(), 1);
    assert_eq!(d.deletes[0].realm, "acme");
    shadow.advance(&d);
    assert!(shadow.entry("acme", "cn=c").is_none());
    assert!(shadow.entry("beta", "cn=d").is_some());
}

#[test]
fn touched_realms_come_in_object_keys_order() {
    let shadow = Shadow::new();
    let live = snapshot(&[
        ("zeta", "k", "1"),
        ("10", "k", "1"),
        ("2", "k", "1"),
        ("alpha", "k", "1"),
        ("01", "k", "1"),
    ]);
    let d = shadow.diff(&Walk::Full(&live), &[]);
    assert_eq!(d.touched, vec!["2", "10", "zeta", "alpha", "01"]);
}

fn row(id: &str, name: &str, overrides: Json, retiring: Json) -> Json {
    json!({ "id": id, "name": name, "description": "d", "domain": "x.example",
            "createdAt": 1, "overrides": overrides, "retiringSince": retiring })
}

#[test]
fn a_realm_delta_carries_only_what_changed() {
    let mut shadow = Shadow::new();
    let rows = [row("acme", "Acme", json!({ "a": 1, "b": "x" }), Json::Null)];
    let first = shadow.realms_delta(&rows, &[]);
    assert_eq!(first.upserts.len(), 1);
    assert!(first.upserts[0].name && first.upserts[0].description);
    shadow.advance_realms(&first);
    assert!(shadow.realms_delta(&rows, &[]).upserts.is_empty());

    let rows = [row(
        "acme",
        "Acme",
        json!({ "a": 2, "c": true }),
        json!(1700),
    )];
    let d = shadow.realms_delta(&rows, &[]);
    let change = &d.upserts[0];
    assert!(!change.name && !change.description && change.retiring);
    assert_eq!(
        Json::Object(change.set.clone()),
        json!({ "a": 2, "c": true })
    );
    assert_eq!(change.cleared, vec!["b"]);
    shadow.advance_realms(&d);
    assert_eq!(
        shadow.realm("acme").unwrap()["overrides"],
        json!({ "a": 2, "c": true })
    );
    // The mark is one-way: clearing it on the row is not a change.
    let rows = [row(
        "acme",
        "Acme",
        json!({ "a": 2, "c": true }),
        Json::Null,
    )];
    assert!(shadow.realms_delta(&rows, &[]).upserts.is_empty());

    // A removal is reported only for a realm no longer live.
    let d = shadow.realms_delta(&[], &["acme".to_string(), "gone".to_string()]);
    assert_eq!(d.removed, vec!["acme", "gone"]);
    let d = shadow.realms_delta(&rows, &["acme".to_string()]);
    assert!(d.removed.is_empty());
}

#[test]
fn an_override_delta_carries_only_what_changed() {
    let mut shadow = Shadow::new();
    let live = json!({ "x": 1, "y": { "a": 1, "b": 2 } });
    let first = shadow.appconfig_delta(live.as_object().unwrap());
    assert_eq!(first.set.len(), 2);
    shadow.advance_appconfig(&first);
    assert!(shadow.appconfig_delta(live.as_object().unwrap()).is_empty());
    // Key order is a difference, as JSON.stringify makes it one.
    let reordered = json!({ "x": 1, "y": { "b": 2, "a": 1 } });
    assert_eq!(
        shadow
            .appconfig_delta(reordered.as_object().unwrap())
            .set
            .len(),
        1
    );
    let fewer = json!({ "y": { "a": 1, "b": 2 } });
    let d = shadow.appconfig_delta(fewer.as_object().unwrap());
    assert!(d.set.is_empty());
    assert_eq!(d.cleared, vec!["x"]);
}
