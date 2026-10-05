// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The shadow: what this process knows the store holds, and the diff that
//! would take the store to what is live (`persistence.js`'s `diff()`,
//! `advanceShadow()`, `realmsDelta()` and `appconfigDelta()`).
//!
//! **The shadow records what was WRITTEN, never what is live now.** It is
//! advanced from the exact JSON a diff computed and a write sent, and only
//! after that write succeeded — so a failed flush recomputes the same diff
//! rather than losing it, and a change made while the write was out is
//! still a difference the next flush finds (2026-09-07: re-reading the live
//! entries here recorded a newer value as persisted that was never sent).
//!
//! Three shadows, one rule: the directory's (a JSON string per entry, per
//! realm), the realm registry's (each row as last written) and the runtime
//! overrides'. The realm and override deltas carry only what changed — a
//! key set or cleared, a name, the one-way retiring mark — so two nodes
//! changing different settings of one realm do not overwrite each other.

use indexmap::IndexMap;
use serde_json::{Map, Value as Json};

use crate::merge::entry_json;
use crate::model::StoredEntry;

/// The live directory, read one entry at a time: a journalled flush looks
/// up only the keys it was told about rather than snapshotting everything.
pub trait EntryLookup {
    /// The entry at a normalised DN in one realm, or `None`.
    fn entry_at(&self, realm: &str, key: &str) -> Option<StoredEntry>;
}

/// Realm id to normalised DN to entry, in the directory's own order.
pub type Snapshot = IndexMap<String, IndexMap<String, StoredEntry>>;

/// What a flush compares the shadow against.
pub enum Walk<'a> {
    /// Everything (no journal, a restore, the first flush). Only this walk
    /// can see a realm that is gone.
    Full(&'a Snapshot),
    /// The journalled keys only, looked for in every realm listed.
    Keys {
        realms: &'a [String],
        wanted: &'a [String],
        lookup: &'a dyn EntryLookup,
    },
}

/// One entry to write.
#[derive(Clone, Debug, PartialEq)]
pub struct Upsert {
    pub realm: String,
    pub key: String,
    pub entry: StoredEntry,
    /// Exactly what is sent, and what the shadow takes once it is written.
    pub json: String,
    /// What the change was based on: the shadow's copy, or `None` when this
    /// process believed the DN held nothing. The postgres driver merges
    /// against it ([`crate::merge::merge_entry`]).
    pub base: Option<String>,
}

/// One entry to delete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delete {
    pub realm: String,
    pub key: String,
}

/// The directory's half of a flush.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Diff {
    pub upserts: Vec<Upsert>,
    pub deletes: Vec<Delete>,
    /// The realms something happened in, in `Object.keys()` order.
    pub touched: Vec<String>,
    /// The realms that are gone, every row of them deleted.
    pub removed_realms: Vec<String>,
    /// Entries found unchanged, and changed: the shadow's cache counts.
    pub hits: u64,
    pub misses: u64,
}

impl Diff {
    pub fn is_empty(&self) -> bool {
        self.upserts.is_empty() && self.deletes.is_empty()
    }

    fn touch(&mut self, realm: &str) {
        if !self.touched.iter().any(|r| r == realm) {
            self.touched.push(realm.to_string());
        }
    }

    /// `Object.keys()` order: canonical array indices ascending first, then
    /// the rest as inserted. A realm id may be all digits.
    fn order_touched(&mut self) {
        let index = |s: &String| -> Option<u32> {
            let ok = !s.is_empty()
                && s.bytes().all(|c| c.is_ascii_digit())
                && (s == "0" || !s.starts_with('0'));
            ok.then(|| s.parse::<u32>().ok())
                .flatten()
                .filter(|n| *n < u32::MAX)
        };
        let (mut numeric, rest): (Vec<String>, Vec<String>) =
            self.touched.drain(..).partition(|s| index(s).is_some());
        numeric.sort_by_key(|s| index(s));
        numeric.extend(rest);
        self.touched = numeric;
    }
}

/// What one realm row changed against what the store is known to hold.
#[derive(Clone, Debug, PartialEq)]
pub struct RealmChange {
    pub row: Json,
    pub name: bool,
    pub description: bool,
    pub set: Map<String, Json>,
    pub cleared: Vec<String>,
    /// The retiring mark (#262) newly set. One-way: nothing unmarks.
    pub retiring: bool,
}

/// The realm registry's half of a flush.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RealmsDelta {
    pub upserts: Vec<RealmChange>,
    pub removed: Vec<String>,
    pub hits: u64,
    pub misses: u64,
}

/// The overrides' half of a flush.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AppconfigDelta {
    pub set: Map<String, Json>,
    pub cleared: Vec<String>,
}

impl AppconfigDelta {
    pub fn is_empty(&self) -> bool {
        self.set.is_empty() && self.cleared.is_empty()
    }
}

/// `JSON.stringify(a) === JSON.stringify(b)`, undefined as null: key order
/// counts, as it does there.
fn same_value(a: Option<&Json>, b: Option<&Json>) -> bool {
    let text = |v: Option<&Json>| v.unwrap_or(&Json::Null).to_string();
    text(a) == text(b)
}

/// `Number(v) > 0`.
fn positive(v: Option<&Json>) -> bool {
    match v {
        Some(Json::Number(n)) => n.as_f64().is_some_and(|x| x > 0.0),
        Some(Json::String(s)) => {
            let t = s.trim();
            t.is_empty()
                .then_some(0.0)
                .or_else(|| t.parse().ok())
                .is_some_and(|x: f64| x > 0.0)
        }
        Some(Json::Bool(b)) => *b,
        _ => false,
    }
}

fn overrides_of(row: &Json) -> Map<String, Json> {
    row.get("overrides")
        .and_then(Json::as_object)
        .cloned()
        .unwrap_or_default()
}

/// The keys `live` sets differently from `held`, and the keys `held` has
/// that `live` does not.
fn map_delta(
    live: &Map<String, Json>,
    held: &Map<String, Json>,
) -> (Map<String, Json>, Vec<String>) {
    let set = live
        .iter()
        .filter(|(k, v)| {
            !held.contains_key(*k) || !same_value(held.get(*k), Some(v))
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let cleared = held
        .keys()
        .filter(|k| !live.contains_key(*k))
        .cloned()
        .collect();
    (set, cleared)
}

/// The change one realm row makes against the parsed shadow `was` (`None`
/// for a realm the store does not hold), or `None` for nothing.
pub fn realm_change_of(row: &Json, was: Option<&Json>) -> Option<RealmChange> {
    let overrides = overrides_of(row);
    let Some(was) = was else {
        return Some(RealmChange {
            row: row.clone(),
            name: true,
            description: true,
            set: overrides,
            cleared: Vec::new(),
            retiring: false,
        });
    };
    let (set, cleared) = map_delta(&overrides, &overrides_of(was));
    let name = row.get("name") != was.get("name");
    let description = row.get("description") != was.get("description");
    let retiring = positive(row.get("retiringSince"))
        && !positive(was.get("retiringSince"));
    if !name
        && !description
        && !retiring
        && cleared.is_empty()
        && set.is_empty()
    {
        return None;
    }
    Some(RealmChange {
        row: row.clone(),
        name,
        description,
        set,
        cleared,
        retiring,
    })
}

/// What this process knows the store holds.
#[derive(Clone, Debug, Default)]
pub struct Shadow {
    directory: IndexMap<String, IndexMap<String, String>>,
    realms: IndexMap<String, Json>,
    appconfig: Option<Map<String, Json>>,
}

impl Shadow {
    pub fn new() -> Shadow {
        Shadow::default()
    }

    /// The JSON the shadow holds for one entry.
    pub fn entry(&self, realm: &str, key: &str) -> Option<&str> {
        self.directory.get(realm)?.get(key).map(String::as_str)
    }

    /// Records an entry as the store holds it — what a load or an applied
    /// replication row is known to have put there.
    pub fn set_entry(&mut self, realm: &str, key: &str, json: String) {
        self.directory
            .entry(realm.to_string())
            .or_default()
            .insert(key.to_string(), json);
    }

    /// Forgets one entry (the store is known not to hold it).
    pub fn forget_entry(&mut self, realm: &str, key: &str) {
        if let Some(held) = self.directory.get_mut(realm) {
            held.shift_remove(key);
        }
    }

    /// The number of entries held, over every realm.
    pub fn entry_count(&self) -> usize {
        self.directory.values().map(IndexMap::len).sum()
    }

    /// Every entry held, for the cache report: realm, key, JSON.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &str, &str)> {
        self.directory.iter().flat_map(|(realm, rows)| {
            rows.iter()
                .map(move |(k, j)| (realm.as_str(), k.as_str(), j.as_str()))
        })
    }

    /// The upserts and deletes that would take the store to what is live.
    /// `removals` are the realms THIS process removed: a realm in the shadow
    /// and not live may be one another node created whose entries arrived
    /// before its registry row did, and deleting it would delete it
    /// everywhere (#46).
    pub fn diff(&self, walk: &Walk<'_>, removals: &[String]) -> Diff {
        let mut out = Diff::default();
        let empty = IndexMap::new();
        let consider = |out: &mut Diff, realm: &str, key: &str, entry| {
            let was = self.directory.get(realm).unwrap_or(&empty);
            let json = entry_json(&entry).to_string();
            if was.get(key) == Some(&json) {
                out.hits += 1;
                return;
            }
            out.misses += 1;
            out.upserts.push(Upsert {
                realm: realm.to_string(),
                key: key.to_string(),
                entry,
                json,
                base: was.get(key).cloned(),
            });
            out.touch(realm);
        };
        match walk {
            Walk::Keys {
                realms,
                wanted,
                lookup,
            } => {
                for realm in realms.iter() {
                    let was = self.directory.get(realm).unwrap_or(&empty);
                    for key in wanted.iter() {
                        match lookup.entry_at(realm, key) {
                            Some(entry) => {
                                consider(&mut out, realm, key, entry)
                            }
                            // Gone, and a delete only if this process had
                            // written it: a key journalled in one realm is
                            // looked for in every realm.
                            None if was.contains_key(key) => {
                                out.deletes.push(Delete {
                                    realm: realm.clone(),
                                    key: key.clone(),
                                });
                                out.touch(realm);
                            }
                            None => {}
                        }
                    }
                }
            }
            Walk::Full(live) => {
                for (realm, rows) in live.iter() {
                    for (key, entry) in rows {
                        consider(&mut out, realm, key, entry.clone());
                    }
                    if let Some(was) = self.directory.get(realm) {
                        for key in was.keys().filter(|k| !rows.contains_key(*k))
                        {
                            out.deletes.push(Delete {
                                realm: realm.clone(),
                                key: key.clone(),
                            });
                            out.touch(realm);
                        }
                    }
                }
                for (realm, was) in &self.directory {
                    if live.contains_key(realm) || !removals.contains(realm) {
                        continue;
                    }
                    out.deletes.extend(was.keys().map(|key| Delete {
                        realm: realm.clone(),
                        key: key.clone(),
                    }));
                    out.removed_realms.push(realm.clone());
                }
            }
        }
        out.order_touched();
        out
    }

    /// The shadow advanced to what a successful write sent, and nothing
    /// else.
    pub fn advance(&mut self, diff: &Diff) {
        for realm in &diff.removed_realms {
            self.directory.shift_remove(realm);
        }
        for row in &diff.upserts {
            self.set_entry(&row.realm, &row.key, row.json.clone());
        }
        for row in &diff.deletes {
            self.forget_entry(&row.realm, &row.key);
        }
    }

    /// The realm registry against its shadow. `rows` are the written form of
    /// every realm but the default: `id, name, description, domain,
    /// createdAt, overrides, retiringSince`.
    pub fn realms_delta(
        &self,
        rows: &[Json],
        removals: &[String],
    ) -> RealmsDelta {
        let mut out = RealmsDelta::default();
        let mut live = Vec::new();
        for row in rows {
            let id = row.get("id").and_then(Json::as_str).unwrap_or("");
            live.push(id);
            match realm_change_of(row, self.realms.get(id)) {
                Some(change) => {
                    out.misses += 1;
                    out.upserts.push(change);
                }
                None => out.hits += 1,
            }
        }
        out.removed = removals
            .iter()
            .filter(|id| !live.contains(&id.as_str()))
            .cloned()
            .collect();
        out
    }

    /// The realm shadow advanced to what a successful write sent.
    pub fn advance_realms(&mut self, delta: &RealmsDelta) {
        for id in &delta.removed {
            self.realms.shift_remove(id);
        }
        for change in &delta.upserts {
            let id = change.row.get("id").and_then(Json::as_str).unwrap_or("");
            let field = |k: &str| change.row.get(k).cloned();
            let mut was = self.realms.get(id).cloned().unwrap_or_else(|| {
                let mut m = Map::new();
                for k in ["name", "description"] {
                    if let Some(v) = field(k) {
                        m.insert(k.to_string(), v);
                    }
                }
                m.insert("overrides".to_string(), Json::Object(Map::new()));
                Json::Object(m)
            });
            let Some(obj) = was.as_object_mut() else {
                continue;
            };
            let flags = [
                ("name", change.name),
                ("description", change.description),
                ("retiringSince", change.retiring),
            ];
            for (k, changed) in flags {
                if changed {
                    match field(k) {
                        Some(v) => obj.insert(k.to_string(), v),
                        None => obj.shift_remove(k),
                    };
                }
            }
            let mut overrides = obj
                .get("overrides")
                .and_then(Json::as_object)
                .cloned()
                .unwrap_or_default();
            for k in &change.cleared {
                overrides.shift_remove(k);
            }
            for (k, v) in &change.set {
                overrides.insert(k.clone(), v.clone());
            }
            obj.insert("overrides".to_string(), Json::Object(overrides));
            self.realms.insert(id.to_string(), was);
        }
    }

    /// The parsed shadow of one realm row.
    pub fn realm(&self, id: &str) -> Option<&Json> {
        self.realms.get(id)
    }

    /// The realms whose rows the shadow holds.
    pub fn realm_ids(&self) -> Vec<String> {
        self.realms.keys().cloned().collect()
    }

    /// Forgets a realm: its row and its directory.
    pub fn forget_realm(&mut self, id: &str) {
        self.realms.shift_remove(id);
        self.directory.shift_remove(id);
    }

    /// Records a realm row as the store holds it.
    pub fn set_realm(&mut self, id: &str, row: Json) {
        self.realms.insert(id.to_string(), row);
    }

    /// The persistable overrides against their shadow.
    pub fn appconfig_delta(&self, live: &Map<String, Json>) -> AppconfigDelta {
        let empty = Map::new();
        let (set, cleared) =
            map_delta(live, self.appconfig.as_ref().unwrap_or(&empty));
        AppconfigDelta { set, cleared }
    }

    /// The overrides' shadow advanced to what a successful write sent.
    pub fn advance_appconfig(&mut self, delta: &AppconfigDelta) {
        let next = self.appconfig.get_or_insert_with(Map::new);
        for k in &delta.cleared {
            next.shift_remove(k);
        }
        for (k, v) in &delta.set {
            next.insert(k.clone(), v.clone());
        }
    }

    /// Records the overrides as the store holds them.
    pub fn set_appconfig(&mut self, overrides: Map<String, Json>) {
        self.appconfig = Some(overrides);
    }
}
