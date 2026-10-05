// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The fan-in for `merge: own` stores (`persistence_replication.js`) — the
//! counters and the audit ring.
//!
//! Each process writes ONLY ITS OWN row for these, so what another process
//! contributed is in the store and not in memory: this holds what the
//! restore and the applier read, and the reporting code asks for it. **The
//! caller merges** — a sum for a counter, a concatenation for a ring —
//! because only it knows what its rows mean; a generic merge here would be
//! a second place the shape of every counter is written down.
//!
//! Four levels — handle, realm, key, origin — because all four name one
//! contribution: a map-shaped counter's keys are HTTP paths. An object or
//! array store uses the empty key.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard, PoisonError};

use serde_json::Value as Json;
use sts_core::realm;

type ByOrigin = BTreeMap<String, Json>;
type ByKey = BTreeMap<String, ByOrigin>;
type ByRealm = BTreeMap<String, ByKey>;

/// What every other process contributed.
#[derive(Default)]
pub struct FanIn {
    contributions: Mutex<BTreeMap<String, ByRealm>>,
}

fn realm_or_ambient(realm_id: Option<&str>) -> String {
    match realm_id {
        Some(id) => id.to_string(),
        None => realm::current_id(),
    }
}

impl FanIn {
    fn map(&self) -> MutexGuard<'_, BTreeMap<String, ByRealm>> {
        self.contributions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// `contribute()`: what `origin` holds under a handle, realm and key;
    /// `None` removes it.
    pub fn contribute(
        &self,
        handle: &str,
        realm_id: &str,
        key: &str,
        origin: &str,
        value: Option<Json>,
    ) {
        let mut map = self.map();
        let by_origin = map
            .entry(handle.to_string())
            .or_default()
            .entry(realm_id.to_string())
            .or_default()
            .entry(key.to_string())
            .or_default();
        match value {
            Some(v) => {
                by_origin.insert(origin.to_string(), v);
            }
            None => {
                by_origin.remove(origin);
            }
        }
    }

    /// `remoteRows()`: one value per other process; `None` is the ambient
    /// realm.
    pub fn remote_rows(
        &self,
        handle: &str,
        realm_id: Option<&str>,
        key: &str,
    ) -> Vec<Json> {
        self.map()
            .get(handle)
            .and_then(|r| r.get(&realm_or_ambient(realm_id)))
            .and_then(|k| k.get(key))
            .map(|o| o.values().cloned().collect())
            .unwrap_or_default()
    }

    /// `remoteSegmentedRows()`: a segmented array store's elements as each
    /// other process holds them, its segments in position order (a bare
    /// array, an older build's whole-array row, ahead of any segment). The
    /// caller trims: a process may carry one segment more than it holds.
    pub fn remote_segmented_rows(
        &self,
        handle: &str,
        realm_id: Option<&str>,
    ) -> Vec<Vec<Json>> {
        let map = self.map();
        let Some(by_key) = map
            .get(handle)
            .and_then(|r| r.get(&realm_or_ambient(realm_id)))
        else {
            return Vec::new();
        };
        let mut parts: BTreeMap<&str, Vec<(f64, &Vec<Json>)>> = BTreeMap::new();
        for by_origin in by_key.values() {
            for (from, value) in by_origin {
                let segments = parts.entry(from.as_str()).or_default();
                if let Json::Array(rows) = value {
                    segments.push((f64::NEG_INFINITY, rows));
                } else if let Some(Json::Array(rows)) = value.get("rows") {
                    let start = value
                        .get("start")
                        .and_then(Json::as_f64)
                        .unwrap_or(0.0);
                    segments.push((start, rows));
                }
            }
        }
        parts
            .into_values()
            .map(|mut segments| {
                segments.sort_by(|a, b| {
                    a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal)
                });
                segments
                    .into_iter()
                    .flat_map(|(_, rows)| rows.iter().cloned())
                    .collect()
            })
            .collect()
    }

    /// `remoteKeys()`: every key another process contributed under a
    /// handle in a realm — another process may count a path this one never
    /// served.
    pub fn remote_keys(
        &self,
        handle: &str,
        realm_id: Option<&str>,
    ) -> Vec<String> {
        self.map()
            .get(handle)
            .and_then(|r| r.get(&realm_or_ambient(realm_id)))
            .map(|k| k.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// `origins()`: every other process that contributed a row, so a
    /// single-process deployment can be told it is one.
    pub fn origins(&self) -> Vec<String> {
        let mut all = BTreeSet::new();
        for by_realm in self.map().values() {
            for by_key in by_realm.values() {
                for by_origin in by_key.values() {
                    all.extend(by_origin.keys().cloned());
                }
            }
        }
        all.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn the_fan_in() {
        let f = FanIn::default();
        f.contribute("stats.calls", "default", "GET /x", "p1", Some(json!(3)));
        f.contribute("stats.calls", "default", "GET /x", "p2", Some(json!(4)));
        f.contribute("stats.calls", "default", "GET /y", "p2", Some(json!(1)));
        assert_eq!(
            f.remote_rows("stats.calls", Some("default"), "GET /x"),
            vec![json!(3), json!(4)]
        );
        assert_eq!(
            f.remote_keys("stats.calls", None),
            vec!["GET /x", "GET /y"]
        );
        f.contribute("stats.calls", "default", "GET /x", "p1", None);
        assert_eq!(
            f.remote_rows("stats.calls", Some("default"), "GET /x"),
            vec![json!(4)]
        );
        assert_eq!(f.origins(), vec!["p2"]);
        f.contribute(
            "audit",
            "default",
            "0",
            "p3",
            Some(json!({ "start": 2, "rows": ["c"] })),
        );
        f.contribute(
            "audit",
            "default",
            "1",
            "p3",
            Some(json!({ "start": 0, "rows": ["a", "b"] })),
        );
        f.contribute("audit", "default", "", "p4", Some(json!(["old"])));
        assert_eq!(
            f.remote_segmented_rows("audit", Some("default")),
            vec![vec![json!("a"), json!("b"), json!("c")], vec![json!("old")]]
        );
    }
}
