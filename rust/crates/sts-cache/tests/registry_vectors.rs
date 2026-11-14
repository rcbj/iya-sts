// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The cache registry against Node: `cache-registry-node.json`, which
//! `tests/tools/crypto-vectors.js` writes with `common/cache_registry.js`
//! over three stores — one per process with expired and live entries, one
//! per realm whose lookup is not counted, one replay store that tallies
//! rather than lists. The report `/admin/caches` draws, one store's detail,
//! the compact snapshot a heartbeat carries (Node's array rows), an
//! ejection and the report after it must all be Node's.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed; with it unset
//! this test says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use std::sync::{Arc, Mutex};

use serde_json::{json, Value as Json};
use sts_cache::{CacheRegistry, Descriptor, Kind, Row, Scope, Tally};

struct Store {
    d: Json,
    max: usize,
    lifetime: &'static str,
    rows: Mutex<Vec<(Option<String>, String, Option<i64>)>>,
    tally: Option<Tally>,
}

impl Descriptor for Store {
    fn name(&self) -> &str {
        self.d["name"].as_str().unwrap()
    }
    fn title(&self) -> &str {
        self.d["title"].as_str().unwrap()
    }
    fn description(&self) -> &str {
        self.d["description"].as_str().unwrap()
    }
    fn owner(&self) -> &str {
        self.d["owner"].as_str().unwrap()
    }
    fn scope(&self) -> Scope {
        if self.d["scope"] == "realm" {
            Scope::Realm
        } else {
            Scope::Process
        }
    }
    fn kind(&self) -> Kind {
        if self.d["kind"] == "replay" {
            Kind::Replay
        } else {
            Kind::Cache
        }
    }
    fn max_entries(&self) -> usize {
        self.max
    }
    fn bound(&self) -> String {
        self.d["bound"].as_str().unwrap_or("").to_string()
    }
    fn lifetime(&self) -> String {
        self.lifetime.to_string()
    }
    fn entries(&self, now: i64) -> Result<Vec<Row>, String> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .iter()
            .map(|(r, k, u)| Row::timed(r.clone(), k.clone(), *u, now))
            .collect())
    }
    fn ejects(&self) -> bool {
        self.name() == "v.process"
    }
    fn eject(&self, now: i64) -> Result<usize, String> {
        let mut rows = self.rows.lock().unwrap();
        let before = rows.len();
        rows.retain(|(_, _, u)| u.is_none_or(|u| u > now));
        Ok(before - rows.len())
    }
    fn settings(&self) -> Vec<String> {
        self.d["settings"]
            .as_array()
            .map(|a| {
                a.iter().map(|s| s.as_str().unwrap().to_string()).collect()
            })
            .unwrap_or_default()
    }
    fn hit_meaning(&self) -> String {
        self.d["hitMeaning"]
            .as_str()
            .unwrap_or("a lookup answered from the cache")
            .to_string()
    }
    fn persisted(&self) -> bool {
        self.d["persisted"] == true
    }
    fn counted(&self) -> Result<(), String> {
        if self.d["counted"] == false {
            Err(self.d["notCountedWhy"].as_str().unwrap().to_string())
        } else {
            Ok(())
        }
    }
    fn tally(&self, _now: i64) -> Option<Tally> {
        self.tally
    }
}

fn norm(v: Json) -> Json {
    match v {
        Json::Number(n) => match n.as_f64() {
            Some(f) if f.fract() == 0.0 && f.abs() < 9e15 => json!(f as i64),
            _ => Json::Number(n),
        },
        Json::Array(a) => Json::Array(a.into_iter().map(norm).collect()),
        Json::Object(o) => Json::Object(
            o.into_iter()
                .filter(|(k, _)| k != "pid")
                .map(|(k, x)| (k, norm(x)))
                .collect(),
        ),
        other => other,
    }
}

#[tokio::test]
async fn the_registry_is_nodes() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!("STS_CRYPTO_VECTORS is not set; nothing to compare");
        return;
    };
    let path = format!("{}/cache-registry-node.json", dir);
    let Ok(text) = std::fs::read_to_string(&path) else {
        eprintln!("{} is not there; nothing to compare", path);
        return;
    };
    let v: Json = serde_json::from_str(&text).unwrap();
    let now = v["now"].as_i64().unwrap();
    let d = v["descriptors"].as_array().unwrap();
    let reg = CacheRegistry::new();
    let proc_rows = v["procRows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (None, e[0].as_str().unwrap().to_string(), e[1].as_i64()))
        .collect();
    let realm_rows = v["realmRows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["realm"].as_str().map(str::to_string),
                r["key"].as_str().unwrap().to_string(),
                r["validUntil"].as_i64(),
            )
        })
        .collect();
    let c1 = reg.register(Arc::new(Store {
        d: d[0].clone(),
        max: 3,
        lifetime: "five minutes",
        rows: Mutex::new(proc_rows),
        tally: None,
    }));
    let c2 = reg.register(Arc::new(Store {
        d: d[1].clone(),
        max: 2,
        lifetime: "an hour",
        rows: Mutex::new(realm_rows),
        tally: None,
    }));
    let c3 = reg.register(Arc::new(Store {
        d: d[2].clone(),
        max: 100,
        lifetime: "a day",
        rows: Mutex::new(Vec::new()),
        tally: Some(Tally {
            size: 10,
            largest_realm: 6,
            valid: 7,
        }),
    }));
    c1.hit();
    c1.hit();
    c1.hit();
    c1.miss();
    c1.evicted(2);
    c2.hit();
    c2.refused();
    c3.miss();
    let got = json!({
        "report": reg.report(now),
        "detail": reg.detail("v.process", now),
        "snapshot": reg.snapshot(now),
        "ejected": reg.eject_expired_async(now).await,
        "after": reg.report(now),
        "snapshotAsync": reg.snapshot_async(now).await,
    });
    let mut failures = Vec::new();
    for k in [
        "report",
        "detail",
        "snapshot",
        "ejected",
        "after",
        "snapshotAsync",
    ] {
        if norm(got[k].clone()) != norm(v[k].clone()) {
            failures
                .push(format!("{}:\n  rust {}\n  node {}", k, got[k], v[k]));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
