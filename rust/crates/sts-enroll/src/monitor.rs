// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE ENROLLMENT MONITOR (`common/enrollment_monitor.ts`): what ACME, EST
//! and SCEP have done, per realm, behind the three monitoring pages and
//! `GET /admin-api/{acme,est,scep}/monitor`.
//!
//! One row per family per realm, under the key `counters`, in a store
//! declared as Node declares it — `enrollment_monitor.<family>`, persisted,
//! merged `own` — so a row a 1.x install wrote is read here, and Node reads
//! this one. Each process writes only its own row; a read adds every other
//! process's (`replication.remoteRows()`), which [`RemoteRows`] answers —
//! the runtime's fan-in where one is wired, nothing otherwise (one process).
//!
//! `record()` never fails the request it counts: Node catches and logs
//! under STS-ENROLL-0090, and here nothing in it can fail but the family
//! name, which is logged under that code too.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Map, Value as Json};
use sts_core::errors::codes;
use sts_core::realm;
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{Merge, RealmMap, StoreHandles, StoreSpec};

use crate::core::FAMILIES;
use crate::ports::Monitor;

/// `RECENT`: the recent rows each family keeps per realm.
pub const RECENT: usize = 50;

/// `MAX_KEYS`: the distinct keys a table keeps before it folds the rest
/// into "(other)".
pub const MAX_KEYS: usize = 200;

/// `replication.remoteRows(handle, undefined, key)`: the row every other
/// process holds under the key in the ambient realm.
pub trait RemoteRows: Send + Sync {
    fn remote_rows(&self, handle: &str, key: &str) -> Vec<Json>;
}

/// One process: nobody else's rows.
pub struct Alone;

impl RemoteRows for Alone {
    fn remote_rows(&self, _handle: &str, _key: &str) -> Vec<Json> {
        Vec::new()
    }
}

/// The counters' six numbers, in Node's order.
const NUMBERS: [&str; 6] = [
    "requests",
    "issued",
    "refused",
    "revoked",
    "credentialsCreated",
    "credentialsRedeemed",
];

/// The counters' six tables, in Node's order.
const TABLES: [&str; 6] = [
    "operations",
    "profiles",
    "principals",
    "codes",
    "statuses",
    "failInfos",
];

/// The three families' stores.
#[derive(Clone)]
pub struct EnrollmentMonitor {
    stores: BTreeMap<&'static str, RealmMap<Json>>,
    remote: Arc<dyn RemoteRows>,
    started_at: String,
}

/// `String(value).slice(0, n)`, by UTF-16 unit as JavaScript counts.
fn slice(text: &str, n: usize) -> String {
    let units: Vec<u16> = text.encode_utf16().take(n).collect();
    String::from_utf16_lossy(&units)
}

/// `String(v)` of a detail member, `''` for none.
fn text_of(detail: &Json, key: &str) -> String {
    match detail.get(key) {
        None | Some(Json::Null) => String::new(),
        Some(Json::String(s)) => s.clone(),
        Some(Json::Bool(b)) => b.to_string(),
        Some(other) => other.to_string(),
    }
}

/// A detail member is truthy (`said.profile ? … : null`).
fn truthy(detail: &Json, key: &str) -> bool {
    match detail.get(key) {
        None | Some(Json::Null) => false,
        Some(Json::String(s)) => !s.is_empty(),
        Some(Json::Bool(b)) => *b,
        Some(Json::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(_) => true,
    }
}

/// `emptyRow()`.
fn empty_row() -> Json {
    json!({ "requests": 0, "issued": 0, "refused": 0, "revoked": 0,
            "credentialsCreated": 0, "credentialsRedeemed": 0,
            "operations": {}, "profiles": {}, "principals": {}, "codes": {},
            "statuses": {}, "failInfos": {}, "recent": [], "lastAt": null })
}

/// `bump(table, key)`: one more of a name, folded past MAX_KEYS.
fn bump(table: &mut Map<String, Json>, key: &str) {
    let name = slice(if key.is_empty() { "(none)" } else { key }, 120);
    let count = |v: Option<&Json>| v.and_then(Json::as_f64).unwrap_or(0.0);
    if !table.contains_key(&name) && table.len() >= MAX_KEYS {
        let n = count(table.get("(other)")) + 1.0;
        table.insert("(other)".into(), number(n));
        return;
    }
    let n = count(table.get(&name)) + 1.0;
    table.insert(name, number(n));
}

/// A count as JSON writes it: an integer where it is one.
fn number(n: f64) -> Json {
    if n.fract() == 0.0 && n.abs() < 9.0e15 {
        Json::from(n as i64)
    } else {
        Json::from(n)
    }
}

/// `Number(x || 0)` of a row's member.
fn num(row: &Json, key: &str) -> f64 {
    match row.get(key) {
        Some(Json::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(Json::String(s)) => s.trim().parse().unwrap_or(0.0),
        _ => 0.0,
    }
}

/// `new Date().toISOString()`.
fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

impl EnrollmentMonitor {
    /// Declares the three stores (before the store opens).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn declare(
        lifecycle: &Arc<RealmLifecycle>,
        handles: &Arc<StoreHandles>,
    ) -> EnrollmentMonitor {
        let mut stores = BTreeMap::new();
        for family in FAMILIES {
            let mut spec = StoreSpec::persisted(&Self::handle_of(family));
            spec.merge = Merge::Own;
            stores.insert(*family, RealmMap::new(lifecycle, handles, spec));
        }
        EnrollmentMonitor {
            stores,
            remote: Arc::new(Alone),
            started_at: now_iso(),
        }
    }

    /// The same monitor reading other processes' rows through `remote`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn with_remote(mut self, remote: Arc<dyn RemoteRows>) -> Self {
        self.remote = remote;
        self
    }

    fn handle_of(family: &str) -> String {
        format!("enrollment_monitor.{}", family)
    }

    /// `snapshot(family)`: this process's counters and every other
    /// process's, added together, in the ambient realm; `None` for a name
    /// that is not a family.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn snapshot(&self, family: &str) -> Option<Json> {
        let store = self.stores.get(family)?;
        let mut out = store.get("counters").unwrap_or_else(empty_row);
        if out.get("failInfos").is_none_or(Json::is_null) {
            out["failInfos"] = json!({});
        }
        let theirs = self
            .remote
            .remote_rows(&Self::handle_of(family), "counters");
        for row in theirs.iter().filter(|r| !r.is_null()) {
            for field in NUMBERS {
                let n = num(&out, field) + num(row, field);
                out[field] = number(n);
            }
            for table in TABLES {
                let mut into = out
                    .get(table)
                    .and_then(Json::as_object)
                    .cloned()
                    .unwrap_or_default();
                if let Some(from) = row.get(table).and_then(Json::as_object) {
                    for (name, v) in from {
                        let n = num(&Json::Object(into.clone()), name)
                            + num(&json!({ "v": v }), "v");
                        into.insert(name.clone(), number(n));
                    }
                }
                out[table] = Json::Object(into);
            }
            let mut recent =
                out["recent"].as_array().cloned().unwrap_or_default();
            recent
                .extend(row["recent"].as_array().cloned().unwrap_or_default());
            out["recent"] = Json::Array(recent);
            let theirs_at = text_of(row, "lastAt");
            let mine_at = text_of(&out, "lastAt");
            if !theirs_at.is_empty()
                && (mine_at.is_empty() || theirs_at > mine_at)
            {
                out["lastAt"] = Json::from(theirs_at);
            }
        }
        let mut recent = out["recent"].as_array().cloned().unwrap_or_default();
        // A stable sort, newest first, as Array.prototype.sort is.
        recent.sort_by_key(|r| std::cmp::Reverse(text_of(r, "at")));
        recent.truncate(RECENT);
        out["recent"] = Json::Array(recent);
        out["startedAt"] = Json::from(self.started_at.as_str());
        out["realm"] = Json::from(realm::current_id());
        out["family"] = Json::from(family);
        out["processes"] = Json::from(1 + theirs.len());
        Some(out)
    }

    /// `resetForTests(family)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn reset_for_tests(&self, family: &str) {
        if let Some(store) = self.stores.get(family) {
            store.delete("counters");
        }
    }
}

impl Monitor for EnrollmentMonitor {
    /// `record(family, detail)`: one request counted in the ambient realm.
    // A hot path: once per enrollment request; no span.
    fn record(&self, family: &str, detail: &Json) {
        let Some(store) = self.stores.get(family) else {
            tracing::warn!(
                "{}enrollment monitor: \"{}\" is not an enrollment family; \
                 nothing counted.",
                sts_core::log::tag(codes::STS_ENROLL_0090.as_str()),
                family
            );
            return;
        };
        let said = if detail.is_object() {
            detail.clone()
        } else {
            json!({})
        };
        let outcome = match text_of(&said, "outcome") {
            o if o.is_empty() => "answered".to_string(),
            o => o,
        };
        let now = now_iso();
        {
            let mut row = store.get("counters").unwrap_or_else(empty_row);
            let add = |row: &mut Json, field: &str| {
                let n = num(row, field) + 1.0;
                row[field] = number(n);
            };
            add(&mut row, "requests");
            match outcome.as_str() {
                "issued" => add(&mut row, "issued"),
                "refused" => add(&mut row, "refused"),
                "revoked" => add(&mut row, "revoked"),
                "credential" => add(&mut row, "credentialsCreated"),
                "redeemed" => add(&mut row, "credentialsRedeemed"),
                _ => {}
            }
            let table = |row: &mut Json, name: &str, key: &str| {
                let mut t = row[name].as_object().cloned().unwrap_or_default();
                bump(&mut t, key);
                row[name] = Json::Object(t);
            };
            table(&mut row, "operations", &text_of(&said, "operation"));
            for (member, name) in [
                ("profile", "profiles"),
                ("principal", "principals"),
                ("errorCode", "codes"),
                ("status", "statuses"),
                ("failInfo", "failInfos"),
            ] {
                if truthy(&said, member) {
                    table(&mut row, name, &text_of(&said, member));
                }
            }
            let cut = |member: &str, n: usize| {
                if truthy(&said, member) {
                    Json::from(slice(&text_of(&said, member), n))
                } else {
                    Json::Null
                }
            };
            let status = match said.get("status") {
                Some(Json::Number(n)) => n
                    .as_f64()
                    .filter(|f| *f != 0.0 && f.is_finite())
                    .map(number)
                    .unwrap_or(Json::Null),
                Some(Json::String(s)) => s
                    .trim()
                    .parse::<f64>()
                    .ok()
                    .filter(|f| *f != 0.0)
                    .map(number)
                    .unwrap_or(Json::Null),
                _ => Json::Null,
            };
            let first = json!({
                "at": now,
                "operation": slice(&text_of(&said, "operation"), 60),
                "outcome": outcome,
                "status": status,
                "profile": cut("profile", 40),
                "principal": cut("principal", 120),
                "target": cut("target", 120),
                "errorCode": cut("errorCode", 40),
                "failInfo": cut("failInfo", 40),
                "serialHex": cut("serialHex", 80),
            });
            let mut recent = vec![first];
            recent
                .extend(row["recent"].as_array().cloned().unwrap_or_default());
            recent.truncate(RECENT);
            row["recent"] = Json::Array(recent);
            row["lastAt"] = Json::from(now.as_str());
            store.set("counters", row);
        }
    }
}
