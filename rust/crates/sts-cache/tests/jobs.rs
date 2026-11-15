// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The registry's two jobs are valid scheduler jobs, per-process and quiet,
//! and do what they say: the ejection deletes what has expired and counts
//! it, the report keeps a snapshot for the heartbeat, and is off where this
//! process is not a joined node.

#![allow(clippy::unwrap_used)] // a test file

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value as Json};
use sts_cache::jobs::{
    cache_report_job, eject_job, CACHE_REPORT_JOB, EJECT_JOB,
};
use sts_cache::{CacheRegistry, Descriptor, Row, Scope};
use sts_cluster::schedule::{Kind, RunContext, SchedulerSettings, Schedules};

struct Expiring(Mutex<HashMap<String, i64>>);
impl Descriptor for Expiring {
    fn name(&self) -> &str {
        "t.expiring"
    }
    fn title(&self) -> &str {
        "T"
    }
    fn description(&self) -> &str {
        "D"
    }
    fn owner(&self) -> &str {
        "o"
    }
    fn scope(&self) -> Scope {
        Scope::Process
    }
    fn max_entries(&self) -> usize {
        10
    }
    fn lifetime(&self) -> String {
        "a minute".into()
    }
    fn entries(&self, now: i64) -> Result<Vec<Row>, String> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|(k, u)| Row::timed(None, k.clone(), Some(*u), now))
            .collect())
    }
    fn ejects(&self) -> bool {
        true
    }
    fn eject(&self, now: i64) -> Result<usize, String> {
        let mut m = self.0.lock().unwrap();
        let before = m.len();
        m.retain(|_, u| *u > now);
        Ok(before - m.len())
    }
}

struct Settings;
impl SchedulerSettings for Settings {
    fn number(&self, _: &str) -> f64 {
        0.0
    }
    fn flag(&self, k: &str) -> bool {
        k == "scheduler.enabled"
    }
    fn list(&self, _: &str) -> Vec<String> {
        Vec::new()
    }
}

fn ctx(now: f64) -> RunContext {
    RunContext {
        realm: "default".into(),
        run_id: "r".into(),
        trigger: "schedule".into(),
        params: Json::Null,
        still_owner: Arc::new(|| true),
        now_ms: Arc::new(move || now),
    }
}

#[tokio::test]
async fn the_ejection_and_the_report_are_per_process_jobs() {
    let reg = Arc::new(CacheRegistry::new());
    let store = Arc::new(Expiring(Mutex::new(HashMap::from([
        ("old".to_string(), 5),
        ("new".to_string(), 50),
    ]))));
    reg.register(store.clone());
    let eject = eject_job(reg.clone());
    let report = Arc::new(Mutex::new(None));
    let joined = Arc::new(Mutex::new(false));
    let off = {
        let joined = joined.clone();
        Arc::new(move || {
            if *joined.lock().unwrap() {
                String::new()
            } else {
                "this process is not a joined front process".to_string()
            }
        })
    };
    let reporting = cache_report_job(reg.clone(), report.clone(), off);
    for job in [&eject, &reporting] {
        assert_eq!(job.kind, Kind::PerProcess);
        assert!(job.quiet);
    }
    let mut schedules = Schedules::new(Arc::new(Settings));
    schedules.register(eject.clone()).unwrap();
    schedules.register(reporting.clone()).unwrap();
    assert!(schedules.job(EJECT_JOB).is_some());
    assert!(schedules.job(CACHE_REPORT_JOB).is_some());

    let done = (eject.run.clone().unwrap())(ctx(10.0)).await.unwrap();
    assert_eq!(done, json!({ "ejected": 1, "stores": 1, "failed": 0 }));
    assert_eq!(store.0.lock().unwrap().len(), 1);

    assert!(!schedules
        .off_reason(schedules.job(CACHE_REPORT_JOB).unwrap(), "default")
        .is_empty());
    *joined.lock().unwrap() = true;
    assert!(schedules
        .off_reason(schedules.job(CACHE_REPORT_JOB).unwrap(), "default")
        .is_empty());
    (reporting.run.clone().unwrap())(ctx(10.0)).await.unwrap();
    let taken = report.lock().unwrap().clone().unwrap();
    assert_eq!(taken.caches.len(), 1);
    assert_eq!(taken.caches[0].evictions, 1);
}
