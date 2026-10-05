// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The scheduler's core against Node: `scheduler-node.json`, which
//! `tests/tools/crypto-vectors.js` writes with `cluster/scheduler.ts`'s own
//! `Scheduler` over stand-in deps. Both sides build the same jobs from the
//! same descriptors and settings; every interval, schedule text,
//! off-reason, time limit, slot, run id, next delay, concurrency limit,
//! refused registration, row rank, expiry, span and cron occurrence must be
//! Node's.
//!
//! Two answers differ by design and are pinned here: croner's complaint
//! about an expression it cannot read is in each parser's own words, so a
//! refusal is compared up to it; and the npm croner THROWS for every
//! occurrence of `0 0 29 2 *` (a leap day), where the Rust crate finds them.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed; with it unset
//! this test says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_cluster::schedule::{
    compare_rows, cron_next, cron_prev, run_id_for, span, JobSpec, Kind,
    Schedule, SchedulerSettings, Schedules, Scope, Unit,
};

struct Settings(HashMap<String, Json>);

impl SchedulerSettings for Settings {
    fn number(&self, key: &str) -> f64 {
        self.0.get(key).and_then(Json::as_f64).unwrap_or(0.0)
    }
    fn flag(&self, key: &str) -> bool {
        self.0.get(key).and_then(Json::as_bool).unwrap_or(false)
    }
    fn list(&self, key: &str) -> Vec<String> {
        self.0
            .get(key)
            .and_then(Json::as_array)
            .map(|a| {
                a.iter().map(|x| x.as_str().unwrap().to_string()).collect()
            })
            .unwrap_or_default()
    }
}

/// Integral floats as integers, so `30000.0` is Node's `30000`.
fn norm(v: Json) -> Json {
    match v {
        Json::Number(n) => match n.as_f64() {
            Some(f) if f.fract() == 0.0 && f.abs() < 9e15 => json!(f as i64),
            _ => Json::Number(n),
        },
        Json::Array(a) => Json::Array(a.into_iter().map(norm).collect()),
        Json::Object(o) => {
            Json::Object(o.into_iter().map(|(k, x)| (k, norm(x))).collect())
        }
        other => other,
    }
}

fn spec_of(d: &Json) -> JobSpec {
    let id = d["id"].as_str().unwrap();
    let schedule = if let Some(ms) = d["everyMs"].as_f64() {
        Schedule::Every(Arc::new(move || ms))
    } else if let Some(key) = d["everySetting"].as_str() {
        let unit = match d["unit"].as_str() {
            Some("ms") => Unit::Ms,
            Some("min") => Unit::Min,
            Some("h") => Unit::H,
            Some("days") => Unit::Days,
            _ => Unit::S,
        };
        Schedule::EverySetting {
            key: key.to_string(),
            unit,
        }
    } else if let Some(expr) = d["cron"].as_str() {
        Schedule::Cron(expr.to_string())
    } else {
        Schedule::ManualOnly
    };
    let mut spec = JobSpec::new(id, &format!("T {}", id), "D", "O", schedule);
    if d["kind"] == "per-process" {
        spec.kind = Kind::PerProcess;
    }
    if d["scope"] == "realm" {
        spec.scope = Scope::Realm;
    }
    spec.run = Some(Arc::new(|_| Box::pin(async { Ok(Json::Null) })));
    spec.quiet = d["quiet"].as_bool().unwrap_or(false);
    if let Some(t) = d["timeoutS"].as_f64() {
        spec.timeout_s = Some(Arc::new(move || t));
    }
    if let Some(off) = d["off"].as_object() {
        let off = off.clone();
        spec.off = Some(Arc::new(move |realm: &str| {
            Ok(off
                .get(realm)
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_string())
        }));
    }
    if let Some(why) = d["offThrows"].as_str() {
        let why = why.to_string();
        spec.off = Some(Arc::new(move |_: &str| Err(why.clone())));
    }
    spec
}

#[test]
fn the_scheduler_core_is_nodes() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: scheduler-node.json is not checked"
        );
        return;
    };
    let v: Json = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(&dir).join("scheduler-node.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let mut failures = Vec::new();
    let mut checked = 0;
    let mut check = |ok: bool, what: String| {
        checked += 1;
        if !ok {
            failures.push(what);
        }
    };

    let settings: HashMap<String, Json> = v["settings"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, x)| (k.clone(), x.clone()))
        .collect();
    let pool = Arc::new(std::sync::Mutex::new(0.0f64));
    let pool_reader = pool.clone();
    let mut sched = Schedules::new(Arc::new(Settings(settings)))
        .with_store_connections(Arc::new(move || *pool_reader.lock().unwrap()));
    for d in v["descriptors"].as_array().unwrap() {
        sched.register(spec_of(d)).unwrap();
    }
    let times: Vec<i64> = v["times"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_i64().unwrap())
        .collect();

    for node in v["jobs"].as_array().unwrap() {
        let id = node["id"].as_str().unwrap();
        let job = sched.job(id).unwrap();
        check(
            norm(json!(sched.interval_ms(job))) == node["interval"],
            format!("{} interval", id),
        );
        check(
            json!(sched.schedule_text(job)) == node["text"],
            format!("{} text: {}", id, sched.schedule_text(job)),
        );
        let off: Vec<String> = ["default", "acme"]
            .iter()
            .map(|r| sched.off_reason(job, r))
            .collect();
        check(json!(off) == node["off"], format!("{} off {:?}", id, off));
        check(
            norm(json!(sched.timeout_ms_of(job))) == node["timeout"],
            format!("{} timeout", id),
        );
        for (t, want) in times.iter().zip(node["slots"].as_array().unwrap()) {
            let got = sched
                .slot_at(job, *t)
                .map(|s| json!({ "slot": s.slot, "startsAt": s.starts_at, "nextAt": s.next_at }))
                .unwrap_or(Json::Null);
            let cron = matches!(job.schedule, Schedule::Cron(_));
            check(
                norm(got.clone()) == *want
                    || (cron && want["nextAt"].is_null()),
                format!("{} slot at {}: {} vs {}", id, t, got, want),
            );
        }
        for (slot, want) in [0i64, 1, 1767322800000]
            .iter()
            .zip(node["runIds"].as_array().unwrap())
        {
            check(
                json!(run_id_for(id, "acme", *slot)) == *want,
                format!("{} run id {}", id, slot),
            );
        }
    }
    for (t, want) in times.iter().zip(v["delays"].as_array().unwrap()) {
        let got = json!({ "cluster": sched.next_delay_ms(Kind::Cluster, *t, "default"),
                          "perProcess": sched.next_delay_ms(Kind::PerProcess, *t, "default") });
        check(
            norm(got.clone()) == *want,
            format!("next delay at {}: {} vs {}", t, got, want),
        );
    }
    for (n, want) in [0.0, 1.0, 2.0, 3.0, 10.0]
        .iter()
        .zip(v["concurrency"].as_array().unwrap())
    {
        *pool.lock().unwrap() = *n;
        check(
            norm(json!(sched.max_concurrent_runs())) == *want,
            format!("concurrency at pool {}", n),
        );
    }
    for r in v["refused"].as_array().unwrap() {
        let got = sched.register(spec_of(&r["descriptor"])).err();
        let want = r["error"].as_str();
        let same = match (got.as_deref(), want) {
            (Some(g), Some(w)) if w.contains("croner can read (") => {
                g.split_once("croner can read (").map(|p| p.0)
                    == w.split_once("croner can read (").map(|p| p.0)
            }
            (g, w) => g == w,
        };
        check(
            same,
            format!(
                "register {}:\n  rust {:?}\n  node {:?}",
                r["descriptor"]["id"], got, want
            ),
        );
    }
    for (row, want) in v["rows"]
        .as_array()
        .unwrap()
        .iter()
        .zip(v["expiries"].as_array().unwrap())
    {
        check(
            norm(json!(sched.expiry_of(row))) == *want,
            format!("expiry of {}", row),
        );
    }
    for r in v["ranks"].as_array().unwrap() {
        let got = compare_rows(&r["a"], &r["b"]) as i8;
        check(
            json!(got) == r["order"],
            format!("rank {} vs {}", r["a"], r["b"]),
        );
    }
    for (ms, want) in v["spans"]
        .as_array()
        .unwrap()
        .iter()
        .zip(v["spanText"].as_array().unwrap())
    {
        let got = span(ms.as_f64().unwrap());
        check(json!(got) == *want, format!("span {} = {}", ms, got));
    }
    for c in v["cron"].as_array().unwrap() {
        let expr = c["expr"].as_str().unwrap();
        let valid = sts_cluster::schedule::parse_cron(expr).is_ok();
        check(
            json!(valid) == c["valid"],
            format!("cron {} valid {}", expr, valid),
        );
        for a in c["at"].as_array().unwrap() {
            let t = a["t"].as_i64().unwrap();
            for (name, got) in
                [("prev", cron_prev(expr, t)), ("next", cron_next(expr, t))]
            {
                // The npm croner throws for a leap day (see above).
                if a[name] == "throws" && expr == "0 0 29 2 *" {
                    continue;
                }
                check(
                    json!(got) == a[name],
                    format!(
                        "cron {} {} at {}: {:?} vs {}",
                        expr, name, t, got, a[name]
                    ),
                );
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} differ:\n{}",
        failures.len(),
        checked,
        failures.join("\n")
    );
    eprintln!("{} answers as Node gives them", checked);
}

#[test]
fn a_leap_day_has_occurrences() {
    // 2026-10-05 → 2028-02-29, and back from 2027 to 2024-02-29.
    assert_eq!(cron_next("0 0 29 2 *", 1791191861123), Some(1835395200000));
    assert_eq!(cron_prev("0 0 29 2 *", 1800000000000), Some(1709164800000));
}
