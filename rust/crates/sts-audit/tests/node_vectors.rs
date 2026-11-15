// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The audit log against Node: `auditmail-node.json`'s `audit`, which
//! `tests/tools/audit-vectors.js` records from `common/audit.js`,
//! `admin-core/admin_views.ts` and `common/audit_export.ts`. Every step
//! Node ran is replayed here, under the same frozen clock and the same
//! ephemeral key-encryption key (so the keyed checksums are the same), and
//! every answer must be Node's:
//!
//! * every row each funnel wrote, member for member, checksum included;
//! * the ring after them, `list()`, `summary()`, the two attempts readers,
//!   `verifyIntegrity()` over the ring and over five tampered copies;
//! * the `/admin-api/audit` answer for twenty-one queries;
//! * the pure helpers;
//! * the export (`export_vectors`, below).
//!
//! With `STS_WRITE_VECTORS=1` the last test writes `audit-rust.json` —
//! rows Rust wrote and events it built — which `tests/rust_crypto_vectors.js`
//! checks in Node. The directory is `STS_CRYPTO_VECTORS`, never committed;
//! unset, these tests say so and pass.

#![allow(clippy::unwrap_used, clippy::expect_used)] // a test file

use std::collections::HashMap;
mod common;

use common::{same, vectors, Frozen, Keys};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_audit::log::ApiCaller;
use sts_audit::view::{self, AuditQuery, ViewPorts};
use sts_audit::{AuditLog, AuditPorts, AuditRow, HttpExchange};
use sts_core::mode::Mode;
use sts_core::settings::Settings;

struct NoUsers;

impl ViewPorts for NoUsers {
    fn known_user(&self, _: &str) -> bool {
        false
    }
    fn page_settings(
        &self,
    ) -> Option<sts_model_management_components_1::AuditListSettings> {
        None
    }
    fn persisted(&self) -> bool {
        false
    }
}

pub struct Ring {
    pub log: AuditLog,
    pub settings: Arc<Settings>,
    pub clock: Arc<AtomicI64>,
}

pub fn ring(v: &Json) -> Ring {
    let settings = Arc::new(Settings::new(Json::Null, HashMap::new()));
    let clock = Arc::new(AtomicI64::new(v["t0"].as_i64().unwrap()));
    let keys =
        sts_store::keystore::DataKeys::ephemeral(v["kek"].as_str().unwrap())
            .unwrap();
    let mut ports = AuditPorts::local(settings.clone());
    ports.clock = Arc::new(Frozen(clock.clone()));
    ports.digest = Some(Arc::new(Keys(keys)));
    Ring {
        log: AuditLog::new(ports),
        settings,
        clock,
    }
}

fn text(v: &Json) -> String {
    v.as_str().unwrap_or("").to_string()
}

fn exchange(step: &Json) -> HttpExchange {
    let req = &step["req"];
    let res = &step["res"];
    let info = &step["info"];
    let locals = &res["locals"];
    HttpExchange {
        method: text(&req["method"]),
        original_url: text(&req["url"]),
        query: req["query"].as_object().cloned().unwrap_or_default(),
        body: req["body"].as_str().map(str::to_string),
        content_type: text(&req["contentType"]),
        status: res["status"].as_u64().unwrap() as u16,
        marked: res["mark"].as_str().map(str::to_string),
        route: text(&info["route"]),
        matched: info["matched"].as_bool().unwrap_or(false),
        duration_ms: info["durationMs"].as_f64().unwrap_or(0.0),
        address: text(&step["resolved"]),
        actor: text(&step["actor"]),
        session: text(&step["session"]),
        api_caller: locals["apiCaller"].as_object().map(|c| ApiCaller {
            name: c["name"].as_str().unwrap_or("").to_string(),
            owner: c["owner"].as_bool().unwrap_or(false),
        }),
        quiet_when_ok: locals["auditQuietWhenOk"].as_bool().unwrap_or(false),
        incident: None,
    }
}

fn step(r: &Ring, s: &Json) -> Json {
    let row =
        |x: Option<AuditRow>| x.map(|r| r.to_json()).unwrap_or(Json::Null);
    match s["op"].as_str().unwrap() {
        "set" => {
            r.settings
                .set_override(s["key"].as_str().unwrap(), s["value"].clone())
                .unwrap();
            Json::Bool(true)
        }
        "now" => {
            r.clock.store(s["at"].as_i64().unwrap(), Ordering::SeqCst);
            s["at"].clone()
        }
        "audit" => row(r.log.audit(&s["event"])),
        "failure" => {
            row(r.log.failure(s["code"].as_str().unwrap(), &s["event"]))
        }
        "directory" => row(r.log.record_directory(&s["event"])),
        "source" => {
            AuditLog::with_source(s["address"].as_str().unwrap(), || {
                step(r, &s["then"])
            })
        }
        "http" => {
            let mut x = exchange(s);
            if s["reserve"].as_bool() == Some(true) {
                let seq = r.log.reserve_incident();
                assert_eq!(Json::from(seq), s["reserved"], "the incident");
                x.incident = Some(seq);
            }
            row(r.log.record_http(&x))
        }
        other => panic!("no step {}", other),
    }
}

fn rows_of(v: &Json) -> Vec<AuditRow> {
    serde_json::from_value(v.clone()).unwrap()
}

fn strings(v: &Json) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect()
}

pub fn replay_ring(v: &Json) -> Ring {
    let r = ring(v);
    let ring_v = &v["ring"];
    let steps = ring_v["steps"].as_array().unwrap();
    let results = ring_v["results"].as_array().unwrap();
    for (i, (s, want)) in steps.iter().zip(results).enumerate() {
        let got = step(&r, s);
        same(&format!("ring step {} ({})", i, s), &got, want);
    }
    r
}

#[test]
fn ring_vectors() {
    let Some(v) = vectors() else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set (or has no audit vectors): \
             nothing to check"
        );
        return;
    };
    let r = replay_ring(&v);
    let ring_v = &v["ring"];
    let local: Vec<Json> =
        r.log.local_events().iter().map(AuditRow::to_json).collect();
    same("localEvents()", &Json::from(local), &ring_v["local"]);
    let list: Vec<Json> = r.log.list().iter().map(AuditRow::to_json).collect();
    same("list()", &Json::from(list), &ring_v["list"]);
    same("summary()", &r.log.summary(), &ring_v["summary"]);
    same(
        "verifyIntegrity()",
        &r.log.verify_integrity(None),
        &ring_v["integrity"],
    );
    for t in ring_v["tampered"].as_array().unwrap() {
        let held = rows_of(&t["held"]);
        same(
            &format!("verifyIntegrity({})", t["name"]),
            &r.log.verify_integrity(Some(&held)),
            &t["verdict"],
        );
    }
    for a in ring_v["attempts"].as_array().unwrap() {
        let seqs: Vec<i64> = r
            .log
            .authentication_events_for(&strings(&a["names"]))
            .iter()
            .map(|row| row.seq)
            .collect();
        same(
            &format!("authenticationEventsFor({})", a["names"]),
            &json!(seqs),
            &a["seqs"],
        );
    }
    for p in ring_v["person"].as_array().unwrap() {
        let seqs: Vec<i64> = r
            .log
            .authentication_events_for_person(
                &strings(&p["names"]),
                p["since"].as_f64().unwrap(),
            )
            .iter()
            .map(|row| row.seq)
            .collect();
        same(
            &format!("authenticationEventsForPerson({})", p["names"]),
            &json!(seqs),
            &p["seqs"],
        );
    }
    let mode = Mode::new(r.settings.clone());
    let ports: Arc<dyn ViewPorts> = Arc::new(NoUsers);
    for one in ring_v["views"].as_array().unwrap() {
        let query = AuditQuery::from_map(one["query"].as_object().unwrap());
        let answer = view::audit_view(&r.log, &mode, &ports, &query);
        let got = serde_json::to_value(&answer).unwrap();
        same(&format!("auditView({})", one["query"]), &got, &one["json"]);
    }
}

#[test]
fn helper_vectors() {
    let Some(v) = vectors() else {
        return;
    };
    use sts_audit::log::*;
    let h = &v["helpers"];
    for p in h["redactedPath"].as_array().unwrap() {
        assert_eq!(
            redacted_path(p[0].as_str().unwrap()),
            text(&p[1]),
            "{}",
            p[0]
        );
    }
    for q in h["redactedQuery"].as_array().unwrap() {
        let got = redacted_query(q[0].as_object().unwrap());
        same("redactedQuery", &Json::Object(got), &q[1]);
    }
    let containers = |c: &Json| (text(&c["users"]), text(&c["groups"]));
    for o in h["objectKindOf"].as_array().unwrap() {
        let (u, g) = containers(&o[1]);
        assert_eq!(
            object_kind_of(o[0].as_str().unwrap(), &u, &g),
            text(&o[2]),
            "{}",
            o
        );
    }
    for o in h["directoryActionFor"].as_array().unwrap() {
        let (u, g) = containers(&o[2]);
        assert_eq!(
            directory_action_for(
                o[0].as_str().unwrap(),
                o[1].as_str().unwrap(),
                &u,
                &g
            ),
            text(&o[3])
        );
    }
    for q in h["quietWhenOk"].as_array().unwrap() {
        let s = match &q[0][2] {
            Json::String(s) => s.clone(),
            other => other.to_string(),
        };
        assert_eq!(
            quiet_when_ok(
                q[0][0].as_str().unwrap(),
                q[0][1].as_str().unwrap(),
                &s
            ),
            q[1].as_bool().unwrap(),
            "{}",
            q
        );
    }
}

/// The other direction: rows a fresh Rust log wrote under Node's key, and
/// the events and lines Rust built from them, for `fromRust()` in
/// `tests/tools/audit-vectors.js` to check with Node's own functions.
#[test]
fn write_rust_vectors() {
    if std::env::var("STS_WRITE_VECTORS").as_deref() != Ok("1") {
        return;
    }
    let Some(v) = vectors() else {
        return;
    };
    let r = ring(&v);
    let events = [
        json!({ "action": "authentication", "actor": "zoë",
                "detail": { "client_id": "app", "password": "p",
                            "deep": { "token": "t" } } }),
        json!({ "action": "session.start", "detail": "a sentence" }),
        json!({ "action": "consent.granted", "summary": "naïve\nline",
                "errorCode": "STS-AUDIT-0007" }),
        json!({ "action": "no.such", "category": "other", "outcome": "error",
                "detail": { "2": 2, "1": 1, "x": [1, null] } }),
    ];
    for (i, e) in events.iter().enumerate() {
        r.clock.fetch_add(1000 + i as i64, Ordering::SeqCst);
        assert!(r.log.audit(e).is_some());
    }
    assert!(r
        .log
        .failure("STS-AUDIT-0009", &json!({ "summary": "f" }))
        .is_some());
    assert!(r
        .log
        .record_directory(&json!({ "action": "user.create",
        "target": "uid=a,ou=users,dc=x" }))
        .is_some());
    let rows: Vec<Json> =
        r.log.local_events().iter().map(AuditRow::to_json).collect();
    let names = vec!["password".to_string(), "deep".to_string()];
    let made: Vec<Json> = rows
        .iter()
        .map(|row| {
            let opts = sts_audit::export::event::CanonicalOptions {
                realm: "acme".into(),
                origin: String::new(),
                source: "sts-rust".into(),
                names: names.iter().cloned().collect(),
                now: 0,
            };
            let event = sts_audit::export::event::canonical(row, &opts);
            let dest = json!({ "facility": 5, "appName": "rust app" });
            let syslog = sts_audit::export::event::syslog_line(
                &event,
                &dest,
                "rust-host",
                7,
                0,
            );
            json!({ "row": row, "realm": "acme", "origin": "",
                    "source": "sts-rust", "names": names, "event": event,
                    "dest": dest, "syslog": syslog })
        })
        .collect();
    let dir = std::env::var("STS_CRYPTO_VECTORS").unwrap();
    let out = json!({ "kek": v["kek"], "rows": rows, "events": made });
    std::fs::write(
        std::path::Path::new(&dir).join("audit-rust.json"),
        serde_json::to_string_pretty(&out).unwrap(),
    )
    .unwrap();
}
