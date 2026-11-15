// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The ring in the store, both ways (`store.rs`; D11, the compatible
//! upgrade): what this runtime writes under `audit.events` is Node's
//! `segmentedArr()` — a row per 32 entries keyed by the segment's number,
//! `{ start, rows }` — and `audit.nums` is Node's counter object; and a
//! ring Node wrote, given back in that form, is what the log lists. The
//! row JSON itself is proved against Node by `node_vectors.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_audit::store::{StoreRing, EVENTS_HANDLE, NUMS_HANDLE};
use sts_audit::{AuditLog, AuditPorts};
use sts_core::mode::Mode;
use sts_core::realm::{RealmRegistry, SettingsEnvironment};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::StoreHandles;
use sts_core::settings::Settings;

struct World {
    handles: Arc<StoreHandles>,
    ring: Arc<StoreRing>,
    log: AuditLog,
}

fn world(max_events: i64) -> World {
    let settings = Arc::new(Settings::new(
        json!({ "audit": { "maxEvents": max_events } }),
        HashMap::new(),
    ));
    let mode = Mode::shared(settings.clone());
    let registry = Arc::new(RealmRegistry::new(Arc::new(
        SettingsEnvironment::new(settings.clone(), Vec::new()),
    )));
    let lifecycle = RealmLifecycle::new(registry, settings.clone(), mode);
    let handles = StoreHandles::new();
    let ring = StoreRing::declare(&lifecycle, &handles);
    let mut ports = AuditPorts::local(settings);
    ports.sink = Some(ring.clone());
    World {
        handles,
        ring,
        log: AuditLog::new(ports),
    }
}

fn dump(w: &World, handle: &str) -> Vec<(String, Json)> {
    w.handles
        .handle_for(handle)
        .expect("declared")
        .access
        .dump("default")
}

fn write(w: &World, n: usize) {
    for i in 0..n {
        w.log.failure(
            "STS-OAUTH-0950",
            &json!({ "summary": format!("row {}", i), "channel": "http" }),
        );
    }
}

#[test]
fn both_handles_are_declared_as_node_declares_them() {
    let w = world(5000);
    for handle in [EVENTS_HANDLE, NUMS_HANDLE] {
        let h = w.handles.handle_for(handle).expect("declared");
        assert_eq!(h.spec.merge, sts_core::realm_store::Merge::Own);
        assert_eq!(h.scope, "realm");
    }
    assert_eq!(w.handles.handle_for(EVENTS_HANDLE).unwrap().shape, "arr");
    assert_eq!(w.handles.handle_for(NUMS_HANDLE).unwrap().shape, "obj");
}

#[test]
fn rust_writes_node_segments() {
    let w = world(5000);
    write(&w, 40);
    let segments = dump(&w, EVENTS_HANDLE);
    let keys: Vec<&str> = segments.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(keys, vec!["0", "1"]);
    assert_eq!(segments[0].1["start"], json!(0));
    assert_eq!(segments[0].1["rows"].as_array().unwrap().len(), 32);
    assert_eq!(segments[1].1["start"], json!(32));
    assert_eq!(segments[1].1["rows"].as_array().unwrap().len(), 8);
    let first = &segments[0].1["rows"][0];
    assert_eq!(first["errorCode"], json!("STS-OAUTH-0950"));
    assert_eq!(first["seq"], json!(1));
    let nums = dump(&w, NUMS_HANDLE);
    assert_eq!(nums.len(), 1);
    assert_eq!(nums[0].0, "");
    assert_eq!(nums[0].1["seq"], json!(40));
    assert_eq!(nums[0].1["recorded"], json!(40));
    for member in ["head", "headSeq", "headMac"] {
        assert!(nums[0].1.get(member).is_some(), "{}", member);
    }
}

#[test]
fn a_trim_drops_the_front_as_the_ring_does() {
    let w = world(10);
    write(&w, 40);
    let rows: Vec<Json> = dump(&w, EVENTS_HANDLE)
        .into_iter()
        .flat_map(|(_, seg)| seg["rows"].as_array().unwrap().clone())
        .collect();
    let seqs: Vec<i64> =
        rows.iter().map(|r| r["seq"].as_i64().unwrap()).collect();
    assert_eq!(seqs, (31..=40).collect::<Vec<i64>>());
    let held: Vec<i64> = w.log.local_events().iter().map(|r| r.seq).collect();
    assert_eq!(seqs, held);
}

#[test]
fn a_ring_node_wrote_reads_back() {
    // What a 1.x install keeps: two segments and the counters, as
    // `segmentedArr()` and `realms.obj()` write them.
    let node_row = |seq: i64| {
        json!({ "seq": seq, "origin": "", "at": 1_700_000_000_000i64 + seq,
                "category": "protocol", "action": "protocol.failure",
                "outcome": "refused", "errorCode": "STS-OAUTH-0950",
                "actor": "", "actorForm": "", "target": "", "protocol": "",
                "channel": "http", "address": "10.0.0.1",
                "summary": format!("[STS-OAUTH-0950] row {}", seq),
                "detail": {}, "prev": "", "mac": "" })
    };
    let w = world(5000);
    let events = w.handles.handle_for(EVENTS_HANDLE).unwrap();
    events.access.restore(
        "default",
        "0",
        json!({ "start": 0, "rows": (1..=32).map(node_row).collect::<Vec<_>>() }),
    );
    events.access.restore(
        "default",
        "1",
        json!({ "start": 32, "rows": (33..=35).map(node_row).collect::<Vec<_>>() }),
    );
    w.handles.handle_for(NUMS_HANDLE).unwrap().access.restore(
        "default",
        "",
        json!({ "seq": 35, "recorded": 35, "head": "", "headSeq": 0,
                "headMac": "" }),
    );
    w.ring.restore_into(&w.log, &["default".to_string()]);
    let listed = w.log.list();
    assert_eq!(listed.len(), 35);
    assert_eq!(listed[0].seq, 35, "newest first");
    assert_eq!(listed[34].to_json(), node_row(1), "member for member");
    // The next row continues Node's counter, and lands in segment 1.
    write(&w, 1);
    assert_eq!(w.log.list()[0].seq, 36);
    let segments = dump(&w, EVENTS_HANDLE);
    assert_eq!(segments[1].1["rows"].as_array().unwrap().len(), 4);
}
