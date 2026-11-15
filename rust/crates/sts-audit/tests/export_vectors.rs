// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The audit export against Node: every scenario `tests/tools/audit-vectors.js`
//! ran through `common/audit_export.ts` — acts and their refusals, ticks
//! against scripted receivers, screens, the page — replayed here against
//! receivers scripted the same way, and every answer compared: the result
//! and its code, what each destination was sent (headers, body, frame,
//! line), the rows the exporter audited, the cursors after, the files and
//! `view()`. Then the static half (`canonical()`, `syslogLine()`, the
//! classifiers and readers) over Node's own inputs.
//!
//! ONE PINNED DISAGREEMENT, a Node defect: Node's UDP syslog never
//! transmits — `sendUdp()` calls `setTimeout()` on a `dgram.Socket`, which
//! has none, so every send fails `STS-AUDIT-0006` ("sock.setTimeout is not
//! a function") and the cursor never moves. Rust transmits. The `udp`
//! destination of the syslog scenario is checked for that and left out of
//! the comparison.

#![allow(clippy::unwrap_used, clippy::expect_used)] // a test file

mod common;

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use common::{norm, same, vectors, Frozen};
use serde_json::{json, Map, Value as Json};
use sts_audit::export::outbound::{NoCaFiles, Outbound, TlsPolicy};
use sts_audit::export::transport::{
    AppendFile, Files, HttpAnswer, HttpRequest, HttpTransport,
    RealTransports, Resolver, SendError, SyslogPipe, SyslogTransport,
};
use sts_audit::export::{
    event, AuditExport, AuditSink, ExportPorts, MemoryMaps, NoSealing,
};
use sts_cluster::schedule::BoxFuture;
use sts_core::mode::Mode;
use sts_core::settings::Settings;

type Sent = Arc<Mutex<Vec<Json>>>;

struct Book {
    held: Mutex<Vec<Json>>,
    recorded: Mutex<Vec<Json>>,
}

impl AuditSink for Book {
    fn local_events(&self) -> Vec<Json> {
        self.held.lock().unwrap().clone()
    }
    fn audit(&self, event: &Json) {
        let mut row = Map::new();
        row.insert("kind".into(), json!("audit"));
        row.extend(event.as_object().unwrap().clone());
        self.recorded.lock().unwrap().push(Json::Object(row));
    }
    fn failure(&self, code: &str, event: &Json) {
        let mut row = Map::new();
        row.insert("kind".into(), json!("failure"));
        row.insert("errorCode".into(), json!(code));
        row.extend(event.as_object().unwrap().clone());
        self.recorded.lock().unwrap().push(Json::Object(row));
    }
}

struct Dns(Map<String, Json>);

impl Resolver for Dns {
    fn lookup<'a>(
        &'a self,
        host: &'a str,
    ) -> BoxFuture<'a, Result<Vec<String>, String>> {
        Box::pin(async move {
            match self.0.get(&host.to_lowercase()) {
                Some(Json::String(s)) if s == "fail" => {
                    Err("lookup failed".to_string())
                }
                Some(Json::Array(a)) => Ok(a
                    .iter()
                    .map(|v| v.as_str().unwrap().to_string())
                    .collect()),
                _ => Ok(vec!["8.8.8.8".to_string()]),
            }
        })
    }
}

struct Http {
    sent: Sent,
    queue: Arc<Mutex<VecDeque<Json>>>,
}

impl HttpTransport for Http {
    fn post<'a>(
        &'a self,
        r: &'a HttpRequest,
    ) -> BoxFuture<'a, Result<HttpAnswer, String>> {
        Box::pin(async move {
            let headers: Map<String, Json> = r
                .headers
                .iter()
                .map(|(k, v)| {
                    let text = match v {
                        Json::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    (k.clone(), json!(text))
                })
                .collect();
            let mut one = json!({ "kind": "http", "protocol": r.protocol,
                "hostname": r.hostname, "port": r.port, "path": r.path,
                "method": r.method, "headers": headers, "body": r.body,
                "pinned": r.pinned });
            if let Some(tls) = &r.tls {
                one["rejectUnauthorized"] = json!(tls.reject_unauthorized);
            }
            self.sent.lock().unwrap().push(one);
            let answered = self
                .queue
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(json!({ "status": 200 }));
            let status = answered["status"].as_u64().unwrap() as u16;
            let headers: HashMap<String, String> = answered["headers"]
                .as_object()
                .map(|m| {
                    m.iter()
                        .map(|(k, v)| (k.clone(), v.as_str().unwrap().into()))
                        .collect()
                })
                .unwrap_or_default();
            let mut answer = HttpAnswer { status, headers,
                                          ..HttpAnswer::default() };
            if (300..400).contains(&status) {
                return Ok(answer);
            }
            let body = match &answered["body"] {
                Json::Null => String::new(),
                Json::String(s) => s.clone(),
                other => other.to_string(),
            };
            if body.len() > event::BODY_CAP {
                answer.overflow = true;
            } else {
                answer.body = body.into_bytes();
            }
            Ok(answer)
        })
    }
}

struct Pipe {
    sent: Sent,
    record: Json,
}

impl SyslogPipe for Pipe {
    fn write<'a>(
        &'a mut self,
        frame: &'a [u8],
        _timeout_ms: u64,
    ) -> BoxFuture<'a, Result<(), SendError>> {
        Box::pin(async move {
            let mut one = self.record.clone();
            one["bytes"] = json!(String::from_utf8_lossy(frame));
            self.sent.lock().unwrap().push(one);
            Ok(())
        })
    }
    fn close(&mut self) {}
}

struct Syslog {
    sent: Sent,
}

impl SyslogTransport for Syslog {
    fn open<'a>(
        &'a self,
        transport: &'a str,
        ip: &'a str,
        port: u16,
        servername: Option<&'a str>,
        tls: Option<&'a TlsPolicy>,
        _timeout_ms: u64,
    ) -> BoxFuture<'a, Result<Box<dyn SyslogPipe>, SendError>> {
        Box::pin(async move {
            let mut record = json!({ "kind": transport, "host": ip,
                                     "port": port,
                                     "servername": servername.unwrap_or("") });
            if let Some(t) = tls {
                record["rejectUnauthorized"] = json!(t.reject_unauthorized);
            }
            Ok(Box::new(Pipe { sent: self.sent.clone(), record })
                as Box<dyn SyslogPipe>)
        })
    }
    fn send_udp<'a>(
        &'a self,
        message: &'a [u8],
        ip: &'a str,
        port: u16,
        _timeout_ms: u64,
    ) -> BoxFuture<'a, Result<(), SendError>> {
        Box::pin(async move {
            self.sent.lock().unwrap().push(json!({ "kind": "udp", "host": ip,
                "port": port, "bytes": String::from_utf8_lossy(message) }));
            Ok(())
        })
    }
}

struct RealFiles;

impl Files for RealFiles {
    fn open_append(&self, path: &str, mode: u32)
        -> Result<Box<dyn AppendFile>, String> {
        RealTransports.open_append(path, mode)
    }
    fn exists(&self, path: &str) -> bool {
        RealTransports.exists(path)
    }
    fn rename(&self, from: &str, to: &str) -> Result<(), String> {
        RealTransports.rename(from, to)
    }
}

fn swap(v: &Json, from: &str, to: &str) -> Json {
    serde_json::from_str(&v.to_string().replace(from, to)).unwrap()
}

fn sorted(items: &Json) -> Vec<String> {
    let mut out: Vec<String> = items
        .as_array()
        .unwrap()
        .iter()
        .map(|v| norm(v).to_string())
        .collect();
    out.sort();
    out
}

fn files_of(dir: &str) -> Json {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    names.sort();
    use std::os::unix::fs::PermissionsExt;
    Json::Array(
        names
            .iter()
            .map(|n| {
                let p = format!("{}/{}", dir, n);
                let mode = std::fs::metadata(&p).unwrap().permissions().mode()
                    & 0o777;
                json!({ "name": n, "mode": mode,
                        "text": std::fs::read_to_string(&p).unwrap() })
            })
            .collect(),
    )
}

/// Leaves the `udp` destination out of a syslog-scenario answer.
fn without_udp(v: &Json) -> Json {
    let mut v = v.clone();
    if let Some(c) = v.get_mut("cursors").and_then(Json::as_object_mut) {
        c.shift_remove("udp");
    }
    if let Some(r) = v.get_mut("recorded").and_then(Json::as_array_mut) {
        r.retain(|row| row["target"] != json!("udp"));
    }
    if let Some(s) = v.get_mut("sent").and_then(Json::as_array_mut) {
        s.retain(|one| one["kind"] != json!("udp"));
    }
    if let Some(d) = v.get_mut("destinations").and_then(Json::as_array_mut) {
        d.retain(|one| one["id"] != json!("udp"));
        v.as_object_mut().unwrap().shift_remove("stats");
    }
    v
}

#[tokio::test]
async fn export_vectors() {
    let Some(v) = vectors() else {
        eprintln!("STS_CRYPTO_VECTORS is not set: nothing to check");
        return;
    };
    let e = &v["export"];
    let node_work = e["work"].as_str().unwrap().to_string();
    let base = std::fs::canonicalize(std::env::var("STS_CRYPTO_VECTORS")
        .unwrap())
        .unwrap()
        .to_string_lossy()
        .to_string();
    let work = format!("{}/audit-export-rust", base);
    std::fs::remove_dir_all(&work).ok();
    std::fs::create_dir_all(&work).unwrap();
    for scenario in e["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let settings = Arc::new(Settings::new(Json::Null, HashMap::new()));
        for (k, val) in e["settings"].as_object().unwrap() {
            settings.set_override(k, val.clone()).unwrap();
        }
        let mode = Arc::new(Mode::new(settings.clone()));
        let clock = Arc::new(AtomicI64::new(v["t0"].as_i64().unwrap()));
        let sent: Sent = Arc::new(Mutex::new(Vec::new()));
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let book = Arc::new(Book { held: Mutex::new(Vec::new()),
                                   recorded: Mutex::new(Vec::new()) });
        let uuid = Arc::new(AtomicU64::new(0));
        let next_uuid = uuid.clone();
        let exporter = AuditExport::new(ExportPorts {
            settings: settings.clone(),
            mode: mode.clone(),
            outbound: Arc::new(Outbound::new(settings.clone(), mode.clone(),
                                             Arc::new(NoCaFiles))),
            clock: Arc::new(Frozen(clock.clone())),
            audit: book.clone(),
            maps: Arc::new(MemoryMaps::default()),
            dns: Arc::new(Dns(e["dns"].as_object().unwrap().clone())),
            http: Arc::new(Http { sent: sent.clone(), queue: queue.clone() }),
            syslog: Arc::new(Syslog { sent: sent.clone() }),
            files: Arc::new(RealFiles),
            secrets: Arc::new(NoSealing),
            uuid: Arc::new(move || {
                let n = next_uuid.fetch_add(1, Ordering::SeqCst) + 1;
                format!("00000000-0000-4000-8000-{:012}", n)
            }),
            hostname: v["hostname"].as_str().unwrap().to_string(),
            pid: v["pid"].as_u64().unwrap() as u32,
            user_agent: v["userAgent"].as_str().unwrap().to_string(),
            origin: Arc::new(String::new),
            realms: None,
        });
        let steps = scenario["steps"].as_array().unwrap();
        let answers = scenario["answers"].as_array().unwrap();
        for (i, (raw, want)) in steps.iter().zip(answers).enumerate() {
            let step = swap(raw, &node_work, &work);
            let want = swap(want, &node_work, &work);
            let what = format!("{} step {} {}", name, i, raw);
            let take = |list: &Mutex<Vec<Json>>| {
                Json::Array(std::mem::take(&mut *list.lock().unwrap()))
            };
            match step["do"].as_str().unwrap() {
                "act" => {
                    let got = exporter.act(&step["body"]).await;
                    same(&format!("{} result", what), &got.json,
                         &want["result"]);
                    assert_eq!(got.code, want["code"].as_str().unwrap(),
                               "{} code", what);
                    same(&format!("{} recorded", what),
                         &take(&book.recorded), &want["recorded"]);
                    same(&format!("{} sent", what), &take(&sent),
                         &want["sent"]);
                }
                "ring" => {
                    *book.held.lock().unwrap() =
                        step["rows"].as_array().unwrap().clone();
                }
                "answer" => {
                    for one in step["answers"].as_array().unwrap() {
                        queue.lock().unwrap().push_back(one.clone());
                    }
                }
                "now" => clock.store(step["at"].as_i64().unwrap(),
                                     Ordering::SeqCst),
                "set" => {
                    settings
                        .set_override(step["key"].as_str().unwrap(),
                                      step["value"].clone())
                        .unwrap();
                }
                "tick" => {
                    let ran = exporter.run_async(&|| true).await;
                    let got = json!({
                        "ran": ran,
                        "sent": take(&sent),
                        "recorded": take(&book.recorded),
                        "cursors": cursors_of(&exporter, &want),
                    });
                    let (g, w) = if name == "syslog" {
                        let udp: Vec<&Json> = got["sent"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .filter(|s| s["kind"] == json!("udp"))
                            .collect();
                        assert_eq!(udp.len(), 4, "Rust transmits UDP");
                        assert!(want["recorded"].to_string()
                                    .contains("setTimeout is not a function")
                                || want["cursors"]["udp"]["lastFailure"]
                                    .as_str()
                                    .unwrap_or("")
                                    .contains("setTimeout"),
                                "Node's UDP defect is as pinned");
                        (without_udp(&got), without_udp(&want))
                    } else {
                        (got, want.clone())
                    };
                    same(&format!("{} ran", what), &g["ran"], &w["ran"]);
                    assert_eq!(sorted(&g["sent"]), sorted(&w["sent"]),
                               "{} sent", what);
                    assert_eq!(sorted(&g["recorded"]), sorted(&w["recorded"]),
                               "{} recorded", what);
                    same(&format!("{} cursors", what), &g["cursors"],
                         &w["cursors"]);
                }
                "view" => {
                    let got = exporter.view();
                    let (g, w) = if name == "syslog" {
                        (without_udp(&got), without_udp(&want))
                    } else {
                        (got, want.clone())
                    };
                    same(&what, &g, &w);
                }
                // A rotated name carries the instant of the rotation:
                // Node's `new Date()`, the wall clock (the frozen clock is
                // `Date.now()` only), so the stamp is masked on both sides.
                "files" => same(&what, &stamped(&files_of(&work)),
                                &stamped(&want)),
                "screenHost" => {
                    let got = exporter
                        .screen_host(step["host"].as_str().unwrap(),
                                     step["atSend"].as_bool().unwrap())
                        .await;
                    same(&what, &got.json, &want);
                }
                "screenUrl" => {
                    let got = exporter
                        .screen_url(step["url"].as_str().unwrap(),
                                    step["atSend"].as_bool().unwrap())
                        .await;
                    same(&what, &got.json, &want);
                }
                other => panic!("no step {}", other),
            }
        }
        for spec in scenario["registered"].as_array().unwrap() {
            let mine = exporter.job_spec();
            assert_eq!(mine.id, spec["id"].as_str().unwrap());
            assert_eq!(mine.title, spec["title"].as_str().unwrap());
            assert_eq!(mine.describe, spec["describe"].as_str().unwrap());
            assert_eq!(mine.owner, spec["owner"].as_str().unwrap());
            assert_eq!(spec["kind"], json!("per-process"));
            assert_eq!(mine.kind, sts_cluster::schedule::Kind::PerProcess);
            assert_eq!(spec["scope"], json!("realm"));
            assert_eq!(mine.scope, sts_cluster::schedule::Scope::Realm);
            assert_eq!(mine.quiet, spec["quiet"].as_bool().unwrap());
            assert_eq!(mine.manual, spec["manual"].as_bool().unwrap());
            match &mine.schedule {
                sts_cluster::schedule::Schedule::EverySetting { key, unit } => {
                    assert_eq!(key, spec["everySetting"].as_str().unwrap());
                    assert_eq!(*unit, sts_cluster::schedule::Unit::S);
                }
                _ => panic!("the schedule"),
            }
            let timeout = mine.timeout_s.as_ref().unwrap()();
            assert_eq!(json!(timeout as i64), spec["timeoutS"]);
        }
        exporter.close_files();
        for entry in std::fs::read_dir(&work).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                std::fs::remove_dir_all(&p).unwrap();
            } else {
                std::fs::remove_file(&p).unwrap();
            }
        }
    }
    std::fs::remove_dir_all(&work).ok();
}

/// The stored cursors, read back through the page's own model.
fn cursors_of(exporter: &AuditExport, want: &Json) -> Json {
    let mut out = Map::new();
    for (id, _) in want["cursors"].as_object().cloned().unwrap_or_default() {
        if let Some(c) = exporter.stored_cursor(&id) {
            out.insert(id, c);
        }
    }
    Json::Object(out)
}

#[test]
fn export_statics() {
    let Some(v) = vectors() else {
        return;
    };
    let s = &v["export"]["statics"];
    for one in s["ackUrl"].as_array().unwrap() {
        assert_eq!(event::ack_url(one[0].as_str().unwrap()).unwrap(),
                   one[1].as_str().unwrap());
    }
    let now = v["t0"].as_i64().unwrap();
    for one in s["retryAfter"].as_array().unwrap() {
        same(&format!("retryAfter {}", one[0]),
             &json!(event::retry_after(one[0].as_str(), now)), &one[1]);
    }
    for one in s["parseMode"].as_array().unwrap() {
        assert_eq!(json!(event::parse_mode(Some(&one[0]))), one[1],
                   "parseMode {}", one[0]);
    }
    for one in s["safeWhy"].as_array().unwrap() {
        assert_eq!(event::safe_why(one[0].as_str().unwrap()),
                   one[1].as_str().unwrap());
    }
    for one in s["classify"].as_array().unwrap() {
        let p = &one[0];
        let posted = event::Posted {
            ok: false,
            status: p["status"].as_u64().unwrap() as u16,
            code: p["code"].as_str().unwrap_or("").to_string(),
            why: p["why"].as_str().unwrap_or("").to_string(),
            retry_after_ms: p["retryAfterMs"].as_f64().unwrap_or(0.0),
            json: p["json"].clone(),
        };
        let got = event::classify_http(&posted, one[1].as_bool().unwrap());
        same(&format!("classify {}", one[0]),
             &serde_json::to_value(&got).unwrap(), &one[2]);
    }
    let names = s["names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap().to_string())
        .collect();
    let opts = event::CanonicalOptions {
        realm: "default".into(),
        origin: String::new(),
        source: "ua".into(),
        names,
        now,
    };
    let rows = s["rows"].as_array().unwrap();
    for (row, want) in rows.iter().zip(s["events"].as_array().unwrap()) {
        let got = event::canonical(row, &opts);
        same("canonical", &got, want);
        assert_eq!(got.to_string(), want.to_string(),
                   "canonical, byte for byte");
    }
    let events = s["events"].as_array().unwrap();
    for (event_v, want) in events.iter().zip(s["template"].as_array().unwrap())
    {
        assert_eq!(event::fill_template("{id}|{message}|{x}|{{realm}}",
                                        event_v),
                   want.as_str().unwrap());
    }
    let host = v["hostname"].as_str().unwrap();
    let pid = v["pid"].as_u64().unwrap() as u32;
    for (event_v, one) in events.iter().zip(s["syslog"].as_array().unwrap()) {
        assert_eq!(event::syslog_line(event_v, &one[0], host, pid, now),
                   one[1].as_str().unwrap(), "syslog {}", one[0]);
    }
    for one in s["sdEscape"].as_array().unwrap() {
        let text = sts_audit_text(&one[0]);
        assert_eq!(event::sd_escape(&text), one[1].as_str().unwrap());
    }
    use sts_audit::export::address;
    for one in s["hosts"].as_array().unwrap() {
        let h = one[0].as_str().unwrap();
        assert_eq!(address::is_private(h), one[1].as_bool().unwrap(),
                   "isPrivate {}", h);
        assert_eq!(address::is_metadata(h), one[2].as_bool().unwrap(),
                   "isMetadata {}", h);
        let bare = address::bare_host(h);
        assert_eq!(address::is_ip(&bare), one[3].as_bool().unwrap(),
                   "isIp {}", h);
        assert_eq!(bare, one[4].as_str().unwrap());
    }
    for one in s["transport"].as_array().unwrap() {
        assert_eq!(event::transport_of(&one[0]), one[1].as_str().unwrap());
        assert_eq!(json!(event::port_of(&one[0])), one[2]);
    }
    let offs = &v["export"]["offs"];
    assert!(offs["noDestination"].is_string() && offs["off"].is_string());
}

fn stamped(v: &Json) -> Json {
    let re = regex::Regex::new(r"\.\d{4}-\d\d-\d\dT\d\d-\d\d-\d\d-\d{3}Z")
        .unwrap();
    serde_json::from_str(&re.replace_all(&v.to_string(), ".STAMP")).unwrap()
}

fn sts_audit_text(v: &Json) -> String {
    match v {
        Json::Null => String::new(),
        Json::String(s) => s.clone(),
        other => other.to_string(),
    }
}
