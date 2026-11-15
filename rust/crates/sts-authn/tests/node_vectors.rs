// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The session core against Node: `session-node.json`, which
//! `tests/tools/session-vectors.js` records by driving Node's own `Authn`
//! over recorded ports. Each step is replayed here, in order, against ONE
//! Rust session service, so the store a step leaves is the store the next
//! one starts from, exactly as in Node: Rust's doors are handed the answers
//! Node's ports gave, must make the same calls with the same arguments,
//! and must answer the same — the session, the door's detail with its
//! refusal code, the cookies, the response's locals — and leave the store
//! holding the same rows, member for member and in Node's order.
//!
//! With `STS_WRITE_VECTORS=1` it also writes `session-rust.json`: the
//! sessions Rust minted and the cookies naming them, which
//! `tests/rust_crypto_vectors.js` reads back through Node's `Authn` — a
//! session this runtime writes is one Node honours.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed; unset, the test
//! says so and passes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod replay;

use std::collections::HashMap;
use std::sync::Arc;

use replay::{normal, Replay};
use serde_json::{json, Value};
use sts_authn::js::Object;
use sts_authn::ports::{Request, Response};
use sts_authn::{cookie, merge, record, Sessions, SessionsDeps};
use sts_core::mode::Mode;
use sts_core::realm::RealmRegistry;
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::StoreHandles;
use sts_core::settings::Settings as CoreSettings;

fn vectors() -> Option<(Value, std::path::PathBuf)> {
    let dir = std::env::var("STS_CRYPTO_VECTORS").ok()?;
    let dir = std::path::PathBuf::from(dir);
    let text = std::fs::read_to_string(dir.join("session-node.json")).ok()?;
    // The generator's stdout may carry the service's log lines.
    let text: String = text
        .lines()
        .filter(|l| !l.starts_with("{\"name\""))
        .collect::<Vec<_>>()
        .join("\n");
    Some((serde_json::from_str(&text).ok()?, dir))
}

struct Env;

impl sts_core::realm::RealmEnvironment for Env {
    fn enabled(&self) -> bool {
        true
    }
    fn path_segment(&self) -> String {
        "realm".to_string()
    }
    fn global_domain(&self) -> String {
        "example.com".to_string()
    }
    fn reserved(&self) -> Vec<String> {
        Vec::new()
    }
    fn est_labels(&self) -> Vec<String> {
        Vec::new()
    }
}

fn service(replay: &Arc<Replay>) -> Sessions {
    let settings = Arc::new(CoreSettings::new(Value::Null, HashMap::new()));
    let registry = Arc::new(RealmRegistry::new(Arc::new(Env)));
    let lifecycle = RealmLifecycle::new(
        registry,
        settings.clone(),
        Arc::new(Mode::new(settings)),
    );
    let r = replay.clone();
    let sessions = Sessions::new(
        SessionsDeps {
            settings: r.clone(),
            mode: r.clone(),
            realms: r.clone(),
            people: r.clone(),
            accounts: r.clone(),
            policy: r.clone(),
            gate: r.clone(),
            credentials: r.clone(),
            devices: r.clone(),
            records: r.clone(),
            audit: r.clone(),
            binding: r.clone(),
            backchannel: Some(r.clone()),
            session_management: Some(r.clone()),
            risk: Some(r.clone()),
            claims: None,
            clock: r.clone(),
        },
        &lifecycle,
        &StoreHandles::new(),
    );
    sessions.set_session_observer(r);
    sessions
}

fn request(cookie: &str) -> Request {
    Request {
        cookie: cookie.to_string(),
        user_agent: "Vectors/1.0".into(),
        address: String::new(),
        device_fp: String::new(),
    }
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|x| x.as_str().unwrap_or("").to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Every setting any step was answered, the last answer kept.
fn all_settings(doc: &Value) -> HashMap<String, Value> {
    let mut out = HashMap::new();
    for step in doc["steps"].as_array().unwrap() {
        for c in step["calls"].as_array().unwrap() {
            if c["port"] == "settings" {
                out.insert(
                    c["args"][0].as_str().unwrap_or("").to_string(),
                    c["answer"].clone(),
                );
            }
        }
    }
    out
}

/// What a door answered and wrote, for comparison with the step.
struct Got {
    answer: Value,
    response: Response,
}

fn run(step: &Value, s: &Sessions) -> Got {
    let input = &step["input"];
    let mut response = Response::default();
    let text = |k: &str| input[k].as_str().unwrap_or("").to_string();
    let answer = match step["door"].as_str().unwrap() {
        "startSession" => {
            let mut detail: Object =
                input["detail"].as_object().cloned().unwrap_or_default();
            let r = request(&text("cookie"));
            let session = s.start_session(
                &mut response,
                &text("username"),
                &strings(&input["amr"]),
                &text("acr"),
                &text("via"),
                &mut detail,
                Some(&r),
            );
            json!({"session": session, "detail": detail})
        }
        "sessionOf" => {
            json!({"session": s.session_of(&request(&text("cookie")), false)})
        }
        "notePresented" => json!({"reported": s.note_presented(
            &text("sid"), &text("via"), None, &text("application"))}),
        "holdPresentation" => {
            s.hold_presentation(&text("sid"));
            json!({"held": true})
        }
        "backdate" => {
            s.backdate_authentication(
                &text("sid"),
                input["seconds"].as_f64().unwrap(),
            );
            json!({"authTime": s.session_by_id(&text("sid")).unwrap()["authTime"]})
        }
        "startArrivalSession" => json!({"session": s.start_arrival_session(
            &request(&text("cookie")), &mut response, &text("via"))}),
        "sweep" => json!({"ended": s.sweep_expired_sessions()}),
        "noteSessionChanged" => {
            let now = step["now"].clone();
            let sid = text("sid");
            let sub = s.session_by_id(&sid).unwrap()["user"]["sub"].clone();
            let changed = s.note_session_changed(&sid, |row| {
                row.insert(
                    "oidcClients".into(),
                    json!({"client-a": {"first": now, "last": now,
                        "count": 1, "iss": "https://as.example",
                        "sub": sub}}),
                );
            });
            json!({"changed": changed})
        }
        "endSession" => json!({"session": s.end_session(
            &request(&text("cookie")), &mut response)}),
        "endSessionById" => json!({"session": s.end_session_by_id(
            &text("sid"), &text("via"), &text("initiatingEntity"))}),
        other => panic!("no such door: {other}"),
    };
    Got { answer, response }
}

/// The store a step left, row by row, as JSON text in member order.
fn store_text(s: &Sessions) -> Vec<(String, String)> {
    s.store()
        .entries()
        .into_iter()
        .map(|(k, v)| (k, serde_json::to_string(&v).unwrap()))
        .collect()
}

#[test]
fn every_door_answers_as_node_does() {
    let Some((doc, dir)) = vectors() else {
        eprintln!("STS_CRYPTO_VECTORS unset or no session-node.json: skipped");
        return;
    };
    let replay = Arc::new(Replay::new(all_settings(&doc)));
    let sessions = service(&replay);
    let mut failures: Vec<String> = Vec::new();
    let mut minted: Vec<Value> = Vec::new();
    let steps = doc["steps"].as_array().unwrap();
    for step in steps {
        let name = step["name"].as_str().unwrap();
        replay.step(step);
        let got = run(step, &sessions);
        let mut problems = replay.finish();
        if normal(&got.answer) != normal(&step["answer"]) {
            problems.push(format!(
                "answer:\n    Rust {}\n    Node {}",
                got.answer, step["answer"]
            ));
        }
        let cookies: Vec<Value> =
            got.response.cookies.iter().map(|c| json!(c)).collect();
        if Value::Array(cookies) != step["cookies"] {
            problems.push(format!(
                "cookies: Rust {:?}, Node {}",
                got.response.cookies, step["cookies"]
            ));
        }
        if Value::Object(got.response.locals.clone()) != step["locals"] {
            problems.push(format!(
                "locals: Rust {:?}, Node {}",
                got.response.locals, step["locals"]
            ));
        }
        let node_store: Vec<(String, String)> = step["store"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::to_string(v).unwrap()))
            .collect();
        let rust_store = store_text(&sessions);
        if rust_store != node_store {
            for (i, (k, v)) in rust_store.iter().enumerate() {
                match node_store.get(i) {
                    Some((nk, nv)) if nk == k && nv == v => {}
                    Some((nk, nv)) => problems.push(format!(
                        "store row {i}:\n    Rust {k} {v}\n    Node {nk} {nv}"
                    )),
                    None => {
                        problems.push(format!("store: Rust also holds {k}"))
                    }
                }
            }
            if node_store.len() > rust_store.len() {
                problems.push(format!(
                    "store: Node holds {} rows, Rust {}",
                    node_store.len(),
                    rust_store.len()
                ));
            }
        }
        if !problems.is_empty() {
            failures.push(format!("{name}:\n  {}", problems.join("\n  ")));
        }
        if step["door"] == "startSession"
            || step["door"] == "startArrivalSession"
        {
            if let (Some(line), Some(session)) = (
                got.response.cookies.first(),
                got.answer["session"].as_object(),
            ) {
                let value = line.split(';').next().unwrap_or("");
                let value = value.trim_start_matches("sts_session=");
                minted.push(json!({"name": name, "cookie": value,
                    "now": step["now"], "session": session}));
            }
        }
    }
    failures.extend(pure(&doc, &replay));
    if std::env::var("STS_WRITE_VECTORS").is_ok() {
        std::fs::write(
            dir.join("session-rust.json"),
            serde_json::to_string_pretty(&json!({"sessions": minted})).unwrap(),
        )
        .unwrap();
    }
    assert!(
        failures.is_empty(),
        "{} of {} checks differ from Node:\n{}",
        failures.len(),
        steps.len() + doc["pure"].as_array().unwrap().len(),
        failures.join("\n")
    );
    eprintln!(
        "{} steps and {} pure cases agree with Node",
        steps.len(),
        doc["pure"].as_array().unwrap().len()
    );
}

/// The pure functions: the merge, the cookie parser, the phrases, the
/// clocks, the subject, the policy question and the cookie clearing.
fn pure(doc: &Value, replay: &Arc<Replay>) -> Vec<String> {
    let mut failures = Vec::new();
    let last_now = doc["steps"]
        .as_array()
        .unwrap()
        .last()
        .map(|s| s["now"].clone())
        .unwrap_or(json!(0));
    for (i, case) in doc["pure"].as_array().unwrap().iter().enumerate() {
        let args = &case["args"];
        let got: Value = match case["fn"].as_str().unwrap() {
            "mergeSessionRows" => merge::merge_session_rows(
                &args[0],
                &args[1],
                last_now.as_f64().unwrap(),
            ),
            "cookiesOf" => {
                match cookie::cookies_of(args[0].as_str().unwrap()) {
                    Ok(o) => Value::Object(o),
                    Err(e) => json!({"threw": e}),
                }
            }
            "methodPhraseFor" => {
                json!(record::method_phrase_for(&strings(&args[0])))
            }
            "sessionEnded" => {
                replay.step(&json!({"calls": [], "now": last_now}));
                let s = service(replay);
                json!(s.session_ended(
                    Some(&args[0]).filter(|v| !v.is_null()),
                    args[1].as_f64().unwrap()
                ))
            }
            "subjectIdOf" => json!(record::subject_id_of(
                Some(&args[0]).filter(|v| !v.is_null())
            )),
            "authnPolicyRefusal" => {
                replay.step(&json!({"calls": case["calls"], "now": last_now}));
                let s = service(replay);
                let answer = s.authn_policy_refusal(
                    &strings(&args[0]),
                    Some(&json!({"kind": args[1]})),
                );
                let problems = replay.finish();
                if !problems.is_empty() {
                    failures.push(format!(
                        "pure {i} authnPolicyRefusal: {}",
                        problems.join("; ")
                    ));
                }
                json!(answer)
            }
            "clearSessionCookie" => {
                let https = case["https"] == json!(true);
                let calls = json!([
                    {"port": "settings", "method": "value",
                     "args": ["global.https"], "answer": https},
                    {"port": "helpers", "method": "cookieDomainAttribute",
                     "args": [], "answer": ""},
                    {"port": "sessionManagement", "method": "enabled",
                     "args": [], "answer": false},
                ]);
                replay.step(&json!({"calls": calls, "now": last_now}));
                let s = service(replay);
                let mut r = Response::default();
                s.clear_session_cookie(&mut r, "");
                if !https {
                    s.clear_session_cookie(&mut r, "sts_portal");
                }
                json!(r.cookies)
            }
            other => {
                failures.push(format!("pure {i}: no such function {other}"));
                continue;
            }
        };
        if got != case["answer"] {
            failures.push(format!(
                "pure {i} {} {}:\n    Rust {}\n    Node {}",
                case["fn"],
                case["name"].as_str().unwrap_or(""),
                got,
                case["answer"]
            ));
        } else if case["fn"] == "mergeSessionRows"
            && serde_json::to_string(&got).unwrap()
                != serde_json::to_string(&case["answer"]).unwrap()
        {
            failures.push(format!(
                "pure {i} mergeSessionRows {}: the members' order differs",
                case["name"].as_str().unwrap_or("")
            ));
        }
    }
    failures
}
