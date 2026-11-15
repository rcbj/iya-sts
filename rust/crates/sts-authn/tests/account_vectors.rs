// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Browsers' account sets (#561) against Node: `account-sets-node.json`,
//! which `tests/tools/account-set-vectors.js` records by driving Node's own
//! `Authn` with `authn.multipleAccounts` on, every port recorded. Each step
//! is replayed here, in order, against ONE Rust session service: the same
//! calls with the same arguments, the same answer, the same cookies and
//! locals, and the same three stores — the sessions, the account sets and
//! the tickets — row for row and in Node's member order.
//!
//! With `STS_WRITE_VECTORS=1` it also writes `account-sets-rust.json`:
//! browsers this runtime signed in, their cookies, their sets and the
//! sessions the sets list, which `tests/rust_crypto_vectors.js` hands to
//! Node's own `Authn` — a set this runtime writes is one Node honours.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed; unset, the test
//! says so and passes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod plain;
mod replay;

use std::collections::HashMap;
use std::sync::Arc;

use replay::{normal, Replay};
use serde_json::{json, Value};
use sts_authn::account_sets::AccountSets;
use sts_authn::js::Object;
use sts_authn::ports::{Request, Response};
use sts_authn::{RecordChange, Sessions, SessionsDeps};
use sts_core::mode::Mode;
use sts_core::realm::RealmRegistry;
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::StoreHandles;
use sts_core::settings::Settings as CoreSettings;

fn vectors() -> Option<(Value, std::path::PathBuf)> {
    let dir = std::env::var("STS_CRYPTO_VECTORS").ok()?;
    let dir = std::path::PathBuf::from(dir);
    let text =
        std::fs::read_to_string(dir.join("account-sets-node.json")).ok()?;
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

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|x| x.as_str().unwrap_or("").to_string())
                .collect()
        })
        .unwrap_or_default()
}

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

fn request(input: &Value) -> Request {
    let r = Request {
        cookie: input["cookie"].as_str().unwrap_or("").to_string(),
        user_agent: "Vectors/1.0".into(),
        url: input["url"].as_str().unwrap_or("/").to_string(),
        ..Request::default()
    };
    r.accounts.lock().response_open = input["open"] == json!(true);
    r
}

fn change(c: RecordChange) -> Value {
    match c {
        RecordChange::Keep => json!({"kind": "keep"}),
        RecordChange::Delete(id) => json!({"kind": "delete", "id": id}),
        RecordChange::Set(r) => json!({"kind": "set", "record": r}),
    }
}

fn run(step: &Value, s: &Sessions) -> (Value, Response) {
    let input = &step["input"];
    let mut response = Response::default();
    let text = |k: &str| input[k].as_str().unwrap_or("").to_string();
    let mut r = request(input);
    if input["hint"].is_object() && step["door"] != "accountTicketFor" {
        s.hint_account(&r, &input["hint"]);
    }
    let answer = match step["door"].as_str().unwrap() {
        "startSession" => {
            let mut detail: Object =
                input["detail"].as_object().cloned().unwrap_or_default();
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
        "sessionOf" => json!({"session": s.session_of(&r, false)}),
        "accountChoiceNeeded" => {
            json!({"need": s.account_choice_needed(&r)})
        }
        "hintAccountKey" => {
            s.hint_account_key(&r, &text("key"));
            json!({"session": s.session_of(&r, false)})
        }
        "accountTicketFor" => json!({"target": s.account_ticket_for(
            &r, &text("target"), &input["hint"])}),
        "spendThenSessionOf" => {
            s.spend_account_ticket(&mut r);
            json!({"url": r.url, "session": s.session_of(&r, false)})
        }
        "ticketedReturn" => {
            let res = Response {
                locals: input["locals"].as_object().cloned().unwrap(),
                ..Response::default()
            };
            json!({"target": s.ticketed_return(
                &res, &text("recordId"), &text("target"))})
        }
        "browserAccounts" => json!({"listed": s.browser_accounts(&r)}),
        "signedInAccounts" => {
            let ids: Vec<Value> = s
                .account_sessions_of(&r)
                .iter()
                .map(|x| x["id"].clone())
                .collect();
            json!({"accounts": s.signed_in_accounts(&r), "sessions": ids})
        }
        "auditActor" => json!({"actor": s.audit_actor_of(&r),
                               "sid": s.audit_actor_session_of(&r)}),
        "bindingSessionOf" => {
            let sid = text("sid");
            let found = s.binding_session_of(&r, &|x: &Value| x["id"] == sid);
            json!({"found": found, "names": s.session_cookie_names(&r, &sid)})
        }
        "noteAccountAmbiguous" => {
            s.note_account_ambiguous(&r, &text("via"), &text("answer"));
            json!({"noted": true})
        }
        "beginAccountChoice" => {
            let c = s
                .begin_account_choice(
                    Some(&r),
                    &text("accountChoice"),
                    input["hinted"] == json!(true),
                )
                .unwrap_or_default();
            json!({"choice": {"pick": c.pick, "hint": c.hint}})
        }
        "routeToAccounts" => {
            let existing = input["existing"].as_object().cloned();
            let (record, location) = s.route_to_accounts(
                existing,
                &input["opts"],
                &text("target"),
                &text("why"),
                Some(&r),
            );
            json!({"routed": {"record": record, "location": location}})
        }
        "accountsView" => {
            let base = step["answer"]["view"]["base"].as_str().unwrap_or("");
            json!({"view": s.accounts_view(&r, &input["record"], base)})
        }
        "accountsAct" => {
            let out = s.accounts_act(
                &r,
                &mut response,
                &input["record"],
                &input["body"],
                &|t: &str| t.to_string(),
            );
            json!({"outcome": {
                "answer": {"status": out.answer.status,
                           "body": out.answer.body,
                           "code": out.answer.code.unwrap_or(""),
                           "retryAfter": out.answer.retry_after},
                "record": change(out.record)}})
        }
        "endSession" => json!({"session": s.end_session_for(
            &r, &mut response, &text("sid"))}),
        "clearSiteData" => {
            json!({"cleared": s.clear_site_data_after_sign_out(&r)})
        }
        "refuseAccountsUnread" => {
            json!({"refused": s.refuse_accounts_unread(&r).is_some()})
        }
        "sweepAccountSets" => json!({"done": s.sweep_account_sets()}),
        "sweepAccountSetsBudgeted" => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            json!({"done": rt.block_on(s.sweep_account_sets_budgeted())})
        }
        other => panic!("no such door: {other}"),
    };
    for line in r.accounts.take_appended() {
        response.append_cookie(line);
    }
    (answer, response)
}

fn rows(entries: Vec<(String, Value)>) -> Vec<(String, String)> {
    entries
        .into_iter()
        .map(|(k, v)| (k, serde_json::to_string(&v).unwrap()))
        .collect()
}

fn compare(what: &str, rust: &[(String, String)], node: &Value) -> Vec<String> {
    let node: Vec<(String, String)> = node
        .as_object()
        .map(|o| {
            o.iter()
                .map(|(k, v)| (k.clone(), serde_json::to_string(v).unwrap()))
                .collect()
        })
        .unwrap_or_default();
    let mut out = Vec::new();
    if rust == node.as_slice() {
        return out;
    }
    for (i, (k, v)) in rust.iter().enumerate() {
        match node.get(i) {
            Some((nk, nv)) if nk == k && nv == v => {}
            Some((nk, nv)) => out.push(format!(
                "{what} row {i}:\n    Rust {k} {v}\n    Node {nk} {nv}"
            )),
            None => out.push(format!("{what}: Rust also holds {k} {v}")),
        }
    }
    if node.len() > rust.len() {
        out.push(format!(
            "{what}: Node holds {} rows, Rust {}: {:?}",
            node.len(),
            rust.len(),
            &node[rust.len()..]
        ));
    }
    out
}

#[test]
fn every_account_door_answers_as_node_does() {
    let Some((doc, _dir)) = vectors() else {
        eprintln!(
            "STS_CRYPTO_VECTORS unset or no account-sets-node.json: skipped"
        );
        return;
    };
    let replay = Arc::new(Replay::new(all_settings(&doc)));
    let sessions = service(&replay);
    let mut failures: Vec<String> = Vec::new();
    let steps = doc["steps"].as_array().unwrap();
    for step in steps {
        let name = step["name"].as_str().unwrap();
        replay.step(step);
        let (answer, response) = run(step, &sessions);
        let mut problems = replay.finish();
        if normal(&answer) != normal(&step["answer"]) {
            problems.push(format!(
                "answer:\n    Rust {}\n    Node {}",
                answer, step["answer"]
            ));
        }
        let cookies: Vec<Value> =
            response.cookies.iter().map(|c| json!(c)).collect();
        if Value::Array(cookies) != step["cookies"] {
            problems.push(format!(
                "cookies: Rust {:?}, Node {}",
                response.cookies, step["cookies"]
            ));
        }
        if Value::Object(response.locals.clone()) != step["locals"] {
            problems.push(format!(
                "locals: Rust {:?}, Node {}",
                response.locals, step["locals"]
            ));
        }
        problems.extend(compare(
            "sessions",
            &rows(sessions.store().entries()),
            &step["store"],
        ));
        problems.extend(compare(
            "sets",
            &rows(sessions.account_sets().store().entries()),
            &step["sets"],
        ));
        problems.extend(compare(
            "tickets",
            &rows(sessions.account_sets().ticket_store().entries()),
            &step["tickets"],
        ));
        if !problems.is_empty() {
            failures.push(format!("{name}:\n  {}", problems.join("\n  ")));
        }
    }
    failures.extend(pure(&doc));
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

fn pure(doc: &Value) -> Vec<String> {
    let mut failures = Vec::new();
    for (i, case) in doc["pure"].as_array().unwrap().iter().enumerate() {
        let args = &case["args"];
        let got = match case["fn"].as_str().unwrap() {
            "merge" => AccountSets::merge(&args[0], &args[1]),
            "stripTicket" => {
                let (url, ticket) =
                    AccountSets::strip_ticket(args[0].as_str().unwrap());
                json!({"url": url, "ticket": ticket})
            }
            "withTicket" => json!(AccountSets::with_ticket(
                args[0].as_str().unwrap(),
                args[1].as_str().unwrap()
            )),
            "keyOf" => json!(AccountSets::key_of(&args[0])),
            other => {
                failures.push(format!("pure {i}: no such function {other}"));
                continue;
            }
        };
        if serde_json::to_string(&got).unwrap()
            != serde_json::to_string(&case["answer"]).unwrap()
        {
            failures.push(format!(
                "pure {i} {} {}:\n    Rust {}\n    Node {}",
                case["fn"],
                case["name"].as_str().unwrap_or(""),
                got,
                case["answer"]
            ));
        }
    }
    failures
}

/// Browsers this runtime signs in, for Node to read back.
#[test]
fn rust_writes_account_sets_node_reads() {
    let Some((_, dir)) = vectors() else {
        eprintln!("STS_CRYPTO_VECTORS unset: skipped");
        return;
    };
    if std::env::var("STS_WRITE_VECTORS").is_err() {
        return;
    }
    let now = sts_core::time::now_ms_f64().floor();
    let p = plain::Plain::new(now, true);
    let (s, _) = plain::service(&p, &StoreHandles::new(), None);
    let mut out = Vec::new();
    let mut record = |name: &str, jar: &plain::Jar, s: &Sessions| {
        let r = jar.request();
        let set = s
            .account_sets()
            .set_of(&sts_authn::cookie::cookies_of(&r.cookie))
            .unwrap();
        let mut held = Object::new();
        for sid in set["sessions"].as_object().unwrap().keys() {
            held.insert(sid.clone(), s.session_by_id(sid).unwrap());
        }
        let accounts = s.browser_accounts(&r)["accounts"].clone();
        let acts = s
            .session_of(&jar.request(), false)
            .map(|x| x["id"].clone())
            .unwrap_or(json!(""));
        let set = s.account_sets().by_id(set["id"].as_str().unwrap()).unwrap();
        out.push(json!({"name": name, "now": *p.now.lock().unwrap(),
            "cookie": jar.header(), "set": set, "sessions": held,
            "accounts": accounts, "actsAs": acts}));
    };
    let mut one = plain::Jar::default();
    plain::sign_in(&s, &mut one, "dora").unwrap();
    record("one account", &one, &s);
    let mut two = plain::Jar::default();
    plain::sign_in(&s, &mut two, "emil").unwrap();
    *p.now.lock().unwrap() += 1000.0;
    plain::sign_in(&s, &mut two, "fay").unwrap();
    record("two accounts, nothing chooses", &two, &s);
    let mut r = two.request();
    let mut response = Response::default();
    let fay = s
        .session_of(
            &{
                let x = two.request();
                s.hint_account(&x, &json!({"loginHint": "fay"}));
                x
            },
            false,
        )
        .unwrap();
    s.end_session_for(&r, &mut response, fay["id"].as_str().unwrap());
    two.take(&response);
    r.cookie = two.header();
    record("one signed out, one left", &two, &s);
    std::fs::write(
        dir.join("account-sets-rust.json"),
        serde_json::to_string_pretty(&json!({"browsers": out})).unwrap(),
    )
    .unwrap();
}
