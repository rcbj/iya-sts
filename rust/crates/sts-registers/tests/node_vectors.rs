// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The registers against Node: `registers-node.json`, which
//! `tests/tools/registers-vectors.js` records by driving Node's own
//! registers over its in-memory directory. Each step is replayed here
//! (`replay/mod.rs`): Rust's register is handed the answers Node's ports
//! gave, must make the same port calls with the same arguments, and must
//! give the same answer, sentence for sentence, and the same code.
//!
//! With `STS_WRITE_VECTORS=1` the test also writes `registers-rust.json`:
//! the role and group entries Rust wrote, which `tests/rust_crypto_vectors.js`
//! reads back through Node's registers.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed; unset, the test
//! says so and passes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod replay;

use std::sync::Arc;

use replay::{code_text, Replay};
use serde_json::{json, Value};
use sts_registers::outcome::Outcome;
use sts_registers::roles::{self, Roles, Who};

fn vectors() -> Option<Value> {
    let dir = std::env::var("STS_CRYPTO_VECTORS").ok()?;
    let path = std::path::Path::new(&dir).join("registers-node.json");
    let text = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&text).ok()
}

/// What one register answered, for comparison with the step.
struct Got {
    answer: Value,
    code: Value,
}

fn got(outcome: Outcome) -> Got {
    Got {
        answer: outcome.answer,
        code: code_text(outcome.code),
    }
}

fn plain(answer: Value) -> Got {
    Got {
        answer,
        code: Value::Null,
    }
}

fn roles_over(replay: &Arc<Replay>) -> Roles {
    Roles::new(Some(replay.clone()), replay.clone())
}

/// The roles register's steps.
fn run_roles(step: &Value, replay: &Arc<Replay>) -> Option<Got> {
    let input = &step["input"];
    let r = roles_over(replay);
    let name = input["name"].as_str().unwrap_or("");
    Some(match step["op"].as_str()? {
        "checkName" => plain(json!({"problem": roles::check_name(name)})),
        "write" => got(r.write(name, &input["record"])),
        "read" => plain(json!(r.read(name))),
        "all" => plain(json!(r.all())),
        "catalogue" => plain(json!(r.catalogue())),
        "addOwner" => {
            got(r.add_owner(name, input["owner"].as_str().unwrap_or("")))
        }
        "removeOwner" => {
            got(r.remove_owner(name, input["owner"].as_str().unwrap_or("")))
        }
        "setOwnerProtected" => got(r.set_owner_protected(
            name,
            input["flag"] == json!(true),
        )),
        "seedNativeRoles" => plain(json!({"made": r.seed_native_roles()})),
        "rolesAuthorizing" => plain(json!(r.roles_authorizing(
            input["permission"].as_str().unwrap_or("")
        ))),
        "conferredBy" => plain(json!(
            r.conferred_by(input["clientId"].as_str().unwrap_or(""))
        )),
        "rolesOf" => plain(json!(r.roles_of(&Who::from_json(&input["who"])))),
        "claimFor" => plain(json!(r.claim_for(&Who::from_json(&input["who"])))),
        "rolesInClaims" => plain(json!(r.roles_in_claims(&input["claims"]))),
        _ => return None,
    })
}

#[test]
fn every_register_answers_as_node_does() {
    let Some(v) = vectors() else {
        eprintln!(
            "registers-node.json not found (STS_CRYPTO_VECTORS unset): \
             nothing to check"
        );
        return;
    };
    let steps = v["steps"].as_array().unwrap();
    let mut failures: Vec<String> = Vec::new();
    let mut checked = 0;
    let mut skipped = std::collections::BTreeMap::<String, usize>::new();
    for (i, step) in steps.iter().enumerate() {
        let register = step["register"].as_str().unwrap_or("");
        let replay = Arc::new(Replay::new(step, &[]));
        let answer = match register {
            "roles" => run_roles(step, &replay),
            _ => None,
        };
        let Some(answer) = answer else {
            *skipped.entry(register.to_string()).or_default() += 1;
            continue;
        };
        checked += 1;
        let mut wrong = replay.finish();
        if answer.answer != step["answer"] {
            wrong.push(format!(
                "answer\n     rust {}\n     node {}",
                answer.answer, step["answer"]
            ));
        }
        if answer.code != step["code"] {
            wrong.push(format!(
                "code rust {} node {}",
                answer.code, step["code"]
            ));
        }
        if !wrong.is_empty() {
            failures.push(format!(
                "step {i} {register}.{} {}:\n   {}",
                step["op"].as_str().unwrap_or(""),
                step["input"],
                wrong.join("\n   ")
            ));
        }
    }
    eprintln!("{checked} steps checked; not ported here: {skipped:?}");
    assert!(
        failures.is_empty(),
        "{} of {checked} steps differ from Node:\n{}",
        failures.len(),
        failures
            .iter()
            .take(25)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
