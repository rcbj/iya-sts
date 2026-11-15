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
use sts_registers::app_permissions::AppPermissions;
use sts_registers::group_claims::GroupClaims;
use sts_registers::outcome::Outcome;
use sts_registers::ownership::{Ownership, OwnershipDeps};
use sts_registers::people::{AccountChange, AccountState, People, PeopleDeps};
use sts_registers::rbac::Rbac;
use sts_registers::role_actions::RoleActions;
use sts_registers::role_permissions::{
    RolePermissions, RolePermissionsDeps, Subject,
};
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

fn accounts_over(replay: &Arc<Replay>) -> AccountState {
    AccountState::new(
        replay.clone(),
        replay.clone(),
        Some(replay.clone()),
        replay.clone(),
        replay.clone(),
    )
}

fn people_over(replay: &Arc<Replay>) -> People {
    People::new(
        PeopleDeps {
            people: Some(replay.clone()),
            groups: Some(replay.clone()),
            credentials: replay.clone(),
            service_accounts: replay.clone(),
            signals: replay.clone(),
            mailer: replay.clone(),
            mode: replay.clone(),
            audit: replay.clone(),
        },
        Arc::new(accounts_over(replay)),
    )
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
        "setOwnerProtected" => {
            got(r.set_owner_protected(name, input["flag"] == json!(true)))
        }
        "seedNativeRoles" => plain(json!({"made": r.seed_native_roles()})),
        "rolesAuthorizing" => plain(json!(
            r.roles_authorizing(input["permission"].as_str().unwrap_or(""))
        )),
        "conferredBy" => plain(json!(
            r.conferred_by(input["clientId"].as_str().unwrap_or(""))
        )),
        "rolesOf" => plain(json!(r.roles_of(&Who::from_json(&input["who"])))),
        "claimFor" => plain(json!(r.claim_for(&Who::from_json(&input["who"])))),
        "rolesInClaims" => plain(json!(r.roles_in_claims(&input["claims"]))),
        _ => return None,
    })
}

/// THE PINNED DISAGREEMENTS.
///
/// `users/create`'s answer carries `entry`, and in Node that is the LIVE
/// directory entry object, which the credential step then writes on — so
/// Node's answer shows the `userPassword` hash, `pwdChangedTime` and the
/// activation token's hash set after the create (a Node defect: a
/// credential hash in an `/admin-api` answer). Rust answers the entry as
/// the directory's writer returned it, which must be the entry Node's
/// writer returned before the credential step; the rest of the answer is
/// compared whole.
fn pinned(register: &str, step: &Value, mut mine: Value) -> (Value, Value) {
    let mut theirs = step["answer"].clone();
    let create = register == "users"
        && step["input"]["body"]["action"] == json!("create");
    if create {
        if let (Some(m), Some(t)) =
            (mine.as_object_mut(), theirs.as_object_mut())
        {
            m.remove("entry");
            t.remove("entry");
        }
    }
    (mine, theirs)
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
    let mut written: Vec<Value> = Vec::new();
    for (i, step) in steps.iter().enumerate() {
        let register = step["register"].as_str().unwrap_or("");
        // The application register's pure helpers are ported into the
        // crate (app_permissions.rs), so Node's calls of them are not owed.
        let replay = Arc::new(Replay::new(
            step,
            &[
                "applications.permissionBaseOf",
                "applications.permissionsOf",
                "applications.permissionValueOf",
            ],
        ));
        let answer = match register {
            "roles" => run_roles(step, &replay),
            "roleActions" => {
                let actions = RoleActions::new(
                    Arc::new(roles_over(&replay)),
                    replay.clone(),
                    replay.clone(),
                );
                Some(got(actions.act(&step["input"]["body"], "vectors")))
            }
            "accountState" => {
                let accounts = accounts_over(&replay);
                let input = &step["input"];
                let who = input["who"].as_str().unwrap_or("");
                Some(match step["op"].as_str().unwrap_or("") {
                    "isDisabled" => {
                        plain(json!({"disabled": accounts.is_disabled(who)}))
                    }
                    _ => got(accounts.set_disabled(
                        who,
                        input["disabled"] == json!(true),
                        &AccountChange::from_json(&input["opts"]),
                    )),
                })
            }
            "users" => people_over(&replay)
                .users(&step["input"]["body"], "api", "vectors")
                .map(got),
            "groups" => {
                Some(got(people_over(&replay)
                    .groups(&step["input"]["body"], "vectors")))
            }
            "groupClaims" => {
                let gc = GroupClaims::new(
                    Some(replay.clone()),
                    replay.clone(),
                    replay.clone(),
                    replay.clone(),
                );
                let input = &step["input"];
                let text =
                    |k: &str| input[k].as_str().unwrap_or("").to_string();
                Some(match step["op"].as_str().unwrap_or("") {
                    "groupsOf" => {
                        got(gc.groups_of(&text("username"), &text("app")))
                    }
                    "jwtClaimsFor" => plain(
                        gc.jwt_claims_for(&text("set"), &input["context"]),
                    ),
                    "samlAttributesFor" => plain(json!(
                        gc.saml_attributes_for(&text("set"), &input["context"])
                    )),
                    _ => plain(gc.state()),
                })
            }
            "ownership" => {
                let o = Ownership::new(OwnershipDeps {
                    settings: replay.clone(),
                    directory: replay.clone(),
                    roles: Arc::new(roles_over(&replay)),
                    applications: replay.clone(),
                    service_accounts: replay.clone(),
                    scope_policy: replay.clone(),
                });
                let input = &step["input"];
                let text =
                    |k: &str| input[k].as_str().unwrap_or("").to_string();
                Some(match step["op"].as_str().unwrap_or("") {
                    "identityOf" => plain(o.identity_of(&text("username"))),
                    "ownsAnything" => plain(
                        json!({"owns": o.owns_anything(&text("username"))}),
                    ),
                    "objectOf" => {
                        plain(o.object_of(&text("kind"), &text("name")))
                    }
                    "owns" => plain(json!({"owns": o.owns(
                        &text("username"), &text("kind"), &text("name"))})),
                    _ => got(o.set_protected(
                        &text("kind"),
                        &text("name"),
                        &input["flag"],
                        &json!({"actor": "vectors"}),
                    )),
                })
            }
            "appPermissions" => {
                let p = AppPermissions::new(replay.clone());
                let input = &step["input"];
                let arg = |i: usize| {
                    input["args"][i].as_str().unwrap_or("").to_string()
                };
                Some(match step["op"].as_str().unwrap_or("") {
                    "register" => plain(p.register()),
                    "forApplication" => plain(p.for_application(
                        input["identifier"].as_str().unwrap_or(""),
                    )),
                    "definePermission" => got(p.define_permission(
                        &arg(0),
                        &arg(1),
                        &arg(2),
                        &arg(3),
                    )),
                    "removePermission" => {
                        got(p.remove_permission(&arg(0), &arg(1), &arg(2)))
                    }
                    "grant" => got(p.grant(&arg(0), &arg(1), &arg(2))),
                    "revoke" => got(p.revoke(&arg(0), &arg(1), &arg(2))),
                    _ => got(p.set_base_uri(&arg(0), &arg(1), &arg(2))),
                })
            }
            "rolePermissions" => {
                let rp = RolePermissions::new(RolePermissionsDeps {
                    roles: Arc::new(roles_over(&replay)),
                    applications: replay.clone(),
                    audit: replay.clone(),
                    roster: replay.clone(),
                    ownership: replay.clone(),
                    gate: replay.clone(),
                    subjects: replay.clone(),
                    mode: replay.clone(),
                });
                let input = &step["input"];
                let text =
                    |k: &str| input[k].as_str().unwrap_or("").to_string();
                let who = Subject::from_json(&input["subject"]);
                Some(plain(match step["op"].as_str().unwrap_or("") {
                    "isGated" => json!({"gated": rp.is_gated(&text("value")),
                        "application": rp.is_application_permission(&text("value"))}),
                    "heldRoles" => rp.held_roles(&who).to_json(),
                    "asksFor" => {
                        json!({"asks": rp.asks_for(&text("scope"), &who)})
                    }
                    "conferredOn" => {
                        json!(rp.conferred_on(&who, &text("clientId")))
                    }
                    "narrowScope" => {
                        rp.narrow_scope(&text("scope"), &who, &input["context"])
                    }
                    _ => {
                        let carried: Vec<String> = input["carried"]
                            .as_array()
                            .map(|l| {
                                l.iter()
                                    .map(|v| {
                                        v.as_str().unwrap_or("").to_string()
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        rp.effective_roles(&input["claims"], &carried)
                    }
                }))
            }
            "permissionActions" => {
                Some(got(AppPermissions::new(replay.clone())
                    .act(&step["input"]["body"], "vectors")))
            }
            "rbac" => {
                let rbac = Rbac::new(
                    Some(replay.clone()),
                    replay.clone(),
                    replay.clone(),
                    replay.clone(),
                    replay.clone(),
                );
                Some(got(rbac.act(&step["input"]["body"], "api", "vectors")))
            }
            _ => None,
        };
        let Some(answer) = answer else {
            *skipped.entry(register.to_string()).or_default() += 1;
            continue;
        };
        checked += 1;
        written.extend(replay.written.lock().unwrap().drain(..));
        let mut wrong = replay.finish();
        let (mine, theirs) = pinned(register, step, answer.answer.clone());
        if mine != theirs {
            if let Ok(dir) = std::env::var("STS_REGISTERS_DIFF") {
                let at = std::path::Path::new(&dir);
                std::fs::write(
                    at.join(format!("{i}-rust.json")),
                    mine.to_string(),
                )
                .unwrap();
                std::fs::write(
                    at.join(format!("{i}-node.json")),
                    theirs.to_string(),
                )
                .unwrap();
            }
            wrong.push(format!(
                "answer\n     rust {}\n     node {}",
                mine, theirs
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
    if std::env::var("STS_WRITE_VECTORS").is_ok_and(|v| v == "1") {
        write_rust_vectors(&written);
    }
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

/// One role entry as the directory would hand it back: Rust's write.
struct OneRole(Value);

impl sts_registers::port::RoleDirectory for OneRole {
    fn all_roles(&self) -> Vec<Value> {
        vec![self.0.clone()]
    }
    fn write_role(&self, _: &str, _: &Value) -> sts_registers::port::Marked {
        sts_registers::port::Marked::plain(json!(true))
    }
    fn delete_role(&self, _: &str) -> bool {
        false
    }
    fn resolve_owner(&self, _: &str) -> Value {
        json!({"kind": "", "dn": "", "name": ""})
    }
    fn groups_of_user(&self, _: &str) -> Vec<String> {
        Vec::new()
    }
    fn ensure_group(&self, _: &str, _: &Value) -> Value {
        json!({"ok": true})
    }
}

/// Settings for the read-back: the console groups Node's run held.
struct FixedSettings;

impl sts_registers::port::Settings for FixedSettings {
    fn value(&self, key: &str) -> Value {
        match key {
            "admin.readGroup" => json!("admin-read"),
            "admin.writeGroup" => json!("admin-write"),
            "admin.securityGroup" => json!("security-admin"),
            _ => Value::Null,
        }
    }
}

/// `registers-rust.json`: every role entry Rust wrote, and the row Rust
/// reads back from it, for `tests/rust_crypto_vectors.js` to read with
/// Node's `roles.read()`.
fn write_rust_vectors(written: &[Value]) {
    let dir = std::env::var("STS_CRYPTO_VECTORS").unwrap();
    let mut roles_out = Vec::new();
    for one in written {
        let name = one["name"].as_str().unwrap_or("").to_string();
        let entry = json!({"name": name,
            "dn": format!("cn={name},ou=roles,dc=example,dc=com"),
            "attributes": one["attributes"]});
        let r = Roles::new(
            Some(Arc::new(OneRole(entry.clone()))),
            Arc::new(FixedSettings),
        );
        roles_out.push(json!({"entry": entry, "row": r.read(&name)}));
    }
    let path = std::path::Path::new(&dir).join("registers-rust.json");
    std::fs::write(path, json!({"roles": roles_out}).to_string()).unwrap();
}
