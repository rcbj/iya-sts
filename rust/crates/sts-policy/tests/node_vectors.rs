// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The named policies against Node as it is now: `policy-node.json`, which
//! `tests/tools/policy-vectors.js` writes over Node's own in-memory
//! directory (`STS_ONLY=policy node tests/tools/crypto-vectors.js`, in the
//! tests image). Held to it:
//!
//! * every PolicySelection answer — the ranking, the checks and their
//!   sentences — is Node's;
//! * the kinds' list, its actions and the unknown-action refusal are
//!   Node's;
//! * every case — a kind's read, selection, save, refusal, reset or act, in
//!   the default realm or `acme` — answers what Node answered, with Node's
//!   error code, ASKING only what Node asked: each port is answered from
//!   the case's tape, and a question Node never asked fails the case; and
//!   every write and delete the kind makes is the one Node made, attribute
//!   for attribute, answered as Node's directory answered it.
//!
//! With `STS_WRITE_VECTORS=1` it writes what this crate answered, and
//! passwords it generated, as `policy-rust.json`, which
//! `tests/rust_crypto_vectors.js` holds to Node. The directory is
//! `STS_CRYPTO_VECTORS`, never committed; with it unset this test says so
//! and passes.

#![allow(clippy::unwrap_used, clippy::expect_used)] // a test file

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::Path;

use serde_json::{json, Map, Value};
use sts_policy::js::Object;
use sts_policy::kinds::attributes::{AttributePolicy, Subject};
use sts_policy::kinds::authn::AuthnPolicy;
use sts_policy::kinds::locale::LocalePolicy;
use sts_policy::kinds::passkey::PasskeyPolicy;
use sts_policy::kinds::password::PasswordPolicy;
use sts_policy::kinds::post_login::PostLoginPolicy;
use sts_policy::kinds::service_account::ServiceAccountPolicy;
use sts_policy::ports::{
    ApplicationRegister, Container, GroupReference, OfferedRow, PeopleNaming,
    PolicyDirectory, PolicyEntry, PolicyEnvironment, Ports, RealmFacts,
    RegistrationRows, WriteOutcome,
};
use sts_policy::selection::{self, Holders, Reference, SelectionSpec};
use sts_policy::{registry, Answer};

/// One case's recorded world, answering every port from the tape.
struct Tape {
    map: HashMap<String, Value>,
    node_mutations: Vec<Value>,
    gen: Cell<i64>,
    mutations: RefCell<Vec<Value>>,
    misses: RefCell<Vec<String>>,
    vocabularies: (Vec<String>, Vec<String>),
}

fn key(parts: Vec<Value>) -> String {
    serde_json::to_string(&Value::Array(parts)).unwrap()
}

fn s(v: &str) -> Value {
    Value::String(v.to_string())
}

impl Tape {
    fn new(case: &Value, vocabularies: (Vec<String>, Vec<String>)) -> Tape {
        Tape {
            map: case["tape"]
                .as_object()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .collect(),
            node_mutations: case["mutations"]
                .as_array()
                .cloned()
                .unwrap_or_default(),
            gen: Cell::new(0),
            mutations: RefCell::new(Vec::new()),
            misses: RefCell::new(Vec::new()),
            vocabularies,
        }
    }

    fn get(&self, parts: Vec<Value>) -> Option<Value> {
        let k = key(parts);
        match self.map.get(&k) {
            Some(v) => Some(v.clone()),
            None => {
                self.misses.borrow_mut().push(k);
                None
            }
        }
    }

    // The entries a hook answered at this generation — or, where Node did
    // not ask at it, at the nearest generation no mutation of the same
    // container and realm separates from it (Node's `haveDirectory()` asks
    // no hook, where the port's `entries()` is also that question).
    fn entries_at(&self, realm: &str, hook: &str) -> Option<Value> {
        let g = self.gen.get();
        let at = |n: i64| {
            self.map
                .get(&key(vec![s("hook"), json!(n), s(realm), s(hook)]))
        };
        if let Some(v) = at(g) {
            return Some(v.clone());
        }
        let touched = |n: i64| {
            self.node_mutations.get(n as usize).is_some_and(|m| {
                m["realm"] == s(realm)
                    && hook_container(&m["hook"]) == hook_container(&s(hook))
            })
        };
        let mut h = g - 1;
        while h >= 0 && !touched(h) {
            if let Some(v) = at(h) {
                return Some(v.clone());
            }
            h -= 1;
        }
        let mut h = g;
        while (h as usize) < self.node_mutations.len() + 1 && !touched(h) {
            if let Some(v) = at(h + 1) {
                return Some(v.clone());
            }
            h += 1;
        }
        self.misses
            .borrow_mut()
            .push(format!("entries {realm} {hook} gen {g}"));
        None
    }
}

fn hook_container(hook: &Value) -> String {
    let h = hook.as_str().unwrap_or("");
    h.trim_start_matches("all")
        .trim_start_matches("write")
        .trim_start_matches("delete")
        .to_string()
}

fn entry_of(v: &Value) -> PolicyEntry {
    PolicyEntry {
        name: v["name"].as_str().unwrap_or("").to_string(),
        dn: v["dn"].as_str().unwrap_or("").to_string(),
        attributes: v["attributes"].as_object().cloned().unwrap_or_default(),
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

fn groups(v: &Value) -> Vec<GroupReference> {
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|g| GroupReference {
                    cn: g["cn"].as_str().unwrap_or("").to_string(),
                    dn: g["dn"].as_str().unwrap_or("").to_string(),
                    value: g["value"].as_str().unwrap_or("").to_string(),
                })
                .collect()
        })
        .unwrap_or_default()
}

impl PolicyDirectory for Tape {
    fn installed(&self, _container: Container) -> bool {
        true
    }

    fn entries(
        &self,
        realm: &str,
        container: Container,
    ) -> Option<Vec<PolicyEntry>> {
        let v = self
            .entries_at(realm, container.hooks()[0])
            .unwrap_or(json!([]));
        Some(
            v.as_array()
                .map(|a| a.iter().map(entry_of).collect())
                .unwrap_or_default(),
        )
    }

    fn write(
        &self,
        realm: &str,
        container: Container,
        name: &str,
        attributes: &Object,
    ) -> WriteOutcome {
        let n = self.mutations.borrow().len();
        self.mutations.borrow_mut().push(json!({
            "hook": container.hooks()[1], "realm": realm, "name": name,
            "attributes": Value::Object(attributes.clone()) }));
        self.gen.set(self.gen.get() + 1);
        match self.node_mutations.get(n).map(|m| &m["outcome"]) {
            Some(Value::Bool(true)) => WriteOutcome::Written,
            Some(Value::Object(o))
                if o.get("ok") == Some(&Value::Bool(false)) =>
            {
                WriteOutcome::Refused {
                    nul: o.get("reason") == Some(&s("nul")),
                    errors: strings(o.get("errors").unwrap_or(&json!([]))),
                }
            }
            Some(Value::Object(_)) => WriteOutcome::Written,
            _ => WriteOutcome::Full,
        }
    }

    fn delete(&self, realm: &str, container: Container, name: &str) -> bool {
        let n = self.mutations.borrow().len();
        self.mutations.borrow_mut().push(json!({
            "hook": container.hooks()[2], "realm": realm, "name": name,
            "attributes": null }));
        self.gen.set(self.gen.get() + 1);
        self.node_mutations
            .get(n)
            .map(|m| m["outcome"] == json!(true))
            .unwrap_or(false)
    }

    fn person_group_references(
        &self,
        realm: &str,
        person: &str,
        attribute: &str,
    ) -> Option<Vec<GroupReference>> {
        self.get(vec![
            s("personGroupReferences"),
            s(realm),
            s(person),
            s(attribute),
        ])
        .map(|v| groups(&v))
    }

    fn groups_naming_policy(
        &self,
        realm: &str,
        attribute: &str,
        name: &str,
    ) -> Option<Vec<String>> {
        self.get(vec![
            s("groupsNamingPolicy"),
            s(realm),
            s(attribute),
            s(name),
        ])
        .map(|v| strings(&v))
    }

    fn group_references(
        &self,
        realm: &str,
        groups_in: &[String],
        attribute: &str,
    ) -> Option<Vec<GroupReference>> {
        let list = Value::Array(groups_in.iter().map(|g| s(g)).collect());
        self.get(vec![s("groupReferences"), s(realm), list, s(attribute)])
            .map(|v| groups(&v))
    }

    fn people_naming_policy(
        &self,
        realm: &str,
        attribute: &str,
        name: &str,
    ) -> Option<PeopleNaming> {
        self.get(vec![
            s("peopleNamingPolicyAsync"),
            s(realm),
            s(attribute),
            s(name),
        ])
        .map(|v| PeopleNaming {
            people: strings(&v["people"]),
            complete: v["complete"] != json!(false),
        })
    }

    fn known_name(&self, realm: &str, name: &str) -> String {
        self.get(vec![s("knownName"), s(realm), s(name)])
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default()
    }

    fn holders(&self, realm: &str, name: &str) -> u64 {
        self.get(vec![s("holders"), s(realm), s(name)])
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
    }
}

impl ApplicationRegister for Tape {
    fn by_client_id(&self, realm: &str, client_id: &str) -> Option<Object> {
        self.get(vec![s("app.forClientId"), s(realm), s(client_id)])
            .and_then(|v| v.as_object().cloned())
    }

    fn by_identifier(&self, realm: &str, identifier: &str) -> Option<Object> {
        self.get(vec![s("app.get"), s(realm), s(identifier)])
            .and_then(|v| v.as_object().cloned())
    }

    fn naming_policy(
        &self,
        realm: &str,
        attribute: &str,
        name: &str,
    ) -> Vec<String> {
        self.get(vec![s("app.naming"), s(realm), s(attribute), s(name)])
            .map(|v| strings(&v))
            .unwrap_or_default()
    }
}

impl PolicyEnvironment for Tape {
    fn setting(&self, realm: &str, k: &str) -> Value {
        self.get(vec![s("setting"), s(realm), s(k)])
            .unwrap_or(Value::Null)
    }

    fn verifies_credentials(&self, realm: &str) -> bool {
        self.get(vec![s("mode.verifiesCredentials"), s(realm)])
            == Some(json!(true))
    }

    fn recovers_weaker_than_passkeys(&self, realm: &str) -> bool {
        self.get(vec![s("mode.recoversWeakerThanPasskeys"), s(realm)])
            == Some(json!(true))
    }

    fn creates_incomplete_people(&self, realm: &str) -> bool {
        self.get(vec![s("mode.createsIncompletePeople"), s(realm)])
            == Some(json!(true))
    }

    fn mail_available(&self, realm: &str) -> bool {
        self.get(vec![s("mailAvailable"), s(realm)]) == Some(json!(true))
    }

    fn realm(&self, realm: &str) -> RealmFacts {
        let v = self.get(vec![s("realm"), s(realm)]).unwrap_or(json!({}));
        RealmFacts {
            id: v["id"].as_str().unwrap_or("").into(),
            name: v["name"].as_str().unwrap_or("").into(),
            domain: v["domain"].as_str().unwrap_or("").into(),
        }
    }

    fn authn_vocabularies(&self) -> (Vec<String>, Vec<String>) {
        self.vocabularies.clone()
    }

    fn destination_count(&self, realm: &str) -> i64 {
        self.get(vec![s("destinationCount"), s(realm)])
            .and_then(|v| v.as_i64())
            .unwrap_or(-1)
    }

    fn service_account_reference(&self, realm: &str, username: &str) -> String {
        self.get(vec![s("serviceAccount.reference"), s(realm), s(username)])
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default()
    }

    fn service_accounts_naming(&self, realm: &str, name: &str) -> Vec<String> {
        self.get(vec![s("serviceAccount.naming"), s(realm), s(name)])
            .map(|v| strings(&v))
            .unwrap_or_default()
    }

    fn is_service_account(&self, realm: &str, attributes: &Object) -> bool {
        self.get(vec![
            s("serviceAccount.is"),
            s(realm),
            Value::Object(attributes.clone()),
        ]) == Some(json!(true))
    }

    fn offers_post_quantum(
        &self,
        realm: &str,
        rows: &RegistrationRows,
    ) -> bool {
        let r = json!({
            "registrationAlgorithms": rows.registration_algorithms,
            "registrationMode": rows.registration_mode,
            "postQuantumRequired": rows.post_quantum_required,
            "lanes": rows.lanes });
        self.get(vec![s("webauthn.offersPostQuantum"), s(realm), r])
            == Some(json!(true))
    }

    fn canonical_locale(&self, tag: &str) -> String {
        // `i18n.canonical()` is recorded in the realm it was asked in.
        let found = self
            .map
            .iter()
            .find(|(k, _)| {
                serde_json::from_str::<Value>(k).ok().is_some_and(|p| {
                    p[0] == s("i18n.canonical") && p[2] == s(tag)
                })
            })
            .map(|(_, v)| v.clone());
        match found {
            Some(v) => v.as_str().unwrap_or("").to_string(),
            None => {
                self.misses
                    .borrow_mut()
                    .push(format!("i18n.canonical {tag}"));
                String::new()
            }
        }
    }

    fn offered_attributes(
        &self,
        realm: &str,
    ) -> Result<Vec<OfferedRow>, String> {
        let v = self.get(vec![s("offered"), s(realm)]).unwrap_or(json!([]));
        if let Some(e) = v.get("error") {
            return Err(e.as_str().unwrap_or("").into());
        }
        Ok(v.as_array()
            .map(|a| {
                a.iter()
                    .map(|r| OfferedRow {
                        name: r["name"].as_str().unwrap_or("").into(),
                        label: r["label"].as_str().unwrap_or("").into(),
                        schema: r["schema"].as_str().unwrap_or("").into(),
                        custom: r["custom"] == json!(true),
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    fn passkey_clients_act(
        &self,
        realm: &str,
        action: &str,
        body: &Object,
    ) -> Answer {
        let v = self
            .get(vec![
                s("passkeyClients.act"),
                s(realm),
                s(action),
                Value::Object(body.clone()),
            ])
            .unwrap_or(Value::Null);
        Answer {
            value: v["value"].clone(),
            code: v["code"].as_str().and_then(known_code),
        }
    }
}

// A code the learned clients' register marks (the one it has, #1112).
fn known_code(code: &str) -> Option<sts_core::errors::ErrorCode> {
    match code {
        "STS-AUTHN-0477" => Some(sts_core::errors::codes::STS_AUTHN_0477),
        _ => None,
    }
}

fn arg(args: &[Value], n: usize) -> Value {
    args.get(n).cloned().unwrap_or(Value::Null)
}

fn text_arg(args: &[Value], n: usize) -> String {
    match args.get(n) {
        Some(Value::String(v)) => v.clone(),
        _ => String::new(),
    }
}

fn name_arg(args: &[Value], n: usize) -> Option<String> {
    match args.get(n) {
        Some(Value::String(v)) if !v.is_empty() => Some(v.clone()),
        _ => None,
    }
}

fn obj(v: &Value) -> Option<Object> {
    v.as_object().cloned()
}

fn subject(v: &Value) -> Option<Subject> {
    let o = v.as_object()?;
    Some(Subject {
        uid: o.get("uid").and_then(|u| u.as_str().map(String::from)),
        attributes: o.get("attributes").and_then(|a| a.as_object().cloned()),
        groups: strings(o.get("groups").unwrap_or(&json!([]))),
    })
}

fn plain(v: Value) -> Answer {
    Answer::of(v)
}

fn refusal_pair(r: Option<(sts_core::errors::ErrorCode, String)>) -> Value {
    match r {
        Some((code, message)) => {
            json!({ "code": code.as_str(), "message": message })
        }
        None => Value::Null,
    }
}

/// Runs one case's method over the tape.
fn run(case: &Value, ports: Ports) -> Answer {
    let realm = case["realm"].as_str().unwrap();
    let method = case["method"].as_str().unwrap();
    let args: Vec<Value> = case["args"].as_array().cloned().unwrap_or_default();
    let body = obj(&arg(&args, 1));
    let list = |v: Vec<Value>| plain(Value::Array(v));
    match (case["kind"].as_str().unwrap(), method) {
        ("password", m) => {
            let k = PasswordPolicy::new(ports);
            match m {
                "read" => plain(k.read(realm, name_arg(&args, 0).as_deref())),
                "list" => list(k.list(realm)),
                "selectionFor" => plain(s(&k.selection_for(
                    realm,
                    &text_arg(&args, 0),
                    &text_arg(&args, 1),
                ))),
                "problemsWith" => plain(json!(k.problems_with(
                    realm,
                    &text_arg(&args, 0),
                    args.get(1)
                ))),
                "save" => k.save(realm, &arg(&args, 0), body.as_ref()),
                "reset" => k.reset(realm, &arg(&args, 0)),
                "namedBy" => {
                    plain(k.named_by(realm, &text_arg(&args, 0)).json())
                }
                other => panic!("password {other}"),
            }
        }
        ("authn", m) => {
            let k = AuthnPolicy::new(ports);
            match m {
                "read" => plain(k.read(realm, name_arg(&args, 0).as_deref())),
                "list" => list(k.list(realm)),
                "save" => k.save(realm, &arg(&args, 0), body.as_ref()),
                "reset" => k.reset(realm, &arg(&args, 0)),
                "act" => k.act(realm, &text_arg(&args, 0), body.as_ref()),
                "named" => {
                    list(k.named(realm).iter().map(|p| p.json()).collect())
                }
                "namedPolicy" => plain(
                    k.named_policy(realm, &arg(&args, 0))
                        .map(|p| p.json())
                        .unwrap_or(Value::Null),
                ),
                "mechanismsFor" => plain(k.mechanisms_for(
                    realm,
                    obj(&arg(&args, 0)).as_ref(),
                    &text_arg(&args, 1),
                )),
                "namedBy" => plain(k.named_by(realm, &arg(&args, 0)).json()),
                other => panic!("authn {other}"),
            }
        }
        ("serviceAccount", m) => {
            let k = ServiceAccountPolicy::new(ports);
            match m {
                "read" => plain(k.read(realm, name_arg(&args, 0).as_deref())),
                "list" => list(k.list(realm)),
                "save" => k.save(realm, &arg(&args, 0), body.as_ref()),
                "reset" => k.reset(realm, &arg(&args, 0)),
                "profileFor" => {
                    plain(k.profile_for(realm, &text_arg(&args, 0)))
                }
                "namedBy" => plain(k.named_by(realm, &arg(&args, 0)).json()),
                "writeRefusal" => plain(refusal_pair(k.write_refusal(
                    realm,
                    &obj(&arg(&args, 0)).unwrap_or_default(),
                ))),
                other => panic!("serviceAccount {other}"),
            }
        }
        ("passkey", m) => {
            let k = PasskeyPolicy::new(ports);
            match m {
                "read" => plain(k.read(realm, name_arg(&args, 0).as_deref())),
                "list" => list(k.list(realm)),
                "save" => k.save(realm, &arg(&args, 0), body.as_ref()),
                "reset" => k.reset(realm, &arg(&args, 0)),
                "selectionFor" => plain(s(&k.selection_for(
                    realm,
                    &text_arg(&args, 0),
                    &text_arg(&args, 1),
                ))),
                "forApplication" => {
                    plain(k.for_application(realm, &arg(&args, 0)))
                }
                "act" => k.act(realm, &text_arg(&args, 0), body.as_ref()),
                other => panic!("passkey {other}"),
            }
        }
        ("locale", m) => {
            let k = LocalePolicy::new(ports);
            match m {
                "read" => plain(k.read(realm, name_arg(&args, 0).as_deref())),
                "list" => list(k.list(realm)),
                "save" => k.save(realm, &arg(&args, 0), body.as_ref()),
                "reset" => k.reset(realm, &arg(&args, 0)),
                "profileNameFor" => plain(s(&k.profile_name_for(
                    realm,
                    &text_arg(&args, 0),
                    &text_arg(&args, 1),
                ))),
                "forApplication" => plain(k.for_application(
                    realm,
                    &text_arg(&args, 0),
                    &text_arg(&args, 1),
                )),
                "namedBy" => {
                    plain(k.named_by(realm, &text_arg(&args, 0)).json())
                }
                other => panic!("locale {other}"),
            }
        }
        ("attributes", m) => {
            let k = AttributePolicy::new(ports);
            match m {
                "read" => plain(k.read(realm, &arg(&args, 0))),
                "list" => list(k.list(realm)),
                "profileNames" => plain(json!(k.profile_names(realm))),
                "save" => k.save(realm, &arg(&args, 0), body.as_ref()),
                "reset" => k.reset(realm, &arg(&args, 0)),
                "act" => k.act(realm, &text_arg(&args, 0), body.as_ref()),
                "definitions" => list(
                    k.definitions(realm).iter().map(|d| d.json()).collect(),
                ),
                "selectionFor" => plain(
                    k.selection_for(realm, subject(&arg(&args, 0)).as_ref())
                        .json(),
                ),
                "required" => plain(json!(
                    k.required(realm, subject(&arg(&args, 0)).as_ref())
                )),
                "createRefusal" => plain(k.create_refusal(
                    realm,
                    &obj(&arg(&args, 0)).unwrap_or_default(),
                    subject(&arg(&args, 1)).as_ref(),
                )),
                "editRefusal" => plain(k.edit_refusal(
                    realm,
                    &obj(&arg(&args, 0)).unwrap_or_default(),
                    &obj(&arg(&args, 1)).unwrap_or_default(),
                    subject(&arg(&args, 2)).as_ref(),
                )),
                other => panic!("attributes {other}"),
            }
        }
        ("postLogin", m) => {
            let k = PostLoginPolicy::new(ports);
            match m {
                "read" => plain(k.read(realm, name_arg(&args, 0).as_deref())),
                "list" => list(k.list(realm)),
                "save" => k.save(realm, &arg(&args, 0), body.as_ref()),
                "reset" => k.reset(realm, &arg(&args, 0)),
                "profileNameFor" => plain(s(&k.profile_name_for(
                    realm,
                    &text_arg(&args, 0),
                    &text_arg(&args, 2),
                ))),
                "forPerson" => plain(k.for_person(
                    realm,
                    &text_arg(&args, 0),
                    &text_arg(&args, 2),
                )),
                other => panic!("postLogin {other}"),
            }
        }
        (kind, m) => panic!("{kind} {m}"),
    }
}

// PolicySelection's pure answers, as Node writes them.
fn entries_of(v: &Value) -> Option<Vec<PolicyEntry>> {
    v.as_array().map(|a| a.iter().map(entry_of).collect())
}

fn spec_of(v: &Value) -> SelectionSpec {
    SelectionSpec {
        precedence_attribute: v["precedenceAttribute"]
            .as_str()
            .unwrap_or("")
            .into(),
        default_precedence: v["defaultPrecedence"].as_i64(),
    }
}

fn refs_of(v: &Value) -> Vec<Reference> {
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|r| Reference {
                    by: r["by"].as_str().unwrap_or("").into(),
                    holder: r["holder"].as_str().unwrap_or("").into(),
                    value: r.get("value").cloned().unwrap_or(Value::Null),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn selection_answer(row: &Value) -> Value {
    let a = row["args"].as_array().unwrap();
    match row["method"].as_str().unwrap() {
        "rank" => selection::rank(entries_of(&a[0]).as_deref(), &spec_of(&a[1]), &refs_of(&a[2])).json(),
        "named" => Value::Array(
            selection::named(entries_of(&a[0]).as_deref(), &spec_of(&a[1]))
                .iter()
                .map(|n| json!({ "name": n.name, "dn": n.dn, "precedence": n.precedence.json() }))
                .collect(),
        ),
        "forReference" => {
            let f = selection::for_reference(entries_of(&a[0]).as_deref(), &spec_of(&a[1]), &a[2]);
            json!({ "named": f.named, "missing": f.missing, "applies": f.applies,
                    "precedence": f.precedence.json() })
        }
        "groupReferences" => Value::Array(
            selection::group_references(&a[0].as_array().unwrap().iter().map(|g| GroupReference {
                cn: g["cn"].as_str().unwrap_or("").into(),
                dn: g["dn"].as_str().unwrap_or("").into(),
                value: g["value"].as_str().unwrap_or("").into(),
            }).collect::<Vec<_>>())
            .iter()
            .map(|r| json!({ "by": r.by, "holder": r.holder, "value": r.value }))
            .collect(),
        ),
        "nameProblem" => json!(selection::name_problem(&a[0], a[1].as_str().unwrap(), a[2] == json!(true))),
        "checkPrecedence" => {
            let (p, problems) = selection::check_precedence(a[0].as_object(), &spec_of(&a[1]));
            json!({ "precedence": p, "problems": problems })
        }
        "referenceProblem" => {
            let choices = a[1].as_array().map(|_| strings(&a[1]));
            json!(selection::reference_problem(&a[0], choices.as_deref(), a[2].as_str().unwrap()))
        }
        "deleteProblem" => {
            let h = &a[2];
            let holders = Holders {
                applications: strings(&h["applications"]),
                groups: strings(&h["groups"]),
                people: strings(&h["people"]),
            };
            json!(selection::delete_problem(a[0].as_str().unwrap(), a[1].as_str().unwrap(), &holders))
        }
        "compare" => {
            let p = |v: &Value| selection::Precedence(v["precedence"].as_f64().unwrap());
            let o = selection::compare(
                (a[0]["name"].as_str().unwrap(), p(&a[0])),
                (a[1]["name"].as_str().unwrap(), p(&a[1])),
            );
            json!(o as i32)
        }
        "fold" => json!(sts_policy::js::fold(&a[0])),
        other => panic!("selection {other}"),
    }
}

fn field_json(f: &sts_policy::tables::Field) -> Map<String, Value> {
    let mut o = Map::new();
    o.insert("key".into(), s(&f.key));
    o.insert("attribute".into(), s(&f.attribute));
    o.insert("type".into(), s(&f.kind));
    o.insert("dflt".into(), f.dflt.clone());
    if let Some(n) = f.min {
        o.insert("min".into(), json!(n));
    }
    if let Some(n) = f.max {
        o.insert("max".into(), json!(n));
    }
    if !f.values.is_empty() {
        o.insert("values".into(), json!(f.values));
    }
    o.insert("optional".into(), json!(f.optional));
    o.insert("label".into(), s(&f.label));
    if let Some(u) = &f.unit {
        o.insert("unit".into(), s(u));
    }
    o.insert("what".into(), s(&f.what));
    if let Some(e) = &f.empty {
        o.insert("empty".into(), s(e));
    }
    if let Some(n) = f.max_items {
        o.insert("maxItems".into(), json!(n));
    }
    if let Some(m) = &f.mechanism {
        o.insert("mechanism".into(), s(m));
    }
    if let Some(r) = &f.role {
        o.insert("role".into(), s(r));
    }
    o.insert("email".into(), json!(f.email));
    if let Some(d) = &f.door {
        o.insert("door".into(), s(d));
    }
    o
}

fn canonical(v: &Value) -> Value {
    match v {
        Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for k in keys {
                out.insert(k.clone(), canonical(&o[k]));
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

#[test]
fn every_policy_answer_is_nodes() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!("STS_CRYPTO_VECTORS is not set: nothing to check");
        return;
    };
    let path = Path::new(&dir).join("policy-node.json");
    if !path.exists() {
        eprintln!("no {}: nothing to check", path.display());
        return;
    }
    let node: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let mut wrong: Vec<String> = Vec::new();

    // THE SELECTION.
    let rows = node["selection"].as_array().unwrap();
    for (n, row) in rows.iter().enumerate() {
        let mine = selection_answer(row);
        if canonical(&mine) != canonical(&row["answer"]) {
            wrong.push(format!(
                "selection {n} {}: Rust {mine} Node {}",
                row["method"], row["answer"]
            ));
        }
    }

    // THE KINDS' LIST.
    let kinds = &node["kinds"];
    let mine_list: Vec<Value> = registry::KINDS
        .iter()
        .map(|k| {
            json!({ "id": k.id, "label": k.label, "container": k.container,
                    "governs": k.governs, "auditAction": k.audit_action,
                    "appliesTo": k.applies_to, "fallsBackTo": k.falls_back_to,
                    "tabbed": k.tabbed, "noun": k.noun(), "saveAction": k.save_action(),
                    "resetAction": k.reset_action(),
                    "extraActions": k.extra_actions.iter().map(|x| json!({
                        "action": x.action, "operationId": x.operation_id,
                        "auditAction": x.audit_action })).collect::<Vec<_>>() })
        })
        .collect();
    if Value::Array(mine_list) != kinds["list"] {
        wrong.push("the kinds' list differs".into());
    }
    if json!(registry::actions()) != kinds["actions"] {
        wrong.push("the actions differ".into());
    }
    let messages: Map<String, Value> = registry::MESSAGES
        .iter()
        .map(|(k, v)| (k.to_string(), s(v)))
        .collect();
    if Value::Object(messages) != kinds["messages"] {
        wrong.push("the messages differ".into());
    }
    for pair in kinds["numberWords"].as_array().unwrap() {
        if registry::number_word(pair[0].as_u64().unwrap() as usize)
            != pair[1].as_str().unwrap()
        {
            wrong.push(format!("numberWord {pair}"));
        }
    }
    for row in kinds["forAction"].as_array().unwrap() {
        let mine = registry::for_action(row["action"].as_str().unwrap());
        let got = json!({ "kind": mine.map(|m| m.0.id), "verb": mine.map(|m| m.1.as_str()) });
        if got["kind"] != row["kind"] || got["verb"] != row["verb"] {
            wrong.push(format!("forAction {row}"));
        }
    }
    let unknown = registry::unknown_action("frobnicate");
    if unknown.value != kinds["unknown"]["answer"]
        || unknown.code.map(|c| c.as_str()) != kinds["unknown"]["code"].as_str()
    {
        wrong.push(format!("unknown action: {}", unknown.value));
    }

    // EVERY KIND'S FIELDS, member by member as Node holds them.
    let mine_fields: Vec<(&str, &[sts_policy::tables::Field])> = vec![
        ("password", PasswordPolicy::fields()),
        ("authn", AuthnPolicy::fields()),
        ("serviceAccount", ServiceAccountPolicy::fields()),
        ("passkey", PasskeyPolicy::fields()),
        ("locale", LocalePolicy::fields()),
        ("attributes", AttributePolicy::fields()),
        ("postLogin", PostLoginPolicy::fields()),
    ];
    for (kind, rows) in mine_fields {
        let theirs = node["fields"][kind].as_array().cloned().unwrap_or_default();
        if theirs.len() != rows.len() {
            wrong.push(format!("{kind}: {} rows, Node {}", rows.len(), theirs.len()));
            continue;
        }
        for (f, t) in rows.iter().zip(theirs.iter()) {
            let mine = field_json(f);
            for (k, v) in t.as_object().unwrap() {
                if mine.get(k) != Some(v) {
                    wrong.push(format!("{kind}.{}.{k}: Rust {:?} Node {v}", f.key, mine.get(k)));
                }
            }
        }
    }

    // THE CASES.
    let vocabularies = (
        strings(&node["vocabularies"]["mechanisms"]),
        strings(&node["vocabularies"]["secondFactors"]),
    );
    let mut answered = Vec::new();
    let cases = node["cases"].as_array().unwrap();
    for (n, case) in cases.iter().enumerate() {
        let tape = Tape::new(case, vocabularies.clone());
        let ports = Ports {
            directory: &tape,
            applications: &tape,
            env: &tape,
        };
        let got = run(case, ports);
        let code = got.code.map(|c| c.as_str().to_string()).unwrap_or_default();
        let what = format!(
            "case {n} {}.{} {} {}",
            case["kind"],
            case["method"],
            case["realm"],
            serde_json::to_string(&case["args"])
                .unwrap()
                .chars()
                .take(120)
                .collect::<String>()
        );
        if canonical(&got.value) != canonical(&case["answer"]) {
            wrong.push(format!(
                "{what}\n   Rust {}\n   Node {}",
                got.value, case["answer"]
            ));
        } else if code != case["code"].as_str().unwrap_or("") {
            wrong.push(format!(
                "{what}: Rust code {code}, Node {}",
                case["code"]
            ));
        }
        let mine = tape.mutations.borrow().clone();
        let theirs: Vec<Value> = tape
            .node_mutations
            .iter()
            .map(|m| json!({ "hook": m["hook"], "realm": m["realm"], "name": m["name"],
                             "attributes": m["attributes"] }))
            .collect();
        if canonical(&Value::Array(mine.clone()))
            != canonical(&Value::Array(theirs.clone()))
        {
            wrong.push(format!(
                "{what}: writes\n   Rust {}\n   Node {}",
                json!(mine),
                json!(theirs)
            ));
        }
        let misses = tape.misses.borrow().clone();
        if !misses.is_empty() {
            wrong.push(format!(
                "{what}: asked what Node never asked: {}",
                misses.join("; ")
            ));
        }
        answered.push(json!({ "answer": got.value, "code": code }));
    }

    // GENERATED PASSWORDS, for Node to check, over a default-realm tape.
    let mut generated = Vec::new();
    if let Some(case) = cases.iter().find(|c| {
        c["method"] == s("problemsWith") && c["realm"] == s("default")
    }) {
        let tape = Tape::new(case, vocabularies.clone());
        let ports = Ports {
            directory: &tape,
            applications: &tape,
            env: &tape,
        };
        let k = PasswordPolicy::new(ports);
        for extra in [
            json!({}),
            json!({ "generatedLength": 32 }),
            json!({ "minLength": 40, "generatedLength": 40 }),
        ] {
            let mut profile = case["args"][1].clone();
            for (key, v) in extra.as_object().unwrap() {
                profile[key] = v.clone();
            }
            for _ in 0..5 {
                let p =
                    k.generate("default", Some(&profile)).expect("a password");
                generated.push(json!({ "password": p, "profile": profile }));
            }
        }
    }

    if std::env::var("STS_WRITE_VECTORS").is_ok() {
        std::fs::write(
            Path::new(&dir).join("policy-rust.json"),
            serde_json::to_string(
                &json!({ "cases": answered, "generated": generated }),
            )
            .unwrap(),
        )
        .unwrap();
    }
    assert!(
        wrong.is_empty(),
        "{} of {} selection rows and {} cases differ from Node:\n{}",
        wrong.len(),
        rows.len(),
        cases.len(),
        wrong
            .iter()
            .take(25)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
