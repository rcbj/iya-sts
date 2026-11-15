// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The credentials against Node as it is now: `credentials-node.json`,
//! which `tests/tools/credentials-vectors.js` writes over Node's own
//! modules (`STS_ONLY=credentials node tests/tools/crypto-vectors.js`, in
//! the tests image). Held to it:
//!
//! * every mechanism call — TOTP, recovery codes, app passwords — answers
//!   what Node answered, or throws where Node threw, with Node's code;
//! * every door scenario, step by step, answers Node's verdict with Node's
//!   code, ASKING only what Node asked: each port is answered from the
//!   case's tape, and a question Node never asked fails the case; every
//!   write is the one Node made, in order, a hash compared by the plaintext
//!   it verifies; every random draw is the one Node drew; every
//!   observation (a failure recorded, a password observed) is Node's;
//! * phishing resistance answers Node's classes, URIs and sentences;
//! * the WebAuthn ceremonies — registrations and assertions software
//!   authenticators made in Node — verify, or are refused, as Node's did,
//!   check by check.
//!
//! With `STS_WRITE_VECTORS=1` it writes what this crate stored (and the
//! plaintext each hash it made stands for) as `credentials-rust.json`,
//! which `tests/rust_crypto_vectors.js` holds to Node: Node verifies what
//! Rust stored. The directory is `STS_CRYPTO_VECTORS`, never committed;
//! with it unset this test says so and passes.

#![allow(clippy::unwrap_used, clippy::expect_used)] // a test file

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde_json::{json, Map, Value as Json};
use sts_core::mode::Mode;
use sts_core::realm::{RealmEnvironment, RealmRegistry};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::StoreHandles;
use sts_core::settings::Settings;
use sts_credentials::app_passwords::AppPasswords;
use sts_credentials::backup_codes::BackupCodes;
use sts_credentials::credentials::{
    Credentials, CredentialsDeps, PendingStores, VerifyOptions,
};
use sts_credentials::phishing::PhishingResistance;
use sts_credentials::ports::{
    CredentialDirectory, Environment, Hook, Keystore, Observers, People,
    Policies, ServiceAccounts,
};
use sts_credentials::totp::Totp;
use sts_credentials::{js, Verdict};
use sts_crypto::secrets::{
    hash_secret, is_hashed_secret, verify_secret, ScryptCost,
};

const NOW: f64 = 1_767_225_600_000.0;

// ---------------------------------------------------------------------------
// THE TAPE.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct State {
    gen: i64,
    random: usize,
    mutations: Vec<Json>,
    observed: Vec<Json>,
    misses: Vec<String>,
    hashes: Map<String, Json>,
}

/// One case's recorded world, answering every port from the tape.
struct Tape {
    map: HashMap<String, Json>,
    node_mutations: Vec<Json>,
    random: Vec<Json>,
    now: f64,
    realm: String,
    state: Mutex<State>,
}

fn key(parts: Vec<Json>) -> String {
    serde_json::to_string(&Json::Array(parts)).unwrap()
}

fn s(v: &str) -> Json {
    Json::String(v.to_string())
}

impl Tape {
    fn new(case: &Value) -> Tape {
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
            random: case["random"].as_array().cloned().unwrap_or_default(),
            now: case["spec"]["now"].as_f64().unwrap_or(NOW),
            realm: case["spec"]["realm"]
                .as_str()
                .unwrap_or("default")
                .to_string(),
            state: Mutex::new(State::default()),
        }
    }

    fn ask(&self, parts: Vec<Json>) -> Json {
        let k = key(parts);
        match self.map.get(&k) {
            Some(v) => v.clone(),
            None => {
                self.state.lock().unwrap().misses.push(k);
                Json::Null
            }
        }
    }

    fn hook(&self, name: &str, who: &str) -> Hook<Json> {
        let gen = self.state.lock().unwrap().gen;
        let answer =
            self.ask(vec![s(&format!("dir.{name}")), json!(gen), s(who)]);
        if let Some(t) = answer.get("threw") {
            return Err(js::string(t));
        }
        Ok(answer.get("value").cloned().unwrap_or(Json::Null))
    }

    fn write(&self, hook: &str, name: &str, value: Json) -> Hook<bool> {
        let mut st = self.state.lock().unwrap();
        let n = st.mutations.len();
        let outcome = self
            .node_mutations
            .get(n)
            .map(|m| m["outcome"].clone())
            .unwrap_or(json!({ "value": false }));
        st.mutations
            .push(json!({ "hook": hook, "name": name, "value": value,
                                  "outcome": outcome }));
        st.gen += 1;
        if let Some(t) = outcome.get("threw") {
            return Err(js::string(t));
        }
        Ok(outcome["value"] == json!(true))
    }

    fn next_random(&self) -> Json {
        let mut st = self.state.lock().unwrap();
        let at = st.random;
        st.random += 1;
        match self.random.get(at) {
            Some(r) => r.clone(),
            None => {
                st.misses.push(format!("random draw {at}"));
                Json::Null
            }
        }
    }
}

type Value = Json;

fn opt_text(v: Json) -> Option<String> {
    match v {
        Json::Null => None,
        Json::String(t) if t.is_empty() => None,
        other => Some(js::string(&other)),
    }
}

impl Environment for Tape {
    fn setting(&self, key: &str) -> Json {
        self.ask(vec![s("setting"), s(key)])
    }
    fn predicate(&self, name: &str) -> bool {
        self.ask(vec![s("predicate"), s(name)]) == json!(true)
    }
    fn now_ms(&self) -> f64 {
        self.now
    }
    // The realm is AMBIENT in Node: the pending stores read it without
    // asking a dependency, so it is answered from the case, not the tape.
    fn realm_id(&self) -> String {
        match self.map.get(&key(vec![s("realm")])) {
            Some(v) => js::string(v),
            None => self.realm.clone(),
        }
    }
    fn random_bytes(&self, n: usize) -> Vec<u8> {
        let r = self.next_random();
        if r["kind"] != json!("bytes") || r["n"] != json!(n) {
            self.state
                .lock()
                .unwrap()
                .misses
                .push(format!("bytes({n}) drew {r}"));
        }
        hex(r["hex"].as_str().unwrap_or(""))
    }
    fn random_int(&self, min: u64, max: u64) -> u64 {
        let r = self.next_random();
        if r["kind"] != json!("int")
            || r["min"] != json!(min)
            || r["max"] != json!(max)
        {
            self.state
                .lock()
                .unwrap()
                .misses
                .push(format!("int({min},{max}) drew {r}"));
        }
        r["value"].as_u64().unwrap_or(0)
    }
    fn hash_secret(&self, plaintext: &str) -> String {
        let out = hash_secret(plaintext, ScryptCost::default()).unwrap();
        self.state
            .lock()
            .unwrap()
            .hashes
            .insert(out.clone(), s(plaintext));
        out
    }
}

impl CredentialDirectory for Tape {
    fn read_password(&self, name: &str) -> Hook<Option<String>> {
        self.hook("readPassword", name).map(opt_text)
    }
    fn write_password(&self, name: &str, hash: &str) -> Hook<bool> {
        self.write("writePassword", name, s(hash))
    }
    fn read_password_reset(&self, name: &str) -> Hook<bool> {
        self.hook("readPasswordReset", name).map(|v| js::truthy(&v))
    }
    fn read_password_history(&self, name: &str) -> Hook<Vec<String>> {
        self.hook("readPasswordHistory", name).map(|v| {
            v.as_array()
                .map(|l| l.iter().map(js::string).collect())
                .unwrap_or_default()
        })
    }
    fn is_person(&self, name: &str) -> Hook<bool> {
        self.hook("isPerson", name).map(|v| js::truthy(&v))
    }
    fn person_exists(&self, name: &str) -> Hook<bool> {
        self.hook("personExists", name).map(|v| js::truthy(&v))
    }
    fn read_account_disabled(&self, name: &str) -> Hook<bool> {
        self.hook("readAccountDisabled", name)
            .map(|v| js::truthy(&v))
    }
    fn read_mfa_required(&self, name: &str) -> Hook<bool> {
        self.hook("readMfaRequired", name).map(|v| js::truthy(&v))
    }
    fn read_totp(&self, name: &str) -> Hook<Option<String>> {
        self.hook("readTotp", name).map(opt_text)
    }
    fn write_totp(&self, name: &str, value: Option<&str>) -> Hook<bool> {
        self.write("writeTotp", name, value.map_or(Json::Null, s))
    }
    fn read_backup_codes(&self, name: &str) -> Hook<Option<String>> {
        self.hook("readBackupCodes", name).map(opt_text)
    }
    fn write_backup_codes(
        &self,
        name: &str,
        value: Option<&str>,
    ) -> Hook<bool> {
        self.write("writeBackupCodes", name, value.map_or(Json::Null, s))
    }
    fn read_app_passwords(&self, name: &str) -> Hook<Option<String>> {
        self.hook("readAppPasswords", name).map(opt_text)
    }
    fn write_app_passwords(
        &self,
        name: &str,
        value: Option<&str>,
    ) -> Hook<bool> {
        self.write("writeAppPasswords", name, value.map_or(Json::Null, s))
    }
    fn read_webauthn(&self, name: &str) -> Hook<Vec<Json>> {
        self.hook("readWebauthn", name)
            .map(|v| v.as_array().cloned().unwrap_or_default())
    }
}

impl Keystore for Tape {
    fn persists(&self) -> bool {
        self.ask(vec![s("keystore.persists")]) == json!(true)
    }
    fn seal(&self, plain: &str, label: &str, scope: &str) -> Option<String> {
        opt_text(self.ask(vec![
            s("keystore.seal"),
            s(plain),
            s(label),
            s(scope),
        ]))
    }
    fn open(&self, sealed: &str, label: &str) -> Option<String> {
        opt_text(self.ask(vec![s("keystore.open"), s(sealed), s(label)]))
    }
}

impl Policies for Tape {
    fn allows(&self, mechanism: &str, role: &str) -> bool {
        self.ask(vec![s("policy.allows"), s(mechanism), s(role)]) == json!(true)
    }
    fn require_second_factor(&self) -> String {
        js::string_or_empty(Some(
            &self.ask(vec![s("policy.requireSecondFactor")]),
        ))
    }
    fn configured_second_factor(&self) -> String {
        js::string_or_empty(Some(
            &self.ask(vec![s("policy.configuredSecondFactor")]),
        ))
    }
    fn require_second_factor_for_administrators(&self) -> String {
        js::string_or_empty(Some(
            &self.ask(vec![s("policy.requireSecondFactorForAdministrators")]),
        ))
    }
    fn key_use_allowed(&self, key_use: &str) -> bool {
        self.ask(vec![s("policy.keyUse"), s(key_use)]) == json!(true)
    }
    fn password_profile_for(&self, name: &str) -> Json {
        self.ask(vec![s("policy.passwordProfile"), s(name)])
    }
    fn password_hash_spec(&self, profile: &Json) -> Json {
        self.ask(vec![s("policy.hashSpec"), profile.clone()])
    }
}

impl ServiceAccounts for Tape {
    fn is_service_account_name(&self, name: &str) -> bool {
        self.ask(vec![s("svc.is"), s(name)]) == json!(true)
    }
    fn refuses_door(&self, name: &str, door: &str) -> bool {
        self.ask(vec![s("svc.refusesDoor"), s(name), s(door)]) == json!(true)
    }
    fn exempt_from_second_factor(&self, name: &str) -> bool {
        self.ask(vec![s("svc.exempt"), s(name)]) == json!(true)
    }
    fn previous_password_hash(&self, name: &str) -> Hook<Option<String>> {
        Ok(opt_text(self.ask(vec![s("svc.previous"), s(name)])))
    }
}

impl People for Tape {
    fn console_roles_of(&self, name: &str) -> (bool, bool) {
        let v = self.ask(vec![s("people.roles"), s(name)]);
        (v[0] == json!(true), v[1] == json!(true))
    }
    fn bootstrap_name(&self) -> String {
        js::string_or_empty(Some(&self.ask(vec![s("people.bootstrap")])))
    }
}

impl Observers for Tape {
    fn password(&self, name: &str, password: &str, facts: &Json) {
        self.state
            .lock()
            .unwrap()
            .observed
            .push(json!({ "kind": "password",
            "name": name, "password": password, "facts": facts }));
    }
    fn failure(&self, username: &str, via: &str, code: &str) {
        self.state
            .lock()
            .unwrap()
            .observed
            .push(json!({ "kind": "failure",
            "username": username, "via": via, "code": code }));
    }
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

// ---------------------------------------------------------------------------
// HASH-AWARE COMPARISON: a stored value holding a hash is the same as
// Node's when it verifies the plaintext Node's hashed.
// ---------------------------------------------------------------------------

fn same(node: &Json, rust: &Json, hashes: &Map<String, Json>) -> bool {
    match (node, rust) {
        (Json::String(a), Json::String(b)) => {
            if a == b {
                return true;
            }
            if let Some(plain) = hashes.get(a) {
                return is_hashed_secret(b)
                    && verify_secret(&js::string(plain), b);
            }
            // A string that is JSON this service wrote: compared parsed.
            match (
                serde_json::from_str::<Json>(a),
                serde_json::from_str::<Json>(b),
            ) {
                (Ok(x @ (Json::Object(_) | Json::Array(_))), Ok(y)) => {
                    same(&x, &y, hashes)
                }
                _ => false,
            }
        }
        (Json::Number(a), Json::Number(b)) => a.as_f64() == b.as_f64(),
        (Json::Array(a), Json::Array(b)) => {
            a.len() == b.len()
                && a.iter().zip(b).all(|(x, y)| same(x, y, hashes))
        }
        (Json::Object(a), Json::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(k, v)| b.get(k).is_some_and(|w| same(v, w, hashes)))
        }
        (a, b) => a == b,
    }
}

fn vectors() -> Option<Json> {
    let dir = std::env::var("STS_CRYPTO_VECTORS").ok()?;
    let path = Path::new(&dir).join("credentials-node.json");
    let text = std::fs::read_to_string(&path).ok()?;
    Some(serde_json::from_str(&text).unwrap())
}

struct Env;

impl RealmEnvironment for Env {
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

fn pending() -> PendingStores {
    let settings = Arc::new(Settings::new(Json::Null, HashMap::new()));
    let registry = Arc::new(RealmRegistry::new(Arc::new(Env)));
    let life = RealmLifecycle::new(
        registry,
        settings.clone(),
        Arc::new(Mode::new(settings)),
    );
    life.create("acme", "", "", "", &Map::new(), false).unwrap();
    PendingStores::declare(&life, &StoreHandles::new())
}

fn credentials_over(tape: &Arc<Tape>) -> Credentials {
    Credentials::new(CredentialsDeps {
        env: tape.clone(),
        policies: tape.clone(),
        keystore: tape.clone(),
        service_accounts: tape.clone(),
        people: tape.clone(),
        observers: tape.clone(),
        directory: Some(tape.clone()),
        pending: pending(),
    })
}

fn verdict_json(v: &Verdict) -> (Json, String) {
    (v.value.clone(), v.code_text().to_string())
}

fn f(v: &Json) -> Option<f64> {
    if v.is_null() {
        None
    } else {
        Some(js::number(v))
    }
}

fn bytes_of(v: &Json) -> Vec<u8> {
    v["data"]
        .as_array()
        .map(|l| l.iter().map(|b| b.as_u64().unwrap_or(0) as u8).collect())
        .unwrap_or_default()
}

/// One mechanism call, as the case names it: `(value, code, threw)`.
fn mechanism(
    target: &str,
    method: &str,
    args: &[Json],
    tape: &Arc<Tape>,
) -> (Json, String, Option<String>) {
    let totp = Totp::new(tape.clone(), tape.clone());
    let backup = BackupCodes::new(tape.clone(), tape.clone());
    let apps = AppPasswords::new(tape.clone());
    let a = |i: usize| args.get(i).cloned().unwrap_or(Json::Null);
    let t = |i: usize| js::string_or_empty(args.get(i));
    let ok = |v: Json| (v, String::new(), None);
    let res = |r: Result<Json, String>| match r {
        Ok(v) => (v, String::new(), None),
        Err(e) => (Json::Null, String::new(), Some(e)),
    };
    match (target, method) {
        ("totp", "settings") => ok(totp.settings().to_json()),
        ("totp", "base32Encode") => {
            ok(s(&Totp::base32_encode(&bytes_of(&a(0)))))
        }
        ("totp", "base32Decode") => res(Totp::base32_decode(&t(0)).map(|b| {
            s(&b.iter().map(|x| format!("{x:02x}")).collect::<String>())
        })),
        ("totp", "grouped") => ok(s(&Totp::grouped(&t(0)))),
        ("totp", "generateSecret") => {
            ok(s(&totp.generate_secret(f(&a(0)["bytes"]))))
        }
        ("totp", "issuerFor") => ok(s(&totp.issuer_for(&t(0)))),
        ("totp", "otpauthUri") => {
            let o = a(0);
            ok(s(&Totp::otpauth_uri(
                &js::string_or(o.get("issuer"), ""),
                &js::string_or(o.get("account"), ""),
                &js::string_or(o.get("secret"), ""),
                &js::string_or(o.get("algorithm"), ""),
                js::number_or_fallback(o.get("digits"), 0.0),
                js::number_or_fallback(o.get("period"), 0.0),
            )))
        }
        ("totp", "codeAt") => {
            let o = a(2);
            res(totp
                .code_at(
                    &t(0),
                    f(&a(1)),
                    o.get("period").and_then(f),
                    o.get("digits").and_then(f),
                    o.get("algorithm").and_then(Json::as_str),
                )
                .map(|c| s(&c)))
        }
        ("totp", "verify") => {
            let o = a(2);
            match totp.verify(
                &a(0),
                &a(1),
                o.get("at").and_then(f),
                o.get("window"),
            ) {
                Ok(v) => {
                    let (value, code) = verdict_json(&v);
                    (value, code, None)
                }
                Err(e) => (Json::Null, String::new(), Some(e)),
            }
        }
        ("backup", "settings") => ok(backup.settings().to_json()),
        ("backup", "formatted") => ok(s(&backup.formatted(&t(0), f(&a(1))))),
        ("backup", "generate") => {
            let o = a(0);
            ok(backup
                .generate(
                    o.get("count").and_then(f),
                    o.get("length").and_then(f),
                )
                .map_or(Json::Null, |l| js::strings(&l)))
        }
        ("backup", "generateCode") => ok(s(&backup.generate_code(f(&a(0))))),
        ("backup", "normalise") => ok(s(&BackupCodes::normalise(&t(0)))),
        ("backup", "wellFormed") => ok(json!(BackupCodes::well_formed(&t(0)))),
        ("backup", "matches") => ok(json!(BackupCodes::matches(&t(0), &t(1)))),
        ("backup", "isHash") => ok(json!(BackupCodes::is_hash(&t(0)))),
        ("backup", "matchesHash") => {
            ok(json!(BackupCodes::matches_hash(&t(0), &t(1))))
        }
        ("apps", "settings") => ok(apps.settings()),
        ("apps", "scopeOf") => {
            let sc = AppPasswords::scope_of(&a(0));
            ok(json!({ "ok": sc.ok, "doors": sc.doors, "bad": sc.bad }))
        }
        ("apps", "passwordAloneDoors") => {
            ok(js::strings(&apps.password_alone_doors()))
        }
        ("apps", "nameOf") => ok(s(&AppPasswords::name_of(&a(0)))),
        ("apps", "wellFormed") => ok(json!(AppPasswords::well_formed(&t(0)))),
        ("apps", "idOf") => ok(s(&AppPasswords::id_of(&t(0)))),
        ("apps", "normalise") => ok(s(&AppPasswords::normalise(&t(0)))),
        ("apps", "printed") => ok(s(&AppPasswords::printed(&t(0)))),
        ("apps", "isDoor") => ok(json!(AppPasswords::is_door(&t(0)))),
        ("apps", "doorLabel") => ok(s(&AppPasswords::door_label(&t(0)))),
        ("apps", "generate") => {
            let taken: Vec<String> = a(0)
                .as_array()
                .map(|l| l.iter().map(js::string).collect())
                .unwrap_or_default();
            let m = apps.generate(&taken);
            ok(
                json!({ "id": m.id, "password": m.password, "printed": m.printed }),
            )
        }
        _ => (
            Json::Null,
            String::new(),
            Some(format!("no such call {target}.{method}")),
        ),
    }
}

/// One door step.
fn step(
    c: &Credentials,
    method: &str,
    args: &[Json],
) -> (Json, String, Option<String>) {
    let a = |i: usize| args.get(i).cloned().unwrap_or(Json::Null);
    let t = |i: usize| js::string_or_empty(args.get(i));
    let v = |v: Verdict| {
        let (value, code) = verdict_json(&v);
        (value, code, None)
    };
    let r = |r: Result<Verdict, String>| match r {
        Ok(x) => v(x),
        Err(e) => (Json::Null, String::new(), Some(e)),
    };
    let ok = |j: Json| (j, String::new(), None);
    match method {
        "verify" => v(c.verify(&t(0), &t(1), &VerifyOptions::from_json(&a(2)))),
        "passwordOnlyDoors" => ok(c.password_only_doors(&t(0))),
        "mfaRequirementFor" => ok(c.mfa_requirement_for(&t(0))),
        "secondFactorDemand" => ok(c.second_factor_demand(&t(0))),
        "keysOf" => ok(Json::Array(c.keys_of(&t(0)))),
        "createAppPassword" => v(c.create_app_password(&t(0), &a(1))),
        "revokeAppPassword" => v(c.revoke_app_password(&t(0), &t(1))),
        "appPasswordsOf" => ok(c.app_passwords_of(&t(0))),
        "beginTotpEnrolment" => v(c.begin_totp_enrolment(
            &t(0),
            &js::string_or_empty(a(1).get("base")),
        )),
        "confirmTotpEnrolment" => r(c.confirm_totp_enrolment(&t(0), &a(1))),
        "verifyTotp" => {
            let o = a(2);
            r(c.verify_totp(
                &t(0),
                &a(1),
                o.get("at").and_then(f),
                o.get("window"),
            ))
        }
        "totpOf" => ok(c.totp_of(&t(0)).unwrap_or(Json::Null)),
        "backupCodeStatus" => ok(c.backup_code_status(&t(0))),
        "beginBackupCodes" => v(c.begin_backup_codes(&t(0), None, None)),
        "confirmBackupCodes" => v(c.confirm_backup_codes(&t(0), &t(1))),
        "verifyBackupCode" => v(c.verify_backup_code(&t(0), &t(1))),
        other => (
            Json::Null,
            String::new(),
            Some(format!("no such door {other}")),
        ),
    }
}

struct Report {
    wrong: Vec<String>,
    written: Vec<Json>,
}

fn check_case(
    label: &str,
    case: &Json,
    tape: &Tape,
    answers: Vec<(Json, String, Option<String>)>,
    expected: Vec<&Json>,
    report: &mut Report,
) {
    let mut hashes = case["hashes"].as_object().cloned().unwrap_or_default();
    let st = tape.state.lock().unwrap();
    hashes.extend(st.hashes.clone());
    for (n, ((value, code, threw), node)) in
        answers.iter().zip(expected).enumerate()
    {
        let node_threw = node["threw"].as_str().map(str::to_string);
        if threw.is_some() != node_threw.is_some()
            || (threw.is_none()
                && (!same(&node["value"], value, &hashes)
                    || node["code"].as_str().unwrap_or("") != code))
        {
            report.wrong.push(format!(
                "{label} step {n}: Node {} {} {:?} / Rust {} {} {:?}",
                node["value"], node["code"], node_threw, value, code, threw
            ));
        }
    }
    let node_mutations =
        case["mutations"].as_array().cloned().unwrap_or_default();
    if node_mutations.len() != st.mutations.len()
        || !node_mutations
            .iter()
            .zip(&st.mutations)
            .all(|(a, b)| same(a, b, &hashes))
    {
        report.wrong.push(format!(
            "{label}: writes differ: Node {} / Rust {}",
            Json::Array(node_mutations.clone()),
            Json::Array(st.mutations.clone())
        ));
    }
    let node_observed =
        case["observed"].as_array().cloned().unwrap_or_default();
    if node_observed.len() != st.observed.len()
        || !node_observed
            .iter()
            .zip(&st.observed)
            .all(|(a, b)| same(a, b, &hashes))
    {
        report.wrong.push(format!(
            "{label}: observations differ: Node {} / Rust {}",
            Json::Array(node_observed),
            Json::Array(st.observed.clone())
        ));
    }
    if st.random != tape.random.len() {
        report.wrong.push(format!(
            "{label}: Rust drew {} random values, Node {}",
            st.random,
            tape.random.len()
        ));
    }
    if !st.misses.is_empty() {
        report.wrong.push(format!(
            "{label}: asked what Node never asked: {:?}",
            st.misses
        ));
    }
    report
        .written
        .push(json!({ "label": label, "mutations": st.mutations,
        "hashes": st.hashes }));
}

#[test]
fn credentials_answer_what_node_answers() {
    let Some(v) = vectors() else {
        eprintln!("STS_CRYPTO_VECTORS is unset or holds no credentials-node.json: nothing to check");
        return;
    };
    let mut report = Report {
        wrong: Vec::new(),
        written: Vec::new(),
    };
    let mut counted = 0;
    for list in ["totp", "backup", "apps"] {
        for (n, case) in v[list].as_array().unwrap().iter().enumerate() {
            let tape = Arc::new(Tape::new(case));
            let target = list;
            let method = case["method"].as_str().unwrap();
            let args = case["args"].as_array().cloned().unwrap_or_default();
            let answer =
                tape_realm(&tape, || mechanism(target, method, &args, &tape));
            let label = format!("{list} {n} {method}");
            check_case(
                &label,
                case,
                &tape,
                vec![answer],
                vec![case],
                &mut report,
            );
            counted += 1;
        }
    }
    for case in v["scenarios"].as_array().unwrap() {
        let tape = Arc::new(Tape::new(case));
        let c = credentials_over(&tape);
        let steps = case["steps"].as_array().unwrap();
        let answers: Vec<_> = steps
            .iter()
            .map(|st| {
                let args = st["args"].as_array().cloned().unwrap_or_default();
                step(&c, st["method"].as_str().unwrap(), &args)
            })
            .collect();
        let expected: Vec<&Json> =
            steps.iter().map(|st| &st["answer"]).collect();
        check_case(
            case["name"].as_str().unwrap(),
            case,
            &tape,
            answers,
            expected,
            &mut report,
        );
        counted += 1;
    }
    // Phishing resistance.
    for (n, row) in v["phishing"].as_array().unwrap().iter().enumerate() {
        let event = &row["event"];
        let session = json!({ "events": [event, { "authenticated": false }] });
        let mine = json!({
            "ofEvent": PhishingResistance::of_event(event),
            "ofSession": PhishingResistance::of_session(&session),
            "shortfall": PhishingResistance::hardware_shortfall_of(&session),
            "factOf": PhishingResistance::fact_of(&PhishingResistance::of_event(event)),
        });
        for k in ["ofEvent", "ofSession", "shortfall", "factOf"] {
            if mine[k] != row[k] {
                report.wrong.push(format!(
                    "phishing {n} {k}: Node {} / Rust {}",
                    row[k], mine[k]
                ));
            }
        }
        for d in row["demands"].as_array().unwrap() {
            let uris = &d["uris"];
            let (force, class, eap) = PhishingResistance::sign_in_for(uris);
            let got = json!({
                "list": PhishingResistance::uri_list(uris),
                "signIn": { "forceKey": force, "phishingClass": class, "eapOnly": eap },
                "met": PhishingResistance::eap_demand_met(&session, uris),
                "assertion": PhishingResistance::assertion_uri(&session, uris),
            });
            for k in ["list", "signIn", "met", "assertion"] {
                if got[k] != d[k] {
                    report.wrong.push(format!(
                        "phishing {n} {uris} {k}: Node {} / Rust {}",
                        d[k], got[k]
                    ));
                }
            }
        }
        counted += 1;
    }
    for row in v["phishingKeys"].as_array().unwrap() {
        if json!(PhishingResistance::stored_key_earns_hardware(&row["key"]))
            != row["earns"]
        {
            report.wrong.push(format!("phishing key {}", row["key"]));
        }
    }
    counted += webauthn::check(&v["webauthn"], &mut report.wrong);
    if std::env::var("STS_WRITE_VECTORS").is_ok() {
        let dir = std::env::var("STS_CRYPTO_VECTORS").unwrap();
        std::fs::write(
            Path::new(&dir).join("credentials-rust.json"),
            serde_json::to_string_pretty(&json!({ "cases": report.written,
                "webauthn": webauthn::written() }))
            .unwrap(),
        )
        .unwrap();
    }
    assert!(
        report.wrong.is_empty(),
        "{} of {counted} cases differ from Node:\n{}",
        report.wrong.len(),
        report.wrong.join("\n")
    );
    eprintln!("{counted} credential cases answer what Node answered");
}

/// The mechanisms read the realm through the environment only, so a case
/// needs no ambient realm entered.
fn tape_realm<R>(_tape: &Arc<Tape>, f: impl FnOnce() -> R) -> R {
    f()
}

mod webauthn {
    use serde_json::Value as Json;

    pub fn check(_v: &Json, _wrong: &mut Vec<String>) -> usize {
        0
    }

    pub fn written() -> Json {
        Json::Null
    }
}
