// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE REPLAY: every port of the session core answered from what Node's
//! ports answered in the same step (`tests/tools/session-vectors.js`), and
//! every call Rust makes checked against the call Node made.
//!
//! A STATEFUL port method (an audit row, a random id, the gate's decision,
//! a notice) is a queue: Rust's n-th call of it must carry the n-th call's
//! arguments, and every recorded call must be made. A PURE one (a setting,
//! a subject, whether an account is disabled) is a lookup by arguments.
//! A request or a response crosses a port as `[request]` / `[response]`,
//! and an object's `request` and `req` members are left out of the
//! comparison: Rust hands the request to a port beside its JSON, where
//! Node put it inside.

#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::{json, Value};
use sts_authn::ports::*;

/// Port methods answered by lookup rather than by queue.
const PURE: &[&str] = &[
    "settings.value",
    "helpers.cookieDomainAttribute",
    "mode.verifiesCredentials",
    "mode.revokesAccessTokensAtSignOut",
    "realms.retiringRefusal",
    "people.userFor",
    "people.subjectForName",
    "people.nameForSubject",
    "people.hasSubjectResolver",
    "accounts.isDisabled",
    "accounts.serviceAccountRefusesDoor",
    "authnPolicy.allows",
    "mechanisms.declared",
    "mechanisms.mfaAllowed",
    "postLogin.dueFor",
    "gate.deviceRequirementOf",
    "request.clientHello",
    "backchannel.onExpiry",
    "sessionManagement.enabled",
];

/// `[request]` and `req` members out of every object.
pub fn normal(v: &Value) -> Value {
    match v {
        Value::Object(o) => Value::Object(
            o.iter()
                .filter(|(k, v)| {
                    k.as_str() != "req" && *v != &json!("[request]")
                })
                .map(|(k, v)| (k.clone(), normal(v)))
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(normal).collect()),
        other => other.clone(),
    }
}

/// One step's recorded calls, and the clock.
pub struct Replay {
    calls: Mutex<Vec<Value>>,
    used: Mutex<Vec<bool>>,
    pub problems: Mutex<Vec<String>>,
    /// Every setting any step was answered, the last answer kept: what a
    /// read Node did not make in this step is answered from.
    settings: HashMap<String, Value>,
    pub now: Mutex<f64>,
}

impl Replay {
    pub fn new(settings: HashMap<String, Value>) -> Replay {
        Replay {
            calls: Mutex::new(Vec::new()),
            used: Mutex::new(Vec::new()),
            problems: Mutex::new(Vec::new()),
            settings,
            now: Mutex::new(0.0),
        }
    }

    /// The step about to be replayed.
    pub fn step(&self, step: &Value) {
        let calls = step["calls"].as_array().cloned().unwrap_or_default();
        *self.used.lock().unwrap() = vec![false; calls.len()];
        *self.calls.lock().unwrap() = calls;
        self.problems.lock().unwrap().clear();
        *self.now.lock().unwrap() = step["now"].as_f64().unwrap_or(0.0);
    }

    fn key(row: &Value) -> String {
        format!(
            "{}.{}",
            row["port"].as_str().unwrap_or(""),
            row["method"].as_str().unwrap_or("")
        )
    }

    fn problem(&self, text: String) {
        self.problems.lock().unwrap().push(text);
    }

    /// The answer Rust's call is given.
    pub fn answer(&self, port: &str, method: &str, args: Value) -> Value {
        let key = format!("{port}.{method}");
        let args = normal(&args);
        let calls = self.calls.lock().unwrap().clone();
        if PURE.contains(&key.as_str()) {
            let found = calls.iter().find(|row| {
                Replay::key(row) == key && normal(&row["args"]) == args
            });
            if let Some(row) = found {
                return row["answer"].clone();
            }
            if key == "settings.value" {
                if let Some(v) =
                    self.settings.get(args[0].as_str().unwrap_or(""))
                {
                    return v.clone();
                }
            }
            self.problem(format!("{key}{args}: Node never asked"));
            return Value::Null;
        }
        let mut used = self.used.lock().unwrap();
        let at = (0..calls.len())
            .find(|&i| !used[i] && Replay::key(&calls[i]) == key);
        match at {
            Some(i) => {
                used[i] = true;
                let row = &calls[i];
                if normal(&row["args"]) != args {
                    drop(used);
                    self.problem(format!(
                        "{key}:\n    Rust sent {args}\n    Node sent {}",
                        normal(&row["args"])
                    ));
                }
                row["answer"].clone()
            }
            None => {
                drop(used);
                self.problem(format!("{key}{args}: one call more than Node"));
                Value::Null
            }
        }
    }

    /// Every queued call Node made that Rust did not, and every problem.
    pub fn finish(&self) -> Vec<String> {
        let used = self.used.lock().unwrap();
        let calls = self.calls.lock().unwrap();
        let mut out = self.problems.lock().unwrap().clone();
        for (i, row) in calls.iter().enumerate() {
            let key = Replay::key(row);
            if !used[i] && !PURE.contains(&key.as_str()) {
                out.push(format!(
                    "{key}{}: Node called, Rust did not",
                    normal(&row["args"])
                ));
            }
        }
        out
    }
}

fn req(r: Option<&Request>) -> Value {
    if r.is_some() {
        json!("[request]")
    } else {
        Value::Null
    }
}

fn s(v: &str) -> Value {
    json!(v)
}

impl Settings for Replay {
    fn value(&self, key: &str) -> Value {
        self.answer("settings", "value", json!([key]))
    }
    fn cookie_domain_attribute(&self) -> String {
        self.answer("helpers", "cookieDomainAttribute", json!([]))
            .as_str()
            .unwrap_or("")
            .to_string()
    }
}

impl ModeQuestions for Replay {
    fn verifies_credentials(&self) -> bool {
        self.answer("mode", "verifiesCredentials", json!([])) == json!(true)
    }
    fn revokes_access_tokens_at_sign_out(&self) -> bool {
        self.answer("mode", "revokesAccessTokensAtSignOut", json!([]))
            == json!(true)
    }
}

impl Realms for Replay {
    fn retiring_refusal(&self) -> Option<Value> {
        Some(self.answer("realms", "retiringRefusal", json!([])))
            .filter(|v| !v.is_null())
    }
    fn ids(&self) -> Vec<String> {
        vec!["default".to_string()]
    }
    fn run_in(&self, _id: &str, work: &mut dyn FnMut()) {
        work()
    }
}

impl People for Replay {
    fn user_for(&self, username: &str) -> Value {
        self.answer("people", "userFor", json!([username]))
    }
    fn subject_for_name(&self, name: &str) -> String {
        let v = self.answer("people", "subjectForName", json!([name]));
        v.as_str().unwrap_or("").to_string()
    }
    fn name_for_subject(&self, subject: &str) -> String {
        let v = self.answer("people", "nameForSubject", json!([subject]));
        v.as_str().unwrap_or("").to_string()
    }
    fn has_subject_resolver(&self) -> bool {
        self.answer("people", "hasSubjectResolver", json!([])) == json!(true)
    }
}

impl Accounts for Replay {
    fn is_disabled(&self, who: &str) -> bool {
        self.answer("accounts", "isDisabled", json!([who])) == json!(true)
    }
    fn service_account_refuses_door(&self, username: &str, door: &str) -> bool {
        self.answer(
            "accounts",
            "serviceAccountRefusesDoor",
            json!([username, door]),
        ) == json!(true)
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

impl SignInPolicy for Replay {
    fn allows(&self, mechanism: &str, role: &str) -> bool {
        self.answer("authnPolicy", "allows", json!([mechanism, role]))
            == json!(true)
    }
    fn declared_mechanisms(
        &self,
        application: &str,
        username: &str,
    ) -> Vec<String> {
        let v = self.answer(
            "mechanisms",
            "declared",
            json!([application, username]),
        );
        strings(&v["allowed"])
    }
    fn mfa_allowed(&self, application: &str, username: &str) -> Vec<String> {
        strings(&self.answer(
            "mechanisms",
            "mfaAllowed",
            json!([application, username]),
        ))
    }
    fn post_login_due(
        &self,
        username: &str,
        application: &str,
    ) -> Option<Value> {
        Some(self.answer("postLogin", "dueFor", json!([username, application])))
            .filter(|v| !v.is_null())
    }
    fn select_passkey_policy(&self, username: &str, application: &Value) {
        self.answer("passkeyPolicy", "select", json!([username, application]));
    }
}

impl Gate for Replay {
    fn check(&self, ask: &Value) -> Value {
        self.answer("gate", "check", json!([ask]))
    }
    fn device_requirement(&self) -> Vec<String> {
        strings(&self.answer("gate", "deviceRequirementOf", json!([])))
    }
}

fn opt(v: Value) -> Option<Value> {
    Some(v).filter(|v| !v.is_null())
}

impl CredentialChecks for Replay {
    fn passkey_sign_in_refusal(
        &self,
        username: &str,
        credential: &Value,
    ) -> Option<Value> {
        opt(self.answer(
            "credentials",
            "passkeySignInRefusal",
            json!([username, credential]),
        ))
    }
    fn recovery_refusal_at_session(
        &self,
        username: &str,
        credential: &Value,
    ) -> Option<Value> {
        opt(self.answer(
            "credentials",
            "recoveryRefusalAtSession",
            json!([username, credential]),
        ))
    }
    fn note_algorithm_mismatch(
        &self,
        username: &str,
        credential: &Value,
        via: &Value,
    ) {
        self.answer(
            "credentials",
            "noteAlgorithmMismatch",
            json!([username, credential, via]),
        );
    }
    fn note_passkey_standing(
        &self,
        username: &str,
        credential: &Value,
        refusal: &Value,
    ) {
        self.answer(
            "credentials",
            "notePasskeyStanding",
            json!([username, credential, refusal]),
        );
    }
    fn recovery_completed(&self, username: &str, detail: &Value) {
        self.answer(
            "credentials",
            "recoveryCompleted",
            json!([username, detail]),
        );
    }
}

impl Devices for Replay {
    fn recognize(
        &self,
        ask: &Value,
        _request: &Request,
    ) -> Result<Value, String> {
        Ok(self.answer("devices", "recognize", json!([ask])))
    }
    fn client_hello(&self, _request: &Request) -> Option<Value> {
        opt(self.answer("request", "clientHello", json!(["[request]"])))
    }
}

impl Records for Replay {
    fn record_authentication(
        &self,
        record: &Value,
        _request: Option<&Request>,
    ) {
        self.answer("stats", "recordAuthentication", json!([record]));
    }
    fn revoke_session_tokens(
        &self,
        _sid: &str,
        _revokes_access: bool,
        reason: &str,
        opts: &Value,
        tags: &[String],
    ) -> usize {
        self.answer("stats", "revokeWhere", json!([null, reason, opts, tags]))
            .as_u64()
            .unwrap_or(0) as usize
    }
}

impl AuditLog for Replay {
    fn audit(&self, row: &Value) {
        self.answer("audit", "audit", json!([row]));
    }
}

impl SessionObserver for Replay {
    fn notice(
        &self,
        notice: &Value,
        _request: Option<&Request>,
    ) -> Result<(), String> {
        self.answer("observer", "notice", json!([notice]));
        Ok(())
    }
}

impl DeviceBinding for Replay {
    fn offer(&self, _response: &mut Response, session: &Value) {
        self.answer("deviceBound", "offer", json!(["[response]", session]));
    }
    fn honours(&self, session: &Value, request: Option<&Request>) -> bool {
        self.answer("deviceBound", "honours", json!([session, req(request)]))
            == json!(true)
    }
    fn note_skipped(&self, session: &Value, request: Option<&Request>) {
        self.answer(
            "deviceBound",
            "noteSkipped",
            json!([session, req(request)]),
        );
    }
    fn binding_of(&self, session: &Value) -> Value {
        self.answer("deviceBound", "bindingOf", json!([session]))
    }
}

impl Backchannel for Replay {
    fn on_expiry(&self) -> bool {
        self.answer("backchannel", "onExpiry", json!([])) == json!(true)
    }
    fn plan(&self, session: &Value, opts: &Value) -> Value {
        self.answer("backchannel", "plan", json!([session, opts]))
    }
    fn dispatch(&self, planned: &Value) {
        self.answer("backchannel", "dispatch", json!([planned]));
    }
}

impl SessionManagement for Replay {
    fn enabled(&self) -> bool {
        self.answer("sessionManagement", "enabled", json!([])) == json!(true)
    }
    fn write_cookie(&self, _response: &mut Response, value: &str) {
        self.answer(
            "sessionManagement",
            "writeCookie",
            json!(["[response]", s(value)]),
        );
    }
}

impl RiskAssessment for Replay {
    fn assess(
        &self,
        session: &Value,
        event: &Value,
        via: &Value,
        detail: &Value,
    ) {
        self.answer("risk", "assess", json!([session, event, via, detail]));
    }
}

impl Clock for Replay {
    fn now_ms(&self) -> f64 {
        *self.now.lock().unwrap()
    }
    fn random_id(&self, bytes: usize) -> String {
        self.answer("random", "id", json!([bytes]))
            .as_str()
            .unwrap_or("")
            .to_string()
    }
}
