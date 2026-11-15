// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The ports of a realm with no policy, for a session service a test drives
//! by itself rather than by replay: the directory's subjects, every
//! mechanism allowed, the gate permitting, the settings a map, a clock the
//! test moves and random ids from `sts_crypto`.

#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use sts_authn::ports::*;
use sts_authn::{Sessions, SessionsDeps};
use sts_core::mode::Mode;
use sts_core::realm::{RealmRegistry, SettingsEnvironment};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::StoreHandles;
use sts_core::settings::Settings as CoreSettings;

pub const PEOPLE: &[(&str, &str)] = &[
    ("dora", "0b6f6c1e-8c55-4b8a-9b2e-3d1f0d5c2a11"),
    ("emil", "7d0f2a44-1b9c-4f3e-8a6d-5c2b1e9f4d22"),
    ("fay", "3c9e7b55-2d8a-4e1f-9b3c-6a5d4e2f1b33"),
    ("gil", "5e4d3c2b-1a09-4f8e-9d7c-6b5a4e3d2c55"),
];

pub struct Plain {
    pub now: Mutex<f64>,
    pub settings: Mutex<HashMap<String, Value>>,
}

impl Plain {
    pub fn new(now: f64, multiple: bool) -> Arc<Plain> {
        let settings: HashMap<String, Value> = [
            ("authn.sessionLifetimeS", json!(3600)),
            ("authn.sessionIdleTimeoutS", json!(0)),
            ("authn.pendingTtlS", json!(600)),
            ("authn.maxSessions", json!(100000)),
            ("authn.maxSessionsPerSubject", json!(32)),
            ("authn.sessionShedPerSweep", json!(100)),
            ("authn.maxBrowserAccounts", json!(10)),
            ("authn.rememberedAccountDays", json!(30)),
            ("global.https", json!(true)),
            ("authn.multipleAccounts", json!(multiple)),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        Arc::new(Plain {
            now: Mutex::new(now),
            settings: Mutex::new(settings),
        })
    }
}

impl Settings for Plain {
    fn value(&self, key: &str) -> Value {
        self.settings
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .unwrap_or(Value::Null)
    }
    fn cookie_domain_attribute(&self) -> String {
        String::new()
    }
}

impl ModeQuestions for Plain {
    fn verifies_credentials(&self) -> bool {
        true
    }
    fn revokes_access_tokens_at_sign_out(&self) -> bool {
        true
    }
}

impl Realms for Plain {
    fn retiring_refusal(&self) -> Option<Value> {
        None
    }
    fn ids(&self) -> Vec<String> {
        vec!["default".into()]
    }
    fn run_in(&self, _id: &str, work: &mut dyn FnMut()) {
        work()
    }
}

impl People for Plain {
    fn user_for(&self, username: &str) -> Value {
        json!({"sub": self.subject_for_name(username), "username": username,
               "preferred_username": username})
    }
    fn subject_for_name(&self, name: &str) -> String {
        PEOPLE
            .iter()
            .find(|p| p.0 == name)
            .map(|p| format!("urn:uuid:{}", p.1))
            .unwrap_or_default()
    }
    fn name_for_subject(&self, subject: &str) -> String {
        let id = subject.trim_start_matches("urn:uuid:");
        PEOPLE
            .iter()
            .find(|p| p.1 == id)
            .map(|p| p.0.to_string())
            .unwrap_or_default()
    }
    fn has_subject_resolver(&self) -> bool {
        true
    }
}

impl Accounts for Plain {
    fn is_disabled(&self, _who: &str) -> bool {
        false
    }
    fn service_account_refuses_door(&self, _u: &str, _d: &str) -> bool {
        false
    }
}

impl SignInPolicy for Plain {
    fn allows(&self, _m: &str, _r: &str) -> bool {
        true
    }
    fn declared_mechanisms(&self, _a: &str, _u: &str) -> Vec<String> {
        Vec::new()
    }
    fn mfa_allowed(&self, _a: &str, _u: &str) -> Vec<String> {
        Vec::new()
    }
    fn post_login_due(&self, _u: &str, _a: &str) -> Option<Value> {
        None
    }
    fn select_passkey_policy(&self, _u: &str, _a: &Value) {}
}

impl Gate for Plain {
    fn check(&self, _ask: &Value) -> Value {
        json!({"allowed": true, "why": ""})
    }
    fn device_requirement(&self) -> Vec<String> {
        Vec::new()
    }
}

impl CredentialChecks for Plain {
    fn passkey_sign_in_refusal(&self, _u: &str, _c: &Value) -> Option<Value> {
        None
    }
    fn recovery_refusal_at_session(
        &self,
        _u: &str,
        _c: &Value,
    ) -> Option<Value> {
        None
    }
    fn note_algorithm_mismatch(&self, _u: &str, _c: &Value, _v: &Value) {}
    fn note_passkey_standing(&self, _u: &str, _c: &Value, _r: &Value) {}
    fn recovery_completed(&self, _u: &str, _d: &Value) {}
}

impl Devices for Plain {
    fn recognize(&self, _a: &Value, _r: &Request) -> Result<Value, String> {
        Ok(Value::Null)
    }
    fn client_hello(&self, _r: &Request) -> Option<Value> {
        None
    }
}

impl Records for Plain {
    fn record_authentication(&self, _r: &Value, _q: Option<&Request>) {}
    fn revoke_session_tokens(
        &self,
        _s: &str,
        _a: bool,
        _r: &str,
        _o: &Value,
        _t: &[String],
    ) -> usize {
        0
    }
    fn record_account_choice(&self, _k: &str, _n: Option<u64>) {}
}

impl AuditLog for Plain {
    fn audit(&self, _row: &Value) {}
}

impl DeviceBinding for Plain {
    fn offer(&self, _r: &mut Response, _s: &Value) {}
    fn honours(&self, _s: &Value, _r: Option<&Request>) -> bool {
        true
    }
    fn note_skipped(&self, _s: &Value, _r: Option<&Request>) {}
    fn binding_of(&self, _s: &Value) -> Value {
        Value::Null
    }
}

impl Clock for Plain {
    fn now_ms(&self) -> f64 {
        *self.now.lock().unwrap()
    }
    fn random_id(&self, bytes: usize) -> String {
        SystemClock.random_id(bytes)
    }
}

/// The session service over `plain`, its stores declared in `handles`.
pub fn service(
    plain: &Arc<Plain>,
    handles: &Arc<StoreHandles>,
    lifecycle: Option<Arc<RealmLifecycle>>,
) -> (Arc<Sessions>, Arc<RealmLifecycle>) {
    let lifecycle = lifecycle.unwrap_or_else(|| {
        let settings = Arc::new(CoreSettings::new(Value::Null, HashMap::new()));
        let registry = Arc::new(RealmRegistry::new(Arc::new(
            SettingsEnvironment::new(settings.clone(), Vec::new()),
        )));
        RealmLifecycle::new(
            registry,
            settings.clone(),
            Arc::new(Mode::new(settings)),
        )
    });
    let p = plain.clone();
    let sessions = Arc::new(Sessions::new(
        SessionsDeps {
            settings: p.clone(),
            mode: p.clone(),
            realms: p.clone(),
            people: p.clone(),
            accounts: p.clone(),
            policy: p.clone(),
            gate: p.clone(),
            credentials: p.clone(),
            devices: p.clone(),
            records: p.clone(),
            audit: p.clone(),
            binding: p.clone(),
            backchannel: None,
            session_management: None,
            risk: None,
            claims: None,
            clock: p,
        },
        &lifecycle,
        handles,
    ));
    (sessions, lifecycle)
}

/// A browser: its cookies, kept as Set-Cookie lines say.
#[derive(Default, Clone)]
pub struct Jar {
    pub held: Vec<(String, String)>,
}

impl Jar {
    pub fn take(&mut self, response: &Response) {
        for line in &response.cookies {
            let first = line.split(';').next().unwrap_or("");
            let (name, value) = first.split_once('=').unwrap_or((first, ""));
            self.held.retain(|(n, _)| n != name);
            if !value.is_empty() && !line.contains("Max-Age=0") {
                self.held.push((name.to_string(), value.to_string()));
            }
        }
    }
    pub fn header(&self) -> String {
        self.held
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("; ")
    }
    pub fn request(&self) -> Request {
        Request {
            cookie: self.header(),
            user_agent: "Plain/1.0".into(),
            url: "/".into(),
            ..Request::default()
        }
    }
}

/// A password sign-in in `jar`'s browser, its cookies taken.
pub fn sign_in(
    sessions: &Sessions,
    jar: &mut Jar,
    username: &str,
) -> Option<Value> {
    let mut response = Response::default();
    let mut detail = json!({"application": "app-one",
                            "credential": {"kind": "password"}})
    .as_object()
    .cloned()
    .unwrap();
    let r = jar.request();
    let s = sessions.start_session(
        &mut response,
        username,
        &["pwd".to_string()],
        "1",
        "OAuth 2.0 / OIDC",
        &mut detail,
        Some(&r),
    );
    jar.take(&response);
    s
}
