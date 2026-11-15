// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The sessions' two-way proof over a REAL store (#444 phase 5; rcbj,
//! 2026-11-14: the Rust runtime upgrades a 1.x install in place, so a person
//! signed in before the upgrade is signed in after it, and the reverse).
//! Node's half is `tests/tools/session-interop.js`; both run against one
//! PostgreSQL with `postgres/schema.sql` applied (`STS_TEST_DATABASE_URL`),
//! sharing one durable key-encryption key in `STS_INTEROP_DIR`, which is
//! never committed. In order:
//!
//! 1. `session-interop.js write` — Node signs people in through
//!    `authn.ts`'s `startSession()` and flushes them with
//!    `persistence_minted.js`;
//! 2. [`rust_honours_what_node_wrote`] — this runtime's persistence restores
//!    them into [`Sessions`]'s store, and each cookie Node wrote is honoured
//!    by [`Sessions::session_of`], the row Node's own, member for member;
//!    the session Node ended stays ended;
//! 3. with `STS_INTEROP_WRITE=1`, [`rust_signs_in_for_node`] — the minted
//!    tables cleared, people signed in through [`Sessions::start_session`]
//!    and flushed by this runtime's minted persistence, one ended, and what
//!    was written recorded in `session-interop-rust.json`;
//! 4. `session-interop.js read` — Node restores them and holds its own
//!    doors to them.
//!
//! The ports are what a composition root would pass for a realm with no
//! policy: the directory's subjects, every mechanism allowed, the gate
//! permitting. With either variable unset it says so and passes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use sts_authn::js::Object;
use sts_authn::ports::*;
use sts_authn::{Sessions, SessionsDeps};
use sts_core::mode::Mode;
use sts_core::realm::{RealmRegistry, SettingsEnvironment};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::StoreHandles;
use sts_core::settings::Settings as CoreSettings;
use sts_store::persistence::{MemoryDirectory, Persistence, StoreMode};
use sts_store::postgres::PostgresDriver;

const PEOPLE: &[(&str, &str)] = &[
    ("dora", "0b6f6c1e-8c55-4b8a-9b2e-3d1f0d5c2a11"),
    ("fay", "3c9e7b55-2d8a-4e1f-9b3c-6a5d4e2f1b33"),
    ("gil", "5e4d3c2b-1a09-4f8e-9d7c-6b5a4e3d2c55"),
];

fn setting() -> Option<(String, PathBuf)> {
    let url = std::env::var("STS_TEST_DATABASE_URL").ok()?;
    let dir = std::env::var("STS_INTEROP_DIR").ok()?;
    Some((url, PathBuf::from(dir)))
}

/// The ports of a realm with no policy.
struct Plain {
    now: Mutex<f64>,
}

impl Settings for Plain {
    fn value(&self, key: &str) -> Value {
        match key {
            "authn.sessionLifetimeS" => json!(3600),
            "authn.pendingTtlS" => json!(600),
            "authn.maxSessions" => json!(100000),
            "authn.maxSessionsPerSubject" => json!(32),
            "authn.sessionShedPerSweep" => json!(100),
            "global.https" => json!(true),
            "authn.multipleAccounts" => json!(false),
            _ => Value::Null,
        }
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

struct Proc {
    persistence: Arc<Persistence>,
    sessions: Arc<Sessions>,
    plain: Arc<Plain>,
}

fn proc(url: &str, dir: &std::path::Path, now: f64) -> Proc {
    let env: HashMap<String, String> = [
        ("STS_MODE", "product"),
        ("STS_KEYS_SOURCE", "persisted"),
        ("STS_KEYS_KEK_PROVIDER", "file"),
        ("STS_SECRETS_ALLOW_LOCAL_SECRETS", "true"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .chain(std::iter::once((
        "STS_KEYS_KEK_FILE".to_string(),
        dir.join("interop-kek.txt").to_str().unwrap().to_string(),
    )))
    .collect();
    let settings = Arc::new(CoreSettings::new(
        json!({"persistence": {"writeDelay": 0}}),
        env,
    ));
    let registry = Arc::new(RealmRegistry::new(Arc::new(
        SettingsEnvironment::new(settings.clone(), Vec::new()),
    )));
    let lifecycle = RealmLifecycle::new(
        registry,
        settings.clone(),
        Arc::new(Mode::new(settings.clone())),
    );
    let handles = StoreHandles::new();
    let plain = Arc::new(Plain {
        now: Mutex::new(now),
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
        &handles,
    ));
    let persistence = Persistence::new(
        StoreMode::Postgres,
        Some(Arc::new(PostgresDriver::new(url, false, 4).unwrap())),
        settings,
        lifecycle,
        Arc::new(MemoryDirectory::default()),
    );
    persistence.attach_minted(handles);
    Proc {
        persistence,
        sessions,
        plain,
    }
}

fn request(cookie: &str) -> Request {
    Request {
        cookie: format!("sts_session={}", cookie),
        user_agent: "Interop/1.0".into(),
        ..Request::default()
    }
}

#[tokio::test]
async fn rust_honours_what_node_wrote() {
    let Some((url, dir)) = setting() else {
        eprintln!("STS_TEST_DATABASE_URL or STS_INTEROP_DIR unset: skipped");
        return;
    };
    if std::env::var("STS_INTEROP_WRITE").is_ok() {
        return;
    }
    let Ok(text) =
        std::fs::read_to_string(dir.join("session-interop-node.json"))
    else {
        eprintln!("no session-interop-node.json: skipped");
        return;
    };
    let v: Value = serde_json::from_str(&text).unwrap();
    let p = proc(&url, &dir, v["now"].as_f64().unwrap());
    p.persistence.start().await.unwrap();
    let mut failures = Vec::new();
    for one in v["sessions"].as_array().unwrap() {
        let name = one["name"].as_str().unwrap();
        let cookie = one["cookie"].as_str().unwrap();
        let row = &one["row"];
        match p.sessions.session_of(&request(cookie), false) {
            None => failures.push(format!(
                "{name}: the cookie Node wrote names no live session here"
            )),
            Some(s) => {
                if serde_json::to_string(&s).unwrap()
                    != serde_json::to_string(row).unwrap()
                {
                    failures.push(format!(
                        "{name}:\n    Rust restored {s}\n    Node wrote {row}"
                    ));
                }
            }
        }
        if !p
            .sessions
            .session_is_live(one["sid"].as_str().unwrap(), None)
        {
            failures.push(format!("{name}: session_is_live() says no"));
        }
    }
    let ended = v["ended"].as_str().unwrap();
    if p.sessions.session_by_id(ended).is_some() {
        failures.push("the session Node ended came back here".into());
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    eprintln!(
        "Rust honours all {} session(s) Node flushed, and the one it ended \
         stays ended",
        v["sessions"].as_array().unwrap().len()
    );
}

async fn clear(url: &str) {
    let mut tls =
        openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())
            .unwrap();
    tls.set_verify(openssl::ssl::SslVerifyMode::NONE);
    let mut connector = postgres_openssl::MakeTlsConnector::new(tls.build());
    connector.set_callback(|c, _| {
        c.set_verify_hostname(false);
        Ok(())
    });
    let (client, conn) = tokio_postgres::connect(url, connector).await.unwrap();
    tokio::spawn(conn);
    for table in [
        "sts_minted",
        "sts_minted_index",
        "sts_sessions",
        "sts_changes",
    ] {
        client
            .execute(&format!("DELETE FROM {}", table), &[])
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn rust_signs_in_for_node() {
    let Some((url, dir)) = setting() else {
        eprintln!("STS_TEST_DATABASE_URL or STS_INTEROP_DIR unset: skipped");
        return;
    };
    if std::env::var("STS_INTEROP_WRITE").is_err() {
        return;
    }
    clear(&url).await;
    let now = sts_core::time::now_ms_f64().floor();
    let p = proc(&url, &dir, now);
    p.persistence.start().await.unwrap();
    let start = |username: &str,
                 amr: &[&str],
                 acr: &str,
                 via: &str,
                 detail: Value,
                 cookie: &str| {
        let mut response = Response::default();
        let mut d: Object = detail.as_object().cloned().unwrap();
        let amr: Vec<String> = amr.iter().map(|a| a.to_string()).collect();
        let r = Request {
            cookie: if cookie.is_empty() {
                String::new()
            } else {
                format!("sts_session={}", cookie)
            },
            user_agent: "Interop/1.0".into(),
            ..Request::default()
        };
        let s = p
            .sessions
            .start_session(
                &mut response,
                username,
                &amr,
                acr,
                via,
                &mut d,
                Some(&r),
            )
            .unwrap_or_else(|| panic!("{username} was refused: {d:?}"));
        let line = response.cookies.first().cloned().unwrap_or_default();
        let value = line
            .split(';')
            .next()
            .unwrap_or("")
            .trim_start_matches("sts_session=")
            .to_string();
        (
            s,
            if value.is_empty() {
                cookie.to_string()
            } else {
                value
            },
        )
    };
    let (dora, c) = start(
        "dora",
        &["pwd"],
        "1",
        "OAuth 2.0 / OIDC",
        json!({"application": "app-one", "credential": {"kind": "password"}}),
        "",
    );
    *p.plain.now.lock().unwrap() = now + 30_000.0;
    let (up, c) = start(
        "dora",
        &["pwd", "otp"],
        "mfa",
        "OAuth 2.0 / OIDC",
        json!({"application": "app-two", "credential": {"kind": "totp"}}),
        &c,
    );
    assert_eq!(dora["id"], up["id"], "a step-up keeps the sid");
    let mut out = vec![json!({"name": "a password sign-in stepped up",
        "cookie": c, "sid": up["id"]})];
    let (fay, c) = start(
        "fay",
        &["hwk", "user"],
        "mfa",
        "OAuth 2.0 / OIDC",
        json!({"application": "app-one", "credential": {"kind": "webauthn",
            "id": "cred-fay", "ceremony": "assertion",
            "backupEligible": false, "attestationTrusted": true,
            "algorithm": "ES256", "coseAlg": -7, "lane": "classical"}}),
        "",
    );
    out.push(json!({"name": "a passkey sign-in", "cookie": c,
        "sid": fay["id"]}));
    let (gil, c) = start(
        "gil",
        &["pwd"],
        "1",
        "SAML 2.0",
        json!({"application": "sp-one",
            "credential": {"kind": "federation", "relationship": "p1"},
            "federation": {"id": "p1", "peer": "https://idp.example",
                           "subject": "g-1"},
            "fedPartnerSession": {"relationship": "p1",
                                  "sessionIndex": "idx-1"},
            "sessionNotOnOrAfter": now + 20.0 * 60.0 * 1000.0}),
        "",
    );
    out.push(
        json!({"name": "a federated sign-in, bounded by its partner",
        "cookie": c, "sid": gil["id"]}),
    );
    let (gone, _) = start(
        "gil",
        &["pwd"],
        "1",
        "OAuth 2.0 / OIDC",
        json!({"application": "app-one", "credential": {"kind": "password"}}),
        "",
    );
    let ended = gone["id"].as_str().unwrap().to_string();
    p.sessions
        .end_session_by_id(&ended, "the interop proof", "admin")
        .unwrap();
    p.persistence.flush().await.unwrap();
    for one in out.iter_mut() {
        let row = p.sessions.session_by_id(one["sid"].as_str().unwrap());
        one["row"] = row.unwrap();
    }
    std::fs::write(
        dir.join("session-interop-rust.json"),
        serde_json::to_string_pretty(&json!({"now": now + 30_000.0,
            "sessions": out, "ended": ended}))
        .unwrap(),
    )
    .unwrap();
    eprintln!(
        "Rust signed in {} session(s), ended one, and flushed them",
        3
    );
}
