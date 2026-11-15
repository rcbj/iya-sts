// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The sign-out over the REAL session core and token register — the parts
//! the vectors hold as ports, put together as the runtime puts them
//! ([`sts_logout::wiring`]): `sts-authn`'s `Sessions`, whose
//! `drop_session()` is every session's end, and `sts-oauth`'s
//! `SessionTokens` over its `TokenRegister`.
//!
//! What it holds, in development and in product:
//!
//! * the page's act (`POST /authn-api/logout`) with nothing ticked is a
//!   GLOBAL sign-out: every session the person holds ends, every token
//!   listed is revoked, the browser's cookie is cleared and
//!   `Clear-Site-Data` sent;
//! * ticking ONE session ends that one and no other, and its END revokes
//!   what the session was issued: its online refresh token always (RFC
//!   9700 section 2.2.2, `oauth2.revokeRefreshOnLogout`), its ACCESS
//!   token only in product (#1449), an `offline_access` refresh token
//!   never — the root `CLAUDE.md`'s index row, "except that in product a
//!   sign-out revokes the session's access tokens";
//! * and the old cookie no longer names a live session.

#![allow(clippy::unwrap_used, clippy::expect_used)]

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
use sts_logout::ports::{Asked, HostPort, Reply};
use sts_logout::wiring::{IdentityKeys, SessionsPort, TokensPort, Unported};
use sts_logout::{Logout, LogoutDeps};
use sts_oauth::minted::{IssuedUnder, SessionTokens, TokenRegister};

const DORA: &str = "urn:uuid:0b6f6c1e-8c55-4b8a-9b2e-3d1f0d5c2a11";

struct Plain {
    product: bool,
}

impl Settings for Plain {
    fn value(&self, key: &str) -> Value {
        match key {
            "authn.sessionLifetimeS" => json!(3600),
            "authn.sessionIdleTimeoutS" => json!(0),
            "authn.pendingTtlS" => json!(600),
            "authn.maxSessions" => json!(100000),
            "authn.maxSessionsPerSubject" => json!(32),
            "authn.multipleAccounts" => json!(false),
            "global.https" => json!(true),
            _ => Value::Null,
        }
    }
    fn cookie_domain_attribute(&self) -> String {
        String::new()
    }
}

impl ModeQuestions for Plain {
    fn verifies_credentials(&self) -> bool {
        self.product
    }
    fn revokes_access_tokens_at_sign_out(&self) -> bool {
        self.product
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
        json!({ "sub": self.subject_for_name(username), "username": username,
                "preferred_username": username })
    }
    fn subject_for_name(&self, name: &str) -> String {
        if name == "dora" {
            DORA.into()
        } else {
            String::new()
        }
    }
    fn name_for_subject(&self, subject: &str) -> String {
        if subject == DORA {
            "dora".into()
        } else {
            String::new()
        }
    }
    fn has_subject_resolver(&self) -> bool {
        true
    }
}

impl Accounts for Plain {
    fn is_disabled(&self, _w: &str) -> bool {
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
    fn check(&self, _a: &Value) -> Value {
        json!({ "allowed": true, "why": "" })
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

/// The host: the sign-out's settings, the mode, one realm.
struct Host {
    product: bool,
    audited: Mutex<Vec<Value>>,
}

impl HostPort for Host {
    fn setting(&self, key: &str) -> Value {
        match key {
            "logout.maxRows" => json!(200),
            "logout.anyUser" => json!(true),
            "logout.ldapDisconnect" => json!(true),
            "logout.kerberosSignOut" => json!(true),
            "account.recentAuthMinutes" => json!(15),
            _ => Value::Null,
        }
    }
    fn opens_test_controls(&self) -> bool {
        !self.product
    }
    fn verifies_credentials(&self) -> bool {
        self.product
    }
    fn audit(&self, row: &Value) {
        self.audited.lock().unwrap().push(row.clone());
    }
    fn audit_failure(&self, _code: &str, _row: &Value) {}
    fn subject_for_name(&self, name: &str) -> String {
        Plain { product: false }.subject_for_name(name)
    }
    fn name_for_subject(&self, subject: &str) -> String {
        Plain { product: false }.name_for_subject(subject)
    }
    fn result_secret(&self) -> Vec<u8> {
        b"real-sessions".to_vec()
    }
    fn subject_terminated(&self, _r: &str, _k: &str) {}
    fn person_signed_out(&self, _k: &str) {}
    fn realm_id(&self) -> String {
        sts_core::realm::current_id()
    }
    fn realm_prefix(&self) -> String {
        String::new()
    }
    fn now_ms(&self) -> f64 {
        chrono::Utc::now().timestamp_millis() as f64
    }
}

struct World {
    logout: Logout,
    sessions: Arc<Sessions>,
    register: Arc<TokenRegister>,
    cookies: Vec<String>,
    sids: Vec<String>,
}

fn world(product: bool) -> World {
    let settings = Arc::new(CoreSettings::new(Value::Null, HashMap::new()));
    let registry = Arc::new(RealmRegistry::new(Arc::new(
        SettingsEnvironment::new(settings.clone(), Vec::new()),
    )));
    let lifecycle = RealmLifecycle::new(
        registry,
        settings.clone(),
        Arc::new(Mode::new(settings.clone())),
    );
    let handles = StoreHandles::new();
    let revoked = sts_oauth::revocation::RevokedTokens::new(
        &lifecycle,
        &handles,
        settings.clone(),
    );
    let register =
        TokenRegister::new(&lifecycle, &handles, settings.clone(), revoked);
    let records = Arc::new(SessionTokens {
        inner: None,
        register: register.clone(),
        revoke_refresh_on_logout: Arc::new(|_c: &str| true),
        now_ms: Arc::new(|| chrono::Utc::now().timestamp_millis()),
    });
    let p = Arc::new(Plain { product });
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
            records,
            audit: p.clone(),
            binding: p.clone(),
            backchannel: None,
            session_management: None,
            risk: None,
            claims: None,
            clock: Arc::new(SystemClock),
        },
        &lifecycle,
        &handles,
    ));
    let mut cookies = Vec::new();
    let mut sids = Vec::new();
    for _ in 0..2 {
        let mut response = Response::default();
        let mut detail = serde_json::Map::new();
        let s = sessions
            .start_session(
                &mut response,
                "dora",
                &["pwd".to_string()],
                "1",
                "OAuth 2.0 / OIDC",
                &mut detail,
                Some(&Request::default()),
            )
            .expect("a session");
        sids.push(s["id"].as_str().unwrap().to_string());
        let line = response.cookies.first().cloned().unwrap();
        cookies.push(line.split(';').next().unwrap().to_string());
    }
    let realm = sts_core::realm::current_id();
    let now = chrono::Utc::now().timestamp_millis();
    let exp = now / 1000 + 600;
    for (i, sid) in sids.iter().enumerate() {
        let under = IssuedUnder {
            session_id: sid.clone(),
            ..IssuedUnder::default()
        };
        for (jti, typ, scope) in [
            (format!("at-{}", i), "Bearer", "openid"),
            (format!("rt-{}", i), "Refresh", "openid"),
            (format!("off-{}", i), "Refresh", "openid offline_access"),
        ] {
            register.record_jwt(
                &realm,
                &json!({ "jti": jti, "typ": typ, "sub": DORA,
                         "username": "dora", "client_id": "appA",
                         "scope": scope, "exp": exp }),
                "signed",
                &under,
                now,
            );
        }
    }
    let people: Arc<dyn People> = p.clone();
    let unported = Arc::new(Unported {
        settings: settings.clone(),
    });
    let logout = Logout::new(LogoutDeps {
        authn: Arc::new(SessionsPort {
            sessions: sessions.clone(),
            begin: Arc::new(|_o: &Value| "/authn/login?authn=x".to_string()),
        }),
        stats: Arc::new(TokensPort {
            keys: IdentityKeys { people },
            register: Some(register.clone()),
            settings,
        }),
        frontchannel: unported.clone(),
        backchannel: unported.clone(),
        wsfed: unported.clone(),
        saml2: unported.clone(),
        federation_slo: unported.clone(),
        oauth2: unported.clone(),
        oid4vc: unported.clone(),
        krb5: unported.clone(),
        ldap: unported.clone(),
        gnap: unported.clone(),
        grants: unported.clone(),
        uma: unported,
        host: Arc::new(Host {
            product,
            audited: Mutex::new(Vec::new()),
        }),
    });
    World {
        logout,
        sessions,
        register,
        cookies,
        sids,
    }
}

fn asked(cookie: &str) -> Asked {
    Asked {
        request: Request {
            cookie: cookie.to_string(),
            ..Request::default()
        },
        base: "https://sts.example".into(),
        ..Asked::default()
    }
}

fn revoked(w: &World, jti: &str) -> bool {
    let realm = sts_core::realm::current_id();
    w.register
        .get(&realm, jti)
        .is_some_and(|r| r["revoked"] == json!(true))
}

#[test]
fn the_default_is_global_and_clears_the_cookie() {
    for product in [false, true] {
        let w = world(product);
        let mut reply = Reply::default();
        let body = serde_json::Map::new();
        let got = w
            .logout
            .sign_out_act(&asked(&w.cookies[0]), &mut reply, &body)
            .unwrap();
        assert_eq!(got.status, 200, "{:?}", got);
        assert_eq!(got.json["scope"], json!("global"));
        assert_eq!(got.json["ownSessionEnded"], json!(true));
        for sid in &w.sids {
            assert!(w.sessions.session_by_id(sid).is_none(), "{} ended", sid);
        }
        for jti in ["at-0", "rt-0", "off-0", "at-1", "rt-1", "off-1"] {
            assert!(revoked(&w, jti), "{} revoked by the global sign-out", jti);
        }
        assert!(
            reply
                .cookies
                .iter()
                .any(|c| c.starts_with("sts_session=; Path=/; Max-Age=0")),
            "the cookie cleared: {:?}",
            reply.cookies
        );
        assert!(reply
            .headers
            .contains(&("clear-site-data".into(), "\"storage\"".into())));
        assert!(
            w.sessions
                .session_of(&asked(&w.cookies[0]).request, false)
                .is_none(),
            "the old cookie names nobody"
        );
        // What is left is the Kerberos row Node always draws (this realm
        // has no KDC principal for her), which nothing can end.
        assert_eq!(got.json["view"]["remaining"], json!(1));
        assert!(w.logout.held_ids("dora").unwrap().is_empty());
    }
}

#[test]
fn one_sessions_end_revokes_what_it_was_issued_by_mode() {
    for product in [false, true] {
        let w = world(product);
        let mut reply = Reply::default();
        let mut body = serde_json::Map::new();
        body.insert("scope".into(), json!("selected"));
        body.insert("select".into(), json!([format!("session:{}", w.sids[0])]));
        let got = w
            .logout
            .sign_out_act(&asked(&w.cookies[0]), &mut reply, &body)
            .unwrap();
        assert_eq!(got.status, 200, "{:?}", got);
        assert!(w.sessions.session_by_id(&w.sids[0]).is_none());
        assert!(
            w.sessions.session_by_id(&w.sids[1]).is_some(),
            "not the other"
        );
        assert_eq!(
            revoked(&w, "at-0"),
            product,
            "the session's access token, revoked in product only (#1449)"
        );
        assert!(revoked(&w, "rt-0"), "its online refresh token, always");
        assert!(!revoked(&w, "off-0"), "offline_access outlives the session");
        for jti in ["at-1", "rt-1", "off-1"] {
            assert!(!revoked(&w, jti), "the other session's {}", jti);
        }
        assert!(reply.cookies.iter().any(|c| c.starts_with("sts_session=;")));
    }
}
