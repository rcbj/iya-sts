// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE HAND-OFF TO SIGN-IN (`authn/authn.ts`'s `beginAuthentication()`): a
//! protocol with nobody signed in writes a PENDING SIGN-IN — where to come
//! back to, why, and how the person is to authenticate — and sends the
//! browser to the screen that row names. The sign-in surface
//! (`/authn-api`, `sts-authn-api`) reads the row and, once a session is
//! made, returns the browser to `returnTo`, so the authorization request is
//! answered again, this time with a session.
//!
//! [`SignInHandOff`] is the port the authorization endpoint calls;
//! [`PendingSignIns`] is Node's body over the `authn.pending` store, the
//! row Node's, member for member:
//!
//! * the account half (#561) first, through the session core's
//!   `begin_account_choice()` and `route_to_accounts()`: the picker where a
//!   browser holding several accounts named none, or the request asked for
//!   it (`prompt=select_account`);
//! * then `beginAuthenticationHere()`: the application's mechanism
//!   (`mechanismFor()`), the record, and the screen — `/authn/login`, or
//!   the wallet's or SPNEGO's door where the application's entry declares
//!   one.
//!
//! WHAT IS NOT HERE, and what is answered meanwhile: an
//! identity-provider-side federation relationship brokering the sign-in
//! and a `domain_hint` naming a home realm (`federation.authenticationFor()`,
//! `homeRealmFor()`, phase 7): the person is sent to the screen, as for an
//! application with no relationship; the multi-cell restart record (cells
//! are phase 9: single cell, nothing to record). The application's own
//! mechanisms come through [`MechanismPolicy`], whose default answers what
//! Node answers for an entry naming none.

use std::sync::Arc;

use serde_json::{json, Map, Value as Json};
use sts_authn::ports::Request;
use sts_authn::Sessions;
use sts_core::realm_store::RealmMap;
use sts_core::settings::Settings;

/// `LOGIN_PATH`, `SPNEGO_PATH`, `WALLET_PATH`.
pub const LOGIN_PATH: &str = "/authn/login";
pub const SPNEGO_PATH: &str = "/authn/spnego";
pub const WALLET_PATH: &str = "/authn/wallet";

/// What a protocol asks of the sign-in (`beginAuthentication(opts)`).
#[derive(Debug, Clone, Default)]
pub struct Begin {
    pub return_to: String,
    pub details: Json,
    pub hint: String,
    pub locked_username: String,
    pub force_mfa: bool,
    pub force_key: bool,
    pub phishing_class: String,
    /// `always`, `never` or ''.
    pub account_choice: String,
    pub reauthentication: String,
    pub protocol: String,
    pub application: String,
    pub ui_locales: String,
    pub domain_hint: String,
}

/// The hand-off the authorization endpoint makes.
pub trait SignInHandOff: Send + Sync {
    /// The path to send the browser to, or why none could be made.
    fn begin_authentication(
        &self,
        begin: &Begin,
        request: &Request,
    ) -> Result<String, String>;
}

/// The application's authentication mechanisms
/// (`authn_policy.mechanismsFor(fields, person)` through
/// `declaredMechanismsFor()`): the ids it allows, empty for every one.
pub trait MechanismPolicy: Send + Sync {
    fn allowed_for(&self, application: &str) -> Vec<String>;
}

/// No application narrows its mechanisms.
pub struct EveryMechanism;

impl MechanismPolicy for EveryMechanism {
    fn allowed_for(&self, _application: &str) -> Vec<String> {
        Vec::new()
    }
}

/// `federation.MECHANISM_IDS`.
const MECHANISM_IDS: [&str; 6] = [
    "password",
    "password-mfa",
    "webauthn",
    "spnego",
    "wallet",
    "federation",
];

/// `mechanismFor()`'s answer, without the federation half.
struct Chosen {
    mechanism: String,
    source: String,
    problem: String,
    allowed: Vec<String>,
}

/// What the hand-off asks of the session core: the pending row's lifetime
/// and the account half (#561).
pub trait AccountChoices: Send + Sync {
    /// `pendingTtlMs()`.
    fn pending_ttl_ms(&self) -> f64;
    /// `begin_account_choice()`: `(pick, hint)`, or `None` with the setting
    /// off.
    fn begin_account_choice(
        &self,
        request: &Request,
        account_choice: &str,
        hinted: bool,
    ) -> Option<(String, Option<String>)>;
    /// `routeToAccounts()`: the record to set and the picker's address.
    fn route_to_accounts(
        &self,
        existing: Option<Map<String, Json>>,
        opts: &Json,
        target: &str,
        why: &str,
        request: &Request,
    ) -> (Map<String, Json>, String);
}

impl AccountChoices for Sessions {
    fn pending_ttl_ms(&self) -> f64 {
        Sessions::pending_ttl_ms(self)
    }

    fn begin_account_choice(
        &self,
        request: &Request,
        account_choice: &str,
        hinted: bool,
    ) -> Option<(String, Option<String>)> {
        Sessions::begin_account_choice(
            self,
            Some(request),
            account_choice,
            hinted,
        )
        .map(|c| (c.pick, c.hint))
    }

    fn route_to_accounts(
        &self,
        existing: Option<Map<String, Json>>,
        opts: &Json,
        target: &str,
        why: &str,
        request: &Request,
    ) -> (Map<String, Json>, String) {
        Sessions::route_to_accounts(
            self,
            existing,
            opts,
            target,
            why,
            Some(request),
        )
    }
}

/// Node's `beginAuthentication()` over the `authn.pending` store.
pub struct PendingSignIns {
    pub sessions: Arc<dyn AccountChoices>,
    pub pending: RealmMap<Json>,
    pub settings: Arc<Settings>,
    pub mechanisms: Arc<dyn MechanismPolicy>,
    pub random_id: Arc<dyn Fn(usize) -> String + Send + Sync>,
    pub now_ms: Arc<dyn Fn() -> f64 + Send + Sync>,
}

impl PendingSignIns {
    /// `declaredMechanismsFor()` and `mechanismFor()` with no federation
    /// relationship to ask.
    fn mechanism_for(&self, application: &str) -> Chosen {
        let wanted = application.trim();
        if wanted.is_empty() {
            return Chosen {
                mechanism: "password".into(),
                source: "default".into(),
                problem: String::new(),
                allowed: Vec::new(),
            };
        }
        let allowed = self.mechanisms.allowed_for(wanted);
        let mut problems: Vec<String> = Vec::new();
        let usable: Vec<String> = allowed
            .iter()
            .filter(|declared| {
                if !MECHANISM_IDS.contains(&declared.as_str()) {
                    problems.push(format!(
                        "The application \"{}\" allows the authentication mechanism \"{}\", which is not one this service has: they are {}.",
                        wanted, declared, MECHANISM_IDS.join(", ")));
                    return false;
                }
                if declared.as_str() == "spnego"
                    && !self.settings.value_of("krb5.spnegoAuthentication").as_bool()
                {
                    problems.push(format!(
                        "The application \"{}\" allows signing in with a Kerberos ticket over SPNEGO, and krb5.spnegoAuthentication is off on this service, so that door is not offered.",
                        wanted));
                    return false;
                }
                if declared.as_str() == "wallet"
                    && !self.settings.value_of("oid4vp.signIn").as_bool()
                {
                    problems.push(format!(
                        "The application \"{}\" allows signing in with a wallet, and oid4vp.signIn is off on this service, so that door is not offered.",
                        wanted));
                    return false;
                }
                true
            })
            .cloned()
            .collect();
        if !allowed.is_empty() && usable.is_empty() {
            problems.push(format!(
                "None of the mechanisms \"{}\" allows can be offered here, so nobody can sign in to it until its authentication policy (appAuthnPolicy) or this service's settings change.",
                wanted));
        }
        let problem = problems.join(" ");
        if usable.len() == 1 && usable[0] != "federation" {
            return Chosen {
                mechanism: usable[0].clone(),
                source: "application".into(),
                problem,
                allowed,
            };
        }
        if usable.len() > 1 || (!allowed.is_empty() && usable.is_empty()) {
            return Chosen {
                mechanism: "password".into(),
                source: "application".into(),
                problem,
                allowed,
            };
        }
        if usable.len() == 1 {
            return Chosen {
                mechanism: "password".into(),
                source: "application".into(),
                problem: format!(
                    "The application \"{}\" authenticates its users through a federation relationship and its entry names none that this service can use. Set appFederationRelationship on it.",
                    wanted),
                allowed,
            };
        }
        Chosen {
            mechanism: "password".into(),
            source: "default".into(),
            problem: String::new(),
            allowed,
        }
    }

    /// `beginAuthenticationHere(opts)`.
    fn begin_here(&self, opts: &Begin) -> Result<(String, String), String> {
        let return_to = opts.return_to.as_str();
        if !return_to.starts_with('/') || return_to[1..].starts_with('/') {
            return Err(format!(
                "beginAuthentication() needs a path on this service to return to, not \"{}\".",
                return_to
            ));
        }
        let chosen = self.mechanism_for(&opts.application);
        let allows = |id: &str| chosen.allowed.iter().any(|a| a == id);
        let several =
            chosen.allowed.len() > 1 && chosen.mechanism == "password";
        let force_mfa = opts.force_mfa
            || chosen.mechanism == "password-mfa"
            || (several
                && allows("password-mfa")
                && !allows("password")
                && !allows("webauthn"));
        let mut force_passwordless = chosen.mechanism == "webauthn"
            || (several
                && allows("webauthn")
                && !allows("password")
                && !allows("password-mfa"));
        let mut integrated = chosen.mechanism == "spnego";
        if integrated && (opts.force_key || force_mfa) {
            integrated = false;
        }
        if force_passwordless && force_mfa {
            force_passwordless = false;
        }
        let locked = opts.locked_username.trim().to_string();
        let id = (self.random_id)(18);
        let now = (self.now_ms)();
        let mut record = Map::new();
        let put = |r: &mut Map<String, Json>, k: &str, v: Json| {
            r.insert(k.to_string(), v);
        };
        put(&mut record, "id", json!(id));
        put(&mut record, "restart", Json::Null);
        put(&mut record, "returnTo", json!(return_to));
        put(
            &mut record,
            "details",
            if opts.details.is_array() {
                opts.details.clone()
            } else {
                json!([])
            },
        );
        put(
            &mut record,
            "hint",
            json!(if locked.is_empty() {
                opts.hint.clone()
            } else {
                locked.clone()
            }),
        );
        put(&mut record, "lockedUsername", json!(locked));
        put(&mut record, "allowedMechanisms", json!(chosen.allowed));
        put(&mut record, "forceMfa", json!(force_mfa));
        put(&mut record, "forceKey", json!(opts.force_key));
        put(
            &mut record,
            "phishingClass",
            json!(if opts.phishing_class == "phrh" {
                "phrh"
            } else {
                ""
            }),
        );
        put(&mut record, "forcePasswordless", json!(force_passwordless));
        put(&mut record, "integrated", json!(integrated));
        put(
            &mut record,
            "walletDoor",
            json!(chosen.mechanism == "wallet"),
        );
        put(&mut record, "mechanism", json!(chosen.mechanism));
        put(&mut record, "mechanismSource", json!(chosen.source));
        put(&mut record, "mechanismVia", json!(""));
        put(&mut record, "mechanismProblem", json!(chosen.problem));
        put(
            &mut record,
            "protocol",
            json!(if opts.protocol.is_empty() {
                "OAuth 2.0 / OIDC"
            } else {
                &opts.protocol
            }),
        );
        put(&mut record, "application", json!(opts.application));
        put(
            &mut record,
            "uiLocales",
            json!(js_slice(&opts.ui_locales, 256)),
        );
        put(
            &mut record,
            "reauthentication",
            json!(if ["prompt_login", "max_age"]
                .contains(&opts.reauthentication.as_str())
            {
                opts.reauthentication.clone()
            } else {
                String::new()
            }),
        );
        put(&mut record, "federation", Json::Null);
        put(
            &mut record,
            "expires",
            json!(now + self.sessions.pending_ttl_ms()),
        );
        let walled = chosen.mechanism == "wallet";
        self.pending.set(&id, Json::Object(record));
        self.pending
            .in_realm(&sts_core::realm::current_id())
            .retain(|_, v| crate::js::to_number(&v["expires"]) >= now);
        let encoded = sts_authn::account_sets::encode_uri_component(&id);
        let path = if integrated {
            SPNEGO_PATH
        } else if walled {
            WALLET_PATH
        } else {
            LOGIN_PATH
        };
        Ok((format!("{}?authn={}", path, encoded), id))
    }
}

fn js_slice(text: &str, n: usize) -> String {
    String::from_utf16_lossy(&text.encode_utf16().take(n).collect::<Vec<u16>>())
}

impl SignInHandOff for PendingSignIns {
    #[tracing::instrument(level = "debug", skip(self, request))]
    fn begin_authentication(
        &self,
        begin: &Begin,
        request: &Request,
    ) -> Result<String, String> {
        let hinted =
            !begin.hint.is_empty() || !begin.locked_username.is_empty();
        let Some((pick, hint)) = self.sessions.begin_account_choice(
            request,
            &begin.account_choice,
            hinted,
        ) else {
            return self.begin_here(begin).map(|(t, _)| t);
        };
        let mut given = begin.clone();
        if let Some(h) = hint.filter(|_| !hinted) {
            given.hint = h;
        }
        let (target, id) = self.begin_here(&given)?;
        if pick.is_empty() {
            return Ok(target);
        }
        let existing =
            self.pending.get(&id).and_then(|v| v.as_object().cloned());
        let opts = json!({
            "returnTo": given.return_to, "details": given.details,
            "protocol": given.protocol, "application": given.application,
            "uiLocales": given.ui_locales,
        });
        let (record, location) = self
            .sessions
            .route_to_accounts(existing, &opts, &target, &pick, request);
        let rid = crate::js::string_of(record.get("id"));
        self.pending.set(&rid, Json::Object(record));
        Ok(location)
    }
}
