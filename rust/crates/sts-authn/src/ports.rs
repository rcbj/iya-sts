// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What the session core reaches beyond itself, each a trait handed to
//! [`crate::Sessions::new`] — Node's `AuthnDeps`, narrowed to what the
//! session doors use, and the modules `authn.ts` reached by `require()`.
//!
//! The arguments and answers are Node's JSON where Node's are JSON, so the
//! adapters the composition root writes are thin and the vectors
//! (`tests/tools/session-vectors.js`) can answer every port from what Node's
//! answered. A port that Node reached lazily, and that a process may lack
//! (the back-channel library, OpenID Connect Session Management, the risk
//! engine, the cluster claim), is an `Option` in [`crate::SessionsDeps`].
//!
//! Each trait method is called once per session act at most, and none
//! carries a span of its own: the act's span covers it.

use std::sync::{Arc, Mutex, PoisonError};

use serde_json::Value;

use crate::js::Object;

/// A request as a session door sees it: the cookie header and the facts an
/// authentication event records (`eventContext()`).
#[derive(Debug, Clone, Default)]
pub struct Request {
    /// The `Cookie` header, as it arrived.
    pub cookie: String,
    /// The `User-Agent` header.
    pub user_agent: String,
    /// The client address the audit log would record.
    pub address: String,
    /// The sign-in form's `device_fp`, where it posted one (#62 P6).
    pub device_fp: String,
    /// The address as express's `req.url` holds it once the realm prefix
    /// is off: the path and its query. What a selection ticket is bound to
    /// (#561) and taken off ([`crate::Sessions::spend_account_ticket`]).
    pub url: String,
    /// What the account set's doors leave on the request (#561).
    pub accounts: AccountMarks,
}

/// A protocol's hint about which account a request is for (#561,
/// `hintAccount()`): `req.stsAccountHint`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountHint {
    pub login_hint: String,
    pub sub: String,
    pub sid: String,
    pub soft: bool,
}

/// A ticket's choice that this request cannot honour (#731): who it named.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EndedSelection {
    pub username: String,
    pub sid: String,
}

/// Node's `req.stsAccount*` members, and `req.res` for D12.
#[derive(Debug, Default)]
pub struct AccountMarksInner {
    /// `stsAccountSetId`: the set this request created or rotated.
    pub set_id: String,
    /// `stsAccountSetUnread`: the set's read failed, which is not absence.
    pub set_unread: bool,
    /// `stsAccountSelection`: the sid a ticket spent on this request chose.
    pub selection: String,
    /// `stsAccountSelectionEnded`.
    pub selection_ended: Option<EndedSelection>,
    /// `stsAccountHint`.
    pub hint: Option<AccountHint>,
    /// Whether the request's own response can still take a cookie (Node's
    /// `req.res`, not yet sent): what lets D12 make a set around a session
    /// from a door handed no response, such as `sessionOf()`.
    pub response_open: bool,
    /// The cookies appended to the request's response from such a door, in
    /// order, for the HTTP layer to append (`req.res.append`).
    pub appended: Vec<String>,
}

/// The request's marks, shared by every clone of it: Node's doors write
/// them on the one `req` object every later door of the request reads.
#[derive(Debug, Clone, Default)]
pub struct AccountMarks(pub Arc<Mutex<AccountMarksInner>>);

impl AccountMarks {
    /// The marks, locked for one read or write.
    // A hot path: every session read; no span.
    pub fn lock(&self) -> std::sync::MutexGuard<'_, AccountMarksInner> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The cookies a door appended to the request's response, taken.
    // A hot path: once per request; no span.
    pub fn take_appended(&self) -> Vec<String> {
        std::mem::take(&mut self.lock().appended)
    }
}

/// A response a session door writes cookies on: `set` replaces, `append`
/// adds (`setCookieHeader()` and `clearSessionCookie()`'s two mechanisms),
/// and `locals` is express's `res.locals`.
#[derive(Debug, Clone, Default)]
pub struct Response {
    pub cookies: Vec<String>,
    pub locals: Object,
}

impl Response {
    /// `res.set('Set-Cookie', line)`: one cookie per response.
    // A hot path: every sign-in writes one; no span.
    pub fn set_cookie(&mut self, line: String) {
        self.cookies = vec![line];
    }

    /// `res.append('Set-Cookie', line)`.
    // A hot path: every sign-out writes one; no span.
    pub fn append_cookie(&mut self, line: String) {
        self.cookies.push(line);
    }
}

/// `config.value(key)`, and the cookie `Domain` attribute the listener map
/// writes (`helpers.cookieDomainAttribute()`, #472).
pub trait Settings: Send + Sync {
    fn value(&self, key: &str) -> Value;
    fn cookie_domain_attribute(&self) -> String;
}

/// The two `common/mode.js` predicates the session doors ask.
pub trait ModeQuestions: Send + Sync {
    fn verifies_credentials(&self) -> bool;
    fn revokes_access_tokens_at_sign_out(&self) -> bool;
}

/// `common/realms.js`: whether the ambient realm is being removed, and every
/// realm the sweep walks.
pub trait Realms: Send + Sync {
    /// `retiringRefusal()`: `{ why }`, or `None`.
    fn retiring_refusal(&self) -> Option<Value>;
    /// Every realm id, default first.
    fn ids(&self) -> Vec<String>;
    /// Runs `work` with that realm ambient (`realms.run(realm, fn)`), so
    /// what it reports is filed and signed as that realm's.
    fn run_in(&self, id: &str, work: &mut dyn FnMut());
}

/// The directory as the session sees it: `helpers.userFor()` and the
/// subject resolver `ldap_server.js` fills (sts-directory's
/// `subject_for_name()` / `name_for_subject()`), in the ambient realm.
pub trait People: Send + Sync {
    /// `userFor(username)`: `{ sub, username, preferred_username, … }`.
    fn user_for(&self, username: &str) -> Value;
    fn subject_for_name(&self, name: &str) -> String;
    fn name_for_subject(&self, subject: &str) -> String;
    fn has_subject_resolver(&self) -> bool;
}

/// The account state (`common/account_state.ts`, sts-registers'
/// `AccountState::is_disabled`) and the service-account policy's door rule.
pub trait Accounts: Send + Sync {
    fn is_disabled(&self, who: &str) -> bool;
    fn service_account_refuses_door(&self, username: &str, door: &str) -> bool;
}

/// The authentication policy at sign-in: the realm's profile
/// (`authnPolicy.allows()`, sts-policy's authn kind), an application's
/// mechanism lists (`declaredMechanismsFor()`, `mfaAllowedFor()`, which
/// read sts-policy's `mechanisms_for()`), the post-login register
/// (`postLogin.dueFor()`, rule 3ct) and the passkey policy's selection.
pub trait SignInPolicy: Send + Sync {
    /// `allows(mechanism, role)`, `role` `primary` or `second-factor`.
    fn allows(&self, mechanism: &str, role: &str) -> bool;
    fn declared_mechanisms(
        &self,
        application: &str,
        username: &str,
    ) -> Vec<String>;
    fn mfa_allowed(&self, application: &str, username: &str) -> Vec<String>;
    /// `{ activity, required, profile, askedBy }`, or `None`.
    fn post_login_due(
        &self,
        username: &str,
        application: &str,
    ) -> Option<Value>;
    /// `passkeyPolicy.select(username, application)`; `application` is the
    /// door's value as given (null where it named none).
    fn select_passkey_policy(&self, username: &str, application: &Value);
}

/// The issuance gate (`common/issuance_gate.js`): the session question and
/// the device requirement. The decision is the XACML engine's.
pub trait Gate: Send + Sync {
    /// `gate.check(ask)`: `{ allowed, why, policy, mechanism, device, risk }`.
    fn check(&self, ask: &Value) -> Value;
    fn device_requirement(&self) -> Vec<String>;
}

/// The credential checks `startSession()` asks of a passkey and an account
/// recovery: the credentials slice's (`passkeySignInRefusal()`,
/// `recoveryRefusalAtSession()`, `noteAlgorithmMismatch()`,
/// `recoveryCompleted()`).
pub trait CredentialChecks: Send + Sync {
    /// `{ code, why, reason }`, or `None`.
    fn passkey_sign_in_refusal(
        &self,
        username: &str,
        credential: &Value,
    ) -> Option<Value>;
    /// `{ code, why, reason }`, or `None`.
    fn recovery_refusal_at_session(
        &self,
        username: &str,
        credential: &Value,
    ) -> Option<Value>;
    fn note_algorithm_mismatch(
        &self,
        username: &str,
        credential: &Value,
        via: &Value,
    );
    fn note_passkey_standing(
        &self,
        username: &str,
        credential: &Value,
        refusal: &Value,
    );
    fn recovery_completed(&self, username: &str, detail: &Value);
}

/// The registered device behind a sign-in (`common/device_recognition.ts`)
/// and the connection's ClientHello (`tls/client_hello.ts`).
pub trait Devices: Send + Sync {
    /// `recognize(ask)`; an `Err` is a recogniser that threw
    /// (`STS-DEVICE-0029`), recorded as no device.
    fn recognize(
        &self,
        ask: &Value,
        request: &Request,
    ) -> Result<Value, String>;
    /// `{ ja4, stack }` of the request's connection, or `None`.
    fn client_hello(&self, request: &Request) -> Option<Value>;
}

/// The identity register (`common/admin_stats.js`): an authentication
/// recorded, and the tokens issued on an ended session revoked.
pub trait Records: Send + Sync {
    /// `recordAuthentication(record)`; `request` is the request the record
    /// was made for, which Node hands in as a member.
    fn record_authentication(&self, record: &Value, request: Option<&Request>);
    /// `revokeWhere(test, reason, opts, tags)` for the session `sid`, its
    /// test Node's (`dropSession()`): the session's access tokens where
    /// `revokes_access`, and its refresh tokens the RFC 9700 rule revokes.
    fn revoke_session_tokens(
        &self,
        sid: &str,
        revokes_access: bool,
        reason: &str,
        opts: &Value,
        tags: &[String],
    ) -> usize;
    /// `recordAccountChoice(kind, n)` (#561): `selected`, `ambiguous`,
    /// `selectFailed`, `added`, `forgotten`, `expired`, `switched`; `n` is
    /// `None` where Node passed one argument (a count of one).
    fn record_account_choice(&self, kind: &str, n: Option<u64>);
}

/// The audit log (`common/audit.js`'s `audit()`).
pub trait AuditLog: Send + Sync {
    fn audit(&self, row: &Value);
}

/// THE ONE INVERTED HOOK THIS MODULE OFFERS (`setSessionObserver()`), kept
/// a slot: `ssf/` fills it, and is built long after the session core.
pub trait SessionObserver: Send + Sync {
    /// `{ kind, session, via, … }`; `request` is the notice's `req`. An
    /// `Err` is an observer that threw (`STS-AUTHN-0014`), swallowed.
    fn notice(
        &self,
        notice: &Value,
        request: Option<&Request>,
    ) -> Result<(), String>;
}

/// The device-bound session (#725, `authn/device_bound_sessions.ts`).
pub trait DeviceBinding: Send + Sync {
    fn offer(&self, response: &mut Response, session: &Value);
    fn honours(&self, session: &Value, request: Option<&Request>) -> bool;
    fn note_skipped(&self, session: &Value, request: Option<&Request>);
    fn binding_of(&self, session: &Value) -> Value;
}

/// OpenID Connect Back-Channel Logout (`oauth-oidc/backchannel_logout.ts`):
/// the OAuth slice's.
pub trait Backchannel: Send + Sync {
    fn on_expiry(&self) -> bool;
    fn plan(&self, session: &Value, opts: &Value) -> Value;
    fn dispatch(&self, planned: &Value);
}

/// OpenID Connect Session Management's OP browser state cookie (#121,
/// `oauth-oidc/session_management.ts`): the OAuth slice's.
pub trait SessionManagement: Send + Sync {
    fn enabled(&self) -> bool;
    fn write_cookie(&self, response: &mut Response, value: &str);
    /// `browserStatesValue(sessions.map(browserStateOf))`: the cookie value
    /// naming every account's OP browser state (#561 with #121).
    fn browser_states_value(&self, sessions: &[Value]) -> String;
}

/// The risk engine's assessment of a new authentication (#62): the risk
/// slice's. Fire-and-forget, as Node's.
pub trait RiskAssessment: Send + Sync {
    fn assess(
        &self,
        session: &Value,
        event: &Value,
        via: &Value,
        detail: &Value,
    );
}

/// `authn.session-end`, the cluster claim that a session's end is reported
/// once (#46 section 6): `true` when this process reports it, `false` when
/// another already has; an `Err` is a claim that could not be asked, and
/// the end is reported anyway (`STS-AUTHN-0192`). Absent: one process,
/// reported inline.
pub trait EndClaims: Send + Sync {
    fn claim(&self, sid: &str) -> Result<bool, String>;
}

/// The clock and the random ids: `Date.now()` and `helpers.randomId()`.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> f64;
    /// `randomId(bytes)`: base64url of that many random bytes.
    fn random_id(&self, bytes: usize) -> String;
}

/// The real clock: the system time and `sts_crypto`'s random bytes.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> f64 {
        chrono::Utc::now().timestamp_millis() as f64
    }

    fn random_id(&self, bytes: usize) -> String {
        match sts_crypto::random::random_bytes(bytes) {
            Ok(b) => sts_crypto::b64::encode(&b),
            Err(e) => {
                tracing::error!("authn: no random bytes for an id: {}", e);
                String::new()
            }
        }
    }
}
