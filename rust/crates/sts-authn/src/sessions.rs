// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE SESSION SERVICE: the store every protocol family reads to answer "is
//! this person already signed in?", and the only place that writes it — a
//! port of `authn/authn.ts`'s session half.
//!
//! The doors, by their Node names:
//!
//! * [`Sessions::start_session`] — `startSession()`: the refusals in Node's
//!   order (a realm being removed, a disabled account, a service account
//!   at a browser door, the authentication policy, the passkey and the
//!   recovery checks, the issuance policy and the application's mechanisms,
//!   the device, the post-login hold), then a keyed caller's touch, a
//!   RE-AUTHENTICATION of the same person on a live session (an event
//!   ADDED, the handle rotated, the `sid` kept), or a new session (an
//!   arrival upgraded in place, a different person's session REPLACED).
//!   The authentication is recorded HERE, once (the sixth argument's rule).
//! * [`Sessions::session_of`] — `sessionOf()`: the cookie's session with
//!   its current handle, held to every rule (ended or idle, an arrival
//!   nobody chose, a disabled or deleted account, the device binding).
//! * [`Sessions::drop_session`] — `dropSession()`, the ONE place a session
//!   stops existing: its derived sessions, the RFC 9700 section 2.2.2
//!   refresh revocation, the `session.end` row and CAEP's
//!   `session-revoked`; `end_session` and `end_session_by_id` over it.
//! * [`Sessions::expire_session`] and [`Sessions::sweep_expired_sessions`]
//!   — a session that RAN OUT says so (audit row, `session-revoked`
//!   initiated by `policy`, the back-channel Logout Tokens), and the
//!   `authn.session-expiry` scheduler job is the sweep ([`crate::job`]).
//! * [`Sessions::note_presented`], `hold_presentation`,
//!   `note_session_changed`, `session_is_live`, `start_arrival_session`,
//!   `backdate_authentication`, `sign_on_facts_for`.
//!
//! WHAT REPLACED WHAT. Node's module-level `sessions` map is a
//! [`RealmMap`] declared with Node's spec ([`crate::merge::spec`]); the
//! observer slot is a `RwLock` the SSF family fills; `Date.now()` and
//! `randomId()` are the [`Clock`] port; and a session Node edits in place
//! through a shared object is edited here through
//! [`Sessions::note_session_changed`], which writes the held row. Account
//! sets (#561), the session window (#350) and the relying-party sessions
//! are not this crate's yet — see the crate's documentation.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use serde_json::{json, Value};
use sts_core::errors::codes;
use sts_core::log::tag;
use sts_core::realm;
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{RealmMap, RealmView, StoreHandles};

use crate::cookie;
use crate::js::{self, Object};
use crate::merge;
use crate::ports::*;
use crate::record::{self, Context, ANONYMOUS_USERNAME, DEFAULT_VIA};
use crate::record::{MAX_SESSION_EVENTS, SESSION_COOKIE};

/// The absolute lifetime's default, `authn.sessionLifetimeS` unset.
const SESSION_TTL_MS: f64 = 60.0 * 60.0 * 1000.0;
/// How long an interrupted request waits, `authn.pendingTtlS` unset.
const AUTHN_TTL_MS: f64 = 10.0 * 60.0 * 1000.0;
/// CAEP section 2's four words for who ended a session (`initiatorOf()`).
const INITIATING_ENTITIES: [&str; 4] = ["admin", "user", "policy", "system"];

/// What the session core is built over.
pub struct SessionsDeps {
    pub settings: Arc<dyn Settings>,
    pub mode: Arc<dyn ModeQuestions>,
    pub realms: Arc<dyn Realms>,
    pub people: Arc<dyn People>,
    pub accounts: Arc<dyn Accounts>,
    pub policy: Arc<dyn SignInPolicy>,
    pub gate: Arc<dyn Gate>,
    pub credentials: Arc<dyn CredentialChecks>,
    pub devices: Arc<dyn Devices>,
    pub records: Arc<dyn Records>,
    pub audit: Arc<dyn AuditLog>,
    pub binding: Arc<dyn DeviceBinding>,
    pub backchannel: Option<Arc<dyn Backchannel>>,
    pub session_management: Option<Arc<dyn SessionManagement>>,
    pub risk: Option<Arc<dyn RiskAssessment>>,
    pub claims: Option<Arc<dyn EndClaims>>,
    pub clock: Arc<dyn Clock>,
}

/// One door's ask of a request: the device it recognised, asked once per
/// request and credential (`registeredDeviceFor()`'s memo).
#[derive(Default)]
struct Attempt {
    devices: HashMap<String, Value>,
}

/// The session core.
pub struct Sessions {
    deps: SessionsDeps,
    store: RealmMap<Value>,
    /// THE ONE INVERTED HOOK (`setSessionObserver()`): `ssf/` fills it, after
    /// this is built. Advisory and fire-and-forget.
    observer: RwLock<Option<Arc<dyn SessionObserver>>>,
    /// Ends a capacity rule took since the last log line, and when it was.
    capacity_log: Mutex<(u64, f64)>,
    refuse_log: Mutex<(u64, f64)>,
}

fn obj(v: &Value) -> Object {
    js::object_of(Some(v))
}

fn iso(ms: f64) -> String {
    chrono::DateTime::from_timestamp_millis(ms as i64)
        .map(|t| t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        .unwrap_or_default()
}

/// A member set only where Node's value is defined (`JSON.stringify` drops
/// `undefined`).
fn put_defined(o: &mut Object, key: &str, value: Option<&Value>) {
    if let Some(v) = value {
        o.insert(key.into(), v.clone());
    }
}

/// `{ sessionId, sub, … }` with `sub` second, where it is defined.
fn with_sub(sub: Option<&Value>, rest: Value) -> Object {
    let rest = obj(&rest);
    let mut out = Object::new();
    for (i, (k, v)) in rest.into_iter().enumerate() {
        out.insert(k, v);
        if i == 0 {
            put_defined(&mut out, "sub", sub);
        }
    }
    out
}

/// `String(x && x.kind)` for an optional credential.
fn kind_text(credential: Option<&Value>) -> String {
    match credential {
        Some(c) if js::truthy(Some(c)) => match c.get("kind") {
            None => "undefined".to_string(),
            Some(k) => js::text(k),
        },
        Some(c) => js::text(c),
        None => "undefined".to_string(),
    }
}

impl Sessions {
    /// Builds the service and declares its store. `lifecycle` purges a
    /// removed realm's partition; `handles` is where minted persistence
    /// finds the store (`authn.sessions`).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(
        deps: SessionsDeps,
        lifecycle: &Arc<RealmLifecycle>,
        handles: &Arc<StoreHandles>,
    ) -> Sessions {
        let clock = deps.clock.clone();
        let spec = merge::spec(Arc::new(move || clock.now_ms()));
        Sessions {
            deps,
            store: RealmMap::new(lifecycle, handles, spec),
            observer: RwLock::new(None),
            capacity_log: Mutex::new((0, 0.0)),
            refuse_log: Mutex::new((0, 0.0)),
        }
    }

    /// The store, as every protocol family reads it.
    pub fn store(&self) -> &RealmMap<Value> {
        &self.store
    }

    fn now(&self) -> f64 {
        self.deps.clock.now_ms()
    }

    fn now_sec(&self) -> f64 {
        (self.now() / 1000.0).floor()
    }

    fn setting(&self, key: &str) -> Value {
        self.deps.settings.value(key)
    }

    fn here(&self) -> RealmView<Value> {
        self.store.in_realm(&realm::current_id())
    }

    fn https(&self) -> bool {
        js::truthy(Some(&self.setting("global.https")))
    }

    // -------------------------------------------------------------------
    // The clocks (2026-09-12): the lifetime is STAMPED at creation, the idle
    // timeout CHECKED at read, and `session_ended()` is the one answer.
    // -------------------------------------------------------------------

    fn seconds_setting(&self, key: &str, fallback: f64) -> f64 {
        let n = js::number(Some(&self.setting(key)));
        if n.is_finite() && n > 0.0 {
            n.floor() * 1000.0
        } else {
            fallback
        }
    }

    /// `sessionLifetimeMs()`: `authn.sessionLifetimeS`, an hour unset.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn session_lifetime_ms(&self) -> f64 {
        self.seconds_setting("authn.sessionLifetimeS", SESSION_TTL_MS)
    }

    /// `sessionIdleTimeoutMs()`: ZERO IS THE DEFAULT AND MEANS NONE.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn session_idle_timeout_ms(&self) -> f64 {
        let n = js::number(Some(&self.setting("authn.sessionIdleTimeoutS")));
        if n.is_finite() && n > 0.0 {
            n.floor() * 1000.0
        } else {
            0.0
        }
    }

    /// `pendingTtlMs()`: `authn.pendingTtlS`, an arrival's window.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn pending_ttl_ms(&self) -> f64 {
        self.seconds_setting("authn.pendingTtlS", AUTHN_TTL_MS)
    }

    /// `sessionEnded(session, nowMs)`: '' live, 'expired' (or no session,
    /// or ended by an administrator, #1520), 'idle'. An arrival is exempt
    /// from the idle rule.
    #[tracing::instrument(level = "debug", skip(self, session))]
    pub fn session_ended(&self, session: Option<&Value>, now: f64) -> String {
        let now = if now != 0.0 { now } else { self.now() };
        let Some(s) = session.filter(|s| js::truthy(Some(s))) else {
            return "expired".into();
        };
        let expires = s.get("expires");
        if js::truthy(expires) && js::number(expires) < now {
            return "expired".into();
        }
        let before =
            js::number(Some(&self.setting("authn.sessionsEndedBefore")));
        if before > 0.0 && js::number_or_zero(s.get("startedAt")) < before {
            return "expired".into();
        }
        let idle = self.session_idle_timeout_ms();
        let seen = s.get("lastSeenAt");
        if idle != 0.0
            && s.get("chosen") != Some(&Value::Bool(false))
            && js::truthy(seen)
            && now - js::number(seen) > idle
        {
            return "idle".into();
        }
        String::new()
    }

    // -------------------------------------------------------------------
    // The observer (rule 3e's slot, `setSessionObserver()`).
    // -------------------------------------------------------------------

    /// `setSessionObserver(fn)`: the one observer told when a session is
    /// established, presented, re-authenticated or ended.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn set_session_observer(&self, observer: Arc<dyn SessionObserver>) {
        *self
            .observer
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(observer);
        tracing::info!(
            "authn: a session observer was installed; the Shared Signals \
             transmitter will be told when a session is created, presented \
             or ended."
        );
    }

    /// `notifySession(kind, session, extra)`: nothing about an arrival
    /// (#242); an observer that throws is swallowed (`STS-AUTHN-0014`).
    fn notify(
        &self,
        kind: &str,
        session: Option<&Value>,
        extra: Object,
        request: Option<&Request>,
    ) {
        let observer = self
            .observer
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let (Some(observer), Some(session)) = (observer, session) else {
            return;
        };
        if session.get("chosen") == Some(&Value::Bool(false)) {
            return;
        }
        let mut notice = Object::new();
        notice.insert("kind".into(), json!(kind));
        notice.insert("session".into(), session.clone());
        for (k, v) in extra {
            notice.insert(k, v);
        }
        if let Err(e) = observer.notice(&Value::Object(notice), request) {
            tracing::error!(
                "{}authn: the session observer threw on a \"{}\" and was \
                 ignored: {}",
                tag(codes::STS_AUTHN_0014.as_str()),
                kind,
                e
            );
        }
    }

    // -------------------------------------------------------------------
    // The cookie.
    // -------------------------------------------------------------------

    /// `sessionCookieLine(name, value)`.
    fn cookie_line(&self, name: &str, value: &str) -> String {
        let domain = if name == SESSION_COOKIE {
            self.deps.settings.cookie_domain_attribute()
        } else {
            String::new()
        };
        cookie::cookie_line(name, value, &domain, self.https())
    }

    /// `cookieSession(req, cookieName)`: the session a cookie names IF it
    /// carries that session's current handle, in the ambient realm. It
    /// expires nothing.
    #[tracing::instrument(level = "debug", skip(self, request))]
    pub fn cookie_session(
        &self,
        request: Option<&Request>,
        name: &str,
    ) -> Option<(String, Value)> {
        let value = cookie::cookie_value(&request?.cookie, name);
        let p = cookie::presented(&value)?;
        let session = self.here().get(&p.id)?;
        if !cookie::holds_handle(&obj(&session), &p.handle) {
            return None;
        }
        Some((p.id, session))
    }

    /// `clearSessionCookie(res, cookieName)`: APPENDS, so a sign-out on a
    /// hosted surface clears its own cookie and the sign-on one.
    #[tracing::instrument(level = "debug", skip(self, response))]
    pub fn clear_session_cookie(&self, response: &mut Response, name: &str) {
        let name = if name.is_empty() {
            SESSION_COOKIE
        } else {
            name
        };
        let domain = if name == SESSION_COOKIE {
            self.deps.settings.cookie_domain_attribute()
        } else {
            String::new()
        };
        response.append_cookie(cookie::clear_line(name, &domain, self.https()));
        if name == SESSION_COOKIE {
            if let Some(sm) = &self.deps.session_management {
                if sm.enabled() {
                    sm.write_cookie(response, "");
                }
            }
        }
    }

    fn mint(&self, session: &mut Object) -> String {
        let clock = self.deps.clock.clone();
        cookie::mint_handle(session, self.now(), move |n| clock.random_id(n))
    }

    // -------------------------------------------------------------------
    // Identity.
    // -------------------------------------------------------------------

    /// `sameIdentity(user, username)`: by subject where both have one (an
    /// alias of the same entry included), by name otherwise, and two empty
    /// subjects are never one person.
    fn same_identity(&self, user: &Value, username: &str) -> bool {
        let theirs = js::or_empty(user.get("sub"));
        let asked = self.deps.people.subject_for_name(username);
        if !theirs.is_empty() && !asked.is_empty() {
            let aliased = theirs != asked
                && self.deps.people.subject_for_name(
                    &self.deps.people.name_for_subject(&theirs),
                ) == asked;
            return theirs == asked || aliased;
        }
        theirs.is_empty()
            && asked.is_empty()
            && js::or_empty(user.get("username")) == username
    }

    fn signed_in_row(s: &Value) -> bool {
        js::truthy(s.get("user"))
            && s.get("authenticated") != Some(&Value::Bool(false))
            && s.get("chosen") != Some(&Value::Bool(false))
            && !js::truthy(s.get("credentialKey"))
    }

    /// `sessionAccountDisabled(session)`.
    #[tracing::instrument(level = "debug", skip(self, session))]
    pub fn session_account_disabled(&self, session: &Value) -> bool {
        if !Self::signed_in_row(session) {
            return false;
        }
        let user = obj(&session["user"]);
        let who = match js::or_empty(user.get("sub")) {
            s if s.is_empty() => js::or_empty(user.get("username")),
            s => s,
        };
        self.deps.accounts.is_disabled(&who)
    }

    /// `sessionAccountGone(session)`: a `urn:uuid` subject the directory no
    /// longer names (#241).
    #[tracing::instrument(level = "debug", skip(self, session))]
    pub fn session_account_gone(&self, session: &Value) -> bool {
        if !Self::signed_in_row(session) {
            return false;
        }
        let sub = js::or_empty(session["user"].get("sub"));
        let uuid = sub
            .get(..9)
            .is_some_and(|p| p.eq_ignore_ascii_case("urn:uuid:"));
        if !uuid || !self.deps.people.has_subject_resolver() {
            return false;
        }
        self.deps.people.name_for_subject(&sub).is_empty()
    }

    // -------------------------------------------------------------------
    // The authentication event.
    // -------------------------------------------------------------------

    fn context_of(&self, detail: &Object, request: Option<&Request>) -> Value {
        let hello = request.and_then(|r| self.deps.devices.client_hello(r));
        let digest = |text: &str| {
            if text.is_empty() {
                String::new()
            } else {
                cookie::handle_hash_of(text)
            }
        };
        let fingerprinting =
            self.setting("risk.fingerprinting") == Value::Bool(true);
        let fp = match request {
            Some(r)
                if fingerprinting
                    && (8..=64).contains(&r.device_fp.len())
                    && r.device_fp
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric()) =>
            {
                r.device_fp.clone()
            }
            _ => String::new(),
        };
        let hello = hello.unwrap_or(Value::Null);
        let ja4 = js::or_empty(hello.get("ja4"));
        let stack = match js::or_empty(hello.get("stack")) {
            s if s.is_empty() => ja4.clone(),
            s => s,
        };
        let address = match js::or_empty(detail.get("address")) {
            a if a.is_empty() => {
                request.map(|r| r.address.clone()).unwrap_or_default()
            }
            a => a,
        };
        let context = Context {
            address,
            ua_fingerprint: digest(
                &request.map(|r| r.user_agent.clone()).unwrap_or_default(),
            ),
            ja4,
            tls_stack: stack,
            device: if fp.is_empty() {
                String::new()
            } else {
                digest(&format!("device:{}", fp))
            },
        };
        context
            .json(record::credential_context(detail.get("credential"), digest))
    }

    /// `registeredDeviceFor(detail, username)`: recognised once per request
    /// and credential; a recogniser that throws records none
    /// (`STS-DEVICE-0029`).
    fn device_for(
        &self,
        attempt: &mut Attempt,
        detail: &Object,
        username: Option<&str>,
        request: Option<&Request>,
    ) -> Value {
        let given = js::object_of(detail.get("credential"));
        let credential_id = if given.get("kind") == Some(&json!("webauthn")) {
            js::or_empty(given.get("id"))
        } else {
            String::new()
        };
        let memo = format!("{}\u{0}{}", credential_id, username.unwrap_or(""));
        if let Some(fact) = attempt.devices.get(&memo) {
            return fact.clone();
        }
        let mut ask = Object::new();
        ask.insert("webauthnCredentialId".into(), json!(credential_id));
        if let Some(u) = username {
            ask.insert("subject".into(), json!(u));
        }
        if js::truthy(detail.get("application")) {
            ask.insert(
                "clientId".into(),
                detail.get("application").cloned().unwrap_or_default(),
            );
        }
        let Some(r) = request else {
            return Value::Null;
        };
        let fact = match self.deps.devices.recognize(&Value::Object(ask), r) {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(
                    "{}authn: recognising the device behind a sign-in \
                     threw: {}",
                    tag(codes::STS_DEVICE_0029.as_str()),
                    e
                );
                Value::Null
            }
        };
        attempt.devices.insert(memo, fact.clone());
        fact
    }

    /// `authenticationEvent(amr, acr, via, extra, username)`.
    #[allow(clippy::too_many_arguments)]
    fn event(
        &self,
        attempt: &mut Attempt,
        amr: &[String],
        acr: &str,
        via: &str,
        detail: &Object,
        username: &str,
        request: Option<&Request>,
    ) -> Value {
        let mut e = Object::new();
        e.insert("at".into(), js::num(self.now_sec()));
        e.insert("amr".into(), js::string_array(amr));
        e.insert("acr".into(), json!(acr));
        e.insert(
            "via".into(),
            json!(if via.is_empty() { DEFAULT_VIA } else { via }),
        );
        e.insert(
            "authenticated".into(),
            json!(detail.get("authenticated") != Some(&Value::Bool(false))),
        );
        e.insert("authority".into(), record::authority_of(detail));
        e.insert(
            "evidence".into(),
            json!(if js::truthy(detail.get("key")) {
                js::string_of(detail.get("key"))
            } else {
                String::new()
            }),
        );
        e.insert("context".into(), self.context_of(detail, request));
        e.insert(
            "registeredDevice".into(),
            self.device_for(attempt, detail, Some(username), request),
        );
        Value::Object(e)
    }

    fn default_sign_in_note(&self) -> String {
        if self.deps.mode.verifies_credentials() {
            "What was presented was verified before the session started; \
             the method says what it was."
                .into()
        } else {
            "No password was checked (development mode); the name typed is \
             the identity."
                .into()
        }
    }

    /// `statsExtra`: the door's detail without what the register must not
    /// keep.
    fn stats_extra(detail: &Object) -> Object {
        let mut out = detail.clone();
        for k in [
            "authenticated",
            "risk",
            "riskDecision",
            "riskStepUp",
            "fedPartnerSession",
            "sessionNotOnOrAfter",
        ] {
            out.shift_remove(k);
        }
        out
    }

    /// `bindPartnerSession(session, extra)` (#167): a partner's session rides
    /// on this one, and can only shorten it.
    fn bind_partner_session(&self, session: &mut Object, detail: &Object) {
        if let Some(p @ Value::Object(_)) = detail.get("fedPartnerSession") {
            session.insert("fedPartnerSession".into(), p.clone());
        }
        let bound = js::number_or_zero(detail.get("sessionNotOnOrAfter"));
        let expires = session.get("expires");
        if bound > 0.0 && (!js::truthy(expires) || bound < js::number(expires))
        {
            session.insert("expires".into(), js::num(bound));
            session
                .insert("expiresBoundBy".into(), json!("SessionNotOnOrAfter"));
            tracing::info!(
                "authn: session {} ends at {}, the partner's \
                 SessionNotOnOrAfter, which is earlier than its own \
                 lifetime.",
                js::or_empty(session.get("id")),
                iso(bound)
            );
        }
    }

    fn refuse_row(
        &self,
        username: &str,
        via: &str,
        code: &str,
        summary: String,
        facts: Object,
        more: Object,
    ) {
        self.deps.audit.audit(&json!({
            "action": "session.refuse",
            "actor": username,
            "errorCode": code,
            "protocol": if via.is_empty() { DEFAULT_VIA } else { via },
            "channel": "http",
            "target": "",
            "summary": summary,
            "detail": js::assign(&facts, &more),
        }));
    }

    /// `authnPolicyRefusal(amr, credential)`: the realm's authentication
    /// policy asked of the mechanism that answered, in its role; '' or
    /// `STS-AUTHN-0268` / `STS-AUTHN-0269`.
    #[tracing::instrument(level = "debug", skip(self, credential))]
    pub fn authn_policy_refusal(
        &self,
        amr: &[String],
        credential: Option<&Value>,
    ) -> String {
        let kind = credential
            .map(|c| js::or_empty(c.get("kind")))
            .unwrap_or_default();
        let mut primary = amr.len() <= 1;
        let mechanism = match kind.as_str() {
            "certificate" | "kerberos" | "federation" => {
                primary = true;
                kind.clone()
            }
            "password" => "password".into(),
            "wallet" => "wallet".into(),
            "email-code" => "emailCode".into(),
            "email-link" => "emailLink".into(),
            "webauthn" if !amr.iter().any(|a| a == "pwd") => {
                primary = true;
                "passkey".into()
            }
            _ => String::new(),
        };
        let role = if primary { "primary" } else { "second-factor" };
        let refused =
            !mechanism.is_empty() && !self.deps.policy.allows(&mechanism, role);
        if !refused {
            String::new()
        } else if primary {
            codes::STS_AUTHN_0268.as_str().into()
        } else {
            codes::STS_AUTHN_0269.as_str().into()
        }
    }

    fn refuse_on_mechanism(
        &self,
        detail: &mut Object,
        username: &str,
        via: &str,
        answer: &Value,
        method: &str,
    ) -> Option<Value> {
        let mechanism = &answer["mechanism"];
        let second = mechanism.get("secondFactor") == Some(&json!(true));
        let code = if second {
            codes::STS_AUTHN_0305
        } else {
            codes::STS_AUTHN_0298
        };
        let application = js::or_empty(detail.get("application"));
        tracing::info!(
            "{}authn: a session for \"{}\" was REFUSED at the {} door: \"{}\" \
             allows {}{}.",
            tag(code.as_str()),
            username,
            if via.is_empty() { "sign-in" } else { via },
            application,
            if second { "the second factors " } else { "" },
            js::strings(mechanism.get("allowed")).join(", ")
        );
        let mut more = Object::new();
        more.insert(
            "allowed".into(),
            mechanism.get("allowed").cloned().unwrap_or(Value::Null),
        );
        more.insert(
            "used".into(),
            mechanism.get("satisfied").cloned().unwrap_or(Value::Null),
        );
        more.insert("policy".into(), json!(js::or_empty(answer.get("policy"))));
        self.refuse_row(
            username,
            via,
            code.as_str(),
            format!(
                "a session for {} was refused at the {} door: the \
                 application does not allow {}",
                username,
                if via.is_empty() { "sign-in" } else { via },
                if second {
                    "that second factor"
                } else {
                    "that sign-in mechanism"
                }
            ),
            record::attempt_facts(&application, method),
            more,
        );
        detail.insert("refusedWith".into(), json!(code.as_str()));
        detail.insert(
            "refusedWhy".into(),
            answer.get("why").cloned().unwrap_or(Value::Null),
        );
        None
    }

    /// `refusedOnDevice()`: the gated path's device question.
    #[allow(clippy::too_many_arguments)]
    fn refused_on_device(
        &self,
        attempt: &mut Attempt,
        detail: &mut Object,
        username: &str,
        via: &str,
        method: &str,
        request: Option<&Request>,
    ) -> bool {
        let requirement = self.deps.gate.device_requirement();
        let fact = self.device_for(attempt, detail, Some(username), request);
        let wants = |w: &str| requirement.iter().any(|r| r == w);
        let matters = wants("compliant")
            || (js::truthy(Some(&fact))
                && fact.get("status") == Some(&json!("compromised"))
                && wants("not-compromised"));
        if !matters {
            return false;
        }
        let application = js::or_empty(detail.get("application"));
        let answer = self.deps.gate.check(&json!({
            "application": application,
            "kind": "start-session",
            "subject": {
                "kind": "user", "name": username,
                "authenticated":
                    detail.get("authenticated") != Some(&Value::Bool(false)),
            },
            "claims": null, "risk": null, "rolesWaived": true,
            "device": fact,
        }));
        if answer.get("allowed") == Some(&json!(true))
            || !js::truthy(answer.get("device"))
        {
            return false;
        }
        let code =
            if answer["device"].get("refusal") == Some(&json!("compromised")) {
                codes::STS_DEVICE_0038
            } else {
                codes::STS_DEVICE_0037
            };
        self.deps.audit.audit(&json!({
            "action": "session.refuse", "actor": username,
            "errorCode": code.as_str(),
            "protocol": if via.is_empty() { DEFAULT_VIA } else { via },
            "channel": "http", "target": "",
            "summary": format!(
                "a session for {} was refused on its device at the {} door",
                username, if via.is_empty() { "sign-in" } else { via }),
            "detail": js::assign(&record::attempt_facts(&application, method),
                &obj(&json!({
                    "why": answer.get("why").cloned().unwrap_or(Value::Null),
                    "device": if js::truthy(Some(&fact)) {
                        js::text(&fact["id"]) } else { String::new() },
                    "policy": js::or_empty(answer.get("policy")),
                }))),
        }));
        detail.insert("refusedWith".into(), json!(code.as_str()));
        detail.insert(
            "refusedWhy".into(),
            answer.get("why").cloned().unwrap_or(Value::Null),
        );
        tracing::info!(
            "authn: a session for \"{}\" was REFUSED on its device ({}).",
            username,
            js::or_empty(answer["device"].get("refusal"))
        );
        true
    }

    // -------------------------------------------------------------------
    // startSession()
    // -------------------------------------------------------------------

    /// `startSession(res, username, amr, acr, via, detail)`: the session for
    /// a person who just authenticated, or `None` with `detail.refusedWith`
    /// (and often `refusedWhy`) saying why. `request` is Node's
    /// `detail.request`, the request the door is answering.
    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(level = "debug", skip_all, fields(username))]
    pub fn start_session(
        &self,
        response: &mut Response,
        username: &str,
        amr: &[String],
        acr: &str,
        via: &str,
        detail: &mut Object,
        request: Option<&Request>,
    ) -> Option<Value> {
        let mut attempt = Attempt::default();
        let authenticated =
            detail.get("authenticated") != Some(&Value::Bool(false));
        let keyed = js::truthy(detail.get("key"));
        let application = js::or_empty(detail.get("application"));
        let door = if via.is_empty() { "sign-in" } else { via };
        let protocol = if via.is_empty() { DEFAULT_VIA } else { via };
        let method = if authenticated {
            record::method_phrase_for(amr)
        } else {
            "declined".to_string()
        };
        let facts = record::attempt_facts(&application, &method);
        let credential = detail.get("credential").cloned();
        let credential_arg = credential.clone().unwrap_or(Value::Null);
        self.deps.policy.select_passkey_policy(
            username,
            detail.get("application").unwrap_or(&Value::Null),
        );

        if let Some(retiring) = self.deps.realms.retiring_refusal() {
            let why = js::string_of(retiring.get("why"));
            tracing::info!(
                "authn: a session for \"{}\" was REFUSED at the {} door: {}",
                username,
                door,
                why
            );
            self.refuse_row(
                username,
                via,
                codes::STS_CORE_0121.as_str(),
                format!(
                    "a session for {} was refused at the {} door: the realm \
                     is being removed",
                    username, door
                ),
                facts.clone(),
                obj(&json!({"why": why})),
            );
            detail.insert(
                "refusedWith".into(),
                json!(codes::STS_CORE_0121.as_str()),
            );
            detail.insert("refusedWhy".into(), json!(why));
            return None;
        }
        if authenticated && self.deps.accounts.is_disabled(username) {
            tracing::info!(
                "authn: a session for \"{}\" was REFUSED at the {} door: the \
                 account is disabled.",
                username,
                door
            );
            self.refuse_row(
                username,
                via,
                codes::STS_AUTHN_0201.as_str(),
                format!(
                    "a session for {} was refused at the {} door: the \
                     account is disabled",
                    username, door
                ),
                facts.clone(),
                obj(
                    &json!({"why": "pwdAccountLockedTime is set on the entry"}),
                ),
            );
            detail.insert(
                "refusedWith".into(),
                json!(codes::STS_AUTHN_0201.as_str()),
            );
            return None;
        }
        if authenticated
            && !keyed
            && self
                .deps
                .accounts
                .service_account_refuses_door(username, "browser")
        {
            tracing::info!(
                "authn: a session for \"{}\" was REFUSED at the {} door: it \
                 is a service account and this realm's service-account \
                 policy refuses it every browser sign-in.",
                username,
                door
            );
            self.refuse_row(
                username,
                via,
                codes::STS_SVCACCT_0010.as_str(),
                format!(
                    "a session for {} was refused at the {} door: a service \
                     account may not sign in at a browser in this realm",
                    username, door
                ),
                facts.clone(),
                obj(&json!({"why": "stsServiceAccount is TRUE and the \
                    service-account policy's allowBrowserSignIn is off"})),
            );
            detail.insert(
                "refusedWith".into(),
                json!(codes::STS_SVCACCT_0010.as_str()),
            );
            return None;
        }
        let policy_code = if authenticated {
            self.authn_policy_refusal(amr, credential.as_ref())
        } else {
            String::new()
        };
        if !policy_code.is_empty() {
            let kind = kind_text(credential.as_ref());
            tracing::info!(
                "authn: a session for \"{}\" was REFUSED at the {} door: this \
                 realm's authentication policy does not accept {} there ({}).",
                username,
                door,
                kind,
                policy_code
            );
            self.refuse_row(
                username,
                via,
                &policy_code,
                format!(
                    "a session for {} was refused at the {} door: the \
                     authentication policy does not accept that mechanism in \
                     that role",
                    username, door
                ),
                facts.clone(),
                obj(&json!({"credential": kind})),
            );
            detail.insert("refusedWith".into(), json!(policy_code));
            return None;
        }
        let synced = if authenticated {
            self.deps
                .credentials
                .passkey_sign_in_refusal(username, &credential_arg)
        } else {
            None
        };
        if let Some(refusal) = synced.filter(|r| js::truthy(Some(r))) {
            let code = js::string_of(refusal.get("code"));
            let reason = js::string_of(refusal.get("reason"));
            tracing::info!(
                "authn: a session for \"{}\" was REFUSED at the {} door: the \
                 passkey policy refused the passkey that answered ({}): {}",
                username,
                door,
                code,
                js::string_of(refusal.get("why"))
            );
            let what = match reason.as_str() {
                "pin-length" => {
                    "the passkey's minimum PIN length is not what the passkey \
                     policy requires"
                }
                "backup-eligible" => {
                    "a synced (backup-eligible) passkey, where the passkey \
                     policy takes only device-bound ones"
                }
                "post-quantum" => {
                    "a passkey whose signature algorithm is not post-quantum, \
                     where the passkey policy requires a post-quantum one"
                }
                _ => "the issuance policy refused the passkey",
            };
            let id = credential
                .as_ref()
                .filter(|c| js::truthy(Some(c)))
                .map(|c| js::or_empty(c.get("id")))
                .unwrap_or_default();
            self.refuse_row(
                username,
                via,
                &code,
                format!(
                    "a session for {} was refused at the {} door: {}",
                    username, door, what
                ),
                facts.clone(),
                obj(&json!({
                    "credential": "webauthn",
                    "credentialFingerprint": if id.is_empty() {
                        String::new() } else { cookie::handle_hash_of(&id) },
                })),
            );
            if reason == "post-quantum" {
                self.deps.credentials.note_passkey_standing(
                    username,
                    &credential_arg,
                    &refusal,
                );
            }
            detail.insert("refusedWith".into(), json!(code));
            detail.insert(
                "refusedWhy".into(),
                refusal.get("why").cloned().unwrap_or(Value::Null),
            );
            return None;
        }
        if authenticated
            && credential.as_ref().is_some_and(|c| js::truthy(Some(c)))
            && js::or_empty(credential_arg.get("kind")) == "webauthn"
            && credential_arg.get("ceremony") != Some(&json!("registration"))
        {
            self.deps.credentials.note_algorithm_mismatch(
                username,
                &credential_arg,
                &json!(via),
            );
        }
        let recovery = if !authenticated || keyed {
            None
        } else {
            self.deps
                .credentials
                .recovery_refusal_at_session(username, &credential_arg)
        };
        if let Some(refusal) = recovery.filter(|r| js::truthy(Some(r))) {
            let code = js::string_of(refusal.get("code"));
            let reason = js::string_of(refusal.get("reason"));
            let limited = reason == "recovery-enrol-first";
            tracing::info!(
                "authn: a session for \"{}\" was REFUSED at the {} door: the \
                 passkey policy holds an account recovery to the passkey it \
                 replaces ({}).",
                username,
                door,
                code
            );
            self.refuse_row(
                username,
                via,
                &code,
                format!(
                    "a session for {} was refused at the {} door: {}",
                    username,
                    door,
                    if limited {
                        "after an account recovery only a passkey reaches an \
                         application"
                    } else {
                        "the passkey policy lets only an operator recover \
                         this account"
                    }
                ),
                facts.clone(),
                obj(&json!({
                    "credential": kind_text(credential.as_ref()),
                    "reason": reason,
                })),
            );
            detail.insert("refusedWith".into(), json!(code));
            detail.insert(
                "refusedWhy".into(),
                refusal.get("why").cloned().unwrap_or(Value::Null),
            );
            detail.insert("recoveryLimited".into(), json!(limited));
            return None;
        }
        let arrived = request.and_then(|r| self.arrival_session_of(r));
        let current =
            request.and_then(|r| self.cookie_session(Some(r), SESSION_COOKIE));
        if self.setting("authn.multipleAccounts") == Value::Bool(true) {
            self.note_accounts_unported();
        }
        let reauthenticating = match &current {
            Some((_, s)) => {
                !keyed
                    && authenticated
                    && s.get("chosen") != Some(&Value::Bool(false))
                    && s.get("authenticated") != Some(&Value::Bool(false))
                    && !js::truthy(s.get("rpSurface"))
                    && !js::truthy(s.get("credentialKey"))
                    && self.session_ended(Some(s), 0.0).is_empty()
                    && self.deps.binding.honours(s, request)
                    && js::truthy(s.get("user"))
                    && self.same_identity(&s["user"], username)
            }
            None => false,
        };
        let mut replace_id = String::new();
        if request.is_some() {
            let previous =
                current.as_ref().map(|c| c.0.clone()).unwrap_or_default();
            let arrival_id = arrived
                .as_ref()
                .map(|a| js::or_empty(a.get("id")))
                .unwrap_or_default();
            if !previous.is_empty()
                && !reauthenticating
                && !(arrived.is_some() && arrival_id == previous)
            {
                replace_id = previous;
            }
        }
        let mechanism_event = if keyed {
            Value::Null
        } else {
            let mut context = Object::new();
            let mut cred = Object::new();
            cred.insert(
                "kind".into(),
                json!(credential
                    .as_ref()
                    .filter(|c| js::truthy(Some(c)))
                    .map(|c| js::or_empty(c.get("kind")))
                    .unwrap_or_default()),
            );
            for (k, v) in record::phishing_evidence_of(credential.as_ref()) {
                cred.insert(k, v);
            }
            context.insert("credential".into(), Value::Object(cred));
            json!({
                "amr": js::string_array(amr), "acr": acr,
                "authenticated": authenticated,
                "authority": record::authority_of(detail),
                "context": context,
            })
        };
        let subject = json!({"kind": "user", "name": username,
                             "authenticated": authenticated});
        let gated = detail.get("gated") == Some(&json!(true));
        if gated
            && !mechanism_event.is_null()
            && js::truthy(detail.get("application"))
            && (!self
                .deps
                .policy
                .declared_mechanisms(&application, username)
                .is_empty()
                || !self
                    .deps
                    .policy
                    .mfa_allowed(&application, username)
                    .is_empty())
        {
            let answer = self.deps.gate.check(&json!({
                "application": application, "kind": "start-session",
                "subject": subject, "claims": null, "rolesWaived": true,
                "deviceDeferred": true,
                "authenticationEvent": mechanism_event,
            }));
            if answer.get("allowed") != Some(&json!(true))
                && js::truthy(answer.get("mechanism"))
            {
                return self.refuse_on_mechanism(
                    detail, username, via, &answer, &method,
                );
            }
        }
        if !gated {
            let mut ask = obj(&json!({
                "application": application, "kind": "start-session",
                "subject": subject, "claims": null,
            }));
            ask.insert(
                "authentication".into(),
                if authenticated {
                    let kinds = credential
                        .as_ref()
                        .filter(|c| js::truthy(Some(c)))
                        .filter(|c| js::truthy(c.get("kind")))
                        .map(|c| vec![js::text(&c["kind"])])
                        .unwrap_or_default();
                    json!({"amr": js::string_array(amr), "acr": acr,
                           "kinds": kinds})
                } else {
                    Value::Null
                },
            );
            ask.insert("authenticationEvent".into(), mechanism_event.clone());
            if keyed {
                ask.insert("deviceDeferred".into(), json!(true));
            } else {
                let device = self.device_for(
                    &mut attempt,
                    detail,
                    Some(username),
                    request,
                );
                ask.insert("device".into(), device);
            }
            let answer = self.deps.gate.check(&Value::Object(ask));
            let allowed = answer.get("allowed") == Some(&json!(true));
            let risk = &answer["risk"];
            if !allowed
                && js::truthy(Some(risk))
                && !js::truthy(risk.get("observed"))
            {
                let action = js::or_empty(risk.get("action"));
                let code = if action == "step-up" {
                    codes::STS_RISK_0017
                } else {
                    codes::STS_RISK_0016
                };
                let factor = js::or_empty(risk.get("factor"));
                tracing::info!(
                    "authn: a session for \"{}\" was REFUSED on risk at the \
                     {} door ({}{}).",
                    username,
                    door,
                    action,
                    if factor.is_empty() {
                        String::new()
                    } else {
                        format!(": {}", factor)
                    }
                );
                self.deps.audit.audit(&json!({
                    "action": "session.refuse", "actor": username,
                    "errorCode": code.as_str(), "protocol": protocol,
                    "channel": "http", "target": "",
                    "summary": format!("a session for {} was refused on risk \
                        at the {} door", username, door),
                    "detail": js::assign(&facts, &obj(&json!({
                        "action": risk.get("action").cloned()
                            .unwrap_or(Value::Null),
                        "factor": risk.get("factor").cloned()
                            .unwrap_or(Value::Null),
                        "level": "", "assessment": "",
                        "policy": js::or_empty(answer.get("policy")),
                    }))),
                }));
                detail.insert("refusedWith".into(), json!(code.as_str()));
                detail.insert("riskStepUp".into(), json!(factor));
                return None;
            }
            if !allowed && js::truthy(answer.get("mechanism")) {
                return self.refuse_on_mechanism(
                    detail, username, via, &answer, &method,
                );
            }
            if !allowed {
                let why = answer.get("why").cloned().unwrap_or(Value::Null);
                tracing::info!(
                    "authn: a session for \"{}\" was REFUSED by the issuance \
                     policy at the {} door. {}",
                    username,
                    door,
                    js::string_of(Some(&why))
                );
                self.refuse_row(
                    username,
                    via,
                    codes::STS_AUTHN_0010.as_str(),
                    format!(
                        "a session for {} was refused by the issuance policy \
                         at the {} door",
                        username, door
                    ),
                    facts.clone(),
                    obj(&json!({
                        "why": why,
                        "policy": js::or_empty(answer.get("policy")),
                    })),
                );
                let code = if js::truthy(answer.get("device")) {
                    if answer["device"].get("refusal")
                        == Some(&json!("compromised"))
                    {
                        codes::STS_DEVICE_0038
                    } else {
                        codes::STS_DEVICE_0037
                    }
                } else {
                    codes::STS_AUTHN_0010
                };
                detail.insert("refusedWith".into(), json!(code.as_str()));
                detail.insert("refusedWhy".into(), why);
                return None;
            }
        } else if !keyed
            && self.refused_on_device(
                &mut attempt,
                detail,
                username,
                via,
                &method,
                request,
            )
        {
            return None;
        }

        let due = if !authenticated
            || keyed
            || detail.get("postLoginDone") == Some(&json!(true))
            || request.is_none()
            || username.is_empty()
        {
            None
        } else {
            self.deps.policy.post_login_due(username, &application)
        };
        if let Some(due) = due.filter(|d| js::truthy(Some(d))) {
            if detail.get("postLoginHold") == Some(&json!(true)) {
                detail.insert(
                    "postLogin".into(),
                    json!({"due": due, "amr": js::string_array(amr),
                           "acr": acr, "via": via}),
                );
                detail.insert(
                    "refusedWith".into(),
                    json!(codes::STS_AUTHN_0473.as_str()),
                );
                detail.insert(
                    "refusedWhy".into(),
                    json!(
                        "You have to complete a step after signing in. \
                           Start the request again from the application \
                           that sent you here."
                    ),
                );
                tracing::info!(
                    "authn: the session for \"{}\" is HELD at the {} door \
                     for a post-login activity ({}, {}).",
                    username,
                    door,
                    js::string_of(due.get("activity")),
                    if js::truthy(due.get("required")) {
                        "required"
                    } else {
                        "skippable"
                    }
                );
                return None;
            }
            if js::truthy(due.get("required")) {
                tracing::info!(
                    "{}authn: a session for \"{}\" was REFUSED at the {} \
                     door: a required post-login activity ({}) cannot be \
                     done there.",
                    tag(codes::STS_AUTHN_0473.as_str()),
                    username,
                    door,
                    js::string_of(due.get("activity"))
                );
                self.deps.audit.audit(&json!({
                    "action": "authn.post-login.held", "actor": username,
                    "errorCode": codes::STS_AUTHN_0473.as_str(),
                    "outcome": "failure", "protocol": protocol,
                    "channel": "http", "target": "",
                    "summary": format!("a session for {} was refused at the \
                        {} door: a required post-login activity is overdue \
                        and cannot be done there", username, door),
                    "detail": js::assign(&facts, &obj(&json!({
                        "activity": due.get("activity").cloned()
                            .unwrap_or(Value::Null),
                        "profile": due.get("profile").cloned()
                            .unwrap_or(Value::Null),
                        "askedBy": due.get("askedBy").cloned()
                            .unwrap_or(Value::Null),
                    }))),
                }));
                detail.insert(
                    "refusedWith".into(),
                    json!(codes::STS_AUTHN_0473.as_str()),
                );
                detail.insert(
                    "refusedWhy".into(),
                    json!(
                        "Before you can sign in this way you have to \
                           register a post-quantum passkey, and the time \
                           allowed for it has passed. Sign in at this \
                           service's sign-in screen, where you will be asked \
                           to register it."
                    ),
                );
                return None;
            }
        }

        if keyed {
            let wanted = js::string_of(detail.get("key"));
            let found = self.here().entries().into_iter().find(|(_, held)| {
                js::or_empty(held.get("credentialKey")) == wanted
                    && held.get("credentialKey").is_some_and(Value::is_string)
                    && self.session_ended(Some(held), 0.0).is_empty()
            });
            if let Some((id, mut found)) = found {
                let now = self.now();
                let calls = match found.get("calls") {
                    Some(c) if js::truthy(Some(c)) => js::number(Some(c)),
                    _ => 1.0,
                };
                if let Some(f) = found.as_object_mut() {
                    f.insert(
                        "expires".into(),
                        js::num(now + self.session_lifetime_ms()),
                    );
                    f.insert("lastSeenAt".into(), js::num(now));
                    f.insert("calls".into(), js::num(calls + 1.0));
                }
                self.here().set(&id, found.clone());
                let via_was = if via.is_empty() {
                    js::or_empty(found.get("via"))
                } else {
                    via.to_string()
                };
                self.notify(
                    "presented",
                    Some(&found),
                    obj(&json!({"via": via_was, "req": null})),
                    None,
                );
                return Some(found);
            }
        }
        if reauthenticating {
            let (_, session) = current?;
            let again = self.reauthenticate_session(
                &mut attempt,
                response,
                session,
                username,
                amr,
                acr,
                via,
                detail,
                request,
            );
            self.deps
                .credentials
                .recovery_completed(username, &Value::Object(detail.clone()));
            return Some(again);
        }
        let session_id = match &arrived {
            Some(a) => js::or_empty(a.get("id")),
            None => self.deps.clock.random_id(24),
        };
        let first =
            self.event(&mut attempt, amr, acr, via, detail, username, request);
        let mut stats = obj(&json!({
            "presented": username, "protocol": protocol,
            "method": if authenticated {
                record::method_phrase_for(amr) } else { "declined".into() },
            "amr": js::string_array(amr), "acr": acr,
            "sessionId": session_id,
            "note": if authenticated { self.default_sign_in_note() } else {
                "Nobody authenticated: this is the anonymous principal, from \
                 \"Continue without signing in\" at the sign-in screen."
                    .into() },
        }));
        stats = js::assign(&stats, &Self::stats_extra(detail));
        stats.insert("sessionId".into(), json!(session_id));
        self.deps
            .records
            .record_authentication(&Value::Object(stats), request);
        let user = self.deps.people.user_for(username);
        if !js::truthy(user.get("sub"))
            && authenticated
            && !keyed
            && self.deps.people.has_subject_resolver()
        {
            let federation = js::object_of(detail.get("federation"));
            let fed_id = js::or_empty(federation.get("id"));
            tracing::info!(
                "{}authn: a session for \"{}\" was REFUSED at the {} door: \
                 the directory holds no entry for them, so there is no \
                 subject to give the session. {}",
                tag(codes::STS_AUTHN_0180.as_str()),
                username,
                door,
                if fed_id.is_empty() {
                    "ldap.autocreateUsers is off, so the person has to be \
                     created before they sign in."
                        .to_string()
                } else {
                    format!(
                        "Dynamic provisioning is off on the federation \
                         relationship \"{}\", so the person has to be \
                         provisioned before they sign in.",
                        fed_id
                    )
                }
            );
            self.refuse_row(
                username,
                via,
                codes::STS_AUTHN_0180.as_str(),
                format!(
                    "a session for {} was refused: the directory holds no \
                     entry for them",
                    username
                ),
                facts.clone(),
                obj(&json!({
                    "why": "no directory entry, so no subject",
                    "federation": fed_id,
                    "autocreate": if detail.get("federation")
                        .is_some_and(|f| js::truthy(Some(f))) {
                        (federation.get("autocreate") != Some(&json!(false)))
                            .to_string()
                    } else { String::new() },
                })),
            );
            detail.insert(
                "refusedWith".into(),
                json!(codes::STS_AUTHN_0180.as_str()),
            );
            return None;
        }
        let now = self.now();
        let mut session = Object::new();
        session.insert("id".into(), json!(session_id));
        session.insert("user".into(), user.clone());
        session.insert("authTime".into(), first["at"].clone());
        session.insert(
            "expires".into(),
            js::num(now + self.session_lifetime_ms()),
        );
        session.insert("authenticated".into(), json!(authenticated));
        session.insert("chosen".into(), json!(true));
        session.insert(
            "subjectId".into(),
            json!(record::subject_id_of(Some(&user))),
        );
        session.insert(
            "startedAt".into(),
            match &arrived {
                Some(a) => a.get("startedAt").cloned().unwrap_or(Value::Null),
                None => js::num(now),
            },
        );
        session.insert("amr".into(), js::string_array(amr));
        session.insert("acr".into(), json!(acr));
        session.insert("events".into(), json!([first.clone()]));
        session.insert("via".into(), json!(protocol));
        session.insert(
            "credentialKey".into(),
            if keyed {
                json!(js::string_of(detail.get("key")))
            } else {
                Value::Null
            },
        );
        session.insert("lastSeenAt".into(), js::num(now));
        session.insert("calls".into(), json!(1));
        session.insert("risk".into(), Value::Null);
        self.bind_partner_session(&mut session, detail);
        let upgrading = arrived.is_some() && self.here().has(&session_id);
        if upgrading {
            self.end_one_own(&Value::Object(session.clone()), &session_id);
        } else if !self.make_room(&Value::Object(session.clone()), &replace_id)
        {
            self.deps.audit.audit(&json!({
                "action": "session.refuse", "actor": username,
                "errorCode": codes::STS_AUTHN_0337.as_str(),
                "protocol": protocol, "channel": "http", "target": "",
                "summary": format!("a session for {} was refused: the realm \
                    is at authn.maxSessions", username),
                "detail": js::assign(&facts, &obj(&json!({
                    "why": "the realm is at authn.maxSessions and this \
                            insert freed no row",
                }))),
            }));
            detail.insert(
                "refusedWith".into(),
                json!(codes::STS_AUTHN_0337.as_str()),
            );
            return None;
        }
        let value = self.mint(&mut session);
        self.here().set(&session_id, Value::Object(session.clone()));
        if !replace_id.is_empty()
            && replace_id != session_id
            && self.here().has(&replace_id)
        {
            tracing::info!(
                "authn: ending the session this browser was already on ({}) \
                 because a new sign-in is replacing it. Every sign-in is a \
                 privilege change and the old session must not outlive it.",
                replace_id
            );
            self.drop_session(
                &replace_id,
                "a new sign-in in the same browser",
                true,
                request,
                "user",
            );
        }
        if detail.get("cookie") != Some(&json!(false)) {
            response.set_cookie(self.cookie_line(SESSION_COOKIE, &value));
            self.deps
                .binding
                .offer(response, &Value::Object(session.clone()));
        }
        let mut more = Object::new();
        more.insert("sessionId".into(), json!(session_id));
        put_defined(&mut more, "sub", user.get("sub"));
        more.insert("amr".into(), json!(amr.join(", ")));
        more.insert("acr".into(), json!(acr));
        more.insert("authTime".into(), session["authTime"].clone());
        more.insert(
            "expiresAt".into(),
            json!(iso(js::number(session.get("expires")))),
        );
        let cred = credential.clone().unwrap_or(Value::Null);
        if js::truthy(cred.get("algorithm")) {
            let cose = if js::truthy(cred.get("coseAlg")) {
                format!(" ({})", js::text(&cred["coseAlg"]))
            } else {
                String::new()
            };
            more.insert(
                "credentialAlgorithm".into(),
                json!(format!("{}{}", js::text(&cred["algorithm"]), cose)),
            );
        }
        if js::truthy(cred.get("lane")) {
            more.insert(
                "credentialLane".into(),
                json!(js::text(&cred["lane"])),
            );
        }
        more.insert(
            "note".into(),
            json!(match js::or_empty(detail.get("note")) {
                n if n.is_empty() => self.default_sign_in_note(),
                n => n,
            }),
        );
        let summary = match js::or_empty(detail.get("summary")) {
            s if s.is_empty() => format!(
                "{} was signed in at the {} screen; session {} was created",
                username, protocol, session_id
            ),
            s => s,
        };
        self.deps.audit.audit(&json!({
            "action": "session.start", "actor": username,
            "protocol": protocol, "channel": "http", "target": session_id,
            "summary": summary,
            "detail": js::assign(&facts, &more),
        }));
        session.insert("firstPresentationIsTheSignIn".into(), json!(true));
        let session = Value::Object(session);
        self.here().set(&session_id, session.clone());
        self.notify(
            "established",
            Some(&session),
            obj(&json!({"via": protocol, "req": null})),
            request,
        );
        if let Some(risk) = &self.deps.risk {
            risk.assess(
                &session,
                &first,
                &json!(via),
                &Value::Object(detail.clone()),
            );
        }
        if !keyed {
            response.locals.insert(
                "stsStartedSession".into(),
                json!({"id": session_id,
                "username": match js::or_empty(user.get("username")) {
                    u if u.is_empty() => username.to_string(),
                    u => u,
                }}),
            );
        }
        self.deps
            .credentials
            .recovery_completed(username, &Value::Object(detail.clone()));
        Some(session)
    }

    /// `reauthenticateSession()`: the same person on a live session — an
    /// event ADDED (the first kept, then the most recent, at most
    /// [`MAX_SESSION_EVENTS`]), the handle rotated, `sid` and the derived
    /// sessions, parties and refresh tokens untouched.
    #[allow(clippy::too_many_arguments)]
    fn reauthenticate_session(
        &self,
        attempt: &mut Attempt,
        response: &mut Response,
        session: Value,
        username: &str,
        amr: &[String],
        acr: &str,
        via: &str,
        detail: &Object,
        request: Option<&Request>,
    ) -> Value {
        let mut s = obj(&session);
        let previous = json!({
            "amr": s.get("amr").cloned().filter(Value::is_array)
                .unwrap_or(json!([])),
            "acr": js::or_empty(s.get("acr")),
            "authTime": s.get("authTime").cloned()
                .filter(|v| js::truthy(Some(v))).unwrap_or(json!(0)),
            "via": js::or_empty(s.get("via")),
        });
        let event =
            self.event(attempt, amr, acr, via, detail, username, request);
        let mut events = match s.get("events") {
            Some(Value::Array(e)) if !e.is_empty() => e.clone(),
            _ => vec![record::unrecorded_event(&s)],
        };
        events.push(event.clone());
        if events.len() > MAX_SESSION_EVENTS {
            let dropped = events.len() - MAX_SESSION_EVENTS;
            let mut kept = vec![events[0].clone()];
            kept.extend(events[dropped + 1..].iter().cloned());
            events = kept;
            let before = js::number_or_zero(s.get("eventsDropped"));
            s.insert("eventsDropped".into(), js::num(before + dropped as f64));
        }
        s.insert("events".into(), Value::Array(events));
        s.insert("amr".into(), event["amr"].clone());
        s.insert("acr".into(), event["acr"].clone());
        s.insert("authTime".into(), event["at"].clone());
        s.insert("via".into(), event["via"].clone());
        s.insert("lastSeenAt".into(), js::num(self.now()));
        s.insert("firstPresentationIsTheSignIn".into(), json!(true));
        self.bind_partner_session(&mut s, detail);
        let value = self.mint(&mut s);
        let id = js::or_empty(s.get("id"));
        self.here().set(&id, Value::Object(s.clone()));
        if detail.get("cookie") != Some(&json!(false)) {
            response.set_cookie(self.cookie_line(SESSION_COOKIE, &value));
            self.deps.binding.offer(response, &Value::Object(s.clone()));
        }
        let protocol = js::string_of(event.get("via"));
        let method = record::method_phrase_for(amr);
        let sub = s["user"].get("sub").cloned();
        let mut stats = Object::new();
        stats.insert("presented".into(), json!(username));
        stats.insert("protocol".into(), json!(protocol));
        stats.insert("method".into(), json!(method));
        put_defined(&mut stats, "sub", sub.as_ref());
        stats.insert("amr".into(), event["amr"].clone());
        stats.insert("acr".into(), event["acr"].clone());
        stats.insert(
            "note".into(),
            json!(
                "A re-authentication on a session this person already \
                   held."
            ),
        );
        stats = js::assign(&stats, &Self::stats_extra(detail));
        stats.insert("sessionId".into(), json!(id));
        self.deps
            .records
            .record_authentication(&Value::Object(stats), request);
        let application = js::or_empty(detail.get("application"));
        let count = s["events"].as_array().map_or(0, Vec::len) as f64
            + js::number_or_zero(s.get("eventsDropped"));
        let prev_acr = js::string_of(previous.get("acr"));
        self.deps.audit.audit(&json!({
            "action": "session.reauthenticate", "actor": username,
            "protocol": protocol, "channel": "http", "target": id,
            "summary": format!("{} re-authenticated through {} on session {} \
                (acr {} to {})", username, protocol, id,
                if prev_acr.is_empty() { "none" } else { &prev_acr },
                if acr.is_empty() { "none" } else { acr }),
            "detail": js::assign(&record::attempt_facts(&application, &method),
                &with_sub(sub.as_ref(), json!({
                    "sessionId": id,
                    "amr": amr.join(", "), "acr": acr,
                    "previousAmr": js::strings(previous.get("amr")).join(", "),
                    "previousAcr": prev_acr,
                    "authTime": event["at"],
                    "events": js::num(count),
                    "authority": event["authority"]["kind"],
                    "expiresAt": iso(js::number(s.get("expires"))),
                }))),
        }));
        let s = Value::Object(s);
        self.notify(
            "reauthenticated",
            Some(&s),
            obj(&json!({"via": protocol, "previous": previous, "req": null})),
            request,
        );
        if let Some(risk) = &self.deps.risk {
            risk.assess(
                &s,
                &event,
                &json!(protocol),
                &Value::Object(detail.clone()),
            );
        }
        s
    }

    fn note_accounts_unported(&self) {
        tracing::warn!(
            "authn: authn.multipleAccounts is on, and this runtime does not \
             hold browsers' account sets yet (#561): a sign-in in a browser \
             already signed in REPLACES the session, as with the setting \
             off."
        );
    }

    /// `backdateAuthentication(session, seconds)` (#1554): a federated
    /// sign-in's real authentication time, never moved forward.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn backdate_authentication(&self, sid: &str, seconds: f64) {
        let view = self.here();
        let Some(mut s) = view.get(sid) else {
            return;
        };
        if seconds > 0.0 && seconds < js::number_or_zero(s.get("authTime")) {
            s["authTime"] = js::num(seconds);
            if let Some(last) = s
                .get_mut("events")
                .and_then(Value::as_array_mut)
                .and_then(|e| e.last_mut())
            {
                last["at"] = js::num(seconds);
            }
            view.set(sid, s);
        }
    }

    // -------------------------------------------------------------------
    // Arrival sessions.
    // -------------------------------------------------------------------

    /// `startArrivalSession(req, res, via)`: an anonymous, unchosen row for
    /// a cookie-less visitor at a front door; never a sign-in.
    #[tracing::instrument(level = "debug", skip(self, request, response))]
    pub fn start_arrival_session(
        &self,
        request: &Request,
        response: &mut Response,
        via: &str,
    ) -> Option<Value> {
        if self.cookie_session(Some(request), SESSION_COOKIE).is_some() {
            return None;
        }
        let id = self.deps.clock.random_id(24);
        let now = self.now();
        let mut s = Object::new();
        s.insert("id".into(), json!(id));
        s.insert("user".into(), self.deps.people.user_for(ANONYMOUS_USERNAME));
        s.insert("authenticated".into(), json!(false));
        s.insert("chosen".into(), json!(false));
        s.insert("authTime".into(), js::num(self.now_sec()));
        s.insert("expires".into(), js::num(now + self.pending_ttl_ms()));
        s.insert("startedAt".into(), js::num(now));
        s.insert("lastSeenAt".into(), js::num(now));
        s.insert("amr".into(), json!([]));
        s.insert("acr".into(), json!("0"));
        s.insert(
            "via".into(),
            json!(if via.is_empty() { "unknown" } else { via }),
        );
        s.insert("relyingParties".into(), json!([]));
        s.insert("events".into(), json!([]));
        s.insert("subjectId".into(), json!(""));
        if !self.make_room(&Value::Object(s.clone()), "") {
            return None;
        }
        let value = self.mint(&mut s);
        let s = Value::Object(s);
        self.here().set(&id, s.clone());
        response.set_cookie(self.cookie_line(SESSION_COOKIE, &value));
        Some(s)
    }

    /// `arrivalSessionOf(req)`: the cookie's arrival row, while live.
    fn arrival_session_of(&self, request: &Request) -> Option<Value> {
        let (_, s) = self.cookie_session(Some(request), SESSION_COOKIE)?;
        if s.get("chosen") != Some(&Value::Bool(false)) {
            return None;
        }
        if js::number(s.get("expires")) < self.now() {
            return None;
        }
        Some(s)
    }

    /// `touchArrivalSession(req)`: an arrival's window slides while the
    /// person is at the screen.
    #[tracing::instrument(level = "debug", skip(self, request))]
    pub fn touch_arrival_session(&self, request: &Request) {
        let Some((id, mut s)) =
            self.cookie_session(Some(request), SESSION_COOKIE)
        else {
            return;
        };
        if s.get("chosen") != Some(&Value::Bool(false)) {
            return;
        }
        let now = self.now();
        if js::truthy(s.get("expires")) && js::number(s.get("expires")) <= now {
            return;
        }
        s["expires"] = js::num(now + self.pending_ttl_ms());
        s["lastSeenAt"] = js::num(now);
        self.here().set(&id, s);
    }

    // -------------------------------------------------------------------
    // The caps (#345, #350).
    // -------------------------------------------------------------------

    fn counts_toward_subject(s: &Value) -> bool {
        match s.get("chosen") {
            Some(Value::Bool(false)) => false,
            Some(Value::Bool(true)) => true,
            _ => js::truthy(s.get("rpSurface")),
        }
    }

    fn earlier(a: &Value, b: &Value) -> bool {
        let (sa, sb) = (
            js::number_or_zero(a.get("lastSeenAt")),
            js::number_or_zero(b.get("lastSeenAt")),
        );
        if sa != sb {
            return sa < sb;
        }
        js::number_or_zero(a.get("startedAt"))
            < js::number_or_zero(b.get("startedAt"))
    }

    fn subject_cap(&self) -> f64 {
        let mut per =
            js::number(Some(&self.setting("authn.maxSessionsPerSubject")))
                .floor();
        let cap = js::number(Some(&self.setting("authn.maxSessions"))).floor();
        if cap >= 1.0 && per > cap {
            per = cap;
        }
        per
    }

    fn note_capacity_end(&self, count: u64) {
        let now = self.now();
        let mut log = self
            .capacity_log
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        log.0 += count;
        if now - log.1 >= 60000.0 {
            tracing::warn!(
                "{}authn: {} session(s) were ended at the per-subject \
                 session cap. Each was that subject's own oldest countable \
                 session, never another subject's and never an arrival. \
                 Each is an audit row.",
                tag(codes::STS_AUTHN_0292.as_str()),
                log.0
            );
            *log = (0, now);
        }
    }

    /// `endOneOwn(store, incoming, skipId)`: a subject at
    /// `authn.maxSessionsPerSubject` loses their own oldest countable row.
    fn end_one_own(&self, incoming: &Value, skip: &str) -> u64 {
        if !Self::counts_toward_subject(incoming) {
            return 0;
        }
        let subject = js::or_empty(incoming.get("subjectId"));
        if subject.is_empty() {
            return 0;
        }
        let cap = self.subject_cap();
        if cap.is_nan() || cap < 1.0 {
            return 0;
        }
        let derived = js::or_empty(incoming.get("derivedFrom"));
        let mut count = 0.0;
        let mut oldest: Option<(String, Value)> = None;
        for (id, row) in self.here().entries() {
            if !Self::counts_toward_subject(&row)
                || js::or_empty(row.get("subjectId")) != subject
            {
                continue;
            }
            if !skip.is_empty() && id == skip {
                continue;
            }
            count += 1.0;
            if !derived.is_empty() && id == derived {
                continue;
            }
            let older = match &oldest {
                None => true,
                Some((_, o)) => Self::earlier(&row, o),
            };
            if older {
                oldest = Some((id, row));
            }
        }
        let Some((id, row)) = oldest.filter(|_| count >= cap) else {
            return 0;
        };
        self.expire_session(
            &id,
            &row,
            "the per-subject session cap",
            "capacity",
        );
        self.note_capacity_end(1);
        1
    }

    /// `makeRoomForSession(store, session, replacingId)`: false at
    /// `authn.maxSessions` when the insert freed no row (`STS-AUTHN-0337`).
    fn make_room(&self, session: &Value, replacing: &str) -> bool {
        let id = js::or_empty(session.get("id"));
        if !id.is_empty() && self.here().has(&id) {
            return true;
        }
        let ended = self.end_one_own(session, "");
        let cap = js::number(Some(&self.setting("authn.maxSessions"))).floor();
        let mut size = self.here().len() as f64;
        if !replacing.is_empty()
            && replacing != id
            && self.here().has(replacing)
        {
            size -= 1.0;
        }
        if cap >= 1.0 && size >= cap && ended == 0 {
            let now = self.now();
            let mut log = self
                .refuse_log
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            log.0 += 1;
            if now - log.1 >= 60000.0 {
                tracing::warn!(
                    "{}authn: {} new session(s) were not admitted. The realm \
                     is at authn.maxSessions and the insert freed no row. An \
                     arrival continues with no cookie; a chosen sign-in is \
                     drawn again.",
                    tag(codes::STS_AUTHN_0337.as_str()),
                    log.0
                );
                *log = (0, now);
            }
            return false;
        }
        true
    }

    // -------------------------------------------------------------------
    // sessionOf()
    // -------------------------------------------------------------------

    /// `sessionOf(req)`: the signed-in session the sign-on cookie names, in
    /// the ambient realm, held to every rule — an ended or idle one is
    /// expired on the way past, an arrival is nobody's, a disabled or
    /// deleted account's is ended, a device-bound one needs its bound
    /// cookie (#725). A malformed Cookie header reads as no cookie here,
    /// where Node's `decodeURIComponent()` threw (a Node defect).
    #[tracing::instrument(level = "debug", skip(self, request))]
    pub fn session_of(
        &self,
        request: &Request,
        ignore_binding: bool,
    ) -> Option<Value> {
        let (id, session) =
            self.cookie_session(Some(request), SESSION_COOKIE)?;
        self.honoured_session(request, &id, session, ignore_binding)
    }

    fn honoured_session(
        &self,
        request: &Request,
        id: &str,
        session: Value,
        ignore_binding: bool,
    ) -> Option<Value> {
        let ended = self.session_ended(Some(&session), 0.0);
        if !ended.is_empty() {
            self.expire_session(
                id,
                &session,
                "a request that presented it",
                &ended,
            );
            return None;
        }
        if session.get("chosen") == Some(&Value::Bool(false)) {
            return None;
        }
        if self.session_account_disabled(&session) {
            self.drop_session(
                id,
                "an administrator disabling the account",
                false,
                Some(request),
                "admin",
            );
            return None;
        }
        if self.session_account_gone(&session) {
            self.drop_session(
                id,
                "the deletion of the account",
                false,
                Some(request),
                "admin",
            );
            return None;
        }
        self.deps.binding.note_skipped(&session, Some(request));
        if !ignore_binding
            && !self.deps.binding.honours(&session, Some(request))
        {
            return None;
        }
        Some(self.note_session_used(id, session))
    }

    /// `noteSessionUsed()`: only with an idle timeout in force, and at most
    /// once a second, is a read a write.
    fn note_session_used(&self, id: &str, mut session: Value) -> Value {
        if self.session_idle_timeout_ms() == 0.0 {
            return session;
        }
        let now = self.now();
        let seen = js::number_or_zero(session.get("lastSeenAt"));
        if seen != 0.0 && now - seen < 1000.0 {
            return session;
        }
        session["lastSeenAt"] = js::num(now);
        self.here().set(id, session.clone());
        session
    }

    /// `sessionById(id)`: the ambient realm's row, expiring nothing.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn session_by_id(&self, id: &str) -> Option<Value> {
        self.here().get(id)
    }

    /// `OAuth2Server.sessionIsLive(sid, username)`: a sign-on session still
    /// live, authenticated, and — where a username is given — still that
    /// person's.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn session_is_live(&self, sid: &str, username: Option<&str>) -> bool {
        let Some(held) =
            (!sid.is_empty()).then(|| self.session_by_id(sid)).flatten()
        else {
            return false;
        };
        self.session_ended(Some(&held), 0.0).is_empty()
            && held.get("authenticated") != Some(&Value::Bool(false))
            && js::truthy(held.get("user"))
            && username
                .is_none_or(|u| js::or_empty(held["user"].get("username")) == u)
    }

    /// `sessionStartedAt(session)`, in milliseconds.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn session_started_at(&self, session: &Value) -> i64 {
        record::started_at(session.as_object())
    }

    /// `signOnFactsFor(session)`: how a person is signed in, read from the
    /// sign-on session behind a relying-party session while it is live.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn sign_on_facts_for(&self, session: &Value) -> Value {
        let mut source = session.clone();
        let mut from_parent = false;
        if js::truthy(session.get("derivedFrom")) {
            let realm_id = match js::or_empty(session.get("derivedFromRealm")) {
                r if r.is_empty() => realm::current_id(),
                r => r,
            };
            let parent = self
                .store
                .in_realm(&realm_id)
                .get(&js::string_of(session.get("derivedFrom")));
            if let Some(p) = parent {
                if self.session_ended(Some(&p), 0.0).is_empty() {
                    source = p;
                    from_parent = true;
                }
            }
        }
        let view = record::view(source.as_object());
        let events = if view.events.is_empty() {
            1
        } else {
            view.events.len() as i64
        };
        json!({
            "startedAt": record::started_at(source.as_object()),
            "authTime": view.auth_time * 1000,
            "amr": view.methods.unwrap_or_default(),
            "acr": view.assurance_level.unwrap_or_default(),
            "authentications": events + view.events_dropped.unwrap_or(0),
            "fromParent": from_parent,
            "deviceBound": self.deps.binding.binding_of(&source),
        })
    }

    // -------------------------------------------------------------------
    // Presented, held, changed.
    // -------------------------------------------------------------------

    /// `noteSessionChanged(session)`, as Rust holds it: a protocol that
    /// records something ON a session (`oidcClients`, `wsfedRealms`, …)
    /// edits the HELD row through `edit`, so the store's journal sees the
    /// write and every node gets it. It never brings back a session another
    /// request ended: `false` when the row is gone.
    #[tracing::instrument(level = "debug", skip(self, edit))]
    pub fn note_session_changed(
        &self,
        sid: &str,
        edit: impl FnOnce(&mut Object),
    ) -> bool {
        self.here()
            .update(sid, |row| {
                if let Some(o) = row.as_object_mut() {
                    edit(o);
                }
            })
            .is_some()
    }

    /// `noteSessionChanged()` with a copy the caller changed: merged with the
    /// held row (`mergeSessionRows()`), so neither the edit nor a newer row
    /// replication brought in is lost.
    #[tracing::instrument(level = "debug", skip(self, session))]
    pub fn note_session_copy_changed(&self, session: &Value) -> bool {
        let sid = js::or_empty(session.get("id"));
        let view = self.here();
        let Some(held) = (!sid.is_empty()).then(|| view.get(&sid)).flatten()
        else {
            return false;
        };
        let merged = if &held == session {
            held
        } else {
            merge::merge_session_rows(session, &held, self.now())
        };
        view.set(&sid, merged);
        true
    }

    /// `notePresented(session, via, req, application)`: an existing session
    /// answered a protocol (CAEP `session-presented`, a `session.presented`
    /// row) — except the FIRST presentation of a new session, which is the
    /// sign-in's own round trip and is spent here, in the store too.
    #[tracing::instrument(level = "debug", skip(self, request))]
    pub fn note_presented(
        &self,
        sid: &str,
        via: &str,
        request: Option<&Request>,
        application: &str,
    ) -> bool {
        let Some(session) = self.session_by_id(sid) else {
            return false;
        };
        if js::truthy(session.get("firstPresentationIsTheSignIn")) {
            self.note_session_changed(sid, |s| {
                s.insert("firstPresentationIsTheSignIn".into(), json!(false));
            });
            return false;
        }
        let protocol = if via.is_empty() { DEFAULT_VIA } else { via };
        let user = obj(&session["user"]);
        let username = js::or_empty(user.get("username"));
        let id = js::or_empty(session.get("id"));
        self.deps.audit.audit(&json!({
            "action": "session.presented", "actor": username,
            "protocol": protocol, "channel": "http", "target": id,
            "summary": format!("{}'s existing session {} was presented \
                through {}{}", username, id, protocol,
                if application.is_empty() { String::new() } else {
                    format!(" to {}", application) }),
            "detail": js::assign(
                &record::attempt_facts(application, "existing session"),
                &obj(&json!({
                    "presented": username,
                    "sub": js::or_empty(user.get("sub")),
                    "sessionId": id,
                    "amr": js::strings(session.get("amr")).join(", "),
                    "acr": js::or_empty(session.get("acr")),
                }))),
        }));
        self.notify(
            "presented",
            Some(&session),
            obj(&json!({"via": protocol, "req": null})),
            request,
        );
        true
    }

    /// `holdPresentation(session)`: the request in flight goes through the
    /// consent screen and comes back; that trip is not a presentation.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn hold_presentation(&self, sid: &str) {
        self.note_session_changed(sid, |s| {
            s.insert("firstPresentationIsTheSignIn".into(), json!(true));
        });
    }

    // -------------------------------------------------------------------
    // The end of a session.
    // -------------------------------------------------------------------

    /// `initiatorOf(asked, via)`: the caller's word, or `system` with a
    /// warning (`STS-AUTHN-0290`), never guessed from the sentence.
    fn initiator_of(asked: &str, via: &str) -> String {
        if INITIATING_ENTITIES.contains(&asked) {
            return asked.to_string();
        }
        tracing::warn!(
            "{}authn: a session was ended ({}) without saying who initiated \
             it{}; CAEP session-revoked says \"system\".",
            tag(codes::STS_AUTHN_0290.as_str()),
            if via.is_empty() { "no door named" } else { via },
            if asked.is_empty() {
                String::new()
            } else {
                format!(
                    " (\"{}\" is not one of {})",
                    asked,
                    INITIATING_ENTITIES.join(", ")
                )
            }
        );
        "system".to_string()
    }

    /// `sessionEndOnce(id, emit, onLost)`: the report goes out once however
    /// many processes notice the end. One process (no claim port): inline.
    fn end_once(&self, id: &str, emit: impl FnOnce(), lost: impl FnOnce()) {
        let Some(claims) = &self.deps.claims else {
            emit();
            return;
        };
        let mut answer = Err(String::new());
        for _ in 0..3 {
            answer = claims.claim(id);
            if answer.is_ok() {
                break;
            }
        }
        match answer {
            Ok(true) => emit(),
            Ok(false) => lost(),
            Err(why) => {
                tracing::warn!(
                    "{}authn: whether another process already reported the \
                     end of session {} could not be asked (the claim failed \
                     3 times: {}); it is reported here, and a receiver may \
                     be told twice.",
                    tag(codes::STS_AUTHN_0192.as_str()),
                    id,
                    why
                );
                emit();
            }
        }
    }

    fn plan_backchannel(
        &self,
        session: &Value,
        via: &str,
        trigger: &str,
    ) -> Value {
        match &self.deps.backchannel {
            Some(b) => {
                b.plan(session, &json!({"via": via, "trigger": trigger}))
            }
            None => json!([]),
        }
    }

    fn dispatch_backchannel(&self, planned: &Value) {
        if let Some(b) = &self.deps.backchannel {
            if planned.as_array().is_some_and(|p| !p.is_empty()) {
                b.dispatch(planned);
            }
        }
    }

    /// `derivedFrom(parentId, store, alsoRealm)`: the relying-party sessions
    /// derived from one session, in the ambient partition, the default
    /// realm's, and `also`; one found outside the ambient one must name
    /// this parent's realm.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn derived_from(
        &self,
        parent: &str,
        also: &str,
    ) -> Vec<(String, Value, String)> {
        let here = realm::current_id();
        let mut found: Vec<(String, Value, String)> = Vec::new();
        let mut scan = |realm_id: &str| {
            for (id, held) in self.store.in_realm(realm_id).entries() {
                if js::string_of(held.get("derivedFrom")) != parent
                    || held.get("derivedFrom").is_none()
                    || found.iter().any(|f| f.0 == id)
                {
                    continue;
                }
                let theirs = match js::or_empty(held.get("derivedFromRealm")) {
                    r if r.is_empty() => realm_id.to_string(),
                    r => r,
                };
                if theirs != here {
                    continue;
                }
                found.push((id, held, realm_id.to_string()));
            }
        };
        scan(&here);
        if here != realm::DEFAULT_ID {
            scan(realm::DEFAULT_ID);
        }
        if !also.is_empty()
            && also != here
            && also != realm::DEFAULT_ID
            && self.deps.realms.ids().iter().any(|r| r == also)
        {
            scan(also);
        }
        found
    }

    /// `dropSession(id, via, cookiePresented, req, initiatingEntity)`: THE
    /// ONE PLACE A SESSION STOPS EXISTING. Its derived sessions go with it,
    /// the tokens issued on it are revoked by Back-Channel Logout section
    /// 2.7's rule, and the end is reported once: CAEP `session-revoked`,
    /// then the `session.end` row. Answers the session as it was, because
    /// the parties a sign-out fans out to live on it.
    #[tracing::instrument(level = "debug", skip(self, request))]
    pub fn drop_session(
        &self,
        id: &str,
        via: &str,
        cookie_presented: bool,
        request: Option<&Request>,
        initiating_entity: &str,
    ) -> Option<Value> {
        let entity = Self::initiator_of(initiating_entity, via);
        let view = self.here();
        let session = if id.is_empty() { None } else { view.get(id) };
        if !id.is_empty() {
            view.delete(id);
        }
        if let Some(s) = &session {
            let also = if js::or_empty(s.get("rpSurface")) == "admin" {
                js::or_empty(s.get("derivedFromRealm"))
            } else {
                String::new()
            };
            for (child, held, child_realm) in self.derived_from(id, &also) {
                tracing::info!(
                    "authn: ending the {} session {} (realm {}) with the \
                     sign-on session it was derived from ({}).",
                    match js::or_empty(held.get("rpSurface")) {
                        r if r.is_empty() => "relying party".to_string(),
                        r => r,
                    },
                    child,
                    child_realm,
                    id
                );
                let via_child =
                    format!(
                    "the end of the sign-on session it was derived from ({})",
                    if via.is_empty() { "an unknown door" } else { via }
                );
                let end = || {
                    self.drop_session(
                        &child, &via_child, false, request, &entity,
                    );
                };
                if child_realm != realm::current_id() {
                    self.deps.realms.run_in(&child_realm, &mut || end());
                } else {
                    end();
                }
            }
        }
        if !id.is_empty() {
            let revokes = self.deps.mode.revokes_access_tokens_at_sign_out();
            let revoked = self.deps.records.revoke_session_tokens(
                id,
                revokes,
                "Back-Channel Logout section 2.7: the sign-on session it was \
                 issued on ended",
                &json!({"initiatingEntity": entity}),
                &[format!("sid:{}", id)],
            );
            if revoked > 0 {
                tracing::info!(
                    "Back-Channel Logout section 2.7: signing out of session \
                     {} revoked {} token(s) issued on it. Without that, a \
                     sign-out drops a cookie and leaves a thirty-day \
                     credential in the client's hands.",
                    id,
                    revoked
                );
            }
        }
        match &session {
            Some(s) => {
                let planned = self.plan_backchannel(
                    s,
                    if via.is_empty() { "a sign-out" } else { via },
                    "sign-out",
                );
                let sid = js::or_empty(s.get("id"));
                self.end_once(
                    &sid,
                    || {
                        self.report_sign_out(
                            Some(s),
                            id,
                            via,
                            cookie_presented,
                            request,
                            &entity,
                        );
                        self.dispatch_backchannel(&planned);
                    },
                    || {
                        self.report_sign_out_already_ended(
                            s,
                            via,
                            cookie_presented,
                        )
                    },
                );
            }
            None => self.report_sign_out(
                None,
                id,
                via,
                cookie_presented,
                request,
                &entity,
            ),
        }
        session
    }

    fn report_sign_out(
        &self,
        session: Option<&Value>,
        id: &str,
        via: &str,
        cookie_presented: bool,
        request: Option<&Request>,
        entity: &str,
    ) {
        let door = if via.is_empty() {
            "a sign-out endpoint"
        } else {
            via
        };
        self.notify(
            "revoked",
            session,
            obj(&json!({"via": door, "initiatingEntity": entity,
                        "byAdmin": entity == "admin", "req": null})),
            request,
        );
        let username = session
            .map(|s| js::or_empty(s["user"].get("username")))
            .unwrap_or_default();
        let sid = session
            .map(|s| js::or_empty(s.get("id")))
            .unwrap_or_default();
        self.deps.audit.audit(&json!({
            "action": "session.end",
            "outcome": if session.is_some() { "success" } else { "refused" },
            "errorCode": if session.is_some() { "" } else {
                codes::STS_AUTHN_0011.as_str() },
            "actor": username,
            "channel": "http",
            "target": if session.is_some() { sid.clone() } else {
                id.to_string() },
            "summary": if session.is_some() {
                format!("the sign-on session for {} was ended", username)
            } else {
                "a sign-out was asked for and there was no session to end"
                    .to_string()
            },
            "detail": {
                "sessionId": sid,
                "cookiePresented": if cookie_presented { "yes" } else { "no" },
                "namedBy": if cookie_presented { "the session cookie" } else {
                    "its identifier" },
                "via": door,
                "sessionFound": if session.is_some() { "yes" } else { "no" },
                "amr": session.map(|s| js::strings(s.get("amr")).join(", "))
                    .unwrap_or_default(),
                "acr": session.map(|s| js::or_empty(s.get("acr")))
                    .unwrap_or_default(),
            },
        }));
    }

    fn report_sign_out_already_ended(
        &self,
        session: &Value,
        via: &str,
        cookie_presented: bool,
    ) {
        let username = js::or_empty(session["user"].get("username"));
        let id = js::or_empty(session.get("id"));
        self.deps.audit.audit(&json!({
            "action": "session.end", "outcome": "refused",
            "errorCode": codes::STS_AUTHN_0191.as_str(),
            "actor": username, "channel": "http", "target": id,
            "summary": format!("a sign-out of {}'s session {} found its end \
                already reported by another process", username, id),
            "detail": {
                "sessionId": id,
                "cookiePresented": if cookie_presented { "yes" } else { "no" },
                "via": if via.is_empty() { "a sign-out endpoint" } else { via },
                "sessionFound": "yes, and already ended elsewhere",
            },
        }));
    }

    /// `endSession(req, res)`: the browser's own sign-out — the cookie's
    /// session ended, the cookie cleared.
    #[tracing::instrument(level = "debug", skip(self, request, response))]
    pub fn end_session(
        &self,
        request: &Request,
        response: &mut Response,
    ) -> Option<Value> {
        let id = self
            .cookie_session(Some(request), SESSION_COOKIE)
            .map(|f| f.0)
            .unwrap_or_default();
        let presented =
            !cookie::cookie_value(&request.cookie, SESSION_COOKIE).is_empty();
        let session = self.drop_session(
            &id,
            "the sign-out endpoint for this browser",
            presented,
            Some(request),
            "user",
        );
        self.clear_session_cookie(response, SESSION_COOKIE);
        session
    }

    /// `endSessionById(id, via, initiatingEntity)`: a session the caller has
    /// no cookie for.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn end_session_by_id(
        &self,
        id: &str,
        via: &str,
        initiating_entity: &str,
    ) -> Option<Value> {
        self.drop_session(id, via, false, None, initiating_entity)
    }

    /// `expireSession(store, id, session, via, why)`: the one place a
    /// session ends by RUNNING OUT, for the two lazy lookups, the sweep and
    /// the caps. The delete is local and at once; the report (audit row,
    /// `session-revoked` initiated by `policy`, the back-channel Logout
    /// Tokens where `oauth2.backchannelLogoutOnExpiry`) once per cluster.
    #[tracing::instrument(level = "debug", skip(self, session))]
    pub fn expire_session(
        &self,
        id: &str,
        session: &Value,
        via: &str,
        why: &str,
    ) {
        self.here().delete(id);
        let idle = why == "idle";
        let evicted = why == "capacity";
        let on_expiry = self
            .deps
            .backchannel
            .as_ref()
            .is_some_and(|b| b.on_expiry());
        let planned = if on_expiry {
            self.plan_backchannel(
                session,
                if evicted {
                    "this subject was at authn.maxSessionsPerSubject, and this \
                     was their own oldest countable session"
                } else if idle {
                    "the session went idle (authn.sessionIdleTimeoutS)"
                } else {
                    "the session expired (authn.sessionLifetimeS)"
                },
                "expiry",
            )
        } else {
            json!([])
        };
        let kind = if evicted {
            "capacity"
        } else if idle {
            "idle"
        } else {
            ""
        };
        self.end_once(
            id,
            || {
                self.report_expiry(id, session, via, kind);
                self.dispatch_backchannel(&planned);
            },
            || {},
        );
    }

    fn report_expiry(&self, id: &str, session: &Value, via: &str, kind: &str) {
        let idle = kind == "idle";
        let evicted = kind == "capacity";
        let username = js::or_empty(session["user"].get("username"));
        let mut row = obj(&json!({
            "action": "session.end", "outcome": "success",
            "actor": username,
            "protocol": match js::or_empty(session.get("via")) {
                v if v.is_empty() => "Authentication service".to_string(),
                v => v },
            "channel": "none", "target": id,
            "summary": format!("{}'s session {}{}",
                if username.is_empty() { "somebody" } else { &username }, id,
                if evicted { " was ended at the per-subject session cap: it \
                    was that subject's own oldest countable session" }
                else { " expired and was discarded" }),
            "detail": {
                "sessionId": id,
                "reason": if evicted {
                    "this subject was at authn.maxSessionsPerSubject, and \
                     this was their own oldest countable session \u{2014} \
                     never another subject's row and never an arrival"
                } else if idle {
                    "the session went unused for longer than \
                     authn.sessionIdleTimeoutS"
                } else { "the session lifetime ran out" },
                "noticedBy": via,
                "expiresAt": if js::truthy(session.get("expires")) {
                    iso(js::number(session.get("expires"))) }
                    else { String::new() },
            },
        }));
        if evicted {
            row.insert(
                "errorCode".into(),
                json!(codes::STS_AUTHN_0292.as_str()),
            );
        }
        self.deps.audit.audit(&Value::Object(row));
        let reason = if evicted {
            "This subject was at the per-subject session cap, and this was \
             their own oldest countable session. Nobody signed out \u{2014} \
             this service stopped honouring it. It was not another \
             subject's session and not an arrival."
        } else if idle {
            "The session went unused for longer than this service's idle \
             timeout. Nobody signed out \u{2014} this service stopped \
             honouring a session nobody was using."
        } else {
            "The session lifetime ran out. Nobody signed out \u{2014} this \
             service stopped honouring the session because its absolute \
             expiry passed, and it is not extended by use."
        };
        self.notify(
            "revoked",
            Some(session),
            obj(&json!({"via": via, "byAdmin": false, "expired": true,
                        "initiatingEntity": "policy", "reason": reason,
                        "req": null})),
            None,
        );
    }

    /// `sweepExpiredSessions()`: the body of the `authn.session-expiry` job —
    /// every realm, inside each one, every session that ran out ended
    /// through [`Sessions::expire_session`]; then each realm's
    /// `authn.sessionShedPerSweep` of one subject's surplus.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn sweep_expired_sessions(&self) -> u64 {
        let now = self.now();
        let mut gone = 0;
        for realm_id in self.deps.realms.ids() {
            let mut expired: Vec<(String, Value, String)> = Vec::new();
            self.deps.realms.run_in(&realm_id, &mut || {
                for (id, s) in self.store.in_realm(&realm_id).entries() {
                    if js::truthy(s.get("expires"))
                        && js::number(s.get("expires")) <= now
                    {
                        expired.push((id, s, "expired".into()));
                        continue;
                    }
                    let ended = self.session_ended(Some(&s), now);
                    if !ended.is_empty() {
                        expired.push((id, s, ended));
                    }
                }
                for (id, s, why) in &expired {
                    self.expire_session(id, s, "the session sweep", why);
                    gone += 1;
                }
            });
        }
        let shed = self.shed_subject_surplus();
        if gone > 0 {
            tracing::info!(
                "authn: the session sweep ended {} expired session(s). Each \
                 one is an audit row and a CAEP session-revoked, which is the \
                 whole reason the sweep exists: an expiry noticed only when \
                 somebody comes back is an expiry nobody is ever told about.",
                gone
            );
        }
        gone + shed
    }

    /// `shedSubjectSurplus()`: a lowered per-subject cap does not mass-end;
    /// each sweep ends at most `authn.sessionShedPerSweep` such rows per
    /// realm, oldest first, one subject at a time.
    fn shed_subject_surplus(&self) -> u64 {
        let mut shed = 0;
        for realm_id in self.deps.realms.ids() {
            self.deps.realms.run_in(&realm_id, &mut || {
                let budget = js::number(Some(
                    &self.setting("authn.sessionShedPerSweep"),
                ))
                .floor();
                if budget.is_nan() || budget < 1.0 {
                    return;
                }
                let per = self.subject_cap();
                if per.is_nan() || per < 1.0 {
                    return;
                }
                let view = self.store.in_realm(&realm_id);
                let mut by_subject: Vec<(String, Vec<(String, Value)>)> =
                    Vec::new();
                for (id, s) in view.entries() {
                    if !Self::counts_toward_subject(&s) {
                        continue;
                    }
                    let subject = js::or_empty(s.get("subjectId"));
                    if subject.is_empty() {
                        continue;
                    }
                    match by_subject.iter_mut().find(|g| g.0 == subject) {
                        Some(g) => g.1.push((id, s)),
                        None => by_subject.push((subject, vec![(id, s)])),
                    }
                }
                let order = |a: &Value, b: &Value| {
                    if Self::earlier(a, b) {
                        std::cmp::Ordering::Less
                    } else if Self::earlier(b, a) {
                        std::cmp::Ordering::Greater
                    } else {
                        std::cmp::Ordering::Equal
                    }
                };
                let mut groups: Vec<Vec<(String, Value)>> = by_subject
                    .into_iter()
                    .filter(|g| g.1.len() as f64 > per)
                    .map(|mut g| {
                        g.1.sort_by(|a, b| order(&a.1, &b.1));
                        g.1
                    })
                    .collect();
                groups.sort_by(|a, b| order(&a[0].1, &b[0].1));
                let mut left = budget;
                for rows in groups {
                    let mut held = rows.len() as f64;
                    for (id, _) in &rows {
                        if !(left > 0.0 && held > per) {
                            break;
                        }
                        let Some(live) = view.get(id) else {
                            held -= 1.0;
                            continue;
                        };
                        self.expire_session(
                            id,
                            &live,
                            "the session sweep",
                            "capacity",
                        );
                        shed += 1;
                        held -= 1.0;
                        left -= 1.0;
                    }
                }
            });
        }
        if shed > 0 {
            self.note_capacity_end(shed);
        }
        shed
    }
}
