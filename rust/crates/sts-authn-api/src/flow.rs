// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE SIGN-IN SCREEN'S VIEWS AND ACTS: what `authn/authn.ts` answers
//! `/authn-api` with (`screenView()`, `screenAct()`,
//! `finishPasswordSignIn()`, `mfaView()`, `mfaTotpAct()`,
//! `mfaBackupCodeAct()`, `mfaPasswordAct()`, `mfaStartOver()`, the forced
//! password change), over the session core and the credentials.
//!
//! **THE LOGIC IS NODE'S, BRANCH FOR BRANCH**, and each function names the
//! one it ports. A credential is EVIDENCE on an authentication event and the
//! session is THE identity (`authn/CLAUDE.md`): every act that finishes a
//! sign-in ends in [`Sessions::start_session`] with the evidence the door
//! verified (`sts_credentials::evidence::Evidence`), and the answer that
//! carries the `sts_session` cookie is the one naming where to go next.
//!
//! **WHAT IS ANSWERED HERE AND WHAT IS NOT YET** (the report says why):
//! the screen, Cancel, Continue without signing in, the password, the
//! second-factor step a password leads to (its view and the code, recovery
//! code and password-factor acts), Start over, and the forced password
//! change. A sign-in that the act would send to a step whose page is not
//! yet ported here — a passkey ceremony, the set-up step, an emailed code
//! — is still sent there exactly as Node sends it (the step minted, the
//! answer naming it); the step's own operations answer
//! [`Outcome::Unported`] until their slice lands.

use std::sync::Arc;

use serde_json::{json, Map, Value as Json};
use sts_authn::ports::{Request, Response};
use sts_authn::Sessions;
use sts_core::errors::{codes, ErrorCode};
use sts_credentials::credentials::{Credentials, VerifyOptions};
use sts_credentials::evidence::Evidence;
use sts_credentials::limits::{Limit, RateLimiter};
use sts_credentials::Verdict;

use crate::pending::PendingStores;
use crate::ports::SignInFacts;

/// The screen.
pub const LOGIN_PATH: &str = "/authn/login";
/// The one-time code's page.
pub const TOTP_PATH: &str = "/authn/totp";
/// The passkey's page.
pub const WEBAUTHN_PATH: &str = "/authn/webauthn";
/// The set-up step's page.
pub const MFA_SETUP_PATH: &str = "/authn/mfa-setup";
/// The forced password change's page.
pub const PASSWORD_CHANGE_PATH: &str = "/authn/password-change";
/// The emailed code's page.
pub const EMAIL_CODE_PATH: &str = "/authn/email-code";
/// The emailed link's page.
pub const EMAIL_LINK_PATH: &str = "/authn/email-link";
/// The stable name an unauthenticated session is given (`ANONYMOUS_USERNAME`).
pub const ANONYMOUS_USERNAME: &str = "anonymous";

const AUTHN_TTL_MS: f64 = 10.0 * 60.0 * 1000.0;
const MFA_TTL_MS: f64 = 5.0 * 60.0 * 1000.0;
const RESERVED_REFUSAL: &str = "invalid";

/// The request as the screen's logic reads it.
#[derive(Debug, Clone, Default)]
pub struct Call {
    /// What the session core reads: the cookie, the agent, the address.
    pub request: Request,
    /// `baseUrlOf(req)`: the realm's base.
    pub base: String,
    /// `realms.currentPrefix()`.
    pub prefix: String,
}

/// An answer: the status, the JSON, the cookies set on it, and the code
/// recorded (never sent).
#[derive(Debug, Clone, PartialEq)]
pub struct Answer {
    pub status: u16,
    pub body: Json,
    pub cookies: Vec<String>,
    pub headers: Vec<(String, String)>,
    pub code: Option<ErrorCode>,
}

impl Answer {
    /// `answerJson(res, status, body)`.
    #[tracing::instrument(level = "trace", skip(body))]
    pub fn json(status: u16, body: Json) -> Answer {
        Answer {
            status,
            body,
            cookies: Vec::new(),
            headers: Vec::new(),
            code: None,
        }
    }

    /// `errorCodes.mark(res, code)`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn marked(mut self, code: ErrorCode) -> Answer {
        self.code = Some(code);
        self
    }
}

/// What a door answered: an answer, or that its logic is not ported here.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Answered(Answer),
    Unported(&'static str),
}

/// The screen's fields, as `AuthnApi.act()` hands them to `screenAct()`.
#[derive(Debug, Clone, Default)]
pub struct Fields {
    pub action: String,
    pub username: String,
    pub password: String,
    pub use_webauthn: String,
    pub webauthn_only: String,
    pub remember_browser: String,
    pub device_fp: String,
}

fn text(v: Option<&Json>) -> String {
    match v {
        None | Some(Json::Null) => String::new(),
        Some(Json::String(s)) => s.clone(),
        Some(Json::Bool(b)) => b.to_string(),
        Some(Json::Number(n)) => n.to_string(),
        Some(other) => other.to_string(),
    }
}

fn truthy(v: Option<&Json>) -> bool {
    match v {
        None | Some(Json::Null) => false,
        Some(Json::Bool(b)) => *b,
        Some(Json::String(s)) => !s.is_empty(),
        Some(Json::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(_) => true,
    }
}

fn number(v: Option<&Json>) -> f64 {
    match v {
        Some(Json::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
        Some(Json::String(s)) => s.trim().parse().unwrap_or(f64::NAN),
        _ => f64::NAN,
    }
}

fn num(n: f64) -> Json {
    if n.fract() == 0.0 && n.abs() < 9.0e15 {
        json!(n as i64)
    } else {
        json!(n)
    }
}

/// `encodeURIComponent()`.
fn encode_component(s: &str) -> String {
    sts_credentials::totp::encode_uri_component(s)
}

/// The sign-in surface's logic.
pub struct SignIn {
    pub stores: PendingStores,
    pub sessions: Arc<Sessions>,
    pub credentials: Arc<Credentials>,
    pub limits: Arc<RateLimiter>,
    pub facts: Arc<dyn SignInFacts>,
}

impl SignIn {
    // -------------------------------------------------------------------
    // The clocks.
    // -------------------------------------------------------------------

    /// `secondsSetting(key, fallbackMs)`.
    fn seconds_setting(&self, key: &str, fallback: f64) -> f64 {
        let n = number(Some(&self.facts.setting(key)));
        if n.is_finite() && n > 0.0 {
            n.floor() * 1000.0
        } else {
            fallback
        }
    }

    /// `pendingTtlMs()`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn pending_ttl_ms(&self) -> f64 {
        self.seconds_setting("authn.pendingTtlS", AUTHN_TTL_MS)
    }

    /// `mfaStepTtlMs()`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn mfa_step_ttl_ms(&self) -> f64 {
        self.seconds_setting("authn.mfaStepTtlS", MFA_TTL_MS)
    }

    fn now(&self) -> f64 {
        self.facts.now_ms()
    }

    // -------------------------------------------------------------------
    // The registers.
    // -------------------------------------------------------------------

    /// `pendingFor(id)`: a sign-in anybody holding the id may continue —
    /// not expired (an expired one is dropped on the way past), not a
    /// restart-only record (#98 D9) and not a picker-only one (#561).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn pending_for(&self, id: &str) -> Option<Json> {
        let record = self.stores.pending.get(id)?;
        if number(record.get("expires")) < self.now() {
            self.stores.pending.delete(&text(record.get("id")));
            return None;
        }
        if truthy(record.get("restartOnly"))
            || truthy(record.get("accountsOnly"))
        {
            return None;
        }
        Some(record)
    }

    /// `mfaStepFor(id, accepts)`: a live step; a post-login step only to
    /// its own page, the passkey page once Register made it that ceremony,
    /// and the acts that end any step (`any`).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn mfa_step_for(&self, id: &str, accepts: &str) -> Option<Json> {
        let step = self.stores.mfa.get(id)?;
        if number(step.get("expires")) < self.now() {
            self.stores.mfa.delete(id);
            return None;
        }
        if truthy(step.get("postLogin"))
            && accepts != "any"
            && accepts != "post-login"
            && !(accepts == "webauthn"
                && text(step.get("factor")) == "webauthn")
        {
            return None;
        }
        Some(step)
    }

    /// `claimStepForBrowser(id, sessionId, kind)` (#1454): a step belongs
    /// to the first browser that asks about it.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn claim_step_for_browser(
        &self,
        id: &str,
        sid: &str,
        kind: &str,
    ) -> bool {
        let store = match kind {
            "pending" => &self.stores.pending,
            "password-change" => &self.stores.password_change,
            _ => &self.stores.mfa,
        };
        let Some(mut step) = store.get(id) else {
            return true;
        };
        if sid.is_empty() {
            return !truthy(step.get("browserSession"));
        }
        if !truthy(step.get("browserSession")) {
            step["browserSession"] = json!(sid);
            store.set(id, step.clone());
        }
        text(step.get("browserSession")) == sid
    }

    /// `firstAmrOf(step)`.
    fn first_amr_of(step: &Json) -> Vec<String> {
        sts_credentials::evidence::first_amr_of(step)
    }

    // -------------------------------------------------------------------
    // The answers.
    // -------------------------------------------------------------------

    /// `locationOf(res, target)`: the address `res.location()` would have
    /// sent — the realm's prefix put on a root-relative target
    /// (`realms.href()`), then Express's `encodeurl`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn location_of(&self, call: &Call, target: &str) -> String {
        let prefix = &call.prefix;
        let prefixed = if prefix.is_empty()
            || !target.starts_with('/')
            || target == prefix
            || target.starts_with(&format!("{}/", prefix))
        {
            target.to_string()
        } else {
            format!("{}{}", prefix, target)
        };
        sts_http::encode_url(&prefixed)
    }

    /// `stepAnswer(res, next, step, id, path, query)`, to the API.
    fn step_answer(
        &self,
        call: &Call,
        next: &str,
        step: &str,
        id: &str,
        path: &str,
        query: &str,
    ) -> Answer {
        let location = format!(
            "{}{}?{}={}",
            call.prefix,
            path,
            query,
            encode_component(id)
        );
        Answer::json(
            200,
            json!({ "ok": true, "next": next, "step": step, "id": id,
                    "location": self.location_of(call, &location) }),
        )
    }

    /// `stepRefused(res, why, status)`.
    fn step_refused(why: &str, status: u16) -> Answer {
        Answer::json(
            status,
            json!({ "ok": false, "next": "refused", "errors": [why] }),
        )
    }

    /// `screenRefused(res, record, message, extra)`, to the API: the
    /// record put back while it has time left (the sentence on it only
    /// where the refusal came from a step, whose page goes to the screen),
    /// and the sentence answered.
    fn screen_refused(
        &self,
        call: &Call,
        record: &mut Json,
        message: &str,
        status: u16,
        from_step: bool,
        post_quantum_required: bool,
    ) -> Answer {
        let id = text(record.get("id"));
        let live =
            !id.is_empty() && !(number(record.get("expires")) < self.now());
        if live {
            record["screenError"] = json!(if from_step {
                message.to_string()
            } else {
                String::new()
            });
            record["postQuantumRequired"] = json!(post_quantum_required);
            self.stores.pending.set(&id, record.clone());
        }
        let mut body = json!({ "ok": false, "next": "refused",
                               "errors": [if message.is_empty() { "Refused." }
                                          else { message }] });
        if from_step && live {
            body["location"] = json!(self.location_of(
                call,
                &format!(
                    "{}{}?authn={}",
                    call.prefix,
                    LOGIN_PATH,
                    encode_component(&id)
                ),
            ));
        }
        Answer::json(status, body)
    }

    /// `noteRefusedAuthentication(pendingRecord, username, method, code,
    /// note)` (#954).
    fn note_refused(
        &self,
        pending: &Json,
        username: &str,
        method: &str,
        code: ErrorCode,
        note: &str,
    ) {
        let authn = pending
            .get("authn")
            .filter(|a| a.is_object())
            .unwrap_or(pending);
        self.facts.note_refused(&json!({
            "presented": username,
            "protocol": text(authn.get("protocol")),
            "method": method,
            "application": text(authn.get("application")),
            "errorCode": code.as_str(),
            "note": note,
            "channel": "http" }));
    }

    /// `returnToCaller(res, record, error, description)`: the 303 a form
    /// got, as the answer naming where to go. The attribute sources a
    /// sign-in reads (#94) and the account set's ticket (#561) are not in
    /// this runtime yet: with none configured and the setting off, Node
    /// goes straight on, as this does.
    fn return_to_caller(
        &self,
        call: &Call,
        record: &Json,
        error: Option<(&str, &str)>,
        started: Option<&Response>,
    ) -> Answer {
        let mut target = text(record.get("returnTo"));
        // THE FLOW RESUMES AS THE SESSION THIS SIGN-IN STARTED (#561): a
        // selection ticket, where the session joined an account set.
        if let (None, Some(response)) = (error, started) {
            target = self.sessions.ticketed_return(
                response,
                &text(record.get("id")),
                &target,
            );
        }
        if let Some((error, description)) = error {
            target.push(if target.contains('?') { '&' } else { '?' });
            target.push_str(&format!(
                "authn_error={}&authn_error_description={}",
                encode_component(error),
                encode_component(description)
            ));
        }
        Answer::json(
            200,
            json!({ "ok": true, "next": "redirect",
                    "location": self.location_of(call, &target) }),
        )
    }

    // -------------------------------------------------------------------
    // The screen's view.
    // -------------------------------------------------------------------

    /// `screenProblem(record)`: the configuration's problems the screen
    /// shows, each once.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn screen_problem(record: &Json) -> String {
        let mut seen: Vec<String> = Vec::new();
        let mut all = vec![record.get("mechanismProblem").cloned()];
        if let Some(problems) = record
            .get("federation")
            .and_then(|f| f.get("problems"))
            .and_then(Json::as_array)
        {
            all.extend(problems.iter().cloned().map(Some));
        }
        for one in all.into_iter().flatten() {
            let t = text(Some(&one));
            if truthy(Some(&one)) && !seen.contains(&t) {
                seen.push(t);
            }
        }
        seen.join(" ")
    }

    fn offers(restricted: &[String], id: &str) -> bool {
        restricted.is_empty() || restricted.iter().any(|r| r == id)
    }

    /// `screenView(req, record, problem)`: every decision the screen's
    /// markup was drawn under, as facts. The federation partners, the
    /// Kerberos door, the wallet, a passkey with no username, the
    /// certificate on the connection and the post-quantum panel are the
    /// slices' that port those doors; until then each is answered as Node
    /// answers it with that door not configured (null, or `false`).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn screen_view(
        &self,
        call: &Call,
        record: &Json,
        problem: &str,
    ) -> Json {
        let key_policy = self.facts.key_policy();
        let locked = text(record.get("lockedUsername"));
        let restricted: Vec<String> = record
            .get("allowedMechanisms")
            .and_then(Json::as_array)
            .map(|l| l.iter().map(|v| text(Some(v))).collect())
            .unwrap_or_default();
        let screen_offered = SignIn::offers(&restricted, "password")
            || SignIn::offers(&restricted, "password-mfa")
            || SignIn::offers(&restricted, "webauthn");
        let password_first = self.facts.authn_allows("password", "primary")
            && (SignIn::offers(&restricted, "password")
                || SignIn::offers(&restricted, "password-mfa"));
        let email = if !locked.is_empty()
            || truthy(record.get("forceKey"))
            || truthy(record.get("forcePasswordless"))
            || !restricted.is_empty()
        {
            json!({ "code": false, "link": false })
        } else {
            json!({ "code": self.facts.authn_active("emailCode", "primary"),
                    "link": self.facts.authn_active("emailLink", "primary") })
        };
        let error = [problem.to_string(), text(record.get("screenError"))]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        let details: Vec<Json> = record
            .get("details")
            .and_then(Json::as_array)
            .map(|l| {
                l.iter()
                    .map(|d| {
                        let note = d.get("note");
                        json!({ "label": text(d.get("label")),
                                "value": match d.get("value") {
                                    None | Some(Json::Null) => String::new(),
                                    v => text(v) },
                                "note": if truthy(note) { text(note) }
                                        else { String::new() } })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let remember = self.facts.remembers_browsers() && locked.is_empty();
        let anonymous =
            truthy(Some(&self.facts.setting("authn.unauthenticatedSessions")))
                && locked.is_empty()
                && restricted.is_empty();
        let partners_offered =
            locked.is_empty() && SignIn::offers(&restricted, "federation");
        let kerberos_offered =
            locked.is_empty() && SignIn::offers(&restricted, "spnego");
        let wallet_offered =
            locked.is_empty() && SignIn::offers(&restricted, "wallet");
        json!({
            "id": text(record.get("id")),
            "base": call.base,
            "protocol": text(record.get("protocol")),
            "application": text(record.get("application")),
            "error": error,
            "locked": locked,
            "hint": text(record.get("hint")),
            "screen": screen_offered,
            "password": password_first,
            "keys": { "enabled": truthy(key_policy.get("enabled")),
                      "mfaAllowed": truthy(key_policy.get("mfaAllowed")),
                      "primaryAllowed": truthy(key_policy.get("primaryAllowed")) },
            "demands": { "mfa": truthy(record.get("forceMfa")),
                         "key": truthy(record.get("forceKey")),
                         "passwordless": truthy(record.get("forcePasswordless")),
                         "via": text(record.get("mechanismVia")) },
            "remember": remember,
            "anonymous": anonymous,
            "passkey": false,
            "usernameless": false,
            "email": email,
            "clientDisplay": self.facts.client_display(&text(record.get("application"))),
            "reauthentication": text(record.get("reauthentication")),
            "certificate": Json::Null,
            "postQuantumRequired": Json::Null,
            "forgot": if locked.is_empty() && self.facts.offers_password_reset() {
                "/portal/forgot-password" } else { "" },
            "partners": if partners_offered {
                record.get("federation").and_then(|f| f.get("partners")).cloned()
                    .filter(|p| p.as_array().is_some_and(|a| !a.is_empty()))
                    .map(|_| Json::Null).unwrap_or(Json::Null)
            } else { Json::Null },
            "kerberos": if kerberos_offered { Json::Null } else { Json::Null },
            "wallet": if wallet_offered { Json::Null } else { Json::Null },
            "verifiesCredentials": self.facts.predicate("verifiesCredentials"),
            "fingerprint": self.facts.fingerprinting(),
            "details": details,
        })
    }

    // -------------------------------------------------------------------
    // The credential facts a step is decided from.
    // -------------------------------------------------------------------

    /// `mechanismsFor(username)`'s members the screen reads: the keys and
    /// their uses (`keyUses()`), the authenticator app and its detail, the
    /// recovery codes, `mfaRequired` and `secondFactor`. The emailed
    /// factor (#64) is held by nobody until its slice lands — it is off
    /// unless the authentication policy allows it.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn mechanisms_for(&self, username: &str) -> Json {
        let name = username.trim();
        let keys = self.credentials.keys_of(name);
        let held = keys.len();
        let primary =
            if held > 0 && self.facts.key_use_allowed("primary").is_ok() {
                held
            } else {
                0
            };
        let mfa = if held > 0 && self.facts.key_use_allowed("mfa").is_ok() {
            held
        } else {
            0
        };
        let totp = self.credentials.totp_of(name);
        let detail = totp.as_ref().map(|t| {
            json!({ "enrolledAt": t.get("enrolledAt").cloned().unwrap_or(json!(0)),
                    "digits": t.get("digits").cloned().unwrap_or(json!(0)),
                    "period": t.get("period").cloned().unwrap_or(json!(0)),
                    "unusable": truthy(t.get("unusable")) })
        });
        let backup = self.credentials.backup_code_status(name);
        json!({
            "username": name,
            "primaryKeys": held_count(primary),
            "mfaKeys": held_count(mfa),
            "totp": totp.is_some(),
            "totpDetail": detail.unwrap_or(Json::Null),
            "backupCodes": backup,
            "mfaRequired": mfa > 0 || totp.is_some(),
            "secondFactor": if mfa > 0 { "webauthn" }
                            else if totp.is_some() { "totp" } else { "" },
            "mailFactor": { "held": "" },
        })
    }

    // -------------------------------------------------------------------
    // The screen's acts.
    // -------------------------------------------------------------------

    /// `screenAct(req, res, record, body)`.
    #[tracing::instrument(level = "debug", skip_all, fields(action = %fields.action))]
    pub async fn screen_act(
        &self,
        call: &Call,
        mut record: Json,
        fields: &Fields,
    ) -> Outcome {
        let id = text(record.get("id"));
        if let Some(r) = record.as_object_mut() {
            r.remove("screenError");
            r.remove("postQuantumRequired");
        }
        let action = fields.action.as_str();
        if action == "cancel" {
            self.stores.pending.delete(&id);
            return Outcome::Answered(
                self.return_to_caller(
                    call,
                    &record,
                    Some((
                        "access_denied",
                        "The user cancelled at the sign-in screen.",
                    )),
                    None,
                )
                .marked(codes::STS_AUTHN_0004),
            );
        }
        let locked = text(record.get("lockedUsername"));
        if action == "anonymous"
            && locked.is_empty()
            && truthy(Some(
                &self.facts.setting("authn.unauthenticatedSessions"),
            ))
        {
            let application = text(record.get("application"));
            let gate = self.facts.gate_session(
                &application,
                ANONYMOUS_USERNAME,
                false,
            );
            if gate.get("allowed") != Some(&Json::Bool(true)) {
                tracing::info!(
                    "authn: the issuance policy refused an unauthenticated \
                     session at \"{}\". {}",
                    application,
                    text(gate.get("why"))
                );
                return Outcome::Answered(
                    self.screen_refused(
                        call,
                        &mut record,
                        &text(gate.get("why")),
                        400,
                        false,
                        false,
                    )
                    .marked(codes::STS_AUTHN_0005),
                );
            }
            self.stores.pending.delete(&id);
            let mut said = Map::new();
            said.insert("authenticated".into(), json!(false));
            said.insert("gated".into(), json!(true));
            said.insert("application".into(), json!(application));
            let mut response = Response::default();
            let started = self.sessions.start_session(
                &mut response,
                ANONYMOUS_USERNAME,
                &[],
                "0",
                &text(record.get("protocol")),
                &mut said,
                Some(&call.request),
            );
            return Outcome::Answered(self.after_session(
                call,
                &mut record,
                ANONYMOUS_USERNAME,
                started,
                &said,
                response,
                false,
            ));
        }
        record["rememberBrowser"] = json!(fields.remember_browser == "1");
        match action {
            "certificate" => {
                return Outcome::Unported("continueWithCertificate")
            }
            "passkey" => return Outcome::Unported("signInWithPasskey"),
            "email-code" | "email-link" => {
                return Outcome::Unported("signInByEmail")
            }
            _ => {}
        }
        let username = if locked.is_empty() {
            fields.username.trim().to_string()
        } else {
            locked.clone()
        };
        if username.is_empty() {
            return Outcome::Answered(
                self.screen_refused(
                    call,
                    &mut record,
                    "Enter a username. It does not have to exist — it is the \
                     identity the issued tokens will describe.",
                    400,
                    false,
                    false,
                )
                .marked(codes::STS_AUTHN_0006),
            );
        }
        if locked.is_empty() && is_lane_name(&username) {
            tracing::info!(
                "authn: a sign-in naming \"{}\" was refused: that is a \
                 passkey's name in a credential manager, not a username.",
                username
            );
            return Outcome::Answered(
                self.screen_refused(
                    call,
                    &mut record,
                    "That is the name your password manager shows for a \
                     post-quantum passkey, not a username. Type your \
                     username without the part after the \"+\".",
                    400,
                    false,
                    false,
                )
                .marked(codes::STS_AUTHN_0354),
            );
        }
        let passwordless = truthy(record.get("forcePasswordless"))
            || fields.webauthn_only == "1";
        let second_factor = !passwordless
            && (truthy(record.get("forceMfa"))
                || truthy(record.get("forceKey"))
                || fields.use_webauthn == "1");
        if passwordless && !locked.is_empty() {
            return Outcome::Answered(
                self.screen_refused(
                    call,
                    &mut record,
                    "Linking an account signs in with its password — and its \
                     second factor, where it has one — so a security key on \
                     its own is not offered here.",
                    400,
                    false,
                    false,
                )
                .marked(codes::STS_AUTHN_0212),
            );
        }
        if passwordless || second_factor {
            if let Err((why, code)) = self
                .facts
                .key_use_allowed(if passwordless { "primary" } else { "mfa" })
            {
                tracing::info!(
                    "authn: a security-key sign-in was asked for as a {} \
                     credential and this realm does not allow it. {}",
                    if passwordless {
                        "primary"
                    } else {
                        "second-factor"
                    },
                    why
                );
                return Outcome::Answered(
                    self.screen_refused(
                        call,
                        &mut record,
                        &why,
                        400,
                        false,
                        false,
                    )
                    .marked(code),
                );
            }
        }
        if passwordless && truthy(record.get("forceMfa")) {
            return Outcome::Answered(
                self.screen_refused(
                    call,
                    &mut record,
                    "This request asked for a second factor, so a passkey on \
                     its own cannot answer it — one factor is one factor. \
                     Sign in with a password and the passkey together.",
                    400,
                    false,
                    false,
                )
                .marked(codes::STS_AUTHN_0007),
            );
        }
        if passwordless
            && !self.facts.predicate("enrolsKeysOnFirstUse")
            && number(self.mechanisms_for(&username).get("primaryKeys")) < 1.0
        {
            tracing::info!(
                "authn: product mode, so a passwordless sign-in for \"{}\", \
                 who holds no passkey, was refused rather than enrolling one \
                 at the sign-in screen.",
                username
            );
            return Outcome::Answered(
                self.screen_refused(
                    call,
                    &mut record,
                    "There is no passkey registered for signing in to this \
                     account. Sign in with your password, then add a passkey \
                     at /portal/keys.",
                    400,
                    false,
                    false,
                )
                .marked(codes::STS_AUTHN_0206),
            );
        }
        if !passwordless && !self.facts.authn_allows("password", "primary") {
            tracing::info!(
                "authn: a password sign-in for \"{}\" was refused: this \
                 realm's authentication policy does not accept a password as \
                 a first factor.",
                username
            );
            self.note_refused(
                &record,
                &username,
                "password",
                codes::STS_AUTHN_0255,
                "password-not-a-first-factor",
            );
            return Outcome::Answered(
                self.screen_refused(
                    call,
                    &mut record,
                    "This realm does not accept a password as a first factor. \
                     Use one of the other ways of signing in below.",
                    400,
                    false,
                    false,
                )
                .marked(codes::STS_AUTHN_0255),
            );
        }
        let mut breached_at_sign_in = false;
        if !passwordless {
            let allowed = self.limits.attempt(
                "sign-in",
                &call.request.address,
                &username,
                &Limit::from_json(&Json::Null),
            );
            if !allowed.ok() {
                let kind = text(allowed.value.get("kind"));
                tracing::warn!(
                    "authn: too many sign-in attempts for \"{}\" ({} \
                     bucket). Refusing for {}s.",
                    username,
                    kind,
                    text(allowed.value.get("retryAfterS"))
                );
                self.note_refused(
                    &record,
                    &username,
                    "password",
                    codes::STS_AUTHN_0008,
                    if kind.is_empty() { "rate-limit" } else { &kind },
                );
                return Outcome::Answered(
                    self.screen_refused(
                        call,
                        &mut record,
                        &text(allowed.value.get("detail")),
                        429,
                        false,
                        false,
                    )
                    .marked(codes::STS_AUTHN_0008),
                );
            }
            let delay = self.limits.wait_after_failures_ms(&username);
            if delay > 0.0 {
                tokio::time::sleep(std::time::Duration::from_millis(
                    delay as u64,
                ))
                .await;
            }
            let opts = VerifyOptions::from_json(&json!({
                "via": "the sign-in screen", "allowPasswordReset": true,
                "secondFactor": "asked-next" }));
            let credential =
                self.credentials.verify(&username, &fields.password, &opts);
            if !credential.ok() {
                self.limits.note_failure(&username);
                tracing::info!(
                    "authn: the sign-in for \"{}\" was refused ({}): {}",
                    username,
                    credential.reason(),
                    text(credential.value.get("detail"))
                );
                let code = credential.code.unwrap_or(codes::STS_AUTHN_0054);
                let reason = credential.reason();
                self.note_refused(
                    &record,
                    &username,
                    "password",
                    code,
                    if reason.is_empty() { "refused" } else { reason },
                );
                return Outcome::Answered(
                    self.screen_refused(
                        call,
                        &mut record,
                        &format!("Authentication failed for {}.", username),
                        400,
                        false,
                        false,
                    )
                    .marked(code),
                );
            }
            self.limits.succeeded(
                "sign-in",
                &call.request.address,
                &username,
                false,
            );
            self.limits.forget_failures(&username);
            if self.facts.setting("risk.breachCheckAtSignIn")
                != Json::Bool(false)
                && self.facts.breached(&fields.password)
            {
                breached_at_sign_in = true;
                tracing::info!(
                    "authn: the password \"{}\" signed in with has appeared \
                     in a data breach; it must be changed before the sign-in \
                     finishes.",
                    username
                );
            }
        }
        if !passwordless
            && (breached_at_sign_in
                || self.credentials.password_reset_required(&username))
        {
            self.stores.pending.delete(&id);
            let change_id = self.facts.random_id(24);
            self.stores.password_change.set(
                &change_id,
                json!({ "authn": record, "username": username,
                        "secondFactor": second_factor,
                        "notice": if breached_at_sign_in {
                            "The password you signed in with has appeared in \
                             a data breach, so it has to be changed now. \
                             Choose one you have not used anywhere else." }
                            else { "" },
                        "expires": num(self.now() + self.mfa_step_ttl_ms()) }),
            );
            let now = self.now();
            for (k, v) in self.stores.password_change.entries() {
                if number(v.get("expires")) < now {
                    self.stores.password_change.delete(&k);
                }
            }
            tracing::info!(
                "authn: \"{}\" must change their password before this sign-in \
                 continues (pwdReset).",
                username
            );
            return Outcome::Answered(self.step_answer(
                call,
                "password-change",
                "password-change",
                &change_id,
                PASSWORD_CHANGE_PATH,
                "change",
            ));
        }
        Outcome::Answered(self.finish_password_sign_in(
            call,
            record,
            &username,
            passwordless,
            second_factor,
        ))
    }

    /// `finishPasswordSignIn(req, res, base, record, username,
    /// passwordless, secondFactor)`: a first factor verified, so a session
    /// — or the second factor the person holds, or the set-up step a
    /// requirement asks for. The risk engine (#62) and the remembered
    /// browser (#265) are not in this runtime yet; with no assessment and
    /// no remembered browser Node takes the branches taken here.
    #[tracing::instrument(level = "debug", skip_all, fields(username))]
    pub fn finish_password_sign_in(
        &self,
        call: &Call,
        mut record: Json,
        username: &str,
        passwordless: bool,
        second_factor: bool,
    ) -> Answer {
        let id = text(record.get("id"));
        let application = text(record.get("application"));
        if self.credentials.account_disabled(username) {
            tracing::info!(
                "authn: a sign-in for \"{}\" was refused: the account is \
                 disabled.",
                username
            );
            return self
                .screen_refused(
                    call,
                    &mut record,
                    &format!("Authentication failed for {}.", username),
                    400,
                    false,
                    false,
                )
                .marked(codes::STS_AUTHN_0201);
        }
        let gate = self.facts.gate_session(&application, username, true);
        if gate.get("allowed") != Some(&Json::Bool(true)) {
            tracing::info!(
                "authn: the issuance policy refused a session for \"{}\" at \
                 \"{}\". {}",
                username,
                application,
                text(gate.get("why"))
            );
            let code = if truthy(gate.get("retiring")) {
                codes::STS_CORE_0121
            } else {
                codes::STS_AUTHN_0009
            };
            return self
                .screen_refused(
                    call,
                    &mut record,
                    &text(gate.get("why")),
                    400,
                    false,
                    false,
                )
                .marked(code);
        }
        let enrolled = self.mechanisms_for(username);
        let configured = if truthy(enrolled.get("mfaRequired")) {
            text(enrolled.get("secondFactor"))
        } else {
            String::new()
        };
        let mfa_keys = number(enrolled.get("mfaKeys"));
        let force_key = truthy(record.get("forceKey"));
        if force_key
            && !passwordless
            && mfa_keys == 0.0
            && truthy(enrolled.get("mfaRequired"))
        {
            return self
                .screen_refused(
                    call,
                    &mut record,
                    "This request needs a passkey, and this account holds \
                     none. Add one at /portal/keys and sign in again.",
                    400,
                    false,
                    false,
                )
                .marked(codes::STS_AUTHN_0204);
        }
        let factor = if passwordless || force_key {
            "webauthn".to_string()
        } else if !configured.is_empty() {
            configured.clone()
        } else if second_factor {
            "webauthn".to_string()
        } else {
            String::new()
        };
        let mfa_allowed = self.facts.mfa_allowed_for(&application, username);
        let requirement = self.credentials.mfa_requirement_for(username);
        if truthy(requirement.get("required")) && passwordless {
            let by_user = truthy(requirement.get("byUser"));
            return self
                .screen_refused(
                    call,
                    &mut record,
                    &format!(
                        "A second factor is required {}, and a security key \
                         on its own is one factor. Sign in with your \
                         password; you will be asked for your second factor, \
                         or to set one up.",
                        if by_user {
                            "for this account"
                        } else {
                            "in this realm"
                        }
                    ),
                    400,
                    false,
                    false,
                )
                .marked(codes::STS_AUTHN_0171);
        }
        if truthy(requirement.get("required")) && factor.is_empty() {
            let offered = self.enrolment_offered_for(&mfa_allowed);
            if !offered.0 && !offered.1 && !mfa_allowed.is_empty() {
                tracing::info!(
                    "{}authn: a second factor is required of \"{}\", who \
                     holds none, and none of the ones \"{}\" allows ({}) can \
                     be set up at sign-in; refused.",
                    sts_core::log::tag(codes::STS_AUTHN_0306),
                    username,
                    application,
                    mfa_allowed.join(", ")
                );
                return self
                    .screen_refused(
                        call,
                        &mut record,
                        "A second factor is required, and none that this \
                         application accepts can be set up here. Ask an \
                         administrator.",
                        400,
                        false,
                        false,
                    )
                    .marked(codes::STS_AUTHN_0306);
            }
            if !offered.0 && !offered.1 {
                tracing::warn!(
                    "{}authn: a second factor is required of \"{}\", who \
                     holds none, and neither mechanism can be enrolled in \
                     this realm (the authentication policy on Directory > \
                     Policies, webauthn.enabled, webauthn.mfaAllowed). The \
                     sign-in is REFUSED rather than let through on one \
                     factor.",
                    sts_core::log::tag(codes::STS_AUTHN_0172),
                    username
                );
                return self
                    .screen_refused(
                        call,
                        &mut record,
                        "A second factor is required for this account and \
                         none can be set up here: authenticator apps and \
                         security keys are both switched off in this realm. \
                         Ask an administrator.",
                        400,
                        false,
                        false,
                    )
                    .marked(codes::STS_AUTHN_0172);
            }
            self.stores.pending.delete(&id);
            let setup_id = self.facts.random_id(24);
            let required_by = if truthy(requirement.get("byUser")) {
                "account"
            } else if truthy(requirement.get("byRealm")) {
                "realm"
            } else {
                "administrator"
            };
            self.stores.mfa.set(
                &setup_id,
                json!({ "authn": record, "username": username,
                        "challenge": self.facts.random_id(32),
                        "factor": "enrol", "alternate": "", "backup": false,
                        "passwordless": false, "requiredBy": required_by,
                        "mfaAllowed": mfa_allowed,
                        "expires": num(self.now() + self.mfa_step_ttl_ms()) }),
            );
            self.facts.audit(&json!({
                "action": "authn.mfa.enrolment.required", "outcome": "success",
                "actor": username, "target": username, "channel": "http",
                "protocol": record.get("protocol").cloned().unwrap_or(Json::Null),
                "summary": format!("{} holds no second factor and one is \
                    required; asked to set one up before signing in", username),
                "detail": { "requiredBy": required_by } }));
            tracing::info!(
                "authn: \"{}\" holds no second factor and one is required; \
                 asking them to set one up.",
                username
            );
            return self.step_answer(
                call,
                "mfa",
                "enrol",
                &setup_id,
                MFA_SETUP_PATH,
                "mfa",
            );
        }
        if truthy(requirement.get("offered"))
            && factor.is_empty()
            && !passwordless
        {
            let offered = self.enrolment_offered_for(&mfa_allowed);
            if offered.0 || offered.1 {
                self.stores.pending.delete(&id);
                let offer_id = self.facts.random_id(24);
                self.stores.mfa.set(
                    &offer_id,
                    json!({ "authn": record, "username": username,
                            "challenge": self.facts.random_id(32),
                            "factor": "enrol", "alternate": "", "backup": false,
                            "passwordless": false,
                            "requiredBy": "administrator", "optional": true,
                            "mfaAllowed": mfa_allowed,
                            "riskDecision": "permit",
                            "expires": num(self.now() + self.mfa_step_ttl_ms()) }),
                );
                self.facts.audit(&json!({
                    "action": "authn.mfa.enrolment.offered", "outcome": "success",
                    "actor": username, "target": username, "channel": "http",
                    "protocol": record.get("protocol").cloned().unwrap_or(Json::Null),
                    "summary": format!("{} holds an administrator role and \
                        no second factor; offered one before signing in", username),
                    "detail": { "requiredBy": "administrator" } }));
                return self.step_answer(
                    call,
                    "mfa",
                    "enrol",
                    &offer_id,
                    MFA_SETUP_PATH,
                    "mfa",
                );
            }
        }
        if !factor.is_empty() {
            self.stores.pending.delete(&id);
            let mfa_id = self.facts.random_id(24);
            let holds_totp = truthy(enrolled.get("totp"));
            let alternate = if force_key {
                ""
            } else if factor == "webauthn" && holds_totp {
                "totp"
            } else if factor == "totp" && mfa_keys > 0.0 {
                "webauthn"
            } else {
                ""
            };
            let remaining = number(
                enrolled.get("backupCodes").and_then(|b| b.get("remaining")),
            );
            let backup = !force_key && remaining > 0.0;
            let mut step = json!({ "authn": record, "username": username,
                "challenge": self.facts.random_id(32),
                "factor": factor, "alternate": alternate,
                "email": if force_key || factor.starts_with("email-") { "" }
                         else { "" },
                "backup": backup, "passwordless": passwordless,
                "riskKey": false, "mfaAllowed": mfa_allowed,
                "thenEnrol": false,
                "expires": num(self.now() + self.mfa_step_ttl_ms()) });
            self.narrow_step(&mut step);
            if factor == "webauthn" {
                step["atSignIn"] = json!(true);
            }
            self.stores.mfa.set(&mfa_id, step);
            let now = self.now();
            for (k, v) in self.stores.mfa.entries() {
                if number(v.get("expires")) < now {
                    self.stores.mfa.delete(&k);
                }
            }
            if factor == "totp" {
                return self.step_answer(
                    call, "mfa", "totp", &mfa_id, TOTP_PATH, "mfa",
                );
            }
            if factor == "email-code" || factor == "email-link" {
                return self.step_answer(
                    call,
                    "mfa",
                    &factor,
                    &mfa_id,
                    if factor == "email-code" {
                        EMAIL_CODE_PATH
                    } else {
                        EMAIL_LINK_PATH
                    },
                    "mfa",
                );
            }
            return self.step_answer(
                call,
                "mfa",
                "webauthn",
                &mfa_id,
                WEBAUTHN_PATH,
                "mfa",
            );
        }
        self.stores.pending.delete(&id);
        let mut said = Map::new();
        said.insert("postLoginHold".into(), json!(true));
        said.insert("gated".into(), json!(true));
        said.insert("application".into(), json!(application));
        said.insert("riskDecision".into(), json!("permit"));
        let mut response = Response::default();
        let started = Evidence::password().start_session(
            &self.sessions,
            &mut response,
            username,
            &text(record.get("protocol")),
            &mut said,
            Some(&call.request),
        );
        self.after_session(
            call,
            &mut record,
            username,
            started,
            &said,
            response,
            false,
        )
    }

    /// `enrolmentOfferedFor(allowed)`: `(totp, webauthn)`.
    fn enrolment_offered_for(&self, allowed: &[String]) -> (bool, bool) {
        let totp = self.credentials.totp().offered();
        let policy = self.facts.key_policy();
        let webauthn = truthy(policy.get("enabled"))
            && truthy(policy.get("enrolmentAllowed").or(Some(&json!(true))))
            && self.facts.key_use_allowed("mfa").is_ok();
        if allowed.is_empty() {
            return (totp, webauthn);
        }
        (
            totp && allowed.iter().any(|a| a == "totp"),
            webauthn && allowed.iter().any(|a| a == "securityKey"),
        )
    }

    /// `narrowStep(step)`: the alternates an application's second-factor
    /// list (#475) leaves out, taken off the step.
    fn narrow_step(&self, step: &mut Json) {
        let allowed: Vec<String> = step
            .get("mfaAllowed")
            .and_then(Json::as_array)
            .map(|l| l.iter().map(|v| text(Some(v))).collect())
            .unwrap_or_default();
        if allowed.is_empty() || truthy(step.get("thenEnrol")) {
            return;
        }
        let allows = |factor: &str| match factor {
            "webauthn" => allowed.iter().any(|a| a == "securityKey"),
            "backup" => allowed.iter().any(|a| a == "recoveryCode"),
            other => allowed.iter().any(|a| a == other),
        };
        let alternate = text(step.get("alternate"));
        if !alternate.is_empty() && !allows(&alternate) {
            step["alternate"] = json!("");
        }
        if truthy(step.get("backup")) && !allows("backup") {
            step["backup"] = json!(false);
        }
    }

    /// `refusedSession()` and `afterBrowserSignIn()` together: a session
    /// started is answered by `returnToCaller()` with its cookie; a refused
    /// one draws the screen again with the refusal's sentence where it has
    /// one to give.
    #[allow(clippy::too_many_arguments)]
    fn after_session(
        &self,
        call: &Call,
        record: &mut Json,
        username: &str,
        started: Option<Json>,
        said: &Map<String, Json>,
        response: Response,
        from_step: bool,
    ) -> Answer {
        if started.is_some() {
            let mut answer =
                self.return_to_caller(call, record, None, Some(&response));
            answer.cookies = response.cookies;
            return answer;
        }
        let refused =
            said.get("refusedWith").and_then(Json::as_str).unwrap_or("");
        let code = if !refused.is_empty() {
            sts_core::errors::known(refused).unwrap_or(codes::STS_AUTHN_0010)
        } else if self.credentials.account_disabled(username) {
            codes::STS_AUTHN_0201
        } else {
            codes::STS_AUTHN_0010
        };
        let why = text(said.get("refusedWhy"));
        let says = [
            "STS-AUTHN-0010",
            "STS-AUTHN-0298",
            "STS-AUTHN-0305",
            "STS-AUTHN-0313",
            "STS-AUTHN-0315",
            "STS-AUTHN-0356",
            "STS-AUTHN-0380",
            "STS-AUTHN-0381",
            "STS-AUTHN-0473",
        ]
        .contains(&code.as_str())
            && !why.is_empty();
        let message = if says {
            why
        } else {
            format!("Authentication failed for {}.", username)
        };
        tracing::info!(
            "authn: the session for \"{}\" was refused at the end of the \
             sign-in screen ({}); drawing the screen again.",
            username,
            code.as_str()
        );
        let id = text(record.get("id"));
        if !id.is_empty()
            && !self.stores.pending.has(&id)
            && !(number(record.get("expires")) < self.now())
        {
            self.stores.pending.set(&id, record.clone());
        }
        let mut answer = self
            .screen_refused(
                call,
                record,
                &message,
                400,
                from_step,
                code == codes::STS_AUTHN_0356,
            )
            .marked(code);
        answer.cookies = response.cookies;
        answer
    }

    // -------------------------------------------------------------------
    // A second-factor step's view.
    // -------------------------------------------------------------------

    /// `keyDemandProblem(step, what)`.
    fn key_demand_problem(
        step: &Json,
        what: &str,
    ) -> Option<(ErrorCode, String)> {
        let force =
            step.get("authn").is_some_and(|a| truthy(a.get("forceKey")));
        if !force && !truthy(step.get("riskKey")) {
            return None;
        }
        tracing::info!(
            "authn: {} was offered for \"{}\" where the sign-in demands a \
             security key; refused.",
            what,
            text(step.get("username"))
        );
        Some((
            codes::STS_AUTHN_0204,
            format!(
                "This sign-in demands a passkey, and {} does not answer \
                 that. Use your passkey on the previous screen.",
                what
            ),
        ))
    }

    /// `stepProblem(page, mfaId)`: the step a page is drawn for, or the
    /// refusal's code and sentence.
    #[tracing::instrument(level = "debug", skip(self, id))]
    pub fn step_problem(
        &self,
        page: &str,
        id: &str,
    ) -> Result<Json, (ErrorCode, String)> {
        let restart =
            " Start the request again from the application that sent you here.";
        if page == "setup" {
            let setup = self.stores.mfa.get(id);
            let live = setup.as_ref().filter(|s| {
                !(number(s.get("expires")) < self.now())
                    && ["enrol", "enrol-totp"]
                        .contains(&text(s.get("factor")).as_str())
            });
            if let Some(s) = live {
                return Ok(s.clone());
            }
            if setup.is_some_and(|s| number(s.get("expires")) < self.now()) {
                self.stores.mfa.delete(id);
            }
            return Err((
                codes::STS_AUTHN_0173,
                format!("This second-factor set-up has expired or does not exist.{}", restart),
            ));
        }
        let step = self.mfa_step_for(id, page);
        if page == "post-login" {
            return match step {
                Some(s) if text(s.get("factor")) == "post-login" && truthy(s.get("postLogin")) => Ok(s),
                _ => Err((
                    codes::STS_AUTHN_0019,
                    format!("This step after signing in has expired or does not exist.{}", restart),
                )),
            };
        }
        if page == "password" {
            return match step {
                Some(s)
                    if !SignIn::first_amr_of(&s).iter().any(|a| a == "pwd") =>
                {
                    Ok(s)
                }
                _ => Err((
                    codes::STS_AUTHN_0019,
                    format!(
                        "There is no sign-in waiting for a password as its \
                         second factor.{}",
                        restart
                    ),
                )),
            };
        }
        let Some(step) = step else {
            return Err((
                codes::STS_AUTHN_0019,
                format!("This second-factor step has expired.{}", restart),
            ));
        };
        let username = text(step.get("username"));
        match page {
            "totp" => {
                if let Some(p) =
                    SignIn::key_demand_problem(&step, "a one-time code")
                {
                    return Err(p);
                }
                if !truthy(self.mechanisms_for(&username).get("totp")) {
                    tracing::info!(
                        "authn: a one-time code screen was asked for \"{}\", \
                         who has no authenticator enrolled. Refused.",
                        username
                    );
                    return Err((
                        codes::STS_AUTHN_0076,
                        "No authenticator app is enrolled for that account, \
                         so there is no code to ask for."
                            .into(),
                    ));
                }
            }
            "backup-code" => {
                let held = self.credentials.backup_code_status(&username);
                if number(held.get("remaining")) > 0.0 {
                    return Ok(step);
                }
                tracing::info!(
                    "authn: a recovery code screen was asked for \"{}\". \
                     Refused.",
                    username
                );
                return Err(if number(held.get("total")) > 0.0 {
                    (
                        codes::STS_AUTHN_0088,
                        "Every recovery code on that account has been used. \
                         A set is issued once and is never topped up, so an \
                         administrator has to clear it before a new one can \
                         be issued."
                            .into(),
                    )
                } else {
                    (
                        codes::STS_AUTHN_0087,
                        "No recovery codes have been issued for that account, \
                         so there is nothing to ask for."
                            .into(),
                    )
                });
            }
            _ => {}
        }
        Ok(step)
    }

    /// `stepLinks(page, step)`.
    fn step_links(&self, page: &str, step: &Json) -> Json {
        let mut links = json!({ "totp": false, "webauthn": false, "wallet": false,
                                "password": false, "email": "", "backup": false });
        let alternate = text(step.get("alternate"));
        if page == "password" {
            links["totp"] = json!(alternate == "totp");
            return links;
        }
        if page != "totp" && page != "webauthn" {
            return links;
        }
        links["totp"] = json!(page == "webauthn" && alternate == "totp");
        links["webauthn"] = json!(page == "totp" && alternate == "webauthn");
        // The wallet as a second factor is phase 9's (OID4VP): offered
        // only where `oid4vp.signIn` is on, which it is not by default.
        links["wallet"] = json!(false);
        links["password"] = json!(truthy(step.get("passwordAlternate")));
        let email = text(step.get("email"));
        links["email"] = json!(if email == "code" || email == "link" {
            email
        } else {
            String::new()
        });
        links["backup"] = json!(truthy(step.get("backup")));
        links
    }

    /// `mfaView(req, page, mfaId, key)`: `{ view, uiLocales,
    /// preferredLanguage }`, or the refusal. The passkey page, the set-up
    /// page and the post-login page are their slices' (`Unported`).
    #[tracing::instrument(level = "debug", skip(self, call, id))]
    pub fn mfa_view(
        &self,
        call: &Call,
        page: &str,
        id: &str,
    ) -> Result<Result<Json, (ErrorCode, String)>, &'static str> {
        if ["webauthn", "setup", "post-login"].contains(&page) {
            return Err("getStep");
        }
        let step = match self.step_problem(page, id) {
            Ok(s) => s,
            Err(p) => return Ok(Err(p)),
        };
        let _ = &call.base;
        let username = text(step.get("username"));
        let application = step
            .get("authn")
            .map(|a| text(a.get("application")))
            .unwrap_or_default();
        let mut view = json!({ "page": page, "id": id, "username": username,
                               "passwordless": truthy(step.get("passwordless")),
                               "links": self.step_links(page, &step),
                               "clientDisplay": self.facts.client_display(&application) });
        match page {
            "totp" => {
                let detail =
                    self.mechanisms_for(&username)["totpDetail"].clone();
                let or = |k: &str, d: i64| {
                    let n = number(detail.get(k));
                    if n.is_finite() && n != 0.0 {
                        num(n)
                    } else {
                        json!(d)
                    }
                };
                view["totp"] = json!({ "digits": or("digits", 6), "period": or("period", 30) });
            }
            "password" => {
                let mut amr = SignIn::first_amr_of(&step);
                amr.push("pwd".into());
                view["amr"] = json!(amr);
            }
            "backup-code" => {
                let status = self.credentials.backup_code_status(&username);
                let factor = text(step.get("factor"));
                let remaining = number(status.get("remaining"));
                let remaining = if remaining.is_finite() {
                    remaining
                } else {
                    0.0
                };
                let total = number(status.get("total"));
                let total = if total.is_finite() { total } else { 0.0 };
                view["backup"] = json!({
                    "factor": if factor == "webauthn" { "passkey" }
                              else if factor.starts_with("email-") {
                                  if factor == "email-code" { "code" } else { "link" } }
                              else { "app" },
                    "back": if ["webauthn", "email-code", "email-link"].contains(&factor.as_str()) {
                                factor.clone() } else { "totp".into() },
                    "remaining": num(remaining), "total": num(total),
                    "low": remaining > 0.0 && remaining <= 3.0 });
            }
            _ => {}
        }
        let ui = step
            .get("authn")
            .map(|a| text(a.get("uiLocales")))
            .unwrap_or_default();
        let own = self.facts.preferred_language_of(&username);
        Ok(Ok(json!({ "view": view, "uiLocales": ui,
                      "preferredLanguage": own.unwrap_or(Json::Null) })))
    }

    /// The page a step is drawn on where none was asked for
    /// (`AuthnApi.pageOf()`).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn page_of(&self, id: &str) -> String {
        let factor = self
            .mfa_step_for(id, "any")
            .map(|s| text(s.get("factor")))
            .unwrap_or_default();
        match factor.as_str() {
            "enrol" | "enrol-totp" => "setup".into(),
            "post-login" => "post-login".into(),
            "totp" | "webauthn" | "password" | "email-code" | "email-link" => {
                factor
            }
            _ => "totp".into(),
        }
    }

    // -------------------------------------------------------------------
    // A second-factor step's acts.
    // -------------------------------------------------------------------

    /// `codeStepOf(res, mfaId, what)`.
    fn code_step_of(&self, id: &str, what: &str) -> Result<Json, Answer> {
        let Some(step) = self.mfa_step_for(id, "") else {
            return Err(SignIn::step_refused(
                "This second-factor step has expired. Start the request \
                 again from the application that sent you here.",
                400,
            )
            .marked(codes::STS_AUTHN_0019));
        };
        if let Some((code, why)) = SignIn::key_demand_problem(&step, what) {
            return Err(SignIn::step_refused(&why, 400).marked(code));
        }
        Ok(step)
    }

    /// A step's session, started with the evidence its act verified
    /// (`finishTotp()`, `finishBackupCode()`, `mfaPasswordAct()`'s ends).
    fn finish_step(
        &self,
        call: &Call,
        mut step: Json,
        evidence: Evidence,
    ) -> Answer {
        let username = text(step.get("username"));
        let application = step
            .get("authn")
            .map(|a| text(a.get("application")))
            .unwrap_or_default();
        let mut said = Map::new();
        said.insert("postLoginHold".into(), json!(true));
        said.insert("application".into(), json!(application));
        if let Some(risk) = step.get("risk").filter(|r| !r.is_null()) {
            said.insert("risk".into(), risk.clone());
        }
        let mut response = Response::default();
        let protocol = step
            .get("authn")
            .map(|a| text(a.get("protocol")))
            .unwrap_or_default();
        let mut evidence = evidence;
        evidence.acr = "mfa".into();
        let started = evidence.start_session(
            &self.sessions,
            &mut response,
            &username,
            &protocol,
            &mut said,
            Some(&call.request),
        );
        let mut record = step["authn"].take();
        self.after_session(
            call,
            &mut record,
            &username,
            started,
            &said,
            response,
            true,
        )
    }

    /// `mfaTotpAct(req, res, mfaId, body)` and `finishTotp()`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn mfa_totp_act(&self, call: &Call, id: &str, code: &str) -> Outcome {
        let step = match self.code_step_of(id, "a one-time code") {
            Ok(s) => s,
            Err(a) => return Outcome::Answered(a),
        };
        let username = text(step.get("username"));
        if let Some(refused) = self.rate_limited(
            "mfa-code",
            call,
            &username,
            codes::STS_AUTHN_0040,
            "one-time code",
        ) {
            return Outcome::Answered(refused);
        }
        let verdict = match self.credentials.verify_totp(
            &username,
            &json!(code),
            None,
            None,
        ) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(
                    "{}authn: checking a one-time code for \"{}\" threw: {}",
                    sts_core::log::tag(codes::STS_AUTHN_0182),
                    username,
                    e
                );
                return Outcome::Answered(
                    SignIn::step_refused(
                        "That code could not be checked. Try the next one.",
                        400,
                    )
                    .marked(codes::STS_AUTHN_0182),
                );
            }
        };
        if !verdict.ok() {
            return Outcome::Answered(self.step_verdict_refused(
                &step,
                &username,
                "totp",
                &verdict,
                codes::STS_AUTHN_0105,
                "one-time code",
            ));
        }
        self.limits.succeeded(
            "mfa-code",
            &call.request.address,
            &username,
            false,
        );
        self.stores.mfa.delete(id);
        if truthy(step.get("thenEnrol")) {
            return Outcome::Unported("thenEnrol");
        }
        Outcome::Answered(self.finish_step(
            call,
            step.clone(),
            Evidence::totp_after(&step),
        ))
    }

    /// `mfaBackupCodeAct(req, res, mfaId, body)` and `finishBackupCode()`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn mfa_backup_code_act(
        &self,
        call: &Call,
        id: &str,
        code: &str,
    ) -> Outcome {
        let step = match self.code_step_of(id, "a recovery code") {
            Ok(s) => s,
            Err(a) => return Outcome::Answered(a),
        };
        let username = text(step.get("username"));
        if let Some(refused) = self.rate_limited(
            "mfa-code",
            call,
            &username,
            codes::STS_AUTHN_0042,
            "recovery code",
        ) {
            return Outcome::Answered(refused);
        }
        let verdict = self.credentials.verify_backup_code(&username, code);
        if !verdict.ok() {
            return Outcome::Answered(self.step_verdict_refused(
                &step,
                &username,
                "backup-code",
                &verdict,
                codes::STS_AUTHN_0092,
                "recovery code",
            ));
        }
        self.limits.succeeded(
            "mfa-code",
            &call.request.address,
            &username,
            false,
        );
        self.stores.mfa.delete(id);
        if truthy(step.get("thenEnrol")) {
            return Outcome::Unported("thenEnrol");
        }
        Outcome::Answered(self.finish_step(
            call,
            step.clone(),
            Evidence::recovery_code_after(&step),
        ))
    }

    fn step_verdict_refused(
        &self,
        step: &Json,
        username: &str,
        method: &str,
        verdict: &Verdict,
        fallback: ErrorCode,
        what: &str,
    ) -> Answer {
        let code = verdict.code.unwrap_or(fallback);
        let reason = verdict.reason();
        tracing::info!(
            "authn: the {} for \"{}\" was refused ({}).",
            what,
            username,
            reason
        );
        self.note_refused(
            step,
            username,
            method,
            code,
            if reason.is_empty() { "refused" } else { reason },
        );
        SignIn::step_refused(&text(verdict.value.get("detail")), 400)
            .marked(code)
    }

    fn rate_limited(
        &self,
        door: &str,
        call: &Call,
        username: &str,
        code: ErrorCode,
        what: &str,
    ) -> Option<Answer> {
        let allowed = self.limits.attempt(
            door,
            &call.request.address,
            username,
            &Limit::from_json(&Json::Null),
        );
        if allowed.ok() {
            return None;
        }
        tracing::warn!(
            "authn: too many {} attempts for \"{}\" ({} bucket). Refusing \
             for {}s.",
            what,
            username,
            text(allowed.value.get("kind")),
            text(allowed.value.get("retryAfterS"))
        );
        Some(
            SignIn::step_refused(&text(allowed.value.get("detail")), 429)
                .marked(code),
        )
    }

    /// `mfaPasswordAct(req, res, mfaId, body)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn mfa_password_act(
        &self,
        call: &Call,
        id: &str,
        password: &str,
    ) -> Outcome {
        let step = match self.step_problem("password", id) {
            Ok(s) => s,
            Err((code, why)) => {
                return Outcome::Answered(
                    SignIn::step_refused(&why, 400).marked(code),
                )
            }
        };
        let username = text(step.get("username"));
        let allowed = self.limits.attempt(
            "sign-in",
            &call.request.address,
            &username,
            &Limit::from_json(&Json::Null),
        );
        if !allowed.ok() {
            return Outcome::Answered(
                SignIn::step_refused(&text(allowed.value.get("detail")), 429)
                    .marked(codes::STS_AUTHN_0008),
            );
        }
        let delay = self.limits.wait_after_failures_ms(&username);
        if delay > 0.0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay as u64))
                .await;
        }
        let opts = VerifyOptions::from_json(&json!({
            "via": "the password-factor screen", "secondFactor": "asked-next" }));
        let credential = self.credentials.verify(&username, password, &opts);
        if !credential.ok() {
            self.limits.note_failure(&username);
            tracing::info!(
                "authn: the password second factor for \"{}\" was refused ({}).",
                username,
                credential.reason()
            );
            return Outcome::Answered(
                SignIn::step_refused("That password is not right.", 400)
                    .marked(credential.code.unwrap_or(codes::STS_AUTHN_0196)),
            );
        }
        self.limits.succeeded(
            "sign-in",
            &call.request.address,
            &username,
            false,
        );
        self.limits.forget_failures(&username);
        self.stores.mfa.delete(id);
        if truthy(step.get("thenEnrol")) {
            return Outcome::Unported("thenEnrol");
        }
        let mut amr = SignIn::first_amr_of(&step);
        amr.push("pwd".into());
        let evidence = Evidence {
            amr,
            acr: "mfa".into(),
            credential: json!({ "kind": "password" }),
        };
        Outcome::Answered(self.finish_step(call, step, evidence))
    }

    /// `restartFrom(res, step, kind)`: the step left, its pending sign-in
    /// put back with a fresh clock, and the screen (or the front door,
    /// where it had no request to return to) the answer.
    fn restart_from(&self, call: &Call, step: &Json, kind: &str) -> Answer {
        let username = text(step.get("username"));
        let mut record = step.get("authn").cloned().unwrap_or(Json::Null);
        let id = text(record.get("id"));
        let back = record.is_object() && !id.is_empty();
        if back {
            if let Some(r) = record.as_object_mut() {
                r.insert("screenError".into(), json!(""));
                r.remove("postQuantumRequired");
                r.remove("passkeyChallenge");
                r.insert("rememberBrowser".into(), json!(false));
                r.insert(
                    "expires".into(),
                    num(self.now() + self.pending_ttl_ms()),
                );
            }
            self.stores.pending.set(&id, record.clone());
        }
        let protocol = record
            .get("protocol")
            .map(|p| text(Some(p)))
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| "Authentication".into());
        self.facts.audit(&json!({
            "action": "authn.sign-in.started-over", "outcome": "success",
            "actor": if username.is_empty() { "anonymous".to_string() } else { username.clone() },
            "target": username, "channel": "http", "protocol": protocol,
            "summary": format!("{} left the {} step and started the sign-in over{}",
                if username.is_empty() { "somebody" } else { &username }, kind,
                if back { "" } else { "; it had no request to return to" }),
            "detail": { "step": kind, "returned": back } }));
        let target = if back {
            format!(
                "{}{}?authn={}",
                call.prefix,
                LOGIN_PATH,
                encode_component(&id)
            )
        } else {
            format!("{}/", call.prefix)
        };
        Answer::json(
            200,
            json!({ "ok": true, "next": "redirect",
                                  "location": self.location_of(call, &target) }),
        )
    }

    fn already_ended() -> Answer {
        Answer::json(
            400,
            json!({ "ok": false, "next": "refused", "errors": [
                "This sign-in step has already ended. Start the request again \
                 from the application that sent you here."] }),
        )
        .marked(codes::STS_AUTHN_0331)
    }

    /// `mfaStartOver(req, res, mfaId)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn mfa_start_over(&self, call: &Call, id: &str) -> Answer {
        let Some(step) = self.mfa_step_for(id, "any") else {
            return SignIn::already_ended();
        };
        self.stores.mfa.delete(id);
        let factor = text(step.get("factor"));
        self.restart_from(
            call,
            &step,
            if factor.is_empty() {
                "second-factor"
            } else {
                &factor
            },
        )
    }

    // -------------------------------------------------------------------
    // The forced password change.
    // -------------------------------------------------------------------

    /// `passwordChangeStep(res, changeId)`: the step, or Node's refusal
    /// (`oauthError()`'s shape).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn password_change_step(&self, id: &str) -> Result<Json, Answer> {
        match self.stores.password_change.get(id) {
            Some(step) if !(number(step.get("expires")) < self.now()) => {
                Ok(step)
            }
            _ => {
                self.stores.password_change.delete(id);
                Err(Answer::json(
                    400,
                    json!({ "error": "invalid_request",
                            "error_description": "This password change has \
                             expired. Start the request again from the \
                             application that sent you here." }),
                )
                .marked(codes::STS_AUTHN_0144))
            }
        }
    }

    /// `passwordChangeView(changeId, step)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn password_change_view(id: &str, step: &Json) -> Json {
        json!({ "id": id, "username": text(step.get("username")),
                "notice": text(step.get("notice")) })
    }

    /// `passwordChangeAct(req, res, changeId, step, body)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn password_change_act(
        &self,
        call: &Call,
        id: &str,
        step: Json,
        new_password: &str,
        confirm: &str,
    ) -> Answer {
        let username = text(step.get("username"));
        let problem = if new_password.is_empty() {
            "Enter a new password."
        } else if new_password != confirm {
            "The two passwords are not the same."
        } else if new_password == RESERVED_REFUSAL {
            "That password is reserved and is refused at every sign-in, so \
             it cannot be yours."
        } else {
            ""
        };
        if !problem.is_empty() {
            return SignIn::step_refused(problem, 400)
                .marked(codes::STS_AUTHN_0146);
        }
        let application = step
            .get("authn")
            .map(|a| text(a.get("application")))
            .unwrap_or_default();
        let written = match self.credentials.set_password(
            &username,
            new_password,
            &json!({ "via": "the forced password change", "application": application }),
        ) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(
                    "{}authn: the forced password change for \"{}\" threw: {}",
                    sts_core::log::tag(codes::STS_AUTHN_0146),
                    username,
                    e
                );
                Verdict::coded(
                    codes::STS_AUTHN_0146,
                    json!({ "ok": false, "errors": [] }),
                )
            }
        };
        if !written.ok() {
            let errors: Vec<String> = written
                .value
                .get("errors")
                .and_then(Json::as_array)
                .map(|l| l.iter().map(|e| text(Some(e))).collect())
                .unwrap_or_default();
            let said = errors.join(" ");
            return SignIn::step_refused(
                if said.is_empty() {
                    "The new password was not accepted."
                } else {
                    &said
                },
                400,
            )
            .marked(written.code.unwrap_or(codes::STS_AUTHN_0146));
        }
        if !self.facts.clear_password_reset(&username) {
            tracing::warn!(
                "{}authn: the password for \"{}\" was changed and pwdReset \
                 could not be cleared, so it will be asked for again.",
                sts_core::log::tag(codes::STS_AUTHN_0143),
                username
            );
        }
        self.stores.password_change.delete(id);
        self.facts.audit(&json!({
            "action": "authn.password.changed", "outcome": "success",
            "actor": username, "target": username, "channel": "http",
            "protocol": step.get("authn").and_then(|a| a.get("protocol")).cloned()
                .unwrap_or(Json::Null),
            "summary": format!("{} changed a password they were required to \
                change at sign-in", username),
            "detail": { "forced": true } }));
        tracing::info!(
            "authn: \"{}\" chose a new password; the sign-in continues.",
            username
        );
        let record = step.get("authn").cloned().unwrap_or(Json::Null);
        self.finish_password_sign_in(
            call,
            record,
            &username,
            false,
            truthy(step.get("secondFactor")),
        )
    }

    /// `passwordChangeStartOver(req, res, changeId)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn password_change_start_over(&self, call: &Call, id: &str) -> Answer {
        let step = self.stores.password_change.get(id);
        let Some(step) =
            step.filter(|s| !(number(s.get("expires")) < self.now()))
        else {
            self.stores.password_change.delete(id);
            return SignIn::already_ended();
        };
        self.stores.password_change.delete(id);
        self.restart_from(call, &step, "password-change")
    }
}

fn held_count(n: usize) -> Json {
    json!(n)
}

/// `Credentials.isLaneName(username)` (#643): `name+ml-dsa` or
/// `name+ml-dsa-<n>`, the name a credential manager shows for a
/// post-quantum passkey.
#[tracing::instrument(level = "trace")]
pub fn is_lane_name(username: &str) -> bool {
    static LANE: std::sync::LazyLock<Option<regex::Regex>> =
        std::sync::LazyLock::new(|| {
            regex::Regex::new(r"(?i)\+(ml-dsa(-[0-9]+)?|pqc)$").ok()
        });
    LANE.as_ref().is_some_and(|r| r.is_match(username.trim()))
}
