// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! WHAT THE CHANNEL IS FOR (`common/mail_uses.ts`): the request each use
//! hands [`Mail::send`] — an administrator's link, a security notice and the
//! administrators' alert beside it, the notices `ssf/account_signals.ts`
//! turns acts into, an access request waiting for its owner, a UMA or
//! AuthZEN approval, the pinned-certificate audit, a post-login reminder, a
//! changed address told to the former one.
//!
//! A request is built as the JSON object Node builds and read with
//! [`SendRequest::from_json`], so the two cannot drift by a member. A value
//! that is words is `{ i18n: 'mailValues.<key>' }` ([`MailUses::said`]),
//! made words by the channel in the recipient's language; an instant is
//! `{ date }`.
//!
//! **NOT HERE YET**: the self-service reset (`requestReset()`) and the
//! address verification (`startVerification()`, `checkVerification()`,
//! `startAddressChange()`), which stand on the credential store, the
//! recovery codes, the passkey policy and the directory's writes — each
//! another slice's crate. Their sentences and codes are Node's and come
//! with those ports.

use std::sync::Arc;

use serde_json::{json, Map, Value as Json};
use sts_core::errors::codes;
use sts_core::settings::Settings;

use crate::channel::{Mail, SendRequest, SendResult};

/// The portal's reset page.
pub const RESET_PATH: &str = "/portal/reset-password";
/// The portal's activation page.
pub const ACTIVATE_PATH: &str = "/portal/activate";
/// The portal's address verification page.
pub const VERIFY_PATH: &str = "/portal/verify-email";

/// The uses, over the channel.
pub struct MailUses {
    mail: Arc<Mail>,
    settings: Arc<Settings>,
    now: Arc<dyn Fn() -> i64 + Send + Sync>,
}

/// `encodeURIComponent()`.
fn encode_component(text: &str) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn skipped(why: &str) -> Json {
    json!({ "ok": false, "skipped": why })
}

/// What a use handed the channel: its requests, and the rows they queued,
/// which the caller attempts with [`Mail::dispatch`] (Node's `send()`
/// dispatched them itself).
#[derive(Debug, Default)]
pub struct Made {
    pub requests: Vec<Json>,
    pub queued: Vec<Json>,
}

/// A use's answer: the channel's, or why nothing was sent.
#[derive(Debug, Clone, PartialEq)]
pub enum UseResult {
    Sent(SendResult),
    Skipped(Json),
}

impl UseResult {
    /// As Node answers it.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn to_json(&self) -> Json {
        match self {
            UseResult::Sent(r) => r.to_json(),
            UseResult::Skipped(j) => j.clone(),
        }
    }
}

impl MailUses {
    /// Over the channel, the settings and the clock.
    pub fn new(
        mail: Arc<Mail>,
        settings: Arc<Settings>,
        now: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> MailUses {
        MailUses { mail, settings, now }
    }

    /// `MailUses.said(key, params)`: words, made in the recipient's
    /// language.
    #[tracing::instrument(level = "debug")]
    pub fn said(key: &str, params: Option<Json>) -> Json {
        match params {
            Some(p) => json!({ "i18n": format!("mailValues.{}", key),
                               "params": p }),
            None => json!({ "i18n": format!("mailValues.{}", key) }),
        }
    }

    /// `MailUses.keyOf(value)`: a value as a dedup key's part.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn key_of(value: Option<&Json>) -> String {
        match value {
            Some(v @ Json::Object(_)) | Some(v @ Json::Array(_)) => v.to_string(),
            other => crate::js::text_or_empty(other),
        }
    }

    fn instant(&self) -> Json {
        json!({ "date": (self.now)() })
    }

    fn send(&self, req: Json) -> SendResult {
        self.mail.send(&SendRequest::from_json(&req))
    }

    /// Sends one request, noting it and what it queued.
    fn sent(&self, req: Json, made: &mut Made) -> SendResult {
        made.requests.push(req.clone());
        let out = self.send(req);
        made.queued.extend(out.queued.iter().cloned());
        out
    }

    /// `mailAdministratorLink(kind, username, token, actor, via)`.
    #[tracing::instrument(level = "debug", skip(self, token, made))]
    pub fn mail_administrator_link(
        &self,
        kind: &str,
        username: &str,
        token: &str,
        actor: &str,
        via: &str,
        made: &mut Made,
    ) -> (Json, SendResult) {
        let reset = kind == "reset";
        let ttl = self.settings.value_of(if reset {
            "security.passwordResetTtlMinutes"
        } else {
            "security.activationTtlMinutes"
        }).as_int();
        let requested = if actor.is_empty() {
            MailUses::said("requestedBy.administrator", None)
        } else {
            MailUses::said("requestedBy.administratorNamed",
                           Some(json!({ "actor": actor })))
        };
        let sent = self.sent(json!({
            "username": username,
            "template": if reset { "password-reset" } else {
                "account-activation" },
            "values": { "username": username, "requestedBy": requested,
                        "expiresMinutes": ttl.to_string() },
            "links": { "link": format!("{}?user={}#token={}",
                if reset { RESET_PATH } else { ACTIVATE_PATH },
                encode_component(username), encode_component(token)) },
            "via": via, "actor": actor
        }), made);
        if !sent.ok {
            let code = sent.refused.first().map_or(codes::STS_MAIL_0001,
                                                   |r| r.code);
            let answer = json!({ "ok": false, "errors": [format!(
                "The link was not mailed: {}.", sent.error.clone()
                    .unwrap_or_else(|| "it was refused".into()))],
                "code": code.as_str() });
            return (answer, sent);
        }
        let to = sent.queued.first().or(sent.duplicates.first())
            .and_then(|v| v.get("to")).and_then(Json::as_str).unwrap_or("")
            .to_string();
        (json!({ "ok": true, "mailedTo": to, "message": format!(
            "The link was mailed to {} and is not shown here.", to) }), sent)
    }

    /// `notice(kind, username, facts)`: a security notice; with `bySystem`
    /// the realm's administrators are told too.
    #[tracing::instrument(level = "debug", skip(self, facts, made))]
    pub fn notice(
        &self,
        kind: &str,
        username: &str,
        facts: &Json,
        made: &mut Made,
    ) -> UseResult {
        if !self.settings.value_of("mail.securityNotices").as_bool()
            || username.is_empty()
            || !self.mail.available()
        {
            return UseResult::Skipped(skipped("off"));
        }
        let mut values = Map::new();
        values.insert("username".into(), json!(username));
        values.insert("when".into(), self.instant());
        if let Some(given) = facts.get("values").and_then(Json::as_object) {
            for (k, v) in given {
                values.insert(k.clone(), v.clone());
            }
        }
        fn truthy(v: Option<&Json>) -> Option<&Json> {
            v.filter(|v| match v {
                Json::Null | Json::Bool(false) => false,
                Json::String(s) => !s.is_empty(),
                _ => true,
            })
        }
        let key = truthy(values.get("how")).or(truthy(values.get("why")))
            .or(truthy(values.get("by")));
        let text = |k: &str| crate::js::text_or_empty(facts.get(k));
        let dedup = if text("dedupKey").is_empty() {
            format!("{}:{}", kind, MailUses::key_of(key))
        } else {
            text("dedupKey")
        };
        let via = if text("via").is_empty() { "a security notice".into() }
                  else { text("via") };
        let out = self.sent(json!({
            "username": username, "template": kind, "values": values,
            "dedupKey": dedup, "via": via, "actor": text("actor")
        }), made);
        let by_system = facts.get("bySystem").and_then(Json::as_bool)
            .unwrap_or(false);
        if by_system && self.settings.value_of("mail.notifyAdministrators")
            .as_bool() {
            let act = facts.get("act").cloned()
                .filter(|a| !a.is_null() && a != "")
                .unwrap_or(json!(kind));
            self.sent(json!({
                "toAdministrators": true, "template": "administrator-alert",
                "values": { "username": username, "when": values["when"],
                            "act": act,
                            "why": values.get("why").cloned()
                                .filter(|w| !w.is_null()).unwrap_or(json!("")) },
                "dedupKey": format!("admin:{}:{}", kind, username),
                "via": via, "actor": "the service"
            }), made);
        }
        UseResult::Sent(out)
    }

    /// `fromAccountSignal(act, notice)`: the CAEP / RISC acts turned into
    /// notices — a password change (not an app password's), a compromised
    /// credential, a recovery whose link was not itself mailed.
    #[tracing::instrument(level = "debug", skip(self, n, made))]
    pub fn from_account_signal(
        &self,
        act: &str,
        n: &Json,
        made: &mut Made,
    ) -> UseResult {
        let text = |k: &str| crate::js::text_or_empty(n.get(k));
        let username = text("username");
        let system = text("initiatingEntity") == "system";
        let credential = if text("credentialType").is_empty() { "password" }
                         else { "" }.to_string();
        let credential = if credential.is_empty() { text("credentialType") }
                         else { credential };
        let truthy = |k: &str| n.get(k).is_some_and(|v| match v {
            Json::Null | Json::Bool(false) => false,
            Json::String(s) => !s.is_empty(),
            _ => true,
        });
        if act == "credentialChanged" && credential == "password"
            && !truthy("friendlyName") {
            let how = if truthy("reasonUser") || truthy("via") {
                json!(if truthy("reasonUser") { text("reasonUser") }
                      else { text("via") })
            } else {
                MailUses::said("how.by", Some(json!({ "entity":
                    if text("initiatingEntity").is_empty() { "someone".into() }
                    else { text("initiatingEntity") } })))
            };
            let mut facts = json!({ "values": { "how": how } });
            if let Some(v) = n.get("via") {
                facts["via"] = v.clone();
            }
            return self.notice("password-changed", &username, &facts,
                               made);
        }
        if act == "credentialCompromised" {
            let mut facts = json!({
                "values": { "what": MailUses::said("credential.type",
                    Some(json!({ "type": credential }))),
                            "why": text("reasonUser") },
                "bySystem": system,
                "act": MailUses::said("act.credentialCompromised", None) });
            if let Some(v) = n.get("via") {
                facts["via"] = v.clone();
            }
            return self.notice("credential-compromised", &username, &facts,
                               made);
        }
        if act == "recoveryActivated" && !truthy("mailed") {
            let by = if text("initiatingEntity") == "user" {
                MailUses::said("by.you", None)
            } else {
                MailUses::said("by.administrator", None)
            };
            let mut facts = json!({ "values": { "by": by } });
            if let Some(v) = n.get("via") {
                facts["via"] = v.clone();
            }
            return self.notice("recovery-started", &username, &facts,
                               made);
        }
        UseResult::Skipped(skipped("not a notice"))
    }

    fn waiting(
        &self,
        username: &str,
        req: Json,
        made: &mut Made,
    ) -> UseResult {
        if username.is_empty() || !self.mail.available() {
            return UseResult::Skipped(skipped("no transport"));
        }
        UseResult::Sent(self.sent(req, made))
    }

    /// `accessRequested(username, facts)` (#432): a GNAP grant waiting on
    /// `/portal/ciba`.
    #[tracing::instrument(level = "debug", skip(self, f, made))]
    pub fn access_requested(&self, username: &str, f: &Json,
                            made: &mut Made) -> UseResult {
        let text = |k: &str| crate::js::text_or_empty(f.get(k));
        let rights = if text("rights").is_empty() {
            MailUses::said("rights.access", None)
        } else {
            json!(text("rights"))
        };
        let dedup = if text("dedupKey").is_empty() {
            format!("access-request:{}", username)
        } else {
            text("dedupKey")
        };
        self.waiting(username, json!({
            "username": username, "template": "access-request",
            "values": { "username": username, "client": text("client"),
                        "rights": rights,
                        "expiresMinutes": text("expiresMinutes") },
            "links": { "link": "/portal/ciba" }, "dedupKey": dedup,
            "via": "a GNAP access request", "actor": text("client")
        }), made)
    }

    /// `pkiPinStatus(facts)`: to the realm's administrators.
    #[tracing::instrument(level = "debug", skip(self, f, made))]
    pub fn pki_pin_status(&self, f: &Json, made: &mut Made)
        -> UseResult {
        let text = |k: &str| crate::js::text_or_empty(f.get(k));
        UseResult::Sent(self.sent(json!({
            "toAdministrators": true, "template": "pki-pin-status",
            "values": { "changes": text("changes") },
            "dedupKey": text("dedupKey"),
            "via": "the pinned certificate audit", "actor": "the service"
        }), made))
    }

    /// `postLoginReminder(username, facts)` (#1111).
    #[tracing::instrument(level = "debug", skip(self, f, made))]
    pub fn post_login_reminder(&self, username: &str, f: &Json,
                               made: &mut Made) -> UseResult {
        let text = |k: &str| crate::js::text_or_empty(f.get(k));
        let mails = f.get("mails").and_then(Json::as_f64).unwrap_or(0.0);
        self.waiting(username, json!({
            "username": username, "template": "post-login-reminder",
            "values": { "username": username },
            "links": { "signin": "/portal" },
            "dedupKey": format!("post-login-reminder:{}:{}:{}",
                                text("started"), username,
                                crate::js::string_of(&json!(mails))),
            "via": "a started post-login activity", "actor": text("actor")
        }), made)
    }

    /// `umaApprovalRequested(username, facts)`.
    #[tracing::instrument(level = "debug", skip(self, f, made))]
    pub fn uma_approval_requested(&self, username: &str, f: &Json,
                                  made: &mut Made) -> UseResult {
        let text = |k: &str| crate::js::text_or_empty(f.get(k));
        let dedup = if text("dedupKey").is_empty() {
            format!("uma-approval:{}", username)
        } else {
            text("dedupKey")
        };
        self.waiting(username, json!({
            "username": username, "template": "uma-approval",
            "values": { "username": username, "requester": text("requester"),
                        "client": text("client"), "resource": text("resource"),
                        "scopes": text("scopes"),
                        "expiresMinutes": text("expiresMinutes") },
            "links": { "link": "/portal/shared" }, "dedupKey": dedup,
            "via": "a UMA request", "actor": text("client")
        }), made)
    }

    /// `authzenAccessRequested(username, facts)` (#563, #1180).
    #[tracing::instrument(level = "debug", skip(self, f, made))]
    pub fn authzen_access_requested(&self, username: &str, f: &Json,
                                    made: &mut Made) -> UseResult {
        let text = |k: &str| crate::js::text_or_empty(f.get(k));
        let emergency = f.get("emergency").is_some_and(|e| e == true);
        let mut values = json!({ "username": username,
            "requester": text("requester"), "subject": text("subject"),
            "action": text("action"), "resource": text("resource"),
            "application": text("application") });
        if emergency {
            values["justification"] = json!(text("justification"));
        } else {
            values["expiresMinutes"] = json!(text("expiresMinutes"));
        }
        let dedup = if text("dedupKey").is_empty() {
            format!("authzen-access-request:{}", username)
        } else {
            text("dedupKey")
        };
        self.waiting(username, json!({
            "username": username,
            "template": if emergency { "authzen-emergency-access" }
                        else { "authzen-access-request" },
            "values": values, "links": { "link": "/portal/access-requests" },
            "dedupKey": dedup, "via": "an AuthZEN access request",
            "actor": text("requester")
        }), made)
    }

    /// `accountDisabled(username, why, bySystem)`.
    #[tracing::instrument(level = "debug", skip(self, made))]
    pub fn account_disabled(&self, username: &str, why: &str, by_system: bool,
                            made: &mut Made) -> UseResult {
        self.notice("account-disabled", username, &json!({
            "values": { "why": why }, "bySystem": by_system,
            "act": MailUses::said("act.accountDisabled", None),
            "via": "account state" }), made)
    }

    /// `sessionsEnded(username, count, by)`.
    #[tracing::instrument(level = "debug", skip(self, by, made))]
    pub fn sessions_ended(&self, username: &str, count: i64, by: &Json,
                          made: &mut Made) -> UseResult {
        let by = match by {
            Json::Object(_) => by.clone(),
            Json::String(s) if !s.is_empty() => by.clone(),
            _ => MailUses::said("by.administrator", None),
        };
        self.notice("sessions-ended", username, &json!({
            "values": { "count": count.to_string(), "by": by },
            "dedupKey": format!("sessions-ended:{}", username),
            "via": "an administrator" }), made)
    }

    /// `addressChanged(username, former, new)`: told to the former address.
    #[tracing::instrument(level = "debug", skip(self, made))]
    pub fn address_changed(&self, username: &str, former: &str,
                           new_address: &str, made: &mut Made) -> UseResult {
        if former.is_empty()
            || !self.settings.value_of("mail.securityNotices").as_bool()
            || !self.mail.available()
        {
            return UseResult::Skipped(skipped("nothing to tell"));
        }
        let address = if new_address.is_empty() {
            MailUses::said("address.none", None)
        } else {
            json!(new_address)
        };
        let req = json!({ "username": username, "formerAddress": former,
            "template": "address-changed",
            "values": { "username": username, "when": self.instant(),
                        "address": address },
            "dedupKey": format!("address-changed:{}>{}", former, new_address),
            "via": "a directory change" });
        let out = self.mail.send_to_former_address(
            &SendRequest::from_json(&req));
        made.queued.extend(out.queued.iter().cloned());
        UseResult::Sent(out)
    }
}
