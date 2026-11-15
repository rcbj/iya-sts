// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The emailed code and the emailed sign-in link AS A FACT ABOUT A PERSON:
//! a port of `common/mail_factor.ts` (`common/CLAUDE.md` 3be, #64) — who
//! has opted in to which, whether it is usable (the authentication policy
//! accepts it, the realm can send mail, the address is verified), the
//! consecutive-failure limit that turns it off (NIST SP 800-63B-4 section
//! 3.2.2), and the secrets themselves: a six-digit code or a 256-bit link
//! token, hashed like a password and compared in constant time.
//!
//! The step that SENDS one and spends it (`authn/email_factor.ts`) is the
//! sign-in screen's and not here; what it sends goes through `sts-mail`,
//! reached by [`MailFactorPorts::send`]. The person's values arrive through
//! [`MailFactorPorts::person`], already read off the entry by the model's
//! classes (`User.email`, `PersonRecord.mailVerified`,
//! `AuthenticationPolicy.stsMailFactor` and `…Failures`), as
//! `MailFactor.entryOf()` reads them.

use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_core::errors::codes;
use sts_core::log::tag;
use sts_crypto::secrets::verify_secret;

use crate::js;
use crate::ports::Environment;
use crate::Verdict;

/// `AccountSignals.EMAIL_OTP_CREDENTIAL_TYPE`: what a CAEP
/// credential-change event names this factor.
pub const EMAIL_OTP_CREDENTIAL_TYPE: &str =
    "urn:iya:sts:credential-type:email-otp";

/// The mechanism names the authentication policy knows them by.
#[tracing::instrument(level = "debug", skip_all)]
pub fn mechanism(kind: &str) -> &'static str {
    if kind == "link" {
        "emailLink"
    } else {
        "emailCode"
    }
}

/// `MailFactor.isKind()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn is_kind(value: &str) -> bool {
    value == "code" || value == "link"
}

/// A person's values, as `entryOf()` answers them.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PersonValues {
    pub mail: String,
    pub verified: String,
    pub factor: String,
    pub failures: String,
}

/// What the emailed factor reaches outside itself for.
pub trait MailFactorPorts: Send + Sync {
    /// `entryOf(username)`: the person's values, or none.
    fn person(&self, username: &str) -> Option<PersonValues>;
    /// `directory.writeMailFlag(username, name, value)`.
    fn write_flag(&self, username: &str, name: &str, value: &str) -> bool;
    /// `authnPolicy.allows(mechanism, role)`.
    fn allows(&self, mechanism: &str, role: &str) -> bool;
    /// `authnPolicy.active(mechanism, role)`: allowed, and mail can go.
    fn active(&self, mechanism: &str, role: &str) -> bool;
    /// `authnPolicy.emailSettings().failureLimit`.
    fn failure_limit(&self) -> f64;
    /// `audit.audit(row)`.
    fn audit(&self, row: &Json);
    /// `account_signals.credentialChanged(facts)`.
    fn credential_changed(&self, facts: &Json);
    /// `account_signals.credentialCompromised(facts)`.
    fn credential_compromised(&self, facts: &Json);
    /// `mail.send(message)`, through `sts-mail`.
    fn send(&self, message: &Json);
    /// `new Date().toISOString()`.
    fn now_iso(&self) -> String;
}

/// The mechanism.
pub struct MailFactor {
    env: Arc<dyn Environment>,
    ports: Arc<dyn MailFactorPorts>,
}

impl MailFactor {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(
        env: Arc<dyn Environment>,
        ports: Arc<dyn MailFactorPorts>,
    ) -> MailFactor {
        MailFactor { env, ports }
    }

    /// `status(username)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn status(&self, username: &str) -> Json {
        self.status_of_values(self.ports.person(username).as_ref())
    }

    fn status_of_values(&self, entry: Option<&PersonValues>) -> Json {
        let kind = entry
            .map(|e| e.factor.clone())
            .filter(|f| is_kind(f))
            .unwrap_or_default();
        let verified = entry.is_some_and(|e| {
            !e.mail.is_empty()
                && e.verified.to_lowercase() == e.mail.to_lowercase()
        });
        let code = self.ports.active(mechanism("code"), "second-factor");
        let link = self.ports.active(mechanism("link"), "second-factor");
        let offered = if kind == "link" { link } else { code };
        let why = if kind.is_empty() {
            "not opted in".to_string()
        } else if !self.ports.allows(mechanism(&kind), "second-factor") {
            format!(
                "this realm's authentication policy does not accept an \
                 emailed {kind} as a second factor"
            )
        } else if !offered {
            "this realm cannot send mail".to_string()
        } else if !verified {
            "the address on the account is not verified".to_string()
        } else {
            String::new()
        };
        let failures = entry.map_or(0.0, |e| {
            let n = js::number_or_fallback(Some(&json!(e.failures)), 0.0);
            if n.is_nan() {
                0.0
            } else {
                n
            }
        });
        json!({ "optedIn": kind, "kind": kind,
            "usable": !kind.is_empty() && why.is_empty(), "why": why,
            "verified": verified,
            "address": entry.map_or(String::new(), |e| e.mail.clone()),
            "offered": { "code": code, "link": link },
            "failures": js::num(failures) })
    }

    /// `held(username)`: the kind, where it is usable.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn held(&self, username: &str) -> String {
        let s = self.status(username);
        if js::truthy_opt(s.get("usable")) {
            js::string(&s["kind"])
        } else {
            String::new()
        }
    }

    /// `masked(address)`: the first letter of the local part, `***`, the
    /// domain.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn masked(address: &str) -> String {
        let units: Vec<u16> = address.encode_utf16().collect();
        let at = units.iter().rposition(|u| *u == u16::from(b'@'));
        match at {
            Some(i) if i >= 1 => {
                let first = String::from_utf16_lossy(&units[..1]);
                format!("{first}***{}", String::from_utf16_lossy(&units[i..]))
            }
            _ => "your address".to_string(),
        }
    }

    /// `optIn(username, kind, actor, via)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn opt_in(
        &self,
        username: &str,
        kind: &str,
        actor: &str,
        via: &str,
    ) -> Verdict {
        let refuse = |code, sentence: String| {
            Verdict::coded(code, json!({ "ok": false, "errors": [sentence] }))
        };
        if !is_kind(kind) {
            return refuse(
                codes::STS_AUTHN_0247,
                "An emailed second factor is a `code` or a `link`.".to_string(),
            );
        }
        let m = mechanism(kind);
        if !self.ports.allows(m, "second-factor") {
            return refuse(
                codes::STS_AUTHN_0248,
                format!(
                    "This realm's authentication policy does not accept an \
                     emailed {kind} as a second factor."
                ),
            );
        }
        if !self.ports.active(m, "second-factor") {
            return refuse(
                codes::STS_AUTHN_0249,
                format!(
                    "This realm cannot send mail just now, so an emailed \
                     {kind} could not reach you."
                ),
            );
        }
        let status = self.status(username);
        if !js::truthy_opt(status.get("verified")) {
            return refuse(
                codes::STS_AUTHN_0250,
                "Your address is not verified. Verify it on the Email page \
                 first: a code sent to an address nobody proved they read is \
                 a code anybody might read."
                    .to_string(),
            );
        }
        if !self.ports.write_flag(username, "stsMailFactor", kind)
            || !self.ports.write_flag(username, "stsMailFactorFailures", "")
        {
            return refuse(
                codes::STS_AUTHN_0251,
                "Your choice could not be stored. Try again.".to_string(),
            );
        }
        self.ports
            .audit(&json!({ "action": "authn.mail-factor.change",
            "actor": actor, "target": username, "channel": "http",
            "protocol": "Authentication",
            "summary": format!("{username} now receives an emailed {kind} \
                                as a second factor"),
            "detail": { "kind": kind, "via": via } }));
        let before = js::string(&status["optedIn"]);
        let change = if before.is_empty() {
            "create"
        } else if before == kind {
            ""
        } else {
            "update"
        };
        self.signal_change(username, change, kind, actor, via, "");
        Verdict::of(json!({ "ok": true, "kind": kind }))
    }

    /// `clear(username, actor, via, why)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn clear(
        &self,
        username: &str,
        actor: &str,
        via: &str,
        why: &str,
    ) -> Json {
        let before = js::string(&self.status(username)["optedIn"]);
        if before.is_empty() {
            return json!({ "ok": true, "removed": false });
        }
        let written = self.ports.write_flag(username, "stsMailFactor", "")
            && self.ports.write_flag(username, "stsMailFactorFailures", "");
        if written {
            self.ports
                .audit(&json!({ "action": "authn.mail-factor.change",
                "actor": actor, "target": username, "channel": "http",
                "protocol": "Authentication",
                "summary": format!(
                    "{username} no longer receives an emailed {before} as a \
                     second factor{}",
                    if why.is_empty() { String::new() }
                    else { format!(" ({why})") }),
                "detail": { "kind": "", "was": before, "via": via,
                            "why": why } }));
            self.signal_change(username, "delete", &before, actor, via, why);
        }
        json!({ "ok": written, "removed": written, "was": before })
    }

    fn signal_change(
        &self,
        username: &str,
        change: &str,
        kind: &str,
        actor: &str,
        via: &str,
        why: &str,
    ) {
        if change.is_empty() {
            return;
        }
        let initiating = if actor.is_empty() {
            "system"
        } else if actor == username {
            "user"
        } else {
            "admin"
        };
        let what = format!("the emailed {kind} as a second factor");
        let verb = match change {
            "create" => "turned on",
            "update" => "changed",
            _ => "turned off",
        };
        let who = match initiating {
            "system" => "This service".to_string(),
            "user" => username.to_string(),
            _ => "An administrator".to_string(),
        };
        self.ports.credential_changed(&json!({ "username": username,
            "credentialType": EMAIL_OTP_CREDENTIAL_TYPE, "changeType": change,
            "initiatingEntity": initiating,
            "friendlyName": format!("emailed {kind}"), "via": via,
            "reasonAdmin": format!("{who} {verb} {what} for {username}{}.",
                if why.is_empty() { String::new() }
                else { format!(" ({why})") }),
            "reasonUser": format!("Your emailed second factor was {verb}{}.",
                if why.is_empty() { String::new() }
                else { format!(": {why}") }) }));
    }

    /// `noteSuccess(username)`: the failure count goes back to none.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn note_success(&self, username: &str) {
        if js::truthy_opt(self.status(username).get("failures")) {
            self.ports.write_flag(username, "stsMailFactorFailures", "");
        }
    }

    /// `noteFailure(username)`: one more consecutive failure; at the
    /// policy's limit the factor is turned off, signalled and mailed
    /// (STS-AUTHN-0252).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn note_failure(&self, username: &str) -> Json {
        let status = self.status(username);
        let failures = js::number_opt(status.get("failures")) + 1.0;
        let limit = self.ports.failure_limit();
        if failures < limit {
            self.ports.write_flag(
                username,
                "stsMailFactorFailures",
                &js::number_text(failures),
            );
            return json!({ "failures": js::num(failures), "cleared": false });
        }
        let n = js::number_text(failures);
        let l = js::number_text(limit);
        tracing::warn!(
            "{}authn: {} consecutive failed emailed codes or links for \"{}\", \
             the limit of {}. Their emailed factor is turned off (NIST SP \
             800-63B-4 section 3.2.2).",
            tag(codes::STS_AUTHN_0252),
            n,
            username,
            l
        );
        self.clear(
            username,
            "",
            "failure-limit",
            &format!("{n} consecutive failures, the limit"),
        );
        self.ports.write_flag(username, "stsMailFactorFailures", "");
        self.ports.credential_compromised(&json!({ "username": username,
            "credentialType": EMAIL_OTP_CREDENTIAL_TYPE, "initiatingEntity": "system",
            "mailed": true, "via": "authn",
            "reasonAdmin": format!(
                "{n} consecutive failed emailed codes or links for \
                 {username} reached the limit of {l}, and the factor was \
                 turned off."),
            "reasonUser": "Too many wrong codes or links turned your emailed \
                           second factor off." }));
        let when = self.ports.now_iso();
        let hour: String = when.chars().take(13).collect();
        self.ports.send(&json!({ "username": username,
            "template": "credential-compromised",
            "values": { "username": username, "when": when,
                        "what": "emailed second factor",
                        "why": format!("{n} wrong codes or links in a row \
                                        turned it off.") },
            "dedupKey": format!("mail-factor-limit:{hour}"), "via": "authn" }));
        self.ports.send(&json!({ "toAdministrators": true,
            "template": "administrator-alert",
            "values": { "username": username, "when": when,
                        "act": "turned off the emailed second factor",
                        "why": format!("{n} consecutive failed codes or links \
                                        reached the limit of {l}.") },
            "dedupKey": format!("mail-factor-limit:{username}:{hour}"),
            "via": "authn" }));
        json!({ "failures": js::num(failures), "cleared": true })
    }

    /// `mintCode()`: six digits.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn mint_code(&self) -> String {
        format!("{:06}", self.env.random_int(0, 1_000_000))
    }

    /// `mintToken()`: 256 random bits, base64url.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn mint_token(&self) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        URL_SAFE_NO_PAD.encode(self.env.random_bytes(32))
    }

    /// `hash(secret)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn hash(&self, secret: &str) -> String {
        self.env.hash_secret(secret)
    }

    /// `matches(secret, stored)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn matches(secret: &str, stored: &str) -> bool {
        !stored.is_empty()
            && !secret.is_empty()
            && verify_secret(secret, stored)
    }

    /// `normalizeCode(typed)`: six digits once spaces and dashes go, else
    /// empty.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn normalize_code(typed: &str) -> String {
        let out = js::without_spaces_and_dashes(typed);
        if out.len() == 6 && out.chars().all(|c| c.is_ascii_digit()) {
            out
        } else {
            String::new()
        }
    }
}
