// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The credential questions `startSession()` asks, as the session slice's
//! [`CredentialChecks`] port: `authn.ts`'s `passkeySignInRefusal()`
//! (#536, #718), `recoveryRefusalAtSession()` and `recoveryCompleted()`
//! (#724, 3cq), `noteAlgorithmMismatch()` (#943) and
//! `notePasskeyStanding()` (#718), over this crate's credential store and
//! the passkey policy's decisions ([`PasskeyRules`]).
//!
//! **RECOVERY NO WEAKER THAN THE PASSKEY IT REPLACES** (3cq): a session for
//! a person who holds a passkey, when a recovery is pending on their entry
//! or the credential that answered is itself a recovery door (a recovery
//! code, an emailed code or link), is asked of the issuance policy
//! (`recover-account`); a passkey ASSERTION afterwards completes the
//! recovery. A key registered in the same act is not one (#901).

use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_authn::ports::CredentialChecks;

use crate::credentials::Credentials;
use crate::js;
use crate::ports::PasskeyRules;

/// `passkeyPolicy.RECOVERY_CREDENTIALS`: the credential kinds that are
/// themselves a recovery door, by the door's name.
pub fn recovery_door_of(kind: &str) -> &'static str {
    match kind {
        "backup-code" => "recovery-code",
        "email-code" => "email-code",
        "email-link" => "email-link",
        _ => "",
    }
}

/// `AccountSignals.keyCredentialType(key)`.
pub fn key_credential_type(key: &Json) -> &'static str {
    if key.get("attachment").and_then(Json::as_str) == Some("platform") {
        "fido2-platform"
    } else {
        "fido2-roaming"
    }
}

/// The port's implementation.
pub struct SessionChecks {
    credentials: Arc<Credentials>,
    rules: Arc<dyn PasskeyRules>,
}

impl SessionChecks {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(
        credentials: Arc<Credentials>,
        rules: Arc<dyn PasskeyRules>,
    ) -> SessionChecks {
        SessionChecks { credentials, rules }
    }

    fn key_of(
        &self,
        username: &str,
        credential: &Json,
    ) -> (Option<Json>, Vec<Json>) {
        let id = js::string_or(credential.get("id"), "");
        let keys = self.credentials.keys_of(username);
        let key = keys
            .iter()
            .find(|k| js::string_or_empty(k.get("credentialId")) == id)
            .cloned();
        (key, keys)
    }
}

fn kind_of(credential: &Json) -> String {
    js::string_or(credential.get("kind"), "")
}

impl CredentialChecks for SessionChecks {
    /// `passkeySignInRefusal(username, credential)`: whether the passkey
    /// that answered may sign this person in — its BE flag, the PIN length
    /// it reported, its algorithm and lane, asked of the passkey policy.
    #[tracing::instrument(level = "debug", skip(self, credential))]
    fn passkey_sign_in_refusal(
        &self,
        username: &str,
        credential: &Json,
    ) -> Option<Json> {
        if kind_of(credential) != "webauthn" {
            return None;
        }
        let (key, _) = self.key_of(username, credential);
        let mut facts = serde_json::Map::new();
        facts.insert("username".into(), json!(username));
        facts.insert(
            "minPinLength".into(),
            key.as_ref()
                .and_then(|k| k.get("minPinLength").cloned())
                .unwrap_or(Json::Null),
        );
        if let Some(Json::Bool(be)) = credential.get("backupEligible") {
            facts.insert("backupEligible".into(), json!(be));
        }
        if let Some(k) = &key {
            let a = Credentials::key_algorithm(k);
            facts.insert("algorithm".into(), a["name"].clone());
            facts.insert("lane".into(), a["lane"].clone());
        } else if js::truthy_opt(credential.get("algorithm")) {
            facts.insert(
                "algorithm".into(),
                json!(js::string_or_empty(credential.get("algorithm"))),
            );
            facts.insert(
                "lane".into(),
                json!(js::string_or(credential.get("lane"), "classical")),
            );
        }
        self.rules.refusal_for("sign-in", &Json::Object(facts))
    }

    /// `recoveryRefusalAtSession(username, credential)`.
    #[tracing::instrument(level = "debug", skip(self, credential))]
    fn recovery_refusal_at_session(
        &self,
        username: &str,
        credential: &Json,
    ) -> Option<Json> {
        let registered = kind_of(credential) == "webauthn"
            && js::string_or(credential.get("ceremony"), "") == "registration";
        let kind = if registered {
            "webauthn-registration".to_string()
        } else {
            kind_of(credential)
        };
        let door = recovery_door_of(&kind);
        let pending = self.credentials.recovery_pending(username);
        if pending.is_none() && door.is_empty() {
            return None;
        }
        self.rules.recovery_refusal(&json!({ "username": username,
            "door": door, "at": "session", "credential": kind,
            "covered": self.credentials.holds_passkey(username),
            "pending": pending.is_some() }))
    }

    /// `noteAlgorithmMismatch(username, credential, via)`: evidence, never
    /// the sign-in.
    #[tracing::instrument(level = "debug", skip(self, credential, via))]
    fn note_algorithm_mismatch(
        &self,
        username: &str,
        credential: &Json,
        via: &Json,
    ) {
        let (key, keys) = self.key_of(username, credential);
        let used = match &key {
            Some(k) => js::string(&Credentials::key_algorithm(k)["name"]),
            None => js::string_or(credential.get("algorithm"), ""),
        };
        let held: Vec<Json> = keys
            .iter()
            .map(|k| Credentials::key_algorithm(k)["name"].clone())
            .collect();
        let row = json!({ "username": username, "used": used, "held": held,
            "required": self.rules.requires_post_quantum("sign-in"),
            "door": js::string_or(Some(via), "") });
        if let Err(e) = self.rules.algorithm_mismatch(&row) {
            tracing::debug!("Caught in note_algorithm_mismatch(): {}", e);
        }
    }

    /// `notePasskeyStanding(username, credential, refusal)`: marked on the
    /// key's row the first time per key and reason, and only then a CAEP
    /// credential-change by `policy`.
    #[tracing::instrument(level = "debug", skip(self, credential, refusal))]
    fn note_passkey_standing(
        &self,
        username: &str,
        credential: &Json,
        refusal: &Json,
    ) {
        let id = js::string_or(credential.get("id"), "");
        let (key, _) = self.key_of(username, credential);
        let Some(key) = key else {
            return;
        };
        let why = js::string_or_empty(refusal.get("why"));
        if !self.credentials.note_key_policy_refused(
            username,
            &id,
            &js::string_or_empty(refusal.get("reason")),
            &js::string_or_empty(refusal.get("code")),
            &why,
        ) {
            return;
        }
        self.rules.credential_changed(&json!({ "username": username,
            "credentialType": key_credential_type(&key),
            "fido2Aaguid": crate::evidence::aaguid_string(
                &js::string_or(key.get("aaguid"), "")),
            "friendlyName": js::string_or(key.get("label"), ""),
            "changeType": "update", "initiatingEntity": "policy",
            "via": "sign-in",
            "reasonAdmin": format!("A passkey of {username} no longer meets \
                                    this realm's passkey policy: {why}"),
            "reasonUser": "One of your passkeys no longer meets this \
                           service's rules and cannot sign you in." }));
    }

    /// `recoveryCompleted(username, detail)`: a passkey ASSERTION after a
    /// recovery clears it, with an audit row.
    #[tracing::instrument(level = "debug", skip(self, detail))]
    fn recovery_completed(&self, username: &str, detail: &Json) {
        let credential = detail.get("credential").filter(|c| js::truthy(c));
        let Some(credential) = credential else {
            return;
        };
        if kind_of(credential) != "webauthn"
            || js::string_or(credential.get("ceremony"), "assertion")
                != "assertion"
        {
            return;
        }
        let Some(pending) = self.credentials.recovery_pending(username) else {
            return;
        };
        self.credentials.set_recovery_pending(username, "");
        let door = js::string(&pending["door"]);
        self.rules
            .audit(&json!({ "action": "authn.recovery.completed",
            "actor": username, "target": username, "channel": "http",
            "outcome": "success",
            "summary": format!("a passkey signed {username} in after an \
                                account recovery ({door}); the recovery is \
                                complete"),
            "detail": { "door": door, "since": pending["at"],
                        "application": js::string_or(detail.get("application"),
                                                     "") } }));
        tracing::info!(
            "authn: a passkey signed \"{}\" in after the recovery through {}; \
             it is no longer pending.",
            username,
            door
        );
    }
}
