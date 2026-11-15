// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! PEOPLE AND GROUPS: the account state (`common/account_state.ts`, rule
//! 3at), and the `/admin-api/users` and `/admin-api/groups` acts that make
//! a person, switch an account and write a group
//! (`admin-core/admin_actions.ts`'s `usersAction()` and `groupsAction()`).
//!
//! **A DISABLED ACCOUNT HAS ONE PLACE** (3at): `pwdAccountLockedTime` on
//! the person's entry, written through [`Credentials`] by the console, the
//! API and SCIM alike, and a disable ENDS everything the person holds
//! through the same global sign-out ([`Logout`]). Enabling brings nothing
//! back.
//!
//! **A PERSON IS AN ENTRY** (`users/create`): the directory's writer makes
//! it, with the attributes the caller typed and — unless `invent` is off —
//! the invented person behind the name; then the credential the caller
//! chose. A person whose credential failed still EXISTS, and the answer
//! says so rather than refusing. The password's rules are the password
//! policy's (the policy slice), behind [`Credentials`].
//!
//! **A GROUP GRANTS NOTHING BY BEING A GROUP** (`common/CLAUDE.md` 3d-ii):
//! the answer to every group create says so. The group acts are the
//! directory's writer's; this layer only reads the body and keeps the
//! writer's code. `add-member` here is idempotent (`changed: false`) where
//! a role's is not.

use std::sync::Arc;

use serde_json::{json, Map, Value};
use sts_core::errors::{codes, ErrorCode};

use crate::js;
use crate::outcome::Outcome;
use crate::port::*;

/// `USERS_ACTIONS`, in Node's order.
pub const USERS_ACTIONS: [&str; 55] = [
    "create",
    "set-password",
    "issue-activation",
    "clear-totp",
    "clear-key",
    "clear-backup-codes",
    "rename-key",
    "clear-email-factor",
    "set-mail",
    "set-pseudonyms",
    "set-aud-sub",
    "reset-password",
    "issue-password-reset",
    "disable-primary-keys",
    "disable-mfa",
    "require-mfa",
    "stop-requiring-mfa",
    "disable",
    "enable",
    "federation-link",
    "federation-unlink",
    "create-app-password",
    "revoke-app-password",
    "set-not-delegated",
    "set-may-act",
    "set-delegation-semantics",
    "record-verification",
    "remove-verification",
    "enrol-self-issued-subject",
    "remove-self-issued-subject",
    "set-preferred-self-issued-subject",
    "deactivate-published-did",
    "remove-device",
    "answer-ciba-request",
    "set-attribute",
    "add-attribute",
    "remove-attribute",
    "update-fields",
    "set-service-account",
    "rotate-password",
    "add-service-account-owner",
    "remove-service-account-owner",
    "set-service-account-destination",
    "begin-passkey-upgrade",
    "prove-passkey-upgrade",
    "finish-passkey-upgrade",
    "cancel-passkey-upgrade",
    "begin-passkey-enrolment",
    "finish-passkey-enrolment",
    "add-certificate",
    "remove-certificate",
    "issue-signing-certificate",
    "revoke-signing-certificate",
    "export-ldif",
    "import-ldif",
];

/// `DEFAULT_CREDENTIAL`.
pub const DEFAULT_CREDENTIAL: &str = "generate";

/// `USER_FIELD_PREFIX`.
pub const USER_FIELD_PREFIX: &str = "field.";

fn refused(code: ErrorCode, errors: Vec<String>) -> Outcome {
    Outcome::marked(code, json!({"ok": false, "errors": errors}))
}

/// `refusedBy(code, result)`: the owner's code wins.
fn refused_by(code: ErrorCode, result: Marked) -> Outcome {
    Outcome {
        code: Some(result.code.unwrap_or(code)),
        answer: result.value,
    }
}

/// `encodeURIComponent(text)`.
#[tracing::instrument(level = "debug")]
pub fn encode_uri_component(text: &str) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        let keep = b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
            );
        if keep {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `AdminActions.truthy(value)`: `true`, or `true`/`yes`/`on`/`1` as text.
#[tracing::instrument(level = "debug", skip_all)]
pub fn form_truthy(value: Option<&Value>) -> bool {
    if value == Some(&Value::Bool(true)) {
        return true;
    }
    let text = js::lower(js::trim(&js::unless_null(value)));
    matches!(text.as_str(), "true" | "yes" | "on" | "1")
}

/// `userFieldsFrom(body)`: `attributes`, then each `field.<name>` (and
/// `field.<name>.<n>` for a value of a multi-valued attribute).
#[tracing::instrument(level = "debug", skip_all)]
pub fn user_fields_from(body: &Value) -> Map<String, Value> {
    let mut fields = Map::new();
    if let Some(given) = body.get("attributes").and_then(Value::as_object) {
        for (k, v) in given {
            fields.insert(k.clone(), v.clone());
        }
    }
    let Some(map) = body.as_object() else {
        return fields;
    };
    for (key, raw) in map {
        let Some(name) = key.strip_prefix(USER_FIELD_PREFIX) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let value = js::trim(&js::string(raw)).to_string();
        let boxed = name.rsplit_once('.').filter(|(head, n)| {
            !head.is_empty()
                && !n.is_empty()
                && n.chars().all(|c| c.is_ascii_digit())
        });
        if let Some((head, _)) = boxed {
            if !value.is_empty() {
                let mut held = match fields.get(head) {
                    Some(Value::Array(list)) => list.clone(),
                    None => Vec::new(),
                    Some(other) => vec![other.clone()],
                };
                held.push(json!(value));
                fields.insert(head.to_string(), Value::Array(held));
            }
            continue;
        }
        if !value.is_empty() {
            fields.insert(name.to_string(), json!(value));
        }
    }
    fields
}

/// The account state.
pub struct AccountState {
    credentials: Arc<dyn Credentials>,
    keys: Arc<dyn IdentityKeys>,
    logout: Option<Arc<dyn Logout>>,
    effects: Arc<dyn AccountEffects>,
    audit: Arc<dyn Audit>,
}

/// The options of a disable or enable (`setDisabled()`'s `opts`).
#[derive(Debug, Clone, Default)]
pub struct AccountChange {
    pub actor: String,
    /// `api` from `/admin-api`, else the console.
    pub via: String,
    pub reason: String,
    pub risc_reason: String,
    /// A door that is not an administrator (risk scoring, a policy).
    pub door: String,
    pub by: String,
    pub initiating_entity: String,
}

impl AccountChange {
    /// From Node's `opts` object.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn from_json(o: &Value) -> AccountChange {
        let f = |k: &str| js::or_empty(o.get(k));
        AccountChange {
            actor: f("actor"),
            via: f("via"),
            reason: f("reason"),
            risc_reason: f("riscReason"),
            door: f("door"),
            by: f("by"),
            initiating_entity: f("initiatingEntity"),
        }
    }
}

impl AccountState {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(
        credentials: Arc<dyn Credentials>,
        keys: Arc<dyn IdentityKeys>,
        logout: Option<Arc<dyn Logout>>,
        effects: Arc<dyn AccountEffects>,
        audit: Arc<dyn Audit>,
    ) -> AccountState {
        AccountState {
            credentials,
            keys,
            logout,
            effects,
            audit,
        }
    }

    fn key_of(&self, who: &str) -> String {
        let text = js::trim(who);
        if text.is_empty() {
            return String::new();
        }
        match self.keys.identity_key_of(text) {
            k if k.is_empty() => text.to_string(),
            k => k,
        }
    }

    /// `isDisabled(who)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn is_disabled(&self, who: &str) -> bool {
        let raw = js::trim(who);
        if raw.is_empty() || raw == "anonymous" {
            return false;
        }
        self.credentials.account_disabled(raw) || {
            let key = self.key_of(raw);
            key != raw && self.credentials.account_disabled(&key)
        }
    }

    /// `endEverything(who, opts)`: the global sign-out, for a disable.
    fn end_everything(&self, who: &str, o: &Value) -> Value {
        let Some(logout) = self.logout.as_ref() else {
            return json!({"ended": false, "terminated": 0, "backchannel": [],
                "message": "No sign-out module is loaded in this process, \
                    so nothing the person held was ended here."});
        };
        let get = |k: &str, d: &str| match js::or_empty(o.get(k)) {
            v if v.is_empty() => d.to_string(),
            v => v,
        };
        let result = logout.terminate(
            &self.key_of(who),
            &json!([]),
            &json!({
                "actor": get("actor", ""),
                "channel": get("channel", "internal"),
                "by": get("by", "an administrator disabling the account"),
                "initiatingEntity": get("initiatingEntity", "admin"),
                "providerCommand": false,
            }),
        );
        let count = |k: &str| {
            result.get(k).and_then(Value::as_array).map_or(0, Vec::len)
        };
        json!({
            "ended": true,
            "terminated": count("terminated"),
            "skipped": count("skipped"),
            "notifications": count("notifications"),
            "backchannel": result.get("backchannel").cloned()
                .filter(|b| !b.is_null()).unwrap_or(json!([])),
            "message": js::or_empty(result.get("message")),
        })
    }

    /// `setDisabled(who, disabled, opts)`.
    #[tracing::instrument(level = "debug", skip(self, o))]
    pub fn set_disabled(
        &self,
        who: &str,
        disabled: bool,
        o: &AccountChange,
    ) -> Outcome {
        let name = js::trim(who).to_string();
        if name.is_empty() {
            return refused(
                codes::STS_ADMIN_0792,
                vec![format!(
                    "Name the person to {}.",
                    if disabled { "disable" } else { "enable" }
                )],
            );
        }
        if name == "anonymous" {
            return refused(
                codes::STS_ADMIN_0792,
                vec!["The anonymous principal is not an account and cannot \
                      be disabled; turn authn.unauthenticatedSessions off \
                      instead."
                    .to_string()],
            );
        }
        let was = self.is_disabled(&name);
        let door = if !o.door.is_empty() {
            o.door.clone()
        } else if o.via == "api" {
            "/admin-api/users".to_string()
        } else {
            "the admin console".to_string()
        };
        if was == disabled {
            return Outcome::ok(json!({
                "ok": true, "username": name, "disabled": disabled,
                "changed": false,
                "message": format!("{name} is already {}; nothing was \
                    changed.", if disabled { "disabled" } else { "enabled" }),
            }));
        }
        let written = self.credentials.set_account_disabled(
            &name,
            disabled,
            &json!({"riscReason": o.risc_reason}),
        );
        if !written.value.get("ok").is_some_and(js::truthy) {
            return Outcome {
                answer: written.value,
                code: written.code,
            };
        }
        if disabled {
            self.effects.note_revoking_write("an account disabled");
        }
        let ended = if disabled {
            let by = if !o.by.is_empty() {
                o.by.clone()
            } else if !o.door.is_empty() {
                format!("{door} disabling the account")
            } else {
                format!("an administrator disabling the account ({door})")
            };
            let initiating = if !o.initiating_entity.is_empty() {
                o.initiating_entity.clone()
            } else if !o.door.is_empty() {
                "policy".to_string()
            } else {
                "admin".to_string()
            };
            Some(self.end_everything(
                &name,
                &json!({
                    "actor": o.actor,
                    "channel": if o.via.is_empty() { "http" } else { &o.via },
                    "initiatingEntity": initiating, "by": by,
                }),
            ))
        } else {
            None
        };
        let terminated = ended
            .as_ref()
            .map(|e| js::string(&e["terminated"]))
            .unwrap_or_default();
        let back_count = ended
            .as_ref()
            .and_then(|e| e["backchannel"].as_array().map(Vec::len))
            .unwrap_or(0);
        self.audit.audit(&json!({
            "action": if disabled { "account.disable" } else {
                "account.enable" },
            "actor": o.actor,
            "channel": if o.via == "api" { "api" } else { "http" },
            "protocol": "Directory",
            "target": name,
            "summary": format!("{name}'s account was {} from {door}{}",
                if disabled { "DISABLED" } else { "enabled" },
                match &ended {
                    Some(_) => format!("; {terminated} live item(s) were \
                        ended"),
                    None => String::new(),
                }),
            "detail": {
                "username": name,
                "attribute": "pwdAccountLockedTime",
                "reason": o.reason,
                "ended": terminated,
                "backchannel": if ended.is_some() {
                    back_count.to_string()
                } else {
                    String::new()
                },
            },
        }));
        tracing::info!(
            "account state: {name} was {} from {door}.",
            if disabled { "DISABLED" } else { "enabled" }
        );
        if disabled {
            self.effects.mail_account_disabled(
                &name,
                &o.reason,
                !o.door.is_empty(),
            );
        }
        let message = if disabled {
            let e = ended.clone().unwrap_or(Value::Null);
            let said = if e.get("ended").is_some_and(js::truthy) {
                format!(
                    "{terminated} live item(s) they held were ended{}. \
                     Front-channel notifications need the person's own \
                     browser and are not sent from here.",
                    if back_count > 0 {
                        format!(
                            ", with {back_count} back-channel Logout \
                                 Token(s) queued"
                        )
                    } else {
                        String::new()
                    }
                )
            } else {
                format!(
                    "nothing they held could be ended here: {}",
                    js::or_empty(e.get("message"))
                )
            };
            format!(
                "{name} is disabled: every door refuses them from now on, \
                 and {said} RISC receivers are told account-disabled."
            )
        } else {
            format!(
                "{name} is enabled again. Nothing they held before the \
                 disable comes back; they sign in afresh. RISC receivers are \
                 told account-enabled."
            )
        };
        Outcome::ok(json!({
            "ok": true, "username": name, "disabled": disabled,
            "changed": true, "ended": ended, "message": message,
        }))
    }
}

/// The ports `usersAction()` and `groupsAction()` reach.
pub struct PeopleDeps {
    pub people: Option<Arc<dyn PersonWriter>>,
    pub groups: Option<Arc<dyn GroupWriter>>,
    pub credentials: Arc<dyn Credentials>,
    pub service_accounts: Arc<dyn ServiceAccounts>,
    pub signals: Arc<dyn AccountSignals>,
    pub mailer: Arc<dyn LinkMailer>,
    pub mode: Arc<dyn Mode>,
    pub audit: Arc<dyn Audit>,
}

/// The users and groups acts.
pub struct People {
    deps: PeopleDeps,
    accounts: Arc<AccountState>,
}

impl People {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(deps: PeopleDeps, accounts: Arc<AccountState>) -> People {
        People { deps, accounts }
    }

    /// `usersAction(body, context)` for the actions this crate ports:
    /// `create`, `disable`, `enable`, and the refusal of an unknown one.
    /// `None` for an action Node has that is not ported here.
    #[tracing::instrument(level = "debug", skip(self, body))]
    pub fn users(
        &self,
        body: &Value,
        via: &str,
        actor: &str,
    ) -> Option<Outcome> {
        let action = js::or_empty(body.get("action"));
        match action.as_str() {
            "create" => Some(self.create_user(body, via, actor)),
            "disable" | "enable" => {
                Some(self.switch(body, action == "disable", via, actor))
            }
            "set-pseudonyms" => Some(self.set_pseudonyms(body, via, actor)),
            known if USERS_ACTIONS.contains(&known) => None,
            _ => Some(refused(
                codes::STS_ADMIN_0500,
                vec![format!(
                    "Unknown action \"{action}\". The {} are: {}.",
                    js::number_word(USERS_ACTIONS.len()),
                    USERS_ACTIONS.join(", ")
                )],
            )),
        }
    }

    fn switch(
        &self,
        body: &Value,
        disable: bool,
        via: &str,
        actor: &str,
    ) -> Outcome {
        let who = js::trim(&match js::or_empty(body.get("user")) {
            u if u.is_empty() => js::or_empty(body.get("username")),
            u => u,
        })
        .to_string();
        if who.is_empty() {
            return refused(
                codes::STS_ADMIN_0518,
                vec!["Name the person in `user`.".to_string()],
            );
        }
        let risc = js::unless_null(body.get("riscReason"));
        if !risc.is_empty() && risc != "hijacking" && risc != "bulk-account" {
            return refused(
                codes::STS_ADMIN_0794,
                vec![format!(
                    "\"{risc}\" is not a reason RISC account-disabled \
                     carries; it is hijacking or bulk-account (RISC 1.0 \
                     section 2.2), or none."
                )],
            );
        }
        let answer = self.accounts.set_disabled(
            &who,
            disable,
            &AccountChange {
                actor: actor.to_string(),
                via: via.to_string(),
                reason: js::or_empty(body.get("reason")),
                risc_reason: risc,
                ..AccountChange::default()
            },
        );
        if !answer.is_ok() {
            let errors = answer
                .answer
                .get("errors")
                .filter(|e| js::truthy(e))
                .cloned()
                .unwrap_or_else(|| {
                    json!([format!(
                        "The account could not be {}d.",
                        if disable { "disable" } else { "enable" }
                    )])
                });
            return Outcome::marked(
                answer.code.unwrap_or(codes::STS_ADMIN_0793),
                json!({"ok": false, "errors": errors}),
            );
        }
        let a = &answer.answer;
        Outcome::ok(json!({
            "ok": true, "username": who, "disabled": a["disabled"],
            "changed": a["changed"],
            "ended": a.get("ended").cloned().unwrap_or(Value::Null),
            "message": a["message"],
        }))
    }

    /// `usersAction()`'s `set-pseudonyms`: the person and EXACTLY ONE of
    /// `add`, `remove` or `cancelPending`, written by the directory
    /// (`writePseudonyms()`, `source: admin`, so an address is live at
    /// once). Audited either way.
    ///
    /// A refusal from the directory is answered as Node answers it, in ONE
    /// sentence whatever the directory's reason — no person, a shape the
    /// rules refuse, a name another person answers to — and STS-ADMIN-0909:
    /// the writer's own code and sentence are not carried (a Node defect,
    /// ported as it is).
    fn set_pseudonyms(&self, body: &Value, via: &str, actor: &str) -> Outcome {
        let who = js::trim(&match js::or_empty(body.get("user")) {
            u if u.is_empty() => js::or_empty(body.get("username")),
            u => u,
        })
        .to_string();
        let has = |k: &str| body.get(k).is_some();
        let (has_add, has_remove, has_cancel) =
            (has("add"), has("remove"), has("cancelPending"));
        let picked = [has_add, has_remove, has_cancel]
            .iter()
            .filter(|b| **b)
            .count();
        let text = |k: &str| match body.get(k) {
            None | Some(Value::Null) => String::new(),
            Some(v) => js::trim(&js::string(v)).to_string(),
        };
        let add = text("add");
        let remove = text("remove");
        let cancel = text("cancelPending").to_lowercase();
        let cancel_yes = ["true", "on", "1", "yes"].contains(&cancel.as_str());
        if who.is_empty()
            || picked != 1
            || (has_add && add.is_empty())
            || (has_remove && remove.is_empty())
            || (has_cancel && !cancel_yes)
        {
            return refused(
                codes::STS_ADMIN_0908,
                vec!["Name the person and exactly one of add, remove or \
                      cancelPending."
                    .to_string()],
            );
        }
        let (op, value) = if has_add {
            ("add", add)
        } else if has_remove {
            ("remove", remove)
        } else {
            ("cancel", String::new())
        };
        let written = match self.deps.people.as_ref() {
            Some(writer) => writer.write_pseudonyms(&who, op, &value, "admin"),
            None => Value::Null,
        };
        let ok = written.get("ok") == Some(&Value::Bool(true));
        let names = if ok {
            written.get("pseudonyms").cloned().unwrap_or(json!([]))
        } else {
            json!([])
        };
        let email = !value.is_empty()
            && self
                .deps
                .people
                .as_ref()
                .is_some_and(|w| w.is_email(&value));
        self.deps.audit.record(&json!({
            "category": "admin", "action": "admin.pseudonym.set",
            "actor": actor, "target": who,
            "outcome": if ok { "success" } else { "failure" },
            "summary": format!("{} the sign-in names of {who}",
                if ok { "changed" } else { "could not change" }),
            "detail": { "username": who, "via": via, "op": op,
                        "length": names.as_array().map_or(0, Vec::len),
                        "email": email },
        }));
        if !ok {
            return refused(
                codes::STS_ADMIN_0909,
                vec![format!(
                    "There is no person called \"{who}\" in this realm, or \
                     the directory would not write the name."
                )],
            );
        }
        // `written.pending === true ? null : (written.pending || null)`.
        let pending = match written.get("pending") {
            Some(Value::Bool(true)) | None | Some(Value::Null) => Value::Null,
            Some(v) if !js::truthy(v) => Value::Null,
            Some(v) => v.clone(),
        };
        Outcome::ok(json!({
            "ok": true, "pseudonyms": names, "pending": pending,
            "message": format!("The sign-in names of {who} were changed."),
        }))
    }

    fn create_user(&self, body: &Value, via: &str, actor: &str) -> Outcome {
        let d = &self.deps;
        let Some(writer) = d.people.as_ref() else {
            return refused(
                codes::STS_ADMIN_0501,
                vec!["No LDAP directory is loaded in this process, so there \
                      is nowhere to put a person. The rest of this page is \
                      unaffected — it reports what this service has seen, \
                      which does not come from the directory."
                    .to_string()],
            );
        };
        let username = js::trim(&match js::or_empty(body.get("username")) {
            u if u.is_empty() => js::or_empty(body.get("user")),
            u => u,
        })
        .to_string();
        let typed = user_fields_from(body);
        let invent = match body.get("invent") {
            None => true,
            v => form_truthy(v),
        };
        let as_service = form_truthy(body.get("serviceAccount"));
        let reference = match typed.get("stsServiceAccountPolicy") {
            Some(Value::Array(list)) => list.first().cloned(),
            other => other.cloned(),
        };
        let reference_text =
            reference.as_ref().map(js::string).unwrap_or_default();
        if let Some(refusal) = d.service_accounts.write_refusal(&json!({
            "stsServiceAccount": if as_service { "TRUE" } else { "" },
            "stsServiceAccountPolicy": reference_text,
        })) {
            return Outcome::marked(
                refusal.code,
                json!({"ok": false, "errors": [refusal.message]}),
            );
        }
        if as_service {
            let mut asked = body.clone();
            if let Some(map) = asked.as_object_mut() {
                map.insert("policy".into(), json!(reference_text));
            }
            let pre = d.service_accounts.check(&asked, "");
            if pre.value.get("ok") != Some(&Value::Bool(true)) {
                return refused_by(codes::STS_SVCACCT_0027, pre);
            }
        }
        let note = js::trim(&js::or_empty(body.get("note"))).to_string();
        let result = writer.create_user(
            &username,
            &json!({
                "origin": "console",
                "note": if note.is_empty() {
                    "created by hand on the admin console rather than by \
                     authenticating".to_string()
                } else {
                    note
                },
                "channel": "console",
                "attributes": Value::Object(typed),
                "invent": invent,
                "requiredExempt": if as_service { "service account" } else {
                    "" },
            }),
        );
        if !result.value.get("ok").is_some_and(js::truthy) {
            return refused_by(codes::STS_ADMIN_0526, result);
        }
        let r = &result.value;
        let user = js::unless_null(r.get("username"));
        let dn = js::unless_null(r.get("dn"));
        let credential = match js::trim(&js::or_empty(body.get("credential"))) {
            "" => DEFAULT_CREDENTIAL.to_string(),
            c => c.to_string(),
        };
        let typed_names = r
            .get("typed")
            .filter(|t| js::truthy(t))
            .cloned()
            .unwrap_or(json!([]));
        let invented = r.get("invented").is_some_and(js::truthy);
        let mut answer = Map::new();
        answer.insert("ok".into(), json!(true));
        answer.insert("dn".into(), json!(dn));
        answer.insert("username".into(), json!(user));
        if let Some(entry) = r.get("entry").filter(|e| !e.is_null()) {
            answer.insert("entry".into(), entry.clone());
        }
        answer.insert("typed".into(), typed_names.clone());
        answer.insert("invented".into(), json!(invented));
        answer.insert("credential".into(), json!(credential));
        let mut said = String::new();
        let mut error = String::new();
        if as_service {
            let mut change = json!({"serviceAccount": true});
            if let Some(map) = change.as_object_mut() {
                for k in ["owners", "destination", "secretName"] {
                    if let Some(v) = body.get(k) {
                        map.insert(k.into(), v.clone());
                    }
                }
            }
            let flagged = d.service_accounts.set(&user, &change);
            let ok = flagged.get("ok").is_some_and(js::truthy);
            answer.insert("serviceAccount".into(), json!(ok));
            if !ok {
                let errors: Vec<String> = flagged
                    .get("errors")
                    .and_then(Value::as_array)
                    .map(|e| e.iter().map(js::string).collect())
                    .unwrap_or_default();
                answer.insert(
                    "serviceAccountError".into(),
                    json!(errors.join(" ")),
                );
            } else {
                let owners: Vec<Value> = flagged
                    .get("account")
                    .and_then(|a| a.get("owners"))
                    .and_then(Value::as_array)
                    .map(|l| l.iter().map(|o| o["dn"].clone()).collect())
                    .unwrap_or_default();
                d.audit.record(&json!({
                    "category": "admin",
                    "action": "admin.service-account.set",
                    "actor": actor, "target": user, "outcome": "success",
                    "summary": format!("{user} was created as a service \
                        account"),
                    "detail": {"owners": owners,
                        "destination": js::or_empty(body.get("destination")),
                        "via": via},
                }));
            }
        }
        if credential == "password" || credential == "generate" {
            let generated = credential == "generate";
            let typed_password = js::or_empty(body.get("password"));
            let confirm = body.get("passwordConfirm");
            if !generated && typed_password.is_empty() {
                error = "No password was sent, so none was set.".to_string();
            } else if !generated
                && confirm.is_some()
                && js::unless_null(confirm) != typed_password
            {
                error = "The two passwords do not match, so none was set."
                    .to_string();
            } else {
                let password = if generated {
                    d.credentials.generate_password(&user)
                } else {
                    typed_password
                };
                let set = d.credentials.set_password(
                    &user,
                    &password,
                    &json!({"generated": generated}),
                );
                if !set.get("ok").is_some_and(js::truthy) {
                    let errors: Vec<String> = set
                        .get("errors")
                        .and_then(Value::as_array)
                        .map(|e| e.iter().map(js::string).collect())
                        .unwrap_or_default();
                    error = errors.join(" ");
                } else {
                    d.audit.record(&json!({
                        "category": "authentication", "action": "password.set",
                        "actor": actor, "target": user, "outcome": "success",
                        "summary": format!("a password was set for {user} as \
                            they were created"),
                        "detail": {"generated": generated},
                    }));
                    d.signals.credential_changed(&json!({
                        "username": user, "credentialType": "password",
                        "changeType": "create", "initiatingEntity": "admin",
                        "via": via,
                        "reasonAdmin": format!("An administrator set a \
                            password for {user} as they were created."),
                        "reasonUser": "A password was set for your new \
                            account.",
                    }));
                    answer.insert("passwordSet".into(), json!(true));
                    answer.insert("generated".into(), json!(generated));
                    if generated {
                        if d.mode.verifies_credentials() {
                            d.credentials
                                .set_password_reset_required(&user, true);
                        }
                        answer.insert("password".into(), json!(password));
                        said = " A password has been GENERATED for them and \
                            is shown once: this service stores a scrypt hash \
                            and cannot produce it again, only replace it."
                            .to_string();
                    } else {
                        said = " The password you typed is set, stored as a \
                            scrypt hash, and cannot be shown again by anybody \
                            including this console."
                            .to_string();
                    }
                }
            }
        } else if credential == "activation" {
            let issued = d.credentials.issue_activation(&user);
            if !issued.get("ok").is_some_and(js::truthy) {
                let errors: Vec<String> = issued
                    .get("errors")
                    .and_then(Value::as_array)
                    .map(|e| e.iter().map(js::string).collect())
                    .unwrap_or_default();
                error = errors.join(" ");
            } else {
                let expires = js::unless_null(issued.get("expiresAt"));
                let token = js::unless_null(issued.get("token"));
                d.audit.record(&json!({
                    "category": "authentication",
                    "action": "activation.issued",
                    "actor": actor, "target": user, "outcome": "success",
                    "summary": format!("an activation link was issued for \
                        {user} as they were created"),
                    "detail": {"expiresAt": issued.get("expiresAt")},
                }));
                answer.insert("expiresAt".into(), json!(expires));
                let mailed = d.mailer.mailed_link(
                    "activation",
                    &user,
                    &token,
                    body,
                    actor,
                    "the new user screen",
                );
                if mailed.get("ok").is_some_and(js::truthy) {
                    let to = js::unless_null(mailed.get("mailedTo"));
                    answer.insert("mailedTo".into(), json!(to));
                    said = format!(
                        " They have NO credential and an activation link \
                         instead, valid until {expires}, which was MAILED to \
                         {to} and is not shown here."
                    );
                } else {
                    answer.insert(
                        "activationUrl".into(),
                        json!(format!(
                            "/portal/activate?user={}#token={}",
                            encode_uri_component(&user),
                            encode_uri_component(&token)
                        )),
                    );
                    let mut lead = String::new();
                    if js::truthy(&mailed) {
                        let errors: Vec<String> = mailed
                            .get("errors")
                            .and_then(Value::as_array)
                            .map(|e| e.iter().map(js::string).collect())
                            .unwrap_or_default();
                        let joined = errors.join(" ");
                        answer.insert("mailError".into(), json!(joined));
                        lead = format!(" THE LINK WAS NOT MAILED: {joined}");
                    }
                    said = format!(
                        "{lead} They have NO credential and an activation \
                         link instead, valid until {expires} and shown once. \
                         They choose a password, a security key or both at \
                         it; nothing about this account is decided until \
                         they do."
                    );
                }
            }
        } else if credential != "none" {
            error = format!(
                "Unknown credential option \"{credential}\". The four are: \
                 none, password, generate, activation. Nothing was set."
            );
        }
        if !error.is_empty() {
            answer.insert("credentialError".into(), json!(error));
            said = format!(
                " THE PERSON EXISTS AND HAS NO CREDENTIAL: {error} Set one \
                 from their row on Users rather than creating them again — \
                 the name is taken now, by this entry."
            );
        }
        let count = typed_names.as_array().map_or(0, Vec::len);
        let held = if invented {
            format!(
                ", with the invented person behind that name written onto it \
                 — so a credential issued for {user} and an ldapsearch for \
                 that entry say the same thing."
            )
        } else {
            format!(
                ", carrying {}. Nothing was invented for it.",
                if count > 0 {
                    format!(
                        "the {count} attribute(s) you typed and nothing \
                             else"
                    )
                } else {
                    "no attributes at all beyond its object classes and its \
                     uid"
                    .to_string()
                }
            )
        };
        answer.insert(
            "message".into(),
            json!(format!(
                "{dn} now exists in the directory{held}{said} They will NOT \
                 appear in the table on the Users page until they \
                 authenticate somewhere: that list is who this service has \
                 seen, and the entry is what the directory HOLDS."
            )),
        );
        Outcome::ok(Value::Object(answer))
    }

    /// `groupsAction(body, context)`.
    #[tracing::instrument(level = "debug", skip(self, body))]
    pub fn groups(&self, body: &Value, actor: &str) -> Outcome {
        let Some(writer) = self.deps.groups.as_ref() else {
            return refused(
                codes::STS_ADMIN_0501,
                vec!["No LDAP directory is loaded in this process, so there \
                      is nowhere to put a group. The rest of this page is \
                      unaffected — if it is showing you groups, they are \
                      being read through a different slot and only the \
                      writes are missing."
                    .to_string()],
            );
        };
        let field = |k: &str| js::trim(&js::or_empty(body.get(k))).to_string();
        let options = json!({"origin": "console", "channel": "console",
                             "actor": actor});
        let action = js::or_empty(body.get("action"));
        match action.as_str() {
            "create" => {
                let name = match field("group") {
                    g if g.is_empty() => field("displayName"),
                    g => g,
                };
                let listed: Vec<String> = match body.get("members") {
                    Some(Value::Array(items)) => {
                        items.iter().map(|v| js::unless_null(Some(v))).collect()
                    }
                    other => js::unless_null(other)
                        .split(['\r', '\n', ','])
                        .map(str::to_string)
                        .collect(),
                };
                let members: Vec<String> = listed
                    .iter()
                    .map(|one| js::trim(one).to_string())
                    .filter(|one| !one.is_empty())
                    .collect();
                let note = field("note");
                let result = writer.create_group(
                    &name,
                    &json!({
                        "origin": "console",
                        "note": if note.is_empty() {
                            "created by hand on the admin console rather \
                             than by a directory client".to_string()
                        } else {
                            note
                        },
                        "channel": "console", "actor": actor,
                        "members": members, "mail": field("mail"),
                    }),
                );
                if !result.value.get("ok").is_some_and(js::truthy) {
                    return refused_by(codes::STS_ADMIN_0527, result);
                }
                let mut answer = result.value.clone();
                let dn = js::unless_null(answer.get("dn"));
                let count = answer
                    .get("members")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len);
                let listing = if count > 0 {
                    format!(", listing {count} member(s)")
                } else {
                    " with no members at all — an empty groupOfNames is \
                     something a real directory refuses (RFC 4519 makes \
                     `member` MUST) and this one has no schema, so it is \
                     here because you asked for it"
                        .to_string()
                };
                if let Some(map) = answer.as_object_mut() {
                    map.insert(
                        "message".into(),
                        json!(format!(
                            "{dn} now exists{listing}. IT GRANTS NOTHING. No \
                         endpoint in this service checks a group, and the \
                         only two that decide anything are the console roles \
                         on /admin/rbac. What it does change is what a \
                         directory client sees and what the groups claim in \
                         an issued token says."
                        )),
                    );
                }
                Outcome {
                    answer,
                    code: result.code,
                }
            }
            "add-member" => {
                let member = ["member", "user", "username"]
                    .iter()
                    .map(|k| js::or_empty(body.get(*k)))
                    .find(|v| !v.is_empty())
                    .unwrap_or_default();
                let result = writer.add_group_member(
                    &field("group"),
                    js::trim(&member),
                    &options,
                );
                self.handed(result, codes::STS_ADMIN_0528)
            }
            "set-mail" => {
                let result = writer.set_group_mail(
                    &field("group"),
                    &field("mail"),
                    &options,
                );
                self.handed(result, codes::STS_ADMIN_0896)
            }
            "set-policy" => {
                let result = writer.set_group_policy(
                    &field("group"),
                    &field("attribute"),
                    &field("policy"),
                    &options,
                );
                self.handed(result, codes::STS_ADMIN_0907)
            }
            "add-owner" => {
                let result = writer.add_group_owner(
                    &field("group"),
                    &field("owner"),
                    &options,
                );
                self.handed(result, codes::STS_ADMIN_0852)
            }
            "remove-owner" => {
                let result = writer.remove_group_owner(
                    &field("group"),
                    &field("owner"),
                    &options,
                );
                self.handed(result, codes::STS_ADMIN_0853)
            }
            _ => refused(
                codes::STS_ADMIN_0500,
                vec![format!(
                    "Unknown action \"{action}\". The six are: create, \
                     add-member, set-mail, set-policy, add-owner, \
                     remove-owner. Removing a member is /admin/rbac for the \
                     two console roles, and an ldapmodify or a SCIM PATCH \
                     for every other group; deleting one is an ldapdelete or \
                     a SCIM DELETE."
                )],
            ),
        }
    }

    fn handed(&self, result: Marked, code: ErrorCode) -> Outcome {
        if !result.value.get("ok").is_some_and(js::truthy) {
            return refused_by(code, result);
        }
        Outcome {
            answer: result.value,
            code: result.code,
        }
    }
}
