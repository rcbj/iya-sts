// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE REPLAY: every port of the crate, answered from what Node's ports
//! answered in the same step (`tests/tools/registers-vectors.js`), and
//! every call Rust makes checked against the call Node made.
//!
//! A STATEFUL port method (a directory read or write, an audit row) is a
//! queue: Rust's n-th call of it must carry the n-th call's arguments, and
//! every recorded call must be made. A PURE one (a setting, a DN's
//! normal form, a property) is a lookup by arguments, made as often as the
//! code likes.

#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::collections::HashSet;
use std::sync::Mutex;

use serde_json::{json, Value};
use sts_core::errors::ErrorCode;
use sts_registers::port::*;

include!(concat!(env!("OUT_DIR"), "/code_named.rs"));

/// Port methods answered by lookup rather than by queue.
const PURE: &[&str] = &[
    "settings.value",
    "rbac.directory.usersDn",
    "rbac.directory.realmId",
    "rbac.directory.normalizeDn",
    "rbac.directory.nameUsableInDn",
    "rbac.directory.groupDnFor",
    "bootstrap.current",
    "mode.opensConsoleToAnyone",
    "mode.verifiesCredentials",
    "mode.refusesTokenForGoneSubject",
    "helpers.subjectIsGone",
    "helpers.nameForSubject",
    "stats.identityKeyOf",
    "applications.settingFor",
    "stats.RESERVED_JWT_CLAIMS",
    "stats.CLAIM_SET_IDS",
    "stats.DEFAULT_SAML11_NAMESPACE",
];

/// One step's recorded calls.
pub struct Replay {
    calls: Vec<Value>,
    used: Mutex<Vec<bool>>,
    pub problems: Mutex<Vec<String>>,
    /// Methods Rust does inline (pure functions ported into the crate):
    /// their recorded calls need not be made.
    inline: HashSet<String>,
    /// The role entries Rust wrote, for `registers-rust.json`.
    pub written: Mutex<Vec<Value>>,
}

impl Replay {
    pub fn new(step: &Value, inline: &[&str]) -> Replay {
        let calls = step["calls"].as_array().cloned().unwrap_or_default();
        let n = calls.len();
        Replay {
            calls,
            used: Mutex::new(vec![false; n]),
            problems: Mutex::new(Vec::new()),
            inline: inline.iter().map(|s| s.to_string()).collect(),
            written: Mutex::new(Vec::new()),
        }
    }

    fn key(row: &Value) -> String {
        format!(
            "{}.{}",
            row["port"].as_str().unwrap_or(""),
            row["method"].as_str().unwrap_or("")
        )
    }

    /// Whether Node called this port method in the step.
    pub fn has(&self, key: &str) -> bool {
        self.calls.iter().any(|row| Replay::key(row) == key)
    }

    fn problem(&self, text: String) {
        self.problems.lock().unwrap().push(text);
    }

    /// The recorded row Rust's call is answered from.
    pub fn call(&self, port: &str, method: &str, args: Value) -> Value {
        let key = format!("{port}.{method}");
        if PURE.contains(&key.as_str()) {
            let found = self
                .calls
                .iter()
                .find(|row| Replay::key(row) == key && row["args"] == args);
            if let Some(row) = found {
                return row.clone();
            }
            self.problem(format!("{key}{args}: Node never asked"));
            return json!({"answer": null});
        }
        let mut used = self.used.lock().unwrap();
        let at = (0..self.calls.len())
            .find(|&i| !used[i] && Replay::key(&self.calls[i]) == key);
        match at {
            Some(i) => {
                used[i] = true;
                let row = &self.calls[i];
                if row["args"] != args {
                    drop(used);
                    self.problem(format!(
                        "{key}: Rust sent {args}\n          Node sent {}",
                        row["args"]
                    ));
                }
                row.clone()
            }
            None => {
                drop(used);
                self.problem(format!("{key}{args}: one call more than Node"));
                json!({"answer": null})
            }
        }
    }

    pub fn answer(&self, port: &str, method: &str, args: Value) -> Value {
        self.call(port, method, args)["answer"].clone()
    }

    pub fn marked(&self, port: &str, method: &str, args: Value) -> Marked {
        let row = self.call(port, method, args);
        Marked {
            value: row["answer"].clone(),
            code: row["code"].as_str().and_then(code_named),
        }
    }

    /// Every queued call Node made that Rust did not.
    pub fn finish(&self) -> Vec<String> {
        let used = self.used.lock().unwrap();
        let mut out = self.problems.lock().unwrap().clone();
        for (i, row) in self.calls.iter().enumerate() {
            let key = Replay::key(row);
            if !used[i]
                && !PURE.contains(&key.as_str())
                && !self.inline.contains(&key)
            {
                out.push(format!("{key}{}: Node called, Rust did not", row["args"]));
            }
        }
        out
    }
}

pub fn code_text(code: Option<ErrorCode>) -> Value {
    match code {
        Some(c) => json!(c.as_str()),
        None => Value::Null,
    }
}

impl Settings for Replay {
    fn value(&self, key: &str) -> Value {
        self.answer("settings", "value", json!([key]))
    }
}

impl RoleDirectory for Replay {
    fn all_roles(&self) -> Vec<Value> {
        let a = self.answer("roles.directory", "allRoles", json!([]));
        a.as_array().cloned().unwrap_or_default()
    }
    fn write_role(&self, name: &str, attributes: &Value) -> Marked {
        self.written
            .lock()
            .unwrap()
            .push(json!({"name": name, "attributes": attributes}));
        self.marked("roles.directory", "writeRole", json!([name, attributes]))
    }
    fn delete_role(&self, name: &str) -> bool {
        self.answer("roles.directory", "deleteRole", json!([name])) == json!(true)
    }
    fn resolve_owner(&self, text: &str) -> Value {
        self.answer("roles.directory", "resolveOwner", json!([text]))
    }
    fn groups_of_user(&self, name: &str) -> Vec<String> {
        let a = self.answer("roles.directory", "groupsOfUser", json!([name]));
        a.as_array()
            .map(|l| l.iter().map(|v| v.as_str().unwrap_or("").to_string()).collect())
            .unwrap_or_default()
    }
    fn ensure_group(&self, name: &str, options: &Value) -> Value {
        self.answer("roles.directory", "ensureGroup", json!([name, options]))
    }
}

impl RosterDirectory for Replay {
    fn users_dn(&self) -> String {
        self.answer("rbac.directory", "usersDn", json!([]))
            .as_str()
            .unwrap_or("")
            .to_string()
    }
    fn realm_id(&self) -> Option<String> {
        self.answer("rbac.directory", "realmId", json!([]))
            .as_str()
            .map(str::to_string)
    }
    fn group_dn_for(&self, cn: &str) -> String {
        self.answer("rbac.directory", "groupDnFor", json!([cn]))
            .as_str()
            .unwrap_or("")
            .to_string()
    }
    fn read_group_entry(&self, dn: &str) -> Value {
        self.answer("rbac.directory", "readGroupEntry", json!([dn]))
    }
    fn write_group_entry(&self, dn: &str, attributes: &Value, origin: &str) -> Value {
        self.answer(
            "rbac.directory",
            "writeGroupEntry",
            json!([dn, attributes, origin]),
        )
    }
    fn normalize_dn(&self, dn: &str) -> String {
        self.answer("rbac.directory", "normalizeDn", json!([dn]))
            .as_str()
            .unwrap_or("")
            .to_string()
    }
    fn existing_user_entry(&self, name: &str) -> Value {
        self.answer("rbac.directory", "existingUserEntry", json!([name]))
    }
    fn name_usable_in_dn(&self, name: &str) -> bool {
        self.answer("rbac.directory", "nameUsableInDn", json!([name])) == json!(true)
    }
    fn claimed_members_of(&self, dn: &str) -> Vec<Value> {
        self.answer("rbac.directory", "claimedMembersOf", json!([dn]))
            .as_array()
            .cloned()
            .unwrap_or_default()
    }
    fn read_person_flags(&self, name: &str) -> Value {
        // Node reads them inside withRememberedUserNames(), which is the
        // call its recorder saw.
        let _ = name;
        self.answer("rbac.directory", "withRememberedUserNames", json!([null]))
    }
}

impl Audit for Replay {
    fn audit(&self, row: &Value) {
        self.call("audit", "audit", json!([row]));
    }
    fn record(&self, row: &Value) {
        self.call("audit", "record", json!([row]));
    }
    fn failure(&self, code: ErrorCode, row: &Value) {
        self.call("audit", "failure", json!([code.as_str(), row]));
    }
}

impl Applications for Replay {
    fn get(&self, identifier: &str) -> Value {
        self.answer("applications", "get", json!([identifier]))
    }
    fn list(&self) -> Vec<Value> {
        self.answer("applications", "list", json!([]))
            .as_array()
            .cloned()
            .unwrap_or_default()
    }
    fn required_roles_of(&self, identifier: &str) -> Vec<String> {
        self.answer("applications", "requiredRolesOf", json!([identifier]))
            .as_array()
            .map(|l| l.iter().map(|v| v.as_str().unwrap_or("").to_string()).collect())
            .unwrap_or_default()
    }
    fn role_gating_for(&self, id: &str) -> Value {
        self.answer("applications", "roleGatingFor", json!([id]))
    }
    fn for_permission(&self, id: &str) -> Value {
        self.answer("applications", "forPermission", json!([id]))
    }
    fn setting_for(&self, identifier: &str, key: &str) -> Value {
        let row = self
            .calls
            .iter()
            .find(|r| {
                Replay::key(r) == "applications.settingFor"
                    && r["args"][0] == json!(identifier)
                    && r["args"][1] == json!(key)
            })
            .cloned();
        match row {
            Some(r) => r["answer"].clone(),
            None => {
                self.problem(format!("settingFor {identifier} {key}: Node never asked"));
                Value::Null
            }
        }
    }
    fn update_application(&self, identifier: &str, change: &Value) -> Marked {
        self.marked("applications", "updateApplication", json!([identifier, change]))
    }
    fn is_internal_identifier(&self, identifier: &str) -> bool {
        self.answer("applications", "isInternalIdentifier", json!([identifier]))
            == json!(true)
    }
    fn owner_protected(&self, identifier: &str) -> bool {
        self.answer("applications", "ownerProtected", json!([identifier])) == json!(true)
    }
    fn set_owner_protected(&self, identifier: &str, flag: bool) -> Marked {
        self.marked("applications", "setOwnerProtected", json!([identifier, flag]))
    }
    fn owner_values(&self) -> Vec<Vec<String>> {
        self.answer("applications", "ownerValues", json!([]))
            .as_array()
            .map(|l| {
                l.iter()
                    .map(|v| {
                        v.as_array()
                            .map(|x| x.iter().map(|s| s.as_str().unwrap_or("").to_string()).collect())
                            .unwrap_or_default()
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Mode for Replay {
    fn opens_console_to_anyone(&self, _realm: &str) -> bool {
        self.answer("mode", "opensConsoleToAnyone", json!([])) == json!(true)
    }
    fn verifies_credentials(&self) -> bool {
        self.answer("mode", "verifiesCredentials", json!([])) == json!(true)
    }
    fn refuses_token_for_gone_subject(&self) -> bool {
        self.answer("mode", "refusesTokenForGoneSubject", json!([])) == json!(true)
    }
}

impl BootstrapName for Replay {
    fn current(&self) -> String {
        self.answer("bootstrap", "current", json!([]))
            .as_str()
            .unwrap_or("")
            .to_string()
    }
}

fn strings_of(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|l| l.iter().map(|s| s.as_str().unwrap_or("").to_string()).collect())
        .unwrap_or_default()
}

impl Credentials for Replay {
    fn account_disabled(&self, name: &str) -> bool {
        self.answer("credentials", "accountDisabled", json!([name])) == json!(true)
    }
    fn set_account_disabled(&self, name: &str, disabled: bool, options: &Value) -> Marked {
        self.marked("credentials", "setAccountDisabled", json!([name, disabled, options]))
    }
    fn generate_password(&self, name: &str) -> String {
        self.answer("credentials", "generatePassword", json!([name]))
            .as_str()
            .unwrap_or("")
            .to_string()
    }
    fn set_password(&self, name: &str, password: &str, options: &Value) -> Value {
        self.answer("credentials", "setPassword", json!([name, password, options]))
    }
    fn set_password_reset_required(&self, name: &str, flag: bool) -> Value {
        self.answer("credentials", "setPasswordResetRequired", json!([name, flag]))
    }
    fn issue_activation(&self, name: &str) -> Value {
        self.answer("credentials", "issueActivation", json!([name]))
    }
}

impl IdentityKeys for Replay {
    fn identity_key_of(&self, name: &str) -> String {
        self.answer("stats", "identityKeyOf", json!([name]))
            .as_str()
            .unwrap_or("")
            .to_string()
    }
}

impl Logout for Replay {
    fn terminate(&self, key: &str, selection: &Value, options: &Value) -> Value {
        self.answer("logout", "terminate", json!([key, selection, options]))
    }
}

impl AccountEffects for Replay {
    fn note_revoking_write(&self, what: &str) {
        self.call("revokingWrites", "note", json!([what]));
    }
    fn mail_account_disabled(&self, name: &str, why: &str, by_system: bool) {
        self.call("mail", "accountDisabled", json!([name, why, by_system]));
    }
}

impl PersonWriter for Replay {
    fn create_user(&self, name: &str, options: &Value) -> Marked {
        self.marked("directory", "createUser", json!([name, options]))
    }
}

impl GroupWriter for Replay {
    fn create_group(&self, name: &str, options: &Value) -> Marked {
        self.marked("groups", "createGroup", json!([name, options]))
    }
    fn add_group_member(&self, group: &str, member: &str, options: &Value) -> Marked {
        self.marked("groups", "addGroupMember", json!([group, member, options]))
    }
    fn set_group_mail(&self, group: &str, mail: &str, options: &Value) -> Marked {
        self.marked("groups", "setGroupMail", json!([group, mail, options]))
    }
    fn set_group_policy(&self, group: &str, attribute: &str, policy: &str, options: &Value) -> Marked {
        self.marked("groups", "setGroupPolicy", json!([group, attribute, policy, options]))
    }
    fn add_group_owner(&self, group: &str, owner: &str, options: &Value) -> Marked {
        self.marked("groups", "addGroupOwner", json!([group, owner, options]))
    }
    fn remove_group_owner(&self, group: &str, owner: &str, options: &Value) -> Marked {
        self.marked("groups", "removeGroupOwner", json!([group, owner, options]))
    }
}

impl GroupDirectory for Replay {
    fn groups_of_user(&self, name: &str) -> Value {
        // The groups claim reads it as `groups.directory`, ownership as `ldap`.
        let port = if self.has("groups.directory.groupsOfUser") {
            "groups.directory"
        } else {
            "ldap"
        };
        self.answer(port, "groupsOfUser", json!([name]))
    }
    fn groups_owned_by(&self, dns: &[String]) -> Vec<Value> {
        self.answer("ldap", "groupsOwnedBy", json!([dns]))
            .as_array()
            .cloned()
            .unwrap_or_default()
    }
    fn group_ownership(&self, name: &str) -> Value {
        self.answer("ldap", "groupOwnership", json!([name]))
    }
    fn set_group_owner_protected(&self, name: &str, flag: bool, options: &Value) -> Marked {
        self.marked("ldap", "setGroupOwnerProtected", json!([name, flag, options]))
    }
}

impl ServiceAccounts for Replay {
    fn write_refusal(&self, fields: &Value) -> Option<PolicyRefusal> {
        let a = self.answer("serviceAccountPolicy", "writeRefusal", json!([fields]));
        if a.is_null() {
            return None;
        }
        Some(PolicyRefusal {
            code: a["code"].as_str().and_then(code_named)?,
            message: a["message"].as_str().unwrap_or("").to_string(),
        })
    }
    fn check(&self, body: &Value, existing: &str) -> Marked {
        self.marked("serviceAccounts", "check", json!([body, existing]))
    }
    fn set(&self, username: &str, change: &Value) -> Value {
        self.answer("serviceAccounts", "set", json!([username, change]))
    }
    fn list(&self) -> Vec<Value> {
        self.answer("serviceAccounts", "list", json!([]))
            .as_array()
            .cloned()
            .unwrap_or_default()
    }
    fn of(&self, name: &str) -> Value {
        self.answer("serviceAccounts", "of", json!([name]))
    }
    fn set_owner_protected(&self, name: &str, flag: bool) -> Marked {
        self.marked("serviceAccounts", "setOwnerProtected", json!([name, flag]))
    }
}

impl AccountSignals for Replay {
    fn credential_changed(&self, change: &Value) {
        self.call("accountSignals", "credentialChanged", json!([change]));
    }
}

impl LinkMailer for Replay {
    fn mailed_link(&self, kind: &str, who: &str, token: &str, body: &Value, actor: &str, via: &str) -> Value {
        self.answer("actions", "mailedLink", json!([kind, who, token, body, actor, via]))
    }
}

impl ScopePolicy for Replay {
    fn protected_scopes(&self) -> Vec<String> {
        strings_of(&self.answer("scopePolicy", "protectedScopes", json!([])))
    }
    fn declared_scopes(&self, identifier: &str) -> Vec<String> {
        strings_of(&self.answer("scopePolicy", "declaredScopes", json!([identifier])))
    }
    fn delegated_permission_scopes(&self, identifier: &str) -> Vec<String> {
        strings_of(&self.answer("scopePolicy", "delegatedPermissionScopes", json!([identifier])))
    }
}

impl ClaimTables for Replay {
    fn reserved_jwt_claims(&self) -> Vec<String> {
        strings_of(&self.answer("stats", "RESERVED_JWT_CLAIMS", json!([])))
    }
    fn claim_set_ids(&self) -> Vec<String> {
        strings_of(&self.answer("stats", "CLAIM_SET_IDS", json!([])))
    }
    fn default_saml11_namespace(&self) -> String {
        self.answer("stats", "DEFAULT_SAML11_NAMESPACE", json!([]))
            .as_str()
            .unwrap_or("")
            .to_string()
    }
}

impl RosterRoles for Replay {
    fn roles_of(&self, name: &str, realm: &str) -> Value {
        self.answer("rbac", "rolesOf", json!([name, realm]))
    }
}

impl OwnsAnything for Replay {
    fn owns_anything(&self, name: &str) -> bool {
        self.answer("ownership", "ownsAnything", json!([name])) == json!(true)
    }
}

impl IssuanceGate for Replay {
    fn check_scopes(&self, request: &Value) -> Vec<ScopeVerdict> {
        let a = self.answer("gate", "checkScopes", json!([request]));
        a["verdicts"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|v| ScopeVerdict {
                scope: v["scope"].as_str().unwrap_or("").to_string(),
                verdict: v["verdict"].as_str().unwrap_or("").to_string(),
                code: v["code"].as_str().and_then(code_named),
            })
            .collect()
    }
}

impl Subjects for Replay {
    fn subject_is_gone(&self, sub: &str) -> bool {
        self.answer("helpers", "subjectIsGone", json!([sub])) == json!(true)
    }
    fn name_for_subject(&self, sub: &str) -> String {
        self.answer("helpers", "nameForSubject", json!([sub]))
            .as_str()
            .unwrap_or("")
            .to_string()
    }
}
