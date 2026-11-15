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
    "stats.identityKeyOf",
];

/// One step's recorded calls.
pub struct Replay {
    calls: Vec<Value>,
    used: Mutex<Vec<bool>>,
    pub problems: Mutex<Vec<String>>,
    /// Methods Rust does inline (pure functions ported into the crate):
    /// their recorded calls need not be made.
    inline: HashSet<String>,
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
        }
    }

    fn key(row: &Value) -> String {
        format!(
            "{}.{}",
            row["port"].as_str().unwrap_or(""),
            row["method"].as_str().unwrap_or("")
        )
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
}

impl BootstrapName for Replay {
    fn current(&self) -> String {
        self.answer("bootstrap", "current", json!([]))
            .as_str()
            .unwrap_or("")
            .to_string()
    }
}
