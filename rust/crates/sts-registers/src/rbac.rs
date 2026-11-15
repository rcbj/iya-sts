// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE CONSOLE ROSTER (`admin-ui/admin_rbac.ts`): who may use the admin
//! console and the management API, as three ordinary groups in the
//! directory — Admin Read, Admin Write, Security Administrator — whose cns
//! are the settings `admin.readGroup`, `admin.writeGroup` and
//! `admin.securityGroup`. `POST /admin-api/rbac/grant` and `/rbac/revoke`
//! are [`Rbac::grant`] and [`Rbac::revoke`], reached through
//! `rbacAction()` ([`Rbac::act`]).
//!
//! **A GRANT IS IDEMPOTENT**: a person already listed answers
//! `changed: false` and nothing is written — unlike a role's `add-member`
//! (`role_actions.rs`), which refuses the second add. **A grant needs a
//! person who EXISTS** (`STS-ADMIN-0920`), so that somebody created later
//! under the same name inherits nothing (#1613).
//!
//! The groups grant nothing anywhere else: being in one changes no token
//! this service issues. That is the one place a group decides anything,
//! and it decides it by being one of the three the settings NAME.

use std::sync::Arc;

use serde_json::{json, Map, Value};
use sts_core::errors::{codes, ErrorCode};

use crate::js;
use crate::outcome::Outcome;
use crate::port::{Audit, BootstrapName, Mode, RosterDirectory, Settings};
use crate::roles::{RosterRole, ROSTER_ROLES};

/// `NO_DIRECTORY`.
const NO_DIRECTORY: &str = "No LDAP directory is loaded in this process, so \
    there is nowhere to hold the roles. That is a build of this service \
    without ldap_server.js and not a failure — but it means nobody can be \
    granted anything, so the console gate leaves this console reachable \
    only while admin.openWhenEmpty is on.";

/// `NOT_WRITTEN_BACK`: what a group's write never carries back.
const NOT_WRITTEN_BACK: [&str; 3] =
    ["entrydn", "createtimestamp", "modifytimestamp"];

/// The console roster's acts.
pub struct Rbac {
    directory: Option<Arc<dyn RosterDirectory>>,
    settings: Arc<dyn Settings>,
    audit: Arc<dyn Audit>,
    mode: Arc<dyn Mode>,
    bootstrap: Arc<dyn BootstrapName>,
}

fn refused(code: ErrorCode, answer: Value) -> Outcome {
    Outcome::marked(code, answer)
}

struct Target {
    dn: String,
    present: bool,
}

impl Rbac {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(
        directory: Option<Arc<dyn RosterDirectory>>,
        settings: Arc<dyn Settings>,
        audit: Arc<dyn Audit>,
        mode: Arc<dyn Mode>,
        bootstrap: Arc<dyn BootstrapName>,
    ) -> Rbac {
        Rbac {
            directory,
            settings,
            audit,
            mode,
            bootstrap,
        }
    }

    /// `roleFor(id)`.
    #[tracing::instrument(level = "debug")]
    pub fn role_for(id: &str) -> Option<&'static RosterRole> {
        let wanted = js::lower(js::trim(id));
        ROSTER_ROLES.iter().find(|role| role.id == wanted)
    }

    fn unknown_role(id: &str) -> Outcome {
        let ids: Vec<&str> = ROSTER_ROLES.iter().map(|r| r.id).collect();
        refused(
            codes::STS_ADMIN_0582,
            json!({"ok": false, "errors": [format!(
                "Unknown role \"{id}\". There are {}: {}.",
                ids.len(), ids.join(", "))]}),
        )
    }

    fn cn_for(&self, role: &RosterRole) -> String {
        js::trim(&js::or_empty(Some(&self.settings.value(role.setting))))
            .to_string()
    }

    fn dn_for(&self, d: &dyn RosterDirectory, role: &RosterRole) -> String {
        d.group_dn_for(&self.cn_for(role))
    }

    fn target(&self, d: &dyn RosterDirectory, name: &str) -> Target {
        let existing = d.existing_user_entry(name);
        if js::truthy(&existing) {
            return Target {
                dn: js::unless_null(existing.get("dn")),
                present: true,
            };
        }
        Target {
            dn: format!("uid={name},{}", d.users_dn()),
            present: false,
        }
    }

    fn members(entry: &Value) -> Vec<Value> {
        entry
            .get("members")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    }

    /// `memberIndex(entry, username, memberDn)`.
    fn member_index(
        d: &dyn RosterDirectory,
        entry: &Value,
        username: &str,
        member_dn: &str,
    ) -> Vec<usize> {
        let normalized = d.normalize_dn(member_dn);
        let wanted = js::lower(js::trim(username));
        let mut hits = Vec::new();
        for (i, member) in Rbac::members(entry).iter().enumerate() {
            let value = js::unless_null(member.get("value"));
            if member.get("holds") == Some(&json!("uid")) {
                if js::lower(js::trim(&value)) == wanted {
                    hits.push(i);
                }
                continue;
            }
            if d.normalize_dn(&value) == normalized {
                hits.push(i);
                continue;
            }
            if member.get("present").is_some_and(js::truthy)
                && d.normalize_dn(&js::unless_null(member.get("dn")))
                    == normalized
            {
                hits.push(i);
            }
        }
        hits
    }

    /// `rosterEmpty()`: no role group lists anybody, counting the people
    /// who claim one through their own `memberOf`.
    fn roster_empty(&self, d: &dyn RosterDirectory) -> bool {
        let listed = ROSTER_ROLES.iter().any(|role| {
            let entry = d.read_group_entry(&self.dn_for(d, role));
            js::truthy(&entry) && !Rbac::members(&entry).is_empty()
        });
        if listed {
            return false;
        }
        let total: usize = ROSTER_ROLES
            .iter()
            .map(|role| {
                let dn = self.dn_for(d, role);
                let entry = d.read_group_entry(&dn);
                if !js::truthy(&entry) {
                    return 0;
                }
                Rbac::members(&entry).len() + d.claimed_members_of(&dn).len()
            })
            .sum();
        total == 0
    }

    fn writable(entry: &Value) -> Map<String, Value> {
        let mut out = Map::new();
        if let Some(at) = entry.get("attributes").and_then(Value::as_object) {
            for (name, values) in at {
                if NOT_WRITTEN_BACK.contains(&js::lower(name).as_str()) {
                    continue;
                }
                out.insert(name.clone(), values.clone());
            }
        }
        out
    }

    fn refusal_text(written: &Value, dn: &str) -> String {
        let reason = js::unless_null(written.get("reason"));
        match reason.as_str() {
            "notAGroup" => format!(
                "There is already an entry at {dn} and it is not a group. \
                 Something wrote it — an ldapadd, a SCIM POST — and this \
                 console will not overwrite an entry it did not make. Delete \
                 it, or point the role at another cn on /admin/rbac."
            ),
            "noParent" => format!(
                "There is no {} to put {dn} under. The groups container is \
                 created at startup, so something deleted it.",
                js::unless_null(written.get("parent"))
            ),
            "full" => "The directory holds its maximum number of entries \
                (ldap.maxEntries), so the role group could not be created."
                .to_string(),
            _ => format!("The directory refused to write {dn} ({reason})."),
        }
    }

    /// `grant(username, roleId, context)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn grant(
        &self,
        username: &str,
        role_id: &str,
        via: &str,
        actor: &str,
    ) -> Outcome {
        let name = js::trim(username).to_string();
        let Some(d) = self.directory.as_deref() else {
            return refused(
                codes::STS_ADMIN_0501,
                json!({"ok": false, "errors": [NO_DIRECTORY]}),
            );
        };
        let Some(role) = Rbac::role_for(role_id) else {
            return Rbac::unknown_role(role_id);
        };
        if name.is_empty() {
            return refused(
                codes::STS_ADMIN_0583,
                json!({"ok": false, "errors": ["No name was given. Choose \
                    somebody from the list, or type the name of a person in \
                    this realm's directory."]}),
            );
        }
        if !d.name_usable_in_dn(&name) {
            return refused(
                codes::STS_ADMIN_0583,
                json!({"ok": false, "errors": [format!(
                    "\"{name}\" carries a character RFC 4514 reserves in a \
                     DN, so it cannot name an entry under {}. That is the \
                     same refusal creating a person gets, and for the same \
                     reason: names of that shape get into this directory by \
                     being PRESENTED — a certificate subject, a did: — \
                     rather than by being typed.", d.users_dn())]}),
            );
        }
        if !js::truthy(&d.existing_user_entry(&name)) {
            return refused(
                codes::STS_ADMIN_0920,
                json!({"ok": false, "reason": "noSuchPerson",
                    "username": name, "errors": [format!(
                    "Nobody called \"{name}\" is in this realm's directory \
                     ({}), so there is nobody to grant a console role to. \
                     Create the person first — Directory, People, or POST \
                     /admin-api/users/create — and grant the role then. A \
                     role is granted only to somebody who exists, so that a \
                     person created later under the same name inherits \
                     nothing.", d.users_dn())]}),
            );
        }
        let dn = self.dn_for(d, role);
        let cn = self.cn_for(role);
        let existing = d.read_group_entry(&dn);
        let target = self.target(d, &name);
        let was_empty = self.roster_empty(d);
        if js::truthy(&existing)
            && !Rbac::member_index(d, &existing, &name, &target.dn).is_empty()
        {
            return Outcome::ok(json!({
                "ok": true, "changed": false, "role": role.id,
                "username": name, "dn": dn, "member": target.dn,
                "message": format!("{name} already holds {} — {dn} lists \
                    them. Nothing was changed.", role.label),
            }));
        }
        let attributes = if js::truthy(&existing) {
            let mut at = Rbac::writable(&existing);
            let mut member = at
                .get("member")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            member.push(json!(target.dn));
            at.insert("member".into(), Value::Array(member));
            Value::Object(at)
        } else {
            json!({
                "objectClass": ["top", "groupOfNames"],
                "cn": [cn],
                "description": [format!("The {} role for this service's \
                    admin console. It grants nothing anywhere else: no \
                    token, assertion, ticket or credential this service \
                    issues is changed by being in it.", role.label)],
                "member": [target.dn],
            })
        };
        let written = d.write_group_entry(&dn, &attributes, "console");
        if !written.get("ok").is_some_and(js::truthy) {
            return refused(
                codes::STS_ADMIN_0585,
                json!({"ok": false,
                    "errors": [Rbac::refusal_text(&written, &dn)],
                    "reason": written.get("reason").cloned()
                        .unwrap_or(Value::Null)}),
            );
        }
        let created = written.get("created").cloned();
        let mut detail = json!({"role": role.id, "username": name,
            "member": target.dn});
        if let Some(map) = detail.as_object_mut() {
            if let Some(c) = created.clone().filter(|c| !c.is_null()) {
                map.insert("created".into(), c);
            }
            map.insert("via".into(), json!(via));
            map.insert("resolves".into(), json!(target.present));
            map.insert("rosterWasEmpty".into(), json!(was_empty));
        }
        self.audit.record(&json!({
            "action": "admin.role.change", "outcome": "success",
            "actor": actor, "target": dn,
            "channel": if via == "api" { "http" } else { "internal" },
            "summary": format!("{name} was granted {}", role.label),
            "detail": detail,
        }));
        let made = created.as_ref().is_some_and(js::truthy);
        let mut message = format!(
            "{name} now holds {}, as {} in {dn}.",
            role.label, target.dn
        );
        if made {
            message.push_str(" The group did not exist and was created.");
        }
        if was_empty {
            message.push_str(
                " This was the FIRST grant, so the roster is now enforced: \
                 whoever is not in one of these two groups can no longer use \
                 this console.",
            );
        }
        let mut answer = json!({
            "ok": true, "changed": true, "role": role.id, "username": name,
            "dn": dn, "member": target.dn, "created": made,
            "resolves": target.present,
        });
        if let Some(map) = answer.as_object_mut() {
            if let Some(entry) = written.get("entry").filter(|e| !e.is_null()) {
                map.insert("entry".into(), entry.clone());
            }
            map.insert("message".into(), json!(message));
        }
        Outcome::ok(answer)
    }

    /// `bootstrapState()`'s two facts the revoke needs.
    fn bootstrap_claimed(&self, d: &dyn RosterDirectory) -> bool {
        let name = self.bootstrap.current();
        if name.is_empty() {
            return false;
        }
        let flags = d.read_person_flags(&name);
        if !js::truthy(&flags) {
            return false;
        }
        let seeded =
            flags.get("bootstrapAdministrator").is_some_and(js::truthy);
        let claimed = !js::or_empty(flags.get("consoleClaimedAt")).is_empty();
        seeded && claimed
    }

    /// `revoke(username, roleId, context)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn revoke(
        &self,
        username: &str,
        role_id: &str,
        via: &str,
        actor: &str,
    ) -> Outcome {
        let name = js::trim(username).to_string();
        let Some(d) = self.directory.as_deref() else {
            return refused(
                codes::STS_ADMIN_0501,
                json!({"ok": false, "errors": [NO_DIRECTORY]}),
            );
        };
        let Some(role) = Rbac::role_for(role_id) else {
            return Rbac::unknown_role(role_id);
        };
        if name.is_empty() {
            return refused(
                codes::STS_ADMIN_0584,
                json!({"ok": false, "errors": ["No name was given."]}),
            );
        }
        let dn = self.dn_for(d, role);
        let existing = d.read_group_entry(&dn);
        if !js::truthy(&existing) {
            return Outcome::ok(json!({
                "ok": true, "changed": false, "role": role.id,
                "username": name, "dn": dn,
                "message": format!("There is no {dn}, so nobody holds {} and \
                    there was nothing to take away.", role.label),
            }));
        }
        let target = self.target(d, &name);
        let hits = Rbac::member_index(d, &existing, &name, &target.dn);
        if hits.is_empty() {
            let wanted = d.normalize_dn(&target.dn);
            let claimed = d.claimed_members_of(&dn).iter().any(|row| {
                d.normalize_dn(&js::unless_null(row.get("dn"))) == wanted
            });
            if claimed {
                return refused(
                    codes::STS_ADMIN_0586,
                    json!({"ok": false, "reason": "claimed", "role": role.id,
                        "username": name, "dn": dn, "errors": [format!(
                        "{name} holds {} through a memberOf value on THEIR \
                         OWN entry ({}) rather than through a member value \
                         on {dn}, so there is nothing in the group to \
                         remove. Nothing here maintains memberOf — a client \
                         wrote it — and this console writes only to groups, \
                         deliberately. Delete that value with an ldapmodify \
                         or a SCIM PATCH of the person and the role goes \
                         with it.", role.label, target.dn)]}),
                );
            }
            return Outcome::ok(json!({
                "ok": true, "changed": false, "role": role.id,
                "username": name, "dn": dn,
                "message": format!("{name} does not hold {}. Nothing was \
                    changed.", role.label),
            }));
        }
        let members = Rbac::members(&existing);
        let removed: Vec<Value> =
            hits.iter().map(|&i| members[i].clone()).collect();
        let mut attributes = Rbac::writable(&existing);
        for member in &removed {
            let attribute =
                js::lower(&js::unless_null(member.get("attribute")));
            let value = js::unless_null(member.get("value"));
            let key = attributes
                .keys()
                .find(|k| js::lower(k) == attribute)
                .cloned();
            let Some(key) = key else {
                continue;
            };
            let kept: Vec<Value> = attributes[&key]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|v| js::string(v) != value)
                .collect();
            if kept.is_empty() {
                attributes.remove(&key);
            } else {
                attributes.insert(key, Value::Array(kept));
            }
        }
        let written =
            d.write_group_entry(&dn, &Value::Object(attributes), "console");
        if !written.get("ok").is_some_and(js::truthy) {
            return refused(
                codes::STS_ADMIN_0585,
                json!({"ok": false,
                    "errors": [Rbac::refusal_text(&written, &dn)],
                    "reason": written.get("reason").cloned()
                        .unwrap_or(Value::Null)}),
            );
        }
        let now_empty = self.roster_empty(d);
        let values: Vec<String> = removed
            .iter()
            .map(|m| {
                format!(
                    "{}: {}",
                    js::unless_null(m.get("attribute")),
                    js::unless_null(m.get("value"))
                )
            })
            .collect();
        self.audit.record(&json!({
            "action": "admin.role.change", "outcome": "success",
            "actor": actor, "target": dn,
            "channel": if via == "api" { "http" } else { "internal" },
            "summary": format!("{name} was stripped of {}", role.label),
            "detail": {"role": role.id, "username": name, "via": via,
                       "values": values.join(", "),
                       "rosterNowEmpty": now_empty},
        }));
        // bootstrapState() is read whenever the roster is empty, before
        // the setting is asked, as Node does.
        let claimed = now_empty && self.bootstrap_claimed(d);
        let reopens = now_empty
            && js::truthy(&self.settings.value("admin.openWhenEmpty"))
            && !claimed
            && self.mode.opens_console_to_anyone(
                &d.realm_id()
                    .filter(|r| !r.is_empty())
                    .unwrap_or_else(|| "default".to_string()),
            );
        let mut message = format!(
            "{name} no longer holds {} — {} membership value(s) removed from \
             {dn}.",
            role.label,
            removed.len()
        );
        if now_empty {
            message.push_str(
                " THAT WAS THE LAST GRANT ON THIS SERVICE. The \
                roster is empty again, so ",
            );
            message.push_str(if reopens {
                "this console is open to anybody who signs in until somebody \
                 is granted a role."
            } else {
                "nobody can use this console at all. POST \
                 /admin-api/rbac/grant is the way back in."
            });
        }
        Outcome::ok(json!({
            "ok": true, "changed": true, "role": role.id, "username": name,
            "dn": dn, "removed": removed.len(), "message": message,
        }))
    }

    /// `available()`: whether a directory is installed, and so whether the
    /// roles can be read at all.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn available(&self) -> bool {
        self.directory.is_some()
    }

    /// `boundRealmId()`: the realm the directory's view is bound to.
    fn bound_realm(&self) -> String {
        self.directory
            .as_ref()
            .and_then(|d| d.realm_id())
            .filter(|r| !r.is_empty())
            .unwrap_or_else(|| sts_core::realm::DEFAULT_ID.to_string())
    }

    /// `rolesOf(username)`: every role a person holds, Admin Write and the
    /// Security Administrator expanded to Admin Read, membership asked of
    /// the directory both ways (`groupsOfUser()`), and the open-console
    /// rule applied HERE so the banner, the API's answer and the refusal
    /// cannot disagree about whether the door is open: while the bootstrap
    /// administrator has not claimed the console (or, with none seeded,
    /// while the roster is empty) a person holding nothing is let in with
    /// the window's roles — in development only (#103), where
    /// `admin.openWhenEmpty` is on. `claimPending` is that account before
    /// its claim in product; `withheld` a person product refuses where
    /// development would have let them in.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn roles_of(&self, username: &str) -> Value {
        let name = js::trim(username).to_string();
        let mut out = Map::new();
        out.insert("username".into(), json!(name));
        out.insert("roles".into(), json!([]));
        out.insert("read".into(), json!(false));
        out.insert("write".into(), json!(false));
        out.insert("security".into(), json!(false));
        out.insert("groups".into(), json!([]));
        out.insert("open".into(), json!(false));
        out.insert("openable".into(), json!(false));
        out.insert("available".into(), json!(self.directory.is_some()));
        out.insert("empty".into(), json!(false));
        let Some(d) = self.directory.as_deref() else {
            return Value::Object(out);
        };
        if name.is_empty() {
            return Value::Object(out);
        }
        let mut wanted: Vec<(String, &'static RosterRole)> = Vec::new();
        for role in ROSTER_ROLES {
            let cn = self.cn_for(role);
            if !cn.is_empty() {
                wanted.push((js::lower(&cn), role));
                wanted.push((d.normalize_dn(&self.dn_for(d, role)), role));
            }
        }
        let mut held: Vec<&str> = Vec::new();
        let mut groups: Vec<Value> = Vec::new();
        let membership = d.groups_of_user(&name);
        for group in membership
            .get("groups")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            let cn = js::lower(js::trim(&js::or_empty(group.get("cn"))));
            let dn = d.normalize_dn(&js::or_empty(group.get("dn")));
            let role = wanted
                .iter()
                .find(|(k, _)| *k == cn)
                .or_else(|| wanted.iter().find(|(k, _)| *k == dn))
                .map(|(_, r)| *r);
            let Some(role) = role else {
                continue;
            };
            groups.push(json!({
                "role": role.id, "cn": group.get("cn").cloned()
                    .unwrap_or(Value::Null),
                "dn": group.get("dn").cloned().unwrap_or(Value::Null),
                "via": group.get("via").cloned().unwrap_or(Value::Null),
                "viaMemberOf": group.get("viaMemberOf").cloned()
                    .unwrap_or(Value::Null),
            }));
            if !held.contains(&role.id) {
                held.push(role.id);
            }
            for implied in role.implies {
                if !held.contains(implied) {
                    held.push(implied);
                }
            }
        }
        out.insert("groups".into(), Value::Array(groups));
        let empty = self.roster_empty(d);
        out.insert("empty".into(), json!(empty));
        let bootstrap_name = self.bootstrap.current();
        let mut seeded = false;
        let mut claimed_at = String::new();
        if !bootstrap_name.is_empty() {
            let flags = d.read_person_flags(&bootstrap_name);
            if js::truthy(&flags) {
                seeded =
                    flags.get("bootstrapAdministrator").is_some_and(js::truthy);
                claimed_at = js::or_empty(flags.get("consoleClaimedAt"));
            }
        }
        out.insert(
            "bootstrap".into(),
            json!({ "username": bootstrap_name, "seeded": seeded,
                    "claimedAt": claimed_at }),
        );
        let unclaimed = if seeded { claimed_at.is_empty() } else { empty };
        let realm = self.bound_realm();
        let opens = self.mode.opens_console_to_anyone(&realm);
        out.insert("windowOpens".into(), json!(opens));
        if unclaimed && held.is_empty() {
            out.insert("openable".into(), json!(true));
            if opens && js::truthy(&self.settings.value("admin.openWhenEmpty"))
            {
                out.insert("open".into(), json!(true));
                let window: &[&str] = if realm == sts_core::realm::DEFAULT_ID {
                    &["read", "write", "security"]
                } else {
                    &["read", "write"]
                };
                for id in window {
                    if !held.contains(id) {
                        held.push(id);
                    }
                }
            }
        }
        out.insert(
            "claimPending".into(),
            json!(
                !opens
                    && seeded
                    && claimed_at.is_empty()
                    && !bootstrap_name.is_empty()
                    && js::lower(&name) == js::lower(&bootstrap_name)
                    && !held.is_empty()
            ),
        );
        out.insert(
            "withheld".into(),
            json!(!opens && unclaimed && held.is_empty()),
        );
        let roles: Vec<&str> = ROSTER_ROLES
            .iter()
            .map(|r| r.id)
            .filter(|id| held.contains(id))
            .collect();
        out.insert("roles".into(), json!(roles));
        out.insert("read".into(), json!(held.contains(&"read")));
        out.insert("write".into(), json!(held.contains(&"write")));
        out.insert("security".into(), json!(held.contains(&"security")));
        Value::Object(out)
    }

    /// `rbacAction(body, context)`: `grant` and `revoke`; a code the roster
    /// put on its refusal wins over this door's `STS-ADMIN-0539`.
    #[tracing::instrument(level = "debug", skip(self, body))]
    pub fn act(&self, body: &Value, via: &str, actor: &str) -> Outcome {
        let action = js::or_empty(body.get("action"));
        let username =
            js::trim(&js::or_empty(body.get("username"))).to_string();
        let role = js::trim(&js::or_empty(body.get("role"))).to_string();
        let mut result = match action.as_str() {
            "grant" => self.grant(&username, &role, via, actor),
            "revoke" => self.revoke(&username, &role, via, actor),
            _ => {
                return refused(
                    codes::STS_ADMIN_0500,
                    json!({"ok": false, "errors": [format!(
                        "Unknown action \"{action}\". There are two: grant \
                         and revoke.")]}),
                )
            }
        };
        if result.refused() && result.code.is_none() {
            result.code = Some(codes::STS_ADMIN_0539);
        }
        result
    }
}
