// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! OWNERS (`common/ownership.ts`, rule 3cn, #607): who owns a role, a
//! group, a service account or an application, and what an owner may not
//! touch.
//!
//! An owner is a person or a group named on the object (`owner`,
//! `stsServiceAccountOwner`, `appOwner`); a person owns what names them or
//! a group they are in. Owning something is what the two built-in roles
//! `OWNER_READ` and `OWNER_WRITE` are computed from (`roles.rs`), and the
//! access-control policy's owner rule decides what each may do through
//! `/admin-api` (the API slice's).
//!
//! **SOME OBJECTS ARE CLOSED TO THEIR OWNERS WHATEVER THEY NAME**
//! ([`Ownership::protection_of`]): a built-in or native role, a role
//! authorizing a permission of this service, a group that grants a role or
//! the console roster by its name, a member of such a role, one of this
//! service's own applications, an application declaring such a
//! permission, a service account holding such a role — and anything an
//! administrator closed by hand (`stsOwnerProtected`).

use std::sync::Arc;

use serde_json::{json, Map, Value};
use sts_core::errors::codes;

use crate::js;
use crate::outcome::Outcome;
use crate::port::{
    Applications, GroupDirectory, ScopePolicy, ServiceAccounts, Settings,
};
use crate::roles::{self, owner_roles, Roles, Who, NATIVE_ROLES};

/// `KINDS`.
pub const KINDS: [&str; 4] = ["role", "group", "service-account", "application"];

/// The reason an administrator's own closing gives.
pub const MARKED: &str = "an administrator closed it to its owners";

/// `GRANTING_GROUP_SETTINGS`: the groups that grant by their name.
pub const GRANTING_GROUP_SETTINGS: [&str; 5] = [
    "admin.readGroup",
    "admin.writeGroup",
    "roles.remotePepGroup",
    "roles.xacmlUserGroup",
    "roles.authzenPepGroup",
];

/// `Ownership.dnKey(dn)`.
#[tracing::instrument(level = "debug")]
pub fn dn_key(dn: &str) -> String {
    js::trim(&roles::owner_key(dn)).to_string()
}

/// `Ownership.isKind(kind)`.
#[tracing::instrument(level = "debug")]
pub fn is_kind(kind: &str) -> bool {
    KINDS.contains(&kind)
}

/// The registers and ports ownership asks.
pub struct OwnershipDeps {
    pub settings: Arc<dyn Settings>,
    pub directory: Arc<dyn GroupDirectory>,
    pub roles: Arc<Roles>,
    pub applications: Arc<dyn Applications>,
    pub service_accounts: Arc<dyn ServiceAccounts>,
    pub scope_policy: Arc<dyn ScopePolicy>,
}

/// Ownership.
pub struct Ownership {
    deps: OwnershipDeps,
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|l| l.iter().map(js::string).collect())
        .unwrap_or_default()
}

impl Ownership {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(deps: OwnershipDeps) -> Ownership {
        Ownership { deps }
    }

    /// `identityOf(username)`: the person's DN, their groups, and the keys
    /// an owner value is compared with.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn identity_of(&self, username: &str) -> Value {
        let mut dn = String::new();
        let mut groups: Vec<Value> = Vec::new();
        if !username.is_empty() {
            let found = self.deps.directory.groups_of_user(username);
            if found.get("entryFound").is_some_and(js::truthy) {
                dn = js::or_empty(found.get("dn"));
            }
            groups = found
                .get("groups")
                .and_then(Value::as_array)
                .map(|l| {
                    l.iter()
                        .map(|one| {
                            let gdn = js::unless_null(one.get("dn"));
                            let cn = match js::or_empty(one.get("cn")) {
                                c if c.is_empty() => gdn.clone(),
                                c => c,
                            };
                            json!({"dn": gdn, "cn": cn})
                        })
                        .collect()
                })
                .unwrap_or_default();
        }
        let mut keys: Vec<String> = Vec::new();
        for one in std::iter::once(dn.clone())
            .chain(groups.iter().map(|g| js::string(&g["dn"])))
        {
            if !one.is_empty() {
                keys.push(dn_key(&one));
            }
        }
        json!({"username": username, "dn": dn, "groups": groups,
               "keys": keys})
    }

    fn names(owners: &[String], keys: &[String]) -> bool {
        owners.iter().any(|dn| keys.contains(&dn_key(dn)))
    }

    /// `ownsAnything(username)`: whether anything names them, or a group
    /// they are in, as an owner — the fact OWNER_READ and OWNER_WRITE are
    /// computed from.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn owns_anything(&self, username: &str) -> bool {
        let who = self.identity_of(username);
        let keys = strings(&who["keys"]);
        if keys.is_empty() {
            return false;
        }
        if self
            .deps
            .roles
            .all()
            .iter()
            .any(|row| Ownership::names(&row.owners, &keys))
        {
            return true;
        }
        let mut dns: Vec<String> = Vec::new();
        let dn = js::string(&who["dn"]);
        if !dn.is_empty() {
            dns.push(dn);
        }
        for g in who["groups"].as_array().cloned().unwrap_or_default() {
            let one = js::string(&g["dn"]);
            if !one.is_empty() {
                dns.push(one);
            }
        }
        if !self.deps.directory.groups_owned_by(&dns).is_empty() {
            return true;
        }
        if self.deps.service_accounts.list().iter().any(|one| {
            let owners: Vec<String> = one
                .get("owners")
                .and_then(Value::as_array)
                .map(|l| l.iter().map(|o| js::string(&o["dn"])).collect())
                .unwrap_or_default();
            Ownership::names(&owners, &keys)
        }) {
            return true;
        }
        self.deps
            .applications
            .owner_values()
            .iter()
            .any(|owners| Ownership::names(owners, &keys))
    }

    /// `objectOf(kind, name)`: the object, its owners and whether it is
    /// closed to them.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn object_of(&self, kind: &str, name: &str) -> Value {
        let mut found = false;
        let mut shown = js::trim(name).to_string();
        let mut dn = String::new();
        let mut owners: Vec<String> = Vec::new();
        if is_kind(kind) && !shown.is_empty() {
            match kind {
                "role" => {
                    if let Some(row) = self.deps.roles.read(&shown) {
                        found = true;
                        shown = row.name.clone();
                        dn = row.dn.clone();
                        owners = row.owners.clone();
                    }
                }
                "group" => {
                    let group = self.deps.directory.group_ownership(&shown);
                    if js::truthy(&group) {
                        found = true;
                        dn = js::unless_null(group.get("dn"));
                        shown = match js::or_empty(group.get("cn")) {
                            c if c.is_empty() => dn.clone(),
                            c => c,
                        };
                        owners = strings(&group["owners"]);
                    }
                }
                "service-account" => {
                    let facts = self.deps.service_accounts.of(&shown);
                    if js::truthy(&facts) {
                        found = true;
                        shown = js::unless_null(facts.get("username"));
                        dn = js::unless_null(facts.get("dn"));
                        owners = facts
                            .get("owners")
                            .and_then(Value::as_array)
                            .map(|l| {
                                l.iter().map(|o| js::string(&o["dn"])).collect()
                            })
                            .unwrap_or_default();
                    }
                }
                _ => {
                    let app = self.deps.applications.get(&shown);
                    if js::truthy(&app) {
                        found = true;
                        shown = js::unless_null(app.get("identifier"));
                        dn = js::or_empty(app.get("dn"));
                        owners = match app.get("fields").and_then(|f| {
                            f.get("appOwner")
                        }) {
                            Some(Value::Array(l)) => {
                                l.iter().map(js::string).collect()
                            }
                            Some(v) if js::truthy(v) => vec![js::string(v)],
                            _ => Vec::new(),
                        }
                        .into_iter()
                        .filter(|o: &String| !o.is_empty())
                        .collect();
                    }
                }
            }
        }
        let reasons = if found {
            self.protection_of(kind, &shown)
        } else {
            Vec::new()
        };
        json!({
            "found": found, "kind": kind, "name": shown, "dn": dn,
            "owners": owners, "protected": !reasons.is_empty(),
            "marked": reasons.iter().any(|r| r == MARKED),
            "reasons": reasons,
        })
    }

    /// `owns(username, kind, name)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn owns(&self, username: &str, kind: &str, name: &str) -> bool {
        let facts = self.object_of(kind, name);
        if facts["found"] != json!(true) {
            return false;
        }
        let keys = strings(&self.identity_of(username)["keys"]);
        Ownership::names(&strings(&facts["owners"]), &keys)
    }

    fn protected_permissions(&self) -> Vec<String> {
        let mut out = self.deps.scope_policy.protected_scopes();
        let natives = NATIVE_ROLES.iter().map(|row| row.permission);
        let owned = owner_roles().into_iter().map(|(_, p)| p);
        for permission in natives.chain(owned) {
            if !out.iter().any(|one| one == permission) {
                out.push(permission.to_string());
            }
        }
        out
    }

    fn protected_roles(&self) -> Map<String, Value> {
        let permissions = self.protected_permissions();
        let mut out = Map::new();
        for row in self.deps.roles.all() {
            if row.native {
                out.insert(row.name.clone(),
                           json!("it is a native role of this service"));
                continue;
            }
            let held: Vec<&String> = row
                .permissions
                .iter()
                .filter(|p| permissions.contains(p))
                .collect();
            if !held.is_empty() {
                let list: Vec<&str> = held.iter().map(|s| s.as_str()).collect();
                out.insert(row.name.clone(), json!(format!(
                    "it authorizes {}, a permission of this service no owner \
                     may come to hold", list.join(", "))));
            }
        }
        out
    }

    fn granting_groups(&self) -> Vec<String> {
        GRANTING_GROUP_SETTINGS
            .iter()
            .map(|key| {
                js::lower(js::trim(&js::or_empty(Some(
                    &self.deps.settings.value(key),
                ))))
            })
            .filter(|one| !one.is_empty())
            .collect()
    }

    /// `protectionOf(kind, name)`: every reason the object is closed to
    /// its owners.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn protection_of(&self, kind: &str, wanted: &str) -> Vec<String> {
        let mut reasons: Vec<String> = Vec::new();
        let protected = self.protected_roles();
        let protected_names: Vec<&String> = protected.keys().collect();
        let in_role = |test: &dyn Fn(&roles::RoleRow) -> bool| -> Vec<String> {
            self.deps
                .roles
                .all()
                .into_iter()
                .filter(|row| protected_names.contains(&&row.name) && test(row))
                .map(|row| row.name)
                .collect()
        };
        match kind {
            "role" => {
                if roles::is_built_in(wanted) {
                    reasons.push("it is a built-in role, computed rather than \
                                  stored".to_string());
                } else if let Some(why) = protected.get(wanted) {
                    reasons.push(js::string(why));
                }
                if self
                    .deps
                    .roles
                    .read(wanted)
                    .is_some_and(|row| row.owner_protected)
                {
                    reasons.push(MARKED.to_string());
                }
            }
            "group" => {
                let group = self.deps.directory.group_ownership(wanted);
                if js::truthy(&group) {
                    let cn = js::lower(&js::or_empty(group.get("cn")));
                    let gdn = js::unless_null(group.get("dn"));
                    if self.granting_groups().contains(&cn) {
                        reasons.push("it is a group this service grants a \
                                      role or the console roster through by \
                                      its name".to_string());
                    }
                    let held = in_role(&|row| {
                        row.groups.iter().any(|one| {
                            js::lower(one) == cn || dn_key(one) == dn_key(&gdn)
                        })
                    });
                    if !held.is_empty() {
                        reasons.push(format!(
                            "it is a member of {}, which no owner may \
                             administer",
                            held.join(", ")
                        ));
                    }
                    if group.get("ownerProtected").is_some_and(js::truthy) {
                        reasons.push(MARKED.to_string());
                    }
                }
            }
            "application" => {
                let apps = &self.deps.applications;
                if apps.is_internal_identifier(wanted) {
                    reasons.push("it is one of this service's own \
                                  applications".to_string());
                }
                let held = in_role(&|row| {
                    row.applications.iter().any(|a| a == wanted)
                });
                if !held.is_empty() {
                    reasons.push(format!(
                        "it is a member of {}, which no owner may administer",
                        held.join(", ")
                    ));
                }
                let permissions = self.protected_permissions();
                let mut declared = self.deps.scope_policy.declared_scopes(wanted);
                declared.extend(
                    self.deps.scope_policy.delegated_permission_scopes(wanted),
                );
                let declared: Vec<String> = declared
                    .into_iter()
                    .filter(|one| permissions.contains(one))
                    .collect();
                if !declared.is_empty() {
                    reasons.push(format!(
                        "it declares {}, a permission of this service no \
                         owner may come to hold",
                        declared.join(", ")
                    ));
                }
                if apps.owner_protected(wanted) {
                    reasons.push(MARKED.to_string());
                }
            }
            "service-account" => {
                let facts = self.deps.service_accounts.of(wanted);
                let held = if js::truthy(&facts) {
                    self.deps.roles.roles_of(&Who::subject(
                        false,
                        &js::unless_null(facts.get("username")),
                        true,
                    ))
                } else {
                    Vec::new()
                };
                let closing: Vec<String> = held
                    .into_iter()
                    .filter(|role| {
                        protected_names.contains(&role)
                            || ["REMOTE_PEPS", "XACML_USER", "AUTHZEN_PEPS"]
                                .contains(&role.as_str())
                    })
                    .collect();
                if !closing.is_empty() {
                    reasons.push(format!(
                        "it holds {}, which no owner may come to hold \
                         through it",
                        closing.join(", ")
                    ));
                }
                if facts.get("ownerProtected").is_some_and(js::truthy) {
                    reasons.push(MARKED.to_string());
                }
            }
            _ => {}
        }
        reasons
    }

    /// `setProtected(kind, name, flag, options)`: an administrator closing
    /// an object to its owners, or opening it again.
    #[tracing::instrument(level = "debug", skip(self, flag, options))]
    pub fn set_protected(&self, kind: &str, name: &str, flag: &Value,
                         options: &Value) -> Outcome {
        let wanted = flag == &Value::Bool(true) || js::string(flag) == "true";
        let what = js::trim(name).to_string();
        if !is_kind(kind) {
            return Outcome::marked(
                codes::STS_API_0134,
                json!({"ok": false, "errors": ["`kind` must be one of role, \
                    group, service-account, application."]}),
            );
        }
        if what.is_empty() {
            return Outcome::marked(
                codes::STS_API_0134,
                json!({"ok": false, "errors": [format!(
                    "Which {kind}? Send `name`.")]}),
            );
        }
        let done = match kind {
            "role" => {
                let result = self.deps.roles.set_owner_protected(&what, wanted);
                if !result.is_ok() {
                    return Outcome::marked(
                        codes::STS_XACML_0057,
                        json!({"ok": false, "errors": [result.why()]}),
                    );
                }
                result
            }
            "group" => {
                let m = self.deps.directory.set_group_owner_protected(
                    &what, wanted, options);
                Outcome { answer: m.value, code: m.code }
            }
            "service-account" => {
                let m = self.deps.service_accounts.set_owner_protected(&what,
                                                                       wanted);
                Outcome { answer: m.value, code: m.code }
            }
            _ => {
                let m = self.deps.applications.set_owner_protected(&what,
                                                                   wanted);
                Outcome { answer: m.value, code: m.code }
            }
        };
        if done.answer.get("ok") != Some(&Value::Bool(true)) {
            return done;
        }
        Outcome::ok(json!({
            "ok": true,
            "changed": done.answer.get("changed") != Some(&Value::Bool(false)),
            "kind": kind, "name": what, "ownerProtected": wanted,
            "message": format!("{what}{}", if wanted {
                " is closed to its owners: they may not administer it \
                 through /admin-api."
            } else {
                " is open to its owners again, unless another reason closes \
                 it."
            }),
        }))
    }
}
