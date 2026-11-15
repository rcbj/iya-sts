// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A ROLE AUTHORIZES A PERMISSION (`common/role_permissions.ts`, rule
//! 3bq, #302, #303): which scopes a request asks for are GATED — a native
//! permission of this service, an owner permission, or an application's
//! permission its resource gates by role (`oauthRoleGatedPermission`) —
//! and which of them the subject's roles authorize.
//!
//! A person's roles are the configured ones they hold, the console
//! roster's (a person never holds a console role as a member: the roster
//! decides, `ADMIN_READ` and `ADMIN_WRITE` carrying `REPORT_USE` and
//! `REPORT_ADMIN` with them), the owner roles when they own anything, and
//! a role the client they sign in through CONFERS. The issuance gate
//! ([`IssuanceGate`], the XACML policy's `issue-scope` verdict, #304)
//! decides each scope from the facts gathered here; a scope the gate did
//! not answer for is dropped when gated (`STS-ADMIN-0821`) or an
//! application's permission (`STS-OAUTH-0957`), and kept otherwise.

use std::sync::Arc;

use serde_json::{json, Map, Value};
use sts_core::errors::{codes, ErrorCode};
use sts_xacml::model::{category, types as datatype};

use crate::js;
use crate::port::*;
use crate::roles::{
    self, console_roles, owner_roles, Roles, Who, NATIVE_ROLES,
};

/// The issuance attribute of a gated scope (`ISSUANCE_ATTRIBUTE` in
/// `xacml/xacml_templates.ts`).
pub const SCOPE_GATED: &str = "urn:sts:xacml:scope-gated";
/// The roles that authorize the scope.
pub const AUTHORIZING_ROLE: &str = "urn:sts:xacml:authorizing-role";
/// An application's own permission.
pub const SCOPE_APPLICATION_PERMISSION: &str =
    "urn:sts:xacml:scope-application-permission";

/// `REPORT_ROLES_OF_ROSTER`.
const REPORT_ROLES_OF_ROSTER: [(&str, &str); 3] = [
    ("write", "REPORT_ADMIN"),
    ("write", "REPORT_USE"),
    ("read", "REPORT_USE"),
];

/// The roles a subject holds (`heldRoles()`'s answer).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Held {
    pub all: Vec<String>,
    pub configured: Vec<String>,
    pub why: String,
}

impl Held {
    /// As Node answers it.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn to_json(&self) -> Value {
        json!({"all": self.all, "configured": self.configured,
               "why": self.why})
    }
}

/// A subject as `role_permissions.ts` takes one: `{kind, name,
/// authenticated}`, `authenticated` true unless it is `false`.
#[derive(Debug, Clone, PartialEq)]
pub struct Subject {
    pub application: bool,
    pub name: String,
    pub authenticated: bool,
}

impl Subject {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn from_json(who: &Value) -> Subject {
        Subject {
            application: who.get("kind") == Some(&json!("application")),
            name: js::or_empty(who.get("name")),
            authenticated: who.get("authenticated") != Some(&json!(false)),
        }
    }
}

/// The dependencies.
pub struct RolePermissionsDeps {
    pub roles: Arc<Roles>,
    pub applications: Arc<dyn Applications>,
    pub audit: Arc<dyn Audit>,
    pub roster: Arc<dyn RosterRoles>,
    pub ownership: Arc<dyn OwnsAnything>,
    pub gate: Arc<dyn IssuanceGate>,
    pub subjects: Arc<dyn Subjects>,
    pub mode: Arc<dyn Mode>,
}

/// Role permissions.
pub struct RolePermissions {
    deps: RolePermissionsDeps,
}

fn fact(id: &str, value: bool) -> Value {
    json!({"category": category::RESOURCE, "id": id, "values": [value],
           "type": datatype::BOOLEAN})
}

fn strings_fact(id: &str, values: &[String]) -> Value {
    json!({"category": category::RESOURCE, "id": id, "values": values,
           "type": datatype::STRING})
}

/// `RolePermissions.split(scope)`.
#[tracing::instrument(level = "debug")]
pub fn split(scope: &str) -> Vec<String> {
    js::split_on(scope, js::is_space)
}

impl RolePermissions {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(deps: RolePermissionsDeps) -> RolePermissions {
        RolePermissions { deps }
    }

    /// `isGated(value)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn is_gated(&self, value: &str) -> bool {
        let native = NATIVE_ROLES.iter().any(|r| r.permission == value)
            || owner_roles().iter().any(|(_, p)| *p == value);
        if native {
            return true;
        }
        let found = self.deps.applications.role_gating_for(value);
        js::truthy(&found) && found.get("gated").is_some_and(js::truthy)
    }

    /// `isApplicationPermission(value)`: defined by an application and not
    /// gated.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn is_application_permission(&self, value: &str) -> bool {
        let found = self.deps.applications.for_permission(value);
        js::truthy(&found) && !self.is_gated(value)
    }

    /// `asksForGated(scope)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn asks_for_gated(&self, scope: &str) -> bool {
        split(scope).iter().any(|one| self.is_gated(one))
    }

    /// `asksFor(scope, subject)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn asks_for(&self, scope: &str, subject: &Subject) -> bool {
        if self.asks_for_gated(scope) {
            return true;
        }
        subject.application
            && split(scope)
                .iter()
                .any(|one| self.is_application_permission(one))
    }

    /// `heldRoles(subject)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn held_roles(&self, subject: &Subject) -> Held {
        let name = js::trim(&subject.name).to_string();
        let everything = self.deps.roles.roles_of(&Who {
            kind_application: subject.application,
            name: name.clone(),
            authenticated: subject.authenticated,
            ids: true,
            ..Who::default()
        });
        let built_in: Vec<String> = everything
            .iter()
            .filter(|one| roles::is_built_in(one))
            .cloned()
            .collect();
        if name.is_empty() || (!subject.application && !subject.authenticated) {
            return Held {
                all: built_in,
                configured: Vec::new(),
                why: if name.is_empty() {
                    "nobody is named as the subject".to_string()
                } else {
                    format!("{name} did not authenticate")
                },
            };
        }
        let mut configured: Vec<String> = everything
            .iter()
            .filter(|one| !roles::is_built_in(one))
            .cloned()
            .collect();
        let mut why = String::new();
        if !subject.application {
            configured.retain(|one| roles::console_role_for(one).is_none());
            let realm = sts_core::realm::current_id();
            let roster = self.deps.roster.roles_of(&name, &realm);
            if !js::truthy(&roster) {
                why = format!(
                    "the console roster of the realm \"{realm}\" could not \
                     be read"
                );
            } else if roster.get("claimPending") == Some(&json!(true)) {
                why = format!(
                    "{name} is the bootstrap administrator and has not yet \
                     claimed the admin console by signing in to it with its \
                     password; until it has, its roles open the console \
                     alone"
                );
            } else {
                let holds = |r: &str| roster.get(r) == Some(&json!(true));
                for row in console_roles() {
                    if holds(row.console_role) {
                        configured.push(row.name.to_string());
                    }
                }
                for (console, role) in REPORT_ROLES_OF_ROSTER {
                    if holds(console) && !configured.iter().any(|c| c == role) {
                        configured.push(role.to_string());
                    }
                }
                if !roster.get("read").is_some_and(js::truthy) {
                    why = format!(
                        "{name} holds neither Admin Read nor Admin Write on \
                         the console roster of the realm \"{realm}\""
                    );
                } else if !roster.get("write").is_some_and(js::truthy) {
                    why = format!(
                        "{name} holds Admin Read but not Admin Write on the \
                         console roster of the realm \"{realm}\""
                    );
                }
            }
            if self.deps.ownership.owns_anything(&name) {
                for (role, _) in owner_roles() {
                    if !configured.iter().any(|c| c == role) {
                        configured.push(role.to_string());
                    }
                }
            }
        }
        let mut all = built_in;
        all.extend(configured.iter().cloned());
        Held {
            all,
            configured,
            why,
        }
    }

    /// `conferredOn(subject, clientId)`: the roles a client confers on a
    /// person signing in through it.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn conferred_on(
        &self,
        subject: &Subject,
        client_id: &str,
    ) -> Vec<String> {
        if client_id.is_empty()
            || subject.application
            || !subject.authenticated
            || js::trim(&subject.name).is_empty()
        {
            return Vec::new();
        }
        self.deps.roles.conferred_by(client_id)
    }

    /// `configuredRolesOf(subject)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn configured_roles_of(&self, subject: &Subject) -> Vec<String> {
        self.held_roles(subject).configured
    }

    /// `permissionsByRole()`: role → what it authorizes, in Node's key
    /// order (the stored roles, the native ones fixed, the owner roles).
    fn permissions_by_role(&self) -> Map<String, Value> {
        let mut out = Map::new();
        for row in self.deps.roles.all() {
            out.insert(row.name.clone(), json!(row.permissions));
        }
        for row in NATIVE_ROLES {
            out.insert(row.name.to_string(), json!([row.permission]));
        }
        for (role, permission) in owner_roles() {
            out.insert(role.to_string(), json!([permission]));
        }
        out
    }

    fn ssf_role_check(
        &self,
        role: &str,
        value: &str,
        who: &Subject,
        client: &str,
    ) -> (bool, String) {
        let Some(native) = NATIVE_ROLES.iter().find(|r| r.name == role) else {
            return (true, String::new());
        };
        if native.name != "SSF_READ" && native.name != "SSF_MANAGE" {
            return (true, String::new());
        }
        if native.permission != value {
            return (false, format!("{role} does not authorize {value}"));
        }
        if client.is_empty() {
            return (
                false,
                format!(
                    "no client is named, and {role} needs \
                the client to be a member"
                ),
            );
        }
        let Some(row) = self.deps.roles.read(role) else {
            return (false, format!("the role {role} could not be read"));
        };
        let wanted = js::lower(client);
        if !row.applications.iter().any(|a| js::lower(a) == wanted) {
            return (
                false,
                format!(
                    "the application \"{client}\" is not a \
                member of the role {role}"
                ),
            );
        }
        if who.application {
            return (true, String::new());
        }
        let groups: Vec<String> = self
            .deps
            .roles
            .groups_of(&who.name)
            .iter()
            .map(|g| js::lower(g))
            .collect();
        let in_group =
            row.groups.iter().any(|g| groups.contains(&js::lower(g)));
        let shown = if who.name.is_empty() {
            "the person".to_string()
        } else {
            who.name.clone()
        };
        (
            in_group,
            if in_group {
                String::new()
            } else {
                format!(
                    "{shown} is in none of the groups of the role {role} \
                ({})",
                    if row.groups.is_empty() {
                        "it lists none".to_string()
                    } else {
                        row.groups.join(", ")
                    }
                )
            },
        )
    }

    fn why_removed(
        &self,
        value: &str,
        held: &Held,
        who: &Subject,
        client: &str,
    ) -> String {
        let name = js::trim(&who.name).to_string();
        let nobody =
            name.is_empty() || (!who.application && !who.authenticated);
        if !held.why.is_empty() && nobody {
            return held.why.clone();
        }
        let on_roster = console_roles().iter().any(|r| r.permission == value);
        if on_roster && !held.why.is_empty() {
            return held.why.clone();
        }
        if let Some(ssf) = NATIVE_ROLES.iter().find(|r| {
            r.permission == value
                && (r.name == "SSF_READ" || r.name == "SSF_MANAGE")
        }) {
            let (stands, why) =
                self.ssf_role_check(ssf.name, value, who, client);
            if !stands {
                return why;
            }
        }
        format!(
            "{} holds no role authorizing {value}{}",
            if name.is_empty() {
                "an unnamed subject"
            } else {
                &name
            },
            if held.configured.is_empty() {
                String::new()
            } else {
                format!(" (holds {})", held.configured.join(", "))
            }
        )
    }

    /// `narrowScope(scope, subject, context)`: the scope with every
    /// permission the subject's roles do not authorize taken off.
    /// `context` is `{clientId, grant, stage, record}`.
    #[tracing::instrument(level = "debug", skip(self, context))]
    pub fn narrow_scope(
        &self,
        scope: &str,
        who: &Subject,
        context: &Value,
    ) -> Value {
        let unchanged = json!({"scope": scope, "removed": [],
                               "emptied": false, "why": ""});
        let values = split(scope);
        let gated: Vec<String> = values
            .iter()
            .filter(|v| self.is_gated(v))
            .cloned()
            .collect();
        let app_permissions: Vec<String> = if who.application {
            values
                .iter()
                .filter(|v| {
                    !gated.contains(v) && self.is_application_permission(v)
                })
                .cloned()
                .collect()
        } else {
            Vec::new()
        };
        if gated.is_empty() && app_permissions.is_empty() {
            return unchanged;
        }
        let client = js::or_empty(context.get("clientId"));
        let mut held = self.held_roles(who);
        for role in self.conferred_on(who, &client) {
            if !held.configured.contains(&role) {
                held.configured.push(role.clone());
                held.all.push(role);
            }
        }
        let authorizes = self.permissions_by_role();
        let facts: Vec<Value> = values
            .iter()
            .map(|value| {
                let is_gated = gated.contains(value);
                let authorizing: Vec<String> = authorizes
                    .iter()
                    .filter(|(role, perms)| {
                        perms.as_array().is_some_and(|p| {
                            p.iter().any(|one| one == &json!(value))
                        }) && self.ssf_role_check(role, value, who, &client).0
                    })
                    .map(|(role, _)| role.clone())
                    .collect();
                let mut attributes = vec![
                    fact(SCOPE_GATED, is_gated),
                    strings_fact(AUTHORIZING_ROLE, &authorizing),
                ];
                if app_permissions.contains(value) {
                    attributes.push(fact(SCOPE_APPLICATION_PERMISSION, true));
                }
                json!({"scope": value, "gated": is_gated,
                       "attributes": attributes})
            })
            .collect();
        let verdicts = self.deps.gate.check_scopes(&json!({
            "subject": {"kind": if who.application { "application" } else {
                    "user" },
                "name": who.name, "authenticated": who.authenticated},
            "application": client, "client": client,
            "grantType": js::or_empty(context.get("grant")),
            "protocol": "OAuth 2.0",
            "held": held.configured, "requested": values,
            "stage": js::or_empty(context.get("stage")),
            "facts": facts,
        }));
        let decided = |value: &str| -> (String, Option<ErrorCode>) {
            if let Some(v) = verdicts.iter().find(|v| v.scope == value) {
                return (v.verdict.clone(), v.code);
            }
            if gated.iter().any(|g| g == value) {
                return ("drop".into(), Some(codes::STS_ADMIN_0821));
            }
            if app_permissions.iter().any(|a| a == value) {
                return ("drop".into(), Some(codes::STS_OAUTH_0957));
            }
            ("keep".into(), None)
        };
        let refused = values.iter().any(|v| decided(v).0 == "refuse");
        let removed: Vec<String> = values
            .iter()
            .filter(|v| decided(v).0 != "keep")
            .cloned()
            .collect();
        if removed.is_empty() {
            return unchanged;
        }
        let kept: Vec<String> = values
            .iter()
            .filter(|v| !removed.contains(v))
            .cloned()
            .collect();
        let mut reasons: Vec<String> = Vec::new();
        for value in &removed {
            let why = self.why_removed(value, &held, who, &client);
            if !reasons.contains(&why) {
                reasons.push(why);
            }
        }
        let reason = reasons.join("; ");
        let answer = json!({
            "scope": kept.join(" "), "removed": removed,
            "emptied": kept.is_empty() || refused,
            "why": format!("the permission(s) {} cannot be issued: {reason}",
                           removed.join(", ")),
        });
        if context.get("record") == Some(&json!(false)) {
            return answer;
        }
        let code = decided(&removed[0]).1.unwrap_or(codes::STS_ADMIN_0821);
        self.deps.audit.failure(
            code,
            &json!({
                "actor": who.name, "protocol": "OAuth 2.0 / OIDC",
                "channel": "http", "target": removed.join(" "),
                "outcome": "refused",
                "summary": format!("the permission(s) {} were not issued to \
                    {}{}: {reason}", removed.join(", "),
                    if who.application { "the application " } else { "" },
                    if who.name.is_empty() { "an unnamed subject" } else {
                        &who.name }),
                "detail": {"client_id": client,
                    "grant": js::or_empty(context.get("grant")),
                    "subject_kind": if who.application { "application" } else {
                        "user" },
                    "removed": removed.join(" "), "why": reason},
            }),
        );
        answer
    }

    /// `isClientToken(claims)`: a client's own token.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn is_client_token(claims: &Value) -> bool {
        let client = js::or_empty(claims.get("client_id"));
        let sub = js::or_empty(claims.get("sub"));
        !client.is_empty()
            && (sub == client || sub == format!("urn:sts:client:{client}"))
    }

    /// `effectiveRoles(claims, carried)`: the roles a token's scopes still
    /// stand on, and the gated scopes no role authorizes any more.
    #[tracing::instrument(level = "debug", skip(self, claims))]
    pub fn effective_roles(&self, claims: &Value, carried: &[String]) -> Value {
        let client = RolePermissions::is_client_token(claims);
        let sub = js::or_empty(claims.get("sub"));
        let subject = if client {
            Subject {
                application: true,
                name: js::or_empty(claims.get("client_id")),
                authenticated: true,
            }
        } else {
            let gone = self.deps.subjects.subject_is_gone(&sub)
                && self.deps.mode.refuses_token_for_gone_subject();
            let name = if gone {
                String::new()
            } else {
                [
                    self.deps.subjects.name_for_subject(&sub),
                    js::or_empty(claims.get("username")),
                    js::or_empty(claims.get("preferred_username")),
                    sub.clone(),
                ]
                .into_iter()
                .find(|one| !one.is_empty())
                .unwrap_or_default()
            };
            Subject {
                application: false,
                name,
                authenticated: true,
            }
        };
        let mut held = self.held_roles(&subject);
        let confers = if client {
            String::new()
        } else {
            js::or_empty(claims.get("client_id"))
        };
        for role in self.conferred_on(&subject, &confers) {
            if !held.configured.contains(&role) {
                held.configured.push(role);
            }
        }
        let built_in: Vec<String> = self
            .deps
            .roles
            .roles_of(&Who {
                kind_application: subject.application,
                name: subject.name.clone(),
                authenticated: true,
                scopes: carried.to_vec(),
                ..Who::default()
            })
            .into_iter()
            .filter(|one| roles::is_built_in(one))
            .collect();
        let authorizes = self.permissions_by_role();
        let perms_of = |role: &str| -> Vec<String> {
            authorizes
                .get(role)
                .and_then(Value::as_array)
                .map(|l| l.iter().map(js::string).collect())
                .unwrap_or_default()
        };
        let effective: Vec<String> = held
            .configured
            .iter()
            .filter(|role| {
                let p = perms_of(role);
                p.is_empty() || p.iter().any(|one| carried.contains(one))
            })
            .cloned()
            .collect();
        let withdrawn: Vec<String> = carried
            .iter()
            .filter(|one| {
                self.is_gated(one)
                    && !held
                        .configured
                        .iter()
                        .any(|r| perms_of(r).contains(one))
            })
            .cloned()
            .collect();
        let roster_scope = withdrawn
            .iter()
            .any(|one| console_roles().iter().any(|r| r.permission == one));
        let why = if !held.why.is_empty()
            && (roster_scope || js::trim(&subject.name).is_empty())
        {
            held.why.clone()
        } else {
            format!(
                "{} holds no role authorizing {}",
                subject.name,
                withdrawn.join(", ")
            )
        };
        let mut roles_now = built_in;
        roles_now.extend(effective);
        json!({
            "roles": roles_now, "withdrawn": withdrawn, "why": why,
            "subject": {"kind": if subject.application { "application" }
                        else { "user" },
                        "name": subject.name, "authenticated": true},
        })
    }
}
