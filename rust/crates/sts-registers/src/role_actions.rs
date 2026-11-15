// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `POST /admin-api/roles/{action}`: `admin-core/admin_actions.ts`'s
//! `rolesAction()`, the act the console's Roles page and the management
//! API share (rule 7). Eleven actions over the [`Roles`] register, each
//! refusal with its code.
//!
//! **`add-member` IS NOT IDEMPOTENT** (#1299): a second add of a member the
//! role already lists, in any case, is refused `STS-ADMIN-0547` ("… already
//! holds …"), which the API answers 400. That is the opposite of the
//! console roster's `rbac/grant`, which answers `changed: false`, and of a
//! group's `add-member`, which does too; a caller that may repeat itself
//! reads the role first.
//!
//! A code a register put on its own refusal wins over this layer's
//! (`refusedBy()` / `innerCode()`), because the owner knows the condition.

use std::sync::Arc;

use serde_json::{json, Value};
use sts_core::errors::{codes, ErrorCode};

use crate::js;
use crate::outcome::Outcome;
use crate::port::{Applications, Audit};
use crate::roles::{self, Roles, APPLICATION_SEPARATOR, NATIVE_ROLES};

/// `ROLE_ACTIONS`.
pub const ROLE_ACTIONS: [&str; 11] = [
    "create-role",
    "delete-role",
    "add-member",
    "remove-member",
    "describe-role",
    "add-permission",
    "remove-permission",
    "add-conferring-client",
    "remove-conferring-client",
    "add-owner",
    "remove-owner",
];

/// `ROLE_MEMBER_KINDS`: the kind, its label and the record member.
pub const MEMBER_KINDS: [(&str, &str, &str); 3] = [
    ("user", "a person", "users"),
    ("group", "a group", "groups"),
    ("application", "an application", "applications"),
];

/// The role acts.
pub struct RoleActions {
    roles: Arc<Roles>,
    applications: Arc<dyn Applications>,
    audit: Arc<dyn Audit>,
}

fn refused(code: ErrorCode, errors: Vec<String>) -> Outcome {
    Outcome::marked(code, json!({"ok": false, "errors": errors}))
}

/// `this.refused(this.innerCode(result) || fallback, {ok: false,
/// errors: [result.why]})`.
fn handed_up(result: &Outcome, fallback: ErrorCode) -> Outcome {
    Outcome::marked(
        result.code.unwrap_or(fallback),
        json!({"ok": false, "errors": [result.why()]}),
    )
}

impl RoleActions {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(
        roles: Arc<Roles>,
        applications: Arc<dyn Applications>,
        audit: Arc<dyn Audit>,
    ) -> RoleActions {
        RoleActions {
            roles,
            applications,
            audit,
        }
    }

    fn audit(&self, action: &str, actor: &str, target: &str, detail: String) {
        self.audit.audit(&json!({
            "action": action, "actor": actor, "target": target,
            "protocol": "XACML", "channel": "http", "detail": detail,
        }));
    }

    fn write_back(&self, row: &roles::RoleRow, change: Value) -> Outcome {
        let mut record = json!({
            "description": row.description, "users": row.users,
            "groups": row.groups, "applications": row.applications,
            "permissions": row.permissions, "application": row.application,
            "displayName": row.display_name, "memberTypes": row.member_types,
        });
        if let (Some(map), Some(extra)) =
            (record.as_object_mut(), change.as_object())
        {
            for (k, v) in extra {
                map.insert(k.clone(), v.clone());
            }
        }
        self.roles.write(&row.name, &record)
    }

    /// `rolesAction(body, context)`.
    #[tracing::instrument(level = "debug", skip(self, body))]
    pub fn act(&self, body: &Value, actor: &str) -> Outcome {
        let field = |k: &str| js::trim(&js::or_empty(body.get(k))).to_string();
        let action = js::or_empty(body.get("action"));
        let name = field("role");
        let kind = field("kind");
        let member = field("member");
        let description = js::or_empty(body.get("description"));
        let member_types: Option<Vec<String>> = match body.get("memberTypes") {
            None => None,
            Some(Value::Array(items)) => {
                Some(items.iter().map(js::string).collect())
            }
            Some(other) => Some(js::split_on(&js::string(other), |c| {
                js::is_space(c) || c == ','
            })),
        };
        let display_name: Option<String> = body
            .get("displayName")
            .map(|v| js::trim(&js::string(v)).to_string());
        match action.as_str() {
            "create-role" => self.create(
                body,
                &name,
                &description,
                display_name,
                member_types,
                actor,
            ),
            "delete-role" => self.delete(&name, actor),
            "describe-role" => {
                let Some(row) = self.roles.read(&name) else {
                    return refused(
                        codes::STS_ADMIN_0543,
                        vec![format!("There is no role called \"{name}\".")],
                    );
                };
                let result = self.write_back(
                    &row,
                    json!({
                        "description": description,
                        "displayName": display_name
                            .clone()
                            .unwrap_or(row.display_name.clone()),
                        "memberTypes": member_types
                            .clone()
                            .unwrap_or(row.member_types.clone()),
                    }),
                );
                if result.is_ok() {
                    let said = match &member_types {
                        None => String::new(),
                        Some(t) => format!(
                            "; it may be held by {}",
                            if t.is_empty() {
                                "users and applications".to_string()
                            } else {
                                t.join(" and ")
                            }
                        ),
                    };
                    self.audit(
                        "roles.describe",
                        actor,
                        &name,
                        format!("described the role \"{name}\"{said}"),
                    );
                    return result;
                }
                handed_up(&result, codes::STS_ADMIN_0542)
            }
            "add-member" | "remove-member" => {
                self.member(&action, &name, &kind, &member, actor)
            }
            "add-permission" | "remove-permission" => {
                self.permission(&action, &name, &field("permission"), actor)
            }
            "add-conferring-client" | "remove-conferring-client" => {
                self.conferring(&action, &name, &field("client"), actor)
            }
            "add-owner" | "remove-owner" => {
                self.owner(&action, &name, &field("owner"), actor)
            }
            _ => refused(
                codes::STS_ADMIN_0500,
                vec![format!(
                    "Unknown action \"{action}\". The {} are: {}.",
                    js::number_word(ROLE_ACTIONS.len()),
                    ROLE_ACTIONS.join(", ")
                )],
            ),
        }
    }

    fn create(
        &self,
        body: &Value,
        name: &str,
        description: &str,
        display_name: Option<String>,
        member_types: Option<Vec<String>>,
        actor: &str,
    ) -> Outcome {
        let for_application =
            js::trim(&js::or_empty(body.get("application"))).to_string();
        if for_application.is_empty() && name.contains(APPLICATION_SEPARATOR) {
            return refused(
                codes::STS_ADMIN_0829,
                vec!["A realm-wide role's name may not contain \"@\": that \
                      is how an application's role is named \
                      (<role>@<application>). To make a role for one \
                      application, give `application` and the role's own \
                      name."
                    .to_string()],
            );
        }
        if !for_application.is_empty()
            && !js::truthy(&self.applications.get(&for_application))
        {
            return refused(
                codes::STS_ADMIN_0830,
                vec![format!(
                    "There is no application \"{for_application}\" in this \
                     realm to make a role for."
                )],
            );
        }
        let full = if for_application.is_empty() {
            name.to_string()
        } else {
            format!("{name}{APPLICATION_SEPARATOR}{for_application}")
        };
        if self.roles.read(&full).is_some() {
            return refused(
                codes::STS_ADMIN_0541,
                vec![format!(
                    "There is already a role called \"{full}\". Roles are \
                     edited in place — add a member to it rather than \
                     creating it again."
                )],
            );
        }
        let result = self.roles.write(
            &full,
            &json!({
                "description": description,
                "application": for_application,
                "displayName": display_name.unwrap_or_default(),
                "memberTypes": member_types.unwrap_or_default(),
            }),
        );
        if result.is_ok() {
            self.audit(
                "roles.create",
                actor,
                &full,
                format!(
                    "created the role \"{full}\"{}",
                    if for_application.is_empty() {
                        String::new()
                    } else {
                        format!(" for the application \"{for_application}\"")
                    }
                ),
            );
            return result;
        }
        handed_up(&result, codes::STS_ADMIN_0542)
    }

    fn delete(&self, name: &str, actor: &str) -> Outcome {
        let still: Vec<String> = self
            .applications
            .list()
            .iter()
            .map(|row| js::unless_null(row.get("identifier")))
            .filter(|id| {
                self.applications
                    .required_roles_of(id)
                    .iter()
                    .any(|one| one == name)
            })
            .collect();
        let result = self.roles.remove(name);
        if !result.is_ok() {
            return handed_up(&result, codes::STS_ADMIN_0542);
        }
        self.audit(
            "roles.delete",
            actor,
            name,
            format!(
                "deleted the role \"{name}\"{}",
                if still.is_empty() {
                    String::new()
                } else {
                    format!("; still required by {}", still.join(", "))
                }
            ),
        );
        let mut message = format!("The role \"{name}\" is gone.");
        if !still.is_empty() {
            message.push_str(&format!(
                " {} application(s) still require it and can now be issued \
                 nothing: {}. Clear appRequiredRole on each, or create the \
                 role again.",
                js::number_word(still.len()),
                still.join(", ")
            ));
        }
        Outcome::ok(json!({"ok": true, "name": name, "stillRequired": still,
                           "message": message}))
    }

    fn member(
        &self,
        action: &str,
        name: &str,
        kind: &str,
        member: &str,
        actor: &str,
    ) -> Outcome {
        let adding = action == "add-member";
        let Some(&(_, label, field)) =
            MEMBER_KINDS.iter().find(|(k, _, _)| *k == kind)
        else {
            let kinds: Vec<&str> = MEMBER_KINDS.iter().map(|k| k.0).collect();
            return refused(
                codes::STS_ADMIN_0544,
                vec![format!(
                    "\"{kind}\" is not a kind of member. There are three: {}.",
                    kinds.join(", ")
                )],
            );
        };
        if member.is_empty() {
            return refused(
                codes::STS_ADMIN_0545,
                vec![format!(
                    "`member` names {label} being {} the role, and it is \
                     required. `role` is the role's own name.",
                    if adding { "added to" } else { "removed from" }
                )],
            );
        }
        let Some(row) = self.roles.read(name) else {
            if roles::is_built_in(name) {
                return refused(
                    codes::STS_ADMIN_0546,
                    vec![format!(
                        "\"{name}\" is a BUILT-IN role. It is COMPUTED from \
                         the context of each decision rather than stored, so \
                         it has no membership to edit — everybody who \
                         matches it holds it, always. Create a role of your \
                         own to give somebody something they do not already \
                         have."
                    )],
                );
            }
            return refused(
                codes::STS_ADMIN_0543,
                vec![format!(
                    "There is no role called \"{name}\". Create it first."
                )],
            );
        };
        let mut users = row.users.clone();
        let mut groups = row.groups.clone();
        let mut applications = row.applications.clone();
        let list = match field {
            "users" => &mut users,
            "groups" => &mut groups,
            _ => &mut applications,
        };
        let wanted = js::lower(member);
        let at = list.iter().position(|one| js::lower(one) == wanted);
        if adding {
            if at.is_some() {
                return refused(
                    codes::STS_ADMIN_0547,
                    vec![format!(
                        "\"{member}\" already holds \"{name}\" as {label}."
                    )],
                );
            }
            list.push(member.to_string());
        } else {
            let Some(at) = at else {
                return refused(
                    codes::STS_ADMIN_0548,
                    vec![format!(
                        "\"{member}\" does not hold \"{name}\" as {label}."
                    )],
                );
            };
            list.remove(at);
        }
        let result = self.write_back(
            &row,
            json!({"users": users, "groups": groups,
                   "applications": applications}),
        );
        if !result.is_ok() {
            return handed_up(&result, codes::STS_ADMIN_0542);
        }
        self.audit(
            if adding {
                "roles.grant"
            } else {
                "roles.revoke"
            },
            actor,
            member,
            format!(
                "{} {label} \"{member}\" the role \"{name}\"{}",
                if adding { "gave" } else { "took" },
                if adding { "" } else { " away" }
            ),
        );
        Outcome::ok(json!({
            "ok": true, "role": name, "kind": kind, "member": member,
            "message": if adding {
                format!("\"{member}\" now holds \"{name}\".")
            } else {
                format!("\"{member}\" no longer holds \"{name}\".")
            },
        }))
    }

    fn permission(
        &self,
        action: &str,
        name: &str,
        permission: &str,
        actor: &str,
    ) -> Outcome {
        let adding = action == "add-permission";
        let Some(row) = self.roles.read(name) else {
            return if roles::is_built_in(name) {
                refused(
                    codes::STS_ADMIN_0546,
                    vec![format!(
                        "\"{name}\" is a BUILT-IN role. It is computed from \
                         the context of each decision and authorizes nothing \
                         by itself."
                    )],
                )
            } else {
                refused(
                    codes::STS_ADMIN_0543,
                    vec![format!(
                        "There is no role called \"{name}\". Create it first."
                    )],
                )
            };
        };
        if row.native {
            return refused(
                codes::STS_ADMIN_0823,
                vec![format!(
                    "\"{name}\" authorizes a permission of this service \
                     itself, and what it authorizes is fixed: {}. A native \
                     role authorizing anything else would make the service's \
                     own permissions mean something they do not.",
                    row.permissions.join(", ")
                )],
            );
        }
        if permission.is_empty() {
            return refused(
                codes::STS_ADMIN_0824,
                vec!["`permission` names what the role authorizes: the full \
                      identifier a client asks for, the resource's \
                      oauthPermissionBaseUri followed by the permission name \
                      (https://api.example/write)."
                    .to_string()],
            );
        }
        let at = row.permissions.iter().position(|p| p == permission);
        let mut gated = Value::Null;
        if adding {
            if let Some(native) =
                NATIVE_ROLES.iter().find(|one| one.permission == permission)
            {
                return refused(
                    codes::STS_ADMIN_0825,
                    vec![format!(
                        "\"{permission}\" is a native permission of this \
                         service and is authorized by {} alone. Add the \
                         member to {}{}.",
                        native.name,
                        native.name,
                        if native.console_role.is_empty() {
                            ""
                        } else {
                            " — for a person, grant the console role on \
                             /admin/rbac"
                        }
                    )],
                );
            }
            gated = self.applications.role_gating_for(permission);
            let owner = js::unless_null(gated.get("identifier"));
            if js::truthy(&gated)
                && !row.application.is_empty()
                && owner != row.application
            {
                return refused(
                    codes::STS_ADMIN_0831,
                    vec![format!(
                        "\"{name}\" belongs to the application \"{}\", and \
                         may authorize only a permission that application \
                         defines; \"{permission}\" is \"{owner}\"'s (#310).",
                        row.application
                    )],
                );
            }
            if !js::truthy(&gated) {
                return refused(
                    codes::STS_ADMIN_0826,
                    vec![format!(
                        "No application in this realm defines the permission \
                         \"{permission}\", and a permission must be DEFINED \
                         before a role can authorize it. Give the resource \
                         application an oauthPermissionBaseUri and an \
                         oauthPermission, then name the two joined together."
                    )],
                );
            }
            if at.is_some() {
                return refused(
                    codes::STS_ADMIN_0827,
                    vec![format!(
                        "\"{name}\" already authorizes \"{permission}\"."
                    )],
                );
            }
        } else if at.is_none() {
            return refused(
                codes::STS_ADMIN_0828,
                vec![format!(
                    "\"{name}\" does not authorize \"{permission}\"."
                )],
            );
        }
        let mut permissions = row.permissions.clone();
        match at {
            Some(i) if !adding => {
                permissions.remove(i);
            }
            _ => permissions.push(permission.to_string()),
        }
        let result = self.write_back(&row, json!({"permissions": permissions}));
        if !result.is_ok() {
            return handed_up(&result, codes::STS_ADMIN_0542);
        }
        self.audit(
            if adding {
                "roles.authorize"
            } else {
                "roles.unauthorize"
            },
            actor,
            permission,
            format!(
                "the role \"{name}\" {} \"{permission}\"",
                if adding {
                    "now authorizes"
                } else {
                    "no longer authorizes"
                }
            ),
        );
        let is_gated = gated.get("gated").cloned();
        let not_gated =
            js::truthy(&gated) && !is_gated.as_ref().is_some_and(js::truthy);
        let message = if adding {
            let mut m = format!("\"{name}\" now authorizes \"{permission}\".");
            if not_gated {
                m.push_str(&format!(
                    " Its resource application, {}, does not gate it yet \
                     (oauthRoleGatedPermission), so it is still issued to \
                     anybody who may ask for it until it does.",
                    js::unless_null(gated.get("identifier"))
                ));
            }
            m
        } else {
            format!("\"{name}\" no longer authorizes \"{permission}\".")
        };
        let mut answer = json!({"ok": true, "role": name,
                                "permission": permission});
        if js::truthy(&gated) {
            if let (Some(map), Some(g)) = (answer.as_object_mut(), is_gated) {
                map.insert("gated".into(), g);
            }
        }
        if let Some(map) = answer.as_object_mut() {
            map.insert("message".into(), json!(message));
        }
        Outcome::ok(answer)
    }

    fn conferring(
        &self,
        action: &str,
        name: &str,
        client: &str,
        actor: &str,
    ) -> Outcome {
        let adding = action == "add-conferring-client";
        let Some(row) = self.roles.read(name) else {
            return if roles::is_built_in(name) {
                refused(
                    codes::STS_ADMIN_0546,
                    vec![format!(
                        "\"{name}\" is a BUILT-IN role, computed from the \
                         context of each decision; no client can confer it."
                    )],
                )
            } else {
                refused(
                    codes::STS_ADMIN_0543,
                    vec![format!(
                        "There is no role called \"{name}\". Create it first."
                    )],
                )
            };
        };
        if client.is_empty() {
            return refused(
                codes::STS_ADMIN_0845,
                vec!["`client` names the application that confers the role: \
                      its client_id in this realm."
                    .to_string()],
            );
        }
        let mut conferring = row.conferred_by.clone();
        let at = conferring.iter().position(|c| c == client);
        if adding {
            if !js::truthy(&self.applications.get(client)) {
                return refused(
                    codes::STS_ADMIN_0845,
                    vec![format!(
                        "There is no application \"{client}\" in this realm \
                         to confer \"{name}\"."
                    )],
                );
            }
            if at.is_some() {
                return refused(
                    codes::STS_ADMIN_0846,
                    vec![format!("\"{client}\" already confers \"{name}\".")],
                );
            }
            conferring.push(client.to_string());
        } else {
            let Some(at) = at else {
                return refused(
                    codes::STS_ADMIN_0847,
                    vec![format!("\"{client}\" does not confer \"{name}\".")],
                );
            };
            conferring.remove(at);
        }
        let result = self.write_back(&row, json!({"conferredBy": conferring}));
        if !result.is_ok() {
            return handed_up(&result, codes::STS_ADMIN_0542);
        }
        self.audit(
            if adding {
                "roles.confer"
            } else {
                "roles.unconfer"
            },
            actor,
            client,
            format!(
                "\"{client}\" {} the role \"{name}\" on everybody signing in \
                 through it",
                if adding {
                    "now confers"
                } else {
                    "no longer confers"
                }
            ),
        );
        Outcome::ok(json!({
            "ok": true, "role": name, "client": client,
            "message": if adding {
                format!("\"{client}\" now confers \"{name}\" on everybody \
                         who signs in through it.")
            } else {
                format!("\"{client}\" no longer confers \"{name}\".")
            },
        }))
    }

    fn owner(
        &self,
        action: &str,
        name: &str,
        owner: &str,
        actor: &str,
    ) -> Outcome {
        let adding = action == "add-owner";
        let result = if adding {
            self.roles.add_owner(name, owner)
        } else {
            self.roles.remove_owner(name, owner)
        };
        if !result.is_ok() {
            return handed_up(
                &result,
                if adding {
                    codes::STS_ADMIN_0854
                } else {
                    codes::STS_ADMIN_0855
                },
            );
        }
        if result.answer.get("changed").is_some_and(js::truthy) {
            let role = js::unless_null(result.answer.get("role"));
            let who = js::unless_null(result.answer.get("owner"));
            self.audit(
                if adding {
                    "roles.add-owner"
                } else {
                    "roles.remove-owner"
                },
                actor,
                &role,
                format!(
                    "{} {who}{} the role \"{role}\"",
                    if adding { "made" } else { "took" },
                    if adding {
                        " an owner of"
                    } else {
                        " off the owners of"
                    }
                ),
            );
        }
        result
    }
}
