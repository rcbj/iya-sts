// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE CONFIGURED PERMISSION REGISTER (`common/app_permissions.ts`, rule
//! 3s): which application exposes which permission (`oauthPermission`
//! under its `oauthPermissionBaseUri`), and which client holds a grant of
//! one (`oauthDelegatedPermission`). Everything here is a READING of
//! application entries, and every change is one `updateApplication()` on
//! the entry named — the register has no store of its own, which is the
//! whole of its argument.
//!
//! **DEFINING A PERMISSION GRANTS IT TO NOBODY**, and **REMOVING ONE
//! REVOKES NOTHING**: the grants that named it become DANGLING and are
//! reported, never rewritten, because that would be this act writing to
//! entries the caller did not name.
//!
//! The three helpers of `common/applications.js` it leans on — a base made
//! to end in a separator, a stored value split into name and description,
//! the permissions an entry exposes — are pure and live here; the rest of
//! the application register is the [`Applications`] port.

use std::sync::Arc;

use serde_json::{json, Map, Value};
use sts_core::errors::codes;

use crate::js;
use crate::outcome::Outcome;
use crate::port::{Applications, Marked};

/// `applications.permissionBaseOf(value)`: the base, ending in `/`, `#` or
/// `:` (a `/` added when it does not).
#[tracing::instrument(level = "debug", skip_all)]
pub fn permission_base_of(value: Option<&Value>) -> String {
    let text = js::trim(&js::unless_null(value)).to_string();
    if text.is_empty() {
        return text;
    }
    if text.ends_with(['/', '#', ':']) {
        text
    } else {
        format!("{text}/")
    }
}

/// `applications.permissionValueOf(name, description)`: `name|description`.
#[tracing::instrument(level = "debug")]
pub fn permission_value_of(name: &str, description: &str) -> String {
    let leaf = js::trim(name);
    let what = js::trim(description);
    if what.is_empty() {
        leaf.to_string()
    } else {
        format!("{leaf}|{what}")
    }
}

/// `valuesOf(value)`: a member as a list of non-empty strings.
#[tracing::instrument(level = "debug", skip_all)]
pub fn values_of(value: Option<&Value>) -> Vec<String> {
    match value {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(s)) if s.is_empty() => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(js::string)
            .filter(|one| !one.is_empty())
            .collect(),
        Some(one) => vec![js::string(one)]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect(),
    }
}

/// `applications.permissionsOf(source)`: `{name, description, id, raw}`
/// per `oauthPermission` value.
#[tracing::instrument(level = "debug", skip_all)]
pub fn permissions_of(source: &Value) -> Vec<Value> {
    let fields = &source["fields"];
    let base = permission_base_of(fields.get("oauthPermissionBaseUri"));
    values_of(fields.get("oauthPermission"))
        .into_iter()
        .map(|value| {
            let (name, description) = match value.find('|') {
                Some(at) => (
                    js::trim(&value[..at]).to_string(),
                    js::trim(&value[at + 1..]).to_string(),
                ),
                None => (js::trim(&value).to_string(), String::new()),
            };
            let id = if base.is_empty() {
                String::new()
            } else {
                format!("{base}{name}")
            };
            json!({"name": name, "description": description, "id": id,
                   "raw": value})
        })
        .collect()
}

/// The permission register.
pub struct AppPermissions {
    applications: Arc<dyn Applications>,
}

fn with_message(result: Marked, message: String) -> Outcome {
    let mut answer = result.value;
    if let Some(map) = answer.as_object_mut() {
        map.insert("message".into(), json!(message));
    }
    Outcome {
        answer,
        code: result.code,
    }
}

fn handed(result: Marked) -> Outcome {
    Outcome {
        answer: result.value,
        code: result.code,
    }
}

impl AppPermissions {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(applications: Arc<dyn Applications>) -> AppPermissions {
        AppPermissions { applications }
    }

    /// `register()`: every exposed permission, every grant, and the
    /// counts the delegation page draws.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn register(&self) -> Value {
        let rows = self.applications.list();
        let mut resources: Vec<Map<String, Value>> = Vec::new();
        for row in &rows {
            let fields = &row["fields"];
            let base = permission_base_of(fields.get("oauthPermissionBaseUri"));
            let permissions = permissions_of(row);
            if base.is_empty() && permissions.is_empty() {
                continue;
            }
            let identifier = js::unless_null(row.get("identifier"));
            let name = match js::or_empty(row.get("name")) {
                n if n.is_empty() => identifier.clone(),
                n => n,
            };
            let mut resource = Map::new();
            resource.insert("identifier".into(), json!(identifier));
            resource.insert("name".into(), json!(name));
            resource.insert("baseUri".into(), json!(base));
            resource.insert(
                "rawBaseUri".into(),
                json!(js::or_empty(fields.get("oauthPermissionBaseUri"))),
            );
            resource.insert(
                "permissions".into(),
                json!(permissions
                    .iter()
                    .map(|p| json!({"name": p["name"],
                    "description": p["description"], "id": p["id"],
                    "raw": p["raw"], "grantedTo": []}))
                    .collect::<Vec<_>>()),
            );
            resource.insert("grantsHeld".into(), json!(0));
            resources.push(resource);
        }
        let mut grants: Vec<Value> = Vec::new();
        for row in &rows {
            let fields = &row["fields"];
            let held = match fields.get("oauthDelegatedPermission") {
                Some(Value::Array(l)) => l.clone(),
                None | Some(Value::Null) => Vec::new(),
                Some(one) => vec![one.clone()],
            };
            let asked: Vec<String> = match fields.get("oauthScope") {
                Some(Value::Array(l)) => l.iter().map(js::string).collect(),
                None | Some(Value::Null) => Vec::new(),
                Some(one) => vec![js::string(one)],
            };
            let client = js::unless_null(row.get("identifier"));
            let client_name = match js::or_empty(row.get("name")) {
                n if n.is_empty() => client.clone(),
                n => n,
            };
            for value in held {
                let id = js::string(&value);
                let mut known: Option<(usize, usize)> = None;
                for (ri, r) in resources.iter().enumerate() {
                    if let Some(list) = r["permissions"].as_array() {
                        if let Some(pi) = list.iter().position(|p| {
                            p["id"] == json!(id) && !id.is_empty()
                        }) {
                            known = Some((ri, pi));
                        }
                    }
                }
                let was_asked = asked.contains(&id);
                let grant = match known {
                    Some((ri, pi)) => {
                        let r = &resources[ri];
                        let p = &r["permissions"][pi];
                        json!({"client": client, "clientName": client_name,
                            "permissionId": id, "resource": r["identifier"],
                            "resourceName": r["name"], "baseUri": r["baseUri"],
                            "permissionName": p["name"],
                            "description": p["description"],
                            "dangling": false, "asked": was_asked})
                    }
                    None => json!({"client": client,
                        "clientName": client_name, "permissionId": id,
                        "resource": "", "resourceName": "", "baseUri": "",
                        "permissionName": "", "description": "",
                        "dangling": true, "asked": was_asked}),
                };
                grants.push(grant);
                if let Some((ri, pi)) = known {
                    let r = &mut resources[ri];
                    if let Some(p) = r
                        .get_mut("permissions")
                        .and_then(|l| l.get_mut(pi))
                        .and_then(|p| p.get_mut("grantedTo"))
                        .and_then(Value::as_array_mut)
                    {
                        p.push(json!({"identifier": client,
                            "name": client_name, "asked": was_asked}));
                    }
                    let n = r["grantsHeld"].as_u64().unwrap_or(0) + 1;
                    r.insert("grantsHeld".into(), json!(n));
                }
            }
        }
        resources.sort_by(|a, b| {
            js::locale_compare(
                &js::string(&a["identifier"]),
                &js::string(&b["identifier"]),
            )
        });
        grants.sort_by(|a, b| {
            js::locale_compare(
                &js::string(&a["client"]),
                &js::string(&b["client"]),
            )
            .then_with(|| {
                js::locale_compare(
                    &js::string(&a["permissionId"]),
                    &js::string(&b["permissionId"]),
                )
            })
        });
        let mut permissions: Vec<Value> = Vec::new();
        for r in &resources {
            for p in r["permissions"].as_array().cloned().unwrap_or_default() {
                permissions.push(json!({"resource": r["identifier"],
                    "resourceName": r["name"], "baseUri": r["baseUri"],
                    "name": p["name"], "description": p["description"],
                    "id": p["id"], "raw": p["raw"],
                    "grantedTo": p["grantedTo"]}));
            }
        }
        let mut clients: Vec<String> = Vec::new();
        for g in &grants {
            let c = js::string(&g["client"]);
            if !clients.contains(&c) {
                clients.push(c);
            }
        }
        let count = |f: &dyn Fn(&Value) -> bool, l: &[Value]| {
            l.iter().filter(|one| f(one)).count()
        };
        json!({
            "resources": resources,
            "counts": {
                "resources": resources.len(),
                "permissions": permissions.len(),
                "unidentified": count(&|p| p["id"] == json!(""), &permissions),
                "grants": grants.len(),
                "dangling": count(&|g| g["dangling"] == json!(true), &grants),
                "unused": count(&|g| g["asked"] != json!(true)
                    && g["dangling"] != json!(true), &grants),
                "ungranted": count(&|p| p["grantedTo"].as_array()
                    .is_none_or(Vec::is_empty), &permissions),
                "clients": clients.len(),
            },
            "permissions": permissions,
            "grants": grants,
        })
    }

    /// `forApplication(identifier)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn for_application(&self, identifier: &str) -> Value {
        let wanted = js::trim(identifier);
        let all = self.register();
        let pick = |list: &str, key: &str| -> Vec<Value> {
            all[list]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|one| one[key] == json!(wanted))
                .collect()
        };
        json!({"identifier": wanted,
               "exposes": pick("permissions", "resource"),
               "holds": pick("grants", "client"),
               "grantedToOthers": pick("grants", "resource")})
    }

    /// `setBaseUri(resource, value, actor)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn set_base_uri(
        &self,
        resource: &str,
        value: &str,
        actor: &str,
    ) -> Outcome {
        let asked = js::trim(value).to_string();
        let result = self.applications.update_application(
            resource,
            &json!({
            "attribute": "oauthPermissionBaseUri", "mode": "set",
            "value": asked, "actor": actor}),
        );
        if !result.value.get("ok").is_some_and(js::truthy) {
            return handed(result);
        }
        let normalised = permission_base_of(Some(&json!(asked)));
        let message = if asked.is_empty() {
            format!(
                "\"{resource}\" no longer has a permission base URI. Any \
                permission still on the entry has no identifier now and no \
                client can ask for it — /admin/delegation lists those rather \
                than hiding them. Grants already made are unaffected on the \
                clients holding them and become DANGLING, which is the same \
                honest state."
            )
        } else {
            format!(
                "\"{resource}\" exposes its permissions under \
                {normalised}{}A permission called `write` on it is now \
                `{normalised}write`, which is what a client puts in a `scope` \
                and what an access token asking for it is AUDIENCED to.",
                if normalised == asked {
                    ". ".to_string()
                } else {
                    format!(
                        " — a trailing separator was added, because a \
                        permission identifier is the base followed by the \
                        name and \"{asked}\" + \"write\" would otherwise \
                        read as one word. "
                    )
                }
            )
        };
        with_message(result, message)
    }

    /// `definePermission(resource, name, description, actor)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn define_permission(
        &self,
        resource: &str,
        name: &str,
        description: &str,
        actor: &str,
    ) -> Outcome {
        let leaf = js::trim(name).to_string();
        let value = permission_value_of(&leaf, description);
        let result = self.applications.update_application(
            resource,
            &json!({
            "attribute": "oauthPermission", "mode": "add", "value": value,
            "actor": actor}),
        );
        if !result.value.get("ok").is_some_and(js::truthy) {
            return handed(result);
        }
        let base = permission_base_of(
            result.value["application"]["fields"].get("oauthPermissionBaseUri"),
        );
        let message = format!(
            "\"{resource}\" now exposes the permission \
            `{leaf}`, identified by `{base}{leaf}`. NOTHING HOLDS IT YET — \
            defining a permission grants it to nobody, which is the ordering \
            this feature is built on. Grant it to a client and a request \
            carrying `{base}{leaf}` in its `scope` produces an access token \
            audienced to {base} with `{leaf}` on its scope claim."
        );
        with_message(result, message)
    }

    /// `removePermission(resource, name, actor)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn remove_permission(
        &self,
        resource: &str,
        name: &str,
        actor: &str,
    ) -> Outcome {
        let leaf = js::trim(name).to_string();
        let entry = self.applications.get(resource);
        if !js::truthy(&entry) {
            return Outcome::marked(
                codes::STS_REG_0021,
                json!({"ok": false, "errors": [format!("There is no \
                    application called \"{resource}\" in this registry.")]}),
            );
        }
        let defined = permissions_of(&entry);
        let Some(found) = defined.iter().find(|p| p["name"] == json!(leaf))
        else {
            let names: Vec<String> =
                defined.iter().map(|p| js::string(&p["name"])).collect();
            return Outcome::marked(
                codes::STS_REG_0027,
                json!({"ok": false, "errors": [format!("\"{resource}\" \
                    defines no permission called \"{leaf}\". It defines: {}.",
                    if names.is_empty() { "(none)".to_string() } else {
                        names.join(", ") })]}),
            );
        };
        let found = found.clone();
        let result = self.applications.update_application(
            resource,
            &json!({
            "attribute": "oauthPermission", "mode": "remove",
            "value": found["raw"], "actor": actor}),
        );
        if !result.value.get("ok").is_some_and(js::truthy) {
            return handed(result);
        }
        let stranded: Vec<String> = self.register()["grants"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|g| g["permissionId"] == found["id"])
            .map(|g| js::string(&g["client"]))
            .collect();
        let id = js::string(&found["id"]);
        let message = format!(
            "\"{resource}\" no longer exposes `{leaf}`. {}",
            if stranded.is_empty() {
                "Nothing was holding it, so no grant was stranded.".to_string()
            } else {
                format!(
                    "<strong>{} grant(s) still name `{id}` and are now \
                    DANGLING</strong> — on {}. They were NOT removed, \
                    deliberately: revoking them would be this action writing \
                    to entries you did not name. Revoke each one, or define \
                    the permission again and they resolve exactly as before.",
                    stranded.len(),
                    stranded.join(", ")
                )
            }
        );
        with_message(result, message)
    }

    /// `grant(client, permissionId, actor)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn grant(
        &self,
        client: &str,
        permission_id: &str,
        actor: &str,
    ) -> Outcome {
        let id = js::trim(permission_id).to_string();
        let result = self.applications.update_application(
            client,
            &json!({
            "attribute": "oauthDelegatedPermission", "mode": "add",
            "value": id, "actor": actor}),
        );
        if !result.value.get("ok").is_some_and(js::truthy) {
            return handed(result);
        }
        let defines = self.applications.for_permission(&id);
        let known = js::truthy(&defines);
        let message = format!(
            "\"{client}\" is granted `{id}`{}. A request \
            from it carrying that string in `scope` produces an access token \
            audienced to {} with `{}` on its scope claim. In product mode an \
            ungranted permission is refused, so this grant is what lets it \
            through; in development it was already producing one — the grant \
            is recorded and reported and refuses nothing unless \
            `oauth2.delegatedPermissionsEnforced` is on.",
            if known {
                format!(
                    ", which \"{}\" exposes",
                    js::unless_null(defines.get("identifier"))
                )
            } else {
                String::new()
            },
            if known {
                js::unless_null(defines.get("baseUri"))
            } else {
                "the permission's base URI".to_string()
            },
            if known {
                js::unless_null(defines.get("name"))
            } else {
                id.clone()
            }
        );
        with_message(result, message)
    }

    /// `revoke(client, permissionId, actor)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn revoke(
        &self,
        client: &str,
        permission_id: &str,
        actor: &str,
    ) -> Outcome {
        let id = js::trim(permission_id).to_string();
        let result = self.applications.update_application(
            client,
            &json!({
            "attribute": "oauthDelegatedPermission", "mode": "remove",
            "value": id, "actor": actor}),
        );
        if !result.value.get("ok").is_some_and(js::truthy) {
            return handed(result);
        }
        let message = format!(
            "\"{client}\" no longer holds `{id}`. In \
            product mode its next request for it is refused invalid_scope. \
            In development with `oauth2.delegatedPermissionsEnforced` OFF \
            this changes nothing about what it is issued — the permission \
            still becomes an audience and a scope, and /admin/delegation now \
            shows those requests as UNGRANTED, which is the state the \
            setting turns into a refusal."
        );
        with_message(result, message)
    }
}

/// `PERMISSION_ACTIONS`.
pub const PERMISSION_ACTIONS: [&str; 5] = [
    "set-permission-base",
    "define-permission",
    "remove-permission",
    "grant-permission",
    "revoke-permission",
];

impl AppPermissions {
    /// `permissionsAction(body, context)`: `POST /admin-api/permissions/
    /// {action}`. A code the register put on its refusal wins over this
    /// door's `STS-ADMIN-0516`.
    #[tracing::instrument(level = "debug", skip(self, body))]
    pub fn act(&self, body: &Value, actor: &str) -> Outcome {
        let action = js::or_empty(body.get("action"));
        let resource =
            js::trim(&js::or_empty(body.get("resource"))).to_string();
        let client = js::trim(&js::or_empty(body.get("client"))).to_string();
        let refused = |code, text: &str| {
            Outcome::marked(code, json!({"ok": false, "errors": [text]}))
        };
        if [
            "set-permission-base",
            "define-permission",
            "remove-permission",
        ]
        .contains(&action.as_str())
            && resource.is_empty()
        {
            return refused(
                codes::STS_ADMIN_0514,
                "Which application exposes \
                it? Send `resource` with the identifier exactly as the \
                registry holds it — this is the application whose API the \
                permission belongs to, not the one that will ask for it.",
            );
        }
        if ["grant-permission", "revoke-permission"].contains(&action.as_str())
            && client.is_empty()
        {
            return refused(
                codes::STS_ADMIN_0515,
                "Which application holds \
                it? Send `client` with the identifier exactly as the registry \
                holds it — this is the application that will name the \
                permission in a `scope`, not the one that exposes it.",
            );
        }
        let text = |k: &str| js::or_empty(body.get(k));
        let mut result = match action.as_str() {
            "set-permission-base" => self.set_base_uri(
                &resource,
                &js::unless_null(body.get("baseUri")),
                actor,
            ),
            "define-permission" => self.define_permission(
                &resource,
                &text("name"),
                &text("description"),
                actor,
            ),
            "remove-permission" => {
                self.remove_permission(&resource, &text("name"), actor)
            }
            "grant-permission" => {
                self.grant(&client, &text("permission"), actor)
            }
            "revoke-permission" => {
                self.revoke(&client, &text("permission"), actor)
            }
            _ => {
                return refused(
                    codes::STS_ADMIN_0500,
                    &format!(
                        "Unknown action \"{action}\". The {} are: {}.",
                        js::number_word(PERMISSION_ACTIONS.len()),
                        PERMISSION_ACTIONS.join(", ")
                    ),
                )
            }
        };
        if result.refused() && result.code.is_none() {
            result.code = Some(codes::STS_ADMIN_0516);
        }
        result
    }
}
