// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE CONSOLE'S FIRST SCREEN (#446, #454): what the static console asks
//! before it draws anything, ported from `mgmt-api/admin_api.ts` and
//! `admin-ui/admin.ts`.
//!
//! | Operation | Node |
//! |---|---|
//! | `GET /admin-api/me` | `AdminApi.meJson()` |
//! | `GET /admin-api/console` | `consoleGateOf()`, `AdminConsole.shellJson()` and `consoleLocale()` |
//! | `GET /admin-api/console/dashboard` | `AdminConsole.dashboardJson()`, the console twin of `GET /admin-api/status` |
//! | `GET /admin-api/announcements` | `SsfReceivers.announcementsFor('admin-console')` |
//!
//! **`me` ANSWERS WHAT THE GATE DECIDED**, never a second reading: the
//! caller, its scopes and its roles are the [`Caller`] the gate let in, so
//! the answer cannot disagree with what the next call will be allowed. The
//! roster is asked only for what the gate does not decide (whether the
//! console is still open, the bootstrap administrator's state), for a
//! person, in the token's realm.
//!
//! What these read outside this crate — the roster, the photo's path, the
//! process's runtime facts, the store's status, the language negotiation
//! and its catalogs, the realm's issuer, the announcements — is
//! [`ConsolePorts`], each with the answer a process with none of them gives.

use axum::http::HeaderMap;
use serde_json::{json, Map, Value as Json};

use crate::gate::{Caller, DEFAULT_REALM};
use crate::router::Services;
use crate::tables::tables;

/// What the console's screens read outside this crate.
pub trait ConsolePorts: Send + Sync {
    /// `rbac.rolesOf(name, realm)`: the roster's answer, or `None` when it
    /// cannot be read.
    fn roster(&self, name: &str, realm: &str) -> Option<Json> {
        let _ = (name, realm);
        None
    }
    /// `rbac.available()`: whether a directory holds the roster.
    fn roster_available(&self) -> bool {
        false
    }
    /// `ProfilePhoto.pathFor(username)`: this realm's copy, or ''.
    fn photo_path(&self, username: &str) -> String {
        let _ = username;
        String::new()
    }
    /// `AdminConsole.runtimeFacts()`.
    fn runtime_facts(&self) -> Json {
        json!({})
    }
    /// `persistence.status()`'s `enabled` and `mode`.
    fn persistence(&self) -> (bool, String) {
        (false, String::new())
    }
    /// `PageLocale.consoleData()` (or `consoleLanguage()` with
    /// `as_files`) for the console's client and this person.
    fn locale(
        &self,
        headers: &HeaderMap,
        username: &str,
        as_files: bool,
    ) -> Json {
        let _ = (headers, username, as_files);
        Json::Null
    }
    /// `IssuerNames.issuer()`: the realm's one issuer, in every protocol.
    fn issuer(&self, realm_base: &str) -> String {
        realm_base.to_string()
    }
    /// `announcementsFor(surface, since)`.
    fn announcements(&self, surface: &str, since: i64) -> Json {
        let _ = (surface, since);
        json!({ "now": 0, "everyMs": 0, "announcements": [] })
    }
}

/// A process with none of the console's ports.
pub struct NoConsole;

impl ConsolePorts for NoConsole {}

fn text(settings: &sts_core::settings::Settings, key: &str) -> Json {
    Json::from(settings.value_of(key).as_str().to_string())
}

fn truthy(v: Option<&Json>) -> bool {
    match v {
        None | Some(Json::Null) => false,
        Some(Json::Bool(b)) => *b,
        Some(Json::String(s)) => !s.is_empty(),
        Some(Json::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(_) => true,
    }
}

/// `AdminScope.pageVisible(state, path)`: a realm administrator does not
/// reach a service page, or anything under one.
#[tracing::instrument(level = "debug")]
pub fn page_visible(authority: Option<&str>, path: &str) -> bool {
    if authority != Some("realm") {
        return true;
    }
    !tables().service_pages.iter().any(|prefix| {
        path == prefix || path.starts_with(&format!("{}/", prefix))
    })
}

/// `AdminConsole.visibleSections(state)`: every section for a service
/// administrator; for a realm's, what is left of each section, at any
/// depth, a group or a section with nothing left dropped.
#[tracing::instrument(level = "debug")]
pub fn visible_sections(authority: Option<&str>) -> Json {
    let all = tables().console_sections.clone();
    if authority != Some("realm") {
        return all;
    }
    fn visible(items: &[Json]) -> Vec<Json> {
        items
            .iter()
            .filter_map(|item| {
                // `isNavGroup()`: a title and items, and no path.
                if let Some(inner) = item.get("items").and_then(Json::as_array)
                {
                    if item.get("path").is_none() {
                        let kept = visible(inner);
                        if kept.is_empty() {
                            return None;
                        }
                        let mut out = item.clone();
                        if let Some(o) = out.as_object_mut() {
                            o.insert("items".into(), Json::Array(kept));
                        }
                        return Some(out);
                    }
                }
                let path = item.get("path").and_then(Json::as_str)?;
                page_visible(Some("realm"), path).then(|| item.clone())
            })
            .collect()
    }
    Json::Array(
        all.as_array()
            .map(|sections| {
                sections
                    .iter()
                    .filter_map(|section| {
                        let items = section
                            .get("items")
                            .and_then(Json::as_array)
                            .map(|i| visible(i))
                            .unwrap_or_default();
                        if items.is_empty() {
                            return None;
                        }
                        let mut out = section.clone();
                        if let Some(o) = out.as_object_mut() {
                            o.insert("items".into(), Json::Array(items));
                        }
                        Some(out)
                    })
                    .collect()
            })
            .unwrap_or_default(),
    )
}

/// `AdminApi.meJson()`.
#[tracing::instrument(level = "debug", skip(services, caller))]
pub fn me_json(services: &Services, caller: Option<&Caller>) -> Json {
    let required = services
        .mode
        .value_in_force("adminApi.authRequired")
        .as_bool();
    let ambient = sts_core::realm::current_id();
    let realm_id = caller.map_or(ambient.clone(), |c| c.realm.clone());
    let authority = caller.map(|_| {
        if realm_id == DEFAULT_REALM {
            "service"
        } else {
            "realm"
        }
    });
    let roles: Vec<String> = caller.map(|c| c.roles.clone()).unwrap_or_default();
    let roster = caller
        .filter(|c| c.kind == "person")
        .and_then(|c| services.console.roster(&c.name, &realm_id));
    let has = |role: &str| roles.iter().any(|r| r == role);
    let pages: Vec<Json> = tables()
        .console_pages
        .as_array()
        .map(|list| {
            list.iter()
                .filter(|p| {
                    page_visible(authority, p.as_str().unwrap_or_default())
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    let r = roster.as_ref();
    let mut console = Map::new();
    console.insert(
        "available".into(),
        Json::Bool(services.console.roster_available()),
    );
    console.insert(
        "open".into(),
        Json::Bool(truthy(r.and_then(|x| x.get("open")))),
    );
    console.insert(
        "empty".into(),
        Json::Bool(truthy(r.and_then(|x| x.get("empty")))),
    );
    console.insert(
        "windowOpens".into(),
        Json::Bool(r.is_none_or(|x| x.get("windowOpens") != Some(&json!(false)))),
    );
    console.insert(
        "bootstrapPasswordRequired".into(),
        Json::Bool(truthy(r.and_then(|x| x.get("claimPending")))),
    );
    console.insert(
        "bootstrap".into(),
        r.and_then(|x| x.get("bootstrap"))
            .filter(|b| truthy(Some(b)))
            .cloned()
            .unwrap_or(Json::Null),
    );
    let mut out = Map::new();
    out.insert("tokenRequired".into(), Json::Bool(required));
    out.insert(
        "caller".into(),
        caller.map_or(Json::Null, |c| {
            json!({ "kind": c.kind, "name": c.name, "clientId": c.client_id })
        }),
    );
    out.insert("realm".into(), Json::from(realm_id.clone()));
    out.insert("readingRealm".into(), Json::from(ambient));
    out.insert(
        "authority".into(),
        authority.map_or(Json::Null, Json::from),
    );
    out.insert(
        "scopes".into(),
        json!(caller.map(|c| c.scopes.clone()).unwrap_or_default()),
    );
    out.insert("roles".into(), json!(roles));
    out.insert("read".into(), Json::Bool(!required || has("ADMIN_READ")));
    out.insert("write".into(), Json::Bool(!required || has("ADMIN_WRITE")));
    out.insert(
        "security".into(),
        Json::Bool(!required || has("SECURITY_ADMIN")),
    );
    out.insert(
        "expiresAt".into(),
        caller
            .and_then(|c| c.expires_at)
            .map_or(Json::Null, Json::from),
    );
    out.insert(
        "photo".into(),
        Json::from(
            caller
                .filter(|c| c.kind == "person")
                .map(|c| services.console.photo_path(&c.name))
                .unwrap_or_default(),
        ),
    );
    out.insert("mode".into(), Json::from(services.mode.current()));
    out.insert(
        "readGroup".into(),
        text(&services.settings, "admin.readGroup"),
    );
    out.insert(
        "writeGroup".into(),
        text(&services.settings, "admin.writeGroup"),
    );
    out.insert("console".into(), Json::Object(console));
    out.insert("pages".into(), Json::Array(pages));
    Json::Object(out)
}

/// `AdminApi.consoleGateOf(me)`: `meJson()`'s answer in the shape
/// `gateStateFor()` gives — a token is a session, its subject the
/// username, and the roles the console's `read`, `write` and `security`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn console_gate_of(me: &Json) -> Json {
    let roles: Vec<Json> = me
        .get("roles")
        .and_then(Json::as_array)
        .map(|list| {
            list.iter()
                .map(|r| {
                    let id = r.as_str().unwrap_or_default();
                    Json::from(match id {
                        "ADMIN_READ" => "read".to_string(),
                        "ADMIN_WRITE" => "write".to_string(),
                        "SECURITY_ADMIN" => "security".to_string(),
                        other => other.to_lowercase(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let held = me.get("console").cloned().unwrap_or(json!({}));
    let enforced = truthy(me.get("tokenRequired"));
    let caller = me.get("caller").filter(|c| !c.is_null());
    let flag = |k: &str| truthy(held.get(k));
    let mut out = Map::new();
    out.insert("enforced".into(), Json::Bool(enforced));
    out.insert("available".into(), Json::Bool(flag("available")));
    out.insert("session".into(), Json::Bool(caller.is_some()));
    out.insert(
        "username".into(),
        Json::from(
            caller
                .and_then(|c| c.get("name"))
                .and_then(Json::as_str)
                .unwrap_or_default(),
        ),
    );
    out.insert(
        "authority".into(),
        me.get("authority")
            .filter(|a| truthy(Some(a)))
            .cloned()
            .unwrap_or(Json::Null),
    );
    out.insert(
        "identityRealm".into(),
        me.get("realm")
            .filter(|a| truthy(Some(a)))
            .cloned()
            .unwrap_or(Json::Null),
    );
    out.insert(
        "readGroup".into(),
        me.get("readGroup").cloned().unwrap_or(Json::Null),
    );
    out.insert(
        "writeGroup".into(),
        me.get("writeGroup").cloned().unwrap_or(Json::Null),
    );
    out.insert("read".into(), Json::Bool(truthy(me.get("read"))));
    out.insert("write".into(), Json::Bool(truthy(me.get("write"))));
    out.insert("security".into(), Json::Bool(truthy(me.get("security"))));
    let no_roles = roles.is_empty();
    out.insert("roles".into(), Json::Array(roles));
    out.insert("open".into(), Json::Bool(enforced && flag("open")));
    out.insert(
        "closed".into(),
        Json::Bool(enforced && flag("empty") && !flag("open") && no_roles),
    );
    out.insert(
        "windowOpens".into(),
        Json::Bool(held.get("windowOpens") != Some(&json!(false))),
    );
    out.insert("empty".into(), Json::Bool(flag("empty")));
    out.insert(
        "bootstrapPasswordRequired".into(),
        Json::Bool(enforced && flag("bootstrapPasswordRequired")),
    );
    out.insert(
        "bootstrap".into(),
        held.get("bootstrap")
            .filter(|b| truthy(Some(b)))
            .cloned()
            .unwrap_or(Json::Null),
    );
    Json::Object(out)
}

/// `holdsNoConsoleRole(gate)`: a signed-in person holding neither console
/// role, where a token is required (#454).
fn holds_no_console_role(gate: &Json) -> bool {
    truthy(gate.get("enforced"))
        && truthy(gate.get("session"))
        && !truthy(gate.get("read"))
        && !truthy(gate.get("write"))
}

/// `shellRuntimeFacts(gate)`: every fact for a service administrator, the
/// mode alone for a realm's, none for nobody signed in.
fn shell_runtime_facts(services: &Services, gate: &Json) -> Json {
    if truthy(gate.get("enforced")) && !truthy(gate.get("session")) {
        return json!({});
    }
    if holds_no_console_role(gate) {
        return json!({});
    }
    let facts = services.console.runtime_facts();
    if gate.get("authority").and_then(Json::as_str) == Some("realm") {
        return json!({ "mode": facts.get("mode").cloned()
                                 .unwrap_or(Json::Null) });
    }
    facts
}

/// `version.buildInfo(v)`: the line under the version at the foot.
#[tracing::instrument(level = "debug", skip_all)]
pub fn build_info(v: &sts_core::version::VersionInfo) -> String {
    let head = if v.build.is_empty() {
        String::new()
    } else {
        format!(
            "{}{} — ",
            if v.release { "Release build " } else { "Build " },
            v.build
        )
    };
    format!(
        "{}{}{}{}{}",
        head,
        if v.stamped { "Built " } else { "Started " },
        v.built_at,
        if v.commit.is_empty() {
            String::new()
        } else {
            format!(" — commit {}", v.commit)
        },
        if v.stamped {
            ""
        } else {
            " — not a stamped build (running from a checkout)"
        }
    )
}

/// `AdminConsole.shellJson(req, gate, gate)` and the `locale` member
/// `GET /admin-api/console` puts beside it. `root` is the base URL with
/// the ambient realm's prefix taken off (`realmRoot()`).
#[tracing::instrument(level = "debug", skip_all)]
pub fn shell_json(
    services: &Services,
    gate: &Json,
    root: &str,
    headers: &HeaderMap,
    username: &str,
    as_files: bool,
) -> Json {
    let registry = &services.registry;
    let ambient = sts_core::realm::current();
    let mut labels = Map::new();
    for id in gate
        .get("roles")
        .and_then(Json::as_array)
        .into_iter()
        .flatten()
    {
        let id = id.as_str().unwrap_or_default();
        let label = sts_registers::rbac::Rbac::role_for(id)
            .map_or(id.to_string(), |r| r.label.to_string());
        labels.insert(id.to_string(), Json::from(label));
    }
    let realms = if registry.active() {
        Json::Array(
            registry
                .list()
                .iter()
                .map(|one| {
                    json!({ "id": one.id, "name": one.name,
                            "prefix": registry.prefix_of(one) })
                })
                .collect(),
        )
    } else {
        Json::Null
    };
    let home = gate
        .get("identityRealm")
        .and_then(Json::as_str)
        .and_then(|id| registry.get(id))
        .or_else(|| registry.get(DEFAULT_REALM));
    let portal = format!(
        "{}{}/portal",
        root,
        home.map(|h| registry.prefix_of(&h)).unwrap_or_default()
    );
    let realm_base = format!("{}{}", root, registry.prefix_of(&ambient));
    let authority = gate.get("authority").and_then(Json::as_str);
    let (enabled, mode) = services.console.persistence();
    let v = &services.version;
    let mut out = Map::new();
    out.insert(
        "gate".into(),
        if gate.is_null() {
            Json::Null
        } else {
            gate.clone()
        },
    );
    out.insert(
        "navAuthority".into(),
        Json::from(authority.unwrap_or_default()),
    );
    out.insert("roleLabels".into(), Json::Object(labels));
    out.insert(
        "realm".into(),
        json!({ "id": ambient.id, "name": ambient.name }),
    );
    out.insert(
        "wsTrustIssuer".into(),
        Json::from(services.console.issuer(&realm_base)),
    );
    out.insert("realms".into(), realms);
    out.insert("realmRoot".into(), Json::from(root));
    out.insert("portalHref".into(), Json::from(portal));
    out.insert(
        "sections".into(),
        if holds_no_console_role(gate) {
            json!([])
        } else {
            visible_sections(authority)
        },
    );
    out.insert("navLabels".into(), tables().nav_labels.clone());
    out.insert(
        "retiring".into(),
        crate::setup::retiring_json(&services.lifecycle, &ambient.id),
    );
    out.insert("runtime".into(), shell_runtime_facts(services, gate));
    out.insert(
        "persistence".into(),
        json!({ "enabled": enabled,
                "mode": if enabled { mode } else { String::new() } }),
    );
    out.insert(
        "version".into(),
        json!({ "version": v.version, "stamped": v.stamped,
                "buildInfo": build_info(v) }),
    );
    out.insert(
        "locale".into(),
        services.console.locale(headers, username, as_files),
    );
    Json::Object(out)
}

/// `AdminConsole.dashboardJson(req, totals)`: the totals, then the base
/// URL, persistence, whether the page describes a test double, and the
/// sections this reader may see. The management twin, `GET
/// /admin-api/status`, leaves the last four out (`consoleMembers`).
#[tracing::instrument(level = "debug", skip_all)]
pub fn dashboard_json(
    services: &Services,
    totals: Json,
    base: &str,
    authority: Option<&str>,
) -> Json {
    let mut out = totals.as_object().cloned().unwrap_or_default();
    let (enabled, mode) = services.console.persistence();
    out.insert("base".into(), Json::from(base));
    out.insert(
        "persistence".into(),
        json!({ "enabled": enabled,
                "mode": if enabled { mode } else { String::new() } }),
    );
    out.insert(
        "testDouble".into(),
        Json::Bool(
            services
                .mode
                .predicate("describesItselfAsTestDouble")
                .unwrap_or(false),
        ),
    );
    out.insert("sections".into(), visible_sections(authority));
    Json::Object(out)
}
