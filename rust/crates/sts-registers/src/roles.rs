// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE ROLE REGISTER (`common/roles.js`, rule 3u): who holds a role, which
//! roles are computed rather than stored, and the entries of `ou=roles`.
//!
//! Three kinds of role, as in Node:
//!
//! * the BUILT-IN roles (`EVERYBODY`, `ALL_AUTHENTICATED_USERS`, …,
//!   `OWNER_READ`, `OWNER_WRITE`) are COMPUTED from the context of a
//!   decision and never stored, so a stored role of the same name could
//!   never be reached and is refused;
//! * the NATIVE roles (`ADMIN_READ`, …, `REPORT_ADMIN`) authorize a
//!   permission of this service itself, are kept in every realm, and
//!   authorize exactly that permission; the three console roles among them
//!   take their people from the console roster's groups, never as members;
//! * every other role is an entry under `ou=roles`, its membership people,
//!   groups and applications, resolved at DECISION TIME.
//!
//! THERE IS NO STORE OF ITS OWN, deliberately: with no directory the
//! built-in roles still answer and the configured ones are missing, which
//! is `haveDirectory()`'s warning. The directory is the [`RoleDirectory`]
//! port; the settings the [`Settings`] port.
//!
//! What a group is NOT is the other half of this register's argument
//! (`common/CLAUDE.md` 3d-ii): a group grants nothing by being a group. It
//! reaches a role only by being named on one (`roleMemberGroup`), or the
//! console roster by being one of the three groups its settings name.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use regex::Regex;
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::sync::LazyLock;
use sts_core::errors::codes;
use sts_core::log::tag;
use sts_model::domain::{DirectoryEntry, Role};
use sts_model::FieldSource;

use crate::js;
use crate::outcome::Outcome;
use crate::port::{RoleDirectory, Settings};
use crate::schema;

#[path = "roles_table.rs"]
mod table;

/// A built-in, computed role.
#[derive(Debug, Clone, Copy)]
pub struct BuiltIn {
    pub name: &'static str,
    pub permission: Option<&'static str>,
    pub what: &'static str,
}

/// A native role: a permission of this service itself.
#[derive(Debug, Clone, Copy)]
pub struct NativeRole {
    pub name: &'static str,
    /// `read`, `write`, `security` for the three console roles, else ''.
    pub console_role: &'static str,
    pub permission: &'static str,
    /// The settings naming the console roster's groups that hold it.
    pub group_settings: &'static [&'static str],
    pub seed_applications: &'static [&'static str],
    pub seed_conferred_by: &'static [&'static str],
    pub seed_groups: &'static [&'static str],
    pub what: &'static str,
}

/// One of the console roster's three roles (`admin_rbac.ts`'s `ROLES`).
#[derive(Debug, Clone, Copy)]
pub struct RosterRole {
    pub id: &'static str,
    pub label: &'static str,
    pub setting: &'static str,
    pub implies: &'static [&'static str],
    pub what: &'static str,
}

pub use table::{BUILT_IN, NATIVE_ROLES, ROSTER_ROLES};

/// `APPLICATION_SEPARATOR`: an application's role is `<role>@<app>`.
pub const APPLICATION_SEPARATOR: &str = "@";

/// `MEMBER_TYPES`: what a role may be restricted to.
pub const MEMBER_TYPES: [&str; 2] = ["user", "application"];

/// `MAX_OWNERS`: the most owners a role may name.
pub const MAX_OWNERS: usize = 25;

/// `DEFAULT_REQUIRED_ROLE`.
pub const DEFAULT_REQUIRED_ROLE: &str = "EVERYBODY";

static ROLE_NAME: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9 ._:@-]{0,63}$").ok());

static DN_COMMAS: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"\s*,\s*").ok());

/// `isBuiltIn(name)`.
#[tracing::instrument(level = "debug")]
pub fn is_built_in(name: &str) -> bool {
    BUILT_IN.iter().any(|one| one.name == name)
}

/// `nativeRoleFor(name)`.
#[tracing::instrument(level = "debug")]
pub fn native_role_for(name: &str) -> Option<&'static NativeRole> {
    NATIVE_ROLES.iter().find(|one| one.name == name)
}

/// `consoleRoleFor(name)`: the three console roles are the native roles
/// with a console role.
#[tracing::instrument(level = "debug")]
pub fn console_role_for(name: &str) -> Option<&'static NativeRole> {
    NATIVE_ROLES
        .iter()
        .find(|one| one.name == name && !one.console_role.is_empty())
}

/// `CONSOLE_ROLES`.
#[tracing::instrument(level = "debug")]
pub fn console_roles() -> Vec<&'static NativeRole> {
    NATIVE_ROLES
        .iter()
        .filter(|one| !one.console_role.is_empty())
        .collect()
}

/// `OWNER_ROLES`: the built-in roles that authorize a permission.
#[tracing::instrument(level = "debug")]
pub fn owner_roles() -> Vec<(&'static str, &'static str)> {
    BUILT_IN
        .iter()
        .filter_map(|one| one.permission.map(|p| (one.name, p)))
        .collect()
}

/// `builtInCatalogue()`.
#[tracing::instrument(level = "debug")]
pub fn built_in_catalogue() -> Vec<Value> {
    BUILT_IN
        .iter()
        .map(|one| json!({"name": one.name, "what": one.what, "builtIn": true}))
        .collect()
}

/// `checkName(name)`: the refusal's sentence, or `None`.
#[tracing::instrument(level = "debug")]
pub fn check_name(name: &str) -> Option<String> {
    let text = js::trim(name);
    if text.is_empty() {
        return Some("A role needs a name.".to_string());
    }
    if is_built_in(text) {
        let names: Vec<&str> = BUILT_IN.iter().map(|one| one.name).collect();
        return Some(format!(
            "There is already a built-in role called \"{text}\", and the \
             built-in ones are COMPUTED rather than stored — a stored role \
             of the same name could never be reached, because the resolver \
             answers the built-in one first. The six are: {}.",
            names.join(", ")
        ));
    }
    let fits = ROLE_NAME.as_ref().is_some_and(|re| re.is_match(text));
    if !fits {
        return Some(format!(
            "A role name is up to 64 characters of letters, digits, and . _ \
             : @ - or a space, starting with a letter or a digit. \"{text}\" \
             is not, and the name becomes an LDAP RDN and a value in a token \
             claim."
        ));
    }
    None
}

/// The owner DN comparison form: lower case, no spaces round the commas.
#[tracing::instrument(level = "debug")]
pub fn owner_key(dn: &str) -> String {
    let lower = js::lower(dn);
    match DN_COMMAS.as_ref() {
        Some(re) => re.replace_all(&lower, ",").into_owned(),
        None => lower,
    }
}

/// A row of the register, as `all()` gives it.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleRow {
    pub name: String,
    pub application: String,
    pub local_name: String,
    pub dn: String,
    pub id: String,
    pub display_name: String,
    pub member_types: Vec<String>,
    pub description: String,
    pub users: Vec<String>,
    pub groups: Vec<String>,
    pub applications: Vec<String>,
    pub conferred_by: Vec<String>,
    pub permissions: Vec<String>,
    pub owners: Vec<String>,
    pub owner_protected: bool,
    pub console: bool,
    pub native: bool,
    pub built_in: bool,
}

/// The context a role decision is made in (`normalizeContext()`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Who {
    pub kind_application: bool,
    pub name: String,
    pub authenticated: bool,
    pub groups: Option<Vec<String>>,
    pub applications: Vec<String>,
    pub ids: bool,
    pub scopes: Vec<String>,
    pub owns: bool,
    pub cross_realm: bool,
    pub sids: Vec<String>,
}

impl Who {
    /// `normalizeContext(who)` from the object a caller hands Node.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn from_json(given: &Value) -> Who {
        let get = |k: &str| given.get(k);
        let list = |v: Option<&Value>| -> Option<Vec<String>> {
            match v {
                Some(Value::Array(items)) => {
                    Some(items.iter().map(js::string).collect())
                }
                _ => None,
            }
        };
        let applications = match get("applications") {
            Some(Value::Array(items)) => items.iter().map(js::string).collect(),
            _ => match get("application") {
                Some(v) if js::truthy(v) => vec![js::string(v)],
                _ => Vec::new(),
            },
        }
        .into_iter()
        .filter(|one: &String| !one.is_empty())
        .collect();
        let scopes = match get("scopes") {
            Some(Value::Array(items)) => items.iter().map(js::string).collect(),
            other => js::split_on(&js::or_empty(other), js::is_space),
        };
        Who {
            kind_application: get("kind")
                == Some(&Value::String("application".into())),
            name: js::or_empty(get("name")),
            authenticated: get("authenticated") == Some(&Value::Bool(true)),
            groups: list(get("groups")),
            applications,
            ids: get("ids") == Some(&Value::Bool(true)),
            scopes,
            owns: get("owns") == Some(&Value::Bool(true)),
            cross_realm: get("crossRealm") == Some(&Value::Bool(true)),
            sids: list(get("sids"))
                .unwrap_or_default()
                .into_iter()
                .filter(|one| !one.is_empty())
                .collect(),
        }
    }

    /// A person or an application, by name.
    #[tracing::instrument(level = "debug")]
    pub fn subject(application: bool, name: &str, authenticated: bool) -> Who {
        Who {
            kind_application: application,
            name: name.to_string(),
            authenticated,
            ..Who::default()
        }
    }

    fn is_user(&self) -> bool {
        !self.kind_application
    }
}

/// The values an entry holds for a model field, read as `DomainMap.valuesOf`
/// reads them: the attribute named case-insensitively, `null`s dropped.
fn field_values(
    fields: &[FieldSource],
    field: &str,
    at: &Value,
) -> Vec<String> {
    let attribute = fields
        .iter()
        .find(|one| one.name == field)
        .and_then(|one| one.attribute)
        .unwrap_or(field);
    entry_values(at, attribute)
}

/// `DomainMap.valuesOf(attributes, name)`.
#[tracing::instrument(level = "debug", skip(at))]
pub fn entry_values(at: &Value, attribute: &str) -> Vec<String> {
    let wanted = js::lower(attribute);
    let Some(map) = at.as_object() else {
        return Vec::new();
    };
    let Some((_, held)) = map.iter().find(|(k, _)| js::lower(k) == wanted)
    else {
        return Vec::new();
    };
    match held {
        Value::Array(items) => items
            .iter()
            .filter(|one| !one.is_null())
            .map(js::string)
            .collect(),
        Value::Null => Vec::new(),
        other => vec![js::string(other)],
    }
}

fn typed_bool(values: &[String]) -> Option<bool> {
    values.iter().find_map(|one| match js::lower(one).as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    })
}

fn nonempty(values: Vec<String>) -> Option<Vec<String>> {
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

/// `DomainClasses.Role.fromEntry(attributes)`: the model's concept.
#[tracing::instrument(level = "debug", skip_all)]
pub fn role_of_entry(at: &Value) -> Role {
    let f = |field: &str| field_values(Role::FIELDS, field, at);
    Role {
        name: f("name").into_iter().next().unwrap_or_default(),
        display_name: f("displayName").into_iter().next(),
        description: f("description").into_iter().next(),
        member_users: nonempty(f("memberUsers")),
        member_groups: nonempty(f("memberGroups")),
        member_applications: nonempty(f("memberApplications")),
        permissions: nonempty(f("permissions")),
        realm: None,
        role_conferred_by: nonempty(f("roleConferredBy")),
        role_application: f("roleApplication").into_iter().next(),
        role_allowed_member_type: nonempty(f("roleAllowedMemberType")),
        owner: nonempty(f("owner")),
        sts_owner_protected: typed_bool(&f("stsOwnerProtected")),
    }
}

/// `trimmedValues(values)`.
fn trimmed(values: Option<Vec<String>>) -> Vec<String> {
    values
        .unwrap_or_default()
        .iter()
        .map(|one| js::trim(one).to_string())
        .filter(|one| !one.is_empty())
        .collect()
}

/// `list.map(trim).filter((one, at, all) => one && all.indexOf(one) === at)`.
fn trimmed_distinct(values: Vec<String>) -> Vec<String> {
    let trimmed: Vec<String> =
        values.iter().map(|one| js::trim(one).to_string()).collect();
    let mut out: Vec<String> = Vec::new();
    for (at, one) in trimmed.iter().enumerate() {
        if !one.is_empty()
            && trimmed.iter().position(|other| other == one) == Some(at)
        {
            out.push(one.clone());
        }
    }
    out
}

/// JavaScript's default `sort()`: by UTF-16 code units.
fn sort_utf16(list: &mut [String]) {
    list.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
}

/// `contains(list, wanted)`: case-insensitive.
fn contains(list: &[String], wanted: &str) -> bool {
    let key = js::lower(wanted);
    list.iter().any(|one| js::lower(one) == key)
}

/// The role register.
pub struct Roles {
    directory: Option<Arc<dyn RoleDirectory>>,
    settings: Arc<dyn Settings>,
    warned: AtomicBool,
}

impl Roles {
    /// `roles.setDirectory(hooks)` is the constructor's `directory`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(
        directory: Option<Arc<dyn RoleDirectory>>,
        settings: Arc<dyn Settings>,
    ) -> Roles {
        Roles {
            directory,
            settings,
            warned: AtomicBool::new(false),
        }
    }

    fn setting_text(&self, key: &str) -> String {
        js::trim(&js::or_empty(Some(&self.settings.value(key)))).to_string()
    }

    /// `haveDirectory()`.
    fn directory(&self) -> Option<&Arc<dyn RoleDirectory>> {
        if self.directory.is_none() && !self.warned.swap(true, Ordering::SeqCst)
        {
            tracing::warn!(
                "roles: the embedded directory was never loaded, so there is \
                 no ou=roles to hold a role. The six BUILT-IN roles still \
                 answer — they are computed rather than stored — so an \
                 application requiring EVERYBODY still admits everybody, \
                 which is the default. Only configured roles are missing. \
                 There is no fallback store, deliberately: a role register \
                 that quietly lived in memory would decide things nobody \
                 could find."
            );
        }
        self.directory.as_ref()
    }

    /// `consoleRoleGroups(row)`: the roster's groups that hold a console
    /// role, from its settings, distinct.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn console_role_groups(&self, row: &NativeRole) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for key in row.group_settings {
            let group = self.setting_text(key);
            if !group.is_empty() && !out.contains(&group) {
                out.push(group);
            }
        }
        out
    }

    /// `all()`: every stored role, sorted by `localeCompare`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn all(&self) -> Vec<RoleRow> {
        let Some(directory) = self.directory() else {
            return Vec::new();
        };
        let mut rows: Vec<RoleRow> = directory
            .all_roles()
            .iter()
            .map(|entry| self.row_of(entry))
            .collect();
        rows.sort_by(|a, b| js::locale_compare(&a.name, &b.name));
        rows
    }

    fn row_of(&self, entry: &Value) -> RoleRow {
        let empty = Value::Object(Map::new());
        let at = entry.get("attributes").unwrap_or(&empty);
        let name = js::unless_null(entry.get("name"));
        let role = role_of_entry(at);
        let console = console_role_for(&name);
        let native = native_role_for(&name);
        let application = role.role_application.clone().unwrap_or_default();
        let separated = format!("{APPLICATION_SEPARATOR}{application}");
        let local_name = if !application.is_empty()
            && name.ends_with(&separated)
        {
            let keep = js::len_utf16(&name) - js::len_utf16(&application) - 1;
            js::slice_utf16(&name, keep)
        } else {
            name.clone()
        };
        let id = field_values(DirectoryEntry::FIELDS, "entryUuid", at)
            .into_iter()
            .next()
            .map(|one| js::lower(&one))
            .unwrap_or_default();
        RoleRow {
            name,
            application,
            local_name,
            dn: js::unless_null(entry.get("dn")),
            id,
            display_name: role.display_name.clone().unwrap_or_default(),
            member_types: trimmed(role.role_allowed_member_type.clone()),
            description: role.description.clone().unwrap_or_default(),
            users: if console.is_some() {
                Vec::new()
            } else {
                trimmed(role.member_users.clone())
            },
            groups: match console {
                Some(row) => self.console_role_groups(row),
                None => trimmed(role.member_groups.clone()),
            },
            applications: trimmed(role.member_applications.clone()),
            conferred_by: trimmed(role.role_conferred_by.clone()),
            permissions: match native {
                Some(row) => vec![row.permission.to_string()],
                None => trimmed(role.permissions.clone()),
            },
            owners: trimmed(role.owner.clone()),
            owner_protected: role.sts_owner_protected == Some(true),
            console: console.is_some(),
            native: native.is_some(),
            built_in: false,
        }
    }

    /// `read(name)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn read(&self, name: &str) -> Option<RoleRow> {
        self.all().into_iter().find(|row| row.name == name)
    }

    /// `catalogue()`: the built-in roles and every stored one.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn catalogue(&self) -> Vec<Value> {
        let mut out = built_in_catalogue();
        out.extend(self.all().iter().map(|row| {
            json!({
                "name": row.name,
                "what": row.description,
                "builtIn": false,
                "members": row.users.len() + row.groups.len()
                    + row.applications.len(),
            })
        }));
        out
    }

    /// `write(name, record)`: creates or replaces a stored role. `record`
    /// is Node's record object: `description`, `users`, `groups`,
    /// `applications`, `permissions`, `application`, `displayName`,
    /// `memberTypes`, `owners`, `ownerProtected`, `conferredBy`.
    #[tracing::instrument(level = "debug", skip(self, record))]
    pub fn write(&self, name: &str, record: &Value) -> Outcome {
        if let Some(problem) = check_name(name) {
            return Outcome::marked(
                codes::STS_XACML_0055,
                json!({"ok": false, "why": problem}),
            );
        }
        let Some(directory) = self.directory().cloned() else {
            return Outcome::marked(
                codes::STS_XACML_0026,
                json!({"ok": false, "why": "There is no embedded directory \
                    in this process, so there is nowhere to keep a role. \
                    ou=roles IS the register."}),
            );
        };
        let given = |k: &str| record.get(k);
        let application =
            js::trim(&js::or_empty(given("application"))).to_string();
        if !application.is_empty() {
            let keep = js::len_utf16(name)
                .saturating_sub(js::len_utf16(&application) + 1);
            let local = js::slice_utf16(name, keep);
            if name != format!("{local}{APPLICATION_SEPARATOR}{application}")
                || local.is_empty()
                || local.contains(APPLICATION_SEPARATOR)
                || check_name(&local).is_some()
            {
                return Outcome::marked(
                    codes::STS_XACML_0080,
                    json!({"ok": false, "why": format!(
                        "An application's role is named <role>@<application>, \
                         the role part a role name with no \"@\" in it; \
                         \"{name}\" for \"{application}\" is not.")}),
                );
            }
            if native_role_for(&local).is_some() || is_built_in(&local) {
                return Outcome::marked(
                    codes::STS_XACML_0080,
                    json!({"ok": false, "why": format!(
                        "\"{local}\" is a role of this service itself and \
                         cannot be an application's role too: a token would \
                         carry one name meaning two things.")}),
                );
            }
        }
        let users = js::strings(given("users"));
        let groups = js::strings(given("groups"));
        let applications = js::strings(given("applications"));
        let console = console_role_for(name);
        if let Some(row) = console {
            if !users.is_empty()
                || groups
                    .iter()
                    .any(|g| !self.console_role_groups(row).contains(g))
            {
                return Outcome::marked(
                    codes::STS_XACML_0075,
                    json!({"ok": false, "why": format!(
                        "\"{name}\" is one of the two console roles, and the \
                         people who hold it are the console roster's: add \
                         them to the Admin Read or Admin Write group on \
                         /admin/rbac (or POST /admin-api/rbac/grant). Its \
                         groups are the settings admin.readGroup and \
                         admin.writeGroup, and two places granting one role \
                         would be two answers. An application is added \
                         here.")}),
                );
            }
        }
        let asked: Vec<String> = match given("memberTypes") {
            Some(Value::Array(items)) => items.iter().map(js::string).collect(),
            other => {
                let text = js::or_empty(other);
                text.split(|c: char| js::is_space(c) || c == ',')
                    .map(str::to_string)
                    .collect()
            }
        };
        let mut member_types: Vec<String> = Vec::new();
        let mut unknown: Vec<String> = Vec::new();
        for one in asked {
            let one = js::lower(js::trim(&one));
            if one.is_empty() {
                continue;
            }
            if !MEMBER_TYPES.contains(&one.as_str()) {
                unknown.push(one);
            } else if !member_types.contains(&one) {
                member_types.push(one);
            }
        }
        if !unknown.is_empty() {
            return Outcome::marked(
                codes::STS_XACML_0081,
                json!({"ok": false, "why": format!(
                    "A role's member types are user and application; \"{}\" \
                     is not one.", unknown.join("\", \""))}),
            );
        }
        if console.is_some() && !member_types.is_empty() {
            return Outcome::marked(
                codes::STS_XACML_0083,
                json!({"ok": false, "why": format!(
                    "\"{name}\" is one of the two console roles: the console \
                     roster grants it to people and the seed to the \
                     management API's application, so it holds both kinds \
                     and cannot be restricted to one.")}),
            );
        }
        let has = |t: &str| member_types.iter().any(|one| one == t);
        let mut excluded: Vec<&str> = Vec::new();
        if !member_types.is_empty() {
            if !has("user") && (!users.is_empty() || !groups.is_empty()) {
                excluded.push("people or groups");
            }
            if !has("application") && !applications.is_empty() {
                excluded.push("applications");
            }
        }
        if !excluded.is_empty() {
            return Outcome::marked(
                codes::STS_XACML_0082,
                json!({"ok": false, "why": format!(
                    "\"{name}\" may be held by {} only, and {} cannot be its \
                     members.",
                    if has("user") { "people" } else { "applications" },
                    excluded.join(" and "))}),
            );
        }
        let before = self.read(name);
        let owners = trimmed_distinct(match given("owners") {
            None => before
                .as_ref()
                .map(|b| b.owners.clone())
                .unwrap_or_default(),
            Some(v) => js::strings(Some(v)),
        });
        let owner_protected = match given("ownerProtected") {
            None => before.as_ref().is_some_and(|b| b.owner_protected),
            Some(v) => v == &Value::Bool(true),
        };
        let conferred_by = trimmed_distinct(match given("conferredBy") {
            None => before
                .as_ref()
                .map(|b| b.conferred_by.clone())
                .unwrap_or_default(),
            Some(v) => js::strings(Some(v)),
        });
        if !conferred_by.is_empty() && console.is_some() {
            return Outcome::marked(
                codes::STS_XACML_0089,
                json!({"ok": false, "why": format!(
                    "\"{name}\" is one of the two console roles, and the \
                     people who hold it are the console roster's: a client \
                     cannot confer it on everybody signing in through it. \
                     Grant it on /admin/rbac.")}),
            );
        }
        if !conferred_by.is_empty() && !member_types.is_empty() && !has("user")
        {
            return Outcome::marked(
                codes::STS_XACML_0088,
                json!({"ok": false, "why": format!(
                    "\"{name}\" may be held by applications only, and a role \
                     a client confers is held by the PEOPLE who sign in \
                     through it. Let people hold it, or take {} off it.",
                    conferred_by.join(", "))}),
            );
        }
        let display = js::trim(&js::or_empty(given("displayName"))).to_string();
        let console_held = console.is_some();
        let attributes = json!({
            "objectClass": schema::object_classes_with_top("role"),
            "roleName": name,
            "description": js::or_empty(given("description")),
            "roleMemberUser": if console_held { Vec::new() } else { users },
            "roleMemberGroup": if console_held { Vec::new() } else { groups },
            "roleMemberApplication": applications,
            "roleConferredBy": conferred_by,
            "roleApplication": if application.is_empty() {
                Vec::new()
            } else {
                vec![application]
            },
            "roleAllowedMemberType": member_types,
            "owner": owners,
            "stsOwnerProtected": if owner_protected {
                vec!["TRUE"]
            } else {
                Vec::new()
            },
            "displayName": if display.is_empty() {
                Vec::new()
            } else {
                vec![display]
            },
            "rolePermission": match native_role_for(name) {
                Some(row) => vec![row.permission.to_string()],
                None => js::strings(given("permissions")),
            },
        });
        let written = directory.write_role(name, &attributes);
        if written.value.get("ok") == Some(&Value::Bool(false)) {
            let why = written
                .value
                .get("errors")
                .and_then(|e| e.get(0))
                .filter(|e| js::truthy(e))
                .map(js::string)
                .unwrap_or_else(|| {
                    "A description cannot carry an operator error code."
                        .to_string()
                });
            let nul = written.value.get("reason")
                == Some(&Value::String("nul".into()));
            return Outcome::marked(
                if nul {
                    codes::STS_LDAP_0008
                } else {
                    codes::STS_LDAP_0211
                },
                json!({"ok": false, "why": why}),
            );
        }
        if !js::truthy(&written.value) {
            return Outcome::marked(
                codes::STS_XACML_0027,
                json!({"ok": false, "why": "The directory would not store \
                    the role — it is at its maximum number of entries."}),
            );
        }
        Outcome::ok(json!({"ok": true, "name": name}))
    }

    /// `remove(name)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn remove(&self, name: &str) -> Outcome {
        if is_built_in(name) {
            return Outcome::marked(
                codes::STS_XACML_0056,
                json!({"ok": false, "why": format!(
                    "\"{name}\" is a built-in role. It is computed rather \
                     than stored, so there is nothing to delete — and an \
                     application requiring it would be requiring something \
                     that no longer existed.")}),
            );
        }
        if let Some(row) = native_role_for(name) {
            return Outcome::marked(
                codes::STS_XACML_0076,
                json!({"ok": false, "why": format!(
                    "\"{name}\" authorizes a permission of this service \
                     itself ({}) and is kept in every realm: without it \
                     nobody could ever be issued that permission there. Take \
                     a member out with remove-member instead.",
                    row.permission)}),
            );
        }
        let gone = self
            .directory()
            .is_some_and(|directory| directory.delete_role(name));
        if !gone {
            return Outcome::marked(
                codes::STS_XACML_0057,
                json!({"ok": false, "why": format!(
                    "There is no role called \"{name}\".")}),
            );
        }
        Outcome::ok(json!({"ok": true}))
    }

    fn resolve(&self, text: &str) -> Value {
        match self.directory.as_ref() {
            Some(directory) => directory.resolve_owner(text),
            None => json!({"kind": "", "dn": "", "name": ""}),
        }
    }

    /// `ownersOf(row)`: each owner DN resolved.
    #[tracing::instrument(level = "debug", skip(self, row))]
    pub fn owners_of(&self, row: &RoleRow) -> Vec<Value> {
        row.owners
            .iter()
            .map(|dn| {
                let found = self.resolve(dn);
                let kind = js::or_empty(found.get("kind"));
                json!({
                    "dn": if kind.is_empty() {
                        dn.clone()
                    } else {
                        js::unless_null(found.get("dn"))
                    },
                    "kind": kind,
                    "name": js::or_empty(found.get("name")),
                    "present": !kind.is_empty(),
                })
            })
            .collect()
    }

    fn no_such(name: &str) -> Outcome {
        Outcome::marked(
            codes::STS_XACML_0057,
            json!({"ok": false, "why": format!(
                "There is no role called \"{name}\".")}),
        )
    }

    fn record_with_owners(row: &RoleRow, owners: &[String]) -> Value {
        json!({
            "description": row.description,
            "users": row.users,
            "groups": row.groups,
            "applications": row.applications,
            "permissions": row.permissions,
            "application": row.application,
            "displayName": row.display_name,
            "memberTypes": row.member_types,
            "owners": owners,
        })
    }

    /// `addOwner(name, owner)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn add_owner(&self, name: &str, owner: &str) -> Outcome {
        let Some(row) = self.read(name) else {
            return Roles::no_such(name);
        };
        let wanted = js::trim(owner).to_string();
        if wanted.is_empty() {
            return Outcome::marked(
                codes::STS_XACML_0173,
                json!({"ok": false, "why": "Who? Send `owner` with a person \
                    (a username or DN) or a group (its cn or DN) of this \
                    realm."}),
            );
        }
        let resolved = self.resolve(&wanted);
        let kind = js::or_empty(resolved.get("kind"));
        if kind.is_empty() {
            return Outcome::marked(
                codes::STS_XACML_0174,
                json!({"ok": false, "why": format!(
                    "\"{}\" names no person and no group in this realm. An \
                     owner answers for the role, so it must name somebody.",
                    js::slice_utf16(&wanted, 128))}),
            );
        }
        let dn = js::unless_null(resolved.get("dn"));
        let shown = match js::or_empty(resolved.get("name")) {
            n if n.is_empty() => dn.clone(),
            n => n,
        };
        let before = self.owners_of(&row);
        let mut owners: Vec<String> = before
            .iter()
            .map(|one| js::unless_null(one.get("dn")))
            .collect();
        if owners.iter().any(|one| owner_key(one) == owner_key(&dn)) {
            return Outcome::ok(json!({
                "ok": true, "changed": false, "role": row.name, "owner": dn,
                "owners": before,
                "message": format!("{shown} was already an owner of the role \
                    \"{}\".", row.name),
            }));
        }
        if owners.len() >= MAX_OWNERS {
            return Outcome::marked(
                codes::STS_XACML_0175,
                json!({"ok": false, "why": format!(
                    "The role \"{}\" already names {} owners, the most a \
                     role may name ({MAX_OWNERS}). Name a group of them \
                     instead.", row.name, owners.len())}),
            );
        }
        owners.push(dn.clone());
        let written =
            self.write(&row.name, &Roles::record_with_owners(&row, &owners));
        if !written.is_ok() {
            return written;
        }
        let after = self.read(&row.name).unwrap_or(row.clone());
        Outcome::ok(json!({
            "ok": true, "changed": true, "role": row.name, "owner": dn,
            "owners": self.owners_of(&after),
            "message": format!("{shown} is now an owner of the role \"{}\".",
                row.name),
        }))
    }

    /// `removeOwner(name, owner)`. A person or group must be named by the
    /// DN stored, as Node compares it (a Node defect: `add-owner` takes a
    /// username, `remove-owner` only the DN it was stored as).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn remove_owner(&self, name: &str, owner: &str) -> Outcome {
        let Some(row) = self.read(name) else {
            return Roles::no_such(name);
        };
        let wanted = js::trim(owner).to_string();
        let kept: Vec<String> = row
            .owners
            .iter()
            .filter(|dn| owner_key(dn) != owner_key(&wanted))
            .cloned()
            .collect();
        if wanted.is_empty() || kept.len() == row.owners.len() {
            return Outcome::marked(
                codes::STS_XACML_0176,
                json!({"ok": false, "why": format!(
                    "\"{}\" is not one of the owners of the role \"{}\".",
                    js::slice_utf16(&wanted, 128), row.name)}),
            );
        }
        let written =
            self.write(&row.name, &Roles::record_with_owners(&row, &kept));
        if !written.is_ok() {
            return written;
        }
        let after = self.read(&row.name).unwrap_or(row.clone());
        Outcome::ok(json!({
            "ok": true, "changed": true, "role": row.name, "owner": wanted,
            "owners": self.owners_of(&after),
            "message": format!("{wanted} is no longer an owner of the role \
                \"{}\".", row.name),
        }))
    }

    /// `setOwnerProtected(name, flag)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn set_owner_protected(&self, name: &str, flag: bool) -> Outcome {
        let Some(row) = self.read(name) else {
            return Roles::no_such(name);
        };
        if row.owner_protected == flag {
            return Outcome::ok(json!({"ok": true, "changed": false,
                "role": row.name, "ownerProtected": flag}));
        }
        let mut record = Roles::record_with_owners(&row, &row.owners);
        if let Some(map) = record.as_object_mut() {
            map.insert("conferredBy".into(), json!(row.conferred_by));
            map.insert("ownerProtected".into(), json!(flag));
        }
        let written = self.write(&row.name, &record);
        if !written.is_ok() {
            return written;
        }
        Outcome::ok(json!({"ok": true, "changed": true, "role": row.name,
            "ownerProtected": flag}))
    }

    /// `seedNativeRoles()`: each native role made where it is missing, and
    /// the groups the SSF and report roles name.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn seed_native_roles(&self) -> usize {
        let Some(directory) = self.directory().cloned() else {
            return 0;
        };
        let mut made = 0;
        for row in NATIVE_ROLES {
            for group in row.seed_groups {
                let done = directory.ensure_group(
                    group,
                    &json!({
                        "note": format!("Members of this group hold the \
                            native role {} when that role lists the group. \
                            Seeded empty; adding a member is how a person is \
                            granted {}.", row.name, row.permission),
                        "origin": "seed", "actor": "seed",
                        "channel": "internal",
                    }),
                );
                if done.get("ok") != Some(&Value::Bool(true)) {
                    let why: Vec<String> = done
                        .get("errors")
                        .and_then(Value::as_array)
                        .map(|e| e.iter().map(js::string).collect())
                        .unwrap_or_default();
                    tracing::warn!(
                        "{}roles: the group \"{group}\" for the native role \
                         \"{}\" was not seeded{}.",
                        tag(codes::STS_XACML_0077),
                        row.name,
                        if why.is_empty() {
                            String::new()
                        } else {
                            format!(": {}", why.join(" "))
                        }
                    );
                }
            }
            if self.read(row.name).is_some() {
                continue;
            }
            let written = self.write(
                row.name,
                &json!({
                    "description": row.what,
                    "applications": row.seed_applications,
                    "conferredBy": row.seed_conferred_by,
                    "groups": row.seed_groups,
                }),
            );
            if written.is_ok() {
                made += 1;
            } else {
                tracing::warn!(
                    "{}roles: the native role \"{}\" was not seeded: {} \
                     Machine clients cannot be issued {} in this realm until \
                     it exists.",
                    tag(codes::STS_XACML_0077),
                    row.name,
                    js::string(&written.why()),
                    row.permission
                );
            }
        }
        made
    }

    /// `rolesAuthorizing(permission)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn roles_authorizing(&self, permission: &str) -> Vec<String> {
        self.all()
            .into_iter()
            .filter(|row| row.permissions.iter().any(|p| p == permission))
            .map(|row| row.name)
            .collect()
    }

    /// `conferredBy(clientId)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn conferred_by(&self, client_id: &str) -> Vec<String> {
        if client_id.is_empty() {
            return Vec::new();
        }
        self.all()
            .into_iter()
            .filter(|row| row.conferred_by.iter().any(|c| c == client_id))
            .map(|row| row.name)
            .collect()
    }

    /// `groupsOf(username)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn groups_of(&self, username: &str) -> Vec<String> {
        match self.directory.as_ref() {
            Some(directory) => directory.groups_of_user(username),
            None => Vec::new(),
        }
    }

    fn groups_for(&self, who: &Who) -> Vec<String> {
        if who.cross_realm {
            return Vec::new();
        }
        if let Some(groups) = who.groups.as_ref() {
            return groups.clone();
        }
        if !who.is_user() || who.name.is_empty() {
            return Vec::new();
        }
        self.groups_of(&who.name)
    }

    fn group_named(&self, key: &str, who: &Who) -> bool {
        let wanted = js::lower(&self.setting_text(key));
        if wanted.is_empty() {
            return false;
        }
        who.groups
            .as_ref()
            .is_some_and(|g| g.iter().any(|one| js::lower(one) == wanted))
    }

    fn holds(&self, role: &BuiltIn, who: &Who) -> bool {
        let user = who.is_user();
        match role.name {
            "EVERYBODY" => true,
            "ALL_AUTHENTICATED_USERS" => user && who.authenticated,
            "ALL_UNAUTHENTICATED_USERS" => user && !who.authenticated,
            "ALL_APPLICATIONS" => !user,
            "ALL_AUTHENTICATED_APPLICATIONS" => !user && who.authenticated,
            "ALL_UNAUTHENTICATED_APPLICATIONS" => !user && !who.authenticated,
            "REMOTE_PEPS" => self.group_named("roles.remotePepGroup", who),
            "XACML_USER" => self.group_named("roles.xacmlUserGroup", who),
            "AUTHZEN_PEPS" => self.group_named("roles.authzenPepGroup", who),
            "OWNER_READ" | "OWNER_WRITE" => {
                user && who.authenticated && who.owns
            }
            _ => false,
        }
    }

    /// `rolesOf(who)`: the built-in roles held, then the configured ones.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn roles_of(&self, who: &Who) -> Vec<String> {
        let mut context = who.clone();
        context.groups = Some(self.groups_for(&context));
        let held: Vec<String> = if context.cross_realm {
            Vec::new()
        } else {
            BUILT_IN
                .iter()
                .filter(|one| self.holds(one, &context))
                .map(|one| one.name.to_string())
                .collect()
        };
        let mut out = held.clone();
        for one in self.configured_roles_of(&context) {
            if !held.contains(&one) {
                out.push(one);
            }
        }
        out
    }

    /// `memberNamesOf(kind, name, crossRealm)` (Node's 62c6081d2,
    /// 2026-11-14): THE NAMES A DIRECT MEMBERSHIP IS MATCHED UNDER. A role
    /// names its people by username (`roleMemberUser`), and a person also
    /// arrives as their subject, `urn:uuid:<entryUUID>` — the `sub` a remote
    /// PEP asks `POST /xacml/pip` about. The group half already found them,
    /// the direct half compared the username list against the subject and
    /// missed, so one person was Permit by name and Deny by subject. Only a
    /// person: an application is named by its client_id, and a principal
    /// that arrived through a Kerberos trust has no entry here to name.
    fn member_names_of(&self, who: &Who) -> Vec<String> {
        let mut out = vec![who.name.clone()];
        let subject = who.name.trim().to_lowercase();
        if !who.is_user()
            || who.cross_realm
            || !subject.starts_with("urn:uuid:")
        {
            return out;
        }
        let filed = self
            .directory
            .as_ref()
            .map(|d| d.name_for_subject(&who.name))
            .unwrap_or_default();
        if !filed.is_empty() && filed.to_lowercase() != who.name.to_lowercase()
        {
            out.push(filed);
        }
        out
    }

    /// `configuredRolesOf(context)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn configured_roles_of(&self, who: &Who) -> Vec<String> {
        if who.name.is_empty() {
            return Vec::new();
        }
        let names = self.member_names_of(who);
        let groups = if !who.is_user() {
            Vec::new()
        } else if who.cross_realm {
            who.sids.clone()
        } else {
            self.groups_for(who)
        };
        let lower_groups: Vec<String> =
            groups.iter().map(|one| js::lower(one)).collect();
        self.all()
            .into_iter()
            .filter(|role| {
                if !who.is_user() {
                    return contains(&role.applications, &who.name);
                }
                names.iter().any(|one| contains(&role.users, one))
                    || role
                        .groups
                        .iter()
                        .any(|g| lower_groups.contains(&js::lower(g)))
            })
            .filter(|role| {
                who.ids
                    || role.application.is_empty()
                    || who.applications.contains(&role.application)
            })
            .map(|role| {
                if who.ids || role.application.is_empty() {
                    role.name
                } else {
                    role.local_name
                }
            })
            .collect()
    }

    /// `claimFor(who)`: `{<roles.claimName>: [...]}` or `None`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn claim_for(&self, who: &Who) -> Option<Value> {
        if self.settings.value("roles.claim") == Value::Bool(false) {
            return None;
        }
        let mut names = self.configured_roles_of(who);
        if names.is_empty() {
            return None;
        }
        let claim =
            match js::or_empty(Some(&self.settings.value("roles.claimName"))) {
                n if n.is_empty() => "roles".to_string(),
                n => n,
            };
        sort_utf16(&mut names);
        let mut out = Map::new();
        out.insert(claim, json!(names));
        Some(Value::Object(out))
    }

    /// `rolesInClaims(claims)`: the role names a token's claims carry.
    #[tracing::instrument(level = "debug", skip(self, claims))]
    pub fn roles_in_claims(&self, claims: &Value) -> Vec<String> {
        if !claims.is_object() && !claims.is_array() {
            return Vec::new();
        }
        let claim =
            match js::or_empty(Some(&self.settings.value("roles.claimName"))) {
                n if n.is_empty() => "roles".to_string(),
                n => n,
            };
        let raw = match claims.get(&claim) {
            None | Some(Value::Null) => return Vec::new(),
            Some(v) => v,
        };
        let values: Vec<String> = match raw {
            Value::Array(items) => items.iter().map(js::string).collect(),
            Value::String(s) => s
                .split(|c: char| js::is_space(c) || c == ',')
                .map(str::to_string)
                .collect(),
            other => vec![js::string(other)],
        };
        values
            .iter()
            .map(|one| js::trim(one).to_string())
            .filter(|one| !one.is_empty())
            .collect()
    }
}
