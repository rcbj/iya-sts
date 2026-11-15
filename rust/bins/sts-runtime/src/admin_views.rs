// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE READS `/admin-api` ANSWERS OVER WHAT THE RUNTIME HOLDS (#444, phase
//! 5, the `apis3` slice): `admin-core/admin_views.ts`'s views, one per
//! operation, each held to its model by the router like every answer.
//!
//! | Operation | Node | Over |
//! |---|---|---|
//! | `getGroups` | `groupsJson()`, `groupsListJson()`, `groupDetailJson()` | the directory's groups ([`super::groups::Groups`]), the identity register |
//! | `grantAdminRole`, `revokeAdminRole` | `adminActions.rbacAction()` | `sts-registers`' `Rbac` over the roster, whose group writes are the directory's ([`super::groups::write_group_json`]) |
//! | `getUsers` with `?user=` | `usersJson()`, `userDetailJson()` (in part), `stats.userDetail()`, `ldapObjectJson()` | the identity register, the token register, the directory |
//! | `grantGlobalConsent` | `consentAction()`'s `grant-global-consent`, `consent.grantGlobal()` | the application register |
//!
//! THE IDENTITY REGISTER (`common/admin_stats.js`'s `users`, persisted as
//! `admin_stats.users`, `merge: own`) is READ here, never written: who this
//! service has seen authenticate. A view asks it which names are known
//! (`knownUserKeys()`), which is the register's keys, every other
//! process's rows (the store's fan-in, a previous run of Node's included)
//! and the holders of the tokens the token register keeps
//! (`collectUserKeys()`). This runtime's own sign-ins record there through
//! `admin_identity.rs` (`recordAuthentication()`, the `apis4` slice).
//!
//! `getUsers` IS PORTED FOR ONE PERSON, IN PART: `known`, `user` (the
//! register's row as `buildUserRowsResolved()` builds it — its record, the
//! tokens it holds, counted by state; the artifacts it was issued are not
//! counted, `admin_stats.artifacts` not being read here), `subject` and
//! `ldap` (`objectFor()`, its secrets masked), or `known: false` with
//! `registryKeeps` for nobody. Every other member of the drill-down is
//! absent rather than empty. The LIST (no `user`) is not ported and answers
//! as an operation not yet ported.
//!
//! NOT YET IN `getGroups`' drill-down, and absent rather than empty:
//! `policyReferences` (the policy kinds' declared group references —
//! `PolicySelection.referencesOn('group')` — are not declared in this
//! runtime, whose policy registers are not wired yet) and `ownership`
//! (`ownership.objectOf()`).

use std::sync::Arc;

use serde_json::{json, Map, Value as Json};
use sts_core::errors::{codes, ErrorCode};
use sts_core::realm;
use sts_core::realm_store::RealmMap;
use sts_core::settings::Settings;
use sts_directory::EntryExt;
use sts_mgmt_api::families::Asked;
use sts_mgmt_api::paging::{Options, Paging};
use sts_mgmt_api::setup::Answered;
use sts_store::persistence::Persistence;

use super::groups::Groups;
use super::LiveDir;

/// `admin_stats.users`' handle.
pub const USERS_HANDLE: &str = super::identity::USERS_HANDLE;

/// The identity register, read.
pub struct IdentityRegister {
    users: RealmMap<Json>,
    persistence: Arc<Persistence>,
    pub tokens: Arc<sts_oauth::minted::TokenRegister>,
    dir: Arc<LiveDir>,
}

impl IdentityRegister {
    /// The register over the map its writer declared
    /// (`admin_identity.rs`), before the store opened.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn over(
        users: RealmMap<Json>,
        persistence: Arc<Persistence>,
        tokens: Arc<sts_oauth::minted::TokenRegister>,
        dir: Arc<LiveDir>,
    ) -> IdentityRegister {
        IdentityRegister {
            users,
            persistence,
            tokens,
            dir,
        }
    }

    /// `identityOf(value)`: `(key, unresolved)` — a `urn:uuid:` subject is
    /// its person's name where it resolves, a realm-qualified name is the
    /// name, a DN or a DID is itself.
    // A hot path: once per token record; no span.
    pub fn identity_of(&self, value: &str) -> (String, bool) {
        let text = value.trim();
        if text.is_empty() {
            return (String::new(), false);
        }
        let rest = text.strip_prefix("urn:sts:user:").unwrap_or(text);
        if rest.len() >= 9 && rest[..9].eq_ignore_ascii_case("urn:uuid:") {
            let named = self
                .dir
                .with(|t| t.name_for_subject(&realm::current_id(), rest));
            if named.is_empty() {
                return (rest.to_string(), true);
            }
            return (named, false);
        }
        let dn = {
            let mut c = rest.chars();
            matches!(c.next(), Some(ch) if ch.is_ascii_alphabetic())
                && rest.split_once('=').is_some_and(|(n, _)| {
                    n.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
                })
        };
        let did = rest.len() > 4
            && rest[..4].eq_ignore_ascii_case("did:")
            && rest[4..].split_once(':').is_some_and(|(m, _)| {
                !m.is_empty() && m.chars().all(|c| c.is_ascii_alphanumeric())
            });
        if !dn && !did {
            if let Some(at) = rest.rfind('@').filter(|a| *a > 0) {
                return (rest[..at].to_string(), false);
            }
        }
        (rest.to_string(), false)
    }

    /// `holderKeyOf(username, sub)`.
    // A hot path: once per token record; no span.
    pub fn holder_key_of(&self, username: &str, sub: &str) -> String {
        if sub.len() >= 9 && sub[..9].eq_ignore_ascii_case("urn:uuid:") {
            let (key, unresolved) = self.identity_of(sub);
            if !key.is_empty() && !unresolved {
                return key;
            }
        }
        self.identity_of(if username.is_empty() { sub } else { username })
            .0
    }

    /// The register's records in the ambient realm: this process's, then
    /// every other process's that this one does not hold (`users.forEach`
    /// and `replication.remoteRows('admin_stats.users')`).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn records(&self) -> Vec<(String, Json)> {
        let realm_id = realm::current_id();
        let mut out: Vec<(String, Json)> =
            self.users.in_realm(&realm_id).entries();
        if let Some(minted) = self.persistence.minted() {
            let fan = minted.fan_in();
            for key in fan.remote_keys(USERS_HANDLE, Some(&realm_id)) {
                if out.iter().any(|(k, _)| *k == key) {
                    continue;
                }
                for value in
                    fan.remote_rows(USERS_HANDLE, Some(&realm_id), &key)
                {
                    if value.is_object() {
                        out.push((key.clone(), value));
                        break;
                    }
                }
            }
        }
        out
    }

    /// `userKeys()` (`collectUserKeys()`): every identity the register
    /// knows, the token holders' with them.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn user_keys(&self) -> std::collections::BTreeSet<String> {
        let mut keys = std::collections::BTreeSet::new();
        for (key, record) in self.records() {
            let named = record
                .get("key")
                .and_then(Json::as_str)
                .filter(|k| !k.is_empty())
                .map(str::to_string)
                .unwrap_or(key);
            keys.insert(named);
        }
        for record in self.tokens.records_in(&realm::current_id()) {
            let text = |k: &str| {
                record
                    .get(k)
                    .and_then(Json::as_str)
                    .unwrap_or("")
                    .to_string()
            };
            let key = self.holder_key_of(&text("username"), &text("sub"));
            let (folded, _) = self.identity_of(&key);
            if !folded.is_empty() {
                keys.insert(folded);
            }
        }
        keys
    }
}

/// The views.
/// `MAX_USERS`, the identity register's cap (`registryKeeps`).
const MAX_USERS: i64 = 2000;

/// `countedRows(counts, nameKey)`: one row per name, by count, highest
/// first (a stable sort, as `Array.prototype.sort` is).
fn counted_rows(counts: &Json, name_key: &str) -> Json {
    let mut rows: Vec<Json> = counts
        .as_object()
        .map(|o| {
            o.iter()
                .map(|(name, count)| {
                    let mut row = Map::new();
                    row.insert("count".into(), count.clone());
                    row.insert(name_key.into(), json!(name));
                    Json::Object(row)
                })
                .collect()
        })
        .unwrap_or_default();
    rows.sort_by(|a, b| {
        let n = |v: &Json| v["count"].as_f64().unwrap_or(0.0);
        n(b).partial_cmp(&n(a)).unwrap_or(std::cmp::Ordering::Equal)
    });
    Json::Array(rows)
}

fn bump(map: &mut Json, key: &str) {
    if let Some(o) = map.as_object_mut() {
        let n = o.get(key).and_then(Json::as_f64).unwrap_or(0.0) + 1.0;
        o.insert(key.into(), json!(n as i64));
    }
}

pub struct Views {
    pub mode: Arc<sts_core::mode::Mode>,
    pub roster: Arc<super::RosterRoles>,
    /// `adminActions.rolesAction()`, over the role register.
    pub role_actions: Arc<sts_registers::role_actions::RoleActions>,
    /// `adminActions.permissionsAction()`, over the application register.
    pub app_permissions: Arc<sts_registers::app_permissions::AppPermissions>,
    pub apps: Arc<sts_registers::applications::ApplicationRegistry>,
    pub dir: Arc<LiveDir>,
    pub settings: Arc<Settings>,
    pub register: Arc<IdentityRegister>,
}

/// `dnKey(dn)`: trimmed, lower-cased, the spaces around each comma gone.
fn dn_key(dn: &str) -> String {
    let lower = dn.trim().to_lowercase();
    let parts: Vec<&str> = lower.split(',').map(str::trim).collect();
    // `/\s*,\s*/g` folds only the spaces NEXT TO a comma: the ends of the
    // whole were trimmed already.
    parts.join(",")
}

fn text_of(query: &sts_mgmt_api::request::Query, key: &str) -> String {
    match query.get(key) {
        Some(Json::String(s)) => s.clone(),
        Some(Json::Array(l)) => {
            l.first().and_then(Json::as_str).unwrap_or("").to_string()
        }
        Some(Json::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

impl Views {
    /// The view an operation names, or None.
    #[tracing::instrument(level = "debug", skip_all, fields(op = asked.operation_id))]
    pub fn answer(&self, asked: &Asked<'_>) -> Option<Answered> {
        let setup = asked.setup?;
        let body = match asked.operation_id {
            "getGroups" => self.groups_json(asked, setup),
            "getUsers" => self.users_json(asked)?,
            "getDirectoryEntries" => self.directory_entries_json(asked),
            "getDirectoryService" => self.directory_service_json(asked),
            "grantGlobalConsent" => return Some(self.grant_global(asked)),
            "grantAdminRole" | "revokeAdminRole" => {
                return Some(self.rbac_action(asked))
            }
            "getAdminRoles" => self.rbac_list_json(asked, setup),
            "getNewUserForm" => self.new_user_json(asked),
            "getIssued" => self.tokens_json(asked),
            "createRole"
            | "deleteRole"
            | "describeRole"
            | "addRoleMember"
            | "removeRoleMember"
            | "addRolePermission"
            | "removeRolePermission"
            | "addRoleConferringClient"
            | "removeRoleConferringClient"
            | "addRoleOwner"
            | "removeRoleOwner" => {
                let o = self
                    .role_actions
                    .act(&self.with_action(asked), &actor_of(asked));
                return Some(answered_of(o, codes::STS_API_0059));
            }
            "setPermissionBase" | "definePermission" | "removePermission"
            | "grantPermission" | "revokePermission" => {
                let o = self
                    .app_permissions
                    .act(&self.with_action(asked), &actor_of(asked));
                return Some(answered_of(o, codes::STS_API_0058));
            }
            _ => return None,
        };
        Some(Answered {
            status: 200,
            body,
            code: None,
        })
    }

    fn admin_groups(&self) -> Json {
        json!({ "read": self.settings.value_of("admin.readGroup").as_str(),
                "write": self.settings.value_of("admin.writeGroup").as_str() })
    }

    /// `groupsJson(req)`: the list, or one group with `?group=`.
    #[tracing::instrument(level = "debug", skip_all)]
    fn groups_json(
        &self,
        asked: &Asked<'_>,
        setup: &sts_mgmt_api::setup::Setup<'_>,
    ) -> Json {
        let wanted = text_of(asked.query, "group").trim().to_string();
        let realm_id = realm::current_id();
        let info = self.dir.with(|t| {
            let r = t.realms().iter().position(|x| x.id == realm_id)?;
            Some(Groups { tree: t, r }.groups_for(&self.settings, &wanted))
        });
        let Some(info) = info else {
            return json!({ "directory": false, "groups": [] });
        };
        if wanted.is_empty() {
            self.groups_list_json(asked, setup, info)
        } else {
            self.group_detail_json(asked, &wanted, info)
        }
    }

    /// `groupsListJson(req)`.
    fn groups_list_json(
        &self,
        asked: &Asked<'_>,
        setup: &sts_mgmt_api::setup::Setup<'_>,
        info: Json,
    ) -> Json {
        let wanted_text = text_of(asked.query, "q").trim().to_string();
        let needle = wanted_text.to_lowercase();
        let excluded: Vec<String> = match asked.query.get("exclude") {
            None => Vec::new(),
            Some(Json::Array(l)) => {
                l.iter().map(|v| dn_key(v.as_str().unwrap_or(""))).collect()
            }
            Some(v) => vec![dn_key(v.as_str().unwrap_or(""))],
        }
        .into_iter()
        .filter(|one| !one.is_empty())
        .collect();
        let all: Vec<Json> =
            info["groups"].as_array().cloned().unwrap_or_default();
        let filtered: Vec<Json> = all
            .iter()
            .filter(|g| {
                let dn = g["dn"].as_str().unwrap_or("");
                if excluded.contains(&dn_key(dn)) {
                    return false;
                }
                needle.is_empty()
                    || dn.to_lowercase().contains(&needle)
                    || g["cn"]
                        .as_str()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&needle)
            })
            .cloned()
            .collect();
        let paging =
            Paging::of(asked.query, filtered.len(), Options::default());
        let shown = paging.slice(&filtered);
        let sum = |k: &str| -> i64 {
            all.iter().map(|g| g[k].as_i64().unwrap_or(0)).sum()
        };
        json!({
            "groupCount": info["groupCount"],
            "matched": filtered.len(),
            "shown": shown.len(),
            "canWrite": true,
            "membershipValues": sum("memberCount"),
            "dangling": sum("danglingCount"),
            "settings": setup.page_settings("/admin/groups"),
            "filter": {
                "q": if wanted_text.is_empty() { Json::Null }
                     else { json!(wanted_text) },
                "exclude": if excluded.is_empty() { Json::Null }
                           else { json!(excluded) },
            },
            "page": paging.page, "pages": paging.pages,
            "perPage": paging.per_page,
            "firstRow": paging.first_row, "lastRow": paging.last_row,
            "baseDn": info["baseDn"], "groupsDn": info["groupsDn"],
            "usersDn": info["usersDn"],
            "port": info["port"], "listening": info["listening"],
            "listenError": info["listenError"],
            "ldapsPort": info["ldapsPort"],
            "ldapsListening": info["ldapsListening"],
            "paging": paging.to_json(),
            "entryCount": info["entryCount"],
            "adminGroups": self.admin_groups(),
            "groups": shown,
        })
    }

    /// `groupDetailJson(req, dn)`.
    fn group_detail_json(
        &self,
        asked: &Asked<'_>,
        wanted: &str,
        info: Json,
    ) -> Json {
        let mut out: Map<String, Json> =
            info.as_object().cloned().unwrap_or_default();
        if info["found"] != json!(true) {
            out.insert("wanted".into(), json!(wanted));
            out.insert("adminGroups".into(), self.admin_groups());
            return Json::Object(out);
        }
        let mut group = info["group"].clone();
        let members = group["members"].as_array().cloned().unwrap_or_default();
        let claimed = group["claimed"].as_array().cloned().unwrap_or_default();
        let member_page = Paging::of(
            asked.query,
            members.len(),
            Options {
                name: "members",
                noun: "members",
                ..Options::default()
            },
        );
        let claimed_page = Paging::of(
            asked.query,
            claimed.len(),
            Options {
                name: "claimed",
                noun: "entries",
                ..Options::default()
            },
        );
        let members_shown = member_page.slice(&members);
        let claimed_shown = claimed_page.slice(&claimed);
        group["members"] = json!(members_shown);
        group["claimed"] = json!(claimed_shown);
        // `knownHere`: the shown rows' keys the identity register knows.
        let known_keys = self.register.user_keys();
        let mut known = Map::new();
        for one in members_shown.iter().chain(claimed_shown.iter()) {
            let key = one["userKey"].as_str().unwrap_or("");
            if !key.is_empty() && known_keys.contains(key) {
                known.insert(key.to_string(), json!(true));
            }
        }
        out.insert("canWrite".into(), json!(true));
        out.insert("group".into(), group);
        out.insert("membersPaging".into(), member_page.to_json());
        out.insert("claimedPaging".into(), claimed_page.to_json());
        out.insert("known".into(), Json::Object(known));
        out.insert("adminGroups".into(), self.admin_groups());
        Json::Object(out)
    }

    /// `consentAction()`'s `grant-global-consent` and
    /// `consent.grantGlobal(client, scope, actor)`: the scope held to the
    /// scope token rule (STS-REG-0018), `oauthGlobalConsent` added to the
    /// application's entry (the register's own refusals), and the
    /// sentence saying it is an override. A refusal is
    /// `refusedBy('STS-ADMIN-0540', result)`: the register's code where it
    /// has one.
    #[tracing::instrument(level = "debug", skip_all)]
    fn grant_global(&self, asked: &Asked<'_>) -> Answered {
        let field = |k: &str| -> String {
            match asked.body.get(k) {
                Some(Json::String(s)) => s.trim().to_string(),
                Some(Json::Null) | None => String::new(),
                Some(other) => other.to_string().trim().to_string(),
            }
        };
        let who = field("client");
        let leaf = field("scope");
        let actor = asked.caller.map(|c| c.name.clone()).unwrap_or_default();
        let refused = |code: ErrorCode, body: Json| Answered {
            status: 400,
            body,
            code: Some(code),
        };
        if let Some(problem) =
            sts_registers::applications::checks::uris::scope_token_problem(
                &leaf,
            )
        {
            return refused(
                codes::STS_REG_0018,
                json!({ "ok": false, "errors": [problem] }),
            );
        }
        let result = self.apps.update_application(
            &who,
            &json!({ "attribute": "oauthGlobalConsent", "mode": "add",
                     "value": leaf, "actor": actor }),
        );
        if result.answer.get("ok") != Some(&Json::Bool(true)) {
            return refused(
                result.code.unwrap_or(codes::STS_ADMIN_0540),
                result.answer,
            );
        }
        let permission = self.apps.for_permission(&leaf);
        tracing::info!(
            "consent: \"{}\" is globally consented for the application \
             \"{}\". Nobody signing in to it will be asked about that scope \
             again, and nothing is written to anybody's entry — this is an \
             override rather than a record.",
            leaf,
            who
        );
        let exposed = permission
            .map(|p| {
                format!(
                    ", which is the permission \"{}\" exposed by \"{}\"",
                    p["name"].as_str().unwrap_or(""),
                    p["identifier"].as_str().unwrap_or("")
                )
            })
            .unwrap_or_default();
        let mut body = result.answer;
        if let Some(map) = body.as_object_mut() {
            map.insert(
                "message".into(),
                json!(format!(
                    "Everybody who signs in to \"{who}\" is now treated as \
                     having consented to <code>{leaf}</code>{exposed}. No \
                     consent was written onto anybody's entry: this is an \
                     OVERRIDE, so removing it asks everybody again — \
                     including the people who would have said yes."
                )),
            );
        }
        Answered {
            status: 200,
            body,
            code: None,
        }
    }

    /// `POST /admin-api/rbac/{grant,revoke}` (`adminActions.rbacAction()`):
    /// the roster's act in the ambient realm, 200 for `ok` and 400
    /// otherwise, marked with the act's code or STS-API-0034.
    #[tracing::instrument(level = "debug", skip_all)]
    fn rbac_action(&self, asked: &Asked<'_>) -> Answered {
        let mut body = asked.body.as_object().cloned().unwrap_or_default();
        body.insert("action".into(), json!(asked.action));
        let actor = asked.caller.map(|c| c.name.clone()).unwrap_or_default();
        let rbac = self.roster.rbac(&realm::current_id());
        let outcome = rbac.act(&Json::Object(body), "api", &actor);
        let ok = outcome.answer.get("ok") == Some(&Json::Bool(true));
        Answered {
            status: if ok { 200 } else { 400 },
            code: if ok {
                None
            } else {
                Some(outcome.code.unwrap_or(codes::STS_API_0034))
            },
            body: outcome.answer,
        }
    }

    /// `withAction(req, body)`: the body with the path's action forced
    /// over whatever it carried.
    fn with_action(&self, asked: &Asked<'_>) -> Json {
        let mut body = asked.body.as_object().cloned().unwrap_or_default();
        body.insert("action".into(), json!(asked.action));
        Json::Object(body)
    }

    /// `apiGateStateOf(caller)`: who is asking, in `gateStateFor()`'s
    /// shape, from the `/admin-api` token's caller.
    fn api_gate_state_of(&self, asked: &Asked<'_>) -> Json {
        let Some(caller) = asked.caller else {
            return json!({ "username": "", "roles": [], "read": false,
                           "write": false, "open": false });
        };
        let identity_realm = if caller.realm.is_empty() {
            realm::DEFAULT_ID.to_string()
        } else {
            caller.realm.clone()
        };
        let outside = identity_realm != realm::DEFAULT_ID
            && realm::current_id() != identity_realm;
        let roles: Vec<String> = caller
            .roles
            .iter()
            .map(|r| match r.as_str() {
                "ADMIN_READ" => "read".to_string(),
                "ADMIN_WRITE" => "write".to_string(),
                "SECURITY_ADMIN" => "security".to_string(),
                other => other.to_lowercase(),
            })
            .collect();
        let has = |id: &str| !outside && roles.iter().any(|r| r == id);
        json!({
            "username": caller.name,
            "roles": if outside { Vec::new() } else { roles.clone() },
            "read": has("read") || has("write") || has("security"),
            "write": has("write"),
            "open": false,
        })
    }

    /// `GET /admin-api/rbac` (`adminViews.rbacListJson(req)`, and
    /// `windowedRbacList()` where the directory is a window over the
    /// store): the realm's roster as `rbac.describe()` gives it, one row
    /// per grant, filtered by `q` and `role` and paged, and the people a
    /// role could be granted to, searched by `personq` and paged by
    /// `candidatesPage` (or the pane's `personfrom`).
    ///
    /// Held in memory the candidates are the directory's people and who
    /// has signed in (`rbac.candidates()`); windowed they are the direct
    /// children of `ou=users` in RDN order, a page at a time, the
    /// username the lower-cased RDN (`candidatePageAsync()`).
    #[tracing::instrument(level = "debug", skip_all)]
    fn rbac_list_json(
        &self,
        asked: &Asked<'_>,
        setup: &sts_mgmt_api::setup::Setup<'_>,
    ) -> Json {
        let realm_id = realm::current_id();
        let rbac = self.roster.rbac(&realm_id);
        let info = rbac.describe();
        let state = self.api_gate_state_of(asked);
        let lower = |v: &Json| v.as_str().unwrap_or("").to_lowercase();
        let mut grants: Vec<Json> = Vec::new();
        for role in info["roles"].as_array().cloned().unwrap_or_default() {
            for m in role["members"].as_array().cloned().unwrap_or_default() {
                grants.push(json!({
                    "username": m["username"], "role": role["role"],
                    "roleLabel": role["label"], "cn": role["cn"],
                    "dn": role["dn"], "value": m["value"],
                    "attribute": m["attribute"], "holds": m["holds"],
                    "memberDn": m["dn"], "present": m["present"],
                    "kind": m["kind"], "userKey": m["userKey"],
                }));
            }
        }
        grants.sort_by(|a, b| {
            let (an, bn) = (lower(&a["username"]), lower(&b["username"]));
            if an != bn {
                return an.cmp(&bn);
            }
            // `a.role < b.role ? -1 : 1`: never equal.
            if a["role"].as_str() < b["role"].as_str() {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        });
        let wanted_text = text_of(asked.query, "q").trim().to_string();
        let needle = wanted_text.to_lowercase();
        let wanted_role = text_of(asked.query, "role").trim().to_lowercase();
        let filtered: Vec<Json> = grants
            .iter()
            .filter(|row| {
                if !wanted_role.is_empty()
                    && row["role"].as_str() != Some(wanted_role.as_str())
                {
                    return false;
                }
                needle.is_empty()
                    || lower(&row["username"]).contains(&needle)
                    || lower(&row["value"]).contains(&needle)
            })
            .cloned()
            .collect();
        let paging = Paging::of(
            asked.query,
            filtered.len(),
            Options {
                noun: "grants",
                ..Options::default()
            },
        );
        let shown = paging.slice(&filtered);
        let known: std::collections::BTreeSet<String> =
            self.register.user_keys();
        let folded: std::collections::BTreeSet<String> =
            known.iter().map(|k| k.to_lowercase()).collect();
        let seen = |name: &str| -> bool {
            !name.is_empty() && folded.contains(&name.to_lowercase())
        };
        let person_wanted = text_of(asked.query, "personq").trim().to_string();
        let person_asked = text_of(asked.query, "person").trim().to_string();
        let candidate_options = Options {
            name: "candidates",
            noun: "people",
            default_per: Some(CHOOSER_HITS),
            ..Options::default()
        };
        // Every candidate this process can list, as `{username,
        // inDirectory, seen}`, and how many the walk counted.
        let windowed = self.windowed();
        let usable = |name: &str| {
            !name.is_empty() && !name.chars().any(|c| ",=+<>#;\"\\".contains(c))
        };
        let (all, total) = self.dir.with(|t| {
            let Some(r) = t.realms().iter().position(|x| x.id == realm_id)
            else {
                return (Vec::new(), 0usize);
            };
            let users =
                sts_ldap::service_dn::normalize_dn(Some(&t.users_dn(r)));
            let mut rdns: Vec<String> = Vec::new();
            for e in t.realms()[r].entries.values() {
                let dn = &e.dn;
                let parent = dn.split_once(',').map(|x| x.1).unwrap_or("");
                let direct =
                    sts_ldap::service_dn::normalize_dn(Some(parent)) == users;
                if windowed && !direct {
                    continue;
                }
                if !windowed && !t.is_person_dn(r, dn) {
                    continue;
                }
                let first = dn.split(',').next().unwrap_or("");
                let value = first.split_once('=').map(|x| x.1).unwrap_or("");
                rdns.push(value.to_string());
            }
            let total = rdns.len();
            (rdns, total)
        });
        let mut rows: Vec<Json> = Vec::new();
        if windowed {
            let mut names: Vec<String> =
                all.iter().map(|v| v.to_lowercase()).collect();
            names.sort_by(|a, b| store_order(a, b));
            for name in names {
                if !usable(&name) {
                    continue;
                }
                rows.push(json!({ "username": name, "inDirectory": true,
                                  "seen": seen(&name) }));
            }
        } else {
            // `rbac.candidates(seen)`: by lower-cased name, the
            // directory's first, then who has signed in.
            let mut by: Vec<(String, Json)> = Vec::new();
            let mut add = |name: &str, source: &str| {
                let value = name.trim();
                if value.is_empty() {
                    return;
                }
                let key = value.to_lowercase();
                let at = match by.iter().position(|(k, _)| *k == key) {
                    Some(i) => i,
                    None => {
                        by.push((
                            key,
                            json!({ "username": value,
                            "inDirectory": false, "seen": false }),
                        ));
                        by.len() - 1
                    }
                };
                by[at].1[source] = json!(true);
            };
            for name in &all {
                add(name, "inDirectory");
            }
            for key in &known {
                add(key, "seen");
            }
            let mut list: Vec<Json> = by
                .into_iter()
                .map(|(_, v)| v)
                .filter(|v| usable(v["username"].as_str().unwrap_or("")))
                .collect();
            list.sort_by(|a, b| {
                sts_registers::js::locale_compare(
                    a["username"].as_str().unwrap_or(""),
                    b["username"].as_str().unwrap_or(""),
                )
            });
            rows = list;
        }
        let pw = person_wanted.to_lowercase();
        let matched: Vec<Json> = rows
            .iter()
            .filter(|row| {
                pw.is_empty()
                    || row["username"]
                        .as_str()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&pw)
            })
            .cloned()
            .collect();
        let mut candidate_paging =
            Paging::of(asked.query, matched.len(), candidate_options);
        let offset_asked: Option<i64> =
            text_of(asked.query, "personfrom").trim().parse().ok();
        if text_of(asked.query, "candidatesPage").is_empty() {
            if let Some(off) =
                offset_asked.filter(|o| *o > 0 && (*o as usize) < matched.len())
            {
                let mut as_page = asked.query.clone();
                as_page.insert(
                    "candidatesPage".into(),
                    json!(((off / candidate_paging.per_page) + 1).to_string()),
                );
                candidate_paging =
                    Paging::of(&as_page, matched.len(), candidate_options);
            }
        }
        let pane_from = offset_asked
            .filter(|o| *o >= 0 && (*o as usize) < matched.len())
            .unwrap_or(0) as usize;
        let page_rows = candidate_paging.slice(&matched);
        let pane_rows: Vec<Json> = matched
            .iter()
            .skip(pane_from)
            .take(CHOOSER_HITS as usize)
            .cloned()
            .collect();
        let picked = if person_asked.is_empty() {
            Json::Null
        } else {
            let wanted = person_asked.to_lowercase();
            let hit = rows
                .iter()
                .find(|row| {
                    row["username"].as_str().unwrap_or("").to_lowercase()
                        == wanted
                })
                .cloned();
            let hit = hit.or_else(|| {
                (windowed && seen(&person_asked)).then(|| {
                    let key = known
                        .iter()
                        .find(|k| k.to_lowercase() == wanted)
                        .cloned()
                        .unwrap_or_default();
                    json!({ "username": key, "inDirectory": false,
                            "seen": true })
                })
            });
            json!({ "asked": person_asked,
                    "candidate": hit.unwrap_or(Json::Null) })
        };
        let mut known_here = Map::new();
        for row in &shown {
            if let Some(k) = row["userKey"].as_str().filter(|k| !k.is_empty()) {
                if known.contains(k) {
                    known_here.insert(k.to_string(), json!(true));
                }
            }
        }
        let roles: Vec<Json> = info["roles"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|mut role| {
                if let Some(o) = role.as_object_mut() {
                    o.remove("members");
                    o.remove("claimed");
                }
                role
            })
            .collect();
        let choices: Vec<Json> = sts_registers::roles::ROSTER_ROLES
            .iter()
            .map(|r| {
                json!({ "id": r.id, "label": r.label, "setting": r.setting,
                        "implies": r.implies, "what": r.what })
            })
            .collect();
        let or_null = |s: &str| {
            if s.is_empty() {
                Json::Null
            } else {
                json!(s)
            }
        };
        json!({
            "enforced": info["enforced"],
            "openWhenEmpty": info["openWhenEmpty"],
            "openToAnyone": info["openToAnyone"],
            "closedToEveryone": info["closedToEveryone"],
            "windowOpens": info["windowOpens"],
            "bootstrapPasswordRequired": info["bootstrapPasswordRequired"],
            "bootstrap": info["bootstrap"],
            "available": info["available"], "groupsDn": info["groupsDn"],
            "usersDn": info["usersDn"], "grantCount": info["grantCount"],
            "matched": filtered.len(), "shown": shown.len(),
            "settings": setup.page_settings("/admin/rbac"),
            "filter": { "q": or_null(&wanted_text),
                        "role": or_null(&wanted_role) },
            "page": paging.page, "pages": paging.pages,
            "perPage": paging.per_page, "firstRow": paging.first_row,
            "lastRow": paging.last_row,
            "you": { "username": state["username"], "roles": state["roles"],
                     "read": state["read"], "write": state["write"],
                     "viaEmptyRoster": state["open"] },
            "roles": roles,
            "grants": shown,
            "candidates": page_rows,
            "candidatesPaging": candidate_paging.to_json(),
            "candidateSearch": {
                "q": or_null(&person_wanted),
                "total": if windowed { total } else { rows.len() },
                "matched": matched.len(), "countCapped": false,
                "countCap": WINDOWED_PAGE_CAP, "complete": true,
                "incomplete": Json::Null,
            },
            "picked": picked,
            "paging": paging.to_json(),
            "candidatePane": { "from": pane_from, "matched": matched.len(),
                               "countCapped": false, "shown": pane_rows },
            "known": known_here,
            "roleChoices": choices,
        })
    }

    /// `GET /admin-api/users/new` (`adminViews.newUserJson(req)`): the
    /// form a person is created from — the credential catalogue a create's
    /// `attributes` are checked against, the field grid, what the realm's
    /// attribute policy requires and whether it is enforced (product), the
    /// credential choices, the rows the form draws (`newUserFieldRows()`)
    /// and the password rules a typed or generated password meets.
    ///
    /// The constant members are Node's own, exported for a realm with no
    /// custom attribute (`tables/admin_api.json`'s `newUserForm`); what the
    /// realm's policy requires is this process's. The password rules are
    /// the default profile's (`passwordPolicy.describe()`): no group names
    /// a password policy in this runtime, whose policy registers are not
    /// wired yet.
    #[tracing::instrument(level = "debug", skip_all)]
    fn new_user_json(&self, asked: &Asked<'_>) -> Json {
        let form = &sts_mgmt_api::tables::tables().new_user_form;
        let realm_now = realm::current();
        let realm_id = realm::current_id();
        let username = text_of(asked.query, "user").trim().to_string();
        let container = self.dir.with(|t| {
            t.realms()
                .iter()
                .position(|x| x.id == realm_id)
                .map(|r| t.users_dn(r))
        });
        let credentials = |with_what: bool| -> Json {
            Json::Array(
                form["credentials"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|mut c| {
                        if !with_what {
                            if let Some(o) = c.as_object_mut() {
                                o.remove("what");
                            }
                        }
                        c
                    })
                    .collect(),
            )
        };
        let realm_json =
            json!({ "id": realm_id, "name": realm_now.name.as_str() });
        let Some(container) = container else {
            return json!({ "directory": false, "container": Json::Null,
                           "realm": realm_json, "fields": [],
                           "credentials": credentials(false) });
        };
        let required = sts_directory::ports::default_required_attributes();
        let required_lower: Vec<String> =
            required.iter().map(|r| r.to_lowercase()).collect();
        let field_rows: Vec<Json> = form["rows"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|row| {
                let s = |k: &str| row[k].as_str().unwrap_or("").to_string();
                let name = s("name");
                let multi = row["multi"].as_bool().unwrap_or(false);
                let claim = s("claim");
                let is_required = required_lower.contains(&name.to_lowercase());
                let mut what = format!("{} — {}.", s("label"), s("schema"));
                if !s("note").is_empty() {
                    what.push_str(&format!(" It takes {}.", s("note")));
                }
                if !multi {
                    what.push_str(" It holds one value.");
                }
                if !claim.is_empty() {
                    what.push_str(&format!(
                        " It reaches a credential as {claim}."
                    ));
                }
                json!({
                    "attribute": name,
                    "type": if multi { "array" } else { "string" },
                    "what": what, "example": row["example"],
                    "forText": row["label"], "families": [],
                    "everyFamily": true, "group": row["group"],
                    "simple": row["simple"].as_bool().unwrap_or(false)
                        || is_required,
                    "required": is_required,
                })
            })
            .collect();
        let transport = self.settings.value_of("mail.transport");
        let captures = self.mode.predicate("capturesMail").unwrap_or(false);
        let transport = match transport.as_str() {
            "" | "default" => {
                if captures {
                    "capture"
                } else {
                    "off"
                }
            }
            other => other,
        }
        .to_string();
        let mail_available =
            transport != "off" && !(transport == "capture" && !captures);
        let status = self.register.persistence.status();
        // `passwordPolicy.describe(profile)`: the default profile's two
        // sentences, filled (`serverProse.fill()`).
        let sentences = &form["passwordSentences"];
        let profile = sts_policy::kinds::password::PasswordPolicy::defaults();
        let number = |k: &str| {
            profile
                .get(k)
                .and_then(Json::as_f64)
                .map(|n| n.to_string())
                .unwrap_or_default()
        };
        let fill = |k: &str, n: &str| {
            sentences[k].as_str().unwrap_or("").replace("{{n}}", n)
        };
        let mut rules = vec![fill("minLength", &number("minLength"))];
        if profile.get("history").and_then(Json::as_f64).unwrap_or(0.0) > 0.0 {
            rules.push(fill("history", &number("history")));
        }
        let credential = text_of(asked.query, "credential");
        let default_credential =
            form["defaultCredential"].as_str().unwrap_or("generate");
        json!({
            "directory": true,
            "container": container,
            "realm": realm_json,
            "mode": self.mode.current(),
            "offersExampleData": self.mode.current() == "development",
            "fields": form["fields"],
            "fieldGroups": form["fieldGroups"],
            "gridFields": form["gridFields"],
            "requiredAttributes": required,
            "requiredEnforced":
                !self.mode.predicate("createsIncompletePeople").unwrap_or(false),
            "credentials": credentials(true),
            "username": username,
            "fieldRows": field_rows,
            "longTextAttributes": form["longTextAttributes"],
            "mailAvailable": mail_available,
            "persistence": {
                "persistsDirectory":
                    status["persistsDirectory"].as_bool().unwrap_or(false),
                "mode": status["mode"],
            },
            "defaultCredential": default_credential,
            "credential": if credential.is_empty() {
                default_credential.to_string()
            } else {
                credential
            },
            "passwordPolicy": {
                "enforced":
                    self.mode.predicate("verifiesCredentials").unwrap_or(false),
                "profile": "default",
                "rules": rules,
            },
        })
    }

    /// `usersListJson(req)` (`GET /admin-api/users` without `?user=`), IN
    /// PART: the people this service has seen authenticate (the identity
    /// register's rows, as `userRow()` builds each) and the directory's
    /// people it has not (a blank row, `knownBy: directory`), applications
    /// left out, sorted by name, filtered by `q` and `protocol` and paged.
    ///
    /// NOT YET: the credential census (`secondFactorPopulation()`,
    /// `peopleCensus()`), so every row's `factors` is null, `factor`
    /// filters nothing and the `factors`, `directoryCounts` and service
    /// account members are absent; the live-session count is zero.
    #[tracing::instrument(level = "debug", skip_all)]
    fn users_list_json(&self, asked: &Asked<'_>) -> Json {
        let realm_id = realm::current_id();
        let mut by: indexmap::IndexMap<String, Json> =
            indexmap::IndexMap::new();
        for key in self.register.user_keys() {
            if let Some(mut row) = self.user_row(&key) {
                row["factors"] = Json::Null;
                row["inDirectory"] = json!(false);
                by.insert(key, row);
            }
        }
        let (people, applications) = self.dir.with(|t| {
            let Some(r) = t.realms().iter().position(|x| x.id == realm_id)
            else {
                return (Vec::new(), Vec::new());
            };
            let people: Vec<String> = t.realms()[r]
                .entries
                .values()
                .filter(|e| t.is_person_dn(r, &e.dn))
                .map(sts_directory::Directory::person_name_of)
                .filter(|n| !n.is_empty())
                .collect();
            let apps: Vec<String> = t.realms()[r]
                .entries
                .values()
                .filter(|e| e.dn.to_lowercase().contains(",ou=applications,"))
                .filter_map(|e| e.first("cn").map(str::to_string))
                .collect();
            (people, apps)
        });
        for name in &people {
            let key = sts_registers::persona::plain_identity_key(name);
            if key.is_empty() {
                continue;
            }
            let row = by.entry(key.clone()).or_insert_with(|| {
                json!({ "key": key, "name": name, "forms": [],
                        "realms": [], "protocols": [], "authentications": 0,
                        "firstAt": 0, "lastAt": 0, "isClient": false,
                        "authenticated": false, "knownBy": "directory",
                        "events": [], "eventsForgotten": 0,
                        "tokens": { "issued": 0, "valid": 0, "expired": 0,
                                    "revoked": 0, "other": 0 },
                        "artifactKinds": [], "artifacts": 0,
                        "lastActivityAt": 0, "factors": Json::Null,
                        "inDirectory": false })
            });
            row["inDirectory"] = json!(true);
        }
        // `isApplicationRow()`: a client the register saw is not a person.
        let mut all: Vec<Json> = by
            .into_values()
            .filter(|row| {
                let key = row["key"].as_str().unwrap_or("");
                !(row["isClient"] == json!(true)
                    && !row["inDirectory"].as_bool().unwrap_or(false))
                    && !applications.iter().any(|a| a == key)
            })
            .collect();
        all.sort_by(|a, b| {
            let n = |v: &Json| v["name"].as_str().unwrap_or("").to_lowercase();
            if n(a) < n(b) {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        });
        for row in all.iter_mut() {
            row["serviceAccount"] = json!(false);
        }
        let wanted_text = text_of(asked.query, "q").trim().to_string();
        let wanted_protocol = text_of(asked.query, "protocol");
        let wanted_factor = text_of(asked.query, "factor");
        let kind = text_of(asked.query, "kind");
        let wanted_kind = if kind == "service" || kind == "person" {
            kind
        } else {
            String::new()
        };
        let mut protocols: Vec<String> = Vec::new();
        for row in &all {
            for f in row["protocols"].as_array().cloned().unwrap_or_default() {
                if let Some(p) = f["protocol"].as_str() {
                    if !protocols.iter().any(|x| x == p) {
                        protocols.push(p.to_string());
                    }
                }
            }
        }
        protocols.sort();
        let filtered: Vec<Json> = all
            .iter()
            .filter(|row| {
                let key = row["key"].as_str().unwrap_or("").to_lowercase();
                if !wanted_text.is_empty()
                    && !key.contains(&wanted_text.to_lowercase())
                {
                    return false;
                }
                if !wanted_protocol.is_empty()
                    && !row["protocols"].as_array().is_some_and(|l| {
                        l.iter().any(|f| {
                            f["protocol"].as_str()
                                == Some(wanted_protocol.as_str())
                        })
                    })
                {
                    return false;
                }
                wanted_kind != "service"
            })
            .cloned()
            .collect();
        // `pagedRows(query, filtered)`: no noun, so `rows`.
        let paging =
            Paging::of(asked.query, filtered.len(), Options::default());
        let users_dn = self.dir.with(|t| {
            t.realms()
                .iter()
                .position(|x| x.id == realm_id)
                .map(|r| t.users_dn(r))
                .unwrap_or_default()
        });
        let shown: Vec<Json> = paging
            .slice(&filtered)
            .into_iter()
            .map(|mut row| {
                let key = row["key"].as_str().unwrap_or("").to_string();
                let dn = self.dir.with(|t| {
                    t.realms()
                        .iter()
                        .position(|x| x.id == realm_id)
                        .and_then(|r| t.locate(r, &key).map(|e| e.dn.clone()))
                        .unwrap_or_default()
                });
                row["liveSessions"] = json!(0);
                row["dn"] = json!(dn);
                row
            })
            .collect();
        let or_null = |s: &str| {
            if s.is_empty() {
                Json::Null
            } else {
                json!(s)
            }
        };
        let field_count = sts_registers::persona::tables()
            .map_or(0, |t| t.person_fields.len());
        json!({
            "known": all.len(), "matched": filtered.len(),
            "shown": shown.len(),
            "authenticatedHere": all.iter()
                .filter(|r| r["authenticated"] == json!(true)).count(),
            "registryCap": MAX_USERS,
            "filter": { "q": or_null(&wanted_text),
                        "protocol": or_null(&wanted_protocol),
                        "factor": or_null(&wanted_factor),
                        "kind": or_null(&wanted_kind) },
            "serviceAccounts": 0,
            "protocols": protocols,
            "page": paging.page, "pages": paging.pages,
            "perPage": paging.per_page, "firstRow": paging.first_row,
            "lastRow": paging.last_row, "paging": paging.to_json(),
            "withActiveSession": 0,
            "personFieldCount": field_count,
            "newUserContainer": users_dn,
            "registryKeeps": MAX_USERS,
            "users": shown,
        })
    }

    /// `GET /admin-api/tokens` (`tokensView(query)`): every JWT the token
    /// register holds in the realm (`issuedList()`, newest first), grouped
    /// into the sets one response issued together (`groupIssued()`),
    /// filtered by `family`, `kind`, `state` and `session` and paged.
    ///
    /// The register is held whole here, so the coverage is `held` and
    /// complete. NOT YET: the artifact families (SAML assertions, Kerberos
    /// tickets, SVIDs), whose register (`admin_stats.artifacts`) this
    /// runtime does not read — their counts are zero.
    #[tracing::instrument(level = "debug", skip_all)]
    fn tokens_json(&self, asked: &Asked<'_>) -> Json {
        let tables = &sts_mgmt_api::tables::tables().issued;
        let now_ms = chrono::Utc::now().timestamp_millis() as f64;
        let mut rows: Vec<(f64, usize, Json)> = self
            .register
            .tokens
            .records_in(&realm::current_id())
            .into_iter()
            .enumerate()
            .map(|(i, mut r)| {
                let state = self.token_state(&r, now_ms);
                let exp = r.get("exp").and_then(Json::as_f64).unwrap_or(0.0);
                let issued =
                    r.get("issuedAt").and_then(Json::as_f64).unwrap_or(0.0);
                r["family"] = json!("token");
                r["state"] = json!(state);
                r["expiresAtMs"] =
                    json!(if exp > 0.0 { exp * 1000.0 } else { 0.0 });
                r["identifier"] =
                    json!(r.get("jti").and_then(Json::as_str).unwrap_or(""));
                r["revocationReach"] = json!("protocol");
                (issued, i, r)
            })
            .collect();
        rows.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(b.1.cmp(&a.1))
        });
        let rows: Vec<Json> = rows
            .into_iter()
            .enumerate()
            .map(|(i, (_, _, mut r))| {
                r["order"] = json!(i);
                r
            })
            .collect();
        // `groupIssued(rows)`.
        let mut sets: indexmap::IndexMap<String, (String, Vec<Json>)> =
            indexmap::IndexMap::new();
        for row in rows {
            let set_id = row["setId"].as_str().unwrap_or("").to_string();
            let key = if set_id.is_empty() {
                let k = row["key"].as_str().filter(|k| !k.is_empty());
                format!(
                    "one:{}",
                    k.unwrap_or(row["identifier"].as_str().unwrap_or(""))
                )
            } else {
                format!("set:{set_id}")
            };
            sets.entry(key)
                .or_insert_with(|| (set_id, Vec::new()))
                .1
                .push(row);
        }
        let text = |v: &Json| v.as_str().unwrap_or("").to_string();
        let all: Vec<Json> = sets
            .into_iter()
            .map(|(key, (set_id, mut members))| {
                members.sort_by_key(|m| m["order"].as_i64().unwrap_or(0));
                let first = members[0].clone();
                let mut states = Map::new();
                let mut shared = String::new();
                let mut mixed = false;
                let (mut issued, mut early, mut late) =
                    (0.0f64, 0.0f64, 0.0f64);
                let (mut revocable, mut revoked) = (0, 0);
                let mut kinds: Vec<Json> = Vec::new();
                let mut families: Vec<Json> = Vec::new();
                for m in &members {
                    let st = text(&m["state"]);
                    let n = states.get(&st).and_then(Json::as_i64).unwrap_or(0);
                    states.insert(st.clone(), json!(n + 1));
                    if shared.is_empty() {
                        shared = st.clone();
                    } else if shared != st {
                        mixed = true;
                    }
                    let at = m["issuedAt"].as_f64().unwrap_or(0.0);
                    if issued == 0.0 || at < issued {
                        issued = at;
                    }
                    let exp = m["expiresAtMs"].as_f64().unwrap_or(0.0);
                    if exp != 0.0 {
                        if early == 0.0 || exp < early {
                            early = exp;
                        }
                        if exp > late {
                            late = exp;
                        }
                    }
                    if m["revocable"] == json!(true) {
                        revocable += 1;
                    }
                    if st == "revoked" {
                        revoked += 1;
                    }
                    if !kinds.contains(&m["kind"]) {
                        kinds.push(m["kind"].clone());
                    }
                    if !families.contains(&m["family"]) {
                        families.push(m["family"].clone());
                    }
                }
                json!({
                    "setKey": key, "setId": set_id,
                    "grouped": members.len() > 1, "size": members.len(),
                    "kinds": kinds, "families": families,
                    "family": first["family"],
                    "state": if mixed { "mixed".to_string() } else { shared },
                    "states": states, "issuedAt": issued,
                    "expiresAtMs": early, "lastExpiresAtMs": late,
                    "username": text(&first["username"]),
                    "sub": text(&first["sub"]),
                    "client_id": text(&first["client_id"]),
                    "audience": text(&first["audience"]),
                    "scope": text(&first["scope"]),
                    "sessionId": text(&first["sessionId"]),
                    "sessionAuthenticated":
                        first["sessionAuthenticated"] != json!(false),
                    "grant": text(&first["grant"]),
                    "revocableCount": revocable, "revokedCount": revoked,
                    "members": members,
                })
            })
            .collect();
        let wanted = |k: &str| text_of(asked.query, k);
        let (family, kind, state, session) = (
            wanted("family"),
            wanted("kind"),
            wanted("state"),
            wanted("session"),
        );
        let has = |set: &Json, k: &str, v: &str| {
            set["members"].as_array().is_some_and(|l| {
                l.iter().any(|m| m[k].as_str().unwrap_or("") == v)
            })
        };
        let filtered: Vec<Json> = all
            .iter()
            .filter(|s| family.is_empty() || has(s, "family", &family))
            .filter(|s| kind.is_empty() || has(s, "kind", &kind))
            .filter(|s| state.is_empty() || has(s, "state", &state))
            .filter(|s| session.is_empty() || has(s, "sessionId", &session))
            .cloned()
            .collect();
        let paging =
            Paging::of(asked.query, filtered.len(), Options::default());
        let shown = paging.slice(&filtered);
        let count = |sets: &[Json]| -> i64 {
            sets.iter().map(|s| s["size"].as_i64().unwrap_or(0)).sum()
        };
        let mut by_family = Map::new();
        for f in tables["families"].as_array().cloned().unwrap_or_default() {
            let name = text(&f["family"]);
            let n = if name == "token" { count(&all) } else { 0 };
            by_family.insert(name, json!(n));
        }
        let records: Vec<Json> = shown
            .iter()
            .flat_map(|s| s["members"].as_array().cloned().unwrap_or_default())
            .collect();
        let or_null =
            |s: &str| if s.is_empty() { Json::Null } else { json!(s) };
        let (_, revoked_count) =
            self.register.tokens.held_in(&realm::current_id());
        json!({
            "held": count(&all), "heldSets": all.len(),
            "coverage": { "source": "held", "complete": true,
                          "newest": Json::Null,
                          "session": or_null(&session),
                          "unread": false, "countEstimated": false },
            "matched": filtered.len(), "matchedCredentials": count(&filtered),
            "shown": shown.len(), "shownCredentials": count(&shown),
            "heldByFamily": by_family,
            "filter": { "family": or_null(&family), "kind": or_null(&kind),
                        "state": or_null(&state),
                        "session": or_null(&session) },
            "page": paging.page, "pages": paging.pages,
            "perPage": paging.per_page, "firstRow": paging.first_row,
            "lastRow": paging.last_row,
            "families": tables["families"],
            "revocableKinds": tables["revocableKinds"],
            "revokedCount": revoked_count,
            "sets": shown,
            "issued": records,
            "paging": paging.to_json(),
        })
    }

    /// `tokenStateOf(record, now)`.
    fn token_state(&self, record: &Json, now_ms: f64) -> &'static str {
        let skew = self.settings.value_of("oauth2.clockSkewS").as_int() as f64
            * 1000.0;
        let num = |k: &str| record.get(k).and_then(Json::as_f64).unwrap_or(0.0);
        if record
            .get("revoked")
            .is_some_and(|v| !matches!(v, Json::Null | Json::Bool(false)))
            || record
                .get("jti")
                .and_then(Json::as_str)
                .is_some_and(|j| self.register.tokens.is_revoked(j))
        {
            return "revoked";
        }
        let (exp, nbf) = (num("exp"), num("nbf"));
        if exp != 0.0 && exp * 1000.0 + skew <= now_ms {
            return "expired";
        }
        if nbf != 0.0 && nbf * 1000.0 - skew > now_ms {
            return "not yet valid";
        }
        if exp == 0.0 {
            return "no expiry stated";
        }
        "valid"
    }

    /// `userRow(key)` (`buildUserRowsResolved(key)`): the register's record
    /// and the tokens it holds, or None for nobody either names.
    fn user_row(&self, wanted: &str) -> Option<Json> {
        let record = self
            .register
            .records()
            .into_iter()
            .map(|(_, v)| v)
            .find(|v| v.get("key").and_then(Json::as_str) == Some(wanted));
        let blank = |key: &str, name: &str| {
            json!({ "key": key, "name": name, "forms": {}, "realms": {},
                    "protocols": {}, "authentications": 0, "firstAt": 0,
                    "lastAt": 0, "isClient": false, "authenticated": false,
                    "events": [], "eventsForgotten": 0,
                    "tokens": { "issued": 0, "valid": 0, "expired": 0,
                                "revoked": 0, "other": 0 },
                    "artifactKinds": {}, "artifacts": 0,
                    "lastActivityAt": 0 })
        };
        let mut row: Option<Json> = record.map(|r| {
            let name = r["name"].as_str().unwrap_or(wanted).to_string();
            let mut row = blank(wanted, &name);
            for k in [
                "forms",
                "realms",
                "protocols",
                "authentications",
                "firstAt",
                "lastAt",
                "isClient",
                "eventsForgotten",
            ] {
                if let Some(v) = r.get(k) {
                    row[k] = v.clone();
                }
            }
            let known_by = r
                .get("knownBy")
                .and_then(Json::as_str)
                .filter(|k| !k.is_empty());
            row["authenticated"] = json!(known_by.is_none());
            row["knownBy"] = json!(known_by.unwrap_or("authentication"));
            row["events"] = r.get("events").cloned().unwrap_or(json!([]));
            row["lastActivityAt"] =
                r.get("lastAt").cloned().unwrap_or(json!(0));
            row
        });
        let now_ms = chrono::Utc::now().timestamp_millis() as f64;
        for record in self.register.tokens.records_in(&realm::current_id()) {
            let text = |k: &str| {
                record
                    .get(k)
                    .and_then(Json::as_str)
                    .unwrap_or("")
                    .to_string()
            };
            let holder =
                self.register.holder_key_of(&text("username"), &text("sub"));
            let (key, _) = self.register.identity_of(&holder);
            if key.is_empty() || key != wanted {
                continue;
            }
            let row = row.get_or_insert_with(|| blank(&key, &key));
            bump(&mut row["forms"], holder.trim());
            if !text("sub").is_empty() && !text("username").is_empty() {
                bump(&mut row["forms"], &text("sub"));
            }
            if text("grant") == "client_credentials" {
                row["isClient"] = json!(true);
            }
            bump(&mut row["tokens"], "issued");
            let state = match self.token_state(&record, now_ms) {
                "valid" => "valid",
                "expired" => "expired",
                "revoked" => "revoked",
                _ => "other",
            };
            bump(&mut row["tokens"], state);
            let issued =
                record.get("issuedAt").and_then(Json::as_f64).unwrap_or(0.0);
            if issued > row["lastActivityAt"].as_f64().unwrap_or(0.0) {
                row["lastActivityAt"] = record["issuedAt"].clone();
            }
        }
        let mut row = row?;
        let forms = counted_rows(&row["forms"], "form");
        let realms = counted_rows(&row["realms"], "realm");
        let kinds = counted_rows(&row["artifactKinds"], "kind");
        let mut protocols: Vec<Json> = row["protocols"]
            .as_object()
            .map(|o| {
                o.values()
                    .map(|f| {
                        json!({ "protocol": f["protocol"],
                                     "count": f["count"],
                                     "firstAt": f["firstAt"],
                                     "lastAt": f["lastAt"],
                                     "methods": counted_rows(&f["methods"],
                                                             "method") })
                    })
                    .collect()
            })
            .unwrap_or_default();
        protocols.sort_by(|a, b| {
            let n = |v: &Json| v["lastAt"].as_f64().unwrap_or(0.0);
            n(b).partial_cmp(&n(a)).unwrap_or(std::cmp::Ordering::Equal)
        });
        row["forms"] = forms;
        row["realms"] = realms;
        row["artifactKinds"] = kinds;
        row["protocols"] = json!(protocols);
        Some(row)
    }

    /// `ldapObjectJson(key)` (`withoutSecrets(objectFor(name))`): where the
    /// name is, or would be, filed, the entry with its secrets masked, and
    /// the directory's state.
    fn ldap_object(&self, wanted: &str) -> Json {
        let key = wanted.trim();
        let realm_id = realm::current_id();
        self.dir.with(|t| {
            let Some(r) = t.realms().iter().position(|x| x.id == realm_id)
            else {
                return Json::Null;
            };
            let model = sts_directory::DirectoryModel::get();
            let stored = if key.is_empty() {
                None
            } else {
                t.locate(r, key)
            };
            let dn = match stored {
                Some(e) => e.dn.clone(),
                None if key.is_empty() => String::new(),
                None => format!("uid={},{}", key, t.users_dn(r)),
            };
            let plain = !key.is_empty()
                && !key.contains('=')
                && !key.to_lowercase().starts_with("did:")
                && !key.to_lowercase().starts_with("spiffe://");
            let mut also: Vec<String> = Vec::new();
            if plain {
                let here = sts_ldap::service_dn::normalize_dn(Some(&dn));
                for e in t.realms()[r].entries.values() {
                    if sts_ldap::service_dn::normalize_dn(Some(&e.dn)) != here
                        && e.values("uid").iter().any(|v| v == key)
                    {
                        also.push(e.dn.clone());
                    }
                }
            }
            also.sort();
            let reads = Groups { tree: t, r };
            let state = reads.directory_state(&self.settings);
            let max = state["maxEntries"].as_i64().unwrap_or(0);
            let total: usize = t.realms().iter().map(|x| x.entries.len()).sum();
            let entry = stored.map(|e| {
                let mut names: Vec<&String> = e.attributes.keys().collect();
                names.sort();
                let mut attributes = Map::new();
                for name in names {
                    let values = sts_enroll::core::Core::withheld_values(
                        name,
                        e.values(name),
                    );
                    let values: Vec<Json> = if model.is_secret(name) {
                        values
                            .iter()
                            .map(|_| json!("(set — not returned)"))
                            .collect()
                    } else {
                        values.into_iter().map(Json::from).collect()
                    };
                    attributes.insert(
                        model.canonical_name(name),
                        Json::Array(values),
                    );
                }
                json!({ "dn": e.dn,
                        "origin": e.origin.as_deref().unwrap_or("unstated"),
                        "createdAt": e.created_at, "modifiedAt": e.modified_at,
                        "operational": sts_directory::directory::OPERATIONAL
                            .iter().map(|n| model.canonical_name(n))
                            .collect::<Vec<_>>(),
                        "attributes": attributes })
            });
            let auto = self.mode.predicate("autoCreates").unwrap_or(false)
                && self.settings.value_of("ldap.autocreateUsers").as_bool();
            json!({
                "dn": dn, "found": stored.is_some(),
                "entry": entry.unwrap_or(Json::Null),
                "alsoNamed": also,
                "baseDn": state["baseDn"], "usersDn": state["usersDn"],
                "port": state["port"], "listening": state["listening"],
                "listenError": state["listenError"],
                "ldapsPort": state["ldapsPort"],
                "ldapsListening": state["ldapsListening"],
                "autoCreateUsers": auto,
                "entryCount": state["entryCount"],
                "maxEntries": max,
                "full": total as i64 >= max,
            })
        })
    }

    /// `usersJson(req)` for one person (`?user=`); None for the list.
    #[tracing::instrument(level = "debug", skip_all)]
    fn users_json(&self, asked: &Asked<'_>) -> Option<Json> {
        let wanted = text_of(asked.query, "user").trim().to_string();
        if wanted.is_empty() {
            return Some(self.users_list_json(asked));
        }
        let realm_id = realm::current_id();
        let row = self.user_row(&wanted).or_else(|| {
            let in_directory = self.dir.with(|t| {
                t.realms()
                    .iter()
                    .position(|x| x.id == realm_id)
                    .and_then(|r| t.locate(r, &wanted).map(|_| ()))
                    .is_some()
            });
            in_directory.then(|| {
                json!({ "key": wanted, "name": wanted, "forms": [],
                        "realms": [], "protocols": [], "authentications": 0,
                        "firstAt": 0, "lastAt": 0, "isClient": false,
                        "authenticated": false, "knownBy": "directory",
                        "events": [], "eventsForgotten": 0,
                        "tokens": { "issued": 0, "valid": 0, "expired": 0,
                                    "revoked": 0, "other": 0 },
                        "artifactKinds": [], "artifacts": 0,
                        "lastActivityAt": 0 })
            })
        });
        let Some(row) = row else {
            return Some(json!({ "user": wanted, "known": false,
                                "registryKeeps": MAX_USERS }));
        };
        let subject = self.dir.with(|t| t.subject_for_name(&realm_id, &wanted));
        Some(json!({
            "known": true,
            "user": row,
            "subject": subject,
            "ldap": self.ldap_object(&wanted),
        }))
    }
}

/// The act's caller, for the audit row (`callerNameOf(res)`).
fn actor_of(asked: &Asked<'_>) -> String {
    asked.caller.map(|c| c.name.clone()).unwrap_or_default()
}

/// An act's answer: 200 for `ok`, 400 otherwise, marked with the act's
/// code or the door's.
fn answered_of(
    o: sts_registers::outcome::Outcome,
    fallback: ErrorCode,
) -> Answered {
    let ok = o.answer.get("ok") == Some(&Json::Bool(true));
    Answered {
        status: if ok { 200 } else { 400 },
        code: if ok {
            None
        } else {
            Some(o.code.unwrap_or(fallback))
        },
        body: o.answer,
    }
}

/// `CHOOSER_HITS`: how many results a chooser pane shows at a time.
const CHOOSER_HITS: i64 = 20;

/// `WINDOWED_PAGE_CAP`, `CANDIDATE_COUNT_CAP`: the furthest the pager
/// reaches.
const WINDOWED_PAGE_CAP: i64 = 100_000;

/// `DIRECTORY_SEARCH_SCAN`: how far a windowed search looks.
const DIRECTORY_SEARCH_SCAN: usize = 5000;

/// The order a windowed process's pages come in: postgres's `ORDER BY
/// dn_key` under the database's collation (the image's `en_US.utf8`, ISO
/// 14651 as glibc implements it), which compares the letters and digits
/// first, punctuation ignored, and only then the rest. Approximated here
/// by those two passes over the normalised DN.
fn store_order(a: &str, b: &str) -> std::cmp::Ordering {
    let ka = sts_ldap::service_dn::normalize_dn(Some(a));
    let kb = sts_ldap::service_dn::normalize_dn(Some(b));
    let alnum = |k: &str| -> String {
        k.chars().filter(|c| c.is_alphanumeric()).collect()
    };
    alnum(&ka).cmp(&alnum(&kb)).then_with(|| ka.cmp(&kb))
}

/// `MASK` (`ldap/directory_secrets.ts`).
const MASK: &str = "(set — not returned)";

/// `directoryRowOf(stored)`: the entry's attributes under their canonical
/// names, the withheld values withheld; `masked` applies
/// `DirectorySecrets.withoutSecrets()` too.
fn directory_row_of(
    stored: &sts_store::model::StoredEntry,
    masked: bool,
) -> Json {
    let model = sts_directory::DirectoryModel::get();
    let mut attributes = Map::new();
    for (name, values) in &stored.attributes {
        let shown =
            sts_directory::directory::shown_values(name, values.clone());
        let shown: Vec<Json> = if masked && model.is_secret(name) {
            shown.iter().map(|_| json!(MASK)).collect()
        } else {
            shown.into_iter().map(Json::from).collect()
        };
        attributes.insert(model.canonical_name(name), Json::Array(shown));
    }
    json!({ "dn": stored.dn,
            "origin": stored.origin.as_deref().unwrap_or("unstated"),
            "attributes": attributes })
}

// `directoryEntryMatches(stored, needle)`: the DN, an attribute's name or
// one of its values (as `directoryRowOf()` shows it, before masking).
fn directory_entry_matches(
    stored: &sts_store::model::StoredEntry,
    needle: &str,
) -> bool {
    if stored.dn.to_lowercase().contains(needle) {
        return true;
    }
    let row = directory_row_of(stored, false);
    row["attributes"].as_object().is_some_and(|o| {
        o.iter().any(|(name, values)| {
            name.to_lowercase().contains(needle)
                || values.as_array().is_some_and(|v| {
                    v.iter().any(|x| {
                        x.as_str().unwrap_or("").to_lowercase().contains(needle)
                    })
                })
        })
    })
}

impl Views {
    /// `directoryWindow`: the people and devices held as a window over
    /// the store (`persistence.directoryWindowWanted()`): `postgres-lru`,
    /// or `auto` on postgres (one cell).
    fn windowed(&self) -> bool {
        let chosen = self.settings.value_of("ldap.workerDirectory");
        let postgres =
            self.settings.value_of("persistence.mode").as_str() == "postgres";
        postgres
            && (chosen.as_str() == "postgres-lru" || chosen.as_str() == "auto")
    }

    /// `ldapDirectoryView(req)`'s JSON (`GET /admin-api/ldap/directory`):
    /// every entry of the realm's directory sorted by DN as
    /// `Intl.Collator` sorts it, filtered by `q` (a substring of the DN, an
    /// attribute's name or a value, case-insensitive) and `origin`, paged,
    /// each row with its secrets masked. Where Node windows the directory
    /// (`windowedDirectoryView()`, postgres) the answer is that one's: the
    /// store's order (`order: key`), and a search that looks at the first
    /// `DIRECTORY_SEARCH_SCAN` entries and says so (`search`).
    #[tracing::instrument(level = "debug", skip_all)]
    fn directory_entries_json(&self, asked: &Asked<'_>) -> Json {
        let realm_id = realm::current_id();
        let wanted_text = text_of(asked.query, "q").trim().to_string();
        let wanted_origin = text_of(asked.query, "origin").trim().to_string();
        let needle = wanted_text.to_lowercase();
        self.dir.with(|t| {
            let Some(r) = t.realms().iter().position(|x| x.id == realm_id)
            else {
                return json!({ "directory": false });
            };
            let mut listed: Vec<&sts_store::model::StoredEntry> =
                t.realms()[r].entries.values().collect();
            let windowed = self.windowed();
            if windowed {
                listed.sort_by(|a, b| store_order(&a.dn, &b.dn));
            } else {
                listed.sort_by(|a, b| {
                    sts_registers::js::locale_compare(&a.dn, &b.dn)
                });
            }
            let origin_of = |e: &sts_store::model::StoredEntry| -> String {
                e.origin.clone().unwrap_or_else(|| "unstated".into())
            };
            let of_origin: Vec<&sts_store::model::StoredEntry> = listed
                .iter()
                .filter(|e| {
                    wanted_origin.is_empty() || origin_of(e) == wanted_origin
                })
                .copied()
                .collect();
            // A windowed process searches the first DIRECTORY_SEARCH_SCAN
            // entries of the store's order and says so (`search`).
            let (looked, search) = if windowed && !needle.is_empty() {
                let scanned = of_origin.len().min(DIRECTORY_SEARCH_SCAN);
                (
                    &of_origin[..scanned],
                    json!({ "complete": of_origin.len() < DIRECTORY_SEARCH_SCAN,
                            "scanned": scanned,
                            "scanLimit": DIRECTORY_SEARCH_SCAN }),
                )
            } else {
                (&of_origin[..], Json::Null)
            };
            let filtered: Vec<&sts_store::model::StoredEntry> = looked
                .iter()
                .filter(|e| {
                    needle.is_empty() || directory_entry_matches(e, &needle)
                })
                .copied()
                .collect();
            let paging = Paging::of(
                asked.query,
                filtered.len(),
                Options {
                    noun: "entries",
                    ..Options::default()
                },
            );
            let shown: Vec<Json> = paging
                .slice(&filtered)
                .into_iter()
                .map(|e| directory_row_of(e, true))
                .collect();
            let mut counted: std::collections::BTreeMap<String, i64> =
                std::collections::BTreeMap::new();
            for e in &listed {
                *counted.entry(origin_of(e)).or_insert(0) += 1;
            }
            let origins: Vec<&String> = counted.keys().collect();
            json!({
                "baseDn": t.realms()[r].base,
                "count": listed.len(),
                "matched": filtered.len(),
                "shown": shown.len(),
                "filter": {
                    "q": if wanted_text.is_empty() { Json::Null }
                         else { json!(wanted_text) },
                    "origin": if wanted_origin.is_empty() { Json::Null }
                              else { json!(wanted_origin) },
                },
                "origins": origins,
                "originCounts": counted,
                "page": paging.page, "pages": paging.pages,
                "perPage": paging.per_page,
                "firstRow": paging.first_row, "lastRow": paging.last_row,
                "paging": paging.to_json(),
                "order": if windowed { "key" } else { "dn" },
                "search": search,
                "entries": shown,
            })
        })
    }

    /// `ldapServiceView(req)`'s JSON (`GET /admin-api/ldap/service`), IN
    /// PART: the directory's names, its two sockets as they bound, the
    /// limits and the operations. Absent rather than empty: the prose
    /// members (`searchScope`, `bindPolicy`, `schema`, `autoCreateRule`,
    /// `authenticationFacts`, `enforcedRules`, `specifications`,
    /// `implementation`), `persistence`, `tls` and
    /// `certificateProvenance`, whose sources are not ported here.
    #[tracing::instrument(level = "debug", skip_all)]
    fn directory_service_json(&self, asked: &Asked<'_>) -> Json {
        let realm_id = realm::current_id();
        let host = asked
            .base
            .split("://")
            .nth(1)
            .unwrap_or("localhost")
            .split(['/', ':'])
            .next()
            .unwrap_or("localhost")
            .to_string();
        self.dir.with(|t| {
            let Some(r) = t.realms().iter().position(|x| x.id == realm_id)
            else {
                return json!({ "directory": false });
            };
            let state = Groups { tree: t, r }.directory_state(&self.settings);
            // `boundPort`: the configured port until a socket binds one.
            let port = state["port"].clone();
            let total: usize = t.realms().iter().map(|x| x.entries.len()).sum();
            let auto = self.mode.predicate("autoCreates").unwrap_or(false)
                && self.settings.value_of("ldap.autocreateUsers").as_bool();
            json!({
                "url": format!("ldap://{}:{}", host,
                               port.as_i64().map_or("null".to_string(),
                                                    |p| p.to_string())),
                "port": port,
                "listening": state["listening"],
                "listenError": state["listenError"],
                "baseDn": state["baseDn"],
                "usersDn": state["usersDn"],
                "groupsDn": state["groupsDn"],
                "namingContexts": t.naming_contexts(),
                "ldapVersion": 3,
                "refusedPassword": "invalid",
                "referentialIntegrity": false,
                "autoCreateUsers": auto,
                "limits": {
                    "maxEntries": state["maxEntries"],
                    "maxSearchResults":
                        self.settings.value_of("ldap.sizeLimit").as_int(),
                    "currentEntries": t.realms()[r].entries.len(),
                    "currentEntriesEverywhere": total,
                },
                "operations": ["bind", "unbind", "add", "delete", "modify",
                               "modifyDN", "compare", "search"],
                "ldapPort": self.settings.value_of("ldap.port").as_int(),
                "ldapsPort": self.settings.value_of("ldap.tlsPort").as_int(),
            })
        })
    }
}
