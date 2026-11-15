// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE READS `/admin-api` ANSWERS OVER WHAT THE RUNTIME HOLDS (#444, phase
//! 5, the `apis3` slice): `admin-core/admin_views.ts`'s views, one per
//! operation, each held to its model by the router like every answer.
//!
//! | Operation | Node | Over |
//! |---|---|---|
//! | `getGroups` | `groupsJson()`, `groupsListJson()`, `groupDetailJson()` | the directory's groups ([`super::groups::Groups`]), the identity register |
//! | `grantGlobalConsent` | `consentAction()`'s `grant-global-consent`, `consent.grantGlobal()` | the application register |
//!
//! THE IDENTITY REGISTER (`common/admin_stats.js`'s `users`, persisted as
//! `admin_stats.users`, `merge: own`) is READ here, never written: who this
//! service has seen authenticate. A view asks it which names are known
//! (`knownUserKeys()`), which is the register's keys, every other
//! process's rows (the store's fan-in, a previous run of Node's included)
//! and the holders of the tokens the token register keeps
//! (`collectUserKeys()`). This runtime's own sign-ins do not record there
//! yet (`recordAuthentication()` is another slice's), so a person known
//! only from a Rust sign-in is known through their tokens alone.
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
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{Merge, RealmMap, StoreHandles, StoreSpec};
use sts_core::settings::Settings;
use sts_mgmt_api::families::Asked;
use sts_mgmt_api::paging::{Options, Paging};
use sts_mgmt_api::setup::Answered;
use sts_store::persistence::Persistence;

use super::groups::Groups;
use super::LiveDir;

/// `admin_stats.users`' handle.
pub const USERS_HANDLE: &str = "admin_stats.users";

/// The identity register, read.
pub struct IdentityRegister {
    users: RealmMap<Json>,
    persistence: Arc<Persistence>,
    tokens: Arc<sts_oauth::minted::TokenRegister>,
    dir: Arc<LiveDir>,
}

impl IdentityRegister {
    /// Declares the register's store as Node declares it, before the
    /// store opens, so its rows (and every other process's) are loaded.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn declare(
        lifecycle: &Arc<RealmLifecycle>,
        handles: &Arc<StoreHandles>,
        persistence: Arc<Persistence>,
        tokens: Arc<sts_oauth::minted::TokenRegister>,
        dir: Arc<LiveDir>,
    ) -> IdentityRegister {
        let spec = StoreSpec {
            merge: Merge::Own,
            ..StoreSpec::persisted(USERS_HANDLE)
        };
        IdentityRegister {
            users: RealmMap::new(lifecycle, handles, spec),
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
pub struct Views {
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
            "grantGlobalConsent" => return Some(self.grant_global(asked)),
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
}
