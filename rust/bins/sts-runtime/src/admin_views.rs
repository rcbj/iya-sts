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
            return None;
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
    /// `ldapDirectoryView(req)`'s JSON (`GET /admin-api/ldap/directory`):
    /// every entry of the realm's directory sorted by DN as
    /// `Intl.Collator` sorts it, filtered by `q` (a substring of the DN, an
    /// attribute's name or a value, case-insensitive) and `origin`, paged,
    /// each row with its secrets masked. Not the windowed process's
    /// store-paged answer: this runtime holds the directory in memory.
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
            listed.sort_by(|a, b| {
                sts_registers::js::locale_compare(&a.dn, &b.dn)
            });
            let origin_of = |e: &sts_store::model::StoredEntry| -> String {
                e.origin.clone().unwrap_or_else(|| "unstated".into())
            };
            let filtered: Vec<&sts_store::model::StoredEntry> = listed
                .iter()
                .filter(|e| {
                    (wanted_origin.is_empty() || origin_of(e) == wanted_origin)
                        && (needle.is_empty()
                            || directory_entry_matches(e, &needle))
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
                "order": "dn",
                "search": Json::Null,
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
