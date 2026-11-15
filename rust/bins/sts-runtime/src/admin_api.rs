// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `/admin-api` IN THE RUNTIME (`common/protocol_stack.ts`'s `19`,
//! `mgmt-api/admin_api`): phase 4's `sts-mgmt-api` router over what the
//! runtime holds. The router is the crate's, whole — the gate, the request
//! checks, the closed-model check of every answer (#1353) — and this module
//! answers its ports:
//!
//! | Port | Answered by |
//! |---|---|
//! | the key sets the gate verifies a token under | the store's key sets (`KeySets::open`), the DEFAULT realm's for the service credential |
//! | `DPoP-Nonce`, the proof's history | the authorization server's own `DpopStores` (one declaration per handle) |
//! | the revoked-token register, a token's session | the stack's one `TokenRegister`, the session core's `Sessions` |
//! | a disabled account | `sts-credentials`' `account_disabled()` over the live directory |
//! | a client's method, its certificate declaration, the scopes it declares | the application register over the directory, as the token endpoint reads it |
//! | the roles a token's subject holds now | `sts-registers`' `RolePermissions` over `Roles` and the console roster's `roles_of()` |
//! | the console's frame | [`Console`] |
//!
//! **THE DIRECTORY IS THE LIVE ONE, AND A WRITE GOES BACK TO IT.** The
//! registers work on an `sts_directory::Directory`; this module keeps one,
//! refilled from the live directory before each request (as the
//! authorization server refills its own), with a journal that names every
//! entry a write touched — and after the request each touched entry is put
//! back into the live directory and marked for the store's next flush, the
//! way every other door here writes (`DirectoryPorts::write`). So what an
//! operation writes is what the authorization server reads on its next
//! request, and what the store persists.
//!
//! NOT PORTED HERE, and how the gate answers meanwhile: the owner roles
//! (`ownership.ownsAnything()` answers false, so an owner's token is never
//! an owner's); a security change outside `/admin/config`
//! (`SecurityOperations.classify()` answers none, so such a write needs
//! admin:write, not admin:security); a realm administrator's confinement
//! (`admin_scope.refusalFor()` answers none for the operations ported).

use std::sync::{Arc, Mutex, PoisonError};

use axum::http::HeaderMap;
use serde_json::{json, Value as Json};
use sts_core::mode::Mode;
use sts_core::realm::{self, RealmRegistry};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{RealmMap, StoreHandles, StoreSpec};
use sts_core::settings::Settings;
use sts_directory::ports::DirectoryJournal;
use sts_directory::{Directory, EntryExt};
use sts_mgmt_api::config_view::ProcessFacts;
use sts_mgmt_api::console::ConsolePorts;
use sts_mgmt_api::gate::{ConsoleOperation, Effective, GatePorts};
use sts_mgmt_api::router::{KeySource, Services};
use sts_mgmt_api::setup::{Listener, Seeded, SetupPorts};
use sts_oauth::clients::Clients;
use sts_registers::applications::ApplicationRegistry;
use sts_registers::port as rp;
use sts_store::key_sets::KeySet;
use sts_store::persistence::{LiveDirectory, MemoryDirectory, Persistence};

/// The first path segment of every route Node's router serves
/// (`realms.reserved()`, as `GET /admin-api/realms` answers it): a realm
/// may not be called one of them. The Rust router does not register every
/// family yet, so the list is Node's.
const RESERVED: &[&str] = &[
    "access",
    "account-api",
    "admin",
    "admin-api",
    "applications",
    "authn",
    "authn-api",
    "bbs",
    "crypto",
    "docs",
    "enroll",
    "federation",
    "federationmetadata",
    "gnap",
    "gnap-api",
    "healthcheck",
    "home-api",
    "kdcproxy",
    "launch",
    "logout",
    "oauth2",
    "oid4vci",
    "oid4vp",
    "oidfed",
    "pki",
    "policy",
    "portal",
    "realms",
    "report",
    "report-api",
    "saml11",
    "saml2",
    "scim",
    "spiffe",
    "ssf",
    "status-lists",
    "sts",
    "tls",
    "tos",
    "uma",
    "users",
    "vc-api",
    "web",
    "wsfed",
    "xacml",
];

/// What the composition root hands [`AdminStack::declare`].
pub struct AdminParts {
    pub settings: Arc<Settings>,
    pub mode: Arc<Mode>,
    pub registry: Arc<RealmRegistry>,
    pub lifecycle: Arc<RealmLifecycle>,
    pub handles: Arc<StoreHandles>,
    pub persistence: Arc<Persistence>,
    pub live: Arc<MemoryDirectory>,
    pub oauth: Arc<crate::oauth::OAuthStack>,
    pub sessions: Arc<sts_authn::Sessions>,
    pub credentials: Arc<sts_credentials::credentials::Credentials>,
    /// The sign-in surface's facts: whether a passkey may be a first or a
    /// second factor here (`webauthnPolicy.useAllowed()`).
    pub facts: Arc<dyn sts_authn_api::ports::SignInFacts>,
    pub catalogs: Arc<sts_http::i18n::Catalogs>,
    pub version: sts_core::version::VersionInfo,
    /// The protocol-independent sign-out (`logout/logout.ts`), which a
    /// disable ends everything the person holds through.
    pub logout: Arc<sts_logout::Logout>,
}

/// The journal of a request's writes: `(realm, key)` of every entry the
/// directory's handlers touched (`touchDirectory()`).
#[derive(Default)]
struct Touched(Mutex<Vec<(String, String)>>);

impl DirectoryJournal for Touched {
    fn touched(&self, realm: &str, key: &str) {
        let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let one = (realm.to_string(), key.to_string());
        if !held.contains(&one) {
            held.push(one);
        }
    }
}

/// The registers' directory, over the live one.
pub struct LiveDir {
    settings: Arc<Settings>,
    registry: Arc<RealmRegistry>,
    live: Arc<MemoryDirectory>,
    persistence: Arc<Persistence>,
    tree: Arc<Mutex<Directory>>,
    touched: Arc<Touched>,
}

impl LiveDir {
    fn fresh(&self) -> Directory {
        let domain = self.settings.value_of("global.domain");
        let mut fresh =
            Directory::new(&realm::base_dn_of_domain(domain.as_str()))
                .with_journal(self.touched.clone());
        for one in self.registry.list() {
            if one.id != realm::DEFAULT_ID {
                fresh.add_realm(&one.id, &self.registry.base_dn_of(&one));
            }
            let entries: Vec<_> =
                self.live.realm_entries(&one.id).into_values().collect();
            fresh.restore(&one.id, entries);
        }
        fresh
    }

    /// Refills the registers' directory from the live one, before a
    /// request reads it.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn reload(&self) {
        let fresh = self.fresh();
        *self.tree.lock().unwrap_or_else(PoisonError::into_inner) = fresh;
        self.touched
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    /// Puts every entry the request wrote back into the live directory and
    /// marks it for the store's next flush; an entry the request removed is
    /// removed there.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn write_back(&self) {
        let touched: Vec<(String, String)> = std::mem::take(
            &mut *self
                .touched
                .0
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        if touched.is_empty() {
            return;
        }
        let tree = self.tree.lock().unwrap_or_else(PoisonError::into_inner);
        for (realm_id, key) in touched {
            let Some(r) = tree.realms().iter().position(|t| t.id == realm_id)
            else {
                continue;
            };
            let entry = tree.get(r, &key).cloned();
            self.live.apply_entry(&realm_id, &key, entry);
            self.persistence.directory_changed(Some(&key));
        }
    }

    /// Reads the registers' directory. A hot path: every port's read goes
    /// through it, so it carries no span.
    pub fn with<R>(&self, f: impl FnOnce(&Directory) -> R) -> R {
        let tree = self.tree.lock().unwrap_or_else(PoisonError::into_inner);
        f(&tree)
    }

    fn realm_index(tree: &Directory, realm_id: &str) -> Option<usize> {
        tree.realms().iter().position(|t| t.id == realm_id)
    }
}

/// `groupsOfUser(key)` over the registers' directory: every group listing
/// the person (`member`, `uniqueMember`), and every group the person's own
/// `memberOf` names, one row per group, sorted by normalised DN.
fn groups_of_user(tree: &Directory, r: usize, key: &str) -> Json {
    let wanted = key.trim();
    let mut out = json!({ "key": wanted, "dn": "", "entryFound": false,
                          "groups": [] });
    if wanted.is_empty() {
        return out;
    }
    let users = tree.users_dn(r);
    let located = tree.locate(r, wanted);
    let dn = located
        .map(|e| e.dn.clone())
        .unwrap_or_else(|| format!("uid={},{}", wanted, users));
    out["dn"] = json!(dn);
    out["entryFound"] = json!(located.is_some());
    let person = sts_ldap::service_dn::normalize_dn(Some(&dn));
    let mut rows: Vec<(String, Json)> = Vec::new();
    let Some(t) = tree.realms().get(r) else {
        return out;
    };
    for (gkey, group) in &t.entries {
        let rule = tree.group_rule(r, &group.dn, &group.attributes);
        if rule.is_empty() {
            continue;
        }
        let via: Vec<&str> = ["member", "uniquemember"]
            .into_iter()
            .filter(|a| {
                group.values(a).iter().any(|v| {
                    sts_ldap::service_dn::normalize_dn(Some(v)) == person
                })
            })
            .map(|a| {
                if a == "member" {
                    "member"
                } else {
                    "uniqueMember"
                }
            })
            .collect();
        let claimed = located.is_some_and(|e| {
            e.values("memberof")
                .iter()
                .any(|v| sts_ldap::service_dn::normalize_dn(Some(v)) == *gkey)
        });
        if via.is_empty() && !claimed {
            continue;
        }
        rows.push((
            gkey.clone(),
            json!({ "dn": group.dn, "cn": group.first("cn").unwrap_or(""),
                    "rule": rule, "via": via, "viaMemberOf": claimed }),
        ));
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    out["groups"] = Json::Array(rows.into_iter().map(|(_, g)| g).collect());
    out
}

/// The console roster's reads, in one realm (`rosterViewFor(realm)`).
struct Roster {
    dir: Arc<LiveDir>,
    realm: String,
}

impl Roster {
    fn r(&self, tree: &Directory) -> usize {
        LiveDir::realm_index(tree, &self.realm).unwrap_or(0)
    }
}

impl rp::RosterDirectory for Roster {
    fn users_dn(&self) -> String {
        self.dir.with(|t| t.users_dn(self.r(t)))
    }
    fn realm_id(&self) -> Option<String> {
        Some(self.realm.clone())
    }
    fn group_dn_for(&self, cn: &str) -> String {
        self.dir
            .with(|t| format!("cn={},{}", cn, t.groups_dn(self.r(t))))
    }
    fn read_group_entry(&self, dn: &str) -> Json {
        self.dir.with(|t| {
            let r = self.r(t);
            let Some(stored) = t.get(r, dn) else {
                return Json::Null;
            };
            let rule = t.group_rule(r, &stored.dn, &stored.attributes);
            if rule.is_empty() {
                return Json::Null;
            }
            let mut object =
                sts_registers::applications::store::StoredApplication::of(
                    stored,
                )
                .to_json();
            let members: Vec<Json> = ["member", "uniquemember"]
                .into_iter()
                .flat_map(|a| {
                    stored
                        .values(a)
                        .iter()
                        .map(move |v| json!({ "value": v, "attribute": a }))
                })
                .collect();
            object["rule"] = json!(rule);
            object["members"] = Json::Array(members);
            object
        })
    }
    fn write_group_entry(
        &self,
        dn: &str,
        _attributes: &Json,
        _origin: &str,
    ) -> Json {
        // The roster's writes (`rbac/grant`, `rbac/revoke`) are not routed
        // in this runtime yet; nothing asks this.
        json!({ "ok": false, "reason": "notPorted", "dn": dn })
    }
    fn normalize_dn(&self, dn: &str) -> String {
        sts_ldap::service_dn::normalize_dn(Some(dn))
    }
    fn existing_user_entry(&self, name: &str) -> Json {
        self.dir.with(|t| {
            t.existing_user_entry(self.r(t), name)
                .map_or(Json::Null, |e| json!({ "dn": e.dn }))
        })
    }
    fn name_usable_in_dn(&self, name: &str) -> bool {
        !name.chars().any(|c| ",=+<>#;\"\\".contains(c))
    }
    fn claimed_members_of(&self, dn: &str) -> Vec<Json> {
        // `unlistedClaimsOf()`: the people whose own `memberOf` names the
        // group and whom the group does not list.
        self.dir.with(|t| {
            let r = self.r(t);
            let key = sts_ldap::service_dn::normalize_dn(Some(dn));
            let listed: Vec<String> = t
                .get(r, dn)
                .map(|g| {
                    ["member", "uniquemember"]
                        .into_iter()
                        .flat_map(|a| g.values(a).to_vec())
                        .map(|v| sts_ldap::service_dn::normalize_dn(Some(&v)))
                        .collect()
                })
                .unwrap_or_default();
            let Some(tree) = t.realms().get(r) else {
                return Vec::new();
            };
            let mut rows: Vec<(String, Json)> = tree
                .entries
                .iter()
                .filter(|(k, e)| {
                    t.is_person_dn(r, &e.dn)
                        && !listed.contains(k)
                        && e.values("memberof").iter().any(|v| {
                            sts_ldap::service_dn::normalize_dn(Some(v)) == key
                        })
                })
                .map(|(k, e)| {
                    (
                        k.clone(),
                        json!({ "dn": e.dn,
                                "userKey": e.first("uid").unwrap_or(""),
                                "cn": e.first("cn").unwrap_or(""),
                                "mail": e.first("mail").unwrap_or("") }),
                    )
                })
                .collect();
            rows.sort_by(|a, b| a.0.cmp(&b.0));
            rows.into_iter().map(|(_, v)| v).collect()
        })
    }
    fn read_person_flags(&self, name: &str) -> Json {
        self.dir.with(|t| {
            let Some(e) = t.locate(self.r(t), name) else {
                return Json::Null;
            };
            let one = |a: &str| e.first(a).unwrap_or("").to_string();
            json!({
                "dn": e.dn,
                "pwdReset": one("pwdreset").eq_ignore_ascii_case("true"),
                "bootstrapAdministrator":
                    one("stsbootstrapadministrator")
                        .eq_ignore_ascii_case("true"),
                "consoleClaimedAt": one("stsconsoleclaimedat"),
                "mfaRequired": one("stsmfarequired")
                    .eq_ignore_ascii_case("true"),
                "accountLockedTime": one("pwdaccountlockedtime"),
            })
        })
    }
    fn groups_of_user(&self, name: &str) -> Json {
        self.dir.with(|t| groups_of_user(t, self.r(t), name))
    }
}

/// What the role register asks of `ou=roles`, in the ambient realm.
struct RoleDir(Arc<LiveDir>);

impl rp::RoleDirectory for RoleDir {
    fn all_roles(&self) -> Vec<Json> {
        self.0.with(|t| {
            let Some(r) = LiveDir::realm_index(t, &realm::current_id()) else {
                return Vec::new();
            };
            let roles = format!("ou=roles,{}", t.realms()[r].base);
            let key = sts_ldap::service_dn::normalize_dn(Some(&roles));
            t.realms()[r]
                .entries
                .iter()
                .filter(|(k, e)| {
                    **k != key
                        && sts_ldap::service_dn::is_under(
                            Some(&e.dn),
                            Some(&roles),
                        )
                })
                .map(|(_, e)| {
                    let mut o =
                        sts_registers::applications::store::StoredApplication::of(e)
                            .to_json();
                    let name = e.first("cn").map(str::to_string).unwrap_or_else(
                        || {
                            e.dn.split(',')
                                .next()
                                .unwrap_or("")
                                .trim_start_matches("cn=")
                                .trim_start_matches("CN=")
                                .to_string()
                        },
                    );
                    o["name"] = json!(name);
                    o
                })
                .collect()
        })
    }
    fn write_role(&self, _name: &str, _attributes: &Json) -> rp::Marked {
        rp::Marked::plain(json!(false))
    }
    fn delete_role(&self, _name: &str) -> bool {
        false
    }
    fn resolve_owner(&self, _text: &str) -> Json {
        json!({ "kind": "", "dn": "", "name": "" })
    }
    fn groups_of_user(&self, name: &str) -> Vec<String> {
        self.0.with(|t| {
            let Some(r) = LiveDir::realm_index(t, &realm::current_id()) else {
                return Vec::new();
            };
            groups_of_user(t, r, name)["groups"]
                .as_array()
                .map(|g| {
                    g.iter()
                        .filter_map(|x| x["cn"].as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        })
    }
    fn ensure_group(&self, _name: &str, _options: &Json) -> Json {
        json!({ "ok": false })
    }
}

/// The settings, in the ambient realm.
struct RegSettings(Arc<Settings>);

impl rp::Settings for RegSettings {
    fn value(&self, key: &str) -> Json {
        match self.0.value_of(key) {
            sts_core::settings::SettingValue::Text(t) => json!(t),
            sts_core::settings::SettingValue::Int(n) => json!(n),
            sts_core::settings::SettingValue::Bool(b) => json!(b),
            sts_core::settings::SettingValue::List(l) => json!(l),
        }
    }
}

/// The mode's questions, in a realm.
struct RegMode {
    mode: Arc<Mode>,
    registry: Arc<RealmRegistry>,
}

impl rp::Mode for RegMode {
    fn opens_console_to_anyone(&self, realm_id: &str) -> bool {
        let one = self
            .registry
            .get(realm_id)
            .unwrap_or_else(|| self.registry.default_realm());
        realm::run_sync(one, || {
            self.mode.predicate("opensConsoleToAnyone").unwrap_or(false)
        })
    }
    fn verifies_credentials(&self) -> bool {
        self.mode.predicate("verifiesCredentials").unwrap_or(true)
    }
    fn refuses_token_for_gone_subject(&self) -> bool {
        self.mode
            .predicate("refusesTokenForGoneSubject")
            .unwrap_or(false)
    }
}

/// The bootstrap administrator's name (`common/bootstrap_name.ts`).
struct Bootstrap(Arc<Settings>);

impl rp::BootstrapName for Bootstrap {
    fn current(&self) -> String {
        self.0
            .value_of("admin.bootstrapUsername")
            .as_str()
            .trim()
            .to_string()
    }
}

/// The audit rows the registers write, to the log.
struct LogAudit;

impl rp::Audit for LogAudit {
    fn audit(&self, row: &Json) {
        tracing::info!("audit: {}", row);
    }
    fn record(&self, row: &Json) {
        tracing::info!("audit: {}", row);
    }
    fn failure(&self, code: sts_core::errors::ErrorCode, row: &Json) {
        tracing::info!("{}audit: {}", sts_core::log::tag(code), row);
    }
}

/// The application register's answers the other registers ask.
struct RegApps(Arc<ApplicationRegistry>);

impl rp::Applications for RegApps {
    fn get(&self, identifier: &str) -> Json {
        self.0.get(identifier).unwrap_or(Json::Null)
    }
    fn list(&self) -> Vec<Json> {
        self.0.list()
    }
    fn required_roles_of(&self, identifier: &str) -> Vec<String> {
        self.0.required_roles_of(identifier)
    }
    fn role_gating_for(&self, id: &str) -> Json {
        self.0.role_gating_for(id).unwrap_or(Json::Null)
    }
    fn for_permission(&self, id: &str) -> Json {
        self.0.for_permission(id).unwrap_or(Json::Null)
    }
    fn setting_for(&self, identifier: &str, key: &str) -> Json {
        self.0.setting_for(identifier, key)
    }
    fn update_application(
        &self,
        _identifier: &str,
        _change: &Json,
    ) -> rp::Marked {
        rp::Marked::plain(json!({ "ok": false }))
    }
    fn is_internal_identifier(&self, identifier: &str) -> bool {
        self.0.is_internal_identifier(identifier)
    }
    fn owner_protected(&self, _identifier: &str) -> bool {
        false
    }
    fn set_owner_protected(
        &self,
        _identifier: &str,
        _flag: bool,
    ) -> rp::Marked {
        rp::Marked::plain(json!({ "ok": false }))
    }
    fn owner_values(&self) -> Vec<Vec<String>> {
        self.0.owner_values()
    }
}

/// `ownership.ownsAnything()`: not ported — nobody is an owner here.
struct NoOwners;

impl rp::OwnsAnything for NoOwners {
    fn owns_anything(&self, _name: &str) -> bool {
        false
    }
}

/// The issuance gate's verdicts: every scope kept. `effectiveRoles()`
/// never asks it; only narrowing does.
struct KeepEveryScope;

impl rp::IssuanceGate for KeepEveryScope {
    fn check_scopes(&self, _request: &Json) -> Vec<rp::ScopeVerdict> {
        Vec::new()
    }
}

/// A token's `sub`, resolved to a person in the ambient realm.
struct Subjects(Arc<LiveDir>);

impl rp::Subjects for Subjects {
    fn subject_is_gone(&self, sub: &str) -> bool {
        let lower = sub.trim().to_lowercase();
        if !lower.starts_with("urn:uuid:") {
            return false;
        }
        self.0
            .with(|t| t.name_for_subject(&realm::current_id(), sub).is_empty())
    }
    fn name_for_subject(&self, sub: &str) -> String {
        self.0
            .with(|t| t.name_for_subject(&realm::current_id(), sub))
    }
}

/// The console roster's read in a realm.
struct RosterRoles {
    dir: Arc<LiveDir>,
    settings: Arc<Settings>,
    mode: Arc<RegMode>,
}

impl RosterRoles {
    fn rbac(&self, realm_id: &str) -> sts_registers::rbac::Rbac {
        sts_registers::rbac::Rbac::new(
            Some(Arc::new(Roster {
                dir: self.dir.clone(),
                realm: realm_id.to_string(),
            })),
            Arc::new(RegSettings(self.settings.clone())),
            Arc::new(LogAudit),
            self.mode.clone(),
            Arc::new(Bootstrap(self.settings.clone())),
        )
    }
}

impl rp::RosterRoles for RosterRoles {
    fn roles_of(&self, name: &str, realm_id: &str) -> Json {
        self.rbac(realm_id).roles_of(name)
    }
}

/// `ldap_server.js`'s `createUser(name, options)`: a person created on
/// purpose at `uid=<name>,ou=users`, refused for a name that is a DN, a
/// subject identifier, a DID or a SPIFFE ID, that carries RFC 4514's
/// reserved characters, or that is taken; held to the realm's attribute
/// policy in product mode (#396), a `cn` made from `givenName sn` first,
/// and a `description` saying why the entry exists. The entry is put back
/// into the live directory at once, so a password set in the same act
/// (`sts-credentials`, over the live directory) finds it.
///
/// NOT PORTED: the persona `namePlan()` and `applyVcAttributes()` invent
/// in development mode (`mode.inventsClaimValues()`), so a person made here
/// in development carries only what was typed — product's behaviour; the
/// attribute catalogue's check of each typed name (STS-LDAP-0047, 0106);
/// the account observer's notice and the identity register's row.
struct PersonWriter {
    dir: Arc<LiveDir>,
    mode: Arc<Mode>,
}

impl PersonWriter {
    fn refused(code: sts_core::errors::ErrorCode, why: String) -> rp::Marked {
        rp::Marked {
            value: json!({ "ok": false, "errors": [why] }),
            code: Some(code),
        }
    }
}

impl rp::PersonWriter for PersonWriter {
    fn create_user(&self, name: &str, options: &Json) -> rp::Marked {
        use sts_core::errors::codes;
        let wanted = name.trim().to_string();
        if wanted.is_empty() {
            return Self::refused(
                codes::STS_LDAP_0042,
                "Which user? Send `username` with the name they will authenticate under — the same string \
                 that would appear in a token's `sub` and on /admin/users."
                    .into(),
            );
        }
        let lower = wanted.to_lowercase();
        let dn_shaped = wanted.split_once('=').is_some_and(|(a, _)| {
            a.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                && a.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
        if dn_shaped {
            return Self::refused(
                codes::STS_LDAP_0043,
                format!(
                    "\"{}\" is a DN and not a username. An entry named by a distinguished name gets here by \
                     presenting a client certificate, where the DN is the identity; there is nothing to create \
                     one from by hand.",
                    wanted
                ),
            );
        }
        if lower.starts_with("urn:uuid:")
            || sts_directory::uuid::uuid_shaped(&lower)
        {
            return Self::refused(
                codes::STS_LDAP_0090,
                format!(
                    "\"{}\" is a subject identifier and not a username. Every person here is given one — their \
                     entryUUID — and a token's sub is urn:uuid:<that value>, so a person named after one would \
                     be a second person answering to somebody else's subject.",
                    wanted
                ),
            );
        }
        if sts_directory::uuid::did_shaped(&wanted) {
            return Self::refused(
                codes::STS_LDAP_0044,
                format!(
                    "\"{}\" is a decentralized identifier and not a username. A DID reaches this directory by \
                     being presented, and where this service knows whose it is the identifier goes onto that \
                     person's entry as didSubject.",
                    wanted.chars().take(48).collect::<String>()
                ),
            );
        }
        if lower.starts_with("spiffe://") {
            return Self::refused(
                codes::STS_LDAP_0045,
                format!(
                    "\"{}\" is a SPIFFE identity and not a username. A workload identity reaches this directory \
                     by being PRESENTED — an X509-SVID over mutual TLS at the SPIRE Server API, an agent \
                     attesting, a JWT-SVID validated at the Workload API — and its entry is named by a digest \
                     with the identity on it as spiffeSubject. What you probably want instead is a REGISTRATION \
                     ENTRY, which is a different thing in a different container: /admin/spiffe/entries, POST \
                     /admin-api/spiffe/entries/create, or BatchCreateEntry.",
                    wanted.chars().take(64).collect::<String>()
                ),
            );
        }
        if wanted.chars().any(|c| ",=+<>#;\"\\".contains(c)) {
            return Self::refused(
                codes::STS_LDAP_0046,
                format!(
                    "\"{}\" cannot be a username here: it carries a character RFC 4514 reserves in a DN (one of \
                     , = + < > # ; \" \\), so the entry would be named something other than what was typed. An \
                     ldapadd can still create such an entry, with the escaping written out.",
                    wanted
                ),
            );
        }
        let realm_id = realm::current_id();
        let outcome = {
            let mut tree =
                self.dir.tree.lock().unwrap_or_else(PoisonError::into_inner);
            let Some(r) = LiveDir::realm_index(&tree, &realm_id) else {
                return Self::refused(
                    codes::STS_LDAP_0008,
                    "This realm has no directory.".into(),
                );
            };
            if let Some(clash) = tree.existing_user_entry(r, &wanted) {
                return rp::Marked {
                    value: json!({ "ok": false,
                        "errors": [format!(
                            "There is already a user called \"{}\" here, at {}. One entry per person is the rule \
                             this directory keeps at every door — whatever protocol authenticated them, and \
                             whichever attribute their entry happens to be named by.",
                            wanted, clash.dn)],
                        "existing": { "dn": clash.dn,
                                      "origin": clash.origin.clone().unwrap_or_default() } }),
                    code: Some(codes::STS_LDAP_0005),
                };
            }
            let mut attributes: indexmap::IndexMap<String, Vec<String>> =
                indexmap::IndexMap::new();
            attributes.insert(
                "objectclass".into(),
                ["top", "person", "organizationalPerson", "inetOrgPerson"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            );
            attributes.insert("uid".into(), vec![wanted.clone()]);
            let mut typed: Vec<String> = Vec::new();
            if let Some(given) = options["attributes"].as_object() {
                for (k, v) in given {
                    let values: Vec<String> = match v {
                        Json::Array(l) => l
                            .iter()
                            .map(|x| match x {
                                Json::String(t) => t.trim().to_string(),
                                other => other.to_string(),
                            })
                            .filter(|t| !t.is_empty())
                            .collect(),
                        Json::Null => Vec::new(),
                        Json::String(t) => vec![t.trim().to_string()]
                            .into_iter()
                            .filter(|t| !t.is_empty())
                            .collect(),
                        other => vec![other.to_string()],
                    };
                    if values.is_empty() {
                        continue;
                    }
                    typed.push(k.clone());
                    attributes.insert(k.to_lowercase(), values);
                }
            }
            if !attributes.contains_key("description") {
                let note = options["note"].as_str().unwrap_or("").trim();
                attributes.insert(
                    "description".into(),
                    vec![if note.is_empty() {
                        "created by hand rather than by authenticating"
                            .to_string()
                    } else {
                        note.to_string()
                    }],
                );
            }
            if !attributes.contains_key("cn") {
                let given = attributes
                    .get("givenname")
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_default();
                let sn = attributes
                    .get("sn")
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_default();
                let cn = format!("{} {}", given, sn).trim().to_string();
                if !cn.is_empty() {
                    attributes.insert("cn".into(), vec![cn]);
                }
            }
            let exempt = options["requiredExempt"]
                .as_str()
                .is_some_and(|e| !e.is_empty());
            if !exempt {
                use sts_directory::ports::PersonRules;
                let enforced = !self
                    .mode
                    .predicate("createsIncompletePeople")
                    .unwrap_or(false);
                if let Some(refusal) = sts_directory::ports::DefaultPersonRules
                    .attribute_create_refusal(&attributes, enforced)
                {
                    return rp::Marked {
                        value: json!({ "ok": false,
                                       "errors": [refusal.message] }),
                        code: Some(codes::STS_LDAP_0162),
                    };
                }
            }
            let mail = attributes
                .get("mail")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            if !mail.is_empty() {
                // `verifyWrittenMail()`: an address an administrator typed
                // is verified.
                attributes.insert("stsmailverified".into(), vec![mail]);
            }
            let dn = format!("uid={},{}", wanted, tree.users_dn(r));
            let pairs: Vec<(String, Vec<String>)> =
                attributes.into_iter().collect();
            let origin = options["origin"].as_str().unwrap_or("console");
            match tree.put_entry(r, &dn, &pairs, Some(origin), None) {
                Err(e) => Err(e),
                Ok(_) => Ok((
                    dn.clone(),
                    tree.get(r, &dn).map(|e| {
                        sts_registers::applications::store::StoredApplication::of(e)
                    }),
                    typed,
                )),
            }
        };
        let (dn, stored, typed) = match outcome {
            Err(e) => {
                return rp::Marked {
                    value: json!({ "ok": false, "errors": [e.message.clone()] }),
                    code: Some(e.code.unwrap_or(codes::STS_LDAP_0008)),
                }
            }
            Ok(v) => v,
        };
        self.dir.write_back();
        tracing::info!(
            "audit: user.create {} on request ({})",
            dn,
            options["note"].as_str().unwrap_or("")
        );
        let entry = stored.map(|s| {
            json!({ "dn": s.dn, "origin": s.origin, "attributes": s.attributes })
        });
        rp::Marked::plain(json!({ "ok": true, "dn": dn, "username": wanted,
                                  "typed": typed, "invented": false,
                                  "entry": entry }))
    }
}

/// `common/credentials.ts` as the users acts ask it, over `sts-credentials`.
struct PeopleCredentials(Arc<sts_credentials::credentials::Credentials>);

impl rp::Credentials for PeopleCredentials {
    fn account_disabled(&self, name: &str) -> bool {
        self.0.account_disabled(name)
    }
    fn set_account_disabled(
        &self,
        name: &str,
        disabled: bool,
        _options: &Json,
    ) -> rp::Marked {
        // `credentials.setAccountDisabled()`: the lock on the entry. The
        // RISC reason in `options` is the signal's, and this runtime has no
        // transmitter to carry it.
        let v = self.0.set_account_disabled(name, disabled);
        rp::Marked {
            value: v.value,
            code: v.code,
        }
    }
    fn generate_password(&self, _name: &str) -> String {
        // `generatePassword()` is the password policy's; until it is in the
        // runtime, a random token of 192 bits.
        sts_crypto::random::random_token(Some(192)).unwrap_or_default()
    }
    fn set_password(&self, name: &str, password: &str, options: &Json) -> Json {
        match self.0.set_password(name, password, options) {
            Ok(v) => v.value,
            Err(e) => json!({ "ok": false, "errors": [e] }),
        }
    }
    fn set_password_reset_required(&self, _name: &str, _flag: bool) -> Json {
        json!({ "ok": false })
    }
    fn issue_activation(&self, _name: &str) -> Json {
        json!({ "ok": false,
                "errors": ["An activation link is not ported to this runtime yet."] })
    }
}

/// Service accounts: not ported. Nothing is refused, nothing is one.
struct NoServiceAccounts;

impl rp::ServiceAccounts for NoServiceAccounts {
    fn write_refusal(&self, _fields: &Json) -> Option<rp::PolicyRefusal> {
        None
    }
    fn check(&self, _body: &Json, _existing: &str) -> rp::Marked {
        rp::Marked::plain(json!({ "ok": true }))
    }
    fn set(&self, _username: &str, _change: &Json) -> Json {
        json!({ "ok": false,
                "errors": ["Service accounts are not ported to this runtime yet."] })
    }
    fn list(&self) -> Vec<Json> {
        Vec::new()
    }
    fn of(&self, _name: &str) -> Json {
        Json::Null
    }
    fn set_owner_protected(&self, _name: &str, _flag: bool) -> rp::Marked {
        rp::Marked::plain(json!({ "ok": false }))
    }
}

/// The CAEP and RISC signals of a credential change: SSF is not ported.
struct NoSignals;

impl rp::AccountSignals for NoSignals {
    fn credential_changed(&self, _change: &Json) {}
}

/// No mail channel in this runtime: a link is never mailed.
struct NoMailer;

impl rp::LinkMailer for NoMailer {
    fn mailed_link(
        &self,
        _kind: &str,
        _who: &str,
        _token: &str,
        _body: &Json,
        _actor: &str,
        _via: &str,
    ) -> Json {
        Json::Null
    }
}

/// `admin_stats.identityKeyOf(name)`: the name itself.
struct Names;

impl rp::IdentityKeys for Names {
    fn identity_key_of(&self, name: &str) -> String {
        name.to_string()
    }
}

/// `logout.terminate(key, selection, options)` over the runtime's
/// sign-out: what a disable ends (`endEverything()`).
struct EndEverything(Arc<sts_logout::Logout>);

impl rp::Logout for EndEverything {
    fn terminate(&self, key: &str, selection: &Json, options: &Json) -> Json {
        let text = |k: &str| {
            options
                .get(k)
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_string()
        };
        let opts = sts_logout::TerminateOptions {
            actor: text("actor"),
            by: text("by"),
            channel: text("channel"),
            initiating_entity: text("initiatingEntity"),
            no_provider_command: options.get("providerCommand")
                == Some(&Json::Bool(false)),
            ..Default::default()
        };
        let chosen: Vec<String> = selection
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        match self.0.terminate(key, &chosen, &opts) {
            Ok(v) => v,
            Err(e) => json!({ "message": e }),
        }
    }
}

/// The side effects of an account change outside the register.
struct NoEffects;

impl rp::AccountEffects for NoEffects {
    fn note_revoking_write(&self, _what: &str) {}
    fn mail_account_disabled(&self, _name: &str, _why: &str, _by: bool) {}
}

/// The gate's registers.
struct Gate {
    registry: Arc<RealmRegistry>,
    tokens: Arc<sts_oauth::minted::TokenRegister>,
    sessions: Arc<sts_authn::Sessions>,
    credentials: Arc<sts_credentials::credentials::Credentials>,
    clients: Arc<dyn Clients>,
    scopes: Arc<sts_oauth::scopes::ScopePolicy>,
    roles: Arc<sts_registers::role_permissions::RolePermissions>,
}

impl Gate {
    fn in_realm<R>(&self, realm_id: &str, f: impl FnOnce() -> R) -> R {
        let one = self
            .registry
            .get(realm_id)
            .unwrap_or_else(|| self.registry.default_realm());
        realm::run_sync(one, f)
    }
}

impl GatePorts for Gate {
    fn revoked(&self, realm_id: &str, jti: &str) -> bool {
        self.in_realm(realm_id, || self.tokens.is_revoked(jti))
    }
    fn disabled(&self, realm_id: &str, sub: &str) -> bool {
        self.in_realm(realm_id, || self.credentials.account_disabled(sub))
    }
    fn session_ended(&self, realm_id: &str, jti: &str) -> bool {
        self.in_realm(realm_id, || {
            let sid = self
                .tokens
                .get(realm_id, jti)
                .and_then(|row| row["sessionId"].as_str().map(str::to_string))
                .unwrap_or_default();
            !sid.is_empty()
                && !sts_oauth::token_endpoint::GrantSessions::ended(
                    self.sessions.as_ref(),
                    &sid,
                )
                .is_empty()
        })
    }
    fn client_method(&self, realm_id: &str, client: &str) -> String {
        self.in_realm(realm_id, || {
            self.clients.client_config_of(client)["token_endpoint_auth_method"]
                .as_str()
                .unwrap_or("")
                .to_string()
        })
    }
    fn certificate_declaration(&self, realm_id: &str, client: &str) -> String {
        // `mtls.certificateDeclaration(clientConfigOf(client))`.
        self.in_realm(realm_id, || {
            let r = self.clients.client_config_of(client);
            if r["known"] != json!(true) {
                return String::new();
            }
            const CERTIFICATE_METHODS: [&str; 2] =
                ["tls_client_auth", "self_signed_tls_client_auth"];
            let listed: Vec<String> = r["token_endpoint_auth_methods"]
                .as_array()
                .filter(|l| !l.is_empty())
                .map(|l| {
                    l.iter()
                        .map(|m| m.as_str().unwrap_or("").trim().to_string())
                        .collect()
                })
                .unwrap_or_else(|| {
                    vec![r["token_endpoint_auth_method"]
                        .as_str()
                        .unwrap_or("")
                        .trim()
                        .to_string()]
                });
            if let Some(m) = listed
                .iter()
                .find(|m| CERTIFICATE_METHODS.contains(&m.as_str()))
            {
                return format!("token_endpoint_auth_method={}", m);
            }
            if r["tls_client_certificate_bound_access_tokens"] == json!(true) {
                return "tls_client_certificate_bound_access_tokens=true"
                    .to_string();
            }
            String::new()
        })
    }
    fn declares(&self, realm_id: &str, client: &str, scope: &str) -> bool {
        // `scopePolicy.declares()`: a word a delegated permission grant
        // governs, by that grant alone (#1141); otherwise an exact listing.
        // (The Shared Signals coverage rule, #334, governs no admin scope.)
        self.in_realm(realm_id, || {
            if !self.scopes.delegated_permission_api_of(scope).is_empty() {
                return self
                    .scopes
                    .delegated_permission_scopes(client)
                    .iter()
                    .any(|s| s == scope);
            }
            self.scopes
                .declared_scopes(client)
                .is_some_and(|held| held.iter().any(|s| s == scope))
        })
    }
    fn effective_roles(
        &self,
        realm_id: &str,
        claims: &Json,
        scopes: &[String],
    ) -> Effective {
        self.in_realm(realm_id, || {
            let e = self.roles.effective_roles(claims, scopes);
            let list = |v: &Json| -> Vec<String> {
                v.as_array()
                    .map(|a| {
                        a.iter()
                            .map(|x| x.as_str().unwrap_or("").to_string())
                            .collect()
                    })
                    .unwrap_or_default()
            };
            Effective {
                roles: list(&e["roles"]),
                withdrawn: list(&e["withdrawn"]),
                why: e["why"].as_str().unwrap_or("").to_string(),
                subject_kind: e["subject"]["kind"]
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
                subject_name: e["subject"]["name"]
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
            }
        })
    }
    fn security_change(
        &self,
        _realm: &str,
        _operation: &ConsoleOperation,
        _body: &Json,
    ) -> Option<String> {
        None
    }
    fn realm_refusal(
        &self,
        _realm: &str,
        _operation: &ConsoleOperation,
        _body: Option<&Json>,
    ) -> Option<String> {
        None
    }
}

/// The key sets and the nonce.
struct Keys {
    persistence: Arc<Persistence>,
    dpop: Arc<sts_oauth::dpop_stores::DpopStores>,
}

impl KeySource for Keys {
    fn key_set(&self, realm_id: &str) -> Option<KeySet> {
        let id = if realm_id == realm::DEFAULT_ID {
            ""
        } else {
            realm_id
        };
        self.persistence.key_sets().and_then(|s| s.open(id))
    }
    fn issue_nonce(&self) -> String {
        self.dpop.issue_nonce().unwrap_or_default()
    }
}

/// The setup operations' reads.
struct Setup {
    persistence: Arc<Persistence>,
    apps: Arc<ApplicationRegistry>,
    people: Arc<sts_registers::people::People>,
    tokens: Arc<sts_oauth::minted::TokenRegister>,
    sessions: Arc<sts_authn::Sessions>,
    dir: Arc<LiveDir>,
    started: std::time::Instant,
    started_at: String,
}

impl SetupPorts for Setup {
    fn seed_administrator(&self, _realm: &str) -> Seeded {
        // `rbac.seedBootstrapAdministrator()` is not ported: a realm made
        // here gets no administrator of its own (the service roster still
        // reaches it).
        Seeded::default()
    }
    fn kid_of(&self, realm_id: &str) -> String {
        let Some(sets) = self.persistence.key_sets() else {
            return String::new();
        };
        if let Some(kid) = sets.open(realm_id).and_then(|s| s.kid()) {
            return kid;
        }
        // A realm made a moment ago has no key set yet: made now, as
        // `stsKeysFor()` makes one.
        let id = realm_id.to_string();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { sets.open_or_make(&id).await })
        })
        .ok()
        .and_then(|s| s.kid())
        .unwrap_or_default()
    }
    fn listeners_of(&self, _realm: &str) -> Vec<Listener> {
        Vec::new()
    }
    fn advertised_base(&self, _realm: &str) -> String {
        String::new()
    }
    fn reserved(&self) -> Vec<String> {
        RESERVED.iter().map(|s| s.to_string()).collect()
    }
    fn totals(&self, realm_id: &str) -> Json {
        let held = self.tokens_held(realm_id);
        let people = self.dir.with(|t| {
            LiveDir::realm_index(t, realm_id).map_or(0, |r| {
                t.realms()[r]
                    .entries
                    .values()
                    .filter(|e| t.is_person_dn(r, &e.dn))
                    .count()
            })
        });
        json!({
            "issuer": "",
            "startedAt": self.started_at,
            "uptimeMs": self.started.elapsed().as_millis() as u64,
            "calls": 0,
            "tokensHeld": held.0,
            "tokensHeldOnly": false,
            "tokensRevoked": held.1,
            "artifactsHeld": 0,
            "signOnSessions": self.sessions_held(),
            "usersKnown": people,
            "usersAuthenticatedHere": 0,
        })
    }
    fn retire(
        &self,
        _realm: &str,
    ) -> Result<Json, (sts_core::errors::ErrorCode, Vec<String>)> {
        Err((
            sts_core::errors::codes::STS_API_0050,
            vec!["Removing a trust realm is not ported to this runtime yet."
                .to_string()],
        ))
    }
    fn applications(&self) -> Option<Arc<ApplicationRegistry>> {
        Some(self.apps.clone())
    }
    fn people(&self) -> Option<Arc<sts_registers::people::People>> {
        Some(self.people.clone())
    }
}

impl Setup {
    /// `snap.tokens.held` and `snap.tokens.revoked`: the realm's token
    /// register and its revoked list.
    fn tokens_held(&self, realm_id: &str) -> (usize, usize) {
        self.tokens.held_in(realm_id)
    }
    /// `sessions.size`: the ambient realm's sign-on sessions.
    fn sessions_held(&self) -> usize {
        self.sessions.store().len()
    }
}

/// The console's first screen.
struct Console {
    settings: Arc<Settings>,
    version: sts_core::version::VersionInfo,
    mode: Arc<Mode>,
    roster: Arc<RosterRoles>,
    persistence: Arc<Persistence>,
    catalogs: Arc<sts_http::i18n::Catalogs>,
    announcements: RealmMap<Json>,
}

impl ConsolePorts for Console {
    fn roster(&self, name: &str, realm_id: &str) -> Option<Json> {
        Some(rp::RosterRoles::roles_of(
            self.roster.as_ref(),
            name,
            realm_id,
        ))
    }
    fn roster_available(&self) -> bool {
        true
    }
    fn runtime_facts(&self) -> Json {
        let status = self.persistence.status();
        let mode = status["mode"].as_str().unwrap_or("memory").to_string();
        json!({
            "process": "single process",
            "mode": self.mode.current(),
            "database": match mode.as_str() {
                "memory" => "memory (nothing written down)".to_string(),
                other => other.to_string(),
            },
        })
    }
    fn persistence(&self) -> (bool, String) {
        let status = self.persistence.status();
        (
            status["enabled"].as_bool().unwrap_or(false),
            status["mode"].as_str().unwrap_or("").to_string(),
        )
    }
    fn locale(
        &self,
        headers: &HeaderMap,
        _username: &str,
        as_files: bool,
    ) -> Json {
        let preferences = sts_mgmt_api::console::preferences_of(headers, None);
        if as_files {
            sts_mgmt_api::console::locale_files(
                &self.catalogs,
                &preferences,
                &self.version,
            )
        } else {
            sts_mgmt_api::console::locale_data(
                &self.catalogs,
                &preferences,
                &["console"],
            )
        }
    }
    fn announcements(&self, surface: &str, since: i64) -> Json {
        announcements_for(&self.announcements, &self.settings, surface, since)
    }
}

/// `SsfReceivers.announcementsFor(surface, since)`: what a broadcast left
/// for this surface since the caller's first answer, oldest first; a row
/// older than `ssf.announcementKeepS` is never answered.
#[tracing::instrument(level = "debug", skip_all)]
pub fn announcements_for(
    store: &RealmMap<Json>,
    settings: &Settings,
    surface: &str,
    since: i64,
) -> Json {
    let now = chrono::Utc::now().timestamp_millis();
    let keep_ms = settings.value_of("ssf.announcementKeepS").as_int() * 1000;
    let mut found: Vec<Json> = store
        .in_realm(&realm::current_id())
        .entries()
        .into_iter()
        .map(|(_, row)| row)
        .filter(|row| {
            let at = row["atMs"].as_f64().unwrap_or(0.0) as i64;
            now - at <= keep_ms
                && since > 0
                && row["surface"].as_str() == Some(surface)
                && at > since
        })
        .collect();
    found.sort_by_key(|row| row["atMs"].as_f64().unwrap_or(0.0) as i64);
    json!({
        "now": now,
        "everyMs": settings.value_of("ssf.announcementPollMs").as_int(),
        "announcements": found.iter().map(|row| {
            let at = row["atMs"].as_f64().unwrap_or(0.0) as i64;
            json!({ "id": row["jti"], "at": chrono::DateTime::from_timestamp_millis(at)
                        .map(sts_core::time::iso).unwrap_or_default(),
                    "message": row["message"] })
        }).collect::<Vec<_>>(),
    })
}

/// What `/account-api` reads, in the ambient realm.
struct Account {
    settings: Arc<Settings>,
    dir: Arc<LiveDir>,
    tokens: Arc<sts_oauth::minted::TokenRegister>,
    sessions: Arc<sts_authn::Sessions>,
    credentials: Arc<sts_credentials::credentials::Credentials>,
    facts: Arc<dyn sts_authn_api::ports::SignInFacts>,
    catalogs: Arc<sts_http::i18n::Catalogs>,
}

impl sts_mgmt_api::account::AccountPorts for Account {
    fn name_for_subject(&self, sub: &str) -> String {
        self.dir
            .with(|t| t.name_for_subject(&realm::current_id(), sub))
    }
    fn subject_is_gone(&self, sub: &str) -> bool {
        sub.trim().to_lowercase().starts_with("urn:uuid:")
            && self.name_for_subject(sub).is_empty()
    }
    fn session_id_of(&self, jti: &str) -> String {
        self.tokens
            .get(&realm::current_id(), jti)
            .and_then(|row| row["sessionId"].as_str().map(str::to_string))
            .unwrap_or_default()
    }
    fn session(&self, sid: &str) -> Option<Json> {
        self.sessions.session_by_id(sid)
    }
    fn sign_on_facts(&self, session: &Json) -> Json {
        self.sessions.sign_on_facts_for(session)
    }
    fn person_entry(&self, name: &str) -> Option<Json> {
        self.dir.with(|t| {
            let r = LiveDir::realm_index(t, &realm::current_id())?;
            t.existing_user_entry(r, name)
                .map(|e| json!({ "dn": e.dn, "attributes": e.attributes }))
        })
    }
    fn mechanisms(&self, name: &str) -> Json {
        // `credentials.mechanismsFor(name)`'s members the Overview reads.
        // The emailed second factor (#64, off by default) is not ported.
        let keys = self.credentials.keys_of(name);
        let held = keys.len();
        let mfa = if held > 0 && self.facts.key_use_allowed("mfa").is_ok() {
            held
        } else {
            0
        };
        let totp = self.credentials.totp_of(name);
        let unusable =
            totp.as_ref().is_some_and(|t| t["unusable"] == json!(true));
        json!({
            "password": self.credentials.has_password(name),
            "keys": keys,
            "totp": totp.is_some(),
            "totpUsable": totp.is_some() && !unusable,
            "mfaRequired": mfa > 0 || totp.is_some(),
            "secondFactor": if mfa > 0 { "webauthn" }
                            else if totp.is_some() { "totp" } else { "" },
            "backupCodes": self.credentials.backup_code_status(name),
        })
    }
    fn times_signed_in(&self, _name: &str) -> Option<i64> {
        // `stats.userDetail()` is the identity register's, not ported: no
        // row, so the page draws no figure rather than a zero.
        None
    }
    fn photo_path(&self, _name: &str) -> String {
        String::new()
    }
    fn photo_view(&self, name: &str) -> Json {
        // `ProfilePhoto.viewFor(name)`: the photos themselves are not
        // ported (#719), so there is no path and no origin; the settings
        // are the realm's.
        let n = |k: &str| self.settings.value_of(k).as_int();
        json!({ "path": self.photo_path(name), "origin": "",
                "selfService":
                    self.settings.value_of("profilePhoto.selfService").as_bool(),
                "limits": {
                    "maxFileBytes": n("profilePhoto.maxFileBytes"),
                    "maxStoredBytes": n("profilePhoto.maxStoredBytes"),
                    "minPixels": n("profilePhoto.minPixels"),
                    "maxPixels": n("profilePhoto.maxPixels"),
                    "types": ["image/jpeg", "image/png"],
                } })
    }
    fn locale(&self, headers: &HeaderMap, _username: &str) -> Json {
        sts_mgmt_api::console::locale_data(
            &self.catalogs,
            &sts_mgmt_api::console::preferences_of(headers, None),
            &["portal", "chooser"],
        )
    }
    fn offered(&self) -> Vec<Json> {
        self.catalogs.offered()
    }
}

/// `/admin-api`, built.
pub struct AdminStack {
    pub services: Arc<Services>,
    pub dir: Arc<LiveDir>,
    /// One request at a time: the registers' directory is refilled before
    /// a request and written back after it, so two at once would undo each
    /// other's writes.
    serial: Arc<tokio::sync::Mutex<()>>,
    /// `/account-api` over the same services.
    account: Arc<sts_mgmt_api::account::AccountApi>,
    /// The families' acts, answered once the router hands them over.
    pub families: Arc<crate::admin_families::AdminFamilies>,
}

impl AdminStack {
    /// Builds the API over the runtime, declaring its one store (the
    /// announcements a broadcast leaves) before the store opens.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn declare(parts: AdminParts) -> Arc<AdminStack> {
        let settings = parts.settings.clone();
        let mode = parts.mode.clone();
        let domain = settings.value_of("global.domain");
        let tree = Arc::new(Mutex::new(Directory::new(
            &realm::base_dn_of_domain(domain.as_str()),
        )));
        let dir = Arc::new(LiveDir {
            settings: settings.clone(),
            registry: parts.registry.clone(),
            live: parts.live.clone(),
            persistence: parts.persistence.clone(),
            tree: tree.clone(),
            touched: Arc::new(Touched::default()),
        });
        let apps = Arc::new(ApplicationRegistry::new(
            Some(tree),
            Arc::new(crate::oauth::SealingEnv {
                core: sts_registers::applications::env::CoreEnv {
                    settings: settings.clone(),
                    mode: mode.clone(),
                },
                persistence: parts.persistence.clone(),
            }),
            Arc::new(sts_registers::applications::env::NoEffects),
        ));
        let accepts = mode.clone();
        let clients: Arc<dyn Clients> =
            Arc::new(sts_oauth::clients::RegisterClients {
                registry: apps.clone(),
                now_s: Arc::new(|| chrono::Utc::now().timestamp()),
                accepts_unregistered: Arc::new(move || {
                    accepts.accepts_unregistered_addresses()
                }),
            });
        let scopes = Arc::new(sts_oauth::scopes::ScopePolicy {
            settings: settings.clone(),
            mode: mode.clone(),
            clients: clients.clone(),
            credential_scopes: Vec::new(),
        });
        let reg_mode = Arc::new(RegMode {
            mode: mode.clone(),
            registry: parts.registry.clone(),
        });
        let roster = Arc::new(RosterRoles {
            dir: dir.clone(),
            settings: settings.clone(),
            mode: reg_mode.clone(),
        });
        let roles = Arc::new(sts_registers::roles::Roles::new(
            Some(Arc::new(RoleDir(dir.clone()))),
            Arc::new(RegSettings(settings.clone())),
        ));
        let permissions =
            Arc::new(sts_registers::role_permissions::RolePermissions::new(
                sts_registers::role_permissions::RolePermissionsDeps {
                    roles,
                    applications: Arc::new(RegApps(apps.clone())),
                    audit: Arc::new(LogAudit),
                    roster: roster.clone(),
                    ownership: Arc::new(NoOwners),
                    gate: Arc::new(KeepEveryScope),
                    subjects: Arc::new(Subjects(dir.clone())),
                    mode: reg_mode,
                },
            ));
        let register = parts.oauth.tokens.register.clone();
        let dpop = parts.oauth.tokens.dpop.clone();
        let credentials: Arc<dyn rp::Credentials> =
            Arc::new(PeopleCredentials(parts.credentials.clone()));
        let people = Arc::new(sts_registers::people::People::new(
            sts_registers::people::PeopleDeps {
                people: Some(Arc::new(PersonWriter {
                    dir: dir.clone(),
                    mode: mode.clone(),
                })),
                groups: None,
                credentials: credentials.clone(),
                service_accounts: Arc::new(NoServiceAccounts),
                signals: Arc::new(NoSignals),
                mailer: Arc::new(NoMailer),
                mode: Arc::new(RegMode {
                    mode: mode.clone(),
                    registry: parts.registry.clone(),
                }),
                audit: Arc::new(LogAudit),
            },
            Arc::new(sts_registers::people::AccountState::new(
                credentials,
                Arc::new(Names),
                Some(Arc::new(EndEverything(parts.logout.clone()))),
                Arc::new(NoEffects),
                Arc::new(LogAudit),
            )),
        ));
        let announcements = RealmMap::new(
            &parts.lifecycle,
            &parts.handles,
            StoreSpec::persisted("ssf_receivers.announcements"),
        );
        let store = parts.persistence.status();
        let families =
            Arc::new(crate::admin_families::AdminFamilies::default());
        let services = Arc::new(Services {
            settings: settings.clone(),
            mode: mode.clone(),
            lifecycle: parts.lifecycle.clone(),
            registry: parts.registry.clone(),
            tokens: Arc::new(
                sts_oauth::jwt_access_token::JwtAccessTokens::new(
                    settings.clone(),
                ),
            ),
            keys: Arc::new(Keys {
                persistence: parts.persistence.clone(),
                dpop: dpop.clone(),
            }),
            gate_ports: Arc::new(Gate {
                registry: parts.registry.clone(),
                tokens: register.clone(),
                sessions: parts.sessions.clone(),
                credentials: parts.credentials.clone(),
                clients,
                scopes,
                roles: permissions,
            }),
            access: Arc::new(sts_mgmt_api::gate::BuiltInAccess::new()),
            dpop,
            setup_ports: Arc::new(Setup {
                persistence: parts.persistence.clone(),
                apps,
                people,
                tokens: register,
                sessions: parts.sessions.clone(),
                dir: dir.clone(),
                started: std::time::Instant::now(),
                started_at: sts_core::time::iso(chrono::Utc::now()),
            }),
            console: Arc::new(Console {
                settings: settings.clone(),
                version: parts.version.clone(),
                mode: mode.clone(),
                roster,
                persistence: parts.persistence.clone(),
                catalogs: parts.catalogs.clone(),
                announcements,
            }),
            families: families.clone(),
            facts: ProcessFacts {
                config_file: std::env::var("CONFIG_FILE").ok(),
                defaults_file: "./env/defaults.js".to_string(),
                persists_appconfig: parts.persistence.mode().is_database(),
                persists_realms: parts.persistence.mode().is_database(),
                persistence_mode: store["mode"]
                    .as_str()
                    .unwrap_or("memory")
                    .to_string(),
                persistence_enabled: store["enabled"]
                    .as_bool()
                    .unwrap_or(false),
            },
            version: parts.version,
            eddsa_curve: String::new(),
            now: Arc::new(|| chrono::Utc::now().timestamp()),
        });
        let account = Arc::new(sts_mgmt_api::account::AccountApi {
            services: services.clone(),
            ports: Arc::new(Account {
                settings: settings.clone(),
                dir: dir.clone(),
                tokens: parts.oauth.tokens.register.clone(),
                sessions: parts.sessions.clone(),
                credentials: parts.credentials.clone(),
                facts: parts.facts.clone(),
                catalogs: parts.catalogs.clone(),
            }),
        });
        Arc::new(AdminStack {
            services,
            dir,
            account,
            families,
            serial: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    /// The router, every path under `/admin-api`: the registers' directory
    /// refilled before the request and its writes put back after it.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn router(&self) -> axum::Router {
        let dir = self.dir.clone();
        let serial = self.serial.clone();
        sts_mgmt_api::router::router(self.services.clone())
            .merge(self.account.clone().router())
            .layer(axum::middleware::from_fn(
                move |request: axum::extract::Request,
                      next: axum::middleware::Next| {
                    let (dir, serial) = (dir.clone(), serial.clone());
                    async move {
                        let _one = serial.lock().await;
                        dir.reload();
                        let response = next.run(request).await;
                        dir.write_back();
                        response
                    }
                },
            ))
    }
}
