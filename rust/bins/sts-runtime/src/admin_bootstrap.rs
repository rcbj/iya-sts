// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A REALM'S BOOTSTRAP ADMINISTRATOR (#444, phase 5, the `apis3` slice):
//! `common/bootstrap_name.ts`'s `BootstrapName.current()` and
//! `admin-ui/admin_rbac.ts`'s `seedBootstrapAdministrator()`, with the
//! product password `adminActions.realmsAction()`'s `create` hands back.
//!
//! **THE NAME IS DECIDED IN THE REALM'S MODE** (`mode.generatesBootstrapName()`
//! asked inside the realm): a product realm whose configured name is a
//! default one (`admin`, `root`, `sa`, `administrator`, or none) is
//! administered by `admin-<the first 16 hex of HMAC-SHA-256 over the csrf
//! cluster secret and this domain>`, a development realm by the name as
//! configured. The roster's reads ask the same function, so the account the
//! seeding makes and the account the console counts as the bootstrap are
//! one.
//!
//! The seeding: the person's entry made where it is missing (exempt from
//! the attribute policy, as `createPerson()` makes it), marked
//! `stsBootstrapAdministrator` and, when made here, `pwdReset`; given both
//! console roles through the roster (`grant()` with `via: bootstrap`); and,
//! when somebody else already administers the realm, the console window
//! closed at once (`stsConsoleClaimedAt`). The Security Administrator is
//! seeded only in the default realm (`seedSecurityAdministrator()`), which
//! no realm create reaches, so it is not here.
//!
//! NOT PORTED: the audit row (logged, as `LogAudit` logs every row here),
//! CAEP's `credential-change` for the bootstrap password
//! (`noteBootstrapPassword()` — no transmitter in this runtime), and
//! `reportClosedConsole()`'s log line.

use std::sync::{Arc, PoisonError};

use serde_json::{json, Value as Json};
use sts_core::errors::codes;
use sts_core::mode::Mode;
use sts_core::realm::{self, RealmRegistry};
use sts_core::settings::Settings;
use sts_directory::EntryExt;
use sts_mgmt_api::setup::Seeded;
use sts_registers::port::PersonWriter as _;
use sts_store::persistence::LiveDirectory as _;

use super::groups::Groups;
use super::LiveDir;

/// `DEFAULT_NAMES`.
const DEFAULT_NAMES: [&str; 4] = ["admin", "root", "sa", "administrator"];

/// `DOMAIN`, the HMAC's message.
const DOMAIN: &str = "iya-sts bootstrap administrator name";

/// The `csrf` cluster secret (`cluster/cluster_secrets.ts`), as the sign-in
/// surface reads it: `STS_CSRF_SECRET`.
fn csrf_secret() -> String {
    std::env::var("STS_CSRF_SECRET").unwrap_or_default()
}

/// `BootstrapName.current()`, in the AMBIENT realm's mode: the configured
/// name, or the generated one where product does not allow a default.
#[tracing::instrument(level = "debug", skip_all)]
pub fn bootstrap_name(settings: &Settings, mode: &Mode) -> String {
    let named = settings
        .value_of("admin.bootstrapUsername")
        .as_str()
        .trim()
        .to_string();
    let lower = named.to_lowercase();
    let is_default =
        lower.is_empty() || DEFAULT_NAMES.contains(&lower.as_str());
    if !mode.predicate("generatesBootstrapName").unwrap_or(false) || !is_default
    {
        return named;
    }
    let digest = sts_crypto::raw_sig::hmac_sha256(
        csrf_secret().as_bytes(),
        DOMAIN.as_bytes(),
    )
    .unwrap_or_default();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("admin-{}", &hex[..16.min(hex.len())])
}

/// What the seeding needs.
pub struct Seeder {
    pub dir: Arc<LiveDir>,
    pub settings: Arc<Settings>,
    pub mode: Arc<Mode>,
    pub registry: Arc<RealmRegistry>,
    pub roster: Arc<super::RosterRoles>,
    pub credentials: Arc<sts_credentials::credentials::Credentials>,
}

impl Seeder {
    /// `writePersonFlag(key, name, value)`: TRUE, a text, or removed.
    fn write_flag(&self, realm_id: &str, name: &str, flag: &str, value: &str) {
        {
            let mut tree =
                self.dir.tree.lock().unwrap_or_else(PoisonError::into_inner);
            let Some(r) = LiveDir::realm_index(&tree, realm_id) else {
                return;
            };
            let Some(mut stored) = tree.locate(r, name).cloned() else {
                tracing::warn!(
                    "{}ldap: \"{}\" has no entry in this realm, so {} was \
                     not written.",
                    sts_core::log::tag(codes::STS_LDAP_0078),
                    name,
                    flag
                );
                return;
            };
            let lower = flag.to_lowercase();
            if value.is_empty() {
                stored.attributes.shift_remove(&lower);
            } else {
                stored.attributes.insert(lower, vec![value.to_string()]);
            }
            let created = stored.created_at.clone();
            let pairs: Vec<(String, Vec<String>)> = stored
                .attributes
                .iter()
                .filter(|(k, _)| {
                    !sts_directory::directory::OPERATIONAL.contains(&k.as_str())
                })
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let origin = stored.origin.clone();
            if tree
                .put_entry(r, &stored.dn, &pairs, origin.as_deref(), None)
                .is_ok()
            {
                if let Some(c) = created {
                    tree.restamp_created(r, &stored.dn, &c);
                }
            }
        }
        self.dir.write_back();
    }

    /// `readPersonFlags(name)`: `(dn, bootstrapAdministrator,
    /// consoleClaimedAt)`, or None for nobody.
    fn flags(
        &self,
        realm_id: &str,
        name: &str,
    ) -> Option<(String, bool, String)> {
        self.dir.with(|t| {
            let r = LiveDir::realm_index(t, realm_id)?;
            let e = t.locate(r, name)?;
            Some((
                e.dn.clone(),
                e.first("stsbootstrapadministrator")
                    .is_some_and(|v| v.eq_ignore_ascii_case("true")),
                e.first("stsconsoleclaimedat").unwrap_or("").to_string(),
            ))
        })
    }

    /// The people the realm's roster already names, the bootstrap
    /// administrator left out (`roster()`'s members and claimed).
    fn administered_by(&self, realm_id: &str, name: &str) -> Vec<String> {
        let groups = [
            self.settings
                .value_of("admin.readGroup")
                .as_str()
                .to_string(),
            self.settings
                .value_of("admin.writeGroup")
                .as_str()
                .to_string(),
        ];
        self.dir.with(|t| {
            let Some(r) = LiveDir::realm_index(t, realm_id) else {
                return Vec::new();
            };
            let reads = Groups { tree: t, r };
            let mut names: Vec<String> = Vec::new();
            for cn in &groups {
                let info =
                    reads.groups_for(&self.settings, &reads.group_dn_for(cn));
                let group = &info["group"];
                let rows =
                    group["members"].as_array().into_iter().flatten().chain(
                        group["claimed"].as_array().into_iter().flatten(),
                    );
                for one in rows {
                    let who = one["userKey"].as_str().unwrap_or("").to_string();
                    if !who.is_empty()
                        && who.to_lowercase() != name.to_lowercase()
                        && !names.contains(&who)
                    {
                        names.push(who);
                    }
                }
            }
            names
        })
    }

    /// `seedBootstrapAdministrator()` in a realm, then the product password.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn seed(&self, realm_id: &str) -> Seeded {
        let Some(one) = self.registry.get(realm_id) else {
            return Seeded::default();
        };
        // A realm made in this request is not in the registers' directory
        // yet: it was refilled before the request.
        if self
            .dir
            .with(|t| LiveDir::realm_index(t, realm_id).is_none())
        {
            let mut tree =
                self.dir.tree.lock().unwrap_or_else(PoisonError::into_inner);
            tree.add_realm(realm_id, &self.registry.base_dn_of(&one));
            let entries: Vec<_> = self
                .dir
                .live
                .realm_entries(realm_id)
                .into_values()
                .collect();
            tree.restore(realm_id, entries);
        }
        // `mode.isProduct()` in the realm the create was asked in.
        let product_here = self.mode.current() == "product";
        let seeded = realm::run_sync(one.clone(), || self.seed_in(realm_id));
        if !(seeded.ran && seeded.created && product_here) {
            return seeded;
        }
        // In product nobody's password is accepted unchecked: a generated
        // one, handed back ONCE, and changed at the first sign-in.
        let password = realm::run_sync(one, || {
            let generated =
                sts_crypto::random::random_token(Some(192)).unwrap_or_default();
            match self.credentials.set_password(
                &seeded.username,
                &generated,
                &json!({ "generated": true }),
            ) {
                Ok(v) if v.value.get("ok") == Some(&Json::Bool(true)) => {
                    self.write_flag(
                        realm_id,
                        &seeded.username,
                        "pwdReset",
                        "TRUE",
                    );
                    Some(generated)
                }
                _ => {
                    tracing::error!(
                        "{}admin: the bootstrap administrator \"{}\" of the \
                         \"{}\" realm could not be given a password.",
                        sts_core::log::tag(codes::STS_ADMIN_0706),
                        seeded.username,
                        realm_id
                    );
                    None
                }
            }
        });
        Seeded { password, ..seeded }
    }

    fn seed_in(&self, realm_id: &str) -> Seeded {
        let name = bootstrap_name(&self.settings, &self.mode);
        if name.is_empty() {
            return Seeded::default();
        }
        let mut flags = self.flags(realm_id, &name);
        if let Some((_, true, claimed)) = &flags {
            if !claimed.is_empty() {
                return Seeded {
                    ran: false,
                    username: name,
                    created: false,
                    password: None,
                };
            }
        }
        let administered = self.administered_by(realm_id, &name);
        let mut created = false;
        if flags.is_none() {
            let writer = super::PersonWriter {
                dir: self.dir.clone(),
                mode: self.mode.clone(),
            };
            let made = writer.create_user(
                &name,
                &json!({ "requiredExempt": "bootstrap administrator" }),
            );
            if made.value.get("ok") != Some(&Json::Bool(true)) {
                tracing::error!(
                    "{}admin_rbac: the bootstrap administrator \"{}\" could \
                     not be created in the \"{}\" realm: {}",
                    sts_core::log::tag(codes::STS_ADMIN_0706),
                    name,
                    realm_id,
                    made.value["errors"]
                );
                return Seeded {
                    ran: false,
                    username: name,
                    created: false,
                    password: None,
                };
            }
            created = true;
            flags = self.flags(realm_id, &name);
        }
        if !flags.as_ref().is_some_and(|f| f.1) {
            self.write_flag(
                realm_id,
                &name,
                "stsBootstrapAdministrator",
                "TRUE",
            );
        }
        if created {
            self.write_flag(realm_id, &name, "pwdReset", "TRUE");
        }
        let rbac = self.roster.rbac(realm_id);
        let failed: Vec<String> = ["read", "write"]
            .iter()
            .map(|id| rbac.grant(&name, id, "bootstrap", "bootstrap"))
            .filter(|one| one.refused())
            .map(|one| one.answer["errors"].to_string())
            .collect();
        if !failed.is_empty() {
            tracing::error!(
                "{}admin_rbac: the bootstrap administrator \"{}\" could not \
                 be given both console roles: {}",
                sts_core::log::tag(codes::STS_ADMIN_0706),
                name,
                failed.join(" ")
            );
        }
        let closed_at_once = !administered.is_empty();
        if closed_at_once {
            let now = chrono::Utc::now().format("%Y%m%d%H%M%SZ").to_string();
            self.write_flag(realm_id, &name, "stsConsoleClaimedAt", &now);
        }
        tracing::info!(
            "admin_rbac: \"{}\" in the \"{}\" realm holds Admin Read and \
             Admin Write{}. {}",
            name,
            realm_id,
            if created {
                ", and must change its password at its first sign-in"
            } else {
                ""
            },
            if closed_at_once {
                format!(
                    "The roster already named {}, so the console stays \
                     enforced.",
                    administered.join(", ")
                )
            } else {
                "Until it first signs in to /admin, every signed-in person \
                 may use the console."
                    .to_string()
            }
        );
        Seeded {
            ran: true,
            username: name,
            created,
            password: None,
        }
    }
}
