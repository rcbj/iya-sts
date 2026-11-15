// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE IDENTITY FUNNEL (#444 phase 5, the `oauth7` slice): what
//! `admin_stats.recordAuthentication()` hands the directory's user
//! observer (`ldap_server.js`'s `observeIdentity()`) before anything else
//! is recorded — the entry for whoever authenticated, CREATED where this
//! service creates people (`autoCreateUser()`: `mode.autoCreates()` and
//! `ldap.autocreateUsers`, development's default), found and noted where
//! it already exists.
//!
//! ONE FUNNEL, TWO DOORS, as in Node: the sign-on session's
//! `startSession()` records every authentication through the session
//! core's `Records` port, and the token endpoint's password grant
//! (RFC 6749 section 4.3) records its own through the SAME port before it
//! asks for the person's subject — so a first sign-in and a first
//! password grant for an unprovisioned name both create
//! `uid=<name>,ou=users`, and in product mode (or with the setting off)
//! neither does and both refuse for want of a subject.
//!
//! "THE DIRECTORY IS TOLD FIRST" (`admin_stats.js`, 2026-09-14): the entry
//! is written before the call returns, so the caller's `userFor()` that
//! follows finds its `entryUUID`. The write goes into the live directory
//! and is marked for the store's next flush; another node reads it from
//! the change log, as Node's do.
//!
//! What this wraps (`inner`) is the identity register's recording — the
//! counts `/admin/users` draws, not in this runtime yet — and is handed
//! every record after the directory was told.
//!
//! The pure decisions are `sts_directory::funnel`'s; what is not ported is
//! said there.

use std::sync::Arc;

use serde_json::Value as Json;
use sts_authn::ports::{Records, Request};
use sts_core::errors::codes;
use sts_core::log::tag;
use sts_core::mode::Mode;
use sts_core::realm::{self, RealmRegistry};
use sts_core::settings::Settings;
use sts_directory::funnel::{self, NotAPerson};
use sts_directory::{Directory, EntryExt};
use sts_store::model::StoredEntry;
use sts_store::persistence::{LiveDirectory, MemoryDirectory, Persistence};
use sts_store::shadow::EntryLookup;

/// The funnel, over the live directory.
pub struct IdentityFunnel {
    pub live: Arc<MemoryDirectory>,
    pub persistence: Arc<Persistence>,
    pub registry: Arc<RealmRegistry>,
    pub settings: Arc<Settings>,
    pub mode: Arc<Mode>,
    /// The identity register's recording, handed every record after.
    pub inner: Option<Arc<dyn Records>>,
}

fn text(record: &Json, key: &str) -> String {
    match record.get(key) {
        Some(Json::String(s)) => s.clone(),
        _ => String::new(),
    }
}

fn now() -> String {
    chrono::Utc::now().format("%Y%m%d%H%M%SZ").to_string()
}

impl IdentityFunnel {
    fn realm(&self) -> (String, String) {
        let current = realm::current();
        (current.id.clone(), self.registry.base_dn_of(&current))
    }

    /// `autocreateUsers()`: `mode.autoCreates()` and the setting.
    fn creates(&self) -> bool {
        self.mode.predicate("autoCreates").unwrap_or(false)
            && self.settings.value_of("ldap.autocreateUsers").as_bool()
    }

    /// `existingUserEntry(name)`: the `uid` DN under `ou=users`, then the
    /// first person there answering to the name (a `uid` value, a live
    /// pseudonym, the RDN). The scan runs only for a name the direct key
    /// misses — a newcomer or an alias.
    fn existing_user_entry(
        &self,
        realm_id: &str,
        base: &str,
        name: &str,
    ) -> Option<StoredEntry> {
        let wanted = name.trim().to_lowercase();
        if wanted.is_empty() {
            return None;
        }
        let users = format!("ou=users,{}", base).to_lowercase();
        let direct = format!("uid={},{}", wanted, users);
        if let Some(e) = self.live.entry_at(realm_id, &direct) {
            return Some(e);
        }
        let suffix = format!(",{}", users);
        self.live
            .realm_entries(realm_id)
            .into_iter()
            .find(|(k, e)| {
                k.ends_with(&suffix)
                    && !k[..k.len() - suffix.len()].contains(',')
                    && (e
                        .values("uid")
                        .iter()
                        .chain(e.values("stspseudonym"))
                        .any(|v| v.trim().to_lowercase() == wanted)
                        || Directory::username_of_dn(&e.dn).to_lowercase()
                            == wanted)
            })
            .map(|(_, e)| e)
    }

    /// `subjectNameOf()`: the name a `urn:uuid:` subject's person is filed
    /// under in this realm.
    fn name_of_subject(&self, realm_id: &str, subject: &str) -> Option<String> {
        let wanted = subject.trim().to_lowercase();
        let wanted = wanted.strip_prefix("urn:uuid:").unwrap_or(&wanted);
        self.live
            .realm_entries(realm_id)
            .into_values()
            .find(|e| {
                e.first("entryuuid")
                    .is_some_and(|u| u.to_lowercase() == wanted)
            })
            .map(|e| Directory::person_name_of(&e))
            .filter(|n| !n.is_empty())
    }

    fn write(&self, realm_id: &str, entry: StoredEntry) {
        let key = entry.dn.to_lowercase();
        self.live.apply_entry(realm_id, &key, Some(entry));
        self.persistence.directory_changed(Some(&key));
    }

    fn total_entries(&self) -> usize {
        self.registry
            .list()
            .iter()
            .map(|r| self.live.realm_entries(&r.id).len())
            .sum()
    }

    /// `recordAuthentication()`'s identity and its observer call: the
    /// fold, the alias resolved to the name the entry is filed under, and
    /// `autoCreateUser()`. Answers the entry, or `None` where nothing was
    /// created or found.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn observe(&self, record: &Json) -> Option<StoredEntry> {
        let (realm_id, base) = self.realm();
        let resolve = |s: &str| self.name_of_subject(&realm_id, s);
        let presented = text(record, "presented");
        let mut identity = funnel::identity_of(&presented, &resolve);
        if identity.key.is_empty() {
            return None;
        }
        // A live pseudonym is this person (#644): the whole presented
        // string, asked of the directory, replaces the fold.
        if let Some(hit) =
            self.existing_user_entry(&realm_id, &base, &identity.form)
        {
            let filed = Directory::person_name_of(&hit);
            if !filed.is_empty() {
                identity.key = filed.clone();
                identity.name = filed;
                identity.realm = String::new();
            }
        }
        let event = match text(record, "event") {
            e if e.is_empty() => "authentication".to_string(),
            e => e,
        };
        if event != "authentication" && event != "enrolment" {
            return None;
        }
        self.auto_create_user(&realm_id, &base, &identity.key, &event, record)
    }

    /// `autoCreateUser(detail)`.
    fn auto_create_user(
        &self,
        realm_id: &str,
        base: &str,
        name: &str,
        event: &str,
        record: &Json,
    ) -> Option<StoredEntry> {
        let federation = record.get("federation").filter(|f| f.is_object());
        let creates = self.creates();
        if !creates && federation.is_none() {
            tracing::debug!("ldap: LDAP_AUTOCREATE_USERS is off.");
            return None;
        }
        let name = name.trim();
        let protocol = text(record, "protocol");
        let is_client = record.get("isClient") == Some(&Json::Bool(true));
        match funnel::not_a_person(name, &protocol, is_client) {
            None => {}
            Some(NotAPerson::Subject) => {
                tracing::info!(
                    "{}ldap: not creating an entry for \"{}\": it is a \
                     subject identifier naming nobody in this realm's \
                     directory, not a username.",
                    tag(codes::STS_LDAP_0091.as_str()),
                    name
                );
                return None;
            }
            Some(other) => {
                tracing::debug!(
                    "ldap: autoCreateUser() creates nobody for \"{}\" ({:?}).",
                    name,
                    other
                );
                return None;
            }
        }
        let users_dn = format!("ou=users,{}", base);
        let already = self.existing_user_entry(realm_id, base, name);
        let invents =
            self.mode.predicate("inventsClaimValues").unwrap_or(false);
        let resolve = |s: &str| self.name_of_subject(realm_id, s);
        let plan = funnel::name_plan(
            name,
            already.as_ref(),
            &users_dn,
            invents,
            &resolve,
        );
        let existing = self.live.entry_at(realm_id, &plan.dn.to_lowercase());
        let federation_creates = federation
            .and_then(|f| f.get("create"))
            .is_some_and(|c| c == &Json::Bool(true));
        if !creates && !federation_creates {
            // The federated attributes a provisioned entry is given here
            // (`applyFederatedAttributes()`) are federation's, which this
            // runtime does not serve yet.
            return existing;
        }
        if existing.is_none() && federation.is_some() && !federation_creates {
            return None;
        }
        let note = funnel::note_of(event, &protocol);
        let amr: Vec<String> = match record.get("amr") {
            Some(Json::Array(a)) => a
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
            _ => Vec::new(),
        };
        let acr = text(record, "acr");
        let stamp = now();
        if let Some(mut entry) = existing {
            let mut changed =
                funnel::add_values(&mut entry, "description", &[note]);
            for (attribute, value) in &plan.merge {
                if funnel::add_values(
                    &mut entry,
                    attribute,
                    std::slice::from_ref(value),
                ) {
                    changed = true;
                }
            }
            if funnel::apply_authentication_factors(
                &mut entry, &amr, &acr, &stamp,
            ) {
                changed = true;
            }
            if changed {
                entry
                    .attributes
                    .insert("modifytimestamp".into(), vec![stamp]);
                self.write(realm_id, entry.clone());
                tracing::debug!(
                    "ldap: {} records something it did not before.",
                    entry.dn
                );
            }
            return Some(entry);
        }
        let max = self.settings.value_of("ldap.maxEntries").as_int();
        if self.total_entries() as i64 >= max {
            tracing::warn!(
                "{}ldap: not creating {}; the directory holds its maximum of \
                 {} entries.",
                tag(codes::STS_LDAP_0007.as_str()),
                plan.dn,
                max
            );
            return None;
        }
        let mut attributes = plan.attributes.clone();
        attributes.push(("description".into(), vec![note.clone()]));
        let mut tree = Directory::new(&realm::base_dn_of_domain(
            self.settings.value_of("global.domain").as_str(),
        ));
        let r = if realm_id == realm::DEFAULT_ID {
            0
        } else {
            tree.add_realm(realm_id, base);
            tree.realms()
                .iter()
                .position(|t| t.id == realm_id)
                .unwrap_or(0)
        };
        let key = match tree.put_entry(
            r,
            &plan.dn,
            &attributes,
            Some("authentication"),
            None,
        ) {
            Ok(key) => key,
            Err(e) => {
                tracing::warn!(
                    "{}ldap: not creating {} because the directory refused \
                     the entry.",
                    tag(e.code.unwrap_or(codes::STS_LDAP_0211).as_str()),
                    plan.dn
                );
                return None;
            }
        };
        let mut created = tree.get(r, &key).cloned()?;
        funnel::apply_authentication_factors(&mut created, &amr, &acr, &stamp);
        self.write(realm_id, created.clone());
        tracing::info!(
            "audit: user.create {} because {} {} (created by this service, \
             not by an LDAP client; {})",
            created.dn,
            name,
            note,
            if creates {
                "ldap.autocreateUsers is on"
            } else {
                "the federation relationship's fedAutocreateUsers is on"
            }
        );
        Some(created)
    }
}

impl Records for IdentityFunnel {
    fn record_authentication(&self, record: &Json, request: Option<&Request>) {
        self.observe(record);
        if let Some(inner) = &self.inner {
            inner.record_authentication(record, request);
        }
    }

    fn revoke_session_tokens(
        &self,
        sid: &str,
        revokes_access: bool,
        reason: &str,
        opts: &Json,
        tags: &[String],
    ) -> usize {
        match &self.inner {
            Some(inner) => inner.revoke_session_tokens(
                sid,
                revokes_access,
                reason,
                opts,
                tags,
            ),
            None => 0,
        }
    }

    fn record_account_choice(&self, kind: &str, n: Option<u64>) {
        if let Some(inner) = &self.inner {
            inner.record_account_choice(kind, n);
        }
    }
}
