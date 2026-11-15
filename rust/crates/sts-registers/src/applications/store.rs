// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `ou=applications` AS A STORE: the functions `ldap/ldap_server.js` fills
//! `applications.setDirectory()` with — `readApplication()`,
//! `writeApplication()`, `allApplications()`, `applicationCount()`,
//! `deleteApplicationEntry()`, `resolveServiceAccountOwner()`,
//! `containerDn()` and `maxApplications()` — over
//! [`sts_directory::Directory`] directly (rule 3g: the directory owns WHERE
//! an entry lives, how it is created and what the cap is; the register
//! owns what an entry IS).
//!
//! An entry is answered as `entryObject()` builds it: every attribute
//! under its canonical spelling, sorted by lower-cased name, `entryDN`
//! added, with the row's `origin`, `createdAt` and `modifiedAt`.

use serde_json::{json, Map, Value};
use sts_core::errors::codes;
use sts_directory::directory::OPERATIONAL;
use sts_directory::{Directory, DirectoryModel, Entry, EntryExt};
use sts_ldap::service_dn::{escape_dn_value, is_under, normalize_dn};

use super::record::{generalized_time, label_for_with};
use super::{AppEffects, ApplicationRegistry};

/// `entryObject(stored)`: the entry as `readApplication()` answers it.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredApplication {
    pub dn: String,
    pub origin: String,
    pub created_at: Value,
    pub modified_at: Value,
    pub operational: Vec<String>,
    /// Canonical spelling to values, in lower-cased name order.
    pub attributes: Map<String, Value>,
}

impl StoredApplication {
    // `entryObject()`.
    fn of(stored: &Entry) -> StoredApplication {
        let model = DirectoryModel::get();
        let mut names: Vec<&String> = stored.attributes.keys().collect();
        names.sort();
        let mut attributes = Map::new();
        for name in names {
            let values = stored.values(name);
            attributes.insert(
                model.canonical_name(name),
                Value::Array(
                    values.iter().cloned().map(Value::String).collect(),
                ),
            );
        }
        attributes.insert(
            model.canonical_name("entrydn"),
            json!([stored.dn.clone()]),
        );
        StoredApplication {
            dn: stored.dn.clone(),
            origin: stored
                .origin
                .clone()
                .unwrap_or_else(|| "unstated".to_string()),
            created_at: stored
                .created_at
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
            modified_at: stored
                .modified_at
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
            operational: OPERATIONAL
                .iter()
                .map(|n| model.canonical_name(n))
                .collect(),
            attributes,
        }
    }

    /// The entry as JSON, the shape `view()` reads.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn to_json(&self) -> Value {
        json!({
            "dn": self.dn,
            "origin": self.origin,
            "createdAt": self.created_at,
            "modifiedAt": self.modified_at,
            "operational": self.operational,
            "attributes": self.attributes,
        })
    }
}

/// `resolveServiceAccountOwner(value)`: `{kind, dn, name}`, `kind` ''
/// for nobody.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Owner {
    pub kind: String,
    pub dn: String,
    pub name: String,
}

impl ApplicationRegistry {
    // The ambient realm's tree, by index.
    pub(crate) fn realm_index(dir: &Directory) -> Option<usize> {
        let id = sts_core::realm::current_id();
        dir.realms().iter().position(|t| t.id == id)
    }

    /// `shortName(identifier)` and `labelFor()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn label_for(&self, identifier: &str) -> String {
        label_for_with(identifier, |id| {
            let hex = self.env.sha256_hex(id);
            format!("app-{}", &hex[..12.min(hex.len())])
        })
    }

    fn applications_dn(dir: &Directory, r: usize) -> String {
        format!("ou=applications,{}", dir.realms()[r].base)
    }

    fn application_dn(&self, dir: &Directory, r: usize, id: &str) -> String {
        format!(
            "cn={},{}",
            escape_dn_value(Some(&self.label_for(id))),
            Self::applications_dn(dir, r)
        )
    }

    // `entriesUnder(applicationsDn())`, in the store's order.
    fn entries_under(dir: &Directory, r: usize) -> Vec<&Entry> {
        let base = Self::applications_dn(dir, r);
        let key = normalize_dn(Some(&base));
        dir.realms()[r]
            .entries
            .values()
            .filter(|e| {
                is_under(Some(&e.dn), Some(&base))
                    && normalize_dn(Some(&e.dn)) != key
            })
            .collect()
    }

    // `applicationEntry(identifier)`: at its DN, then the first entry
    // under the container whose `appIdentifier` is the identifier (an
    // entry somebody renamed with an ldapmodrdn).
    fn application_entry<'d>(
        &self,
        dir: &'d Directory,
        r: usize,
        identifier: &str,
    ) -> Option<&'d Entry> {
        if let Some(direct) =
            dir.get(r, &self.application_dn(dir, r, identifier))
        {
            return Some(direct);
        }
        Self::entries_under(dir, r)
            .into_iter()
            .find(|e| e.first("appidentifier") == Some(identifier))
    }

    /// `readApplication(identifier)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn read_application(
        &self,
        identifier: &str,
    ) -> Option<StoredApplication> {
        let dir = self.directory.as_ref()?.lock().ok()?;
        let r = Self::realm_index(&dir)?;
        self.application_entry(&dir, r, identifier)
            .map(StoredApplication::of)
    }

    /// `allApplications()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn all_applications(&self) -> Vec<StoredApplication> {
        let Some(dir) = self.directory.as_ref().and_then(|d| d.lock().ok())
        else {
            return Vec::new();
        };
        let Some(r) = Self::realm_index(&dir) else {
            return Vec::new();
        };
        Self::entries_under(&dir, r)
            .into_iter()
            .map(StoredApplication::of)
            .collect()
    }

    /// `applicationCount()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn count(&self) -> usize {
        let Some(dir) = self.directory.as_ref().and_then(|d| d.lock().ok())
        else {
            return 0;
        };
        Self::realm_index(&dir)
            .map(|r| Self::entries_under(&dir, r).len())
            .unwrap_or(0)
    }

    /// `containerDn()`: the realm's `ou=applications`, or None.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn container_dn(&self) -> Option<String> {
        let dir = self.directory.as_ref()?.lock().ok()?;
        let r = Self::realm_index(&dir)?;
        Some(Self::applications_dn(&dir, r))
    }

    /// `maxApplications()`: `applications.max`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn max_applications(&self) -> Option<i64> {
        self.directory.as_ref()?;
        self.env.setting("applications.max").as_i64()
    }

    /// `writeApplication(identifier, attributes, {owned})`: the entry
    /// created or replaced, every attribute this register does not own
    /// kept from the entry already there. `false` (and a warning) when the
    /// container or the directory is full, or the directory refuses it.
    #[tracing::instrument(level = "debug", skip(self, attributes, owned))]
    pub fn write_application(
        &self,
        identifier: &str,
        attributes: &[(String, Vec<String>)],
        owned: &[String],
    ) -> bool {
        let Some(mut dir) = self.directory.as_ref().and_then(|d| d.lock().ok())
        else {
            return false;
        };
        let Some(r) = Self::realm_index(&dir) else {
            return false;
        };
        let existing = self.application_entry(&dir, r, identifier).cloned();
        let dn = existing
            .as_ref()
            .map(|e| e.dn.clone())
            .unwrap_or_else(|| self.application_dn(&dir, r, identifier));
        let max = self.env.setting("applications.max").as_i64().unwrap_or(0);
        if existing.is_none()
            && Self::entries_under(&dir, r).len() as i64 >= max
        {
            tracing::warn!(
                "{}ldap: not creating {}; ou=applications holds its maximum \
                 of {} entry/entries (applications.max). The application \
                 itself is unaffected — it simply goes unrecorded.",
                sts_core::log::tag(codes::STS_LDAP_0035),
                dn,
                max
            );
            return false;
        }
        let total: usize = dir.realms().iter().map(|t| t.entries.len()).sum();
        let ceiling = self.env.setting("ldap.maxEntries").as_i64().unwrap_or(0);
        if existing.is_none() && total as i64 >= ceiling {
            tracing::warn!(
                "{}ldap: not creating {}; the directory holds its maximum \
                 of {} entries.",
                sts_core::log::tag(codes::STS_LDAP_0007),
                dn,
                ceiling
            );
            return false;
        }
        let written = match &existing {
            Some(e) => with_unowned(e, attributes, owned),
            None => attributes.to_vec(),
        };
        let now = self.env.now_ms();
        let created = existing
            .as_ref()
            .and_then(|e| e.created_at.clone())
            .unwrap_or_else(|| generalized_time(0, now));
        let origin = existing
            .as_ref()
            .and_then(|e| e.origin.clone())
            .unwrap_or_else(|| "application".to_string());
        if let Err(e) = dir.put_entry(r, &dn, &written, Some(&origin), None) {
            tracing::debug!("the directory refused {}: {}", dn, e.message);
            return false;
        }
        dir.restamp_created(r, &dn, &created);
        drop(dir);
        let mut names: Vec<String> =
            attributes.iter().map(|(n, _)| n.clone()).collect();
        names.sort();
        audit_directory(
            self.effects.as_ref(),
            if existing.is_some() {
                "entry.update"
            } else {
                "entry.create"
            },
            &dn,
            &names,
            existing.is_none(),
        );
        true
    }

    /// `deleteApplicationEntry(identifier)`: `false` when it was not there.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn delete_application_entry(&self, identifier: &str) -> bool {
        let Some(mut dir) = self.directory.as_ref().and_then(|d| d.lock().ok())
        else {
            return false;
        };
        let Some(r) = Self::realm_index(&dir) else {
            return false;
        };
        let Some(dn) = self
            .application_entry(&dir, r, identifier)
            .map(|e| e.dn.clone())
        else {
            return false;
        };
        let Some(stored) = dir.remove_entry(r, &dn, "the application registry")
        else {
            return false;
        };
        drop(dir);
        let mut names: Vec<String> =
            stored.attributes.keys().cloned().collect();
        names.sort();
        audit_directory(
            self.effects.as_ref(),
            "entry.delete",
            &stored.dn,
            &names,
            false,
        );
        // `noteApplicationRemoved(stored, 'the application registry')`.
        if let Some(id) =
            stored.first("appidentifier").filter(|i| !i.is_empty())
        {
            self.effects.application_removed(
                id,
                &stored.dn,
                "the application registry",
            );
        }
        true
    }

    /// `resolveServiceAccountOwner(value)`: a person (username, DN,
    /// subject) or a group (its cn or DN) of the realm.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn resolve_owner(&self, value: &str) -> Owner {
        let Some(dir) = self.directory.as_ref().and_then(|d| d.lock().ok())
        else {
            return Owner::default();
        };
        let Some(r) = Self::realm_index(&dir) else {
            return Owner::default();
        };
        let text = crate::js::trim(value);
        let groups = dir.groups_dn(r);
        let mut stored = if text.is_empty() {
            None
        } else {
            dir.locate(r, text)
        };
        if stored.is_none()
            && !text.is_empty()
            && !sts_directory::uuid::dn_shaped(text)
        {
            stored = dir.get(
                r,
                &format!("cn={},{}", escape_dn_value(Some(text)), groups),
            );
        }
        let Some(stored) = stored else {
            return Owner::default();
        };
        if dir.is_person_dn(r, &stored.dn) {
            return Owner {
                kind: "person".into(),
                dn: stored.dn.clone(),
                name: Directory::username_of_dn(&stored.dn),
            };
        }
        if is_under(Some(&stored.dn), Some(&groups))
            && normalize_dn(Some(&stored.dn)) != normalize_dn(Some(&groups))
        {
            return Owner {
                kind: "group".into(),
                dn: stored.dn.clone(),
                name: stored.first("cn").unwrap_or("").to_string(),
            };
        }
        Owner {
            kind: String::new(),
            dn: stored.dn.clone(),
            name: String::new(),
        }
    }
}

// `withUnownedAttributes(existing, attributes, owned)`: what the register
// writes, then every attribute it does not own, kept as it was.
fn with_unowned(
    existing: &Entry,
    attributes: &[(String, Vec<String>)],
    owned: &[String],
) -> Vec<(String, Vec<String>)> {
    let owned: Vec<String> = owned
        .iter()
        .map(|n| n.split(';').next().unwrap_or("").to_lowercase())
        .collect();
    let given: Vec<String> =
        attributes.iter().map(|(n, _)| n.to_lowercase()).collect();
    let mut out = attributes.to_vec();
    for (name, values) in &existing.attributes {
        let lower = name.to_lowercase();
        let base = lower.split(';').next().unwrap_or("").to_string();
        if owned.contains(&base)
            || given.contains(&lower)
            || OPERATIONAL.contains(&lower.as_str())
        {
            continue;
        }
        if !values.is_empty() {
            out.push((lower, values.clone()));
        }
    }
    out
}

// `auditDirectory(action, dn, attributes, created)`.
fn audit_directory(
    effects: &dyn AppEffects,
    action: &str,
    dn: &str,
    names: &[String],
    created: bool,
) {
    let verb = if action == "entry.delete" {
        "deleted"
    } else if created {
        "created"
    } else {
        "updated"
    };
    effects.audit(&json!({
        "action": action,
        "actor": "",
        "protocol": "LDAP",
        "channel": "internal",
        "target": dn,
        "summary": format!("The application entry {} was {}", dn, verb),
        "detail": { "attributes": names.join(", ") },
    }));
}
