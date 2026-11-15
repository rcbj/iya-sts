// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A REALM IS BUILT WHEN IT IS CREATED (`ldap_server.js`'s
//! `realms.onCreate()` builder; #444, phase 5, the `apis4` slice).
//!
//! Node's builder runs four steps inside the new realm, and they are run
//! here in the same order, from `/admin-api/realms/create`, before the
//! realm's administrator is seeded:
//!
//! 1. `seed()`: the realm's root entry and every container, and in a
//!    development realm (`mode.seedsDemoData()`) the demonstration people
//!    and groups, the remote PEP's and the XACML caller's identities, and
//!    the three groups the `roles.*` settings name;
//! 2. `populateVcAttributes()`: the seeded people's invented claim values,
//!    in development (`mode.inventsClaimValues()`);
//! 3. `applications.seedInternalApplications({ scope: 'every' })`: the
//!    applications that are this service (the console, the portal, the
//!    reports client, the API resources and the API client), then
//!    `fillHostedSessionBounds()` — `sts-registers`' port of both;
//! 4. `roles.seedNativeRoles()`: the native roles and their groups.
//!
//! STEPS 1 AND 2 ARE DATA — prose and fixed values, one shape per mode —
//! read off Node's own builder by `tests/tools/export-realm-seed.js` into
//! `tables/realm_seed.json`, with the realm's base DN and domain as
//! markers; `putEntry()`'s own operational attributes (the timestamps,
//! the `entryUUID` derived from the realm and the DN, the population
//! language) are added by `put_entry()` exactly as Node adds them. The
//! claim values the sweep adds are written with the entry rather than
//! after it, so they sit before the timestamps in the entry's attribute
//! order where Node's sit after; nothing reads that order (an LDAP entry's
//! attributes are a set, RFC 4512 section 2.5). A group named by a
//! `roles.*` setting takes the realm's name for it, and is not made where
//! the setting is empty or carries DN syntax (`STS-LDAP-0041`), as Node
//! does. The default realm's Kerberos trust and trust-anchor container are
//! the default realm's alone and are not in the table.
//!
//! STEP 3'S SPECS ARE NODE'S `internalApplications()`, exported the same
//! way, their URLs written against `@@BASE@@`: the base is
//! `internalBaseUrl()`'s — `global.publicBaseUrl` with the realm's prefix,
//! else this service's own `scheme://localhost:port` (the API resources
//! adding the prefix to that). `@@ISSUED@@` is the instant in seconds and
//! every `@@RANDOM@@` is `randomId(24)`. A hosted application's own
//! listener (`helpers.rebaseTo()`, `listeners.applications`) is not
//! ported in this runtime, so every address is on the base.
//!
//! What a realm's creation also sets off in Node and this runtime does not
//! yet: the realm's certificate-authority branch (`pki.js`'s
//! `ensureScope()`, made on first use instead), its Shared Signals
//! receivers (`ssf_receivers.seedStreams()`) and the listener reconcile.

use std::sync::{Arc, LazyLock, PoisonError};

use serde_json::{json, Value as Json};
use sts_core::errors::codes;
use sts_core::mode::Mode;
use sts_core::realm::{self, RealmRegistry};
use sts_core::settings::Settings;
use sts_registers::applications::ApplicationRegistry;

use super::LiveDir;

/// The table `tests/tools/export-realm-seed.js` writes.
static TABLE: LazyLock<Json> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../tables/realm_seed.json"))
        .unwrap_or_else(|e| {
            tracing::error!(
                "{}admin: tables/realm_seed.json could not be read ({e}); a \
                 realm created here is built without its containers.",
                sts_core::log::tag(codes::STS_CORE_0019)
            );
            Json::Null
        })
});

/// What a realm is built with, and over.
pub struct RealmBuilder {
    pub dir: Arc<LiveDir>,
    pub apps: Arc<ApplicationRegistry>,
    pub roles: Arc<sts_registers::roles::Roles>,
    pub settings: Arc<Settings>,
    pub mode: Arc<Mode>,
    pub registry: Arc<RealmRegistry>,
}

fn values_of(v: &Json) -> Vec<String> {
    match v {
        Json::Array(a) => a
            .iter()
            .map(|x| match x {
                Json::String(s) => s.clone(),
                other => other.to_string(),
            })
            .collect(),
        Json::Null => Vec::new(),
        Json::String(s) => vec![s.clone()],
        other => vec![other.to_string()],
    }
}

// The markers of a seed row's text, replaced.
fn unmarked(text: &str, base: &str, domain: &str) -> String {
    text.replace("@@BASE@@", base).replace("@@DOMAIN@@", domain)
}

// A spec's markers replaced: the base URL, the instant, the random ids.
fn spec_of(value: &Json, base: &str, issued: i64) -> Json {
    match value {
        Json::Array(a) => {
            Json::Array(a.iter().map(|v| spec_of(v, base, issued)).collect())
        }
        Json::Object(o) => Json::Object(
            o.iter()
                .map(|(k, v)| (k.clone(), spec_of(v, base, issued)))
                .collect(),
        ),
        Json::String(s) if s == "@@ISSUED@@" => json!(issued),
        Json::String(s) if s == "@@RANDOM@@" => json!(
            // `randomId(24)`: 24 random bytes, base64url.
            sts_crypto::random::random_token(Some(192)).unwrap_or_default()
        ),
        Json::String(s) => Json::String(s.replace("@@BASE@@", base)),
        other => other.clone(),
    }
}

impl RealmBuilder {
    /// The realm builder's four steps, in the realm.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn build(&self, realm_id: &str) {
        let Some(one) = self.registry.get(realm_id) else {
            return;
        };
        {
            let mut tree =
                self.dir.tree.lock().unwrap_or_else(PoisonError::into_inner);
            if LiveDir::realm_index(&tree, realm_id).is_none() {
                tree.add_realm(realm_id, &self.registry.base_dn_of(&one));
            }
        }
        realm::run_sync(one.clone(), || {
            let seeded = self.seed_directory(realm_id, &one);
            let made = self.seed_applications(realm_id, &one);
            let filled = self.apps.fill_hosted_session_bounds();
            let roles = self.roles.seed_native_roles();
            tracing::info!(
                "ldap: built the \"{}\" realm's subtree at {}: {} seeded \
                 entries, {} of this service's own application(s), {} \
                 hosted session bound(s), {} native role(s).",
                realm_id,
                self.registry.base_dn_of(&one),
                seeded,
                made,
                filled,
                roles
            );
        });
    }

    // `seed()` and `populateVcAttributes()` (see the module comment).
    fn seed_directory(&self, realm_id: &str, one: &realm::Realm) -> usize {
        let product = self.mode.current() == "product";
        let rows = TABLE["seed"]
            [if product { "product" } else { "development" }]
        .as_array()
        .cloned()
        .unwrap_or_default();
        let base = self.registry.base_dn_of(one);
        let domain = self.registry.domain_of(one);
        let mut tree =
            self.dir.tree.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(r) = LiveDir::realm_index(&tree, realm_id) else {
            return 0;
        };
        let mut seeded = 0;
        for row in rows {
            let mut dn =
                unmarked(row["dn"].as_str().unwrap_or(""), &base, &domain);
            let mut attributes: Vec<(String, Vec<String>)> = Vec::new();
            for part in ["attributes", "after"] {
                if let Some(o) = row[part].as_object() {
                    for (k, v) in o {
                        attributes.push((
                            k.clone(),
                            values_of(v)
                                .iter()
                                .map(|x| unmarked(x, &base, &domain))
                                .collect(),
                        ));
                    }
                }
            }
            // A group a `roles.*` setting names, under the realm's name.
            if let Some(key) = row["setting"].as_str() {
                let name =
                    self.settings.value_of(key).as_str().trim().to_string();
                if name.is_empty() {
                    continue;
                }
                if !sts_ldap::service_dn::name_usable_in_dn(Some(&name)) {
                    tracing::warn!(
                        "{}ldap: {} is \"{}\", which carries DN syntax, so \
                         no group was seeded for it.",
                        sts_core::log::tag(codes::STS_LDAP_0041),
                        key,
                        name
                    );
                    continue;
                }
                dn = format!("cn={name},ou=groups,{base}");
                for (k, v) in attributes.iter_mut() {
                    if k == "cn" {
                        *v = vec![name.clone()];
                    }
                }
            }
            match tree.put_entry(r, &dn, &attributes, Some("seed"), None) {
                Ok(_) => seeded += 1,
                Err(e) => tracing::warn!(
                    "ldap: {} was not seeded in \"{}\": {}",
                    dn,
                    realm_id,
                    e.message
                ),
            }
        }
        seeded
    }

    // `seedInternalApplications({ scope: 'every' })`.
    fn seed_applications(&self, realm_id: &str, one: &realm::Realm) -> usize {
        if !self
            .settings
            .value_of("applications.seedInternal")
            .as_bool()
        {
            tracing::info!(
                "applications: the console and the management API were not \
                 seeded as applications; applications.seedInternal is off."
            );
            return 0;
        }
        let prefix = self.registry.prefix_of(one);
        let pinned = self
            .settings
            .value_of("global.publicBaseUrl")
            .as_str()
            .trim()
            .trim_end_matches('/')
            .to_string();
        // `internalBaseUrl()` and `apiResourceApplications()`'s
        // `realmBase`.
        let (base, api_base) = if pinned.is_empty() {
            let own = format!(
                "{}://localhost:{}",
                if self.settings.value_of("global.https").as_bool() {
                    "https"
                } else {
                    "http"
                },
                self.settings.value_of("global.port").as_int()
            );
            (own.clone(), format!("{own}{prefix}"))
        } else {
            let b = format!("{pinned}{prefix}");
            (b.clone(), b)
        };
        let issued = chrono::Utc::now().timestamp();
        let specs = TABLE["applications"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let mut made = 0;
        for spec in &specs {
            let resource = spec["kinds"].as_array().is_some_and(|k| {
                k.iter().any(|x| x == "oauth2-resource-server")
            });
            let filled =
                spec_of(spec, if resource { &api_base } else { &base }, issued);
            if self.apps.seed_internal_application(&filled) {
                made += 1;
            }
        }
        tracing::info!(
            "applications: {} of this service's own {} application(s) were \
             seeded into the \"{}\" realm. They are ORDINARY entries — edit \
             one, or delete it, and it stays that way until a restart.",
            made,
            specs.len(),
            realm_id
        );
        made
    }
}
