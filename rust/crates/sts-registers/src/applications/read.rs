// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE READS: `view()`, `get()`, `list()`, the listing and its indexes
//! (`buildListing()`), and the questions every protocol puts to the
//! register — which entry a `client_id` (`forClientId()`,
//! `everyForClientId()`), an audience (`forAudience()`), an `AppliesTo` or
//! an entityID (`forAppliesTo()`), a service principal name
//! (`forServicePrincipal()`) or a permission (`forPermission()`,
//! `forPermissionBase()`) names; the identifier itself is `get()` (a
//! wtrealm, an entityID and a client_id are each the identifier of the
//! entry their sighting filed); `settingFor()` and its override table; the
//! required roles; `applicationsNamingPolicy()`; `ownerValues()`;
//! `applicationsEnforcingFga()` and `applicationsDeclaredFor()`.

use serde_json::{json, Map, Value};
use sts_core::errors::codes;

use super::checks::SEALED_FIELDS;
use super::record::{first_of, iso_string, values_of, Fields, Record};
use super::store::StoredApplication;
use super::tables::Tables;
use super::write::{declared_families_of, observed_return_addresses};
use super::ApplicationRegistry;

/// `WITHHELD_FIELDS`: what a view never shows of an entry.
pub const WITHHELD_FIELDS: &[&str] = &[
    "krb5ServiceKeys",
    "appEnrolledPrivateKey",
    "appAcmeEabKey",
    "appScepChallenge",
    "secretDestCredential",
    "scimClientPassword",
    "scimClientOAuthClientSecret",
    "scimClientTlsPrivateKey",
];

/// `POLICY_REFERENCES`: the attributes naming a policy profile.
pub const POLICY_REFERENCES: &[&str] = &[
    "appAuthnPolicy",
    "appPasskeyPolicy",
    "appLocalePolicy",
    "appPostLoginPolicy",
    "appAttributePolicy",
];

// `withheldSentence(value, name)`.
fn withheld_sentence(value: &str, name: &str) -> String {
    match name {
        "secretDestCredential" => "(withheld: a secret destination's write \
                                   credential, set, never shown)"
            .to_string(),
        "scimClientPassword"
        | "scimClientOAuthClientSecret"
        | "scimClientTlsPrivateKey" => {
            "(withheld: a SCIM client credential, set, never shown)"
                .to_string()
        }
        _ => format!(
            "(withheld: Kerberos key material, {} characters, never shown)",
            crate::js::len_utf16(value)
        ),
    }
}

/// `withholdFields(fields)`: every withheld attribute's values replaced by
/// the sentence saying what was there.
#[tracing::instrument(level = "debug", skip_all)]
pub fn withhold_fields(fields: &Map<String, Value>) -> Map<String, Value> {
    let mut out = fields.clone();
    for name in WITHHELD_FIELDS {
        let Some(v) = out.get(*name).cloned() else {
            continue;
        };
        let replaced = match v {
            Value::Array(list) => Value::Array(
                list.iter()
                    .map(|one| {
                        Value::String(withheld_sentence(
                            &crate::js::string(one),
                            name,
                        ))
                    })
                    .collect(),
            ),
            other => Value::String(withheld_sentence(
                &crate::js::string(&other),
                name,
            )),
        };
        out.insert((*name).to_string(), replaced);
    }
    out
}

/// `declaredKindsOf(fields)`: the kinds the declared families stand for.
#[tracing::instrument(level = "debug", skip_all)]
pub fn declared_kinds_of(fields: &Fields) -> Vec<String> {
    let t = Tables::get();
    let mut out: Vec<String> = Vec::new();
    for id in values_of(fields.get("appAllowedProtocol")) {
        if let Some(row) = t.protocol(&id) {
            if !row.kind.is_empty() && !out.iter().any(|k| k == row.kind) {
                out.push(row.kind.to_string());
            }
        }
    }
    out
}

/// `requiredRolesFrom(source)`: the roles a person must hold to be
/// issued anything for it, `EVERYBODY` by default.
#[tracing::instrument(level = "debug", skip_all)]
pub fn required_roles_from(fields: Option<&Fields>) -> Vec<String> {
    let values: Vec<String> = fields
        .map(|f| {
            values_of(f.get("appRequiredRole"))
                .iter()
                .map(|one| crate::js::trim(one).to_string())
                .filter(|one| !one.is_empty())
                .collect()
        })
        .unwrap_or_default();
    if values.is_empty() {
        vec![crate::roles::DEFAULT_REQUIRED_ROLE.to_string()]
    } else {
        values
    }
}

/// `narrowedRoles(required)`.
#[tracing::instrument(level = "debug")]
pub fn narrowed_roles(required: &[String]) -> bool {
    !(required.len() == 1 && required[0] == crate::roles::DEFAULT_REQUIRED_ROLE)
}

/// One application of the listing: its entry and its record.
#[derive(Debug, Clone)]
pub struct Item {
    pub entry: StoredApplication,
    pub record: Record,
}

impl ApplicationRegistry {
    // `openSealedFields(fields, identifier)`: what a view shows of a sealed
    // value is the value opened, where it opens.
    fn open_sealed_fields(&self, fields: &Fields, identifier: &str) -> Fields {
        let mut out = fields.clone();
        if let Some(Value::String(token)) = out.get("appRegistrationAccessToken")
        {
            if self.env.is_sealed(token) {
                let opened = self.registration_access_token_of(fields);
                let shown = if opened.is_empty() {
                    token.clone()
                } else {
                    opened
                };
                out.insert("appRegistrationAccessToken".into(), json!(shown));
            }
        }
        if let Some(Value::Array(secrets)) = out.get("oauthClientSecret").cloned()
        {
            let any = secrets
                .iter()
                .any(|v| self.env.is_sealed(&crate::js::string(v)));
            if any {
                let opened: Vec<Value> = secrets
                    .iter()
                    .map(|v| {
                        let s = crate::js::string(v);
                        if self.env.is_sealed(&s) {
                            let o =
                                self.open_credential_text(&s, "client-secret");
                            Value::String(if o.is_empty() { s } else { o })
                        } else {
                            v.clone()
                        }
                    })
                    .collect();
                out.insert("oauthClientSecret".into(), Value::Array(opened));
            }
        }
        for name in SEALED_FIELDS {
            let Some(Value::String(v)) = out.get(*name).cloned() else {
                continue;
            };
            if v.is_empty() || !self.env.is_sealed(&v) {
                continue;
            }
            let label = super::checks::seal_label_of(name);
            let opened = match self.env.open(&v, label) {
                Some(o) => o,
                None => {
                    tracing::warn!(
                        "{}applications: the private key on \"{}\" is sealed \
                         and will not open under this process's \
                         key-encryption key.",
                        sts_core::log::tag(codes::STS_REG_0023),
                        identifier
                    );
                    v
                }
            };
            out.insert((*name).to_string(), Value::String(opened));
        }
        out
    }

    /// `view(record, entry)`: what every page and the API show of an
    /// application.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn view(&self, record: &Record, entry: Option<&StoredApplication>) -> Value {
        let t = Tables::get();
        let observed: Vec<Value> = observed_return_addresses(&record.fields)
            .into_iter()
            .map(|row| {
                let registered = self
                    .return_addresses_of(&record.fields, &row.attribute);
                let trusted = row.held
                    && registered
                        .get("registered")
                        .and_then(Value::as_array)
                        .is_some_and(|l| {
                            l.contains(&Value::String(row.value.clone()))
                        });
                json!({ "attribute": row.attribute, "value": row.value,
                        "held": row.held, "trusted": trusted })
            })
            .collect();
        let registered_by = {
            let by = crate::js::or_empty(record.fields.get("appRegisteredBy"));
            if by.is_empty() && record.registered {
                "rfc7591".to_string()
            } else {
                by
            }
        };
        let mut fields =
            self.open_sealed_fields(&withhold_fields(&record.fields), &record.identifier);
        if !record.description.is_empty() {
            fields.insert("description".into(), json!(record.description));
        }
        let e = entry.map(StoredApplication::to_json);
        json!({
            "identifier": record.identifier,
            "dnLabel": record.label,
            "dn": e.as_ref().map(|e| e["dn"].clone()).unwrap_or(Value::Null),
            "name": record.name,
            "kinds": record.kinds,
            "protocols": record.protocols,
            "allowedProtocols": values_of(record.fields.get("appAllowedProtocol")),
            "recordedProtocols": t.protocol_ids_for_kinds(&record.kinds),
            "declaredKinds": declared_kinds_of(&record.fields),
            "registeredBy": registered_by,
            "returnAddressesObserved": observed,
            "registered": record.registered,
            "firstSeen": if record.first_at != 0 {
                iso_string(record.first_at)
            } else {
                String::new()
            },
            "lastSeen": if record.last_at != 0 {
                iso_string(record.last_at)
            } else {
                String::new()
            },
            "authentications": record.authentications,
            "sessions": record.session_count,
            "users": record.user_count,
            "description": record.description,
            "origin": e.as_ref().map(|e| e["origin"].clone()).unwrap_or(Value::Null),
            "createdAt": e.as_ref().map(|e| e["createdAt"].clone())
                .unwrap_or(Value::Null),
            "modifiedAt": e.as_ref().map(|e| e["modifiedAt"].clone())
                .unwrap_or(Value::Null),
            "operational": e.as_ref().map(|e| e["operational"].clone())
                .unwrap_or_else(|| json!([])),
            "attributes": entry
                .map(|e| Value::Object(withhold_fields(&e.attributes)))
                .unwrap_or_else(|| json!({})),
            "fields": Value::Object(fields),
        })
    }

    /// `get(identifier)`: the view, or None.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn get(&self, identifier: &str) -> Option<Value> {
        let loaded = self.load(identifier);
        if loaded.known {
            Some(self.view(&loaded.record, loaded.entry.as_ref()))
        } else {
            None
        }
    }

    /// `buildListing()`'s items: every entry under the container, most
    /// recently seen first.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn listing(&self) -> Vec<Item> {
        let mut items: Vec<(String, Item)> = self
            .all_applications()
            .into_iter()
            .map(|entry| {
                let record = Record::from_attributes(&entry.attributes);
                let last = if record.last_at != 0 {
                    iso_string(record.last_at)
                } else {
                    String::new()
                };
                (last, Item { entry, record })
            })
            .collect();
        // `String(b.lastSeen).localeCompare(String(a.lastSeen))`, stable.
        items.sort_by(|a, b| crate::js::locale_compare(&b.0, &a.0));
        items.into_iter().map(|(_, i)| i).collect()
    }

    pub(crate) fn listing_records(&self) -> Vec<Record> {
        self.listing().into_iter().map(|i| i.record).collect()
    }

    /// `list()`: every application's view, most recently seen first.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn list(&self) -> Vec<Value> {
        self.listing()
            .iter()
            .map(|i| self.view(&i.record, Some(&i.entry)))
            .collect()
    }

    // `lookedUp(index, wanted)`: the views of every item whose
    // `attribute` holds the value, in listing order.
    fn looked_up(&self, attribute: &str, wanted: &str) -> Vec<Value> {
        self.listing()
            .iter()
            .filter(|i| {
                values_of(i.record.fields.get(attribute))
                    .iter()
                    .any(|v| v == wanted)
            })
            .map(|i| self.view(&i.record, Some(&i.entry)))
            .collect()
    }

    fn warn_shared(found: &[Value], what: &str, wanted: &str) {
        if found.len() > 1 {
            let ids: Vec<String> = found
                .iter()
                .map(|r| crate::js::or_empty(r.get("identifier")))
                .collect();
            tracing::warn!(
                "{}applications: {} applications have registered {} \"{}\" \
                 ({}).",
                sts_core::log::tag(codes::STS_REG_0026),
                found.len(),
                what,
                wanted,
                ids.join(", ")
            );
        }
    }

    /// `forClientId(clientId)`: the entry whose `oauthClientId` is it.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn for_client_id(&self, client_id: &str) -> Option<Value> {
        let wanted = crate::js::trim(client_id);
        if wanted.is_empty() {
            return None;
        }
        let found = self.looked_up("oauthClientId", wanted);
        Self::warn_shared(&found, "the client_id", wanted);
        found.into_iter().next()
    }

    /// `everyForClientId(clientId)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn every_for_client_id(&self, client_id: &str) -> Vec<Value> {
        let wanted = crate::js::trim(client_id);
        if wanted.is_empty() {
            return Vec::new();
        }
        self.looked_up("oauthClientId", wanted)
    }

    /// `forAudience(audience)`: the entry whose `oauthAudience` is it.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn for_audience(&self, audience: &str) -> Option<Value> {
        let wanted = crate::js::trim(audience);
        if wanted.is_empty() {
            return None;
        }
        let found = self.looked_up("oauthAudience", wanted);
        Self::warn_shared(&found, "the audience", wanted);
        found.into_iter().next()
    }

    /// `forAppliesTo(appliesTo)`: the entry whose `wstrustAppliesTo`, then
    /// whose `samlEntityId`, is it — an entry named by the value itself
    /// left out — with `matchedAttribute`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn for_applies_to(&self, applies_to: &str) -> Option<Value> {
        let wanted = crate::js::trim(applies_to);
        if wanted.is_empty() {
            return None;
        }
        for attribute in ["wstrustAppliesTo", "samlEntityId"] {
            let found: Vec<Value> = self
                .looked_up(attribute, wanted)
                .into_iter()
                .filter(|row| {
                    row.get("identifier").and_then(Value::as_str) != Some(wanted)
                })
                .collect();
            if found.is_empty() {
                continue;
            }
            Self::warn_shared(&found, "the AppliesTo", wanted);
            let mut first = found.into_iter().next().unwrap_or(Value::Null);
            if let Some(o) = first.as_object_mut() {
                o.insert("matchedAttribute".into(), json!(attribute));
            }
            return Some(first);
        }
        None
    }

    /// `forServicePrincipal(spn)`: the entry whose
    /// `krb5ServicePrincipalName` is it.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn for_service_principal(&self, spn: &str) -> Option<Value> {
        let wanted = crate::js::trim(spn);
        if wanted.is_empty() {
            return None;
        }
        let found = self.looked_up("krb5ServicePrincipalName", wanted);
        Self::warn_shared(&found, "the SPN", wanted);
        found.into_iter().next()
    }

    /// `forPermission(id)`: the application defining a permission, by its
    /// full identifier — the first entry, in listing order, that defines
    /// it.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn for_permission(&self, id: &str) -> Option<Value> {
        let wanted = crate::js::trim(id);
        if wanted.is_empty() {
            return None;
        }
        for item in self.listing() {
            let fields = json!({ "fields": item.record.fields });
            let permissions = crate::app_permissions::permissions_of(&fields);
            let Some(hit) = permissions.iter().find(|p| {
                p.get("id").and_then(Value::as_str) == Some(wanted)
            }) else {
                continue;
            };
            let row = self.view(&item.record, Some(&item.entry));
            let base = crate::app_permissions::permission_base_of(
                row["fields"].get("oauthPermissionBaseUri"),
            );
            return Some(json!({
                "identifier": row["identifier"],
                "application": row,
                "baseUri": base,
                "name": hit.get("name").cloned().unwrap_or(Value::Null),
                "description":
                    hit.get("description").cloned().unwrap_or(Value::Null),
                "id": hit.get("id").cloned().unwrap_or(Value::Null),
            }));
        }
        None
    }

    /// `roleGatingFor(id)`: `forPermission()` and whether the permission is
    /// gated by role.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn role_gating_for(&self, id: &str) -> Option<Value> {
        let mut found = self.for_permission(id)?;
        let name = crate::js::or_empty(found.get("name"));
        let gated = values_of(
            found["application"]["fields"].get("oauthRoleGatedPermission"),
        )
        .contains(&name);
        let mut out = Map::new();
        out.insert("gated".into(), Value::Bool(gated));
        if let Some(o) = found.as_object_mut() {
            for (k, v) in o.iter() {
                out.insert(k.clone(), v.clone());
            }
        }
        Some(Value::Object(out))
    }

    /// `forPermissionBase(base)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn for_permission_base(&self, base: &str) -> Option<Value> {
        let wanted =
            crate::app_permissions::permission_base_of(Some(&json!(base)));
        if wanted.is_empty() {
            return None;
        }
        let found: Vec<Value> = self
            .listing()
            .iter()
            .filter(|i| {
                crate::app_permissions::permission_base_of(
                    i.record.fields.get("oauthPermissionBaseUri"),
                ) == wanted
            })
            .map(|i| self.view(&i.record, Some(&i.entry)))
            .collect();
        Self::warn_shared(&found, "the base URI", &wanted);
        found.into_iter().next()
    }

    // `forClientId(who) || get(who)`.
    fn client_or_identifier(&self, who: &str) -> Option<Value> {
        let who = crate::js::trim(who);
        if who.is_empty() {
            return None;
        }
        self.for_client_id(who).or_else(|| self.get(who))
    }

    /// `holdsPermission(clientId, id)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn holds_permission(&self, client_id: &str, id: &str) -> bool {
        let wanted = crate::js::trim(id);
        if wanted.is_empty() || crate::js::trim(client_id).is_empty() {
            return false;
        }
        self.client_or_identifier(client_id).is_some_and(|f| {
            values_of(f["fields"].get("oauthDelegatedPermission"))
                .iter()
                .any(|v| v == wanted)
        })
    }

    /// `allowedScopesOf(clientId)`: None when it declares none.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn allowed_scopes_of(&self, client_id: &str) -> Option<Vec<String>> {
        let found = self.client_or_identifier(client_id)?;
        let held: Vec<String> = values_of(found["fields"].get("oauthAllowedScope"))
            .iter()
            .map(|one| crate::js::trim(one).to_string())
            .filter(|one| !one.is_empty())
            .collect();
        if held.is_empty() {
            None
        } else {
            Some(held)
        }
    }

    /// `isResourceServer(clientId)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn is_resource_server(&self, client_id: &str) -> bool {
        self.client_or_identifier(client_id).is_some_and(|e| {
            let kinds = crate::js::strings(e.get("kinds"));
            kinds.iter().any(|k| k == "oauth2-resource-server")
                && !kinds.iter().any(|k| k == "oauth2-client")
        })
    }

    /// `nativeSsoOf(clientId)`: `{enabled, group}`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn native_sso_of(&self, client_id: &str) -> Value {
        let fields = self
            .client_or_identifier(client_id)
            .and_then(|f| f["fields"].as_object().cloned())
            .unwrap_or_default();
        let flag = first_of(&fields, "oauthNativeSso").to_uppercase() == "TRUE";
        let group = crate::js::trim(&first_of(&fields, "oauthNativeSsoGroup"))
            .to_string();
        let shaped = !group.is_empty()
            && crate::js::len_utf16(&group) <= 64
            && group.chars().all(|c| {
                c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-')
            });
        let enabled = flag && shaped;
        json!({ "enabled": enabled, "group": if enabled { group } else { String::new() } })
    }

    /// `httpSignaturesOf(clientId)`: `{known, required, fields}`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn http_signatures_of(&self, client_id: &str) -> Value {
        let found = self.client_or_identifier(client_id);
        let fields = found
            .as_ref()
            .and_then(|f| f["fields"].as_object().cloned())
            .unwrap_or_default();
        let required =
            first_of(&fields, "oauthHttpSignedRequests").to_uppercase() == "TRUE";
        json!({ "known": found.is_some(), "required": required,
                "fields": Value::Object(fields) })
    }

    /// `didClaimWithPairwiseOf(clientId)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn did_claim_with_pairwise_of(&self, client_id: &str) -> bool {
        let fields = self
            .client_or_identifier(client_id)
            .and_then(|f| f["fields"].as_object().cloned())
            .unwrap_or_default();
        crate::js::trim(&first_of(&fields, "oauthDidClaimWithPairwise"))
            .to_uppercase()
            == "TRUE"
    }

    /// `requiredRolesOf(identifier)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn required_roles_of(&self, identifier: &str) -> Vec<String> {
        let loaded = self.load(identifier);
        required_roles_from(loaded.known.then_some(&loaded.record.fields))
    }

    /// `requiresNarrowedRoles(identifier)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn requires_narrowed_roles(&self, identifier: &str) -> bool {
        narrowed_roles(&self.required_roles_of(identifier))
    }

    /// `applicationsNamingPolicy(attribute, name)`: the identifiers whose
    /// `attribute` names the profile, case-insensitively.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn applications_naming_policy(
        &self,
        attribute: &str,
        name: &str,
    ) -> Vec<String> {
        let wanted = crate::js::trim(name).to_lowercase();
        if wanted.is_empty() || !POLICY_REFERENCES.contains(&attribute) {
            return Vec::new();
        }
        self.listing()
            .into_iter()
            .filter(|i| {
                crate::js::trim(&first_of(&i.record.fields, attribute))
                    .to_lowercase()
                    == wanted
            })
            .map(|i| i.record.identifier)
            .collect()
    }

    /// `ownerValues()`: every application's `appOwner` values.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn owner_values(&self) -> Vec<Vec<String>> {
        self.listing()
            .into_iter()
            .map(|i| values_of(i.record.fields.get("appOwner")))
            .filter(|o| !o.is_empty())
            .collect()
    }

    /// `applicationsDeclaredFor(family)`: sorted identifiers.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn applications_declared_for(&self, family: &str) -> Vec<String> {
        let wanted = crate::js::trim(family).to_lowercase();
        if wanted.is_empty() {
            return Vec::new();
        }
        let mut out: Vec<String> = self
            .listing()
            .into_iter()
            .filter(|i| {
                !i.record.identifier.is_empty()
                    && declared_families_of(&i.record.fields).contains(&wanted)
            })
            .map(|i| i.record.identifier)
            .collect();
        out.sort();
        out
    }

    /// `applicationsEnforcingFga()`: sorted identifiers.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn applications_enforcing_fga(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .listing()
            .into_iter()
            .filter(|i| {
                !i.record.identifier.is_empty()
                    && first_of(&i.record.fields, "appFgaEnforced")
                        .to_uppercase()
                        == "TRUE"
            })
            .map(|i| i.record.identifier)
            .collect();
        out.sort();
        out
    }

    /// `OVERRIDE_ATTRIBUTES[settingKey]`: the attribute overriding a
    /// setting per application (the last row naming it wins).
    #[tracing::instrument(level = "debug")]
    pub fn override_attribute(setting: &str) -> Option<String> {
        Tables::get()
            .schema
            .attributes
            .iter()
            .rev()
            .find(|r| r.overrides == setting)
            .map(|r| r.name.clone())
    }

    /// `overridableSettings()`.
    #[tracing::instrument(level = "debug")]
    pub fn overridable_settings() -> Vec<Value> {
        let mut seen: Vec<String> = Vec::new();
        let mut out = Vec::new();
        for row in &Tables::get().schema.attributes {
            if row.overrides.is_empty() || seen.contains(&row.overrides) {
                continue;
            }
            seen.push(row.overrides.clone());
            out.push(json!({
                "setting": row.overrides,
                "attribute": Self::override_attribute(&row.overrides),
            }));
        }
        out
    }

    /// `settingFor(identifier, settingKey)`: the application's override of
    /// a setting where it carries a usable one, else the setting — each as
    /// the mode lets it be in force.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn setting_for(&self, identifier: &str, key: &str) -> Value {
        let fallback = self.env.in_force(key, &self.env.setting(key));
        if identifier.is_empty() {
            return fallback;
        }
        let Some(attribute) = Self::override_attribute(key) else {
            return fallback;
        };
        let Some(record) = self.get(identifier) else {
            return fallback;
        };
        let raw = values_of(record["fields"].get(&attribute))
            .into_iter()
            .next()
            .unwrap_or_default();
        if crate::js::trim(&raw).is_empty() {
            return fallback;
        }
        match self.env.parse_as(key, &raw) {
            Ok(v) => self.env.in_force(key, &v),
            Err(problem) => {
                tracing::warn!(
                    "{}applications: {} carries {}=\"{}\", which is not \
                     usable — {}. The service-wide {} is being used instead.",
                    sts_core::log::tag(codes::STS_REG_0025),
                    identifier,
                    attribute,
                    raw,
                    problem,
                    key
                );
                fallback
            }
        }
    }

    /// `largestSetting(settingKey)`: the most any application's override
    /// makes the setting.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn largest_setting(&self, key: &str) -> f64 {
        let num = |v: &Value| v.as_f64().unwrap_or(0.0);
        let mut most = num(&self.env.setting(key));
        if Self::override_attribute(key).is_none() {
            return most;
        }
        for row in self.list() {
            let id = crate::js::or_empty(row.get("identifier"));
            let v = num(&self.setting_for(&id, key));
            if v > most {
                most = v;
            }
        }
        most
    }
}
