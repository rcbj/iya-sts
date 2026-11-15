// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE WRITES: `load()`, `save()`, `setField()`, `fillPrimaryNames()`,
//! the observed-address marks, `seen()` (a sighting), `createApplication()`
//! (a registration by an administrator), `updateApplication()` (one
//! attribute set, added to or removed from), `deleteApplication()`, the
//! owners (#604), the return-address provenance pair and the FGA state
//! (#564), with `noteCredentialWrite()`'s CAEP credential-change.
//!
//! REGISTRATION VERSUS A SIGHTING. An entry a protocol FILED on sight
//! (`seen()`, development mode only — `mode.autoCreates()`) carries no
//! `appRegisteredBy`; one an administrator created carries
//! `administrator`, one RFC 7591 registered `rfc7591`. A return address a
//! sighting wrote is marked OBSERVED (`appReturnAddressObserved`) and
//! product mode refuses it until it is confirmed.

use serde_json::{json, Map, Value};
use sts_core::errors::{codes, ErrorCode};

use super::checks::{self, address_kind, nz, values, Coded, SEALED_FIELDS};
use super::record::{first_of, snapshot_of, values_of, Fields, Record, Snapshot};
use super::store::StoredApplication;
use super::tables::{Tables, PROTOCOLS};
use super::{refused, ApplicationRegistry, Marked};

/// `OBSERVED_ADDRESS_ATTRIBUTE`.
pub const OBSERVED_ADDRESS_ATTRIBUTE: &str = "appReturnAddressObserved";
/// `OBSERVED_CERTIFICATE_ATTRIBUTE`.
pub const OBSERVED_CERTIFICATE_ATTRIBUTE: &str =
    "samlObservedSigningCertificate";
/// `SAML_CERTIFICATE_ATTRIBUTES`.
pub const SAML_CERTIFICATE_ATTRIBUTES: &[&str] =
    &["samlSigningCertificate", "samlSpMetadataSigningCertificate"];
/// `NOT_THE_REGISTRY_IDENTIFIER`.
const NOT_THE_REGISTRY_IDENTIFIER: &[&str] =
    &["oauthTlsClientAuthSubjectDn", "ldapBindDn", "spiffeWorkloadId"];
/// `KEY_SOURCES`.
pub const KEY_SOURCES: &[&str] =
    &["issued", "uploaded-realm-ca", "uploaded-external-ca"];
/// `KEY_SOURCE_ATTRIBUTES`.
pub const KEY_SOURCE_ATTRIBUTES: &[&str] =
    &["oauthAssertionKeySource", "oauthSamlAssertionKeySource"];
/// `GNAP_KEY_ATTRIBUTES`.
const GNAP_KEY_ATTRIBUTES: &[&str] =
    &["gnapKey", "gnapKeyReference", "gnapKeyIdentity"];
/// `APPLICATION_REFERENCE_ATTRIBUTES`.
pub const APPLICATION_REFERENCE_ATTRIBUTES: &[&str] =
    &["appAllowedToDelegateTo", "appAllowedToActOnBehalfOf"];
/// `MAX_OWNERS`.
pub const MAX_OWNERS: usize = 25;

/// `load(identifier)`'s answer.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub record: Record,
    pub known: bool,
    pub entry: Option<StoredApplication>,
}

/// One credential change written and not yet announced
/// (`pendingCredentialWrites`' value).
#[derive(Debug, Clone)]
pub struct PendingCredentialWrite {
    pub key: String,
    pub identifier: String,
    pub before: Value,
    pub after: Value,
    pub how: How,
}

/// `save(record, how)`'s `how`.
#[derive(Debug, Clone, Default)]
pub struct How {
    pub actor: String,
    pub quiet: bool,
    pub observation: bool,
}

impl How {
    /// `{actor}`.
    #[tracing::instrument(level = "debug")]
    pub fn actor(actor: &str) -> How {
        How {
            actor: actor.to_string(),
            ..How::default()
        }
    }

    fn quiet() -> How {
        How {
            quiet: true,
            ..How::default()
        }
    }
}

/// `primaryNameAttributes(protocols)`: the identifier attribute of each
/// declared family that presents its registry identifier, once.
#[tracing::instrument(level = "debug")]
pub fn primary_name_attributes(protocols: &[String]) -> Vec<&'static str> {
    let mut wanted = Vec::new();
    for family in PROTOCOLS {
        if !protocols.iter().any(|p| p == family.id) {
            continue;
        }
        let a = family.identifier_attribute;
        if a.is_empty()
            || NOT_THE_REGISTRY_IDENTIFIER.contains(&a)
            || wanted.contains(&a)
        {
            continue;
        }
        wanted.push(a);
    }
    wanted
}

/// `declaredFamiliesOf(record)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn declared_families_of(fields: &Fields) -> Vec<String> {
    values_of(fields.get("appAllowedProtocol"))
        .iter()
        .map(|one| crate::js::trim(one).to_lowercase())
        .filter(|one| !one.is_empty())
        .collect()
}

/// `familyRefusal(attributeName, declared, identifier)`: '' when the
/// attribute serves no particular family or a declared one.
#[tracing::instrument(level = "debug", skip(declared))]
pub fn family_refusal(
    attribute: &str,
    declared: &[String],
    identifier: &str,
) -> String {
    let t = Tables::get();
    let Some(row) = t.attribute(attribute) else {
        return String::new();
    };
    if row.families.is_empty() {
        return String::new();
    }
    let held: Vec<String> = declared
        .iter()
        .map(|one| crate::js::trim(one).to_lowercase())
        .collect();
    if row.families.iter().any(|id| held.contains(id)) {
        return String::new();
    }
    let labels: Vec<String> = row
        .families
        .iter()
        .map(|id| {
            t.protocol(id)
                .map(|f| f.label.to_string())
                .unwrap_or_else(|| id.clone())
        })
        .collect();
    let why = if row.family_why.is_empty() {
        "It decides what the TOKEN ENDPOINT does for one client_id, so on an \
         entry no token request can ever name it would sit there looking \
         like a policy that was in force."
            .to_string()
    } else {
        row.family_why.clone()
    };
    format!(
        "\"{}\" applies to the {} {}, and \"{}\" is declared for {}. {} Add \
         {} to `appAllowedProtocol` first — that is the tick box on \
         /admin/applications/new and the `protocols` member of the create — \
         and then set this. An `ldapmodify` reaches the attribute like every \
         other and is not checked.",
        attribute,
        labels.join(" and "),
        if labels.len() == 1 {
            "family"
        } else {
            "families"
        },
        identifier,
        if held.is_empty() {
            "no family at all".to_string()
        } else {
            held.join(", ")
        },
        why,
        labels.join(" or ")
    )
}

/// `normaliseProtocols(value)`: the declared families, in table order, or
/// the refusal naming the unknown ones (STS-REG-0005).
#[tracing::instrument(level = "debug", skip_all)]
pub fn normalise_protocols(value: &Value) -> Result<Vec<String>, String> {
    let t = Tables::get();
    let list: Vec<Value> = match value {
        Value::Array(l) => l.clone(),
        other => vec![other.clone()],
    };
    let mut asked: Vec<String> = Vec::new();
    for one in list.iter().filter(|v| !v.is_null()) {
        for part in crate::js::string(one)
            .split(|c: char| crate::js::is_space(c) || c == ',')
        {
            let p = crate::js::trim(part);
            if !p.is_empty() {
                asked.push(p.to_string());
            }
        }
    }
    let mut chosen: Vec<String> = Vec::new();
    let mut unknown: Vec<String> = Vec::new();
    for one in asked {
        if !t.protocol_ids.contains(&one.as_str()) {
            if !unknown.contains(&one) {
                unknown.push(one);
            }
            continue;
        }
        if !chosen.contains(&one) {
            chosen.push(one);
        }
    }
    if !unknown.is_empty() {
        let quoted: Vec<String> =
            unknown.iter().map(|u| format!("\"{u}\"")).collect();
        return Err(format!(
            "{}{} this registry knows. The {} are: {}.",
            quoted.join(", "),
            if unknown.len() > 1 {
                " are not protocol families"
            } else {
                " is not a protocol family"
            },
            t.protocol_ids.len(),
            t.protocol_ids.join(", ")
        ));
    }
    Ok(t
        .protocol_ids
        .iter()
        .filter(|id| chosen.iter().any(|c| c == *id))
        .map(|id| id.to_string())
        .collect())
}

// `addTo(list, value)`.
fn add_to(list: &mut Vec<String>, value: &str) -> bool {
    let text = crate::js::trim(value).to_string();
    if text.is_empty() || list.contains(&text) {
        return false;
    }
    list.push(text);
    true
}

// `noteDescription(record, value)`.
fn note_description(record: &mut Record, value: &str) -> bool {
    let text = crate::js::trim(value).to_string();
    if text.is_empty() || !record.description.is_empty() {
        return false;
    }
    record.description = text;
    true
}

// `observedMarkFor(attribute, value)`.
fn observed_mark_for(attribute: &str, value: &str) -> String {
    format!("{attribute} {value}")
}

// `parseObservedMark(text)`.
fn parse_observed_mark(text: &str) -> Option<(String, String)> {
    let at = text.find(' ')?;
    if at == 0 {
        return None;
    }
    let attribute = &text[..at];
    let value = crate::js::trim(&text[at + 1..]);
    if !Tables::get()
        .return_address_attributes
        .contains(&attribute)
        || value.is_empty()
    {
        return None;
    }
    Some((attribute.to_string(), value.to_string()))
}

/// One row of `observedReturnAddresses()`.
#[derive(Debug, Clone, PartialEq)]
pub struct ObservedRow {
    pub attribute: String,
    pub value: String,
    pub held: bool,
}

/// `observedReturnAddresses(source)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn observed_return_addresses(fields: &Fields) -> Vec<ObservedRow> {
    values_of(fields.get(OBSERVED_ADDRESS_ATTRIBUTE))
        .iter()
        .filter_map(|mark| parse_observed_mark(mark))
        .map(|(attribute, value)| ObservedRow {
            held: values_of(fields.get(&attribute)).contains(&value),
            attribute,
            value,
        })
        .collect()
}

// `clearObservedMark(record, attribute, value)`.
fn clear_observed_mark(
    record: &mut Record,
    attribute: &str,
    value: &str,
) -> bool {
    let have = values_of(record.fields.get(OBSERVED_ADDRESS_ATTRIBUTE));
    let left: Vec<String> = have
        .iter()
        .filter(|mark| {
            !parse_observed_mark(mark)
                .is_some_and(|(a, v)| a == attribute && v == value)
        })
        .cloned()
        .collect();
    if left.len() == have.len() {
        return false;
    }
    if left.is_empty() {
        record.fields.shift_remove(OBSERVED_ADDRESS_ATTRIBUTE);
    } else {
        record.fields.insert(
            OBSERVED_ADDRESS_ATTRIBUTE.into(),
            Value::Array(left.into_iter().map(Value::String).collect()),
        );
    }
    true
}

// A list of strings as a JSON array.
fn list(values: Vec<String>) -> Value {
    Value::Array(values.into_iter().map(Value::String).collect())
}

impl ApplicationRegistry {
    /// `load(identifier)`: the record, and whether the directory holds it.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn load(&self, identifier: &str) -> Loaded {
        match self.read_application(identifier) {
            Some(entry) => Loaded {
                record: Record::from_attributes(&entry.attributes),
                known: true,
                entry: Some(entry),
            },
            None => Loaded {
                record: Record::blank(identifier, self.label_for(identifier)),
                known: false,
                entry: None,
            },
        }
    }

    /// `ownedAttributeNames()`: every name in the SCHEMA, lower-cased,
    /// `objectclass` first.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn owned_attribute_names(&self) -> Vec<String> {
        let mut names = vec!["objectclass".to_string()];
        for row in &Tables::get().schema.attributes {
            let n = row.name.split(';').next().unwrap_or("").to_lowercase();
            if !names.contains(&n) {
                names.push(n);
            }
        }
        names
    }

    /// `save(record, how)`: the entry written, and its credentials
    /// compared with what it was read with.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn save(&self, record: &mut Record, how: &How) -> bool {
        if self.directory.is_none() {
            return false;
        }
        let attributes = record
            .attributes(self.label_for(&record.identifier), self.env.now_ms());
        let written = self.write_application(
            &record.identifier,
            &attributes,
            &self.owned_attribute_names(),
        );
        if written && !how.quiet {
            self.note_credential_write(record, how);
        }
        written
    }

    // `noteCredentialWrite(record, how)`: the change held, by realm and
    // identifier, for `flush_credential_writes()` — Node announces it at
    // the end of the turn, so two writes of one entry in one turn are ONE
    // change, from the first state to the last.
    fn note_credential_write(&self, record: &mut Record, how: &How) {
        let before = record
            .snapshot
            .clone()
            .map(|s| s.0)
            .unwrap_or_else(|| snapshot_of(&Fields::new()));
        let after = snapshot_of(&record.fields);
        record.snapshot = Some(Snapshot(after.clone()));
        let key =
            format!("{}\n{}", sts_core::realm::current_id(), record.identifier);
        let Ok(mut pending) = self.pending.lock() else {
            return;
        };
        let held = pending.iter().position(|p| p.key == key);
        match held {
            None if before == after => {}
            None => pending.push(PendingCredentialWrite {
                key,
                identifier: record.identifier.clone(),
                before,
                after,
                how: how.clone(),
            }),
            Some(at) => {
                let one = &mut pending[at];
                one.after = after;
                if !how.actor.is_empty() {
                    one.how.actor = how.actor.clone();
                }
            }
        }
    }

    /// `flushCredentialWrites()`: every held credential change announced
    /// (a CAEP credential-change or certificate-change each), in the order
    /// first written. The runtime calls it when a request is answered, as
    /// Node's microtask runs at the end of the turn; how many notices went.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn flush_credential_writes(&self) -> usize {
        let due: Vec<PendingCredentialWrite> = match self.pending.lock() {
            Ok(mut p) => std::mem::take(&mut *p),
            Err(_) => return 0,
        };
        due.iter()
            .map(|one| {
                self.announce_credential_changes(
                    &one.identifier,
                    &one.before,
                    &one.after,
                    &one.how,
                )
            })
            .sum()
    }

    // `secretIdsOf(stored)`: id to expiry.
    fn secret_ids_of(&self, stored: &Value) -> Vec<(String, i64)> {
        let mut out: Vec<(String, i64)> = Vec::new();
        for one in values_of(Some(stored)) {
            if let Some(r) = self.parse_client_secret_value(&one) {
                if let Some(slot) = out.iter_mut().find(|(id, _)| *id == r.id)
                {
                    slot.1 = r.expires_at;
                } else {
                    out.push((r.id, r.expires_at));
                }
            }
        }
        out
    }

    // `announceCredentialChanges(identifier, before, after, how)`.
    fn announce_credential_changes(
        &self,
        identifier: &str,
        b: &Value,
        a: &Value,
        how: &How,
    ) -> usize {
        let s = |v: &Value, k: &str| -> String {
            v.get(k).map(crate::js::string).unwrap_or_default()
        };
        let entity = if how.actor.is_empty() {
            "system"
        } else {
            "admin"
        };
        let mut changes: Vec<Value> = Vec::new();
        if b.get("secrets") != a.get("secrets") {
            let was =
                self.secret_ids_of(b.get("secrets").unwrap_or(&Value::Null));
            let now =
                self.secret_ids_of(a.get("secrets").unwrap_or(&Value::Null));
            let added: Vec<String> = now
                .iter()
                .filter(|(id, _)| !was.iter().any(|(w, _)| w == id))
                .map(|(id, _)| id.clone())
                .collect();
            let removed: Vec<String> = was
                .iter()
                .filter(|(id, _)| !now.iter().any(|(n, _)| n == id))
                .map(|(id, _)| id.clone())
                .collect();
            let moved = now
                .iter()
                .any(|(id, e)| was.iter().any(|(w, we)| w == id && we != e));
            let ty = if !added.is_empty() && (!removed.is_empty() || moved) {
                "update"
            } else if !added.is_empty() {
                "create"
            } else if !removed.is_empty() {
                "revoke"
            } else {
                ""
            };
            if !ty.is_empty() {
                let named = if added.is_empty() { &removed } else { &added };
                changes.push(json!({
                    "credentialType":
                        "urn:iya:sts:credential-type:client-secret",
                    "changeType": ty,
                    "friendlyName":
                        format!("client secret {}", named.join(",")),
                    "reasonAdmin": format!(
                        "A client secret of the application {} was {}.",
                        identifier,
                        match ty {
                            "create" => "added",
                            "revoke" => "removed",
                            _ => "replaced",
                        }
                    ),
                }));
            }
        }
        let keys = |v: &Value| -> String {
            if !s(v, "oauthJwks").is_empty() || !s(v, "oauthJwksUri").is_empty()
            {
                format!("{}\n{}", s(v, "oauthJwks"), s(v, "oauthJwksUri"))
            } else {
                String::new()
            }
        };
        let keys_type = change_type_of(&keys(b), &keys(a));
        if !keys_type.is_empty() {
            let uri = !s(a, "oauthJwksUri").is_empty()
                || (s(a, "oauthJwks").is_empty()
                    && !s(b, "oauthJwksUri").is_empty());
            changes.push(json!({
                "credentialType": "urn:iya:sts:credential-type:jwk",
                "changeType": keys_type,
                "friendlyName": if uri { "jwks_uri" } else { "jwks" },
                "reasonAdmin": format!(
                    "The registered keys (jwks / jwks_uri) of the application \
                     {} changed.",
                    identifier
                ),
            }));
        }
        let pair = |v: &Value| -> String {
            let c = s(v, "oauthAssertionCertificate");
            if c.is_empty() {
                s(v, "oauthAssertionJwks")
            } else {
                c
            }
        };
        let pair_type = change_type_of(&pair(b), &pair(a));
        if !pair_type.is_empty() {
            let pem = if pair_type == "revoke" {
                s(b, "oauthAssertionCertificate")
            } else {
                s(a, "oauthAssertionCertificate")
            };
            changes.push(json!({
                "pem": pem,
                "credentialType": if pem.is_empty() {
                    "urn:iya:sts:credential-type:jwk"
                } else {
                    "x509"
                },
                "changeType": pair_type,
                "friendlyName": "RFC 7523 signing key pair",
                "reasonAdmin": format!(
                    "The RFC 7523 signing key pair of the application {} was \
                     {}.",
                    identifier,
                    match pair_type {
                        "create" => "issued",
                        "revoke" => "removed",
                        _ => "replaced",
                    }
                ),
            }));
        }
        for (name, label) in [
            ("oauthSamlAssertionCertificate", "RFC 7522 signing key pair"),
            (
                "oauthSamlAssertionSigningCertificate",
                "RFC 7522 registered signing certificate",
            ),
            ("samlEncryptionCertificate", "SAML encryption certificate"),
        ] {
            let ty = change_type_of(&s(b, name), &s(a, name));
            if !ty.is_empty() {
                changes.push(json!({
                    "pem": if ty == "revoke" { s(b, name) } else { s(a, name) },
                    "credentialType": "x509",
                    "changeType": ty,
                    "friendlyName": label,
                    "reasonAdmin": format!(
                        "The {} of the application {} changed.",
                        label, identifier
                    ),
                }));
            }
        }
        let signing = |v: &Value| values_of(v.get("samlSigning"));
        let (was, now) = (signing(b), signing(a));
        for one in now.iter().filter(|one| !was.contains(one)) {
            changes.push(json!({
                "pem": one, "credentialType": "x509", "changeType": "create",
                "friendlyName": "SAML signing certificate",
                "reasonAdmin": format!(
                    "A SAML signing certificate was registered for the \
                     application {}.",
                    identifier
                ),
            }));
        }
        for one in was.iter().filter(|one| !now.contains(one)) {
            changes.push(json!({
                "pem": one, "credentialType": "x509", "changeType": "revoke",
                "friendlyName": "SAML signing certificate",
                "reasonAdmin": format!(
                    "A SAML signing certificate of the application {} was \
                     removed.",
                    identifier
                ),
            }));
        }
        for change in &changes {
            let mut notice = Map::new();
            notice.insert("application".into(), json!(identifier));
            notice.insert("initiatingEntity".into(), json!(entity));
            notice.insert("via".into(), json!("the application registry"));
            if let Value::Object(c) = change {
                for (k, v) in c {
                    notice.insert(k.clone(), v.clone());
                }
            }
            notice.insert(
                "reasonUser".into(),
                json!("A credential of this application changed."),
            );
            let pem =
                change.get("pem").map(crate::js::string).unwrap_or_default();
            if !pem.is_empty() {
                if !pem.contains("-----BEGIN") {
                    let flat: String =
                        pem.chars().filter(|c| !c.is_whitespace()).collect();
                    let lines: Vec<String> = flat
                        .as_bytes()
                        .chunks(64)
                        .map(|c| String::from_utf8_lossy(c).into_owned())
                        .collect();
                    notice.insert(
                        "pem".into(),
                        json!(format!(
                            "-----BEGIN CERTIFICATE-----\n{}\n-----END \
                             CERTIFICATE-----\n",
                            lines.join("\n")
                        )),
                    );
                }
                self.effects.certificate_changed(&Value::Object(notice));
            } else {
                notice.shift_remove("pem");
                self.effects.credential_changed(&Value::Object(notice));
            }
        }
        changes.len()
    }

    /// `setField(record, name, value)`: one attribute's value written onto
    /// the record; whether it changed. A secret goes through
    /// `putClientSecret()`, a registration access token is sealed.
    #[tracing::instrument(level = "debug", skip(self, record, value))]
    pub fn set_field(
        &self,
        record: &mut Record,
        name: &str,
        value: &Value,
    ) -> Result<bool, Coded> {
        let Some(row) = Tables::get().attribute(name) else {
            tracing::warn!(
                "{}applications: \"{}\" is not in the schema and was not \
                 recorded. Add a row to models/directory/application.tsp \
                 rather than writing an attribute nothing publishes.",
                sts_core::log::tag(codes::STS_REG_0006),
                name
            );
            return Ok(false);
        };
        match value {
            Value::Null => return Ok(false),
            Value::String(s) if s.is_empty() => return Ok(false),
            _ => {}
        }
        if name == "description" {
            let text = match value {
                Value::Array(l) => l
                    .first()
                    .filter(|v| crate::js::truthy(v))
                    .map(crate::js::string)
                    .unwrap_or_default(),
                other => crate::js::string(other),
            };
            let text = crate::js::trim(&text).to_string();
            let changed = !text.is_empty() && record.description != text;
            if !text.is_empty() {
                record.description = text;
            }
            return Ok(changed);
        }
        if name == "oauthClientSecret" {
            return self.put_client_secret(record, value, None);
        }
        let mut value = value.clone();
        if name == "appRegistrationAccessToken"
            && !self.env.is_sealed(&crate::js::string(&value))
        {
            value = Value::String(self.seal_credential_text(
                &crate::js::string(&value),
                super::secrets::REGISTRATION_TOKEN_LABEL,
                "A registration access token",
            )?);
        }
        if row.kind == "multi" {
            let mut held = values_of(record.fields.get(name));
            let mut changed = false;
            let given: Vec<Value> = match &value {
                Value::Array(l) => l.clone(),
                other => vec![other.clone()],
            };
            for one in &given {
                if add_to(&mut held, &crate::js::unless_null(Some(one))) {
                    changed = true;
                }
            }
            record.fields.insert(name.into(), list(held));
            return Ok(changed);
        }
        let text = crate::js::string(&value);
        if record.fields.get(name) == Some(&Value::String(text.clone())) {
            return Ok(false);
        }
        record.fields.insert(name.into(), Value::String(text));
        Ok(true)
    }

    // `setField()` where Node cannot fail.
    fn put(&self, record: &mut Record, name: &str, value: Value) -> bool {
        self.set_field(record, name, &value).unwrap_or(false)
    }

    /// `fillPrimaryNames(record, protocols)`: an empty identifier
    /// attribute of a declared family filled with the identifier.
    #[tracing::instrument(level = "debug", skip(self, record))]
    pub fn fill_primary_names(
        &self,
        record: &mut Record,
        protocols: &[String],
    ) -> Vec<String> {
        let mut filled = Vec::new();
        for attribute in primary_name_attributes(protocols) {
            if !values_of(record.fields.get(attribute)).is_empty() {
                continue;
            }
            let id = record.identifier.clone();
            self.put(record, attribute, Value::String(id));
            filled.push(attribute.to_string());
        }
        filled
    }

    // `markObservedAddresses(record, attribute, before)`.
    fn mark_observed_addresses(
        &self,
        record: &mut Record,
        attribute: &str,
        before: &[String],
    ) -> bool {
        let mut changed = false;
        for one in values_of(record.fields.get(attribute)) {
            if before.contains(&one) {
                continue;
            }
            if self.put(
                record,
                OBSERVED_ADDRESS_ATTRIBUTE,
                Value::String(observed_mark_for(attribute, &one)),
            ) {
                changed = true;
            }
        }
        changed
    }

    /// `returnAddressesOf(source, attribute)`: `{attribute, registered,
    /// unconfirmed}` — in development every value is registered.
    #[tracing::instrument(level = "debug", skip(self, fields))]
    pub fn return_addresses_of(
        &self,
        fields: &Fields,
        attribute: &str,
    ) -> Value {
        let values = values_of(fields.get(attribute));
        if self.env.mode("acceptsUnregisteredAddresses") {
            return json!({ "attribute": attribute, "registered": values,
                           "unconfirmed": [] });
        }
        let marked: Vec<String> = observed_return_addresses(fields)
            .into_iter()
            .filter(|row| row.attribute == attribute)
            .map(|row| row.value)
            .collect();
        let registered: Vec<&String> =
            values.iter().filter(|v| !marked.contains(v)).collect();
        let unconfirmed: Vec<&String> =
            values.iter().filter(|v| marked.contains(v)).collect();
        json!({ "attribute": attribute, "registered": registered,
                "unconfirmed": unconfirmed })
    }

    /// `seen(detail)`: an identifier a protocol ACCEPTED, recorded — the
    /// entry created on first sight in development, never in product.
    /// Answers the record, or None.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn seen(&self, detail: &Value) -> Option<Record> {
        let identifier =
            crate::js::trim(&crate::js::unless_null(detail.get("identifier")))
                .to_string();
        let stated: Vec<String> = match detail.get("kind") {
            Some(Value::Array(l)) => l
                .iter()
                .filter(|v| crate::js::truthy(v))
                .map(crate::js::string)
                .collect(),
            Some(v) if crate::js::truthy(v) => vec![crate::js::string(v)],
            _ => Vec::new(),
        };
        let kind_phrase = if stated.is_empty() {
            String::new()
        } else {
            format!(" ({})", stated.join(", "))
        };
        if identifier.is_empty() {
            return None;
        }
        let loaded = self.load(&identifier);
        let mut record = loaded.record;
        let known = loaded.known;
        if !known && !self.env.mode("autoCreates") {
            tracing::info!(
                "applications: product mode, so \"{}\"{} was NOT created on \
                 sight.",
                identifier,
                kind_phrase
            );
            return None;
        }
        let now = self.env.now_ms();
        let mut changed = !known;
        let mut structural = !known;
        let t = Tables::get();
        for kind in &stated {
            if !t.kind_ids.contains(&kind.as_str()) {
                tracing::warn!(
                    "applications: \"{}\" is not one of the kinds this \
                     registry knows ({}).",
                    kind,
                    t.kind_ids.join(", ")
                );
            }
            if add_to(&mut record.kinds, kind) {
                changed = true;
                structural = true;
            }
        }
        if let Some(p) =
            detail.get("protocol").filter(|v| crate::js::truthy(v))
        {
            if add_to(&mut record.protocols, &crate::js::string(p)) {
                changed = true;
                structural = true;
            }
        }
        if let Some(n) = detail.get("name").filter(|v| crate::js::truthy(v)) {
            let name = crate::js::string(n);
            if record.name != name {
                record.name = name;
                changed = true;
                structural = true;
            }
        }
        if let Some(n) = detail.get("note").filter(|v| crate::js::truthy(v)) {
            if note_description(&mut record, &crate::js::string(n)) {
                changed = true;
                structural = true;
            }
        }
        let guarded: Vec<&str> =
            if self.env.mode("acceptsUnregisteredAddresses") {
                Vec::new()
            } else {
                t.return_address_attributes.clone()
            };
        if let Some(Value::Object(fields)) = detail.get("fields") {
            for (name, value) in fields {
                if guarded.contains(&name.as_str()) {
                    continue;
                }
                let is_address =
                    t.return_address_attributes.contains(&name.as_str());
                let before = if is_address {
                    values_of(record.fields.get(name))
                } else {
                    Vec::new()
                };
                if self.set_field(&mut record, name, value).unwrap_or(false) {
                    changed = true;
                    structural = true;
                }
                if is_address
                    && self.mark_observed_addresses(&mut record, name, &before)
                {
                    changed = true;
                    structural = true;
                }
            }
        }
        if record.first_at == 0 {
            record.first_at = now;
        }
        record.last_at = now;
        if detail.get("counts") != Some(&Value::Bool(false)) {
            record.authentications += 1;
            changed = true;
        }
        if let Some(sid) =
            detail.get("sessionId").filter(|v| crate::js::truthy(v))
        {
            let sid = crate::js::string(sid);
            if record.fields.get("appLastSession")
                != Some(&Value::String(sid.clone()))
            {
                record.session_count += 1;
                self.put(&mut record, "appLastSession", Value::String(sid));
                changed = true;
            }
        }
        let user = crate::js::or_empty(detail.get("user"));
        if !user.is_empty()
            && record.fields.get("appLastUser")
                != Some(&Value::String(user.clone()))
        {
            record.user_count += 1;
            self.put(&mut record, "appLastUser", Value::String(user.clone()));
            changed = true;
        }
        if !changed {
            return Some(record);
        }
        let how = How {
            observation: known && !structural,
            ..How::default()
        };
        let protocol = match detail.get("protocol") {
            Some(v) if crate::js::truthy(v) => crate::js::string(v),
            _ => "unstated".to_string(),
        };
        if !self.save(&mut record, &how) && self.directory.is_some() {
            self.effects.failure(
                codes::STS_REG_0020,
                &json!({
                    "protocol": protocol, "channel": "internal",
                    "actor": user, "target": identifier,
                    "summary": format!(
                        "The application registry could not write \"{}\": \
                         the ou=applications container is full \
                         (applications.max) or the directory refused the \
                         entry.",
                        identifier
                    ),
                    "outcome": "error",
                }),
            );
        }
        self.effects.audit(&json!({
            "action": if known {
                "application.update"
            } else {
                "application.create"
            },
            "actor": user,
            "protocol": protocol,
            "channel": "internal",
            "target": identifier,
            "summary": format!(
                "{}{}{}{}",
                if known {
                    "Application \""
                } else {
                    "A new application \""
                },
                identifier,
                if known {
                    "\" recorded something new"
                } else {
                    "\" was seen for the first time"
                },
                kind_phrase
            ),
            "detail": {
                "identifier": identifier,
                "kinds": record.kinds.join(", "),
                "protocols": record.protocols.join(", "),
                "authentications": record.authentications,
                "registered": record.registered,
            },
        }));
        Some(record)
    }

    // `identifierProblem(identifier)`.
    fn identifier_problem(identifier: &str) -> Option<String> {
        let text = crate::js::trim(identifier);
        if text.is_empty() {
            return Some(
                "An identifier is required — the client_id, wtrealm, \
                 AppliesTo, entityID or service principal name this \
                 application is known by."
                    .to_string(),
            );
        }
        let n = crate::js::len_utf16(text);
        if n > 512 {
            return Some(format!(
                "That identifier is {} characters. The longest this registry \
                 will hold is 512, which is already far past anything a \
                 client_id or an entityID should be.",
                n
            ));
        }
        if text.contains(['\r', '\n', '\0']) {
            return Some(
                "An identifier cannot contain a line break or a NUL."
                    .to_string(),
            );
        }
        None
    }

    /// `viewAfterWrite(identifier, record)`: the entry as the directory
    /// now holds it, or the record's own view.
    #[tracing::instrument(level = "debug", skip(self, record))]
    pub fn view_after_write(&self, identifier: &str, record: &Record) -> Value {
        self.get(identifier)
            .unwrap_or_else(|| self.view(record, None))
    }

    // The certificate trust door for a SAML certificate given on a write
    // (`certificateTrust.registrationProblem()`).
    fn certificate_refusal(
        &self,
        attribute: &str,
        value: &str,
    ) -> Option<(String, ErrorCode)> {
        let b64 = values::saml_certificate_base64(value);
        let der = sts_crypto::b64::decode_loose(&b64).unwrap_or_default();
        self.effects.certificate_registration_problem(
            if attribute == "samlEncryptionCertificate" {
                "encryption-recipient"
            } else {
                "saml-signer"
            },
            &der,
        )
    }

    /// `createApplication(detail)`: an application an ADMINISTRATOR
    /// registers — `{identifier, name, kind, protocols, fields,
    /// lifetimeDays, actor}`. Answers `{ok, application}` or a refusal.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn create_application(&self, detail: &Value) -> Marked {
        let identifier =
            crate::js::trim(&crate::js::or_empty(detail.get("identifier")))
                .to_string();
        let given_map = match detail.get("fields") {
            Some(Value::Object(f)) => f.clone(),
            _ => Map::new(),
        };
        for attribute in SAML_CERTIFICATE_ATTRIBUTES
            .iter()
            .chain(["samlEncryptionCertificate"].iter())
        {
            for one in values_of(given_map.get(*attribute)) {
                if let Some((why, code)) =
                    self.certificate_refusal(attribute, &one)
                {
                    return refused(
                        code,
                        vec![format!("`{}` is refused: {}.", attribute, why)],
                    );
                }
            }
        }
        if let Some(problem) = Self::identifier_problem(&identifier) {
            return refused(codes::STS_REG_0001, vec![problem]);
        }
        if self.directory.is_none() {
            return refused(
                codes::STS_REG_0002,
                vec!["There is no directory loaded in this process, so there \
                      is no ou=applications container and nothing to create. \
                      The registry has no store of its own on purpose."
                    .to_string()],
            );
        }
        let loaded = self.load(&identifier);
        if loaded.known {
            return refused(
                codes::STS_REG_0003,
                vec![format!(
                    "\"{}\" is already in this registry. Change what it holds \
                     instead of creating it again — an identifier names one \
                     application here whatever protocol brought it.",
                    identifier
                )],
            );
        }
        let t = Tables::get();
        let kind = crate::js::trim(&crate::js::or_empty(detail.get("kind")))
            .to_string();
        if !kind.is_empty() && !t.kind_ids.contains(&kind.as_str()) {
            return refused(
                codes::STS_REG_0004,
                vec![format!(
                    "\"{}\" is not one of the kinds this registry knows. The \
                     {} are: {}.",
                    kind,
                    crate::js::number_word(t.kind_ids.len()),
                    t.kind_ids.join(", ")
                )],
            );
        }
        let protocols = match normalise_protocols(
            detail.get("protocols").unwrap_or(&Value::Array(Vec::new())),
        ) {
            Ok(p) => p,
            Err(e) => return refused(codes::STS_REG_0005, vec![e]),
        };
        let given = self.normalise_fields(&given_map);
        if !given.ok() {
            return refused(
                given.code.unwrap_or(codes::STS_REG_0006),
                given.errors,
            );
        }
        let wrong: Vec<String> = given
            .fields
            .keys()
            .map(|name| family_refusal(name, &protocols, &identifier))
            .filter(|one| !one.is_empty())
            .collect();
        if !wrong.is_empty() {
            return refused(codes::STS_REG_0010, wrong);
        }
        let mut did_problems = Vec::new();
        for (name, value) in &given.fields {
            let mut seen_values: Vec<String> = Vec::new();
            for one in values_of(Some(value)) {
                let problem = nz(values::did_value_problem(self, name, &one))
                    .or_else(|| nz(values::claim_rows_problem(name, &one)))
                    .or_else(|| nz(values::claim_selection_problem(name, &one)))
                    .or_else(|| {
                        if name == "oauthPermissionClaims" {
                            nz(values::permission_claims_problem(
                                &one,
                                &given.fields,
                            ))
                        } else {
                            None
                        }
                    })
                    .or_else(|| {
                        nz(values::did_duplicate_problem(name, &one, &seen_values))
                    });
                if let Some(p) = problem {
                    did_problems.push(p);
                }
                seen_values.push(one);
            }
        }
        if !did_problems.is_empty() {
            return refused(codes::STS_REG_0204, did_problems);
        }
        let mut choice_problems = Vec::new();
        for (name, value) in &given.fields {
            for one in values_of(Some(value)) {
                if let Some(p) = nz(values::choice_problem(name, &one)) {
                    choice_problems.push(p);
                }
            }
        }
        if !choice_problems.is_empty() {
            return refused(codes::STS_REG_0203, choice_problems);
        }
        if let Some(p) = nz(values::token_response_types_problem(
            self,
            &values_of(given.fields.get("oauthAllowedTokenResponseTypes")),
        )) {
            return refused(codes::STS_REG_0364, vec![p]);
        }
        if let Some(p) = nz(values::auth_methods_problem(
            given.fields.get("oauthTokenEndpointAuthMethod"),
        )) {
            return refused(codes::STS_REG_0207, vec![p]);
        }
        let mut self_problems = Vec::new();
        for name in APPLICATION_REFERENCE_ATTRIBUTES
            .iter()
            .chain(["appMayAct"].iter())
        {
            for one in values_of(given.fields.get(*name)) {
                if let Some(p) = checks::uris::self_reference_problem(
                    self,
                    name,
                    &one,
                    &identifier,
                    &given.fields,
                    None,
                ) {
                    self_problems.push(p);
                }
            }
        }
        if !self_problems.is_empty() {
            return refused(codes::STS_REG_0335, self_problems);
        }
        let first = |v: &Value| values_of(Some(v)).into_iter().next();
        let strict: Vec<String> = given
            .fields
            .iter()
            .filter_map(|(name, value)| {
                nz(values::strict_override_problem(
                    self,
                    name,
                    &first(value).unwrap_or_default(),
                ))
            })
            .collect();
        if !strict.is_empty() {
            return refused(codes::STS_REG_0202, strict);
        }
        let modes: Vec<String> = given
            .fields
            .iter()
            .filter_map(|(name, value)| {
                nz(values::override_mode_problem(
                    self,
                    name,
                    &first(value).unwrap_or_default(),
                ))
            })
            .collect();
        if !modes.is_empty() {
            return refused(codes::STS_REG_0193, modes);
        }
        let Ok(days) =
            Self::client_secret_lifetime_of(detail.get("lifetimeDays"))
        else {
            let d = self
                .env
                .setting("oauth2.clientSecretLifetimeDays")
                .as_f64()
                .unwrap_or(0.0);
            return refused(
                codes::STS_REG_0359,
                vec![format!(
                    "The client secret's lifetime is a whole number of days \
                     from 0 (never expires) to 730, or empty for \
                     oauth2.clientSecretLifetimeDays ({}). \"{}\" is not one.",
                    if d > 0.0 {
                        format!("{} days", crate::js::string(&json!(d)))
                    } else {
                        "never expires".to_string()
                    },
                    crate::js::trim(&crate::js::string(
                        detail.get("lifetimeDays").unwrap_or(&Value::Null)
                    ))
                )],
            );
        };
        if let Some(days) = days {
            let text = super::secrets::given_secret_text(
                given.fields.get("oauthClientSecret").unwrap_or(&Value::Null),
            );
            let whole = text.starts_with('{')
                && self
                    .parse_client_secret_value(&text)
                    .is_some_and(|p| p.created_at > 0);
            if text.is_empty() || whole {
                return refused(
                    codes::STS_REG_0360,
                    vec![format!(
                        "A client secret lifetime of {} day(s) was given and \
                         there is no new client secret for it to apply to: {}",
                        days,
                        if text.is_empty() {
                            "oauthClientSecret is empty. Generate or type a \
                             secret, or leave the lifetime empty."
                        } else {
                            "the oauthClientSecret given is a whole record, \
                             which keeps the expiry it carries."
                        }
                    )],
                );
            }
        }
        if let Some(stated) = given.fields.get("oauthConfidential") {
            let mut preview = Record::default();
            preview.fields.insert(
                "oauthTokenEndpointAuthMethod".into(),
                json!(values::preview_auth_methods(&protocols, &given.fields)),
            );
            let determination = values::oauth_confidential_of(false, &preview.fields);
            let problem = values::confidential_disagreement(
                &crate::js::string(stated),
                &determination,
            );
            if !problem.is_empty() {
                return refused(codes::STS_REG_0363, vec![problem]);
            }
        }
        let mut record = loaded.record;
        let now = self.env.now_ms();
        record.first_at = now;
        record.last_at = now;
        if let Some(n) = detail.get("name").filter(|v| crate::js::truthy(v)) {
            record.name = crate::js::string(n);
        }
        if !kind.is_empty() {
            add_to(&mut record.kinds, &kind);
        }
        self.put(&mut record, "appRegisteredBy", json!("administrator"));
        if !protocols.is_empty() {
            self.put(&mut record, "appAllowedProtocol", json!(protocols));
        }
        for (name, value) in &given.fields {
            if name == "oauthConfidential" {
                continue;
            }
            let wrote = if name == "oauthClientSecret" && days.is_some() {
                self.put_client_secret(
                    &mut record,
                    value,
                    super::secrets::expiry_of_lifetime(days, self.now_sec()),
                )
            } else {
                self.set_field(&mut record, name, value)
            };
            if let Err(e) = wrote {
                return refused(e.code, vec![e.message]);
            }
        }
        self.fill_primary_names(&mut record, &protocols);
        if protocols.iter().any(|p| p == "oauth2" || p == "oidc")
            && values_of(record.fields.get("oauthTokenEndpointAuthMethod"))
                .is_empty()
        {
            let method = values::credential_auth_method(&record.fields);
            self.put(&mut record, "oauthTokenEndpointAuthMethod", json!(method));
        }
        values::record_oauth_confidential(
            &mut record,
            Some(given.fields.contains_key("oauthConfidential")),
        );
        note_description(
            &mut record,
            "created from the console; nothing has authenticated for it yet",
        );
        if !self.save(&mut record, &How::default()) {
            return refused(
                codes::STS_REG_0020,
                vec!["The ou=applications container is full \
                      (applications.max) or the directory is. Nothing was \
                      created."
                    .to_string()],
            );
        }
        let actor = crate::js::or_empty(detail.get("actor"));
        let names: Vec<String> = given.fields.keys().cloned().collect();
        self.effects.audit(&json!({
            "action": "application.create",
            "actor": actor,
            "protocol": "console",
            "channel": "internal",
            "target": identifier,
            "summary": format!(
                "Application \"{}\" was created from the console{}",
                identifier,
                if kind.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", kind)
                }
            ),
            "detail": {
                "identifier": identifier, "kind": kind,
                "createdByHand": true,
                "protocols": protocols.join(", "),
                "attributes": names.join(", "),
            },
        }));
        self.fga_hook("created", &identifier, &actor, "");
        Marked::ok(json!({
            "ok": true,
            "application": self.view_after_write(&identifier, &record),
        }))
    }

    /// `updateApplication(identifier, {attribute, mode, value, actor,
    /// observed, confirm, consentRegister})`: one attribute SET (a single
    /// value), ADDED to or REMOVED from (a list).
    #[tracing::instrument(level = "debug", skip(self, change))]
    pub fn update_application(
        &self,
        identifier: &str,
        change: &Value,
    ) -> Marked {
        let attribute = crate::js::or_empty(change.get("attribute"));
        let mode = crate::js::or_empty(change.get("mode"));
        let actor = crate::js::or_empty(change.get("actor"));
        let loaded = self.load(identifier);
        if !loaded.known {
            return refused(
                codes::STS_REG_0021,
                vec![format!(
                    "There is no application called \"{}\" in this registry. \
                     An entry appears when an identifier is ACCEPTED by a \
                     protocol, or when one is created here.",
                    identifier
                )],
            );
        }
        let t = Tables::get();
        let Some(row) = t.attribute(&attribute) else {
            return refused(
                codes::STS_REG_0006,
                vec![format!(
                    "\"{}\" is not in the published schema. GET \
                     /admin/ldap/applications lists every attribute an entry \
                     may carry; adding one that is not there means adding a \
                     row to models/directory/application.tsp, not writing it \
                     through this.",
                    attribute
                )],
            );
        };
        if mode == "remove"
            && values::is_hosted_session_client(identifier)
            && values::hosted_bound_attribute(&attribute)
        {
            return refused(
                codes::STS_REG_0369,
                vec![format!(
                    "\"{}\" is this application's own session bound. \
                     Removing it is refused, the same as clearing it: a \
                     longer realm setting would lengthen the admin console, \
                     the user portal or the reports application.",
                    attribute
                )],
            );
        }
        if row.editable.is_empty() && attribute != "oauthConfidential" {
            let editable = t.editable_attributes("");
            let names: Vec<&str> =
                editable.iter().map(|r| r.name.as_str()).collect();
            return refused(
                codes::STS_REG_0007,
                vec![format!(
                    "\"{}\" is not editable here. It is DERIVED — what \
                     happened rather than what this application may do — and \
                     a form that could rewrite it would make this page lie \
                     about the service's own behaviour. The {} that are \
                     editable are: {}.",
                    attribute,
                    names.len(),
                    names.join(", ")
                )],
            );
        }
        if row.editable == "set" && mode != "set" {
            return refused(
                codes::STS_REG_0008,
                vec![format!(
                    "\"{}\" holds ONE value, so it is set rather than added \
                     to or removed from.",
                    attribute
                )],
            );
        }
        if row.editable == "multi" && mode != "add" && mode != "remove" {
            return refused(
                codes::STS_REG_0008,
                vec![format!(
                    "\"{}\" holds a LIST, so values are added and removed \
                     rather than set — a set would replace the list with one \
                     value and read afterwards as the others having been \
                     forgotten.",
                    attribute
                )],
            );
        }
        let mut value = crate::js::unless_null(change.get("value"));
        if attribute == "oauthConfidential" {
            if mode != "set" {
                return refused(
                    codes::STS_REG_0363,
                    vec![values::confidential_mode_sentence()],
                );
            }
            if crate::js::trim(&value).is_empty() {
                return refused(
                    codes::STS_REG_0363,
                    vec![values::confidential_clear_sentence()],
                );
            }
            let determination = values::oauth_confidential_of(
                loaded.record.registered,
                &loaded.record.fields,
            );
            let problem =
                values::confidential_disagreement(&value, &determination);
            if !problem.is_empty() {
                return refused(codes::STS_REG_0363, vec![problem]);
            }
            value = determination;
        }
        if mode != "set" && value.is_empty() {
            return refused(
                codes::STS_REG_0009,
                vec![format!("A value is required to {}.", mode)],
            );
        }
        let fields = &loaded.record.fields;
        let held = values_of(fields.get(&attribute));
        if attribute == "oauthScope" && mode == "add" {
            return refused(
                codes::STS_REG_0361,
                vec!["\"oauthScope\" records the scopes this client has ASKED \
                      FOR, written as its requests arrive, so it cannot be \
                      added by hand. What it may be issued is \
                      oauthAllowedScope."
                    .to_string()],
            );
        }
        if (attribute == "oauthResponseType"
            || attribute == "oauthAllowedTokenResponseTypes")
            && (mode == "add" || (mode == "remove" && !held.contains(&value)))
        {
            value = values::canonical_response_type(&value);
        }
        if attribute == "appAllowedProtocol" && mode == "add" {
            if let Err(e) = normalise_protocols(&Value::String(value.clone()))
            {
                return refused(codes::STS_REG_0005, vec![e]);
            }
        }
        let set_or_add = mode == "set" || mode == "add";
        let set_value = mode == "set" && !value.is_empty();
        let set_or_add_value = set_or_add && !value.is_empty();
        if set_or_add_value {
            let did = nz(values::did_value_problem(self, &attribute, &value)).or_else(
                || {
                    if mode == "add" {
                        nz(values::did_duplicate_problem(&attribute, &value, &held))
                    } else {
                        None
                    }
                },
            );
            if let Some(p) = did {
                return refused(codes::STS_REG_0204, vec![p]);
            }
            if let Some(p) = nz(values::claim_rows_problem(&attribute, &value)) {
                return refused(codes::STS_REG_0206, vec![p]);
            }
            if let Some(p) = nz(values::claim_selection_problem(&attribute, &value))
            {
                return refused(codes::STS_REG_0215, vec![p]);
            }
            if attribute == "oauthPermissionClaims" {
                if let Some(p) =
                    nz(values::permission_claims_problem(&value, fields))
                {
                    return refused(codes::STS_REG_0344, vec![p]);
                }
            }
            if let Some(p) = nz(values::choice_problem(&attribute, &value)) {
                return refused(codes::STS_REG_0203, vec![p]);
            }
            if attribute == "oauthAllowedTokenResponseTypes" {
                if let Some(p) =
                    nz(values::token_response_types_problem(self, &[value.clone()]))
                {
                    return refused(codes::STS_REG_0364, vec![p]);
                }
            }
            if attribute == "oauthTokenEndpointAuthMethod" && mode == "add" {
                let mut all = held.clone();
                all.push(value.clone());
                if let Some(p) = nz(values::auth_methods_problem(Some(&json!(all)))) {
                    return refused(codes::STS_REG_0207, vec![p]);
                }
            }
        }
        if set_value {
            if let Some(p) =
                nz(values::strict_override_problem(self, &attribute, &value))
            {
                return refused(codes::STS_REG_0202, vec![p]);
            }
            if let Some(p) =
                nz(values::override_mode_problem(self, &attribute, &value))
            {
                return refused(codes::STS_REG_0193, vec![p]);
            }
        }
        if set_value || mode == "add" {
            let wrong = family_refusal(
                &attribute,
                &declared_families_of(fields),
                identifier,
            );
            if !wrong.is_empty() {
                return refused(codes::STS_REG_0010, vec![wrong]);
            }
        }
        if attribute == "ssfAllowedEvents" && (mode == "add" || set_value) {
            if let Some(p) = checks::uris::ssf_allowed_event_problem(&value, &|u| {
                self.effects.ssf_event_known(u)
            }) {
                return refused(codes::STS_REG_0053, vec![p]);
            }
        }
        if set_value {
            if let Some(p) = checks::oauth::introspection_attribute_problem(
                self, &attribute, &value, fields,
            ) {
                return refused(codes::STS_REG_0073, vec![p]);
            }
        }
        if set_or_add_value {
            if let Some(p) = checks::oauth::request_object_attribute_problem(
                self, &attribute, &value, fields,
            ) {
                return refused(codes::STS_REG_0101, vec![p]);
            }
            if let Some(p) = checks::uris::delegation_attribute_problem(
                self, &attribute, &value,
            ) {
                return refused(codes::STS_REG_0194, vec![p]);
            }
            if let Some(p) = checks::uris::kerberos_trust_attribute_problem(
                self,
                &attribute,
                &value,
                &|r| self.effects.kerberos_accepts_realm(r),
            ) {
                return refused(codes::STS_REG_0362, vec![p]);
            }
            if let Some(p) = checks::uris::self_reference_problem(
                self,
                &attribute,
                &value,
                identifier,
                fields,
                loaded.entry.as_ref().map(|e| e.dn.as_str()),
            ) {
                return refused(codes::STS_REG_0335, vec![p]);
            }
        }
        if set_value {
            if let Some(p) =
                checks::oauth::pushed_authorization_attribute_problem(
                    self, &attribute, &value,
                )
            {
                return refused(codes::STS_REG_0121, vec![p]);
            }
            if let Some(p) = checks::oauth::oidc_subject_attribute_problem(
                self, &attribute, &value, fields,
            ) {
                return refused(codes::STS_REG_0168, vec![p]);
            }
            if let Some(p) = checks::oauth::mtls_attribute_problem(
                self, &attribute, &value, fields,
            ) {
                return refused(p.code, vec![p.message]);
            }
            if let Some(p) =
                checks::oauth::gnap_mtls_trust_problem(self, &attribute, &value)
            {
                return refused(p.code, vec![p.message]);
            }
        }
        if set_or_add_value {
            if let Some(p) = checks::oauth::authzen_attribute_problem(
                self, &attribute, &value,
            ) {
                return refused(p.code, vec![p.message]);
            }
            if let Some(p) =
                checks::oauth::authorization_details_attribute_problem(
                    self, &attribute, &value,
                )
            {
                return refused(p.code, vec![p.message]);
            }
            if attribute == "oauthAuthorizationDetailsType" {
                if let Some(p) =
                    checks::oauth::fga_coverage_problem(self, fields, &value)
                {
                    return refused(codes::STS_FGA_0019, vec![p]);
                }
            }
        }
        if set_value {
            if let Some(p) = checks::oauth::client_response_attribute_problem(
                self, &attribute, &value, fields,
            ) {
                return refused(codes::STS_REG_0340, vec![p]);
            }
            if let Some(p) = checks::oauth::step_up_attribute_problem(
                self, &attribute, &value,
            ) {
                return refused(p.code, vec![p.message]);
            }
        }
        if KEY_SOURCE_ATTRIBUTES.contains(&attribute.as_str())
            && set_value
            && !KEY_SOURCES.contains(&value.as_str())
        {
            return refused(
                codes::STS_REG_0060,
                vec![format!(
                    "\"{}\" is not a key source. `{}` records where a key \
                     pair came from and holds one of {}.",
                    value,
                    attribute,
                    KEY_SOURCES.join(", ")
                )],
            );
        }
        if address_kind(&attribute).is_some()
            && set_or_add_value
            && !held.contains(&value)
        {
            if let Some(p) = checks::uris::address_problem(&attribute, &value)
            {
                return refused(codes::STS_REG_0071, vec![p]);
            }
            if attribute == "oauthBackchannelLogoutUri" {
                let public =
                    values_of(fields.get("oauthTokenEndpointAuthMethod"))
                        .iter()
                        .any(|m| m == "none");
                if let Some(p) =
                    checks::uris::backchannel_scheme_problem(&value, public, &|u| {
                        self.effects.dial_problem(u)
                    })
                {
                    return refused(p.code, vec![p.message]);
                }
            }
            if attribute == "oauthFrontchannelLogoutUri" {
                if let Some(p) = checks::uris::frontchannel_origin_problem(
                    &value,
                    fields.get("oauthRedirectUri"),
                ) {
                    return refused(codes::STS_REG_0171, vec![p]);
                }
            }
        }
        if (attribute == "oauthResourceMetadata"
            || attribute == "oauthResourceMetadataUrl")
            && set_value
        {
            let p = if attribute == "oauthResourceMetadata" {
                checks::uris::resource_metadata_problem(&value)
            } else {
                checks::uris::resource_metadata_url_problem(&value)
            };
            if let Some(p) = p {
                return refused(codes::STS_REG_0089, vec![p]);
            }
        }
        if attribute == "appCorsOrigin" && mode == "add" {
            if let Some(p) = checks::uris::cors_origin_write_problem(&value) {
                return refused(codes::STS_REG_0150, vec![p]);
            }
            value = checks::validation::normalise_origin(&value);
        }
        if attribute == "appCorsOrigin"
            && mode == "remove"
            && !held.contains(&value)
            && !checks::validation::normalise_origin(&value).is_empty()
        {
            value = checks::validation::normalise_origin(&value);
        }
        if attribute == "appHomePageUrl" && set_value {
            if let Some(p) = checks::uris::home_page_problem(&value) {
                return refused(codes::STS_REG_0011, vec![p]);
            }
        }
        if attribute == "oauthInitiateLoginUri" && set_value {
            if let Some(p) = checks::uris::initiate_login_uri_problem(&value) {
                return refused(codes::STS_REG_0188, vec![p]);
            }
        }
        if checks::CLIENT_DISPLAY_ATTRIBUTES.contains(&attribute.as_str())
            && set_value
        {
            if let Some(p) =
                checks::uris::client_display_uri_problem(&attribute, &value)
            {
                return refused(codes::STS_REG_0365, vec![p]);
            }
        }
        if attribute == "gnapOwnerLookupUri" && set_value {
            if let Some(p) = checks::uris::owner_lookup_uri_problem(&value) {
                return refused(codes::STS_REG_0334, vec![p]);
            }
        }
        if attribute == "oauthPermissionBaseUri" && set_value {
            if let Some(p) = checks::uris::permission_base_problem(&value) {
                return refused(codes::STS_REG_0012, vec![p]);
            }
        }
        let permissions = crate::app_permissions::permissions_of(
            &json!({ "fields": fields }),
        );
        if attribute == "oauthPermission" && mode == "add" {
            let parsed = checks::uris::parse_permission_value(&value);
            if let Some(p) = checks::uris::permission_operator_code_problem(
                &parsed.name,
                &parsed.description,
            ) {
                return refused(codes::STS_REG_0367, vec![p]);
            }
            if let Some(p) = checks::uris::permission_name_problem(&parsed.name)
            {
                return refused(codes::STS_REG_0013, vec![p]);
            }
            if let Some(already) = permissions.iter().find(|one| {
                one.get("name").and_then(Value::as_str)
                    == Some(parsed.name.as_str())
            }) {
                let description =
                    crate::js::or_empty(already.get("description"));
                return refused(
                    codes::STS_REG_0014,
                    vec![format!(
                        "This application already defines a permission called \
                         \"{}\"{}. A permission has one description, so \
                         change it by removing \"{}\" and adding the new \
                         value — adding a second would put two rows with one \
                         name on every page that lists them.",
                        parsed.name,
                        if description.is_empty() {
                            String::new()
                        } else {
                            format!(" ({})", description)
                        },
                        crate::js::or_empty(already.get("raw"))
                    )],
                );
            }
            if crate::app_permissions::permission_base_of(
                fields.get("oauthPermissionBaseUri"),
            )
            .is_empty()
            {
                return refused(
                    codes::STS_REG_0015,
                    vec!["This application has no `oauthPermissionBaseUri`, \
                          so a permission on it would have no identifier: a \
                          permission is named by its base URI followed by its \
                          name, and a client asks for it by putting that \
                          whole string in a `scope`. Set the base first — \
                          `https://example.com/` is the shape, and Entra ID \
                          spells the same thing `api://<guid>`."
                        .to_string()],
                );
            }
        }
        if attribute == "oauthRoleGatedPermission"
            && mode == "add"
            && !permissions.iter().any(|one| {
                one.get("name").and_then(Value::as_str) == Some(value.as_str())
            })
        {
            return refused(
                codes::STS_REG_0090,
                vec![checks::uris::role_gated_problem(&value)],
            );
        }
        if attribute == "oauthDelegatedPermission" && mode == "add" {
            let Some(defines) = self.for_permission(&value) else {
                return refused(
                    codes::STS_REG_0016,
                    vec![format!(
                        "No application in this registry defines the \
                         permission \"{}\", and a permission must be DEFINED \
                         before it can be GRANTED — that is the one ordering \
                         rule this feature has. Give the resource application \
                         an `oauthPermissionBaseUri` and an \
                         `oauthPermission`, then grant the two joined \
                         together. The identifier is an exact match rather \
                         than a prefix of a registered base, so that a client \
                         cannot address a token to somebody's API by \
                         inventing a word after their base URI. `ldapmodify` \
                         reaches this attribute like every other and is not \
                         checked, which is what /admin/delegation reports as \
                         a DANGLING grant.",
                        value
                    )],
                );
            };
            if defines.get("identifier").and_then(Value::as_str)
                == Some(identifier)
            {
                return refused(
                    codes::STS_REG_0017,
                    vec![format!(
                        "\"{}\" is the application that DEFINES \"{}\", so \
                         granting it to itself would address a token to its \
                         own API — which is what an ID Token already is, and \
                         which draws as a line from a box back to the same \
                         box. A grant is between two applications.",
                        identifier, value
                    )],
                );
            }
        }
        if attribute == "oauthGlobalConsent"
            && mode == "remove"
            && change.get("consentRegister") != Some(&Value::Bool(true))
        {
            return refused(
                codes::STS_REG_0191,
                vec!["A global consent is withdrawn through the consent \
                      register — the `revoke-global-consent` action at \
                      /admin/consent or `POST \
                      /admin-api/consent/revoke-global-consent` — and not by \
                      removing the value here: withdrawing it also revokes \
                      every token issued under it and records when, so that \
                      adding it back revives nothing. Nothing was changed."
                    .to_string()],
            );
        }
        if attribute == "oauthGlobalConsent" && mode == "add" {
            if let Some(p) = checks::uris::scope_token_problem(&value) {
                return refused(codes::STS_REG_0018, vec![p]);
            }
        }
        if attribute == "oauthAllowedScope" && mode == "add" {
            if let Some(p) = checks::uris::scope_token_problem(&value) {
                return refused(codes::STS_REG_0172, vec![p]);
            }
        }
        if attribute == "samlEncryptionCertificate"
            && !value.is_empty()
            && mode != "remove"
        {
            if let Some((why, code)) =
                self.certificate_refusal(&attribute, &value)
            {
                return refused(
                    code,
                    vec![format!(
                        "`{}` is refused: {}. Nothing was written.",
                        attribute, why
                    )],
                );
            }
        }
        if SAML_CERTIFICATE_ATTRIBUTES.contains(&attribute.as_str())
            && !value.is_empty()
        {
            value = values::saml_certificate_base64(&value);
            if mode != "remove" {
                if let Some(p) = nz(values::saml_certificate_problem(self, &value)) {
                    return refused(
                        codes::STS_REG_0160,
                        vec![format!(
                            "`{}` must be an X.509 certificate whose key \
                             makes an XML signature this service verifies, \
                             base64 DER or PEM, and this one is not: {}. \
                             Nothing was written.",
                            attribute, p
                        )],
                    );
                }
            }
        }
        if SEALED_FIELDS.contains(&attribute.as_str()) && !value.is_empty() {
            match self.seal_field_value(&attribute, &value) {
                Some(sealed) => value = sealed,
                None => {
                    return refused(
                        codes::STS_REG_0019,
                        vec![format!(
                            "`{}` is private key material and this service \
                             could not encrypt it, so it was not stored. \
                             Nothing was written and no key pair is on the \
                             entry. The key-encryption key is the one \
                             /admin/persistence reports on; product mode \
                             cannot run without it.",
                            attribute
                        )],
                    );
                }
            }
        }
        let mut record = loaded.record.clone();
        let mut changed;
        let mut what;
        let rra = &t.return_address_attributes;
        if attribute == "appName" {
            changed = record.name != value;
            record.name = value.clone();
            what = format!("appName is now \"{}\"", value);
        } else if attribute == "description" {
            changed = record.description != value;
            record.description = value.clone();
            what = if value.is_empty() {
                "the description was cleared".to_string()
            } else {
                format!("the description is now \"{}\"", value)
            };
        } else if mode == "set" {
            changed = match self.set_field(
                &mut record,
                &attribute,
                &Value::String(value.clone()),
            ) {
                Ok(c) => c,
                Err(e) => return refused(e.code, vec![e.message]),
            };
            if value.is_empty() && record.fields.contains_key(&attribute) {
                record.fields.shift_remove(&attribute);
                changed = true;
            }
            what = if value.is_empty() {
                format!("{} was cleared", attribute)
            } else if row.sensitive || row.secret {
                format!(
                    "{} was set (a credential; its value is not repeated \
                     here)",
                    attribute
                )
            } else {
                format!("{} is now \"{}\"", attribute, value)
            };
        } else if mode == "add" {
            let before = values_of(record.fields.get(&attribute));
            changed = match self.set_field(
                &mut record,
                &attribute,
                &Value::String(value.clone()),
            ) {
                Ok(c) => c,
                Err(e) => return refused(e.code, vec![e.message]),
            };
            what = format!("added \"{}\" to {}", value, attribute);
            if attribute == "samlSigningCertificate"
                && first_of(&record.fields, OBSERVED_CERTIFICATE_ATTRIBUTE)
                    == value
            {
                record.fields.shift_remove(OBSERVED_CERTIFICATE_ATTRIBUTE);
                changed = true;
                what = format!(
                    "registered \"{}\" from the certificate the last signed \
                     request carried (it was OBSERVED and is trusted now)",
                    attribute
                );
            }
            if rra.contains(&attribute.as_str()) {
                if change.get("observed") == Some(&Value::Bool(true))
                    && self.env.mode("acceptsUnregisteredAddresses")
                {
                    if self.mark_observed_addresses(
                        &mut record,
                        &attribute,
                        &before,
                    ) {
                        changed = true;
                        what.push_str(
                            ", marked as OBSERVED rather than registered",
                        );
                    }
                } else if clear_observed_mark(&mut record, &attribute, &value)
                {
                    changed = true;
                    if before.contains(&value) {
                        what = format!(
                            "confirmed \"{}\" on {} (it was there as an \
                             OBSERVED address and is registered now)",
                            value, attribute
                        );
                    }
                }
            }
        } else {
            let unmarked = rra.contains(&attribute.as_str())
                && clear_observed_mark(&mut record, &attribute, &value);
            let have = values_of(record.fields.get(&attribute));
            let left: Vec<String> =
                have.iter().filter(|one| **one != value).cloned().collect();
            changed = unmarked || left.len() != have.len();
            if left.is_empty() {
                record.fields.shift_remove(&attribute);
            } else {
                record.fields.insert(attribute.clone(), list(left));
            }
            what = format!("removed \"{}\" from {}", value, attribute);
        }
        if attribute == "oauthTokenEndpointAuthMethod"
            && values::record_oauth_confidential(&mut record, None)
        {
            changed = true;
            what = format!(
                "{}oauthConfidential is now \"{}\"",
                if what.is_empty() {
                    String::new()
                } else {
                    format!("{}, and ", what)
                },
                first_of(&record.fields, "oauthConfidential")
            );
        }
        if !changed {
            return Marked::ok(json!({
                "ok": true,
                "changed": false,
                "application": self.view_after_write(identifier, &record),
                "message": format!(
                    "Nothing changed: {} already said that.",
                    attribute
                ),
            }));
        }
        let hosted = values::is_hosted_session_client(identifier)
            && values::hosted_bound_attribute(&attribute);
        if hosted {
            if let Some(bound) = values::hosted_session_bound_refusal(
                self,
                identifier,
                &attribute,
                &value,
                change.get("confirm"),
            ) {
                return refused(bound.code, vec![bound.message]);
            }
        }
        if record.last_at == 0 {
            record.last_at = self.env.now_ms();
        }
        self.save(&mut record, &How::actor(&actor));
        let mut d = json!({ "identifier": identifier, "attribute": attribute,
                            "mode": mode, "editedByHand": true });
        if hosted {
            d["hostedSessionBound"] = Value::Bool(true);
        }
        self.effects.audit(&json!({
            "action": "application.update",
            "actor": actor,
            "protocol": "console",
            "channel": "internal",
            "target": identifier,
            "summary": format!("Application \"{}\": {}", identifier, what),
            "detail": d,
        }));
        if mode == "remove" {
            self.announce_scope_removal(identifier, &record, &attribute, &value);
        }
        if GNAP_KEY_ATTRIBUTES.contains(&attribute.as_str()) {
            self.end_gnap_grants(identifier, true, &actor);
        }
        Marked::ok(json!({
            "ok": true,
            "changed": true,
            "application": self.view_after_write(identifier, &record),
            "message": format!("{}.", what),
        }))
    }

    // `endGnapGrants(identifier, keyChanged, actor)`.
    fn end_gnap_grants(
        &self,
        identifier: &str,
        key_changed: bool,
        actor: &str,
    ) -> i64 {
        let how = json!({
            "why": if key_changed {
                "its client's key was removed or replaced on its application \
                 entry"
            } else {
                "its client's application entry was deleted"
            },
            "actor": actor,
            "via": "the application registry",
            "initiatingEntity": "admin",
        });
        self.effects.end_gnap_grants(identifier, key_changed, &how)
    }

    // `announceScopeRemoval(identifier, record, attribute, value)`.
    fn announce_scope_removal(
        &self,
        identifier: &str,
        record: &Record,
        attribute: &str,
        value: &str,
    ) {
        if attribute == "oauthDelegatedPermission" {
            let enforced = !self.env.mode("honoursUngrantedPermissions")
                || crate::js::truthy(
                    &self.env.setting("oauth2.delegatedPermissionsEnforced"),
                );
            if !enforced {
                return;
            }
            if let Some(defined) = self.for_permission(value) {
                let base = crate::js::or_empty(defined.get("baseUri"));
                if !base.is_empty() {
                    let name = crate::js::or_empty(defined.get("name"));
                    self.effects
                        .claims_fan_out(identifier, attribute, &name, &base);
                }
            }
        } else if attribute == "oauthPermission" {
            let base = crate::app_permissions::permission_base_of(
                record.fields.get("oauthPermissionBaseUri"),
            );
            let removed = checks::uris::parse_permission_value(value).name;
            if !base.is_empty() && !removed.is_empty() {
                self.effects
                    .claims_fan_out(identifier, attribute, &removed, &base);
            }
        } else if attribute == "oauthAllowedScope"
            && !self.effects.scope_kept(value, identifier)
        {
            self.effects.claims_fan_out(identifier, attribute, value, "");
        }
    }

    /// `deleteApplication(identifier, {actor})`.
    #[tracing::instrument(level = "debug", skip(self, options))]
    pub fn delete_application(
        &self,
        identifier: &str,
        options: &Value,
    ) -> Marked {
        if self.directory.is_none() {
            return refused(
                codes::STS_REG_0002,
                vec!["There is no directory loaded in this process, so there \
                      is nothing to delete from."
                    .to_string()],
            );
        }
        let loaded = self.load(identifier);
        if !loaded.known {
            return refused(
                codes::STS_REG_0021,
                vec![format!(
                    "There is no application called \"{}\" here.",
                    identifier
                )],
            );
        }
        let actor = crate::js::or_empty(options.get("actor"));
        let policy = first_of(&loaded.record.fields, "appFgaPolicy");
        if !self.delete_application_entry(identifier) {
            return refused(
                codes::STS_REG_0022,
                vec![format!(
                    "The directory would not delete \"{}\".",
                    identifier
                )],
            );
        }
        self.effects.audit(&json!({
            "action": "application.delete",
            "actor": actor,
            "protocol": "console",
            "channel": "internal",
            "target": identifier,
            "summary": format!(
                "Application \"{}\" was deleted from the registry",
                identifier
            ),
            "detail": {
                "identifier": identifier,
                "authentications": loaded.record.authentications,
                "registered": loaded.record.registered,
            },
        }));
        self.end_gnap_grants(identifier, false, &actor);
        self.fga_hook("deleted", identifier, &actor, &policy);
        Marked::ok(json!({
            "ok": true,
            "message": format!(
                "\"{}\" is gone from the registry, along with what it had \
                 recorded: {} authentication(s) and whatever attributes it \
                 carried. It will reappear, empty, the next time that \
                 identifier is accepted by a protocol.",
                identifier, loaded.record.authentications
            ),
        }))
    }

    // `observedAddressRequest(identifier, change, verb)`.
    fn observed_address_request(
        &self,
        identifier: &str,
        change: &Value,
        verb: &str,
    ) -> Result<(Loaded, String, String, bool), Marked> {
        let attribute =
            crate::js::trim(&crate::js::or_empty(change.get("attribute")))
                .to_string();
        let value =
            crate::js::trim(&crate::js::unless_null(change.get("value")))
                .to_string();
        let loaded = self.load(identifier);
        if !loaded.known {
            return Err(Self::no_such(identifier));
        }
        let rra = &Tables::get().return_address_attributes;
        if !rra.contains(&attribute.as_str()) {
            return Err(refused(
                codes::STS_REG_0051,
                vec![format!(
                    "\"{}\" is not a return-address attribute, so nothing on \
                     it is ever marked as observed. The {} that are: {}.",
                    if attribute.is_empty() {
                        "(none)"
                    } else {
                        &attribute
                    },
                    crate::js::number_word(rra.len()),
                    rra.join(", ")
                )],
            ));
        }
        if value.is_empty() {
            return Err(refused(
                codes::STS_REG_0052,
                vec![format!(
                    "A value is required to {}: the address, exactly as \
                     appReturnAddressObserved holds it.",
                    verb
                )],
            ));
        }
        let rows = observed_return_addresses(&loaded.record.fields);
        let Some(row) = rows
            .iter()
            .find(|one| one.attribute == attribute && one.value == value)
        else {
            let marked: Vec<String> = rows
                .iter()
                .map(|one| observed_mark_for(&one.attribute, &one.value))
                .collect();
            let on_entry = values_of(loaded.record.fields.get(&attribute))
                .contains(&value);
            return Err(refused(
                codes::STS_REG_0050,
                vec![format!(
                    "\"{}\" on {} of \"{}\" is not marked as observed, so \
                     there is nothing to {}. {}{}",
                    value,
                    attribute,
                    identifier,
                    verb,
                    if on_entry {
                        format!(
                            "It is on the entry with no mark, which is what a \
                             registered address looks like — {}",
                            if verb == "discard" {
                                "take it off with `remove` if it should not \
                                 be there."
                            } else {
                                "product mode already believes it."
                            }
                        )
                    } else {
                        "It is not on the entry either.".to_string()
                    },
                    if marked.is_empty() {
                        " Nothing on this entry is marked observed."
                            .to_string()
                    } else {
                        format!(
                            " The addresses marked observed are: {}.",
                            marked.join(", ")
                        )
                    }
                )],
            ));
        };
        let held = row.held;
        Ok((loaded, attribute, value, held))
    }

    fn no_such(identifier: &str) -> Marked {
        refused(
            codes::STS_REG_0021,
            vec![format!(
                "There is no application called \"{}\" in this registry.",
                identifier
            )],
        )
    }

    // `saveObservedAddressChange(identifier, found, record, verb, what,
    // actor)`.
    #[allow(clippy::too_many_arguments)]
    fn save_observed_address_change(
        &self,
        identifier: &str,
        attribute: &str,
        address: &str,
        record: &mut Record,
        verb: &str,
        what: &str,
        actor: &str,
    ) -> Marked {
        if record.last_at == 0 {
            record.last_at = self.env.now_ms();
        }
        self.save(record, &How::default());
        self.effects.audit(&json!({
            "action": "application.update", "actor": actor,
            "protocol": "console", "channel": "internal",
            "target": identifier,
            "summary": format!("Application \"{}\": {}", identifier, what),
            "detail": { "identifier": identifier, "attribute": attribute,
                        "mode": format!("{}-address", verb),
                        "address": address, "editedByHand": true },
        }));
        Marked::ok(json!({
            "ok": true, "changed": true,
            "application": self.view_after_write(identifier, record),
            "message": format!("{}.", what),
        }))
    }

    /// `confirmReturnAddress(identifier, {attribute, value, actor})`.
    #[tracing::instrument(level = "debug", skip(self, change))]
    pub fn confirm_return_address(
        &self,
        identifier: &str,
        change: &Value,
    ) -> Marked {
        let (loaded, attribute, value, held) =
            match self.observed_address_request(identifier, change, "confirm")
            {
                Ok(f) => f,
                Err(m) => return m,
            };
        let mut record = loaded.record;
        clear_observed_mark(&mut record, &attribute, &value);
        let what = if held {
            format!(
                "confirmed \"{}\" on {}. It was recorded from a request in \
                 development mode and is now a registered address, which \
                 product mode believes from the next request",
                value, attribute
            )
        } else {
            format!(
                "took the observed mark off \"{}\" on {}. The address itself \
                 is no longer on the entry, so there was nothing to confirm \
                 and nothing is registered by this",
                value, attribute
            )
        };
        self.save_observed_address_change(
            identifier,
            &attribute,
            &value,
            &mut record,
            "confirm",
            &what,
            &crate::js::or_empty(change.get("actor")),
        )
    }

    /// `discardReturnAddress(identifier, {attribute, value, actor})`.
    #[tracing::instrument(level = "debug", skip(self, change))]
    pub fn discard_return_address(
        &self,
        identifier: &str,
        change: &Value,
    ) -> Marked {
        let (loaded, attribute, value, held) =
            match self.observed_address_request(identifier, change, "discard")
            {
                Ok(f) => f,
                Err(m) => return m,
            };
        let mut record = loaded.record;
        clear_observed_mark(&mut record, &attribute, &value);
        let left: Vec<String> = values_of(record.fields.get(&attribute))
            .into_iter()
            .filter(|one| *one != value)
            .collect();
        if left.is_empty() {
            record.fields.shift_remove(&attribute);
        } else {
            record.fields.insert(attribute.clone(), list(left));
        }
        let what = format!(
            "discarded \"{}\" from {}. It was recorded from a request in \
             development mode and nobody confirmed it, so it is gone from \
             the entry: product mode refuses it, and development records it \
             again, marked, if a request names it again{}",
            value,
            attribute,
            if held {
                ""
            } else {
                " (the address had already gone; only its mark was left)"
            }
        );
        self.save_observed_address_change(
            identifier,
            &attribute,
            &value,
            &mut record,
            "discard",
            &what,
            &crate::js::or_empty(change.get("actor")),
        )
    }

    /// `ownersOf(source)`: each `appOwner` resolved, `present` false for a
    /// DN that names nobody now.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn owners_of(&self, fields: &Fields) -> Vec<Value> {
        values_of(fields.get("appOwner"))
            .into_iter()
            .map(|dn| {
                let found = self.resolve_owner(&dn);
                json!({
                    "dn": if found.kind.is_empty() { dn } else { found.dn },
                    "kind": found.kind,
                    "name": found.name,
                    "present": !found.kind.is_empty(),
                })
            })
            .collect()
    }

    fn owners_of_identifier(&self, identifier: &str) -> Vec<Value> {
        let loaded = self.load(identifier);
        if loaded.known {
            self.owners_of(&loaded.record.fields)
        } else {
            Vec::new()
        }
    }

    /// `addOwner(identifier, owner)` (#604).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn add_owner(&self, identifier: &str, owner: &str) -> Marked {
        let loaded = self.load(identifier);
        if !loaded.known {
            return refused(
                codes::STS_REG_0353,
                vec![format!("There is no application \"{}\".", identifier)],
            );
        }
        let wanted = crate::js::trim(owner).to_string();
        if wanted.is_empty() {
            return refused(
                codes::STS_REG_0354,
                vec!["Who? Send `owner` with a person (a username or DN) or a \
                      group (its cn or DN) of this realm."
                    .to_string()],
            );
        }
        let resolved = self.resolve_owner(&wanted);
        if resolved.kind.is_empty() {
            return refused(
                codes::STS_REG_0355,
                vec![format!(
                    "\"{}\" names no person and no group in this realm. An \
                     owner answers for the application, so it must name \
                     somebody.",
                    crate::js::slice_utf16(&wanted, 128)
                )],
            );
        }
        let mut record = loaded.record;
        let before = self.owners_of(&record.fields);
        let mut held = values_of(record.fields.get("appOwner"));
        let label = if resolved.name.is_empty() {
            resolved.dn.clone()
        } else {
            resolved.name.clone()
        };
        if held
            .iter()
            .any(|dn| owner_lower(dn) == owner_lower(&resolved.dn))
        {
            return Marked::ok(json!({
                "ok": true, "changed": false,
                "application": record.identifier,
                "owner": resolved.dn, "owners": before,
                "message": format!(
                    "{} was already an owner of {}.",
                    label, record.identifier
                ),
            }));
        }
        if held.len() >= MAX_OWNERS {
            return refused(
                codes::STS_REG_0356,
                vec![format!(
                    "{} already names {} owners, the most an application may \
                     name ({}). Name a group of them instead.",
                    record.identifier,
                    held.len(),
                    MAX_OWNERS
                )],
            );
        }
        held.push(resolved.dn.clone());
        record.fields.insert("appOwner".into(), list(held));
        if !self.save(&mut record, &How::quiet()) {
            return refused(
                codes::STS_REG_0358,
                vec![format!(
                    "The owner could not be written onto {}.",
                    record.identifier
                )],
            );
        }
        Marked::ok(json!({
            "ok": true, "changed": true,
            "application": record.identifier,
            "owner": resolved.dn,
            "owners": self.owners_of_identifier(&record.identifier),
            "message": format!(
                "{} is now an owner of {}.",
                label, record.identifier
            ),
        }))
    }

    /// `removeOwner(identifier, owner)` (#604).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn remove_owner(&self, identifier: &str, owner: &str) -> Marked {
        let loaded = self.load(identifier);
        if !loaded.known {
            return refused(
                codes::STS_REG_0353,
                vec![format!("There is no application \"{}\".", identifier)],
            );
        }
        let mut record = loaded.record;
        let wanted = crate::js::trim(owner).to_string();
        let held = values_of(record.fields.get("appOwner"));
        let kept: Vec<String> = held
            .iter()
            .filter(|dn| owner_lower(dn) != owner_lower(&wanted))
            .cloned()
            .collect();
        if wanted.is_empty() || kept.len() == held.len() {
            return refused(
                codes::STS_REG_0357,
                vec![format!(
                    "\"{}\" is not one of {}'s owners.",
                    crate::js::slice_utf16(&wanted, 128),
                    record.identifier
                )],
            );
        }
        record.fields.insert("appOwner".into(), list(kept));
        if !self.save(&mut record, &How::quiet()) {
            return refused(
                codes::STS_REG_0358,
                vec![format!(
                    "The owners could not be written onto {}.",
                    record.identifier
                )],
            );
        }
        Marked::ok(json!({
            "ok": true, "changed": true,
            "application": record.identifier,
            "owner": wanted,
            "owners": self.owners_of_identifier(&record.identifier),
            "message": format!(
                "{} is no longer an owner of {}.",
                wanted, record.identifier
            ),
        }))
    }

    // `replaceOwner(from, to)`: every entry naming `from` rewritten.
    fn replace_owner(&self, from: &str, to: &str) -> Vec<String> {
        let was = owner_lower(crate::js::trim(from));
        let now = crate::js::trim(to).to_string();
        if was.is_empty()
            || was == owner_lower(&now)
            || self.directory.is_none()
        {
            return Vec::new();
        }
        let named: Vec<String> = self
            .listing_records()
            .into_iter()
            .filter(|r| {
                values_of(r.fields.get("appOwner"))
                    .iter()
                    .any(|one| owner_lower(crate::js::trim(one)) == was)
            })
            .map(|r| r.identifier)
            .collect();
        let mut changed = Vec::new();
        for identifier in named {
            let loaded = self.load(&identifier);
            if !loaded.known {
                continue;
            }
            let mut record = loaded.record;
            let mut owners: Vec<String> = Vec::new();
            for one in values_of(record.fields.get("appOwner")) {
                let value = if owner_lower(crate::js::trim(&one)) == was {
                    now.clone()
                } else {
                    one.clone()
                };
                if !value.is_empty()
                    && !owners
                        .iter()
                        .any(|o| owner_lower(o) == owner_lower(&value))
                {
                    owners.push(value);
                }
            }
            record.fields.insert("appOwner".into(), list(owners));
            if self.save(&mut record, &How::quiet()) {
                changed.push(identifier);
            } else {
                tracing::error!(
                    "{}applications: could not rewrite the owner {} on {}.",
                    sts_core::log::tag(codes::STS_ADMIN_0922),
                    from,
                    identifier
                );
            }
        }
        changed
    }

    /// `forgetOwner(dn)`: a deleted person or group off every entry.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn forget_owner(&self, dn: &str) -> Vec<String> {
        self.replace_owner(dn, "")
    }

    /// `renameOwner(from, to)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn rename_owner(&self, from: &str, to: &str) -> Vec<String> {
        if crate::js::trim(to).is_empty() {
            Vec::new()
        } else {
            self.replace_owner(from, to)
        }
    }

    /// `ownerProtected(identifier)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn owner_protected(&self, identifier: &str) -> bool {
        let loaded = self.load(identifier);
        loaded.known
            && first_of(&loaded.record.fields, "stsOwnerProtected")
                .to_uppercase()
                == "TRUE"
    }

    /// `setOwnerProtected(identifier, flag)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn set_owner_protected(&self, identifier: &str, flag: bool) -> Marked {
        let loaded = self.load(identifier);
        if !loaded.known {
            return refused(
                codes::STS_REG_0353,
                vec![format!("There is no application \"{}\".", identifier)],
            );
        }
        let mut record = loaded.record;
        if self.owner_protected(&record.identifier) == flag {
            return Marked::ok(json!({
                "ok": true, "changed": false,
                "application": record.identifier, "ownerProtected": flag,
            }));
        }
        record.fields.insert(
            "stsOwnerProtected".into(),
            if flag { json!(["TRUE"]) } else { json!([]) },
        );
        if !self.save(&mut record, &How::quiet()) {
            return refused(
                codes::STS_REG_0358,
                vec![format!(
                    "The mark could not be written onto {}.",
                    record.identifier
                )],
            );
        }
        Marked::ok(json!({
            "ok": true, "changed": true,
            "application": record.identifier, "ownerProtected": flag,
        }))
    }

    /// `fgaStateOf(identifier)`: `{known, policy, enforced}`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn fga_state_of(&self, identifier: &str) -> Value {
        let loaded = self.load(identifier);
        if !loaded.known {
            return json!({ "known": false, "policy": "", "enforced": false });
        }
        let f = &loaded.record.fields;
        json!({
            "known": true,
            "policy": first_of(f, "appFgaPolicy"),
            "enforced": first_of(f, "appFgaEnforced").to_uppercase() == "TRUE",
        })
    }

    /// `setFgaState(identifier, {policy, enforced}, {actor})` (#564).
    #[tracing::instrument(level = "debug", skip(self, change, options))]
    pub fn set_fga_state(
        &self,
        identifier: &str,
        change: &Value,
        options: &Value,
    ) -> Marked {
        let loaded = self.load(identifier);
        if !loaded.known {
            return refused(
                codes::STS_FGA_0009,
                vec![format!(
                    "There is no application called \"{}\" in this realm.",
                    identifier
                )],
            );
        }
        let actor = crate::js::or_empty(options.get("actor"));
        let mut record = loaded.record;
        let mut touched: Vec<&str> = Vec::new();
        if let Some(p) = change.get("policy") {
            let policy = crate::js::or_empty(Some(p));
            if first_of(&record.fields, "appFgaPolicy") != policy {
                if policy.is_empty() {
                    record.fields.shift_remove("appFgaPolicy");
                } else {
                    record.fields.insert("appFgaPolicy".into(), json!(policy));
                }
                touched.push("appFgaPolicy");
            }
        }
        if let Some(e) = change.get("enforced") {
            let enforced = if crate::js::truthy(e) { "TRUE" } else { "FALSE" };
            let now = first_of(&record.fields, "appFgaEnforced");
            let now = if now.is_empty() {
                "FALSE".to_string()
            } else {
                now
            };
            if now.to_uppercase() != enforced {
                record.fields.insert("appFgaEnforced".into(), json!(enforced));
                touched.push("appFgaEnforced");
            }
        }
        if touched.is_empty() {
            return Marked::ok(json!({ "ok": true, "changed": false }));
        }
        if !self.save(&mut record, &How::actor(&actor)) {
            return refused(
                codes::STS_FGA_0012,
                vec![format!(
                    "The directory would not write {} on \"{}\".",
                    touched.join(" and "),
                    identifier
                )],
            );
        }
        let asked_policy = crate::js::or_empty(change.get("policy"));
        let summary = if touched.contains(&"appFgaEnforced") {
            if change.get("enforced").is_some_and(crate::js::truthy) {
                "enforced".to_string()
            } else {
                "not enforced".to_string()
            }
        } else if asked_policy.is_empty() {
            "policy cleared".to_string()
        } else {
            format!("policy set to \"{}\"", asked_policy)
        };
        self.effects.audit(&json!({
            "action": "application.update", "actor": actor,
            "protocol": "console", "channel": "internal",
            "target": identifier,
            "summary": format!(
                "Application \"{}\": fine-grained authorization {}",
                identifier, summary
            ),
            "detail": { "identifier": identifier, "attributes": touched,
                        "mode": "fga" },
        }));
        Marked::ok(json!({ "ok": true, "changed": true }))
    }
}

/// `ownerLower(dn)`: lower-cased, the spaces around every comma gone.
#[tracing::instrument(level = "debug")]
pub fn owner_lower(dn: &str) -> String {
    let lower = dn.to_lowercase();
    let chars: Vec<char> = lower.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == ',' || crate::js::is_space(chars[i]) {
            // A run of spaces, a comma, a run of spaces is one comma; a run
            // of spaces with no comma in it stays.
            let start = i;
            let mut j = i;
            while j < chars.len() && crate::js::is_space(chars[j]) {
                j += 1;
            }
            if j < chars.len() && chars[j] == ',' {
                j += 1;
                while j < chars.len() && crate::js::is_space(chars[j]) {
                    j += 1;
                }
                out.push(',');
                i = j;
                continue;
            }
            out.extend(&chars[start..j.max(start + 1)]);
            i = j.max(start + 1);
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

// `changeTypeOf(from, to)`.
fn change_type_of(from: &str, to: &str) -> &'static str {
    match (from.is_empty(), to.is_empty()) {
        (true, false) => "create",
        (false, true) => "revoke",
        _ if from != to => "update",
        _ => "",
    }
}
