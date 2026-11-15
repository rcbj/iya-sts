// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE PASSKEY DOORS' PORTS, OVER WHAT THE RUNTIME HOLDS (#444, phase 5,
//! the `passkeys` slice): what [`crate::wiring::SignInStack::declare`]
//! builds the WebAuthn policy, the key doors and the ceremony log over.
//!
//! | Port | Answered with |
//! |---|---|
//! | `PolicySource` | the settings and mode, and the stored passkey profiles read by `sts-policy`'s passkey kind over the live directory's `ou=passkeyPolicies` |
//! | `KeyPorts` | the live directory's `stsWebauthnCredential` and user-handle attributes (`writeWebauthn()`, `readWebauthnUserHandle()`, `writeWebauthnUserHandle()`, `webauthnUserHandleOwner()`), a process's claims and counters, and the ceremony log |
//! | `AttestationPorts` | the WebAuthn policy's attestation settings; no FIDO metadata BLOB, no Android status list and no revocation service is loaded in this runtime, so each answers as Node does with none loaded |
//! | `AuditSink` | the audit log (`sts-audit`) the runtime hands in, else the log |
//! | `PostLogin` | a process's progress rows; no post-login policy is read here, so none is ever due |
//!
//! WHAT REPLACED WHAT, AND WHAT IS OWED. Node's `claims.claim()` and
//! `counters.advance()` are `cluster/claims.ts` and `cluster/counters.ts`,
//! held in the store across nodes; here they are one process's maps, which
//! is the whole cluster of a single-node runtime. A multi-node runtime owes
//! them the store's claim and counter rows (`sts-cluster`). The owner of a
//! user handle is found by a walk of the realm's people where Node keeps an
//! index (`userHandleIndexes()`), owed the same index.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::{json, Map, Value as Json};
use sts_core::mode::Mode;
use sts_core::realm::RealmRegistry;
use sts_core::settings::Settings;
use sts_credentials::ports::Hook;
use sts_credentials::webauthn::ceremonies::{AuditSink, Ceremonies};
use sts_credentials::webauthn::enrolment::KeyPorts;
use sts_credentials::webauthn::policy::{PolicySource, WebauthnPolicy};
use sts_credentials::webauthn::trust::{
    AndroidStatus, AttestationPorts, Metadata, Revocation,
};
use sts_policy::js::Object;
use sts_policy::kinds::passkey::PasskeyPolicy;
use sts_policy::ports::{
    ApplicationRegister, Container, GroupReference, OfferedRow, PeopleNaming,
    PolicyDirectory, PolicyEntry, PolicyEnvironment, Ports, RealmFacts,
    WriteOutcome,
};
use sts_store::persistence::{LiveDirectory, MemoryDirectory};

use crate::ports::PostLogin;
use crate::wiring::{DirectoryPorts, Environment};

fn first(
    attributes: &indexmap::IndexMap<String, Vec<String>>,
    name: &str,
) -> String {
    attributes
        .get(&name.to_ascii_lowercase())
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_default()
}

/// The stored passkey profiles, as `sts-policy`'s passkey kind reads them:
/// the realm's `ou=passkeyPolicies`, read only.
pub struct PasskeyProfiles {
    pub directory: Arc<MemoryDirectory>,
    pub registry: Arc<RealmRegistry>,
    pub settings: Arc<Settings>,
    pub mode: Arc<Mode>,
}

impl PasskeyProfiles {
    fn base_of(&self, realm: &str) -> String {
        let found = self
            .registry
            .list()
            .into_iter()
            .find(|r| r.id == realm)
            .unwrap_or_else(sts_core::realm::current);
        self.registry.base_dn_of(&found)
    }
}

impl PolicyDirectory for PasskeyProfiles {
    fn installed(&self, container: Container) -> bool {
        container == Container::Passkey
    }

    fn entries(
        &self,
        realm: &str,
        container: Container,
    ) -> Option<Vec<PolicyEntry>> {
        if container != Container::Passkey {
            return None;
        }
        let under = format!(",ou=passkeypolicies,{}", self.base_of(realm))
            .to_lowercase();
        let rows = self
            .directory
            .realm_entries(realm)
            .into_iter()
            .filter(|(k, _)| k.ends_with(&under))
            .map(|(_, e)| {
                let mut attributes = Object::new();
                for (k, v) in &e.attributes {
                    attributes.insert(k.clone(), json!(v));
                }
                let cn = first(&e.attributes, "cn");
                PolicyEntry {
                    name: if cn.is_empty() {
                        e.dn.split(',')
                            .next()
                            .unwrap_or("")
                            .trim_start_matches("cn=")
                            .to_string()
                    } else {
                        cn
                    },
                    dn: e.dn.clone(),
                    attributes,
                }
            })
            .collect();
        Some(rows)
    }

    fn write(
        &self,
        _: &str,
        _: Container,
        _: &str,
        _: &Object,
    ) -> WriteOutcome {
        WriteOutcome::Full
    }

    fn delete(&self, _: &str, _: Container, _: &str) -> bool {
        false
    }

    fn person_group_references(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> Option<Vec<GroupReference>> {
        None
    }

    fn groups_naming_policy(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> Option<Vec<String>> {
        None
    }

    fn group_references(
        &self,
        _: &str,
        _: &[String],
        _: &str,
    ) -> Option<Vec<GroupReference>> {
        None
    }

    fn people_naming_policy(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> Option<PeopleNaming> {
        None
    }

    fn known_name(&self, _: &str, name: &str) -> String {
        name.to_string()
    }

    fn holders(&self, _: &str, _: &str) -> u64 {
        0
    }
}

impl ApplicationRegister for PasskeyProfiles {
    fn by_client_id(&self, _: &str, _: &str) -> Option<Object> {
        None
    }

    fn by_identifier(&self, _: &str, _: &str) -> Option<Object> {
        None
    }

    fn naming_policy(&self, _: &str, _: &str, _: &str) -> Vec<String> {
        Vec::new()
    }
}

impl PolicyEnvironment for PasskeyProfiles {
    fn setting(&self, _realm: &str, key: &str) -> Json {
        crate::wiring::json_of(self.settings.value_of(key))
    }

    fn verifies_credentials(&self, _: &str) -> bool {
        self.mode.predicate("verifiesCredentials").unwrap_or(false)
    }

    fn recovers_weaker_than_passkeys(&self, _: &str) -> bool {
        self.mode
            .predicate("recoversWeakerThanPasskeys")
            .unwrap_or(false)
    }

    fn creates_incomplete_people(&self, _: &str) -> bool {
        self.mode
            .predicate("createsIncompletePeople")
            .unwrap_or(false)
    }

    fn mail_available(&self, _: &str) -> bool {
        false
    }

    fn realm(&self, realm: &str) -> RealmFacts {
        RealmFacts {
            id: realm.to_string(),
            ..RealmFacts::default()
        }
    }

    fn authn_vocabularies(&self) -> (Vec<String>, Vec<String>) {
        (Vec::new(), Vec::new())
    }

    fn destination_count(&self, _: &str) -> i64 {
        -1
    }

    fn service_account_reference(&self, _: &str, _: &str) -> String {
        String::new()
    }

    fn service_accounts_naming(&self, _: &str, _: &str) -> Vec<String> {
        Vec::new()
    }

    fn is_service_account(&self, _: &str, _: &Object) -> bool {
        false
    }

    fn offers_post_quantum(
        &self,
        _: &str,
        _: &sts_policy::ports::RegistrationRows,
    ) -> bool {
        true
    }

    fn canonical_locale(&self, tag: &str) -> String {
        tag.to_string()
    }

    fn offered_attributes(&self, _: &str) -> Result<Vec<OfferedRow>, String> {
        Ok(Vec::new())
    }

    fn passkey_clients_act(
        &self,
        _: &str,
        _: &str,
        _: &Object,
    ) -> sts_policy::Answer {
        sts_policy::Answer::of(Json::Null)
    }
}

/// What the WebAuthn policy reads.
pub struct Source {
    pub env: Arc<Environment>,
    pub profiles: Arc<PasskeyProfiles>,
    pub directory: Arc<DirectoryPorts>,
}

impl Source {
    fn kind(&self) -> PasskeyPolicy<'_> {
        PasskeyPolicy::new(Ports {
            directory: self.profiles.as_ref(),
            applications: self.profiles.as_ref(),
            env: self.profiles.as_ref(),
        })
    }
}

impl PolicySource for Source {
    fn setting(&self, key: &str) -> Json {
        self.env.setting(key)
    }

    fn value_in_force(&self, key: &str) -> Json {
        crate::wiring::json_of(self.env.mode.value_in_force(key))
    }

    fn predicate(&self, name: &str) -> bool {
        self.env.predicate(name)
    }

    fn realm_id(&self) -> String {
        sts_core::realm::current_id()
    }

    fn realm_name(&self) -> String {
        sts_core::realm::current().name.clone()
    }

    fn profile(&self, name: &str) -> Json {
        self.kind().read(&sts_core::realm::current_id(), Some(name))
    }

    fn selection_for(&self, username: &str, application: &str) -> String {
        self.kind().selection_for(
            &sts_core::realm::current_id(),
            username,
            application,
        )
    }

    fn authn_allows(&self, mechanism: &str, _role: &str) -> bool {
        !matches!(mechanism, "emailCode" | "emailLink")
    }

    fn person_attribute_values(
        &self,
        username: &str,
        attribute: &str,
    ) -> Vec<String> {
        self.directory
            .person_attribute(username, attribute)
            .unwrap_or_default()
    }
}

/// The audit rows the ceremony log writes: to the audit log, or to the
/// log where the runtime handed none.
pub struct LogAudit(pub Option<Arc<sts_audit::AuditLog>>);

impl AuditSink for LogAudit {
    fn audit(&self, row: &Json) {
        match &self.0 {
            Some(log) => {
                log.audit(row);
            }
            None => tracing::info!("audit: {}", row),
        }
    }
}

/// A process's claims and counters (`cluster/claims.ts`,
/// `cluster/counters.ts` with one node).
#[derive(Default)]
pub struct LocalCoordination {
    claims: Mutex<HashMap<String, f64>>,
    counters: Mutex<HashMap<String, f64>>,
}

/// The key doors' ports.
pub struct KeyStore {
    pub directory: Arc<DirectoryPorts>,
    pub ceremonies: Arc<Ceremonies>,
    pub coordination: Arc<LocalCoordination>,
}

impl KeyPorts for KeyStore {
    fn client_name(&self) -> String {
        String::new()
    }

    fn learned_entry(&self, _client: &str) -> Json {
        Json::Null
    }

    fn mds_usable(&self) -> bool {
        false
    }

    fn lookup_authenticator(
        &self,
        _aaguid: &str,
    ) -> Result<Option<Json>, String> {
        Ok(None)
    }

    fn claim(
        &self,
        scope: &str,
        value: &str,
        ttl_ms: f64,
        realm: &str,
    ) -> Json {
        let now = sts_core::time::now_ms_f64();
        let key = format!("{realm}\u{0}{scope}\u{0}{value}");
        let mut held = self
            .coordination
            .claims
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        held.retain(|_, until| *until > now);
        if held.contains_key(&key) {
            return json!({ "ok": false, "reason": "used" });
        }
        held.insert(key.clone(), now + ttl_ms);
        json!({ "ok": true, "handle": key })
    }

    fn release(&self, handle: &Json) {
        if let Some(key) = handle.as_str() {
            self.coordination
                .claims
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(key);
        }
    }

    fn advance(&self, scope: &str, key: &str, value: f64, realm: &str) -> Json {
        let slot = format!("{realm}\u{0}{scope}\u{0}{key}");
        let mut held = self
            .coordination
            .counters
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // `cluster_counters.js`'s `verdictOf()`: advanced where it goes
        // above the highest; a counter that is always zero stands.
        let highest = held.get(&slot).copied();
        if highest.is_none_or(|h| value > h) {
            held.insert(slot, value);
            return json!({ "ok": true, "advanced": true, "highest": value });
        }
        let highest = highest.unwrap_or(0.0);
        if value == 0.0 && highest == 0.0 {
            return json!({ "ok": true, "advanced": false, "highest": 0 });
        }
        json!({ "ok": false, "reason": "behind", "highest": highest })
    }

    fn ceremony(&self, row: &Json) {
        self.ceremonies.record(row, sts_core::time::now_ms_f64());
    }

    fn possibly_replaced(&self, facts: &Json) {
        self.ceremonies.possibly_replaced(facts);
    }

    fn credential_compromised(&self, facts: &Json) -> bool {
        tracing::info!("risc: a credential compromised: {}", facts);
        false
    }

    fn authenticator_compromised(&self, facts: &Json) {
        tracing::info!("risk: an authenticator compromised: {}", facts);
    }

    fn android_registration(&self, _what: &str) {}

    fn writes_keys(&self) -> bool {
        true
    }

    fn reads_user_handles(&self) -> bool {
        true
    }

    fn writes_user_handles(&self) -> bool {
        true
    }

    fn reads_user_handle_owners(&self) -> bool {
        true
    }

    fn write_webauthn(&self, name: &str, value: &str) -> Hook<bool> {
        let mut values = self
            .directory
            .person_attribute(name, "stsWebauthnCredential")
            .unwrap_or_default();
        values.push(value.to_string());
        self.directory.write_attribute(
            name,
            "stsWebauthnCredential",
            Some(values),
        )
    }

    fn read_user_handle(&self, name: &str, lane: &str) -> Hook<String> {
        Ok(self
            .directory
            .person_attribute(name, handle_attribute(lane))
            .and_then(|v| v.into_iter().next())
            .unwrap_or_default())
    }

    fn write_user_handle(
        &self,
        name: &str,
        handle: &str,
        lane: &str,
    ) -> Hook<bool> {
        let attribute = handle_attribute(lane);
        if attribute != "stsWebauthnUserHandle"
            && self
                .directory
                .person_attribute(name, "stsWebauthnUserHandle")
                .and_then(|v| v.into_iter().next())
                .unwrap_or_default()
                .is_empty()
        {
            return Ok(false);
        }
        self.directory.write_attribute(
            name,
            attribute,
            Some(vec![handle.to_string()]),
        )
    }

    fn user_handle_owner(&self, handle: &str) -> Hook<String> {
        Ok(self.directory.user_handle_owner(handle))
    }
}

/// `userHandleAttribute(lane)`.
fn handle_attribute(lane: &str) -> &'static str {
    if lane == "pqc" {
        "stsWebauthnPqcUserHandle"
    } else {
        "stsWebauthnUserHandle"
    }
}

/// No FIDO metadata BLOB is loaded here.
pub struct NoMetadata;

impl Metadata for NoMetadata {
    fn lookup_authenticator_by(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<Json>, String> {
        Ok(None)
    }
}

impl AndroidStatus for NoMetadata {
    fn lookup_attestation_serials(&self, _: &[String]) -> Result<Json, String> {
        Ok(json!({ "checked": false, "version": "", "hits": [],
                   "why": "no list" }))
    }
}

impl Revocation for NoMetadata {
    fn verdict_for(&self, _: &str, _: &[String]) -> Result<Json, String> {
        Ok(Json::Null)
    }
}

/// The attestation's ports.
pub struct AttestationOver {
    pub webauthn: Arc<WebauthnPolicy>,
    pub env: Arc<Environment>,
    pub none: NoMetadata,
}

impl AttestationPorts for AttestationOver {
    fn settings(&self) -> Json {
        self.webauthn.attestation_settings()
    }

    fn insecure_allowed(&self) -> bool {
        self.webauthn.insecure_algorithms_allowed()
    }

    fn now_ms(&self) -> f64 {
        sts_core::time::now_ms_f64()
    }

    fn metadata(&self) -> &dyn Metadata {
        &self.none
    }

    fn revocation(&self) -> &dyn Revocation {
        &self.none
    }

    fn android_status(&self) -> &dyn AndroidStatus {
        &self.none
    }

    fn refuses_unchecked_android_revocation(&self) -> bool {
        self.env.predicate("refusesUncheckedAttestationRevocation")
    }
}

/// The post-login progress rows of one process.
#[derive(Default)]
pub struct LocalPostLogin {
    rows: Mutex<HashMap<String, Json>>,
}

impl LocalPostLogin {
    fn row(&self, username: &str, due: &Json) -> (String, Json) {
        let key = format!(
            "{}\u{0}{}\u{0}{}",
            sts_core::realm::current_id(),
            username,
            due.get("activity").and_then(Json::as_str).unwrap_or("")
        );
        let row = self
            .rows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
            .cloned()
            .unwrap_or_else(|| json!({}));
        (key, row)
    }

    fn put(&self, key: String, row: Json) {
        self.rows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key, row);
    }
}

impl PostLogin for LocalPostLogin {
    fn note_asked(&self, username: &str, due: &Json) -> Json {
        let now = sts_core::time::now_ms_f64().floor();
        let (key, mut row) = self.row(username, due);
        if row.get("invitedAt").and_then(Json::as_f64).unwrap_or(0.0) == 0.0 {
            row["invitedAt"] = json!(now as i64);
        }
        row["asks"] =
            json!(row.get("asks").and_then(Json::as_f64).unwrap_or(0.0) + 1.0);
        self.put(key, row.clone());
        row
    }

    fn note_skipped(&self, username: &str, due: &Json) -> Json {
        if due.get("required") == Some(&Json::Bool(true)) {
            return json!({ "ok": false });
        }
        let now = sts_core::time::now_ms_f64().floor();
        let (key, mut row) = self.row(username, due);
        let days = due
            .get("snoozeDays")
            .and_then(Json::as_f64)
            .filter(|d| *d != 0.0)
            .unwrap_or(1.0);
        let until = now + days * 24.0 * 60.0 * 60.0 * 1000.0;
        row["snoozedUntil"] = json!(until as i64);
        self.put(key, row);
        json!({ "ok": true, "snoozedUntil": until as i64 })
    }

    fn note_done(&self, username: &str, due: &Json) {
        let now = sts_core::time::now_ms_f64().floor();
        let (key, mut row) = self.row(username, due);
        row["doneAt"] = json!(now as i64);
        row["snoozedUntil"] = json!(0);
        self.put(key, row);
    }
}

/// The facts a sign-in step reads of the passkey policy's settings
/// (`webauthnPolicy.settings()`'s `{ enabled, mfaAllowed,
/// primaryAllowed, usernameless }`).
#[tracing::instrument(level = "trace", skip_all)]
pub fn key_policy_of(webauthn: &WebauthnPolicy) -> Json {
    let s = webauthn.settings();
    let mut out = Map::new();
    for k in ["enabled", "mfaAllowed", "primaryAllowed", "usernameless"] {
        out.insert(k.into(), s[k].clone());
    }
    Json::Object(out)
}
