// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE COMPOSITION ROOT'S ONE CALL (`common/protocol_stack.ts`'s `8` and
//! `8-api`: `authn/authn`, then `authn/authn_api`): the session core, the
//! credentials and the sign-in surface built over what the runtime holds —
//! the settings, the mode, the realms, the declared stores, the live
//! directory and the keystore — and the two things mounted.
//!
//! [`SignInStack::declare`] runs BEFORE the store opens (the stores it
//! declares are restored from what a node wrote); [`SignInStack::mount`]
//! after the HTTP layer is built.
//!
//! WHAT EACH PORT IS ANSWERED WITH. The directory's — a person's entry,
//! their subject, their password, authenticator app, recovery codes and
//! keys — are the live directory's ([`DirectoryPorts`], over
//! `sts_store::persistence::MemoryDirectory`, a write marked for the next
//! flush). The settings and the mode are `sts-core`'s. The rest are
//! families later phases port, answered as Node answers them where that
//! family has nothing configured, each said at its port below:
//!
//! * the issuance gate allows (rule 3v: an empty decider means issue — the
//!   XACML engine is not armed in this runtime yet);
//! * the authentication policy is the built-in profile (`if-held`,
//!   `offer`; a password and every key use allowed, the emailed factors
//!   not), with product mode's "everybody" (#1490) and
//!   `authn.allowOptionalSecondFactor`;
//! * no device is recognised, no risk is assessed, no attribute source is
//!   read, no browser is remembered, no client display is registered, no
//!   service account and no console role is known;
//! * the identity register's refusal rows and the audit rows go to the
//!   log (`sts-audit` is not in the runtime yet).

use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_authn::ports::{self as authn_ports, Request, Response};
use sts_authn::{Sessions, SessionsDeps};
use sts_core::errors::{codes, ErrorCode};
use sts_core::mode::Mode;
use sts_core::realm::RealmRegistry;
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::StoreHandles;
use sts_core::settings::{SettingValue, Settings};
use sts_credentials::credentials::{
    Credentials, CredentialsDeps, PendingStores as CredentialPending,
};
use sts_credentials::limits::{MemoryBuckets, RateLimiter};
use sts_credentials::ports::{self as cred_ports, Hook};
use sts_credentials::session_checks::SessionChecks;
use sts_store::model::StoredEntry;
use sts_store::persistence::{LiveDirectory, MemoryDirectory, Persistence};
use sts_store::shadow::EntryLookup;

use crate::door::AuthnApi;
use crate::flow::SignIn;
use crate::pending::PendingStores;
use crate::ports::SignInFacts;

/// A setting as Node's `config.value()` answers it.
fn json_of(value: SettingValue) -> Json {
    match value {
        SettingValue::Text(t) => Json::String(t),
        SettingValue::Int(n) => json!(n),
        SettingValue::Bool(b) => Json::Bool(b),
        SettingValue::List(l) => json!(l),
    }
}

/// The settings, the mode and the clock.
pub struct Environment {
    pub settings: Arc<Settings>,
    pub mode: Arc<Mode>,
    pub registry: Arc<RealmRegistry>,
}

impl Environment {
    fn setting(&self, key: &str) -> Json {
        json_of(self.settings.value_of(key))
    }

    fn predicate(&self, name: &str) -> bool {
        self.mode.predicate(name).unwrap_or(false)
    }
}

impl authn_ports::Settings for Environment {
    fn value(&self, key: &str) -> Json {
        self.setting(key)
    }

    fn cookie_domain_attribute(&self) -> String {
        let domain = self.settings.value_of("authn.cookieDomain");
        let domain = domain.as_str().trim();
        if domain.is_empty() {
            String::new()
        } else {
            format!("; Domain={}", domain)
        }
    }
}

impl authn_ports::ModeQuestions for Environment {
    fn verifies_credentials(&self) -> bool {
        self.predicate("verifiesCredentials")
    }

    fn revokes_access_tokens_at_sign_out(&self) -> bool {
        self.predicate("revokesAccessTokensAtSignOut")
    }
}

impl authn_ports::Realms for Environment {
    fn retiring_refusal(&self) -> Option<Json> {
        None
    }

    fn ids(&self) -> Vec<String> {
        self.registry.list().iter().map(|r| r.id.clone()).collect()
    }

    fn run_in(&self, _id: &str, work: &mut dyn FnMut()) {
        // The sweep's realm is entered by the caller's store view; the work
        // reads no ambient realm of its own here.
        work()
    }
}

impl cred_ports::Environment for Environment {
    fn setting(&self, key: &str) -> Json {
        Environment::setting(self, key)
    }

    fn predicate(&self, name: &str) -> bool {
        Environment::predicate(self, name)
    }

    fn now_ms(&self) -> f64 {
        sts_core::time::now_ms_f64()
    }

    fn realm_id(&self) -> String {
        sts_core::realm::current_id()
    }

    fn random_bytes(&self, n: usize) -> Vec<u8> {
        sts_crypto::random::random_bytes(n).unwrap_or_default()
    }

    fn random_int(&self, min: u64, max: u64) -> u64 {
        sts_crypto::random::random_int(min, max).unwrap_or(min)
    }

    fn hash_secret(&self, plaintext: &str) -> String {
        sts_crypto::secrets::hash_secret(
            plaintext,
            sts_crypto::secrets::ScryptCost::default(),
        )
        .unwrap_or_default()
    }
}

/// The live directory, as the session and the credentials read and write
/// a person's entry.
pub struct DirectoryPorts {
    pub directory: Arc<MemoryDirectory>,
    pub persistence: Arc<Persistence>,
    pub registry: Arc<RealmRegistry>,
    pub settings: Arc<Settings>,
    pub mode: Arc<Mode>,
}

fn first(entry: &StoredEntry, attribute: &str) -> Option<String> {
    entry
        .attributes
        .get(&attribute.to_ascii_lowercase())
        .and_then(|v| v.first())
        .cloned()
}

fn is_true(entry: &StoredEntry, attribute: &str) -> bool {
    first(entry, attribute).is_some_and(|v| v.eq_ignore_ascii_case("true"))
}

impl DirectoryPorts {
    fn realm(&self) -> (String, String) {
        let realm = sts_core::realm::current();
        (realm.id.clone(), self.registry.base_dn_of(&realm))
    }

    fn key_of(&self, name: &str) -> (String, String) {
        let (realm, base) = self.realm();
        (
            realm,
            format!("uid={},ou=users,{}", name.trim(), base).to_lowercase(),
        )
    }

    /// `existingUserEntry(name)`: the person's entry, by its `uid` DN.
    fn person(&self, name: &str) -> Option<(String, String, StoredEntry)> {
        if name.trim().is_empty() {
            return None;
        }
        let (realm, key) = self.key_of(name);
        self.directory
            .entry_at(&realm, &key)
            .map(|e| (realm, key, e))
    }

    fn write(
        &self,
        name: &str,
        attribute: &str,
        values: Option<Vec<String>>,
    ) -> Hook<bool> {
        let Some((realm, key, mut entry)) = self.person(name) else {
            return Ok(false);
        };
        let attr = attribute.to_ascii_lowercase();
        match values {
            Some(v) if !v.is_empty() => {
                entry.attributes.insert(attr, v);
            }
            _ => {
                entry.attributes.shift_remove(&attr);
            }
        }
        let stamp = chrono::Utc::now().format("%Y%m%d%H%M%SZ").to_string();
        entry
            .attributes
            .insert("modifytimestamp".into(), vec![stamp]);
        self.directory.put(&realm, entry);
        self.persistence.directory_changed(Some(&key));
        Ok(true)
    }

    fn entry_by_uuid(&self, subject: &str) -> Option<StoredEntry> {
        let wanted = subject.trim().to_lowercase();
        let wanted = wanted
            .strip_prefix("urn:uuid:")
            .unwrap_or(&wanted)
            .to_string();
        let (realm, base) = self.realm();
        let users = format!(",ou=users,{}", base).to_lowercase();
        self.directory
            .realm_entries(&realm)
            .into_iter()
            .find(|(k, e)| {
                k.ends_with(&users)
                    && first(e, "entryUUID")
                        .is_some_and(|u| u.to_lowercase() == wanted)
            })
            .map(|(_, e)| e)
    }
}

impl authn_ports::People for DirectoryPorts {
    fn user_for(&self, username: &str) -> Json {
        let typed = if username.is_empty() {
            "mock-user"
        } else {
            username
        };
        let sub = self.subject_for_name(typed);
        let filed = if sub.is_empty() {
            String::new()
        } else {
            self.name_for_subject(&sub)
        };
        let name = if filed.is_empty() {
            typed.to_string()
        } else {
            filed
        };
        let mut user =
            json!({ "sub": sub, "username": name, "preferred_username": name });
        if self.mode.predicate("inventsClaimValues").unwrap_or(false) {
            user["name"] = json!(format!("{} (mock)", name));
            user["given_name"] = json!(name);
            user["family_name"] = json!("Mock");
            user["email"] = json!(self.registry.invented_mail_of(&name));
            user["email_verified"] = json!(true);
        }
        user
    }

    fn subject_for_name(&self, name: &str) -> String {
        self.person(name)
            .and_then(|(_, _, e)| first(&e, "entryUUID"))
            .map(|u| format!("urn:uuid:{}", u.to_lowercase()))
            .unwrap_or_default()
    }

    fn name_for_subject(&self, subject: &str) -> String {
        self.entry_by_uuid(subject)
            .and_then(|e| first(&e, "uid"))
            .unwrap_or_default()
    }

    fn has_subject_resolver(&self) -> bool {
        true
    }
}

impl authn_ports::Accounts for DirectoryPorts {
    fn is_disabled(&self, who: &str) -> bool {
        self.person(who).is_some_and(|(_, _, e)| {
            first(&e, "pwdAccountLockedTime").is_some()
        })
    }

    fn service_account_refuses_door(
        &self,
        _username: &str,
        _door: &str,
    ) -> bool {
        false
    }
}

impl cred_ports::CredentialDirectory for DirectoryPorts {
    fn read_password(&self, name: &str) -> Hook<Option<String>> {
        Ok(self.person(name).and_then(|(_, _, e)| {
            first(&e, sts_credentials::credentials::PASSWORD_ATTRIBUTE)
        }))
    }

    fn write_password(
        &self,
        name: &str,
        hash: &str,
        history: Option<&[String]>,
    ) -> Hook<bool> {
        let done =
            self.write(name, "userPassword", Some(vec![hash.to_string()]))?;
        if let Some(h) = history {
            self.write(name, "pwdHistory", Some(h.to_vec()))?;
        }
        Ok(done)
    }

    fn read_password_reset(&self, name: &str) -> Hook<bool> {
        Ok(self
            .person(name)
            .is_some_and(|(_, _, e)| is_true(&e, "pwdReset")))
    }

    fn read_password_history(&self, name: &str) -> Hook<Vec<String>> {
        Ok(self
            .person(name)
            .and_then(|(_, _, e)| e.attributes.get("pwdhistory").cloned())
            .unwrap_or_default())
    }

    fn is_person(&self, name: &str) -> Hook<bool> {
        Ok(self.person(name).is_some())
    }

    fn person_exists(&self, name: &str) -> Hook<bool> {
        Ok(self.person(name).is_some())
    }

    fn read_account_disabled(&self, name: &str) -> Hook<bool> {
        Ok(authn_ports::Accounts::is_disabled(self, name))
    }

    fn read_mfa_required(&self, name: &str) -> Hook<bool> {
        Ok(self
            .person(name)
            .is_some_and(|(_, _, e)| is_true(&e, "stsMfaRequired")))
    }

    fn read_totp(&self, name: &str) -> Hook<Option<String>> {
        Ok(self.person(name).and_then(|(_, _, e)| {
            first(&e, sts_credentials::credentials::TOTP_ATTRIBUTE)
        }))
    }

    fn write_totp(&self, name: &str, value: Option<&str>) -> Hook<bool> {
        self.write(
            name,
            sts_credentials::credentials::TOTP_ATTRIBUTE,
            value.map(|v| vec![v.to_string()]),
        )
    }

    fn read_backup_codes(&self, name: &str) -> Hook<Option<String>> {
        Ok(self.person(name).and_then(|(_, _, e)| {
            first(&e, sts_credentials::credentials::BACKUP_CODES_ATTRIBUTE)
        }))
    }

    fn write_backup_codes(
        &self,
        name: &str,
        value: Option<&str>,
    ) -> Hook<bool> {
        self.write(
            name,
            sts_credentials::credentials::BACKUP_CODES_ATTRIBUTE,
            value.map(|v| vec![v.to_string()]),
        )
    }

    fn read_app_passwords(&self, name: &str) -> Hook<Option<String>> {
        Ok(self.person(name).and_then(|(_, _, e)| {
            first(&e, sts_credentials::credentials::APP_PASSWORDS_ATTRIBUTE)
        }))
    }

    fn write_app_passwords(
        &self,
        name: &str,
        value: Option<&str>,
    ) -> Hook<bool> {
        self.write(
            name,
            sts_credentials::credentials::APP_PASSWORDS_ATTRIBUTE,
            value.map(|v| vec![v.to_string()]),
        )
    }

    fn read_webauthn(&self, name: &str) -> Hook<Vec<Json>> {
        Ok(self
            .person(name)
            .and_then(|(_, _, e)| {
                e.attributes.get("stswebauthncredential").cloned()
            })
            .unwrap_or_default()
            .into_iter()
            .map(Json::String)
            .collect())
    }

    fn replace_webauthn(&self, name: &str, values: &[String]) -> Hook<Json> {
        let done =
            self.write(name, "stsWebauthnCredential", Some(values.to_vec()))?;
        Ok(json!({ "ok": done }))
    }

    fn read_recovery_pending(&self, name: &str) -> Hook<Option<String>> {
        Ok(self
            .person(name)
            .and_then(|(_, _, e)| first(&e, "stsRecoveryPending")))
    }

    fn write_recovery_pending(&self, name: &str, value: &str) -> Hook<bool> {
        self.write(
            name,
            "stsRecoveryPending",
            (!value.is_empty()).then(|| vec![value.to_string()]),
        )
    }
}

/// `common/keystore.js` over the store's data keys.
pub struct KeystorePort {
    pub persistence: Arc<Persistence>,
}

impl cred_ports::Keystore for KeystorePort {
    fn persists(&self) -> bool {
        self.persistence.data_keys().sealed()
    }

    fn seal(&self, plain: &str, label: &str, scope: &str) -> Option<String> {
        self.persistence.data_keys().seal(plain, label, scope)
    }

    fn open(&self, sealed: &str, label: &str) -> Option<String> {
        self.persistence.data_keys().open(sealed, label)
    }
}

/// The families not in this runtime yet, answered as Node answers them with
/// nothing configured (the module header lists them).
pub struct Unconfigured {
    pub env: Arc<Environment>,
}

impl Unconfigured {
    fn everyone(&self) -> bool {
        self.env.predicate("requiresSecondFactorOfEveryone")
    }

    fn key_setting(&self, key: &str, fallback: bool) -> bool {
        match self.env.setting(key) {
            Json::Bool(b) => b,
            _ => fallback,
        }
    }
}

impl authn_ports::SignInPolicy for Unconfigured {
    fn allows(&self, mechanism: &str, _role: &str) -> bool {
        !matches!(mechanism, "emailCode" | "emailLink")
    }

    fn declared_mechanisms(
        &self,
        _application: &str,
        _username: &str,
    ) -> Vec<String> {
        Vec::new()
    }

    fn mfa_allowed(&self, _application: &str, _username: &str) -> Vec<String> {
        Vec::new()
    }

    fn post_login_due(
        &self,
        _username: &str,
        _application: &str,
    ) -> Option<Json> {
        None
    }

    fn select_passkey_policy(&self, _username: &str, _application: &Json) {}
}

impl authn_ports::Gate for Unconfigured {
    fn check(&self, _ask: &Json) -> Json {
        json!({ "allowed": true, "why": "" })
    }

    fn device_requirement(&self) -> Vec<String> {
        Vec::new()
    }
}

impl authn_ports::Devices for Unconfigured {
    fn recognize(
        &self,
        _ask: &Json,
        _request: &Request,
    ) -> Result<Json, String> {
        Ok(Json::Null)
    }

    fn client_hello(&self, _request: &Request) -> Option<Json> {
        None
    }
}

impl authn_ports::Records for Unconfigured {
    fn record_authentication(&self, record: &Json, _request: Option<&Request>) {
        tracing::debug!(
            "authn: an authentication of {} recorded.",
            record.get("username").and_then(Json::as_str).unwrap_or("")
        );
    }

    fn revoke_session_tokens(
        &self,
        _sid: &str,
        _revokes_access: bool,
        _reason: &str,
        _opts: &Json,
        _tags: &[String],
    ) -> usize {
        0
    }

    fn record_account_choice(&self, kind: &str, n: Option<u64>) {
        tracing::debug!("authn: an account choice ({}, {:?}).", kind, n);
    }
}

impl authn_ports::AuditLog for Unconfigured {
    fn audit(&self, row: &Json) {
        tracing::info!("audit: {}", row);
    }
}

impl authn_ports::DeviceBinding for Unconfigured {
    fn offer(&self, _response: &mut Response, _session: &Json) {}

    fn honours(&self, _session: &Json, _request: Option<&Request>) -> bool {
        true
    }

    fn note_skipped(&self, _session: &Json, _request: Option<&Request>) {}

    fn binding_of(&self, _session: &Json) -> Json {
        Json::Null
    }
}

impl cred_ports::Policies for Unconfigured {
    fn allows(&self, mechanism: &str, _role: &str) -> bool {
        !matches!(mechanism, "emailCode" | "emailLink")
    }

    fn require_second_factor(&self) -> String {
        if self.everyone() { "always" } else { "if-held" }.into()
    }

    fn configured_second_factor(&self) -> String {
        "if-held".into()
    }

    fn require_second_factor_for_administrators(&self) -> String {
        if self.everyone() { "always" } else { "offer" }.into()
    }

    fn key_use_allowed(&self, key_use: &str) -> bool {
        self.key_setting("webauthn.enabled", true)
            && match key_use {
                "primary" => self.key_setting("webauthn.primaryAllowed", true),
                _ => self.key_setting("webauthn.mfaAllowed", true),
            }
    }

    fn password_profile_for(&self, _name: &str, _application: &str) -> Json {
        json!({})
    }

    fn password_hash_spec(&self, _profile: &Json) -> Json {
        json!({ "algorithm": "scrypt" })
    }

    fn password_problems(
        &self,
        _password: &str,
        _profile: &Json,
    ) -> Vec<String> {
        Vec::new()
    }

    fn password_history_value(&self, hash: &str) -> String {
        format!(
            "{}#1.3.6.1.4.1.1466.115.121.1.40#{}",
            chrono::Utc::now().format("%Y%m%d%H%M%SZ"),
            hash
        )
    }

    fn breach_screening(&self) -> bool {
        false
    }

    fn breach_verdict(&self, _password: &str) -> Option<bool> {
        None
    }
}

impl cred_ports::ServiceAccounts for Unconfigured {
    fn is_service_account_name(&self, _name: &str) -> bool {
        false
    }

    fn refuses_door(&self, _name: &str, _door: &str) -> bool {
        false
    }

    fn exempt_from_second_factor(&self, _name: &str) -> bool {
        false
    }

    fn rotates_through_destination(&self, _name: &str) -> bool {
        false
    }

    fn previous_password_hash(&self, _name: &str) -> Hook<Option<String>> {
        Ok(None)
    }
}

impl cred_ports::People for Unconfigured {
    fn console_roles_of(&self, _name: &str) -> (bool, bool) {
        (false, false)
    }

    fn bootstrap_name(&self) -> String {
        "admin".into()
    }
}

impl cred_ports::Observers for Unconfigured {
    fn password(&self, _name: &str, _password: &str, _facts: &Json) {}

    fn failure(&self, username: &str, via: &str, code: &str) {
        tracing::info!("{} risk: a failure for {} at {}", code, username, via);
    }
}

impl cred_ports::PasskeyRules for Unconfigured {
    fn refusal_for(&self, _at: &str, _facts: &Json) -> Option<Json> {
        None
    }

    fn recovery_refusal(&self, _ask: &Json) -> Option<Json> {
        None
    }

    fn requires_post_quantum(&self, _at: &str) -> bool {
        false
    }

    fn algorithm_mismatch(&self, _row: &Json) -> Hook<()> {
        Ok(())
    }

    fn credential_changed(&self, _facts: &Json) {}

    fn audit(&self, row: &Json) {
        tracing::info!("audit: {}", row);
    }
}

/// What the screen asks beyond the session and the credentials.
pub struct Facts {
    pub env: Arc<Environment>,
    pub directory: Arc<DirectoryPorts>,
    pub unconfigured: Arc<Unconfigured>,
}

impl SignInFacts for Facts {
    fn setting(&self, key: &str) -> Json {
        self.env.setting(key)
    }

    fn predicate(&self, name: &str) -> bool {
        self.env.predicate(name)
    }

    fn now_ms(&self) -> f64 {
        sts_core::time::now_ms_f64()
    }

    fn random_id(&self, bytes: usize) -> String {
        authn_ports::Clock::random_id(&authn_ports::SystemClock, bytes)
    }

    fn authn_allows(&self, mechanism: &str, role: &str) -> bool {
        authn_ports::SignInPolicy::allows(&*self.unconfigured, mechanism, role)
    }

    fn authn_active(&self, mechanism: &str, role: &str) -> bool {
        self.authn_allows(mechanism, role)
    }

    fn key_policy(&self) -> Json {
        let u = &self.unconfigured;
        // `usernameless`: the passkey policy's allowUsernameless, on by
        // default (no named passkey policy is read here yet).
        json!({ "enabled": u.key_setting("webauthn.enabled", true),
                "mfaAllowed": u.key_setting("webauthn.mfaAllowed", true),
                "primaryAllowed": u.key_setting("webauthn.primaryAllowed", true),
                "usernameless": true })
    }

    fn key_use_allowed(
        &self,
        key_use: &str,
    ) -> Result<(), (String, ErrorCode)> {
        if cred_ports::Policies::key_use_allowed(&*self.unconfigured, key_use) {
            Ok(())
        } else {
            Err((
                format!(
                    "This realm does not allow a passkey as {} (webauthn.{}).",
                    if key_use == "primary" {
                        "a first factor"
                    } else {
                        "a second factor"
                    },
                    if key_use == "primary" {
                        "primaryAllowed"
                    } else {
                        "mfaAllowed"
                    }
                ),
                codes::STS_AUTHN_0044,
            ))
        }
    }

    fn gate_session(
        &self,
        _application: &str,
        _username: &str,
        _authenticated: bool,
    ) -> Json {
        json!({ "allowed": true, "why": "" })
    }

    fn mfa_allowed_for(
        &self,
        _application: &str,
        _username: &str,
    ) -> Vec<String> {
        Vec::new()
    }

    fn client_display(&self, _application: &str) -> Json {
        Json::Null
    }

    fn preferred_language_of(&self, username: &str) -> Option<Json> {
        let (_, _, entry) = self.directory.person(username)?;
        first(&entry, "preferredLanguage")
            .map(|v| json!({ "value": v, "populated": true }))
    }

    fn remembers_browsers(&self) -> bool {
        self.env.setting("devices.browserDevices") != Json::Bool(false)
    }

    fn offers_password_reset(&self) -> bool {
        false
    }

    fn fingerprinting(&self) -> Json {
        Json::Bool(false)
    }

    fn breached(&self, _password: &str) -> bool {
        false
    }

    fn clear_password_reset(&self, username: &str) -> bool {
        self.directory
            .write(username, "pwdReset", None)
            .unwrap_or(false)
    }

    fn audit(&self, row: &Json) {
        tracing::info!("audit: {}", row);
    }

    fn note_refused(&self, row: &Json) {
        tracing::info!("authn: a refused authentication: {}", row);
    }
}

/// The in-memory rate-limit buckets (`security.rateLimitBuckets` is a
/// shared map in Node; one process here, so one map).
fn buckets() -> Arc<MemoryBuckets> {
    Arc::new(MemoryBuckets::default())
}

/// The `csrf` cluster secret (`cluster/cluster_secrets.ts`): the
/// environment's `STS_CSRF_SECRET`, or 32 random bytes in base64 made for
/// this process.
fn csrf_secret() -> String {
    if let Ok(text) = std::env::var("STS_CSRF_SECRET") {
        if !text.is_empty() {
            return text;
        }
    }
    let bytes = sts_crypto::random::random_bytes(32).unwrap_or_default();
    standard_base64(&bytes)
}

/// RFC 4648 base64 with padding, as Node's `toString('base64')`.
fn standard_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n =
            (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Everything the sign-in surface built: the session core and the API.
pub struct SignInStack {
    pub sessions: Arc<Sessions>,
    pub signin: Arc<SignIn>,
    pub api: Arc<AuthnApi>,
}

/// What the composition root hands [`SignInStack::declare`].
pub struct RuntimeParts {
    pub settings: Arc<Settings>,
    pub mode: Arc<Mode>,
    pub registry: Arc<RealmRegistry>,
    pub lifecycle: Arc<RealmLifecycle>,
    pub handles: Arc<StoreHandles>,
    pub directory: Arc<MemoryDirectory>,
    pub persistence: Arc<Persistence>,
    /// The build's version (`version.json`).
    pub version: String,
}

impl SignInStack {
    /// Builds the session core, the credentials and the screen's logic,
    /// declaring their stores (before the store opens).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn declare(parts: RuntimeParts) -> SignInStack {
        let env = Arc::new(Environment {
            settings: parts.settings.clone(),
            mode: parts.mode.clone(),
            registry: parts.registry.clone(),
        });
        let directory = Arc::new(DirectoryPorts {
            directory: parts.directory.clone(),
            persistence: parts.persistence.clone(),
            registry: parts.registry.clone(),
            settings: parts.settings.clone(),
            mode: parts.mode.clone(),
        });
        let unconfigured = Arc::new(Unconfigured { env: env.clone() });
        let credentials = Arc::new(Credentials::new(CredentialsDeps {
            env: env.clone(),
            policies: unconfigured.clone(),
            keystore: Arc::new(KeystorePort {
                persistence: parts.persistence.clone(),
            }),
            service_accounts: unconfigured.clone(),
            people: unconfigured.clone(),
            observers: unconfigured.clone(),
            directory: Some(directory.clone()),
            pending: CredentialPending::declare(
                &parts.lifecycle,
                &parts.handles,
            ),
        }));
        let checks = Arc::new(SessionChecks::new(
            credentials.clone(),
            unconfigured.clone(),
        ));
        let sessions = Arc::new(Sessions::new(
            SessionsDeps {
                settings: env.clone(),
                mode: env.clone(),
                realms: env.clone(),
                people: directory.clone(),
                accounts: directory.clone(),
                policy: unconfigured.clone(),
                gate: unconfigured.clone(),
                credentials: checks,
                devices: unconfigured.clone(),
                records: unconfigured.clone(),
                audit: unconfigured.clone(),
                binding: unconfigured.clone(),
                backchannel: None,
                session_management: None,
                risk: None,
                claims: None,
                clock: Arc::new(authn_ports::SystemClock),
            },
            &parts.lifecycle,
            &parts.handles,
        ));
        let limits = Arc::new(RateLimiter::new(env.clone(), buckets()));
        let signin = Arc::new(SignIn {
            stores: PendingStores::declare(&parts.lifecycle, &parts.handles),
            sessions: sessions.clone(),
            credentials,
            limits,
            facts: Arc::new(Facts {
                env: env.clone(),
                directory,
                unconfigured,
            }),
        });
        let api = Arc::new(AuthnApi {
            signin: signin.clone(),
            csrf_secret: csrf_secret(),
            version: parts.version,
            https: parts.settings.value_of("global.https").as_bool(),
        });
        SignInStack {
            sessions,
            signin,
            api,
        }
    }

    /// Mounts the shells on the HTTP layer and answers the router to put
    /// behind it.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn mount(
        &self,
        http: &Arc<sts_http::HttpLayer>,
        surfaces: Arc<sts_http::surfaces::SurfaceHost>,
        settings: Arc<Settings>,
    ) -> axum::Router {
        http.add_routes(Arc::new(crate::router::SignInShells {
            signin: self.signin.clone(),
            shells: Arc::new(crate::router::ShellsSource(surfaces)),
        }));
        crate::router::router(self.api.clone(), http.clone(), settings)
    }
}
