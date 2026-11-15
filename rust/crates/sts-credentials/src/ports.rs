// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What the credential doors reach outside themselves for, as traits.
//!
//! WHAT REPLACED WHAT. `common/credentials.ts` is handed the directory
//! through `setDirectory()` (an inverted hook filled by
//! `ldap/ldap_server.js`, rule 3e) and reaches `config`, `mode`,
//! `keystore`, the authentication, WebAuthn and password policies and the
//! service-account register through its `CredentialsDeps`. Here each is a
//! trait object handed to the constructor (rust/DESIGN.md section 4.2), and
//! a hook that THROWS in Node is an `Err(message)`: the doors catch it at
//! the same place, with the same code.
//!
//! The production implementations are the directory (`sts-directory`'s
//! credential attributes), `sts-core`'s settings, mode and keystore, and
//! `sts-policy`'s password, authentication and passkey kinds; this crate's
//! tests answer every one of them from a tape Node recorded, so a question
//! Node never asked fails the case.

use serde_json::Value as Json;

/// The process and the request: settings, the mode, the clock, the ambient
/// realm and the random source.
pub trait Environment: Send + Sync {
    /// `config.value(key)`, as the JSON Node's reader answers.
    fn setting(&self, key: &str) -> Json;
    /// A `common/mode.js` predicate, by its name there.
    fn predicate(&self, name: &str) -> bool;
    /// `Date.now()`.
    fn now_ms(&self) -> f64;
    /// `realms.currentId()`.
    fn realm_id(&self) -> String;
    /// `crypto.randomBytes(n)`.
    fn random_bytes(&self, n: usize) -> Vec<u8>;
    /// `crypto.randomInt(min, max)`: `min <= x < max`.
    fn random_int(&self, min: u64, max: u64) -> u64;
    /// `crypto.hashSecret(plaintext)`: scrypt at the settings' cost.
    fn hash_secret(&self, plaintext: &str) -> String;
}

/// A directory hook's answer: `Err` is the message it threw.
pub type Hook<T> = Result<T, String>;

/// The credential attributes of a person's entry: the hooks
/// `ldap/ldap_server.js` hands `setDirectory()` (and `addDirectoryHooks()`).
pub trait CredentialDirectory: Send + Sync {
    /// `readPassword(name)`: the stored `userPassword`, or none.
    fn read_password(&self, name: &str) -> Hook<Option<String>>;
    /// `writePassword(name, hash)`.
    fn write_password(&self, name: &str, hash: &str) -> Hook<bool>;
    /// `readPasswordReset(name)`: `pwdReset`.
    fn read_password_reset(&self, name: &str) -> Hook<bool>;
    /// `readPasswordHistory(name)`: the previous hashes, newest first.
    fn read_password_history(&self, name: &str) -> Hook<Vec<String>>;
    /// `isPerson(name)`.
    fn is_person(&self, name: &str) -> Hook<bool>;
    /// `personExists(name)`.
    fn person_exists(&self, name: &str) -> Hook<bool>;
    /// `readAccountDisabled(name)`: `pwdAccountLockedTime` is set.
    fn read_account_disabled(&self, name: &str) -> Hook<bool>;
    /// `readMfaRequired(name)`: `stsMfaRequired`.
    fn read_mfa_required(&self, name: &str) -> Hook<bool>;
    /// `readTotp(name)`: `stsTotpSecret`'s JSON.
    fn read_totp(&self, name: &str) -> Hook<Option<String>>;
    /// `writeTotp(name, json)`.
    fn write_totp(&self, name: &str, value: Option<&str>) -> Hook<bool>;
    /// `readBackupCodes(name)`: `stsBackupCodes`'s JSON.
    fn read_backup_codes(&self, name: &str) -> Hook<Option<String>>;
    /// `writeBackupCodes(name, json)`.
    fn write_backup_codes(&self, name: &str, value: Option<&str>)
        -> Hook<bool>;
    /// `readAppPasswords(name)`: `stsAppPassword`'s JSON.
    fn read_app_passwords(&self, name: &str) -> Hook<Option<String>>;
    /// `writeAppPasswords(name, json)`; `None` removes the attribute.
    fn write_app_passwords(
        &self,
        name: &str,
        value: Option<&str>,
    ) -> Hook<bool>;
    /// `readWebauthn(name)`: the `stsWebauthnCredential` values.
    fn read_webauthn(&self, name: &str) -> Hook<Vec<Json>>;
}

/// `common/keystore.js`: sealing under the key-encryption key.
pub trait Keystore: Send + Sync {
    /// `keystore.persists()`: whether a key outlives the process.
    fn persists(&self) -> bool;
    /// `keystore.seal(plain, label, scope)`; none when it could not.
    fn seal(&self, plain: &str, label: &str, scope: &str) -> Option<String>;
    /// `keystore.open(sealed, label)`; none when it will not open.
    fn open(&self, sealed: &str, label: &str) -> Option<String>;
}

/// The policies a door asks: the authentication policy (`authn_policy.ts`),
/// the WebAuthn policy's uses (`webauthn_policy.ts`) and the password
/// policy (`password_policy.ts`), as `sts-policy` answers them.
pub trait Policies: Send + Sync {
    /// `authnPolicy.allows(mechanism, role)`.
    fn allows(&self, mechanism: &str, role: &str) -> bool;
    /// `authnPolicy.requireSecondFactor()`.
    fn require_second_factor(&self) -> String;
    /// `authnPolicy.configuredSecondFactor()`.
    fn configured_second_factor(&self) -> String;
    /// `authnPolicy.requireSecondFactorForAdministrators()`.
    fn require_second_factor_for_administrators(&self) -> String;
    /// `webauthnPolicy.useAllowed(use).ok`.
    fn key_use_allowed(&self, key_use: &str) -> bool;
    /// `passwordPolicy.profileFor(name)`.
    fn password_profile_for(&self, name: &str) -> Json;
    /// `passwordPolicy.hashSpec(profile)`: the spec a new hash is made at.
    fn password_hash_spec(&self, profile: &Json) -> Json;
}

/// The service-account register and its policy (`service_accounts.ts`,
/// `service_account_policy.ts`).
pub trait ServiceAccounts: Send + Sync {
    /// `serviceAccounts.isServiceAccountName(name)`.
    fn is_service_account_name(&self, name: &str) -> bool;
    /// `!serviceAccountPolicy.allowsDoor(door, profileFor(name))`.
    fn refuses_door(&self, name: &str, door: &str) -> bool;
    /// `exemptFromSecondFactor(profileFor(name))`.
    fn exempt_from_second_factor(&self, name: &str) -> bool;
    /// `previousPassword(name).hash`: inside a rotation's overlap.
    fn previous_password_hash(&self, name: &str) -> Hook<Option<String>>;
}

/// Who holds a console role, and the realm's built-in administrator.
pub trait People: Send + Sync {
    /// `consoleRolesOf(name)`: (read, write).
    fn console_roles_of(&self, name: &str) -> (bool, bool);
    /// `bootstrap_name.current()`.
    fn bootstrap_name(&self) -> String;
}

/// What a door tells others and does not wait on: the password observer
/// (`setPasswordObserver()`, the account-state and history writers) and
/// `risk/risk_failures.recordFailure()`.
pub trait Observers: Send + Sync {
    /// `passwordObserver(name, password, { event, hash, retainPreviousMs,
    /// previousHash })`.
    fn password(&self, name: &str, password: &str, facts: &Json);
    /// `recordFailure(username, via, code)`.
    fn failure(&self, username: &str, via: &str, code: &str);
}
