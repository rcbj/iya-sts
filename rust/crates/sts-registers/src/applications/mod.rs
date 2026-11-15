// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE APPLICATION REGISTER (#444, phase 4): `common/applications.js`
//! (rule 3g, `common/CLAUDE.md`), the one register of every party this
//! service has dealt with — an OAuth client, a relying party, a service
//! provider, a WS-Trust or WS-Federation application, a Kerberos service
//! principal, a federated identity provider, a GNAP instance — each one
//! entry under `ou=applications`, whatever protocol brought it.
//!
//! | Module | Node it ports |
//! |---|---|
//! | [`tables`] | `KINDS`, `PROTOCOLS`, `SCHEMA` and their indexes |
//! | [`record`] | `attributesFor()`, `recordFromAttributes()`, `blankRecord()`, `generalizedTime()`, `labelFor()` |
//! | [`store`] | `ldap_server.js`'s `readApplication()`, `writeApplication()`, `allApplications()`, `deleteApplicationEntry()`, `resolveServiceAccountOwner()` — the slot `applications.setDirectory()` is filled with, over [`sts_directory::Directory`] itself |
//! | [`checks`] | `normaliseFields()` and every per-attribute value check, each with Node's sentence and code |
//! | [`write`] | `seen()`, `createApplication()`, `updateApplication()`, `deleteApplication()`, `setField()`, the owners, the return-address provenance pair, the FGA state |
//! | [`secrets`] | the client secrets: minted, sealed, added, removed, rotated, regenerated |
//! | [`read`] | `view()`, `get()`, `list()`, the listing and its indexes, the protocol-identifier lookups, `settingFor()` |
//! | [`ports`] | the [`crate::port::Applications`] and `sts_policy::ApplicationRegister` ports implemented over the register |
//!
//! WHAT REPLACED WHAT (brief-phase3, DESIGN section 4):
//!
//! * the SLOT `setDirectory()` is gone: the register holds the directory
//!   (`Arc<Mutex<Directory>>`) and the five functions `ldap_server.js`
//!   fills the slot with are [`store`]'s methods over it;
//! * the slot `setFgaLifecycle()` STAYS a slot ([`FgaLifecycle`]): the
//!   XACML family fills it later, and until it does an application is
//!   created and deleted with no policy, exactly as in Node;
//! * `config.value()`, the `mode.js` predicates, `keystore.js`'s seal and
//!   open, the clock and `crypto.js`'s random and digest are one
//!   environment port ([`AppEnv`]), so a test hands the register the values
//!   Node read;
//! * what a write SETS OFF in other families — the audit rows, the CAEP
//!   credential-change, the GNAP grants ended, the claims fan-out, the
//!   roles an application owned — is the effects port ([`AppEffects`]);
//!   Node reaches each by a lazy `require` so that the register never
//!   loads them, and a port is the same arrangement made explicit;
//! * the load memo and the listing memo (`applications.load`,
//!   `applications.listing`, keyed on `subtreeVersion()`) are not kept: a
//!   read walks the realm's tree, which is what a memo miss does, and
//!   answers the same.
//!
//! The ambient realm (`realms.current()`) is `sts_core::realm::current_id()`.

pub mod checks;
pub mod read;
pub mod record;
pub mod secrets;
pub mod store;
pub mod tables;
pub mod write;

mod ports;

use std::sync::{Arc, Mutex, RwLock};

use serde_json::{Map, Value};
use sts_core::errors::ErrorCode;
use sts_directory::Directory;

pub use record::{Fields, Record};
pub use tables::Tables;

/// Everything the register reads that is not the directory: the settings,
/// the mode, the key store, the clock and the random source.
pub trait AppEnv: Send + Sync {
    /// `Date.now()`, milliseconds.
    fn now_ms(&self) -> i64;
    /// `config.value(key)` in the ambient realm.
    fn setting(&self, key: &str) -> Value;
    /// A `mode.js` predicate by its name (`autoCreates`,
    /// `acceptsUnregisteredAddresses`, `verifiesCredentials`, …).
    fn mode(&self, predicate: &str) -> bool;
    /// `config.parseAs(key, raw)`: the value, or the problem.
    fn parse_as(&self, key: &str, raw: &str) -> Result<Value, String>;
    /// `mode.allowsValue(key, value)`.
    fn allows_value(&self, key: &str, value: &Value) -> bool;
    /// `mode.writeRefusalReason(setting.onlyWhile)` for the setting `key`.
    fn write_refusal_reason(&self, key: &str) -> String;
    /// `crypto.randomBytes(n)`.
    fn random_bytes(&self, n: usize) -> Vec<u8>;
    /// `crypto.digest('sha256', text, 'hex')`.
    fn sha256_hex(&self, text: &str) -> String;
    /// `crypto.isEncryptedWithKek(value)`.
    fn is_sealed(&self, value: &str) -> bool;
    /// `keystore.persists()`.
    fn keystore_persists(&self) -> bool;
    /// `keystore.persists() && keystore.sealed() &&
    /// !keystore.hasEphemeralKek()`.
    fn seals_client_secrets(&self) -> bool;
    /// `keystore.seal(text, label)`.
    fn seal(&self, text: &str, label: &str) -> Option<String>;
    /// `keystore.open(text, label)`.
    fn open(&self, text: &str, label: &str) -> Option<String>;
}

/// What a write sets off outside the register.
pub trait AppEffects: Send + Sync {
    /// `audit.audit(row)`.
    fn audit(&self, row: &Value);
    /// `audit.failure(code, row)`.
    fn failure(&self, code: ErrorCode, row: &Value);
    /// `account_signals.credentialChanged(notice)`.
    fn credential_changed(&self, notice: &Value);
    /// `account_signals.certificateChanged(notice)`.
    fn certificate_changed(&self, notice: &Value);
    /// `gnap_revocation.endForClientKeyChange()` / `endForClient()`:
    /// how many grants ended.
    fn end_gnap_grants(&self, identifier: &str, key_changed: bool, how: &Value)
        -> i64;
    /// `account_signals.claimsFanOut()` for a scope withdrawn from
    /// `attribute` on `identifier` (`announceScopeRemoval()`): `removed`
    /// is the scope the tokens lose, `audience` the base URI a permission
    /// token is addressed to, '' when the client id decides.
    fn claims_fan_out(
        &self,
        identifier: &str,
        attribute: &str,
        removed: &str,
        audience: &str,
    );
    /// `scope_policy.judge(scope, identifier).kept` contains the scope.
    fn scope_kept(&self, scope: &str, identifier: &str) -> bool;
    /// `certificate_trust.registrationProblem(use, der)`: `{why, code}`.
    fn certificate_registration_problem(
        &self,
        usage: &str,
        der: &[u8],
    ) -> Option<(String, ErrorCode)>;
}

/// The fine-grained authorization lifecycle slot (`setFgaLifecycle()`,
/// #564), filled by the XACML family: an application's own policy is
/// created with it and retired with it. Each answers `{ok, why, errors}`.
pub trait FgaLifecycle: Send + Sync {
    /// `hooks.created(identifier, actor, '')`.
    fn created(&self, identifier: &str, actor: &str) -> Value;
    /// `hooks.deleted(identifier, actor, policy)`.
    fn deleted(&self, identifier: &str, actor: &str, policy: &str) -> Value;
}

/// The register.
pub struct ApplicationRegistry {
    directory: Option<Arc<Mutex<Directory>>>,
    env: Arc<dyn AppEnv>,
    effects: Arc<dyn AppEffects>,
    fga: RwLock<Option<Arc<dyn FgaLifecycle>>>,
}

impl std::fmt::Debug for ApplicationRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApplicationRegistry")
            .field("directory", &self.directory.is_some())
            .finish()
    }
}

/// A result and the code marked on it (`errorCodes.mark()`).
pub type Marked = crate::outcome::Outcome;

impl ApplicationRegistry {
    /// The register over a directory. `None` is Node's register before
    /// `ldap_server.js` is required: every query answers empty and every
    /// write is refused (STS-REG-0002).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(
        directory: Option<Arc<Mutex<Directory>>>,
        env: Arc<dyn AppEnv>,
        effects: Arc<dyn AppEffects>,
    ) -> ApplicationRegistry {
        ApplicationRegistry {
            directory,
            env,
            effects,
            fga: RwLock::new(None),
        }
    }

    /// `setFgaLifecycle(hooks)`: installs the slot, or empties it.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn set_fga_lifecycle(&self, hooks: Option<Arc<dyn FgaLifecycle>>) {
        if let Ok(mut held) = self.fga.write() {
            *held = hooks;
        }
    }

    /// `fgaLifecycleInstalled()`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn fga_lifecycle_installed(&self) -> bool {
        self.fga.read().map(|h| h.is_some()).unwrap_or(false)
    }

    /// `registryAvailable()`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn registry_available(&self) -> bool {
        self.directory.is_some()
    }

    /// The environment, for the checks.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn env(&self) -> &dyn AppEnv {
        self.env.as_ref()
    }

    // `fgaHook(which, identifier, actor, policy)`: a refusal or a panic is
    // logged under STS-FGA-0010 and changes nothing about the write.
    fn fga_hook(&self, which: &str, identifier: &str, actor: &str, policy: &str) {
        let hooks = self.fga.read().ok().and_then(|h| h.clone());
        let Some(hooks) = hooks else {
            return;
        };
        let answer = if which == "created" {
            hooks.created(identifier, actor)
        } else {
            hooks.deleted(identifier, actor, policy)
        };
        if answer.get("ok") == Some(&Value::Bool(false)) {
            tracing::warn!(
                "{}applications: \"{}\" was {}, and its fine-grained \
                 authorization policy was not {}.",
                sts_core::log::tag(sts_core::errors::codes::STS_FGA_0010),
                identifier,
                which,
                if which == "created" { "created" } else { "retired" }
            );
        }
    }
}

/// `{ok: false, errors: [..]}` marked with a code.
fn refused(code: ErrorCode, errors: Vec<String>) -> Marked {
    let mut answer = Map::new();
    answer.insert("ok".into(), Value::Bool(false));
    answer.insert(
        "errors".into(),
        Value::Array(errors.into_iter().map(Value::String).collect()),
    );
    Marked::marked(code, Value::Object(answer))
}
