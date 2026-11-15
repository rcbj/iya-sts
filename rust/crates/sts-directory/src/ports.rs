// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What the directory asks of the rest of the service, as traits ("ports").
//!
//! `ldap_server.js` reaches each of these by a `require` of another module;
//! the Rust directory is handed them. Each says which Node function it
//! stands for, and each has a default the vectors run against — the mode,
//! the settings and the clock over `sts-core`'s, the rest the answer Node's
//! module gives on a directory with no policy of that kind named.
//!
//! | Port | Node | Real implementation |
//! |---|---|---|
//! | [`DirectoryMode`] | `common/mode.js`'s predicates | `sts_core::mode::Mode` (below) |
//! | [`DirectorySettings`] | `config.value()` of six keys | `sts_core::settings::Settings` (below) |
//! | [`Clock`], [`UuidSource`] | `new Date()`, `stsCrypto.randomUuid()` | [`SystemClock`], [`CryptoUuids`] |
//! | [`DirectoryJournal`] | `touchDirectory()`, `persistence.dnKeyRefusal()` | `sts-store`'s directory flush |
//! | [`DirectoryAuthority`] | `admin_rbac.rolesOf()`, `SecurityOperations` | the console roster (phase 4's registers) |
//! | [`PersonRules`] | password, service-account, attribute and locale policy | each policy's crate |
//! | [`RegisterCascade`] | `roles.forgetMember()` and the owner doors | the role and application registers |
//! | [`DirectoryObserver`] | `audit.*`, `noteAccountChange()` and the rest | audit, SSF, the registers' notices |

use serde_json::Value as Json;

use sts_core::errors::ErrorCode;

use crate::entry::{Attributes, Entry};
use crate::model::DirectoryModel;

/// The mode's directory questions (`common/mode.js`), each a predicate at
/// its call site and never a literal.
pub trait DirectoryMode: Send + Sync {
    /// `authorizesDirectoryWrites()`: who may write is asked at all.
    fn authorizes_directory_writes(&self) -> bool;
    /// `authorizesDirectoryReads()`: the reader's identity is asked.
    fn authorizes_directory_reads(&self) -> bool;
    /// `requiresDirectoryBind()`: a read needs a bind.
    fn requires_directory_bind(&self) -> bool;
    /// `withholdsDirectorySecrets()`: credentials never leave on the wire.
    fn withholds_directory_secrets(&self) -> bool;
    /// `protectsOperationalAttributes()`: the timestamps are the directory's.
    fn protects_operational_attributes(&self) -> bool;
    /// `verifiesCredentials()`: a password is checked.
    fn verifies_credentials(&self) -> bool;
    /// `createsIncompletePeople()`: the attribute policy is not enforced.
    fn creates_incomplete_people(&self) -> bool;
}

impl DirectoryMode for sts_core::mode::Mode {
    fn authorizes_directory_writes(&self) -> bool {
        sts_core::mode::Mode::authorizes_directory_writes(self)
    }
    fn authorizes_directory_reads(&self) -> bool {
        sts_core::mode::Mode::authorizes_directory_reads(self)
    }
    fn requires_directory_bind(&self) -> bool {
        sts_core::mode::Mode::requires_directory_bind(self)
    }
    fn withholds_directory_secrets(&self) -> bool {
        sts_core::mode::Mode::withholds_directory_secrets(self)
    }
    fn protects_operational_attributes(&self) -> bool {
        sts_core::mode::Mode::protects_operational_attributes(self)
    }
    fn verifies_credentials(&self) -> bool {
        sts_core::mode::Mode::verifies_credentials(self)
    }
    fn creates_incomplete_people(&self) -> bool {
        sts_core::mode::Mode::creates_incomplete_people(self)
    }
}

/// A mode fixed at construction: every predicate is the mode, as each of
/// the six is in `mode.js` (`product` answers true in product mode).
#[derive(Debug, Clone, Copy, Default)]
pub struct FixedMode {
    pub product: bool,
}

impl DirectoryMode for FixedMode {
    fn authorizes_directory_writes(&self) -> bool {
        self.product
    }
    fn authorizes_directory_reads(&self) -> bool {
        self.product
    }
    fn requires_directory_bind(&self) -> bool {
        self.product
    }
    fn withholds_directory_secrets(&self) -> bool {
        self.product
    }
    fn protects_operational_attributes(&self) -> bool {
        self.product
    }
    fn verifies_credentials(&self) -> bool {
        self.product
    }
    fn creates_incomplete_people(&self) -> bool {
        !self.product
    }
}

/// The settings the directory reads, per call (`config.value()`).
pub trait DirectorySettings: Send + Sync {
    /// `ldap.maxEntries`.
    fn max_entries(&self) -> i64;
    /// `ldap.sizeLimit`.
    fn size_limit(&self) -> i64;
    /// `admin.bootstrapUsername`.
    fn bootstrap_username(&self) -> String;
    /// `ldap.selfWritableAttributes`, lower-cased.
    fn self_writable_attributes(&self) -> Vec<String>;
    /// `ldap.directoryReadableAttributes`, lower-cased.
    fn directory_readable_attributes(&self) -> Vec<String>;
    /// `ldap.groupMembersReadable`.
    fn group_members_readable(&self) -> bool;
    /// `admin.securityGroup`.
    fn security_group(&self) -> String;
}

fn listed(value: sts_core::settings::SettingValue) -> Vec<String> {
    use sts_core::settings::SettingValue;
    let raw: Vec<String> = match value {
        SettingValue::List(l) => l,
        SettingValue::Text(t) => t.split(',').map(str::to_string).collect(),
        _ => Vec::new(),
    };
    raw.into_iter()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

impl DirectorySettings for sts_core::settings::Settings {
    fn max_entries(&self) -> i64 {
        int(self.value(sts_core::settings::keys::LDAP_MAX_ENTRIES))
    }
    fn size_limit(&self) -> i64 {
        int(self.value(sts_core::settings::keys::LDAP_SIZE_LIMIT))
    }
    fn bootstrap_username(&self) -> String {
        self.text(sts_core::settings::keys::ADMIN_BOOTSTRAP_USERNAME)
    }
    fn self_writable_attributes(&self) -> Vec<String> {
        listed(
            self.value(sts_core::settings::keys::LDAP_SELF_WRITABLE_ATTRIBUTES),
        )
    }
    fn directory_readable_attributes(&self) -> Vec<String> {
        listed(self.value(
            sts_core::settings::keys::LDAP_DIRECTORY_READABLE_ATTRIBUTES,
        ))
    }
    fn group_members_readable(&self) -> bool {
        matches!(
            self.value(sts_core::settings::keys::LDAP_GROUP_MEMBERS_READABLE),
            sts_core::settings::SettingValue::Bool(true)
        )
    }
    fn security_group(&self) -> String {
        self.text(sts_core::settings::keys::ADMIN_SECURITY_GROUP)
    }
}

fn int(value: sts_core::settings::SettingValue) -> i64 {
    match value {
        sts_core::settings::SettingValue::Int(n) => n,
        sts_core::settings::SettingValue::Text(t) => {
            t.trim().parse().unwrap_or(0)
        }
        _ => 0,
    }
}

/// Settings held as values, for a directory without `sts-core`'s.
#[derive(Debug, Clone)]
pub struct FixedSettings {
    pub max_entries: i64,
    pub size_limit: i64,
    pub bootstrap_username: String,
    pub self_writable_attributes: Vec<String>,
    pub directory_readable_attributes: Vec<String>,
    pub group_members_readable: bool,
    pub security_group: String,
}

impl Default for FixedSettings {
    /// `common/config.js`'s defaults.
    fn default() -> Self {
        FixedSettings {
            max_entries: 2000,
            size_limit: 500,
            bootstrap_username: "admin".to_string(),
            self_writable_attributes: Vec::new(),
            directory_readable_attributes: Vec::new(),
            group_members_readable: false,
            security_group: String::new(),
        }
    }
}

impl DirectorySettings for FixedSettings {
    fn max_entries(&self) -> i64 {
        self.max_entries
    }
    fn size_limit(&self) -> i64 {
        self.size_limit
    }
    fn bootstrap_username(&self) -> String {
        self.bootstrap_username.clone()
    }
    fn self_writable_attributes(&self) -> Vec<String> {
        self.self_writable_attributes.clone()
    }
    fn directory_readable_attributes(&self) -> Vec<String> {
        self.directory_readable_attributes.clone()
    }
    fn group_members_readable(&self) -> bool {
        self.group_members_readable
    }
    fn security_group(&self) -> String {
        self.security_group.clone()
    }
}

/// `generalizedTime()`'s clock.
pub trait Clock: Send + Sync {
    /// The instant as `YYYYMMDDHHMMSSZ`, UTC.
    fn generalized_time(&self) -> String;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn generalized_time(&self) -> String {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        generalized_time_of(secs)
    }
}

/// `generalizedTime(new Date(seconds * 1000))`.
#[tracing::instrument(level = "debug")]
pub fn generalized_time_of(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        y,
        m,
        d,
        rest / 3600,
        (rest % 3600) / 60,
        rest % 60
    )
}

/// `stsCrypto.randomUuid()`: a version 4 UUID.
pub trait UuidSource: Send + Sync {
    fn random_uuid(&self) -> String;
}

/// The one random UUID source, `sts_crypto`'s.
#[derive(Debug, Clone, Copy, Default)]
pub struct CryptoUuids;

impl UuidSource for CryptoUuids {
    fn random_uuid(&self) -> String {
        sts_crypto::random::random_uuid().unwrap_or_default()
    }
}

/// What the store is told and asked (`touchDirectory()`,
/// `persistence.dnKeyRefusal()`). The in-memory store needs neither, which
/// is [`NoJournal`].
pub trait DirectoryJournal: Send + Sync {
    /// An entry at this key was written or removed in this realm.
    fn touched(&self, realm: &str, key: &str) {
        let _ = (realm, key);
    }
    /// Why the store cannot hold this key (MariaDB's key length), or None.
    fn dn_key_refusal(&self, realm: &str, key: &str) -> Option<String> {
        let _ = (realm, key);
        None
    }
}

/// The memory store: nothing to tell, and every key fits.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoJournal;

impl DirectoryJournal for NoJournal {}

/// A console role's answer for one identity (`admin_rbac.rolesOf()`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Roles {
    pub read: bool,
    pub write: bool,
    pub security: bool,
    /// Held only because the roster is empty (`admin.openWhenEmpty`).
    pub open: bool,
}

/// Who holds what, for the product-mode write and read rules.
pub trait DirectoryAuthority: Send + Sync {
    /// The roles the person filed under `console_key` holds in `realm`.
    fn roles_of(&self, console_key: &str, realm: &str) -> Roles {
        let _ = (console_key, realm);
        Roles::default()
    }
    /// `adminRbac.holdsSecurity()`.
    fn holds_security(&self, console_key: &str, realm: &str) -> bool {
        self.roles_of(console_key, realm).security
    }
    /// `SecurityOperations.policyContainers()`: the policy containers'
    /// RDNs, lower-cased and unspaced (`ou=passwordpolicies`).
    fn policy_containers(&self) -> Vec<String> {
        Vec::new()
    }
    /// `SecurityOperations.referenceAttributes()` for the application, the
    /// group and the person, lower-cased.
    fn policy_reference_attributes(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Nobody holds anything: every product-mode write by a bound DN that is
/// not its own entry is refused, which is what an empty roster answers here
/// (the open window does not count, `boundDnHoldsRole()`).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoAuthority;

impl DirectoryAuthority for NoAuthority {}

/// A clear password the password policy accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedPassword {
    pub hash: String,
    pub history: Vec<String>,
}

/// A policy's refusal: its code and its sentences.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRefusal {
    pub code: Option<ErrorCode>,
    pub message: String,
    /// What it names (the attributes missing or taken away).
    pub names: Vec<String>,
}

/// The policies a person's write meets, each another module's.
pub trait PersonRules: Send + Sync {
    /// `credentials.preparePassword()`: a clear password checked against
    /// the policy and hashed.
    fn prepare_password(
        &self,
        username: &str,
        password: &str,
        current: &str,
        history: &[String],
    ) -> Result<PreparedPassword, PolicyRefusal>;
    /// `localePolicy.populationFor()`: the language a new person's entry is
    /// given, or "".
    fn population_language(&self, application: &str, dn: &str) -> String;
    /// `serviceAccountPolicy.writeRefusal()`: a `stsServiceAccountPolicy`
    /// reference the realm does not hold, or on a person who is not one.
    fn service_account_reference_refusal(
        &self,
        attributes: &Attributes,
    ) -> Option<PolicyRefusal>;
    /// `requiresOwner(profileForReference(reference, uid))`.
    fn service_account_requires_owner(
        &self,
        reference: &str,
        uid: &str,
    ) -> bool;
    /// `attributePolicy.createRefusal()`: what a new person lacks, where
    /// the policy is `enforced` (`!mode.createsIncompletePeople()`).
    fn attribute_create_refusal(
        &self,
        attributes: &Attributes,
        enforced: bool,
    ) -> Option<PolicyRefusal>;
    /// `attributePolicy.editRefusal()`: a required value taken away.
    fn attribute_edit_refusal(
        &self,
        before: &Attributes,
        after: &Attributes,
        enforced: bool,
    ) -> Option<PolicyRefusal>;
}

/// The policies as a realm with no named policy of any kind answers them:
/// each policy's defaults, read from its generated `fields.json`. The
/// attribute policy is its `default` profile: `uid`, `cn` and `sn`, then
/// `requiredAttributes`' default, each spelt as published (the named
/// profiles and their selection are `policy_selection.ts`'s, another
/// slice's). A clear password is refused:
/// the hash is the password policy's, and a directory without one must not
/// store a password nobody hashed.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultPersonRules;

impl PersonRules for DefaultPersonRules {
    fn prepare_password(
        &self,
        _username: &str,
        _password: &str,
        _current: &str,
        _history: &[String],
    ) -> Result<PreparedPassword, PolicyRefusal> {
        Err(PolicyRefusal {
            code: None,
            message: "no password policy is installed in this directory"
                .to_string(),
            names: Vec::new(),
        })
    }
    fn population_language(&self, _application: &str, _dn: &str) -> String {
        let model = DirectoryModel::get();
        let populate =
            model.field_default("policy.locale", "populatePreferredLanguage");
        if populate == Json::Bool(true) {
            match model.field_default("policy.locale", "defaultLocale") {
                Json::String(s) => s,
                _ => String::new(),
            }
        } else {
            String::new()
        }
    }
    fn service_account_reference_refusal(
        &self,
        _attributes: &Attributes,
    ) -> Option<PolicyRefusal> {
        None
    }
    fn service_account_requires_owner(
        &self,
        _reference: &str,
        _uid: &str,
    ) -> bool {
        DirectoryModel::get()
            .field_default("policy.serviceAccount", "requireOwner")
            == Json::Bool(true)
    }
    fn attribute_create_refusal(
        &self,
        attributes: &Attributes,
        enforced: bool,
    ) -> Option<PolicyRefusal> {
        if !enforced {
            return None;
        }
        let required = default_required_attributes();
        let missing: Vec<String> = required
            .iter()
            .filter(|n| !holds(attributes, n))
            .cloned()
            .collect();
        if missing.is_empty() {
            return None;
        }
        Some(PolicyRefusal {
            code: None,
            message: format!(
                "This realm's attribute policy requires every person to hold {}, and this one would have no \
value of {}. Directory > Policies > Attribute policy sets the list.",
                required.join(", "),
                missing.join(", ")
            ),
            names: missing,
        })
    }
    fn attribute_edit_refusal(
        &self,
        before: &Attributes,
        after: &Attributes,
        enforced: bool,
    ) -> Option<PolicyRefusal> {
        if !enforced {
            return None;
        }
        let removed: Vec<String> = default_required_attributes()
            .into_iter()
            .filter(|n| holds(before, n) && !holds(after, n))
            .collect();
        if removed.is_empty() {
            return None;
        }
        Some(PolicyRefusal {
            code: None,
            message: format!(
                "This realm's attribute policy requires every person to hold {}, so the edit may not leave {} \
without a value. Set another value instead.",
                removed.join(", "),
                if removed.len() == 1 { "it" } else { "them" }
            ),
            names: removed,
        })
    }
}

/// `ALWAYS_REQUIRED` and the default profile's `requiredAttributes`:
/// `attributePolicy.required()` where no profile is stored.
#[tracing::instrument(level = "debug")]
pub fn default_required_attributes() -> Vec<String> {
    let model = DirectoryModel::get();
    let listed =
        match model.field_default("policy.attributes", "requiredAttributes") {
            Json::String(s) => s,
            _ => String::new(),
        };
    let mut out: Vec<String> = vec!["uid".into(), "cn".into(), "sn".into()];
    for one in listed.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let spelt = model.canonical_name(&one.to_lowercase());
        if !out.iter().any(|r| r.to_lowercase() == spelt.to_lowercase()) {
            out.push(spelt);
        }
    }
    out
}

// `holds()`: a non-empty value of the name, in any case.
fn holds(attributes: &Attributes, name: &str) -> bool {
    let wanted = name.to_lowercase();
    attributes.iter().any(|(k, v)| {
        k.to_lowercase() == wanted && v.iter().any(|s| !s.trim().is_empty())
    })
}

/// The registers that name people and groups by name or DN outside the
/// directory's own entries: the role register (`roles.forgetMember()`,
/// `roles.renameMember()`, `roles.forgetOwner()`, `roles.renameOwner()`)
/// and the application registry's owners. Each rewrites its OWN entries.
pub trait RegisterCascade: Send + Sync {
    /// A person (`users`) or group (`groups`) gone.
    fn forget_member(&self, kind: &str, name: &str) {
        let _ = (kind, name);
    }
    /// A person or group renamed.
    fn rename_member(&self, kind: &str, old: &str, new: &str) {
        let _ = (kind, old, new);
    }
    /// An owner's DN gone (`to` empty) or moved.
    fn rewrite_owner(&self, old_dn: &str, to: &str) {
        let _ = (old_dn, to);
    }
}

/// No register is installed.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRegisters;

impl RegisterCascade for NoRegisters {}

/// What the directory reports as it works: the audit rows and the
/// account notices Node writes from the handlers.
#[derive(Debug, Clone, PartialEq)]
pub enum DirectoryNotice {
    /// `ldapRefusal()`'s `audit.failure()` row.
    Refused {
        code: Option<ErrorCode>,
        summary: String,
        target: String,
    },
    /// `auditLdap()`'s row for an operation done.
    Done {
        action: String,
        target: String,
        summary: String,
    },
    /// An entry written, with the attributes before (None for a create).
    Written {
        realm: String,
        before: Option<Box<Entry>>,
        after: Box<Entry>,
    },
    /// An entry removed.
    Removed { realm: String, entry: Box<Entry> },
    /// An entry renamed.
    Renamed {
        realm: String,
        from: String,
        to: Box<Entry>,
    },
}

/// Where the notices go.
pub trait DirectoryObserver: Send + Sync {
    fn notice(&self, notice: DirectoryNotice) {
        let _ = notice;
    }
}

/// Nobody is listening.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoObserver;

impl DirectoryObserver for NoObserver {}
