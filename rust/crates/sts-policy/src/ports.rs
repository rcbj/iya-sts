// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What the policy kinds reach outside themselves for, as the smallest
//! traits that say it (#444 phase 4: the directory and the registers are
//! other slices' crates, written beside this one).
//!
//! In Node each kind is handed the directory through a slot
//! `ldap/ldap_server.js` fills (`setDirectory()`), reaches the application
//! register lazily (`require('./applications')`), and reads settings, mode
//! predicates and a few registers through its `deps`. Here every one of
//! those is a method of one of three traits, each taking the realm it asks
//! about explicitly — the ambient realm of Node (`realms.run()`) is an
//! argument in Rust (rust/DESIGN.md section 4.3) — so the inheritance from
//! the default realm, which Node does by running a read in that realm's
//! context, is a second call naming [`DEFAULT_REALM`].
//!
//! What the real implementations must provide is each method's comment.

use serde_json::Value;

use crate::js::Object;

/// The default realm's id, as `realms.currentId()` answers in it.
pub const DEFAULT_REALM: &str = "default";

/// The containers a kind keeps its entries in, named by the directory hook
/// the Node kind calls (`allPasswordPolicies()` and its write and delete).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Container {
    Password,
    Authn,
    ServiceAccount,
    Passkey,
    Locale,
    Attributes,
    /// `ou=attributeDefinitions`, the attribute policy's custom attributes.
    AttributeDefinitions,
    PostLogin,
}

impl Container {
    /// The three hooks Node's directory offers for the container: read
    /// every entry, write one, delete one.
    pub const fn hooks(self) -> [&'static str; 3] {
        match self {
            Container::Password => [
                "allPasswordPolicies",
                "writePasswordPolicy",
                "deletePasswordPolicy",
            ],
            Container::Authn => ["allAuthnPolicies", "writeAuthnPolicy", "deleteAuthnPolicy"],
            Container::ServiceAccount => [
                "allServiceAccountPolicies",
                "writeServiceAccountPolicy",
                "deleteServiceAccountPolicy",
            ],
            Container::Passkey => [
                "allPasskeyPolicies",
                "writePasskeyPolicy",
                "deletePasskeyPolicy",
            ],
            Container::Locale => [
                "allLocalePolicies",
                "writeLocalePolicy",
                "deleteLocalePolicy",
            ],
            Container::Attributes => [
                "allAttributePolicies",
                "writeAttributePolicy",
                "deleteAttributePolicy",
            ],
            Container::AttributeDefinitions => [
                "allAttributeDefinitions",
                "writeAttributeDefinition",
                "deleteAttributeDefinition",
            ],
            Container::PostLogin => [
                "allPostLoginPolicies",
                "writePostLoginPolicy",
                "deletePostLoginPolicy",
            ],
        }
    }
}

/// One entry of a container, as the directory hook answers it.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyEntry {
    /// The entry's `cn`, as stored.
    pub name: String,
    pub dn: String,
    /// The attributes, every value an array as the directory holds them
    /// (a kind reads a bare string too).
    pub attributes: Object,
}

/// What a write answered: Node's `putEntry()` answers `true`, `false` for
/// a directory at its maximum, or `{ ok: false, reason, errors }` for a
/// description carrying an operator code (`reason` absent) or a NUL
/// (`reason: 'nul'`), writing nothing (#1416).
#[derive(Debug, Clone, PartialEq)]
pub enum WriteOutcome {
    Written,
    Full,
    Refused { nul: bool, errors: Vec<String> },
}

/// A group of the person's, with the policy its reference attribute names
/// ('' for none): `personGroupReferences()`'s rows.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct GroupReference {
    pub cn: String,
    pub dn: String,
    pub value: String,
}

/// The people naming a policy (`peopleNamingPolicyAsync()`): a holder
/// question, which may stop short (`complete: false`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PeopleNaming {
    pub people: Vec<String>,
    pub complete: bool,
}

/// The embedded directory, as the kinds use it. The real one is the
/// directory slice's; every method is the Node hook of the same name.
pub trait PolicyDirectory {
    /// Every entry of a container in a realm, or `None` where no directory
    /// is installed (Node's `haveDirectory()` false: the built-in profile
    /// is in force and nothing can be saved).
    fn entries(&self, realm: &str, container: Container) -> Option<Vec<PolicyEntry>>;
    /// Replaces an entry whole (`write…Policy(name, attributes)`).
    fn write(&self, realm: &str, container: Container, name: &str, attributes: &Object)
        -> WriteOutcome;
    /// Deletes an entry; whether one was there.
    fn delete(&self, realm: &str, container: Container, name: &str) -> bool;
    /// The person's groups, each with the value of `attribute` on it
    /// (`personGroupReferences(key, attribute)`); `None` where the hook is
    /// not installed.
    fn person_group_references(
        &self,
        realm: &str,
        person: &str,
        attribute: &str,
    ) -> Option<Vec<GroupReference>>;
    /// The cns of the groups whose `attribute` names `name`, in DN order
    /// (`groupsNamingPolicy(attribute, name)`, matched in any case).
    fn groups_naming_policy(&self, realm: &str, attribute: &str, name: &str)
        -> Option<Vec<String>>;
    /// The given groups with the value of `attribute` on each
    /// (`groupReferences(groups, attribute)`, the attribute policy's).
    fn group_references(
        &self,
        realm: &str,
        groups: &[String],
        attribute: &str,
    ) -> Option<Vec<GroupReference>>;
    /// The people whose own `attribute` names `name`.
    fn people_naming_policy(&self, realm: &str, attribute: &str, name: &str)
        -> Option<PeopleNaming>;
    /// The spelling the directory knows an attribute name by, '' for one it
    /// does not (`knownName()`).
    fn known_name(&self, realm: &str, name: &str) -> String;
    /// How many people in the realm hold a value of the attribute.
    fn holders(&self, realm: &str, name: &str) -> u64;
}

/// The application register, as the kinds use it (the registers slice's).
pub trait ApplicationRegister {
    /// The fields of the application with this `client_id`
    /// (`applications.forClientId()`).
    fn by_client_id(&self, realm: &str, client_id: &str) -> Option<Object>;
    /// The fields of the application with this identifier
    /// (`applications.get()`).
    fn by_identifier(&self, realm: &str, identifier: &str) -> Option<Object>;
    /// The identifiers of the applications whose `attribute` names the
    /// policy (`applicationsNamingPolicy(attribute, name)`).
    fn naming_policy(&self, realm: &str, attribute: &str, name: &str) -> Vec<String>;
}

/// A realm's own facts the password check reads (`realms.current()` and
/// `realms.domainOf()`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RealmFacts {
    pub id: String,
    pub name: String,
    pub domain: String,
}

/// The registration rows a passkey profile's algorithms are resolved from
/// (`RegistrationRows`, #940), handed to the WebAuthn settings.
#[derive(Debug, Clone, PartialEq)]
pub struct RegistrationRows {
    pub registration_algorithms: Vec<String>,
    pub registration_mode: String,
    pub post_quantum_required: String,
    pub lanes: String,
}

/// An attribute a person may be given a value for, as the person editor
/// publishes it (the attribute policy's `offered()`).
#[derive(Debug, Clone, PartialEq)]
pub struct OfferedRow {
    pub name: String,
    pub label: String,
    pub schema: String,
    pub custom: bool,
}

/// Everything else a kind asks: settings, mode predicates, the mail
/// channel, the service-account register, the locale catalogue, the
/// WebAuthn settings and the learned clients. Each is the Node `deps`
/// member or module call named beside it.
pub trait PolicyEnvironment {
    /// `config.value(key)` in the realm, as JSON.
    fn setting(&self, realm: &str, key: &str) -> Value;
    /// `mode.verifiesCredentials()` (the password policy is enforced).
    fn verifies_credentials(&self, realm: &str) -> bool;
    /// `mode.recoversWeakerThanPasskeys()` (the passkey policy's mode-
    /// dependent default for `recoveryAssurance`).
    fn recovers_weaker_than_passkeys(&self, realm: &str) -> bool;
    /// `mode.createsIncompletePeople()` (the attribute policy is NOT
    /// enforced).
    fn creates_incomplete_people(&self, realm: &str) -> bool;
    /// `mail.available()`: whether the realm can send mail.
    fn mail_available(&self, realm: &str) -> bool;
    /// The realm's own facts.
    fn realm(&self, realm: &str) -> RealmFacts;
    /// The first-factor mechanism ids (`federation.MECHANISM_IDS`) and the
    /// second-factor ids (`mfa_mechanisms.IDS`) a named authentication
    /// policy may list.
    fn authn_vocabularies(&self) -> (Vec<String>, Vec<String>);
    /// How many secret destinations the realm has, -1 where the register is
    /// not loaded.
    fn destination_count(&self, realm: &str) -> i64;
    /// The profile a service account's `stsServiceAccountPolicy` names, ''
    /// for none or for a person who is not one.
    fn service_account_reference(&self, realm: &str, username: &str) -> String;
    /// The service accounts naming a profile (folded name).
    fn service_accounts_naming(&self, realm: &str, name: &str) -> Vec<String>;
    /// Whether an entry's attributes are a service account's.
    fn is_service_account(&self, realm: &str, attributes: &Object) -> bool;
    /// `webauthn_policy.offersPostQuantum(rows)`.
    fn offers_post_quantum(&self, realm: &str, rows: &RegistrationRows) -> bool;
    /// `i18n.canonical(tag)`: the canonical BCP 47 tag, '' for none.
    fn canonical_locale(&self, tag: &str) -> String;
    /// The person editor's universe, or the reason it could not be asked.
    fn offered_attributes(&self, realm: &str) -> Result<Vec<OfferedRow>, String>;
    /// `passkey_clients.act(action, body)`: the learned clients' acts,
    /// answered with their own code where refused.
    fn passkey_clients_act(&self, realm: &str, action: &str, body: &Object)
        -> crate::Answer;
}

/// The three ports, as one set a kind is built over.
#[derive(Clone, Copy)]
pub struct Ports<'a> {
    pub directory: &'a dyn PolicyDirectory,
    pub applications: &'a dyn ApplicationRegister,
    pub env: &'a dyn PolicyEnvironment,
}
