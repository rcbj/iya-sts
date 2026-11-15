// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The directory itself: one tree per trust realm, and the seven handlers
//! `ldap/ldap_server.js` registers on the socket, without the socket.
//!
//! **WHAT REPLACED WHAT.** In Node the store is a Map per realm keyed by the
//! normalised DN, selected by an ambient realm the handler enters with
//! `realms.run(realmFor(req.dn))`, and a request reaches a handler either
//! from the socket or rebuilt in a request worker from its plain shape
//! (`operationContext()`). Here the realm is not ambient: every operation
//! names the realm its DN selects ([`Directory::realm_for`]) and works on
//! that tree, and an [`Operation`] IS the plain shape — what the wire slice
//! (`sts-ldap`) decodes and a worker would receive. The handler's answer is
//! an [`Outcome`]: the entries it sent, a compare's answer, or the refusal
//! (`next(err)`), with the STS code its audit row carries.
//!
//! **THE RULES, IN THE HANDLERS' ORDER.** Each operation asks its questions
//! in exactly the order Node's handler does, because the first refusal is
//! the answer and the order is what makes a refusal say nothing about the
//! tree (the write and read rules are asked before whether the target
//! exists). Every sentence is Node's, word for word.
//!
//! **IN DEVELOPMENT MODE THE DIRECTORY AUTHORIZES NO READ OR WRITE** (the
//! root `CLAUDE.md`'s refusal index): `DirectoryMode`'s predicates decide,
//! at each call site, as `mode.js`'s do.
//!
//! **NOT HERE**, and why: the bind (it needs the password check and the
//! rate limiter, the wire slice's and the authentication slice's); the
//! windowed worker's store queries (#349; the memory store holds the whole
//! tree, which is what this is) and so the search's time limit, which only
//! a windowed search can reach; and every notice Node sends a register
//! (SSF, RISC, the identity register, mail verification), which goes to the
//! [`DirectoryObserver`] as a [`DirectoryNotice`] instead.

use std::sync::Arc;

use indexmap::IndexMap;
use sts_core::errors::{codes, ErrorCode};
use sts_ldap::filter::Filter;
use sts_ldap::service_dn::{
    depth_under, escape_dn_value, is_under, normalize_dn, parent_dn, rdn_pairs,
    split_rdns, unescape_dn_value,
};

use crate::domain_map::{DomainMap, FromOptions};
use crate::entry::{Attributes, Entry, EntryExt};
use crate::error::LdapError;
use crate::matching;
use crate::model::DirectoryModel;
use crate::ports::{
    Clock, CryptoUuids, DefaultPersonRules, DirectoryAuthority, DirectoryJournal,
    DirectoryMode, DirectoryNotice, DirectoryObserver, DirectorySettings,
    FixedMode, FixedSettings, NoAuthority, NoJournal, NoObserver, NoRegisters,
    PersonRules, RegisterCascade, SystemClock, UuidSource,
};
use crate::read_policy::{self, AttributeRule, EntryFacts, EntryKind, Reader, ReaderKind};
use crate::uuid::backfilled_entry_uuid;

/// The default realm's id.
pub const DEFAULT_REALM: &str = "default";

/// The operational attributes, returned only when asked for by name
/// (RFC 4511 section 4.5.1.8).
pub const OPERATIONAL: &[&str] = &[
    "createtimestamp",
    "modifytimestamp",
    "entrydn",
    "entryuuid",
    ENTRY_UUID_ALIAS,
];

/// The losing `entryUUID` of a two-process create race.
pub const ENTRY_UUID_ALIAS: &str = "stsentryuuidalias";

/// Which door provisioned an entry.
pub const PROVISIONED_BY: &str = "stsprovisionedby";

const CLIENT_WRITTEN_OPERATIONAL: &[&str] = &[
    "createtimestamp",
    "modifytimestamp",
    "entrydn",
    "entryuuid",
    ENTRY_UUID_ALIAS,
    PROVISIONED_BY,
];

// Refused in every mode: `entryUUID` is a person's subject.
const ALWAYS_PROTECTED_OPERATIONAL: &[&str] = &["entryuuid", ENTRY_UUID_ALIAS, PROVISIONED_BY];

const GROUP_CLASSES: &[&str] = &["groupofnames", "groupofuniquenames", "posixgroup", "groupofurls"];

/// `MEMBER_ATTRIBUTES`: what each one's values ARE.
const MEMBER_ATTRIBUTES: &[(&str, bool)] = &[("member", false), ("uniquemember", false), ("memberuid", true)];

const OWNER_REFERENCE_ATTRIBUTES: &[&str] = &["owner", "stsserviceaccountowner"];

const PSEUDONYM_LDAP_ATTRIBUTES: &[&str] = &[
    "stspseudonym",
    "stspseudonymverifytoken",
    "stspseudonymverifyexpires",
    "stspseudonymverifyaddress",
];

// `serviceAccounts.ATTRIBUTES`, lower-cased.
const SERVICE_ACCOUNT_ATTRIBUTES: &[&str] = &[
    "stsserviceaccount",
    "stsserviceaccountowner",
    "stssecretdestination",
    "stssecretname",
    "stspasswordrotatedat",
    "stspreviouspassword",
    "stspreviouspasswordexpires",
    "stsrotationfailures",
    "stsrotationlasterror",
    "stsrotationlastattempt",
    "stsownerprotected",
    "stsserviceaccountpolicy",
];

const SERVICE_ACCOUNT_MAINTAINED: &[&str] = &[
    "stspasswordrotatedat",
    "stspreviouspassword",
    "stspreviouspasswordexpires",
    "stsrotationfailures",
    "stsrotationlasterror",
    "stsrotationlastattempt",
];

// `serviceAccounts.MAX_OWNERS` (#600).
const MAX_OWNERS: usize = 25;

const SASL_MECHANISMS: &[&str] = &["EXTERNAL"];

const DESCRIPTION_OPERATOR_CODE: &str = "A description cannot carry an operator error code. Those codes are \
recorded, and a description is stored text that this service would send back.";

const NUL_SENTENCE: &str = "contains a NUL byte. It is malformed under every LDAP string syntax, and a value \
that half this stack reads as shorter than the other half is worse than no value at all.";

// `CREDENTIAL_ATTRIBUTE_DOORS` (#237): each credential, and the door that
// owns it.
const CREDENTIAL_ATTRIBUTE_DOORS: &[(&str, &str)] = &[
    ("stswebauthncredential", "/portal/keys, the sign-in screen, or /admin/users (remove)"),
    ("stsandroidattestedcredential", "the doors of stsWebauthnCredential, from which it is derived on every write"),
    ("stswebauthnuserhandle", "the first passkey registered at /portal/keys or the sign-in screen, which mints it"),
    (
        "stswebauthnpqcuserhandle",
        "the first post-quantum passkey registered at /portal/keys or the sign-in screen, which mints it",
    ),
    ("ststotpcredential", "/portal/mfa, or /admin/users (clear)"),
    ("stsbackupcodes", "/portal/mfa, or /admin/users (clear)"),
    ("stsapppassword", "/portal/app-passwords, or /admin/users"),
    ("hobapublickey", "the SCIM HOBA registration (/scim/v2 with Hobareg)"),
    ("stsselfissuedsubject", "/portal/self-issued, or /admin/users"),
    (
        "stspublisheddid",
        "/portal/self-issued (publish, change a key, deactivate), or /admin/users (deactivate)",
    ),
    ("stsprofilephoto", "/portal (Profile photo)"),
    ("stsmailfactor", "/portal/mfa, or /admin/users"),
    ("stsmailfactorfailures", "the emailed factor's own sign-in step"),
    ("stskrb5keys", "a verified sign-in, or the Kerberos keys controls on /admin/users"),
    ("stskrb5keyinfo", "a verified sign-in, or the Kerberos keys controls on /admin/users"),
    ("stscibausercode", "/portal/ciba"),
    ("stsacmeeabkey", "/portal/certificates, or the ACME console page"),
    ("appacmeeabkey", "the ACME console page"),
    ("stsscepchallenge", "/portal/certificates, or the SCEP console page"),
    ("appscepchallenge", "the SCEP console page"),
    (
        "stsenrolledcertificate",
        "an enrollment protocol (ACME, EST, SCEP), or its revoke on the portal or the console",
    ),
    ("stsenrolledprivatekey", "EST /serverkeygen"),
    ("appenrolledprivatekey", "EST /serverkeygen"),
    ("stsdevicesecrethash", "Native SSO, or /admin/devices"),
    ("stsdevicekey", "/portal/devices, or /admin/devices"),
    ("stsdevicecredentialid", "/portal/devices, or /admin/devices"),
    ("stskrb5trustkeys", "the Kerberos trust register (kerberos/krb5_trusts.ts)"),
];

const CREDENTIAL_ATTRIBUTE_PREFIXES: &[(&str, &str)] = &[
    ("stsassertion", "/portal/signing-key, or the signing key controls on /admin/users"),
    ("stssamlassertion", "/portal/signing-key, or the signing key controls on /admin/users"),
];

// What a search never shows, in every mode (`krb5PersonKeys`,
// `certEnrollment` and the key tables' `withheldValues()`).
const KERBEROS_WITHHELD: &[&str] = &["stskrb5keys", "krb5servicekeys"];
const ENROLLMENT_WITHHELD: &[&str] = &[
    "stsenrolledprivatekey",
    "appenrolledprivatekey",
    "stsacmeeabkey",
    "appacmeeabkey",
    "stsscepchallenge",
    "appscepchallenge",
];

/// One tree: a realm's id, its base DN and its entries by normalised DN,
/// in insertion order.
#[derive(Debug, Clone, Default)]
pub struct RealmTree {
    pub id: String,
    pub base: String,
    pub entries: IndexMap<String, Entry>,
}

/// One change of a modify: `add`, `replace` or `delete`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub operation: String,
    pub attribute: String,
    pub values: Vec<String>,
}

/// What an operation asks, as `operationRequest()` describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    Add {
        attributes: Vec<(String, Vec<String>)>,
    },
    Modify {
        changes: Vec<Change>,
    },
    Delete,
    ModifyDn {
        new_rdn: String,
        new_superior: String,
        delete_old_rdn: bool,
    },
    Compare {
        attribute: String,
        value: String,
    },
    Search {
        /// The number on the wire: 0 base, 1 one level, anything else sub.
        scope: i64,
        filter: String,
        attributes: Vec<String>,
        size_limit: i64,
    },
}

/// One request: the DN it names, who is bound, and the operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub dn: String,
    /// The connection's bind DN; `cn=anonymous` and "" are nobody.
    pub bound_dn: String,
    /// Whether the connection is LDAPS.
    pub encrypted: bool,
    pub operation: Operation,
}

/// One entry a search sent: its DN and its attributes, spelt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchEntry {
    pub object_name: String,
    pub attributes: Vec<(String, Vec<String>)>,
}

/// What a handler answered.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Outcome {
    pub entries: Vec<SearchEntry>,
    /// A compare's answer.
    pub compared: Option<bool>,
    pub error: Option<LdapError>,
}

/// The directory: every realm's tree and what it asks of the service.
pub struct Directory {
    model: &'static DirectoryModel,
    realms: Vec<RealmTree>,
    mode: Arc<dyn DirectoryMode>,
    realm_modes: Vec<(String, Arc<dyn DirectoryMode>)>,
    settings: Arc<dyn DirectorySettings>,
    clock: Arc<dyn Clock>,
    uuids: Arc<dyn UuidSource>,
    journal: Arc<dyn DirectoryJournal>,
    authority: Arc<dyn DirectoryAuthority>,
    rules: Arc<dyn PersonRules>,
    registers: Arc<dyn RegisterCascade>,
    observer: Arc<dyn DirectoryObserver>,
    sasl_external: bool,
}

impl std::fmt::Debug for Directory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Directory")
            .field("realms", &self.realms.len())
            .finish()
    }
}

fn values_of(attributes: &[(String, Vec<String>)]) -> Vec<String> {
    attributes.iter().map(|(t, _)| t.to_lowercase()).collect()
}

fn distinct(list: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for one in list {
        if !out.contains(one) {
            out.push(one.clone());
        }
    }
    out
}

fn credential_door(ty: &str) -> &'static str {
    let name = ty.to_lowercase();
    if let Some((_, door)) = CREDENTIAL_ATTRIBUTE_DOORS.iter().find(|(n, _)| *n == name) {
        return door;
    }
    CREDENTIAL_ATTRIBUTE_PREFIXES
        .iter()
        .find(|(p, _)| name.starts_with(p))
        .map(|(_, d)| *d)
        .unwrap_or("")
}

// `STS-[A-Z]+-[0-9]{4}` in a value.
fn carries_operator_code(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut i = 0;
    while let Some(at) = value[i..].find("STS-") {
        let start = i + at + 4;
        let mut j = start;
        while j < bytes.len() && bytes[j].is_ascii_uppercase() {
            j += 1;
        }
        if j > start
            && j + 5 <= bytes.len()
            && bytes[j] == b'-'
            && bytes[j + 1..j + 5].iter().all(u8::is_ascii_digit)
        {
            return true;
        }
        i = i + at + 1;
    }
    false
}

fn description_carries_code(attributes: &[(String, Vec<String>)]) -> bool {
    attributes
        .iter()
        .filter(|(t, _)| t.to_lowercase() == "description")
        .any(|(_, v)| v.iter().any(|s| carries_operator_code(s)))
}

fn nul_refusal(ty: &str, values: &[String]) -> Option<LdapError> {
    if values.iter().any(|v| v.contains('\u{0}')) {
        return Some(LdapError::new(
            "InvalidAttributeSyntaxError",
            format!("The value for \"{ty}\" {NUL_SENTENCE}"),
            Some(codes::STS_LDAP_0008),
        ));
    }
    None
}

// `withoutBinaryOption()`.
fn without_binary(lower: &str) -> String {
    if lower.len() >= 7 && lower[lower.len() - 7..].eq_ignore_ascii_case(";binary") {
        lower[..lower.len() - 7].to_string()
    } else {
        lower.to_string()
    }
}

// The values a key table row shows: its private key withheld.
fn withheld_key_table(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|v| match serde_json::from_str::<serde_json::Value>(&v) {
            Ok(mut row) => {
                if let Some(obj) = row.as_object_mut() {
                    let truthy = obj.get("privateKey").is_some_and(|p| match p {
                        serde_json::Value::Null | serde_json::Value::Bool(false) => false,
                        serde_json::Value::String(s) => !s.is_empty(),
                        serde_json::Value::Number(n) => n.as_f64() != Some(0.0),
                        _ => true,
                    });
                    if truthy {
                        obj.insert(
                            "privateKey".to_string(),
                            serde_json::Value::String("(withheld: the private key, never shown)".to_string()),
                        );
                    }
                }
                serde_json::to_string(&row).unwrap_or_default()
            }
            Err(_) => "(withheld: a key-table row that is not JSON)".to_string(),
        })
        .collect()
}

fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

// What a search sends of one attribute's values.
fn shown_values(name: &str, values: Vec<String>) -> Vec<String> {
    let lower = name.to_lowercase();
    if KERBEROS_WITHHELD.contains(&lower.as_str()) {
        return values
            .iter()
            .map(|v| format!("(withheld: Kerberos key material, {} characters, never shown)", utf16_len(v)))
            .collect();
    }
    if ENROLLMENT_WITHHELD.contains(&lower.as_str()) {
        return values
            .iter()
            .map(|v| {
                format!(
                    "(withheld: certificate-enrollment credential, {} characters, never shown)",
                    utf16_len(v)
                )
            })
            .collect();
    }
    if lower == "fedencryptionkey" || lower == "stsoidfedkeys" {
        return withheld_key_table(values);
    }
    values
}

/// The defaults the vectors run against: development mode, `config.js`'s
/// settings, the system clock and `sts_crypto`'s UUIDs, the memory store,
/// nobody's roles, each policy's defaults, no register and no observer.
impl Directory {
    /// A directory whose default realm is rooted at `root` (`ROOT_DN`,
    /// `global.domain`'s tree), empty.
    #[tracing::instrument(level = "debug")]
    pub fn new(root: &str) -> Directory {
        Directory {
            model: DirectoryModel::get(),
            realms: vec![RealmTree {
                id: DEFAULT_REALM.to_string(),
                base: root.to_string(),
                entries: IndexMap::new(),
            }],
            mode: Arc::new(FixedMode::default()),
            realm_modes: Vec::new(),
            settings: Arc::new(FixedSettings::default()),
            clock: Arc::new(SystemClock),
            uuids: Arc::new(CryptoUuids),
            journal: Arc::new(NoJournal),
            authority: Arc::new(NoAuthority),
            rules: Arc::new(DefaultPersonRules),
            registers: Arc::new(NoRegisters),
            observer: Arc::new(NoObserver),
            sasl_external: false,
        }
    }

    /// The mode's predicates.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn with_mode(mut self, mode: Arc<dyn DirectoryMode>) -> Self {
        self.mode = mode;
        self
    }

    /// A realm whose mode is not the process's: `global.mode` is a setting
    /// a realm may carry, so a realm can be in product mode while the
    /// process is not, and every predicate is asked in the realm the
    /// operation's DN selects.
    #[tracing::instrument(level = "debug", skip(self, mode))]
    pub fn with_realm_mode(mut self, realm: &str, mode: Arc<dyn DirectoryMode>) -> Self {
        self.realm_modes.retain(|(id, _)| id != realm);
        self.realm_modes.push((realm.to_string(), mode));
        self
    }

    // The mode in a realm: its own where it carries one.
    fn mode_at(&self, r: usize) -> &dyn DirectoryMode {
        let id = self.realms.get(r).map(|t| t.id.as_str()).unwrap_or("");
        self.realm_modes
            .iter()
            .find(|(realm, _)| realm == id)
            .map(|(_, m)| m.as_ref())
            .unwrap_or(self.mode.as_ref())
    }

    /// The settings read per call.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn with_settings(mut self, settings: Arc<dyn DirectorySettings>) -> Self {
        self.settings = settings;
        self
    }

    /// The clock and the UUID source.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>, uuids: Arc<dyn UuidSource>) -> Self {
        self.clock = clock;
        self.uuids = uuids;
        self
    }

    /// The store's journal.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn with_journal(mut self, journal: Arc<dyn DirectoryJournal>) -> Self {
        self.journal = journal;
        self
    }

    /// Who holds which console role.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn with_authority(mut self, authority: Arc<dyn DirectoryAuthority>) -> Self {
        self.authority = authority;
        self
    }

    /// The policies a person's write meets.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn with_rules(mut self, rules: Arc<dyn PersonRules>) -> Self {
        self.rules = rules;
        self
    }

    /// The registers a delete or a rename reaches.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn with_registers(mut self, registers: Arc<dyn RegisterCascade>) -> Self {
        self.registers = registers;
        self
    }

    /// Where the notices go.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn with_observer(mut self, observer: Arc<dyn DirectoryObserver>) -> Self {
        self.observer = observer;
        self
    }

    /// Whether LDAPS asks for a client certificate, so SASL EXTERNAL is
    /// offered (`saslExternalOffered()`, the TLS slice's to say).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn with_sasl_external(mut self, offered: bool) -> Self {
        self.sasl_external = offered;
        self
    }

    /// A realm's tree, rooted at its base (`realmBaseDn()`: the RFC 2247
    /// mapping of its domain, `sts_core::realm::base_dn_of_domain`).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn add_realm(&mut self, id: &str, base: &str) {
        if let Some(r) = self.realms.iter_mut().find(|r| r.id == id) {
            r.base = base.to_string();
            return;
        }
        self.realms.push(RealmTree {
            id: id.to_string(),
            base: base.to_string(),
            entries: IndexMap::new(),
        });
    }

    /// A realm removed, its tree with it.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn remove_realm(&mut self, id: &str) {
        if id != DEFAULT_REALM {
            self.realms.retain(|r| r.id != id);
        }
    }

    /// Entries restored into a realm as the store holds them, in order
    /// (the persistence load; a row without an `entryUUID` is backfilled,
    /// as `storedFromRow()` does).
    #[tracing::instrument(level = "debug", skip(self, entries))]
    pub fn restore(&mut self, realm: &str, entries: Vec<Entry>) {
        let Some(r) = self.realms.iter().position(|t| t.id == realm) else {
            return;
        };
        for mut entry in entries {
            let key = normalize_dn(Some(&entry.dn));
            if entry.entry_uuid().is_empty() {
                entry
                    .attributes
                    .insert("entryuuid".to_string(), vec![backfilled_entry_uuid(realm, &key)]);
            }
            self.realms[r].entries.insert(key, entry);
        }
    }

    /// What a store driver's `load_directory()` answered, each realm's rows
    /// restored into the tree of that id (a realm not added is skipped, as
    /// a row of a removed realm is).
    #[tracing::instrument(level = "debug", skip(self, loaded))]
    pub fn load(&mut self, loaded: &sts_store::driver::Directory) {
        for (realm, entries) in loaded {
            self.restore(realm, entries.clone());
        }
    }

    /// Every realm's entries as a driver's `save_directory()` takes them
    /// (`DirectoryChange::all`).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn snapshot(&self) -> sts_store::driver::Directory {
        self.realms
            .iter()
            .map(|r| (r.id.clone(), r.entries.values().cloned().collect()))
            .collect()
    }

    /// The realms' trees, default first.
    pub fn realms(&self) -> &[RealmTree] {
        &self.realms
    }

    /// One realm's tree.
    pub fn tree(&self, realm: &str) -> Option<&RealmTree> {
        self.realms.iter().find(|r| r.id == realm)
    }

    /// `namingContexts()`: the default realm's base, then every other
    /// realm's that differs from it.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn naming_contexts(&self) -> Vec<String> {
        let root = self.realms[0].base.clone();
        let mut out = vec![root.clone()];
        for r in self.realms.iter().skip(1) {
            if normalize_dn(Some(&r.base)) != normalize_dn(Some(&root)) {
                out.push(r.base.clone());
            }
        }
        out
    }

    /// `inNamingContext()`: under any realm's base.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn in_naming_context(&self, dn: &str) -> bool {
        self.realms.iter().any(|r| is_under(Some(dn), Some(&r.base)))
    }

    /// `realmFor()`: the realm with the deepest base containing the DN, the
    /// default realm otherwise. Lengths are of the bases as written, as in
    /// Node.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn realm_for(&self, dn: &str) -> usize {
        let root = &self.realms[0].base;
        let mut best = 0;
        let mut best_len: i64 = if is_under(Some(dn), Some(root)) {
            utf16_len(root) as i64
        } else {
            -1
        };
        for (i, r) in self.realms.iter().enumerate().skip(1) {
            if is_under(Some(dn), Some(&r.base)) && (utf16_len(&r.base) as i64) > best_len {
                best = i;
                best_len = utf16_len(&r.base) as i64;
            }
        }
        best
    }

    // ---- the containers of a realm ----------------------------------

    fn base(&self, r: usize) -> &str {
        &self.realms[r].base
    }

    fn container(&self, r: usize, rdn: &str) -> String {
        format!("{rdn},{}", self.base(r))
    }

    /// `usersDn()`.
    pub fn users_dn(&self, r: usize) -> String {
        self.container(r, "ou=users")
    }

    /// `groupsDn()`.
    pub fn groups_dn(&self, r: usize) -> String {
        self.container(r, "ou=groups")
    }

    fn applications_dn(&self, r: usize) -> String {
        self.container(r, "ou=applications")
    }

    fn roles_dn(&self, r: usize) -> String {
        self.container(r, "ou=roles")
    }

    fn devices_dn(&self, r: usize) -> String {
        self.container(r, "ou=devices")
    }

    // ---- reading entries --------------------------------------------

    /// `getEntry()`: the entry at a DN in a realm.
    pub fn get(&self, r: usize, dn: &str) -> Option<&Entry> {
        self.realms.get(r)?.entries.get(&normalize_dn(Some(dn)))
    }

    fn has_children(&self, r: usize, dn: &str) -> bool {
        let key = normalize_dn(Some(dn));
        let suffix = format!(",{key}");
        self.realms[r].entries.keys().any(|k| *k != key && k.ends_with(&suffix))
    }

    fn total_entries(&self) -> usize {
        self.realms.iter().map(|r| r.entries.len()).sum()
    }

    /// `isPersonEntry()`: placed under `ou=users`, the container excepted.
    pub fn is_person_dn(&self, r: usize, dn: &str) -> bool {
        let users = self.users_dn(r);
        is_under(Some(dn), Some(&users)) && normalize_dn(Some(dn)) != normalize_dn(Some(&users))
    }

    /// `groupRuleFor()`: '' for not a group, else `both`, `placement` or
    /// `objectClass`.
    pub fn group_rule(&self, r: usize, dn: &str, attributes: &Attributes) -> &'static str {
        let groups = self.groups_dn(r);
        let under = is_under(Some(dn), Some(&groups)) && normalize_dn(Some(dn)) != normalize_dn(Some(&groups));
        let classed = attributes
            .get("objectclass")
            .is_some_and(|v| v.iter().any(|c| GROUP_CLASSES.contains(&c.to_lowercase().as_str())));
        match (under, classed) {
            (true, true) => "both",
            (true, false) => "placement",
            (false, true) => "objectClass",
            _ => "",
        }
    }

    fn is_role_dn(&self, r: usize, dn: &str) -> bool {
        let roles = self.roles_dn(r);
        !dn.is_empty() && is_under(Some(dn), Some(&roles)) && normalize_dn(Some(dn)) != normalize_dn(Some(&roles))
    }

    /// `usernameOfEntry()`: the RDN's value, unescaped.
    pub fn username_of_dn(dn: &str) -> String {
        let rdn = split_rdns(Some(dn)).into_iter().next().unwrap_or_default();
        rdn_pairs(Some(&rdn))
            .first()
            .map(|p| unescape_dn_value(Some(&p.value)))
            .unwrap_or_default()
    }

    // `usernameKeysOf()`.
    fn username_keys(entry: &Entry) -> Vec<String> {
        let mut names: Vec<String> = entry.values("uid").to_vec();
        names.extend(entry.values("stspseudonym").iter().cloned());
        names.push(Self::username_of_dn(&entry.dn));
        let mut out: Vec<String> = Vec::new();
        for n in names {
            let k = n.trim().to_lowercase();
            if !k.is_empty() && !out.contains(&k) {
                out.push(k);
            }
        }
        out
    }

    /// `personNameOf()`.
    pub fn person_name_of(entry: &Entry) -> String {
        for a in ["uid", "x509subject", "didsubject", "spiffesubject"] {
            if let Some(v) = entry.first(a) {
                if !v.is_empty() {
                    return v.to_string();
                }
            }
        }
        Self::username_of_dn(&entry.dn)
    }

    // `consoleKeyFor()`.
    fn console_key(dn: &str, stored: Option<&Entry>) -> String {
        if let Some(uid) = stored.and_then(|s| s.first("uid")) {
            return uid.to_string();
        }
        let leaf = split_rdns(Some(dn)).into_iter().next().unwrap_or_default();
        rdn_pairs(Some(&leaf))
            .into_iter()
            .find(|p| p.attribute == "uid")
            .map(|p| unescape_dn_value(Some(&p.value)))
            .unwrap_or_default()
    }

    /// `existingUserEntry()`: the `uid` DN directly under `ou=users`, then
    /// the first entry there, in the store's order, answering to the name.
    pub fn existing_user_entry(&self, r: usize, name: &str) -> Option<&Entry> {
        let wanted = name.trim().to_lowercase();
        if wanted.is_empty() {
            return None;
        }
        let users = self.users_dn(r);
        if let Some(e) = self.get(r, &format!("uid={name},{users}")) {
            return Some(e);
        }
        let users_key = normalize_dn(Some(&users));
        self.realms[r]
            .entries
            .values()
            .find(|e| normalize_dn(Some(&parent_dn(Some(&e.dn)))) == users_key && Self::username_keys(e).contains(&wanted))
    }

    /// `entryByUuid()`: a primary value before an alias.
    pub fn entry_by_uuid(&self, r: usize, uuid: &str) -> Option<&Entry> {
        let lower = uuid.trim().to_lowercase();
        let wanted = lower.strip_prefix("urn:uuid:").unwrap_or(&lower);
        if !crate::uuid::uuid_shaped(wanted) {
            return None;
        }
        let entries = &self.realms.get(r)?.entries;
        entries.values().find(|e| e.entry_uuid() == wanted).or_else(|| {
            entries
                .values()
                .find(|e| e.values(ENTRY_UUID_ALIAS).iter().any(|a| a.to_lowercase() == wanted))
        })
    }

    // `firstRecording()`: the first entry whose attribute holds the value.
    fn first_recording(&self, r: usize, attribute: &str, wanted: &str) -> Option<&Entry> {
        self.realms[r]
            .entries
            .values()
            .find(|e| e.values(attribute).iter().any(|v| v == wanted))
    }

    /// `locateEntry()`'s lookup half: a subject, a DN (or the certificate
    /// subject an entry recorded), a DID, a SPIFFE ID, or a name.
    pub fn locate(&self, r: usize, key: &str) -> Option<&Entry> {
        let lower = key.to_lowercase();
        if lower.starts_with("urn:uuid:") {
            return self.entry_by_uuid(r, key);
        }
        if crate::uuid::dn_shaped(key) {
            return self.get(r, key).or_else(|| self.first_recording(r, "x509subject", key));
        }
        let trimmed = key.trim();
        if crate::uuid::did_shaped(key) {
            return if trimmed.is_empty() {
                None
            } else {
                self.first_recording(r, "didsubject", trimmed)
            };
        }
        if lower.starts_with("spiffe://") {
            return if trimmed.is_empty() {
                None
            } else {
                self.first_recording(r, "spiffesubject", trimmed)
            };
        }
        self.existing_user_entry(r, key)
    }

    /// The subject resolver's first half (`subjectForName()`):
    /// `urn:uuid:<entryUUID>` of the person a name locates, or "".
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn subject_for_name(&self, realm: &str, name: &str) -> String {
        let Some(r) = self.realms.iter().position(|t| t.id == realm) else {
            return String::new();
        };
        let text = name.trim();
        if text.is_empty() {
            return String::new();
        }
        match self.locate(r, text) {
            Some(e) if self.is_person_dn(r, &e.dn) && !e.entry_uuid().is_empty() => {
                format!("urn:uuid:{}", e.entry_uuid())
            }
            _ => String::new(),
        }
    }

    /// The resolver's second half (`nameForSubject()`): the name a subject's
    /// person is filed under, or "".
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn name_for_subject(&self, realm: &str, subject: &str) -> String {
        let Some(r) = self.realms.iter().position(|t| t.id == realm) else {
            return String::new();
        };
        match self.entry_by_uuid(r, subject) {
            Some(e) if self.is_person_dn(r, &e.dn) => Self::person_name_of(e),
            _ => String::new(),
        }
    }

    fn is_bootstrap_administrator(&self, r: usize, entry: &Entry) -> bool {
        let wanted = self.settings.bootstrap_username().trim().to_lowercase();
        let flagged = entry
            .values("stsbootstrapadministrator")
            .iter()
            .any(|v| v.to_uppercase() == "TRUE");
        !wanted.is_empty()
            && (r == 0 || flagged)
            && self.is_person_dn(r, &entry.dn)
            && Self::username_of_dn(&entry.dn).to_lowercase() == wanted
    }

    fn is_service_account(attributes: &Attributes) -> bool {
        DomainMap::default()
            .field_of("ServiceAccount", "serviceAccount", attributes, &FromOptions::default())
            .ok()
            .flatten()
            == Some(serde_json::Value::Bool(true))
    }

    // ---- writing entries ------------------------------------------------

    /// `putEntry()`: an entry stored whole, the operational attributes added
    /// here, the `entryUUID` and the provisioner carried from the entry
    /// already at the DN and never taken from the caller. Answers the
    /// refusal (and writes nothing) for a NUL or an operator code in a
    /// description.
    #[tracing::instrument(level = "debug", skip(self, attributes))]
    pub fn put_entry(
        &mut self,
        r: usize,
        dn: &str,
        attributes: &[(String, Vec<String>)],
        origin: Option<&str>,
        provisioned_by: Option<&str>,
    ) -> Result<String, LdapError> {
        for (ty, values) in attributes {
            if values.iter().any(|v| v.contains('\u{0}')) {
                return Err(LdapError::new(
                    "ConstraintViolationError",
                    format!("The value for \"{ty}\" {NUL_SENTENCE}"),
                    Some(codes::STS_LDAP_0008),
                ));
            }
        }
        if description_carries_code(attributes) {
            return Err(LdapError::new(
                "ConstraintViolationError",
                DESCRIPTION_OPERATOR_CODE,
                Some(codes::STS_LDAP_0211),
            ));
        }
        let now = self.clock.generalized_time();
        let key = normalize_dn(Some(dn));
        let mut stored = Entry {
            dn: dn.to_string(),
            attributes: Attributes::new(),
            origin: origin.map(str::to_string),
            created_at: Some(now.clone()),
            modified_at: Some(now.clone()),
        };
        for (name, values) in attributes {
            stored.attributes.insert(name.to_lowercase(), values.clone());
        }
        stored.attributes.insert("createtimestamp".to_string(), vec![now.clone()]);
        stored.attributes.insert("modifytimestamp".to_string(), vec![now]);
        let previous = self.realms[r].entries.get(&key).cloned();
        // fillPreferredLanguage(): a NEW person without one.
        if previous.is_none()
            && self.is_person_dn(r, dn)
            && stored.values("preferredlanguage").is_empty()
        {
            let tag = self.rules.population_language("", dn);
            if !tag.is_empty() {
                stored.attributes.insert("preferredlanguage".to_string(), vec![tag.clone()]);
                stored
                    .attributes
                    .insert("stspreferredlanguagepopulated".to_string(), vec![tag]);
            }
        }
        let carried = previous.as_ref().map(Entry::entry_uuid).unwrap_or_default();
        let uuid = if !carried.is_empty() {
            carried
        } else if stored.origin.as_deref() == Some("seed") {
            backfilled_entry_uuid(&self.realms[r].id, &key)
        } else {
            self.uuids.random_uuid()
        };
        stored.attributes.insert("entryuuid".to_string(), vec![uuid]);
        stored.attributes.shift_remove(ENTRY_UUID_ALIAS);
        if let Some(aliases) = previous.as_ref().map(|p| p.values(ENTRY_UUID_ALIAS).to_vec()) {
            if !aliases.is_empty() {
                stored.attributes.insert(ENTRY_UUID_ALIAS.to_string(), aliases);
            }
        }
        stored.attributes.shift_remove(PROVISIONED_BY);
        let before = previous
            .as_ref()
            .map(|p| p.values(PROVISIONED_BY).to_vec())
            .unwrap_or_default();
        if !before.is_empty() {
            stored.attributes.insert(PROVISIONED_BY.to_string(), before);
        } else if previous.is_none() {
            if let Some(p) = provisioned_by {
                stored.attributes.insert(PROVISIONED_BY.to_string(), vec![p.to_string()]);
            }
        }
        self.realms[r].entries.insert(key.clone(), stored.clone());
        self.journal.touched(&self.realms[r].id, &key);
        self.observer.notice(DirectoryNotice::Written {
            realm: self.realms[r].id.clone(),
            before: previous.map(Box::new),
            after: Box::new(stored),
        });
        Ok(key)
    }

    // ---- refusals -------------------------------------------------------

    // `ldapRefusal()`: recorded, then answered.
    fn refuse(&self, code: Option<ErrorCode>, summary: String, mut err: LdapError, target: &str) -> LdapError {
        if code.is_some() {
            err.code = code;
        }
        self.observer.notice(DirectoryNotice::Refused {
            code: err.code,
            summary,
            target: target.to_string(),
        });
        err
    }

    fn bound_dn(request: &Request) -> String {
        if request.bound_dn.is_empty() || request.bound_dn.to_lowercase() == "cn=anonymous" {
            String::new()
        } else {
            request.bound_dn.clone()
        }
    }

    // `rolesGrant()`.
    fn roles_grant(roles: crate::ports::Roles, role: &str) -> bool {
        let held = match role {
            "read" => roles.read || roles.write,
            "security" => roles.security,
            _ => roles.write,
        };
        held && !roles.open
    }

    // `boundDnHoldsRole()`: in the DEFAULT realm's store.
    fn holds_role(&self, bound: &str, role: &str) -> bool {
        match self.get(0, bound) {
            Some(stored) => Self::roles_grant(
                self.authority.roles_of(&Self::console_key(&stored.dn, Some(stored)), DEFAULT_REALM),
                role,
            ),
            None => false,
        }
    }

    // `boundDnHoldsRealmRole()`.
    fn holds_realm_role(&self, r: usize, bound: &str, role: &str) -> bool {
        if r == 0 || bound.is_empty() {
            return false;
        }
        match self.get(r, bound) {
            Some(stored) => Self::roles_grant(
                self.authority
                    .roles_of(&Self::console_key(&stored.dn, Some(stored)), &self.realms[r].id),
                role,
            ),
            None => false,
        }
    }

    // `securityNeedOf()`.
    fn security_need(
        &self,
        r: usize,
        operation: &str,
        dn: &str,
        types: &[String],
        values: &[(String, Vec<String>)],
        bound: &str,
    ) -> String {
        let target = normalize_dn(Some(dn));
        let rdns: Vec<&str> = target.split(',').collect();
        if let Some(c) = self.authority.policy_containers().into_iter().find(|c| rdns.contains(&c.as_str())) {
            return format!("it is under {c}, a Directory → Policies container");
        }
        let cn = self.settings.security_group().trim().to_string();
        let security_dn = if cn.is_empty() {
            String::new()
        } else {
            normalize_dn(Some(&format!("cn={},{}", escape_dn_value(Some(&cn)), self.groups_dn(r))))
        };
        if !security_dn.is_empty() && target == security_dn {
            return format!("it is {cn}, the Security Administrator's group");
        }
        let references = self.authority.policy_reference_attributes();
        let named: Vec<String> = distinct(types).into_iter().filter(|t| references.contains(t)).collect();
        if !named.is_empty() {
            return format!("it writes {}, which names a policy", named.join(", "));
        }
        let member_of = values
            .iter()
            .filter(|(t, _)| t.to_lowercase() == "memberof")
            .flat_map(|(_, v)| v.iter())
            .any(|v| {
                let text = v.trim();
                !security_dn.is_empty()
                    && (normalize_dn(Some(text)) == security_dn || text.to_lowercase() == cn.to_lowercase())
            });
        if member_of {
            return format!(
                "it writes a memberOf naming {cn}, which grants the Security Administrator's role"
            );
        }
        if operation != "add" && !bound.is_empty() && normalize_dn(Some(bound)) != target {
            if let Some(stored) = self.get(r, dn) {
                if self.is_person_dn(r, &stored.dn)
                    && self
                        .authority
                        .holds_security(&Self::console_key(&stored.dn, Some(stored)), &self.realms[r].id)
                {
                    return "it is the entry of a person who holds the Security Administrator's role".to_string();
                }
            }
        }
        String::new()
    }

    // `directoryWriteRefusal()`: product mode only.
    fn write_refusal(
        &self,
        r: usize,
        request: &Request,
        operation: &str,
        types: &[String],
        values: &[(String, Vec<String>)],
    ) -> Option<LdapError> {
        if !self.mode_at(r).authorizes_directory_writes() {
            return None;
        }
        let dn = &request.dn;
        let bound = Self::bound_dn(request);
        if bound.is_empty() {
            return Some(self.refuse(
                Some(codes::STS_LDAP_0052),
                format!("an anonymous connection asked for a {operation} of {dn}"),
                LdapError::new(
                    "InsufficientAccessRightsError",
                    "an anonymous connection may not write this directory; bind first",
                    None,
                ),
                dn,
            ));
        }
        let need = self.security_need(r, operation, dn, types, values, &bound);
        if !need.is_empty() {
            if self.holds_role(&bound, "security") || self.holds_realm_role(r, &bound, "security") {
                return None;
            }
            return Some(self.refuse(
                Some(codes::STS_LDAP_0203),
                format!(
                    "{bound} asked for a {operation} of {dn} without holding the Security Administrator's role: {need}"
                ),
                LdapError::new(
                    "InsufficientAccessRightsError",
                    format!("only a Security Administrator may make this change: {need}"),
                    None,
                ),
                dn,
            ));
        }
        if self.holds_role(&bound, "write") || self.holds_realm_role(r, &bound, "write") {
            return None;
        }
        let own = operation == "modify"
            && normalize_dn(Some(&bound)) == normalize_dn(Some(dn))
            && self.get(r, dn).is_some_and(|e| self.is_person_dn(r, &e.dn));
        if !own {
            let sentence = if operation == "modify" {
                "only an administrator may modify an entry other than your own".to_string()
            } else {
                format!("only an administrator may {operation} an entry")
            };
            return Some(self.refuse(
                Some(codes::STS_LDAP_0053),
                format!("{bound} asked for a {operation} of {dn} without holding Admin Write"),
                LdapError::new("InsufficientAccessRightsError", sentence, None),
                dn,
            ));
        }
        let allowed: Vec<String> = self
            .settings
            .self_writable_attributes()
            .into_iter()
            .filter(|t| !SERVICE_ACCOUNT_ATTRIBUTES.contains(&t.as_str()))
            .collect();
        let refused: Vec<String> = distinct(types).into_iter().filter(|t| !allowed.contains(t)).collect();
        if !refused.is_empty() {
            let list = refused.join(", ");
            return Some(self.refuse(
                Some(codes::STS_LDAP_0054),
                format!("{bound} asked to change {list} on their own entry, which is not self-writable"),
                LdapError::new(
                    "InsufficientAccessRightsError",
                    format!("you may not change {list} on your own entry"),
                    None,
                ),
                dn,
            ));
        }
        None
    }

    fn operational_refusal(&self, r: usize, operation: &str, dn: &str, types: &[String]) -> Option<LdapError> {
        let protected: &[&str] = if self.mode_at(r).protects_operational_attributes() {
            CLIENT_WRITTEN_OPERATIONAL
        } else {
            ALWAYS_PROTECTED_OPERATIONAL
        };
        let named: Vec<String> = distinct(types).into_iter().filter(|t| protected.contains(&t.as_str())).collect();
        if named.is_empty() {
            return None;
        }
        let list = named.join(", ");
        Some(self.refuse(
            Some(codes::STS_LDAP_0076),
            format!("a {operation} of {dn} named {list}, which this directory maintains itself"),
            LdapError::new(
                "ConstraintViolationError",
                format!("{list} is maintained by this directory and cannot be written"),
                None,
            ),
            dn,
        ))
    }

    fn credential_refusal(&self, operation: &str, dn: &str, types: &[String]) -> Option<LdapError> {
        let named: Vec<String> = distinct(types).into_iter().filter(|t| !credential_door(t).is_empty()).collect();
        if named.is_empty() {
            return None;
        }
        let list = named.join(", ");
        let doors: Vec<String> = named.iter().map(|t| format!("{t}: {}", credential_door(t))).collect();
        Some(self.refuse(
            Some(codes::STS_LDAP_0111),
            format!(
                "a {operation} of {dn} named the credential attribute(s) {list}, which are written only through \
their own doors"
            ),
            LdapError::new(
                "UnwillingToPerformError",
                format!("{list} is a credential and is not written over LDAP; use {}", doors.join("; ")),
                None,
            ),
            dn,
        ))
    }

    fn pseudonym_refusal(&self, operation: &str, dn: &str, types: &[String]) -> Option<LdapError> {
        let named: Vec<String> = distinct(types)
            .into_iter()
            .filter(|t| PSEUDONYM_LDAP_ATTRIBUTES.contains(&t.as_str()))
            .collect();
        if named.is_empty() {
            return None;
        }
        let list = named.join(", ");
        Some(self.refuse(
            Some(codes::STS_LDAP_0198),
            format!(
                "a {operation} of {dn} named {list}, which are written only through the portal and POST \
/admin-api/users/set-pseudonyms"
            ),
            LdapError::new(
                "ConstraintViolationError",
                format!("{list} is not written over LDAP; use the portal or POST /admin-api/users/set-pseudonyms"),
                None,
            ),
            dn,
        ))
    }

    fn key_refusal(&self, r: usize, verb: &str, dn: &str, target: &str) -> Option<LdapError> {
        let refusal = self
            .journal
            .dn_key_refusal(&self.realms[r].id, &normalize_dn(Some(target)))?;
        let short: String = dn.chars().take(80).collect();
        Some(self.refuse(
            Some(codes::STS_LDAP_0204),
            format!("{verb} of {short}… was refused: {refusal}"),
            LdapError::new("AdminLimitExceededError", refusal, None),
            dn,
        ))
    }

    // `membersNamingNothing()`: the member values a group write ADDS that
    // name no stored entry.
    fn members_naming_nothing(&self, r: usize, before: Option<&Attributes>, after: &[(String, Vec<String>)]) -> Vec<String> {
        let mut missing = Vec::new();
        for (name, uid) in MEMBER_ATTRIBUTES {
            let had: Vec<String> = before
                .and_then(|b| b.iter().find(|(k, _)| k.to_lowercase() == *name))
                .map(|(_, v)| {
                    v.iter()
                        .map(|s| if *uid { s.trim().to_lowercase() } else { normalize_dn(Some(s)) })
                        .collect()
                })
                .unwrap_or_default();
            let Some((_, values)) = after.iter().find(|(k, _)| k.to_lowercase() == *name) else {
                continue;
            };
            for value in values {
                let raw = value.trim().to_string();
                let key = if *uid { raw.to_lowercase() } else { normalize_dn(Some(&raw)) };
                if had.contains(&key) {
                    continue;
                }
                let there = if *uid {
                    self.existing_user_entry(r, &raw).is_some()
                } else {
                    !raw.is_empty() && self.get(r, &raw).is_some()
                };
                if !there {
                    missing.push(raw);
                }
            }
        }
        missing
    }

    // `passwordWriteRefusal()`: `attributes` is the entry as it will be
    // (keys in any case), `previous` as it was; a clear password is hashed
    // into `attributes` through the policy.
    fn password_refusal(
        &self,
        r: usize,
        dn: &str,
        attributes: &mut Vec<(String, Vec<String>)>,
        previous: &Attributes,
        touched: &[String],
    ) -> Option<LdapError> {
        if self.mode_at(r).verifies_credentials()
            && touched.iter().any(|t| t == "pwdhistory" || t == "pwdchangedtime")
        {
            return Some(LdapError::new(
                "ConstraintViolationError",
                "pwdHistory and pwdChangedTime are maintained by this service's password policy and cannot be written",
                Some(codes::STS_LDAP_0009),
            ));
        }
        if !touched.iter().any(|t| t == "userpassword") {
            return None;
        }
        let at = attributes.iter().position(|(k, _)| k.to_lowercase() == "userpassword");
        let values: Vec<String> = at.map(|i| attributes[i].1.clone()).unwrap_or_default();
        if values.is_empty() {
            return None;
        }
        if values.len() > 1 {
            return Some(LdapError::new(
                "ConstraintViolationError",
                "an entry holds one userPassword; replace it rather than adding a second",
                Some(codes::STS_LDAP_0010),
            ));
        }
        let value = values[0].clone();
        let had = previous.get("userpassword").and_then(|v| v.first()).cloned();
        if had.as_deref() == Some(value.as_str()) {
            return None;
        }
        if sts_crypto::secrets::is_hashed_secret(&value) {
            if self.mode_at(r).verifies_credentials() {
                return Some(LdapError::new(
                    "ConstraintViolationError",
                    "a pre-hashed userPassword cannot be checked against the password policy; send the password \
itself (over LDAPS), or set it through /admin-api/users/set-password",
                    Some(codes::STS_LDAP_0011),
                ));
            }
            return None;
        }
        let history: Vec<String> = previous.get("pwdhistory").cloned().unwrap_or_default();
        match self.rules.prepare_password(
            &Self::username_of_dn(dn),
            &value,
            had.as_deref().unwrap_or(""),
            &history,
        ) {
            Err(refusal) => Some(LdapError::new(
                "ConstraintViolationError",
                refusal.message,
                Some(refusal.code.unwrap_or(codes::STS_LDAP_0012)),
            )),
            Ok(prepared) => {
                if let Some(i) = at {
                    attributes[i].1 = vec![prepared.hash];
                }
                let key_of = |list: &Vec<(String, Vec<String>)>, lower: &str| {
                    list.iter().position(|(k, _)| k.to_lowercase() == lower)
                };
                match (key_of(attributes, "pwdhistory"), prepared.history.is_empty()) {
                    (Some(i), false) => attributes[i].1 = prepared.history,
                    (None, false) => attributes.push(("pwdhistory".to_string(), prepared.history)),
                    (Some(i), true) => {
                        attributes.remove(i);
                    }
                    (None, true) => {}
                }
                let now = vec![self.clock.generalized_time()];
                match key_of(attributes, "pwdchangedtime") {
                    Some(i) => attributes[i].1 = now,
                    None => attributes.push(("pwdchangedtime".to_string(), now)),
                }
                None
            }
        }
    }

    // `resolveServiceAccountOwner()`: a person's or a group's kind, or "".
    fn owner_kind(&self, r: usize, value: &str) -> &'static str {
        let text = value.trim();
        let mut stored = if text.is_empty() { None } else { self.locate(r, text) };
        if stored.is_none() && !text.is_empty() && !crate::uuid::dn_shaped(text) {
            stored = self.get(r, &format!("cn={},{}", escape_dn_value(Some(text)), self.groups_dn(r)));
        }
        let Some(stored) = stored else { return "" };
        if self.is_person_dn(r, &stored.dn) {
            return "person";
        }
        let groups = self.groups_dn(r);
        if is_under(Some(&stored.dn), Some(&groups)) && normalize_dn(Some(&stored.dn)) != normalize_dn(Some(&groups)) {
            return "group";
        }
        ""
    }

    // `serviceAccountWriteRefusal()`.
    fn service_account_refusal(&self, r: usize, working: &Attributes, touched: &[String]) -> Option<LdapError> {
        let changed: Vec<&String> = touched
            .iter()
            .filter(|t| SERVICE_ACCOUNT_ATTRIBUTES.contains(&t.as_str()))
            .collect();
        if changed.is_empty() {
            return None;
        }
        let maintained: Vec<String> = changed
            .iter()
            .filter(|t| SERVICE_ACCOUNT_MAINTAINED.contains(&t.as_str()))
            .map(|t| t.to_string())
            .collect();
        if !maintained.is_empty() && self.mode_at(r).verifies_credentials() {
            return Some(LdapError::new(
                "ConstraintViolationError",
                format!(
                    "{} are maintained by this service's password rotation and cannot be written",
                    maintained.join(", ")
                ),
                Some(codes::STS_SVCACCT_0030),
            ));
        }
        if let Some(reference) = self.rules.service_account_reference_refusal(working) {
            let code = if reference.code == Some(codes::STS_SVCACCT_0048) {
                codes::STS_SVCACCT_0048
            } else {
                codes::STS_SVCACCT_0050
            };
            return Some(LdapError::new("ConstraintViolationError", reference.message, Some(code)));
        }
        if !Self::is_service_account(working) {
            return None;
        }
        let first = |name: &str| {
            working
                .get(name)
                .and_then(|v| v.first())
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        };
        let owners: Vec<String> = working
            .get("stsserviceaccountowner")
            .map(|v| v.iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
            .unwrap_or_default();
        if owners.is_empty()
            && self
                .rules
                .service_account_requires_owner(&first("stsserviceaccountpolicy"), &first("uid"))
        {
            return Some(LdapError::new(
                "ConstraintViolationError",
                "this realm's service-account policy requires stsServiceAccountOwner (a person or a group)",
                Some(codes::STS_SVCACCT_0023),
            ));
        }
        if owners.len() > MAX_OWNERS {
            return Some(LdapError::new(
                "ConstraintViolationError",
                format!("stsServiceAccountOwner may hold at most {MAX_OWNERS} values"),
                Some(codes::STS_SVCACCT_0031),
            ));
        }
        if owners.iter().any(|o| !matches!(self.owner_kind(r, o), "person" | "group")) {
            return Some(LdapError::new(
                "ConstraintViolationError",
                "stsServiceAccountOwner must name a person or a group in this realm",
                Some(codes::STS_SVCACCT_0024),
            ));
        }
        if first("stssecretdestination").is_empty() != first("stssecretname").is_empty() {
            return Some(LdapError::new(
                "ConstraintViolationError",
                "stsSecretDestination and stsSecretName go together",
                Some(codes::STS_SVCACCT_0026),
            ));
        }
        None
    }

    // `keepServiceAccountClass()`.
    fn keep_service_account_class(&self, attributes: &mut Attributes) {
        let class = self.model.object_class("serviceAccount");
        let mut classes: Vec<String> = attributes
            .get("objectclass")
            .map(|v| v.iter().filter(|c| c.to_lowercase() != class.to_lowercase()).cloned().collect())
            .unwrap_or_default();
        if Self::is_service_account(attributes) {
            classes.push(class);
        }
        if !classes.is_empty() {
            attributes.insert("objectclass".to_string(), classes);
        }
    }

    // ---- the reader ---------------------------------------------------

    // `readerOf()`.
    fn reader_of(&self, r: usize, request: &Request) -> Reader {
        if !self.mode_at(r).authorizes_directory_reads() {
            return Reader {
                kind: ReaderKind::Unrestricted,
                dn: String::new(),
                readable_of_others: Vec::new(),
                group_members_readable: false,
            };
        }
        let bound = Self::bound_dn(request);
        if bound.is_empty() {
            return Reader {
                kind: ReaderKind::Anonymous,
                dn: String::new(),
                readable_of_others: Vec::new(),
                group_members_readable: false,
            };
        }
        let dn = normalize_dn(Some(&bound));
        if self.holds_role(&bound, "read") || self.holds_realm_role(r, &bound, "read") {
            return Reader {
                kind: ReaderKind::Administrator,
                dn,
                readable_of_others: Vec::new(),
                group_members_readable: false,
            };
        }
        Reader {
            kind: if self.get(r, &bound).is_some() {
                ReaderKind::Person
            } else {
                ReaderKind::Outsider
            },
            dn,
            readable_of_others: self.settings.directory_readable_attributes(),
            group_members_readable: self.settings.group_members_readable(),
        }
    }

    // `readKindOf()`.
    fn read_kind(&self, r: usize, stored: &Entry) -> EntryKind {
        if self.is_person_dn(r, &stored.dn) {
            return EntryKind::Person;
        }
        if !self.group_rule(r, &stored.dn, &stored.attributes).is_empty() {
            return EntryKind::Group;
        }
        let normal = normalize_dn(Some(&stored.dn));
        let crl_class = stored.values("objectclass").iter().any(|c| c.to_lowercase() == "crldistributionpoint");
        if normal.contains(",ou=crl,") && crl_class {
            return EntryKind::Public;
        }
        let leaf = split_rdns(Some(&stored.dn)).into_iter().next().unwrap_or_default();
        let pairs = rdn_pairs(Some(&leaf));
        let named = !pairs.is_empty() && pairs.iter().all(|p| ["ou", "dc", "o"].contains(&p.attribute.as_str()));
        if named || normal == normalize_dn(Some(self.base(r))) {
            EntryKind::Container
        } else {
            EntryKind::Other
        }
    }

    // `listedMemberDns()`.
    fn listed_member_dns(&self, r: usize, stored: &Entry) -> Vec<String> {
        let users = self.users_dn(r);
        let mut out = Vec::new();
        for (name, uid) in MEMBER_ATTRIBUTES {
            for v in stored.values(name) {
                out.push(if *uid {
                    normalize_dn(Some(&format!("uid={},{users}", escape_dn_value(Some(v)))))
                } else {
                    normalize_dn(Some(v))
                });
            }
        }
        out
    }

    // `readViewOf()`: whether the entry is visible, and the rule.
    fn read_view(&self, r: usize, reader: &Reader, stored: &Entry) -> (bool, Option<AttributeRule>) {
        if matches!(reader.kind, ReaderKind::Unrestricted | ReaderKind::Administrator) {
            return (true, None);
        }
        let kind = self.read_kind(r, stored);
        let facts = EntryFacts {
            kind,
            dn: normalize_dn(Some(&stored.dn)),
            members: if kind == EntryKind::Group && reader.kind == ReaderKind::Person {
                self.listed_member_dns(r, stored)
            } else {
                Vec::new()
            },
        };
        if !read_policy::visible(reader, &facts) {
            return (false, None);
        }
        (true, Some(read_policy::attribute_rule(reader, &facts)))
    }

    fn withheld(&self, r: usize, name: &str) -> bool {
        self.mode_at(r).withholds_directory_secrets() && self.model.is_secret(name)
    }

    // `matchable()` as a reader may see it (`matchableForReader()`).
    fn matchable(
        &self,
        r: usize, stored: &Entry, rule: Option<&AttributeRule>) -> Attributes {
        let mut out = Attributes::new();
        for (name, values) in &stored.attributes {
            out.insert(name.clone(), values.clone());
            let ty = without_binary(name);
            if ty != *name && !out.contains_key(&ty) {
                out.insert(ty, values.clone());
            }
        }
        out.insert("entrydn".to_string(), vec![stored.dn.clone()]);
        let secrets = self.mode_at(r).withholds_directory_secrets();
        if !secrets && rule.is_none_or(|r| r.all) {
            return out;
        }
        out.retain(|name, _| {
            !((secrets && self.model.is_secret(name)) || rule.is_some_and(|r| !read_policy::readable(r, name)))
        });
        out
    }

    // `toSearchEntry()`.
    fn search_entry(
        &self,
        r: usize, stored: &Entry, requested: &[String], rule: Option<&AttributeRule>) -> SearchEntry {
        let wanted: Vec<String> = requested.iter().map(|a| a.to_lowercase()).collect();
        let all = wanted.is_empty() || wanted.iter().any(|w| w == "*");
        let mut attributes: Vec<(String, Vec<String>)> = Vec::new();
        for (name, values) in &stored.attributes {
            let operational = OPERATIONAL.contains(&name.as_str());
            let ty = without_binary(name);
            let asked = wanted.contains(name)
                || (ty != *name && (wanted.contains(&ty) || wanted.contains(&format!("{ty};binary"))));
            if self.withheld(r, name) {
                continue;
            }
            if rule.is_some_and(|r| !read_policy::readable(r, name)) {
                continue;
            }
            if asked || (all && !operational) {
                let spelt = self.model.canonical_name(name);
                // `new ldap.Attribute({ type, values })`: a `;binary`
                // type's strings are base64, read back as the bytes they
                // decode to.
                let shown = sts_ldap::attribute::Attribute::from_strings(
                    &spelt,
                    &shown_values(name, values.clone()),
                )
                .values();
                match attributes.iter_mut().find(|(k, _)| *k == spelt) {
                    Some(slot) => slot.1 = shown,
                    None => attributes.push((spelt, shown)),
                }
            }
        }
        if wanted.iter().any(|w| w == "entrydn") {
            match attributes.iter_mut().find(|(k, _)| k == "entryDN") {
                Some(slot) => slot.1 = vec![stored.dn.clone()],
                None => attributes.push(("entryDN".to_string(), vec![stored.dn.clone()])),
            }
        }
        SearchEntry {
            object_name: stored.dn.clone(),
            attributes,
        }
    }

    // `isCrlDistributionEntry()`.
    fn is_crl_distribution(&self, r: usize, scope: i64, dn: &str) -> bool {
        if scope != 0 || !normalize_dn(Some(dn)).contains(",ou=crl,") {
            return false;
        }
        self.get(r, dn).is_some_and(|e| {
            e.values("objectclass").iter().any(|c| c.to_lowercase() == "crldistributionpoint")
        })
    }

    // `directoryReadRefusal()`.
    fn read_refusal(&self, r: usize, request: &Request, operation: &str, scope: Option<i64>) -> Option<LdapError> {
        if !self.mode_at(r).requires_directory_bind() || !Self::bound_dn(request).is_empty() {
            return None;
        }
        if let Some(s) = scope {
            if self.is_crl_distribution(r, s, &request.dn) {
                return None;
            }
        }
        let dn = &request.dn;
        Some(self.refuse(
            Some(codes::STS_LDAP_0074),
            format!("a {operation} of {dn} arrived on a connection that has not bound as anybody"),
            LdapError::new("InsufficientAccessRightsError", "bind as somebody before reading this directory", None),
            dn,
        ))
    }

    // ---- the handlers -------------------------------------------------

    /// One operation, as the socket's handler answers it.
    #[tracing::instrument(level = "debug", skip(self), fields(dn = %request.dn))]
    pub fn perform(&mut self, request: &Request) -> Outcome {
        let result = match &request.operation {
            Operation::Add { attributes } => self.add(request, attributes).map(|_| Outcome::default()),
            Operation::Modify { changes } => self.modify(request, changes).map(|_| Outcome::default()),
            Operation::Delete => self.delete(request).map(|_| Outcome::default()),
            Operation::ModifyDn {
                new_rdn,
                new_superior,
                delete_old_rdn,
            } => self
                .modify_dn(request, new_rdn, new_superior, *delete_old_rdn)
                .map(|_| Outcome::default()),
            Operation::Compare { attribute, value } => self.compare(request, attribute, value).map(|m| Outcome {
                compared: Some(m),
                ..Outcome::default()
            }),
            Operation::Search { .. } => return self.search(request),
        };
        match result {
            Ok(o) => o,
            Err(e) => Outcome {
                error: Some(e),
                ..Outcome::default()
            },
        }
    }

    fn add(&mut self, request: &Request, given: &[(String, Vec<String>)]) -> Result<(), LdapError> {
        let dn = request.dn.clone();
        let r = self.realm_for(&dn);
        let types = values_of(given);
        if let Some(e) = self.write_refusal(r, request, "add", &types, given) {
            return Err(e);
        }
        if let Some(e) = self.operational_refusal(r, "add", &dn, &types) {
            return Err(e);
        }
        if let Some(e) = self.credential_refusal("add", &dn, &types) {
            return Err(e);
        }
        if let Some(e) = self.pseudonym_refusal("add", &dn, &types) {
            return Err(e);
        }
        if let Some(e) = self.key_refusal(r, "an add", &dn, &dn) {
            return Err(e);
        }
        if !self.in_naming_context(&dn) {
            let root = self.realms[0].base.clone();
            return Err(self.refuse(
                Some(codes::STS_LDAP_0003),
                format!("an add of {dn} named a DN outside this directory's naming context"),
                LdapError::new("NoSuchObjectError", root, None),
                &dn,
            ));
        }
        if self.get(r, &dn).is_some() {
            return Err(self.refuse(
                Some(codes::STS_LDAP_0004),
                format!("an add of {dn} named an entry that already exists"),
                LdapError::new("EntryAlreadyExistsError", dn.clone(), None),
                &dn,
            ));
        }
        let parent = parent_dn(Some(&dn));
        let users = self.users_dn(r);
        let under_users = normalize_dn(Some(&parent)) == normalize_dn(Some(&users));
        if under_users {
            let mut proposed = vec![Self::username_of_dn(&dn)];
            for (t, v) in given {
                if t.to_lowercase() == "uid" {
                    proposed.extend(v.iter().cloned());
                }
            }
            let clash = proposed
                .iter()
                .find_map(|c| self.existing_user_entry(r, c).map(|e| e.dn.clone()));
            if let Some(held) = clash {
                return Err(self.refuse(
                    Some(codes::STS_LDAP_0005),
                    format!("an add of {dn} named a username {held} already holds"),
                    LdapError::new("EntryAlreadyExistsError", held, None),
                    &dn,
                ));
            }
        }
        if !parent.is_empty() && self.get(r, &parent).is_none() {
            return Err(self.refuse(
                Some(codes::STS_LDAP_0006),
                format!("an add of {dn} named a parent that does not exist"),
                LdapError::new("NoSuchObjectError", parent, None),
                &dn,
            ));
        }
        let max = self.settings.max_entries();
        if self.total_entries() as i64 >= max {
            return Err(self.refuse(
                Some(codes::STS_LDAP_0007),
                format!("an add of {dn} was refused because the directory holds its maximum of {max} entries"),
                LdapError::new(
                    "AdminLimitExceededError",
                    format!("this directory holds its maximum of {max} entries"),
                    None,
                ),
                &dn,
            ));
        }
        // The attributes as the handler holds them: keyed by the type as
        // sent, a later row of the same type replacing an earlier one.
        let mut attributes: Vec<(String, Vec<String>)> = Vec::new();
        let mut nul: Option<LdapError> = None;
        for (t, v) in given {
            if nul.is_none() {
                nul = nul_refusal(t, v);
            }
            match attributes.iter_mut().find(|(k, _)| k == t) {
                Some(slot) => slot.1 = v.clone(),
                None => attributes.push((t.clone(), v.clone())),
            }
        }
        if let Some(e) = nul {
            return Err(self.refuse(None, format!("an add of {dn} carried a value with a NUL byte"), e, &dn));
        }
        if description_carries_code(&attributes) {
            return Err(self.refuse(
                Some(codes::STS_LDAP_0211),
                format!("an add of {dn} carried a description with an operator error code"),
                LdapError::new("ConstraintViolationError", DESCRIPTION_OPERATOR_CODE, None),
                &dn,
            ));
        }
        if under_users {
            let lowered = lowered(&attributes);
            let keys: Vec<String> = lowered.keys().cloned().collect();
            if let Some(e) = self.service_account_refusal(r, &lowered, &keys) {
                return Err(self.refuse(None, format!("an add of {dn} was refused by the service-account rules"), e, &dn));
            }
            if let Some(e) = self.password_refusal(r, &dn, &mut attributes, &Attributes::new(), &keys) {
                return Err(self.refuse(
                    None,
                    format!("an add of {dn} carried a userPassword the password policy refused"),
                    e,
                    &dn,
                ));
            }
            if !Self::is_service_account(&lowered) {
                let mut prospective = lowered.clone();
                let leaf_len = dn.len().saturating_sub(parent.len() + 1);
                let leaf = dn.get(..leaf_len).unwrap_or("");
                if let Some((t, v)) = rdn_of(leaf) {
                    if prospective.get(&t).is_none_or(Vec::is_empty) {
                        prospective.insert(t, vec![v]);
                    }
                }
                if let Some(refusal) = self.rules.attribute_create_refusal(&prospective, !self.mode_at(r).creates_incomplete_people()) {
                    return Err(self.refuse(
                        Some(codes::STS_LDAP_0162),
                        format!(
                            "an add of {dn} was refused by the attribute policy: it holds no {}",
                            refusal.names.join(", ")
                        ),
                        LdapError::new("ObjectclassViolationError", refusal.message, None),
                        &dn,
                    ));
                }
            }
        }
        let added = lowered(&attributes);
        if !self.group_rule(r, &dn, &added).is_empty() {
            let pairs: Vec<(String, Vec<String>)> = added.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            let nothing = self.members_naming_nothing(r, None, &pairs);
            if !nothing.is_empty() {
                let list = nothing.join(", ");
                return Err(self.refuse(
                    Some(codes::STS_LDAP_0212),
                    format!("an add of {dn} listed {list} as a member, and nothing is stored there"),
                    LdapError::new(
                        "ConstraintViolationError",
                        format!("a group lists only entries that exist; nothing is stored at {list}"),
                        None,
                    ),
                    &dn,
                ));
            }
        }
        // `stampLdapRegistration()`.
        if normalize_dn(Some(&parent)) == normalize_dn(Some(&self.applications_dn(r)))
            && !attributes
                .iter()
                .any(|(k, v)| k.to_lowercase() == "appregisteredby" && !v.is_empty())
        {
            let bound = Self::bound_dn(request);
            let by = if bound.is_empty() { "ldap".to_string() } else { format!("ldap:{bound}") };
            match attributes.iter_mut().find(|(k, _)| k == "appRegisteredBy") {
                Some(slot) => slot.1 = vec![by],
                None => attributes.push(("appRegisteredBy".to_string(), vec![by])),
            }
        }
        self.put_entry(r, &dn, &attributes, Some("ldap add"), None)?;
        self.observer.notice(DirectoryNotice::Done {
            action: "create".to_string(),
            target: dn.clone(),
            summary: format!("added {dn} with {} attribute(s)", attributes.len()),
        });
        Ok(())
    }

    fn modify(&mut self, request: &Request, changes: &[Change]) -> Result<(), LdapError> {
        let dn = request.dn.clone();
        let r = self.realm_for(&dn);
        let types: Vec<String> = changes.iter().map(|c| c.attribute.to_lowercase()).collect();
        let written: Vec<(String, Vec<String>)> = changes
            .iter()
            .filter(|c| c.operation.to_lowercase() != "delete")
            .map(|c| (c.attribute.clone(), c.values.clone()))
            .collect();
        if let Some(e) = self.write_refusal(r, request, "modify", &types, &written) {
            return Err(e);
        }
        if let Some(e) = self.operational_refusal(r, "modify", &dn, &types) {
            return Err(e);
        }
        if let Some(e) = self.credential_refusal("modify", &dn, &types) {
            return Err(e);
        }
        if let Some(e) = self.pseudonym_refusal("modify", &dn, &types) {
            return Err(e);
        }
        let Some(stored) = self.get(r, &dn).cloned() else {
            return Err(self.refuse(
                Some(codes::STS_LDAP_0013),
                format!("a modify named {dn}, which does not exist"),
                LdapError::new("NoSuchObjectError", dn.clone(), None),
                &dn,
            ));
        };
        if changes.is_empty() {
            return Err(self.refuse(
                Some(codes::STS_LDAP_0015),
                format!("a modify of {dn} carried no changes"),
                LdapError::new("ProtocolError", "a modify must carry at least one change", None),
                &dn,
            ));
        }
        let mut working = stored.attributes.clone();
        for change in changes {
            let op = change.operation.to_lowercase();
            let ty = change.attribute.to_lowercase();
            let values = &change.values;
            if let Some(e) = nul_refusal(&ty, values) {
                return Err(self.refuse(None, format!("a modify of {dn} carried a value with a NUL byte"), e, &dn));
            }
            if (op == "add" || op == "replace")
                && !values.is_empty()
                && ty == "description"
                && values.iter().any(|v| carries_operator_code(v))
            {
                return Err(self.refuse(
                    Some(codes::STS_LDAP_0211),
                    format!("a modify of {dn} carried a description with an operator error code"),
                    LdapError::new("ConstraintViolationError", DESCRIPTION_OPERATOR_CODE, None),
                    &dn,
                ));
            }
            match op.as_str() {
                "add" => {
                    let mut now = working.get(&ty).cloned().unwrap_or_default();
                    let before = now.clone();
                    now.extend(values.iter().filter(|v| !before.contains(v)).cloned());
                    working.insert(ty, now);
                }
                "replace" => {
                    if values.is_empty() {
                        working.shift_remove(&ty);
                    } else {
                        working.insert(ty, values.clone());
                    }
                }
                "delete" => {
                    let Some(held) = working.get(&ty).cloned() else {
                        return Err(self.refuse(
                            Some(codes::STS_LDAP_0017),
                            format!("a modify of {dn} deleted the attribute {ty}, which the entry does not hold"),
                            LdapError::new("NoSuchAttributeError", ty.clone(), None),
                            &dn,
                        ));
                    };
                    if values.is_empty() {
                        working.shift_remove(&ty);
                    } else {
                        let kept: Vec<String> = held.into_iter().filter(|v| !values.contains(v)).collect();
                        if kept.is_empty() {
                            working.shift_remove(&ty);
                        } else {
                            working.insert(ty, kept);
                        }
                    }
                }
                _ => {
                    return Err(self.refuse(
                        Some(codes::STS_LDAP_0016),
                        format!("a modify of {dn} named an unknown change operation"),
                        LdapError::new("ProtocolError", format!("unknown modify operation \"{op}\""), None),
                        &dn,
                    ));
                }
            }
        }
        if self.is_person_dn(r, &stored.dn) {
            let mut pairs: Vec<(String, Vec<String>)> = working.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            if let Some(e) = self.password_refusal(r, &stored.dn, &mut pairs, &stored.attributes, &types) {
                return Err(self.refuse(None, format!("a modify of {dn} was refused by the password rules"), e, &dn));
            }
            working = pairs.into_iter().collect();
            if let Some(e) = self.service_account_refusal(r, &working, &types) {
                return Err(self.refuse(None, format!("a modify of {dn} was refused by the service-account rules"), e, &dn));
            }
            if !Self::is_service_account(&working) {
                if let Some(taken) = self.rules.attribute_edit_refusal(
                    &stored.attributes,
                    &working,
                    !self.mode_at(r).creates_incomplete_people(),
                ) {
                    return Err(self.refuse(
                        Some(codes::STS_LDAP_0164),
                        format!(
                            "a modify of {dn} would have left {} without a value, which the attribute policy requires",
                            taken.names.join(", ")
                        ),
                        LdapError::new("ObjectclassViolationError", taken.message, None),
                        &dn,
                    ));
                }
            }
            self.keep_service_account_class(&mut working);
        }
        if let Some(created) = stored.attributes.get("createtimestamp") {
            working.insert("createtimestamp".to_string(), created.clone());
        } else if let Some(at) = &stored.created_at {
            working.insert("createtimestamp".to_string(), vec![at.clone()]);
        } else {
            working.shift_remove("createtimestamp");
        }
        if let Some(uuid) = stored.attributes.get("entryuuid") {
            working.insert("entryuuid".to_string(), uuid.clone());
        }
        working.shift_remove(ENTRY_UUID_ALIAS);
        if let Some(aliases) = stored.attributes.get(ENTRY_UUID_ALIAS) {
            working.insert(ENTRY_UUID_ALIAS.to_string(), aliases.clone());
        }
        if !self.group_rule(r, &stored.dn, &stored.attributes).is_empty()
            || !self.group_rule(r, &stored.dn, &working).is_empty()
        {
            let pairs: Vec<(String, Vec<String>)> = working.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            let nothing = self.members_naming_nothing(r, Some(&stored.attributes), &pairs);
            if !nothing.is_empty() {
                let list = nothing.join(", ");
                return Err(self.refuse(
                    Some(codes::STS_LDAP_0212),
                    format!("a modify of {dn} added {list} as a member, and nothing is stored there"),
                    LdapError::new(
                        "ConstraintViolationError",
                        format!("a group lists only entries that exist; nothing is stored at {list}"),
                        None,
                    ),
                    &dn,
                ));
            }
        }
        let now = self.clock.generalized_time();
        working.insert("modifytimestamp".to_string(), vec![now.clone()]);
        let key = normalize_dn(Some(&stored.dn));
        let before = stored.clone();
        if let Some(entry) = self.realms[r].entries.get_mut(&key) {
            entry.attributes = working;
            entry.modified_at = Some(now);
            let after = entry.clone();
            self.journal.touched(&self.realms[r].id, &key);
            self.observer.notice(DirectoryNotice::Written {
                realm: self.realms[r].id.clone(),
                before: Some(Box::new(before)),
                after: Box::new(after),
            });
        }
        Ok(())
    }

    fn delete(&mut self, request: &Request) -> Result<(), LdapError> {
        let dn = request.dn.clone();
        let r = self.realm_for(&dn);
        if let Some(e) = self.write_refusal(r, request, "delete", &[], &[]) {
            return Err(e);
        }
        let Some(stored) = self.get(r, &dn).cloned() else {
            return Err(self.refuse(
                Some(codes::STS_LDAP_0013),
                format!("a delete named {dn}, which does not exist"),
                LdapError::new("NoSuchObjectError", dn.clone(), None),
                &dn,
            ));
        };
        if self.is_bootstrap_administrator(r, &stored) {
            return Err(self.refuse(
                Some(codes::STS_LDAP_0077),
                format!(
                    "a delete of {dn} was refused: it is the default realm's bootstrap administrator, which cannot \
be deleted"
                ),
                LdapError::new("UnwillingToPerformError", dn.clone(), None),
                &dn,
            ));
        }
        if self.has_children(r, &dn) {
            return Err(self.refuse(
                Some(codes::STS_LDAP_0014),
                format!("a delete of {dn} was refused because it has entries beneath it"),
                LdapError::new("NotAllowedOnNonLeafError", dn.clone(), None),
                &dn,
            ));
        }
        let person = self.is_person_dn(r, &stored.dn);
        let group = !self.group_rule(r, &stored.dn, &stored.attributes).is_empty();
        let key = normalize_dn(Some(&stored.dn));
        self.realms[r].entries.shift_remove(&key);
        self.journal.touched(&self.realms[r].id, &key);
        self.observer.notice(DirectoryNotice::Removed {
            realm: self.realms[r].id.clone(),
            entry: Box::new(stored.clone()),
        });
        if person {
            // `removePersonEntry()`.
            self.forget_group_memberships(r, &stored.dn, "an LDAP delete");
            self.registers.forget_member("users", &Self::username_of_dn(&stored.dn));
            self.rewrite_owner_references(r, &stored.dn, "", "an LDAP delete");
        } else {
            if group {
                self.registers
                    .forget_member("groups", stored.first("cn").unwrap_or(""));
                self.rewrite_owner_references(r, &stored.dn, "", "an LDAP delete");
            }
            self.forget_group_memberships(r, &dn, "an LDAP delete");
        }
        Ok(())
    }

    fn modify_dn(&mut self, request: &Request, new_rdn: &str, new_superior: &str, delete_old_rdn: bool) -> Result<(), LdapError> {
        let dn = request.dn.clone();
        let r = self.realm_for(&dn);
        let superior = if new_superior.is_empty() {
            parent_dn(Some(&dn))
        } else {
            new_superior.to_string()
        };
        let target = if superior.is_empty() {
            new_rdn.to_string()
        } else {
            format!("{new_rdn},{superior}")
        };
        if let Some(e) = self.write_refusal(r, request, "rename", &[], &[]) {
            return Err(e);
        }
        if let Some(e) = self.key_refusal(r, "a rename", &dn, &target) {
            return Err(e);
        }
        let Some(stored) = self.get(r, &dn).cloned() else {
            return Err(self.refuse(
                Some(codes::STS_LDAP_0013),
                format!("a rename named {dn}, which does not exist"),
                LdapError::new("NoSuchObjectError", dn.clone(), None),
                &dn,
            ));
        };
        if self.is_bootstrap_administrator(r, &stored) {
            return Err(self.refuse(
                Some(codes::STS_LDAP_0077),
                format!(
                    "a rename of {dn} was refused: it is the default realm's bootstrap administrator, and a rename \
would delete that account under another name"
                ),
                LdapError::new("UnwillingToPerformError", dn.clone(), None),
                &dn,
            ));
        }
        if self.has_children(r, &dn) {
            return Err(self.refuse(
                Some(codes::STS_LDAP_0014),
                format!("a rename of {dn} was refused because it has entries beneath it"),
                LdapError::new("NotAllowedOnNonLeafError", dn.clone(), None),
                &dn,
            ));
        }
        if self.get(r, &target).is_some() {
            return Err(self.refuse(
                Some(codes::STS_LDAP_0004),
                format!("a rename of {dn} named {target}, which already exists"),
                LdapError::new("EntryAlreadyExistsError", target.clone(), None),
                &dn,
            ));
        }
        if !self.in_naming_context(&target) {
            let root = self.realms[0].base.clone();
            return Err(self.refuse(
                Some(codes::STS_LDAP_0003),
                format!("a rename of {dn} named a DN outside this directory's naming context"),
                LdapError::new("NoSuchObjectError", root, None),
                &dn,
            ));
        }
        if self.realm_for(&target) != r {
            return Err(self.refuse(
                Some(codes::STS_LDAP_0018),
                format!("a rename of {dn} would have moved it into another trust realm"),
                LdapError::new("AffectsMultipleDsasError", target.clone(), None),
                &dn,
            ));
        }
        let name_before = if self.is_person_dn(r, &stored.dn) {
            Self::person_name_of(&stored)
        } else {
            String::new()
        };
        let group_cn_before = stored.first("cn").unwrap_or("").to_string();
        let old_key = normalize_dn(Some(&stored.dn));
        self.realms[r].entries.shift_remove(&old_key);
        let mut moved = stored.clone();
        moved.dn = target.clone();
        if delete_old_rdn {
            let first = split_unescaped(&dn).into_iter().next().unwrap_or_default();
            let parts: Vec<&str> = first.split('=').collect();
            if parts.len() >= 2 {
                let old_type = parts[0].trim().to_lowercase();
                let old_value = parts[1..].join("=").trim().to_lowercase();
                let kept: Vec<String> = moved
                    .values(&old_type)
                    .iter()
                    .filter(|v| v.to_lowercase() != old_value)
                    .cloned()
                    .collect();
                if kept.is_empty() {
                    moved.attributes.shift_remove(&old_type);
                } else {
                    moved.attributes.insert(old_type, kept);
                }
            }
        }
        let parts: Vec<&str> = new_rdn.split('=').collect();
        if parts.len() >= 2 {
            let ty = parts[0].trim().to_lowercase();
            let value = parts[1..].join("=").trim().to_string();
            let mut current = moved.values(&ty).to_vec();
            if !current.contains(&value) {
                current.push(value);
                moved.attributes.insert(ty, current);
            }
        }
        moved
            .attributes
            .insert("modifytimestamp".to_string(), vec![self.clock.generalized_time()]);
        let new_key = normalize_dn(Some(&target));
        self.realms[r].entries.insert(new_key.clone(), moved.clone());
        self.journal.touched(&self.realms[r].id, &old_key);
        self.journal.touched(&self.realms[r].id, &new_key);
        self.observer.notice(DirectoryNotice::Renamed {
            realm: self.realms[r].id.clone(),
            from: dn.clone(),
            to: Box::new(moved.clone()),
        });
        let person = self.is_person_dn(r, &moved.dn);
        let name_after = if person { Self::person_name_of(&moved) } else { String::new() };
        self.move_group_memberships(r, &dn, &target, &name_before, &name_after);
        if person && !name_before.is_empty() {
            self.registers.rename_member("users", &name_before, &name_after);
        } else if !self.group_rule(r, &moved.dn, &moved.attributes).is_empty() && !group_cn_before.is_empty() {
            self.registers
                .rename_member("groups", &group_cn_before, moved.first("cn").unwrap_or(""));
        }
        if person || !self.group_rule(r, &moved.dn, &moved.attributes).is_empty() {
            self.rewrite_owner_references(r, &dn, &target, "an LDAP rename");
        }
        Ok(())
    }

    fn compare(&mut self, request: &Request, attribute: &str, value: &str) -> Result<bool, LdapError> {
        let dn = request.dn.clone();
        let r = self.realm_for(&dn);
        let ty = attribute.to_lowercase();
        if let Some(e) = self.read_refusal(r, request, "compare", None) {
            return Err(e);
        }
        if self.withheld(r, &ty) {
            return Err(self.refuse(
                Some(codes::STS_LDAP_0075),
                format!("a compare on {dn} named {ty}, a credential attribute no reader of this socket may test"),
                LdapError::new("InsufficientAccessRightsError", format!("{ty} cannot be compared over LDAP"), None),
                &dn,
            ));
        }
        let stored = self.get(r, &dn).cloned();
        let reader = self.reader_of(r, request);
        let view = stored.as_ref().map(|s| self.read_view(r, &reader, s));
        let (Some(stored), Some((true, rule))) = (stored.as_ref(), view.clone()) else {
            let suffix = if stored.is_some() { " for this reader" } else { "" };
            return Err(self.refuse(
                Some(codes::STS_LDAP_0013),
                format!("a compare named {dn}, which does not exist{suffix}"),
                LdapError::new("NoSuchObjectError", dn.clone(), None),
                &dn,
            ));
        };
        if let Some(rule) = &rule {
            if !read_policy::readable(rule, &ty) {
                let bound = Self::bound_dn(request);
                return Err(self.refuse(
                    Some(codes::STS_LDAP_0099),
                    format!("{bound} asked to compare {ty} on {dn}, which they may not read"),
                    LdapError::new("InsufficientAccessRightsError", format!("you may not read {ty} on this entry"), None),
                    &dn,
                ));
            }
        }
        let Some(held) = stored.attributes.get(&ty) else {
            return Err(self.refuse(
                Some(codes::STS_LDAP_0019),
                format!("a compare on {dn} named the attribute {ty}, which the entry does not hold"),
                LdapError::new("NoSuchAttributeError", ty.clone(), None),
                &dn,
            ));
        };
        let wanted = value.to_lowercase();
        Ok(held.iter().any(|v| v.to_lowercase() == wanted))
    }

    fn root_dse(&self) -> Entry {
        let r = 0;
        let mut attributes = Attributes::new();
        attributes.insert("objectclass".to_string(), vec!["top".to_string(), "LDAProotDSE".to_string()]);
        attributes.insert("namingcontexts".to_string(), self.naming_contexts());
        attributes.insert("supportedldapversion".to_string(), vec!["3".to_string()]);
        attributes.insert(
            "vendorname".to_string(),
            vec!["IYA STS (ldapjs, unmodified, pinned as a submodule)".to_string()],
        );
        if self.sasl_external {
            attributes.insert(
                "supportedsaslmechanisms".to_string(),
                SASL_MECHANISMS.iter().map(|s| s.to_string()).collect(),
            );
        }
        let binds = if self.mode_at(r).verifies_credentials() {
            "Binds are verified, and a read requires one. "
        } else {
            "Every bind succeeds except the password \"invalid\". "
        };
        let sasl = if self.sasl_external {
            "; SASL EXTERNAL binds over LDAPS with a client certificate this service issued."
        } else {
            ", and no SASL mechanism while LDAPS asks for no client certificate."
        };
        attributes.insert(
            "description".to_string(),
            vec![format!(
                "{binds}This directory has no schema and answers no controls or extended operations{sasl}"
            )],
        );
        Entry {
            dn: String::new(),
            attributes,
            origin: None,
            created_at: None,
            modified_at: None,
        }
    }

    fn search(&mut self, request: &Request) -> Outcome {
        let Operation::Search {
            scope,
            filter,
            attributes,
            size_limit,
        } = &request.operation
        else {
            return Outcome::default();
        };
        let base = request.dn.clone();
        let mut out = Outcome::default();
        if normalize_dn(Some(&base)).is_empty() {
            if *scope == 0 {
                out.entries.push(self.search_entry(0, &self.root_dse(), attributes, None));
            } else {
                let name = scope_name(*scope);
                out.error = Some(self.refuse(
                    Some(codes::STS_LDAP_0020),
                    format!("a {name} search of the root DSE was refused; only a base search reads it"),
                    LdapError::new("NoSuchObjectError", "", None),
                    "(root DSE)",
                ));
            }
            return out;
        }
        let r = self.realm_for(&base);
        if let Some(e) = self.read_refusal(r, request, "search", Some(*scope)) {
            out.error = Some(e);
            return out;
        }
        if !self.in_naming_context(&base) {
            out.error = Some(self.refuse(
                Some(codes::STS_LDAP_0003),
                format!("a search based at {base} named a DN outside this directory's naming context"),
                LdapError::new("NoSuchObjectError", base.clone(), None),
                &base,
            ));
            return out;
        }
        let reader = self.reader_of(r, request);
        let base_entry = self.get(r, &base).cloned();
        let visible = base_entry.as_ref().is_some_and(|e| self.read_view(r, &reader, e).0);
        if !visible {
            let suffix = if base_entry.is_some() { " for this reader" } else { "" };
            out.error = Some(self.refuse(
                Some(codes::STS_LDAP_0013),
                format!("a search named the base {base}, which does not exist{suffix}"),
                LdapError::new("NoSuchObjectError", base.clone(), None),
                &base,
            ));
            return out;
        }
        let parsed = Filter::parse(filter).ok();
        let server = self.settings.size_limit();
        let limit = if *size_limit > 0 { (*size_limit).min(server) } else { server };
        let entries: Vec<Entry> = self.realms[r].entries.values().cloned().collect();
        for stored in &entries {
            if !is_under(Some(&stored.dn), Some(&base)) {
                continue;
            }
            let depth = depth_under(Some(&stored.dn), Some(&base));
            if (*scope == 0 && depth != 0) || (*scope == 1 && depth != 1) {
                continue;
            }
            let (seen, rule) = self.read_view(r, &reader, stored);
            if !seen {
                continue;
            }
            let matched = match &parsed {
                Some(f) => matching::matches(f, &self.matchable(r, stored, rule.as_ref())).unwrap_or(false),
                None => false,
            };
            if !matched {
                continue;
            }
            if out.entries.len() as i64 >= limit {
                out.error = Some(LdapError::new(
                    "SizeLimitExceededError",
                    format!(
                        "this search returned its limit of {limit} entry/entries and the answer is INCOMPLETE; ask \
for less with a filter, or raise ldap.sizeLimit"
                    ),
                    Some(codes::STS_LDAP_0021),
                ));
                return out;
            }
            out.entries.push(self.search_entry(r, stored, attributes, rule.as_ref()));
        }
        out
    }

    // ---- the directory's own consequences -------------------------------

    // The groups listing `key`, in the store's order (`groupIndexNow()`'s
    // `byMember`): a `member` or `uniqueMember` naming the DN, or a
    // `memberUid` naming `uid=<value>` under `ou=users`.
    fn groups_listing(&self, r: usize, key: &str) -> Vec<String> {
        let users = self.users_dn(r);
        self.realms[r]
            .entries
            .iter()
            .filter(|(_, e)| !self.group_rule(r, &e.dn, &e.attributes).is_empty())
            .filter(|(_, e)| {
                MEMBER_ATTRIBUTES.iter().any(|(name, uid)| {
                    e.values(name).iter().any(|v| {
                        let means = if *uid { format!("uid={v},{users}") } else { v.clone() };
                        normalize_dn(Some(&means)) == key
                    })
                })
            })
            .map(|(k, _)| k.clone())
            .collect()
    }

    // `writeGroupEntry()` for an existing group: putEntry() with the row's
    // creation instant kept.
    fn write_group(&mut self, r: usize, dn: &str, attributes: Vec<(String, Vec<String>)>, origin: &str) -> Result<(), LdapError> {
        let existing = self.get(r, dn).cloned();
        if let Some(e) = &existing {
            if self.group_rule(r, &e.dn, &e.attributes).is_empty() {
                return Err(LdapError::new("OperationsError", "notAGroup", Some(codes::STS_LDAP_0048)));
            }
        }
        if self.get(r, &parent_dn(Some(dn))).is_none() {
            return Err(LdapError::new("OperationsError", "noParent", Some(codes::STS_LDAP_0006)));
        }
        if !self
            .members_naming_nothing(r, existing.as_ref().map(|e| &e.attributes), &attributes)
            .is_empty()
        {
            return Err(LdapError::new("OperationsError", "danglingMember", Some(codes::STS_LDAP_0212)));
        }
        let created = existing
            .as_ref()
            .and_then(|e| e.created_at.clone())
            .unwrap_or_else(|| self.clock.generalized_time());
        let origin = existing.as_ref().and_then(|e| e.origin.clone()).unwrap_or_else(|| origin.to_string());
        let key = self.put_entry(r, dn, &attributes, Some(&origin), None)?;
        let now = self.clock.generalized_time();
        if let Some(stored) = self.realms[r].entries.get_mut(&key) {
            stored.created_at = Some(created.clone());
            stored.attributes.insert("createtimestamp".to_string(), vec![created]);
            stored.attributes.insert("modifytimestamp".to_string(), vec![now]);
        }
        Ok(())
    }

    // `forgetGroupMemberships()`: a deleted DN out of every group.
    fn forget_group_memberships(&mut self, r: usize, dn: &str, origin: &str) -> usize {
        let key = normalize_dn(Some(dn));
        let users = self.users_dn(r);
        let mut changed = 0;
        for group_key in self.groups_listing(r, &key) {
            let Some(existing) = self.realms[r].entries.get(&group_key).cloned() else { continue };
            let mut removed = 0;
            let attributes: Vec<(String, Vec<String>)> = existing
                .attributes
                .iter()
                .filter(|(k, _)| !OPERATIONAL.contains(&k.to_lowercase().as_str()))
                .map(|(k, v)| {
                    let member = MEMBER_ATTRIBUTES.iter().find(|(n, _)| *n == k.to_lowercase());
                    let values = match member {
                        Some((_, uid)) => v
                            .iter()
                            .filter(|value| {
                                let means = if *uid { format!("uid={value},{users}") } else { value.to_string() };
                                let gone = normalize_dn(Some(&means)) == key;
                                if gone {
                                    removed += 1;
                                }
                                !gone
                            })
                            .cloned()
                            .collect(),
                        None => v.clone(),
                    };
                    (k.clone(), values)
                })
                .collect();
            if removed > 0 && self.write_group(r, &existing.dn, attributes, origin).is_ok() {
                changed += 1;
            }
        }
        changed
    }

    // `moveGroupMemberships()`: a renamed entry's memberships moved.
    fn move_group_memberships(&mut self, r: usize, old_dn: &str, new_dn: &str, old_name: &str, new_name: &str) -> usize {
        let key = normalize_dn(Some(old_dn));
        let mut changed = 0;
        for group_key in self.groups_listing(r, &key) {
            let Some(existing) = self.realms[r].entries.get(&group_key).cloned() else { continue };
            let mut moved = 0;
            let attributes: Vec<(String, Vec<String>)> = existing
                .attributes
                .iter()
                .filter(|(k, _)| !OPERATIONAL.contains(&k.to_lowercase().as_str()))
                .map(|(k, v)| {
                    let member = MEMBER_ATTRIBUTES.iter().find(|(n, _)| *n == k.to_lowercase());
                    let values = match member {
                        Some((_, true)) => v
                            .iter()
                            .map(|value| {
                                if !old_name.is_empty()
                                    && !new_name.is_empty()
                                    && value.to_lowercase() == old_name.to_lowercase()
                                {
                                    moved += 1;
                                    new_name.to_string()
                                } else {
                                    value.clone()
                                }
                            })
                            .collect(),
                        Some((_, false)) => v
                            .iter()
                            .map(|value| {
                                if normalize_dn(Some(value)) == key {
                                    moved += 1;
                                    new_dn.to_string()
                                } else {
                                    value.clone()
                                }
                            })
                            .collect(),
                        None => v.clone(),
                    };
                    (k.clone(), values)
                })
                .collect();
            if moved > 0 && self.write_group(r, &existing.dn, attributes, "an LDAP rename").is_ok() {
                changed += 1;
            }
        }
        changed
    }

    // `rewriteOwnerReferences()`: a deleted (`to` empty) or renamed owner
    // taken off or moved on every group's and service account's owner
    // list; the roles' and applications' are their registers'.
    fn rewrite_owner_references(&mut self, r: usize, old_dn: &str, to: &str, origin: &str) -> usize {
        let key = normalize_dn(Some(old_dn));
        let to = to.trim().to_string();
        if key.is_empty() || key == normalize_dn(Some(&to)) {
            return 0;
        }
        self.registers.rewrite_owner(old_dn, &to);
        let names = |values: &[String]| values.iter().any(|v| normalize_dn(Some(v)) == key);
        let replaced = |values: &[String]| {
            let mut out: Vec<String> = Vec::new();
            for v in values {
                let one = if normalize_dn(Some(v)) == key { to.clone() } else { v.clone() };
                if !one.is_empty() && !out.iter().any(|k| normalize_dn(Some(k)) == normalize_dn(Some(&one))) {
                    out.push(one);
                }
            }
            out
        };
        let applications = self.applications_dn(r);
        let devices = self.devices_dn(r);
        let naming: Vec<Entry> = self.realms[r]
            .entries
            .values()
            .filter(|e| OWNER_REFERENCE_ATTRIBUTES.iter().any(|a| names(e.values(a))))
            .cloned()
            .collect();
        let mut changed = 0;
        for stored in naming {
            if self.is_role_dn(r, &stored.dn)
                || is_under(Some(&stored.dn), Some(&applications))
                || is_under(Some(&stored.dn), Some(&devices))
            {
                continue;
            }
            if !self.group_rule(r, &stored.dn, &stored.attributes).is_empty() && names(stored.values("owner")) {
                // `writeGroupOwners()`: the entry's attributes sorted, the
                // operational ones and the owners left out, the owners last.
                let owners = replaced(stored.values("owner"));
                let mut keys: Vec<&String> = stored.attributes.keys().collect();
                keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
                let mut attributes: Vec<(String, Vec<String>)> = keys
                    .into_iter()
                    .filter(|k| !OPERATIONAL.contains(&k.as_str()) && k.as_str() != "owner")
                    .map(|k| (k.clone(), stored.attributes[k].clone()))
                    .collect();
                if !owners.is_empty() {
                    attributes.push(("owner".to_string(), owners));
                }
                if self.write_group(r, &stored.dn, attributes, origin).is_ok() {
                    changed += 1;
                }
            }
            if self.is_person_dn(r, &stored.dn) && names(stored.values("stsserviceaccountowner")) {
                // `writeServiceAccount()`.
                let owners = replaced(stored.values("stsserviceaccountowner"));
                let now = self.clock.generalized_time();
                let skey = normalize_dn(Some(&stored.dn));
                let mut working = stored.attributes.clone();
                if owners.is_empty() {
                    working.shift_remove("stsserviceaccountowner");
                } else {
                    working.insert("stsserviceaccountowner".to_string(), owners);
                }
                self.keep_service_account_class(&mut working);
                working.insert("modifytimestamp".to_string(), vec![now]);
                if let Some(entry) = self.realms[r].entries.get_mut(&skey) {
                    entry.attributes = working;
                    changed += 1;
                }
                self.journal.touched(&self.realms[r].id, &skey);
            }
        }
        changed
    }
}

// The attributes keyed lower-cased, a later key replacing an earlier one in
// its place, as a JS object built `lowered[key.toLowerCase()] = …` is.
fn lowered(attributes: &[(String, Vec<String>)]) -> Attributes {
    let mut out = Attributes::new();
    for (k, v) in attributes {
        out.insert(k.to_lowercase(), v.clone());
    }
    out
}

// The add's RDN test: `/^\s*([^=\s]+)\s*=\s*(.*)$/` over the leaf.
fn rdn_of(leaf: &str) -> Option<(String, String)> {
    let at = leaf.find('=')?;
    let ty = leaf[..at].trim();
    if ty.is_empty() || ty.chars().any(char::is_whitespace) {
        return None;
    }
    Some((ty.to_lowercase(), leaf[at + 1..].trim_start().to_string()))
}

// `String(dn).split(/(?<!\\),/)`.
fn split_unescaped(dn: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut previous = '\0';
    for c in dn.chars() {
        if c == ',' && previous != '\\' {
            out.push(std::mem::take(&mut current));
        } else {
            current.push(c);
        }
        previous = c;
    }
    out.push(current);
    out
}

fn scope_name(scope: i64) -> &'static str {
    match scope {
        0 => "base",
        1 => "one",
        _ => "sub",
    }
}
