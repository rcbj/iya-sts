// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! WHO MAY BE ISSUED A CERTIFICATE FOR WHOM, AND WHAT GOES IN IT
//! (`common/cert_enrollment.ts`, rule 3ag): the core ACME, EST and SCEP
//! issue through, so none of the three decides any of it.
//!
//! `common/CLAUDE.md`'s 3ag is the design and rcbj's four decisions of
//! 2026-09-13 its spine: a private key is kept only when this service made
//! it; each protocol authenticates natively; the CA, OCSP and KDC profiles
//! are refused; a host name is issued only when REGISTERED on the entry,
//! so nothing here ever dials an address somebody supplied.
//!
//! | Module | Node it ports |
//! |---|---|
//! | this file | the shapes, `resolveEntry()`, the authentication doors, `authorizeTarget()`, the profiles and an application's own rules, the transport rule and the throttles |
//! | [`csr`] | `parseCsr()` and `pki.csrProofOfPossession()` |
//! | [`issue`] | `targetFromRequest()`, `namesFor()`, `subjectFor()`, `issue()`, `issueWithServerKey()`, `findEnrolled()`, `revokeEnrolled()`, the records on an entry |
//! | [`credentials`] | the EAB key and the SCEP challenge, host names |
//! | [`trust`] | `pki.verifyLeaf()` and `authenticatePresentedCertificate()` |
//!
//! **NOT PORTED, AND HOW RUST ANSWERS MEANWHILE**: the `device` profile
//! (`issueForDevice()` — no device register is in the runtime yet; asked
//! for it, the core refuses with Node's `STS-DEVICE-0025` sentence for a
//! family that does not issue it, and EST/SCEP answer it with
//! `STS-ENROLL-0011`'s "no directory" refusal); cells (`credentialId()`
//! stamps nothing, as a single-cell Node service stamps nothing); the
//! cluster-SHARED throttle windows (`throttledShared()` is the local
//! window here, as `sharesThrottle()` is false where no store shares one);
//! paranoid PKI mode's field checks (`CertificateTrust.fields()`).

pub mod credentials;
pub mod csr;
pub mod issue;
pub mod trust;

use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_core::errors::{codes, ErrorCode};
use sts_core::mode::Mode;
use sts_core::realm::{self, RealmRegistry, DEFAULT_ID};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::settings::Settings;
use sts_credentials::limits::{Limit, RateLimiter};
use sts_credentials::ports::Keystore;
use sts_pki::authority::Authority;

use crate::ports::{
    Applications, Audit, Entries, EntryRead, IssuanceGate, Monitor, Passwords,
    Roster, Signals,
};

/// The three enrollment families.
pub const FAMILIES: &[&str] = &["acme", "est", "scep"];

/// The nine profiles an enrollment protocol issues
/// (`common/enrollment_profiles.js`).
pub const PROFILE_IDS: &[&str] = &[
    "tls-server",
    "tls-client",
    "tls-server-client",
    "digital-signature",
    "key-encipherment",
    "code-signing",
    "email",
    "timestamping",
    "smartcard-logon",
];

/// The five never issued, each with the reason every page draws.
pub const REFUSED_PROFILES: &[(&str, &str)] = &[
    (
        "root-ca",
        "A Root CA is a trust anchor. Its holder could issue a certificate for anybody and be \
         believed by everything that trusts this service's Root — and it is self-signed, so \
         it would not even chain to this authority.",
    ),
    (
        "intermediate-ca",
        "An Intermediate CA may sign further CAs. Its holder could build a branch of this \
         hierarchy nobody operates.",
    ),
    (
        "issuing-ca",
        "An Issuing CA signs certificates. Its holder could issue a certificate naming any \
         person or application in the realm, which is exactly the rule this whole module \
         exists to enforce.",
    ),
    (
        "ocsp-responder",
        "An OCSP Responder certificate issued by this realm's CA is a DELEGATED responder \
         (RFC 6960 section 4.2.2.2): its holder could sign \"good\" about a certificate this \
         service revoked, and a relying party would believe it.",
    ),
    (
        "kdc",
        "A Kerberos KDC certificate lets its holder answer PKINIT as the realm's KDC and \
         impersonate it to every client that trusts this authority.",
    ),
];

/// The device profile's id; issued over EST and SCEP only.
pub const DEVICE_PROFILE: &str = "device";
const DEVICE_PROFILE_FAMILIES: &[&str] = &["est", "scep"];

/// The most live EAB keys or SCEP challenges one entry may hold.
pub const MAX_CREDENTIALS_PER_ENTRY: usize = 10;

/// What a family is called in a sentence.
#[tracing::instrument(level = "debug")]
pub fn family_label(family: &str) -> &'static str {
    match family {
        "acme" => "ACME",
        "est" => "EST",
        "scep" => "SCEP",
        _ => "",
    }
}

/// The attribute each record family is kept in, per kind of entry.
#[tracing::instrument(level = "debug")]
pub fn attribute(kind: &str, key: &str) -> &'static str {
    let person = kind == "person";
    match key {
        "certificate" if person => "stsEnrolledCertificate",
        "certificate" => "appEnrolledCertificate",
        "privateKey" if person => "stsEnrolledPrivateKey",
        "privateKey" => "appEnrolledPrivateKey",
        "eab" if person => "stsAcmeEabKey",
        "eab" => "appAcmeEabKey",
        "challenge" if person => "stsScepChallenge",
        "challenge" => "appScepChallenge",
        "hostName" if person => "stsCertificateHostName",
        _ => "appCertificateHostName",
    }
}

/// A refusal: the HTTP status a protocol module should send, the code
/// marked on it, and the sentence for an operator (never a secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: ErrorCode,
    pub status: u16,
    pub sentence: String,
}

impl Refusal {
    /// `refuse(code, status, sentence)`.
    // A hot path: every refusal of every door; no span.
    pub fn new(
        code: ErrorCode,
        status: u16,
        sentence: impl Into<String>,
    ) -> Refusal {
        Refusal {
            code,
            status,
            sentence: sentence.into(),
        }
    }
}

pub type Outcome<T> = Result<T, Refusal>;

/// A person, an application or a device entry, by its identifier.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Entry {
    pub kind: String,
    pub id: String,
}

impl Entry {
    /// `{ kind, id }`.
    // A hot path: every record names one; no span.
    pub fn new(kind: &str, id: &str) -> Entry {
        Entry {
            kind: kind.to_string(),
            id: id.to_string(),
        }
    }

    /// `entryUri()`.
    // A hot path: as `new()`; no span.
    pub fn uri(&self) -> String {
        let prefix = match self.kind.as_str() {
            "device" => "urn:sts:device:",
            "person" => "urn:sts:person:",
            _ => "urn:sts:application:",
        };
        format!("{}{}", prefix, self.id)
    }

    /// `entryLabel()`: `person "alice"`.
    // A hot path: every sentence about an entry; no span.
    pub fn label(&self) -> String {
        let kind = if self.kind == "person" || self.kind == "device" {
            self.kind.as_str()
        } else {
            "application"
        };
        format!("{} \"{}\"", kind, self.id)
    }

    /// `{ kind, id }` as JSON.
    // A hot path: every record names one; no span.
    pub fn to_json(&self) -> Json {
        json!({ "kind": self.kind, "id": self.id })
    }

    /// From `{ kind, id }`.
    // A hot path: every stored row names one; no span.
    pub fn from_json(v: &Json) -> Option<Entry> {
        let kind = v.get("kind")?.as_str()?;
        let id = v.get("id")?.as_str()?;
        Some(Entry::new(kind, id))
    }
}

/// An authenticated principal: `{ kind, id, admin, via, realm, hasEntry }`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Principal {
    pub kind: String,
    pub id: String,
    pub admin: bool,
    pub via: String,
    pub realm: String,
    pub has_entry: bool,
    pub app_password: Option<String>,
    pub certificate_serial: Option<String>,
    pub certificate_family: Option<String>,
}

impl Principal {
    /// The entry it is.
    // A hot path: every identity rule asks; no span.
    pub fn entry(&self) -> Entry {
        Entry::new(&self.kind, &self.id)
    }

    /// `{ kind, id, admin }`, the record's `requestedBy`.
    // A hot path: every record; no span.
    pub fn requested_by(&self) -> Json {
        json!({ "kind": self.kind, "id": self.id, "admin": self.admin })
    }
}

/// `resolveEntry()`'s answer.
#[derive(Debug, Clone, Default)]
pub struct Resolved {
    pub entry: Entry,
    pub dn: String,
    pub mail: String,
    pub upn: String,
    pub host_names: Vec<String>,
    pub attributes: EntryRead,
}

impl Resolved {
    /// `heldValues(resolved, key)`: one of the record attributes' values.
    // A hot path: every record read; no span.
    pub fn held(&self, key: &str) -> Vec<String> {
        self.attributes.values(attribute(&self.entry.kind, key))
    }
}

/// What the core is built from.
pub struct CoreDeps {
    pub settings: Arc<Settings>,
    pub mode: Arc<Mode>,
    pub registry: Arc<RealmRegistry>,
    pub lifecycle: Option<Arc<RealmLifecycle>>,
    pub authority: Arc<Authority>,
    pub entries: Arc<dyn Entries>,
    pub applications: Arc<dyn Applications>,
    pub passwords: Arc<dyn Passwords>,
    pub roster: Arc<dyn Roster>,
    pub gate: Arc<dyn IssuanceGate>,
    pub audit: Arc<dyn Audit>,
    pub signals: Arc<dyn Signals>,
    pub monitor: Arc<dyn Monitor>,
    pub keystore: Arc<dyn Keystore>,
    pub claims: Arc<dyn sts_cluster::scheduler::Claims>,
    pub limits: Arc<RateLimiter>,
}

/// The core (`CertEnrollment`).
pub struct Core {
    pub(crate) d: CoreDeps,
}

/// `wellFormedId()`: printable, 1 to 256 characters (UTF-16 units), no
/// control character.
#[tracing::instrument(level = "trace")]
pub fn well_formed_id(id: &str) -> bool {
    let n = id.encode_utf16().count();
    (1..=256).contains(&n)
        && !id.chars().any(|c| (c as u32) < 0x20 || c == '\u{7f}')
}

/// `entryFromUri()`: the person or application a `urn:sts:` URI names.
#[tracing::instrument(level = "trace")]
pub fn entry_from_uri(uri: &str) -> Option<Entry> {
    for (kind, prefix) in [
        ("person", "urn:sts:person:"),
        ("application", "urn:sts:application:"),
    ] {
        if let Some(id) = uri.strip_prefix(prefix) {
            if well_formed_id(id) {
                return Some(Entry::new(kind, id));
            }
        }
    }
    None
}

/// `normalSerial()`: lower-case hex without leading zeros.
#[tracing::instrument(level = "trace")]
pub fn normal_serial(serial: &str) -> String {
    let hex: String = serial
        .chars()
        .filter(char::is_ascii_hexdigit)
        .collect::<String>()
        .to_ascii_lowercase();
    let trimmed = hex.trim_start_matches('0');
    if trimmed.is_empty() && !hex.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

/// `net.isIP(text)`.
#[tracing::instrument(level = "trace")]
pub fn is_ip(text: &str) -> bool {
    if text.contains('%') {
        // node accepts a zone id on IPv6.
        return text.split_once('%').is_some_and(|(a, z)| {
            !z.is_empty() && a.parse::<std::net::Ipv6Addr>().is_ok()
        });
    }
    if text.parse::<std::net::Ipv6Addr>().is_ok() {
        return true;
    }
    // node's IPv4 grammar: four decimal octets, no leading zero.
    let parts: Vec<&str> = text.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.chars().all(|c| c.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
                && p.parse::<u16>().is_ok_and(|n| n <= 255)
        })
}

/// `normalHostName()`: lower-cased, a trailing dot removed, RFC 1123
/// labels with one leading wildcard allowed; `''` when not one.
#[tracing::instrument(level = "trace")]
pub fn normal_host_name(value: &str) -> String {
    let mut text = value.trim().to_lowercase();
    if is_ip(&text) {
        return text;
    }
    if text.ends_with('.') {
        text.pop();
    }
    static RE: std::sync::LazyLock<Option<regex::Regex>> =
        std::sync::LazyLock::new(|| {
            regex::Regex::new(
                r"^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$",
            )
            .ok()
        });
    let ok =
        RE.as_ref().is_some_and(|re| re.is_match(&text)) && text.len() <= 253;
    if ok {
        text
    } else {
        String::new()
    }
}

/// `Date.now()`.
#[tracing::instrument(level = "trace")]
pub fn now_ms() -> f64 {
    sts_core::time::now_ms_f64()
}

/// `new Date(ms).toISOString()`.
#[tracing::instrument(level = "trace")]
pub fn iso(ms: f64) -> String {
    chrono::DateTime::from_timestamp_millis(ms as i64)
        .map(sts_core::time::iso)
        .unwrap_or_default()
}

/// `new Date(text).getTime()`; NaN for what does not parse.
#[tracing::instrument(level = "trace")]
pub fn ms_of(text: &str) -> f64 {
    chrono::DateTime::parse_from_rfc3339(text)
        .map(|t| t.timestamp_millis() as f64)
        .unwrap_or(f64::NAN)
}

/// A JSON value's text as `String(v || '')` reads it.
// A hot path: every record field read; no span.
pub fn str_of<'a>(v: &'a Json, key: &str) -> &'a str {
    v.get(key).and_then(Json::as_str).unwrap_or("")
}

/// `parseJsonValues()`: the values that are JSON objects; a value written
/// by hand that is not one is left on the entry and not read.
#[tracing::instrument(level = "trace", skip_all)]
pub fn parse_json_values(values: &[String]) -> Vec<Json> {
    values
        .iter()
        .filter_map(|v| serde_json::from_str::<Json>(v).ok())
        .filter(Json::is_object)
        .collect()
}

/// `JSON.stringify()` of a record.
// A hot path: every record written; no span.
pub fn stringify(v: &Json) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

impl Core {
    /// Builds the core over its ports.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(d: CoreDeps) -> Arc<Core> {
        Arc::new(Core { d })
    }

    /// The settings it reads.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn settings(&self) -> &Arc<Settings> {
        &self.d.settings
    }

    /// The mode it reads.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn mode(&self) -> &Arc<Mode> {
        &self.d.mode
    }

    /// The certificate authority.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn authority(&self) -> &Arc<Authority> {
        &self.d.authority
    }

    /// The audit log.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn audit(&self) -> &Arc<dyn Audit> {
        &self.d.audit
    }

    /// The enrollment monitor.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn monitor(&self) -> &Arc<dyn Monitor> {
        &self.d.monitor
    }

    /// The cluster claims.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn claims(&self) -> &Arc<dyn sts_cluster::scheduler::Claims> {
        &self.d.claims
    }

    /// The applications register.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn applications(&self) -> &Arc<dyn Applications> {
        &self.d.applications
    }

    /// The directory slot.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn entries(&self) -> &Arc<dyn Entries> {
        &self.d.entries
    }

    // A hot path: every request reads several settings; no span.
    pub(crate) fn setting_text(&self, key: &str) -> String {
        self.d.settings.value_of(key).as_str().to_string()
    }

    // A hot path: every request reads several settings; no span.
    pub(crate) fn setting_int(&self, key: &str) -> i64 {
        self.d.settings.value_of(key).as_int()
    }

    // A hot path: every request reads several settings; no span.
    pub(crate) fn setting_on(&self, key: &str) -> bool {
        // `config.value(key) !== false`.
        !matches!(
            self.d.settings.value_of(key),
            sts_core::settings::SettingValue::Bool(false)
        )
    }

    // A hot path: every request reads several settings; no span.
    pub(crate) fn setting_list(&self, key: &str) -> Vec<String> {
        match self.d.settings.value_of(key) {
            sts_core::settings::SettingValue::List(l) => l,
            other => other
                .as_str()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        }
    }

    /// Whether a trust realm of that id exists.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn realm_exists(&self, id: &str) -> bool {
        self.d.registry.get(id).is_some()
    }

    // A hot path: every request reads several settings; no span.
    pub(crate) fn predicate(&self, name: &str) -> bool {
        self.d.mode.predicate(name).unwrap_or(false)
    }

    // -----------------------------------------------------------------
    // THE ENTRY.
    // -----------------------------------------------------------------

    /// `resolveEntry(kind, id)` in the ambient realm.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn resolve_entry(&self, kind: &str, id: &str) -> Outcome<Resolved> {
        if !(kind == "person" || kind == "application") || !well_formed_id(id) {
            return Err(Refusal::new(
                codes::STS_ENROLL_0010,
                400,
                "A certificate is issued for a person or an application, named by a printable \
                 identifier of at most 256 characters.",
            ));
        }
        let Some(found) = self.d.entries.read(kind, id) else {
            return Err(Refusal::new(
                codes::STS_ENROLL_0012,
                404,
                format!(
                    "There is no {} in this realm. A certificate issued over an enrollment \
                     protocol always names an entry that exists, and is kept on it.",
                    Entry::new(kind, id).label()
                ),
            ));
        };
        let (mail, upn) = if kind == "person" {
            (found.first("mail"), found.first("userPrincipalName"))
        } else {
            (String::new(), String::new())
        };
        let host_names = found
            .values(attribute(kind, "hostName"))
            .iter()
            .map(|h| normal_host_name(h))
            .filter(|h| !h.is_empty())
            .collect();
        Ok(Resolved {
            entry: Entry::new(kind, id),
            dn: found.dn.clone(),
            mail,
            upn,
            host_names,
            attributes: found,
        })
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub(crate) fn read_attribute(
        &self,
        entry: &Entry,
        key: &str,
    ) -> Option<Vec<String>> {
        self.resolve_entry(&entry.kind, &entry.id)
            .ok()
            .map(|r| r.held(key))
    }

    // skip_all: the values are records, and an EAB key or a challenge in
    // one is not for the log.
    #[tracing::instrument(level = "debug", skip_all)]
    pub(crate) fn write_attribute(
        &self,
        entry: &Entry,
        key: &str,
        values: &[String],
    ) -> bool {
        let written = self.d.entries.write(
            &entry.kind,
            &entry.id,
            attribute(&entry.kind, key),
            values,
        );
        if !written {
            tracing::error!(
                "{}enrollment: could not write {} on the {}: no such entry",
                sts_core::log::tag(codes::STS_ENROLL_0041.as_str()),
                attribute(&entry.kind, key),
                entry.label()
            );
        }
        written
    }

    // -----------------------------------------------------------------
    // AUTHENTICATION.
    // -----------------------------------------------------------------

    fn roster_grants(&self, name: &str, realm_id: &str, session: bool) -> bool {
        let roles = self.d.roster.roles_of(name, realm_id);
        roles.write && !roles.open && (!session || !roles.claim_pending)
    }

    /// `adminFor(username, password, via)`: Admin Write in the default
    /// realm's roster or the ambient realm's, with the password verified
    /// in THAT roster's realm. An empty roster grants nothing here.
    #[tracing::instrument(level = "debug", skip(self, password))]
    pub async fn admin_for(
        &self,
        username: &str,
        password: &str,
        via: &str,
    ) -> bool {
        if username.is_empty() {
            return false;
        }
        let default = self.d.registry.default_realm();
        let passwords = self.d.passwords.clone();
        let verified = realm::run(default, async {
            passwords.verify(username, password, via, "est").ok
        })
        .await;
        if verified && self.roster_grants(username, DEFAULT_ID, false) {
            return true;
        }
        let here = realm::current_id();
        if here == DEFAULT_ID {
            return false;
        }
        let local = self.d.passwords.verify(username, password, via, "est").ok;
        local && self.roster_grants(username, &here, false)
    }

    /// `sessionIsAdmin(username)`: the ambient realm's roster, for a
    /// principal a session already authenticated.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn session_is_admin(&self, username: &str) -> bool {
        self.roster_grants(username, &realm::current_id(), true)
    }

    /// `sessionPrincipal(username, via, { admin })`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn session_principal(
        &self,
        username: &str,
        via: &str,
        admin: Option<bool>,
    ) -> Principal {
        let has_entry = !username.is_empty()
            && self.resolve_entry("person", username).is_ok();
        Principal {
            kind: "person".into(),
            id: username.to_string(),
            admin: admin == Some(true)
                || (admin != Some(false) && self.session_is_admin(username)),
            via: via.to_string(),
            realm: realm::current_id(),
            has_entry,
            ..Default::default()
        }
    }

    /// `authenticatePerson(username, password, via)`, EST's Basic.
    #[tracing::instrument(level = "debug", skip(self, password))]
    pub async fn authenticate_person(
        &self,
        username: &str,
        password: &str,
        via: &str,
    ) -> Outcome<Principal> {
        if !well_formed_id(username) {
            return Err(Refusal::new(
                codes::STS_ENROLL_0013,
                401,
                "A username is required.",
            ));
        }
        let local = self.resolve_entry("person", username);
        let verified = if local.is_ok() {
            Some(self.d.passwords.verify(username, password, via, "est"))
        } else {
            None
        };
        let admin = self.admin_for(username, password, via).await;
        if let (Ok(_), Some(v)) = (&local, &verified) {
            if v.ok {
                return Ok(Principal {
                    kind: "person".into(),
                    id: username.to_string(),
                    admin,
                    via: via.to_string(),
                    realm: realm::current_id(),
                    has_entry: true,
                    app_password: v.app_password.clone(),
                    ..Default::default()
                });
            }
        }
        if admin {
            return Ok(Principal {
                kind: "person".into(),
                id: username.to_string(),
                admin: true,
                via: via.to_string(),
                realm: realm::current_id(),
                has_entry: false,
                ..Default::default()
            });
        }
        // A RIGHT PASSWORD REFUSED FOR WANT OF A SECOND FACTOR is recorded
        // as the verifier's STS-AUTHN-0213, as LDAP and SCIM record it; the
        // answer is the same (Node's fix of 2026-11-14, #444 D12).
        if local.is_ok()
            && verified
                .as_ref()
                .is_some_and(|v| v.reason == "second-factor-required")
        {
            return Err(Refusal::new(
                codes::STS_AUTHN_0213,
                401,
                "The password was not accepted.",
            ));
        }
        Err(Refusal::new(
            if local.is_ok() {
                codes::STS_ENROLL_0014
            } else {
                codes::STS_ENROLL_0015
            },
            401,
            "The password was not accepted.",
        ))
    }

    /// `secretsEqual()`: SHA-256 of each, in constant time.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn secrets_equal(presented: &str, expected: &str) -> bool {
        let a = sts_crypto::jws_alg::Hash::Sha256.digest(presented.as_bytes());
        let b = sts_crypto::jws_alg::Hash::Sha256.digest(expected.as_bytes());
        sts_crypto::secrets::constant_time_equals(&a, &b)
            && !expected.is_empty()
    }

    /// `authenticateApplication(clientId, secret, via)`, EST's Basic for
    /// an application.
    #[tracing::instrument(level = "debug", skip(self, secret))]
    pub fn authenticate_application(
        &self,
        client_id: &str,
        secret: &str,
        via: &str,
    ) -> Outcome<Principal> {
        if !well_formed_id(client_id) {
            return Err(Refusal::new(
                codes::STS_ENROLL_0013,
                401,
                "A client_id is required.",
            ));
        }
        let refused = || {
            Refusal::new(
                codes::STS_ENROLL_0016,
                401,
                "The client credentials were not accepted.",
            )
        };
        let Some(view) = self
            .d
            .applications
            .find(client_id)
            .filter(|v| !v.identifier.is_empty())
        else {
            return Err(refused());
        };
        if self.predicate("requiresConfidentialClientAuthentication") {
            let expected = self.d.applications.client_secret(&view.identifier);
            if expected.is_empty() || !Core::secrets_equal(secret, &expected) {
                return Err(refused());
            }
        }
        self.resolve_entry("application", &view.identifier)?;
        Ok(Principal {
            kind: "application".into(),
            id: view.identifier.clone(),
            admin: false,
            via: via.to_string(),
            realm: realm::current_id(),
            has_entry: true,
            ..Default::default()
        })
    }

    /// `authorizeTarget(principal, target)`: its own entry, or as an
    /// administrator any person or application in the realm. `Ok(true)`
    /// when it is as an administrator.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn authorize_target(
        &self,
        principal: Option<&Principal>,
        target: &Entry,
    ) -> Outcome<bool> {
        let kinds = |k: &str| k == "person" || k == "application";
        let Some(p) =
            principal.filter(|p| kinds(&p.kind) && kinds(&target.kind))
        else {
            return Err(Refusal::new(
                codes::STS_ENROLL_0020,
                403,
                "Nobody authenticated, or nobody was named.",
            ));
        };
        if p.entry() == *target && p.has_entry {
            return Ok(false);
        }
        if p.kind == "person" && p.admin {
            return Ok(true);
        }
        Err(Refusal::new(
            codes::STS_ENROLL_0021,
            403,
            format!(
                "A certificate may be issued only for the entry that authenticated — the {} — \
                 and this request is for the {}. Only a holder of Admin Write may request a \
                 certificate for somebody else.",
                p.entry().label(),
                target.label()
            ),
        ))
    }

    // -----------------------------------------------------------------
    // PROFILES AGAINST SETTINGS.
    // -----------------------------------------------------------------

    fn known_profiles(family: &str) -> Vec<String> {
        let mut known: Vec<String> =
            PROFILE_IDS.iter().map(|s| s.to_string()).collect();
        if DEVICE_PROFILE_FAMILIES.contains(&family) {
            known.push(DEVICE_PROFILE.into());
        }
        known
    }

    /// `applicationProfileList(family, entry)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn application_profile_list(
        &self,
        family: &str,
        entry: Option<&Entry>,
    ) -> Vec<String> {
        let Some(e) = entry.filter(|e| e.kind == "application") else {
            return Vec::new();
        };
        self.d
            .applications
            .get(&e.id)
            .map(|v| v.field(&format!("{}AllowedProfiles", family)))
            .unwrap_or_default()
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// `allowedProfiles(family, entry)`: the realm's list, replaced by an
    /// application's own where it lists something.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn allowed_profiles(
        &self,
        family: &str,
        entry: Option<&Entry>,
    ) -> Vec<String> {
        let known = Core::known_profiles(family);
        let listed: Vec<String> = self
            .setting_list(&format!("{}.allowedProfiles", family))
            .into_iter()
            .filter(|p| known.contains(p))
            .collect();
        let own: Vec<String> = self
            .application_profile_list(family, entry)
            .into_iter()
            .filter(|p| known.contains(p))
            .collect();
        let chosen = if own.is_empty() { listed } else { own };
        known.into_iter().filter(|p| chosen.contains(p)).collect()
    }

    /// `checkProfile(family, profileId, entry, { structural })`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn check_profile(
        &self,
        family: &str,
        profile: &str,
        entry: Option<&Entry>,
        structural: bool,
    ) -> Outcome<String> {
        if let Some((_, why)) =
            REFUSED_PROFILES.iter().find(|(id, _)| *id == profile)
        {
            return Err(Refusal::new(
                codes::STS_ENROLL_0002,
                403,
                format!(
                    "The \"{}\" profile is never issued over an enrollment protocol. {}",
                    profile, why
                ),
            ));
        }
        if profile == DEVICE_PROFILE
            && !DEVICE_PROFILE_FAMILIES.contains(&family)
        {
            return Err(Refusal::new(
                codes::STS_DEVICE_0025,
                403,
                format!(
                    "The \"device\" profile is issued over EST and SCEP only (#164 decision 6), \
                     not over {}.",
                    family_label(family)
                ),
            ));
        }
        if !PROFILE_IDS.contains(&profile) && profile != DEVICE_PROFILE {
            return Err(Refusal::new(
                codes::STS_ENROLL_0001,
                400,
                format!(
                    "\"{}\" is not a certificate profile. The {} issued over {} are: {}.",
                    profile,
                    PROFILE_IDS.len(),
                    family_label(family),
                    PROFILE_IDS.join(", ")
                ),
            ));
        }
        let own_list = !self.application_profile_list(family, entry).is_empty();
        if structural {
            return Ok(profile.to_string());
        }
        if !own_list
            && !self
                .allowed_profiles(family, None)
                .iter()
                .any(|p| p == profile)
        {
            return Err(Refusal::new(
                codes::STS_ENROLL_0003,
                403,
                format!(
                    "The \"{}\" profile is not in {}.allowedProfiles in this realm.",
                    profile, family
                ),
            ));
        }
        if own_list
            && !self
                .allowed_profiles(family, entry)
                .iter()
                .any(|p| p == profile)
        {
            return Err(Refusal::new(
                codes::STS_ENROLL_0095,
                403,
                format!(
                    "The \"{}\" profile is not in the {}AllowedProfiles of the application \
                     \"{}\".",
                    profile,
                    family,
                    entry.map(|e| e.id.as_str()).unwrap_or("undefined")
                ),
            ));
        }
        Ok(profile.to_string())
    }

    /// `defaultProfile(family, entry)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn default_profile(
        &self,
        family: &str,
        entry: Option<&Entry>,
    ) -> String {
        let realm_default = {
            let t = self.setting_text(&format!("{}.defaultProfile", family));
            if t.is_empty() {
                "tls-client".to_string()
            } else {
                t
            }
        };
        if let Some(e) = entry.filter(|e| e.kind == "application") {
            let own = self
                .d
                .applications
                .get(&e.id)
                .map(|v| v.field(&format!("{}DefaultProfile", family)))
                .unwrap_or_default()
                .into_iter()
                .next()
                .unwrap_or_default()
                .trim()
                .to_string();
            if !own.is_empty()
                && self.allowed_profiles(family, entry).contains(&own)
            {
                return own;
            }
        }
        realm_default
    }

    /// `profileForIdentifiers(family, types, entry)` (#252).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn profile_for_identifiers(
        &self,
        family: &str,
        types: &[String],
        entry: Option<&Entry>,
    ) -> String {
        let hosts_only =
            !types.is_empty() && types.iter().all(|t| t == "dns" || t == "ip");
        if hosts_only
            && self
                .allowed_profiles(family, entry)
                .iter()
                .any(|p| p == "tls-server")
        {
            return "tls-server".into();
        }
        self.default_profile(family, entry)
    }

    /// `estSwitch(name, entry)`: an application's own `est<Name>` where it
    /// set one, the realm's `est.<name>` otherwise.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn est_switch(&self, name: &str, entry: Option<&Entry>) -> bool {
        let realm_value = self.setting_on(&format!("est.{}", name));
        let Some(e) = entry.filter(|e| e.kind == "application") else {
            return realm_value;
        };
        let mut chars = name.chars();
        let attribute = match chars.next() {
            Some(c) => {
                format!("est{}{}", c.to_ascii_uppercase(), chars.as_str())
            }
            None => "est".into(),
        };
        let raw = self
            .d
            .applications
            .get(&e.id)
            .map(|v| v.field(&attribute))
            .unwrap_or_default()
            .into_iter()
            .next()
            .unwrap_or_default()
            .trim()
            .to_uppercase();
        match raw.as_str() {
            "TRUE" => true,
            "FALSE" => false,
            _ => realm_value,
        }
    }

    // -----------------------------------------------------------------
    // THE TWO OWASP CONTROLS EVERY ENDPOINT SHARES.
    // -----------------------------------------------------------------

    /// `transportRefusal(req, family)`: product refuses an ACME or EST
    /// request that reached a plain HTTP listener.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn transport_refusal(
        &self,
        over_tls: bool,
        family: &str,
    ) -> Option<Refusal> {
        if over_tls {
            return None;
        }
        if !self.predicate("requiresEnrollmentTls") {
            tracing::info!(
                "enrollment: a {} request arrived over plain HTTP; development mode answers it \
                 (product mode would refuse it, {}).",
                family_label(family),
                codes::STS_ENROLL_0060.as_str()
            );
            return None;
        }
        Some(Refusal::new(
            codes::STS_ENROLL_0060,
            403,
            format!(
                "{} is served over TLS only (RFC 8555 section 6.1, RFC 7030 section 3.2), and \
                 this request did not arrive over TLS.",
                family_label(family)
            ),
        ))
    }

    fn limit_of(&self, family: &str) -> Limit {
        Limit {
            identity: Some(
                self.setting_int(&format!("{}.attemptsPerIdentity", family))
                    as f64,
            ),
            address: Some(
                self.setting_int(&format!("{}.attemptsPerAddress", family))
                    as f64,
            ),
        }
    }

    fn throttle_refusal(family: &str, retry_after: f64) -> Refusal {
        let wait = if retry_after > 0.0 { retry_after } else { 60.0 };
        Refusal::new(
            codes::STS_ENROLL_0061,
            429,
            format!(
                "Too many refused {} requests. Wait {} seconds and try again.",
                family_label(family),
                wait as i64
            ),
        )
    }

    /// `throttledShared(family, req, identity)`: over the limit of refused
    /// requests right now? Counts nothing. The local window: no store
    /// shares one here (`sharesThrottle()` is false).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn throttled(
        &self,
        family: &str,
        address: &str,
        identity: &str,
    ) -> Option<Refusal> {
        let blocked = self.d.limits.blocked(
            &format!("enroll-{}", family),
            address,
            identity,
            &self.limit_of(family),
        )?;
        let retry = blocked
            .value
            .get("retryAfterS")
            .and_then(Json::as_f64)
            .unwrap_or(60.0);
        Some(Core::throttle_refusal(family, retry))
    }

    /// `countFailure(family, req, identity)`: one refused request counted.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn count_failure(&self, family: &str, address: &str, identity: &str) {
        let _counted = self.d.limits.attempt(
            &format!("enroll-{}", family),
            address,
            identity,
            &self.limit_of(family),
        );
    }

    /// `retryAfterOf(refusal)`: the seconds a throttled refusal names.
    #[tracing::instrument(level = "trace")]
    pub fn retry_after_of(refusal: &Refusal) -> i64 {
        refusal
            .sentence
            .split("Wait ")
            .nth(1)
            .and_then(|r| r.split(' ').next())
            .and_then(|n| n.parse::<i64>().ok())
            .unwrap_or(60)
    }

    // -----------------------------------------------------------------
    // THE FAMILY'S AUTHORITY.
    // -----------------------------------------------------------------

    /// `caChainOf(family)`: the family's Issuing CA, the realm
    /// Intermediate and the service Root.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn ca_chain_of(&self, family: &str) -> Option<CaChain> {
        let id = realm::current_id();
        let row = self.d.authority.raw_row_for(&id)?;
        let issuing = row.get("issuing")?.get(family)?;
        let intermediate = row.get("intermediate").filter(|i| !i.is_null())?;
        let root = self
            .d
            .authority
            .trust_anchors_for(&id)
            .into_iter()
            .next()
            .unwrap_or_default();
        let issuing_pem = str_of(issuing, "certificatePem").to_string();
        let intermediate_pem =
            str_of(intermediate, "certificatePem").to_string();
        let mut chain_pem = vec![issuing_pem.clone(), intermediate_pem.clone()];
        if !root.is_empty() {
            chain_pem.push(root.clone());
        }
        Some(CaChain {
            issuing_pem,
            intermediate_pem,
            root_pem: root,
            chain_pem,
        })
    }

    /// `ensureAuthority(family)`: the family CA made where the branch was
    /// built before the enrollment use cases existed.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn ensure_authority(&self, family: &str) -> Option<CaChain> {
        if let Some(chain) = self.ca_chain_of(family) {
            return Some(chain);
        }
        if !self.d.authority.has_root() {
            return None;
        }
        if let Err(e) = self.d.authority.ensure_scope(&realm::current_id()) {
            tracing::debug!("Caught in ensure_authority(): {:?}", e);
        }
        self.ca_chain_of(family)
    }

    /// `realms.retiringRefusal()`: a realm being removed issues nothing.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn retiring_refusal(&self) -> Option<Refusal> {
        let lifecycle = self.d.lifecycle.as_ref()?;
        let (code, why) = lifecycle.retiring_refusal(&realm::current_id())?;
        Some(Refusal::new(code, 503, why))
    }

    /// The organisation and country certificates in this realm carry.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn organisation_of(&self) -> (String, String) {
        let row = self.d.authority.raw_row_for(&realm::current_id());
        let org = row
            .as_ref()
            .map(|r| str_of(r, "organisation").to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                let t = self.setting_text("pki.organisation");
                if t.is_empty() {
                    "iya-sts".into()
                } else {
                    t
                }
            });
        let country = row
            .as_ref()
            .map(|r| str_of(r, "country").to_string())
            .unwrap_or_default();
        (org, country)
    }

    /// `withheldValues(attribute, values)`: the six secret attributes are
    /// never shown by a dump or a search, in every mode.
    #[tracing::instrument(level = "trace", skip(values))]
    pub fn withheld_values(attribute: &str, values: &[String]) -> Vec<String> {
        const SECRET: &[&str] = &[
            "stsEnrolledPrivateKey",
            "appEnrolledPrivateKey",
            "stsAcmeEabKey",
            "appAcmeEabKey",
            "stsScepChallenge",
            "appScepChallenge",
        ];
        if !SECRET.iter().any(|s| s.eq_ignore_ascii_case(attribute)) {
            return values.to_vec();
        }
        values
            .iter()
            .map(|v| {
                format!(
                    "(withheld: certificate-enrollment credential, {} characters, never shown)",
                    v.encode_utf16().count()
                )
            })
            .collect()
    }
}

/// `caChainOf()`'s answer.
#[derive(Debug, Clone, Default)]
pub struct CaChain {
    pub issuing_pem: String,
    pub intermediate_pem: String,
    pub root_pem: String,
    pub chain_pem: Vec<String>,
}
