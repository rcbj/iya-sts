// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! WHAT THE CORE AND THE THREE FAMILIES READ FROM THE REST OF THE SERVICE,
//! one trait per module `cert_enrollment.ts` and its families require
//! (`CertEnrollmentDeps`, `AcmeDeps`, `EstDeps`, `ScepDeps`). The runtime
//! answers each in [`crate::wiring`]; a test answers them with fakes.
//!
//! * [`Entries`] is the directory SLOT `ldap/ldap_server.js` fills —
//!   `read()`, `write()`, `holdersWithValues()` — over the AMBIENT realm,
//!   plus `helpers.subjectForName()` / `nameForSubject()`, which the core
//!   reads a holder's subject through (`findEnrolled()`'s rename rule).
//! * [`Applications`] is `common/applications.js` as the core reads it:
//!   an entry by client id or identifier, one of its fields, its secret.
//! * [`Passwords`] is `credentials.verifyAsync()` in the ambient realm.
//! * [`Roster`] is `admin_rbac.rolesOf(name, realm)`.
//! * [`IssuanceGate`] is `issuance_gate.check()` asked the tenth kind,
//!   `issue-certificate` (#380).
//! * [`Audit`], [`Signals`] and [`Monitor`] are `audit.js`,
//!   `ssf/account_signals.ts` and `common/enrollment_monitor.ts`.

use serde_json::Value as Json;
use sts_core::errors::ErrorCode;

/// An entry as the slot's `read()` answers it: its DN and its attributes
/// by LOWER-CASED name (the store's spelling).
#[derive(Debug, Clone, Default)]
pub struct EntryRead {
    pub dn: String,
    pub attributes: std::collections::BTreeMap<String, Vec<String>>,
}

impl EntryRead {
    /// The values of an attribute, any case.
    // A hot path: every attribute read of every entry; no span.
    pub fn values(&self, name: &str) -> Vec<String> {
        self.attributes
            .get(&name.to_ascii_lowercase())
            .cloned()
            .unwrap_or_default()
    }

    /// Its first value, or `''`.
    // A hot path: as `values()`; no span.
    pub fn first(&self, name: &str) -> String {
        self.values(name).into_iter().next().unwrap_or_default()
    }
}

/// The directory slot, over the ambient realm.
pub trait Entries: Send + Sync {
    /// `read(kind, id)`: a person by username, an application by its
    /// identifier; none for no such entry.
    fn read(&self, kind: &str, id: &str) -> Option<EntryRead>;
    /// `write(kind, id, name, values)`: REPLACES the attribute; an empty
    /// list removes it. False for no such entry.
    fn write(
        &self,
        kind: &str,
        id: &str,
        name: &str,
        values: &[String],
    ) -> bool;
    /// `holdersWithValues(kind, name)`: `(id, values)` of every entry of
    /// the kind carrying the attribute, in the directory's order.
    fn holders_with_values(
        &self,
        kind: &str,
        name: &str,
    ) -> Vec<(String, Vec<String>)>;
    /// `helpers.subjectForName(name)`: the person's `urn:uuid:` subject.
    fn subject_for_name(&self, name: &str) -> String;
    /// `helpers.nameForSubject(subject)`: the person now holding it.
    fn name_for_subject(&self, subject: &str) -> String;
}

/// An application as `applications.get()` / `forClientId()` answer it.
#[derive(Debug, Clone, Default)]
pub struct Application {
    pub identifier: String,
    /// `view.fields`: attribute name (canonical spelling) to its values.
    pub fields: std::collections::BTreeMap<String, Vec<String>>,
}

impl Application {
    /// `view.fields[name]`, as the values held.
    // A hot path: every rule an application's enrolment reads; no span.
    pub fn field(&self, name: &str) -> Vec<String> {
        self.fields
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    }
}

/// `common/applications.js`, as the core reads it.
pub trait Applications: Send + Sync {
    /// `applications.forClientId(id) || applications.get(id)`.
    fn find(&self, client_id_or_identifier: &str) -> Option<Application>;
    /// `applications.get(identifier)`.
    fn get(&self, identifier: &str) -> Option<Application>;
    /// `clientConfigOf(identifier).client_secret`, `''` for none.
    fn client_secret(&self, identifier: &str) -> String;
}

/// `credentials.verifyAsync()`'s answer.
#[derive(Debug, Clone, Default)]
pub struct PasswordVerdict {
    pub ok: bool,
    /// The app password's name, where one was used.
    pub app_password: Option<String>,
}

/// `credentials.verifyAsync(name, password, { via, door })`, in the
/// ambient realm.
pub trait Passwords: Send + Sync {
    fn verify(
        &self,
        name: &str,
        password: &str,
        via: &str,
        door: &str,
    ) -> PasswordVerdict;
}

/// `admin_rbac.rolesOf(name, realm)`'s three answers the core reads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Roles {
    pub write: bool,
    pub open: bool,
    pub claim_pending: bool,
}

/// `admin_rbac.rolesOf(name, realm)`.
pub trait Roster: Send + Sync {
    fn roles_of(&self, name: &str, realm: &str) -> Roles;
}

/// `issuance_gate.check({ kind: 'issue-certificate', ... })` for an
/// application subject: whether it may be issued a certificate over the
/// family. An EMPTY gate answers "allowed" (rule 3v).
pub trait IssuanceGate: Send + Sync {
    fn certificate_allowed(&self, application: &str, family: &str) -> bool;
}

/// `audit.record(row)` and `audit.failure(code, row)`.
pub trait Audit: Send + Sync {
    fn record(&self, row: &Json);
    fn failure(&self, code: ErrorCode, row: &Json);
}

/// `ssf/account_signals.ts`'s three doors the core calls.
pub trait Signals: Send + Sync {
    fn certificate_changed(&self, event: &Json);
    fn credential_changed(&self, event: &Json);
    fn credential_compromised(&self, event: &Json);
}

/// `enrollment_monitor.record(family, detail)`.
pub trait Monitor: Send + Sync {
    fn record(&self, family: &str, detail: &Json);
}

/// The answers of a port nothing has been configured for yet: the gate
/// allows (rule 3v), the audit and the signals log, the monitor counts
/// nothing. What the runtime installs where a family is not ported.
pub struct Quiet;

impl IssuanceGate for Quiet {
    fn certificate_allowed(&self, _application: &str, _family: &str) -> bool {
        true
    }
}

impl Audit for Quiet {
    fn record(&self, row: &Json) {
        tracing::info!("audit: {}", row);
    }
    fn failure(&self, code: ErrorCode, row: &Json) {
        tracing::info!("{}audit: {}", sts_core::log::tag(code.as_str()), row);
    }
}

impl Signals for Quiet {
    fn certificate_changed(&self, event: &Json) {
        tracing::debug!("signals: certificate changed {}", event);
    }
    fn credential_changed(&self, event: &Json) {
        tracing::debug!("signals: credential changed {}", event);
    }
    fn credential_compromised(&self, event: &Json) {
        tracing::debug!("signals: credential compromised {}", event);
    }
}

impl Monitor for Quiet {
    fn record(&self, family: &str, detail: &Json) {
        tracing::debug!("enrollment monitor: {} {}", family, detail);
    }
}
