// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE PORTS: everything a register reaches that is not itself a register.
//!
//! In Node each register reaches the directory through a SLOT the directory
//! fills at its require (`roles.setDirectory()`, `admin_rbac.setDirectory()`,
//! `group_claims.setDirectory()`, `admin.setDirectoryWriter()`, …, rule 3e),
//! and the settings, the audit log and the other registers through plain
//! requires. Here every one of them is a trait object handed to the
//! register's constructor (rust/DESIGN.md 4.2): the slot's cycle does not
//! exist when the composition root builds in dependency order.
//!
//! The directory's half is written by the directory slice (`sts-directory`)
//! at the same time as this crate, so these traits are the SMALLEST surface
//! each register needs, in the shapes `ldap/ldap_server.js` answers today —
//! a role entry as `{name, dn, attributes}`, a group entry with its resolved
//! `members`, a refusal as `{ok: false, errors, reason}` carrying its code.
//! What the real implementation must provide is each method's doc comment;
//! the replay tests (tests/node_vectors.rs) hold every one to what Node's
//! directory answered.
//!
//! A port answer that Node marks with an error code comes back as a
//! [`Marked`], so the register that hands it up keeps the owner's code,
//! as `errorCodes.codeOf()` does.

use serde_json::Value;
use sts_core::errors::ErrorCode;

/// A value a port answered, with the code its owner marked on it.
#[derive(Debug, Clone, PartialEq)]
pub struct Marked {
    pub value: Value,
    pub code: Option<ErrorCode>,
}

impl Marked {
    /// An unmarked answer.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn plain(value: Value) -> Marked {
        Marked { value, code: None }
    }
}

/// `config.value(key)`, the five-level resolution in the ambient realm
/// (`sts-core::Settings`, owned by the config slice). The registers read it
/// through this so that a test can hand them the values Node read.
pub trait Settings: Send + Sync {
    /// The effective value of a setting, as JSON.
    fn value(&self, key: &str) -> Value;
}

/// What `roles.js` asks of `ou=roles` (`ldap_server.js`'s hooks).
pub trait RoleDirectory: Send + Sync {
    /// Every role entry of the realm: `{dn, name, attributes, …}`, the
    /// attributes as the store holds them, canonically spelled, each a list.
    fn all_roles(&self) -> Vec<Value>;
    /// Writes (creates or replaces) `cn=<name>,ou=roles`. Node answers
    /// `true`, `false` (the directory is full) or a refusal
    /// `{ok: false, errors, reason}` (a NUL or an operator code in a value).
    fn write_role(&self, name: &str, attributes: &Value) -> Marked;
    /// Deletes the role entry; `false` when there was none.
    fn delete_role(&self, name: &str) -> bool;
    /// Resolves an owner given as a username, a group cn or a DN:
    /// `{kind: 'person'|'group'|'', dn, name}`.
    fn resolve_owner(&self, text: &str) -> Value;
    /// The cn of every group a person is in (both group rules).
    fn groups_of_user(&self, name: &str) -> Vec<String>;
    /// Creates a group when its DN is missing, leaving an existing one alone.
    fn ensure_group(&self, name: &str, options: &Value) -> Value;
}

/// What the console roster asks of the directory (`ldap_server.js`'s
/// `rosterViewFor(realm)`).
pub trait RosterDirectory: Send + Sync {
    /// `uid=…,ou=users,<base>` of the realm.
    fn users_dn(&self) -> String;
    /// The realm the view is bound to, when it says.
    fn realm_id(&self) -> Option<String>;
    /// `cn=<cn>,ou=groups,<base>`.
    fn group_dn_for(&self, cn: &str) -> String;
    /// A group entry with its resolved members, or `null`.
    fn read_group_entry(&self, dn: &str) -> Value;
    /// Writes a group entry: `{ok, created, reason, parent, entry}`.
    fn write_group_entry(&self, dn: &str, attributes: &Value, origin: &str)
        -> Value;
    /// A DN in the directory's comparison form.
    fn normalize_dn(&self, dn: &str) -> String;
    /// The person's entry, `{dn, …}`, or `null`.
    fn existing_user_entry(&self, name: &str) -> Value;
    /// Whether a name can be an RDN value without escaping.
    fn name_usable_in_dn(&self, name: &str) -> bool;
    /// The people whose own `memberOf` names the group: `[{dn, userKey,
    /// cn, mail}]`.
    fn claimed_members_of(&self, dn: &str) -> Vec<Value>;
    /// A person's console flags (`bootstrapAdministrator`,
    /// `consoleClaimedAt`, `dn`), read with remembered user names.
    fn read_person_flags(&self, name: &str) -> Value;
}

/// The audit log (`common/audit.js`): rows written, never read here.
pub trait Audit: Send + Sync {
    /// `audit.audit(row)`.
    fn audit(&self, row: &Value);
    /// `audit.record(row)`.
    fn record(&self, row: &Value);
    /// `audit.failure(code, row)`.
    fn failure(&self, code: ErrorCode, row: &Value);
}

/// What the registers ask of the application register
/// (`common/applications.js`). The register itself is ported in pieces;
/// these are the questions the others put to it.
pub trait Applications: Send + Sync {
    /// `applications.get(identifier)`: the view, or `null`.
    fn get(&self, identifier: &str) -> Value;
    /// `applications.list()`: every application's view.
    fn list(&self) -> Vec<Value>;
    /// `applications.requiredRolesOf(identifier)`.
    fn required_roles_of(&self, identifier: &str) -> Vec<String>;
    /// `applications.roleGatingFor(permissionId)`: `{gated, identifier,
    /// application, baseUri, name, description, id}` or `null`.
    fn role_gating_for(&self, id: &str) -> Value;
    /// `applications.forPermission(permissionId)`: as above without `gated`.
    fn for_permission(&self, id: &str) -> Value;
    /// `applications.settingFor(identifier, key, config)`: the
    /// application's own override of a setting, else the setting.
    fn setting_for(&self, identifier: &str, key: &str) -> Value;
    /// `applications.updateApplication(identifier, change)`:
    /// `{ok, application}` or a marked refusal.
    fn update_application(&self, identifier: &str, change: &Value) -> Marked;
    /// `applications.isInternalIdentifier(identifier)`.
    fn is_internal_identifier(&self, identifier: &str) -> bool;
    /// `applications.ownerProtected(identifier)`.
    fn owner_protected(&self, identifier: &str) -> bool;
    /// `applications.setOwnerProtected(identifier, flag)`.
    fn set_owner_protected(&self, identifier: &str, flag: bool) -> Marked;
    /// `applications.ownerValues()`: every application's `appOwner` values.
    fn owner_values(&self) -> Vec<Vec<String>>;
}

/// `mode.js`'s questions the registers ask, in a realm.
pub trait Mode: Send + Sync {
    /// `mode.opensConsoleToAnyone()` in the realm named.
    fn opens_console_to_anyone(&self, realm: &str) -> bool;
    /// `mode.verifiesCredentials()`.
    fn verifies_credentials(&self) -> bool;
}

/// `common/bootstrap_name.ts`: the bootstrap administrator's username.
pub trait BootstrapName: Send + Sync {
    /// `BootstrapName.current()`.
    fn current(&self) -> String;
}
