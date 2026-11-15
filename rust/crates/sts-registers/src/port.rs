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

/// `common/credentials.ts`: a person's credentials and account lock, kept
/// on their directory entry (`pwdAccountLockedTime`, the password hash).
/// The password policy — what a password must be, how one is generated —
/// is the policy slice's, behind `set_password` and `generate_password`.
pub trait Credentials: Send + Sync {
    /// `accountDisabled(name)`.
    fn account_disabled(&self, name: &str) -> bool;
    /// `setAccountDisabled(name, disabled, {riscReason})`: `{ok, …}` or a
    /// marked refusal.
    fn set_account_disabled(&self, name: &str, disabled: bool,
                            options: &Value) -> Marked;
    /// `generatePassword(name)`: one the person's policy accepts.
    fn generate_password(&self, name: &str) -> String;
    /// `setPassword(name, password, {generated})`: `{ok, errors}`.
    fn set_password(&self, name: &str, password: &str, options: &Value)
        -> Value;
    /// `setPasswordResetRequired(name, flag)`.
    fn set_password_reset_required(&self, name: &str, flag: bool) -> Value;
    /// `issueActivation(name)`: `{ok, token, expiresAt}` or `{ok, errors}`.
    fn issue_activation(&self, name: &str) -> Value;
}

/// `admin_stats.identityKeyOf(name)`: the one key a person is counted
/// under.
pub trait IdentityKeys: Send + Sync {
    fn identity_key_of(&self, name: &str) -> String;
}

/// The sign-out model (`logout/logout.ts`): `terminate(key, selection,
/// options)`, ending everything a person holds.
pub trait Logout: Send + Sync {
    fn terminate(&self, key: &str, selection: &Value, options: &Value)
        -> Value;
}

/// The side effects of an account change that are not this register's:
/// `RevokingWrites.note(what)` and the account-disabled mail.
pub trait AccountEffects: Send + Sync {
    /// `RevokingWrites.note(what)`.
    fn note_revoking_write(&self, what: &str);
    /// `mail_uses.accountDisabled(name, why, bySystem)`.
    fn mail_account_disabled(&self, name: &str, why: &str, by_system: bool);
}

/// `ldap_server.js`'s person writer (`admin.setDirectoryWriter()`):
/// `createUser(name, options)`, `{ok, dn, username, typed, invented,
/// entry}` or a marked refusal.
pub trait PersonWriter: Send + Sync {
    fn create_user(&self, name: &str, options: &Value) -> Marked;
}

/// `ldap_server.js`'s group writer (`admin.setGroupWriter()`): each act
/// answers `{ok, changed, …}` or a marked refusal.
pub trait GroupWriter: Send + Sync {
    fn create_group(&self, name: &str, options: &Value) -> Marked;
    fn add_group_member(&self, group: &str, member: &str, options: &Value)
        -> Marked;
    fn set_group_mail(&self, group: &str, mail: &str, options: &Value)
        -> Marked;
    fn set_group_policy(&self, group: &str, attribute: &str, policy: &str,
                        options: &Value) -> Marked;
    fn add_group_owner(&self, group: &str, owner: &str, options: &Value)
        -> Marked;
    fn remove_group_owner(&self, group: &str, owner: &str, options: &Value)
        -> Marked;
}

/// What the directory answers about groups for the groups claim and for
/// ownership (`ldap_server.js`).
pub trait GroupDirectory: Send + Sync {
    /// `groupsOfUser(name)`: `{dn, entryFound, groups: [{dn, cn, via,
    /// viaMemberOf}]}`.
    fn groups_of_user(&self, name: &str) -> Value;
    /// `groupsOwnedBy(dns)`: the groups naming any of them as an owner.
    fn groups_owned_by(&self, dns: &[String]) -> Vec<Value>;
    /// `groupOwnership(name)`: `{dn, cn, owners, ownerProtected}` or null.
    fn group_ownership(&self, name: &str) -> Value;
    /// `setGroupOwnerProtected(name, flag, options)`.
    fn set_group_owner_protected(&self, name: &str, flag: bool,
                                 options: &Value) -> Marked;
}

/// Service accounts (`common/service_accounts.ts`) and their policy
/// (`common/service_account_policy.ts`), the policy slice's.
pub trait ServiceAccounts: Send + Sync {
    /// `serviceAccountPolicy.writeRefusal(fields)`: the refusal, or none.
    fn write_refusal(&self, fields: &Value) -> Option<PolicyRefusal>;
    /// `check(body, existing)`.
    fn check(&self, body: &Value, existing: &str) -> Marked;
    /// `set(username, change)`.
    fn set(&self, username: &str, change: &Value) -> Value;
    /// `list()`.
    fn list(&self) -> Vec<Value>;
    /// `of(name)`: `{username, dn, owners, ownerProtected}` or null.
    fn of(&self, name: &str) -> Value;
    /// `setOwnerProtected(name, flag)`.
    fn set_owner_protected(&self, name: &str, flag: bool) -> Marked;
}

/// `ssf/account_signals.ts`: the CAEP and RISC signals of a credential
/// change.
pub trait AccountSignals: Send + Sync {
    fn credential_changed(&self, change: &Value);
}

/// `AdminActions.mailedLink(kind, who, token, body, actor, via)`: an
/// activation or reset link mailed, `{ok, mailedTo}` / `{ok: false,
/// errors}`, or null with no mail channel.
pub trait LinkMailer: Send + Sync {
    fn mailed_link(&self, kind: &str, who: &str, token: &str, body: &Value,
                   actor: &str, via: &str) -> Value;
}

/// `common/scope_policy.ts`'s questions ownership asks.
pub trait ScopePolicy: Send + Sync {
    fn protected_scopes(&self) -> Vec<String>;
    fn declared_scopes(&self, identifier: &str) -> Vec<String>;
    fn delegated_permission_scopes(&self, identifier: &str) -> Vec<String>;
}

/// A refusal a policy decided before a write: its code and its sentence.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyRefusal {
    pub code: ErrorCode,
    pub message: String,
}

/// The claim tables of `common/admin_stats.js` the groups claim reads.
pub trait ClaimTables: Send + Sync {
    /// `RESERVED_JWT_CLAIMS`: the names this service sets itself.
    fn reserved_jwt_claims(&self) -> Vec<String>;
    /// `CLAIM_SET_IDS`.
    fn claim_set_ids(&self) -> Vec<String>;
    /// `DEFAULT_SAML11_NAMESPACE`.
    fn default_saml11_namespace(&self) -> String;
}
