// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE ONE PLACE A PRESENTED CREDENTIAL IS VERIFIED: the doors of
//! `common/credentials.ts` that a sign-in step asks — the password
//! (`verify()`, with the previous password inside a rotation's overlap,
//! `pwdReset`, the disabled account, the service-account door and the
//! second-factor refusal of rule 3ax), the app password a password-only
//! door accepts in its place, the authenticator app (`verifyTotp()` and
//! its two-step enrolment), and the recovery codes (`verifyBackupCode()`
//! and their two-step issue, 3y) — with every write they make to the
//! person's entry, in Node's stored forms.
//!
//! **What the doors earn** is [`crate::evidence`]; the session the
//! evidence lands on is the session slice's.
//!
//! WHAT REPLACED WHAT. Node's `Credentials` reads the directory through
//! `setDirectory()`'s hooks and keeps the pending enrolments in
//! module-level `realms.map()`s; here the hooks are
//! [`CredentialDirectory`] and the pending stores are [`PendingStores`],
//! `RealmMap`s declared under Node's persist names
//! (`credentials.pendingTotp`, `credentials.pendingBackupCodes`) so a row
//! one process wrote is read by the other. The asynchronous doors
//! (`verifyAsync()`, `verifyBackupCodeAsync()`) exist in Node only to keep
//! scrypt off its one thread; the Rust caller runs these on a blocking
//! thread instead, so the synchronous order — the one both Node doors share
//! — is the one ported. `verifyTotpAsync()`'s cluster step counter is the
//! session slice's store and is asked through [`StepCounters`].

use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_core::errors::{codes, ErrorCode};
use sts_core::log::tag;
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{
    expiry_field, RealmMap, Retain, StoreHandles, StoreSpec,
};
use sts_crypto::secrets::{
    constant_time_equals, credential_digest, hash_password, is_hashed_secret,
    stored_secret_is_weaker, stored_secret_matches_spec, verify_secret,
    PasswordHashAsk,
};

use crate::app_passwords::{door_ids, AppPasswords};
use crate::backup_codes::BackupCodes;
use crate::js;
use crate::ports::{
    CredentialDirectory, Environment, Keystore, Observers, People, Policies,
    ServiceAccounts,
};
use crate::totp::Totp;
use crate::Verdict;

/// The attribute names Node's sentences use.
pub const PASSWORD_ATTRIBUTE: &str = "userPassword";
pub const TOTP_ATTRIBUTE: &str = "stsTotpCredential";
pub const BACKUP_CODES_ATTRIBUTE: &str = "stsBackupCodes";
pub const APP_PASSWORDS_ATTRIBUTE: &str = "stsAppPassword";
/// The password refused in every mode.
pub const RESERVED_REFUSAL: &str = "invalid";
/// How long a use of an app password at the same door is not re-recorded.
pub const APP_PASSWORD_USE_WRITE_MS: f64 = 60.0 * 1000.0;
/// `risk_failures.TOTP_REPLAY_DOOR`.
pub const TOTP_REPLAY_DOOR: &str = "a replayed one-time code";

/// What a password door says of itself (`opts` in Node).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VerifyOptions {
    /// The door, for the logs and the risk record.
    pub via: Option<String>,
    /// The password-only door's id (`ldap`, `wstrust`, …).
    pub door: Option<String>,
    /// `asked-next` or `session-held`: the caller asks the second factor.
    pub second_factor: Option<String>,
    /// The sign-in screen's own password change.
    pub allow_password_reset: bool,
}

impl VerifyOptions {
    /// From Node's `opts` object.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn from_json(opts: &Json) -> VerifyOptions {
        let text =
            |k: &str| opts.get(k).filter(|v| js::truthy(v)).map(js::string);
        VerifyOptions {
            via: text("via"),
            door: text("door"),
            second_factor: text("secondFactor"),
            allow_password_reset: opts.get("allowPasswordReset")
                == Some(&Json::Bool(true)),
        }
    }

    fn via(&self) -> String {
        self.via.clone().unwrap_or_else(|| "unstated".to_string())
    }

    fn door(&self) -> String {
        self.door.clone().unwrap_or_default()
    }

    fn asks_second_factor(&self) -> bool {
        matches!(
            self.second_factor.as_deref(),
            Some("asked-next") | Some("session-held")
        )
    }
}

/// The cluster's per-enrolment step counter (`counters.advance()`), which
/// proves an accepted TOTP step was not accepted on another node.
pub trait StepCounters: Send + Sync {
    /// Advance `key` to `value` if it is higher: `Ok(None)` advanced,
    /// `Ok(Some(highest))` was behind, `Err(why)` could not be proved.
    fn advance(
        &self,
        realm: &str,
        key: &str,
        value: f64,
    ) -> Result<Option<f64>, String>;
}

/// The pending stores, declared once under Node's names.
#[derive(Clone)]
pub struct PendingStores {
    pub totp: RealmMap<Json>,
    pub backup_codes: RealmMap<Json>,
}

impl PendingStores {
    /// Declares the two stores: persisted, retained by age, each row
    /// expiring at its own `expires` (ms), as Node declares them.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn declare(
        lifecycle: &Arc<RealmLifecycle>,
        handles: &Arc<StoreHandles>,
    ) -> PendingStores {
        let spec = |name: &str| StoreSpec {
            retain: Retain::Age,
            expires_at: Some(expiry_field(Some("expires"), 1.0)),
            ..StoreSpec::persisted(name)
        };
        PendingStores {
            totp: RealmMap::new(
                lifecycle,
                handles,
                spec("credentials.pendingTotp"),
            ),
            backup_codes: RealmMap::new(
                lifecycle,
                handles,
                spec("credentials.pendingBackupCodes"),
            ),
        }
    }
}

/// What `Credentials` is built over.
#[derive(Clone)]
pub struct CredentialsDeps {
    pub env: Arc<dyn Environment>,
    pub policies: Arc<dyn Policies>,
    pub keystore: Arc<dyn Keystore>,
    pub service_accounts: Arc<dyn ServiceAccounts>,
    pub people: Arc<dyn People>,
    pub observers: Arc<dyn Observers>,
    /// `None` is Node's directory slot unfilled.
    pub directory: Option<Arc<dyn CredentialDirectory>>,
    pub pending: PendingStores,
}

/// `verifyPrepare()`'s answer.
enum Ready {
    /// Settled before any comparison; `name` where an app password may
    /// still be tried (no credential, or one this service cannot read).
    Done(Verdict, Option<String>),
    Stored {
        stored: String,
        name: String,
    },
}

/// The doors.
pub struct Credentials {
    d: CredentialsDeps,
    totp: Totp,
    backup: BackupCodes,
    apps: AppPasswords,
}

fn coded(code: ErrorCode, value: Json) -> Verdict {
    Verdict::coded(code, value)
}

fn trimmed(name: &str) -> String {
    js::trim(name).to_string()
}

fn errors(code: ErrorCode, sentence: String) -> Verdict {
    coded(code, json!({ "ok": false, "errors": [sentence] }))
}

impl Credentials {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(d: CredentialsDeps) -> Credentials {
        Credentials {
            totp: Totp::new(d.env.clone(), d.policies.clone()),
            backup: BackupCodes::new(d.env.clone(), d.policies.clone()),
            apps: AppPasswords::new(d.env.clone()),
            d,
        }
    }

    /// The mechanisms, for a caller that needs one beside the store.
    /// A hot path (an accessor), so it carries no span.
    pub fn totp(&self) -> &Totp {
        &self.totp
    }

    /// A hot path (an accessor), so it carries no span.
    pub fn backup_codes(&self) -> &BackupCodes {
        &self.backup
    }

    /// A hot path (an accessor), so it carries no span.
    pub fn app_passwords(&self) -> &AppPasswords {
        &self.apps
    }

    fn now(&self) -> f64 {
        self.d.env.now_ms()
    }

    // -----------------------------------------------------------------------
    // The facts a door reads about a person.
    // -----------------------------------------------------------------------

    /// `accountDisabled(username)`: a throwing read is not disabled.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn account_disabled(&self, username: &str) -> bool {
        let name = trimmed(username);
        let Some(directory) = &self.d.directory else {
            return false;
        };
        if name.is_empty() {
            return false;
        }
        directory.read_account_disabled(&name).unwrap_or(false)
    }

    /// `disabledRefusal(username, via)`: STS-AUTHN-0200.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn disabled_refusal(&self, username: &str, via: &str) -> Verdict {
        coded(
            codes::STS_AUTHN_0200,
            json!({ "ok": false, "reason": "account-disabled",
                "detail": format!(
                    "the account \"{username}\" is disabled \
                     (pwdAccountLockedTime is set on its entry), so it is \
                     refused at {} in every mode until an administrator \
                     enables it",
                    if via.is_empty() { "every door" } else { via }) }),
        )
    }

    /// The directory slot, for the WebAuthn key doors
    /// ([`crate::webauthn::enrolment`]), which write through it.
    /// A hot path (an accessor), so it carries no span.
    pub fn directory(&self) -> Option<&Arc<dyn CredentialDirectory>> {
        self.d.directory.as_ref()
    }

    /// `hasPassword(username)`: whether the entry holds a password at all;
    /// a read that throws is no password.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn has_password(&self, username: &str) -> bool {
        self.d.directory.as_ref().is_some_and(|d| {
            d.read_password(&trimmed(username))
                .ok()
                .flatten()
                .is_some_and(|p| !p.is_empty())
        })
    }

    /// `!!backupCodesOf(username)`: whether a usable set is held.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn holds_backup_codes(&self, username: &str) -> bool {
        self.backup_codes_of(username).is_some()
    }

    /// `entryExists(name)`: the person's entry is there; no store is yes.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn entry_exists(&self, name: &str) -> bool {
        match &self.d.directory {
            None => true,
            Some(d) => d.person_exists(name).unwrap_or(false),
        }
    }

    fn is_person_entry(&self, name: &str) -> bool {
        match &self.d.directory {
            None => true,
            Some(d) => d.is_person(name).unwrap_or(true),
        }
    }

    /// `keysOf(username)`: the stored keys, each value that is JSON this
    /// service wrote with a credential id and a public key.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn keys_of(&self, username: &str) -> Vec<Json> {
        let Some(directory) = &self.d.directory else {
            return Vec::new();
        };
        let raw = match directory.read_webauthn(&trimmed(username)) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(
                    "{}credentials: reading the security keys for {} threw: \
                     {}",
                    tag(codes::STS_AUTHN_0065),
                    username,
                    e
                );
                return Vec::new();
            }
        };
        raw.iter()
            .filter_map(|v| {
                let text = v.as_str()?;
                let mut parsed: Json = serde_json::from_str(text).ok()?;
                if js::truthy_opt(parsed.get("credentialId"))
                    && js::truthy_opt(parsed.get("publicKeyJwk"))
                {
                    if let Some(o) = parsed.as_object_mut() {
                        o.shift_remove("role");
                    }
                    Some(parsed)
                } else {
                    None
                }
            })
            .collect()
    }

    /// `keyUses(held)`: how many keys count for each use the WebAuthn
    /// policy allows.
    fn key_uses(&self, held: usize) -> (usize, usize) {
        let primary = if held > 0 && self.d.policies.key_use_allowed("primary")
        {
            held
        } else {
            0
        };
        let mfa = if held > 0 && self.d.policies.key_use_allowed("mfa") {
            held
        } else {
            0
        };
        (primary, mfa)
    }

    /// `mfaRequirementFor(username)`: whether a second factor is required
    /// of this person — on their entry, by the realm, or as a console
    /// administrator — or offered. The session slice's one reader
    /// (`sts_authn::requirement`), over this store's facts.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn mfa_requirement_for(&self, username: &str) -> Json {
        let facts = RequirementFacts {
            c: self,
            name: trimmed(username),
        };
        sts_authn::requirement::mfa_requirement_for(&facts, username)
    }

    /// `secondFactorDemand(username)`: whether this person holds or must
    /// hold a second factor.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn second_factor_demand(&self, username: &str) -> Json {
        let name = trimmed(username);
        if name.is_empty() || !self.is_person_entry(&name) {
            return json!({ "person": false, "totp": false, "key": false,
                "holds": false, "required": false, "byUser": false,
                "needed": false });
        }
        let key = self.key_uses(self.keys_of(&name).len()).1 > 0;
        let totp = self.totp_of(&name).is_some();
        let requirement = self.mfa_requirement_for(&name);
        let holds = key || totp;
        let exempt = js::truthy_opt(requirement.get("exemptServiceAccount"));
        let required = js::truthy_opt(requirement.get("required"));
        json!({ "person": true, "totp": totp, "key": key, "holds": holds,
            "required": required,
            "byUser": js::truthy_opt(requirement.get("byUser")),
            "exemptServiceAccount": exempt,
            "needed": !exempt && (holds || required) })
    }

    /// `passwordOnlyDoors(username)`: which of the five doors refuse this
    /// person's password alone, and which take it.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn password_only_doors(&self, username: &str) -> Json {
        let name = trimmed(username);
        let person = !name.is_empty() && self.is_person_entry(&name);
        let holds = person
            && (self.key_uses(self.keys_of(&name).len()).1 > 0
                || self.totp_of(&name).is_some());
        let requirement = if person {
            self.mfa_requirement_for(&name)
        } else {
            json!({ "required": false, "byUser": false, "byRealm": false })
        };
        let second = holds || js::truthy_opt(requirement.get("required"));
        let applies = second
            && !self
                .d
                .env
                .predicate("acceptsPasswordAloneFromSecondFactorAccounts");
        let alone = self.apps.password_alone_doors();
        let refused: Vec<String> = if applies {
            door_ids()
                .into_iter()
                .filter(|d| !alone.iter().any(|a| a == d))
                .map(str::to_string)
                .collect()
        } else {
            Vec::new()
        };
        let accepted: Vec<String> = door_ids()
            .into_iter()
            .filter(|d| !refused.iter().any(|r| r == d))
            .map(str::to_string)
            .collect();
        json!({ "secondFactor": second, "holds": holds,
            "requirement": requirement, "applies": applies,
            "alone": alone, "refused": refused, "accepted": accepted })
    }

    /// `holdsPasskey(username)`: any key at all, since a key has no role.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn holds_passkey(&self, username: &str) -> bool {
        !self.keys_of(&trimmed(username)).is_empty()
    }

    /// `Credentials.keyAlgorithm(key)`: `{ name, coseAlg, text,
    /// postQuantum, insecure, lane }` — the row's own, or what its JWK says.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn key_algorithm(key: &Json) -> Json {
        let stored = js::number_opt(key.get("coseAlg"));
        let cose = if stored != 0.0 && !stored.is_nan() {
            stored
        } else {
            crate::webauthn::ceremony::cose_alg_of_jwk(
                key.get("publicKeyJwk").unwrap_or(&json!({})),
            ) as f64
        };
        let name = match key.get("algorithm").filter(|v| js::truthy(v)) {
            Some(a) => js::string(a),
            None => crate::webauthn::ceremony::cose_name(cose as i64)
                .map_or_else(
                    || format!("COSE {}", js::number_text(cose)),
                    str::to_string,
                ),
        };
        json!({ "name": name, "coseAlg": js::num(cose),
            "text": format!("{name} ({})", js::number_text(cose)),
            "postQuantum": name.starts_with("ML-DSA-"),
            "insecure": crate::webauthn::ceremony::insecure_cose_ids()
                .contains(&(cose as i64)),
            "lane": crate::evidence::key_lane(key) })
    }

    /// `recoveryPending(username)`: `{ door, at }`, or none.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn recovery_pending(&self, username: &str) -> Option<Json> {
        let directory = self.d.directory.as_ref()?;
        let raw = directory
            .read_recovery_pending(&trimmed(username))
            .ok()
            .flatten()
            .unwrap_or_default();
        if raw.is_empty() {
            return None;
        }
        let mut parts = raw.split(' ');
        let door = parts.next().unwrap_or("").to_string();
        let at = parts.next().unwrap_or("").to_string();
        Some(json!({ "door": door, "at": at }))
    }

    /// `setRecoveryPending(username, door)`: `<door> <now>`, or cleared.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn set_recovery_pending(&self, username: &str, door: &str) -> bool {
        let Some(directory) = &self.d.directory else {
            return false;
        };
        let name = trimmed(username);
        let value = if door.is_empty() {
            String::new()
        } else {
            format!("{door} {}", sts_pki::foreign::iso_ms(self.now() as i64))
        };
        let written = directory
            .write_recovery_pending(&name, &value)
            .unwrap_or(false);
        if !written {
            tracing::error!(
                "{}credentials: the pending recovery of {} could not be {}.",
                tag(codes::STS_AUTHN_0382),
                name,
                if door.is_empty() {
                    "cleared"
                } else {
                    "written"
                }
            );
        }
        written
    }

    /// `rewriteKey(username, credentialId, mutate)`: `Ok(Some(result))`
    /// written, `Ok(None)` no store, no such key or unchanged, `Err` threw.
    #[tracing::instrument(level = "debug", skip(self, mutate))]
    pub(crate) fn rewrite_key(
        &self,
        username: &str,
        credential_id: &str,
        mutate: impl FnOnce(&mut Json) -> bool,
    ) -> Result<Option<Json>, String> {
        let Some(directory) = &self.d.directory else {
            return Ok(None);
        };
        let mut keys = self.keys_of(username);
        let Some(found) = keys.iter_mut().find(|k| {
            js::string_or_empty(k.get("credentialId")) == credential_id
        }) else {
            return Ok(None);
        };
        if !mutate(found) {
            return Ok(None);
        }
        let values: Vec<String> = keys.iter().map(Json::to_string).collect();
        directory
            .replace_webauthn(&trimmed(username), &values)
            .map(Some)
    }

    /// `noteKeyPolicyRefused(username, credentialId, reason, code, why)`:
    /// the refusal marked on the key's row, once per key and reason.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn note_key_policy_refused(
        &self,
        username: &str,
        credential_id: &str,
        reason: &str,
        code: &str,
        why: &str,
    ) -> bool {
        // `String(why).slice(0, 500)`: UTF-16 units, as JavaScript counts.
        let units: Vec<u16> = why.encode_utf16().take(500).collect();
        let why = String::from_utf16_lossy(&units);
        let now = self.now();
        let outcome = self.rewrite_key(username, credential_id, |found| {
            let held = match found.get("policyRefused") {
                Some(Json::Object(o)) => o.clone(),
                _ => serde_json::Map::new(),
            };
            if reason.is_empty()
                || held.get(reason).is_some_and(|h| h["why"] == json!(why))
            {
                return false;
            }
            let mut next = held;
            next.insert(
                reason.to_string(),
                json!({ "code": code, "why": why, "at": js::num(now) }),
            );
            found["policyRefused"] = Json::Object(next);
            true
        });
        match outcome {
            Ok(Some(result)) => js::truthy(&result),
            Ok(None) => false,
            Err(e) => {
                tracing::error!(
                    "{}credentials: the refusal of a passkey of {} ({}) could \
                     not be recorded: {}",
                    tag(codes::STS_AUTHN_0318),
                    username,
                    reason,
                    e
                );
                false
            }
        }
    }

    // -----------------------------------------------------------------------
    // The password.
    // -----------------------------------------------------------------------

    fn service_account_door_of(opts: &VerifyOptions) -> String {
        if opts.asks_second_factor() {
            "browser".to_string()
        } else {
            opts.door()
        }
    }

    /// `serviceAccountRefusesDoor(username, door)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn service_account_refuses_door(
        &self,
        username: &str,
        door: &str,
    ) -> bool {
        let name = trimmed(username);
        let sa = &self.d.service_accounts;
        !name.is_empty()
            && sa.is_service_account_name(&name)
            && sa.refuses_door(&name, door)
    }

    fn service_account_door_refusal(
        &self,
        name: &str,
        opts: &VerifyOptions,
    ) -> Option<Verdict> {
        let door = Credentials::service_account_door_of(opts);
        if !self.service_account_refuses_door(name, &door) {
            return None;
        }
        let via = opts.via();
        let browser = door == "browser";
        tracing::info!(
            "credentials: {} is a SERVICE ACCOUNT and was refused at {}.",
            name,
            via
        );
        Some(coded(
            if browser {
                codes::STS_SVCACCT_0010
            } else {
                codes::STS_SVCACCT_0011
            },
            json!({ "ok": false, "reason": "service-account-door",
                "detail": format!(
                    "{name} is a service account, and this realm's \
                     service-account policy does not let it in at {via} \
                     (Directory → Policies)") }),
        ))
    }

    fn verify_prepare(
        &self,
        username: &str,
        password: &str,
        opts: &VerifyOptions,
    ) -> Ready {
        let name = trimmed(username);
        let via = opts.via();
        if password == RESERVED_REFUSAL {
            return Ready::Done(
                coded(
                    codes::STS_AUTHN_0048,
                    json!({ "ok": false, "reason": "reserved-refusal",
                        "detail": "the password \"invalid\" is reserved and \
                                   is refused in every mode, so that a \
                                   client can be tested against a refusal \
                                   without anything being configured" }),
                ),
                None,
            );
        }
        if !name.is_empty() && self.account_disabled(&name) {
            tracing::info!(
                "credentials: {} is disabled and was refused (via {}).",
                name,
                via
            );
            return Ready::Done(self.disabled_refusal(&name, &via), None);
        }
        if !name.is_empty() {
            if let Some(v) = self.service_account_door_refusal(&name, opts) {
                return Ready::Done(v, None);
            }
        }
        if !self.d.env.predicate("verifiesCredentials") {
            return Ready::Done(
                Verdict::of(json!({ "ok": true,
                    "reason": "development-mode",
                    "detail": "development mode checks no password in any \
                               protocol; what was proved is that somebody \
                               typed a name" })),
                None,
            );
        }
        if name.is_empty() {
            return Ready::Done(
                coded(
                    codes::STS_AUTHN_0049,
                    json!({ "ok": false, "reason": "no-username",
                        "detail": "no username was presented" }),
                ),
                None,
            );
        }
        let Some(directory) = &self.d.directory else {
            tracing::error!(
                "{}credentials: product mode is in force and no credential \
                 store is installed, so every verification is REFUSED.",
                tag(codes::STS_AUTHN_0050)
            );
            return Ready::Done(
                coded(
                    codes::STS_AUTHN_0050,
                    json!({ "ok": false, "reason": "no-store",
                        "detail": "product mode is in force and no \
                                   credential store is installed, so \
                                   nothing can be verified" }),
                ),
                None,
            );
        };
        let stored = match directory.read_password(&name) {
            Ok(s) => s.unwrap_or_default(),
            Err(e) => {
                tracing::error!(
                    "{}credentials: reading the stored password for {} threw \
                     and the verification is being REFUSED: {}",
                    tag(codes::STS_AUTHN_0051),
                    name,
                    e
                );
                return Ready::Done(
                    coded(
                        codes::STS_AUTHN_0051,
                        json!({ "ok": false, "reason": "store-error",
                            "detail": "the credential store could not be \
                                       read" }),
                    ),
                    None,
                );
            }
        };
        if stored.is_empty() {
            return Ready::Done(
                coded(
                    codes::STS_AUTHN_0052,
                    json!({ "ok": false, "reason": "no-credential",
                        "detail": format!(
                            "no {PASSWORD_ATTRIBUTE} is set for \"{name}\". \
                             In product mode a person with no stored \
                             credential cannot sign in — set one from \
                             /admin/users, POST \
                             /admin-api/users/set-password, SCIM, or an LDAP \
                             modify") }),
                ),
                Some(name),
            );
        }
        if !is_hashed_secret(&stored) {
            tracing::warn!(
                "credentials: {} holds a {} that this service did not write \
                 and cannot read.",
                name,
                PASSWORD_ATTRIBUTE
            );
            return Ready::Done(
                coded(
                    codes::STS_AUTHN_0053,
                    json!({ "ok": false, "reason": "unreadable-credential",
                        "detail": format!(
                            "the stored {PASSWORD_ATTRIBUTE} is not in the \
                             form this service writes, so it cannot be \
                             verified") }),
                ),
                Some(name),
            );
        }
        Ready::Stored { stored, name }
    }

    fn previous_password_hash(&self, name: &str) -> String {
        if name.is_empty() {
            return String::new();
        }
        match self.d.service_accounts.previous_password_hash(name) {
            Ok(Some(h)) => h,
            _ => String::new(),
        }
    }

    fn verify_finish(ok: bool, name: &str, via: &str) -> Verdict {
        if !ok {
            tracing::info!(
                "credentials: {} presented a password that does not match \
                 (via {}).",
                name,
                via
            );
            return coded(
                codes::STS_AUTHN_0054,
                json!({ "ok": false, "reason": "wrong-password",
                    "detail": "the presented password does not match" }),
            );
        }
        Verdict::of(json!({ "ok": true, "reason": "verified",
            "detail": format!("the presented password matched the stored \
                               {PASSWORD_ATTRIBUTE}") }))
    }

    /// `passwordResetRequired(username)`: `pwdReset` on the entry.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn password_reset_required(&self, username: &str) -> bool {
        let name = trimmed(username);
        match (&self.d.directory, name.is_empty()) {
            (Some(d), false) => d.read_password_reset(&name).unwrap_or(false),
            _ => false,
        }
    }

    fn reset_refusal(
        &self,
        answer: &Verdict,
        name: &str,
        opts: &VerifyOptions,
    ) -> Option<Verdict> {
        if !answer.ok()
            || answer.reason() != "verified"
            || opts.allow_password_reset
            || !self.password_reset_required(name)
        {
            return None;
        }
        Some(coded(
            codes::STS_AUTHN_0142,
            json!({ "ok": false, "reason": "password-reset-required",
                "detail": "the password is right and must be changed first: \
                           pwdReset is TRUE on this entry, so sign in at the \
                           sign-in screen, which asks for a new one" }),
        ))
    }

    fn second_factor_refusal(
        &self,
        answer: &Verdict,
        name: &str,
        opts: &VerifyOptions,
    ) -> Option<Verdict> {
        if !answer.ok()
            || answer.reason() != "verified"
            || self
                .d
                .env
                .predicate("acceptsPasswordAloneFromSecondFactorAccounts")
            || opts.asks_second_factor()
        {
            return None;
        }
        let demand = self.second_factor_demand(name);
        if !js::truthy_opt(demand.get("person"))
            || !js::truthy_opt(demand.get("needed"))
        {
            return None;
        }
        let holds = js::truthy_opt(demand.get("holds"));
        let by_user = js::truthy_opt(demand.get("byUser"));
        let door = opts.door();
        let via = opts.via();
        if !door.is_empty() && self.apps.password_alone_doors().contains(&door)
        {
            tracing::warn!(
                "credentials: {} signed in with a password ALONE at {} \
                 though a second factor is held or required, because \
                 authn.passwordAloneDoors lists \"{}\".",
                name,
                via,
                door
            );
            return None;
        }
        let why = if holds {
            "they hold a second factor"
        } else if by_user {
            "a second factor is required of them on their entry \
             (stsMfaRequired)"
        } else {
            "the realm requires a second factor of everybody (the \
             authentication policy)"
        };
        Some(coded(
            codes::STS_AUTHN_0213,
            json!({ "ok": false, "reason": "second-factor-required",
                "detail": format!(
                    "the password is right and {why}, and {via} cannot ask \
                     for one: make an app password for this door on \
                     /portal/app-passwords") }),
        ))
    }

    fn note_refusal(
        &self,
        username: &str,
        opts: &VerifyOptions,
        answer: &Verdict,
    ) {
        let reason = answer.reason();
        if answer.ok()
            || matches!(
                reason,
                "no-store"
                    | "store-error"
                    | "password-reset-required"
                    | "service-account-door"
            )
        {
            return;
        }
        let code = match answer.code_text() {
            "" => codes::STS_AUTHN_0054.as_str(),
            c => c,
        };
        self.d.observers.failure(username, &opts.via(), code);
    }

    fn notify_password(
        &self,
        name: &str,
        password: &str,
        event: &str,
        hash: Option<&str>,
        previous: Option<&str>,
    ) {
        if name.is_empty() || password.is_empty() {
            return;
        }
        self.d.observers.password(
            name,
            password,
            &json!({ "event": event, "hash": hash, "retainPreviousMs": 0,
                     "previousHash": previous }),
        );
    }

    fn rehash_spec_for(&self, name: &str, stored: &str) -> Option<Json> {
        self.d.directory.as_ref()?;
        if !is_hashed_secret(stored) {
            return None;
        }
        let profile = self.d.policies.password_profile_for(name, "");
        let spec = self.d.policies.password_hash_spec(&profile);
        let ask = hash_ask(&spec);
        if stored_secret_matches_spec(stored, &ask)
            || !stored_secret_is_weaker(stored, &ask)
        {
            return None;
        }
        Some(spec)
    }

    /// `upgradeHash(name, password, stored)`: a verified password whose
    /// stored hash is weaker than the policy's is written again at the
    /// policy's parameters — unless the stored value changed meanwhile.
    /// A failure is logged (STS-AUTHN-0409) and the sign-in stands.
    #[tracing::instrument(level = "debug", skip(self, password, stored))]
    pub fn upgrade_hash(
        &self,
        name: &str,
        password: &str,
        stored: &str,
    ) -> bool {
        let Some(spec) = self.rehash_spec_for(name, stored) else {
            return false;
        };
        let Some(directory) = &self.d.directory else {
            return false;
        };
        let hash = match hash_password(password, &hash_ask(&spec)) {
            Ok(h) => {
                self.d.observers.hashed(&h, password);
                h
            }
            Err(e) => {
                tracing::warn!(
                    "{}credentials: the password hash for {} could not be \
                     upgraded, and the sign-in stands: {}",
                    tag(codes::STS_AUTHN_0409),
                    name,
                    e
                );
                return false;
            }
        };
        match directory.read_password(name) {
            Ok(now) if now.as_deref().unwrap_or("") == stored => {}
            Ok(_) => {
                tracing::info!(
                    "credentials: the stored password hash for {} changed \
                     while it was being upgraded, so the upgrade was \
                     dropped.",
                    name
                );
                return false;
            }
            Err(e) => {
                tracing::error!(
                    "{}credentials: writing the upgraded password hash for \
                     {} threw, and the sign-in stands: {}",
                    tag(codes::STS_AUTHN_0409),
                    name,
                    e
                );
                return false;
            }
        }
        match directory.write_password(name, &hash, None) {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(
                    "{}credentials: the upgraded password hash for {} was \
                     not written, and the sign-in stands.",
                    tag(codes::STS_AUTHN_0409),
                    name
                );
                return false;
            }
            Err(e) => {
                tracing::error!(
                    "{}credentials: writing the upgraded password hash for \
                     {} threw, and the sign-in stands: {}",
                    tag(codes::STS_AUTHN_0409),
                    name,
                    e
                );
                return false;
            }
        }
        self.notify_password(
            name,
            password,
            "rehash",
            Some(&hash),
            Some(stored),
        );
        true
    }

    /// `verify(username, password, opts)`: the password door. In order:
    /// the reserved refusal, a disabled account, the service-account door,
    /// development mode (which checks nothing), the stored hash — and an
    /// APP PASSWORD before any of the last, where the presented value has
    /// an app password's shape — then the previous password inside a
    /// rotation's overlap, `pwdReset`, and the second-factor refusal.
    #[tracing::instrument(level = "debug", skip(self, password))]
    pub fn verify(
        &self,
        username: &str,
        password: &str,
        opts: &VerifyOptions,
    ) -> Verdict {
        let ready = self.verify_prepare(username, password, opts);
        if let Some((name, record)) =
            self.app_password_candidate(&ready, password)
        {
            let hash = js::string_or_empty(record.get("hash"));
            let matched = AppPasswords::matches_hash(password, &hash);
            if let Some(answered) =
                self.app_password_answer(&name, &record, matched, opts)
            {
                self.note_refusal(username, opts, &answered);
                return answered;
            }
        }
        let (stored, name) = match ready {
            Ready::Done(v, _) => {
                self.note_refusal(username, opts, &v);
                return v;
            }
            Ready::Stored { stored, name } => (stored, name),
        };
        let via = opts.via();
        let previous = self.previous_password_hash(&name);
        let current = verify_secret(password, &stored);
        let by_previous = !current
            && !previous.is_empty()
            && verify_secret(password, &previous);
        if by_previous {
            tracing::info!(
                "credentials: {} presented its PREVIOUS password at {}, \
                 inside the rotation's overlap.",
                name,
                via
            );
        }
        let finished =
            Credentials::verify_finish(current || by_previous, &name, &via);
        let answer = self
            .reset_refusal(&finished, &name, opts)
            .or_else(|| self.second_factor_refusal(&finished, &name, opts))
            .unwrap_or(finished);
        if answer.ok() && answer.reason() == "verified" && !by_previous {
            self.notify_password(
                &name,
                password,
                "verified",
                Some(&stored),
                None,
            );
            self.upgrade_hash(&name, password, &stored);
        }
        self.note_refusal(username, opts, &answer);
        answer
    }

    // -----------------------------------------------------------------------
    // Setting a password: the policy, the breach screen, the history.
    // -----------------------------------------------------------------------

    /// `passwordProblem(password, username, application)`: the sentence a
    /// refusal by the password policy carries, empty where it passes or
    /// nothing is enforced.
    #[tracing::instrument(level = "debug", skip(self, password))]
    pub fn password_problem(
        &self,
        password: &str,
        username: &str,
        application: &str,
    ) -> String {
        if !self.d.env.predicate("verifiesCredentials") {
            return String::new();
        }
        let profile =
            self.d.policies.password_profile_for(username, application);
        let problems = self.d.policies.password_problems(password, &profile);
        if problems.is_empty() {
            return String::new();
        }
        format!(
            "That password does not meet this realm's password policy, which \
             asks for {}. The rules are on /admin/policies (profile \"{}\").",
            problems.join(", "),
            js::string_or_empty(profile.get("name"))
        )
    }

    fn reused_password(
        password: &str,
        current: &str,
        history: &[String],
        depth: usize,
    ) -> bool {
        std::iter::once(current.to_string())
            .chain(history.iter().take(depth).cloned())
            .filter(|one| !one.is_empty())
            .any(|stored| {
                if is_hashed_secret(&stored) {
                    verify_secret(password, &stored)
                } else {
                    constant_time_equals(password.as_bytes(), stored.as_bytes())
                }
            })
    }

    /// `passwordPolicy.hashOfHistoryValue(value)`: the hash in a stored
    /// `pwdHistory` value — everything after its third `#`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn hash_of_history_value(value: &str) -> String {
        let parts: Vec<&str> = value.split('#').collect();
        if parts.len() < 4 {
            String::new()
        } else {
            parts[3..].join("#")
        }
    }

    /// `preparePassword(username, password, opts)`: everything setting a
    /// password checks before anything is written — a password at all, a
    /// service account that rotates through its destination
    /// (STS-SVCACCT-0013), the policy (0056), the breach screen (0222), the
    /// history (0057) — and the hash and the new `pwdHistory`. `opts` is
    /// Node's: `application`, `generated`, `via`, `current`, `history`,
    /// `rotation`, `hashOfThisPassword`.
    #[tracing::instrument(level = "debug", skip(self, password, opts))]
    pub fn prepare_password(
        &self,
        username: &str,
        password: &str,
        opts: &Json,
    ) -> Result<Verdict, String> {
        let name = trimmed(username);
        if password.is_empty() {
            return Ok(errors(
                codes::STS_AUTHN_0055,
                format!(
                    "Give a password. To take one away, remove the \
                     {PASSWORD_ATTRIBUTE} attribute from the entry."
                ),
            ));
        }
        if !js::truthy_opt(opts.get("rotation"))
            && self.d.service_accounts.rotates_through_destination(&name)
        {
            return Ok(coded(
                codes::STS_SVCACCT_0013,
                json!({ "ok": false, "reason": "service-account-rotates",
                    "errors": [format!(
                        "{name} is a service account whose password rotates \
                         through its push destination, so it cannot be set \
                         by hand: the destination is where its consumers \
                         read it. Use Rotate now on its page, or POST \
                         /admin-api/users/rotate-password.")] }),
            ));
        }
        let application = js::string_or(opts.get("application"), "");
        let profile = self.d.policies.password_profile_for(&name, &application);
        let enforced = self.d.env.predicate("verifiesCredentials");
        let generated = js::truthy_opt(opts.get("generated"));
        if enforced {
            let problems =
                self.d.policies.password_problems(password, &profile);
            if !problems.is_empty() {
                let said = self.password_problem(password, &name, &application);
                return Ok(coded(
                    codes::STS_AUTHN_0056,
                    json!({ "ok": false, "reason": "password-policy",
                            "problems": problems, "errors": [said] }),
                ));
            }
        }
        if enforced && !generated && self.d.policies.breach_screening() {
            match self.d.policies.breach_verdict(password) {
                Some(true) => {
                    return Ok(coded(
                        codes::STS_AUTHN_0222,
                        json!({ "ok": false, "reason": "breached",
                            "errors": ["That password has appeared in a data \
                                        breach, so people trying stolen \
                                        passwords will try it. Choose a \
                                        different one."] }),
                    ));
                }
                Some(false) => {}
                None => tracing::warn!(
                    "{}credentials: a password was set through {} without \
                     being screened against Pwned Passwords.",
                    tag(codes::STS_AUTHN_0223),
                    js::string_or(
                        opts.get("via"),
                        "a door that did not say which"
                    )
                ),
            }
        }
        let current = match opts.get("current") {
            Some(c) => js::string_or(Some(c), ""),
            None => match &self.d.directory {
                Some(d) => d.read_password(&name)?.unwrap_or_default(),
                None => String::new(),
            },
        };
        let stored_history: Vec<String> = match opts.get("history") {
            Some(Json::Array(l)) => l.iter().map(js::string).collect(),
            _ => match &self.d.directory {
                Some(d) => d.read_password_history(&name)?,
                None => Vec::new(),
            },
        };
        let remembered: Vec<String> = stored_history
            .iter()
            .map(|v| Credentials::hash_of_history_value(v))
            .filter(|h| !h.is_empty())
            .collect();
        let depth = js::number_opt(profile.get("history"));
        if enforced
            && depth > 0.0
            && !generated
            && Credentials::reused_password(
                password,
                &current,
                &remembered,
                depth as usize,
            )
        {
            return Ok(coded(
                codes::STS_AUTHN_0057,
                json!({ "ok": false, "reason": "password-history",
                    "errors": [format!(
                        "That password has been used for this account \
                         recently. This realm's password policy refuses the \
                         current password and the {} before it (profile \
                         \"{}\"). Choose one you have not used here.",
                        js::number_text(depth),
                        js::string_or_empty(profile.get("name")))] }),
            ));
        }
        let mut history: Vec<String> = Vec::new();
        if !current.is_empty() && is_hashed_secret(&current) {
            history.push(self.d.policies.password_history_value(&current));
        }
        history.extend(stored_history);
        let keep = if depth.is_nan() || depth < 0.0 {
            0
        } else {
            depth as usize
        };
        history.truncate(keep);
        let spec = self.d.policies.password_hash_spec(&profile);
        let ask = hash_ask(&spec);
        let given = js::string_or(opts.get("hashOfThisPassword"), "");
        let hash = if is_hashed_secret(&given)
            && stored_secret_matches_spec(&given, &ask)
        {
            given
        } else {
            let made =
                hash_password(password, &ask).map_err(|e| e.to_string())?;
            self.d.observers.hashed(&made, password);
            made
        };
        Ok(Verdict::of(
            json!({ "ok": true, "hash": hash, "history": history,
            "profile": js::string_or_empty(profile.get("name")) }),
        ))
    }

    /// `setPassword(username, password, opts)`: prepared, written with the
    /// new `pwdHistory`, and observed. The service-account rotation's
    /// bookkeeping (`opts.rotation`) is the service-account slice's.
    #[tracing::instrument(level = "debug", skip(self, password, opts))]
    pub fn set_password(
        &self,
        username: &str,
        password: &str,
        opts: &Json,
    ) -> Result<Verdict, String> {
        let name = trimmed(username);
        if name.is_empty() {
            return Ok(errors(
                codes::STS_AUTHN_0058,
                "Name the person whose password to set.".to_string(),
            ));
        }
        let Some(directory) = self.d.directory.clone() else {
            if password.is_empty() {
                return Ok(errors(
                    codes::STS_AUTHN_0055,
                    format!(
                        "Give a password. To take one away, remove the \
                         {PASSWORD_ATTRIBUTE} attribute from the entry."
                    ),
                ));
            }
            return Ok(errors(
                codes::STS_AUTHN_0059,
                "No credential store is installed in this process, so a \
                 password cannot be set."
                    .to_string(),
            ));
        };
        let prepared = self.prepare_password(&name, password, opts)?;
        if !prepared.ok() {
            return Ok(prepared);
        }
        let hash = js::string(&prepared.value["hash"]);
        let history: Vec<String> = prepared.value["history"]
            .as_array()
            .map(|l| l.iter().map(js::string).collect())
            .unwrap_or_default();
        match directory.write_password(&name, &hash, Some(&history)) {
            Err(e) => {
                tracing::error!(
                    "{}credentials: writing the password for {} threw: {}",
                    tag(codes::STS_AUTHN_0060),
                    name,
                    e
                );
                return Ok(errors(
                    codes::STS_AUTHN_0060,
                    format!("The credential store refused the write: {e}"),
                ));
            }
            Ok(false) => {
                return Ok(errors(
                    codes::STS_AUTHN_0061,
                    format!(
                        "There is nobody called \"{name}\" in this realm's \
                         directory. In product mode every referenced object \
                         must be created ahead of time."
                    ),
                ))
            }
            Ok(true) => {}
        }
        tracing::info!(
            "credentials: a password was set for {}. It is stored as a hash \
             and CANNOT BE READ BACK.",
            name
        );
        self.notify_password(&name, password, "set", Some(&hash), None);
        Ok(Verdict::of(json!({ "ok": true, "username": name,
            "message": format!("The password for {name} is set. It is stored \
                                as a hash and cannot be shown again.") })))
    }

    // -----------------------------------------------------------------------
    // App passwords (3ax).
    // -----------------------------------------------------------------------

    /// `appPasswordRecords(name)`: `(ok, records, stored)`.
    fn app_password_records(&self, username: &str) -> (bool, Vec<Json>, bool) {
        let name = trimmed(username);
        let Some(directory) = &self.d.directory else {
            return (true, Vec::new(), false);
        };
        if name.is_empty() {
            return (true, Vec::new(), false);
        }
        let raw = match directory.read_app_passwords(&name) {
            Ok(r) => r.unwrap_or_default(),
            Err(e) => {
                tracing::error!(
                    "{}credentials: reading the app passwords of {} threw: {}",
                    tag(codes::STS_AUTHN_0220),
                    name,
                    e
                );
                return (false, Vec::new(), true);
            }
        };
        if raw.is_empty() {
            return (true, Vec::new(), true);
        }
        let parsed: Option<Json> = serde_json::from_str(&raw).ok();
        let Some(list) = parsed
            .as_ref()
            .filter(|p| js::truthy(p))
            .and_then(|p| p.get("passwords"))
            .and_then(Json::as_array)
        else {
            tracing::warn!(
                "{}credentials: the {} value on {} is not what this service \
                 writes, so none of it is accepted and nothing is written \
                 over it.",
                tag(codes::STS_AUTHN_0220),
                APP_PASSWORDS_ATTRIBUTE,
                name
            );
            return (false, Vec::new(), true);
        };
        let records = list
            .iter()
            .filter(|one| {
                js::truthy(one)
                    && one.get("id").is_some_and(Json::is_string)
                    && one.get("hash").is_some_and(Json::is_string)
            })
            .map(|one| {
                let doors: Vec<Json> = one
                    .get("doors")
                    .and_then(Json::as_array)
                    .map(|d| {
                        d.iter().map(|x| Json::String(js::string(x))).collect()
                    })
                    .unwrap_or_default();
                json!({
                    "id": js::string_or_empty(one.get("id")),
                    "name": js::string_or(one.get("name"), ""),
                    "doors": doors,
                    "hash": js::string_or_empty(one.get("hash")),
                    "createdAt": js::num(js::number_or_fallback(
                        one.get("createdAt"), 0.0)),
                    "createdBy": js::string_or(one.get("createdBy"), ""),
                    "lastUsedAt": js::num(js::number_or_fallback(
                        one.get("lastUsedAt"), 0.0)),
                    "lastUsedDoor": js::string_or(one.get("lastUsedDoor"), ""),
                })
            })
            .collect();
        (true, records, true)
    }

    fn write_app_password_records(
        &self,
        username: &str,
        records: &[Json],
    ) -> Verdict {
        let name = trimmed(username);
        let value = if records.is_empty() {
            None
        } else {
            Some(json!({ "version": 1, "passwords": records }).to_string())
        };
        let written = match &self.d.directory {
            Some(d) => match d.write_app_passwords(&name, value.as_deref()) {
                Ok(w) => w,
                Err(e) => {
                    tracing::error!(
                        "{}credentials: writing the app passwords of {} \
                         threw: {}",
                        tag(codes::STS_AUTHN_0220),
                        name,
                        e
                    );
                    false
                }
            },
            None => false,
        };
        if !written {
            return errors(
                codes::STS_AUTHN_0220,
                format!(
                    "The app passwords could not be written onto {name}'s \
                     entry."
                ),
            );
        }
        Verdict::of(json!({ "ok": true }))
    }

    fn app_password_view(one: &Json) -> Json {
        let doors: Vec<String> = one
            .get("doors")
            .and_then(Json::as_array)
            .map(|d| d.iter().map(js::string).collect())
            .unwrap_or_default();
        let labels: Vec<String> =
            doors.iter().map(|d| AppPasswords::door_label(d)).collect();
        json!({ "id": one["id"], "name": one["name"], "doors": doors,
            "doorLabels": labels, "createdAt": one["createdAt"],
            "createdBy": one["createdBy"], "lastUsedAt": one["lastUsedAt"],
            "lastUsedDoor": one["lastUsedDoor"] })
    }

    /// `appPasswordsOf(username)`: newest first, never a hash.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn app_passwords_of(&self, username: &str) -> Json {
        let (ok, mut records, _) = self.app_password_records(username);
        records.sort_by(|a, b| {
            let n = |v: &Json| js::number_opt(v.get("createdAt"));
            n(b).partial_cmp(&n(a)).unwrap_or(std::cmp::Ordering::Equal)
        });
        let list: Vec<Json> =
            records.iter().map(Credentials::app_password_view).collect();
        json!({ "ok": ok, "unreadable": !ok, "passwords": list })
    }

    /// `createAppPassword(username, { name, doors, createdBy })`: one made,
    /// hashed, and shown once.
    #[tracing::instrument(level = "debug", skip(self, spec))]
    pub fn create_app_password(&self, username: &str, spec: &Json) -> Verdict {
        let name = trimmed(username);
        if self.d.directory.is_none() {
            return errors(
                codes::STS_AUTHN_0059,
                "No credential store is installed.".to_string(),
            );
        }
        if name.is_empty() || !self.entry_exists(&name) {
            return errors(
                codes::STS_AUTHN_0061,
                format!(
                    "There is nobody called \"{name}\" in this realm's \
                     directory."
                ),
            );
        }
        if !self.is_person_entry(&name) {
            return errors(
                codes::STS_AUTHN_0221,
                format!(
                    "\"{name}\" is not a person in this realm's directory. An \
                     app password is a person's; an application uses its own \
                     client credentials."
                ),
            );
        }
        let live = self.apps.settings();
        if !js::truthy_opt(live.get("enabled")) {
            return errors(
                codes::STS_AUTHN_0218,
                "App passwords are turned off in this realm \
                 (appPasswords.enabled). One already made goes on working."
                    .to_string(),
            );
        }
        let label =
            AppPasswords::name_of(spec.get("name").unwrap_or(&Json::Null));
        if label.is_empty() {
            return errors(
                codes::STS_AUTHN_0215,
                format!(
                    "Give the app password a name of at most {} characters, \
                     saying which client it is for.",
                    crate::app_passwords::MAX_NAME
                ),
            );
        }
        let scope =
            AppPasswords::scope_of(spec.get("doors").unwrap_or(&Json::Null));
        if !scope.ok {
            let first = if scope.bad.is_empty() {
                "Choose at least one door. ".to_string()
            } else {
                format!("There is no door called {}. ", scope.bad.join(", "))
            };
            return errors(
                codes::STS_AUTHN_0216,
                format!(
                    "{first}An app password is scoped to one or more of: {}.",
                    door_ids().join(", ")
                ),
            );
        }
        let (ok, records, _) = self.app_password_records(&name);
        if !ok {
            return errors(
                codes::STS_AUTHN_0220,
                "The app passwords already on this entry cannot be read, so \
                 none is made over them. An administrator can see what is \
                 stored on the directory page."
                    .to_string(),
            );
        }
        if records.iter().any(|r| r["name"] == json!(label)) {
            return errors(
                codes::STS_AUTHN_0215,
                format!(
                    "There is already an app password called \"{label}\". \
                     Revoke it, or give this one another name."
                ),
            );
        }
        let most = js::number_opt(live.get("maxPerPerson"));
        if records.len() as f64 >= most {
            return errors(
                codes::STS_AUTHN_0217,
                format!(
                    "{name} already holds {} app passwords, which is the most \
                     one person may (appPasswords.maxPerPerson). Revoke one \
                     first.",
                    records.len()
                ),
            );
        }
        let taken: Vec<String> =
            records.iter().map(|r| js::string(&r["id"])).collect();
        let made = self.apps.generate(&taken);
        let created_by = js::string_or(spec.get("createdBy"), &name);
        let record = json!({ "id": made.id, "name": label,
            "doors": scope.doors, "hash": self.apps.hash(&made.password),
            "createdAt": js::num(self.now()), "createdBy": created_by,
            "lastUsedAt": 0, "lastUsedDoor": "" });
        let mut all = records.clone();
        all.push(record.clone());
        let written = self.write_app_password_records(&name, &all);
        if !written.ok() {
            return written;
        }
        tracing::info!(
            "credentials: an app password \"{}\" ({}) was made for {} by {}, \
             scoped to {}. It was shown once.",
            label,
            made.id,
            name,
            created_by,
            scope.doors.join(", ")
        );
        let mut out = json!({ "ok": true, "username": name,
                              "password": made.printed });
        if let (Some(o), Json::Object(view)) =
            (out.as_object_mut(), Credentials::app_password_view(&record))
        {
            o.extend(view);
        }
        Verdict::of(out)
    }

    /// `revokeAppPassword(username, id)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn revoke_app_password(&self, username: &str, id: &str) -> Verdict {
        let name = trimmed(username);
        let wanted = js::upper(js::trim(id));
        if self.d.directory.is_none() {
            return errors(
                codes::STS_AUTHN_0059,
                "No credential store is installed.".to_string(),
            );
        }
        let (ok, records, _) = self.app_password_records(&name);
        if !ok {
            return errors(
                codes::STS_AUTHN_0220,
                "The app passwords on this entry cannot be read.".to_string(),
            );
        }
        let going = records.iter().find(|r| js::string(&r["id"]) == wanted);
        let Some(going) = going.filter(|_| !wanted.is_empty()).cloned() else {
            return errors(
                codes::STS_AUTHN_0219,
                format!(
                    "{name} holds no app password with the id \"{wanted}\"."
                ),
            );
        };
        let kept: Vec<Json> = records
            .into_iter()
            .filter(|r| js::string(&r["id"]) != wanted)
            .collect();
        let written = self.write_app_password_records(&name, &kept);
        if !written.ok() {
            return written;
        }
        Verdict::of(json!({ "ok": true, "username": name,
            "revoked": Credentials::app_password_view(&going) }))
    }

    /// `appPasswordCandidate(ready, password)`: the record whose id the
    /// presented value carries, where the password step has not already
    /// settled the answer.
    fn app_password_candidate(
        &self,
        ready: &Ready,
        password: &str,
    ) -> Option<(String, Json)> {
        let name = match ready {
            Ready::Done(_, Some(n)) => n.clone(),
            Ready::Done(_, None) => return None,
            Ready::Stored { name, .. } => name.clone(),
        };
        if name.is_empty() {
            return None;
        }
        let id = AppPasswords::id_of(password);
        if id.is_empty() {
            return None;
        }
        let (ok, records, _) = self.app_password_records(&name);
        if !ok {
            return None;
        }
        records
            .into_iter()
            .find(|r| js::string(&r["id"]) == id)
            .map(|r| (name, r))
    }

    fn app_password_answer(
        &self,
        name: &str,
        record: &Json,
        matched: bool,
        opts: &VerifyOptions,
    ) -> Option<Verdict> {
        if !matched {
            return None;
        }
        let door = opts.door();
        let via = opts.via();
        let doors: Vec<String> = record["doors"]
            .as_array()
            .map(|d| d.iter().map(js::string).collect())
            .unwrap_or_default();
        let id = js::string(&record["id"]);
        let label = js::string(&record["name"]);
        if !AppPasswords::is_door(&door) || !doors.contains(&door) {
            tracing::info!(
                "credentials: {} presented the app password \"{}\" ({}) at \
                 {}, where it is not accepted. Refused as a wrong password \
                 is.",
                name,
                label,
                id,
                via
            );
            return Some(coded(
                codes::STS_AUTHN_0214,
                json!({ "ok": false, "reason": "app-password-out-of-scope",
                    "detail": "an app password was presented where it is \
                               not accepted" }),
            ));
        }
        self.note_app_password_used(name, &id, &door);
        Some(Verdict::of(json!({ "ok": true, "reason": "app-password",
            "appPassword": { "id": id, "name": label, "doors": doors },
            "detail": format!("an app password (\"{label}\", {id}) scoped \
                               to this door matched — one factor") })))
    }

    fn note_app_password_used(&self, name: &str, id: &str, door: &str) {
        let (ok, mut records, _) = self.app_password_records(name);
        let now = self.now();
        if !ok {
            return;
        }
        let Some(record) =
            records.iter_mut().find(|r| js::string(&r["id"]) == id)
        else {
            return;
        };
        let last = js::number_opt(record.get("lastUsedAt"));
        if now - last < APP_PASSWORD_USE_WRITE_MS
            && js::string(&record["lastUsedDoor"]) == door
        {
            return;
        }
        record["lastUsedAt"] = js::num(now);
        record["lastUsedDoor"] = json!(door);
        let written = self.write_app_password_records(name, &records);
        if !written.ok() {
            tracing::debug!("credentials: the use was not recorded.");
        }
    }

    // -----------------------------------------------------------------------
    // The authenticator app.
    // -----------------------------------------------------------------------

    fn pending_key_of(username: &str) -> String {
        js::trim(username).to_lowercase()
    }

    fn sweep_pending(&self, map: &RealmMap<Json>) {
        let realm = self.d.env.realm_id();
        let view = map.in_realm(&realm);
        let now = self.now();
        for (key, value) in view.entries() {
            if !js::truthy(&value)
                || js::number_or_fallback(value.get("expires"), 0.0) < now
            {
                view.delete(&key);
            }
        }
    }

    /// `totpOf(username)`: the enrolment with its secret opened, `{
    /// unusable, why }` for one that cannot be read, or none.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn totp_of(&self, username: &str) -> Option<Json> {
        let name = trimmed(username);
        let directory = self.d.directory.as_ref()?;
        let raw = match directory.read_totp(&name) {
            Ok(r) => r.unwrap_or_default(),
            Err(e) => {
                tracing::error!(
                    "{}credentials: reading the authenticator enrolment for \
                     {} threw: {}",
                    tag(codes::STS_AUTHN_0071),
                    name,
                    e
                );
                return None;
            }
        };
        if raw.is_empty() {
            return None;
        }
        let Ok(mut parsed) = serde_json::from_str::<Json>(&raw) else {
            tracing::warn!(
                "credentials: the {} value on {} is not JSON this service \
                 wrote and is being reported as an unusable enrolment.",
                TOTP_ATTRIBUTE,
                name
            );
            return Some(json!({ "unusable": true,
                "why": "the stored value is not readable" }));
        };
        if js::truthy_opt(parsed.get("sealed")) {
            let sealed = js::string_or_empty(parsed.get("secret"));
            let Some(opened) = self.d.keystore.open(&sealed, "totp-secret")
            else {
                tracing::warn!(
                    "credentials: the authenticator secret for {} is sealed \
                     and will not open under this process's key-encryption \
                     key. It is reported as UNUSABLE rather than as absent.",
                    name
                );
                return Some(json!({ "unusable": true,
                    "why": "the stored secret is sealed under a different \
                            key-encryption key" }));
            };
            parsed["secret"] = json!(opened);
        }
        if parsed.is_null() {
            return None;
        }
        Some(parsed)
    }

    fn write_totp_record(&self, username: &str, record: &Json) -> Verdict {
        let name = trimmed(username);
        let mut out = record.clone();
        if self.d.keystore.persists() {
            let secret = js::string_or_empty(out.get("secret"));
            let Some(sealed) =
                self.d.keystore.seal(&secret, "totp-secret", "cell")
            else {
                tracing::error!(
                    "{}credentials: the authenticator secret for {} could \
                     not be sealed, so it was NOT written.",
                    tag(codes::STS_AUTHN_0072),
                    name
                );
                return errors(
                    codes::STS_AUTHN_0072,
                    "The shared secret could not be encrypted, so it was not \
                     stored."
                        .to_string(),
                );
            };
            out["secret"] = json!(sealed);
            out["sealed"] = json!(true);
        } else {
            out["sealed"] = json!(false);
        }
        let Some(directory) = &self.d.directory else {
            return errors(
                codes::STS_AUTHN_0059,
                "No credential store is installed.".to_string(),
            );
        };
        match directory.write_totp(&name, Some(&out.to_string())) {
            Err(e) => {
                tracing::error!(
                    "{}credentials: writing the authenticator enrolment for \
                     {} threw: {}",
                    tag(codes::STS_AUTHN_0073),
                    name,
                    e
                );
                errors(
                    codes::STS_AUTHN_0073,
                    format!("The credential store refused the write: {e}"),
                )
            }
            Ok(false) => errors(
                codes::STS_AUTHN_0061,
                format!(
                    "There is nobody called \"{name}\" in this realm's \
                     directory."
                ),
            ),
            Ok(true) => Verdict::of(json!({ "ok": true })),
        }
    }

    /// `beginTotpEnrolment(username, { base })`: a secret minted into the
    /// pending store; nothing is on the entry until a code confirms it.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn begin_totp_enrolment(&self, username: &str, base: &str) -> Verdict {
        let name = trimmed(username);
        if self.d.directory.is_none() {
            return errors(
                codes::STS_AUTHN_0059,
                "No credential store is installed, so an authenticator app \
                 cannot be enrolled."
                    .to_string(),
            );
        }
        if !self.totp.offered() {
            return errors(
                codes::STS_AUTHN_0074,
                "Authenticator apps are turned off on this service (the \
                 authentication policy)."
                    .to_string(),
            );
        }
        if name.is_empty() {
            return errors(
                codes::STS_AUTHN_0058,
                "There is no name to enrol an authenticator for.".to_string(),
            );
        }
        if js::has_control(&name) {
            return errors(
                codes::STS_AUTHN_0557,
                "The name holds a control character, so no person has it. \
                 Nothing was started."
                    .to_string(),
            );
        }
        if !self.d.env.predicate("autoCreates") && !self.entry_exists(&name) {
            return errors(
                codes::STS_AUTHN_0024,
                format!(
                    "There is nobody called \"{name}\" in this realm's \
                     directory. In product mode every referenced object must \
                     exist first."
                ),
            );
        }
        let live = self.totp.settings();
        let secret = self.totp.generate_secret(None);
        self.sweep_pending(&self.d.pending.totp);
        let expires = self.now() + live.enrolment_ttl_ms;
        self.d.pending.totp.in_realm(&self.d.env.realm_id()).set(
            &Credentials::pending_key_of(&name),
            json!({ "secret": secret, "algorithm": live.algorithm,
                    "digits": js::num(live.digits),
                    "period": js::num(live.period),
                    "expires": js::num(expires) }),
        );
        let issuer = self.totp.issuer_for(base);
        let uri = Totp::otpauth_uri(
            &issuer,
            &name,
            &secret,
            &live.algorithm,
            live.digits,
            live.period,
        );
        Verdict::of(json!({ "ok": true, "username": name, "secret": secret,
            "issuer": issuer, "grouped": Totp::grouped(&secret),
            "algorithm": live.algorithm, "digits": js::num(live.digits),
            "period": js::num(live.period), "uri": uri,
            "expiresAt": js::num(self.now() + live.enrolment_ttl_ms) }))
    }

    /// `pendingTotpFor(username)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn pending_totp_for(&self, username: &str) -> Option<Json> {
        self.sweep_pending(&self.d.pending.totp);
        self.d
            .pending
            .totp
            .in_realm(&self.d.env.realm_id())
            .get(&Credentials::pending_key_of(username))
    }

    /// `abandonTotpEnrolment(username)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn abandon_totp_enrolment(&self, username: &str) {
        let view = self.d.pending.totp.in_realm(&self.d.env.realm_id());
        let key = Credentials::pending_key_of(username);
        if view.has(&key) {
            view.delete(&key);
        }
    }

    /// `confirmTotpEnrolment(username, code)`: the first code proves the
    /// app holds the secret; the enrolment is written with that step spent.
    #[tracing::instrument(level = "debug", skip(self, code))]
    pub fn confirm_totp_enrolment(
        &self,
        username: &str,
        code: &Json,
    ) -> Result<Verdict, String> {
        let name = trimmed(username);
        let Some(held) = self.pending_totp_for(&name) else {
            return Ok(coded(
                codes::STS_AUTHN_0075,
                json!({ "ok": false, "reason": "expired",
                    "errors": ["That enrolment has expired. Start again and \
                                scan the new code."] }),
            ));
        };
        let verdict = self.totp.verify(&held, code, None, None)?;
        if !verdict.ok() {
            let detail = verdict.value["detail"].clone();
            return Ok(coded(
                verdict.code.unwrap_or(codes::STS_AUTHN_0105),
                json!({ "ok": false, "reason": verdict.reason(),
                        "errors": [detail] }),
            ));
        }
        let now = self.now();
        let written = self.write_totp_record(
            &name,
            &json!({ "secret": held["secret"], "algorithm": held["algorithm"],
                "digits": held["digits"], "period": held["period"],
                "enrolledAt": js::num(now),
                "lastCounter": verdict.value["counter"],
                "lastUsedAt": js::num(now), "label": "authenticator app" }),
        );
        if !written.ok() {
            return Ok(written);
        }
        self.abandon_totp_enrolment(&name);
        tracing::info!(
            "credentials: {} enrolled an authenticator app as a second \
             factor.",
            name
        );
        let advised =
            self.backup.offered() && self.backup_codes_of(&name).is_none();
        Ok(Verdict::of(json!({ "ok": true, "username": name,
            "recoveryAdvised": advised,
            "recoveryNote": if advised {
                "You now have a second factor and no recovery codes. \
                 Generate a set from your account page before you need it — \
                 this service will not issue one for you, and a set is shown \
                 once."
            } else { "" } })))
    }

    fn totp_prepare(
        &self,
        name: &str,
        code: &Json,
        at: Option<f64>,
        window: Option<&Json>,
    ) -> Result<Result<(Json, Verdict), Verdict>, String> {
        let Some(record) = self.totp_of(name) else {
            return Ok(Err(coded(
                codes::STS_AUTHN_0076,
                json!({ "ok": false, "reason": "none",
                    "detail": format!("No authenticator app is enrolled for \
                                       {name}.") }),
            )));
        };
        if js::truthy_opt(record.get("unusable")) {
            tracing::error!(
                "{}credentials: {} holds an authenticator enrolment this \
                 process cannot read ({}), so the second factor cannot be \
                 checked.",
                tag(codes::STS_AUTHN_0077),
                name,
                js::string_or_empty(record.get("why"))
            );
            return Ok(Err(coded(
                codes::STS_AUTHN_0077,
                json!({ "ok": false, "reason": "unusable",
                    "detail": "Your authenticator enrolment cannot be read \
                               by this service, so it cannot be checked. An \
                               administrator has to clear it on your row \
                               under /admin/users and you can enrol \
                               again." }),
            )));
        }
        let verdict = self.totp.verify(&record, code, at, window)?;
        if !verdict.ok() {
            if verdict.reason() == "replay" {
                self.d.observers.failure(
                    name,
                    TOTP_REPLAY_DOOR,
                    codes::STS_AUTHN_0106.as_str(),
                );
            }
            return Ok(Err(coded(
                verdict.code.unwrap_or(codes::STS_AUTHN_0105),
                json!({ "ok": false, "reason": verdict.reason(),
                        "detail": verdict.value["detail"] }),
            )));
        }
        Ok(Ok((record, verdict)))
    }

    fn totp_finish(
        &self,
        name: &str,
        mut record: Json,
        verdict: &Verdict,
    ) -> Verdict {
        record["lastCounter"] = verdict.value["counter"].clone();
        record["lastUsedAt"] = js::num(self.now());
        let written = self.write_totp_record(name, &record);
        if !written.ok() {
            tracing::error!(
                "{}credentials: the accepted step for {} could not be \
                 recorded, so that code could be replayed inside its window.",
                tag(codes::STS_AUTHN_0078),
                name
            );
        }
        Verdict::of(json!({ "ok": true, "counter": verdict.value["counter"],
                            "drift": verdict.value["drift"] }))
    }

    /// `verifyTotp(username, code, { at, window })`: the code checked for
    /// real in every mode, and its step recorded as spent. `Err` where Node
    /// throws.
    #[tracing::instrument(level = "debug", skip(self, code))]
    pub fn verify_totp(
        &self,
        username: &str,
        code: &Json,
        at: Option<f64>,
        window: Option<&Json>,
    ) -> Result<Verdict, String> {
        let name = trimmed(username);
        Ok(match self.totp_prepare(&name, code, at, window)? {
            Err(done) => done,
            Ok((record, verdict)) => self.totp_finish(&name, record, &verdict),
        })
    }

    /// `verifyTotpAsync()`'s cluster half: the step is accepted only once
    /// the cluster counter for this enrolment advanced to it.
    #[tracing::instrument(level = "debug", skip(self, code, counters))]
    pub fn verify_totp_counted(
        &self,
        username: &str,
        code: &Json,
        counters: &dyn StepCounters,
    ) -> Result<Verdict, String> {
        let name = trimmed(username);
        let (record, verdict) =
            match self.totp_prepare(&name, code, None, None)? {
                Err(done) => return Ok(done),
                Ok(r) => r,
            };
        let key = format!(
            "{name}\n{}",
            js::number_text(js::number_or_fallback(
                record.get("enrolledAt"),
                0.0
            ))
        );
        let step = js::number_opt(verdict.value.get("counter"));
        Ok(match counters.advance(&self.d.env.realm_id(), &key, step) {
            Ok(None) => self.totp_finish(&name, record, &verdict),
            Ok(Some(highest)) => {
                tracing::warn!(
                    "credentials: a code for {} verified at step {} and was \
                     REFUSED: step {} has already been accepted for this \
                     enrolment.",
                    name,
                    js::number_text(step),
                    js::number_text(highest)
                );
                self.d.observers.failure(
                    &name,
                    TOTP_REPLAY_DOOR,
                    codes::STS_AUTHN_0106.as_str(),
                );
                coded(
                    codes::STS_AUTHN_0106,
                    json!({ "ok": false, "reason": "replay",
                        "counter": verdict.value["counter"],
                        "detail": "That code has already been used. Wait for \
                                   your authenticator to show the next \
                                   one." }),
                )
            }
            Err(why) => {
                tracing::error!(
                    "{}credentials: a code for {} verified and could not be \
                     proved unspent ({}), so it was refused.",
                    tag(codes::STS_AUTHN_0182),
                    name,
                    why
                );
                coded(
                    codes::STS_AUTHN_0182,
                    json!({ "ok": false, "reason": "store",
                        "detail": "That code could not be checked just now. \
                                   Try the next one in a moment." }),
                )
            }
        })
    }

    // -----------------------------------------------------------------------
    // Recovery codes (3y).
    // -----------------------------------------------------------------------

    fn backup_codes_of(&self, username: &str) -> Option<Json> {
        let name = trimmed(username);
        let directory = self.d.directory.as_ref()?;
        let raw = match directory.read_backup_codes(&name) {
            Ok(r) => r.unwrap_or_default(),
            Err(e) => {
                tracing::error!(
                    "{}credentials: reading the recovery codes for {} threw: \
                     {}",
                    tag(codes::STS_AUTHN_0080),
                    name,
                    e
                );
                return None;
            }
        };
        self.backup_codes_from_value(&raw, &name)
    }

    fn backup_codes_from_value(&self, raw: &str, name: &str) -> Option<Json> {
        if raw.is_empty() {
            return None;
        }
        let Ok(parsed) = serde_json::from_str::<Json>(raw) else {
            tracing::warn!(
                "credentials: the {} value on {} is not JSON this service \
                 wrote and is being reported as an unusable set.",
                BACKUP_CODES_ATTRIBUTE,
                name
            );
            return Some(json!({ "unusable": true,
                "why": "the stored value is not readable" }));
        };
        let num = |k: &str| js::num(js::number_or_fallback(parsed.get(k), 0.0));
        let mut vault = parsed.get("vault").cloned().unwrap_or(Json::Null);
        if js::truthy_opt(parsed.get("sealed")) {
            let sealed = js::string_or_empty(parsed.get("vault"));
            let Some(opened) = self.d.keystore.open(&sealed, "recovery-codes")
            else {
                tracing::warn!(
                    "credentials: the recovery codes for {} are sealed and \
                     will not open under this process's key-encryption key.",
                    name
                );
                return Some(json!({ "unusable": true, "sealed": true,
                    "total": num("total"), "remaining": num("remaining"),
                    "generatedAt": num("generatedAt"),
                    "lastUsedAt": num("lastUsedAt"),
                    "why": "the stored set is sealed under a different \
                            key-encryption key" }));
            };
            vault = json!(opened);
        }
        // `JSON.parse(vault)`: a string is parsed; anything else is
        // String()-ed first, as JSON.parse does.
        let text = match &vault {
            Json::String(s) => s.clone(),
            other => js::string(other),
        };
        let Ok(codes_list) = serde_json::from_str::<Json>(&text) else {
            return Some(json!({ "unusable": true,
                "why": "the stored code list is not readable" }));
        };
        let Some(list) = codes_list.as_array() else {
            return Some(json!({ "unusable": true,
                "why": "the stored code list is not a list" }));
        };
        let normalised: Vec<Json> = list
            .iter()
            .map(|one| {
                let stored = match one.get("hash") {
                    Some(h) => Some(h),
                    None => one.get("code"),
                };
                json!({ "hash": js::string_or(stored, ""),
                    "usedAt": js::num(js::number_or_fallback(
                        one.get("usedAt"), 0.0)) })
            })
            .collect();
        let legacy = normalised.iter().any(|one| {
            let h = js::string(&one["hash"]);
            !h.is_empty() && !BackupCodes::is_hash(&h)
        });
        Some(json!({ "codes": normalised, "hashed": !legacy,
            "legacy": legacy,
            "sealed": js::truthy_opt(parsed.get("sealed")),
            "generatedAt": num("generatedAt"),
            "lastUsedAt": num("lastUsedAt") }))
    }

    fn write_backup_codes_record(
        &self,
        username: &str,
        codes_list: &[Json],
        generated_at: f64,
        last_used_at: f64,
    ) -> Verdict {
        let name = trimmed(username);
        let list: Vec<Json> = codes_list
            .iter()
            .map(|one| {
                json!({ "hash": js::string_or(one.get("hash"), ""),
                    "usedAt": js::num(js::number_or_fallback(
                        one.get("usedAt"), 0.0)) })
            })
            .collect();
        let plain = Json::Array(list.clone()).to_string();
        let legacy = list.iter().any(|one| {
            let h = js::string(&one["hash"]);
            !h.is_empty() && !BackupCodes::is_hash(&h)
        });
        let mut vault = plain.clone();
        let mut sealed = false;
        if legacy && self.d.keystore.persists() {
            let Some(text) =
                self.d.keystore.seal(&plain, "recovery-codes", "cell")
            else {
                tracing::error!(
                    "{}credentials: the legacy recovery codes for {} could \
                     not be sealed, so they were NOT written.",
                    tag(codes::STS_AUTHN_0195),
                    name
                );
                return errors(
                    codes::STS_AUTHN_0195,
                    "The recovery codes could not be encrypted, so the change \
                     was not stored."
                        .to_string(),
                );
            };
            vault = text;
            sealed = true;
        }
        let remaining = list
            .iter()
            .filter(|one| !js::truthy_opt(one.get("usedAt")))
            .count();
        let generated = if generated_at != 0.0 && !generated_at.is_nan() {
            generated_at
        } else {
            self.now()
        };
        let out = json!({ "version": 2, "total": list.len(),
            "remaining": remaining, "generatedAt": js::num(generated),
            "lastUsedAt": js::num(if last_used_at.is_nan() { 0.0 }
                                  else { last_used_at }),
            "sealed": sealed, "hashed": !legacy, "vault": vault });
        let Some(directory) = &self.d.directory else {
            return errors(
                codes::STS_AUTHN_0059,
                "No credential store is installed.".to_string(),
            );
        };
        match directory.write_backup_codes(&name, Some(&out.to_string())) {
            Err(e) => {
                tracing::error!(
                    "{}credentials: writing the recovery codes for {} threw: \
                     {}",
                    tag(codes::STS_AUTHN_0081),
                    name,
                    e
                );
                errors(
                    codes::STS_AUTHN_0081,
                    format!("The credential store refused the write: {e}"),
                )
            }
            Ok(false) => errors(
                codes::STS_AUTHN_0061,
                format!(
                    "There is nobody called \"{name}\" in this realm's \
                     directory."
                ),
            ),
            Ok(true) => Verdict::of(json!({ "ok": true, "total": list.len(),
                                            "remaining": remaining })),
        }
    }

    fn pending_ttl_ms(&self) -> f64 {
        let asked = js::number_or_fallback(
            Some(&self.d.env.setting("backupCodes.pendingTtlS")),
            900.0,
        );
        asked.clamp(60.0, 3600.0) * 1000.0
    }

    fn pending_codes_key(handle: &str) -> String {
        credential_digest(handle).unwrap_or_default()
    }

    /// `beginBackupCodes(username, { count, length })`: a set minted and
    /// SHOWN; nothing is stored until it is confirmed.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn begin_backup_codes(
        &self,
        username: &str,
        count: Option<f64>,
        length: Option<f64>,
    ) -> Verdict {
        let name = trimmed(username);
        let refuse = |code, reason: &str, sentence: &str| {
            coded(
                code,
                json!({ "ok": false, "reason": reason,
                                "errors": [sentence] }),
            )
        };
        if self.d.directory.is_none() {
            return refuse(
                codes::STS_AUTHN_0059,
                "no-store",
                "This credential store does not hold recovery codes.",
            );
        }
        if !self.backup.offered() {
            return refuse(
                codes::STS_AUTHN_0082,
                "disabled",
                "Recovery codes are turned off on this service (the \
                 authentication policy).",
            );
        }
        if name.is_empty() {
            return refuse(
                codes::STS_AUTHN_0058,
                "name",
                "A set of recovery codes belongs to somebody.",
            );
        }
        let live = self.backup.settings();
        let Some(minted) = self.backup.generate(
            Some(count.filter(|c| *c != 0.0).unwrap_or(live.count)),
            Some(length.filter(|l| *l != 0.0).unwrap_or(live.length)),
        ) else {
            tracing::error!(
                "{}credentials: no recovery codes could be generated for {}.",
                tag(codes::STS_AUTHN_0083),
                name
            );
            return refuse(
                codes::STS_AUTHN_0083,
                "generate",
                "A set of recovery codes could not be generated.",
            );
        };
        let realm = self.d.env.realm_id();
        let view = self.d.pending.backup_codes.in_realm(&realm);
        let now = self.now();
        for (key, record) in view.entries() {
            if js::number_opt(record.get("expires")) < now {
                view.delete(&key);
            }
        }
        for (key, record) in view.entries() {
            if js::string_or_empty(record.get("username")) == name {
                view.delete(&key);
            }
        }
        let handle = base64url(&self.d.env.random_bytes(24));
        view.set(
            &Credentials::pending_codes_key(&handle),
            json!({ "username": name, "codes": minted,
                "begunAt": js::num(self.now()),
                "expires": js::num(self.now() + self.pending_ttl_ms()) }),
        );
        Verdict::of(json!({ "ok": true, "handle": handle, "codes": minted,
            "total": minted.len(),
            "expiresAt": js::num(self.now() + self.pending_ttl_ms()),
            "replacing": self.backup_codes_of(&name).is_some() }))
    }

    fn pending_backup_codes_for(
        &self,
        username: &str,
        handle: &str,
    ) -> Option<Json> {
        let realm = self.d.env.realm_id();
        let view = self.d.pending.backup_codes.in_realm(&realm);
        let now = self.now();
        for (key, record) in view.entries() {
            if js::number_opt(record.get("expires")) < now {
                view.delete(&key);
            }
        }
        view.get(&Credentials::pending_codes_key(handle))
            .filter(|r| {
                js::string_or_empty(r.get("username")) == trimmed(username)
            })
    }

    /// `confirmBackupCodes(username, handle)`: the shown set, hashed code
    /// by code and written, replacing any set held.
    #[tracing::instrument(level = "debug", skip(self, handle))]
    pub fn confirm_backup_codes(
        &self,
        username: &str,
        handle: &str,
    ) -> Verdict {
        let name = trimmed(username);
        let Some(record) = self.pending_backup_codes_for(&name, handle) else {
            return coded(
                codes::STS_AUTHN_0084,
                json!({ "ok": false, "reason": "pending",
                    "errors": ["There is no set of recovery codes waiting to \
                                be confirmed, or it has expired. Nothing was \
                                stored, so the set you were shown does not \
                                work — generate another one."] }),
            );
        };
        let hashed: Vec<Json> = record["codes"]
            .as_array()
            .map(|l| {
                l.iter()
                    .map(|c| {
                        json!({ "hash": self.backup.hash(&js::string(c)),
                                     "usedAt": 0 })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let written = self.write_backup_codes_record(
            &name,
            &hashed,
            js::number_opt(record.get("begunAt")),
            0.0,
        );
        if !written.ok() {
            tracing::error!(
                "{}credentials: the recovery codes for {} could not be \
                 stored. The set is still pending, so confirming again will \
                 retry.",
                tag(codes::STS_AUTHN_0085),
                name
            );
            return coded(
                codes::STS_AUTHN_0085,
                json!({ "ok": false, "reason": "store", "retryable": true,
                        "errors": written.value["errors"] }),
            );
        }
        self.d
            .pending
            .backup_codes
            .in_realm(&self.d.env.realm_id())
            .delete(&Credentials::pending_codes_key(handle));
        Verdict::of(json!({ "ok": true, "total": written.value["total"],
                            "remaining": written.value["remaining"] }))
    }

    /// `backupCodeStatus(username)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn backup_code_status(&self, username: &str) -> Json {
        let held = self.backup_codes_of(username);
        let Some(held) = held else {
            return json!({ "present": false, "usable": false, "total": 0,
                "remaining": 0, "used": 0, "generatedAt": 0,
                "lastUsedAt": 0, "sealed": false, "why": "" });
        };
        let n = |k: &str| js::number_or_fallback(held.get(k), 0.0);
        if js::truthy_opt(held.get("unusable")) {
            return json!({ "present": true, "usable": false,
                "total": js::num(n("total")),
                "remaining": js::num(n("remaining")),
                "used": js::num((n("total") - n("remaining")).max(0.0)),
                "generatedAt": js::num(n("generatedAt")),
                "lastUsedAt": js::num(n("lastUsedAt")),
                "sealed": js::truthy_opt(held.get("sealed")),
                "why": js::string_or(held.get("why"), "") });
        }
        let list = held["codes"].as_array().cloned().unwrap_or_default();
        let remaining = list
            .iter()
            .filter(|c| !js::truthy_opt(c.get("usedAt")))
            .count();
        json!({ "present": true, "usable": true, "total": list.len(),
            "remaining": remaining, "used": list.len() - remaining,
            "generatedAt": held["generatedAt"],
            "lastUsedAt": held["lastUsedAt"], "sealed": held["sealed"],
            "hashed": js::truthy_opt(held.get("hashed")),
            "legacy": js::truthy_opt(held.get("legacy")), "why": "" })
    }

    fn compare_one(presented: &str, entry: &Json) -> bool {
        let stored = js::string_or(entry.get("hash"), "");
        if stored.is_empty() {
            return false;
        }
        if BackupCodes::is_hash(&stored) {
            BackupCodes::matches_hash(presented, &stored)
        } else {
            BackupCodes::matches(presented, &stored)
        }
    }

    /// `verifyBackupCode(username, presented)`: checked for real in every
    /// mode, against every code (so the time taken does not say which), and
    /// SPENT — a spend that will not write is a refusal (STS-AUTHN-0093).
    #[tracing::instrument(level = "debug", skip(self, presented))]
    pub fn verify_backup_code(
        &self,
        username: &str,
        presented: &str,
    ) -> Verdict {
        let name = trimmed(username);
        let Some(held) = self.backup_codes_of(&name) else {
            return coded(
                codes::STS_AUTHN_0087,
                json!({ "ok": false, "reason": "none",
                    "detail": format!("No recovery codes have been issued \
                                       for {name}.") }),
            );
        };
        if js::truthy_opt(held.get("unusable")) {
            tracing::error!(
                "{}credentials: {} holds a set of recovery codes this process \
                 cannot read ({}), so they cannot be checked.",
                tag(codes::STS_AUTHN_0089),
                name,
                js::string_or_empty(held.get("why"))
            );
            return coded(
                codes::STS_AUTHN_0089,
                json!({ "ok": false, "reason": "unusable",
                    "detail": "Your recovery codes cannot be read by this \
                               service, so they cannot be checked. An \
                               administrator has to clear them on your row \
                               under /admin/users." }),
            );
        }
        if !BackupCodes::well_formed(presented) {
            return coded(
                codes::STS_AUTHN_0090,
                json!({ "ok": false, "reason": "shape",
                    "detail": "A recovery code is letters and digits only — \
                               the ones this service printed for you, in \
                               groups. Dashes and spaces are ignored." }),
            );
        }
        let list = held["codes"].as_array().cloned().unwrap_or_default();
        let mut matched: Option<usize> = None;
        let mut spent: Option<usize> = None;
        for (i, entry) in list.iter().enumerate() {
            if Credentials::compare_one(presented, entry) {
                if js::truthy_opt(entry.get("usedAt")) {
                    spent = spent.or(Some(i));
                } else {
                    matched = matched.or(Some(i));
                }
            }
        }
        let Some(index) = matched else {
            if spent.is_some() {
                return coded(
                    codes::STS_AUTHN_0091,
                    json!({ "ok": false, "reason": "spent",
                        "detail": "That recovery code has already been used. \
                                   Each one works once — use the next unused \
                                   code on your list." }),
                );
            }
            return coded(
                codes::STS_AUTHN_0092,
                json!({ "ok": false, "reason": "mismatch",
                    "detail": "That is not one of your recovery codes." }),
            );
        };
        let now = self.now();
        let updated: Vec<Json> = list
            .iter()
            .enumerate()
            .map(|(i, one)| {
                json!({ "hash": one["hash"],
                    "usedAt": if i == index { js::num(now) }
                              else { js::num(js::number_or_fallback(
                                  one.get("usedAt"), 0.0)) } })
            })
            .collect();
        let written = self.write_backup_codes_record(
            &name,
            &updated,
            js::number_opt(held.get("generatedAt")),
            now,
        );
        if !written.ok() {
            tracing::error!(
                "{}credentials: a recovery code for {} verified and could NOT \
                 be marked as spent, so it was REFUSED.",
                tag(codes::STS_AUTHN_0093),
                name
            );
            return coded(
                codes::STS_AUTHN_0093,
                json!({ "ok": false, "reason": "store",
                    "detail": "That code is right and this service could not \
                               record that it has been used, so it was not \
                               accepted. Try another one, and tell an \
                               administrator." }),
            );
        }
        Verdict::of(json!({ "ok": true,
            "remaining": written.value["remaining"],
            "total": written.value["total"] }))
    }
}

/// The facts `mfaRequirementFor()` reads, asked only as Node asks them:
/// the configured rule for a service account, the realm's for anybody
/// else, the administrators' only for a name.
struct RequirementFacts<'a> {
    c: &'a Credentials,
    name: String,
}

impl sts_authn::requirement::SecondFactorFacts for RequirementFacts<'_> {
    fn is_service_account_name(&self, name: &str) -> bool {
        self.c.d.service_accounts.is_service_account_name(name)
    }
    fn service_account_exempt(&self, name: &str) -> bool {
        self.c.d.service_accounts.exempt_from_second_factor(name)
    }
    fn read_mfa_required(&self, name: &str) -> Option<Result<bool, String>> {
        self.c
            .d
            .directory
            .as_ref()
            .map(|d| d.read_mfa_required(name))
    }
    fn rules(&self) -> sts_authn::requirement::SecondFactorRules {
        let p = &self.c.d.policies;
        let service = !self.name.is_empty()
            && self
                .c
                .d
                .service_accounts
                .is_service_account_name(&self.name);
        sts_authn::requirement::SecondFactorRules {
            require: if service {
                String::new()
            } else {
                p.require_second_factor()
            },
            configured: if service {
                p.configured_second_factor()
            } else {
                String::new()
            },
            for_administrators: if self.name.is_empty() {
                "if-held".to_string()
            } else {
                p.require_second_factor_for_administrators()
            },
        }
    }
    fn console_roles_of(&self, name: &str) -> (bool, bool) {
        self.c.d.people.console_roles_of(name)
    }
    fn current_realm(&self) -> String {
        self.c.d.env.realm_id()
    }
    fn bootstrap_name(&self) -> String {
        self.c.d.people.bootstrap_name()
    }
}

/// Node's `hashSpec()` answer as the ask `sts-crypto` takes.
fn hash_ask(spec: &Json) -> PasswordHashAsk {
    let f = |k: &str| spec.get(k).and_then(Json::as_f64);
    PasswordHashAsk {
        algorithm: spec
            .get("algorithm")
            .and_then(Json::as_str)
            .map(str::to_string),
        memory: f("memory"),
        passes: f("passes"),
        parallelism: f("parallelism"),
        log_n: f("logN"),
        r: f("r"),
        p: f("p"),
    }
}

/// `buffer.toString('base64url')`.
fn base64url(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(bytes)
}
