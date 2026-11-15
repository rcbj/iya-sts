// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! WHETHER A SECOND FACTOR IS REQUIRED AT SIGN-IN: the authentication
//! policy's three rules (`common/authn_policy.ts`'s `requireSecondFactor()`,
//! `configuredSecondFactor()`, `requireSecondFactorForAdministrators()`)
//! and the one reader that decides with them (`common/credentials.ts`'s
//! `mfaRequirementFor()`).
//!
//! **A SECOND FACTOR OF EVERYBODY, IN PRODUCT** (#1490, ASVS 5.0.0 6.3.3;
//! `mode.requiresSecondFactorOfEveryone()`, unless
//! `authn.allowOptionalSecondFactor`): the rule reads `always` whatever the
//! realm configured — except for a service account, which has nobody to
//! answer one and is held to the realm's configured rule.
//!
//! **THE BOUNDARY IS THE DOOR, NOT THIS FUNCTION** (rcbj, 2026-11-09): a
//! certificate sign-in in a browser asks this and steps up; a FEDERATED
//! sign-in never does — the partner is the authentication and states its
//! own strength — so the federation door calls `startSession()` without
//! asking here. The credentials and federation slices keep that.

use serde_json::{json, Value};

use crate::js;

/// The authentication policy's second-factor rules, as one profile and the
/// mode read them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecondFactorRules {
    /// `requireSecondFactor()`: `if-held` or `always`.
    pub require: String,
    /// `configuredSecondFactor()`: the profile's own, without "everybody".
    pub configured: String,
    /// `requireSecondFactorForAdministrators()`: `if-held`, `offer`,
    /// `always`.
    pub for_administrators: String,
}

impl SecondFactorRules {
    /// The rules of a profile (`authnPolicy.read()`'s row), with product
    /// mode's "everybody" applied where `everyone`
    /// (`mode.requires_second_factor_of_everyone()`).
    #[tracing::instrument(level = "debug", skip(profile))]
    pub fn of(profile: &Value, everyone: bool) -> SecondFactorRules {
        let text = |k: &str| js::string_of(profile.get(k));
        SecondFactorRules {
            require: if everyone {
                "always".into()
            } else {
                text("requireSecondFactor")
            },
            configured: text("requireSecondFactor"),
            for_administrators: if everyone {
                "always".into()
            } else {
                text("requireSecondFactorForAdministrators")
            },
        }
    }
}

/// What `mfaRequirementFor()` reads about a person.
pub trait SecondFactorFacts: Send + Sync {
    /// `serviceAccounts.isServiceAccountName(name)`.
    fn is_service_account_name(&self, name: &str) -> bool;
    /// `serviceAccountPolicy.exemptFromSecondFactor(profileFor(name))`.
    fn service_account_exempt(&self, name: &str) -> bool;
    /// `directory.readMfaRequired(name)`: `None` where there is no
    /// directory, an `Err` a read that threw (read as not required).
    fn read_mfa_required(&self, name: &str) -> Option<Result<bool, String>>;
    /// The ambient realm's rules.
    fn rules(&self) -> SecondFactorRules;
    /// `consoleRolesOf(name)`: `(read, write)`.
    fn console_roles_of(&self, name: &str) -> (bool, bool);
    fn current_realm(&self) -> String;
    /// `bootstrap_name.current()`.
    fn bootstrap_name(&self) -> String;
}

/// `mfaRequirementFor(username)`: `{ required, byUser, byRealm,
/// byAdministrator, offered, exemptServiceAccount }`.
#[tracing::instrument(level = "debug", skip(facts))]
pub fn mfa_requirement_for(
    facts: &dyn SecondFactorFacts,
    username: &str,
) -> Value {
    let name = username.trim();
    let service = !name.is_empty() && facts.is_service_account_name(name);
    if service && facts.service_account_exempt(name) {
        return json!({"required": false, "byUser": false, "byRealm": false,
                      "byAdministrator": false, "offered": false,
                      "exemptServiceAccount": true});
    }
    let by_user = match (!name.is_empty())
        .then(|| facts.read_mfa_required(name))
        .flatten()
    {
        Some(Ok(b)) => b,
        Some(Err(e)) => {
            tracing::debug!("Caught in mfa_requirement_for(): {}", e);
            false
        }
        None => false,
    };
    let rules = facts.rules();
    let by_realm = if service {
        rules.configured == "always"
    } else {
        rules.require == "always"
    };
    let for_admins = if name.is_empty() {
        "if-held".to_string()
    } else {
        rules.for_administrators.clone()
    };
    let mut by_administrator = false;
    let mut offered = false;
    if for_admins != "if-held" {
        let (read, write) = facts.console_roles_of(name);
        if read || write {
            let built_in = facts.current_realm() == "default"
                && name == facts.bootstrap_name();
            by_administrator = for_admins == "always" && !built_in;
            offered = !by_administrator;
        }
    }
    let required = by_user || by_realm || by_administrator;
    json!({"required": required, "byUser": by_user, "byRealm": by_realm,
           "byAdministrator": by_administrator,
           "offered": offered && !required, "exemptServiceAccount": false})
}
