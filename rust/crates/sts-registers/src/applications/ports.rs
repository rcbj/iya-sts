// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The two ports other crates read the application register through, now
//! implemented over it: the registers' [`crate::port::Applications`] (the
//! questions roles, ownership, app permissions and the groups claim put to
//! `common/applications.js`) and the policy kinds'
//! [`sts_policy::ports::ApplicationRegister`] (`by_client_id`,
//! `by_identifier`, `naming_policy`).

use std::sync::Arc;

use serde_json::{json, Value};
use sts_policy::js::Object;

use super::ApplicationRegistry;
use crate::port::{Applications, Marked};

impl Applications for ApplicationRegistry {
    fn get(&self, identifier: &str) -> Value {
        ApplicationRegistry::get(self, identifier).unwrap_or(Value::Null)
    }

    fn list(&self) -> Vec<Value> {
        ApplicationRegistry::list(self)
    }

    fn required_roles_of(&self, identifier: &str) -> Vec<String> {
        ApplicationRegistry::required_roles_of(self, identifier)
    }

    fn role_gating_for(&self, id: &str) -> Value {
        ApplicationRegistry::role_gating_for(self, id).unwrap_or(Value::Null)
    }

    fn for_permission(&self, id: &str) -> Value {
        ApplicationRegistry::for_permission(self, id).unwrap_or(Value::Null)
    }

    fn setting_for(&self, identifier: &str, key: &str) -> Value {
        ApplicationRegistry::setting_for(self, identifier, key)
    }

    fn update_application(&self, identifier: &str, change: &Value) -> Marked {
        let out = ApplicationRegistry::update_application(self, identifier, change);
        Marked {
            value: out.answer,
            code: out.code,
        }
    }

    fn is_internal_identifier(&self, identifier: &str) -> bool {
        ApplicationRegistry::is_internal_identifier(self, identifier)
    }

    fn owner_protected(&self, identifier: &str) -> bool {
        ApplicationRegistry::owner_protected(self, identifier)
    }

    fn set_owner_protected(&self, identifier: &str, flag: bool) -> Marked {
        let out = ApplicationRegistry::set_owner_protected(self, identifier, flag);
        Marked {
            value: out.answer,
            code: out.code,
        }
    }

    fn owner_values(&self) -> Vec<Vec<String>> {
        ApplicationRegistry::owner_values(self)
    }
}

// Runs a question in the realm named, as the policy kinds ask it.
fn in_realm<R>(realm: &str, work: impl FnOnce() -> R) -> R {
    if realm.is_empty() || realm == sts_core::realm::current_id() {
        return work();
    }
    let mut r = sts_core::realm::Realm::default_realm();
    r.id = realm.to_string();
    sts_core::realm::run_sync(Arc::new(r), work)
}

fn fields_of(view: Option<Value>) -> Option<Object> {
    view.and_then(|v| v.get("fields").and_then(Value::as_object).cloned())
}

impl sts_policy::ports::ApplicationRegister for ApplicationRegistry {
    fn by_client_id(&self, realm: &str, client_id: &str) -> Option<Object> {
        in_realm(realm, || fields_of(self.for_client_id(client_id)))
    }

    fn by_identifier(&self, realm: &str, identifier: &str) -> Option<Object> {
        in_realm(realm, || fields_of(ApplicationRegistry::get(self, identifier)))
    }

    fn naming_policy(
        &self,
        realm: &str,
        attribute: &str,
        name: &str,
    ) -> Vec<String> {
        in_realm(realm, || self.applications_naming_policy(attribute, name))
    }
}

impl ApplicationRegistry {
    /// `isInternalIdentifier(identifier)`: one of the applications this
    /// service seeds for its own surfaces (`internalApplications()`).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn is_internal_identifier(&self, identifier: &str) -> bool {
        INTERNAL_IDENTIFIERS.contains(&identifier)
    }

    /// The registers' `{ok: false, …}` answers, for a caller that wants
    /// the JSON with its code.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn marked_json(out: &super::Marked) -> Value {
        json!({ "answer": out.answer, "code": out.code.map(|c| c.as_str()) })
    }
}

/// The identifiers `internalApplications()` seeds, in its order: the
/// three hosted surfaces' clients, the management API's, and the embedded
/// debugger's (`debuggerApplications()`, listed whether or not the
/// debugger is enabled).
pub const INTERNAL_IDENTIFIERS: &[&str] = &[
    "sts-admin-console",
    "sts-user-portal",
    "sts-report",
    "sts-api-client",
    "sts-debugger-ui",
];

/// `HOSTED_SURFACE_CLIENT_IDS`.
pub const HOSTED_SURFACE_CLIENT_IDS: &[&str] = &[
    "sts-admin-console",
    "sts-user-portal",
    "sts-report",
    "sts-debugger-ui",
];
