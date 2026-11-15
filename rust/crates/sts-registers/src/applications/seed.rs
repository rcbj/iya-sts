// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE APPLICATIONS THAT ARE THIS SERVICE, SEEDED INTO A REALM
//! (`common/applications.js`'s `seedInternalApplication(spec)` and
//! `fillHostedSessionBounds()`; #444, phase 5, the `apis4` slice).
//!
//! A spec is one row of `internalApplications()` — `identifier`, `name`,
//! `kinds`, `protocols`, `description`, `registration` (an RFC 7591
//! client's metadata) and `attributes` — with its realm's values already
//! filled in by the caller (the runtime reads the specs off Node's own
//! function, `tests/tools/export-realm-seed.js`). An application the
//! directory already holds is left alone, exactly as Node leaves it.
//!
//! `applyRegistrationFields(record, registration)` is ported for the
//! members a spec carries and nothing more: the registration document,
//! its access token, the client id and secret, the redirect and sign-out
//! addresses, the home page, the grant and response types, the token
//! response types they allow, the scope and the token endpoint's
//! authentication method. On a blank record every `delete` Node makes
//! first is a no-op, so the members a spec never carries (the JWKS, the
//! certificate subject, introspection, request objects, CIBA, the command
//! endpoint, the display members) write nothing either way. The dynamic
//! registration endpoint, which is where the rest is reached, is not this
//! module's.

use serde_json::{json, Value};

use super::checks::values;
use super::record::values_of;
use super::write::{add_to, note_description, How};
use super::ApplicationRegistry;

fn strings(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(list)) => {
            list.iter().map(crate::js::string).collect()
        }
        Some(Value::Null) | None => Vec::new(),
        Some(other) => vec![crate::js::string(other)],
    }
}

fn text(value: Option<&Value>) -> String {
    match value {
        Some(Value::Null) | None => String::new(),
        Some(other) => crate::js::string(other),
    }
}

impl ApplicationRegistry {
    // `setField()` whose refusal (a seal that failed) is logged, as a seed
    // carries on past one.
    fn seed_field(
        &self,
        record: &mut super::record::Record,
        name: &str,
        value: &Value,
    ) {
        if let Err(e) = self.set_field(record, name, value) {
            tracing::warn!(
                "applications: \"{}\" was not written while seeding \"{}\": \
                 {:?}",
                name,
                record.identifier,
                e
            );
        }
    }

    // `applyRegistrationFields(record, registration)` for a blank record
    // and a spec's members (see the module comment).
    fn apply_seeded_registration(
        &self,
        record: &mut super::record::Record,
        meta: &Value,
    ) {
        let get = |k: &str| meta.get(k);
        self.seed_field(
            record,
            "appRegistrationJson",
            &Value::String(meta.to_string()),
        );
        self.seed_field(
            record,
            "appRegistrationAccessToken",
            get("registration_access_token").unwrap_or(&Value::Null),
        );
        let id = Value::String(record.identifier.clone());
        self.seed_field(record, "oauthClientId", &id);
        // `putClientSecret(record, meta.client_secret, {expiresAt:
        // Number(meta.client_secret_expires_at) || 0})`.
        let expires = get("client_secret_expires_at")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        if let Err(e) = self.put_client_secret(
            record,
            get("client_secret").unwrap_or(&Value::Null),
            Some(expires),
        ) {
            tracing::warn!(
                "applications: the client secret of \"{}\" was not \
                 written: {:?}",
                record.identifier,
                e
            );
        }
        let null = Value::Null;
        self.seed_field(
            record,
            "oauthRedirectUri",
            get("redirect_uris").unwrap_or(&null),
        );
        self.seed_field(
            record,
            "oauthPostLogoutRedirectUri",
            get("post_logout_redirect_uris").unwrap_or(&null),
        );
        self.seed_field(
            record,
            "appHomePageUrl",
            get("client_uri").unwrap_or(&null),
        );
        self.seed_field(
            record,
            "oauthGrantType",
            get("grant_types").unwrap_or(&null),
        );
        self.seed_field(
            record,
            "oauthResponseType",
            get("response_types").unwrap_or(&null),
        );
        let mut allowed: Vec<String> = Vec::new();
        for one in strings(get("response_types")) {
            let c = values::canonical_response_type(&one);
            if values::TOKEN_RESPONSE_TYPES.contains(&c.as_str())
                && !allowed.contains(&c)
            {
                allowed.push(c);
            }
        }
        self.seed_field(
            record,
            "oauthAllowedTokenResponseTypes",
            &json!(allowed),
        );
        let declared: Vec<String> = text(get("scope"))
            .split_whitespace()
            .map(str::to_string)
            .collect();
        if !declared.is_empty() {
            self.seed_field(record, "oauthAllowedScope", &json!(declared));
        }
        match get("token_endpoint_auth_method") {
            None => self.seed_field(
                record,
                "oauthTokenEndpointAuthMethod",
                &json!("client_secret_basic"),
            ),
            Some(stated) => {
                let method = text(Some(stated)).trim().to_string();
                if !method.is_empty() {
                    record.fields.shift_remove("oauthTokenEndpointAuthMethod");
                    self.seed_field(
                        record,
                        "oauthTokenEndpointAuthMethod",
                        &json!(method),
                    );
                }
            }
        }
        values::record_oauth_confidential(record, None);
    }

    /// `seedInternalApplication(spec)`: the application written as Node
    /// seeds it at startup (`appRegisteredBy: startup`) where the realm
    /// does not hold it; whether it was.
    #[tracing::instrument(level = "debug", skip(self, spec))]
    pub fn seed_internal_application(&self, spec: &Value) -> bool {
        let identifier = text(spec.get("identifier"));
        let loaded = self.load(&identifier);
        if loaded.known {
            tracing::debug!(
                "applications: \"{}\" is already here and was left alone.",
                identifier
            );
            return false;
        }
        let mut record = loaded.record;
        let now = self.env().now_ms();
        record.registered = true;
        self.seed_field(&mut record, "appRegisteredBy", &json!("startup"));
        record.first_at = now;
        record.last_at = now;
        record.name = text(spec.get("name"));
        for kind in strings(spec.get("kinds")) {
            add_to(&mut record.kinds, &kind);
        }
        for protocol in strings(spec.get("protocols")) {
            add_to(&mut record.protocols, &protocol);
        }
        note_description(&mut record, &text(spec.get("description")));
        let meta = spec.get("registration").cloned().unwrap_or(json!({}));
        self.apply_seeded_registration(&mut record, &meta);
        if let Some(attributes) =
            spec.get("attributes").and_then(Value::as_object)
        {
            for (name, value) in attributes {
                self.seed_field(&mut record, name, value);
            }
        }
        values::record_oauth_confidential(&mut record, None);
        if !self.save(&mut record, &How::quiet()) {
            tracing::warn!(
                "{}applications: \"{}\" was not seeded — the \
                 ou=applications container is full (applications.max) or \
                 the directory is. Nothing else is affected; the surface it \
                 names answers exactly as it did.",
                sts_core::log::tag(sts_core::errors::codes::STS_REG_0020),
                identifier
            );
            return false;
        }
        self.effects.audit(&json!({
            "action": "application.create", "actor": "",
            "protocol": "internal", "channel": "internal",
            "target": identifier,
            "summary": format!(
                "Application \"{}\" was seeded at startup ({})",
                identifier, record.name),
            "detail": { "identifier": identifier,
                        "kinds": record.kinds.join(", "),
                        "registered": true, "seeded": true },
        }));
        true
    }

    /// `fillHostedSessionBounds()`: each hosted surface's client given its
    /// shipped session bounds where it holds none; how many were written.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn fill_hosted_session_bounds(&self) -> usize {
        let mut wrote = 0;
        for (identifier, bounds) in values::HOSTED_SESSION_BOUNDS {
            let loaded = self.load(identifier);
            if !loaded.known {
                continue;
            }
            let mut record = loaded.record;
            let mut filled: Vec<&str> = Vec::new();
            for (name, value) in bounds.iter() {
                let have = values_of(record.fields.get(*name));
                if have.first().is_some_and(|v| !v.trim().is_empty()) {
                    continue;
                }
                if self
                    .set_field(&mut record, name, &json!(value))
                    .unwrap_or(false)
                {
                    filled.push(name);
                }
            }
            if filled.is_empty() {
                continue;
            }
            if !self.save(&mut record, &How::quiet()) {
                tracing::warn!(
                    "{}applications: \"{}\" was not given its hosted session \
                     bound — the directory would not take the write. The \
                     shipped number is still what enforcement uses.",
                    sts_core::log::tag(sts_core::errors::codes::STS_REG_0020),
                    identifier
                );
                continue;
            }
            self.effects.audit(&json!({
                "action": "application.update", "actor": "",
                "protocol": "internal", "channel": "internal",
                "target": identifier,
                "summary": format!(
                    "Application \"{}\" was given its hosted session bound \
                     ({})", identifier, filled.join(", ")),
                "detail": { "identifier": identifier,
                            "attribute": filled.join(", "),
                            "hostedSessionBound": true, "seeded": true },
            }));
            wrote += 1;
        }
        wrote
    }
}
