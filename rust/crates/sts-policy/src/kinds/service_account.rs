// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE SERVICE-ACCOUNT POLICY (3cd) — a port of
//! `common/service_account_policy.ts`: what a service account may do (the
//! second factor, the browser, the password doors) and how its password
//! rotates (#221).
//!
//! `cn=default` is inherited from the default realm while a realm has none
//! of its own; a NAMED profile (#1240) is the realm's own and is named by a
//! service account's own `stsServiceAccountPolicy` — never by an
//! application or a group. A name the realm does not hold gets `default`
//! (STS-SVCACCT-0047), and a profile something names is not deleted
//! (STS-SVCACCT-0049).

use std::sync::LazyLock;

use serde_json::Value;
use sts_core::errors::{codes, ErrorCode};

use super::common::{self, Inherit, DEFAULT_PROFILE};
use super::password::PasswordPolicy;
use crate::js::{self, Object};
use crate::ports::{Container, Ports};
use crate::selection::{self, Holders, Reference, SelectionSpec};
use crate::tables::{self, Field};
use crate::Answer;

const NOUN: &str = "service-account policy";
const PERSON_REFERENCE: &str = "stsServiceAccountPolicy";
const PRECEDENCE: &str = "stsServiceAccountPrecedence";

/// A password door a service account may be allowed (`DOORS`).
#[derive(Debug, Clone, PartialEq)]
pub struct Door {
    pub id: String,
    pub key: String,
    pub label: String,
}

static DOORS: LazyLock<Vec<Door>> = LazyLock::new(|| {
    tables::table("policy.serviceAccount")
        .facts
        .get("doors")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .map(|d| Door {
                    id: d.get("id").and_then(Value::as_str).unwrap_or("").into(),
                    key: d.get("key").and_then(Value::as_str).unwrap_or("").into(),
                    label: d.get("label").and_then(Value::as_str).unwrap_or("").into(),
                })
                .collect()
        })
        .unwrap_or_default()
});

static FIELDS: LazyLock<Vec<Field>> = LazyLock::new(|| {
    let table = tables::table("policy.serviceAccount");
    let computed = DOORS
        .iter()
        .map(|d| {
            let mut c = d.key.chars();
            let attribute = match c.next() {
                Some(f) => format!("stsSvcAcct{}{}", f.to_uppercase(), c.as_str()),
                None => "stsSvcAcct".into(),
            };
            Field {
                what: table.attribute_what(&attribute),
                key: d.key.clone(),
                attribute,
                kind: "bool".into(),
                dflt: Value::Bool(true),
                door: Some(d.id.clone()),
                label: format!("Door: {}", d.label),
                ..Field::default()
            }
        })
        .collect();
    tables::fields("policy.serviceAccount", |_| {}, Some(("rotationEnabled", computed)))
});

fn spec() -> SelectionSpec {
    SelectionSpec::new(PRECEDENCE)
}

/// The service-account policy, built over the ports.
pub struct ServiceAccountPolicy<'a> {
    ports: Ports<'a>,
}

impl<'a> ServiceAccountPolicy<'a> {
    /// The kind over its ports.
    pub fn new(ports: Ports<'a>) -> ServiceAccountPolicy<'a> {
        // A hot path: built per question the API layer asks.
        ServiceAccountPolicy { ports }
    }

    /// The rows, the doors' before `rotationEnabled`.
    pub fn fields() -> &'static [Field] {
        // A hot path: read per row of every profile.
        &FIELDS
    }

    /// The password doors.
    pub fn doors() -> &'static [Door] {
        // A hot path: read by every `allowsDoor()`.
        &DOORS
    }

    // `authn_policy.ts`'s parse without its enum.
    fn parse(field: &Field, raw: &Value) -> Result<Value, String> {
        let text = common::raw_text(raw);
        if field.kind == "bool" {
            return common::parse_bool(&text)
                .map(Value::Bool)
                .ok_or_else(|| common::bool_problem(field, &text));
        }
        common::parse_whole(field, &text)
    }

    // The two checks that read OTHER registers, asked of a save only.
    fn save_problems(&self, realm: &str, values: &Object) -> Vec<String> {
        let mut out = Vec::new();
        let minimum = PasswordPolicy::new(self.ports)
            .read(realm, None)
            .get("minLength")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let generated = values.get("generatedLength").and_then(Value::as_f64).unwrap_or(f64::NAN);
        if generated < minimum {
            out.push(format!(
                "A rotated password of {} characters is shorter than this realm's password \
                 policy allows ({}). Raise the length, or lower the password policy's minimum \
                 first.",
                common::number_text(generated),
                common::number_text(minimum)
            ));
        }
        if values.get("rotationEnabled") == Some(&Value::Bool(true))
            && self.ports.env.destination_count(realm) == 0
        {
            out.push(
                "Rotation cannot be turned on while this realm has no push destination: a \
                 rotated password has to be pushed somewhere before it is used. Register one \
                 under Directory → Secret destinations first."
                    .into(),
            );
        }
        out
    }

    /// `read(name)`: this realm's entry, else — for `default` only — the
    /// default realm's, else the built-in defaults.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn read(&self, realm: &str, name: Option<&str>) -> Value {
        let profile = js::trim(name.filter(|n| !n.is_empty()).unwrap_or(DEFAULT_PROFILE))
            .to_lowercase();
        let found = common::entry_for(
            &self.ports,
            realm,
            Container::ServiceAccount,
            &profile,
            Inherit::DefaultOnly,
        );
        let (values, sources, problems) = common::read_rows(
            &FIELDS,
            &found,
            &common::defaults_of(&FIELDS),
            Self::parse,
            |f| common::shown(&f.dflt),
        );
        let empty = Object::new();
        let precedence = if profile == DEFAULT_PROFILE {
            Value::from(0)
        } else {
            selection::precedence_of(
                found.entry.as_ref().map(|e| &e.attributes).unwrap_or(&empty),
                &spec(),
            )
            .json()
        };
        common::profile(
            vec![
                ("name", Value::String(profile)),
                ("precedence", precedence),
                ("stored", Value::Bool(found.from == common::From::Realm)),
                ("inherited", Value::Bool(found.from == common::From::DefaultRealm)),
                ("from", Value::String(found.from.as_str().into())),
                (
                    "dn",
                    Value::String(found.entry.as_ref().map(|e| e.dn.clone()).unwrap_or_default()),
                ),
                ("description", Value::String(common::description_in(&found))),
                ("sources", Value::Object(sources)),
                ("problems", js::strings(&problems)),
                ("enforced", Value::Bool(true)),
            ],
            values,
        )
    }

    /// `profileFor(username)`: the profile the account's
    /// `stsServiceAccountPolicy` names, else `default`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn profile_for(&self, realm: &str, username: &str) -> Value {
        let name = js::trim(username);
        let reference = if name.is_empty() {
            String::new()
        } else {
            self.ports.env.service_account_reference(realm, name)
        };
        self.profile_for_reference(realm, &Value::String(reference), name)
    }

    /// `profileForReference(reference, holder)`: a name the realm does not
    /// hold is logged (STS-SVCACCT-0047) and gets `default`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn profile_for_reference(&self, realm: &str, reference: &Value, holder: &str) -> Value {
        let entries = self.ports.directory.entries(realm, Container::ServiceAccount);
        let Some(entries) = entries.filter(|_| !js::fold(reference).is_empty()) else {
            return self.read(realm, Some(DEFAULT_PROFILE));
        };
        let ranked = selection::rank(
            Some(&entries),
            &spec(),
            &[Reference { by: "person".into(), holder: holder.into(), value: reference.clone() }],
        );
        for m in &ranked.missing {
            tracing::warn!(
                code = codes::STS_SVCACCT_0047.as_str(),
                "service-account policy: the service account \"{}\" names the service-account \
                 policy \"{}\", which this realm does not hold; `default` governs it until the \
                 policy exists or the reference changes.",
                m.holder,
                m.name
            );
        }
        self.read(realm, Some(&ranked.name))
    }

    /// `list()`: `default`, then the named by precedence, ties by name.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn list(&self, realm: &str) -> Vec<Value> {
        let entries = self.ports.directory.entries(realm, Container::ServiceAccount);
        let mut named: Vec<Value> = selection::named(entries.as_deref(), &spec())
            .iter()
            .map(|n| self.read(realm, Some(&n.name)))
            .collect();
        common::sort_by_precedence(&mut named);
        let mut rows = vec![self.read(realm, Some(DEFAULT_PROFILE))];
        rows.extend(named);
        rows
    }

    /// `namedBy(name)`: the service accounts naming it.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn named_by(&self, realm: &str, name: &Value) -> Holders {
        let wanted = js::fold(name);
        let people = if wanted.is_empty() || wanted == DEFAULT_PROFILE {
            Vec::new()
        } else {
            self.ports.env.service_accounts_naming(realm, &wanted)
        };
        Holders { applications: Vec::new(), groups: Vec::new(), people }
    }

    /// `holderRefusal(attributes)`: the reference on an entry that is not a
    /// service account (STS-SVCACCT-0048).
    #[tracing::instrument(level = "debug", skip(self, attributes))]
    pub fn holder_refusal(&self, realm: &str, attributes: &Object) -> Option<(ErrorCode, String)> {
        if self.ports.env.is_service_account(realm, attributes) {
            return None;
        }
        Some((
            codes::STS_SVCACCT_0048,
            format!(
                "{PERSON_REFERENCE} names the service-account policy that governs a SERVICE \
                 ACCOUNT, and this person is not one. Make them a service account first (the \
                 Service account tab, or POST /admin-api/users/set-service-account)."
            ),
        ))
    }

    /// `writeRefusal(attributes)`: a reference on an entry that may not hold
    /// it, or naming a profile the realm does not hold (STS-SVCACCT-0050).
    #[tracing::instrument(level = "debug", skip(self, attributes))]
    pub fn write_refusal(&self, realm: &str, attributes: &Object) -> Option<(ErrorCode, String)> {
        let value = js::values_of(attributes, PERSON_REFERENCE).into_iter().next().unwrap_or_default();
        let text = js::fold_str(&value);
        if text.is_empty() {
            return None;
        }
        if let Some(refused) = self.holder_refusal(realm, attributes) {
            return Some(refused);
        }
        let choices: Vec<String> = self
            .list(realm)
            .iter()
            .map(|p| p.get("name").map(js::text).unwrap_or_default())
            .collect();
        selection::reference_problem(&Value::String(text), Some(&choices), PERSON_REFERENCE)
            .map(|p| (codes::STS_SVCACCT_0050, p))
    }

    fn check_name(name: &Value) -> Option<String> {
        let given = match name {
            Value::Null => Value::String(DEFAULT_PROFILE.into()),
            Value::String(s) if s.is_empty() => Value::String(DEFAULT_PROFILE.into()),
            other => other.clone(),
        };
        selection::name_problem(&given, NOUN, true)
    }

    /// `validate(given)`: every row required (save's cross checks too).
    #[tracing::instrument(level = "debug", skip(self, given))]
    pub fn validate(&self, realm: &str, given: Option<&Object>) -> (Object, Vec<String>) {
        let empty = Object::new();
        let body = given.unwrap_or(&empty);
        let mut values = Object::new();
        let mut problems = Vec::new();
        for f in FIELDS.iter() {
            match common::sent(body, f) {
                None => problems.push(common::required_problem(f)),
                Some(raw) => match Self::parse(f, &raw) {
                    Ok(v) => {
                        values.insert(f.key.clone(), v);
                    }
                    Err(p) => problems.push(p),
                },
            }
        }
        if problems.is_empty() {
            problems.extend(self.save_problems(realm, &values));
        }
        (values, problems)
    }

    /// `save(name, given)`.
    #[tracing::instrument(level = "debug", skip(self, given))]
    pub fn save(&self, realm: &str, name: &Value, given: Option<&Object>) -> Answer {
        if let Some(refused) = Self::check_name(name) {
            return Answer::refused(codes::STS_SVCACCT_0001, vec![refused]);
        }
        let which = which(name);
        let (values, mut problems) = self.validate(realm, given);
        let ranked = (which != DEFAULT_PROFILE).then(|| selection::check_precedence(given, &spec()));
        if let Some((_, p)) = &ranked {
            problems.extend(p.iter().cloned());
        }
        if !problems.is_empty() {
            return Answer::refused(codes::STS_SVCACCT_0002, problems);
        }
        if !self.ports.directory.installed(Container::ServiceAccount) {
            return common::no_directory(
                codes::STS_SVCACCT_0003,
                "a service-account policy",
                "ou=serviceAccountPolicies",
            );
        }
        let mut attributes =
            common::row_attributes(&["top", "stsServiceAccountPolicy"], &FIELDS, &values, given);
        if let Some((p, _)) = ranked {
            attributes.insert(PRECEDENCE.into(), Value::String(p.to_string()));
        }
        let outcome =
            self.ports.directory.write(realm, Container::ServiceAccount, &which, &attributes);
        if let Some(refused) = common::write_refusal(&outcome, codes::STS_SVCACCT_0004, "profile") {
            return refused;
        }
        common::saved(self.read(realm, Some(&which)))
    }

    /// `reset(name)`: `default` goes back to inheriting; a named profile is
    /// removed whole, not while a service account names it.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn reset(&self, realm: &str, name: &Value) -> Answer {
        if let Some(refused) = Self::check_name(name) {
            return Answer::refused(codes::STS_SVCACCT_0001, vec![refused]);
        }
        let which = which(name);
        if !self.ports.directory.installed(Container::ServiceAccount) {
            return common::removed(false, self.read(realm, Some(&which)));
        }
        if which != DEFAULT_PROFILE {
            let holders = self.named_by(realm, &Value::String(which.clone()));
            if let Some(held) = selection::delete_problem(NOUN, &which, &holders) {
                return Answer::refused(codes::STS_SVCACCT_0049, vec![held]);
            }
        }
        let removed = self.ports.directory.delete(realm, Container::ServiceAccount, &which);
        common::removed(removed, self.read(realm, Some(&which)))
    }

    /// The reference attribute: on the service account's own entry.
    pub const REFERENCES: [(&'static str, &'static str); 1] = [("person", PERSON_REFERENCE)];
}

/// `String(name || DEFAULT_PROFILE).trim().toLowerCase()`.
fn which(name: &Value) -> String {
    let text = js::or_empty(Some(name));
    let text = if text.is_empty() { DEFAULT_PROFILE.to_string() } else { text };
    js::trim(&text).to_lowercase()
}
