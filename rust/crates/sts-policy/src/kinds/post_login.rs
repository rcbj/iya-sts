// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE POST-LOGIN ACTIVITY POLICY (3ct) — a port of
//! `common/post_login_policy.ts`: what a person is asked to do after
//! signing in (#1096), today to register a post-quantum passkey.
//!
//! `cn=default` reaches every person and follows the default realm's while
//! the realm has none; a named profile (#1239) is named by a group
//! (`stsPostLoginPolicy`) or by the application signed in to
//! (`appPostLoginPolicy`), lowest precedence winning. A reference to a
//! profile the realm does not hold selects nothing (STS-AUTHN-0542) — the
//! policy asks, it guards no door — and a named profile something names is
//! not deleted (STS-AUTHN-0543).

use std::sync::LazyLock;

use serde_json::Value;
use sts_core::errors::codes;
use sts_model::domain::PostLoginPolicy as Concept;

use super::common::{self, Inherit, DEFAULT_PROFILE};
use super::locale::which;
use crate::js::{self, Object};
use crate::ports::{Container, GroupReference, Ports};
use crate::selection::{self, Holders, Reference, SelectionSpec, DEFAULT_PRECEDENCE};
use crate::tables::{self, Field};
use crate::Answer;

const APP_REFERENCE: &str = "appPostLoginPolicy";
const GROUP_REFERENCE: &str = "stsPostLoginPolicy";
const PRECEDENCE: &str = "stsPostLoginPrecedence";
/// The activities a profile may ask for (`ACTIVITIES`).
pub const ACTIVITIES: [&str; 1] = ["pqc-passkey-migration"];

static FIELDS: LazyLock<Vec<Field>> = LazyLock::new(|| {
    tables::fields(
        "policy.postLogin",
        |f| {
            if f.key == "activity" {
                f.values = ACTIVITIES.iter().map(|s| s.to_string()).collect();
            }
        },
        None,
    )
});

fn spec() -> SelectionSpec {
    SelectionSpec::new(PRECEDENCE)
}

/// The post-login activity policy, built over the ports.
pub struct PostLoginPolicy<'a> {
    ports: Ports<'a>,
}

impl<'a> PostLoginPolicy<'a> {
    /// The kind over its ports.
    pub fn new(ports: Ports<'a>) -> PostLoginPolicy<'a> {
        // A hot path: built per sign-in.
        PostLoginPolicy { ports }
    }

    /// The rows.
    pub fn fields() -> &'static [Field] {
        // A hot path: read per row of every profile.
        &FIELDS
    }

    fn parse(field: &Field, raw: &Value) -> Result<Value, String> {
        let text = common::raw_text(raw);
        match field.kind.as_str() {
            "bool" => common::parse_bool(&text)
                .map(Value::Bool)
                .ok_or_else(|| common::bool_problem(field, &text)),
            "enum" => {
                let lower = text.to_lowercase();
                if field.values.contains(&lower) {
                    Ok(Value::String(lower))
                } else {
                    Err(format!(
                        "{} is one of {}; \"{}\" is not.",
                        field.label,
                        field.values.join(", "),
                        js::slice(&text, 40)
                    ))
                }
            }
            _ => match js::digits(&text, 6) {
                Some(n)
                    if field.min.is_none_or(|m| n >= m) && field.max.is_none_or(|m| n <= m) =>
                {
                    Ok(Value::from(n))
                }
                _ => Err(format!(
                    "{} is a whole number of {} from {} to {}; \"{}\" is not.",
                    field.label,
                    field.unit.clone().unwrap_or_else(|| "units".into()),
                    common::bound(field.min),
                    common::bound(field.max),
                    js::slice(&text, 40)
                )),
            },
        }
    }

    fn holds(&self, realm: &str, name: &str) -> bool {
        self.ports
            .directory
            .entries(realm, Container::PostLogin)
            .is_some_and(|list| common::entry_in(&list, name).is_some())
    }

    /// `read(name)`: a named profile the realm does not hold is `default`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn read(&self, realm: &str, name: Option<&str>) -> Value {
        let asked = name.filter(|n| !n.is_empty()).unwrap_or(DEFAULT_PROFILE).to_lowercase();
        let profile = if asked != DEFAULT_PROFILE && !self.holds(realm, &asked) {
            DEFAULT_PROFILE.to_string()
        } else {
            asked
        };
        let found = common::entry_for(
            &self.ports,
            realm,
            Container::PostLogin,
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
        let at = found.entry.as_ref().map(|e| &e.attributes).unwrap_or(&empty);
        let precedence = if profile == DEFAULT_PROFILE {
            Value::from(DEFAULT_PRECEDENCE)
        } else {
            selection::precedence_of(at, &spec()).json()
        };
        let description = if found.entry.is_some() {
            common::concept_values(Concept::FIELDS, "description", at)
                .into_iter()
                .next()
                .unwrap_or_default()
        } else {
            String::new()
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
                ("description", Value::String(description)),
                ("sources", Value::Object(sources)),
                ("problems", js::strings(&problems)),
                ("enforced", Value::Bool(true)),
            ],
            values,
        )
    }

    /// `list()`: `default`, then the named by precedence, ties by name.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn list(&self, realm: &str) -> Vec<Value> {
        let entries = self.ports.directory.entries(realm, Container::PostLogin);
        let mut named: Vec<Value> = common::named_profiles(entries.as_deref())
            .iter()
            .map(|n| self.read(realm, Some(n)))
            .collect();
        common::sort_by_precedence(&mut named);
        let mut rows = vec![self.read(realm, Some(DEFAULT_PROFILE))];
        rows.extend(named);
        rows
    }

    /// `personGroups(username)`: the person's groups with the policy each
    /// names.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn person_groups(&self, realm: &str, username: &str) -> Vec<GroupReference> {
        if username.is_empty() || !self.ports.directory.installed(Container::PostLogin)
        {
            return Vec::new();
        }
        self.ports
            .directory
            .person_group_references(realm, username, GROUP_REFERENCE)
            .unwrap_or_default()
    }

    /// `profileNameFor(username, groupsOf, application)`: of the profile the
    /// application names and those the person's groups name, the lowest
    /// precedence, else `default`. Nobody named: `default`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn profile_name_for(&self, realm: &str, username: &str, application: &str) -> String {
        if username.is_empty() {
            return DEFAULT_PROFILE.to_string();
        }
        let Some(entries) = self.ports.directory.entries(realm, Container::PostLogin) else {
            return DEFAULT_PROFILE.to_string();
        };
        if selection::named(Some(&entries), &spec()).is_empty() {
            return DEFAULT_PROFILE.to_string();
        }
        let held = self.person_groups(realm, username);
        let mut references = Vec::new();
        let app = common::application_reference(&self.ports, realm, application, APP_REFERENCE);
        if !app.is_empty() {
            references.push(Reference::new("application", application, &app));
        }
        references.extend(selection::group_references(&held));
        let ranked = selection::rank(Some(&entries), &spec(), &references);
        for m in &ranked.missing {
            tracing::warn!(
                code = codes::STS_AUTHN_0542.as_str(),
                "post-login policy: the {} \"{}\" names the post-login policy \"{}\", which \
                 this realm does not hold; it selects nothing until the policy exists or the \
                 reference changes.",
                m.by,
                m.holder,
                m.name
            );
        }
        ranked.name
    }

    /// `forPerson(username, groupsOf, application)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn for_person(&self, realm: &str, username: &str, application: &str) -> Value {
        let name = self.profile_name_for(realm, username, application);
        self.read(realm, Some(&name))
    }

    /// `namedBy(name)`: the applications and the groups.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn named_by(&self, realm: &str, name: &str) -> Holders {
        Holders {
            applications: self.ports.applications.naming_policy(realm, APP_REFERENCE, name),
            groups: self
                .ports
                .directory
                .groups_naming_policy(realm, GROUP_REFERENCE, name)
                .unwrap_or_default(),
            people: Vec::new(),
        }
    }

    fn check_name(name: &Value) -> Option<String> {
        let given = js::or_empty(Some(name));
        let text = if given.is_empty() { DEFAULT_PROFILE.to_string() } else { given };
        let text = js::trim(&text);
        if text != DEFAULT_PROFILE && !selection::is_policy_name(text) {
            return Some(format!(
                "A post-login profile is \"{DEFAULT_PROFILE}\" or a name of lower-case letters, \
                 digits and hyphens, at most 64; \"{}\" is neither.",
                js::slice(text, 64)
            ));
        }
        None
    }

    /// `validate(given)`.
    #[tracing::instrument(level = "debug", skip(given))]
    pub fn validate(given: Option<&Object>) -> (Object, Vec<String>) {
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
        (values, problems)
    }

    /// `save(name, given)`.
    #[tracing::instrument(level = "debug", skip(self, given))]
    pub fn save(&self, realm: &str, name: &Value, given: Option<&Object>) -> Answer {
        if let Some(refused) = Self::check_name(name) {
            return Answer::refused(codes::STS_AUTHN_0470, vec![refused]);
        }
        let which = which(name);
        let (values, mut problems) = Self::validate(given);
        let named = which != DEFAULT_PROFILE;
        let mut precedence = DEFAULT_PRECEDENCE;
        if named {
            let (p, bad) = selection::check_precedence(given, &spec());
            problems.extend(bad);
            precedence = p;
        }
        if !problems.is_empty() {
            return Answer::refused(codes::STS_AUTHN_0471, problems);
        }
        if !self.ports.directory.installed(Container::PostLogin) {
            return common::no_directory(
                codes::STS_AUTHN_0472,
                "a post-login profile",
                "ou=postLoginPolicies",
            );
        }
        let mut attributes =
            common::row_attributes(&["top", "stsPostLoginPolicy"], &FIELDS, &values, given);
        if named {
            attributes.insert(PRECEDENCE.into(), Value::String(precedence.to_string()));
        }
        let outcome = self.ports.directory.write(realm, Container::PostLogin, &which, &attributes);
        if let Some(refused) = common::write_refusal(&outcome, codes::STS_AUTHN_0472, "profile") {
            return refused;
        }
        common::saved(self.read(realm, Some(&which)))
    }

    /// `reset(name)`: refused while an application or a group names a named
    /// profile (STS-AUTHN-0543).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn reset(&self, realm: &str, name: &Value) -> Answer {
        if let Some(refused) = Self::check_name(name) {
            return Answer::refused(codes::STS_AUTHN_0470, vec![refused]);
        }
        let which = which(name);
        if !self.ports.directory.installed(Container::PostLogin) {
            return common::removed(false, self.read(realm, Some(&which)));
        }
        if which != DEFAULT_PROFILE {
            if let Some(held) =
                selection::delete_problem("post-login policy", &which, &self.named_by(realm, &which))
            {
                return Answer::refused(codes::STS_AUTHN_0543, vec![held]);
            }
        }
        let removed = self.ports.directory.delete(realm, Container::PostLogin, &which);
        common::removed(removed, self.read(realm, Some(&which)))
    }

    /// The reference attributes: on an application and on a group.
    pub const REFERENCES: [(&'static str, &'static str); 2] =
        [("application", APP_REFERENCE), ("group", GROUP_REFERENCE)];
}
