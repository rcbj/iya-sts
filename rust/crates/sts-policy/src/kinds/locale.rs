// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE LOCALE POLICY (3ci) — a port of `common/locale_policy.ts`: the
//! language a page falls back to, the language mail is written in when a
//! person names none, and the `preferredLanguage` a new person is given
//! (#539).
//!
//! `cn=default` follows the default realm's while a realm has none; named
//! profiles (#1238) are the realm's own, named by an application
//! (`appLocalePolicy`) or a group (`stsLocalePolicy`), ranked by
//! precedence. A reference to a profile the realm does not hold selects
//! nothing and is logged (STS-I18N-0013); this kind does NOT fail closed —
//! it only chooses a fallback language. A named profile something names is
//! not deleted (STS-I18N-0014).

use std::sync::LazyLock;

use serde_json::Value;
use sts_core::errors::codes;
use sts_model::domain::LocalePolicy as Concept;

use super::common::{self, Inherit, DEFAULT_PROFILE};
use crate::js::{self, Object};
use crate::ports::{Container, Ports};
use crate::selection::{self, Holders, Reference, SelectionSpec};
use crate::tables::{self, Field};
use crate::Answer;

const APP_REFERENCE: &str = "appLocalePolicy";
const GROUP_REFERENCE: &str = "stsLocalePolicy";
const PRECEDENCE: &str = "stsLocalePrecedence";

static FIELDS: LazyLock<Vec<Field>> =
    LazyLock::new(|| tables::fields("policy.locale", |_| {}, None));

fn spec() -> SelectionSpec {
    SelectionSpec::new(PRECEDENCE)
}

/// The locale policy, built over the ports.
pub struct LocalePolicy<'a> {
    ports: Ports<'a>,
}

impl<'a> LocalePolicy<'a> {
    /// The kind over its ports.
    /// A hot path, so it carries no span (the logging rule's exemption).
    pub fn new(ports: Ports<'a>) -> LocalePolicy<'a> {
        LocalePolicy { ports }
    }

    /// The rows.
    /// A hot path, so it carries no span (the logging rule's exemption).
    pub fn fields() -> &'static [Field] {
        &FIELDS
    }

    // `passkey_policy.ts`'s parse, with a language tag for its enum.
    fn parse(&self, field: &Field, raw: &Value) -> Result<Value, String> {
        let text = common::raw_text(raw);
        if field.kind == "bool" {
            return common::parse_bool(&text)
                .map(Value::Bool)
                .ok_or_else(|| common::bool_problem(field, &text));
        }
        let tag = self.ports.env.canonical_locale(&text);
        if tag.is_empty() {
            return Err(format!(
                "{} must be a BCP 47 language tag (RFC 5646) such as en, fr-CA or zh-TW; \"{}\" \
                 is not one.",
                field.label,
                js::slice(&text, 40)
            ));
        }
        Ok(Value::String(tag))
    }

    fn holds(&self, realm: &str, name: &str) -> bool {
        self.ports
            .directory
            .entries(realm, Container::Locale)
            .is_some_and(|list| common::entry_in(&list, name).is_some())
    }

    /// `read(name)`: a named profile the realm does not hold is `default`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn read(&self, realm: &str, name: Option<&str>) -> Value {
        let asked = name
            .filter(|n| !n.is_empty())
            .unwrap_or(DEFAULT_PROFILE)
            .to_lowercase();
        let profile = if asked != DEFAULT_PROFILE && !self.holds(realm, &asked)
        {
            DEFAULT_PROFILE.to_string()
        } else {
            asked
        };
        let found = common::entry_for(
            &self.ports,
            realm,
            Container::Locale,
            &profile,
            Inherit::DefaultOnly,
        );
        let (values, sources, problems) = common::read_rows(
            &FIELDS,
            &found,
            &common::defaults_of(&FIELDS),
            |f, raw| self.parse(f, raw),
            |f| common::shown(&f.dflt),
        );
        let empty = Object::new();
        let at = found
            .entry
            .as_ref()
            .map(|e| &e.attributes)
            .unwrap_or(&empty);
        let precedence = if profile == DEFAULT_PROFILE {
            Value::from(0)
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
                (
                    "inherited",
                    Value::Bool(found.from == common::From::DefaultRealm),
                ),
                ("from", Value::String(found.from.as_str().into())),
                (
                    "dn",
                    Value::String(
                        found
                            .entry
                            .as_ref()
                            .map(|e| e.dn.clone())
                            .unwrap_or_default(),
                    ),
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
        let entries = self.ports.directory.entries(realm, Container::Locale);
        let mut named: Vec<Value> = common::named_profiles(entries.as_deref())
            .iter()
            .map(|n| self.read(realm, Some(n)))
            .collect();
        named.sort_by(|a, b| {
            let p = |v: &Value| {
                selection::Precedence(
                    v.get("precedence").and_then(Value::as_f64).unwrap_or(0.0),
                )
            };
            let n = |v: &Value| {
                v.get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string()
            };
            selection::compare((&n(a), p(a)), (&n(b), p(b)))
        });
        let mut rows = vec![self.read(realm, Some(DEFAULT_PROFILE))];
        rows.extend(named);
        rows
    }

    /// `profileNameFor(application, person)`: of the profile the
    /// application names and those the person's groups name, the lowest
    /// precedence, else `default`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn profile_name_for(
        &self,
        realm: &str,
        application: &str,
        person: &str,
    ) -> String {
        let Some(entries) =
            self.ports.directory.entries(realm, Container::Locale)
        else {
            return DEFAULT_PROFILE.to_string();
        };
        if selection::named(Some(&entries), &spec()).is_empty() {
            return DEFAULT_PROFILE.to_string();
        }
        let who = js::trim(person);
        let groups = if who.is_empty() {
            Vec::new()
        } else {
            self.ports
                .directory
                .person_group_references(realm, who, GROUP_REFERENCE)
                .unwrap_or_default()
        };
        let mut references = vec![Reference::new(
            "application",
            application,
            &common::application_reference(
                &self.ports,
                realm,
                application,
                APP_REFERENCE,
            ),
        )];
        references.extend(selection::group_references(&groups));
        let ranked = selection::rank(Some(&entries), &spec(), &references);
        for m in &ranked.missing {
            tracing::warn!(
                code = codes::STS_I18N_0013.as_str(),
                "locale policy: the {} \"{}\" names the locale policy \"{}\", which this realm \
                 does not hold; it selects nothing, and `default` applies where nothing else \
                 names a profile, until the policy exists or the reference changes.",
                m.by,
                m.holder,
                m.name
            );
        }
        ranked.name
    }

    /// `forApplication(application, person)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn for_application(
        &self,
        realm: &str,
        application: &str,
        person: &str,
    ) -> Value {
        let name = self.profile_name_for(realm, application, person);
        self.read(realm, Some(&name))
    }

    /// `namedBy(name)`: the applications and the groups.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn named_by(&self, realm: &str, name: &str) -> Holders {
        Holders {
            applications: self.ports.applications.naming_policy(
                realm,
                APP_REFERENCE,
                name,
            ),
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
        let text = if given.is_empty() {
            DEFAULT_PROFILE.to_string()
        } else {
            given
        };
        selection::name_problem(
            &Value::String(text),
            "locale policy profile",
            true,
        )
    }

    /// `validate(given)`.
    #[tracing::instrument(level = "debug", skip(self, given))]
    pub fn validate(&self, given: Option<&Object>) -> (Object, Vec<String>) {
        let empty = Object::new();
        let body = given.unwrap_or(&empty);
        let mut values = Object::new();
        let mut problems = Vec::new();
        for f in FIELDS.iter() {
            match common::sent(body, f) {
                None => problems.push(common::required_problem(f)),
                Some(raw) => match self.parse(f, &raw) {
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
    pub fn save(
        &self,
        realm: &str,
        name: &Value,
        given: Option<&Object>,
    ) -> Answer {
        if let Some(refused) = Self::check_name(name) {
            return Answer::refused(codes::STS_I18N_0003, vec![refused]);
        }
        let which = which(name);
        let (values, mut problems) = self.validate(given);
        let ranked = (which != DEFAULT_PROFILE)
            .then(|| selection::check_precedence(given, &spec()));
        if let Some((_, p)) = &ranked {
            problems.extend(p.iter().cloned());
        }
        if !problems.is_empty() {
            return Answer::refused(codes::STS_I18N_0004, problems);
        }
        if !self.ports.directory.installed(Container::Locale) {
            return common::no_directory(
                codes::STS_I18N_0005,
                "a locale policy",
                "ou=localePolicies",
            );
        }
        let mut attributes = common::row_attributes(
            &["top", "stsLocalePolicy"],
            &FIELDS,
            &values,
            given,
        );
        if let Some((p, _)) = ranked {
            attributes.insert(PRECEDENCE.into(), Value::String(p.to_string()));
        }
        let outcome = self.ports.directory.write(
            realm,
            Container::Locale,
            &which,
            &attributes,
        );
        if let Some(refused) =
            common::write_refusal(&outcome, codes::STS_I18N_0006, "profile")
        {
            return refused;
        }
        common::saved(self.read(realm, Some(&which)))
    }

    /// `reset(name)`: refused while an application or a group names a named
    /// profile (STS-I18N-0014).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn reset(&self, realm: &str, name: &Value) -> Answer {
        if let Some(refused) = Self::check_name(name) {
            return Answer::refused(codes::STS_I18N_0003, vec![refused]);
        }
        let which = which(name);
        if !self.ports.directory.installed(Container::Locale) {
            return common::removed(false, self.read(realm, Some(&which)));
        }
        if which != DEFAULT_PROFILE {
            if let Some(held) = selection::delete_problem(
                "locale policy",
                &which,
                &self.named_by(realm, &which),
            ) {
                return Answer::refused(codes::STS_I18N_0014, vec![held]);
            }
        }
        let removed =
            self.ports
                .directory
                .delete(realm, Container::Locale, &which);
        common::removed(removed, self.read(realm, Some(&which)))
    }

    /// The reference attributes: on an application and on a group.
    pub const REFERENCES: [(&'static str, &'static str); 2] =
        [("application", APP_REFERENCE), ("group", GROUP_REFERENCE)];
}

/// `String(name || DEFAULT_PROFILE).trim().toLowerCase()`.
/// A hot path, so it carries no span (the logging rule's exemption).
pub(crate) fn which(name: &Value) -> String {
    let text = js::or_empty(Some(name));
    let text = if text.is_empty() {
        DEFAULT_PROFILE.to_string()
    } else {
        text
    };
    js::trim(&text).to_lowercase()
}
