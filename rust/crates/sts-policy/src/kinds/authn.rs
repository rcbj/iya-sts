// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE AUTHENTICATION POLICY (3bd) — a port of `common/authn_policy.ts`:
//! which ways of signing in a realm accepts as a first factor, which as a
//! second, and when a second is required; and its NAMED policies (#1148,
//! #1237), each two lists an application or a group naming it narrows a
//! sign-in to.
//!
//! `cn=default,ou=authnPolicies` is the realm's own; a realm with none is
//! governed by the default realm's, then by the built-in defaults (D6). The
//! named policies are the realm's own and never inherited. A name that
//! resolves to no policy ALLOWS NO MECHANISM (STS-AUTHN-0536): a reference
//! fails closed. The two email rows cannot be saved on while the realm
//! cannot send mail (NIST SP 800-63B-4 section 3.1.3.1, D1).

use std::sync::LazyLock;

use serde_json::Value;
use sts_core::errors::codes;
use sts_model::domain::AuthenticationPolicy as Concept;

use super::common::{self, Found, Inherit, DEFAULT_PROFILE};
use crate::js::{self, Object};
use crate::ports::{Container, Ports};
use crate::selection::{self, Holders, Reference, SelectionSpec};
use crate::tables::{self, Field};
use crate::Answer;

const APP_REFERENCE: &str = "appAuthnPolicy";
const GROUP_REFERENCE: &str = "stsAuthnPolicy";
const PRECEDENCE: &str = "stsAuthnPolicyPrecedence";
/// What a reference to a policy nobody holds allows (#1148): a value no
/// mechanism has, so the list matches nothing.
pub const MISSING_MECHANISM: &str = "(no such authentication policy)";

/// One way of signing in and what it is capable of: `primary` and
/// `second_factor` are the built-in defaults, `None` where the mechanism
/// cannot take that role.
#[derive(Debug, Clone, PartialEq)]
pub struct Mechanism {
    pub id: String,
    pub label: String,
    pub primary: Option<bool>,
    pub second_factor: Option<bool>,
    pub email: bool,
}

static MECHANISMS: LazyLock<Vec<Mechanism>> = LazyLock::new(|| {
    tables::table("policy.authn")
        .facts
        .get("mechanisms")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .map(|m| Mechanism {
                    id: m.get("id").and_then(Value::as_str).unwrap_or("").into(),
                    label: m.get("label").and_then(Value::as_str).unwrap_or("").into(),
                    primary: m.get("primary").and_then(Value::as_bool),
                    second_factor: m.get("secondFactor").and_then(Value::as_bool),
                    email: m.get("email").and_then(Value::as_bool).unwrap_or(false),
                })
                .collect()
        })
        .unwrap_or_default()
});

fn key_of(mechanism: &str, primary: bool) -> String {
    format!("{mechanism}{}", if primary { "Primary" } else { "SecondFactor" })
}

fn attribute_of(key: &str) -> String {
    let mut c = key.chars();
    match c.next() {
        Some(first) => format!("stsAuthn{}{}", first.to_uppercase(), c.as_str()),
        None => "stsAuthn".into(),
    }
}

static FIELDS: LazyLock<Vec<Field>> = LazyLock::new(|| {
    let table = tables::table("policy.authn");
    let mut computed = Vec::new();
    for m in MECHANISMS.iter() {
        for primary in [true, false] {
            let dflt = if primary { m.primary } else { m.second_factor };
            let Some(dflt) = dflt else { continue };
            let key = key_of(&m.id, primary);
            let attribute = attribute_of(&key);
            computed.push(Field {
                what: table.attribute_what(&attribute),
                key,
                attribute,
                kind: "bool".into(),
                dflt: Value::Bool(dflt),
                mechanism: Some(m.id.clone()),
                role: Some(if primary { "primary" } else { "second-factor" }.into()),
                email: m.email,
                label: format!(
                    "{} — as a {}",
                    m.label,
                    if primary { "first factor" } else { "second factor" }
                ),
                ..Field::default()
            });
        }
    }
    tables::fields("policy.authn", |_| {}, Some(("emailCodeTtlS", computed)))
});

fn spec() -> SelectionSpec {
    SelectionSpec::new(PRECEDENCE)
}

/// A named authentication policy, as `named()` lists it.
#[derive(Debug, Clone, PartialEq)]
pub struct NamedAuthnPolicy {
    pub name: String,
    pub dn: String,
    pub description: String,
    pub precedence: selection::Precedence,
    pub mechanisms: Vec<String>,
    pub second_factors: Vec<String>,
}

impl NamedAuthnPolicy {
    /// As Node's object.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn json(&self) -> Value {
        js::object(vec![
            ("name", Value::String(self.name.clone())),
            ("dn", Value::String(self.dn.clone())),
            ("description", Value::String(self.description.clone())),
            ("precedence", self.precedence.json()),
            ("mechanisms", js::strings(&self.mechanisms)),
            ("secondFactors", js::strings(&self.second_factors)),
        ])
    }
}

/// The authentication policy, built over the ports.
pub struct AuthnPolicy<'a> {
    ports: Ports<'a>,
}

// The list `named()` reads: trimmed, the empty ones and the repeats gone.
fn list_of(values: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for v in values {
        let t = js::trim(&v).to_string();
        if !t.is_empty() && !out.contains(&t) {
            out.push(t);
        }
    }
    out
}

// `saveNamed()`'s list: each value split at whitespace and commas.
fn list_sent(value: Option<&Value>) -> Vec<String> {
    let items: Vec<&Value> = match value {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(a)) => a.iter().collect(),
        Some(one) => vec![one],
    };
    let mut out: Vec<String> = Vec::new();
    for one in items {
        let text = match one {
            Value::Null => "null".to_string(),
            other => js::text(other),
        };
        for part in text.split(|c: char| c == ',' || js::is_js_space(c)) {
            if !part.is_empty() && !out.iter().any(|o| o == part) {
                out.push(part.to_string());
            }
        }
    }
    out
}

impl<'a> AuthnPolicy<'a> {
    /// The kind over its ports.
    pub fn new(ports: Ports<'a>) -> AuthnPolicy<'a> {
        // A hot path: built per question the API layer asks.
        AuthnPolicy { ports }
    }

    /// The rows, with the computed mechanism rows before `emailCodeTtlS`.
    pub fn fields() -> &'static [Field] {
        // A hot path: read per row of every profile.
        &FIELDS
    }

    /// The mechanisms, from the model's facts.
    pub fn mechanisms() -> &'static [Mechanism] {
        // A hot path: read by every `allows()`.
        &MECHANISMS
    }

    fn parse(field: &Field, raw: &Value) -> Result<Value, String> {
        let text = common::raw_text(raw);
        match field.kind.as_str() {
            "bool" => common::parse_bool(&text)
                .map(Value::Bool)
                .ok_or_else(|| common::bool_problem(field, &text)),
            "enum" => {
                if field.values.contains(&text) {
                    Ok(Value::String(text))
                } else {
                    Err(format!(
                        "{} is one of {}; \"{}\" is not.",
                        field.label,
                        field.values.join(", "),
                        js::slice(&text, 40)
                    ))
                }
            }
            _ => common::parse_whole(field, &text),
        }
    }

    // `crossFieldProblems()`: a realm must leave SOME way in.
    fn cross_field_problems(values: &Object) -> Vec<String> {
        let on = |k: String| values.get(&k).is_some_and(js::truthy);
        let mut out = Vec::new();
        let any_primary = MECHANISMS
            .iter()
            .any(|m| m.primary.is_some() && on(key_of(&m.id, true)));
        if !any_primary {
            out.push(
                "No mechanism is accepted as a first factor, so nobody could sign in to this \
                 realm — its administrators included. Leave at least one on."
                    .into(),
            );
        }
        let always = |k: &str| values.get(k) == Some(&Value::String("always".into()));
        if always("requireSecondFactor") || always("requireSecondFactorForAdministrators") {
            let any_second = MECHANISMS
                .iter()
                .any(|m| m.second_factor.is_some() && on(key_of(&m.id, false)));
            if !any_second {
                out.push(format!(
                    "A second factor is required of {}, but no mechanism is accepted as one, so \
                     nobody could finish signing in. Turn one on, or require a second factor \
                     only of those who hold one.",
                    if always("requireSecondFactor") { "everybody" } else { "administrators" }
                ));
            }
        }
        out
    }

    /// `read(name)`: this realm's entry, else the default realm's, else the
    /// built-in defaults; always answers.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn read(&self, realm: &str, name: Option<&str>) -> Value {
        let profile = name.filter(|n| !n.is_empty()).unwrap_or(DEFAULT_PROFILE).to_string();
        let found = common::entry_for(&self.ports, realm, Container::Authn, &profile, Inherit::Any);
        let (values, sources, mut problems) = common::read_rows(
            &FIELDS,
            &found,
            &common::defaults_of(&FIELDS),
            Self::parse,
            |f| common::shown(&f.dflt),
        );
        if found.entry.is_some() {
            problems.extend(Self::cross_field_problems(&values));
        }
        common::profile(
            vec![
                ("name", Value::String(profile)),
                ("stored", Value::Bool(found.from == common::From::Realm)),
                ("inherited", Value::Bool(found.from == common::From::DefaultRealm)),
                ("from", Value::String(found.from.as_str().into())),
                ("dn", Value::String(Self::dn_of(&found))),
                ("description", Value::String(common::description_in(&found))),
                ("sources", Value::Object(sources)),
                ("problems", js::strings(&problems)),
                ("enforced", Value::Bool(true)),
            ],
            values,
        )
    }

    fn dn_of(found: &Found) -> String {
        found.entry.as_ref().map(|e| e.dn.clone()).unwrap_or_default()
    }

    /// `list()`: the one profile in force.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn list(&self, realm: &str) -> Vec<Value> {
        vec![self.read(realm, Some(DEFAULT_PROFILE))]
    }

    /// `allows(mechanism, role, profile)`: false for an unknown mechanism or
    /// a role it cannot take.
    #[tracing::instrument(level = "debug", skip(self, profile))]
    pub fn allows(&self, realm: &str, mechanism: &str, primary: bool, profile: Option<&Value>) -> bool {
        let Some(m) = MECHANISMS.iter().find(|m| m.id == mechanism) else {
            return false;
        };
        if (if primary { m.primary } else { m.second_factor }).is_none() {
            return false;
        }
        let read;
        let rules = match profile {
            Some(p) => p,
            None => {
                read = self.read(realm, Some(DEFAULT_PROFILE));
                &read
            }
        };
        rules.get(key_of(mechanism, primary)).is_some_and(js::truthy)
    }

    /// `named()`: the realm's named authentication policies, by name.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn named(&self, realm: &str) -> Vec<NamedAuthnPolicy> {
        let Some(entries) = self.ports.directory.entries(realm, Container::Authn) else {
            return Vec::new();
        };
        let mut out: Vec<NamedAuthnPolicy> = entries
            .iter()
            .filter(|e| e.name.to_lowercase() != DEFAULT_PROFILE)
            .map(|e| {
                let at = &e.attributes;
                NamedAuthnPolicy {
                    name: e.name.to_lowercase(),
                    dn: e.dn.clone(),
                    description: list_of(common::concept_values(Concept::FIELDS, "description", at))
                        .into_iter()
                        .next()
                        .unwrap_or_default(),
                    precedence: selection::precedence_of(at, &spec()),
                    mechanisms: list_of(common::concept_values(Concept::FIELDS, "policyMechanism", at)),
                    second_factors: list_of(common::concept_values(
                        Concept::FIELDS,
                        "policySecondFactor",
                        at,
                    )),
                }
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// `namedPolicy(name)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn named_policy(&self, realm: &str, name: &Value) -> Option<NamedAuthnPolicy> {
        let wanted = js::trim(&js::text(name)).to_lowercase();
        if wanted.is_empty() || wanted == DEFAULT_PROFILE {
            return None;
        }
        self.named(realm).into_iter().find(|p| p.name == wanted)
    }

    /// `mechanismsFor(fields, person)`: the named policy that applies to a
    /// sign-in, as its two lists. Nothing named: both empty. A reference to
    /// a name the realm does not hold: `missing`, and lists that match
    /// nothing (fail closed, STS-AUTHN-0536).
    #[tracing::instrument(level = "debug", skip(self, fields))]
    pub fn mechanisms_for(&self, realm: &str, fields: Option<&Object>, person: &str) -> Value {
        let first = |f: &Object, k: &str| -> Option<Value> {
            match f.get(k) {
                None | Some(Value::Null) => None,
                Some(v) if !js::truthy(v) && !v.is_array() => None,
                Some(Value::Array(a)) => Some(a.first().cloned().unwrap_or(Value::Null)),
                Some(v) => Some(v.clone()),
            }
        };
        let held = fields
            .and_then(|f| first(f, APP_REFERENCE))
            .filter(|v| !v.is_null())
            .unwrap_or(Value::String(String::new()));
        let application = fields
            .map(|f| {
                let pick = match f.get("identifier") {
                    Some(v) if js::truthy(v) => Some(v),
                    _ => f.get("cn").filter(|v| js::truthy(v)),
                };
                match pick {
                    Some(Value::Array(a)) => a.first().map(js::text).unwrap_or_default(),
                    Some(v) => js::text(v),
                    None => String::new(),
                }
            })
            .unwrap_or_default();
        let mut references = vec![Reference {
            by: "application".into(),
            holder: application,
            value: held,
        }];
        let key = js::trim(person);
        if !key.is_empty() {
            if let Some(groups) =
                self.ports.directory.person_group_references(realm, key, GROUP_REFERENCE)
            {
                references.extend(selection::group_references(&groups));
            }
        }
        let default = || {
            js::object(vec![
                ("policy", Value::String(DEFAULT_PROFILE.into())),
                ("by", Value::String(DEFAULT_PROFILE.into())),
                ("holder", Value::String(String::new())),
                ("precedence", Value::from(0)),
                ("mechanisms", Value::Array(vec![])),
                ("secondFactors", Value::Array(vec![])),
                ("missing", Value::Bool(false)),
            ])
        };
        let named = references.iter().any(|r| {
            let v = js::fold(&r.value);
            !v.is_empty() && v != DEFAULT_PROFILE
        });
        if !named {
            return default();
        }
        let entries = self.ports.directory.entries(realm, Container::Authn).unwrap_or_default();
        let ranked = selection::rank(Some(&entries), &spec(), &references);
        if let Some(first) = ranked.missing.first() {
            for m in &ranked.missing {
                tracing::warn!(
                    code = codes::STS_AUTHN_0536.as_str(),
                    "authn policy: the {}{} names the authentication policy \"{}\", which this \
                     realm does not hold; the sign-in allows no mechanism until the policy \
                     exists or the reference ({}) changes.",
                    m.by,
                    if m.holder.is_empty() { String::new() } else { format!(" \"{}\"", m.holder) },
                    m.name,
                    if m.by == "group" { GROUP_REFERENCE } else { APP_REFERENCE }
                );
            }
            let missing = js::strings(&[MISSING_MECHANISM.to_string()]);
            return js::object(vec![
                ("policy", Value::String(first.name.clone())),
                ("by", Value::String(first.by.clone())),
                ("holder", Value::String(first.holder.clone())),
                ("precedence", Value::from(0)),
                ("mechanisms", missing.clone()),
                ("secondFactors", missing),
                ("missing", Value::Bool(true)),
            ]);
        }
        let found = if ranked.name == DEFAULT_PROFILE {
            None
        } else {
            self.named_policy(realm, &Value::String(ranked.name.clone()))
        };
        match found {
            None => default(),
            Some(p) => js::object(vec![
                ("policy", Value::String(p.name)),
                ("by", Value::String(ranked.by)),
                ("holder", Value::String(ranked.holder)),
                ("precedence", ranked.precedence.json()),
                ("mechanisms", js::strings(&p.mechanisms)),
                ("secondFactors", js::strings(&p.second_factors)),
                ("missing", Value::Bool(false)),
            ]),
        }
    }

    /// `namedBy(name)`: the applications and the groups.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn named_by(&self, realm: &str, name: &Value) -> Holders {
        let wanted = js::trim(&js::text(name)).to_lowercase();
        Holders {
            applications: self.ports.applications.naming_policy(realm, APP_REFERENCE, &wanted),
            groups: self
                .ports
                .directory
                .groups_naming_policy(realm, GROUP_REFERENCE, &wanted)
                .unwrap_or_default(),
            people: Vec::new(),
        }
    }

    /// `saveNamed(name, given)`: a named policy created or replaced.
    #[tracing::instrument(level = "debug", skip(self, given))]
    pub fn save_named(&self, realm: &str, name: &Value, given: Option<&Object>) -> Answer {
        let text = js::trim(&js::text(name)).to_lowercase();
        let ok_name = text.len() <= 63
            && selection::is_policy_name(&text)
            && text != DEFAULT_PROFILE;
        if !ok_name {
            return Answer::refused(
                codes::STS_AUTHN_0532,
                vec![format!(
                    "A named authentication policy is named with lower-case letters, digits and \
                     hyphens, at most 63, starting with a letter or digit, and is not \
                     \"{DEFAULT_PROFILE}\" (the realm's own policy); \"{}\" is not one.",
                    js::slice(&js::text(name), 64)
                )],
            );
        }
        let (known_first, known_second) = self.ports.env.authn_vocabularies();
        let mechanisms = list_sent(given.and_then(|g| g.get("mechanisms")));
        let second = list_sent(given.and_then(|g| g.get("secondFactors")));
        let mut problems = Vec::new();
        for one in &mechanisms {
            if !known_first.contains(one) {
                problems.push(format!(
                    "\"{}\" is not a first-factor mechanism; one of {}.",
                    js::slice(one, 40),
                    known_first.join(", ")
                ));
            }
        }
        for one in &second {
            if !known_second.contains(one) {
                problems.push(format!(
                    "\"{}\" is not a second factor; one of {}.",
                    js::slice(one, 40),
                    known_second.join(", ")
                ));
            }
        }
        if !problems.is_empty() {
            return Answer::refused(codes::STS_AUTHN_0533, problems);
        }
        let (precedence, bad) = selection::check_precedence(given, &spec());
        if !bad.is_empty() {
            return Answer::refused(codes::STS_AUTHN_0541, bad);
        }
        if !self.ports.directory.installed(Container::Authn) {
            return common::no_directory(
                codes::STS_AUTHN_0245,
                "an authentication policy",
                "ou=authnPolicies",
            );
        }
        let mut attributes = Object::new();
        attributes.insert(
            "objectClass".into(),
            Value::Array(vec!["top".into(), "stsAuthnPolicy".into()]),
        );
        attributes.insert("stsAuthnPolicyMechanism".into(), js::strings(&mechanisms));
        attributes.insert("stsAuthnPolicySecondFactor".into(), js::strings(&second));
        attributes.insert(PRECEDENCE.into(), Value::String(precedence.to_string()));
        let description = common::description_of(given);
        if !description.is_empty() {
            attributes.insert("description".into(), Value::String(description));
        }
        let outcome = self.ports.directory.write(realm, Container::Authn, &text, &attributes);
        if let Some(refused) = common::write_refusal(&outcome, codes::STS_AUTHN_0246, "policy") {
            return refused;
        }
        let policy = self.named_policy(realm, &Value::String(text.clone()));
        let dn = policy.as_ref().map(|p| p.dn.clone()).unwrap_or_default();
        let message = format!(
            "The authentication policy \"{text}\" is saved{}, precedence {precedence}. Where it \
             is the policy that applies — named by the application (appAuthnPolicy) or by one \
             of the person's groups (stsAuthnPolicy), and the lowest precedence of those named \
             — a sign-in allows {} as a first factor and {} as a second.",
            if policy.is_some() { format!(" at {dn}") } else { String::new() },
            if mechanisms.is_empty() {
                "every mechanism the realm allows".to_string()
            } else {
                mechanisms.join(", ")
            },
            if second.is_empty() {
                "the realm's second factors".to_string()
            } else {
                second.join(", ")
            }
        );
        Answer::of(js::object(vec![
            ("ok", Value::Bool(true)),
            ("policy", policy.map(|p| p.json()).unwrap_or(Value::Null)),
            ("dn", Value::String(dn)),
            ("message", Value::String(message)),
        ]))
    }

    /// `deleteNamed(name)`: refused while an application or a group names
    /// it (STS-AUTHN-0534) and for a name the realm does not hold
    /// (STS-AUTHN-0535).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn delete_named(&self, realm: &str, name: &Value) -> Answer {
        let Some(found) = self.named_policy(realm, name) else {
            return Answer::refused(
                codes::STS_AUTHN_0535,
                vec![format!(
                    "This realm holds no named authentication policy \"{}\".",
                    js::slice(&js::text(name), 64)
                )],
            );
        };
        let holders = self.named_by(realm, &Value::String(found.name.clone()));
        if let Some(held) = selection::delete_problem("authentication policy", &found.name, &holders)
        {
            return Answer::refused(
                codes::STS_AUTHN_0534,
                vec![format!(
                    "{held} Deleting it would leave them allowing no mechanism (appAuthnPolicy on \
                     an application, stsAuthnPolicy on a group)."
                )],
            );
        }
        let removed = self.ports.directory.delete(realm, Container::Authn, &found.name);
        Answer::of(js::object(vec![
            ("ok", Value::Bool(true)),
            ("removed", Value::Bool(removed)),
            ("name", Value::String(found.name.clone())),
            ("dn", Value::String(found.dn.clone())),
            (
                "message",
                Value::String(format!("The authentication policy \"{}\" is deleted.", found.name)),
            ),
        ]))
    }

    /// `act(action, body)`: the two acts beside save and reset.
    #[tracing::instrument(level = "debug", skip(self, body))]
    pub fn act(&self, realm: &str, action: &str, body: Option<&Object>) -> Answer {
        let null = Value::Null;
        let name = body.and_then(|b| b.get("name")).unwrap_or(&null);
        match action {
            "save-named-authn-policy" => self.save_named(realm, name, body),
            "delete-named-authn-policy" => self.delete_named(realm, name),
            _ => Answer::refused(
                codes::STS_ADMIN_0500,
                vec![format!(
                    "\"{}\" is not an act of the authentication policy; its two are \
                     save-named-authn-policy and delete-named-authn-policy.",
                    js::slice(action, 64)
                )],
            ),
        }
    }

    fn check_name(name: &Value) -> Option<String> {
        let given = js::or_empty(Some(name));
        let text = if given.is_empty() { DEFAULT_PROFILE.to_string() } else { given };
        let text = js::trim(&text);
        if text.to_lowercase() != DEFAULT_PROFILE {
            return Some(format!(
                "The realm's authentication policy is \"{DEFAULT_PROFILE}\", and it applies to \
                 everybody in this realm. \"{}\" is not it: a NAMED authentication policy \
                 (#1148) holds only the mechanisms an application naming it allows, and is \
                 saved as one (save-named).",
                js::slice(text, 64)
            ));
        }
        None
    }

    /// `validate(given)`: every row is required, except an unticked
    /// console checkbox.
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
        if problems.is_empty() {
            problems.extend(Self::cross_field_problems(&values));
        }
        (values, problems)
    }

    /// `save(name, given)`: the realm's profile, replaced whole.
    #[tracing::instrument(level = "debug", skip(self, given))]
    pub fn save(&self, realm: &str, name: &Value, given: Option<&Object>) -> Answer {
        if let Some(refused) = Self::check_name(name) {
            return Answer::refused(codes::STS_AUTHN_0242, vec![refused]);
        }
        let (values, problems) = Self::validate(given);
        if !problems.is_empty() {
            return Answer::refused(codes::STS_AUTHN_0243, problems);
        }
        let email_on: Vec<&Field> = FIELDS
            .iter()
            .filter(|f| f.kind == "bool" && f.email && values.get(&f.key).is_some_and(js::truthy))
            .collect();
        if !email_on.is_empty() && !self.ports.env.mail_available(realm) {
            return Answer::refused(
                codes::STS_AUTHN_0244,
                vec![format!(
                    "{} cannot be turned on: this realm cannot send mail. Configure a transport \
                     on Server configuration > Mail (/admin/mail) first.",
                    email_on.iter().map(|f| f.label.clone()).collect::<Vec<_>>().join(", ")
                )],
            );
        }
        if !self.ports.directory.installed(Container::Authn) {
            return common::no_directory(
                codes::STS_AUTHN_0245,
                "an authentication policy",
                "ou=authnPolicies",
            );
        }
        let attributes = common::row_attributes(&["top", "stsAuthnPolicy"], &FIELDS, &values, given);
        let outcome = self.ports.directory.write(realm, Container::Authn, DEFAULT_PROFILE, &attributes);
        if let Some(refused) = common::write_refusal(&outcome, codes::STS_AUTHN_0246, "profile") {
            return refused;
        }
        common::saved(self.read(realm, Some(DEFAULT_PROFILE)))
    }

    /// `reset(name)`: this realm's own entry deleted, so it inherits again.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn reset(&self, realm: &str, name: &Value) -> Answer {
        if let Some(refused) = Self::check_name(name) {
            return Answer::refused(codes::STS_AUTHN_0242, vec![refused]);
        }
        if !self.ports.directory.installed(Container::Authn) {
            return common::removed(false, self.read(realm, Some(DEFAULT_PROFILE)));
        }
        let removed = self.ports.directory.delete(realm, Container::Authn, DEFAULT_PROFILE);
        common::removed(removed, self.read(realm, Some(DEFAULT_PROFILE)))
    }

    /// The reference attributes: on an application and on a group.
    pub const REFERENCES: [(&'static str, &'static str); 2] =
        [("application", APP_REFERENCE), ("group", GROUP_REFERENCE)];
}
