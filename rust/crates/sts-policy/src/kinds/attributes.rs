// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE ATTRIBUTE POLICY (3co) — a port of `common/attribute_policy.ts`:
//! what every person in a realm must hold (#396), and the custom
//! attributes a realm adds to what a person may hold.
//!
//! One row, `requiredAttributes` (`givenName, sn, mail` by default), beside
//! the three always required (`uid`, `cn`, `sn`). `cn=default` follows the
//! default realm's while a realm has none; named profiles (#1241) are named
//! by the person's own `stsAttributePolicy` and by their groups', lowest
//! precedence winning; a dangling reference selects nothing
//! (STS-LDAP-0196), and a named profile something names is not deleted
//! (STS-LDAP-0197) — the people asked as a holder question. Enforced in
//! product mode only (`mode.createsIncompletePeople()`).
//!
//! The custom attribute register, `ou=attributeDefinitions`, is the realm's
//! own and this kind's three acts: define, update (#700) and remove.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;
use sts_core::errors::codes;
use sts_model::domain::{AttributePolicy as Concept, User};

use super::common::{self, Found, From, Inherit, DEFAULT_PROFILE};
use crate::js::{self, Object};
use crate::ports::{Container, Ports};
use crate::selection::{self, Holders, Ranked, Reference, SelectionSpec};
use crate::tables::{self, Field};
use crate::Answer;

const NOUN: &str = "attribute policy";
const REFERENCE: &str = "stsAttributePolicy";
const PRECEDENCE: &str = "stsAttributePolicyPrecedence";
/// Required of every person whatever the profile says.
pub const ALWAYS_REQUIRED: [&str; 3] = ["uid", "cn", "sn"];
/// The syntaxes a custom attribute's values are checked against.
pub const SYNTAXES: [&str; 7] = ["string", "integer", "boolean", "date", "email", "uri", "dn"];
/// The most custom attributes one realm defines.
pub const MAX_DEFINITIONS: usize = 100;

static FIELDS: LazyLock<Vec<Field>> =
    LazyLock::new(|| tables::fields("policy.attributes", |_| {}, None));
static DESCR: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z][A-Za-z0-9-]{0,63}$").ok());

fn descr(name: &str) -> bool {
    DESCR.as_ref().is_some_and(|r| r.is_match(name))
}

fn control(text: &str) -> bool {
    text.chars().any(|c| matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}'))
}

fn spec() -> SelectionSpec {
    SelectionSpec::new(PRECEDENCE)
}

/// Whose profile is asked for: the person, the entry as it will be
/// written, and any group the same write adds.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Subject {
    pub uid: Option<String>,
    pub attributes: Option<Object>,
    pub groups: Vec<String>,
}

/// One custom attribute, as the register answers it.
#[derive(Debug, Clone, PartialEq)]
pub struct Definition {
    pub name: String,
    pub label: String,
    pub syntax: String,
    pub multi: bool,
    pub description: String,
    pub portal_visible: bool,
    pub portal_editable: bool,
    pub dn: String,
}

impl Definition {
    /// As Node's object.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn json(&self) -> Value {
        js::object(vec![
            ("name", Value::String(self.name.clone())),
            ("label", Value::String(self.label.clone())),
            ("syntax", Value::String(self.syntax.clone())),
            ("multi", Value::Bool(self.multi)),
            ("description", Value::String(self.description.clone())),
            ("portalVisible", Value::Bool(self.portal_visible)),
            ("portalEditable", Value::Bool(self.portal_editable)),
            ("dn", Value::String(self.dn.clone())),
        ])
    }
}

// `listOf()`: an array, or text split at commas and line breaks.
fn list_of(raw: &Value) -> Vec<String> {
    let items: Vec<String> = match raw {
        Value::Array(a) => a.iter().map(js::text).collect(),
        Value::Null => Vec::new(),
        other => js::text(other).split([',', '\n']).map(String::from).collect(),
    };
    items.into_iter().map(|s| js::trim(&s).to_string()).filter(|s| !s.is_empty()).collect()
}

// `parseFlag()`: absent is None, a value refused is Some(None).
fn parse_flag(raw: Option<&Value>) -> Option<Option<bool>> {
    let raw = match raw {
        None | Some(Value::Null) => return None,
        Some(Value::Bool(b)) => return Some(Some(*b)),
        Some(Value::Array(a)) => a.last().cloned().unwrap_or(Value::Null),
        Some(v) => v.clone(),
    };
    let text = match &raw {
        Value::Null => "undefined".to_string(),
        v => js::text(v),
    };
    match js::trim(&text).to_lowercase().as_str() {
        "true" | "on" | "1" | "yes" => Some(Some(true)),
        "false" | "off" | "0" | "no" | "" => Some(Some(false)),
        _ => Some(None),
    }
}

/// `concept.<boolean field>`: TRUE or FALSE in any case, else absent.
fn concept_bool(name: &str, at: &Object) -> Option<bool> {
    common::concept_values(Concept::FIELDS, name, at)
        .first()
        .and_then(|v| match v.to_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        })
}

/// The attribute policy, built over the ports.
pub struct AttributePolicy<'a> {
    ports: Ports<'a>,
}

impl<'a> AttributePolicy<'a> {
    /// The kind over its ports.
    pub fn new(ports: Ports<'a>) -> AttributePolicy<'a> {
        // A hot path: built per person written.
        AttributePolicy { ports }
    }

    /// The row.
    pub fn fields() -> &'static [Field] {
        // A hot path: read per profile.
        &FIELDS
    }

    fn label() -> String {
        FIELDS.first().map(|f| f.label.clone()).unwrap_or_default()
    }

    fn entries(&self, realm: &str) -> Option<Vec<crate::ports::PolicyEntry>> {
        self.ports.directory.entries(realm, Container::Attributes)
    }

    // `offeredNames()`: lower-cased name to its spelling; None where the
    // person editor could not be asked.
    fn offered_names(&self, realm: &str) -> Option<Vec<(String, String)>> {
        let mut out: Vec<(String, String)> =
            ALWAYS_REQUIRED.iter().map(|n| (n.to_string(), n.to_string())).collect();
        let rows = self.ports.env.offered_attributes(realm).ok()?;
        for r in rows {
            let key = r.name.to_lowercase();
            match out.iter_mut().find(|(k, _)| *k == key) {
                Some(slot) => slot.1 = r.name.clone(),
                None => out.push((key, r.name.clone())),
            }
        }
        Some(out)
    }

    fn lookup(names: &[(String, String)], one: &str) -> Option<String> {
        let key = one.to_lowercase();
        names.iter().find(|(k, _)| *k == key).map(|(_, v)| v.clone())
    }

    /// `enforced()`: in product mode only.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn enforced(&self, realm: &str) -> bool {
        !self.ports.env.creates_incomplete_people(realm)
    }

    /// `read(name)`: a named profile the realm holds, else `default` — the
    /// realm's own, the default realm's, or the built-in list.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn read(&self, realm: &str, name: &Value) -> Value {
        let folded = js::fold(name);
        let asked = if folded.is_empty() { DEFAULT_PROFILE.to_string() } else { folded };
        let own = if asked != DEFAULT_PROFILE {
            self.entries(realm).and_then(|list| common::entry_in(&list, &asked))
        } else {
            None
        };
        let profile_name = if own.is_some() { asked } else { DEFAULT_PROFILE.to_string() };
        let found = match own {
            Some(e) => Found { entry: Some(e), from: From::Realm },
            None => common::entry_for(
                &self.ports,
                realm,
                Container::Attributes,
                DEFAULT_PROFILE,
                Inherit::Any,
            ),
        };
        let empty = Object::new();
        let at = found.entry.as_ref().map(|e| &e.attributes).unwrap_or(&empty);
        let offered = self.offered_names(realm);
        let mut problems = Vec::new();
        let listed: Vec<String> = if found.entry.is_some() {
            common::concept_values(Concept::FIELDS, "required", at)
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect()
        } else {
            list_of(FIELDS.first().map(|f| &f.dflt).unwrap_or(&Value::Null))
        };
        let dn = found.entry.as_ref().map(|e| e.dn.clone()).unwrap_or_default();
        let mut kept: Vec<String> = Vec::new();
        for one in &listed {
            let canonical = match &offered {
                Some(names) => Self::lookup(names, one),
                None => Some(one.clone()),
            };
            match canonical {
                None => problems.push(format!(
                    "stsAttributeRequired on {dn} names {}, which a person in this realm cannot \
                     be given a value for (a custom attribute removed, or one another realm \
                     defines), so it is not required here.",
                    js::slice(one, 64)
                )),
                Some(c) => {
                    if !kept.contains(&c) {
                        kept.push(c);
                    }
                }
            }
        }
        let mut required: Vec<String> = ALWAYS_REQUIRED.iter().map(|s| s.to_string()).collect();
        for one in &kept {
            if !required.iter().any(|r| r.to_lowercase() == one.to_lowercase()) {
                required.push(one.clone());
            }
        }
        let precedence = if profile_name == DEFAULT_PROFILE {
            Value::from(0)
        } else {
            selection::precedence_of(at, &spec()).json()
        };
        js::object(vec![
            ("name", Value::String(profile_name)),
            ("precedence", precedence),
            ("stored", Value::Bool(found.from == From::Realm)),
            ("inherited", Value::Bool(found.from == From::DefaultRealm)),
            ("from", Value::String(found.from.as_str().into())),
            ("dn", Value::String(dn)),
            (
                "description",
                Value::String(
                    common::concept_values(Concept::FIELDS, "description", at)
                        .into_iter()
                        .find(|s| !s.is_empty())
                        .unwrap_or_default(),
                ),
            ),
            (
                "sources",
                js::object(vec![(
                    "requiredAttributes",
                    Value::String(found.from.source().into()),
                )]),
            ),
            ("problems", js::strings(&problems)),
            ("enforced", Value::Bool(self.enforced(realm))),
            ("requiredAttributes", Value::String(kept.join(", "))),
            ("required", js::strings(&required)),
        ])
    }

    fn sorted_named(&self, realm: &str) -> Vec<selection::NamedPolicy> {
        let mut named = selection::named(self.entries(realm).as_deref(), &spec());
        named.sort_by(|a, b| selection::compare((&a.name, a.precedence), (&b.name, b.precedence)));
        named
    }

    /// `list()`: `default`, then the named by precedence, ties by name.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn list(&self, realm: &str) -> Vec<Value> {
        let named = selection::named(self.entries(realm).as_deref(), &spec());
        let mut rows: Vec<Value> =
            named.iter().map(|n| self.read(realm, &Value::String(n.name.clone()))).collect();
        rows.sort_by(|a, b| {
            let p = |v: &Value| selection::Precedence(
                v.get("precedence").and_then(Value::as_f64).unwrap_or(0.0),
            );
            let n = |v: &Value| v.get("name").and_then(Value::as_str).unwrap_or("").to_string();
            selection::compare((&n(a), p(a)), (&n(b), p(b)))
        });
        let mut out = vec![self.read(realm, &Value::String(DEFAULT_PROFILE.into()))];
        out.extend(rows);
        out
    }

    /// `profileNames()`: `default`, then the named, as a reference may take
    /// them.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn profile_names(&self, realm: &str) -> Vec<String> {
        let mut out = vec![DEFAULT_PROFILE.to_string()];
        out.extend(self.sorted_named(realm).into_iter().map(|n| n.name));
        out
    }

    // `subjectOf()`: the entry as written, its own uid.
    fn subject_of(attributes: Option<&Object>, subject: Option<&Subject>) -> Subject {
        let mut out = subject.cloned().unwrap_or_default();
        if out.attributes.is_none() {
            out.attributes = Some(attributes.cloned().unwrap_or_default());
        }
        if out.uid.is_none() {
            let at = out.attributes.clone().unwrap_or_default();
            out.uid = Some(
                common::concept_values(User::FIELDS, "username", &at)
                    .into_iter()
                    .next()
                    .unwrap_or_default(),
            );
        }
        out
    }

    /// `selectionFor(subject)`: the person's own reference and each of
    /// their groups' — those they are in and those the same write adds.
    #[tracing::instrument(level = "debug", skip(self, subject))]
    pub fn selection_for(&self, realm: &str, subject: Option<&Subject>) -> Ranked {
        let none = Ranked {
            name: DEFAULT_PROFILE.into(),
            by: DEFAULT_PROFILE.into(),
            holder: String::new(),
            precedence: selection::Precedence(0.0),
            missing: Vec::new(),
        };
        let Some(entries) = self.entries(realm) else {
            return none;
        };
        let empty = Subject::default();
        let s = subject.unwrap_or(&empty);
        let uid = js::trim(s.uid.as_deref().unwrap_or("")).to_string();
        let no_attributes = Object::new();
        let own = js::values_of(s.attributes.as_ref().unwrap_or(&no_attributes), REFERENCE)
            .into_iter()
            .next()
            .unwrap_or_default();
        if selection::named(Some(&entries), &spec()).is_empty() && js::fold_str(&own).is_empty() {
            return none;
        }
        let mut groups = if uid.is_empty() {
            Vec::new()
        } else {
            self.ports
                .directory
                .person_group_references(realm, &uid, REFERENCE)
                .unwrap_or_default()
        };
        if !s.groups.is_empty() {
            groups.extend(
                self.ports
                    .directory
                    .group_references(realm, &s.groups, REFERENCE)
                    .unwrap_or_default(),
            );
        }
        let mut references = vec![Reference::new("person", &uid, &own)];
        references.extend(selection::group_references(&groups));
        let ranked = selection::rank(Some(&entries), &spec(), &references);
        for m in &ranked.missing {
            tracing::warn!(
                code = codes::STS_LDAP_0196.as_str(),
                "attribute policy: the {} \"{}\" names the attribute policy \"{}\", which this \
                 realm does not hold; it selects nothing, and {} applies.",
                m.by,
                m.holder,
                m.name,
                if ranked.name == DEFAULT_PROFILE {
                    "`default`".to_string()
                } else {
                    format!("\"{}\"", ranked.name)
                }
            );
        }
        ranked
    }

    /// `profileFor(subject)`.
    #[tracing::instrument(level = "debug", skip(self, subject))]
    pub fn profile_for(&self, realm: &str, subject: Option<&Subject>) -> Value {
        let name = match subject {
            Some(s) => self.selection_for(realm, Some(s)).name,
            None => DEFAULT_PROFILE.into(),
        };
        self.read(realm, &Value::String(name))
    }

    /// `required(subject)`: the whole list in force for the subject.
    #[tracing::instrument(level = "debug", skip(self, subject))]
    pub fn required(&self, realm: &str, subject: Option<&Subject>) -> Vec<String> {
        let resolved = subject.map(|s| Self::subject_of(s.attributes.as_ref(), Some(s)));
        let profile = self.profile_for(realm, resolved.as_ref());
        profile
            .get("required")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(js::text).collect())
            .unwrap_or_else(|| ALWAYS_REQUIRED.iter().map(|s| s.to_string()).collect())
    }

    // `holds()`: a non-empty value of the name, in any case of key.
    fn holds(attributes: &Object, name: &str) -> bool {
        let wanted = name.to_lowercase();
        attributes.iter().any(|(k, v)| {
            if k.to_lowercase() != wanted {
                return false;
            }
            let items: Vec<&Value> = match v {
                Value::Array(a) => a.iter().collect(),
                one => vec![one],
            };
            items
                .iter()
                .any(|one| !one.is_null() && !js::trim(&js::text(one)).is_empty())
        })
    }

    fn whose(profile: &Value) -> String {
        let name = profile.get("name").and_then(Value::as_str).unwrap_or("");
        if name == DEFAULT_PROFILE {
            "This realm's attribute policy requires every person".into()
        } else {
            format!("The attribute policy \"{name}\", which applies to this person, requires them")
        }
    }

    fn required_of(profile: &Value) -> Vec<String> {
        profile
            .get("required")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(js::text).collect())
            .unwrap_or_default()
    }

    /// `createRefusal(attributes, subject)`: a create that would leave a
    /// required attribute empty, in product mode.
    #[tracing::instrument(level = "debug", skip(self, attributes, subject))]
    pub fn create_refusal(&self, realm: &str, attributes: &Object, subject: Option<&Subject>) -> Value {
        if !self.enforced(realm) {
            return Value::Null;
        }
        let s = Self::subject_of(Some(attributes), subject);
        let profile = self.profile_for(realm, Some(&s));
        let required = Self::required_of(&profile);
        let missing: Vec<String> =
            required.iter().filter(|n| !Self::holds(attributes, n)).cloned().collect();
        if missing.is_empty() {
            return Value::Null;
        }
        js::object(vec![
            ("missing", js::strings(&missing)),
            ("policy", profile.get("name").cloned().unwrap_or(Value::Null)),
            (
                "message",
                Value::String(format!(
                    "{} to hold {}, and this one would have no value of {}. Directory > \
                     Policies > Attribute policy sets the list.",
                    Self::whose(&profile),
                    required.join(", "),
                    missing.join(", ")
                )),
            ),
        ])
    }

    /// `editRefusal(before, after, subject)`: an edit that would take a
    /// required value away, in product mode.
    #[tracing::instrument(level = "debug", skip(self, before, after, subject))]
    pub fn edit_refusal(
        &self,
        realm: &str,
        before: &Object,
        after: &Object,
        subject: Option<&Subject>,
    ) -> Value {
        if !self.enforced(realm) {
            return Value::Null;
        }
        let s = Self::subject_of(Some(after), subject);
        let profile = self.profile_for(realm, Some(&s));
        let removed: Vec<String> = Self::required_of(&profile)
            .into_iter()
            .filter(|n| Self::holds(before, n) && !Self::holds(after, n))
            .collect();
        if removed.is_empty() {
            return Value::Null;
        }
        js::object(vec![
            ("removed", js::strings(&removed)),
            ("policy", profile.get("name").cloned().unwrap_or(Value::Null)),
            (
                "message",
                Value::String(format!(
                    "{} to hold {}, so the edit may not leave {} without a value. Set another \
                     value instead.",
                    Self::whose(&profile),
                    removed.join(", "),
                    if removed.len() == 1 { "it" } else { "them" }
                )),
            ),
        ])
    }

    /// `deriveCommonName(attributes)`: a create naming no `cn` is given
    /// `givenName sn`; whether it was.
    #[tracing::instrument(level = "debug", skip(attributes))]
    pub fn derive_common_name(attributes: &mut Object) -> bool {
        let value_of = |at: &Object, name: &str| -> String {
            let held = at.iter().find(|(k, _)| k.to_lowercase() == name).map(|(_, v)| v);
            let items: Vec<&Value> = match held {
                None => Vec::new(),
                Some(Value::Array(a)) => a.iter().collect(),
                Some(one) => vec![one],
            };
            items
                .into_iter()
                .find(|v| !v.is_null() && !js::trim(&js::text(v)).is_empty())
                .map(|v| js::trim(&js::text(v)).to_string())
                .unwrap_or_default()
        };
        if !value_of(attributes, "cn").is_empty() {
            return false;
        }
        let derived = [value_of(attributes, "givenname"), value_of(attributes, "sn")]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        if derived.is_empty() {
            return false;
        }
        attributes.retain(|k, _| k.to_lowercase() != "cn");
        attributes.insert("cn".into(), Value::Array(vec![Value::String(derived)]));
        true
    }

    fn check_name(name: &Value) -> Option<String> {
        let given = match name {
            Value::Null => Value::String(DEFAULT_PROFILE.into()),
            Value::String(s) if s.is_empty() => Value::String(DEFAULT_PROFILE.into()),
            other => other.clone(),
        };
        selection::name_problem(&given, NOUN, true)
    }

    /// `validate(given)`: the list, each name one a person here may be given
    /// a value for.
    #[tracing::instrument(level = "debug", skip(self, given))]
    pub fn validate(&self, realm: &str, given: Option<&Object>) -> (Vec<String>, Vec<String>) {
        let empty = Object::new();
        let body = given.unwrap_or(&empty);
        let mut problems = Vec::new();
        let raw = match body.get("requiredAttributes") {
            Some(v) => v.clone(),
            None if body.get("form") == Some(&Value::String("console".into())) => {
                Value::String(String::new())
            }
            None => {
                problems.push(format!(
                    "`requiredAttributes` ({}) is required. A save replaces the whole profile, so \
                     the list is sent, empty for none beyond uid, cn and sn.",
                    Self::label()
                ));
                return (Vec::new(), problems);
            }
        };
        let offered = self.offered_names(realm).unwrap_or_default();
        let items = list_of(&raw);
        if items.len() > 256 {
            problems.push("At most 256 attributes may be required.".into());
        }
        let mut values = Vec::new();
        let mut unknown = Vec::new();
        for one in &items {
            match Self::lookup(&offered, one) {
                None => unknown.push(js::slice(one, 64)),
                Some(c) => {
                    if !values.contains(&c) {
                        values.push(c);
                    }
                }
            }
        }
        if !unknown.is_empty() {
            problems.push(format!(
                "A person in this realm cannot be given a value for {}, so {} cannot be required. \
                 The attributes the policy may require are the ones on its tab: the inetOrgPerson \
                 schema, the credential catalogue, mail and this realm's custom attributes — \
                 never userPassword, a binary attribute, memberOf or an sts attribute.",
                unknown.join(", "),
                if unknown.len() == 1 { "it" } else { "they" }
            ));
        }
        (values, problems)
    }

    /// `save(name, given)`.
    #[tracing::instrument(level = "debug", skip(self, given))]
    pub fn save(&self, realm: &str, name: &Value, given: Option<&Object>) -> Answer {
        if let Some(refused) = Self::check_name(name) {
            return Answer::refused(codes::STS_LDAP_0165, vec![refused]);
        }
        let folded = js::fold(name);
        let which = if folded.is_empty() { DEFAULT_PROFILE.to_string() } else { folded };
        let (values, mut problems) = self.validate(realm, given);
        let ranked = (which != DEFAULT_PROFILE).then(|| selection::check_precedence(given, &spec()));
        if let Some((_, p)) = &ranked {
            problems.extend(p.iter().cloned());
        }
        if !problems.is_empty() {
            return Answer::refused(codes::STS_LDAP_0166, problems);
        }
        if self.entries(realm).is_none() {
            return common::no_directory(
                codes::STS_LDAP_0167,
                "an attribute policy",
                "ou=attributePolicies",
            );
        }
        let mut attributes = Object::new();
        attributes.insert(
            "objectClass".into(),
            Value::Array(vec!["top".into(), "stsAttributePolicy".into()]),
        );
        let description = common::description_of(given);
        if !description.is_empty() {
            attributes.insert("description".into(), Value::String(description));
        }
        if !values.is_empty() {
            attributes.insert("stsAttributeRequired".into(), js::strings(&values));
        }
        if let Some((p, _)) = ranked {
            attributes.insert(PRECEDENCE.into(), Value::String(p.to_string()));
        }
        let outcome = self.ports.directory.write(realm, Container::Attributes, &which, &attributes);
        if let Some(refused) = common::write_refusal(&outcome, codes::STS_LDAP_0168, "profile") {
            return refused;
        }
        common::saved(self.read(realm, &Value::String(which)))
    }

    /// `namedBy(name)`: the groups (the people are `named_by_people()`'s).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn named_by(&self, realm: &str, name: &Value) -> Holders {
        Holders {
            applications: Vec::new(),
            groups: self
                .ports
                .directory
                .groups_naming_policy(realm, REFERENCE, &js::fold(name))
                .unwrap_or_default(),
            people: Vec::new(),
        }
    }

    /// `namedByAsync(name)`: the groups and the people, and whether the
    /// people's answer is complete.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn named_by_people(&self, realm: &str, name: &Value) -> (Holders, bool) {
        let mut out = self.named_by(realm, name);
        let found = self.ports.directory.people_naming_policy(realm, REFERENCE, &js::fold(name));
        let complete = found.as_ref().is_none_or(|f| f.complete);
        if let Some(f) = found {
            out.people = f.people;
        }
        (out, complete)
    }

    /// `reset(name)`: `default` goes back to inheriting; a named profile is
    /// removed, not while a person or a group names it (STS-LDAP-0197).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn reset(&self, realm: &str, name: &Value) -> Answer {
        if let Some(refused) = Self::check_name(name) {
            return Answer::refused(codes::STS_LDAP_0165, vec![refused]);
        }
        let folded = js::fold(name);
        let which = if folded.is_empty() { DEFAULT_PROFILE.to_string() } else { folded };
        let target = Value::String(which.clone());
        if self.entries(realm).is_none() {
            return common::removed(false, self.read(realm, &target));
        }
        if which == DEFAULT_PROFILE {
            let removed = self.ports.directory.delete(realm, Container::Attributes, DEFAULT_PROFILE);
            return common::removed(removed, self.read(realm, &target));
        }
        let (holders, _) = self.named_by_people(realm, &target);
        if let Some(held) = selection::delete_problem(NOUN, &which, &holders) {
            return Answer::refused(codes::STS_LDAP_0197, vec![held]);
        }
        let removed = self.ports.directory.delete(realm, Container::Attributes, &which);
        common::removed(removed, self.read(realm, &target))
    }

    /// `definitions()`: the realm's custom attributes, by name.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn definitions(&self, realm: &str) -> Vec<Definition> {
        let Some(entries) = self.ports.directory.entries(realm, Container::AttributeDefinitions)
        else {
            return Vec::new();
        };
        let mut rows: Vec<Definition> = entries
            .iter()
            .map(|e| {
                let at = &e.attributes;
                let first = |n: &str| {
                    common::concept_values(Concept::FIELDS, n, at).into_iter().next()
                };
                let syntax = first("syntax")
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "string".into())
                    .to_lowercase();
                let single = match at.get("stsAttributeSingleValued")
                    .or_else(|| at.get("stsattributesinglevalued"))
                {
                    None | Some(Value::Null) => Vec::new(),
                    Some(Value::Array(a)) => a
                        .iter()
                        .map(|v| if v.is_null() { "null".into() } else { js::text(v) })
                        .filter(|s: &String| !s.is_empty())
                        .collect(),
                    Some(v) => vec![js::text(v)].into_iter().filter(|s| !s.is_empty()).collect(),
                };
                let editable = concept_bool("portalEditable", at) == Some(true);
                Definition {
                    name: e.name.clone(),
                    label: first("label").filter(|s| !s.is_empty()).unwrap_or_else(|| e.name.clone()),
                    syntax: if SYNTAXES.contains(&syntax.as_str()) { syntax } else { "string".into() },
                    multi: single.first().cloned().unwrap_or_else(|| "TRUE".into()).to_uppercase()
                        != "TRUE",
                    description: common::concept_values(Concept::FIELDS, "description", at)
                        .into_iter()
                        .find(|s| !s.is_empty())
                        .unwrap_or_default(),
                    portal_visible: concept_bool("portalVisible", at) == Some(true) || editable,
                    portal_editable: editable,
                    dn: e.dn.clone(),
                }
            })
            .filter(|d| descr(&d.name))
            .collect();
        rows.sort_by(|a, b| {
            if a.name.to_lowercase() < b.name.to_lowercase() {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        });
        rows
    }

    /// `definition(name)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn definition(&self, realm: &str, name: &str) -> Option<Definition> {
        let wanted = js::trim(name).to_lowercase();
        self.definitions(realm).into_iter().find(|d| d.name.to_lowercase() == wanted)
    }

    fn label_problem() -> String {
        "A custom attribute needs a label of at most 128 characters with no control character: \
         it is what the pages draw beside the name."
            .into()
    }

    fn description_problem() -> String {
        "A description is at most 1024 characters with no control character.".into()
    }

    fn flags_problem() -> String {
        "portalVisible and portalEditable are each true or false.".into()
    }

    /// `define(body)`: a custom attribute written into the register.
    #[tracing::instrument(level = "debug", skip(self, body))]
    pub fn define(&self, realm: &str, body: Option<&Object>) -> Answer {
        let empty = Object::new();
        let given = body.unwrap_or(&empty);
        let name = js::trim(&js::string_of(given.get("name"))).to_string();
        let mut problems = Vec::new();
        if !descr(&name) {
            problems.push(format!(
                "A custom attribute's name is a letter followed by letters, digits and hyphens, \
                 at most 64 (RFC 4512 section 1.4, a descr); \"{}\" is not one.",
                js::slice(&name, 64)
            ));
        }
        let label = js::trim(&js::string_of(given.get("label"))).to_string();
        if label.is_empty() || js::length(&label) > 128 || control(&label) {
            problems.push(Self::label_problem());
        }
        let syntax_raw = match given.get("syntax") {
            None => "string".to_string(),
            Some(v) => js::string_of(Some(v)),
        };
        let syntax = {
            let s = js::trim(&syntax_raw).to_lowercase();
            if s.is_empty() { "string".to_string() } else { s }
        };
        if !SYNTAXES.contains(&syntax.as_str()) {
            problems.push(format!(
                "\"{}\" is not a syntax here; the syntaxes are {}.",
                js::slice(&syntax, 32),
                SYNTAXES.join(", ")
            ));
        }
        let multi_raw = given.get("multiValued").or_else(|| given.get("values"));
        let multi_text = js::trim(&js::string_of(multi_raw)).to_lowercase();
        let mut multi = false;
        if ["true", "on", "1", "yes", "multiple"].contains(&multi_text.as_str()) {
            multi = true;
        } else if !["false", "off", "0", "no", "single", ""].contains(&multi_text.as_str()) {
            problems.push(format!(
                "Whether a custom attribute holds several values is yes or no (single or \
                 multiple); \"{}\" is neither.",
                js::slice(&multi_text, 32)
            ));
        }
        let description = js::trim(&js::string_of(given.get("description"))).to_string();
        if js::length(&description) > 1024 || control(&description) {
            problems.push(Self::description_problem());
        }
        let visible = parse_flag(given.get("portalVisible"));
        let editable = parse_flag(given.get("portalEditable"));
        if visible == Some(None) || editable == Some(None) {
            problems.push(Self::flags_problem());
        }
        let portal_editable = editable == Some(Some(true));
        let portal_visible = visible == Some(Some(true)) || portal_editable;
        if !problems.is_empty() {
            return Answer::refused(codes::STS_LDAP_0169, problems);
        }
        if self.ports.directory.entries(realm, Container::AttributeDefinitions).is_none() {
            return common::no_directory(
                codes::STS_LDAP_0167,
                "a custom attribute",
                "ou=attributeDefinitions",
            );
        }
        let lower = name.to_lowercase();
        let known = self.ports.directory.known_name(realm, &name);
        let existing = self.definition(realm, &name);
        if lower.starts_with("sts") || lower == "memberof" || !known.is_empty() || existing.is_some() {
            let why = if let Some(e) = &existing {
                format!(
                    "This realm already defines {} ({}). Remove it first to define it again.",
                    e.name, e.dn
                )
            } else if lower.starts_with("sts") {
                "A name beginning \"sts\" is this service's own: its credentials and records are \
                 spelt that way, and a custom attribute under one would be read as one of them."
                    .into()
            } else if lower == "memberof" {
                "memberOf is the directory's record of group membership, which grants the console \
                 roles; it is never an attribute an editor offers."
                    .into()
            } else {
                format!(
                    "The directory already knows {known} (a schema, catalogue or service \
                     attribute), so it cannot be defined again as a custom attribute."
                )
            };
            return Answer::refused(codes::STS_LDAP_0170, vec![why]);
        }
        if self.definitions(realm).len() >= MAX_DEFINITIONS {
            return Answer::refused(
                codes::STS_LDAP_0171,
                vec![format!(
                    "This realm defines its maximum of {MAX_DEFINITIONS} custom attributes."
                )],
            );
        }
        let mut attributes = Object::new();
        attributes.insert(
            "objectClass".into(),
            Value::Array(vec!["top".into(), "stsAttributeDefinition".into()]),
        );
        attributes.insert("stsAttributeLabel".into(), Value::String(label));
        attributes.insert("stsAttributeSyntax".into(), Value::String(syntax));
        let flag = |b: bool| Value::String(if b { "TRUE" } else { "FALSE" }.into());
        attributes.insert("stsAttributeSingleValued".into(), flag(!multi));
        attributes.insert("stsAttributePortalVisible".into(), flag(portal_visible));
        attributes.insert("stsAttributePortalEditable".into(), flag(portal_editable));
        if !description.is_empty() {
            attributes.insert("description".into(), Value::String(description));
        }
        let outcome =
            self.ports.directory.write(realm, Container::AttributeDefinitions, &name, &attributes);
        if let Some(refused) = common::write_refusal(&outcome, codes::STS_LDAP_0168, "definition") {
            return refused;
        }
        let made = self.definition(realm, &name);
        let dn = made.as_ref().map(|d| d.dn.clone()).unwrap_or_default();
        Answer::of(js::object(vec![
            ("ok", Value::Bool(true)),
            ("definition", made.map(|d| d.json()).unwrap_or(Value::Null)),
            (
                "message",
                Value::String(format!(
                    "The custom attribute {name} is defined in this realm at {dn}. It may now be \
                     set on a person and required by this policy."
                )),
            ),
        ]))
    }

    /// `redefine(body)`: a definition's label, description and portal flags
    /// changed in place (#700); the syntax and cardinality are fixed
    /// (STS-LDAP-0208).
    #[tracing::instrument(level = "debug", skip(self, body))]
    pub fn redefine(&self, realm: &str, body: Option<&Object>) -> Answer {
        let empty = Object::new();
        let given = body.unwrap_or(&empty);
        let wanted = js::trim(&js::string_or_empty(given.get("name"))).to_string();
        if self.ports.directory.entries(realm, Container::AttributeDefinitions).is_none() {
            return Answer::refused(
                codes::STS_LDAP_0167,
                vec!["There is no embedded directory in this process, so there is no custom \
                      attribute to change."
                    .into()],
            );
        }
        let Some(found) = self.definition(realm, &wanted) else {
            return Answer::refused(
                codes::STS_LDAP_0206,
                vec![format!(
                    "This realm defines no custom attribute called \"{}\", so there is nothing to \
                     change. Define it instead.",
                    js::slice(&wanted, 64)
                )],
            );
        };
        let mut fixed = Vec::new();
        let syntax = js::string_or_empty(given.get("syntax"));
        if !js::trim(&syntax).is_empty() && js::trim(&syntax).to_lowercase() != found.syntax {
            fixed.push("syntax");
        }
        let multi_raw = given.get("multiValued").or_else(|| given.get("values"));
        let multi_text = js::string_or_empty(multi_raw);
        if !js::trim(&multi_text).is_empty() {
            let text = js::trim(&multi_text).to_lowercase();
            let several = ["true", "on", "1", "yes", "multiple"].contains(&text.as_str());
            let one = ["false", "off", "0", "no", "single"].contains(&text.as_str());
            if (!several && !one) || several != found.multi {
                fixed.push("multiValued");
            }
        }
        if !fixed.is_empty() {
            return Answer::refused(
                codes::STS_LDAP_0208,
                vec![format!(
                    "{}'s {} cannot be changed: the values people already hold were checked \
                     against {}. Remove the attribute and define it again, which is refused \
                     while anybody holds a value.",
                    found.name,
                    fixed.join(" and "),
                    if fixed.len() > 1 { "them" } else { "it" }
                )],
            );
        }
        let mut problems = Vec::new();
        let label = match given.get("label") {
            None | Some(Value::Null) => found.label.clone(),
            Some(v) => js::trim(&js::text(v)).to_string(),
        };
        if label.is_empty() || js::length(&label) > 128 || control(&label) {
            problems.push(Self::label_problem());
        }
        let description = match given.get("description") {
            None | Some(Value::Null) => found.description.clone(),
            Some(v) => js::trim(&js::text(v)).to_string(),
        };
        if js::length(&description) > 1024 || control(&description) {
            problems.push(Self::description_problem());
        }
        let visible = parse_flag(given.get("portalVisible"));
        let editable = parse_flag(given.get("portalEditable"));
        if visible == Some(None) || editable == Some(None) {
            problems.push(Self::flags_problem());
        }
        if !problems.is_empty() {
            return Answer::refused(codes::STS_LDAP_0207, problems);
        }
        let portal_editable = match editable {
            Some(e) => e.unwrap_or(false),
            None => {
                if visible == Some(Some(false)) {
                    false
                } else {
                    found.portal_editable
                }
            }
        };
        let portal_visible = match visible {
            Some(v) => v.unwrap_or(false),
            None => found.portal_visible,
        } || portal_editable;
        let mut attributes = Object::new();
        attributes.insert(
            "objectClass".into(),
            Value::Array(vec!["top".into(), "stsAttributeDefinition".into()]),
        );
        let flag = |b: bool| Value::String(if b { "TRUE" } else { "FALSE" }.into());
        attributes.insert("stsAttributeLabel".into(), Value::String(label));
        attributes.insert("stsAttributeSyntax".into(), Value::String(found.syntax.clone()));
        attributes.insert("stsAttributeSingleValued".into(), flag(!found.multi));
        attributes.insert("stsAttributePortalVisible".into(), flag(portal_visible));
        attributes.insert("stsAttributePortalEditable".into(), flag(portal_editable));
        if !description.is_empty() {
            attributes.insert("description".into(), Value::String(description));
        }
        let outcome = self.ports.directory.write(
            realm,
            Container::AttributeDefinitions,
            &found.name,
            &attributes,
        );
        match outcome {
            crate::ports::WriteOutcome::Written => {}
            crate::ports::WriteOutcome::Refused { .. } => {
                if let Some(r) = common::write_refusal(&outcome, codes::STS_LDAP_0209, "change") {
                    return r;
                }
            }
            crate::ports::WriteOutcome::Full => {
                return Answer::refused(
                    codes::STS_LDAP_0209,
                    vec![format!("The directory would not store the change to {}.", found.name)],
                )
            }
        }
        let made = self.definition(realm, &found.name);
        let dn = made.as_ref().map(|d| d.dn.clone()).unwrap_or_else(|| found.dn.clone());
        Answer::of(js::object(vec![
            ("ok", Value::Bool(true)),
            ("definition", made.map(|d| d.json()).unwrap_or(Value::Null)),
            ("name", Value::String(found.name.clone())),
            ("dn", Value::String(dn)),
            (
                "message",
                Value::String(format!(
                    "The custom attribute {} is changed. Its syntax and whether it holds several \
                     values are as they were.",
                    found.name
                )),
            ),
        ]))
    }

    /// `undefine(name)`: refused while any of the realm's own profiles
    /// requires it (STS-LDAP-0173) or anybody holds a value
    /// (STS-LDAP-0172).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn undefine(&self, realm: &str, name: Option<&Value>) -> Answer {
        let wanted = js::trim(&js::string_or_empty(name)).to_string();
        if self.ports.directory.entries(realm, Container::AttributeDefinitions).is_none() {
            return Answer::refused(
                codes::STS_LDAP_0167,
                vec!["There is no embedded directory in this process, so there is no custom \
                      attribute to remove."
                    .into()],
            );
        }
        let Some(found) = self.definition(realm, &wanted) else {
            return Answer::refused(
                codes::STS_LDAP_0174,
                vec![format!(
                    "This realm defines no custom attribute called \"{}\".",
                    js::slice(&wanted, 64)
                )],
            );
        };
        let requiring: Vec<String> = self
            .list(realm)
            .iter()
            .filter(|p| {
                p.get("stored") == Some(&Value::Bool(true))
                    && Self::required_of(p)
                        .iter()
                        .any(|r| r.to_lowercase() == found.name.to_lowercase())
            })
            .map(|p| p.get("name").map(js::text).unwrap_or_default())
            .collect();
        if !requiring.is_empty() {
            return Answer::refused(
                codes::STS_LDAP_0173,
                vec![format!(
                    "This realm's attribute {}{}. Take it off the required list first.",
                    if requiring.len() == 1 {
                        format!("policy \"{}\" requires ", requiring[0])
                    } else {
                        format!("policies {} require ", requiring.join(", "))
                    },
                    found.name
                )],
            );
        }
        let holders = self.ports.directory.holders(realm, &found.name);
        if holders > 0 {
            let mut refused = Answer::refused(
                codes::STS_LDAP_0172,
                vec![format!(
                    "{holders} {} a value of {}, and a definition removed from under its values \
                     would leave data no door here offers again. Remove the values first.",
                    if holders == 1 { "person holds" } else { "people hold" },
                    found.name
                )],
            );
            if let Value::Object(o) = &mut refused.value {
                o.insert("holders".into(), Value::from(holders));
            }
            return refused;
        }
        let removed =
            self.ports.directory.delete(realm, Container::AttributeDefinitions, &found.name);
        Answer::of(js::object(vec![
            ("ok", Value::Bool(true)),
            ("removed", Value::Bool(removed)),
            ("name", Value::String(found.name.clone())),
            ("dn", Value::String(found.dn.clone())),
            (
                "message",
                Value::String(format!(
                    "The custom attribute {} is no longer defined in this realm.",
                    found.name
                )),
            ),
        ]))
    }

    /// `act(action, body)`: the register's three acts.
    #[tracing::instrument(level = "debug", skip(self, body))]
    pub fn act(&self, realm: &str, action: &str, body: Option<&Object>) -> Answer {
        match action {
            "define-person-attribute" => self.define(realm, body),
            "update-person-attribute" => self.redefine(realm, body),
            "remove-person-attribute" => self.undefine(realm, body.and_then(|b| b.get("name"))),
            _ => Answer::refused(
                codes::STS_ADMIN_0500,
                vec![format!(
                    "\"{}\" is not an act of the attribute policy; its three are \
                     define-person-attribute, update-person-attribute and \
                     remove-person-attribute.",
                    js::slice(action, 64)
                )],
            ),
        }
    }

    /// The reference attributes: on the person and on a group.
    pub const REFERENCES: [(&'static str, &'static str); 2] =
        [("group", REFERENCE), ("person", REFERENCE)];
}
