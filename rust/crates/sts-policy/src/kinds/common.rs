// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What the seven kinds share: not a field, a store or a decision — the
//! kinds stay separate, as rcbj asked of them in Node — but the shape
//! `password_policy.ts` established and every kind copied, each copy with
//! its own small differences in wording. The helpers here are the parts
//! that are word for word the same in every kind that uses them; where a
//! kind's sentence differs, the kind says it itself.

use serde_json::Value;
use sts_core::errors::{codes, ErrorCode};

use crate::js::{self, Object};
use crate::ports::{Container, PolicyEntry, Ports, WriteOutcome, DEFAULT_REALM};
use crate::tables::Field;
use crate::Answer;

/// The name of every kind's own profile.
pub const DEFAULT_PROFILE: &str = "default";

/// Where a profile's entry came from: Node's `from`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum From {
    Realm,
    DefaultRealm,
    BuiltIn,
}

impl From {
    /// As Node writes it.
    pub const fn as_str(self) -> &'static str {
        match self {
            From::Realm => "realm",
            From::DefaultRealm => "default-realm",
            From::BuiltIn => "built-in",
        }
    }

    /// What a field read from it is sourced as.
    pub const fn source(self) -> &'static str {
        match self {
            From::Realm => "directory",
            From::DefaultRealm => "default realm",
            From::BuiltIn => "built-in",
        }
    }
}

/// Which names a realm with no entry of its own inherits from the default
/// realm: the authentication, passkey and attribute policies any name,
/// the service-account, locale and post-login policies `default` alone,
/// the password policy none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inherit {
    Never,
    DefaultOnly,
    Any,
}

/// An entry found, and where.
#[derive(Debug, Clone, PartialEq)]
pub struct Found {
    pub entry: Option<PolicyEntry>,
    pub from: From,
}

/// A kind's `entryIn()`: the entry whose name is `name` in any case.
#[tracing::instrument(level = "debug", skip(list))]
pub fn entry_in(list: &[PolicyEntry], name: &str) -> Option<PolicyEntry> {
    let wanted = name.to_lowercase();
    list.iter().find(|e| e.name.to_lowercase() == wanted).cloned()
}

/// A kind's `entryFor()`: this realm's own entry, then — as the kind
/// allows — the default realm's.
#[tracing::instrument(level = "debug", skip(ports))]
pub fn entry_for(
    ports: &Ports,
    realm: &str,
    container: Container,
    name: &str,
    inherit: Inherit,
) -> Found {
    let Some(own) = ports.directory.entries(realm, container) else {
        return Found { entry: None, from: From::BuiltIn };
    };
    if let Some(e) = entry_in(&own, name) {
        return Found { entry: Some(e), from: From::Realm };
    }
    let may = match inherit {
        Inherit::Never => false,
        Inherit::DefaultOnly => name.to_lowercase() == DEFAULT_PROFILE,
        Inherit::Any => true,
    };
    if !may || realm == DEFAULT_REALM {
        return Found { entry: None, from: From::BuiltIn };
    }
    let inherited = ports
        .directory
        .entries(DEFAULT_REALM, container)
        .and_then(|list| entry_in(&list, name));
    match inherited {
        Some(e) => Found { entry: Some(e), from: From::DefaultRealm },
        None => Found { entry: None, from: From::BuiltIn },
    }
}

/// The kinds' boolean: LDAP's TRUE and FALSE, a form's `on`, JSON's true
/// and false; anything else is a problem rather than a guess.
#[tracing::instrument(level = "debug")]
pub fn parse_bool(text: &str) -> Option<bool> {
    match text.to_lowercase().as_str() {
        "true" | "on" | "1" => Some(true),
        "false" | "off" | "0" | "" => Some(false),
        _ => None,
    }
}

/// The yes-or-no refusal every kind words the same.
#[tracing::instrument(level = "debug")]
pub fn bool_problem(field: &Field, text: &str) -> String {
    format!(
        "{} is a yes-or-no setting, and \"{}\" is neither.",
        field.label,
        js::slice(text, 40)
    )
}

/// `String(field.min)`: `undefined` where the row has none.
#[tracing::instrument(level = "debug")]
pub fn bound(b: Option<i64>) -> String {
    b.map(|n| n.to_string()).unwrap_or_else(|| "undefined".to_string())
}

/// The whole-number parse the password, authentication and service-account
/// policies share: `/^\d+$/`, then the row's bounds.
#[tracing::instrument(level = "debug")]
pub fn parse_whole(field: &Field, text: &str) -> Result<Value, String> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "{} must be a whole number between {} and {}; \"{}\" is not one.",
            field.label,
            bound(field.min),
            bound(field.max),
            js::slice(text, 40)
        ));
    }
    let value: f64 = text.parse().unwrap_or(f64::INFINITY);
    let below = field.min.is_some_and(|m| value < m as f64);
    let above = field.max.is_some_and(|m| value > m as f64);
    if below || above {
        return Err(format!(
            "{} must be between {} and {}; {} is not.",
            field.label,
            bound(field.min),
            bound(field.max),
            number_text(value)
        ));
    }
    Ok(number(value))
}

/// `String(n)` of a number Node computed.
#[tracing::instrument(level = "debug")]
pub fn number_text(n: f64) -> String {
    match serde_json::Number::from_f64(n) {
        Some(num) => js::number_text(&num),
        None if n.is_infinite() => {
            if n > 0.0 { "Infinity".into() } else { "-Infinity".into() }
        }
        None => "NaN".into(),
    }
}

/// A number as Node's JSON writes it: an integer without a point.
#[tracing::instrument(level = "debug")]
pub fn number(n: f64) -> Value {
    if n.fract() == 0.0 && n.abs() < 9.0e15 {
        Value::from(n as i64)
    } else {
        serde_json::Number::from_f64(n).map(Value::Number).unwrap_or(Value::Null)
    }
}

/// The text a body member is parsed from: `String(raw)` of what was sent.
#[tracing::instrument(level = "debug")]
pub fn raw_text(raw: &Value) -> String {
    js::trim(&js::text(raw)).to_string()
}

/// "A save replaces the whole profile": the refusal of a row left out.
#[tracing::instrument(level = "debug")]
pub fn required_problem(field: &Field) -> String {
    format!(
        "`{}` ({}) is required. A save replaces the whole profile, so every field is sent.",
        field.key, field.label
    )
}

/// What an entry's unreadable value is reported as in `problems`.
#[tracing::instrument(level = "debug")]
pub fn unreadable(field: &Field, dn: &str, problem: &str, default_shown: &str) -> String {
    format!(
        "{} on {} is unreadable ({}) and the built-in default of {} is in force instead.",
        field.attribute, dn, problem, default_shown
    )
}

/// `String(value)` of a row's default, as the unreadable sentence shows it.
#[tracing::instrument(level = "debug")]
pub fn shown(value: &Value) -> String {
    js::text(value)
}

/// The value a save body sends for a row, the console's unticked checkbox
/// read as `false` (`body.form === 'console'`).
#[tracing::instrument(level = "debug", skip(body))]
pub fn sent<'a>(body: &'a Object, field: &Field) -> Option<Value> {
    match body.get(&field.key) {
        Some(v) => Some(v.clone()),
        None if field.kind == "bool"
            && body.get("form") == Some(&Value::String("console".into())) =>
        {
            Some(Value::String("false".into()))
        }
        None => None,
    }
}

/// How a row's value is written: TRUE/FALSE for a boolean, `String()`
/// otherwise.
#[tracing::instrument(level = "debug")]
pub fn written(field: &Field, value: &Value) -> Value {
    if field.kind == "bool" {
        let on = js::truthy(value);
        Value::String(if on { "TRUE" } else { "FALSE" }.into())
    } else {
        Value::String(js::text(value))
    }
}

/// `String((given && given.description) || '').slice(0, 1024)`.
#[tracing::instrument(level = "debug", skip(given))]
pub fn description_of(given: Option<&Object>) -> String {
    js::slice(&js::or_empty(given.and_then(|g| g.get("description"))), 1024)
}

/// The answer of a write that did not store: the directory's own refusal
/// of a description (STS-LDAP-0008 for a NUL, STS-LDAP-0211 for an
/// operator code, #1416), or the kind's "at its maximum".
#[tracing::instrument(level = "debug")]
pub fn write_refusal(outcome: &WriteOutcome, full: ErrorCode, what: &str) -> Option<Answer> {
    match outcome {
        WriteOutcome::Written => None,
        WriteOutcome::Refused { nul, errors } => Some(Answer::refused(
            if *nul { codes::STS_LDAP_0008 } else { codes::STS_LDAP_0211 },
            errors.clone(),
        )),
        WriteOutcome::Full => Some(Answer::refused(
            full,
            vec![format!(
                "The directory would not store the {what} — it is at its maximum number of \
                 entries."
            )],
        )),
    }
}

/// A kind's `applicationReference()`: the application's reference
/// attribute, found by what a sign-in names it by — a client_id, else its
/// identifier; '' where nothing is named.
#[tracing::instrument(level = "debug", skip(ports))]
pub fn application_reference(
    ports: &Ports,
    realm: &str,
    application: &str,
    attribute: &str,
) -> String {
    let name = js::trim(application);
    if name.is_empty() {
        return String::new();
    }
    let fields = ports
        .applications
        .by_client_id(realm, name)
        .or_else(|| ports.applications.by_identifier(realm, name));
    match fields.as_ref().and_then(|f| f.get(attribute)) {
        Some(Value::Array(items)) => items.first().map(js::text).unwrap_or_default(),
        Some(Value::Null) | None => String::new(),
        Some(one) => js::text(one),
    }
}

/// The header members every kind's profile carries before its rows.
#[tracing::instrument(level = "debug", skip(found))]
pub fn description_in(found: &Found) -> String {
    match &found.entry {
        Some(e) => js::text(&js::first_value(&e.attributes, "description")),
        None => String::new(),
    }
}

/// A kind's read of its rows from an entry: each row's value, its source,
/// and a problem per unreadable value. `default_shown` words a row's
/// default in the problem sentence.
#[tracing::instrument(level = "debug", skip(fields, parse, default_shown, defaults))]
pub fn read_rows(
    fields: &[Field],
    found: &Found,
    defaults: &Object,
    parse: impl Fn(&Field, &Value) -> Result<Value, String>,
    default_shown: impl Fn(&Field) -> String,
) -> (Object, Object, Vec<String>) {
    let mut values = defaults.clone();
    let mut sources = Object::new();
    let mut problems = Vec::new();
    for f in fields {
        sources.insert(f.key.clone(), Value::String("built-in".into()));
    }
    if let Some(entry) = &found.entry {
        for f in fields {
            let raw = js::first_value(&entry.attributes, &f.attribute);
            if js::is_empty_string(&raw) {
                continue;
            }
            match parse(f, &raw) {
                Err(p) => problems.push(unreadable(f, &entry.dn, &p, &default_shown(f))),
                Ok(v) => {
                    values.insert(f.key.clone(), v);
                    sources.insert(f.key.clone(), Value::String(found.from.source().into()));
                }
            }
        }
    }
    (values, sources, problems)
}

/// Every row's default, by key.
#[tracing::instrument(level = "debug", skip(fields))]
pub fn defaults_of(fields: &[Field]) -> Object {
    let mut out = Object::new();
    for f in fields {
        out.insert(f.key.clone(), f.dflt.clone());
    }
    out
}

/// The names of the realm's named profiles, lower-cased, `default` left
/// out, in the directory's order (`namedProfiles()`).
#[tracing::instrument(level = "debug", skip(entries))]
pub fn named_profiles(entries: Option<&[PolicyEntry]>) -> Vec<String> {
    entries
        .unwrap_or(&[])
        .iter()
        .map(|e| e.name.to_lowercase())
        .filter(|n| !n.is_empty() && n != DEFAULT_PROFILE)
        .collect()
}

/// `list()`'s order for the named: precedence, then `a.name < b.name ? -1
/// : 1` (a sort with no tie, so equal names keep no defined order — they
/// cannot be equal here).
#[tracing::instrument(level = "debug", skip(rows))]
pub fn sort_by_precedence(rows: &mut [Value]) {
    rows.sort_by(|a, b| {
        let pa = a.get("precedence").and_then(Value::as_f64).unwrap_or(0.0);
        let pb = b.get("precedence").and_then(Value::as_f64).unwrap_or(0.0);
        let na = a.get("name").and_then(Value::as_str).unwrap_or("");
        let nb = b.get("name").and_then(Value::as_str).unwrap_or("");
        pa.partial_cmp(&pb)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| na.cmp(nb))
    });
}

/// `{ ok, removed, profile }`.
#[tracing::instrument(level = "debug", skip(profile))]
pub fn removed(removed: bool, profile: Value) -> Answer {
    Answer::of(js::object(vec![
        ("ok", Value::Bool(true)),
        ("removed", Value::Bool(removed)),
        ("profile", profile),
    ]))
}

/// `{ ok: true, profile }`.
#[tracing::instrument(level = "debug", skip(profile))]
pub fn saved(profile: Value) -> Answer {
    Answer::of(js::object(vec![("ok", Value::Bool(true)), ("profile", profile)]))
}

/// The "no embedded directory" refusal every kind words alike.
#[tracing::instrument(level = "debug")]
pub fn no_directory(code: ErrorCode, a_noun: &str, container: &str) -> Answer {
    Answer::refused(
        code,
        vec![format!(
            "There is no embedded directory in this process, so there is nowhere to keep \
             {a_noun}. {container} IS the register."
        )],
    )
}

/// A profile object: its header members, then its rows' values.
#[tracing::instrument(level = "debug", skip(header, values))]
pub fn profile(header: Vec<(&str, Value)>, values: Object) -> Value {
    let mut out = Object::new();
    for (k, v) in header {
        out.insert(k.to_string(), v);
    }
    for (k, v) in values {
        out.insert(k, v);
    }
    Value::Object(out)
}

/// The attributes of a profile's write: its object classes, the
/// description where one is given, each row's value.
#[tracing::instrument(level = "debug", skip(fields, values, given))]
pub fn row_attributes(
    classes: &[&str],
    fields: &[Field],
    values: &Object,
    given: Option<&Object>,
) -> Object {
    let mut out = Object::new();
    out.insert(
        "objectClass".into(),
        Value::Array(classes.iter().map(|c| Value::String((*c).into())).collect()),
    );
    let description = description_of(given);
    out.insert("description".into(), Value::String(description.clone()));
    for f in fields {
        if let Some(v) = values.get(&f.key) {
            out.insert(f.attribute.clone(), written(f, v));
        }
    }
    if description.is_empty() {
        out.remove("description");
    }
    out
}

/// The directory attribute a concept's field is read from, by the field's
/// name in the model (`DomainMap`'s `field.from.attr`): the shapes come
/// from sts-model (D15), so a kind that reads a concept names its field,
/// not an attribute.
#[tracing::instrument(level = "debug", skip(fields))]
pub fn concept_attribute(fields: &[sts_model::FieldSource], name: &str) -> &'static str {
    fields
        .iter()
        .find(|f| f.name == name)
        .and_then(|f| f.attribute)
        .unwrap_or("")
}

/// A concept's string field from an entry, every value (`DomainMap`'s
/// `fromEntry()` of a string field: null values dropped).
#[tracing::instrument(level = "debug", skip(fields, attributes))]
pub fn concept_values(fields: &[sts_model::FieldSource], name: &str, attributes: &Object) -> Vec<String> {
    js::domain_values(attributes, concept_attribute(fields, name))
}
