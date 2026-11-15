// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE PASSWORD POLICY (3ac) — a port of `common/password_policy.ts`: what
//! a password here must look like, which of a person's old ones it may not
//! be, how a new one is hashed, and how one is generated.
//!
//! `default` and any number of named policies, each `cn=<name>` under
//! `ou=passwordPolicies` with the built-in defaults standing in for any
//! value absent or unreadable; an application (`appPasswordPolicy`) and a
//! group (`stsPasswordPolicy`) name the one they are held to (#1236), and
//! the lowest precedence wins. NOT inherited from the default realm, unlike
//! most kinds. Enforced in product mode (`mode.verifiesCredentials()`); a
//! GENERATED password meets the profile in both.
//!
//! No composition rules (#1444, ASVS 5.0.0 6.2.5): the three rows stay so
//! the entry's shape does not change, and a save asking for one is refused.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;
use sts_core::errors::codes;
use sts_crypto::secrets::{
    scrypt_owasp_min_p, ARGON2_LIMITS, PASSWORD_HASH_ALGORITHMS, SCRYPT_PASSWORD_LIMITS,
};
use unicode_normalization::UnicodeNormalization;

use super::common::{self, Found, From, Inherit, DEFAULT_PROFILE};
use crate::js::{self, Object};
use crate::ports::{Container, Ports};
use crate::selection::{self, Holders, Reference, SelectionSpec};
use crate::tables::{self, Field};
use crate::Answer;

const NOUN: &str = "password policy";
const APP_REFERENCE: &str = "appPasswordPolicy";
const GROUP_REFERENCE: &str = "stsPasswordPolicy";
const PRECEDENCE: &str = "stsPasswordPrecedence";
const SERVICE_WORDS: [&str; 3] = ["iya-sts", "iyasec", "iya cybersecurity"];
const MIN_CONTEXT_WORD: usize = 4;
const MAX_DRAWS: usize = 1000;
const GENERATOR_EXCLUDES: &str = "\"`";
/// `GENERATOR_POOLS`, in their order: lowercase, uppercase, numbers,
/// symbols.
pub const GENERATOR_POOLS: [&str; 4] = [
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "0123456789",
    "!@#$%^&*()+_-=}{[]|:;\"/?.><,`~",
];

static FIELDS: LazyLock<Vec<Field>> = LazyLock::new(|| {
    tables::fields(
        "policy.password",
        |f| {
            let limit = match f.key.as_str() {
                "argon2Memory" => Some(ARGON2_LIMITS.memory),
                "argon2Iterations" => Some(ARGON2_LIMITS.passes),
                "argon2Parallelism" => Some(ARGON2_LIMITS.parallelism),
                "scryptLogN" => Some(SCRYPT_PASSWORD_LIMITS.log_n),
                "scryptBlockSize" => Some(SCRYPT_PASSWORD_LIMITS.r),
                "scryptParallelism" => Some(SCRYPT_PASSWORD_LIMITS.p),
                _ => None,
            };
            if let Some(l) = limit {
                f.dflt = Value::from(l.dflt);
                f.min = Some(l.min as i64);
                f.max = Some(l.max as i64);
            }
            if f.key == "hashAlgorithm" {
                f.values = PASSWORD_HASH_ALGORITHMS.iter().map(|s| s.to_string()).collect();
            }
        },
        None,
    )
});

static PUNCTUATION: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"[^\p{L}\p{N}]").ok());

/// The password policy, built over the ports.
pub struct PasswordPolicy<'a> {
    ports: Ports<'a>,
}

fn spec() -> SelectionSpec {
    SelectionSpec::new(PRECEDENCE)
}

fn num(values: &Object, key: &str) -> f64 {
    match values.get(key) {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
        Some(v) => selection::js_number(&js::text(v)),
        None => f64::NAN,
    }
}

/// `scryptOwaspMinP(Number(logN))`.
fn min_p(values: &Object) -> f64 {
    let n = num(values, "scryptLogN");
    if n >= 17.0 {
        return 1.0;
    }
    if n.fract() == 0.0 && (13.0..=16.0).contains(&n) {
        return scrypt_owasp_min_p(n as u64) as f64;
    }
    10.0
}

impl<'a> PasswordPolicy<'a> {
    /// The kind over its ports.
    pub fn new(ports: Ports<'a>) -> PasswordPolicy<'a> {
        // A hot path: built per question the API layer asks.
        PasswordPolicy { ports }
    }

    /// The rows (`FIELDS`).
    pub fn fields() -> &'static [Field] {
        // A hot path: read per row of every profile.
        &FIELDS
    }

    /// `DEFAULTS`.
    #[tracing::instrument(level = "debug")]
    pub fn defaults() -> Object {
        common::defaults_of(&FIELDS)
    }

    // `parseField()`: never guesses — `12.5` is not 12, `yes` is not TRUE.
    fn parse(field: &Field, raw: &Value) -> Result<Value, String> {
        let text = common::raw_text(raw);
        match field.kind.as_str() {
            "enum" => {
                if field.values.contains(&text) {
                    Ok(Value::String(text))
                } else {
                    Err(format!(
                        "{} must be one of {}; \"{}\" is not.",
                        field.label,
                        field.values.join(", "),
                        js::slice(&text, 40)
                    ))
                }
            }
            "bool" => common::parse_bool(&text)
                .map(Value::Bool)
                .ok_or_else(|| common::bool_problem(field, &text)),
            _ => common::parse_whole(field, &text),
        }
    }

    // `crossFieldProblems()`: the rules that relate two rows.
    fn cross_field_problems(values: &Object) -> Vec<String> {
        let mut out = Vec::new();
        let generated = num(values, "generatedLength");
        let minimum = num(values, "minLength");
        if generated < minimum {
            out.push(format!(
                "A generated password would be {} characters, which is shorter than the \
                 minimum length of {} — this service would make up passwords its own policy \
                 refuses. Raise the generated length to at least {}.",
                common::number_text(generated),
                common::number_text(minimum),
                common::number_text(minimum)
            ));
        }
        if num(values, "minSymbols") > 0.0
            || values.get("requireUppercase").is_some_and(js::truthy)
            || values.get("requireDigit").is_some_and(js::truthy)
        {
            out.push(
                "A password policy may not require symbols, an uppercase letter or a number. \
                 ASVS 5.0.0 requirement 6.2.5 accepts a password of any composition; set a \
                 longer minimum length instead."
                    .to_string(),
            );
        }
        let need = min_p(values);
        if values.get("hashAlgorithm") == Some(&Value::String("scrypt".into()))
            && num(values, "scryptParallelism") < need
        {
            out.push(format!(
                "scrypt at 2^{} needs a parallelism of at least {}, which is what OWASP's table \
                 lists at r=8; {} is below it.",
                values.get("scryptLogN").map(js::text).unwrap_or_default(),
                common::number_text(need),
                values.get("scryptParallelism").map(js::text).unwrap_or_default()
            ));
        }
        out
    }

    // `raisedToTable()`: a stored scrypt parallelism below OWASP's table is
    // read at the table (the review of #872).
    fn raise_to_table(values: &mut Object) {
        let need = min_p(values);
        if num(values, "scryptParallelism") >= need {
            return;
        }
        let raised = need.min(SCRYPT_PASSWORD_LIMITS.p.max as f64);
        values.insert("scryptParallelism".into(), common::number(raised));
    }

    fn entry(&self, realm: &str, name: &str) -> Found {
        common::entry_for(&self.ports, realm, Container::Password, name, Inherit::Never)
    }

    /// `read(name)`: the profile in force — the stored entry field by
    /// field, the built-in default for anything absent or unreadable.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn read(&self, realm: &str, name: Option<&str>) -> Value {
        let profile = js::trim(name.filter(|n| !n.is_empty()).unwrap_or(DEFAULT_PROFILE))
            .to_lowercase();
        let found = self.entry(realm, &profile);
        let (mut values, sources, mut problems) = common::read_rows(
            &FIELDS,
            &found,
            &Self::defaults(),
            Self::parse,
            |f| common::shown(&f.dflt),
        );
        if found.entry.is_some() {
            Self::raise_to_table(&mut values);
            problems.extend(Self::cross_field_problems(&values));
        }
        let mut header = vec![
            ("name", Value::String(profile.clone())),
            ("stored", Value::Bool(found.entry.is_some())),
            (
                "dn",
                Value::String(found.entry.as_ref().map(|e| e.dn.clone()).unwrap_or_default()),
            ),
            ("description", Value::String(common::description_in(&found))),
            ("sources", Value::Object(sources)),
            ("problems", js::strings(&problems)),
            ("enforced", Value::Bool(self.ports.env.verifies_credentials(realm))),
        ];
        let mut out = common::profile(std::mem::take(&mut header), values);
        if profile != DEFAULT_PROFILE {
            let p = match &found.entry {
                Some(e) => selection::precedence_of(&e.attributes, &spec()).json(),
                None => Value::from(selection::DEFAULT_PRECEDENCE),
            };
            if let Value::Object(o) = &mut out {
                o.insert("precedence".into(), p);
            }
        }
        out
    }

    /// `selectionFor(username, application)`: of the policy the application
    /// names and the policies the person's groups name, the lowest
    /// precedence, else `default`. A dangling reference is dropped
    /// (STS-AUTHN-0539).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn selection_for(&self, realm: &str, username: &str, application: &str) -> String {
        let Some(entries) = self.ports.directory.entries(realm, Container::Password) else {
            return DEFAULT_PROFILE.to_string();
        };
        if selection::named(Some(&entries), &spec()).is_empty() {
            return DEFAULT_PROFILE.to_string();
        }
        let who = js::trim(username);
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
            &common::application_reference(&self.ports, realm, application, APP_REFERENCE),
        )];
        references.extend(selection::group_references(&groups));
        let ranked = selection::rank(Some(&entries), &spec(), &references);
        for m in &ranked.missing {
            tracing::warn!(
                code = codes::STS_AUTHN_0539.as_str(),
                "password policy: the {} \"{}\" names the password policy \"{}\", which this \
                 realm does not hold, so it names nothing: the other references still rank, \
                 and default applies where none remains, until the policy exists or the \
                 reference changes.",
                m.by,
                m.holder,
                m.name
            );
        }
        ranked.name
    }

    /// `profileFor(username, application)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn profile_for(&self, realm: &str, username: &str, application: &str) -> Value {
        let name = self.selection_for(realm, username, application);
        self.read(realm, Some(&name))
    }

    /// `namedBy(name)`: the applications and the groups; no person names a
    /// password policy.
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

    /// `list()`: `default`, then the named by precedence, ties by name.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn list(&self, realm: &str) -> Vec<Value> {
        let entries = self.ports.directory.entries(realm, Container::Password);
        let mut named = selection::named(entries.as_deref(), &spec());
        named.sort_by(|a, b| selection::compare((&a.name, a.precedence), (&b.name, b.precedence)));
        let mut rows = vec![self.read(realm, Some(DEFAULT_PROFILE))];
        rows.extend(named.iter().map(|n| self.read(realm, Some(&n.name))));
        rows
    }

    fn check_name(name: &Value) -> Option<String> {
        let given = match name {
            Value::Null => Value::String(DEFAULT_PROFILE.into()),
            Value::String(s) if s.is_empty() => Value::String(DEFAULT_PROFILE.into()),
            other => other.clone(),
        };
        selection::name_problem(&given, NOUN, true)
    }

    fn which(name: &Value) -> String {
        let text = js::or_empty(Some(name));
        let text = if text.is_empty() { DEFAULT_PROFILE.to_string() } else { text };
        js::trim(&text).to_lowercase()
    }

    /// `validate(given, name)`: every row is required, except an unticked
    /// console checkbox and an optional row, which keeps the value in force
    /// for the profile being saved (#847).
    #[tracing::instrument(level = "debug", skip(self, given))]
    pub fn validate(&self, realm: &str, given: Option<&Object>, which: &str) -> (Object, Vec<String>) {
        let empty = Object::new();
        let body = given.unwrap_or(&empty);
        let mut values = Object::new();
        let mut problems = Vec::new();
        let mut in_force: Option<Value> = None;
        for f in FIELDS.iter() {
            let Some(raw) = common::sent(body, f) else {
                if f.optional {
                    let profile = in_force.get_or_insert_with(|| self.read(realm, Some(which)));
                    if let Some(v) = profile.get(&f.key) {
                        values.insert(f.key.clone(), v.clone());
                    }
                } else {
                    problems.push(common::required_problem(f));
                }
                continue;
            };
            match Self::parse(f, &raw) {
                Ok(v) => {
                    values.insert(f.key.clone(), v);
                }
                Err(p) => problems.push(p),
            }
        }
        if problems.is_empty() {
            problems.extend(Self::cross_field_problems(&values));
        }
        (values, problems)
    }

    /// `save(name, given)`: replaces a profile's entry with every row,
    /// `description` and, for a named policy, `precedence`.
    #[tracing::instrument(level = "debug", skip(self, given))]
    pub fn save(&self, realm: &str, name: &Value, given: Option<&Object>) -> Answer {
        if let Some(refused) = Self::check_name(name) {
            return Answer::refused(codes::STS_AUTHN_0107, vec![refused]);
        }
        let which = Self::which(name);
        let (values, mut problems) = self.validate(realm, given, &which);
        let ranked = (which != DEFAULT_PROFILE).then(|| selection::check_precedence(given, &spec()));
        if let Some((_, p)) = &ranked {
            problems.extend(p.iter().cloned());
        }
        if !problems.is_empty() {
            return Answer::refused(codes::STS_AUTHN_0108, problems);
        }
        if !self.ports.directory.installed(Container::Password) {
            return common::no_directory(
                codes::STS_AUTHN_0109,
                "a password policy",
                "ou=passwordPolicies",
            );
        }
        let mut attributes = Object::new();
        attributes.insert(
            "objectClass".into(),
            Value::Array(vec!["top".into(), "pwdPolicy".into(), "stsPasswordPolicy".into()]),
        );
        attributes.insert("pwdAttribute".into(), Value::String("userPassword".into()));
        let description = common::description_of(given);
        attributes.insert("description".into(), Value::String(description.clone()));
        for f in FIELDS.iter() {
            let v = values.get(&f.key).cloned().unwrap_or(Value::Null);
            attributes.insert(f.attribute.clone(), common::written(f, &v));
        }
        if description.is_empty() {
            attributes.remove("description");
        }
        if let Some((p, _)) = ranked {
            attributes.insert(PRECEDENCE.into(), Value::String(p.to_string()));
        }
        let outcome = self.ports.directory.write(realm, Container::Password, &which, &attributes);
        if let Some(refused) = common::write_refusal(&outcome, codes::STS_AUTHN_0110, "profile") {
            return refused;
        }
        common::saved(self.read(realm, Some(&which)))
    }

    /// `reset(name)`: `default`'s puts the built-in defaults back; a named
    /// policy is removed, refused while an application or a group names it
    /// (STS-AUTHN-0540).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn reset(&self, realm: &str, name: &Value) -> Answer {
        if let Some(refused) = Self::check_name(name) {
            return Answer::refused(codes::STS_AUTHN_0107, vec![refused]);
        }
        let which = Self::which(name);
        if !self.ports.directory.installed(Container::Password) {
            return common::removed(false, self.read(realm, Some(&which)));
        }
        if which != DEFAULT_PROFILE {
            if let Some(held) =
                selection::delete_problem(NOUN, &which, &self.named_by(realm, &which))
            {
                return Answer::refused(codes::STS_AUTHN_0540, vec![held]);
            }
        }
        let removed = self.ports.directory.delete(realm, Container::Password, &which);
        let _ = From::Realm;
        common::removed(removed, self.read(realm, Some(DEFAULT_PROFILE)))
    }

    // `contextWords()`: the service's own names, the realm's id, name and
    // domain labels, and `security.passwordContextWords` (#1505).
    fn context_words(&self, realm: &str) -> Vec<String> {
        let facts = self.ports.env.realm(realm);
        let listed = self.ports.env.setting(realm, "security.passwordContextWords");
        let mut out: Vec<String> = SERVICE_WORDS.iter().map(|s| s.to_string()).collect();
        match &listed {
            Value::Array(items) => out.extend(items.iter().map(js::text)),
            other => out.extend(js::or_empty(Some(other)).split(',').map(String::from)),
        }
        if !facts.id.is_empty() && facts.id != "default" {
            out.push(facts.id.clone());
            out.push(facts.name.clone());
        }
        let labels: Vec<&str> = facts.domain.split('.').collect();
        out.extend(labels[..labels.len().saturating_sub(1)].iter().map(|s| s.to_string()));
        out.into_iter()
            .map(|s| js::trim(&s).to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    fn squash(text: &str, one: char) -> String {
        let lowered: String = text.nfkc().collect::<String>().to_lowercase();
        let mapped: String = lowered
            .chars()
            .map(|c| match c {
                '0' => 'o',
                '1' => one,
                '3' => 'e',
                '4' | '@' => 'a',
                '5' | '$' => 's',
                '7' => 't',
                '!' => 'i',
                other => other,
            })
            .collect();
        match PUNCTUATION.as_ref() {
            Some(r) => r.replace_all(&mapped, "").into_owned(),
            None => mapped,
        }
    }

    fn context_word_in(&self, realm: &str, password: &str) -> String {
        let forms = [Self::squash(password, 'i'), Self::squash(password, 'l')];
        self.context_words(realm)
            .into_iter()
            .find(|w| {
                let key = Self::squash(w, 'i');
                js::length(&key) >= MIN_CONTEXT_WORD && forms.iter().any(|f| f.contains(&key))
            })
            .unwrap_or_default()
    }

    /// `problemsWith(password, profile)`: every rule the password breaks,
    /// whatever the mode; the history rule is the caller's.
    #[tracing::instrument(level = "debug", skip(self, password, profile))]
    pub fn problems_with(&self, realm: &str, password: &str, profile: Option<&Value>) -> Vec<String> {
        let read;
        let rules = match profile {
            Some(p) => p,
            None => {
                read = self.read(realm, Some(DEFAULT_PROFILE));
                &read
            }
        };
        let mut out = Vec::new();
        let length = password.chars().count() as f64;
        let minimum = rules
            .get("minLength")
            .map(|v| match v {
                Value::Number(n) => n.as_f64().unwrap_or(f64::NAN),
                other => selection::js_number(&js::text(other)),
            })
            .unwrap_or(f64::NAN);
        if length < minimum {
            out.push(format!(
                "at least {} characters (it has {})",
                common::number_text(minimum),
                common::number_text(length)
            ));
        }
        let word = self.context_word_in(realm, password);
        if !word.is_empty() {
            out.push(format!(
                "no word this organization or service is known by (it contains \"{word}\")"
            ));
        }
        out
    }

    /// `generate(profile)`: draws until a password satisfies the profile —
    /// every pool present (`strict`), the double quote and the backtick
    /// left out — and refuses (STS-AUTHN-0111) after 1000 draws, which only
    /// a hand-edited profile can cause.
    #[tracing::instrument(level = "debug", skip(self, profile))]
    pub fn generate(&self, realm: &str, profile: Option<&Value>) -> Result<String, Answer> {
        let read;
        let rules = match profile {
            Some(p) => p,
            None => {
                read = self.read(realm, Some(DEFAULT_PROFILE));
                &read
            }
        };
        let n = |k: &str| rules.get(k).and_then(Value::as_f64).unwrap_or(0.0);
        let length = n("generatedLength").max(n("minLength")).max(0.0) as usize;
        let pools: Vec<String> = GENERATOR_POOLS
            .iter()
            .map(|p| p.chars().filter(|c| !GENERATOR_EXCLUDES.contains(*c)).collect())
            .collect();
        let alphabet: String = pools.concat();
        for _ in 0..MAX_DRAWS {
            let Ok(candidate) = sts_crypto::random::random_string(&alphabet, length) else {
                break;
            };
            let strict = pools.iter().all(|p| candidate.chars().any(|c| p.contains(c)));
            if strict && self.problems_with(realm, &candidate, Some(rules)).is_empty() {
                return Ok(candidate);
            }
        }
        tracing::error!(
            code = codes::STS_AUTHN_0111.as_str(),
            "password_policy: {MAX_DRAWS} draws of {length} characters produced no password \
             satisfying the profile. The profile cannot be satisfied by a generated password."
        );
        Err(Answer::refused(
            codes::STS_AUTHN_0111,
            vec![format!(
                "No generated password of {length} characters satisfied the password policy in \
                 {MAX_DRAWS} draws. Raise the generated length or lower the symbol count on \
                 /admin/policies."
            )],
        ))
    }

    /// The reference attributes: on an application and on a group.
    pub const REFERENCES: [(&'static str, &'static str); 2] =
        [("application", APP_REFERENCE), ("group", GROUP_REFERENCE)];
}
