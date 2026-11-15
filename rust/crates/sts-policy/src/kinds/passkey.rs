// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE PASSKEY POLICY (3ch) — a port of the profile half of
//! `common/passkey_policy.ts`: how passkeys behave in a realm (#527) —
//! usernameless sign-in, what a security key is asked to store, hints, PIN
//! length, attestation, the post-quantum requirement and the registration
//! rows (#718, #940), recovery assurance (#724) — and its named profiles
//! (#535, #1235), named by an application (`appPasskeyPolicy`) or a group
//! (`stsPasskeyPolicy`).
//!
//! `default` is inherited from the default realm while a realm has none; a
//! reference to a profile the realm does not hold selects nothing
//! (STS-AUTHN-0537) — the default profile is never weaker than nothing. A
//! save is refused where its rows contradict one another (STS-AUTHN-0430,
//! -0431, -0476), where it requires a post-quantum passkey the realm offers
//! no ML-DSA for (STS-AUTHN-0357), or a bound session the realm does not
//! offer (STS-AUTHN-0461). An optional row a save leaves out keeps what the
//! realm's own entry stored (#907).
//!
//! NOT HERE: the ceremonies' questions (`question()`, `refusalFor()` and
//! the getters a ceremony reads), which belong with the WebAuthn port, and
//! the learned clients' register (`common/passkey_clients.ts`), which this
//! kind's two acts reach through the environment port.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;
use sts_core::errors::{codes, ErrorCode};

use super::common::{self, Inherit, DEFAULT_PROFILE};
use crate::js::{self, Object};
use crate::ports::{Container, Ports, RegistrationRows};
use crate::selection::{self, Holders, Reference, SelectionSpec};
use crate::tables::{self, Field};
use crate::Answer;

const APP_REFERENCE: &str = "appPasskeyPolicy";
const GROUP_REFERENCE: &str = "stsPasskeyPolicy";
const PRECEDENCE: &str = "stsPasskeyPrecedence";
const MAX_CLIENT_RULES: usize = 20;
const NO_HINTS: &str = "none";
const REALM_LIST: &str = "realm";
const HINTS: [&str; 3] = ["security-key", "client-device", "hybrid"];
const POST_QUANTUM_ALGORITHMS: [&str; 3] = ["ML-DSA-87", "ML-DSA-65", "ML-DSA-44"];
const POST_QUANTUM_REQUIRED_VALUES: [&str; 3] = ["off", "sign-in", "registration-and-sign-in"];
const REGISTRATION_MODES: [&str; 4] = ["realm", "pq-only", "pq-first", "classical-only"];
const LANES_VALUES: [&str; 3] = ["realm", "both", "one"];

fn hint_attachment(hint: &str) -> Option<&'static str> {
    match hint {
        "security-key" | "hybrid" => Some("cross-platform"),
        "client-device" => Some("platform"),
        _ => None,
    }
}

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// `REGISTRATION_ALGORITHM_VALUES` (#940): `webauthn.algorithms`' own
/// values, less RS1, from the settings row so the two cannot drift.
static REGISTRATION_ALGORITHM_VALUES: LazyLock<Vec<String>> = LazyLock::new(|| {
    let from_row = sts_core::settings::row("webauthn.algorithms").and_then(|r| r.csv_values);
    match from_row {
        Some(values) => values.iter().filter(|v| **v != "RS1").map(|v| v.to_string()).collect(),
        None => strings(&["ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "ES256", "RS256"]),
    }
});

static FIELDS: LazyLock<Vec<Field>> = LazyLock::new(|| {
    tables::fields(
        "policy.passkey",
        |f| match f.key.as_str() {
            "securityKeyResidentKey" => f.values = strings(&["discouraged", "preferred", "required"]),
            "backupEligibility" => f.values = strings(&["allow", "disallow"]),
            "minPinLength" => {
                f.dflt = Value::from(4);
                f.min = Some(4);
                f.max = Some(63);
            }
            "postQuantumRequired" => f.values = strings(&POST_QUANTUM_REQUIRED_VALUES),
            "postQuantumAllowCredentials" => {
                f.values = strings(&["realm", "narrow", "list-and-refuse"])
            }
            "registrationAlgorithms" => {
                f.values = REGISTRATION_ALGORITHM_VALUES.clone();
                f.dflt = Value::String(REALM_LIST.into());
                f.empty = Some(REALM_LIST.into());
                f.max_items = Some(REGISTRATION_ALGORITHM_VALUES.len());
            }
            "registrationMode" => f.values = strings(&REGISTRATION_MODES),
            "lanes" => f.values = strings(&LANES_VALUES),
            "passkeyHints" | "securityKeyHints" => f.values = strings(&HINTS),
            "signInHints" => {
                f.values = strings(&HINTS);
                f.dflt = Value::String(NO_HINTS.into());
            }
            "rpNameExtras" => {
                f.values = strings(&["none", "realm", "organisation", "realm-and-organisation"])
            }
            "recoveryAssurance" => f.values = strings(&["any", "not-weaker", "operator-only"]),
            "attestationAlgorithms" => {
                f.values = strings(&[
                    "post-quantum",
                    "ml-dsa-44",
                    "ml-dsa-65",
                    "ml-dsa-87",
                    "slh-dsa",
                    "composite-ml-dsa",
                ]);
                f.dflt = Value::String(NO_HINTS.into());
            }
            "adminEnrolment" => f.values = strings(&["off", "on"]),
            _ => {}
        },
        None,
    )
});

fn re(pattern: &str) -> Option<Regex> {
    Regex::new(pattern).ok()
}

static DESCR: LazyLock<Option<Regex>> = LazyLock::new(|| re(r"^[A-Za-z][A-Za-z0-9-]{0,63}$"));
static RULE_SIDES: LazyLock<Option<Regex>> = LazyLock::new(|| re(r"(?i)^(.+?) on (.+)$"));
static SIDE: LazyLock<Option<Regex>> =
    LazyLock::new(|| re(r"^(.*?) ([0-9]{1,4})?(?:(-)([0-9]{1,4})?)?$"));
static FAMILY: LazyLock<Option<Regex>> = LazyLock::new(|| re(r"^[A-Za-z][A-Za-z0-9 .-]{0,31}$"));
static CONTROLS: LazyLock<Option<Regex>> = LazyLock::new(|| {
    re("[\u{0}-\u{1f}\u{7f}-\u{9f}\u{61c}\u{200e}\u{200f}\u{202a}-\u{202e}\u{2066}-\u{2069}]")
});

fn matches(r: &LazyLock<Option<Regex>>, text: &str) -> bool {
    r.as_ref().is_some_and(|r| r.is_match(text))
}

/// `text.replace(/\s+/g, ' ')`.
fn collapse(text: &str) -> String {
    let mut out = String::new();
    let mut space = false;
    for c in text.chars() {
        if js::is_js_space(c) {
            if !space {
                out.push(' ');
            }
            space = true;
        } else {
            out.push(c);
            space = false;
        }
    }
    out
}

fn split_space(text: &str) -> Vec<String> {
    text.split(js::is_js_space).filter(|s| !s.is_empty()).map(String::from).collect()
}

/// `PasskeyPolicy.displaySafe()` (#533): no control or bidirectional-
/// formatting characters, whitespace collapsed and trimmed, at most `max`
/// code points.
#[tracing::instrument(level = "debug")]
pub fn display_safe(value: &str, max: usize) -> String {
    let once = collapse(value);
    let stripped = match CONTROLS.as_ref() {
        Some(r) => r.replace_all(&once, "").into_owned(),
        None => once,
    };
    let again = collapse(&stripped);
    let kept: String = js::trim(&again).chars().take(max).collect();
    js::trim(&kept).to_string()
}

/// One side of a client rule (#1112), parsed.
#[derive(Debug, Clone, PartialEq)]
pub struct ClientRuleSide {
    pub family: String,
    pub low: Option<u32>,
    pub high: Option<u32>,
    pub ranged: bool,
    pub text: String,
}

fn client_side(raw: &str) -> Option<ClientRuleSide> {
    let text = js::trim(raw).to_string();
    let caps = SIDE.as_ref().and_then(|r| r.captures(&text));
    let g = |n: usize| caps.as_ref().and_then(|c| c.get(n)).map(|m| m.as_str().to_string());
    let has_range = caps.is_some() && (g(2).is_some() || g(4).is_some());
    let family = if has_range { js::trim(&g(1).unwrap_or_default()).to_string() } else { text.clone() };
    if !(family == "*" || matches(&FAMILY, &family)) {
        return None;
    }
    let num = |s: Option<String>| s.and_then(|v| v.parse::<u32>().ok());
    let low = if has_range { num(g(2)) } else { None };
    let dash = g(3).is_some();
    let high = if has_range {
        if dash { num(g(4)) } else { low }
    } else {
        None
    };
    if let (Some(l), Some(h)) = (low, high) {
        if l > h {
            return None;
        }
    }
    let show = |n: Option<u32>| n.map(|v| v.to_string()).unwrap_or_default();
    let range = if !has_range {
        String::new()
    } else if low.is_some() && high.is_some() && low == high && !dash {
        show(low)
    } else {
        format!("{}-{}", show(low), show(high))
    };
    Some(ClientRuleSide {
        text: if range.is_empty() { family.clone() } else { format!("{family} {range}") },
        family,
        low,
        high,
        ranged: has_range,
    })
}

/// `PasskeyPolicy.parseClientRules()` (#1112): the rules and their
/// canonical text, or the problem with the first bad rule.
#[tracing::instrument(level = "debug")]
pub fn parse_client_rules(raw: &str) -> Result<(Vec<(ClientRuleSide, ClientRuleSide)>, String), String> {
    let items: Vec<String> = raw
        .split(';')
        .map(|one| collapse(js::trim(one)))
        .filter(|s| !s.is_empty())
        .collect();
    if items.len() > MAX_CLIENT_RULES {
        return Err(format!(
            "at most {MAX_CLIENT_RULES} rules, and there are {}.",
            items.len()
        ));
    }
    let mut rules = Vec::new();
    for item in &items {
        let sides = RULE_SIDES.as_ref().and_then(|r| r.captures(item));
        let pair = sides.and_then(|c| {
            let b = client_side(c.get(1)?.as_str())?;
            let s = client_side(c.get(2)?.as_str())?;
            Some((b, s))
        });
        match pair {
            Some(p) => rules.push(p),
            None => {
                return Err(format!(
                    "\"{}\" is not `<browser> on <system>`, each a family or `*` and an \
                     optional major-version range such as `130-140`.",
                    js::slice(item, 60)
                ))
            }
        }
    }
    let text = rules
        .iter()
        .map(|(b, s)| format!("{} on {}", b.text, s.text))
        .collect::<Vec<_>>()
        .join("; ");
    Ok((rules, text))
}

/// `PasskeyPolicy.listOf()`: a stored hint list as an array.
#[tracing::instrument(level = "debug")]
pub fn hint_list(value: &Value) -> Vec<String> {
    let text = js::text(value);
    if text == NO_HINTS {
        return Vec::new();
    }
    text.split(',').filter(|h| HINTS.contains(h)).map(String::from).collect()
}

/// `PasskeyPolicy.isPostQuantum()`.
#[tracing::instrument(level = "debug")]
pub fn is_post_quantum(algorithm: &str) -> bool {
    POST_QUANTUM_ALGORITHMS.contains(&algorithm)
}

fn spec() -> SelectionSpec {
    SelectionSpec::new(PRECEDENCE)
}

/// The passkey policy, built over the ports.
pub struct PasskeyPolicy<'a> {
    ports: Ports<'a>,
}

impl<'a> PasskeyPolicy<'a> {
    /// The kind over its ports.
    pub fn new(ports: Ports<'a>) -> PasskeyPolicy<'a> {
        // A hot path: built per ceremony.
        PasskeyPolicy { ports }
    }

    /// The rows.
    pub fn fields() -> &'static [Field] {
        // A hot path: read per row of every profile.
        &FIELDS
    }

    /// `DEFAULTS`, with `recoveryAssurance`'s mode-dependent default
    /// (#724): `any` where the mode recovers weaker than passkeys.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn defaults(&self, realm: &str) -> Object {
        let mut out = common::defaults_of(&FIELDS);
        if out.contains_key("recoveryAssurance") {
            let weaker = self.ports.env.recovers_weaker_than_passkeys(realm);
            out.insert(
                "recoveryAssurance".into(),
                Value::String(if weaker { "any" } else { "not-weaker" }.into()),
            );
        }
        out
    }

    fn field(key: &str) -> Field {
        FIELDS.iter().find(|f| f.key == key).cloned().unwrap_or_default()
    }

    fn parse(field: &Field, raw: &Value) -> Result<Value, String> {
        let text = common::raw_text(raw);
        match field.kind.as_str() {
            "attributes" => {
                let items: Vec<Vec<String>> = if text.is_empty() {
                    Vec::new()
                } else {
                    text.split(',').map(|one| split_space(js::trim(one))).collect()
                };
                let bad = items.len() > 6
                    || items.iter().any(|g| {
                        g.is_empty() || g.len() > 3 || g.iter().any(|n| !matches(&DESCR, n))
                    });
                if bad {
                    return Err(format!(
                        "{} must be up to six attribute names or space-separated groups of up to \
                         three, separated by commas; \"{}\" is not.",
                        field.label,
                        js::slice(&text, 60)
                    ));
                }
                Ok(Value::String(
                    items.iter().map(|g| g.join(" ")).collect::<Vec<_>>().join(", "),
                ))
            }
            "clientRules" => match parse_client_rules(&text) {
                Ok((_, canonical)) => Ok(Value::String(canonical)),
                Err(p) => Err(format!("{}: {}", field.label, p)),
            },
            "text" => {
                let kept = display_safe(&text, 60);
                if kept != collapse(&text) {
                    return Err(format!(
                        "{} may hold no control or direction-changing characters and at most 60 \
                         characters.",
                        field.label
                    ));
                }
                Ok(Value::String(kept))
            }
            "attribute" => {
                if !text.is_empty() && !matches(&DESCR, &text) {
                    return Err(format!(
                        "{} must be an attribute name — a letter, then letters, digits and \
                         hyphens — or empty; \"{}\" is not.",
                        field.label,
                        js::slice(&text, 60)
                    ));
                }
                Ok(Value::String(text))
            }
            "list" => {
                let empty = field.empty.clone().unwrap_or_else(|| NO_HINTS.into());
                let items: Vec<String> = if text.to_lowercase() == empty {
                    Vec::new()
                } else {
                    text.split(|c: char| c == ',' || js::is_js_space(c))
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect()
                };
                let unknown = items.iter().any(|i| !field.values.contains(i));
                let twice = items.iter().enumerate().any(|(n, i)| items.iter().position(|x| x == i) != Some(n));
                if unknown || twice || items.len() > field.max_items.unwrap_or(8) {
                    return Err(format!(
                        "{} must be \"{}\" or a list of {}, each once; \"{}\" is not.",
                        field.label,
                        empty,
                        field.values.join(", "),
                        js::slice(&text, 60)
                    ));
                }
                Ok(Value::String(if items.is_empty() { empty } else { items.join(",") }))
            }
            "int" => match js::digits(&text, 6) {
                Some(n)
                    if field.min.is_some_and(|m| n >= m) && field.max.is_some_and(|m| n <= m) =>
                {
                    Ok(Value::from(n))
                }
                _ => Err(format!(
                    "{} must be a whole number between {} and {}; \"{}\" is not.",
                    field.label,
                    common::bound(field.min),
                    common::bound(field.max),
                    js::slice(&text, 40)
                )),
            },
            "bool" => common::parse_bool(&text)
                .map(Value::Bool)
                .ok_or_else(|| common::bool_problem(field, &text)),
            _ => {
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
        }
    }

    fn holds(&self, realm: &str, name: &str) -> bool {
        self.ports
            .directory
            .entries(realm, Container::Passkey)
            .is_some_and(|list| common::entry_in(&list, name).is_some())
    }

    /// `read(name)`: no name is the selected profile, `default` outside a
    /// selection; a named profile the realm does not hold is `default`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn read(&self, realm: &str, name: Option<&str>) -> Value {
        let asked = name.filter(|n| !n.is_empty()).unwrap_or(DEFAULT_PROFILE).to_lowercase();
        let profile = if asked != DEFAULT_PROFILE && !self.holds(realm, &asked) {
            DEFAULT_PROFILE.to_string()
        } else {
            asked
        };
        let found = common::entry_for(&self.ports, realm, Container::Passkey, &profile, Inherit::Any);
        let defaults = self.defaults(realm);
        let shown_defaults = defaults.clone();
        let (values, sources, problems) = common::read_rows(
            &FIELDS,
            &found,
            &defaults,
            Self::parse,
            |f| shown_defaults.get(&f.key).map(js::text).unwrap_or_else(|| "undefined".into()),
        );
        let empty = Object::new();
        let at = found.entry.as_ref().map(|e| &e.attributes).unwrap_or(&empty);
        let precedence = if profile == DEFAULT_PROFILE {
            Value::from(0)
        } else {
            selection::precedence_of(at, &spec()).json()
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

    /// `list()`: `default`, then the named by precedence, ties by name.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn list(&self, realm: &str) -> Vec<Value> {
        let entries = self.ports.directory.entries(realm, Container::Passkey);
        let mut named: Vec<Value> = common::named_profiles(entries.as_deref())
            .iter()
            .map(|n| self.read(realm, Some(n)))
            .collect();
        common::sort_by_precedence(&mut named);
        let mut rows = vec![self.read(realm, Some(DEFAULT_PROFILE))];
        rows.extend(named);
        rows
    }

    /// `selectionFor(username, application)`: a dangling reference selects
    /// nothing (STS-AUTHN-0537).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn selection_for(&self, realm: &str, username: &str, application: &str) -> String {
        let Some(entries) = self.ports.directory.entries(realm, Container::Passkey) else {
            return DEFAULT_PROFILE.to_string();
        };
        if selection::named(Some(&entries), &spec()).is_empty() {
            return DEFAULT_PROFILE.to_string();
        }
        let groups = if username.is_empty() {
            Vec::new()
        } else {
            self.ports
                .directory
                .person_group_references(realm, username, GROUP_REFERENCE)
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
                code = codes::STS_AUTHN_0537.as_str(),
                "passkey policy: the {} \"{}\" names the passkey policy \"{}\", which this realm \
                 does not hold; it selects nothing until the policy exists or the reference \
                 changes.",
                m.by,
                m.holder,
                m.name
            );
        }
        ranked.name
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

    /// `forApplication(reference)`: the application page's answer, and how
    /// many named profiles a group names.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn for_application(&self, realm: &str, reference: &Value) -> Value {
        let entries = self.ports.directory.entries(realm, Container::Passkey).unwrap_or_default();
        let out = selection::for_reference(Some(&entries), &spec(), reference);
        let group_policies = selection::named(Some(&entries), &spec())
            .iter()
            .filter(|p| !self.named_by(realm, &p.name).groups.is_empty())
            .count();
        js::object(vec![
            ("named", Value::String(out.named)),
            ("missing", Value::Bool(out.missing)),
            ("applies", Value::String(out.applies)),
            ("precedence", out.precedence.json()),
            ("groupPolicies", Value::from(group_policies)),
        ])
    }

    /// `registrationRows(profile)` (#940).
    #[tracing::instrument(level = "debug", skip(values))]
    pub fn registration_rows(values: &Object) -> RegistrationRows {
        let text = match values.get("registrationAlgorithms") {
            None | Some(Value::Null) => REALM_LIST.to_string(),
            Some(v) => js::text(v),
        };
        let algorithms = if text == REALM_LIST {
            Vec::new()
        } else {
            text.split(',')
                .filter(|a| REGISTRATION_ALGORITHM_VALUES.iter().any(|v| v == a))
                .map(String::from)
                .collect()
        };
        let mode = js::or_empty(values.get("registrationMode"));
        let pick = |v: Option<&Value>, list: &[&str], fallback: &str| {
            let t = v.map(js::text).unwrap_or_else(|| "undefined".into());
            if list.contains(&t.as_str()) { t } else { fallback.to_string() }
        };
        RegistrationRows {
            registration_algorithms: algorithms,
            registration_mode: if REGISTRATION_MODES.contains(&mode.as_str()) {
                mode
            } else {
                "realm".into()
            },
            post_quantum_required: pick(
                values.get("postQuantumRequired"),
                &POST_QUANTUM_REQUIRED_VALUES,
                "off",
            ),
            lanes: pick(values.get("lanes"), &LANES_VALUES, "realm"),
        }
    }

    fn attachment_for(&self, realm: &str, kind: &str) -> String {
        let setting = js::or_empty(Some(&self.ports.env.setting(realm, "webauthn.authenticatorAttachment")));
        let setting = if setting.is_empty() { "any".to_string() } else { setting };
        if setting != "any" {
            setting
        } else if kind == "security-key" {
            "cross-platform".into()
        } else {
            String::new()
        }
    }

    fn hint_problems(&self, realm: &str, values: &Object) -> Vec<String> {
        let mut out = Vec::new();
        for (key, kind) in [("passkeyHints", "passkey"), ("securityKeyHints", "security-key")] {
            let list = hint_list(values.get(key).unwrap_or(&Value::Null));
            let attachment = self.attachment_for(realm, kind);
            if attachment.is_empty() {
                continue;
            }
            let bad: Vec<String> = list
                .into_iter()
                .filter(|h| hint_attachment(h).is_some_and(|a| a != attachment))
                .collect();
            if !bad.is_empty() {
                out.push(format!(
                    "{}: {} contradicts the authenticatorAttachment that request sends ({}); {}.",
                    Self::field(key).label,
                    bad.join(", "),
                    attachment,
                    bad.iter()
                        .map(|h| format!("{h} implies {}", hint_attachment(h).unwrap_or("")))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
        out
    }

    /// `validate(given)`: an optional row left out keeps the default here
    /// (and the stored value at the write, #907).
    #[tracing::instrument(level = "debug", skip(self, given))]
    pub fn validate(&self, realm: &str, given: Option<&Object>) -> (Object, Vec<String>) {
        let empty = Object::new();
        let body = given.unwrap_or(&empty);
        let mut values = Object::new();
        let mut problems = Vec::new();
        for f in FIELDS.iter() {
            match common::sent(body, f) {
                None if f.optional => {}
                None => problems.push(common::required_problem(f)),
                Some(raw) => match Self::parse(f, &raw) {
                    Ok(v) => {
                        values.insert(f.key.clone(), v);
                    }
                    Err(p) => problems.push(p),
                },
            }
        }
        if values.get("requireUsernameless") == Some(&Value::Bool(true))
            && values.get("allowUsernameless") == Some(&Value::Bool(false))
        {
            problems.push(format!(
                "`requireUsernameless` ({}) needs `allowUsernameless` on: a sign-in screen with \
                 no username field signs in only with a passkey that names its own account.",
                Self::field("requireUsernameless").label
            ));
        }
        problems.extend(self.hint_problems(realm, &values));
        (values, problems)
    }

    // `standingValues()`: the profile as the save will leave it.
    fn standing(&self, realm: &str, which: &str, values: &Object) -> Object {
        let mut out = self.defaults(realm);
        let own = self
            .ports
            .directory
            .entries(realm, Container::Passkey)
            .and_then(|list| list.into_iter().find(|e| e.name.to_lowercase() == which));
        for f in FIELDS.iter() {
            if let Some(v) = values.get(&f.key) {
                out.insert(f.key.clone(), v.clone());
                continue;
            }
            let Some(own) = own.as_ref().filter(|_| f.optional) else {
                continue;
            };
            let raw = js::first_value(&own.attributes, &f.attribute);
            if js::is_empty_string(&raw) {
                continue;
            }
            if let Ok(v) = Self::parse(f, &raw) {
                out.insert(f.key.clone(), v);
            }
        }
        out
    }

    // `registrationContradiction()` (#940).
    fn contradiction(&self, realm: &str, values: &Object) -> Option<(ErrorCode, String)> {
        let rows = Self::registration_rows(values);
        let mode = rows.registration_mode.clone();
        let label = |k: &str| Self::field(k).label;
        let mode_label = format!("`registrationMode` ({}) is {}", label("registrationMode"), mode);
        if mode == "classical-only" && rows.post_quantum_required != "off" {
            return Some((
                codes::STS_AUTHN_0430,
                format!(
                    "{mode_label}, and `postQuantumRequired` ({}) is {}: a classical passkey can \
                     never satisfy that requirement, so this profile's people could register \
                     nothing that signs them in. Set one of the two differently.",
                    label("postQuantumRequired"),
                    rows.post_quantum_required
                ),
            ));
        }
        if mode == "classical-only" && rows.lanes == "both" {
            return Some((
                codes::STS_AUTHN_0476,
                format!(
                    "{mode_label}, and `lanes` ({}) is both: a classical-only population makes no \
                     post-quantum passkey, so there is no second lane to hold one in. Set one of \
                     the two differently.",
                    label("lanes")
                ),
            ));
        }
        let attested = {
            let t = js::or_empty(values.get("attestationAlgorithms"));
            if t.is_empty() { NO_HINTS.to_string() } else { t }
        };
        if mode == "classical-only" && attested != NO_HINTS {
            return Some((
                codes::STS_AUTHN_0430,
                format!(
                    "{mode_label}, and `attestationAlgorithms` ({}) is {attested}: that list \
                     admits only an authenticator attesting with a post-quantum signature, which \
                     is not the device a classical-only population holds. Set \
                     attestationAlgorithms to none, or choose another mode.",
                    label("attestationAlgorithms")
                ),
            ));
        }
        if mode == "pq-only" || mode == "pq-first" {
            let list: Vec<String> = if !rows.registration_algorithms.is_empty() {
                rows.registration_algorithms.clone()
            } else {
                match self.ports.env.setting(realm, "webauthn.algorithms") {
                    Value::Array(items) => {
                        items.iter().map(|v| js::trim(&js::text(v)).to_string()).collect()
                    }
                    other => js::or_empty(Some(&other))
                        .split(',')
                        .map(|s| js::trim(s).to_string())
                        .collect(),
                }
            };
            if !list.iter().any(|a| is_post_quantum(a)) {
                let shown: Vec<&String> = list.iter().filter(|s| !s.is_empty()).collect();
                return Some((
                    codes::STS_AUTHN_0431,
                    format!(
                        "{mode_label}, and the algorithms this profile would offer ({}: {}) name \
                         no ML-DSA algorithm, so the mode would ask for what the list never \
                         offers. Add ML-DSA-44, ML-DSA-65 or ML-DSA-87 to the list.",
                        if rows.registration_algorithms.is_empty() {
                            "the realm's webauthn.algorithms"
                        } else {
                            "its registrationAlgorithms"
                        },
                        if shown.is_empty() {
                            "nothing".to_string()
                        } else {
                            shown.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                        }
                    ),
                ));
            }
        }
        None
    }

    fn check_name(name: &Value) -> Option<String> {
        let given = js::or_empty(Some(name));
        let text = if given.is_empty() { DEFAULT_PROFILE.to_string() } else { given };
        let text = js::trim(&text);
        if text != DEFAULT_PROFILE && !selection::is_policy_name(text) {
            return Some(format!(
                "A passkey policy profile is \"{DEFAULT_PROFILE}\" or a name of lower-case \
                 letters, digits and hyphens, at most 64; \"{}\" is neither.",
                js::slice(text, 64)
            ));
        }
        None
    }

    /// `save(name, given)`.
    #[tracing::instrument(level = "debug", skip(self, given))]
    pub fn save(&self, realm: &str, name: &Value, given: Option<&Object>) -> Answer {
        if let Some(refused) = Self::check_name(name) {
            return Answer::refused(codes::STS_AUTHN_0308, vec![refused]);
        }
        let which = super::locale::which(name);
        let (values, mut problems) = self.validate(realm, given);
        let ranked = (which != DEFAULT_PROFILE).then(|| selection::check_precedence(given, &spec()));
        if let Some((_, p)) = &ranked {
            problems.extend(p.iter().cloned());
        }
        if !problems.is_empty() {
            return Answer::refused(codes::STS_AUTHN_0309, problems);
        }
        let standing = self.standing(realm, &which, &values);
        if let Some((code, problem)) = self.contradiction(realm, &standing) {
            return Answer::refused(code, vec![problem]);
        }
        let required = standing.get("postQuantumRequired").map(js::text).unwrap_or_default();
        if required != "off"
            && !self.ports.env.offers_post_quantum(realm, &Self::registration_rows(&standing))
        {
            return Answer::refused(
                codes::STS_AUTHN_0357,
                vec![format!(
                    "`postQuantumRequired` ({}) is {}, and this realm offers no ML-DSA algorithm \
                     at registration (webauthn.algorithms names none, and neither \
                     webauthn.pqcOnly nor webauthn.pqcAlongsideClassical is on), so no passkey \
                     anybody could register would satisfy it. Offer ML-DSA first.",
                    Self::field("postQuantumRequired").label,
                    values.get("postQuantumRequired").map(js::text).unwrap_or_else(|| "undefined".into())
                )],
            );
        }
        if standing.get("deviceBoundRequired") == Some(&Value::Bool(true))
            && self.ports.env.setting(realm, "authn.deviceBoundSessions") != Value::Bool(true)
        {
            return Answer::refused(
                codes::STS_AUTHN_0461,
                vec![format!(
                    "`deviceBoundRequired` ({}) is on, and authn.deviceBoundSessions is off, so \
                     no session could meet it. Turn device-bound sessions on first.",
                    Self::field("deviceBoundRequired").label
                )],
            );
        }
        let Some(entries) = self.ports.directory.entries(realm, Container::Passkey) else {
            return common::no_directory(codes::STS_AUTHN_0310, "a passkey policy", "ou=passkeyPolicies");
        };
        let own = entries.into_iter().find(|e| e.name.to_lowercase() == which);
        let mut attributes = Object::new();
        attributes.insert(
            "objectClass".into(),
            Value::Array(vec!["top".into(), "stsPasskeyPolicy".into()]),
        );
        let description = common::description_of(given);
        attributes.insert("description".into(), Value::String(description.clone()));
        for f in FIELDS.iter() {
            match values.get(&f.key) {
                None if f.optional => {
                    let kept = own.as_ref().and_then(|e| js::member(&e.attributes, &f.attribute));
                    if let Some(kept) = kept {
                        attributes.insert(f.attribute.clone(), kept.clone());
                    }
                }
                v => {
                    attributes.insert(
                        f.attribute.clone(),
                        common::written(f, v.unwrap_or(&Value::Null)),
                    );
                }
            }
        }
        if description.is_empty() {
            attributes.remove("description");
        }
        if let Some((p, _)) = ranked {
            attributes.insert(PRECEDENCE.into(), Value::String(p.to_string()));
        }
        let outcome = self.ports.directory.write(realm, Container::Passkey, &which, &attributes);
        if let Some(refused) = common::write_refusal(&outcome, codes::STS_AUTHN_0311, "profile") {
            return refused;
        }
        common::saved(self.read(realm, Some(&which)))
    }

    /// `reset(name)`: refused while an application or a group names a named
    /// profile (STS-AUTHN-0538).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn reset(&self, realm: &str, name: &Value) -> Answer {
        if let Some(refused) = Self::check_name(name) {
            return Answer::refused(codes::STS_AUTHN_0308, vec![refused]);
        }
        let which = super::locale::which(name);
        if !self.ports.directory.installed(Container::Passkey) {
            return common::removed(false, self.read(realm, Some(&which)));
        }
        if which != DEFAULT_PROFILE {
            if let Some(held) =
                selection::delete_problem("passkey policy", &which, &self.named_by(realm, &which))
            {
                return Answer::refused(codes::STS_AUTHN_0538, vec![held]);
            }
        }
        let removed = self.ports.directory.delete(realm, Container::Passkey, &which);
        common::removed(removed, self.read(realm, Some(&which)))
    }

    /// `act(action, body)`: the learned clients' clears (#1112).
    #[tracing::instrument(level = "debug", skip(self, body))]
    pub fn act(&self, realm: &str, action: &str, body: Option<&Object>) -> Answer {
        let empty = Object::new();
        self.ports.env.passkey_clients_act(realm, action, body.unwrap_or(&empty))
    }

    /// The reference attributes: on an application and on a group.
    pub const REFERENCES: [(&'static str, &'static str); 2] =
        [("application", APP_REFERENCE), ("group", GROUP_REFERENCE)];
}
