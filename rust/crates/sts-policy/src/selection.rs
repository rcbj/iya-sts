// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! WHICH NAMED POLICY APPLIES, FOR EVERY POLICY KIND — a port of
//! `common/policy_selection.ts` (#1235, rule 3cx).
//!
//! rcbj's decisions on #1234: what a named policy covers names it — one
//! single-valued reference attribute on the application (`app<Kind>Policy`),
//! the person and the group (`sts<Kind>Policy`) — and a named policy keeps
//! only its rows and its precedence (1 to 1000). The candidates are the
//! policies the references name; THE LOWEST PRECEDENCE WINS, ties by name,
//! and `default` applies where there is none. A reference that is empty or
//! says `default` is no candidate; one naming a policy the realm does not
//! hold is no candidate either and is handed back in `missing`, for the
//! kind to give its meaning (the authentication policy fails closed, the
//! others read their baseline). Matching is trimmed and case-insensitive.
//!
//! It is selection, not authorization, and a leaf: functions over values
//! the caller hands in. Its one piece of state, as in Node, is the register
//! of person and group references a kind declares
//! ([`declare_reference`]), which the person editor and the group writer
//! read to draw a picker per kind and check a write.

use std::sync::{LazyLock, Mutex};

use regex::Regex;
use serde_json::Value;
use sts_core::errors::ErrorCode;

use crate::js::{self, Object};
use crate::ports::{GroupReference, PolicyEntry};

/// The name of the policy every realm has.
pub const DEFAULT_NAME: &str = "default";
/// The lowest precedence a named policy may have.
pub const MIN_PRECEDENCE: i64 = 1;
/// The highest.
pub const MAX_PRECEDENCE: i64 = 1000;
/// Where a named policy ranks when its entry says nothing readable.
pub const DEFAULT_PRECEDENCE: i64 = 100;

static NAME_PATTERN: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9-]{0,63}$").ok());

/// Whether a (folded) name is one a named policy's cn may be:
/// `NAME_PATTERN`.
pub fn is_policy_name(text: &str) -> bool {
    // A hot path: asked of every name a save or a reset is given.
    NAME_PATTERN.as_ref().is_some_and(|r| r.is_match(text))
}

/// How a kind's named policies rank: the attribute holding a policy's
/// precedence, and the kind's default precedence.
#[derive(Debug, Clone, PartialEq)]
pub struct SelectionSpec {
    pub precedence_attribute: String,
    /// `spec.defaultPrecedence`; `None` (or 0, which `||` passes over) is
    /// [`DEFAULT_PRECEDENCE`].
    pub default_precedence: Option<i64>,
}

impl SelectionSpec {
    /// A kind's spec at the shared default precedence.
    pub fn new(attribute: &str) -> SelectionSpec {
        // A hot path: built once per question a kind asks.
        SelectionSpec {
            precedence_attribute: attribute.to_string(),
            default_precedence: Some(DEFAULT_PRECEDENCE),
        }
    }

    fn fallback(&self) -> i64 {
        match self.default_precedence {
            Some(p) if p != 0 => p,
            _ => DEFAULT_PRECEDENCE,
        }
    }
}

/// A precedence as Node holds it: a stored value is `Number()` of its text,
/// so `12.5` ranks as 12.5. Written as an integer wherever it is one.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Precedence(pub f64);

impl Precedence {
    /// The JSON number Node writes for it.
    pub fn json(self) -> Value {
        // A hot path: one per ranked policy.
        if self.0.fract() == 0.0 && self.0.abs() < 9.0e15 {
            Value::from(self.0 as i64)
        } else {
            serde_json::Number::from_f64(self.0)
                .map(Value::Number)
                .unwrap_or(Value::Null)
        }
    }
}

/// What names a policy: `by` is what the caller calls the holder
/// (`application`, `person`, `group`), `holder` which one it is, `value`
/// its reference attribute's value.
#[derive(Debug, Clone, PartialEq)]
pub struct Reference {
    pub by: String,
    pub holder: String,
    pub value: Value,
}

impl Reference {
    /// A reference whose value is text.
    pub fn new(by: &str, holder: &str, value: &str) -> Reference {
        // A hot path: one per reference of every sign-in.
        Reference {
            by: by.to_string(),
            holder: holder.to_string(),
            value: Value::String(value.to_string()),
        }
    }
}

/// One named policy, read.
#[derive(Debug, Clone, PartialEq)]
pub struct NamedPolicy {
    pub name: String,
    pub dn: String,
    pub precedence: Precedence,
}

/// A reference to a name the realm does not hold.
#[derive(Debug, Clone, PartialEq)]
pub struct Missing {
    pub by: String,
    pub holder: String,
    pub name: String,
}

/// What [`rank`] answers: the winner, what named it, its precedence (0 for
/// `default`) and every reference to a name the realm does not hold.
#[derive(Debug, Clone, PartialEq)]
pub struct Ranked {
    pub name: String,
    pub by: String,
    pub holder: String,
    pub precedence: Precedence,
    pub missing: Vec<Missing>,
}

impl Ranked {
    /// The answer as Node's object.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn json(&self) -> Value {
        js::object(vec![
            ("name", Value::String(self.name.clone())),
            ("by", Value::String(self.by.clone())),
            ("holder", Value::String(self.holder.clone())),
            ("precedence", self.precedence.json()),
            (
                "missing",
                Value::Array(
                    self.missing
                        .iter()
                        .map(|m| {
                            js::object(vec![
                                ("by", Value::String(m.by.clone())),
                                ("holder", Value::String(m.holder.clone())),
                                ("name", Value::String(m.name.clone())),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    }
}

/// `Number(text)`: JavaScript's reading of a string as a number — trimmed,
/// '' as 0, decimal, `0x`/`0o`/`0b` integers and `Infinity`; NaN otherwise.
pub fn js_number(text: &str) -> f64 {
    // A hot path: one per stored precedence read.
    let t = js::trim(text);
    if t.is_empty() {
        return 0.0;
    }
    let radix = |p: &str, r: u32| -> f64 {
        u64::from_str_radix(p, r).map(|n| n as f64).unwrap_or(f64::NAN)
    };
    let lower = t.to_ascii_lowercase();
    if let Some(p) = lower.strip_prefix("0x") {
        return radix(p, 16);
    }
    if let Some(p) = lower.strip_prefix("0o") {
        return radix(p, 8);
    }
    if let Some(p) = lower.strip_prefix("0b") {
        return radix(p, 2);
    }
    match t {
        "Infinity" | "+Infinity" => return f64::INFINITY,
        "-Infinity" => return f64::NEG_INFINITY,
        _ => {}
    }
    let ok = t.bytes().all(|b| b.is_ascii_digit() || b"+-.eE".contains(&b))
        && t.bytes().any(|b| b.is_ascii_digit());
    if !ok {
        return f64::NAN;
    }
    t.parse::<f64>().unwrap_or(f64::NAN)
}

/// `PolicySelection.precedenceOf()`: a stored precedence, or the kind's
/// default where it is not a number from 1 to 1000.
pub fn precedence_of(attributes: &Object, spec: &SelectionSpec) -> Precedence {
    // A hot path: Node's own carries no Entering/Leaving pair (`rank()`
    // asks it per named policy on every sign-in).
    let p = js::values_of(attributes, &spec.precedence_attribute)
        .first()
        .map(|s| js_number(s))
        .unwrap_or(f64::NAN);
    if p >= MIN_PRECEDENCE as f64 && p <= MAX_PRECEDENCE as f64 {
        Precedence(p)
    } else {
        Precedence(spec.fallback() as f64)
    }
}

/// `PolicySelection.named()`: a realm's named policies — every entry but
/// `default` — with their precedence, unordered.
#[tracing::instrument(level = "debug", skip(entries))]
pub fn named(entries: Option<&[PolicyEntry]>, spec: &SelectionSpec) -> Vec<NamedPolicy> {
    entries
        .unwrap_or(&[])
        .iter()
        .filter(|e| {
            let n = js::fold_str(&e.name);
            !n.is_empty() && n != DEFAULT_NAME
        })
        .map(|e| NamedPolicy {
            name: js::fold_str(&e.name),
            dn: e.dn.clone(),
            precedence: precedence_of(&e.attributes, spec),
        })
        .collect()
}

/// `PolicySelection.compare()`: the lowest precedence first, ties by name.
pub fn compare(
    a: (&str, Precedence),
    b: (&str, Precedence),
) -> std::cmp::Ordering {
    // A hot path: the sort's comparator.
    a.1 .0
        .partial_cmp(&b.1 .0)
        .unwrap_or(std::cmp::Ordering::Equal)
        .then_with(|| a.0.cmp(b.0))
}

/// `PolicySelection.rank()`: of the policies the references name, the
/// lowest precedence (ties by name), else `default`.
#[tracing::instrument(level = "debug", skip(entries, references))]
pub fn rank(
    entries: Option<&[PolicyEntry]>,
    spec: &SelectionSpec,
    references: &[Reference],
) -> Ranked {
    let held = named(entries, spec);
    let mut missing = Vec::new();
    let mut candidates: Vec<(NamedPolicy, String, String)> = Vec::new();
    for r in references {
        let wanted = js::fold(&r.value);
        if wanted.is_empty() || wanted == DEFAULT_NAME {
            continue;
        }
        // `byName[wanted]`: the LAST entry of a name wins, as an object
        // assigned in order keeps the last.
        match held.iter().rev().find(|p| p.name == wanted) {
            Some(p) => candidates.push((p.clone(), r.by.clone(), r.holder.clone())),
            None => missing.push(Missing {
                by: r.by.clone(),
                holder: r.holder.clone(),
                name: wanted,
            }),
        }
    }
    candidates.sort_by(|a, b| compare((&a.0.name, a.0.precedence), (&b.0.name, b.0.precedence)));
    match candidates.into_iter().next() {
        Some((p, by, holder)) => Ranked {
            name: p.name,
            by,
            holder,
            precedence: p.precedence,
            missing,
        },
        None => Ranked {
            name: DEFAULT_NAME.to_string(),
            by: DEFAULT_NAME.to_string(),
            holder: String::new(),
            precedence: Precedence(0.0),
            missing,
        },
    }
}

/// `PolicySelection.groupReferences()`: one reference per group whose
/// reference names something, `by: 'group'`, `holder` its cn or DN.
#[tracing::instrument(level = "debug", skip(groups))]
pub fn group_references(groups: &[GroupReference]) -> Vec<Reference> {
    groups
        .iter()
        .filter(|g| !js::fold_str(&g.value).is_empty())
        .map(|g| Reference {
            by: "group".to_string(),
            holder: if g.cn.is_empty() { g.dn.clone() } else { g.cn.clone() },
            value: Value::String(g.value.clone()),
        })
        .collect()
}

/// What one holder's reference comes to on its own
/// (`PolicySelection.forReference()`).
#[derive(Debug, Clone, PartialEq)]
pub struct ForReference {
    pub named: String,
    pub missing: bool,
    pub applies: String,
    pub precedence: Precedence,
}

/// `PolicySelection.forReference()`: the application page's answer.
#[tracing::instrument(level = "debug", skip(entries))]
pub fn for_reference(
    entries: Option<&[PolicyEntry]>,
    spec: &SelectionSpec,
    value: &Value,
) -> ForReference {
    let ranked = rank(
        entries,
        spec,
        &[Reference {
            by: "reference".to_string(),
            holder: String::new(),
            value: value.clone(),
        }],
    );
    let named = js::fold(value);
    ForReference {
        named: if named.is_empty() { DEFAULT_NAME.to_string() } else { named },
        missing: !ranked.missing.is_empty(),
        applies: ranked.name,
        precedence: ranked.precedence,
    }
}

/// `PolicySelection.nameProblem()`: `default` is the realm's own, and a cn
/// is lower-case letters, digits and hyphens, at most 64.
#[tracing::instrument(level = "debug")]
pub fn name_problem(name: &Value, noun: &str, allow_default: bool) -> Option<String> {
    let text = js::fold(name);
    if text == DEFAULT_NAME {
        return if allow_default {
            None
        } else {
            Some(format!(
                "A named {noun} cannot be called \"{DEFAULT_NAME}\": that is the realm's own."
            ))
        };
    }
    if !is_policy_name(&text) {
        return Some(format!(
            "A {noun} is \"{DEFAULT_NAME}\" or a name of lower-case letters, digits and \
             hyphens, at most 64; \"{}\" is neither.",
            js::slice(&js::text(name), 64)
        ));
    }
    None
}

/// `PolicySelection.checkPrecedence()`: a whole number from 1 to 1000, the
/// kind's default when omitted.
#[tracing::instrument(level = "debug", skip(given))]
pub fn check_precedence(given: Option<&Object>, spec: &SelectionSpec) -> (i64, Vec<String>) {
    let fallback = spec.fallback();
    let raw = given.and_then(|b| b.get("precedence"));
    let shown = match raw {
        None | Some(Value::Null) => fallback.to_string(),
        Some(Value::String(s)) if s.is_empty() => fallback.to_string(),
        Some(v) => js::text(v),
    };
    let text = js::trim(&shown).to_string();
    match js::digits(&text, 4) {
        Some(n) if (MIN_PRECEDENCE..=MAX_PRECEDENCE).contains(&n) => (n, Vec::new()),
        _ => (
            fallback,
            vec![format!(
                "The precedence of a named policy is a whole number from {MIN_PRECEDENCE} to \
                 {MAX_PRECEDENCE}; \"{}\" is not.",
                js::slice(&text, 40)
            )],
        ),
    }
}

/// `PolicySelection.referenceProblem()`: the write-time check every
/// holder's door makes; '' clears and is always allowed.
#[tracing::instrument(level = "debug")]
pub fn reference_problem(value: &Value, choices: Option<&[String]>, attribute: &str) -> Option<String> {
    let text = js::fold(value);
    let list = choices.unwrap_or(&[]);
    if text.is_empty() || list.iter().any(|c| js::fold_str(c) == text) {
        return None;
    }
    Some(format!(
        "The value for {attribute} is \"{DEFAULT_NAME}\" or a named policy of this realm ({}); \
         \"{}\" is neither.",
        list.join(", "),
        js::slice(&js::text(value), 80)
    ))
}

/// What names a policy: `{ applications, groups, people }`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Holders {
    pub applications: Vec<String>,
    pub groups: Vec<String>,
    pub people: Vec<String>,
}

impl Holders {
    /// As Node's object.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn json(&self) -> Value {
        js::object(vec![
            ("applications", js::strings(&self.applications)),
            ("groups", js::strings(&self.groups)),
            ("people", js::strings(&self.people)),
        ])
    }
}

/// `PolicySelection.deleteProblem()`: the refusal of a named policy's
/// delete while something still names it.
#[tracing::instrument(level = "debug")]
pub fn delete_problem(noun: &str, name: &str, holders: &Holders) -> Option<String> {
    let shown = |list: &[String]| -> String {
        let mut s = list.iter().take(10).cloned().collect::<Vec<_>>().join(", ");
        if list.len() > 10 {
            s.push_str(&format!(" and {} more", list.len() - 10));
        }
        s
    };
    let parts: Vec<String> = [
        ("the application(s) ", &holders.applications),
        ("the group(s) ", &holders.groups),
        ("the person or people ", &holders.people),
    ]
    .iter()
    .filter(|(_, l)| !l.is_empty())
    .map(|(w, l)| format!("{w}{}", shown(l)))
    .collect();
    if parts.is_empty() {
        return None;
    }
    Some(format!(
        "The {noun} \"{name}\" is still named by {}. Point them at another policy, or at \
         `default`, first.",
        parts.join(" and ")
    ))
}

/// Who may hold a declared reference (#1240): handed the holder's
/// attributes and the value written; a coded refusal or `None`.
pub type HolderRefusal = Box<dyn Fn(&Object, &str) -> Option<(ErrorCode, String)> + Send + Sync>;

/// Answers a declared reference's choices when asked.
pub type Choices = Box<dyn Fn() -> Vec<String> + Send + Sync>;

struct Declared {
    holder: String,
    attribute: String,
    noun: String,
    choices: Choices,
    holder_refusal: Option<HolderRefusal>,
}

static DECLARED: LazyLock<Mutex<Vec<Declared>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// A reference a kind declared, with its choices now.
#[derive(Debug, Clone, PartialEq)]
pub struct DeclaredReference {
    pub attribute: String,
    pub noun: String,
    pub choices: Vec<String>,
    pub has_holder_refusal: bool,
}

/// The holders a reference may be declared on.
const HOLDERS: [&str; 2] = ["person", "group"];

/// `PolicySelection.declareReference()`: a kind's single-valued attribute
/// on a person's or a group's entry; a second declaration of the holder and
/// attribute replaces the first. Refused for another holder, in Node's
/// sentence.
#[tracing::instrument(level = "debug", skip(choices, holder_refusal))]
pub fn declare_reference(
    holder: &str,
    attribute: &str,
    noun: &str,
    choices: Choices,
    holder_refusal: Option<HolderRefusal>,
) -> Result<(), String> {
    if !HOLDERS.contains(&holder) {
        return Err(format!(
            "policy_selection: a reference is declared on a person or a group, not \"{holder}\"."
        ));
    }
    withdraw_reference(holder, attribute);
    if let Ok(mut all) = DECLARED.lock() {
        all.push(Declared {
            holder: holder.to_string(),
            attribute: attribute.to_string(),
            noun: noun.to_string(),
            choices,
            holder_refusal,
        });
    }
    Ok(())
}

/// `PolicySelection.withdrawReference()`.
#[tracing::instrument(level = "debug")]
pub fn withdraw_reference(holder: &str, attribute: &str) {
    let key = attribute.to_lowercase();
    if let Ok(mut all) = DECLARED.lock() {
        all.retain(|d| !(d.holder == holder && d.attribute.to_lowercase() == key));
    }
}

/// `PolicySelection.referenceOf()`: `default` first, then the realm's
/// named policies, each once.
#[tracing::instrument(level = "debug")]
pub fn reference_of(holder: &str, attribute: &str) -> Option<DeclaredReference> {
    let key = attribute.to_lowercase();
    let all = DECLARED.lock().ok()?;
    let found = all
        .iter()
        .find(|d| d.holder == holder && d.attribute.to_lowercase() == key)?;
    let names: Vec<String> = (found.choices)().iter().map(|c| js::fold_str(c)).collect();
    let mut choices = vec![DEFAULT_NAME.to_string()];
    for (n, one) in names.iter().enumerate() {
        if !one.is_empty() && one != DEFAULT_NAME && names.iter().position(|x| x == one) == Some(n) {
            choices.push(one.clone());
        }
    }
    Some(DeclaredReference {
        attribute: found.attribute.clone(),
        noun: found.noun.clone(),
        choices,
        has_holder_refusal: found.holder_refusal.is_some(),
    })
}

/// A declared reference's holder refusal, asked of a holder's attributes.
#[tracing::instrument(level = "debug", skip(attributes))]
pub fn holder_refusal(
    holder: &str,
    attribute: &str,
    attributes: &Object,
    value: &str,
) -> Option<(ErrorCode, String)> {
    let key = attribute.to_lowercase();
    let all = DECLARED.lock().ok()?;
    let found = all
        .iter()
        .find(|d| d.holder == holder && d.attribute.to_lowercase() == key)?;
    found.holder_refusal.as_ref().and_then(|f| f(attributes, value))
}

/// `PolicySelection.referencesOn()`: every reference declared on a holder,
/// in declaration order.
#[tracing::instrument(level = "debug")]
pub fn references_on(holder: &str) -> Vec<DeclaredReference> {
    let attributes: Vec<String> = match DECLARED.lock() {
        Ok(all) => all
            .iter()
            .filter(|d| d.holder == holder)
            .map(|d| d.attribute.clone())
            .collect(),
        Err(_) => Vec::new(),
    };
    attributes
        .iter()
        .filter_map(|a| reference_of(holder, a))
        .collect()
}
