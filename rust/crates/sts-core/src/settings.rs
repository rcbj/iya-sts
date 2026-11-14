// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Every setting this service has, one row each, and the five layers a value
//! comes from. A port of `common/config.js` (rust/DESIGN.md section 4.4);
//! that file's comments argue each rule, and the ones that matter to a
//! reader of this one are repeated where they bite.
//!
//! **The table is ONE table.** Until the cutover it is `config.js`'s
//! `SETTINGS`, exported to `tables/settings.json` and compiled in by
//! `build.rs` — a constant per key in [`keys`], so a setting read by a name
//! the table does not have does not compile (Node throws `no such setting`
//! at the first read).
//!
//! **The layers, highest first**: the ambient trust realm's override, the
//! process's runtime override, the environment (then a row's legacy
//! variable), the operator's appconfig file, and the defaults. A
//! `realmOnly` row skips the three process layers — a value the process was
//! given would otherwise be every realm's — and a `perProcess` row, like the
//! `realms.*` ones, skips the realm layer. A DERIVED default is a function:
//! four are of other settings and the rest of the mode
//! (`strongerInProduct()`, #1491), all computed here
//! ([`Settings::derived`]).
//!
//! **A raw value is a JSON value**: a string from the environment or a form,
//! anything from the appconfig file. Every type coerces from either, exactly
//! as `config.js`'s `TYPES` do — including JavaScript's `parseInt()` and
//! `String()` — because the console's refusals and the values a deployment
//! already carries are the contract.

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

use serde_json::Value as Json;

use crate::errors::{codes, ErrorCode};

/// A setting's name. Made only by the generated constants in [`keys`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key(&'static str);

impl Key {
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl AsRef<str> for Key {
    fn as_ref(&self) -> &str {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingType {
    String,
    Int,
    Port,
    Bool,
    Csv,
    Enum,
    /// A colour (#717): `#rgb` or `#rrggbb`, read as lower-case `#rrggbb`.
    Color,
}

impl SettingType {
    pub fn as_str(self) -> &'static str {
        match self {
            SettingType::String => "string",
            SettingType::Int => "int",
            SettingType::Port => "port",
            SettingType::Bool => "bool",
            SettingType::Csv => "csv",
            SettingType::Enum => "enum",
            SettingType::Color => "color",
        }
    }
}

/// A row's `dflt`. `Derived` is a function: one of the four of other
/// settings, or a row's [`ByMode`] pair.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DefaultValue {
    Text(&'static str),
    Int(i64),
    Bool(bool),
    List(&'static [&'static str]),
    Derived,
}

impl DefaultValue {
    fn raw(self) -> Json {
        match self {
            DefaultValue::Text(text) => Json::from(text),
            DefaultValue::Int(n) => Json::from(n),
            DefaultValue::Bool(b) => Json::from(b),
            DefaultValue::List(list) => Json::from(list.to_vec()),
            DefaultValue::Derived => Json::Null,
        }
    }

    /// JavaScript's `!!dflt`, which is what an unreadable boolean falls back
    /// to — a derived default is a function, and a function is truthy.
    fn truthy(self) -> bool {
        match self {
            DefaultValue::Text(text) => !text.is_empty(),
            DefaultValue::Int(n) => n != 0,
            DefaultValue::Bool(b) => b,
            DefaultValue::List(_) | DefaultValue::Derived => true,
        }
    }
}

/// One row of the table, as `config.js` declares it.
#[derive(Debug)]
pub struct SettingRow {
    pub key: &'static str,
    pub group: &'static str,
    pub label: &'static str,
    pub env: Option<&'static str>,
    pub legacy_env: Option<&'static str>,
    pub kind: SettingType,
    pub default: DefaultValue,
    pub runtime: bool,
    pub restart_reason: &'static str,
    pub description: &'static str,
    pub min: Option<i64>,
    pub max: Option<i64>,
    pub step: Option<i64>,
    pub realm_runtime: bool,
    pub realm_only: bool,
    pub enum_values: &'static [&'static str],
    pub csv_values: Option<&'static [&'static str]>,
    pub csv_value_notes: &'static [(&'static str, &'static str)],
    pub ordered: bool,
    pub derived: bool,
    pub per_process: bool,
    pub path: Option<&'static str>,
    pub secret: bool,
    pub only_while: Option<&'static str>,
    pub only_while_values: Option<&'static [&'static str]>,
    /// `onlyWhileValuesUnless` (#1456): more values the mode marks, unless
    /// the named boolean setting is on.
    pub only_while_values_unless: Option<ValuesUnless>,
    /// `maxLength` (#717): a string row's bound, in UTF-16 code units as
    /// JavaScript counts a string's length.
    pub max_length: Option<i64>,
    /// `absoluteUri` (2026-11-12): a caller's write must be RFC 3986's
    /// scheme, a colon and at least one more character, with no space or
    /// control character.
    pub absolute_uri: bool,
    /// `selectAll` (#1130): what an ordered row's Select all ticks.
    pub select_all: Option<SelectAll>,
    /// A `strongerInProduct(product, development)` default (#1491).
    pub by_mode: Option<ByMode>,
}

/// `strongerInProduct()`'s two values: the default in a product realm and
/// in a development one, resolved when read, in the ambient realm's mode.
#[derive(Debug, Clone, Copy)]
pub struct ByMode {
    pub product: DefaultValue,
    pub development: DefaultValue,
}

/// `onlyWhileValuesUnless`: `values` are marked too while `setting` is not
/// `true`.
#[derive(Debug)]
pub struct ValuesUnless {
    pub setting: &'static str,
    pub values: &'static [&'static str],
}

/// `selectAll`: `only_while_on` ticks its values only while that switch is
/// on; while an `alone_while_on` switch is on, only its values are ticked.
#[derive(Debug)]
pub struct SelectAll {
    pub only_while_on: &'static [(&'static str, &'static [&'static str])],
    pub alone_while_on: &'static [(&'static str, &'static [&'static str])],
}

/// A key that was REMOVED and is refused by name, saying what replaced it.
#[derive(Debug)]
pub struct Replaced {
    pub key: &'static str,
    pub env: Option<&'static str>,
    /// A legacy variable that went with the key (#523), refused by name too.
    pub legacy_env: Option<&'static str>,
    pub now: &'static [&'static str],
    pub why: Option<&'static str>,
}

/// The constants, one per key, and the rows.
#[allow(dead_code)]
mod generated {
    use super::{
        ByMode, DefaultValue, Key, Replaced, SelectAll, SettingRow,
        SettingType, ValuesUnless,
    };
    include!(concat!(env!("OUT_DIR"), "/settings.rs"));
}

pub use generated::keys;

/// Every row, in the table's order.
pub fn rows() -> &'static [SettingRow] {
    generated::ROWS
}

/// The keys refused because they were replaced.
pub fn replaced() -> &'static [Replaced] {
    generated::REPLACED
}

static BY_KEY: std::sync::LazyLock<HashMap<&'static str, &'static SettingRow>> =
    std::sync::LazyLock::new(|| {
        rows().iter().map(|row| (row.key, row)).collect()
    });

/// The row for a key given as text — a form field, an API body.
pub fn row(key: &str) -> Option<&'static SettingRow> {
    BY_KEY.get(key).copied()
}

/// A value, coerced to its row's type.
#[derive(Debug, Clone, PartialEq)]
pub enum SettingValue {
    /// `string` and `enum`.
    Text(String),
    /// `int` and `port`.
    Int(i64),
    Bool(bool),
    /// `csv`: trimmed, empty entries dropped.
    List(Vec<String>),
}

impl SettingValue {
    pub fn as_str(&self) -> &str {
        match self {
            SettingValue::Text(text) => text,
            _ => "",
        }
    }

    pub fn as_int(&self) -> i64 {
        match self {
            SettingValue::Int(n) => *n,
            _ => 0,
        }
    }

    pub fn as_bool(&self) -> bool {
        matches!(self, SettingValue::Bool(true))
    }

    pub fn as_list(&self) -> &[String] {
        match self {
            SettingValue::List(list) => list,
            _ => &[],
        }
    }
}

/// Which layer a value came from — `config.js`'s `sourceOf()` words, which
/// the console and the API print.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Realm,
    Override,
    Env,
    EnvLegacy,
    Appconfig,
    Defaults,
    Default,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Realm => "realm",
            Source::Override => "override",
            Source::Env => "env",
            Source::EnvLegacy => "env-legacy",
            Source::Appconfig => "appconfig",
            Source::Defaults => "defaults",
            Source::Default => "default",
        }
    }
}

// ---------------------------------------------------------------------------
// JavaScript's coercions, which the types are written in terms of.
// ---------------------------------------------------------------------------

/// `String(n)` for a JavaScript number: the shortest digits that read back
/// as `n`, in decimal from 1e-6 up to 1e21 and in exponent form outside it
/// (`1e+21`, `1e-7`), and `0` for negative zero.
pub(crate) fn js_number_text(n: f64) -> String {
    if n.is_nan() {
        return "NaN".to_string();
    }
    if n.is_infinite() {
        return if n > 0.0 { "Infinity" } else { "-Infinity" }.to_string();
    }
    if n == 0.0 {
        return "0".to_string();
    }
    let magnitude = n.abs();
    if (1e-6..1e21).contains(&magnitude) {
        return n.to_string();
    }
    // Rust writes `1e21` and `1.5e-8`; JavaScript writes the sign.
    let text = format!("{:e}", n);
    match text.split_once('e') {
        Some((mantissa, exponent)) if !exponent.starts_with('-') => {
            format!("{}e+{}", mantissa, exponent)
        }
        _ => text,
    }
}

/// `String(raw)`: what the environment and a form would have carried.
pub(crate) fn js_string(raw: &Json) -> String {
    match raw {
        Json::Null => "null".to_string(),
        Json::Bool(b) => b.to_string(),
        Json::Number(n) => match (n.as_i64(), n.as_f64()) {
            // An integer beyond 2^53 is a double in JavaScript, and is
            // written as the double it rounds to.
            (Some(i), _) if i.unsigned_abs() <= 1 << 53 => i.to_string(),
            (_, Some(f)) => js_number_text(f),
            _ => n.to_string(),
        },
        Json::String(text) => text.clone(),
        // An array's String() is its elements joined by commas, null as "".
        Json::Array(items) => items
            .iter()
            .map(|one| match one {
                Json::Null => String::new(),
                other => js_string(other),
            })
            .collect::<Vec<_>>()
            .join(","),
        Json::Object(_) => "[object Object]".to_string(),
    }
}

/// `String.prototype.trim()`: JavaScript's white space and line
/// terminators, which are not Rust's `str::trim` set.
pub(crate) fn js_trim(text: &str) -> &str {
    text.trim_matches(is_js_space)
}

/// `parseInt(text, 10)` as the double JavaScript reads: leading white
/// space, a sign, the leading digits; `None` where JavaScript answers NaN.
fn js_parse_number(text: &str) -> Option<f64> {
    let trimmed = text.trim_start_matches(is_js_space);
    let (negative, digits) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    let run: String = digits.chars().take_while(char::is_ascii_digit).collect();
    if run.is_empty() {
        return None;
    }
    let magnitude = run.parse::<f64>().unwrap_or(f64::INFINITY);
    Some(if negative { -magnitude } else { magnitude })
}

/// `parseInt(text, 10)` as the integer a row holds. A value beyond what an
/// `i64` holds saturates, where JavaScript keeps a double; nothing a row
/// bounds reaches that far.
fn js_parse_int(text: &str) -> Option<i64> {
    // `as` saturates, and -0 is 0.
    js_parse_number(text).map(|n| n as i64)
}

fn is_whole_number(text: &str, allow_sign: bool) -> bool {
    // JavaScript's `\d` is ASCII.
    let digits = if allow_sign {
        text.strip_prefix('-').unwrap_or(text)
    } else {
        text
    };
    !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
}

fn is_true_word(text: &str) -> bool {
    ["1", "true", "yes", "on"]
        .iter()
        .any(|word| text.eq_ignore_ascii_case(word))
}

fn is_false_word(text: &str) -> bool {
    ["0", "false", "no", "off"]
        .iter()
        .any(|word| text.eq_ignore_ascii_case(word))
}

/// `#rgb` or `#rrggbb`, either case.
fn is_color(text: &str) -> bool {
    let Some(hex) = text.strip_prefix('#') else {
        return false;
    };
    (hex.len() == 3 || hex.len() == 6)
        && hex.chars().all(|c| c.is_ascii_hexdigit())
}

/// The colour type's parse: trimmed, lower-cased, `#rgb` widened to
/// `#rrggbb`; anything else is kept as written (the check refuses it).
fn color_value(raw: &str) -> String {
    let s = js_trim(raw).to_lowercase();
    match s.strip_prefix('#') {
        Some(hex)
            if hex.len() == 3 && hex.chars().all(|c| c.is_ascii_hexdigit()) =>
        {
            hex.chars().fold(String::from("#"), |mut out, c| {
                out.push(c);
                out.push(c);
                out
            })
        }
        _ => s,
    }
}

/// JavaScript's `\s`, which is not Rust's `char::is_whitespace` (U+0085 is
/// one there and not here; U+FEFF is one here and not there).
fn is_js_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n'
            | '\u{b}'
            | '\u{c}'
            | '\r'
            | ' '
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

/// `/^[A-Za-z][A-Za-z0-9+.-]*:[^\s\u0000-\u001f\u007f]+$/`.
fn is_absolute_uri(text: &str) -> bool {
    let Some((scheme, rest)) = text.split_once(':') else {
        return false;
    };
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c))
        && !rest.is_empty()
        && rest
            .chars()
            .all(|c| !(is_js_space(c) || c <= '\u{1f}' || c == '\u{7f}'))
}

/// The csv type's split: an array as itself, anything else on commas.
fn csv_parts(raw: &Json) -> Vec<String> {
    match raw {
        Json::Array(items) => items.iter().map(js_string).collect(),
        other => js_string(other).split(',').map(str::to_string).collect(),
    }
}

impl SettingRow {
    /// `TYPES[type].parse(raw, setting)`: coerced to this row's type. A
    /// missing value (`None`) is JavaScript's `undefined`.
    pub fn parse(&self, raw: Option<&Json>) -> SettingValue {
        match self.kind {
            SettingType::String => SettingValue::Text(match raw {
                None => String::new(),
                Some(raw) => js_string(raw),
            }),
            SettingType::Enum => SettingValue::Text(match raw {
                None => String::new(),
                Some(raw) => js_trim(&js_string(raw)).to_string(),
            }),
            SettingType::Color => SettingValue::Text(match raw {
                None | Some(Json::Null) => String::new(),
                Some(raw) => color_value(&js_string(raw)),
            }),
            SettingType::Int | SettingType::Port => SettingValue::Int(
                raw.map(js_string)
                    .and_then(|text| js_parse_int(&text))
                    .unwrap_or(0),
            ),
            SettingType::Bool => SettingValue::Bool(self.parse_bool(raw)),
            SettingType::Csv => SettingValue::List(match raw {
                None => Vec::new(),
                Some(raw) => csv_parts(raw)
                    .into_iter()
                    .map(|part| js_trim(&part).to_string())
                    .filter(|part| !part.is_empty())
                    .collect(),
            }),
        }
    }

    /// A value that is neither spelling falls back to the DEFAULT and is
    /// warned about: a typo in a setting whose default is on must not
    /// silently turn it off.
    fn parse_bool(&self, raw: Option<&Json>) -> bool {
        if let Some(Json::Bool(b)) = raw {
            return *b;
        }
        let text = raw.map(js_string).unwrap_or_else(|| "undefined".into());
        let text = js_trim(&text);
        if is_true_word(text) {
            return true;
        }
        if is_false_word(text) {
            return false;
        }
        let fallback = self.default.truthy();
        tracing::warn!(
            "config: \"{}\" is not a true/false value{}; using the default \
             ({}).",
            text,
            self.env
                .map(|env| format!(" for {}", env))
                .unwrap_or_default(),
            fallback
        );
        fallback
    }

    /// `TYPES[type].text(value)`: the single line the console's input shows
    /// and the environment would carry.
    pub fn text(&self, value: &SettingValue) -> String {
        match value {
            SettingValue::Text(text) => text.clone(),
            SettingValue::Int(n) => n.to_string(),
            SettingValue::Bool(b) => b.to_string(),
            SettingValue::List(list) => list.join(","),
        }
    }

    /// `TYPES[type].check(raw, setting)`: what is wrong with a value a caller
    /// supplied, in the words the console prints after the key, or `None`.
    pub fn check(&self, raw: &Json) -> Option<String> {
        match self.kind {
            SettingType::String => self.check_string(raw),
            SettingType::Color => {
                let text = match raw {
                    Json::Null => String::new(),
                    other => js_string(other),
                };
                if is_color(js_trim(&text)) {
                    return None;
                }
                Some(format!(
                    "must be a colour written #rgb or #rrggbb, got \"{}\"",
                    js_string(raw)
                ))
            }
            SettingType::Int => self.check_int(raw),
            SettingType::Port => {
                let text = js_string(raw);
                let s = js_trim(&text);
                if !is_whole_number(s, false) {
                    return Some(format!(
                        "must be a port number, got \"{}\"",
                        text
                    ));
                }
                let n = js_parse_number(s).unwrap_or(0.0);
                if n > 65535.0 {
                    return Some(format!(
                        "must be 0-65535, got {}",
                        js_number_text(n)
                    ));
                }
                None
            }
            SettingType::Bool => {
                if raw.is_boolean() {
                    return None;
                }
                let text = js_string(raw);
                let s = js_trim(&text);
                if is_true_word(s) || is_false_word(s) {
                    return None;
                }
                Some(format!("must be true or false, got \"{}\"", text))
            }
            SettingType::Csv => {
                let allowed = self.csv_values?;
                let parts = match raw {
                    Json::Null => vec![String::new()],
                    other => csv_parts(other),
                };
                let bad = parts
                    .iter()
                    .map(|part| js_trim(part))
                    .find(|part| !part.is_empty() && !allowed.contains(part))?;
                Some(format!(
                    "must be one of {}, got \"{}\"",
                    allowed.join(", "),
                    bad
                ))
            }
            SettingType::Enum => {
                let text = js_string(raw);
                if self.enum_values.contains(&js_trim(&text)) {
                    return None;
                }
                Some(format!(
                    "must be one of {}, got \"{}\"",
                    self.enum_values.join(", "),
                    text
                ))
            }
        }
    }

    /// A string row's `maxLength` and `absoluteUri`; a row with neither is
    /// any text, as every string row was before them.
    fn check_string(&self, raw: &Json) -> Option<String> {
        let text = match raw {
            Json::Null => String::new(),
            other => js_string(other),
        };
        if let Some(max) = self.max_length {
            let length = text.encode_utf16().count() as i64;
            if length > max {
                return Some(format!(
                    "must be at most {} characters, got {}",
                    max, length
                ));
            }
        }
        if self.absolute_uri && !is_absolute_uri(&text) {
            return Some(
                "must be an absolute URI (a scheme, a colon and the rest, \
                 with no spaces), such as \
                 urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
                    .into(),
            );
        }
        None
    }

    /// An integer, which a row may narrow with `min`, `max` and `step`; the
    /// empty string is refused rather than read as 0, because "" is what an
    /// emptied form field sends and 0 is a port.
    fn check_int(&self, raw: &Json) -> Option<String> {
        let text = js_string(raw);
        let s = js_trim(&text);
        if s.is_empty() {
            return Some("must be a number".into());
        }
        if !is_whole_number(s, true) {
            return Some(format!("must be a whole number, got \"{}\"", text));
        }
        // Compared and written as the double JavaScript reads.
        let n = js_parse_number(s).unwrap_or(0.0);
        if let Some(min) = self.min {
            if n < min as f64 {
                return Some(format!(
                    "must be at least {}, got {}",
                    min,
                    js_number_text(n)
                ));
            }
        }
        if let Some(max) = self.max {
            if n > max as f64 {
                return Some(format!(
                    "must be at most {}, got {}",
                    max,
                    js_number_text(n)
                ));
            }
        }
        if let Some(step) = self.step {
            let from = (n - self.min.unwrap_or(0) as f64) % step as f64;
            if step > 1 && from != 0.0 {
                let above = match self.min {
                    Some(min) if min % step != 0 => format!(" above {}", min),
                    _ => String::new(),
                };
                return Some(format!(
                    "must be a multiple of {}{}, got {}",
                    step,
                    above,
                    js_number_text(n)
                ));
            }
        }
        None
    }

    /// The dot path into an appconfig file: the key, unless the row says
    /// otherwise (the log level and the mode do).
    pub fn dotted(&self) -> &'static str {
        self.path.unwrap_or(self.key)
    }
}

// ---------------------------------------------------------------------------
// The layers.
// ---------------------------------------------------------------------------

/// The ambient trust realm's overrides, as the realm layer of the HTTP stack
/// knows them. `None` outside a request, with realms off, or in the default
/// realm — on the read path of every setting, so it answers the realm's map
/// rather than a copy of it.
pub trait RealmLayer: Send + Sync {
    fn ambient_overrides(&self) -> Option<Arc<HashMap<String, Json>>>;
}

/// A rule between settings, owned by the module that reads them (#423): the
/// problem and its code for a write it refuses, `None` otherwise.
/// `in_realm` is true for a write that lands in a realm's overrides (#472:
/// a rule over the process's settings leaves those to the realm module).
///
/// Node also hands a rule `beside(key)`, a companion setting's value as a
/// `withWriteBatch()` write leaves it (#1114); the doors that batch writes
/// are not ported yet, so a rule here reads a companion with
/// [`Settings::value_of`], which is what `beside()` answers outside a batch.
pub trait WriteRule: Send + Sync {
    fn problem(
        &self,
        key: &str,
        parsed: &SettingValue,
        in_realm: bool,
    ) -> Option<(String, ErrorCode)>;
}

thread_local! {
    // Set while a DERIVED default is resolved for the PROCESS rather than for
    // the ambient realm (`config.js`'s `processValue()`): every step between
    // here and the default is synchronous, so a flag on the thread is the
    // right primitive, saved and restored so a derived default that reads
    // another one nests.
    static SUPPRESS_REALM: Cell<bool> = const { Cell::new(false) };
}

/// Every setting's value. One per process, built by the composition root
/// and passed to everything that reads one.
pub struct Settings {
    operator: Json,
    env: HashMap<String, String>,
    /// In the order they were set, as config.js's object keeps them.
    overrides: RwLock<indexmap::IndexMap<String, Json>>,
    realm: OnceLock<Arc<dyn RealmLayer>>,
    rules: RwLock<Vec<Arc<dyn WriteRule>>>,
}

/// A refused write: the sentence the console prints, and its code.
#[derive(Debug, Clone, PartialEq)]
pub struct Refusal {
    pub problem: String,
    pub code: ErrorCode,
}

impl Settings {
    /// `operator`: the operator's appconfig file (a JSON document; `Null` for
    /// none). `env`: the process environment.
    pub fn new(operator: Json, env: HashMap<String, String>) -> Settings {
        Settings {
            operator,
            env,
            overrides: RwLock::new(indexmap::IndexMap::new()),
            realm: OnceLock::new(),
            rules: RwLock::new(Vec::new()),
        }
    }

    /// The process's own environment and the given appconfig file.
    pub fn from_process(operator: Json) -> Settings {
        Settings::new(operator, std::env::vars().collect())
    }

    /// Fills the realm layer, once: the realm module is built after this one
    /// and reads settings itself, which is why it is late-bound.
    pub fn set_realm_layer(&self, layer: Arc<dyn RealmLayer>) -> bool {
        self.realm.set(layer).is_ok()
    }

    /// Adds a rule every write is checked against.
    pub fn add_write_rule(&self, rule: Arc<dyn WriteRule>) {
        match self.rules.write() {
            Ok(mut rules) => rules.push(rule),
            Err(poisoned) => poisoned.into_inner().push(rule),
        }
    }

    fn row_of(key: &str) -> &'static SettingRow {
        // Every key that reaches here is a generated constant or a name a
        // caller checked with `row()`; an unknown one is a programming error
        // the type of `Key` already rules out.
        match row(key) {
            Some(row) => row,
            None => &EMPTY_ROW,
        }
    }

    /// Whether a realm may carry this setting at all: not a `realms.*` row
    /// (how a realm is reached) and not a `perProcess` one (a property of the
    /// OS process).
    pub fn is_per_process(key: &str) -> bool {
        row(key).is_some_and(|row| row.per_process)
    }

    /// Whether a trust realm other than the default one is ambient, for the
    /// rules that ask that of the realm itself rather than of a key
    /// (`config.js`'s `realmContext()`).
    pub fn ambient_realm(&self) -> bool {
        self.realm
            .get()
            .is_some_and(|layer| layer.ambient_overrides().is_some())
    }

    fn realm_overrides(&self, key: &str) -> Option<Arc<HashMap<String, Json>>> {
        if SUPPRESS_REALM.with(Cell::get)
            || key.starts_with("realms.")
            || Settings::is_per_process(key)
        {
            return None;
        }
        self.realm.get()?.ambient_overrides()
    }

    /// The raw value and where it came from. One function, so the two
    /// answers cannot disagree.
    fn resolve(&self, key: &str) -> (Option<Json>, Source) {
        let row = Settings::row_of(key);
        if let Some(realm) = self.realm_overrides(key) {
            if let Some(raw) = realm.get(key) {
                return (Some(raw.clone()), Source::Realm);
            }
        }
        if row.realm_only {
            return self.defaults_layer(row);
        }
        let overridden = match self.overrides.read() {
            Ok(map) => map.get(key).cloned(),
            Err(poisoned) => poisoned.into_inner().get(key).cloned(),
        };
        if let Some(raw) = overridden {
            return (Some(raw), Source::Override);
        }
        if let Some(raw) = row.env.and_then(|name| self.env.get(name)) {
            return (Some(Json::from(raw.as_str())), Source::Env);
        }
        if let Some(raw) = row.legacy_env.and_then(|name| self.env.get(name)) {
            return (Some(Json::from(raw.as_str())), Source::EnvLegacy);
        }
        if let Some(raw) = dig(&self.operator, row.dotted()) {
            return (Some(raw.clone()), Source::Appconfig);
        }
        self.defaults_layer(row)
    }

    /// The defaults file is the `dflt` column (`env/defaults.js` is
    /// generated from it); a derived row is not in it and is computed.
    fn defaults_layer(&self, row: &SettingRow) -> (Option<Json>, Source) {
        if row.default == DefaultValue::Derived {
            return (Some(self.derived(row.key)), Source::Default);
        }
        (Some(row.default.raw()), Source::Defaults)
    }

    /// The defaults that are functions: a `strongerInProduct()` pair, read
    /// in the ambient realm's mode, or one of the four of other settings.
    fn derived(&self, key: &str) -> Json {
        if let Some(pair) = Settings::row_of(key).by_mode {
            // `value('global.mode') === 'product' ? product : development`:
            // the realm's mode, unless the process is being asked.
            let product = self.value(keys::GLOBAL_MODE).as_str() == "product";
            return if product {
                pair.product
            } else {
                pair.development
            }
            .raw();
        }
        match key {
            // A statement about a bound socket, so read for the PROCESS: a
            // FAPI profile and both OAuth modes imply TLS.
            "global.https" => {
                let fapi = self.process_value(keys::OAUTH2_FAPI);
                let fapi = fapi.as_str();
                Json::from(
                    self.process_value(keys::OAUTH2_RFC9700).as_bool()
                        || self.process_value(keys::OAUTH2_OAUTH21).as_bool()
                        || !(fapi.is_empty() || fapi == "off"),
                )
            }
            "adminApi.audience" => Json::from(self.management_api_base_url()),
            "oid4vp.walletUrl" => {
                Json::from(self.value(keys::OID4VCI_WALLET_URL).as_str())
            }
            "krb5.serviceDomains" => Json::from(format!(
                "{},localhost,sts,127.0.0.1",
                self.value(keys::KRB5_REALM).as_str().to_lowercase()
            )),
            _ => Json::Null,
        }
    }

    /// THE read every module makes, coerced to the row's type.
    pub fn value(&self, key: Key) -> SettingValue {
        self.value_of(key.as_str())
    }

    /// The same for a key given as text, already known to be a row.
    pub fn value_of(&self, key: &str) -> SettingValue {
        let (raw, _) = self.resolve(key);
        Settings::row_of(key).parse(raw.as_ref())
    }

    /// The value with the realm layer set aside — what the setting is for
    /// the PROCESS.
    pub fn process_value(&self, key: Key) -> SettingValue {
        let was = SUPPRESS_REALM.with(|flag| flag.replace(true));
        let value = self.value(key);
        SUPPRESS_REALM.with(|flag| flag.set(was));
        value
    }

    pub fn source_of(&self, key: Key) -> Source {
        self.resolve(key.as_str()).1
    }

    /// The value as one line.
    pub fn text(&self, key: Key) -> String {
        Settings::row_of(key.as_str()).text(&self.value(key))
    }

    /// The management API's base URL as the process knows it without a
    /// request; a wildcard bind is drawn as `localhost`, and the scheme's
    /// standard port is left off.
    pub fn management_api_base_url(&self) -> String {
        let pinned = self.process_value(keys::GLOBAL_PUBLIC_BASE_URL);
        let pinned = pinned.as_str().trim().trim_end_matches('/');
        if !pinned.is_empty() {
            return format!("{}/admin-api", pinned);
        }
        let https = self.process_value(keys::GLOBAL_HTTPS).as_bool();
        let port = self.process_value(keys::GLOBAL_PORT).as_int();
        let bound = self.process_value(keys::GLOBAL_HOST);
        let bound = bound
            .as_str()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let host = if bound.is_empty() || bound == "0.0.0.0" || bound == "::" {
            "localhost".to_string()
        } else if bound.contains(':') {
            format!("[{}]", bound)
        } else {
            bound
        };
        let standard = if https { 443 } else { 80 };
        format!(
            "{}://{}{}/admin-api",
            if https { "https" } else { "http" },
            host,
            if port == standard {
                String::new()
            } else {
                format!(":{}", port)
            }
        )
    }

    /// `checkOverride()`: why a runtime write of `raw` to `key` would be
    /// refused, or `None`. `for_realm`: the write lands on a realm, which
    /// admits the `realmRuntime` rows; `None` means wherever it would land —
    /// the ambient realm when there is one.
    pub fn check_override(
        &self,
        key: &str,
        raw: &Json,
        for_realm: Option<bool>,
    ) -> Option<Refusal> {
        let in_realm =
            for_realm.unwrap_or_else(|| self.realm_overrides(key).is_some());
        let Some(row) = row(key) else {
            return Some(Refusal {
                problem: format!(
                    "Unknown setting \"{}\".{}",
                    key,
                    replaced_by(key)
                ),
                code: codes::STS_CORE_0004,
            });
        };
        if !row.runtime && !(in_realm && row.realm_runtime) {
            return Some(Refusal {
                problem: format!(
                    "\"{}\" cannot be changed while this service is running: \
                     {}. Set it in the appconfig file or as {} and restart.",
                    key,
                    row.restart_reason,
                    row.env.unwrap_or("its environment variable")
                ),
                code: codes::STS_CORE_0005,
            });
        }
        // After the runtime check and before the type check, so a
        // non-default realm hears STS-CORE-0162 rather than a type error
        // (#368).
        if let Some(problem) = self.max_count_realm_problem(key) {
            return Some(Refusal {
                problem,
                code: codes::STS_CORE_0162,
            });
        }
        if unstorable_text(raw) {
            return Some(Refusal {
                problem: format!(
                    "\"{}\" holds a NUL character or half of a surrogate \
                     pair, which this service cannot store.",
                    key
                ),
                code: codes::STS_CORE_0171,
            });
        }
        if let Some(problem) = row.check(raw) {
            return Some(Refusal {
                problem: format!("\"{}\" {}.", key, problem),
                code: codes::STS_CORE_0006,
            });
        }
        self.write_rule_problem(key, &row.parse(Some(raw)), in_realm)
    }

    /// `maxCountRealmProblem()`: `realms.maxCount` is a cap on the whole
    /// service, so it is written only while the default realm is ambient.
    fn max_count_realm_problem(&self, key: &str) -> Option<String> {
        if key != "realms.maxCount" || !self.ambient_realm() {
            return None;
        }
        Some(
            "\"realms.maxCount\" can be set only in the default realm, by a \
             service administrator. Open /admin/realms there, or POST \
             /admin-api/config/set with no realm prefix."
                .to_string(),
        )
    }

    /// The first rule's refusal, or `None`. A rule that panics refuses
    /// nothing, as one that threw did.
    fn write_rule_problem(
        &self,
        key: &str,
        parsed: &SettingValue,
        in_realm: bool,
    ) -> Option<Refusal> {
        let rules = match self.rules.read() {
            Ok(rules) => rules.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        for rule in rules {
            let answer =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    rule.problem(key, parsed, in_realm)
                }));
            match answer {
                Ok(Some((problem, code))) => {
                    return Some(Refusal { problem, code });
                }
                Ok(None) => {}
                Err(_) => tracing::warn!(
                    "{}config: a rule between settings failed on {}; the \
                     write is not refused by it.",
                    crate::log::tag(codes::STS_CORE_0149),
                    key
                ),
            }
        }
        None
    }

    /// Sets a process-wide runtime override, after `check_override()`.
    pub fn set_override(&self, key: &str, raw: Json) -> Result<(), Refusal> {
        if let Some(refusal) = self.check_override(key, &raw, Some(false)) {
            return Err(refusal);
        }
        match self.overrides.write() {
            Ok(mut map) => map.insert(key.to_string(), raw),
            Err(poisoned) => poisoned.into_inner().insert(key.to_string(), raw),
        };
        Ok(())
    }

    /// Removes a process-wide runtime override; whether there was one.
    pub fn clear_override(&self, key: &str) -> bool {
        match self.overrides.write() {
            Ok(mut map) => map.shift_remove(key).is_some(),
            Err(poisoned) => poisoned.into_inner().shift_remove(key).is_some(),
        }
    }

    /// The process-wide runtime overrides, in the order they were set
    /// (`persistableOverrides()`): what persistence writes down.
    pub fn runtime_overrides(&self) -> serde_json::Map<String, Json> {
        let map = match self.overrides.read() {
            Ok(map) => map,
            Err(poisoned) => poisoned.into_inner(),
        };
        map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
}

/// The sentence a removed key's refusal ends with.
pub fn replaced_by(key: &str) -> String {
    match replaced().iter().find(|one| one.key == key) {
        Some(Replaced { why: Some(why), .. }) => why.to_string(),
        Some(one) => format!(
            " It was removed on 2026-09-23 (#171) and replaced by {}: plain \
             http, certificate verification (off in development only) and a \
             CA file are three settings now.",
            one.now.join(", ")
        ),
        None => String::new(),
    }
}

/// `unstorableText()` (#1463): whether a value holds text the store's
/// `jsonb` columns can never hold — a NUL (22P05) or half of a surrogate
/// pair (22P02) — in a string, a key, or anything nested. A Rust string
/// cannot hold half a pair (`serde_json` refuses a lone `\ud800` where the
/// body is read), so what is left to ask here is the NUL.
pub fn unstorable_text(value: &Json) -> bool {
    match value {
        Json::String(text) => text.contains('\u{0}'),
        Json::Array(items) => items.iter().any(unstorable_text),
        Json::Object(map) => map
            .iter()
            .any(|(key, one)| key.contains('\u{0}') || unstorable_text(one)),
        _ => false,
    }
}

/// A dot path into an appconfig document; `None` for any missing hop, so a
/// file that omits a whole section falls through to the next layer.
fn dig<'a>(root: &'a Json, dotted: &str) -> Option<&'a Json> {
    let mut node = root;
    for part in dotted.split('.') {
        node = node.as_object()?.get(part)?;
    }
    Some(node)
}

static EMPTY_ROW: SettingRow = SettingRow {
    key: "",
    group: "",
    label: "",
    env: None,
    legacy_env: None,
    kind: SettingType::String,
    default: DefaultValue::Text(""),
    runtime: false,
    restart_reason: "",
    description: "",
    min: None,
    max: None,
    step: None,
    realm_runtime: false,
    realm_only: false,
    enum_values: &[],
    csv_values: None,
    csv_value_notes: &[],
    ordered: false,
    derived: false,
    per_process: false,
    path: None,
    secret: false,
    only_while: None,
    only_while_values: None,
    only_while_values_unless: None,
    max_length: None,
    absolute_uri: false,
    select_all: None,
    by_mode: None,
};

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn settings(operator: Json, env: &[(&str, &str)]) -> Settings {
        Settings::new(
            operator,
            env.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    #[test]
    fn the_table_is_whole() {
        assert!(rows().len() > 1100);
        assert_eq!(keys::GLOBAL_PORT.as_str(), "global.port");
        assert!(row("global.port").is_some_and(|r| r.env == Some("STS_PORT")));
        // A derived default is one of the four of other settings, or a
        // strongerInProduct() pair; the export refuses any other kind.
        let by_hand = [
            "global.https",
            "adminApi.audience",
            "oid4vp.walletUrl",
            "krb5.serviceDomains",
        ];
        let derived: Vec<&SettingRow> = rows()
            .iter()
            .filter(|r| r.default == DefaultValue::Derived)
            .collect();
        assert_eq!(derived.len(), 23);
        for one in derived {
            assert!(
                by_hand.contains(&one.key) || one.by_mode.is_some(),
                "{} has a derived default sts-core does not compute",
                one.key
            );
        }
    }

    #[test]
    fn a_default_stronger_in_product() {
        let development = settings(Json::Null, &[]);
        let product = settings(Json::Null, &[("STS_MODE", "product")]);
        assert_eq!(development.value(keys::TOTP_WINDOW).as_int(), 1);
        assert_eq!(product.value(keys::TOTP_WINDOW).as_int(), 0);
        assert_eq!(product.source_of(keys::TOTP_WINDOW), Source::Default);
        assert_eq!(product.value(keys::PKI_KEY_ALGORITHM).as_str(), "rsa-3072");
        assert!(development.value(keys::LDAP_PLAIN_LISTENER).as_bool());
        assert!(!product.value(keys::LDAP_PLAIN_LISTENER).as_bool());
        // The realm's mode decides, as value('global.mode') reads it.
        let mut map = HashMap::new();
        map.insert("global.mode".to_string(), json!("product"));
        development.set_realm_layer(Arc::new(Acme(Arc::new(map))));
        assert_eq!(development.value(keys::TOTP_WINDOW).as_int(), 0);
    }

    #[test]
    fn the_layers_in_order() {
        let s = settings(json!({"global": {"port": 9000}}), &[]);
        assert_eq!(s.value(keys::GLOBAL_PORT), SettingValue::Int(9000));
        assert_eq!(s.source_of(keys::GLOBAL_PORT), Source::Appconfig);
        let s =
            settings(json!({"global": {"port": 9000}}), &[("STS_PORT", "7")]);
        assert_eq!(s.value(keys::GLOBAL_PORT).as_int(), 7);
        assert_eq!(s.source_of(keys::GLOBAL_PORT), Source::Env);
        let s = settings(Json::Null, &[]);
        assert_eq!(s.value(keys::GLOBAL_PORT).as_int(), 8081);
        assert_eq!(s.source_of(keys::GLOBAL_PORT), Source::Defaults);
        // The mode's appconfig path is `mode`, not `global.mode`.
        let s = settings(json!({"mode": "product"}), &[]);
        assert_eq!(s.value(keys::GLOBAL_MODE).as_str(), "product");
    }

    struct Acme(Arc<HashMap<String, Json>>);
    impl RealmLayer for Acme {
        fn ambient_overrides(&self) -> Option<Arc<HashMap<String, Json>>> {
            Some(self.0.clone())
        }
    }

    #[test]
    fn a_realm_is_above_everything_but_not_for_the_process() {
        let s = settings(Json::Null, &[]);
        let mut map = HashMap::new();
        map.insert("oauth2.rfc9700".to_string(), json!(true));
        s.set_realm_layer(Arc::new(Acme(Arc::new(map))));
        assert!(s.value(keys::OAUTH2_RFC9700).as_bool());
        assert_eq!(s.source_of(keys::OAUTH2_RFC9700), Source::Realm);
        // global.https's default is about the socket: the realm's mode does
        // not move it.
        assert!(!s.value(keys::GLOBAL_HTTPS).as_bool());
        assert!(!s.process_value(keys::OAUTH2_RFC9700).as_bool());
    }

    #[test]
    fn the_derived_defaults() {
        let s = settings(Json::Null, &[("STS_PORT", "8443")]);
        assert_eq!(
            s.value(keys::ADMIN_API_AUDIENCE).as_str(),
            "http://localhost:8443/admin-api"
        );
        assert_eq!(s.source_of(keys::ADMIN_API_AUDIENCE), Source::Default);
        let domains = s.value(keys::KRB5_SERVICE_DOMAINS);
        assert_eq!(domains.as_list()[1..], ["localhost", "sts", "127.0.0.1"]);
        assert_eq!(
            domains.as_list()[0],
            s.value(keys::KRB5_REALM).as_str().to_lowercase()
        );
    }

    #[test]
    fn javascript_coercions() {
        let int = Settings::row_of("global.port");
        assert_eq!(int.parse(Some(&json!(" 12abc"))).as_int(), 12);
        assert_eq!(int.parse(Some(&json!("x"))).as_int(), 0);
        assert_eq!(int.parse(Some(&json!(1.0))).as_int(), 1);
        let csv = row("krb5.serviceDomains").unwrap_or(&EMPTY_ROW);
        assert_eq!(
            csv.parse(Some(&json!(" a, ,b ,"))).as_list(),
            ["a".to_string(), "b".to_string()]
        );
        assert_eq!(
            csv.parse(Some(&json!(["x ", ""]))).as_list(),
            ["x".to_string()]
        );
        assert_eq!(js_string(&json!([1, null, "a"])), "1,,a");
        assert_eq!(js_string(&json!(1e21)), "1e+21");
        assert_eq!(js_string(&json!(0.0000001)), "1e-7");
        assert_eq!(js_string(&json!(-0.0)), "0");
        assert_eq!(js_string(&json!(1.5)), "1.5");
        // JavaScript's white space is not Rust's.
        assert_eq!(js_trim("\u{feff} x\u{a0}"), "x");
        assert_eq!(js_trim("\u{85}x"), "\u{85}x");
    }

    #[test]
    fn checks_word_for_word() {
        let port = Settings::row_of("global.port");
        assert_eq!(
            port.check(&json!("70000")).as_deref(),
            Some("must be 0-65535, got 70000")
        );
        assert_eq!(
            port.check(&json!("-1")).as_deref(),
            Some("must be a port number, got \"-1\"")
        );
        let ranged = rows()
            .iter()
            .find(|r| r.kind == SettingType::Int && r.min == Some(1))
            .unwrap_or(&EMPTY_ROW);
        assert_eq!(
            ranged.check(&json!("0")).as_deref(),
            Some("must be at least 1, got 0")
        );
        assert_eq!(
            ranged.check(&json!("")).as_deref(),
            Some("must be a number")
        );
        let mode = Settings::row_of("global.mode");
        assert_eq!(
            mode.check(&json!("prod")).as_deref(),
            Some("must be one of development, product, got \"prod\"")
        );
    }

    #[test]
    fn writes_are_checked_and_coded() {
        let s = settings(Json::Null, &[]);
        let refused = s.set_override("global.port", json!(1));
        assert_eq!(refused.map_err(|r| r.code), Err(codes::STS_CORE_0005));
        let unknown = s.check_override("nope.nope", &json!(1), None);
        assert_eq!(unknown.map(|r| r.code), Some(codes::STS_CORE_0004));
        let replaced =
            s.check_override("gnap.pushAllowInsecure", &json!(1), None);
        assert!(
            replaced.is_some_and(|r| r.problem.contains("gnap.pushAllowHttp"))
        );
        assert!(s.set_override("global.mode", json!("product")).is_ok());
        assert_eq!(s.source_of(keys::GLOBAL_MODE), Source::Override);
        assert!(s.clear_override("global.mode"));
        let bad = s.set_override("global.mode", json!("prod"));
        assert_eq!(bad.map_err(|r| r.code), Err(codes::STS_CORE_0006));
        let nul = s.check_override("global.mode", &json!("a\u{0}b"), None);
        assert_eq!(nul.map(|r| r.code), Some(codes::STS_CORE_0171));
    }

    #[test]
    fn the_realm_cap_is_the_default_realms() {
        let s = settings(Json::Null, &[]);
        assert!(s
            .check_override("realms.maxCount", &json!("3"), None)
            .is_none());
        s.set_realm_layer(Arc::new(Acme(Arc::new(HashMap::new()))));
        let refused = s.check_override("realms.maxCount", &json!("x"), None);
        assert_eq!(refused.map(|r| r.code), Some(codes::STS_CORE_0162));
    }
}
