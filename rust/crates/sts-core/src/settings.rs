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
//! `realms.*` ones, skips the realm layer. The four DERIVED defaults are
//! functions of other settings, computed here ([`Settings::derived`]).
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
        }
    }
}

/// A row's `dflt`. `Derived` is one of the four that are functions of other
/// settings.
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
}

/// A key that was REMOVED and is refused by name, saying what replaced it.
#[derive(Debug)]
pub struct Replaced {
    pub key: &'static str,
    pub env: Option<&'static str>,
    pub now: &'static [&'static str],
    pub why: Option<&'static str>,
}

/// The constants, one per key, and the rows.
#[allow(dead_code)]
mod generated {
    use super::{DefaultValue, Key, Replaced, SettingRow, SettingType};
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

/// `String(raw)`: what the environment and a form would have carried.
fn js_string(raw: &Json) -> String {
    match raw {
        Json::Null => "null".to_string(),
        Json::Bool(b) => b.to_string(),
        Json::Number(n) => match (n.as_i64(), n.as_f64()) {
            (Some(i), _) => i.to_string(),
            (None, Some(f)) if f.fract() == 0.0 && f.abs() < 1e21 => {
                format!("{:.0}", f)
            }
            (None, Some(f)) => f.to_string(),
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

/// `parseInt(text, 10)`: leading whitespace, a sign, the leading digits;
/// `None` where JavaScript answers NaN.
fn js_parse_int(text: &str) -> Option<i64> {
    let trimmed = text.trim_start();
    let (negative, digits) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    let run: String = digits.chars().take_while(char::is_ascii_digit).collect();
    if run.is_empty() {
        return None;
    }
    let magnitude = run.parse::<i64>().unwrap_or(i64::MAX);
    Some(if negative { -magnitude } else { magnitude })
}

fn is_whole_number(text: &str, allow_sign: bool) -> bool {
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
                Some(raw) => js_string(raw).trim().to_string(),
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
                    .map(|part| part.trim().to_string())
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
        let text = text.trim();
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
            SettingType::String => None,
            SettingType::Int => self.check_int(raw),
            SettingType::Port => {
                let text = js_string(raw);
                let s = text.trim();
                if !is_whole_number(s, false) {
                    return Some(format!(
                        "must be a port number, got \"{}\"",
                        text
                    ));
                }
                let n = js_parse_int(s).unwrap_or(0);
                if n > 65535 {
                    return Some(format!("must be 0-65535, got {}", n));
                }
                None
            }
            SettingType::Bool => {
                if raw.is_boolean() {
                    return None;
                }
                let text = js_string(raw);
                let s = text.trim();
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
                    .map(|part| part.trim())
                    .find(|part| !part.is_empty() && !allowed.contains(part))?;
                Some(format!(
                    "must be one of {}, got \"{}\"",
                    allowed.join(", "),
                    bad
                ))
            }
            SettingType::Enum => {
                let text = js_string(raw);
                if self.enum_values.contains(&text.trim()) {
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

    /// An integer, which a row may narrow with `min`, `max` and `step`; the
    /// empty string is refused rather than read as 0, because "" is what an
    /// emptied form field sends and 0 is a port.
    fn check_int(&self, raw: &Json) -> Option<String> {
        let text = js_string(raw);
        let s = text.trim();
        if s.is_empty() {
            return Some("must be a number".into());
        }
        if !is_whole_number(s, true) {
            return Some(format!("must be a whole number, got \"{}\"", text));
        }
        let n = js_parse_int(s).unwrap_or(0);
        if let Some(min) = self.min {
            if n < min {
                return Some(format!("must be at least {}, got {}", min, n));
            }
        }
        if let Some(max) = self.max {
            if n > max {
                return Some(format!("must be at most {}, got {}", max, n));
            }
        }
        if let Some(step) = self.step {
            if step > 1 && (n - self.min.unwrap_or(0)) % step != 0 {
                let above = match self.min {
                    Some(min) if min % step != 0 => format!(" above {}", min),
                    _ => String::new(),
                };
                return Some(format!(
                    "must be a multiple of {}{}, got {}",
                    step, above, n
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
pub trait WriteRule: Send + Sync {
    fn problem(
        &self,
        key: &str,
        parsed: &SettingValue,
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
    overrides: RwLock<HashMap<String, Json>>,
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
            overrides: RwLock::new(HashMap::new()),
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

    /// The four defaults that are functions of other settings.
    fn derived(&self, key: &str) -> Json {
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
        if let Some(problem) = row.check(raw) {
            return Some(Refusal {
                problem: format!("\"{}\" {}.", key, problem),
                code: codes::STS_CORE_0006,
            });
        }
        self.write_rule_problem(key, &row.parse(Some(raw)))
    }

    /// The first rule's refusal, or `None`. A rule that panics refuses
    /// nothing, as one that threw did.
    fn write_rule_problem(
        &self,
        key: &str,
        parsed: &SettingValue,
    ) -> Option<Refusal> {
        let rules = match self.rules.read() {
            Ok(rules) => rules.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        for rule in rules {
            let answer =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    rule.problem(key, parsed)
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
            Ok(mut map) => map.remove(key).is_some(),
            Err(poisoned) => poisoned.into_inner().remove(key).is_some(),
        }
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
        let derived: Vec<&str> = rows()
            .iter()
            .filter(|r| r.default == DefaultValue::Derived)
            .map(|r| r.key)
            .collect();
        assert_eq!(
            derived,
            [
                "global.https",
                "adminApi.audience",
                "oid4vp.walletUrl",
                "krb5.serviceDomains"
            ]
        );
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
    }
}
