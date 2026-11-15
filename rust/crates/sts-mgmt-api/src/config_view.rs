// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The configuration as the management API shows it: `config.js`'s
//! `describe()`, `groups()` and `snapshot()`, the console's settings block
//! (`configSettingsJson()`, `settingsContext()`), and the masking every
//! answer passes a sensitive value through (`admin-core/config_dump.ts`,
//! #1478). All of it is a view over `sts-core`'s settings and mode; the
//! console's tables (which page a group lives on, its label) are the
//! exported ones.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value as Json};
use sts_core::mode::Mode;
use sts_core::settings::{
    keys, rows, DefaultValue, SettingRow, SettingType, SettingValue, Settings,
};

use crate::tables::tables;

/// What a settings block states about the process (`settingsContext()`),
/// and what the configuration snapshot names: the files and the store.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProcessFacts {
    /// `process.env.CONFIG_FILE`, or `None`.
    pub config_file: Option<String>,
    /// `config.DEFAULTS_FILE`.
    pub defaults_file: String,
    /// `persistence.status()`.
    pub persists_appconfig: bool,
    pub persists_realms: bool,
    pub persistence_mode: String,
    pub persistence_enabled: bool,
}

/// What the view reads.
pub struct ConfigView<'a> {
    pub settings: &'a Settings,
    pub mode: &'a Mode,
    pub facts: &'a ProcessFacts,
    /// The ambient realm's id.
    pub realm: &'a str,
}

/// `JSON` of a coerced value.
#[tracing::instrument(level = "debug")]
pub fn value_json(value: &SettingValue) -> Json {
    match value {
        SettingValue::Text(s) => Json::from(s.as_str()),
        SettingValue::Int(n) => Json::from(*n),
        SettingValue::Bool(b) => Json::from(*b),
        SettingValue::List(list) => Json::from(list.clone()),
    }
}

fn raw_default(d: DefaultValue) -> Json {
    match d {
        DefaultValue::Text(text) => Json::from(text),
        DefaultValue::Int(n) => Json::from(n),
        DefaultValue::Bool(b) => Json::from(b),
        DefaultValue::List(list) => Json::from(list.to_vec()),
        DefaultValue::Derived => Json::Null,
    }
}

const MASK: &str = "********";

static SENSITIVE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new("(?i)secret|passw|passphrase|token|salt|credential|privatekey|clientkey|apikey").ok()
});

static POINTER: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        "(?i)(file|files|ref|field|vault|region|mount|role|url|urls|uri|endpoint|host|hosts|port|alg|algs|\
         algorithm|algorithms|format|formats|type|types|doors|method|methods|lifetime|ttl|length|prefix|header|\
         attribute)$",
    )
    .ok()
});

static TEXT_RULES: LazyLock<Vec<(Regex, String)>> = LazyLock::new(|| {
    [
        (
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----|$)",
            MASK.to_string(),
        ),
        (r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]*(?:\.[\w-]+\.[\w-]+)?", MASK.to_string()),
        (r"(?i)\b([a-z][a-z0-9+.-]*://[^\s/:@]*):([^\s/@]+)@", format!("${{1}}:{}@", MASK)),
        (r"\b(Basic|Bearer|DPoP)\s+[A-Za-z0-9+/._~-]{8,}=*", format!("${{1}} {}", MASK)),
        (
            r#"(?i)(["']?[\w-]*(?:secret|password|passwd|pwd|token|accesskey|apikey)[\w-]*["']?\s*[=:]\s*)(["']?)[^"'&;,\s]+"#,
            format!("${{1}}${{2}}{}", MASK),
        ),
    ]
    .into_iter()
    .filter_map(|(re, to)| Regex::new(re).ok().map(|re| (re, to)))
    .collect()
});

static JWK_PRIVATE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r#"("(?:d|p|q|dp|dq|qi|k|oth|priv|seed)"\s*:\s*)"[^"]*""#).ok()
});

/// `ConfigDump.nameIsSensitive()`.
#[tracing::instrument(level = "debug")]
pub fn name_is_sensitive(key: &str) -> bool {
    let last = key.rsplit('.').next().unwrap_or("");
    SENSITIVE.as_ref().is_some_and(|re| re.is_match(last))
        && !POINTER.as_ref().is_some_and(|re| re.is_match(last))
}

fn mask_text(text: &str) -> String {
    let mut out = text.to_string();
    for (re, to) in TEXT_RULES.iter() {
        out = re.replace_all(&out, to.as_str()).into_owned();
    }
    if out.contains("\"kty\"") {
        if let Some(re) = JWK_PRIVATE.as_ref() {
            out = re
                .replace_all(&out, format!("${{1}}\"{}\"", MASK).as_str())
                .into_owned();
        }
    }
    out
}

fn mask_value(value: &Json, whole: bool) -> Json {
    match value {
        Json::Array(list) => {
            Json::Array(list.iter().map(|v| mask_value(v, whole)).collect())
        }
        Json::String(s) if !s.is_empty() => Json::String(if whole {
            MASK.to_string()
        } else {
            mask_text(s)
        }),
        other => other.clone(),
    }
}

/// `maskDescribed()`: a described row with a sensitive value replaced.
#[tracing::instrument(level = "debug", skip_all)]
pub fn mask_row(row: &Json) -> Json {
    let kind = row.get("type").and_then(Json::as_str).unwrap_or("");
    if kind != "string" && kind != "csv" {
        return row.clone();
    }
    let key = row.get("key").and_then(Json::as_str).unwrap_or("");
    let whole = sts_core::settings::row(key).is_some_and(|r| r.secret)
        || name_is_sensitive(key);
    let null = Json::Null;
    let value = mask_value(row.get("value").unwrap_or(&null), whole);
    let dflt = mask_value(row.get("default").unwrap_or(&null), whole);
    let text = mask_value(row.get("text").unwrap_or(&null), whole);
    let changed =
        Some(&value) != row.get("value") || Some(&dflt) != row.get("default");
    let mut out = row.as_object().cloned().unwrap_or_default();
    if row.get("value").is_some() {
        out.insert("value".into(), value);
    }
    if row.get("default").is_some() {
        out.insert("default".into(), dflt);
    }
    if row.get("text").is_some() {
        out.insert("text".into(), text);
    }
    if changed {
        out.insert("masked".into(), Json::Bool(true));
    }
    Json::Object(out)
}

/// `maskKeyed()`.
#[tracing::instrument(level = "debug", skip(value))]
pub fn mask_keyed(key: &str, value: &Json) -> Json {
    let row = sts_core::settings::row(key);
    let free = row.is_none_or(|r| {
        matches!(r.kind, SettingType::String | SettingType::Csv)
    });
    if !free {
        return value.clone();
    }
    mask_value(
        value,
        row.is_some_and(|r| r.secret) || name_is_sensitive(key),
    )
}

/// `isEchoOfMask()`: the mask posted back, which says "leave it".
#[tracing::instrument(level = "debug", skip_all)]
pub fn is_echo_of_mask(described: &Json, posted: &Json) -> bool {
    let shown = mask_row(described);
    let text = |v: &Json| match v {
        Json::String(s) => s.clone(),
        Json::Null => "null".into(),
        Json::Array(list) => list
            .iter()
            .map(|x| match x {
                Json::String(s) => s.clone(),
                Json::Null => String::new(),
                o => o.to_string(),
            })
            .collect::<Vec<_>>()
            .join(","),
        other => other.to_string(),
    };
    shown.get("masked") == Some(&Json::Bool(true))
        && text(posted) == text(shown.get("text").unwrap_or(&Json::Null))
}

impl ConfigView<'_> {
    fn in_default(&self) -> bool {
        self.realm == crate::gate::DEFAULT_REALM
    }

    /// `realmFor(key)`: whether a write here lands in the ambient realm.
    fn realm_for(&self, key: &str) -> bool {
        !self.in_default()
            && !key.starts_with("realms.")
            && !Settings::is_per_process(key)
            && self.settings.ambient_realm()
    }

    fn default_of(&self, row: &SettingRow) -> Json {
        if let Some(pair) = row.by_mode {
            let product =
                self.settings.value(keys::GLOBAL_MODE).as_str() == "product";
            return raw_default(if product {
                pair.product
            } else {
                pair.development
            });
        }
        match row.default {
            DefaultValue::Derived => match row.key {
                "global.https" => {
                    let fapi = self.settings.process_value(keys::OAUTH2_FAPI);
                    Json::from(
                        self.settings
                            .process_value(keys::OAUTH2_RFC9700)
                            .as_bool()
                            || self
                                .settings
                                .process_value(keys::OAUTH2_OAUTH21)
                                .as_bool()
                            || !(fapi.as_str().is_empty()
                                || fapi.as_str() == "off"),
                    )
                }
                "adminApi.audience" => {
                    Json::from(self.settings.management_api_base_url())
                }
                "oid4vp.walletUrl" => Json::from(
                    self.settings.value(keys::OID4VCI_WALLET_URL).as_str(),
                ),
                "krb5.serviceDomains" => Json::from(format!(
                    "{},localhost,sts,127.0.0.1",
                    self.settings
                        .value(keys::KRB5_REALM)
                        .as_str()
                        .to_lowercase()
                )),
                _ => Json::Null,
            },
            other => raw_default(other),
        }
    }

    /// `describe(setting)`.
    #[tracing::instrument(level = "debug", skip(self, row), fields(key = row.key))]
    pub fn describe(&self, row: &SettingRow) -> Json {
        let key = row.key;
        let locked = key == "realms.maxCount" && !self.in_default();
        let runtime_here =
            row.runtime || (row.realm_runtime && self.realm_for(key));
        let mut out = Map::new();
        out.insert("key".into(), Json::from(key));
        out.insert("group".into(), Json::from(row.group));
        out.insert("label".into(), Json::from(row.label));
        out.insert("description".into(), Json::from(row.description));
        out.insert("type".into(), Json::from(row.kind.as_str()));
        if !row.enum_values.is_empty() {
            out.insert(
                "enumValues".into(),
                Json::from(row.enum_values.to_vec()),
            );
        }
        if let Some(values) = row.csv_values {
            out.insert("csvValues".into(), Json::from(values.to_vec()));
        }
        if row.ordered {
            out.insert("ordered".into(), Json::Bool(true));
        }
        if !row.csv_value_notes.is_empty() {
            let notes: Map<String, Json> = row
                .csv_value_notes
                .iter()
                .map(|(k, v)| (k.to_string(), Json::from(*v)))
                .collect();
            out.insert("csvValueNotes".into(), Json::Object(notes));
        }
        if let Some(select) = &row.select_all {
            let rule = |list: &[(&str, &[&str])]| {
                Json::Array(
                    list.iter()
                        .map(|(setting, values)| {
                            let can = self.mode.allows_value(
                                setting,
                                &SettingValue::Bool(true),
                            );
                            let mut one = Map::new();
                            one.insert("setting".into(), Json::from(*setting));
                            one.insert(
                                "values".into(),
                                Json::from(values.to_vec()),
                            );
                            one.insert(
                                "on".into(),
                                Json::Bool(
                                    can && self.settings.value_of(setting)
                                        == SettingValue::Bool(true),
                                ),
                            );
                            one.insert("canBeOn".into(), Json::Bool(can));
                            Json::Object(one)
                        })
                        .collect(),
                )
            };
            let mut s = Map::new();
            s.insert("onlyWhileOn".into(), rule(select.only_while_on));
            s.insert("aloneWhileOn".into(), rule(select.alone_while_on));
            out.insert("selectAll".into(), Json::Object(s));
        }
        if let Some(n) = row.min {
            out.insert("min".into(), Json::from(n));
        }
        if let Some(n) = row.max {
            out.insert("max".into(), Json::from(n));
        }
        if let Some(n) = row.step {
            out.insert("step".into(), Json::from(n));
        }
        out.insert("value".into(), value_json(&self.settings.value_of(key)));
        out.insert("text".into(), Json::from(self.settings.text_named(key)));
        out.insert(
            "source".into(),
            Json::from(self.settings.source_named(key).as_str()),
        );
        out.insert("editable".into(), Json::Bool(!locked && runtime_here));
        if !locked && !runtime_here {
            out.insert("restartReason".into(), Json::from(row.restart_reason));
        }
        if locked {
            out.insert(
                "editRefusal".into(),
                Json::from(
                    "\"realms.maxCount\" can be set only in the default realm, by a service administrator. Open \
                     /admin/realms there, or POST /admin-api/config/set with no realm prefix.",
                ),
            );
        }
        if let Some(env) = row.env {
            out.insert("env".into(), Json::from(env));
        }
        if let Some(env) = row.legacy_env {
            out.insert("legacyEnv".into(), Json::from(env));
        }
        out.insert("appconfigPath".into(), Json::from(row.path.unwrap_or(key)));
        let dflt = self.default_of(row);
        out.insert("default".into(), dflt);
        out.insert(
            "realmSettable".into(),
            Json::Bool(
                !Settings::is_per_process(key) && !key.starts_with("realms."),
            ),
        );
        out.insert(
            "overridden".into(),
            Json::Bool(self.settings.runtime_overrides().contains_key(key)),
        );
        Json::Object(out)
    }

    /// `describe()` of a key the caller has checked.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn describe_key(&self, key: &str) -> Json {
        sts_core::settings::row(key)
            .map(|row| self.describe(row))
            .unwrap_or(Json::Null)
    }

    /// `groups()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn groups(&self) -> Vec<Json> {
        let mut order: Vec<&str> = Vec::new();
        let mut bucket: std::collections::HashMap<&str, Vec<Json>> =
            std::collections::HashMap::new();
        for row in rows() {
            if !bucket.contains_key(row.group) {
                order.push(row.group);
            }
            bucket
                .entry(row.group)
                .or_default()
                .push(self.describe(row));
        }
        order
            .into_iter()
            .map(|g| {
                let mut one = Map::new();
                one.insert("group".into(), Json::from(g));
                one.insert(
                    "settings".into(),
                    Json::Array(bucket.remove(g).unwrap_or_default()),
                );
                Json::Object(one)
            })
            .collect()
    }

    fn masked_groups(groups: Vec<Json>) -> Vec<Json> {
        groups
            .into_iter()
            .map(|mut g| {
                if let Some(Json::Array(list)) = g.get("settings") {
                    let masked: Vec<Json> = list.iter().map(mask_row).collect();
                    if let Some(o) = g.as_object_mut() {
                        o.insert("settings".into(), Json::Array(masked));
                    }
                }
                g
            })
            .collect()
    }

    /// `settingsContext()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn context(&self) -> Json {
        let mut out = Map::new();
        out.insert(
            "configFile".into(),
            self.facts
                .config_file
                .clone()
                .map(Json::from)
                .unwrap_or(Json::Null),
        );
        out.insert(
            "defaultsFile".into(),
            Json::from(self.facts.defaults_file.as_str()),
        );
        out.insert(
            "persistsAppconfig".into(),
            Json::Bool(self.facts.persists_appconfig),
        );
        out.insert(
            "persistsRealms".into(),
            Json::Bool(self.facts.persists_realms),
        );
        out.insert(
            "persistenceMode".into(),
            Json::from(self.facts.persistence_mode.as_str()),
        );
        out.insert("inRealm".into(), Json::Bool(!self.in_default()));
        out.insert("realmId".into(), Json::from(self.realm));
        Json::Object(out)
    }

    /// `configSettingsJson(page)`: a page's settings block.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn settings_block(&self, page: &str) -> Json {
        let home = tables().page_settings.get(page);
        let wanted: Vec<String> =
            home.map(|h| h.groups.clone()).unwrap_or_default();
        let groups: Vec<Json> = self
            .groups()
            .into_iter()
            .filter(|g| {
                g.get("group")
                    .and_then(Json::as_str)
                    .is_some_and(|n| wanted.iter().any(|w| w == n))
            })
            .collect();
        let groups = ConfigView::masked_groups(groups);
        let all: Vec<&Json> = groups
            .iter()
            .flat_map(|g| {
                g.get("settings")
                    .and_then(Json::as_array)
                    .into_iter()
                    .flatten()
            })
            .collect();
        let mut out = Map::new();
        out.insert("page".into(), Json::from(page));
        out.insert("groups".into(), Json::Array(groups.clone()));
        out.insert("settingCount".into(), Json::from(all.len()));
        out.insert(
            "editableCount".into(),
            Json::from(
                all.iter()
                    .filter(|s| s.get("editable") == Some(&Json::Bool(true)))
                    .count(),
            ),
        );
        out.insert(
            "overridden".into(),
            Json::Array(
                all.iter()
                    .filter(|s| s.get("overridden") == Some(&Json::Bool(true)))
                    .filter_map(|s| s.get("key").cloned())
                    .collect(),
            ),
        );
        out.insert(
            "setWith".into(),
            Json::from("POST /admin-api/config/set-many"),
        );
        out.insert("context".into(), self.context());
        out.insert(
            "sharedWith".into(),
            home.map(|h| h.shared_with.clone())
                .unwrap_or(Json::Object(Map::new())),
        );
        Json::Object(out)
    }

    /// `admin.configJson()`: `config.snapshot()`, its groups masked, with
    /// the settings homes and the page's own block.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn config_json(&self, realm_settings: Vec<String>) -> Json {
        let mut out = Map::new();
        out.insert("realm".into(), Json::from(self.realm));
        out.insert("realmSettings".into(), Json::from(realm_settings));
        out.insert(
            "configFile".into(),
            self.facts
                .config_file
                .clone()
                .map(Json::from)
                .unwrap_or(Json::Null),
        );
        out.insert(
            "defaultsFile".into(),
            Json::from(self.facts.defaults_file.as_str()),
        );
        out.insert("settingCount".into(), Json::from(rows().len()));
        out.insert(
            "editableCount".into(),
            Json::from(rows().iter().filter(|r| r.runtime).count()),
        );
        out.insert(
            "overridden".into(),
            Json::Array(
                self.settings
                    .runtime_overrides()
                    .keys()
                    .cloned()
                    .map(Json::from)
                    .collect(),
            ),
        );
        out.insert(
            "groups".into(),
            Json::Array(ConfigView::masked_groups(self.groups())),
        );
        out.insert("homes".into(), tables().homes.clone());
        out.insert("homeProblems".into(), tables().home_problems.clone());
        out.insert("settings".into(), self.settings_block("/admin/config"));
        Json::Object(out)
    }
}
