// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE CHANNEL (`common/mail.ts`): `send()`, the outbox, the claim per
//! attempt, the `mail.deliver` job, the ceilings, a realm's own wording, the
//! preferences and the startup check. Every message is a row in the realm's
//! outbox before anything is attempted; a SENT message loses its body, a
//! dead letter keeps it for its retry.
//!
//! **WHAT NODE'S MODULE STATE BECAME.** The three realm stores
//! (`mail.outbox`, tombstoned and merged by [`compare_rows`];
//! `mail.templates`; `mail.preferences`) are [`MailStore`]; the directory
//! slot `ldap_server.js` filled is [`Directory`], handed in; the realm's
//! name, domain and prefix are [`RealmInfo`]; the claim store is
//! [`Claims`]; the i18n translator a `{ i18n }` or `{ date }` value is
//! resolved by is [`ValueResolver`]; the locale policy is [`LocalePolicy`];
//! a hosted application's advertised base is [`LinkBases`]; the audit log
//! is [`AuditSink`]. The settings and the mode are `sts_core`'s, read where
//! used. The sweep is registered with `sts_cluster`'s scheduler
//! ([`Mail::register_jobs`]).
//!
//! Every refusal carries Node's code and sentence; the audit rows are
//! Node's.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value as Json};
use sts_core::errors::{codes, ErrorCode};
use sts_core::mode::Mode;
use sts_core::settings::Settings;

use crate::compose::OutMessage;
use crate::js;
use crate::templates::{Parts, TemplateSpec, Templates};
use crate::transports::{self, BoxFuture, SendError, Transport};

/// `STATES`.
pub const STATES: [&str; 4] = ["pending", "sent", "captured", "dead"];
/// `TRANSPORTS`.
pub const TRANSPORTS: [&str; 5] = ["capture", "smtp", "ses", "acs", "gmail"];
/// The claim scope an attempt is spent under.
pub const ATTEMPT_SCOPE: &str = "mail.attempt";
/// The scheduler job.
pub const DELIVER_JOB: &str = "mail.deliver";

/// The settings a transport is built from — its fingerprint.
pub const TRANSPORT_KEYS: [&str; 33] = [
    "mail.transport", "mail.from", "mail.smtpPreset", "mail.smtpHost",
    "mail.smtpPort", "mail.smtpTls", "mail.smtpCaFile", "mail.smtpServerName",
    "mail.smtpAuth", "mail.smtpUser", "mail.smtpPasswordProvider",
    "mail.smtpPasswordRef", "mail.smtpPasswordField",
    "mail.smtpClientCertFile", "mail.smtpClientKeyFile", "mail.dkimDomain",
    "mail.dkimSelector", "mail.dkimAlgorithm", "mail.dkimKeyProvider",
    "mail.dkimKeyRef", "mail.dkimKeyField", "mail.sesRegion",
    "mail.sesConfigurationSet", "mail.acsEndpoint", "mail.acsAuth",
    "mail.acsConnectionStringProvider", "mail.acsConnectionStringRef",
    "mail.acsConnectionStringField", "mail.gmailSender",
    "mail.gmailKeyProvider", "mail.gmailKeyRef", "mail.gmailKeyField",
    "mail.timeoutMs",
];

/// One outbox row, as Node stores it (the compatible upgrade reads a 1.x
/// row as it is).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Message {
    pub id: String,
    pub realm: String,
    pub username: String,
    pub to: String,
    pub category: String,
    pub template: String,
    pub lang: String,
    pub dedup: String,
    pub subject: String,
    pub text: String,
    pub html: String,
    pub from: String,
    pub from_name: String,
    pub message_id: String,
    pub via: String,
    pub actor: String,
    pub state: String,
    pub transport: String,
    pub generation: i64,
    pub attempts: i64,
    pub in_flight: i64,
    pub fence_at: i64,
    pub holder: String,
    pub error_code: String,
    pub why: String,
    pub provider_id: String,
    pub queued_at: i64,
    pub next_attempt_at: i64,
    pub last_attempt_at: i64,
    pub finished_at: i64,
    pub updated_at: i64,
}

fn rank_of(r: &Message) -> [i64; 5] {
    [
        r.generation,
        r.attempts.max(r.in_flight),
        r.fence_at,
        if r.state == "pending" { 0 } else { 1 },
        r.updated_at,
    ]
}

/// `compareRows(a, b)`: which of two copies is newer — generation,
/// attempt, fence, final over pending, then last update. The store's
/// `mergeRow` keeps the greater.
#[tracing::instrument(level = "debug", skip_all)]
pub fn compare_rows(a: &Message, b: &Message) -> std::cmp::Ordering {
    rank_of(a).cmp(&rank_of(b))
}

/// The three realm stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Store {
    /// `mail.outbox`: persisted, tombstoned, merged by [`compare_rows`].
    Outbox,
    /// `mail.templates`, keyed `<template>:<language>`.
    Templates,
    /// `mail.preferences`, keyed by username.
    Preferences,
}

/// A realm's maps (`realms.map({ persist })`), in insertion order.
pub trait MailStore: Send + Sync {
    fn get(&self, realm: &str, store: Store, key: &str) -> Option<Json>;
    fn set(&self, realm: &str, store: Store, key: &str, value: Json);
    fn delete(&self, realm: &str, store: Store, key: &str);
    fn entries(&self, realm: &str, store: Store) -> Vec<(String, Json)>;
}

/// The in-memory store a test and a development process use.
#[derive(Default)]
pub struct MemoryStore {
    maps: Mutex<HashMap<(String, Store), IndexMap<String, Json>>>,
}

impl MailStore for MemoryStore {
    fn get(&self, realm: &str, store: Store, key: &str) -> Option<Json> {
        let maps = self.maps.lock().unwrap_or_else(|p| p.into_inner());
        maps.get(&(realm.to_string(), store))?.get(key).cloned()
    }
    fn set(&self, realm: &str, store: Store, key: &str, value: Json) {
        let mut maps = self.maps.lock().unwrap_or_else(|p| p.into_inner());
        maps.entry((realm.to_string(), store))
            .or_default()
            .insert(key.to_string(), value);
    }
    fn delete(&self, realm: &str, store: Store, key: &str) {
        let mut maps = self.maps.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(map) = maps.get_mut(&(realm.to_string(), store)) {
            map.shift_remove(key);
        }
    }
    fn entries(&self, realm: &str, store: Store) -> Vec<(String, Json)> {
        let maps = self.maps.lock().unwrap_or_else(|p| p.into_inner());
        maps.get(&(realm.to_string(), store))
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default()
    }
}

/// THE DIRECTORY (Node's slot, filled by `ldap/ldap_server.js`): an entry's
/// attributes, name → values, or `None`.
pub trait Directory: Send + Sync {
    fn person_entry(&self, username: &str) -> Option<Map<String, Json>>;
    fn group_entry(&self, dn: &str) -> Option<Map<String, Json>>;
}

/// The ambient realm.
pub trait RealmInfo: Send + Sync {
    fn id(&self) -> String;
    /// Its display name (`realm.name`), `''` for none.
    fn name(&self) -> String;
    /// Its DNS domain (`realms.domainOf()`).
    fn domain(&self) -> String;
    /// Its path prefix (`realms.currentPrefix()`).
    fn prefix(&self) -> String;
}

/// What a claim answered (`cluster/claims`).
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimAnswer {
    pub ok: bool,
    /// `store` when the claim store could not be reached.
    pub reason: String,
    pub claimed_at: i64,
}

/// The claim store an attempt is spent under.
pub trait Claims: Send + Sync {
    fn claim<'a>(
        &'a self,
        scope: &'a str,
        value: &'a str,
        ttl_ms: i64,
        realm: &'a str,
    ) -> BoxFuture<'a, ClaimAnswer>;
}

/// `resolveValues()`'s i18n half: a value given as `{ i18n, params }` or
/// `{ date }` made words in the languages given (#539). The runtime's
/// implementation is the i18n translator's.
pub trait ValueResolver: Send + Sync {
    fn resolve(&self, given: &Map<String, Json>, langs: &[String])
        -> Map<String, Json>;
}

/// `locale_policy.defaultLocaleFor(application, person)`.
pub trait LocalePolicy: Send + Sync {
    fn default_locale_for(&self, application: &str, person: &str) -> String;
}

/// A hosted application's advertised base for a path (`linkOn()`), `None`
/// where the path is the main port's.
pub trait LinkBases: Send + Sync {
    fn advertised_base(&self, path: &str) -> Option<String>;
}

/// The audit log: one event, as Node's `audit.audit()` takes it.
pub trait AuditSink: Send + Sync {
    fn audit(&self, event: Json);
}

/// `transports.build(cfg)`: the realm's transport, its secrets read.
pub trait TransportBuilder: Send + Sync {
    fn build<'a>(
        &'a self,
        cfg: &'a Json,
    ) -> BoxFuture<'a, Result<Arc<dyn Transport>, SendError>>;
}

/// Everything the channel is built from.
pub struct MailDeps {
    pub settings: Arc<Settings>,
    pub mode: Arc<Mode>,
    pub store: Arc<dyn MailStore>,
    pub directory: Arc<dyn Directory>,
    pub realm: Arc<dyn RealmInfo>,
    pub claims: Arc<dyn Claims>,
    pub resolver: Arc<dyn ValueResolver>,
    pub locales: Arc<dyn LocalePolicy>,
    pub links: Arc<dyn LinkBases>,
    pub audit: Arc<dyn AuditSink>,
    pub transports: Arc<dyn TransportBuilder>,
    pub administrators: Arc<dyn Fn() -> Vec<String> + Send + Sync>,
    pub now: Arc<dyn Fn() -> i64 + Send + Sync>,
    /// A fresh outbox id: sixteen random bytes, base64url.
    pub id: Arc<dyn Fn() -> String + Send + Sync>,
    /// This process's name on a claimed row (`hostname:processTag`).
    pub holder: String,
}

/// What `send()` asks for.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SendRequest {
    pub username: String,
    pub to_administrators: bool,
    pub group_dn: String,
    pub template: String,
    pub values: Map<String, Json>,
    pub links: Map<String, Json>,
    pub dedup_key: String,
    pub via: String,
    pub actor: String,
    /// For `sendToFormerAddress()`.
    pub former_address: String,
    /// Whether the request named a template at all (Node's audit row says
    /// `undefined` for one that did not).
    pub has_template: bool,
}

impl SendRequest {
    /// From Node's request object.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn from_json(v: &Json) -> SendRequest {
        let text = |k: &str| js::text_or_empty(v.get(k)).to_string();
        let map = |k: &str| {
            v.get(k).and_then(Json::as_object).cloned().unwrap_or_default()
        };
        SendRequest {
            username: text("username"),
            to_administrators: v
                .get("toAdministrators")
                .is_some_and(|b| b.as_bool() == Some(true)),
            group_dn: text("groupDn"),
            template: text("template"),
            values: map("values"),
            links: map("links"),
            dedup_key: text("dedupKey"),
            via: text("via"),
            actor: text("actor"),
            former_address: text("formerAddress"),
            has_template: v.get("template").is_some_and(|t| !t.is_null()),
        }
    }
}

/// What `send()` answers: `{ ok, queued, refused, duplicates, error }`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SendResult {
    pub ok: bool,
    pub queued: Vec<Json>,
    pub refused: Vec<Refused>,
    pub duplicates: Vec<Json>,
    pub error: Option<String>,
}

/// One refused recipient: its code and Node's sentence.
#[derive(Debug, Clone, PartialEq)]
pub struct Refused {
    pub username: String,
    pub code: ErrorCode,
    pub why: String,
}

impl SendResult {
    /// The answer as Node serialises it.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn to_json(&self) -> Json {
        let mut out = json!({
            "ok": self.ok,
            "queued": self.queued,
            "refused": self.refused.iter().map(|r| json!({
                "username": r.username, "code": r.code.as_str(),
                "why": r.why })).collect::<Vec<_>>(),
            "duplicates": self.duplicates,
        });
        if let Some(e) = &self.error {
            out["error"] = json!(e);
        }
        out
    }
}

/// A refusal of an act (`errorCodes.mark({ ok: false, errors }, code)`).
#[derive(Debug, Clone, PartialEq)]
pub struct ActRefusal {
    pub code: ErrorCode,
    pub errors: Vec<String>,
}

/// A recipient as the channel sees them.
#[derive(Debug, Clone, PartialEq)]
pub struct Recipient {
    pub username: String,
    pub address: String,
    pub verified: bool,
    pub language: String,
    pub name: String,
    pub group: bool,
}

fn first(attrs: &Map<String, Json>, name: &str) -> String {
    match attrs.get(name) {
        Some(Json::Array(values)) => values
            .iter()
            .find_map(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        Some(Json::String(s)) => s.clone(),
        _ => String::new(),
    }
}

fn iso(ms: i64) -> String {
    if ms == 0 {
        return String::new();
    }
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|at| at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        .unwrap_or_default()
}

/// The channel.
pub struct Mail {
    deps: MailDeps,
    built: Mutex<HashMap<String, (String, Arc<dyn Transport>)>>,
    build_problems: Mutex<HashMap<String, (i64, String)>>,
    in_flight_here: Mutex<i64>,
}

impl Mail {
    /// From its dependencies.
    pub fn new(deps: MailDeps) -> Mail {
        Mail {
            deps,
            built: Mutex::new(HashMap::new()),
            build_problems: Mutex::new(HashMap::new()),
            in_flight_here: Mutex::new(0),
        }
    }

    fn text(&self, key: &str) -> String {
        self.deps.settings.value_of(key).as_str().to_string()
    }

    fn int(&self, key: &str) -> i64 {
        self.deps.settings.value_of(key).as_int()
    }

    fn now(&self) -> i64 {
        (self.deps.now)()
    }

    fn templates() -> Option<&'static Templates> {
        Templates::get()
    }

    /// `effectiveTransport()`: `default` is `capture` in development and
    /// `off` in product.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn effective_transport(&self) -> String {
        let named = self.text("mail.transport");
        let named = if named.is_empty() { "default".to_string() } else { named };
        if named == "default" {
            return if self.deps.mode.captures_mail() {
                "capture".to_string()
            } else {
                "off".to_string()
            };
        }
        named
    }

    /// `available()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn available(&self) -> bool {
        let t = self.effective_transport();
        t != "off" && !(t == "capture" && !self.deps.mode.captures_mail())
    }

    /// `fromAddress()`: `mail.from`, or `no-reply@` the realm's domain.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn from_address(&self) -> String {
        let set = js::trim(&self.text("mail.from")).to_string();
        if !set.is_empty() {
            return set;
        }
        let domain = self.deps.realm.domain();
        format!(
            "no-reply@{}",
            if domain.is_empty() { "localhost" } else { domain.as_str() }
        )
    }

    /// `transportConfig()`: the settings a transport is built from, presets
    /// applied, the From address defaulted.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn transport_config(&self) -> Json {
        let mut cfg = Map::new();
        cfg.insert("setting".into(), json!(self.text("mail.transport")));
        for key in TRANSPORT_KEYS {
            let value = self.deps.settings.value_of(key);
            let name = key.trim_start_matches("mail.");
            let row = sts_core::settings::row(key);
            let as_json = match row.map(|r| r.kind.as_str()) {
                Some("int") | Some("port") => json!(value.as_int()),
                Some("bool") => json!(value.as_bool()),
                _ => json!(value.as_str()),
            };
            cfg.insert(name.into(), as_json);
        }
        cfg.insert("transport".into(), json!(self.effective_transport()));
        cfg.insert("from".into(), json!(self.from_address()));
        let preset = cfg.get("smtpPreset").and_then(Json::as_str).unwrap_or("");
        let host_empty = cfg
            .get("smtpHost")
            .and_then(Json::as_str)
            .is_none_or(str::is_empty);
        let preset_host = match preset {
            "google-workspace-relay" => Some("smtp-relay.gmail.com".to_string()),
            "aws-ses-smtp" => {
                let region = cfg.get("sesRegion").and_then(Json::as_str)
                    .filter(|r| !r.is_empty()).unwrap_or("us-east-1");
                Some(format!("email-smtp.{}.amazonaws.com", region))
            }
            _ => None,
        };
        if let (Some(host), true) = (preset_host, host_empty) {
            cfg.insert("smtpHost".into(), json!(host));
            cfg.insert("smtpPort".into(), json!(587));
            cfg.insert("smtpTls".into(), json!("starttls"));
        }
        cfg.insert("realm".into(), json!(self.deps.realm.id()));
        Json::Object(cfg)
    }

    /// `fingerprint(cfg)`: a digest of what a transport was built from.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn fingerprint(cfg: &Json) -> String {
        let mut values: Vec<Json> = TRANSPORT_KEYS
            .iter()
            .map(|k| cfg.get(k.trim_start_matches("mail.")).cloned()
                 .unwrap_or(Json::Null))
            .collect();
        for k in ["transport", "smtpHost", "smtpPort"] {
            values.push(cfg.get(k).cloned().unwrap_or(Json::Null));
        }
        let text = Json::Array(values).to_string();
        sts_crypto::b64::encode(
            &sts_crypto::jws_alg::Hash::Sha256.digest(text.as_bytes()),
        )
    }

    /// `transport()`: the realm's transport, built the first time and
    /// again whenever its settings change; capture is refused in product.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn transport(&self) -> Result<Arc<dyn Transport>, SendError> {
        let cfg = self.transport_config();
        let realm = self.deps.realm.id();
        if cfg["transport"] == "capture" && !self.deps.mode.captures_mail() {
            return Err(SendError::new(
                "mail.transport is \"capture\", which product mode refuses: \
                 a captured message puts its body on the console",
                codes::STS_MAIL_0003,
                false,
            ));
        }
        let print = Mail::fingerprint(&cfg);
        let held = self
            .built
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&realm)
            .cloned();
        if let Some((p, t)) = &held {
            if p == &print {
                return Ok(t.clone());
            }
        }
        match self.deps.transports.build(&cfg).await {
            Ok(made) => {
                self.built
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(realm.clone(), (print, made.clone()));
                self.build_problems
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&realm);
                Ok(made)
            }
            Err(e) => {
                self.build_problems
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(realm, (self.now(), e.message.clone()));
                Err(e)
            }
        }
    }

    /// `linkBase()`: `global.publicBaseUrl` and the realm's prefix; with
    /// that empty, the listener's address in development and `''` in
    /// product.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn link_base(&self) -> String {
        let pinned = js::trim(&self.text("global.publicBaseUrl"))
            .trim_end_matches('/')
            .to_string();
        if !pinned.is_empty() {
            return pinned + &self.deps.realm.prefix();
        }
        if !self.deps.mode.mails_links_from_listener_address() {
            return String::new();
        }
        let bound = self.text("global.host");
        let bound = bound.trim_start_matches('[').trim_end_matches(']');
        let host = if bound.is_empty() || bound == "0.0.0.0" || bound == "::" {
            "localhost".to_string()
        } else if bound.contains(':') {
            format!("[{}]", bound)
        } else {
            bound.to_string()
        };
        format!(
            "{}://{}:{}{}",
            if self.deps.settings.value_of("global.https").as_bool() {
                "https"
            } else {
                "http"
            },
            host,
            self.int("global.port"),
            self.deps.realm.prefix()
        )
    }

    fn link_on(&self, base: &str, path: &str) -> String {
        match self.deps.links.advertised_base(path) {
            Some(own) if !own.is_empty() => {
                format!("{}{}{}", own, self.deps.realm.prefix(), path)
            }
            _ => format!("{}{}", base, path),
        }
    }

    /// `recipient(username)`: their address, whether it is verified, their
    /// language.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn recipient(&self, username: &str) -> Option<Recipient> {
        if username.is_empty() {
            return None;
        }
        let attrs = self.deps.directory.person_entry(username)?;
        let address = js::trim(&first(&attrs, "mail")).to_string();
        let verified = js::trim(&first(&attrs, "stsMailVerified")).to_string();
        let display = first(&attrs, "displayName");
        let cn = first(&attrs, "cn");
        Some(Recipient {
            username: username.to_string(),
            verified: !address.is_empty()
                && verified.to_lowercase() == address.to_lowercase(),
            address,
            language: first(&attrs, "preferredLanguage"),
            name: if !display.is_empty() {
                display
            } else if !cn.is_empty() {
                cn
            } else {
                username.to_string()
            },
            group: false,
        })
    }

    /// `groupRecipient(dn)` (#989): the group's own `mail`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn group_recipient(&self, dn: &str) -> Option<Recipient> {
        if dn.is_empty() {
            return None;
        }
        let attrs = self.deps.directory.group_entry(dn)?;
        let address = js::trim(&first(&attrs, "mail")).to_string();
        let cn = first(&attrs, "cn");
        Some(Recipient {
            username: dn.to_string(),
            verified: !address.is_empty(),
            address,
            language: String::new(),
            name: if cn.is_empty() { dn.to_string() } else { cn },
            group: true,
        })
    }

    /// `declined(username)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn declined(&self, username: &str) -> Vec<String> {
        self.deps
            .store
            .get(&self.deps.realm.id(), Store::Preferences, username)
            .and_then(|held| held.get("declined").cloned())
            .and_then(|d| serde_json::from_value(d).ok())
            .unwrap_or_default()
    }

    /// `setDeclined(username, category, decline, actor)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn set_declined(
        &self,
        username: &str,
        category: &str,
        decline: bool,
        actor: &str,
    ) -> Result<Json, ActRefusal> {
        let t = Mail::templates();
        let cat = t.and_then(|t| t.category(category));
        let Some(cat) = cat.filter(|c| c.optional) else {
            let sentence = match cat {
                Some(c) => format!(
                    "{} cannot be declined: {}",
                    c.label,
                    if c.id == "security" {
                        "a person is always told what happened to their \
                         account."
                    } else {
                        "a link is only sent when somebody asked for it."
                    }
                ),
                None => format!("There is no category \"{}\".", category),
            };
            return Err(ActRefusal {
                code: codes::STS_MAIL_0034,
                errors: vec![sentence],
            });
        };
        let mut set: Vec<String> = self
            .declined(username)
            .into_iter()
            .filter(|one| one != &cat.id)
            .collect();
        if decline {
            set.push(cat.id.clone());
        }
        self.deps.store.set(
            &self.deps.realm.id(),
            Store::Preferences,
            username,
            json!({ "declined": set, "at": self.now() }),
        );
        self.deps.audit.audit(json!({
            "action": "mail.preferences",
            "actor": if actor.is_empty() { username } else { actor },
            "target": username, "protocol": "Mail", "channel": "http",
            "summary": format!("{}{}{}", username,
                if decline { " declined " } else { " accepted " }, cat.label),
            "detail": { "category": cat.id,
                        "declined": decline.to_string() }
        }));
        Ok(json!({
            "ok": true, "declined": set,
            "message": format!("{}{}.", if decline {
                "You will not be sent "
            } else {
                "You will be sent "
            }, cat.label.to_lowercase())
        }))
    }

    /// `templateFor(id, languages)`: for each language in order, the
    /// realm's own wording, then the built-in translation; else English.
    /// `(spec, parts, lang, own)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn template_for(
        &self,
        id: &str,
        languages: &[String],
    ) -> Option<(TemplateSpec, Parts, String, bool)> {
        let t = Mail::templates()?;
        let spec = t.built_in(id)?.clone();
        let realm = self.deps.realm.id();
        let own = |key: &str| {
            self.deps.store.get(&realm, Store::Templates, key)
                .map(|held| Parts::from_json(&held))
        };
        for lang in languages {
            if let Some(held) = own(&format!("{}:{}", id, lang)) {
                return Some((spec, held, lang.clone(), true));
            }
            if let Some((parts, tag)) = t.built_in_for(id, lang) {
                for one in t.chain_for(lang) {
                    let tag = one.to_lowercase();
                    if let Some(held) = own(&format!("{}:{}", id, tag)) {
                        return Some((spec, held, tag, true));
                    }
                }
                return Some((spec, parts, tag, false));
            }
            if lang == "en" {
                let parts = Parts::of(&spec);
                return Some((spec, parts, "en".to_string(), false));
            }
        }
        let parts = Parts::of(&spec);
        Some((spec, parts, "en".to_string(), false))
    }

    /// `templateView(id, lang)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn template_view(&self, id: &str, lang: &str) -> Option<Json> {
        let t = Mail::templates()?;
        let spec = t.built_in(id)?;
        let tag = if lang.is_empty() { "en".to_string() } else {
            lang.to_lowercase()
        };
        let held = self.deps.store.get(&self.deps.realm.id(), Store::Templates,
                                       &format!("{}:{}", spec.id, tag));
        let parts = held.as_ref().map(Parts::from_json)
            .unwrap_or_else(|| Parts::of(spec));
        let mut values: Vec<String> = t.common().to_vec();
        values.extend(spec.values.iter().cloned());
        Some(json!({
            "id": spec.id, "title": spec.title, "category": spec.category,
            "lang": tag, "own": held.is_some(), "values": values,
            "links": spec.links, "subject": parts.subject, "text": parts.text,
            "html": parts.html
        }))
    }

    /// `listTemplates()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn list_templates(&self) -> Vec<Json> {
        let Some(t) = Mail::templates() else {
            return Vec::new();
        };
        let own = self.deps.store.entries(&self.deps.realm.id(),
                                          Store::Templates);
        t.all().iter().map(|spec| {
            let mut langs: Vec<String> = own.iter().filter_map(|(key, _)| {
                let at = key.find(':')?;
                (key[..at] == spec.id).then(|| key[at + 1..].to_string())
            }).collect();
            langs.sort();
            let mut values: Vec<String> = t.common().to_vec();
            values.extend(spec.values.iter().cloned());
            json!({ "id": spec.id, "title": spec.title,
                    "category": spec.category, "values": values,
                    "links": spec.links, "languages": langs,
                    "builtInLanguages": t.built_in_languages(&spec.id) })
        }).collect()
    }

    /// `saveTemplate(id, lang, parts, actor)`.
    #[tracing::instrument(level = "debug", skip(self, parts))]
    pub fn save_template(
        &self,
        id: &str,
        lang: &str,
        parts: &Json,
        actor: &str,
    ) -> Result<Json, ActRefusal> {
        let t = Mail::templates();
        let spec = t.and_then(|t| t.built_in(id));
        let tag = js::trim(lang).to_lowercase();
        let Some(spec) = spec else {
            return Err(ActRefusal { code: codes::STS_MAIL_0017,
                errors: vec![format!("There is no message \"{}\".", id)] });
        };
        let tag_ok = regex::Regex::new(r"^[a-z]{1,8}(-[a-z0-9]{1,8})*$")
            .is_ok_and(|re| re.is_match(&tag));
        if !tag_ok {
            return Err(ActRefusal { code: codes::STS_MAIL_0016,
                errors: vec![format!("\"{}\" is not a BCP 47 language tag.",
                                     lang)] });
        }
        let given = Parts::from_json(parts);
        let problem = Templates::problem(Some(spec), &given);
        if !problem.is_empty() {
            return Err(ActRefusal { code: codes::STS_MAIL_0016,
                errors: vec![format!("The {} ({}) template was not saved: \
                                      {}.", spec.id, tag, problem)] });
        }
        let raw = |k: &str| js::text_or_empty(parts.get(k));
        self.deps.store.set(&self.deps.realm.id(), Store::Templates,
            &format!("{}:{}", spec.id, tag), json!({
                "subject": raw("subject"), "text": raw("text"),
                "html": raw("html"), "savedAt": self.now(),
                "savedBy": actor }));
        self.deps.audit.audit(json!({
            "action": "mail.template", "actor": actor,
            "target": format!("{}:{}", spec.id, tag), "protocol": "Mail",
            "channel": "http",
            "summary": format!("the {} message was reworded in {}", spec.id,
                               tag) }));
        Ok(json!({ "ok": true, "message": format!(
            "The {} message in {} is this realm's own wording now.", spec.id,
            tag) }))
    }

    /// `resetTemplate(id, lang, actor)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn reset_template(
        &self,
        id: &str,
        lang: &str,
        actor: &str,
    ) -> Result<Json, ActRefusal> {
        let spec = Mail::templates().and_then(|t| t.built_in(id));
        let tag = js::trim(lang).to_lowercase();
        let realm = self.deps.realm.id();
        let key = spec.map(|s| format!("{}:{}", s.id, tag));
        let held = key.as_ref().and_then(|k| {
            self.deps.store.get(&realm, Store::Templates, k)
        });
        let (Some(spec), Some(key), Some(_)) = (spec, key, held) else {
            return Err(ActRefusal { code: codes::STS_MAIL_0017,
                errors: vec![format!("This realm has no wording of its own \
                                      for \"{}\" in \"{}\".", id, tag)] });
        };
        self.deps.store.delete(&realm, Store::Templates, &key);
        self.deps.audit.audit(json!({
            "action": "mail.template", "actor": actor, "target": key,
            "protocol": "Mail", "channel": "http",
            "summary": format!("the {} message in {} was put back to the \
                                built-in wording", spec.id, tag) }));
        Ok(json!({ "ok": true, "message": format!(
            "The {} message in {} is the built-in wording again.", spec.id,
            tag) }))
    }

    fn refuse(&self, req: &SendRequest, username: &str, code: ErrorCode,
              why: String) -> Refused {
        let named = !req.template.is_empty() || req.has_template;
        let mut detail = Map::new();
        if named {
            detail.insert("template".into(), json!(req.template));
        }
        detail.insert("via".into(), json!(req.via));
        self.deps.audit.audit(json!({
            "action": "mail.refused", "outcome": "refused",
            "errorCode": code.as_str(), "actor": req.actor,
            "target": username, "protocol": "Mail", "channel": "internal",
            "summary": format!("a {} message for {} was not queued: {}",
                if named { req.template.as_str() } else { "undefined" },
                if username.is_empty() { "?" } else { username }, why),
            "detail": detail
        }));
        Refused { username: username.to_string(), code, why }
    }
}

/// One recipient's outcome in `queueOne()`.
enum Queued {
    Row(Json),
    Duplicate(Json),
    Refused(Refused),
}

impl Mail {
    fn recent_counts(&self, realm: &str, username: &str, category: &str)
        -> (i64, i64) {
        let since = self.now() - self.int("mail.rateWindowS") * 1000;
        let (mut all, mut cat) = (0, 0);
        for (_, row) in self.deps.store.entries(realm, Store::Outbox) {
            let row: Message = serde_json::from_value(row).unwrap_or_default();
            if row.username == username && row.queued_at >= since {
                all += 1;
                if row.category == category {
                    cat += 1;
                }
            }
        }
        (all, cat)
    }

    fn duplicate_of(&self, realm: &str, dedup: &str) -> Option<Message> {
        let window = self.int("mail.dedupWindowS") * 1000;
        if dedup.is_empty() || window <= 0 {
            return None;
        }
        let since = self.now() - window;
        self.deps.store.entries(realm, Store::Outbox).into_iter()
            .filter_map(|(_, row)| serde_json::from_value::<Message>(row).ok())
            .find(|row| row.dedup == dedup && row.queued_at >= since)
    }

    /// `send(req)`: every check, then a row per recipient; the queued rows
    /// are attempted by [`Mail::dispatch`].
    #[tracing::instrument(level = "debug", skip(self, req))]
    pub fn send(&self, req: &SendRequest) -> SendResult {
        let mut out = SendResult::default();
        let t = Mail::templates();
        let spec = t.and_then(|t| t.built_in(&req.template))
            .filter(|s| Some(s.id.as_str()) != t.map(|t| t.layout_id()));
        let Some(spec) = spec.cloned() else {
            out.refused.push(self.refuse(req, "", codes::STS_MAIL_0017,
                format!("there is no message \"{}\"", req.template)));
            return out;
        };
        let mut group: Option<Recipient> = None;
        let names: Vec<String> = if req.to_administrators {
            (self.deps.administrators)()
        } else if !req.group_dn.is_empty() {
            group = self.group_recipient(&req.group_dn);
            vec![req.group_dn.clone()]
        } else if !req.username.is_empty() {
            vec![req.username.clone()]
        } else {
            Vec::new()
        };
        if !self.available() {
            for name in &names {
                let why = format!("no mail transport is configured in this \
                                   realm (mail.transport is \"{}\")",
                                  self.text("mail.transport"));
                out.refused.push(self.refuse(req, name, codes::STS_MAIL_0001,
                                             why));
            }
            out.error = Some("no mail transport is configured".into());
            return out;
        }
        let base = if spec.links.is_empty() { String::new() } else {
            self.link_base()
        };
        if !spec.links.is_empty() && base.is_empty() {
            for name in &names {
                out.refused.push(self.refuse(req, name, codes::STS_MAIL_0015,
                    "a link is mailed only on global.publicBaseUrl, which is \
                     empty here, and product mode never builds one from a \
                     request".to_string()));
            }
            out.error = Some("global.publicBaseUrl is not set".into());
            return out;
        }
        for name in &names {
            match self.queue_one(req, &spec, name, &base, None, group.clone())
            {
                Queued::Refused(r) => out.refused.push(r),
                Queued::Duplicate(v) => out.duplicates.push(v),
                Queued::Row(v) => out.queued.push(v),
            }
        }
        out.ok = out.queued.len() + out.duplicates.len() > 0;
        if !out.ok {
            if let Some(first) = out.refused.first() {
                out.error = Some(first.why.clone());
            }
        }
        out
    }

    fn pending_send(&self, req: &SendRequest, template: &str, attr: &str,
                    none: &str) -> SendResult {
        let mut out = SendResult::default();
        let spec = Mail::templates().and_then(|t| t.built_in(template))
            .cloned();
        let (Some(spec), true, true) = (spec, req.template == template,
                                        self.available()) else {
            out.error = Some("no mail transport is configured".into());
            return out;
        };
        let base = self.link_base();
        if base.is_empty() {
            out.error = Some("global.publicBaseUrl is not set".into());
            return out;
        }
        let pending = if req.username.is_empty() { String::new() } else {
            self.deps.directory.person_entry(&req.username)
                .map(|attrs| first(&attrs, attr)).unwrap_or_default()
        };
        if pending.is_empty() {
            out.error = Some(none.to_string());
            return out;
        }
        match self.queue_one(req, &spec, &req.username, &base, Some(&pending),
                             None) {
            Queued::Refused(r) => {
                out.error = Some(r.why.clone());
                out.refused.push(r);
            }
            Queued::Duplicate(v) => out.duplicates.push(v),
            Queued::Row(v) => out.queued.push(v),
        }
        out.ok = out.queued.len() + out.duplicates.len() > 0;
        out
    }

    /// `sendToPendingAddress(req)`: the verification link of a person's
    /// own change of address, to the pending `stsMailVerifyAddress`.
    #[tracing::instrument(level = "debug", skip(self, req))]
    pub fn send_to_pending_address(&self, req: &SendRequest) -> SendResult {
        self.pending_send(req, "address-verification", "stsMailVerifyAddress",
                          "no address change is pending")
    }

    /// `sendToPseudonymAddress(req)` (#644).
    #[tracing::instrument(level = "debug", skip(self, req))]
    pub fn send_to_pseudonym_address(&self, req: &SendRequest) -> SendResult {
        self.pending_send(req, "pseudonym-verification",
                          "stsPseudonymVerifyAddress",
                          "no sign-in name is pending")
    }

    /// `sendToFormerAddress(req)`: `address-changed`, to the address the
    /// entry had.
    #[tracing::instrument(level = "debug", skip(self, req))]
    pub fn send_to_former_address(&self, req: &SendRequest) -> SendResult {
        let mut out = SendResult::default();
        let spec = Mail::templates().and_then(|t| t.built_in("address-changed"))
            .cloned();
        let (Some(spec), true, true) = (spec, req.template == "address-changed",
                                        self.available()) else {
            return out;
        };
        match self.queue_one(req, &spec, &req.username, "",
                             Some(&req.former_address), None) {
            Queued::Refused(r) => out.refused.push(r),
            Queued::Duplicate(v) => out.duplicates.push(v),
            Queued::Row(v) => out.queued.push(v),
        }
        out.ok = out.queued.len() + out.duplicates.len() > 0;
        out
    }

    fn queue_one(&self, req: &SendRequest, spec: &TemplateSpec, username: &str,
                 base: &str, former: Option<&str>,
                 group: Option<Recipient>) -> Queued {
        let realm = self.deps.realm.id();
        let found = group.or_else(|| self.recipient(username));
        let Some(mut who) = found else {
            return Queued::Refused(self.refuse(req, username,
                codes::STS_MAIL_0012,
                format!("there is no entry for \"{}\" in this realm",
                        username)));
        };
        if let Some(former) = former.filter(|f| !f.is_empty()) {
            who.address = former.to_string();
        }
        if who.address.is_empty() {
            return Queued::Refused(self.refuse(req, username,
                codes::STS_MAIL_0011,
                format!("{}'s entry has no mail attribute", username)));
        }
        let bad = transports::address_problem(&who.address);
        if !bad.is_empty() {
            return Queued::Refused(self.refuse(req, username,
                codes::STS_MAIL_0023,
                format!("{}'s mail attribute {}", username, bad)));
        }
        let from_bad = transports::address_problem(&self.from_address());
        if !from_bad.is_empty() {
            return Queued::Refused(self.refuse(req, username,
                codes::STS_MAIL_0023,
                format!("the From address (mail.from) {}", from_bad)));
        }
        let t = Mail::templates();
        let cat = t.and_then(|t| t.category(&spec.category));
        if let Some(cat) = cat {
            if cat.optional && self.declined(username).contains(&cat.id) {
                return Queued::Refused(self.refuse(req, username,
                    codes::STS_MAIL_0013,
                    format!("{} declined {}", username,
                            cat.label.to_lowercase())));
            }
        }
        let dedup = if req.dedup_key.is_empty() { String::new() } else {
            let text = format!("{}\n{}\n{}", username, spec.id, req.dedup_key);
            let digest = sts_crypto::b64::encode(
                &sts_crypto::jws_alg::Hash::Sha256.digest(text.as_bytes()));
            digest.chars().take(22).collect()
        };
        if let Some(dup) = self.duplicate_of(&realm, &dedup) {
            return Queued::Duplicate(self.view(&dup, false));
        }
        let (all, in_cat) = self.recent_counts(&realm, username,
                                               &spec.category);
        let per_all = self.int("mail.ratePerRecipient");
        let per_cat = self.int("mail.ratePerCategory");
        if all >= per_all || in_cat >= per_cat {
            return Queued::Refused(self.refuse(req, username,
                codes::STS_MAIL_0010,
                format!("{} has been sent {} in the last {} seconds, the \
                         ceiling (mail.ratePerRecipient, \
                         mail.ratePerCategory)", username,
                        if all >= per_all {
                            format!("{} message(s)", all)
                        } else {
                            format!("{} {} message(s)", in_cat, spec.category)
                        }, self.int("mail.rateWindowS"))));
        }
        let fallback = self.deps.locales.default_locale_for("",
            if who.group { "" } else { username });
        let languages = Templates::language_order(&who.language,
            if fallback.is_empty() { "en" } else { &fallback });
        let Some((_, parts, lang, _)) = self.template_for(&spec.id, &languages)
        else {
            return Queued::Refused(self.refuse(req, username,
                codes::STS_MAIL_0017,
                format!("there is no message \"{}\"", spec.id)));
        };
        let top = languages.first().cloned().unwrap_or_default();
        let primary = |t: &str| t.split('-').next().unwrap_or("")
            .to_lowercase();
        let value_langs = if !top.is_empty() && !lang.is_empty()
            && primary(&top) == primary(&lang) {
            vec![top, lang.clone()]
        } else {
            vec![lang.clone()]
        };
        let mut values = self.resolve_values(&req.values, &value_langs);
        let realm_name = self.deps.realm.name();
        values.insert("realm".into(), json!(if realm_name.is_empty() {
            realm.clone()
        } else {
            realm_name
        }));
        let given_service = values.get("service").map(|v| match v {
            Json::Null | Json::Bool(false) => false,
            Json::String(s) => !s.is_empty(),
            Json::Number(n) => n.as_f64() != Some(0.0),
            _ => true,
        }).unwrap_or(false);
        if !given_service {
            let domain = self.deps.realm.domain();
            values.insert("service".into(), json!(if domain.is_empty() {
                "this service".to_string()
            } else {
                domain
            }));
        }
        for name in &spec.links {
            let path = js::text_or_empty(req.links.get(name));
            let ok = path.starts_with('/') && !path.starts_with("//")
                && !path.chars().any(|c| js::is_space(c) || c == '\\');
            values.insert(name.clone(), json!(if ok {
                self.link_on(base, &path)
            } else {
                String::new()
            }));
        }
        let body = Templates::render(&parts, &values);
        let mut layout_langs = vec![lang.clone()];
        layout_langs.extend(languages.iter().cloned());
        let layout_id = t.map_or("layout", |t| t.layout_id()).to_string();
        let rendered = match self.template_for(&layout_id, &layout_langs) {
            Some((_, layout, layout_lang, _)) => {
                let mut with = values.clone();
                with.insert("reason".into(), json!(match (t, cat) {
                    (Some(t), Some(c)) => t.reason_for(&c.id, &layout_lang),
                    _ => "a message from this service".to_string(),
                }));
                Templates::wrap(&layout, &body, &with)
            }
            None => body,
        };
        let at = self.now();
        let id = (self.deps.id)();
        let from = self.from_address();
        let domain = from.rsplit('@').next().unwrap_or("").to_string();
        let row = Message {
            id: id.clone(), realm: realm.clone(),
            username: username.to_string(), to: who.address.clone(),
            category: spec.category.clone(), template: spec.id.clone(),
            lang: lang.clone(), dedup, subject: rendered.subject.clone(),
            text: rendered.text.clone(),
            html: Templates::html_document(&rendered.html, &lang),
            from, from_name: self.text("mail.fromName"),
            message_id: format!("<{}@{}>", id, domain),
            via: req.via.clone(), actor: req.actor.clone(),
            state: "pending".into(), transport: self.effective_transport(),
            generation: 1, queued_at: at, next_attempt_at: at,
            updated_at: at, ..Message::default()
        };
        let row = self.write_row(row);
        self.deps.audit.audit(json!({
            "action": "mail.queued", "actor": row.actor, "target": username,
            "protocol": "Mail", "channel": "internal",
            "summary": format!("a {} message ({}) was queued for {}", spec.id,
                               spec.category, username),
            "detail": { "message": id, "template": spec.id,
                        "category": spec.category, "to": who.address,
                        "via": row.via, "transport": row.transport }
        }));
        Queued::Row(self.view(&row, false))
    }

    /// `resolveValues(given, lang)`: a plain value as it is; a `{ i18n }`
    /// or `{ date }` value made words through [`ValueResolver`]; any other
    /// object `''`.
    #[tracing::instrument(level = "debug", skip(self, given))]
    pub fn resolve_values(&self, given: &Map<String, Json>, langs: &[String])
        -> Map<String, Json> {
        let langs: Vec<String> = langs.iter().filter(|l| !l.is_empty())
            .cloned().collect();
        let needs = given.values().any(Json::is_object);
        let resolved = if needs {
            self.deps.resolver.resolve(given, &langs)
        } else {
            Map::new()
        };
        given.iter().map(|(name, v)| {
            let value = if v.is_object() {
                resolved.get(name).cloned().unwrap_or(json!(""))
            } else {
                v.clone()
            };
            (name.clone(), value)
        }).collect()
    }

    fn live_row(&self, realm: &str, id: &str) -> Option<Message> {
        self.deps.store.get(realm, Store::Outbox, id)
            .and_then(|v| serde_json::from_value(v).ok())
    }

    fn write_row(&self, row: Message) -> Message {
        self.write_row_checked(row).0
    }

    /// `writeRow()`: the copy that stands, and whether it is the one given
    /// (a newer copy already standing is answered instead).
    fn write_row_checked(&self, mut row: Message) -> (Message, bool) {
        let held = self.live_row(&row.realm, &row.id);
        row.updated_at = self.now().max(held.as_ref()
            .map_or(0, |h| h.updated_at + 1));
        if let Some(held) = held {
            if compare_rows(&row, &held) == std::cmp::Ordering::Less {
                return (held, false);
            }
        }
        self.deps.store.set(&row.realm.clone(), Store::Outbox, &row.id.clone(),
                            serde_json::to_value(&row).unwrap_or(Json::Null));
        (row, true)
    }

    /// `view(row, withBody)`: a row as a page shows it, and its body only
    /// when it was captured and asked for.
    #[tracing::instrument(level = "debug", skip(self, row))]
    pub fn view(&self, row: &Message, with_body: bool) -> Json {
        let mut out = json!({
            "id": row.id, "realm": row.realm, "username": row.username,
            "to": row.to, "category": row.category, "template": row.template,
            "lang": row.lang, "subject": row.subject, "from": row.from,
            "messageId": row.message_id, "via": row.via, "actor": row.actor,
            "state": row.state, "transport": row.transport,
            "generation": row.generation, "attempts": row.attempts,
            "inFlight": row.in_flight != 0, "holder": row.holder,
            "errorCode": row.error_code, "why": row.why,
            "providerId": row.provider_id,
            "bodyKept": !row.text.is_empty() || !row.html.is_empty(),
            "queuedAt": iso(row.queued_at),
            "nextAttemptAt": iso(row.next_attempt_at),
            "lastAttemptAt": iso(row.last_attempt_at),
            "finishedAt": iso(row.finished_at)
        });
        if with_body && row.state == "captured" {
            out["text"] = json!(row.text);
            out["html"] = json!(row.html);
        }
        out
    }

    /// `message(id)`: one row, with its body when it was captured.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn message(&self, id: &str) -> Option<Json> {
        self.live_row(&self.deps.realm.id(), id).map(|r| self.view(&r, true))
    }

    /// `list(options)`: newest first.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn list(&self, state: &str, username: &str, q: &str) -> Vec<Json> {
        let q = q.to_lowercase();
        let mut rows: Vec<Message> = self.deps.store
            .entries(&self.deps.realm.id(), Store::Outbox).into_iter()
            .filter_map(|(_, v)| serde_json::from_value::<Message>(v).ok())
            .filter(|r| state.is_empty() || r.state == state)
            .filter(|r| username.is_empty() || r.username == username)
            .filter(|r| q.is_empty() || [r.username.as_str(), &r.to,
                &r.template, &r.error_code, &r.subject].join(" ")
                .to_lowercase().contains(&q))
            .collect();
        rows.sort_by(|a, b| b.queued_at.cmp(&a.queued_at)
            .then(a.id.cmp(&b.id)));
        rows.iter().map(|r| self.view(r, false)).collect()
    }

    fn finish(&self, mut row: Message, state: &str, code: &str, why: &str)
        -> Message {
        row.state = state.to_string();
        row.error_code = code.to_string();
        row.why = why.to_string();
        row.finished_at = self.now();
        row.in_flight = 0;
        row.next_attempt_at = 0;
        if state == "sent" {
            row.text.clear();
            row.html.clear();
        }
        let (written, ours) = self.write_row_checked(row.clone());
        if written.state != state || !ours {
            return written;
        }
        let row = written.clone();
        let dead = state == "dead";
        self.deps.audit.audit(json!({
            "action": if dead { "mail.dead" } else { "mail.sent" },
            "outcome": if dead { "error" } else { "success" },
            "errorCode": if dead { code } else { "" },
            "summarised": true, "actor": row.actor, "target": row.username,
            "protocol": "Mail", "channel": "internal",
            "summary": if dead {
                format!("a {} message for {} was not delivered and is a dead \
                         letter: {}", row.template, row.username, why)
            } else {
                format!("a {} message for {} was {}", row.template,
                    row.username, if state == "captured" {
                        "captured (development: not sent)".to_string()
                    } else {
                        format!("accepted by the {} transport", row.transport)
                    })
            },
            "detail": { "message": row.id, "template": row.template,
                "category": row.category, "to": row.to,
                "transport": row.transport,
                "attempts": row.attempts.to_string(),
                "generation": row.generation.to_string(), "state": state,
                "providerId": row.provider_id }
        }));
        written
    }

    fn lease_ms(&self) -> i64 {
        self.int("mail.leaseMs").max(self.int("mail.timeoutMs") + 2000)
    }

    /// `attempt(realm, id)`: one attempt of one message, claimed. `sent`,
    /// `captured`, `retry`, `dead`, or why nothing was done (`not-due`,
    /// `claimed-elsewhere`, `deferred`, `gone`).
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn attempt(&self, realm: &str, id: &str) -> String {
        let Some(before) = self.live_row(realm, id)
            .filter(|r| r.state == "pending") else {
            return "gone".into();
        };
        if before.next_attempt_at > self.now() {
            return "not-due".into();
        }
        let n = if before.in_flight != 0 { before.in_flight } else {
            before.attempts + 1
        };
        let lease = self.lease_ms();
        let value = format!("{}:{}:{}", id, before.generation, n);
        let answer = self.deps.claims.claim(ATTEMPT_SCOPE, &value, lease,
                                            realm).await;
        if !answer.ok {
            return if answer.reason == "store" { "deferred".into() } else {
                "claimed-elsewhere".into()
            };
        }
        let Some(mut row) = self.live_row(realm, id).filter(|r| {
            r.state == "pending" && r.generation == before.generation
        }) else {
            return "gone".into();
        };
        let started = self.now();
        let fence = if answer.claimed_at != 0 { answer.claimed_at } else {
            started
        };
        row.in_flight = n;
        row.fence_at = fence;
        row.holder = self.deps.holder.clone();
        row.last_attempt_at = started;
        row.next_attempt_at = started + lease;
        let row = self.write_row(row);
        if row.fence_at != fence || row.in_flight != n {
            return "claimed-elsewhere".into();
        }
        let message = OutMessage {
            from: row.from.clone(), from_name: row.from_name.clone(),
            to: row.to.clone(), subject: row.subject.clone(),
            text: row.text.clone(), html: row.html.clone(),
            message_id: row.message_id.clone(), date_ms: row.queued_at,
            lang: row.lang.clone(),
        };
        let mut transport_name = row.transport.clone();
        let outcome = match self.transport().await {
            Ok(transport) => {
                transport_name = transport.name().to_string();
                transport.send(&message).await
            }
            Err(e) => Err(e),
        };
        let Some(mut current) = self.live_row(realm, id).filter(|c| {
            c.fence_at == fence && c.generation == row.generation
        }) else {
            return "claimed-elsewhere".into();
        };
        current.attempts = n;
        current.in_flight = 0;
        current.transport = transport_name.clone();
        let failure = match outcome {
            Ok(sent) => {
                current.provider_id = sent.provider_id;
                let state = if transport_name == "capture" { "captured" } else {
                    "sent"
                };
                self.finish(current, state, "", "");
                return state.into();
            }
            Err(e) => e,
        };
        let code = failure.code;
        let retry = failure.retry.unwrap_or(code == codes::STS_MAIL_0004
            || code == codes::STS_MAIL_0006);
        let worth = retry || code == codes::STS_MAIL_0004
            || code == codes::STS_MAIL_0006 || code == codes::STS_MAIL_0007;
        let attempts = self.int("mail.attempts").max(1);
        if !worth || n >= attempts {
            let why = format!("{}{}", failure.message, if n > 1 {
                format!(" (after {} attempts)", n)
            } else {
                String::new()
            });
            self.finish(current, "dead", code.as_str(), &why);
            return "dead".into();
        }
        let backoff = self.int("mail.backoffS").max(1) * 1000
            * 2i64.pow((n - 1).clamp(0, 30) as u32);
        current.error_code = code.as_str().to_string();
        current.why = format!("{} (attempt {}; trying again)",
                              failure.message, n);
        current.next_attempt_at = self.now() + backoff;
        self.write_row(current);
        "retry".into()
    }

    /// `dispatch(rows)`: attempt what was just queued.
    #[tracing::instrument(level = "debug", skip(self, rows))]
    pub async fn dispatch(&self, rows: &[Json]) {
        let realm = self.deps.realm.id();
        for row in rows {
            if row.get("state").and_then(Json::as_str) != Some("pending") {
                continue;
            }
            let id = row.get("id").and_then(Json::as_str).unwrap_or("");
            let at = row.get("realm").and_then(Json::as_str)
                .filter(|r| !r.is_empty()).unwrap_or(&realm).to_string();
            self.attempt(&at, id).await;
        }
    }

    /// `retry(id, actor)`: a dead letter queued again, as generation + 1.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn retry(&self, id: &str, actor: &str) -> Result<Json, ActRefusal> {
        let refuse = |why: String| Err(ActRefusal {
            code: codes::STS_MAIL_0018, errors: vec![why] });
        let realm = self.deps.realm.id();
        let Some(row) = self.live_row(&realm, id) else {
            return refuse(format!("There is no message \"{}\" in this realm's \
                                   outbox; retention may have removed it.",
                                  id));
        };
        if row.state != "dead" {
            return refuse(format!("The message to {} is {}, not a dead \
                                   letter; only a dead letter is retried by \
                                   hand.", row.username, row.state));
        }
        if row.text.is_empty() && row.html.is_empty() {
            return refuse(format!("The message to {} kept no body, so it \
                                   cannot be sent again.", row.username));
        }
        let who = self.recipient(&row.username);
        let Some(who) = who.filter(|w| !w.address.is_empty()
            && transports::address_problem(&w.address).is_empty()) else {
            return refuse(format!("{} has no usable mail address now, so a \
                                   retry would fail the same way.",
                                  row.username));
        };
        let at = self.now();
        let fresh = Message {
            to: who.address.clone(), state: "pending".into(),
            generation: row.generation + 1, attempts: 0, in_flight: 0,
            fence_at: 0, holder: String::new(), error_code: String::new(),
            why: format!("retried by {}", if actor.is_empty() {
                "an administrator"
            } else {
                actor
            }),
            next_attempt_at: at, finished_at: 0,
            transport: self.effective_transport(), ..row.clone()
        };
        let written = self.write_row(fresh);
        self.deps.audit.audit(json!({
            "action": "mail.retry", "actor": actor, "target": row.username,
            "protocol": "Mail", "channel": "http",
            "summary": format!("a dead {} message for {} was queued again \
                                (generation {})", row.template, row.username,
                               written.generation),
            "detail": { "message": row.id, "to": who.address }
        }));
        Ok(json!({ "ok": true, "row": self.view(&written, false),
                   "message": format!("The message to {} was queued again; \
                       it is sent after this answer, and the outbox shows \
                       where it got to.", row.username) }))
    }

    /// `sweepRealm()` for the ambient realm: dead-letter what is stale,
    /// remove finished rows past retention or the cap, attempt what is due
    /// (at most `mail.concurrency` at once). `{ attempted, removed, dead }`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn sweep(&self) -> Json {
        let realm = self.deps.realm.id();
        let at = self.now();
        let keep_ms = self.int("mail.retentionS").max(1) * 1000;
        let cap = self.int("mail.maxRows").max(1);
        let rows = self.deps.store.entries(&realm, Store::Outbox);
        let size = rows.len() as i64;
        let mut due = Vec::new();
        let mut finished = Vec::new();
        let mut stale = Vec::new();
        for (id, row) in rows {
            let Ok(row) = serde_json::from_value::<Message>(row) else {
                continue;
            };
            if row.state == "pending" {
                if at - row.queued_at > keep_ms {
                    stale.push(row);
                } else if row.next_attempt_at <= at {
                    due.push(id);
                }
                continue;
            }
            finished.push(row);
        }
        let mut dead = 0;
        for row in stale {
            self.finish(row, "dead", codes::STS_MAIL_0019.as_str(),
                &format!("still unsent {} seconds after it was queued \
                          (mail.retentionS)", keep_ms / 1000));
            dead += 1;
        }
        finished.sort_by_key(|r| r.queued_at);
        let over = (size - cap).max(0);
        let mut removed = 0;
        for (i, row) in finished.iter().enumerate() {
            if at - row.queued_at > keep_ms || (i as i64) < over {
                self.deps.store.delete(&realm, Store::Outbox, &row.id);
                removed += 1;
            }
        }
        let limit = self.int("mail.concurrency").max(1);
        let mut attempted = 0;
        for id in due {
            {
                let mut here = self.in_flight_here.lock()
                    .unwrap_or_else(|p| p.into_inner());
                if *here >= limit {
                    break;
                }
                *here += 1;
            }
            attempted += 1;
            self.attempt(&realm, &id).await;
            let mut here = self.in_flight_here.lock()
                .unwrap_or_else(|p| p.into_inner());
            *here -= 1;
        }
        json!({ "attempted": attempted, "removed": removed, "dead": dead })
    }

    /// `startupProblem()` for the ambient realm: `''`, or why a product
    /// service whose configured transport cannot be built does not start,
    /// its code at the front.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn startup_problem(&self) -> String {
        if self.deps.mode.current() != "product" {
            return String::new();
        }
        let t = self.effective_transport();
        if t == "off" {
            return String::new();
        }
        match self.transport().await {
            Ok(_) => String::new(),
            Err(e) => {
                let code = if e.code == codes::STS_MAIL_0003 {
                    codes::STS_MAIL_0003
                } else {
                    codes::STS_MAIL_0002
                };
                format!("{}mail: the \"{}\" transport configured in the \
                         \"{}\" realm cannot be built, and a product service \
                         that cannot send the links it offers does not \
                         start: {}", sts_core::log::tag(code), t,
                        self.deps.realm.id(), e.message)
            }
        }
    }

    /// Registers `mail.deliver` with the scheduler: a cluster job, once,
    /// on the leader, every `mail.deliverS`. The runtime runs it in each
    /// realm (Node's `sweep()` walks `realms.list()`).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn register_jobs(
        me: &Arc<Mail>,
        scheduler: &sts_cluster::scheduler::Scheduler,
    ) -> Result<bool, String> {
        use sts_cluster::schedule::{JobSpec, Schedule, Unit};
        if scheduler.job(DELIVER_JOB).is_some() {
            return Ok(false);
        }
        let mut spec = JobSpec::new(
            DELIVER_JOB,
            "Mail outbox delivery",
            "Sends every queued message that is due — a retry whose backoff \
             has passed, a lease that lapsed, a row restored after a restart \
             — dead-letters any still pending past mail.retentionS, and \
             removes finished rows past it.",
            "common/mail.ts",
            Schedule::EverySetting { key: "mail.deliverS".into(), unit: Unit::S },
        );
        let mail = me.clone();
        spec.run = Some(Arc::new(move |_ctx| {
            let mail = mail.clone();
            Box::pin(async move { Ok(mail.sweep().await) })
        }));
        scheduler.register(spec)?;
        Ok(true)
    }
}
