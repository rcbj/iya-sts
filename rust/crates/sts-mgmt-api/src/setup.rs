// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The setup operations, over `sts-core`: the configuration
//! (`adminActions.configAction()`, `admin.configJson()`), the mode
//! (`ModeAdmin.modeView()`), the trust realms (`adminActions.realmsAction()`,
//! `adminViews.realmsJson()`) and the status (`admin.dashboardJsonAsync()`,
//! less the members only its console twin answers).
//!
//! What these read outside `sts-core` — a realm's bootstrap administrator,
//! its signing key's kid, its listeners, the reserved first segments of the
//! router, the console's totals — is [`SetupPorts`].

use serde_json::{Map, Value as Json};
use sts_core::errors::{codes, ErrorCode};
use sts_core::mode::Mode;
use sts_core::realm::{self, RealmRegistry};
use sts_core::realm_lifecycle::{Overrides, RealmLifecycle};
use sts_core::settings::{rows, Settings};

use crate::config_view::{
    is_echo_of_mask, mask_keyed, mask_row, ConfigView, ProcessFacts,
};
use crate::tables::tables;

/// What an operation answers: a status, a body and the code it records.
#[derive(Clone, Debug, PartialEq)]
pub struct Answered {
    pub status: u16,
    pub body: Json,
    pub code: Option<ErrorCode>,
}

impl Answered {
    fn ok(body: Json) -> Answered {
        Answered {
            status: 200,
            body,
            code: None,
        }
    }

    fn refused(code: ErrorCode, errors: Vec<String>) -> Answered {
        Answered {
            status: 400,
            body: serde_json::json!({ "ok": false, "errors": errors }),
            code: Some(code),
        }
    }
}

/// The realm's bootstrap administrator (`rbac.seedBootstrapAdministrator()`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Seeded {
    pub ran: bool,
    pub username: String,
    pub created: bool,
    /// Product mode's generated password, handed back once.
    pub password: Option<String>,
}

/// A listener a realm configured (`listenerMap.allListeners()`), as the
/// realm's row shows it.
pub type Listener = Json;

/// What the setup operations read outside `sts-core`.
pub trait SetupPorts: Send + Sync {
    /// Seeds a new realm's administrator, and in product gives it a
    /// generated password.
    fn seed_administrator(&self, realm: &str) -> Seeded;
    /// The kid of a realm's signing key (made if the realm has none yet).
    fn kid_of(&self, realm: &str) -> String;
    /// A realm's own listeners, as its row shows them.
    fn listeners_of(&self, realm: &str) -> Vec<Listener>;
    /// The base a realm's applications are advertised on, or empty.
    fn advertised_base(&self, realm: &str) -> String;
    /// The first path segments a realm may not be called (`reserved()`).
    fn reserved(&self) -> Vec<String>;
    /// The console's totals (`consoleJsonAsync()`) for the ambient realm.
    fn totals(&self, realm: &str) -> Json;
    /// A realm's removal: retire it, then remove it (`realms.retire()`).
    fn retire(&self, realm: &str) -> Result<Json, (ErrorCode, Vec<String>)>;
    /// The application register (`common/applications.js`), over the
    /// directory; None until the composition root hands it over, when the
    /// applications operations answer as operations not yet ported.
    fn applications(
        &self,
    ) -> Option<std::sync::Arc<sts_registers::applications::ApplicationRegistry>>
    {
        None
    }
    /// What an applications act reads outside the register: the SAML
    /// metadata consumer and the scope policy's warnings.
    fn application_ports(
        &self,
    ) -> std::sync::Arc<dyn sts_registers::applications::actions::ActionPorts>
    {
        std::sync::Arc::new(sts_registers::applications::actions::NoActionPorts)
    }
    /// The users acts (`adminActions.usersAction()`, `sts-registers`'
    /// `People`); None until the composition root hands it over, when they
    /// answer as operations not yet ported.
    fn people(&self) -> Option<std::sync::Arc<sts_registers::people::People>> {
        None
    }
}

/// `realms.retiringState(id)`: a realm being removed, as the realm's row
/// and the console's frame show it, or `null`.
#[tracing::instrument(level = "debug", skip(lifecycle))]
pub fn retiring_json(lifecycle: &RealmLifecycle, id: &str) -> Json {
    lifecycle
        .retiring_state(id)
        .map(|s| {
            serde_json::json!({
                "since": s.since, "sinceIso": s.since_iso, "inProgress": s.in_progress,
                "interrupted": !s.in_progress, "finishesBy": s.finishes_by,
                "refusing": format!(
                    "every new sign-in and every new token, assertion, ticket, credential, certificate and \
                     SVID in this realm ({}); sign-out, revocation, introspection, UserInfo, metadata and the \
                     SSF poll endpoint still answer",
                    codes::STS_CORE_0121
                ),
                "why": s.why, "finish": s.finish
            })
        })
        .unwrap_or(Json::Null)
}

/// What the setup operations read.
pub struct Setup<'a> {
    pub settings: &'a Settings,
    pub mode: &'a Mode,
    pub lifecycle: &'a RealmLifecycle,
    pub registry: &'a RealmRegistry,
    pub facts: &'a ProcessFacts,
    pub ports: &'a dyn SetupPorts,
    /// The ambient realm.
    pub realm: &'a str,
}

fn str_of(body: &Json, key: &str) -> String {
    match body.get(key) {
        None | Some(Json::Null) => String::new(),
        Some(Json::String(s)) => s.clone(),
        Some(Json::Bool(false)) => String::new(),
        Some(other) => other.to_string(),
    }
}

/// `numberWord()`.
fn number_word(n: usize) -> String {
    const WORDS: [&str; 21] = [
        "zero",
        "one",
        "two",
        "three",
        "four",
        "five",
        "six",
        "seven",
        "eight",
        "nine",
        "ten",
        "eleven",
        "twelve",
        "thirteen",
        "fourteen",
        "fifteen",
        "sixteen",
        "seventeen",
        "eighteen",
        "nineteen",
        "twenty",
    ];
    WORDS
        .get(n)
        .map(|w| w.to_string())
        .unwrap_or_else(|| n.to_string())
}

/// The unknown-action sentence every action resource answers in its
/// handler's shape (`"Unknown action "x". The four are: …"`), built from
/// what the route declares.
#[tracing::instrument(level = "debug")]
pub fn unknown_action(action: &str, known: &[String]) -> String {
    format!(
        "Unknown action \"{}\". The {} are: {}.",
        action,
        number_word(known.len()),
        known.join(", ")
    )
}

/// `JSON.stringify(text(key))`, the message form of a described text.
fn text_field(described: &Json) -> String {
    described
        .get("text")
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_string()
}

impl Setup<'_> {
    /// `configSettingsJson(page)`: a console page's settings block.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn page_settings(&self, page: &str) -> Json {
        self.view().settings_block(page)
    }

    fn view(&self) -> ConfigView<'_> {
        ConfigView {
            settings: self.settings,
            mode: self.mode,
            facts: self.facts,
            realm: self.realm,
        }
    }

    fn in_default(&self) -> bool {
        self.realm == crate::gate::DEFAULT_REALM
    }

    fn masked_setting(&self, key: &str) -> Json {
        mask_row(&self.view().describe_key(key))
    }

    /// `overrideDurability()`.
    fn durability(&self, keys: &[String]) -> String {
        let realm_wide = if keys.is_empty() {
            true
        } else {
            keys.iter().any(|k| !k.starts_with("realms."))
        };
        let in_realm = realm_wide && !self.in_default();
        let kept = if in_realm {
            self.facts.persists_realms
        } else {
            self.facts.persists_appconfig
        };
        if kept {
            return format!(
                "It is written to the {} store{} and kept across restarts.",
                self.facts.persistence_mode,
                if in_realm {
                    format!(" with the \"{}\" realm", self.realm)
                } else {
                    String::new()
                }
            );
        }
        format!(
            "It is in memory and gone on restart; to keep it, put it in the appconfig file or its environment \
             variable, or turn on a persistent store ({}).",
            if in_realm { "persistence.realms" } else { "persistence.appconfig" }
        )
    }

    /// `checkWrite()` and its code, without writing.
    fn check_write(
        &self,
        key: &str,
        raw: &Json,
    ) -> Option<(String, ErrorCode)> {
        let in_realm = !self.in_default()
            && !key.starts_with("realms.")
            && !Settings::is_per_process(key);
        if let Some(r) = self.settings.check_override(key, raw, Some(in_realm))
        {
            return Some((r.problem, r.code));
        }
        self.mode
            .write_problem(key, raw)
            .map(|r| (r.problem, r.code))
    }

    /// `POST /admin-api/config/{action}` (`configAction()`).
    #[tracing::instrument(level = "debug", skip(self, body))]
    pub fn config_action(&self, action: &str, body: &Json) -> Answered {
        let reset_key = str_of(body, "reset").trim().to_string();
        let action = if body.get("reset").is_some() && !reset_key.is_empty() {
            "reset"
        } else {
            action
        };
        let known = |k: &str| sts_core::settings::row(k).is_some();
        match action {
            "set" => {
                let key = str_of(body, "key").trim().to_string();
                let value = body.get("value").cloned().unwrap_or(Json::Null);
                if known(&key) && is_echo_of_mask(&self.view().describe_key(&key), &value) {
                    return Answered::ok(serde_json::json!({
                        "ok": true, "key": key, "setting": self.masked_setting(&key),
                        "message": format!("{} is unchanged: the value posted was its mask.", key)
                    }));
                }
                match self.settings.set_override(&key, value) {
                    Err(r) => Answered::refused(r.code, vec![r.problem]),
                    Ok(_) => {
                        let shown = self.masked_setting(&key);
                        Answered::ok(serde_json::json!({
                            "ok": true, "key": key, "setting": shown,
                            "message": format!(
                                "{} is now \"{}\". It applies to the next token, assertion, ticket or search. {}",
                                key, text_field(&shown), self.durability(std::slice::from_ref(&key)))
                        }))
                    }
                }
            }
            "set-many" => {
                let object = body.as_object().cloned().unwrap_or_default();
                let posted: Vec<String> =
                    object.keys().filter(|k| k.as_str() != "action" && known(k)).cloned().collect();
                let view = self.view();
                let wanted: Vec<String> = posted
                    .iter()
                    .filter(|k| !is_echo_of_mask(&view.describe_key(k), object.get(*k).unwrap_or(&Json::Null)))
                    .cloned()
                    .collect();
                if posted.is_empty() {
                    return Answered::refused(
                        codes::STS_ADMIN_0565,
                        vec!["No settings were posted. Every name must be one of the keys GET \
                              /admin/config?format=json lists."
                            .into()],
                    );
                }
                let batch: Map<String, Json> =
                    wanted.iter().map(|k| (k.clone(), object.get(k).cloned().unwrap_or(Json::Null))).collect();
                let mut errors = Vec::new();
                let mut first = None;
                self.settings.with_write_batch(&batch, || {
                    for key in &wanted {
                        if let Some((problem, code)) = self.check_write(key, &batch[key]) {
                            errors.push(problem);
                            first.get_or_insert(code);
                        }
                    }
                });
                if !errors.is_empty() {
                    return Answered::refused(first.unwrap_or(codes::STS_ADMIN_0564), errors);
                }
                let mut changed = Vec::new();
                self.settings.with_write_batch(&batch, || {
                    for key in &wanted {
                        let before = self.settings.text_named(key);
                        let _written = self.settings.set_override(key, batch[key].clone());
                        if self.settings.text_named(key) != before {
                            changed.push(key.clone());
                        }
                    }
                });
                let settings: Vec<Json> = wanted.iter().map(|k| self.masked_setting(k)).collect();
                Answered::ok(serde_json::json!({
                    "ok": true, "applied": wanted, "changed": changed, "settings": settings,
                    "message": if changed.is_empty() {
                        "Nothing changed — every value posted was the one already in force.".to_string()
                    } else {
                        format!("{} setting(s) changed: {}. {}", changed.len(), changed.join(", "),
                                self.durability(&changed))
                    }
                }))
            }
            "reset" => {
                let key = if reset_key.is_empty() { str_of(body, "key").trim().to_string() } else { reset_key };
                match self.settings.reset_override(&key) {
                    Err(r) => Answered::refused(r.code, vec![r.problem]),
                    Ok(_) => {
                        let shown = self.masked_setting(&key);
                        Answered::ok(serde_json::json!({
                            "ok": true, "key": key, "setting": shown,
                            "message": format!("{} is back to its {} value, \"{}\".", key,
                                               self.settings.source_named(&key).as_str(), text_field(&shown))
                        }))
                    }
                }
            }
            "reset-all" => self.reset_all(),
            other => Answered::refused(
                codes::STS_ADMIN_0500,
                vec![format!(
                    "Unknown action \"{}\". The four are: set, set-many, reset, reset-all.",
                    other.trim()
                )],
            ),
        }
    }

    /// `clearAllOverrides()`: in a realm, the realm's only.
    fn reset_all(&self) -> Answered {
        let keys: Vec<String> = if self.in_default() {
            self.settings.runtime_overrides().keys().cloned().collect()
        } else {
            self.lifecycle
                .overrides(self.realm)
                .map(|o| o.keys().cloned().collect())
                .unwrap_or_default()
        };
        if keys.iter().any(|k| k == "pki.pinnedSigners") {
            if let Err(r) = self.settings.reset_override("pki.pinnedSigners") {
                if r.code == codes::STS_PKI_0215 {
                    return Answered::refused(r.code, vec![r.problem]);
                }
            }
        }
        for key in &keys {
            let _cleared = self.settings.reset_override(key);
        }
        Answered::ok(serde_json::json!({
            "ok": true, "cleared": keys,
            "message": if keys.is_empty() {
                "There were no runtime overrides to clear.".to_string()
            } else {
                format!("{} runtime override(s) cleared: {}.", keys.len(), keys.join(", "))
            }
        }))
    }

    /// `GET /admin-api/config`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn config_json(&self) -> Answered {
        let realm_settings = if self.in_default() {
            Vec::new()
        } else {
            self.lifecycle
                .overrides(self.realm)
                .map(|o| o.keys().cloned().collect())
                .unwrap_or_default()
        };
        Answered::ok(self.view().config_json(realm_settings))
    }

    /// `GET /admin-api/mode` (`modeView()`): the report, its values masked.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn mode_json(&self) -> Answered {
        let mut report = self.mode.report();
        if let Some(Json::Array(list)) =
            report.get_mut("developmentOnlySettings")
        {
            for row in list.iter_mut() {
                let key = row
                    .get("key")
                    .and_then(Json::as_str)
                    .unwrap_or("")
                    .to_string();
                if let Some(o) = row.as_object_mut() {
                    for member in ["default", "value", "inForce"] {
                        if let Some(v) = o.get(member).cloned() {
                            o.insert(member.into(), mask_keyed(&key, &v));
                        }
                    }
                }
            }
        }
        Answered::ok(report)
    }

    /// `GET /admin-api/status`, less the console's members.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn status_json(&self) -> Answered {
        let mut totals = self.ports.totals(self.realm);
        if let Some(o) = totals.as_object_mut() {
            o.insert("pages".into(), tables().console_pages.clone());
        }
        Answered::ok(totals)
    }

    fn realm_rows(&self, overrides: &Overrides) -> Vec<Json> {
        let mut keys: Vec<&String> = overrides.keys().collect();
        keys.sort();
        keys.into_iter()
            .map(|key| {
                let raw = &overrides[key];
                let text = match raw {
                    Json::String(s) => s.clone(),
                    Json::Array(list) => list
                        .iter()
                        .map(|x| match x {
                            Json::String(s) => s.clone(),
                            Json::Null => String::new(),
                            o => o.to_string(),
                        })
                        .collect::<Vec<_>>()
                        .join(","),
                    Json::Null => "null".into(),
                    other => other.to_string(),
                };
                let row = sts_core::settings::row(key);
                serde_json::json!({
                    "key": key,
                    "value": mask_keyed(key, &Json::String(text)),
                    "label": row.map(|r| r.label).unwrap_or(key.as_str()),
                    "group": row.map(|r| r.group).unwrap_or(""),
                })
            })
            .collect()
    }

    /// `realmJson()`.
    fn realm_json(&self, root: &str, realm: &sts_core::realm::Realm) -> Json {
        let prefix = self.registry.prefix_of(realm);
        let advertised = self.ports.advertised_base(&realm.id);
        let base = format!(
            "{}{}",
            if advertised.is_empty() {
                root.to_string()
            } else {
                advertised
            },
            prefix
        );
        let retiring = retiring_json(self.lifecycle, &realm.id);
        serde_json::json!({
            "id": realm.id,
            "name": realm.name,
            "description": realm.description,
            "domain": self.registry.domain_of(realm),
            "baseDn": self.registry.base_dn_of(realm),
            "builtin": realm.builtin,
            "retiring": retiring,
            "pathPrefix": prefix,
            "baseUrl": base,
            "listeners": self.ports.listeners_of(&realm.id),
            "kid": self.ports.kid_of(&realm.id),
            "settings": self.lifecycle.overrides(&realm.id).map(|o| self.realm_rows(&o)).unwrap_or_default(),
            "endpoints": {
                "openidConfiguration": format!("{}/.well-known/openid-configuration", base),
                "authorizationServerMetadata": format!("{}/.well-known/oauth-authorization-server", base),
                "jwks": format!("{}/oauth2/jwks", base),
                "samlMetadata": format!("{}/saml2/metadata", base),
            }
        })
    }

    /// `GET /admin-api/realms` (`realmsJson()`). `root` is the request's
    /// base with the ambient realm's prefix taken off (`realmRootUrl()`).
    #[tracing::instrument(level = "debug", skip(self, query))]
    pub fn realms_json(
        &self,
        root: &str,
        query: &crate::request::Query,
    ) -> Answered {
        let mut reserved = self.ports.reserved();
        reserved.sort();
        let list = self.registry.list();
        let realms: Vec<Json> =
            list.iter().map(|r| self.realm_json(root, r)).collect();
        let total = realms.len();
        let text = |k: &str| match query.get(k) {
            Some(Json::String(s)) => s.clone(),
            Some(Json::Array(a)) => a
                .iter()
                .filter_map(Json::as_str)
                .collect::<Vec<_>>()
                .join(","),
            _ => String::new(),
        };
        let asked_per = js_parse_int(&text("per"));
        let per = match asked_per {
            Some(n) if n > 0 => n.min(300),
            _ => 50,
        };
        let pages = ((total as i64 + per - 1) / per).max(1);
        let page = js_parse_int(&text("page")).unwrap_or(1).max(1).min(pages);
        let offset = (page - 1) * per;
        let current = realm::current();
        let mut out = Map::new();
        out.insert(
            "enabled".into(),
            Json::Bool(self.settings.value_of("realms.enabled").as_bool()),
        );
        out.insert("active".into(), Json::Bool(self.registry.active()));
        out.insert(
            "pathSegment".into(),
            Json::from(self.registry.path_segment()),
        );
        out.insert("current".into(), Json::from(self.realm));
        out.insert("reserved".into(), Json::from(reserved));
        out.insert("realms".into(), Json::Array(realms));
        out.insert("support".into(), tables().realm_support.clone());
        out.insert(
            "settings".into(),
            self.view().settings_block("/admin/realms"),
        );
        out.insert(
            "defaultDomain".into(),
            Json::from(self.registry.domain_of(&self.registry.default_realm())),
        );
        out.insert("count".into(), Json::from(self.registry.count()));
        out.insert("currentName".into(), Json::from(current.name.as_str()));
        out.insert(
            "persistence".into(),
            serde_json::json!({ "persistsRealms": self.facts.persists_realms, "mode": self.facts.persistence_mode }),
        );
        out.insert(
            "paging".into(),
            serde_json::json!({
                "page": page, "pages": pages, "perPage": per,
                "firstRow": if total > 0 { offset + 1 } else { 0 },
                "lastRow": (offset + per).min(total as i64), "total": total,
                "param": "page", "noun": "rows"
            }),
        );
        Answered::ok(Json::Object(out))
    }

    /// `POST /admin-api/realms/{action}` (`realmsAction()`).
    #[tracing::instrument(level = "debug", skip(self, body))]
    pub fn realms_action(&self, action: &str, body: &Json) -> Answered {
        let id = str_of(body, "id").trim().to_string();
        let refused = |r: sts_core::realm::Refusals| {
            Answered::refused(
                r.code.unwrap_or(codes::STS_ADMIN_0562),
                r.sentences,
            )
        };
        match action.trim() {
            "create" => {
                let overrides = body.get("overrides").and_then(Json::as_object).cloned().unwrap_or_default();
                let created = self.lifecycle.create(
                    &id.to_lowercase(),
                    &str_of(body, "name"),
                    &str_of(body, "description"),
                    &str_of(body, "domain"),
                    &overrides,
                    false,
                );
                let realm = match created {
                    Ok(r) => r,
                    Err(r) => return refused(r),
                };
                let seeded = self.ports.seed_administrator(&realm.id);
                let prefix = self.registry.prefix_of(&realm);
                let opens = realm::run_sync(realm.clone(), || {
                    self.mode.predicate("opensConsoleToAnyone").unwrap_or(true)
                });
                let mut message = format!(
                    "The realm \"{}\" is defined. Every HTTP endpoint this service has now answers under {}/ as \
                     well, with its own signing key and nothing issued yet.",
                    realm.id, prefix
                );
                if seeded.ran {
                    message.push_str(&format!(
                        " \"{}\" administers it, and only it, from {}/admin{}",
                        seeded.username,
                        prefix,
                        if seeded.created { ", and must choose a new password at its first sign-in." } else { "." }
                    ));
                    if !opens {
                        message.push_str(&format!(
                            " Until it has signed in there with its password nobody else may use that console, \
                             and a sign-in as \"{}\" by any other method does not count.",
                            seeded.username
                        ));
                    }
                }
                let mut out = Map::new();
                out.insert("ok".into(), Json::Bool(true));
                out.insert("realm".into(), Json::from(realm.id.as_str()));
                out.insert("prefix".into(), Json::from(prefix));
                out.insert(
                    "bootstrap".into(),
                    if seeded.ran {
                        serde_json::json!({ "username": seeded.username, "created": seeded.created,
                                            "passwordResetRequired": seeded.created })
                    } else {
                        Json::Null
                    },
                );
                if let Some(password) = seeded.password.filter(|p| !p.is_empty()) {
                    out.insert("password".into(), Json::from(password));
                    out.insert("username".into(), Json::from(seeded.username.as_str()));
                }
                out.insert("message".into(), Json::from(message));
                Answered::ok(Json::Object(out))
            }
            "update" => {
                let name = body.get("name").map(|_| str_of(body, "name"));
                let description = body.get("description").map(|_| str_of(body, "description"));
                let domain = body.get("domain").map(|_| str_of(body, "domain"));
                match self.lifecycle.update(
                    &id,
                    name.as_deref(),
                    description.as_deref(),
                    None,
                    domain.as_deref(),
                    false,
                    None,
                ) {
                    Err(r) => refused(r),
                    Ok(_) => Answered::ok(serde_json::json!({ "ok": true, "realm": id, "message": "Saved." })),
                }
            }
            "set" => {
                let key = str_of(body, "key").trim().to_string();
                match self.lifecycle.set_override(&id, &key, body.get("value").cloned().unwrap_or(Json::Null)) {
                    Err(r) => refused(r),
                    Ok(()) => Answered::ok(serde_json::json!({
                        "ok": true, "realm": id, "key": key,
                        "message": format!("{} is set on the \"{}\" realm. It applies to the next request that \
                                            arrives under that realm's prefix, and to nothing else.", key, id)
                    })),
                }
            }
            "unset" => {
                let key = str_of(body, "key").trim().to_string();
                match self.lifecycle.clear_override(&id, &key) {
                    Err(r) => refused(r),
                    Ok(()) => Answered::ok(serde_json::json!({
                        "ok": true, "realm": id, "key": key,
                        "message": format!("{} is no longer set on the \"{}\" realm; it comes from whatever this \
                                            service as a whole is configured with.", key, id)
                    })),
                }
            }
            "remove" => {
                if !id.is_empty() && id == self.realm {
                    return Answered::refused(
                        codes::STS_ADMIN_0563,
                        vec![format!(
                            "This request arrived inside the \"{}\" realm, so removing it would leave the caller on \
                             a path that no longer exists — the console would be redirected into a prefix that had \
                             stopped existing one instruction earlier. Do it from another realm: the switcher at the \
                             top of the console sidebar, or the same call under a different prefix.",
                            id
                        )],
                    );
                }
                if self.registry.get(&id).is_none() {
                    return match self.lifecycle.remove(&id) {
                        Err(r) => refused(r),
                        Ok(_) => Answered::ok(serde_json::json!({ "ok": true, "realm": id })),
                    };
                }
                match self.ports.retire(&id) {
                    Err((code, errors)) => Answered::refused(code, errors),
                    Ok(answer) => Answered::ok(answer),
                }
            }
            other => Answered::refused(
                codes::STS_ADMIN_0500,
                vec![format!("Unknown action \"{}\". The five are: create, update, set, unset, remove.", other)],
            ),
        }
    }
}

/// `parseInt(text, 10)`.
fn js_parse_int(text: &str) -> Option<i64> {
    let t = text.trim_start();
    let (sign, digits) = match t.strip_prefix('-') {
        Some(rest) => (-1, rest),
        None => (1, t.strip_prefix('+').unwrap_or(t)),
    };
    let run: String = digits.chars().take_while(char::is_ascii_digit).collect();
    if run.is_empty() {
        return None;
    }
    run.parse::<i64>().ok().map(|n| n * sign)
}

/// Every setting row's key, for the index of what a body may name.
#[tracing::instrument(level = "debug")]
pub fn setting_keys() -> Vec<&'static str> {
    rows().iter().map(|r| r.key).collect()
}

/// `POST /admin-api/users/{action}` (`adminActions.usersAction()`): the
/// acts `sts-registers`' `People` ports, 200 for `ok` and 400 otherwise,
/// marked with the act's code or STS-API-0030, as the route marks it.
/// None where there is no register, or for an action Node has and the
/// register does not port.
#[tracing::instrument(level = "debug", skip(setup, body, caller))]
pub fn users_action(
    setup: &Setup<'_>,
    action: &str,
    body: &Json,
    caller: Option<&crate::gate::Caller>,
) -> Option<Answered> {
    let people = setup.ports.people()?;
    let mut asked = body.as_object().cloned().unwrap_or_default();
    asked.insert("action".into(), Json::from(action));
    let actor = caller.map(|c| c.name.clone()).unwrap_or_default();
    let outcome = people.users(&Json::Object(asked), "api", &actor)?;
    let ok = outcome.answer.get("ok") == Some(&Json::Bool(true));
    Some(Answered {
        status: if ok { 200 } else { 400 },
        code: if ok {
            None
        } else {
            Some(outcome.code.unwrap_or(codes::STS_API_0030))
        },
        body: outcome.answer,
    })
}
