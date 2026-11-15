// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE PROSE THE SERVER WRITES INTO A VIEW, IN THE READER'S LANGUAGE
//! (#543; `common/server_prose.ts`, the `apis5` slice of #444).
//!
//! `/admin-api` translates while it answers, and ONLY when the request
//! names a language in `Accept-Language`: the console sends the locale it
//! negotiated, and a caller that names none reads English whatever a
//! realm's locale policy says. The OpenAPI documents stay English. Only
//! the request's own header is negotiated (`i18n.negotiate()` over
//! `i18n.acceptLanguage()`), against `common/locales`' catalog list.
//!
//! A VIEW IS TRANSLATED BY EXACT MATCH, AFTER IT IS BUILT
//! ([`Prose::translate_view`], `translateView()`): every plain object is
//! offered to the SETTINGS source, which knows a described setting by its
//! `key` and replaces `label`, `description`, `restartReason` and each
//! `csvValueNotes` sentence only where the member is exactly that
//! setting's English; every string is offered to each PHRASE source whose
//! routes hold the answer's route (`*` every route), which replaces a
//! message's English, or refills a template it matches in the translated
//! template, each parameter translated in turn when it is itself a phrase,
//! a filled template or a list of them joined by `, `. A string under an
//! identifier member (`key`, `id`, `value`, …) is never translated.
//!
//! The English is `common/prose_locales/<ns>/en.json` (generated from the
//! source in Node and held to it there) and each translation
//! `<ns>/<tag>.json`, `{ en: <hash>, text }`, served only while its hash is
//! the first sixteen hex digits of the CURRENT English's SHA-256. What is
//! not a file — which kind each namespace is, the routes a phrase source is
//! scoped to, the members never translated — is Node's, exported by
//! `tests/tools/export-server-prose.js` into `tables/server_prose.json`.
//! The files are read once, on first use, from the web root
//! (`STS_WEB_ROOT`): a file that cannot be read costs its translations,
//! never the answer.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde::Deserialize;
use serde_json::{Map, Value as Json};

const TABLE: &str = include_str!("../tables/server_prose.json");

/// `SOURCE`: the catalog every translation is made from.
const SOURCE: &str = "en";
/// `LIST_SEP`.
const LIST_SEP: &str = ", ";
/// `SETTING_FIELDS`.
const SETTING_FIELDS: [&str; 3] = ["label", "description", "restartReason"];

#[derive(Debug, Clone, Deserialize)]
struct NamespaceRow {
    kind: String,
    #[serde(default)]
    routes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Table {
    separator: String,
    never: Vec<String>,
    namespaces: indexmap::IndexMap<String, NamespaceRow>,
}

static PLACEHOLDER: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"\{\{([A-Za-z0-9]+)\}\}").ok());

/// One template: its key, its English, the matcher and the names of its
/// placeholders in order.
struct Template {
    key: String,
    english: String,
    re: Regex,
    names: Vec<String>,
}

/// A phrase source's index (`phraseSource()`'s `build()`).
struct Phrases {
    routes: Vec<String>,
    exact: HashMap<String, String>,
    params: HashMap<String, String>,
    templates: Vec<Template>,
}

/// One described setting's English, from the settings namespace.
#[derive(Default)]
struct SettingRow {
    fields: HashMap<String, String>,
    notes: Option<Map<String, Json>>,
}

enum Kind {
    Settings(HashMap<String, SettingRow>),
    Phrases(Phrases),
}

struct Namespace {
    name: String,
    kind: Kind,
    /// tag → key → (hash of the English, text)
    catalogs: HashMap<String, HashMap<String, (String, String)>>,
}

/// The prose catalogs and their sources.
pub struct Prose {
    namespaces: Vec<Namespace>,
    never: HashSet<String>,
    i18n: sts_http::i18n::Catalogs,
}

/// `ServerProse.fill(template, params)`: each `{{name}}` replaced by its
/// parameter; one with no parameter is left as written.
#[tracing::instrument(level = "trace", skip_all)]
pub fn fill(template: &str, params: &HashMap<String, String>) -> String {
    let Some(re) = PLACEHOLDER.as_ref() else {
        return template.to_string();
    };
    re.replace_all(template, |c: &regex::Captures<'_>| {
        params
            .get(&c[1])
            .cloned()
            .unwrap_or_else(|| c[0].to_string())
    })
    .into_owned()
}

/// `ServerProse.hashOf(english)`: the first sixteen hex digits of its
/// SHA-256.
#[tracing::instrument(level = "trace", skip_all)]
pub fn hash_of(english: &str) -> String {
    sts_crypto::raw_sig::Sha256Digester::new()
        .ok()
        .and_then(|mut d| {
            d.update(english.as_bytes()).ok()?;
            d.hex().ok()
        })
        .map(|h| h.chars().take(16).collect())
        .unwrap_or_default()
}

fn read_json(path: &Path) -> Option<Map<String, Json>> {
    let text = std::fs::read_to_string(path).ok()?;
    match serde_json::from_str::<Json>(&text) {
        Ok(Json::Object(o)) => Some(o),
        Ok(_) => None,
        Err(e) => {
            tracing::error!(
                "{}i18n: {} could not be read ({}); its prose falls back \
                 along the chain to English.",
                sts_core::log::tag(sts_core::errors::codes::STS_I18N_0011),
                path.display(),
                e
            );
            None
        }
    }
}

impl Phrases {
    fn build(routes: Vec<String>, english: &Map<String, Json>) -> Phrases {
        let mut exact = HashMap::new();
        let mut params = HashMap::new();
        let mut templates: Vec<Template> = Vec::new();
        let Some(ph) = PLACEHOLDER.as_ref() else {
            return Phrases {
                routes,
                exact,
                params,
                templates,
            };
        };
        for (key, value) in english {
            let Some(text) = value.as_str() else {
                continue;
            };
            let names: Vec<String> =
                ph.captures_iter(text).map(|c| c[1].to_string()).collect();
            if names.is_empty() {
                let into = if key.contains(".param.") {
                    &mut params
                } else {
                    &mut exact
                };
                into.entry(text.to_string()).or_insert_with(|| key.clone());
                continue;
            }
            // `english.split(PLACEHOLDER)` interleaves the names; each
            // literal part escaped, each name a lazy capture.
            let mut source = String::from("^");
            let mut last = 0;
            for m in ph.find_iter(text) {
                source.push_str(&regex::escape(&text[last..m.start()]));
                source.push_str("((?s:.+?))");
                last = m.end();
            }
            source.push_str(&regex::escape(&text[last..]));
            source.push('$');
            if let Ok(re) = Regex::new(&source) {
                templates.push(Template {
                    key: key.clone(),
                    english: text.to_string(),
                    re,
                    names,
                });
            }
        }
        // The template with the most literal text first (a stable sort, as
        // `Array.prototype.sort` is), so `at least {{n}} symbols` is tried
        // before anything shorter it would also match.
        let literal = |t: &Template| {
            ph.replace_all(&t.english, "").encode_utf16().count()
        };
        templates.sort_by_key(|t| std::cmp::Reverse(literal(t)));
        Phrases {
            routes,
            exact,
            params,
            templates,
        }
    }

    fn translate(
        &self,
        text: &str,
        lookup: &dyn Fn(&str, &str) -> String,
        depth: usize,
    ) -> Option<String> {
        if let Some(key) = self.exact.get(text) {
            return Some(lookup(key, text));
        }
        if depth > 3 || self.templates.is_empty() {
            return None;
        }
        for one in &self.templates {
            let Some(m) = one.re.captures(text) else {
                continue;
            };
            let mut params = HashMap::new();
            for (i, name) in one.names.iter().enumerate() {
                let got = m.get(i + 1).map_or("", |g| g.as_str());
                params.insert(name.clone(), self.value(got, lookup, depth + 1));
            }
            return Some(fill(&lookup(&one.key, &one.english), &params));
        }
        None
    }

    fn value(
        &self,
        text: &str,
        lookup: &dyn Fn(&str, &str) -> String,
        depth: usize,
    ) -> String {
        if let Some(key) = self.params.get(text) {
            return lookup(key, text);
        }
        if let Some(whole) = self.translate(text, lookup, depth) {
            return whole;
        }
        let parts: Vec<&str> = text.split(LIST_SEP).collect();
        if parts.len() < 2 {
            return text.to_string();
        }
        // best[i]: the translated pieces of parts[0..i), or None.
        let mut best: Vec<Option<Vec<String>>> = vec![Some(Vec::new())];
        for i in 1..=parts.len() {
            best.push(None);
            let mut j = i;
            while j > 0 && best[i].is_none() {
                j -= 1;
                let Some(before) = best[j].clone() else {
                    continue;
                };
                let joined = parts[j..i].join(LIST_SEP);
                if let Some(piece) = self.translate(&joined, lookup, depth) {
                    let mut next = before;
                    next.push(piece);
                    best[i] = Some(next);
                }
            }
        }
        best[parts.len()]
            .as_ref()
            .map_or_else(|| text.to_string(), |b| b.join(LIST_SEP))
    }
}

impl Prose {
    /// The prose under a web root: `common/prose_locales/` and the catalog
    /// list in `common/locales/`.
    #[tracing::instrument(level = "debug")]
    pub fn load(root: &Path) -> Prose {
        let table: Option<Table> = serde_json::from_str(TABLE)
            .map_err(|e| tracing::error!("tables/server_prose.json: {}", e))
            .ok();
        let i18n = sts_http::i18n::Catalogs::load(
            &sts_http::i18n::Catalogs::dir_in(root),
        );
        let Some(table) = table else {
            return Prose {
                namespaces: Vec::new(),
                never: HashSet::new(),
                i18n,
            };
        };
        let dir: PathBuf = root.join("common").join("prose_locales");
        let tags: Vec<String> = i18n
            .catalogs()
            .iter()
            .filter_map(|c| c.get("tag").and_then(Json::as_str))
            .filter(|t| *t != SOURCE)
            .map(str::to_string)
            .collect();
        let sep = table.separator.clone();
        let mut names: Vec<&String> = table.namespaces.keys().collect();
        names.sort();
        let namespaces = names
            .into_iter()
            .map(|ns| {
                let row = &table.namespaces[ns];
                let english = read_json(&dir.join(ns).join("en.json"))
                    .unwrap_or_default();
                let kind = if row.kind == "settings" {
                    let mut rows: HashMap<String, SettingRow> = HashMap::new();
                    for (key, text) in &english {
                        let parts: Vec<&str> =
                            key.split(sep.as_str()).collect();
                        let Some(text) = text.as_str() else {
                            continue;
                        };
                        let one = rows.entry(parts[0].to_string()).or_default();
                        match parts.as_slice() {
                            [_, field] => {
                                one.fields.insert(
                                    field.to_string(),
                                    text.to_string(),
                                );
                            }
                            [_, "csvValueNotes", value] => {
                                one.notes.get_or_insert_with(Map::new).insert(
                                    value.to_string(),
                                    Json::from(text),
                                );
                            }
                            _ => {}
                        }
                    }
                    Kind::Settings(rows)
                } else {
                    Kind::Phrases(Phrases::build(row.routes.clone(), &english))
                };
                let mut catalogs = HashMap::new();
                for tag in &tags {
                    let file = dir.join(ns).join(format!("{tag}.json"));
                    if !file.exists() {
                        continue;
                    }
                    let Some(body) = read_json(&file) else {
                        continue;
                    };
                    let flat: HashMap<String, (String, String)> = body
                        .into_iter()
                        .filter_map(|(k, v)| {
                            let en = v.get("en")?.as_str()?.to_string();
                            let text = v.get("text")?.as_str()?.to_string();
                            Some((k, (en, text)))
                        })
                        .collect();
                    catalogs.insert(tag.clone(), flat);
                }
                Namespace {
                    name: ns.clone(),
                    kind,
                    catalogs,
                }
            })
            .collect();
        Prose {
            namespaces,
            never: table.never.into_iter().collect(),
            i18n,
        }
    }

    /// The prose under `STS_WEB_ROOT` (or `/usr/src/sts`), read once.
    #[tracing::instrument(level = "debug")]
    pub fn shared() -> &'static Prose {
        static SHARED: LazyLock<Prose> = LazyLock::new(|| {
            Prose::load(&sts_http::files::WebRoot::from_env().0)
        });
        &SHARED
    }

    /// `translatorFor(acceptLanguage)`'s chain: the catalogs to look in,
    /// English left out, or None when the header names nothing but
    /// English (or nothing at all).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn chain_for(&self, accept_language: &str) -> Option<Vec<String>> {
        if accept_language.trim().is_empty() {
            return None;
        }
        let prefs = sts_http::i18n::accept_language(accept_language);
        let negotiated = self.i18n.negotiate(&prefs, "");
        let chain: Vec<String> = negotiated
            .chain
            .into_iter()
            .filter(|t| t != SOURCE)
            .collect();
        (!chain.is_empty()).then_some(chain)
    }

    fn lookup(
        &self,
        ns: &Namespace,
        chain: &[String],
        key: &str,
        en: &str,
    ) -> String {
        let hash = hash_of(en);
        for tag in chain {
            if let Some((h, text)) =
                ns.catalogs.get(tag).and_then(|c| c.get(key))
            {
                // A translation of an OLDER English is not served.
                if *h == hash {
                    return text.clone();
                }
            }
        }
        en.to_string()
    }

    /// `translateView(body, translatorFor(acceptLanguage, route))`: a
    /// translated copy of an answer, or the answer as it is where the
    /// header names no language this service translates into.
    #[tracing::instrument(level = "debug", skip(self, body))]
    pub fn translate_view(
        &self,
        body: Json,
        accept_language: &str,
        route: &str,
    ) -> Json {
        let Some(chain) = self.chain_for(accept_language) else {
            return body;
        };
        self.walk(body, None, &chain, route)
    }

    fn walk(
        &self,
        value: Json,
        member: Option<&str>,
        chain: &[String],
        route: &str,
    ) -> Json {
        match value {
            Json::String(text) => {
                if member.is_some_and(|m| self.never.contains(m)) {
                    return Json::String(text);
                }
                for ns in &self.namespaces {
                    let Kind::Phrases(p) = &ns.kind else {
                        continue;
                    };
                    if !p.routes.iter().any(|r| r == "*" || r == route) {
                        continue;
                    }
                    let lookup =
                        |key: &str, en: &str| self.lookup(ns, chain, key, en);
                    if let Some(found) = p.translate(&text, &lookup, 0) {
                        return Json::String(found);
                    }
                }
                Json::String(text)
            }
            Json::Array(list) => Json::Array(
                list.into_iter()
                    .map(|one| self.walk(one, member, chain, route))
                    .collect(),
            ),
            Json::Object(mut obj) => {
                for ns in &self.namespaces {
                    if let Kind::Settings(rows) = &ns.kind {
                        self.recognise(ns, rows, &mut obj, chain);
                    }
                }
                Json::Object(
                    obj.into_iter()
                        .map(|(k, v)| {
                            let walked = self.walk(v, Some(&k), chain, route);
                            (k, walked)
                        })
                        .collect(),
                )
            }
            other => other,
        }
    }

    /// The settings source's `recognise(obj)`: a described setting's
    /// prose members, where each is exactly the setting's English.
    fn recognise(
        &self,
        ns: &Namespace,
        rows: &HashMap<String, SettingRow>,
        obj: &mut Map<String, Json>,
        chain: &[String],
    ) {
        let Some(key) =
            obj.get("key").and_then(Json::as_str).map(str::to_string)
        else {
            return;
        };
        let Some(row) = rows.get(&key) else {
            return;
        };
        let sep = "|";
        for field in SETTING_FIELDS {
            let Some(english) = row.fields.get(field) else {
                continue;
            };
            if obj.get(field).and_then(Json::as_str) == Some(english.as_str()) {
                let text = self.lookup(
                    ns,
                    chain,
                    &format!("{key}{sep}{field}"),
                    english,
                );
                obj.insert(field.to_string(), Json::String(text));
            }
        }
        let Some(notes) = &row.notes else {
            return;
        };
        if let Some(Json::Object(copy)) = obj.get_mut("csvValueNotes") {
            for (value, held) in copy.iter_mut() {
                let Some(english) = notes.get(value).and_then(Json::as_str)
                else {
                    continue;
                };
                if held.as_str() == Some(english) {
                    *held = Json::String(self.lookup(
                        ns,
                        chain,
                        &format!("{key}{sep}csvValueNotes{sep}{value}"),
                        english,
                    ));
                }
            }
        }
    }

    /// The namespaces, sorted (`namespaces()`).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn namespaces(&self) -> Vec<String> {
        self.namespaces.iter().map(|n| n.name.clone()).collect()
    }
}
