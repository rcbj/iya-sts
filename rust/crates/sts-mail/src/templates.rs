// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The mail channel's messages: `common/mail_templates.ts`. The built-in
//! English templates, the translations of `common/mail_locales/`, the
//! categories, the rules a realm's own wording must keep (`problem()`),
//! and the renderer — each value escaped BY THE RENDERER (HTML-escaped in
//! the HTML part, its control characters made spaces elsewhere), a link
//! only ever a placeholder whose value is this service's own.
//!
//! The data is `tables/mail_templates.json`, exported from the module by
//! `tests/tools/export-rust-tables.js`, never written by hand.

use std::sync::LazyLock;

use indexmap::IndexMap;
use regex::Regex;
use serde::Deserialize;
use serde_json::{Map, Value as Json};

use crate::js;
use crate::locale::Catalogs;
use crate::sanitize;

const TABLE: &str = include_str!("../tables/mail_templates.json");

/// A message category, and whether a person may decline it.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct Category {
    pub id: String,
    pub optional: bool,
    pub label: String,
    pub reason: String,
    pub what: String,
}

/// One built-in template: what it offers and its three English parts.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TemplateSpec {
    pub id: String,
    pub category: String,
    pub title: String,
    pub values: Vec<String>,
    pub links: Vec<String>,
    pub subject: String,
    pub text: String,
    pub html: String,
}

/// A subject, a text part and an HTML part.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parts {
    pub subject: String,
    pub text: String,
    pub html: String,
}

impl Parts {
    /// From `{ subject, text, html }`, each `String(x || '')`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn from_json(value: &Json) -> Parts {
        let one = |key: &str| match value.get(key) {
            None | Some(Json::Null) | Some(Json::Bool(false)) => String::new(),
            Some(Json::String(s)) => s.clone(),
            Some(other) => js::string_of(other),
        };
        Parts {
            subject: one("subject"),
            text: one("text"),
            html: one("html"),
        }
    }

    /// The parts of a built-in template.
    pub fn of(spec: &TemplateSpec) -> Parts {
        Parts {
            subject: spec.subject.clone(),
            text: spec.text.clone(),
            html: spec.html.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Table {
    layout_id: String,
    common: Vec<String>,
    categories: Vec<Category>,
    built_in: Vec<TemplateSpec>,
    locales: IndexMap<String, Json>,
    source: String,
    catalogs: Vec<CatalogRow>,
}

#[derive(Deserialize)]
struct CatalogRow {
    tag: String,
}

/// The exported table and the catalogs' parts, read once.
pub struct Templates {
    table: Table,
    catalogs: Catalogs,
}

static TEMPLATES: LazyLock<Option<Templates>> = LazyLock::new(|| {
    let table: Table = match serde_json::from_str(TABLE) {
        Ok(table) => table,
        Err(e) => {
            tracing::error!(
                "{}mail: tables/mail_templates.json could not be read: {}",
                sts_core::log::tag(sts_core::errors::codes::STS_I18N_0001),
                e
            );
            return None;
        }
    };
    let tags: Vec<String> =
        table.catalogs.iter().map(|row| row.tag.clone()).collect();
    let catalogs = Catalogs::new(&tags, &table.source);
    Some(Templates { table, catalogs })
});

static PLACEHOLDER: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"\{\{\s*([A-Za-z][A-Za-z0-9]*)\s*\}\}").ok()
});
static URL: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?i)https?://").ok());
static CONTENT: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"\{\{\s*content\s*\}\}").ok());
static SUBJECT: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"\{\{\s*subject\s*\}\}").ok());
static HREF: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r#"(?i)\shref\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)"#).ok()
});
static HREF_HEAD: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*href\s*=\s*").ok());
static WHOLE_PLACEHOLDER: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"^\{\{\s*([A-Za-z][A-Za-z0-9]*)\s*\}\}$").ok()
});
static TAG: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"^[a-z]{1,8}(-[a-z0-9]{1,8})*$").ok()
});
static QUALITY: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^\s*q\s*=\s*([0-9.]+)\s*$").ok());

/// What every message offers: `realm`, `service`.
pub const COMMON: [&str; 2] = ["realm", "service"];

/// `Html.esc()`. A hot path: no span.
pub fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// `MailTemplates.plain()`: every control character a space. A hot path:
/// no span.
pub fn plain(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if (c as u32) <= 0x1f || c == '\u{7f}' {
                ' '
            } else {
                c
            }
        })
        .collect()
}

fn links_text(links: &[String]) -> String {
    links
        .iter()
        .map(|l| format!("{{{{{}}}}}", l))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Whether `mailto:` follows a JavaScript word boundary (`\bmailto:`).
fn has_mailto(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let mut from = 0;
    while let Some(at) = lower[from..].find("mailto:") {
        let at = from + at;
        let before = lower[..at].chars().next_back();
        if !before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
            return true;
        }
        from = at + 1;
    }
    false
}

impl Templates {
    /// The one table.
    pub fn get() -> Option<&'static Templates> {
        TEMPLATES.as_ref()
    }

    /// `LAYOUT_ID`.
    pub fn layout_id(&self) -> &str {
        &self.table.layout_id
    }

    /// `BUILT_IN`.
    pub fn all(&self) -> &[TemplateSpec] {
        &self.table.built_in
    }

    /// `CATEGORIES`.
    pub fn categories(&self) -> &[Category] {
        &self.table.categories
    }

    /// `COMMON`.
    pub fn common(&self) -> &[String] {
        &self.table.common
    }

    /// `builtIn(id)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn built_in(&self, id: &str) -> Option<&TemplateSpec> {
        self.table.built_in.iter().find(|one| one.id == id)
    }

    /// `category(id)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn category(&self, id: &str) -> Option<&Category> {
        self.table.categories.iter().find(|one| one.id == id)
    }

    /// `chainFor(language)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn chain_for(&self, language: &str) -> Vec<String> {
        self.catalogs.chain_for(language)
    }

    /// `builtInFor(id, language)`: the first translation along the chain,
    /// and the catalog that answered; `None` for English, an unknown
    /// language or an unknown id.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn built_in_for(
        &self,
        id: &str,
        language: &str,
    ) -> Option<(Parts, String)> {
        self.built_in(id)?;
        for tag in self.chain_for(language) {
            let Some(file) = self.table.locales.get(&tag) else {
                continue;
            };
            let parts = if id == self.table.layout_id {
                file.get("layout")
            } else {
                file.get("templates").and_then(|t| t.get(id))
            };
            if let Some(parts) = parts.filter(|p| p.is_object()) {
                return Some((Parts::from_json(parts), tag));
            }
        }
        None
    }

    /// `builtInLanguages(id)`, sorted.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn built_in_languages(&self, id: &str) -> Vec<String> {
        let mut out: Vec<String> = self
            .table
            .locales
            .keys()
            .filter(|tag| self.built_in_for(id, tag).is_some())
            .cloned()
            .collect();
        out.sort();
        out
    }

    /// `reasonFor(category, language)`: the layout's `{{reason}}`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn reason_for(&self, id: &str, language: &str) -> String {
        let Some(category) = self.category(id) else {
            return "a message from this service".to_string();
        };
        for tag in self.chain_for(language) {
            let reason = self
                .table
                .locales
                .get(&tag)
                .and_then(|f| f.get("categories"))
                .and_then(|c| c.get(id))
                .and_then(|one| one.get("reason"))
                .and_then(Json::as_str)
                .filter(|r| !r.is_empty());
            if let Some(reason) = reason {
                return reason.to_string();
            }
        }
        category.reason.clone()
    }

    /// `placeholders(text)`: every `{{name}}`, once each, in order.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn placeholders(text: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        if let Some(re) = PLACEHOLDER.as_ref() {
            for cap in re.captures_iter(text) {
                let name = cap[1].to_string();
                if !out.contains(&name) {
                    out.push(name);
                }
            }
        }
        out
    }

    /// `problem(spec, parts)`: what is wrong with a realm's template, as
    /// Node's sentence, or `''`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn problem(spec: Option<&TemplateSpec>, parts: &Parts) -> String {
        let Some(spec) = spec else {
            return "there is no such message".to_string();
        };
        let (subject, text, html) = (&parts.subject, &parts.text, &parts.html);
        if js::trim(subject).is_empty()
            || js::trim(text).is_empty()
            || js::trim(html).is_empty()
        {
            return "a template needs a subject, a text part and an HTML part"
                .to_string();
        }
        if js::len(subject) > 250
            || js::len(text) > 20000
            || js::len(html) > 40000
        {
            return "a subject is at most 250 characters, a text part 20000 \
                    and an HTML part 40000"
                .to_string();
        }
        if subject.contains('\r') || subject.contains('\n') {
            return "a subject is one line".to_string();
        }
        let mut known: Vec<String> =
            COMMON.iter().map(|s| s.to_string()).collect();
        known.extend(spec.values.iter().cloned());
        known.extend(spec.links.iter().cloned());
        for part in [subject, text, html] {
            let url = URL.as_ref().is_some_and(|re| re.is_match(part));
            if url || has_mailto(part) {
                return format!(
                    "a template may not write an address of its own — a link \
                     is a placeholder ({}) whose value is this service's own",
                    if spec.links.is_empty() {
                        "this message has none".to_string()
                    } else {
                        links_text(&spec.links)
                    }
                );
            }
            let unknown: Vec<String> = Templates::placeholders(part)
                .into_iter()
                .filter(|name| !known.contains(name))
                .collect();
            if !unknown.is_empty() {
                return format!(
                    "unknown placeholder(s) {}; this message offers {}",
                    links_text(&unknown),
                    links_text(&known)
                );
            }
        }
        let layout = Templates::get().map_or("layout", |t| t.layout_id());
        if spec.id == layout {
            let once = |part: &str| {
                CONTENT.as_ref().map_or(0, |re| re.find_iter(part).count())
                    == 1
            };
            if !once(text) || !once(html) {
                return "the layout must carry {{content}} exactly once in \
                        the text part and once in the HTML part — it is \
                        where every message's own body goes"
                    .to_string();
            }
            if !SUBJECT.as_ref().is_some_and(|re| re.is_match(subject)) {
                return "the layout's subject must carry {{subject}}, the \
                        message's own subject"
                    .to_string();
            }
        }
        if !spec.links.is_empty()
            && spec
                .links
                .iter()
                .any(|name| !text.contains(&format!("{{{{{}}}}}", name)))
        {
            return format!(
                "the text part must carry every link ({}), because a reader \
                 may see no HTML at all",
                links_text(&spec.links)
            );
        }
        if html.contains("<!") || sanitize::changed_by_allow_list(html) {
            return "the HTML part may carry only text formatting, tables and \
                    links: a message this service sends loads nothing and \
                    runs nothing when it is opened"
                .to_string();
        }
        let bad = HREF.as_ref().is_some_and(|re| {
            re.find_iter(html).any(|found| {
                let head = HREF_HEAD
                    .as_ref()
                    .map_or(found.as_str().to_string(), |h| {
                        h.replace(found.as_str(), "").into_owned()
                    });
                let mut value = head.as_str();
                if value.starts_with('"') || value.starts_with('\'') {
                    value = &value[1..];
                }
                if value.ends_with('"') || value.ends_with('\'') {
                    value = &value[..value.len() - 1];
                }
                let value = js::trim(value);
                match WHOLE_PLACEHOLDER.as_ref().and_then(|w| w.captures(value))
                {
                    Some(cap) => !spec.links.iter().any(|l| l == &cap[1]),
                    None => true,
                }
            })
        });
        if bad {
            return format!(
                "an href must be exactly one link placeholder ({})",
                if spec.links.is_empty() {
                    "this message has none".to_string()
                } else {
                    links_text(&spec.links)
                }
            );
        }
        String::new()
    }

    /// `render(parts, values)`: each placeholder filled, escaped for HTML in
    /// the HTML part and stripped of control characters elsewhere; a
    /// placeholder with no value renders empty.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn render(parts: &Parts, values: &Map<String, Json>) -> Parts {
        let fill = |text: &str, html: bool| {
            fill_with(text, |name| {
                values.get(name).map(|v| escaped(v, html))
            })
        };
        Parts {
            subject: js::trim(&fill(&parts.subject, false)).to_string(),
            text: fill(&parts.text, false),
            html: fill(&parts.html, true),
        }
    }

    /// `wrap(layout, rendered, values)`: the layout round a rendered
    /// message — its body as `{{content}}`, unescaped, its subject as
    /// `{{subject}}`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn wrap(
        layout: &Parts,
        rendered: &Parts,
        values: &Map<String, Json>,
    ) -> Parts {
        let fill = |text: &str, html: bool, content: &str| {
            fill_with(text, |name| {
                if name == "content" {
                    return Some(content.to_string());
                }
                if name == "subject" {
                    return Some(escaped(
                        &Json::String(rendered.subject.clone()),
                        html,
                    ));
                }
                values.get(name).map(|v| escaped(v, html))
            })
        };
        let subject = js::trim(&fill(&layout.subject, false, "")).to_string();
        Parts {
            subject: if subject.is_empty() {
                rendered.subject.clone()
            } else {
                subject
            },
            text: fill(&layout.text, false, &rendered.text),
            html: fill(&layout.html, true, &rendered.html),
        }
    }

    /// `htmlDocument(body, lang)`.
    #[tracing::instrument(level = "debug", skip(body))]
    pub fn html_document(body: &str, lang: &str) -> String {
        format!(
            "<!DOCTYPE html><html lang=\"{}\"><head><meta charset=\"utf-8\">\
             </head><body>{}</body></html>",
            esc(if lang.is_empty() { "en" } else { lang }),
            body
        )
    }

    /// `languageOrder(preferred, fallback)`: each tag of an Accept-Language
    /// value and its primary subtag by q, then the fallback, then `en`.
    #[tracing::instrument(level = "debug")]
    pub fn language_order(preferred: &str, fallback: &str) -> Vec<String> {
        let mut ranked: Vec<(String, f64, usize)> = preferred
            .split(',')
            .enumerate()
            .filter_map(|(i, part)| {
                let bits: Vec<&str> = js::trim(part).split(';').collect();
                let tag = js::trim(bits.first().copied().unwrap_or(""))
                    .to_lowercase();
                let q = bits
                    .iter()
                    .skip(1)
                    .filter_map(|b| {
                        let cap = QUALITY.as_ref()?.captures(b)?;
                        cap[1].parse::<f64>().ok()
                    })
                    .next()
                    .unwrap_or(1.0);
                let ok = TAG.as_ref().is_some_and(|re| re.is_match(&tag));
                (ok && q > 0.0).then_some((tag, q, i))
            })
            .collect();
        ranked.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.2.cmp(&b.2))
        });
        let mut out: Vec<String> = Vec::new();
        let mut add = |tag: String| {
            if !tag.is_empty() && !out.contains(&tag) {
                out.push(tag);
            }
        };
        for (tag, _, _) in ranked {
            let primary = tag.split('-').next().unwrap_or("").to_string();
            add(tag);
            add(primary);
        }
        add(js::trim(fallback).to_lowercase());
        add("en".to_string());
        out
    }
}

/// A value as a part takes it. A hot path: no span.
fn escaped(value: &Json, html: bool) -> String {
    let text = js::text_or_empty(Some(value));
    if html {
        esc(&text)
    } else {
        plain(&text)
    }
}

/// Each placeholder replaced by what `value` answers, `''` for `None`.
fn fill_with(text: &str, value: impl Fn(&str) -> Option<String>) -> String {
    let Some(re) = PLACEHOLDER.as_ref() else {
        return text.to_string();
    };
    re.replace_all(text, |cap: &regex::Captures| {
        value(&cap[1]).unwrap_or_default()
    })
    .into_owned()
}
