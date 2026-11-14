// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The catalogs (#539) as the HTTP layer needs them — a port of the parts
//! of `common/i18n.ts` and `common/web_locale.ts` a shell and `/web` read:
//! the catalogs loaded from `common/locales/` (the index `catalogs.json`
//! and one directory per namespace), a namespace's messages in one catalog
//! as `/web/locales/<ns>/<tag>.json` serves them, the console's merged
//! `console-all`, the order of a page's language preferences, the
//! negotiation of those against the catalogs, and a translator for the
//! words the server draws itself (the page footer).
//!
//! **THE BROWSER TRANSLATES** (rcbj's decision 3 on #570): every static
//! surface negotiates and formats in the browser from these same files,
//! so what the server needs is the files served as they were loaded and
//! the few words a shell carries.
//!
//! **TAGS ARE ICU'S, AS NODE'S ARE.** `Intl.getCanonicalLocales()` and
//! `Intl.Locale.maximize()` are V8's ICU; here they are ICU4X's
//! `LocaleCanonicalizer` and `LocaleExpander`, over the CLDR data each
//! carries — so `tl` is `fil`, `iw` is `he`, and `zh-TW` reaches the
//! `zh-Hant` catalog. A tag either refuses is skipped, as Node skips it.
//!
//! **WHAT IS NOT HERE**: the MessageFormat a static surface's runtime
//! formats with (`web_messages.ts`), which the browser runs. The server's
//! translator formats `{name}` arguments only — every message the server
//! draws (the footer's) uses nothing else; one with a plural or a select
//! is drawn as written, which is what Node does with a message it cannot
//! format.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use icu_locale::{Locale, LocaleCanonicalizer, LocaleExpander};
use serde_json::{Map, Value as Json};
use sts_core::errors::codes;
use sts_core::log::tag;

/// The catalog every chain ends in.
pub const SOURCE: &str = "en";

/// A catalog's tag taken apart (`TagParts`).
#[derive(Clone, Debug, PartialEq)]
pub struct TagParts {
    pub tag: String,
    pub language: String,
    pub script: String,
    pub region: String,
    pub explicit_region: String,
    pub rtl: bool,
}

/// A negotiation's answer (`Negotiated`).
#[derive(Clone, Debug, PartialEq)]
pub struct Negotiated {
    pub locale: String,
    pub chain: Vec<String>,
    pub catalog: String,
    pub rtl: bool,
    pub matched: bool,
}

/// `WebLocale.canonical()`: a canonical tag, or '' for one that is not
/// well-formed (`Intl.getCanonicalLocales()`).
#[tracing::instrument(level = "trace")]
pub fn canonical(tag: &str) -> String {
    let text = tag.trim();
    if text.is_empty() || text.chars().count() > 64 || text == "*" {
        return String::new();
    }
    // Node refuses the grandfathered and private-use forms; ICU4X refuses
    // them too, and an underscore, which `Intl` refuses as well.
    if text.contains('_') {
        return String::new();
    }
    let Ok(mut locale) = Locale::try_from_str(text) else {
        return String::new();
    };
    LocaleCanonicalizer::new_extended().canonicalize(&mut locale);
    locale.to_string()
}

/// Scripts written right to left, for a tag's direction.
const RTL_SCRIPTS: &[&str] = &[
    "Arab", "Hebr", "Thaa", "Syrc", "Nkoo", "Adlm", "Rohg", "Mand", "Samr",
    "Mend", "Yezi",
];

/// `WebLocale.partsOf()`: a canonical tag taken apart, maximized.
#[tracing::instrument(level = "trace")]
pub fn parts_of(tag: &str) -> Option<TagParts> {
    let given = Locale::try_from_str(tag).ok()?;
    let mut full = given.id.clone();
    LocaleExpander::new_extended().maximize(&mut full);
    let script = full.script.map(|s| s.to_string()).unwrap_or_default();
    Some(TagParts {
        tag: tag.to_string(),
        language: full.language.to_string(),
        rtl: RTL_SCRIPTS.contains(&script.as_str()),
        script,
        region: full.region.map(|r| r.to_string()).unwrap_or_default(),
        explicit_region: given
            .id
            .region
            .map(|r| r.to_string())
            .unwrap_or_default(),
    })
}

/// `WebLocale.acceptLanguage()`: an `Accept-Language` value's tags, best
/// first; `q=0` and the wildcard left out, a malformed tag skipped.
#[tracing::instrument(level = "trace")]
pub fn accept_language(value: &str) -> Vec<String> {
    let mut rows: Vec<(String, f64, usize)> = Vec::new();
    for (at, part) in value.split(',').take(32).enumerate() {
        let mut bits = part.trim().split(';');
        let tag = canonical(bits.next().unwrap_or(""));
        if tag.is_empty() {
            continue;
        }
        let mut q = 1.0_f64;
        for param in bits {
            let param = param.trim();
            let Some((name, v)) = param.split_once('=') else {
                continue;
            };
            let v = v.trim();
            if name.trim().eq_ignore_ascii_case("q")
                && !v.is_empty()
                && v.bytes().all(|b| b.is_ascii_digit() || b == b'.')
            {
                q = js_number(v);
            }
        }
        if q.is_nan() || q <= 0.0 {
            continue;
        }
        rows.push((tag, q.min(1.0), at));
    }
    rows.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.2.cmp(&b.2))
    });
    let mut out: Vec<String> = Vec::new();
    for (tag, _, _) in rows {
        if !out.contains(&tag) {
            out.push(tag);
        }
    }
    out
}

/// `Number()` of a digits-and-dots string: NaN for `1.2.3`.
fn js_number(text: &str) -> f64 {
    text.parse::<f64>().unwrap_or(f64::NAN)
}

/// `WebLocale.uiLocales()`.
#[tracing::instrument(level = "trace")]
pub fn ui_locales(value: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for part in value.split_whitespace().take(32) {
        let tag = canonical(part);
        if !tag.is_empty() && !out.contains(&tag) {
            out.push(tag);
        }
    }
    out
}

/// What a page's language is chosen from (`PreferenceInputs`).
#[derive(Clone, Debug, Default)]
pub struct Preferences {
    pub ui_locales: String,
    /// The person's own `preferredLanguage`, and whether the locale policy
    /// populated it.
    pub own: Option<(String, bool)>,
    /// The chooser's cookie, `sts_lang`.
    pub chooser: String,
    pub accept_language: String,
}

/// `WebLocale.preferences()`: canonical tags, best first, each once.
#[tracing::instrument(level = "trace", skip_all)]
pub fn preferences(input: &Preferences) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |tags: Vec<String>| {
        for tag in tags {
            if !tag.is_empty() && !out.contains(&tag) {
                out.push(tag);
            }
        }
    };
    add(ui_locales(&input.ui_locales));
    if let Some((value, false)) = &input.own {
        if !value.is_empty() {
            add(accept_language(value));
        }
    }
    add(vec![canonical(&input.chooser)]);
    add(accept_language(&input.accept_language));
    if let Some((value, true)) = &input.own {
        if !value.is_empty() {
            add(accept_language(value));
        }
    }
    out
}

/// One catalog's index row, kept as JSON so it is served as it was read.
#[derive(Clone, Debug)]
struct CatalogRow {
    tag: String,
    raw: Map<String, Json>,
}

/// The catalogs, loaded once from `common/locales/`.
pub struct Catalogs {
    rows: Vec<CatalogRow>,
    offered: Vec<Json>,
    parts: Vec<TagParts>,
    /// namespace → catalog → the file's string members, in a JavaScript
    /// object's key order.
    messages: BTreeMap<String, BTreeMap<String, Map<String, Json>>>,
    problems: Vec<String>,
}

/// A JSON object's members in a JavaScript object's order: array indices
/// (canonical non-negative integers below 2^32 - 1) first, ascending, then
/// the rest as written. `JSON.parse` then `JSON.stringify` reorder them
/// so, and the files are served through that pair.
pub fn js_order(map: Map<String, Json>) -> Map<String, Json> {
    let index = |k: &str| -> Option<u64> {
        let ok = !k.is_empty()
            && k.bytes().all(|b| b.is_ascii_digit())
            && (k == "0" || !k.starts_with('0'));
        ok.then(|| k.parse::<u64>().ok())
            .flatten()
            .filter(|n| *n < u64::from(u32::MAX))
    };
    let mut numbered: Vec<(u64, String, Json)> = Vec::new();
    let mut named: Vec<(String, Json)> = Vec::new();
    for (k, v) in map {
        match index(&k) {
            Some(n) => numbered.push((n, k, v)),
            None => named.push((k, v)),
        }
    }
    numbered.sort_by_key(|(n, _, _)| *n);
    let mut out = Map::new();
    for (_, k, v) in numbered {
        out.insert(k, v);
    }
    for (k, v) in named {
        out.insert(k, v);
    }
    out
}

impl Catalogs {
    /// Reads `<dir>/catalogs.json` and every namespace directory beside it.
    /// A file that cannot be read costs its messages, never the start.
    #[tracing::instrument(level = "debug")]
    pub fn load(dir: &Path) -> Catalogs {
        let mut problems = Vec::new();
        let index: Json = match std::fs::read_to_string(
            dir.join("catalogs.json"),
        )
        .map_err(|e| e.to_string())
        .and_then(|t| serde_json::from_str(&t).map_err(|e| e.to_string()))
        {
            Ok(j) => j,
            Err(e) => {
                tracing::error!(
                    "{}i18n: common/locales/catalogs.json could not be read \
                     ({}), so every page is drawn in English.",
                    tag(codes::STS_I18N_0001),
                    e
                );
                problems
                    .push(format!("catalogs.json could not be read: {}", e));
                serde_json::json!({
                    "source": SOURCE, "offered": [],
                    "catalogs": [{ "tag": SOURCE, "name": "English",
                                   "english": "English", "status": "source" }]
                })
            }
        };
        let rows: Vec<CatalogRow> = index
            .get("catalogs")
            .and_then(Json::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(|r| r.as_object().cloned())
                    .map(|raw| CatalogRow {
                        tag: raw
                            .get("tag")
                            .and_then(Json::as_str)
                            .unwrap_or("")
                            .to_string(),
                        raw,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let offered = index
            .get("offered")
            .and_then(Json::as_array)
            .cloned()
            .unwrap_or_default();
        let parts = rows.iter().filter_map(|r| parts_of(&r.tag)).collect();
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                    .filter_map(|e| e.file_name().into_string().ok())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        let mut messages = BTreeMap::new();
        for ns in names {
            let mut by_tag = BTreeMap::new();
            for row in &rows {
                let file = dir.join(&ns).join(format!("{}.json", row.tag));
                if !file.exists() {
                    continue;
                }
                let parsed = std::fs::read_to_string(&file)
                    .map_err(|e| e.to_string())
                    .and_then(|t| {
                        serde_json::from_str::<Json>(&t)
                            .map_err(|e| e.to_string())
                    });
                match parsed {
                    Ok(Json::Object(body)) => {
                        let flat: Map<String, Json> = body
                            .into_iter()
                            .filter(|(_, v)| v.is_string())
                            .collect();
                        by_tag.insert(row.tag.clone(), js_order(flat));
                    }
                    Ok(_) => {
                        by_tag.insert(row.tag.clone(), Map::new());
                    }
                    Err(e) => {
                        tracing::error!(
                            "{}i18n: {}/{}.json could not be read ({}); its \
                             messages fall back along the chain to English.",
                            tag(codes::STS_I18N_0001),
                            ns,
                            row.tag,
                            e
                        );
                        problems.push(format!(
                            "{}/{}.json could not be read: {}",
                            ns, row.tag, e
                        ));
                    }
                }
            }
            messages.insert(ns, by_tag);
        }
        Catalogs {
            rows,
            offered,
            parts,
            messages,
            problems,
        }
    }

    /// The directory a tree's catalogs are in: `common/locales`.
    #[tracing::instrument(level = "debug")]
    pub fn dir_in(root: &Path) -> PathBuf {
        root.join("common").join("locales")
    }

    /// `catalogs()`: every catalog's index row, in order.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn catalogs(&self) -> Vec<Json> {
        self.rows
            .iter()
            .map(|r| Json::Object(r.raw.clone()))
            .collect()
    }

    /// `offered()`: the locales the chooser offers.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn offered(&self) -> Vec<Json> {
        self.offered.clone()
    }

    /// `namespaces()`, sorted.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn namespaces(&self) -> Vec<String> {
        self.messages.keys().cloned().collect()
    }

    /// Whether a catalog of this tag exists.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn has_catalog(&self, tag: &str) -> bool {
        self.rows.iter().any(|r| r.tag == tag)
    }

    /// `messagesOf()`: one namespace's messages in one catalog; empty when
    /// there are none.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn messages_of(&self, ns: &str, tag: &str) -> Map<String, Json> {
        self.messages
            .get(ns)
            .and_then(|m| m.get(tag))
            .cloned()
            .unwrap_or_default()
    }

    /// `catalogData()`'s one catalog: every namespace starting with
    /// `prefix` (and the footer's), keyed `namespace.key`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn merged(&self, tag: &str, prefix: &str) -> Map<String, Json> {
        let mut flat = Map::new();
        for (ns, by_tag) in &self.messages {
            if !(ns.starts_with(prefix) || ns == "footer") {
                continue;
            }
            if let Some(own) = by_tag.get(tag) {
                for (k, v) in own {
                    flat.insert(format!("{}.{}", ns, k), v.clone());
                }
            }
        }
        js_order(flat)
    }

    /// What went wrong while the catalogs were read.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn problems(&self) -> Vec<String> {
        self.problems.clone()
    }

    /// `WebLocale.chainFor()`: the catalogs that answer one tag, most
    /// specific first and English last.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn chain_for(&self, tag: &str) -> (Vec<String>, bool, bool) {
        let Some(want) = parts_of(tag) else {
            return (vec![SOURCE.to_string()], false, false);
        };
        let same: Vec<&TagParts> = self
            .parts
            .iter()
            .filter(|h| h.language == want.language && h.script == want.script)
            .collect();
        let regional = same.iter().filter(|h| {
            !h.explicit_region.is_empty() && h.explicit_region == want.region
        });
        let bases = same.iter().filter(|h| h.explicit_region.is_empty());
        let mut chain: Vec<String> = Vec::new();
        for has in regional.chain(bases) {
            if !chain.contains(&has.tag) {
                chain.push(has.tag.clone());
            }
        }
        let matched = !chain.is_empty();
        if !chain.iter().any(|c| c == SOURCE) {
            chain.push(SOURCE.to_string());
        }
        (chain, matched, want.rtl)
    }

    /// `WebLocale.negotiate()`: the first preference a catalog answers,
    /// else the last resort, else English.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn negotiate(
        &self,
        preferences: &[String],
        last_resort: &str,
    ) -> Negotiated {
        let mut tried: Vec<String> = preferences.to_vec();
        if !last_resort.is_empty() {
            tried.push(last_resort.to_string());
        }
        for raw in tried {
            let tag = canonical(&raw);
            if tag.is_empty() {
                continue;
            }
            let (chain, matched, rtl) = self.chain_for(&tag);
            if matched {
                return Negotiated {
                    locale: tag,
                    catalog: chain[0].clone(),
                    chain,
                    rtl,
                    matched: true,
                };
            }
        }
        Negotiated {
            locale: SOURCE.to_string(),
            chain: vec![SOURCE.to_string()],
            catalog: SOURCE.to_string(),
            rtl: false,
            matched: false,
        }
    }

    /// `i18n.translator()`: a translator over a negotiation.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn translator(
        &self,
        preferences: &[String],
        last_resort: &str,
    ) -> Translator<'_> {
        Translator {
            catalogs: self,
            negotiated: self.negotiate(preferences, last_resort),
        }
    }
}

/// A page's words in its negotiated language.
pub struct Translator<'a> {
    catalogs: &'a Catalogs,
    pub negotiated: Negotiated,
}

impl Translator<'_> {
    fn find(&self, key: &str) -> Option<String> {
        let (ns, name) = key.split_once('.')?;
        self.negotiated.chain.iter().find_map(|tag| {
            self.catalogs
                .messages
                .get(ns)
                .and_then(|m| m.get(tag))
                .and_then(|m| m.get(name))
                .and_then(Json::as_str)
                .map(str::to_string)
        })
    }

    /// Whether some catalog along the chain has the message.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn has(&self, key: &str) -> bool {
        self.find(key).is_some()
    }

    /// The message as text, its `{name}` arguments filled; the key where no
    /// catalog has it.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn text(&self, key: &str, params: &[(&str, &str)]) -> String {
        let Some(message) = self.find(key) else {
            tracing::warn!(
                "{}i18n: no catalog has the message {}, so its key is drawn.",
                tag(codes::STS_I18N_0002),
                key
            );
            return key.to_string();
        };
        fill(&message, params)
    }
}

/// `{name}` arguments filled; anything else as written.
fn fill(message: &str, params: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(message.len());
    let mut rest = message;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        match after.find('}') {
            Some(close)
                if after[..close]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_') =>
            {
                let name = &after[..close];
                match params.iter().find(|(n, _)| *n == name) {
                    Some((_, v)) => out.push_str(v),
                    None => out.push_str(&rest[open..open + close + 2]),
                }
                rest = &after[close + 1..];
            }
            _ => {
                out.push('{');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_canonical_as_intl_makes_them() {
        assert_eq!(canonical("EN-us"), "en-US");
        assert_eq!(canonical("fr-ca"), "fr-CA");
        assert_eq!(canonical("zh-hk"), "zh-HK");
        assert_eq!(canonical("tl"), "fil");
        assert_eq!(canonical("iw"), "he");
        assert_eq!(canonical("*"), "");
        assert_eq!(canonical("en_US"), "");
    }

    #[test]
    fn a_tag_is_maximized_as_intl_maximizes_it() {
        let p = parts_of("zh-TW").unwrap();
        assert_eq!((p.language.as_str(), p.script.as_str()), ("zh", "Hant"));
        let p = parts_of("zh").unwrap();
        assert_eq!((p.script.as_str(), p.region.as_str()), ("Hans", "CN"));
        assert!(parts_of("he").unwrap().rtl);
        assert_eq!(parts_of("fr-CA").unwrap().explicit_region, "CA");
    }

    #[test]
    fn accept_language_orders_by_weight_then_position() {
        assert_eq!(
            accept_language("fr;q=0.5, en-GB, de;q=0, *, zh-tw;q=0.9"),
            vec!["en-GB", "zh-TW", "fr"]
        );
    }

    #[test]
    fn arguments_are_filled_and_the_rest_kept() {
        assert_eq!(fill("© {years} Iya", &[("years", "2026")]), "© 2026 Iya");
        assert_eq!(fill("{a} {b}", &[("a", "1")]), "1 {b}");
    }
}
