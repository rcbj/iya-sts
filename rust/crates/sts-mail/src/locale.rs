// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Which translation files a language tag reads: `mail_templates.ts`'s
//! `chainFor()` over `i18n.chainFor()` and `web_locale.ts`'s
//! `canonical()`, `partsOf()` and `chainFor()`.
//!
//! **NODE ASKS `Intl`, AND THIS ASKS A TABLE.** `Intl.getCanonicalLocales()`
//! and `Intl.Locale.maximize()` stand on CLDR; a catalog is matched only by
//! its language and script, and by its region where it names one, so what
//! matters is the likely script and region of the languages the catalogs
//! are in (`tables/mail_templates.json`'s `catalogs`). Those are below;
//! any other language matches no catalog in either implementation. The
//! vectors hold the two to the same answer over a list of tags.

use std::collections::HashMap;

/// One tag's parts, as `partsOf()` answers them.
#[derive(Debug, Clone, PartialEq)]
struct Parts {
    tag: String,
    language: String,
    script: String,
    region: String,
    explicit_region: String,
}

/// The parts of a well-formed, canonical tag. CLDR's aliases that matter
/// here: `tl` is `fil`. A hot path (every message): no span.
fn parts_of(tag: &str) -> Option<Parts> {
    let subtags: Vec<&str> = tag.split('-').collect();
    let mut language = subtags.first()?.to_lowercase();
    if language == "tl" {
        language = "fil".to_string();
    }
    let mut script = String::new();
    let mut region = String::new();
    for one in subtags.iter().skip(1) {
        if one.len() == 4 && one.chars().all(|c| c.is_ascii_alphabetic()) {
            if script.is_empty() && region.is_empty() {
                script = title(one);
            }
        } else if (one.len() == 2
            && one.chars().all(|c| c.is_ascii_alphabetic()))
            || (one.len() == 3 && one.chars().all(|c| c.is_ascii_digit()))
        {
            if region.is_empty() {
                region = one.to_uppercase();
            }
        }
    }
    let explicit_region = region.clone();
    let (likely_script, likely_region) = likely(&language, &script, &region);
    if script.is_empty() {
        script = likely_script.to_string();
    }
    if region.is_empty() {
        region = likely_region.to_string();
    }
    Some(Parts {
        tag: tag.to_string(),
        language,
        script,
        region,
        explicit_region,
    })
}

/// CLDR's likely subtags for the catalogs' languages.
fn likely(
    language: &str,
    script: &str,
    region: &str,
) -> (&'static str, &'static str) {
    match language {
        "zh" => {
            let hant = script == "Hant"
                || (script.is_empty()
                    && matches!(region, "TW" | "HK" | "MO"));
            if hant {
                ("Hant", "TW")
            } else {
                ("Hans", "CN")
            }
        }
        "en" => ("Latn", "US"),
        "fr" => ("Latn", "FR"),
        "es" => ("Latn", "ES"),
        "sv" => ("Latn", "SE"),
        "fil" => ("Latn", "PH"),
        _ => ("", ""),
    }
}

fn title(text: &str) -> String {
    let mut out = String::new();
    for (i, c) in text.chars().enumerate() {
        if i == 0 {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

/// `Intl.getCanonicalLocales(tag)[0]`, for the well-formed tags of the
/// syntax RFC 5646 section 2.1 gives (language, script, region, variants,
/// extensions), or `''`. A hot path: no span.
pub fn canonical(tag: &str) -> String {
    let text = crate::js::trim(tag);
    if text.is_empty() || crate::js::len(text) > 64 || text == "*" {
        return String::new();
    }
    let subtags: Vec<&str> = text.split('-').collect();
    let first = subtags[0];
    let alpha = |s: &str| s.chars().all(|c| c.is_ascii_alphabetic());
    let alnum = |s: &str| s.chars().all(|c| c.is_ascii_alphanumeric());
    if !alpha(first) || !matches!(first.len(), 2 | 3 | 5..=8) {
        return String::new();
    }
    let mut out = vec![first.to_lowercase()];
    let mut stage = 0;
    for one in subtags.iter().skip(1) {
        if one.is_empty() || one.len() > 8 || !alnum(one) {
            return String::new();
        }
        if stage < 1 && one.len() == 4 && alpha(one) {
            out.push(title(one));
            stage = 1;
        } else if stage < 2
            && ((one.len() == 2 && alpha(one))
                || (one.len() == 3
                    && one.chars().all(|c| c.is_ascii_digit())))
        {
            out.push(one.to_uppercase());
            stage = 2;
        } else if (one.len() >= 5)
            || (one.len() == 4 && one.chars().next().is_some_and(|c| {
                c.is_ascii_digit()
            }))
        {
            out.push(one.to_lowercase());
            stage = 3;
        } else {
            return String::new();
        }
    }
    out.join("-")
}

/// The catalogs' tags, with their parts.
pub struct Catalogs {
    source: String,
    parts: Vec<Parts>,
}

impl Catalogs {
    /// From `catalogs.json`'s rows and its source tag.
    pub fn new(tags: &[String], source: &str) -> Catalogs {
        Catalogs {
            source: source.to_string(),
            parts: tags.iter().filter_map(|tag| parts_of(tag)).collect(),
        }
    }

    /// `MailTemplates.chainFor()`: the catalogs to read for a tag, most
    /// specific first, the source language left out; empty when no
    /// catalog answers. A hot path (every message): no span.
    pub fn chain_for(&self, language: &str) -> Vec<String> {
        let tag = canonical(language);
        if tag.is_empty() {
            return Vec::new();
        }
        let Some(want) = parts_of(&tag) else {
            return Vec::new();
        };
        let same: Vec<&Parts> = self
            .parts
            .iter()
            .filter(|has| {
                has.language == want.language && has.script == want.script
            })
            .collect();
        let mut chain: Vec<String> = Vec::new();
        for has in same.iter().filter(|has| {
            !has.explicit_region.is_empty()
                && has.explicit_region == want.region
        }) {
            if !chain.contains(&has.tag) {
                chain.push(has.tag.clone());
            }
        }
        for has in same.iter().filter(|has| has.explicit_region.is_empty()) {
            if !chain.contains(&has.tag) {
                chain.push(has.tag.clone());
            }
        }
        chain.retain(|one| one != &self.source);
        chain
    }
}

/// A cache-free lookup table type the templates module keys by tag.
pub type ByTag<T> = HashMap<String, T>;
