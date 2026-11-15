// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The page footer every shell draws (rcbj, 2026-11-14) — a port of
//! `common/web_footer.ts`'s markup and `common/page_footer.ts`'s facts:
//! the three links, the two social accounts, the copyright and the
//! version, in the page's language, with the version and the build line
//! from `version.json` (the one source every surface that draws a version
//! reads) and the current year.
//!
//! The stylesheet is `/web/footer.css` ([`CSS`]) and the social items'
//! markup holds no word to translate, so both are the TypeScript module's
//! own text, kept beside this crate (`assets/`) and held to Node's bytes
//! by the differential harness (`tests/tools/http-differential.js`).

use sts_core::version::VersionInfo;

use crate::express::escape_html as esc;
use crate::i18n::Translator;

/// `/web/footer.css` (`WebFooter.CSS`).
pub const CSS: &str = include_str!("../assets/web_footer.css");

/// The two social accounts' `<li>` items (`WebFooter.SOCIAL`, drawn).
const SOCIAL_ITEMS: &str = include_str!("../assets/footer_social_items.html");

/// The three links, in the model's order: key, English, address.
const LINKS: &[(&str, &str, &str)] = &[
    (
        "documentation",
        "Documentation",
        "https://rcbj.github.io/iya-sts/",
    ),
    (
        "contact",
        "Contact",
        "https://github.com/rcbj/iya-sts/issues",
    ),
    ("about", "About", "https://github.com/rcbj/iya-sts"),
];

/// The English of each message, where a translator does not have it.
fn english(key: &str) -> &'static str {
    match key {
        "documentation" => "Documentation",
        "contact" => "Contact",
        "about" => "About",
        "linksLabel" => "About this service",
        "socialLabel" => "Iya CyberSecurity Solutions on social media",
        "copyright" => {
            "© {years} Iya CyberSecurity Solutions, LLC. All \
                        rights reserved."
        }
        "version" => "Version {version}",
        _ => "",
    }
}

/// The facts a footer draws that are not words.
#[derive(Clone, Debug)]
pub struct Facts {
    pub version: String,
    pub build_info: String,
    pub year: String,
}

/// `version.buildInfo()`: the build line for a footer's title.
#[tracing::instrument(level = "debug", skip_all)]
pub fn build_info(v: &VersionInfo) -> String {
    let head = if v.build.is_empty() {
        String::new()
    } else {
        format!(
            "{}{} — ",
            if v.release {
                "Release build "
            } else {
                "Build "
            },
            v.build
        )
    };
    format!(
        "{}{}{}{}{}",
        head,
        if v.stamped { "Built " } else { "Started " },
        v.built_at,
        if v.commit.is_empty() {
            String::new()
        } else {
            format!(" — commit {}", v.commit)
        },
        if v.stamped {
            ""
        } else {
            " — not a stamped build (running from a checkout)"
        }
    )
}

/// `version.buildId()`: the build instant's digits and the commit, the key
/// the catalogs' addresses are cached by.
#[tracing::instrument(level = "debug", skip_all)]
pub fn build_id(v: &VersionInfo) -> String {
    let at: String = v.built_at.chars().filter(char::is_ascii_digit).collect();
    let at = if at.is_empty() { "0".to_string() } else { at };
    if v.commit.is_empty() {
        at
    } else {
        format!("{}-{}", at, v.commit)
    }
}

/// `PageFooter.facts()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn facts(v: &VersionInfo) -> Facts {
    Facts {
        version: v.version.clone(),
        build_info: build_info(v),
        year: chrono::Utc::now().format("%Y").to_string(),
    }
}

/// `WebFooter.years()`: 2026 alone while it is the current year, the
/// range once it has moved on.
fn years(year: &str) -> String {
    match year.parse::<i64>() {
        Ok(now) if now > 2026 => format!("2026–{}", now),
        _ => "2026".to_string(),
    }
}

/// `WebFooter.word()`: the translator's message, or English.
fn word(
    t: Option<&Translator<'_>>,
    key: &str,
    params: &[(&str, &str)],
) -> String {
    let full = format!("footer.{}", key);
    if let Some(t) = t.filter(|t| t.has(&full)) {
        return t.text(&full, params);
    }
    let mut out = english(key).to_string();
    for (name, value) in params {
        out = out.replace(&format!("{{{}}}", name), value);
    }
    out
}

/// `WebFooter.html()`: the `<footer>` element.
#[tracing::instrument(level = "debug", skip_all)]
pub fn html(t: Option<&Translator<'_>>, facts: &Facts) -> String {
    let links: String = LINKS
        .iter()
        .map(|(key, _, href)| {
            format!(
                "<li><a href=\"{}\" target=\"_blank\" rel=\"noopener \
                 noreferrer\">{}</a></li>",
                esc(href),
                esc(&word(t, key, &[]))
            )
        })
        .collect();
    format!(
        "<footer class=\"sts-footer\" data-sts-footer-version=\"{}\" \
         data-sts-footer-build=\"{}\" data-sts-footer-year=\"{}\"><ul \
         class=\"sts-footer-links\" aria-label=\"{}\">{}</ul><ul \
         class=\"sts-footer-social\" aria-label=\"{}\">{}</ul><div \
         class=\"sts-footer-copyright\">{}</div><div \
         class=\"sts-footer-version\" title=\"{}\">{}</div></footer>",
        esc(&facts.version),
        esc(&facts.build_info),
        esc(&facts.year),
        esc(&word(t, "linksLabel", &[])),
        links,
        esc(&word(t, "socialLabel", &[])),
        SOCIAL_ITEMS,
        esc(&word(t, "copyright", &[("years", &years(&facts.year))])),
        esc(&facts.build_info),
        esc(&word(t, "version", &[("version", &facts.version)]))
    )
}
