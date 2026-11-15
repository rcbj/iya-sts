// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A realm's sign-in appearance (#717) — a port of `common/branding.ts`:
//! its four colours (`branding.accentColor`, `pageColor`, `cardColor`,
//! `textColor`), the ten quieter tones derived from them and never set,
//! the closed set of layouts, the brand name and the logo, reaching a page
//! as `/web/theme.css` (the custom properties that differ from a realm
//! that set nothing) and as `<html>` attributes the runtime draws from.
//!
//! **CONTRAST BELOW WCAG 2.2 AA IS REFUSED** (D3): [`ContrastRule`] is a
//! settings write rule, so every door that writes a colour — the console,
//! the API, a restored value — refuses a text or accent colour below
//! 4.5:1 against the card (`STS-AUTHN-0544`), and a logo link that is not
//! an absolute https URL (`STS-AUTHN-0551`).
//!
//! **WHAT REPLACED WHAT.** The logo is kept in the realm's persisted store
//! (`branding.assets`), which the store slice ports: it arrives through
//! [`LogoStore`], and an empty slot holds no logo — the answer for every
//! realm that never uploaded one. The upload, the console's preview page
//! (`/web/branding/preview`) and the `logoAlt` rule that needs the store
//! are listed in the slice's report as left for the phase that ports the
//! console's appearance page.

use std::sync::{Arc, RwLock};

use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use serde_json::Value as Json;
use sts_core::errors::{codes, ErrorCode};
use sts_core::settings::{SettingValue, Settings, WriteRule};

/// The layouts a realm may choose.
const LAYOUTS: &[&str] = &["centered", "split", "banner"];

/// The four colours, by name, setting and default.
const COLOURS: &[(&str, &str, &str)] = &[
    ("accent", "branding.accentColor", "#12107c"),
    ("page", "branding.pageColor", "#f4f4f7"),
    ("card", "branding.cardColor", "#ffffff"),
    ("text", "branding.textColor", "#222222"),
];

/// The custom properties as a realm that set nothing has them, in the
/// palette's order.
const DEFAULT_PROPERTIES: &[(&str, &str)] = &[
    ("accent", "#12107c"),
    ("on-accent", "#ffffff"),
    ("page", "#f4f4f7"),
    ("card", "#ffffff"),
    ("text", "#222222"),
    ("muted", "#666666"),
    ("faint", "#777777"),
    ("dim", "#555555"),
    ("border", "#d5d5dd"),
    ("rule", "#eeeeee"),
    ("tint", "#fafafd"),
    ("tint-2", "#f0f0f5"),
    ("bad", "#b00020"),
    ("good", "#0b6b4f"),
];

/// WCAG 2.2 AA's contrast for normal text (1.4.3).
pub const AA_CONTRAST: f64 = 4.5;

/// The paths this module answers.
pub const THEME_PATH: &str = "/web/theme.css";
pub const LOGO_PATH: &str = "/web/branding/logo";

/// A realm's stored logo: what `branding.assets`' `logo` row holds.
#[derive(Clone, Debug)]
pub struct Logo {
    pub content_type: String,
    pub bytes: Vec<u8>,
    pub sha256: String,
}

/// The ambient realm's logo, from its persisted store.
pub trait LogoStore: Send + Sync {
    fn logo(&self) -> Option<Logo>;
}

/// `#rrggbb`'s channels.
fn channels(hex: &str) -> Option<[f64; 3]> {
    let h = hex.strip_prefix('#')?;
    if h.len() != 6 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let c = |i: usize| u8::from_str_radix(&h[i..i + 2], 16).ok().map(f64::from);
    Some([c(0)?, c(2)?, c(4)?])
}

/// A colour's relative luminance (WCAG 2.2).
#[tracing::instrument(level = "trace")]
pub fn luminance(hex: &str) -> f64 {
    let c = channels(hex).unwrap_or([0.0; 3]);
    let lin = |v: f64| {
        let s = v / 255.0;
        if s <= 0.04045 {
            s / 12.92
        } else {
            ((s + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * lin(c[0]) + 0.7152 * lin(c[1]) + 0.0722 * lin(c[2])
}

/// The contrast ratio of two colours, 1 to 21.
#[tracing::instrument(level = "trace")]
pub fn contrast(a: &str, b: &str) -> f64 {
    let (la, lb) = (luminance(a), luminance(b));
    (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
}

/// `t` of the way from `a` to `b`.
#[tracing::instrument(level = "trace")]
pub fn mix(a: &str, b: &str, t: f64) -> String {
    let x = channels(a).unwrap_or([0.0; 3]);
    let y = channels(b).unwrap_or([0.0; 3]);
    let mut out = String::from("#");
    for i in 0..3 {
        // `Math.round()`: half up.
        let v = (x[i] + (y[i] - x[i]) * t + 0.5).floor() as i64;
        out.push_str(&format!("{:02x}", v));
    }
    out
}

/// The text mixed toward the card as far as `t` while it keeps AA.
fn quieter(text: &str, card: &str, t: f64) -> String {
    let mut at = t;
    let mut out = mix(text, card, at);
    while at > 0.0 && contrast(&out, card) < AA_CONTRAST {
        at = (at - 0.02).max(0.0);
        out = mix(text, card, at);
    }
    out
}

/// Of several colours, the first with AA, or the one with the most.
fn readable(choices: &[&str], background: &str) -> String {
    let mut best = choices[0];
    for one in choices {
        if contrast(one, background) >= AA_CONTRAST {
            return (*one).to_string();
        }
        if contrast(one, background) > contrast(best, background) {
            best = one;
        }
    }
    best.to_string()
}

/// `palette()`: the fourteen custom properties, in order.
#[tracing::instrument(level = "debug")]
pub fn palette(
    accent: &str,
    page: &str,
    card: &str,
    text: &str,
) -> Vec<(String, String)> {
    let on_accent =
        if contrast("#ffffff", accent) >= contrast("#000000", accent) {
            "#ffffff"
        } else {
            "#000000"
        };
    let before = text == "#222222" && card == "#ffffff";
    let pick =
        |old: &str, new: String| if before { old.to_string() } else { new };
    vec![
        ("accent".into(), accent.into()),
        ("on-accent".into(), on_accent.into()),
        ("page".into(), page.into()),
        ("card".into(), card.into()),
        ("text".into(), text.into()),
        ("muted".into(), pick("#666666", quieter(text, card, 0.31))),
        ("faint".into(), pick("#777777", quieter(text, card, 0.38))),
        ("dim".into(), pick("#555555", quieter(text, card, 0.24))),
        ("border".into(), pick("#d5d5dd", mix(text, card, 0.81))),
        ("rule".into(), pick("#eeeeee", mix(text, card, 0.93))),
        ("tint".into(), pick("#fafafd", mix(card, text, 0.03))),
        ("tint-2".into(), pick("#f0f0f5", mix(card, text, 0.07))),
        (
            "bad".into(),
            pick("#b00020", readable(&["#b00020", "#ff8a80"], card)),
        ),
        (
            "good".into(),
            pick("#0b6b4f", readable(&["#0b6b4f", "#69f0ae"], card)),
        ),
    ]
}

/// What is wrong with a set of colours under AA, each a sentence.
#[tracing::instrument(level = "debug")]
pub fn contrast_problems(accent: &str, card: &str, text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (colour, key, what) in [
        (text, "branding.textColor", "the text"),
        (accent, "branding.accentColor", "the links and the accent"),
    ] {
        let ratio = contrast(colour, card);
        if ratio < AA_CONTRAST {
            out.push(format!(
                "{} ({} {}) has a contrast of {:.2}:1 against the card \
                 (branding.cardColor {}); WCAG 2.2 AA asks at least {}:1",
                what, key, colour, ratio, card, AA_CONTRAST
            ));
        }
    }
    out
}

/// Whether a text is an absolute https URL.
fn https_url(text: &str) -> bool {
    url::Url::parse(text.trim()).is_ok_and(|u| {
        u.scheme() == "https" && u.host_str().is_some_and(|h| !h.is_empty())
    })
}

/// The ambient realm's appearance (`Theme`).
#[derive(Clone, Debug)]
pub struct Theme {
    pub active: bool,
    pub layout: String,
    pub display_name: String,
    /// The logo's address, its alternative text and its link.
    pub logo: Option<(String, String, String)>,
    pub css: String,
    pub digest: String,
}

/// The appearance module, over the settings and the logo store.
pub struct Branding {
    settings: Option<Arc<Settings>>,
    logos: RwLock<Option<Arc<dyn LogoStore>>>,
}

impl Branding {
    /// Over the settings; no logo store until one is filled.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(settings: Option<Arc<Settings>>) -> Arc<Branding> {
        Arc::new(Branding {
            settings,
            logos: RwLock::new(None),
        })
    }

    /// Fills the logo store's slot.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn set_logo_store(&self, store: Arc<dyn LogoStore>) {
        if let Ok(mut slot) = self.logos.write() {
            *slot = Some(store);
        }
    }

    fn setting(&self, key: &str, fallback: &str) -> String {
        let value = self
            .settings
            .as_ref()
            .map(|s| s.value_of(key).as_str().to_string())
            .unwrap_or_default();
        if value.is_empty() {
            fallback.to_string()
        } else {
            value
        }
    }

    fn logo(&self) -> Option<Logo> {
        self.logos
            .read()
            .ok()
            .and_then(|s| s.as_ref().and_then(|l| l.logo()))
            .filter(|l| !l.bytes.is_empty())
    }

    /// `theme()`: the ambient realm's appearance.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn theme(&self) -> Theme {
        let set: Vec<String> = COLOURS
            .iter()
            .map(|(_, key, dflt)| self.setting(key, dflt))
            .collect();
        let layout = self.setting("branding.layout", "centered");
        let layout = if LAYOUTS.contains(&layout.as_str()) {
            layout
        } else {
            "centered".to_string()
        };
        let display_name =
            self.setting("branding.displayName", "").trim().to_string();
        let logo = self.logo().map(|record| {
            let alt = self.setting("branding.logoAlt", "").trim().to_string();
            let link =
                self.setting("branding.logoLinkUrl", "").trim().to_string();
            (
                format!(
                    "{}?v={}",
                    LOGO_PATH,
                    &record.sha256[..16.min(record.sha256.len())]
                ),
                alt,
                if https_url(&link) {
                    link
                } else {
                    String::new()
                },
            )
        });
        let colours = palette(&set[0], &set[1], &set[2], &set[3]);
        let css = format!(
            ":root{{{}}}",
            colours
                .iter()
                .filter(|(k, v)| DEFAULT_PROPERTIES
                    .iter()
                    .find(|(n, _)| n == k)
                    .is_none_or(|(_, d)| d != v))
                .map(|(k, v)| format!("--sts-{}:{}", k, v))
                .collect::<Vec<_>>()
                .join(";")
        );
        let changed = COLOURS
            .iter()
            .zip(set.iter())
            .any(|((_, _, dflt), v)| v != dflt);
        let active = layout != "centered"
            || !display_name.is_empty()
            || logo.is_some()
            || changed;
        let digest: String = sts_crypto::jws_alg::Hash::Sha256
            .digest(css.as_bytes())
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        Theme {
            active,
            layout,
            display_name,
            logo,
            css,
            digest: digest[..16].to_string(),
        }
    }

    /// `shellParts()`: the `<html>` attributes and the stylesheet a shell
    /// carries, or nothing for a realm that set nothing.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn shell_parts(&self) -> (Vec<(String, String)>, String) {
        let theme = self.theme();
        if !theme.active {
            return (Vec::new(), String::new());
        }
        let (url, alt, link) = theme.logo.clone().unwrap_or_default();
        (
            vec![
                ("data-sts-layout".into(), theme.layout.clone()),
                ("data-sts-brand-name".into(), theme.display_name.clone()),
                ("data-sts-brand-logo".into(), url),
                ("data-sts-brand-alt".into(), alt),
                ("data-sts-brand-link".into(), link),
            ],
            format!("{}?v={}", THEME_PATH, theme.digest),
        )
    }

    /// `GET /web/theme.css`, without a preview.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn theme_css(&self, request: &HeaderMap, query: &str) -> Response {
        let theme = self.theme();
        let asked = crate::assets::query_value(query, "v");
        let for_good = asked.as_deref() == Some(theme.digest.as_str());
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/css; charset=utf-8"),
        );
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(if for_good {
                "public, max-age=31536000, immutable"
            } else {
                "no-cache"
            }),
        );
        crate::files::send_compressed(
            request,
            headers,
            theme.css.into(),
            true,
            None,
            None,
        )
    }

    /// `GET /web/branding/logo`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn logo_response(&self, request: &HeaderMap, query: &str) -> Response {
        let Some(record) = self.logo() else {
            let mut r = crate::text("This realm has no sign-in logo.");
            *r.status_mut() = StatusCode::NOT_FOUND;
            r.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("no-store"),
            );
            return crate::mark(r, codes::STS_AUTHN_0549);
        };
        let etag =
            format!("\"{}\"", &record.sha256[..32.min(record.sha256.len())]);
        let asked = crate::assets::query_value(query, "v").unwrap_or_default();
        let mut headers = HeaderMap::new();
        if let Ok(v) = HeaderValue::from_str(&etag) {
            headers.insert(header::ETAG, v);
        }
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        let policy = crate::csp::content_security_policy(&[
            ("style-src", None),
            ("img-src", None),
            ("sandbox", Some("")),
        ]);
        if let Ok(v) = HeaderValue::from_str(&policy) {
            headers.insert(header::CONTENT_SECURITY_POLICY, v);
        }
        let for_good = !asked.is_empty()
            && record.sha256.starts_with(&asked)
            && asked.len() == 16;
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(if for_good {
                "public, max-age=31536000, immutable"
            } else {
                "no-cache"
            }),
        );
        let matched = request
            .get(header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == etag);
        if matched {
            let mut r = Response::new(axum::body::Body::empty());
            *r.status_mut() = StatusCode::NOT_MODIFIED;
            *r.headers_mut() = headers;
            return r;
        }
        if let Ok(v) = HeaderValue::from_str(&record.content_type) {
            headers.insert(header::CONTENT_TYPE, v);
        }
        headers.insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("inline; filename=\"logo\""),
        );
        crate::express::send(StatusCode::OK, headers, record.bytes, false)
    }
}

/// The write rule: a colour below AA against the card, a logo link that is
/// not https.
pub struct ContrastRule {
    settings: Arc<Settings>,
}

impl ContrastRule {
    /// The rule, reading the companion colours from `settings`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(settings: Arc<Settings>) -> Arc<ContrastRule> {
        Arc::new(ContrastRule { settings })
    }
}

impl WriteRule for ContrastRule {
    fn problem(
        &self,
        key: &str,
        parsed: &SettingValue,
        _in_realm: bool,
    ) -> Option<(String, ErrorCode)> {
        if matches!(
            key,
            "branding.textColor"
                | "branding.accentColor"
                | "branding.cardColor"
        ) {
            let read = |k: &str| {
                if k == key {
                    parsed.as_str().to_string()
                } else {
                    self.settings.value_of(k).as_str().to_string()
                }
            };
            let problems = contrast_problems(
                &read("branding.accentColor"),
                &read("branding.cardColor"),
                &read("branding.textColor"),
            );
            if problems.is_empty() {
                return None;
            }
            return Some((
                format!(
                    "The sign-in appearance was not changed: {}.",
                    problems.join("; ")
                ),
                codes::STS_AUTHN_0544,
            ));
        }
        if key == "branding.logoLinkUrl"
            && !parsed.as_str().trim().is_empty()
            && !https_url(parsed.as_str())
        {
            return Some((
                "\"branding.logoLinkUrl\" must be an absolute https URL, or \
                 empty for a logo that is not a link."
                    .to_string(),
                codes::STS_AUTHN_0551,
            ));
        }
        None
    }
}

/// For a JSON caller: the palette as an object.
#[tracing::instrument(level = "debug", skip_all)]
pub fn palette_json(colours: &[(String, String)]) -> Json {
    Json::Object(
        colours
            .iter()
            .map(|(k, v)| (k.clone(), Json::String(v.clone())))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_the_old_literals() {
        let p = palette("#12107c", "#f4f4f7", "#ffffff", "#222222");
        for ((k, v), (dk, dv)) in p.iter().zip(DEFAULT_PROPERTIES) {
            assert_eq!((k.as_str(), v.as_str()), (*dk, *dv));
        }
    }

    #[test]
    fn contrast_is_wcag_s() {
        assert!((contrast("#000000", "#ffffff") - 21.0).abs() < 1e-9);
        assert!((contrast("#777777", "#ffffff") - 4.478).abs() < 0.01);
        assert_eq!(contrast_problems("#12107c", "#ffffff", "#222222").len(), 0);
        assert_eq!(contrast_problems("#cccccc", "#ffffff", "#dddddd").len(), 2);
    }
}
