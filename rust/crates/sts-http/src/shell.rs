// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The one document a static surface answers, and how it is sent — a port
//! of `common/shell_document.ts` (#570) and of `PageLocale`'s
//! `shellAttributes()`.
//!
//! A shell is a doctype, an `<html>` whose `data-sts-*` attributes tell the
//! runtime where things are (each drawn only where it has a value), the
//! surface's stylesheets and its `defer` script (root-relative, so the
//! realm's rewrite puts them under the realm), a `<noscript>` notice and
//! nothing else — or a refusal and no script where the surface knows it
//! cannot work here — and the page footer. `data-sts-accounts="on"` where
//! `authn.multipleAccounts` is on in the ambient realm (#561), and the
//! realm's sign-in appearance where it applies (#717): every shell comes
//! through [`document`], so none can forget either.
//!
//! It is sent `no-store`, with its Content-Security-Policy ONLY through
//! [`crate::csp::content_security_policy`] — `script-src 'self'`,
//! `connect-src 'self'` and the other listeners' origins, `style-src
//! 'self'`, the logo origins a sign-in page names (#1300), what a surface
//! adds — so `frame-ancestors` and `base-uri` cannot be dropped. The
//! console, the portal and the reports application are `isolated`
//! (Qualys QIDs 531930, 531928).

use std::sync::Arc;

use axum::body::Bytes;
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::Response;
use sts_core::settings::Settings;
use sts_core::version::VersionInfo;

use crate::branding::Branding;
use crate::express::escape_html;
use crate::i18n::{self, Catalogs};

/// The card's stylesheet, whose shells take the realm's appearance.
pub const CARD_PATH: &str = "/web/card.css";

/// The footer's stylesheet.
pub const FOOTER_PATH: &str = "/web/footer.css";

const VIEWPORT: &str = "width=device-width, initial-scale=1";

/// The chooser's cookie (`PageLocale.COOKIE`).
pub const LANG_COOKIE: &str = "sts_lang";

/// The locale policy's default for an application and a person
/// (`localePolicy.defaultLocaleFor()`): a policy kind a later phase ports.
pub trait LocaleDefaults: Send + Sync {
    fn default_locale_for(&self, application: &str, person: &str) -> String;
}

/// No policy: English, the last resort Node falls back to.
pub struct EnglishDefault;

impl LocaleDefaults for EnglishDefault {
    fn default_locale_for(&self, _: &str, _: &str) -> String {
        "en".to_string()
    }
}

/// What every shell is drawn with.
pub struct Surfaces {
    pub settings: Option<Arc<Settings>>,
    pub catalogs: Arc<Catalogs>,
    pub version: VersionInfo,
    pub branding: Arc<Branding>,
    pub locales: Arc<dyn LocaleDefaults>,
}

/// What a shell is drawn from (`ShellSpec`).
#[derive(Clone, Debug, Default)]
pub struct ShellSpec {
    pub title: String,
    pub lang: Option<String>,
    pub dir: Option<String>,
    pub attributes: Vec<(String, String)>,
    pub viewport: Option<String>,
    pub stylesheets: Vec<String>,
    pub script: String,
    pub open: String,
    pub close: String,
    pub noscript: String,
    pub loading: String,
    pub refusal: Option<String>,
    /// `None`: applies to a shell that links the card.
    pub branded: Option<bool>,
    /// The console escapes an apostrophe `&apos;`.
    pub apos: bool,
    /// `false` only for a specification's own response (RFC 4559's).
    pub footer: bool,
}

/// How a shell is sent (`ServeOptions`).
#[derive(Clone, Debug, Default)]
pub struct ServeOptions {
    pub connect: Vec<String>,
    pub csp: Vec<(String, Option<String>)>,
    pub images: Vec<String>,
    pub compress: bool,
    pub prefix: String,
    pub isolated: bool,
}

/// The console's escaping: `&apos;` for an apostrophe.
fn esc_apos(value: &str) -> String {
    escape_html(value).replace("&#39;", "&apos;")
}

/// A request's cookie by name (`PageLocale.cookieOf()`), decoded.
#[tracing::instrument(level = "trace", skip_all)]
pub fn cookie_of(request: &HeaderMap, name: &str) -> String {
    let header = request
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let mut out = String::new();
    for part in header.split(';') {
        if let Some(at) = part.find('=') {
            if at > 0 && part[..at].trim() == name {
                out = crate::cors::percent_decode_strict(part[at + 1..].trim())
                    .unwrap_or_default();
            }
        }
    }
    out
}

impl Surfaces {
    /// `ShellDocument.accountsOn()`.
    fn accounts_on(&self) -> bool {
        self.settings
            .as_ref()
            .is_some_and(|s| s.value_of("authn.multipleAccounts").as_bool())
    }

    /// The translator a page is drawn with (`PageLocale.translatorFor()`):
    /// the chooser's cookie, `Accept-Language`, the policy's default.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn translator(
        &self,
        request: &HeaderMap,
        application: &str,
        person: &str,
    ) -> i18n::Translator<'_> {
        let prefs = i18n::preferences(&i18n::Preferences {
            chooser: cookie_of(request, LANG_COOKIE),
            accept_language: request
                .get(header::ACCEPT_LANGUAGE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string(),
            ..i18n::Preferences::default()
        });
        let last = self.locales.default_locale_for(application, person);
        self.catalogs.translator(&prefs, &last)
    }

    /// `PageLocale.shellAttributes()`: the version, the chooser's choice,
    /// the policy's default and the build, for the runtime to choose the
    /// page's language in the browser.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn locale_attributes(
        &self,
        request: &HeaderMap,
        application: &str,
        person: &str,
    ) -> Vec<(String, String)> {
        let last = self.locales.default_locale_for(application, person);
        let default = i18n::canonical(&last);
        vec![
            ("data-sts-version".into(), self.version.version.clone()),
            (
                "data-sts-lang".into(),
                i18n::canonical(&cookie_of(request, LANG_COOKIE)),
            ),
            (
                "data-sts-locale-default".into(),
                if default.is_empty() {
                    "en".into()
                } else {
                    default
                },
            ),
            (
                "data-sts-build".into(),
                crate::footer::build_id(&self.version),
            ),
        ]
    }

    /// `ShellDocument.document()`.
    #[tracing::instrument(level = "debug", skip_all, fields(title = %spec.title))]
    pub fn document(&self, request: &HeaderMap, spec: &ShellSpec) -> String {
        let esc = |v: &str| {
            if spec.apos {
                esc_apos(v)
            } else {
                escape_html(v)
            }
        };
        let refused = spec.refusal.is_some();
        let applies = spec.branded.unwrap_or_else(|| {
            spec.stylesheets
                .iter()
                .any(|h| h.split('?').next() == Some(CARD_PATH))
        });
        let brand = if applies {
            self.branding.shell_parts()
        } else {
            (Vec::new(), String::new())
        };
        let mut stylesheets = spec.stylesheets.clone();
        if !brand.1.is_empty() {
            let at = stylesheets
                .iter()
                .position(|h| h.split('?').next() == Some(CARD_PATH));
            let at = at.map_or(stylesheets.len(), |a| a + 1);
            stylesheets.insert(at, brand.1.clone());
        }
        let footer = if spec.footer {
            let t = self.translator(request, "", "");
            crate::footer::html(Some(&t), &crate::footer::facts(&self.version))
        } else {
            String::new()
        };
        if !footer.is_empty() {
            stylesheets.push(FOOTER_PATH.to_string());
        }
        let mut attributes = spec.attributes.clone();
        attributes.push((
            "data-sts-accounts".into(),
            if self.accounts_on() {
                "on".into()
            } else {
                String::new()
            },
        ));
        attributes.extend(brand.0);
        let attributes: String = attributes
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| format!(" {}=\"{}\"", k, esc(v)))
            .collect();
        let links: String = stylesheets
            .iter()
            .map(|h| format!("<link rel=\"stylesheet\" href=\"{}\">", esc(h)))
            .collect();
        let mut html = String::with_capacity(4096);
        html.push_str("<!DOCTYPE html>\n<html lang=\"");
        html.push_str(&esc(spec.lang.as_deref().unwrap_or("en")));
        html.push('"');
        if let Some(dir) = spec.dir.as_deref().filter(|d| !d.is_empty()) {
            html.push_str(&format!(" dir=\"{}\"", esc(dir)));
        }
        html.push_str(&attributes);
        html.push_str(
            "><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"",
        );
        html.push_str(&esc(spec.viewport.as_deref().unwrap_or(VIEWPORT)));
        html.push_str("\"><title>");
        html.push_str(&esc(&spec.title));
        html.push_str("</title>");
        html.push_str(&links);
        if !refused {
            html.push_str(&format!(
                "<script src=\"{}\" defer></script>",
                esc(&spec.script)
            ));
        }
        html.push_str("</head><body>");
        html.push_str(&spec.open);
        match &spec.refusal {
            Some(refusal) => html.push_str(refusal),
            None => {
                html.push_str("<noscript>");
                html.push_str(&spec.noscript);
                html.push_str("</noscript>");
                html.push_str(&spec.loading);
            }
        }
        html.push_str(&spec.close);
        html.push_str(&footer);
        html.push_str("</body></html>\n");
        html
    }
}

/// `ShellDocument.originsOf()`: the distinct origins of some bases.
#[tracing::instrument(level = "debug")]
pub fn origins_of(bases: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for base in bases.iter().filter(|b| !b.is_empty()) {
        if let Ok(u) = url::Url::parse(base) {
            let origin = u.origin().ascii_serialization();
            if !out.contains(&origin) {
                out.push(origin);
            }
        }
    }
    out
}

/// `ShellDocument.imageSources()`: `img-src` naming each https origin
/// given exactly, or nothing to add.
fn image_sources(origins: &[String]) -> Option<String> {
    let mut named: Vec<&str> = Vec::new();
    for one in origins {
        let exact = url::Url::parse(one).is_ok_and(|u| {
            u.scheme() == "https" && u.origin().ascii_serialization() == *one
        });
        if exact && !named.contains(&one.as_str()) {
            named.push(one);
        }
    }
    if named.is_empty() {
        return None;
    }
    Some(format!("'self' data: {}", named.join(" ")))
}

/// `ShellDocument.policy()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn policy(options: &ServeOptions) -> String {
    let mut connect = vec!["'self'".to_string()];
    connect.extend(options.connect.iter().cloned());
    let mut directives: Vec<(String, Option<String>)> = vec![
        ("script-src".into(), Some("'self'".into())),
        ("connect-src".into(), Some(connect.join(" "))),
        ("style-src".into(), Some("'self'".into())),
    ];
    if let Some(img) = image_sources(&options.images) {
        directives.push(("img-src".into(), Some(img)));
    }
    for (k, v) in &options.csp {
        match directives.iter_mut().find(|(n, _)| n == k) {
            Some(slot) => slot.1 = v.clone(),
            None => directives.push((k.clone(), v.clone())),
        }
    }
    let refs: Vec<(&str, Option<&str>)> = directives
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_deref()))
        .collect();
    crate::csp::content_security_policy(&refs)
}

/// `ShellDocument.serve()`: the policy, `no-store`, the document —
/// compressed, with the realm's links put on first, where the surface
/// asks.
#[tracing::instrument(level = "debug", skip_all)]
pub fn serve(
    request: &HeaderMap,
    html: String,
    options: &ServeOptions,
) -> Response {
    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&policy(options)) {
        headers.insert(header::CONTENT_SECURITY_POLICY, v);
    }
    if options.isolated {
        headers.insert(
            "cross-origin-opener-policy",
            HeaderValue::from_static("same-origin-allow-popups"),
        );
        headers.insert(
            "cross-origin-resource-policy",
            HeaderValue::from_static("same-origin"),
        );
    }
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if !options.compress {
        return crate::express::send(
            axum::http::StatusCode::OK,
            headers,
            html,
            true,
        );
    }
    let prefix = options.prefix.clone();
    let finish = move |text: &str| crate::with_realm_links(text, &prefix);
    crate::files::send_compressed(
        request,
        headers,
        Bytes::from(html),
        true,
        None,
        Some(&finish),
    )
}
