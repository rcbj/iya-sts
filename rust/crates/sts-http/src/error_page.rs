// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! ONE ERROR PAGE FOR EVERY SERVER-DRAWN BROWSER FLOW THAT ENDS IN AN ERROR
//! (#1326, rcbj's decision, 2026-11-05) — a port of `common/error_page.ts`,
//! with the language chooser it draws (`PageLocale.chooser()`, which is
//! `WebLocale.chooserHtml()` in its collapsed row, #1289).
//!
//! The order is rcbj's design and Node's: the error first, in the yellow
//! box (the protocol's error value as sent, and a sentence in the page's
//! language); what the person can do; the background, collapsed in a
//! `<details>` (these pages run no script); a note to close the tab with a
//! link to the realm's user portal; the diagnostics — the time, the
//! INCIDENT ID, and whatever the caller knows — and the page footer.
//!
//! It draws markup; it decides nothing. A caller translates its message,
//! background and diagnostics and passes them in, as Node's callers do.
//!
//! WHAT REPLACED WHAT: Node reserves the incident ID from the audit ring
//! (`audit.reserveIncident(res)`) inside `send()`; here the caller hands
//! the number in — `call_log::reserve_incident()`, which the request's
//! call-log row then carries — and a caller with no audit ring passes 0,
//! when the page says "none recorded", as Node's does for 0.

use crate::express::escape_html as esc;
use crate::i18n::{Catalogs, Translator};

/// The page's own rules (`CSS`).
pub const CSS: &str = concat!(
    "body{font-family:system-ui,-apple-system,\"Segoe UI\",Roboto,sans-serif;",
    "margin:2rem auto;max-width:46rem;padding:0 1rem;line-height:1.5;",
    "color:#222;background:#fff}",
    "h1{font-size:1.5rem;margin:.4rem 0 1rem}",
    "code{font-family:ui-monospace,Menlo,monospace;font-size:.85rem;",
    "background:#f4f4f8;padding:.1rem .25rem;border-radius:3px;",
    "word-break:break-all}",
    ".warn{background:#fff8e1;border:1px solid #ffe082;padding:.7rem .9rem;",
    "border-radius:4px;margin:1rem 0}",
    ".warn .error{display:block;font-weight:600;margin-bottom:.2rem}",
    "details.prose{margin:1rem 0;color:#444}",
    "details.prose>summary{cursor:pointer;color:#1f4fa3}",
    "details.prose>summary:hover{color:#2c5cc5}",
    "details.prose>div{margin:.5rem 0 0 1rem;font-size:.92rem}",
);

/// The ending every error page shares (`FOOTER_CSS`), for a page that
/// borrows only [`footer`].
pub const FOOTER_CSS: &str = concat!(
    ".next{margin:1.2rem 0}",
    ".next a.portal{display:inline-block;margin-top:.5rem;padding:.35rem .8rem;",
    "border:1px solid #1f4fa3;border-radius:4px;color:#1f4fa3;",
    "text-decoration:none}",
    ".next a.portal:hover{background:#eef3fc}",
    "button.as-link{background:none;border:0;padding:0;font:inherit;",
    "color:#00e;color:LinkText;text-decoration:underline;cursor:pointer}",
    "section.diagnostics{margin:2rem 0 1rem;padding:.6rem .9rem;",
    "border:1px solid #ddd;border-radius:4px;background:#fafafa;",
    "font-size:.82rem;color:#555}",
    "section.diagnostics h2{font-size:.85rem;margin:0 0 .4rem;",
    "text-transform:uppercase;letter-spacing:.04em;color:#666}",
    "section.diagnostics dl{display:grid;grid-template-columns:max-content 1fr;",
    "gap:.15rem .9rem;margin:0}",
    "section.diagnostics dt{color:#666}section.diagnostics dd{margin:0;",
    "min-width:0}section.diagnostics dd code{font-size:.8rem}",
);

/// The collapsed language row's rules (`WebLocale.ROW_CSS`).
pub const ROW_CSS: &str = concat!(
    "details.language-row{font-size:.85em;position:relative}",
    "details.language-row>summary{cursor:pointer;list-style:none;",
    "padding:2px 6px;border-radius:6px;white-space:nowrap}",
    "details.language-row>summary::-webkit-details-marker{display:none}",
    "details.language-row>summary::before{content:\"\\25B8\\00A0\"}",
    "details.language-row[open]>summary::before{content:\"\\25BE\\00A0\"}",
    "details.language-row .lr-label{opacity:.7}",
    "details.language-row .lr-current{font-weight:600}",
    "details.language-row form.language-chooser{float:none;display:flex;",
    "align-items:center;gap:6px;margin:0;position:absolute;right:0;",
    "top:100%;z-index:30;white-space:nowrap;background:#fff;color:#222;",
    "border:1px solid #c9cad6;border-radius:8px;padding:8px 10px;",
    "box-shadow:0 4px 14px rgba(0,0,0,.14)}",
);

/// One row of the diagnostics box: a translated label and a value shown
/// as data. An empty value leaves the row out.
#[derive(Clone, Debug, Default)]
pub struct DiagnosticRow {
    pub label: String,
    pub value: String,
}

/// What to draw (`ErrorPageSpec`).
#[derive(Clone, Debug, Default)]
pub struct ErrorPageSpec {
    /// The language chooser ([`chooser`]), or '' for none.
    pub chooser: String,
    pub status: u16,
    /// The heading, translated (plain text).
    pub title: String,
    /// The protocol's error value, shown in bold, or ''.
    pub error: String,
    /// The sentence in the box, translated HTML.
    pub message: String,
    /// HTML right below the box: an action, or a sentence that must stay
    /// visible.
    pub after: String,
    /// The background, translated HTML, drawn collapsed; '' for none.
    pub background: String,
    /// The caller's diagnostics, below the time and the incident ID.
    pub diagnostics: Vec<DiagnosticRow>,
    /// Anything for the head (a refresh).
    pub extra_head: String,
}

/// `WebMessages.stripTags()`: every `<…>` removed until none is left.
fn strip_tags(text: &str) -> String {
    let mut out = text.to_string();
    loop {
        let mut next = String::with_capacity(out.len());
        let mut rest = out.as_str();
        let mut changed = false;
        while let Some(open) = rest.find('<') {
            let after = &rest[open + 1..];
            match after.find(['<', '>']) {
                Some(c) if after.as_bytes()[c] == b'>' => {
                    next.push_str(&rest[..open]);
                    rest = &after[c + 1..];
                    changed = true;
                }
                _ => {
                    next.push_str(&rest[..open + 1]);
                    rest = after;
                }
            }
        }
        next.push_str(rest);
        if !changed {
            return next;
        }
        out = next;
    }
}

/// `t.html(key, params)`: the message's own markup kept, every parameter
/// escaped; the key, escaped, where no catalog has it.
#[tracing::instrument(level = "trace", skip_all)]
pub fn html(t: &Translator<'_>, key: &str, params: &[(&str, &str)]) -> String {
    if !t.has(key) {
        return esc(key);
    }
    let escaped: Vec<(String, String)> = params
        .iter()
        .map(|(n, v)| (n.to_string(), esc(v)))
        .collect();
    let refs: Vec<(&str, &str)> = escaped
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    t.text(key, &refs)
}

/// `t.text(key, params)`: the catalog's markup stripped and never a
/// value's; nothing escaped (the caller escapes).
#[tracing::instrument(level = "trace", skip_all)]
pub fn text(t: &Translator<'_>, key: &str, params: &[(&str, &str)]) -> String {
    if !t.has(key) {
        return key.to_string();
    }
    // The values are held out as placeholders while the tags are removed,
    // then put back, as `format()` does.
    let slots: Vec<(String, String)> = params
        .iter()
        .enumerate()
        .map(|(i, (n, _))| (n.to_string(), format!("\u{E000}{}\u{E001}", i)))
        .collect();
    let refs: Vec<(&str, &str)> = slots
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    let mut out = strip_tags(&t.text(key, &refs));
    for (i, (_, v)) in params.iter().enumerate() {
        out = out.replace(&format!("\u{E000}{}\u{E001}", i), v);
    }
    out
}

/// `ErrorPage.sentence(t, candidates, params)`: the first key the
/// catalogs hold, drawn as HTML; '' where none is held.
#[tracing::instrument(level = "trace", skip_all)]
pub fn sentence(
    t: &Translator<'_>,
    candidates: &[String],
    params: &[(&str, &str)],
) -> String {
    candidates
        .iter()
        .find(|k| !k.is_empty() && t.has(k))
        .map(|k| html(t, k, params))
        .unwrap_or_default()
}

/// `ErrorPage.returnPath(req)`: the request itself where asking again is
/// harmless (a GET), the realm's front door otherwise.
#[tracing::instrument(level = "trace")]
pub fn return_path(method: &str, original_url: &str, prefix: &str) -> String {
    let ok = method.eq_ignore_ascii_case("GET")
        && original_url.starts_with('/')
        && !original_url[1..].starts_with('/');
    if ok {
        original_url.to_string()
    } else {
        format!("{}/", prefix)
    }
}

/// `WebLocale.safeReturn(value)`: a local path, or `/`.
fn safe_return(value: &str) -> String {
    let n = value.encode_utf16().count();
    let ok = n > 0
        && n <= 2048
        && value.starts_with('/')
        && !value[1..].starts_with('/')
        && !value
            .chars()
            .any(|c| c == '\\' || (c as u32) < 0x20 || c == '\u{7f}')
        && !{
            let head: String = value[1..]
                .chars()
                .take_while(|c| !matches!(c, '/' | '?' | '#'))
                .collect();
            head.contains(':')
        };
    if ok {
        value.to_string()
    } else {
        "/".to_string()
    }
}

/// `PageLocale.chooser(t, base, returnTo)` (`WebLocale.chooserHtml()` in
/// its collapsed row, #1289): a form posting to `/authn/language`, the
/// offered locales by their own names, the current one selected.
#[tracing::instrument(level = "trace", skip_all)]
pub fn chooser(
    t: &Translator<'_>,
    catalogs: &Catalogs,
    return_to: &str,
) -> String {
    let here = safe_return(return_to);
    let current = t.negotiated.locale.to_lowercase();
    let offered = catalogs.offered();
    let field = |o: &serde_json::Value, name: &str| -> String {
        o.get(name)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let exact = offered
        .iter()
        .find(|o| field(o, "tag").to_lowercase() == current);
    let same = offered.iter().find(|o| {
        catalogs.negotiate(&[field(o, "tag")], "").catalog
            == t.negotiated.catalog
    });
    let selected = exact
        .or(same)
        .or(offered.first())
        .map(|o| field(o, "tag"))
        .unwrap_or_default();
    let drawn: String = offered
        .iter()
        .map(|o| {
            let tag = field(o, "tag");
            format!(
                "<option value=\"{}\" lang=\"{}\"{}>{}</option>",
                esc(&tag),
                esc(&tag),
                if tag == selected { " selected" } else { "" },
                esc(&field(o, "name"))
            )
        })
        .collect();
    let chosen = offered.iter().find(|o| field(o, "tag") == selected);
    let label = t.text("chooser.label", &[]);
    let form = format!(
        "<form class=\"language-chooser\" method=\"post\" \
         action=\"/authn/language\"><input type=\"hidden\" name=\"return\" \
         value=\"{}\"><label for=\"sts-language\">{}</label> <select \
         id=\"sts-language\" name=\"lang\">{}</select> <button \
         type=\"submit\">{}</button></form>",
        esc(&here),
        label,
        drawn,
        t.text("chooser.change", &[])
    );
    format!(
        "<details class=\"language-row\"><summary><span \
         class=\"lr-label\">{}</span>{}</summary>{}</details>",
        label,
        match chosen {
            Some(c) => format!(
                " <span class=\"lr-current\" lang=\"{}\">{}</span>",
                esc(&field(c, "tag")),
                esc(&field(c, "name"))
            ),
            None => String::new(),
        },
        form
    )
}

/// `PageLocale.htmlAttributes(t)`: ` lang="…" dir="…"`.
#[tracing::instrument(level = "trace", skip_all)]
pub fn html_attributes(t: &Translator<'_>) -> String {
    format!(
        " lang=\"{}\" dir=\"{}\"",
        esc(&t.negotiated.locale),
        if t.negotiated.rtl { "rtl" } else { "ltr" }
    )
}

/// `new Date().toISOString()`.
#[tracing::instrument(level = "trace")]
pub fn iso_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// `ErrorPage.footer(t, diagnostics, incident, now)`: the start-over note,
/// the link to the realm's portal, and the diagnostics with the time and
/// the incident ID first.
#[tracing::instrument(level = "trace", skip_all)]
pub fn footer(
    t: &Translator<'_>,
    diagnostics: &[DiagnosticRow],
    incident: i64,
    now: &str,
    _prefix: &str,
) -> String {
    let mut rows = vec![
        DiagnosticRow {
            label: text(t, "errorPages.time", &[]),
            value: now.to_string(),
        },
        DiagnosticRow {
            label: text(t, "errorPages.incident", &[]),
            value: if incident != 0 {
                incident.to_string()
            } else {
                text(t, "errorPages.noIncident", &[])
            },
        },
    ];
    rows.extend(diagnostics.iter().cloned());
    // ROOT-RELATIVE, LIKE EVERY LINK A SERVER-DRAWN PAGE CARRIES: the
    // realm's prefix is put on it as the page is sent (`put_prefix_back`,
    // `withRealmLinks()`). Drawn with the prefix it was
    // `/realm/<id>/realm/<id>/portal`, a 404 (Node's fix of 2026-11-14,
    // #444 D12); `_prefix` stays in the signature for the callers.
    let portal = "/portal";
    let drawn: String = rows
        .iter()
        .filter(|r| !r.value.is_empty())
        .map(|r| {
            format!(
                "<dt>{}</dt><dd><code>{}</code></dd>",
                esc(&r.label),
                esc(&r.value)
            )
        })
        .collect();
    format!(
        "<div class=\"next\"><p>{}</p><a class=\"portal\" href=\"{}\">{}</a>\
         </div><section class=\"diagnostics\" \
         aria-labelledby=\"diagnostics-heading\"><h2 \
         id=\"diagnostics-heading\">{}</h2><dl>{}</dl></section>",
        html(t, "errorPages.startOver", &[]),
        esc(portal),
        html(t, "errorPages.portal", &[]),
        html(t, "errorPages.diagnostics", &[]),
        drawn
    )
}

/// `ErrorPage.document(spec, incident, now)`: the whole document.
#[tracing::instrument(level = "debug", skip_all)]
pub fn document(
    t: &Translator<'_>,
    spec: &ErrorPageSpec,
    incident: i64,
    now: &str,
    prefix: &str,
    facts: &crate::footer::Facts,
) -> String {
    let background = if spec.background.is_empty() {
        String::new()
    } else {
        format!(
            "<details class=\"prose\"><summary>{}</summary><div>{}</div>\
             </details>",
            html(t, "errorPages.background", &[]),
            spec.background
        )
    };
    let error = if spec.error.is_empty() {
        String::new()
    } else {
        format!("<span class=\"error\">{}</span>", esc(&spec.error))
    };
    format!(
        "<!doctype html><html{}><head><meta charset=\"utf-8\"><meta \
         name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         {}<title>{}</title><style>{}{}.sub{{color:#666;font-size:.92rem}}\
         details.language-row{{float:right;margin:0 0 .5rem 1rem}}{}{}\
         </style></head><body>{}<h1>{}</h1><div class=\"warn\" \
         role=\"alert\">{}{}</div>{}{}{}{}</body></html>",
        html_attributes(t),
        spec.extra_head,
        esc(&spec.title),
        CSS,
        FOOTER_CSS,
        ROW_CSS,
        crate::footer::CSS,
        spec.chooser,
        esc(&spec.title),
        error,
        spec.message,
        spec.after,
        background,
        footer(t, &spec.diagnostics, incident, now, prefix),
        crate::footer::html(Some(t), facts)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_get_comes_back_to_itself_and_anything_else_to_the_front_door() {
        assert_eq!(
            return_path("GET", "/oauth2/authorize?a=b", ""),
            "/oauth2/authorize?a=b"
        );
        assert_eq!(
            return_path("POST", "/oauth2/authorize", "/realm/x"),
            "/realm/x/"
        );
        assert_eq!(return_path("GET", "//evil", ""), "/");
    }

    #[test]
    fn tags_are_stripped_until_none_is_left() {
        assert_eq!(strip_tags("a <strong>b</strong> c"), "a b c");
        assert_eq!(strip_tags("<<b>b>x"), "x");
        assert_eq!(strip_tags("a < b"), "a < b");
    }
}
