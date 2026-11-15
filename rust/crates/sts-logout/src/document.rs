// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE MARKUP THE SIGN-OUT DRAWS ON THE SERVER: the console's fold rule
//! (`admin-ui/web_kit.ts`'s `note()`, which the fan-out's two notes and the
//! signed-out document's go through) and its tabs (`tabbedPanels()`).
//!
//! One fold rule for the console and this page, as Node has it: a note
//! that reads as one line (110 visible characters) is a paragraph; a longer
//! one is a `<details>` whose summary is its bolded headline, its opening
//! sentence, or a word-boundary teaser ending in an ellipsis.

const ONE_LINE_CHARS: usize = 110;
const SUMMARY_CHARS: usize = 96;

/// `WebMessages.stripTags()`: `<…>` removed until nothing changes.
fn strip_tags(html: &str) -> String {
    let mut out = html.to_string();
    loop {
        let mut next = String::with_capacity(out.len());
        let mut rest = out.as_str();
        let mut changed = false;
        while let Some(open) = rest.find('<') {
            let after = &rest[open + 1..];
            let close = after.find(['<', '>']);
            match close {
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

/// `plainTextOf()`: the tags off, whitespace runs one space, trimmed.
fn plain_text_of(html: &str) -> String {
    strip_tags(html)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// `visibleLength()`: an entity counts as one character (UTF-16 units).
fn visible_length(text: &str) -> usize {
    let mut n = 0;
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        n += rest[..amp].encode_utf16().count();
        let after = &rest[amp + 1..];
        let body_len = after
            .find(';')
            .filter(|end| entity_body(&after[..*end]))
            .map(|end| end + 1);
        match body_len {
            Some(len) => {
                n += 1;
                rest = &after[len..];
            }
            None => {
                n += 1;
                rest = after;
            }
        }
    }
    n + rest.encode_utf16().count()
}

/// `#\d+`, `#x[0-9a-fA-F]+` or `[a-zA-Z][a-zA-Z0-9]*`.
fn entity_body(body: &str) -> bool {
    if let Some(hex) = body.strip_prefix("#x") {
        return !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit());
    }
    if let Some(dec) = body.strip_prefix('#') {
        return !dec.is_empty() && dec.bytes().all(|b| b.is_ascii_digit());
    }
    let mut bytes = body.bytes();
    matches!(bytes.next(), Some(b) if b.is_ascii_alphabetic())
        && bytes.all(|b| b.is_ascii_alphanumeric())
}

/// `sentenceEnd(html)`: the offset after the opening sentence's stop, at
/// element depth zero and at least thirty characters in.
fn sentence_end(html: &str) -> Option<usize> {
    let chars: Vec<(usize, char)> = html.char_indices().collect();
    let mut depth: i64 = 0;
    let mut i = 0;
    while i < chars.len() {
        let (at, c) = chars[i];
        if c == '<' {
            let close = html[at..].find('>')? + at;
            let tag = &html[at..=close];
            let lower = tag.to_ascii_lowercase();
            if tag.starts_with("</") {
                depth -= 1;
            } else if !tag.ends_with("/>")
                && !["<br", "<hr", "<img", "<input", "<meta", "<link"]
                    .iter()
                    .any(|p| {
                        lower.starts_with(p)
                            && lower[p.len()..].chars().next().is_none_or(|n| {
                                !n.is_alphanumeric() && n != '_'
                            })
                    })
            {
                depth += 1;
            }
            while i < chars.len() && chars[i].0 <= close {
                i += 1;
            }
            continue;
        }
        let units = html[..at].encode_utf16().count();
        if depth == 0
            && units >= 30
            && matches!(c, '.' | '!' | '?')
            && chars.get(i + 1).is_some_and(|(_, n)| n.is_whitespace())
        {
            return Some(at + c.len_utf8());
        }
        i += 1;
    }
    None
}

/// `teaserOf(text)`: cut to a summary line at a word boundary, with an
/// ellipsis; a half entity dropped.
fn teaser_of(text: &str) -> String {
    if visible_length(text) <= SUMMARY_CHARS {
        return text.to_string();
    }
    let mut cut = crate::js::slice16(text, SUMMARY_CHARS);
    if let Some(space) = cut.rfind(' ') {
        if cut[..space].encode_utf16().count() > 40 {
            cut.truncate(space);
        }
    }
    if let Some(amp) = cut.rfind('&') {
        let tail = &cut[amp + 1..];
        let body = tail.strip_suffix(';').unwrap_or(tail);
        if body.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'#') {
            cut.truncate(amp);
        }
    }
    let trimmed = cut
        .trim_end_matches(|c: char| c.is_whitespace() || ",.;:—-".contains(c));
    format!("{}&hellip;", trimmed)
}

/// `foldOf(html)`: the summary and the body of one fold.
fn fold_of(html: &str) -> (String, String) {
    for tag in ["strong", "b", "em"] {
        let lead = html.trim_start();
        let open = format!("<{}>", tag);
        if let Some(after) = lead.strip_prefix(&open) {
            let close = format!("</{}>", tag);
            if let Some(end) = after.find(&close) {
                let title = plain_text_of(&after[..end]);
                let n = title.encode_utf16().count();
                if (24..=SUMMARY_CHARS).contains(&n)
                    && title.ends_with(['.', ':', '!', '?'])
                {
                    let body = after[end + close.len()..].trim_start();
                    return (title, body.to_string());
                }
            }
            break;
        }
    }
    if let Some(cut) = sentence_end(html) {
        let head = plain_text_of(&html[..cut]);
        if !head.is_empty() && head.encode_utf16().count() <= SUMMARY_CHARS {
            return (head, html[cut..].trim_start().to_string());
        }
    }
    (teaser_of(&plain_text_of(html)), html.to_string())
}

/// `WebKit.note(html)`: a paragraph, or a fold when longer than a line.
#[tracing::instrument(level = "trace", skip_all)]
pub fn note(html: &str) -> String {
    let text = plain_text_of(html);
    if visible_length(&text) <= ONE_LINE_CHARS {
        return format!("<p class=\"note\">{}</p>", html);
    }
    let (summary, body) = fold_of(html);
    format!(
        "<details class=\"note fold\"><summary>{}</summary><div \
         class=\"foldbody\">{}</div></details>",
        summary, body
    )
}

/// `WebKit.esc()`: `&#39;` for an apostrophe, as the console escapes.
fn kit_esc(text: &str) -> String {
    sts_http::escape_html(text)
}

/// `WebKit.tabbedPanels(cls, panels)`: the tab bar and the panels; an
/// empty panel is not drawn. The sign-out's tab ids have no documentation
/// link (`common/web_doc_links.ts`).
#[tracing::instrument(level = "trace", skip_all)]
pub fn tabbed_panels(cls: &str, panels: &[(&str, &str, String)]) -> String {
    let shown: Vec<&(&str, &str, String)> =
        panels.iter().filter(|p| !p.2.trim().is_empty()).collect();
    let bar: String = shown
        .iter()
        .enumerate()
        .map(|(n, (id, label, _))| {
            format!(
                "<a{} href=\"#{}\">{}</a>",
                if n == 0 { " class=\"first\"" } else { "" },
                kit_esc(id),
                kit_esc(label)
            )
        })
        .collect();
    let bodies: String = shown
        .iter()
        .enumerate()
        .map(|(n, (id, _, html))| {
            format!(
                "<section class=\"tabpanel{}\" id=\"{}\">{}</section>",
                if n == 0 { " first" } else { "" },
                kit_esc(id),
                html
            )
        })
        .collect();
    format!(
        "<div class=\"tabs {}\"><nav class=\"tabbar\" aria-label=\"Sections \
         of this page\">{}</nav>{}</div>",
        kit_esc(cls),
        bar,
        bodies
    )
}

/// `PageLocale.chooser(t, base, returnTo)`: the one copy is the shared
/// error page's (`sts_http::error_page::chooser`), which every server-drawn
/// page with a language row draws.
#[tracing::instrument(level = "trace", skip_all)]
pub fn chooser(
    t: &sts_http::i18n::Translator<'_>,
    catalogs: &sts_http::i18n::Catalogs,
    return_to: &str,
) -> String {
    sts_http::error_page::chooser(t, catalogs, return_to)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_is_a_paragraph_and_long_folds_at_its_first_sentence() {
        assert_eq!(note("Short."), "<p class=\"note\">Short.</p>");
        let long = "Each was fetched as a one-pixel image as this page \
                    loaded — front-channel logout — and the links are the \
                    same URLs so a failed ping can be seen rather than \
                    guessed at.";
        assert!(note(long).starts_with("<details class=\"note fold\">"));
        assert_eq!(visible_length("a&amp;b"), 3);
        assert_eq!(strip_tags("<b>x</b>y"), "xy");
        assert_eq!(sentence_end("Short. Rest"), None);
    }
}
