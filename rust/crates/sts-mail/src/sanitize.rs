// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Whether `sanitize-html` would change a template's HTML part:
//! `mail_templates.ts`'s `problem()` compares the allow-listed run
//! (`MAIL_HTML_ALLOWED`) with one that keeps everything, so a template is
//! refused exactly when the allow-list drops something. What the allow-list
//! drops, read the way htmlparser2 tokenizes:
//!
//! * a tag (opening or closing) not in `ALLOWED_TAGS`;
//! * an attribute not allowed on its tag (`href`, `title` on `a`; `dir`,
//!   `lang` on every tag);
//! * an `href` whose value, entities decoded and every character up to
//!   U+0020 removed, names a scheme (none is allowed) or starts with two
//!   slashes or backslashes (protocol-relative is not allowed).
//!
//! Comments and declarations (`<!`) are refused before this is asked.

/// `MAIL_HTML_ALLOWED.allowedTags`.
const ALLOWED_TAGS: &[&str] = &[
    "a",
    "b",
    "blockquote",
    "br",
    "code",
    "div",
    "em",
    "h1",
    "h2",
    "h3",
    "h4",
    "hr",
    "i",
    "li",
    "ol",
    "p",
    "pre",
    "small",
    "span",
    "strong",
    "table",
    "tbody",
    "td",
    "th",
    "thead",
    "tr",
    "u",
    "ul",
];

fn attribute_allowed(tag: &str, name: &str) -> bool {
    matches!(name, "dir" | "lang") || (tag == "a" && matches!(name, "href" | "title"))
}

/// htmlparser2's `decodeEntities` for what an href may carry: numeric
/// references and the five XML names.
fn decode_entities(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        let end = tail.find(';');
        let decoded = end.and_then(|end| {
            let body = &tail[1..end];
            let ch = if let Some(hex) = body
                .strip_prefix("#x")
                .or_else(|| body.strip_prefix("#X"))
            {
                u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
            } else if let Some(dec) = body.strip_prefix('#') {
                dec.parse::<u32>().ok().and_then(char::from_u32)
            } else {
                match body {
                    "amp" => Some('&'),
                    "lt" => Some('<'),
                    "gt" => Some('>'),
                    "quot" => Some('"'),
                    "apos" => Some('\''),
                    "colon" => Some(':'),
                    "sol" => Some('/'),
                    _ => None,
                }
            };
            ch.map(|c| (c, end + 1))
        });
        match decoded {
            Some((c, used)) => {
                out.push(c);
                rest = &tail[used..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// `naughtyHref()` with `allowedSchemes: []` and no protocol-relative.
fn naughty_href(value: &str) -> bool {
    let decoded = decode_entities(value);
    let mut href: String =
        decoded.chars().filter(|c| (*c as u32) > 0x20).collect();
    while let Some(start) = href.find("<!--") {
        match href[start + 4..].find("-->") {
            Some(end) => {
                href.replace_range(start..start + 4 + end + 3, "");
            }
            None => break,
        }
    }
    let bytes = href.as_bytes();
    if !bytes.is_empty() && bytes[0].is_ascii_alphabetic() {
        let mut i = 1;
        while i < bytes.len()
            && (bytes[i].is_ascii_alphanumeric()
                || matches!(bytes[i], b'.' | b'-' | b'+'))
        {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b':' {
            return true;
        }
    }
    bytes.len() >= 2
        && matches!(bytes[0], b'/' | b'\\')
        && matches!(bytes[1], b'/' | b'\\')
}

/// Whether the allow-list would change `html`. A hot path of a template's
/// save: no span.
pub fn changed_by_allow_list(html: &str) -> bool {
    let chars: Vec<char> = html.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '<' {
            i += 1;
            continue;
        }
        let next = chars.get(i + 1).copied();
        let closing = next == Some('/')
            && chars.get(i + 2).is_some_and(|c| c.is_ascii_alphabetic());
        if !closing && !next.is_some_and(|c| c.is_ascii_alphabetic()) {
            i += 1;
            continue;
        }
        let mut j = if closing { i + 2 } else { i + 1 };
        let start = j;
        while j < chars.len()
            && !chars[j].is_whitespace()
            && chars[j] != '/'
            && chars[j] != '>'
        {
            j += 1;
        }
        let name: String =
            chars[start..j].iter().collect::<String>().to_lowercase();
        if !ALLOWED_TAGS.contains(&name.as_str()) {
            return true;
        }
        // The attributes, to the end of the tag.
        loop {
            while j < chars.len() && (chars[j].is_whitespace() || chars[j] == '/')
            {
                j += 1;
            }
            if j >= chars.len() || chars[j] == '>' {
                break;
            }
            let at = j;
            while j < chars.len()
                && !chars[j].is_whitespace()
                && !matches!(chars[j], '=' | '/' | '>')
            {
                j += 1;
            }
            let attribute: String =
                chars[at..j].iter().collect::<String>().to_lowercase();
            let mut k = j;
            while k < chars.len() && chars[k].is_whitespace() {
                k += 1;
            }
            let mut value = String::new();
            if k < chars.len() && chars[k] == '=' {
                k += 1;
                while k < chars.len() && chars[k].is_whitespace() {
                    k += 1;
                }
                if k < chars.len() && (chars[k] == '"' || chars[k] == '\'') {
                    let quote = chars[k];
                    k += 1;
                    let from = k;
                    while k < chars.len() && chars[k] != quote {
                        k += 1;
                    }
                    value = chars[from..k.min(chars.len())].iter().collect();
                    k += 1;
                } else {
                    let from = k;
                    while k < chars.len()
                        && !chars[k].is_whitespace()
                        && chars[k] != '>'
                    {
                        k += 1;
                    }
                    value = chars[from..k].iter().collect();
                }
                j = k;
            }
            if closing {
                continue;
            }
            if !attribute.is_empty() && !attribute_allowed(&name, &attribute)
            {
                return true;
            }
            if attribute == "href" && naughty_href(&value) {
                return true;
            }
        }
        i = j + 1;
    }
    false
}
