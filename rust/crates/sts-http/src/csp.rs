// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The Content-Security-Policy every response carries, and the two doors a
//! page relaxes it through. `script-src 'none'` makes the family of
//! reflected-content problems moot rather than unlikely; a page that needs a
//! script names one resource (`'self'`), never `'unsafe-inline'`.

/// The base policy, in order.
const BASE: &[(&str, &str)] = &[
    ("default-src", "'none'"),
    ("script-src", "'none'"),
    ("style-src", "'unsafe-inline'"),
    ("img-src", "'self' data:"),
    ("base-uri", "'none'"),
    ("frame-ancestors", "'none'"),
    ("object-src", "'none'"),
];

/// What no caller can turn off.
const UNDROPPABLE: &[&str] = &["frame-ancestors", "base-uri"];

fn base_of(name: &str) -> Option<&'static str> {
    BASE.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
}

/// The directives merged as `Object.assign({}, BASE, overrides)` merges
/// them: the base's in order, a new one after; `None` drops one.
fn merged(overrides: &[(&str, Option<&str>)]) -> Vec<(String, Option<String>)> {
    let mut out: Vec<(String, Option<String>)> = BASE
        .iter()
        .map(|(n, v)| (n.to_string(), Some(v.to_string())))
        .collect();
    for (name, value) in overrides {
        let value = value.map(str::to_string);
        match out.iter_mut().find(|(n, _)| n == name) {
            Some(slot) => slot.1 = value,
            None => out.push((name.to_string(), value)),
        }
    }
    out
}

fn render(directives: Vec<(String, Option<String>)>) -> String {
    directives
        .into_iter()
        .filter_map(|(n, v)| v.map(|v| format!("{} {}", n, v)))
        .collect::<Vec<_>>()
        .join("; ")
}

/// The base policy, as every response carries it.
pub fn base_policy() -> String {
    content_security_policy(&[])
}

/// The base policy with some directives relaxed. `frame-ancestors` and
/// `base-uri` are always the base's, whatever was asked — deliberately.
pub fn content_security_policy(overrides: &[(&str, Option<&str>)]) -> String {
    let mut directives = merged(overrides);
    for (name, value) in directives.iter_mut() {
        if UNDROPPABLE.contains(&name.as_str()) {
            *value = base_of(name).map(str::to_string);
        }
    }
    render(directives)
}

/// The policy a response that is not a page gets at the flush (Qualys QID
/// 150207, 2026-11-10, `NOT_A_PAGE_POLICY`): the base without `style-src`
/// and `img-src`, which permit nothing a JSON answer, a metadata document
/// or a plain-text refusal wanted.
pub fn not_a_page_policy() -> String {
    content_security_policy(&[("style-src", None), ("img-src", None)])
}

/// Whether a `Content-Type` is one [`not_a_page_policy`] is for
/// (`NOT_A_PAGE_TYPES`): JSON, XML (`application/…+xml`, `text/xml`) or
/// plain text. An SVG is XML that may style itself, and keeps the base.
pub fn not_a_page_type(content_type: &str) -> bool {
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if essence.contains(char::is_whitespace) {
        return false;
    }
    if essence == "text/plain" || essence == "text/xml" {
        return true;
    }
    let Some(sub) = essence.strip_prefix("application/") else {
        return false;
    };
    let last = sub.rsplit('+').next().unwrap_or(sub);
    (last == "json" || last == "xml")
        && !sub.is_empty()
        && (sub == last || !sub[..sub.len() - last.len() - 1].is_empty())
}

/// A `script-src` narrowed to the sources that name a script exactly
/// (`exactScriptSources()`, #1297): `'none'`, `'self'` and hash sources;
/// `'none'` when nothing else is left.
fn exact_script_sources(value: Option<&str>) -> String {
    let value = value.unwrap_or("'none'");
    let exact = |one: &str| {
        if one == "'none'" || one == "'self'" {
            return true;
        }
        let Some(inner) =
            one.strip_prefix('\'').and_then(|o| o.strip_suffix('\''))
        else {
            return false;
        };
        let Some((alg, b64)) = inner.split_once('-') else {
            return false;
        };
        let body = b64.trim_end_matches('=');
        matches!(alg, "sha256" | "sha384" | "sha512")
            && !body.is_empty()
            && b64.len() - body.len() <= 2
            && body
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
    };
    let sources: Vec<&str> = value
        .split_whitespace()
        .filter(|one| exact(one) && *one != "'none'")
        .collect();
    if sources.is_empty() {
        "'none'".to_string()
    } else {
        sources.join(" ")
    }
}

/// Whether an origin may frame the one framed page: an http(s) origin and
/// nothing more (no path, no wildcard).
fn framing_origin(origin: &str) -> bool {
    let rest = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"));
    rest.is_some_and(|r| {
        !r.is_empty()
            && r.bytes().all(|c| {
                c.is_ascii_alphanumeric()
                    || matches!(c, b'.' | b'-' | b'[' | b']' | b':')
            })
    })
}

/// The policy for the OP iframe (#121): `frame-ancestors` narrowed to the
/// named origins, `'none'` when none is an http(s) origin. `*` cannot be
/// reached through it, and its `script-src` names scripts exactly or not
/// at all (#1297): never `'unsafe-inline'`.
pub fn framed_content_security_policy(
    origins: &[&str],
    overrides: &[(&str, Option<&str>)],
) -> String {
    let allowed: Vec<&str> = origins
        .iter()
        .copied()
        .filter(|o| framing_origin(o))
        .collect();
    let mut directives = merged(overrides);
    for (name, value) in directives.iter_mut() {
        if name == "base-uri" {
            *value = base_of(name).map(str::to_string);
        }
        if name == "script-src" {
            *value = Some(exact_script_sources(value.as_deref()));
        }
        if name == "frame-ancestors" {
            *value = Some(if allowed.is_empty() {
                "'none'".to_string()
            } else {
                allowed.join(" ")
            });
        }
    }
    render(directives)
}

/// Whether a policy's `frame-ancestors` is `'none'`.
pub fn frame_ancestors_none(policy: &str) -> bool {
    policy
        .split(';')
        .map(str::trim)
        .find_map(|d| d.strip_prefix("frame-ancestors"))
        .is_some_and(|v| v.trim() == "'none'")
}
