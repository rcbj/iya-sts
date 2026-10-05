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
/// reached through it.
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
