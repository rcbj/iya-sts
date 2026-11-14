// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The service's own DN string helpers, ported from `ldap/ldap_server.js`
//! (`normalizeDn()`, `parentDn()`, `isUnder()`, `depthUnder()`,
//! `splitRdns()`, `rdnPairs()`, `escapeDnValue()`, `unescapeDnValue()`,
//! `nameUsableInDn()` and `DN_RESERVED`).
//!
//! They are string operations, not `@ldapjs/dn`: the directory compares
//! and stores DNs as these produce them, so they are ported as they are —
//! `normalizeDn()` lowercases values as well as names and splits on every
//! comma, escaped or not; `parentDn()` splits on every comma too, so the
//! parent of `cn=a\,b,dc=x` is `b,dc=x`; `escapeDnValue()` escapes `=` and
//! `\` (which `@ldapjs/dn` does not). `null` is the empty string. Lengths
//! are counted in UTF-16 code units, as `depthUnder()`'s `slice()` does.

use crate::js;

fn text(v: Option<&str>) -> String {
    v.unwrap_or("").to_string()
}

/// `normalizeDn()`.
#[tracing::instrument(level = "debug")]
pub fn normalize_dn(value: Option<&str>) -> String {
    let t = text(value);
    js::trim(&t)
        .split(',')
        .map(|p| js::trim(p).to_lowercase())
        .collect::<Vec<_>>()
        .join(",")
}

/// `parentDn()`.
#[tracing::instrument(level = "debug")]
pub fn parent_dn(value: Option<&str>) -> String {
    let t = text(value);
    let parts: Vec<&str> = t.split(',').collect();
    if parts.len() <= 1 {
        return String::new();
    }
    js::trim(&parts[1..].join(",")).to_string()
}

/// `isUnder()`.
#[tracing::instrument(level = "debug")]
pub fn is_under(dn: Option<&str>, base: Option<&str>) -> bool {
    let a = normalize_dn(dn);
    let b = normalize_dn(base);
    if b.is_empty() || a == b {
        return true;
    }
    a.ends_with(&format!(",{b}"))
}

/// `depthUnder()`.
#[tracing::instrument(level = "debug")]
pub fn depth_under(dn: Option<&str>, base: Option<&str>) -> usize {
    let a = js::units(&normalize_dn(dn));
    let b = js::units(&normalize_dn(base));
    if a == b {
        return 0;
    }
    let end = a.len() as i64 - b.len() as i64 - 1;
    let rest = js::slice_units(&a, 0, end);
    js::split_units(rest, u16::from(b',')).len()
}

/// `splitRdns()`: split on commas not preceded by a backslash, trimmed,
/// empty parts dropped.
#[tracing::instrument(level = "debug")]
pub fn split_rdns(dn: Option<&str>) -> Vec<String> {
    let t = text(dn);
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut prev = None;
    for c in t.chars() {
        if c == ',' && prev != Some('\\') {
            parts.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
        prev = Some(c);
    }
    parts.push(cur);
    parts
        .iter()
        .map(|p| js::trim(p).to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

/// One `{ attribute, value }` of `rdnPairs()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdnPair {
    pub attribute: String,
    pub value: String,
}

/// `rdnPairs()`.
#[tracing::instrument(level = "debug")]
pub fn rdn_pairs(rdn: Option<&str>) -> Vec<RdnPair> {
    let t = text(rdn);
    t.split('+')
        .filter_map(|part| {
            let u = js::units(part);
            let at = js::index_of(&u, &[u16::from(b'=')], 0)?;
            if at < 1 {
                return None;
            }
            Some(RdnPair {
                attribute: js::trim(&js::from_units(&u[..at])).to_lowercase(),
                value: js::trim(&js::from_units(&u[at + 1..])).to_string(),
            })
        })
        .collect()
}

/// `escapeDnValue()`.
#[tracing::instrument(level = "debug")]
pub fn escape_dn_value(value: Option<&str>) -> String {
    let t = text(value);
    let mut out = String::with_capacity(t.len());
    for c in t.chars() {
        if matches!(c, '\\' | ',' | '+' | '"' | '<' | '>' | ';' | '=') {
            out.push('\\');
        }
        out.push(c);
    }
    if out.starts_with('#') {
        out.insert(0, '\\');
    }
    if out.starts_with(' ') {
        out.replace_range(0..1, "\\ ");
    }
    if out.ends_with(' ') {
        let n = out.len();
        out.replace_range(n - 1..n, "\\ ");
    }
    out
}

/// `unescapeDnValue()`: `/\\(.)/g` → `$1`, where `.` is anything but a
/// line terminator.
#[tracing::instrument(level = "debug")]
pub fn unescape_dn_value(value: Option<&str>) -> String {
    let t = text(value);
    let chars: Vec<char> = t.chars().collect();
    let mut out = String::with_capacity(t.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' {
            if let Some(&n) = chars.get(i + 1) {
                if !matches!(n, '\n' | '\r' | '\u{2028}' | '\u{2029}') {
                    out.push(n);
                    i += 2;
                    continue;
                }
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// `nameUsableInDn()`: none of `DN_RESERVED`, `/[,=+<>#;"\\]/`.
#[tracing::instrument(level = "debug")]
pub fn name_usable_in_dn(name: Option<&str>) -> bool {
    !text(name).chars().any(|c| {
        matches!(c, ',' | '=' | '+' | '<' | '>' | '#' | ';' | '"' | '\\')
    })
}
