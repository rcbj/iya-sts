// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! RFC 2849 LDIF, as `persistence_ldif.js` writes and reads it.
//!
//! * A value is plain text only when it is a SAFE-STRING (no leading space,
//!   colon or `<`, no NUL, LF or CR) that does not END with a space — and
//!   is ASCII: a file whose encoding a reader guesses comes back wrong, and
//!   base64 removes the guess. Anything else is `name:: base64`.
//! * Lines are folded at 76 columns, OpenLDAP's width, so a diff against a
//!   file its tools wrote lines up; a continuation is one space.
//! * `origin` rides as a `# sts-origin: <value>` comment above the record:
//!   every other reader ignores it, where an invented attribute would be
//!   real on reload.
//! * A URL-valued attribute (`name:< url`) is never followed: reading a
//!   file: or http: URL out of a data file reads what somebody else chose.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use indexmap::IndexMap;
use sts_core::errors::codes;
use sts_core::log::tag;

use crate::model::StoredEntry;

const WRAP_AT: usize = 76;
const ORIGIN_COMMENT: &str = "# sts-origin: ";

/// Whether a value must be written base64-encoded.
pub fn needs_base64(value: &str) -> bool {
    let b = value.as_bytes();
    let Some(&first) = b.first() else {
        return false;
    };
    if first == b' ' || first == b':' || first == b'<' {
        return true;
    }
    if b[b.len() - 1] == b' ' {
        return true;
    }
    b.iter()
        .any(|&c| c == 0 || c == b'\n' || c == b'\r' || c > 0x7f)
}

/// One `name: value` line, encoded and folded.
pub fn ldif_line(name: &str, value: &str) -> String {
    let line = if needs_base64(value) {
        format!("{}:: {}", name, STANDARD.encode(value.as_bytes()))
    } else {
        format!("{}: {}", name, value)
    };
    // A written line is ASCII (anything else was base64), so bytes are
    // characters here.
    if line.len() <= WRAP_AT || !line.is_ascii() {
        return line;
    }
    let mut parts = vec![line[..WRAP_AT].to_string()];
    let mut rest = &line[WRAP_AT..];
    while !rest.is_empty() {
        let take = rest.len().min(WRAP_AT - 1);
        parts.push(format!(" {}", &rest[..take]));
        rest = &rest[take..];
    }
    parts.join("\n")
}

fn entry_to_ldif(entry: &StoredEntry) -> String {
    let mut lines = Vec::new();
    if let Some(origin) = entry.origin.as_deref().filter(|o| !o.is_empty()) {
        lines.push(format!("{}{}", ORIGIN_COMMENT, origin));
    }
    lines.push(ldif_line("dn", &entry.dn));
    for (name, values) in &entry.attributes {
        for value in values {
            lines.push(ldif_line(name, value));
        }
    }
    lines.join("\n")
}

/// `toLdif()`: the header as comments, `version: 1`, then each record
/// followed by a blank line.
pub fn to_ldif(rows: &[StoredEntry], header: &[&str]) -> String {
    let mut out: Vec<String> =
        header.iter().map(|l| format!("# {}", l)).collect();
    out.push("version: 1".to_string());
    out.push(String::new());
    for entry in rows {
        out.push(entry_to_ldif(entry));
        out.push(String::new());
    }
    out.join("\n")
}

/// `Buffer.from(text, 'base64').toString('utf8')`: lenient, as node is.
fn node_base64_text(text: &str) -> String {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => continue,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn unfold(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        match (line.strip_prefix(' '), out.last_mut()) {
            (Some(rest), Some(last)) => last.push_str(rest),
            _ => out.push(line.to_string()),
        }
    }
    out
}

enum Parsed {
    Value(String, String),
    Url,
}

fn parse_line(line: &str) -> Option<Parsed> {
    let colon = line.find(':')?;
    let name = &line[..colon];
    let rest = &line[colon + 1..];
    if rest.starts_with('<') {
        return Some(Parsed::Url);
    }
    if let Some(b64) = rest.strip_prefix(':') {
        return Some(Parsed::Value(
            name.to_string(),
            node_base64_text(b64.trim()),
        ));
    }
    Some(Parsed::Value(
        name.to_string(),
        rest.strip_prefix(' ').unwrap_or(rest).to_string(),
    ))
}

/// `fromLdif()`: the entries back, attribute names lower-cased, origin from
/// its comment, the two timestamps rebuilt from their attributes. Skipped
/// lines (a URL value, an attribute before any `dn:`) are reported once.
pub fn from_ldif(text: &str) -> Vec<StoredEntry> {
    let mut entries = Vec::new();
    let mut current: Option<StoredEntry> = None;
    let mut pending_origin = String::new();
    let mut skipped = 0usize;
    for line in unfold(text) {
        if line.is_empty() {
            entries.extend(current.take());
            pending_origin.clear();
            continue;
        }
        if line.starts_with('#') {
            if let Some(origin) = line.strip_prefix(ORIGIN_COMMENT) {
                pending_origin = origin.trim().to_string();
            }
            continue;
        }
        let Some(parsed) = parse_line(&line) else {
            continue;
        };
        let Parsed::Value(name, value) = parsed else {
            skipped += 1;
            continue;
        };
        let name = name.to_lowercase();
        if name == "version" {
            continue;
        }
        if name == "dn" {
            entries.extend(current.take());
            current = Some(StoredEntry {
                dn: value,
                attributes: IndexMap::new(),
                origin: (!pending_origin.is_empty())
                    .then(|| pending_origin.clone()),
                created_at: None,
                modified_at: None,
            });
            pending_origin.clear();
            continue;
        }
        match current.as_mut() {
            Some(entry) => {
                entry.attributes.entry(name).or_default().push(value)
            }
            None => skipped += 1,
        }
    }
    entries.extend(current.take());
    for entry in &mut entries {
        let first = |n: &str| {
            entry
                .attributes
                .get(n)
                .and_then(|v| v.first())
                .filter(|v| !v.is_empty())
                .cloned()
        };
        let created = first("createtimestamp");
        let modified = first("modifytimestamp");
        entry.modified_at = modified.or_else(|| created.clone());
        entry.created_at = created;
    }
    if skipped > 0 {
        tracing::warn!(
            "{}persistence: {} LDIF line(s) were not loaded — a URL-valued attribute (which this service will \
             not dereference) or a line before the first dn:.",
            tag(codes::STS_STORE_0010),
            skipped
        );
    }
    entries
}
