// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! One application as the register works on it (`blankRecord()`,
//! `recordFromAttributes()`) and as the directory stores it
//! (`attributesFor()`).
//!
//! `fields` is Node's `record.fields`: an attribute name to ONE string for
//! a single-valued row and a LIST of strings for a multi-valued one, in
//! the order the record was given them — a JSON object, because every
//! check reads it the way Node's does (`valuesOf(fields[name])`).

use serde_json::{Map, Value};

use super::tables::Tables;

/// `record.fields`.
pub type Fields = Map<String, Value>;

/// The credential snapshot (`credentialSnapshotOf()`) a record was read
/// with: what `noteCredentialWrite()` compares a write against.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Snapshot(pub Value);

/// An application record.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Record {
    pub identifier: String,
    pub label: String,
    pub name: String,
    pub kinds: Vec<String>,
    pub protocols: Vec<String>,
    pub description: String,
    /// Milliseconds; 0 for never.
    pub first_at: i64,
    pub last_at: i64,
    pub authentications: i64,
    pub session_count: i64,
    pub user_count: i64,
    pub registered: bool,
    pub fields: Fields,
    /// Absent on a blank record (Node's symbol is not set).
    pub snapshot: Option<Snapshot>,
}

/// The longest identifier that is its own `cn` (`MAX_RDN_LENGTH`).
pub const MAX_RDN_LENGTH: usize = 64;

/// The members of a record that are its own attributes, never `fields`.
const OWN_ATTRIBUTES: &[&str] = &[
    "appIdentifier",
    "cn",
    "appName",
    "appKind",
    "appProtocol",
    "description",
    "appFirstSeen",
    "appLastSeen",
    "appAuthentications",
    "appSessions",
    "appUsers",
    "appRegistered",
];

/// The single-valued credential attributes the snapshot carries
/// (`SNAPSHOT_SINGLE`).
pub const SNAPSHOT_SINGLE: &[&str] = &[
    "oauthJwks",
    "oauthJwksUri",
    "oauthAssertionJwks",
    "oauthAssertionCertificate",
    "oauthSamlAssertionCertificate",
    "oauthSamlAssertionSigningCertificate",
    "samlEncryptionCertificate",
];

// A HOT PATH: every check reads values through it, so no span.
/// `valuesOf(value)`: nothing for `undefined`, `null` and `''`; a list's
/// members (or the one value) as strings, the empty ones dropped.
pub fn values_of(value: Option<&Value>) -> Vec<String> {
    match value {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(s)) if s.is_empty() => Vec::new(),
        Some(Value::Array(list)) => list
            .iter()
            .map(crate::js::string)
            .filter(|s| !s.is_empty())
            .collect(),
        Some(other) => {
            let s = crate::js::string(other);
            if s.is_empty() {
                Vec::new()
            } else {
                vec![s]
            }
        }
    }
}

// A HOT PATH: every check reads values through it, so no span.
/// `String(valuesOf(fields[name])[0] || '')`.
pub fn first_of(fields: &Fields, name: &str) -> String {
    values_of(fields.get(name))
        .into_iter()
        .next()
        .unwrap_or_default()
}

/// `generalizedTime(when)`: `when` is milliseconds, and 0 (falsy) is NOW,
/// as `when ? new Date(when) : new Date()` reads it.
#[tracing::instrument(level = "debug")]
pub fn generalized_time(when_ms: i64, now_ms: i64) -> String {
    let ms = if when_ms != 0 { when_ms } else { now_ms };
    sts_directory::ports::generalized_time_of(ms.div_euclid(1000))
}

/// `fromGeneralizedTime(value)`: milliseconds, 0 for a value that is not
/// `YYYYMMDDHHMMSSZ`.
#[tracing::instrument(level = "debug")]
pub fn from_generalized_time(value: &str) -> i64 {
    let b = value.as_bytes();
    if b.len() != 15 || b[14] != b'Z' || !b[..14].iter().all(u8::is_ascii_digit)
    {
        return 0;
    }
    let n = |a: usize, z: usize| value[a..z].parse::<i64>().unwrap_or(0);
    date_utc(
        n(0, 4),
        n(4, 6) - 1,
        n(6, 8),
        n(8, 10),
        n(10, 12),
        n(12, 14),
    )
}

/// `Date.UTC(y, m, d, h, mi, s)`, overflowing months and days as it does.
fn date_utc(y: i64, m: i64, d: i64, h: i64, mi: i64, s: i64) -> i64 {
    let y = y + m.div_euclid(12);
    let m = m.rem_euclid(12) + 1;
    // Howard Hinnant's days-from-civil.
    let yy = if m <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468 + (d - 1);
    ((days * 24 + h) * 60 + mi) * 60_000 + s * 1000
}

/// `new Date(ms).toISOString()`.
#[tracing::instrument(level = "debug")]
pub fn iso_string(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let g = sts_directory::ports::generalized_time_of(secs);
    format!(
        "{}-{}-{}T{}:{}:{}.{:03}Z",
        &g[0..4],
        &g[4..6],
        &g[6..8],
        &g[8..10],
        &g[10..12],
        &g[12..14],
        millis
    )
}

impl Record {
    /// `blankRecord(identifier)`.
    #[tracing::instrument(level = "debug", skip(label))]
    pub fn blank(identifier: &str, label: String) -> Record {
        Record {
            identifier: identifier.to_string(),
            label,
            name: identifier.to_string(),
            ..Record::default()
        }
    }

    /// `recordFromAttributes(attributes)`: the attributes read by
    /// LOWER-CASED name, the schema's rows in schema order.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn from_attributes(attributes: &Map<String, Value>) -> Record {
        let mut lower: Map<String, Value> = Map::new();
        for (k, v) in attributes {
            lower.insert(k.to_lowercase(), v.clone());
        }
        let all = |name: &str| -> Vec<String> {
            match lower.get(&name.to_lowercase()) {
                Some(Value::Array(list)) => {
                    list.iter().map(crate::js::string).collect()
                }
                Some(Value::Null) | None => Vec::new(),
                Some(other) => vec![crate::js::string(other)],
            }
        };
        let first = |name: &str| -> String {
            all(name).into_iter().next().unwrap_or_default()
        };
        let int = |name: &str| -> i64 { js_parse_int(&first(name)) };
        let mut fields = Fields::new();
        for row in &Tables::get().schema.attributes {
            if OWN_ATTRIBUTES.contains(&row.name.as_str()) {
                continue;
            }
            let values = all(&row.name);
            if values.is_empty() {
                continue;
            }
            let value = if row.kind == "multi" {
                Value::Array(values.into_iter().map(Value::String).collect())
            } else {
                Value::String(values[0].clone())
            };
            fields.insert(row.name.clone(), value);
        }
        let snapshot = Some(Snapshot(snapshot_of(&fields)));
        Record {
            identifier: first("appIdentifier"),
            label: first("cn"),
            name: first("appName"),
            kinds: all("appKind"),
            protocols: all("appProtocol"),
            description: first("description"),
            first_at: from_generalized_time(&first("appFirstSeen")),
            last_at: from_generalized_time(&first("appLastSeen")),
            authentications: int("appAuthentications"),
            session_count: int("appSessions"),
            user_count: int("appUsers"),
            registered: first("appRegistered") == "TRUE",
            fields,
            snapshot,
        }
    }

    /// `attributesFor(record)`: the entry's attributes, in Node's order,
    /// the empty ones left out. `label` is `labelFor(identifier)`;
    /// `now_ms` is the clock `generalizedTime()` reads for a time of 0.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn attributes(
        &self,
        label: String,
        now_ms: i64,
    ) -> Vec<(String, Vec<String>)> {
        let mut out: Vec<(String, Vec<String>)> = vec![
            ("objectClass".into(), Tables::get().object_classes()),
            ("cn".into(), vec![label]),
            ("appIdentifier".into(), vec![self.identifier.clone()]),
            (
                "appName".into(),
                vec![if self.name.is_empty() {
                    self.identifier.clone()
                } else {
                    self.name.clone()
                }],
            ),
            ("appKind".into(), self.kinds.clone()),
            ("appProtocol".into(), self.protocols.clone()),
            (
                "appFirstSeen".into(),
                vec![generalized_time(self.first_at, now_ms)],
            ),
            (
                "appLastSeen".into(),
                vec![generalized_time(self.last_at, now_ms)],
            ),
            (
                "appAuthentications".into(),
                vec![self.authentications.to_string()],
            ),
            ("appSessions".into(), vec![self.session_count.to_string()]),
            ("appUsers".into(), vec![self.user_count.to_string()]),
            (
                "appRegistered".into(),
                vec![if self.registered { "TRUE" } else { "FALSE" }.into()],
            ),
            (
                "description".into(),
                if self.description.is_empty() {
                    Vec::new()
                } else {
                    vec![self.description.clone()]
                },
            ),
        ];
        for (name, value) in &self.fields {
            if out.iter().any(|(n, _)| n == name) {
                continue;
            }
            out.push((name.clone(), values_of(Some(value))));
        }
        out.retain(|(_, v)| !v.is_empty());
        out
    }
}

/// `labelFor(identifier)`, with the digest handed in (`shortName()` is
/// `'app-' + sha256(identifier).slice(0, 12)`).
#[tracing::instrument(level = "debug", skip(digest))]
pub fn label_for_with(
    identifier: &str,
    digest: impl Fn(&str) -> String,
) -> String {
    if crate::js::len_utf16(identifier) <= MAX_RDN_LENGTH {
        identifier.to_string()
    } else {
        digest(identifier)
    }
}

/// `credentialSnapshotOf(fields)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn snapshot_of(fields: &Fields) -> Value {
    let mut secrets = values_of(fields.get("oauthClientSecret"));
    secrets.sort();
    let mut signing = values_of(fields.get("samlSigningCertificate"));
    signing.sort();
    let mut out = Map::new();
    out.insert(
        "secrets".into(),
        Value::Array(secrets.into_iter().map(Value::String).collect()),
    );
    out.insert(
        "samlSigning".into(),
        Value::Array(signing.into_iter().map(Value::String).collect()),
    );
    for name in SNAPSHOT_SINGLE {
        out.insert((*name).into(), Value::String(first_of(fields, name)));
    }
    Value::Object(out)
}

// A HOT PATH: read for every counter of every record, so no span.
/// `parseInt(text || '0', 10) || 0`.
pub fn js_parse_int(text: &str) -> i64 {
    let t = crate::js::trim(text);
    let (neg, digits) = match t.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let lead: String =
        digits.chars().take_while(char::is_ascii_digit).collect();
    if lead.is_empty() {
        return 0;
    }
    let n = lead.parse::<i64>().unwrap_or(0);
    if neg {
        -n
    } else {
        n
    }
}
