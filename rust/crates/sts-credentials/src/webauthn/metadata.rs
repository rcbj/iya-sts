// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The two lists an attestation's trust is read against, as rows
//! `risk/risk_datasets.ts` keeps them: the FIDO Metadata Service's MDS3
//! BLOB (`mdsRowsOf()`, `lookupAuthenticatorBy()`, #62 P5 and #105) and
//! Google's Android attestation status list (`androidStatusRowsOf()`,
//! `lookupAttestationSerials()`, #256).
//!
//! WHAT REPLACED WHAT. Node imports each into the risk store as a dataset
//! VERSION (`activeVersions()`, `isStale()`, `store.lookupFido()`), which is
//! the risk slice's to port; what the verifier reads of it is a row by key.
//! Here each list is held in memory, built from the document — the BLOB
//! verified with `sts-pki`'s `verify_fido_mds_blob()` against the MDS trust
//! anchors first — and answers the lookups Node answers for a fresh active
//! version. The version a lookup names is the BLOB's serial number (`no`)
//! and the status list's caller-given version; a stale or missing list is
//! simply not built, which is Node's null ("no usable BLOB"), and decides
//! nothing.

use std::collections::HashMap;

use serde_json::{json, Map, Value as Json};
use sts_pki::path::Entry;

use super::trust::{AndroidStatus, Metadata};
use crate::js;

/// `RiskDatasets.MDS_COMPROMISED`: a model is compromised if ANY report
/// ever said one of these.
pub const MDS_COMPROMISED: [&str; 5] = [
    "REVOKED",
    "USER_VERIFICATION_BYPASS",
    "ATTESTATION_KEY_COMPROMISE",
    "USER_KEY_REMOTE_COMPROMISE",
    "USER_KEY_PHYSICAL_COMPROMISE",
];

/// `Date.parse()` of the two forms MDS3 and Google's list write — a date
/// (`2024-01-31`, UTC midnight) or an RFC 3339 instant with `Z` — and NaN
/// for anything else, as `Date.parse(x) || 0` then reads it.
#[tracing::instrument(level = "debug")]
pub fn date_parse(text: &str) -> f64 {
    let t = text.trim();
    let num = |s: &str| -> Option<i64> {
        (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse().ok())
            .flatten()
    };
    let (date, time) = match t.split_once('T') {
        Some((d, rest)) => (d, Some(rest)),
        None => (t, None),
    };
    let parts: Vec<&str> = date.split('-').collect();
    if parts.len() != 3 || parts[0].len() != 4 {
        return f64::NAN;
    }
    let (Some(y), Some(m), Some(d)) =
        (num(parts[0]), num(parts[1]), num(parts[2]))
    else {
        return f64::NAN;
    };
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return f64::NAN;
    }
    let mut ms: i64 = 0;
    if let Some(rest) = time {
        let Some(clock) = rest.strip_suffix('Z') else {
            return f64::NAN;
        };
        let (hms, frac) = match clock.split_once('.') {
            Some((a, b)) => (a, Some(b)),
            None => (clock, None),
        };
        let p: Vec<&str> = hms.split(':').collect();
        if p.len() < 2 || p.len() > 3 {
            return f64::NAN;
        }
        let (Some(h), Some(mi)) = (num(p[0]), num(p[1])) else {
            return f64::NAN;
        };
        let sec = if p.len() == 3 { num(p[2]) } else { Some(0) };
        let Some(sec) = sec else {
            return f64::NAN;
        };
        let milli = match frac {
            Some(f) => match num(f) {
                Some(_) => {
                    let three: String =
                        f.chars().chain("000".chars()).take(3).collect();
                    three.parse::<i64>().unwrap_or(0)
                }
                None => return f64::NAN,
            },
            None => 0,
        };
        ms = ((h * 60 + mi) * 60 + sec) * 1000 + milli;
    }
    // Days from the civil date (Howard Hinnant's algorithm).
    let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    (days * 86_400_000 + ms) as f64
}

fn text(v: Option<&Json>) -> String {
    match v {
        None | Some(Json::Null) => String::new(),
        Some(other) => js::string(other),
    }
}

/// The FIDO Metadata Service's BLOB, as rows by the key each model is
/// listed under.
#[derive(Debug, Clone, Default)]
pub struct FidoMetadata {
    version: String,
    rows: HashMap<String, Json>,
}

impl FidoMetadata {
    /// `verifyFidoMdsBlob()` against `anchors`, then the rows of every
    /// entry. `Err` is the verifier's reason.
    #[tracing::instrument(level = "debug", skip(token, anchors))]
    pub fn from_blob(
        token: &str,
        anchors: &[Entry],
        now_ms: i64,
    ) -> Result<FidoMetadata, String> {
        let verdict = sts_pki::foreign::verify_fido_mds_blob(
            token, anchors, now_ms, false,
        );
        if verdict["ok"] != json!(true) {
            return Err(text(verdict.get("reason")));
        }
        Ok(FidoMetadata::from_payload(&verdict["payload"]))
    }

    /// The rows of a verified payload's entries; the version is its `no`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn from_payload(payload: &Json) -> FidoMetadata {
        let mut out = FidoMetadata {
            version: text(payload.get("no")),
            rows: HashMap::new(),
        };
        for entry in payload["entries"].as_array().into_iter().flatten() {
            for row in FidoMetadata::rows_of(entry) {
                let k = format!(
                    "{}\u{0}{}",
                    text(row.get("keyKind")),
                    text(row.get("key"))
                );
                out.rows.insert(k, row);
            }
        }
        out
    }

    /// `RiskDatasets.mdsRowsOf(entry)`: one row per key the model is listed
    /// under — the latest status report, whether ANY report ever said it was
    /// compromised, the latest FIDO_CERTIFIED* report's level, and the
    /// metadata statement without its icon.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn rows_of(entry: &Json) -> Vec<Json> {
        let mut reports: Vec<Json> = entry["statusReports"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        reports.sort_by(|a, b| {
            text(a.get("effectiveDate")).cmp(&text(b.get("effectiveDate")))
        });
        let latest = reports.last().cloned().unwrap_or(json!({}));
        let certified: Vec<&Json> = reports
            .iter()
            .filter(|r| text(r.get("status")).starts_with("FIDO_CERTIFIED"))
            .collect();
        let mut statement = match entry.get("metadataStatement") {
            Some(Json::Object(o)) => o.clone(),
            _ => Map::new(),
        };
        statement.shift_remove("icon");
        let parsed = date_parse(&text(latest.get("effectiveDate")));
        let base: Vec<(&str, Json)> = vec![
            ("description", json!(text(statement.get("description")))),
            (
                "protocolFamily",
                json!(text(statement.get("protocolFamily"))),
            ),
            (
                "certificationLevel",
                json!(certified
                    .last()
                    .map(|r| text(r.get("status")))
                    .unwrap_or_default()),
            ),
            ("latestStatus", json!(text(latest.get("status")))),
            (
                "latestStatusAt",
                js::num(if parsed.is_nan() { 0.0 } else { parsed }),
            ),
            (
                "compromised",
                json!(reports.iter().any(|r| MDS_COMPROMISED
                    .contains(&text(r.get("status")).as_str()))),
            ),
            (
                "statusReports",
                Json::Array(
                    reports
                        .iter()
                        .map(|r| {
                            json!({ "status": text(r.get("status")),
                                "effectiveDate": text(r.get("effectiveDate")) })
                        })
                        .collect(),
                ),
            ),
            ("metadataStatement", Json::Object(statement)),
        ];
        let row = |kind: &str, key: String| {
            let mut o = Map::new();
            o.insert("keyKind".into(), json!(kind));
            o.insert("key".into(), json!(key.to_lowercase()));
            for (k, v) in &base {
                o.insert((*k).to_string(), v.clone());
            }
            Json::Object(o)
        };
        let mut rows = Vec::new();
        if js::truthy_opt(entry.get("aaguid")) {
            rows.push(row("aaguid", text(entry.get("aaguid"))));
        }
        if js::truthy_opt(entry.get("aaid")) {
            rows.push(row("aaid", text(entry.get("aaid"))));
        }
        for one in entry["attestationCertificateKeyIdentifiers"]
            .as_array()
            .into_iter()
            .flatten()
        {
            rows.push(row("acki", js::string(one)));
        }
        rows
    }

    /// The version a lookup names.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn version(&self) -> &str {
        &self.version
    }
}

impl Metadata for FidoMetadata {
    /// `lookupAuthenticatorBy(keyKind, key)`: `{ model, version }`, or none
    /// — for the all-zero AAGUID too, and for a kind it does not key by.
    fn lookup_authenticator_by(
        &self,
        kind: &str,
        key: &str,
    ) -> Result<Option<Json>, String> {
        let wanted = key.to_lowercase();
        if kind == "aaguid"
            && (wanted.is_empty()
                || wanted.chars().all(|c| c == '0' || c == '-'))
        {
            return Ok(None);
        }
        if !["aaguid", "aaid", "acki"].contains(&kind) || wanted.is_empty() {
            return Ok(None);
        }
        Ok(self
            .rows
            .get(&format!("{kind}\u{0}{wanted}"))
            .map(|row| json!({ "model": row, "version": self.version })))
    }
}

/// Google's Android attestation status list, as rows by serial.
#[derive(Debug, Clone, Default)]
pub struct AndroidStatusList {
    version: String,
    rows: HashMap<String, Json>,
}

impl AndroidStatusList {
    /// The list (`{ entries: { serial: entry } }`) under `version`, or none
    /// for a document that is not such a list.
    #[tracing::instrument(level = "debug", skip(list))]
    pub fn from_list(list: &Json, version: &str) -> Option<AndroidStatusList> {
        let rows = AndroidStatusList::rows_of(list)?;
        Some(AndroidStatusList {
            version: version.to_string(),
            rows: rows.into_iter().map(|r| (text(r.get("key")), r)).collect(),
        })
    }

    /// `RiskDatasets.androidSerialKey(serial)`: lower-case hex, no leading
    /// zeros, no `0x`, colons or spaces; empty for what is not hex.
    #[tracing::instrument(level = "debug")]
    pub fn serial_key(serial: &str) -> String {
        let lower = serial.trim().to_lowercase();
        let lower = lower.strip_prefix("0x").unwrap_or(&lower);
        let hex: String = lower
            .chars()
            .filter(|c| *c != ':' && !c.is_whitespace())
            .collect();
        if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return String::new();
        }
        let trimmed = hex.trim_start_matches('0');
        if trimmed.is_empty() {
            "0".to_string()
        } else {
            trimmed.to_string()
        }
    }

    /// `RiskDatasets.androidStatusRowsOf(list)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn rows_of(list: &Json) -> Option<Vec<Json>> {
        let entries = list.get("entries")?.as_object()?;
        let mut rows = Vec::new();
        for (serial, e) in entries {
            let key = AndroidStatusList::serial_key(serial);
            let status = text(e.get("status")).to_uppercase();
            if key.is_empty() || !["REVOKED", "SUSPENDED"].contains(&&*status) {
                continue;
            }
            let reason = match e.get("reason") {
                Some(r) if js::truthy(r) => js::string(r).to_uppercase(),
                _ => "UNSPECIFIED".to_string(),
            };
            let comment: String =
                text(e.get("comment")).chars().take(500).collect();
            let parsed = date_parse(&text(e.get("expires")));
            let compromised =
                ["KEY_COMPROMISE", "CA_COMPROMISE"].contains(&reason.as_str());
            let at = if parsed.is_nan() { 0.0 } else { parsed };
            rows.push(json!({
                "keyKind": "android-serial", "key": key,
                "description": comment,
                "latestStatus": status,
                "latestStatusAt": js::num(at),
                "compromised": compromised,
                "statusReports": [{ "status": status, "reason": reason,
                    "expires": text(e.get("expires")),
                    "comment": comment }],
                "metadataStatement": {}
            }));
        }
        Some(rows)
    }
}

impl AndroidStatus for AndroidStatusList {
    /// `lookupAttestationSerials(serials)` for a fresh active list.
    fn lookup_attestation_serials(
        &self,
        serials: &[String],
    ) -> Result<Json, String> {
        let mut hits = Vec::new();
        for one in serials {
            let key = AndroidStatusList::serial_key(one);
            if key.is_empty() {
                continue;
            }
            if let Some(row) = self.rows.get(&key) {
                hits.push(json!({ "serial": key,
                    "status": text(row.get("latestStatus")),
                    "reason": text(row["statusReports"][0].get("reason")),
                    "compromised": row["compromised"] == json!(true) }));
            }
        }
        Ok(
            json!({ "checked": true, "version": self.version, "hits": hits,
                   "why": "" }),
        )
    }
}
