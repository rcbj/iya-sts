// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Times: what `new Date(x)` reads, and the two encodings a validity field
//! has (RFC 5280 section 4.1.2.5) — UTCTime before 2050, GeneralizedTime
//! from it, because a 2050 UTCTime reads as 1950.

use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, TimeZone, Utc};
use serde_json::Value as Json;

use crate::der;
use crate::error::{PkiError, PkiResult};

/// `new Date(x)` for a spec's date: an ISO string, a date alone (UTC
/// midnight, as ECMAScript reads it), or milliseconds since the epoch.
pub fn js_date(value: &Json) -> PkiResult<DateTime<Utc>> {
    let invalid = || PkiError::new("Invalid time value");
    match value {
        Json::Number(n) => {
            let ms = n.as_f64().ok_or_else(invalid)?;
            Utc.timestamp_millis_opt(ms as i64)
                .single()
                .ok_or_else(invalid)
        }
        Json::String(s) => parse_iso(s).ok_or_else(invalid),
        _ => Err(invalid()),
    }
}

fn parse_iso(s: &str) -> Option<DateTime<Utc>> {
    if let Ok(t) = DateTime::parse_from_rfc3339(s) {
        return Some(t.with_timezone(&Utc));
    }
    if let Ok(d) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Some(Utc.from_utc_datetime(&d.and_hms_opt(0, 0, 0)?));
    }
    // A date-time with no zone is LOCAL time to ECMAScript; the service runs
    // in UTC, so it is read as UTC here.
    NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f")
        .ok()
        .map(|t| Utc.from_utc_datetime(&t))
}

/// `Date.prototype.toISOString()`: milliseconds always.
pub fn iso(t: &DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// A validity time as pkijs writes it: UTCTime (YYMMDDHHMMSSZ) before 2050,
/// GeneralizedTime from it — with `.mmm` when the milliseconds are not
/// zero, as asn1js writes one.
pub fn validity_time(t: &DateTime<Utc>) -> Vec<u8> {
    if t.year() >= 2050 {
        let mut text = t.format("%Y%m%d%H%M%S").to_string();
        let ms = t.timestamp_subsec_millis();
        if ms != 0 {
            text.push_str(&format!(".{:03}", ms));
        }
        text.push('Z');
        der::tlv(der::GENERALIZED_TIME, text.as_bytes())
    } else {
        der::tlv(
            der::UTC_TIME,
            t.format("%y%m%d%H%M%SZ").to_string().as_bytes(),
        )
    }
}

/// A UTCTime or GeneralizedTime read back.
pub fn read_time(e: &der::Element<'_>) -> Option<DateTime<Utc>> {
    let text = std::str::from_utf8(e.content).ok()?;
    let body = text.strip_suffix('Z')?;
    match e.tag {
        der::UTC_TIME => {
            let yy: i32 = body.get(0..2)?.parse().ok()?;
            let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
            let rest = NaiveDateTime::parse_from_str(
                &format!("{}{}", year, body.get(2..)?),
                "%Y%m%d%H%M%S",
            )
            .ok()?;
            Some(Utc.from_utc_datetime(&rest))
        }
        der::GENERALIZED_TIME => {
            let (main, frac) = match body.split_once('.') {
                Some((m, f)) => (m, Some(f)),
                None => (body, None),
            };
            let t = NaiveDateTime::parse_from_str(main, "%Y%m%d%H%M%S").ok()?;
            let mut out = Utc.from_utc_datetime(&t);
            if let Some(f) = frac {
                let ms: i64 = format!("{:0<3}", f).get(0..3)?.parse().ok()?;
                out += chrono::Duration::milliseconds(ms);
            }
            Some(out)
        }
        _ => None,
    }
}
