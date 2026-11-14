// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! KerberosTime (RFC 4120 section 5.2.3): `YYYYMMDDHHMMSSZ`, whole seconds,
//! UTC. Node reads it into a JavaScript `Date` through `Date.UTC()`, and
//! that function's arithmetic is part of the verdict, so it is ported
//! rather than replaced with a calendar library's stricter one:
//!
//! * a month, day, hour, minute or second out of range ROLLS OVER rather
//!   than being refused (`20261332000000Z` is 2027-02-01);
//! * a year below 100 is read as 1900 plus it (`0050…` is 1950).
//!
//! Formatting is Node's `formatKerberosTime()`: the year is `String(year)`,
//! unpadded.

use serde::{Serialize, Serializer};

use crate::error::{Krb5Error, Krb5Result};

/// A KerberosTime, as seconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KrbTime(pub i64);

/// Days from 1970-01-01 to a proleptic Gregorian date (Hinnant's
/// `days_from_civil`), month 1–12.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The inverse: (year, month 1–12, day 1–31).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

impl KrbTime {
    /// JavaScript's `Date.UTC(year, month0, day, h, mi, s)` in seconds,
    /// with its roll-over and its two-digit-year rule.
    pub fn utc(
        year: i64,
        month0: i64,
        day: i64,
        h: i64,
        mi: i64,
        s: i64,
    ) -> Self {
        let year = if (0..=99).contains(&year) {
            1900 + year
        } else {
            year
        };
        let y = year + month0.div_euclid(12);
        let m = month0.rem_euclid(12) + 1;
        let days = days_from_civil(y, m, 1) + (day - 1);
        KrbTime(days * 86_400 + h * 3600 + mi * 60 + s)
    }

    /// The civil fields: (year, month 1–12, day, hour, minute, second).
    pub fn fields(&self) -> (i64, i64, i64, i64, i64, i64) {
        let days = self.0.div_euclid(86_400);
        let secs = self.0.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        (y, m, d, secs / 3600, (secs / 60) % 60, secs % 60)
    }

    /// Node's `parseKerberosTime()`.
    pub fn parse(text: &str) -> Krb5Result<Self> {
        let b = text.as_bytes();
        let ok = b.len() == 15
            && b[14] == b'Z'
            && b[..14].iter().all(u8::is_ascii_digit);
        if !ok {
            return Err(Krb5Error::new(format!(
                "krb5: KerberosTime must be YYYYMMDDHHMMSSZ, got {}",
                json_string(text)
            )));
        }
        let n = |from: usize, to: usize| -> i64 {
            b[from..to]
                .iter()
                .fold(0i64, |acc, d| acc * 10 + i64::from(d - b'0'))
        };
        Ok(KrbTime::utc(
            n(0, 4),
            n(4, 6) - 1,
            n(6, 8),
            n(8, 10),
            n(10, 12),
            n(12, 14),
        ))
    }

    /// Node's `formatKerberosTime()`.
    pub fn format(&self) -> String {
        let (y, m, d, h, mi, s) = self.fields();
        format!("{}{:02}{:02}{:02}{:02}{:02}Z", y, m, d, h, mi, s)
    }

    /// JavaScript's `Date.prototype.toISOString()`, which is how a decoded
    /// time serializes.
    pub fn iso(&self) -> String {
        let (y, m, d, h, mi, s) = self.fields();
        let year = if (0..=9999).contains(&y) {
            format!("{:04}", y)
        } else if y < 0 {
            format!("-{:06}", -y)
        } else {
            format!("+{:06}", y)
        };
        format!(
            "{}-{:02}-{:02}T{:02}:{:02}:{:02}.000Z",
            year, m, d, h, mi, s
        )
    }
}

/// `JSON.stringify()` of a string, for the one error message that quotes
/// one.
pub(crate) fn json_string(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

impl Serialize for KrbTime {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.iso())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn date_utc_rules() {
        let t = KrbTime::parse("20260101123456Z").unwrap();
        assert_eq!(t.format(), "20260101123456Z");
        assert_eq!(t.iso(), "2026-01-01T12:34:56.000Z");
        assert_eq!(
            KrbTime::parse("20261332000000Z").unwrap().format(),
            "20270201000000Z"
        );
        assert_eq!(
            KrbTime::parse("00500101000000Z").unwrap().format(),
            "19500101000000Z"
        );
        assert_eq!(KrbTime(0).format(), "19700101000000Z");
        assert!(KrbTime::parse("2026010112345Z").is_err());
    }
}
