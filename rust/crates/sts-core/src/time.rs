// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Instants as the Node service writes them: JavaScript's
//! `Date.prototype.toISOString()`, to the millisecond with a `Z`.

use chrono::{DateTime, SecondsFormat, Utc};

/// Now, as `2026-10-05T12:34:56.789Z`.
pub fn iso_now() -> String {
    iso(Utc::now())
}

/// An instant, as `toISOString()` writes it.
pub fn iso(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// An instant to the whole second, as `version.js` writes `builtAt`.
pub fn iso_seconds(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Secs, true)
}
