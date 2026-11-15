// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Recovery codes as a MECHANISM: a port of `common/backup_codes.ts`
//! (`common/CLAUDE.md` 3y) — what a code is made of, how one is generated,
//! printed, compared and hashed. Where a set LIVES is the store's
//! ([`crate::credentials`]).
//!
//! The alphabet is base32's thirty-two characters and is NOT shared with
//! [`crate::totp`]: there it is for interoperability, here because no pair
//! of them is confusable on paper. They are declared apart because they are
//! the same set by coincidence.

use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_core::errors::codes;
use sts_core::log::tag;
use sts_crypto::secrets::{constant_time_equals, verify_secret};

use crate::js;
use crate::ports::{Environment, Policies};

/// The thirty-two characters a code is drawn from.
pub const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// `settings()`'s answer.
#[derive(Debug, Clone, PartialEq)]
pub struct BackupCodeSettings {
    pub enabled: bool,
    pub count: f64,
    pub length: f64,
    pub group_size: f64,
}

impl BackupCodeSettings {
    /// As Node's object.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn to_json(&self) -> Json {
        json!({ "enabled": self.enabled, "count": js::num(self.count),
                "length": js::num(self.length),
                "groupSize": js::num(self.group_size) })
    }
}

/// The mechanism.
pub struct BackupCodes {
    env: Arc<dyn Environment>,
    policies: Arc<dyn Policies>,
}

impl BackupCodes {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(
        env: Arc<dyn Environment>,
        policies: Arc<dyn Policies>,
    ) -> BackupCodes {
        BackupCodes { env, policies }
    }

    /// `settings()`: count 1–50 (10), length 8–32 (10), groupSize 0–16
    /// (5, and a legal zero means unbroken).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn settings(&self) -> BackupCodeSettings {
        let env = &self.env;
        BackupCodeSettings {
            enabled: self.policies.allows("recoveryCode", "second-factor"),
            count: clamp(
                js::number_or_fallback(
                    Some(&env.setting("backupCodes.count")),
                    10.0,
                ),
                1.0,
                50.0,
            ),
            length: clamp(
                js::number_or_fallback(
                    Some(&env.setting("backupCodes.length")),
                    10.0,
                ),
                8.0,
                32.0,
            ),
            group_size: clamp(
                js::number_or(Some(&env.setting("backupCodes.groupSize")), 5.0),
                0.0,
                16.0,
            ),
        }
    }

    /// `offered()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn offered(&self) -> bool {
        self.settings().enabled
    }

    /// `generateCode(length)`: one `crypto.randomInt()` per character.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn generate_code(&self, length: Option<f64>) -> String {
        let want = length
            .filter(|l| *l != 0.0 && !l.is_nan())
            .unwrap_or_else(|| self.settings().length);
        let alphabet = ALPHABET.as_bytes();
        let mut out = String::new();
        let mut i = 0.0;
        while i < want {
            let at = self.env.random_int(0, alphabet.len() as u64) as usize;
            out.push(alphabet[at.min(alphabet.len() - 1)] as char);
            i += 1.0;
        }
        out
    }

    /// `generate({ count, length })`: distinct codes, or none (and
    /// STS-AUTHN-0083 logged) when twenty draws a code could not make them.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn generate(
        &self,
        count: Option<f64>,
        length: Option<f64>,
    ) -> Option<Vec<String>> {
        let live = self.settings();
        let count = max(
            1.0,
            count
                .filter(|c| *c != 0.0 && !c.is_nan())
                .unwrap_or(live.count),
        );
        let length = max(
            8.0,
            length
                .filter(|l| *l != 0.0 && !l.is_nan())
                .unwrap_or(live.length),
        );
        let mut codes: Vec<String> = Vec::new();
        let ceiling = count * 20.0;
        let mut tries = 0.0;
        while (codes.len() as f64) < count && tries < ceiling {
            tries += 1.0;
            let candidate = self.generate_code(Some(length));
            if !codes.contains(&candidate) {
                codes.push(candidate);
            }
        }
        if (codes.len() as f64) < count {
            tracing::error!(
                "{}backup_codes: only {} distinct code(s) could be generated \
                 out of {} asked for, in {} attempt(s). The alphabet or the \
                 length must have been changed to something too small.",
                tag(codes::STS_AUTHN_0083),
                codes.len(),
                js::number_text(count),
                js::number_text(tries)
            );
            return None;
        }
        Some(codes)
    }

    /// `normalise(text)`: upper case, spaces and dashes dropped.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn normalise(text: &str) -> String {
        js::without_spaces_and_dashes(&js::upper(text))
    }

    /// `formatted(code, groupSize)`: dash-separated groups.
    #[tracing::instrument(level = "debug", skip(self, code))]
    pub fn formatted(&self, code: &str, group_size: Option<f64>) -> String {
        let size = group_size.unwrap_or_else(|| self.settings().group_size);
        let chars: Vec<char> = code.chars().collect();
        if size == 0.0
            || size.is_nan()
            || size <= 0.0
            || size >= js::length(code) as f64
        {
            return code.to_string();
        }
        let size = size as usize;
        chars
            .chunks(size)
            .map(|c| c.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join("-")
    }

    /// `matches(presented, stored)`: a LEGACY entry, compared as a string.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn matches(presented: &str, stored: &str) -> bool {
        constant_time_equals(
            BackupCodes::normalise(presented).as_bytes(),
            BackupCodes::normalise(stored).as_bytes(),
        )
    }

    /// `hash(code)`: `crypto.hashSecret()` of the normalised code.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn hash(&self, code: &str) -> String {
        self.env.hash_secret(&BackupCodes::normalise(code))
    }

    /// `matchesHash(presented, storedHash)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn matches_hash(presented: &str, stored: &str) -> bool {
        verify_secret(&BackupCodes::normalise(presented), stored)
    }

    /// `isHash(stored)`: a scrypt form (`$scrypt$`), which is what a set
    /// has been written as since 2026-09-11.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn is_hash(stored: &str) -> bool {
        stored.starts_with("$scrypt$")
    }

    /// `wellFormed(presented)`: non-empty, every character from the
    /// alphabet once normalised — so a password typed into the code box is
    /// refused on its shape and costs no hashing.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn well_formed(presented: &str) -> bool {
        let text = BackupCodes::normalise(presented);
        !text.is_empty() && text.chars().all(|c| ALPHABET.contains(c))
    }
}

fn clamp(v: f64, lo: f64, hi: f64) -> f64 {
    if v.is_nan() {
        return f64::NAN;
    }
    v.min(hi).max(lo)
}

fn max(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.max(b)
    }
}
