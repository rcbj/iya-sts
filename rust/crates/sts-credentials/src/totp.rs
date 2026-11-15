// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The authenticator app as a MECHANISM: a port of `common/totp.ts`
//! (RFC 6238 over `crypto.hotpCode()`, the `otpauth://` Key Uri Format,
//! and the settings that shape both). Where the enrolment LIVES — the
//! pending record, the sealed secret on the entry, the spent step — is the
//! store's, [`crate::credentials`], exactly the split Node keeps.
//!
//! The QR code (`qrSvgDataUri()`) is the screen's and is not here.

use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_core::errors::codes;
use sts_core::log::tag;
use sts_crypto::secrets::{constant_time_equals, hotp_code, HOTP_ALGS};

use crate::js;
use crate::ports::{Environment, Policies};
use crate::Verdict;

/// RFC 4648's base32 alphabet, as the Key Uri Format expects.
pub const BASE32_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// `settings()`'s answer.
#[derive(Debug, Clone, PartialEq)]
pub struct TotpSettings {
    pub enabled: bool,
    pub issuer: String,
    pub algorithm: String,
    pub digits: f64,
    pub period: f64,
    pub window: f64,
    pub secret_bytes: f64,
    pub enrolment_ttl_ms: f64,
}

impl TotpSettings {
    /// As Node's object.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn to_json(&self) -> Json {
        json!({
            "enabled": self.enabled,
            "issuer": self.issuer,
            "algorithm": self.algorithm,
            "digits": js::num(self.digits),
            "period": js::num(self.period),
            "window": js::num(self.window),
            "secretBytes": js::num(self.secret_bytes),
            "enrolmentTtlMs": js::num(self.enrolment_ttl_ms),
        })
    }
}

/// The mechanism.
pub struct Totp {
    env: Arc<dyn Environment>,
    policies: Arc<dyn Policies>,
}

impl Totp {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(env: Arc<dyn Environment>, policies: Arc<dyn Policies>) -> Totp {
        Totp { env, policies }
    }

    /// `base32Encode()`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn base32_encode(bytes: &[u8]) -> String {
        let alphabet = BASE32_ALPHABET.as_bytes();
        let mut bits = 0u32;
        let mut value = 0u64;
        let mut out = String::new();
        for b in bytes {
            value = ((value << 8) | u64::from(*b)) & 0xffff_ffff;
            bits += 8;
            while bits >= 5 {
                out.push(
                    alphabet[((value >> (bits - 5)) & 31) as usize] as char,
                );
                bits -= 5;
            }
        }
        if bits > 0 {
            out.push(alphabet[((value << (5 - bits)) & 31) as usize] as char);
        }
        out
    }

    /// `base32Decode()`: upper-cased, spaces, dashes and trailing `=`
    /// dropped; a character outside the alphabet is an error with Node's
    /// sentence.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn base32_decode(text: &str) -> Result<Vec<u8>, String> {
        let upper = js::upper(text);
        let cleaned = js::without_spaces_and_dashes(&upper);
        let cleaned = cleaned.trim_end_matches('=');
        let mut bits = 0u32;
        let mut value = 0u64;
        let mut out = Vec::new();
        for c in cleaned.chars() {
            let Some(index) = BASE32_ALPHABET.find(c) else {
                return Err(format!(
                    "\"{c}\" is not a base32 character. A shared secret is \
                     the letters A to Z and the digits 2 to 7."
                ));
            };
            value = ((value << 5) | index as u64) & 0xffff_ffff;
            bits += 5;
            if bits >= 8 {
                out.push(((value >> (bits - 8)) & 255) as u8);
                bits -= 8;
            }
        }
        Ok(out)
    }

    /// `grouped()`: fours, for a person typing the secret by hand.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn grouped(secret: &str) -> String {
        let chars: Vec<char> = secret.chars().collect();
        let mut out = String::new();
        let mut i = 0;
        while i + 4 <= chars.len() {
            out.extend(&chars[i..i + 4]);
            out.push(' ');
            i += 4;
        }
        out.extend(&chars[i..]);
        js::trim(&out).to_string()
    }

    /// `settings()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn settings(&self) -> TotpSettings {
        let env = &self.env;
        let algorithm = js::upper(&js::string_or(
            Some(&env.setting("totp.algorithm")),
            "SHA1",
        ));
        let algorithm = if HOTP_ALGS.contains(&algorithm.as_str()) {
            algorithm
        } else {
            "SHA1".to_string()
        };
        let digits =
            js::number_or_fallback(Some(&env.setting("totp.digits")), 6.0);
        let period =
            js::number_or_fallback(Some(&env.setting("totp.period")), 30.0);
        let window = js::number_or(Some(&env.setting("totp.window")), 1.0);
        let secret_bytes = js::number_or_fallback(
            Some(&env.setting("totp.secretBytes")),
            20.0,
        );
        let ttl = js::number_or_fallback(
            Some(&env.setting("totp.enrolmentTtlMinutes")),
            10.0,
        );
        TotpSettings {
            enabled: self.policies.allows("totp", "second-factor"),
            issuer: js::trim(&js::string_or(
                Some(&env.setting("totp.issuer")),
                "",
            ))
            .to_string(),
            algorithm,
            digits: clamp(digits, 6.0, 8.0),
            period: clamp(period, 15.0, 300.0),
            window: clamp(window, 0.0, 10.0),
            secret_bytes: clamp(secret_bytes, 16.0, 64.0),
            enrolment_ttl_ms: max(1.0, ttl) * 60.0 * 1000.0,
        }
    }

    /// `offered()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn offered(&self) -> bool {
        self.settings().enabled
    }

    /// `generateSecret()`: `secretBytes` random bytes, in base32.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn generate_secret(&self, bytes: Option<f64>) -> String {
        let n = bytes
            .filter(|b| *b != 0.0 && !b.is_nan())
            .unwrap_or_else(|| self.settings().secret_bytes);
        Totp::base32_encode(&self.env.random_bytes(n as usize))
    }

    /// `counterAt(at, period)`.
    #[tracing::instrument(level = "debug")]
    pub fn counter_at(at: f64, period: f64) -> f64 {
        (at / 1000.0 / period).floor()
    }

    /// `codeAt(secret, at, opts)`: the code an app shows at `at`.
    #[tracing::instrument(level = "debug", skip(self, secret))]
    pub fn code_at(
        &self,
        secret: &str,
        at: Option<f64>,
        period: Option<f64>,
        digits: Option<f64>,
        algorithm: Option<&str>,
    ) -> Result<String, String> {
        let period = period
            .filter(|p| *p != 0.0 && !p.is_nan())
            .unwrap_or_else(|| self.settings().period);
        let at = at
            .filter(|a| *a != 0.0 && !a.is_nan())
            .unwrap_or_else(|| self.env.now_ms());
        let counter = Totp::counter_at(at, period);
        hotp(&Totp::base32_decode(secret)?, counter, digits, algorithm)
    }

    /// `verify(record, presented, { at, window })`: the shape, the
    /// comparison across the window (every step computed, so the time taken
    /// does not say which matched), and the spent step. A verdict with
    /// STS-AUTHN-0103 (shape), 0104 (the stored secret), 0105 (mismatch) or
    /// 0106 (replay). `Err` where Node THROWS: a stored secret that decodes
    /// to nothing, or an algorithm `crypto.hotpCode()` does not know.
    #[tracing::instrument(level = "debug", skip(self, record, presented))]
    pub fn verify(
        &self,
        record: &Json,
        presented: &Json,
        at: Option<f64>,
        window: Option<&Json>,
    ) -> Result<Verdict, String> {
        let now = at
            .filter(|a| *a != 0.0 && !a.is_nan())
            .unwrap_or_else(|| self.env.now_ms());
        let live = || self.settings();
        let digits = match record.get("digits").filter(|v| js::truthy(v)) {
            Some(v) => js::number(v),
            None => live().digits,
        };
        let period = match record.get("period").filter(|v| js::truthy(v)) {
            Some(v) => js::number(v),
            None => live().period,
        };
        let algorithm = match record.get("algorithm").filter(|v| js::truthy(v))
        {
            Some(v) => js::string(v),
            None => live().algorithm,
        };
        let window = match window {
            None => live().window,
            Some(w) => max(0.0, js::number(w)),
        };
        let code = js::without_spaces_and_dashes(&match presented {
            Json::Null => String::new(),
            other => js::string(other),
        });
        if code.is_empty()
            || !code.chars().all(|c| c.is_ascii_digit())
            || (code.len() as f64) != digits
        {
            return Ok(Verdict::coded(
                codes::STS_AUTHN_0103,
                json!({ "ok": false, "reason": "shape",
                    "detail": format!("A code is {} digits.",
                                      js::number_text(digits)) }),
            ));
        }
        let secret = match Totp::base32_decode(&js::string_or_empty(
            record.get("secret"),
        )) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(
                    "{}totp: the stored secret could not be decoded: {}",
                    tag(codes::STS_AUTHN_0104),
                    e
                );
                return Ok(Verdict::coded(
                    codes::STS_AUTHN_0104,
                    json!({ "ok": false, "reason": "store",
                        "detail": "The stored shared secret could not be \
                                   read." }),
                ));
            }
        };
        let centre = Totp::counter_at(now, period);
        let mut matched: Option<(f64, f64)> = None;
        let mut drift = -window;
        while drift <= window {
            let counter = centre + drift;
            if counter >= 0.0 {
                let candidate =
                    hotp(&secret, counter, Some(digits), Some(&algorithm))?;
                if constant_time_equals(candidate.as_bytes(), code.as_bytes())
                    && matched.is_none()
                {
                    matched = Some((counter, drift));
                }
            }
            drift += 1.0;
        }
        let Some((counter, drift)) = matched else {
            return Ok(Verdict::coded(
                codes::STS_AUTHN_0105,
                json!({ "ok": false, "reason": "mismatch",
                    "detail": "That code is not right, or it has \
                               expired." }),
            ));
        };
        let spent = js::number_or_fallback(record.get("lastCounter"), 0.0);
        if spent != 0.0 && !spent.is_nan() && counter <= spent {
            tracing::info!(
                "totp: a code was refused as already spent (step {}, last \
                 accepted {}).",
                js::number_text(counter),
                js::number_text(spent)
            );
            return Ok(Verdict::coded(
                codes::STS_AUTHN_0106,
                json!({ "ok": false, "reason": "replay",
                    "counter": js::num(counter),
                    "detail": "That code has already been used. Wait for \
                               your authenticator to show the next one." }),
            ));
        }
        Ok(Verdict::of(
            json!({ "ok": true, "counter": js::num(counter),
                               "drift": js::num(drift) }),
        ))
    }

    /// `issuerFor(base)`: `totp.issuer`, else the host of the base URL
    /// with the realm's id in brackets.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn issuer_for(&self, base: &str) -> String {
        let configured = self.settings().issuer;
        if !configured.is_empty() {
            return configured;
        }
        let lower = base.to_ascii_lowercase();
        let rest = if lower.starts_with("https://") {
            &base[8..]
        } else if lower.starts_with("http://") {
            &base[7..]
        } else {
            base
        };
        let host = rest.split('/').next().unwrap_or("");
        let host = if host.is_empty() { "IYA STS" } else { host };
        let id = self.env.realm_id();
        if id.is_empty() {
            host.to_string()
        } else {
            format!("{host} ({id})")
        }
    }

    /// `otpauthUri(spec)`: the Key Uri Format.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn otpauth_uri(
        issuer: &str,
        account: &str,
        secret: &str,
        algorithm: &str,
        digits: f64,
        period: f64,
    ) -> String {
        let issuer = if issuer.is_empty() { "IYA STS" } else { issuer };
        let account = if account.is_empty() { "user" } else { account };
        let label = format!(
            "{}:{}",
            encode_uri_component(issuer),
            encode_uri_component(account)
        );
        let algorithm = if algorithm.is_empty() {
            "SHA1"
        } else {
            algorithm
        };
        let digits = if digits == 0.0 || digits.is_nan() {
            6.0
        } else {
            digits
        };
        let period = if period == 0.0 || period.is_nan() {
            30.0
        } else {
            period
        };
        format!(
            "otpauth://totp/{label}?secret={}&issuer={}&algorithm={}&\
             digits={}&period={}",
            secret.trim_end_matches('='),
            encode_uri_component(issuer),
            algorithm,
            js::number_text(digits),
            js::number_text(period)
        )
    }
}

fn hotp(
    key: &[u8],
    counter: f64,
    digits: Option<f64>,
    algorithm: Option<&str>,
) -> Result<String, String> {
    let digits = digits.map(|d| clamp(d, 6.0, 10.0) as u32);
    hotp_code(key, counter as u64, digits, algorithm).map_err(|e| e.to_string())
}

fn clamp(v: f64, lo: f64, hi: f64) -> f64 {
    max(lo, min(hi, v))
}

/// `Math.max`, which answers NaN for a NaN.
fn max(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.max(b)
    }
}

/// `Math.min`, the same.
fn min(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.min(b)
    }
}

/// `encodeURIComponent()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn encode_uri_component(text: &str) -> String {
    let mut out = String::new();
    for b in text.as_bytes() {
        let c = *b as char;
        if c.is_ascii_alphanumeric()
            || matches!(c, '-' | '_' | '.' | '!' | '~' | '*' | '\'' | '(' | ')')
        {
            out.push(c);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
