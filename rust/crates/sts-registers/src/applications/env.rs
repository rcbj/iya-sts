// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The register's environment over `sts-core` itself, for the composition
//! root: [`CoreEnv`] reads `config.value()` from [`Settings`], the
//! `mode.js` predicates, `allowsValue()` and `inForce()` from [`Mode`],
//! `parseAs()` from the settings row, the clock from the system and the
//! random and the digest from `sts_crypto`. The key store is not part of
//! `sts-core`: [`CoreEnv`] seals nothing, which is development mode's
//! answer (`keystore.persists()` is false there); product mode's sealing
//! arrives with the key store's port.
//!
//! [`NoEffects`] is the effects port with nobody listening.

use std::sync::Arc;

use serde_json::Value;
use sts_core::errors::ErrorCode;
use sts_core::mode::Mode;
use sts_core::settings::{self, Settings, SettingValue};

use super::{AppEffects, AppEnv};

/// The environment over `sts-core`.
pub struct CoreEnv {
    pub settings: Arc<Settings>,
    pub mode: Arc<Mode>,
}

fn json_of(value: &SettingValue) -> Value {
    match value {
        SettingValue::Text(s) => Value::from(s.as_str()),
        SettingValue::Int(n) => Value::from(*n),
        SettingValue::Bool(b) => Value::from(*b),
        SettingValue::List(l) => Value::from(l.clone()),
    }
}

fn value_of(key: &str, value: &Value) -> Option<SettingValue> {
    settings::row(key).map(|row| row.parse(Some(value)))
}

impl AppEnv for CoreEnv {
    fn now_ms(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    fn setting(&self, key: &str) -> Value {
        json_of(&self.settings.value_of(key))
    }

    fn mode(&self, predicate: &str) -> bool {
        self.mode.predicate(predicate).unwrap_or(false)
    }

    fn parse_as(&self, key: &str, raw: &str) -> Result<Value, String> {
        let Some(row) = settings::row(key) else {
            return Err(format!("{key} is not a setting"));
        };
        let given = Value::from(raw);
        match row.check(&given) {
            Some(problem) => Err(problem),
            None => Ok(json_of(&row.parse(Some(&given)))),
        }
    }

    fn allows_value(&self, key: &str, value: &Value) -> bool {
        value_of(key, value)
            .map(|v| self.mode.allows_value(key, &v))
            .unwrap_or(true)
    }

    fn write_refusal_reason(&self, key: &str) -> String {
        settings::row(key)
            .and_then(|row| row.only_while)
            .map(sts_core::mode::write_refusal_reason)
            .unwrap_or_else(|| sts_core::mode::write_refusal_reason(""))
            .to_string()
    }

    fn random_bytes(&self, n: usize) -> Vec<u8> {
        sts_crypto::random::random_bytes(n).unwrap_or_default()
    }

    fn sha256_hex(&self, text: &str) -> String {
        let Ok(mut d) = sts_crypto::raw_sig::Sha256Digester::new() else {
            return String::new();
        };
        if d.update(text.as_bytes()).is_err() {
            return String::new();
        }
        d.hex().unwrap_or_default()
    }

    fn is_sealed(&self, value: &str) -> bool {
        sts_crypto::secrets::is_encrypted_with_kek(value)
    }

    fn keystore_persists(&self) -> bool {
        false
    }

    fn seals_client_secrets(&self) -> bool {
        false
    }

    fn seal(&self, _text: &str, _label: &str) -> Option<String> {
        None
    }

    fn open(&self, _text: &str, _label: &str) -> Option<String> {
        None
    }

    fn in_force(&self, key: &str, value: &Value) -> Value {
        match value_of(key, value) {
            Some(v) => json_of(&self.mode.in_force(key, v, key)),
            None => value.clone(),
        }
    }
}

/// Nobody listening: the audit rows and signals go nowhere, every other
/// family answers as one that is not loaded.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoEffects;

impl AppEffects for NoEffects {
    fn audit(&self, _row: &Value) {}
    fn failure(&self, _code: ErrorCode, _row: &Value) {}
    fn credential_changed(&self, _notice: &Value) {}
    fn certificate_changed(&self, _notice: &Value) {}
    fn application_removed(&self, _identifier: &str, _dn: &str, _via: &str) {}
    fn end_gnap_grants(&self, _: &str, _: bool, _: &Value) -> i64 {
        0
    }
    fn claims_fan_out(&self, _: &str, _: &str, _: &str, _: &str) {}
    fn scope_kept(&self, _scope: &str, _identifier: &str) -> bool {
        true
    }
    fn certificate_registration_problem(
        &self,
        _usage: &str,
        _der: &[u8],
    ) -> Option<(String, ErrorCode)> {
        None
    }
    fn dial_problem(&self, _url: &str) -> String {
        String::new()
    }
    fn ssf_event_known(&self, _uri: &str) -> bool {
        false
    }
    fn kerberos_accepts_realm(&self, _realm: &str) -> bool {
        false
    }
}
