// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The [`Settings`] port over phase 3's `sts_core::settings::Settings`: the
//! five-level resolution in the ambient realm, each value as the JSON
//! `config.value(key)` answers in Node. A key that is not a row answers
//! `null`, as Node's `config.value()` answers `undefined`.

use serde_json::{json, Value};
use sts_core::settings::{self, SettingValue};

use crate::port::Settings;

impl Settings for settings::Settings {
    #[tracing::instrument(level = "debug", skip(self))]
    fn value(&self, key: &str) -> Value {
        if settings::row(key).is_none() {
            return Value::Null;
        }
        match self.value_of(key) {
            SettingValue::Text(text) => json!(text),
            SettingValue::Int(n) => json!(n),
            SettingValue::Bool(b) => json!(b),
            SettingValue::List(list) => json!(list),
        }
    }
}
