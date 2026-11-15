// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! STUB (to be ported): the value checks of `common/applications.js`.

#![allow(unused_variables)]

use serde_json::Value;
use sts_core::errors::ErrorCode;

use crate::applications::{ApplicationRegistry, Fields, Record};

/// `statedConfidential(value)`: 'TRUE', 'FALSE' or '' for neither.
#[tracing::instrument(level = "debug")]
pub fn stated_confidential(value: &str) -> String {
    String::new()
}

/// `confidentialDisagreement(raw, determination)`: '' when they agree.
#[tracing::instrument(level = "debug")]
pub fn confidential_disagreement(raw: &str, determination: &str) -> String {
    String::new()
}

/// `canonicalResponseType(value)`.
#[tracing::instrument(level = "debug")]
pub fn canonical_response_type(value: &str) -> String {
    value.to_string()
}
