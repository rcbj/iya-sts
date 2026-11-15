// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A refusal, as a handler hands it to `next()`: node-ldapjs's error class
//! (its name and the result code it carries), the sentence that becomes the
//! diagnostic message, and the STS code the refusal is RECORDED under — on
//! the audit row, never on the wire (root `CLAUDE.md`, *Every failure has
//! an error code*).

use sts_core::errors::ErrorCode;
use sts_ldap::result_codes;

/// One refusal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{name}: {message}")]
pub struct LdapError {
    /// The ldapjs class: `NoSuchObjectError`.
    pub name: String,
    /// Its RFC 4511 result code.
    pub result_code: i32,
    /// The diagnostic message.
    pub message: String,
    /// The STS code, where the refusal has one.
    pub code: Option<ErrorCode>,
}

impl LdapError {
    /// `new ldap[name](message)`, recorded under `code`. An empty message
    /// is the class's name, which is what an ldapjs error built with none
    /// says.
    #[tracing::instrument(level = "debug", skip(message))]
    pub fn new(
        name: &str,
        message: impl Into<String>,
        code: Option<ErrorCode>,
    ) -> Self {
        let message = message.into();
        let result_code = result_codes::error_classes()
            .into_iter()
            .find(|c| c.name == name)
            .map(|c| c.code)
            .unwrap_or(1);
        LdapError {
            message: if message.is_empty() {
                name.to_string()
            } else {
                message
            },
            name: name.to_string(),
            result_code,
            code,
        }
    }

    /// The same error recorded under a code.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn coded(mut self, code: ErrorCode) -> Self {
        self.code = Some(code);
        self
    }
}
