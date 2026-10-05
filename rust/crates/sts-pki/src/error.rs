// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The one error type: a sentence, as Node's `Error` carries one. The
//! callers that report it to an operator report the text, so the text is
//! Node's.

use sts_crypto::error::CryptoError;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct PkiError(pub String);

impl PkiError {
    pub fn new(message: impl Into<String>) -> PkiError {
        PkiError(message.into())
    }
}

impl From<CryptoError> for PkiError {
    fn from(e: CryptoError) -> PkiError {
        PkiError(e.0)
    }
}

impl From<openssl::error::ErrorStack> for PkiError {
    fn from(e: openssl::error::ErrorStack) -> PkiError {
        PkiError(e.to_string())
    }
}

pub type PkiResult<T> = Result<T, PkiError>;
