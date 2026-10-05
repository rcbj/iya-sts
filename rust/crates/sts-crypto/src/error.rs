// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The one error this crate returns: a sentence a caller can log and refuse
//! with. The Node module throws `Error`s whose messages the callers pass on,
//! so the message is the contract, not a variant.

/// What went wrong, in words.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct CryptoError(pub String);

impl CryptoError {
    pub fn new(message: impl Into<String>) -> CryptoError {
        CryptoError(message.into())
    }
}

impl From<openssl::error::ErrorStack> for CryptoError {
    fn from(stack: openssl::error::ErrorStack) -> CryptoError {
        CryptoError(format!("OpenSSL: {}", stack))
    }
}

pub type CryptoResult<T> = Result<T, CryptoError>;
