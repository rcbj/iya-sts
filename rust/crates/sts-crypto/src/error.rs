// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The one error this crate returns: a sentence a caller can log and refuse
//! with. The Node module throws `Error`s whose messages the callers pass on,
//! so the message is the contract, not a variant.
//!
//! **A CODE RIDES BESIDE THE SENTENCE, NEVER IN IT** (#1368). Where Node
//! marks its `Error` with `errorCodes.mark()` — the signature policy's
//! refusals at the JOSE and COSE chokepoints — the code is the second
//! member, for the caller's audit row and log line. It is never in the
//! message, because callers copy the message into an `error_description`
//! and a code is never sent.

use sts_core::errors::ErrorCode;

/// What went wrong, in words, and the operator's code where Node marks one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct CryptoError(pub String, pub Option<ErrorCode>);

impl CryptoError {
    pub fn new(message: impl Into<String>) -> CryptoError {
        CryptoError(message.into(), None)
    }

    /// A refusal Node marks with a code.
    pub fn coded(message: impl Into<String>, code: ErrorCode) -> CryptoError {
        CryptoError(message.into(), Some(code))
    }

    /// The code Node would have marked, if any.
    pub fn code(&self) -> Option<ErrorCode> {
        self.1
    }
}

impl From<openssl::error::ErrorStack> for CryptoError {
    fn from(stack: openssl::error::ErrorStack) -> CryptoError {
        CryptoError(format!("OpenSSL: {}", stack), None)
    }
}

pub type CryptoResult<T> = Result<T, CryptoError>;
