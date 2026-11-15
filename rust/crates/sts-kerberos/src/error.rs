// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The codec's one error: a sentence, exactly as Node's `Error.message`
//! reads, because a caller (the KDC's `e-text`, the KDC proxy's 400 body,
//! a debugger page) shows it, and parity is the sentence as well as the
//! verdict.

/// A codec failure, carrying Node's message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Krb5Error(pub String);

/// The codec's result.
pub type Krb5Result<T> = Result<T, Krb5Error>;

impl Krb5Error {
    /// An error with this message.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(message: impl Into<String>) -> Self {
        Krb5Error(message.into())
    }

    /// What Node throws when a REQUIRED field is absent and the reader
    /// dereferences it: a JavaScript `TypeError`, not a sentence of the
    /// codec's own. Node's readers index the field map and hand the
    /// result on, so a missing field is `undefined` and the first
    /// property read off it names itself — `tag` for the primitive
    /// decoders, `value` for the structure readers. Ported as the message
    /// it is, because it is what the KDC proxy answers in development
    /// (`the KDC-PROXY-MESSAGE does not decode: …`).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn missing(property: &str) -> Self {
        Krb5Error(format!(
            "Cannot read properties of undefined (reading '{}')",
            property
        ))
    }

    /// The message.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl From<sts_crypto::CryptoError> for Krb5Error {
    fn from(e: sts_crypto::CryptoError) -> Self {
        Krb5Error(e.to_string())
    }
}
