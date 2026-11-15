// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What a decoder or encoder gives up with: node-ldapjs's exception.
//!
//! node-ldapjs throws (an `Error`, a `TypeError` from reading a property
//! of `null`, an `InvalidAsn1Error`), and the server's answer to a thrown
//! decode is to destroy the connection; the text matters only where it is
//! recorded (the DN and filter vectors) or sent (never, for a decode). So
//! a [`Fault::Thrown`] carries V8's sentence, ported where the vectors
//! show it.
//!
//! Every SEQUENCE OF it reads is a `while (ber.offset < end)` loop over a
//! length the peer sent, and a read that cannot be satisfied answers
//! `null` without moving. Until the `rcbj/node-ldapjs` fork's fix (#1784)
//! such a loop read the same bytes for ever, which wedged the whole Node
//! process, and this crate answered a `Stalled` fault there instead. The
//! fork now throws when an iteration does not advance — [`advanced`] —
//! so Rust and Node agree again: the connection is destroyed.
//!
//! Its functions are a hot path — every refusal of every decode — and
//! carry no span (rust/DESIGN.md D3, section 4.5).

use std::fmt;

/// A decode or encode that did not finish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault {
    /// What node-ldapjs throws, with its message.
    Thrown(String),
}

impl Fault {
    /// A thrown `Error` with this message.
    pub fn thrown(message: impl Into<String>) -> Fault {
        Fault::Thrown(message.into())
    }

    /// V8's `TypeError` for reading `property` of `null`.
    pub fn null_read(property: &str) -> Fault {
        Fault::Thrown(format!(
            "Cannot read properties of null (reading '{property}')"
        ))
    }

    /// V8's `TypeError` for reading `property` of `undefined`.
    pub fn undefined_read(property: &str) -> Fault {
        Fault::Thrown(format!(
            "Cannot read properties of undefined (reading '{property}')"
        ))
    }

    /// The message.
    pub fn message(&self) -> &str {
        match self {
            Fault::Thrown(m) => m,
        }
    }
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for Fault {}

/// What a decoder answers.
pub type Outcome<T> = Result<T, Fault>;

/// The fork's guard on a SEQUENCE OF loop (`iya-sts:` in
/// `node-ldapjs/packages/*`): an iteration that left the offset at or
/// before `before` is malformed BER, `Error('malformed <what> at offset
/// <before>')`. Every such loop calls this after its read, as Node does.
pub fn advanced(after: i64, before: i64, what: &str) -> Outcome<()> {
    if after <= before {
        return Err(Fault::thrown(format!(
            "malformed {what} at offset {before}"
        )));
    }
    Ok(())
}

/// How deep a filter may nest before Rust refuses it. Node recurses until
/// V8's stack runs out (about ten thousand frames) and throws `RangeError`;
/// Rust's stack would overflow first and abort the process, so the bound
/// is explicit and lower. No client sends a filter a thousand levels deep.
pub const MAX_FILTER_DEPTH: usize = 1000;

/// The message V8 gives a stack exhausted by recursion.
pub fn too_deep() -> Fault {
    Fault::thrown("Maximum call stack size exceeded")
}
