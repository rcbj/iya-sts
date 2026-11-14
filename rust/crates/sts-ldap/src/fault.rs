// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What a decoder or encoder gives up with: node-ldapjs's exception, or
//! the loop it never leaves.
//!
//! node-ldapjs throws (an `Error`, a `TypeError` from reading a property
//! of `null`, an `InvalidAsn1Error`), and the server's answer to a thrown
//! decode is to destroy the connection; the text matters only where it is
//! recorded (the DN and filter vectors) or sent (never, for a decode). So
//! a [`Fault::Thrown`] carries V8's sentence, ported where the vectors
//! show it.
//!
//! Several of its loops read a field, find it short, return `null` without
//! advancing, and read it again forever — on Node that wedges the event
//! loop, and with it every connection of every protocol the process
//! serves. Rust never loops: it reports [`Fault::Stalled`] where Node
//! would hang, and the front treats it as a destroyed connection. That
//! difference is deliberate; `tests/node_vectors.rs` pins every case.

use std::fmt;

/// A decode or encode that did not finish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault {
    /// What node-ldapjs throws, with its message.
    Thrown(String),
    /// Where node-ldapjs loops without end.
    Stalled,
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

    /// The message, or `"stalled"`.
    pub fn message(&self) -> &str {
        match self {
            Fault::Thrown(m) => m,
            Fault::Stalled => "stalled",
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

/// How many passes a loop that must consume input may make over a buffer
/// of `size` bytes before it is taken to be Node's endless one. Every pass
/// of a loop that ends reads at least one byte, so a bounded buffer cannot
/// need more than this; a pass that reads nothing, or a field length that
/// sends the offset backwards into a cycle, can.
pub fn pass_limit(size: usize) -> usize {
    size.saturating_mul(4).saturating_add(64)
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
