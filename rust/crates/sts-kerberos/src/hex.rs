// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! How a decoded structure's bytes serialize: lowercase hex. The decoded
//! structures serialize to the shape Node's readers return (camelCase
//! keys, `null` for an absent optional field), with bytes as hex and times
//! as ISO 8601, which is the form the parity vectors compare.

use serde::Serializer;

/// Lowercase hex of some bytes.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(b"0123456789abcdef"[usize::from(b >> 4)]));
        out.push(char::from(b"0123456789abcdef"[usize::from(b & 15)]));
    }
    out
}

pub fn ser<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&encode(bytes))
}

pub fn opt<S: Serializer>(
    bytes: &Option<Vec<u8>>,
    s: S,
) -> Result<S::Ok, S::Error> {
    match bytes {
        Some(b) => s.serialize_str(&encode(b)),
        None => s.serialize_none(),
    }
}
