// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! An attribute and a modification as `@ldapjs/attribute` 1.0.0 and
//! `@ldapjs/change` 1.0.0 hold them.
//!
//! An attribute keeps its values as BYTES; its string values are those
//! bytes as UTF-8, or as base64 when the type ends `;binary` (case
//! sensitive — `;Binary` is UTF-8), and a string value given to it is
//! turned into bytes the same way. That matters twice on the wire:
//!
//! * an add request keeps the bytes the client sent (and lowercases the
//!   type), but a modify request's changes pass through the string values
//!   and back (`Change.fromBer()` → `pojo` → `new Change()`), so a value
//!   that is not UTF-8 reaches the handler — and is re-encoded — with
//!   each bad sequence as U+FFFD;
//! * a search entry the service sends with a `…;binary` attribute writes
//!   the base64-DECODED value, decoded as Node decodes it.
//!
//! Its functions are a hot path — every attribute of every add, modify and
//! entry — and carry no span (rust/DESIGN.md D3, section 4.5).

use crate::ber::{Reader, Writer};
use crate::fault::{pass_limit, Fault, Outcome};
use crate::js;

/// An attribute: a type and its values' bytes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Attribute {
    pub attr_type: String,
    pub buffers: Vec<Vec<u8>>,
}

fn is_binary(t: &str) -> bool {
    t.ends_with(";binary")
}

impl Attribute {
    /// `new Attribute({ type, values })` with string values.
    pub fn from_strings(attr_type: &str, values: &[String]) -> Attribute {
        let buffers = values
            .iter()
            .map(|v| {
                if is_binary(attr_type) {
                    js::base64_decode(v)
                } else {
                    v.as_bytes().to_vec()
                }
            })
            .collect();
        Attribute {
            attr_type: attr_type.to_string(),
            buffers,
        }
    }

    /// The `values` getter.
    pub fn values(&self) -> Vec<String> {
        self.buffers
            .iter()
            .map(|b| {
                if is_binary(&self.attr_type) {
                    js::base64_encode(b)
                } else {
                    js::utf8(b)
                }
            })
            .collect()
    }

    /// `Attribute.fromBer()`.
    pub fn read(ber: &mut Reader<'_>) -> Outcome<Attribute> {
        ber.read_sequence(None)?;
        let attr_type = ber.read_string(0x04)?.unwrap_or_default();
        let mut buffers = Vec::new();
        if ber.peek() == Some(0x31) && ber.read_sequence(Some(0x31))?.is_some() {
            let end = ber.offset() + ber.length();
            let limit = pass_limit(ber.buffer().len());
            while ber.offset() < end {
                if buffers.len() > limit {
                    return Err(Fault::Stalled);
                }
                match ber.read_bytes(0x04)? {
                    Some(b) => buffers.push(b),
                    // `readString` answered null without moving: Node
                    // reads the same bytes again for ever.
                    None => return Err(Fault::Stalled),
                }
            }
        }
        Ok(Attribute { attr_type, buffers })
    }

    /// `attribute.toBer()`.
    pub fn to_ber(&self) -> Outcome<Vec<u8>> {
        let mut w = Writer::new();
        w.start_sequence(0x30);
        w.write_string(&self.attr_type, 0x04)?;
        w.start_sequence(0x31);
        for b in &self.buffers {
            w.write_byte(0x04);
            w.write_length(b.len())?;
            w.append(b);
        }
        w.end_sequence()?;
        w.end_sequence()?;
        Ok(w.into_bytes())
    }
}

/// A modification: `add`, `delete` or `replace` (0, 1, 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub operation: u8,
    pub modification: Attribute,
}

impl Change {
    pub fn operation_name(&self) -> &'static str {
        match self.operation {
            0 => "add",
            1 => "delete",
            _ => "replace",
        }
    }

    /// `Change.fromBer()`, and then the trip through `pojo` that
    /// `ModifyRequest.parseToPojo()` makes: the values become strings and
    /// the strings become bytes again.
    pub fn read(ber: &mut Reader<'_>) -> Outcome<Change> {
        ber.read_sequence(None)?;
        let op = ber.read_enumeration()?;
        let modification = Attribute::read(ber)?;
        if !(0..=2).contains(&op) {
            return Err(Fault::thrown(format!(
                "invalid operation type: 0x{}",
                js::hex_js(i64::from(op))
            )));
        }
        let values = modification.values();
        Ok(Change {
            operation: op as u8,
            modification: Attribute::from_strings(&modification.attr_type, &values),
        })
    }

    /// `change.toBer()`.
    pub fn to_ber(&self) -> Outcome<Vec<u8>> {
        let mut w = Writer::new();
        w.start_sequence(0x30);
        w.write_enumeration(i32::from(self.operation));
        w.append(&self.modification.to_ber()?);
        w.end_sequence()?;
        Ok(w.into_bytes())
    }
}
