// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What every crate of the generated API types shares (#444, `rust/DESIGN.md`
//! decision D15).
//!
//! The five documents' types are written across several crates
//! (`planCrates()` in `models/lib/rust_lib.mjs`), because one crate of all
//! of them took a single rustc past 12 GB. This is the crate they all
//! depend on: the unions of scalars the documents share, and
//! [`double_option`], which a member that may be absent or `null` is read
//! and written through. `sts-model` re-exports both, so a caller names them
//! `sts_model::unions` and `sts_model::double_option` as before.
//!
//! `generated/unions.rs` is written by `tests/tools/regenerate-model-docs.sh`
//! and never by hand; `tests/model_domain.js` fails when it differs from
//! what the model makes.

#![forbid(unsafe_code)]

#[rustfmt::skip]
#[allow(clippy::all, clippy::pedantic, missing_docs, non_camel_case_types)]
pub mod unions {
    include!("generated/unions.rs");
}

/// A member that may be absent or `null`, kept as two answers: absent is
/// `None`, `null` is `Some(None)`. Serde reads an absent member through
/// `default` and a present one through here.
pub mod double_option {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Reads a present member: `null` is `Some(None)`.
    ///
    /// A hot path: serde calls it for every such member of every body and
    /// answer read, so it opens no span.
    pub fn deserialize<'de, T, D>(
        deserializer: D,
    ) -> Result<Option<Option<T>>, D::Error>
    where
        T: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        Option::<T>::deserialize(deserializer).map(Some)
    }

    /// Writes a present member; `skip_serializing_if` leaves `None` out.
    ///
    /// A hot path: serde calls it for every such member of every body and
    /// answer written, so it opens no span.
    pub fn serialize<T, S>(
        value: &Option<Option<T>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        T: Serialize,
        S: Serializer,
    {
        match value {
            Some(inner) => inner.serialize(serializer),
            None => serializer.serialize_none(),
        }
    }
}
