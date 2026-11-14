// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The abstract model's data objects, as Rust (#444, `rust/DESIGN.md`
//! decision D15).
//!
//! `models/` (#1390) is the one source of the domain concepts and of every
//! request and answer of the five published APIs. Its build writes them as
//! TypeScript for the Node service and, through `models/lib/rust_lib.mjs`,
//! as the Rust types here, so both implementations are held to one model.
//! The three files under `generated/` are written by
//! `tests/tools/regenerate-model-docs.sh` and never by hand;
//! `tests/model_domain.js` fails when they differ from what the model
//! makes.
//!
//! * [`domain`]: a struct per concept, and where each field comes from.
//! * [`api`]: a module per document, and in it a module per operation with
//!   its `METHOD`, `PATH`, `OPERATION_ID`, `Body`, `Query` and `AnswerNNN`.
//! * [`unions`]: the unions of scalars the documents share.
//!
//! The types carry shapes, not rules: a value's bounds, patterns and
//! formats are checked against the served document at runtime, as Node
//! checks them (#1353).

#![forbid(unsafe_code)]

#[rustfmt::skip]
#[allow(clippy::all, clippy::pedantic, missing_docs, non_camel_case_types)]
pub mod domain {
    include!("generated/domain.rs");
}

#[rustfmt::skip]
#[allow(clippy::all, clippy::pedantic, missing_docs, non_camel_case_types)]
pub mod api {
    include!("generated/api.rs");
}

#[rustfmt::skip]
#[allow(clippy::all, clippy::pedantic, missing_docs, non_camel_case_types)]
pub mod unions {
    include!("generated/unions.rs");
}

/// What a domain concept is made from: the directory entry it reads, or the
/// record (named for the function that writes it) it is a view of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MadeFrom {
    Entry(&'static str),
    Record(&'static str),
}

/// Where one field of a concept comes from, as `DomainMap` reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldSource {
    /// The field's name in the model.
    pub name: &'static str,
    /// The directory attribute it is read from.
    pub attribute: Option<&'static str>,
    /// The entry the attribute is on, when it is not the concept's own.
    pub on: Option<&'static str>,
    /// The record member it is read from.
    pub key: Option<&'static str>,
    /// The transform applied to what is read, by name.
    pub transform: Option<&'static str>,
    /// Whether it holds a secret, left out unless a caller names it.
    pub secret: bool,
    /// Whether the service derives it rather than reading it.
    pub derived: bool,
    /// Whether it is another concept embedded in this one.
    pub embedded: bool,
}

/// A member that may be absent or `null`, kept as two answers: absent is
/// `None`, `null` is `Some(None)`. Serde reads an absent member through
/// `default` and a present one through here.
pub mod double_option {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Reads a present member: `null` is `Some(None)`.
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
