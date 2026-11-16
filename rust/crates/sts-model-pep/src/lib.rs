// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The remote PEP's requests and answers, as Rust data types (#1830).
//!
//! `models/pep/` is the TypeSpec source of every HTTP surface the remote PEP
//! serves or calls; `models/tools/generate_pep.mjs` writes an OpenAPI 3.1
//! document per surface to `xacml-pep/openapi/` and these types to
//! `src/generated/`, through the Rust conversion's renderer
//! (`models/lib/rust_lib.mjs`, #444 D15), so a member is read here by the
//! same rules the runtime's model crates read one:
//!
//! * a member the schema does not require is an `Option`, and one that may
//!   also be `null` an `Option<Option<_>>` read through [`double_option`],
//!   so absent and `null` stay two answers;
//! * a closed object refuses a member it does not name
//!   (`deny_unknown_fields`); an open one keeps the rest in `extra`;
//! * a union of scalars is one of [`unions`], named by its kinds.
//!
//! Each document is a module, each operation a module inside it named by its
//! operationId, holding `METHOD`, `PATH`, `OPERATION_ID` and its `Body`,
//! `Query` and `AnswerNNN` types; each document module also has
//! `read_body()` and `read_answer()`, which read a JSON value as an
//! operation's body or answer by operationId.
//!
//! This crate is written for the PEP and depends on no other crate of the
//! service: the PEP is a container of its own (`xacml-pep/CLAUDE.md`). The
//! files under `src/generated/` are written by
//! `tests/tools/regenerate-pep-model.sh` and never by hand;
//! `tests/model_pep.js` fails when one differs from what the model makes,
//! and when a module below is missing for a file it writes.

#![forbid(unsafe_code)]

/// The unions of scalars the PEP's documents use, each an untagged enum
/// named by its kinds.
#[rustfmt::skip]
#[allow(clippy::all, clippy::pedantic, missing_docs, non_camel_case_types, unused_variables)]
pub mod unions {
    include!("generated/unions.rs");
}

/// The PEP's own listener: its status, health, demonstration decision, the
/// policy nudge and its credential's CRLs.
#[rustfmt::skip]
#[allow(clippy::all, clippy::pedantic, missing_docs, non_camel_case_types, unused_variables)]
pub mod pep_service {
    include!("generated/pep_service.rs");
}

/// The AuthZEN edge PDP the PEP answers on its HTTPS listener (#1179).
#[rustfmt::skip]
#[allow(clippy::all, clippy::pedantic, missing_docs, non_camel_case_types, unused_variables)]
pub mod pep_authzen {
    include!("generated/pep_authzen.rs");
}

/// The paths the reverse proxy owns whatever it is configured with (#1760):
/// the sign-in callback, sign-out, the account chooser and the logo.
#[rustfmt::skip]
#[allow(clippy::all, clippy::pedantic, missing_docs, non_camel_case_types, unused_variables)]
pub mod pep_proxy {
    include!("generated/pep_proxy.rs");
}

/// The control plane: what the identity service serves for a remote PEP
/// under `/xacml/pep/` and at `/xacml/pip`, which the PEP calls.
#[rustfmt::skip]
#[allow(clippy::all, clippy::pedantic, missing_docs, non_camel_case_types, unused_variables)]
pub mod pep_control_plane {
    include!("generated/pep_control_plane.rs");
}

/// A member that may be absent or `null`, kept as two answers: absent is
/// `None`, `null` is `Some(None)`. Serde reads an absent member through
/// `default` and a present one through here. The same as `sts-model-base`'s
/// (#444), which this crate does not depend on.
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
