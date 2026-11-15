// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The certificate authority (#444 phase 2, rust/DESIGN.md).
//!
//! [`x509`] is `common/crypto_impl/x509.js` (the parent project's copy until
//! #1280, this service's own since) — authoring a certificate or a PKCS#10
//! request with every extension that module writes, reading one back, and
//! checking a chain — with the encoding held to Node's byte for byte by
//! `tests/x509_vectors.rs`. [`fields`] is `common/crypto.js` section 18 and
//! [`path`] the RFC 5280 rules of `common/pki.js` with #1360's and #1368's
//! additions, the pure half of the one validation door
//! (`tests/door_vectors.rs`, `tests/limbo_vectors.rs`). `common/pki.js`, the
//! hierarchy this service keeps on top of it, follows.

#![forbid(unsafe_code)]

pub mod attestation;
pub mod authority;
pub mod der;
pub mod error;
pub mod fields;
pub mod foreign;
pub mod listener;
pub mod path;
pub mod x509;

pub use error::{PkiError, PkiResult};
