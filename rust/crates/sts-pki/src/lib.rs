// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The certificate authority (#444 phase 2, rust/DESIGN.md).
//!
//! [`x509`] is the parent project's `common/vendored/x509.js` — authoring a
//! certificate or a PKCS#10 request with every extension that module
//! writes, reading one back, and checking a chain — with the encoding held
//! to Node's byte for byte by `tests/x509_vectors.rs`. `common/pki.js`, the
//! hierarchy this service keeps on top of it, follows.

#![forbid(unsafe_code)]

pub mod der;
pub mod error;
pub mod foreign;
pub mod path;
pub mod x509;

pub use error::{PkiError, PkiResult};
