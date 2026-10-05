// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Certificate paths from authorities this service does not keep (`pki.js`'s
//! "SOMEBODY ELSE'S CERTIFICATES" and "RFC 5280 SECTION 6.1, ONCE"): the
//! facts of a certificate, the one set of rules every path is held to, and
//! the builder. Held to Node's verdict on every C2SP x509-limbo case by
//! `tests/limbo_vectors.rs`.

pub mod build;
pub mod entry;
pub mod facts;
pub mod rules;

pub use build::{
    verify_issued_directly, verify_path_to_anchors, PathOptions, PathVerdict,
};
pub use entry::Entry;
