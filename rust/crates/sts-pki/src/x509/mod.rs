// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! X.509 certificates: authoring one, describing one, checking a chain —
//! the parent project's `common/vendored/x509.js`, whose output this is
//! held to byte for byte.

pub mod algorithms;
pub mod extensions;
pub mod issue;
pub mod js;
pub mod keys;
pub mod names;
pub mod read;
pub mod time;

pub use algorithms::{sig_alg, SigAlg, SigKind};
pub use issue::{
    certification_request, issue_certificate, CertificationRequest,
    IssuedCertificate,
};
pub use read::{describe_certificate, verify_chain, Certificate};
