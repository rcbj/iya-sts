// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! XML for the service: a namespace-aware mutable DOM ([`dom`]) and Canonical
//! XML 1.0 in both forms ([`c14n`]) — what the SAML, WS-Trust, WS-Federation
//! and XML-security code is written over (rust/DESIGN.md section 6). No I/O.

#![forbid(unsafe_code)]

pub mod c14n;
pub mod dom;

pub use dom::{Document, NodeId, NodeKind, XmlError, XmlResult};
