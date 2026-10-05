// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Every signing, encryption and key algorithm this service offers — a port
//! of `common/crypto.js` and the modules under it (rust/DESIGN.md section
//! 6), over OpenSSL. A LEAF: no I/O, no settings, no mode; a policy that
//! differs by mode arrives as an argument.

#![deny(unsafe_code)]

pub mod b64;
pub mod error;
pub mod hpke;
pub mod jwe;
pub mod jws;
pub mod jws_alg;
pub mod keys;
pub mod pq;

pub use error::{CryptoError, CryptoResult};
