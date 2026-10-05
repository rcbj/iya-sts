// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What every crate shares: the log, the clock format, the version, the
//! error codes, the settings and the mode. Crypto and PKI are phase 2's next
//! (rust/DESIGN.md section 11).

#![forbid(unsafe_code)]

pub mod errors;
pub mod log;
pub mod mode;
pub mod settings;
pub mod time;
pub mod version;
