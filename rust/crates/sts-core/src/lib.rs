// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What every crate shares. Phase 1 needs the log, the clock format and the
//! version; the settings table, the error-code table and the mode predicates
//! arrive in phase 2 (rust/DESIGN.md section 11).

pub mod log;
pub mod time;
pub mod version;
