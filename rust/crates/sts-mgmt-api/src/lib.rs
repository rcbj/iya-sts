// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `/admin-api` (`mgmt-api/admin_api.ts`), ported a piece at a time (#444).
//!
//! * [`gate`] — the access-token half of the gate every operation sits
//!   behind, for the SERVICE credential: everything from "is there a token"
//!   to its sender constraints. The scope and role steps after it need the
//!   application and role registers and arrive with them.

#![forbid(unsafe_code)]

pub mod gate;
