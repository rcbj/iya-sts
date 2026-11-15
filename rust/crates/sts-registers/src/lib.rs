// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The registers that sit over the directory (#444, phase 4), as the Node
//! service holds them now. Each module names the Node file it ports; the
//! directory, the settings, the audit log and the registers one does not
//! own arrive as ports ([`port`]).

#![forbid(unsafe_code)]

pub mod js;
pub mod port;
pub mod schema;
pub mod outcome;
pub mod roles;
pub mod rbac;
pub mod role_actions;
