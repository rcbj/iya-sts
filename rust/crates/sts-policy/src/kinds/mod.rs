// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The seven kinds, each a module of its own as in Node: they share no
//! field, store or decision, only the shape `password_policy.ts`
//! established (`common`).

pub mod attributes;
pub mod authn;
pub mod common;
pub mod locale;
pub mod passkey;
pub mod password;
pub mod post_login;
pub mod service_account;
