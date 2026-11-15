// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `/admin-api` (`mgmt-api/admin_api.ts`): the framework every operation
//! sits in, and the setup operations (#444, phase 4).
//!
//! * [`operations`] — every operation of the model, generated; [`routing`]
//!   binds each to a handler or names it as not yet ported, exhaustively,
//!   and `build.rs` refuses a routing row the model does not have.
//! * [`document`] — the two documents served as the model generates them.
//! * [`request`], [`schema`] — what a request may name and hold, with
//!   Node's refusals and ajv's words.
//! * [`answer`] — every answer held to its closed model (#1353).
//! * [`gate`] — the access-token gate, whole.
//! * [`config_view`], [`setup`] — the configuration, mode, realm and status
//!   operations over `sts-core`.
//! * [`router`] — the axum router the HTTP layer mounts.

#![forbid(unsafe_code)]

pub mod answer;
pub mod config_view;
pub mod document;
pub mod gate;
pub mod operations;
pub mod request;
pub mod router;
pub mod routing;
pub mod schema;
pub mod setup;
pub mod tables;
