// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The registers that sit over the directory (#444, phase 4), as the Node
//! service holds them now. Each module names the Node file it ports:
//!
//! * [`roles`] — `common/roles.js` (3u): built-in, native and stored roles;
//! * [`role_actions`] — `admin_actions.ts` `rolesAction()`: the eleven
//!   `/admin-api/roles` acts, `add-member` refusing a second add;
//! * [`rbac`] — `admin-ui/admin_rbac.ts`: the console roster's grant and
//!   revoke (`rbac/grant` is idempotent; a person must exist);
//! * [`role_permissions`] — `common/role_permissions.ts` (3bq);
//! * [`app_permissions`] — `common/app_permissions.ts` (3s) and
//!   `permissionsAction()`, with `applications.js`'s pure permission
//!   helpers;
//! * [`ownership`] — `common/ownership.ts` (3cn);
//! * [`group_claims`] — `common/group_claims.ts` (3d-ii): a group grants
//!   nothing by being a group;
//! * [`people`] — `common/account_state.ts` (3at), `usersAction()`'s
//!   create, disable and enable, and `groupsAction()`;
//! * [`applications`] — `common/applications.js` (3g): the application
//!   register itself, over `sts-directory`;
//! * [`operations`] — the `/admin-api` operations those back.
//!
//! The directory, the settings, the audit log and every register this
//! crate does not own arrive as ports ([`port`]): traits handed to each
//! constructor, where Node fills a slot (rule 3e). `schema` holds the
//! directory objects' tables generated from the model; `js` the
//! JavaScript coercions Node's sentences are built with.
//!
//! The proof is `tests/node_vectors.rs`: every step
//! `tests/tools/registers-vectors.js` records from Node's own registers is
//! replayed here, calls and answers, sentence and code.

#![forbid(unsafe_code)]

pub mod app_permissions;
pub mod applications;
pub mod group_claims;
pub mod js;
pub mod operations;
pub mod outcome;
pub mod ownership;
pub mod people;
pub mod port;
pub mod rbac;
pub mod role_actions;
pub mod role_permissions;
pub mod roles;
pub mod schema;
pub mod settings;
