// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE PROTOCOL-INDEPENDENT SIGN-OUT (#444, phase 5, the `logout` slice):
//! `logout/logout.ts`. `logout/CLAUDE.md` is the design; this crate is its
//! own, as that directory is — one module that needs EVERY family is
//! neither `common/` (more than one family needs it) nor `authn/` (the two
//! halves of one ceremony).
//!
//! | Module | Node it ports |
//! |---|---|
//! | [`families`] | `buildFamilies()`'s table: the order a person reads, `endOrder`, the prose |
//! | [`logout`] | the model — one row per live thing, read from its owner — `inventoryFor()`, `terminate()`, `heldIds()`, `terminateEach()`, `revokeGrantsOf()`, `endFactorSessions()`, `endPartnerSession()`, `endBoundSession()` |
//! | [`signout`] | `subjectOf()`, `endFor()`, the account step (#561), `signOutView()` / `signOutAct()`, `fanOutOf()`, `sealResult()` / `openResult()` |
//! | [`door`] | `registerRoutes()`: `GET`/`POST /logout`, `POST /logout/signed-out`, and the page's operations behind `/authn-api/logout` |
//! | [`document`] | the console's fold and tabs, the language chooser, for the signed-out document |
//! | [`ports`] | one trait per module `logout.ts` reads and ends (rule 3m) |
//! | [`wiring`] | what the runtime answers each port with today |
//!
//! **RULE 3m: IT HOLDS NO STATE OF ITS OWN.** Every row is read live from
//! the module that OWNS that thing and every termination is a call into
//! that module, through [`ports`]; Node's one per-call index (`withIndex()`)
//! is passed down the call, never kept.
//!
//! **IN PRODUCT A SIGN-OUT REVOKES THE ACCESS TOKENS OF ITS SESSION
//! (#1449)**, and it is the session's end that does it: the `session`
//! family ends every session through `endSessionById()`, which is
//! `sts-authn`'s `drop_session()`, whose `Records` port is `sts-oauth`'s
//! `SessionTokens` in the runtime ([`wiring`]).
//!
//! The proof is `tests/node_vectors.rs`: every act
//! `tests/tools/logout-vectors.js` records from Node's own `Logout` — a
//! person signed in to clients across the families, signing out of one,
//! the default and everything, in development and product — replayed here
//! call for call, answer for answer.

#![forbid(unsafe_code)]

pub mod document;
pub mod door;
pub mod families;
pub mod js;
pub mod logout;
pub mod ports;
pub mod signout;
pub mod wiring;

pub use logout::{Logout, LogoutDeps, TerminateOptions};
