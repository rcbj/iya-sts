// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `/authn-api` AND THE SIGN-IN SURFACE'S SERVER SIDE (#444, phase 5, the
//! `authnapi` slice): `authn/authn_api.ts` — the door every protocol's
//! browser sign-in passes through, which the unchanged sign-in bundle
//! (`/authn/signin.js`) draws every page from and sends every act to — and
//! the parts of `authn/authn.ts` it calls: the pending sign-ins, the
//! screen's view and acts, the second-factor steps, the forced password
//! change, and the shells.
//!
//! | Module | Node it ports |
//! |---|---|
//! | [`operations`] | the five operation tables, in Node's order |
//! | [`model`] | the document (`models/api/authn.tsp`) and `response_models.ts`'s check of every answer |
//! | [`body`] | `validation.js`'s `checkParsed()` over the model's zod schema, in zod v4's words |
//! | [`door`] | `AuthnApi`: the binding, the ids, the shape check, the dispatch |
//! | [`flow`] | `authn.ts`'s views and acts the door calls |
//! | [`pending`] | the three pending registers, under Node's names |
//! | [`router`] | the axum router and the shells (`signInShell()`, the arrival session) |
//! | [`ports`] | what else the screen asks, and the account sets' narrow port |
//! | [`wiring`] | the composition root's one call |
//!
//! THE SESSION IS THE IDENTITY (`authn/CLAUDE.md`): every act that
//! finishes a sign-in hands the credential it verified, as EVIDENCE, to
//! `sts_authn::Sessions::start_session()`; the cookie that names the
//! session is set on the answer naming where to go next. An error code is
//! recorded on the response (`sts_http::mark`), never sent.

#![forbid(unsafe_code)]
// A refusal is an `Answer` (the status, the JSON, the cookies, the code),
// carried back as an `Err` through the door's checks exactly as Node
// returns from the handler with the refusal sent; it is the rare path, and
// boxing every one would only move the allocation.
#![allow(clippy::result_large_err)]

pub mod body;
pub mod door;
pub mod flow;
pub mod model;
pub mod operations;
pub mod pending;
pub mod ports;
pub mod router;
pub mod wiring;
