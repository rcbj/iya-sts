// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE SESSION CORE (#444, phase 5): `authn/authn.ts`'s sign-on session, the
//! identity every artifact this service issues is a projection of (root
//! `CLAUDE.md`, *What an authenticated identity is*; `authn/CLAUDE.md`).
//!
//! * [`record`] — the record: the subject `urn:uuid:<entryUUID>`, the
//!   authentication events (`at`, `amr`, `acr`, `via`, the authority, the
//!   evidence, the context, the registered device), the `Session` concept
//!   (`sts_model`, D15) read from Node's row;
//! * [`cookie`] — `sts_session` = `<sid>.<handle>`, only the handle's hash
//!   stored, rotated on every re-authentication;
//! * [`merge`] — two nodes' copies of one row merged
//!   (`mergeSessionRows()`), and the store's declaration;
//! * [`sessions`] — the doors: `startSession()`, `sessionOf()`, the
//!   re-authentication, `dropSession()` and the ends over it, the expiry
//!   and the sweep, the caps, the arrival sessions, presented and held;
//! * [`job`] — `authn.session-expiry` on the one scheduler;
//! * [`ports`] — what it reaches beyond itself, and the observer slot.
//!
//! COMPATIBILITY (D11). The store is `authn.sessions`, tombstoned and
//! merged as Node declares it; the row is Node's JSON, member for member,
//! sealed and filed in `sts_sessions` by `sts-store`'s minted flush exactly
//! as Node files it — so a 1.x install's sessions are live here and Node
//! reads this runtime's (`tests/store_interop.rs`).
//!
//! NOT HERE YET, each argued in the slice's report: browsers' account sets
//! (`authn.multipleAccounts`, #561 — with the setting on, a sign-in in a
//! signed-in browser replaces the session, as with it off), the session
//! window (#350's `auto`, which a one-process runtime with the full map in
//! memory does not need), the hosted surfaces' relying-party sessions, and
//! the risk engine's drift re-assessment (#62), which only a session the
//! risk engine assessed carries.
//!
//! The proof is `tests/node_vectors.rs`: every step
//! `tests/tools/session-vectors.js` records from Node's own `Authn` is
//! replayed here — calls, answers, cookies, refusal codes, and the store
//! the step leaves, row for row.

#![forbid(unsafe_code)]

pub mod cookie;
pub mod job;
pub mod js;
pub mod merge;
pub mod ports;
pub mod record;
pub mod sessions;

pub use sessions::{Sessions, SessionsDeps};
