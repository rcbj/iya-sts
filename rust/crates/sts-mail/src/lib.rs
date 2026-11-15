// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The mail channel (#444, phase 4; `common/CLAUDE.md` section 3ba): the
//! one way this service tells a person anything.
//!
//! | Module | Node file it ports |
//! |---|---|
//! | [`templates`] | `common/mail_templates.ts`: the messages, their rules and the renderer |
//! | [`locale`] | the language chain `mail_templates.ts` asks `common/i18n.ts` for |
//! | [`compose`] | the raw RFC 5322 message nodemailer's composer makes (`mail_transports.ts`'s `compose()`) |
//! | [`transports`] | `common/mail_transports.ts`: the five transports, their failures |
//! | [`channel`] | `common/mail.ts`: `send()`, the outbox, the attempt, the sweep job |
//! | [`uses`] | `common/mail_uses.ts`: what each use hands the channel |
//!
//! **THE THREE RULES THAT KEEP IT FROM BEING AN OPEN RELAY** hold here as in
//! Node: the recipient is a directory entry (never an address a request
//! supplies), a link is built on `global.publicBaseUrl` (never on a
//! request), and a template loads nothing, runs nothing and writes no
//! address of its own. And nothing is sent in the clear: the SMTP transport
//! is STARTTLS-required or implicit TLS, behind [`transports::SmtpRelay`].
//!
//! Proved against Node by `tests/node_vectors.rs` over `auditmail-node.json`
//! (`tests/tools/mail-vectors.js`), and the other way by
//! `tests/rust_crypto_vectors.js` over `mail-rust.json`.

#![forbid(unsafe_code)]

pub mod js;
pub mod locale;
mod sanitize;
pub mod templates;
