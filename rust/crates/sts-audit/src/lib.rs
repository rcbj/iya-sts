// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The audit log (#444, phase 4; `common/CLAUDE.md` 3c and 3da).
//!
//! | Module | Node file it ports |
//! |---|---|
//! | [`vocabulary`] | `common/audit.js`'s `CATEGORIES`, `ACTIONS`, `OUTCOMES` |
//! | [`row`] | the row `common/audit.js`'s `record()` writes |
//! | [`log`] | `common/audit.js`: the ring, the funnels, the readers, the chain |
//! | [`view`] | `admin-core/admin_views.ts`'s `auditView()`: `GET /admin-api/audit` |
//! | [`export`] | `common/audit_export.ts` (#641) and the part of `common/outbound_tls.ts` it asks |
//!
//! Proved against Node by `tests/node_vectors.rs` over
//! `auditmail-node.json`'s `audit` (`tests/tools/audit-vectors.js`), and
//! the other way by `tests/rust_crypto_vectors.js` over `audit-rust.json`.

#![forbid(unsafe_code)]

pub mod export;
mod js;
pub mod log;
pub mod row;
pub mod store;
pub mod view;
pub mod vocabulary;

pub use log::{ApiCaller, AuditLog, AuditPorts, HttpExchange};
pub use row::AuditRow;
