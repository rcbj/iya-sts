// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The certificate authority this service keeps (#444 phase 6):
//! `common/pki.js` (rule 3w), `common/pki_revocation.js`,
//! `common/pki_merge.js` and `pki/pki_service.ts`.
//!
//! * [`catalog`] — the tiers, the scopes and the use cases, and the key
//!   algorithms an authority may hold;
//! * [`config`] — what the authority reads from the settings and the mode;
//! * [`rows`] — the `pki:<scope>` rows, Node's JSON carried whole;
//! * [`hierarchy`] — the Root, each scope's branch, issuing
//!   (`issueUnder()`, `issueEnrolled()` for ACME/EST/SCEP, `certify()`);
//! * [`revocation`], [`crl`], [`ocsp`] — the register, the per-CA list and
//!   the responder;
//! * [`merge`] — the three-way merge of a row two writers stored;
//! * [`surface`] — the public `/pki/*` answers.
//!
//! The row is the compatibility boundary: a hierarchy a 1.x product
//! install sealed is read and issued under, and a row written here is
//! Node's shape member for member (`tests/pki_authority_vectors.rs`).

pub mod catalog;
pub mod config;
pub mod crl;
pub mod hierarchy;
pub mod merge;
pub mod ocsp;
pub mod revocation;
pub mod rows;
pub mod surface;

pub use config::PkiConfig;
pub use hierarchy::{Authority, BuildOptions, Refusal};
pub use rows::{MemoryRows, RowStore};
