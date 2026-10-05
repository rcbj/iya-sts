// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The one place the runtime writes anything down (`persistence/`).
//!
//! Three modes, by `persistence.mode`: `memory` (the default: nothing is
//! written or read), `ldif` (local development: an RFC 2849 file per realm
//! and JSON for the realm registry and the overrides) and `postgres` (the
//! shared store). Every driver implements [`Driver`]; the capability groups
//! a driver may lack — minted state, the change log, the used-assertion
//! history — are separate traits a driver answers for by name, so a driver
//! without one is a smaller store rather than a broken one, and the absence
//! is reported rather than silent.

#![forbid(unsafe_code)]

pub mod codec;
pub mod driver;
pub mod ldif;
pub mod ldif_driver;
pub mod memory;
pub mod merge;
pub mod model;
pub mod persistence;
pub mod postgres;
pub mod shadow;

pub use driver::{Driver, StoreError, StoreFuture, StoreResult};
pub use model::{
    DirectoryChange, DirectoryDelete, DirectoryOutcome, DirectoryUpsert,
    StoredEntry,
};
