// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The cache registry (rule 3ap, #74): ONE place where every cache and
//! replay store this service holds says what it is, how big it is and how
//! often it was useful — `common/cache_registry.js` — and the two bounded
//! stores a bound is enforced through: [`BoundedMap`], which evicts the
//! entry INSERTED first or refuses (`makeRoom()`), and [`BoundedLru`],
//! which evicts the entry READ least recently and never a pinned one
//! (`common/bounded_lru.ts`, #349).
//!
//! **A bound is a `usize`.** Node allowed `maxEntries()` to answer anything
//! and then reported a store with no finite bound as STS-CORE-0096; here a
//! descriptor that has no bound does not compile.
//!
//! **A row never carries a value.** [`Row`] has five members and none of
//! them is the cached thing.
//!
//! **The registry is not global.** The composition root builds one and
//! hands it to every family that owns a cache (rust/DESIGN.md 4.4).

#![forbid(unsafe_code)]

mod bounded;
mod lru;
mod registry;

pub use bounded::{BoundedMap, Expired, Policy, Room};
pub use lru::{BoundedLru, LruOptions, LruStats};
pub use registry::{
    clip_key, digest_key, CacheRegistry, Counter, Descriptor, Detail, Ejected,
    Kind, Row, Scope, Snapshot, SnapshotRow, Summary,
};
