// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE RING IN THE STORE, under Node's two handles (`common/audit.js`):
//!
//! ```text
//! realms.arr({ persist: 'audit.events', merge: 'own', segment: 32,
//!              contributionsOnRead: true })
//! realms.obj(…, { persist: 'audit.nums', merge: 'own',
//!                 contributionsOnRead: true })
//! ```
//!
//! So a 1.x install's ring reads back after the upgrade, and a ring this
//! runtime wrote reads back in Node: the same handles, the same segments
//! of 32 (`{ start, rows }`), the same row and counter JSON
//! ([`crate::row::AuditRow`], [`crate::log::Nums`]).
//!
//! What replaced what (rust/DESIGN.md section 4):
//!
//! * the ring is held by [`crate::AuditLog`]; this mirrors each change
//!   into the declared stores ([`RingSink`]), so the store's journal sees
//!   an append as ONE segment and a trim as the segment it emptied — the
//!   reason Node segments the ring (#46);
//! * `merge: 'own'` is the store's: each process writes only its own rows,
//!   and what the others wrote reaches [`Replication`] through the fan-in
//!   (`persistence_replication`'s `remoteSegmentedRows()`), read when the
//!   page is drawn (`contributionsOnRead`, #820);
//! * the restore (`realms.arr()` filled from the store at open) is
//!   [`StoreRing::restore_into`], called once the store is open.

use std::sync::Arc;

use serde_json::Value as Json;
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{
    Merge, RealmObj, RealmVec, StoreHandles, StoreSpec,
};

use crate::log::{AuditLog, Nums, Replication, RingSink};
use crate::row::AuditRow;

/// `audit.events`.
pub const EVENTS_HANDLE: &str = "audit.events";
/// `audit.nums`.
pub const NUMS_HANDLE: &str = "audit.nums";
/// Node's segment size for the ring (#46).
pub const SEGMENT: u64 = 32;

/// What another process contributed, as the fan-in holds it.
pub trait Contributions: Send + Sync {
    /// `remoteSegmentedRows(handle)`: each other process's rows of the
    /// ambient realm, its segments in position order.
    fn segmented_rows(&self, handle: &str) -> Vec<Vec<Json>>;
    /// `remoteRows(handle, '')`: each other process's object.
    fn rows(&self, handle: &str) -> Vec<Json>;
}

/// The two declared stores.
pub struct StoreRing {
    events: RealmVec<AuditRow>,
    nums: RealmObj<Nums>,
}

impl StoreRing {
    /// Declares `audit.events` and `audit.nums` (before the store opens).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn declare(
        lifecycle: &Arc<RealmLifecycle>,
        handles: &Arc<StoreHandles>,
    ) -> Arc<StoreRing> {
        let own = |handle: &str| StoreSpec {
            merge: Merge::Own,
            ..StoreSpec::persisted(handle)
        };
        Arc::new(StoreRing {
            events: RealmVec::new(
                lifecycle,
                handles,
                own(EVENTS_HANDLE),
                SEGMENT,
            ),
            nums: RealmObj::new(
                lifecycle,
                handles,
                own(NUMS_HANDLE),
                Arc::new(|_: &str| Nums::default()),
            ),
        })
    }

    /// Hands what the store restored for each realm to the log, once the
    /// store is open.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn restore_into(&self, log: &AuditLog, realms: &[String]) {
        for realm in realms {
            let rows = self.events.to_vec_in(Some(realm));
            let nums = self.nums.get_in(realm);
            if rows.is_empty() && nums == Nums::default() {
                continue;
            }
            log.restore(realm, rows, nums);
        }
    }
}

impl RingSink for StoreRing {
    // A hot path (every row): no span. The ring only appends at the back
    // and trims at the front, so the mirror drops from its front what the
    // ring no longer holds and appends what it has not seen; `seq` names a
    // row within a realm.
    fn changed(
        &self,
        realm: &str,
        rows: &std::collections::VecDeque<AuditRow>,
        nums: &Nums,
    ) {
        let held = self.events.to_vec_in(Some(realm));
        let first = rows.front().map(|r| (r.seq, r.origin.clone()));
        let mut skip = 0usize;
        for row in &held {
            if Some((row.seq, row.origin.clone())) == first {
                break;
            }
            skip += 1;
        }
        for _ in 0..skip {
            self.events.shift_in(Some(realm));
        }
        let kept = held.len() - skip;
        for row in rows.iter().skip(kept) {
            self.events.push_in(Some(realm), row.clone());
        }
        let nums = nums.clone();
        self.nums.update(move |n| *n = nums);
    }
}

/// The fan-in, as [`Replication`].
pub struct FanInReplication(pub Arc<dyn Contributions>);

impl Replication for FanInReplication {
    fn remote_segmented_rows(&self) -> Vec<Vec<AuditRow>> {
        self.0
            .segmented_rows(EVENTS_HANDLE)
            .into_iter()
            .map(|rows| {
                rows.into_iter()
                    .filter_map(|r| serde_json::from_value(r).ok())
                    .collect()
            })
            .collect()
    }

    fn remote_recorded(&self) -> i64 {
        self.0
            .rows(NUMS_HANDLE)
            .iter()
            .filter_map(|n| n.get("recorded").and_then(Json::as_i64))
            .sum()
    }
}
