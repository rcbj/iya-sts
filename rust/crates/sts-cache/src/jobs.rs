// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The registry's two scheduler jobs, both PER-PROCESS and QUIET, because
//! every process holds its own copy of every store (root CLAUDE.md,
//! *Anything periodic is a scheduler job*):
//!
//! * `caches.eject-expired` (`admin-ui/caches_admin.ts`'s
//!   `registerEjectJob()`, #49 P5): every minute, every store's `eject()`.
//!   Housekeeping only — every owner still refuses an expired entry where it
//!   READS it, and still bounds its store where it INSERTS
//!   ([`crate::BoundedMap::make_room`]); ejection only stops an idle store
//!   holding dead rows until its next lookup.
//! * `cluster.cache-report` (`cluster/cluster.js`'s `scheduleCacheReport()`):
//!   every thirty seconds, this process's [`crate::Snapshot`], which the
//!   heartbeat carries to `/admin/caches` on every other node. Off unless
//!   this process is a joined cluster node.
//!
//! Both give the runtime a turn between stores (#704's slices).

use std::sync::{Arc, Mutex, PoisonError};

use serde_json::json;
use sts_cluster::schedule::{JobSpec, Kind, Schedule};
use sts_core::errors::codes;
use sts_core::log::tag;

use crate::{CacheRegistry, Snapshot};

/// The ejection job's id.
pub const EJECT_JOB: &str = "caches.eject-expired";
/// The cluster cache report's id.
pub const CACHE_REPORT_JOB: &str = "cluster.cache-report";
/// How often the report is taken (`CACHE_REPORT_MS`).
pub const CACHE_REPORT_MS: f64 = 30_000.0;

/// `caches.eject-expired`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn eject_job(registry: Arc<CacheRegistry>) -> JobSpec {
    let mut job = JobSpec::new(
        EJECT_JOB,
        "Expired cache entries ejection",
        "Deletes, in this process, every cache and replay-store entry whose lifetime has passed — \
         housekeeping only: each store still refuses an expired entry where it reads it.",
        "admin-ui/caches_admin.ts",
        Schedule::Every(Arc::new(|| 60_000.0)),
    );
    job.kind = Kind::PerProcess;
    job.quiet = true;
    job.run = Some(Arc::new(move |ctx| {
        let registry = registry.clone();
        Box::pin(async move {
            let done =
                registry.eject_expired_async((ctx.now_ms)() as i64).await;
            if !done.failed.is_empty() {
                tracing::warn!(
                    "{}caches: {} store(s) could not eject their expired entries: {}",
                    tag(codes::STS_CORE_0102),
                    done.failed.len(),
                    done.failed.join("; ")
                );
            }
            Ok(
                json!({ "ejected": done.ejected, "stores": done.by_cache.len(),
                       "failed": done.failed.len() }),
            )
        })
    }));
    job
}

/// The snapshot the heartbeat carries, kept between reports.
pub type CacheReport = Arc<Mutex<Option<Snapshot>>>;

/// `cluster.cache-report`: `off` says why this process does not report
/// (`''` when it does — a joined front process).
#[tracing::instrument(level = "debug", skip_all)]
pub fn cache_report_job(
    registry: Arc<CacheRegistry>,
    report: CacheReport,
    off: Arc<dyn Fn() -> String + Send + Sync>,
) -> JobSpec {
    let mut job = JobSpec::new(
        CACHE_REPORT_JOB,
        "Cluster cache report",
        "Takes this node's cache and replay-store snapshot, which its heartbeat carries to /admin/caches \
         on every other node.",
        "cluster/cluster.js",
        Schedule::Every(Arc::new(|| CACHE_REPORT_MS)),
    );
    job.kind = Kind::PerProcess;
    job.quiet = true;
    job.off = Some(Arc::new(move |_realm: &str| Ok(off())));
    job.run = Some(Arc::new(move |ctx| {
        let (registry, report) = (registry.clone(), report.clone());
        Box::pin(async move {
            let taken = registry.snapshot_async((ctx.now_ms)() as i64).await;
            *report.lock().unwrap_or_else(PoisonError::into_inner) =
                Some(taken);
            Ok(json!({ "taken": true }))
        })
    }));
    job
}
