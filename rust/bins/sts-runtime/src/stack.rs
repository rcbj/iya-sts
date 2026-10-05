// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The composition root (`common/protocol_stack.ts`'s Rust counterpart,
//! rust/DESIGN.md section 4.2): the shared services built in dependency
//! order, then — in later phases — the families in the order of the root
//! `CLAUDE.md` table.
//!
//! What phase 3 builds: the settings and the mode; the realm registry and
//! the realms' lifecycle, which is the settings' realm layer; the declared
//! stores; persistence (memory or ldif) over the directory; the scheduler,
//! leading at once in a service of one process, with its own history job;
//! and the HTTP layer every route will sit behind. No protocol family is
//! served yet, so every path answers the ordinary 404.

use std::sync::{Arc, OnceLock, Weak};

use serde_json::Value as Json;
use sts_cluster::schedule::{compare_rows, Schedules};
use sts_cluster::scheduler::{Deps, Scheduler};
use sts_core::errors::codes;
use sts_core::log::tag;
use sts_core::mode::Mode;
use sts_core::realm::{RealmRegistry, SettingsEnvironment};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{RealmMap, StoreHandles, StoreSpec};
use sts_core::settings::Settings;
use sts_store::ldif_driver::LdifDriver;
use sts_store::persistence::{MemoryDirectory, Persistence, StoreMode};
use sts_store::Driver;

use crate::solo::{LocalClaims, LocalClock, LogAudit, RunStore, SoloCluster};

/// Everything the runtime built, held for its lifetime. Later phases read
/// the fields this one only holds.
#[allow(dead_code)]
pub struct Stack {
    pub settings: Arc<Settings>,
    pub mode: Arc<Mode>,
    pub registry: Arc<RealmRegistry>,
    pub lifecycle: Arc<RealmLifecycle>,
    pub handles: Arc<StoreHandles>,
    pub directory: Arc<MemoryDirectory>,
    pub persistence: Arc<Persistence>,
    pub scheduler: Arc<Scheduler>,
}

/// `persistence.mode` as this runtime can serve it, or why not.
fn store_mode(settings: &Settings) -> Result<StoreMode, String> {
    match settings.value_of("persistence.mode").as_str() {
        "memory" => Ok(StoreMode::Memory),
        "ldif" => Ok(StoreMode::Ldif),
        "postgres" => Err(format!(
            "{}persistence.mode is \"postgres\", and the Rust runtime has no postgres driver yet (#444, phase 3). \
             Use memory or ldif with this runtime, or the Node runtime.",
            tag(codes::STS_STORE_0003)
        )),
        other => Err(format!(
            "{}persistence: \"{}\" is not a mode this module knows (memory, ldif, postgres).",
            tag(codes::STS_STORE_0003),
            other
        )),
    }
}

impl Stack {
    /// Builds the shared services from the settings. Nothing is opened or
    /// started here; [`Stack::start`] does that.
    pub fn build(settings: Arc<Settings>) -> Result<Stack, String> {
        let mode = Arc::new(Mode::new(settings.clone()));
        let environment =
            Arc::new(SettingsEnvironment::new(settings.clone(), Vec::new()));
        let registry = Arc::new(RealmRegistry::new(environment));
        let lifecycle = RealmLifecycle::new(
            registry.clone(),
            settings.clone(),
            mode.clone(),
        );
        let handles = StoreHandles::new();
        let directory = Arc::new(MemoryDirectory::default());

        let chosen = store_mode(&settings)?;
        let driver: Option<Arc<dyn Driver>> = match chosen {
            StoreMode::Ldif => {
                let dir = settings
                    .value_of("persistence.dataDir")
                    .as_str()
                    .to_string();
                Some(Arc::new(LdifDriver::new(if dir.is_empty() {
                    "./data".to_string()
                } else {
                    dir
                })))
            }
            _ => None,
        };
        let persistence = Persistence::new(
            chosen,
            driver,
            settings.clone(),
            lifecycle.clone(),
            directory.clone(),
        );

        // The scheduler's run rows: persisted, tombstoned, merged by rank,
        // each row's expiry the scheduler's own (a forward reference, read
        // at flush time once the scheduler exists).
        let scheduler_slot: Arc<OnceLock<Weak<Scheduler>>> =
            Arc::new(OnceLock::new());
        let slot = scheduler_slot.clone();
        let spec = StoreSpec {
            tombstone: true,
            merge_row: Some(Arc::new(|mine: &Json, theirs: &Json| {
                if compare_rows(mine, theirs).is_gt() {
                    mine.clone()
                } else {
                    theirs.clone()
                }
            })),
            expires_at: Some(Arc::new(move |row: &Json, _key: &str| {
                slot.get()
                    .and_then(Weak::upgrade)
                    .and_then(|s| s.expiry_of(row))
            })),
            ..StoreSpec::persisted("scheduler.runs")
        };
        let runs = RealmMap::new(&lifecycle, &handles, spec);
        let host = std::env::var("HOSTNAME")
            .unwrap_or_else(|_| "localhost".to_string());
        let scheduler = Scheduler::new(
            Schedules::new(settings.clone()),
            Deps {
                cluster: Arc::new(SoloCluster { host: host.clone() }),
                claims: Arc::new(LocalClaims::default()),
                rows: Arc::new(RunStore { rows: runs }),
                realms: registry.clone(),
                audit: Arc::new(LogAudit),
                clock: Arc::new(LocalClock),
                host,
                pid: std::process::id(),
                thread: None,
                is_request_worker: false,
            },
        );
        if scheduler_slot.set(Arc::downgrade(&scheduler)).is_err() {
            return Err("the scheduler was built twice".to_string());
        }
        scheduler.register_history_job()?;
        Ok(Stack {
            settings,
            mode,
            registry,
            lifecycle,
            handles,
            directory,
            persistence,
            scheduler,
        })
    }

    /// Opens the store and reads it back — fatal when it cannot be — then
    /// starts the scheduler. Before any listener binds.
    pub async fn start(&self) -> Result<(), String> {
        self.persistence.start().await?;
        self.scheduler.start(false);
        Ok(())
    }

    /// Every route, behind the HTTP layer.
    pub fn router(&self) -> axum::Router {
        sts_http::layered(axum::Router::new(), self.registry.clone())
    }

    /// Writes what is pending and closes the store.
    pub async fn stop(&self) {
        self.scheduler.stop();
        if let Err(e) = self.persistence.stop().await {
            tracing::error!(
                "{}runtime: the store could not be closed cleanly: {}",
                tag(codes::STS_STORE_0001),
                e
            );
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)] // tests

    use std::collections::HashMap;

    use axum::body::Body;
    use axum::http::Request;
    use serde_json::json;
    use tower::ServiceExt;

    use super::*;

    fn settings(operator: Json) -> Arc<Settings> {
        Arc::new(Settings::new(operator, HashMap::new()))
    }

    #[tokio::test]
    async fn a_memory_stack_starts_and_answers_the_404() {
        let stack = Stack::build(settings(
            json!({ "persistence": { "mode": "memory" } }),
        ))
        .unwrap();
        stack.start().await.unwrap();
        assert!(stack
            .scheduler
            .job_ids()
            .contains(&"scheduler.history".to_string()));
        let response = stack
            .router()
            .oneshot(Request::get("/oauth2/token").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), 404);
        assert!(response.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'"));
        stack.stop().await;
    }

    #[test]
    fn postgres_is_refused_until_it_is_ported() {
        let err = Stack::build(settings(
            json!({ "persistence": { "mode": "postgres" } }),
        ))
        .err()
        .unwrap();
        assert!(
            err.contains("STS-STORE-0003")
                && err.contains("no postgres driver yet")
        );
    }
}
