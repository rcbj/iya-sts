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
use sts_cluster::coordination::{
    ChangePull, CommitGate, CommitLog, ReadBarrier, Topology,
    READ_BARRIER_TIMEOUT_DEFAULT_MS,
};
use sts_cluster::membership::ClusterNode;
use sts_cluster::membership::{resolve_mode, ModeSettings};
use sts_cluster::schedule::BoxFuture;
use sts_cluster::schedule::{compare_rows, Schedules};
use sts_cluster::scheduler::{Deps, Extras, RunRows, RuntimeLoad, Scheduler};
use sts_core::errors::codes;
use sts_core::log::tag;
use sts_core::mode::Mode;
use sts_core::realm::{RealmRegistry, SettingsEnvironment};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{RealmMap, StoreHandles, StoreSpec};
use sts_core::settings::Settings;
use sts_crypto::random::random_bytes;
use sts_store::ldif_driver::LdifDriver;
use sts_store::persistence::{MemoryDirectory, Persistence, StoreMode};
use sts_store::postgres::PostgresDriver;
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
    /// This node of a clustered service; `None` for one process.
    pub node: Option<Arc<ClusterNode>>,
    /// The HTTP layer every route sits behind (`common/app.js`).
    pub http: Arc<sts_http::HttpLayer>,
    /// How busy this runtime is (#408): a request in flight is one.
    pub load: Arc<RuntimeLoad>,
    /// Rule 1: a request is served after what was committed before it.
    pub barrier: Arc<ReadBarrier>,
    /// Rule 2: a request that wrote is answered once its writes commit.
    pub gate: Arc<CommitGate>,
    /// Every cache describing itself (`common/cache_registry.js`).
    pub caches: Arc<sts_cache::CacheRegistry>,
    runs: Arc<RunStore>,
}

/// The change-log pull the read barrier waits on: `Persistence`'s.
struct PersistencePull(Weak<Persistence>);

impl ChangePull for PersistencePull {
    fn pull(&self) -> BoxFuture<'_, Result<bool, String>> {
        let p = self.0.upgrade();
        Box::pin(async move {
            match p {
                // A pull that returns has applied everything that was
                // visible when it began: caught up.
                Some(p) => p.pull_changes().await.map(|_| true),
                None => Ok(true),
            }
        })
    }

    fn coordinates(&self) -> bool {
        self.0.upgrade().is_some_and(|p| p.coordinates())
    }
}

/// Where this process's writes are: the directory's generation, and the
/// wait for it to be written down.
struct PersistenceCommits(Weak<Persistence>);

impl CommitLog for PersistenceCommits {
    fn position(&self) -> u64 {
        self.0.upgrade().map_or(0, |p| p.generation())
    }

    fn through(&self, position: u64) -> BoxFuture<'_, Result<(), String>> {
        let p = self.0.upgrade();
        Box::pin(async move {
            let Some(p) = p else {
                return Ok(());
            };
            match p.directory_through(position).await {
                sts_store::persistence::Through::Failed(e) => Err(e),
                _ => Ok(()),
            }
        })
    }
}

/// A node id for this process: random, as Node's is per start.
fn node_id() -> String {
    let buf = match random_bytes(8) {
        Ok(buf) => buf,
        Err(e) => {
            tracing::error!("runtime: no random bytes for the node id: {}", e);
            vec![0u8; 8]
        }
    };
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

/// `persistence.mode` as this runtime can serve it, or why not.
fn store_mode(settings: &Settings) -> Result<StoreMode, String> {
    match settings.value_of("persistence.mode").as_str() {
        "memory" => Ok(StoreMode::Memory),
        "ldif" => Ok(StoreMode::Ldif),
        "postgres" => Ok(StoreMode::Postgres),
        other => Err(format!(
            "{}persistence: \"{}\" is not a mode this module knows (memory, ldif, postgres).",
            tag(codes::STS_STORE_0003),
            other
        )),
    }
}

/// `GET /oauth2/jwks`: the ambient realm's published keys, served
/// `no-store` like every document that carries a key, pretty-printed as
/// Node's `JSON.stringify(…, null, 2)`. A realm's set is made on its first
/// use; one that cannot be read or made is answered 500 with
/// `STS-OAUTH-0184`, Node's answer when the JWKS cannot be built.
async fn jwks(persistence: Weak<Persistence>) -> axum::response::Response {
    use axum::http::{header, StatusCode};
    use axum::response::IntoResponse;
    let realm = sts_core::realm::current_id();
    let sets = persistence.upgrade().and_then(|p| p.key_sets());
    let built = match sets {
        Some(sets) => sets.open_or_make(&realm).await.and_then(|set| {
            let published = set.kid().and_then(|kid| {
                sets.published_certificate_for(&realm, "jose", "RS256", &kid)
            });
            sts_store::key_sets::jwks_document(&set, published)
        }),
        None => Err("no key set is held for this realm".to_string()),
    }
    .and_then(|doc| {
        serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())
    });
    match built {
        Ok(body) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/json; charset=utf-8"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            body,
        )
            .into_response(),
        Err(e) => {
            tracing::error!(
                "{}could not publish the JWKS: {}",
                tag(codes::STS_OAUTH_0184),
                e
            );
            sts_http::mark(
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
                    serde_json::json!({ "error": e }).to_string(),
                )
                    .into_response(),
                codes::STS_OAUTH_0184,
            )
        }
    }
}

fn unavailable(code: sts_core::errors::ErrorCode) -> axum::response::Response {
    use axum::response::IntoResponse;
    sts_http::mark(
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            [(axum::http::header::RETRY_AFTER, "1")],
            "Service Unavailable",
        )
            .into_response(),
        code,
    )
}

// A hot path (every request): no span of its own.
async fn guarded(
    load: Arc<RuntimeLoad>,
    barrier: Arc<ReadBarrier>,
    gate: Arc<CommitGate>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let _in_flight = load.enter();
    if let Err(refused) = barrier.wait().await {
        return unavailable(refused.code);
    }
    let before = gate.mark();
    let response = next.run(request).await;
    match gate.hold(before).await {
        Ok(()) => response,
        Err(refused) => unavailable(refused.code),
    }
}

impl Stack {
    /// Builds the shared services from the settings. Nothing is opened or
    /// started here; [`Stack::start`] does that.
    #[tracing::instrument(level = "debug", skip_all)]
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
        let postgres: Option<Arc<PostgresDriver>> = match chosen {
            StoreMode::Postgres => Some(Arc::new(
                PostgresDriver::new(
                    settings.value_of("persistence.databaseUrl").as_str(),
                    settings
                        .value_of("persistence.databaseTlsRejectUnauthorized")
                        .as_bool(),
                    10,
                )
                .map_err(|e| e.to_string())?,
            )),
            _ => None,
        };
        let driver: Option<Arc<dyn Driver>> = match chosen {
            StoreMode::Postgres => {
                postgres.clone().map(|p| p as Arc<dyn Driver>)
            }
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
        // Every declared store's writes are minted state, journalled for
        // the store once it opens (where minted state is persisted).
        persistence.attach_minted(handles.clone());

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
        let run_store = Arc::new(RunStore { rows: runs });
        let host = std::env::var("HOSTNAME")
            .unwrap_or_else(|_| "localhost".to_string());
        // Several nodes share a postgres store; anything else is one
        // process, which leads at once.
        let clustered = postgres.is_some()
            && settings.value_of("cluster.mode").as_str() != "off";
        let node: Option<Arc<ClusterNode>> =
            postgres.as_ref().filter(|_| clustered).map(|p| {
                let name =
                    settings.value_of("cluster.nodeName").as_str().to_string();
                ClusterNode::new(
                    p.clone(),
                    &node_id(),
                    if name.is_empty() { &host } else { &name },
                    settings.value_of("cluster.heartbeatMs").as_int() as f64,
                    settings.value_of("cluster.nodeTtlMs").as_int() as f64,
                    Arc::new(|code: &'static str, why: String| {
                        tracing::error!("{}cluster: {}", tag(code), why);
                        std::process::exit(1);
                    }),
                )
            });
        let (cluster, claims, clock): (
            Arc<dyn sts_cluster::scheduler::Cluster>,
            Arc<dyn sts_cluster::scheduler::Claims>,
            Arc<dyn sts_cluster::scheduler::Clock>,
        ) = match &node {
            Some(n) => (n.clone(), n.clone(), n.clone()),
            None => (
                Arc::new(SoloCluster { host: host.clone() }),
                Arc::new(LocalClaims::default()),
                Arc::new(LocalClock),
            ),
        };
        let load = RuntimeLoad::new();
        // The threads a cluster run's body is handed to (#408): the tokio
        // runtime's workers, which here serve every request too.
        let threads = std::thread::available_parallelism()
            .map_or(1.0, |n| n.get() as f64);
        let scheduler = Scheduler::with_extras(
            Schedules::new(settings.clone())
                .with_request_workers(Arc::new(move || threads)),
            Deps {
                cluster,
                claims,
                rows: run_store.clone(),
                realms: registry.clone(),
                audit: Arc::new(LogAudit),
                clock,
                host,
                pid: std::process::id(),
                thread: None,
                is_request_worker: false,
            },
            // The durable run history (#883) reads run rows back from the
            // minted table by id, which the store slice's minted API does
            // not offer yet; without it every row is kept in the map, as
            // development keeps them. Cells (#98) are not ported.
            Extras {
                loads: Some(load.clone()),
                history: None,
                cells_multi: None,
            },
        );
        if scheduler_slot.set(Arc::downgrade(&scheduler)).is_err() {
            return Err("the scheduler was built twice".to_string());
        }
        scheduler.register_history_job()?;
        // Applies, in this process, what every other process committed to
        // the change log since this one last looked: per process, recorded
        // quietly, on persistence.pollInterval.
        let mut pull = sts_cluster::schedule::JobSpec::new(
            "persistence.change-log-pull",
            "Change-log pull",
            "Applies, in this process, what every other process has committed to the change log since this one \
             last looked. The change log is the contract.",
            "persistence/persistence_replication.js",
            sts_cluster::schedule::Schedule::Every({
                let settings = settings.clone();
                Arc::new(move || {
                    (settings.value_of("persistence.pollInterval").as_int() as f64).max(250.0)
                })
            }),
        );
        pull.kind = sts_cluster::schedule::Kind::PerProcess;
        pull.quiet = true;
        let watched = Arc::downgrade(&persistence);
        pull.off = Some(Arc::new(move |_realm: &str| {
            Ok(match watched.upgrade() {
                Some(p) if p.coordinates() => String::new(),
                _ => "this process's store does not coordinate".to_string(),
            })
        }));
        let puller = Arc::downgrade(&persistence);
        pull.run = Some(Arc::new(move |_ctx| {
            let puller = puller.clone();
            Box::pin(async move {
                match puller.upgrade() {
                    Some(p) => p.pull_changes().await.map(
                        |applied| serde_json::json!({ "applied": applied }),
                    ),
                    None => Ok(Json::Null),
                }
            })
        }));
        scheduler.register(pull)?;
        // The two sweeps of the minted table, each once for the cluster:
        // the tombstones of ended rows past persistence.mintedRetention, and
        // the rows no start will read again (#333).
        for (id, title, describe, every_ms) in [
            (
                "persistence.tombstone-purge",
                "Expired tombstones sweep",
                "Deletes the tombstones of ended minted rows older than persistence.mintedRetention from the \
                 shared store.",
                10.0 * 60.0 * 1000.0,
            ),
            (
                "persistence.minted-expiry-purge",
                "Expired minted rows purge",
                "Deletes from the shared store, in batches of 5000 and at most 20 batches of each kind per run, \
                 the minted rows no start will read again: past their own expiry, of a realm that is no longer \
                 defined (written over an hour ago), and a short-lived store's rows with no expiry older than \
                 persistence.mintedRetention.",
                5.0 * 60.0 * 1000.0,
            ),
        ] {
            let mut job = sts_cluster::schedule::JobSpec::new(
                id,
                title,
                describe,
                "persistence/persistence_minted.js",
                sts_cluster::schedule::Schedule::Every(Arc::new(move || every_ms)),
            );
            let tombstones = id == "persistence.tombstone-purge";
            let watched = Arc::downgrade(&persistence);
            job.off = Some(Arc::new(move |_realm: &str| {
                Ok(match watched.upgrade().and_then(|p| p.minted()) {
                    Some(m) if tombstones => m.tombstone_sweep_off(),
                    Some(_) => String::new(),
                    None => "minted state is not persisted here".to_string(),
                })
            }));
            let owner = Arc::downgrade(&persistence);
            job.run = Some(Arc::new(move |_ctx| {
                let owner = owner.clone();
                Box::pin(async move {
                    let Some(minted) = owner.upgrade().and_then(|p| p.minted()) else {
                        return Ok(Json::Null);
                    };
                    let now = sts_core::time::now_ms_f64() as i64;
                    if tombstones {
                        minted
                            .sweep_tombstones(now)
                            .await
                            .map(|n| serde_json::json!({ "removed": n }))
                    } else {
                        minted.purge_expired(now).await
                    }
                })
            }));
            scheduler.register(job)?;
        }
        // The caches' two jobs: ejection in every process, and the
        // snapshot a joined node's heartbeat carries.
        let caches = Arc::new(sts_cache::CacheRegistry::new());
        scheduler.register(sts_cache::jobs::eject_job(caches.clone()))?;
        let joined = node.is_some();
        scheduler.register(sts_cache::jobs::cache_report_job(
            caches.clone(),
            sts_cache::jobs::CacheReport::default(),
            Arc::new(move || {
                if joined {
                    String::new()
                } else {
                    "this service is not clustered".to_string()
                }
            }),
        ))?;
        // The HTTP layer, the static surfaces' host, and the write rule
        // that holds a realm's colours to WCAG 2.2 AA.
        settings.add_write_rule(sts_http::branding::ContrastRule::new(
            settings.clone(),
        ));
        let http = sts_http::HttpLayer::new(
            registry.clone(),
            settings.clone(),
            mode.clone(),
        );
        http.add_routes(sts_http::surfaces::SurfaceHost::build(
            settings.clone(),
            mode.clone(),
            registry.clone(),
            sts_http::files::WebRoot::from_env(),
        ));
        let barrier_settings = settings.clone();
        let barrier = ReadBarrier::new(
            Arc::new(PersistencePull(Arc::downgrade(&persistence))),
            Arc::new(move || {
                let n = barrier_settings
                    .value_of("workers.readBarrierTimeoutMs")
                    .as_int() as f64;
                if n >= 1.0 {
                    n
                } else {
                    READ_BARRIER_TIMEOUT_DEFAULT_MS
                }
            }),
        );
        let gate = Arc::new(CommitGate::new(Arc::new(PersistenceCommits(
            Arc::downgrade(&persistence),
        ))));
        Ok(Stack {
            settings,
            mode,
            registry,
            lifecycle,
            handles,
            directory,
            persistence,
            scheduler,
            node,
            http,
            load,
            barrier,
            gate,
            caches,
            runs: run_store,
        })
    }

    /// Opens the store and reads it back — fatal when it cannot be — then
    /// starts the scheduler. Before any listener binds.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn start(&self) -> Result<(), String> {
        self.persistence.start().await?;
        // THE DEFAULT REALM'S KEY SET, before anything is served: read
        // from the store, or made on its first start and stored (a set
        // another process stored first is the one kept) — or, where keys do
        // not persist, made for this run.
        if let Some(sets) = self.persistence.key_sets() {
            sets.open_or_make("").await?;
        }
        // WHICH CLUSTER MODE, and the refusals that are configuration's
        // (`cluster.js`'s `resolve()`), before this node joins.
        let s = &self.settings;
        let (cluster_mode, why) = resolve_mode(&ModeSettings {
            cluster_mode: s.value_of("cluster.mode").as_str().to_string(),
            persistence_mode: s
                .value_of("persistence.mode")
                .as_str()
                .to_string(),
            product: self.mode.current() == "product",
            global_mode: s.value_of("global.mode").as_str().to_string(),
            keys_source: s.value_of("keys.source").as_str().to_string(),
            public_base_url: s
                .value_of("global.publicBaseUrl")
                .as_str()
                .to_string(),
            minted: s.value_of("persistence.minted").as_bool(),
        })
        .map_err(|r| format!("{}cluster: {}", tag(r.code), r.why))?;
        tracing::debug!("cluster: {:?} ({})", cluster_mode, why);
        // A STORE IS SHARED BY COORDINATION (`coordinationRefusal()`):
        // several processes on one store with no change log answer wrongly.
        Topology {
            several: self.node.is_some(),
            coordinates: self.persistence.coordinates(),
        }
        .check()
        .map_err(|r| format!("{}{}", tag(r.code), r.why))?;
        if let Some(node) = &self.node {
            node.set_mode(cluster_mode);
            node.join().await?;
        }
        // The run rows the store gave back: a finished run's row is let
        // go, every other is admitted to the scheduler's watch (the
        // `scheduler.runs` restore hook's work, done here until the store
        // offers the hook).
        for realm in self.registry.list() {
            let id = realm.id.clone();
            for row in self.runs.rows(&id) {
                let key = row
                    .get("runId")
                    .and_then(Json::as_str)
                    .unwrap_or_default()
                    .to_string();
                if self.scheduler.is_expiring_run(&row) {
                    if !key.is_empty() {
                        self.runs.delete(&id, &key);
                    }
                } else {
                    self.scheduler.note_admitted(&id, &row);
                }
            }
        }
        self.scheduler.start(false);
        Ok(())
    }

    /// Every route, behind the HTTP layer.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn router(&self) -> axum::Router {
        let persistence = Arc::downgrade(&self.persistence);
        let routes = axum::Router::new().route(
            "/oauth2/jwks",
            axum::routing::get(move || {
                let persistence = persistence.clone();
                async move { jwks(persistence).await }
            }),
        );
        // OUTSIDE everything else, as Node's request pool and cluster
        // barrier sit in front of the app: the request counts as in flight
        // (#408), waits for what was committed before it (rule 1), and its
        // answer waits for its own writes (rule 2) — each refusal a 503 the
        // client may retry, never a stale or uncommitted answer.
        let load = self.load.clone();
        let barrier = self.barrier.clone();
        let gate = self.gate.clone();
        self.http.wrap(routes).layer(axum::middleware::from_fn(
            move |request: axum::extract::Request,
                  next: axum::middleware::Next| {
                let (load, barrier, gate) =
                    (load.clone(), barrier.clone(), gate.clone());
                async move { guarded(load, barrier, gate, request, next).await }
            },
        ))
    }

    /// Writes what is pending and closes the store.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn stop(&self) {
        self.scheduler.stop();
        if let Some(node) = &self.node {
            if let Err(e) = node.leave().await {
                tracing::warn!("runtime: leaving the cluster failed: {}", e);
            }
        }
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

    async fn jwks_of(stack: &Stack, path: &str) -> (u16, Json) {
        let response = stack
            .router()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status().as_u16();
        assert_eq!(response.headers()["cache-control"], "no-store");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn development_serves_a_jwks_per_realm_made_for_the_run() {
        let stack = Stack::build(settings(
            json!({ "persistence": { "mode": "memory" } }),
        ))
        .unwrap();
        stack.start().await.unwrap();
        stack
            .lifecycle
            .create("acme", "", "", "", &serde_json::Map::new(), false)
            .unwrap();
        let (status, default) = jwks_of(&stack, "/oauth2/jwks").await;
        assert_eq!(status, 200);
        assert_eq!(default["keys"][0]["kty"], "RSA");
        assert_eq!(default["keys"].as_array().unwrap().len(), 9);
        let (status, acme) = jwks_of(&stack, "/realm/acme/oauth2/jwks").await;
        assert_eq!(status, 200);
        assert_ne!(acme["keys"][0]["kid"], default["keys"][0]["kid"]);
        // The same set on the next fetch.
        let (_, again) = jwks_of(&stack, "/realm/acme/oauth2/jwks").await;
        assert_eq!(again, acme);
        stack.stop().await;
    }

    #[test]
    fn an_unknown_store_is_refused() {
        let err = Stack::build(settings(
            json!({ "persistence": { "mode": "tape" } }),
        ))
        .err()
        .unwrap();
        assert!(err.contains("STS-STORE-0003"));
    }
}
