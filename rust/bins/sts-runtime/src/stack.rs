// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The composition root (`common/protocol_stack.ts`'s Rust counterpart,
//! rust/DESIGN.md section 4.2): the shared services built in dependency
//! order, then — in later phases — the families in the order of the root
//! `CLAUDE.md` table.
//!
//! What phase 3 builds: the settings and the mode; the realm registry and
//! the realms' lifecycle, which is the settings' realm layer; the declared
//! stores; persistence (memory, ldif, postgres or mariadb, `store.rs`) over
//! the directory, with this process's origin adopted the moment the store
//! is open; the cluster node where the mode clusters; the scheduler —
//! leading at once in a service of one process — with its run history over
//! minted persistence; and the HTTP layer every route sits behind, its read
//! barrier a change-log pull that started after the request. No protocol
//! family is served yet, so every path but the shells, `/web` and
//! `/oauth2/jwks` answers the ordinary 404.

use std::sync::{Arc, OnceLock, Weak};

use serde_json::Value as Json;
use sts_cluster::coordination::{
    ChangePull, CommitGate, CommitLog, ReadBarrier, Topology,
    READ_BARRIER_TIMEOUT_DEFAULT_MS,
};
use sts_cluster::membership::ClusterNode;
use sts_cluster::membership::{resolve_mode, ClusterMode, ModeSettings};
use sts_cluster::schedule::BoxFuture;
use sts_cluster::schedule::{compare_rows, Schedules};
use sts_cluster::scheduler::{Deps, Extras, RuntimeLoad, Scheduler};
use sts_core::errors::codes;
use sts_core::log::tag;
use sts_core::mode::Mode;
use sts_core::realm::{RealmRegistry, SettingsEnvironment};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{RealmMap, SharedMap, StoreHandles, StoreSpec};
use sts_core::settings::Settings;
use sts_crypto::random::random_uuid;
use sts_store::ldif_driver::LdifDriver;
use sts_store::persistence::{
    MemoryDirectory, Persistence, StoreHooks, StoreMode,
};
use sts_store::Driver;

use crate::solo::{LocalClaims, LocalClock, LogAudit, RunStore, SoloCluster};
use crate::store::{
    open_database, pull_interval_ms, store_mode, MintedRunHistory,
    OriginKeeper, RunsReconcile, RUNS_HANDLE,
};

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
    /// This process's origin in the change log; `None` without a database.
    pub origin: Option<Arc<OriginKeeper>>,
    /// The cluster mode the settings resolved to, and why.
    pub cluster_mode: (ClusterMode, String),
    /// The sign-on session, the credentials and `/authn-api` with the
    /// sign-in surface's shells (`8` and `8-api`, #444 phase 5).
    pub signin: sts_authn_api::wiring::SignInStack,
    /// `/authn-api`'s router and the authorization server's, put behind
    /// the HTTP layer.
    pub authn_routes: axum::Router,
    /// The authorization server (`9`, #444 phase 5).
    pub oauth: Arc<crate::oauth::OAuthStack>,
    /// Certificate enrollment's stores (#444 phase 6): ACME, EST's nonces
    /// and SCEP's transactions, declared before the store opens.
    pub enroll: sts_enroll::wiring::EnrollStack,
    /// The cluster claims the enrollment credentials are spent once
    /// through.
    pub claims: Arc<dyn sts_cluster::scheduler::Claims>,
    /// The certificate authority (#444 phase 6), made once the store is
    /// open: its rows are the keystore's.
    pub pki: OnceLock<Arc<sts_pki::authority::Authority>>,
    /// `/admin-api` and `/account-api` (#444 phase 5's `apis` slice).
    pub admin: Arc<crate::admin_api::AdminStack>,
    /// `tls.listenerKeys` (#162, #264): each node's own listener key, kept
    /// where minted state persists, keyed `<unit>@<node>`.
    pub listener_keys: SharedMap<Json>,
    /// `cluster.nodeName`, else the host name.
    pub node_name: String,
}

/// The change-log pull the read barrier waits on: `syncNow()`, a pull that
/// STARTED after the request was asked about, so every row committed
/// before it is visible to that pull's snapshots. Not caught up within the
/// replication's own deadline is said so (`STS-STORE-0039`), and the
/// barrier asks again until `workers.readBarrierTimeoutMs`.
struct PersistencePull(Weak<Persistence>);

impl ChangePull for PersistencePull {
    fn pull(&self) -> BoxFuture<'_, Result<bool, String>> {
        let p = self.0.upgrade();
        Box::pin(async move {
            let Some(p) = p else {
                return Ok(true);
            };
            Ok(match p.sync_now().await {
                Some(synced) => synced.caught_up || !synced.coordinating,
                // Nothing to coordinate with: nothing to wait for.
                None => true,
            })
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

/// A node id for this process: a UUID made per start, as Node's
/// `plannedNodeId()` is.
fn node_id() -> Result<String, String> {
    random_uuid().map_err(|e| format!("no random bytes for the node id: {}", e))
}

/// `cluster.js`'s `resolve()`: which cluster mode, and the refusals that
/// are configuration's. Pure: reads the settings.
fn cluster_mode(
    settings: &Settings,
    mode: &Mode,
) -> Result<(ClusterMode, String), String> {
    let s = settings;
    resolve_mode(&ModeSettings {
        cluster_mode: s.value_of("cluster.mode").as_str().to_string(),
        persistence_mode: s.value_of("persistence.mode").as_str().to_string(),
        product: mode.current() == "product",
        global_mode: s.value_of("global.mode").as_str().to_string(),
        keys_source: s.value_of("keys.source").as_str().to_string(),
        public_base_url: s
            .value_of("global.publicBaseUrl")
            .as_str()
            .to_string(),
        minted: s.value_of("persistence.minted").as_bool(),
    })
    .map_err(|r| format!("{}cluster: {}", tag(r.code), r.why))
}

/// `GET /oauth2/jwks`: the ambient realm's published keys as Node's
/// `sendJwks()` builds them (`sts_oauth::jwks`: the signature policy, the
/// Root after the chain, the standby generations), served `no-store` like
/// every document that carries a key, pretty-printed as Node's
/// `JSON.stringify(…, null, 2)`. A realm's set is made on its first use;
/// one that cannot be read or made is answered 500 with `STS-OAUTH-0184`,
/// Node's answer when the JWKS cannot be built.
async fn jwks(
    persistence: Weak<Persistence>,
    settings: Arc<Settings>,
    mode: Arc<Mode>,
) -> axum::response::Response {
    use axum::http::{header, StatusCode};
    use axum::response::IntoResponse;
    let realm = sts_core::realm::current_id();
    let sets = persistence.upgrade().and_then(|p| p.key_sets());
    let built = match sets {
        Some(sets) => sets.open_or_make(&realm).await.and_then(|set| {
            let now_ms = chrono::Utc::now().timestamp_millis() as f64;
            let sources = sts_oauth::jwks::StoredSources {
                sets: sets.clone(),
                realm: realm.clone(),
                now_ms,
            };
            let policy =
                sts_oauth::jwks::JwksPolicy::from_settings(&settings, &mode);
            sts_oauth::jwks::jwks_keys(&sts_oauth::jwks::JwksInputs {
                blob: &set.blob,
                pq_keys: None,
                sources: &sources,
                policy: &policy,
                now_ms,
            })
        }),
        None => Err("no key set is held for this realm".to_string()),
    }
    .map(sts_oauth::jwks::jwks_body);

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

/// 503 with `Retry-After`, marked with the refusal's code: rule 1's read
/// barrier (`codes::STS_WORKER_0053`) or rule 2's commit gate
/// (`codes::STS_STORE_0066`), each named where it is called.
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
    // The barrier's one refusal: never a stale answer.
    if barrier.wait().await.is_err() {
        return unavailable(codes::STS_WORKER_0053);
    }
    let before = gate.mark();
    let response = next.run(request).await;
    // The gate's one refusal: never the success of an uncommitted write.
    match gate.hold(before).await {
        Ok(()) => response,
        Err(_) => unavailable(codes::STS_STORE_0066),
    }
}

impl Stack {
    /// Builds the shared services from the settings. Nothing is opened or
    /// started here; [`Stack::start`] does that.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn build(settings: Arc<Settings>) -> Result<Stack, String> {
        let mode = Mode::shared(settings.clone());
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
        // A database store: postgres, or the same store on MariaDB (#677).
        let database = open_database(&settings, &mode, chosen)?;
        let driver: Option<Arc<dyn Driver>> = match chosen {
            StoreMode::Postgres | StoreMode::Mariadb => {
                database.as_ref().map(|d| d.driver())
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
            ..StoreSpec::persisted(RUNS_HANDLE)
        };
        // Every row admitted from outside this process is shown to the
        // scheduler's watch, and a finished interval run is not held (the
        // `scheduler.runs` reconcile, #623 and #883).
        let runs = RealmMap::with_reconcile(
            &lifecycle,
            &handles,
            spec,
            Some(Arc::new(RunsReconcile(scheduler_slot.clone()))),
        );
        let run_store = Arc::new(RunStore { rows: runs });
        // Declared before the store opens, so its rows are restored.
        let listener_keys =
            SharedMap::new(&handles, StoreSpec::persisted("tls.listenerKeys"));
        let host = std::env::var("HOSTNAME")
            .unwrap_or_else(|_| "localhost".to_string());
        let node_name = {
            let configured = settings
                .value_of("cluster.nodeName")
                .as_str()
                .trim()
                .to_string();
            if configured.is_empty() {
                host.clone()
            } else {
                configured
            }
        };
        // WHICH CLUSTER MODE (`resolve()`), and the refusals that are
        // configuration's: several nodes share a database store in
        // active-passive or active-active mode; anything else is one
        // process, which leads at once.
        let resolved = cluster_mode(&settings, &mode)?;
        let clustered = resolved.0 != ClusterMode::Off;
        let planned = node_id()?;
        let node: Option<Arc<ClusterNode>> =
            database.as_ref().filter(|_| clustered).map(|d| {
                ClusterNode::new(
                    d.cluster_store(),
                    &planned,
                    &node_name,
                    settings.value_of("cluster.heartbeatMs").as_int() as f64,
                    settings.value_of("cluster.nodeTtlMs").as_int() as f64,
                    Arc::new(|code: &'static str, why: String| {
                        tracing::error!("{}cluster: {}", tag(code), why);
                        std::process::exit(1);
                    }),
                )
            });
        // THIS PROCESS'S ORIGIN (`adoptStableOrigin()`): the front's slot of
        // this node, joined under the membership planned above — '' with
        // clustering off, where nothing is taken over.
        let origin = database.as_ref().map(|d| {
            OriginKeeper::new(
                d.clone(),
                &node_name,
                if clustered { &planned } else { "" },
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
        let enroll_claims = claims.clone();
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
            // The durable run history (#883): a run row the map does not
            // hold — a finished interval run, which a start does not read
            // back — is read from minted persistence by id. Cells (#98) are
            // not ported.
            Extras {
                loads: Some(load.clone()),
                history: Some(Arc::new(MintedRunHistory {
                    persistence: Arc::downgrade(&persistence),
                    handles: handles.clone(),
                })),
                cells_multi: None,
            },
        );
        if scheduler_slot.set(Arc::downgrade(&scheduler)).is_err() {
            return Err("the scheduler was built twice".to_string());
        }
        scheduler.register_history_job()?;
        // Applies, in this process, what every other process committed to
        // the change log since this one last looked: per process, recorded
        // quietly, on persistence.pollInterval — every second on a store
        // that sends no nudge, unless the interval was set (`intervalMs()`).
        let without_nudge = database
            .as_ref()
            .and_then(|d| d.driver().dialect())
            .and_then(|dialect| dialect.poll_without_nudge_ms());
        let mut pull = sts_cluster::schedule::JobSpec::new(
            "persistence.change-log-pull",
            "Change-log pull",
            "Applies, in this process, what every other process has committed to the change log since this one \
             last looked. The change log is the contract.",
            "persistence/persistence_replication.js",
            sts_cluster::schedule::Schedule::Every({
                let settings = settings.clone();
                Arc::new(move || pull_interval_ms(&settings, without_nudge))
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
        if let Some(origin) = &origin {
            scheduler.register(origin.renew_job(clustered))?;
            if let Some(n) = &node {
                origin.ride_on(n);
            }
        }
        // THE STORE'S LIFE, AT THE POINTS ONLY THIS ROOT CAN FILL: the
        // origin adopted the moment the store is open and before anything
        // reads it; what the run store files beside its rows, and that a
        // start reads only its rows with no expiry (#883), before minted
        // state is restored; and, after the last write and before the pool
        // closes, the cluster left and the origin given back (Node's
        // `stop()` chain).
        let opening = origin.clone();
        let gating = node.clone().map(|n| (n, resolved.0));
        let closing = (origin.clone(), node.clone());
        persistence.set_hooks(StoreHooks {
            after_open: opening.map(|o| {
                let step: sts_store::persistence::StoreStep =
                    Arc::new(move || {
                        let o = o.clone();
                        Box::pin(async move { o.adopt().await })
                    });
                step
            }),
            // THE CLUSTER GATE (`cluster.gate()`, #46): after the origin
            // and before anything is read back, this node joins — and in
            // active-passive mode a standby waits here for the service
            // lease, restoring nothing and binding nothing until it holds
            // it.
            cluster_gate: gating.map(|(n, cluster_mode)| {
                let step: sts_store::persistence::StoreStep =
                    Arc::new(move || {
                        let n = n.clone();
                        Box::pin(async move {
                            n.set_mode(cluster_mode);
                            n.join().await?;
                            if cluster_mode == ClusterMode::ActivePassive {
                                n.wait_for_service_lease().await?;
                            }
                            Ok(())
                        })
                    });
                step
            }),
            configure_minted: Some(Arc::new(crate::store::configure_minted)),
            before_close: Some(Arc::new(move || {
                let (origin, node) = closing.clone();
                Box::pin(async move {
                    if let Some(node) = node {
                        if let Err(e) = node.leave().await {
                            tracing::warn!(
                                "runtime: leaving the cluster failed: {}",
                                e
                            );
                        }
                    }
                    if let Some(origin) = origin {
                        origin.release().await;
                    }
                    Ok(())
                })
            })),
        });
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
        let root = sts_http::files::WebRoot::from_env();
        let version_info = sts_core::version::load(&root.0);
        let version = version_info.version.clone();
        let surfaces = sts_http::surfaces::SurfaceHost::build(
            settings.clone(),
            mode.clone(),
            registry.clone(),
            root,
        );
        http.add_routes(surfaces.clone());
        // THE SIGN-ON SESSION AND THE SIGN-IN SURFACE (#444 phase 5): its
        // stores declared before the store opens, its shells added after
        // the static surfaces', and its jobs on the one scheduler.
        // THE TOKEN REGISTER AND ITS ONE REVOCATION SET (`admin_stats.tokens`,
        // `revokedJtis`), declared before the store opens so a 1.x
        // install's rows are restored, and the session core's revocation
        // at sign-out over it (`sts_oauth::minted::SessionTokens`): in
        // product a sign-out revokes the access tokens of its session
        // (#1449), and RFC 9700's refresh rule always. The OAuth slice's
        // token endpoint is to issue into this same register (one
        // declaration per handle).
        let revoked = sts_oauth::revocation::RevokedTokens::new(
            &lifecycle,
            &handles,
            settings.clone(),
        );
        let tokens = sts_oauth::minted::TokenRegister::new(
            &lifecycle,
            &handles,
            settings.clone(),
            revoked,
        );
        let refresh_settings = settings.clone();
        let records: Arc<dyn sts_authn::ports::Records> =
            Arc::new(sts_oauth::minted::SessionTokens {
                inner: None,
                register: tokens.clone(),
                revoke_refresh_on_logout: Arc::new(move |_client: &str| {
                    refresh_settings
                        .value_of("oauth2.revokeRefreshOnLogout")
                        .as_bool()
                }),
                now_ms: Arc::new(|| chrono::Utc::now().timestamp_millis()),
            });
        let signin = sts_authn_api::wiring::SignInStack::declare(
            sts_authn_api::wiring::RuntimeParts {
                settings: settings.clone(),
                mode: mode.clone(),
                registry: registry.clone(),
                lifecycle: lifecycle.clone(),
                handles: handles.clone(),
                directory: directory.clone(),
                persistence: persistence.clone(),
                version,
                records: Some(records),
            },
        );
        scheduler.register(sts_authn::job::session_expiry_job(
            signin.sessions.clone(),
        ))?;
        scheduler.register(sts_authn::job::account_set_expiry_job(
            signin.sessions.clone(),
        ))?;
        // THE AUTHORIZATION SERVER (`9`, #444 phase 5): its stores declared
        // before the store opens, over the sign-in stack's session core and
        // pending sign-ins, and the live directory.
        let oauth =
            crate::oauth::OAuthStack::declare(crate::oauth::OAuthParts {
                settings: settings.clone(),
                mode: mode.clone(),
                registry: registry.clone(),
                lifecycle: lifecycle.clone(),
                handles: handles.clone(),
                persistence: persistence.clone(),
                live: directory.clone(),
                sessions: signin.sessions.clone(),
                footer: sts_http::footer::facts(&version_info),
                pending: signin.signin.stores.pending.clone(),
                people: Arc::new(sts_authn_api::wiring::DirectoryPorts {
                    directory: directory.clone(),
                    persistence: persistence.clone(),
                    registry: registry.clone(),
                    settings: settings.clone(),
                    mode: mode.clone(),
                }),
                catalogs: Arc::new(sts_http::i18n::Catalogs::load(
                    &sts_http::i18n::Catalogs::dir_in(
                        &sts_http::files::WebRoot::from_env().0,
                    ),
                )),
                tokens: tokens.clone(),
            });
        let authn_routes = signin
            .mount(&http, surfaces.clone(), settings.clone())
            .merge(oauth.router(http.clone()));
        // THE PROTOCOL-INDEPENDENT SIGN-OUT (`common/protocol_stack.ts`'s
        // 23a, second to last): `/logout`, `/logout/signed-out`, and the
        // page's operations behind `/authn-api/logout`.
        let logout = sts_logout::wiring::LogoutStack::build(
            sts_logout::wiring::LogoutParts {
                settings: settings.clone(),
                mode: mode.clone(),
                registry: registry.clone(),
                sessions: signin.sessions.clone(),
                people: signin.people.clone(),
                tokens: Some(tokens),
                pending: signin.signin.stores.pending.clone(),
                http: http.clone(),
                surfaces,
            },
        );
        let authn_routes = authn_routes.merge(logout.mount(&signin.api));
        // THE MANAGEMENT API (`19`, #444 phase 5's `apis` slice): phase 4's
        // router over the runtime's registers, its one store declared
        // before the store opens.
        let admin = crate::admin_api::AdminStack::declare(
            crate::admin_api::AdminParts {
                settings: settings.clone(),
                mode: mode.clone(),
                registry: registry.clone(),
                lifecycle: lifecycle.clone(),
                handles: handles.clone(),
                persistence: persistence.clone(),
                live: directory.clone(),
                oauth: oauth.clone(),
                sessions: signin.sessions.clone(),
                credentials: signin.signin.credentials.clone(),
                facts: signin.signin.facts.clone(),
                catalogs: Arc::new(sts_http::i18n::Catalogs::load(
                    &sts_http::i18n::Catalogs::dir_in(
                        &sts_http::files::WebRoot::from_env().0,
                    ),
                )),
                version: version_info,
                logout: logout.logout.clone(),
            },
        );
        let authn_routes = authn_routes.merge(admin.router());
        let admin_stack = admin;
        let enroll =
            sts_enroll::wiring::EnrollStack::declare(&lifecycle, &handles);
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
            origin,
            cluster_mode: resolved,
            signin,
            authn_routes,
            oauth,
            enroll,
            claims: enroll_claims,
            pki: OnceLock::new(),
            admin: admin_stack,
            listener_keys,
            node_name,
        })
    }

    /// Opens the store and reads it back — fatal when it cannot be — then
    /// starts the scheduler. Before any listener binds.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn start(&self) -> Result<(), String> {
        self.persistence.start().await?;
        // The application register's directory, from what the store gave
        // back (`oauth.rs`).
        self.oauth.reload_directory();
        // THE DEFAULT REALM'S KEY SET, before anything is served: read
        // from the store, or made on its first start and stored (a set
        // another process stored first is the one kept) — or, where keys do
        // not persist, made for this run.
        if let Some(sets) = self.persistence.key_sets() {
            sets.open_or_make("").await?;
        }
        // THE CERTIFICATE AUTHORITY (`pki.start()`, after the keystore and
        // before anything binds): the stored hierarchy read, or built where
        // there is none — off the async threads, a key being a tenth of a
        // second.
        let realms = self.registry.list();
        let authority = crate::pki::authority(
            &self.settings,
            &self.mode,
            self.persistence.key_sets(),
            realms
                .iter()
                .filter(|r| !r.domain.is_empty())
                .map(|r| (r.id.clone(), r.domain.clone()))
                .collect(),
        );
        let realm_ids: Vec<String> =
            realms.iter().map(|r| r.id.clone()).collect();
        let starting = authority.clone();
        tokio::task::spawn_blocking(move || starting.start(&realm_ids))
            .await
            .map_err(|e| e.to_string())?;
        if self.pki.set(authority).is_err() {
            tracing::debug!("pki: the authority was already made.");
        }
        let (cluster_mode, why) = self.cluster_mode.clone();
        tracing::debug!("cluster: {:?} ({})", cluster_mode, why);
        // A STORE IS SHARED BY COORDINATION (`coordinationRefusal()`):
        // several processes on one store with no change log answer wrongly.
        Topology {
            several: self.node.is_some(),
            coordinates: self.persistence.coordinates(),
        }
        .check()
        .map_err(|r| format!("{}{}", tag(r.code), r.why))?;
        // The node joined at the store's cluster gate, before the restore.
        // The run rows the store gave back went through the run store's
        // reconcile as they were restored: each shown to the scheduler's
        // watch, a finished interval run not held.
        self.scheduler.start(false);
        Ok(())
    }

    /// Every route, behind the HTTP layer.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn router(&self) -> axum::Router {
        let persistence = Arc::downgrade(&self.persistence);
        let (settings, mode) = (self.settings.clone(), self.mode.clone());
        let jwks_get = move || {
            let persistence = persistence.clone();
            let (settings, mode) = (settings.clone(), mode.clone());
            async move { jwks(persistence, settings, mode).await }
        };
        // A named authorization server's `jwks_uri` (`/{as}/oauth2/jwks`):
        // the keys are the realm's, whichever server is named.
        let named_jwks = jwks_get.clone();
        let mut routes = self
            .authn_routes
            .clone()
            .route("/oauth2/jwks", axum::routing::get(jwks_get))
            .route(
                "/{as}/oauth2/jwks",
                axum::routing::get(
                    move |axum::extract::Path(_as): axum::extract::Path<
                        String,
                    >| named_jwks(),
                ),
            );
        // `pki/pki_service.ts` (17b): the public revocation surface.
        if let Some(authority) = self.pki.get() {
            routes = routes.merge(crate::pki::routes(
                authority.clone(),
                self.settings
                    .value_of("pki.publishCrlToDirectory")
                    .as_bool(),
            ));
            // ACME, EST and SCEP (23e-g): one registration, issuing through
            // the authority's `issue_enrolled()`.
            let families = self.enroll.families(
                sts_enroll::wiring::RuntimeParts {
                    settings: self.settings.clone(),
                    mode: self.mode.clone(),
                    registry: self.registry.clone(),
                    lifecycle: self.lifecycle.clone(),
                    directory: self.directory.clone(),
                    persistence: self.persistence.clone(),
                    credentials: self.signin.signin.credentials.clone(),
                    claims: self.claims.clone(),
                    http: self.http.clone(),
                },
                authority.clone(),
            );
            // The families' acts on `/admin-api`, once they exist.
            self.admin.families.install(
                authority.clone(),
                families.clone(),
                self.registry.clone(),
            );
            routes = routes.merge(families.router());
        }
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
        // The last flush, then the cluster left and the origin released
        // (the store's `before_close` step), then the pool closed.
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

    #[tokio::test]
    async fn the_authorization_server_is_served() {
        let stack = Stack::build(settings(
            json!({ "persistence": { "mode": "memory" } }),
        ))
        .unwrap();
        stack.start().await.unwrap();
        let response = stack
            .router()
            .oneshot(
                Request::get("/.well-known/oauth-authorization-server")
                    .header("host", "as.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let doc: Json = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(doc["issuer"], "http://as.example");
        assert!(doc["signed_metadata"].is_string());
        // An unknown client is refused at the authorization endpoint.
        let response = stack
            .router()
            .oneshot(
                Request::get(
                    "/oauth2/authorize?client_id=nobody&response_type=code\
                     &redirect_uri=https%3A%2F%2Frp.example%2Fcb",
                )
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert!(response.status() == 302 || response.status() == 400);
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
        // RSA, ES256, ES384, ES512 and ES256K, and the two request-object
        // encryption keys: the EdDSA and Ed448 keys the set holds are left
        // out while keys.eddsaSigning is off, as Node leaves them out.
        assert_eq!(default["keys"].as_array().unwrap().len(), 7);
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
