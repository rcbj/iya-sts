// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The store as the composition root wires it: which driver
//! `persistence.mode` names, the database's own trust anchors, this
//! process's ORIGIN in the change log, the change-log pull's interval, and
//! what the scheduler's run rows stand on (`persistence/persistence.js`'s
//! `openStore()`, `databaseTlsCa()`, `adoptStableOrigin()`; the replication
//! module's `intervalMs()`; `cluster/scheduler.ts`'s `runStore` and its
//! `readRuns` dependency).
//!
//! WHAT REPLACED WHAT.
//!
//! * **One driver, two engines.** Node's `persistence_postgres.create()`
//!   takes the engine as an option; here the two are two types,
//!   [`Database`] holding whichever the mode names, so the origin calls —
//!   inherent methods of each, not of the [`Driver`] trait — are reached
//!   without a downcast.
//! * **The origin's renewal timer.** Node renews the claim every
//!   `ORIGIN_RENEW_MS` from a `setInterval` of its own, one of
//!   `tests/no_periodic_timers.js`' permanent exceptions. Rust has one such
//!   timer, the cluster heartbeat, so a clustered node renews the claim
//!   BESIDE ITS HEARTBEAT ([`ClusterNode::on_beat`]), at most once per
//!   `ORIGIN_RENEW_MS`; a process that is not clustered (development mode,
//!   or `cluster.mode=off`) has no heartbeat, and renews it from the
//!   per-process job `persistence.origin-renew` instead — the one job here
//!   Node's scheduler page does not list. Node needs no job because its
//!   timer runs clustered or not; Rust's guard admits no second repeating
//!   timer, so the job is what the timer became. Its prose is not in
//!   `common/prose_locales/scheduler`: those catalogs are harvested from
//!   Node's registry, and a key Node does not register is an orphan
//!   `tests/server_prose_catalogs.js` fails.
//! * **`setOriginLost()`.** Node's driver tells `persistence.js` when a write
//!   finds the origin taken, and the process exits: unclustered with
//!   `STS-STORE-0061` naming the refused write (`STS-CLUSTER-0001`), and on
//!   a clustered node through the cluster's fence handler, which stops it
//!   with `STS-CLUSTER-0011` (`transactionOn()`'s two branches). The Rust
//!   drivers report the refusal through [`Origin`]'s lost hook the same way
//!   ([`OriginKeeper::adopt`] installs it); a renewal that answers "not
//!   held" exits too, as Node's does.
//! * **`checkRenewalTiming()`.** A renewal late to start or slow to answer
//!   by more than half the claim's lifetime is `STS-STORE-0069`. Node names
//!   its event loop's worst delay in the line; a tokio runtime has no one
//!   loop to measure, so the line says what Node's says when it is not
//!   measuring.
//!
//! [`Origin`]: sts_store::origin::Origin

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::time::{Duration, Instant};

use serde_json::Value as Json;
use sts_cluster::membership::{ClusterNode, ClusterStore, FenceReason};
use sts_cluster::schedule::BoxFuture;
use sts_cluster::scheduler::{RunHistory, Scheduler};
use sts_core::errors::codes;
use sts_core::log::tag;
use sts_core::mode::Mode;
use sts_core::realm_store::{partition_id, Reconcile, StoreHandles};
use sts_core::settings::{Settings, Source};
use sts_store::mariadb::MariadbDriver;
use sts_store::origin::{AdoptOptions, Adopted};
use sts_store::persistence::{Persistence, StoreMode};
use sts_store::postgres::PostgresDriver;
use sts_store::side::IndexHooks;
use sts_store::Driver;

/// The scheduler's run store (`cluster/scheduler.ts`'s `runStore`).
pub const RUNS_HANDLE: &str = "scheduler.runs";

/// `ORIGIN_TTL_MS`: how long the origin claim lives unrenewed.
const ORIGIN_TTL_MS: i64 = 30 * 1000;
/// `ORIGIN_RENEW_MS`.
const ORIGIN_RENEW_MS: u64 = 10 * 1000;
/// `ORIGIN_WAIT_MS`: a crashed predecessor's claim is waited out this long.
const ORIGIN_WAIT_MS: i64 = ORIGIN_TTL_MS + 5 * 1000;

/// The database store `persistence.mode` names.
#[derive(Clone)]
pub enum Database {
    Postgres(Arc<PostgresDriver>),
    Mariadb(Arc<MariadbDriver>),
}

impl Database {
    /// The driver persistence writes through.
    // Hot path (asked per store call by its callers' builders): no span.
    pub fn driver(&self) -> Arc<dyn Driver> {
        match self {
            Database::Postgres(p) => p.clone(),
            Database::Mariadb(m) => m.clone(),
        }
    }

    /// The membership, lease and claim tables a clustered node uses.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn cluster_store(&self) -> Arc<dyn ClusterStore> {
        match self {
            Database::Postgres(p) => p.clone(),
            Database::Mariadb(m) => m.clone(),
        }
    }

    async fn adopt(&self, opts: &AdoptOptions) -> Result<Adopted, String> {
        match self {
            Database::Postgres(p) => p.adopt_origin(opts).await,
            Database::Mariadb(m) => m.adopt_origin(opts).await,
        }
        .map_err(|e| e.to_string())
    }

    async fn renew(&self) -> Result<bool, String> {
        match self {
            Database::Postgres(p) => p.renew_origin(ORIGIN_TTL_MS).await,
            Database::Mariadb(m) => m.renew_origin(ORIGIN_TTL_MS).await,
        }
        .map_err(|e| e.to_string())
    }

    /// `setOriginLost()` on whichever driver it is.
    fn set_origin_lost(&self, f: Option<sts_store::origin::OriginLost>) {
        match self {
            Database::Postgres(p) => p.set_origin_lost(f),
            Database::Mariadb(m) => m.set_origin_lost(f),
        }
    }

    async fn release(&self) -> Result<bool, String> {
        match self {
            Database::Postgres(p) => p.release_origin().await,
            Database::Mariadb(m) => m.release_origin().await,
        }
        .map_err(|e| e.to_string())
    }
}

/// `persistence.mode` as this runtime can serve it, or why not.
#[tracing::instrument(level = "debug", skip_all)]
pub fn store_mode(settings: &Settings) -> Result<StoreMode, String> {
    match settings.value_of("persistence.mode").as_str() {
        "memory" => Ok(StoreMode::Memory),
        "ldif" => Ok(StoreMode::Ldif),
        "postgres" => Ok(StoreMode::Postgres),
        "mariadb" => Ok(StoreMode::Mariadb),
        other => Err(format!(
            "{}persistence: \"{}\" is not a mode this module knows (memory, ldif, postgres, mariadb).",
            tag(codes::STS_STORE_0003),
            other
        )),
    }
}

/// The database's own trust anchors (`databaseTlsCa()`): their PEM, and
/// the files they were read from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DatabaseCa {
    pub pem: String,
    pub files: Vec<std::path::PathBuf>,
}

/// `databaseTlsCa()`: the PEM certificates `persistence.databaseTlsCaFile`
/// names (a file, or a directory whose `.crt` and `.pem` files are read in
/// name order), each block that parses kept; none when none is named. A
/// file named and unreadable, or holding no certificate, is
/// `STS-STORE-0079`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn database_tls_ca(settings: &Settings) -> Result<DatabaseCa, String> {
    let file = settings
        .value_of("persistence.databaseTlsCaFile")
        .as_str()
        .trim()
        .to_string();
    if file.is_empty() {
        return Ok(DatabaseCa::default());
    }
    let read = || -> std::io::Result<(String, Vec<std::path::PathBuf>)> {
        let path = std::path::Path::new(&file);
        if !path.is_dir() {
            return Ok((
                std::fs::read_to_string(path)?,
                vec![path.to_path_buf()],
            ));
        }
        let mut names: Vec<String> = std::fs::read_dir(path)?
            .filter_map(Result::ok)
            .filter(|e| e.path().is_file())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| {
                let lower = n.to_ascii_lowercase();
                !n.starts_with('.')
                    && (lower.ends_with(".crt") || lower.ends_with(".pem"))
            })
            .collect();
        names.sort();
        let mut texts = Vec::new();
        let mut files = Vec::new();
        for name in names {
            texts.push(std::fs::read_to_string(path.join(&name))?);
            files.push(path.join(name));
        }
        Ok((texts.join("\n"), files))
    };
    let (text, files) = read().map_err(|e| {
        format!(
            "{}persistence: persistence.databaseTlsCaFile names {}, which cannot be read ({}), so the database \
             connection has no trust anchor anybody chose. Fix the path, or empty the setting to use the \
             default trust store.",
            tag(codes::STS_STORE_0079),
            file,
            e.kind()
        )
    })?;
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut blocks = Vec::new();
    let mut rest = text.as_str();
    while let Some(at) = rest.find(BEGIN) {
        let after = &rest[at + BEGIN.len()..];
        let Some(end) = after.find(END) else {
            break;
        };
        // `[\s\S]+?`: at least one character between the markers.
        if end > 0 {
            blocks
                .push(rest[at..at + BEGIN.len() + end + END.len()].to_string());
        }
        rest = &after[end + END.len()..];
    }
    let good: Vec<&str> = blocks
        .iter()
        .filter(|pem| sts_pki::x509::Certificate::from_pem(pem).is_ok())
        .map(String::as_str)
        .collect();
    if good.is_empty() {
        return Err(format!(
            "{}persistence: persistence.databaseTlsCaFile names {}, which holds no PEM certificate ({} block(s) \
             found, none parsed), so the database connection has no trust anchor anybody chose.",
            tag(codes::STS_STORE_0079),
            file,
            blocks.len()
        ));
    }
    Ok(DatabaseCa {
        pem: good.join("\n") + "\n",
        files,
    })
}

/// The database `persistence.mode` names, its pool not yet dialled. Whether
/// the server's certificate is verified is the setting AS THE MODE LETS IT
/// BE: product reads `persistence.databaseTlsRejectUnauthorized=false` as
/// true, and says so once (`STS-CORE-0106`), as Node's `config.value()`
/// does.
#[tracing::instrument(level = "debug", skip_all)]
pub fn open_database(
    settings: &Settings,
    mode: &Mode,
    store: StoreMode,
) -> Result<Option<Database>, String> {
    if !store.is_database() {
        return Ok(None);
    }
    let url = settings.value_of("persistence.databaseUrl");
    let verify = mode
        .value_in_force("persistence.databaseTlsRejectUnauthorized")
        .as_bool();
    // Read once, before the pool exists, so an unusable file is the fatal
    // refusal its message is written for (`openStore()`).
    let ca = database_tls_ca(settings)?;
    Ok(Some(match store {
        StoreMode::Mariadb => Database::Mariadb(Arc::new(
            MariadbDriver::new(url.as_str(), verify, &ca.pem, 10)
                .map_err(|e| e.to_string())?,
        )),
        _ => Database::Postgres(Arc::new(
            PostgresDriver::with_ca_files(url.as_str(), verify, &ca.files, 10)
                .map_err(|e| e.to_string())?,
        )),
    }))
}

/// `intervalMs()`: how often the change log is pulled. A store that sends
/// no nudge is pulled every second (rcbj on #677) unless somebody set the
/// interval, which then stands; otherwise the setting, `|| 5000`, floored
/// at 250 ms.
// Hot path (asked at every scheduling of the pull): no span.
pub fn pull_interval_ms(
    settings: &Settings,
    without_nudge: Option<u64>,
) -> f64 {
    if let Some(ms) = without_nudge {
        if matches!(
            settings.source_named("persistence.pollInterval"),
            Source::Default | Source::Defaults
        ) {
            return ms as f64;
        }
    }
    let n = settings.value_of("persistence.pollInterval").as_int();
    (if n == 0 { 5000 } else { n } as f64).max(250.0)
}

/// THIS PROCESS'S ORIGIN, its claim adopted at the store's opening and
/// renewed while it runs (`adoptStableOrigin()`, `releaseOrigin()`).
pub struct OriginKeeper {
    db: Database,
    /// `<cluster.nodeName or the host name>:front`.
    name: String,
    /// The membership this process will join under, or '' unclustered.
    node_id: String,
    adopted: Mutex<Option<Adopted>>,
    /// When the last renewal STARTED.
    renewed_at: Mutex<Option<Instant>>,
    /// The renewal before it had started (`originRenewStartedAt`), for
    /// `checkRenewalTiming()`; `None` before the first.
    previous_start: Mutex<Option<Instant>>,
    /// The clustered node whose fence handler a lost origin is reported to.
    node: OnceLock<Weak<ClusterNode>>,
}

/// `originLost()`: unclustered, the refused write is logged under
/// STS-STORE-0061 and the process exits; on a clustered node the cluster's
/// fence handler decides, and a fence that is not one lease's is fatal
/// (STS-CLUSTER-0011).
fn origin_lost(node: Option<Arc<ClusterNode>>, refusal: &str) {
    if let Some(node) = node {
        node.when_fenced(FenceReason::Node, &[], refusal);
        return;
    }
    tracing::error!(
        "{}persistence: this process lost its origin ({}). Another process now holds it and writes under it, so \
         this one stops rather than go on refusing every write.",
        tag(codes::STS_STORE_0061),
        refusal
    );
    std::process::exit(1);
}

/// `checkRenewalTiming()`: a renewal that started late (after the one
/// before it plus `ORIGIN_RENEW_MS`) or took long to answer, by more than
/// half the claim's lifetime, is STS-STORE-0069. Answers whether it warned.
// Hot path (every renewal): no span.
pub fn check_renewal_timing(
    previous: Option<Instant>,
    started: Instant,
    answered: Instant,
) -> bool {
    let half = ORIGIN_TTL_MS as f64 / 2.0;
    let late = previous.map_or(0.0, |p| {
        (started.duration_since(p).as_secs_f64() * 1000.0
            - ORIGIN_RENEW_MS as f64)
            .round()
    });
    let slow =
        (answered.duration_since(started).as_secs_f64() * 1000.0).round();
    if late <= half && slow <= half {
        return false;
    }
    tracing::warn!(
        "{}persistence: the renewal of this process's origin claim started {} ms late and took {} ms to answer, \
         against a {} ms claim. The event loop's worst delay since the last report was not measured — the loop \
         was not the cause; the renewal waited on its connection or the database.",
        tag(codes::STS_STORE_0069),
        late.max(0.0),
        slow,
        ORIGIN_TTL_MS
    );
    true
}

impl OriginKeeper {
    /// The origin of the one process this runtime is: the front's slot.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(db: Database, node_name: &str, node_id: &str) -> Arc<Self> {
        Arc::new(OriginKeeper {
            db,
            name: format!("{}:front", node_name),
            node_id: node_id.to_string(),
            adopted: Mutex::new(None),
            renewed_at: Mutex::new(None),
            previous_start: Mutex::new(None),
            node: OnceLock::new(),
        })
    }

    /// `adoptStableOrigin()`: after the store is open and before anything
    /// reads the origin. Not taking it is a warning (`STS-STORE-0060`) and
    /// this process writes under its random origin; a store that cannot
    /// answer is fatal, as Node's chain rejects.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn adopt(&self) -> Result<(), String> {
        // Told before the adoption, as `adoptStableOrigin()` tells it.
        let node = self.node.get().cloned();
        self.db.set_origin_lost(Some(Arc::new(move |refusal: &str| {
            origin_lost(node.as_ref().and_then(Weak::upgrade), refusal);
        })));
        let a = self
            .db
            .adopt(&AdoptOptions {
                name: self.name.clone(),
                ttl_ms: ORIGIN_TTL_MS,
                wait_ms: ORIGIN_WAIT_MS,
                node_id: self.node_id.clone(),
            })
            .await?;
        if !a.adopted {
            tracing::warn!(
                "{}persistence: this process did not take the stable origin for \"{}\" ({}) and writes under {}. \
                 What it writes to the per-process stores (audit, counters) is kept, and read by the other \
                 processes as a contribution.",
                tag(codes::STS_STORE_0060),
                self.name,
                a.why,
                a.origin
            );
        } else {
            tracing::info!(
                "persistence: this process writes as origin {}{}{}; what that origin wrote before a restart is \
                 restored as this process's own.",
                a.origin,
                if a.took_over_from.is_empty() {
                    String::new()
                } else {
                    format!(
                        ", taken over from {}, whose node membership has left or expired",
                        a.took_over_from
                    )
                },
                if a.waited_ms > 1000 {
                    format!(
                        ", after waiting {} s for the previous holder's claim to lapse",
                        (a.waited_ms as f64 / 1000.0).round()
                    )
                } else {
                    String::new()
                }
            );
            *self
                .renewed_at
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(Instant::now());
        }
        *self.adopted.lock().unwrap_or_else(PoisonError::into_inner) = Some(a);
        Ok(())
    }

    /// Whether a stable origin is held.
    // Hot path (asked by the renewal at every beat): no span.
    pub fn holds(&self) -> bool {
        self.adopted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|a| a.adopted)
    }

    /// One renewal, if `ORIGIN_RENEW_MS` has passed since the last began:
    /// "not held" exits the process (`STS-STORE-0061`), a store that does
    /// not answer is a warning (`STS-STORE-0062`) — the claim outlives a
    /// short outage, and every write checks it anyway.
    // Hot path (every heartbeat): no span.
    pub async fn renew_due(&self) {
        if !self.holds() {
            return;
        }
        let started = Instant::now();
        {
            let mut at = self
                .renewed_at
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if at.is_some_and(|t| {
                t.elapsed() < Duration::from_millis(ORIGIN_RENEW_MS)
            }) {
                return;
            }
            *at = Some(started);
        }
        let previous = self
            .previous_start
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .replace(started);
        let origin = self
            .adopted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|a| a.origin.clone())
            .unwrap_or_default();
        let renewed = self.db.renew().await;
        check_renewal_timing(previous, started, Instant::now());
        match renewed {
            Ok(true) => {}
            Ok(false) => {
                tracing::error!(
                    "{}persistence: this process lost its origin (the claim on {} could not be renewed). Another \
                     process now holds it and writes under it, so this one stops rather than go on refusing every \
                     write.",
                    tag(codes::STS_STORE_0061),
                    origin
                );
                std::process::exit(1);
            }
            Err(e) => tracing::warn!(
                "{}persistence: the claim on origin {} could not be renewed just now: {}",
                tag(codes::STS_STORE_0062),
                origin,
                e
            ),
        }
    }

    /// `releaseOrigin()`: the claim given back after the last write made
    /// under it, so the process that replaces this one takes it at once.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn release(&self) {
        if !self.holds() {
            return;
        }
        if let Err(e) = self.db.release().await {
            tracing::debug!("persistence: the origin was not released: {}", e);
        }
    }

    /// Renews beside every heartbeat of a clustered node.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn ride_on(self: &Arc<Self>, node: &Arc<ClusterNode>) {
        // A lost origin on a clustered node is the cluster's to decide.
        let _first = self.node.set(Arc::downgrade(node));
        let me = Arc::downgrade(self);
        node.on_beat(Arc::new(move || {
            let me = me.clone();
            Box::pin(async move {
                if let Some(me) = me.upgrade() {
                    me.renew_due().await;
                }
            })
        }));
    }

    /// The per-process job that renews it where no heartbeat runs.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn renew_job(
        self: &Arc<Self>,
        clustered: bool,
    ) -> sts_cluster::schedule::JobSpec {
        let mut job = sts_cluster::schedule::JobSpec::new(
            "persistence.origin-renew",
            "Origin claim renewal",
            "Renews this process's claim on its stable origin in the change log (#617, #884), so that no other \
             process can take it while this one writes under it. A clustered node renews it beside its \
             heartbeat instead.",
            "persistence/persistence.js",
            sts_cluster::schedule::Schedule::Every(Arc::new(|| {
                ORIGIN_RENEW_MS as f64
            })),
        );
        job.kind = sts_cluster::schedule::Kind::PerProcess;
        job.quiet = true;
        let watched = Arc::downgrade(self);
        job.off = Some(Arc::new(move |_realm: &str| {
            Ok(match watched.upgrade() {
                _ if clustered => {
                    "this node renews its origin beside its heartbeat"
                        .to_string()
                }
                Some(k) if k.holds() => String::new(),
                _ => "this process holds no stable origin".to_string(),
            })
        }));
        let owner = Arc::downgrade(self);
        job.run = Some(Arc::new(move |_ctx| {
            let owner = owner.clone();
            Box::pin(async move {
                if let Some(k) = owner.upgrade() {
                    k.renew_due().await;
                }
                Ok(Json::Null)
            })
        }));
        job
    }
}

/// `sortBy()` of the run store: a run row's start, queue or end instant,
/// the column `/admin/scheduler`'s newest window is read by (#820, #883).
// Hot path (every run row a flush writes): no span.
pub fn run_sort_of(row: &Json, _key: &str) -> Option<Json> {
    if row.get("kind").and_then(Json::as_str) != Some("run") {
        return None;
    }
    let number = |k: &str| -> f64 {
        match row.get(k) {
            Some(Json::Number(n)) => n.as_f64().unwrap_or(0.0),
            Some(Json::String(s)) => s.trim().parse().unwrap_or(0.0),
            _ => 0.0,
        }
    };
    let at = [number("startedAt"), number("queuedAt"), number("endedAt")]
        .into_iter()
        .find(|n| *n != 0.0 && !n.is_nan())
        .unwrap_or(0.0);
    (at > 0.0).then(|| Json::from(at))
}

/// What the run store declares beside its rows (`realms.map()`'s options
/// for `scheduler.runs`): its sort row, and that a start reads only its
/// rows with no expiry (#883).
#[tracing::instrument(level = "debug", skip_all)]
pub fn configure_minted(minted: &sts_store::minted::Minted) {
    minted.set_index_hooks(
        RUNS_HANDLE,
        IndexHooks {
            sort_of: Some(Arc::new(run_sort_of)),
            ..IndexHooks::default()
        },
    );
    minted.set_restore_expiring(RUNS_HANDLE, false);
}

/// The run store's `reconcile.restore`: every row admitted from outside
/// this process — read back at a start, or brought by the change log — is
/// shown to the scheduler's watch (#623), and a FINISHED interval run is not
/// held (#883). Node also deletes a copy already held; this rule cannot, so
/// such a copy stays until the scheduler releases it.
pub struct RunsReconcile(pub Arc<OnceLock<Weak<Scheduler>>>);

impl Reconcile<Json> for RunsReconcile {
    fn restore(
        &self,
        _key: &str,
        incoming: Json,
        _held: Option<&Json>,
        realm: &str,
    ) -> Result<Option<Json>, String> {
        let Some(scheduler) = self.0.get().and_then(Weak::upgrade) else {
            return Ok(Some(incoming));
        };
        scheduler.note_admitted(realm, &incoming);
        if scheduler.is_expiring_run(&incoming) {
            return Ok(None);
        }
        Ok(Some(incoming))
    }
}

/// The durable run history (#883): the scheduler's `readRuns` and
/// `newestRuns` over minted persistence, and the held copies dropped and
/// admitted without being journalled.
pub struct MintedRunHistory {
    pub persistence: Weak<Persistence>,
    pub handles: Arc<StoreHandles>,
}

impl RunHistory for MintedRunHistory {
    fn persisted(&self) -> bool {
        self.persistence
            .upgrade()
            .is_some_and(|p| p.minted().is_some())
    }

    fn read_runs(
        &self,
        realm: &str,
        ids: Vec<String>,
    ) -> BoxFuture<'_, Result<Option<HashMap<String, Json>>, String>> {
        let realm = realm.to_string();
        Box::pin(async move {
            let Some(p) = self.persistence.upgrade() else {
                return Ok(None);
            };
            let Some(minted) = p.minted() else {
                return Ok(None);
            };
            minted
                .read_many(&p.data_keys(), RUNS_HANDLE, &realm, &ids)
                .await
                .map(Some)
        })
    }

    fn drop_held(&self, realm: &str, key: &str) -> bool {
        let realm = partition_id(realm);
        if let Some(minted) =
            self.persistence.upgrade().and_then(|p| p.minted())
        {
            if minted.journalled(RUNS_HANDLE, realm, key) {
                return false;
            }
        }
        let Some(h) = self.handles.handle_for(RUNS_HANDLE) else {
            return false;
        };
        let gone = h.access.read(realm, key).is_some();
        h.access.remove(realm, key);
        gone
    }

    fn restore_row(&self, realm: &str, key: &str, row: Json) {
        if let Some(h) = self.handles.handle_for(RUNS_HANDLE) {
            h.access.restore(realm, key, row);
        }
    }

    /// `Scheduler.defaultDeps()`'s `newestRuns`: each realm's newest
    /// `limit` run rows by the store's sort index (`minted.newestAsync`),
    /// so the page lists the runs the store holds and not only the ones
    /// this process does. A realm whose read fails is that realm's loss
    /// only; no minted store is `None`, the list being the map's.
    fn newest_runs(
        &self,
        realms: Vec<String>,
        limit: usize,
    ) -> BoxFuture<'_, Result<Option<Vec<Json>>, String>> {
        Box::pin(async move {
            let Some(p) = self.persistence.upgrade() else {
                return Ok(None);
            };
            let Some(minted) = p.minted() else {
                return Ok(None);
            };
            let keys = p.data_keys();
            let mut out = Vec::new();
            for realm in realms {
                let rows = match minted
                    .newest(&keys, RUNS_HANDLE, &realm, limit as i64)
                    .await
                {
                    Ok(rows) => rows,
                    Err(e) => {
                        tracing::debug!(
                            "Caught in Scheduler.defaultDeps(): {}",
                            e
                        );
                        continue;
                    }
                };
                out.extend(rows.into_iter().map(|(_, v)| v).filter(|v| {
                    v.get("kind").and_then(Json::as_str) == Some("run")
                }));
            }
            Ok(Some(out))
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)] // tests

    use serde_json::json;

    use super::*;

    fn settings(operator: Json) -> Settings {
        Settings::new(operator, HashMap::new())
    }

    #[test]
    fn a_renewal_late_or_slow_by_half_a_claim_is_warned() {
        // `checkRenewalTiming()`: 15 s is half of the 30 s claim.
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        assert!(!check_renewal_timing(None, at(0), at(15_000)));
        assert!(check_renewal_timing(None, at(0), at(15_001)));
        assert!(!check_renewal_timing(Some(at(0)), at(25_000), at(25_010)));
        assert!(check_renewal_timing(Some(at(0)), at(25_001), at(25_010)));
        // A renewal that came EARLY is not late.
        assert!(!check_renewal_timing(Some(at(0)), at(1_000), at(1_010)));
    }

    #[test]
    fn a_run_sorts_by_its_first_instant() {
        assert_eq!(
            run_sort_of(&json!({"kind":"run","queuedAt":5,"endedAt":9}), ""),
            Some(json!(5.0))
        );
        assert_eq!(
            run_sort_of(&json!({"kind":"run","startedAt":"7"}), ""),
            Some(json!(7.0))
        );
        assert_eq!(
            run_sort_of(&json!({"kind":"leader","startedAt":1}), ""),
            None
        );
        assert_eq!(run_sort_of(&json!({"kind":"run"}), ""), None);
    }

    #[test]
    fn a_nudgeless_store_is_pulled_every_second_unless_set() {
        assert_eq!(pull_interval_ms(&settings(json!({})), Some(1000)), 1000.0);
        assert_eq!(pull_interval_ms(&settings(json!({})), None), 5000.0);
        let set = settings(json!({"persistence": {"pollInterval": 100}}));
        assert_eq!(pull_interval_ms(&set, Some(1000)), 250.0);
        let zero = settings(json!({"persistence": {"pollInterval": 0}}));
        assert_eq!(pull_interval_ms(&zero, None), 5000.0);
    }

    #[test]
    fn an_unknown_store_and_an_unreadable_ca_are_refused() {
        let err =
            store_mode(&settings(json!({"persistence": {"mode": "tape"}})))
                .unwrap_err();
        assert!(err.contains("STS-STORE-0003"));
        assert_eq!(
            store_mode(&settings(json!({"persistence": {"mode": "mariadb"}})))
                .unwrap(),
            StoreMode::Mariadb
        );
        let err = database_tls_ca(&settings(json!({"persistence": {
            "databaseTlsCaFile": "/nonexistent/ca.pem" }})))
        .unwrap_err();
        assert!(err.contains("STS-STORE-0079"));
        assert_eq!(
            database_tls_ca(&settings(json!({}))).unwrap(),
            DatabaseCa::default()
        );
    }
}
