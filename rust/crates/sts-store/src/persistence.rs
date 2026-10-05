// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The one place the runtime writes anything down (`persistence.js`): what
//! is dirty, when it is flushed, what a flush sends, what happens when it
//! fails, and what is read back at start.
//!
//! * **Writers mark, a flush writes.** The directory, the realm registry and
//!   the runtime overrides each have a dirty bit; the directory also keeps
//!   the keys a writer named, so a flush looks only at those rather than
//!   snapshotting everything ([`crate::shadow::Walk::Keys`]). A realm change
//!   dirties the whole directory, because only a full walk sees a realm
//!   that is gone.
//! * **A flush sends deltas against the shadow** and advances the shadow
//!   only from what it sent, once the write succeeded.
//! * **A failed flush loses nothing**: the dirty bits and keys go back, the
//!   waiters are told, and one retry is armed with a backoff of one second
//!   doubling to thirty. Every writer since is in the next flush anyway.
//! * **A write can be waited for** ([`Persistence::directory_through`]): a
//!   generation counter moves on every mark, and a waiter is answered once
//!   a flush that took that generation committed — or failed.
//! * **At start**, in order: the runtime overrides, the realm registry (each
//!   realm created as RESTORED, so the rules between settings are not asked
//!   again), the directory (a realm not defined is not loaded, and the next
//!   write removes its rows, `STS-STORE-0009`), then the shadow primed from
//!   what was read and a first flush that writes the seeded directory. A
//!   store that cannot be read is FATAL (`STS-STORE-0006`): a process
//!   configured to persist and persisting nothing is the state this exists
//!   to prevent.
//!
//! Postgres, the minted stores, the merge outcomes another node's write
//! decided, and cells are later pieces; this is the memory and ldif half.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError, Weak};

use indexmap::{IndexMap, IndexSet};
use serde_json::{json, Map, Value as Json};
use sts_core::errors::codes;
use sts_core::log::tag;
use sts_core::realm::DEFAULT_ID;
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::settings::Settings;
use tokio::sync::oneshot;

use crate::driver::{Driver, StoreResult};
use crate::model::{DirectoryChange, StoredEntry};
use crate::shadow::{EntryLookup, Shadow, Snapshot, Walk};

const RETRY_FIRST_MS: u64 = 1000;
const RETRY_MAX_MS: u64 = 30_000;

/// The embedded directory, as persistence reads and restores it. Keys are
/// normalised DNs; normalising is the directory's job, not this module's.
pub trait LiveDirectory: EntryLookup + Send + Sync {
    /// Every entry of one realm, keyed by normalised DN, in its order.
    fn realm_entries(&self, realm: &str) -> IndexMap<String, StoredEntry>;
    /// Replaces a realm's whole directory with what the store held.
    fn replace_realm(&self, realm: &str, entries: Vec<StoredEntry>);
    /// Puts what the store decided into the live directory, without
    /// journalling it: an entry another node's write left there, or `None`
    /// for one it deleted.
    fn apply_entry(&self, realm: &str, key: &str, entry: Option<StoredEntry>);
}

/// `persistence.mode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreMode {
    Memory,
    Ldif,
    Postgres,
}

impl StoreMode {
    pub fn as_str(self) -> &'static str {
        match self {
            StoreMode::Memory => "memory",
            StoreMode::Ldif => "ldif",
            StoreMode::Postgres => "postgres",
        }
    }
}

/// What a start read back.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Restored {
    pub entries: usize,
    pub realms: usize,
    pub overrides: usize,
}

/// What [`Persistence::directory_through`] answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Through {
    /// Already written, or nothing is persisted.
    Nothing,
    /// A flush that took the change committed.
    Written,
    /// It failed; the change stays in memory until a retry lands.
    Failed(String),
}

#[derive(Default)]
struct State {
    enabled: bool,
    restoring: bool,
    stopped: bool,
    directory_dirty: bool,
    dirty_keys: IndexSet<String>,
    dirty_everything: bool,
    realms_dirty: bool,
    config_dirty: bool,
    generation: u64,
    committed_at: u64,
    failed_at: u64,
    waiters: Vec<(u64, oneshot::Sender<Through>)>,
    removed_here: HashSet<String>,
    timer: bool,
    retry_armed: bool,
    retry_failures: u32,
    writes: u64,
    failures: u64,
    last_error: String,
    restored: Restored,
    /// The change-log position read before the store was, when this store
    /// coordinates.
    change_from: Option<i64>,
}

/// The persistence of one process.
pub struct Persistence {
    mode: StoreMode,
    driver: Option<Arc<dyn Driver>>,
    settings: Arc<Settings>,
    lifecycle: Arc<RealmLifecycle>,
    directory: Arc<dyn LiveDirectory>,
    state: Mutex<State>,
    shadow: Mutex<Shadow>,
    flush_lock: tokio::sync::Mutex<()>,
    replication: Mutex<Option<Arc<crate::replication::Replication>>>,
    me: Weak<Persistence>,
}

impl Persistence {
    /// Persistence over `driver` (`None` for memory), subscribed to the
    /// realm registry's changes.
    pub fn new(
        mode: StoreMode,
        driver: Option<Arc<dyn Driver>>,
        settings: Arc<Settings>,
        lifecycle: Arc<RealmLifecycle>,
        directory: Arc<dyn LiveDirectory>,
    ) -> Arc<Persistence> {
        let me = Arc::new_cyclic(|me: &Weak<Persistence>| Persistence {
            mode: if driver.is_some() {
                mode
            } else {
                StoreMode::Memory
            },
            driver,
            settings,
            lifecycle: lifecycle.clone(),
            directory,
            state: Mutex::new(State::default()),
            shadow: Mutex::new(Shadow::new()),
            flush_lock: tokio::sync::Mutex::new(()),
            replication: Mutex::new(None),
            me: me.clone(),
        });
        let weak = Arc::downgrade(&me);
        lifecycle.on_change(Arc::new(move |event| {
            let Some(me) = weak.upgrade() else {
                return;
            };
            {
                let mut st = me.state();
                if event.what == "remove" && st.enabled && !st.restoring {
                    st.removed_here.insert(event.id.clone());
                } else if event.what == "create" {
                    st.removed_here.remove(&event.id);
                }
            }
            me.realms_changed();
            me.directory_changed(None);
        }));
        me
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn shadow(&self) -> std::sync::MutexGuard<'_, Shadow> {
        self.shadow.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn mode(&self) -> StoreMode {
        self.mode
    }

    /// Whether anything is being written down at all.
    pub fn enabled(&self) -> bool {
        let st = self.state();
        st.enabled && !st.stopped
    }

    fn flag(&self, key: &str) -> bool {
        self.settings.value_of(key).as_bool()
    }

    fn persists_realms(&self) -> bool {
        self.flag("persistence.realms")
    }

    fn persists_appconfig(&self) -> bool {
        self.flag("persistence.appconfig")
    }

    // -----------------------------------------------------------------
    // Marking.
    // -----------------------------------------------------------------

    /// A directory entry changed (its normalised DN), or `None` for the
    /// whole directory.
    pub fn directory_changed(&self, key: Option<&str>) {
        {
            let mut st = self.state();
            if !st.enabled || st.stopped || st.restoring {
                return;
            }
            st.directory_dirty = true;
            st.generation += 1;
            match key.filter(|k| !k.is_empty()) {
                None => st.dirty_everything = true,
                Some(k) if !st.dirty_everything => {
                    st.dirty_keys.insert(k.to_string());
                }
                Some(_) => {}
            }
        }
        self.schedule();
    }

    /// The realm registry changed.
    pub fn realms_changed(&self) {
        if !self.persists_realms() {
            return;
        }
        {
            let mut st = self.state();
            if !st.enabled || st.stopped || st.restoring {
                return;
            }
            st.realms_dirty = true;
            st.generation += 1;
        }
        self.schedule();
    }

    /// A runtime override changed: on a realm (written on its row) or on
    /// the process.
    pub fn config_changed(&self, realm: Option<&str>) {
        if realm.is_some_and(|r| !r.is_empty()) {
            self.realms_changed();
            return;
        }
        if !self.persists_appconfig() {
            return;
        }
        {
            let mut st = self.state();
            if !st.enabled || st.stopped || st.restoring {
                return;
            }
            st.config_dirty = true;
            st.generation += 1;
        }
        self.schedule();
    }

    /// The generation a waiter waits for: everything marked so far.
    pub fn generation(&self) -> u64 {
        self.state().generation
    }

    fn write_delay_ms(&self) -> u64 {
        if self.mode == StoreMode::Postgres {
            0
        } else {
            self.settings
                .value_of("persistence.writeDelay")
                .as_int()
                .max(0) as u64
        }
    }

    /// One flush, after the write delay: a burst of writes is one write.
    fn schedule(&self) {
        {
            let mut st = self.state();
            if st.timer || st.stopped {
                return;
            }
            st.timer = true;
        }
        let delay = self.write_delay_ms();
        let Some(me) = self.me.upgrade() else {
            return;
        };
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            me.state().timer = false;
            if let Err(e) = me.flush().await {
                tracing::error!(
                    "{}persistence: a scheduled flush failed: {}",
                    tag(codes::STS_STORE_0001),
                    e
                );
            }
        });
    }

    /// The one retry of a failed write, backing off from a second to thirty.
    fn retry_after_failure(&self) {
        let delay = {
            let mut st = self.state();
            if st.retry_armed || st.stopped || !st.enabled {
                return;
            }
            st.retry_armed = true;
            let d =
                (RETRY_FIRST_MS << st.retry_failures.min(5)).min(RETRY_MAX_MS);
            st.retry_failures += 1;
            d
        };
        let Some(me) = self.me.upgrade() else {
            return;
        };
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            me.state().retry_armed = false;
            if let Err(e) = me.flush().await {
                tracing::error!(
                    "{}persistence: a retried flush failed: {}",
                    tag(codes::STS_STORE_0001),
                    e
                );
            }
        });
    }

    fn settle_waiters(&self, error: Option<&str>) {
        let mut st = self.state();
        let committed = st.committed_at;
        let waiters = std::mem::take(&mut st.waiters);
        for (gen, tx) in waiters {
            if committed >= gen {
                let _sent = tx.send(Through::Written).is_ok();
            } else if let Some(e) = error {
                let _sent = tx.send(Through::Failed(e.to_string())).is_ok();
            } else {
                st.waiters.push((gen, tx));
            }
        }
    }

    /// Waits until everything marked up to `target` is written down.
    pub async fn directory_through(&self, target: u64) -> Through {
        let rx = {
            let mut st = self.state();
            if st.committed_at >= target || !st.enabled || st.stopped {
                return Through::Nothing;
            }
            let (tx, rx) = oneshot::channel();
            st.waiters.push((target, tx));
            rx
        };
        if let Some(me) = self.me.upgrade() {
            tokio::spawn(async move {
                if let Err(e) = me.flush().await {
                    tracing::debug!(
                        "persistence: the flush a waiter asked for failed: {}",
                        e
                    );
                }
            });
        }
        rx.await
            .unwrap_or(Through::Failed("the flush was abandoned".to_string()))
    }

    /// Whether a refused write is still waiting for its retry.
    pub fn commit_backlog(&self) -> bool {
        let st = self.state();
        st.enabled && !st.restoring && st.failed_at > st.committed_at
    }

    // -----------------------------------------------------------------
    // The flush.
    // -----------------------------------------------------------------

    fn live_snapshot(&self) -> Snapshot {
        let mut out = Snapshot::new();
        for realm in self.lifecycle.registry().list() {
            out.insert(
                realm.id.clone(),
                self.directory.realm_entries(&realm.id),
            );
        }
        out
    }

    /// Writes what is dirty. Serialised: a flush asked for while one runs
    /// runs after it, and finds only what is still dirty.
    pub async fn flush(&self) -> Result<bool, String> {
        let _guard = self.flush_lock.lock().await;
        let Some(driver) = self.driver.clone() else {
            return Ok(false);
        };
        let (want_dir, want_realms, want_config, taken_at, wanted, removals) = {
            let mut st = self.state();
            if !st.enabled || st.restoring {
                return Ok(false);
            }
            if !st.directory_dirty && !st.realms_dirty && !st.config_dirty {
                st.committed_at = st.generation;
                drop(st);
                self.settle_waiters(None);
                return Ok(false);
            }
            let want_dir = st.directory_dirty;
            let wanted: Option<Vec<String>> =
                (want_dir && !st.dirty_everything && !st.dirty_keys.is_empty())
                    .then(|| st.dirty_keys.iter().cloned().collect());
            if want_dir {
                st.dirty_keys.clear();
                st.dirty_everything = false;
            }
            let out = (
                want_dir,
                st.realms_dirty,
                st.config_dirty,
                st.generation,
                wanted,
                st.removed_here.iter().cloned().collect::<Vec<String>>(),
            );
            st.directory_dirty = false;
            st.realms_dirty = false;
            st.config_dirty = false;
            out
        };
        let realm_ids: Vec<String> = self
            .lifecycle
            .registry()
            .list()
            .iter()
            .map(|r| r.id.clone())
            .collect();
        let snapshot =
            (want_dir && wanted.is_none()).then(|| self.live_snapshot());
        let diff = want_dir.then(|| {
            let shadow = self.shadow();
            match (&snapshot, &wanted) {
                (Some(live), _) => shadow.diff(&Walk::Full(live), &removals),
                (None, Some(keys)) => shadow.diff(
                    &Walk::Keys {
                        realms: &realm_ids,
                        wanted: keys,
                        lookup: self.directory.as_ref(),
                    },
                    &removals,
                ),
                (None, None) => crate::shadow::Diff::default(),
            }
        });
        let realm_delta = want_realms.then(|| {
            self.shadow()
                .realms_delta(&self.lifecycle.rows(), &removals)
        });
        let config_live = self.settings.runtime_overrides();
        let config_delta =
            want_config.then(|| self.shadow().appconfig_delta(&config_live));

        let outcome = self
            .send(
                driver.as_ref(),
                diff.as_ref(),
                realm_delta.as_ref(),
                config_delta.as_ref(),
                &config_live,
            )
            .await;
        match outcome {
            Ok(outcomes) => {
                {
                    let mut shadow = self.shadow();
                    if let Some(d) = &diff {
                        shadow.advance(d);
                    }
                    if let Some(d) = &realm_delta {
                        shadow.advance_realms(d);
                    }
                    if let Some(d) = &config_delta {
                        shadow.advance_appconfig(d);
                    }
                }
                if let Some(d) = &diff {
                    self.apply_outcomes(d, outcomes);
                }
                {
                    let mut st = self.state();
                    st.committed_at = st.committed_at.max(taken_at);
                    for id in &removals {
                        if self.lifecycle.registry().get(id).is_none() {
                            st.removed_here.remove(id);
                        }
                    }
                    st.retry_failures = 0;
                    st.writes += 1;
                    st.last_error.clear();
                }
                self.settle_waiters(None);
                Ok(true)
            }
            Err(e) => {
                {
                    let mut st = self.state();
                    st.failures += 1;
                    st.last_error = e.clone();
                    st.directory_dirty |= want_dir;
                    st.realms_dirty |= want_realms;
                    st.config_dirty |= want_config;
                    if want_dir {
                        match &wanted {
                            Some(keys) if !st.dirty_everything => {
                                for k in keys {
                                    st.dirty_keys.insert(k.clone());
                                }
                            }
                            Some(_) => {}
                            None => st.dirty_everything = true,
                        }
                    }
                    st.failed_at = st.failed_at.max(taken_at);
                }
                self.settle_waiters(Some(&e));
                self.retry_after_failure();
                tracing::error!(
                    "{}persistence: could not write to the {} store: {}. It is retried shortly, and the change \
                     stays in memory until it lands.",
                    tag(codes::STS_STORE_0002),
                    self.mode.as_str(),
                    e
                );
                Err(e)
            }
        }
    }

    async fn send(
        &self,
        driver: &dyn Driver,
        diff: Option<&crate::shadow::Diff>,
        realms: Option<&crate::shadow::RealmsDelta>,
        config: Option<&crate::shadow::AppconfigDelta>,
        config_live: &Map<String, Json>,
    ) -> Result<Vec<crate::model::DirectoryOutcome>, String> {
        let mut outcomes = Vec::new();
        if let Some(d) =
            diff.filter(|d| !d.is_empty() || !d.removed_realms.is_empty())
        {
            let mut change = DirectoryChange {
                touched: d.touched.clone(),
                removed_realms: d.removed_realms.clone(),
                ..DirectoryChange::default()
            };
            change.upserts = d
                .upserts
                .iter()
                .map(|u| crate::model::DirectoryUpsert {
                    realm: u.realm.clone(),
                    key: u.key.clone(),
                    entry: u.entry.clone(),
                    base: u.base.clone(),
                })
                .collect();
            change.deletes = d
                .deletes
                .iter()
                .map(|x| crate::model::DirectoryDelete {
                    realm: x.realm.clone(),
                    key: x.key.clone(),
                })
                .collect();
            // A snapshot driver rewrites a file per realm touched, so it is
            // handed those realms whole.
            let mut all = BTreeMap::new();
            for realm in &d.touched {
                if self.lifecycle.registry().get(realm).is_some()
                    || realm == DEFAULT_ID
                {
                    all.insert(
                        realm.clone(),
                        self.directory
                            .realm_entries(realm)
                            .into_values()
                            .collect(),
                    );
                }
            }
            change.all = all;
            outcomes = driver
                .save_directory(&change)
                .await
                .map_err(|e| e.to_string())?;
        }
        if let Some(delta) = realms {
            driver
                .save_realms_delta(&self.lifecycle.rows(), delta)
                .await
                .map_err(|e| e.to_string())?;
        }
        if let Some(delta) = config {
            driver
                .save_overrides_delta(config_live, delta)
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(outcomes)
    }

    /// What the store decided, applied here: the live directory takes the
    /// stored entry and the shadow is set to it, so the next diff compares
    /// against the truth. A local write made while the flush was out is
    /// marked again and written by the next flush (`STS-STORE-0052` and
    /// `0053` are the store's verdicts).
    fn apply_outcomes(
        &self,
        diff: &crate::shadow::Diff,
        outcomes: Vec<crate::model::DirectoryOutcome>,
    ) {
        for one in outcomes {
            let sent = diff
                .upserts
                .iter()
                .find(|u| u.realm == one.realm && u.key == one.key)
                .map(|u| u.json.clone());
            let live = self
                .directory
                .entry_at(&one.realm, &one.key)
                .map(|e| crate::merge::entry_json(&e).to_string());
            let moved = live.is_some() && live != sent;
            match &one.entry {
                Some(entry) => {
                    self.shadow().set_entry(
                        &one.realm,
                        &one.key,
                        crate::merge::entry_json(entry).to_string(),
                    );
                    if !moved {
                        self.directory.apply_entry(
                            &one.realm,
                            &one.key,
                            Some(entry.clone()),
                        );
                    }
                }
                None => {
                    self.shadow().forget_entry(&one.realm, &one.key);
                    if !moved {
                        self.directory.apply_entry(&one.realm, &one.key, None);
                    }
                }
            }
            if moved {
                // Changed here while the flush was out: written again
                // against what the store now holds.
                self.directory_changed(Some(&one.key));
            }
        }
    }

    // -----------------------------------------------------------------
    // Starting and stopping.
    // -----------------------------------------------------------------

    /// Opens the store and reads back what it holds: the overrides, the
    /// realms, the directory. Fatal when the store cannot be read.
    pub async fn start(&self) -> Result<Restored, String> {
        let Some(driver) = self.driver.clone() else {
            tracing::info!(
                "persistence: off (persistence.mode=memory). Everything this service holds is in memory and goes \
                 when the process does."
            );
            return Ok(Restored::default());
        };
        {
            let mut st = self.state();
            st.enabled = true;
            st.restoring = true;
        }
        match self.restore(driver.as_ref()).await {
            Ok(restored) => {
                {
                    let mut st = self.state();
                    st.restoring = false;
                    st.restored = restored.clone();
                    st.directory_dirty = true;
                    st.dirty_everything = true;
                    st.generation += 1;
                    st.realms_dirty = self.persists_realms();
                    st.config_dirty = false;
                }
                let from = self.state().change_from;
                if let (Some(from), Some(me)) = (from, self.me.upgrade()) {
                    let applier: Arc<dyn crate::replication::Applier> = me;
                    *self
                        .replication
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner) =
                        Some(crate::replication::Replication::new(
                            driver.clone(),
                            Arc::downgrade(&applier),
                            from,
                        ));
                    tracing::info!(
                        "persistence: coordinating with other processes against this store, from change {}. The \
                         change log is the contract; it is pulled by the persistence.change-log-pull job.",
                        from
                    );
                }
                tracing::info!(
                    "persistence: {} store open; restored {} directory entry/entries, {} defined realm(s) and {} \
                     appconfig override(s).",
                    self.mode.as_str(),
                    restored.entries,
                    restored.realms,
                    restored.overrides
                );
                self.schedule();
                Ok(restored)
            }
            Err(e) => {
                {
                    let mut st = self.state();
                    st.restoring = false;
                    st.enabled = false;
                    st.last_error = e.clone();
                }
                Err(format!(
                    "{}persistence.mode is \"{}\" and the store could not be read: {}. Nothing in the store was \
                     changed.",
                    tag(codes::STS_STORE_0006),
                    self.mode.as_str(),
                    e
                ))
            }
        }
    }

    async fn restore(&self, driver: &dyn Driver) -> Result<Restored, String> {
        let mut restored = Restored::default();
        driver.open().await.map_err(|e| e.to_string())?;
        // The change log's position BEFORE anything is read: a change
        // committed while this start reads is in the log after it.
        if let Some(log) = driver
            .change_log()
            .filter(|_| self.flag("persistence.coordinate"))
        {
            let from =
                log.latest_change_seq().await.map_err(|e| e.to_string())?;
            self.state().change_from = Some(from);
        }
        let saved = if self.persists_appconfig() {
            driver.load_overrides().await.map_err(|e| e.to_string())?
        } else {
            None
        };
        let saved = saved.unwrap_or_default();
        for (key, raw) in &saved {
            match self.settings.set_override(key, raw.clone()) {
                Ok(()) => restored.overrides += 1,
                Err(r) => tracing::warn!(
                    "persistence: the stored override {} was not applied: {}",
                    key,
                    r.problem
                ),
            }
        }
        self.shadow().set_appconfig(saved);
        let rows = if self.persists_realms() {
            driver.load_realms().await.map_err(|e| e.to_string())?
        } else {
            None
        };
        for row in rows.unwrap_or_default() {
            if self.restore_realm(&row) {
                restored.realms += 1;
            }
            let id = row.get("id").and_then(Json::as_str).unwrap_or("");
            if self.lifecycle.registry().get(id).is_some() {
                self.shadow().set_realm(
                    id,
                    json!({ "name": row.get("name"), "description": row.get("description"),
                            "overrides": row.get("overrides").cloned().unwrap_or_else(|| json!({})),
                            "retiringSince": row.get("retiringSince").filter(|v| v.as_f64().is_some_and(|n| n > 0.0)) }),
                );
            }
        }
        let mut loaded: Vec<String> = Vec::new();
        if let Some(by_realm) =
            driver.load_directory().await.map_err(|e| e.to_string())?
        {
            for (realm, entries) in by_realm {
                if entries.is_empty() {
                    continue;
                }
                if realm != DEFAULT_ID
                    && self.lifecycle.registry().get(&realm).is_none()
                {
                    tracing::warn!(
                        "{}persistence: the store holds {} entry/ies for the realm \"{}\", which is not defined. \
                         They are not loaded, and the next write will remove them. Turn persistence.realms on to \
                         restore realm definitions too.",
                        tag(codes::STS_STORE_0009),
                        entries.len(),
                        realm
                    );
                    continue;
                }
                restored.entries += entries.len();
                self.directory.replace_realm(&realm, entries);
                loaded.push(realm);
            }
        }
        // The shadow is what the store holds: what was read back, and
        // nothing for a realm that was not.
        let mut shadow = self.shadow();
        for realm in self.lifecycle.registry().list() {
            if !loaded.contains(&realm.id) {
                continue;
            }
            for (key, entry) in self.directory.realm_entries(&realm.id) {
                shadow.set_entry(
                    &realm.id,
                    &key,
                    crate::merge::entry_json(&entry).to_string(),
                );
            }
        }
        Ok(restored)
    }

    fn restore_realm(&self, row: &Json) -> bool {
        let text = |k: &str| {
            row.get(k).and_then(Json::as_str).unwrap_or("").to_string()
        };
        let id = text("id");
        if self.lifecycle.registry().get(&id).is_some() {
            tracing::warn!("persistence: the realm \"{}\" is already defined; the stored row was left alone.", id);
            return false;
        }
        let overrides = row
            .get("overrides")
            .and_then(Json::as_object)
            .cloned()
            .unwrap_or_default();
        match self.lifecycle.create(
            &id,
            &text("name"),
            &text("description"),
            &text("domain"),
            &overrides,
            true,
        ) {
            Err(e) => {
                tracing::error!(
                    "{}persistence: the stored realm \"{}\" could not be restored: {}",
                    tag(codes::STS_STORE_0007),
                    id,
                    e.sentences.join(" ")
                );
                false
            }
            Ok(_) => {
                if let Some(at) = row.get("createdAt").and_then(Json::as_i64) {
                    self.lifecycle.set_created_at(&id, at);
                }
                if let Some(since) = row
                    .get("retiringSince")
                    .and_then(Json::as_f64)
                    .filter(|n| *n > 0.0)
                {
                    if let Err(e) = self.lifecycle.update(
                        &id,
                        None,
                        None,
                        None,
                        None,
                        true,
                        Some(since),
                    ) {
                        tracing::warn!("persistence: \"{}\"'s retiring mark was not restored: {:?}", id, e.sentences);
                    }
                    if let Some(state) = self
                        .lifecycle
                        .retiring_state(&id)
                        .filter(|s| !s.in_progress)
                    {
                        tracing::warn!(
                            "{}persistence: the realm \"{}\" was restored half removed: {} {}",
                            tag(codes::STS_CORE_0123),
                            id,
                            state.why,
                            state.finish
                        );
                    }
                }
                true
            }
        }
    }

    /// Whether this process coordinates through a change log.
    pub fn coordinates(&self) -> bool {
        self.replication
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    /// Pulls and applies what other processes committed since the last
    /// pull: the `persistence.change-log-pull` job's work.
    pub async fn pull_changes(&self) -> Result<i64, String> {
        let replication = self
            .replication
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        match replication {
            Some(r) => r.pull().await,
            None => Ok(0),
        }
    }

    fn quietly<R>(&self, f: impl FnOnce() -> R) -> R {
        let was = std::mem::replace(&mut self.state().restoring, true);
        let out = f();
        self.state().restoring = was;
        out
    }

    /// Another process's change to one entry: the stored entry, unless this
    /// process holds a change of its own to it not yet written, which is
    /// merged with it and written by the next flush.
    async fn apply_directory_change(
        &self,
        driver: &dyn Driver,
        realm: &str,
        key: &str,
    ) -> StoreResult<()> {
        let Some(log) = driver.change_log() else {
            return Ok(());
        };
        let _flush = self.flush_lock.lock().await;
        let theirs = log.read_entry(realm, key).await?;
        let base = self.shadow().entry(realm, key).map(str::to_string);
        let live = self.directory.entry_at(realm, key);
        let live_json = live
            .as_ref()
            .map(|e| crate::merge::entry_json(e).to_string());
        let pending = live_json != base;
        let mut keep: Option<Option<StoredEntry>> = None;
        if pending {
            let base_entry = base
                .as_deref()
                .and_then(|b| serde_json::from_str::<Json>(b).ok())
                .and_then(|b| crate::merge::entry_of_json(&b));
            let verdict = crate::merge::merge_entry(
                base_entry.as_ref(),
                live.as_ref(),
                theirs.as_ref(),
            );
            keep = match (&live, verdict.outcome) {
                // A local delete not yet written: it stands.
                (None, _) => Some(None),
                (
                    _,
                    crate::merge::Outcome::Mine | crate::merge::Outcome::Merged,
                ) => Some(verdict.entry),
                _ => None,
            };
        }
        self.quietly(|| match (&keep, &theirs) {
            (Some(None), _) => {}
            (Some(Some(entry)), _) => {
                self.directory.apply_entry(realm, key, Some(entry.clone()))
            }
            (None, None) => self.directory.apply_entry(realm, key, None),
            (None, Some(entry)) => {
                self.directory.apply_entry(realm, key, Some(entry.clone()))
            }
        });
        {
            let mut shadow = self.shadow();
            match (&theirs, &keep) {
                (None, _) => shadow.forget_entry(realm, key),
                (Some(entry), Some(_)) => shadow.set_entry(
                    realm,
                    key,
                    crate::merge::canonical_json(entry),
                ),
                (Some(_), None) => {
                    if let Some(stored) = self.directory.entry_at(realm, key) {
                        shadow.set_entry(
                            realm,
                            key,
                            crate::merge::entry_json(&stored).to_string(),
                        );
                    }
                }
            }
        }
        if matches!(keep, Some(Some(_))) {
            drop(_flush);
            self.directory_changed(Some(key));
        }
        Ok(())
    }

    /// Another process changed the realm registry: the stored rows, with
    /// this process's unwritten changes on top; a realm another node
    /// removed is removed here.
    async fn apply_realms_change(
        &self,
        driver: &dyn Driver,
    ) -> StoreResult<()> {
        if !self.persists_realms() {
            return Ok(());
        }
        let _flush = self.flush_lock.lock().await;
        let stored = driver.load_realms().await?.unwrap_or_default();
        let removed: Vec<String> =
            self.state().removed_here.iter().cloned().collect();
        let pending =
            self.shadow().realms_delta(&self.lifecycle.rows(), &removed);
        let known = self.shadow().realm_ids();
        let stored_ids: Vec<String> = stored
            .iter()
            .filter_map(|r| {
                r.get("id").and_then(Json::as_str).map(str::to_string)
            })
            .collect();
        let gone: Vec<String> = known
            .iter()
            .filter(|id| {
                !stored_ids.contains(id)
                    && self.lifecycle.registry().get(id).is_some()
            })
            .cloned()
            .collect();
        self.quietly(|| {
            for row in &stored {
                let id = row.get("id").and_then(Json::as_str).unwrap_or("");
                if removed.iter().any(|r| r == id) {
                    continue;
                }
                let mine = pending
                    .upserts
                    .iter()
                    .find(|c| c.row.get("id").and_then(Json::as_str) == Some(id))
                    .filter(|_| known.iter().any(|k| k == id));
                let mut merged = row.clone();
                if let Some(mine) = mine {
                    let mut overrides = row.get("overrides").and_then(Json::as_object).cloned().unwrap_or_default();
                    for k in &mine.cleared {
                        overrides.shift_remove(k);
                    }
                    for (k, v) in &mine.set {
                        overrides.insert(k.clone(), v.clone());
                    }
                    merged["overrides"] = Json::Object(overrides);
                    if mine.name {
                        merged["name"] = mine.row["name"].clone();
                    }
                    if mine.description {
                        merged["description"] = mine.row["description"].clone();
                    }
                }
                self.restore_realm_replicated(&merged);
            }
            for id in &gone {
                tracing::info!("persistence: the \"{}\" realm was removed by another node; removing it here.", id);
                if let Err(e) = self.lifecycle.remove(id) {
                    tracing::warn!("persistence: \"{}\" could not be removed here: {:?}", id, e.sentences);
                }
            }
        });
        {
            let mut shadow = self.shadow();
            for row in &stored {
                let id = row.get("id").and_then(Json::as_str).unwrap_or("");
                shadow.set_realm(
                    id,
                    json!({ "name": row.get("name"), "description": row.get("description"),
                            "overrides": row.get("overrides").cloned().unwrap_or_else(|| json!({})),
                            "retiringSince": row.get("retiringSince").filter(|v| v.as_f64().is_some_and(|n| n > 0.0)) }),
                );
            }
            for id in &gone {
                shadow.forget_realm(id);
            }
        }
        if !pending.upserts.is_empty() {
            drop(_flush);
            self.realms_changed();
        }
        Ok(())
    }

    fn restore_realm_replicated(&self, row: &Json) {
        let text = |k: &str| {
            row.get(k).and_then(Json::as_str).unwrap_or("").to_string()
        };
        let id = text("id");
        if self.lifecycle.registry().get(&id).is_none() {
            self.restore_realm(row);
            return;
        }
        let overrides = row
            .get("overrides")
            .and_then(Json::as_object)
            .cloned()
            .unwrap_or_default();
        let retiring = row
            .get("retiringSince")
            .and_then(Json::as_f64)
            .filter(|n| *n > 0.0);
        if let Err(e) = self.lifecycle.update(
            &id,
            Some(&text("name")),
            Some(&text("description")),
            Some(&overrides),
            None,
            true,
            retiring,
        ) {
            tracing::warn!("persistence: another node's change to \"{}\" was not applied: {:?}", id, e.sentences);
        }
    }

    /// Another process changed the runtime overrides: the stored ones, with
    /// this process's unwritten changes on top.
    async fn apply_appconfig_change(
        &self,
        driver: &dyn Driver,
    ) -> StoreResult<()> {
        if !self.persists_appconfig() {
            return Ok(());
        }
        let _flush = self.flush_lock.lock().await;
        let saved = driver.load_overrides().await?.unwrap_or_default();
        let pending = self
            .shadow()
            .appconfig_delta(&self.settings.runtime_overrides());
        let mut wanted = saved.clone();
        for k in &pending.cleared {
            wanted.shift_remove(k);
        }
        for (k, v) in &pending.set {
            wanted.insert(k.clone(), v.clone());
        }
        self.quietly(|| {
            for key in self.settings.runtime_overrides().keys() {
                if !wanted.contains_key(key) {
                    self.settings.clear_override(key);
                }
            }
            for (key, raw) in &wanted {
                if let Err(r) = self.settings.set_override(key, raw.clone()) {
                    tracing::warn!("persistence: another node's override {} was not applied: {}", key, r.problem);
                }
            }
        });
        self.shadow().set_appconfig(saved);
        if !pending.is_empty() {
            drop(_flush);
            self.config_changed(None);
        }
        Ok(())
    }

    /// Writes what is pending and closes the store, for a clean shutdown.
    pub async fn stop(&self) -> Result<(), String> {
        let flushed = self.flush().await;
        self.state().stopped = true;
        if let Some(driver) = &self.driver {
            driver.close().await.map_err(|e| e.to_string())?;
        }
        flushed.map(|_| ())
    }

    /// What `/admin/database` and the API report.
    pub fn status(&self) -> Json {
        let st = self.state();
        json!({
            "mode": self.mode.as_str(),
            "enabled": st.enabled && !st.stopped,
            "restoring": st.restoring,
            "writes": st.writes,
            "failures": st.failures,
            "lastError": st.last_error,
            "pending": st.directory_dirty || st.realms_dirty || st.config_dirty,
            "restored": { "entries": st.restored.entries, "realms": st.restored.realms,
                          "overrides": st.restored.overrides },
            "shadowEntries": self.shadow().entry_count(),
        })
    }
}

/// A directory held in memory only: the runtime's until the embedded LDAP
/// directory is ported, and what a test hands persistence.
#[derive(Default)]
pub struct MemoryDirectory {
    realms: Mutex<IndexMap<String, IndexMap<String, StoredEntry>>>,
}

impl MemoryDirectory {
    /// Puts an entry under its DN, lower-cased as its key.
    pub fn put(&self, realm: &str, entry: StoredEntry) {
        let key = entry.dn.to_lowercase();
        self.realms
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(realm.to_string())
            .or_default()
            .insert(key, entry);
    }
}

impl EntryLookup for MemoryDirectory {
    fn entry_at(&self, realm: &str, key: &str) -> Option<StoredEntry> {
        self.realms
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(realm)?
            .get(key)
            .cloned()
    }
}

impl LiveDirectory for MemoryDirectory {
    fn realm_entries(&self, realm: &str) -> IndexMap<String, StoredEntry> {
        self.realms
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(realm)
            .cloned()
            .unwrap_or_default()
    }
    fn replace_realm(&self, realm: &str, entries: Vec<StoredEntry>) {
        let rows = entries
            .into_iter()
            .map(|e| (e.dn.to_lowercase(), e))
            .collect();
        self.realms
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(realm.to_string(), rows);
    }
    fn apply_entry(&self, realm: &str, key: &str, entry: Option<StoredEntry>) {
        let mut realms =
            self.realms.lock().unwrap_or_else(PoisonError::into_inner);
        let rows = realms.entry(realm.to_string()).or_default();
        match entry {
            Some(e) => {
                rows.insert(key.to_string(), e);
            }
            None => {
                rows.shift_remove(key);
            }
        }
    }
}

impl crate::replication::Applier for Persistence {
    fn apply<'a>(
        &'a self,
        row: &'a crate::driver::ChangeRow,
    ) -> crate::driver::StoreFuture<'a, ()> {
        Box::pin(async move {
            let Some(driver) = self.driver.clone() else {
                return Ok(());
            };
            match row.kind.as_str() {
                "directory" => {
                    self.apply_directory_change(
                        driver.as_ref(),
                        &row.realm,
                        &row.key,
                    )
                    .await
                }
                "realms" => self.apply_realms_change(driver.as_ref()).await,
                "appconfig" => {
                    self.apply_appconfig_change(driver.as_ref()).await
                }
                // Minted rows and the rest arrive with their stores.
                _ => Ok(()),
            }
        })
    }
}
