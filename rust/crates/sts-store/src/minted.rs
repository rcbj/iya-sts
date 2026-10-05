// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What this process MINTS, written down (`persistence/persistence_minted.js`):
//! sessions, tokens, codes, artifacts, the replay caches — every store
//! declared with a handle (`StoreSpec::persisted`).
//!
//! * **A write is journalled, not written**: a declared store reports each
//!   key it changed, and a flush reads the store for each — present is an
//!   upsert, absent a delete — so the store is the truth and the journal
//!   only says where to look.
//! * **Every body is SEALED** under the keystore, and so is every NAME
//!   (#222): the `key` column is a keyed digest of handle, realm and name,
//!   and `key_sealed` the name sealed for the restore, which has no name to
//!   start from. A session id is the cookie; a dump must not hold it.
//! * **Two kinds of row the store declares**: a tombstoned store's delete
//!   ENDS the key, so a node holding an old copy cannot bring a session back;
//!   a merging store's row is merged with the stored one under its lock.
//! * **Only what is still worth having is restored** (#333): rows of realms
//!   that exist, not past their own expiry, a short-lived store's row not
//!   older than `persistence.mintedRetention`.
//!
//! Not here yet: the fan-in of `merge: own` rows another process wrote (they
//! are passed over and counted), a page prefetch for the applier, and the
//! tombstone and expiry purge jobs.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value as Json};
use sts_core::errors::codes;
use sts_core::log::tag;
use sts_core::realm::{self, RealmRegistry};
use sts_core::realm_store::{DeclaredHandle, Merge, Retain, StoreHandles};
use sts_core::settings::Settings;

use crate::driver::{
    ChangeRow, Driver, MintedDecided, MintedFilter, MintedMerge, MintedRow,
    MintedWrite, PurgeKind,
};
use crate::keystore::DataKeys;

/// What a row's NAME is sealed and digested under.
const NAME_LABEL: &str = "minted-key";
/// What a row's BODY is sealed under.
const BODY_LABEL: &str = "minted-rows";
const EXPIRY_PURGE_BATCH: i64 = 5000;
const EXPIRY_PURGE_MAX_BATCHES: usize = 20;
/// A realm another node is creating writes its minted rows and its registry
/// row in two transactions; an hour is far longer than the gap.
const ORPHAN_GRACE_MS: i64 = 60 * 60 * 1000;

type Journal = BTreeMap<String, BTreeMap<String, BTreeSet<String>>>;

#[derive(Default)]
struct State {
    journal: Journal,
    restoring: bool,
    stopped: bool,
    asked: bool,
    generation: u64,
    committed: u64,
    writes: u64,
    rows_written: u64,
    rows_deleted: u64,
    failures: u64,
    restored: u64,
    dropped_unreadable: u64,
    dropped_unknown: u64,
    foreign_own: u64,
    last_error: String,
    warned: HashSet<String>,
}

/// Minted persistence for one process.
pub struct Minted {
    handles: Arc<StoreHandles>,
    settings: Arc<Settings>,
    registry: Arc<RealmRegistry>,
    driver: Arc<dyn Driver>,
    /// Whether the mode is product, read when asked.
    product: Arc<dyn Fn() -> bool + Send + Sync>,
    /// Whether several processes coordinate through the store.
    coordinated: bool,
    origin: String,
    state: Mutex<State>,
    flushing: tokio::sync::Mutex<()>,
    scheduler: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

fn b64(text: &str) -> String {
    URL_SAFE_NO_PAD.encode(text.as_bytes())
}

fn unb64(text: &str) -> Option<String> {
    String::from_utf8(URL_SAFE_NO_PAD.decode(text).ok()?).ok()
}

/// `storedKey()`: an `own` store's key carries its origin, both halves
/// base64url and joined with '.', which is not in that alphabet.
fn stored_key(h: &DeclaredHandle, key: &str, origin: &str) -> String {
    if h.spec.merge == Merge::Own {
        format!("{}.{}", b64(key), b64(origin))
    } else {
        key.to_string()
    }
}

/// `splitKey()`: the inverse, `(key, origin)`; a name not in that shape is
/// somebody's real data, restored unqualified.
fn split_key(h: &DeclaredHandle, name: &str) -> (String, String) {
    if h.spec.merge != Merge::Own {
        return (name.to_string(), String::new());
    }
    match name.rfind('.') {
        Some(at) => match (unb64(&name[..at]), unb64(&name[at + 1..])) {
            (Some(k), Some(o)) => (k, o),
            _ => (name.to_string(), String::new()),
        },
        None => (name.to_string(), String::new()),
    }
}

impl Minted {
    pub fn new(
        handles: Arc<StoreHandles>,
        settings: Arc<Settings>,
        registry: Arc<RealmRegistry>,
        driver: Arc<dyn Driver>,
        product: Arc<dyn Fn() -> bool + Send + Sync>,
        coordinated: bool,
        origin: String,
    ) -> Arc<Minted> {
        Arc::new(Minted {
            handles,
            settings,
            registry,
            driver,
            product,
            coordinated,
            origin,
            state: Mutex::new(State::default()),
            flushing: tokio::sync::Mutex::new(()),
            scheduler: Mutex::new(None),
        })
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Installs what a journalled write calls to ask for a flush.
    pub fn set_scheduler(&self, f: Arc<dyn Fn() + Send + Sync>) {
        *self
            .scheduler
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(f);
    }

    /// `enabled()`: `persistence.minted`, a store that holds minted rows,
    /// and either product mode or several processes that must agree.
    pub fn enabled(&self, keys: &DataKeys) -> bool {
        !self.state().stopped
            && self.driver.mints()
            && self.settings.value_of("persistence.minted").as_bool()
            && ((self.product)() || (self.coordinated && keys.sealed()))
    }

    /// `note()`: one write a declared store reported. `key` is `None` for a
    /// whole-store write, journalled as the empty key.
    pub fn note(&self, handle: &str, realm: &str, key: Option<&str>) {
        let ask = {
            let mut st = self.state();
            if st.restoring || st.stopped {
                return;
            }
            st.journal
                .entry(handle.to_string())
                .or_default()
                .entry(realm.to_string())
                .or_default()
                .insert(key.unwrap_or("").to_string());
            st.generation += 1;
            let ask = !st.asked;
            st.asked = true;
            ask
        };
        if ask {
            let scheduler = self
                .scheduler
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            match scheduler {
                Some(f) => f(),
                None => self.state().asked = false,
            }
        }
    }

    /// Whether anything is journalled and not yet written.
    pub fn dirty(&self) -> bool {
        !self.state().journal.is_empty()
    }

    /// `keyColumnOf()`: the keyed digest a name is filed under, or the name
    /// where no digest key is held.
    fn key_column_of(
        keys: &DataKeys,
        handle: &str,
        realm: &str,
        name: &str,
    ) -> String {
        keys.keyed_digest(
            NAME_LABEL,
            &format!("{}\n{}\n{}", handle, realm, name),
        )
        .unwrap_or_else(|| name.to_string())
    }

    /// `columnsFor()`: `(key, key_sealed)`.
    fn columns_for(
        keys: &DataKeys,
        handle: &str,
        realm: &str,
        name: &str,
    ) -> (String, String) {
        let digest = Minted::key_column_of(keys, handle, realm, name);
        if digest == name {
            return (name.to_string(), String::new());
        }
        match keys.seal(name, NAME_LABEL, realm) {
            Some(sealed) => (digest, sealed),
            None => (name.to_string(), String::new()),
        }
    }

    /// `nameOfRow()`: the sealed name opened, or the key where there is
    /// none; `None` when it will not open.
    fn name_of_row(keys: &DataKeys, row: &MintedRow) -> Option<String> {
        if row.key_sealed.is_empty() {
            Some(row.key.clone())
        } else {
            keys.open(&row.key_sealed, NAME_LABEL)
        }
    }

    /// `expiryOf()`: the store's own answer, run in the row's realm.
    fn expiry_of(
        &self,
        h: &DeclaredHandle,
        value: &Json,
        key: &str,
        realm: &str,
    ) -> Option<i64> {
        let hook = h.spec.expires_at.clone()?;
        let in_realm = self
            .registry
            .get(if realm.is_empty() {
                realm::DEFAULT_ID
            } else {
                realm
            })
            .unwrap_or_else(|| Arc::new(realm::Realm::default_realm()));
        let at = realm::run_sync(in_realm, || hook(value, key))?;
        (at.is_finite() && at > 0.0).then_some(at.floor() as i64)
    }

    /// `flush()`: every journalled key written, sealed, or deleted. One at a
    /// time; on failure the keys go back into the journal. Answers whether
    /// anything was written.
    pub async fn flush(&self, keys: &Arc<DataKeys>) -> Result<bool, String> {
        let _one = self.flushing.lock().await;
        if !self.enabled(keys) {
            let mut st = self.state();
            st.journal.clear();
            st.asked = false;
            st.committed = st.generation;
            return Ok(false);
        }
        if !keys.sealed() {
            let mut st = self.state();
            st.journal.clear();
            st.asked = false;
            st.committed = st.generation;
            st.last_error =
                "no key-encryption key is available, so nothing minted can be sealed".to_string();
            tracing::error!(
                "{}persistence: {}. Minted state is not being written down.",
                tag(codes::STS_STORE_0018),
                st.last_error
            );
            return Err(st.last_error.clone());
        }
        let (taken, taken_at) = {
            let mut st = self.state();
            st.asked = false;
            (std::mem::take(&mut st.journal), st.generation)
        };
        let mut upserts: Vec<MintedWrite> = Vec::new();
        let mut deletes: Vec<MintedWrite> = Vec::new();
        let mut unsealable = 0;
        for (handle, by_realm) in &taken {
            let Some(h) = self.handles.handle_for(handle) else {
                tracing::error!(
                    "{}persistence: \"{}\" reported a write and is not a declared store. Its rows cannot be \
                     written.",
                    tag(codes::STS_STORE_0019),
                    handle
                );
                continue;
            };
            for (realm, journalled) in by_realm {
                for key in journalled {
                    if key.contains('\0') || realm.contains('\0') {
                        if self.state().warned.insert(format!("nul:{}", handle))
                        {
                            tracing::error!(
                                "{}persistence: \"{}\" journalled a key holding a NUL character; PostgreSQL cannot \
                                 store it, so that row is kept in memory only. Said once per store.",
                                tag(codes::STS_STORE_0063),
                                handle
                            );
                        }
                        continue;
                    }
                    let name = stored_key(&h, key, &self.origin);
                    let (column, sealed_name) =
                        Minted::columns_for(keys, handle, realm, &name);
                    let Some(value) = h.access.read(realm, key) else {
                        deletes.push(MintedWrite {
                            handle: handle.clone(),
                            realm: realm.clone(),
                            key: column,
                            key_sealed: sealed_name,
                            journal_key: key.clone(),
                            body: String::new(),
                            expires_at: None,
                            own: h.spec.merge == Merge::Own,
                            tombstone: h.spec.tombstone,
                            merge: None,
                        });
                        continue;
                    };
                    let Some(body) =
                        keys.seal(&value.to_string(), BODY_LABEL, realm)
                    else {
                        unsealable += 1;
                        continue;
                    };
                    let expires_at = self.expiry_of(&h, &value, key, realm);
                    let merge: Option<MintedMerge> = h.spec.merge_row.clone().map(|merge_row| {
                        let keys = keys.clone();
                        let mine = value.clone();
                        let hook = h.spec.expires_at.clone();
                        let (handle, realm, key) = (handle.clone(), realm.clone(), key.clone());
                        Box::new(move |stored: &str| {
                            let Some(text) = keys.open(stored, BODY_LABEL) else {
                                tracing::warn!(
                                    "{}persistence: the \"{}\" row another node wrote will not open here, so this \
                                     process's copy is written as it is.",
                                    tag(codes::STS_STORE_0056),
                                    handle
                                );
                                return None;
                            };
                            let theirs: Json = serde_json::from_str(&text).ok()?;
                            let merged = merge_row(&mine, &theirs);
                            // THE MERGED RECORD'S EXPIRY IS WHAT IS WRITTEN:
                            // the other node may have extended it.
                            let expires = hook
                                .as_ref()
                                .and_then(|f| f(&merged, &key))
                                .filter(|n| n.is_finite() && *n > 0.0)
                                .map(|n| n.floor() as i64);
                            Some((keys.seal(&merged.to_string(), BODY_LABEL, &realm)?, expires))
                        }) as MintedMerge
                    });
                    upserts.push(MintedWrite {
                        handle: handle.clone(),
                        realm: realm.clone(),
                        key: column,
                        key_sealed: sealed_name,
                        journal_key: key.clone(),
                        body,
                        expires_at,
                        own: h.spec.merge == Merge::Own,
                        tombstone: h.spec.tombstone,
                        merge,
                    });
                }
            }
        }
        if upserts.is_empty() && deletes.is_empty() {
            let mut st = self.state();
            st.committed = st.committed.max(taken_at);
            return Ok(false);
        }
        let (n_up, n_del) = (upserts.len() as u64, deletes.len() as u64);
        // The data keys first: nothing is stored before the keys it was
        // sealed under.
        keys.settle().await;
        match self.driver.save_minted(upserts, deletes).await {
            Ok(decided) => {
                {
                    let mut st = self.state();
                    st.committed = st.committed.max(taken_at);
                    st.writes += 1;
                    st.rows_written += n_up;
                    st.rows_deleted += n_del;
                    st.last_error.clear();
                }
                self.settle_decided(keys, decided);
                if unsealable > 0 {
                    tracing::warn!(
                        "persistence: {} minted row(s) could not be sealed and were not written.",
                        unsealable
                    );
                }
                Ok(true)
            }
            Err(e) => {
                let mut st = self.state();
                for (handle, by_realm) in taken {
                    for (realm, journalled) in by_realm {
                        st.journal
                            .entry(handle.clone())
                            .or_default()
                            .entry(realm)
                            .or_default()
                            .extend(journalled);
                    }
                }
                st.generation += 1;
                st.failures += 1;
                st.last_error = e.to_string();
                tracing::error!(
                    "{}persistence: minted state could not be written: {}. It is retried at the next flush.",
                    tag(codes::STS_STORE_0021),
                    e
                );
                Err(e.to_string())
            }
        }
    }

    /// `settleDecided()`: a row a tombstone refused is ended here too; a
    /// merged row is applied unless this process changed it again since.
    fn settle_decided(&self, keys: &DataKeys, decided: MintedDecided) {
        for (handle, realm, key) in decided.refused {
            let Some(h) = self.handles.handle_for(&handle) else {
                continue;
            };
            tracing::info!(
                "{}persistence: a \"{}\" row was not written back: another node ended it. Dropped here too.",
                tag(codes::STS_STORE_0054),
                handle
            );
            if let Some(set) = self
                .state()
                .journal
                .get_mut(&handle)
                .and_then(|r| r.get_mut(&realm))
            {
                set.remove(&key);
            }
            self.apply_locally(&h, &realm, &key, None);
        }
        for (handle, realm, key, body) in decided.merged {
            let Some(h) = self.handles.handle_for(&handle) else {
                continue;
            };
            let journalled = self
                .state()
                .journal
                .get(&handle)
                .and_then(|r| r.get(&realm))
                .map(|s| s.contains(&key))
                .unwrap_or(false);
            if journalled {
                continue;
            }
            if let Some(value) = keys
                .open(&body, BODY_LABEL)
                .and_then(|t| serde_json::from_str::<Json>(&t).ok())
            {
                self.apply_locally(&h, &realm, &key, Some(value));
            }
        }
    }

    /// Writes into a store without journalling it.
    fn apply_locally(
        &self,
        h: &DeclaredHandle,
        realm: &str,
        key: &str,
        value: Option<Json>,
    ) {
        let was = std::mem::replace(&mut self.state().restoring, true);
        match value {
            Some(v) => h.access.restore(realm, key, v),
            None => h.access.remove(realm, key),
        }
        self.state().restoring = was;
    }

    /// `restoreFilter()`.
    fn restore_filter(&self, now_ms: i64) -> MintedFilter {
        let mut realms: Vec<String> =
            vec![String::new(), realm::DEFAULT_ID.to_string()];
        for one in self.registry.list() {
            if !realms.contains(&one.id) {
                realms.push(one.id.clone());
            }
        }
        let retention = self
            .settings
            .value_of("persistence.mintedRetention")
            .as_int()
            .max(0);
        MintedFilter {
            realms,
            now_ms,
            stale_before: if retention > 0 { now_ms - retention } else { 0 },
            age_handles: self
                .handles
                .handles()
                .iter()
                .filter(|h| h.spec.retain == Retain::Age)
                .map(|h| h.handle.clone())
                .collect(),
        }
    }

    /// `restore()`: the stored rows put back into the stores, once, at the
    /// start. A key generated for this run cannot open an earlier run's
    /// rows, so those are cleared instead.
    pub async fn restore(&self, keys: &Arc<DataKeys>) -> Result<u64, String> {
        if !self.enabled(keys) {
            return Ok(0);
        }
        if !keys.sealed() {
            return Err(format!(
                "{}minted state is persisted (persistence.minted) but no key-encryption key is available to open \
                 it. The stored sessions, tokens, codes and artifacts cannot be read.",
                tag(codes::STS_STORE_0022)
            ));
        }
        let now = sts_core::time::now_ms_f64() as i64;
        if !keys.stores_deks() {
            let removed = match self.driver.purge_minted(now).await {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(
                        "{}persistence: an earlier run's minted rows could not be cleared: {}. They are unreadable \
                         and will be swept by persistence.mintedRetention.",
                        tag(codes::STS_STORE_0023),
                        e
                    );
                    0
                }
            };
            tracing::info!(
                "persistence: {} minted row(s) from an earlier run were cleared. This run seals under a key of its \
                 own, so nothing it finds here is readable and nothing is restored.",
                removed
            );
            return Ok(0);
        }
        let filter = self.restore_filter(now);
        let partitions = filter.realms.len();
        let rows = self.driver.load_minted(filter).await.map_err(|e| {
            format!(
                "{}the minted state in the store could not be read: {}",
                tag(codes::STS_STORE_0026),
                e
            )
        })?;
        let pending = {
            let mut st = self.state();
            st.restoring = true;
            std::mem::take(&mut st.journal)
        };
        let (mut restored, mut unreadable, mut unknown, mut foreign) =
            (0u64, 0u64, 0u64, 0u64);
        let mut stale: BTreeSet<String> = BTreeSet::new();
        for row in rows {
            let Some(h) = self.handles.handle_for(&row.handle) else {
                unknown += 1;
                stale.insert(row.handle);
                continue;
            };
            let value = keys
                .open(&row.body, BODY_LABEL)
                .and_then(|t| serde_json::from_str::<Json>(&t).ok());
            let (Some(value), Some(name)) =
                (value, Minted::name_of_row(keys, &row))
            else {
                unreadable += 1;
                continue;
            };
            let (key, origin) = split_key(&h, &name);
            if h.spec.merge == Merge::Own
                && !origin.is_empty()
                && origin != self.origin
            {
                foreign += 1;
                continue;
            }
            h.access.restore(&row.realm, &key, value);
            restored += 1;
        }
        {
            let mut st = self.state();
            st.restoring = false;
            st.restored = restored;
            st.dropped_unreadable = unreadable;
            st.dropped_unknown = unknown;
            st.foreign_own = foreign;
            st.journal = pending;
        }
        if !stale.is_empty() {
            tracing::info!(
                "persistence: {} minted row(s) belong to handle(s) nothing in this build declares ({}). They were \
                 left alone rather than deleted: a row this build does not understand is usually an older or newer \
                 build's.",
                unknown,
                stale.into_iter().collect::<Vec<_>>().join(", ")
            );
        }
        tracing::info!(
            "persistence: {} minted row(s) restored across {} declared store(s) and {} realm partition(s){}.",
            restored,
            self.handles.handles().len(),
            partitions,
            if unreadable > 0 {
                format!(
                    ", {} unreadable (written under a different key-encryption key?)",
                    unreadable
                )
            } else {
                String::new()
            }
        );
        if self.dirty() {
            if let Some(f) = self
                .scheduler
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
            {
                f();
            }
        }
        Ok(restored)
    }

    /// `applyChange()`: one minted row another process committed, read and
    /// put into its store — or removed, when it is gone (a delete).
    pub async fn apply_change(
        &self,
        keys: &DataKeys,
        change: &ChangeRow,
    ) -> Result<bool, String> {
        let Some(at) = change.key.find('.') else {
            tracing::error!(
                "{}persistence: a minted change names \"{}\", which carries no handle. Skipped.",
                tag(codes::STS_STORE_0014),
                change.key
            );
            return Ok(false);
        };
        let half = &change.key[at + 1..];
        let parsed = unb64(&change.key[..at]).and_then(|handle| {
            let name = if half.contains('$') {
                keys.open(half, NAME_LABEL)?
            } else {
                unb64(half)?
            };
            Some((handle, name))
        });
        let Some((handle, name)) = parsed else {
            tracing::error!(
                "{}persistence: a minted change names \"{}\", which is not the shape the change log is written \
                 in. Skipped.",
                tag(codes::STS_STORE_0014),
                change.key
            );
            return Ok(false);
        };
        let Some(h) = self.handles.handle_for(&handle) else {
            return Ok(false);
        };
        let (key, origin) = split_key(&h, &name);
        if h.spec.merge == Merge::Own
            && !origin.is_empty()
            && origin != self.origin
        {
            self.state().foreign_own += 1;
            return Ok(false);
        }
        let column = Minted::key_column_of(keys, &handle, &change.realm, &name);
        let rows = self
            .driver
            .read_minted_many(vec![(
                handle.clone(),
                change.realm.clone(),
                column,
            )])
            .await
            .map_err(|e| e.to_string())?;
        let Some(row) = rows.into_iter().next() else {
            self.apply_locally(&h, &change.realm, &key, None);
            return Ok(true);
        };
        let Some(text) = keys.open(&row.body, BODY_LABEL) else {
            tracing::warn!(
                "{}persistence: another process's \"{}\" row will not open under this key-encryption key. Skipped.",
                tag(codes::STS_STORE_0016),
                handle
            );
            return Ok(false);
        };
        let Ok(value) = serde_json::from_str::<Json>(&text) else {
            tracing::warn!(
                "{}persistence: another process's \"{}\" row opened and is not JSON. Skipped.",
                tag(codes::STS_STORE_0017),
                handle
            );
            return Ok(false);
        };
        self.apply_locally(&h, &change.realm, &key, Some(value));
        Ok(true)
    }

    fn retention_ms(&self) -> i64 {
        self.settings
            .value_of("persistence.mintedRetention")
            .as_int()
            .max(0)
    }

    /// Whether the tombstone sweep has anything to do here, or why not.
    pub fn tombstone_sweep_off(&self) -> String {
        if !self.driver.mints() {
            "this store keeps no tombstones".to_string()
        } else if self.retention_ms() == 0 {
            "the minted-row retention is 0".to_string()
        } else {
            String::new()
        }
    }

    /// `persistence.tombstone-purge`: the tombstones of ended rows older than
    /// `persistence.mintedRetention`.
    pub async fn sweep_tombstones(&self, now_ms: i64) -> Result<u64, String> {
        let removed = self
            .driver
            .purge_tombstones(now_ms - self.retention_ms())
            .await
            .map_err(|e| {
                tracing::warn!(
                    "{}persistence: sweeping expired tombstones failed: {}.",
                    tag(codes::STS_STORE_0055),
                    e
                );
                e.to_string()
            })?;
        if removed > 0 {
            tracing::info!(
                "persistence: {} expired tombstone(s) of ended minted rows swept.",
                removed
            );
        }
        Ok(removed)
    }

    /// One kind, batch after batch until one comes back short or the bound
    /// is reached: `(removed, more)`.
    async fn purge_kind(&self, kind: PurgeKind) -> Result<(u64, bool), String> {
        let mut removed = 0;
        for _ in 0..EXPIRY_PURGE_MAX_BATCHES {
            let n = self
                .driver
                .purge_expired_minted(kind.clone(), EXPIRY_PURGE_BATCH)
                .await
                .map_err(|e| e.to_string())?;
            removed += n;
            if (n as i64) < EXPIRY_PURGE_BATCH {
                return Ok((removed, false));
            }
        }
        Ok((removed, true))
    }

    /// `persistence.minted-expiry-purge` (#333): the rows no restore will
    /// read again — expired, of a realm no longer defined (written over an
    /// hour ago), a short-lived store's stale row — in bounded batches.
    pub async fn purge_expired(&self, now_ms: i64) -> Result<Json, String> {
        let run = async {
            let (expired, m1) =
                self.purge_kind(PurgeKind::Expired { now_ms }).await?;
            let (orphaned, m2) = self
                .purge_kind(PurgeKind::Orphan {
                    default_realm: realm::DEFAULT_ID.to_string(),
                    before_ms: now_ms - ORPHAN_GRACE_MS,
                })
                .await?;
            let retention = self.retention_ms();
            let (stale, m3) = if retention > 0 {
                self.purge_kind(PurgeKind::Stale {
                    handles: self.restore_filter(now_ms).age_handles,
                    before_ms: now_ms - retention,
                })
                .await?
            } else {
                (0, false)
            };
            Ok::<_, String>((expired, orphaned, stale, m1 || m2 || m3))
        };
        let (expired, orphaned, stale, more) = run.await.map_err(|e| {
            tracing::warn!(
                "{}persistence: purging expired minted rows failed: {}. A start skips them anyway; the next run \
                 tries again.",
                tag(codes::STS_STORE_0065),
                e
            );
            e
        })?;
        let total = expired + orphaned + stale;
        if total > 0 {
            tracing::info!(
                "persistence: {} minted row(s) purged from the store — {} expired, {} of realms no longer defined, \
                 {} short-lived and older than persistence.mintedRetention{}.",
                total,
                expired,
                orphaned,
                stale,
                if more { "; more remain for the next run" } else { "" }
            );
        }
        Ok(
            json!({ "expired": expired, "orphaned": orphaned, "stale": stale, "more": more }),
        )
    }

    /// Writes what is journalled and stops journalling.
    pub async fn stop(&self, keys: &Arc<DataKeys>) -> Result<bool, String> {
        let out = self.flush(keys).await;
        self.state().stopped = true;
        out
    }

    /// What `/admin/database` reports of minted state.
    pub fn status(&self) -> Json {
        let st = self.state();
        json!({ "pending": st.journal.values().flat_map(|r| r.values()).map(BTreeSet::len).sum::<usize>(),
                "generation": st.generation, "committed": st.committed, "writes": st.writes,
                "rowsWritten": st.rows_written, "rowsDeleted": st.rows_deleted, "failures": st.failures,
                "restored": st.restored, "droppedUnreadable": st.dropped_unreadable,
                "droppedUnknown": st.dropped_unknown, "foreignOwn": st.foreign_own,
                "lastError": st.last_error })
    }
}
