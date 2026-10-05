// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A store becomes per realm at its DECLARATION and nowhere else
//! (`common/realms.js`'s `map()`, `sharedMap()` and the handle registry;
//! root CLAUDE.md, trust realms rule 2).
//!
//! * [`RealmMap`] is a map per trust realm. Every read and write lands in
//!   the AMBIENT realm's partition; [`RealmMap::in_realm`] names one,
//!   and a write through it belongs to that realm however the ambient one
//!   is set (a sweep walks every realm from outside all of them).
//! * **An id this process has not heard of is its own partition**, not the
//!   default realm's: a replicated row often arrives before its realm does,
//!   and it waits where the realm will look. The empty id IS the default
//!   realm.
//! * **A removed realm takes no rows** until it is defined again: a row
//!   arriving after the purge would rebuild the partition the purge
//!   emptied.
//! * **A store declared with a handle is persisted**: every write is
//!   reported to the persistence observer (handle, realm, key) — a delete
//!   whether or not the key was held, a clear key by key before it clears —
//!   and `restore` and `remove` write WITHOUT reporting, because what a
//!   restore just read must not be written straight back. A handle declared
//!   twice is refused (`STS-CORE-0022`) and that store is not persisted.
//! * [`SharedMap`] is one map for the whole process, reported under the
//!   realm `''`.
//!
//! The array and object shapes are a later piece.

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, PoisonError, RwLock, Weak};

use indexmap::IndexMap;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value as Json;

use crate::errors::codes;
use crate::log::tag;
use crate::realm::{self, DEFAULT_ID};
use crate::realm_lifecycle::RealmLifecycle;

/// How two processes' copies of a store combine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Merge {
    /// A write is an ASSIGNMENT: the later one wins.
    Replace,
    /// A write is an INCREMENT (a counter, a ring): each process writes only
    /// its own row and the fan-in is where the value is reported.
    Own,
}

/// How long a row is kept in the store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retain {
    /// Until the store deletes it.
    Keep,
    /// Short-lived by nature: dropped at the next start past
    /// `persistence.mintedRetention`.
    Age,
}

pub type MergeRow = Arc<dyn Fn(&Json, &Json) -> Json + Send + Sync>;
pub type ExpiresAt = Arc<dyn Fn(&Json, &str) -> Option<f64> + Send + Sync>;

/// What a store says about its rows when it is declared.
#[derive(Clone)]
pub struct StoreSpec {
    /// The handle its rows are written under; `None` for a store that is
    /// not persisted (the embedded directory is one).
    pub persist: Option<String>,
    pub merge: Merge,
    /// A deleted key is ENDED: a later write of it is refused, so a node
    /// holding an old copy cannot bring it back.
    pub tombstone: bool,
    /// The row is edited in place by several nodes; the flush writes what
    /// this answers. Pure, and convergent.
    pub merge_row: Option<MergeRow>,
    /// A write is a tally of what a request did, not a thing it did.
    pub observation: bool,
    pub retain: Retain,
    /// The instant a row stops being worth anything, never earlier.
    pub expires_at: Option<ExpiresAt>,
}

impl StoreSpec {
    /// A store not persisted.
    pub fn memory() -> StoreSpec {
        StoreSpec {
            persist: None,
            merge: Merge::Replace,
            tombstone: false,
            merge_row: None,
            observation: false,
            retain: Retain::Keep,
            expires_at: None,
        }
    }

    /// A store persisted under `handle`.
    pub fn persisted(handle: &str) -> StoreSpec {
        StoreSpec {
            persist: Some(handle.to_string()),
            ..StoreSpec::memory()
        }
    }
}

/// `expiryField()`: a row's own expiry is one field of it, or the value
/// itself when it is a number, in milliseconds (`scale` 1) or seconds
/// (`scale` 1000); anything not a positive number does not expire.
pub fn expiry_field(field: Option<&'static str>, scale: f64) -> ExpiresAt {
    let factor = if scale > 0.0 { scale } else { 1.0 };
    Arc::new(move |value: &Json, _key: &str| {
        let raw = match field {
            None => Some(value),
            Some(f) => value.get(f),
        };
        let n = match raw {
            Some(Json::Number(n)) => n.as_f64(),
            Some(Json::String(s)) => match s.trim().parse::<f64>() {
                Ok(n) => Some(n),
                Err(_) => chrono::DateTime::parse_from_rfc3339(s)
                    .ok()
                    .map(|t| t.timestamp_millis() as f64 / factor),
            },
            _ => None,
        }?;
        (n.is_finite() && n > 0.0).then_some(n * factor)
    })
}

/// What persistence reaches a declared store through.
pub trait StoreAccess: Send + Sync {
    /// Every row of one realm's partition.
    fn dump(&self, realm: &str) -> Vec<(String, Json)>;
    fn read(&self, realm: &str, key: &str) -> Option<Json>;
    /// Writes a stored row WITHOUT reporting it.
    fn restore(&self, realm: &str, key: &str, value: Json);
    /// Removes a row another process deleted, without reporting it.
    fn remove(&self, realm: &str, key: &str);
}

/// One declared store.
pub struct DeclaredHandle {
    pub handle: String,
    /// `map` or `shared-map`.
    pub shape: &'static str,
    /// `realm` or `shared`.
    pub scope: &'static str,
    pub spec: StoreSpec,
    pub access: Arc<dyn StoreAccess>,
}

type Observer = Arc<dyn Fn(&str, &str, Option<&str>) + Send + Sync>;

/// Every handle declared, in declaration order, and the observer each write
/// is reported to.
#[derive(Default)]
pub struct StoreHandles {
    declared: RwLock<Vec<Arc<DeclaredHandle>>>,
    observer: RwLock<Option<Observer>>,
}

impl StoreHandles {
    pub fn new() -> Arc<StoreHandles> {
        Arc::new(StoreHandles::default())
    }

    /// Declares a handle, or refuses a second store under one handle: two
    /// stores sharing a name would each overwrite the other's rows, and the
    /// damage would show one restart later. Refused rather than fatal: at
    /// worst that store is not persisted.
    fn declare(
        &self,
        spec: &StoreSpec,
        shape: &'static str,
        scope: &'static str,
        access: Arc<dyn StoreAccess>,
    ) -> Option<String> {
        let handle = spec.persist.clone()?;
        let mut declared = self
            .declared
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(already) = declared.iter().find(|h| h.handle == handle) {
            tracing::error!(
                "{}realms: the handle \"{}\" is declared TWICE ({} and {}). The second declaration will not be \
                 persisted: two stores under one handle would each overwrite the other's rows, and the damage would \
                 only be visible one restart later.",
                tag(codes::STS_CORE_0022),
                handle,
                already.shape,
                shape
            );
            return None;
        }
        declared.push(Arc::new(DeclaredHandle {
            handle: handle.clone(),
            shape,
            scope,
            spec: spec.clone(),
            access,
        }));
        Some(handle)
    }

    /// Installs the observer every write is reported to. Consulted per write,
    /// so stores declared before it are reached too.
    pub fn set_persist_observer(&self, f: Observer) {
        *self
            .observer
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(f);
    }

    fn observing(&self) -> bool {
        self.observer
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    /// Reports one write; a store that cannot report must not fail the
    /// request that wrote (`STS-CORE-0023`).
    fn note(&self, handle: &str, realm: &str, key: Option<&str>) {
        let observer = self
            .observer
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(f) = observer {
            if catch_unwind(AssertUnwindSafe(|| f(handle, realm, key))).is_err()
            {
                tracing::error!(
                    "{}realms: \"{}\" could not report a write.",
                    tag(codes::STS_CORE_0023),
                    handle
                );
            }
        }
    }

    pub fn handles(&self) -> Vec<Arc<DeclaredHandle>> {
        self.declared
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// One handle by name: a stored handle nothing declares is an older
    /// build's row, which a restore reports and passes over.
    pub fn handle_for(&self, name: &str) -> Option<Arc<DeclaredHandle>> {
        self.declared
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|h| h.handle == name)
            .cloned()
    }
}

/// The partition a realm id names: the empty id is the default realm, and
/// an id not yet heard of is its own.
pub fn partition_id(realm: &str) -> &str {
    if realm.is_empty() {
        DEFAULT_ID
    } else {
        realm
    }
}

/// A store's own rule for rows other processes send: the value to hold
/// (`None`: hold nothing new), and whether a removal is allowed. A rule that
/// fails applies nothing (`STS-CORE-0042`).
pub trait Reconcile<V>: Send + Sync {
    fn restore(
        &self,
        key: &str,
        incoming: V,
        held: Option<&V>,
        realm: &str,
    ) -> Result<Option<V>, String>;
    fn remove(
        &self,
        _key: &str,
        _held: Option<&V>,
        _realm: &str,
    ) -> Result<bool, String> {
        Ok(true)
    }
}

type Partition<V> = Arc<RwLock<IndexMap<String, V>>>;

struct Inner<V> {
    partitions: RwLock<HashMap<String, Partition<V>>>,
    handle: RwLock<Option<String>>,
    name: String,
    handles: Arc<StoreHandles>,
    lifecycle: Weak<RealmLifecycle>,
    reconcile: Option<Arc<dyn Reconcile<V>>>,
    /// A shared store reports every write under the realm `''`.
    shared: bool,
}

impl<V> Inner<V> {
    fn partition(&self, realm: &str) -> Partition<V> {
        let id = partition_id(realm);
        if let Some(p) = self
            .partitions
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
        {
            return p.clone();
        }
        self.partitions
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(id.to_string())
            .or_default()
            .clone()
    }

    fn note(&self, realm: &str, key: &str) {
        if let Some(handle) = self
            .handle
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_deref()
        {
            let realm = if self.shared { "" } else { partition_id(realm) };
            self.handles.note(handle, realm, Some(key));
        }
    }

    fn journals(&self) -> bool {
        self.handle
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
            && self.handles.observing()
    }

    fn accepts(&self, realm: &str) -> bool {
        self.lifecycle
            .upgrade()
            .is_none_or(|l| l.accepts_rows(partition_id(realm)))
    }
}

/// A map per trust realm.
pub struct RealmMap<V> {
    inner: Arc<Inner<V>>,
}

impl<V> Clone for RealmMap<V> {
    fn clone(&self) -> Self {
        RealmMap {
            inner: self.inner.clone(),
        }
    }
}

struct MapAccess<V>(Weak<Inner<V>>);

impl<V> StoreAccess for MapAccess<V>
where
    V: Clone + Serialize + DeserializeOwned + Send + Sync + 'static,
{
    fn dump(&self, realm: &str) -> Vec<(String, Json)> {
        let Some(inner) = self.0.upgrade() else {
            return Vec::new();
        };
        let p = inner.partition(realm);
        let held = p.read().unwrap_or_else(PoisonError::into_inner);
        held.iter()
            .filter_map(|(k, v)| {
                serde_json::to_value(v).ok().map(|j| (k.clone(), j))
            })
            .collect()
    }

    fn read(&self, realm: &str, key: &str) -> Option<Json> {
        let inner = self.0.upgrade()?;
        let p = inner.partition(realm);
        let held = p.read().unwrap_or_else(PoisonError::into_inner);
        held.get(key).and_then(|v| serde_json::to_value(v).ok())
    }

    fn restore(&self, realm: &str, key: &str, value: Json) {
        let Some(inner) = self.0.upgrade() else {
            return;
        };
        if !inner.accepts(realm) {
            return;
        }
        let value: V = match serde_json::from_value(value) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(
                    "{}realms: \"{}\" could not read a stored row under \"{}\", so it was NOT applied: {}",
                    tag(codes::STS_CORE_0042),
                    inner.name,
                    key,
                    e
                );
                return;
            }
        };
        let p = inner.partition(realm);
        let mut held = p.write().unwrap_or_else(PoisonError::into_inner);
        match &inner.reconcile {
            None => {
                held.insert(key.to_string(), value);
            }
            Some(r) => match r.restore(key, value, held.get(key), partition_id(realm)) {
                Ok(Some(v)) => {
                    held.insert(key.to_string(), v);
                }
                Ok(None) => {}
                Err(e) => tracing::error!(
                    "{}realms: \"{}\" could not reconcile a stored row under \"{}\", so it was NOT applied and what \
                     this process held is unchanged: {}",
                    tag(codes::STS_CORE_0042),
                    inner.name,
                    key,
                    e
                ),
            },
        }
    }

    fn remove(&self, realm: &str, key: &str) {
        let Some(inner) = self.0.upgrade() else {
            return;
        };
        let p = inner.partition(realm);
        let mut held = p.write().unwrap_or_else(PoisonError::into_inner);
        let allowed = match &inner.reconcile {
            None => true,
            Some(r) => {
                match r.remove(key, held.get(key), partition_id(realm)) {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::error!(
                        "{}realms: \"{}\" could not reconcile a stored removal of \"{}\", so it was NOT applied and \
                         what this process held is unchanged: {}",
                        tag(codes::STS_CORE_0042),
                        inner.name,
                        key,
                        e
                    );
                        false
                    }
                }
            }
        };
        if allowed {
            held.shift_remove(key);
        }
    }
}

/// One realm's partition of a [`RealmMap`], journalling under that realm.
pub struct RealmView<V> {
    inner: Arc<Inner<V>>,
    realm: String,
    part: Partition<V>,
}

impl<V> RealmMap<V>
where
    V: Clone + Serialize + DeserializeOwned + Send + Sync + 'static,
{
    /// Declares a per-realm map, purged when a realm is removed.
    pub fn new(
        lifecycle: &Arc<RealmLifecycle>,
        handles: &Arc<StoreHandles>,
        spec: StoreSpec,
    ) -> RealmMap<V> {
        RealmMap::with_reconcile(lifecycle, handles, spec, None)
    }

    /// The same, with the store's rule for rows other processes send.
    pub fn with_reconcile(
        lifecycle: &Arc<RealmLifecycle>,
        handles: &Arc<StoreHandles>,
        spec: StoreSpec,
        reconcile: Option<Arc<dyn Reconcile<V>>>,
    ) -> RealmMap<V> {
        let inner = Arc::new(Inner {
            partitions: RwLock::new(HashMap::new()),
            handle: RwLock::new(None),
            name: spec
                .persist
                .clone()
                .unwrap_or_else(|| "(undeclared)".to_string()),
            handles: handles.clone(),
            lifecycle: Arc::downgrade(lifecycle),
            reconcile,
            shared: false,
        });
        let handle = handles.declare(
            &spec,
            "map",
            "realm",
            Arc::new(MapAccess(Arc::downgrade(&inner))),
        );
        *inner.handle.write().unwrap_or_else(PoisonError::into_inner) = handle;
        let weak = Arc::downgrade(&inner);
        lifecycle.on_remove(Arc::new(move |id: &str| {
            if let Some(inner) = weak.upgrade() {
                inner
                    .partitions
                    .write()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(id);
            }
        }));
        RealmMap { inner }
    }

    fn current(&self) -> RealmView<V> {
        self.in_realm(&realm::current_id())
    }

    /// One realm's partition by name.
    pub fn in_realm(&self, realm: &str) -> RealmView<V> {
        let realm = partition_id(realm).to_string();
        RealmView {
            part: self.inner.partition(&realm),
            inner: self.inner.clone(),
            realm,
        }
    }

    /// Every partition held, by realm id.
    pub fn realm_ids(&self) -> Vec<String> {
        self.inner
            .partitions
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .cloned()
            .collect()
    }

    pub fn handle(&self) -> Option<String> {
        self.inner
            .handle
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn get(&self, key: &str) -> Option<V> {
        self.current().get(key)
    }
    pub fn set(&self, key: &str, value: V) {
        self.current().set(key, value)
    }
    pub fn has(&self, key: &str) -> bool {
        self.current().has(key)
    }
    pub fn delete(&self, key: &str) -> bool {
        self.current().delete(key)
    }
    pub fn clear(&self) {
        self.current().clear()
    }
    pub fn len(&self) -> usize {
        self.current().len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn keys(&self) -> Vec<String> {
        self.current().keys()
    }
    pub fn entries(&self) -> Vec<(String, V)> {
        self.current().entries()
    }
    /// Edits a row in place, and reports it.
    pub fn update<R>(
        &self,
        key: &str,
        f: impl FnOnce(&mut V) -> R,
    ) -> Option<R> {
        self.current().update(key, f)
    }
}

impl<V: Clone> RealmView<V> {
    pub fn realm(&self) -> &str {
        &self.realm
    }

    fn held(&self) -> std::sync::RwLockReadGuard<'_, IndexMap<String, V>> {
        self.part.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn held_mut(&self) -> std::sync::RwLockWriteGuard<'_, IndexMap<String, V>> {
        self.part.write().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn get(&self, key: &str) -> Option<V> {
        self.held().get(key).cloned()
    }

    pub fn set(&self, key: &str, value: V) {
        self.held_mut().insert(key.to_string(), value);
        self.inner.note(&self.realm, key);
    }

    pub fn has(&self, key: &str) -> bool {
        self.held().contains_key(key)
    }

    /// Reported whether or not the key was held: a row restored and swept
    /// before anything read it still has a stored row to delete.
    pub fn delete(&self, key: &str) -> bool {
        let gone = self.held_mut().shift_remove(key).is_some();
        self.inner.note(&self.realm, key);
        gone
    }

    /// Every key reported BEFORE the clear: afterwards there is nothing
    /// left to name.
    pub fn clear(&self) {
        let keys: Vec<String> = if self.inner.journals() {
            self.keys()
        } else {
            Vec::new()
        };
        for k in &keys {
            self.inner.note(&self.realm, k);
        }
        self.held_mut().clear();
    }

    pub fn len(&self) -> usize {
        self.held().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn keys(&self) -> Vec<String> {
        self.held().keys().cloned().collect()
    }

    pub fn entries(&self) -> Vec<(String, V)> {
        self.held()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    pub fn update<R>(
        &self,
        key: &str,
        f: impl FnOnce(&mut V) -> R,
    ) -> Option<R> {
        let answer = self.held_mut().get_mut(key).map(f);
        if answer.is_some() {
            self.inner.note(&self.realm, key);
        }
        answer
    }

    /// Removes every row for which `keep` answers false, reporting each.
    pub fn retain(&self, mut keep: impl FnMut(&str, &V) -> bool) -> usize {
        let gone: Vec<String> = self
            .held()
            .iter()
            .filter(|(k, v)| !keep(k, v))
            .map(|(k, _)| k.clone())
            .collect();
        for k in &gone {
            self.delete(k);
        }
        gone.len()
    }
}

/// One map for the whole process, reported under the realm `''`: a shared
/// store has one row set, and filing its writes under whichever realm was
/// ambient would scatter them.
pub struct SharedMap<V> {
    inner: Arc<Inner<V>>,
}

impl<V> SharedMap<V>
where
    V: Clone + Serialize + DeserializeOwned + Send + Sync + 'static,
{
    pub fn new(handles: &Arc<StoreHandles>, spec: StoreSpec) -> SharedMap<V> {
        let inner = Arc::new(Inner {
            partitions: RwLock::new(HashMap::new()),
            handle: RwLock::new(None),
            name: spec
                .persist
                .clone()
                .unwrap_or_else(|| "(undeclared)".to_string()),
            handles: handles.clone(),
            lifecycle: Weak::new(),
            reconcile: None,
            shared: true,
        });
        let handle = handles.declare(
            &spec,
            "shared-map",
            "shared",
            Arc::new(SharedAccess(Arc::downgrade(&inner))),
        );
        *inner.handle.write().unwrap_or_else(PoisonError::into_inner) = handle;
        SharedMap { inner }
    }

    fn view(&self) -> RealmView<V> {
        RealmView {
            part: self.inner.partition(DEFAULT_ID),
            inner: self.inner.clone(),
            realm: String::new(),
        }
    }

    pub fn get(&self, key: &str) -> Option<V> {
        self.view().get(key)
    }
    pub fn set(&self, key: &str, value: V) {
        self.view().set(key, value)
    }
    pub fn has(&self, key: &str) -> bool {
        self.view().has(key)
    }
    pub fn delete(&self, key: &str) -> bool {
        self.view().delete(key)
    }
    pub fn clear(&self) {
        self.view().clear()
    }
    pub fn len(&self) -> usize {
        self.view().len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn entries(&self) -> Vec<(String, V)> {
        self.view().entries()
    }
}

struct SharedAccess<V>(Weak<Inner<V>>);

impl<V> StoreAccess for SharedAccess<V>
where
    V: Clone + Serialize + DeserializeOwned + Send + Sync + 'static,
{
    fn dump(&self, _realm: &str) -> Vec<(String, Json)> {
        MapAccess(self.0.clone()).dump(DEFAULT_ID)
    }
    fn read(&self, _realm: &str, key: &str) -> Option<Json> {
        MapAccess(self.0.clone()).read(DEFAULT_ID, key)
    }
    fn restore(&self, _realm: &str, key: &str, value: Json) {
        MapAccess(self.0.clone()).restore(DEFAULT_ID, key, value)
    }
    fn remove(&self, _realm: &str, key: &str) {
        MapAccess(self.0.clone()).remove(DEFAULT_ID, key)
    }
}
