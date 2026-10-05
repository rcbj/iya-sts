// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A bounded cache in least-recently-USED order, with pinning
//! (`common/bounded_lru.ts`, #349).
//!
//! * **The bound is a function**, asked on every insert, so a runtime
//!   setting that lowers it takes effect at the next insert. A bound of 0
//!   is treated as 1: a bound nobody can read is not permission to grow.
//! * **A pinned key is never evicted** (an unwritten change, a running
//!   request's working set). Pins are counted. With every key pinned the
//!   cache stays over its bound, and `stats().over_bound` says by how much:
//!   a correctness rule outranks a size rule.
//! * **It describes itself to the registry** when given one; a row is the
//!   key as `row_of` shows it, never the value.
//!
//! Recency is a tick per key and an ordered index over the ticks, so a read
//! and an eviction are O(log n) for the 200,000-entry directory window this
//! was written for.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::registry::{CacheRegistry, Counter, Descriptor, Row, Scope};

type Bound = Arc<dyn Fn() -> usize + Send + Sync>;
type RowOf<K> = Arc<dyn Fn(&K) -> (Option<String>, String) + Send + Sync>;
type OnEvict<K, V> = Arc<dyn Fn(&K, &V) + Send + Sync>;

/// What the cache says on `/admin/caches`, and how it is bounded.
pub struct LruOptions<K, V> {
    pub name: String,
    pub max_entries: Bound,
    pub title: Option<String>,
    pub description: Option<String>,
    pub owner: Option<String>,
    pub scope: Scope,
    pub settings: Vec<String>,
    pub lifetime: Option<String>,
    pub bound: Option<String>,
    pub row_of: Option<RowOf<K>>,
    /// Told of every key the bound evicted, after it has gone.
    pub on_evict: Option<OnEvict<K, V>>,
}

impl<K, V> LruOptions<K, V> {
    pub fn new(
        name: &str,
        max_entries: impl Fn() -> usize + Send + Sync + 'static,
    ) -> LruOptions<K, V> {
        LruOptions {
            name: name.to_string(),
            max_entries: Arc::new(max_entries),
            title: None,
            description: None,
            owner: None,
            scope: Scope::Process,
            settings: Vec::new(),
            lifetime: None,
            bound: None,
            row_of: None,
            on_evict: None,
        }
    }
}

/// `stats()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LruStats {
    pub name: String,
    pub size: usize,
    pub max_entries: usize,
    pub pinned: usize,
    pub over_bound: usize,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

struct Core<K, V> {
    held: HashMap<K, (V, u64)>,
    order: BTreeMap<u64, K>,
    pins: HashMap<K, usize>,
    tick: u64,
    hits: u64,
    misses: u64,
    evictions: u64,
}

impl<K: Hash + Eq + Clone, V> Core<K, V> {
    fn touch(&mut self, key: &K) {
        self.tick += 1;
        let tick = self.tick;
        if let Some(entry) = self.held.get_mut(key) {
            self.order.remove(&entry.1);
            entry.1 = tick;
            self.order.insert(tick, key.clone());
        }
    }

    fn is_pinned(&self, key: &K) -> bool {
        self.pins.get(key).is_some_and(|n| *n > 0)
    }
}

fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The cache. Shared behind an `Arc`; every method takes `&self`.
pub struct BoundedLru<K, V> {
    core: Arc<Mutex<Core<K, V>>>,
    name: String,
    limit: Bound,
    counter: Option<Counter>,
    on_evict: Option<OnEvict<K, V>>,
}

impl<K, V> BoundedLru<K, V>
where
    // `Debug` is how a key is shown on the page when no `row_of` is given.
    K: Hash + Eq + Clone + Send + std::fmt::Debug + 'static,
    V: Clone + Send + 'static,
{
    /// Builds the cache and, given a registry, describes it there.
    pub fn new(
        options: LruOptions<K, V>,
        registry: Option<&CacheRegistry>,
    ) -> BoundedLru<K, V> {
        let core = Arc::new(Mutex::new(Core {
            held: HashMap::new(),
            order: BTreeMap::new(),
            pins: HashMap::new(),
            tick: 0,
            hits: 0,
            misses: 0,
            evictions: 0,
        }));
        let limit = options.max_entries.clone();
        let counter = registry.map(|r| {
            r.register(Arc::new(LruDescriptor {
                core: core.clone(),
                limit: limit.clone(),
                name: options.name.clone(),
                title: options.title.clone().unwrap_or_else(|| options.name.clone()),
                description: options
                    .description
                    .clone()
                    .unwrap_or_else(|| "A bounded cache in least-recently-used order.".to_string()),
                owner: options.owner.clone().unwrap_or_else(|| "sts-cache::BoundedLru".to_string()),
                scope: options.scope,
                settings: options.settings.clone(),
                lifetime: options
                    .lifetime
                    .clone()
                    .unwrap_or_else(|| "Until evicted by the bound or dropped by its owner.".to_string()),
                bound: options.bound.clone().unwrap_or_else(|| {
                    "Enforced: an insert past the bound evicts the least recently used unpinned entries."
                        .to_string()
                }),
                row_of: options.row_of.clone(),
            }))
        });
        BoundedLru {
            core,
            name: options.name,
            limit,
            counter,
            on_evict: options.on_evict,
        }
    }

    /// The bound now: at least one.
    pub fn limit(&self) -> usize {
        (self.limit)().max(1)
    }

    pub fn len(&self) -> usize {
        locked(&self.core).held.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The ONE counted lookup; a hit becomes the most recently used.
    pub fn get(&self, key: &K) -> Option<V> {
        let mut core = locked(&self.core);
        let value = core.held.get(key).map(|(v, _)| v.clone());
        match value {
            Some(v) => {
                core.touch(key);
                core.hits += 1;
                if let Some(c) = &self.counter {
                    c.hit();
                }
                Some(v)
            }
            None => {
                core.misses += 1;
                if let Some(c) = &self.counter {
                    c.miss();
                }
                None
            }
        }
    }

    /// A read that is neither counted nor a use.
    pub fn peek(&self, key: &K) -> Option<V> {
        locked(&self.core).held.get(key).map(|(v, _)| v.clone())
    }

    pub fn contains_key(&self, key: &K) -> bool {
        locked(&self.core).held.contains_key(key)
    }

    /// Puts a value as the most recently used, then evicts.
    pub fn insert(&self, key: K, value: V) {
        let victims = {
            let mut core = locked(&self.core);
            core.tick += 1;
            let tick = core.tick;
            if let Some((_, old)) = core.held.insert(key.clone(), (value, tick))
            {
                core.order.remove(&old);
            }
            core.order.insert(tick, key);
            self.trim(&mut core)
        };
        self.evicted(victims);
    }

    /// Drops a key and any pins on it.
    pub fn remove(&self, key: &K) -> bool {
        let mut core = locked(&self.core);
        core.pins.remove(key);
        match core.held.remove(key) {
            Some((_, tick)) => {
                core.order.remove(&tick);
                true
            }
            None => false,
        }
    }

    /// Drops every key and pin; the counters are the process's and stay.
    pub fn clear(&self) {
        let mut core = locked(&self.core);
        core.held.clear();
        core.order.clear();
        core.pins.clear();
    }

    /// The keys, least to most recently used.
    pub fn keys(&self) -> Vec<K> {
        locked(&self.core).order.values().cloned().collect()
    }

    /// Keeps a key from eviction until unpinned as many times; a key may be
    /// pinned before it is held.
    pub fn pin(&self, key: &K) {
        *locked(&self.core).pins.entry(key.clone()).or_insert(0) += 1;
    }

    /// Releases one pin, and evicts if the cache is over its bound.
    pub fn unpin(&self, key: &K) {
        let victims = {
            let mut core = locked(&self.core);
            match core.pins.get(key).copied().unwrap_or(0) {
                0 | 1 => {
                    core.pins.remove(key);
                }
                n => {
                    core.pins.insert(key.clone(), n - 1);
                }
            }
            self.trim(&mut core)
        };
        self.evicted(victims);
    }

    pub fn is_pinned(&self, key: &K) -> bool {
        locked(&self.core).is_pinned(key)
    }

    /// From the old end, skipping pinned keys. Hot path: no tracing span.
    fn trim(&self, core: &mut Core<K, V>) -> Vec<(K, V)> {
        let max = self.limit();
        let mut excess = core.held.len().saturating_sub(max);
        if excess == 0 {
            return Vec::new();
        }
        let mut chosen = Vec::new();
        for key in core.order.values() {
            if excess == 0 {
                break;
            }
            if core.is_pinned(key) {
                continue;
            }
            chosen.push(key.clone());
            excess -= 1;
        }
        let mut victims = Vec::new();
        for key in chosen {
            if let Some((value, tick)) = core.held.remove(&key) {
                core.order.remove(&tick);
                victims.push((key, value));
            }
        }
        core.evictions += victims.len() as u64;
        victims
    }

    /// Counts the victims and tells the listener, outside the lock.
    fn evicted(&self, victims: Vec<(K, V)>) {
        if victims.is_empty() {
            return;
        }
        if let Some(c) = &self.counter {
            c.evicted(victims.len());
        }
        if let Some(listener) = &self.on_evict {
            for (k, v) in &victims {
                listener(k, v);
            }
        }
    }

    pub fn stats(&self) -> LruStats {
        let max = self.limit();
        let core = locked(&self.core);
        let pinned = core
            .pins
            .iter()
            .filter(|(k, n)| **n > 0 && core.held.contains_key(*k))
            .count();
        LruStats {
            name: self.name.clone(),
            size: core.held.len(),
            max_entries: max,
            pinned,
            over_bound: core.held.len().saturating_sub(max),
            hits: core.hits,
            misses: core.misses,
            evictions: core.evictions,
        }
    }
}

/// The cache as the registry sees it.
struct LruDescriptor<K, V> {
    core: Arc<Mutex<Core<K, V>>>,
    limit: Bound,
    name: String,
    title: String,
    description: String,
    owner: String,
    scope: Scope,
    settings: Vec<String>,
    lifetime: String,
    bound: String,
    row_of: Option<RowOf<K>>,
}

impl<K, V> Descriptor for LruDescriptor<K, V>
where
    K: Hash + Eq + Clone + Send + std::fmt::Debug + 'static,
    V: Send + 'static,
{
    fn name(&self) -> &str {
        &self.name
    }
    fn title(&self) -> &str {
        &self.title
    }
    fn description(&self) -> &str {
        &self.description
    }
    fn owner(&self) -> &str {
        &self.owner
    }
    fn scope(&self) -> Scope {
        self.scope
    }
    fn max_entries(&self) -> usize {
        (self.limit)().max(1)
    }
    fn bound(&self) -> String {
        self.bound.clone()
    }
    fn lifetime(&self) -> String {
        self.lifetime.clone()
    }
    fn settings(&self) -> Vec<String> {
        self.settings.clone()
    }
    fn hit_meaning(&self) -> String {
        "a read answered from the cache without going to the store".to_string()
    }
    fn entries(&self, _now: i64) -> Result<Vec<Row>, String> {
        let core = locked(&self.core);
        Ok(core
            .order
            .values()
            .map(|k| {
                let (realm, key) = match &self.row_of {
                    Some(f) => f(k),
                    None => (None, format!("{:?}", k)),
                };
                Row {
                    realm,
                    key,
                    valid_until: None,
                    valid: true,
                    basis: "least recently used".to_string(),
                }
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn lru(max: usize) -> BoundedLru<String, u32> {
        BoundedLru::new(LruOptions::new("t", move || max), None)
    }

    #[test]
    fn evicts_the_least_recently_read() {
        let c = lru(2);
        c.insert("a".into(), 1);
        c.insert("b".into(), 2);
        assert_eq!(c.get(&"a".into()), Some(1));
        c.insert("c".into(), 3);
        assert_eq!(c.keys(), vec!["a".to_string(), "c".to_string()]);
        assert_eq!(c.stats().evictions, 1);
    }

    #[test]
    fn a_pinned_key_stays_and_the_overrun_shows() {
        let c = lru(1);
        c.pin(&"a".into());
        c.insert("a".into(), 1);
        c.pin(&"b".into());
        c.insert("b".into(), 2);
        assert_eq!(c.len(), 2);
        assert_eq!(c.stats().over_bound, 1);
        c.unpin(&"a".into());
        assert_eq!(c.keys(), vec!["b".to_string()]);
    }

    #[test]
    fn a_bound_of_zero_is_one_and_listeners_hear_evictions() {
        let heard = Arc::new(AtomicUsize::new(0));
        let h = heard.clone();
        let mut o = LruOptions::new("t", || 0);
        o.on_evict = Some(Arc::new(move |_: &String, _: &u32| {
            h.fetch_add(1, Ordering::Relaxed);
        }));
        let c = BoundedLru::new(o, None);
        c.insert("a".into(), 1);
        c.insert("b".into(), 2);
        assert_eq!(c.len(), 1);
        assert_eq!(heard.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn it_describes_itself_and_counts() {
        let registry = CacheRegistry::new();
        let c: BoundedLru<String, u32> = BoundedLru::new(
            LruOptions::new("dir.window", || 3),
            Some(&registry),
        );
        c.insert("k".into(), 1);
        c.get(&"k".into());
        c.get(&"missing".into());
        let report = registry.report(0);
        assert_eq!(report.len(), 1);
        let s = &report[0];
        assert_eq!(
            (s.size, s.max_entries, s.hits, s.misses),
            (1, 3, Some(1), Some(1))
        );
        assert_eq!(s.hit_ratio, Some(0.5));
    }
}
