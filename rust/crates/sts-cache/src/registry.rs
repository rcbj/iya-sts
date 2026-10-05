// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The registry itself: descriptors, counters, the report `/admin/caches`
//! draws, the compact snapshot another cluster node reads, and the
//! ejection the `caches.eject-expired` job runs.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use openssl::hash::{hash, MessageDigest};
use serde::Serialize;
use sts_core::errors::codes;
use sts_core::log::tag;

/// One bound for the whole process, or one per realm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Process,
    Realm,
}

/// A `cache` can be rebuilt from somewhere else; a `replay` store makes a
/// one-time value work once, and its entries cannot be rebuilt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Cache,
    Replay,
}

/// One entry as the page shows it: which realm, a key, how long it has —
/// and never its value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Row {
    pub realm: Option<String>,
    pub key: String,
    /// Milliseconds since the epoch; `None` for no expiry.
    pub valid_until: Option<i64>,
    pub valid: bool,
    pub basis: String,
}

impl Row {
    /// A row whose validity is its deadline against `now`.
    pub fn timed(
        realm: Option<String>,
        key: String,
        valid_until: Option<i64>,
        now: i64,
    ) -> Row {
        Row {
            realm,
            key,
            valid_until,
            valid: valid_until.is_none_or(|u| u > now),
            basis: if valid_until.is_some() {
                "time".to_string()
            } else {
                "no expiry".to_string()
            },
        }
    }
}

/// What a cache says about itself, asked when the page is drawn and never
/// on a request.
pub trait Descriptor: Send + Sync {
    fn name(&self) -> &str;
    fn title(&self) -> &str;
    fn description(&self) -> &str;
    /// The owning file.
    fn owner(&self) -> &str;
    fn scope(&self) -> Scope;
    fn kind(&self) -> Kind {
        Kind::Cache
    }
    /// The bound: per realm for a `Realm` scope.
    fn max_entries(&self) -> usize;
    /// How the bound holds, in a sentence: ENFORCED or STRUCTURAL.
    fn bound(&self) -> String {
        String::new()
    }
    fn lifetime(&self) -> String;
    /// The rows held now. An error is shown on the cache's row, never fatal.
    fn entries(&self, now: i64) -> Result<Vec<Row>, String>;
    /// Whether this store's entries expire and `eject()` deletes them.
    fn ejects(&self) -> bool {
        false
    }
    /// Deletes what has expired at `now` and answers how many. Deletes
    /// nothing its reader would still honour.
    fn eject(&self, _now: i64) -> Result<usize, String> {
        Ok(0)
    }
    /// The settings that size or time it.
    fn settings(&self) -> Vec<String> {
        Vec::new()
    }
    /// What a hit means for this store.
    fn hit_meaning(&self) -> String {
        "a lookup answered from the cache".to_string()
    }
    fn persisted(&self) -> bool {
        false
    }
    /// `false` where the lookup is in a file this repository may not edit;
    /// the reason is what the page says.
    fn counted(&self) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Default)]
struct Counts {
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
    refusals: AtomicU64,
}

/// What an owner calls at its ONE lookup, and when its bound acts.
#[derive(Clone)]
pub struct Counter(Arc<Counts>);

impl Counter {
    /// A counter that belongs to no registry (a test's, or an unregistered
    /// store's).
    pub fn detached() -> Counter {
        Counter(Arc::new(Counts::default()))
    }

    // Hot path: called on every lookup, so no tracing span.
    pub fn hit(&self) {
        self.0.hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn miss(&self) {
        self.0.misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn evicted(&self, n: usize) {
        self.0.evictions.fetch_add(n as u64, Ordering::Relaxed);
    }

    pub fn refused(&self) {
        self.0.refusals.fetch_add(1, Ordering::Relaxed);
    }

    fn read(&self) -> (u64, u64, u64, u64) {
        (
            self.0.hits.load(Ordering::Relaxed),
            self.0.misses.load(Ordering::Relaxed),
            self.0.evictions.load(Ordering::Relaxed),
            self.0.refusals.load(Ordering::Relaxed),
        )
    }

    fn reset(&self) {
        self.0.hits.store(0, Ordering::Relaxed);
        self.0.misses.store(0, Ordering::Relaxed);
        self.0.evictions.store(0, Ordering::Relaxed);
        self.0.refusals.store(0, Ordering::Relaxed);
    }
}

/// One store summarised, as `report()` answers it.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub name: String,
    pub title: String,
    pub description: String,
    pub owner: String,
    pub scope: Scope,
    pub kind: Kind,
    pub persisted: bool,
    pub size: usize,
    pub largest_realm: usize,
    pub valid: usize,
    pub expired: usize,
    pub max_entries: usize,
    pub bound: String,
    pub at_bound: bool,
    pub lifetime: String,
    pub settings: Vec<String>,
    pub counted: bool,
    pub not_counted_why: String,
    pub hit_meaning: String,
    pub hits: Option<u64>,
    pub misses: Option<u64>,
    pub hit_ratio: Option<f64>,
    pub evictions: u64,
    pub refusals: u64,
    pub problem: Option<String>,
}

/// One store with every row it holds, soonest deadline first.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Detail {
    pub summary: Summary,
    pub rows: Vec<Row>,
}

/// One store in the compact form another node reads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotRow {
    pub name: String,
    pub size: usize,
    pub largest_realm: usize,
    pub valid: usize,
    pub max_entries: usize,
    pub hits: Option<u64>,
    pub misses: Option<u64>,
    pub evictions: u64,
    pub refusals: u64,
}

/// `snapshot()`: sizes and counters, never a row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Snapshot {
    pub at: i64,
    pub caches: Vec<SnapshotRow>,
}

/// What `eject_expired()` did.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Ejected {
    pub ejected: usize,
    pub by_cache: BTreeMap<String, usize>,
    pub failed: Vec<String>,
}

struct Registered {
    descriptor: Arc<dyn Descriptor>,
    counter: Counter,
}

/// The registry. One per process, built by the composition root.
#[derive(Default)]
pub struct CacheRegistry {
    stores: Mutex<BTreeMap<String, Registered>>,
}

/// A lock whose holder panicked still holds a consistent map: every write
/// to it is one insert or remove.
fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl CacheRegistry {
    pub fn new() -> CacheRegistry {
        CacheRegistry::default()
    }

    /// Registers a store, replacing one of the same name (a rebuilt
    /// instance must not leave two rows), and answers its counter. A
    /// re-registration keeps the counts.
    pub fn register(&self, descriptor: Arc<dyn Descriptor>) -> Counter {
        let name = descriptor.name().to_string();
        let mut stores = locked(&self.stores);
        let counter = stores
            .get(&name)
            .map_or_else(Counter::detached, |r| r.counter.clone());
        stores.insert(
            name,
            Registered {
                descriptor,
                counter: counter.clone(),
            },
        );
        counter
    }

    pub fn names(&self) -> Vec<String> {
        locked(&self.stores).keys().cloned().collect()
    }

    pub fn has(&self, name: &str) -> bool {
        locked(&self.stores).contains_key(name)
    }

    /// The counter of a registered store.
    pub fn counter(&self, name: &str) -> Option<Counter> {
        locked(&self.stores).get(name).map(|r| r.counter.clone())
    }

    /// For tests: drop one store.
    pub fn forget(&self, name: &str) -> bool {
        locked(&self.stores).remove(name).is_some()
    }

    /// For tests: zero every counter, keep the descriptors.
    pub fn reset_counts(&self) {
        for r in locked(&self.stores).values() {
            r.counter.reset();
        }
    }

    /// The registered stores, without the lock held while they are asked:
    /// a descriptor may itself take a lock its owner holds.
    fn snapshot_of(&self) -> Vec<(Arc<dyn Descriptor>, Counter)> {
        locked(&self.stores)
            .values()
            .map(|r| (r.descriptor.clone(), r.counter.clone()))
            .collect()
    }

    /// Every store summarised, in name order.
    pub fn report(&self, now: i64) -> Vec<Summary> {
        self.snapshot_of()
            .into_iter()
            .map(|(d, c)| {
                let (rows, problem) = rows_of(d.as_ref(), now);
                summary_of(d.as_ref(), &c, &rows, problem)
            })
            .collect()
    }

    /// One store with its rows, soonest deadline first (none last), then
    /// realm and key.
    pub fn detail(&self, name: &str, now: i64) -> Option<Detail> {
        let (d, c) = {
            let stores = locked(&self.stores);
            let r = stores.get(name)?;
            (r.descriptor.clone(), r.counter.clone())
        };
        let (mut rows, problem) = rows_of(d.as_ref(), now);
        let summary = summary_of(d.as_ref(), &c, &rows, problem);
        rows.sort_by(|a, b| {
            let x = a.valid_until.unwrap_or(i64::MAX);
            let y = b.valid_until.unwrap_or(i64::MAX);
            x.cmp(&y)
                .then_with(|| a.realm.cmp(&b.realm))
                .then_with(|| a.key.cmp(&b.key))
        });
        Some(Detail { summary, rows })
    }

    /// The compact form a cluster node publishes on its membership row.
    pub fn snapshot(&self, now: i64) -> Snapshot {
        let caches = self
            .report(now)
            .into_iter()
            .map(|s| SnapshotRow {
                name: s.name,
                size: s.size,
                largest_realm: s.largest_realm,
                valid: s.valid,
                max_entries: s.max_entries,
                hits: s.hits,
                misses: s.misses,
                evictions: s.evictions,
                refusals: s.refusals,
            })
            .collect();
        Snapshot { at: now, caches }
    }

    /// Calls every store's ejector. Housekeeping, never correctness: every
    /// owner still refuses an expired entry where it reads it.
    pub fn eject_expired(&self, now: i64) -> Ejected {
        let mut out = Ejected::default();
        for (d, c) in self.snapshot_of() {
            if !d.ejects() {
                continue;
            }
            match d.eject(now) {
                Ok(0) => {}
                Ok(n) => {
                    out.by_cache.insert(d.name().to_string(), n);
                    out.ejected += n;
                    c.evicted(n);
                }
                Err(e) => out.failed.push(format!("{}: {}", d.name(), e)),
            }
        }
        out
    }

    /// The stores that eject, in name order.
    pub fn ejecting(&self) -> Vec<String> {
        self.snapshot_of()
            .into_iter()
            .filter(|(d, _)| d.ejects())
            .map(|(d, _)| d.name().to_string())
            .collect()
    }
}

fn rows_of(d: &dyn Descriptor, now: i64) -> (Vec<Row>, Option<String>) {
    match d.entries(now) {
        Ok(rows) => (rows, None),
        Err(e) => {
            tracing::error!(
                "{}Cache {} could not list its entries: {}",
                tag(codes::STS_CORE_0095),
                d.name(),
                e
            );
            (Vec::new(), Some(e))
        }
    }
}

fn largest_realm_of(rows: &[Row]) -> usize {
    let mut per: BTreeMap<&str, usize> = BTreeMap::new();
    for r in rows {
        *per.entry(r.realm.as_deref().unwrap_or("")).or_default() += 1;
    }
    per.values().copied().max().unwrap_or(0)
}

fn summary_of(
    d: &dyn Descriptor,
    c: &Counter,
    rows: &[Row],
    problem: Option<String>,
) -> Summary {
    let (hits, misses, evictions, refusals) = c.read();
    let valid = rows.iter().filter(|r| r.valid).count();
    let max = d.max_entries();
    let largest = match d.scope() {
        Scope::Realm => largest_realm_of(rows),
        Scope::Process => rows.len(),
    };
    let counted = d.counted();
    let lookups = hits + misses;
    Summary {
        name: d.name().to_string(),
        title: d.title().to_string(),
        description: d.description().to_string(),
        owner: d.owner().to_string(),
        scope: d.scope(),
        kind: d.kind(),
        persisted: d.persisted(),
        size: rows.len(),
        largest_realm: largest,
        valid,
        expired: rows.len() - valid,
        max_entries: max,
        bound: d.bound(),
        at_bound: largest >= max,
        lifetime: d.lifetime(),
        settings: d.settings(),
        counted: counted.is_ok(),
        not_counted_why: counted.clone().err().unwrap_or_default(),
        hit_meaning: d.hit_meaning(),
        hits: counted.is_ok().then_some(hits),
        misses: counted.is_ok().then_some(misses),
        hit_ratio: (counted.is_ok() && lookups > 0)
            .then(|| hits as f64 / lookups as f64),
        evictions,
        refusals,
        problem,
    }
}

/// A key clipped for display: its front, and its length.
pub fn clip_key(text: &str, max: usize) -> String {
    let limit = if max == 0 { 160 } else { max };
    let units: Vec<u16> = text.encode_utf16().collect();
    if units.len() <= limit {
        text.to_string()
    } else {
        format!(
            "{}… ({} characters)",
            String::from_utf16_lossy(&units[..limit]),
            units.len()
        )
    }
}

/// A key that is itself a credential, shown as its kind prefix (up to the
/// first colon, within sixteen characters) and the first twelve hex
/// characters of its SHA-256.
pub fn digest_key(text: &str) -> String {
    let kind = match text.find(':') {
        Some(at) if at > 0 && text[..at].encode_utf16().count() <= 16 => {
            &text[..=at]
        }
        _ => "",
    };
    let digest = hash(MessageDigest::sha256(), text.as_bytes())
        .map(|d| d.iter().map(|b| format!("{:02x}", b)).collect::<String>())
        .unwrap_or_default();
    format!("{}sha256:{}…", kind, &digest[..12.min(digest.len())])
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    struct Fixed {
        name: &'static str,
        scope: Scope,
        rows: Vec<Row>,
        fail: bool,
    }

    impl Descriptor for Fixed {
        fn name(&self) -> &str {
            self.name
        }
        fn title(&self) -> &str {
            "T"
        }
        fn description(&self) -> &str {
            "D"
        }
        fn owner(&self) -> &str {
            "test"
        }
        fn scope(&self) -> Scope {
            self.scope
        }
        fn max_entries(&self) -> usize {
            2
        }
        fn lifetime(&self) -> String {
            "a minute".to_string()
        }
        fn entries(&self, _now: i64) -> Result<Vec<Row>, String> {
            if self.fail {
                Err("it broke".to_string())
            } else {
                Ok(self.rows.clone())
            }
        }
        fn ejects(&self) -> bool {
            true
        }
        fn eject(&self, _now: i64) -> Result<usize, String> {
            if self.fail {
                Err("no".to_string())
            } else {
                Ok(1)
            }
        }
    }

    fn row(
        realm: Option<&str>,
        key: &str,
        until: Option<i64>,
        now: i64,
    ) -> Row {
        Row::timed(realm.map(str::to_string), key.to_string(), until, now)
    }

    #[test]
    fn a_report_counts_validity_and_the_fullest_realm() {
        let r = CacheRegistry::new();
        let c = r.register(Arc::new(Fixed {
            name: "a",
            scope: Scope::Realm,
            rows: vec![
                row(Some("x"), "1", Some(50), 100),
                row(Some("x"), "2", Some(500), 100),
                row(Some("y"), "3", None, 100),
            ],
            fail: false,
        }));
        c.hit();
        c.hit();
        c.miss();
        c.evicted(4);
        let s = &r.report(100)[0];
        assert_eq!((s.size, s.largest_realm, s.valid, s.expired), (3, 2, 2, 1));
        assert!(s.at_bound);
        assert_eq!(s.hit_ratio, Some(2.0 / 3.0));
        assert_eq!(s.evictions, 4);
        let d = r.detail("a", 100).unwrap();
        let keys: Vec<&str> = d.rows.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(keys, vec!["1", "2", "3"]);
    }

    #[test]
    fn a_descriptor_that_fails_shows_why_and_ejection_carries_on() {
        let r = CacheRegistry::new();
        r.register(Arc::new(Fixed {
            name: "bad",
            scope: Scope::Process,
            rows: vec![],
            fail: true,
        }));
        r.register(Arc::new(Fixed {
            name: "good",
            scope: Scope::Process,
            rows: vec![],
            fail: false,
        }));
        let report = r.report(0);
        assert_eq!(report[0].problem.as_deref(), Some("it broke"));
        let e = r.eject_expired(0);
        assert_eq!(e.ejected, 1);
        assert_eq!(e.failed, vec!["bad: no".to_string()]);
        assert_eq!(r.ejecting(), vec!["bad".to_string(), "good".to_string()]);
        assert_eq!(r.report(0)[1].evictions, 1);
    }

    #[test]
    fn re_registering_keeps_one_row_and_its_counts() {
        let r = CacheRegistry::new();
        let make = || {
            Arc::new(Fixed {
                name: "a",
                scope: Scope::Process,
                rows: vec![],
                fail: false,
            })
        };
        r.register(make()).hit();
        r.register(make());
        assert_eq!(r.names(), vec!["a".to_string()]);
        assert_eq!(r.report(0)[0].hits, Some(1));
    }

    #[test]
    fn keys_are_shown_as_node_shows_them() {
        assert_eq!(
            digest_key("session:abcdef"),
            "session:sha256:13dc6973a59b…"
        );
        assert_eq!(digest_key("nocolon"), "sha256:91afaf58c731…");
        assert_eq!(
            digest_key("averyveryverylongkind:x"),
            "sha256:c5813b52ccba…"
        );
        assert_eq!(digest_key(":lead"), "sha256:3950e7496fa1…");
        assert_eq!(digest_key("é:x"), "é:sha256:be0e16f0bc7f…");
        assert_eq!(
            clip_key(&"x".repeat(170), 0),
            format!("{}… (170 characters)", "x".repeat(160))
        );
        assert_eq!(clip_key("abc", 2), "ab… (3 characters)");
    }
}
