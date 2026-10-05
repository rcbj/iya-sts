// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A store whose bound is enforced the one way every enforced bound on the
//! page behaves (`cache_registry.js`'s `makeRoom()`): before a NEW key goes
//! in, what has expired goes; below the bound there is room; at it, either
//! the entry INSERTED first goes until there is room, or nothing goes and
//! the insert is refused. Which is the owner's call: a store that decides a
//! replay refuses, because forgetting a live entry reopens the replay; a
//! store of things this service handed out, or could rebuild, drops the
//! oldest.

use std::hash::Hash;
use std::time::{Duration, Instant};

use indexmap::IndexMap;
use sts_core::errors::codes;
use sts_core::log::tag;

use crate::registry::Counter;

/// The owner's expiry test, the same one its reader applies.
pub type Expired<'a, K, V> = &'a dyn Fn(&K, &V) -> bool;

/// What a full store does with a new key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    EvictOldest,
    Refuse,
}

/// The answer to an insert: refused, or how many went to make room.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Room {
    pub ok: bool,
    pub evicted: usize,
}

/// An insertion-ordered map with a bound.
pub struct BoundedMap<K, V> {
    held: IndexMap<K, V>,
    name: String,
    policy: Policy,
    /// The setting an operator raises when a refusing store is full.
    setting: Option<String>,
    counter: Counter,
    last_refusal_log: Option<Instant>,
}

impl<K: Hash + Eq, V> BoundedMap<K, V> {
    pub fn new(
        name: &str,
        policy: Policy,
        counter: Counter,
    ) -> BoundedMap<K, V> {
        BoundedMap {
            held: IndexMap::new(),
            name: name.to_string(),
            policy,
            setting: None,
            counter,
            last_refusal_log: None,
        }
    }

    /// Names the setting the refusal log line tells an operator to raise.
    pub fn with_setting(mut self, setting: &str) -> BoundedMap<K, V> {
        self.setting = Some(setting.to_string());
        self
    }

    pub fn len(&self) -> usize {
        self.held.len()
    }

    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// The ONE counted lookup.
    pub fn get(&self, key: &K) -> Option<&V> {
        let found = self.held.get(key);
        if found.is_some() {
            self.counter.hit();
        } else {
            self.counter.miss();
        }
        found
    }

    /// A read that is not a lookup (a page, a flush).
    pub fn peek(&self, key: &K) -> Option<&V> {
        self.held.get(key)
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.held.contains_key(key)
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.held.shift_remove(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.held.iter()
    }

    /// `makeRoom()`: drops what `expired` marks (when the store is at its
    /// bound), then makes room by the policy. Hot path: no tracing span.
    pub fn make_room(
        &mut self,
        max: usize,
        expired: Option<Expired<'_, K, V>>,
    ) -> Room {
        if let Some(expired) = expired {
            if self.held.len() >= max {
                self.held.retain(|k, v| !expired(k, v));
            }
        }
        if max == 0 || self.held.len() < max {
            return Room {
                ok: true,
                evicted: 0,
            };
        }
        if self.policy == Policy::Refuse {
            self.counter.refused();
            let due = self
                .last_refusal_log
                .is_none_or(|at| at.elapsed() >= Duration::from_secs(60));
            if due {
                self.last_refusal_log = Some(Instant::now());
                tracing::warn!(
                    "{}Cache {} is full ({} of {} live entries) and refuses new ones rather than forgetting a live one. {}Logged at most once a minute.",
                    tag(codes::STS_CORE_0097),
                    self.name,
                    self.held.len(),
                    max,
                    self.setting
                        .as_ref()
                        .map(|s| format!("Raise {} if this load is legitimate. ", s))
                        .unwrap_or_default()
                );
            }
            return Room {
                ok: false,
                evicted: 0,
            };
        }
        let mut evicted = 0;
        while self.held.len() >= max {
            if self.held.shift_remove_index(0).is_none() {
                break;
            }
            evicted += 1;
        }
        if evicted > 0 {
            self.counter.evicted(evicted);
        }
        Room { ok: true, evicted }
    }

    /// Puts a value under a key: an update of a key already held needs no
    /// room; a new key is made room for first, and is not inserted when the
    /// store refuses.
    pub fn insert(
        &mut self,
        key: K,
        value: V,
        max: usize,
        expired: Option<Expired<'_, K, V>>,
    ) -> Room {
        if let Some(slot) = self.held.get_mut(&key) {
            *slot = value;
            return Room {
                ok: true,
                evicted: 0,
            };
        }
        let room = self.make_room(max, expired);
        if room.ok {
            self.held.insert(key, value);
        }
        room
    }

    /// Deletes what `expired` marks and answers how many: a descriptor's
    /// `eject()`.
    pub fn eject(&mut self, expired: impl Fn(&K, &V) -> bool) -> usize {
        let before = self.held.len();
        self.held.retain(|k, v| !expired(k, v));
        before - self.held.len()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn evicts_the_oldest_inserted() {
        let mut m =
            BoundedMap::new("t", Policy::EvictOldest, Counter::detached());
        for i in 0..3 {
            assert!(m.insert(i, i, 3, None).ok);
        }
        let room = m.insert(3, 3, 3, None);
        assert_eq!(
            room,
            Room {
                ok: true,
                evicted: 1
            }
        );
        assert!(!m.contains_key(&0));
        // An update needs no room.
        assert_eq!(m.insert(3, 30, 3, None).evicted, 0);
        assert_eq!(m.len(), 3);
    }

    #[test]
    fn a_replay_store_refuses_rather_than_forgets() {
        let mut m = BoundedMap::new("t", Policy::Refuse, Counter::detached());
        assert!(m.insert("a", 1, 1, None).ok);
        assert!(!m.insert("b", 2, 1, None).ok);
        assert!(m.contains_key(&"a") && !m.contains_key(&"b"));
        // ...unless what is held has expired.
        let expired = |_: &&str, v: &i32| *v < 5;
        assert!(m.insert("b", 9, 1, Some(&expired)).ok);
        assert!(!m.contains_key(&"a"));
    }
}
