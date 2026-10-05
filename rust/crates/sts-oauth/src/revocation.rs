// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE REVOKED-TOKEN REGISTER (`admin_stats.js`'s `revokedJtis`): the one
//! set every door that revokes an OAuth token writes, and every resource
//! server asks.
//!
//! * **Per realm, and persisted as `admin_stats.revokedJtis`** — Node's
//!   handle and Node's value, `{ exp }`, so a row either runtime writes is
//!   the other's. A value from before #345 (`true`) is a revocation with no
//!   stated expiry.
//! * **A revocation carries its token's `exp`** (#345), the latest any door
//!   stated: once that has passed (plus `oauth2.clockSkewS`) no verifier
//!   accepts the token, and the purge drops it. An undated one is kept.
//! * **The size cap, `oauth2.maxRevokedJtis`, is asked AT INSERT**, because
//!   a bound cannot wait for a timer. At the cap it first drops every
//!   revocation whose token has expired, which costs nothing; only if that
//!   leaves no room does it FORGET ONE THAT STILL MATTERS — the one whose
//!   token expires SOONEST, the smallest window in which a revoked token is
//!   accepted again. An undated one sorts last (forgetting it re-opens a
//!   token for good), the oldest first among equals. A cap lowered below the
//!   register's size is met at the next revocation. Logged under
//!   STS-OAUTH-0787 at most once a minute, with the count.
//!
//! The token REGISTER (what `/admin/tokens` draws, and the `exp` a door
//! that knows only the jti is dated from) is a separate store and comes with
//! the token endpoint; a door here states the `exp` itself.

use std::sync::{Arc, Mutex, PoisonError};

use serde_json::{json, Value as Json};
use sts_core::log::tag;
use sts_core::realm;
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{RealmMap, StoreHandles, StoreSpec};
use sts_core::settings::{keys, Settings};

/// The store's name, Node's.
pub const HANDLE: &str = "admin_stats.revokedJtis";

/// Told of every NEWLY revoked jti, with the door that revoked it. It is
/// called for its side effect and cannot fail a revocation.
pub type Observer = Arc<dyn Fn(&str, &str) + Send + Sync>;

/// `revokedExpOf()`: the expiry a revocation carries, in epoch seconds, or 0
/// when none was stated.
pub fn revoked_exp_of(value: &Json) -> i64 {
    let exp = value.get("exp").and_then(Json::as_f64).unwrap_or(0.0);
    if exp.is_finite() && exp > 0.0 {
        exp as i64
    } else {
        0
    }
}

pub struct RevokedTokens {
    lifecycle: Arc<RealmLifecycle>,
    settings: Arc<Settings>,
    set: RealmMap<Json>,
    /// Forgotten since the last line, and when that line was written.
    forgotten: Mutex<(u64, i64)>,
    observer: Mutex<Option<Observer>>,
}

impl RevokedTokens {
    pub fn new(
        lifecycle: &Arc<RealmLifecycle>,
        handles: &Arc<StoreHandles>,
        settings: Arc<Settings>,
    ) -> Arc<RevokedTokens> {
        Arc::new(RevokedTokens {
            lifecycle: lifecycle.clone(),
            settings,
            set: RealmMap::new(
                lifecycle,
                handles,
                StoreSpec::persisted(HANDLE),
            ),
            forgotten: Mutex::new((0, 0)),
            observer: Mutex::new(None),
        })
    }

    /// `setRevocationObserver()`.
    pub fn set_observer(&self, observer: Option<Observer>) {
        *self.observer.lock().unwrap_or_else(PoisonError::into_inner) =
            observer;
    }

    fn skew_ms(&self) -> i64 {
        self.settings.value(keys::OAUTH2_CLOCK_SKEW_S).as_int() * 1000
    }

    /// Whether the jti is revoked in the ambient realm.
    pub fn is_revoked(&self, jti: &str) -> bool {
        !jti.is_empty() && self.set.has(jti)
    }

    /// How many the ambient realm holds.
    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// The expiry the ambient realm's revocation of `jti` carries.
    pub fn exp_of(&self, jti: &str) -> Option<i64> {
        self.set.get(jti).map(|v| revoked_exp_of(&v))
    }

    /// `revoke()`: in the ambient realm, dated with the latest `exp` anybody
    /// stated. True when newly revoked.
    pub fn revoke(&self, jti: &str, via: &str, exp: i64, now_ms: i64) -> bool {
        if jti.is_empty() {
            return false;
        }
        let first = !self.set.has(jti);
        if first {
            self.make_room(now_ms);
        }
        let exp = exp
            .max(0)
            .max(self.set.get(jti).map(|v| revoked_exp_of(&v)).unwrap_or(0));
        self.set.set(jti, json!({ "exp": exp }));
        tracing::info!(
            "admin: the token with jti {} is revoked ({}). {} revoked in total.",
            jti,
            if via.is_empty() { "unstated" } else { via },
            self.set.len()
        );
        if first {
            let observer = self
                .observer
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            if let Some(tell) = observer {
                tell(jti, if via.is_empty() { "unstated" } else { via });
            }
        }
        first
    }

    /// `restore()`: the non-standard un-revoke, offered for experimenting.
    pub fn restore(&self, jti: &str) -> bool {
        self.set.delete(jti)
    }

    /// `makeRoomForRevocation()`: room for one more under the cap.
    /// Answers how many LIVE revocations were forgotten.
    fn make_room(&self, now_ms: i64) -> usize {
        let cap = self.settings.value(keys::OAUTH2_MAX_REVOKED_JTIS).as_int();
        if cap <= 0 || (self.set.len() as i64) < cap {
            return 0;
        }
        let skew = self.skew_ms();
        let mut live: Vec<(String, i64)> = Vec::new();
        for (jti, value) in self.set.entries() {
            let exp = revoked_exp_of(&value);
            if exp > 0 && exp * 1000 + skew <= now_ms {
                self.set.delete(&jti);
            } else {
                live.push((jti, if exp > 0 { exp } else { i64::MAX }));
            }
        }
        let over = self.set.len() as i64 - cap + 1;
        if over <= 0 {
            return 0;
        }
        // Stable, so a tie keeps the order the map holds them in.
        live.sort_by_key(|(_, exp)| *exp);
        let forgotten: Vec<String> = live
            .into_iter()
            .take(over as usize)
            .map(|(j, _)| j)
            .collect();
        for jti in &forgotten {
            self.set.delete(jti);
        }
        let mut count = self
            .forgotten
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        count.0 += forgotten.len() as u64;
        if now_ms - count.1 >= 60_000 {
            tracing::warn!(
                "{}admin: the revoked-token register reached oauth2.maxRevokedJtis ({}) with nothing expired \
                 in it, so {} revocation(s) of unexpired tokens were forgotten, the soonest to expire first \
                 (the latest was {}). Raise the setting.",
                tag("STS-OAUTH-0787"),
                cap,
                count.0,
                forgotten.last().map(String::as_str).unwrap_or("")
            );
            *count = (0, now_ms);
        }
        forgotten.len()
    }

    /// The revocation half of `purgeExpiredTokens()`: in every realm, the
    /// revocations whose tokens have expired. Answers how many went.
    pub fn purge_expired(&self, now_ms: i64) -> u64 {
        let mut gone = 0;
        for one in self.lifecycle.registry().list() {
            let id = one.id.clone();
            gone += realm::run_sync(one, || {
                let skew = self.skew_ms();
                self.set.in_realm(&id).retain(|_, value| {
                    let exp = revoked_exp_of(value);
                    exp == 0 || exp * 1000 + skew > now_ms
                })
            }) as u64;
        }
        gone
    }
}
