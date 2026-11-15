// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE RATE LIMIT AND THE LOCKOUT a credential door sits behind: the
//! process-local half of `common/websecurity.ts` — `attempt()`,
//! `blocked()`, `succeeded()` (fixed windows per door, one bucket by
//! identity and one by client address, STS-HTTP-0017 and 0018), and the
//! sign-in's failure delay (`noteFailure()`, `failureDelayMs()`,
//! `forgetFailures()`: 250 ms doubling to 4 s for fifteen minutes after
//! the last wrong password), which is how this service locks out
//! guessing without locking out the person — there is no account lockout,
//! by design (`authn/CLAUDE.md`).
//!
//! NOT HERE: the CSRF token (the HTTP layer's), resolving a request to its
//! client address (`client_address.js`, the HTTP layer's — the caller
//! passes the address), and the CLUSTER-shared windows
//! (`attemptShared()` and friends, which count through the cluster store's
//! counters); a caller with several nodes asks those first and these as
//! well, as Node does.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::{json, Value as Json};
use sts_core::errors::codes;
use sts_core::log::tag;

use crate::js;
use crate::ports::Environment;
use crate::Verdict;

/// The first delay after a wrong password.
pub const FAILURE_DELAY_BASE_MS: f64 = 250.0;
/// The longest.
pub const FAILURE_DELAY_CAP_MS: f64 = 4000.0;
/// How long a run of failures is remembered after the last.
pub const FAILURE_QUIET_MS: f64 = 900_000.0;
/// The most buckets held before the oldest quarter is dropped.
pub const MAX_BUCKETS: usize = 20_000;

/// One bucket: how many attempts, and when its window ends.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bucket {
    pub count: f64,
    pub until: f64,
}

/// Where the buckets live (`security.rateLimitBuckets`, one map shared by
/// every realm, so a caller cannot get a fresh allowance per realm).
/// Insertion-ordered: the oldest go first when the table is full.
pub trait BucketStore: Send + Sync {
    fn get(&self, key: &str) -> Option<Bucket>;
    fn set(&self, key: &str, bucket: Bucket);
    fn delete(&self, key: &str);
    fn len(&self) -> usize;
    /// The keys, oldest first.
    fn keys(&self) -> Vec<String>;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// An in-process store, for one process or a test.
#[derive(Default)]
pub struct MemoryBuckets {
    rows: Mutex<(HashMap<String, Bucket>, Vec<String>)>,
}

impl BucketStore for MemoryBuckets {
    fn get(&self, key: &str) -> Option<Bucket> {
        let held = self.rows.lock().unwrap_or_else(PoisonError::into_inner);
        held.0.get(key).copied()
    }
    fn set(&self, key: &str, bucket: Bucket) {
        let mut held = self.rows.lock().unwrap_or_else(PoisonError::into_inner);
        if held.0.insert(key.to_string(), bucket).is_none() {
            held.1.push(key.to_string());
        }
    }
    fn delete(&self, key: &str) {
        let mut held = self.rows.lock().unwrap_or_else(PoisonError::into_inner);
        if held.0.remove(key).is_some() {
            held.1.retain(|k| k != key);
        }
    }
    fn len(&self) -> usize {
        self.rows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .0
            .len()
    }
    fn keys(&self) -> Vec<String> {
        self.rows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .1
            .clone()
    }
}

/// A caller's ceiling: one number for both buckets, or each named
/// (`{ identity, address }`), else the settings'.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Limit {
    pub identity: Option<f64>,
    pub address: Option<f64>,
}

impl Limit {
    /// `IDENTITY_ONLY`: a door with no request behind it (a Kerberos
    /// datagram's address can be forged) counts by identity alone.
    pub const IDENTITY_ONLY: Limit = Limit {
        identity: None,
        address: Some(9_007_199_254_740_991.0),
    };

    /// From Node's `NamedLimit` (a number, or `{ identity, address }`).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn from_json(v: &Json) -> Limit {
        match v {
            Json::Object(o) => Limit {
                identity: o.get("identity").map(js::number),
                address: o.get("address").map(js::number),
            },
            Json::Null => Limit::default(),
            other => {
                let n = js::number(other);
                Limit {
                    identity: Some(n),
                    address: Some(n),
                }
            }
        }
    }
}

/// The limiter.
pub struct RateLimiter {
    env: Arc<dyn Environment>,
    buckets: Arc<dyn BucketStore>,
}

struct Check {
    kind: &'static str,
    key: String,
    limit: f64,
    on: bool,
}

impl RateLimiter {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(
        env: Arc<dyn Environment>,
        buckets: Arc<dyn BucketStore>,
    ) -> RateLimiter {
        RateLimiter { env, buckets }
    }

    fn window_ms(&self) -> f64 {
        let s = js::number_or_fallback(
            Some(&self.env.setting("security.rateLimitWindowS")),
            60.0,
        );
        s.max(1.0) * 1000.0
    }

    fn limit_for(&self, kind: &str) -> f64 {
        let key = if kind == "address" {
            "security.rateLimitPerAddress"
        } else {
            "security.rateLimitPerIdentity"
        };
        js::number_or_fallback(Some(&self.env.setting(key)), 5.0).max(1.0)
    }

    fn named(limit: Option<f64>) -> f64 {
        match limit {
            Some(n) if n > 0.0 => n.floor(),
            _ => 0.0,
        }
    }

    fn checks(
        &self,
        what: &str,
        address: &str,
        identity: &str,
        limit: &Limit,
    ) -> Vec<Check> {
        let or = |n: f64, kind: &str| {
            if n != 0.0 {
                n
            } else {
                self.limit_for(kind)
            }
        };
        vec![
            Check {
                kind: "identity",
                key: format!("{what}|id|{}", identity.to_lowercase()),
                limit: or(RateLimiter::named(limit.identity), "identity"),
                on: !identity.is_empty(),
            },
            Check {
                kind: "address",
                key: format!("{what}|ip|{address}"),
                limit: or(RateLimiter::named(limit.address), "address"),
                on: true,
            },
        ]
    }

    fn prune(&self) {
        if self.buckets.len() < MAX_BUCKETS {
            return;
        }
        let cutoff = MAX_BUCKETS / 4;
        let keys = self.buckets.keys();
        for key in keys.iter().take(cutoff) {
            self.buckets.delete(key);
        }
        tracing::warn!(
            "websecurity: the rate-limit table reached {} entries and the \
             oldest {} were dropped. That is a cap on memory rather than a \
             decision about any one caller.",
            MAX_BUCKETS,
            cutoff.min(keys.len())
        );
    }

    fn refusal(
        kind: &str,
        limit: f64,
        retry: f64,
        detail_lead: &str,
    ) -> Verdict {
        let code = if kind == "address" {
            codes::STS_HTTP_0018
        } else {
            codes::STS_HTTP_0017
        };
        Verdict::coded(
            code,
            json!({ "ok": false, "kind": kind, "limit": js::num(limit),
                "retryAfterS": js::num(retry),
                "detail": format!("{detail_lead} Wait {} seconds and try \
                                   again.", js::number_text(retry)) }),
        )
    }

    /// `attempt(what, req, identity, limit)`: count one attempt in both
    /// buckets, and refuse once either is over its limit for the window.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn attempt(
        &self,
        what: &str,
        address: &str,
        identity: &str,
        limit: &Limit,
    ) -> Verdict {
        let now = self.env.now_ms();
        let span = self.window_ms();
        let checks = self.checks(what, address, identity, limit);
        self.prune();
        let mut refusal: Option<(&'static str, f64, f64)> = None;
        for check in checks.iter().filter(|c| c.on) {
            match self.buckets.get(&check.key) {
                Some(row) if row.until > now => {
                    let row = Bucket {
                        count: row.count + 1.0,
                        until: row.until,
                    };
                    self.buckets.set(&check.key, row);
                    if row.count > check.limit && refusal.is_none() {
                        refusal = Some((
                            check.kind,
                            check.limit,
                            ((row.until - now) / 1000.0).ceil(),
                        ));
                    }
                }
                _ => self.buckets.set(
                    &check.key,
                    Bucket {
                        count: 1.0,
                        until: now + span,
                    },
                ),
            }
        }
        let Some((kind, limit, retry)) = refusal else {
            return Verdict::of(json!({ "ok": true }));
        };
        tracing::warn!(
            "{}websecurity: too many \"{}\" attempts ({} bucket, limit {} per \
             {}s). Refusing for another {}s.",
            tag(if kind == "address" {
                codes::STS_HTTP_0018
            } else {
                codes::STS_HTTP_0017
            }),
            what,
            kind,
            js::number_text(limit),
            js::number_text((span / 1000.0).round()),
            js::number_text(retry)
        );
        RateLimiter::refusal(kind, limit, retry, "Too many attempts.")
    }

    /// `blocked(what, req, identity, limit)`: whether either bucket is
    /// already at its limit — asked before a door does any work, counting
    /// nothing.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn blocked(
        &self,
        what: &str,
        address: &str,
        identity: &str,
        limit: &Limit,
    ) -> Option<Verdict> {
        let now = self.env.now_ms();
        for check in self.checks(what, address, identity, limit) {
            if !check.on {
                continue;
            }
            if let Some(row) = self.buckets.get(&check.key) {
                if row.until > now && row.count >= check.limit {
                    return Some(RateLimiter::refusal(
                        check.kind,
                        check.limit,
                        ((row.until - now) / 1000.0).ceil(),
                        "Too many failed attempts.",
                    ));
                }
            }
        }
        None
    }

    /// `succeeded(what, req, identity, { keepAddress })`: a success clears
    /// the identity's bucket, and the address's unless kept.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn succeeded(
        &self,
        what: &str,
        address: &str,
        identity: &str,
        keep_address: bool,
    ) {
        if !identity.is_empty() {
            self.buckets
                .delete(&format!("{what}|id|{}", identity.to_lowercase()));
        }
        if !keep_address {
            self.buckets.delete(&format!("{what}|ip|{address}"));
        }
    }

    fn failure_key(identity: &str) -> String {
        format!("sign-in|failures|{}", identity.to_lowercase())
    }

    /// `failureDelayMs(identity)`: how long the next answer to this
    /// identity waits — 250 ms after one failure, doubling, at most 4 s.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn failure_delay_ms(&self, identity: &str) -> f64 {
        match self.buckets.get(&RateLimiter::failure_key(identity)) {
            Some(row) if row.until > self.env.now_ms() && row.count >= 1.0 => {
                (FAILURE_DELAY_BASE_MS * 2f64.powf(row.count - 1.0))
                    .min(FAILURE_DELAY_CAP_MS)
            }
            _ => 0.0,
        }
    }

    /// `waitAfterFailures()`'s question: the delay, where the mode checks
    /// credentials at all.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn wait_after_failures_ms(&self, identity: &str) -> f64 {
        if self.env.predicate("verifiesCredentials") {
            self.failure_delay_ms(identity)
        } else {
            0.0
        }
    }

    /// `noteFailure(identity)`: one more wrong password in the run.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn note_failure(&self, identity: &str) {
        let key = RateLimiter::failure_key(identity);
        let now = self.env.now_ms();
        let count = match self.buckets.get(&key) {
            Some(row) if row.until > now => row.count + 1.0,
            _ => 1.0,
        };
        self.buckets.set(
            &key,
            Bucket {
                count,
                until: now + FAILURE_QUIET_MS,
            },
        );
    }

    /// `forgetFailures(identity)`: a success ends the run.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn forget_failures(&self, identity: &str) {
        self.buckets.delete(&RateLimiter::failure_key(identity));
    }
}
