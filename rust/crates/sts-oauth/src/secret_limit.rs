// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE SHARED RATE WINDOWS A TOKEN-ENDPOINT DOOR COUNTS IN (#444, phase 5,
//! the `oauth6` slice): `common/websecurity.ts`'s `blockedShared()`,
//! `failedShared()` (through `attemptShared()`) and `succeededShared()`,
//! over `cluster/cluster_counters.js`' windows (`sts_cluster_windows`), for
//! the two doors here that count in them:
//!
//! * the failed-client-secret limit (`secretLimitKey()`,
//!   `countSecretFailure()`, `settleSecretSuccess()`, `secretLockout()`):
//!   a client and address past the limit answered 429 before the secret is
//!   looked at, a failure whose increment took the bucket PAST the limit
//!   answered with the lockout rather than "wrong secret", and a verified
//!   secret answered only while the bucket is under it;
//! * the password grant's budget, the sign-in screen's own bucket
//!   (`attemptShared('sign-in', …)`, `succeededShared('sign-in', …)`).
//!
//! **ONE COUNT FOR EVERY PROCESS ON THE STORE**, Node's and Rust's alike:
//! the scope is Node's (`security.rate-limit`), the realm `''` (a bucket is
//! not per realm — the realm is in `what`), the keys `<what>|id|<identity>`
//! and `<what>|ip|<address>`. Where the store shares no windows (memory,
//! ldif) the counts are this process's own, in the same fixed windows —
//! Node's `attempt()` — and where it cannot be asked they are too, logged
//! `STS-CLUSTER-0023`, as Node falls back.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::{json, Value as Json};
use sts_core::errors::{codes, ErrorCode};
use sts_core::log::tag;
use sts_core::settings::Settings;

/// `SHARED_SCOPE`: the windows' scope.
pub const SHARED_SCOPE: &str = "security.rate-limit";

/// A window's count: `{ count, remainingMs }`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Window {
    pub count: i64,
    pub remaining_ms: i64,
}

/// A future of the windows' store.
pub type WindowFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// `clusterCounters`' three window operations (realm `''`), or `None`
/// where nothing is shared: the store's `countWindow()`, `peekWindow()`
/// and `clearWindow()`.
pub trait SharedWindows: Send + Sync {
    /// `sharesWindows()`.
    fn shares(&self) -> bool;
    fn count<'a>(
        &'a self,
        key: &'a str,
        window_ms: i64,
    ) -> WindowFuture<'a, Result<Window, String>>;
    fn peek<'a>(&'a self, key: &'a str)
        -> WindowFuture<'a, Result<Window, String>>;
    fn clear<'a>(&'a self, key: &'a str) -> WindowFuture<'a, Result<bool, String>>;
}

/// No shared store.
pub struct Unshared;

impl SharedWindows for Unshared {
    fn shares(&self) -> bool {
        false
    }
    fn count<'a>(
        &'a self,
        _key: &'a str,
        _window_ms: i64,
    ) -> WindowFuture<'a, Result<Window, String>> {
        Box::pin(async { Err("unshared".to_string()) })
    }
    fn peek<'a>(
        &'a self,
        _key: &'a str,
    ) -> WindowFuture<'a, Result<Window, String>> {
        Box::pin(async { Err("unshared".to_string()) })
    }
    fn clear<'a>(
        &'a self,
        _key: &'a str,
    ) -> WindowFuture<'a, Result<bool, String>> {
        Box::pin(async { Ok(false) })
    }
}

/// A refusal: `{ ok: false, kind, limit, retryAfterS, detail }`, marked
/// `STS-HTTP-0017` (identity) or `STS-HTTP-0018` (address).
#[derive(Clone, Debug, PartialEq)]
pub struct LimitRefusal {
    pub kind: &'static str,
    pub limit: i64,
    pub retry_after_s: i64,
    pub detail: String,
    pub code: ErrorCode,
}

struct Check {
    kind: &'static str,
    key: String,
    limit: i64,
}

/// The limiter's shared half, with this process's own fixed windows for
/// a store that shares none (`attempt()`, `blocked()`, `succeeded()`).
pub struct SharedLimits {
    pub settings: Arc<Settings>,
    pub windows: Arc<dyn SharedWindows>,
    pub now_ms: Arc<dyn Fn() -> i64 + Send + Sync>,
    local: Mutex<HashMap<String, (i64, i64)>>,
}

impl SharedLimits {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(
        settings: Arc<Settings>,
        windows: Arc<dyn SharedWindows>,
        now_ms: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> SharedLimits {
        SharedLimits {
            settings,
            windows,
            now_ms,
            local: Mutex::new(HashMap::new()),
        }
    }

    fn number(&self, key: &str, fallback: i64) -> i64 {
        // `Number(config.value(key) || n)`: 0 is the fallback, as Node's
        // `||` makes it.
        match self.settings.value_of(key).as_int() {
            0 => fallback,
            n => n,
        }
    }

    /// `windowMs()`.
    fn window_ms(&self) -> i64 {
        self.number("security.rateLimitWindowS", 60).max(1) * 1000
    }

    /// `bucketChecks(what, req, identity)`: the identity's bucket where
    /// there is one, then the address's.
    fn checks(&self, what: &str, address: &str, identity: &str) -> Vec<Check> {
        let mut out = Vec::new();
        if !identity.is_empty() {
            out.push(Check {
                kind: "identity",
                key: format!("{}|id|{}", what, identity.to_lowercase()),
                limit: self.number("security.rateLimitPerIdentity", 5).max(1),
            });
        }
        out.push(Check {
            kind: "address",
            key: format!("{}|ip|{}", what, address),
            limit: self.number("security.rateLimitPerAddress", 5).max(1),
        });
        out
    }

    /// `secondsLeft(remainingMs)`.
    fn seconds_left(remaining_ms: i64) -> i64 {
        ((remaining_ms.max(0) as f64) / 1000.0).ceil().max(1.0) as i64
    }

    /// `sharedRefusal(refusal, detailLead)`.
    fn refusal(
        kind: &'static str,
        limit: i64,
        retry: i64,
        lead: &str,
    ) -> LimitRefusal {
        LimitRefusal {
            kind,
            limit,
            retry_after_s: retry,
            detail: format!("{} Wait {} seconds and try again.", lead, retry),
            code: if kind == "address" {
                codes::STS_HTTP_0018
            } else {
                codes::STS_HTTP_0017
            },
        }
    }

    // This process's fixed windows: the same arithmetic as the store's.
    fn local_count(&self, key: &str, span: i64) -> Window {
        let now = (self.now_ms)();
        let mut held = self.local.lock().unwrap_or_else(PoisonError::into_inner);
        let row = held.entry(key.to_string()).or_insert((0, now));
        if row.1 <= now {
            *row = (1, now + span);
        } else {
            row.0 += 1;
        }
        Window {
            count: row.0,
            remaining_ms: (row.1 - now).max(0),
        }
    }

    fn local_peek(&self, key: &str) -> Window {
        let now = (self.now_ms)();
        let held = self.local.lock().unwrap_or_else(PoisonError::into_inner);
        match held.get(key) {
            Some((count, ends)) if *ends > now => Window {
                count: *count,
                remaining_ms: ends - now,
            },
            _ => Window::default(),
        }
    }

    fn local_clear(&self, key: &str) {
        self.local
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(key);
    }

    async fn counts(&self, what: &str, checks: &[Check]) -> Vec<Window> {
        let span = self.window_ms();
        if self.windows.shares() {
            let mut out = Vec::new();
            let mut failed = false;
            for check in checks {
                match self.windows.count(&check.key, span).await {
                    Ok(w) => out.push(w),
                    Err(e) => {
                        tracing::debug!("limits: the store said {}", e);
                        failed = true;
                        break;
                    }
                }
            }
            if !failed {
                return out;
            }
            tracing::warn!(
                "{}websecurity: the \"{}\" attempt could not be counted in \
                 the shared store; it is counted in this process's buckets, \
                 so for now the budget is per node.",
                tag(codes::STS_CLUSTER_0023),
                what
            );
        }
        checks.iter().map(|c| self.local_count(&c.key, span)).collect()
    }

    /// `attemptShared(what, req, identity)`: one attempt counted in both
    /// buckets; refused once either is past its limit.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn attempt(
        &self,
        what: &str,
        address: &str,
        identity: &str,
    ) -> Option<LimitRefusal> {
        let checks = self.checks(what, address, identity);
        let answers = self.counts(what, &checks).await;
        let (check, window) = checks
            .iter()
            .zip(answers.iter())
            .find(|(c, w)| w.count > c.limit)?;
        let retry = Self::seconds_left(window.remaining_ms);
        tracing::warn!(
            "{}websecurity: too many \"{}\" attempts across the cluster ({} \
             bucket, limit {} per {}s). Refusing for another {}s.",
            tag(if check.kind == "address" {
                codes::STS_HTTP_0018
            } else {
                codes::STS_HTTP_0017
            }),
            what,
            check.kind,
            check.limit,
            self.window_ms() / 1000,
            retry
        );
        Some(Self::refusal(check.kind, check.limit, retry, "Too many attempts."))
    }

    /// `peekShared()`: the refusal where a bucket is AT its limit, and the
    /// counts read (`None` where the shared store was not read).
    async fn peek(
        &self,
        what: &str,
        address: &str,
        identity: &str,
    ) -> (Option<LimitRefusal>, Option<HashMap<String, i64>>) {
        let checks = self.checks(what, address, identity);
        let mut read: Option<Vec<Window>> = None;
        if self.windows.shares() {
            let mut out = Vec::new();
            for check in &checks {
                match self.windows.peek(&check.key).await {
                    Ok(w) => out.push(w),
                    Err(_) => {
                        out.clear();
                        break;
                    }
                }
            }
            if out.len() == checks.len() {
                read = Some(out);
            } else {
                tracing::warn!(
                    "{}websecurity: the \"{}\" buckets could not be read from \
                     the shared store; this process's own buckets decide, so \
                     for now the budget is per node.",
                    tag(codes::STS_CLUSTER_0023),
                    what
                );
            }
        }
        let shared = read.is_some();
        let windows = read.unwrap_or_else(|| {
            checks.iter().map(|c| self.local_peek(&c.key)).collect()
        });
        let refusal = checks
            .iter()
            .zip(windows.iter())
            .find(|(c, w)| w.count >= c.limit)
            .map(|(c, w)| {
                Self::refusal(
                    c.kind,
                    c.limit,
                    Self::seconds_left(w.remaining_ms),
                    "Too many failed attempts.",
                )
            });
        let counts = shared.then(|| {
            checks
                .iter()
                .zip(windows.iter())
                .map(|(c, w)| (c.key.clone(), w.count))
                .collect()
        });
        (refusal, counts)
    }

    /// `blockedShared(what, req, identity)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn blocked(
        &self,
        what: &str,
        address: &str,
        identity: &str,
    ) -> Option<LimitRefusal> {
        self.peek(what, address, identity).await.0
    }

    /// `failedShared(what, req, identity)`: a failure counted; the lockout
    /// once the count is past the limit.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn failed(
        &self,
        what: &str,
        address: &str,
        identity: &str,
    ) -> Option<LimitRefusal> {
        self.attempt(what, address, identity).await
    }

    /// `succeededShared(what, req, identity, { keepAddress, unlessBlocked })`:
    /// the buckets forgotten — with `unless_blocked`, only while under the
    /// limit, the lockout answered otherwise and nothing cleared. A bucket
    /// just read empty is not cleared (#820).
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn succeeded(
        &self,
        what: &str,
        address: &str,
        identity: &str,
        keep_address: bool,
        unless_blocked: bool,
    ) -> Option<LimitRefusal> {
        let mut counted = None;
        if unless_blocked {
            let (refusal, counts) = self.peek(what, address, identity).await;
            if refusal.is_some() {
                return refusal;
            }
            counted = counts;
        }
        let mut keys = Vec::new();
        if !identity.is_empty() {
            keys.push(format!("{}|id|{}", what, identity.to_lowercase()));
        }
        if !keep_address {
            keys.push(format!("{}|ip|{}", what, address));
        }
        for key in &keys {
            self.local_clear(key);
        }
        if !self.windows.shares() {
            return None;
        }
        for key in keys {
            let read_empty = counted
                .as_ref()
                .and_then(|c: &HashMap<String, i64>| c.get(&key))
                .is_some_and(|n| *n <= 0);
            if read_empty {
                continue;
            }
            if let Err(e) = self.windows.clear(&key).await {
                tracing::warn!(
                    "{}websecurity: a window could not be cleared in the \
                     shared store: {}",
                    tag(codes::STS_CLUSTER_0023),
                    e
                );
            }
        }
        None
    }

    /// `secretLimitKey(req, clientId)`: `{ what, identity }`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn secret_key(
        &self,
        realm: &str,
        client_id: &str,
        address: &str,
    ) -> (String, String) {
        (
            format!(
                "token-client-secret:{}",
                if realm.is_empty() { "default" } else { realm }
            ),
            format!("{}|{}", client_id, address),
        )
    }
}

/// `secretPresented(presented, registered)`: Basic, a body secret, or an
/// assertion from a client that may use `client_secret_jwt`.
#[tracing::instrument(level = "debug", skip(registered))]
pub fn secret_presented(
    basic: bool,
    body_secret: bool,
    assertion: bool,
    registered: &Json,
) -> bool {
    let methods: Vec<String> = match registered
        .get("token_endpoint_auth_methods")
        .filter(|v| !v.is_null())
        .or_else(|| registered.get("token_endpoint_auth_method"))
    {
        Some(Json::Array(list)) => {
            list.iter().map(|m| crate::js::string_of(Some(m))).collect()
        }
        Some(Json::Null) | None => Vec::new(),
        Some(one) => vec![crate::js::string_of(Some(one))],
    };
    basic
        || body_secret
        || (assertion && methods.iter().any(|m| m == "client_secret_jwt"))
}

/// `secretLockout(res, clientId, lockedOut)`'s description.
#[tracing::instrument(level = "debug")]
pub fn lockout_description(client_id: &str, detail: &str) -> String {
    format!(
        "Too many failed client authentications for client \"{}\" from this \
         address. {}",
        client_id, detail
    )
}

/// The refusal as Node's object, for a test.
#[tracing::instrument(level = "debug")]
pub fn refusal_json(r: &LimitRefusal) -> Json {
    json!({ "ok": false, "kind": r.kind, "limit": r.limit,
            "retryAfterS": r.retry_after_s, "shared": true,
            "detail": r.detail })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> SharedLimits {
        let settings = Arc::new(Settings::new(
            Json::Null,
            std::collections::HashMap::new(),
        ));
        SharedLimits::new(settings, Arc::new(Unshared), Arc::new(|| 1_000))
    }

    #[tokio::test]
    async fn the_fourth_failure_is_the_lockout_and_a_success_then_too() {
        let l = limits();
        let (what, id) = l.secret_key("acme", "c", "1.2.3.4");
        for _ in 0..3 {
            assert!(l.blocked(&what, "1.2.3.4", &id).await.is_none());
            assert!(l.failed(&what, "1.2.3.4", &id).await.is_none());
        }
        assert!(l.blocked(&what, "1.2.3.4", &id).await.is_none());
        assert!(l.failed(&what, "1.2.3.4", &id).await.is_none());
        assert!(l.failed(&what, "1.2.3.4", &id).await.is_none());
        let past = l.failed(&what, "1.2.3.4", &id).await.unwrap();
        assert_eq!(past.code, codes::STS_HTTP_0017);
        assert!(l.blocked(&what, "1.2.3.4", &id).await.is_some());
        assert!(l
            .succeeded(&what, "1.2.3.4", &id, true, true)
            .await
            .is_some());
    }
}
