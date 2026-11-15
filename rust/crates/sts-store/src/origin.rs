// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! WHO THIS PROCESS IS IN THE CHANGE LOG, AND THE CLAIM THAT MAKES A
//! STABLE NAME SAFE (`persistence_postgres.js`'s `adoptOrigin()`,
//! `renewOrigin()`, `releaseOrigin()`, `checkOriginFence()`; #617, #884).
//!
//! * **The origin is `<pid>-<uuid>` until a stable name is adopted**:
//!   stamped on every `sts_changes` row, so a process skips its own writes.
//!   Two processes sharing one would each drop the other's for ever.
//! * **A process with a stable name (node and slot) takes `n:<name>`** — the
//!   origin its previous life wrote `merge: own` rows under — through a
//!   claim in `sts_cluster_claims` (scope [`ORIGIN_SCOPE`]) that lives
//!   `ttl_ms` and is renewed, and only while nobody else holds it. Its
//!   informational `origin` column says `<process>@<membership>`.
//! * **A holder whose membership has gone is taken over** (#617): its row
//!   in `sts_cluster_nodes` has left or expired. A claim naming a live
//!   membership, or none, is waited for.
//! * **Every write transaction is fenced on it**: a row of
//!   `sts_cluster_locks` named `fence:origin:<key>:<reservation>` is
//!   share-locked and the claim read; a successor that took the claim
//!   replaced the reservation and with it that row, so a process paused
//!   past its claim finds its writes refused (STS-CLUSTER-0001). A claim
//!   that LAPSED with the lock still ours is extended, not fenced.
//!
//! WHAT REPLACED NODE'S POLL. `adoptOrigin()` retries every `pollMs` until
//! `waitMs`. A repeating timer is the scheduler's (`sts-guards`' second
//! guard), and a claim that can be taken lapses at the instant its row
//! says, so this asks once, waits ONCE — until the refusing claim's own
//! expiry, or the end of the wait if that is sooner — and asks again. A
//! crashed predecessor's claim is taken the moment it lapses, as Node's
//! poll takes it within `pollMs` of then; a live holder renews and both
//! keep the random origin.

use std::sync::{Arc, Mutex, PoisonError, RwLock};

use sts_core::errors::codes;
use sts_core::log::tag;

use crate::driver::{StoreError, StoreFuture, StoreResult};

/// The claim scope of an origin (`ORIGIN_SCOPE`).
pub const ORIGIN_SCOPE: &str = "persistence.origin";

/// `fenceLockName()`.
// Hot path (every row a flush writes): no span.
pub fn fence_lock_name(kind: &str, id: &str, identity: &str) -> String {
    format!("fence:{}:{}:{}", kind, id, identity)
}

/// A claim's lifetime as Node bounds it: at least a second, 30 s unset.
#[tracing::instrument(level = "debug", skip_all)]
pub fn ttl_of(ttl_ms: i64) -> i64 {
    if ttl_ms > 0 {
        ttl_ms.max(1000)
    } else {
        30_000
    }
}

/// The claim this process holds on a stable origin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginClaim {
    pub key: String,
    pub reservation: String,
    pub ttl_ms: i64,
}

/// What `adoptOrigin()` is asked with.
#[derive(Clone, Debug, Default)]
pub struct AdoptOptions {
    /// The stable name (node name and slot); empty adopts nothing.
    pub name: String,
    pub ttl_ms: i64,
    /// How long a live claim is waited out.
    pub wait_ms: i64,
    /// This process's node membership id, or empty.
    pub node_id: String,
}

/// What `adoptOrigin()` answers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Adopted {
    pub adopted: bool,
    pub origin: String,
    pub waited_ms: i64,
    pub took_over_from: String,
    pub why: String,
}

/// A live claim of one scope (`claimsOfScope()`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeClaim {
    pub scope: String,
    pub realm: String,
    pub key: String,
    pub reservation: String,
    pub origin: String,
}

/// What a refused claim said of its holder.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Holder {
    pub origin: String,
    pub expires_at: i64,
}

/// What each engine does for the origin, in its own dialect.
pub trait OriginEngine: Send + Sync {
    /// The claim made, its fence lock installed in the same transaction;
    /// `Err(holder)` when a live claim refuses it.
    fn claim_origin<'a>(
        &'a self,
        claim: &'a OriginClaim,
        holder: &'a str,
    ) -> StoreFuture<'a, Result<(), Holder>>;
    /// `takeOverFromGone()`: true when this process now holds the claim.
    fn take_over_from_gone<'a>(
        &'a self,
        claim: &'a OriginClaim,
        holder: &'a str,
        node_id: &'a str,
    ) -> StoreFuture<'a, bool>;
    /// The claim extended while still live; false when it was not.
    fn renew_live<'a>(
        &'a self,
        claim: &'a OriginClaim,
    ) -> StoreFuture<'a, bool>;
    /// `reassertOrigin()`: extended by its reservation, lapsed or not.
    fn reassert<'a>(&'a self, claim: &'a OriginClaim) -> StoreFuture<'a, bool>;
    /// The claim and its lock deleted, in one transaction.
    fn release<'a>(&'a self, claim: &'a OriginClaim) -> StoreFuture<'a, bool>;
    /// The database's clock, in milliseconds.
    fn clock(&self) -> StoreFuture<'_, i64>;
}

/// What is told when a write was refused because this process's origin was
/// taken (`setOriginLost()`'s function), with the refusal's message.
pub type OriginLost = Arc<dyn Fn(&str) + Send + Sync>;

/// The origin a process writes under, and its claim.
pub struct Origin {
    process_id: RwLock<String>,
    claim: Mutex<Option<OriginClaim>>,
    lost: RwLock<Option<OriginLost>>,
}

/// The fence's refusal (`fenced('origin', …)`).
#[tracing::instrument(level = "debug", skip_all)]
pub fn fenced(message: &str) -> StoreError {
    StoreError::new(format!("{}{}", tag(codes::STS_CLUSTER_0001), message))
}

impl Origin {
    /// `<pid>-<uuid>`, as Node's `processId` is made.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new() -> StoreResult<Origin> {
        let id = sts_crypto::random::random_uuid()
            .map_err(|e| StoreError::new(e.to_string()))?;
        Ok(Origin {
            process_id: RwLock::new(format!("{}-{}", std::process::id(), id)),
            claim: Mutex::new(None),
            lost: RwLock::new(None),
        })
    }

    /// `setOriginLost()`: who is told when a write is refused because the
    /// origin was taken. Node's `persistence.js` hands its `originLost()`,
    /// which logs STS-STORE-0061 and exits; a clustered node's fence
    /// handler is told instead (`transactionOn()`'s two branches).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn set_lost(&self, f: Option<OriginLost>) {
        *self.lost.write().unwrap_or_else(PoisonError::into_inner) = f;
    }

    /// A write refused by the origin fence (`STS-CLUSTER-0001`), reported to
    /// [`Origin::set_lost`]'s function and handed back to be returned:
    /// a process that has lost its origin must not go on trying to write
    /// under it (`adoptOrigin()`).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn lost(&self, refusal: StoreError) -> StoreError {
        let f = self
            .lost
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(f) = f {
            f(&refusal.to_string());
        }
        refusal
    }

    /// This process's name in the change log.
    // Hot path (every row a flush writes): no span.
    pub fn id(&self) -> String {
        self.process_id
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The claim held, if any.
    // Hot path (every row a flush writes): no span.
    pub fn held(&self) -> Option<OriginClaim> {
        self.claim
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// `adoptOrigin()`. Called after `open()` and before anything reads
    /// [`Origin::id`].
    #[tracing::instrument(level = "debug", skip(self, engine))]
    pub async fn adopt(
        &self,
        engine: &dyn OriginEngine,
        opts: &AdoptOptions,
    ) -> StoreResult<Adopted> {
        let name = opts.name.trim();
        if name.is_empty() {
            return Ok(Adopted {
                origin: self.id(),
                why: "no stable name".to_string(),
                ..Adopted::default()
            });
        }
        let claim = OriginClaim {
            key: format!("n:{}", name),
            reservation: sts_crypto::random::random_uuid()
                .map_err(|e| StoreError::new(e.to_string()))?,
            ttl_ms: ttl_of(opts.ttl_ms),
        };
        let node_id = opts.node_id.trim();
        let holder = if node_id.is_empty() {
            self.id()
        } else {
            format!("{}@{}", self.id(), node_id)
        };
        let started = std::time::Instant::now();
        let mut refused =
            match self.attempt(engine, &claim, &holder, node_id).await? {
                Ok(from) => return Ok(self.adopted(claim, from, started)),
                Err(h) => h,
            };
        let wait = opts.wait_ms.max(0);
        let now = engine.clock().await?;
        // ONE wait: to the refusing claim's own expiry (and a beat after,
        // so the database's clock has passed it), never past the wait.
        let until_lapse = (refused.expires_at - now + 50).max(0);
        let pause =
            until_lapse.min(wait - started.elapsed().as_millis() as i64);
        if pause > 0 && until_lapse <= wait {
            tokio::time::sleep(std::time::Duration::from_millis(pause as u64))
                .await;
            match self.attempt(engine, &claim, &holder, node_id).await? {
                Ok(from) => return Ok(self.adopted(claim, from, started)),
                Err(h) => refused = h,
            }
        }
        Ok(Adopted {
            origin: self.id(),
            waited_ms: started.elapsed().as_millis() as i64,
            why: format!(
                "held by a live process ({})",
                if refused.origin.is_empty() {
                    "?"
                } else {
                    &refused.origin
                }
            ),
            ..Adopted::default()
        })
    }

    /// One claim, and the takeover where its holder's membership is gone:
    /// `Ok(from)` with whom it was taken over from ('' when claimed).
    async fn attempt(
        &self,
        engine: &dyn OriginEngine,
        claim: &OriginClaim,
        holder: &str,
        node_id: &str,
    ) -> StoreResult<Result<String, Holder>> {
        match engine.claim_origin(claim, holder).await? {
            Ok(()) => Ok(Ok(String::new())),
            Err(h) => {
                if !node_id.is_empty()
                    && engine
                        .take_over_from_gone(claim, holder, node_id)
                        .await?
                {
                    let from = if h.origin.is_empty() {
                        "?".to_string()
                    } else {
                        h.origin
                    };
                    return Ok(Ok(from));
                }
                Ok(Err(h))
            }
        }
    }

    fn adopted(
        &self,
        claim: OriginClaim,
        from: String,
        started: std::time::Instant,
    ) -> Adopted {
        let key = claim.key.clone();
        *self
            .process_id
            .write()
            .unwrap_or_else(PoisonError::into_inner) = key.clone();
        *self.claim.lock().unwrap_or_else(PoisonError::into_inner) =
            Some(claim);
        Adopted {
            adopted: true,
            origin: key,
            waited_ms: started.elapsed().as_millis() as i64,
            took_over_from: from,
            why: String::new(),
        }
    }

    /// `renewOrigin()`: the live claim first, quietly; only where that
    /// matches nothing is it extended by its reservation. False when it is
    /// no longer this process's.
    #[tracing::instrument(level = "debug", skip(self, engine))]
    pub async fn renew(
        &self,
        engine: &dyn OriginEngine,
        ttl_ms: i64,
    ) -> StoreResult<bool> {
        let Some(mut held) = self.held() else {
            return Ok(true);
        };
        held.ttl_ms = ttl_of(ttl_ms);
        if engine.renew_live(&held).await? {
            return Ok(true);
        }
        engine.reassert(&held).await
    }

    /// `releaseOrigin()`: given back at a clean stop.
    #[tracing::instrument(level = "debug", skip(self, engine))]
    pub async fn release(
        &self,
        engine: &dyn OriginEngine,
    ) -> StoreResult<bool> {
        let held = self
            .claim
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        match held {
            Some(claim) => engine.release(&claim).await,
            None => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)] // tests

    use super::*;

    #[test]
    fn a_refused_write_is_reported_and_handed_back() {
        let origin = Origin::new().unwrap();
        let refusal = origin.lost(fenced("no hook, no report"));
        assert!(refusal
            .to_string()
            .starts_with(&tag(codes::STS_CLUSTER_0001)));
        let told: Arc<Mutex<Vec<String>>> = Arc::default();
        let into = told.clone();
        origin.set_lost(Some(Arc::new(move |m: &str| {
            into.lock().unwrap().push(m.to_string());
        })));
        let refusal = origin.lost(fenced("the claim is gone"));
        assert_eq!(*told.lock().unwrap(), vec![refusal.to_string()]);
        assert!(refusal.to_string().contains("the claim is gone"));
    }
}
