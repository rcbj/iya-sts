// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! DPoP's two stores (`dpop.ts`'s `issuedNonces` and `seenJtis`) and the
//! [`ProofContext`] over them.
//!
//! * **Per realm, persisted under Node's handles** (`dpop.issuedNonces`,
//!   `dpop.seenJtis`), the value the SECOND something was issued or seen,
//!   so either runtime reads the other's rows; both age out at a restart
//!   (`retain: age`), and each row's own deadline is the second plus its
//!   window, read from the settings when asked.
//! * **The nonce bound evicts the oldest** (`oauth2.dpopNonceCacheSize`): a
//!   nonce is a value this service handed out, and its holder is simply
//!   asked again (`use_dpop_nonce`). **The replay bound REFUSES**
//!   (`oauth2.dpopReplayCacheSize`): this history decides a replay, so a
//!   full one refuses rather than forget a live jti.
//! * **Not here yet**: the cross-node reservation (#46), which answers
//!   [`Seen::Elsewhere`] and [`Seen::Unknown`] through the cluster's claims,
//!   and FAPI 2.0's minute-ahead rule, which arrives with the FAPI profiles.

use std::sync::{Arc, Mutex, PoisonError};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value as Json;
use sts_core::log::tag;
use sts_core::realm;
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{RealmMap, Retain, StoreHandles, StoreSpec};
use sts_core::settings::{keys, Settings};

use crate::dpop::{ProofContext, Seen, IAT_SKEW_SECONDS};

/// The nonce window where `oauth2.dpopNonceTtlS` is unusable.
pub const NONCE_TTL_SECONDS: i64 = 300;

/// The clock, in epoch seconds.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

pub struct DpopStores {
    settings: Arc<Settings>,
    nonces: RealmMap<Json>,
    seen: RealmMap<Json>,
    clock: Clock,
    last_refusal_log: Mutex<i64>,
}

fn positive(value: i64, fallback: i64) -> i64 {
    if value > 0 {
        value
    } else {
        fallback
    }
}

fn seconds_of(value: &Json) -> i64 {
    value
        .as_f64()
        .filter(|n| n.is_finite() && *n > 0.0)
        .map(|n| n as i64)
        .unwrap_or(0)
}

impl DpopStores {
    pub fn new(
        lifecycle: &Arc<RealmLifecycle>,
        handles: &Arc<StoreHandles>,
        settings: Arc<Settings>,
        clock: Clock,
    ) -> Arc<DpopStores> {
        let for_nonces = settings.clone();
        let nonces = RealmMap::new(
            lifecycle,
            handles,
            StoreSpec {
                retain: Retain::Age,
                expires_at: Some(Arc::new(move |value: &Json, _key: &str| {
                    let at = seconds_of(value);
                    let ttl = for_nonces
                        .value(keys::OAUTH2_DPOP_NONCE_TTL_S)
                        .as_int();
                    (at > 0 && ttl > 0).then(|| ((at + ttl) * 1000) as f64)
                })),
                ..StoreSpec::persisted("dpop.issuedNonces")
            },
        );
        let for_seen = settings.clone();
        let seen = RealmMap::new(
            lifecycle,
            handles,
            StoreSpec {
                retain: Retain::Age,
                expires_at: Some(Arc::new(move |value: &Json, _key: &str| {
                    let at = seconds_of(value);
                    let skew =
                        for_seen.value(keys::OAUTH2_DPOP_IAT_SKEW_S).as_int();
                    (at > 0 && skew > 0)
                        .then(|| ((at + 2 * skew) * 1000) as f64)
                })),
                ..StoreSpec::persisted("dpop.seenJtis")
            },
        );
        Arc::new(DpopStores {
            settings,
            nonces,
            seen,
            clock,
            last_refusal_log: Mutex::new(0),
        })
    }

    fn nonce_ttl(&self) -> i64 {
        positive(
            self.settings.value(keys::OAUTH2_DPOP_NONCE_TTL_S).as_int(),
            NONCE_TTL_SECONDS,
        )
    }

    fn skew(&self) -> i64 {
        positive(
            self.settings.value(keys::OAUTH2_DPOP_IAT_SKEW_S).as_int(),
            IAT_SKEW_SECONDS,
        )
    }

    fn prune_nonces(&self) {
        let cutoff = (self.clock)() - self.nonce_ttl();
        self.nonces
            .in_realm(&realm::current_id())
            .retain(|_, issued| seconds_of(issued) >= cutoff);
    }

    fn prune_jtis(&self) {
        let cutoff = (self.clock)() - 2 * self.skew();
        self.seen
            .in_realm(&realm::current_id())
            .retain(|_, at| seconds_of(at) >= cutoff);
    }

    /// `nonceModeOn()`: `oauth2.dpopNonceRequired`, in the ambient realm.
    pub fn nonce_mode_on(&self) -> bool {
        self.settings
            .value(keys::OAUTH2_DPOP_NONCE_REQUIRED)
            .as_bool()
    }

    /// `issueNonce()`: a fresh nonce, the oldest evicted at the bound.
    pub fn issue_nonce(&self) -> Result<String, String> {
        self.prune_nonces();
        let max = self
            .settings
            .value(keys::OAUTH2_DPOP_NONCE_CACHE_SIZE)
            .as_int();
        if max > 0 {
            let mut held = self.nonces.entries();
            let over = held.len() as i64 - max + 1;
            if over > 0 {
                held.sort_by_key(|(_, at)| seconds_of(at));
                for (nonce, _) in held.into_iter().take(over as usize) {
                    self.nonces.delete(&nonce);
                }
            }
        }
        let nonce = URL_SAFE_NO_PAD.encode(
            sts_crypto::random::random_bytes(16).map_err(|e| e.to_string())?,
        );
        self.nonces.set(&nonce, Json::from((self.clock)()));
        Ok(nonce)
    }

    /// How many each store holds in the ambient realm: (nonces, proofs).
    pub fn sizes(&self) -> (usize, usize) {
        (self.nonces.len(), self.seen.len())
    }
}

impl ProofContext for DpopStores {
    fn iat_skew_seconds(&self) -> i64 {
        self.skew()
    }

    fn trust_proxy(&self) -> bool {
        self.settings.value(keys::GLOBAL_TRUST_PROXY).as_bool()
    }

    fn nonce_required(&self) -> bool {
        self.nonce_mode_on()
    }

    fn nonce_is_current(&self, nonce: &Json) -> bool {
        self.prune_nonces();
        match nonce {
            Json::String(s) if !s.is_empty() => self.nonces.has(s),
            _ => false,
        }
    }

    fn seen(&self, jti: &str) -> Seen {
        self.prune_jtis();
        if self.seen.has(jti) {
            Seen::Here
        } else {
            Seen::No
        }
    }

    fn remember(&self, jti: &str, now: i64) -> bool {
        let max = self
            .settings
            .value(keys::OAUTH2_DPOP_REPLAY_CACHE_SIZE)
            .as_int();
        if max > 0 && self.seen.len() as i64 >= max {
            let mut last = self
                .last_refusal_log
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if now - *last >= 60 {
                *last = now;
                tracing::warn!(
                    "{}Cache dpop.proof-ids is full ({} of {} live entries) and refuses new ones rather than \
                     forgetting a live one. Raise oauth2.dpopReplayCacheSize. Logged at most once a minute.",
                    tag("STS-CORE-0097"),
                    self.seen.len(),
                    max
                );
            }
            return false;
        }
        self.seen.set(jti, Json::from(now));
        true
    }
}
