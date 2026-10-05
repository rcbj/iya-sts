// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A DPoP proof's `jti` reserved ACROSS THE CLUSTER on arrival (#46,
//! `dpop.ts`'s `proofClaims()`), which [`verify_proof`] then consults
//! after the local history, so a replay this process can see keeps its own
//! code (STS-OAUTH-0110) and one another node took is STS-OAUTH-0519.
//!
//! * **Read from the UNVERIFIED proof**, because the reservation has to be
//!   made before anything else is decided about it; a malformed proof
//!   reserves nothing and is refused by the check that would refuse it
//!   anyway.
//! * **For twice the `iat` skew**: a proof is refused outside `iat` ± the
//!   skew, so that is every moment it could be presented.
//! * **A store that cannot be asked is a refusal** (STS-OAUTH-0520): whether
//!   the proof was used could not be recorded.
//! * **Kept only when the proof is accepted**; otherwise released when the
//!   request is done ([`Reservation::settle`]), so a proof refused for its
//!   `ath`, say, is not a replay on the next try.
//!
//! [`verify_proof`]: crate::dpop::verify_proof

use std::sync::atomic::{AtomicBool, Ordering};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value as Json;
use sts_cluster::scheduler::{ClaimRefused, Claims};
use sts_core::realm;

use crate::dpop::{ProofContext, Seen};

/// The claims' scope, Node's.
pub const SCOPE: &str = "oauth.dpop-jti";

/// `unverifiedJtiOf()`: the `jti` of a compact JWS read without verifying
/// it, or `""`.
pub fn unverified_jti_of(raw: &str) -> String {
    let raw = raw.trim();
    let parts: Vec<&str> = raw.split('.').collect();
    if parts.len() != 3 || raw.contains(',') {
        return String::new();
    }
    URL_SAFE_NO_PAD
        .decode(parts[1].trim_end_matches('='))
        .ok()
        .and_then(|b| serde_json::from_slice::<Json>(&b).ok())
        .and_then(|p| p.get("jti").and_then(Json::as_str).map(str::to_string))
        .unwrap_or_default()
}

/// What the cluster said about one proof's `jti`.
pub struct Reservation {
    pub jti: String,
    /// The claim's handle, or why there is none.
    answer: Result<Json, ClaimRefused>,
    kept: AtomicBool,
}

impl Reservation {
    /// `proofClaims()`: reserves the `jti` the `DPoP` header names, in the
    /// ambient realm. `None` when there is no proof or no `jti` to read.
    pub async fn reserve(
        claims: &dyn Claims,
        dpop_header: Option<&str>,
        skew_seconds: i64,
    ) -> Option<Reservation> {
        let jti = unverified_jti_of(dpop_header?);
        if jti.is_empty() {
            return None;
        }
        let answer = claims
            .claim(
                SCOPE,
                &jti,
                &realm::current_id(),
                (skew_seconds * 2 * 1000) as f64,
            )
            .await
            .map(|claim| claim.handle);
        Some(Reservation {
            jti,
            answer,
            kept: AtomicBool::new(false),
        })
    }

    /// What it means for a proof naming `jti`.
    fn seen(&self, jti: &str) -> Seen {
        if jti != self.jti {
            return Seen::No;
        }
        match &self.answer {
            Ok(_) => Seen::No,
            Err(ClaimRefused::Held) => Seen::Elsewhere,
            Err(ClaimRefused::Store(_)) => Seen::Unknown,
        }
    }

    /// When the request is done: released unless the proof was accepted.
    /// Answers whether it was kept.
    pub async fn settle(&self, claims: &dyn Claims) -> bool {
        let kept = self.kept.load(Ordering::SeqCst);
        if let (false, Ok(handle)) = (kept, &self.answer) {
            claims.release(handle).await;
        }
        kept
    }
}

/// The local stores, with the cluster's reservation asked after them.
pub struct Reserved<'a> {
    pub local: &'a dyn ProofContext,
    pub reservation: Option<&'a Reservation>,
}

impl ProofContext for Reserved<'_> {
    fn iat_skew_seconds(&self) -> i64 {
        self.local.iat_skew_seconds()
    }
    fn trust_proxy(&self) -> bool {
        self.local.trust_proxy()
    }
    fn future_refusal(
        &self,
        iat: &Json,
    ) -> Option<(sts_core::errors::ErrorCode, String)> {
        self.local.future_refusal(iat)
    }
    fn nonce_required(&self) -> bool {
        self.local.nonce_required()
    }
    fn nonce_is_current(&self, nonce: &Json) -> bool {
        self.local.nonce_is_current(nonce)
    }
    fn seen(&self, jti: &str) -> Seen {
        match self.local.seen(jti) {
            Seen::No => {
                self.reservation.map(|r| r.seen(jti)).unwrap_or(Seen::No)
            }
            other => other,
        }
    }
    fn remember(&self, jti: &str, now: i64) -> bool {
        let room = self.local.remember(jti, now);
        if room {
            if let Some(r) = self.reservation.filter(|r| r.jti == jti) {
                r.kept.store(true, Ordering::SeqCst);
            }
        }
        room
    }
    fn key_policy(&self) -> sts_crypto::keys::KeyPolicy {
        self.local.key_policy()
    }
}
