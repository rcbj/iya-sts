// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! OpenID Connect CIBA Core 1.0's token half (`oauth-oidc/ciba.ts`'s
//! `poll()` and `redeem()`, #131, rule 3bc): the backchannel requests in
//! Node's store, `oauth2.cibaRequests` — keyed by `credentialDigest(
//! auth_req_id)` (#614), `{ key, authReqId, clientId, username, scope,
//! mode, state, expiresAt, interval, lastPolledAt, approval,
//! grantManagement, … }` — polled by a poll or ping client at the token
//! endpoint (section 10.1), the one token response of an approval claimed
//! across the cluster (`oauth.ciba`).
//!
//! NOT HERE, each Node's still, and what answers meanwhile:
//! `/oauth2/bc-authorize` (the request, its hints, `binding_message`,
//! `user_code`, signed requests and FAPI-CIBA), the person's approval on
//! the portal (`/account-api`), and ping and push delivery on the shared
//! outbound queue with its sweep job — a request Node created is redeemed
//! here, and its rows are Node's shape both ways. Grant Management (#142)
//! is not ported: a request carrying a grant plan is issued with the plan's
//! scope, and the plan is not checked against, nor applied to, the grant
//! register.

use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{RealmMap, Retain, StoreHandles, StoreSpec};
use sts_core::settings::Settings;

/// The CIBA grant type (section 10).
pub const GRANT_TYPE: &str = "urn:openid:params:grant-type:ciba";
const REDEEM_SCOPE: &str = "oauth.ciba";
const RETENTION_MS: f64 = 60.0 * 60.0 * 1000.0;

fn num(v: Option<&Json>) -> f64 {
    v.map_or(0.0, crate::js::to_number)
}

/// The requests, and the claims.
pub struct CibaRequests {
    pub settings: Arc<Settings>,
    pub requests: RealmMap<Json>,
    pub claims: Arc<dyn sts_cluster::scheduler::Claims>,
    pub now_ms: Arc<dyn Fn() -> f64 + Send + Sync>,
}

impl CibaRequests {
    /// Declares the store as Node declares it, before the store opens.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn declare(
        lifecycle: &Arc<RealmLifecycle>,
        handles: &Arc<StoreHandles>,
        settings: Arc<Settings>,
        claims: Arc<dyn sts_cluster::scheduler::Claims>,
        now_ms: Arc<dyn Fn() -> f64 + Send + Sync>,
    ) -> Arc<CibaRequests> {
        let spec = StoreSpec {
            retain: Retain::Age,
            expires_at: Some(Arc::new(|row: &Json, _key: &str| {
                let ended = [&row["finishedAt"], &row["redeemedAt"]]
                    .into_iter()
                    .map(crate::js::to_number)
                    .find(|n| *n != 0.0 && !n.is_nan())
                    .unwrap_or_else(|| crate::js::to_number(&row["expiresAt"]));
                (row.is_object() && row["state"] != "pending" && ended > 0.0)
                    .then_some(ended + RETENTION_MS)
            })),
            ..StoreSpec::persisted("oauth2.cibaRequests")
        };
        Arc::new(CibaRequests {
            settings,
            requests: RealmMap::new(lifecycle, handles, spec),
            claims,
            now_ms,
        })
    }

    /// `enabled()`: `oauth2.ciba`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn enabled(&self) -> bool {
        self.settings.value_of("oauth2.ciba").as_bool()
    }

    fn save(&self, record: &Json) {
        self.requests
            .set(&crate::js::string_of(record.get("key")), record.clone());
    }

    /// `poll(id, clientId)`: the state — `pending`, `slow_down`,
    /// `approved`, `denied`, `expired`, `redeemed` or `unknown` — and the
    /// request, section 11's interval enforced.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn poll(&self, id: &str, client_id: &str) -> (String, Option<Json>) {
        let key =
            sts_crypto::secrets::credential_digest(id).unwrap_or_default();
        let Some(mut record) = self.requests.get(&key) else {
            return ("unknown".into(), None);
        };
        if crate::js::string_of(record.get("clientId")) != client_id {
            return ("unknown".into(), None);
        }
        let now = (self.now_ms)();
        if record["state"] == "pending" && num(record.get("expiresAt")) <= now {
            // `expire()`, for a poll or ping request: nothing to deliver.
            record["state"] = json!("expired");
            record["finishedAt"] = json!(now);
            if let Some(m) = record.as_object_mut() {
                m.remove("authReqId");
            }
            self.save(&record);
        }
        if record["state"] != "pending" {
            return (crate::js::string_of(record.get("state")), Some(record));
        }
        let last = num(record.get("lastPolledAt"));
        let interval = num(record.get("interval"));
        let too_soon = last != 0.0 && now - last < interval * 1000.0;
        if too_soon {
            record["interval"] = json!(interval + 5.0);
        }
        record["lastPolledAt"] = json!(now);
        self.save(&record);
        (
            if too_soon { "slow_down" } else { "pending" }.into(),
            Some(record),
        )
    }

    /// `redeem(record)`: one token response per approval, cluster-wide.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn redeem(&self, record: &Json) -> bool {
        let ttl = (num(record.get("expiresAt")) - (self.now_ms)()).max(0.0)
            + RETENTION_MS;
        let claimed = self
            .claims
            .claim(
                REDEEM_SCOPE,
                &crate::js::string_of(record.get("key")),
                &sts_core::realm::current_id(),
                ttl,
            )
            .await;
        if claimed.is_err() {
            return false;
        }
        let mut record = record.clone();
        record["state"] = json!("redeemed");
        record["redeemedAt"] = json!((self.now_ms)());
        self.save(&record);
        true
    }
}
