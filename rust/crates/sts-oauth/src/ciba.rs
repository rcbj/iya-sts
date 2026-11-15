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
    /// `credentials.readCibaUserCode(username)`: the stored (hashed) user
    /// code a person set, '' for none.
    pub user_code_of: Arc<dyn Fn(&str) -> String + Send + Sync>,
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
        user_code_of: Arc<dyn Fn(&str) -> String + Send + Sync>,
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
            user_code_of,
        })
    }

    /// `enabled()`: `oauth2.ciba`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn enabled(&self) -> bool {
        self.settings.value_of("oauth2.ciba").as_bool()
    }

    fn setting(&self, key: &str) -> f64 {
        crate::grants::setting_number(&self.settings, key)
    }

    /// `expire(record)` for a request no notification is owed for; a push
    /// request's expiry notification is Node's (see the module header).
    fn expire(&self, record: &mut Json) {
        record["state"] = json!("expired");
        record["finishedAt"] = crate::js::number((self.now_ms)());
        if record["mode"] != "push" {
            if let Some(m) = record.as_object_mut() {
                m.remove("authReqId");
            }
        }
        self.save(record);
    }

    /// `pendingFor(username)`: every request still waiting for a person,
    /// oldest first; an expired one is marked so on the way past.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn pending_for(&self, username: &str) -> Vec<Json> {
        let who = username.to_lowercase();
        let now = (self.now_ms)();
        let mut out = Vec::new();
        for (_, mut record) in self.requests.entries() {
            if record["state"] == "pending"
                && num(record.get("expiresAt")) <= now
            {
                self.expire(&mut record);
                continue;
            }
            if record["state"] == "pending"
                && crate::js::string_of(record.get("username")).to_lowercase()
                    == who
            {
                out.push(record);
            }
        }
        out.sort_by(|a, b| {
            num(a.get("createdAt"))
                .partial_cmp(&num(b.get("createdAt")))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        out
    }

    /// `userCodeMatches(username, code)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn user_code_matches(&self, username: &str, code: &str) -> bool {
        let stored = (self.user_code_of)(username);
        !stored.is_empty()
            && !code.is_empty()
            && sts_crypto::secrets::verify_secret(code, &stored)
    }

    /// `create(spec)`: `(record, auth_req_id, expires_in)`, or Node's
    /// `(code, error, description)` refusal.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn create(
        &self,
        spec: &Json,
    ) -> Result<
        (Json, String, i64),
        (sts_core::errors::ErrorCode, String, String),
    > {
        let text = |k: &str| crate::js::string_of(spec.get(k));
        let waiting = self.pending_for(&text("username")).len();
        if waiting as f64 >= self.setting("oauth2.cibaMaxPendingPerPerson") {
            return Err((
                sts_core::errors::codes::STS_OAUTH_0635,
                "access_denied".into(),
                format!(
                    "this person already has {} sign-in requests waiting, \
                     the most oauth2.cibaMaxPendingPerPerson allows; ask \
                     again once they have answered or those have expired.",
                    waiting
                ),
            ));
        }
        let max_expiry = self.setting("oauth2.cibaMaxExpiryS");
        let asked = crate::js::to_number(&spec["requestedExpiry"]);
        let expires_in = if asked > 0.0 {
            asked.floor().min(max_expiry)
        } else {
            self.setting("oauth2.cibaDefaultExpiryS").min(max_expiry)
        } as i64;
        let id = sts_crypto::b64::encode(
            &sts_crypto::random::random_bytes(32).unwrap_or_default(),
        );
        let mode = text("mode");
        let now = (self.now_ms)();
        let mut record = serde_json::Map::new();
        record.insert(
            "key".into(),
            json!(
                sts_crypto::secrets::credential_digest(&id).unwrap_or_default()
            ),
        );
        if mode != "poll" {
            record.insert("authReqId".into(), json!(id));
        }
        let client_id = text("clientId");
        let client_name = text("clientName");
        let scope = text("scope");
        for (k, v) in [
            ("state", json!("pending")),
            ("clientId", json!(client_id)),
            (
                "clientName",
                json!(if client_name.is_empty() {
                    client_id.clone()
                } else {
                    client_name
                }),
            ),
            ("username", json!(text("username"))),
            (
                "scope",
                json!(if scope.is_empty() {
                    "openid".into()
                } else {
                    scope
                }),
            ),
            (
                "acrValues",
                spec.get("acrValues").cloned().unwrap_or(json!([])),
            ),
            ("bindingMessage", json!(text("bindingMessage"))),
            (
                "requestContext",
                if spec["requestContext"].is_object() {
                    spec["requestContext"].clone()
                } else {
                    Json::Null
                },
            ),
            ("grantManagement", Json::Null),
            ("mode", json!(mode)),
            ("notificationToken", json!(text("notificationToken"))),
            ("notificationEndpoint", json!(text("notificationEndpoint"))),
            ("base", json!(text("base"))),
            ("createdAt", crate::js::number(now)),
            (
                "expiresAt",
                crate::js::number(now + expires_in as f64 * 1000.0),
            ),
            (
                "interval",
                crate::js::number(self.setting("oauth2.cibaIntervalS")),
            ),
            ("lastPolledAt", json!(0)),
            ("approval", Json::Null),
        ] {
            record.insert(k.into(), v);
        }
        let record = Json::Object(record);
        self.save(&record);
        tracing::info!(
            "ciba: \"{}\" asked to authenticate {} ({}, expires in {} s).",
            client_id,
            text("username"),
            mode,
            expires_in
        );
        Ok((record, id, expires_in))
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
            self.expire(&mut record);
        }
        if record["state"] != "pending" {
            return (crate::js::string_of(record.get("state")), Some(record));
        }
        let last = num(record.get("lastPolledAt"));
        let interval = num(record.get("interval"));
        let too_soon = last != 0.0 && now - last < interval * 1000.0;
        if too_soon {
            record["interval"] = crate::js::number(interval + 5.0);
        }
        record["lastPolledAt"] = crate::js::number(now);
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
        record["redeemedAt"] = crate::js::number((self.now_ms)());
        self.save(&record);
        true
    }
}
