// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! RFC 8628, the OAuth 2.0 Device Authorization Grant
//! (`oauth-oidc/device_authorization.ts`, #150, rule 3bk): device codes,
//! user codes, the person's answer, and the polling — in Node's store and
//! Node's rows, so a code Node issued is polled here and the other way
//! round (D11).
//!
//! The store is `oauth2.deviceCodes`, per realm: `d|<digest of the device
//! code>` holds the record — `{ deviceKey, userCodeKey, clientId,
//! clientName, scope, dpopJkt, state, createdAt, expiresAt, interval,
//! lastPolledAt, username, approval }`, the codes themselves never stored
//! (#614) — and `u|<digest of the user code>` names the record a pending
//! user code belongs to. A finished record is kept an hour past its end.
//!
//! The token responses of one approval are claimed once across the
//! cluster (`oauth.device`), so two nodes polled at the same instant issue
//! one set.
//!
//! WHAT REPLACED WHAT. Node's sweep is a scheduler job
//! (`oauth2.device-code-sweep`, every five minutes): [`DeviceCodes::sweep`]
//! is its body, and a finished record also ends by its own expiry in the
//! store; a pending record is expired by the poll that finds it late.

use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{RealmMap, Retain, StoreHandles, StoreSpec};
use sts_core::settings::Settings;

/// The device code grant type the token endpoint accepts.
pub const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// The scheduler job Node expires and drops device codes with.
pub const SWEEP_JOB: &str = "oauth2.device-code-sweep";
const REDEEM_SCOPE: &str = "oauth.device";
const RETENTION_MS: f64 = 60.0 * 60.0 * 1000.0;
const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

fn num(v: Option<&Json>) -> f64 {
    v.map_or(0.0, crate::js::to_number)
}

fn text(v: Option<&Json>) -> String {
    crate::js::string_of(v)
}

/// The store and the claims.
pub struct DeviceCodes {
    pub settings: Arc<Settings>,
    pub codes: RealmMap<Json>,
    pub claims: Arc<dyn sts_cluster::scheduler::Claims>,
    pub now_ms: Arc<dyn Fn() -> f64 + Send + Sync>,
}

impl DeviceCodes {
    /// Declares the store as Node declares it, before the store opens.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn declare(
        lifecycle: &Arc<RealmLifecycle>,
        handles: &Arc<StoreHandles>,
        settings: Arc<Settings>,
        claims: Arc<dyn sts_cluster::scheduler::Claims>,
        now_ms: Arc<dyn Fn() -> f64 + Send + Sync>,
    ) -> Arc<DeviceCodes> {
        let spec = StoreSpec {
            retain: Retain::Age,
            // A pending record lasts until it is answered or found late;
            // a finished one is kept an hour past its end.
            expires_at: Some(Arc::new(|row: &Json, _key: &str| {
                if !row.is_object() || row["state"] == "pending" {
                    return None;
                }
                let ended = [&row["finishedAt"], &row["redeemedAt"]]
                    .into_iter()
                    .map(crate::js::to_number)
                    .find(|n| *n != 0.0 && !n.is_nan())
                    .unwrap_or_else(|| crate::js::to_number(&row["expiresAt"]));
                (ended > 0.0).then_some(ended + RETENTION_MS)
            })),
            ..StoreSpec::persisted("oauth2.deviceCodes")
        };
        Arc::new(DeviceCodes {
            settings,
            codes: RealmMap::new(lifecycle, handles, spec),
            claims,
            now_ms,
        })
    }

    /// `enabled()`: `oauth2.deviceAuthorization`, off by default.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn enabled(&self) -> bool {
        self.settings
            .value_of("oauth2.deviceAuthorization")
            .as_bool()
    }

    /// `normalize(userCode)`: case, spaces and hyphens ignored (section
    /// 6.1).
    #[tracing::instrument(level = "debug")]
    pub fn normalize(user_code: &str) -> String {
        user_code
            .to_uppercase()
            .chars()
            .filter(|c| c.is_ascii_uppercase())
            .collect()
    }

    fn new_user_code() -> String {
        (0..8)
            .map(|_| {
                let i = sts_crypto::random::random_int(
                    0,
                    USER_CODE_ALPHABET.len() as u64,
                )
                .unwrap_or(0) as usize;
                USER_CODE_ALPHABET[i % USER_CODE_ALPHABET.len()] as char
            })
            .collect()
    }

    /// `keyOf(code)`: `credentialDigest(code)` (#614).
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn key_of(code: &str) -> String {
        sts_crypto::secrets::credential_digest(code).unwrap_or_default()
    }

    fn save(&self, record: &Json) {
        self.codes.set(
            &format!("d|{}", text(record.get("deviceKey"))),
            record.clone(),
        );
    }

    /// `create(clientId, clientName, scope, dpopJkt)`: the record, with
    /// `deviceCode` and `userCode` beside it for the response.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn create(
        &self,
        client_id: &str,
        client_name: &str,
        scope: &str,
        dpop_jkt: &str,
    ) -> Json {
        let mut user_code = Self::new_user_code();
        for _ in 0..5 {
            if self
                .codes
                .get(&format!("u|{}", Self::key_of(&user_code)))
                .is_none()
            {
                break;
            }
            user_code = Self::new_user_code();
        }
        let lifetime = crate::grants::setting_number(
            &self.settings,
            "oauth2.deviceCodeLifetimeS",
        );
        let interval = crate::grants::setting_number(
            &self.settings,
            "oauth2.deviceCodeIntervalS",
        );
        let device_code = sts_crypto::b64::encode(
            &sts_crypto::random::random_bytes(32).unwrap_or_default(),
        );
        let now = (self.now_ms)();
        let record = json!({
            "deviceKey": Self::key_of(&device_code),
            "userCodeKey": Self::key_of(&user_code),
            "clientId": client_id,
            "clientName": if client_name.is_empty() { client_id }
                          else { client_name },
            "scope": scope, "dpopJkt": dpop_jkt, "state": "pending",
            "createdAt": now, "expiresAt": now + lifetime * 1000.0,
            "interval": interval, "lastPolledAt": 0, "username": "",
            "approval": null,
        });
        self.save(&record);
        self.codes.set(
            &format!("u|{}", text(record.get("userCodeKey"))),
            record["deviceKey"].clone(),
        );
        let mut out = record;
        out["deviceCode"] = json!(device_code);
        out["userCode"] = json!(user_code);
        out
    }

    /// `byUserCode(typed)`: the pending record a typed user code names,
    /// with the normalised `userCode` beside it, or `None`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn by_user_code(&self, typed: &str) -> Option<Json> {
        let user_code = Self::normalize(typed);
        let device_key =
            self.codes.get(&format!("u|{}", Self::key_of(&user_code)))?;
        let record =
            self.codes.get(&format!("d|{}", text(Some(&device_key))))?;
        if record["state"] != "pending"
            || num(record.get("expiresAt")) <= (self.now_ms)()
        {
            return None;
        }
        let mut out = record;
        out["userCode"] = json!(user_code);
        Some(out)
    }

    /// `answer(typed, username, approve, approval)`: the record, or why
    /// not.
    #[tracing::instrument(level = "debug", skip(self, approval))]
    pub fn answer(
        &self,
        typed: &str,
        username: &str,
        approve: bool,
        approval: &Json,
    ) -> Result<Json, String> {
        let found = self.by_user_code(typed);
        let mut record = found
            .and_then(|f| {
                self.codes.get(&format!("d|{}", text(f.get("deviceKey"))))
            })
            .ok_or_else(|| {
                "no pending sign-in has that code; it may have expired — \
                 start again on the device"
                    .to_string()
            })?;
        record["state"] = json!(if approve { "approved" } else { "denied" });
        record["username"] = json!(username);
        record["approval"] = if approve {
            approval.clone()
        } else {
            Json::Null
        };
        record["finishedAt"] = json!((self.now_ms)());
        self.save(&record);
        self.codes
            .delete(&format!("u|{}", text(record.get("userCodeKey"))));
        Ok(record)
    }

    /// `poll(deviceCode, clientId)`: the state — `pending`, `slow_down`,
    /// `approved`, `denied`, `expired`, `redeemed` or `unknown` — and the
    /// record, the interval enforced (section 3.5).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn poll(
        &self,
        device_code: &str,
        client_id: &str,
    ) -> (String, Option<Json>) {
        let Some(mut record) =
            self.codes.get(&format!("d|{}", Self::key_of(device_code)))
        else {
            return ("unknown".into(), None);
        };
        if text(record.get("clientId")) != client_id {
            return ("unknown".into(), None);
        }
        let now = (self.now_ms)();
        if record["state"] == "pending" && num(record.get("expiresAt")) <= now {
            record["state"] = json!("expired");
            record["finishedAt"] = json!(now);
            self.save(&record);
        }
        if record["state"] != "pending" {
            return (text(record.get("state")), Some(record));
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

    /// `redeem(record)`: the approval's one token response claimed across
    /// the cluster, and the record marked redeemed.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn redeem(&self, record: &Json) -> bool {
        let ttl = (num(record.get("expiresAt")) - (self.now_ms)()).max(0.0)
            + RETENTION_MS;
        let claimed = self
            .claims
            .claim(
                REDEEM_SCOPE,
                &text(record.get("deviceKey")),
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

    /// `sweep()`: expires what nobody answered and drops what finished an
    /// hour ago — the body of Node's scheduler job.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn sweep(&self) -> String {
        let now = (self.now_ms)();
        let mut gone: Vec<String> = Vec::new();
        let mut expired = 0;
        for (key, row) in self.codes.entries() {
            if !key.starts_with("d|") || !row.is_object() {
                continue;
            }
            let user = format!("u|{}", text(row.get("userCodeKey")));
            if row["state"] == "pending" && num(row.get("expiresAt")) <= now {
                let mut row = row.clone();
                row["state"] = json!("expired");
                row["finishedAt"] = json!(now);
                self.save(&row);
                gone.push(user);
                expired += 1;
            } else if row["state"] != "pending" {
                let ended = [&row["finishedAt"], &row["redeemedAt"]]
                    .into_iter()
                    .map(crate::js::to_number)
                    .find(|n| *n != 0.0 && !n.is_nan())
                    .unwrap_or_else(|| crate::js::to_number(&row["expiresAt"]));
                if ended < now - RETENTION_MS {
                    gone.push(key.clone());
                    gone.push(user);
                }
            }
        }
        for key in &gone {
            self.codes.delete(key);
        }
        format!(
            "{} device code(s) expired, {} row(s) removed",
            expired,
            gone.len()
        )
    }
}
