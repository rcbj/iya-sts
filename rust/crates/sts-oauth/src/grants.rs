// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What a grant leaves behind between its requests, in Node's stores and
//! Node's shapes, so that a code Node issued is redeemed here and a refresh
//! token this runtime rotated is refused as a replay by Node (D11):
//!
//! | Store | Node | A row |
//! |---|---|---|
//! | `oauth2.authzCodes` | `oauth2.ts`'s `authzCodes` | the authorization request a code came from, keyed by `credentialDigest(code)` (#614), tombstoned, expiring at `expires` |
//! | `oauth2.redeemedCodes` | `redeemedCodes` | what became of a code: `{ when, expires, forget, ttlMs, client_id, fingerprint, jtis, family }`, expiring at `forget` |
//! | `oauth2_bcp.transactions` | `transactions` | a PKCE challenge or nonce already used (RFC 9700 section 2.1.1) |
//! | `oauth2_bcp.refreshTokens` | `refreshTokens` | a refresh token's family and whether it was rotated (section 2.2.2), merged so a rotation on either node sticks |
//! | `oauth2_bcp.refreshFamilies` | `refreshFamilies` | a family's client and last use |
//! | `oauth2_bcp.grantTokens` | `grantTokens` | what a grant issued, where rotation is off (RFC 7009's revocation of the pair) |
//!
//! WHAT REPLACED WHAT. Node files the refresh records by family
//! (`indexBy`) and holds them on demand; here the realm's rows are in
//! memory and a family's members are found by a scan, which finds the same
//! rows. The cap sweeps (`forgetStale*()`) are the stores' own expiry plus
//! the bound at insert.

use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{
    expiry_field, RealmMap, Retain, StoreHandles, StoreSpec,
};
use sts_core::settings::Settings;

/// `FAMILY_CLAIM`: the refresh token's claim naming its family.
pub const FAMILY_CLAIM: &str = "refresh_family";

/// `AUTH_CODE_TTL_MS`.
pub const AUTH_CODE_TTL_MS: f64 = 5.0 * 60.0 * 1000.0;

/// `TRANSACTION_TTL_MS` and `MAX_TRANSACTIONS`.
const TRANSACTION_TTL_MS: f64 = 10.0 * 60.0 * 1000.0;
const MAX_TRANSACTIONS: usize = 500;

/// `MAX_REFRESH_TOKENS`.
const MAX_REFRESH_TOKENS: usize = 2000;

fn num(v: Option<&Json>) -> f64 {
    v.map_or(0.0, crate::js::to_number)
}

fn text(v: Option<&Json>) -> String {
    crate::js::string_of(v)
}

/// `Number(config.value(key))`.
pub fn setting_number(settings: &Settings, key: &str) -> f64 {
    use sts_core::settings::SettingValue;
    match settings.value_of(key) {
        SettingValue::Int(n) => n as f64,
        SettingValue::Text(t) => t.trim().parse().unwrap_or(f64::NAN),
        SettingValue::Bool(b) => f64::from(u8::from(b)),
        SettingValue::List(_) => f64::NAN,
    }
}

/// The stores.
pub struct GrantStores {
    pub settings: Arc<Settings>,
    pub codes: RealmMap<Json>,
    pub redeemed: RealmMap<Json>,
    pub transactions: RealmMap<Json>,
    pub refresh_tokens: RealmMap<Json>,
    pub refresh_families: RealmMap<Json>,
    pub grant_tokens: RealmMap<Json>,
}

impl GrantStores {
    /// Declares the six, as Node declares them, before the store opens.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn declare(
        lifecycle: &Arc<RealmLifecycle>,
        handles: &Arc<StoreHandles>,
        settings: Arc<Settings>,
    ) -> Arc<GrantStores> {
        let aged =
            |name: &str, field: &'static str, tombstone: bool| StoreSpec {
                retain: Retain::Age,
                tombstone,
                expires_at: Some(expiry_field(Some(field), 1.0)),
                ..StoreSpec::persisted(name)
            };
        let kept = |name: &str, tombstone: bool| StoreSpec {
            tombstone,
            expires_at: Some(expiry_field(Some("forget"), 1.0)),
            ..StoreSpec::persisted(name)
        };
        let mut refresh = kept("oauth2_bcp.refreshTokens", true);
        refresh.merge_row = Some(Arc::new(|mine: &Json, theirs: &Json| {
            if !mine.is_object() || !theirs.is_object() {
                return if mine.is_null() {
                    theirs.clone()
                } else {
                    mine.clone()
                };
            }
            let mut out = mine.clone();
            out["rotated"] = json!(
                mine.get("rotated") == Some(&Json::Bool(true))
                    || theirs.get("rotated") == Some(&Json::Bool(true))
            );
            out
        }));
        Arc::new(GrantStores {
            settings,
            codes: RealmMap::new(
                lifecycle,
                handles,
                aged("oauth2.authzCodes", "expires", true),
            ),
            redeemed: RealmMap::new(
                lifecycle,
                handles,
                aged("oauth2.redeemedCodes", "forget", false),
            ),
            transactions: RealmMap::new(
                lifecycle,
                handles,
                aged("oauth2_bcp.transactions", "forget", false),
            ),
            refresh_tokens: RealmMap::new(lifecycle, handles, refresh),
            refresh_families: RealmMap::new(
                lifecycle,
                handles,
                kept("oauth2_bcp.refreshFamilies", false),
            ),
            grant_tokens: RealmMap::new(
                lifecycle,
                handles,
                kept("oauth2_bcp.grantTokens", true),
            ),
        })
    }

    fn setting_num(&self, key: &str) -> f64 {
        setting_number(&self.settings, key)
    }

    /// `authCodeTtlMs()`: OAuth 2.1's ten-minute cap and FAPI 2.0's
    /// sixty seconds are their slices'.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn code_ttl_ms(&self) -> f64 {
        let seconds = self.setting_num("oauth2.authorizationCodeTtlS");
        if seconds.is_finite() && seconds > 0.0 {
            seconds.floor() * 1000.0
        } else {
            AUTH_CODE_TTL_MS
        }
    }

    // -------------------------------------------------------------------
    // Transactions (RFC 9700 section 2.1.1).
    // -------------------------------------------------------------------

    fn transaction_ttl_ms(&self) -> f64 {
        let seconds = self.setting_num("oauth2.authorizationCodeTtlS");
        if seconds.is_finite() && seconds > 0.0 {
            seconds.floor() * 2000.0
        } else {
            TRANSACTION_TTL_MS
        }
    }

    fn max_transactions(&self) -> usize {
        let n = self.setting_num("oauth2.maxPendingTransactions");
        if n.is_finite() && n > 0.0 {
            n.floor() as usize
        } else {
            MAX_TRANSACTIONS
        }
    }

    /// `transactionKeys(query)`.
    pub fn transaction_keys(query: &Json) -> Vec<(String, &'static str)> {
        let mut keys = Vec::new();
        let challenge = text(query.get("code_challenge"));
        if !challenge.is_empty() {
            keys.push((format!("pkce:{}", challenge), "code_challenge"));
        }
        let nonce = text(query.get("nonce"));
        if !nonce.is_empty() {
            keys.push((format!("nonce:{}", nonce), "nonce"));
        }
        keys
    }

    /// `checkTransactionValues()`: `(code, description)` of a refusal.
    #[tracing::instrument(level = "debug", skip(self, query))]
    pub fn check_transaction_values(
        &self,
        bcp_enabled: bool,
        query: &Json,
        client_id: &str,
        now_ms: f64,
    ) -> Option<(sts_core::errors::ErrorCode, String)> {
        use sts_core::errors::codes;
        if !bcp_enabled {
            return None;
        }
        for (key, what) in Self::transaction_keys(query) {
            let Some(record) = self.transactions.get(&key) else {
                continue;
            };
            if num(record.get("forget")) < now_ms {
                continue;
            }
            let held = text(record.get("clientId"));
            if held != client_id {
                return Some((codes::STS_OAUTH_0124, format!(
                    "RFC 9700 section 2.1.1: the {} must be bound to the client and user-agent transaction. This one was already used by client \"{}\" and cannot also be a fresh value chosen by \"{}\".",
                    what, held, client_id)));
            }
            if record.get("redeemed") == Some(&Json::Bool(true)) {
                return Some((codes::STS_OAUTH_0125, format!(
                    "RFC 9700 section 2.1.1: the {} must be transaction-specific. This value was used for an authorization code that has already been redeemed, so this is a second transaction reusing a first one's value. Generate a fresh one per request.",
                    what)));
            }
        }
        None
    }

    /// `rememberTransactionValues()`.
    #[tracing::instrument(level = "debug", skip(self, query))]
    pub fn remember_transaction_values(
        &self,
        bcp_enabled: bool,
        query: &Json,
        client_id: &str,
        completed: bool,
        now_ms: f64,
    ) {
        if !bcp_enabled {
            return;
        }
        let forget = now_ms + self.transaction_ttl_ms();
        for (key, _) in Self::transaction_keys(query) {
            self.transactions.set(
                &key,
                json!({ "clientId": client_id, "redeemed": completed,
                        "forget": forget }),
            );
        }
        self.transactions
            .in_realm(&sts_core::realm::current_id())
            .retain(|_, v| num(v.get("forget")) >= now_ms);
        let cap = self.max_transactions();
        let keys = self.transactions.keys();
        if keys.len() > cap {
            for key in keys.iter().take(keys.len() - cap) {
                self.transactions.delete(key);
            }
        }
    }

    /// `noteRedeemed(record)`.
    #[tracing::instrument(level = "debug", skip(self, record))]
    pub fn note_redeemed(&self, bcp_enabled: bool, record: &Json) {
        if !bcp_enabled {
            return;
        }
        for (key, _) in Self::transaction_keys(record) {
            if let Some(mut known) = self.transactions.get(&key) {
                known["redeemed"] = json!(true);
                self.transactions.set(&key, known);
            }
        }
    }

    // -------------------------------------------------------------------
    // Refresh families (RFC 9700 section 2.2.2).
    // -------------------------------------------------------------------

    fn refresh_family_window_ms(&self) -> f64 {
        (self.setting_num("oauth2.refreshTokenTtlS") * 1000.0)
            .max(3600.0 * 1000.0)
    }

    fn max_refresh_tokens(&self) -> usize {
        let n = self.setting_num("oauth2.maxRefreshTokenFamilies");
        if n.is_finite() && n > 0.0 {
            n.floor() as usize
        } else {
            MAX_REFRESH_TOKENS
        }
    }

    /// `familyForIssuance(jti, parentJti, parentFamily)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn family_for_issuance(
        &self,
        jti: &str,
        parent_jti: &str,
        parent_family: &str,
    ) -> String {
        if !parent_family.is_empty() {
            return parent_family.to_string();
        }
        let parent = (!parent_jti.is_empty())
            .then(|| {
                self.refresh_tokens
                    .get(parent_jti)
                    .or_else(|| self.grant_tokens.get(parent_jti))
            })
            .flatten();
        match parent.map(|p| text(p.get("family"))) {
            Some(f) if !f.is_empty() => f,
            _ => jti.to_string(),
        }
    }

    /// `membersOf(familyId, alsoJti, accessOut)`: the refresh tokens of a
    /// family, and the access tokens beside them.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn members_of(
        &self,
        family: &str,
        also: &str,
    ) -> (Vec<String>, Vec<String>) {
        let mut out: Vec<String> = Vec::new();
        let mut access: Vec<String> = Vec::new();
        if !also.is_empty() {
            out.push(also.to_string());
        }
        if !family.is_empty() {
            for (jti, record) in self.refresh_tokens.entries() {
                if text(record.get("family")) == family {
                    if !out.contains(&jti) {
                        out.push(jti.clone());
                    }
                    let a = text(record.get("access"));
                    if !a.is_empty() && !access.contains(&a) {
                        access.push(a);
                    }
                }
            }
            if let Some(f) = self.refresh_families.get(family) {
                if let Some(list) = f.get("members").and_then(Json::as_array) {
                    for one in list {
                        let j = text(Some(one));
                        if !out.contains(&j) {
                            out.push(j);
                        }
                    }
                }
            }
        }
        (out, access)
    }

    /// `familyOfRefresh(claims)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn family_of_refresh(&self, claims: &Json) -> String {
        let jti = text(claims.get("jti"));
        let known = (!jti.is_empty())
            .then(|| {
                self.refresh_tokens
                    .get(&jti)
                    .or_else(|| self.grant_tokens.get(&jti))
            })
            .flatten();
        let named = text(claims.get(FAMILY_CLAIM));
        if !named.is_empty() {
            return named;
        }
        match known.map(|k| text(k.get("family"))) {
            Some(f) if !f.is_empty() => f,
            _ => jti,
        }
    }

    /// `grantMembersOf(familyId, alsoJti)`: every token a grant issued.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn grant_members_of(&self, family: &str, also: &str) -> Vec<String> {
        let (mut out, access) = self.members_of(family, also);
        for a in access {
            if !out.contains(&a) {
                out.push(a);
            }
        }
        if !family.is_empty() {
            for (jti, record) in self.grant_tokens.entries() {
                if text(record.get("family")) == family {
                    if !out.contains(&jti) {
                        out.push(jti.clone());
                    }
                    let a = text(record.get("access"));
                    if !a.is_empty() && !out.contains(&a) {
                        out.push(a);
                    }
                }
            }
        }
        out
    }

    fn grant_forget_of(&self, exp_s: f64, now_ms: f64) -> f64 {
        let skew = self.setting_num("oauth2.clockSkewS");
        (if exp_s.is_finite() && exp_s > 0.0 {
            exp_s * 1000.0
        } else {
            now_ms + self.refresh_family_window_ms()
        }) + if skew.is_finite() { skew * 1000.0 } else { 0.0 }
    }

    /// `noteRefreshIssued(jti, parentJti, clientId, parentFamily, grant)`.
    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn note_refresh_issued(
        &self,
        rotation: bool,
        jti: &str,
        parent_jti: &str,
        client_id: &str,
        parent_family: &str,
        access: &str,
        exp_s: f64,
        now_ms: f64,
    ) {
        if !rotation || jti.is_empty() {
            return;
        }
        let family = self.family_for_issuance(jti, parent_jti, parent_family);
        let forget = now_ms + self.refresh_family_window_ms();
        let kept = self.grant_forget_of(exp_s, now_ms);
        self.refresh_tokens.set(
            jti,
            json!({ "family": family, "clientId": client_id,
                    "rotated": false, "forget": forget.max(kept),
                    "access": access }),
        );
        let row = match self.refresh_families.get(&family) {
            Some(mut known) => {
                known["forget"] = json!(forget);
                known
            }
            None => json!({ "clientId": client_id, "forget": forget,
                            "lastUsedAt": now_ms }),
        };
        self.refresh_families.set(&family, row);
        let cap = self.max_refresh_tokens();
        if self.refresh_tokens.len() > cap {
            self.forget_stale_refresh_tokens(now_ms, cap);
        }
    }

    fn forget_stale_refresh_tokens(&self, now_ms: f64, cap: usize) {
        self.refresh_tokens
            .in_realm(&sts_core::realm::current_id())
            .retain(|_, v| num(v.get("forget")) >= now_ms);
        self.refresh_families
            .in_realm(&sts_core::realm::current_id())
            .retain(|_, v| num(v.get("forget")) >= now_ms);
        let rotated: Vec<String> = self
            .refresh_tokens
            .entries()
            .into_iter()
            .filter(|(_, v)| v.get("rotated") == Some(&Json::Bool(true)))
            .map(|(k, _)| k)
            .collect();
        for jti in rotated {
            if self.refresh_tokens.len() <= cap {
                break;
            }
            self.refresh_tokens.delete(&jti);
        }
        let mut dropped = 0;
        for key in self.refresh_tokens.keys() {
            if self.refresh_tokens.len() <= cap {
                break;
            }
            self.refresh_tokens.delete(&key);
            dropped += 1;
        }
        if dropped > 0 {
            tracing::warn!(
                "RFC 9700 mode: {} LIVE refresh token record(s) were forgotten because \
                 oauth2.maxRefreshTokenFamilies ({}) is full of unexpired, unrotated tokens. \
                 Those tokens still work and a replay of a rotated one is still refused as \
                 revoked, but a replay will no longer revoke its whole family. Raise the setting.",
                dropped,
                cap
            );
        }
    }

    /// `noteGrantTokens(familyId, refreshJti, accessJti, clientId, expSec)`.
    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn note_grant_tokens(
        &self,
        rotation: bool,
        family: &str,
        refresh_jti: &str,
        access_jti: &str,
        client_id: &str,
        exp_s: f64,
        now_ms: f64,
    ) {
        if family.is_empty() || refresh_jti.is_empty() || rotation {
            return;
        }
        self.grant_tokens.set(
            refresh_jti,
            json!({ "family": family, "access": access_jti,
                    "clientId": client_id,
                    "forget": self.grant_forget_of(exp_s, now_ms) }),
        );
        let cap = 2 * self.max_refresh_tokens();
        if self.grant_tokens.len() > cap {
            self.grant_tokens
                .in_realm(&sts_core::realm::current_id())
                .retain(|_, v| num(v.get("forget")) >= now_ms);
            let mut dropped = 0;
            for key in self.grant_tokens.keys() {
                if self.grant_tokens.len() <= cap {
                    break;
                }
                self.grant_tokens.delete(&key);
                dropped += 1;
            }
            if dropped > 0 {
                tracing::warn!(
                    "RFC 7009: {} record(s) of what a grant issued were forgotten because twice \
                     oauth2.maxRefreshTokenFamilies ({}) is full of unexpired token sets. Those \
                     tokens still work until they expire, but revoking their refresh token will no \
                     longer revoke them with it. Raise the setting.",
                    dropped,
                    cap
                );
            }
        }
    }

    /// `noteRefreshRotated(jti)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn note_refresh_rotated(&self, rotation: bool, jti: &str, now_ms: f64) {
        if !rotation || jti.is_empty() {
            return;
        }
        if let Some(mut known) = self.refresh_tokens.get(jti) {
            known["rotated"] = json!(true);
            let family = text(known.get("family"));
            self.refresh_tokens.set(jti, known);
            if let Some(mut f) = self.refresh_families.get(&family) {
                f["lastUsedAt"] = json!(now_ms);
                self.refresh_families.set(&family, f);
            }
        }
    }

    /// `familyRevocationTtlMs(clientId)`, with the client's own
    /// `oauth2.refreshTokenTtlS` override handed in.
    pub fn family_revocation_ttl_ms(&self, per_client_s: f64) -> f64 {
        let skew = self.setting_num("oauth2.clockSkewS");
        self.refresh_family_window_ms()
            .max(if per_client_s.is_finite() {
                per_client_s * 1000.0
            } else {
                0.0
            })
            + if skew.is_finite() { skew * 1000.0 } else { 0.0 }
    }

    /// A family's row (`refreshFamilies.get()`).
    pub fn family(&self, id: &str) -> Option<Json> {
        self.refresh_families.get(id)
    }

    /// A refresh token's row (`refreshTokens.get()`).
    pub fn refresh_record(&self, jti: &str) -> Option<Json> {
        self.refresh_tokens.get(jti)
    }
}
