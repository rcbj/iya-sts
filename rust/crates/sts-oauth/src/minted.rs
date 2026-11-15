// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The register of every JWT this service mints (`common/admin_stats.js`'s
//! `recordJwt()` and `revokeWhere()`), in Node's store and Node's shape:
//! `admin_stats.tokens`, one row per `jti`, each row the record
//! `recordJwt()` writes member for member, so a 1.x install's register is
//! read here and Node reads this one's.
//!
//! What a revocation writes is [`RevokedTokens`]'s (`revokedJtis`), and the
//! row is marked `revoked` beside it unless the revocation only supersedes
//! the token (`how.superseded`), as Node marks it.
//!
//! [`SessionTokens`] is the session core's `Records::revoke_session_tokens`
//! (`authn.ts`'s `dropSession()` predicate): a session's access tokens where
//! sign-out revokes them (`mode.revokesAccessTokensAtSignOut()`), and its
//! refresh tokens unless granted with `offline_access` to a client that is
//! not one of the hosted surfaces — and only where
//! `oauth2.revokeRefreshOnLogout` holds for the client.
//!
//! Node files the register by person, session, client and bound key
//! (`indexBy`) and holds it on demand; a store of this runtime's size scans
//! it, which finds the same rows.

use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{RealmMap, Retain, StoreHandles, StoreSpec};
use sts_core::settings::Settings;

use crate::revocation::RevokedTokens;

/// The store's handle.
pub const HANDLE: &str = "admin_stats.tokens";

/// `HOSTED_SURFACE_CLIENT_IDS` (`common/applications.js`).
pub const HOSTED_SURFACE_CLIENT_IDS: [&str; 4] = [
    "sts-admin-console",
    "sts-user-portal",
    "sts-report",
    "sts-debugger-ui",
];

/// `REVOCABLE_KINDS`.
const REVOCABLE_KINDS: [&str; 4] = [
    "access_token",
    "id_token",
    "refresh_token",
    "gnap_access_token",
];

/// `kindOfTyp()`.
fn kind_of_typ(typ: &str) -> String {
    match typ {
        "Bearer" => "access_token".into(),
        "Refresh" => "refresh_token".into(),
        "UserInfo" => "userinfo_response".into(),
        "oauth-authz-req+jwt" => "request_object".into(),
        "GNAP" => "gnap_access_token".into(),
        other => format!(
            "other (typ={})",
            if other.is_empty() { "none" } else { other }
        ),
    }
}

fn token_kinds() -> [&'static str; 6] {
    [
        "id_token",
        "access_token",
        "refresh_token",
        "userinfo_response",
        "request_object",
        "gnap_access_token",
    ]
}

/// `claimText()`.
fn claim_text(v: Option<&Json>) -> String {
    match v {
        Some(Json::String(s)) => s.clone(),
        Some(Json::Number(n)) => n.to_string(),
        Some(Json::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

fn or_text(v: Option<&Json>) -> String {
    match v {
        None | Some(Json::Null) | Some(Json::Bool(false)) => String::new(),
        Some(Json::String(s)) => s.clone(),
        other => crate::js::string_of(other),
    }
}

fn or_zero(v: Option<&Json>) -> Json {
    match v {
        Some(Json::Number(n)) if n.as_f64() != Some(0.0) => {
            Json::Number(n.clone())
        }
        _ => json!(0),
    }
}

/// What a token was issued under (`recordJwt()`'s `context`).
#[derive(Debug, Clone, Default)]
pub struct IssuedUnder {
    pub kind: String,
    pub grant: String,
    pub session_id: String,
    pub session_authenticated: bool,
    pub set_id: String,
    pub grant_id: String,
    pub grant_refresh: bool,
    pub cert_spki: String,
}

/// `admin_stats.tokens`.
pub struct TokenRegister {
    tokens: RealmMap<Json>,
    revoked: Arc<RevokedTokens>,
}

impl TokenRegister {
    /// Declares the store.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(
        lifecycle: &Arc<RealmLifecycle>,
        handles: &Arc<StoreHandles>,
        settings: Arc<Settings>,
        revoked: Arc<RevokedTokens>,
    ) -> Arc<TokenRegister> {
        let keep = settings.clone();
        let spec = StoreSpec {
            retain: Retain::Keep,
            expires_at: Some(Arc::new(move |record: &Json, _key: &str| {
                let exp = record.get("exp").map_or(0.0, crate::js::to_number);
                let skew = keep.value_of("oauth2.clockSkewS").as_int().max(0);
                let hold = keep
                    .value_of("oauth2.expiredTokenRetentionS")
                    .as_int()
                    .max(0);
                (exp > 0.0).then(|| (exp + (skew + hold) as f64) * 1000.0)
            })),
            ..StoreSpec::persisted(HANDLE)
        };
        Arc::new(TokenRegister {
            tokens: RealmMap::new(lifecycle, handles, spec),
            revoked,
        })
    }

    /// `recordJwt(payload, signed, context)`: the record, filed under its
    /// `jti`. `now_ms` is `issuedAt`.
    /// `tokens.size` and `revokedJtis.size` (`admin_stats.js`'s snapshot):
    /// the tokens the register holds in a realm, and the jtis on the
    /// AMBIENT realm's revoked list — the realm the dashboard is asked in.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn held_in(&self, realm: &str) -> (usize, usize) {
        (self.tokens.in_realm(realm).len(), self.revoked.len())
    }

    /// Every record the register holds in a realm (`tokens.forEach()`), for
    /// the console's views (#444, phase 5, the `apis3` slice).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn records_in(&self, realm: &str) -> Vec<Json> {
        self.tokens
            .in_realm(realm)
            .entries()
            .into_iter()
            .map(|(_, v)| v)
            .collect()
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn record_jwt(
        &self,
        realm: &str,
        payload: &Json,
        signed: &str,
        under: &IssuedUnder,
        now_ms: i64,
    ) -> Json {
        let typ = or_text(payload.get("typ"));
        let kind = if token_kinds().contains(&under.kind.as_str()) {
            under.kind.clone()
        } else {
            kind_of_typ(&typ)
        };
        let jti = or_text(payload.get("jti"));
        let aud = payload.get("aud");
        let first_aud = match aud {
            Some(Json::Array(list)) => or_text(list.first()),
            other => or_text(other),
        };
        let client = {
            let c = or_text(payload.get("client_id"));
            if !c.is_empty() {
                c
            } else {
                let azp = or_text(payload.get("azp"));
                if azp.is_empty() {
                    first_aud
                } else {
                    azp
                }
            }
        };
        let username = {
            let u = or_text(payload.get("username"));
            let p = or_text(payload.get("preferred_username"));
            if !u.is_empty() {
                u
            } else if !p.is_empty() {
                p
            } else if under.grant == "client_credentials" {
                or_text(payload.get("client_id"))
            } else {
                String::new()
            }
        };
        let cnf = payload.get("cnf");
        let x5t = or_text(cnf.and_then(|c| c.get("x5t#S256")));
        let record = json!({
            "key": jti,
            "jti": jti,
            "kind": kind,
            "typ": typ,
            "revocable": !jti.is_empty()
                && REVOCABLE_KINDS.contains(&kind.as_str()),
            "sub": claim_text(payload.get("sub")),
            "iss": or_text(payload.get("iss")),
            "username": username,
            "client_id": client,
            "audience": match aud {
                Some(Json::Array(list)) => list.iter()
                    .map(|a| crate::js::string_of(Some(a)))
                    .collect::<Vec<_>>().join(" "),
                other => or_text(other),
            },
            "scope": or_text(payload.get("scope")),
            "jkt": or_text(cnf.and_then(|c| c.get("jkt"))),
            "x5t": x5t,
            "x5tSpki": if x5t.is_empty() { "" } else { under.cert_spki.as_str() },
            "iat": or_zero(payload.get("iat")),
            "nbf": or_zero(payload.get("nbf")),
            "exp": or_zero(payload.get("exp")),
            "sessionId": under.session_id,
            "sessionAuthenticated": under.session_authenticated,
            "setId": under.set_id,
            "grant": under.grant,
            "grantId": under.grant_id,
            "grantRefresh": under.grant_refresh,
            "issuedAt": now_ms,
            "revoked": false,
            "revokedAt": 0,
            "revokedVia": "",
            "length": signed.encode_utf16().count(),
        });
        if !jti.is_empty() {
            self.tokens.in_realm(realm).set(&jti, record.clone());
        }
        record
    }

    /// `stats.isRevoked(jti)`: in the ambient realm's revoked-token
    /// register.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn is_revoked(&self, jti: &str) -> bool {
        self.revoked.is_revoked(jti)
    }

    /// One record.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn get(&self, realm: &str, jti: &str) -> Option<Json> {
        self.tokens.in_realm(realm).get(jti)
    }

    /// `revoke(jti, via, how)`: into the revoked-token register, and the
    /// record marked unless `superseded`. True the first time.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn revoke(
        &self,
        realm: &str,
        jti: &str,
        via: &str,
        superseded: bool,
        now_ms: i64,
    ) -> bool {
        if jti.is_empty() {
            return false;
        }
        let view = self.tokens.in_realm(realm);
        let held = view.get(jti);
        let exp = held
            .as_ref()
            .and_then(|r| r.get("exp"))
            .map_or(0.0, crate::js::to_number) as i64;
        // The revoked-token register is the AMBIENT realm's, as every
        // caller here runs in the realm it names.
        let first = self.revoked.revoke(jti, via, exp, now_ms);
        if let (Some(mut record), false) = (held, superseded) {
            if record.get("revokedAt").map_or(0.0, crate::js::to_number) == 0.0
            {
                record["revokedAt"] = json!(now_ms);
            }
            if or_text(record.get("revokedVia")).is_empty() {
                record["revokedVia"] =
                    json!(if via.is_empty() { "unstated" } else { via });
            }
            record["revoked"] = json!(true);
            view.set(jti, record);
        }
        first
    }

    /// `revokeWhere(predicate, via)`: every revocable, unrevoked record the
    /// predicate holds of, revoked; the count.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn revoke_where(
        &self,
        realm: &str,
        predicate: &dyn Fn(&Json) -> bool,
        via: &str,
        now_ms: i64,
    ) -> usize {
        let found: Vec<String> = self
            .tokens
            .in_realm(realm)
            .entries()
            .into_iter()
            .filter(|(_, r)| {
                r.get("revocable") == Some(&Json::Bool(true))
                    && r.get("revoked") != Some(&Json::Bool(true))
                    && predicate(r)
            })
            .map(|(k, r)| {
                let jti = or_text(r.get("jti"));
                if jti.is_empty() {
                    k
                } else {
                    jti
                }
            })
            .collect();
        found
            .iter()
            .filter(|jti| self.revoke(realm, jti, via, false, now_ms))
            .count()
    }
}

/// The session core's revocation at sign-out, over the register; the
/// identity register's other door, `recordAuthentication()`, is
/// `inner`'s (`admin_stats.js`'s, another slice's).
pub struct SessionTokens {
    pub inner: Option<Arc<dyn sts_authn::ports::Records>>,
    pub register: Arc<TokenRegister>,
    /// `oauth2.revokeRefreshOnLogout` for a client
    /// (`applications.settingFor()`).
    pub revoke_refresh_on_logout: Arc<dyn Fn(&str) -> bool + Send + Sync>,
    pub now_ms: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl SessionTokens {
    /// `dropSession()`'s `revokeWhere()`.
    #[tracing::instrument(level = "debug", skip(self, _opts, _tags))]
    pub fn revoke_session_tokens(
        &self,
        sid: &str,
        revokes_access: bool,
        reason: &str,
        _opts: &Json,
        _tags: &[String],
    ) -> usize {
        let realm = sts_core::realm::current_id();
        let refresh_on_logout = self.revoke_refresh_on_logout.clone();
        let predicate = move |record: &Json| -> bool {
            if or_text(record.get("sessionId")) != sid {
                return false;
            }
            let typ = or_text(record.get("typ"));
            if typ == "Bearer" {
                return revokes_access;
            }
            let client = or_text(record.get("client_id"));
            typ == "Refresh"
                && (!or_text(record.get("scope"))
                    .split_whitespace()
                    .any(|s| s == "offline_access")
                    || HOSTED_SURFACE_CLIENT_IDS.contains(&client.as_str()))
                && refresh_on_logout(&client)
        };
        self.register
            .revoke_where(&realm, &predicate, reason, (self.now_ms)())
    }
}

impl sts_authn::ports::Records for SessionTokens {
    fn record_authentication(
        &self,
        record: &Json,
        request: Option<&sts_authn::ports::Request>,
    ) {
        if let Some(inner) = &self.inner {
            inner.record_authentication(record, request);
        }
    }

    /// `admin_stats.recordAccountChoice()` (#561), forwarded as
    /// `record_authentication` is: the token register only owns
    /// revocation, and the counts belong to whatever it wraps.
    fn record_account_choice(&self, kind: &str, n: Option<u64>) {
        if let Some(inner) = &self.inner {
            inner.record_account_choice(kind, n);
        }
    }

    fn revoke_session_tokens(
        &self,
        sid: &str,
        revokes_access: bool,
        reason: &str,
        opts: &Json,
        tags: &[String],
    ) -> usize {
        SessionTokens::revoke_session_tokens(
            self,
            sid,
            revokes_access,
            reason,
            opts,
            tags,
        )
    }
}
