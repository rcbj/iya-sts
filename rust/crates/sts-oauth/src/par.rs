// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! RFC 9126 PUSHED AUTHORIZATION REQUESTS: THE STORE AND THE REFERENCE
//! (`par.ts`'s `PushedRequests`), in Node's store — `oauth2.pushedRequests`,
//! per realm, keyed by `credentialDigest(request_uri)` (#614), each record
//! `{ clientId, authorizationServer, params, createdAt, expiresAt, spentAt,
//! reads, clientAuthenticated, method, source, alg, encrypted, dpopJkt,
//! attestedJkt, redirectRelaxed }` — so a request pushed at a Node beside
//! this runtime is resolved here, and one pushed here is resolved there.
//!
//! * [`PushedRequests::push`] mints `urn:ietf:params:oauth:request_uri:`
//!   and 32 random bytes, bound to the client and the authorization server;
//!   a full store refuses (`STS-OAUTH-0408`) and never forgets a live one;
//! * [`PushedRequests::resolve`] is what the authorization endpoint reads a
//!   pushed `request_uri` through, with Node's refusals (0410–0414);
//! * [`PushedRequests::spend`] marks it when an authorization response is
//!   issued on it (decision 2: read many times, spent once).
//!
//! The endpoint (`parEndpoint()`) is [`crate::authorize`]'s, because its
//! validation IS the authorization endpoint's; the listing and the delete
//! the monitoring page draws are the management API's.

use std::sync::Arc;

use serde_json::{json, Map, Value as Json};
use sts_core::errors::{codes, ErrorCode};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{
    expiry_field, RealmMap, Retain, StoreHandles, StoreSpec,
};
use sts_core::settings::Settings;

/// `REQUEST_URI_PREFIX` (section 2.2).
pub const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// `REFERENCE_BYTES`.
const REFERENCE_BYTES: usize = 32;

fn s(v: Option<&Json>) -> String {
    crate::js::string_of(v)
}

/// A refusal: the code, the protocol error, the description.
pub type Refusal = (ErrorCode, &'static str, String);

/// What a resolved pushed request carries.
#[derive(Debug, Clone, Default)]
pub struct Resolved {
    pub params: Map<String, Json>,
    pub alg: String,
    pub encrypted: String,
    /// `{ requestUri, clientAuthenticated, method, source, dpopJkt,
    /// attestedJkt, redirectUriAuthenticated, expiresAt }`.
    pub pushed: Json,
}

/// What a push records beside the parameters.
#[derive(Debug, Clone, Default)]
pub struct Push {
    pub client_id: String,
    pub authorization_server: String,
    pub params: Map<String, Json>,
    pub client_authenticated: bool,
    pub method: String,
    /// `request` or `form`.
    pub source: String,
    pub alg: String,
    pub dpop_jkt: String,
    pub redirect_relaxed: bool,
}

/// The store.
pub struct PushedRequests {
    pub settings: Arc<Settings>,
    pub store: RealmMap<Json>,
    pub now_ms: Arc<dyn Fn() -> f64 + Send + Sync>,
}

impl PushedRequests {
    /// Declares `oauth2.pushedRequests` (before the store opens).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn declare(
        lifecycle: &Arc<RealmLifecycle>,
        handles: &Arc<StoreHandles>,
        settings: Arc<Settings>,
        now_ms: Arc<dyn Fn() -> f64 + Send + Sync>,
    ) -> Arc<PushedRequests> {
        Arc::new(PushedRequests {
            settings,
            store: RealmMap::new(
                lifecycle,
                handles,
                StoreSpec {
                    retain: Retain::Age,
                    expires_at: Some(expiry_field(Some("expiresAt"), 1.0)),
                    ..StoreSpec::persisted("oauth2.pushedRequests")
                },
            ),
            now_ms,
        })
    }

    /// `lifetimeS()`: 5 to 600 seconds, 60 by default.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn lifetime_s(&self) -> i64 {
        let raw = self.settings.value_of("oauth2.parRequestUriLifetimeS");
        let n = raw.as_int();
        if n == 0 {
            return 60;
        }
        n.clamp(5, 600)
    }

    fn capacity(&self) -> usize {
        let n = self.settings.value_of("oauth2.parMaxRequests").as_int();
        if n >= 1 {
            n as usize
        } else {
            10_000
        }
    }

    /// `isPushedRequestUri(value)`.
    #[tracing::instrument(level = "trace")]
    pub fn is_pushed_request_uri(value: &str) -> bool {
        value.len() > REQUEST_URI_PREFIX.len()
            && value[..REQUEST_URI_PREFIX.len()]
                .eq_ignore_ascii_case(REQUEST_URI_PREFIX)
    }

    /// `keyOf(requestUri)`: its digest.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn key_of(request_uri: &str) -> String {
        sts_crypto::secrets::credential_digest(request_uri).unwrap_or_default()
    }

    /// `sweep(now)`: the expired and the spent past their life.
    fn sweep(&self, now: f64) {
        self.store
            .in_realm(&sts_core::realm::current_id())
            .retain(|_, r| crate::js::to_number(&r["expiresAt"]) > now);
    }

    /// `push(entry)`: `(request_uri, expires_in)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn push(&self, entry: &Push) -> Result<(String, i64), Refusal> {
        if entry.client_id.is_empty() {
            return Err((
                codes::STS_OAUTH_0405,
                "invalid_request",
                "a pushed authorization request is bound to the client that \
                 pushed it (RFC 9126 section 2.2), and this one names no \
                 client."
                    .into(),
            ));
        }
        let now = (self.now_ms)();
        if self.store.len() >= self.capacity() {
            self.sweep(now);
        }
        if self.store.len() >= self.capacity() {
            tracing::warn!(
                "{}par: this realm holds {} live pushed authorization \
                 requests (oauth2.parMaxRequests), and the push from \"{}\" \
                 was refused rather than forgetting one.",
                sts_core::log::tag(codes::STS_OAUTH_0408),
                self.store.len(),
                entry.client_id
            );
            return Err((
                codes::STS_OAUTH_0408,
                "temporarily_unavailable",
                "this authorization server is holding as many pushed \
                 authorization requests as it is configured to \
                 (oauth2.parMaxRequests), all of them still live. Retry \
                 shortly; a live request_uri is never forgotten to make room."
                    .into(),
            ));
        }
        let seconds = self.lifetime_s();
        let request_uri = format!(
            "{}{}",
            REQUEST_URI_PREFIX,
            sts_crypto::b64::encode(
                &sts_crypto::random::random_bytes(REFERENCE_BYTES)
                    .unwrap_or_default()
            )
        );
        let mut params = entry.params.clone();
        params.remove("request");
        params.remove("request_uri");
        let server = if entry.authorization_server.is_empty() {
            crate::authorization_servers::DEFAULT_ID.to_string()
        } else {
            entry.authorization_server.clone()
        };
        self.store.set(
            &Self::key_of(&request_uri),
            json!({
                "clientId": entry.client_id,
                "authorizationServer": server,
                "params": params,
                "createdAt": now as i64,
                "expiresAt": (now as i64) + seconds * 1000,
                "spentAt": 0,
                "reads": 0,
                "clientAuthenticated": entry.client_authenticated,
                "method": entry.method,
                "source": if entry.source == "request" { "request" } else { "form" },
                "alg": entry.alg,
                "encrypted": "",
                "dpopJkt": entry.dpop_jkt,
                "attestedJkt": "",
                "redirectRelaxed": entry.redirect_relaxed,
            }),
        );
        tracing::info!(
            "par: client \"{}\" pushed an authorization request ({}, {}), \
             valid {}s.",
            entry.client_id,
            entry.source,
            if entry.client_authenticated {
                format!("authenticated by {}", entry.method)
            } else {
                "not authenticated".to_string()
            },
            seconds
        );
        Ok((request_uri, seconds))
    }

    /// `resolve(requestUri, clientId, { authorizationServer })`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn resolve(
        &self,
        uri: &str,
        client: &str,
        server: &str,
    ) -> Result<Resolved, Refusal> {
        let refused = |code: ErrorCode, description: String| {
            tracing::info!(
                "par: the request_uri from \"{}\" was refused: {}",
                if client.is_empty() {
                    "(no client_id)"
                } else {
                    client
                },
                description
            );
            (code, "invalid_request_uri", description)
        };
        if !Self::is_pushed_request_uri(uri) {
            return Err(refused(
                codes::STS_OAUTH_0410,
                format!(
                    "the request_uri \"{}\" is not one this authorization \
                     server issues: a pushed request_uri begins \"{}\" (RFC \
                     9126 section 2.2).",
                    uri, REQUEST_URI_PREFIX
                ),
            ));
        }
        let now = (self.now_ms)();
        let key = Self::key_of(uri);
        let Some(mut record) = self.store.get(&key) else {
            return Err(refused(
                codes::STS_OAUTH_0410,
                "the request_uri is not one this authorization server \
                 issued, or it expired and was swept. A request_uri is valid \
                 for oauth2.parRequestUriLifetimeS seconds from the push (RFC \
                 9126 section 2.2); push the request again."
                    .into(),
            ));
        };
        let expires = crate::js::to_number(&record["expiresAt"]);
        if expires <= now {
            return Err(refused(
                codes::STS_OAUTH_0411,
                format!(
                    "the request_uri expired {} — \"an expired request_uri \
                     MUST be rejected as invalid\" (RFC 9126 section 4). Push \
                     the request again.",
                    crate::js::iso_instant(expires as i64)
                ),
            ));
        }
        if s(record.get("clientId")) != client {
            return Err(refused(
                codes::STS_OAUTH_0413,
                format!(
                    "the request_uri was pushed by a different client than \
                     client_id \"{}\" — a request_uri is bound to the client \
                     that pushed it (RFC 9126 section 2.2).",
                    client
                ),
            ));
        }
        let server = if server.is_empty() {
            crate::authorization_servers::DEFAULT_ID
        } else {
            server
        };
        if s(record.get("authorizationServer")) != server {
            return Err(refused(
                codes::STS_OAUTH_0414,
                format!(
                    "the request_uri was pushed at the \"{}\" authorization \
                     server and is being used at \"{}\". A credential does \
                     not cross between the authorization servers this \
                     process serves.",
                    s(record.get("authorizationServer")),
                    server
                ),
            ));
        }
        let spent = crate::js::to_number(&record["spentAt"]);
        if spent > 0.0 {
            return Err(refused(
                codes::STS_OAUTH_0412,
                format!(
                    "the request_uri was already used: an authorization \
                     response was issued on it at {}. A client \"MUST only \
                     use a request_uri value once\" (RFC 9126 section 4); \
                     push the request again.",
                    crate::js::iso_instant(spent as i64)
                ),
            ));
        }
        let reads = crate::js::to_number(&record["reads"]) as i64 + 1;
        record["reads"] = json!(reads);
        self.store.set(&key, record.clone());
        let flag = |name: &str| record.get(name) == Some(&Json::Bool(true));
        Ok(Resolved {
            params: record
                .get("params")
                .and_then(Json::as_object)
                .cloned()
                .unwrap_or_default(),
            alg: s(record.get("alg")),
            encrypted: s(record.get("encrypted")),
            pushed: json!({
                "requestUri": uri,
                "clientAuthenticated": flag("clientAuthenticated"),
                "method": s(record.get("method")),
                "source": s(record.get("source")),
                "dpopJkt": s(record.get("dpopJkt")),
                "attestedJkt": s(record.get("attestedJkt")),
                "redirectUriAuthenticated": flag("redirectRelaxed"),
                "expiresAt": expires as i64,
            }),
        })
    }

    /// `spend(requestUri)`: true when something was spent.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn spend(&self, uri: &str) -> bool {
        let key = Self::key_of(uri);
        let Some(mut record) = self.store.get(&key) else {
            return false;
        };
        if crate::js::to_number(&record["spentAt"]) > 0.0 {
            return false;
        }
        record["spentAt"] = json!((self.now_ms)() as i64);
        self.store.set(&key, record);
        true
    }
}
