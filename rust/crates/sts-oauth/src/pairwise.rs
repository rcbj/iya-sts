// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! PAIRWISE AND EPHEMERAL SUBJECT IDENTIFIERS (`pairwise_subjects.ts`,
//! OpenID Connect Core 1.0 section 8, #118, #149): the `sub` a client is
//! told for a person.
//!
//! * **public** — the person's own `urn:uuid:<entryUUID>`;
//! * **pairwise** — HMAC-SHA256 (`deriveSharedCredential()`) over the
//!   realm, the client's SECTOR and the public `sub`, under the
//!   `oidc-pairwise` cluster secret, labelled `oidc-pairwise-sub`. The
//!   sector is the host of `sector_identifier_uri`, or the one host every
//!   redirect URI shares; a client with neither is refused with Node's
//!   sentence rather than given a public `sub` it registered not to be
//!   given;
//! * **ephemeral** — 20 random bytes, base64url, per authentication at the
//!   client, in Node's store (`oauth2.ephemeralSubjects`: `s|<session>|
//!   <client>` → the `sub`, `e|<sub>` → `{ local, client, session, until }`).
//!
//! THE SECRET IS NODE'S OWN (D11): the `oidc-pairwise` row of
//! `sts_cluster_secrets`, sealed as Node seals it and read through
//! `sts_store::cluster_secrets` — `STS_OIDC_PAIRWISE_SECRET` where an
//! operator set it, the store's where keys persist, a per-process value
//! where nothing can be shared — so a pairwise `sub` a 1.x install gave a
//! client is the one this runtime gives it, on every node. The secret is
//! read at each derivation, not when the stack is declared: the store's
//! value is known only after the store has started. The purge job
//! (`oauth2.ephemeral-subjects-purge`) is
//! [`PairwiseSubjects::purge`], for the scheduler to run.

use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{RealmMap, StoreHandles, StoreSpec};
use sts_core::settings::Settings;

use crate::clients::Clients;

/// `LABEL`.
const LABEL: &str = "oidc-pairwise-sub";

fn s(v: Option<&Json>) -> String {
    crate::js::string_of(v)
}

/// `new URL(uri).host`: the host and a non-default port.
fn host_of(uri: &str) -> Option<String> {
    let u = url::Url::parse(uri).ok()?;
    let host = u.host_str()?.to_string();
    Some(match u.port() {
        Some(p) => format!("{}:{}", host, p),
        None => host,
    })
}

/// The subjects.
pub struct PairwiseSubjects {
    pub settings: Arc<Settings>,
    pub clients: Arc<dyn Clients>,
    /// The `oidc-pairwise` secret's text (`clusterSecrets.text(
    /// 'oidc-pairwise')`), read at each derivation.
    pub secret: Arc<dyn Fn() -> String + Send + Sync>,
    pub ephemeral: RealmMap<Json>,
    pub now_ms: Arc<dyn Fn() -> f64 + Send + Sync>,
}

impl PairwiseSubjects {
    /// Declares `oauth2.ephemeralSubjects` (before the store opens).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn declare_ephemeral(
        lifecycle: &Arc<RealmLifecycle>,
        handles: &Arc<StoreHandles>,
    ) -> RealmMap<Json> {
        RealmMap::new(
            lifecycle,
            handles,
            StoreSpec::persisted("oauth2.ephemeralSubjects"),
        )
    }

    /// `sectorOf(client)`: the sector URI's host, or the one host every
    /// redirect URI shares; '' where there is none.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn sector_of(client: &Json) -> String {
        let sector = s(client.get("sector_identifier_uri"));
        if !sector.is_empty() {
            return host_of(&sector).unwrap_or_default();
        }
        let mut hosts: Vec<String> = Vec::new();
        if let Some(list) = client.get("redirect_uris").and_then(Json::as_array)
        {
            for uri in list {
                let host = host_of(&s(Some(uri))).unwrap_or_default();
                if !hosts.contains(&host) {
                    hosts.push(host);
                }
            }
        }
        if hosts.len() == 1 {
            hosts.remove(0)
        } else {
            String::new()
        }
    }

    /// `subjectFor(clientId, localSub, sessionId)`: `Err` with Node's
    /// sentence for a pairwise client with no sector.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn subject_for(
        &self,
        client_id: &str,
        local: &str,
        session_id: &str,
    ) -> Result<String, String> {
        if local.is_empty() || client_id.is_empty() {
            return Ok(local.to_string());
        }
        let cfg = self.clients.client_config_of(client_id);
        match s(cfg.get("subject_type")).as_str() {
            "ephemeral" => Ok(self.ephemeral_for(client_id, local, session_id)),
            "pairwise" => {
                let sector = Self::sector_of(&cfg);
                if sector.is_empty() {
                    return Err(format!(
                        "client \"{}\" is registered for pairwise subject \
                         identifiers and has no sector: its redirect URIs \
                         span several hosts and it names no \
                         sector_identifier_uri (OIDC Core section 8.1). Give \
                         it one on /admin/applications.",
                        client_id
                    ));
                }
                sts_crypto::secrets::derive_shared_credential(
                    &(self.secret)(),
                    LABEL,
                    &[&sts_core::realm::current_id(), &sector, local],
                )
                .map_err(|e| e.to_string())
            }
            _ => Ok(local.to_string()),
        }
    }

    /// `ephemeralLifetimeMs()`.
    fn ephemeral_lifetime_ms(&self) -> f64 {
        let session = self.settings.value_of("authn.sessionLifetimeS").as_int();
        let refresh =
            self.settings.value_of("oauth2.refreshTokenTtlS").as_int();
        (session.max(refresh).max(3600) as f64) * 1000.0
    }

    /// `ephemeralFor(clientId, local, sessionId)`: the same within one
    /// authentication at the client, a new one for the next.
    fn ephemeral_for(
        &self,
        client_id: &str,
        local: &str,
        session: &str,
    ) -> String {
        let index = if session.is_empty() {
            String::new()
        } else {
            format!("s|{}|{}", session, client_id)
        };
        let mut sub = if index.is_empty() {
            String::new()
        } else {
            self.ephemeral
                .get(&index)
                .map(|v| s(Some(&v)))
                .unwrap_or_default()
        };
        let held = if sub.is_empty() {
            None
        } else {
            self.ephemeral.get(&format!("e|{}", sub))
        };
        if held.is_none_or(|h| s(h.get("local")) != local) {
            sub = sts_crypto::b64::encode(
                &sts_crypto::random::random_bytes(20).unwrap_or_default(),
            );
        }
        let until = (self.now_ms)() + self.ephemeral_lifetime_ms();
        self.ephemeral.set(
            &format!("e|{}", sub),
            json!({ "local": local, "client": client_id, "session": session,
                    "until": until as i64 }),
        );
        if !index.is_empty() {
            self.ephemeral.set(&index, json!(sub));
        }
        sub
    }

    /// `localFor(sub)`: an ephemeral `sub` mapped back to the public one.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn local_for(&self, sub: &str) -> String {
        self.ephemeral
            .get(&format!("e|{}", sub))
            .map(|h| s(h.get("local")))
            .unwrap_or_default()
    }

    /// `purge()`: every mapping past its life, with its session index.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn purge(&self) -> usize {
        let now = (self.now_ms)();
        let mut gone: Vec<String> = Vec::new();
        for (key, row) in self.ephemeral.entries() {
            if key.starts_with("e|")
                && crate::js::to_number(&row["until"]) < now
            {
                gone.push(key.clone());
                let session = s(row.get("session"));
                if !session.is_empty() {
                    gone.push(format!(
                        "s|{}|{}",
                        session,
                        s(row.get("client"))
                    ));
                }
            }
        }
        for key in &gone {
            self.ephemeral.delete(key);
        }
        gone.len()
    }
}
