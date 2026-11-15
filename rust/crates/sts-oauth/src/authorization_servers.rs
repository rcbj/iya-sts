// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! MORE THAN ONE AUTHORIZATION SERVER OUT OF ONE PROCESS (rule 3j,
//! `oauth-oidc/authorization_servers.ts`): a named authorization server is a
//! PROFILE — member overrides and removals applied to the document this
//! service would otherwise publish — selected by a path component, and the
//! capabilities in its document DRIVE its endpoints (`capabilitiesOf()`),
//! so a document cannot describe a server that is not there.
//!
//! * **The store is Node's** — `authorization_servers.profiles`, per realm,
//!   a row `{ id, label, description, overrides, removed, at, createdAt,
//!   seenAt, seen, autoCreated }` — so a server the console made on a Node
//!   beside this runtime is the one served here, and one first asked for
//!   here is the one the console lists.
//! * **Every name is an authorization server** (`ensure()`): one nobody
//!   configured is created on first sight with the defaults and marked
//!   `autoCreated`, bounded by `oauth2.maxAuthorizationServerProfiles`
//!   (past the cap a name is still served, with the defaults, and not
//!   recorded).
//! * **Which one a request is for** is ambient for the request ([`run`],
//!   [`current`]) where Node carries `req.__asProfile`.
//!
//! WHAT IS NOT HERE: the console's and `/admin-api`'s writes (create, set,
//! remove, reset — the management API's slice), the catalogue's prose and
//! the drift report, and a named server's own FAPI profile (FAPI's slice):
//! a server whose profile names one is served without it.

use std::future::Future;
use std::sync::Arc;

use serde_json::{json, Map, Value as Json};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{RealmMap, StoreHandles, StoreSpec};
use sts_core::settings::Settings;

/// `DEFAULT_ID`: the profile a URL with no path component selects.
pub const DEFAULT_ID: &str = "default";

/// `MAX_PROFILES`: `oauth2.maxAuthorizationServerProfiles`'s default.
const MAX_PROFILES: i64 = 200;

/// The catalogue rows that belong to a document other than the OAuth one
/// (`documentOf()`): `server` (published nowhere) and `gnap`.
const OTHER_DOCUMENT: &[(&str, &str)] = &[
    ("fapi", "server"),
    ("access_token_signing_alg", "server"),
    ("interaction_start_modes_supported", "gnap"),
    ("interaction_finish_methods_supported", "gnap"),
    ("key_proofs_supported", "gnap"),
    ("sub_id_formats_supported", "gnap"),
    ("assertion_formats_supported", "gnap"),
    ("key_rotation_supported", "gnap"),
    ("token_formats_supported", "gnap"),
];

tokio::task_local! {
    static PROFILE: String;
}

/// Runs `work` for the authorization server `id` (`req.__asProfile`).
#[tracing::instrument(level = "debug", skip(work))]
pub async fn run<F: Future>(id: String, work: F) -> F::Output {
    PROFILE.scope(id, work).await
}

/// The authorization server the request is for (`profileOf(req)`).
#[tracing::instrument(level = "trace")]
pub fn current() -> String {
    PROFILE
        .try_with(Clone::clone)
        .unwrap_or_else(|_| DEFAULT_ID.to_string())
}

/// `asPathOf(req)`: `''` for the default server, `/<id>` for a named one.
#[tracing::instrument(level = "trace")]
pub fn path_of(id: &str) -> String {
    if id.is_empty() || id == DEFAULT_ID {
        String::new()
    } else {
        format!("/{}", id)
    }
}

/// `ID_SHAPE`: one URL path segment, 1 to 64 characters.
#[tracing::instrument(level = "trace")]
pub fn id_shape(id: &str) -> bool {
    let b = id.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || b"._~-".contains(c))
}

/// `documentOf(member)`.
#[tracing::instrument(level = "trace")]
pub fn document_of(member: &str) -> &'static str {
    OTHER_DOCUMENT
        .iter()
        .find(|(name, _)| *name == member)
        .map(|(_, doc)| *doc)
        .unwrap_or("oauth")
}

/// The register over the store.
pub struct AuthorizationServers {
    pub settings: Arc<Settings>,
    pub profiles: RealmMap<Json>,
    pub now_ms: Arc<dyn Fn() -> f64 + Send + Sync>,
}

impl AuthorizationServers {
    /// Declares the store (before the store opens).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn declare(
        lifecycle: &Arc<RealmLifecycle>,
        handles: &Arc<StoreHandles>,
        settings: Arc<Settings>,
        now_ms: Arc<dyn Fn() -> f64 + Send + Sync>,
    ) -> Arc<AuthorizationServers> {
        Arc::new(AuthorizationServers {
            settings,
            profiles: RealmMap::new(
                lifecycle,
                handles,
                StoreSpec::persisted("authorization_servers.profiles"),
            ),
            now_ms,
        })
    }

    /// `maxProfiles()`.
    fn max_profiles(&self) -> usize {
        let n = self
            .settings
            .value_of("oauth2.maxAuthorizationServerProfiles")
            .as_int();
        (if n > 0 { n } else { MAX_PROFILES }) as usize
    }

    /// `blank(id)`.
    fn blank(&self, id: &str, auto_created: bool) -> Json {
        json!({ "id": id, "label": "", "description": "",
                "overrides": {}, "removed": [], "at": 0,
                "createdAt": (self.now_ms)() as i64, "seenAt": 0, "seen": 0,
                "autoCreated": auto_created })
    }

    /// `ensure(id, { autoCreated, seen })`: the profile an id names,
    /// created with the defaults on first sight; `None` for an unusable id
    /// or one past the cap.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn ensure(
        &self,
        id: &str,
        auto_created: bool,
        seen: bool,
    ) -> Option<Json> {
        let key = id.trim();
        if key.is_empty() || !id_shape(key) {
            return None;
        }
        let mut profile = match self.profiles.get(key) {
            Some(p) => p,
            None => {
                if self.profiles.len() >= self.max_profiles() {
                    tracing::warn!(
                        "authorization_servers: not recording \"{}\"; {} \
                         profiles are held (the id comes off a URL path, so \
                         any caller can invent one). It is still served, \
                         with the defaults.",
                        key,
                        self.max_profiles()
                    );
                    return None;
                }
                let made = self.blank(key, auto_created);
                self.profiles.set(key, made.clone());
                tracing::info!(
                    "authorization_servers: \"{}\" {}, with the default \
                     capabilities. {} authorization server(s).",
                    key,
                    if auto_created {
                        "was asked for and did not exist, so it now does"
                    } else {
                        "created"
                    },
                    self.profiles.len()
                );
                made
            }
        };
        if seen {
            let count = profile.get("seen").and_then(Json::as_i64).unwrap_or(0);
            profile["seen"] = json!(count + 1);
            profile["seenAt"] = json!((self.now_ms)() as i64);
            self.profiles.set(key, profile.clone());
        }
        Some(profile)
    }

    /// `apply(metadata, id)` and `capabilitiesOf(id, defaults, document)`:
    /// the overrides, then the removals, so a removal wins.
    #[tracing::instrument(level = "debug", skip(self, defaults))]
    pub fn capabilities_of(
        &self,
        id: &str,
        defaults: Json,
        document: &str,
    ) -> Json {
        let mut merged = defaults;
        let Some(profile) =
            self.profiles
                .get(if id.is_empty() { DEFAULT_ID } else { id })
        else {
            return merged;
        };
        let Some(m) = merged.as_object_mut() else {
            return merged;
        };
        let empty = Map::new();
        for (member, value) in profile
            .get("overrides")
            .and_then(Json::as_object)
            .unwrap_or(&empty)
        {
            if document_of(member) == document {
                m.insert(member.clone(), value.clone());
            }
        }
        for member in profile
            .get("removed")
            .and_then(Json::as_array)
            .cloned()
            .unwrap_or_default()
        {
            let name = crate::js::string_of(Some(&member));
            if document_of(&name) == document {
                m.remove(&name);
            }
        }
        merged
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_id_is_one_path_segment() {
        assert!(id_shape("t1") && id_shape("a.b~c-d_e"));
        assert!(!id_shape("") && !id_shape("-x") && !id_shape("a/b"));
        assert!(!id_shape(&"a".repeat(65)));
        assert_eq!(document_of("fapi"), "server");
        assert_eq!(document_of("issuer"), "oauth");
        assert_eq!(path_of("default"), "");
        assert_eq!(path_of("t1"), "/t1");
    }
}
