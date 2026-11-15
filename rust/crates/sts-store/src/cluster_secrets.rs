// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE SECRETS EVERY NODE MUST AGREE ON (`cluster/cluster_secrets.ts`, #46):
//! the CSRF key, ACME's nonce key, the SSF receiver's secret, the OpenID
//! Connect pairwise key, OpenID Federation's page key, the sign-out
//! result's key and DBSC's.
//!
//! Each is DECLARED here, generated once for the whole store, and read by
//! every process before it serves: [`ClusterSecrets::start`] offers a fresh
//! value SEALED under the key-encryption key (label `cluster-secret`, the
//! default realm's DEK, as Node's `keystore.seal(offer, 'cluster-secret')`
//! at start), the store keeps the first offer it ever received
//! (`ensureSharedSecret()`, `INSERT … ON CONFLICT DO NOTHING`), and every
//! process uses what the store kept. A row Node wrote is therefore a row
//! this runtime opens, and the other way round — which is the whole point
//! for `oidc-pairwise`: a pairwise `sub` that changed across the upgrade
//! would show a client one person as two.
//!
//! [`ClusterSecrets::text`] is synchronous and answers the shared value
//! once started, and a per-process random value before — which is what a
//! store that cannot share (memory, ldif) keeps for ever. **An operator's
//! environment variable wins**, on every node: agreement by configuration.
//!
//! **No key-encryption key, no sharing**, and an EPHEMERAL one (Node's
//! `hasEphemeralKek()`; here, data keys that are derived rather than
//! stored) counts as none — except in active-active mode, which is refused
//! (`STS-CLUSTER-0017`). Any other failure on a store that can share is
//! FATAL (`STS-CLUSTER-0016`): a node serving with its own key refuses
//! every other node's forms.
//!
//! WHAT REPLACED WHAT. Node writes a per-process value into the
//! environment so the request workers it forks inherit it; this runtime is
//! one process, so the value is held here and nothing is written to the
//! environment. The generator rows (`generate`) Node once had are gone from
//! Node's table too.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::{json, Value as Json};
use sts_core::errors::codes;
use sts_core::log::tag;

use crate::driver::Driver;
use crate::keystore::DataKeys;

/// One declared secret: its name, the random bytes it is made of, the
/// environment variable that overrides it, and what it keys.
#[derive(Clone, Copy, Debug)]
pub struct Declared {
    pub name: &'static str,
    pub bytes: usize,
    pub env: &'static str,
    pub what: &'static str,
}

/// `DECLARED`, row for row Node's.
pub const DECLARED: &[Declared] = &[
    Declared {
        name: "csrf",
        bytes: 32,
        env: "STS_CSRF_SECRET",
        what: "The key a form's CSRF token is MACed with \
               (common/websecurity.ts).",
    },
    Declared {
        name: "acme-nonce",
        bytes: 32,
        env: "STS_ACME_NONCE_SECRET",
        what: "The key ACME's Replay-Nonce values are MACed with \
               (acme/acme_jws.ts).",
    },
    Declared {
        name: "ssf-receiver",
        bytes: 32,
        env: "STS_SSF_RECEIVER_SECRET",
        what: "The secret the console's and the portal's own SSF receivers \
               authenticate pushes with (ssf/ssf_receivers.ts).",
    },
    Declared {
        name: "oidc-pairwise",
        bytes: 32,
        env: "STS_OIDC_PAIRWISE_SECRET",
        what: "The key an OpenID Connect pairwise subject identifier is \
               derived with (oauth-oidc/pairwise_subjects.ts, OIDC Core \
               section 8.1).",
    },
    Declared {
        name: "oidfed-page",
        bytes: 32,
        env: "STS_OIDFED_PAGE_SECRET",
        what: "The key an OpenID Federation listing's or collection's page \
               pointer is MACed with (oidfed/page_pointer.ts).",
    },
    Declared {
        name: "logout-result",
        bytes: 32,
        env: "STS_LOGOUT_RESULT_SECRET",
        what: "The key a sign-out's result is MACed with on its way to the \
               signed-out document (logout/logout.ts).",
    },
    Declared {
        name: "dbsc",
        bytes: 32,
        env: "STS_DBSC_SECRET",
        what: "The key a Device Bound Session Credentials challenge and \
               bound cookie are MACed with (authn/device_bound_sessions.ts).",
    },
];

/// The label a shared secret is sealed under (`'cluster-secret'`).
pub const SEAL_LABEL: &str = "cluster-secret";

/// What this process holds for one secret.
#[derive(Clone, Debug)]
struct Held {
    text: String,
    /// `process`, `store` or `environment`.
    source: &'static str,
}

/// Reads an environment variable; a seam for the tests.
pub type EnvReader = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// The secrets, one register per process.
pub struct ClusterSecrets {
    values: Mutex<HashMap<&'static str, Held>>,
    /// Names whose value this process made itself, so `start()` can tell
    /// its own from an operator's.
    generated_here: Mutex<HashSet<&'static str>>,
    started: Mutex<bool>,
    env: EnvReader,
}

impl Default for ClusterSecrets {
    fn default() -> ClusterSecrets {
        ClusterSecrets::with_env(Arc::new(|name: &str| {
            std::env::var(name).ok()
        }))
    }
}

/// Standard base64 with padding, as Node's `toString('base64')`.
fn base64_std(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

impl ClusterSecrets {
    /// A register reading the environment through `env`.
    pub fn with_env(env: EnvReader) -> ClusterSecrets {
        ClusterSecrets {
            values: Mutex::new(HashMap::new()),
            generated_here: Mutex::new(HashSet::new()),
            started: Mutex::new(false),
            env,
        }
    }

    fn declared(name: &str) -> Option<&'static Declared> {
        DECLARED.iter().find(|d| d.name == name)
    }

    fn env_value(&self, declared: &Declared) -> Option<String> {
        (self.env)(declared.env).filter(|v| !v.is_empty())
    }

    /// `processValue(name)`: the environment's, or random bytes made for
    /// this process (and remembered as made here).
    fn process_value(&self, declared: &'static Declared) -> Held {
        let held = match self.env_value(declared) {
            Some(text) => Held {
                text,
                source: "environment",
            },
            None => {
                self.generated_here
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(declared.name);
                Held {
                    text: base64_std(
                        &sts_crypto::random::random_bytes(declared.bytes)
                            .unwrap_or_default(),
                    ),
                    source: "process",
                }
            }
        };
        self.values
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(declared.name, held.clone());
        held
    }

    /// `text(name)`: the secret's text, synchronously — the shared value
    /// once started, a per-process (or the environment's) value before.
    /// `Err` for a name that is not declared, Node's sentence.
    // Hot path (a map read per form, per pairwise subject): no span.
    pub fn text(&self, name: &str) -> Result<String, String> {
        let Some(declared) = ClusterSecrets::declared(name) else {
            return Err(format!(
                "cluster_secrets: \"{}\" is not a declared shared secret; \
                 add it to DECLARED.",
                name
            ));
        };
        if let Some(held) = self
            .values
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(declared.name)
        {
            return Ok(held.text.clone());
        }
        Ok(self.process_value(declared).text)
    }

    /// `describe()`: where each secret's value came from, never the value.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn describe(&self) -> Json {
        let values = self.values.lock().unwrap_or_else(PoisonError::into_inner);
        let secrets: Vec<Json> = DECLARED
            .iter()
            .map(|d| {
                json!({
                    "name": d.name,
                    "what": d.what,
                    "source": values
                        .get(d.name)
                        .map(|h| h.source)
                        .unwrap_or("not yet used"),
                })
            })
            .collect();
        json!({
            "started": *self.started.lock()
                .unwrap_or_else(PoisonError::into_inner),
            "secrets": secrets,
        })
    }

    fn seed_process_values(&self) {
        for declared in DECLARED {
            let has = self
                .values
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains_key(declared.name);
            if !has {
                self.process_value(declared);
            }
        }
    }

    fn mark_started(&self) {
        *self.started.lock().unwrap_or_else(PoisonError::into_inner) = true;
    }

    /// `start(keystore)`: every declared secret read from the shared
    /// store, a fresh sealed value offered first so the store keeps the
    /// first offer. Answers `{ shared, names }`, or `{ shared: false }`
    /// where the values stay per process.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn start(
        &self,
        driver: Option<&Arc<dyn Driver>>,
        keys: &Arc<DataKeys>,
        active_active: bool,
    ) -> Result<Json, String> {
        let Some(driver) = driver.filter(|d| d.shares_secrets()) else {
            self.seed_process_values();
            self.mark_started();
            return Ok(json!({ "shared": false }));
        };
        // AN EPHEMERAL KEK IS TREATED AS NONE: derived data keys change at
        // every restart, so a row sealed under the last run's would not
        // open under this one's.
        if !keys.sealed() || !keys.stores_deks() {
            if active_active {
                return Err(format!(
                    "{}cluster secrets: active-active mode and no \
                     key-encryption key is open to seal the shared secrets \
                     with.",
                    tag(codes::STS_CLUSTER_0017)
                ));
            }
            self.seed_process_values();
            self.mark_started();
            return Ok(json!({ "shared": false }));
        }
        let mut names: Vec<&'static str> = Vec::new();
        for declared in DECLARED {
            let mine = self
                .generated_here
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(declared.name);
            if self.env_value(declared).is_some() && !mine {
                self.process_value(declared);
                continue;
            }
            names.push(declared.name);
        }
        for name in &names {
            let declared =
                ClusterSecrets::declared(name).ok_or("undeclared")?;
            let offer = base64_std(
                &sts_crypto::random::random_bytes(declared.bytes)
                    .map_err(|e| e.to_string())?,
            );
            // Sealed under the DEFAULT realm's DEK: Node's `start()` runs
            // with no realm entered.
            let Some(sealed) = keys.seal(&offer, SEAL_LABEL, "") else {
                return Err(format!(
                    "{}cluster secrets: the \"{}\" secret could not be \
                     sealed, and a shared secret is never written to the \
                     store in the clear.",
                    tag(codes::STS_CLUSTER_0017),
                    name
                ));
            };
            // THE DATA-KEY ROW LANDS FIRST (#391): another node opening
            // this secret must find the DEK it was sealed under.
            keys.settle().await;
            let row = driver
                .ensure_shared_secret(name, &sealed)
                .await
                .map_err(|e| {
                    format!(
                        "{}cluster secrets: the shared secrets could not be \
                         read: {}",
                        tag(codes::STS_CLUSTER_0016),
                        e
                    )
                })?;
            let Some(row) = row else {
                return Err(format!(
                    "{}cluster secrets: the \"{}\" secret was not in the \
                     store after it was offered.",
                    tag(codes::STS_CLUSTER_0016),
                    name
                ));
            };
            let opened = match keys.open(&row.material, SEAL_LABEL) {
                Some(text) => Some(text),
                // A DEK another node wrote since this one loaded: read the
                // rows again and try once more.
                None if keys.names_unheld(&row.material) => {
                    keys.load(false).await.map_err(|e| e.to_string())?;
                    keys.open(&row.material, SEAL_LABEL)
                }
                None => None,
            };
            let Some(opened) = opened else {
                return Err(format!(
                    "{}cluster secrets: the stored \"{}\" secret would not \
                     open under this node's key-encryption key. Every node \
                     against one store must hold the same one.",
                    tag(codes::STS_CLUSTER_0017),
                    name
                ));
            };
            self.values
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(
                    declared.name,
                    Held {
                        text: opened,
                        source: "store",
                    },
                );
            self.generated_here
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(declared.name);
        }
        self.mark_started();
        tracing::info!(
            "cluster secrets: {} secret(s) are shared through the store: {}.",
            names.len(),
            names.join(", ")
        );
        Ok(json!({ "shared": true, "names": names }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_undeclared_name_is_refused_with_nodes_sentence() {
        let secrets = ClusterSecrets::with_env(Arc::new(|_: &str| None));
        assert_eq!(
            secrets.text("nope").unwrap_err(),
            "cluster_secrets: \"nope\" is not a declared shared secret; \
             add it to DECLARED."
        );
    }

    #[test]
    fn a_process_value_is_stable_and_the_environment_wins() {
        let secrets = ClusterSecrets::with_env(Arc::new(|name: &str| {
            (name == "STS_CSRF_SECRET").then(|| "pinned".to_string())
        }));
        assert_eq!(secrets.text("csrf").unwrap(), "pinned");
        let one = secrets.text("oidc-pairwise").unwrap();
        assert_eq!(one.len(), 44);
        assert_eq!(secrets.text("oidc-pairwise").unwrap(), one);
        let described = secrets.describe();
        assert_eq!(described["secrets"][0]["source"], "environment");
        assert_eq!(described["secrets"][3]["source"], "process");
    }

    #[tokio::test]
    async fn without_a_sharing_store_every_value_is_per_process() {
        let secrets = ClusterSecrets::with_env(Arc::new(|_: &str| None));
        let out = secrets.start(None, &DataKeys::none(), false).await.unwrap();
        assert_eq!(out, json!({ "shared": false }));
        assert_eq!(secrets.describe()["started"], true);
    }
}
