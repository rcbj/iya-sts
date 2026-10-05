// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What the scheduler stands on in a service that is not clustered: one
//! process that leads at once, claims held in this process, this process's
//! clock, the audit log as log lines, and the run rows in a per-realm store
//! persisted as `scheduler.runs`.
//!
//! The clustered implementations — membership, leases with a fencing token,
//! claims in the store, the database's clock — are `sts-cluster`'s next
//! pieces, and replace these one for one.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::Value as Json;
use sts_cluster::schedule::{compare_rows, BoxFuture};
use sts_cluster::scheduler::{
    Audit, Claim, ClaimRefused, Claims, Clock, Cluster, LeaseHandler, RunRows,
};
use sts_core::realm_store::RealmMap;

/// A service of one process: the lease is granted at once, token 0.
pub struct SoloCluster {
    pub host: String,
}

impl Cluster for SoloCluster {
    fn enabled(&self) -> bool {
        false
    }
    fn node_id(&self) -> String {
        String::new()
    }
    fn node_name(&self) -> String {
        self.host.clone()
    }
    fn lead(&self, _lease: &str, handler: Arc<dyn LeaseHandler>) {
        handler.on_gain(0);
    }
    fn step_down(&self, _lease: &str) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async { Err("this service is not clustered".to_string()) })
    }
}

/// Claims held in this process, each until its time-to-live passes.
#[derive(Default)]
pub struct LocalClaims {
    held: Mutex<HashMap<String, f64>>,
}

impl Claims for LocalClaims {
    fn claim(
        &self,
        scope: &str,
        value: &str,
        realm: &str,
        ttl_ms: f64,
    ) -> BoxFuture<'_, Result<Claim, ClaimRefused>> {
        let now = sts_core::time::now_ms_f64();
        let key = format!("{}|{}|{}", scope, realm, value);
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        held.retain(|_, until| *until > now);
        let answer = if held.contains_key(&key) {
            Err(ClaimRefused::Held)
        } else {
            held.insert(key.clone(), now + ttl_ms);
            Ok(Claim {
                claimed_at: now,
                handle: Json::String(key),
            })
        };
        Box::pin(async move { answer })
    }

    fn release(&self, handle: &Json) -> BoxFuture<'_, ()> {
        if let Some(key) = handle.as_str() {
            self.held
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(key);
        }
        Box::pin(async {})
    }
}

/// This process's clock, which is also the "database's" without one.
pub struct LocalClock;

impl Clock for LocalClock {
    fn now(&self) -> f64 {
        sts_core::time::now_ms_f64()
    }
    fn db_now(&self) -> BoxFuture<'_, Result<f64, String>> {
        Box::pin(async { Ok(sts_core::time::now_ms_f64()) })
    }
}

/// The audit log, until it is ported: one log line per event.
pub struct LogAudit;

impl Audit for LogAudit {
    fn record(&self, event: Json) {
        tracing::info!("audit: {}", event);
    }
}

/// The run rows: a per-realm store, merged by rank as Node's is.
pub struct RunStore {
    pub rows: RealmMap<Json>,
}

impl RunRows for RunStore {
    fn get(&self, realm: &str, key: &str) -> Option<Json> {
        self.rows.in_realm(realm).get(key)
    }
    fn set(&self, realm: &str, key: &str, row: Json) {
        let view = self.rows.in_realm(realm);
        // The store's merge rule, applied to this process's own copy too.
        if let Some(held) = view.get(key) {
            if compare_rows(&row, &held).is_lt() {
                return;
            }
        }
        view.set(key, row);
    }
    fn rows(&self, realm: &str) -> Vec<Json> {
        self.rows
            .in_realm(realm)
            .entries()
            .into_iter()
            .map(|(_, v)| v)
            .collect()
    }
    fn delete(&self, realm: &str, key: &str) {
        self.rows.in_realm(realm).delete(key);
    }
}
