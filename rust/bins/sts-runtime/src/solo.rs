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

use sts_registers::applications::env::NoEffects as NoAppEffects;
use sts_registers::applications::AppEffects;

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

/// The scheduler's rows (`scheduler.run`, `scheduler.step-down`), into
/// the audit log (`common/audit.js`).
pub struct LogAudit(pub Arc<sts_audit::AuditLog>);

impl Audit for LogAudit {
    fn record(&self, event: Json) {
        self.0.audit(&event);
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

/// The application register's side effects (`AppEffects`): its audit rows
/// into the audit log, every other effect the not-yet-loaded families'
/// answer (`NoEffects`).
pub struct AuditedEffects(pub Arc<sts_audit::AuditLog>);

impl AppEffects for AuditedEffects {
    fn audit(&self, row: &Json) {
        self.0.audit(row);
    }
    fn failure(&self, code: sts_core::errors::ErrorCode, row: &Json) {
        self.0.failure(code.as_str(), row);
    }
    fn credential_changed(&self, notice: &Json) {
        NoAppEffects.credential_changed(notice)
    }
    fn certificate_changed(&self, notice: &Json) {
        NoAppEffects.certificate_changed(notice)
    }
    fn application_removed(&self, identifier: &str, dn: &str, via: &str) {
        NoAppEffects.application_removed(identifier, dn, via)
    }
    fn end_gnap_grants(&self, id: &str, changed: bool, how: &Json) -> i64 {
        NoAppEffects.end_gnap_grants(id, changed, how)
    }
    fn claims_fan_out(&self, id: &str, a: &str, removed: &str, aud: &str) {
        NoAppEffects.claims_fan_out(id, a, removed, aud)
    }
    fn scope_kept(&self, scope: &str, identifier: &str) -> bool {
        NoAppEffects.scope_kept(scope, identifier)
    }
    fn certificate_registration_problem(
        &self,
        usage: &str,
        der: &[u8],
    ) -> Option<(String, sts_core::errors::ErrorCode)> {
        NoAppEffects.certificate_registration_problem(usage, der)
    }
    fn dial_problem(&self, url: &str) -> String {
        NoAppEffects.dial_problem(url)
    }
    fn ssf_event_known(&self, uri: &str) -> bool {
        NoAppEffects.ssf_event_known(uri)
    }
    fn kerberos_accepts_realm(&self, realm: &str) -> bool {
        NoAppEffects.kerberos_accepts_realm(realm)
    }
}

/// What the other processes contributed to the audit ring, as the minted
/// store's fan-in holds it (`persistence_replication`); nothing where
/// minted state is not persisted.
pub struct StoreContributions(
    pub std::sync::Weak<sts_store::persistence::Persistence>,
);

impl sts_audit::store::Contributions for StoreContributions {
    fn segmented_rows(&self, handle: &str) -> Vec<Vec<Json>> {
        self.0
            .upgrade()
            .and_then(|p| p.minted())
            .map(|m| m.fan_in().remote_segmented_rows(handle, None))
            .unwrap_or_default()
    }
    fn rows(&self, handle: &str) -> Vec<Json> {
        self.0
            .upgrade()
            .and_then(|p| p.minted())
            .map(|m| m.fan_in().remote_rows(handle, None, ""))
            .unwrap_or_default()
    }
}
