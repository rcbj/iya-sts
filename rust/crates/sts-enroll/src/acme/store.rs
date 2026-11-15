// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! EVERYTHING ACME MINTS, PER TRUST REALM (`acme/acme_store.ts`): seven
//! persisted maps under Node's handles — `acme.accounts`,
//! `acme.accountKeys`, `acme.orders`, `acme.authorizations`,
//! `acme.certificates`, `acme.renewalInfo`, `acme.usedNonces` — whose
//! rows are Node's JSON, so an account, order or nonce a 1.x install
//! stored is read here as Node wrote it, and Node reads what is written
//! here (D11). The PEM of an issued certificate stays on the directory
//! entry; the store keeps its index.

use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{
    expiry_field, RealmMap, Retain, StoreHandles, StoreSpec,
};

use super::jws::b64u;
use crate::core::{iso, ms_of, normal_serial, now_ms, str_of};

/// Orders kept per account once they are finished.
pub const MAX_ORDERS_PER_ACCOUNT: usize = 1000;

/// The seven stores.
#[derive(Clone)]
pub struct AcmeStore {
    accounts: RealmMap<Json>,
    account_keys: RealmMap<Json>,
    orders: RealmMap<Json>,
    authorizations: RealmMap<Json>,
    certificates: RealmMap<Json>,
    renewals: RealmMap<Json>,
    used_nonces: RealmMap<Json>,
}

/// `unlessValid(record)` (#333): an order or authorization that never
/// became valid goes a day after its `expires`.
fn unless_valid() -> sts_core::realm_store::ExpiresAt {
    Arc::new(|record: &Json, _key: &str| {
        if record.get("status").and_then(Json::as_str) == Some("valid") {
            return None;
        }
        let at = ms_of(str_of(record, "expires"));
        (at.is_finite() && at > 0.0).then_some(at + 86_400_000.0)
    })
}

impl AcmeStore {
    /// Declares the stores (before the store opens).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn declare(
        lifecycle: &Arc<RealmLifecycle>,
        handles: &Arc<StoreHandles>,
    ) -> AcmeStore {
        let map = |spec: StoreSpec| RealmMap::new(lifecycle, handles, spec);
        let mut orders = StoreSpec::persisted("acme.orders");
        orders.expires_at = Some(unless_valid());
        let mut authorizations = StoreSpec::persisted("acme.authorizations");
        authorizations.retain = Retain::Age;
        authorizations.expires_at = Some(unless_valid());
        let mut nonces = StoreSpec::persisted("acme.usedNonces");
        nonces.retain = Retain::Age;
        nonces.expires_at = Some(expiry_field(None, 1000.0));
        AcmeStore {
            accounts: map(StoreSpec::persisted("acme.accounts")),
            account_keys: map(StoreSpec::persisted("acme.accountKeys")),
            orders: map(orders),
            authorizations: map(authorizations),
            certificates: map(StoreSpec::persisted("acme.certificates")),
            renewals: map(StoreSpec::persisted("acme.renewalInfo")),
            used_nonces: map(nonces),
        }
    }

    /// `newId(bytes)`: random base64url (no cell tag in a single-cell
    /// service, as Node's `cellLocator.stamp()` adds none there).
    #[tracing::instrument(level = "trace")]
    pub fn new_id(bytes: usize) -> String {
        b64u(&sts_crypto::random::random_bytes(bytes).unwrap_or_default())
    }

    /// `createAccount(fields)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn create_account(&self, fields: Json) -> Json {
        let mut account = json!({
            "id": AcmeStore::new_id(12),
            "status": "valid",
            "contact": [],
            "termsOfServiceAgreed": false,
            "createdAt": iso(now_ms()),
            "orderIds": [],
        });
        merge(&mut account, fields);
        self.accounts.set(str_of(&account, "id"), account.clone());
        self.account_keys.set(
            str_of(&account, "thumbprint"),
            Json::from(str_of(&account, "id")),
        );
        account
    }

    /// `getAccount(id)`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn get_account(&self, id: &str) -> Option<Json> {
        if id.is_empty() {
            return None;
        }
        self.accounts.get(id)
    }

    /// `accountByThumbprint(thumbprint)`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn account_by_thumbprint(&self, thumbprint: &str) -> Option<Json> {
        if thumbprint.is_empty() {
            return None;
        }
        let id = self.account_keys.get(thumbprint)?;
        self.get_account(id.as_str()?)
    }

    /// `saveAccount(account)`.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn save_account(&self, account: &Json) {
        self.accounts.set(str_of(account, "id"), account.clone());
    }

    /// `rekeyAccount(account, jwk, thumbprint)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn rekey_account(
        &self,
        account: &mut Json,
        jwk: Json,
        thumbprint: &str,
    ) {
        let old = str_of(account, "thumbprint").to_string();
        let id = str_of(account, "id").to_string();
        if self
            .account_keys
            .get(&old)
            .and_then(|v| v.as_str().map(str::to_string))
            == Some(id.clone())
        {
            self.account_keys.delete(&old);
        }
        account["jwk"] = jwk;
        account["thumbprint"] = Json::from(thumbprint);
        account["rekeyedAt"] = Json::from(iso(now_ms()));
        self.accounts.set(&id, account.clone());
        self.account_keys.set(thumbprint, Json::from(id));
    }

    /// `createAuthorization(fields)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn create_authorization(&self, fields: Json) -> Json {
        let mut authz =
            json!({ "id": AcmeStore::new_id(15), "status": "valid" });
        merge(&mut authz, fields);
        self.authorizations.set(str_of(&authz, "id"), authz.clone());
        authz
    }

    /// `getAuthorization(id)`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn get_authorization(&self, id: &str) -> Option<Json> {
        self.authorizations.get(id)
    }

    /// `saveAuthorization(authz)`.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn save_authorization(&self, authz: &Json) {
        self.authorizations.set(str_of(authz, "id"), authz.clone());
    }

    /// `createOrder(account, fields)`: dead orders pruned first.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn create_order(&self, account: &mut Json, fields: Json) -> Json {
        self.prune_orders();
        let mut order = json!({
            "id": AcmeStore::new_id(15),
            "accountId": account["id"],
            "status": "ready",
            "createdAt": iso(now_ms()),
        });
        merge(&mut order, fields);
        self.orders.set(str_of(&order, "id"), order.clone());
        let mut ids: Vec<Json> = account
            .get("orderIds")
            .and_then(Json::as_array)
            .cloned()
            .unwrap_or_default();
        ids.push(order["id"].clone());
        let skip = ids.len().saturating_sub(MAX_ORDERS_PER_ACCOUNT);
        account["orderIds"] = Json::Array(ids.into_iter().skip(skip).collect());
        self.save_account(account);
        order
    }

    /// `getOrder(id)`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn get_order(&self, id: &str) -> Option<Json> {
        self.orders.get(id)
    }

    /// `saveOrder(order)`.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn save_order(&self, order: &Json) {
        self.orders.set(str_of(order, "id"), order.clone());
    }

    /// `pruneOrders()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn prune_orders(&self) {
        let cutoff = now_ms() - 86_400_000.0;
        for (id, order) in self.orders.entries() {
            if str_of(&order, "status") != "valid"
                && ms_of(str_of(&order, "expires")) < cutoff
            {
                for authz in order
                    .get("authorizationIds")
                    .and_then(Json::as_array)
                    .cloned()
                    .unwrap_or_default()
                {
                    if let Some(a) = authz.as_str() {
                        self.authorizations.delete(a);
                    }
                }
                self.orders.delete(&id);
            }
        }
    }

    /// `recordCertificate(fields)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn record_certificate(&self, fields: Json) -> Json {
        let mut record =
            json!({ "id": AcmeStore::new_id(15), "issuedAt": iso(now_ms()) });
        merge(&mut record, fields);
        self.certificates.set(str_of(&record, "id"), record.clone());
        let cert_id = str_of(&record, "certId");
        if !cert_id.is_empty() {
            self.renewals.set(cert_id, record["id"].clone());
        }
        record
    }

    /// `getCertificate(id)`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn get_certificate(&self, id: &str) -> Option<Json> {
        self.certificates.get(id)
    }

    /// `saveCertificate(record)`.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn save_certificate(&self, record: &Json) {
        self.certificates.set(str_of(record, "id"), record.clone());
    }

    /// `certificateByCertId(certId)`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn certificate_by_cert_id(&self, cert_id: &str) -> Option<Json> {
        let id = self.renewals.get(cert_id)?;
        self.get_certificate(id.as_str()?)
    }

    /// `certificateBySerial(serialHex)`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn certificate_by_serial(&self, serial: &str) -> Option<Json> {
        let wanted = normal_serial(serial);
        self.certificates
            .entries()
            .into_iter()
            .map(|(_, v)| v)
            .find(|r| normal_serial(str_of(r, "serialHex")) == wanted)
    }

    /// `listAccounts()`, newest first.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn list_accounts(&self) -> Vec<Json> {
        let mut out: Vec<Json> = self
            .accounts
            .entries()
            .into_iter()
            .map(|(_, v)| v)
            .collect();
        out.sort_by(|a, b| str_of(b, "createdAt").cmp(str_of(a, "createdAt")));
        out
    }

    /// `spendNonce(id, expiresS)`: false for one already spent. A realm
    /// holding `acme.maxSpentNonces` live spends refuses the new one.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn spend_nonce(&self, id: &str, expires_s: u32, max: usize) -> bool {
        let Ok(key) = sts_crypto::secrets::credential_digest(id) else {
            return false;
        };
        if self.used_nonces.has(&key) {
            return false;
        }
        if self.used_nonces.len() >= max {
            let now_s = (now_ms() / 1000.0).floor();
            for (k, v) in self.used_nonces.entries() {
                if v.as_f64().unwrap_or(0.0) <= now_s {
                    self.used_nonces.delete(&k);
                }
            }
            if self.used_nonces.len() >= max {
                tracing::warn!(
                    "{}cache acme.nonces: full of live entries (acme.maxSpentNonces); the new \
                     one was refused.",
                    sts_core::log::tag(sts_core::errors::codes::STS_CORE_0097.as_str())
                );
                return false;
            }
        }
        self.used_nonces.set(&key, Json::from(expires_s));
        true
    }
}

fn merge(target: &mut Json, fields: Json) {
    if let (Some(t), Json::Object(f)) = (target.as_object_mut(), fields) {
        for (k, v) in f {
            t.insert(k, v);
        }
    }
}
