// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A DPoP proof is good for one request ACROSS NODES: two nodes (two sets
//! of local stores) over one claim table. A proof accepted on A is refused
//! on B with STS-OAUTH-0519; one A refused for its `ath` is released and B
//! may use it; a replay A can see itself keeps STS-OAUTH-0110; a claim store
//! that cannot be asked is STS-OAUTH-0520; and only the reservation of a
//! proof that was accepted is kept.

#![allow(clippy::unwrap_used)] // a test file

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value as Json};
use sts_cluster::scheduler::{Claim, ClaimRefused, Claims};
use sts_core::errors::{codes, ErrorCode};
use sts_core::mode::Mode;
use sts_core::realm::{RealmRegistry, SettingsEnvironment};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::StoreHandles;
use sts_core::settings::Settings;
use sts_crypto::jws::{generate_key, sign_jws, SignOptions};
use sts_crypto::keys::JwsKey;
use sts_oauth::dpop::{ath_of, verify_proof, ProofRequest};
use sts_oauth::dpop_reservation::{
    unverified_jti_of, Reservation, Reserved, SCOPE,
};
use sts_oauth::dpop_stores::DpopStores;

const NOW: i64 = 1_791_000_000;
const HTU: &str = "https://sts.example/oauth2/userinfo";

#[derive(Default)]
struct Table {
    held: Mutex<HashSet<String>>,
    broken: AtomicBool,
    asked: Mutex<Vec<(String, String, f64)>>,
}

impl Claims for Table {
    fn claim(
        &self,
        scope: &str,
        value: &str,
        realm: &str,
        ttl_ms: f64,
    ) -> futures_like::Boxed<'_, Result<Claim, ClaimRefused>> {
        let key = format!("{}|{}|{}", scope, realm, value);
        self.asked.lock().unwrap().push((
            scope.to_string(),
            realm.to_string(),
            ttl_ms,
        ));
        let answer = if self.broken.load(Ordering::SeqCst) {
            Err(ClaimRefused::Store("down".into()))
        } else if self.held.lock().unwrap().insert(key.clone()) {
            Ok(Claim {
                claimed_at: 0.0,
                handle: json!({ "key": key }),
            })
        } else {
            Err(ClaimRefused::Held)
        };
        Box::pin(async move { answer })
    }
    fn release(&self, handle: &Json) -> futures_like::Boxed<'_, ()> {
        let key = handle["key"].as_str().unwrap_or("").to_string();
        self.held.lock().unwrap().remove(&key);
        Box::pin(async {})
    }
}

mod futures_like {
    pub type Boxed<'a, T> =
        std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;
}

fn node() -> Arc<DpopStores> {
    node_with(json!({ "oauth2": { "dpopIatSkewS": 60 } }))
}

fn node_with(file: Json) -> Arc<DpopStores> {
    let settings = Arc::new(Settings::new(file, HashMap::new()));
    let registry = Arc::new(RealmRegistry::new(Arc::new(
        SettingsEnvironment::new(settings.clone(), Vec::new()),
    )));
    let lifecycle = RealmLifecycle::new(
        registry,
        settings.clone(),
        Arc::new(Mode::new(settings.clone())),
    );
    DpopStores::new(
        &lifecycle,
        &StoreHandles::new(),
        settings,
        Arc::new(|| NOW),
    )
}

fn proof(key: &JwsKey, jti: &str, ath: Option<&str>) -> String {
    let mut claims =
        json!({ "jti": jti, "htm": "GET", "htu": HTU, "iat": NOW });
    if let Some(a) = ath {
        claims["ath"] = json!(a);
    }
    sign_jws(
        claims.as_object().unwrap(),
        key,
        &SignOptions {
            algorithm: Some("ES256".into()),
            header: json!({ "typ": "dpop+jwt", "jwk": key.public_jwk().unwrap().unwrap() }).as_object().unwrap().clone(),
            now: Some(NOW),
            ..Default::default()
        },
    )
    .unwrap()
}

/// One request: reserve, verify, settle.
async fn request(
    table: &Table,
    local: &DpopStores,
    p: &str,
    token: Option<&str>,
) -> (Result<(), ErrorCode>, bool) {
    let reservation = Reservation::reserve(table, Some(p), 60).await;
    let ctx = Reserved {
        local,
        reservation: reservation.as_ref(),
    };
    let r = verify_proof(
        Some(p),
        &ProofRequest {
            htm: "GET",
            htu: HTU,
            access_token: token,
            expected_jkt: None,
            now: NOW,
        },
        &ctx,
    )
    .map(|_| ())
    .map_err(|f| f.code);
    let kept = match &reservation {
        Some(res) => res.settle(table).await,
        None => false,
    };
    (r, kept)
}

#[tokio::test]
async fn a_proof_is_good_once_across_nodes() {
    let key = generate_key("ES256").unwrap();
    let table = Table::default();
    let (a, b) = (node(), node());

    let once = proof(&key, "j1", None);
    assert_eq!(request(&table, &a, &once, None).await, (Ok(()), true));
    assert_eq!(
        table.asked.lock().unwrap()[0],
        (SCOPE.to_string(), "default".into(), 120_000.0),
        "twice the skew, the default realm"
    );
    assert_eq!(
        request(&table, &b, &once, None).await.0,
        Err(codes::STS_OAUTH_0519)
    );
    // A sees its own replay first.
    assert_eq!(
        request(&table, &a, &once, None).await.0,
        Err(codes::STS_OAUTH_0110)
    );

    // Refused on A for its ath: released, so B may use it.
    let token = "an.access.token";
    let no_ath = proof(&key, "j2", None);
    assert_eq!(
        request(&table, &a, &no_ath, Some(token)).await,
        (Err(codes::STS_OAUTH_0111), false)
    );
    assert_eq!(request(&table, &b, &no_ath, None).await, (Ok(()), true));

    let with_ath = proof(&key, "j3", Some(&ath_of(token)));
    table.broken.store(true, Ordering::SeqCst);
    assert_eq!(
        request(&table, &a, &with_ath, Some(token)).await.0,
        Err(codes::STS_OAUTH_0520)
    );
    table.broken.store(false, Ordering::SeqCst);
    assert_eq!(
        request(&table, &a, &with_ath, Some(token)).await,
        (Ok(()), true)
    );

    // A refused for a full history: released, so B may use it.
    let full = node_with(
        json!({ "oauth2": { "dpopIatSkewS": 60, "dpopReplayCacheSize": 1 } }),
    );
    assert_eq!(
        request(&table, &full, &proof(&key, "f1", None), None).await,
        (Ok(()), true)
    );
    let next = proof(&key, "f2", None);
    assert_eq!(
        request(&table, &full, &next, None).await,
        (Err(codes::STS_OAUTH_0554), false)
    );
    assert_eq!(request(&table, &b, &next, None).await, (Ok(()), true));

    // Nothing to read reserves nothing.
    assert!(Reservation::reserve(&table, None, 60).await.is_none());
    assert!(Reservation::reserve(&table, Some("a.b"), 60)
        .await
        .is_none());
    assert_eq!(unverified_jti_of(&format!("{}, {}", once, once)), "");
    assert_eq!(unverified_jti_of(&once), "j1");
}
