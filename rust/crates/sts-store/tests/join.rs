// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `joinCluster()` on both engines (`cluster.js`'s `join()`): under the join
//! lock, a live node in another mode refuses membership with STS-CLUSTER-0002
//! and writes nothing; one in the same mode is joined beside. Against the
//! databases `STS_TEST_DATABASE_URL` (postgres) and `STS_TEST_MARIADB_URL`
//! name; with neither set it says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use std::sync::Arc;

use serde_json::json;
use sts_cluster::membership::ClusterStore;
use sts_store::mariadb::MariadbDriver;
use sts_store::postgres::PostgresDriver;
use sts_store::Driver;

async fn refuses_another_mode(store: Arc<dyn ClusterStore>, tag: &str) {
    let stamp = std::process::id();
    let (a, b, c) = (
        format!("join-a-{}-{}", tag, stamp),
        format!("join-b-{}-{}", tag, stamp),
        format!("join-c-{}-{}", tag, stamp),
    );
    store
        .join(&a, 60_000.0, json!({ "name": "a", "mode": "active-passive", "version": "1.1.0" }))
        .await
        .unwrap();
    let refused = store
        .join(
            &b,
            60_000.0,
            json!({ "name": "b", "mode": "active-active" }),
        )
        .await
        .unwrap_err();
    assert!(refused.contains("STS-CLUSTER-0002"), "{}", refused);
    assert!(
        refused.contains(&format!("a ({}, active-passive, 1.1.0)", a)),
        "{}",
        refused
    );
    store
        .join(
            &c,
            60_000.0,
            json!({ "name": "c", "mode": "active-passive" }),
        )
        .await
        .unwrap();
    for n in [a, c] {
        store.leave(&n).await.unwrap();
    }
}

#[tokio::test]
async fn postgres_refuses_a_node_in_another_mode() {
    let Ok(url) = std::env::var("STS_TEST_DATABASE_URL") else {
        eprintln!("STS_TEST_DATABASE_URL is not set: the join is not checked");
        return;
    };
    let d = Arc::new(PostgresDriver::new(&url, false, 2).unwrap());
    d.open().await.unwrap();
    refuses_another_mode(d, "pg").await;
}

#[tokio::test]
async fn mariadb_refuses_a_node_in_another_mode() {
    let Ok(url) = std::env::var("STS_TEST_MARIADB_URL") else {
        eprintln!("STS_TEST_MARIADB_URL is not set: the join is not checked");
        return;
    };
    let d = Arc::new(MariadbDriver::new(&url, false, "", 2).unwrap());
    d.open().await.unwrap();
    refuses_another_mode(d, "maria").await;
}
