// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The postgres driver against a real PostgreSQL with `postgres/schema.sql`
//! applied, named by `STS_TEST_DATABASE_URL` (unset: this test says so and
//! passes). One test, in order, because every step shares the one database:
//!
//! * a server whose certificate is not trusted is refused when verifying;
//! * persistence writes the directory, a realm and an override, and a second
//!   start reads them back;
//! * two nodes add different members to one group from the same base, and
//!   the second flush MERGES — both members survive, and the second node's
//!   live directory takes the merged entry;
//! * a realm's settings changed on two nodes keep both;
//! * the cluster tables: one leader at a time, the token moving on, a claim
//!   single-use and released only by its holder.

#![allow(clippy::unwrap_used)] // a test file

use std::collections::HashMap;
use std::sync::Arc;

use indexmap::IndexMap;
use serde_json::{json, Map};
use sts_cluster::membership::{ClaimAnswer, ClusterStore};
use sts_core::mode::Mode;
use sts_core::realm::{RealmRegistry, SettingsEnvironment};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::settings::Settings;
use sts_store::persistence::{
    MemoryDirectory, Persistence, StoreMode, Through,
};
use sts_store::postgres::PostgresDriver;
use sts_store::shadow::EntryLookup;
use sts_store::{Driver, StoredEntry};

struct Node {
    persistence: Arc<Persistence>,
    lifecycle: Arc<RealmLifecycle>,
    settings: Arc<Settings>,
    dir: Arc<MemoryDirectory>,
}

fn node(url: &str) -> Node {
    let settings = Arc::new(Settings::new(
        json!({ "persistence": { "writeDelay": 0 } }),
        HashMap::new(),
    ));
    let registry = Arc::new(RealmRegistry::new(Arc::new(
        SettingsEnvironment::new(settings.clone(), Vec::new()),
    )));
    let lifecycle = RealmLifecycle::new(
        registry,
        settings.clone(),
        Arc::new(Mode::new(settings.clone())),
    );
    let dir = Arc::new(MemoryDirectory::default());
    let driver = Arc::new(PostgresDriver::new(url, false, 4).unwrap());
    let persistence = Persistence::new(
        StoreMode::Postgres,
        Some(driver),
        settings.clone(),
        lifecycle.clone(),
        dir.clone(),
    );
    Node {
        persistence,
        lifecycle,
        settings,
        dir,
    }
}

fn entry(dn: &str, attrs: &[(&str, &[&str])]) -> StoredEntry {
    let mut attributes = IndexMap::new();
    for (k, vs) in attrs {
        attributes
            .insert(k.to_string(), vs.iter().map(|v| v.to_string()).collect());
    }
    StoredEntry {
        dn: dn.to_string(),
        attributes,
        ..StoredEntry::default()
    }
}

async fn flush(n: &Node) {
    assert_eq!(
        n.persistence
            .directory_through(n.persistence.generation())
            .await,
        Through::Written
    );
}

#[tokio::test]
async fn the_postgres_store() {
    let Ok(url) = std::env::var("STS_TEST_DATABASE_URL") else {
        eprintln!("STS_TEST_DATABASE_URL is not set: the postgres driver is not checked");
        return;
    };
    // A clean store.
    let raw = PostgresDriver::new(&url, false, 2).unwrap();
    raw.open().await.unwrap();
    for table in [
        "sts_ldap_entries",
        "sts_realms",
        "sts_appconfig",
        "sts_cluster_leases",
        "sts_cluster_claims",
        "sts_cluster_nodes",
    ] {
        let _cleared = raw_exec(&url, &format!("DELETE FROM {}", table)).await;
    }

    // Verifying a certificate nothing trusts is refused.
    let strict = PostgresDriver::new(&url, true, 2).unwrap();
    assert!(
        strict.open().await.is_err(),
        "an untrusted server certificate is refused"
    );

    // Written, then read back by a second start.
    let a = node(&url);
    a.persistence.start().await.unwrap();
    a.dir.put(
        "default",
        entry(
            "cn=admins,dc=example,dc=com",
            &[
                ("objectClass", &["top", "groupOfNames"]),
                ("member", &["uid=a"]),
                ("entryUUID", &["U-1"]),
            ],
        ),
    );
    a.persistence
        .directory_changed(Some("cn=admins,dc=example,dc=com"));
    a.lifecycle
        .create("acme", "Acme", "", "", &Map::new(), false)
        .unwrap();
    a.settings
        .set_override("saml2.entityId", json!("urn:pg"))
        .unwrap();
    a.persistence.config_changed(None);
    flush(&a).await;

    let b = node(&url);
    let restored = b.persistence.start().await.unwrap();
    assert_eq!(
        (restored.entries, restored.realms, restored.overrides),
        (1, 1, 1)
    );
    assert_eq!(b.settings.value_of("saml2.entityId").as_str(), "urn:pg");

    // Two nodes change one group from the same base: both members survive.
    let key = "cn=admins,dc=example,dc=com";
    let mut on_a = a.dir.entry_at("default", key).unwrap();
    on_a.attributes
        .insert("member".into(), vec!["uid=a".into(), "uid=b".into()]);
    a.dir.put("default", on_a);
    a.persistence.directory_changed(Some(key));
    flush(&a).await;
    let mut on_b = b.dir.entry_at("default", key).unwrap();
    on_b.attributes
        .insert("member".into(), vec!["uid=a".into(), "uid=c".into()]);
    b.dir.put("default", on_b);
    b.persistence.directory_changed(Some(key));
    flush(&b).await;
    let stored = raw.load_directory().await.unwrap().unwrap();
    let group = &stored["default"][0];
    assert_eq!(group.attributes["member"], vec!["uid=a", "uid=b", "uid=c"]);
    assert_eq!(
        b.dir.entry_at("default", key).unwrap().attributes["member"],
        vec!["uid=a", "uid=b", "uid=c"],
        "B took the merged entry"
    );

    // Two settings of one realm, changed on two nodes: both kept.
    a.lifecycle
        .set_override("acme", "saml2.entityId", json!("urn:a"))
        .unwrap();
    flush(&a).await;
    b.lifecycle
        .set_override("acme", "wsfed.entityId", json!("urn:b"))
        .unwrap();
    flush(&b).await;
    let realms = raw.load_realms().await.unwrap().unwrap();
    assert_eq!(realms[0]["overrides"]["saml2.entityId"], "urn:a");
    assert_eq!(realms[0]["overrides"]["wsfed.entityId"], "urn:b");

    // The cluster tables.
    raw.join("n1", 3000.0, json!({ "name": "one" }))
        .await
        .unwrap();
    raw.join("n2", 3000.0, json!({ "name": "two" }))
        .await
        .unwrap();
    let first = raw
        .acquire_lease("ops.scheduler", "n1", 3000.0)
        .await
        .unwrap();
    assert!(first.held && first.token == 1);
    let refused = raw
        .acquire_lease("ops.scheduler", "n2", 3000.0)
        .await
        .unwrap();
    assert!(!refused.held && refused.holder == "n1");
    assert_eq!(
        raw.heartbeat("n1", 3000.0).await.unwrap().leases,
        vec![("ops.scheduler".to_string(), 1)]
    );
    assert!(raw.release_lease("ops.scheduler", "n1", 1).await.unwrap());
    let second = raw
        .acquire_lease("ops.scheduler", "n2", 3000.0)
        .await
        .unwrap();
    assert!(
        second.held && second.token == 2,
        "the token moves on with the holder"
    );
    raw.leave("n2").await.unwrap();
    assert!(!raw.heartbeat("n2", 3000.0).await.unwrap().alive);
    assert!(matches!(
        raw.claim_once("s", "", "k", 5000.0, "r1", "n1")
            .await
            .unwrap(),
        ClaimAnswer::Claimed { .. }
    ));
    assert!(matches!(
        raw.claim_once("s", "", "k", 5000.0, "r2", "n2")
            .await
            .unwrap(),
        ClaimAnswer::Used { .. }
    ));
    assert!(!raw.release_claim("s", "", "k", "r2").await.unwrap());
    assert!(raw.release_claim("s", "", "k", "r1").await.unwrap());
    assert!(raw.now().await.unwrap() > 1.7e12);
    a.persistence.stop().await.unwrap();
    b.persistence.stop().await.unwrap();
}

/// A statement outside the driver, for clearing tables between runs.
async fn raw_exec(url: &str, sql: &str) -> Result<u64, String> {
    let mut tls =
        openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())
            .unwrap();
    tls.set_verify(openssl::ssl::SslVerifyMode::NONE);
    let mut connector = postgres_openssl::MakeTlsConnector::new(tls.build());
    connector.set_callback(|c, _| {
        c.set_verify_hostname(false);
        Ok(())
    });
    let (client, conn) = tokio_postgres::connect(url, connector)
        .await
        .map_err(|e| e.to_string())?;
    tokio::spawn(conn);
    client.execute(sql, &[]).await.map_err(|e| e.to_string())
}
