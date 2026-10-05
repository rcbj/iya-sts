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
    // Coordination through the change log: what A commits, B applies on
    // its next pull — an entry, a realm's setting, a process override, a
    // realm removed — and A's own rows are nothing to A.
    assert!(a.persistence.coordinates() && b.persistence.coordinates());
    b.persistence.pull_changes().await.unwrap();
    a.persistence.pull_changes().await.unwrap();
    a.dir.put(
        "default",
        entry(
            "uid=dora,dc=example,dc=com",
            &[("uid", &["dora"]), ("entryUUID", &["U-9"])],
        ),
    );
    a.persistence
        .directory_changed(Some("uid=dora,dc=example,dc=com"));
    a.lifecycle
        .set_override("acme", "saml11.providerId", json!("urn:a11"))
        .unwrap();
    a.settings
        .set_override("wstrust.issuer", json!("urn:wst"))
        .unwrap();
    a.persistence.config_changed(None);
    flush(&a).await;
    assert!(b
        .dir
        .entry_at("default", "uid=dora,dc=example,dc=com")
        .is_none());
    b.persistence.pull_changes().await.unwrap();
    assert_eq!(
        b.dir
            .entry_at("default", "uid=dora,dc=example,dc=com")
            .unwrap()
            .attributes["uid"],
        vec!["dora"]
    );
    assert_eq!(
        b.lifecycle.overrides("acme").unwrap()["saml11.providerId"],
        "urn:a11"
    );
    assert_eq!(b.settings.value_of("wstrust.issuer").as_str(), "urn:wst");
    // B's own unwritten change to the group meets A's committed one.
    let mut on_b = b.dir.entry_at("default", key).unwrap();
    on_b.attributes.insert(
        "member".into(),
        vec![
            "uid=a".into(),
            "uid=b".into(),
            "uid=c".into(),
            "uid=e".into(),
        ],
    );
    b.dir.put("default", on_b);
    let mut on_a = a.dir.entry_at("default", key).unwrap();
    on_a.attributes.insert(
        "member".into(),
        vec![
            "uid=a".into(),
            "uid=b".into(),
            "uid=c".into(),
            "uid=d".into(),
        ],
    );
    a.dir.put("default", on_a);
    a.persistence.directory_changed(Some(key));
    flush(&a).await;
    b.persistence.pull_changes().await.unwrap();
    assert_eq!(
        b.dir.entry_at("default", key).unwrap().attributes["member"],
        vec!["uid=a", "uid=b", "uid=c", "uid=d", "uid=e"],
        "B kept its own member and took A's"
    );
    flush(&b).await;
    a.persistence.pull_changes().await.unwrap();
    assert_eq!(
        a.dir.entry_at("default", key).unwrap().attributes["member"],
        vec!["uid=a", "uid=b", "uid=c", "uid=d", "uid=e"]
    );
    // A realm removed on A is removed on B.
    a.lifecycle.remove("acme").unwrap();
    flush(&a).await;
    b.persistence.pull_changes().await.unwrap();
    assert!(b.lifecycle.registry().get("acme").is_none());
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

/// Two processes' data keys on one postgres store: each makes a key for one
/// class at the same moment and the row keeps both, each opens what the
/// other sealed once it has read the row, and the digest key is ONE — the
/// first written — so both compute the same keyed digest.
#[tokio::test]
async fn data_keys_on_postgres() {
    let Ok(url) = std::env::var("STS_TEST_DATABASE_URL") else {
        eprintln!(
            "STS_TEST_DATABASE_URL is not set: the data keys are not checked"
        );
        return;
    };
    raw_exec(&url, "DELETE FROM sts_keys").await.unwrap();
    let kek = b"a test key-encryption key, never a real one".to_vec();
    let keys = |url: &str| {
        let driver: Arc<dyn Driver> =
            Arc::new(PostgresDriver::new(url, false, 2).unwrap());
        sts_store::keystore::DataKeys::durable(kek.clone(), true, driver, None)
            .unwrap()
    };
    let a = keys(&url);
    let b = keys(&url);
    a.ensure_digest_key().await;
    b.ensure_digest_key().await;
    assert!(a.keyed_digest("l", "x").is_some());
    assert_eq!(a.keyed_digest("l", "x"), b.keyed_digest("l", "x"));
    let from_a = a.seal("from a", "sessions", "kstest").unwrap();
    let from_b = b.seal("from b", "sessions", "kstest").unwrap();
    assert_ne!(
        sts_crypto::secrets::dek_id_of(&from_a),
        sts_crypto::secrets::dek_id_of(&from_b)
    );
    tokio::join!(a.settle(), b.settle());
    a.load(false).await.unwrap();
    b.load(false).await.unwrap();
    assert_eq!(a.open(&from_b, "sessions").as_deref(), Some("from b"));
    assert_eq!(b.open(&from_a, "sessions").as_deref(), Some("from a"));
    let rows = PostgresDriver::new(&url, false, 1)
        .unwrap()
        .load_keys()
        .await
        .unwrap();
    let row: serde_json::Value = serde_json::from_str(
        &rows
            .iter()
            .find(|(k, _)| k == "dek:service:kstest")
            .unwrap()
            .1,
    )
    .unwrap();
    assert_eq!(row["deks"].as_array().unwrap().len(), 2);
    let defaults: serde_json::Value = serde_json::from_str(
        &rows
            .iter()
            .find(|(k, _)| k == "dek:service:default")
            .unwrap()
            .1,
    )
    .unwrap();
    assert_eq!(
        defaults["deks"].as_array().unwrap().len(),
        1,
        "one digest key"
    );

    // Two processes making a realm's first key set at once agree on one.
    raw_exec(&url, "DELETE FROM sts_keys WHERE realm = 'kstest'")
        .await
        .unwrap();
    let sets = |keys: Arc<sts_store::keystore::DataKeys>| {
        sts_store::key_sets::KeySets::new(
            Arc::new(PostgresDriver::new(&url, false, 2).unwrap()),
            keys,
        )
    };
    let (sa, sb) = (sets(a.clone()), sets(b.clone()));
    let blob_a = json!({ "certB64": "A", "generations": { "generation": 0 } });
    let blob_b = json!({ "certB64": "B", "generations": { "generation": 0 } });
    let (ra, rb) =
        tokio::join!(sa.save("kstest", &blob_a), sb.save("kstest", &blob_b));
    // A loser of the insert race is told to try again; it then keeps the
    // winner's.
    let ra = match ra {
        Err(_) => sa.save("kstest", &blob_a).await,
        other => other,
    };
    let rb = match rb {
        Err(_) => sb.save("kstest", &blob_b).await,
        other => other,
    };
    let written = [&ra, &rb]
        .iter()
        .filter(|r| matches!(r, Ok(sts_store::key_sets::Saved::Written)))
        .count();
    assert_eq!(written, 1, "{:?} {:?}", ra, rb);
    assert_eq!(
        sa.open("kstest").unwrap().cert_b64(),
        sb.open("kstest").unwrap().cert_b64(),
        "both hold the one written"
    );
}
