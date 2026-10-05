// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Minted state on a live postgres store, two product-mode processes
//! sharing it: a session minted on one is read by the other, sealed in the
//! table with its NAME digested and sealed too; a delete ENDS a tombstoned
//! store's key, so the other cannot write it back; an in-place edit both
//! make is merged; and a third process started afterwards restores what is
//! live and nothing that expired.
//!
//! `STS_TEST_DATABASE_URL` names the database; with it unset this test says
//! so and passes. The key-encryption key is made here, for this test only.

#![allow(clippy::unwrap_used)] // a test file

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_core::mode::Mode;
use sts_core::realm::{RealmRegistry, SettingsEnvironment};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{RealmMap, StoreHandles, StoreSpec};
use sts_core::settings::Settings;
use sts_store::persistence::{MemoryDirectory, Persistence, StoreMode};
use sts_store::postgres::PostgresDriver;

struct Proc {
    persistence: Arc<Persistence>,
    sessions: RealmMap<Json>,
    carts: RealmMap<Json>,
    counts: RealmMap<Json>,
}

/// The same key the data-key test in `postgres.rs` uses: the two share the
/// `sts_keys` rows, and a different key would refuse the other's.
const KEK: &str = "a test key-encryption key, never a real one";

fn kek_file() -> String {
    let path = std::env::temp_dir()
        .join(format!("sts-minted-kek-{}", std::process::id()));
    std::fs::write(&path, KEK).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }
    path.to_str().unwrap().to_string()
}

fn proc(url: &str, kek: &str) -> Proc {
    let settings = Arc::new(Settings::new(
        json!({ "mode": "product",
                "keys": { "kekFile": kek },
                "persistence": { "writeDelay": 0 } }),
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
    let handles = StoreHandles::new();
    let sessions = RealmMap::new(
        &lifecycle,
        &handles,
        StoreSpec {
            tombstone: true,
            expires_at: Some(sts_core::realm_store::expiry_field(
                Some("expiresAt"),
                1.0,
            )),
            ..StoreSpec::persisted("test.sessions")
        },
    );
    let carts = RealmMap::new(
        &lifecycle,
        &handles,
        StoreSpec {
            // The union of both copies' items: convergent and pure.
            merge_row: Some(Arc::new(|mine: &Json, theirs: &Json| {
                let mut items: Vec<Json> =
                    theirs["items"].as_array().cloned().unwrap_or_default();
                for one in mine["items"].as_array().cloned().unwrap_or_default()
                {
                    if !items.contains(&one) {
                        items.push(one);
                    }
                }
                items.sort_by_key(|v| v.to_string());
                json!({ "items": items })
            })),
            ..StoreSpec::persisted("test.carts")
        },
    );
    // Each process counts its own: the others' arrive in the fan-in.
    let counts = RealmMap::new(
        &lifecycle,
        &handles,
        StoreSpec {
            merge: sts_core::realm_store::Merge::Own,
            ..StoreSpec::persisted("test.counts")
        },
    );
    let persistence = Persistence::new(
        StoreMode::Postgres,
        Some(Arc::new(PostgresDriver::new(url, false, 4).unwrap())),
        settings,
        lifecycle,
        Arc::new(MemoryDirectory::default()),
    );
    persistence.attach_minted(handles);
    Proc {
        persistence,
        sessions,
        carts,
        counts,
    }
}

async fn raw(url: &str, sql: &str) -> Vec<tokio_postgres::Row> {
    let mut tls =
        openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())
            .unwrap();
    tls.set_verify(openssl::ssl::SslVerifyMode::NONE);
    let mut connector = postgres_openssl::MakeTlsConnector::new(tls.build());
    connector.set_callback(|c, _| {
        c.set_verify_hostname(false);
        Ok(())
    });
    let (client, conn) = tokio_postgres::connect(url, connector).await.unwrap();
    tokio::spawn(conn);
    client.query(sql, &[]).await.unwrap()
}

#[tokio::test]
async fn minted_state_on_postgres() {
    let Ok(url) = std::env::var("STS_TEST_DATABASE_URL") else {
        eprintln!(
            "STS_TEST_DATABASE_URL is not set: minted state is not checked"
        );
        return;
    };
    raw(&url, "DELETE FROM sts_minted WHERE handle LIKE 'test.%'").await;
    let kek = kek_file();
    let a = proc(&url, &kek);
    let b = proc(&url, &kek);
    a.persistence.start().await.unwrap();
    b.persistence.start().await.unwrap();
    assert!(a.persistence.minted().is_some());

    // A session minted on A is B's once B has pulled.
    let far = 4_000_000_000_000i64;
    a.sessions
        .set("sid-1", json!({ "sub": "alice", "expiresAt": far }));
    a.sessions
        .set("sid-gone", json!({ "sub": "old", "expiresAt": 1000 }));
    a.persistence.flush().await.unwrap();
    b.persistence.pull_changes().await.unwrap();
    assert_eq!(b.sessions.get("sid-1").unwrap()["sub"], "alice");
    // Both rows were read ahead, in one round trip for the page.
    assert!(
        b.persistence.status()["minted"]["prefetchHits"]
            .as_u64()
            .unwrap()
            >= 2,
        "{}",
        b.persistence.status()
    );

    // In the table: no name, no subject.
    let rows = raw(
        &url,
        "SELECT key, key_sealed, body, expires_at FROM sts_minted WHERE handle = 'test.sessions'",
    )
    .await;
    assert_eq!(rows.len(), 2);
    for row in &rows {
        let key: String = row.get(0);
        let sealed: String = row.get(1);
        let body: String = row.get(2);
        assert!(!key.contains("sid-"), "the name is a digest: {}", key);
        assert!(sealed.starts_with("$aes"), "the name is sealed: {}", sealed);
        assert!(!body.contains("alice") && body.starts_with("$aes"));
    }
    assert!(rows.iter().any(|r| r.get::<_, Option<i64>>(3) == Some(far)));

    // A delete on A ends the key: B's old copy is refused and dropped.
    a.sessions.delete("sid-1");
    a.persistence.flush().await.unwrap();
    b.sessions
        .set("sid-1", json!({ "sub": "alice", "expiresAt": far }));
    b.persistence.flush().await.unwrap();
    assert!(b.sessions.get("sid-1").is_none(), "the tombstone won");

    // An edit both make to one row is merged.
    a.carts.set("c", json!({ "items": ["apple"] }));
    a.persistence.flush().await.unwrap();
    b.persistence.pull_changes().await.unwrap();
    b.carts.set("c", json!({ "items": ["apple", "pear"] }));
    a.carts.set("c", json!({ "items": ["apple", "fig"] }));
    a.persistence.flush().await.unwrap();
    b.persistence.flush().await.unwrap();
    // Whichever wrote second merged (a write delay of 0 lets a background
    // flush land first), so each side converges once it has pulled.
    a.persistence.pull_changes().await.unwrap();
    b.persistence.pull_changes().await.unwrap();
    assert_eq!(
        b.carts.get("c").unwrap()["items"],
        json!(["apple", "fig", "pear"])
    );
    assert_eq!(
        a.carts.get("c").unwrap()["items"],
        json!(["apple", "fig", "pear"])
    );

    // A counter each counts its own of: the other's is in the fan-in, never
    // in the store.
    a.counts.set("GET /x", json!(3));
    b.counts.set("GET /x", json!(4));
    a.persistence.flush().await.unwrap();
    b.persistence.flush().await.unwrap();
    a.persistence.pull_changes().await.unwrap();
    b.persistence.pull_changes().await.unwrap();
    assert_eq!(a.counts.get("GET /x"), Some(json!(3)));
    let fan_in = a.persistence.minted().unwrap().fan_in().clone();
    assert_eq!(
        fan_in.remote_rows("test.counts", Some("default"), "GET /x"),
        vec![json!(4)]
    );
    assert_eq!(
        b.persistence.minted().unwrap().fan_in().remote_rows(
            "test.counts",
            Some("default"),
            "GET /x"
        ),
        vec![json!(3)]
    );

    // A third process restores what is live, and not what expired.
    a.sessions
        .set("sid-2", json!({ "sub": "bob", "expiresAt": far }));
    a.persistence.stop().await.unwrap();
    b.persistence.stop().await.unwrap();
    let c = proc(&url, &kek);
    c.persistence.start().await.unwrap();
    assert_eq!(c.sessions.get("sid-2").unwrap()["sub"], "bob");
    assert!(c.sessions.get("sid-1").is_none());
    assert!(
        c.sessions.get("sid-gone").is_none(),
        "expired, not restored"
    );
    assert_eq!(
        c.carts.get("c").unwrap()["items"].as_array().unwrap().len(),
        3
    );
    // The purges: expired rows and a realm nobody defines go; so does an
    // ended row's tombstone once it is past the retention.
    raw(
        &url,
        "INSERT INTO sts_minted (handle, realm, key, body, written_at, expires_at) VALUES \
         ('test.sessions', 'default', 'x-expired', 'b', now(), 1), \
         ('test.sessions', 'no-such-realm', 'x-orphan', 'b', now() - interval '2 hours', NULL)",
    )
    .await;
    let minted = c.persistence.minted().unwrap();
    let now = sts_core::time::now_ms_f64() as i64;
    let purged = minted.purge_expired(now).await.unwrap();
    assert!(purged["expired"].as_u64().unwrap() >= 2, "{}", purged);
    assert!(purged["orphaned"].as_u64().unwrap() >= 1, "{}", purged);
    assert_eq!(purged["more"], false);
    assert_eq!(minted.tombstone_sweep_off(), "");
    assert!(minted.sweep_tombstones(far).await.unwrap() >= 1);
    // Both counters came back, each as the other process's contribution.
    let mut restored =
        minted
            .fan_in()
            .remote_rows("test.counts", Some("default"), "GET /x");
    restored.sort_by_key(|v| v.to_string());
    assert_eq!(restored, vec![json!(3), json!(4)]);
    let left = raw(
        &url,
        "SELECT key FROM sts_minted WHERE handle = 'test.sessions'",
    )
    .await;
    assert_eq!(left.len(), 1, "only the live session is left");
    let status = c.persistence.status();
    assert!(
        status["minted"]["restored"].as_u64().unwrap() >= 2,
        "{}",
        status
    );
    c.persistence.stop().await.unwrap();
    let _removed = std::fs::remove_file(&kek).is_ok();
}
