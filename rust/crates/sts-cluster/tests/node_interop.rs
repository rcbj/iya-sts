// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! One Node.js node and one Rust node on the same PostgreSQL store agree on
//! who leads. Under the compatible-upgrade decision (D11) the two never run
//! together in production, but a Rust node must read and write the cluster
//! tables' rows exactly as Node does. The Node half is the service's own
//! postgres driver, run by `tests/tools/cluster-interop-node.js` in the tests
//! image named by `STS_NODE_INTEROP_IMAGE`; the store is
//! `STS_TEST_DATABASE_URL`. Either unset: this test says so and passes.
//!
//! The Rust node leads; the Node node, contending, is told the Rust node
//! holds the lease at its token; the Rust node leaves and the Node node takes
//! it at the next token; a second Rust node is refused it while the Node node
//! holds it, and takes it at the next token again once the Node node is
//! killed.

#![allow(clippy::unwrap_used)] // a test file

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value as Json;
use sts_cluster::membership::{ClusterNode, ClusterStore};
use sts_cluster::scheduler::{Cluster, LeaseHandler};
use sts_store::postgres::PostgresDriver;

struct Nothing;
impl LeaseHandler for Nothing {
    fn on_gain(&self, _: u64) {}
    fn on_lose(&self) {}
}

fn rust_node(store: &Arc<PostgresDriver>, id: &str) -> Arc<ClusterNode> {
    ClusterNode::new(
        store.clone(),
        id,
        id,
        250.0,
        1500.0,
        Arc::new(|code, why| panic!("the Rust node stopped: {} {}", code, why)),
    )
}

async fn holder(store: &PostgresDriver) -> (String, u64) {
    let a = store
        .acquire_lease("ops.scheduler", "observer", 1000.0)
        .await
        .unwrap();
    (a.holder, a.token)
}

/// Waits until the Node node has printed a line `pred` accepts.
async fn node_saw(
    lines: &Arc<Mutex<Vec<Json>>>,
    pred: impl Fn(&Json) -> bool,
) -> Json {
    for _ in 0..80 {
        if let Some(l) = lines.lock().unwrap().iter().find(|l| pred(l)) {
            return l.clone();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the Node node never said it: {:?}", lines.lock().unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_node_and_a_rust_node_agree_on_who_leads() {
    let (Ok(url), Ok(image)) = (
        std::env::var("STS_TEST_DATABASE_URL"),
        std::env::var("STS_NODE_INTEROP_IMAGE"),
    ) else {
        eprintln!("STS_TEST_DATABASE_URL or STS_NODE_INTEROP_IMAGE unset");
        return;
    };
    let store = Arc::new(PostgresDriver::new(&url, false, 2).unwrap());
    let tag = std::process::id();
    let (r1, n1, r2) = (
        format!("rust1-{}", tag),
        format!("nodejs-{}", tag),
        format!("rust2-{}", tag),
    );
    let rust = rust_node(&store, &r1);
    rust.join().await.unwrap();
    rust.lead("ops.scheduler", Arc::new(Nothing));
    tokio::time::sleep(Duration::from_millis(800)).await;
    let token = rust.token_of("ops.scheduler").unwrap();

    let tool = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/tools/cluster-interop-node.js")
        .canonicalize()
        .unwrap();
    let container = format!("cluster-interop-444p3-{}", tag);
    let mut child = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--name",
            &container,
            "--network",
            "host",
            "-v",
            &format!(
                "{}:/usr/src/sts/tests/tools/cluster-interop-node.js:ro",
                tool.display()
            ),
            &image,
            "node",
            "tests/tools/cluster-interop-node.js",
            &url,
            &n1,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let lines = Arc::new(Mutex::new(Vec::<Json>::new()));
    {
        let lines = lines.clone();
        let out = child.stdout.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                if let Ok(j) = serde_json::from_str::<Json>(&line) {
                    if j.get("name").is_none() {
                        lines.lock().unwrap().push(j);
                    }
                }
            }
        });
    }
    let joined = node_saw(&lines, |l| l.get("joined").is_some()).await;
    assert_eq!(
        joined["joined"], true,
        "Node joined beside Rust: {}",
        joined
    );
    let told = node_saw(&lines, |l| l.get("held").is_some()).await;
    assert_eq!(told["held"], false);
    assert_eq!(told["holder"], r1.as_str(), "Node is told Rust leads");
    assert_eq!(told["token"], token);

    // The Rust node leaves; the Node node takes the lease at the next token.
    rust.leave().await.unwrap();
    let took = node_saw(&lines, |l| l["held"] == true).await;
    assert_eq!(took["token"], token + 1, "{}", took);
    assert_eq!(holder(&store).await, (n1.clone(), token + 1));

    // A second Rust node is refused it while Node holds it...
    let second = rust_node(&store, &r2);
    second.join().await.unwrap();
    assert!(!second.acquire("ops.scheduler").await.held);
    second.lead("ops.scheduler", Arc::new(Nothing));
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(!second.holds("ops.scheduler"), "two leaders");
    // ...and takes it at the next token once Node is killed and its rows
    // expire by the database's clock.
    let _killed = Command::new("docker")
        .args(["kill", &container])
        .status()
        .unwrap();
    let _reaped = child.wait();
    tokio::time::sleep(Duration::from_millis(3000)).await;
    assert!(second.holds("ops.scheduler"));
    assert_eq!(second.token_of("ops.scheduler"), Some(token + 2));
    assert_eq!(holder(&store).await, (r2.clone(), token + 2));
    second.leave().await.unwrap();
}
