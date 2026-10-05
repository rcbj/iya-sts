// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The path validator against Node over C2SP x509-limbo: for every case,
//! `verify_path_to_anchors()` and `verify_issued_directly()` give Node's
//! verdict — ok, the check that refused, the sentence, the chain's length
//! and the policies — at the instant Node judged it.
//!
//! Needs the corpus (`STS_X509_LIMBO_DIR`, `tests/tools/fetch-x509-limbo.sh`)
//! and Node's verdicts (`limbo-node.json` in `STS_CRYPTO_VECTORS`, written by
//! `tests/tools/crypto-vectors.js`); with either missing it says so and
//! passes.

#![allow(clippy::unwrap_used)] // a test file

use serde_json::{json, Value as Json};
use sts_pki::path::{self, Entry, PathOptions};
use sts_pki::x509::keys::pem_to_der;

/// The one case where both refuse for different reasons: pkijs cannot parse
/// a certificate with 2048 subject attributes ("Data is not correct for
/// 'Certificate'") and calls it unusable; Rust reads it and refuses it on
/// the name constraints it was built to stress.
fn pinned(id: &str, which: &str, mine: &Json, node: &Json) -> bool {
    id == "pathological::nc-dos-1"
        && mine["ok"] == false
        && node["ok"] == false
        && mine["check"] == "name-constraints"
        && node["check"] == "unusable"
        && (which == "anchors" || which == "direct")
}

#[test]
fn every_limbo_case_as_node_judges_it() {
    let (Ok(limbo), Ok(vectors)) = (
        std::env::var("STS_X509_LIMBO_DIR"),
        std::env::var("STS_CRYPTO_VECTORS"),
    ) else {
        eprintln!("STS_X509_LIMBO_DIR or STS_CRYPTO_VECTORS is not set: x509-limbo is not checked");
        return;
    };
    let node_path = std::path::Path::new(&vectors).join("limbo-node.json");
    if !node_path.exists() {
        eprintln!(
            "{} does not exist: x509-limbo is not checked",
            node_path.display()
        );
        return;
    }
    let corpus: Json = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(&limbo).join("limbo.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let node: Json =
        serde_json::from_str(&std::fs::read_to_string(node_path).unwrap())
            .unwrap();
    let only = std::env::var("STS_LIMBO_ONLY").unwrap_or_default();
    let mut failures = Vec::new();
    let mut checked = 0;
    for (t, n) in corpus["testcases"]
        .as_array()
        .unwrap()
        .iter()
        .zip(node["cases"].as_array().unwrap())
    {
        let id = t["id"].as_str().unwrap();
        assert_eq!(id, n["id"].as_str().unwrap());
        if !only.is_empty() && !id.starts_with(&only) {
            continue;
        }
        let der = |v: &Json| pem_to_der(v.as_str().unwrap()).unwrap();
        let leaf = der(&t["peer_certificate"]);
        let intermediates: Vec<Vec<u8>> = t["untrusted_intermediates"]
            .as_array()
            .unwrap()
            .iter()
            .map(der)
            .collect();
        let trusted: Vec<Vec<u8>> = t["trusted_certs"]
            .as_array()
            .unwrap()
            .iter()
            .map(der)
            .collect();
        let anchors: Vec<Entry> =
            trusted.iter().filter_map(|d| Entry::from_der(d)).collect();
        let options = PathOptions {
            now_ms: n["now"].as_i64().unwrap(),
            ..PathOptions::default()
        };

        let a = path::verify_path_to_anchors(
            &leaf,
            &intermediates,
            &anchors,
            &options,
        );
        let mine = json!({ "ok": a.ok, "check": a.check, "reason": a.reason,
                           "chain": a.chain.len(), "policies": a.policies });
        checked += 1;
        if mine != n["anchors"] && !pinned(id, "anchors", &mine, &n["anchors"])
        {
            failures.push(format!(
                "{} anchors:\n  rust {}\n  node {}",
                id, mine, n["anchors"]
            ));
        }
        let (d, index) =
            path::verify_issued_directly(&leaf, &trusted, &options);
        let mine = json!({ "ok": d.ok, "check": d.check, "reason": d.reason, "index": index });
        checked += 1;
        if mine != n["direct"] && !pinned(id, "direct", &mine, &n["direct"]) {
            failures.push(format!(
                "{} direct:\n  rust {}\n  node {}",
                id, mine, n["direct"]
            ));
        }
    }
    let shown: Vec<&String> = failures.iter().take(40).collect();
    assert!(
        failures.is_empty(),
        "{} of {} verdicts differ:\n{}",
        failures.len(),
        checked,
        shown
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );
    eprintln!("{} verdicts as Node gives them", checked);
}
