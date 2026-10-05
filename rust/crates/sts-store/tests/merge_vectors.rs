// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The three-way merge against Node: `merge-node.json`, which
//! `tests/tools/crypto-vectors.js` writes with `directory_merge.js` itself —
//! every (base, mine, theirs) drawn from a pool built to reach each branch,
//! every `mergeValues()` over a set of lists, and `canonicalJson()`. Each
//! answer must be Node's, key order included.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed; with it unset
//! this test says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use serde_json::{json, Value as Json};
use sts_store::merge::{self, entry_of_json, merge_entry, merge_values};
use sts_store::StoredEntry;

/// An entry in the shape the pool gave it.
fn json_of(e: &StoredEntry) -> Json {
    let mut out = json!({ "dn": e.dn, "attributes": e.attributes,
                          "createdAt": e.created_at, "modifiedAt": e.modified_at });
    if let Some(o) = &e.origin {
        out["origin"] = json!(o);
    }
    out
}

fn list(v: &Json) -> Option<Vec<String>> {
    v.as_array()
        .map(|a| a.iter().map(|x| x.as_str().unwrap().to_string()).collect())
}

#[test]
fn the_merge_is_nodes() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: merge-node.json is not checked"
        );
        return;
    };
    let v: Json = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(&dir).join("merge-node.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let mut failures = Vec::new();
    let mut checked = 0;
    let mut check = |ok: bool, what: String| {
        checked += 1;
        if !ok {
            failures.push(what);
        }
    };

    check(
        json!(merge::SINGLE) == v["single"]
            && json!(merge::MULTI) == v["multi"],
        "the SINGLE and MULTI tables".to_string(),
    );
    let pool: Vec<Option<StoredEntry>> = v["pool"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| if p.is_null() { None } else { entry_of_json(p) })
        .collect();
    for (p, entry) in v["pool"].as_array().unwrap().iter().zip(&pool) {
        if let Some(e) = entry {
            assert_eq!(
                json_of(e).to_string(),
                p.to_string(),
                "pool round trip"
            );
        }
    }
    for c in v["cases"].as_array().unwrap() {
        let at = |k: &str| pool[c[k].as_u64().unwrap() as usize].as_ref();
        let got = merge_entry(at("base"), at("mine"), at("theirs"));
        let mine = json!({ "outcome": got.outcome.as_str(),
                           "entry": got.entry.as_ref().map(json_of) });
        // As text: key order is part of Node's answer and `Value`'s `==`
        // ignores it.
        #[allow(clippy::cmp_owned)]
        let same = mine.to_string() == c["result"].to_string();
        check(
            same,
            format!(
                "base {} mine {} theirs {}:\n  rust {}\n  node {}",
                c["base"], c["mine"], c["theirs"], mine, c["result"]
            ),
        );
    }
    for c in v["values"].as_array().unwrap() {
        let (b, m, t) =
            (list(&c["base"]), list(&c["mine"]), list(&c["theirs"]));
        let got = merge_values(b.as_deref(), m.as_deref(), t.as_deref());
        check(
            json!(got) == c["merged"],
            format!(
                "mergeValues({} {} {}) = {:?}",
                c["base"], c["mine"], c["theirs"], got
            ),
        );
    }
    for (entry, node) in pool.iter().zip(v["canonical"].as_array().unwrap()) {
        let got = entry.as_ref().map(merge::canonical_json);
        check(
            json!(got) == *node,
            format!("canonicalJson: {:?} vs {}", got, node),
        );
    }

    assert!(
        failures.is_empty(),
        "{} of {} differ:\n{}",
        failures.len(),
        checked,
        failures
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    eprintln!("{} answers as Node gives them", checked);
}
