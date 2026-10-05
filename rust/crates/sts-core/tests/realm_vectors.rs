// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The realm model against Node: `realms-node.json`, which
//! `tests/tools/crypto-vectors.js` writes with realms really created in
//! `common/realms.js`. Ids, domains, base DNs, EST label paths, invented
//! addresses, and — under three values of `realms.pathSegment` — every
//! prefix, path match, unknown-realm verdict and `href()`.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed; with it unset
//! this test says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use std::sync::{Arc, Mutex};

use serde_json::{json, Value as Json};
use sts_core::realm::{
    self, normalize_domain, Realm, RealmEnvironment, RealmRegistry,
};

struct Env {
    segment: Mutex<String>,
    global_domain: String,
    est_labels: Vec<String>,
}

impl RealmEnvironment for Env {
    fn enabled(&self) -> bool {
        true
    }
    fn path_segment(&self) -> String {
        self.segment.lock().unwrap().clone()
    }
    fn global_domain(&self) -> String {
        self.global_domain.clone()
    }
    fn reserved(&self) -> Vec<String> {
        Vec::new()
    }
    fn est_labels(&self) -> Vec<String> {
        self.est_labels.clone()
    }
}

#[test]
fn realms_as_node_answers() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: realms-node.json is not checked"
        );
        return;
    };
    let v: Json = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(&dir).join("realms-node.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let env = Arc::new(Env {
        segment: Mutex::new("realm".to_string()),
        global_domain: v["globalDomain"].as_str().unwrap().to_string(),
        est_labels: v["estLabels"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l.as_str().unwrap().to_string())
            .collect(),
    });
    let registry = RealmRegistry::new(env.clone());
    let mut failures = Vec::new();
    let mut checked = 0;
    let mut check = |ok: bool, what: String| {
        checked += 1;
        if !ok {
            failures.push(what);
        }
    };

    // create(): the id, then the domain (`<id>.<global.domain>` when none).
    let specs = [
        ("acme", Some("Acme.Example.COM.")),
        ("dev", Some("dev.acme.example.com")),
        ("x1", None),
        ("bücher", None),
        ("zz", Some("acme.example.com")),
    ];
    for ((id, domain), node) in
        specs.iter().zip(v["created"].as_array().unwrap())
    {
        let mut refusals = registry.validate_id(id);
        let domain = match domain {
            Some(d) => normalize_domain(d),
            None => format!("{}.{}", id, normalize_domain(&env.global_domain)),
        };
        if refusals.is_empty() {
            refusals = registry.validate_domain(&domain, id);
        }
        if refusals.is_empty() {
            let mut r = Realm::default_realm();
            r.id = id.to_string();
            r.builtin = false;
            r.domain = domain.clone();
            registry.insert(r);
        }
        check(
            json!(refusals.sentences) == node["errors"],
            format!(
                "create {}: {:?} vs {}",
                id, refusals.sentences, node["errors"]
            ),
        );
    }
    for row in v["ids"].as_array().unwrap() {
        let id = row["id"].as_str().unwrap();
        check(
            json!(registry.validate_id(id).sentences) == row["errors"],
            format!("validateId({})", id),
        );
    }
    for row in v["domains"].as_array().unwrap() {
        let n = normalize_domain(row["raw"].as_str().unwrap());
        check(
            n == row["normalized"].as_str().unwrap(),
            format!("normalizeDomain({}) = {}", row["raw"], n),
        );
        check(
            json!(registry.validate_domain(&n, "new").sentences)
                == row["errors"],
            format!("validateDomain({})", n),
        );
    }
    for (r, row) in registry.list().iter().zip(v["baseDns"].as_array().unwrap())
    {
        let mine = json!({ "id": r.id, "domain": registry.domain_of(r), "baseDn": registry.base_dn_of(r),
                           "est": registry.est_label_path(r) });
        check(mine == *row, format!("realm {}: {} vs {}", r.id, mine, row));
    }
    let dev = registry.get("dev").unwrap();
    let mail = realm::run_sync(dev, || {
        ["alice", "bob@x.org", "@lead"]
            .iter()
            .map(|n| registry.invented_mail_of(n))
            .collect::<Vec<_>>()
    });
    check(
        json!(mail) == v["mail"],
        format!("invented mail {:?}", mail),
    );

    for case in v["bySegment"].as_array().unwrap() {
        *env.segment.lock().unwrap() =
            case["segment"].as_str().unwrap().to_string();
        let seg = case["segment"].clone();
        let prefixes: Vec<String> = registry
            .list()
            .iter()
            .map(|r| registry.prefix_of(r))
            .collect();
        check(
            json!(prefixes) == case["prefixes"],
            format!("segment {}: prefixes {:?}", seg, prefixes),
        );
        for m in case["matches"].as_array().unwrap() {
            let p = m["path"].as_str().unwrap();
            let mine = registry
                .match_path(p)
                .map(|x| json!({ "realm": x.realm.id, "rest": x.rest, "est": x.est_label }))
                .unwrap_or(Json::Null);
            check(
                mine == m["match"],
                format!("segment {}: matchPath({}) = {}", seg, p, mine),
            );
            check(
                registry.unknown_realm_path(p)
                    == m["unknown"].as_bool().unwrap(),
                format!("segment {}: unknownRealmPath({})", seg, p),
            );
        }
        let acme = registry.get("acme").unwrap();
        let hrefs = realm::run_sync(acme, || {
            let current = registry.current_prefix();
            [
                "/oauth2/token",
                "/realm/acme/x",
                "https://a/b",
                "rel",
                current.as_str(),
            ]
            .iter()
            .map(|p| registry.href(p))
            .collect::<Vec<_>>()
        });
        check(
            json!(hrefs) == case["hrefs"],
            format!("segment {}: href {:?}", seg, hrefs),
        );
    }

    assert!(
        failures.is_empty(),
        "{} differences:\n{}",
        failures.len(),
        failures.join("\n")
    );
    eprintln!("{} answers as Node gives them", checked);
}

#[tokio::test]
async fn the_ambient_realm_follows_the_task() {
    assert_eq!(realm::current_id(), "default");
    let mut r = Realm::default_realm();
    r.id = "acme".to_string();
    let inside = realm::run(Arc::new(r), async {
        tokio::task::yield_now().await;
        realm::current_id()
    })
    .await;
    assert_eq!(inside, "acme");
    assert_eq!(realm::current_id(), "default");
}
