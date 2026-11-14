// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The pure half of the one validation door (#1360, #1368) against Node,
//! from the sections of `x509-node.json` that `tests/tools/crypto-vectors.js`
//! writes for it:
//!
//! * `fields`: for every certificate Node issued, `crypto.js` section 18's
//!   `certificateFacts()`, `certificateFieldProblems()` under thirteen
//!   option sets (check, code and sentence, every one in order), and
//!   `certificateNameMatches()` under twenty-eight expectations;
//! * `paths`: `verifyPathToAnchors()` under ten accept lists
//!   (`pki.acceptedSignatureAlgorithms`) and five leaf rules (`opts.leaf`);
//! * `anchors`: a truststore's admission rule, both doors;
//! * `registry`: the X.509 rows of the algorithm registry.
//!
//! The other way round: with `STS_WRITE_VECTORS` set, every certificate
//! Rust issues from the same specs goes to `x509-door-rust.json` with its
//! facts and field problems, and `tests/rust_crypto_vectors.js` asks Node
//! for the same of each.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed; with it unset
//! this test says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value as Json};
use sts_pki::fields::{self, EkuRule, ExpectedNames, FieldOptions};
use sts_pki::path::accept::{self, X509_ROWS};
use sts_pki::path::anchors::{
    anchor_problem, anchor_problem_sync, AnchorOptions, AnchorProblem,
    CertificateInput,
};
use sts_pki::path::{self, Entry, PathOptions};

fn b64(v: &Json) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}

fn strings(v: &Json) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|s| s.as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// A Node option set as `FieldOptions`.
pub fn field_options(o: &Json, now: i64) -> FieldOptions {
    FieldOptions {
        role: o["role"].as_str().map(str::to_string),
        now_ms: Some(o["now"].as_i64().unwrap_or(now)),
        skew_ms: o["skewMs"].as_i64().unwrap_or(0),
        key_usage: strings(&o["keyUsage"]),
        eku: o.get("eku").filter(|e| e.is_object()).map(|e| EkuRule {
            oids: strings(&e["oids"]),
            required: e["required"].as_bool().unwrap_or(false),
        }),
        may_be_ca: o["mayBeCa"].as_bool().unwrap_or(false),
        allow_sha1: o["allowSha1"].as_bool().unwrap_or(false),
        allow_critical: strings(&o["allowCritical"]),
        validity_at_ms: o["validityAt"].as_i64(),
    }
}

fn problems_json(der: &[u8], options: &FieldOptions) -> Json {
    match fields::certificate_field_problems(der, options) {
        Ok(list) => json!(list
            .iter()
            .map(|p| json!({ "check": p.check, "code": p.code.as_str(),
                             "why": p.why }))
            .collect::<Vec<_>>()),
        Err(e) => json!({ "error": e }),
    }
}

fn anchor_json(p: Option<AnchorProblem>) -> Json {
    match p {
        None => Json::Null,
        Some(p) => json!({ "code": p.code.as_str(), "role": p.role,
                           "why": p.why }),
    }
}

#[test]
fn the_door_matches_node() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: x509-node.json is not checked"
        );
        return;
    };
    let v: Json = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(&dir).join("x509-node.json"),
        )
        .unwrap(),
    )
    .unwrap();
    if v.get("fields").is_none() {
        eprintln!("x509-node.json predates #1360's sections: not checked");
        return;
    }
    let mut failures = Vec::new();
    let mut checked = 0;
    let mut check = |ok: bool, what: String| {
        checked += 1;
        if !ok {
            failures.push(what);
        }
    };

    // The registry's X.509 rows.
    let mine: Vec<Json> = X509_ROWS
        .iter()
        .map(|r| {
            json!({ "id": r.id, "oid": r.oid, "hash": r.hash,
                         "x509": r.x509 })
        })
        .collect();
    check(
        json!(mine) == v["registry"],
        format!("the X.509 rows of the registry:\n{:?}", v["registry"]),
    );

    // Section 18.
    let f = &v["fields"];
    let now = f["now"].as_i64().unwrap();
    let certificates: std::collections::HashMap<String, Vec<u8>> = v
        ["certificates"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["der"].is_string())
        .map(|c| (c["name"].as_str().unwrap().to_string(), b64(&c["der"])))
        .collect();
    for row in f["certificates"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let der = &certificates[name];
        let facts = fields::certificate_facts(der)
            .map(|x| serde_json::to_value(x).unwrap())
            .unwrap_or_else(|e| json!({ "error": e }));
        check(
            facts == row["facts"],
            format!(
                "{}: certificateFacts():\n  rust {}\n  node {}",
                name, facts, row["facts"]
            ),
        );
        for (i, o) in f["options"].as_array().unwrap().iter().enumerate() {
            let mine = problems_json(der, &field_options(o, now));
            check(
                mine == row["problems"][i],
                format!(
                    "{}: certificateFieldProblems({}):\n  rust {}\n  node {}",
                    name, o, mine, row["problems"][i]
                ),
            );
        }
        for (i, n) in f["names"].as_array().unwrap().iter().enumerate() {
            let expected = ExpectedNames {
                dns: n["dns"].as_str().map(str::to_string),
                ip: n["ip"].as_str().map(str::to_string),
                uri: n["uri"].as_str().map(str::to_string),
                email: n["email"].as_str().map(str::to_string),
            };
            let mine = match fields::certificate_name_matches(der, &expected) {
                Ok(b) => json!(b),
                Err(e) => json!({ "error": e }),
            };
            check(
                mine == row["names"][i],
                format!(
                    "{}: certificateNameMatches({}): rust {}, node {}",
                    name, n, mine, row["names"][i]
                ),
            );
        }
    }

    // The two rules the path rules gained.
    let leaf_rules = [
        None,
        Some(json!({ "keyUsage": ["digitalSignature"],
                     "eku": { "oids": [fields::eku::SERVER_AUTH],
                              "required": true } })),
        Some(json!({ "keyUsage": ["digitalSignature"],
                     "eku": { "oids": [fields::eku::CLIENT_AUTH],
                              "required": true } })),
        Some(json!({ "keyUsage": ["keyCertSign"], "eku": null,
                     "mayBeCa": true })),
        Some(json!({ "keyUsage": ["cRLSign"], "eku": null })),
    ];
    for row in v["paths"].as_array().unwrap() {
        let anchors: Vec<Entry> = row["anchors"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|a| Entry::from_der(&b64(a)))
            .collect();
        let intermediates: Vec<Vec<u8>> = row["intermediates"]
            .as_array()
            .unwrap()
            .iter()
            .map(b64)
            .collect();
        let mut options = PathOptions {
            now_ms: row["now"].as_i64().unwrap(),
            ..PathOptions::default()
        };
        options.rules.allow_sha1 = row["allowSha1"].as_bool().unwrap();
        options.rules.accepted_signature_algorithms =
            accept::parse_list(row["accept"].as_str().unwrap());
        let r = row["leafRule"].as_u64().unwrap() as usize;
        options.rules.leaf = leaf_rules[r].as_ref().map(|o| {
            let mut opts = field_options(o, 0);
            // Node passes no `now` to the leaf's field check.
            opts.now_ms = None;
            opts
        });
        let a = path::verify_path_to_anchors(
            &b64(&row["leaf"]),
            &intermediates,
            &anchors,
            &options,
        );
        let mine = json!({ "ok": a.ok, "check": a.check, "reason": a.reason,
                           "chain": a.chain.len() });
        check(
            mine == row["verdict"],
            format!(
                "path {} accept={:?} leaf rule {} sha1={}:\n  rust {}\n  node {}",
                row["name"],
                row["accept"],
                r,
                row["allowSha1"],
                mine,
                row["verdict"]
            ),
        );
    }

    // A truststore's admission rule.
    for row in v["anchors"].as_array().unwrap() {
        let pem = row["pem"].as_str().unwrap();
        let held: Vec<String> = strings(&row["held"]);
        let opts = AnchorOptions {
            role: row["role"].as_str().filter(|r| !r.is_empty()),
            held_anchors: held
                .iter()
                .map(|p| CertificateInput::Pem(p.as_str()))
                .collect(),
            held_intermediates: Vec::new(),
            now_ms: row["now"].as_i64(),
        };
        let input = CertificateInput::Pem(pem);
        let a = anchor_json(anchor_problem(input, &opts));
        check(
            a == row["async"],
            format!(
                "anchorProblem({}, {}):\n  rust {}\n  node {}",
                row["name"], row["role"], a, row["async"]
            ),
        );
        let s = anchor_json(anchor_problem_sync(input, &opts));
        check(
            s == row["sync"],
            format!(
                "anchorProblemSync({}, {}):\n  rust {}\n  node {}",
                row["name"], row["role"], s, row["sync"]
            ),
        );
    }

    // Rust's own certificates, for Node to read back: the same specs
    // issued here, with what section 18 says of each.
    let mut written = Vec::new();
    for row in v["certificates"].as_array().unwrap() {
        if !row["der"].is_string() {
            continue;
        }
        let Ok(mine) = sts_pki::x509::issue_certificate(&row["spec"]) else {
            continue;
        };
        let facts = fields::certificate_facts(&mine.der)
            .map(|x| serde_json::to_value(x).unwrap())
            .unwrap_or_else(|e| json!({ "error": e }));
        let problems: Vec<Json> = f["options"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| problems_json(&mine.der, &field_options(o, now)))
            .collect();
        written.push(json!({ "name": row["name"], "pem": mine.pem,
                             "facts": facts, "problems": problems }));
    }
    if std::env::var("STS_WRITE_VECTORS").is_ok() {
        std::fs::write(
            std::path::Path::new(&dir).join("x509-door-rust.json"),
            serde_json::to_string_pretty(&json!({
                "now": now, "options": f["options"], "certificates": written
            }))
            .unwrap(),
        )
        .unwrap();
    }

    let shown: Vec<&String> = failures.iter().take(40).collect();
    assert!(
        failures.is_empty(),
        "{} of {} answers differ:\n{}",
        failures.len(),
        checked,
        shown
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );
    eprintln!("{} answers as Node gives them", checked);
}
