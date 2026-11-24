// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE EMBEDDED PEP CORPUS (#2024), written by this engine and held to it.
//!
//! Every language's embedded PEP package (`iya-pep-<lang>`, #1206) carries a
//! lightweight engine of its own, and this crate stays the reference. Those
//! packages cannot read a Rust test, so the cases they are held to are DATA:
//! `xacml/pep-corpus/`, one JSON file per case, each with the policies as
//! the policy pull would send them, the request as attributes by category
//! (a package builds its request in code and reads no request XML), the
//! instant the `current-*` attributes come from, and the answer THIS engine
//! gives. `xacml/pep-corpus/README.md` is the format and the comparison
//! rules; `MANIFEST.json` is the version a package pins.
//!
//! This test is both halves of `common/error_codes.js --docs`:
//!
//! * by default it REGENERATES the corpus in memory and fails when a
//!   committed file differs, is missing, or is left over;
//! * with `STS_PEP_CORPUS_WRITE=1` it writes the files instead.
//!
//! The version in `MANIFEST.json` moves by one whenever the cases' digest
//! does, so a package that pinned a version can tell that it is stale. A
//! regeneration that changes nothing keeps the version.
//!
//! The source is the OASIS suite `tests/conformance.rs` already runs, read
//! the same way. A case is in the corpus only if, at the corpus's fixed
//! instant, this engine gives the decision and the obligations the suite's
//! own Response.xml expects — so the corpus can never encode an answer the
//! standard disagrees with. The cases left out are listed, with the reason,
//! in the manifest.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use sts_xacml::pdp::{EvaluationOptions, Pdp, Repository};
use sts_xacml::policy::PolicyNode;
use sts_xacml::request::{Request, ResolvedObligation};
use sts_xacml::xml;

/// The corpus's own format. A change to the SHAPE of a case file (not to
/// its cases) moves this, and a package's reader says which it reads.
const FORMAT: u64 = 1;

/// 2026-01-01T00:00:00Z: the instant every case is decided at. Fixed, so a
/// regeneration is reproducible and a package can inject the same `now`.
const NOW_UNIX: u64 = 1_767_225_600;
const NOW_TEXT: &str = "2026-01-01T00:00:00Z";

/// `tests/conformance.rs`'s, with its reason in
/// `xacml/conformance/MANIFEST.js`.
const EXPECTED_FAILURES: &[&str] = &["IIE003"];

const WRITE_ENV: &str = "STS_PEP_CORPUS_WRITE";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn suite_root() -> PathBuf {
    repo_root().join("xacml/conformance/mandatory")
}

fn corpus_root() -> PathBuf {
    repo_root().join("xacml/pep-corpus")
}

fn read(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", path.display(), e))
}

/// A policy document as the pull's `PolicyRow` carries it, less the
/// members only the console reads.
fn policy_row(document: &str, is_root: bool) -> Result<Value, String> {
    let node = xml::parse_policy(document)
        .map_err(|e| format!("a policy could not be loaded: {}", e))?;
    let (kind, version) = match &node {
        PolicyNode::Policy(p) => ("Policy", p.version.clone()),
        PolicyNode::PolicySet(s) => ("PolicySet", s.version.clone()),
        _ => return Err("a document is a bare reference".into()),
    };
    Ok(json!({
        "policyId": node.id(),
        "kind": kind,
        "version": version,
        "isRoot": is_root,
        "document": document,
    }))
}

fn request_json(request: &Request) -> Value {
    let categories: Vec<Value> = request
        .categories
        .iter()
        .map(|c| {
            let attributes: Vec<Value> = c
                .attributes
                .iter()
                .map(|a| {
                    let mut out = Map::new();
                    out.insert("attributeId".into(), json!(a.attribute_id));
                    if let Some(issuer) = &a.issuer {
                        out.insert("issuer".into(), json!(issuer));
                    }
                    out.insert(
                        "includeInResult".into(),
                        json!(a.include_in_result),
                    );
                    let values: Vec<Value> = a
                        .values
                        .iter()
                        .map(|v| {
                            json!({"dataType": v.type_uri, "value": v.lexical})
                        })
                        .collect();
                    out.insert("values".into(), Value::Array(values));
                    Value::Object(out)
                })
                .collect();
            let mut out = Map::new();
            out.insert("category".into(), json!(c.category));
            if let Some(id) = &c.id {
                out.insert("id".into(), json!(id));
            }
            out.insert("hasContent".into(), json!(c.has_content));
            out.insert("attributes".into(), Value::Array(attributes));
            Value::Object(out)
        })
        .collect();
    json!({
        "returnPolicyIdList": request.return_policy_id_list,
        "combinedDecision": request.combined_decision,
        "categories": categories,
    })
}

fn obligations_json(list: &[ResolvedObligation]) -> Value {
    Value::Array(
        list.iter()
            .map(|o| {
                let assignments: Vec<Value> = o
                    .assignments
                    .iter()
                    .map(|a| {
                        let mut out = Map::new();
                        out.insert("attributeId".into(), json!(a.attribute_id));
                        if let Some(category) = &a.category {
                            out.insert("category".into(), json!(category));
                        }
                        if let Some(issuer) = &a.issuer {
                            out.insert("issuer".into(), json!(issuer));
                        }
                        out.insert("dataType".into(), json!(a.type_uri));
                        out.insert("value".into(), json!(a.lexical));
                        Value::Object(out)
                    })
                    .collect();
                json!({"id": o.id, "assignments": assignments})
            })
            .collect(),
    )
}

/// What one OASIS case directory becomes: a case, or the reason it is not.
enum Outcome {
    Case(Value),
    Excluded(String),
}

fn build_case(directory: &Path, name: &str) -> Outcome {
    let has = |f: &str| directory.join(f).exists();
    // First: IIE003's files are marked `.ignore` too, and its reason is not
    // the invalid policy the next test would name.
    if EXPECTED_FAILURES.contains(&name) {
        return Outcome::Excluded(
            "a recorded failure of the reference engine \
             (xacml/conformance/MANIFEST.js): no answer to hold a package to"
                .into(),
        );
    }
    if has("Request.xml.ignore") && has("Response.xml.ignore") {
        return Outcome::Excluded(
            "the policy is invalid and must be refused: static validation \
             is the service's, at deploy, and a PEP is only ever sent \
             policies that passed it"
                .into(),
        );
    }
    if has("Policy.xml.ignore") && has("Response.xml.ignore") {
        return Outcome::Excluded(
            "the request XML is invalid and must be refused: a PEP builds \
             its request in code and reads no request XML"
                .into(),
        );
    }
    match decide(directory) {
        Ok(case) => Outcome::Case(case),
        Err(why) => panic!("{}: {}", name, why),
    }
}

fn decide(directory: &Path) -> Result<Value, String> {
    // The three IIE cases put Policy.xml INSIDE Policies/, beside the
    // documents it references.
    let root_path = if directory.join("Policy.xml").exists() {
        directory.join("Policy.xml")
    } else {
        directory.join("Policies/Policy.xml")
    };
    let root_text = read(&root_path);
    let mut rows = vec![policy_row(&root_text, true)?];

    let mut repository: Repository = HashMap::new();
    let mut others: BTreeMap<String, String> = BTreeMap::new();
    let policies_dir = directory.join("Policies");
    if policies_dir.is_dir() {
        let entries = fs::read_dir(&policies_dir).map_err(|e| e.to_string())?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("xml") {
                continue;
            }
            let text = read(&path);
            let Ok(node) = xml::parse_policy(&text) else {
                // `tests/conformance.rs` skips it too; the case then fails
                // on its unresolvable reference, and the assertion below
                // says so.
                continue;
            };
            let id = node.id().to_string();
            repository.insert(id.clone(), node);
            if path != root_path {
                others.insert(id, text);
            }
        }
    }
    for text in others.values() {
        rows.push(policy_row(text, false)?);
    }

    let policy = xml::parse_policy(&root_text).map_err(|e| e.to_string())?;
    let request = xml::parse_request(&read(&directory.join("Request.xml")))
        .map_err(|e| format!("request: {}", e))?;
    let expected = xml::parse_response(&read(&directory.join("Response.xml")))
        .map_err(|e| format!("response: {}", e))?;
    let options = EvaluationOptions {
        repository: (!repository.is_empty()).then_some(&repository),
        now: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(NOW_UNIX)),
        ..EvaluationOptions::default()
    };
    let actual = Pdp::new().evaluate(&policy, &request, &options);

    // The corpus never encodes an answer the standard disagrees with.
    let wanted = expected
        .results
        .first()
        .ok_or("the expected Response holds no Result")?;
    if Some(actual.decision) != wanted.decision {
        return Err(format!(
            "at {} the engine says {}, the suite {}",
            NOW_TEXT, actual.decision, wanted.decision_text
        ));
    }
    let mut want_ids = wanted.obligation_ids.clone();
    let mut got_ids: Vec<String> =
        actual.obligations.iter().map(|o| o.id.clone()).collect();
    want_ids.sort();
    got_ids.sort();
    if want_ids != got_ids {
        return Err(format!(
            "obligations differ from the suite's: [{}] against [{}]",
            got_ids.join(", "),
            want_ids.join(", ")
        ));
    }

    Ok(json!({
        "policies": rows,
        "request": request_json(&request),
        "expected": {
            "decision": actual.decision.to_string(),
            "obligations": obligations_json(&actual.obligations),
            "advice": obligations_json(&actual.advice),
        },
    }))
}

fn pretty(value: &Value) -> String {
    let mut text = serde_json::to_string_pretty(value)
        .unwrap_or_else(|e| panic!("cannot serialise: {}", e));
    text.push('\n');
    text
}

/// Every file the corpus should hold, by path relative to its root.
fn generate() -> BTreeMap<String, String> {
    let mut directories: Vec<PathBuf> = fs::read_dir(suite_root())
        .unwrap_or_else(|e| panic!("cannot read the suite: {}", e))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    directories.sort();

    let mut files = BTreeMap::new();
    let mut excluded = Map::new();
    let mut hasher = Sha256::new();
    for directory in &directories {
        let name = directory
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        match build_case(directory, &name) {
            Outcome::Case(mut case) => {
                if let Value::Object(map) = &mut case {
                    let mut ordered = Map::new();
                    ordered.insert("name".into(), json!(name));
                    ordered.insert("source".into(), json!("oasis-mandatory"));
                    ordered.append(map);
                    case = Value::Object(ordered);
                }
                let text = pretty(&case);
                hasher.update(name.as_bytes());
                hasher.update(text.as_bytes());
                files.insert(format!("oasis/{}.json", name), text);
            }
            Outcome::Excluded(why) => {
                excluded.insert(name, json!(why));
            }
        }
    }

    // The bias and obligation rule both PEPs are held to, carried as it is:
    // it is a table of section 7.2, not engine cases.
    let enforcement =
        read(&repo_root().join("xacml-pep/enforcement_cases.json"));
    hasher.update(b"enforcement.json");
    hasher.update(enforcement.as_bytes());
    files.insert("enforcement.json".into(), enforcement);

    let digest: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    let cases = files.keys().filter(|k| k.starts_with("oasis/")).count();
    let previous: Option<Value> =
        fs::read_to_string(corpus_root().join("MANIFEST.json"))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok());
    let version = match &previous {
        Some(p) if p["sha256"] == json!(digest) => p["version"].clone(),
        Some(p) => json!(p["version"].as_u64().unwrap_or(0) + 1),
        None => json!(1),
    };
    let manifest = json!({
        "what": "The cases every embedded PEP package's engine is held to \
                 (iya-sts #1206, #2024). Written by \
                 rust/crates/sts-xacml/tests/pep_corpus.rs from the engine \
                 the service runs; never edited by hand. README.md is the \
                 format and the comparison rules.",
        "format": FORMAT,
        "version": version,
        "sha256": digest,
        "now": NOW_TEXT,
        "cases": {"oasis": cases, "enforcement": 1},
        "sources": {
            "oasis": "xacml/conformance/mandatory (Apache-2.0; \
                      xacml/conformance/PROVENANCE.md)",
            "enforcement": "xacml-pep/enforcement_cases.json",
        },
        "excluded": excluded,
    });
    files.insert("MANIFEST.json".into(), pretty(&manifest));
    files
}

/// What is under the corpus root now, by relative path (README.md aside:
/// it is written by hand).
fn on_disk() -> BTreeMap<String, String> {
    let mut found = BTreeMap::new();
    let root = corpus_root();
    for top in ["MANIFEST.json", "enforcement.json"] {
        if let Ok(text) = fs::read_to_string(root.join(top)) {
            found.insert(top.to_string(), text);
        }
    }
    if let Ok(entries) = fs::read_dir(root.join("oasis")) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let (Some(name), Ok(text)) =
                (path.file_name(), fs::read_to_string(&path))
            {
                found.insert(format!("oasis/{}", name.to_string_lossy()), text);
            }
        }
    }
    found
}

#[test]
fn the_committed_corpus_is_what_this_engine_answers() {
    let wanted = generate();
    let present = on_disk();

    if std::env::var(WRITE_ENV).as_deref() == Ok("1") {
        let root = corpus_root();
        for stale in present.keys().filter(|k| !wanted.contains_key(*k)) {
            fs::remove_file(root.join(stale))
                .unwrap_or_else(|e| panic!("cannot remove {}: {}", stale, e));
        }
        for (path, text) in &wanted {
            let target = root.join(path);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).unwrap_or_else(|e| {
                    panic!("cannot create {}: {}", parent.display(), e)
                });
            }
            fs::write(&target, text).unwrap_or_else(|e| {
                panic!("cannot write {}: {}", target.display(), e)
            });
        }
        println!("wrote {} corpus files", wanted.len());
        return;
    }

    let mut problems = Vec::new();
    for (path, text) in &wanted {
        match present.get(path) {
            None => problems.push(format!("missing: {}", path)),
            Some(found) if found != text => {
                problems.push(format!("differs: {}", path))
            }
            Some(_) => {}
        }
    }
    for path in present.keys().filter(|k| !wanted.contains_key(*k)) {
        problems.push(format!("left over: {}", path));
    }
    assert!(
        problems.is_empty(),
        "xacml/pep-corpus is not what the engine answers ({} file(s)); \
         regenerate with {}=1 cargo test -p sts-xacml --test pep_corpus:\n{}",
        problems.len(),
        WRITE_ENV,
        problems.join("\n")
    );
}
