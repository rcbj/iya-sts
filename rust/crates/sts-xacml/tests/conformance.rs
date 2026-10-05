// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The OASIS XACML 3.0 conformance suite against this engine — the same 455
//! mandatory cases, read the same way, and compared on the same two things
//! as `tests/xacml_conformance.js` holds the Node engine to:
//!
//! * THE DECISION, always;
//! * THE OBLIGATIONS, by identifier and count (the IIIA cases exist for
//!   nothing else).
//!
//! Not the status code, which the specification lets PDPs choose between,
//! and not the XML serialisation.
//!
//! The suite is read in place from `xacml/conformance/`, which is vendored,
//! Apache-2.0, and never edited here. `EXPECTED_FAILURES` mirrors the one in
//! `xacml/conformance/MANIFEST.js`, with its reason there; it is asserted in
//! BOTH directions, because a recorded failure that starts passing is drift
//! too.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use sts_xacml::pdp::{EvaluationOptions, Pdp, Repository};
use sts_xacml::xml;

/// The cases `xacml/conformance/MANIFEST.js` records as expected failures.
const EXPECTED_FAILURES: &[&str] = &["IIE003"];

/// The mandatory case count, `MANIFEST.js`'s denominator. A suite that has
/// quietly lost half its cases still reports a percentage.
const MANDATORY_CASES: usize = 455;

fn suite_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../xacml/conformance/mandatory")
}

struct Case {
    name: String,
    policy: Option<String>,
    request: Option<String>,
    response: Option<String>,
    expects_policy_rejected: bool,
    expects_request_rejected: bool,
    repository_dir: Option<PathBuf>,
}

fn read_case(directory: &Path) -> Case {
    let has = |name: &str| directory.join(name).exists();
    let read = |path: PathBuf| fs::read_to_string(path).ok();
    // The three IIE cases put Policy.xml INSIDE Policies/, beside the
    // documents it references.
    let policy = if has("Policy.xml") {
        read(directory.join("Policy.xml"))
    } else if directory.join("Policies/Policy.xml").exists() {
        read(directory.join("Policies/Policy.xml"))
    } else {
        None
    };
    Case {
        name: directory
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        policy,
        request: read(directory.join("Request.xml")),
        response: read(directory.join("Response.xml")),
        expects_policy_rejected: has("Request.xml.ignore")
            && has("Response.xml.ignore"),
        expects_request_rejected: has("Policy.xml.ignore")
            && has("Response.xml.ignore"),
        repository_dir: has("Policies").then(|| directory.join("Policies")),
    }
}

/// The referenced documents, keyed by the PolicyId INSIDE each, not the
/// file name.
fn read_repository(directory: &Path) -> Repository {
    let mut repository = HashMap::new();
    let Ok(entries) = fs::read_dir(directory) else {
        return repository;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("xml") {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        // A malformed document is not this case's assertion: the case will
        // fail on its unresolvable reference and say so.
        if let Ok(parsed) = xml::parse_policy(&text) {
            repository.insert(parsed.id().to_string(), parsed);
        }
    }
    repository
}

/// `Ok` with a note, or `Err` with why.
fn run_case(case: &Case) -> Result<String, String> {
    if case.expects_policy_rejected {
        return match xml::parse_policy(case.policy.as_deref().unwrap_or("")) {
            Ok(_) => Err("the policy is invalid and was accepted".into()),
            Err(_) => Ok("the invalid policy was refused".into()),
        };
    }
    if case.expects_request_rejected {
        return match xml::parse_request(case.request.as_deref().unwrap_or("")) {
            Ok(_) => Err("the request is invalid and was accepted".into()),
            Err(_) => Ok("the invalid request was refused".into()),
        };
    }
    let (Some(policy), Some(request), Some(response)) =
        (&case.policy, &case.request, &case.response)
    else {
        return Err("the case is missing one of its three files".into());
    };
    let loaded = xml::parse_policy(policy).and_then(|p| {
        Ok((
            p,
            xml::parse_request(request)?,
            xml::parse_response(response)?,
        ))
    });
    let (policy, request, expected) =
        loaded.map_err(|e| format!("could not be loaded: {}", e))?;
    let repository = case.repository_dir.as_deref().map(read_repository);
    let options = EvaluationOptions {
        repository: repository.as_ref(),
        ..EvaluationOptions::default()
    };
    let actual = Pdp::new().evaluate(&policy, &request, &options);
    let wanted = expected
        .results
        .first()
        .ok_or("the expected Response holds no Result")?;
    if Some(actual.decision) != wanted.decision {
        return Err(format!(
            "expected {}, got {}{}",
            wanted.decision_text,
            actual.decision,
            actual
                .status
                .message
                .map(|m| format!(" ({})", m))
                .unwrap_or_default()
        ));
    }
    let mut expected_ids = wanted.obligation_ids.clone();
    let mut actual_ids: Vec<String> =
        actual.obligations.iter().map(|o| o.id.clone()).collect();
    expected_ids.sort();
    actual_ids.sort();
    if expected_ids != actual_ids {
        return Err(format!(
            "obligations differ: expected [{}], got [{}]",
            expected_ids.join(", "),
            actual_ids.join(", ")
        ));
    }
    Ok(actual.decision.to_string())
}

#[test]
fn every_mandatory_case_passes_bar_the_recorded_exceptions() {
    let root = suite_root();
    let mut names: Vec<PathBuf> = fs::read_dir(&root)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", root.display(), e))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    names.sort();
    assert_eq!(names.len(), MANDATORY_CASES, "the vendored suite is intact");

    let mut failures = Vec::new();
    let mut stale_passes = Vec::new();
    let mut passed = 0;
    for directory in &names {
        let case = read_case(directory);
        let expected = EXPECTED_FAILURES.contains(&case.name.as_str());
        match run_case(&case) {
            Ok(_) => {
                passed += 1;
                if expected {
                    stale_passes.push(case.name.clone());
                }
            }
            Err(why) => {
                if !expected {
                    failures.push(format!("{}: {}", case.name, why));
                }
            }
        }
    }
    println!(
        "{} of {} mandatory cases pass, {} recorded in EXPECTED_FAILURES",
        passed,
        names.len(),
        EXPECTED_FAILURES.len()
    );
    assert!(
        failures.is_empty(),
        "{} unexpected failure(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(
        stale_passes.is_empty(),
        "cases in EXPECTED_FAILURES that now pass: {}",
        stale_passes.join(", ")
    );
}
