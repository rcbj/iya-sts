// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! EVERY EXAMPLE IN THE FIVE DOCUMENTS READS AS ITS GENERATED TYPE (#444,
//! D15).
//!
//! The documents' examples are what the Node service answers and accepts
//! (`tests/openapi_response_models.js` holds them to the closed models), so
//! a generated type that cannot read one is a wrong type: a member made
//! required that may be absent, a union missing a kind, a closed struct
//! missing a member. The documents are generated only in an image build, so
//! this reads them from `STS_MODEL_DIR` (a copy of `models/generated/`) and
//! passes with a note when it is unset, as the vector tests do.

use serde_json::Value;
use std::path::Path;

type Reader = fn(&str, &Value) -> Option<Result<(), serde_json::Error>>;
type AnswerReader =
    fn(&str, u16, &Value) -> Option<Result<(), serde_json::Error>>;

/// The examples a media type carries: `example`, and each `examples` value.
fn examples_of(media: &Value) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    if let Some(one) = media.get("example") {
        out.push(("example".to_string(), one.clone()));
    }
    if let Some(map) = media.get("examples").and_then(Value::as_object) {
        for (name, one) in map {
            if let Some(value) = one.get("value") {
                out.push((name.clone(), value.clone()));
            }
        }
    }
    out
}

fn check(
    dir: &Path,
    name: &str,
    read_body: Reader,
    read_answer: AnswerReader,
    failures: &mut Vec<String>,
) -> usize {
    let path = dir.join(format!("openapi.{}.json", name));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {}", path.display(), e));
    let document: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("{}: {}", path.display(), e));
    let mut checked = 0;
    let paths = document["paths"].as_object().cloned().unwrap_or_default();
    for (route, methods) in &paths {
        let Some(methods) = methods.as_object() else {
            continue;
        };
        for (method, operation) in methods {
            let Some(id) = operation["operationId"].as_str() else {
                continue;
            };
            let body = &operation["requestBody"]["content"]["application/json"];
            for (label, value) in examples_of(body) {
                checked += 1;
                match read_body(id, &value) {
                    Some(Ok(())) => {}
                    Some(Err(e)) => failures.push(format!(
                        "{} {} {} body {}: {}",
                        name, method, route, label, e
                    )),
                    None => failures.push(format!(
                        "{} {}: a body example and no body type",
                        name, id
                    )),
                }
            }
            let answers = operation["responses"]
                .as_object()
                .cloned()
                .unwrap_or_default();
            for (status, answer) in &answers {
                let Ok(code) = status.parse::<u16>() else {
                    continue;
                };
                if !(200..300).contains(&code) {
                    continue;
                }
                let media = &answer["content"]["application/json"];
                for (label, value) in examples_of(media) {
                    checked += 1;
                    match read_answer(id, code, &value) {
                        Some(Ok(())) => {}
                        Some(Err(e)) => failures.push(format!(
                            "{} {} {} {} {}: {}",
                            name, method, route, status, label, e
                        )),
                        None => failures.push(format!(
                            "{} {} {}: an example and no answer type",
                            name, id, status
                        )),
                    }
                }
            }
        }
    }
    checked
}

#[test]
fn every_example_reads_as_its_type() {
    let Ok(dir) = std::env::var("STS_MODEL_DIR") else {
        eprintln!("STS_MODEL_DIR is unset: no documents to read");
        return;
    };
    let dir = Path::new(&dir);
    let mut failures = Vec::new();
    let mut checked = 0;
    use sts_model::api;
    checked += check(
        dir,
        "management",
        api::management::read_body,
        api::management::read_answer,
        &mut failures,
    );
    checked += check(
        dir,
        "console",
        api::console::read_body,
        api::console::read_answer,
        &mut failures,
    );
    checked += check(
        dir,
        "account",
        api::account::read_body,
        api::account::read_answer,
        &mut failures,
    );
    checked += check(
        dir,
        "authn",
        api::authn::read_body,
        api::authn::read_answer,
        &mut failures,
    );
    checked += check(
        dir,
        "report",
        api::report::read_body,
        api::report::read_answer,
        &mut failures,
    );
    eprintln!("{} examples read, {} failed", checked, failures.len());
    for one in failures.iter().take(40) {
        eprintln!("  {}", one);
    }
    assert!(checked > 0, "the documents carry no examples");
    assert!(failures.is_empty(), "{} examples failed", failures.len());
}
