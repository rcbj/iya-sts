// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE ROUTING ROWS AND THE MODEL CANNOT DRIFT, CHECKED AT BUILD TIME
//! (sts-mgmt-api's rule, for `/authn-api`).
//!
//! The model's document (`src/generated/openapi.authn.json`, written by
//! `tests/tools/regenerate-model-docs.sh`) is every operation the API has;
//! `src/operations.rs` is what Node keeps in code about each. Node builds
//! one from the other (`authn_api.ts` reads the summary and what it
//! mirrors out of the document), so they agree by construction; here they
//! are two files, so the build refuses an operation one has and the other
//! does not, or a row whose method or path the model says differently.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;

/// The string literals of every `op(` call, in order: method, path, id.
fn rows(source: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let mut rest = source;
    while let Some(at) = rest.find("op(\n") {
        let declaration = rest[..at].ends_with("fn ");
        rest = &rest[at + 4..];
        if declaration {
            continue;
        }
        let mut strings = Vec::new();
        let mut cursor = rest;
        while strings.len() < 3 {
            let Some(open) = cursor.find('"') else {
                break;
            };
            let after = &cursor[open + 1..];
            let Some(close) = after.find('"') else {
                break;
            };
            strings.push(after[..close].to_string());
            cursor = &after[close + 1..];
        }
        if strings.len() == 3 {
            out.push((
                strings[0].clone(),
                strings[1].clone(),
                strings[2].clone(),
            ));
        }
    }
    // The one-line row (`op("GET", "/authn-api", ...)`).
    for line in source.lines() {
        let line = line.trim();
        if let Some(inner) = line.strip_prefix("op(\"") {
            let parts: Vec<&str> = inner.split('"').collect();
            if parts.len() >= 5 {
                out.push((
                    parts[0].to_string(),
                    parts[2].to_string(),
                    parts[4].to_string(),
                ));
            }
        }
    }
    out
}

fn main() -> Result<(), Box<dyn Error>> {
    let doc_file = "src/generated/openapi.authn.json";
    let rows_file = "src/operations.rs";
    println!("cargo:rerun-if-changed={}", doc_file);
    println!("cargo:rerun-if-changed={}", rows_file);
    let doc: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(doc_file)?)?;
    let mut model = BTreeSet::new();
    let paths = doc
        .get("paths")
        .and_then(|p| p.as_object())
        .ok_or("the authn document has no paths")?;
    for (path, methods) in paths {
        for (method, op) in methods.as_object().into_iter().flatten() {
            let id = op
                .get("operationId")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            model.insert(format!("{} {} {}", id, method.to_uppercase(), path));
        }
    }
    let mut routed = BTreeSet::new();
    for (method, path, id) in rows(&fs::read_to_string(rows_file)?) {
        let documented = path
            .split('/')
            .map(|p| match p.strip_prefix(':') {
                Some(name) => format!("{{{}}}", name),
                None => p.to_string(),
            })
            .collect::<Vec<_>>()
            .join("/");
        routed.insert(format!("{} {} {}", id, method, documented));
    }
    let only_model: Vec<_> = model.difference(&routed).collect();
    let only_rows: Vec<_> = routed.difference(&model).collect();
    if !only_model.is_empty() || !only_rows.is_empty() {
        return Err(format!(
            "the model and the routing rows disagree. In the model only: \
             {:?}. In src/operations.rs only: {:?}. Run \
             tests/tools/regenerate-model-docs.sh.",
            only_model, only_rows
        )
        .into());
    }
    Ok(())
}
