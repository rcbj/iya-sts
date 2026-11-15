// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE ROUTING ROWS AND THE MODEL CANNOT DRIFT, CHECKED AT BUILD TIME.
//!
//! The model's two documents (`src/generated/openapi.*.json`, written by
//! `tests/tools/regenerate-model-docs.sh`) are every operation `/admin-api`
//! has; `tables/admin_api.json` (written by
//! `tests/tools/export-admin-api-tables.js` from `mgmt-api/admin_api.ts`)
//! is what Node keeps in code about each — what it mirrors, its tag, its
//! console twin. Node builds one from the other, so they agree by
//! construction; here they are two files, so the build refuses an
//! operation one has and the other does not, or a row whose method, path
//! or kind the model says differently. The handler half of the same rule is
//! the exhaustive `match` in `src/routing.rs`.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;

fn main() -> Result<(), Box<dyn Error>> {
    for file in [
        "src/generated/openapi.management.json",
        "src/generated/openapi.console.json",
        "tables/admin_api.json",
    ] {
        println!("cargo:rerun-if-changed={}", file);
    }
    let mut model = BTreeSet::new();
    for (kind, file) in [
        ("management", "src/generated/openapi.management.json"),
        ("console", "src/generated/openapi.console.json"),
    ] {
        let doc: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(file)?)?;
        let paths = doc
            .get("paths")
            .and_then(|p| p.as_object())
            .ok_or_else(|| format!("{} has no paths", file))?;
        for (path, methods) in paths {
            for (method, op) in methods.as_object().into_iter().flatten() {
                let id = op
                    .get("operationId")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                model.insert(format!(
                    "{} {} {} {}",
                    id,
                    method.to_uppercase(),
                    path,
                    kind
                ));
            }
        }
    }
    let tables: serde_json::Value =
        serde_json::from_str(&fs::read_to_string("tables/admin_api.json")?)?;
    let mut rows = BTreeSet::new();
    for row in tables
        .get("rows")
        .and_then(|r| r.as_array())
        .ok_or("tables/admin_api.json has no rows")?
    {
        let text = |k: &str| {
            row.get(k)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string()
        };
        rows.insert(format!(
            "{} {} {} {}",
            text("operationId"),
            text("method"),
            text("path"),
            text("kind")
        ));
    }
    let only_model: Vec<_> = model.difference(&rows).collect();
    let only_rows: Vec<_> = rows.difference(&model).collect();
    if !only_model.is_empty() || !only_rows.is_empty() {
        return Err(format!(
            "the model and the routing rows disagree. In the model only: \
             {:?}. In tables/admin_api.json only: {:?}. Run \
             tests/tools/regenerate-model-docs.sh and \
             tests/tools/export-admin-api-tables.js from one checkout.",
            only_model, only_rows
        )
        .into());
    }
    Ok(())
}
