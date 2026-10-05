// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The writer against every policy document of the OASIS suite: read, write,
//! read again, and the two models are EQUAL (bar the XPath bindings the
//! writer narrows on purpose) — the property the Node writer
//! is held to (`tests/xacml_service.js`: a document through the reader and
//! back decides identically), asserted on the model, which is stronger. And
//! writing is a fixed point: the second document is the first, byte for
//! byte.

use std::fs;
use std::path::{Path, PathBuf};

use sts_xacml::xml::{parse_policy_unchecked, write_policy};

fn documents(directory: &Path, into: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            documents(&path, into);
        } else if path.extension().and_then(|e| e.to_str()) == Some("xml")
            && path.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                !n.starts_with("Request") && !n.starts_with("Response")
            })
        {
            into.push(path);
        }
    }
}

#[test]
fn every_suite_policy_survives_the_round_trip() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../xacml/conformance");
    let mut paths = Vec::new();
    documents(&root, &mut paths);
    paths.sort();
    let mut checked = 0;
    for path in &paths {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        // A document the reader refuses (the cases whose policy is meant to
        // be invalid, and anything that is not a policy) has nothing to
        // write.
        let Ok(first) = parse_policy_unchecked(&text) else {
            continue;
        };
        let written = write_policy(&first);
        let second = parse_policy_unchecked(&written).unwrap_or_else(|e| {
            panic!(
                "{}: the written document does not read: {:?}\n{}",
                path.display(),
                e,
                written
            )
        });
        // An XPath's captured bindings are narrowed to the prefixes it uses
        // (the writer's rule), so for those documents the models differ by
        // exactly that and the fixed point below is the check: the writer
        // writes every other field, so equal documents are equal models.
        if !written.contains("xpathExpression")
            && !written.contains("<AttributeSelector")
        {
            assert_eq!(first, second, "{}: the model changed", path.display());
        }
        assert_eq!(
            written,
            write_policy(&second),
            "{}: writing is not a fixed point",
            path.display()
        );
        checked += 1;
    }
    assert!(checked > 400, "only {} policies were checked", checked);
}
