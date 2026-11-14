// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Canonical XML against Node, byte for byte: every element of every
//! document `tests/tools/crypto-vectors.js` wrote into `c14n-node.json`, in
//! the four forms (exclusive and inclusive, each with and without comments)
//! `common/crypto_impl/xmldsig.js` computes.
//!
//! The corpus is the hand-written edge cases in that script and, when it ran
//! with `STS_C14N_CORPUS`, every XML file of a directory — the repository's
//! own 1461 (the OASIS XACML suite, mostly) is what it has been run over;
//! the W3C interop corpus is the one to add where the network allows it.
//!
//! The directory is `STS_CRYPTO_VECTORS`; with it unset this test says so
//! and passes.
//!
//! **A DOCUMENT NODE REFUSES IS REFUSED HERE, AND THE OTHER WAY ROUND.**
//! Until 2026-11-10 Node's xmldom accepted a DOCTYPE and this DOM did not,
//! the one difference this test allowed. Node's `common/xml_parser.js` now
//! refuses a `<!DOCTYPE` or `<!ENTITY` anywhere in the text, and
//! `sts_xml::dom::declaration_in()` is the same test, so a declaration's
//! refusal is required to be Node's in its words too.

#![allow(clippy::unwrap_used)] // a test file

use serde_json::Value as Json;
use sts_xml::c14n::{exclusive, inclusive, Options};
use sts_xml::dom::Document;

#[test]
fn every_node_canonical_form_is_reproduced() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: c14n-node.json is not checked"
        );
        return;
    };
    let path = std::path::Path::new(&dir).join("c14n-node.json");
    let text = std::fs::read_to_string(path).unwrap();
    let cases: Vec<Json> = serde_json::from_str(&text).unwrap();
    let plain = Options::default();
    let comments = Options {
        comments: true,
        ..Options::default()
    };
    let (mut checked, mut failures) = (0usize, Vec::new());
    for case in &cases {
        let name = case["name"].as_str().unwrap();
        let xml = case["xml"].as_str().unwrap();
        let parsed = Document::parse(xml);
        if let Some(refusal) = case.get("refused").and_then(Json::as_str) {
            match &parsed {
                Ok(_) => failures
                    .push(format!("{}: Node refused it, this accepted", name)),
                // A declaration's words are xml_parser.js's, and are
                // compared; any other refusal's are the parser's own.
                Err(e) if refusal.contains("> declaration, which") => {
                    checked += 1;
                    if !refusal.ends_with(&format!("XML: {}", e)) {
                        failures.push(format!(
                            "{}: refused in other words:\n node: {}\n \
                             rust: {}",
                            name, refusal, e
                        ));
                    }
                }
                Err(_) => checked += 1,
            }
            continue;
        }
        let doc = match parsed {
            Ok(doc) => doc,
            Err(e) => {
                failures.push(format!(
                    "{}: Node parsed it, this refused: {}",
                    name, e
                ));
                continue;
            }
        };
        if let Some(want) = case["serialized"].as_str() {
            checked += 1;
            let got = doc.serialize();
            if got != want {
                failures.push(format!(
                    "{}: serialized differently: {}",
                    name,
                    first_difference(want, &got)
                ));
            }
        }
        let root = doc.document_element().unwrap();
        let elements = doc.descendants(root);
        let forms = case["forms"].as_array().unwrap();
        if elements.len() != forms.len() {
            failures.push(format!(
                "{}: {} elements here, {} in Node",
                name,
                elements.len(),
                forms.len()
            ));
            continue;
        }
        for (i, (&el, want)) in elements.iter().zip(forms).enumerate() {
            let got = [
                exclusive(&doc, el, &plain),
                exclusive(&doc, el, &comments),
                inclusive(&doc, el, &plain),
                inclusive(&doc, el, &comments),
            ];
            for (f, g) in got.iter().enumerate() {
                checked += 1;
                let w = want[f].as_str().unwrap();
                if g != w {
                    failures.push(format!(
                        "{} element {} form {}:\n node: {}\n rust: {}",
                        name, i, f, w, g
                    ));
                }
            }
        }
    }
    if !failures.is_empty() {
        let shown: Vec<_> = failures.iter().take(8).cloned().collect();
        panic!("{} differences:\n{}", failures.len(), shown.join("\n"));
    }
    eprintln!(
        "{} canonical forms and serializations identical to Node's",
        checked
    );
}

/// Where two strings part, with a little of each around it.
fn first_difference(node: &str, rust: &str) -> String {
    let at = node
        .char_indices()
        .zip(rust.chars())
        .find(|((_, a), b)| a != b)
        .map(|((i, _), _)| i)
        .unwrap_or(node.len().min(rust.len()));
    let from = node[..at]
        .char_indices()
        .rev()
        .nth(40)
        .map_or(0, |(i, _)| i);
    let clip = |s: &str| {
        s.get(from..)
            .unwrap_or("")
            .chars()
            .take(100)
            .collect::<String>()
    };
    format!(
        "at byte {}\n node: {:?}\n rust: {:?}",
        at,
        clip(node),
        clip(rust)
    )
}
