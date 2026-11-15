// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE INVENTED PERSON AND THE TYPED-ATTRIBUTE CHECK, HELD TO NODE (#444,
//! phase 5, the `apis5` slice).
//!
//! `tests/tools/people-vectors.js` records `vcClaims.personaFor(name)` for
//! names of every shape and `personEditor.checkCreateValues(name, values)`
//! for the values a create may carry (`people-node.json`); each is answered
//! here by `sts_registers::persona` and must be Node's, member for member.
//!
//! With `STS_WRITE_VECTORS=1` the test writes `people-rust.json` — Rust's
//! personas for names of its OWN choosing and its checks — which
//! `tests/rust_crypto_vectors.js` holds to Node (`checkRust()`).
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed; unset, the test
//! says so and passes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{json, Value};
use sts_registers::persona::{
    check_create_values, plain_identity_key, Persona,
};

fn vectors() -> Option<(std::path::PathBuf, Value)> {
    let dir = std::env::var("STS_CRYPTO_VECTORS").ok()?;
    let path = std::path::Path::new(&dir).join("people-node.json");
    let text = std::fs::read_to_string(&path).ok()?;
    Some((
        std::path::PathBuf::from(dir),
        serde_json::from_str(&text).ok()?,
    ))
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|l| {
            l.iter()
                .map(|x| x.as_str().unwrap_or("").to_string())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn a_persona_is_drawn_as_node_draws_it() {
    // Seeded by the name, so one name is one person: the same twice.
    assert_eq!(Persona::for_name("alice"), Persona::for_name("alice"));
    assert_ne!(Persona::for_name("alice"), Persona::for_name("bob"));
    assert_eq!(Persona::for_name("")["username"], json!("somebody"));
    assert_eq!(plain_identity_key(" ann@EXAMPLE.COM "), "ann");
    assert_eq!(plain_identity_key("uid=a,ou=users"), "uid=a,ou=users");
}

#[test]
fn the_funnel_draws_the_same_five_facts() {
    for name in ["alice", "bob", "e2e.ann", "MiXeD.Case", "ünïcode", ""] {
        let whole = Persona::for_name(&plain_identity_key(name));
        let five = sts_directory::funnel::persona_for(name, &|_| None);
        assert_eq!(whole["given"], json!(five.given), "{name}");
        assert_eq!(whole["family"], json!(five.family), "{name}");
        assert_eq!(whole["display"], json!(five.display), "{name}");
        assert_eq!(whole["email"], json!(five.email), "{name}");
    }
}

#[test]
fn people_match_node() {
    let Some((dir, v)) = vectors() else {
        eprintln!("STS_CRYPTO_VECTORS is not set: people-node.json skipped");
        return;
    };
    let mut bad = Vec::new();
    for one in v["personas"].as_array().unwrap() {
        let name = one["name"].as_str().unwrap();
        let rust = Persona::for_name(&plain_identity_key(name));
        if rust != one["persona"] {
            bad.push(format!(
                "persona for {name:?}: Rust {rust}, Node {}",
                one["persona"]
            ));
        }
    }
    for one in v["checks"].as_array().unwrap() {
        let name = one["name"].as_str().unwrap();
        let values = strings(&one["values"]);
        let rust = check_create_values(name, &values).unwrap_or(Value::Null);
        if rust != one["checked"] {
            bad.push(format!(
                "check of {name} {values:?}: Rust {rust}, Node {}",
                one["checked"]
            ));
        }
    }
    assert!(
        bad.is_empty(),
        "{} difference(s):\n{}",
        bad.len(),
        bad.join("\n")
    );
    if std::env::var("STS_WRITE_VECTORS").is_ok_and(|w| w == "1") {
        // Names Node's builder did not ask, so Node checks Rust's draw and
        // not its own echo.
        let names = [
            "dave",
            "erin",
            "frank.smith",
            "grace-7",
            "HEIDI",
            "ivan.ivanov.42",
            "judy",
            "mallory",
            "oscar",
            "peggy",
        ];
        let personas: Vec<Value> = names
            .iter()
            .map(|n| json!({ "name": n,
                             "persona": Persona::for_name(&plain_identity_key(n)) }))
            .collect();
        let checks: Vec<Value> = [
            ("c", vec!["DK"]),
            ("c", vec!["dk"]),
            ("schacDateOfBirth", vec!["2000-02-29"]),
            ("schacDateOfBirth", vec!["1900-02-29"]),
            ("mail", vec!["x@y.z"]),
            ("givenName", vec!["A", "B"]),
            ("labeledURI", vec!["http://example.org/ x"]),
        ]
        .iter()
        .map(|(name, values)| {
            let values: Vec<String> =
                values.iter().map(|s| s.to_string()).collect();
            json!({ "name": name, "values": values,
                    "checked": check_create_values(name, &values) })
        })
        .collect();
        std::fs::write(
            dir.join("people-rust.json"),
            serde_json::to_string_pretty(
                &json!({ "personas": personas, "checks": checks }),
            )
            .unwrap(),
        )
        .unwrap();
    }
}
