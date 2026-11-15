// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The `oauth7` slice against Node (D11), over `oauth7-node.json`
//! (`tests/tools/oauth7-vectors.js`): the identity funnel's fold
//! (`admin_stats.identityOf()`) and invented person (`personaFor()`), OIDC
//! Core 5.5's claims request as understood or refused
//! (`parseClaimsRequest()`, `verified_claims` among it), Identity
//! Assurance's `matches()` and `project()`, and RFC 9701's negotiation
//! (`wantsJwt()`) — each answered here as Node answered it.
//!
//! With `STS_WRITE_VECTORS=1`, `oauth7-rust.json` carries Rust's answers
//! over the same inputs for Node to compute again
//! (`tests/rust_crypto_vectors.js`).

#![allow(clippy::unwrap_used)] // a test file

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_core::settings::Settings;
use sts_oauth::requested_claims::RequestedClaims;
use sts_oauth::userinfo::NoDirectory;

fn vectors() -> Option<(PathBuf, Json)> {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: oauth7-node.json is not checked"
        );
        return None;
    };
    let dir = PathBuf::from(dir);
    let text = std::fs::read_to_string(dir.join("oauth7-node.json")).ok()?;
    Some((dir, serde_json::from_str(&text).unwrap()))
}

fn text(v: &Json, k: &str) -> String {
    v.get(k).and_then(Json::as_str).unwrap_or("").to_string()
}

fn nobody(_: &str) -> Option<String> {
    None
}

#[test]
fn nodes_folds_personas_claims_matches_and_negotiations() {
    let Some((dir, node)) = vectors() else {
        return;
    };
    assert_eq!(node["problems"], json!([]), "{}", node["problems"]);
    let mut out = serde_json::Map::new();
    let mut identities = Vec::new();
    for row in node["identities"].as_array().unwrap() {
        let id = sts_directory::funnel::identity_of(
            &text(row, "presented"),
            &nobody,
        );
        assert_eq!(id.key, text(row, "key"), "{}", row);
        assert_eq!(id.realm, text(row, "realm"), "{}", row);
        assert_eq!(json!(id.unresolved), row["unresolved"], "{}", row);
        identities.push(json!({ "presented": row["presented"], "key": id.key,
                                "realm": id.realm }));
    }
    out.insert("identities".into(), Json::Array(identities));
    let mut personas = Vec::new();
    for row in node["personas"].as_array().unwrap() {
        let p = sts_directory::funnel::persona_for(&text(row, "name"), &nobody);
        assert_eq!(p.username, text(row, "username"), "{}", row);
        assert_eq!(p.given, text(row, "given"), "{}", row);
        assert_eq!(p.family, text(row, "family"), "{}", row);
        assert_eq!(p.display, text(row, "display"), "{}", row);
        assert_eq!(p.email, text(row, "email"), "{}", row);
        personas.push(json!({ "name": row["name"], "given": p.given,
                              "family": p.family, "display": p.display,
                              "email": p.email }));
    }
    out.insert("personas".into(), Json::Array(personas));
    let mut matches = Vec::new();
    for row in node["matches"].as_array().unwrap() {
        let m = sts_oauth::identity_assurance::matches(
            Some(&row["request"]),
            Some(&row["actual"]),
            0,
        );
        let p = sts_oauth::identity_assurance::project(
            Some(&row["request"]),
            Some(&row["actual"]),
            0,
        )
        .unwrap_or(Json::Null);
        assert_eq!(json!(m), row["matches"], "{}", row);
        assert_eq!(p, row["projected"], "{}", row);
        matches
            .push(json!({ "request": row["request"], "actual": row["actual"],
                             "matches": m, "projected": p }));
    }
    out.insert("matches".into(), Json::Array(matches));
    let mut accepts = Vec::new();
    for row in node["accepts"].as_array().unwrap() {
        let jwt = sts_oauth::introspection::wants_jwt(&text(row, "accept"));
        assert_eq!(json!(jwt), row["jwt"], "{}", row);
        accepts.push(json!({ "accept": row["accept"], "jwt": jwt }));
    }
    out.insert("accepts".into(), Json::Array(accepts));
    let requested = RequestedClaims {
        directory: Arc::new(NoDirectory),
        settings: Arc::new(Settings::new(Json::Null, HashMap::new())),
        invents: Arc::new(|| false),
        now_ms: Arc::new(|| 0),
    };
    let mut claims = Vec::new();
    for row in node["claims"].as_array().unwrap() {
        let raw = row["raw"].clone();
        let mine = match requested.parse(Some(&raw)) {
            Ok(c) => json!({ "raw": raw, "claims": c.unwrap_or(Json::Null) }),
            Err(e) => json!({ "raw": raw, "error": e }),
        };
        assert_eq!(mine, *row, "the claims request {}", raw);
        claims.push(mine);
    }
    out.insert("claims".into(), Json::Array(claims));
    if std::env::var("STS_WRITE_VECTORS").is_ok() {
        std::fs::write(
            dir.join("oauth7-rust.json"),
            serde_json::to_string_pretty(&Json::Object(out)).unwrap(),
        )
        .unwrap();
    }
}
