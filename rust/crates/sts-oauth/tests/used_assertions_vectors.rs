// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The used-assertion history against Node (D11): Node's own
//! `used_assertions.js` keyed documents, said its replay clauses and
//! answered a run of claims and looks (`used-assertions-node.json`,
//! `tests/tools/used-assertions-vectors.js`). Here
//! [`sts_oauth::used_assertions`] must give every key — the
//! `sts_used_assertions` primary key both runtimes write, so a document
//! either spent is refused by the other — every clause and every answer.
//!
//! With `STS_WRITE_VECTORS=1`, `used-assertions-rust.json` carries Rust's
//! keys and clauses for Node to compute again (`tests/rust_crypto_vectors.js`).

#![allow(clippy::unwrap_used)] // a test file

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_core::settings::Settings;
use sts_oauth::used_assertions::{
    key_of, used_as, ClaimAsk, NoSealer, NoStore, NotClaimed, UsedAssertions,
};

fn vectors() -> Option<(PathBuf, Json)> {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: used-assertions-node.json is \
             not checked"
        );
        return None;
    };
    let dir = PathBuf::from(dir);
    let text =
        std::fs::read_to_string(dir.join("used-assertions-node.json")).ok()?;
    Some((dir, serde_json::from_str(&text).unwrap()))
}

fn text(v: &Json, k: &str) -> String {
    v.get(k).and_then(Json::as_str).unwrap_or("").to_string()
}

#[tokio::test]
async fn nodes_keys_clauses_and_answers() {
    let Some((dir, node)) = vectors() else {
        return;
    };
    assert_eq!(node["problems"], json!([]), "{}", node["problems"]);
    let mut keys = Vec::new();
    for row in node["keys"].as_array().unwrap() {
        let mine = key_of(
            &text(row, "format"),
            &text(row, "issuer"),
            &text(row, "identifier"),
        );
        assert_eq!(mine, text(row, "key"), "{}", row);
        keys.push(json!({ "format": row["format"], "issuer": row["issuer"],
                          "identifier": row["identifier"], "key": mine }));
    }
    let mut clauses = Vec::new();
    for row in node["usedAs"].as_array().unwrap() {
        let mine = used_as(&row["existing"]);
        assert_eq!(mine, text(row, "clause"), "{}", row);
        clauses.push(json!({ "existing": row["existing"], "clause": mine }));
    }
    // Three live rows at most: the run's last claim is the fourth.
    let plain = UsedAssertions::new(
        Arc::new(Settings::new(
            json!({ "oauth2": { "assertionReplayCacheSize": 3 } }),
            HashMap::new(),
        )),
        Arc::new(NoStore),
        Arc::new(NoSealer),
        Arc::new(|| chrono::Utc::now().timestamp_millis()),
    );
    for step in node["claims"].as_array().unwrap() {
        let ask = &step["ask"];
        let answer = &step["answer"];
        if text(step, "step") == "peek" {
            let seen = plain
                .peek("jwt", &text(ask, "issuer"), &text(ask, "identifier"))
                .await;
            assert_eq!(
                seen.is_some(),
                answer["used"] == json!(true),
                "{}",
                step
            );
            continue;
        }
        let claim = ClaimAsk {
            format: text(ask, "format"),
            use_: text(ask, "use"),
            issuer: text(ask, "issuer"),
            identifier: text(ask, "identifier"),
            expires_at: ask["expiresAt"].as_i64().unwrap_or(0),
            client_id: text(ask, "clientId"),
            reserve: false,
            ..ClaimAsk::default()
        };
        let got = plain.claim(&claim).await;
        match (got, answer["ok"] == json!(true)) {
            (Ok(_), true) => {}
            (Err(NotClaimed::Replay(row)), false) => {
                assert_eq!(text(answer, "reason"), "replay", "{}", step);
                assert_eq!(row["use"], answer["usedAs"], "{}", step);
            }
            (Err(NotClaimed::Full { .. }), false) => {
                assert_eq!(text(answer, "reason"), "full", "{}", step);
            }
            (other, _) => panic!("{} answered {:?}", step, other),
        }
    }
    if std::env::var("STS_WRITE_VECTORS").is_ok() {
        std::fs::write(
            dir.join("used-assertions-rust.json"),
            serde_json::to_string_pretty(
                &json!({ "keys": keys, "usedAs": clauses }),
            )
            .unwrap(),
        )
        .unwrap();
    }
}
