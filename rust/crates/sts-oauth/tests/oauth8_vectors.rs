// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The `oauth8` slice against Node (D11), over `oauth8-node.json`
//! (`tests/tools/oauth8-vectors.js`): RFC 8693's token types
//! (`exchangeTypeProblem()`, `ownTokenKind()`, `kindProblem()`), #550's
//! actor_token rule, the `act` chain (#443, #471), `may_act` (section
//! 4.4), the built-in issuance policy's exchange questions over fact sets,
//! and `DelegationPolicy.decide()` and `mayActClaimFor()` over one
//! directory — each answered here as Node answered it.
//!
//! WHERE RUST AND NODE DIFFER BY DESIGN, pinned: Rust takes the four types
//! a token of this service can be, and not the assertion, Kerberos or
//! device-secret types (their verifiers are not ported), so its list is
//! shorter and those types are refused `STS-OAUTH-0627`.
//!
//! With `STS_WRITE_VECTORS=1`, `oauth8-rust.json` carries Rust's verdicts,
//! decisions and claims for Node to compute again
//! (`tests/rust_crypto_vectors.js`).

#![allow(clippy::unwrap_used)] // a test file

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{json, Map, Value as Json};
use sts_core::mode::Mode;
use sts_core::settings::Settings;
use sts_oauth::delegation_policy::{
    self as dp, DelegationDirectory, DelegationPolicy, Question,
};
use sts_oauth::token_endpoint::exchange;

fn vectors() -> Option<(PathBuf, Json)> {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: oauth8-node.json is not checked"
        );
        return None;
    };
    let dir = PathBuf::from(dir);
    let text = std::fs::read_to_string(dir.join("oauth8-node.json")).ok()?;
    Some((dir, serde_json::from_str(&text).unwrap()))
}

fn text(v: &Json, k: &str) -> String {
    v.get(k).and_then(Json::as_str).unwrap_or("").to_string()
}

fn strings(v: &Json) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().map(|x| x.as_str().unwrap_or("").into()).collect())
        .unwrap_or_default()
}

/// The vector's directory, as `oauth8-vectors.js`'s `fakeDeps()` reads it.
struct Described(Json);

impl Described {
    fn apps(&self) -> Vec<Json> {
        self.0["apps"].as_array().cloned().unwrap_or_default()
    }
    fn by(&self, attribute: &str, value: &str) -> Option<Json> {
        self.apps()
            .into_iter()
            .find(|a| match &a["fields"][attribute] {
                Json::Array(l) => l.iter().any(|v| v == value),
                Json::String(s) => s == value,
                _ => false,
            })
    }
}

impl DelegationDirectory for Described {
    fn get(&self, identifier: &str) -> Option<Json> {
        self.apps()
            .into_iter()
            .find(|a| a["identifier"] == identifier)
    }
    fn for_client_id(&self, v: &str) -> Option<Json> {
        self.by("oauthClientId", v)
    }
    fn for_audience(&self, v: &str) -> Option<Json> {
        self.by("oauthAudience", v)
    }
    fn for_applies_to(&self, v: &str) -> Option<Json> {
        self.by("wstrustAppliesTo", v)
    }
    fn is_resource_server(&self, id: &str) -> bool {
        self.get(id).is_some_and(|a| {
            let kinds = strings(&a["kinds"]);
            kinds.iter().any(|k| k == "oauth2-resource-server")
                && !kinds.iter().any(|k| k == "oauth2-client")
        })
    }
    fn required_roles_of(&self, identifier: &str) -> Vec<String> {
        strings(&self.0["required"][identifier])
    }
    fn list(&self) -> Vec<Json> {
        self.apps()
    }
    fn roles_of(&self, kind: &str, name: &str) -> Vec<String> {
        strings(&self.0["roles"][format!("{}:{}", kind, name)])
    }
    fn delegation_facts(&self, key: &str) -> Json {
        let people = self.0["people"].as_object().cloned().unwrap_or_default();
        for (name, p) in people {
            if name == key
                || text(&p, "dn").to_lowercase() == key.to_lowercase()
                || text(&p, "sub") == key
            {
                return p;
            }
        }
        json!({ "found": false, "person": false, "dn": "", "username": "",
                "sub": "", "notDelegated": false, "mayAct": "",
                "delegate": null, "groups": [], "semantics": [],
                "defaultSemantics": "" })
    }
}

fn policy_for(node: &Json, mode: &str) -> DelegationPolicy {
    let s = &node["settings"];
    let mut env = HashMap::new();
    env.insert("STS_MODE".to_string(), mode.to_string());
    for (key, var) in [
        (
            "delegation.defaultSemantics",
            "STS_DELEGATION_DEFAULT_SEMANTICS",
        ),
        ("delegation.actorRole", "STS_DELEGATION_ACTOR_ROLE"),
        (
            "delegation.protectedGroups",
            "STS_DELEGATION_PROTECTED_GROUPS",
        ),
        ("admin.readGroup", "ADMIN_READ_GROUP"),
        ("admin.writeGroup", "ADMIN_WRITE_GROUP"),
    ] {
        env.insert(var.to_string(), text(s, key));
    }
    let settings = Arc::new(Settings::new(Json::Null, env));
    DelegationPolicy {
        directory: Arc::new(Described(node["directory"].clone())),
        settings: settings.clone(),
        mode: Arc::new(Mode::new(settings)),
    }
}

fn question_of(q: &Json) -> Question {
    Question {
        protocol: text(q, "protocol"),
        requested: text(q, "requested"),
        actor: text(q, "actor"),
        subject: text(q, "subject"),
        source: strings(&q["source"]),
        targets: strings(&q["targets"]),
        target_kind: text(q, "targetKind"),
        may_act_present: q["mayActPresent"] == true,
        may_act_names_actor: q["mayActNamesActor"] == true,
    }
}

fn verdict_of(a: &Json) -> Json {
    json!({ "verdict": a["verdict"], "refusal": a["refusal"],
            "enforced": a["enforced"], "semantics": a["semantics"],
            "audience": a["audience"], "chosen": a["chosen"] })
}

#[test]
fn nodes_exchange_types_chains_verdicts_and_decisions() {
    let Some((dir, node)) = vectors() else {
        return;
    };
    assert_eq!(node["problems"], json!([]), "{}", node["problems"]);
    let ours = exchange::TOKEN_TYPES
        .iter()
        .map(|(u, _)| *u)
        .collect::<Vec<_>>()
        .join(", ");
    for row in node["types"].as_array().unwrap() {
        let body: Map<String, Json> =
            row["body"].as_object().cloned().unwrap_or_default();
        let mine = exchange::exchange_type_problem(&body);
        let (code, description) =
            mine.map(|(c, d)| (c.to_string(), d)).unwrap_or_default();
        let theirs = text(row, "description");
        let subject_type = text(&row["body"], "subject_token_type");
        let actor_type = text(&row["body"], "actor_token_type");
        let unported = |t: &str| {
            !t.trim().is_empty()
                && !exchange::TOKEN_TYPES.iter().any(|(u, _)| *u == t.trim())
        };
        if theirs.is_empty()
            && (unported(&subject_type) || unported(&actor_type))
        {
            // PINNED: a type Node takes and Rust does not.
            assert_eq!(code, "STS-OAUTH-0627", "{}", row);
            assert!(description.ends_with(&format!("it takes {}.", ours)));
            continue;
        }
        assert_eq!(code, text(row, "code"), "{}", row);
        match theirs.find("; it takes ") {
            Some(at) => {
                // PINNED: Rust's list is its own.
                assert_eq!(description[..at], theirs[..at], "{}", row);
                assert!(description.ends_with(&format!("it takes {}.", ours)));
            }
            None => assert_eq!(description, theirs, "{}", row),
        }
    }
    for row in node["kinds"].as_array().unwrap() {
        let kind =
            exchange::own_token_kind(&text(row, "token"), &row["claims"]);
        assert_eq!(kind, text(row, "kind"), "{}", row);
        assert_eq!(
            exchange::kind_problem(
                &text(row, "declared"),
                kind,
                "subject_token"
            ),
            text(row, "problem"),
            "{}",
            row
        );
    }
    for row in node["actors"].as_array().unwrap() {
        let mine = exchange::actor_token_problem(
            &row["claims"],
            &text(row, "client"),
            &strings(&row["names"]),
            &text(row, "issuer"),
            &text(row, "base"),
        );
        let (code, description) =
            mine.map(|(c, d)| (c.to_string(), d)).unwrap_or_default();
        assert_eq!(code, text(row, "code"), "{}", row);
        assert_eq!(description, text(row, "description"), "{}", row);
    }
    for row in node["chains"].as_array().unwrap() {
        let out =
            exchange::prior_act_chain(&row["chain"], &text(row, "issuer"));
        assert_eq!(out, row["out"], "{}", row);
    }
    for row in node["originals"].as_array().unwrap() {
        let out = exchange::original_client_act(
            &row["subject"],
            row["verified"] == true,
            &text(row, "actor"),
            row["namespaced"] == true,
            "https://iss",
        );
        assert_eq!(out, row["out"], "{}", row);
    }
    for row in node["mayActs"].as_array().unwrap() {
        let a = &row["actor"];
        let names = dp::may_act_names(
            &row["mayAct"],
            &text(a, "sub"),
            &text(a, "iss"),
            &strings(&a["aliases"]),
        );
        assert_eq!(json!(names), row["names"], "{}", row);
    }
    let mut verdicts = Vec::new();
    for row in node["verdicts"].as_array().unwrap() {
        let mine = dp::exchange_verdict(
            &row["facts"],
            &text(row, "mode"),
            &row["settings"],
        );
        assert_eq!(verdict_of(&mine), verdict_of(&row["answer"]), "{}", row);
        verdicts.push(json!({ "facts": row["facts"], "mode": row["mode"],
                              "settings": row["settings"],
                              "answer": verdict_of(&mine) }));
    }
    let mut decisions = Vec::new();
    for row in node["decisions"].as_array().unwrap() {
        let policy = policy_for(&node, &text(row, "mode"));
        let d = policy.decide(&question_of(&row["question"]));
        let mine = dp::decision_json(&d);
        assert_eq!(mine, row["decision"], "{}", row["question"]);
        decisions.push(json!({ "mode": row["mode"],
                               "question": row["question"],
                               "decision": mine }));
    }
    let policy = policy_for(&node, "product");
    let mut claims = Vec::new();
    for row in node["claims"].as_array().unwrap() {
        let claim = policy
            .may_act_claim_for(&text(row, "name"))
            .unwrap_or(Json::Null);
        assert_eq!(claim, row["claim"], "{}", row);
        claims.push(json!({ "name": row["name"], "claim": claim }));
    }
    if std::env::var("STS_WRITE_VECTORS").is_ok() {
        std::fs::write(
            dir.join("oauth8-rust.json"),
            serde_json::to_string_pretty(&json!({
                "verdicts": verdicts, "decisions": decisions,
                "claims": claims,
            }))
            .unwrap(),
        )
        .unwrap();
    }
}
