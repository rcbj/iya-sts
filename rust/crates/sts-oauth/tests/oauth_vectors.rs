// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The authorization server's core against Node
//! (`tests/tools/oauth-vectors.js`, `oauth-node.json`): every answer Node
//! recorded, reproduced here. `STS_CRYPTO_VECTORS` names the directory,
//! never committed; without it the set is not checked.

#![allow(clippy::unwrap_used, clippy::expect_used)] // a test file

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_core::mode::Mode;
use sts_core::settings::Settings;
use sts_oauth::answer::sanitize_description;
use sts_oauth::bcp::{self, BcpMode, Question};
use sts_oauth::client_auth::{
    AssertionHistory, ClientAuth, Clock, MemoryAssertionHistory, MethodHints,
    NoAssertionKeys, Presented, Verified,
};
use sts_oauth::jwks::{
    jwks_body, jwks_keys, CertificateSources, JwksInputs, JwksPolicy,
    PinnedSigner,
};

pub fn vectors() -> Option<Json> {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: oauth-node.json is not checked"
        );
        return None;
    };
    let path = std::path::Path::new(&dir).join("oauth-node.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        eprintln!("{} is missing: not checked", path.display());
        return None;
    };
    Some(serde_json::from_str(&text).unwrap())
}

struct Pinned(i64);
impl Clock for Pinned {
    fn now_ms(&self) -> i64 {
        self.0
    }
}

pub fn settings_with(overrides: &[(&str, Json)]) -> (Arc<Settings>, Arc<Mode>) {
    let settings = Arc::new(Settings::new(Json::Null, HashMap::new()));
    for (k, v) in overrides {
        if v.is_null() {
            continue;
        }
        settings
            .restore_override(k, v.clone())
            .unwrap_or_else(|e| panic!("{} = {}: {:?}", k, v, e.problem));
    }
    let mode = Mode::shared(settings.clone());
    (settings, mode)
}

#[test]
fn sanitized_descriptions() {
    let Some(v) = vectors() else { return };
    for one in v["sanitize"].as_array().unwrap() {
        assert_eq!(
            sanitize_description(one["text"].as_str().unwrap()),
            one["sanitized"].as_str().unwrap(),
            "{}",
            one["text"]
        );
    }
}

fn s(v: &Json) -> String {
    v.as_str().unwrap_or("").to_string()
}

#[test]
fn client_authentication() {
    let Some(v) = vectors() else { return };
    let history: Arc<dyn AssertionHistory> =
        Arc::new(MemoryAssertionHistory::default());
    let mut failures = Vec::new();
    for case in v["clientAuth"].as_array().unwrap() {
        let mode_name = s(&case["mode"]);
        let (settings, mode) =
            settings_with(&[("global.mode", json!(mode_name))]);
        let auth = ClientAuth::new(
            settings,
            mode,
            history.clone(),
            Arc::new(NoAssertionKeys),
            Arc::new(Pinned(case["nowMs"].as_i64().unwrap())),
        );
        let input = &case["input"];
        let presented = Presented {
            client_id: s(&input["clientId"]),
            presented_secret: s(&input["clientSecret"]),
            assertion: s(&input["assertion"]),
            assertion_type: s(&input["assertionType"]),
            audiences: input["audiences"]
                .as_array()
                .unwrap()
                .iter()
                .map(s)
                .collect(),
            strict_audience: s(&input["strictAudience"]),
            issuer: s(&input["issuer"]),
            ..Presented::default()
        };
        let hints = MethodHints {
            assertion: presented.assertion.clone(),
            assertion_type: presented.assertion_type.clone(),
            client_secret: presented.presented_secret.clone(),
            basic: s(&input["headers"]["authorization"]).starts_with("Basic "),
            ..MethodHints::default()
        };
        let q = Question {
            presented: &presented,
            hints: &hints,
            registered: &input["registered"],
        };
        let memo = Verified::default();
        let name = format!("{} [{}]", s(&case["name"]), mode_name);
        if !case["observed"].is_null() {
            let o = bcp::observe_client_authentication(&auth, &q, &memo);
            let got = json!({
                "authenticated": o.authenticated, "method": o.method,
                "errorCode": o.code.map(|c| c.to_string()),
                "why": o.why,
            });
            let want = &case["observed"];
            let wanted = json!({
                "authenticated": want["authenticated"],
                "method": want["method"],
                "errorCode": want.get("errorCode").cloned()
                    .unwrap_or(Json::Null),
                "why": want["why"],
            });
            if got != wanted {
                failures.push(format!(
                    "{} observed\n  rust {}\n  node {}",
                    name, got, wanted
                ));
            }
        }
        let checked = bcp::check_client_authentication(
            BcpMode {
                enabled: case["bcpEnabled"].as_bool().unwrap(),
            },
            &auth,
            &q,
            &memo,
        );
        let got = match checked {
            Ok(method) if method.is_empty() => json!({ "ok": true }),
            Ok(method) => json!({ "ok": true, "method": method }),
            Err(r) => json!({
                "ok": false, "errorCode": r.code.to_string(),
                "error": r.error, "status": r.status,
                "requirement": r.requirement, "description": r.description,
            }),
        };
        if got != case["checked"] {
            failures.push(format!(
                "{} checked\n  rust {}\n  node {}",
                name, got, case["checked"]
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

struct Recorded<'a>(&'a Json);

impl CertificateSources for Recorded<'_> {
    fn published(
        &self,
        _use_case: &str,
        slot: &str,
        kid: &str,
    ) -> Option<(String, Vec<String>)> {
        let held = self.0["published"].get(format!("{}@{}", slot, kid))?;
        Some((
            s(&held["certificatePem"]),
            held["chainPem"].as_array()?.iter().map(s).collect(),
        ))
    }
    fn service_root_pem(&self) -> Option<String> {
        self.0["rootPem"].as_str().map(str::to_string)
    }
    fn pinned_signers(&self, _use_case: &str) -> Vec<PinnedSigner> {
        self.0["pinned"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|one| PinnedSigner {
                kid: s(&one["kid"]),
                kind: s(&one["kind"]),
                certificate_pem: s(&one["certificatePem"]),
                chain_pem: one["chainPem"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(s)
                    .collect(),
                public_jwk: one.get("publicJwk").cloned(),
            })
            .collect()
    }
}

#[test]
fn jwks_documents() {
    let Some(v) = vectors() else { return };
    let mut failures = Vec::new();
    for case in v["jwks"].as_array().unwrap() {
        assert!(case.get("problem").is_none(), "{}", case);
        let overrides: Vec<(&str, Json)> = case["settings"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.as_str(), v.clone()))
            .collect();
        let (settings, mode) = settings_with(&overrides);
        let policy = JwksPolicy::from_settings(&settings, &mode);
        let sources = Recorded(&case["sources"]);
        let keys = jwks_keys(&JwksInputs {
            blob: &case["blob"],
            pq_keys: None,
            sources: &sources,
            policy: &policy,
            now_ms: case["nowMs"].as_f64().unwrap(),
        })
        .unwrap();
        let body = jwks_body(keys);
        if body != s(&case["body"]) {
            failures.push(format!(
                "{}\n  rust {}\n  node {}",
                s(&case["name"]),
                body,
                s(&case["body"])
            ));
        }
        assert_eq!(s(&case["cacheControl"]), "no-store");
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn request_validation() {
    let Some(v) = vectors() else { return };
    let mut failures = Vec::new();
    for case in v["validation"].as_array().unwrap() {
        let input = case["input"].as_object().unwrap();
        let got = match sts_oauth::model::check(
            &s(&case["id"]),
            input,
            &s(&case["where"]),
        ) {
            Ok(value) => json!({ "ok": true, "value": value }),
            Err(r) => json!({ "ok": false, "code": r.code, "field": r.field,
                              "detail": r.detail }),
        };
        if got != case["answer"] {
            failures.push(format!(
                "{}\n  rust {}\n  node {}",
                case["input"], got, case["answer"]
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
