// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The trust half of an attestation against Node as it is now: the
//! `webauthn.trust` cases of `credentials-node.json`, which
//! `tests/tools/credentials-webauthn.js` records over Node's own
//! `assess()` — a registration a software authenticator made, the
//! settings, an MDS3 BLOB signed there under a root made there, Google's
//! status list as rows, and revocation as the case says. Each case's
//! verdict, record and code are Node's, and so is every question the
//! verifier asked of the metadata service, of Google's list and of
//! revocation, in Node's order.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed; with it unset
//! this test says so and passes.

#![allow(clippy::unwrap_used, clippy::expect_used)] // a test file

use std::path::Path;
use std::sync::Mutex;

use serde_json::{json, Value as Json};
use sts_credentials::webauthn::ceremony::{
    verify_registration, RegistrationInput,
};
use sts_credentials::webauthn::metadata::{AndroidStatusList, FidoMetadata};
use sts_credentials::webauthn::trust::{
    AndroidStatus, Attestation, AttestationPorts, Metadata, Revocation,
};
use sts_pki::foreign::certificate_bundle;

fn text(v: &Json) -> String {
    v.as_str().unwrap_or("").to_string()
}

/// One case's world.
struct Case {
    case: Json,
    metadata: FidoMetadata,
    android: Option<AndroidStatusList>,
    calls: Mutex<Vec<Json>>,
}

impl Metadata for Case {
    fn lookup_authenticator_by(
        &self,
        kind: &str,
        key: &str,
    ) -> Result<Option<Json>, String> {
        self.calls.lock().unwrap().push(json!([
            "metadata",
            kind,
            key.to_lowercase()
        ]));
        if self.case["metadataThrows"] == json!(true) {
            return Err("the risk store is unreachable".to_string());
        }
        self.metadata.lookup_authenticator_by(kind, key)
    }
}

impl AndroidStatus for Case {
    fn lookup_attestation_serials(
        &self,
        serials: &[String],
    ) -> Result<Json, String> {
        self.calls.lock().unwrap().push(json!(["android", serials]));
        if self.case["androidList"] == json!("throws") {
            return Err("the risk store is unreachable".to_string());
        }
        match &self.android {
            Some(list) => list.lookup_attestation_serials(serials),
            None => Ok(json!({ "checked": false, "version": "", "hits": [],
                "why": "no Android attestation status list is loaded" })),
        }
    }
}

impl Revocation for Case {
    fn verdict_for(
        &self,
        leaf_pem: &str,
        chain_pems: &[String],
    ) -> Result<Json, String> {
        self.calls.lock().unwrap().push(json!([
            "revocation",
            leaf_pem,
            chain_pems
        ]));
        let given = &self.case["revocation"];
        Ok(if given.is_null() {
            json!({ "refused": false, "status": "good" })
        } else {
            given.clone()
        })
    }
}

impl AttestationPorts for Case {
    fn settings(&self) -> Json {
        self.case["settings"].clone()
    }
    fn insecure_allowed(&self) -> bool {
        false
    }
    fn now_ms(&self) -> f64 {
        self.case["now"].as_f64().unwrap()
    }
    fn metadata(&self) -> &dyn Metadata {
        self
    }
    fn revocation(&self) -> &dyn Revocation {
        self
    }
    fn android_status(&self) -> &dyn AndroidStatus {
        self
    }
    fn refuses_unchecked_android_revocation(&self) -> bool {
        self.case["refusesUnchecked"] == json!(true)
    }
}

fn input(i: &Json) -> RegistrationInput {
    RegistrationInput {
        attestation_object: text(&i["attestationObject"]),
        client_data_json: text(&i["clientDataJSON"]),
        expected_challenge: i["expectedChallenge"].clone(),
        expected_origin: i["expectedOrigin"].clone(),
        expected_rp_id: text(&i["expectedRpId"]),
        require_user_verification: i["requireUserVerification"] == json!(true),
        expected_algorithms: None,
    }
}

/// PEM text compared by its base64 body, line breaks aside.
fn pem_body(v: &Json) -> Json {
    match v {
        Json::String(s) => Json::String(
            s.lines()
                .filter(|l| !l.starts_with("-----"))
                .collect::<String>(),
        ),
        Json::Array(l) => Json::Array(l.iter().map(pem_body).collect()),
        other => other.clone(),
    }
}

#[test]
fn attestation_trust_answers_what_node_answers() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!("STS_CRYPTO_VECTORS is unset; nothing to check");
        return;
    };
    let file = Path::new(&dir).join("credentials-node.json");
    let Ok(raw) = std::fs::read_to_string(&file) else {
        eprintln!("{} is missing; nothing to check", file.display());
        return;
    };
    let v: Json = serde_json::from_str(&raw).unwrap();
    let cases = v["webauthn"]["trust"]["cases"].as_array().unwrap();
    assert!(cases.len() > 40, "too few trust cases: {}", cases.len());
    let mut wrong = Vec::new();
    for case in cases {
        let name = text(&case["name"]);
        let now = case["now"].as_f64().unwrap() as i64;
        let metadata = if case["metadata"].is_null() {
            FidoMetadata::default()
        } else {
            let (anchors, _) =
                certificate_bundle(&text(&case["metadata"]["anchorsPem"]));
            FidoMetadata::from_blob(
                &text(&case["metadata"]["token"]),
                &anchors,
                now,
            )
            .unwrap_or_default()
        };
        let android = case["androidList"].as_object().and_then(|l| {
            AndroidStatusList::from_list(&l["list"], &text(&l["version"]))
        });
        let world = Case {
            case: case.clone(),
            metadata,
            android,
            calls: Mutex::new(Vec::new()),
        };
        let r = match verify_registration(&input(&case["input"])) {
            Ok(r) => r,
            Err(e) => {
                wrong.push(format!("{name}: the registration threw {e}"));
                continue;
            }
        };
        let verdict = Attestation::new(&world).assess(&r);
        if verdict.value != case["answer"]["value"] {
            wrong.push(format!(
                "{name}:\n  Node {}\n  Rust {}",
                case["answer"]["value"], verdict.value
            ));
        }
        if verdict.code_text() != text(&case["answer"]["code"]) {
            wrong.push(format!(
                "{name}: code Node {} Rust {}",
                case["answer"]["code"],
                verdict.code_text()
            ));
        }
        let mine = pem_body(&json!(*world.calls.lock().unwrap()));
        if mine != pem_body(&case["calls"]) {
            wrong.push(format!(
                "{name}: asked\n  Node {}\n  Rust {}",
                case["calls"], mine
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {} wrong:\n{}",
        wrong.len(),
        cases.len(),
        wrong.join("\n")
    );
}
