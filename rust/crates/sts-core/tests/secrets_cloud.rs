// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The six cloud providers against Node and emulators of the three clouds:
//! `tests/tools/secrets-cloud-interop.js` reads each secret and wraps data
//! keys through `common/secrets.js` (`secrets-cloud-node.json`); this reads
//! the same secrets through `sts_core::secrets`, unwraps every data key
//! Node wrapped, sees a changed AAD refused, checks `owns()` and
//! `isStale()` as Node answered them, wraps its own
//! (`secrets-cloud-rust.json`) for the tool's second run to unwrap, rotates
//! each key, and compares the requests both runtimes sent the oct-HSM
//! Key Vault the tool serves.
//!
//! Skipped unless `STS_SECRETS_VECTORS` and `STS_PROBE_GCP` are set; the
//! rest of the environment is the tool's (its header lists it), and the
//! SDKs read theirs as they do in the service: AWS_ENDPOINT_URL and the
//! static credentials, IDENTITY_ENDPOINT and IDENTITY_HEADER, SSL_CERT_FILE.

#![allow(clippy::unwrap_used, clippy::expect_used)] // a test file

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_core::secrets::{Emulators, KmsCrypto, Secret, Secrets, KEK};
use sts_core::settings::Settings;

/// The slot the composition root fills from sts-crypto, filled here from
/// openssl as a test's dev-dependency.
struct Crypto;

impl KmsCrypto for Crypto {
    fn sha256(&self, data: &[u8]) -> Vec<u8> {
        openssl::sha::sha256(data).to_vec()
    }

    fn equal(&self, a: &[u8], b: &[u8]) -> bool {
        a.len() == b.len() && openssl::memcmp::eq(a, b)
    }

    fn pkcs12_of_pem(
        &self,
        pem: &[u8],
        password: &str,
    ) -> Result<Vec<u8>, String> {
        let key = openssl::pkey::PKey::private_key_from_pem(pem)
            .map_err(|e| e.to_string())?;
        let cert =
            openssl::x509::X509::from_pem(pem).map_err(|e| e.to_string())?;
        openssl::pkcs12::Pkcs12::builder()
            .pkey(&key)
            .cert(&cert)
            .build2(password)
            .and_then(|p| p.to_der())
            .map_err(|e| e.to_string())
    }
}

fn secrets(extra: &[(&str, &str)]) -> Secrets {
    let mut env: HashMap<String, String> = std::env::vars()
        .filter(|(k, _)| !k.starts_with("STS_KEYS_"))
        .collect();
    for (k, v) in extra {
        env.insert(k.to_string(), v.to_string());
    }
    let s = Secrets::new(Arc::new(Settings::new(Json::Null, env.clone())), env);
    s.set_kms_crypto(Arc::new(Crypto));
    s.set_emulators(Emulators {
        gcp: std::env::var("STS_PROBE_GCP")
            .ok()
            .map(|at| format!("http://{}", at)),
    });
    s
}

fn shown(secret: Secret) -> Json {
    match secret {
        Secret::Value { bytes, text: true } => {
            json!({"text": String::from_utf8(bytes).unwrap()})
        }
        Secret::Value { bytes, text: false } => json!({"hex": hex(&bytes)}),
        Secret::Remote(h) => json!({"remote": h.label()}),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[tokio::test]
async fn the_clouds_as_node_reads_and_wraps_them() {
    let (Ok(dir), Ok(_)) = (
        std::env::var("STS_SECRETS_VECTORS"),
        std::env::var("STS_PROBE_GCP"),
    ) else {
        eprintln!("STS_SECRETS_VECTORS or STS_PROBE_GCP unset: skipped");
        return;
    };
    let dir = std::path::Path::new(&dir);
    let node: Json = serde_json::from_str(
        &std::fs::read_to_string(dir.join("secrets-cloud-node.json")).unwrap(),
    )
    .unwrap();
    let vault = std::env::var("STS_PROBE_AZURE_VAULT").unwrap();
    let fake = std::env::var("STS_PROBE_AZURE_FAKE").unwrap();
    let mut failures: Vec<String> = Vec::new();

    // THE READS: the same bytes, and the database password beside them.
    let reads: &[(&str, &str, &str, &[(&str, &str)])] = &[
        ("aws", "aws", "sts-kek", &[("STS_KEYS_KEK_FIELD", "kek")]),
        ("aws-binary", "aws", "sts-kek-binary", &[]),
        ("aws-whole", "aws", "sts-kek", &[]),
        (
            "gcp",
            "gcp",
            "projects/iya-probe/secrets/sts-kek",
            &[("STS_KEYS_KEK_FIELD", "kek")],
        ),
        (
            "azure",
            "azure",
            "sts-kek",
            &[("STS_KEYS_KEK_FIELD", "kek"), ("STS_KEYS_KEK_VAULT", "")],
        ),
    ];
    for (name, provider, ref_, extra) in reads {
        let mut env = vec![
            ("STS_KEYS_KEK_PROVIDER", *provider),
            ("STS_KEYS_KEK_REF", *ref_),
        ];
        for (k, v) in extra.iter() {
            env.push((
                k,
                if *k == "STS_KEYS_KEK_VAULT" {
                    &vault
                } else {
                    v
                },
            ));
        }
        let s = secrets(&env);
        let mut got = match s.read(&KEK).await {
            Ok(secret) => shown(secret),
            Err(e) => json!({"refused": e}),
        };
        env.push(("STS_DATABASE_PASSWORD_PROVIDER", provider));
        let s = secrets(&env);
        match s.read(&sts_core::secrets::DATABASE_PASSWORD).await {
            Ok(Secret::Value { bytes, .. }) => {
                got["password"] = json!(String::from_utf8(bytes).unwrap())
            }
            Ok(other) => panic!("{:?}", other),
            Err(e) => got["passwordRefused"] = json!(e),
        }
        let want = &node["reads"][name];
        if &got != want {
            failures.push(format!("read {}: rust {} node {}", name, got, want));
        }
    }
    let s = secrets(&[
        ("STS_KEYS_KEK_PROVIDER", "aws"),
        ("STS_KEYS_KEK_REF", "no-such-secret"),
    ]);
    let missing = s.read(&KEK).await.unwrap_err();
    if json!(missing) != node["reads"]["awsMissing"]["refused"] {
        failures.push(format!(
            "aws missing: rust {:?} node {}",
            missing, node["reads"]["awsMissing"]["refused"]
        ));
    }

    // THE KEYS: every data key Node wrapped, unwrapped, and ours for Node.
    let gcp_key =
        "projects/iya-probe/locations/global/keyRings/sts/cryptoKeys/sts-kek";
    let kms: &[(&str, &str, &str, &str)] = &[
        ("aws-kms", "aws-kms", "alias/sts-kek", ""),
        ("gcp-kms", "gcp-kms", gcp_key, ""),
        ("azure-rsa", "azure-keys", "sts-kek-rsa", &vault),
        ("azure-oct", "azure-keys", "sts-kek-oct", &fake),
    ];
    let mut ours = serde_json::Map::new();
    for (name, provider, ref_, at) in kms {
        let s = secrets(&[
            ("STS_KEYS_KEK_PROVIDER", provider),
            ("STS_KEYS_KEK_REF", ref_),
            ("STS_KEYS_KEK_VAULT", at),
        ]);
        let Secret::Remote(handle) = s.read(&KEK).await.unwrap() else {
            panic!("{} answered no handle", name);
        };
        let theirs = &node["kms"][name];
        if json!(handle.key_ref()) != theirs["keyRef"]
            || json!(handle.label()) != theirs["label"]
            || json!(handle.provider()) != theirs["provider"]
        {
            failures.push(format!(
                "{}: rust {} / {} node {} / {}",
                name,
                handle.key_ref(),
                handle.label(),
                theirs["keyRef"],
                theirs["label"]
            ));
        }
        let mut wrapped = Vec::new();
        for one in theirs["wrapped"].as_array().unwrap() {
            let text = one["text"].as_str().unwrap();
            let aad = one["aad"].as_str().unwrap();
            if json!(handle.owns(text)) != one["owns"]
                || json!(handle.is_stale(text)) != one["stale"]
            {
                failures.push(format!("{} {}: owns/isStale differ", name, aad));
            }
            match handle.unwrap(text, aad).await {
                Ok(dek) if hex(&dek) == one["dek"].as_str().unwrap() => {}
                other => failures
                    .push(format!("{} {}: unwrapped {:?}", name, aad, other)),
            }
            let again = handle
                .wrap(&unhex(one["dek"].as_str().unwrap()), aad)
                .await
                .unwrap();
            assert!(handle.owns(&again), "{}", again);
            wrapped.push(json!({"dek": one["dek"], "aad": aad, "text": again}));
        }
        let first = &theirs["wrapped"][0];
        let wrong = handle
            .unwrap(
                first["text"].as_str().unwrap(),
                &format!("{}x", first["aad"].as_str().unwrap()),
            )
            .await;
        if wrong.is_ok() || theirs["wrongAad"] == json!(false) {
            failures.push(format!("{}: a changed AAD was unwrapped", name));
        }
        // A rotation (#391 P5): a new version where the KMS keeps them, and
        // what was wrapped before it stale — except AWS's, which keeps the
        // earlier material behind the same id.
        let before = wrapped[0]["text"].as_str().unwrap().to_string();
        let rotated = handle.rotate().await;
        match &rotated {
            Ok(version) => {
                let stale = handle.is_stale(&before);
                if stale != (*provider != "aws-kms") {
                    failures.push(format!(
                        "{}: rotated to {:?}, earlier wrap stale {}",
                        name, version, stale
                    ));
                }
                let dek = unhex(wrapped[0]["dek"].as_str().unwrap());
                let aad = wrapped[0]["aad"].as_str().unwrap().to_string();
                let after = handle.wrap(&dek, &aad).await.unwrap();
                assert!(!handle.is_stale(&after));
                wrapped
                    .push(json!({"dek": hex(&dek), "aad": aad, "text": after}));
            }
            Err(e) => {
                eprintln!("{}: the emulator refused a rotation: {:?}", name, e)
            }
        }
        eprintln!(
            "{}: {} Node-wrapped data keys unwrapped, {} wrapped for Node, \
             rotation {:?}",
            name,
            theirs["wrapped"].as_array().unwrap().len(),
            wrapped.len(),
            rotated
        );
        ours.insert(name.to_string(), json!({"wrapped": wrapped}));
    }

    // THE REQUESTS the oct-HSM key saw: the same shapes from both.
    let log = std::fs::read_to_string(dir.join("fake-vault-requests.jsonl"))
        .unwrap_or_default();
    let mut shapes: HashMap<&str, std::collections::BTreeSet<String>> =
        HashMap::new();
    let lines: Vec<Json> = log
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    for one in &lines {
        let agent = one["agent"].as_str().unwrap_or("");
        let who = if agent.contains("rust") {
            "rust"
        } else {
            "node"
        };
        shapes.entry(who).or_default().insert(format!(
            "{} {} {} aad={}",
            one["op"],
            one["alg"],
            one["keys"],
            !one["aad"].is_null()
        ));
    }
    if shapes.get("rust") != shapes.get("node") {
        failures.push(format!("oct-HSM requests differ: {:?}", shapes));
    }
    std::fs::write(
        dir.join("secrets-cloud-rust.json"),
        json!({"kms": ours}).to_string(),
    )
    .unwrap();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
