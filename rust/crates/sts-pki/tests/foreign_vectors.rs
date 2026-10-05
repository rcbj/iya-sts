// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Somebody else's certificates against Node: `foreign-node.json`, which
//! `tests/tools/crypto-vectors.js` writes — a PEM bundle described, WebAuthn
//! attestation certificate facts, OpenSSH keys, signatures, host
//! certificates and authorized_keys lines, FIDO MDS3 BLOBs good, broken and
//! overridden, a sigstore signer's facts and embedded SCTs. Each answer here
//! is Node's.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed; with it unset
//! this test says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value as Json};
use sts_pki::foreign::{self, CtLog};

fn b64(v: &Json) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}

#[test]
fn foreign_certificates_match_node() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: foreign-node.json is not checked"
        );
        return;
    };
    let path = std::path::Path::new(&dir).join("foreign-node.json");
    let v: Json =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let now = v["now"].as_i64().unwrap();
    let mut failures = Vec::new();
    let mut checked = 0;
    let mut check = |ok: bool, what: String| {
        checked += 1;
        if !ok {
            failures.push(what);
        }
    };

    let described = foreign::describe_certificate_bundle(
        v["bundle"]["text"].as_str().unwrap(),
        now,
    );
    check(
        described == v["bundle"]["described"],
        format!("the bundle:\n{}\n{}", described, v["bundle"]["described"]),
    );

    for (name, row) in v["attestation"].as_object().unwrap() {
        let der = b64(&row["der"]);
        let mut mine = foreign::attestation_certificate_facts(&der).unwrap();
        let mut theirs = row["facts"].clone();
        // A post-quantum key: node exports a JWK of its own (`AKP`) that
        // nothing here asks for; the type is compared.
        if theirs["keyType"]
            .as_str()
            .is_some_and(|t| t.starts_with("ml-") || t.starts_with("slh-"))
        {
            mine["publicKeyJwk"] = Json::Null;
            theirs["publicKeyJwk"] = Json::Null;
        }
        check(
            mine == theirs,
            format!("attestation {}:\n{}\n{}", name, mine, theirs),
        );
        check(
            foreign::attestation_key_identifier(&der) == row["keyIdentifier"],
            format!("attestation {}: the key identifier", name),
        );
        let entry = sts_pki::path::Entry::from_der(&der).unwrap();
        check(
            json!(foreign::rsa_key_bits(&entry)) == row["rsaBits"],
            format!("attestation {}: RSA bits", name),
        );
    }

    let ssh = &v["ssh"];
    for row in ssh["keys"].as_array().unwrap() {
        let key = foreign::parse_ssh_public_key(&b64(&row["blob"])).unwrap();
        let t = row["type"].as_str().unwrap();
        check(
            foreign::ssh_fingerprint(&key) == row["fingerprint"],
            format!("ssh {}: fingerprint", t),
        );
        check(
            key.curve == row["curve"].as_str().unwrap_or(""),
            format!("ssh {}: curve", t),
        );
        let data = b64(&row["data"]);
        for sig in row["signatures"].as_array().unwrap() {
            let format = sig["format"].as_str().unwrap();
            let blob = b64(&sig["blob"]);
            check(
                foreign::verify_ssh_signature(&key, &data, format, &blob)
                    == sig["ok"].as_bool().unwrap(),
                format!("ssh {} {}: the signature", t, format),
            );
            check(
                foreign::verify_ssh_signature(
                    &key,
                    &data,
                    "ssh-ed25519x",
                    &blob,
                ) == sig["wrongFormat"].as_bool().unwrap(),
                format!("ssh {} {}: under the wrong format", t, format),
            );
        }
    }
    let authorities: Vec<_> = ssh["authorityBlobs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| foreign::parse_ssh_public_key(&b64(b)).unwrap())
        .collect();
    for row in ssh["certs"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        match foreign::parse_ssh_public_key(&b64(&row["blob"])) {
            Err(e) => check(
                row["error"] == e.as_str(),
                format!("ssh cert {}: refused as Node: {}", name, e),
            ),
            Ok(key) => {
                let c = key.cert.as_ref().unwrap();
                let options = |o: &[(String, String)]| {
                    Json::Object(
                        o.iter().map(|(k, v)| (k.clone(), json!(v))).collect(),
                    )
                };
                let mine = json!({
                    "type": key.key_type, "certType": c.cert_type, "serial": c.serial.to_string(),
                    "kind": c.kind, "keyId": c.key_id, "principals": c.principals,
                    "validAfter": c.valid_after.to_string(), "validBefore": c.valid_before.to_string(),
                    "criticalOptions": options(&c.critical_options), "extensions": options(&c.extensions),
                    "fingerprint": foreign::ssh_fingerprint(&key),
                    "authority": foreign::ssh_fingerprint(&c.signature_key),
                });
                check(
                    mine == row["parsed"],
                    format!("ssh cert {}:\n{}\n{}", name, mine, row["parsed"]),
                );
                let verdict = foreign::check_ssh_host_certificate(
                    &key,
                    "host.example",
                    &authorities,
                    now as f64 / 1000.0,
                );
                check(
                    row["check"] == verdict.as_str(),
                    format!(
                        "ssh cert {}: {} vs {}",
                        name, verdict, row["check"]
                    ),
                );
            }
        }
    }
    for row in ssh["authorized"].as_array().unwrap() {
        let mine =
            foreign::parse_ssh_authorized_key(row["line"].as_str().unwrap())
                .map(|k| foreign::ssh_fingerprint(&k));
        check(
            json!(mine) == row["fingerprint"],
            format!("authorized_keys {}", row["line"]),
        );
    }

    for row in v["mds"].as_array().unwrap() {
        if row["verdict"].is_null() {
            continue;
        }
        let name = row["name"].as_str().unwrap();
        let (anchors, _) =
            foreign::certificate_bundle(row["anchors"].as_str().unwrap());
        let mine = foreign::verify_fido_mds_blob(
            row["token"].as_str().unwrap(),
            &anchors,
            now,
            row["override"].as_bool().unwrap(),
        );
        check(
            mine == row["verdict"],
            format!("MDS {}:\n{}\n{}", name, mine, row["verdict"]),
        );
    }

    let facts =
        foreign::sigstore_signer_facts(&b64(&v["sigstore"]["der"])).unwrap();
    check(
        facts == v["sigstore"]["facts"],
        format!("sigstore facts:\n{}\n{}", facts, v["sigstore"]["facts"]),
    );
    let issuer = b64(&v["scts"]["issuer"]);
    for row in v["scts"]["cases"].as_array().unwrap() {
        let logs: Vec<CtLog> = row["logs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| CtLog {
                log_id_hex: l["logIdHex"].as_str().unwrap().to_string(),
                spki: b64(&l["spki"]),
                start_ms: l["startMs"].as_i64(),
                end_ms: None,
            })
            .collect();
        let (ok, why) =
            foreign::verify_embedded_scts(&b64(&row["leaf"]), &issuer, &logs);
        check(
            json!({ "ok": ok, "why": why }) == row["verdict"],
            format!("SCT {}: {} {}", row["name"], why, row["verdict"]),
        );
    }

    assert!(
        failures.is_empty(),
        "{} differences:\n{}",
        failures.len(),
        failures.join("\n")
    );
    eprintln!("{} answers as Node gives them", checked);
}
