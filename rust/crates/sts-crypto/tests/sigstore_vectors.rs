// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Sigstore and TUF against Node, both ways: `sigstore-node.json`, which
//! `tests/tools/crypto-vectors.js` writes, and — with `STS_WRITE_VECTORS` —
//! `sigstore-rust.json`, whose TUF signatures and Rekor SET
//! `tests/rust_crypto_vectors.js` verifies in Node.
//!
//! * both canonical forms are Node's strings, OLPC's refusals included;
//! * every TUF threshold verdict is Node's — keys of every kind, a keyid
//!   twice, one the role does not name, tampered and odd-length hex,
//!   thresholds `Number()` reads oddly;
//! * every Rekor SET answer is Node's text;
//! * DSSE PAE, SHA-256 and SHA-512 are Node's bytes.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed; with it unset
//! this test says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use serde_json::{json, Value as Json};
use sts_crypto::{pq_x509, sigstore};

fn b64(v: &Json) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// A JSON number as Node wrote it: NaN is `null`.
fn same_number(rust: f64, node: &Json) -> bool {
    match node.as_f64() {
        Some(n) => n == rust,
        None => rust.is_nan(),
    }
}

#[test]
fn sigstore_and_tuf_match_node() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: sigstore-node.json is not checked"
        );
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let v: Json = serde_json::from_str(
        &std::fs::read_to_string(dir.join("sigstore-node.json")).unwrap(),
    )
    .unwrap();
    let mut failures = Vec::new();
    let mut checked = 0;
    let mut check = |ok: bool, what: String| {
        checked += 1;
        if !ok {
            failures.push(what);
        }
    };

    for row in v["canonical"].as_array().unwrap() {
        let value = &row["value"];
        check(
            sigstore::jcs_canonical_json(value) == row["jcs"].as_str().unwrap(),
            format!("JCS of {}", value),
        );
        match (sigstore::olpc_canonical_json(value), row["olpc"].as_str()) {
            (Ok(mine), Some(node)) => {
                check(mine == node, format!("OLPC of {}", value))
            }
            (Err(e), None) => check(
                e == row["olpcError"].as_str().unwrap(),
                format!("OLPC refusal of {}", value),
            ),
            _ => check(false, format!("OLPC of {}: one refused", value)),
        }
    }

    for row in v["threshold"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let t = sigstore::verify_threshold_signatures(
            &v["signed"],
            &row["signatures"],
            &v["keys"],
            &row["role"],
        );
        check(
            t.ok == row["ok"].as_bool().unwrap()
                && t.valid as u64 == row["valid"].as_u64().unwrap()
                && same_number(t.threshold, &row["threshold"]),
            format!("threshold {}: {:?}", name, t),
        );
    }

    let rekor = &v["rekor"];
    let set = b64(&rekor["set"]);
    let logs: Vec<sigstore::RekorLog> = rekor["logs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| sigstore::RekorLog {
            log_id_hex: l["logIdHex"].as_str().unwrap().to_string(),
            spki: b64(&l["spki"]),
        })
        .collect();
    for row in rekor["cases"].as_array().unwrap() {
        let answer = sigstore::verify_rekor_set(&row["payload"], &set, &logs)
            .unwrap_or_default();
        check(
            answer == row["answer"].as_str().unwrap(),
            format!("Rekor {}: {}", row["name"], answer),
        );
    }

    for row in v["pae"].as_array().unwrap() {
        let payload = row["payload"].as_str().unwrap().as_bytes();
        check(
            sigstore::dsse_pae(row["type"].as_str().unwrap(), payload)
                == b64(&row["pae"])
                && sigstore::sha256_hex(payload) == row["sha256"]
                && sigstore::sha512_hex(payload) == row["sha512"],
            format!("PAE and hashes of {} bytes", payload.len()),
        );
    }
    let pq_spki = b64(&v["pqSpki"]);
    check(
        sigstore::public_key_pem_of_spki(&pq_spki) == v["spkiPem"],
        "the PEM of an SPKI".to_string(),
    );
    check(
        sigstore::spki_from_public_key_pem(v["spkiPem"].as_str().unwrap())
            == Some(pq_spki),
        "the SPKI of a PEM".to_string(),
    );

    if std::env::var("STS_WRITE_VECTORS").is_ok() {
        std::fs::write(
            dir.join("sigstore-rust.json"),
            serde_json::to_string_pretty(&rust_signed()).unwrap(),
        )
        .unwrap();
    }
    assert!(
        failures.is_empty(),
        "{} differences:\n{}",
        failures.len(),
        failures.join("\n")
    );
    eprintln!("{} answers as Node gives them", checked);
}

/// TUF metadata signed here by a key of each kind, and a Rekor SET.
fn rust_signed() -> Json {
    let signed = json!({"_type": "targets", "version": 3,
        "note": "ctl\u{1} caf\u{e9} \"q\" \\", "targets": {"b": 1, "a": [2]}});
    let bytes = sigstore::olpc_canonical_json(&signed).unwrap();
    let sign = |key: &PKey<openssl::pkey::Private>,
                md: Option<MessageDigest>| {
        let mut s = match md {
            Some(md) => Signer::new(md, key).unwrap(),
            None => Signer::new_without_digest(key).unwrap(),
        };
        s.sign_oneshot_to_vec(bytes.as_bytes()).unwrap()
    };
    let pem = |key: &PKey<openssl::pkey::Private>| {
        String::from_utf8(key.public_key_to_pem().unwrap()).unwrap()
    };
    let ed = PKey::generate_ed25519().unwrap();
    let ec = PKey::from_ec_key(
        EcKey::generate(
            &EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let rsa = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let (pq_pub, pq_priv) = pq_x509::generate_key_pair("ML-DSA-65").unwrap();
    let keys = json!({
        "ed": {"keytype": "ed25519", "scheme": "ed25519",
               "keyval": {"public": hex(&ed.raw_public_key().unwrap())}},
        "ec": {"keytype": "ecdsa", "scheme": "ecdsa-sha2-nistp256",
               "keyval": {"public": pem(&ec)}},
        "rsa": {"keytype": "rsa", "scheme": "rsassa-pkcs1v15-sha256",
                "keyval": {"public": pem(&rsa)}},
        "pq": {"keytype": "ml-dsa", "scheme": "ml-dsa-65",
               "keyval": {"public": pq_x509::public_pem("ML-DSA-65", &pq_pub)
                   .unwrap()}},
    });
    let signatures = json!([
        {"keyid": "ed", "sig": hex(&sign(&ed, None))},
        {"keyid": "ec", "sig": hex(&sign(&ec, Some(MessageDigest::sha256())))},
        {"keyid": "rsa", "sig": hex(&sign(&rsa, Some(MessageDigest::sha256())))},
        {"keyid": "pq", "sig": hex(&pq_x509::sign("ML-DSA-65", bytes.as_bytes(),
                                                    &pq_priv).unwrap())},
    ]);

    let log = PKey::from_ec_key(
        EcKey::generate(
            &EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let spki = log.public_key_to_der().unwrap();
    let log_id = sigstore::sha256_hex(&spki);
    let payload = json!({"body": "eyJhIjoiXHUwMDAxIn0=",
        "integratedTime": 1700000001u64, "logIndex": 42u64, "logID": log_id});
    let canonical = sigstore::jcs_canonical_json(&payload);
    let mut s = Signer::new(MessageDigest::sha256(), &log).unwrap();
    let set = s.sign_oneshot_to_vec(canonical.as_bytes()).unwrap();
    json!({
        "signed": signed, "keys": keys, "signatures": signatures,
        "role": {"keyids": ["ed", "ec", "rsa", "pq"], "threshold": 4},
        "olpc": bytes,
        "rekor": {"payload": payload, "set": STANDARD.encode(set),
                  "logs": [{"logIdHex": log_id, "spki": STANDARD.encode(spki)}],
                  "jcs": canonical},
    })
}
