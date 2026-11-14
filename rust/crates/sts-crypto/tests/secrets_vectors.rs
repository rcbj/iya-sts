// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The secrets against Node, both ways: `secrets-node.json`, which
//! `tests/tools/crypto-vectors.js` writes, and — with `STS_WRITE_VECTORS`
//! — `secrets-rust.json`, which `tests/rust_crypto_vectors.js` checks in
//! Node. HOTP codes, the derived data keys and ids, the key-encryption
//! key's reading and the shared credentials must be the same bytes; scrypt
//! hashes, envelopes and wrapped keys are random, so each side opens the
//! other's.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed; with it unset
//! this test says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value as Json};
use sts_crypto::secrets::{
    self, KekInput, PasswordHashAsk, PasswordHashSpec, ScryptCost,
    StoredParameters,
};

fn s(v: &Json) -> &str {
    v.as_str().unwrap()
}

fn b64(v: &Json) -> Vec<u8> {
    STANDARD.decode(s(v)).unwrap()
}

/// A policy's number as `clampInt()` reads it: absent, null or empty is no
/// value; anything else is JavaScript's `Number()` of it.
fn number(v: &Json) -> Option<f64> {
    match v {
        Json::Null => None,
        Json::Number(n) => n.as_f64(),
        Json::String(t) if t.is_empty() => None,
        Json::String(t) => Some(t.trim().parse().unwrap_or(f64::NAN)),
        _ => Some(f64::NAN),
    }
}

fn ask_of(v: &Json) -> PasswordHashAsk {
    PasswordHashAsk {
        algorithm: v["algorithm"].as_str().map(str::to_string),
        memory: number(&v["memory"]),
        passes: number(&v["passes"]),
        parallelism: number(&v["parallelism"]),
        log_n: number(&v["logN"]),
        r: number(&v["r"]),
        p: number(&v["p"]),
    }
}

fn spec_json(spec: PasswordHashSpec) -> Json {
    match spec {
        PasswordHashSpec::Argon2id {
            memory,
            passes,
            parallelism,
        } => json!({ "algorithm": "argon2id", "memory": memory,
                     "passes": passes, "parallelism": parallelism }),
        PasswordHashSpec::Scrypt { log_n, r, p } => {
            json!({ "algorithm": "scrypt", "logN": log_n, "r": r, "p": p })
        }
    }
}

fn params_match(params: Option<StoredParameters>, node: &Json) -> bool {
    match params {
        None => node.is_null(),
        Some(StoredParameters::Argon2id {
            memory,
            passes,
            parallelism,
            keylen,
        }) => {
            *node
                == json!({ "algorithm": "argon2id", "memory": memory,
                           "passes": passes, "parallelism": parallelism,
                           "keylen": keylen })
        }
        Some(StoredParameters::Scrypt { n, r, p, keylen }) => {
            node["algorithm"] == "scrypt"
                && ((n as f64).log2() - node["logN"].as_f64().unwrap()).abs()
                    < 1e-12
                && node["r"] == r
                && node["p"] == p
                && node["keylen"] == keylen
        }
    }
}

#[test]
fn secrets_match_node() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: secrets-node.json is not checked"
        );
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let v: Json = serde_json::from_str(
        &std::fs::read_to_string(dir.join("secrets-node.json")).unwrap(),
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

    for h in v["hotp"].as_array().unwrap() {
        let code = secrets::hotp_code(
            &b64(&h["key"]),
            h["counter"].as_u64().unwrap(),
            Some(h["digits"].as_u64().unwrap() as u32),
            Some(s(&h["algorithm"])),
        )
        .unwrap();
        check(code == s(&h["code"]), format!("hotp {}", h));
    }
    let mut hashes = Vec::new();
    for h in v["hashes"].as_array().unwrap() {
        let plain = s(&h["plain"]);
        check(
            secrets::verify_secret(plain, s(&h["stored"])),
            format!("Node's hash of {:?}", plain),
        );
        check(
            !secrets::verify_secret(&format!("{}x", plain), s(&h["stored"])),
            format!("a wrong secret against {:?}", plain),
        );
        let ours = secrets::hash_secret(plain, ScryptCost::default()).unwrap();
        hashes.push(json!({ "plain": plain, "stored": ours }));
    }
    let mut envelopes = Vec::new();
    for e in v["envelopes"].as_array().unwrap() {
        let key = b64(&e["key"]);
        let opened =
            secrets::decrypt_with_dek(&key, s(&e["sealed"]), Some("vectors"));
        check(
            opened.as_deref().ok() == Some(s(&e["plain"])),
            format!("Node's {} envelope", s(&e["alg"])),
        );
        check(
            secrets::dek_id_of(s(&e["sealed"])) == Some(s(&e["id"])),
            format!("the {} envelope's id", s(&e["alg"])),
        );
        let ours = secrets::encrypt_with_dek(
            s(&e["id"]),
            &key,
            s(&e["plain"]),
            Some("vectors"),
        )
        .unwrap();
        envelopes.push(json!({ "alg": e["alg"], "key": e["key"], "plain": e["plain"], "sealed": ours }));
    }
    let mut wraps = Vec::new();
    for w in v["wraps"].as_array().unwrap() {
        let kek = s(&w["kek"]);
        let dek = secrets::unwrap_dek(
            KekInput::Text(kek),
            s(&w["wrapped"]),
            s(&w["aad"]),
        );
        check(
            dek.as_deref().ok() == Some(&b64(&w["dek"])[..]),
            format!("Node's wrap under {:?}", kek),
        );
        let ours = secrets::wrap_dek(
            KekInput::Text(kek),
            &b64(&w["dek"]),
            s(&w["aad"]),
        )
        .unwrap();
        wraps.push(json!({ "kek": kek, "aad": w["aad"], "dek": w["dek"], "wrapped": ours }));
    }
    for d in v["derived"].as_array().unwrap() {
        let kek = s(&d["kek"]);
        let bytes = secrets::kek_bytes(KekInput::Text(kek)).unwrap();
        check(bytes == b64(&d["kekBytes"]), format!("kekBytes({:?})", kek));
        let (id, key) =
            secrets::derive_dek(KekInput::Text(kek), s(&d["context"])).unwrap();
        check(
            id == s(&d["id"]) && key == b64(&d["key"]),
            format!("deriveDek under {:?}", kek),
        );
    }
    for r in v["kekRefusals"].as_array().unwrap() {
        let refused = secrets::kek_bytes(KekInput::Text(s(&r["kek"]))).is_err();
        check(
            refused == r["refused"].as_bool().unwrap(),
            format!("kekBytes refusal {}", r),
        );
    }
    for c in v["credentials"].as_array().unwrap() {
        let parts: Vec<&str> =
            c["parts"].as_array().unwrap().iter().map(s).collect();
        let ours = secrets::derive_shared_credential(
            s(&c["secret"]),
            s(&c["label"]),
            &parts,
        )
        .unwrap();
        check(
            ours == s(&c["credential"]),
            format!("deriveSharedCredential {}", c),
        );
    }

    // A PERSON'S PASSWORD (#847, #872).
    let asks: Vec<PasswordHashAsk> = v["passwordAsks"]
        .as_array()
        .unwrap()
        .iter()
        .map(ask_of)
        .collect();
    for row in v["passwordSpecs"].as_array().unwrap() {
        let spec = secrets::password_hash_spec(&ask_of(&row["ask"]));
        check(
            spec_json(spec) == row["spec"],
            format!("passwordHashSpec({}) = {:?}", row["ask"], spec),
        );
    }
    let mut passwords = Vec::new();
    for row in v["passwords"].as_array().unwrap() {
        let plain = s(&row["plain"]);
        let stored = s(&row["stored"]);
        check(
            secrets::verify_secret(plain, stored),
            format!("Node's password hash {:?}", &stored[..20]),
        );
        check(
            !secrets::verify_secret(&format!("{}x", plain), stored),
            format!("a wrong password against {:?}", &stored[..20]),
        );
        let ask = ask_of(&row["ask"]);
        let ours = secrets::hash_password(plain, &ask).unwrap();
        check(
            secrets::stored_secret_matches_spec(&ours, &ask),
            format!("Rust's hash under {} matches its own spec", row["ask"]),
        );
        passwords
            .push(json!({ "ask": row["ask"], "plain": plain, "stored": ours }));
    }
    for row in v["storedSecrets"].as_array().unwrap() {
        let stored = s(&row["stored"]);
        check(
            secrets::is_hashed_secret(stored) == row["hashed"],
            format!("isHashedSecret({:?})", stored),
        );
        let params = secrets::stored_secret_parameters(stored);
        check(
            params_match(params, &row["parameters"]),
            format!("storedSecretParameters({:?}) = {:?}", stored, params),
        );
        for (i, ask) in asks.iter().enumerate() {
            check(
                secrets::stored_secret_matches_spec(stored, ask)
                    == row["matches"][i],
                format!("storedSecretMatchesSpec({:?}, {:?})", stored, ask),
            );
            check(
                secrets::stored_secret_is_weaker(stored, ask)
                    == row["weaker"][i],
                format!("storedSecretIsWeaker({:?}, {:?})", stored, ask),
            );
        }
    }
    for row in v["credentialDigests"].as_array().unwrap() {
        check(
            secrets::credential_digest(s(&row["value"])).unwrap()
                == s(&row["digest"]),
            format!("credentialDigest({:?})", s(&row["value"])),
        );
    }

    if std::env::var("STS_WRITE_VECTORS").is_ok() {
        std::fs::write(
            dir.join("secrets-rust.json"),
            serde_json::to_string_pretty(&json!({
                "hashes": hashes, "envelopes": envelopes, "wraps": wraps,
                "passwords": passwords,
            }))
            .unwrap(),
        )
        .unwrap();
    }
    assert!(
        failures.is_empty(),
        "{} differences:\n{}",
        failures.len(),
        failures.join("\n")
    );
    eprintln!("{} checks as Node computes them", checked);
}
