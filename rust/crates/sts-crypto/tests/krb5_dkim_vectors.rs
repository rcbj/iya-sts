// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The Kerberos PRF family, `session_state` and DKIM against Node:
//! `krb5-dkim-node.json`, which `tests/tools/crypto-vectors.js` writes. All
//! of it is deterministic, so every answer must be Node's bytes: n-fold,
//! the PRF and PRF+ for every enctype, KRB-FX-CF2 across every pair of
//! enctypes, `session_state`, and DKIM signatures in both algorithms — each
//! of which must also verify here, as Rust's verify in Node's verifier
//! (the field is the same string).
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed; with it unset
//! this test says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use openssl::pkey::PKey;
use serde_json::Value as Json;
use sts_crypto::dkim::{self, DkimOptions};
use sts_crypto::krb5_prf;

fn s(v: &Json) -> &str {
    v.as_str().unwrap()
}

fn b64(v: &Json) -> Vec<u8> {
    STANDARD.decode(s(v)).unwrap()
}

#[test]
fn kerberos_and_dkim_match_node() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: krb5-dkim-node.json is not checked"
        );
        return;
    };
    let path = std::path::Path::new(&dir).join("krb5-dkim-node.json");
    let v: Json =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut failures = Vec::new();
    let mut checked = 0;
    let mut check = |ok: bool, what: String| {
        checked += 1;
        if !ok {
            failures.push(what);
        }
    };
    for n in v["nfold"].as_array().unwrap() {
        let out = krb5_prf::nfold(
            &b64(&n["input"]),
            n["bytes"].as_u64().unwrap() as usize,
        );
        check(out == b64(&n["out"]), format!("nfold {}", n));
    }
    for p in v["prf"].as_array().unwrap() {
        let etype = p["etype"].as_i64().unwrap() as i32;
        let (key, input) = (b64(&p["key"]), b64(&p["input"]));
        check(
            krb5_prf::prf(etype, &key, &input).unwrap() == b64(&p["out"]),
            format!("prf {}", etype),
        );
        check(
            krb5_prf::prf_plus(etype, &key, &input, 77).unwrap()
                == b64(&p["plus"]),
            format!("prf+ {}", etype),
        );
    }
    for c in v["cf2"].as_array().unwrap() {
        let (e1, e2) = (
            c["etype1"].as_i64().unwrap() as i32,
            c["etype2"].as_i64().unwrap() as i32,
        );
        let (etype, key) = krb5_prf::krb_fx_cf2(
            (e1, &b64(&c["key1"])),
            (e2, &b64(&c["key2"])),
            b"armorkey",
            b"ticketarmor",
        )
        .unwrap();
        check(
            etype == e1 && key == b64(&c["out"]),
            format!("cf2 {} {}", e1, e2),
        );
    }
    for st in v["sessionStates"].as_array().unwrap() {
        let a: Vec<&str> =
            st["args"].as_array().unwrap().iter().map(s).collect();
        let out =
            krb5_prf::session_state_hash(a[0], a[1], a[2], Some(a[3])).unwrap();
        check(out == s(&st["out"]), format!("session_state {:?}", a));
    }
    for d in v["dkim"].as_array().unwrap() {
        let alg = s(&d["algorithm"]);
        let which = if alg == "rsa-sha256" {
            "rsa"
        } else {
            "ed25519"
        };
        let keys = &v["dkimKeys"][which];
        let key =
            PKey::private_key_from_pem(s(&keys["privateKeyPem"]).as_bytes())
                .unwrap();
        let message = b64(&d["message"]);
        let field = dkim::dkim_sign(
            &message,
            &key,
            &DkimOptions {
                selector: "s2026",
                domain: "mail.example.com",
                algorithm: Some(alg),
                timestamp: Some(1791100000),
            },
        )
        .unwrap();
        check(
            field == s(&d["field"]),
            format!(
                "{}: signed differently\n node {}\n rust {}",
                s(&d["name"]),
                s(&d["field"]),
                field
            ),
        );
        let mut signed = format!("{}\r\n", s(&d["field"])).into_bytes();
        signed.extend(&message);
        check(
            dkim::dkim_verify(&signed, s(&keys["publicKeyPem"])).is_ok()
                == d["verified"]["ok"].as_bool().unwrap(),
            format!("{}: Node's signature, verified here", s(&d["name"])),
        );
    }
    assert!(
        failures.is_empty(),
        "{} differences:\n{}",
        failures.len(),
        failures.join("\n")
    );
    eprintln!("{} answers identical to Node's", checked);
}
