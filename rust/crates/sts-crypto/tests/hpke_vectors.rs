// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! HPKE and the hybrid KEMs against the drafts' published vectors — the
//! files `tests/tools/fetch-vectors.sh` fetches (checksummed) into
//! `tests/vectors/hpke/` for `tests/jwe_pq_kem.js`. This repository commits
//! no key material, so the vectors are not in it: point `STS_HPKE_DIR` at
//! the fetched directory, and with it unset this test says so and passes.
//!
//! As in Node, the vectors are checked from the RECEIVING side: their Encap
//! used a given randomness, which OpenSSL's ML-KEM does not accept.

#![allow(clippy::unwrap_used)] // a test file

use serde_json::Value as Json;
use sts_crypto::hpke::{
    aead, kem, key_schedule, SetupOptions, Suite, MLKEM1024_P384,
    MLKEM768_P256, MLKEM768_X25519, MODE_BASE,
};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn read(name: &str) -> Option<Json> {
    let dir = std::env::var("STS_HPKE_DIR").ok()?;
    let text = std::fs::read_to_string(format!("{}/{}", dir, name)).ok()?;
    serde_json::from_str(&text).ok()
}

fn field(v: &Json, name: &str) -> Vec<u8> {
    hex(v[name].as_str().unwrap_or(""))
}

#[test]
fn hpke_pq_vectors_from_the_receiving_side() {
    let Some(Json::Array(vectors)) = read("hpke-pq.json") else {
        eprintln!("STS_HPKE_DIR is not set: the HPKE vectors are not run");
        return;
    };
    let mut checked = 0;
    for v in &vectors {
        let suite = Suite {
            kem: v["kem_id"].as_u64().unwrap() as u16,
            kdf: v["kdf_id"].as_u64().unwrap() as u16,
            aead: v["aead_id"].as_u64().unwrap() as u16,
        };
        let name = format!("{:?}", suite);
        assert_eq!(v["mode"].as_u64(), Some(u64::from(MODE_BASE)));
        let kem = kem(suite.kem).unwrap();
        let (sk, pk) = kem.derive_key_pair(&field(v, "ikmR")).unwrap();
        assert_eq!(sk, field(v, "skRm"), "{}: skR", name);
        assert_eq!(pk, field(v, "pkRm"), "{}: pkR", name);
        let ss = kem.decap(&field(v, "enc"), &sk).unwrap();
        assert_eq!(ss, field(v, "shared_secret"), "{}: shared secret", name);
        let info = field(v, "info");
        let mut context = key_schedule(
            suite,
            MODE_BASE,
            &ss,
            &SetupOptions {
                info: &info,
                ..SetupOptions::default()
            },
        )
        .unwrap();
        assert_eq!(context.key, field(v, "key"), "{}: key", name);
        assert_eq!(context.base_nonce, field(v, "base_nonce"), "{}", name);
        assert_eq!(
            context.exporter_secret,
            field(v, "exporter_secret"),
            "{}: exporter secret",
            name
        );
        if aead(suite.aead).unwrap().nk > 0 {
            for e in v["encryptions"].as_array().unwrap() {
                let pt = context.open(&field(e, "aad"), &field(e, "ct"));
                assert_eq!(pt.unwrap(), field(e, "pt"), "{}: open", name);
            }
        }
        for x in v["exports"].as_array().unwrap() {
            let out = context
                .export(
                    &field(x, "exporter_context"),
                    x["L"].as_u64().unwrap() as usize,
                )
                .unwrap();
            assert_eq!(out, field(x, "exported_value"), "{}: export", name);
        }
        checked += 1;
    }
    assert_eq!(checked, vectors.len());
}

#[test]
fn concrete_hybrid_kem_vectors() {
    let Some(file) = read("concrete-hybrid-kems.json") else {
        eprintln!(
            "STS_HPKE_DIR is not set: the hybrid KEM vectors are not run"
        );
        return;
    };
    for (name, hybrid) in [
        ("mlkem768_p256", MLKEM768_P256),
        ("mlkem768_x25519", MLKEM768_X25519),
        ("mlkem1024_p384", MLKEM1024_P384),
    ] {
        for v in file[name].as_array().unwrap() {
            let seed = field(v, "seed");
            let keys = hybrid.expand(&seed).unwrap();
            assert_eq!(keys.ek, field(v, "encapsulation_key"), "{}: ek", name);
            assert_eq!(
                keys.seed_pq,
                field(v, "decapsulation_key_pq"),
                "{}",
                name
            );
            assert_eq!(keys.dk_t, field(v, "decapsulation_key_t"), "{}", name);
            let ss = hybrid.decaps(&seed, &field(v, "ciphertext")).unwrap();
            assert_eq!(ss, field(v, "shared_secret"), "{}: ss", name);
        }
    }
}
