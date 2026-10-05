// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! WebAuthn's COSE signatures and attestation structures against Node:
//! `webauthn-node.json`, which `tests/tools/crypto-vectors.js` writes.
//!
//! * every verdict `verifyCoseSignature()` gave — 24 keys over the 20
//!   algorithms, with and without the insecure flag, tampered, under
//!   another algorithm's key, a fully specified algorithm on the wrong
//!   curve, a 1024-bit RSA key under development's policy — is given here;
//! * every TPM structure and extension reads as Node reads it, field for
//!   field, and every refusal is Node's sentence;
//! * a TPMT_SIGNATURE's ECDSA value carries Node's integers, but as
//!   MINIMAL DER where Node's asn1js keeps a leading zero (the defect
//!   `webauthn.rs` names), which this checks rather than tolerates.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed; with it unset
//! this test says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value as Json};
use sts_crypto::der_lite as der;
use sts_crypto::keys::KeyPolicy;
use sts_crypto::webauthn::{self, CoseKey, CoseOptions};

fn b64(v: &Json) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}

/// An ECDSA DER signature's two integers, leading zeros dropped, and
/// whether each was minimal.
fn integers(sig: &[u8]) -> (Vec<Vec<u8>>, bool) {
    let parts = der::children(der::read(sig).unwrap().content).unwrap();
    let mut minimal = true;
    let ints = parts
        .iter()
        .map(|p| {
            let c = p.content;
            if c.len() > 1 && c[0] == 0 && c[1] & 0x80 == 0 {
                minimal = false;
            }
            c.iter().copied().skip_while(|&b| b == 0).collect()
        })
        .collect();
    (ints, minimal)
}

#[test]
fn webauthn_matches_node() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: webauthn-node.json is not checked"
        );
        return;
    };
    let path = std::path::Path::new(&dir).join("webauthn-node.json");
    let v: Json =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let policy = if v["brokenAlgorithms"].as_bool().unwrap() {
        KeyPolicy::LENIENT
    } else {
        KeyPolicy::STRICT
    };
    let plain = CoseOptions {
        allow_insecure: false,
        policy,
    };
    let insecure = CoseOptions {
        allow_insecure: true,
        policy,
    };
    let data = b"authenticatorData || clientDataHash";
    let mut failures = Vec::new();
    let mut checked = 0;
    let mut check = |ok: bool, what: String| {
        checked += 1;
        if !ok {
            failures.push(what);
        }
    };
    for r in v["cose"].as_array().unwrap() {
        let alg = r["alg"].as_i64().unwrap();
        let name = format!("{} with {}", alg, r["key"].as_str().unwrap());
        let sig = b64(&r["signature"]);
        let mut tampered = sig.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let b = |k: &str| r[k].as_bool().unwrap();
        check(
            webauthn::verify_cose_signature(
                alg,
                CoseKey::Jwk(&r["jwk"]),
                data,
                &sig,
                &plain,
            ) == b("ok"),
            format!("{}: verdict", name),
        );
        check(
            webauthn::verify_cose_signature(
                alg,
                CoseKey::Jwk(&r["jwk"]),
                data,
                &sig,
                &insecure,
            ) == b("okInsecure"),
            format!("{}: insecure allowed", name),
        );
        check(
            webauthn::verify_cose_signature(
                alg,
                CoseKey::Jwk(&r["jwk"]),
                data,
                &tampered,
                &plain,
            ) == b("tampered"),
            format!("{}: tampered", name),
        );
        check(
            webauthn::verify_cose_signature(
                alg,
                CoseKey::Jwk(&r["wrongJwk"]),
                data,
                &sig,
                &plain,
            ) == b("wrongKey"),
            format!("{}: wrong key", name),
        );
    }

    for p in v["tpm"]["publics"].as_array().unwrap() {
        let ours = webauthn::tpm_parse_public(&b64(&p["bytes"]));
        match (&ours, p["error"].as_str()) {
            (Err(e), Some(want)) => check(
                e == want,
                format!("TPMT_PUBLIC refusal: {} / {}", e, want),
            ),
            (Ok(t), None) => {
                let n = &p["parsed"];
                let got = json!({
                    "type": t.object_type, "nameAlg": t.name_alg, "attributes": t.attributes,
                    "scheme": t.scheme, "schemeHash": t.scheme_hash, "keyBits": t.key_bits,
                    "exponent": t.exponent, "curveId": t.curve_id, "kdf": t.kdf, "jwk": t.jwk,
                    "name": STANDARD.encode(webauthn::tpm_name(t).unwrap()),
                });
                check(
                    &got == n,
                    format!("TPMT_PUBLIC fields\n node {}\n rust {}", n, got),
                );
            }
            _ => check(
                false,
                format!(
                    "TPMT_PUBLIC: node {:?}, rust {:?}",
                    p["error"],
                    ours.as_ref().err()
                ),
            ),
        }
    }
    let a = &v["tpm"]["attest"];
    let t = webauthn::tpm_parse_attest(&b64(&a["bytes"])).unwrap();
    let got = json!({
        "bytes": a["bytes"], "magic": t.magic, "type": t.attest_type,
        "extraData": STANDARD.encode(&t.extra_data), "clock": t.clock.to_string(),
        "resetCount": t.reset_count, "restartCount": t.restart_count, "safe": t.safe,
        "firmwareVersion": t.firmware_version.to_string(),
        "name": STANDARD.encode(t.name.unwrap()), "qualifiedName": STANDARD.encode(t.qualified_name.unwrap()),
    });
    check(
        &got == a,
        format!("TPMS_ATTEST\n node {}\n rust {}", a, got),
    );
    for s in v["tpm"]["signatures"].as_array().unwrap() {
        let ours = webauthn::tpm_parse_signature(&b64(&s["bytes"]));
        match (ours, s["parsed"].as_object()) {
            (None, None) => check(true, String::new()),
            (Some(o), Some(n)) => {
                check(
                    o.sig_alg as u64 == n["sigAlg"].as_u64().unwrap()
                        && o.hash as u64 == n["hash"].as_u64().unwrap(),
                    "TPMT_SIGNATURE algorithms".to_string(),
                );
                let theirs = b64(&n["signature"]);
                if o.sig_alg == webauthn::tpm_alg::ECDSA {
                    let (want, _) = integers(&theirs);
                    let (have, minimal) = integers(&o.signature);
                    check(
                        want == have && minimal,
                        "TPMT_SIGNATURE ECDSA: Node's integers, minimal DER"
                            .to_string(),
                    );
                } else {
                    check(
                        o.signature == theirs,
                        "TPMT_SIGNATURE RSA bytes".to_string(),
                    );
                }
            }
            (o, n) => check(
                false,
                format!("TPMT_SIGNATURE: node {:?}, rust {:?}", n, o),
            ),
        }
    }

    let e = &v["extensions"];
    check(
        webauthn::fido_aaguid_extension(&b64(&e["aaguid"]["value"]))
            == Some(b64(&e["aaguid"]["out"])),
        "AAGUID".to_string(),
    );
    check(
        webauthn::apple_attestation_nonce(&b64(&e["apple"]["value"]))
            == Some(b64(&e["apple"]["out"])),
        "Apple nonce".to_string(),
    );
    let d = webauthn::android_key_description(&b64(&e["android"]["value"]))
        .unwrap();
    let list = |l: &webauthn::AuthorizationList| json!({ "purpose": l.purpose, "allApplications": l.all_applications, "origin": l.origin });
    let got = json!({
        "value": e["android"]["value"], "attestationVersion": d.attestation_version,
        "attestationSecurityLevel": d.attestation_security_level,
        "attestationChallenge": STANDARD.encode(&d.attestation_challenge),
        "softwareEnforced": list(&d.software_enforced), "teeEnforced": list(&d.tee_enforced),
    });
    check(
        got == e["android"],
        format!("KeyDescription\n node {}\n rust {}", e["android"], got),
    );

    let c = &v["csr"];
    let bundle = webauthn::csr_attestation_bundle(&b64(&c["bundle"])).unwrap();
    let types: Vec<&str> = bundle
        .attestations
        .iter()
        .map(|a| a.statement_type.as_str())
        .collect();
    check(json!(types) == c["types"], "bundle types".to_string());
    check(
        bundle.attestations[0].stmt == b64(&c["stmt"]),
        "bundle statement".to_string(),
    );
    check(
        json!(bundle
            .certs
            .iter()
            .map(|x| STANDARD.encode(x))
            .collect::<Vec<_>>())
            == c["certs"],
        "bundle certificates".to_string(),
    );
    check(
        bundle.other_certs as u64 == c["otherCerts"].as_u64().unwrap(),
        "bundle other certificates".to_string(),
    );
    let t = webauthn::tcg_tpm_certify_statement(&bundle.attestations[0].stmt)
        .unwrap();
    check(
        t.tpms_attest == b64(&c["tpmSAttest"])
            && t.signature == b64(&c["signature"])
            && t.tpmt_public == Some(b64(&c["tpmTPublic"])),
        "tcg-attest-tpm-certify".to_string(),
    );

    assert!(
        failures.is_empty(),
        "{} differences:\n{}",
        failures.len(),
        failures.join("\n")
    );
    eprintln!("{} answers as Node gives them", checked);
}
