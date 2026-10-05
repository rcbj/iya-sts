// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Post-quantum keys in X.509 against Node, both ways: `pq-x509-node.json`,
//! which `tests/tools/crypto-vectors.js` writes from `pqc_x509.js`, and —
//! with `STS_WRITE_VECTORS` — `pq-x509-rust.json`, whose signatures
//! `tests/rust_crypto_vectors.js` verifies in Node.
//!
//! For each of the 34 algorithms: the SubjectPublicKeyInfo and every PKCS#8
//! arm are Node's bytes (so the expanded keys are noble's), each decodes
//! back to Node's key, the public key is the private key's, and Node's
//! signature verifies here.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed; with it unset
//! this test says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value as Json};
use sts_crypto::pq_x509::{self, PrivateForm};

/// THE ONE KNOWN NODE DEFECT HERE: `@noble/curves` 1.4.0 writes and reads
/// a DER ECDSA signature with a SHORT-FORM length only, so a P-521
/// signature — the one over 127 bytes — is `30 87 …` where DER is
/// `30 81 87 …`. Every composite Node signs with this algorithm is refused
/// by OpenSSL and every strict verifier, and Node refuses correct ones.
/// Rust writes and reads DER.
const NOBLE_P521: &str = "mldsa87-ecdsa-p521-sha512";

fn b64(v: &Json) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}

#[test]
fn post_quantum_x509_matches_node() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: pq-x509-node.json is not checked"
        );
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let rows: Vec<Json> = serde_json::from_str(
        &std::fs::read_to_string(dir.join("pq-x509-node.json")).unwrap(),
    )
    .unwrap();
    let mut failures = Vec::new();
    let mut checked = 0;
    let mut written = Vec::new();
    for row in &rows {
        let id = row["id"].as_str().unwrap();
        let mut check = |ok: bool, what: &str| {
            checked += 1;
            if !ok {
                failures.push(format!("{}: {}", id, what));
            }
        };
        let a = pq_x509::alg(id).unwrap();
        check(a.oid == row["oid"].as_str().unwrap(), "the OID");
        check(
            a.family.name() == row["family"].as_str().unwrap(),
            "the family",
        );
        check(
            pq_x509::label_for(id) == row["label"].as_str().unwrap(),
            "the label",
        );
        let (public, private) = (b64(&row["pub"]), b64(&row["priv"]));
        check(
            pq_x509::encode_spki(id, &public).unwrap() == b64(&row["spki"]),
            "the SubjectPublicKeyInfo bytes",
        );
        let decoded = pq_x509::decode_spki(&b64(&row["spki"]));
        check(
            decoded.is_some_and(|(x, k)| x.id == id && k == public),
            "the SubjectPublicKeyInfo read back",
        );
        check(
            pq_x509::public_from_private(id, &private).unwrap() == public,
            "the public key of the private key",
        );
        for (name, form) in [
            ("seed", PrivateForm::Seed),
            ("expandedKey", PrivateForm::ExpandedKey),
            ("both", PrivateForm::Both),
        ] {
            let Some(theirs) = row["pkcs8"].get(name) else {
                continue;
            };
            let theirs = b64(theirs);
            let ours = pq_x509::encode_pkcs8(id, &private, Some(form)).unwrap();
            check(ours == theirs, &format!("the PKCS#8 {} bytes", name));
            let back = pq_x509::decode_pkcs8(&theirs).unwrap().unwrap();
            check(back.alg.id == id, &format!("the PKCS#8 {} read back", name));
            if name != "expandedKey" {
                check(
                    back.private.as_deref() == Some(&private[..]),
                    &format!("the PKCS#8 {} key", name),
                );
            }
        }
        if let Some(sig) = row.get("signature") {
            let message = b64(&row["message"]);
            let theirs = b64(sig);
            let verified =
                pq_x509::verify(id, &theirs, &message, &public).unwrap();
            if id == NOBLE_P521 {
                // Node's ECDSA half is not DER (see NOBLE_P521): refused
                // here, as OpenSSL refuses it. When Node is fixed this
                // fails, and the exception goes.
                let trad = &theirs[4627..];
                check(
                    !verified && trad[0] == 0x30 && trad[1] > 0x81,
                    "Node's short-form P-521 DER is refused",
                );
            } else {
                check(verified, "Node's signature verifies");
            }
            let ours = pq_x509::sign(id, &message, &private).unwrap();
            written.push(json!({
                "id": id, "pub": row["pub"], "message": row["message"],
                "signature": STANDARD.encode(ours),
            }));
        }
    }
    if std::env::var("STS_WRITE_VECTORS").is_ok() {
        std::fs::write(
            dir.join("pq-x509-rust.json"),
            serde_json::to_string_pretty(&written).unwrap(),
        )
        .unwrap();
    }
    assert!(
        failures.is_empty(),
        "{} differences:\n{}",
        failures.len(),
        failures.join("\n")
    );
    eprintln!(
        "{} checks as Node answers them, over {} algorithms",
        checked,
        rows.len()
    );
}
