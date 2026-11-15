// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! NODE'S ENROLLMENT, READ AND REPRODUCED (`enroll-node.json` in
//! `STS_CRYPTO_VECTORS`, written by `tests/tools/enroll-vectors.js`):
//!
//! * every PKCS#10 request read as `CertEnrollment.parseCsr()` read it —
//!   the key's name and kind, the subject, every requested name — and
//!   every refused one refused with Node's code, status and sentence;
//! * every body and query the enrollment model was asked answered as zod
//!   answered it: the parsed value, or the first issue's path and message;
//! * EST's certs-only, CSR attributes and `decodeBody()` byte for byte;
//! * SCEP: every PKCSReq the device test client built (AES-128, AES-256,
//!   3DES) parsed, its signer verified and its envelope opened with the
//!   RA's key to the very request Node enveloped; `certsOnly()` byte for
//!   byte; Node's SUCCESS and FAILURE CertReps read and opened.
//!
//! With `STS_WRITE_VECTORS`, Rust's CertReps for Node's requester go to
//! `enroll-rust.json`, which `tests/rust_crypto_vectors.js` hands to the
//! client code a SCEP device test reads replies with (`checkRust()`).

#![allow(clippy::unwrap_used, clippy::expect_used)] // tests

mod support;

use std::path::PathBuf;

use serde_json::{json, Value as Json};
use sts_enroll::est::codec;
use sts_enroll::model::Body;
use sts_enroll::scep::cms;

fn vectors() -> Option<(PathBuf, Json)> {
    let dir = PathBuf::from(std::env::var("STS_CRYPTO_VECTORS").ok()?);
    let file = dir.join("enroll-node.json");
    let text = std::fs::read_to_string(&file).ok()?;
    Some((dir, serde_json::from_str(&text).unwrap()))
}

fn unhex(v: &Json) -> Vec<u8> {
    let s = v.as_str().unwrap();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn text(v: &Json) -> &str {
    v.as_str().unwrap_or("")
}

fn strings(v: &Json) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().map(|x| text(x).to_string()).collect())
        .unwrap_or_default()
}

#[tokio::test]
async fn node_enrollment_vectors() {
    let Some((dir, v)) = vectors() else {
        eprintln!("STS_CRYPTO_VECTORS has no enroll-node.json: not checked");
        return;
    };
    let w = support::world();

    // The requests.
    for one in v["csrs"].as_array().unwrap() {
        let what = text(&one["what"]);
        let reading = &one["reading"];
        let parsed = w.core.parse_csr(&unhex(&one["der"]), false);
        if reading["ok"] == true {
            let csr = parsed.unwrap_or_else(|r| panic!("{}: {:?}", what, r));
            assert_eq!(csr.key_alg, text(&reading["keyAlg"]), "{}", what);
            assert_eq!(csr.key_kind, text(&reading["keyKind"]), "{}", what);
            assert_eq!(csr.subject, text(&reading["subject"]), "{}", what);
            assert_eq!(
                csr.common_name,
                text(&reading["commonName"]),
                "{}",
                what
            );
            assert_eq!(
                csr.public_key_pem.trim(),
                text(&reading["publicKeyPem"]).trim(),
                "{}",
                what
            );
            assert_eq!(
                csr.attribute_types,
                strings(&reading["attributeTypes"]),
                "{}",
                what
            );
            let r = &reading["requested"];
            assert_eq!(csr.requested.dns, strings(&r["dns"]), "{}", what);
            assert_eq!(csr.requested.ips, strings(&r["ips"]), "{}", what);
            assert_eq!(csr.requested.uris, strings(&r["uris"]), "{}", what);
            assert_eq!(
                csr.requested.emails,
                strings(&r["emails"]),
                "{}",
                what
            );
            assert_eq!(csr.requested.upns, strings(&r["upns"]), "{}", what);
        } else {
            let refusal = parsed.err().unwrap_or_else(|| {
                panic!("{}: Node refused and Rust read it", what)
            });
            assert_eq!(refusal.code.as_str(), text(&reading["code"]), "{}", what);
            assert_eq!(
                Json::from(refusal.status),
                reading["status"],
                "{}",
                what
            );
            assert_eq!(refusal.sentence, text(&reading["why"]), "{}", what);
        }
    }

    // The model.
    for one in v["model"].as_array().unwrap() {
        let family = text(&one["family"]);
        let id = text(&one["id"]);
        let body = Body::of(family, id).unwrap();
        let what = format!("{}/{} {}", family, id, one["value"]);
        match body.check(&one["value"]) {
            Ok(data) => {
                assert_eq!(one["ok"], true, "{}: Rust accepted", what);
                assert_eq!(data, one["data"], "{}", what);
            }
            Err(issue) => {
                assert_eq!(one["ok"], false, "{}: Rust refused", what);
                assert_eq!(issue.path, strings(&one["path"]), "{}", what);
                assert_eq!(issue.message, text(&one["message"]), "{}", what);
            }
        }
    }

    // EST's codec.
    let est = &v["est"];
    let pems = strings(&est["pems"]);
    assert_eq!(hex(&codec::certs_only(&pems)), text(&est["certsOnly"]));
    let items: Vec<codec::AttrOrOid> = est["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            if let Some(kind) = item["type"].as_str() {
                codec::AttrOrOid::Attribute {
                    kind: kind.into(),
                    values: item["values"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|value| match value["oid"].as_str() {
                            Some(o) => codec::AttrValue::Oid(o.into()),
                            None => {
                                codec::AttrValue::Utf8(text(&value["utf8"]).into())
                            }
                        })
                        .collect(),
                }
            } else {
                codec::AttrOrOid::Oid(text(&item["oid"]).into())
            }
        })
        .collect();
    assert_eq!(hex(&codec::csr_attrs(&items)), text(&est["csrAttrs"]));
    for one in est["decoded"].as_array().unwrap() {
        let got = codec::decode_body(text(&one["text"]).as_bytes());
        assert_eq!(got.is_ok(), one["ok"] == true, "decodeBody {}", one["text"]);
        if let Ok(der) = got {
            assert_eq!(hex(&der), text(&one["der"]), "decodeBody {}", one["text"]);
        }
    }

    // SCEP.
    let s = &v["scep"];
    let ra_cert = text(&s["ra"]["certificatePem"]);
    let ra_key = text(&s["ra"]["privateKeyPem"]);
    let device_cert = text(&s["device"]["certificatePem"]);
    let device_key = text(&s["device"]["privateKeyPem"]);
    for one in s["messages"].as_array().unwrap() {
        let what = text(&one["cipher"]);
        let message = cms::parse_pki_message(&unhex(&one["der"]))
            .unwrap_or_else(|e| panic!("{}: {:?}", what, e));
        assert_eq!(message.message_type, Some(19), "{}", what);
        assert_eq!(message.transaction_id, text(&one["transactionID"]));
        assert_eq!(hex(&message.sender_nonce), text(&one["nonce"]));
        cms::verify_signer(&message).unwrap_or_else(|e| panic!("{}: {:?}", what, e));
        let node = &one["opened"];
        let opened = match cms::open_envelope(
            message.content.as_deref().unwrap(),
            ra_cert,
            ra_key,
        ) {
            Err(refused) => {
                assert_eq!(node["ok"], false, "{}: Node opened it", what);
                assert_eq!(refused.code.as_str(), text(&node["code"]), "{}", what);
                assert_eq!(refused.why, text(&node["why"]), "{}", what);
                assert_eq!(refused.fail_info, text(&node["failInfo"]), "{}", what);
                continue;
            }
            Ok(opened) => opened,
        };
        assert_eq!(node["ok"], true, "{}: Node refused it", what);
        assert_eq!(opened.cipher, text(&node["cipher"]), "{}", what);
        assert_eq!(hex(&opened.content), text(&s["csr"]), "{}", what);
        let csr = w.core.parse_csr(&opened.content, false).unwrap();
        assert_eq!(csr.challenge_password, "p.challenge-value", "{}", what);
    }
    assert_eq!(hex(&cms::certs_only(&pems, &[])), text(&s["certsOnly"]));
    let rep = cms::parse_pki_message(&unhex(&s["certRep"])).unwrap();
    assert_eq!(rep.message_type, Some(3));
    assert_eq!(rep.pki_status, "0");
    assert_eq!(rep.transaction_id, "vector-rep");
    assert_eq!(hex(rep.recipient_nonce.as_deref().unwrap()), text(&s["recipientNonce"]));
    cms::verify_signer(&rep).unwrap();
    let opened =
        cms::open_envelope(rep.content.as_deref().unwrap(), device_cert, device_key)
            .unwrap();
    assert_eq!(hex(&opened.content), text(&s["certsOnly"]));
    let failure = cms::parse_pki_message(&unhex(&s["failure"])).unwrap();
    assert_eq!((failure.pki_status.as_str(), failure.fail_info.as_str()), ("2", "4"));
    cms::verify_signer(&failure).unwrap();

    if std::env::var("STS_WRITE_VECTORS").is_err() {
        return;
    }
    // Rust's CertReps, for Node's requester.
    let nonce = unhex(&s["recipientNonce"]);
    let content = cms::certs_only(&pems, &[]);
    let enveloped =
        cms::envelope(&content, device_cert, "2.16.840.1.101.3.4.1.42").unwrap();
    let spec = |status: &str, fail: &str, content: Option<Vec<u8>>| cms::CertRepSpec {
        ra_certificate_pem: ra_cert.into(),
        ra_private_key_pem: ra_key.into(),
        transaction_id: "rust-rep".into(),
        recipient_nonce: nonce.clone(),
        pki_status: status.into(),
        fail_info: fail.into(),
        content,
        digest: "sha256".into(),
    };
    let rep = cms::cert_rep(&spec("0", "", Some(enveloped))).unwrap();
    let failure = cms::cert_rep(&spec("2", "2", None)).unwrap();
    std::fs::write(
        dir.join("enroll-rust.json"),
        serde_json::to_string_pretty(&json!({
            "ra": { "certificatePem": ra_cert },
            "device": { "certificatePem": device_cert,
                        "privateKeyPem": device_key },
            "pems": pems,
            "transactionID": "rust-rep",
            "recipientNonce": hex(&nonce),
            "certRep": hex(&rep),
            "failure": hex(&failure),
            "certsOnly": hex(&content),
            "estCertsOnly": hex(&codec::certs_only(&pems)),
        }))
        .unwrap(),
    )
    .unwrap();
}
