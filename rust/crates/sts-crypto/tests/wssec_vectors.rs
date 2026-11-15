// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The WS-Security message signature against Node, both ways:
//! `wssec-node.json`, which `tests/tools/wssec-vectors.js` writes, and —
//! with `STS_WRITE_VECTORS` — `wssec-rust.json`, which
//! `tests/rust_crypto_vectors.js` checks in Node.
//!
//! * every envelope Node signed (`signWsSecurity()`, RSA PKCS#1 v1.5 and
//!   the Kerberos HMAC, both deterministic) is signed again here into the
//!   SAME BYTES;
//! * every answer Node gave — the reading, the certificate verifier and the
//!   HMAC verifier, refusals included, among them the one that follows from
//!   Node verifying a serialized copy — is given here key for key, with its
//!   code;
//! * Rust's own envelopes and answers go back to Node.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed (the vectors hold
//! private keys); with it unset this test says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use openssl::pkey::PKey;
use serde_json::{json, Map, Value as Json};
use sts_crypto::xmldsig::{
    self, KeyReference, WsSecurityKey, WsSecurityReading,
    WsSecuritySignOptions, XmlPolicy,
};

fn strings(v: &Json) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn policy_of(v: &Json) -> XmlPolicy {
    let b = |k: &str| v[k].as_bool().unwrap_or(false);
    XmlPolicy {
        sha1_allowed: b("sha1Allowed"),
        broken_algorithms: b("brokenAlgorithms"),
        signature_algorithms: strings(&v["signatureAlgorithms"]),
        accepted_signature_algorithms: strings(
            &v["acceptedSignatureAlgorithms"],
        ),
        accepted_digest_algorithms: strings(&v["acceptedDigestAlgorithms"]),
        pqc_only: b("pqcOnly"),
        jose_signing_algorithms: strings(&v["joseSigningAlgorithms"]),
        jose_accepted_algorithms: strings(&v["joseAcceptedAlgorithms"]),
        omits_unapproved_curves: b("omitsUnapprovedCurves"),
    }
}

fn b64(text: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .unwrap()
}

/// A reading as Node's object would serialize it.
fn to_json(r: &WsSecurityReading) -> Json {
    if !r.present {
        return json!({ "present": false });
    }
    let mut m = Map::new();
    m.insert("ok".into(), json!(r.ok));
    m.insert("present".into(), json!(true));
    m.insert("why".into(), json!(r.why));
    if let Some(k) = &r.key_reference {
        let mut o = json!({ "kind": k.kind() });
        let fields: Vec<(&str, &str)> = match k {
            KeyReference::Token { id, cert_b64 } => {
                vec![("id", id), ("certB64", cert_b64)]
            }
            KeyReference::Kerberos {
                id,
                value_type,
                token_b64,
            } => vec![
                ("id", id),
                ("valueType", value_type),
                ("tokenB64", token_b64),
            ],
            KeyReference::KerberosId { key_identifier } => {
                vec![("keyIdentifier", key_identifier)]
            }
            KeyReference::Thumbprint { sha1 } => vec![("sha1", sha1)],
            KeyReference::Ski { ski } => vec![("ski", ski)],
            KeyReference::IssuerSerial { issuer, serial_hex } => {
                vec![("issuer", issuer), ("serialHex", serial_hex)]
            }
        };
        for (name, value) in fields {
            o[name] = json!(value);
        }
        m.insert("keyReference".into(), o);
    }
    if let Some(t) = &r.timestamp {
        m.insert(
            "timestamp".into(),
            json!({ "created": t.created, "expires": t.expires }),
        );
    }
    let mut put = |k: &str, v: Option<Json>| {
        if let Some(v) = v {
            m.insert(k.into(), v);
        }
    };
    put(
        "signatureValue",
        r.signature_value.as_ref().map(|v| json!(v)),
    );
    put("references", r.references.as_ref().map(|v| json!(v)));
    put(
        "signatureMethod",
        r.signature_method.as_ref().map(|v| json!(v)),
    );
    put("digestMethods", r.digest_methods.as_ref().map(|v| json!(v)));
    put("weak", r.weak.map(|v| json!(v)));
    put("sha1", r.sha1.map(|v| json!(v)));
    put("signatureValid", r.signature_valid.map(|v| json!(v)));
    put("referencesValid", r.references_valid.map(|v| json!(v)));
    put("signerSubject", r.signer_subject.as_ref().map(|v| json!(v)));
    Json::Object(m)
}

/// The answer with what follows "could not be read: " cut off: those are
/// OpenSSL's own words in each runtime, and differ between its callers.
fn openssl_words(v: &Json) -> Json {
    let mut v = v.clone();
    if let Some(why) = v["why"].as_str() {
        let marker = "could not be read: ";
        if let Some(at) = why.find(marker) {
            v["why"] = json!(why[..at + marker.len()].to_string());
        }
    }
    v
}

fn answer(case: &Json, policy: &XmlPolicy) -> WsSecurityReading {
    let xml = case["xml"].as_str().unwrap();
    match case["how"].as_str().unwrap() {
        "read" => xmldsig::read_ws_security_signature(xml, policy),
        "verify" => xmldsig::verify_ws_security_signature(
            xml,
            case["certPem"].as_str(),
            policy,
        ),
        _ => xmldsig::verify_ws_security_hmac(
            xml,
            &case["keyB64"].as_str().map(b64).unwrap_or_default(),
            policy,
        ),
    }
}

#[test]
fn node_wssec_vectors_both_ways() {
    let Some(dir) = std::env::var("STS_CRYPTO_VECTORS")
        .ok()
        .map(std::path::PathBuf::from)
    else {
        eprintln!("STS_CRYPTO_VECTORS is not set; no WS-Security vectors");
        return;
    };
    let file = dir.join("wssec-node.json");
    if !file.exists() {
        eprintln!("{} is missing; no WS-Security vectors", file.display());
        return;
    }
    let v: Json =
        serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    let policy = policy_of(&v["policy"]);
    let key = PKey::private_key_from_pem(
        v["key"]["privateKeyPem"].as_str().unwrap().as_bytes(),
    )
    .unwrap();
    let cert = v["key"]["certPem"].as_str().unwrap();
    let mut failures = Vec::new();
    let mut written = Vec::new();

    for row in v["signed"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let shared = row["keyB64"].as_str().map(b64);
        let info = row["keyInfoXml"].as_str().unwrap_or("");
        let o = WsSecuritySignOptions {
            sig_alg: row["sigAlg"].as_str(),
            key: match &shared {
                Some(k) => WsSecurityKey::Shared {
                    key: k,
                    key_info_xml: info,
                },
                None => WsSecurityKey::Rsa {
                    key: &key,
                    cert_pem: cert,
                },
            },
            sign_timestamp: row["signTimestamp"].as_bool().unwrap(),
        };
        let ours =
            xmldsig::sign_ws_security(row["input"].as_str().unwrap(), &o);
        match ours {
            Ok(xml) => {
                if Some(xml.as_str()) != row["signed"].as_str() {
                    failures.push(format!(
                        "{}: signed differently:\n  node {}\n  rust {}",
                        name, row["signed"], xml
                    ));
                }
                // What Node is handed: the KeyInfo a requester sends (a
                // reference to the token, which signWsSecurity() does not
                // write), and whether it must verify — the Timestamp
                // signed, and no SHA-1 under the default policy.
                let sent = if shared.is_some() {
                    xml.clone()
                } else {
                    let a = xml.find("<ds:KeyInfo>").unwrap();
                    let b = xml.find("</ds:KeyInfo>").unwrap();
                    format!(
                        "{}<ds:KeyInfo><wsse:SecurityTokenReference>\
                         <wsse:Reference URI=\"#x509\"/>\
                         </wsse:SecurityTokenReference></ds:KeyInfo>{}",
                        &xml[..a],
                        &xml[b + "</ds:KeyInfo>".len()..]
                    )
                };
                let sha1 = row["sigAlg"].as_str().unwrap().ends_with("sha1");
                written.push(json!({
                    "name": name, "signed": sent, "certPem": cert,
                    "keyB64": row["keyB64"],
                    "expectOk": row["signTimestamp"].as_bool().unwrap()
                        && !(sha1 && !policy.sha1_allowed),
                }));
            }
            Err(e) => failures.push(format!("{}: refused: {}", name, e)),
        }
    }

    let mut cases_written = Vec::new();
    for case in v["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let ours = answer(case, &policy);
        let got = to_json(&ours);
        let code = ours.code.map(|c| c.as_str().to_string());
        if openssl_words(&got) != openssl_words(&case["answer"])
            || code.as_deref() != case["code"].as_str()
        {
            failures.push(format!(
                "{}:\n  node {} {}\n  rust {} {:?}",
                name, case["code"], case["answer"], got, code
            ));
        }
        cases_written.push(json!({
            "name": name, "xml": case["xml"], "how": case["how"],
            "certPem": case["certPem"], "keyB64": case["keyB64"],
            "answer": got, "code": code,
        }));
    }
    assert!(
        failures.is_empty(),
        "{} of {} differ from Node:\n{}",
        failures.len(),
        v["signed"].as_array().unwrap().len()
            + v["cases"].as_array().unwrap().len(),
        failures.join("\n")
    );
    eprintln!(
        "wssec: {} envelopes signed and {} answers as Node",
        written.len(),
        cases_written.len()
    );
    if std::env::var("STS_WRITE_VECTORS").is_ok() {
        std::fs::write(
            dir.join("wssec-rust.json"),
            serde_json::to_string_pretty(&json!({
                "signed": written,
                "cases": cases_written,
            }))
            .unwrap(),
        )
        .unwrap();
    }
}
