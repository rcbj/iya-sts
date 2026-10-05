// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! XML Signature against Node, both ways: `xmldsig-node.json`, which
//! `tests/tools/crypto-vectors.js` writes, and — with `STS_WRITE_VECTORS` —
//! `xmldsig-rust.json`, which `tests/rust_crypto_vectors.js` verifies in
//! Node.
//!
//! * every document Node signed is signed again here: the SAME BYTES for
//!   RSA PKCS#1 v1.5, which is deterministic, and the same bytes but for the
//!   SignatureValue for ECDSA and the post-quantum methods, which are not;
//! * every verdict `crypto.verifyXmlSignature()` gave — on those, on the
//!   refusals, and on the general engine's signatures in every other method
//!   — is given here, field for field and in the same words, except where
//!   the words are a parser's or OpenSSL's own;
//! * the Redirect binding's signatures, made and checked, and its refusals.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed (the vectors hold
//! private keys); with it unset this test says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use openssl::pkey::{PKey, Private};
use serde_json::{json, Value as Json};
use sts_core::errors::ErrorCode;
use sts_crypto::xmldsig::{
    self, EnvelopedOptions, Placement, QueryVerdict, VerifyOptions, XmlPolicy,
    XmlVerdict,
};
use sts_crypto::{jws, pq};

fn vectors() -> Option<std::path::PathBuf> {
    std::env::var("STS_CRYPTO_VECTORS")
        .ok()
        .map(std::path::PathBuf::from)
}

fn s(v: &Json) -> Option<&str> {
    v.as_str()
}

fn private_key(keys: &Json, name: &str) -> PKey<Private> {
    let k = &keys[name];
    if let Some(alg) = s(&k["alg"]) {
        let raw = base64_decode(s(&k["priv"]).unwrap());
        if alg.starts_with("ML-DSA") {
            return jws::ml_dsa_private(alg, &raw).unwrap();
        }
        return pq::private_from_raw(alg, &raw).unwrap();
    }
    PKey::private_key_from_pem(s(&k["privateKeyPem"]).unwrap().as_bytes())
        .unwrap()
}

fn base64_decode(text: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .unwrap()
}

fn placement(name: &str) -> Placement {
    match name {
        "first" => Placement::First,
        "last" => Placement::Last,
        _ => Placement::AfterIssuer,
    }
}

/// The document with the SignatureValue's text taken out.
fn without_value(xml: &str) -> String {
    let open = "<ds:SignatureValue>";
    let close = "</ds:SignatureValue>";
    match (xml.find(open), xml.find(close)) {
        (Some(a), Some(b)) => {
            format!("{}{}{}", &xml[..a + open.len()], "", &xml[b..])
        }
        _ => xml.to_string(),
    }
}

fn code_str(code: Option<ErrorCode>) -> Option<String> {
    code.map(|c| c.as_str().to_string())
}

/// The words a parser or OpenSSL chose are compared up to their own part.
fn comparable_why(why: &str) -> String {
    for prefix in [
        "the document is not well-formed XML",
        "the signature cannot be checked: the certificate could not be read",
    ] {
        if why.starts_with(prefix) {
            return prefix.to_string();
        }
    }
    why.to_string()
}

fn compare_xml(
    name: &str,
    node: &Json,
    rust: &XmlVerdict,
    out: &mut Vec<String>,
) {
    let mut differ = |field: &str, n: String, r: String| {
        if n != r {
            out.push(format!(
                "{}: {}: node {:?}, rust {:?}",
                name, field, n, r
            ));
        }
    };
    let b = |v: &Json| v.as_bool().unwrap_or(false).to_string();
    let t = |v: &Json| v.as_str().unwrap_or("").to_string();
    differ("ok", b(&node["ok"]), rust.ok.to_string());
    differ("present", b(&node["present"]), rust.present.to_string());
    differ(
        "code",
        node["code"].as_str().unwrap_or("").to_string(),
        code_str(rust.code).unwrap_or_default(),
    );
    differ(
        "why",
        comparable_why(&t(&node["why"])),
        comparable_why(&rust.why),
    );
    differ(
        "signatureValid",
        b(&node["signatureValid"]),
        rust.signature_valid.to_string(),
    );
    differ(
        "referencesValid",
        b(&node["referencesValid"]),
        rust.references_valid.to_string(),
    );
    differ(
        "signatureMethod",
        t(&node["signatureMethod"]),
        rust.signature_method.clone(),
    );
    differ(
        "canonicalization",
        t(&node["canonicalization"]),
        rust.canonicalization.clone(),
    );
    differ(
        "signerSubject",
        t(&node["signerSubject"]),
        rust.signer_subject.clone(),
    );
    differ(
        "signerCertB64",
        t(&node["signerCertB64"]),
        rust.signer_cert_b64.clone(),
    );
    differ(
        "referenceUri",
        t(&node["referenceUri"]),
        rust.reference_uri.clone(),
    );
    let digests: Vec<String> = node["digestMethods"]
        .as_array()
        .map(|a| a.iter().map(t).collect())
        .unwrap_or_default();
    differ(
        "digestMethods",
        format!("{:?}", digests),
        format!("{:?}", rust.digest_methods),
    );
    differ("weak", b(&node["weak"]), rust.weak.to_string());
    differ("sha1", b(&node["sha1"]), rust.sha1.to_string());
}

fn compare_query(
    name: &str,
    node: &Json,
    rust: &QueryVerdict,
    out: &mut Vec<String>,
) {
    let n = (
        node["ok"].as_bool().unwrap_or(false),
        node["usable"].as_bool().unwrap_or(false),
        node["code"].as_str().unwrap_or("").to_string(),
        comparable_why(node["why"].as_str().unwrap_or("")),
        node["signerSubject"].as_str().unwrap_or("").to_string(),
    );
    let r = (
        rust.ok,
        rust.usable,
        code_str(rust.code).unwrap_or_default(),
        comparable_why(&rust.why),
        rust.signer_subject.clone(),
    );
    if n != r {
        out.push(format!("query {}: node {:?}, rust {:?}", name, n, r));
    }
}

#[test]
fn xml_signatures_match_node() {
    let Some(dir) = vectors() else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: xmldsig-node.json is not checked"
        );
        return;
    };
    let text = std::fs::read_to_string(dir.join("xmldsig-node.json")).unwrap();
    let v: Json = serde_json::from_str(&text).unwrap();
    let policy = XmlPolicy {
        sha1_allowed: v["policy"]["sha1Allowed"].as_bool().unwrap(),
        broken_algorithms: v["policy"]["brokenAlgorithms"].as_bool().unwrap(),
    };
    let keys = &v["keys"];
    let mut failures = Vec::new();
    let mut identical = 0;
    let mut written = Vec::new();

    // Signing.
    for case in v["signed"].as_array().unwrap() {
        let name = s(&case["name"]).unwrap();
        let key = private_key(keys, s(&case["key"]).unwrap());
        let options = EnvelopedOptions {
            sig_alg: s(&case["sigAlg"]),
            c14n_alg: s(&case["c14nAlg"]),
            placement: placement(s(&case["placement"]).unwrap()),
            cert_pem: s(&case["certPem"]),
            ..EnvelopedOptions::default()
        };
        let ours = match xmldsig::sign_enveloped(
            s(&case["input"]).unwrap(),
            &key,
            &options,
        ) {
            Ok(x) => x,
            Err(e) => {
                failures.push(format!("{}: did not sign: {}", name, e));
                continue;
            }
        };
        let theirs = s(&case["signed"]).unwrap();
        let same = if case["deterministic"].as_bool().unwrap() {
            ours == theirs
        } else {
            without_value(&ours) == without_value(theirs)
        };
        if same {
            identical += 1;
        } else {
            failures.push(format!(
                "{}: signed differently\n node: {}\n rust: {}",
                name, theirs, ours
            ));
        }
        let key_name = s(&case["key"]).unwrap();
        let element = v["verify"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| s(&c["name"]) == Some(name))
            .and_then(|c| s(&c["element"]))
            .unwrap()
            .to_string();
        written.push(json!({
            "name": name,
            "element": element,
            "publicKeyPem": keys[key_name]["publicKeyPem"],
            "signed": ours,
            "ok": v["verify"].as_array().unwrap().iter()
                .find(|c| s(&c["name"]) == Some(name))
                .map(|c| c["verdict"]["ok"].clone()),
        }));
    }

    // Verifying.
    let mut verified = 0;
    for case in v["verify"].as_array().unwrap() {
        let name = s(&case["name"]).unwrap();
        let ours = xmldsig::verify_xml_signature(
            s(&case["xml"]).unwrap(),
            &VerifyOptions {
                element: s(&case["element"]).unwrap(),
                cert_pem: s(&case["certPem"]),
                public_key_pem: s(&case["publicKeyPem"]),
                policy,
            },
        );
        let before = failures.len();
        compare_xml(name, &case["verdict"], &ours, &mut failures);
        if failures.len() == before {
            verified += 1;
        }
    }

    // The Redirect binding.
    let rsa_cert = s(&keys["rsa"]["certPem"]);
    let mut queries_written = Vec::new();
    for case in v["queries"].as_array().unwrap() {
        let name = s(&case["name"]).unwrap();
        let query = s(&case["query"]).unwrap();
        let sig_alg = s(&case["sigAlg"]).unwrap();
        let key_name = s(&case["key"]).unwrap();
        let key = private_key(keys, key_name);
        let ours =
            xmldsig::sign_query_string(query, &key, Some(sig_alg)).unwrap();
        if case["deterministic"].as_bool().unwrap()
            && Some(ours.as_str()) != s(&case["signature"])
        {
            failures.push(format!("query {}: signed differently", name));
        }
        let method = xmldsig::signature_method(sig_alg).unwrap();
        let public = PKey::public_key_from_pem(
            s(&keys[key_name]["publicKeyPem"]).unwrap().as_bytes(),
        )
        .unwrap();
        let theirs = base64_decode(s(&case["signature"]).unwrap());
        if !xmldsig::verify_signature_value(
            method,
            &public,
            query.as_bytes(),
            &theirs,
            None,
            &policy,
        ) {
            failures.push(format!(
                "query {}: Node's signature did not verify",
                name
            ));
        }
        if !case["verdict"].is_null() {
            let verdict = xmldsig::verify_query_string(
                query,
                s(&case["signature"]),
                sig_alg,
                rsa_cert,
                &policy,
            );
            compare_query(name, &case["verdict"], &verdict, &mut failures);
        }
        queries_written.push(json!({
            "name": name, "query": query, "sigAlg": sig_alg,
            "publicKeyPem": keys[key_name]["publicKeyPem"],
            "signature": ours,
        }));
    }
    for case in v["queryChecks"].as_array().unwrap() {
        let verdict = xmldsig::verify_query_string(
            s(&case["query"]).unwrap(),
            s(&case["signature"]),
            s(&case["sigAlg"]).unwrap(),
            s(&case["certPem"]),
            &policy,
        );
        compare_query(
            s(&case["name"]).unwrap(),
            &case["verdict"],
            &verdict,
            &mut failures,
        );
    }

    if std::env::var("STS_WRITE_VECTORS").is_ok() {
        std::fs::write(
            dir.join("xmldsig-rust.json"),
            serde_json::to_string_pretty(&json!({
                "policy": v["policy"],
                "signed": written,
                "queries": queries_written,
            }))
            .unwrap(),
        )
        .unwrap();
    }
    if !failures.is_empty() {
        let shown: Vec<_> = failures.iter().take(12).cloned().collect();
        panic!("{} differences:\n{}", failures.len(), shown.join("\n"));
    }
    eprintln!(
        "{} signed documents as Node signs them, {} verdicts as Node gives them",
        identical, verified
    );
}
