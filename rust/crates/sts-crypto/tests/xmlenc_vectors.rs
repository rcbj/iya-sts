// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! XML Encryption against Node, both ways: `xmlenc-node.json`, which
//! `tests/tools/crypto-vectors.js` writes, and — with `STS_WRITE_VECTORS` —
//! `xmlenc-rust.json`, which `tests/rust_crypto_vectors.js` decrypts in
//! Node.
//!
//! Every element Node encrypted is decrypted here with Node's verdict,
//! field for field; every refusal Node gave is given here, with its code
//! and in its words (OpenSSL's own words aside); and every encryption is
//! made again here and must be Node's document but for its random values —
//! the content key, the IVs, the ephemeral key.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed; with it unset
//! this test says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use openssl::pkey::PKey;
use serde_json::{json, Value as Json};
use sts_crypto::xmlenc::{self, DecryptOptions, Decrypted, EncryptOptions};

fn list(v: &Json) -> Option<Vec<String>> {
    v.as_array()
        .map(|a| a.iter().map(|x| x.as_str().unwrap().to_string()).collect())
}

fn options(v: &Json, broken: bool) -> DecryptOptions {
    DecryptOptions {
        allowed_ciphers: list(&v["allowedCiphers"]),
        allowed_key_management: list(&v["allowedKeyManagement"]),
        allowed_oaep_digests: list(&v["allowedOaepDigests"]),
        broken_algorithms: broken,
    }
}

/// A library's own words are compared up to where they start.
fn comparable(why: &str) -> String {
    for prefix in [
        "the encrypted element is not well-formed XML",
        "the wrapped key could not be unwrapped with this service's private key",
        "the encrypted element could not be read",
    ] {
        if why.starts_with(prefix) {
            return prefix.to_string();
        }
    }
    why.to_string()
}

fn compare(name: &str, node: &Json, rust: &Decrypted, out: &mut Vec<String>) {
    let s = |k: &str| node[k].as_str().unwrap_or("").to_string();
    let n = (
        node["ok"].as_bool().unwrap(),
        s("xml"),
        comparable(&s("why")),
        s("code"),
        node["refused"].as_bool().unwrap(),
        s("algorithm"),
        s("keyTransport"),
        s("keyWrap"),
        s("oaepDigest"),
    );
    let r = (
        rust.ok,
        rust.xml.clone(),
        comparable(&rust.why),
        rust.code
            .map(|c| c.as_str().to_string())
            .unwrap_or_default(),
        rust.refused,
        rust.algorithm.clone(),
        rust.key_transport.clone(),
        rust.key_wrap.clone(),
        rust.oaep_digest.clone(),
    );
    if n != r {
        out.push(format!("{}:\n node {:?}\n rust {:?}", name, n, r));
    }
}

/// The document with every random value taken out: the CipherValues and
/// the ephemeral public key.
fn without_random(xml: &str) -> String {
    let mut out = String::new();
    let mut rest = xml;
    loop {
        let next = ["<xenc:CipherValue>", "<dsig11:PublicKey>"]
            .iter()
            .filter_map(|tag| rest.find(tag).map(|at| (at, *tag)))
            .min();
        let Some((at, tag)) = next else {
            out.push_str(rest);
            return out;
        };
        out.push_str(&rest[..at + tag.len()]);
        rest = &rest[at + tag.len()..];
        let end = rest.find('<').unwrap_or(rest.len());
        rest = &rest[end..];
    }
}

#[test]
fn xml_encryption_matches_node() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: xmlenc-node.json is not checked"
        );
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let text = std::fs::read_to_string(dir.join("xmlenc-node.json")).unwrap();
    let v: Json = serde_json::from_str(&text).unwrap();
    let broken = v["brokenAlgorithms"].as_bool().unwrap();
    let key = |name: &str| {
        PKey::private_key_from_pem(
            v["recipients"][name]["privateKeyPem"]
                .as_str()
                .unwrap()
                .as_bytes(),
        )
        .unwrap()
    };
    let mut failures = Vec::new();
    let mut written = Vec::new();
    let (mut decrypted, mut encrypted) = (0, 0);
    for case in v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .chain(v["refusals"].as_array().unwrap())
    {
        let name = case["name"].as_str().unwrap();
        let recipient = case["recipient"].as_str().unwrap();
        let private = key(recipient);
        let opts = options(&case["options"], broken);
        let ours = xmlenc::decrypt_element(
            case["xml"].as_str().unwrap(),
            &private,
            &opts,
        );
        let before = failures.len();
        compare(name, &case["verdict"], &ours, &mut failures);
        if failures.len() == before {
            decrypted += 1;
        }
        if case["encrypt"].is_null() {
            continue;
        }
        let e = &case["encrypt"];
        let plain = e["plain"].as_str().unwrap();
        let cert = v["recipients"][recipient]["certPem"].as_str().unwrap();
        let o = &e["options"];
        let made = xmlenc::encrypt_element(
            plain,
            cert,
            &EncryptOptions {
                wrapper: o["wrapper"].as_str(),
                algorithm: o["algorithm"].as_str(),
                key_transport: o["keyTransport"].as_str(),
                key_wrap: o["keyWrap"].as_str(),
            },
        )
        .unwrap();
        if without_random(&made)
            != without_random(case["xml"].as_str().unwrap())
        {
            failures.push(format!(
                "{}: encrypted differently\n node: {}\n rust: {}",
                name,
                case["xml"].as_str().unwrap(),
                made
            ));
        } else {
            encrypted += 1;
        }
        let back = xmlenc::decrypt_element(&made, &private, &opts);
        if !back.ok || back.xml != plain {
            failures.push(format!(
                "{}: our own did not decrypt: {}",
                name, back.why
            ));
        }
        written.push(json!({
            "name": name, "recipient": recipient, "xml": made, "plain": plain,
        }));
    }
    if std::env::var("STS_WRITE_VECTORS").is_ok() {
        std::fs::write(
            dir.join("xmlenc-rust.json"),
            serde_json::to_string_pretty(&json!({ "cases": written })).unwrap(),
        )
        .unwrap();
    }
    if !failures.is_empty() {
        let shown: Vec<_> = failures.iter().take(10).cloned().collect();
        panic!("{} differences:\n{}", failures.len(), shown.join("\n"));
    }
    eprintln!(
        "{} verdicts as Node gives them, {} encryptions shaped as Node's",
        decrypted, encrypted
    );
}
