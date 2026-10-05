// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `x509.js` against Node, both ways: `x509-node.json`, which
//! `tests/tools/crypto-vectors.js` writes, and — with `STS_WRITE_VECTORS`
//! — `x509-rust.json`, which `tests/rust_crypto_vectors.js` reads back in
//! Node.
//!
//! For every spec Node issued (every profile, every extension with values
//! of every kind, every signature algorithm under a chain, the hybrids):
//!
//! * Rust issues the same spec and its TBSCertificate is Node's byte for
//!   byte; where the signer is deterministic (RSA PKCS#1 v1.5, Ed25519) the
//!   whole certificate is;
//! * Rust's `describe_certificate()` of Node's certificate is Node's, and
//!   its `verify_chain()` gives every link Node gave;
//! * a refusal is refused with Node's sentence.
//!
//! PKCS#10 requests likewise, and the ECDSA encoding helpers.
//!
//! Two differences are pinned rather than reproduced, each a Node defect:
//! Node refuses to issue under an ECDSA issuer whose curve is not the
//! subject's ("Named curve mismatch": it imports the issuer's key with the
//! SUBJECT's descriptor), and its describer calls every post-quantum key
//! "Ed25519". When Node is fixed these checks fail and the exceptions go.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed; with it unset
//! this test says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value as Json};
use sts_pki::der;
use sts_pki::x509::{self, extensions, issue, names, read, Certificate};

fn b64(v: &Json) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}

/// A TBSCertificate without its altSignatureValue (a randomised
/// post-quantum signature) — everything else must be Node's.
fn without_alt_value(tbs: &[u8]) -> Vec<u8> {
    let seq = der::read(tbs).unwrap();
    let parts: Vec<Vec<u8>> = der::children(seq.content)
        .unwrap()
        .iter()
        .map(|item| {
            if item.tag != 0xa3 {
                return item.raw.to_vec();
            }
            let kept: Vec<Vec<u8>> =
                der::children(der::read(item.content).unwrap().content)
                    .unwrap()
                    .into_iter()
                    .filter(|e| {
                        der::children(e.content)
                            .and_then(|p| {
                                p.first()
                                    .and_then(|o| der::oid_string(o.content))
                            })
                            .as_deref()
                            != Some(extensions::ALT_SIGNATURE_VALUE)
                    })
                    .map(|e| e.raw.to_vec())
                    .collect();
            der::context(3, true, &der::sequence(&kept))
        })
        .collect();
    der::sequence(&parts)
}

/// Whether a certificate's signatures are reproducible: RSA PKCS#1 v1.5 or
/// Ed25519, with no alternative signature.
fn deterministic(spec: &Json) -> bool {
    let alg = spec["signatureAlg"].as_str().unwrap_or("");
    let classical = alg.ends_with("-rsa") || alg == "ed25519";
    classical && spec.get("altSignature").is_none()
}

/// The curve of an ECDSA signature algorithm's issuer key in these vectors
/// differs from the subject's P-256 in two rows: the Node defect.
fn node_curve_defect(name: &str) -> bool {
    name == "leaf under sha384-ecdsa" || name == "leaf under sha512-ecdsa"
}

fn link_without_error(link: &Json) -> Json {
    let mut l = link.clone();
    if let Some(m) = l.as_object_mut() {
        m.remove("error");
    }
    l
}

#[test]
fn x509_matches_node() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: x509-node.json is not checked"
        );
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let v: Json = serde_json::from_str(
        &std::fs::read_to_string(dir.join("x509-node.json")).unwrap(),
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
    let mut written = Vec::new();

    for row in v["certificates"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let spec = &row["spec"];
        let mine = x509::issue_certificate(spec);
        if let Some(error) = row["error"].as_str() {
            if node_curve_defect(name) {
                check(
                    mine.is_ok(),
                    format!(
                        "{}: Rust issues what Node cannot (the curve defect)",
                        name
                    ),
                );
                if let Ok(m) = mine {
                    let root =
                        spec["issuer"]["certificatePem"].as_str().unwrap();
                    let chain = vec![m.pem.as_str(), root];
                    let links = read::verify_chain(&chain).unwrap();
                    check(
                        links[0]["signatureValid"] == json!(true),
                        format!("{}: and it verifies", name),
                    );
                    written.push(json!({ "name": name, "pem": m.pem, "chain": chain, "links": links,
                                         "describe": read::describe_certificate(&Certificate::from_der(&m.der).unwrap()).unwrap() }));
                }
                continue;
            }
            check(
                mine.as_ref().err().map(|e| e.0.as_str()) == Some(error),
                format!(
                    "{}: refused as Node refuses ({:?} vs {})",
                    name,
                    mine.as_ref().err(),
                    error
                ),
            );
            continue;
        }
        let mine = match mine {
            Ok(m) => m,
            Err(e) => {
                check(false, format!("{}: Rust refused: {}", name, e));
                continue;
            }
        };
        let node_der = b64(&row["der"]);
        let node = Certificate::from_der(&node_der).unwrap();
        let rust = Certificate::from_der(&mine.der).unwrap();
        check(
            without_alt_value(&rust.tbs) == without_alt_value(&node.tbs),
            format!("{}: the TBSCertificate is Node's", name),
        );
        if deterministic(spec) {
            check(
                mine.der == node_der,
                format!("{}: the certificate is Node's", name),
            );
        }
        let result = &row["result"];
        check(
            json!({ "serialHex": mine.serial_hex, "subject": mine.subject, "issuer": mine.issuer,
                    "notBefore": mine.not_before, "notAfter": mine.not_after,
                    "signatureAlg": mine.signature_alg })
                == *result,
            format!("{}: the result fields are Node's", name),
        );

        // Node's certificate described and verified here.
        let mut described = read::describe_certificate(&node).unwrap();
        let mut theirs = row["describe"].clone();
        let pq_key = sts_pki::x509::keys::describe_spki(&node.spki)
            .is_some_and(|k| k.kind() == "pqc");
        if pq_key {
            check(
                theirs["publicKey"] == "Ed25519",
                format!("{}: Node calls a post-quantum key Ed25519", name),
            );
            described["publicKey"] = Json::Null;
            theirs["publicKey"] = Json::Null;
        }
        check(
            described == theirs,
            format!(
                "{}: described as Node describes it:\n{}\n{}",
                name, described, theirs
            ),
        );
        let chain: Vec<&str> = row["chain"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap())
            .collect();
        let links = read::verify_chain(&chain).unwrap();
        let node_links = row["links"].as_array().unwrap();
        check(
            links.iter().map(link_without_error).collect::<Vec<_>>()
                == node_links
                    .iter()
                    .map(link_without_error)
                    .collect::<Vec<_>>(),
            format!(
                "{}: verified as Node verifies it:\n{:?}\n{:?}",
                name, links, node_links
            ),
        );

        // Rust's own certificate verifies under the same chain.
        let mut rust_chain = vec![mine.pem.as_str()];
        rust_chain.extend(chain.iter().skip(1));
        let rust_links = read::verify_chain(&rust_chain).unwrap();
        check(
            rust_links[0]["signatureValid"] == json!(true),
            format!("{}: Rust's certificate verifies", name),
        );
        written.push(json!({ "name": name, "pem": mine.pem, "chain": rust_chain,
                             "describe": read::describe_certificate(&rust).unwrap(),
                             "links": rust_links }));
    }

    for row in v["requests"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let mine = x509::certification_request(&row["spec"]);
        if let Some(error) = row["error"].as_str() {
            check(
                mine.as_ref().err().map(|e| e.0.as_str()) == Some(error),
                format!(
                    "CSR {}: refused as Node refuses ({:?})",
                    name,
                    mine.as_ref().err()
                ),
            );
            continue;
        }
        let mine = mine.unwrap();
        let node_der = b64(&row["der"]);
        let info = |d: &[u8]| {
            let seq = der::read(d).unwrap();
            der::children(seq.content).unwrap()[0].raw.to_vec()
        };
        check(
            info(&mine.der) == info(&node_der),
            format!("CSR {}: the request info is Node's", name),
        );
        let alg = mine.signature_alg.as_str();
        if alg.ends_with("-rsa") || alg == "ed25519" {
            check(
                mine.der == node_der,
                format!("CSR {}: the request is Node's", name),
            );
        }
        check(
            mine.subject == row["subject"]
                && mine.signature_alg == row["signatureAlg"],
            format!("CSR {}: subject and algorithm", name),
        );
        written
            .push(json!({ "name": format!("CSR {}", name), "csr": mine.pem }));
    }

    for row in v["ecdsa"].as_array().unwrap() {
        let raw = b64(&row["raw"]);
        let der_sig = issue::ecdsa_raw_to_der(&raw);
        check(der_sig == b64(&row["der"]), "ecdsaRawToDer".to_string());
        check(
            issue::ecdsa_der_to_raw(&der_sig, 66).unwrap() == b64(&row["back"]),
            "ecdsaDerToRaw".to_string(),
        );
    }
    for row in v["defaults"].as_array().unwrap() {
        let id = row["id"].as_str().unwrap();
        check(
            extensions::default_extensions(id) == row["extensions"],
            format!("defaultExtensions({})", id),
        );
        check(
            extensions::default_subject_cn(id) == row["cn"],
            format!("defaultSubjectCN({})", id),
        );
        check(
            extensions::default_subject_alt_name(id) == row["san"],
            format!("defaultSubjectAltName({})", id),
        );
    }
    for row in v["signatureAlgorithms"].as_array().unwrap() {
        let kind = row["kind"].as_str().unwrap();
        check(
            json!(x509::algorithms::signature_algorithms_for(kind, None))
                == row["ids"],
            format!("signatureAlgorithmsFor({})", kind),
        );
    }
    for row in v["parsedDns"].as_array().unwrap() {
        check(
            json!(names::parse_dn_string(row["text"].as_str().unwrap()))
                == row["attrs"],
            format!("parseDnString({})", row["text"]),
        );
    }

    if std::env::var("STS_WRITE_VECTORS").is_ok() {
        std::fs::write(
            dir.join("x509-rust.json"),
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
    eprintln!("{} answers as Node gives them", checked);
}
