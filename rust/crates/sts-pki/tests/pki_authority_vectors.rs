// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The certificate authority against Node, both ways
//! (`tests/tools/pki-authority-vectors.js` writes `pki-authority-node.json`):
//!
//! * the rows a product Node sealed are held as Node left them, and
//!   ensuring the Root, the process branch and the default realm's branch
//!   BUILDS NOTHING — a 1.x install's hierarchy is read, never replaced;
//! * the addresses a certificate names are Node's (`distributionPoints()`);
//! * Node's four CRLs re-signed from the rows at Node's moment and number
//!   are Node's byte for byte (the hierarchy is RSA: PKCS#1 v1.5 is
//!   deterministic), and so are Node's OCSP answers to Node's requests at
//!   Node's moment — revoked, good with a nonce, unknown, another issuer's
//!   (`unauthorized`), malformed;
//! * Rust issues an enrolled certificate under Node's ACME Issuing CA, and
//!   it chains to Node's Root.
//!
//! The other way round, with `STS_WRITE_VECTORS`: a hierarchy Rust built,
//! a leaf from its ACME CA, that leaf revoked, the CRL and an OCSP answer
//! go to `pki-authority-rust.json`, and `tests/rust_crypto_vectors.js`
//! hands them to Node (`checkRust()`).

#![allow(clippy::unwrap_used)] // a test file

use std::path::PathBuf;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::DateTime;
use serde_json::{json, Value as Json};
use sts_pki::authority::catalog::{PROCESS_SCOPE, SERVICE_SCOPE};
use sts_pki::authority::hierarchy::EnrolledSpec;
use sts_pki::authority::{
    Authority, BuildOptions, MemoryRows, PkiConfig, RowStore,
};
use sts_pki::der;
use sts_pki::x509::read::{verify_signature, Certificate};

fn vectors() -> Option<PathBuf> {
    let dir = PathBuf::from(std::env::var("STS_CRYPTO_VECTORS").ok()?);
    dir.join("pki-authority-node.json").exists().then_some(dir)
}

fn b64(v: &Json) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}

/// The CRL's thisUpdate, read back.
fn crl_number(der_bytes: &[u8]) -> i64 {
    // CertificateList -> TBSCertList -> [0] extensions -> CRLNumber.
    let outer = der::read(der_bytes).unwrap();
    let tbs = der::children(outer.content).unwrap()[0];
    let fields = der::children(tbs.content).unwrap();
    let exts = fields.iter().find(|f| f.is_context(0)).unwrap();
    let list = der::read(exts.content).unwrap();
    let first = der::children(list.content).unwrap()[0];
    let parts = der::children(first.content).unwrap();
    let int = der::read(parts.last().unwrap().content).unwrap();
    der::integer_value(int.content).unwrap()
}

fn authority_over(v: &Json) -> Arc<Authority> {
    let rows = Arc::new(MemoryRows::new());
    for (scope, row) in v["plain"].as_object().unwrap() {
        rows.attach(scope, Some(row));
    }
    let mut config = PkiConfig::development();
    config.distribution.base_url =
        v["config"]["httpBase"].as_str().unwrap().to_string();
    config.distribution.default_base_dn =
        v["config"]["baseDn"].as_str().unwrap().to_string();
    let ldap = v["points"][0]["ldap"].as_str().unwrap();
    let hostport = ldap
        .trim_start_matches("ldap://")
        .split('/')
        .next()
        .unwrap();
    let (host, port) = hostport.rsplit_once(':').unwrap();
    config.distribution.host = host.to_string();
    config.distribution.ldap_port = port.parse().unwrap();
    config.crl_lifetime_minutes =
        v["config"]["crlLifetimeMinutes"].as_i64().unwrap();
    config.uses_broken_algorithms = false;
    Authority::new(rows, config)
}

#[test]
fn node_hierarchy_is_read_reissued_under_and_answered_byte_for_byte() {
    let Some(dir) = vectors() else {
        eprintln!("STS_CRYPTO_VECTORS has no pki-authority-node.json: skipped");
        return;
    };
    let v: Json = serde_json::from_str(
        &std::fs::read_to_string(dir.join("pki-authority-node.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(v["persisted"], true, "Node sealed its rows");
    let authority = authority_over(&v);
    let mut failures: Vec<String> = Vec::new();

    // Read, never replaced.
    let root = authority.ensure_root(&BuildOptions::default()).unwrap();
    if root["serialHex"] != v["plain"][SERVICE_SCOPE]["root"]["serialHex"] {
        failures.push("ensure_root replaced Node's Root".into());
    }
    for scope in [PROCESS_SCOPE, "default"] {
        let row = authority.ensure_scope(scope).unwrap();
        if row["intermediate"]["serialHex"]
            != v["plain"][scope]["intermediate"]["serialHex"]
        {
            failures
                .push(format!("ensure_scope({}) rebuilt the branch", scope));
        }
        if !authority.scope_chains_to_root(scope) {
            failures.push(format!("{} does not chain to the Root", scope));
        }
    }

    // The addresses.
    for p in v["points"].as_array().unwrap() {
        let got = authority.distribution_points(
            p["scope"].as_str().unwrap(),
            p["ca"].as_str().unwrap(),
        );
        for (name, ours) in [
            ("http", &got.http),
            ("ldap", &got.ldap),
            ("ocsp", &got.ocsp),
            ("caIssuers", &got.ca_issuers),
            ("dn", &got.dn),
        ] {
            if p[name].as_str() != Some(ours.as_str()) {
                failures.push(format!(
                    "{}/{} {}: {} != {}",
                    p["scope"], p["ca"], name, ours, p[name]
                ));
            }
        }
    }

    // The CRLs, re-signed at Node's moment and number.
    for crl in v["crls"].as_array().unwrap() {
        let node = b64(&crl["der"]);
        let (scope, ca) =
            (crl["scope"].as_str().unwrap(), crl["ca"].as_str().unwrap());
        let tier = authority.tier_for(scope, ca).unwrap();
        let issuer =
            Certificate::from_pem(tier["certificatePem"].as_str().unwrap())
                .unwrap();
        let at =
            DateTime::parse_from_rfc3339(crl["thisUpdate"].as_str().unwrap())
                .unwrap()
                .with_timezone(&chrono::Utc);
        let number = crl_number(&node);
        assert_eq!(number, crl["crlNumber"].as_i64().unwrap());
        let entries = authority.list_for(scope, ca);
        let ours = sts_pki::authority::crl::sign_crl(
            &sts_pki::authority::crl::CrlInputs {
                issuer: &issuer,
                signer_pem: tier["privateKeyPem"].as_str().unwrap(),
                sig: sts_pki::authority::crl::status_signature_alg(&tier)
                    .unwrap(),
                entries: &entries,
                this_update: at,
                lifetime_ms: authority.config().crl_lifetime_ms(),
                number,
            },
        )
        .unwrap();
        if ours != node {
            failures.push(format!(
                "CRL {}/{} differs:\n node {}\n rust {}",
                scope,
                ca,
                der::hex(&node),
                der::hex(&ours)
            ));
        }
        // And the one the authority signs now is the same document but
        // for its moment and number.
        let now = authority.build_crl(scope, ca).unwrap();
        if now.count != crl["count"].as_u64().unwrap() as usize {
            failures.push(format!("CRL {}/{}: count", scope, ca));
        }
    }

    // OCSP, at Node's moment.
    for one in v["ocsp"].as_array().unwrap() {
        let request = b64(&one["request"]);
        let at = match one["thisUpdate"].as_str() {
            Some(t) => DateTime::parse_from_rfc3339(t)
                .unwrap()
                .with_timezone(&chrono::Utc),
            None => chrono::Utc::now(),
        };
        let ours = authority.answer_ocsp_at(
            one["scope"].as_str().unwrap(),
            one["ca"].as_str().unwrap(),
            &request,
            at,
        );
        if ours.status != one["status"].as_str().unwrap() {
            failures.push(format!(
                "OCSP {}: status {} != {}",
                one["name"], ours.status, one["status"]
            ));
        }
        if ours.der != b64(&one["der"]) {
            failures.push(format!(
                "OCSP {} differs:\n node {}\n rust {}",
                one["name"],
                der::hex(&b64(&one["der"])),
                der::hex(&ours.der)
            ));
        }
    }

    // Issued under Node's ACME CA, chained to Node's Root.
    let issued = authority
        .issue_enrolled(
            "default",
            "acme",
            &EnrolledSpec {
                subject: json!([{ "name": "CN", "value": "dave" }]),
                public_key_pem: v["publicKeyPem"].as_str().unwrap().into(),
                profile: "digital-signature".into(),
                days: 5,
                subject_alt_name: vec![
                    json!({ "kind": "uri", "value": "urn:sts:person:dave" }),
                ],
                identifier: "dave".into(),
                subject_kind: "person".into(),
                holder_subject: String::new(),
            },
        )
        .unwrap();
    let mut chain: Vec<String> = issued.chain_pem.clone();
    chain.push(root["certificatePem"].as_str().unwrap().to_string());
    for pair in chain.windows(2) {
        let (c, i) = (
            Certificate::from_pem(&pair[0]).unwrap(),
            Certificate::from_pem(&pair[1]).unwrap(),
        );
        if !verify_signature(&c, &i).unwrap() {
            failures.push("Rust's leaf does not chain to Node's Root".into());
        }
    }
    if !authority.issued_here("default", "acme", &issued.serial_hex) {
        failures.push("the enrolled leaf is not in the register".into());
    }
    assert!(
        failures.is_empty(),
        "{} differences:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn rust_hierarchy_for_node() {
    let Some(dir) = vectors() else {
        eprintln!("STS_CRYPTO_VECTORS has no pki-authority-node.json: skipped");
        return;
    };
    let rows = Arc::new(MemoryRows::new());
    let authority = Authority::new(rows.clone(), PkiConfig::development());
    let started = authority.start(&[]);
    assert!(started.built && started.errors.is_empty(), "{:?}", started);
    let pair = openssl::ec::EcKey::generate(
        &openssl::ec::EcGroup::from_curve_name(
            openssl::nid::Nid::X9_62_PRIME256V1,
        )
        .unwrap(),
    )
    .unwrap();
    let key = openssl::pkey::PKey::from_ec_key(pair).unwrap();
    let public = String::from_utf8(key.public_key_to_pem().unwrap()).unwrap();
    let issued = authority
        .issue_enrolled(
            "default",
            "acme",
            &EnrolledSpec {
                subject: json!([{ "name": "CN", "value": "erin" }]),
                public_key_pem: public,
                profile: "digital-signature".into(),
                days: 5,
                subject_alt_name: vec![
                    json!({ "kind": "uri", "value": "urn:sts:person:erin" }),
                ],
                identifier: "erin".into(),
                subject_kind: "person".into(),
                holder_subject: String::new(),
            },
        )
        .unwrap();
    authority
        .revoke(
            "default",
            "acme",
            &issued.serial_hex,
            Some("keyCompromise"),
            "CN=erin",
            "",
        )
        .unwrap();
    let crl = authority.build_crl("default", "acme").unwrap();
    // An OCSP request for the revoked leaf, SHA-1 CertID, as openssl and
    // pkijs make one.
    let acme = authority.tier_for("default", "acme").unwrap();
    let issuer =
        Certificate::from_pem(acme["certificatePem"].as_str().unwrap())
            .unwrap();
    let request = ocsp_request(&issuer, &issued.serial_hex);
    let ocsp = authority.answer_ocsp("default", "acme", &request);
    assert_eq!(ocsp.status, "successful");
    assert_eq!(ocsp.answers[0]["status"], "revoked");
    let mut held = serde_json::Map::new();
    for scope in rows.scopes() {
        held.insert(scope.clone(), rows.get(&scope).unwrap());
    }
    if std::env::var("STS_WRITE_VECTORS").is_ok() {
        std::fs::write(
            dir.join("pki-authority-rust.json"),
            serde_json::to_string_pretty(&json!({
                "rows": held,
                "issued": { "certificatePem": issued.certificate_pem,
                            "chainPem": issued.chain_pem },
                "crl": { "der": STANDARD.encode(&crl.der),
                         "revoked": issued.serial_hex },
                "ocsp": { "der": STANDARD.encode(&ocsp.der),
                          "request": STANDARD.encode(&request) },
            }))
            .unwrap(),
        )
        .unwrap();
    }
}

/// An OCSPRequest for one serial under an issuer, SHA-1 CertID.
fn ocsp_request(issuer: &Certificate, serial_hex: &str) -> Vec<u8> {
    let bits = {
        let spki = der::read(&issuer.spki).unwrap();
        let parts = der::children(spki.content).unwrap();
        parts[1].content[1..].to_vec()
    };
    let cert_id = der::sequence(&[
        der::sequence(&[der::oid("1.3.14.3.2.26").unwrap(), der::null()]),
        der::octet_string(&openssl::sha::sha1(&issuer.subject_der)),
        der::octet_string(&openssl::sha::sha1(&bits)),
        der::integer_raw(&sts_pki::authority::crl::serial_bytes(serial_hex)),
    ]);
    der::sequence(&[der::sequence(&[der::sequence(&[der::sequence(&[
        cert_id,
    ])])])])
}
