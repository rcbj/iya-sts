// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! RFC 8705 section 3.1 at a resource server: a bound token on its own
//! certificate, on none (0091), on another (0092), unbound, and foreign; the
//! thumbprint checked against a value computed independently here.

#![allow(clippy::unwrap_used)] // a test file

use serde_json::json;
use sts_core::errors::codes;
use sts_oauth::mtls::{
    bound_thumbprint_of, certificate_thumbprint, check_binding,
};

/// A certificate made for this run, and its DER.
fn certificate(cn: &str) -> Vec<u8> {
    use openssl::{
        asn1::Asn1Time, bn::BigNum, hash::MessageDigest, pkey::PKey, x509,
    };
    let key = PKey::from_ec_key(
        openssl::ec::EcKey::generate(
            &openssl::ec::EcGroup::from_curve_name(
                openssl::nid::Nid::X9_62_PRIME256V1,
            )
            .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let mut name = x509::X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", cn).unwrap();
    let name = name.build();
    let mut b = x509::X509Builder::new().unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    let serial = BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
    b.set_serial_number(&serial).unwrap();
    let start = Asn1Time::days_from_now(0).unwrap();
    let end = Asn1Time::days_from_now(1).unwrap();
    b.set_not_before(&start).unwrap();
    b.set_not_after(&end).unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    b.build().to_der().unwrap()
}

#[test]
fn a_bound_token_is_held_to_its_certificate() {
    let mine = certificate("holder");
    let other = certificate("somebody else");
    // Independently: the digest X509 reports, base64url.
    let x = openssl::x509::X509::from_der(&mine).unwrap();
    let digest = x.digest(openssl::hash::MessageDigest::sha256()).unwrap();
    use base64::Engine;
    let expect =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&*digest);
    assert_eq!(certificate_thumbprint(&mine), expect);
    assert_eq!(expect.len(), 43);

    let claims = json!({ "cnf": { "x5t#S256": expect } });
    assert_eq!(bound_thumbprint_of(&claims), expect);
    assert_eq!(check_binding(&claims, Some(&mine), true, None), None);
    let r = check_binding(&claims, None, true, None).unwrap();
    assert_eq!((r.code, r.error), (codes::STS_OAUTH_0091, "invalid_token"));
    assert!(r.description.contains("this access token is bound"));
    let r =
        check_binding(&claims, Some(&[]), true, Some("refresh token")).unwrap();
    assert_eq!(r.code, codes::STS_OAUTH_0091);
    assert!(r.description.contains("this refresh token is bound"));
    let r = check_binding(&claims, Some(&other), true, None).unwrap();
    assert_eq!(r.code, codes::STS_OAUTH_0092);
    assert!(r.description.contains(&certificate_thumbprint(&other)));
    // A foreign token's cnf is not enforced; an unbound token has none.
    assert_eq!(check_binding(&claims, Some(&other), false, None), None);
    assert_eq!(
        check_binding(&json!({ "cnf": { "jkt": "x" } }), None, true, None),
        None
    );
    assert_eq!(check_binding(&json!({}), None, true, None), None);
    assert_eq!(bound_thumbprint_of(&json!({ "cnf": "flat" })), "");
}
