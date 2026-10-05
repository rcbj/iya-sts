// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! RFC 9068 section 4 at a resource server here, held to the cases
//! `tests/rfc9068_access_tokens.js` holds the Node module to: the `typ`
//! readings, an address as part of an issuer, a pinned issuer, a named
//! authorization server, a partner's `/resource` refused, and the order of
//! the three refusals.

#![allow(clippy::unwrap_used)] // a test file

use std::collections::HashMap;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value as Json};
use sts_core::errors::codes;
use sts_core::settings::Settings;
use sts_oauth::jwt_access_token::{AudienceRule, JwtAccessTokens};

const BASE: &str = "https://sts.example:8081";

fn tokens(file: Json) -> JwtAccessTokens {
    JwtAccessTokens::new(Arc::new(Settings::new(file, HashMap::new())))
}

fn token(typ: Option<&str>) -> String {
    let header = match typ {
        Some(t) => json!({ "alg": "RS256", "typ": t }),
        None => json!({ "alg": "RS256" }),
    };
    format!("{}.e30.c2ln", URL_SAFE_NO_PAD.encode(header.to_string()))
}

#[test]
fn the_type() {
    for ok in [
        "at+jwt",
        "AT+JWT",
        " application/at+jwt ",
        "Application/AT+JWT",
    ] {
        assert!(JwtAccessTokens::is_access_token_type(ok), "{}", ok);
    }
    for no in ["JWT", "", "jwt+at", "application/jwt", "logout+jwt"] {
        assert!(!JwtAccessTokens::is_access_token_type(no), "{}", no);
    }
    assert_eq!(JwtAccessTokens::typ_of(&token(Some("at+jwt"))), "at+jwt");
    assert_eq!(JwtAccessTokens::typ_of(&token(None)), "");
    assert_eq!(JwtAccessTokens::typ_of("not a token"), "");
    assert_eq!(JwtAccessTokens::typ_of(""), "");
}

#[test]
fn the_issuer() {
    let t = tokens(json!({}));
    assert_eq!(t.issuer_for(BASE), BASE);
    assert!(t.is_hosted_issuer(BASE, BASE));
    assert!(t.is_hosted_issuer(&format!("{}/as1", BASE), BASE));
    assert!(t.is_hosted_issuer(&format!("{}/a.b~c-d", BASE), BASE));
    // An address is part of an issuer.
    assert!(!t.is_hosted_issuer("https://127.0.0.1:8081", BASE));
    assert!(!t.is_hosted_issuer(&format!("{}/as1/deeper", BASE), BASE));
    assert!(!t.is_hosted_issuer(&format!("{}/-as1", BASE), BASE));
    assert!(!t.is_hosted_issuer(&format!("{}/{}", BASE, "a".repeat(65)), BASE));
    assert!(!t.is_hosted_issuer(&format!("{}x", BASE), BASE));
    assert!(!t.is_hosted_issuer("", BASE));
    // A pinned issuer wins, and the base no longer answers.
    let pinned =
        tokens(json!({ "oauth2": { "issuer": "https://login.example" } }));
    assert!(pinned.is_hosted_issuer("https://login.example", BASE));
    assert!(!pinned.is_hosted_issuer(BASE, BASE));
    // An http:// pin on an HTTPS listener is served as https://.
    let upgraded = tokens(json!({
        "oauth2": { "issuer": "HTTP://login.example" },
        "global": { "https": true }
    }));
    assert_eq!(upgraded.issuer_for(BASE), "https://login.example");
    let plain = tokens(json!({
        "oauth2": { "issuer": "http://login.example" },
        "global": { "https": false }
    }));
    assert_eq!(plain.issuer_for(BASE), "http://login.example");
}

#[test]
fn the_audience() {
    let own = |aud: &str| JwtAccessTokens::is_own_resource_audience(aud, BASE);
    assert!(own(&format!("{}/resource", BASE)));
    assert!(own(&format!("{}/as1/resource", BASE)));
    // Somebody else's server, narrowed to by RFC 8707, is not this one.
    assert!(!own("https://api.partner.example/resource"));
    assert!(!own("/resource"));
    assert!(!own(BASE));
    assert!(!own(&format!("{}/resources", BASE)));
    assert_eq!(
        JwtAccessTokens::default_audience_for(BASE),
        format!("{}/resource", BASE)
    );
}

#[test]
fn the_refusals_in_the_section_order() {
    let t = tokens(json!({}));
    let good = json!({ "iss": BASE, "aud": format!("{}/resource", BASE) });
    let at = token(Some("at+jwt"));
    assert_eq!(t.resource_server_refusal(&at, &good, BASE, None), None);
    // The type first, even with the issuer and audience wrong too.
    let bad = json!({ "iss": "https://elsewhere", "aud": "x" });
    let r = t
        .resource_server_refusal(&token(Some("JWT")), &bad, BASE, None)
        .unwrap();
    assert_eq!((r.code, r.error), (codes::STS_OAUTH_0247, "invalid_token"));
    assert!(r.description.contains("\"JWT\""));
    let r = t
        .resource_server_refusal(&token(None), &good, BASE, None)
        .unwrap();
    assert!(r.description.contains("is absent"));
    // Then the issuer, then the audience.
    let r = t.resource_server_refusal(&at, &bad, BASE, None).unwrap();
    assert_eq!(r.code, codes::STS_OAUTH_0248);
    assert!(r.description.contains("\"https://elsewhere\""));
    let r = t
        .resource_server_refusal(&at, &json!({ "aud": "x" }), BASE, None)
        .unwrap();
    assert!(r.description.contains("no issuer"));
    let r = t
        .resource_server_refusal(&at, &json!({ "iss": BASE, "aud": "https://api.partner.example/resource" }), BASE, None)
        .unwrap();
    assert_eq!(r.code, codes::STS_OAUTH_0114);
    let r = t
        .resource_server_refusal(&at, &json!({ "iss": BASE }), BASE, None)
        .unwrap();
    assert!(r.description.contains("no audience"));
    // One own audience among several is enough.
    let several = json!({ "iss": format!("{}/as1", BASE),
                          "aud": ["https://api.example/", format!("{}/as1/resource", BASE)] });
    assert_eq!(t.resource_server_refusal(&at, &several, BASE, None), None);
    // A stand-in answering for an application replaces step 4 only.
    let names =
        |held: &[String]| held.iter().any(|a| a == "https://app.example/");
    let rule = AudienceRule {
        names: &names,
        label: "the application app1",
    };
    let for_app = json!({ "iss": BASE, "aud": "https://app.example/" });
    assert_eq!(
        t.resource_server_refusal(&at, &for_app, BASE, Some(&rule)),
        None
    );
    let r = t
        .resource_server_refusal(&at, &good, BASE, Some(&rule))
        .unwrap();
    assert_eq!(r.code, codes::STS_OAUTH_0506);
    assert!(r.description.contains("the application app1"));
    let r = t
        .resource_server_refusal(
            &token(Some("JWT")),
            &for_app,
            BASE,
            Some(&rule),
        )
        .unwrap();
    assert_eq!(r.code, codes::STS_OAUTH_0247);
}
