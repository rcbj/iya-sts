// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The gate's token half, each refusal by its code in Node's order, over a
//! key set this runtime makes: no token (0001), another key (0002), revoked
//! or disabled (0122), not at+jwt (0082), another issuer (0083), another
//! audience (0004, 403), a certificate-bound token without its certificate
//! (0110), a DPoP-bound one as Bearer (0120), and accepted with the scope a
//! GET and a POST need.

#![allow(clippy::unwrap_used)] // a test file

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{json, Map, Value as Json};
use sts_core::errors::codes;
use sts_core::mode::Mode;
use sts_core::realm::{RealmRegistry, SettingsEnvironment};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::StoreHandles;
use sts_core::settings::Settings;
use sts_crypto::jws::{sign_jws, SignOptions};
use sts_mgmt_api::gate::{presented_token_of, Arrived, Gate};
use sts_oauth::dpop_stores::DpopStores;
use sts_oauth::jwt_access_token::JwtAccessTokens;
use sts_store::key_sets::{generate_key_set, KeySet};

const NOW: i64 = 1_791_000_000;
const BASE: &str = "https://sts.example";

fn set() -> KeySet {
    KeySet {
        realm: "default".into(),
        blob: generate_key_set(NOW * 1000).unwrap(),
    }
}

fn token(keys: &KeySet, typ: &str, claims: Json) -> String {
    let (key, kid) = keys.signer_for("RS256", "").unwrap();
    let mut header = Map::new();
    header.insert("typ".into(), json!(typ));
    sign_jws(
        claims.as_object().unwrap(),
        &key,
        &SignOptions {
            algorithm: Some("RS256".into()),
            keyid: Some(kid),
            header,
            now: Some(NOW),
            ..Default::default()
        },
    )
    .unwrap()
}

fn good() -> Json {
    json!({ "iss": BASE, "aud": format!("{}/admin-api", BASE), "exp": NOW + 600, "jti": "t1",
            "client_id": "sts-management-api", "sub": "sts-management-api", "scope": "admin:read admin:write" })
}

#[test]
fn every_refusal_in_order() {
    let settings = Arc::new(Settings::new(json!({}), HashMap::new()));
    let registry = Arc::new(RealmRegistry::new(Arc::new(
        SettingsEnvironment::new(settings.clone(), Vec::new()),
    )));
    let lifecycle = RealmLifecycle::new(
        registry,
        settings.clone(),
        Arc::new(Mode::new(settings.clone())),
    );
    let stores = DpopStores::new(
        &lifecycle,
        &StoreHandles::new(),
        settings.clone(),
        Arc::new(|| NOW),
    );
    let keys = set();
    let tokens = JwtAccessTokens::new(settings.clone());
    let revoked = |jti: &str| jti == "revoked";
    let disabled = |sub: &str| sub == "mallory";
    let ended = |jti: &str| jti == "signed-out";
    let method = |client: &str| {
        if client == "sts-admin-console" {
            "none".to_string()
        } else {
            "private_key_jwt".to_string()
        }
    };
    let gate = Gate {
        settings: &settings,
        keys: &keys,
        tokens: &tokens,
        revoked: &revoked,
        disabled: &disabled,
        dpop: stores.as_ref(),
        eddsa_curve: "",
        session_ended: &ended,
        client_method: &method,
    };
    let ask = |method: &str, auth: Option<String>| {
        gate.check(&Arrived {
            method,
            authorization: auth.as_deref(),
            htu: "https://sts.example/admin-api/users",
            base: BASE,
            now: NOW,
            ..Default::default()
        })
    };
    let bearer = |t: String| Some(format!("Bearer {}", t));
    let code = |r: Result<
        sts_mgmt_api::gate::Admitted,
        sts_mgmt_api::gate::Refused,
    >| r.unwrap_err().code;

    let r = ask("GET", None).unwrap_err();
    assert_eq!((r.status, r.code), (401, codes::STS_API_0001));
    assert!(r
        .www_authenticate
        .unwrap()
        .contains("scope=\"admin:read admin:write\""));
    assert_eq!(
        code(ask("GET", bearer(token(&set(), "at+jwt", good())))),
        codes::STS_API_0002
    );
    let mut c = good();
    c["exp"] = json!(NOW - 1);
    assert_eq!(
        code(ask("GET", bearer(token(&keys, "at+jwt", c)))),
        codes::STS_API_0002,
        "expired fails the verify, as in Node"
    );
    let mut c = good();
    c["jti"] = json!("revoked");
    assert_eq!(
        code(ask("GET", bearer(token(&keys, "at+jwt", c)))),
        codes::STS_API_0122
    );
    let mut c = good();
    c["sub"] = json!("mallory");
    assert_eq!(
        code(ask("GET", bearer(token(&keys, "at+jwt", c)))),
        codes::STS_API_0122
    );
    assert_eq!(
        code(ask("GET", bearer(token(&keys, "JWT", good())))),
        codes::STS_API_0082
    );
    let mut c = good();
    c["iss"] = json!("https://elsewhere.example");
    assert_eq!(
        code(ask("GET", bearer(token(&keys, "at+jwt", c)))),
        codes::STS_API_0083
    );
    let mut c = good();
    c["aud"] = json!(format!("{}/resource", BASE));
    let r = ask("GET", bearer(token(&keys, "at+jwt", c))).unwrap_err();
    assert_eq!((r.status, r.code), (403, codes::STS_API_0004));
    let mut c = good();
    c["cnf"] = json!({ "x5t#S256": "abc" });
    assert_eq!(
        code(ask("GET", bearer(token(&keys, "at+jwt", c)))),
        codes::STS_API_0110
    );
    let mut c = good();
    c["cnf"] = json!({ "jkt": "abc" });
    assert_eq!(
        code(ask("GET", bearer(token(&keys, "at+jwt", c.clone())))),
        codes::STS_API_0120
    );
    assert_eq!(
        code(ask(
            "GET",
            Some(format!("DPoP {}", token(&keys, "at+jwt", c)))
        )),
        codes::STS_OAUTH_0093
    );

    // #446: a token whose sign-on session ended, and the public console's
    // unbound token; the same token from a confidential client is admitted.
    let mut c = good();
    c["jti"] = json!("signed-out");
    assert_eq!(
        code(ask("GET", bearer(token(&keys, "at+jwt", c)))),
        codes::STS_API_0126
    );
    let mut c = good();
    c["client_id"] = json!("sts-admin-console");
    c["sub"] = json!("alice");
    let r = ask("GET", bearer(token(&keys, "at+jwt", c))).unwrap_err();
    assert_eq!((r.status, r.code), (401, codes::STS_OAUTH_0939));
    assert!(ask("GET", bearer(token(&keys, "at+jwt", good()))).is_ok());
    use sts_oauth::sender_constraints::public_client_issuance_refusal as issuance;
    assert_eq!(
        issuance("sts-admin-console", "none", "", "authorization_code")
            .unwrap()
            .code,
        codes::STS_OAUTH_0938
    );
    assert!(
        issuance("sts-admin-console", "none", "jkt", "authorization_code")
            .is_none()
    );
    assert!(
        issuance("sts-admin-console", "client_secret_basic", "", "").is_none(),
        "not while confidential"
    );
    assert!(
        issuance("sts-user-portal", "none", "", "").is_none(),
        "the portal is in neither list"
    );

    let ok = ask("GET", bearer(token(&keys, "at+jwt", good()))).unwrap();
    assert_eq!(
        (ok.needed_scope, ok.scheme.as_str()),
        ("admin:read", "bearer")
    );
    assert_eq!(
        ask("POST", bearer(token(&keys, "at+jwt", good())))
            .unwrap()
            .needed_scope,
        "admin:write"
    );
    assert_eq!(
        presented_token_of(Some("Basic abc")),
        (String::new(), String::new())
    );
    assert_eq!(presented_token_of(Some("bearer  x ")).0, "x");
}
