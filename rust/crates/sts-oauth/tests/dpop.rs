// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! RFC 9449's twelve checks, each refusal by its code, with a client written
//! here on `sts-crypto`'s signer: the thumbprint against RFC 7638's own
//! example, the proof accepted in four algorithm families, and the order —
//! a proof refused for its `ath` is not remembered, so it is not a replay.

#![allow(clippy::unwrap_used)] // a test file

use std::cell::RefCell;
use std::collections::HashSet;

use serde_json::{json, Map, Value as Json};
use sts_core::errors::{codes, ErrorCode};
use sts_crypto::jws::{generate_key, sign_jws, SignOptions};
use sts_crypto::keys::JwsKey;
use sts_oauth::dpop::{
    ath_of, normalize_htu, thumbprint, verify_proof, ProofContext,
    ProofRequest, Seen,
};

const NOW: i64 = 1_791_000_000;
const HTU: &str = "https://sts.example/oauth2/userinfo";

#[derive(Default)]
struct Ctx {
    nonces: bool,
    seen: RefCell<HashSet<String>>,
    elsewhere: Option<Seen>,
    full: bool,
}

impl ProofContext for Ctx {
    fn trust_proxy(&self) -> bool {
        false
    }
    fn nonce_required(&self) -> bool {
        self.nonces
    }
    fn nonce_is_current(&self, nonce: &Json) -> bool {
        nonce == "n-1"
    }
    fn seen(&self, jti: &str) -> Seen {
        if self.seen.borrow().contains(jti) {
            return Seen::Here;
        }
        self.elsewhere.unwrap_or(Seen::No)
    }
    fn remember(&self, jti: &str, _now: i64) -> bool {
        if self.full {
            return false;
        }
        self.seen.borrow_mut().insert(jti.to_string());
        true
    }
}

fn obj(v: Json) -> Map<String, Json> {
    v.as_object().unwrap().clone()
}

fn public(key: &JwsKey) -> Json {
    key.public_jwk().unwrap().unwrap()
}

fn proof_with(key: &JwsKey, alg: &str, header: Json, claims: Json) -> String {
    sign_jws(
        &obj(claims),
        key,
        &SignOptions {
            algorithm: Some(alg.into()),
            header: obj(header),
            now: Some(NOW),
            ..Default::default()
        },
    )
    .unwrap()
}

fn claims(jti: &str) -> Json {
    json!({ "jti": jti, "htm": "GET", "htu": HTU, "iat": NOW })
}

fn proof(key: &JwsKey, alg: &str, c: Json) -> String {
    proof_with(
        key,
        alg,
        json!({ "typ": "dpop+jwt", "jwk": public(key) }),
        c,
    )
}

fn req<'a>(token: Option<&'a str>, jkt: Option<&'a str>) -> ProofRequest<'a> {
    ProofRequest {
        htm: "GET",
        htu: HTU,
        access_token: token,
        expected_jkt: jkt,
        now: NOW,
    }
}

fn code(
    r: Result<sts_oauth::dpop::Proof, sts_oauth::dpop::Failure>,
) -> ErrorCode {
    r.unwrap_err().code
}

#[test]
fn the_thumbprint_is_rfc_7638s() {
    let jwk = json!({
        "kty": "RSA",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e": "AQAB", "alg": "RS256", "kid": "2011-04-29"
    });
    assert_eq!(
        thumbprint(&jwk).unwrap(),
        "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    );
    assert!(
        thumbprint(&json!({ "kty": "EC", "crv": "P-256", "x": "a" })).is_none()
    );
    assert_eq!(
        normalize_htu("HTTPS://STS.Example:443/a/b?x=1#f"),
        "https://sts.example/a/b"
    );
    assert_eq!(normalize_htu("http://h:8080/p"), "http://h:8080/p");
    assert_eq!(normalize_htu("not a url"), "not a url");
}

#[test]
fn a_proof_passes_in_every_family() {
    for alg in ["ES256", "ES384", "PS256", "RS256", "EdDSA", "ES256K"] {
        let key = generate_key(alg).unwrap();
        let ctx = Ctx::default();
        let p = verify_proof(
            Some(&proof(&key, alg, claims("j1"))),
            &req(None, None),
            &ctx,
        )
        .unwrap_or_else(|f| panic!("{}: {:?}", alg, f));
        assert_eq!(p.jkt, thumbprint(&public(&key)).unwrap(), "{}", alg);
    }
}

#[test]
fn every_refusal_has_its_code() {
    let key = generate_key("ES256").unwrap();
    let ctx = Ctx::default();
    let good = proof(&key, "ES256", claims("j1"));
    let r = verify_proof(None, &req(None, None), &ctx).unwrap_err();
    assert_eq!((r.code, r.missing), (codes::STS_OAUTH_0093, true));
    assert_eq!(
        code(verify_proof(
            Some(&format!("{}, {}", good, good)),
            &req(None, None),
            &ctx
        )),
        codes::STS_OAUTH_0094
    );
    assert_eq!(
        code(verify_proof(Some("a.b"), &req(None, None), &ctx)),
        codes::STS_OAUTH_0095
    );
    assert_eq!(
        code(verify_proof(Some("!!.e30.x"), &req(None, None), &ctx)),
        codes::STS_OAUTH_0096
    );
    assert_eq!(
        code(verify_proof(Some("e30.W10.x"), &req(None, None), &ctx)),
        codes::STS_OAUTH_0097
    );
    let jwk = public(&key);
    let r = |h: Json, c: Json, alg: &str| {
        verify_proof(Some(&proof_with(&key, alg, h, c)), &req(None, None), &ctx)
    };
    assert_eq!(
        code(r(json!({ "typ": "JWT", "jwk": jwk }), claims("t"), "ES256")),
        codes::STS_OAUTH_0098
    );
    let mac = proof_with(
        &JwsKey::secret(vec![1u8; 32]),
        "HS256",
        json!({ "typ": "dpop+jwt", "jwk": jwk }),
        claims("m"),
    );
    assert_eq!(
        code(verify_proof(Some(&mac), &req(None, None), &ctx)),
        codes::STS_OAUTH_0099
    );
    assert_eq!(
        code(r(json!({ "typ": "dpop+jwt" }), claims("k"), "ES256")),
        codes::STS_OAUTH_0100
    );
    let mut with_private = jwk.clone();
    with_private["d"] = json!("secret");
    let f = r(
        json!({ "typ": "dpop+jwt", "jwk": with_private }),
        claims("d"),
        "ES256",
    )
    .unwrap_err();
    assert_eq!(f.code, codes::STS_OAUTH_0101);
    assert!(f.description.contains("(d)"));
    let p384 = generate_key("ES384").unwrap();
    let mismatched = proof_with(
        &p384,
        "ES384",
        json!({ "typ": "dpop+jwt", "jwk": jwk }),
        claims("x"),
    );
    assert_eq!(
        code(verify_proof(Some(&mismatched), &req(None, None), &ctx)),
        codes::STS_OAUTH_0102
    );
    let f = r(
        json!({ "typ": "dpop+jwt", "jwk": jwk }),
        json!({ "htm": "GET", "htu": HTU, "iat": NOW }),
        "ES256",
    )
    .unwrap_err();
    assert_eq!(f.code, codes::STS_OAUTH_0103);
    assert!(f.description.contains("missing jti"));
    let f = r(
        json!({ "typ": "dpop+jwt", "jwk": jwk }),
        json!({ "jti": "z", "htm": "", "htu": HTU, "iat": NOW }),
        "ES256",
    )
    .unwrap_err();
    assert!(f.description.contains("missing htm"), "{}", f.description);
    // Another key's signature over a proof naming this one.
    let other = generate_key("ES256").unwrap();
    let forged = proof_with(
        &other,
        "ES256",
        json!({ "typ": "dpop+jwt", "jwk": jwk }),
        claims("f"),
    );
    assert_eq!(
        code(verify_proof(Some(&forged), &req(None, None), &ctx)),
        codes::STS_OAUTH_0104
    );
    let mut post = claims("h");
    post["htm"] = json!("POST");
    assert_eq!(
        code(r(json!({ "typ": "dpop+jwt", "jwk": jwk }), post, "ES256")),
        codes::STS_OAUTH_0105
    );
    let mut elsewhere = claims("u");
    elsewhere["htu"] = json!("https://other.example/oauth2/userinfo");
    let f = r(json!({ "typ": "dpop+jwt", "jwk": jwk }), elsewhere, "ES256")
        .unwrap_err();
    assert_eq!(f.code, codes::STS_OAUTH_0106);
    assert!(f.description.contains("global.trustProxy is OFF"));
    // Query, fragment and the default port are not part of htu.
    let mut same = claims("q");
    same["htu"] = json!("https://STS.example:443/oauth2/userinfo?a=b#c");
    assert!(r(json!({ "typ": "dpop+jwt", "jwk": jwk }), same, "ES256").is_ok());
    let mut old = claims("i");
    old["iat"] = json!(NOW - 301);
    assert_eq!(
        code(r(json!({ "typ": "dpop+jwt", "jwk": jwk }), old, "ES256")),
        codes::STS_OAUTH_0107
    );
    let mut nan = claims("i2");
    nan["iat"] = json!("soon");
    assert_eq!(
        code(r(json!({ "typ": "dpop+jwt", "jwk": jwk }), nan, "ES256")),
        codes::STS_OAUTH_0107
    );
}

#[test]
fn nonces_replays_and_the_binding() {
    let key = generate_key("ES256").unwrap();
    let jkt = thumbprint(&public(&key)).unwrap();
    let nonced = Ctx {
        nonces: true,
        ..Default::default()
    };
    let f = verify_proof(
        Some(&proof(&key, "ES256", claims("n0"))),
        &req(None, None),
        &nonced,
    )
    .unwrap_err();
    assert_eq!((f.code, f.need_nonce), (codes::STS_OAUTH_0108, true));
    let mut wrong = claims("n1");
    wrong["nonce"] = json!("n-0");
    let f = verify_proof(
        Some(&proof(&key, "ES256", wrong)),
        &req(None, None),
        &nonced,
    )
    .unwrap_err();
    assert_eq!((f.code, f.need_nonce), (codes::STS_OAUTH_0109, true));
    let mut right = claims("n2");
    right["nonce"] = json!("n-1");
    assert!(verify_proof(
        Some(&proof(&key, "ES256", right)),
        &req(None, None),
        &nonced
    )
    .is_ok());

    // A proof is good for one request.
    let ctx = Ctx::default();
    let once = proof(&key, "ES256", claims("r1"));
    assert!(verify_proof(Some(&once), &req(None, None), &ctx).is_ok());
    assert_eq!(
        code(verify_proof(Some(&once), &req(None, None), &ctx)),
        codes::STS_OAUTH_0110
    );
    for (seen, want) in [
        (Seen::Elsewhere, codes::STS_OAUTH_0519),
        (Seen::Unknown, codes::STS_OAUTH_0520),
    ] {
        let c = Ctx {
            elsewhere: Some(seen),
            ..Default::default()
        };
        assert_eq!(
            code(verify_proof(
                Some(&proof(&key, "ES256", claims("r2"))),
                &req(None, None),
                &c
            )),
            want
        );
    }
    let full = Ctx {
        full: true,
        ..Default::default()
    };
    assert_eq!(
        code(verify_proof(
            Some(&proof(&key, "ES256", claims("r3"))),
            &req(None, None),
            &full
        )),
        codes::STS_OAUTH_0554
    );

    // With a token: ath, then the binding. A refused proof is not remembered.
    let token = "an.access.token";
    let no_ath = proof(&key, "ES256", claims("a1"));
    assert_eq!(
        code(verify_proof(
            Some(&no_ath),
            &req(Some(token), Some(&jkt)),
            &ctx
        )),
        codes::STS_OAUTH_0111
    );
    assert!(
        verify_proof(Some(&no_ath), &req(None, None), &ctx).is_ok(),
        "not remembered when refused"
    );
    let mut bad_ath = claims("a2");
    bad_ath["ath"] = json!(ath_of("another.token.here"));
    assert_eq!(
        code(verify_proof(
            Some(&proof(&key, "ES256", bad_ath)),
            &req(Some(token), Some(&jkt)),
            &ctx
        )),
        codes::STS_OAUTH_0112
    );
    let mut with_ath = claims("a3");
    with_ath["ath"] = json!(ath_of(token));
    let p = proof(&key, "ES256", with_ath.clone());
    assert_eq!(
        code(verify_proof(
            Some(&p),
            &req(Some(token), Some("someone-else")),
            &ctx
        )),
        codes::STS_OAUTH_0113
    );
    let ok =
        verify_proof(Some(&p), &req(Some(token), Some(&jkt)), &ctx).unwrap();
    assert_eq!(ok.jkt, jkt);
    assert_eq!(ok.claims["jti"], "a3");
}
