// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE REVERSE PROXY OVER REAL SOCKETS (#1760): this container's proxy on
//! a loopback port, in front of a mock application that echoes what
//! reached it, beside a mock service answering the JWKS, the token
//! endpoint and the four validation endpoints — each mechanism admitted and
//! refused, the route table's refusals, the body bound, the upstream's
//! failures, the headers that may not cross, and the session flow from the
//! redirect to a sign-out at the service ending it. Every key is made at
//! run time.

use std::collections::HashSet;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Json, Request};
use axum::http::StatusCode;
use axum::routing::{get, post};
use hyper::body::{Body as HttpBody, Frame};
use openssl::pkey::{PKey, Private};
use serde_json::{json, Value};

use crate::jwt::testing::{jwk_of, rsa_key, sign};
use crate::listener::HttpsListener;
use crate::options::Options;
use crate::pdp_client::PdpClient;
use crate::pip::RemotePip;
use crate::proxy::{self, Proxy};
use crate::rp_session::code_challenge;
use crate::saml_verify::testing as saml;
use crate::service::Pep;
use crate::sync::Sync;

const AUD: &str = "https://app.example/api";
const ISSUER: &str = "https://sts.example/realm/r1";
const SAML_ISSUER: &str = "https://sts.example/realm/r1";
const CLIENT: &str = "xacml-pep-pep-1";

/// What the mock service has been told and has seen.
#[derive(Default)]
struct ServiceState {
    jwks: Value,
    live: HashSet<String>,
    /// (code_challenge, nonce, sid) the next code redemption answers for.
    expect: Option<(String, String, String)>,
    saml_calls: u32,
    introspect_calls: u32,
    jwks_fetches: u32,
}

struct Harness {
    proxy: String,
    service: Arc<Mutex<ServiceState>>,
    key: Arc<PKey<Private>>,
    sync: Arc<Sync>,
    http: reqwest::Client,
    service_base: String,
    upstream_base: String,
    saml_signer: (PKey<Private>, openssl::x509::X509),
}

const POLICY: &str = r#"<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" PolicyId="proxy-test" Version="1.0" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:first-applicable"><Target/>
<Rule RuleId="no-mallory" Effect="Deny"><Target><AnyOf><AllOf><Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal"><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">mallory</AttributeValue><AttributeDesignator Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject" AttributeId="urn:oasis:names:tc:xacml:1.0:subject:subject-id" DataType="http://www.w3.org/2001/XMLSchema#string" MustBePresent="false"/></Match></AllOf></AnyOf></Target></Rule>
<Rule RuleId="no-secret" Effect="Deny"><Target><AnyOf><AllOf><Match MatchId="urn:oasis:names:tc:xacml:1.0:function:anyURI-equal"><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#anyURI">urn:app:secret</AttributeValue><AttributeDesignator Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource" AttributeId="urn:oasis:names:tc:xacml:1.0:resource:resource-id" DataType="http://www.w3.org/2001/XMLSchema#anyURI" MustBePresent="false"/></Match></AllOf></AnyOf></Target></Rule>
<Rule RuleId="everyone-else" Effect="Permit"/></Policy>"#;

async fn serve(router: axum::Router) -> u16 {
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Err(error) = axum::serve(socket, router).await {
            eprintln!("a mock stopped: {}", error);
        }
    });
    port
}

/// The application: echoes the method, path, query, headers and body
/// length; `/pep-app/slow` takes two seconds and `/pep-app/public/away`
/// redirects elsewhere.
async fn upstream() -> u16 {
    let echo = |request: Request| async move {
        let (parts, body) = request.into_parts();
        let bytes = axum::body::to_bytes(body, 10_000_000).await.unwrap();
        if parts.uri.path() == "/pep-app/slow" {
            tokio::time::sleep(Duration::from_millis(2000)).await;
        }
        if parts.uri.path() == "/pep-app/public/away" {
            return axum::response::Response::builder()
                .status(302)
                .header("location", "http://elsewhere.example/")
                .body(axum::body::Body::empty())
                .unwrap();
        }
        let mut headers = serde_json::Map::new();
        for (name, value) in &parts.headers {
            headers.insert(
                name.as_str().to_string(),
                json!(value.to_str().unwrap_or("")),
            );
        }
        let said = json!({ "method": parts.method.as_str(),
            "path": parts.uri.path(), "query": parts.uri.query(),
            "headers": headers, "bodyLength": bytes.len() });
        axum::response::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .header("connection", "x-upstream-private")
            .header("x-upstream-private", "1")
            .body(axum::body::Body::from(said.to_string()))
            .unwrap()
    };
    serve(axum::Router::new().fallback(echo)).await
}

fn id_token(key: &PKey<Private>, nonce: &str, sid: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    sign(
        key,
        "RS256",
        "k1",
        &json!({ "iss": ISSUER, "aud": CLIENT, "sub": "urn:uuid:carol",
                 "preferred_username": "carol", "nonce": nonce, "sid": sid,
                 "exp": now + 300, "iat": now }),
    )
}

async fn service(
    state: Arc<Mutex<ServiceState>>,
    key: Arc<PKey<Private>>,
) -> u16 {
    let s1 = state.clone();
    let jwks = move || {
        let s = s1.clone();
        async move {
            let mut g = s.lock().unwrap();
            g.jwks_fetches += 1;
            Json(g.jwks.clone())
        }
    };
    let s2 = state.clone();
    let introspect = move |Json(body): Json<Value>| {
        let s = s2.clone();
        async move {
            s.lock().unwrap().introspect_calls += 1;
            Json(match body["token"].as_str().unwrap_or("") {
                "opaque-good" => json!({ "active": true, "aud": [AUD],
                    "iss": ISSUER, "sub": "urn:uuid:7", "username": "bob" }),
                "opaque-wrong-aud" => json!({ "active": true,
                    "aud": "https://other", "iss": ISSUER, "sub": "x" }),
                "opaque-other-iss" => json!({ "active": true, "aud": AUD,
                    "iss": "https://other.example", "sub": "x" }),
                "opaque-jkt" => json!({ "active": true, "aud": AUD,
                    "iss": ISSUER, "sub": "x", "cnf": { "jkt": "abc" } }),
                _ => json!({ "active": false }),
            })
        }
    };
    let basic = |Json(body): Json<Value>| async move {
        let user = body["username"].as_str().unwrap_or("");
        let pass = body["password"].as_str().unwrap_or("");
        match (user, pass) {
            ("locked", _) => (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({ "error": "blocked", "retryAfterS": 30 })),
            ),
            (_, "right") => (
                StatusCode::OK,
                Json(
                    json!({ "valid": true, "sub": format!("urn:uuid:{}", user),
                             "username": user }),
                ),
            ),
            _ => (StatusCode::OK, Json(json!({ "valid": false }))),
        }
    };
    let s3 = state.clone();
    let saml_check = move |Json(body): Json<Value>| {
        let s = s3.clone();
        async move {
            s.lock().unwrap().saml_calls += 1;
            let xml = openssl::base64::decode_block(
                body["assertion"].as_str().unwrap_or(""),
            )
            .unwrap_or_default();
            let ok = String::from_utf8_lossy(&xml).contains("service-valid")
                && body["audience"] == AUD;
            Json(if ok {
                json!({ "valid": true, "subject": "urn:uuid:from-service",
                        "username": "sam" })
            } else {
                json!({ "valid": false })
            })
        }
    };
    let s4 = state.clone();
    let session = move |Json(body): Json<Value>| {
        let s = s4.clone();
        async move {
            let live = s
                .lock()
                .unwrap()
                .live
                .contains(body["sid"].as_str().unwrap_or(""));
            Json(json!({ "live": live, "sub": "urn:uuid:carol",
                         "username": "carol" }))
        }
    };
    let s5 = state.clone();
    let token = move |body: String| {
        let s = s5.clone();
        let key = key.clone();
        async move {
            let form: Vec<(String, String)> =
                reqwest::Url::parse(&format!("http://x/?{}", body))
                    .unwrap()
                    .query_pairs()
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .collect();
            let get = |k: &str| {
                form.iter()
                    .find(|(n, _)| n == k)
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default()
            };
            let expect = s.lock().unwrap().expect.clone();
            let Some((challenge, nonce, sid)) = expect else {
                return (StatusCode::BAD_REQUEST, Json(json!({})));
            };
            // PKCE: the verifier must be the challenge's.
            if code_challenge(&get("code_verifier")) != challenge
                || get("client_id") != CLIENT
                || get("grant_type") != "authorization_code"
            {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "invalid_grant" })),
                );
            }
            let nonce = if get("code") == "bad-nonce" {
                "not-the-nonce".to_string()
            } else {
                nonce
            };
            (
                StatusCode::OK,
                Json(json!({ "id_token": id_token(&key, &nonce, &sid),
                             "access_token": "x", "token_type": "Bearer" })),
            )
        }
    };
    let router = axum::Router::new()
        .route("/jwks", get(jwks))
        .route("/introspect", post(introspect))
        .route("/basic", post(basic))
        .route("/saml", post(saml_check))
        .route("/session", post(session))
        .route("/token", post(token));
    serve(router).await
}

fn configuration(upstream: &str, service: &str, cert_pem: &str) -> Value {
    json!({
        "syncToken": "p1", "pep": "pep-1", "configured": true,
        "proxy": {
            "enabled": true,
            "upstream": upstream,
            "publicBaseUrl": "https://proxy.example",
            "upstreamTimeoutMs": 500,
            "maxBodyBytes": 64,
            "routes": [
                { "id": "public", "path": "/public", "methods": ["GET", "HEAD"],
                  "public": true, "subjectHeader": "X-Remote-User" },
                { "id": "api", "path": "/api", "methods": ["GET", "POST"],
                  "mechanisms": ["oauth2", "basic"], "audience": AUD,
                  "subjectHeader": "X-Remote-User",
                  "mechanismHeader": "X-Remote-Auth" },
                { "id": "saml", "path": "/saml", "mechanisms": ["saml2"],
                  "audience": AUD, "subjectHeader": "X-Remote-User" },
                { "id": "app", "path": "/app", "mechanisms": ["session"],
                  "subjectHeader": "X-Remote-User" },
                { "id": "fwd", "path": "/fwd", "mechanisms": ["basic"],
                  "forwardCredentials": true },
                { "id": "secret", "path": "/secret", "match": "exact",
                  "mechanisms": ["basic"], "resource": "urn:app:secret" },
                { "id": "slow", "path": "/slow", "match": "exact",
                  "public": true }
            ]
        },
        "realm": {
            "issuer": ISSUER, "jwksUri": format!("{}/jwks", service),
            "authorizationEndpoint": "https://sts.example/realm/r1/oauth2/authorize",
            "tokenEndpoint": format!("{}/token", service),
            "endSessionEndpoint": "https://sts.example/realm/r1/oauth2/logout",
            "samlIssuer": SAML_ISSUER,
            "signingCertificates": [cert_pem],
            "clientId": CLIENT,
            "redirectUri": "https://proxy.example/.iya-pep/callback"
        },
        "validation": {
            "introspect": format!("{}/introspect", service),
            "basic": format!("{}/basic", service),
            "saml": format!("{}/saml", service),
            "session": format!("{}/session", service)
        }
    })
}

async fn harness() -> Harness {
    let key = Arc::new(rsa_key());
    let state = Arc::new(Mutex::new(ServiceState {
        jwks: json!({ "keys": [jwk_of(&key, "k1")] }),
        ..ServiceState::default()
    }));
    let up = upstream().await;
    let svc = service(state.clone(), key.clone()).await;
    let service_base = format!("http://127.0.0.1:{}", svc);
    let upstream_base = format!("http://127.0.0.1:{}/pep-app", up);
    let mut options = Options::from_env("0.0.0");
    options.pdp_url = service_base.clone();
    options.pip_enabled = false;
    options.proxy_session_recheck_ms = 0;
    let client = PdpClient::new(&options).unwrap();
    let sync = Arc::new(Sync::new(client.clone(), options.clone()));
    sync.load_for_test(&json!({ "syncToken": "1", "policies": [
        { "policyId": "proxy-test", "name": "t", "isRoot": true,
          "document": POLICY } ] }));
    let saml_signer = saml::signer();
    let cert_pem = String::from_utf8(saml_signer.1.to_pem().unwrap()).unwrap();
    sync.receive_proxy(
        &configuration(&upstream_base, &service_base, &cert_pem),
        Some("\"e1\"".into()),
    );
    let pep = Arc::new(Pep::new(
        options,
        sts_core::version::load(Path::new(".")),
        sync.clone(),
        RemotePip::new(client.clone(), false),
        Arc::new(HttpsListener::new("", "", 0, 1000, None)),
    ));
    let proxy = Arc::new(Proxy::new(pep, client));
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    tokio::spawn(proxy::serve_on(proxy, socket));
    Harness {
        proxy: format!("http://127.0.0.1:{}", port),
        service: state,
        key,
        sync,
        http: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
        service_base,
        upstream_base,
        saml_signer,
    }
}

impl Harness {
    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.http.get(format!("{}{}", self.proxy, path))
    }

    fn token(&self, claims: Value) -> String {
        sign(&self.key, "RS256", "k1", &claims)
    }

    fn claims(&self) -> Value {
        let now = chrono::Utc::now().timestamp();
        json!({ "iss": ISSUER, "aud": AUD, "sub": "urn:uuid:alice",
                "username": "alice", "exp": now + 300 })
    }
}

async fn echoed(response: reqwest::Response) -> Value {
    assert_eq!(response.status(), 200, "{:?}", response);
    response.json().await.unwrap()
}

fn challenges(response: &reqwest::Response) -> Vec<String> {
    response
        .headers()
        .get_all("www-authenticate")
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

/// The status of a GET whose request target is sent byte for byte.
async fn raw_status(base: &str, target: &str) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let address = base.trim_start_matches("http://");
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream
        .write_all(
            format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                target, address
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).await.unwrap();
    answer
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// A request body of unknown length, sent chunked.
struct Chunks(Vec<Bytes>);

impl HttpBody for Chunks {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if this.0.is_empty() {
            Poll::Ready(None)
        } else {
            Poll::Ready(Some(Ok(Frame::data(this.0.remove(0)))))
        }
    }
}

#[tokio::test]
async fn routes_paths_methods_and_bodies() {
    let h = harness().await;
    // A public route: no credential, no decision, no identity header —
    // and the client's own forwarding and identity headers are gone.
    let said = echoed(
        h.get("/public/page?x=1&y=%20")
            .header("x-forwarded-for", "6.6.6.6")
            .header("forwarded", "for=6.6.6.6")
            .header("x-remote-user", "admin")
            .header("authorization", "Bearer something")
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(said["path"], "/pep-app/public/page");
    assert_eq!(said["query"], "x=1&y=%20");
    let headers = &said["headers"];
    assert_eq!(headers["x-forwarded-for"], "127.0.0.1");
    assert_eq!(headers["x-forwarded-proto"], "http");
    assert_eq!(
        headers["x-forwarded-host"],
        h.proxy.trim_start_matches("http://")
    );
    assert!(headers.get("forwarded").is_none());
    assert!(headers.get("x-remote-user").is_none(), "spoof stripped");
    assert!(
        headers.get("authorization").is_none(),
        "credential stripped"
    );
    let host = &headers["host"];
    assert!(
        h.upstream_base.contains(host.as_str().unwrap()),
        "Host is the upstream's: {}",
        host
    );
    // An unreserved escape is decoded and matched: `%70ublic` is /public.
    let said = echoed(h.get("/%70ublic/a").send().await.unwrap()).await;
    assert_eq!(said["path"], "/pep-app/public/a");
    // Traversal and its spellings: 400, the application never reached.
    // Over a raw socket, because a URL library resolves `..` and `%2e%2e`
    // before it sends anything.
    for bad in [
        "/public/../api",
        "/public/%2e%2e/api",
        "/public/%2E./api",
        "/public/%2fapi",
        "/public//x",
        "/public/a%5cb",
        "/public/%zz",
        "/public/a%00",
        "/public/a%2eb",
    ] {
        assert_eq!(raw_status(&h.proxy, bad).await, 400, "{}", bad);
    }
    // Unrouted, and not at a segment boundary: 404.
    assert_eq!(h.get("/nothing").send().await.unwrap().status(), 404);
    assert_eq!(h.get("/publicity").send().await.unwrap().status(), 404);
    assert_eq!(h.get("/secret/x").send().await.unwrap().status(), 404);
    // A method the route does not take: 405 with Allow.
    let r = h
        .http
        .delete(format!("{}/api/x", h.proxy))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 405);
    assert_eq!(r.headers()["allow"], "GET, POST");
    assert_eq!(
        h.http
            .post(format!("{}/public", h.proxy))
            .send()
            .await
            .unwrap()
            .status(),
        405
    );
    // The body bound: declared over it, streamed over it, and under it.
    let basic = ("alice", Some("right"));
    let r = h
        .http
        .post(format!("{}/api/w", h.proxy))
        .basic_auth(basic.0, basic.1)
        .body(vec![b'x'; 100])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 413, "declared");
    let r = h
        .http
        .post(format!("{}/api/w", h.proxy))
        .basic_auth(basic.0, basic.1)
        .body(reqwest::Body::wrap(Chunks(vec![
            Bytes::from(vec![b'x'; 40]),
            Bytes::from(vec![b'y'; 40]),
        ])))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 413, "streamed");
    let said = echoed(
        h.http
            .post(format!("{}/api/w", h.proxy))
            .basic_auth(basic.0, basic.1)
            .body(vec![b'x'; 10])
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        (said["method"].as_str(), said["bodyLength"].as_u64()),
        (Some("POST"), Some(10))
    );
    // The application's hop-by-hop headers do not reach the client.
    let r = h.get("/public/page").send().await.unwrap();
    assert!(r.headers().get("x-upstream-private").is_none());
    // A redirect the application answers is passed on, not followed.
    let r = h.get("/public/away").send().await.unwrap();
    assert_eq!(r.status(), 302);
    assert_eq!(r.headers()["location"], "http://elsewhere.example/");
    // Too slow: 504, within the bound.
    let started = std::time::Instant::now();
    assert_eq!(h.get("/slow").send().await.unwrap().status(), 504);
    assert!(started.elapsed() < Duration::from_millis(1800));
    // Nobody listening at the upstream: 502.
    let gone = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = gone.local_addr().unwrap().port();
    drop(gone);
    let cert = String::from_utf8(h.saml_signer.1.to_pem().unwrap()).unwrap();
    h.sync.receive_proxy(
        &configuration(
            &format!("http://127.0.0.1:{}/pep-app", dead),
            &h.service_base,
            &cert,
        ),
        None,
    );
    assert_eq!(h.get("/public/page").send().await.unwrap().status(), 502);
    // A configuration refused whole keeps the one held.
    let mut broken = configuration(&h.upstream_base, &h.service_base, &cert);
    broken["proxy"]["routes"][0]["path"] = json!("/a/../b");
    h.sync.receive_proxy(&broken, None);
    assert_eq!(
        h.get("/public/page").send().await.unwrap().status(),
        502,
        "still the dead upstream: the broken document was not loaded"
    );
    // Unconfigured: 404 to everything.
    h.sync
        .receive_proxy(&json!({ "configured": false, "pep": "pep-1" }), None);
    assert_eq!(h.get("/public/page").send().await.unwrap().status(), 404);
    let overview = h.sync.proxy_json();
    assert_eq!(overview["configured"], false);
    assert!(overview["answered"]["byStatus"]["413"].as_u64() >= Some(2));
    assert!(!overview.to_string().contains("pep-app"), "no URL on GET /");
}

#[tokio::test]
async fn oauth2_locally_and_at_the_service() {
    let h = harness().await;
    let good = h.token(h.claims());
    let said = echoed(
        h.get("/api/x")
            .bearer_auth(&good)
            .header("x-remote-user", "admin")
            .header("x-remote-auth", "basic")
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(said["headers"]["x-remote-user"], "alice");
    assert_eq!(said["headers"]["x-remote-auth"], "oauth2");
    assert!(said["headers"].get("authorization").is_none());
    assert_eq!(h.service.lock().unwrap().introspect_calls, 0, "local");

    let refused = |edit: &dyn Fn(&mut Value)| {
        let mut c = h.claims();
        edit(&mut c);
        h.token(c)
    };
    for (token, what) in [
        (refused(&|c| c["aud"] = json!("https://other")), "audience"),
        (refused(&|c| c["iss"] = json!("https://other")), "issuer"),
        (refused(&|c| c["exp"] = json!(1_000)), "expired"),
        (refused(&|c| c["cnf"] = json!({ "jkt": "abc" })), "jkt"),
        (refused(&|c| c["cnf"] = json!({ "x5t#S256": "abc" })), "x5t"),
        (
            sign(&rsa_key(), "RS256", "k1", &h.claims()),
            "bad signature",
        ),
    ] {
        let r = h.get("/api/x").bearer_auth(&token).send().await.unwrap();
        assert_eq!(r.status(), 401, "{}", what);
        let c = challenges(&r);
        assert!(
            c.iter().any(|v| v.starts_with("Bearer ")
                && v.contains("error=\"invalid_token\"")),
            "{}: {:?}",
            what,
            c
        );
        assert!(c.iter().any(|v| v.starts_with("Basic ")), "{:?}", c);
    }
    let r = h
        .get("/api/x")
        .header("authorization", format!("DPoP {}", good))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401, "DPoP");
    assert_eq!(h.service.lock().unwrap().introspect_calls, 0);

    // A ROTATED KEY: unknown kid, the JWKS fetched again, verified here.
    let rotated = rsa_key();
    h.service.lock().unwrap().jwks =
        json!({ "keys": [jwk_of(&h.key, "k1"), jwk_of(&rotated, "k2")] });
    let fetches = h.service.lock().unwrap().jwks_fetches;
    let token = sign(&rotated, "RS256", "k2", &h.claims());
    echoed(h.get("/api/x").bearer_auth(&token).send().await.unwrap()).await;
    assert_eq!(h.service.lock().unwrap().jwks_fetches, fetches + 1);
    assert_eq!(h.service.lock().unwrap().introspect_calls, 0);

    // Opaque, and a kid unknown after the refetch: the service decides.
    let said = echoed(
        h.get("/api/x")
            .bearer_auth("opaque-good")
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(said["headers"]["x-remote-user"], "bob");
    for (token, what) in [
        ("opaque-wrong-aud".to_string(), "audience"),
        ("opaque-jkt".to_string(), "jkt"),
        ("opaque-other-iss".to_string(), "issuer"),
        ("opaque-bad".to_string(), "inactive"),
        (sign(&rsa_key(), "RS256", "k9", &h.claims()), "unknown kid"),
    ] {
        let r = h.get("/api/x").bearer_auth(&token).send().await.unwrap();
        assert_eq!(r.status(), 401, "{}", what);
    }
    assert_eq!(h.service.lock().unwrap().introspect_calls, 6);

    // No credential at all: a challenge per mechanism.
    let r = h.get("/api/x").send().await.unwrap();
    assert_eq!(r.status(), 401);
    let c = challenges(&r);
    assert_eq!(c.len(), 2, "{:?}", c);
    assert!(!c[0].contains("invalid_token"));
    // A scheme the route does not take.
    let r = h
        .get("/api/x")
        .header("authorization", "SAML abc")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
}

#[tokio::test]
async fn basic_and_the_decision() {
    let h = harness().await;
    let said = echoed(
        h.get("/api/x")
            .basic_auth("alice", Some("right"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(said["headers"]["x-remote-user"], "alice");
    assert_eq!(said["headers"]["x-remote-auth"], "basic");
    let r = h
        .get("/api/x")
        .basic_auth("alice", Some("wrong"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert!(challenges(&r).iter().any(|c| c.starts_with("Basic ")));
    let r = h
        .get("/api/x")
        .basic_auth("locked", Some("right"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 429);
    assert_eq!(r.headers()["retry-after"], "30");
    // THE DECISION: the policy refuses mallory, and the route's resource.
    let r = h
        .get("/api/x")
        .basic_auth("mallory", Some("right"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let r = h
        .get("/secret")
        .basic_auth("alice", Some("right"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "the route's resource is what was decided");
    let decided = h.sync.counters_json();
    assert!(decided["refused"].as_u64() >= Some(2));
    // forwardCredentials: the client's Authorization reaches the app.
    let said = echoed(
        h.get("/fwd/x")
            .basic_auth("alice", Some("right"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert!(said["headers"]["authorization"]
        .as_str()
        .unwrap()
        .starts_with("Basic "));
}

#[tokio::test]
async fn saml_locally_with_the_service_behind() {
    let h = harness().await;
    let (key, _) = &h.saml_signer;
    let now = chrono::Utc::now();
    let later = (now + chrono::Duration::minutes(5))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let earlier = (now - chrono::Duration::minutes(1))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let fixed_before = "2026-11-14T09:59:00Z";
    let xml = saml::unsigned(&later, AUD).replace(fixed_before, &earlier);
    let canonical = saml::CANONICAL
        .replace("2026-11-14T10:05:00Z", &later)
        .replace(fixed_before, &earlier);
    let signed = saml::sign(&xml, &canonical, key);
    let header = |xml: &str| {
        format!("SAML {}", openssl::base64::encode_block(xml.as_bytes()))
    };
    let said = echoed(
        h.get("/saml/x")
            .header("authorization", header(&signed))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(said["headers"]["x-remote-user"], "alice & co");
    assert_eq!(h.service.lock().unwrap().saml_calls, 0, "verified here");
    // Signed by somebody else: the service is asked, and decides.
    let (stranger, _) = saml::signer();
    let other = saml::sign(&xml, &canonical, &stranger);
    let r = h
        .get("/saml/x")
        .header("authorization", header(&other))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(h.service.lock().unwrap().saml_calls, 1);
    let vouched = other.replace("alice &amp; co", "service-valid");
    let said = echoed(
        h.get("/saml/x")
            .header("authorization", header(&vouched))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(said["headers"]["x-remote-user"], "sam");
    // A forged digest over the right signature never succeeds locally.
    let tampered = signed.replace("urn:uuid:1234", "urn:uuid:9999");
    let r = h
        .get("/saml/x")
        .header("authorization", header(&tampered))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(h.service.lock().unwrap().saml_calls, 3);
    // Encrypted: refused, and nobody is asked.
    let r = h
        .get("/saml/x")
        .header(
            "authorization",
            header(
                "<saml:EncryptedAssertion xmlns:saml=\"urn:oasis:names:\
                    tc:SAML:2.0:assertion\"/>",
            ),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(h.service.lock().unwrap().saml_calls, 3);
    assert!(challenges(&r).iter().any(|c| c.starts_with("SAML ")));
}

fn query_of(location: &str) -> Vec<(String, String)> {
    reqwest::Url::parse(location)
        .unwrap()
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn member(pairs: &[(String, String)], key: &str) -> String {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

#[tokio::test]
async fn the_session_flow_and_a_sign_out_at_the_service() {
    let h = harness().await;
    // A non-browser with no session: 401.
    assert_eq!(h.get("/app/page").send().await.unwrap().status(), 401);
    // A browser: sent to sign in, PKCE S256, the original URL kept here.
    let r = h
        .get("/app/page?x=1")
        .header("accept", "text/html")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 302);
    let location = r.headers()["location"].to_str().unwrap().to_string();
    assert!(
        location.starts_with("https://sts.example/realm/r1/oauth2/authorize?")
    );
    let q = query_of(&location);
    assert_eq!(member(&q, "response_type"), "code");
    assert_eq!(member(&q, "client_id"), CLIENT);
    assert_eq!(member(&q, "scope"), "openid");
    assert_eq!(member(&q, "code_challenge_method"), "S256");
    assert_eq!(
        member(&q, "redirect_uri"),
        "https://proxy.example/.iya-pep/callback"
    );
    let state = member(&q, "state");
    h.service.lock().unwrap().expect = Some((
        member(&q, "code_challenge"),
        member(&q, "nonce"),
        "sid-1".into(),
    ));
    h.service.lock().unwrap().live.insert("sid-1".into());
    // A callback with an unknown state, or an error: refused.
    let r = h
        .get("/.iya-pep/callback?code=c&state=nope")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    // The callback: the code redeemed, a session, back where it was going.
    let r = h
        .get(&format!("/.iya-pep/callback?code=c&state={}", state))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 302);
    assert_eq!(r.headers()["location"], "/app/page?x=1");
    let cookie = r.headers()["set-cookie"].to_str().unwrap().to_string();
    assert!(cookie.starts_with("iya_pep_session="));
    assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Lax"));
    assert!(!cookie.contains("Secure"), "a plain listener: no Secure");
    let pair = cookie.split(';').next().unwrap().to_string();
    // The state is spent.
    let r = h
        .get(&format!("/.iya-pep/callback?code=c&state={}", state))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    // An access with the cookie: the person, and the cookie stripped.
    let said = echoed(
        h.get("/app/page")
            .header("cookie", format!("{}; other=1", pair))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(said["headers"]["x-remote-user"], "carol");
    assert_eq!(said["headers"]["cookie"], "other=1");
    // A SIGN-OUT AT THE SERVICE: the next recheck ends the proxy session.
    h.service.lock().unwrap().live.clear();
    let r = h
        .get("/app/page")
        .header("cookie", pair.clone())
        .header("accept", "text/html")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 302, "a browser is sent to sign in again");
    assert!(r.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .contains("Max-Age=0"));
    let r = h
        .get("/app/page")
        .header("cookie", pair)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401, "the proxy session is gone");
    assert_eq!(h.sync.proxy_json()["answered"]["sessionsEnded"], 1);

    // A second sign-in whose ID Token carries another nonce: refused.
    let r = h
        .get("/app/b")
        .header("accept", "text/html")
        .send()
        .await
        .unwrap();
    let q = query_of(r.headers()["location"].to_str().unwrap());
    h.service.lock().unwrap().expect = Some((
        member(&q, "code_challenge"),
        member(&q, "nonce"),
        "sid-2".into(),
    ));
    let r = h
        .get(&format!(
            "/.iya-pep/callback?code=bad-nonce&state={}",
            member(&q, "state")
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    // A third, completed, then signed out here: to the service's logout.
    let r = h
        .get("/app/c")
        .header("accept", "text/html")
        .send()
        .await
        .unwrap();
    let q = query_of(r.headers()["location"].to_str().unwrap());
    h.service.lock().unwrap().expect = Some((
        member(&q, "code_challenge"),
        member(&q, "nonce"),
        "sid-3".into(),
    ));
    h.service.lock().unwrap().live.insert("sid-3".into());
    let r = h
        .get(&format!(
            "/.iya-pep/callback?code=c&state={}",
            member(&q, "state")
        ))
        .send()
        .await
        .unwrap();
    let pair = r.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let r = h
        .get("/.iya-pep/logout")
        .header("cookie", pair.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 302);
    let to = r.headers()["location"].to_str().unwrap();
    assert!(to.starts_with("https://sts.example/realm/r1/oauth2/logout?"));
    assert_eq!(member(&query_of(to), "client_id"), CLIENT);
    assert!(!member(&query_of(to), "id_token_hint").is_empty());
    let r = h.get("/app/c").header("cookie", pair).send().await.unwrap();
    assert_eq!(r.status(), 401, "signed out here");
}

/// What the mock PDP saw of each pull: the query and `If-None-Match`.
type Seen = Arc<Mutex<Vec<(Option<String>, Option<String>)>>>;

/// THE PULL (D3): `GET /xacml/pep/proxy` on the poll, under the PDP URL's
/// realm path, `?since=` and `If-None-Match` sent back, a 304 and a
/// failure keeping what is held, and a document that does not validate
/// refused whole.
#[tokio::test]
async fn the_configuration_is_pulled_with_its_token_and_etag() {
    let mut first = configuration("http://app:1/x", "http://sts:2", "");
    first["realm"]["signingCertificates"] = json!([]);
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let answers: Arc<Mutex<Vec<(u16, Value)>>> = Arc::new(Mutex::new(vec![
        (200, first),
        (304, json!({})),
        (500, json!({})),
        (
            200,
            json!({ "configured": true, "proxy": { "upstream": "ftp://x" } }),
        ),
    ]));
    let (kept, queue) = (seen.clone(), answers.clone());
    let handler = move |request: Request| {
        let (kept, queue) = (kept.clone(), queue.clone());
        async move {
            let since = request.uri().query().map(str::to_string);
            let etag = request
                .headers()
                .get("if-none-match")
                .map(|v| v.to_str().unwrap().to_string());
            kept.lock().unwrap().push((since, etag));
            let (status, body) = queue.lock().unwrap().remove(0);
            axum::response::Response::builder()
                .status(status)
                .header("etag", "\"v1\"")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap()
        }
    };
    let router =
        axum::Router::new().route("/realm/r1/xacml/pep/proxy", get(handler));
    let port = serve(router).await;
    let mut options = Options::from_env("0.0.0");
    options.pdp_url = format!("http://127.0.0.1:{}/realm/r1", port);
    let sync = Sync::new(PdpClient::new(&options).unwrap(), options);
    for _ in 0..4 {
        sync.pull("poll").await;
    }
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 4);
    assert_eq!(seen[0], (None, None));
    assert_eq!(seen[1], (Some("since=p1".into()), Some("\"v1\"".into())));
    let overview = sync.proxy_json();
    assert_eq!(
        overview["active"], true,
        "kept through a 304, a 500 and a document refused whole"
    );
    assert_eq!(overview["routes"], 7);
    assert_eq!(overview["lastPullOk"], false);
    assert!(overview["lastPullWhy"]
        .as_str()
        .unwrap()
        .contains("refused whole"));
}
