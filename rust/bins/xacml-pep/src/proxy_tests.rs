// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE REVERSE PROXY OVER REAL SOCKETS (#1760): this container's proxy on
//! a loopback port, in front of a mock application that echoes what
//! reached it, beside a mock service that is everything the proxy talks
//! to — the four validation endpoints, and an OpenID provider and Shared
//! Signals poll transmitter good enough for the `oidc-caep-risc` library
//! (discovery, JWKS, a `client_secret_basic` token endpoint answering the
//! code and client-credentials grants with an ID Token carrying `typ` and
//! `at_hash`, the SSF configuration, a stream and a poll endpoint). Each
//! mechanism admitted and refused, the route table's refusals, the body
//! bound, the upstream's failures, the headers that may not cross, D10's
//! unusable routes, and the session flow from the redirect to a sign-out
//! at the service ending it — by the session endpoint and by a CAEP
//! session-revoked. Every key is made at run time.

use std::collections::HashSet;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Json, Request};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use hyper::body::{Body as HttpBody, Frame};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use serde_json::{json, Value};

use crate::jwt::b64url_encode;
use crate::jwt::testing::{jwk_of, rsa_key, sign};
use crate::listener::HttpsListener;
use crate::options::Options;
use crate::pdp_client::PdpClient;
use crate::pip::RemotePip;
use crate::proxy::{self, Proxy};
use crate::saml_verify::testing as saml;
use crate::service::Pep;
use crate::sync::Sync;

const AUD: &str = "https://app.example/api";
const SAML_ISSUER: &str = "https://sts.example/realm/r1";
/// The application behind `/app` (signals off: the session endpoint).
const CLIENT: &str = "pep-app";
/// The application behind `/live` (signals on: the CAEP/RISC stream).
const LIVE_CLIENT: &str = "pep-live";
const SECRET: &str = "the-application-secret";
const SESSION_REVOKED: &str =
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked";

/// What the mock service has been told and has seen.
#[derive(Default)]
struct ServiceState {
    issuer: String,
    jwks: Value,
    live: HashSet<String>,
    /// (code_challenge, nonce, sid) the next code redemption answers for.
    expect: Option<(String, String, String)>,
    /// SETs waiting on the poll stream.
    queued: Vec<(String, String)>,
    saml_calls: u32,
    introspect_calls: u32,
    jwks_fetches: u32,
    polls: u32,
    /// The poll stream answers 503 (a stream that died after start).
    poll_down: bool,
    /// D11: what the identity endpoint answered, by route.
    identity_calls: Vec<(String, Value)>,
    /// The lifetime of the next jwt-mode token, seconds (0: 300).
    jwt_lifetime: u64,
    /// Where the application's ACS is.
    acs_url: String,
    /// The heartbeats the PEP sent, as their bodies.
    heartbeats: Vec<Value>,
    /// Who the next ID Token names, (sub, username); carol when unset.
    who: Option<(String, String)>,
    /// Sessions signed out at the service whose access tokens the identity
    /// endpoint now refuses (403), before any signal says so.
    ended: HashSet<String>,
}

/// What the application has seen of its SAML sessions.
#[derive(Default)]
struct UpState {
    /// Every request that reached it, whatever it was (#1760: a refused
    /// request must not be one).
    hits: u32,
    /// The application sessions it holds.
    valid: HashSet<String>,
    acs_posts: u32,
}

struct Harness {
    proxy: String,
    proxied: Arc<Proxy>,
    service: Arc<Mutex<ServiceState>>,
    app: Arc<Mutex<UpState>>,
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

async fn serve_on(socket: tokio::net::TcpListener, router: axum::Router) {
    tokio::spawn(async move {
        if let Err(error) = axum::serve(socket, router).await {
            eprintln!("a mock stopped: {}", error);
        }
    });
}

async fn serve(router: axum::Router) -> u16 {
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    serve_on(socket, router).await;
    port
}

/// The application: echoes the method, path, query, headers and body
/// length; `/pep-app/slow` takes two seconds and `/pep-app/public/away`
/// redirects elsewhere. `/pep-app/acs` is its SAML ACS, which sets a
/// session cookie, and `/pep-app/sso/...` answers 401 without one it holds.
async fn upstream(app: Arc<Mutex<UpState>>) -> u16 {
    let echo = move |request: Request| {
        let app = app.clone();
        async move {
            app.lock().unwrap().hits += 1;
            let (parts, body) = request.into_parts();
            let bytes = axum::body::to_bytes(body, 10_000_000).await.unwrap();
            if parts.uri.path() == "/pep-app/acs" {
                let form = String::from_utf8_lossy(&bytes).to_string();
                let mut g = app.lock().unwrap();
                if !form.starts_with("SAMLResponse=") {
                    return axum::response::Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(axum::body::Body::empty())
                        .unwrap();
                }
                g.acs_posts += 1;
                let session = format!("sess-{}", g.acs_posts);
                g.valid.insert(session.clone());
                return axum::response::Response::builder()
                    .status(302)
                    .header("location", "/pep-app/")
                    .header(
                        "set-cookie",
                        format!("app_session={}; Path=/; HttpOnly", session),
                    )
                    .body(axum::body::Body::empty())
                    .unwrap();
            }
            if parts.uri.path().starts_with("/pep-app/sso") {
                let cookie = parts
                    .headers
                    .get("cookie")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let held = app.lock().unwrap().valid.iter().any(|s| {
                    cookie
                        .split("; ")
                        .any(|c| c == format!("app_session={}", s))
                });
                if !held {
                    return axum::response::Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(axum::body::Body::empty())
                        .unwrap();
                }
            }
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
            let mut answer = axum::response::Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .header("connection", "x-upstream-private")
                .header("x-upstream-private", "1");
            if parts.uri.path().starts_with("/pep-app/sso") {
                // A cookie of the jar's name, which must not reach the
                // browser, and one of the application's own, which may.
                answer = answer
                    .header("set-cookie", "app_session=refreshed; Path=/")
                    .header("set-cookie", "theme=dark; Path=/");
            }
            answer
                .body(axum::body::Body::from(said.to_string()))
                .unwrap()
        }
    };
    serve(axum::Router::new().fallback(echo)).await
}

/// A compact JWS with the header given, RS256 under `key`.
fn jws(key: &PKey<Private>, header: &Value, claims: &Value) -> String {
    let input = format!(
        "{}.{}",
        b64url_encode(header.to_string().as_bytes()),
        b64url_encode(claims.to_string().as_bytes())
    );
    let mut signer = Signer::new(MessageDigest::sha256(), key).unwrap();
    let sig = signer.sign_oneshot_to_vec(input.as_bytes()).unwrap();
    format!("{}.{}", input, b64url_encode(&sig))
}

/// An ID Token as the library holds one to (OpenID Connect Core 3.1.3.7):
/// `typ` JWT, the nonce, `iat`, and the access token's `at_hash`.
fn id_token(
    key: &PKey<Private>,
    issuer: &str,
    client: &str,
    nonce: &str,
    sid: &str,
    access_token: &str,
    who: &(String, String),
) -> String {
    let now = chrono::Utc::now().timestamp();
    let digest = openssl::sha::sha256(access_token.as_bytes());
    jws(
        key,
        &json!({ "alg": "RS256", "kid": "k1", "typ": "JWT" }),
        &json!({ "iss": issuer, "aud": client, "sub": who.0,
                 "preferred_username": who.1, "nonce": nonce, "sid": sid,
                 "at_hash": b64url_encode(&digest[..16]),
                 "exp": now + 300, "iat": now }),
    )
}

/// A CAEP session-revoked SET naming the service's session `sid`.
fn session_revoked(key: &PKey<Private>, issuer: &str, sid: &str) -> String {
    jws(
        key,
        &json!({ "alg": "RS256", "kid": "k1", "typ": "secevent+jwt" }),
        &json!({ "iss": issuer, "jti": format!("set-{}", sid),
                 "iat": chrono::Utc::now().timestamp(),
                 "sub_id": { "format": "complex",
                             "session": { "format": "opaque", "id": sid } },
                 "events": { SESSION_REVOKED: {} } }),
    )
}

/// The client authentication the token endpoint takes:
/// `client_secret_basic` for either application.
fn authenticated(headers: &HeaderMap) -> Option<String> {
    let value = headers.get("authorization")?.to_str().ok()?;
    let encoded = value.strip_prefix("Basic ")?;
    let decoded =
        String::from_utf8(openssl::base64::decode_block(encoded).ok()?).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    let id = id.replace("%2D", "-");
    ((id == CLIENT || id == LIVE_CLIENT) && secret == SECRET).then_some(id)
}

async fn service(
    state: Arc<Mutex<ServiceState>>,
    key: Arc<PKey<Private>>,
) -> u16 {
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let base = format!("http://127.0.0.1:{}", port);
    state.lock().unwrap().issuer = base.clone();
    let discovery = {
        let base = base.clone();
        move || {
            let b = base.clone();
            async move {
                Json(json!({
                    "issuer": b,
                    "authorization_endpoint": format!("{}/authorize", b),
                    "token_endpoint": format!("{}/token", b),
                    "jwks_uri": format!("{}/jwks", b),
                    "end_session_endpoint": format!("{}/logout", b),
                    "response_types_supported": ["code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                    "token_endpoint_auth_methods_supported":
                        ["client_secret_basic", "client_secret_post"],
                    "code_challenge_methods_supported": ["S256"],
                    "grant_types_supported":
                        ["authorization_code", "client_credentials"]
                }))
            }
        }
    };
    let ssf_configuration = {
        let base = base.clone();
        move || {
            let b = base.clone();
            async move {
                Json(json!({
                    "issuer": b,
                    "jwks_uri": format!("{}/jwks", b),
                    "configuration_endpoint": format!("{}/ssf/streams", b),
                    "delivery_methods_supported": ["urn:ietf:rfc:8936"]
                }))
            }
        }
    };
    let streams_list = || async { Json(json!([])) };
    let streams_create = {
        let base = base.clone();
        move |headers: HeaderMap| {
            let b = base.clone();
            async move {
                // Every transmitter call carries the client-credentials
                // token the library got with the application's secret.
                if headers.get("authorization").and_then(|v| v.to_str().ok())
                    != Some("Bearer cc-token")
                {
                    return (StatusCode::UNAUTHORIZED, Json(json!({})));
                }
                (
                    StatusCode::CREATED,
                    Json(json!({ "stream_id": "s1",
                        "delivery": { "method": "urn:ietf:rfc:8936",
                                      "endpoint_url": format!("{}/ssf/poll", b) } })),
                )
            }
        }
    };
    let s0 = state.clone();
    let poll = move || {
        let s = s0.clone();
        async move {
            let mut g = s.lock().unwrap();
            g.polls += 1;
            if g.poll_down {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({ "error": "temporarily_unavailable" })),
                );
            }
            let sets: serde_json::Map<String, Value> =
                g.queued.drain(..).map(|(j, t)| (j, json!(t))).collect();
            (
                StatusCode::OK,
                Json(json!({ "sets": sets, "moreAvailable": false })),
            )
        }
    };
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
            let mut g = s.lock().unwrap();
            g.introspect_calls += 1;
            let issuer = g.issuer.clone();
            Json(match body["token"].as_str().unwrap_or("") {
                "opaque-good" => json!({ "active": true, "aud": [AUD],
                    "iss": issuer, "sub": "urn:uuid:7", "username": "bob" }),
                "opaque-wrong-aud" => json!({ "active": true,
                    "aud": "https://other", "iss": issuer, "sub": "x" }),
                "opaque-other-iss" => json!({ "active": true, "aud": AUD,
                    "iss": "https://other.example", "sub": "x" }),
                "opaque-jkt" => json!({ "active": true, "aud": AUD,
                    "iss": issuer, "sub": "x", "cnf": { "jkt": "abc" } }),
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
                             "username": user,
                             "ticket": format!("tk-{}", user) }),
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
    let token = move |headers: HeaderMap, body: String| {
        let s = s5.clone();
        let key = key.clone();
        async move {
            let Some(client) = authenticated(&headers) else {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({ "error": "invalid_client" })),
                );
            };
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
            if get("grant_type") == "client_credentials" {
                return (
                    StatusCode::OK,
                    Json(json!({ "access_token": "cc-token",
                        "token_type": "Bearer", "expires_in": 300 })),
                );
            }
            let (issuer, expect, who) = {
                let g = s.lock().unwrap();
                (g.issuer.clone(), g.expect.clone(),
                 g.who.clone().unwrap_or_else(|| {
                     ("urn:uuid:carol".to_string(), "carol".to_string())
                 }))
            };
            let Some((challenge, nonce, sid)) = expect else {
                return (StatusCode::BAD_REQUEST, Json(json!({})));
            };
            // PKCE: the verifier must be the challenge's.
            if oidc_caep_risc::code_challenge_s256(&get("code_verifier"))
                != challenge
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
            let access = format!("at-{}", sid);
            (
                StatusCode::OK,
                Json(json!({
                    "id_token":
                        id_token(&key, &issuer, &client, &nonce, &sid, &access,
                                 &who),
                    "access_token": access, "token_type": "Bearer",
                    "expires_in": 300 })),
            )
        }
    };
    let s6 = state.clone();
    let identity = move |Json(body): Json<Value>| {
        let s = s6.clone();
        async move {
            let mut g = s.lock().unwrap();
            let route = body["route"].as_str().unwrap_or("").to_string();
            g.identity_calls
                .push((route.clone(), body["evidence"].clone()));
            // The evidence is re-validated here: a ticket names its subject.
            let who = match (
                body["evidence"]["kind"].as_str(),
                body["evidence"]["value"].as_str(),
            ) {
                (Some("ticket"), Some(t)) => {
                    t.trim_start_matches("tk-").to_string()
                }
                (Some("access_token"), Some(t)) if !t.is_empty() => {
                    // A sign-out at the service revokes the session's
                    // access tokens at once (#1449).
                    if g.ended.contains(t.trim_start_matches("at-")) {
                        return (
                            StatusCode::FORBIDDEN,
                            Json(json!({ "error": "access_denied" })),
                        );
                    }
                    "carol".into()
                }
                _ => {
                    return (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        Json(json!({ "code": "STS-XACML-0235" })),
                    )
                }
            };
            if who == "denied" {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({ "code": "STS-XACML-0234" })),
                );
            }
            match route.as_str() {
                "livehdr" => (
                    StatusCode::OK,
                    Json(json!({ "claims": { "groups": ["g1", "g2"] } })),
                ),
                "hdr" => {
                    let email = if who == "evil" {
                        "x\r\nX-Injected: 1".to_string()
                    } else {
                        format!("{}@example.org", who)
                    };
                    (
                        StatusCode::OK,
                        Json(json!({ "claims": { "email": email,
                            "groups": ["g1", "g2"] } })),
                    )
                }
                "tok" | "apptok" => {
                    let n = g.identity_calls.len();
                    let lifetime = if g.jwt_lifetime == 0 {
                        300
                    } else {
                        g.jwt_lifetime
                    };
                    (
                        StatusCode::OK,
                        Json(json!({ "accessToken": format!("svc-at-{}", n),
                            "tokenType": "Bearer", "expiresIn": lifetime })),
                    )
                }
                "sso" => {
                    let until = (chrono::Utc::now()
                        + chrono::Duration::minutes(5))
                    .to_rfc3339();
                    (
                        StatusCode::OK,
                        Json(json!({
                            "samlResponse": openssl::base64::encode_block(
                                format!("<samlp:Response>{}</samlp:Response>", who).as_bytes()),
                            "acsUrl": g.acs_url, "notOnOrAfter": until })),
                    )
                }
                _ => (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({}))),
            }
        }
    };
    let heartbeat = {
        let state = state.clone();
        move |Json(body): Json<Value>| {
            let state = state.clone();
            async move {
                state.lock().unwrap().heartbeats.push(body);
                Json(json!({ "acknowledged": true, "current": true }))
            }
        }
    };
    let router = axum::Router::new()
        .route("/xacml/pep/heartbeat", post(heartbeat))
        .route("/identity", post(identity))
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/ssf-configuration", get(ssf_configuration))
        .route("/ssf/streams", get(streams_list).post(streams_create))
        .route("/ssf/poll", post(poll))
        .route("/jwks", get(jwks))
        .route("/introspect", post(introspect))
        .route("/basic", post(basic))
        .route("/saml", post(saml_check))
        .route("/session", post(session))
        .route("/token", post(token));
    serve_on(socket, router).await;
    port
}

/// Every method a route may name: "any", stated (#1760, where an empty
/// list is none).
const ALL: [&str; 7] = crate::proxy_config::METHODS;

/// The resource-id `/full` is decided as (#1760, `authorization.resource`).
const FULL_URI: &str = "https://pep.example:9543/pep-app/full";

/// A route decided by the policy entry `policy` (#1760).
fn simple_on(policy: &str) -> Value {
    json!({ "kind": "simple", "policy": policy, "resource": "",
            "actionModel": "method", "roles": {} })
}

/// A public route, decided by `policy` for the anonymous subject.
fn public_on(policy: &str) -> Value {
    json!({ "kind": "public", "policy": policy, "resource": "",
            "actionModel": "method" })
}

/// A policy whose one Permit rule matches `value` (`function`, `datatype`)
/// against `attribute` of `category`, and denies everything else — so a
/// test reads exactly which value the engine was given.
fn permitting(
    id: &str,
    category: &str,
    attribute: &str,
    datatype: &str,
    function: &str,
    value: &str,
) -> String {
    format!(
        r#"<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" PolicyId="{id}" Version="1.0" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:first-applicable"><Target/>
<Rule RuleId="only" Effect="Permit"><Target><AnyOf><AllOf><Match MatchId="urn:oasis:names:tc:xacml:1.0:function:{function}"><AttributeValue DataType="{datatype}">{value}</AttributeValue><AttributeDesignator Category="{category}" AttributeId="{attribute}" DataType="{datatype}" MustBePresent="false"/></Match></AllOf></AnyOf></Target></Rule>
<Rule RuleId="else" Effect="Deny"/></Policy>"#
    )
}

const STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
const ANYURI: &str = "http://www.w3.org/2001/XMLSchema#anyURI";
const ACTION: &str = "urn:oasis:names:tc:xacml:3.0:attribute-category:action";
const ACTION_ID: &str = "urn:oasis:names:tc:xacml:1.0:action:action-id";
const RESOURCE: &str =
    "urn:oasis:names:tc:xacml:3.0:attribute-category:resource";
const RESOURCE_ID: &str = "urn:oasis:names:tc:xacml:1.0:resource:resource-id";
const SUBJECT: &str =
    "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject";
const SUBJECT_ID: &str = "urn:oasis:names:tc:xacml:1.0:subject:subject-id";

fn one_effect(id: &str, effect: &str) -> String {
    format!(
        r#"<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" PolicyId="{id}" Version="1.0" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:first-applicable"><Target/><Rule RuleId="all" Effect="{effect}"/></Policy>"#
    )
}

/// What the harness pulls (#1760): `t`, the root, which every older route
/// names; and one entry per new route, by NAME. `root` is the entry
/// marked as the root.
fn policy_rows(root: &str) -> Value {
    let row = |name: &str, document: String| {
        json!({ "policyId": format!("pid-{}", name), "name": name,
                "isRoot": name == root, "document": document })
    };
    let mut rows = vec![
        json!({ "policyId": "proxy-test", "name": "t", "isRoot": root == "t",
                "document": POLICY }),
        row("deny-all", one_effect("pid-deny-all", "Deny")),
        row("permit-all", one_effect("pid-permit-all", "Permit")),
    ];
    for (name, value) in [
        ("permit-update", "update"),
        ("permit-write", "write"),
        ("permit-put", "PUT"),
    ] {
        let id = format!("pid-{}", name);
        let doc = permitting(&id, ACTION, ACTION_ID, STRING, "string-equal",
                             value);
        rows.push(row(name, doc));
    }
    for (name, value) in
        [("permit-uri", FULL_URI), ("permit-path", "/bypath/x")]
    {
        let id = format!("pid-{}", name);
        let doc = permitting(&id, RESOURCE, RESOURCE_ID, ANYURI, "anyURI-equal",
                             value);
        rows.push(row(name, doc));
    }
    // Permits only a request carrying NO subject-id: the regexp `.` matches
    // any value one carries, and that is denied.
    let anon = format!(
        r#"<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" PolicyId="pid-anon-only" Version="1.0" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:first-applicable"><Target/>
<Rule RuleId="someone" Effect="Deny"><Target><AnyOf><AllOf><Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-regexp-match"><AttributeValue DataType="{STRING}">.</AttributeValue><AttributeDesignator Category="{SUBJECT}" AttributeId="{SUBJECT_ID}" DataType="{STRING}" MustBePresent="false"/></Match></AllOf></AnyOf></Target></Rule>
<Rule RuleId="nobody" Effect="Permit"/></Policy>"#
    );
    rows.push(row("anon-only", anon));
    json!({ "syncToken": format!("root-{}", root), "policies": rows })
}

fn resolved_for(audiences: bool, saml: bool, client: &str) -> Value {
    let mut out = json!({ "usable": true });
    if audiences {
        out["audiences"] = json!(["https://other.example/api", AUD]);
    }
    if saml {
        out["samlAudience"] = json!(AUD);
    }
    if !client.is_empty() {
        out["clientId"] = json!(client);
    }
    out
}

fn configuration(upstream: &str, service: &str, cert_pem: &str) -> Value {
    let client = json!({ "clientSecret": SECRET,
        "tokenEndpointAuthMethod": "client_secret_basic",
        "redirectUri": "https://proxy.example/.iya-pep/callback",
        "scopes": ["openid", "profile"] });
    // Two literals: one would pass `json!`'s recursion limit.
    let mut routes = json!([
        { "id": "public", "path": "/public",
          "methods": ["GET", "HEAD"], "authorization": public_on("t"),
          "identity": { "mode": "headers", "headers": [
            { "name": "X-Remote-User", "claim": "username" } ] } },
        { "id": "api", "path": "/api", "methods": ["GET", "POST"],
          "mechanisms": ["oauth2", "basic"], "application": "api-app",
          "authorization": simple_on("t"),
          "resolved": resolved_for(true, false, ""),
          "identity": { "mode": "headers", "headers": [
            { "name": "X-Remote-User", "claim": "username" },
            { "name": "X-Remote-Auth", "claim": "mechanism" } ] } },
        { "id": "saml", "path": "/saml", "mechanisms": ["saml2"],
          "application": "saml-app",
          "authorization": simple_on("t"), "methods": ALL,
          "resolved": resolved_for(false, true, ""),
          "identity": { "mode": "headers", "headers": [
            { "name": "X-Remote-User", "claim": "username" } ] } },
        { "id": "app", "path": "/app", "mechanisms": ["session"],
          "application": CLIENT,
          "authorization": simple_on("t"), "methods": ALL,
          "signals": false,
          "resolved": resolved_for(false, false, CLIENT),
          "identity": { "mode": "headers", "headers": [
            { "name": "X-Remote-User", "claim": "username" } ] } },
        { "id": "live", "path": "/live", "mechanisms": ["session"],
          "application": LIVE_CLIENT,
          "authorization": simple_on("t"), "methods": ALL,
          "resolved": resolved_for(false, false, LIVE_CLIENT),
          "identity": { "mode": "headers", "headers": [
            { "name": "X-Remote-User", "claim": "username" } ] } },
        { "id": "fwd", "path": "/fwd", "mechanisms": ["basic"],
          "application": "fwd-app",
          "authorization": simple_on("t"), "methods": ALL,
          "forwardCredentials": true,
          "resolved": resolved_for(false, false, "") },
        { "id": "secret", "path": "/secret", "match": "exact",
          "mechanisms": ["basic"], "methods": ALL,
          "authorization": { "kind": "simple", "policy": "t",
            "resource": "urn:app:secret", "actionModel": "method" },
          "application": "secret-app",
          "resolved": resolved_for(false, false, "") },
        { "id": "gone", "path": "/gone", "mechanisms": ["basic"],
          "application": "deleted-app",
          "authorization": simple_on("t"), "methods": ALL,
          "resolved": { "usable": false,
                        "why": "the application was deleted",
                        "code": "STS-XACML-0217" } },
        { "id": "slow", "path": "/slow", "match": "exact",
          "methods": ALL, "authorization": public_on("t") },
        { "id": "hdr", "path": "/hdr", "mechanisms": ["basic"],
          "application": "hdr-app",
          "authorization": simple_on("t"), "methods": ALL,
          "resolved": resolved_for(false, false, ""),
          "identity": { "mode": "headers", "separator": ",",
            "headers": [
              { "name": "X-Iya-Email", "claim": "email" },
              { "name": "X-Iya-Groups", "claim": "groups" },
              { "name": "X-Iya-Via", "claim": "mechanism" } ] } },
        { "id": "tok", "path": "/tok", "mechanisms": ["basic"],
          "application": "tok-app",
          "authorization": simple_on("t"), "methods": ALL,
          "resolved": resolved_for(false, false, ""),
          "identity": { "mode": "jwt" } },
        { "id": "apptok", "path": "/apptok",
          "mechanisms": ["session"], "application": CLIENT,
          "authorization": simple_on("t"), "methods": ALL,
          "signals": false,
          "resolved": resolved_for(false, false, CLIENT),
          "identity": { "mode": "jwt" } },
        { "id": "sso", "path": "/sso", "mechanisms": ["basic"],
          "application": "sso-app",
          "authorization": simple_on("t"), "methods": ALL,
          "resolved": resolved_for(false, false, ""),
          "identity": { "mode": "saml" } },
        { "id": "livehdr", "path": "/livehdr",
          "mechanisms": ["session"], "application": LIVE_CLIENT,
          "authorization": simple_on("t"), "methods": ALL,
          "resolved": resolved_for(false, false, LIVE_CLIENT),
          "identity": { "mode": "headers", "headers": [
            { "name": "X-Iya-Groups", "claim": "groups" } ] } },
        { "id": "multi", "path": "/multi", "mechanisms": ["session"],
          "application": LIVE_CLIENT,
          "authorization": simple_on("t"), "methods": ALL,
          "multipleAccounts": true,
          "resolved": resolved_for(false, false, LIVE_CLIENT),
          "identity": { "mode": "headers", "headers": [
            { "name": "X-Remote-User", "claim": "username" } ] } }
    ]);
    // #1760: each route decided by the policy it names.
    let decided = json!([
        { "id": "named", "path": "/named", "mechanisms": ["basic"],
          "application": "named-app", "methods": ALL,
          "resolved": resolved_for(false, false, ""),
          "authorization": simple_on("deny-all") },
        { "id": "crud", "path": "/crud", "mechanisms": ["basic"],
          "application": "crud-app", "methods": ALL,
          "resolved": resolved_for(false, false, ""),
          "authorization": { "kind": "policy",
            "policy": "permit-update", "actionModel": "crud" } },
        { "id": "rw", "path": "/rw", "mechanisms": ["basic"],
          "application": "rw-app", "methods": ALL,
          "resolved": resolved_for(false, false, ""),
          "authorization": { "kind": "policy",
            "policy": "permit-write", "actionModel": "read-write" } },
        { "id": "bymethod", "path": "/bymethod",
          "mechanisms": ["basic"], "application": "m-app",
          "methods": ALL, "resolved": resolved_for(false, false, ""),
          "authorization": { "kind": "policy",
            "policy": "permit-put", "actionModel": "method" } },
        { "id": "full", "path": "/full", "mechanisms": ["basic"],
          "application": "full-app", "methods": ALL,
          "resolved": resolved_for(false, false, ""),
          "authorization": { "kind": "policy", "policy": "permit-uri",
            "resource": FULL_URI, "actionModel": "method" } },
        { "id": "bypath", "path": "/bypath", "mechanisms": ["basic"],
          "application": "path-app", "methods": ALL,
          "resolved": resolved_for(false, false, ""),
          "authorization": { "kind": "policy",
            "policy": "permit-path", "resource": "",
            "actionModel": "method" } },
        { "id": "anon", "path": "/anon", "methods": ["GET"],
          "authorization": public_on("anon-only") },
        { "id": "missing", "path": "/missing",
          "mechanisms": ["basic"], "application": "missing-app",
          "methods": ALL, "resolved": resolved_for(false, false, ""),
          "authorization": simple_on("never-pulled") },
        { "id": "closed", "path": "/closed", "mechanisms": ["basic"],
          "application": "closed-app", "methods": [],
          "resolved": resolved_for(false, false, ""),
          "authorization": simple_on("t") },
        { "id": "closedpub", "path": "/closedpub", "methods": [],
          "authorization": public_on("t") },
        { "id": "closedgone", "path": "/closedgone",
          "mechanisms": ["basic"], "application": "cg-app",
          "methods": [], "resolved": resolved_for(false, false, ""),
          "authorization": simple_on("never-pulled") }
    ]);
    if let (Some(all), Value::Array(more)) = (routes.as_array_mut(), decided)
    {
        all.extend(more);
    }
    json!({
        "syncToken": "p1", "pep": "pep-1", "configured": true,
        "proxy": {
            "enabled": true,
            "upstream": upstream,
            "publicBaseUrl": "https://proxy.example",
            "upstreamTimeoutMs": 500,
            "maxBodyBytes": 64,
            "routes": routes
        },
        "realm": {
            "issuer": service, "jwksUri": format!("{}/jwks", service),
            "samlIssuer": SAML_ISSUER,
            "signingCertificates": [cert_pem],
            "tlsCaChain": "",
            "clients": { CLIENT: client.clone(), LIVE_CLIENT: client }
        },
        "validation": {
            "introspect": format!("{}/introspect", service),
            "basic": format!("{}/basic", service),
            "saml": format!("{}/saml", service),
            "session": format!("{}/session", service),
            "identity": format!("{}/identity", service)
        }
    })
}

async fn harness() -> Harness {
    harness_with(|_| {}).await
}

async fn harness_with(edit: impl FnOnce(&mut Options)) -> Harness {
    harness_of(edit, true, 1, 2).await
}

/// A PEP that has received NO proxy configuration since it started: what a
/// recreated container is until its first pull succeeds.
async fn harness_unconfigured(edit: impl FnOnce(&mut Options)) -> Harness {
    harness_of(edit, false, 1, 2).await
}

async fn harness_of(
    edit: impl FnOnce(&mut Options),
    configured: bool,
    pool_min: usize,
    pool_max: usize,
) -> Harness {
    let key = Arc::new(rsa_key());
    let state = Arc::new(Mutex::new(ServiceState {
        jwks: json!({ "keys": [jwk_of(&key, "k1")] }),
        ..ServiceState::default()
    }));
    let app = Arc::new(Mutex::new(UpState::default()));
    let up = upstream(app.clone()).await;
    let svc = service(state.clone(), key.clone()).await;
    let service_base = format!("http://127.0.0.1:{}", svc);
    let upstream_base = format!("http://127.0.0.1:{}/pep-app", up);
    state.lock().unwrap().acs_url = format!("{}/acs", upstream_base);
    let mut options = Options::from_env("0.0.0");
    options.pdp_url = service_base.clone();
    options.pip_enabled = false;
    options.proxy_session_recheck_ms = 0;
    // The mock provider is plain http on loopback.
    options.proxy_rp_allow_insecure = true;
    options.proxy_signals_poll_ms = 100;
    options.proxy_max_accounts = 2;
    // Short enough for the stale-stream test, long enough that a busy
    // machine never makes a working stream look stale.
    options.proxy_signals_stale_ms = 2000;
    edit(&mut options);
    let client = PdpClient::new(&options).unwrap();
    let sync = Arc::new(Sync::new(client.clone(), options.clone()));
    sync.load_for_test(&policy_rows("t"));
    let saml_signer = saml::signer();
    let cert_pem = String::from_utf8(saml_signer.1.to_pem().unwrap()).unwrap();
    if configured {
        sync.receive_proxy(
            &configuration(&upstream_base, &service_base, &cert_pem),
            Some("\"e1\"".into()),
        );
    }
    let pep = Arc::new(Pep::new(
        options,
        sts_core::version::load(Path::new(".")),
        sync.clone(),
        RemotePip::new(client.clone(), false),
        Arc::new(HttpsListener::new("", "", 0, 1000, None)),
    ));
    let proxy = Arc::new(Proxy::new(pep, client));
    // What the poll does after every pull: the relying parties built.
    proxy.reconcile().await;
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let runtime = crate::listener_pool::ListenerRuntime::new(
        "proxy-http",
        "proxy",
        false,
    );
    runtime.apply(
        &crate::listener_tuning::Tuning::overlay(
            &serde_json::json!({
                "threadPoolMin": pool_min,
                "threadPoolMax": pool_max
            }),
            "proxy",
            false,
        ),
        false,
    );
    tokio::spawn(proxy::serve_on(proxy.clone(), socket, runtime));
    Harness {
        proxy: format!("http://127.0.0.1:{}", port),
        proxied: proxy,
        service: state,
        app,
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
        json!({ "iss": self.service_base, "aud": AUD, "sub": "urn:uuid:alice",
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

/// The proxy pool starts sixteen workers, each with its own
/// current-thread runtime. A client shared by all of them leaves the
/// second proxied request waiting on the first worker's idle connection
/// until `upstreamTimeoutMs` (504, and the application never sees it).
/// Eight workers make a later request land on another one.
#[tokio::test]
async fn a_later_request_on_another_worker_reaches_the_upstream() {
    let h = harness_of(|_| {}, true, 8, 8).await;
    for n in 0..8 {
        let response = h.get("/public/page").send().await.unwrap();
        let status = response.status();
        let said = echoed(response).await;
        assert_eq!(
            said["path"], "/pep-app/public/page",
            "request {n} answered {status} and did not reach the \
             application: {said}"
        );
    }
}

#[tokio::test]
async fn routes_paths_methods_and_bodies() {
    let h = harness().await;
    // A public route: no credential and no identity header (decided for
    // the anonymous subject by its own policy, which permits it) —
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

impl Harness {
    /// A browser sent to sign in on `path`: the library's authorization
    /// URL, and the mock told what the code it redeems answers for.
    async fn send_to_sign_in(
        &self,
        path: &str,
        sid: &str,
    ) -> Vec<(String, String)> {
        let r = self
            .get(path)
            .header("accept", "text/html")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 302, "{}", path);
        let location = r.headers()["location"].to_str().unwrap().to_string();
        assert!(
            location.starts_with(&format!("{}/authorize?", self.service_base)),
            "{}",
            location
        );
        let q = query_of(&location);
        self.service.lock().unwrap().expect = Some((
            member(&q, "code_challenge"),
            member(&q, "nonce"),
            sid.into(),
        ));
        q
    }

    /// The callback with `code`: the cookie pair it set, when it did.
    async fn come_back(&self, code: &str, state: &str) -> reqwest::Response {
        self.get(&format!("/.iya-pep/callback?code={}&state={}", code, state))
            .send()
            .await
            .unwrap()
    }
}

fn cookie_of(r: &reqwest::Response) -> String {
    r.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn the_session_flow_through_the_library_and_a_sign_out_at_the_service() {
    let h = harness().await;
    // A non-browser with no session: 401.
    assert_eq!(h.get("/app/page").send().await.unwrap().status(), 401);
    // A browser: sent to sign in by the LIBRARY's authorize(): the code
    // flow, the application's client, PKCE S256, its scopes.
    let q = h.send_to_sign_in("/app/page?x=1", "sid-1").await;
    assert_eq!(member(&q, "response_type"), "code");
    assert_eq!(member(&q, "client_id"), CLIENT);
    assert_eq!(member(&q, "scope"), "openid profile");
    assert_eq!(member(&q, "code_challenge_method"), "S256");
    assert_eq!(
        member(&q, "redirect_uri"),
        "https://proxy.example/.iya-pep/callback"
    );
    let state = member(&q, "state");
    h.service.lock().unwrap().live.insert("sid-1".into());
    // A callback with an unknown state: refused.
    assert_eq!(h.come_back("c0", "nope").await.status(), 401);
    // The callback: complete_session() — the code redeemed with the
    // application's secret, the ID Token verified — then back.
    let r = h.come_back("c1", &state).await;
    assert_eq!(r.status(), 302);
    assert_eq!(r.headers()["location"], "/app/page?x=1");
    let cookie = r.headers()["set-cookie"].to_str().unwrap().to_string();
    assert!(cookie.starts_with("iya_pep_session="));
    assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Lax"));
    assert!(!cookie.contains("Secure"), "a plain listener: no Secure");
    let pair = cookie_of(&r);
    // The state is spent.
    assert_eq!(h.come_back("c1", &state).await.status(), 401);
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
    // THE IDENTITY PROVIDER'S COOKIES NEVER GO UPSTREAM (2026-11-14): the
    // service's names, inside and on the wire, by the default prefixes a
    // pull that names none stands on; the application's own are kept.
    let said = echoed(
        h.get("/app/page")
            .header("cookie", format!(
                "__Host-sts_session=s; {}; sts_lang=fr; \
                 __Secure-sts_session_bound=b; other=1; ists_x=2", pair))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(said["headers"]["cookie"], "other=1; ists_x=2");
    // The proxy session is the application's: another session route,
    // another application, does not take it.
    let r = h
        .get("/live/x")
        .header("cookie", pair.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    // A SIGN-OUT AT THE SERVICE (signals off): the session endpoint says
    // dead, and the proxy session is ended.
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

    // An ID Token carrying another nonce: the library refuses the sign-in.
    let q = h.send_to_sign_in("/app/b", "sid-2").await;
    let r = h.come_back("bad-nonce", &member(&q, "state")).await;
    assert_eq!(r.status(), 401);
    assert!(r.headers().get("set-cookie").is_none());
    // A third, completed, then signed out here: to the library's
    // end_session_url() and the proxy session gone.
    let q = h.send_to_sign_in("/app/c", "sid-3").await;
    h.service.lock().unwrap().live.insert("sid-3".into());
    let pair = cookie_of(&h.come_back("c3", &member(&q, "state")).await);
    let r = h
        .get("/.iya-pep/logout")
        .header("cookie", pair.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 302);
    let to = r.headers()["location"].to_str().unwrap();
    assert!(
        to.starts_with(&format!("{}/logout?", h.service_base)),
        "{}",
        to
    );
    assert_eq!(member(&query_of(to), "client_id"), CLIENT);
    assert!(!member(&query_of(to), "id_token_hint").is_empty());
    let r = h.get("/app/c").header("cookie", pair).send().await.unwrap();
    assert_eq!(r.status(), 401, "signed out here");
    let overview = h.sync.proxy_json();
    assert_eq!(overview["relyingParties"], 2);
    assert!(
        !overview.to_string().contains(SECRET),
        "GET / never shows a secret"
    );
}

/// SIGNALS ON: the library's receiver on the service's poll stream ends a
/// proxy session a CAEP session-revoked names, and the next access sees
/// it gone from the library's cache.
#[tokio::test]
async fn a_caep_session_revoked_ends_access() {
    let h = harness().await;
    assert_eq!(
        h.sync.proxy_json()["signalsReceivers"],
        1,
        "the /live application's receiver started"
    );
    let q = h.send_to_sign_in("/live/page", "sid-live").await;
    // The session endpoint says DEAD throughout: with signals on it is
    // not what decides.
    let pair = cookie_of(&h.come_back("live-1", &member(&q, "state")).await);
    let said = echoed(
        h.get("/live/page")
            .header("cookie", pair.clone())
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(said["headers"]["x-remote-user"], "carol");
    let (key, issuer) = (h.key.clone(), h.service_base.clone());
    h.service.lock().unwrap().queued.push((
        "set-sid-live".into(),
        session_revoked(&key, &issuer, "sid-live"),
    ));
    let mut status = 200;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        status = h
            .get("/live/page")
            .header("cookie", pair.clone())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16();
        if status != 200 {
            break;
        }
    }
    assert_eq!(status, 401, "the signal ended the proxy session");
    // AND A BROWSER STILL HOLDING THE COOKIE IS SENT TO SIGN IN WITH IT
    // CLEARED (2026-11-14): the signal removed the session before this
    // request, which therefore found none to end.
    let r = h
        .get("/live/page")
        .header("cookie", pair.clone())
        .header("accept", "text/html")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 302);
    assert!(
        r.headers()
            .get("set-cookie")
            .map(|v| v.to_str().unwrap().contains("Max-Age=0"))
            .unwrap_or(false),
        "the dead iya_pep_session is cleared"
    );
    assert!(h.service.lock().unwrap().polls > 0);
    assert!(
        h.sync.proxy_json()["answered"]["sessionsEnded"].as_u64() >= Some(1)
    );
}

/// SIGNALS ON, THE STREAM DIES AFTER START: with no successful poll within
/// `PEP_PROXY_SIGNALS_STALE_MS` the receiver's health says so, its signals
/// stop deciding, and the service's session endpoint is asked — which
/// here says the session is dead, so access ends although no signal could
/// arrive. `GET /` reports the stream stale, then healthy again.
#[tokio::test]
async fn a_stream_that_stops_answering_falls_back_to_the_session_endpoint() {
    let h = harness().await;
    let q = h.send_to_sign_in("/live/page", "sid-stale").await;
    let pair = cookie_of(&h.come_back("stale-1", &member(&q, "state")).await);
    let r = h
        .get("/live/page")
        .header("cookie", pair.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "healthy: the library's cache decides");
    let signals = h.sync.proxy_json()["signals"].clone();
    assert_eq!(signals["receivers"], 1, "{}", signals);
    assert_eq!(signals["healthy"], 1, "{}", signals);
    assert_eq!(signals["staleAfterMs"], 2000);
    assert_eq!(signals["librarySessions"]["max"], 20000, "twice the bound");
    assert!(signals["librarySessions"]["held"].as_u64() >= Some(1));
    h.service.lock().unwrap().poll_down = true;
    let mut status = 200;
    for _ in 0..200 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        status = h
            .get("/live/page")
            .header("cookie", pair.clone())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16();
        if status != 200 {
            break;
        }
    }
    assert_eq!(status, 401, "the session endpoint said dead");
    let signals = h.sync.proxy_json()["signals"].clone();
    assert_eq!(signals["stale"], 1, "{}", signals);
    assert!(signals["mostConsecutiveFailures"].as_u64() >= Some(1));
    assert!(
        !signals.to_string().contains("127.0.0.1"),
        "no URL or error text on GET /"
    );
    // THE HEARTBEAT CARRIES THE SAME NUMBERS (#1760), so the service can
    // draw a stale stream on the PEP's row.
    assert!(h.sync.heartbeat().await.ok, "the heartbeat was delivered");
    let sent = h
        .service
        .lock()
        .unwrap()
        .heartbeats
        .last()
        .cloned()
        .unwrap();
    assert_eq!(sent["signals"]["receivers"], 1, "{}", sent);
    assert_eq!(sent["signals"]["stale"], 1, "{}", sent);
    assert_eq!(sent["signals"]["staleAfterMs"], 2000, "{}", sent);
    assert!(sent["signals"]["mostConsecutiveFailures"].as_u64() >= Some(1));
    assert!(
        !sent["signals"].to_string().contains("127.0.0.1"),
        "no URL or error text on the heartbeat either"
    );
    h.service.lock().unwrap().poll_down = false;
    let mut healthy = 0;
    for _ in 0..200 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        healthy = h.sync.proxy_json()["signals"]["healthy"]
            .as_u64()
            .unwrap_or(0);
        if healthy == 1 {
            break;
        }
    }
    assert_eq!(healthy, 1, "the stream answers again");
}

/// A PEP WITH NO PROXY sends no `signals` member on its heartbeat (#1760):
/// the service then keeps the row's "not reported", which is a different
/// fact from a proxy holding no streams.
#[tokio::test]
async fn a_pep_without_a_proxy_reports_no_signals() {
    let h = harness().await;
    let mut options = Options::from_env("0.0.0");
    options.pdp_url = h.service_base.clone();
    options.pip_enabled = false;
    let bare = Sync::new(PdpClient::new(&options).unwrap(), options);
    assert!(bare.heartbeat().await.ok, "the heartbeat was delivered");
    let sent = h
        .service
        .lock()
        .unwrap()
        .heartbeats
        .last()
        .cloned()
        .unwrap();
    assert!(sent.get("signals").is_none(), "{}", sent);
    assert!(sent.get("version").is_some(), "the fixed fields still go");
}

/// SIGNALS ON: each access asks the LIBRARY whether the session is still
/// there. A session the library has dropped by itself — its refresh
/// refused, say — ends access even with the proxy's own store holding it.
#[tokio::test]
async fn each_access_asks_the_library_for_the_session() {
    let h = harness().await;
    let q = h.send_to_sign_in("/live/page", "sid-asked").await;
    let r = h.come_back("asked-1", &member(&q, "state")).await;
    let pair = cookie_of(&r);
    let id = pair.trim_start_matches("iya_pep_session=").to_string();
    echoed(
        h.get("/live/page")
            .header("cookie", pair.clone())
            .send()
            .await
            .unwrap(),
    )
    .await;
    h.proxied.library_forgets(LIVE_CLIENT, &id);
    let r = h
        .get("/live/page")
        .header("cookie", pair)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401, "the library no longer holds it");
}

/// D10: a route whose application the service no longer resolves is
/// refused, with no credential asked for and the reason only in the log;
/// usable again on a later pull, it works again.
#[tokio::test]
async fn an_unusable_route_is_refused_until_it_is_usable_again() {
    let h = harness().await;
    let r = h
        .get("/gone/x")
        .basic_auth("alice", Some("right"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let body = r.text().await.unwrap();
    assert!(
        !body.contains("deleted"),
        "the why stays in the log: {}",
        body
    );
    let cert = String::from_utf8(h.saml_signer.1.to_pem().unwrap()).unwrap();
    let mut back = configuration(&h.upstream_base, &h.service_base, &cert);
    back["proxy"]["routes"][7]["resolved"] = json!({ "usable": true });
    h.sync.receive_proxy(&back, None);
    let said = echoed(
        h.get("/gone/x")
            .basic_auth("alice", Some("right"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(said["path"], "/pep-app/gone/x");
    assert_eq!(h.sync.proxy_json()["unusableRoutes"], 0);
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
    assert_eq!(overview["routes"], 26);
    assert_eq!(overview["lastPullOk"], false);
    assert!(overview["lastPullWhy"]
        .as_str()
        .unwrap()
        .contains("refused whole"));
}

/// D11, mode `headers`: claims the credential does not hold are asked of
/// the service with the Basic answer's ticket; a client's own copy of an
/// identity header — any case, any number of times — never survives; a
/// dangerous value is refused, never forwarded; the service's 403 is a 403.
#[tokio::test]
async fn identity_headers_from_the_service() {
    let h = harness().await;
    let said = echoed(
        h.get("/hdr/x")
            .basic_auth("alice", Some("right"))
            .header("X-IYA-EMAIL", "forged@evil")
            .header("x-iya-email", "again@evil")
            .header("x-remote-user", "admin")
            .send()
            .await
            .unwrap(),
    )
    .await;
    let headers = &said["headers"];
    assert_eq!(headers["x-iya-email"], "alice@example.org");
    assert_eq!(headers["x-iya-groups"], "g1,g2");
    assert_eq!(headers["x-iya-via"], "basic");
    assert!(
        headers.get("x-remote-user").is_none(),
        "another route's identity header is stripped here too"
    );
    {
        let g = h.service.lock().unwrap();
        let (route, evidence) = g.identity_calls.last().unwrap();
        assert_eq!(route, "hdr");
        assert_eq!(evidence["kind"], "ticket");
        assert_eq!(evidence["value"], "tk-alice", "never the password");
    }
    let r = h
        .get("/hdr/x")
        .basic_auth("evil", Some("right"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 502, "a CR LF value is refused, not forwarded");
    let r = h
        .get("/hdr/x")
        .basic_auth("denied", Some("right"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    // Claims the credential holds are not asked for (a public route's
    // headers are stripped and nothing is sent).
    let before = h.service.lock().unwrap().identity_calls.len();
    let said = echoed(
        h.get("/api/x")
            .basic_auth("alice", Some("right"))
            .header("X-Remote-Auth", "forged")
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(said["headers"]["x-remote-user"], "alice");
    assert_eq!(said["headers"]["x-remote-auth"], "basic");
    assert_eq!(h.service.lock().unwrap().identity_calls.len(), before);
}

/// D11, mode `jwt`: the service's token for the route's application as
/// `Authorization: Bearer`, the client's own Authorization gone; cached
/// until thirty seconds before it expires.
#[tokio::test]
async fn identity_as_a_service_token() {
    let h = harness().await;
    let first = echoed(
        h.get("/tok/x")
            .basic_auth("alice", Some("right"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(first["headers"]["authorization"], "Bearer svc-at-1");
    let again = echoed(
        h.get("/tok/x")
            .basic_auth("alice", Some("right"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        again["headers"]["authorization"], "Bearer svc-at-1",
        "cached"
    );
    assert_eq!(h.service.lock().unwrap().identity_calls.len(), 1);
    // Another subject: its own token.
    let other = echoed(
        h.get("/tok/x")
            .basic_auth("bob", Some("right"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(other["headers"]["authorization"], "Bearer svc-at-2");
    // A token within thirty seconds of its end is never used.
    h.service.lock().unwrap().jwt_lifetime = 20;
    let short = |n: usize| format!("Bearer svc-at-{}", n);
    let a = echoed(
        h.get("/tok/x")
            .basic_auth("carol", Some("right"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(a["headers"]["authorization"], short(3));
    let b = echoed(
        h.get("/tok/x")
            .basic_auth("carol", Some("right"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(b["headers"]["authorization"], short(4), "not reused");
}

/// D11, mode `saml`: the service's assertion POSTed to the application's
/// ACS server-side, its cookie kept in the proxy's jar and sent with the
/// request, never to the browser; a 401 from the application establishes
/// the session again.
#[tokio::test]
async fn identity_as_an_application_session() {
    let h = harness().await;
    let r = h
        .get("/sso/page")
        .basic_auth("alice", Some("right"))
        .header("cookie", "app_session=forged; mine=1")
        .send()
        .await
        .unwrap();
    let set: Vec<String> = r
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    assert!(
        set.iter().all(|c| !c.starts_with("app_session=")),
        "the jar never reaches the browser: {:?}",
        set
    );
    assert!(set.iter().any(|c| c.starts_with("theme=")), "{:?}", set);
    let said = echoed(r).await;
    assert_eq!(said["headers"]["cookie"], "mine=1; app_session=sess-1");
    assert_eq!(h.app.lock().unwrap().acs_posts, 1);
    // The jar is used again, updated with what the application refreshed.
    h.app.lock().unwrap().valid.insert("refreshed".into());
    let said = echoed(
        h.get("/sso/page")
            .basic_auth("alice", Some("right"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(said["headers"]["cookie"], "app_session=refreshed");
    assert_eq!(h.app.lock().unwrap().acs_posts, 1);
    // The application ends its session: a 401, established again once.
    h.app.lock().unwrap().valid.clear();
    let said = echoed(
        h.get("/sso/page")
            .basic_auth("alice", Some("right"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(said["headers"]["cookie"], "app_session=sess-2");
    assert_eq!(h.app.lock().unwrap().acs_posts, 2);
    // Refused by the service: refused here, the application not reached.
    let r = h
        .get("/sso/page")
        .basic_auth("denied", Some("right"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    assert_eq!(h.app.lock().unwrap().acs_posts, 2);
}

/// D11 on a session route: the evidence is the access token the library
/// holds for the proxy session (`session_access_token`).
#[tokio::test]
async fn a_session_route_proves_its_subject_with_the_librarys_token() {
    let h = harness().await;
    let q = h.send_to_sign_in("/apptok/x", "sid-tok").await;
    h.service.lock().unwrap().live.insert("sid-tok".into());
    let pair = cookie_of(&h.come_back("tok-1", &member(&q, "state")).await);
    let said = echoed(
        h.get("/apptok/x")
            .header("cookie", pair)
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert!(said["headers"]["authorization"]
        .as_str()
        .unwrap()
        .starts_with("Bearer svc-at-"));
    let g = h.service.lock().unwrap();
    let (route, evidence) = g.identity_calls.last().unwrap();
    assert_eq!(route, "apptok");
    assert_eq!(evidence["kind"], "access_token");
    assert_eq!(evidence["value"], "at-sid-tok", "the library's token");
}

impl Harness {
    /// A browser holding `cookie` asks `path`: where the proxy sends it.
    async fn location_of(&self, path: &str, cookie: &str) -> (u16, String) {
        let r = self
            .get(path)
            .header("accept", "text/html")
            .header("cookie", cookie)
            .send()
            .await
            .unwrap();
        let to = r
            .headers()
            .get("location")
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default();
        (r.status().as_u16(), to)
    }

    /// Signs `who` in through the authorization URL `location`, the
    /// service answering for `sid`; the callback's answer.
    async fn sign_in_as(
        &self,
        location: &str,
        who: (&str, &str),
        sid: &str,
        code: &str,
    ) -> reqwest::Response {
        let q = query_of(location);
        {
            let mut g = self.service.lock().unwrap();
            g.expect = Some((
                member(&q, "code_challenge"),
                member(&q, "nonce"),
                sid.into(),
            ));
            g.who = Some((who.0.into(), who.1.into()));
        }
        self.come_back(code, &member(&q, "state")).await
    }

    /// The browser's accounts as `GET /.iya-pep/accounts?format=json`.
    async fn accounts_of(&self, cookie: &str) -> Value {
        self.get("/.iya-pep/accounts?format=json")
            .header("cookie", cookie)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    /// An account act's form, from this proxy's own page.
    async fn account_act(
        &self,
        path: &str,
        form: &str,
        cookie: &str,
        origin: &str,
    ) -> reqwest::Response {
        self.http
            .post(format!("{}{}", self.proxy, path))
            .header("cookie", cookie)
            .header("origin", origin)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form.to_string())
            .send()
            .await
            .unwrap()
    }

    /// Who the application was told is asking, on `/multi/page`.
    async fn forwarded_as(&self, cookie: &str) -> Value {
        echoed(
            self.get("/multi/page")
                .header("cookie", format!("{}; other=1", cookie))
                .send()
                .await
                .unwrap(),
        )
        .await
    }
}

fn account_named(list: &Value, username: &str) -> Value {
    list["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["username"] == username)
        .cloned()
        .unwrap_or(Value::Null)
}

/// SEVERAL ACCOUNTS IN ONE BROWSER (#1760): a second account added with
/// prompt=login, the ACTIVE one the only identity forwarded, switching,
/// a CAEP session-revoked ending ONLY its account (and no other made active
/// in its place), signing one out, and the account-set cookie never
/// reaching the application.
#[tokio::test]
async fn several_accounts_in_one_browser() {
    let h = harness().await;
    let origin = h.proxy.clone();
    // The first sign-in: no set yet, an ordinary authorization request.
    let (status, to) = h.location_of("/multi/page", "").await;
    assert_eq!(status, 302);
    assert_eq!(member(&query_of(&to), "prompt"), "");
    let r = h.sign_in_as(&to, ("urn:uuid:alice", "alice"), "sid-a", "m1")
        .await;
    assert_eq!(r.status(), 302);
    assert_eq!(r.headers()["location"], "/multi/page");
    let set_cookie = r.headers()["set-cookie"].to_str().unwrap().to_string();
    assert!(set_cookie.starts_with("iya_pep_accounts="), "{}", set_cookie);
    assert!(set_cookie.contains("HttpOnly") && set_cookie.contains("SameSite=Lax"));
    let set = cookie_of(&r);
    let said = h.forwarded_as(&set).await;
    assert_eq!(said["headers"]["x-remote-user"], "alice");
    assert_eq!(said["headers"]["cookie"], "other=1",
               "the account set never reaches the application");
    // ADD ANOTHER: prompt=login, the browser back where it was.
    let (status, to) = h
        .location_of("/.iya-pep/accounts/add?return=%2Fmulti%2Fpage", &set)
        .await;
    assert_eq!(status, 302);
    assert_eq!(member(&query_of(&to), "prompt"), "login");
    let r = h.sign_in_as(&to, ("urn:uuid:bob", "bob"), "sid-b", "m2").await;
    assert_eq!(r.status(), 302);
    assert_eq!(cookie_of(&r), set, "one set for the browser");
    // The account added last is the active one: only bob is forwarded.
    let said = h.forwarded_as(&set).await;
    assert_eq!(said["headers"]["x-remote-user"], "bob");
    let list = h.accounts_of(&set).await;
    assert_eq!(list["accounts"].as_array().unwrap().len(), 2);
    assert_eq!(account_named(&list, "bob")["active"], true);
    assert_eq!(account_named(&list, "alice")["active"], false);
    assert_eq!(list["accounts"][0]["application"], LIVE_CLIENT);
    let alice = account_named(&list, "alice")["account"]
        .as_str().unwrap().to_string();
    let bob = account_named(&list, "bob")["account"]
        .as_str().unwrap().to_string();
    // The chooser is the proxy's own page under a strict policy.
    let page = h.get("/.iya-pep/accounts?return=%2Fmulti%2Fpage")
        .header("cookie", set.clone()).send().await.unwrap();
    assert_eq!(page.status(), 200);
    let csp = page.headers()["content-security-policy"].to_str().unwrap()
        .to_string();
    assert!(csp.contains("default-src 'none'") && csp.contains("frame-ancestors 'none'"));
    assert!(csp.contains("style-src 'sha256-"), "{}", csp);
    assert!(!csp.contains("unsafe") && !csp.contains("script-src"), "{}", csp);
    let html = page.text().await.unwrap();
    assert!(html.contains("alice") && html.contains("bob")
            && html.contains("Add another account")
            && html.contains("Sign out of all accounts"));
    assert!(html.contains("<style>") && html.contains("max-width:46rem"),
            "the chooser uses the error page's style sheet: {}", html);
    assert!(html.contains("class=\"portal\"")
            && html.contains("ul class=\"accounts\""), "{}", html);
    assert!(html.contains("sts-footer"), "{}", html);
    assert!(!html.contains("<script"), "no script on the chooser");
    assert!(!html.contains("<section class=\"diagnostics\""),
            "the chooser is not an error page");
    // The active account (bob) can continue; alice can only switch.
    assert_eq!(html.matches("Continue with this user").count(), 1,
               "{}", html);
    assert!(html.contains(
        "action=\"/multi/page\"><button class=\"portal\" \
         type=\"submit\">Continue with this user</button>"
    ), "{}", html);
    assert!(html.contains("Switch to this account"), "{}", html);
    // SWITCH: alice is forwarded again, and only she.
    let r = h.account_act("/.iya-pep/accounts/switch",
        &format!("account={}&return=%2Fmulti%2Fpage", alice), &set, &origin)
        .await;
    assert_eq!(r.status(), 303);
    assert_eq!(r.headers()["location"], "/multi/page");
    assert_eq!(h.forwarded_as(&set).await["headers"]["x-remote-user"],
               "alice");
    // A switch from another site is refused, and changes nothing.
    let r = h.account_act("/.iya-pep/accounts/switch",
        &format!("account={}", bob), &set, "https://evil.example").await;
    assert_eq!(r.status(), 403);
    assert_eq!(h.forwarded_as(&set).await["headers"]["x-remote-user"],
               "alice");
    // An account the set does not hold is refused.
    let r = h.account_act("/.iya-pep/accounts/switch", "account=nobody",
                          &set, &origin).await;
    assert_eq!(r.status(), 404);
    // CAEP SESSION-REVOKED FOR ALICE'S SESSION ends HER account only.
    let (key, issuer) = (h.key.clone(), h.service_base.clone());
    h.service.lock().unwrap().queued.push((
        "set-sid-a".into(),
        session_revoked(&key, &issuer, "sid-a"),
    ));
    let mut status = 200;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        status = h.get("/multi/page").header("cookie", set.clone())
            .send().await.unwrap().status().as_u16();
        if status != 200 {
            break;
        }
    }
    assert_eq!(status, 401, "alice's account ended; nobody else stands in");
    let list = h.accounts_of(&set).await;
    assert_eq!(list["accounts"].as_array().unwrap().len(), 1);
    assert_eq!(list["accounts"][0]["username"], "bob");
    assert_eq!(list["accounts"][0]["active"], false,
               "no account is made active for the person");
    // A browser is sent to the chooser to pick, not signed in as bob.
    let (status, to) = h.location_of("/multi/page", &set).await;
    assert_eq!(status, 302);
    assert!(to.starts_with("/.iya-pep/accounts?return="), "{}", to);
    let r = h.account_act("/.iya-pep/accounts/switch",
        &format!("account={}", bob), &set, &origin).await;
    assert_eq!(r.status(), 303);
    assert_eq!(h.forwarded_as(&set).await["headers"]["x-remote-user"], "bob");
    // SIGN OUT ONE, then the set is empty and the next sign-in starts afresh.
    let r = h.account_act("/.iya-pep/accounts/logout",
        &format!("account={}&return=%2Fmulti%2Fpage", bob), &set, &origin)
        .await;
    assert_eq!(r.status(), 303);
    assert!(h.accounts_of(&set).await["accounts"].as_array().unwrap()
              .is_empty());
    assert_eq!(h.get("/multi/page").header("cookie", set.clone())
                 .send().await.unwrap().status(), 401);
}

/// THE BOUND (`proxyMaxAccounts`, 2 in the harness): a third account is
/// refused rather than evicting one; the same person signing in again
/// replaces their own account; and Sign out of all ends every account.
#[tokio::test]
async fn the_account_set_is_bounded() {
    let h = harness().await;
    let origin = h.proxy.clone();
    let (_, to) = h.location_of("/multi/page", "").await;
    let set = cookie_of(&h.sign_in_as(&to, ("urn:uuid:alice", "alice"),
                                      "sid-1", "b1").await);
    let add = "/.iya-pep/accounts/add?return=%2Fmulti%2Fpage";
    let (_, to) = h.location_of(add, &set).await;
    h.sign_in_as(&to, ("urn:uuid:bob", "bob"), "sid-2", "b2").await;
    let (_, to) = h.location_of(add, &set).await;
    let r = h.sign_in_as(&to, ("urn:uuid:carol", "carol"), "sid-3", "b3")
        .await;
    assert_eq!(r.status(), 403, "a full set refuses the third");
    let list = h.accounts_of(&set).await;
    assert_eq!(list["accounts"].as_array().unwrap().len(), 2);
    assert_eq!(list["max"], 2);
    // Alice again (her account named): prompt=login with her login_hint,
    // and her account kept, its session replaced.
    let alice = account_named(&list, "alice")["account"]
        .as_str().unwrap().to_string();
    let (_, to) = h
        .location_of(&format!("{}&account={}", add, alice), &set)
        .await;
    assert_eq!(member(&query_of(&to), "login_hint"), "alice");
    let r = h.sign_in_as(&to, ("urn:uuid:alice", "alice"), "sid-4", "b4")
        .await;
    assert_eq!(r.status(), 302);
    let list = h.accounts_of(&set).await;
    assert_eq!(list["accounts"].as_array().unwrap().len(), 2);
    assert_eq!(account_named(&list, "alice")["account"], alice.as_str());
    assert_eq!(account_named(&list, "alice")["active"], true);
    // The ID Token must name the account asked for again.
    let (_, to) = h
        .location_of(&format!("{}&account={}", add, alice), &set)
        .await;
    let r = h.sign_in_as(&to, ("urn:uuid:mallory", "mallory"), "sid-5", "b5")
        .await;
    assert_eq!(r.status(), 401, "another person than the one asked for");
    // SIGN OUT OF ALL.
    let r = h.account_act("/.iya-pep/accounts/logout-all",
                          "return=%2Fmulti%2Fpage", &set, &origin).await;
    assert_eq!(r.status(), 303);
    assert!(r.headers()["set-cookie"].to_str().unwrap().contains("Max-Age=0"));
    assert!(h.accounts_of(&set).await["accounts"].as_array().unwrap()
              .is_empty());
}

/// THE WINDOW BEFORE THE SIGNAL (2026-11-14): a sign-out at the service
/// revokes the session's access token at once, and the identity endpoint
/// refuses it before the CAEP event arrives. A browser is then sent to sign
/// in with its cookie cleared — not shown a 403 — and anything else gets a
/// 401; a refusal while the session is still live stays a 403.
#[tokio::test]
async fn a_refused_identity_of_an_ended_session_sends_the_browser_to_sign_in() {
    let h = harness().await;
    let q = h.send_to_sign_in("/livehdr/x", "sid-win").await;
    h.service.lock().unwrap().live.insert("sid-win".into());
    let pair = cookie_of(&h.come_back("win-1", &member(&q, "state")).await);
    let said = echoed(
        h.get("/livehdr/x")
            .header("cookie", pair.clone())
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(said["headers"]["x-iya-groups"], "g1,g2");
    // Refused while the session is live: the service's 403 stands.
    h.service.lock().unwrap().ended.insert("sid-win".into());
    let r = h
        .get("/livehdr/x")
        .header("cookie", pair.clone())
        .header("accept", "text/html")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "a live session's refusal is a refusal");
    // Signed out at the service: the session endpoint says dead too.
    h.service.lock().unwrap().live.remove("sid-win");
    let r = h
        .get("/livehdr/x")
        .header("cookie", pair.clone())
        .header("accept", "text/html")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 302, "a browser is sent to sign in");
    assert!(r.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .contains("Max-Age=0"));
    let r = h
        .get("/livehdr/x")
        .header("cookie", pair)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401, "the proxy session is gone");
    // A non-browser in the same window: 401, not 403.
    let q = h.send_to_sign_in("/livehdr/y", "sid-win2").await;
    h.service.lock().unwrap().live.insert("sid-win2".into());
    let pair = cookie_of(&h.come_back("win-2", &member(&q, "state")).await);
    {
        let mut g = h.service.lock().unwrap();
        g.ended.insert("sid-win2".into());
        g.live.remove("sid-win2");
    }
    let r = h
        .get("/livehdr/y")
        .header("cookie", pair)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
}

/// AN ACCOUNT IS LABELLED BY ITS USERNAME (2026-11-14): the service's ID
/// Token carries no `preferred_username`, so the chooser labelled the
/// account by its `urn:uuid` subject; the sign-in now asks the service's
/// session endpoint, which names the person.
#[tokio::test]
async fn an_account_without_a_username_claim_is_named_by_the_service() {
    let h = harness().await;
    let (status, to) = h.location_of("/multi/page", "").await;
    assert_eq!(status, 302);
    h.service.lock().unwrap().live.insert("sid-u".into());
    let r = h.sign_in_as(&to, ("urn:uuid:carol", ""), "sid-u", "mu").await;
    assert_eq!(r.status(), 302);
    let set = cookie_of(&r);
    let list = h.accounts_of(&set).await;
    assert_eq!(list["accounts"][0]["username"], "carol", "{}", list);
    let page = h
        .get("/.iya-pep/accounts?return=%2Fmulti%2Fpage")
        .header("cookie", set)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("<strong>carol</strong>"), "{}", page);
    assert!(!page.contains("urn:uuid:carol"), "{}", page);
}

/// `return` is followed only when its path matches a configured route.
/// The active account's *Continue with this user* goes there. A value
/// that matches no route, or that is not a path on this proxy, is `/`
/// for the chooser, a switch, and both sign-outs.
#[tokio::test]
async fn a_return_is_followed_only_when_a_route_matches() {
    let h = harness().await;
    let origin = h.proxy.clone();
    let (_, to) = h.location_of("/multi/page", "").await;
    let set = cookie_of(
        &h.sign_in_as(&to, ("urn:uuid:alice", "alice"), "sid-r", "mr")
            .await,
    );
    let alice = account_named(&h.accounts_of(&set).await, "alice")["account"]
        .as_str()
        .unwrap()
        .to_string();
    let html = h
        .get("/.iya-pep/accounts?return=%2Fmulti%2Fpage")
        .header("cookie", set.clone())
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains(
        "action=\"/multi/page\"><button class=\"portal\" \
         type=\"submit\">Continue with this user</button>"
    ), "{}", html);
    assert!(!html.contains("Switch to this account"), "{}", html);
    let html = h
        .get("/.iya-pep/accounts?return=%2Fpublic%2Fx%3Fa%3Db%2520c")
        .header("cookie", set.clone())
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("action=\"/public/x\""), "{}", html);
    assert!(html.contains("name=\"a\" value=\"b c\""), "{}", html);
    let html = h
        .get("/.iya-pep/accounts?return=%2Fnope")
        .header("cookie", set.clone())
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("action=\"/\""), "{}", html);
    assert!(!html.contains("nope"), "{}", html);
    let form = format!(
        "account={}&return=%2Fpublic%2Fx%3Fa%3Db%2520c",
        alice
    );
    let r = h
        .account_act("/.iya-pep/accounts/switch", &form, &set, &origin)
        .await;
    assert_eq!(r.status(), 303);
    assert_eq!(r.headers()["location"], "/public/x?a=b%20c");
    let form = format!("account={}&return=%2Fsecret", alice);
    let r = h
        .account_act("/.iya-pep/accounts/switch", &form, &set, &origin)
        .await;
    assert_eq!(r.headers()["location"], "/secret");
    let form = format!(
        "account={}&return=%2Fmulti%2Fpage%3Fx%3D1%23frag",
        alice
    );
    let r = h
        .account_act("/.iya-pep/accounts/switch", &form, &set, &origin)
        .await;
    assert_eq!(r.headers()["location"], "/multi/page");
    for ret in [
        "%2Fnope",
        "https%3A%2F%2Fevil.example%2Fmulti%2Fpage",
        "%2F%2Fevil.example%2Fmulti",
        "%2Fmulti%2F%2Fpage",
        "%2Fsecret%2Fextra",
    ] {
        let form = format!("account={}&return={}", alice, ret);
        let r = h
            .account_act("/.iya-pep/accounts/switch", &form, &set, &origin)
            .await;
        assert_eq!(r.status(), 303, "{}", ret);
        assert_eq!(r.headers()["location"], "/", "{}", ret);
    }
    let (status, _) = h
        .location_of("/.iya-pep/accounts/add?return=%2Fnope", &set)
        .await;
    assert_eq!(status, 404);
    let form = format!("account={}&return=%2Fnope", alice);
    let r = h
        .account_act("/.iya-pep/accounts/logout", &form, &set, &origin)
        .await;
    assert_eq!(r.status(), 303);
    assert_eq!(
        r.headers()["location"],
        "/.iya-pep/accounts?return=%2F"
    );
    let r = h
        .account_act(
            "/.iya-pep/accounts/logout-all",
            "return=%2Fsecret%2Fextra",
            &set,
            &origin,
        )
        .await;
    assert_eq!(r.status(), 303);
    assert_eq!(r.headers()["location"], "/");
}

/// A request on `path` as alice over Basic, with `method`.
async fn as_alice(h: &Harness, method: reqwest::Method, path: &str) -> u16 {
    h.http
        .request(method, format!("{}{}", h.proxy, path))
        .basic_auth("alice", Some("right"))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

fn hits(h: &Harness) -> u32 {
    h.app.lock().unwrap().hits
}

/// #1760: a route is decided by the policy it NAMES, never the root —
/// whichever way round the two disagree.
#[tokio::test]
async fn a_route_is_decided_by_its_own_policy_not_the_root() {
    let h = harness().await;
    // The root (`t`) permits alice; `/named` names `deny-all`.
    assert_eq!(as_alice(&h, reqwest::Method::GET, "/api/x").await, 200);
    let before = hits(&h);
    let r = h
        .get("/named/x")
        .basic_auth("alice", Some("right"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "the route's deny-all, not the root's permit");
    let body: Value = r.json().await.unwrap();
    assert!(body["error_description"]
        .as_str()
        .unwrap()
        .contains("said Deny"));
    assert_eq!(hits(&h), before, "nothing reached the application");
    // Now the ROOT denies everything and `t` is no longer the root: the
    // routes that name `t` are still decided by it, and admitted.
    h.sync.load_for_test(&policy_rows("deny-all"));
    assert_eq!(as_alice(&h, reqwest::Method::GET, "/api/x").await, 200);
    assert_eq!(as_alice(&h, reqwest::Method::GET, "/named/x").await, 403);
    // No root at all is not "nothing to decide by" for a route either.
    h.sync.load_for_test(&json!({ "syncToken": "x", "policies": [
        { "policyId": "proxy-test", "name": "t", "isRoot": false,
          "document": POLICY },
        { "policyId": "other", "name": "other", "isRoot": false,
          "document": one_effect("other", "Deny") } ] }));
    assert_eq!(as_alice(&h, reqwest::Method::GET, "/api/x").await, 200);
}

/// #1760: a route whose policy this PEP does not hold is refused without a
/// decision — and a permit-biased PEP, which would admit a NotApplicable,
/// refuses it too.
#[tokio::test]
async fn a_route_naming_a_policy_not_held_is_refused_whatever_the_bias() {
    for bias in [
        crate::options::Bias::DenyBiased,
        crate::options::Bias::PermitBiased,
    ] {
        let h = harness_with(|o| o.bias = bias).await;
        let before = hits(&h);
        let decided = h.sync.counters_json();
        let r = h
            .get("/missing/x")
            .basic_auth("alice", Some("right"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403, "{:?}", bias);
        let body: Value = r.json().await.unwrap();
        assert_eq!(
            body["error_description"], "This route cannot be decided now.",
            "{:?}: STS-XPEP-0117's body, which names no policy",
            bias
        );
        assert_eq!(hits(&h), before, "{:?}: the upstream was not hit", bias);
        assert_eq!(
            h.sync.counters_json(),
            decided,
            "{:?}: nothing decided it, so nothing is counted",
            bias
        );
        // Held, it is decided; withheld again (a later pull without it),
        // refused again.
        assert_eq!(as_alice(&h, reqwest::Method::GET, "/api/x").await, 200);
        let mut rows = policy_rows("t");
        rows["policies"]
            .as_array_mut()
            .unwrap()
            .retain(|r| r["name"] != "t");
        h.sync.load_for_test(&rows);
        assert_eq!(
            as_alice(&h, reqwest::Method::GET, "/api/x").await,
            403,
            "{:?}: a route whose policy was withheld",
            bias
        );
    }
}

/// #1760: the action models — the action-id the ENGINE saw, read through
/// policies that permit exactly one value.
#[tokio::test]
async fn each_action_model_sends_its_action_id() {
    use reqwest::Method as M;
    let h = harness().await;
    // crud, `permit-update`: PUT and PATCH are update; nothing else is.
    assert_eq!(as_alice(&h, M::PUT, "/crud/x").await, 200);
    assert_eq!(as_alice(&h, M::PATCH, "/crud/x").await, 200);
    for m in [M::GET, M::HEAD, M::POST, M::DELETE, M::OPTIONS] {
        assert_eq!(as_alice(&h, m.clone(), "/crud/x").await, 403, "{}", m);
    }
    // read-write, `permit-write`: every method that changes is write.
    for m in [M::POST, M::PUT, M::PATCH, M::DELETE] {
        assert_eq!(as_alice(&h, m.clone(), "/rw/x").await, 200, "{}", m);
    }
    for m in [M::GET, M::HEAD, M::OPTIONS] {
        assert_eq!(as_alice(&h, m.clone(), "/rw/x").await, 403, "{}", m);
    }
    // method, `permit-put`: the method itself.
    assert_eq!(as_alice(&h, M::PUT, "/bymethod/x").await, 200);
    assert_eq!(as_alice(&h, M::PATCH, "/bymethod/x").await, 403);
    assert_eq!(as_alice(&h, M::GET, "/bymethod/x").await, 403);
}

/// #1760: `authorization.resource` is the resource-id when set, and the
/// normalised path when empty — read through policies that permit exactly
/// one anyURI.
#[tokio::test]
async fn the_resource_id_is_the_routes_or_the_path() {
    let h = harness().await;
    // `/full` names FULL_URI and `permit-uri` permits only it, whatever
    // path under the route was asked for.
    assert_eq!(as_alice(&h, reqwest::Method::GET, "/full").await, 200);
    assert_eq!(as_alice(&h, reqwest::Method::GET, "/full/a/b").await, 200);
    // `/bypath` names none: the path is sent, and `permit-path` permits
    // `/bypath/x` alone.
    assert_eq!(as_alice(&h, reqwest::Method::GET, "/bypath/x").await, 200);
    assert_eq!(as_alice(&h, reqwest::Method::GET, "/bypath/y").await, 403);
    assert_eq!(as_alice(&h, reqwest::Method::GET, "/bypath").await, 403);
}

/// #1760: a public route is decided in XACML for the ANONYMOUS subject —
/// no subject-id at all — and refused when its policy denies or is gone.
#[tokio::test]
async fn a_public_route_is_decided_in_xacml() {
    let h = harness().await;
    // `anon-only` permits a request with NO subject-id and denies one
    // carrying any: forwarded, so none was sent.
    let said = echoed(h.get("/anon/page").send().await.unwrap()).await;
    assert_eq!(said["path"], "/pep-app/anon/page");
    let decided = h.sync.counters_json();
    assert!(
        decided["allowed"].as_u64() >= Some(1),
        "the public route's decision is counted: {}",
        decided
    );
    // The same document swapped for one that denies: refused, unreached.
    let mut rows = policy_rows("t");
    for row in rows["policies"].as_array_mut().unwrap() {
        if row["name"] == "anon-only" {
            row["document"] = json!(one_effect("pid-anon-only", "Deny"));
        }
    }
    h.sync.load_for_test(&rows);
    let before = hits(&h);
    assert_eq!(h.get("/anon/page").send().await.unwrap().status(), 403);
    // Removed: refused too (STS-XPEP-0117), never "public, so admitted".
    rows["policies"]
        .as_array_mut()
        .unwrap()
        .retain(|r| r["name"] != "anon-only");
    h.sync.load_for_test(&rows);
    let r = h.get("/anon/page").send().await.unwrap();
    assert_eq!(r.status(), 403);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["error_description"], "This route cannot be decided now.");
    assert_eq!(hits(&h), before, "neither reached the application");
}

/// #1760: an EMPTY `methods` list is deny-all — every method, through the
/// engine, refused after a decision that PERMITTED, the application never
/// reached; a missing policy is still 0117 first.
#[tokio::test]
async fn an_empty_methods_list_denies_every_method() {
    use reqwest::Method as M;
    let h = harness().await;
    let before = hits(&h);
    for m in [M::GET, M::HEAD, M::POST, M::PUT, M::PATCH, M::DELETE,
              M::OPTIONS] {
        let permitted = h.sync.counters_json()["allowed"].as_u64();
        let r = h
            .http
            .request(m.clone(), format!("{}/closed/x", h.proxy))
            .basic_auth("alice", Some("right"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403, "{}", m);
        assert!(r.headers().get("allow").is_none(), "not a 405: {}", m);
        if m != M::HEAD {
            let body: Value = r.json().await.unwrap();
            assert!(
                body["error_description"]
                    .as_str()
                    .unwrap()
                    .contains("deny-all"),
                "{}: {}",
                m,
                body
            );
        }
        assert_eq!(
            h.sync.counters_json()["allowed"].as_u64(),
            permitted.map(|n| n + 1),
            "{}: the policy WAS asked, and permitted",
            m
        );
        // The public twin: no identity, the same refusal.
        let r = h
            .http
            .request(m.clone(), format!("{}/closedpub/x", h.proxy))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403, "public {}", m);
    }
    assert_eq!(hits(&h), before, "the upstream was never hit");
    // A route that allows nothing AND names a policy not held: 0117 wins.
    let r = h
        .get("/closedgone/x")
        .basic_auth("alice", Some("right"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["error_description"], "This route cannot be decided now.");
}

/// #1760: the route members the change made required refuse the document
/// whole — the one held kept.
#[tokio::test]
async fn a_route_without_methods_or_authorization_refuses_the_document() {
    let h = harness().await;
    let cert = String::from_utf8(h.saml_signer.1.to_pem().unwrap()).unwrap();
    type Edit = fn(&mut serde_json::Map<String, Value>);
    let edits: [Edit; 4] = [
        |r: &mut serde_json::Map<String, Value>| {
            r.remove("methods");
        },
        |r: &mut serde_json::Map<String, Value>| {
            r.remove("authorization");
        },
        |r: &mut serde_json::Map<String, Value>| {
            r["authorization"]["kind"] = json!("anyone");
        },
        |r: &mut serde_json::Map<String, Value>| {
            r["authorization"]["actionModel"] = json!("http");
        },
    ];
    for edit in edits {
        let mut doc =
            configuration(&h.upstream_base, &h.service_base, &cert);
        doc["syncToken"] = json!("p-broken");
        edit(doc["proxy"]["routes"][1].as_object_mut().unwrap());
        h.sync.receive_proxy(&doc, None);
        let overview = h.sync.proxy_json();
        assert_eq!(overview["lastPullOk"], false, "{}", overview);
        assert!(overview["lastPullWhy"]
            .as_str()
            .unwrap()
            .contains("refused whole"));
        assert_eq!(overview["syncToken"], "p1", "the held one is kept");
        assert_eq!(as_alice(&h, reqwest::Method::GET, "/api/x").await, 200);
    }
}

// ===== THE ERROR PAGE A PERSON SEES (proxy_page.rs) =======================

/// A browser's request: it accepts HTML.
fn as_browser(r: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    r.header("accept", "text/html,application/xhtml+xml,*/*;q=0.8")
}

/// What a refused browser was answered: the status, and the page, checked
/// to be the standard one with its Diagnostics pane and nothing more.
async fn the_page(r: reqwest::Response, status: u16, title: &str) -> String {
    assert_eq!(r.status(), status, "{}", title);
    let headers = r.headers().clone();
    assert_eq!(headers["content-type"], "text/html; charset=utf-8", "{}",
               title);
    assert_eq!(headers["cache-control"], "no-store");
    let csp = headers["content-security-policy"].to_str().unwrap();
    assert!(csp.starts_with("default-src 'none'; style-src 'sha256-"),
            "{}", csp);
    assert!(!csp.contains("script-src") && !csp.contains("unsafe"), "{}",
            csp);
    let html = r.text().await.unwrap();
    for want in [
        format!("<title>{}</title>", title),
        format!("<h1>{}</h1>", title),
        "<div class=\"warn\" role=\"alert\"><span class=\"error\">"
            .to_string(),
        "<section class=\"diagnostics\"".to_string(),
        "<dt>Time (UTC)</dt>".to_string(),
        "<dt>Incident ID</dt><dd><code>".to_string(),
        "<a class=\"portal\" href=\"/\">Go to the start page</a>".to_string(),
    ] {
        assert!(html.contains(&want), "{}: no {} in {}", title, want, html);
    }
    // THE CODE IS RECORDED, NEVER SENT: no STS-… code, no script.
    assert!(!html.contains("STS-"), "{}: a code on the page: {}", title,
            html);
    assert!(!html.contains("<script"), "{}", title);
    html
}

/// The incident ID a page shows.
fn incident_of(html: &str) -> String {
    let at = html.find("<dt>Incident ID</dt><dd><code>").unwrap() + 30;
    html[at..].split('<').next().unwrap().to_string()
}

/// EVERY REFUSAL A BROWSER MEETS IS THE ONE PAGE (rcbj, 2026-11-15), at
/// its own status, with the headers it always had (a 401's challenges, a
/// 405's `Allow`).
#[tokio::test]
async fn each_refusal_a_browser_meets_is_the_standard_page() {
    let h = harness().await;
    let before = hits(&h);
    // 404, no route.
    let r = as_browser(h.get("/nowhere")).send().await.unwrap();
    let html = the_page(r, 404, "Page not found").await;
    assert!(html.contains("<dt>Address</dt><dd><code>/nowhere</code>"));
    assert!(html.contains("<dt>error</dt><dd><code>not_found</code>"));
    // 400, a path that does not normalise.
    let r = as_browser(h.get("/api/a%2fb")).send().await.unwrap();
    the_page(r, 400, "This address cannot be used").await;
    // 405, with its Allow.
    let r = as_browser(h.http.delete(format!("{}/api/x", h.proxy)))
        .send()
        .await
        .unwrap();
    assert_eq!(r.headers()["allow"], "GET, POST");
    the_page(r, 405, "This action is not allowed here").await;
    // 401, no credential: the challenges are kept.
    let r = as_browser(h.get("/api/x")).send().await.unwrap();
    assert!(challenges(&r).iter().any(|c| c.starts_with("Basic ")));
    the_page(r, 401, "Sign-in required").await;
    // 403, the policy said Deny (mallory), and who was asking is shown.
    let r = as_browser(h.get("/api/x"))
        .basic_auth("mallory", Some("right"))
        .send()
        .await
        .unwrap();
    let html =
        the_page(r, 403, "You do not have access to this page").await;
    assert!(html.contains("<dt>Signed in as</dt><dd><code>mallory</code>"));
    assert!(html.contains("<dt>Application</dt><dd><code>api-app</code>"));
    assert!(html.contains("<dt>error</dt><dd><code>access_denied</code>"));
    assert!(!html.contains("/.iya-pep/"), "a Basic route offers no switch");
    // 403, deny-all (0116).
    let r = as_browser(h.get("/closed/x"))
        .basic_auth("alice", Some("right"))
        .send()
        .await
        .unwrap();
    let html = the_page(r, 403, "This page is closed").await;
    assert!(html.contains("deny-all"), "the API's description: {}", html);
    // 403, the route's policy is not held (0117): the generic description.
    let r = as_browser(h.get("/missing/x"))
        .basic_auth("alice", Some("right"))
        .send()
        .await
        .unwrap();
    let html = the_page(r, 403, "Access cannot be decided now").await;
    assert!(html.contains("This route cannot be decided now."));
    assert!(!html.contains("never-pulled"), "the policy's name is logged");
    // 403, the application is not usable (0093): its reason is logged.
    let r = as_browser(h.get("/gone/x"))
        .basic_auth("alice", Some("right"))
        .send()
        .await
        .unwrap();
    let html = the_page(r, 403, "This application cannot be used now").await;
    assert!(html.contains("This route cannot be used now."));
    assert!(!html.contains("was deleted"), "{}", html);
    // 401, a sign-in callback nobody started (0082).
    let r = as_browser(h.get("/.iya-pep/callback?code=c&state=nope"))
        .send()
        .await
        .unwrap();
    the_page(r, 401, "The sign-in could not be completed").await;
    // 504, the application too slow: a generic sentence.
    let r = as_browser(h.get("/slow")).send().await.unwrap();
    the_page(r, 504, "The application did not answer in time").await;
    assert_eq!(hits(&h), before + 1, "only /slow reached the application");
    // 502, nobody at the upstream: nothing about where it was.
    let gone = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = gone.local_addr().unwrap().port();
    drop(gone);
    let cert = String::from_utf8(h.saml_signer.1.to_pem().unwrap()).unwrap();
    h.sync.receive_proxy(
        &configuration(&format!("http://127.0.0.1:{}/pep-app", dead),
                       &h.service_base, &cert),
        None,
    );
    let r = as_browser(h.get("/public/page")).send().await.unwrap();
    let html = the_page(r, 502, "The application cannot be reached").await;
    assert!(!html.contains("127.0.0.1"), "{}", html);
}

/// A refusal of WHO is asking, on a session route, says what to do: the
/// account chooser on a `multipleAccounts` route, a sign-out on any other.
/// Adding an account is the chooser's own action, so the refusal page
/// does not offer it beside the chooser.
#[tokio::test]
async fn a_refused_person_is_offered_another_account() {
    let h = harness().await;
    let (_, to) = h.location_of("/multi/page", "").await;
    let set = cookie_of(&h.sign_in_as(&to, ("urn:uuid:mallory", "mallory"),
                                      "sid-m", "mm").await);
    let r = as_browser(h.get("/multi/page?x=1"))
        .header("cookie", &set)
        .send()
        .await
        .unwrap();
    let html =
        the_page(r, 403, "You do not have access to this page").await;
    assert!(html.contains(
        "<a class=\"portal\" href=\"/.iya-pep/accounts?return=\
         %2Fmulti%2Fpage%3Fx%3D1\">Use a different account</a>"
    ), "{}", html);
    assert!(!html.contains("Sign in with another account"), "{}", html);
    assert!(!html.contains("/.iya-pep/accounts/add"), "{}", html);
    // One sign-in per browser: a sign-out.
    let (_, to) = h.location_of("/livehdr/page", "").await;
    let one = cookie_of(&h.sign_in_as(&to, ("urn:uuid:mallory", "mallory"),
                                      "sid-n", "mn").await);
    let r = as_browser(h.get("/livehdr/page"))
        .header("cookie", &one)
        .send()
        .await
        .unwrap();
    let html =
        the_page(r, 403, "You do not have access to this page").await;
    assert!(html.contains("href=\"/.iya-pep/logout\">Sign out"), "{}", html);
    assert!(!html.contains("/.iya-pep/accounts"), "{}", html);
}

/// What a request carried is drawn escaped.
#[tokio::test]
async fn the_page_escapes_what_the_request_carried() {
    let h = harness().await;
    // Who signed in: a username the service answered.
    let evil = "<script>alert('x')</script>\"&";
    let r = as_browser(h.get("/closed/x"))
        .basic_auth(evil, Some("right"))
        .send()
        .await
        .unwrap();
    let html = the_page(r, 403, "This page is closed").await;
    assert!(!html.contains("<script>alert"), "{}", html);
    assert!(html.contains(
        "<dt>Signed in as</dt><dd><code>&lt;script&gt;alert(&#39;x&#39;)\
         &lt;/script&gt;&quot;&amp;</code>"
    ), "{}", html);
    // The address, as the request spelled it.
    let r = as_browser(h.get("/x\"><b>"))
        .send()
        .await
        .unwrap();
    let html = the_page(r, 404, "Page not found").await;
    assert!(!html.contains("\"><b>"), "{}", html);
}

/// `GET /` is the start page for a browser when no route is mounted there:
/// the product logo, the name, one sentence, and the standard footer. A
/// route mounted at `/` is that route. A client that does not accept HTML
/// keeps the 404 (`a_request_that_does_not_accept_html_keeps_its_json`).
/// The application is not asked.
#[tokio::test]
async fn the_start_page_is_what_go_to_the_start_page_opens() {
    let h = harness().await;
    let before = hits(&h);
    let r = as_browser(h.get("/")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["content-type"], "text/html; charset=utf-8");
    assert_eq!(r.headers()["cache-control"], "no-store");
    let csp = r.headers()["content-security-policy"].to_str().unwrap();
    assert!(csp.contains("img-src 'self'"), "{}", csp);
    assert!(!csp.contains("script-src") && !csp.contains("unsafe"), "{}",
            csp);
    let html = r.text().await.unwrap();
    assert!(html.contains("<title>IYA STS</title>"), "{}", html);
    assert!(html.contains("class=\"front\""), "{}", html);
    assert!(html.contains(
        "src=\"/.iya-pep/logo.png\" width=\"906\" height=\"269\" \
         alt=\"IYA STS — Security Token Service\""
    ), "{}", html);
    assert!(html.contains("<h1>IYA STS</h1>"), "{}", html);
    assert!(html.contains("class=\"sts-footer\""), "{}", html);
    assert!(html.contains("Iya CyberSecurity Solutions, LLC"), "{}", html);
    assert!(html.contains("Version "), "{}", html);
    assert!(!html.contains("STS-"), "{}", html);
    assert!(!html.contains("<script"), "{}", html);
    assert!(!html.contains("<section class=\"diagnostics\""), "{}", html);
    assert_eq!(hits(&h), before, "the start page asks no application");
    // The logo the page names.
    let logo = h.get("/.iya-pep/logo.png").send().await.unwrap();
    assert_eq!(logo.status(), 200);
    assert_eq!(logo.headers()["content-type"], "image/png");
    assert_eq!(logo.headers()["cache-control"], "public, max-age=3600");
    let bytes = logo.bytes().await.unwrap();
    assert!(bytes.starts_with(b"\x89PNG"), "not a PNG");
    // A route mounted at `/` is that route, not this page.
    let cert = String::from_utf8(h.saml_signer.1.to_pem().unwrap()).unwrap();
    let mut doc = configuration(&h.upstream_base, &h.service_base, &cert);
    doc["proxy"]["routes"].as_array_mut().unwrap().insert(
        0,
        json!({
            "id": "root",
            "path": "/",
            "match": "exact",
            "methods": ["GET", "HEAD"],
            "authorization": public_on("t")
        }),
    );
    h.sync.receive_proxy(&doc, None);
    let r = as_browser(h.get("/")).send().await.unwrap();
    let said = echoed(r).await;
    assert_eq!(said["path"], "/pep-app/");
    assert_eq!(hits(&h), before + 1);
    // Switched off: a browser's `/` is still the start page. Another path
    // stays the 404.
    let mut off = configuration(&h.upstream_base, &h.service_base, &cert);
    off["proxy"]["enabled"] = json!(false);
    h.sync.receive_proxy(&off, None);
    let r = as_browser(h.get("/")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let html = r.text().await.unwrap();
    assert!(html.contains("<h1>IYA STS</h1>"), "{}", html);
    let r = as_browser(h.get("/public/page")).send().await.unwrap();
    the_page(r, 404, "Page not found").await;
    assert_eq!(hits(&h), before + 1, "nothing else was forwarded");
}

/// THE API ANSWER IS UNCHANGED: a request that does not accept HTML is
/// answered the JSON it always was, byte for byte.
#[tokio::test]
async fn a_request_that_does_not_accept_html_keeps_its_json() {
    let h = harness().await;
    let json_of = |r: reqwest::Response| async move {
        assert_eq!(r.headers()["content-type"], "application/json");
        assert!(r.headers().get("content-security-policy").is_none());
        r.text().await.unwrap()
    };
    let cases: Vec<(reqwest::RequestBuilder, u16, &str)> = vec![
        (h.get("/nowhere"), 404,
         r#"{"error":"not_found","error_description":"no route matches this path"}"#),
        (h.get("/"), 404,
         r#"{"error":"not_found","error_description":"no route matches this path"}"#),
        (h.get("/closed/x").basic_auth("alice", Some("right")), 403,
         r#"{"error":"access_denied","error_description":"the route allows no method: deny-all"}"#),
        (h.get("/missing/x").basic_auth("alice", Some("right")), 403,
         r#"{"error":"access_denied","error_description":"This route cannot be decided now."}"#),
        (h.get("/gone/x").basic_auth("alice", Some("right")), 403,
         r#"{"error":"access_denied","error_description":"This route cannot be used now."}"#),
        (h.get("/api/x").header("accept", "application/json"), 401,
         r#"{"error":"unauthorized","error_description":"the request carries no credential"}"#),
        (h.get("/slow"), 504,
         r#"{"error":"gateway_timeout","error_description":"The application did not answer in time."}"#),
    ];
    for (request, status, body) in cases {
        let r = request.send().await.unwrap();
        assert_eq!(r.status(), status, "{}", body);
        assert_eq!(json_of(r).await, body);
    }
    let r = h
        .get("/api/x")
        .basic_auth("mallory", Some("right"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let body: Value = serde_json::from_str(&json_of(r).await).unwrap();
    assert_eq!(body["error"], "access_denied");
    assert!(body["error_description"].as_str().unwrap()
        .starts_with("the policy this PEP holds said Deny"));
}

/// THE INCIDENT ID ON THE PAGE IS IN THE REFUSAL'S LOG LINE, beside the
/// error code: what an operator searches the log for.
#[tokio::test]
async fn the_pages_incident_id_finds_the_log_line() {
    let h = harness().await;
    let r = as_browser(h.get("/closed/x"))
        .basic_auth("alice", Some("right"))
        .send()
        .await
        .unwrap();
    let html = the_page(r, 403, "This page is closed").await;
    let incident = incident_of(&html);
    assert_eq!(incident.len(), 16, "{}", incident);
    let lines = proxy::logged::holding(&incident);
    assert_eq!(lines.len(), 1, "one line names {}: {:?}", incident, lines);
    let line = &lines[0];
    assert!(line.contains("[STS-XPEP-0116]"), "{}", line);
    assert!(line.contains(&format!("page incident {}", incident)), "{}",
            line);
    // A second refusal is another incident.
    let r = as_browser(h.get("/closed/x"))
        .basic_auth("alice", Some("right"))
        .send()
        .await
        .unwrap();
    assert_ne!(incident_of(&the_page(r, 403, "This page is closed").await),
               incident);
}

// ===== BEFORE THE FIRST CONFIGURATION: TRY AGAIN LATER ====================

/// The lines `Sync::note_waiting()` writes when the state is first met.
fn waiting_announced() -> usize {
    proxy::logged::holding("has received no configuration since it started")
        .len()
}

/// NOT CONFIGURED YET IS NOT "PAGE NOT FOUND" (rcbj, 2026-11-15). After a
/// start and before the first configuration answer, every path — the
/// proxy's own `/.iya-pep/*` too — is 503 with `Retry-After` (the poll
/// interval, rounded up to whole seconds): the standard page's "Try again
/// later" for a browser, the `{error, error_description}` of the other
/// 503s for anything else. Once a configuration arrives the routes answer;
/// one received EMPTY or SWITCHED OFF is the 404 of STS-XPEP-0065, as
/// before. The log has the state change, not a line per request.
#[tokio::test]
async fn before_its_first_configuration_the_proxy_says_try_again_later() {
    let h = harness_unconfigured(|o| o.poll_interval_ms = 1500).await;
    // A browser: the standard page at 503, with Retry-After.
    let r = as_browser(h.get("/public/page")).send().await.unwrap();
    assert_eq!(r.headers()["retry-after"], "2", "1500 ms, rounded up");
    let html = the_page(r, 503, "Try again later").await;
    assert!(
        html.contains("<dt>error</dt><dd><code>temporarily_unavailable"),
        "{}",
        html
    );
    assert!(html.contains("still receiving its settings"), "{}", html);
    // An API client: the JSON of the proxy's other 503s, no code in it.
    let r = h.get("/api/x").send().await.unwrap();
    assert_eq!(r.status(), 503);
    assert_eq!(r.headers()["retry-after"], "2");
    assert_eq!(r.headers()["content-type"], "application/json");
    let body: Value = r.json().await.unwrap();
    assert_eq!(
        body,
        json!({ "error": "temporarily_unavailable",
                "error_description": "This proxy has not yet received its \
                                      configuration since it started." })
    );
    // The proxy's own paths are not configured yet either.
    for path in [
        "/.iya-pep/accounts",
        "/.iya-pep/accounts/add",
        "/.iya-pep/logout",
        "/.iya-pep/callback?code=c&state=s",
        "/.iya-pep/logo.png",
        "/",
        "/nowhere",
    ] {
        let r = h.get(path).send().await.unwrap();
        assert_eq!(r.status(), 503, "{}", path);
        assert_eq!(r.headers()["retry-after"], "2", "{}", path);
    }
    assert_eq!(hits(&h), 0, "nothing reached the application");
    // Nine requests, one line saying so — not nine.
    assert_eq!(waiting_announced(), 1);
    // The first configuration: the routes answer.
    let cert = String::from_utf8(h.saml_signer.1.to_pem().unwrap()).unwrap();
    h.sync.receive_proxy(
        &configuration(&h.upstream_base, &h.service_base, &cert),
        None,
    );
    h.proxied.reconcile().await;
    let r = h.get("/public/page").send().await.unwrap();
    assert!(r.headers().get("retry-after").is_none());
    echoed(r).await;
    assert_eq!(hits(&h), 1);
    assert_eq!(
        proxy::logged::holding("received its first configuration since it \
                                started; 9 request(s)")
            .len(),
        1,
        "the state change, with its count"
    );
    let r = h.get("/nowhere").send().await.unwrap();
    assert_eq!(r.status(), 404, "no route is 404 again");
    // A configuration switched off: received, so 404 — not 503.
    let mut off = configuration(&h.upstream_base, &h.service_base, &cert);
    off["proxy"]["enabled"] = json!(false);
    h.sync.receive_proxy(&off, None);
    let r = as_browser(h.get("/public/page")).send().await.unwrap();
    assert!(r.headers().get("retry-after").is_none());
    let html = the_page(r, 404, "Page not found").await;
    assert!(html.contains("no configuration that is switched on"), "{}",
            html);
    // None at all for this PEP: received, and empty — 404.
    h.sync
        .receive_proxy(&json!({ "configured": false, "pep": "pep-1" }), None);
    let r = h.get("/.iya-pep/accounts").send().await.unwrap();
    assert_eq!(r.status(), 404);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["error"], "not_found");
    assert_eq!(waiting_announced(), 1, "no 503 after the first answer");
}

/// A FIRST answer that is empty is an answer: 404 from the start, never a
/// 503 the client would wait out for nothing.
#[tokio::test]
async fn a_first_answer_that_holds_nothing_is_404_not_503() {
    let h = harness_unconfigured(|_| {}).await;
    h.sync
        .receive_proxy(&json!({ "configured": false, "pep": "pep-1" }), None);
    let r = h.get("/public/page").send().await.unwrap();
    assert_eq!(r.status(), 404);
    assert!(r.headers().get("retry-after").is_none());
    // A failed later pull keeps what was received: still 404.
    h.sync.receive_proxy(&json!({ "configured": true }), None);
    assert_eq!(h.get("/public/page").send().await.unwrap().status(), 404);
}

/// THE PROXY'S DECISION RECORDS (#1827): one per request that reached its
/// route's authorization — forwarded, refused by the policy, refused by
/// authentication — with the route, the status, the person by username and
/// the path without its query; none for a path no route matches, and none
/// while no configuration has been received (`STS-XPEP-0118`).
#[tokio::test]
async fn queues_a_record_for_each_request_its_route_decided() {
    let h = harness().await;
    let audit = h.proxied.audit();
    let r = h
        .get("/api/x?token=s3cret")
        .basic_auth("alice", Some("right"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let r = h
        .get("/api/x")
        .basic_auth("mallory", Some("right"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let r = h
        .get("/api/x")
        .basic_auth("alice", Some("wrong"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let r = h.get("/nowhere-at-all").send().await.unwrap();
    assert_eq!(r.status(), 404);
    let records = audit.queued_for_test();
    assert_eq!(records.len(), 3, "{:?}", records);

    let allowed = &records[0];
    assert_eq!(
        (allowed.kind.as_str(), allowed.route.as_deref(), allowed.status),
        ("proxy", Some("api"), Some(200))
    );
    assert!(allowed.allowed && !allowed.fault);
    assert_eq!(allowed.decision, "Permit");
    assert_eq!(
        (allowed.subject.as_str(), allowed.resource.as_str(),
         allowed.action.as_str()),
        ("alice", "/api/x", "GET")
    );
    assert_eq!(allowed.policies, ["t"]);
    assert_eq!(allowed.code, "");
    let sent = serde_json::to_string(allowed).unwrap();
    assert!(!sent.contains("s3cret"), "no query string: {}", sent);
    assert!(!sent.contains("right"), "no credential: {}", sent);

    let refused = &records[1];
    assert_eq!((refused.status, refused.allowed), (Some(403), false));
    assert_eq!(refused.code, "STS-XPEP-0086");
    assert_eq!(refused.subject, "mallory");
    assert!(!refused.decision.is_empty() && refused.decision != "Permit");
    assert!(!refused.why.is_empty() && !refused.fault);

    let unauthenticated = &records[2];
    assert_eq!(unauthenticated.status, Some(401));
    assert_eq!(unauthenticated.subject, "", "nobody was established");
    assert_eq!(unauthenticated.decision, "", "no policy was asked");
    assert!(unauthenticated.code.starts_with("STS-XPEP-"));
    // A record's members on the wire: the twenty, and route and status.
    let wire = serde_json::to_value(unauthenticated).unwrap();
    assert_eq!(wire.as_object().unwrap().len(), 22);

    // NOT CONFIGURED YET: a 503, and no record.
    let waiting = harness_unconfigured(|_| {}).await;
    let r = waiting
        .get("/api/x")
        .basic_auth("alice", Some("right"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 503);
    assert!(waiting.proxied.audit().queued_for_test().is_empty());
}
