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
}

/// What the application has seen of its SAML sessions.
#[derive(Default)]
struct UpState {
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
) -> String {
    let now = chrono::Utc::now().timestamp();
    let digest = openssl::sha::sha256(access_token.as_bytes());
    jws(
        key,
        &json!({ "alg": "RS256", "kid": "k1", "typ": "JWT" }),
        &json!({ "iss": issuer, "aud": client, "sub": "urn:uuid:carol",
                 "preferred_username": "carol", "nonce": nonce, "sid": sid,
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
            let (issuer, expect) = {
                let g = s.lock().unwrap();
                (g.issuer.clone(), g.expect.clone())
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
                        id_token(&key, &issuer, &client, &nonce, &sid, &access),
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
    let router = axum::Router::new()
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
                  "public": true, "identity": { "mode": "headers", "headers": [
                    { "name": "X-Remote-User", "claim": "username" } ] } },
                { "id": "api", "path": "/api", "methods": ["GET", "POST"],
                  "mechanisms": ["oauth2", "basic"], "application": "api-app",
                  "resolved": resolved_for(true, false, ""),
                  "identity": { "mode": "headers", "headers": [
                    { "name": "X-Remote-User", "claim": "username" },
                    { "name": "X-Remote-Auth", "claim": "mechanism" } ] } },
                { "id": "saml", "path": "/saml", "mechanisms": ["saml2"],
                  "application": "saml-app",
                  "resolved": resolved_for(false, true, ""),
                  "identity": { "mode": "headers", "headers": [
                    { "name": "X-Remote-User", "claim": "username" } ] } },
                { "id": "app", "path": "/app", "mechanisms": ["session"],
                  "application": CLIENT, "signals": false,
                  "resolved": resolved_for(false, false, CLIENT),
                  "identity": { "mode": "headers", "headers": [
                    { "name": "X-Remote-User", "claim": "username" } ] } },
                { "id": "live", "path": "/live", "mechanisms": ["session"],
                  "application": LIVE_CLIENT,
                  "resolved": resolved_for(false, false, LIVE_CLIENT),
                  "identity": { "mode": "headers", "headers": [
                    { "name": "X-Remote-User", "claim": "username" } ] } },
                { "id": "fwd", "path": "/fwd", "mechanisms": ["basic"],
                  "application": "fwd-app", "forwardCredentials": true,
                  "resolved": resolved_for(false, false, "") },
                { "id": "secret", "path": "/secret", "match": "exact",
                  "mechanisms": ["basic"], "resource": "urn:app:secret",
                  "application": "secret-app",
                  "resolved": resolved_for(false, false, "") },
                { "id": "gone", "path": "/gone", "mechanisms": ["basic"],
                  "application": "deleted-app",
                  "resolved": { "usable": false,
                                "why": "the application was deleted",
                                "code": "STS-XACML-0217" } },
                { "id": "slow", "path": "/slow", "match": "exact",
                  "public": true },
                { "id": "hdr", "path": "/hdr", "mechanisms": ["basic"],
                  "application": "hdr-app",
                  "resolved": resolved_for(false, false, ""),
                  "identity": { "mode": "headers", "separator": ",",
                    "headers": [
                      { "name": "X-Iya-Email", "claim": "email" },
                      { "name": "X-Iya-Groups", "claim": "groups" },
                      { "name": "X-Iya-Via", "claim": "mechanism" } ] } },
                { "id": "tok", "path": "/tok", "mechanisms": ["basic"],
                  "application": "tok-app",
                  "resolved": resolved_for(false, false, ""),
                  "identity": { "mode": "jwt" } },
                { "id": "apptok", "path": "/apptok",
                  "mechanisms": ["session"], "application": CLIENT,
                  "signals": false,
                  "resolved": resolved_for(false, false, CLIENT),
                  "identity": { "mode": "jwt" } },
                { "id": "sso", "path": "/sso", "mechanisms": ["basic"],
                  "application": "sso-app",
                  "resolved": resolved_for(false, false, ""),
                  "identity": { "mode": "saml" } }
            ]
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
    // Short enough for the stale-stream test, long enough that a busy
    // machine never makes a working stream look stale.
    options.proxy_signals_stale_ms = 2000;
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
    // What the poll does after every pull: the relying parties built.
    proxy.reconcile().await;
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    tokio::spawn(proxy::serve_on(proxy.clone(), socket));
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
    assert_eq!(overview["routes"], 13);
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
