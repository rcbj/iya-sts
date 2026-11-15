// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE THREE FAMILIES DRIVEN END TO END, in process, over an in-memory
//! directory and a certificate authority built for the run: an ACME
//! account bound by an External Account Binding, an order, its finalize,
//! the chain, renewal information, revocation and a key change; EST's
//! CA certificates, CSR attributes, simpleenroll, serverkeygen and
//! /nonce; SCEP's capabilities, CA certificates and a PKCSReq answered
//! with a CertRep the requester opens. Every refusal's sentence asserted
//! is the one `tests/enrollment_model_wire.snapshot.json` recorded from
//! Node.

#![allow(clippy::unwrap_used, clippy::expect_used)] // tests

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::{json, Value as Json};
use sts_cluster::scheduler::{Claim, ClaimRefused, Claims};
use sts_core::mode::Mode;
use sts_core::realm::{RealmRegistry, SettingsEnvironment};
use sts_core::settings::Settings;
use sts_credentials::limits::{MemoryBuckets, RateLimiter};
use sts_crypto::keys::JwsKey;
use sts_enroll::acme::store::AcmeStore;
use sts_enroll::acme::Acme;
use sts_enroll::core::{Core, CoreDeps, Entry};
use sts_enroll::est::{Est, EstStore};
use sts_enroll::http::Req;
use sts_enroll::ports::*;
use sts_enroll::scep::{cms, Scep, ScepStore};
use sts_pki::authority::{Authority, MemoryRows, PkiConfig};

// ---------------------------------------------------------------------
// The fakes.
// ---------------------------------------------------------------------

#[derive(Default)]
struct Directory {
    entries: Mutex<BTreeMap<(String, String), BTreeMap<String, Vec<String>>>>,
}

impl Directory {
    fn add(&self, kind: &str, id: &str, attrs: &[(&str, &[&str])]) {
        let mut map = BTreeMap::new();
        for (k, v) in attrs {
            map.insert(
                k.to_lowercase(),
                v.iter().map(|s| s.to_string()).collect(),
            );
        }
        self.entries
            .lock()
            .unwrap()
            .insert((kind.into(), id.into()), map);
    }
}

impl Entries for Directory {
    fn read(&self, kind: &str, id: &str) -> Option<EntryRead> {
        let held = self.entries.lock().unwrap();
        let attrs = held.get(&(kind.to_string(), id.to_string()))?;
        Some(EntryRead {
            dn: format!("uid={},ou=users,dc=test", id),
            attributes: attrs.clone(),
        })
    }
    fn write(
        &self,
        kind: &str,
        id: &str,
        name: &str,
        values: &[String],
    ) -> bool {
        let mut held = self.entries.lock().unwrap();
        let Some(attrs) = held.get_mut(&(kind.to_string(), id.to_string()))
        else {
            return false;
        };
        if values.is_empty() {
            attrs.remove(&name.to_lowercase());
        } else {
            attrs.insert(name.to_lowercase(), values.to_vec());
        }
        true
    }
    fn holders_with_values(
        &self,
        kind: &str,
        name: &str,
    ) -> Vec<(String, Vec<String>)> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter(|((k, _), _)| k == kind)
            .filter_map(|((_, id), a)| {
                a.get(&name.to_lowercase()).map(|v| (id.clone(), v.clone()))
            })
            .collect()
    }
    fn subject_for_name(&self, name: &str) -> String {
        format!("urn:uuid:{}", name)
    }
    fn name_for_subject(&self, subject: &str) -> String {
        subject.trim_start_matches("urn:uuid:").to_string()
    }
}

struct NoApplications;
impl Applications for NoApplications {
    fn find(&self, _id: &str) -> Option<Application> {
        None
    }
    fn get(&self, _id: &str) -> Option<Application> {
        None
    }
    fn client_secret(&self, _id: &str) -> String {
        String::new()
    }
}

/// Development's password door: anything but `invalid`.
struct AnyPassword;
impl Passwords for AnyPassword {
    fn verify(
        &self,
        _n: &str,
        password: &str,
        _via: &str,
        _door: &str,
    ) -> PasswordVerdict {
        PasswordVerdict {
            ok: password != "invalid",
            app_password: None,
        }
    }
}

struct NoRoster;
impl Roster for NoRoster {
    fn roles_of(&self, _n: &str, _r: &str) -> Roles {
        Roles::default()
    }
}

struct Plain;
impl sts_credentials::ports::Keystore for Plain {
    fn persists(&self) -> bool {
        false
    }
    fn seal(&self, plain: &str, _l: &str, _s: &str) -> Option<String> {
        Some(plain.into())
    }
    fn open(&self, sealed: &str, _l: &str) -> Option<String> {
        Some(sealed.into())
    }
}

#[derive(Default)]
struct HeldClaims(Mutex<std::collections::HashSet<String>>);
impl Claims for HeldClaims {
    fn claim(
        &self,
        scope: &str,
        value: &str,
        _realm: &str,
        _ttl: f64,
    ) -> sts_cluster::schedule::BoxFuture<'_, Result<Claim, ClaimRefused>> {
        let key = format!("{}|{}", scope, value);
        let fresh = self.0.lock().unwrap().insert(key.clone());
        Box::pin(async move {
            if fresh {
                Ok(Claim {
                    claimed_at: 0.0,
                    handle: Json::from(key),
                })
            } else {
                Err(ClaimRefused::Held)
            }
        })
    }
    fn release(
        &self,
        handle: &Json,
    ) -> sts_cluster::schedule::BoxFuture<'_, ()> {
        if let Some(k) = handle.as_str() {
            self.0.lock().unwrap().remove(k);
        }
        Box::pin(async {})
    }
}

struct Env(Arc<Settings>);
impl sts_credentials::ports::Environment for Env {
    fn setting(&self, key: &str) -> Json {
        Json::from(self.0.value_of(key).as_int())
    }
    fn predicate(&self, _name: &str) -> bool {
        false
    }
    fn now_ms(&self) -> f64 {
        sts_core::time::now_ms_f64()
    }
    fn realm_id(&self) -> String {
        "default".into()
    }
    fn random_bytes(&self, n: usize) -> Vec<u8> {
        sts_crypto::random::random_bytes(n).unwrap()
    }
    fn random_int(&self, min: u64, _max: u64) -> u64 {
        min
    }
    fn hash_secret(&self, p: &str) -> String {
        p.into()
    }
}

struct World {
    core: Arc<Core>,
    acme: Arc<Acme>,
    est: Arc<Est>,
    scep: Arc<Scep>,
}

fn world() -> World {
    let settings = Arc::new(Settings::new(json!({}), HashMap::new()));
    let mode = Arc::new(Mode::new(settings.clone()));
    let registry = Arc::new(RealmRegistry::new(Arc::new(
        SettingsEnvironment::new(settings.clone(), Vec::new()),
    )));
    let lifecycle = sts_core::realm_lifecycle::RealmLifecycle::new(
        registry.clone(),
        settings.clone(),
        mode.clone(),
    );
    let handles = sts_core::realm_store::StoreHandles::new();
    let authority = Authority::new(
        Arc::new(MemoryRows::default()),
        PkiConfig::development(),
    );
    let started = authority.start(&[]);
    assert!(started.built, "{:?}", started);
    let directory = Arc::new(Directory::default());
    directory.add(
        "person",
        "alicew",
        &[
            ("mail", &["alicew@example.test"]),
            ("stsCertificateHostName", &["www.alicew.test"]),
        ],
    );
    directory.add("person", "bobw", &[("mail", &["bobw@example.test"])]);
    let quiet = Arc::new(Quiet);
    let core = Core::new(CoreDeps {
        settings: settings.clone(),
        mode,
        registry,
        lifecycle: Some(lifecycle.clone()),
        authority,
        entries: directory,
        applications: Arc::new(NoApplications),
        passwords: Arc::new(AnyPassword),
        roster: Arc::new(NoRoster),
        gate: quiet.clone(),
        audit: quiet.clone(),
        signals: quiet.clone(),
        monitor: quiet,
        keystore: Arc::new(Plain),
        claims: Arc::new(HeldClaims::default()),
        limits: Arc::new(RateLimiter::new(
            Arc::new(Env(settings)),
            Arc::new(MemoryBuckets::default()),
        )),
    });
    World {
        acme: Acme::new(core.clone(), AcmeStore::declare(&lifecycle, &handles)),
        est: Est::new(core.clone(), EstStore::declare(&lifecycle, &handles)),
        scep: Scep::new(core.clone(), ScepStore::declare(&lifecycle, &handles)),
        core,
    }
}

const BASE: &str = "http://localhost";

fn req(
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> Req {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let mut map = axum::http::HeaderMap::new();
    for (k, v) in headers {
        map.insert(
            axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
            v.parse().unwrap(),
        );
    }
    map.insert("content-length", body.len().to_string().parse().unwrap());
    Req {
        method: method.into(),
        path: path.into(),
        query: query.into(),
        headers: map,
        text: None,
        body,
        base: BASE.into(),
        address: "127.0.0.1".into(),
        over_tls: false,
        peer_chain: Vec::new(),
    }
}

fn json_of(reply: &sts_enroll::http::Reply) -> Json {
    serde_json::from_slice(&reply.body).unwrap_or(Json::Null)
}

// ---------------------------------------------------------------------
// An ACME client.
// ---------------------------------------------------------------------

struct Client {
    key: JwsKey,
    jwk: Json,
    kid: Option<String>,
    nonce: String,
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

impl Client {
    fn new() -> Client {
        let key = sts_crypto::jws::generate_key("ES256").unwrap();
        let jwk = key.public_jwk().unwrap().unwrap();
        Client {
            key,
            jwk,
            kid: None,
            nonce: String::new(),
        }
    }

    async fn nonce(&mut self, w: &World) {
        let r = w
            .acme
            .handle(&req("HEAD", "/enroll/acme/new-nonce", &[], Vec::new()))
            .await
            .unwrap();
        self.nonce = r.header("Replay-Nonce").unwrap().to_string();
    }

    fn signed(&self, path: &str, payload: Option<&Json>, jwk: bool) -> Vec<u8> {
        let mut header = json!({ "alg": "ES256", "nonce": self.nonce, "url": format!("{}{}", BASE, path) });
        if jwk || self.kid.is_none() {
            header["jwk"] = self.jwk.clone();
        } else {
            header["kid"] = Json::from(self.kid.clone().unwrap());
        }
        let protected = b64(header.to_string().as_bytes());
        let body = payload
            .map(|p| b64(p.to_string().as_bytes()))
            .unwrap_or_default();
        let sig = sts_crypto::jws::sign_input(
            "ES256",
            &self.key,
            format!("{}.{}", protected, body).as_bytes(),
        )
        .unwrap();
        json!({ "protected": protected, "payload": body, "signature": b64(&sig) }).to_string().into_bytes()
    }

    async fn post(
        &mut self,
        w: &World,
        path: &str,
        payload: Option<&Json>,
    ) -> sts_enroll::http::Reply {
        self.nonce(w).await;
        let body = self.signed(path, payload, false);
        w.acme
            .handle(&req(
                "POST",
                path,
                &[("content-type", "application/jose+json")],
                body,
            ))
            .await
            .unwrap()
    }
}

fn csr_for(cn: &str, sans: Json) -> (Vec<u8>, String) {
    let alg = sts_pki::authority::catalog::key_alg("ec-p256").unwrap();
    let (private, public) = alg.generate().unwrap();
    let csr = sts_pki::x509::issue::certification_request(&json!({
        "subject": [{ "name": "CN", "value": cn }],
        "publicKeyPem": public, "privateKeyPem": private,
        "subjectAltName": sans,
    }))
    .unwrap();
    (csr.der, private)
}

#[tokio::test]
async fn acme_end_to_end() {
    let w = world();
    let d = w
        .acme
        .handle(&req("GET", "/enroll/acme/directory", &[], Vec::new()))
        .await
        .unwrap();
    assert_eq!(d.status, 200);
    let dir = json_of(&d);
    assert_eq!(dir["meta"]["externalAccountRequired"], true);
    assert_eq!(dir["newOrder"], "http://localhost/enroll/acme/new-order");
    let wrong = w
        .acme
        .handle(&req("POST", "/enroll/acme/directory", &[], Vec::new()))
        .await
        .unwrap();
    assert_eq!(wrong.status, 405);
    assert_eq!(wrong.header("Allow"), Some("GET, HEAD"));
    assert_eq!(
        json_of(&wrong)["detail"],
        "This ACME resource answers GET, HEAD (RFC 8555 section 6.3)."
    );

    let mut alice = Client::new();
    let r = alice
        .post(&w, "/enroll/acme/new-account", Some(&json!({})))
        .await;
    assert_eq!(r.status, 403);
    assert!(json_of(&r)["detail"]
        .as_str()
        .unwrap()
        .starts_with("This server requires an External Account Binding"));

    let eab = w
        .core
        .create_eab(&Entry::new("person", "alicew"), None, "test")
        .unwrap();
    alice.nonce(&w).await;
    let url = format!("{}/enroll/acme/new-account", BASE);
    let protected = b64(json!({ "alg": "HS256", "kid": eab.kid, "url": url })
        .to_string()
        .as_bytes());
    let payload = b64(alice.jwk.to_string().as_bytes());
    let mac = sts_crypto::jws::sign_input(
        "HS256",
        &JwsKey::secret(URL_SAFE_NO_PAD.decode(&eab.hmac_key).unwrap()),
        format!("{}.{}", protected, payload).as_bytes(),
    )
    .unwrap();
    let binding = json!({ "protected": protected, "payload": payload, "signature": b64(&mac) });
    let body = alice.signed("/enroll/acme/new-account", Some(&json!({ "externalAccountBinding": binding, "termsOfServiceAgreed": true })), true);
    let r = w
        .acme
        .handle(&req(
            "POST",
            "/enroll/acme/new-account",
            &[("content-type", "application/jose+json")],
            body,
        ))
        .await
        .unwrap();
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
    alice.kid = Some(r.header("Location").unwrap().to_string());
    assert_eq!(json_of(&r)["status"], "valid");

    // An unregistered host is the core's refusal, in the snapshot's words.
    let r = alice
        .post(&w, "/enroll/acme/new-order", Some(&json!({ "identifiers": [{ "type": "dns", "value": "nope.test" }] })))
        .await;
    assert_eq!(r.status, 400);
    assert_eq!(
        json_of(&r)["type"],
        "urn:ietf:params:acme:error:rejectedIdentifier"
    );
    assert!(json_of(&r)["detail"].as_str().unwrap().starts_with("The host name \"nope.test\" is not registered on the person \"alicew\"."));

    let r = alice
        .post(&w, "/enroll/acme/new-order", Some(&json!({ "identifiers": [{ "type": "dns", "value": "www.alicew.test" }] })))
        .await;
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
    let order = json_of(&r);
    assert_eq!(order["status"], "ready");
    assert_eq!(order["profile"], "tls-server");
    let finalize = order["finalize"]
        .as_str()
        .unwrap()
        .trim_start_matches(BASE)
        .to_string();
    let authz = order["authorizations"][0]
        .as_str()
        .unwrap()
        .trim_start_matches(BASE)
        .to_string();
    let a = alice.post(&w, &authz, None).await;
    assert_eq!(json_of(&a)["challenges"][0]["type"], "sts-entry-binding-01");

    let (csr, _) = csr_for(
        "www.alicew.test",
        json!([{ "kind": "dns", "value": "www.alicew.test" }]),
    );
    let r = alice
        .post(&w, &finalize, Some(&json!({ "csr": b64(&csr) })))
        .await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let done = json_of(&r);
    assert_eq!(done["status"], "valid");
    let again = alice
        .post(&w, &finalize, Some(&json!({ "csr": b64(&csr) })))
        .await;
    assert_eq!(json_of(&again)["detail"], "The order is \"valid\", and only a \"ready\" order is finalized (RFC 8555 section 7.4).");

    let cert_path = done["certificate"]
        .as_str()
        .unwrap()
        .trim_start_matches(BASE)
        .to_string();
    let c = alice.post(&w, &cert_path, None).await;
    assert_eq!(
        c.header("Content-Type"),
        Some("application/pem-certificate-chain")
    );
    let pem = String::from_utf8(c.body.clone()).unwrap();
    assert_eq!(
        pem.matches("BEGIN CERTIFICATE").count(),
        3,
        "leaf, Issuing CA, Intermediate"
    );
    let leaf = sts_pki::x509::read::Certificate::from_pem(&pem).unwrap();
    assert!(leaf.subject().contains("www.alicew.test"));

    // Renewal information, then revocation by the account, twice.
    let facts = sts_enroll::acme::jws::certificate_facts(&leaf.der).unwrap();
    let cert_id = sts_enroll::acme::jws::cert_id_of(
        facts.aki.as_ref().unwrap(),
        &facts.serial_hex,
    );
    let ri = w
        .acme
        .handle(&req(
            "GET",
            &format!("/enroll/acme/renewal-info/{}", cert_id),
            &[],
            Vec::new(),
        ))
        .await
        .unwrap();
    assert_eq!(ri.status, 200);
    assert_eq!(ri.header("Retry-After"), Some("21600"));
    let r = alice
        .post(
            &w,
            "/enroll/acme/revoke-cert",
            Some(&json!({ "certificate": b64(&leaf.der), "reason": 7 })),
        )
        .await;
    assert_eq!(json_of(&r)["detail"], "Reason code 7 is not one this server accepts from a subscriber. It accepts 0, 1, 3, 4, 5, 9 (RFC 5280 section 5.3.1).");
    let r = alice
        .post(
            &w,
            "/enroll/acme/revoke-cert",
            Some(&json!({ "certificate": b64(&leaf.der) })),
        )
        .await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let r = alice
        .post(
            &w,
            "/enroll/acme/revoke-cert",
            Some(&json!({ "certificate": b64(&leaf.der) })),
        )
        .await;
    assert_eq!(
        json_of(&r)["detail"],
        "That certificate is already revoked."
    );
    let held = w.core.enrolled_of(&Entry::new("person", "alicew"));
    assert_eq!(held[0]["status"], "revoked");

    // The envelope's refusals, in the snapshot's words.
    let r = w
        .acme
        .handle(&req(
            "POST",
            "/enroll/acme/new-order",
            &[("content-type", "application/json")],
            b"{}".to_vec(),
        ))
        .await
        .unwrap();
    assert_eq!((r.status, json_of(&r)["detail"].clone()), (415, json!("An ACME request body is application/jose+json (RFC 8555 section 6.2).")));
    let r = w
        .acme
        .handle(&req(
            "POST",
            "/enroll/acme/new-order",
            &[("content-type", "application/jose+json")],
            b"{nope".to_vec(),
        ))
        .await
        .unwrap();
    assert_eq!(json_of(&r)["detail"], "The request body is not a flattened JWS JSON object: the request body is not JSON.");
    let r = alice
        .post(&w, "/enroll/acme/new-order", Some(&json!({ "identifiers": [{ "type": "dns", "value": "a", "extra": 1 }] })))
        .await;
    assert_eq!(
        json_of(&r)["detail"],
        "The newOrder payload is not acceptable: the newOrder member \"identifiers.0\" is not acceptable: Unrecognized key: \"extra\"."
    );

    // A key change, and the old key refused after it.
    let mut new_key = Client::new();
    let account_url = alice.kid.clone().unwrap();
    let inner_header = json!({ "alg": "ES256", "jwk": new_key.jwk, "url": format!("{}/enroll/acme/key-change", BASE) });
    let inner_protected = b64(inner_header.to_string().as_bytes());
    let inner_payload =
        b64(json!({ "account": account_url, "oldKey": alice.jwk })
            .to_string()
            .as_bytes());
    let inner_sig = sts_crypto::jws::sign_input(
        "ES256",
        &new_key.key,
        format!("{}.{}", inner_protected, inner_payload).as_bytes(),
    )
    .unwrap();
    let inner = json!({ "protected": inner_protected, "payload": inner_payload, "signature": b64(&inner_sig) });
    let r = alice
        .post(&w, "/enroll/acme/key-change", Some(&inner))
        .await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let r = alice
        .post(&w, &account_url.trim_start_matches(BASE).to_string(), None)
        .await;
    assert_eq!(
        json_of(&r)["detail"],
        "The JWS signature does not verify with the account key."
    );
    new_key.kid = Some(account_url.clone());
    let r = new_key
        .post(&w, &account_url.trim_start_matches(BASE).to_string(), None)
        .await;
    assert_eq!(r.status, 200);
}

fn basic(user: &str, password: &str) -> String {
    format!(
        "Basic {}",
        STANDARD.encode(format!("{}:{}", user, password))
    )
}

#[tokio::test]
async fn est_end_to_end() {
    let w = world();
    let r = w
        .est
        .handle(&req("GET", "/.well-known/est/cacerts", &[], Vec::new()))
        .await
        .unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(
        r.header("Content-Type"),
        Some("application/pkcs7-mime; smime-type=certs-only")
    );
    let r = w
        .est
        .handle(&req(
            "GET",
            "/.well-known/est/nope/cacerts",
            &[],
            Vec::new(),
        ))
        .await
        .unwrap();
    assert_eq!(r.status, 404);
    assert!(String::from_utf8_lossy(&r.body)
        .starts_with("There is no EST label \"nope\" here."));
    let r = w
        .est
        .handle(&req("GET", "/.well-known/est/cacerts?x=1", &[], Vec::new()))
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&r.body),
        "No EST operation takes a query string: the query parameter \"(request)\" is not acceptable: Unrecognized key: \"x\".\n"
    );
    let r = w
        .est
        .handle(&req(
            "GET",
            "/.well-known/est/simpleenroll",
            &[],
            Vec::new(),
        ))
        .await
        .unwrap();
    assert_eq!((r.status, r.header("Allow")), (405, Some("POST")));
    let r = w
        .est
        .handle(&req("POST", "/.well-known/est/fullcmc", &[], Vec::new()))
        .await
        .unwrap();
    assert_eq!(r.status, 501);
    let r = w
        .est
        .handle(&req(
            "POST",
            "/.well-known/est/simpleenroll",
            &[("content-type", "application/pkcs10")],
            Vec::new(),
        ))
        .await
        .unwrap();
    assert_eq!(r.status, 401);
    assert_eq!(r.header("WWW-Authenticate"), Some("Basic realm=\"EST\""));
    let (csr, _) = csr_for("alicew", json!([]));
    let body = STANDARD.encode(&csr).into_bytes();
    let auth = basic("alicew", "x");
    let r = w
        .est
        .handle(&req(
            "POST",
            "/.well-known/est/simpleenroll",
            &[
                ("content-type", "application/pkcs10"),
                ("authorization", &auth),
            ],
            body.clone(),
        ))
        .await
        .unwrap();
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let r = w
        .est
        .handle(&req(
            "POST",
            "/.well-known/est/kdc/simpleenroll",
            &[
                ("content-type", "application/pkcs10"),
                ("authorization", &auth),
            ],
            body,
        ))
        .await
        .unwrap();
    assert_eq!(r.status, 403);
    assert!(String::from_utf8_lossy(&r.body).starts_with(
        "The \"kdc\" profile is never issued over an enrollment protocol."
    ));
    let (template, _) = csr_for("alicew", json!([]));
    let r = w
        .est
        .handle(&req(
            "POST",
            "/.well-known/est/serverkeygen",
            &[
                ("content-type", "application/pkcs10"),
                ("authorization", &auth),
            ],
            STANDARD.encode(&template).into_bytes(),
        ))
        .await
        .unwrap();
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert!(r
        .header("Content-Type")
        .unwrap()
        .starts_with("multipart/mixed; boundary=est-"));
    assert_eq!(w.core.enrolled_of(&Entry::new("person", "alicew")).len(), 2);
    let r = w
        .est
        .handle(&req(
            "GET",
            "/.well-known/est/nonce",
            &[("authorization", &auth)],
            Vec::new(),
        ))
        .await
        .unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(json_of(&r)["expiry"], 300);
    assert!(r
        .header("Set-Cookie")
        .unwrap()
        .starts_with("sts_est_nonce=est."));
    let r = w
        .est
        .handle(&req(
            "POST",
            "/.well-known/est/nonce",
            &[
                ("authorization", &auth),
                ("content-type", "application/est-attestation-freshness+json"),
            ],
            br#"{"len": 7}"#.to_vec(),
        ))
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&r.body),
        "The nonce request does not match draft-ietf-lamps-attestation-freshness section 3.2 at \"len\": Too small: expected number to be >=8.\n"
    );
}

/// A SCEP client's PKCSReq: a CSR with the challenge, enveloped to the RA,
/// in a SignedData signed by a self-signed certificate over the CSR's key.
fn pkcs_req(
    ra_pem: &str,
    challenge: &str,
    transaction: &str,
) -> (Vec<u8>, String, String) {
    use sts_enroll::est::codec::{oid, tlv};
    let (private, public) = sts_crypto::cms::generate_rsa(2048).unwrap();
    let spki = sts_pki::x509::keys::pem_to_der(&public).unwrap();
    let subject = tlv(
        0x30,
        &tlv(
            0x31,
            &tlv(0x30, &[oid("2.5.4.3"), tlv(0x0c, b"alicew")].concat()),
        ),
    );
    let attrs = tlv(
        0x30,
        &[
            oid("1.2.840.113549.1.9.7"),
            tlv(0x31, &tlv(0x0c, challenge.as_bytes())),
        ]
        .concat(),
    );
    let info = tlv(
        0x30,
        &[tlv(0x02, &[0]), subject, spki, tlv(0xa0, &attrs)].concat(),
    );
    let sig = sts_crypto::cms::sign_bytes("sha256", &info, &private).unwrap();
    let alg = tlv(0x30, &[oid("1.2.840.113549.1.1.11"), vec![5, 0]].concat());
    let mut bits = vec![0u8];
    bits.extend(sig);
    let csr = tlv(0x30, &[info, alg, tlv(0x03, &bits)].concat());
    let signer_pem = sts_pki::x509::issue::self_signed_cert_pem(&json!({ "publicPem": public, "privatePem": private, "subject": "CN=device" })).unwrap();
    let signer = cms::describe_certificate(
        &sts_pki::x509::keys::pem_to_der(&signer_pem).unwrap(),
    )
    .unwrap();
    let content =
        cms::envelope(&csr, ra_pem, "2.16.840.1.101.3.4.1.2").unwrap();
    let digest = sts_crypto::jws_alg::Hash::Sha256.digest(&content);
    let attr =
        |o: &str, v: Vec<u8>| tlv(0x30, &[oid(o), tlv(0x31, &v)].concat());
    let mut attrs = vec![
        attr("1.2.840.113549.1.9.3", oid("1.2.840.113549.1.7.1")),
        attr("1.2.840.113549.1.9.4", tlv(0x04, &digest)),
        attr("2.16.840.1.113733.1.9.2", tlv(0x13, b"19")),
        attr("2.16.840.1.113733.1.9.7", tlv(0x13, transaction.as_bytes())),
        attr("2.16.840.1.113733.1.9.5", tlv(0x04, &[9u8; 16])),
    ];
    attrs.sort();
    let set = tlv(0x31, &attrs.concat());
    let signature =
        sts_crypto::cms::sign_bytes("sha256", &set, &private).unwrap();
    let mut implicit = set.clone();
    implicit[0] = 0xa0;
    let sha256 = tlv(0x30, &oid("2.16.840.1.101.3.4.2.1"));
    let signer_info = tlv(
        0x30,
        &[
            tlv(0x02, &[1]),
            tlv(
                0x30,
                &[signer.issuer_raw.clone(), tlv(0x02, &signer.serial_raw)]
                    .concat(),
            ),
            sha256.clone(),
            implicit,
            tlv(0x30, &[oid("1.2.840.113549.1.1.1"), vec![5, 0]].concat()),
            tlv(0x04, &signature),
        ]
        .concat(),
    );
    let sd = tlv(
        0x30,
        &[
            tlv(0x02, &[1]),
            tlv(0x31, &sha256),
            tlv(
                0x30,
                &[oid("1.2.840.113549.1.7.1"), tlv(0xa0, &tlv(0x04, &content))]
                    .concat(),
            ),
            tlv(0xa0, &signer.der),
            tlv(0x31, &signer_info),
        ]
        .concat(),
    );
    (
        tlv(
            0x30,
            &[oid("1.2.840.113549.1.7.2"), tlv(0xa0, &sd)].concat(),
        ),
        signer_pem,
        private,
    )
}

#[tokio::test]
async fn scep_end_to_end() {
    let w = world();
    let r = w
        .scep
        .handle(&req(
            "GET",
            "/enroll/scep?operation=GetCACaps",
            &[],
            Vec::new(),
        ))
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&r.body),
        "POSTPKIOperation\nSHA-256\nSHA-512\nAES\nSCEPStandard\nRenewal\n"
    );
    let r = w
        .scep
        .handle(&req("GET", "/enroll/scep", &[], Vec::new()))
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&r.body),
        "SCEP: the query parameter \"operation\" is not acceptable: Invalid option: expected one of \"GetCACaps\"|\"GetCACert\"|\"GetNextCACert\"|\"PKIOperation\". The operations are GetCACaps, GetCACert, GetNextCACert, PKIOperation.\n"
    );
    let r = w
        .scep
        .handle(&req(
            "GET",
            "/enroll/scep/pkiclient.exe?operation=GetCACert",
            &[],
            Vec::new(),
        ))
        .await
        .unwrap();
    assert_eq!(r.status, 200);
    let ra = w.scep.ensure_ra().await.unwrap();
    let challenge = w
        .core
        .create_scep_challenge(
            &Entry::new("person", "alicew"),
            None,
            None,
            "test",
        )
        .unwrap();
    let (message, signer_pem, private) =
        pkcs_req(&ra.certificate_pem, &challenge.challenge, "tx-1");
    let r = w
        .scep
        .handle(&req(
            "POST",
            "/enroll/scep?operation=PKIOperation",
            &[("content-type", "application/x-pki-message")],
            message.clone(),
        ))
        .await
        .unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(r.code, None, "{:?}", r.code);
    let rep = cms::parse_pki_message(&r.body).unwrap();
    assert_eq!(rep.pki_status, "0");
    assert_eq!(rep.recipient_nonce.as_deref(), Some(&[9u8; 16][..]));
    assert!(cms::verify_signer(&rep).is_ok());
    let opened = cms::open_envelope(
        rep.content.as_deref().unwrap(),
        &signer_pem,
        &private,
    )
    .unwrap();
    assert!(!opened.content.is_empty());
    // The same request again is the stored result, no second redemption.
    let r = w
        .scep
        .handle(&req(
            "POST",
            "/enroll/scep?operation=PKIOperation",
            &[("content-type", "application/x-pki-message")],
            message,
        ))
        .await
        .unwrap();
    assert_eq!(cms::parse_pki_message(&r.body).unwrap().pki_status, "0");
    assert_eq!(w.core.enrolled_of(&Entry::new("person", "alicew")).len(), 1);
    // The completed transactionID under another key is badCertId
    // (`Scep.replayed()`, STS-SCEP-0039); a spent challenge in a new
    // transaction is badRequest, from the core's refusal.
    for (transaction, fail) in [("tx-1", "4"), ("tx-2", "2")] {
        let (again, _, _) =
            pkcs_req(&ra.certificate_pem, &challenge.challenge, transaction);
        let r = w
            .scep
            .handle(&req(
                "POST",
                "/enroll/scep?operation=PKIOperation",
                &[("content-type", "application/x-pki-message")],
                again,
            ))
            .await
            .unwrap();
        let rep = cms::parse_pki_message(&r.body).unwrap();
        assert_eq!(
            (rep.pki_status.as_str(), rep.fail_info.as_str()),
            ("2", fail)
        );
    }
}
