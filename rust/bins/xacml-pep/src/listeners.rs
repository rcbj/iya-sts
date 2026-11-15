// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! EVERY LISTENER THIS PEP HAS, AND THE ONES THE SERVICE DEFINES (#1760).
//!
//! rcbj (2026-11-14): "provide the ability to define an arbitrary # of
//! listeners (HTTP, HTTPS)" on the PEP's console page. So beside the four
//! the environment binds (`PEP_PORT`, `PEP_HTTPS_PORT`, `PEP_PROXY_PORT`,
//! `PEP_PROXY_HTTPS_PORT`), which are what lets this process reach the
//! service before it has pulled anything and stay exactly as they were, the
//! settings pull may carry `listeners`: definitions of further HTTP or
//! HTTPS listeners, each for the decision API or the reverse proxy.
//!
//! * **BOUND, REBOUND AND UNBOUND WHILE THE PROCESS RUNS.** After every
//!   pull [`ListenerSet::reconcile`] compares what is held with what was
//!   pulled: a new listener is bound, a removed one's accept loop is
//!   aborted (dropping the socket frees the port; connections already open
//!   finish), and one whose protocol, purpose, address or port changed is
//!   unbound and bound again. A failed pull keeps what is held; an older
//!   service's 404 is no definitions at all, so only the environment's four.
//! * **A REFUSED BIND REFUSES THAT LISTENER ONLY** (`STS-XPEP-0103`, logged
//!   once per reason): it is reported `failed` with a reason from a closed
//!   set, and the next reconcile tries again — a port another process held
//!   may be free by then.
//! * **AN HTTPS LISTENER'S KEY IS GENERATED HERE AND NEVER LEAVES.** The PEP
//!   makes the key, proves possession in a PKCS #10 request and sends it to
//!   `POST /xacml/pep/listener-certificate` over its mutual TLS; the answer
//!   is the certificate and its chain, which [`HttpsListener::install`]
//!   checks against the key whole before serving. A new key is made when the
//!   definition's names or `renew` change, or a third of the certificate's
//!   life is left. Until a certificate arrives the listener waits unbound,
//!   as the environment's HTTPS listener waits for its files
//!   (`STS-XPEP-0104` when the request fails).
//! * **A DEFINITION THAT DOES NOT READ IS LEFT OUT** (`STS-XPEP-0105`) and
//!   the others are bound: one listener does not change what another means.
//! * **WHAT EACH IS DOING GOES ON THE HEARTBEAT** ([`ListenerSet::report`]):
//!   the state and reason from closed sets — never the operating system's
//!   sentence, which goes to the log — and the certificate served.

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};

use chrono::{DateTime, Utc};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509NameBuilder, X509ReqBuilder};
use serde_json::{json, Value};
use sts_core::log::tag;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::listener::{bind_reason, peer_of, HttpsListener, Transport};

/// Builds the handler for one connection, given what is known about it.
pub type MakeService = Arc<
    dyn Fn(Transport) -> TowerToHyperService<axum::routing::Router>
        + Send
        + Sync,
>;

/// What a certificate request answers: the full chain in PEM, or whether
/// the PDP refused it (true) or could not be reached (false), and why.
pub type Certified = Result<String, (bool, String)>;

/// Asks the PDP for a defined listener's certificate: (listener id, CSR in
/// PEM). A function rather than the client so a test can answer it.
pub type Certify = Arc<
    dyn Fn(String, String) -> Pin<Box<dyn Future<Output = Certified> + Send>>
        + Send
        + Sync,
>;

/// The ids the environment's four are reported under; the service reserves
/// them, so a defined listener can never be mistaken for one.
pub const ENVIRONMENT_IDS: &[&str] =
    &["api-http", "api-https", "proxy-http", "proxy-https"];
/// The keys this PEP generates for a defined HTTPS listener.
pub const KEY_ALGS: &[&str] = &["ec-p256", "ec-p384", "rsa-2048", "rsa-3072"];
const MAX_LISTENERS: usize = 32;
const MAX_NAMES: usize = 16;

/// One listener the service defined, as this PEP reads it.
#[derive(Debug, Clone, PartialEq)]
pub struct Def {
    pub id: String,
    pub https: bool,
    pub proxy: bool,
    pub address: IpAddr,
    pub port: u16,
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub key_alg: String,
    pub renew: u64,
}

impl Def {
    /// What, when it changes, means the socket is bound again.
    fn socket(&self) -> (bool, bool, IpAddr, u16) {
        (self.https, self.proxy, self.address, self.port)
    }

    /// What, when it changes, means a new certificate is asked for.
    fn certificate_key(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.dns_names.join(","),
            self.ip_addresses.join(","),
            self.key_alg,
            self.renew
        )
    }
}

/// Reads the pull's `listeners` member, each definition again by the
/// service's own rules: the readable ones, and a sentence for each one left
/// out.
pub fn parse(said: &Value) -> (Vec<Def>, Vec<String>) {
    let mut out: Vec<Def> = Vec::new();
    let mut refused = Vec::new();
    let Some(list) = said.as_array() else {
        return (out, refused);
    };
    for (i, one) in list.iter().enumerate() {
        if out.len() >= MAX_LISTENERS {
            refused.push(format!("listener {} is past the {}", i + 1,
                                 MAX_LISTENERS));
            continue;
        }
        match parse_one(one) {
            Ok(def) => {
                let clash = out.iter().any(|o| {
                    o.id == def.id
                        || (o.port == def.port
                            && (o.address == def.address
                                || o.address.is_unspecified()
                                || def.address.is_unspecified()))
                });
                if clash {
                    refused.push(format!(
                        "listener {} repeats another's id or address and port",
                        def.id
                    ));
                } else {
                    out.push(def);
                }
            }
            Err(why) => refused.push(format!("listener {}: {}", i + 1, why)),
        }
    }
    (out, refused)
}

fn parse_one(one: &Value) -> Result<Def, String> {
    let id = one["id"].as_str().unwrap_or("");
    if id.is_empty()
        || id.len() > 64
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
        || ENVIRONMENT_IDS.contains(&id)
    {
        return Err("its id is not one a listener may have".into());
    }
    let https = match one["protocol"].as_str() {
        Some("https") => true,
        Some("http") => false,
        _ => return Err(format!("{} has no protocol http or https", id)),
    };
    let proxy = match one["purpose"].as_str() {
        Some("proxy") => true,
        Some("api") => false,
        _ => return Err(format!("{} has no purpose api or proxy", id)),
    };
    let address: IpAddr = one["address"]
        .as_str()
        .unwrap_or("0.0.0.0")
        .parse()
        .map_err(|_| format!("{}'s address is not an IP address", id))?;
    let port = one["port"]
        .as_u64()
        .filter(|p| (1..=65535).contains(p))
        .ok_or_else(|| format!("{}'s port is not 1 to 65535", id))?
        as u16;
    let names = |key: &str| -> Result<Vec<String>, String> {
        let list = one[key].as_array().cloned().unwrap_or_default();
        if list.len() > MAX_NAMES {
            return Err(format!("{} has more than {} {}", id, MAX_NAMES, key));
        }
        list.iter()
            .map(|v| {
                v.as_str()
                    .filter(|s| !s.is_empty() && s.len() <= 253)
                    .map(String::from)
                    .ok_or_else(|| format!("{} has a bad {}", id, key))
            })
            .collect()
    };
    let dns_names = names("dnsNames")?;
    let ip_addresses = names("ipAddresses")?;
    if ip_addresses.iter().any(|a| a.parse::<IpAddr>().is_err()) {
        return Err(format!("{} names an IP address that is not one", id));
    }
    let key_alg = one["keyAlg"].as_str().unwrap_or("").to_string();
    if https && !KEY_ALGS.contains(&key_alg.as_str()) {
        return Err(format!("{}'s key is not one of {}", id,
                           KEY_ALGS.join(", ")));
    }
    Ok(Def {
        id: id.to_string(),
        https,
        proxy,
        address,
        port,
        dns_names,
        ip_addresses,
        key_alg: if https { key_alg } else { String::new() },
        renew: one["renew"].as_u64().unwrap_or(0),
    })
}

/// Generates a defined HTTPS listener's key.
pub fn generate_key(alg: &str) -> Result<PKey<Private>, String> {
    let ec = |nid: Nid| -> Result<PKey<Private>, String> {
        let group = EcGroup::from_curve_name(nid).map_err(|e| e.to_string())?;
        let key = EcKey::generate(&group).map_err(|e| e.to_string())?;
        PKey::from_ec_key(key).map_err(|e| e.to_string())
    };
    let rsa = |bits: u32| -> Result<PKey<Private>, String> {
        let key = Rsa::generate(bits).map_err(|e| e.to_string())?;
        PKey::from_rsa(key).map_err(|e| e.to_string())
    };
    match alg {
        "ec-p256" => ec(Nid::X9_62_PRIME256V1),
        "ec-p384" => ec(Nid::SECP384R1),
        "rsa-2048" => rsa(2048),
        "rsa-3072" => rsa(3072),
        other => Err(format!("{} is not a key this PEP generates", other)),
    }
}

/// A PKCS #10 request over the key, its signature the proof of possession.
/// The subject is the PEP's name; the service names the certificate from
/// the definition and reads nothing else here.
pub fn request_for(key: &PKey<Private>, name: &str) -> Result<String, String> {
    let mut subject = X509NameBuilder::new().map_err(|e| e.to_string())?;
    subject
        .append_entry_by_nid(Nid::COMMONNAME, name)
        .map_err(|e| e.to_string())?;
    let subject = subject.build();
    let mut req = X509ReqBuilder::new().map_err(|e| e.to_string())?;
    req.set_subject_name(&subject).map_err(|e| e.to_string())?;
    req.set_pubkey(key).map_err(|e| e.to_string())?;
    req.sign(key, MessageDigest::sha256())
        .map_err(|e| e.to_string())?;
    let pem = req.build().to_pem().map_err(|e| e.to_string())?;
    String::from_utf8(pem).map_err(|e| e.to_string())
}

/// What is known about the certificate a defined listener holds.
#[derive(Clone)]
struct Held {
    key: String,
    not_before: Option<DateTime<Utc>>,
    not_after: Option<DateTime<Utc>>,
}

impl Held {
    /// A third of its life or less is left.
    fn due(&self, now: DateTime<Utc>) -> bool {
        match (self.not_before, self.not_after) {
            (Some(from), Some(to)) => {
                let life = (to - from).num_seconds().max(1);
                (to - now).num_seconds() * 3 <= life
            }
            _ => true,
        }
    }
}

/// One defined listener and what it is doing.
struct Entry {
    def: Def,
    task: Option<JoinHandle<()>>,
    https: Option<Arc<HttpsListener>>,
    held: Option<Held>,
    state: &'static str,
    reason: &'static str,
    logged: String,
}

impl Drop for Entry {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// The state of one of the environment's plain listeners.
#[derive(Default)]
pub struct PlainStatus {
    inner: Mutex<(&'static str, &'static str)>,
}

impl PlainStatus {
    pub fn set(&self, state: &'static str, reason: &'static str) {
        *self.inner.lock().unwrap_or_else(|e| e.into_inner()) =
            (state, reason);
    }

    fn get(&self) -> (&'static str, &'static str) {
        let held = *self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if held.0.is_empty() {
            ("waiting", "none")
        } else {
            held
        }
    }
}

/// One of the environment's four.
pub enum EnvKind {
    Plain(Arc<PlainStatus>),
    Tls(Arc<HttpsListener>),
    /// Not bound at all: the proxy off (`proxy-off`), or a plain-HTTP
    /// listener nobody turned on (`http-off`, the default since #1760).
    Off(&'static str),
    /// THE CRL-ONLY PLAIN LISTENER (`options::crl_listener`): `PEP_PORT`
    /// with `PEP_HTTP` off and `PEP_CRL_HTTP` on, serving `GET /crl/<name>`
    /// and nothing else. Reported with the purpose `crl` (2026-11-15), so
    /// the console labels it "CRL distribution" rather than the decision
    /// API it does not serve. An older service closes the purpose to its
    /// own set and reads `api`; the `crl-only` reason still says it there.
    Crl(Arc<PlainStatus>),
}

/// One of the two plain-HTTP environment listeners: bound and reported
/// by `status` when its switch is on, else `off` with `http-off` (#1760).
pub fn plain_kind(on: bool, status: Arc<PlainStatus>) -> EnvKind {
    if on {
        EnvKind::Plain(status)
    } else {
        EnvKind::Off("http-off")
    }
}

struct EnvListener {
    id: &'static str,
    https: bool,
    proxy: bool,
    port: u16,
    kind: EnvKind,
}

/// Every listener: the environment's, registered at start, and the defined
/// ones, reconciled after each pull.
pub struct ListenerSet {
    name: String,
    api: MakeService,
    proxy: Option<MakeService>,
    client_ca: Option<Vec<u8>>,
    certify: Certify,
    entries: Mutex<HashMap<String, Entry>>,
    order: Mutex<Vec<String>>,
    env: Mutex<Vec<EnvListener>>,
    /// One reconcile at a time.
    running: tokio::sync::Mutex<()>,
    logged_refusals: Mutex<String>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

impl ListenerSet {
    pub fn new(
        name: &str,
        api: MakeService,
        proxy: Option<MakeService>,
        client_ca: Option<Vec<u8>>,
        certify: Certify,
    ) -> ListenerSet {
        ListenerSet {
            name: name.to_string(),
            api,
            proxy,
            client_ca,
            certify,
            entries: Mutex::new(HashMap::new()),
            order: Mutex::new(Vec::new()),
            env: Mutex::new(Vec::new()),
            running: tokio::sync::Mutex::new(()),
            logged_refusals: Mutex::new(String::new()),
        }
    }

    /// Registers one of the environment's four, for the report.
    pub fn environment(&self, id: &'static str, port: u16, kind: EnvKind) {
        let https = id.ends_with("https");
        let proxy = id.starts_with("proxy");
        lock(&self.env).push(EnvListener { id, https, proxy, port, kind });
    }

    /// The pull's definitions, read and applied.
    pub async fn apply(&self, said: &Value) {
        let (defs, refused) = parse(said);
        let joined = refused.join("; ");
        {
            let mut last = lock(&self.logged_refusals);
            if !refused.is_empty() && *last != joined {
                tracing::warn!(
                    "{}xacml-pep: listener definitions left out: {}. The \
                     others are bound.",
                    tag("STS-XPEP-0105"),
                    joined
                );
            }
            *last = joined;
        }
        self.reconcile(defs).await;
    }

    /// Makes what runs match `defs`: see the module header.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn reconcile(&self, defs: Vec<Def>) {
        let _one = self.running.lock().await;
        {
            let mut entries = lock(&self.entries);
            let gone: Vec<String> = entries
                .iter()
                .filter(|(id, e)| {
                    !defs
                        .iter()
                        .any(|d| &d.id == *id && d.socket() == e.def.socket())
                })
                .map(|(id, _)| id.clone())
                .collect();
            for id in gone {
                if entries.remove(&id).is_some() {
                    tracing::info!(
                        "xacml-pep: listener {} is unbound: the service no \
                         longer defines it as it was.",
                        id
                    );
                }
            }
        }
        *lock(&self.order) = defs.iter().map(|d| d.id.clone()).collect();
        for def in defs {
            let held = lock(&self.entries).remove(&def.id);
            let entry = self.converge(def, held).await;
            lock(&self.entries).insert(entry.def.id.clone(), entry);
        }
    }

    async fn converge(&self, def: Def, held: Option<Entry>) -> Entry {
        let mut entry = held.unwrap_or_else(|| Entry {
            def: def.clone(),
            task: None,
            https: None,
            held: None,
            state: "waiting",
            reason: "none",
            logged: String::new(),
        });
        let changed_names =
            entry.def.certificate_key() != def.certificate_key();
        entry.def = def.clone();
        let make = if def.proxy {
            match &self.proxy {
                Some(make) => make.clone(),
                None => {
                    if let Some(task) = entry.task.take() {
                        task.abort();
                    }
                    entry.state = "off";
                    entry.reason = "proxy-off";
                    return entry;
                }
            }
        } else {
            self.api.clone()
        };
        if def.https {
            let https = entry
                .https
                .get_or_insert_with(|| {
                    Arc::new(HttpsListener::in_memory(
                        def.port,
                        if def.proxy {
                            None
                        } else {
                            self.client_ca.as_deref()
                        },
                        def.proxy,
                    ))
                })
                .clone();
            let due = match &entry.held {
                None => true,
                Some(h) => changed_names || h.key != def.certificate_key()
                    || h.due(Utc::now()),
            };
            if due {
                match self.obtain(&def, &https).await {
                    Ok(held) => {
                        entry.held = Some(held);
                    }
                    Err((reason, why)) => {
                        self.note(&mut entry, "STS-XPEP-0104", &why);
                        if https.current().is_none() {
                            entry.state = "waiting";
                            entry.reason = reason;
                            return entry;
                        }
                    }
                }
            }
        }
        let alive = entry.task.as_ref().is_some_and(|t| !t.is_finished());
        if !alive {
            match TcpListener::bind((def.address, def.port)).await {
                Ok(socket) => {
                    let https = entry.https.clone();
                    entry.task = Some(tokio::spawn(serve(
                        socket, https, make, def.proxy,
                    )));
                    tracing::info!(
                        "xacml-pep: listener {} ({}, {}) listens on {}:{}.",
                        def.id,
                        if def.https { "HTTPS" } else { "HTTP" },
                        if def.proxy { "reverse proxy" } else { "API" },
                        def.address,
                        def.port
                    );
                    entry.logged.clear();
                }
                Err(error) => {
                    entry.task = None;
                    entry.state = "failed";
                    entry.reason = bind_reason(&error);
                    self.note(
                        &mut entry,
                        "STS-XPEP-0103",
                        &format!(
                            "could not listen on {}:{}: {}",
                            def.address, def.port, error
                        ),
                    );
                    return entry;
                }
            }
        }
        entry.state = "listening";
        entry.reason = "none";
        entry
    }

    /// A problem with one listener, logged once per sentence.
    fn note(&self, entry: &mut Entry, code: &str, why: &str) {
        if entry.logged != why {
            tracing::warn!(
                "{}xacml-pep: listener {}: {}. It is tried again after the \
                 next pull.",
                tag(code),
                entry.def.id,
                why
            );
            entry.logged = why.to_string();
        }
    }

    /// A new key, its request, the certificate, installed.
    async fn obtain(
        &self,
        def: &Def,
        https: &HttpsListener,
    ) -> Result<Held, (&'static str, String)> {
        let key = generate_key(&def.key_alg)
            .map_err(|e| ("other", format!("no key was generated: {}", e)))?;
        let csr = request_for(&key, &self.name)
            .map_err(|e| ("other", format!("no request was made: {}", e)))?;
        let chain = (self.certify)(def.id.clone(), csr).await.map_err(
            |(refused, why)| {
                (
                    if refused {
                        "certificate-request-refused"
                    } else {
                        "no-certificate"
                    },
                    format!("the certificate request failed: {}", why),
                )
            },
        )?;
        let key_pem = key
            .private_key_to_pem_pkcs8()
            .map_err(|e| ("other", e.to_string()))?;
        let served = https.install(chain.as_bytes(), &key_pem).map_err(|e| {
            (
                "certificate-refused",
                format!("the certificate answered is not usable: {}", e),
            )
        })?;
        let time = |k: &str| {
            served[k]
                .as_str()
                .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
                .map(|t| t.with_timezone(&Utc))
        };
        tracing::info!(
            "xacml-pep: listener {} serves certificate {} ({}), issued by {}.",
            def.id,
            served["serialHex"],
            served["subjectAltName"],
            served["issuer"]
        );
        Ok(Held {
            key: def.certificate_key(),
            not_before: time("validFrom"),
            not_after: time("validTo"),
        })
    }

    /// `listeners` on the heartbeat: every listener, the environment's
    /// first, from the closed sets the service keeps.
    pub fn report(&self) -> Value {
        let mut out = Vec::new();
        for one in lock(&self.env).iter() {
            let (state, reason, certificate) = match &one.kind {
                EnvKind::Plain(status) => {
                    let (s, r) = status.get();
                    (s, r, None)
                }
                EnvKind::Tls(https) => https.state(),
                EnvKind::Off(reason) => ("off", *reason, None),
                EnvKind::Crl(status) => {
                    let (s, r) = status.get();
                    (s, r, None)
                }
            };
            let purpose = match (&one.kind, one.proxy) {
                (EnvKind::Crl(_), _) => "crl",
                (_, true) => "proxy",
                _ => "api",
            };
            out.push(json!({
                "id": one.id, "source": "environment",
                "protocol": if one.https { "https" } else { "http" },
                "purpose": purpose,
                "address": "0.0.0.0", "port": one.port,
                "state": state, "reason": reason, "renew": 0,
                "certificate": certificate
            }));
        }
        let entries = lock(&self.entries);
        for id in lock(&self.order).iter() {
            let Some(e) = entries.get(id) else {
                continue;
            };
            let certificate = e
                .https
                .as_ref()
                .and_then(|h| h.state().2)
                .unwrap_or(Value::Null);
            out.push(json!({
                "id": e.def.id, "source": "service",
                "protocol": if e.def.https { "https" } else { "http" },
                "purpose": if e.def.proxy { "proxy" } else { "api" },
                "address": e.def.address.to_string(), "port": e.def.port,
                "state": e.state, "reason": e.reason,
                "renew": if e.held.is_some() { e.def.renew } else { 0 },
                "certificate": certificate
            }));
        }
        json!({ "listeners": out })
    }

    /// The defined listeners held now, for a test.
    #[cfg(test)]
    pub fn states(&self) -> Vec<(String, &'static str, &'static str)> {
        let entries = lock(&self.entries);
        let mut out: Vec<_> = entries
            .values()
            .map(|e| (e.def.id.clone(), e.state, e.reason))
            .collect();
        out.sort();
        out
    }
}

/// One accept loop, plain or TLS, until its task is aborted.
async fn serve(
    socket: TcpListener,
    https: Option<Arc<HttpsListener>>,
    make: MakeService,
    proxy: bool,
) {
    loop {
        let Ok((stream, remote)) = socket.accept().await else {
            continue;
        };
        let make = make.clone();
        let https = https.clone();
        tokio::spawn(async move {
            let Some(https) = https else {
                let transport = Transport {
                    https: false,
                    peer: None,
                    remote: if proxy { Some(remote) } else { None },
                    crl_only: false,
                };
                let _ = Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), make(transport))
                    .await;
                return;
            };
            let Some(acceptor) = https.current() else {
                return;
            };
            let Ok(ssl) = openssl::ssl::Ssl::new(acceptor.context()) else {
                return;
            };
            let Ok(mut tls) = tokio_openssl::SslStream::new(ssl, stream) else {
                return;
            };
            if let Err(error) = Pin::new(&mut tls).accept().await {
                tracing::debug!("TLS handshake failed: {}", error);
                return;
            }
            let transport = Transport {
                https: true,
                peer: peer_of(tls.ssl()),
                remote: if proxy { Some(remote) } else { None },
                crl_only: false,
            };
            let _ = Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls), make(transport))
                .await;
        });
    }
}

/// The production [`Certify`]: `POST /xacml/pep/listener-certificate`.
pub fn certify_with(client: crate::pdp_client::PdpClient) -> Certify {
    Arc::new(move |id: String, csr: String| {
        let client = client.clone();
        Box::pin(async move {
            let answer = client
                .call(
                    reqwest::Method::POST,
                    "/xacml/pep/listener-certificate",
                    Some(crate::pdp_client::Body::Json(json!({
                        "listener": id, "csr": csr
                    }))),
                )
                .await;
            if let Some(error) = answer.error {
                return Err((false, error));
            }
            if answer.status != 200 {
                return Err((
                    true,
                    format!(
                        "the PDP answered {}{}",
                        answer.status,
                        answer
                            .error_description()
                            .map(|d| format!(": {}", d))
                            .unwrap_or_default()
                    ),
                ));
            }
            answer
                .json
                .as_ref()
                .and_then(|j| j["fullChainPem"].as_str())
                .map(String::from)
                .ok_or((true, "the answer carries no fullChainPem".into()))
        }) as Pin<Box<dyn Future<Output = Certified> + Send>>
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::{Asn1Integer, Asn1Time};
    use openssl::bn::BigNum;
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
    use openssl::x509::{X509Builder, X509Req, X509};
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn answering(text: &'static str) -> MakeService {
        Arc::new(move |_transport: Transport| {
            TowerToHyperService::new(
                axum::Router::new().fallback(move || async move { text }),
            )
        })
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn def(id: &str, https: bool, proxy: bool, port: u16) -> Def {
        Def {
            id: id.into(),
            https,
            proxy,
            address: "127.0.0.1".parse().unwrap(),
            port,
            dns_names: if https { vec!["localhost".into()] } else { vec![] },
            ip_addresses: vec![],
            key_alg: if https { "ec-p256".into() } else { String::new() },
            renew: 0,
        }
    }

    /// A test CA that signs whatever key a request carries, numbering
    /// each certificate, and counts the requests.
    fn authority() -> (Certify, X509, Arc<AtomicU32>) {
        let ca_key = generate_key("ec-p256").unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "test pep-tls CA").unwrap();
        let name = name.build();
        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(
            &Asn1Integer::from_bn(&BigNum::from_u32(1).unwrap()).unwrap(),
        )
        .unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        b.set_pubkey(&ca_key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        b.set_not_after(&Asn1Time::days_from_now(2).unwrap()).unwrap();
        b.append_extension(
            openssl::x509::extension::BasicConstraints::new()
                .critical()
                .ca()
                .build()
                .unwrap(),
        )
        .unwrap();
        b.append_extension(
            openssl::x509::extension::KeyUsage::new()
                .critical()
                .key_cert_sign()
                .build()
                .unwrap(),
        )
        .unwrap();
        b.sign(&ca_key, MessageDigest::sha256()).unwrap();
        let ca = b.build();
        let count = Arc::new(AtomicU32::new(0));
        let (signer, seen) = (ca.clone(), count.clone());
        let certify: Certify = Arc::new(move |_id: String, csr: String| {
            let (ca, ca_key) = (signer.clone(), ca_key.clone());
            let n = seen.fetch_add(1, Ordering::SeqCst) + 2;
            Box::pin(async move {
                let req = X509Req::from_pem(csr.as_bytes()).unwrap();
                let key = req.public_key().unwrap();
                assert!(req.verify(&key).unwrap(), "possession is proved");
                let mut b = X509Builder::new().unwrap();
                b.set_version(2).unwrap();
                b.set_serial_number(
                    &Asn1Integer::from_bn(&BigNum::from_u32(n).unwrap())
                        .unwrap(),
                )
                .unwrap();
                b.set_subject_name(req.subject_name()).unwrap();
                b.set_issuer_name(ca.subject_name()).unwrap();
                b.set_pubkey(&key).unwrap();
                b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
                    .unwrap();
                b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
                    .unwrap();
                let san = openssl::x509::extension::SubjectAlternativeName::new()
                    .dns("localhost")
                    .build(&b.x509v3_context(Some(&ca), None))
                    .unwrap();
                b.append_extension(san).unwrap();
                b.sign(&ca_key, MessageDigest::sha256()).unwrap();
                let mut chain = b.build().to_pem().unwrap();
                chain.extend_from_slice(&ca.to_pem().unwrap());
                Ok(String::from_utf8(chain).unwrap())
            }) as Pin<Box<dyn Future<Output = Certified> + Send>>
        });
        (certify, ca, count)
    }

    fn refusing() -> Certify {
        Arc::new(|_id: String, _csr: String| {
            Box::pin(async {
                Err((true, "the PDP answered 400".to_string()))
            }) as Pin<Box<dyn Future<Output = Certified> + Send>>
        })
    }

    async fn get(port: u16) -> Option<String> {
        let mut stream =
            tokio::net::TcpStream::connect(("127.0.0.1", port)).await.ok()?;
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .ok()?;
        let mut out = String::new();
        stream.read_to_string(&mut out).await.ok()?;
        Some(out)
    }

    async fn get_tls(port: u16, ca: &X509) -> Option<(String, String)> {
        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector.cert_store_mut().add_cert(ca.clone()).unwrap();
        connector.set_verify(SslVerifyMode::PEER);
        let connector = connector.build();
        let ssl = connector
            .configure()
            .unwrap()
            .into_ssl("localhost")
            .unwrap();
        let tcp =
            tokio::net::TcpStream::connect(("127.0.0.1", port)).await.ok()?;
        let mut tls = tokio_openssl::SslStream::new(ssl, tcp).ok()?;
        Pin::new(&mut tls).connect().await.ok()?;
        let serial = tls
            .ssl()
            .peer_certificate()?
            .serial_number()
            .to_bn()
            .ok()?
            .to_string();
        tls.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .ok()?;
        let mut out = String::new();
        let _ = tls.read_to_string(&mut out).await;
        Some((out, serial))
    }

    fn set(certify: Certify, proxy: bool) -> ListenerSet {
        ListenerSet::new(
            "pep-1",
            answering("api"),
            proxy.then(|| answering("proxy")),
            None,
            certify,
        )
    }

    #[test]
    fn a_definition_is_read_by_the_service_rules() {
        let (defs, refused) = parse(&json!([
            { "id": "a", "protocol": "http", "purpose": "api", "port": 9001 },
            { "id": "api-http", "protocol": "http", "purpose": "api",
              "port": 9002 },
            { "id": "b", "protocol": "ftp", "purpose": "api", "port": 9003 },
            { "id": "c", "protocol": "http", "purpose": "edge", "port": 9004 },
            { "id": "d", "protocol": "http", "purpose": "api", "port": 0 },
            { "id": "e", "protocol": "http", "purpose": "api",
              "address": "not-an-ip", "port": 9005 },
            { "id": "f", "protocol": "https", "purpose": "proxy",
              "port": 9006, "keyAlg": "dsa" },
            { "id": "a", "protocol": "http", "purpose": "api", "port": 9007 },
            { "id": "g", "protocol": "http", "purpose": "api", "port": 9001 },
            { "id": "h", "protocol": "https", "purpose": "proxy",
              "address": "::", "port": 9008, "keyAlg": "ec-p384",
              "dnsNames": ["app.example"], "renew": 3 }
        ]));
        let ids: Vec<&str> = defs.iter().map(|d| d.id.as_str()).collect();
        assert_eq!(ids, vec!["a", "h"], "{:?}", refused);
        assert_eq!(refused.len(), 8, "each bad one is left out and named");
        assert_eq!(defs[1].renew, 3);
        assert!(defs[1].address.is_unspecified());
        assert!(parse(&Value::Null).0.is_empty(), "absent is none");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_listener_is_bound_and_unbound_while_the_pep_runs() {
        let listeners = set(refusing(), true);
        let (api, proxy) = (free_port(), free_port());
        listeners
            .reconcile(vec![def("one", false, false, api),
                            def("two", false, true, proxy)])
            .await;
        assert!(get(api).await.unwrap().ends_with("api"));
        assert!(get(proxy).await.unwrap().ends_with("proxy"));
        let report = listeners.report();
        let rows = report["listeners"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["state"], "listening");
        assert_eq!(rows[0]["source"], "service");
        // Removed: the port is free at once.
        listeners.reconcile(vec![def("two", false, true, proxy)]).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(get(api).await.is_none(), "unbound");
        assert!(get(proxy).await.unwrap().ends_with("proxy"), "kept");
        // Moved to another port: unbound and bound again.
        let moved = free_port();
        listeners.reconcile(vec![def("two", false, true, moved)]).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(get(proxy).await.is_none());
        assert!(get(moved).await.unwrap().ends_with("proxy"));
        listeners.reconcile(vec![]).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(get(moved).await.is_none(), "none defined, none bound");
        assert!(listeners.report()["listeners"].as_array().unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_bind_is_reported_and_tried_again() {
        let listeners = set(refusing(), false);
        let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = held.local_addr().unwrap().port();
        listeners.reconcile(vec![def("busy", false, false, port)]).await;
        assert_eq!(listeners.states(),
                   vec![("busy".to_string(), "failed", "address-in-use")]);
        let report = listeners.report();
        assert_eq!(report["listeners"][0]["reason"], "address-in-use");
        drop(held);
        listeners.reconcile(vec![def("busy", false, false, port)]).await;
        assert_eq!(listeners.states(),
                   vec![("busy".to_string(), "listening", "none")]);
        assert!(get(port).await.unwrap().ends_with("api"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_proxy_listener_with_no_proxy_is_off() {
        let listeners = set(refusing(), false);
        let port = free_port();
        listeners.reconcile(vec![def("p", false, true, port)]).await;
        assert_eq!(listeners.states(),
                   vec![("p".to_string(), "off", "proxy-off")]);
        assert!(get(port).await.is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_https_listener_gets_its_certificate_over_its_own_key() {
        let (certify, ca, asked) = authority();
        let listeners = set(certify, false);
        let port = free_port();
        let mut one = def("tls", true, false, port);
        listeners.reconcile(vec![one.clone()]).await;
        assert_eq!(listeners.states(),
                   vec![("tls".to_string(), "listening", "none")]);
        let (body, first) = get_tls(port, &ca).await.unwrap();
        assert!(body.ends_with("api"));
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        let report = listeners.report();
        assert_eq!(report["listeners"][0]["certificate"]["subject"],
                   "CN=pep-1");
        // The same definition again asks for nothing.
        listeners.reconcile(vec![one.clone()]).await;
        assert_eq!(asked.load(Ordering::SeqCst), 1, "held, not asked again");
        // A renewal: a new key and a new certificate, the socket kept.
        one.renew = 1;
        listeners.reconcile(vec![one.clone()]).await;
        assert_eq!(asked.load(Ordering::SeqCst), 2);
        let (_, second) = get_tls(port, &ca).await.unwrap();
        assert_ne!(first, second, "the new certificate is served");
        assert_eq!(listeners.report()["listeners"][0]["renew"], 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_certificate_request_leaves_it_waiting_unbound() {
        let listeners = set(refusing(), false);
        let port = free_port();
        listeners.reconcile(vec![def("tls", true, false, port)]).await;
        assert_eq!(listeners.states(), vec![(
            "tls".to_string(), "waiting", "certificate-request-refused")]);
        assert!(get(port).await.is_none(), "not bound without a certificate");
    }

    #[test]
    fn the_environment_is_reported_first() {
        let listeners = set(refusing(), false);
        let status = Arc::new(PlainStatus::default());
        status.set("failed", "permission-denied");
        listeners.environment("api-http", 80, EnvKind::Plain(status));
        listeners.environment("proxy-http", 9180, EnvKind::Off("proxy-off"));
        let report = listeners.report();
        assert_eq!(report["listeners"][0]["id"], "api-http");
        assert_eq!(report["listeners"][0]["reason"], "permission-denied");
        assert_eq!(report["listeners"][1]["source"], "environment");
        assert_eq!(report["listeners"][1]["purpose"], "proxy");
        assert_eq!(report["listeners"][1]["state"], "off");
    }

    #[test]
    fn a_plain_listener_nobody_turned_on_is_reported_http_off() {
        let listeners = set(refusing(), false);
        let status = Arc::new(PlainStatus::default());
        listeners.environment("api-http", 9090,
                              plain_kind(false, status.clone()));
        listeners.environment("proxy-http", 9180,
                              plain_kind(false, status.clone()));
        let report = listeners.report();
        for i in 0..2 {
            assert_eq!(report["listeners"][i]["state"], "off");
            assert_eq!(report["listeners"][i]["reason"], "http-off");
            assert_eq!(report["listeners"][i]["protocol"], "http");
        }
        // Switched on, it is the listener's own status.
        let on = set(refusing(), false);
        status.set("listening", "none");
        on.environment("api-http", 9090, plain_kind(true, status));
        assert_eq!(on.report()["listeners"][0]["state"], "listening");
        assert_eq!(on.report()["listeners"][0]["reason"], "none");
        assert_eq!(on.report()["listeners"][0]["purpose"], "api");
    }

    #[test]
    fn the_crl_only_listener_is_reported_with_the_purpose_crl() {
        let listeners = set(refusing(), false);
        let status = Arc::new(PlainStatus::default());
        status.set("listening", "crl-only");
        listeners.environment("api-http", 9090, EnvKind::Crl(status.clone()));
        listeners.environment("api-https", 9443,
                              EnvKind::Plain(Arc::new(PlainStatus::default())));
        let report = listeners.report();
        assert_eq!(report["listeners"][0]["id"], "api-http");
        assert_eq!(report["listeners"][0]["purpose"], "crl");
        assert_eq!(report["listeners"][0]["state"], "listening");
        assert_eq!(report["listeners"][0]["reason"], "crl-only");
        assert_eq!(report["listeners"][0]["protocol"], "http");
        assert_eq!(report["listeners"][1]["purpose"], "api",
                   "only the CRL-only listener changes purpose");
        // A CRL listener that failed to bind is still a CRL listener.
        status.set("failed", "other");
        assert_eq!(listeners.report()["listeners"][0]["purpose"], "crl");
    }
}
