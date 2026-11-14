// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Every TLS listener this process holds, and what is applied to them all
//! (`tls_server.js`'s `applyAnchors()` and `reapplyPolicy()`,
//! `tls/listeners.js`' `start()`, `renewDue()` and `status()`).
//!
//! ONE PROCESS HOLDS THEM ALL. Node's front process owned every socket and
//! its request workers owned none, which is why the truststore doors and the
//! listener certificate were pinned to it and why a re-issued certificate
//! was reconciled there and pushed to the workers over IPC
//! (`reconcileTheListener()`). The Rust runtime has no request workers: the
//! process that reconciles is the process that serves, so a re-issue or a
//! truststore change is [`Listeners::reapply`] and nothing travels.
//!
//! A change of TLS policy or client authentication is applied IN PLACE, at
//! the next handshake, and only to a listener whose policy moved; only what
//! a socket is made of (its port, its certificate files) would rebind.
//! `reapply()` is the seam the settings' change notification (the `config`
//! slice) and the truststore doors (phase 4) call.

// Some of what is here is the seam a later phase calls (the settings'
// change notification, the truststore doors, /admin-api/listeners); the
// binary does not call it yet.
#![allow(dead_code)]

use std::sync::{Arc, Mutex, PoisonError, RwLock};

use sts_core::errors::codes;
use sts_core::log::tag;
use sts_core::settings::Settings;
use sts_pki::listener::ListenerCertificate;
use sts_tls::definitions::ListenerDefinition;
use sts_tls::policy::{policy_for, ListenerKind};
use sts_tls::truststore::Truststore;

use crate::certificates::ListenerMaterial;
use crate::listener::{build_context, Applied, ListenerStatus, TlsListener};

/// One registered listener: how to read its policy and what it presents.
struct Entry {
    listener: Arc<TlsListener>,
    kind: ListenerKind,
    /// `None`: the service certificate. `Some`: its own.
    own: Option<Vec<ListenerCertificate>>,
}

/// The process's TLS listeners.
pub struct Listeners {
    settings: Arc<Settings>,
    pub material: RwLock<ListenerMaterial>,
    pub truststore: Arc<Truststore>,
    entries: Mutex<Vec<Entry>>,
}

/// Whether a listener offers HTTP/2 (`http.http2`, or its own `http2`).
#[tracing::instrument(level = "debug", skip_all)]
pub fn http2_for(settings: &Settings, kind: &ListenerKind) -> bool {
    match sts_tls::policy::own_value(settings, kind, "http2") {
        Some(sts_tls::policy::Own::Bool(b)) => b,
        _ => settings.value_of("http.http2").as_bool(),
    }
}

impl Listeners {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(
        settings: Arc<Settings>,
        material: ListenerMaterial,
        truststore: Arc<Truststore>,
    ) -> Arc<Listeners> {
        Arc::new(Listeners {
            settings,
            material: RwLock::new(material),
            truststore,
            entries: Mutex::new(Vec::new()),
        })
    }

    fn certificates_for(
        &self,
        own: Option<&Vec<ListenerCertificate>>,
    ) -> Vec<ListenerCertificate> {
        match own {
            Some(c) => c.clone(),
            None => self
                .material
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .certificates
                .clone(),
        }
    }

    /// The context a listener of this kind gets now.
    #[tracing::instrument(level = "debug", skip(self, own))]
    pub fn context_for(
        &self,
        label: &str,
        kind: &ListenerKind,
        own: Option<&Vec<ListenerCertificate>>,
    ) -> Result<Applied, String> {
        let policy = policy_for(&self.settings, kind);
        let root = self
            .material
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .root_pem();
        let ca = self.truststore.ca_for(
            &policy.trust_anchors_file,
            policy.trust_issued,
            root.as_deref(),
        );
        build_context(
            label,
            &policy,
            &self.certificates_for(own),
            &ca,
            http2_for(&self.settings, kind),
        )
    }

    /// Registers a listener so every later re-application reaches it
    /// (`trustClientCertificatesOn()`).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn register(
        &self,
        listener: Arc<TlsListener>,
        kind: ListenerKind,
        own: Option<Vec<ListenerCertificate>>,
    ) {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Entry {
                listener,
                kind,
                own,
            });
    }

    /// `applyAnchors()` / `reapplyPolicy()`: every registered listener
    /// gets a context built now — the current certificate, truststore and
    /// policy. A context that does not build leaves the listener on the one
    /// it has (`STS-TLS-0011`). Answers how many were re-keyed.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn reapply(&self, only_moved: bool) -> usize {
        let entries =
            self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let mut n = 0;
        for e in entries.iter() {
            if only_moved
                && policy_for(&self.settings, &e.kind) == e.listener.policy()
            {
                continue;
            }
            match self.context_for(&e.listener.label, &e.kind, e.own.as_ref()) {
                Ok(applied) => {
                    e.listener.apply(applied);
                    n += 1;
                }
                Err(why) => tracing::error!(
                    "{}tls: the client truststore and policy could not be applied to {}, which keeps its \
                     previous context: {}",
                    tag(codes::STS_TLS_0011),
                    e.listener.label,
                    why
                ),
            }
        }
        n
    }

    /// `tls/listeners.js`' `renewDue()`: a custom listener's ISSUED
    /// certificate past two thirds of its life is re-issued and applied
    /// without closing the listener. The `tls.listener-renew` job's body.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn renew_due(&self) -> usize {
        let now = chrono::Utc::now();
        let mut entries =
            self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let mut renewed = 0;
        for e in entries.iter_mut() {
            let ListenerKind::Custom { id, .. } = &e.kind else {
                continue;
            };
            let Some(own) = &e.own else {
                continue;
            };
            let due = own.iter().any(|c| {
                c.provenance == sts_pki::listener::Provenance::Issued
                    && c.renewal_due(now)
            });
            if !due {
                continue;
            }
            let fresh = {
                let material = self
                    .material
                    .read()
                    .unwrap_or_else(PoisonError::into_inner);
                issue_for_hostnames(&material, own_hostnames(own))
            };
            match fresh {
                Ok(c) => {
                    e.own = Some(vec![c]);
                    match self.context_for(&e.listener.label, &e.kind, e.own.as_ref()) {
                        Ok(applied) => {
                            e.listener.apply(applied);
                            renewed += 1;
                        }
                        Err(why) => tracing::error!(
                            "{}tls: listener \"{}\"'s renewed certificate could not be applied: {}",
                            tag(codes::STS_TLS_0011),
                            id,
                            why
                        ),
                    }
                }
                Err(why) => tracing::warn!(
                    "{}tls: listener \"{}\"'s certificate could not be renewed: {}; it keeps the one it has.",
                    tag(codes::STS_TLS_0040),
                    id,
                    why
                ),
            }
        }
        renewed
    }

    /// Whether any custom listener is registered (the renew job's `off`).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn has_custom(&self) -> bool {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|e| matches!(e.kind, ListenerKind::Custom { .. }))
    }

    /// `status()`: every listener's state, for `/admin-api/listeners`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn status(&self) -> Vec<ListenerStatus> {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|e| {
                e.listener
                    .status
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone()
            })
            .collect()
    }
}

fn own_hostnames(own: &[ListenerCertificate]) -> Vec<String> {
    own.first()
        .and_then(|c| {
            sts_pki::x509::read::Certificate::from_pem(&c.cert_pem).ok()
        })
        .and_then(|c| sts_pki::x509::read::describe_certificate(&c).ok())
        .and_then(|d| {
            d.pointer("/subjectAltName")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|n| {
                            n.get("value")
                                .and_then(|v| v.as_str())
                                .map(str::to_string)
                        })
                        .collect()
                })
        })
        .unwrap_or_default()
}

/// A custom listener with no certificate file: a leaf for its hostnames.
/// Node's comes from the OWNING REALM's `realm-tls` Issuing CA
/// ("Realm Listener TLS Issuing CA", one slot per listener per node), which
/// is phase 6's with the realm branches; until then it is a leaf of the
/// process branch's TLS Issuing CA, which a client trusting the Root
/// verifies all the same.
#[tracing::instrument(level = "debug", skip_all)]
pub fn issue_for_hostnames(
    material: &ListenerMaterial,
    hostnames: Vec<String>,
) -> Result<ListenerCertificate, String> {
    if hostnames.is_empty() {
        return Err("it has no DNS name to issue one for".to_string());
    }
    let mut identity = material.identity.clone();
    identity.hostnames = hostnames;
    identity.ips = Vec::new();
    let boot = sts_pki::listener::bootstrap(&identity, "rsa")
        .map_err(|e| e.to_string())?;
    match &material.branch {
        Some(branch) => branch
            .certify(&boot, &identity, 365)
            .map_err(|e| e.to_string()),
        None => Ok(boot),
    }
}

/// A custom listener's certificate (`certificateFor()`): its files, read
/// whole, or one issued for its hostnames.
#[tracing::instrument(level = "debug", skip_all)]
pub fn certificate_for(
    material: &ListenerMaterial,
    one: &ListenerDefinition,
) -> Result<ListenerCertificate, String> {
    if !one.certificate_file.is_empty() {
        let cert = std::fs::read_to_string(&one.certificate_file)
            .map_err(|e| format!("{}: {}", one.certificate_file, e))?;
        let key = std::fs::read_to_string(&one.private_key_file)
            .map_err(|e| format!("{}: {}", one.private_key_file, e))?;
        return sts_pki::listener::supplied(
            &one.certificate_file,
            &cert,
            &one.private_key_file,
            &key,
        )
        .map_err(|p| p.message);
    }
    issue_for_hostnames(material, one.hostnames.clone())
}

/// WHERE AN APPLICATION'S URLS ARE BUILT (#472, `listener_map.js`'s
/// `advertisedBase()`), the settings' slot: the advertised listener's
/// `publicBaseUrl`, or empty for `main`, which the settings answer with
/// `global.publicBaseUrl`. Which application is on which listener is
/// `listeners.applications`, not ported yet (its routing is phase 4's), so
/// every application is on `main` — what a service with no mapping is.
pub struct AdvertisedListeners {
    pub definitions: Vec<ListenerDefinition>,
}

impl sts_core::settings::AdvertisedBase for AdvertisedListeners {
    fn advertised_base(&self, _surface: &str) -> String {
        String::new()
    }
}
