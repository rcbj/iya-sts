// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE SIMPLE CERTIFICATE ENROLMENT PROTOCOL (RFC 8894), per trust realm
//! (`scep/scep.ts`, `scep_ra.ts`): the eight routes (`/enroll/scep`,
//! `/pkiclient.exe`, `/:profile`, `/:profile/pkiclient.exe`, GET and POST),
//! the four operations, the five message types and the transaction store.
//! `scep/CLAUDE.md` is the design.
//!
//! * **THE AUTHORIZATION IS THE CHALLENGE**, and the principal the entry it
//!   names; it is spent by the first request that proves it, before the
//!   core rules on the certificate.
//! * **NOT REFUSED OVER PLAIN HTTP**: the request is signed and encrypted
//!   by design (RFC 8894 section 2.1); product answers SCEP only where
//!   `scep.allowInProduct` is on (`mode.answersScep()`).
//! * **TWO ANSWERS**: an HTTP error for a message that cannot be named; a
//!   CertRep FAILURE (HTTP 200, signed by the RA, a failInfo) for every
//!   refusal after that — the code on the mark and never in the reply.
//! * **THE RA CERTIFICATE** is an RSA leaf of the SCEP Issuing CA under the
//!   slot `scep-ra`, PINNED (its private key kept in the realm's row, as
//!   Node's `certify({ pinned: true })` keeps it), re-issued when missing,
//!   expiring within thirty days, of another size than `scep.raKeyAlgorithm`
//!   or no longer under the current Issuing CA; the one it replaces goes on
//!   that CA's list `superseded`.
//!
//! The transaction store is Node's `scep.transactions`. One transaction per
//! (realm, transactionID) runs at a time in this process; across nodes the
//! guard is the `scep.transaction` claim.

pub mod pki_message;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value as Json};
use sts_core::errors::{codes, ErrorCode};
use sts_core::realm;
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{
    expiry_field, RealmMap, Retain, StoreHandles, StoreSpec,
};
use sts_pki::authority::hierarchy::CertifySpec;

use self::pki_message::{CertRepSpec, Message};
use crate::core::issue::IssueSpec;
use crate::core::{normal_serial, now_ms, str_of, Core, Principal, Refusal};
use crate::http::{Reply, Req};
use crate::model;

const SLOT: &str = "scep-ra";
const RENEW_WITHIN_MS: f64 = 30.0 * 86_400_000.0;
const TRANSACTION_TTL_MS: f64 = 24.0 * 3600.0 * 1000.0;
const MAX_TRANSACTIONS: usize = 1000;
const TRANSACTION_CLAIM_TTL_MS: f64 = 2.0 * 60.0 * 1000.0;
const TRANSACTION_WAIT_MS: f64 = 20.0 * 1000.0;
const TRANSACTION_POLL_MS: u64 = 250;

/// `scep.transactions`.
#[derive(Clone)]
pub struct ScepStore {
    transactions: RealmMap<Json>,
}

impl ScepStore {
    /// Declares the store (before the store opens).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn declare(
        lifecycle: &Arc<RealmLifecycle>,
        handles: &Arc<StoreHandles>,
    ) -> ScepStore {
        let mut spec = StoreSpec::persisted("scep.transactions");
        spec.retain = Retain::Age;
        spec.expires_at = Some(expiry_field(Some("expiresAtMs"), 1.0));
        ScepStore {
            transactions: RealmMap::new(lifecycle, handles, spec),
        }
    }
}

/// The RA to use now.
#[derive(Debug, Clone)]
pub struct RaKeys {
    pub certificate_pem: String,
    pub private_key_pem: String,
}

/// A handler's answer: issued, or refused with a failInfo.
#[derive(Debug, Clone, Default)]
struct Outcome {
    ok: bool,
    code: Option<ErrorCode>,
    why: String,
    fail_info: String,
    identity: String,
    principal: String,
    target: String,
    profile: String,
    serial_hex: String,
    certificate_pem: String,
    crl_der: Option<Vec<u8>>,
    cipher: String,
    issued: bool,
    replay: bool,
    audited: bool,
    /// A 429 the throttle answered.
    http: Option<Refusal>,
}

fn failed(code: ErrorCode, why: impl Into<String>, fail: &str) -> Outcome {
    Outcome {
        ok: false,
        code: Some(code),
        why: why.into(),
        fail_info: if fail.is_empty() {
            pki_message::fail_info("badRequest")
        } else {
            fail.to_string()
        },
        ..Default::default()
    }
}

/// `failInfoForCore(code)`.
#[tracing::instrument(level = "trace")]
pub fn fail_info_for_core(code: ErrorCode) -> String {
    let name = match code.as_str() {
        c if c == codes::STS_ENROLL_0031.as_str()
            || c == codes::STS_ENROLL_0032.as_str() =>
        {
            "badAlg"
        }
        c if c == codes::STS_ENROLL_0033.as_str()
            || c == codes::STS_ENROLL_0018.as_str()
            || c == codes::STS_ENROLL_0019.as_str() =>
        {
            "badMessageCheck"
        }
        _ => "badRequest",
    };
    pki_message::fail_info(name)
}

fn from_core(r: &Refusal) -> Outcome {
    failed(r.code, r.sentence.clone(), &fail_info_for_core(r.code))
}

/// The SCEP server.
pub struct Scep {
    core: Arc<Core>,
    store: ScepStore,
    inflight: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    building: tokio::sync::Mutex<()>,
}

fn scep_error(
    status: u16,
    code: ErrorCode,
    text: &str,
    headers: &[(&str, String)],
) -> Reply {
    let mut reply = Reply::new(status);
    reply.mark(code);
    reply.set("Content-Type", "text/plain; charset=utf-8");
    reply.set("Cache-Control", "no-store");
    for (k, v) in headers {
        reply.set(k, v);
    }
    reply.body = format!("{}\n", text).into_bytes();
    reply
}

impl Scep {
    /// Builds the server.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(core: Arc<Core>, store: ScepStore) -> Arc<Scep> {
        Arc::new(Scep {
            core,
            store,
            inflight: Mutex::new(HashMap::new()),
            building: tokio::sync::Mutex::new(()),
        })
    }

    fn record(&self, detail: Json) {
        self.core.monitor().record("scep", &detail);
    }

    // -----------------------------------------------------------------
    // THE RA CERTIFICATE (`scep_ra.ts`).
    // -----------------------------------------------------------------

    fn wanted_bits(&self) -> u32 {
        let alg = self.core.setting_text("scep.raKeyAlgorithm");
        match alg.as_str() {
            "rsa-3072" => 3072,
            "rsa-4096" => 4096,
            _ => 2048,
        }
    }

    fn ra_record(&self) -> Option<Json> {
        self.core
            .authority()
            .raw_row_for(&realm::current_id())?
            .get("certs")?
            .get(format!("scep:{}", SLOT))
            .cloned()
    }

    fn staleness(&self, held: Option<&Json>) -> &'static str {
        let Some(held) = held.filter(|h| {
            !str_of(h, "certificatePem").is_empty()
                && !str_of(h, "privateKeyPem").is_empty()
        }) else {
            return "missing";
        };
        if crate::core::ms_of(str_of(held, "notAfter")) - now_ms()
            < RENEW_WITHIN_MS
        {
            return "expiring";
        }
        let bits = sts_pki::x509::read::Certificate::from_pem(str_of(
            held,
            "certificatePem",
        ))
        .ok()
        .and_then(|c| match sts_pki::x509::keys::describe_spki(&c.spki) {
            Some(sts_pki::x509::keys::KeyDesc::Rsa { bits }) => {
                Some(bits as u32)
            }
            _ => None,
        })
        .unwrap_or(0);
        if bits != self.wanted_bits() {
            return "algorithm";
        }
        let chain = self.core.ca_chain_of("scep");
        let first = held
            .get("chainPem")
            .and_then(|c| c.get(0))
            .and_then(Json::as_str)
            .unwrap_or("");
        if chain.is_none_or(|c| c.issuing_pem != first) {
            return "issuer";
        }
        ""
    }

    async fn issue_ra(
        &self,
        previous: Option<Json>,
        reason: &str,
    ) -> Result<Json, Refusal> {
        let bits = self.wanted_bits();
        let generated = tokio::task::spawn_blocking(move || {
            sts_crypto::pkcs7::generate_rsa(bits)
        })
        .await;
        let Ok(Ok((private_pem, public_pem))) = generated else {
            return Err(Refusal::new(codes::STS_SCEP_0006, 503, "The SCEP RA certificate could not be issued: no RSA key could be generated."));
        };
        let authority = self.core.authority().clone();
        let scope = realm::current_id();
        let spec = CertifySpec {
            slot: SLOT.into(),
            label: Some("SCEP RA".into()),
            common_name: Some("SCEP RA".into()),
            public_key_pem: public_pem.clone(),
            key_alg: format!("rsa-{}", bits),
            profile: Some("digital-signature".into()),
            key_usage: Some(vec![
                "digitalSignature".into(),
                "keyEncipherment".into(),
            ]),
            ..Default::default()
        };
        let made = {
            let (authority, scope) = (authority.clone(), scope.clone());
            tokio::task::spawn_blocking(move || {
                authority.certify(&scope, "scep", &spec)
            })
            .await
        };
        let mut record = match made {
            Ok(Ok(r)) => r,
            Ok(Err(r)) => {
                let why = r.errors.join(" ");
                tracing::error!(
                    "{}scep: the RA certificate for realm \"{}\" could not be issued: {}",
                    sts_core::log::tag(codes::STS_SCEP_0006.as_str()),
                    scope,
                    why
                );
                return Err(Refusal::new(
                    codes::STS_SCEP_0006,
                    503,
                    format!(
                        "The SCEP RA certificate could not be issued: {}",
                        why
                    ),
                ));
            }
            Err(e) => {
                return Err(Refusal::new(
                    codes::STS_SCEP_0006,
                    503,
                    format!(
                        "The SCEP RA certificate could not be issued: {}",
                        e
                    ),
                ))
            }
        };
        // PINNED: the private key kept in the row (`certify({ pinned })`).
        record["pinned"] = Json::Bool(true);
        record["privateKeyPem"] = Json::from(private_pem);
        record["publicKeyPem"] = Json::from(public_pem);
        let mut row =
            authority.raw_row_for(&scope).unwrap_or_else(|| json!({}));
        row["certs"][format!("scep:{}", SLOT)] = record.clone();
        authority.save_row(&scope, &row);
        if let Some(prev) = previous {
            let old = normal_serial(str_of(&prev, "serialHex"));
            if !old.is_empty()
                && old != normal_serial(str_of(&record, "serialHex"))
            {
                if let Err(e) = authority.revoke(
                    &scope,
                    "scep",
                    &old,
                    Some("superseded"),
                    str_of(&prev, "subject"),
                    &format!(
                        "the SCEP RA certificate was re-issued ({})",
                        reason
                    ),
                ) {
                    tracing::warn!(
                        "{}scep: the replaced RA certificate could not be marked superseded: {}",
                        sts_core::log::tag(codes::STS_SCEP_0006.as_str()),
                        e.sentence()
                    );
                }
            }
        }
        tracing::info!(
            "scep: an RSA-{} RA certificate was issued in realm \"{}\" ({}), serial {}, expires {}.",
            bits,
            scope,
            reason,
            str_of(&record, "serialHex"),
            str_of(&record, "notAfter")
        );
        Ok(record)
    }

    /// `ra.ensure(realm)`: the RA to use now, issued first when stale.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn ensure_ra(&self) -> Result<RaKeys, Refusal> {
        if self.core.ensure_authority("scep").is_none() {
            return Err(Refusal::new(
                codes::STS_SCEP_0005,
                503,
                "This realm has no certificate authority yet, so it has no SCEP Issuing CA and no RA certificate. Build the hierarchy on /admin/pki.",
            ));
        }
        let held = self.ra_record();
        let why = self.staleness(held.as_ref());
        if why.is_empty() {
            let h = held.unwrap_or_default();
            return Ok(RaKeys {
                certificate_pem: str_of(&h, "certificatePem").to_string(),
                private_key_pem: str_of(&h, "privateKeyPem").to_string(),
            });
        }
        let _one = self.building.lock().await;
        let now = self.ra_record();
        if self.staleness(now.as_ref()).is_empty() {
            let h = now.unwrap_or_default();
            return Ok(RaKeys {
                certificate_pem: str_of(&h, "certificatePem").to_string(),
                private_key_pem: str_of(&h, "privateKeyPem").to_string(),
            });
        }
        let made = self.issue_ra(now.or(held), why).await?;
        Ok(RaKeys {
            certificate_pem: str_of(&made, "certificatePem").to_string(),
            private_key_pem: str_of(&made, "privateKeyPem").to_string(),
        })
    }

    // -----------------------------------------------------------------
    // THE TRANSACTION STORE.
    // -----------------------------------------------------------------

    fn prune(&self) {
        let now = now_ms();
        let store = self.store.transactions.in_realm(&realm::current_id());
        for (key, value) in store.entries() {
            if value
                .get("expiresAtMs")
                .and_then(Json::as_f64)
                .is_none_or(|e| e <= now)
            {
                store.delete(&key);
            }
        }
        while store.len() > MAX_TRANSACTIONS {
            let Some(first) = store.keys().into_iter().next() else {
                break;
            };
            store.delete(&first);
        }
    }

    fn transaction_of(&self, id: &str) -> Option<Json> {
        self.prune();
        self.store
            .transactions
            .in_realm(&realm::current_id())
            .get(id)
    }

    fn remember(&self, id: &str, result: Json) {
        let now = now_ms();
        let mut row = result;
        row["transactionID"] = Json::from(id);
        row["createdAt"] = Json::from(crate::core::iso(now));
        row["expiresAtMs"] = Json::from(now + TRANSACTION_TTL_MS);
        self.store
            .transactions
            .in_realm(&realm::current_id())
            .set(id, row);
        self.prune();
    }

    // -----------------------------------------------------------------
    // THE MESSAGE TYPES.
    // -----------------------------------------------------------------

    fn spki_sha256(pem: &str) -> String {
        sts_pki::x509::keys::pem_to_der(pem)
            .map(|d| {
                sts_pki::der::hex(&sts_crypto::jws_alg::Hash::Sha256.digest(&d))
            })
            .unwrap_or_default()
    }

    /// `readRequest(message, raKeys)`: the CSR, the cipher, the CSR's hash.
    fn read_request(
        &self,
        message: &Message,
        ra: &RaKeys,
    ) -> Result<(crate::core::csr::Csr, String, String), Box<Outcome>> {
        let opened = pki_message::open_envelope(
            message.content.as_deref().unwrap_or(&[]),
            &ra.certificate_pem,
            &ra.private_key_pem,
        )
        .map_err(|r| Box::new(failed(r.code, r.why, &r.fail_info)))?;
        let csr = self.core.parse_csr(&opened.content, false).map_err(|r| {
            let mut o = from_core(&r);
            o.cipher = opened.cipher.clone();
            Box::new(o)
        })?;
        if csr.key_kind != "rsa" {
            let mut o = failed(
                codes::STS_SCEP_0033,
                format!(
                    "The request carries a {} key. SCEP encrypts its reply to the requester with RSA key transport, so only an RSA key can be enrolled over SCEP; use ACME or EST for an ECDSA, EdDSA or post-quantum key.",
                    csr.key_alg
                ),
                &pki_message::fail_info("badAlg"),
            );
            o.cipher = opened.cipher;
            return Err(Box::new(o));
        }
        let hash = sts_pki::der::hex(
            &sts_crypto::jws_alg::Hash::Sha256.digest(&opened.content),
        );
        Ok((csr, opened.cipher, hash))
    }

    fn replayed(&self, message: &Message, csr_sha256: &str) -> Option<Outcome> {
        let held = self.transaction_of(&message.transaction_id)?;
        let signer = message
            .signer
            .as_ref()
            .map(|s| s.spki_sha256.clone())
            .unwrap_or_default();
        if str_of(&held, "signerKey") != signer {
            return Some(failed(codes::STS_SCEP_0039, "That transactionID completed for a request signed with a different key.", &pki_message::fail_info("badCertId")));
        }
        if str_of(&held, "csrSha256") != csr_sha256 {
            tracing::info!(
                "scep: transactionID {} completed earlier for another request signed with the same key; this one is a new transaction.",
                message.transaction_id.chars().take(80).collect::<String>()
            );
            return None;
        }
        Some(Outcome {
            ok: true,
            replay: true,
            certificate_pem: str_of(&held, "certificatePem").to_string(),
            profile: str_of(&held, "profile").to_string(),
            target: str_of(&held, "target").to_string(),
            principal: str_of(&held, "principal").to_string(),
            serial_hex: str_of(&held, "serialHex").to_string(),
            ..Default::default()
        })
    }

    async fn pkcs_req(
        &self,
        req: &Req,
        message: &Message,
        ra: &RaKeys,
        url_profile: &str,
    ) -> Outcome {
        let (csr, cipher, csr_sha256) = match self.read_request(message, ra) {
            Ok(r) => r,
            Err(o) => return *o,
        };
        let signer = message.signer.clone().unwrap_or_else(|| {
            pki_message::describe_certificate(&[])
                .unwrap_or_else(empty_described)
        });
        let same_key =
            Scep::spki_sha256(&csr.public_key_pem) == signer.spki_sha256;
        if same_key
            && !signer.self_issued
            && self
                .core
                .authenticate_presented_certificate(&signer.pem, "scep", false)
                .is_ok()
        {
            return self.renewal_req(req, message, ra, url_profile).await;
        }
        if !same_key {
            if self
                .core
                .authenticate_presented_certificate(&signer.pem, "scep", false)
                .is_ok()
            {
                return self.renewal_req(req, message, ra, url_profile).await;
            }
            return failed(
                codes::STS_SCEP_0034,
                "The request is signed by a certificate whose key is not the key in the PKCS#10 request. RFC 8894 section 2.3 has a PKCSReq signed by a self-signed certificate for the requested key.",
                &pki_message::fail_info("badMessageCheck"),
            );
        }
        if let Some(mut retry) = self.replayed(message, &csr_sha256) {
            retry.cipher = cipher;
            return retry;
        }
        let password = csr.challenge_password.clone();
        if password.is_empty() {
            return failed(
                codes::STS_SCEP_0035,
                "The request carries no challengePassword attribute. A SCEP enrollment in this service is authorized by a single-use challenge issued for one entry and one profile.",
                "",
            );
        }
        let identity: String = password[..password.rfind('.').unwrap_or(0)]
            .chars()
            .take(400)
            .collect();
        if let Some(blocked) =
            self.core.throttled("scep", &req.address, &identity)
        {
            return Outcome {
                http: Some(blocked),
                identity,
                ..Default::default()
            };
        }
        let peek = match self.core.redeem_scep_challenge(&password, true) {
            Ok(p) => p,
            Err(r) => {
                let mut o = from_core(&r);
                o.identity = identity;
                return o;
            }
        };
        let entry_uri = peek.entry.uri();
        if !url_profile.is_empty() && url_profile != peek.profile {
            let mut o = failed(
                codes::STS_SCEP_0036,
                format!("The URL names the \"{}\" profile and the challenge was issued for \"{}\".", url_profile, peek.profile),
                "",
            );
            o.identity = identity;
            o.profile = peek.profile;
            o.principal = entry_uri;
            return o;
        }
        let spent = match self.core.redeem_scep_challenge_once(&password).await
        {
            Ok(s) => s,
            Err(r) => {
                let mut o = from_core(&r);
                o.identity = identity;
                return o;
            }
        };
        let principal = Principal {
            kind: spent.entry.kind.clone(),
            id: spent.entry.id.clone(),
            admin: false,
            has_entry: true,
            via: "scep".into(),
            realm: realm::current_id(),
            ..Default::default()
        };
        let extra = |mut o: Outcome, audited: bool| -> Outcome {
            o.identity = identity.clone();
            o.profile = spent.profile.clone();
            o.principal = entry_uri.clone();
            o.audited = audited;
            o
        };
        let target = match self.core.target_from_request(
            &csr.requested,
            &csr.common_name,
            Some(&principal),
        ) {
            Ok(t) => t.target,
            Err(r) => return extra(from_core(&r), false),
        };
        let issued = self
            .core
            .issue(&IssueSpec {
                family: "scep".into(),
                profile: spent.profile.clone(),
                principal: Some(principal),
                target: Some(target),
                public_key_pem: csr.public_key_pem.clone(),
                requested: csr.requested.clone(),
                key_source: "client".into(),
                key_alg: csr.key_alg.clone(),
                via: "scep".into(),
                ..Default::default()
            })
            .await;
        let issued = match issued {
            Ok(i) => i,
            Err(r) => return extra(from_core(&r), true),
        };
        let done = json!({
            "certificatePem": issued.record["certificatePem"], "profile": spent.profile,
            "target": issued.target.uri(), "principal": entry_uri,
            "serialHex": issued.record["serialHex"],
        });
        let mut row = json!({ "messageType": "PKCSReq", "signerKey": signer.spki_sha256, "csrSha256": csr_sha256 });
        merge(&mut row, &done);
        self.remember(&message.transaction_id, row);
        Outcome {
            ok: true,
            issued: true,
            cipher,
            identity,
            certificate_pem: str_of(&done, "certificatePem").to_string(),
            profile: spent.profile,
            target: issued.target.uri(),
            principal: entry_uri,
            serial_hex: str_of(&done, "serialHex").to_string(),
            ..Default::default()
        }
    }

    // The refusal is boxed: an Outcome is a whole answer, and a `Result`
    // carrying one inline would be three hundred bytes on every success.
    fn signer_entry(
        &self,
        message: &Message,
    ) -> Result<Principal, Box<Outcome>> {
        let signer = message.signer.clone().unwrap_or_else(empty_described);
        self.core.authenticate_presented_certificate(&signer.pem, "scep", false).map_err(|r| {
            let mut o = failed(
                codes::STS_SCEP_0040,
                format!("The message is not signed by a certificate this realm issued to an entry that still holds it: {}", r.sentence),
                &pki_message::fail_info("badMessageCheck"),
            );
            o.identity = normal_serial(&signer.serial_hex);
            Box::new(o)
        })
    }

    fn renewal_req<'a>(
        &'a self,
        req: &'a Req,
        message: &'a Message,
        ra: &'a RaKeys,
        url_profile: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Outcome> + Send + 'a>>
    {
        Box::pin(async move {
            let principal = match self.signer_entry(message) {
                Ok(p) => p,
                Err(o) => return *o,
            };
            let entry_uri = principal.entry().uri();
            let identity =
                principal.certificate_serial.clone().unwrap_or_default();
            if let Some(blocked) =
                self.core.throttled("scep", &req.address, &identity)
            {
                return Outcome {
                    http: Some(blocked),
                    identity,
                    ..Default::default()
                };
            }
            let (csr, cipher, csr_sha256) = match self.read_request(message, ra)
            {
                Ok(r) => r,
                Err(mut o) => {
                    o.identity = identity;
                    o.principal = entry_uri;
                    return *o;
                }
            };
            if let Some(mut retry) = self.replayed(message, &csr_sha256) {
                retry.cipher = cipher;
                return retry;
            }
            let renewed =
                self.core.enrolled_of(&principal.entry()).into_iter().find(
                    |one| normal_serial(str_of(one, "serialHex")) == identity,
                );
            let profile = renewed
                .as_ref()
                .map(|r| str_of(r, "profile").to_string())
                .unwrap_or_default();
            let extra = |mut o: Outcome, audited: bool| -> Outcome {
                o.identity = identity.clone();
                o.profile = profile.clone();
                o.principal = entry_uri.clone();
                o.audited = audited;
                o
            };
            if !url_profile.is_empty() && url_profile != profile {
                return extra(
                    failed(
                        codes::STS_SCEP_0036,
                        format!("The URL names the \"{}\" profile and the certificate being renewed is \"{}\".", url_profile, profile),
                        "",
                    ),
                    false,
                );
            }
            let target = match self.core.target_from_request(
                &csr.requested,
                &csr.common_name,
                Some(&principal),
            ) {
                Ok(t) => t.target,
                Err(r) => return extra(from_core(&r), false),
            };
            let issued = self
                .core
                .issue(&IssueSpec {
                    family: "scep".into(),
                    profile: profile.clone(),
                    principal: Some(principal.clone()),
                    target: Some(target),
                    public_key_pem: csr.public_key_pem.clone(),
                    requested: csr.requested.clone(),
                    key_source: "client".into(),
                    key_alg: csr.key_alg.clone(),
                    via: "scep".into(),
                    replaces: identity.clone(),
                    ..Default::default()
                })
                .await;
            let issued = match issued {
                Ok(i) => i,
                Err(r) => return extra(from_core(&r), true),
            };
            let signer = message
                .signer
                .as_ref()
                .map(|s| s.spki_sha256.clone())
                .unwrap_or_default();
            let mut row = json!({ "messageType": "RenewalReq", "signerKey": signer, "csrSha256": csr_sha256 });
            merge(
                &mut row,
                &json!({ "certificatePem": issued.record["certificatePem"], "profile": profile,
                         "target": issued.target.uri(), "principal": entry_uri,
                         "serialHex": issued.record["serialHex"] }),
            );
            self.remember(&message.transaction_id, row);
            Outcome {
                ok: true,
                issued: true,
                cipher,
                certificate_pem: str_of(&issued.record, "certificatePem")
                    .to_string(),
                profile,
                target: issued.target.uri(),
                principal: entry_uri,
                serial_hex: str_of(&issued.record, "serialHex").to_string(),
                identity,
                ..Default::default()
            }
        })
    }

    fn cert_poll(&self, message: &Message, ra: &RaKeys) -> Outcome {
        let opened = match pki_message::open_envelope(
            message.content.as_deref().unwrap_or(&[]),
            &ra.certificate_pem,
            &ra.private_key_pem,
        ) {
            Ok(o) => o,
            Err(r) => return failed(r.code, r.why, &r.fail_info),
        };
        if !pki_message::read_issuer_and_subject(&opened.content) {
            return failed(codes::STS_SCEP_0032, "A CertPoll envelope holds an IssuerAndSubject (RFC 8894 section 3.3.3).", "");
        }
        let Some(held) = self.transaction_of(&message.transaction_id) else {
            let mut o = failed(
                codes::STS_SCEP_0038,
                "This realm holds no result for that transactionID. Nothing here is PENDING: a request is issued or refused when it is made.",
                &pki_message::fail_info("badCertId"),
            );
            o.identity = message.transaction_id.clone();
            return o;
        };
        let signer = message
            .signer
            .as_ref()
            .map(|s| s.spki_sha256.clone())
            .unwrap_or_default();
        if str_of(&held, "signerKey") != signer {
            let mut o = failed(codes::STS_SCEP_0039, "That transaction was completed for a request signed with a different key.", &pki_message::fail_info("badCertId"));
            o.identity = message.transaction_id.clone();
            return o;
        }
        Outcome {
            ok: true,
            certificate_pem: str_of(&held, "certificatePem").to_string(),
            cipher: opened.cipher,
            profile: str_of(&held, "profile").to_string(),
            target: str_of(&held, "target").to_string(),
            principal: str_of(&held, "principal").to_string(),
            serial_hex: str_of(&held, "serialHex").to_string(),
            identity: message.transaction_id.clone(),
            ..Default::default()
        }
    }

    fn get_cert(&self, message: &Message, ra: &RaKeys) -> Outcome {
        let principal = match self.signer_entry(message) {
            Ok(p) => p,
            Err(o) => return *o,
        };
        let opened = match pki_message::open_envelope(
            message.content.as_deref().unwrap_or(&[]),
            &ra.certificate_pem,
            &ra.private_key_pem,
        ) {
            Ok(o) => o,
            Err(r) => return failed(r.code, r.why, &r.fail_info),
        };
        let Some((_, serial)) =
            pki_message::read_issuer_and_serial(&opened.content)
        else {
            return failed(codes::STS_SCEP_0032, "A GetCert envelope holds an IssuerAndSerialNumber (RFC 8894 section 3.3.4).", "");
        };
        let entry_uri = principal.entry().uri();
        let identity = principal.certificate_serial.clone().unwrap_or_default();
        let hit =
            self.core
                .enrolled_of(&principal.entry())
                .into_iter()
                .find(|one| {
                    normal_serial(str_of(one, "serialHex"))
                        == normal_serial(&serial)
                });
        let Some(hit) = hit else {
            let mut o = failed(
                codes::STS_SCEP_0041,
                format!(
                    "The {} holds no certificate with that serial.",
                    entry_uri
                ),
                &pki_message::fail_info("badCertId"),
            );
            o.principal = entry_uri;
            o.identity = identity;
            return o;
        };
        Outcome {
            ok: true,
            certificate_pem: str_of(&hit, "certificatePem").to_string(),
            cipher: opened.cipher,
            profile: str_of(&hit, "profile").to_string(),
            target: entry_uri.clone(),
            principal: entry_uri,
            serial_hex: str_of(&hit, "serialHex").to_string(),
            identity,
            ..Default::default()
        }
    }

    fn get_crl(&self, message: &Message, ra: &RaKeys) -> Outcome {
        let principal = match self.signer_entry(message) {
            Ok(p) => p,
            Err(o) => return *o,
        };
        let opened = match pki_message::open_envelope(
            message.content.as_deref().unwrap_or(&[]),
            &ra.certificate_pem,
            &ra.private_key_pem,
        ) {
            Ok(o) => o,
            Err(r) => return failed(r.code, r.why, &r.fail_info),
        };
        let Some((issuer, _)) =
            pki_message::read_issuer_and_serial(&opened.content)
        else {
            return failed(codes::STS_SCEP_0032, "A GetCRL envelope holds an IssuerAndSerialNumber (RFC 8894 section 3.3.4).", "");
        };
        let entry_uri = principal.entry().uri();
        let identity = principal.certificate_serial.clone().unwrap_or_default();
        let issuing = self.core.ca_chain_of("scep").and_then(|c| {
            pki_message::describe_certificate(&crate::est::codec::pem_to_der(
                &c.issuing_pem,
            ))
        });
        if issuing.is_none_or(|i| i.subject_raw != issuer) {
            let mut o = failed(
                codes::STS_SCEP_0042,
                "GetCRL answers for this realm's SCEP Issuing CA, and the request names another issuer.",
                &pki_message::fail_info("badCertId"),
            );
            o.principal = entry_uri;
            o.identity = identity;
            return o;
        }
        match self
            .core
            .authority()
            .build_crl(&realm::current_id(), "scep")
        {
            Ok(crl) => Outcome {
                ok: true,
                crl_der: Some(crl.der),
                cipher: opened.cipher,
                principal: entry_uri,
                identity,
                ..Default::default()
            },
            Err(e) => {
                tracing::error!(
                    "{}scep: the SCEP Issuing CA's CRL could not be built: {}",
                    sts_core::log::tag(codes::STS_SCEP_0043.as_str()),
                    e.sentence()
                );
                let mut o = failed(
                    codes::STS_SCEP_0043,
                    "The SCEP Issuing CA's CRL could not be built.",
                    "",
                );
                o.principal = entry_uri;
                o
            }
        }
    }

    async fn answer_message(
        &self,
        req: &Req,
        message: &Message,
        ra: &RaKeys,
        url_profile: &str,
    ) -> Outcome {
        if let Err(r) = pki_message::verify_signer(message) {
            return failed(r.code, r.why, &r.fail_info);
        }
        let key_type = message
            .signer
            .as_ref()
            .map(|s| s.key_type.clone())
            .unwrap_or_default();
        if key_type != "rsa" {
            return failed(
                codes::STS_SCEP_0025,
                format!(
                    "The message is signed with a {} key. A CertRep is encrypted to the signer's certificate with RSA key transport, so SCEP in this service takes an RSA requester key only.",
                    key_type
                ),
                &pki_message::fail_info("badAlg"),
            );
        }
        let Some(kind) = message
            .message_type
            .filter(|t| [17, 19, 20, 21, 22].contains(t))
        else {
            return failed(
                codes::STS_SCEP_0031,
                format!(
                    "The messageType \"{}\" is not one this server answers. It answers PKCSReq (19), RenewalReq (17), CertPoll (20), GetCert (21) and GetCRL (22).",
                    message.message_type_text
                ),
                "",
            );
        };
        let key = format!("{}|{}", realm::current_id(), message.transaction_id);
        let lock = {
            let mut held =
                self.inflight.lock().unwrap_or_else(PoisonError::into_inner);
            held.entry(key.clone())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        let _turn = lock.lock().await;
        let began = now_ms();
        let claim = loop {
            match self
                .core
                .claims()
                .claim("scep.transaction", &key, "", TRANSACTION_CLAIM_TTL_MS)
                .await
            {
                Ok(c) => break Ok(c),
                Err(sts_cluster::scheduler::ClaimRefused::Held)
                    if now_ms() - began < TRANSACTION_WAIT_MS =>
                {
                    tokio::time::sleep(std::time::Duration::from_millis(
                        TRANSACTION_POLL_MS,
                    ))
                    .await;
                }
                Err(e) => break Err(e),
            }
        };
        let claim = match claim {
            Ok(c) => c,
            Err(sts_cluster::scheduler::ClaimRefused::Held) => {
                tracing::warn!(
                    "{}scep: a transaction was still being answered by another request after {}ms; this copy of it is refused.",
                    sts_core::log::tag(codes::STS_SCEP_0064.as_str()),
                    TRANSACTION_WAIT_MS
                );
                return failed(codes::STS_SCEP_0064, "Another request with this transactionID is still being answered. Retry, or poll with CertPoll.", "");
            }
            Err(e) => {
                tracing::error!("{}scep: a transaction could not be claimed ({:?}); it is refused.", sts_core::log::tag(codes::STS_SCEP_0065.as_str()), e);
                return failed(codes::STS_SCEP_0065, "This server could not check whether the transaction is already being answered.", "");
            }
        };
        let out = match kind {
            19 => self.pkcs_req(req, message, ra, url_profile).await,
            17 => self.renewal_req(req, message, ra, url_profile).await,
            20 => self.cert_poll(message, ra),
            21 => self.get_cert(message, ra),
            _ => self.get_crl(message, ra),
        };
        self.core.claims().release(&claim.handle).await;
        let mut held =
            self.inflight.lock().unwrap_or_else(PoisonError::into_inner);
        if held.get(&key).is_some_and(|l| Arc::strong_count(l) <= 2) {
            held.remove(&key);
        }
        out
    }

    // -----------------------------------------------------------------
    // THE FOUR OPERATIONS.
    // -----------------------------------------------------------------

    async fn get_ca_cert(&self, operation: &str) -> Reply {
        let keys = self.ensure_ra().await;
        let chain = self.core.ca_chain_of("scep");
        let (Ok(keys), Some(chain)) = (keys.clone(), chain) else {
            let r = keys.err().unwrap_or_else(|| {
                Refusal::new(
                    codes::STS_SCEP_0005,
                    503,
                    "This realm has no SCEP Issuing CA.",
                )
            });
            self.record(json!({ "operation": operation, "outcome": "refused", "status": 503, "errorCode": r.code.as_str() }));
            return scep_error(503, r.code, &r.sentence, &[]);
        };
        let pems: Vec<String> = [
            keys.certificate_pem,
            chain.issuing_pem,
            chain.intermediate_pem,
            chain.root_pem,
        ]
        .into_iter()
        .filter(|p| !p.is_empty())
        .collect();
        let mut reply = Reply::new(200);
        reply.set("Content-Type", "application/x-x509-ca-ra-cert");
        reply.set("Cache-Control", "no-store");
        reply.body = pki_message::certs_only(&pems, &[]);
        self.record(json!({ "operation": operation, "outcome": "answered", "status": 200 }));
        reply
    }

    fn message_bytes(
        &self,
        req: &Req,
        operation: &str,
        message_param: &str,
    ) -> Result<Vec<u8>, Reply> {
        let limit = self.core.setting_int("scep.maxRequestBytes") as usize;
        let refuse = |status: u16, code: ErrorCode, text: String| {
            self.record(json!({ "operation": operation, "outcome": "refused", "status": status, "errorCode": code.as_str() }));
            scep_error(status, code, &text, &[])
        };
        if req.method == "POST" {
            let kind = req
                .header("content-type")
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_lowercase();
            if !matches!(
                kind.as_str(),
                "application/x-pki-message" | "application/octet-stream" | ""
            ) {
                return Err(refuse(415, codes::STS_SCEP_0007, "A PKIOperation POST carries Content-Type: application/x-pki-message (RFC 8894 section 4.3).".into()));
            }
            if req.body.len() > limit {
                return Err(refuse(413, codes::STS_SCEP_0008, format!("The message is {} bytes and scep.maxRequestBytes is {}.", req.body.len(), limit)));
            }
            return Ok(req.body.clone());
        }
        let text = message_param;
        if text.len() > limit.div_ceil(3) * 4 + 4 {
            return Err(refuse(413, codes::STS_SCEP_0008, format!("The message parameter is longer than scep.maxRequestBytes ({}) allows.", limit)));
        }
        let body = text.trim_end_matches('=');
        let shape = !text.is_empty()
            && text.len() % 4 == 0
            && text.len() - body.len() <= 2
            && !body.is_empty()
            && body
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/');
        if !shape {
            return Err(refuse(
                400,
                codes::STS_SCEP_0009,
                "A GET PKIOperation carries the pkiMessage in the message parameter as base64 (RFC 8894 section 4.3), with no whitespace.".into(),
            ));
        }
        let bytes = crate::est::codec::lenient_base64(text);
        if bytes.len() > limit {
            return Err(refuse(
                413,
                codes::STS_SCEP_0008,
                format!(
                    "The message is {} bytes and scep.maxRequestBytes is {}.",
                    bytes.len(),
                    limit
                ),
            ));
        }
        Ok(bytes)
    }

    async fn pki_operation(
        &self,
        req: &Req,
        operation: &str,
        url_profile: &str,
        message_param: &str,
    ) -> Reply {
        if let Some(early) = self.core.throttled("scep", &req.address, "") {
            self.record(json!({ "operation": operation, "outcome": "refused", "status": 429, "errorCode": early.code.as_str() }));
            return scep_error(
                429,
                early.code,
                &early.sentence,
                &[("Retry-After", Core::retry_after_of(&early).to_string())],
            );
        }
        let bytes = match self.message_bytes(req, operation, message_param) {
            Ok(b) => b,
            Err(r) => {
                self.core.count_failure("scep", &req.address, "");
                return r;
            }
        };
        let message = match pki_message::parse_pki_message(&bytes) {
            Ok(m) => m,
            Err(r) => {
                self.core.count_failure("scep", &req.address, "");
                self.record(json!({ "operation": operation, "outcome": "refused", "status": 400, "errorCode": r.code.as_str() }));
                self.core.audit().failure(
                    r.code,
                    &json!({ "protocol": "SCEP", "summary": format!("a SCEP pkiMessage was refused before it could be named: {}", r.why) }),
                );
                return scep_error(400, r.code, &r.why, &[]);
            }
        };
        let type_name = message
            .message_type
            .and_then(|t| model::name_of_code("scep", "message-types", t))
            .unwrap_or_else(|| {
                format!("messageType {}", message.message_type_text)
            });
        let op_name = format!("{}:{}", operation, type_name);
        let keys = match self.ensure_ra().await {
            Ok(k) => k,
            Err(r) => {
                self.record(json!({ "operation": op_name, "outcome": "refused", "status": 503, "errorCode": r.code.as_str() }));
                return scep_error(503, r.code, &r.sentence, &[]);
            }
        };
        let result =
            self.answer_message(req, &message, &keys, url_profile).await;
        if let Some(blocked) = &result.http {
            self.record(json!({ "operation": op_name, "outcome": "refused", "status": 429, "errorCode": blocked.code.as_str(), "principal": result.identity }));
            return scep_error(
                429,
                blocked.code,
                &blocked.sentence,
                &[("Retry-After", Core::retry_after_of(blocked).to_string())],
            );
        }
        let digest = pki_message::digest_id(&message.digest_alg)
            .unwrap_or("sha256")
            .to_string();
        let signer_pem = message
            .signer
            .as_ref()
            .map(|s| s.pem.clone())
            .unwrap_or_default();
        let body = if result.ok {
            let inner = match &result.crl_der {
                Some(crl) => {
                    pki_message::certs_only(&[], std::slice::from_ref(crl))
                }
                None => pki_message::certs_only(
                    std::slice::from_ref(&result.certificate_pem),
                    &[],
                ),
            };
            pki_message::envelope(&inner, &signer_pem, &result.cipher).and_then(
                |content| {
                    pki_message::cert_rep(&CertRepSpec {
                        ra_certificate_pem: keys.certificate_pem.clone(),
                        ra_private_key_pem: keys.private_key_pem.clone(),
                        transaction_id: message.transaction_id.clone(),
                        recipient_nonce: message.sender_nonce.clone(),
                        pki_status: pki_message::pki_status("SUCCESS"),
                        content: Some(content),
                        digest: digest.clone(),
                        ..Default::default()
                    })
                },
            )
        } else {
            pki_message::cert_rep(&CertRepSpec {
                ra_certificate_pem: keys.certificate_pem.clone(),
                ra_private_key_pem: keys.private_key_pem.clone(),
                transaction_id: message.transaction_id.clone(),
                recipient_nonce: message.sender_nonce.clone(),
                pki_status: pki_message::pki_status("FAILURE"),
                fail_info: result.fail_info.clone(),
                digest: digest.clone(),
                ..Default::default()
            })
        };
        let Some(body) = body else {
            tracing::error!(
                "{}scep: a CertRep could not be built for transaction {}",
                sts_core::log::tag(codes::STS_SCEP_0044.as_str()),
                message.transaction_id
            );
            self.record(json!({ "operation": op_name, "outcome": "refused", "status": 500, "errorCode": codes::STS_SCEP_0044.as_str() }));
            return scep_error(
                500,
                codes::STS_SCEP_0044,
                "The reply could not be built.",
                &[],
            );
        };
        let mut reply = Reply::new(200);
        if !result.ok {
            self.core
                .count_failure("scep", &req.address, &result.identity);
            let code = result.code.unwrap_or(codes::STS_SCEP_0045);
            if !result.audited {
                let name = pki_message::fail_name(&result.fail_info);
                self.core.audit().failure(
                    code,
                    &json!({ "protocol": "SCEP", "actor": result.principal, "target": result.principal,
                             "summary": format!("a SCEP {} was answered FAILURE {}: {}", type_name, name,
                                 result.why.chars().take(300).collect::<String>()),
                             "detail": { "transactionID": message.transaction_id, "failInfo": name } }),
                );
            }
            reply.mark(code);
        }
        reply.set("Content-Type", "application/x-pki-message");
        reply.set("Cache-Control", "no-store");
        reply.body = body;
        let outcome = if result.ok {
            if result.issued && !result.replay {
                "issued"
            } else {
                "answered"
            }
        } else {
            "refused"
        };
        let principal = if !result.principal.is_empty() {
            Json::from(result.principal.clone())
        } else if !result.identity.is_empty() {
            Json::from(result.identity.clone())
        } else {
            Json::Null
        };
        let opt = |s: &str| {
            if s.is_empty() {
                Json::Null
            } else {
                Json::from(s)
            }
        };
        self.record(json!({
            "operation": op_name, "outcome": outcome, "status": 200,
            "profile": opt(&result.profile), "principal": principal, "target": opt(&result.target),
            "errorCode": if result.ok { Json::Null } else { Json::from(result.code.map(|c| c.as_str()).unwrap_or("")) },
            "serialHex": opt(&result.serial_hex),
            "failInfo": if result.ok { Json::Null } else { opt(&pki_message::fail_name(&result.fail_info)) },
        }));
        reply
    }

    /// Answers a request under `/enroll/scep`, or `None` for a path that
    /// is not one of its eight.
    #[tracing::instrument(level = "debug", skip_all, fields(path = %req.path))]
    pub async fn handle(&self, req: &Req) -> Option<Reply> {
        if req.method != "GET" && req.method != "POST" && req.method != "HEAD" {
            return None;
        }
        let tail = crate::acme::strip_prefix_ci(&req.path, "/enroll/scep")?;
        let segments: Vec<String> = tail
            .trim_end_matches('/')
            .split('/')
            .skip(1)
            .map(crate::acme::percent_decode)
            .collect();
        let url_profile = match segments.as_slice() {
            [] => String::new(),
            [one] if one.eq_ignore_ascii_case("pkiclient.exe") => String::new(),
            [one] => one.clone(),
            [one, exe] if exe.eq_ignore_ascii_case("pkiclient.exe") => {
                one.clone()
            }
            _ => return None,
        };
        Some(self.serve(req, &url_profile).await)
    }

    async fn serve(&self, req: &Req, url_profile: &str) -> Reply {
        let refuse = |status: u16,
                      operation: &str,
                      code: ErrorCode,
                      text: &str,
                      headers: &[(&str, String)]| {
            self.record(json!({ "operation": operation, "outcome": "refused", "status": status, "errorCode": code.as_str() }));
            scep_error(status, code, text, headers)
        };
        let profile_ok = url_profile.is_empty() || {
            let mut c = url_profile.chars();
            c.next().is_some_and(|f| f.is_ascii_lowercase())
                && url_profile.len() <= 64
                && c.all(|ch| {
                    ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-'
                })
        };
        if !profile_ok {
            return refuse(400, "invalid", codes::STS_SCEP_0013, "The path segment after /enroll/scep/ names a certificate profile.", &[]);
        }
        if !self.core.predicate("answersScep") {
            return refuse(503, "disabled", codes::STS_SCEP_0067, "SCEP is not offered in product mode unless scep.allowInProduct is on.", &[]);
        }
        if !self.core.setting_on("scep.enabled") {
            return refuse(
                503,
                "disabled",
                codes::STS_SCEP_0001,
                "SCEP is turned off in this realm (scep.enabled).",
                &[],
            );
        }
        let query = Json::Object(req.query_map());
        let checked = model::Body::of("scep", "query").map(|b| b.check(&query));
        let value = match checked {
            Some(Ok(v)) => v,
            Some(Err(issue)) => {
                let field = issue
                    .path
                    .last()
                    .cloned()
                    .unwrap_or_else(|| "(request)".into());
                let detail = if issue.missing {
                    format!("the query parameter \"{}\" is required.", field)
                } else {
                    format!(
                        "the query parameter \"{}\" is not acceptable: {}.",
                        field, issue.message
                    )
                };
                let ops: Vec<String> = model::operations("scep")
                    .into_iter()
                    .map(|o| o.name)
                    .collect();
                return refuse(
                    400,
                    "invalid",
                    codes::STS_SCEP_0002,
                    &format!(
                        "SCEP: {} The operations are {}.",
                        detail,
                        ops.join(", ")
                    ),
                    &[],
                );
            }
            None => json!({}),
        };
        let operation = str_of(&value, "operation").to_string();
        let message_param = str_of(&value, "message").to_string();
        let methods = model::operations("scep")
            .into_iter()
            .find(|o| o.name == operation)
            .map(|o| o.methods)
            .unwrap_or_default();
        if req.method == "POST" && !methods.iter().any(|m| m == "POST") {
            return refuse(
                405,
                &operation,
                codes::STS_SCEP_0003,
                &format!("{} is a GET (RFC 8894 section 4); only PKIOperation may be POSTed.", operation),
                &[("Allow", methods.join(", "))],
            );
        }
        match operation.as_str() {
            "GetCACaps" => {
                let caps = model::names("scep", "capabilities");
                let mut reply = Reply::new(200);
                reply.set("Content-Type", "text/plain; charset=utf-8");
                reply.set("Cache-Control", "no-store");
                reply.body = format!("{}\n", caps.join("\n")).into_bytes();
                self.record(json!({ "operation": operation, "outcome": "answered", "status": 200 }));
                reply
            }
            "GetCACert" => self.get_ca_cert(&operation).await,
            "GetNextCACert" => refuse(
                501,
                &operation,
                codes::STS_SCEP_0004,
                "GetNextCACert is not implemented: this service does not pre-announce a CA rollover, and GetCACaps does not advertise it.",
                &[],
            ),
            _ => self.pki_operation(req, &operation, url_profile, &message_param).await,
        }
    }

    /// The RA certificate for the console's and the API's view: no key.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn describe_ra(&self) -> Json {
        let Some(held) = self.ra_record() else {
            return json!({ "present": false, "status": "missing", "keyAlgorithm": format!("rsa-{}", self.wanted_bits()) });
        };
        let why = self.staleness(Some(&held));
        json!({
            "present": true, "status": if why.is_empty() { "current" } else { why },
            "subject": held["subject"], "serialHex": held["serialHex"],
            "wantedKeyAlgorithm": format!("rsa-{}", self.wanted_bits()),
            "notBefore": held["notBefore"], "notAfter": held["notAfter"],
            "thumbprint": held["thumbprint"], "certificatePem": held["certificatePem"],
        })
    }
}

fn empty_described() -> pki_message::Described {
    pki_message::Described {
        der: Vec::new(),
        pem: String::new(),
        serial_raw: Vec::new(),
        issuer_raw: Vec::new(),
        subject_raw: Vec::new(),
        ski: None,
        key_type: String::new(),
        spki: Vec::new(),
        spki_sha256: String::new(),
        self_issued: true,
        serial_hex: String::new(),
        not_before_ms: 0.0,
        not_after_ms: 0.0,
        valid_from: String::new(),
        valid_to: String::new(),
    }
}

fn merge(target: &mut Json, more: &Json) {
    if let (Some(t), Some(m)) = (target.as_object_mut(), more.as_object()) {
        for (k, v) in m {
            t.insert(k.clone(), v.clone());
        }
    }
}

/// The base64 of a GET binding's message, for a client building one.
#[tracing::instrument(level = "trace", skip_all)]
pub fn get_binding(message: &[u8]) -> String {
    STANDARD.encode(message)
}
