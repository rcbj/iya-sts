// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! ENROLLMENT OVER SECURE TRANSPORT (RFC 7030 with RFC 8951's
//! clarifications, `est/est.ts`): the six operations at
//! `/.well-known/est/` and under `/.well-known/est/:label/`, and
//! draft-ietf-lamps-attestation-freshness's `/nonce`. `est/CLAUDE.md` is
//! the design.
//!
//! * **A LABEL IS A PROFILE, NOT A CA.** An unknown label is 404; a label
//!   naming a trust realm is the realm (the HTTP layer enters it, #251),
//!   and one naming a realm a second time is 404 `STS-EST-0022`.
//! * **THE ORDER OF THE CHECKS IS A DECISION**: query, `est.enabled`,
//!   transport, label, the operation's own setting, the throttle, the media
//!   type and the size — no credential read and no body decoded — then
//!   authentication, then the body.
//! * **A BASIC USERNAME IS A PERSON FIRST**, then an application's
//!   client id; with no Authorization a TLS client certificate.
//! * **REFUSALS ARE PLAIN TEXT, ONE SENTENCE**, the code marked and never
//!   in the body; a refusal at 400/401/403/409/413/415 counts against the
//!   caller.
//!
//! `/nonce`'s rows are kept in `devices.challenges`, Node's store and
//! shape, declared here until the device register is ported (it is the
//! `csr-attestation` purpose of `device_enrolment.ts`'s challenges).

pub mod codec;

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value as Json};
use sts_core::errors::{codes, ErrorCode};
use sts_core::realm;
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{expiry_field, RealmMap, StoreHandles, StoreSpec};

use self::codec::{AttrOrOid, AttrValue};
use crate::core::csr::{Csr, Requested};
use crate::core::issue::IssueSpec;
use crate::core::{
    normal_host_name, normal_serial, str_of, Core, Entry, Principal, Refusal,
    DEVICE_PROFILE, PROFILE_IDS, REFUSED_PROFILES,
};
use crate::http::{Reply, Req};
use crate::model;

/// Where EST answers.
pub const BASE: &str = "/.well-known/est";
const FAMILY: &str = "est";
const NONCE_COOKIE: &str = "sts_est_nonce";
const MAX_AUTHORIZATION: usize = 4096;
const NONCE_MAX_BYTES: usize = 64;
const NONCE_DEFAULT_BYTES: usize = 32;

/// `devices.challenges`, the `csr-attestation` rows.
#[derive(Clone)]
pub struct EstStore {
    challenges: RealmMap<Json>,
}

impl EstStore {
    /// Declares the store (before the store opens).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn declare(
        lifecycle: &Arc<RealmLifecycle>,
        handles: &Arc<StoreHandles>,
    ) -> EstStore {
        let mut spec = StoreSpec::persisted("devices.challenges");
        spec.tombstone = true;
        spec.expires_at = Some(expiry_field(Some("expiresAt"), 1.0));
        EstStore {
            challenges: RealmMap::new(lifecycle, handles, spec),
        }
    }
}

fn media(name: &str) -> String {
    model::value_of(FAMILY, "media", name)
}

fn counted_statuses() -> Vec<u16> {
    model::rows(FAMILY, "refusal-statuses")
        .iter()
        .filter(|r| r.get("counted") == Some(&Json::Bool(true)))
        .filter_map(|r| r.get("code").and_then(Json::as_u64).map(|c| c as u16))
        .collect()
}

/// The Authorization header, READ but not believed.
#[derive(Debug, Clone, Default)]
struct Basic {
    present: bool,
    basic: bool,
    malformed: bool,
    username: String,
    password: String,
}

/// A request's context.
#[derive(Default)]
struct Ctx {
    op: String,
    labelled: bool,
    profile: String,
    identity: String,
    principal: Option<Principal>,
    target_uri: Option<String>,
    basic: Basic,
}

/// The EST server.
pub struct Est {
    core: Arc<Core>,
    store: EstStore,
}

fn label_shape(label: &str) -> bool {
    let mut chars = label.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && label.len() <= 40
        && chars.all(|c| c.is_ascii_lowercase() || c == '-')
}

impl Est {
    /// Builds the server.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(core: Arc<Core>, store: EstStore) -> Arc<Est> {
        Arc::new(Est { core, store })
    }

    fn counted(&self, ctx: &Ctx, detail: Json) {
        let mut row = json!({
            "operation": ctx.op, "profile": if ctx.profile.is_empty() { Json::Null } else { Json::from(ctx.profile.clone()) },
            "principal": if ctx.identity.is_empty() { Json::Null } else { Json::from(ctx.identity.clone()) },
            "target": ctx.target_uri,
        });
        if let (Some(r), Json::Object(d)) = (row.as_object_mut(), detail) {
            for (k, v) in d {
                r.insert(k, v);
            }
        }
        self.core.monitor().record(FAMILY, &row);
    }

    /// `estError(req, res, ctx, status, sentence, headers)`.
    fn error(
        &self,
        req: &Req,
        ctx: &Ctx,
        status: u16,
        code: ErrorCode,
        sentence: &str,
        headers: &[(&str, String)],
    ) -> Reply {
        self.counted(ctx, json!({ "outcome": "refused", "status": status, "errorCode": code.as_str() }));
        if counted_statuses().contains(&status) {
            self.core.count_failure(FAMILY, &req.address, &ctx.identity);
        }
        tracing::info!(
            "est: {} refused {} {} for {}",
            ctx.op,
            status,
            code.as_str(),
            if ctx.identity.is_empty() {
                "an unauthenticated client"
            } else {
                &ctx.identity
            }
        );
        let mut reply = Reply::new(status);
        for (k, v) in headers {
            reply.set(k, v);
        }
        reply.set("Cache-Control", "no-store");
        reply.set("Content-Type", "text/plain; charset=utf-8");
        reply.mark(code);
        let text = if sentence.is_empty() {
            "The request was refused."
        } else {
            sentence
        };
        reply.body = format!("{}\n", text).into_bytes();
        reply
    }

    /// `refuseWith(req, res, ctx, refusal)`.
    fn refuse_with(&self, req: &Req, ctx: &Ctx, r: &Refusal) -> Reply {
        let mut headers = Vec::new();
        if r.status == 401 && self.core.setting_on("est.basicAuthentication") {
            headers
                .push(("WWW-Authenticate", "Basic realm=\"EST\"".to_string()));
        }
        if r.status == 429 {
            headers.push(("Retry-After", Core::retry_after_of(r).to_string()));
        }
        let status = if r.status == 0 { 400 } else { r.status };
        self.error(req, ctx, status, r.code, &r.sentence, &headers)
    }

    fn send_base64(content_type: &str, der: &[u8]) -> Reply {
        let mut reply = Reply::new(200);
        reply.set("Content-Type", content_type);
        reply.set("Content-Transfer-Encoding", "base64");
        reply.set("Cache-Control", "no-store");
        reply.body = codec::base64_lines(der).into_bytes();
        reply
    }

    /// Answers a request under `/.well-known/est`, or `None` for a path
    /// that is no EST operation.
    #[tracing::instrument(level = "debug", skip_all, fields(path = %req.path))]
    pub async fn handle(&self, req: &Req) -> Option<Reply> {
        let tail = crate::acme::strip_prefix_ci(&req.path, BASE)?;
        let segments: Vec<String> = tail
            .trim_end_matches('/')
            .split('/')
            .skip(1)
            .map(crate::acme::percent_decode)
            .collect();
        let (label, op_name) = match segments.as_slice() {
            [op] => (None, op.to_lowercase()),
            [label, op] => (Some(label.clone()), op.to_lowercase()),
            _ => return None,
        };
        let op = model::operations(FAMILY)
            .into_iter()
            .find(|o| o.name == op_name)?;
        let method = if req.method == "HEAD" {
            "GET"
        } else {
            req.method.as_str()
        };
        if !op.methods.iter().any(|m| m == method) {
            let mut allow = Vec::new();
            for m in &op.methods {
                allow.push(m.clone());
                if m == "GET" {
                    allow.push("HEAD".into());
                }
            }
            let ctx = Ctx {
                op: op.name.clone(),
                ..Default::default()
            };
            return Some(self.error(
                req,
                &ctx,
                405,
                codes::STS_EST_0003,
                &format!(
                    "EST {} answers {} only.",
                    op.name,
                    op.methods.join(", ")
                ),
                &[("Allow", allow.join(", "))],
            ));
        }
        let mut ctx = Ctx {
            op: op.name.clone(),
            ..Default::default()
        };
        if let Some(refused) =
            self.refused_before_authentication(req, &mut ctx, label.as_deref())
        {
            return Some(refused);
        }
        Some(match op.name.as_str() {
            "cacerts" => self.cacerts(req, &ctx),
            "simpleenroll" => self.simpleenroll(req, &mut ctx).await,
            "simplereenroll" => self.simplereenroll(req, &mut ctx).await,
            "serverkeygen" => self.serverkeygen(req, &mut ctx).await,
            "csrattrs" => self.csrattrs(&ctx),
            "nonce" => self.nonce(req, &mut ctx).await,
            _ => self.error(
                req,
                &ctx,
                501,
                codes::STS_EST_0004,
                "Full CMC (RFC 7030 section 4.3) is not implemented here; use /simpleenroll, /simplereenroll or /serverkeygen.",
                &[],
            ),
        })
    }

    fn refused_before_authentication(
        &self,
        req: &Req,
        ctx: &mut Ctx,
        label: Option<&str>,
    ) -> Option<Reply> {
        let query = Json::Object(req.query_map());
        if let Some(Err(issue)) =
            model::Body::of(FAMILY, "query").map(|b| b.check(&query))
        {
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
            return Some(self.error(
                req,
                ctx,
                400,
                codes::STS_EST_0019,
                &format!("No EST operation takes a query string: {}", detail),
                &[],
            ));
        }
        if !self.core.setting_on("est.enabled") {
            return Some(self.error(
                req,
                ctx,
                503,
                codes::STS_EST_0001,
                "EST is turned off in this realm (est.enabled).",
                &[],
            ));
        }
        if let Some(t) = self.core.transport_refusal(req.over_tls, FAMILY) {
            return Some(self.refuse_with(req, ctx, &t));
        }
        if let Some(label) = label {
            let known = label_shape(label)
                && (PROFILE_IDS.contains(&label)
                    || label == DEVICE_PROFILE
                    || REFUSED_PROFILES.iter().any(|(id, _)| *id == label));
            if !known
                && self.core.realm_exists(label)
                && label != realm::DEFAULT_ID
            {
                let shown: String = label.chars().take(40).collect();
                return Some(self.error(
                    req,
                    ctx,
                    404,
                    codes::STS_EST_0022,
                    &format!(
                        "The EST label \"{}\" names a trust realm, and this request already named one. Name the realm once: /.well-known/est/<realm>/[<profile>/]<operation> or /realm/<realm>/.well-known/est/[<profile>/]<operation>.",
                        shown
                    ),
                    &[],
                ));
            }
            if !known {
                let shown: String = label.chars().take(40).collect();
                let mut list: Vec<&str> = PROFILE_IDS.to_vec();
                list.push(DEVICE_PROFILE);
                return Some(self.error(
                    req,
                    ctx,
                    404,
                    codes::STS_EST_0002,
                    &format!("There is no EST label \"{}\" here. A label is a certificate profile, one of: {}.", shown, list.join(", ")),
                    &[],
                ));
            }
            ctx.labelled = true;
            ctx.profile = label.to_string();
        } else {
            ctx.labelled = false;
            ctx.profile = self.core.default_profile(FAMILY, None);
        }
        let enrolling = ["simpleenroll", "simplereenroll", "serverkeygen"]
            .contains(&ctx.op.as_str());
        if ctx.labelled || (enrolling && ctx.op != "simplereenroll") {
            if let Err(r) =
                self.core.check_profile(FAMILY, &ctx.profile, None, true)
            {
                return Some(self.refuse_with(req, ctx, &r));
            }
        }
        None
    }

    fn refused_before_body(&self, req: &Req, ctx: &Ctx) -> Option<Reply> {
        if let Some(t) =
            self.core.throttled(FAMILY, &req.address, &ctx.identity)
        {
            return Some(self.refuse_with(req, ctx, &t));
        }
        let kind = req
            .header("content-type")
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_lowercase();
        if kind != media("pkcs10") {
            let shown: String = kind.chars().take(80).collect();
            return Some(self.error(
                req,
                ctx,
                415,
                codes::STS_EST_0006,
                &format!("An EST enrollment body is {} (RFC 7030 section 4.2.1), and this one was \"{}\".", media("pkcs10"), shown),
                &[],
            ));
        }
        let max = self.core.setting_int("est.maxRequestBytes");
        let declared = req.header("content-length").trim().parse::<f64>().ok();
        if declared.is_some_and(|d| d > max as f64)
            || req.body.len() as i64 > max
        {
            return Some(self.error(req, ctx, 413, codes::STS_EST_0007, &format!("The request body is larger than the {} bytes est.maxRequestBytes allows.", max), &[]));
        }
        None
    }

    fn basic_of(req: &Req) -> Basic {
        let header = req.header("authorization");
        if header.is_empty() {
            return Basic::default();
        }
        let lower = header.to_lowercase();
        if !(lower == "basic"
            || lower.starts_with("basic ")
            || lower.starts_with("basic\t"))
        {
            return Basic {
                present: true,
                ..Default::default()
            };
        }
        let malformed = Basic {
            present: true,
            basic: true,
            malformed: true,
            ..Default::default()
        };
        let shape =
            regex::Regex::new(r"(?i)^basic\s+([A-Za-z0-9+/]+={0,2})\s*$").ok();
        let Some(encoded) = shape
            .as_ref()
            .and_then(|re| re.captures(&header))
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
        else {
            return malformed;
        };
        let encoded = encoded.as_str();
        if header.len() > MAX_AUTHORIZATION || encoded.len() % 4 != 0 {
            return malformed;
        }
        let Ok(decoded) = STANDARD.decode(encoded) else {
            return malformed;
        };
        if STANDARD.encode(&decoded) != encoded {
            return malformed;
        }
        let text = String::from_utf8_lossy(&decoded).into_owned();
        let Some(colon) = text.find(':').filter(|c| *c > 0) else {
            return malformed;
        };
        let username = text[..colon].to_string();
        if !crate::core::well_formed_id(&username) {
            return malformed;
        }
        Basic {
            present: true,
            basic: true,
            malformed: false,
            password: text[colon + 1..].to_string(),
            username,
        }
    }

    fn application_named(&self, client_id: &str) -> bool {
        self.core
            .applications()
            .find(client_id)
            .is_some_and(|a| !a.identifier.is_empty())
    }

    fn certificate_authentication_on(&self, req: &Req) -> bool {
        let named = req
            .peer_leaf()
            .and_then(crate::core::trust::entry_named_by_certificate);
        let entry = named.filter(|n| n.kind == "application");
        self.core
            .est_switch("certificateAuthentication", entry.as_ref())
    }

    async fn authenticate(
        &self,
        req: &Req,
        ctx: &Ctx,
    ) -> Result<Principal, Refusal> {
        let basic = &ctx.basic;
        if basic.present {
            if !basic.basic {
                return Err(Refusal::new(codes::STS_EST_0013, 401, "EST accepts HTTP Basic (RFC 7030 section 3.2.3) and no other Authorization scheme."));
            }
            let person =
                self.core.resolve_entry("person", &basic.username).is_ok();
            let basic_on = self.core.setting_on("est.basicAuthentication")
                || (!person
                    && self.application_named(&basic.username)
                    && self.core.est_switch(
                        "basicAuthentication",
                        Some(&Entry::new("application", &basic.username)),
                    ));
            if !basic_on {
                return Err(Refusal::new(codes::STS_EST_0010, 401, "HTTP Basic is turned off for EST in this realm (est.basicAuthentication)."));
            }
            if basic.malformed {
                return Err(Refusal::new(codes::STS_EST_0011, 401, "The HTTP Basic credential is malformed: it must be base64 of a name, a colon and a password (RFC 7617)."));
            }
            if person || !self.application_named(&basic.username) {
                return self
                    .core
                    .authenticate_person(
                        &basic.username,
                        &basic.password,
                        "est-basic",
                    )
                    .await;
            }
            return self.core.authenticate_application(
                &basic.username,
                &basic.password,
                "est-basic",
            );
        }
        if req.peer_leaf().is_some() {
            if !self.certificate_authentication_on(req) {
                return Err(Refusal::new(codes::STS_EST_0012, 401, "TLS client certificate authentication is turned off for EST in this realm (est.certificateAuthentication)."));
            }
            return self
                .core
                .authenticate_certificate(req.peer_leaf(), "est-certificate");
        }
        Err(Refusal::new(codes::STS_EST_0009, 401, "This EST operation is authenticated: send HTTP Basic, or present a TLS client certificate this realm issued."))
    }

    fn identity_hint_of(req: &Req, basic: &Basic) -> String {
        if basic.present && !basic.username.is_empty() {
            return basic.username.clone();
        }
        if basic.present {
            return String::new();
        }
        req.peer_leaf()
            .and_then(|d| sts_pki::x509::read::Certificate::from_der(d).ok())
            .map(|c| {
                format!(
                    "certificate:{}",
                    normal_serial(&sts_pki::der::hex(&c.serial))
                )
            })
            .unwrap_or_default()
    }

    /// `enrollmentRequest(req, res, ctx, { template }, afterAuthentication)`:
    /// `after_authentication` is asked once the caller is authenticated and
    /// before the body is read, and answers the refusal it made itself
    /// (`serverkeygen`'s switch, #36).
    async fn enrollment_request(
        &self,
        req: &Req,
        ctx: &mut Ctx,
        template: bool,
        after_authentication: Option<&(dyn Fn(&Ctx) -> Option<Reply> + Sync)>,
    ) -> Result<Csr, Reply> {
        ctx.basic = Est::basic_of(req);
        ctx.identity = Est::identity_hint_of(req, &ctx.basic);
        if let Some(r) = self.refused_before_body(req, ctx) {
            return Err(r);
        }
        let principal = self
            .authenticate(req, ctx)
            .await
            .map_err(|r| self.refuse_with(req, ctx, &r))?;
        ctx.identity = format!("{}:{}", principal.kind, principal.id);
        ctx.principal = Some(principal);
        if let Some(refused) = after_authentication.and_then(|ask| ask(ctx)) {
            return Err(refused);
        }
        let der = codec::decode_body(&req.body).map_err(|why| {
            self.error(req, ctx, 400, codes::STS_EST_0008, why, &[])
        })?;
        self.core
            .parse_csr(&der, template)
            .map_err(|r| self.refuse_with(req, ctx, &r))
    }

    fn answer_issued(
        &self,
        ctx: &mut Ctx,
        issued: &crate::core::issue::Issued,
    ) -> Reply {
        ctx.target_uri = Some(issued.target.uri());
        self.counted(ctx, json!({ "outcome": "issued", "status": 200, "serialHex": issued.record["serialHex"] }));
        tracing::info!(
            "est: {} issued {} serial {} for {} to {}",
            ctx.op,
            str_of(&issued.record, "profile"),
            str_of(&issued.record, "serialHex"),
            issued.target.uri(),
            ctx.identity
        );
        Est::send_base64(
            &media("certsOnly"),
            &codec::certs_only(&[
                str_of(&issued.record, "certificatePem").to_string()
            ]),
        )
    }

    fn cacerts(&self, req: &Req, ctx: &Ctx) -> Reply {
        let Some(chain) = self.core.ensure_authority(FAMILY) else {
            return self.error(req, ctx, 503, codes::STS_EST_0014, "This realm has no certificate hierarchy yet, so there is no EST CA certificate to return. Build one on /admin/pki.", &[]);
        };
        self.counted(ctx, json!({ "outcome": "answered", "status": 200 }));
        Est::send_base64(
            &media("certsOnly"),
            &codec::certs_only(&chain.chain_pem),
        )
    }

    async fn simpleenroll(&self, req: &Req, ctx: &mut Ctx) -> Reply {
        let csr = match self.enrollment_request(req, ctx, false, None).await {
            Ok(c) => c,
            Err(r) => return r,
        };
        let target = match self.core.target_from_request(
            &csr.requested,
            &csr.common_name,
            ctx.principal.as_ref(),
        ) {
            Ok(t) => t.target,
            Err(r) => return self.refuse_with(req, ctx, &r),
        };
        ctx.target_uri = Some(target.uri());
        let issued = self
            .core
            .issue(&IssueSpec {
                family: FAMILY.into(),
                profile: ctx.profile.clone(),
                profile_defaulted: !ctx.labelled,
                principal: ctx.principal.clone(),
                target: Some(target),
                public_key_pem: csr.public_key_pem.clone(),
                requested: csr.requested.clone(),
                key_source: "client".into(),
                key_alg: csr.key_alg.clone(),
                via: "est:simpleenroll".into(),
                ..Default::default()
            })
            .await;
        match issued {
            Ok(i) => self.answer_issued(ctx, &i),
            Err(r) => self.refuse_with(req, ctx, &r),
        }
    }

    fn subject_of_certificate(pem: &str) -> Option<String> {
        let cert = sts_pki::x509::read::Certificate::from_pem(pem).ok()?;
        crate::core::csr::subject_text(&cert.subject_der).map(|(s, _)| s)
    }

    fn requested_name_set(requested: &Requested) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        out.extend(requested.uris.iter().map(|u| format!("uri:{}", u)));
        out.extend(
            requested
                .dns
                .iter()
                .map(|d| format!("dns:{}", normal_host_name(d))),
        );
        out.extend(
            requested
                .ips
                .iter()
                .map(|d| format!("ip:{}", normal_host_name(d))),
        );
        out.extend(
            requested
                .emails
                .iter()
                .map(|e| format!("email:{}", e.to_lowercase())),
        );
        out.extend(
            requested
                .upns
                .iter()
                .map(|e| format!("upn:{}", e.to_lowercase())),
        );
        let mut unique: Vec<String> = Vec::new();
        for o in out {
            if !unique.contains(&o) {
                unique.push(o);
            }
        }
        unique.sort();
        unique
    }

    fn record_name_set(record: &Json) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for one in record
            .get("names")
            .and_then(Json::as_array)
            .cloned()
            .unwrap_or_default()
        {
            let text = one.as_str().unwrap_or("").to_string();
            let (kind, value) =
                text.split_once(':').unwrap_or(("", text.as_str()));
            let v = if kind == "uri" {
                text.clone()
            } else {
                format!("{}:{}", kind, value.to_lowercase())
            };
            if !out.contains(&v) {
                out.push(v);
            }
        }
        out.sort();
        out
    }

    fn repeats(csr: &Csr, record: &Json) -> bool {
        Est::subject_of_certificate(str_of(record, "certificatePem"))
            .is_some_and(|s| s == csr.subject)
            && Est::requested_name_set(&csr.requested)
                == Est::record_name_set(record)
    }

    async fn simplereenroll(&self, req: &Req, ctx: &mut Ctx) -> Reply {
        let csr = match self.enrollment_request(req, ctx, false, None).await {
            Ok(c) => c,
            Err(r) => return r,
        };
        let principal = ctx.principal.clone().unwrap_or_default();
        let by_certificate =
            if principal.certificate_serial.is_some() {
                Some(Ok(principal.clone()))
            } else if req.peer_leaf().is_some()
                && self.certificate_authentication_on(req)
            {
                Some(self.core.authenticate_certificate(
                    req.peer_leaf(),
                    "est-certificate",
                ))
            } else {
                None
            };
        let (target, renewed) = if let Some(by) = by_certificate {
            let holder = match by {
                Ok(p) => p,
                Err(r) => return self.refuse_with(req, ctx, &r),
            };
            let target = holder.entry();
            if let Err(r) =
                self.core.authorize_target(Some(&principal), &target)
            {
                return self.refuse_with(req, ctx, &r);
            }
            let serial = holder.certificate_serial.clone().unwrap_or_default();
            let renewed =
                self.core.enrolled_of(&target).into_iter().find(|one| {
                    normal_serial(str_of(one, "serialHex")) == serial
                });
            ctx.target_uri = Some(target.uri());
            match renewed.filter(|r| Est::repeats(&csr, r)) {
                Some(r) => (target, r),
                None => {
                    return self.error(
                        req,
                        ctx,
                        400,
                        codes::STS_EST_0016,
                        "A re-enrollment request must repeat the subject and subjectAltName of the certificate being renewed (RFC 7030 section 4.2.2), and this one differs from the TLS client certificate presented.",
                        &[],
                    )
                }
            }
        } else {
            let target = match self.core.target_from_request(
                &csr.requested,
                &csr.common_name,
                Some(&principal),
            ) {
                Ok(t) => t.target,
                Err(r) => return self.refuse_with(req, ctx, &r),
            };
            ctx.target_uri = Some(target.uri());
            if let Err(r) =
                self.core.authorize_target(Some(&principal), &target)
            {
                return self.refuse_with(req, ctx, &r);
            }
            let held: Vec<Json> = self
                .core
                .enrolled_of(&target)
                .into_iter()
                .filter(|one| {
                    str_of(one, "family") == FAMILY && Est::repeats(&csr, one)
                })
                .collect();
            match held.iter().find(|one| str_of(one, "status") == "valid") {
                Some(r) => (target, r.clone()),
                None => {
                    let (code, sentence) = if held.is_empty() {
                        (
                            codes::STS_EST_0015,
                            format!(
                                "No EST certificate held by the {} has the subject and subjectAltName this request repeats, so there is nothing to renew (RFC 7030 section 4.2.2).",
                                target.label()
                            ),
                        )
                    } else {
                        (codes::STS_EST_0021, "The certificate this request renews has expired or been revoked; ask /simpleenroll for a new one.".to_string())
                    };
                    return self.error(req, ctx, 400, code, &sentence, &[]);
                }
            }
        };
        if str_of(&renewed, "status") != "valid" {
            return self.error(req, ctx, 400, codes::STS_EST_0021, "The certificate this request renews has expired or been revoked; ask /simpleenroll for a new one.", &[]);
        }
        if !ctx.labelled {
            ctx.profile = str_of(&renewed, "profile").to_string();
        }
        let issued = self
            .core
            .issue(&IssueSpec {
                family: FAMILY.into(),
                profile: ctx.profile.clone(),
                principal: ctx.principal.clone(),
                target: Some(target),
                public_key_pem: csr.public_key_pem.clone(),
                requested: csr.requested.clone(),
                key_source: "client".into(),
                key_alg: csr.key_alg.clone(),
                via: "est:simplereenroll".into(),
                replaces: str_of(&renewed, "serialHex").to_string(),
                ..Default::default()
            })
            .await;
        match issued {
            Ok(i) => self.answer_issued(ctx, &i),
            Err(r) => self.refuse_with(req, ctx, &r),
        }
    }

    fn server_key_algorithm(csr: &Csr, profile: &str) -> String {
        let ids = sts_pki::authority::catalog::key_alg_ids();
        if ids.contains(&csr.key_alg) {
            csr.key_alg.clone()
        } else if profile == "key-encipherment" {
            "rsa-2048".into()
        } else {
            "ec-p256".into()
        }
    }

    async fn serverkeygen(&self, req: &Req, ctx: &mut Ctx) -> Reply {
        // Off for the realm refuses ONCE THE CALLER IS AUTHENTICATED, and
        // before the template is read — unless the caller is an
        // administrator, or an application whose own switch turns it on.
        //
        // AUTHENTICATED FIRST (Node's #36, 2026-11-15): the switch was asked
        // before anybody was authenticated, so the asker was always empty:
        // an anonymous caller learnt the realm's setting from a 501 where
        // every other EST refusal asks for a credential first (RFC 7030
        // section 3.2.3), and the two exceptions could never apply.
        let switched_off = |ctx: &Ctx| -> Option<Reply> {
            let asker = ctx.principal.clone().unwrap_or_default();
            let may = (asker.kind == "person" && asker.admin)
                || (asker.kind == "application"
                    && self.core.est_switch(
                        "serverKeyGeneration",
                        Some(&asker.entry()),
                    ));
            if !self.core.setting_on("est.serverKeyGeneration") && !may {
                return Some(self.error(
                    req,
                    ctx,
                    501,
                    codes::STS_EST_0005,
                    "Server-side key generation is turned off for EST in \
                     this realm (est.serverKeyGeneration).",
                    &[],
                ));
            }
            None
        };
        let csr = match self
            .enrollment_request(req, ctx, true, Some(&switched_off))
            .await
        {
            Ok(c) => c,
            Err(r) => return r,
        };
        if csr.attribute_types.iter().any(|t| {
            t == codec::oids::DECRYPT_KEY_IDENTIFIER
                || t == codec::oids::ASYMMETRIC_DECRYPT_KEY_IDENTIFIER
        }) {
            return self.error(
                req,
                ctx,
                501,
                codes::STS_EST_0018,
                "The request asks for the private key to be encrypted (RFC 7030 section 4.4.1.2), which this server does not do; it refuses rather than return the key unencrypted.",
                &[],
            );
        }
        let key_alg = Est::server_key_algorithm(&csr, &ctx.profile);
        let kem = sts_pki::authority::catalog::key_alg(&key_alg)
            .and_then(|a| a.pqc)
            .and_then(sts_crypto::pq_x509::alg)
            .is_some_and(|a| a.usage == sts_crypto::pq_x509::Use::Kem);
        if kem && ctx.profile != "key-encipherment" {
            return self.error(
                req,
                ctx,
                400,
                codes::STS_EST_0017,
                &format!(
                    "A {} key is a key-encapsulation key and can be certified only for key-encipherment; this request is for {}.",
                    key_alg, ctx.profile
                ),
                &[],
            );
        }
        let target = match self.core.target_from_request(
            &csr.requested,
            &csr.common_name,
            ctx.principal.as_ref(),
        ) {
            Ok(t) => t.target,
            Err(r) => return self.refuse_with(req, ctx, &r),
        };
        ctx.target_uri = Some(target.uri());
        let issued = self
            .core
            .issue_with_server_key(&IssueSpec {
                family: FAMILY.into(),
                profile: ctx.profile.clone(),
                profile_defaulted: !ctx.labelled,
                principal: ctx.principal.clone(),
                target: Some(target),
                key_alg: key_alg.clone(),
                requested: csr.requested.clone(),
                via: "est:serverkeygen".into(),
                ..Default::default()
            })
            .await;
        let issued = match issued {
            Ok(i) => i,
            Err(r) => return self.refuse_with(req, ctx, &r),
        };
        let (boundary, body) = codec::multipart_mixed(&[
            (&media("pkcs8"), codec::pem_to_der(&issued.private_key_pem)),
            (
                &media("certsOnly"),
                codec::certs_only(&[
                    str_of(&issued.record, "certificatePem").to_string()
                ]),
            ),
        ]);
        self.counted(ctx, json!({ "outcome": "issued", "status": 200, "serialHex": issued.record["serialHex"] }));
        let mut reply = Reply::new(200);
        reply.set(
            "Content-Type",
            &format!("multipart/mixed; boundary={}", boundary),
        );
        reply.set("Cache-Control", "no-store");
        reply.body = body;
        reply
    }

    /// `csrAttributesFor(profileId)`.
    fn csr_attributes_for(profile: &str) -> Vec<AttrOrOid> {
        let mut items: Vec<AttrOrOid> = codec::SIGNATURE_ALGORITHMS
            .iter()
            .map(|o| AttrOrOid::Oid(o.to_string()))
            .collect();
        items.push(AttrOrOid::Oid(codec::oids::EXTENSION_REQUEST.into()));
        let ekus: Vec<AttrValue> = sts_pki::x509::extensions::profile(profile)
            .map(|p| p.ext_key_usage)
            .unwrap_or(&[])
            .iter()
            .filter_map(|name| {
                sts_pki::x509::extensions::EKU_OIDS
                    .iter()
                    .find(|(n, _)| n == name)
                    .map(|(_, o)| AttrValue::Oid(o.to_string()))
            })
            .collect();
        if !ekus.is_empty() {
            items.push(AttrOrOid::Attribute {
                kind: codec::oids::EXT_KEY_USAGE.into(),
                values: ekus,
            });
        }
        if let Some(row) = model::rows(FAMILY, "csrattrs-names")
            .into_iter()
            .find(|r| str_of(r, "name") == profile)
        {
            let values: Vec<AttrValue> = row
                .get("values")
                .and_then(Json::as_array)
                .cloned()
                .unwrap_or_default()
                .iter()
                .filter_map(|v| {
                    v.as_str().map(|s| AttrValue::Utf8(s.to_string()))
                })
                .collect();
            items.push(AttrOrOid::Attribute {
                kind: codec::oids::SUBJECT_ALT_NAME.into(),
                values,
            });
        }
        items
    }

    fn csrattrs(&self, ctx: &Ctx) -> Reply {
        self.counted(ctx, json!({ "outcome": "answered", "status": 200 }));
        Est::send_base64(
            &media("csrattrs"),
            &codec::csr_attrs(&Est::csr_attributes_for(&ctx.profile)),
        )
    }

    fn nonce_handle_of(req: &Req) -> String {
        let mut handle = String::new();
        for part in req.header("cookie").split(';') {
            let bit = part.trim();
            if let Some(v) = bit.strip_prefix(&format!("{}=", NONCE_COOKIE)) {
                if v.len() == 47
                    && v.starts_with("est.")
                    && v[4..].bytes().all(|b| {
                        b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
                    })
                {
                    handle = v.to_string();
                }
            }
        }
        handle
    }

    fn nonce_request_of(
        req: &Req,
    ) -> Result<Option<i64>, (u16, ErrorCode, String)> {
        let text = req
            .text
            .clone()
            .unwrap_or_else(|| String::from_utf8_lossy(&req.body).into_owned());
        let parsed: Option<Json> = serde_json::from_str(&text).ok();
        let Some(parsed) = parsed.filter(Json::is_object) else {
            return Err((400, codes::STS_EST_0034, "A nonce request is one JSON object (draft-ietf-lamps-attestation-freshness section 3.2); send GET for none.".into()));
        };
        let checked =
            model::Body::of(FAMILY, "nonce-request").map(|b| b.check(&parsed));
        match checked {
            Some(Err(issue)) => {
                let at = if issue.path.is_empty() {
                    "(the object)".to_string()
                } else {
                    issue.path.join(".")
                };
                let message: String = issue.message.chars().take(200).collect();
                Err((400, codes::STS_EST_0034, format!("The nonce request does not match draft-ietf-lamps-attestation-freshness section 3.2 at \"{}\": {}.", at, message)))
            }
            _ => {
                if let Some(info) = parsed.get("reqTypeInfo") {
                    return Err((
                        503,
                        codes::STS_EST_0036,
                        format!(
                            "This EST server defines no reqInfo/respInfo for \"{}\", so it cannot answer that nonce request; ask without reqTypeInfo.",
                            str_of(info, "type")
                        ),
                    ));
                }
                Ok(parsed.get("len").and_then(Json::as_i64))
            }
        }
    }

    async fn nonce(&self, req: &Req, ctx: &mut Ctx) -> Reply {
        ctx.basic = Est::basic_of(req);
        ctx.identity = Est::identity_hint_of(req, &ctx.basic);
        if let Some(t) =
            self.core.throttled(FAMILY, &req.address, &ctx.identity)
        {
            return self.refuse_with(req, ctx, &t);
        }
        let posted = req.method == "POST";
        if posted {
            let kind = req
                .header("content-type")
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_lowercase();
            if kind != media("freshness") {
                let shown: String = kind.chars().take(80).collect();
                return self.error(
                    req,
                    ctx,
                    400,
                    codes::STS_EST_0035,
                    &format!("A nonce request is {} (draft-ietf-lamps-attestation-freshness section 5.1), and this one was \"{}\".", media("freshness"), shown),
                    &[],
                );
            }
            let max = self.core.setting_int("est.maxRequestBytes");
            if req
                .header("content-length")
                .trim()
                .parse::<f64>()
                .ok()
                .is_some_and(|d| d > max as f64)
            {
                return self.error(req, ctx, 400, codes::STS_EST_0034, &format!("The nonce request is larger than the {} bytes est.maxRequestBytes allows.", max), &[]);
            }
        }
        let principal = match self.authenticate(req, ctx).await {
            Ok(p) => p,
            Err(r) => return self.refuse_with(req, ctx, &r),
        };
        ctx.identity = format!("{}:{}", principal.kind, principal.id);
        ctx.principal = Some(principal);
        let mut len = None;
        if posted {
            match Est::nonce_request_of(req) {
                Ok(l) => len = l,
                Err((status, code, why)) => {
                    return self.error(req, ctx, status, code, &why, &[])
                }
            }
        }
        let send = |body: Json| -> Reply {
            let problems = model::undeclared(FAMILY, "nonce", &body);
            if !problems.is_empty() {
                tracing::error!(
                    "{}the EST nonce answer is not its model's: {}",
                    sts_core::log::tag(codes::STS_EST_0037.as_str()),
                    problems.join("; ")
                );
            }
            let mut reply = Reply::new(200);
            reply.set("Content-Type", &media("freshness"));
            reply.set("Cache-Control", "no-store");
            reply.body = serde_json::to_string(&body)
                .unwrap_or_default()
                .into_bytes();
            reply
        };
        if ctx.labelled && ctx.profile != DEVICE_PROFILE {
            self.counted(ctx, json!({ "outcome": "answered", "status": 200 }));
            return send(json!({ "nonce": "" }));
        }
        let existing = Est::nonce_handle_of(req);
        let handle = if existing.is_empty() {
            format!(
                "est.{}",
                sts_crypto::random::random_token(Some(256)).unwrap_or_default()
            )
        } else {
            existing
        };
        // `device_enrolment.issueChallenge({ purpose: 'csr-attestation' })`.
        let realm_store = self.store.challenges.in_realm(&realm::current_id());
        for (key, row) in realm_store.entries() {
            if str_of(&row, "sessionId") == handle
                && str_of(&row, "purpose") == "csr-attestation"
            {
                realm_store.delete(&key);
            }
        }
        let octets = len
            .map(|l| l.max(0) as usize)
            .unwrap_or(NONCE_DEFAULT_BYTES)
            .clamp(16, NONCE_MAX_BYTES);
        let octets = if len == Some(0) {
            NONCE_DEFAULT_BYTES
        } else {
            octets
        };
        let challenge = crate::acme::jws::b64u(
            &sts_crypto::random::random_bytes(octets).unwrap_or_default(),
        );
        let ttl = self.core.setting_int("devices.challengeTtlSeconds").max(30)
            as f64
            * 1000.0;
        let now = crate::core::now_ms();
        realm_store.set(
            &challenge,
            json!({ "sessionId": handle, "username": ctx.identity, "purpose": "csr-attestation",
                    "issuedAt": now as i64, "expiresAt": (now + ttl) as i64, "detail": null }),
        );
        let seconds = ((ttl / 1000.0).round() as i64).max(1);
        let mut reply = send(json!({ "nonce": challenge, "expiry": seconds }));
        reply.append(
            "Set-Cookie",
            &format!(
                "{}={}; Path=/; Max-Age={}; HttpOnly; SameSite=Strict{}",
                NONCE_COOKIE,
                handle,
                seconds,
                if req.over_tls { "; Secure" } else { "" }
            ),
        );
        self.counted(ctx, json!({ "outcome": "answered", "status": 200 }));
        tracing::info!(
            "est: nonce issued to {} ({} octets, {} s)",
            ctx.identity,
            octets,
            seconds
        );
        reply
    }
}
