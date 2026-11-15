// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE ACME SERVER (RFC 8555), per trust realm, at `/enroll/acme`
//! (`acme/acme.ts`): the fourteen resources, with RFC 9773 renewal
//! information, RFC 8738's `ip` and RFC 8823's `email` identifiers,
//! draft-ietf-acme-profiles and draft-ietf-acme-device-attest's
//! `permanent-identifier`. `acme/CLAUDE.md` is the design.
//!
//! An account is bound for life to a directory entry by a REQUIRED
//! External Account Binding; NO CHALLENGE DIALS OUT — an identifier the
//! bound entry owns gets a `valid` authorization at newOrder, one it does
//! not own fails newOrder `rejectedIdentifier`; everything about the
//! certificate is the core's.
//!
//! **THE REQUEST PIPELINE'S ORDER IS THE CONTRACT** ([`Acme::authenticate`]):
//! media type, size, flattened JWS, protected header, `alg`, the jwk/kid
//! rule, the nonce's MAC and expiry, `url`, the account or the key, the
//! signature, the nonce SPENT, the throttle, the payload.
//!
//! **EVERY ANSWER CARRIES A FRESH `Replay-Nonce`, `Link rel="index"` AND
//! `Cache-Control: no-store`**, refusals and the directory included.
//!
//! Cells are not ported (`placeRequest()`): a single-cell service places
//! nothing, which is what this runtime is.

pub mod jws;
pub mod store;

use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_core::errors::{codes, ErrorCode};
use sts_core::realm;

use self::jws::AcmeRefusal;
use self::store::AcmeStore;
use crate::core::csr::Requested;
use crate::core::issue::IssueSpec;
use crate::core::{str_of, Core, Entry, Principal, Refusal};
use crate::http::{Reply, Req};
use crate::model;

/// Where the ACME server answers.
pub const PREFIX: &str = "/enroll/acme";
const FAMILY: &str = "acme";
const ORDERS_PER_PAGE: usize = 100;
const RENEWAL_RETRY_AFTER_S: i64 = 21600;

/// What each issued profile is, for the directory's `meta.profiles`.
pub const PROFILE_DESCRIPTIONS: &[(&str, &str)] = &[
    ("tls-server", "A TLS server certificate (serverAuth) for host names registered on the account's entry."),
    ("tls-client", "A TLS client certificate (clientAuth) naming the entry."),
    ("tls-server-client", "serverAuth and clientAuth, for host names registered on the entry."),
    ("digital-signature", "A signing certificate (digitalSignature, nonRepudiation) naming the entry."),
    ("key-encipherment", "A key-encipherment certificate naming the entry."),
    ("code-signing", "A code-signing certificate (codeSigning) naming the entry."),
    ("email", "An S/MIME certificate (emailProtection) for the person's own mail address."),
    ("timestamping", "A time-stamping authority certificate (timeStamping)."),
    ("smartcard-logon", "A smartcard logon certificate carrying the person's user principal name (userPrincipalName, else mail)."),
];

fn id_ok(id: &str) -> bool {
    (8..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A request's context: its URLs, and who it names once read.
struct Ctx<'a> {
    req: &'a Req,
    operation: &'static str,
    base: String,
    identity: String,
    principal: Option<String>,
    target: Option<String>,
    profile: Option<String>,
    /// Headers a handler set before answering (`Location`, `Link`,
    /// `Retry-After`).
    pending: Vec<(String, String, bool)>,
}

impl Ctx<'_> {
    fn url(&self, tail: &str) -> String {
        format!("{}{}{}", self.base, PREFIX, tail)
    }
    fn account(&self, id: &str) -> String {
        self.url(&format!("/account/{}", id))
    }
    fn set(&mut self, name: &str, value: String) {
        self.pending.push((name.to_string(), value, false));
    }
    fn append(&mut self, name: &str, value: String) {
        self.pending.push((name.to_string(), value, true));
    }
}

/// What `authenticate()` answers.
struct Signed {
    header: Json,
    payload: Option<Json>,
    account: Option<Json>,
    account_key: Option<jws::AccountKey>,
}

/// The ACME server.
pub struct Acme {
    core: Arc<Core>,
    store: AcmeStore,
}

fn account_entry(account: &Json) -> Entry {
    account
        .get("entry")
        .and_then(Entry::from_json)
        .unwrap_or_default()
}

impl Acme {
    /// Builds the server over the core and its stores.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(core: Arc<Core>, store: AcmeStore) -> Arc<Acme> {
        Arc::new(Acme { core, store })
    }

    fn held(&self, id: &str, value: Json) -> Json {
        let problems = model::undeclared(FAMILY, id, &value);
        if !problems.is_empty() {
            tracing::error!(
                "{}the ACME {} answer is not its model's: {}",
                sts_core::log::tag(codes::STS_ACME_0100.as_str()),
                id,
                problems.join("; ")
            );
        }
        value
    }

    fn record(&self, ctx: &Ctx<'_>, detail: Json) {
        let mut row = json!({ "operation": ctx.operation, "principal": ctx.principal, "target": ctx.target });
        if let (Some(r), Json::Object(d)) = (row.as_object_mut(), detail) {
            for (k, v) in d {
                r.insert(k, v);
            }
        }
        self.core.monitor().record(FAMILY, &row);
    }

    fn common_headers(&self, ctx: &Ctx<'_>, reply: &mut Reply) {
        let lifetime = self
            .core
            .settings()
            .value_of("acme.nonceLifetimeS")
            .as_int();
        reply.set(
            "Replay-Nonce",
            &jws::mint_nonce(&realm::current_id(), lifetime),
        );
        reply.set("Cache-Control", "no-store");
        for (name, value, append) in &ctx.pending {
            if *append {
                reply.append(name, value);
            } else {
                reply.set(name, value);
            }
        }
        reply.append(
            "Link",
            &format!("<{}>;rel=\"index\"", ctx.url("/directory")),
        );
    }

    fn send_json(
        &self,
        ctx: &Ctx<'_>,
        status: u16,
        body: &Json,
        location: Option<String>,
    ) -> Reply {
        let mut reply = Reply::new(status);
        self.common_headers(ctx, &mut reply);
        if let Some(l) = location {
            reply.set("Location", &l);
        }
        reply.set("Content-Type", "application/json; charset=utf-8");
        reply.body = serde_json::to_string_pretty(body)
            .unwrap_or_default()
            .into_bytes();
        reply
    }

    fn send_problem(
        &self,
        ctx: &Ctx<'_>,
        status: u16,
        code: ErrorCode,
        body: Json,
    ) -> Reply {
        self.record(ctx, json!({ "outcome": "refused", "status": status, "errorCode": code.as_str() }));
        let kind = str_of(&body, "type")
            .trim_start_matches(jws::ERROR_PREFIX)
            .to_string();
        let mut types = vec![kind];
        for one in body
            .get("subproblems")
            .and_then(Json::as_array)
            .cloned()
            .unwrap_or_default()
        {
            types.push(
                str_of(&one, "type")
                    .trim_start_matches(jws::ERROR_PREFIX)
                    .to_string(),
            );
        }
        for t in &types {
            if model::unknown_term(FAMILY, "problems", t) {
                tracing::error!(
                    "{}the ACME error type \"{}\" is not one models/enrollment/acme.tsp declares.",
                    sts_core::log::tag(codes::STS_ACME_0101.as_str()),
                    t
                );
            }
        }
        let body = self.held("problem", body);
        let mut reply = Reply::new(status);
        self.common_headers(ctx, &mut reply);
        reply.mark(code);
        reply.set("Content-Type", "application/problem+json; charset=utf-8");
        reply.body = serde_json::to_string_pretty(&body)
            .unwrap_or_default()
            .into_bytes();
        reply
    }

    /// `acmeProblem(ctx, status, type, code, detail, extra)`.
    fn problem(
        &self,
        ctx: &Ctx<'_>,
        status: u16,
        kind: &str,
        code: ErrorCode,
        detail: &str,
        extra: Json,
    ) -> Reply {
        let shown: Vec<u16> = detail.encode_utf16().take(2000).collect();
        let mut body = json!({
            "type": format!("{}{}", jws::ERROR_PREFIX, kind),
            "detail": String::from_utf16_lossy(&shown),
            "status": status,
        });
        if let (Some(b), Json::Object(e)) = (body.as_object_mut(), extra) {
            for (k, v) in e {
                if k == "subproblems" {
                    let list: Vec<Json> = v
                        .as_array()
                        .cloned()
                        .unwrap_or_default()
                        .into_iter()
                        .map(|mut one| {
                            let t = format!(
                                "{}{}",
                                jws::ERROR_PREFIX,
                                str_of(&one, "type")
                            );
                            one["type"] = Json::from(t);
                            one
                        })
                        .collect();
                    b.insert(k, Json::Array(list));
                } else {
                    b.insert(k, v);
                }
            }
        }
        let uncounted: Vec<String> = model::rows(FAMILY, "problems")
            .iter()
            .filter(|r| r.get("counted") == Some(&Json::Bool(false)))
            .map(|r| str_of(r, "name").to_string())
            .collect();
        if !uncounted.iter().any(|u| u == kind) && status != 405 {
            self.core
                .count_failure(FAMILY, &ctx.req.address, &ctx.identity);
        }
        self.send_problem(ctx, status, code, body)
    }

    fn send_refusal(&self, ctx: &Ctx<'_>, r: AcmeRefusal) -> Reply {
        self.problem(ctx, r.status, &r.kind, r.code, &r.detail, r.extra)
    }

    /// `coreRefusal(ctx, refusal, fallbackCode)`: a core refusal in ACME's
    /// vocabulary, the core's code kept.
    fn core_refusal(&self, ctx: &mut Ctx<'_>, r: &Refusal) -> Reply {
        let code = r.code.as_str();
        let n = |range: &str| {
            code.strip_prefix(range).and_then(|s| s.parse::<u32>().ok())
        };
        let enroll = n("STS-ENROLL-");
        let (kind, status) = match enroll {
            Some(50..=56) => ("rejectedIdentifier", 400),
            Some(31) | Some(32) => ("badPublicKey", 400),
            Some(30..=39) => ("badCSR", 400),
            Some(1..=3) => ("invalidProfile", 400),
            Some(61) => {
                ctx.set("Retry-After", Core::retry_after_of(r).to_string());
                ("rateLimited", 429)
            }
            _ if matches!(r.status, 401 | 403 | 404 | 409) => {
                ("unauthorized", 403)
            }
            _ if r.status == 400 => ("malformed", 400),
            _ => (
                "serverInternal",
                if r.status >= 500 { r.status } else { 500 },
            ),
        };
        self.problem(ctx, status, kind, r.code, &r.sentence, json!({}))
    }

    /// The gate: turned off, the transport, the throttle.
    fn gate_refused(&self, ctx: &mut Ctx<'_>) -> Option<Reply> {
        if matches!(
            self.core.settings().value_of("acme.enabled"),
            sts_core::settings::SettingValue::Bool(false)
        ) {
            return Some(self.problem(
                ctx,
                503,
                "serverInternal",
                codes::STS_ACME_0001,
                "ACME is turned off in this realm (acme.enabled).",
                json!({}),
            ));
        }
        if let Some(t) = self.core.transport_refusal(ctx.req.over_tls, FAMILY) {
            return Some(self.core_refusal(ctx, &t));
        }
        if let Some(t) =
            self.core.throttled(FAMILY, &ctx.req.address, &ctx.identity)
        {
            return Some(self.core_refusal(ctx, &t));
        }
        None
    }

    fn operations() -> Vec<(regex::Regex, String)> {
        model::operations(FAMILY)
            .into_iter()
            .filter_map(|op| {
                let re = format!(
                    "(?i)^{}/?$",
                    regex::escape(&op.path).replace(":id", "[^/]+")
                );
                regex::Regex::new(&re)
                    .ok()
                    .map(|r| (r, op.methods.join(", ")))
            })
            .collect()
    }

    /// Answers a request under `/enroll/acme`, or `None` for a path that
    /// is no ACME resource (the 404 every unrouted path answers).
    #[tracing::instrument(level = "debug", skip_all, fields(path = %req.path))]
    pub async fn handle(&self, req: &Req) -> Option<Reply> {
        let tail = strip_prefix_ci(&req.path, PREFIX)?;
        let segments: Vec<String> = tail
            .trim_end_matches('/')
            .split('/')
            .skip(1)
            .map(|s| percent_decode(s))
            .collect();
        let seg: Vec<&str> = segments.iter().map(String::as_str).collect();
        let lower: Vec<String> = seg.iter().map(|s| s.to_lowercase()).collect();
        let l: Vec<&str> = lower.iter().map(String::as_str).collect();
        let method = req.method.as_str();
        let get = method == "GET" || method == "HEAD";
        let route: Option<&'static str> = match (method, l.as_slice()) {
            (_, ["directory"]) if get => Some("directory"),
            ("HEAD", ["new-nonce"]) => Some("new-nonce-head"),
            ("GET", ["new-nonce"]) => Some("new-nonce"),
            ("POST", ["new-account"]) => Some("new-account"),
            ("POST", ["account", _]) => Some("account"),
            ("POST", ["account", _, "orders"]) => Some("orders"),
            ("POST", ["new-order"]) => Some("new-order"),
            ("POST", ["order", _]) => Some("order"),
            ("POST", ["order", _, "finalize"]) => Some("finalize"),
            ("POST", ["authz", _]) => Some("authz"),
            ("POST", ["challenge", _]) => Some("challenge"),
            ("POST", ["cert", _]) => Some("cert"),
            ("POST", ["revoke-cert"]) => Some("revoke-cert"),
            ("POST", ["key-change"]) => Some("key-change"),
            (_, ["renewal-info", _]) if get => Some("renewal-info"),
            _ => None,
        };
        let param = seg.get(1).map(|s| s.to_string()).unwrap_or_default();
        let Some(route) = route else {
            let path = format!("/{}", tail.trim_start_matches('/'));
            let row = Acme::operations()
                .into_iter()
                .find(|(re, _)| re.is_match(&path))?;
            let mut ctx = self.context(req, "method-not-allowed");
            ctx.set("Allow", row.1.clone());
            return Some(self.problem(
                &ctx,
                405,
                "malformed",
                codes::STS_ACME_0026,
                &format!(
                    "This ACME resource answers {} (RFC 8555 section 6.3).",
                    row.1
                ),
                json!({}),
            ));
        };
        let operation: &'static str = match route {
            "new-nonce-head" => "new-nonce",
            other => other,
        };
        let mut ctx = self.context(req, operation);
        if let Some(refused) = self.gate_refused(&mut ctx) {
            return Some(refused);
        }
        Some(match route {
            "directory" => {
                self.record(
                    &ctx,
                    json!({ "outcome": "answered", "status": 200 }),
                );
                let body = self.directory_json(&ctx);
                self.send_json(&ctx, 200, &body, None)
            }
            "new-nonce-head" | "new-nonce" => {
                let status = if route == "new-nonce" { 204 } else { 200 };
                self.record(
                    &ctx,
                    json!({ "outcome": "answered", "status": status }),
                );
                let mut reply = Reply::new(status);
                self.common_headers(&ctx, &mut reply);
                reply
            }
            "new-account" => self.new_account(&mut ctx).await,
            "account" => self.account(&mut ctx, &param).await,
            "orders" => self.orders(&mut ctx, &param).await,
            "new-order" => self.new_order(&mut ctx).await,
            "order" => self.order(&mut ctx, &param).await,
            "finalize" => self.finalize(&mut ctx, &param).await,
            "authz" => self.authz(&mut ctx, &param).await,
            "challenge" => self.challenge(&mut ctx, &param).await,
            "cert" => self.cert(&mut ctx, &param).await,
            "revoke-cert" => self.revoke_cert(&mut ctx).await,
            "key-change" => self.key_change(&mut ctx).await,
            _ => self.renewal_info(&mut ctx, &param),
        })
    }

    fn context<'a>(&self, req: &'a Req, operation: &'static str) -> Ctx<'a> {
        Ctx {
            req,
            operation,
            base: req.base.clone(),
            identity: String::new(),
            principal: None,
            target: None,
            profile: None,
            pending: Vec::new(),
        }
    }

    // -----------------------------------------------------------------
    // A SIGNED REQUEST, READ AND AUTHENTICATED.
    // -----------------------------------------------------------------

    /// `authenticate(ctx, { key })`: `Err` is the problem already built.
    async fn authenticate(
        &self,
        ctx: &mut Ctx<'_>,
        key: &str,
    ) -> Result<Signed, Reply> {
        let req = ctx.req;
        if !jws::is_jose_json(&req.header("content-type")) {
            return Err(self.problem(ctx, 415, "malformed", codes::STS_ACME_0010, "An ACME request body is application/jose+json (RFC 8555 section 6.2).", json!({})));
        }
        let max = self
            .core
            .settings()
            .value_of("acme.maxRequestBytes")
            .as_int() as f64;
        let declared = req
            .header("content-length")
            .trim()
            .parse::<f64>()
            .unwrap_or(0.0);
        let actual = req.body.len() as f64;
        if declared > max || actual > max {
            return Err(self.problem(
                ctx,
                413,
                "malformed",
                codes::STS_ACME_0011,
                &format!("The request body is larger than acme.maxRequestBytes ({} bytes).", max as i64),
                json!({}),
            ));
        }
        let text = req
            .text
            .clone()
            .unwrap_or_else(|| String::from_utf8_lossy(&req.body).into_owned());
        let parts =
            jws::parse_body(&text).map_err(|r| self.send_refusal(ctx, r))?;
        let header = jws::parse_protected_header(&parts)
            .map_err(|r| self.send_refusal(ctx, r))?;
        let alg = str_of(&header, "alg").to_string();
        jws::check_algorithm(&alg).map_err(|r| self.send_refusal(ctx, r))?;
        let has_jwk = header.get("jwk").is_some();
        let has_kid = header.get("kid").is_some();
        if has_jwk == has_kid
            || (key == "jwk" && !has_jwk)
            || (key == "kid" && !has_kid)
        {
            let takes = if key == "either" {
                "either".to_string()
            } else {
                format!("\"{}\"", key)
            };
            return Err(self.problem(
                ctx,
                400,
                "malformed",
                codes::STS_ACME_0020,
                &format!(
                    "The protected header must carry exactly one of \"jwk\" and \"kid\", and this \
                     resource takes {} (RFC 8555 section 6.2).",
                    takes
                ),
                json!({}),
            ));
        }
        let nonce =
            jws::check_nonce(str_of(&header, "nonce"), &realm::current_id());
        let (nonce_id, nonce_expires) = match nonce {
            jws::NonceCheck::Ok { id, expires_s } => (id, expires_s),
            jws::NonceCheck::Expired => {
                return Err(self.problem(ctx, 400, "badNonce", codes::STS_ACME_0017, "The Replay-Nonce has expired. Retry with the one on this response.", json!({})))
            }
            _ => {
                return Err(self.problem(
                    ctx,
                    400,
                    "badNonce",
                    codes::STS_ACME_0016,
                    "The Replay-Nonce is missing or is not one this server issued in this realm. Retry with the one on this response.",
                    json!({}),
                ))
            }
        };
        let expected_url = format!("{}{}", req.base, req.path);
        if str_of(&header, "url") != expected_url {
            return Err(self.problem(
                ctx,
                403,
                "unauthorized",
                codes::STS_ACME_0019,
                "The protected header's \"url\" is not the URL this request was sent to (RFC 8555 section 6.4).",
                json!({}),
            ));
        }
        let mut account = None;
        let mut account_key = None;
        let jwk: Json;
        if has_kid {
            let prefix = ctx.url("/account/");
            let kid = str_of(&header, "kid");
            let id = kid.strip_prefix(&prefix).unwrap_or("");
            let found = if id_ok(id) {
                self.store.get_account(id)
            } else {
                None
            };
            ctx.identity = found
                .as_ref()
                .map(|a| format!("account:{}", str_of(a, "id")))
                .unwrap_or_default();
            let Some(found) = found else {
                return Err(self.problem(ctx, 400, "accountDoesNotExist", codes::STS_ACME_0022, "The \"kid\" is not the URL of an account on this server in this realm.", json!({})));
            };
            ctx.principal = Some(format!("account:{}", str_of(&found, "id")));
            ctx.target = found
                .get("entry")
                .and_then(Entry::from_json)
                .map(|e| e.uri());
            if str_of(&found, "status") != "valid" {
                return Err(self.problem(
                    ctx,
                    403,
                    "unauthorized",
                    codes::STS_ACME_0023,
                    &format!(
                        "The account is {}; a deactivated account authorizes nothing (RFC 8555 section 7.3.6).",
                        str_of(&found, "status")
                    ),
                    json!({}),
                ));
            }
            if !jws::algorithm_fits_key(&alg, &found["jwk"]) {
                return Err(self.problem(ctx, 400, "malformed", codes::STS_ACME_0021, "The JWS \"alg\" cannot have been made with this account's key.", json!({})));
            }
            jwk = found["jwk"].clone();
            account = Some(found);
        } else {
            let k = jws::check_account_key(&header["jwk"], &alg)
                .map_err(|r| self.send_refusal(ctx, r))?;
            ctx.identity = format!("key:{}", k.thumbprint);
            jwk = k.jwk.clone();
            account_key = Some(k);
        }
        jws::verify_flattened(&parts, &jwk, &alg)
            .map_err(|r| self.send_refusal(ctx, r))?;
        let max_nonces = self
            .core
            .settings()
            .value_of("acme.maxSpentNonces")
            .as_int()
            .max(1) as usize;
        if !self.store.spend_nonce(&nonce_id, nonce_expires, max_nonces) {
            return Err(self.problem(ctx, 400, "badNonce", codes::STS_ACME_0018, "That Replay-Nonce has already been used. Retry with the one on this response.", json!({})));
        }
        let remaining = nonce_expires as f64 * 1000.0 - crate::core::now_ms();
        let ttl = (remaining + 60_000.0).max(60_000.0);
        match self.core.claims().claim("acme.nonce", &nonce_id, "", ttl).await {
            Ok(_) => {}
            Err(sts_cluster::scheduler::ClaimRefused::Held) => {
                return Err(self.problem(ctx, 400, "badNonce", codes::STS_ACME_0018, "That Replay-Nonce has already been used. Retry with the one on this response.", json!({})))
            }
            Err(e) => {
                tracing::error!(
                    "{}acme: a Replay-Nonce could not be proved unspent ({:?}); the request is refused.",
                    sts_core::log::tag(codes::STS_ACME_0099.as_str()),
                    e
                );
                return Err(self.problem(ctx, 500, "serverInternal", codes::STS_ACME_0099, "The server could not check the Replay-Nonce. Retry.", json!({})));
            }
        }
        if let Some(t) =
            self.core.throttled(FAMILY, &req.address, &ctx.identity)
        {
            return Err(self.core_refusal(ctx, &t));
        }
        let payload =
            jws::read_payload(&parts).map_err(|r| self.send_refusal(ctx, r))?;
        Ok(Signed {
            header,

            payload,
            account,
            account_key,
        })
    }

    fn same_account(
        &self,
        ctx: &Ctx<'_>,
        signed: &Signed,
        id: &str,
    ) -> Option<Reply> {
        let mine = signed
            .account
            .as_ref()
            .map(|a| str_of(a, "id").to_string())
            .unwrap_or_default();
        (mine != id).then(|| {
            self.problem(ctx, 403, "unauthorized", codes::STS_ACME_0027, "The resource belongs to a different account from the one that signed this request.", json!({}))
        })
    }

    fn require_post_as_get(
        &self,
        ctx: &Ctx<'_>,
        signed: &Signed,
    ) -> Option<Reply> {
        signed.payload.is_some().then(|| {
            self.problem(ctx, 400, "malformed", codes::STS_ACME_0025, "This resource is read with POST-as-GET: an empty payload (RFC 8555 section 6.3).", json!({}))
        })
    }

    fn missing(&self, ctx: &Ctx<'_>, what: &str) -> Reply {
        self.problem(
            ctx,
            404,
            "malformed",
            codes::STS_ACME_0028,
            &format!("There is no such {} on this server in this realm.", what),
            json!({}),
        )
    }

    // -----------------------------------------------------------------
    // THE SHAPES OF THE RESOURCES.
    // -----------------------------------------------------------------

    fn account_json(&self, ctx: &Ctx<'_>, account: &Json) -> Json {
        self.held(
            "account",
            json!({
                "status": account["status"],
                "contact": account.get("contact").cloned().unwrap_or(json!([])),
                "termsOfServiceAgreed": account.get("termsOfServiceAgreed").and_then(Json::as_bool).unwrap_or(false),
                "orders": ctx.url(&format!("/account/{}/orders", str_of(account, "id"))),
                "createdAt": account["createdAt"],
            }),
        )
    }

    fn is_expired(when: &str) -> bool {
        !when.is_empty() && crate::core::ms_of(when) <= crate::core::now_ms()
    }

    fn authz_status(&self, authz: Option<&Json>) -> String {
        let Some(a) = authz else {
            return "invalid".into();
        };
        let status = str_of(a, "status");
        if status != "valid" {
            return status.to_string();
        }
        if Acme::is_expired(str_of(a, "expires")) {
            "expired".into()
        } else {
            "valid".into()
        }
    }

    fn order_status(&self, order: &Json) -> String {
        let status = str_of(order, "status");
        if status == "valid" || status == "processing" {
            return status.to_string();
        }
        if Acme::is_expired(str_of(order, "expires")) {
            return "invalid".into();
        }
        let broken = order
            .get("authorizationIds")
            .and_then(Json::as_array)
            .cloned()
            .unwrap_or_default()
            .iter()
            .any(|id| {
                self.authz_status(
                    self.store
                        .get_authorization(id.as_str().unwrap_or(""))
                        .as_ref(),
                ) != "valid"
            });
        if broken {
            "invalid".into()
        } else {
            "ready".into()
        }
    }

    fn order_json(&self, ctx: &Ctx<'_>, order: &Json) -> Json {
        let status = self.order_status(order);
        let authorizations: Vec<String> = order
            .get("authorizationIds")
            .and_then(Json::as_array)
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|id| ctx.url(&format!("/authz/{}", id.as_str().unwrap_or(""))))
            .collect();
        let mut out = json!({
            "status": status,
            "expires": order["expires"],
            "identifiers": order["identifiers"],
            "profile": order["profile"],
            "authorizations": authorizations,
            "finalize": ctx.url(&format!("/order/{}/finalize", str_of(order, "id"))),
        });
        if order
            .get("replaces")
            .is_some_and(|r| !r.is_null() && r != &json!(""))
        {
            out["replaces"] = order["replaces"].clone();
        }
        if status == "valid" && !str_of(order, "certificateId").is_empty() {
            out["certificate"] = Json::from(
                ctx.url(&format!("/cert/{}", str_of(order, "certificateId"))),
            );
        }
        self.held("order", out)
    }

    fn challenge_json(&self, ctx: &Ctx<'_>, authz: &Json) -> Json {
        let status = self.authz_status(Some(authz));
        let mut out = json!({
            "type": model::names(FAMILY, "challenge-types").into_iter().next().unwrap_or_default(),
            "url": ctx.url(&format!("/challenge/{}", str_of(authz, "id"))),
            "status": if status == "valid" { "valid" } else { "invalid" },
        });
        // `validated` and `token` as JSON.stringify writes them: an
        // undefined member is left out.
        for k in ["validated", "token"] {
            if let Some(v) = authz.get(k).filter(|v| !v.is_null()) {
                out[k] = v.clone();
            }
        }
        out
    }

    fn authz_json(&self, ctx: &Ctx<'_>, authz: &Json) -> Json {
        let mut out = json!({
            "identifier": authz["identifier"],
            "status": self.authz_status(Some(authz)),
            "expires": authz["expires"],
            "challenges": [self.challenge_json(ctx, authz)],
        });
        if authz.get("wildcard") == Some(&Json::Bool(true)) {
            out["wildcard"] = Json::Bool(true);
        }
        self.held("authorization", out)
    }

    fn directory_json(&self, ctx: &Ctx<'_>) -> Json {
        let mut profiles = serde_json::Map::new();
        for id in self.core.allowed_profiles(FAMILY, None) {
            let description = PROFILE_DESCRIPTIONS
                .iter()
                .find(|(p, _)| *p == id)
                .map(|(_, d)| d.to_string())
                .unwrap_or_else(|| id.clone());
            profiles.insert(id, Json::from(description));
        }
        self.held(
            "directory",
            json!({
                "newNonce": ctx.url("/new-nonce"),
                "newAccount": ctx.url("/new-account"),
                "newOrder": ctx.url("/new-order"),
                "revokeCert": ctx.url("/revoke-cert"),
                "keyChange": ctx.url("/key-change"),
                "renewalInfo": ctx.url("/renewal-info"),
                "meta": {
                    "externalAccountRequired": true,
                    "website": format!("{}/admin/acme", ctx.base),
                    "profiles": profiles,
                },
            }),
        )
    }

    // -----------------------------------------------------------------
    // THE RESOURCES.
    // -----------------------------------------------------------------

    async fn new_account(&self, ctx: &mut Ctx<'_>) -> Reply {
        let signed = match self.authenticate(ctx, "jwk").await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let payload = signed.payload.clone().unwrap_or(json!({}));
        let checked = jws::check_payload(&payload, "new-account", "newAccount");
        let body = match (checked, signed.payload.is_none()) {
            (Ok(_), true) => {
                return self.problem(
                    ctx,
                    400,
                    "malformed",
                    codes::STS_ACME_0025,
                    "A newAccount request carries a payload.",
                    json!({}),
                )
            }
            (Err(r), _) => {
                return self.problem(
                    ctx,
                    400,
                    "malformed",
                    codes::STS_ACME_0025,
                    &r.detail,
                    json!({}),
                )
            }
            (Ok(v), false) => v,
        };
        let Some(key) = signed.account_key.clone() else {
            return self.problem(ctx, 400, "malformed", codes::STS_ACME_0020, "The protected header must carry exactly one of \"jwk\" and \"kid\", and this resource takes \"jwk\" (RFC 8555 section 6.2).", json!({}));
        };
        if let Some(existing) =
            self.store.account_by_thumbprint(&key.thumbprint)
        {
            ctx.principal =
                Some(format!("account:{}", str_of(&existing, "id")));
            ctx.target = existing
                .get("entry")
                .and_then(Entry::from_json)
                .map(|e| e.uri());
            self.record(ctx, json!({ "outcome": "answered", "status": 200 }));
            let body = self.account_json(ctx, &existing);
            let location = ctx.account(str_of(&existing, "id"));
            return self.send_json(ctx, 200, &body, Some(location));
        }
        if body.get("onlyReturnExisting") == Some(&Json::Bool(true)) {
            return self.problem(
                ctx,
                400,
                "accountDoesNotExist",
                codes::STS_ACME_0030,
                "No account exists for this key in this realm.",
                json!({}),
            );
        }
        let contact: Vec<String> = body
            .get("contact")
            .and_then(Json::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let contacts = match jws::check_contacts(&contact) {
            Ok(c) => c,
            Err(r) => return self.send_refusal(ctx, r),
        };
        let Some(eab_value) =
            body.get("externalAccountBinding").filter(|v| !v.is_null())
        else {
            return self.problem(
                ctx,
                403,
                "externalAccountRequired",
                codes::STS_ACME_0031,
                "This server requires an External Account Binding (RFC 8555 section 7.3.4). An EAB key is issued for one person or application on the user portal, the console or /admin-api.",
                json!({}),
            );
        };
        let eab = match jws::parse_eab(
            eab_value,
            &ctx.url("/new-account"),
            &key.thumbprint,
        ) {
            Ok(e) => e,
            Err(r) => return self.send_refusal(ctx, r),
        };
        ctx.principal = Some(format!("eab:{}", eab.kid));
        ctx.identity = format!("eab:{}", eab.kid);
        let Some(found) = self.core.find_eab(&eab.kid) else {
            return self.problem(
                ctx,
                403,
                "unauthorized",
                codes::STS_ACME_0033,
                "The External Account Binding key is not known in this realm.",
                json!({}),
            );
        };
        if !jws::verify_eab_mac(&eab, &found.hmac_key) {
            return self.problem(ctx, 403, "unauthorized", codes::STS_ACME_0034, "The External Account Binding does not verify with the key issued under that key id.", json!({}));
        }
        if found.expired && found.bound_account.is_none() {
            return self.problem(
                ctx,
                403,
                "unauthorized",
                codes::STS_ACME_0035,
                "The External Account Binding key has expired.",
                json!({}),
            );
        }
        ctx.target = Some(found.entry.uri());
        if self
            .core
            .resolve_entry(&found.entry.kind, &found.entry.id)
            .is_err()
        {
            return self.problem(ctx, 403, "unauthorized", codes::STS_ACME_0048, "The entry that External Account Binding key was issued for no longer exists in this realm.", json!({}));
        }
        if let Err(r) = self.core.bind_eab_once(&eab.kid, &key.thumbprint).await
        {
            return self.problem(
                ctx,
                403,
                "unauthorized",
                r.code,
                &r.sentence,
                json!({}),
            );
        }
        let account = self.store.create_account(json!({
            "jwk": key.jwk,
            "thumbprint": key.thumbprint,
            "contact": contacts,
            "termsOfServiceAgreed": body.get("termsOfServiceAgreed") == Some(&Json::Bool(true)),
            "eabKid": eab.kid,
            "entry": found.entry.to_json(),
        }));
        ctx.principal = Some(format!("account:{}", str_of(&account, "id")));
        self.core.audit().record(&json!({
            "category": "protocol", "action": "enrollment.acme.account.create",
            "protocol": "ACME", "outcome": "success", "actor": format!("eab:{}", eab.kid),
            "target": found.entry.uri(),
            "summary": format!("an ACME account was created and bound for life to the {}", found.entry.label()),
            "detail": { "account": account["id"], "kid": eab.kid },
        }));
        self.record(ctx, json!({ "outcome": "redeemed", "status": 201 }));
        let body = self.account_json(ctx, &account);
        let location = ctx.account(str_of(&account, "id"));
        self.send_json(ctx, 201, &body, Some(location))
    }

    async fn account(&self, ctx: &mut Ctx<'_>, id: &str) -> Reply {
        let signed = match self.authenticate(ctx, "kid").await {
            Ok(s) => s,
            Err(r) => return r,
        };
        if let Some(r) = self.same_account(ctx, &signed, id) {
            return r;
        }
        let mut account = signed.account.clone().unwrap_or(json!({}));
        if let Some(payload) = &signed.payload {
            let update = match jws::check_payload(
                payload,
                "account-update",
                "account",
            ) {
                Ok(u) => u,
                Err(r) => return self.send_refusal(ctx, r),
            };
            let status = update.get("status").and_then(Json::as_str);
            if status.is_some_and(|s| s != "deactivated") {
                return self.problem(ctx, 400, "malformed", codes::STS_ACME_0038, "The only status a client may set on its account is \"deactivated\" (RFC 8555 section 7.3.6).", json!({}));
            }
            if let Some(list) = update.get("contact").and_then(Json::as_array) {
                let contact: Vec<String> = list
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect();
                match jws::check_contacts(&contact) {
                    Ok(c) => account["contact"] = json!(c),
                    Err(r) => return self.send_refusal(ctx, r),
                }
            }
            if status == Some("deactivated") {
                account["status"] = Json::from("deactivated");
                account["deactivatedAt"] =
                    Json::from(crate::core::iso(crate::core::now_ms()));
                self.core.audit().record(&json!({
                    "category": "protocol", "action": "enrollment.acme.account.deactivate",
                    "protocol": "ACME", "outcome": "success",
                    "actor": format!("account:{}", str_of(&account, "id")),
                    "target": ctx.target.clone().unwrap_or_default(),
                    "summary": "an ACME account deactivated itself",
                    "detail": { "account": account["id"] },
                }));
            }
            self.store.save_account(&account);
        }
        self.record(ctx, json!({ "outcome": "answered", "status": 200 }));
        let body = self.account_json(ctx, &account);
        let location = ctx.account(str_of(&account, "id"));
        self.send_json(ctx, 200, &body, Some(location))
    }

    async fn orders(&self, ctx: &mut Ctx<'_>, id: &str) -> Reply {
        let query = Json::Object(ctx.req.query_map());
        let checked =
            model::Body::of(FAMILY, "orders-query").map(|b| b.check(&query));
        let page = match checked {
            Some(Ok(v)) => v
                .get("page")
                .and_then(|p| {
                    p.as_str()
                        .and_then(|s| s.parse::<usize>().ok())
                        .or_else(|| p.as_u64().map(|n| n as usize))
                })
                .unwrap_or(1)
                .max(1),
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
                return self.problem(ctx, 400, "malformed", codes::STS_ACME_0082, &format!("The orders list takes one query parameter, \"page\": {}", detail), json!({}));
            }
            None => 1,
        };
        let signed = match self.authenticate(ctx, "kid").await {
            Ok(s) => s,
            Err(r) => return r,
        };
        if let Some(r) = self
            .same_account(ctx, &signed, id)
            .or_else(|| self.require_post_as_get(ctx, &signed))
        {
            return r;
        }
        let account = signed.account.clone().unwrap_or(json!({}));
        let ids: Vec<String> = account
            .get("orderIds")
            .and_then(Json::as_array)
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .filter(|id| {
                self.store
                    .get_order(id)
                    .is_some_and(|o| self.order_status(&o) != "invalid")
            })
            .collect();
        let shown: Vec<String> = ids
            .iter()
            .skip((page - 1) * ORDERS_PER_PAGE)
            .take(ORDERS_PER_PAGE)
            .map(|id| ctx.url(&format!("/order/{}", id)))
            .collect();
        if page * ORDERS_PER_PAGE < ids.len() {
            let next = format!(
                "<{}?page={}>;rel=\"next\"",
                ctx.url(&format!("/account/{}/orders", str_of(&account, "id"))),
                page + 1
            );
            ctx.append("Link", next);
        }
        self.record(ctx, json!({ "outcome": "answered", "status": 200 }));
        let body = self.held("orders", json!({ "orders": shown }));
        self.send_json(ctx, 200, &body, None)
    }

    fn ownership_problem(
        &self,
        resolved: &crate::core::Resolved,
        identifier: &Json,
    ) -> Option<String> {
        let kind = str_of(identifier, "type");
        let value = str_of(identifier, "value");
        if kind == "permanent-identifier" {
            if value == resolved.entry.id {
                return None;
            }
            let shown: String = value
                .encode_utf16()
                .take(120)
                .collect::<Vec<u16>>()
                .iter()
                .map(|&u| char::from_u32(u as u32).unwrap_or('\u{fffd}'))
                .collect();
            return Some(format!(
                "The permanent-identifier \"{}\" is not the {} this account is bound to. An account is issued certificates for its own entry only.",
                shown,
                resolved.entry.label()
            ));
        }
        let mut requested = Requested::default();
        match kind {
            "dns" => requested.dns.push(value.to_string()),
            "ip" => requested.ips.push(value.to_string()),
            "email" => requested.emails.push(value.to_string()),
            _ => {}
        }
        self.core
            .names_for(resolved, "digital-signature", &requested)
            .err()
            .map(|r| r.sentence)
    }

    async fn new_order(&self, ctx: &mut Ctx<'_>) -> Reply {
        let signed = match self.authenticate(ctx, "kid").await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let body = match &signed.payload {
            None => {
                return self.problem(
                    ctx,
                    400,
                    "malformed",
                    codes::STS_ACME_0025,
                    "A newOrder request carries a payload.",
                    json!({}),
                )
            }
            Some(p) => match jws::check_payload(p, "new-order", "newOrder") {
                Ok(v) => v,
                Err(r) => return self.send_refusal(ctx, r),
            },
        };
        let mut account = signed.account.clone().unwrap_or(json!({}));
        let entry = account_entry(&account);
        if body.get("notBefore").is_some() || body.get("notAfter").is_some() {
            return self.problem(
                ctx,
                400,
                "malformed",
                codes::STS_ACME_0043,
                "This server does not accept \"notBefore\" or \"notAfter\": a certificate's validity is acme.certificateLifetimeDays from issuance, shortened to the Issuing CA's own.",
                json!({}),
            );
        }
        let mut profile: Option<String> = None;
        if let Some(named) = body
            .get("profile")
            .and_then(Json::as_str)
            .filter(|p| !p.is_empty())
        {
            match self.core.check_profile(FAMILY, named, Some(&entry), false) {
                Ok(p) => {
                    ctx.profile = Some(p.clone());
                    profile = Some(p);
                }
                Err(r) => {
                    return self.problem(
                        ctx,
                        400,
                        "invalidProfile",
                        codes::STS_ACME_0044,
                        &r.sentence,
                        json!({}),
                    )
                }
            }
        }
        let Ok(resolved) = self.core.resolve_entry(&entry.kind, &entry.id)
        else {
            return self.problem(ctx, 403, "unauthorized", codes::STS_ACME_0048, "The entry this account is bound to no longer exists in this realm.", json!({}));
        };
        let types = model::names(FAMILY, "identifier-types");
        let mut identifiers: Vec<Json> = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        let mut unsupported: Vec<Json> = Vec::new();
        for one in body
            .get("identifiers")
            .and_then(Json::as_array)
            .cloned()
            .unwrap_or_default()
        {
            let kind = str_of(&one, "type").to_string();
            let raw = str_of(&one, "value").to_string();
            let clip = |s: &str, n: usize| -> String {
                let u: Vec<u16> = s.encode_utf16().take(n).collect();
                String::from_utf16_lossy(&u)
            };
            if !types.contains(&kind) {
                unsupported.push(json!({
                    "type": "unsupportedIdentifier",
                    "detail": "This server issues for dns, ip, email and permanent-identifier identifiers.",
                    "identifier": { "type": clip(&kind, 64), "value": clip(&raw, 256) },
                }));
                continue;
            }
            let mut value = jws::normal_identifier(&kind, &raw);
            if kind == "permanent-identifier" && !value.is_empty() {
                if let Some(named) = crate::core::entry_from_uri(&value) {
                    if named.kind == entry.kind {
                        value = named.id;
                    }
                }
            }
            if value.is_empty() {
                return self.problem(
                    ctx,
                    400,
                    "malformed",
                    codes::STS_ACME_0041,
                    &format!("The {} identifier \"{}\" is not a well-formed value of that type.", kind, clip(&raw, 120)),
                    json!({}),
                );
            }
            let key = format!(
                "{}:{}",
                kind,
                if kind == "email" {
                    value.to_lowercase()
                } else {
                    value.clone()
                }
            );
            if seen.contains(&key) {
                return self.problem(
                    ctx,
                    400,
                    "malformed",
                    codes::STS_ACME_0046,
                    &format!(
                        "The identifier {} appears twice.",
                        clip(&key, 160)
                    ),
                    json!({}),
                );
            }
            seen.push(key);
            identifiers.push(json!({ "type": kind, "value": value }));
        }
        if !unsupported.is_empty() {
            let n = unsupported.len();
            return self.problem(
                ctx,
                400,
                "unsupportedIdentifier",
                codes::STS_ACME_0040,
                &format!("{} identifier(s) are of a type this server does not issue for.", n),
                json!({ "subproblems": unsupported }),
            );
        }
        let kinds: Vec<String> = identifiers
            .iter()
            .map(|i| str_of(i, "type").to_string())
            .collect();
        let profile = match profile {
            Some(p) => p,
            None => {
                let chosen = self.core.profile_for_identifiers(
                    FAMILY,
                    &kinds,
                    Some(&entry),
                );
                match self.core.check_profile(
                    FAMILY,
                    &chosen,
                    Some(&entry),
                    false,
                ) {
                    Ok(p) => {
                        ctx.profile = Some(p.clone());
                        p
                    }
                    Err(r) => {
                        return self.problem(
                            ctx,
                            400,
                            "invalidProfile",
                            codes::STS_ACME_0044,
                            &r.sentence,
                            json!({}),
                        )
                    }
                }
            }
        };
        let rejected: Vec<Json> = identifiers
            .iter()
            .filter_map(|i| {
                self.ownership_problem(&resolved, i)
                    .map(|p| json!({ "type": "rejectedIdentifier", "detail": p, "identifier": i }))
            })
            .collect();
        if !rejected.is_empty() {
            let detail = if rejected.len() == 1 {
                str_of(&rejected[0], "detail").to_string()
            } else {
                format!(
                    "{} identifiers are not the {}'s to ask for.",
                    rejected.len(),
                    resolved.entry.label()
                )
            };
            return self.problem(
                ctx,
                400,
                "rejectedIdentifier",
                codes::STS_ACME_0042,
                &detail,
                json!({ "subproblems": rejected }),
            );
        }
        let has = |t: &str| kinds.iter().any(|k| k == t);
        let needs = if (profile == "tls-server"
            || profile == "tls-server-client")
            && !has("dns")
            && !has("ip")
        {
            format!("A {} order names at least one dns or ip identifier registered on the entry.", profile)
        } else if profile == "email" && !has("email") {
            "An email order names the person's mail as an email identifier (RFC 8823).".to_string()
        } else if profile == "smartcard-logon"
            && resolved.upn.is_empty()
            && resolved.mail.is_empty()
        {
            format!(
                "A smartcard-logon certificate carries a user principal name, and the {} has neither userPrincipalName nor mail.",
                resolved.entry.label()
            )
        } else {
            String::new()
        };
        if !needs.is_empty() {
            return self.problem(
                ctx,
                400,
                "malformed",
                codes::STS_ACME_0045,
                &needs,
                json!({}),
            );
        }
        let mut replaces = Json::Null;
        if let Some(text) = body.get("replaces").and_then(Json::as_str) {
            let old = jws::parse_cert_id(text)
                .and_then(|(_, id)| self.store.certificate_by_cert_id(&id));
            let Some(old) = old.filter(|o| account_entry(o) == entry) else {
                return self.problem(
                    ctx,
                    400,
                    "malformed",
                    codes::STS_ACME_0047,
                    "The \"replaces\" member does not name a certificate this account's entry was issued over ACME in this realm (RFC 9773 section 5).",
                    json!({}),
                );
            };
            if old
                .get("replacedBy")
                .is_some_and(|r| !r.is_null() && r != &json!(""))
            {
                return self.problem(ctx, 409, "alreadyReplaced", codes::STS_ACME_0049, "That certificate has already been replaced by another order (RFC 9773 section 5).", json!({}));
            }
            replaces = Json::from(text);
        }
        let lifetime = self
            .core
            .settings()
            .value_of("acme.orderLifetimeS")
            .as_int() as f64;
        let now = crate::core::now_ms();
        let expires = crate::core::iso(now + lifetime * 1000.0);
        let validated = crate::core::iso(now);
        let authz_ids: Vec<Json> = identifiers
            .iter()
            .map(|identifier| {
                let value = str_of(identifier, "value");
                let wildcard = str_of(identifier, "type") == "dns" && value.starts_with("*.");
                let token = jws::b64u(&sts_crypto::random::random_bytes(24).unwrap_or_default());
                let authz = self.store.create_authorization(json!({
                    "accountId": account["id"],
                    "identifier": { "type": identifier["type"],
                                    "value": if wildcard { &value[2..] } else { value } },
                    "wildcard": wildcard,
                    "expires": expires,
                    "validated": validated,
                    "token": token,
                }));
                authz["id"].clone()
            })
            .collect();
        let order = self.store.create_order(
            &mut account,
            json!({
                "identifiers": identifiers,
                "profile": profile,
                "authorizationIds": authz_ids,
                "expires": expires,
                "replaces": replaces,
            }),
        );
        self.record(
            ctx,
            json!({ "outcome": "answered", "status": 201, "profile": profile }),
        );
        let body = self.order_json(ctx, &order);
        let location = ctx.url(&format!("/order/{}", str_of(&order, "id")));
        self.send_json(ctx, 201, &body, Some(location))
    }

    fn owned_order(
        &self,
        ctx: &Ctx<'_>,
        signed: &Signed,
        id: &str,
    ) -> Result<Json, Reply> {
        let Some(order) = id_ok(id).then(|| self.store.get_order(id)).flatten()
        else {
            return Err(self.missing(ctx, "order"));
        };
        if let Some(r) =
            self.same_account(ctx, signed, str_of(&order, "accountId"))
        {
            return Err(r);
        }
        Ok(order)
    }

    async fn order(&self, ctx: &mut Ctx<'_>, id: &str) -> Reply {
        let signed = match self.authenticate(ctx, "kid").await {
            Ok(s) => s,
            Err(r) => return r,
        };
        if let Some(r) = self.require_post_as_get(ctx, &signed) {
            return r;
        }
        let order = match self.owned_order(ctx, &signed, id) {
            Ok(o) => o,
            Err(r) => return r,
        };
        self.record(ctx, json!({ "outcome": "answered", "status": 200, "profile": order["profile"] }));
        let body = self.order_json(ctx, &order);
        let location = ctx.url(&format!("/order/{}", str_of(&order, "id")));
        self.send_json(ctx, 200, &body, Some(location))
    }

    /// `csrNamesProblem(csr, order, entry)`: the CSR names exactly the
    /// order's identifiers, in both directions.
    fn csr_names_problem(
        &self,
        csr: &crate::core::csr::Csr,
        order: &Json,
        entry: &Entry,
    ) -> Option<String> {
        let key_of = |t: &str, v: &str| -> String {
            format!(
                "{}:{}",
                t,
                if t == "email" || t == "dns" {
                    v.to_lowercase()
                } else {
                    v.to_string()
                }
            )
        };
        let mut want: Vec<String> = Vec::new();
        for one in order
            .get("identifiers")
            .and_then(Json::as_array)
            .cloned()
            .unwrap_or_default()
        {
            let k = key_of(str_of(&one, "type"), str_of(&one, "value"));
            if !want.contains(&k) {
                want.push(k);
            }
        }
        let mut have: Vec<String> = Vec::new();
        let mut bad: Vec<String> = Vec::new();
        let add = |have: &mut Vec<String>, t: &str, v: &str| -> bool {
            let normal = jws::normal_identifier(t, v);
            if normal.is_empty() {
                return false;
            }
            let k = key_of(t, &normal);
            if !have.contains(&k) {
                have.push(k);
            }
            true
        };
        let r = &csr.requested;
        for one in &r.dns {
            if !add(&mut have, "dns", one) {
                bad.push(format!("dNSName {}", one));
            }
        }
        for one in &r.ips {
            if !add(&mut have, "ip", one) {
                bad.push(format!("iPAddress {}", one));
            }
        }
        for one in &r.emails {
            if !add(&mut have, "email", one) {
                bad.push(format!("rfc822Name {}", one));
            }
        }
        for one in &r.uris {
            match crate::core::entry_from_uri(one) {
                Some(named) if named.kind == entry.kind => {
                    let k = key_of("permanent-identifier", &named.id);
                    if !have.contains(&k) {
                        have.push(k);
                    }
                }
                _ => bad.push(format!("URI {}", one)),
            }
        }
        if !r.upns.is_empty() && str_of(order, "profile") != "smartcard-logon" {
            bad.push("a user principal name, which only a smartcard-logon order carries".into());
        }
        if !csr.common_name.is_empty() {
            let cn = &csr.common_name;
            let types = model::names(FAMILY, "identifier-types");
            match types
                .iter()
                .map(|t| key_of(t, cn))
                .find(|k| want.contains(k))
            {
                Some(k) => {
                    if !have.contains(&k) {
                        have.push(k);
                    }
                }
                None => {
                    let shown: Vec<u16> = cn.encode_utf16().take(120).collect();
                    bad.push(format!(
                        "the common name \"{}\"",
                        String::from_utf16_lossy(&shown)
                    ));
                }
            }
        }
        for k in &have {
            if !want.contains(k) {
                bad.push(k.clone());
            }
        }
        if !bad.is_empty() {
            return Some(format!(
                "The CSR names {}, which {} not an identifier of this order (RFC 8555 section 7.4).",
                bad.iter().take(5).cloned().collect::<Vec<_>>().join(", "),
                if bad.len() == 1 { "is" } else { "are" }
            ));
        }
        let missing: Vec<String> =
            want.iter().filter(|k| !have.contains(k)).cloned().collect();
        if !missing.is_empty() {
            return Some(format!(
                "The CSR does not name {}, which the order does. It must indicate exactly the order's identifiers (RFC 8555 section 7.4).",
                missing.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
            ));
        }
        None
    }

    async fn finalize(&self, ctx: &mut Ctx<'_>, id: &str) -> Reply {
        let signed = match self.authenticate(ctx, "kid").await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let mut order = match self.owned_order(ctx, &signed, id) {
            Ok(o) => o,
            Err(r) => return r,
        };
        ctx.profile = Some(str_of(&order, "profile").to_string());
        let checked = match &signed.payload {
            None => {
                return self.problem(
                    ctx,
                    400,
                    "malformed",
                    codes::STS_ACME_0025,
                    "A finalize request carries a payload with a \"csr\".",
                    json!({}),
                )
            }
            Some(p) => match jws::check_payload(p, "finalize", "finalize") {
                Ok(v) => v,
                Err(r) => return self.send_refusal(ctx, r),
            },
        };
        let status = self.order_status(&order);
        if status != "ready" {
            return self.problem(
                ctx,
                403,
                "orderNotReady",
                codes::STS_ACME_0050,
                &format!("The order is \"{}\", and only a \"ready\" order is finalized (RFC 8555 section 7.4).", status),
                json!({}),
            );
        }
        let Some(der) = jws::decode_b64url(str_of(&checked, "csr"), false)
        else {
            return self.problem(ctx, 400, "badCSR", codes::STS_ACME_0051, "The \"csr\" is not the base64url encoding of a DER CertificationRequest.", json!({}));
        };
        let csr = match self.core.parse_csr(&der, false) {
            Ok(c) => c,
            Err(r) => return self.core_refusal(ctx, &r),
        };
        let account = signed.account.clone().unwrap_or(json!({}));
        let entry = account_entry(&account);
        if let Some(mismatch) = self.csr_names_problem(&csr, &order, &entry) {
            return self.problem(
                ctx,
                400,
                "badCSR",
                codes::STS_ACME_0053,
                &mismatch,
                json!({}),
            );
        }
        let lifetime = crate::core::ms_of(str_of(&order, "expires"))
            - crate::core::now_ms();
        let ttl = ((if lifetime.is_finite() { lifetime } else { 0.0 })
            + 60_000.0)
            .max(60_000.0);
        let claim = match self.core.claims().claim("acme.finalize", id, "", ttl).await {
            Ok(c) => c,
            Err(sts_cluster::scheduler::ClaimRefused::Held) => {
                return self.problem(ctx, 403, "orderNotReady", codes::STS_ACME_0098, "The order is already being finalized (RFC 8555 section 7.4). Poll the order.", json!({}))
            }
            Err(e) => {
                tracing::error!(
                    "{}acme: an order could not be claimed for finalize ({:?}); refused.",
                    sts_core::log::tag(codes::STS_ACME_0099.as_str()),
                    e
                );
                return self.problem(ctx, 500, "serverInternal", codes::STS_ACME_0099, "The server could not finalize the order just now. Retry.", json!({}));
            }
        };
        let of = |t: &str| -> Vec<String> {
            order
                .get("identifiers")
                .and_then(Json::as_array)
                .cloned()
                .unwrap_or_default()
                .iter()
                .filter(|i| str_of(i, "type") == t)
                .map(|i| str_of(i, "value").to_string())
                .collect()
        };
        let requested = Requested {
            uris: vec![entry.uri()],
            dns: of("dns"),
            ips: of("ip"),
            emails: of("email"),
            upns: csr.requested.upns.clone(),
        };
        order["status"] = Json::from("processing");
        self.store.save_order(&order);
        let issued = self
            .core
            .issue(&IssueSpec {
                family: FAMILY.into(),
                profile: str_of(&order, "profile").to_string(),
                profile_defaulted: false,
                target: Some(entry.clone()),
                principal: Some(Principal {
                    kind: entry.kind.clone(),
                    id: entry.id.clone(),
                    admin: false,
                    has_entry: true,
                    via: "acme".into(),
                    realm: realm::current_id(),
                    ..Default::default()
                }),
                public_key_pem: csr.public_key_pem.clone(),
                key_alg: csr.key_alg.clone(),
                requested,
                key_source: "client".into(),
                via: "acme".into(),
                ..Default::default()
            })
            .await;
        let issued = match issued {
            Ok(i) => i,
            Err(r) => {
                order["status"] = Json::from("ready");
                self.store.save_order(&order);
                self.core.claims().release(&claim.handle).await;
                return self.core_refusal(ctx, &r);
            }
        };
        let serial = str_of(&issued.record, "serialHex").to_string();
        let facts = jws::pem_to_der(str_of(&issued.record, "certificatePem"))
            .and_then(|d| jws::certificate_facts(&d));
        let cert_id = facts
            .and_then(|f| f.aki)
            .map(|aki| jws::cert_id_of(&aki, &serial))
            .unwrap_or_default();
        let cert = self.store.record_certificate(json!({
            "accountId": account["id"],
            "orderId": order["id"],
            "serialHex": serial,
            "entry": entry.to_json(),
            "profile": order["profile"],
            "notBefore": issued.record["notBefore"],
            "notAfter": issued.record["notAfter"],
            "certId": cert_id,
            "replaces": order.get("replaces").cloned().unwrap_or(Json::Null),
        }));
        if let Some(r) = order
            .get("replaces")
            .and_then(Json::as_str)
            .filter(|r| !r.is_empty())
        {
            if let Some(mut old) = self.store.certificate_by_cert_id(r) {
                old["replacedBy"] = cert["id"].clone();
                self.store.save_certificate(&old);
            }
        }
        order["status"] = Json::from("valid");
        order["certificateId"] = cert["id"].clone();
        self.store.save_order(&order);
        self.record(ctx, json!({ "outcome": "issued", "status": 200, "profile": order["profile"], "serialHex": serial }));
        let body = self.order_json(ctx, &order);
        let location = ctx.url(&format!("/order/{}", str_of(&order, "id")));
        self.send_json(ctx, 200, &body, Some(location))
    }

    fn owned_authz(
        &self,
        ctx: &Ctx<'_>,
        signed: &Signed,
        id: &str,
    ) -> Result<Json, Reply> {
        let Some(authz) = id_ok(id)
            .then(|| self.store.get_authorization(id))
            .flatten()
        else {
            return Err(self.missing(ctx, "authorization"));
        };
        if let Some(r) =
            self.same_account(ctx, signed, str_of(&authz, "accountId"))
        {
            return Err(r);
        }
        Ok(authz)
    }

    async fn authz(&self, ctx: &mut Ctx<'_>, id: &str) -> Reply {
        let signed = match self.authenticate(ctx, "kid").await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let mut authz = match self.owned_authz(ctx, &signed, id) {
            Ok(a) => a,
            Err(r) => return r,
        };
        if let Some(p) = &signed.payload {
            if jws::check_payload(p, "authz-update", "authorization").is_err() {
                return self.problem(
                    ctx,
                    400,
                    "malformed",
                    codes::STS_ACME_0055,
                    "The only change a client may make to an authorization is {\"status\": \"deactivated\"} (RFC 8555 section 7.5.2).",
                    json!({}),
                );
            }
            authz["status"] = Json::from("deactivated");
            self.store.save_authorization(&authz);
        }
        self.record(ctx, json!({ "outcome": "answered", "status": 200 }));
        let body = self.authz_json(ctx, &authz);
        self.send_json(ctx, 200, &body, None)
    }

    async fn challenge(&self, ctx: &mut Ctx<'_>, id: &str) -> Reply {
        let signed = match self.authenticate(ctx, "kid").await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let authz = match self.owned_authz(ctx, &signed, id) {
            Ok(a) => a,
            Err(r) => return r,
        };
        if signed
            .payload
            .as_ref()
            .and_then(Json::as_object)
            .is_some_and(|o| !o.is_empty())
        {
            let kind = model::names(FAMILY, "challenge-types")
                .into_iter()
                .next()
                .unwrap_or_default();
            return self.problem(
                ctx,
                400,
                "malformed",
                codes::STS_ACME_0056,
                &format!("A response to an {} challenge is the empty object {{}} (RFC 8555 section 7.5.1).", kind),
                json!({}),
            );
        }
        ctx.append(
            "Link",
            format!(
                "<{}>;rel=\"up\"",
                ctx.url(&format!("/authz/{}", str_of(&authz, "id")))
            ),
        );
        self.record(ctx, json!({ "outcome": "answered", "status": 200 }));
        let body = self.held("challenge", self.challenge_json(ctx, &authz));
        self.send_json(ctx, 200, &body, None)
    }

    async fn cert(&self, ctx: &mut Ctx<'_>, id: &str) -> Reply {
        let signed = match self.authenticate(ctx, "kid").await {
            Ok(s) => s,
            Err(r) => return r,
        };
        if let Some(r) = self.require_post_as_get(ctx, &signed) {
            return r;
        }
        let Some(cert) =
            id_ok(id).then(|| self.store.get_certificate(id)).flatten()
        else {
            return self.missing(ctx, "certificate");
        };
        if let Some(r) =
            self.same_account(ctx, &signed, str_of(&cert, "accountId"))
        {
            return r;
        }
        let entry = account_entry(&cert);
        let wanted = crate::core::normal_serial(str_of(&cert, "serialHex"));
        let held = self.core.enrolled_of(&entry).into_iter().find(|one| {
            crate::core::normal_serial(str_of(one, "serialHex")) == wanted
        });
        let Some(held) =
            held.filter(|h| !str_of(h, "certificatePem").is_empty())
        else {
            return self.missing(ctx, "certificate");
        };
        let mut chain = vec![str_of(&held, "certificatePem").to_string()];
        for pem in held
            .get("chainPem")
            .and_then(Json::as_array)
            .cloned()
            .unwrap_or_default()
        {
            let pem = pem.as_str().unwrap_or("").to_string();
            let self_signed = sts_pki::x509::read::Certificate::from_pem(&pem)
                .ok()
                .is_some_and(|c| {
                    c.subject() == c.issuer()
                        && sts_pki::x509::read::verify_signature(&c, &c)
                            .unwrap_or(false)
                });
            if !self_signed {
                chain.push(pem);
            }
        }
        let body: String =
            chain.iter().map(|p| format!("{}\n", p.trim())).collect();
        self.record(ctx, json!({ "outcome": "answered", "status": 200, "profile": cert["profile"], "serialHex": cert["serialHex"] }));
        let mut reply = Reply::new(200);
        self.common_headers(ctx, &mut reply);
        reply.set("Content-Type", "application/pem-certificate-chain");
        reply.body = body.into_bytes();
        reply
    }

    async fn revoke_cert(&self, ctx: &mut Ctx<'_>) -> Reply {
        let signed = match self.authenticate(ctx, "either").await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let checked = match &signed.payload {
            None => return self.problem(ctx, 400, "malformed", codes::STS_ACME_0025, "A revokeCert request carries a payload with a \"certificate\".", json!({})),
            Some(p) => match jws::check_payload(p, "revoke", "revokeCert") {
                Ok(v) => v,
                Err(r) => return self.send_refusal(ctx, r),
            },
        };
        let code = checked.get("reason").and_then(Json::as_i64).unwrap_or(0);
        let Some(reason) = jws::revocation_reason(code) else {
            let accepted: Vec<String> = jws::revocation_codes()
                .iter()
                .map(|c| c.to_string())
                .collect();
            return self.problem(
                ctx,
                400,
                "badRevocationReason",
                codes::STS_ACME_0062,
                &format!("Reason code {} is not one this server accepts from a subscriber. It accepts {} (RFC 5280 section 5.3.1).", code, accepted.join(", ")),
                json!({}),
            );
        };
        let facts = jws::decode_b64url(str_of(&checked, "certificate"), false)
            .and_then(|d| jws::certificate_facts(&d));
        let Some(facts) = facts else {
            return self.problem(ctx, 400, "malformed", codes::STS_ACME_0060, "The \"certificate\" is not the base64url encoding of one DER certificate.", json!({}));
        };
        let found = self.core.find_enrolled(&facts.serial_hex, Some(FAMILY));
        let recorded = found
            .as_ref()
            .and_then(|f| jws::pem_to_der(str_of(&f.record, "certificatePem")));
        let Some(found) =
            found.filter(|_| recorded.as_deref() == Some(facts.der.as_slice()))
        else {
            return self.problem(
                ctx,
                404,
                "malformed",
                codes::STS_ACME_0061,
                "That certificate was not issued over ACME in this realm.",
                json!({}),
            );
        };
        ctx.target = Some(found.entry.uri());
        let authorized = match &signed.account {
            Some(account) => account_entry(account) == found.entry,
            None => {
                ctx.principal = Some("certificate-key".into());
                signed
                    .account_key
                    .as_ref()
                    .and_then(|k| jws::spki_of_jwk(&k.jwk))
                    .is_some_and(|spki| spki == facts.spki)
            }
        };
        if !authorized {
            return self.problem(
                ctx,
                403,
                "unauthorized",
                codes::STS_ACME_0063,
                "The request is signed neither by an account bound to the entry that holds this certificate nor by the certificate's own key.",
                json!({}),
            );
        }
        if found
            .record
            .get("revoked")
            .is_some_and(|r| !r.is_null() && r != &Json::Bool(false))
        {
            return self.problem(
                ctx,
                400,
                "alreadyRevoked",
                codes::STS_ACME_0064,
                "That certificate is already revoked.",
                json!({}),
            );
        }
        let by = ctx.principal.clone().unwrap_or_else(|| "acme".into());
        let done = match self.core.revoke_enrolled(
            str_of(&found.record, "serialHex"),
            &reason,
            &by,
            None,
            Some(FAMILY),
            false,
        ) {
            Ok(d) => d,
            Err(r) => return self.core_refusal(ctx, &r),
        };
        self.record(ctx, json!({ "outcome": "revoked", "status": 200, "serialHex": done.record["serialHex"], "profile": found.record["profile"] }));
        let mut reply = Reply::new(200);
        self.common_headers(ctx, &mut reply);
        reply
    }

    async fn key_change(&self, ctx: &mut Ctx<'_>) -> Reply {
        let signed = match self.authenticate(ctx, "kid").await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let mut account = signed.account.clone().unwrap_or(json!({}));
        let payload = signed.payload.clone().unwrap_or(Json::Null);
        let inner = match jws::parse_flattened_object(&payload, "inner JWS") {
            Ok(i) => i,
            Err(r) => {
                return self.problem(
                    ctx,
                    400,
                    "malformed",
                    codes::STS_ACME_0070,
                    &r.detail,
                    json!({}),
                )
            }
        };
        let header = match jws::parse_protected_header(&inner) {
            Ok(h) => h,
            Err(r) => {
                return self.problem(
                    ctx,
                    400,
                    "malformed",
                    codes::STS_ACME_0070,
                    &r.detail,
                    json!({}),
                )
            }
        };
        if header.get("jwk").is_none()
            || header.get("kid").is_some()
            || header.get("nonce").is_some()
            || header.get("url") != signed.header.get("url")
        {
            return self.problem(
                ctx,
                400,
                "malformed",
                codes::STS_ACME_0071,
                "The inner JWS carries the new key as \"jwk\", no \"kid\", no \"nonce\", and the same \"url\" as the outer JWS (RFC 8555 section 7.3.5).",
                json!({}),
            );
        }
        let alg = str_of(&header, "alg").to_string();
        if let Err(r) = jws::check_algorithm(&alg) {
            return self.send_refusal(ctx, r);
        }
        let new_key = match jws::check_account_key(&header["jwk"], &alg) {
            Ok(k) => k,
            Err(r) => return self.send_refusal(ctx, r),
        };
        if jws::verify_flattened(&inner, &new_key.jwk, &alg).is_err() {
            return self.problem(
                ctx,
                400,
                "malformed",
                codes::STS_ACME_0070,
                "The inner JWS is not signed by the new key it carries.",
                json!({}),
            );
        }
        let inner_payload = jws::read_payload(&inner).ok().flatten();
        let checked = match inner_payload {
            Some(p) => jws::check_payload(&p, "key-change-inner", "keyChange"),
            None => Err(jws::refusal(
                "malformed",
                400,
                codes::STS_ACME_0070,
                "The inner JWS payload is {\"account\", \"oldKey\"}.",
            )),
        };
        let checked = match checked {
            Ok(v) => v,
            Err(r) => return self.send_refusal(ctx, r),
        };
        if checked.get("account") != signed.header.get("kid") {
            return self.problem(ctx, 400, "malformed", codes::STS_ACME_0071, "The inner payload's \"account\" is not the account that signed the outer JWS.", json!({}));
        }
        let old = jws::jwk_thumbprint(&checked["oldKey"]).unwrap_or_default();
        if old != str_of(&account, "thumbprint") {
            return self.problem(ctx, 400, "malformed", codes::STS_ACME_0072, "The inner payload's \"oldKey\" is not the account's current key.", json!({}));
        }
        if new_key.thumbprint == str_of(&account, "thumbprint") {
            return self.problem(
                ctx,
                400,
                "malformed",
                codes::STS_ACME_0074,
                "The new key is the account's current key.",
                json!({}),
            );
        }
        if let Some(holder) =
            self.store.account_by_thumbprint(&new_key.thumbprint)
        {
            ctx.set("Location", ctx.account(str_of(&holder, "id")));
            return self.problem(ctx, 409, "malformed", codes::STS_ACME_0073, "The new key is already the key of another account (RFC 8555 section 7.3.5).", json!({}));
        }
        self.store.rekey_account(
            &mut account,
            new_key.jwk.clone(),
            &new_key.thumbprint,
        );
        self.core.audit().record(&json!({
            "category": "protocol", "action": "enrollment.acme.account.key-change",
            "protocol": "ACME", "outcome": "success",
            "actor": format!("account:{}", str_of(&account, "id")),
            "target": ctx.target.clone().unwrap_or_default(),
            "summary": "an ACME account rolled over to a new key",
            "detail": { "account": account["id"] },
        }));
        self.record(ctx, json!({ "outcome": "answered", "status": 200 }));
        let body = self.account_json(ctx, &account);
        let location = ctx.account(str_of(&account, "id"));
        self.send_json(ctx, 200, &body, Some(location))
    }

    fn renewal_info(&self, ctx: &mut Ctx<'_>, id: &str) -> Reply {
        let Some((_, cert_id)) = jws::parse_cert_id(id) else {
            return self.problem(ctx, 400, "malformed", codes::STS_ACME_0080, "The certificate identifier is base64url(AKI keyIdentifier) \".\" base64url(serial) (RFC 9773 section 4.1).", json!({}));
        };
        let Some(cert) = self.store.certificate_by_cert_id(&cert_id) else {
            return self.problem(ctx, 404, "malformed", codes::STS_ACME_0081, "No certificate issued over ACME in this realm has that identifier.", json!({}));
        };
        let wanted = crate::core::normal_serial(str_of(&cert, "serialHex"));
        let held = self
            .core
            .enrolled_of(&account_entry(&cert))
            .into_iter()
            .find(|one| {
                crate::core::normal_serial(str_of(one, "serialHex")) == wanted
            });
        let nb = crate::core::ms_of(str_of(&cert, "notBefore"));
        let na = crate::core::ms_of(str_of(&cert, "notAfter"));
        let now = crate::core::now_ms();
        let revoked = held.as_ref().is_some_and(|h| {
            h.get("revoked")
                .is_some_and(|r| !r.is_null() && r != &Json::Bool(false))
        });
        let window = if revoked {
            json!({ "start": crate::core::iso(now - 7_200_000.0), "end": crate::core::iso(now - 3_600_000.0) })
        } else {
            json!({ "start": crate::core::iso(nb + (na - nb) * 2.0 / 3.0), "end": crate::core::iso(na) })
        };
        ctx.set("Retry-After", RENEWAL_RETRY_AFTER_S.to_string());
        self.record(ctx, json!({ "outcome": "answered", "status": 200, "serialHex": cert["serialHex"] }));
        let body =
            self.held("renewal-info", json!({ "suggestedWindow": window }));
        self.send_json(ctx, 200, &body, None)
    }
}

/// The path under `prefix`, matched as Express matches it (any case).
#[tracing::instrument(level = "trace")]
pub fn strip_prefix_ci<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    let head = path.get(..prefix.len())?;
    if !head.eq_ignore_ascii_case(prefix) {
        return None;
    }
    let tail = &path[prefix.len()..];
    (tail.is_empty() || tail.starts_with('/')).then_some(tail)
}

/// `decodeURIComponent()` of a route parameter.
#[tracing::instrument(level = "trace")]
pub fn percent_decode(text: &str) -> String {
    url::form_urlencoded::parse(
        format!("a={}", text.replace('+', "%2B")).as_bytes(),
    )
    .next()
    .map(|(_, v)| v.into_owned())
    .unwrap_or_else(|| text.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_prefix_is_matched_as_express_matches_it() {
        assert_eq!(
            strip_prefix_ci("/Enroll/ACME/directory", PREFIX),
            Some("/directory")
        );
        assert_eq!(strip_prefix_ci("/enroll/acmex", PREFIX), None);
        assert!(id_ok("abcdefgh"));
        assert!(!id_ok("abc"));
    }
}
