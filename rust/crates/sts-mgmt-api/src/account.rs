// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `/account-api` (`account-api/account_api.ts`, 3ck): the user portal's
//! only door, as an axum router the HTTP layer mounts.
//!
//! **THE PERSON IS THE TOKEN'S.** No operation takes a username naming
//! whose account it acts on: [`AccountApi::authenticate`] composes the
//! caller from the verified token — the person the token's `sub` resolves
//! to in this realm, else its `username` — and a handler reads that and
//! nothing else.
//!
//! THE GATE, IN NODE'S ORDER (`authenticate()`), each step a credential
//! that stopped being one: a token presented (STS-ACCOUNT-0001); verified
//! under THIS realm's key, any generation (0002 — never the default realm's,
//! which is the management API's choice and the opposite one); not expired
//! (0003); RFC 9068 section 4's type (0004), an issuer this realm publishes
//! at the address the request reached (0005), the audience this realm's
//! `/account-api` (0006, 403); the subject gone (0023); revoked or the
//! person disabled (0007); the sign-on session it was issued on still live
//! (0008); RFC 8705's certificate binding (0009); RFC 9449's — never as
//! Bearer (0010), the proof checked, a nonce asked for where one is wanted
//! (0011); the portal as a public client DPoP-bound always; a PERSON's
//! token (0012), carrying `account:manage` (0013), issued to a client that
//! still holds a delegated permission grant of it (0014); and the access
//! policy, `user-portal`, `read` or `manage-own`, the owner the subject
//! (0015).
//!
//! Then the route wrapper (`run()`): the query and headers held to what the
//! operation declares (0020, 0021, 0022), and the handler. Every answer is
//! held to its closed model in `generated/openapi.account.json` (#1353); a
//! mismatch is a 500 marked STS-API-0139.
//!
//! PORTED: `GET /account-api/me`, `/overview` and `/announcements`, the
//! three the portal asks before it draws its first page. Every other
//! operation the document has answers as an operation not yet ported does
//! — the gate runs, then Express's 404 — and the miss is logged. Opaque
//! access tokens (#501, off by default) are not ported: a handle answers
//! 0002. A recent sign-in (`recentAuth`) is asked by no operation ported.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::Response;
use axum::routing::any;
use axum::Router;
use serde_json::{json, Map, Value as Json};
use sts_core::errors::{codes, ErrorCode};
use sts_core::realm;
use sts_crypto::jws::ClaimChecks;
use sts_crypto::keys::KeyPolicy;
use sts_oauth::dpop::{verify_proof, ProofRequest};
use sts_oauth::jwt_access_token::JwtAccessTokens;
use sts_oauth::mtls::{bound_thumbprint_of, check_binding};
use sts_oauth::sender_constraints::{access_token_refusal, Presented};
use sts_xacml::access::Question;

use crate::request::{check_declared, check_headers, parse_query, Query};
use crate::router::Services;

/// The API's path.
pub const BASE: &str = "/account-api";
/// The one scope every operation takes.
pub const SCOPE: &str = "account:manage";
/// The user portal's client.
pub const PORTAL_CLIENT: &str = "sts-user-portal";

/// The document, as the model wrote it.
pub const DOCUMENT_TEXT: &str = include_str!("generated/openapi.account.json");

static DOCUMENT: LazyLock<Json> = LazyLock::new(|| {
    serde_json::from_str(DOCUMENT_TEXT).unwrap_or_else(|e| {
        tracing::error!("account-api: the document does not parse: {}", e);
        Json::Object(Map::new())
    })
});

/// `openapi.every.json`'s `account` list: what every operation takes.
static SHARED: LazyLock<Vec<Json>> = LazyLock::new(|| {
    let every: Json =
        serde_json::from_str(include_str!("generated/openapi.every.json"))
            .unwrap_or(Json::Null);
    every
        .get("account")
        .and_then(Json::as_array)
        .cloned()
        .unwrap_or_default()
});

static VALIDATORS: LazyLock<
    Mutex<HashMap<String, Option<Arc<jsonschema::Validator>>>>,
> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// What the account API reads outside this crate, each in the ambient
/// realm.
pub trait AccountPorts: Send + Sync {
    /// `helpers.nameForSubject(sub)`: the person a `sub` names, or ''.
    fn name_for_subject(&self, sub: &str) -> String;
    /// `helpers.subjectIsGone(sub)`: a `urn:uuid:` naming nobody now.
    fn subject_is_gone(&self, sub: &str) -> bool;
    /// `stats.sessionIdOfJti(jti)`: the sign-on session a token was
    /// issued on, or ''.
    fn session_id_of(&self, jti: &str) -> String;
    /// `authn.sessionById(sid)`.
    fn session(&self, sid: &str) -> Option<Json>;
    /// `authn.signOnFactsFor(session)`.
    fn sign_on_facts(&self, session: &Json) -> Json;
    /// `personEntry(name)`: `{dn, attributes}` (lower-cased names, each a
    /// list), or `None`.
    fn person_entry(&self, name: &str) -> Option<Json>;
    /// `credentials.mechanismsFor(name)`'s members the Overview reads.
    fn mechanisms(&self, name: &str) -> Json;
    /// `stats.userDetail(name)`'s `user.authentications`, or `None` with
    /// no row.
    fn times_signed_in(&self, name: &str) -> Option<i64>;
    /// `ProfilePhoto.pathFor(name)`.
    fn photo_path(&self, name: &str) -> String;
    /// `ProfilePhoto.viewFor(name)`.
    fn photo_view(&self, name: &str) -> Json;
    /// `AccountApi.localeData(username)`: the portal's and the chooser's
    /// catalogs along the negotiated chain.
    fn locale(&self, headers: &HeaderMap, username: &str) -> Json;
    /// `i18n.offered()`.
    fn offered(&self) -> Vec<Json>;
    /// `customAttributesOf(entry)`: the realm's custom attributes this
    /// person may see.
    fn custom_attributes(&self, entry: &Json) -> Vec<Json> {
        let _ = entry;
        Vec::new()
    }
    /// `PortalPseudonyms.listView(username)`: the person's sign-in names,
    /// the pending address, the cap and whether mail can be sent; `None`
    /// where there is no directory.
    fn pseudonyms(&self, username: &str) -> Option<Json> {
        let _ = username;
        None
    }
    /// `writePseudonyms(username, {op, value, source})`.
    fn write_pseudonyms(
        &self,
        username: &str,
        op: &str,
        value: &str,
        source: &str,
    ) -> Json {
        let _ = (username, op, value, source);
        json!({ "ok": false, "code": "" })
    }
    /// `mail.available()`.
    fn mail_available(&self) -> bool {
        false
    }
    /// `ctx.translatorFor(username).text(key, params)`: one of the
    /// portal's messages in the person's language.
    fn text(
        &self,
        username: &str,
        key: &str,
        params: &[(&str, &str)],
    ) -> String {
        let _ = (username, params);
        key.to_string()
    }
}

/// `NO_DIRECTORY` (`portal/portal_pseudonyms.ts`).
const NO_DIRECTORY: &str =
    "The directory is not available, so this could not be done.";
/// `NO_MAIL`.
const NO_MAIL: &str =
    "This service has no way to send mail here at the moment.";
/// `NO_PERSON`.
const NO_PERSON: &str = "There is no such person in this realm.";

/// `GET` and `POST /account-api/pseudonyms` (`portal/portal_pseudonyms.ts`,
/// #644; the `apis5` slice of #444): the list, and an add, a removal or a
/// cancelled pending address, written by the directory with `source:
/// self`.
///
/// NOT YET: the shared `mail-verify` attempt limit before an add
/// (`websecurity.attemptShared()`), and an unverified ADDRESS added while
/// mail can be sent — the pending link and its mail — which answers as an
/// operation not yet ported.
fn pseudonyms_answer(
    ports: &dyn AccountPorts,
    caller: &AccountCaller,
    post: Option<&Json>,
) -> Option<Out> {
    let who = caller.username.as_str();
    let Some(view) = ports.pseudonyms(who) else {
        return Some(refuse(
            503,
            codes::STS_PORTAL_0623,
            NO_DIRECTORY.into(),
            json!({ "view": { "refused": NO_DIRECTORY } }),
        ));
    };
    let Some(body) = post else {
        return Some(Out {
            status: 200,
            body: view,
            code: None,
            headers: Vec::new(),
        });
    };
    let text = |k: &str| match body.get(k) {
        None | Some(Json::Null) => String::new(),
        Some(Json::String(t)) => t.clone(),
        Some(v) => v.to_string(),
    };
    let action = text("action");
    let value = text("value").trim().to_string();
    if !["add", "remove", "cancel-pending"].contains(&action.as_str()) {
        return Some(refuse(
            400,
            codes::STS_LDAP_0199,
            "That is not something this page does.".into(),
            json!({ "view": view }),
        ));
    }
    let email = !value.is_empty()
        && !value.contains(char::is_whitespace)
        && value.contains('@');
    if action == "add" && email {
        if !ports.mail_available() {
            return Some(refuse(
                400,
                codes::STS_MAIL_0032,
                NO_MAIL.into(),
                json!({ "view": view }),
            ));
        }
        return None;
    }
    let op = if action == "cancel-pending" {
        "cancel"
    } else {
        action.as_str()
    };
    let written = ports.write_pseudonyms(who, op, &value, "self");
    if written.get("ok") != Some(&Json::Bool(true)) {
        let mut code = written
            .get("code")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_string();
        let mut sentence = written
            .get("sentence")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_string();
        if code.is_empty() {
            code = "STS-LDAP-0093".into();
            if sentence.is_empty() {
                sentence = NO_PERSON.into();
            }
        }
        let status = if code == "STS-LDAP-0093" || code == "STS-PORTAL-0623" {
            503
        } else {
            400
        };
        let view = ports.pseudonyms(who).unwrap_or(view);
        let code =
            sts_core::errors::known(&code).unwrap_or(codes::STS_LDAP_0093);
        return Some(refuse(status, code, sentence, json!({ "view": view })));
    }
    let key = match action.as_str() {
        "remove" => "portalPseudonyms.done.removed",
        "cancel-pending" => "portalPseudonyms.done.cancelled",
        _ => "portalPseudonyms.done.added",
    };
    Some(Out {
        status: 200,
        body: json!({ "ok": true, "message": ports.text(who, key, &[]) }),
        code: None,
        headers: Vec::new(),
    })
}

/// The signed-in person (`AccountCaller`).
#[derive(Clone, Debug)]
pub struct AccountCaller {
    pub username: String,
    pub sub: String,
    pub realm: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<i64>,
    pub session_id: String,
    pub sign_on: Option<Json>,
}

/// The API: the management API's services and the account's own ports.
pub struct AccountApi {
    pub services: Arc<Services>,
    pub ports: Arc<dyn AccountPorts>,
}

/// A refusal or an answer, before it is sent.
struct Out {
    status: u16,
    body: Json,
    code: Option<ErrorCode>,
    headers: Vec<(&'static str, String)>,
}

fn refuse(status: u16, code: ErrorCode, why: String, extra: Json) -> Out {
    let mut body = json!({ "ok": false, "errors": [why] });
    if let (Some(o), Some(more)) = (body.as_object_mut(), extra.as_object()) {
        for (k, v) in more {
            o.insert(k.clone(), v.clone());
        }
    }
    Out {
        status,
        body,
        code: Some(code),
        headers: Vec::new(),
    }
}

fn challenge(error: &str) -> String {
    format!(
        "DPoP realm=\"{}\"{}, scope=\"{}\", algs=\"ES256 PS256 RS256 EdDSA\"",
        BASE,
        if error.is_empty() {
            String::new()
        } else {
            format!(", error=\"{}\"", error)
        },
        SCOPE
    )
}

/// `unauthorized()`: 401 with the DPoP challenge.
fn unauthorized(code: ErrorCode, error: &str, why: String) -> Out {
    let mut out = refuse(
        401,
        code,
        why,
        json!({ "error": if error.is_empty() { "unauthorized" } else { error } }),
    );
    out.headers.push(("www-authenticate", challenge(error)));
    out
}

fn text(v: Option<&Json>) -> String {
    match v {
        None | Some(Json::Null) => String::new(),
        Some(Json::String(s)) => s.clone(),
        Some(Json::Bool(false)) => String::new(),
        Some(other) => other.to_string(),
    }
}

fn js_json(v: Option<&Json>) -> String {
    match v {
        None | Some(Json::Null) => "null".into(),
        Some(Json::String(s)) if s.is_empty() => "null".into(),
        Some(other) => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// The operation at a method and a path: its id and its entry.
fn operation_of(method: &str, path: &str) -> Option<(String, &'static Json)> {
    let verb = if method.eq_ignore_ascii_case("HEAD") {
        "get".to_string()
    } else {
        method.to_ascii_lowercase()
    };
    let entry = DOCUMENT.get("paths")?.get(path)?.get(&verb)?;
    let id = entry.get("operationId")?.as_str()?.to_string();
    Some((id, entry))
}

fn validator(key: String, schema: &Json) -> Option<Arc<jsonschema::Validator>> {
    let mut cache = match VALIDATORS.lock() {
        Ok(c) => c,
        Err(p) => p.into_inner(),
    };
    if let Some(found) = cache.get(&key) {
        return found.clone();
    }
    let mut root = Map::new();
    root.insert("allOf".into(), Json::Array(vec![schema.clone()]));
    root.insert(
        "components".into(),
        DOCUMENT.get("components").cloned().unwrap_or(json!({})),
    );
    let built = jsonschema::options()
        .with_draft(jsonschema::Draft::Draft7)
        .should_validate_formats(true)
        .build(&Json::Object(root))
        .map(Arc::new)
        .map_err(|e| tracing::debug!("a model does not compile: {}", e))
        .ok();
    cache.insert(key, built.clone());
    built
}

/// What is wrong with an answer, `None` where its model takes it.
#[tracing::instrument(level = "debug", skip(body))]
pub fn problem_of(
    method: &str,
    path: &str,
    status: u16,
    body: &Json,
) -> Option<String> {
    let (id, entry) = operation_of(method, path)?;
    let responses = entry.get("responses")?;
    let Some(declared) = responses
        .get(status.to_string())
        .or_else(|| responses.get("default"))
    else {
        return Some(format!(
            "{} answered {}: a status the operation does not declare",
            id, status
        ));
    };
    let schema = declared
        .pointer("/content/application~1json/schema")
        .cloned()
        .unwrap_or(json!({}));
    let v = validator(format!("{} {}", id, status), &schema)?;
    (!v.is_valid(body)).then(|| {
        let at: Vec<String> = v
            .iter_errors(body)
            .take(8)
            .map(|e| e.instance_path().to_string())
            .collect();
        format!("{} answered {}: {}", id, status, at.join(", "))
    })
}

impl AccountApi {
    /// The router: every path under `/account-api`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route(BASE, any(serve))
            .route(&format!("{}/{{*rest}}", BASE), any(serve))
            .with_state(self)
    }

    fn base(&self, headers: &HeaderMap, over_tls: bool) -> String {
        let settings = &self.services.settings;
        let pinned = settings
            .value_of("global.publicBaseUrl")
            .as_str()
            .trim()
            .trim_end_matches('/')
            .to_string();
        let root = if !pinned.is_empty() {
            pinned
        } else {
            let host = headers
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("localhost");
            format!("{}://{}", if over_tls { "https" } else { "http" }, host)
        };
        format!("{}{}", root, self.services.registry.current_prefix())
    }

    /// `authenticate(req, res, op)`.
    #[allow(clippy::too_many_arguments)]
    fn authenticate(
        &self,
        method: &Method,
        headers: &HeaderMap,
        htu: &str,
        base: &str,
        op: &str,
    ) -> Result<AccountCaller, Out> {
        let s = &self.services;
        let realm_id = realm::current_id();
        let (token, scheme) = crate::gate::presented_token_of(
            headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok()),
        );
        if token.is_empty() {
            return Err(unauthorized(
                codes::STS_ACCOUNT_0001,
                "",
                format!(
                    "This API takes an OAuth 2.0 access token issued to the user portal (`{}`, scope `{}`, \
                     resource {}{}), DPoP-bound, sent as `Authorization: DPoP <token>` with its proof.",
                    PORTAL_CLIENT, SCOPE, base, BASE
                ),
            ));
        }
        let now = (s.now)();
        let claims = s.keys.key_set(&realm_id).and_then(|keys| {
            keys.verify_own_jws(
                &token,
                None,
                &ClaimChecks {
                    now: Some(now),
                    ..Default::default()
                },
                KeyPolicy::STRICT,
                &s.eddsa_curve,
                now as f64 * 1000.0,
            )
            .ok()
        });
        let Some(claims) = claims else {
            return Err(unauthorized(
                codes::STS_ACCOUNT_0002,
                "invalid_token",
                "That access token was not issued by this realm's authorization server, or its signature does \
                 not verify."
                    .into(),
            ));
        };
        if let Some(exp) = claims.get("exp").and_then(Json::as_f64) {
            if exp != 0.0 && exp <= now as f64 {
                return Err(unauthorized(
                    codes::STS_ACCOUNT_0003,
                    "invalid_token",
                    format!(
                        "That access token expired at {}.",
                        chrono::DateTime::from_timestamp_millis(
                            (exp * 1000.0) as i64
                        )
                        .map(sts_core::time::iso)
                        .unwrap_or_default()
                    ),
                ));
            }
        }
        let typ = JwtAccessTokens::typ_of(&token);
        if !JwtAccessTokens::is_access_token_type(&typ) {
            return Err(unauthorized(
                codes::STS_ACCOUNT_0004,
                "invalid_token",
                format!(
                    "RFC 9068 section 4: an access token's typ header must be \"at+jwt\", and this token's is {}.",
                    if typ.is_empty() {
                        "absent".to_string()
                    } else {
                        format!("\"{}\"", typ)
                    }
                ),
            ));
        }
        if !s.tokens.is_hosted_issuer(&text(claims.get("iss")), base) {
            return Err(unauthorized(
                codes::STS_ACCOUNT_0005,
                "invalid_token",
                format!(
                    "RFC 9068 section 4: the iss claim must be an issuer this realm publishes at {}, and this \
                     token names {}.",
                    base,
                    js_json(claims.get("iss"))
                ),
            ));
        }
        let audiences: Vec<String> = match claims.get("aud") {
            Some(Json::Array(list)) => {
                list.iter().map(|a| text(Some(a))).collect()
            }
            None | Some(Json::Null) => Vec::new(),
            Some(other) => vec![text(Some(other))],
        };
        let wanted = format!("{}{}", base, BASE);
        if !audiences.contains(&wanted) {
            return Err(refuse(
                403,
                codes::STS_ACCOUNT_0006,
                format!(
                    "That access token is for {}, and this API answers to \"{}\". Ask the token endpoint with \
                     resource={}.",
                    js_json(claims.get("aud")),
                    wanted,
                    wanted
                ),
                json!({ "error": "invalid_token" }),
            ));
        }
        let sub = text(claims.get("sub"));
        if self.ports.subject_is_gone(&sub)
            && s.mode.predicate("refusesTokenForGoneSubject") == Some(true)
        {
            return Err(unauthorized(
                codes::STS_ACCOUNT_0023,
                "invalid_token",
                "The person this access token names no longer exists.".into(),
            ));
        }
        let person = {
            let named = self.ports.name_for_subject(&sub);
            if named.is_empty() {
                text(claims.get("username"))
            } else {
                named
            }
        };
        let jti = text(claims.get("jti"));
        if (!jti.is_empty() && s.gate_ports.revoked(&realm_id, &jti))
            || (!person.is_empty() && s.gate_ports.disabled(&realm_id, &person))
        {
            return Err(unauthorized(
                codes::STS_ACCOUNT_0007,
                "invalid_token",
                "That access token has been revoked, or the account it was issued to is disabled.".into(),
            ));
        }
        let sid = if jti.is_empty() {
            String::new()
        } else {
            self.ports.session_id_of(&jti)
        };
        if !sid.is_empty() && s.gate_ports.session_ended(&realm_id, &jti) {
            return Err(unauthorized(
                codes::STS_ACCOUNT_0008,
                "invalid_token",
                "That access token was issued on a sign-on session that has since ended, by a sign-out or by \
                 running out. Sign in again."
                    .into(),
            ));
        }
        if let Some(r) = check_binding(&claims, None, true, None) {
            return Err(unauthorized(
                codes::STS_ACCOUNT_0009,
                "invalid_token",
                r.description,
            ));
        }
        let bound_jkt = claims
            .pointer("/cnf/jkt")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_string();
        let mut proof_ok = false;
        if !bound_jkt.is_empty() {
            if scheme != "dpop" {
                return Err(unauthorized(
                    codes::STS_ACCOUNT_0010,
                    "invalid_token",
                    "That access token is DPoP-bound (it carries cnf.jkt), so it must be sent as \
                     \"Authorization: DPoP <token>\" with a DPoP proof."
                        .into(),
                ));
            }
            let request = ProofRequest {
                htm: method.as_str(),
                htu,
                access_token: Some(&token),
                expected_jkt: Some(&bound_jkt),
                now,
            };
            if let Err(f) = verify_proof(
                headers.get("dpop").and_then(|v| v.to_str().ok()),
                &request,
                s.dpop.as_ref(),
            ) {
                if f.need_nonce {
                    let mut out = refuse(
                        401,
                        f.code,
                        f.description,
                        json!({ "error": "use_dpop_nonce" }),
                    );
                    out.headers.push(("dpop-nonce", s.keys.issue_nonce()));
                    out.headers.push((
                        "www-authenticate",
                        "DPoP error=\"use_dpop_nonce\"".to_string(),
                    ));
                    return Err(out);
                }
                return Err(unauthorized(
                    f.code,
                    "invalid_dpop_proof",
                    f.description,
                ));
            }
            proof_ok = true;
        }
        let issued_to = text(claims.get("client_id"));
        let bound_thumbprint = bound_thumbprint_of(&claims);
        let presented = Presented {
            where_: "the account API",
            bound_jkt: &bound_jkt,
            proof_ok,
            bound_thumbprint: &bound_thumbprint,
            certificate: false,
            certificate_matches: false,
            mtls_available: false,
            client_bound:
                sts_oauth::sender_constraints::dpop_bound_public_client(
                    &issued_to,
                    &s.gate_ports.client_method(&realm_id, &issued_to),
                ),
        };
        if let Some(r) = access_token_refusal(&s.settings, &presented) {
            return Err(unauthorized(r.code, r.error, r.description));
        }
        if person.is_empty() || sub == issued_to {
            return Err(refuse(
                403,
                codes::STS_ACCOUNT_0012,
                "That access token names no person: this API acts on the signed-in person's own account, and \
                 a token a client holds for itself has none."
                    .into(),
                json!({ "error": "forbidden" }),
            ));
        }
        let carried: Vec<String> = text(claims.get("scope"))
            .split_whitespace()
            .map(str::to_string)
            .collect();
        if !carried.iter().any(|c| c == SCOPE) {
            let mut out = refuse(
                403,
                codes::STS_ACCOUNT_0013,
                format!(
                    "That access token does not carry \"{}\", which every operation of this API takes.",
                    SCOPE
                ),
                json!({ "error": "insufficient_scope" }),
            );
            out.headers.push((
                "www-authenticate",
                format!(
                    "DPoP error=\"insufficient_scope\", scope=\"{}\"",
                    SCOPE
                ),
            ));
            return Err(out);
        }
        if !s.gate_ports.declares(&realm_id, &issued_to, SCOPE) {
            return Err(refuse(
                403,
                codes::STS_ACCOUNT_0014,
                format!(
                    "The client this token was issued to, {}, no longer holds a delegated permission grant of \
                     \"{}\" (urn:sts:account-api:{} on sts-account-api, #1141).",
                    serde_json::to_string(&issued_to).unwrap_or_default(),
                    SCOPE,
                    SCOPE
                ),
                json!({ "error": "forbidden" }),
            ));
        }
        let sign_on = if sid.is_empty() {
            None
        } else {
            self.ports.session(&sid)
        };
        if s.settings.value_of("xacml.enforceAccess").as_bool() {
            let question = Question {
                resource: "user-portal".into(),
                action: if *method == Method::GET {
                    "read".into()
                } else {
                    "manage-own".into()
                },
                owner: Some(person.clone()),
                subject: person.clone(),
                authenticated: true,
                ..Default::default()
            };
            let answer = s.access.check(&question, &[], &[]);
            if !answer.allowed {
                tracing::info!(
                    "account-api: the access policy refused {} {} for {}. {}",
                    method,
                    op,
                    person,
                    answer.why
                );
                return Err(refuse(
                    403,
                    codes::STS_ACCOUNT_0015,
                    format!(
                        "The access policy refused this request. {}",
                        answer.why
                    ),
                    json!({ "error": "forbidden" }),
                ));
            }
        }
        Ok(AccountCaller {
            username: person,
            sub,
            realm: realm_id,
            client_id: issued_to,
            scopes: carried,
            expires_at: claims
                .get("exp")
                .and_then(Json::as_f64)
                .map(|e| e as i64),
            session_id: sid,
            sign_on,
        })
    }

    /// `GET /account-api/me`.
    fn me(&self, caller: &AccountCaller, headers: &HeaderMap) -> Json {
        let user = caller
            .sign_on
            .as_ref()
            .and_then(|s| s.get("user"))
            .cloned()
            .unwrap_or(json!({}));
        let v = &self.services.version;
        json!({
            "user": { "username": caller.username, "sub": caller.sub,
                      "name": text(user.get("name")),
                      "email": text(user.get("email")),
                      "photo": self.ports.photo_path(&caller.username) },
            "realm": { "id": realm::current_id(),
                       "prefix": self.services.registry.current_prefix() },
            "client": caller.client_id,
            "expiresAt": caller.expires_at,
            "mode": self.services.mode.current(),
            "locale": self.ports.locale(headers, &caller.username),
            "version": { "version": v.version,
                         "buildInfo": crate::console::build_info(v) },
        })
    }

    /// `AccountOverview.overview(caller)`.
    fn overview(&self, caller: &AccountCaller) -> Json {
        let name = &caller.username;
        let m = self.ports.mechanisms(name);
        let entry = self.ports.person_entry(name);
        let sign_on = caller
            .sign_on
            .as_ref()
            .map(|s| self.ports.sign_on_facts(s))
            .unwrap_or(json!({}));
        let user = caller
            .sign_on
            .as_ref()
            .and_then(|s| s.get("user"))
            .cloned()
            .unwrap_or(json!({}));
        let number = |v: Option<&Json>| v.and_then(Json::as_f64).unwrap_or(0.0);
        let bound = sign_on.get("deviceBound").cloned().unwrap_or(json!({}));
        let backup = m.get("backupCodes").cloned().unwrap_or(json!({}));
        let fact = match text(bound.get("fact")) {
            f if f.is_empty() => "none".to_string(),
            f => f,
        };
        let truthy = |v: Option<&Json>| {
            v.is_some_and(|x| match x {
                Json::Bool(b) => *b,
                Json::Null => false,
                Json::Number(n) => n.as_f64() != Some(0.0),
                Json::String(s) => !s.is_empty(),
                _ => true,
            })
        };
        let held = entry
            .as_ref()
            .and_then(|e| e.pointer("/attributes/preferredlanguage/0"))
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_string();
        json!({
            "username": name,
            "sub": caller.sub,
            "entry": entry.as_ref().map(|e| json!({ "dn": text(e.get("dn")) })),
            "session": { "email": text(user.get("email")),
                         "name": text(user.get("name")) },
            "signOn": {
                "startedAt": number(sign_on.get("startedAt")),
                "authTime": number(sign_on.get("authTime")),
                "authentications": number(sign_on.get("authentications")),
                "amr": sign_on.get("amr").cloned().unwrap_or(json!([])),
                "acr": text(sign_on.get("acr")),
                "deviceBound": {
                    "bound": truthy(bound.get("bound")),
                    "alg": text(bound.get("alg")),
                    "fact": fact,
                    "reasons": bound.get("reasons").and_then(Json::as_array)
                        .map(|l| l.iter().map(|r| json!(text(Some(r))))
                            .collect::<Vec<_>>())
                        .unwrap_or_default(),
                },
            },
            "sessionEnds": caller.sign_on.as_ref()
                .map(|s| number(s.get("expires"))).unwrap_or(0.0),
            "timesSignedIn": self.ports.times_signed_in(name),
            "directory": entry.as_ref()
                .map(|e| describe(e.get("attributes").unwrap_or(&Json::Null))),
            "mechanisms": {
                "password": truthy(m.get("password")),
                "keys": m.get("keys").and_then(Json::as_array)
                    .map_or(0, Vec::len),
                "totp": truthy(m.get("totp")),
                "totpUsable": truthy(m.get("totpUsable")),
                "mfaRequired": truthy(m.get("mfaRequired")),
                "secondFactor": text(m.get("secondFactor")),
                "backupCodes": {
                    "present": truthy(backup.get("present")),
                    "usable": truthy(backup.get("usable")),
                    "remaining": number(backup.get("remaining")),
                    "total": number(backup.get("total")),
                },
            },
            "language": { "held": held,
                          "offered": self.ports.offered().iter().map(|o| {
                              json!({ "tag": text(o.get("tag")),
                                      "name": text(o.get("name")) })
                          }).collect::<Vec<_>>() },
            "customAttributes": entry.as_ref()
                .map(|e| self.ports.custom_attributes(e)).unwrap_or_default(),
            "photo": entry.as_ref().map(|_| self.ports.photo_view(name)),
        })
    }
}

/// `InetOrgPerson.describe(entry)`: every row of the schema's fixed list
/// (`inetOrgPersonClasses`, exported from `common/inetorgperson.ts`)
/// joined to what the entry holds — a secret's value never, a binary's
/// size in bytes rather than its octets — grouped by class.
#[tracing::instrument(level = "debug", skip_all)]
pub fn describe(attributes: &Json) -> Json {
    let classes = crate::tables::tables()
        .inet_org_person_classes
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut held_all = 0;
    let mut total_all = 0;
    let groups: Vec<Json> = classes
        .iter()
        .map(|klass| {
            let rows: Vec<Json> = klass
                .get("attributes")
                .and_then(Json::as_array)
                .map(|list| {
                    list.iter().map(|row| row_for(row, attributes)).collect()
                })
                .unwrap_or_default();
            let held =
                rows.iter().filter(|r| r["present"] == json!(true)).count();
            held_all += held;
            total_all += rows.len();
            json!({ "id": klass["id"], "name": klass["name"],
                    "rfc": klass["rfc"], "oid": klass["oid"],
                    "what": klass["what"], "total": rows.len(),
                    "held": held, "rows": rows })
        })
        .map(|mut g| {
            // Node's member order: id, name, rfc, oid, what, rows, held,
            // total.
            let o = g.as_object_mut().map(std::mem::take).unwrap_or_default();
            let mut out = Map::new();
            for k in
                ["id", "name", "rfc", "oid", "what", "rows", "held", "total"]
            {
                if let Some(v) = o.get(k) {
                    out.insert(k.into(), v.clone());
                }
            }
            Json::Object(out)
        })
        .collect();
    json!({ "classes": groups, "held": held_all, "total": total_all })
}

fn row_for(row: &Json, attributes: &Json) -> Json {
    let ldap = text(row.get("ldap"));
    let held: Vec<String> = attributes
        .get(ldap.to_lowercase())
        .map(|v| match v {
            Json::Array(l) => l.iter().map(|x| text(Some(x))).collect(),
            other => vec![text(Some(other))],
        })
        .unwrap_or_default();
    let present = held.iter().any(|v| !v.is_empty());
    let flag = |k: &str| row.get(k).is_some_and(|v| v == &json!(true));
    let mut out = Map::new();
    out.insert("ldap".into(), json!(ldap));
    out.insert(
        "label".into(),
        row.get("label").cloned().unwrap_or(Json::Null),
    );
    out.insert("rfc".into(), row.get("rfc").cloned().unwrap_or(Json::Null));
    out.insert("note".into(), json!(text(row.get("note"))));
    out.insert("must".into(), json!(flag("must")));
    out.insert("secret".into(), json!(flag("secret")));
    out.insert("binary".into(), json!(flag("binary")));
    out.insert("present".into(), json!(present));
    out.insert("count".into(), json!(held.len()));
    out.insert("values".into(), json!([]));
    if present && !flag("secret") {
        if flag("binary") {
            let bytes: usize = held.iter().map(String::len).sum();
            out.insert("bytes".into(), json!(bytes));
        } else {
            out.insert("values".into(), json!(held));
        }
    }
    Json::Object(out)
}

fn send(method: &Method, path: &str, out: Out) -> Response {
    let mut status = out.status;
    let mut body = out.body;
    let mut code = out.code;
    if let Some(problem) = problem_of(method.as_str(), path, status, &body) {
        tracing::error!(
            "{}account-api: an answer its model refuses: {}",
            sts_core::log::tag(codes::STS_API_0139),
            problem
        );
        status = 500;
        body = serde_json::from_str(crate::answer::FAILED_BODY)
            .unwrap_or(Json::Null);
        code = Some(codes::STS_API_0139);
    }
    let mut response = Response::new(Body::from(
        serde_json::to_string(&body).unwrap_or_default(),
    ));
    *response.status_mut() =
        StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    let h = response.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    for (name, value) in out.headers {
        if let Ok(v) = HeaderValue::from_str(&value) {
            h.insert(name, v);
        }
    }
    match code {
        Some(c) => sts_http::mark(response, c),
        None => response,
    }
}

async fn serve(
    State(api): State<Arc<AccountApi>>,
    request: Request,
) -> Response {
    let (parts, raw) = request.into_parts();
    // The body a POST carries, as JSON (the portal's runtime sends JSON);
    // anything else is no body.
    let posted: Option<Json> = if parts.method == axum::http::Method::POST {
        axum::body::to_bytes(raw, 1 << 20)
            .await
            .ok()
            .and_then(|b| serde_json::from_slice::<Json>(&b).ok())
            .or(Some(json!({})))
    } else {
        None
    };
    let over_tls = parts
        .extensions
        .get::<sts_http::cookie_wire::OverTls>()
        .is_some();
    let path = parts.uri.path().to_string();
    let trimmed = if path.len() > 1 {
        path.trim_end_matches('/').to_string()
    } else {
        path.clone()
    };
    let base = api.base(&parts.headers, over_tls);
    let htu = format!("{}{}", base, path);
    let Some((id, entry)) = operation_of(parts.method.as_str(), &trimmed)
    else {
        let mut response =
            sts_http::html(sts_http::express::error_document(&format!(
                "Cannot {} {}",
                parts.method,
                sts_http::express::escape_html(&path)
            )));
        *response.status_mut() = StatusCode::NOT_FOUND;
        return response;
    };
    let person = entry
        .get("security")
        .and_then(Json::as_array)
        .is_some_and(|s| !s.is_empty());
    let caller = if person {
        match api.authenticate(&parts.method, &parts.headers, &htu, &base, &id)
        {
            Ok(c) => Some(c),
            Err(out) => return send(&parts.method, &trimmed, out),
        }
    } else {
        None
    };
    let query: Query = parse_query(parts.uri.query().unwrap_or(""));
    let mut parameters: Vec<Json> = entry
        .get("parameters")
        .and_then(Json::as_array)
        .cloned()
        .unwrap_or_default();
    parameters.extend(SHARED.iter().cloned());
    if let Some((code, sentence)) = check_declared(&parameters, &query) {
        let code = if code == codes::STS_API_0143 {
            codes::STS_ACCOUNT_0021
        } else {
            codes::STS_ACCOUNT_0020
        };
        return send(
            &parts.method,
            &trimmed,
            refuse(400, code, sentence, json!({})),
        );
    }
    if let Some(sentence) =
        check_headers(&parameters, parts.headers.keys().map(|k| k.as_str()))
    {
        return send(
            &parts.method,
            &trimmed,
            refuse(400, codes::STS_ACCOUNT_0022, sentence, json!({})),
        );
    }
    if let ("getPseudonyms" | "postPseudonyms", Some(c)) =
        (id.as_str(), caller.as_ref())
    {
        let post = if id == "postPseudonyms" {
            posted.as_ref()
        } else {
            None
        };
        if let Some(out) = pseudonyms_answer(api.ports.as_ref(), c, post) {
            return send(&parts.method, &trimmed, out);
        }
    }
    let answered = match (id.as_str(), caller.as_ref()) {
        ("getMe", Some(c)) => Some(api.me(c, &parts.headers)),
        ("getOverview", Some(c)) => Some(api.overview(c)),
        ("getAnnouncements", Some(_)) => {
            let since = query
                .get("since")
                .and_then(|v| match v {
                    Json::String(t) => t.trim().parse::<f64>().ok(),
                    Json::Number(n) => n.as_f64(),
                    _ => None,
                })
                .filter(|n| n.is_finite())
                .map_or(0, |n| n as i64);
            Some(api.services.console.announcements("user-portal", since))
        }
        _ => None,
    };
    match answered {
        Some(body) => send(
            &parts.method,
            &trimmed,
            Out {
                status: 200,
                body,
                code: None,
                headers: Vec::new(),
            },
        ),
        None => {
            tracing::info!(
                "account-api: {} {} ({}) is not ported to this runtime yet.",
                parts.method,
                trimmed,
                id
            );
            let mut response =
                sts_http::html(sts_http::express::error_document(&format!(
                    "Cannot {} {}",
                    parts.method,
                    sts_http::express::escape_html(&path)
                )));
            *response.status_mut() = StatusCode::NOT_FOUND;
            response
        }
    }
}
