// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `/admin-api` as an axum router the HTTP layer mounts
//! (`sts_http::HttpLayer::wrap`), with no listener of its own: the gate,
//! then the wrapper `registerRoutes()` puts in front of every handler, then
//! the handler, then `sendJson()` and the answer's check against its model
//! — the same steps, in the same order, for every operation.
//!
//! * `GET`: the console-twin drawing refused (STS-API-0129), the query held
//!   to what the operation declares (0124, 0142, 0143) and the headers
//!   (0144), the handler.
//! * `POST`: the query and headers, a form helper asked at its old address
//!   (0128), an unknown action where helpers left (0130), the body held to
//!   its schema (0009), the handler — which refuses an unknown action of
//!   its own family in its own words.
//! * The answer: the console's members left out of a management answer, an
//!   act's `errorCode`s stripped (#1355), pretty JSON with `no-store`, and
//!   then the model (#1353): a mismatch is a 500 marked STS-API-0139.
//!
//! An operation the model has and this crate does not yet port is not
//! answered here: the gate runs (a caller with no token is told it needs
//! one, as Node tells it) and the path then answers Express's 404, the
//! answer every unrouted path gives, and the miss is logged.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::Response;
use axum::routing::any;
use axum::Router;
use serde_json::{Map, Value as Json};
use sts_core::errors::{codes, ErrorCode};
use sts_core::mode::Mode;
use sts_core::realm::{self, RealmRegistry};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::settings::Settings;
use sts_core::version::VersionInfo;
use sts_oauth::dpop::ProofContext;
use sts_oauth::jwt_access_token::JwtAccessTokens;
use sts_store::key_sets::KeySet;

use crate::answer;
use crate::config_view::ProcessFacts;
use crate::document;
use crate::gate::{
    self, AccessPolicy, Arrived, Caller, Gate, GatePorts, Outcome, BASE,
};
use crate::operations::{self, Kind, OperationRow};
use crate::request::{self, parse_query, Query};
use crate::routing::{handler_of, handler_of_route, Handler};
use crate::setup::{Answered, Setup, SetupPorts};
use crate::tables::{self, tables};

/// The key sets and the DPoP nonce, which the store and `sts-oauth` hold.
pub trait KeySource: Send + Sync {
    /// A realm's signing key set.
    fn key_set(&self, realm: &str) -> Option<KeySet>;
    /// A fresh `DPoP-Nonce` for a proof that must carry one.
    fn issue_nonce(&self) -> String;
}

/// Everything the API reads, built by the composition root.
pub struct Services {
    pub settings: Arc<Settings>,
    pub mode: Arc<Mode>,
    pub lifecycle: Arc<RealmLifecycle>,
    pub registry: Arc<RealmRegistry>,
    pub tokens: Arc<JwtAccessTokens>,
    pub keys: Arc<dyn KeySource>,
    pub gate_ports: Arc<dyn GatePorts>,
    pub access: Arc<dyn AccessPolicy>,
    pub dpop: Arc<dyn ProofContext + Send + Sync>,
    pub setup_ports: Arc<dyn SetupPorts>,
    /// What the console's first screen reads (`console.rs`).
    pub console: Arc<dyn crate::console::ConsolePorts>,
    /// The families' own acts (`families.rs`).
    pub families: Arc<dyn crate::families::FamilyPorts>,
    pub facts: ProcessFacts,
    pub version: VersionInfo,
    pub eddsa_curve: String,
    /// Seconds since the epoch; a test fixes it.
    pub now: Arc<dyn Fn() -> i64 + Send + Sync>,
}

/// The router: every path under `/admin-api`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn router(services: Arc<Services>) -> Router {
    Router::new()
        .route(BASE, any(serve))
        .route(&format!("{}/{{*rest}}", BASE), any(serve))
        .with_state(services)
}

/// The caller the gate let in, on the response, for the audit row (#446:
/// the audit actor is the token's subject).
#[derive(Clone, Debug)]
pub struct ApiCaller(pub Option<Box<Caller>>);

fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// `baseUrlOf()`: `global.publicBaseUrl` where pinned, otherwise the
/// scheme and host the request arrived on (the forwarded ones where
/// `global.trustProxy` believes them), and the ambient realm's prefix.
fn base_of(services: &Services, headers: &HeaderMap, over_tls: bool) -> String {
    let pinned = services
        .settings
        .value_of("global.publicBaseUrl")
        .as_str()
        .trim()
        .trim_end_matches('/')
        .to_string();
    if !pinned.is_empty() {
        return pinned;
    }
    let trust = services.settings.value_of("global.trustProxy").as_bool();
    let first = |v: &str| v.split(',').next().unwrap_or("").trim().to_string();
    let scheme = if trust {
        header_text(headers, "x-forwarded-proto")
            .map(first)
            .filter(|s| !s.is_empty())
    } else {
        None
    }
    .unwrap_or_else(|| {
        if over_tls {
            "https".into()
        } else {
            "http".into()
        }
    });
    let host = if trust {
        header_text(headers, "x-forwarded-host")
            .map(first)
            .filter(|s| !s.is_empty())
    } else {
        None
    }
    .or_else(|| header_text(headers, "host").map(str::to_string))
    .unwrap_or_else(|| "localhost".into());
    format!("{}://{}", scheme, host)
}

/// `sendJson()` and the model's check: the response, marked.
fn send(
    method: &Method,
    path: &str,
    row: Option<&OperationRow>,
    answered: Answered,
) -> Response {
    let mut body = answered.body;
    if answered.status == 200 && body.is_object() {
        if let Some(members) = row
            .and_then(|r| tables::row(r.id))
            .and_then(|r| r.console_members.as_ref())
        {
            if let Some(o) = body.as_object_mut() {
                for m in members {
                    o.shift_remove(m);
                }
            }
        }
    }
    if method == Method::POST {
        body = strip_codes(body);
    }
    let text = pretty(&body);
    let mut response = Response::new(Body::from(text.clone()));
    *response.status_mut() =
        StatusCode::from_u16(answered.status).unwrap_or(StatusCode::OK);
    let h = response.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::VARY, HeaderValue::from_static("Accept-Language"));
    if let Some(problem) = answer::problem_of(
        method.as_str(),
        path,
        answered.status,
        "application/json",
        text.as_bytes(),
    ) {
        answer::report(&problem);
        return failed();
    }
    match answered.code {
        Some(code) => sts_http::mark(response, code),
        None => response,
    }
}

fn failed() -> Response {
    let mut response = Response::new(Body::from(answer::FAILED_BODY));
    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    let h = response.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    sts_http::mark(response, codes::STS_API_0139)
}

/// `JSON.stringify(body, null, 2)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn pretty(body: &Json) -> String {
    serde_json::to_string_pretty(body).unwrap_or_default()
}

/// `ResponseModelKit.stripCodes()`: every `errorCode`, at any depth.
#[tracing::instrument(level = "debug", skip_all)]
pub fn strip_codes(body: Json) -> Json {
    match body {
        Json::Array(list) => {
            Json::Array(list.into_iter().map(strip_codes).collect())
        }
        Json::Object(map) => Json::Object(
            map.into_iter()
                .filter(|(k, _)| k != "errorCode")
                .map(|(k, v)| (k, strip_codes(v)))
                .collect(),
        ),
        other => other,
    }
}

fn refusal(status: u16, code: ErrorCode, errors: Vec<String>) -> Answered {
    Answered {
        status,
        body: serde_json::json!({ "ok": false, "errors": errors }),
        code: Some(code),
    }
}

/// The body as `parseBody()` reads it: JSON, a form, or nothing.
fn parse_body(headers: &HeaderMap, text: &str) -> Json {
    let kind = header_text(headers, "content-type")
        .unwrap_or("")
        .to_ascii_lowercase();
    if text.trim().is_empty() {
        return Json::Object(Map::new());
    }
    if kind.contains("application/x-www-form-urlencoded") {
        let q = parse_query(text);
        return Json::Object(q.into_iter().collect());
    }
    match serde_json::from_str::<Json>(text) {
        Ok(Json::Object(o)) => Json::Object(o),
        Ok(Json::Array(list)) => Json::Object(
            list.into_iter()
                .enumerate()
                .map(|(i, v)| (i.to_string(), v))
                .collect(),
        ),
        _ => Json::Object(Map::new()),
    }
}

/// The operation summaries the index and the console's form table read
/// (`operationSummaries()`).
#[tracing::instrument(level = "debug")]
pub fn summaries(all: bool) -> Vec<Json> {
    tables()
        .rows
        .iter()
        .filter(|r| all || r.kind == "management")
        .map(|r| {
            let mut one = Map::new();
            one.insert("method".into(), Json::from(r.method.as_str()));
            one.insert("path".into(), Json::from(r.path.as_str()));
            one.insert(
                "operationId".into(),
                Json::from(r.operation_id.as_str()),
            );
            one.insert("mirrors".into(), Json::from(r.mirrors.as_str()));
            one.insert("kind".into(), Json::from(r.kind.as_str()));
            if r.route.is_none() {
                if let Some(d) = &r.drawn_on {
                    one.insert("drawnOn".into(), Json::from(d.clone()));
                }
                if all && r.method == "GET" {
                    let row = operations::by_id(&r.operation_id);
                    let names: Vec<Json> = row
                        .map(request::parameters_of)
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|p| {
                            p.get("in").and_then(Json::as_str) == Some("query")
                        })
                        .filter_map(|p| p.get("name").cloned())
                        .collect();
                    one.insert("query".into(), Json::Array(names));
                }
            }
            Json::Object(one)
        })
        .collect()
}

async fn serve(
    State(services): State<Arc<Services>>,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();
    let text = match parts.extensions.get::<sts_http::body::ParsedBody>() {
        Some(parsed) => parsed.text.clone().unwrap_or_default(),
        None => match axum::body::to_bytes(body, sts_http::body::LIMIT).await {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(e) => {
                tracing::debug!("the body could not be read: {}", e);
                String::new()
            }
        },
    };
    let over_tls = parts
        .extensions
        .get::<sts_http::cookie_wire::OverTls>()
        .is_some();
    let original = parts
        .extensions
        .get::<sts_http::OriginalPath>()
        .map(|p| p.0.clone())
        .unwrap_or_else(|| parts.uri.path().to_string());
    let query_text = parts.uri.query().unwrap_or("").to_string();
    let original_url = if query_text.is_empty() {
        original.clone()
    } else {
        format!("{}?{}", original, query_text)
    };
    let response = handle(
        &services,
        &parts.method,
        parts.uri.path(),
        &query_text,
        &original_url,
        &parts.headers,
        &text,
        over_tls,
    );
    response
}

/// One request, start to finish.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(level = "debug", skip(services, headers, text))]
pub fn handle(
    services: &Services,
    method: &Method,
    path: &str,
    query_text: &str,
    original_url: &str,
    headers: &HeaderMap,
    text: &str,
    over_tls: bool,
) -> Response {
    let ambient = realm::current();
    let realm_id = ambient.id.clone();
    let root = base_of(services, headers, over_tls);
    let prefix = services.registry.prefix_of(&ambient);
    let realm_base = format!("{}{}", root, prefix);
    let body = if *method == Method::GET || *method == Method::HEAD {
        Json::Null
    } else {
        parse_body(headers, text)
    };
    let under = path.strip_prefix(BASE).unwrap_or("");
    let htu = format!("{}{}", realm_base, path);
    let default_keys = services.keys.key_set(gate::DEFAULT_REALM);
    let realm_keys = if realm_id == gate::DEFAULT_REALM {
        None
    } else {
        services.keys.key_set(&realm_id)
    };
    let empty = KeySet {
        realm: gate::DEFAULT_REALM.into(),
        blob: Json::Null,
    };
    let g = Gate {
        settings: &services.settings,
        mode: &services.mode,
        keys: default_keys.as_ref().unwrap_or(&empty),
        realm_keys: realm_keys.as_ref(),
        tokens: &services.tokens,
        ports: services.gate_ports.as_ref(),
        access: services.access.as_ref(),
        dpop: services.dpop.as_ref(),
        eddsa_curve: &services.eddsa_curve,
    };
    let arrived = Arrived {
        method: method.as_str(),
        path: if under.is_empty() { "/" } else { under },
        original_url,
        authorization: header_text(headers, "authorization"),
        dpop: header_text(headers, "dpop"),
        htu: &htu,
        base: &root,
        realm_base: &realm_base,
        realm: &realm_id,
        body: if body.is_null() { None } else { Some(&body) },
        certificate: None,
        certificate_verified: false,
        mtls_available: false,
        now: (services.now)(),
    };
    let caller = match g.check(&arrived) {
        Outcome::Open => None,
        Outcome::Admitted(c) => Some(c),
        Outcome::Refused(r) => {
            let mut response = send(
                method,
                path,
                None,
                Answered {
                    status: r.status,
                    body: serde_json::json!({ "error": r.error, "errors": [r.message] }),
                    code: Some(r.code),
                },
            );
            if let Some(w) = r
                .www_authenticate
                .as_deref()
                .and_then(|w| HeaderValue::from_str(w).ok())
            {
                response.headers_mut().insert(header::WWW_AUTHENTICATE, w);
            }
            if r.nonce_wanted {
                if let Ok(v) =
                    HeaderValue::from_str(&services.keys.issue_nonce())
                {
                    response.headers_mut().insert("dpop-nonce", v);
                }
            }
            return response;
        }
    };
    let query = parse_query(query_text);
    let trimmed = if path.len() > 1 {
        path.trim_end_matches('/')
    } else {
        path
    };
    let found = operations::find(method.as_str(), trimmed);
    let action_route = tables::action_route(method.as_str(), trimmed);
    let mut response = match (found, &action_route) {
        (Some(row), _) => run(
            services,
            method,
            row,
            &query,
            headers,
            &body,
            &root,
            caller.as_deref(),
        ),
        (None, Some((route, action))) => unknown_action(
            services, method, route, action, &query, headers, &body,
        ),
        (None, None) => express_404(method, &original_url_path(original_url)),
    };
    response.extensions_mut().insert(ApiCaller(caller));
    response
}

fn original_url_path(url: &str) -> String {
    url.split('?').next().unwrap_or(url).to_string()
}

fn express_404(method: &Method, path: &str) -> Response {
    let mut response = sts_http::html(sts_http::express::error_document(
        &format!("Cannot {} {}", method, sts_http::express::escape_html(path)),
    ));
    *response.status_mut() = StatusCode::NOT_FOUND;
    response
}

fn setup<'a>(services: &'a Services, realm: &'a str) -> Setup<'a> {
    Setup {
        settings: &services.settings,
        mode: &services.mode,
        lifecycle: &services.lifecycle,
        registry: &services.registry,
        facts: &services.facts,
        ports: services.setup_ports.as_ref(),
        realm,
    }
}

#[allow(clippy::too_many_arguments)]
fn unknown_action(
    services: &Services,
    method: &Method,
    route: &tables::ActionRoute,
    action: &str,
    query: &Query,
    headers: &HeaderMap,
    body: &Json,
) -> Response {
    let path = route.route.replace(":action", action);
    // The query and headers are the route's: an unknown action declares
    // nothing of its own, so the route's first action's parameters are
    // the ones it shares.
    let shared = route.actions.first().and_then(|a| {
        operations::find(&route.method, &route.route.replace(":action", a))
    });
    if let Some(row) = shared {
        if let Err(r) =
            request::check_shape(row, query, headers.keys().map(|k| k.as_str()))
        {
            return send(
                method,
                &path,
                None,
                refusal(r.status, r.code, r.errors),
            );
        }
    }
    if let Some(helpers) = &route.console_actions {
        if helpers.iter().any(|h| h == action) {
            return send(
                method,
                &path,
                None,
                refusal(404, codes::STS_API_0128, vec![format!(
                    "\"{}\" is a form helper of the admin console, at {}. It writes nothing; the act it leads to is \
                     an operation here.",
                    action,
                    route.route.replacen(BASE, &format!("{}/console", BASE), 1).replace(":action", action)
                )]),
            );
        }
        return send(
            method,
            &path,
            None,
            refusal(
                400,
                codes::STS_API_0130,
                vec![crate::setup::unknown_action(action, &route.actions)],
            ),
        );
    }
    let realm_id = realm::current_id();
    let answered = match handler_of_route(&route.route) {
        Some(Handler::ConfigAction) => {
            setup(services, &realm_id).config_action(action, body)
        }
        Some(Handler::RealmsAction) => {
            setup(services, &realm_id).realms_action(action, body)
        }
        Some(Handler::Family) => {
            let root = base_of(services, headers, false);
            let realm_base =
                format!("{}{}", root, services.registry.current_prefix());
            let asked = crate::families::Asked {
                operation_id: "",
                family: crate::families::family_of(&path),
                action,
                query,
                body,
                caller: None,
                base: &realm_base,
                setup: None,
            };
            match services.families.answer(&asked) {
                Some(a) => a,
                None => return express_404(method, &path),
            }
        }
        Some(Handler::UsersAction) => {
            match crate::setup::users_action(
                &setup(services, &realm_id),
                action,
                body,
                None,
            ) {
                Some(a) => a,
                None => return express_404(method, &path),
            }
        }
        Some(Handler::ApplicationsAction) => {
            match crate::applications::action(
                &setup(services, &realm_id),
                action,
                body,
                None,
            ) {
                Some(a) => a,
                None => return express_404(method, &path),
            }
        }
        _ => {
            tracing::info!(
                "admin-api: {} {} is not ported to this runtime yet.",
                method,
                path
            );
            return express_404(method, &path);
        }
    };
    send(method, &path, None, answered)
}

#[allow(clippy::too_many_arguments)]
fn run(
    services: &Services,
    method: &Method,
    row: &'static OperationRow,
    query: &Query,
    headers: &HeaderMap,
    body: &Json,
    root: &str,
    caller: Option<&Caller>,
) -> Response {
    let table_row = tables::row(row.id);
    if *method == Method::GET {
        if let Some(twin) = table_row.and_then(|r| r.console_twin.as_ref()) {
            if query.get("format").and_then(Json::as_str) == Some("svg") {
                return send(
                    method,
                    row.path,
                    Some(row),
                    refusal(400, codes::STS_API_0129, vec![format!(
                        "The drawing is the admin console's: ask {}?format=svg. This operation answers the data alone.",
                        twin
                    )]),
                );
            }
        }
    }
    if let Err(r) =
        request::check_shape(row, query, headers.keys().map(|k| k.as_str()))
    {
        return send(
            method,
            row.path,
            Some(row),
            refusal(r.status, r.code, r.errors),
        );
    }
    if *method != Method::GET {
        if let Some(r) = request::check_body(row, body) {
            return send(
                method,
                row.path,
                Some(row),
                refusal(r.status, r.code, r.errors),
            );
        }
        // THE BODY AS ITS MODEL TYPE (D15). A body the schema admitted may
        // still not read as the model's `Body` — Node enforces no
        // `required` at the door (`structureOnly()`), and the handler
        // refuses a missing member in its own words — so a miss is noted,
        // not answered.
        let mut typed = body.clone();
        if let Some(o) = typed.as_object_mut() {
            o.shift_remove("action");
        }
        let read = match row.kind {
            Kind::Management => {
                sts_model::api::management::read_body(row.id, &typed)
            }
            Kind::Console => sts_model::api::console::read_body(row.id, &typed),
        };
        if let Some(Err(e)) = read {
            tracing::debug!(
                "admin-api: {}'s body does not read as its model type: {}",
                row.id,
                e
            );
        }
    }
    let realm_id = realm::current_id();
    let Some(handler) = handler_of(row.operation) else {
        tracing::info!(
            "admin-api: {} {} ({}) is not ported to this runtime yet.",
            method,
            row.path,
            row.id
        );
        return express_404(method, row.path);
    };
    let action = table_row.and_then(|r| r.action.clone()).unwrap_or_default();
    let s = setup(services, &realm_id);
    let realm_base = format!("{}{}", root, services.registry.current_prefix());
    let answered = match handler {
        Handler::Index => Answered {
            status: 200,
            body: index(services, &realm_base),
            code: None,
        },
        Handler::OpenApi => Answered {
            status: 200,
            body: document::served(
                Kind::Management,
                &realm_base,
                &services.version.version,
                gate_required(services),
            ),
            code: None,
        },
        Handler::ConsoleOpenApi => Answered {
            status: 200,
            body: document::served(
                Kind::Console,
                &realm_base,
                &services.version.version,
                gate_required(services),
            ),
            code: None,
        },
        Handler::ConsoleOperations => Answered {
            status: 200,
            body: serde_json::json!({ "operations": summaries(true) }),
            code: None,
        },
        Handler::Config => s.config_json(),
        Handler::ConfigAction => s.config_action(&action, body),
        Handler::Mode => s.mode_json(),
        Handler::Realms => s.realms_json(root, query),
        Handler::RealmsAction => s.realms_action(&action, body),
        Handler::Status => s.status_json(),
        Handler::Applications => match crate::applications::list(&s, query) {
            Some(a) => a,
            None => {
                tracing::info!(
                    "admin-api: {} {}?application= ({}) is not ported to \
                     this runtime yet.",
                    method,
                    row.path,
                    row.id
                );
                return express_404(method, row.path);
            }
        },
        Handler::ApplicationsAction => {
            match crate::applications::action(&s, &action, body, caller) {
                Some(a) => a,
                None => return express_404(method, row.path),
            }
        }
        Handler::Family => {
            let asked = crate::families::Asked {
                operation_id: row.id,
                family: crate::families::family_of(row.path),
                action: &action,
                query,
                body,
                caller,
                base: &realm_base,
                setup: Some(&s),
            };
            match services.families.answer(&asked) {
                Some(a) => a,
                None => {
                    tracing::info!(
                        "admin-api: {} {} ({}) has no family to answer it \
                         in this process.",
                        method,
                        row.path,
                        row.id
                    );
                    return express_404(method, row.path);
                }
            }
        }
        Handler::UsersAction => {
            match crate::setup::users_action(&s, &action, body, caller) {
                Some(a) => a,
                None => return express_404(method, row.path),
            }
        }
        Handler::Me => Answered {
            status: 200,
            body: crate::console::me_json(services, caller),
            code: None,
        },
        Handler::ConsoleShell => {
            let me = crate::console::me_json(services, caller);
            let gate = crate::console::console_gate_of(&me);
            let username = caller
                .filter(|c| c.kind == "person")
                .map(|c| c.name.clone())
                .unwrap_or_default();
            Answered {
                status: 200,
                body: crate::console::shell_json(
                    services,
                    &gate,
                    root,
                    headers,
                    &username,
                    query.get("catalogs").and_then(Json::as_str)
                        == Some("files"),
                ),
                code: None,
            }
        }
        Handler::ConsoleDashboard => {
            let status = s.status_json();
            let authority = caller.map(|c| {
                if c.realm == gate::DEFAULT_REALM {
                    "service"
                } else {
                    "realm"
                }
            });
            Answered {
                status: status.status,
                body: crate::console::dashboard_json(
                    services,
                    status.body,
                    &realm_base,
                    authority,
                ),
                code: status.code,
            }
        }
        Handler::Announcements => Answered {
            status: 200,
            body: services.console.announcements(
                "admin-console",
                query
                    .get("since")
                    .and_then(|v| match v {
                        Json::Number(n) => n.as_f64(),
                        Json::String(t) => t.trim().parse::<f64>().ok(),
                        _ => None,
                    })
                    .filter(|n| n.is_finite())
                    .map_or(0, |n| n as i64),
            ),
            code: None,
        },
    };
    send(method, row.path, Some(row), answered)
}

fn gate_required(services: &Services) -> bool {
    services
        .mode
        .value_in_force("adminApi.authRequired")
        .as_bool()
}

/// `GET /admin-api`: what this API is and every operation it offers.
fn index(services: &Services, base: &str) -> Json {
    let v = &services.version;
    let mut out = Map::new();
    out.insert("name".into(), Json::from("IYA STS management API"));
    out.insert("version".into(), Json::from(v.version.as_str()));
    if !v.build.is_empty() {
        out.insert("build".into(), Json::from(v.build.as_str()));
    }
    out.insert("release".into(), Json::Bool(v.release));
    if !v.commit.is_empty() {
        out.insert("commit".into(), Json::from(v.commit.as_str()));
    }
    out.insert("builtAt".into(), Json::from(v.built_at.as_str()));
    out.insert("stamped".into(), Json::Bool(v.stamped));
    out.insert(
        "openapi".into(),
        Json::from(format!("{}{}/openapi.json", base, BASE)),
    );
    out.insert("protected".into(), Json::Bool(gate_required(services)));
    out.insert(
        "docs".into(),
        Json::from(format!("{}/admin/api-explorer", base)),
    );
    out.insert("console".into(), Json::from(format!("{}/admin", base)));
    out.insert("operations".into(), Json::Array(summaries(false)));
    Json::Object(out)
}
