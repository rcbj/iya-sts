// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE ROUTES (`Logout.registerRoutes()`), in Node's order:
//!
//! * `GET /logout` — the SHELL for a browser (`Shells::signout`), the
//!   inventory as JSON for a program; no session and no name is a 302 to
//!   sign in (a 401 for a program); a name that may not be used is the
//!   shell (the page draws the API's refusal) or a 403;
//! * `POST /logout` — the JSON door's sign-out; A FORM POSTED HERE IS NO
//!   LONGER AN ACT (#577): a 303 to the page, ending nothing;
//! * `POST /logout/signed-out` — the signed-out document, drawn from the
//!   sealed result the act answered, posted by a page of this origin;
//! * and the page's operations behind `/authn-api/logout`
//!   ([`sts_authn_api::ports::SignOutPages`]), whose door is the binding.
//!
//! `/logout/signout.js` and `/logout/signout.css` are the static surfaces'
//! host's (`sts-http`), the same bytes Node serves.
//!
//! `/logout` is a FRONT DOOR (`ARRIVAL_PATHS`): a browser with no session
//! is given an arrival session before the route runs, as Node's
//! middleware gives it; `/logout/signed-out` is not (`NOT_ARRIVAL_PATHS`).
//!
//! Express matches a path case-insensitively and with an optional
//! trailing slash; the router here holds the two spellings Node's own
//! pages use, `/logout` and `/logout/`.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request as AxumRequest, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::Response;
use axum::routing::any;
use axum::Router;
use serde_json::{json, Map, Value};
use sts_core::errors::codes;

use crate::js::{self, Object};
use crate::logout::Logout;
use crate::ports::{Asked, Reply};
use crate::signout::{esc, Answered, LOGOUT_PATH, SIGNED_OUT_PATH};

/// The signed-out document's inline rules: the bytes `/logout/signout.css`
/// serves (`SIGNOUT_CSS`), so the two cannot drift.
pub const SIGNOUT_CSS: &str =
    include_str!("../../sts-http/assets/logout_signout.css");

/// The routes' state: the model, the shells and the layer's facts.
pub struct SignOutDoor {
    pub logout: Arc<Logout>,
    pub surfaces: Arc<sts_http::surfaces::SurfaceHost>,
    pub http: Arc<sts_http::HttpLayer>,
    pub settings: Arc<sts_core::settings::Settings>,
}

fn header_of(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// `res.status(n).type('application/json').set('Cache-Control',
/// 'no-store').send(JSON.stringify(body, null, 2))`.
fn json_answer(status: u16, body: &Value, reply: &Reply) -> Response {
    let text = serde_json::to_string_pretty(body).unwrap_or_default();
    let mut r = Response::new(Body::from(text));
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    with_reply(r, reply)
}

/// The cookies and headers a door wrote, put on the answer.
fn with_reply(mut r: Response, reply: &Reply) -> Response {
    for line in &reply.cookies {
        if let Ok(v) = HeaderValue::from_str(line) {
            r.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    for (k, v) in &reply.headers {
        if let (Ok(name), Ok(value)) = (
            header::HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            r.headers_mut().append(name, value);
        }
    }
    r
}

fn marked(r: Response, code: Option<&'static str>) -> Response {
    match code.and_then(sts_core::errors::known) {
        Some(c) => sts_http::mark(r, c),
        None => r,
    }
}

/// `cors.crossSiteBrowserRequest(req)` (#1442): a page of another site.
fn cross_site(asked: &Asked, cookie_domain: bool) -> bool {
    let origin = asked.header("origin");
    let site = asked.header("sec-fetch-site").to_ascii_lowercase();
    if !origin.is_empty() && origin != "null" {
        return !asked.own_origins.contains(&origin);
    }
    if !site.is_empty() {
        return site != "same-origin"
            && !(site == "same-site" && cookie_domain);
    }
    origin == "null"
}

/// The body as `helpers.parseBody()` reads it: JSON, or a form.
fn body_of(headers: &HeaderMap, text: &str) -> Option<Object> {
    let kind = header_of(headers, "content-type").to_ascii_lowercase();
    if kind.contains("json") {
        if text.trim().is_empty() {
            return Some(Object::new());
        }
        return match serde_json::from_str::<Value>(text) {
            Ok(Value::Object(o)) => Some(o),
            _ => None,
        };
    }
    Some(
        sts_mgmt_api::request::parse_query(text)
            .into_iter()
            .collect(),
    )
}

/// `LOGOUT_FORM`, as the model's schemas are written for the checker.
fn logout_form() -> Value {
    json!({ "type": "object", "properties": {
        "scope": { "anyOf": [{ "type": "string", "const": "" },
                   { "type": "string", "enum": ["global", "selected"] }] },
        "select": { "type": "array",
                    "items": { "type": "string", "maxLength": 4096 } },
        "csrf_token": { "anyOf": [{ "type": "string", "const": "" },
                        { "type": "string", "minLength": 1,
                          "maxLength": 4096 }] } } })
}

impl SignOutDoor {
    /// The router: `/logout` and `/logout/signed-out`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route(LOGOUT_PATH, any(serve))
            .route(&format!("{}/", LOGOUT_PATH), any(serve))
            .route(SIGNED_OUT_PATH, any(serve))
            .with_state(self.clone())
    }

    fn asked_of(&self, request: &AxumRequest) -> Asked {
        let over_tls = request
            .extensions()
            .get::<sts_http::cookie_wire::OverTls>()
            .is_some();
        let peer = request
            .extensions()
            .get::<sts_http::client_address::Peer>()
            .copied();
        let headers = request.headers();
        let prefix = self.http.registry().current_prefix();
        let query = request.uri().query().unwrap_or("").to_string();
        let path = request.uri().path().to_string();
        Asked {
            request: sts_authn::ports::Request {
                cookie: header_of(headers, "cookie"),
                user_agent: header_of(headers, "user-agent"),
                address: self.http.client_address_of(headers, peer.as_ref()),
                url: if query.is_empty() {
                    path
                } else {
                    format!("{}?{}", path, query)
                },
                ..sts_authn::ports::Request::default()
            },
            query: sts_mgmt_api::request::parse_query(&query)
                .into_iter()
                .collect(),
            headers: headers
                .iter()
                .map(|(k, v)| {
                    (
                        k.as_str().to_string(),
                        v.to_str().unwrap_or("").to_string(),
                    )
                })
                .collect(),
            base: sts_authn_api::router::base_of(
                &self.settings,
                headers,
                over_tls,
                &prefix,
            ),
            own_origins: self.http.own_origins(
                headers,
                peer.as_ref(),
                over_tls,
            ),
        }
    }

    /// The sign-out's shell, with the arrival's cookie.
    fn shell(
        &self,
        headers: &HeaderMap,
        person: &str,
        reply: &Reply,
    ) -> Response {
        let html = self.surfaces.shells().signout(headers, person);
        let options = sts_http::shell::ServeOptions {
            csp: vec![("style-src".into(), Some("'self'".into()))],
            ..sts_http::shell::ServeOptions::default()
        };
        with_reply(sts_http::shell::serve(headers, html, &options), reply)
    }

    /// `GET /logout`.
    fn get(
        &self,
        headers: &HeaderMap,
        asked: &Asked,
        mut reply: Reply,
    ) -> Response {
        let logout = &self.logout;
        let subject = logout.subject_of(asked, None);
        let json = Logout::wants_json(asked);
        if subject.refused {
            if json {
                return marked(
                    json_answer(
                        403,
                        &json!({ "error": "forbidden",
                            "error_description":
                                logout.refused_name_message(&subject.asked) }),
                        &reply,
                    ),
                    Some(codes::STS_LOGOUT_0001.as_str()),
                );
            }
            return self.shell(headers, "", &reply);
        }
        if subject.key.is_empty() && logout.account_step(asked, false).is_some()
        {
            if json {
                return self.account_choice_required(asked, &reply);
            }
            return self.shell(headers, "", &reply);
        }
        if subject.key.is_empty() {
            if json {
                return marked(
                    json_answer(
                        401,
                        &json!({ "error": "no_subject",
                            "error_description": logout.nobody_message(false) }),
                        &reply,
                    ),
                    Some(codes::STS_LOGOUT_0002.as_str()),
                );
            }
            let target = logout.deps.authn.begin_authentication(
                &json!({ "returnTo": LOGOUT_PATH, "protocol": "Logout",
                    "details": [{ "label": "what happens next",
                        "value": "you will be shown everything this \
                                  service is still holding for you",
                        "note": "signing out may mean signing in first: \
                                 this service has no other way to know \
                                 who is asking. The session this creates \
                                 is listed too." }] }),
                None,
            );
            return with_reply(sts_http::redirect(&target), &reply);
        }
        if json {
            let issuer = logout.issuer_for(asked);
            return match logout.inventory_for(&subject.key, &issuer) {
                Ok(Value::Object(inventory)) => {
                    let mut out = Map::new();
                    out.insert("username".into(), json!(subject.username));
                    out.extend(inventory);
                    json_answer(200, &Value::Object(out), &reply)
                }
                Ok(_) | Err(_) => self.failed(&mut reply),
            };
        }
        self.shell(headers, &subject.username, &reply)
    }

    /// A throw out of the model (an unread session page): Express's 500.
    fn failed(&self, _reply: &mut Reply) -> Response {
        let mut r = sts_http::text("Internal Server Error");
        *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        r
    }

    /// `accountChoiceRequired(req, res)`: 409 and the accounts by key.
    fn account_choice_required(
        &self,
        asked: &Asked,
        reply: &Reply,
    ) -> Response {
        let step = self
            .logout
            .account_step(asked, true)
            .unwrap_or(json!({ "accounts": [] }));
        let accounts = step.get("accounts").cloned().unwrap_or(json!([]));
        let n = accounts.as_array().map_or(0, Vec::len);
        marked(
            json_answer(
                409,
                &json!({ "error": "account_choice_required",
                    "error_description": format!(
                        "This browser is signed in to {} accounts and the \
                         request names none of them. Name one with account \
                         (its key), or sign every account out at POST \
                         /authn-api/logout/accounts.", n),
                    "accounts": accounts }),
                reply,
            ),
            Some(codes::STS_LOGOUT_0011.as_str()),
        )
    }

    /// `POST /logout`: the JSON door.
    fn post(
        &self,
        asked: &Asked,
        body_text: &str,
        headers: &HeaderMap,
        mut reply: Reply,
    ) -> Response {
        let logout = &self.logout;
        if !Logout::wants_json(asked) {
            let to =
                format!("{}{}", logout.deps.host.realm_prefix(), LOGOUT_PATH);
            return marked(
                with_reply(
                    sts_http::redirect_with(StatusCode::SEE_OTHER, &to),
                    &reply,
                ),
                Some(codes::STS_LOGOUT_0010.as_str()),
            );
        }
        let cookie_domain =
            js::truthy(Some(&logout.deps.host.setting("authn.cookieDomain")));
        if cross_site(asked, cookie_domain) {
            return marked(
                json_answer(
                    403,
                    &json!({ "error": "cross_site_request",
                        "error_description":
                            "This request came from a page of another site." }),
                    &reply,
                ),
                Some(codes::STS_LOGOUT_0014.as_str()),
            );
        }
        let body = body_of(headers, body_text).unwrap_or_default();
        let subject = logout.subject_of(asked, Some(&body));
        if subject.refused {
            return marked(
                json_answer(
                    403,
                    &json!({ "error": "forbidden",
                        "error_description":
                            logout.refused_name_message(&subject.asked) }),
                    &reply,
                ),
                Some(codes::STS_LOGOUT_0001.as_str()),
            );
        }
        if subject.key.is_empty() && logout.account_step(asked, false).is_some()
        {
            return self.account_choice_required(asked, &reply);
        }
        if subject.key.is_empty() {
            return marked(
                json_answer(
                    401,
                    &json!({ "error": "no_subject",
                        "error_description": logout.nobody_message(true) }),
                    &reply,
                ),
                Some(codes::STS_LOGOUT_0002.as_str()),
            );
        }
        if let Err(p) = sts_authn_api::body::check_parsed(
            &Value::Object(body.clone()),
            "body",
            &logout_form(),
        ) {
            return marked(
                json_answer(
                    400,
                    &json!({ "error": "invalid_request",
                             "error_description": p.detail }),
                    &reply,
                ),
                Some(codes::STS_LOGOUT_0003.as_str()),
            );
        }
        if logout.reauthentication_owed(&subject, &body) {
            return marked(
                json_answer(
                    403,
                    &json!({ "error": "reauthentication_required",
                        "errors": ["Sign in again at /authn/login, then come \
                                    back to end your other sessions."] }),
                    &reply,
                ),
                Some(codes::STS_LOGOUT_0015.as_str()),
            );
        }
        match logout.end_for(asked, &mut reply, &subject, &body) {
            Ok((result, ended_own)) => {
                let mut out = Map::new();
                out.insert("username".into(), json!(subject.username));
                out.insert("ownSessionEnded".into(), json!(ended_own));
                if let Value::Object(r) = result {
                    out.extend(r);
                }
                json_answer(200, &Value::Object(out), &reply)
            }
            Err(_) => self.failed(&mut reply),
        }
    }

    /// `POST /logout/signed-out`: the document a sign-out that fans out
    /// answers, from the sealed result.
    fn signed_out(
        &self,
        asked: &Asked,
        headers: &HeaderMap,
        body_text: &str,
    ) -> Response {
        let logout = &self.logout;
        let origin = asked.header("origin");
        let site = asked.header("sec-fetch-site");
        let same_site =
            (origin.is_empty() || origin == "null") && site == "same-origin";
        if !same_site
            && (origin.is_empty() || !asked.own_origins.contains(&origin))
        {
            return self.refused_document(
                headers,
                403,
                codes::STS_LOGOUT_0009.as_str(),
                &format!(
                    "This page is posted by the sign-out page of this \
                     service: the request carried {}.",
                    if !origin.is_empty() && origin != "null" {
                        "another origin"
                    } else {
                        "no origin of this service"
                    }
                ),
            );
        }
        let posted = body_of(headers, body_text).unwrap_or_default();
        let sealed = posted.get("result").and_then(Value::as_str);
        let opened = match sealed {
            Some(s) if s.encode_utf16().count() <= 4 * 1024 * 1024 => {
                logout.open_result(s)
            }
            _ => Err("There is no sign-out result here.".into()),
        };
        let result = match opened {
            Ok(r) => r,
            Err(why) => {
                return self.refused_document(
                    headers,
                    400,
                    codes::STS_LOGOUT_0008.as_str(),
                    &why,
                )
            }
        };
        let key = js::string_of(result.get("key"));
        let issuer = logout.issuer_for(asked);
        let remaining = match logout.inventory_for(&key, &issuer) {
            Ok(r) => r,
            Err(_) => return self.failed(&mut Reply::default()),
        };
        let (html, policy) = self.result_page(headers, &result, &remaining);
        send_page(200, &html, &policy)
    }

    fn translator<'a>(
        &'a self,
        headers: &HeaderMap,
        person: &str,
    ) -> sts_http::i18n::Translator<'a> {
        self.surfaces
            .shells()
            .surfaces
            .translator(headers, "", person)
    }

    /// `page(t, returnTo, title, inner, policy)`: the document, with the
    /// language chooser first.
    fn page(
        &self,
        t: &sts_http::i18n::Translator<'_>,
        return_to: &str,
        title: &str,
        inner: &str,
    ) -> String {
        let catalogs = &self.surfaces.shells().surfaces.catalogs;
        format!(
            "<!doctype html><html lang=\"{}\" dir=\"{}\"><head><meta \
             charset=\"utf-8\"><meta name=\"viewport\" \
             content=\"width=device-width, initial-scale=1\"><title>{}\
             </title><style>{}</style></head><body>{}{}</body></html>",
            esc(&t.negotiated.locale),
            if t.negotiated.rtl { "rtl" } else { "ltr" },
            esc(title),
            SIGNOUT_CSS,
            crate::document::chooser(t, catalogs, return_to),
            inner
        )
    }

    /// `resultPage(base, result, inventory)`: two tabs — *Sign out*, and
    /// *Details* with the fan-out.
    pub fn result_page(
        &self,
        headers: &HeaderMap,
        result: &Value,
        inventory: &Value,
    ) -> (String, String) {
        let logout = &self.logout;
        let key = js::string_of(result.get("key"));
        let t = self.translator(headers, &key);
        let html = |k: &str, params: &[(&str, &str)]| -> String {
            let escaped: Vec<(String, String)> = params
                .iter()
                .map(|(n, v)| (n.to_string(), esc(v)))
                .collect();
            let refs: Vec<(&str, &str)> = escaped
                .iter()
                .map(|(n, v)| (n.as_str(), v.as_str()))
                .collect();
            t.text(k, &refs)
        };
        let list_of = |rows: &[Value], cls: &str| -> String {
            let body: String = rows
                .iter()
                .map(|one| {
                    let label = js::or_empty(one.get("label"));
                    let label = if label.is_empty() {
                        js::string_of(one.get("id"))
                    } else {
                        label
                    };
                    format!(
                        "<tr><td><code>{}</code></td><td class=\"{}\">{}</td></tr>",
                        esc(&label),
                        cls,
                        esc(&js::string_of(one.get("message")))
                    )
                })
                .collect();
            format!("<table><tbody>{}</tbody></table>", body)
        };
        let rows = |name: &str| -> Vec<Value> {
            result
                .get(name)
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        };
        let terminated = rows("terminated");
        let skipped = rows("skipped");
        let fan = logout.fan_out_of(&[result]);
        let partners = logout
            .deps
            .federation_slo
            .render_partner_logouts(&rows("partnerLogouts"));
        let sign_out = format!(
            "{}{}<p><strong>{}</strong></p><p class=\"sub\">{}</p><p><a \
             class=\"btn\" href=\"/portal\">{}</a></p>",
            if terminated.is_empty() {
                format!(
                    "<div class=\"warn\">{}</div>",
                    html("logout.result.nothingEnded", &[])
                )
            } else {
                format!(
                    "<div class=\"ok\">{}</div>",
                    html("logout.result.brief", &[])
                )
            },
            partners,
            html("logout.result.closeTab", &[]),
            html("logout.result.seeDetails", &[]),
            html("logout.result.toPortal", &[])
        );
        let total = js::number_or_zero(inventory.get("total"));
        let details = format!(
            "<p class=\"sub\">{}</p>{}{}{}<h2>{}</h2>{}",
            esc(&js::string_of(result.get("message"))),
            if terminated.is_empty() {
                format!(
                    "<div class=\"warn\">{}</div>",
                    html("logout.result.nothingEnded", &[])
                )
            } else {
                format!(
                    "<h2>{}</h2>{}",
                    html("logout.result.ended", &[]),
                    list_of(&terminated, "sub")
                )
            },
            if skipped.is_empty() {
                String::new()
            } else {
                format!(
                    "<h2>{}</h2>{}{}",
                    html("logout.result.notEnded", &[]),
                    list_of(&skipped, "cannot"),
                    crate::document::note(&html(
                        "logout.result.notEndedNote",
                        &[]
                    ))
                )
            },
            fan.html,
            html("logout.result.stillLive", &[]),
            if total != 0.0 {
                format!(
                    "<p class=\"sub\">{} <a href=\"{}\">{}</a>{}</p>",
                    html(
                        "logout.result.remain",
                        &[("total", &js::text(&js::num(total)))]
                    ),
                    esc(&format!(
                        "{}?username={}",
                        LOGOUT_PATH,
                        js::encode_uri_component(&key)
                    )),
                    html("logout.result.lookAgain", &[]),
                    html("logout.result.lookAgainEnd", &[])
                )
            } else {
                format!(
                    "<div class=\"ok\">{}</div>",
                    html("logout.result.nothingLeft", &[("key", &key)])
                )
            }
        );
        let inner = format!(
            "<h1>{}</h1>{}",
            if js::string_of(result.get("scope")) == "global" {
                html("logout.result.headingGlobal", &[])
            } else {
                html("logout.result.headingSelected", &[])
            },
            crate::document::tabbed_panels(
                "logout-tabs",
                &[
                    (
                        "logout-signout",
                        &t.text("logout.tab.signOut", &[]),
                        sign_out
                    ),
                    (
                        "logout-details",
                        &t.text("logout.tab.details", &[]),
                        details
                    ),
                ]
            )
        );
        let prefix = logout.deps.host.realm_prefix();
        let page = self.page(
            &t,
            &format!("{}{}", prefix, LOGOUT_PATH),
            &t.text("logout.result.title", &[]),
            &inner,
        );
        let refs: Vec<(&str, Option<&str>)> = fan
            .policy
            .iter()
            .map(|(k, v)| (k.as_str(), Some(v.as_str())))
            .collect();
        (page, sts_http::csp::content_security_policy(&refs))
    }

    /// `refusedDocument(res, status, code, why)`: a page of its own,
    /// English, with the way back.
    fn refused_document(
        &self,
        headers: &HeaderMap,
        status: u16,
        code: &'static str,
        why: &str,
    ) -> Response {
        let t = self.translator(headers, "");
        let prefix = self.logout.deps.host.realm_prefix();
        let inner = format!(
            "<h1>{}</h1><div class=\"err\">{}</div><p class=\"sub\"><a \
             href=\"{}\">{}</a>{}</p>",
            esc(&t.text("logout.heading", &[])),
            esc(why),
            esc(LOGOUT_PATH),
            esc(&t.text("logout.startAgain", &[])),
            esc(&t.text("logout.startAgainEnd", &[]))
        );
        let html = self.page(
            &t,
            &format!("{}{}", prefix, LOGOUT_PATH),
            &t.text("logout.title", &[]),
            &inner,
        );
        marked(
            send_page(status, &html, &sts_http::csp::base_policy()),
            Some(code),
        )
    }
}

/// `send(res, built, status)`: HTML, `no-store`, the page's policy.
fn send_page(status: u16, html: &str, policy: &str) -> Response {
    let mut r = sts_http::html(html.to_string());
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    let h = r.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(v) = HeaderValue::from_str(policy) {
        h.insert(header::CONTENT_SECURITY_POLICY, v);
    }
    r
}

async fn serve(
    State(door): State<Arc<SignOutDoor>>,
    request: AxumRequest,
) -> Response {
    let asked = door.asked_of(&request);
    let headers = request.headers().clone();
    let method = request.method().clone();
    let path = request
        .uri()
        .path()
        .trim_end_matches('/')
        .to_ascii_lowercase();
    let body_text = request
        .extensions()
        .get::<sts_http::body::ParsedBody>()
        .and_then(|b| b.text.clone())
        .unwrap_or_default();
    if path.ends_with(SIGNED_OUT_PATH) {
        if method != Method::POST {
            let uri = request.uri().clone();
            return sts_http::not_found(method, uri, None).await;
        }
        return door.signed_out(&asked, &headers, &body_text);
    }
    // THE FRONT DOOR: the arrival session before the route runs.
    let mut reply = Reply::default();
    door.logout.deps.authn.arrival(&asked, &mut reply);
    if method == Method::GET || method == Method::HEAD {
        return door.get(&headers, &asked, reply);
    }
    if method == Method::POST {
        return door.post(&asked, &body_text, &headers, reply);
    }
    let uri = request.uri().clone();
    sts_http::not_found(method, uri, None).await
}

/// The page's operations behind `/authn-api/logout`.
pub struct SignOutPages {
    pub logout: Arc<Logout>,
}

fn asked_from_call(
    call: &sts_authn_api::flow::Call,
    query: &Map<String, Value>,
) -> Asked {
    Asked {
        request: call.request.clone(),
        query: query.clone(),
        headers: Vec::new(),
        base: call.base.clone(),
        own_origins: Vec::new(),
    }
}

fn answer_of(
    seen: Result<Answered, String>,
    reply: Reply,
) -> sts_authn_api::flow::Answer {
    match seen {
        Ok(a) => {
            let mut out = sts_authn_api::flow::Answer::json(a.status, a.json);
            out.code = a.code.and_then(sts_core::errors::known);
            out.cookies = reply.cookies;
            out.headers = reply.headers;
            out
        }
        Err(why) => {
            tracing::error!("logout: the sign-out could not be read: {}", why);
            sts_authn_api::flow::Answer::json(
                500,
                json!({ "ok": false, "errors": ["The sign-out could not be read."] }),
            )
        }
    }
}

impl sts_authn_api::ports::SignOutPages for SignOutPages {
    fn view(
        &self,
        call: &sts_authn_api::flow::Call,
        query: &Map<String, Value>,
    ) -> sts_authn_api::flow::Answer {
        let asked = asked_from_call(call, query);
        answer_of(self.logout.sign_out_view(&asked), Reply::default())
    }

    fn act(
        &self,
        call: &sts_authn_api::flow::Call,
        query: &Map<String, Value>,
        body: &Map<String, Value>,
    ) -> sts_authn_api::flow::Answer {
        let asked = asked_from_call(call, query);
        let mut reply = Reply::default();
        let seen = self.logout.sign_out_act(&asked, &mut reply, body);
        answer_of(seen, reply)
    }

    fn accounts_view(
        &self,
        call: &sts_authn_api::flow::Call,
        query: &Map<String, Value>,
    ) -> sts_authn_api::flow::Answer {
        let asked = asked_from_call(call, query);
        answer_of(
            Ok(self.logout.sign_out_accounts_view(&asked)),
            Reply::default(),
        )
    }

    fn accounts_act(
        &self,
        call: &sts_authn_api::flow::Call,
        query: &Map<String, Value>,
        body: &Map<String, Value>,
    ) -> sts_authn_api::flow::Answer {
        let asked = asked_from_call(call, query);
        let mut reply = Reply::default();
        let seen = self.logout.sign_out_accounts_act(&asked, &mut reply, body);
        answer_of(seen, reply)
    }
}
