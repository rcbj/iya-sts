// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `GET` and `POST /oauth2/authorize` (`oauth2.ts`'s `authorizeEndpoint()`,
//! `authorizeRequest()`, `vetAuthorizationRequest()` and
//! `issueAuthorizationResponse()`), in Node's order, with Node's errors,
//! codes and sentences.
//!
//! * **The request is vetted before anything else** — the model, a client
//!   registered ahead of time in product, the redirect URI against the
//!   client's REGISTERED ones (`oauth2_bcp.checkRedirectUri()`: exact match
//!   in every mode where the client registered any, and in RFC 9700 mode —
//!   which product implies — an absolute https URI, or loopback http, that
//!   is registered), the response type and mode the authorization server
//!   advertises, PKCE (S256, 43 characters; required of a public client),
//!   `nonce` where an ID Token is asked for, the declared flows, RFC 8707's
//!   registered targets.
//! * **RFC 6749 section 4.1.2.1**: a refusal about the client or the
//!   redirect URI is ANSWERED, never redirected; every later one is sent
//!   to the client's redirect URI — except that in RFC 9700 mode nobody
//!   signed in on the browser means the error is shown rather than bounced
//!   (section 4.11.2), so the endpoint is no open redirector.
//! * **The session hand-off**: no session (or `prompt=login`) writes a
//!   pending sign-in ([`crate::signin`]) whose `returnTo` is this request
//!   again, less `prompt`, and the browser goes to the screen; the request
//!   comes back with a session and is answered.
//! * **The code** is minted as Node mints it — 24 random bytes, base64url,
//!   stored under `credentialDigest(code)` in `oauth2.authzCodes` with
//!   Node's record, bound to the client, the redirect URI, the PKCE
//!   challenge, the session and the resources — and returned by the
//!   response mode asked for: the query, the fragment, or `form_post`'s
//!   page posted by `/oauth2/autopost.js`. `iss` is on every response (RFC
//!   9207).
//!
//! WHAT IS NOT HERE, each a later slice, and what this runtime answers
//! meanwhile:
//! * request objects and pushed requests (RFC 9101, RFC 9126): a request
//!   carrying `request` or `request_uri`, or from a client that requires a
//!   signed one, is refused `request_not_supported` (`STS-OAUTH-0340`); a
//!   realm or client requiring PAR refuses every request as Node refuses
//!   an unpushed one (`STS-OAUTH-0419`);
//! * `id_token_hint` (the OIDC slice): refused `invalid_request`
//!   (`STS-OAUTH-0566`), never ignored;
//! * the response types that issue a token from this endpoint (`token`,
//!   `id_token`): refused `unsupported_response_type` (`STS-OAUTH-0162`'s
//!   sentence) until the OIDC slice mints an ID Token here; `none` is
//!   answered;
//! * RFC 9396 details, RFC 9470 step-up, Grant Management, FAPI, the
//!   launch window of an application signed into only from here, OpenID4VCI's
//!   `issuer_state`, OpenID Federation's automatic registration and
//!   Session Management's `session_state`: the request is answered as Node
//!   answers one using none of them, and one that names a parameter
//!   only they read (`authorization_details`, `acr_values`, `max_age`,
//!   `claims`, `grant_management_action`) is answered as if it had not —
//!   which is what Node does with the feature switched off;
//! * consent ([`crate::consent`]): a scope still needing an answer sends
//!   the person to the consent screen, and comes back to this request
//!   whole; `prompt=none` is refused `consent_required`
//!   (`STS-OAUTH-0168`), as in Node.
//!
//! THE PAGES A BROWSER IS SHOWN (#1326's `ErrorPage`, `sts_http::error_page`):
//! a refusal that is never redirected is the shared error page for a GET
//! whose `Accept` names `text/html` (`refuseAuthorization()`) and the JSON
//! a client library gets otherwise; an error RFC 9700 section 4.11.2 will
//! not bounce is the interstitial (`sendRedirectInterstitial()`) — a link
//! carrying what the redirect would have, a button POSTing it for
//! `form_post`, the one JWT-secured `response` for a JARM mode
//! ([`crate::jarm`]).

use std::sync::Arc;

use serde_json::{json, Map, Value as Json};
use sts_authn::ports::Request;
use sts_core::errors::{codes, ErrorCode};
use sts_core::mode::Mode;
use sts_core::settings::Settings;

use crate::answer::{sanitize_description, Answer, Body};
use crate::clients::Clients;
use crate::grants::GrantStores;
use crate::scopes::{
    audience_scopes, describe_unregistered, parse_resource_indicators,
    permission_refusal, protocol_scopes, RegisteredTargets, ScopePolicy,
};
use crate::signin::{Begin, SignInHandOff};
use sts_http::error_page::{DiagnosticRow, ErrorPageSpec};

/// What an authorization request is.
#[derive(Debug, Clone, Default)]
pub struct AuthorizeAsk {
    /// `GET` or `POST`.
    pub method: String,
    pub content_type: String,
    /// The query string, without its `?`.
    pub query: String,
    /// The body of a POST.
    pub body: String,
    pub accept: String,
    /// `Accept-Language`, for the page a `form_post` is drawn on.
    pub accept_language: String,
    /// `asBaseOf(req)`: the realm's base URL.
    pub base: String,
    /// `realms.currentPrefix()`: the realm's path prefix (`''`, or
    /// `/realm/acme`), for the error page's portal link and return path.
    pub prefix: String,
    /// The session core's view of the request (cookies, address, the
    /// account marks).
    pub request: Request,
}

/// The session core's doors the endpoint uses (`sts_authn::Sessions`).
pub trait SignOn: Send + Sync {
    /// `sessionOf(req)`.
    fn session_of(&self, request: &Request) -> Option<Json>;
    /// `notePresented(session, via, req, application)`.
    fn note_presented(&self, sid: &str, request: &Request, application: &str);
    /// `holdPresentation(session)`.
    fn hold_presentation(&self, sid: &str);
    /// `frontchannel.noteClient(session, clientId, { iss, sub })`.
    fn note_client(&self, sid: &str, client_id: &str, iss: &str, sub: &str);
    /// `authn.hintAccount(req, { loginHint, sub, sid })`.
    fn hint_account(&self, request: &Request, login_hint: &str);
    /// `authn.accountChoiceNeeded(req)`.
    fn account_choice_needed(&self, request: &Request) -> Option<Json>;
    /// `authn.noteAccountAmbiguous(req, via, why)`.
    fn note_account_ambiguous(&self, request: &Request, why: &str);
}

impl SignOn for sts_authn::Sessions {
    fn session_of(&self, request: &Request) -> Option<Json> {
        sts_authn::Sessions::session_of(self, request, false)
    }

    fn note_presented(&self, sid: &str, request: &Request, application: &str) {
        sts_authn::Sessions::note_presented(
            self,
            sid,
            "OAuth 2.0 / OIDC",
            Some(request),
            application,
        );
    }

    fn hold_presentation(&self, sid: &str) {
        sts_authn::Sessions::hold_presentation(self, sid);
    }

    fn note_client(&self, sid: &str, client_id: &str, iss: &str, sub: &str) {
        if sid.is_empty() || client_id.is_empty() {
            return;
        }
        let now = sts_core::time::now_ms_f64();
        let (iss, sub) = (iss.to_string(), sub.to_string());
        let client = client_id.to_string();
        self.note_session_changed(sid, move |s| {
            let clients = s.entry("oidcClients").or_insert_with(|| json!({}));
            if !clients.is_object() {
                *clients = json!({});
            }
            let known = clients.get(&client).cloned().unwrap_or(Json::Null);
            let first = known
                .get("first")
                .filter(|v| crate::js::to_number(v) > 0.0)
                .cloned()
                .unwrap_or_else(|| json!(now as i64));
            let count =
                crate::js::to_number(known.get("count").unwrap_or(&json!(0)))
                    as i64;
            let pick = |said: &str, member: &str| {
                if said.is_empty() {
                    crate::js::string_of(known.get(member))
                } else {
                    said.to_string()
                }
            };
            clients[&client] = json!({
                "first": first, "last": now as i64, "count": count + 1,
                "iss": pick(&iss, "iss"), "sub": pick(&sub, "sub"),
            });
        });
    }

    fn hint_account(&self, request: &Request, login_hint: &str) {
        sts_authn::Sessions::hint_account(
            self,
            request,
            &json!({ "loginHint": login_hint }),
        );
    }

    fn account_choice_needed(&self, request: &Request) -> Option<Json> {
        sts_authn::Sessions::account_choice_needed(self, request)
    }

    fn note_account_ambiguous(&self, request: &Request, why: &str) {
        sts_authn::Sessions::note_account_ambiguous(
            self,
            request,
            "OAuth 2.0 / OIDC",
            why,
        );
    }
}

/// The scopes a resource gates by role (`role_permissions.ts`, rule 3bq):
/// `asksForGated(scope)`, and `narrowScope()`'s answer.
pub trait GatedScopes: Send + Sync {
    fn asks_for_gated(&self, scope: &str) -> bool;
    /// `{ scope, emptied, why }` for a person.
    fn narrow(
        &self,
        scope: &str,
        username: &str,
        authenticated: bool,
        client_id: &str,
        grant: &str,
    ) -> Json;
}

/// No scope is gated by role.
pub struct NoGatedScopes;

impl GatedScopes for NoGatedScopes {
    fn asks_for_gated(&self, _scope: &str) -> bool {
        false
    }
    fn narrow(&self, scope: &str, _: &str, _: bool, _: &str, _: &str) -> Json {
        json!({ "scope": scope, "emptied": false, "why": "" })
    }
}

/// The page a `form_post` response is drawn on (`formPostResponse()`):
/// a message of the page's negotiated catalog, unfilled, and the
/// `<html>` attributes (` lang="…" dir="…"`).
pub trait Pages: Send + Sync {
    fn message(
        &self,
        ask: &AuthorizeAsk,
        ui_locales: &str,
        key: &str,
    ) -> String;
    fn html_attributes(&self, ask: &AuthorizeAsk, ui_locales: &str) -> String;
    /// `ErrorPage.send()`'s document (#1326): `draw` translates the page's
    /// parts in the page's language, and the page is drawn with the
    /// incident ID and the footer.
    fn error_page(
        &self,
        ask: &AuthorizeAsk,
        ui_locales: &str,
        draw: &dyn Fn(
            &sts_http::i18n::Translator<'_>,
            &sts_http::i18n::Catalogs,
        ) -> ErrorPageSpec,
    ) -> String;
}

/// The catalogs under `common/locales/` (`PageLocale.translatorFor()`):
/// `ui_locales` first, then the chooser's `sts_lang` cookie, then
/// `Accept-Language`, English last.
pub struct CatalogPages {
    pub catalogs: Arc<sts_http::i18n::Catalogs>,
    /// The page footer's facts (`PageFooter.facts()`).
    pub footer: sts_http::footer::Facts,
    /// `audit.reserveIncident(res)`: the incident ID, or 0 where no audit
    /// ring is held (the page then says none was recorded).
    pub incident: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl CatalogPages {
    fn preferences(ask: &AuthorizeAsk, ui_locales: &str) -> Vec<String> {
        let chooser =
            sts_authn::cookie::cookie_value(&ask.request.cookie, "sts_lang");
        sts_http::i18n::preferences(&sts_http::i18n::Preferences {
            ui_locales: ui_locales.to_string(),
            own: None,
            chooser,
            accept_language: ask.accept_language.clone(),
        })
    }
}

impl Pages for CatalogPages {
    fn message(
        &self,
        ask: &AuthorizeAsk,
        ui_locales: &str,
        key: &str,
    ) -> String {
        let t = self
            .catalogs
            .translator(&Self::preferences(ask, ui_locales), "");
        t.text(key, &[])
    }

    fn html_attributes(&self, ask: &AuthorizeAsk, ui_locales: &str) -> String {
        let n = self
            .catalogs
            .negotiate(&Self::preferences(ask, ui_locales), "");
        format!(
            " lang=\"{}\" dir=\"{}\"",
            esc(&n.locale),
            if n.rtl { "rtl" } else { "ltr" }
        )
    }

    fn error_page(
        &self,
        ask: &AuthorizeAsk,
        ui_locales: &str,
        draw: &dyn Fn(
            &sts_http::i18n::Translator<'_>,
            &sts_http::i18n::Catalogs,
        ) -> ErrorPageSpec,
    ) -> String {
        let t = self
            .catalogs
            .translator(&Self::preferences(ask, ui_locales), "");
        let spec = draw(&t, &self.catalogs);
        sts_http::error_page::document(
            &t,
            &spec,
            (self.incident)(),
            &sts_http::error_page::iso_now(),
            &ask.prefix,
            &self.footer,
        )
    }
}

/// `t.html(key, params)`: the message's own markup kept, every parameter
/// escaped.
fn html_of(message: &str, params: &[(&str, &str)]) -> String {
    let mut out = message.to_string();
    for (name, value) in params {
        out = out.replace(&format!("{{{}}}", name), &esc(value));
    }
    out
}

/// `t.text(key)`: the inline elements a message may carry stripped.
fn text_of(message: &str) -> String {
    let mut out = message.to_string();
    for tag in [
        "<strong>",
        "</strong>",
        "<em>",
        "</em>",
        "<code>",
        "</code>",
        "<br>",
    ] {
        out = out.replace(tag, "");
    }
    out
}

/// `oauth21.DRAFT`: the revision every OAuth 2.1 refusal cites.
const OAUTH21_DRAFT: &str = "draft-ietf-oauth-v2-1-16";

/// `oauth21.registeredClientRefusal(client, clientId)`: OAuth 2.1 mode's
/// refusal of a client with no redirect URI of its own (section 2.3.1).
fn registered_client_refusal(
    client: &Json,
    client_id: &str,
) -> (ErrorCode, String) {
    let withheld = values(client.get("unconfirmed_redirect_uris"));
    if !withheld.is_empty() {
        return (codes::STS_OAUTH_0272, format!(
            "OAuth 2.1 ({}) section 2.3.1: a client must have registered its complete redirect URI. Client \"{}\" has only redirect URIs this service observed and nobody has confirmed, and product mode does not believe an observed address. Confirm the one it should use on /admin/applications, or POST /admin-api/applications/confirm-address.",
            OAUTH21_DRAFT, client_id));
    }
    let who = if client_id.is_empty() {
        "This client".to_string()
    } else {
        format!("Client \"{}\"", client_id)
    };
    let known = client.get("known") == Some(&Json::Bool(true));
    (codes::STS_OAUTH_0271, format!(
        "OAuth 2.1 ({}) section 2.3.1: \"Authorization servers MUST require clients to register their complete redirect URI.\" {} has {}. Register it at POST /oauth2/register with its redirect_uris, or give its application entry an oauthRedirectUri on /admin/applications. The service-wide oauth2.redirectUris list is not consulted in this mode.",
        OAUTH21_DRAFT,
        who,
        if known { "an entry here with no redirect URI on it" } else { "no entry here at all" }))
}

/// `oauthPages.authorizeError.auto`: its one plural (`{seconds, plural,
/// one {# second} other {# seconds}}`) chosen by the page language's
/// cardinal rule, which the server's translator does not format.
fn auto_sentence(t: &sts_http::i18n::Translator<'_>, n: i64) -> String {
    let raw = t.text("oauthPages.authorizeError.auto", &[]);
    let lang = t.negotiated.catalog.split('-').next().unwrap_or("en");
    let one = match lang {
        "zh" => false,
        "fr" => n == 0 || n == 1,
        "fil" => n % 10 != 4 && n % 10 != 6 && n % 10 != 9,
        _ => n == 1,
    };
    let Some(open) = raw.find("{seconds, plural,") else {
        return html_of(&raw, &[("seconds", &n.to_string())]);
    };
    // The plural's two arms, `one {…}` and `other {…}`.
    let body = &raw[open + "{seconds, plural,".len()..];
    let arm = |name: &str| -> Option<String> {
        let at = body.find(&format!("{} {{", name))?;
        let rest = &body[at + name.len() + 2..];
        rest.find('}').map(|end| rest[..end].to_string())
    };
    let chosen = if one { arm("one") } else { arm("other") }
        .or_else(|| arm("other"))
        .unwrap_or_default()
        .replace('#', &n.to_string());
    let close = body
        .rfind("}}")
        .map(|i| open + "{seconds, plural,".len() + i + 2)
        .unwrap_or(raw.len());
    format!("{}{}{}", &raw[..open], esc(&chosen), &raw[close..])
}

/// The endpoint's dependencies.
pub struct AuthorizationEndpoint {
    pub settings: Arc<Settings>,
    pub mode: Arc<Mode>,
    pub clients: Arc<dyn Clients>,
    pub scopes: Arc<ScopePolicy>,
    pub grants: Arc<GrantStores>,
    pub sign_on: Arc<dyn SignOn>,
    pub hand_off: Arc<dyn SignInHandOff>,
    pub gated: Arc<dyn GatedScopes>,
    /// The consent register and screen (`common/consent.ts`,
    /// `consent_screen.ts`); `None` asks nobody and records nothing, as
    /// `oauth2.consentRequired` off does.
    pub consent: Option<Arc<crate::consent::ConsentScreen>>,
    pub pages: Arc<dyn Pages>,
    /// The realm's key, for a JWT-secured response (JARM); `None` refuses
    /// one as a response that cannot be made (`STS-OAUTH-0588`).
    pub signer: Option<Arc<dyn crate::token_endpoint::Signer>>,
    /// `capabilityFor(req, member)`: the authorization server's own
    /// metadata, before the named-server overlay.
    pub capabilities: Arc<dyn Fn(&str) -> Json + Send + Sync>,
    pub now_ms: Arc<dyn Fn() -> f64 + Send + Sync>,
    pub random_id: Arc<dyn Fn(usize) -> String + Send + Sync>,
}

/// What vetting accepts: the parameters, the response types, the client.
type Accepted = (Map<String, Json>, Vec<String>, Json);

/// What vetting refuses: the parameters where they were read, and why.
type Refused = (Option<Map<String, Json>>, Vetted);

/// One refusal of vetting: `redirect` says whether it goes to the client.
struct Vetted {
    redirect: bool,
    status: u16,
    code: ErrorCode,
    error: &'static str,
    description: String,
    /// `pageText.key` (#1326): the error page's sentence where one code
    /// covers two cases.
    page_key: Option<String>,
}

fn s(v: Option<&Json>) -> String {
    crate::js::string_of(v)
}

fn words(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_string).collect()
}

fn values(v: Option<&Json>) -> Vec<String> {
    match v {
        None | Some(Json::Null) => Vec::new(),
        Some(Json::Array(list)) => list.iter().map(|x| s(Some(x))).collect(),
        Some(one) => vec![s(Some(one))],
    }
}

/// `xmlEscape()`.
fn esc(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// The query as Express's `qs` parses it: a repeated name an array, and
/// `a[b]=c` a structure (which the model refuses as `structured`).
fn query_of(raw: &str) -> Map<String, Json> {
    let pairs = crate::js::form_decode(raw);
    let mut plain: Vec<(String, String)> = Vec::new();
    let mut out = Map::new();
    for (k, v) in pairs {
        if let Some(open) = k.find('[') {
            if open > 0 && k.ends_with(']') {
                let name = k[..open].to_string();
                let inner = k[open + 1..k.len() - 1].to_string();
                let held = out.entry(name).or_insert_with(|| json!({}));
                if let Some(o) = held.as_object_mut() {
                    o.insert(inner, Json::from(v));
                }
                continue;
            }
        }
        plain.push((k, v));
    }
    let folded = crate::js::fold(&plain);
    let mut merged = folded;
    for (k, v) in out {
        merged.insert(k, v);
    }
    merged
}

/// `URLSearchParams` over a query object: an array as the name repeated.
fn query_string(q: &Map<String, Json>, omit: &[&str]) -> String {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for (k, v) in q {
        if omit.contains(&k.as_str()) {
            continue;
        }
        match v {
            Json::Array(list) => {
                for one in list {
                    pairs.push((k.clone(), s(Some(one))));
                }
            }
            other => pairs.push((k.clone(), s(Some(other)))),
        }
    }
    crate::js::form_encode(&pairs)
}

impl AuthorizationEndpoint {
    fn bcp_enabled(&self) -> bool {
        self.settings.value_of("oauth2.rfc9700").as_bool()
            || self.settings.value_of("oauth2.oauth21").as_bool()
            || self.mode.enforces_oauth_security_bcp()
    }

    fn capability(&self, base: &str, member: &str) -> Option<Vec<String>> {
        (self.capabilities)(base)
            .get(member)
            .and_then(Json::as_array)
            .map(|l| l.iter().map(|v| s(Some(v))).collect())
    }

    /// `refuseAuthorization()`: never redirected.
    fn refuse(
        &self,
        code: ErrorCode,
        status: u16,
        error: &str,
        description: &str,
    ) -> Answer {
        Answer::refusal(code, status, error, description)
    }

    /// `usesFragment(types, responseMode)`.
    fn uses_fragment(types: &[String], mode: &str) -> bool {
        mode == "fragment" || types.iter().any(|t| t != "code" && t != "none")
    }

    #[allow(clippy::too_many_arguments)]
    /// `redirectBack()`: the response by its mode. `fields` are in Node's
    /// order; `state` and `iss` follow them.
    fn redirect_back(
        &self,
        ask: &AuthorizeAsk,
        redirect_uri: &str,
        state: Option<&str>,
        params: Vec<(String, String)>,
        fragment: bool,
        mode: &str,
        client_id: &str,
        ui_locales: &str,
    ) -> Answer {
        let mut fields: Vec<(String, String)> = params
            .into_iter()
            .map(|(k, v)| {
                if k == "error_description" {
                    let clean = sanitize_description(&v);
                    (k, clean)
                } else {
                    (k, v)
                }
            })
            .collect();
        if let Some(st) = state {
            fields.push(("state".into(), st.to_string()));
        }
        fields.push(("iss".into(), ask.base.clone()));
        if crate::jarm::is_jarm(mode) {
            // `jarmRedirect()`: the fields as one signed `response`, sent
            // by the mode's transport; one that cannot be made is a 400
            // rather than a response sent unsecured.
            let types: Vec<String> =
                vec![if fragment { "token" } else { "code" }.to_string()];
            return match self.jarm_target(
                ask,
                client_id,
                redirect_uri,
                &fields,
                mode,
                &types,
            ) {
                Ok((true, jwt, _)) => self.form_post(
                    ask,
                    redirect_uri,
                    &[("response".to_string(), jwt)],
                    client_id,
                    ui_locales,
                ),
                Ok((false, _, url)) => Answer::redirect(&url),
                Err((code, why)) => {
                    tracing::error!(
                        "{}oauth2: a JARM response could not be made: {}",
                        sts_core::log::tag(code),
                        why
                    );
                    Answer::refusal(code, 400, "invalid_request", &why)
                }
            };
        }
        if mode == "form_post" {
            return self.form_post(
                ask,
                redirect_uri,
                &fields,
                client_id,
                ui_locales,
            );
        }
        let sep = if fragment {
            "#"
        } else if redirect_uri.contains('?') {
            "&"
        } else {
            "?"
        };
        Answer::redirect(&format!(
            "{}{}{}",
            redirect_uri,
            sep,
            crate::js::form_encode(&fields)
        ))
    }

    /// `formPostResponse()`: the fields as hidden inputs, a real submit
    /// button, and `/oauth2/autopost.js`, under `script-src 'self'`.
    fn form_post(
        &self,
        ask: &AuthorizeAsk,
        redirect_uri: &str,
        fields: &[(String, String)],
        _client_id: &str,
        ui_locales: &str,
    ) -> Answer {
        let html_attributes = self.pages.html_attributes(ask, ui_locales);
        let message = |key: &str| self.pages.message(ask, ui_locales, key);
        let h =
            |key: &str, params: &[(&str, &str)]| html_of(&message(key), params);
        let inputs: String = fields
            .iter()
            .map(|(n, v)| {
                format!(
                    "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
                    esc(n),
                    esc(v)
                )
            })
            .collect();
        let rows: String = fields
            .iter()
            .map(|(n, v)| {
                format!("<div>{}: <code>{}</code></div>", esc(n), esc(v))
            })
            .collect();
        let html = format!(
            "<!doctype html><html{}><head><meta charset=\"utf-8\"><title>{}</title><style>\
             body{{font-family:system-ui,sans-serif;margin:2rem;max-width:52rem;color:#222}}\
             code{{font-family:ui-monospace,Menlo,monospace;font-size:.85rem;background:#f4f4f8;\
             padding:.1rem .25rem;border-radius:3px;word-break:break-all}}.sub{{color:#666}}\
             .meta{{margin-top:1.5rem;font-size:.9rem;color:#444}}\
             button{{font:inherit;padding:.4rem .9rem}}</style></head><body>\
             <h1>{}</h1><p class=\"sub\">{}</p><form method=\"post\" action=\"{}\" id=\"oauth2-form\">{}\
             <div><button type=\"submit\">{}</button></div></form><div class=\"meta\"><div>{}</div>{}\
             <div>{}</div></div><script src=\"/oauth2/autopost.js\"></script></body></html>",
            html_attributes,
            esc(&text_of(&message("oauthPages.formPost.title"))),
            h("oauthPages.formPost.heading", &[]),
            h("oauthPages.formPost.sub", &[]),
            esc(redirect_uri),
            inputs,
            h("oauthPages.formPost.continue", &[]),
            h("oauthPages.formPost.postingTo", &[("uri", redirect_uri)]),
            rows,
            h("oauthPages.formPost.scriptNote", &[]),
        );
        let mut a = Answer::new(200, Body::Html(html));
        a.set(
            "Content-Security-Policy",
            &sts_http::csp::content_security_policy(&[(
                "script-src",
                Some("'self'"),
            )]),
        );
        a.set("Content-Type", "text/html; charset=utf-8");
        a.set("Cache-Control", "no-store");
        a
    }

    /// `checkRedirectUri()` (`oauth2_bcp.js`).
    fn check_redirect_uri(
        &self,
        client: &Json,
        client_id: &str,
        presented: &str,
    ) -> Result<(), (ErrorCode, String)> {
        let own = values(client.get("redirect_uris"));
        if !self.bcp_enabled() {
            if own.is_empty()
                || own.iter().any(|r| self.uri_matches(r, presented))
            {
                return Ok(());
            }
            return Err((codes::STS_OAUTH_0569, format!(
                "OIDC Core section 3.1.2.1: \"{}\" is not a redirect URI registered for this client, and a redirect_uri must match a registered one exactly.",
                presented)));
        }
        let Ok(parsed) = url::Url::parse(presented) else {
            return Err((codes::STS_OAUTH_0119, format!(
                "RFC 9700 section 2.1: redirect_uri must be an absolute URI. \"{}\" does not parse as one.",
                presented)));
        };
        if parsed.scheme() == "http"
            && !is_loopback(parsed.host_str().unwrap_or(""))
        {
            return Err((codes::STS_OAUTH_0120, format!(
                "RFC 9700 section 2.6: an authorization server must not allow a redirect URI using the http scheme, except for a native application redirecting to a loopback address (127.0.0.1, [::1] or localhost). \"{}\" is neither.",
                presented)));
        }
        let list = if !own.is_empty() {
            own
        } else {
            self.settings
                .value_of("oauth2.redirectUris")
                .as_list()
                .to_vec()
        };
        let oauth21 = self.settings.value_of("oauth2.oauth21").as_bool();
        // Section 2.3.1: a client registers ITS OWN redirect URI, so OAuth
        // 2.1 mode does not read the service-wide list.
        let list = if oauth21 && values(client.get("redirect_uris")).is_empty()
        {
            Vec::new()
        } else {
            list
        };
        if list.is_empty() && oauth21 {
            return Err(registered_client_refusal(client, client_id));
        }
        if list.is_empty() {
            return Err((codes::STS_OAUTH_0121, "RFC 9700 section 2.1 requires redirect_uri to be compared by exact string match against the URIs registered for this client, and none are registered. Add this URI to the oauth2.redirectUris setting (/admin/oauth2, or POST /admin-api/config), or register the client with its redirect_uris at POST /oauth2/register.".to_string()));
        }
        if list.iter().any(|r| self.uri_matches(r, presented)) {
            return Ok(());
        }
        Err((codes::STS_OAUTH_0122, format!(
            "RFC 9700 section 2.1: \"{}\" is not a redirect URI registered for this client, and a redirect_uri must match a registered one by exact string comparison (RFC 3986 section 6.2.1).",
            presented)))
    }

    /// `uriMatches()`: exact, or a loopback URI with any port where the
    /// realm allows it (RFC 8252 section 7.3).
    fn uri_matches(&self, registered: &str, presented: &str) -> bool {
        if registered == presented {
            return true;
        }
        if !self
            .settings
            .value_of("oauth2.loopbackPortWildcard")
            .as_bool()
        {
            return false;
        }
        let (Ok(a), Ok(b)) =
            (url::Url::parse(registered), url::Url::parse(presented))
        else {
            return false;
        };
        let (ha, hb) = (a.host_str().unwrap_or(""), b.host_str().unwrap_or(""));
        is_loopback(ha)
            && ha.eq_ignore_ascii_case(hb)
            && a.scheme() == b.scheme()
            && a.path() == b.path()
            && a.query() == b.query()
            && a.fragment() == b.fragment()
    }

    /// `vetAuthorizationRequest(req)`: the request's parameters, or the
    /// refusal and whether it is redirected.
    fn vet(
        &self,
        ask: &AuthorizeAsk,
        input: &Map<String, Json>,
    ) -> Result<Accepted, Box<Refused>> {
        let refuse = |code, error, description: String| {
            Box::new((
                None,
                Vetted {
                    redirect: false,
                    status: 400,
                    code,
                    error,
                    description,
                    page_key: None,
                },
            ))
        };
        let mut q = match crate::model::check("authorize", input, "query") {
            Ok(v) => v,
            Err(r) => {
                return Err(refuse(
                    codes::STS_OAUTH_0159,
                    "invalid_request",
                    r.detail,
                ))
            }
        };
        let client_id = s(q.get("client_id"));
        if !self.mode.issues_to_unregistered_applications() {
            let id = client_id.trim();
            if id.is_empty() {
                return Err(refuse(codes::STS_OAUTH_0948, "invalid_request", "The request names no client_id. In product mode this authorization server serves only a client registered ahead of time (the console, /admin-api, RFC 7591, an LDAP add under ou=applications or an OpenID Federation).".into()));
            }
            if self.clients.registered_by(id).is_empty() {
                return Err(refuse(codes::STS_OAUTH_0947, "invalid_client", format!(
                    "The client \"{}\" is not registered in this realm. In product mode this authorization server serves only a client registered ahead of time (the console, /admin-api, RFC 7591, an LDAP add under ou=applications or an OpenID Federation); one that was only seen is not registered.",
                    id)));
            }
        }
        let client = self.clients.client_config_of(&client_id);
        // OAUTH 2.1: THE CLIENT FIRST, AND A DEFAULT redirect_uri (section
        // 4.1.1: OPTIONAL where exactly one is registered). Both refusals
        // are answered here, as a 400: there is no validated address yet.
        if self.settings.value_of("oauth2.oauth21").as_bool() {
            if client_id.trim().is_empty() {
                return Err(refuse(codes::STS_OAUTH_0144, "invalid_request", "RFC 9700 section 4.11.2, citing RFC 6749 section 4.1.2.1: an authorization server must not automatically redirect the user agent for an invalid combination of client_id and redirect_uri. This request names no client_id at all, so there is no client the redirect_uri could belong to — and reporting that BY redirecting to the URI is exactly what that paragraph forbids. It is answered here instead.".into()));
            }
            if s(q.get("redirect_uri")).is_empty() {
                let own = values(client.get("redirect_uris"));
                if own.len() == 1 {
                    q.insert("redirect_uri".into(), Json::from(own[0].clone()));
                } else if own.len() > 1 {
                    return Err(refuse(codes::STS_OAUTH_0273, "invalid_request", format!(
                        "OAuth 2.1 ({}) section 4.1.1: redirect_uri is REQUIRED when a client has registered more than one, and client \"{}\" has {}. Send the one this request should be answered at.",
                        OAUTH21_DRAFT, client_id, own.len())));
                } else {
                    let (code, why) =
                        registered_client_refusal(&client, &client_id);
                    return Err(refuse(code, "invalid_request", why));
                }
            }
        }
        let redirect_uri = s(q.get("redirect_uri"));
        if redirect_uri.is_empty() {
            let mut r = refuse(
                codes::STS_OAUTH_0160,
                "invalid_request",
                if q.contains_key("redirect_uri") {
                    "A valid absolute redirect_uri is required.".into()
                } else {
                    "This authorization request has no redirect_uri, and one is required: without it there is nowhere to send the response.".into()
                },
            );
            if q.contains_key("redirect_uri") {
                r.1.page_key =
                    Some(format!("{}-empty", codes::STS_OAUTH_0160.as_str()));
            }
            return Err(r);
        }
        if let Err((code, description)) =
            self.check_redirect_uri(&client, &client_id, &redirect_uri)
        {
            return Err(refuse(code, "invalid_request", description));
        }
        let response_mode = s(q.get("response_mode"));
        if response_mode == "form_post"
            && crate::model::is_private_use_redirect(&redirect_uri)
        {
            return Err(refuse(codes::STS_OAUTH_0270, "invalid_request", format!(
                "response_mode=form_post cannot be answered at \"{}\": it is a native application's private-use URI, and an operating system hands a protocol handler the URL and never a request body. Use response_mode=query (or fragment).",
                redirect_uri)));
        }
        let redirectable =
            |q: &Map<String, Json>, code, error, description: String| {
                Box::new((
                    Some(q.clone()),
                    Vetted {
                        redirect: true,
                        status: 400,
                        code,
                        error,
                        description,
                        page_key: None,
                    },
                ))
            };
        if self.bcp_enabled() && client_id.trim().is_empty() {
            return Err(refuse(codes::STS_OAUTH_0144, "invalid_request", "RFC 9700 section 4.11.2, citing RFC 6749 section 4.1.2.1: an authorization server must not automatically redirect the user agent for an invalid combination of client_id and redirect_uri. This request names no client_id at all, so there is no client the redirect_uri could belong to — and reporting that BY redirecting to the URI is exactly what that paragraph forbids. It is answered here instead.".into()));
        }
        if client_id.is_empty() {
            return Err(redirectable(
                &q,
                codes::STS_OAUTH_0161,
                "invalid_request",
                "client_id is required.".into(),
            ));
        }
        if let Some(t) = q.get("tenant") {
            let realm = sts_core::realm::current_id();
            let realm = if realm.is_empty() {
                "default".to_string()
            } else {
                realm
            };
            if s(Some(t)) != realm {
                return Err(redirectable(&q, codes::STS_OAUTH_0688, "invalid_request", format!(
                    "tenant \"{}\" is not this authorization server's tenant (\"{}\"); a tenant is chosen by the path the request is sent to.",
                    s(Some(t)), realm)));
            }
        }
        let raw_type = s(q.get("response_type"));
        let types = words(&raw_type);
        if types.len() > 1 && types.iter().any(|t| t == "none") {
            return Err(redirectable(&q, codes::STS_OAUTH_0606, "unsupported_response_type", format!(
                "response_type \"none\" asks for no credential at all (Multiple Response Type Encoding Practices section 4), so it cannot be combined with \"{}\".",
                types.iter().filter(|t| *t != "none").cloned().collect::<Vec<_>>().join(" "))));
        }
        let known = ["code", "token", "id_token", "none"];
        if types.is_empty()
            || types.iter().any(|t| !known.contains(&t.as_str()))
        {
            let named = raw_type.trim().to_string();
            let mut r = redirectable(
                &q,
                codes::STS_OAUTH_0162,
                "unsupported_response_type",
                if named.is_empty() {
                    "This request names no response_type, and every authorization request must name one (RFC 6749 section 3.1.1).".into()
                } else {
                    format!("response_type \"{}\" is not supported.", named)
                },
            );
            if !named.is_empty() {
                r.1.page_key = Some(format!(
                    "{}-unsupported",
                    codes::STS_OAUTH_0162.as_str()
                ));
            }
            return Err(r);
        }
        let mut sorted = types.clone();
        sorted.sort();
        if let Some(advertised) =
            self.capability(&ask.base, "response_types_supported")
        {
            let offered = advertised.iter().any(|one| {
                let mut w = words(one);
                w.sort();
                w == sorted
            });
            if !offered {
                return Err(redirectable(&q, codes::STS_OAUTH_0163, "unsupported_response_type", format!(
                    "The \"default\" authorization server advertises response_types_supported {} and this request asks for \"{}\". What its metadata says is what it does — the document is this authorization server rather than a description of one.",
                    json!(advertised), types.join(" "))));
            }
        }
        if !response_mode.is_empty() {
            if let Some(modes) =
                self.capability(&ask.base, "response_modes_supported")
            {
                if !modes.contains(&response_mode) {
                    return Err(redirectable(&q, codes::STS_OAUTH_0164, "invalid_request", format!(
                        "The \"default\" authorization server advertises response_modes_supported {} and this request asks for \"{}\". It is refused rather than answered with a redirect, because a client that asked for a mode this server does not perform would otherwise wait for a response that never arrives — which is a failure with nothing at this end to point at.{}",
                        json!(modes), response_mode,
                        if response_mode == "web_message" { " `web_message` in particular is postMessage-based, and this service has no browser messaging of any kind: no page here posts a message, receives one, or frames anything." } else { "" })));
                }
            }
        }
        if response_mode == "query"
            && types.iter().any(|t| t == "token" || t == "id_token")
        {
            return Err(redirectable(&q, codes::STS_OAUTH_0607, "invalid_request", format!(
                "response_mode=query cannot carry response_type \"{}\": a response returning a token or an ID Token MUST NOT use the query encoding (OAuth 2.0 Multiple Response Type Encoding Practices section 2.1). Use fragment or form_post.",
                raw_type)));
        }
        let key_binding = !matches!(
            self.settings.value_of("oauth2.keyBinding"),
            sts_core::settings::SettingValue::Bool(false)
        );
        let scope = s(q.get("scope"));
        if !key_binding && words(&scope).iter().any(|w| w == "bound_key") {
            let kept: Vec<String> = words(&scope)
                .into_iter()
                .filter(|w| w != "bound_key")
                .collect();
            q.insert("scope".into(), json!(kept.join(" ")));
        }
        let scope = s(q.get("scope"));
        if words(&scope).iter().any(|w| w == "bound_key") {
            if s(q.get("dpop_jkt")).is_empty() {
                return Err(redirectable(&q, codes::STS_OAUTH_0704, "invalid_request", "The bound_key scope requires dpop_jkt on the authorization request: the ID Token is bound to that DPoP key (OpenID Connect Key Binding section 3).".into()));
            }
            if types.join(" ") != "code" {
                return Err(redirectable(&q, codes::STS_OAUTH_0705, "invalid_request", "The bound_key scope is honoured with response_type=code only: an ID Token from the authorization endpoint carries no DPoP proof to bind it to (OpenID Connect Key Binding section 3).".into()));
            }
        }
        let method = s(q.get("code_challenge_method"));
        if !method.is_empty() {
            if let Some(pkce) =
                self.capability(&ask.base, "code_challenge_methods_supported")
            {
                if !pkce.contains(&method) {
                    return Err(redirectable(&q, codes::STS_OAUTH_0165, "invalid_request", format!(
                        "The \"default\" authorization server advertises code_challenge_methods_supported {} and this request asks for \"{}\".",
                        json!(pkce), method)));
                }
            }
        }
        let id_token_asked = types.iter().any(|t| t == "id_token");
        if id_token_asked && !words(&scope).iter().any(|w| w == "openid") {
            return Err(redirectable(&q, codes::STS_OAUTH_0560, "invalid_scope", format!(
                "response_type \"{}\" asks for an ID Token, and an OpenID Connect request MUST carry the openid scope (OIDC Core section 3.1.2.1). Add openid to scope.",
                raw_type)));
        }
        let prompt = words(&s(q.get("prompt")));
        if prompt.iter().any(|p| p == "none") && prompt.len() > 1 {
            return Err(redirectable(&q, codes::STS_OAUTH_0561, "invalid_request", format!(
                "prompt \"{}\" combines none with another value, and OIDC Core section 3.1.2.1 says that is an error: none forbids every prompt the others ask for.",
                s(q.get("prompt")))));
        }
        let implicit = id_token_asked && !types.iter().any(|t| t == "code");
        if id_token_asked && s(q.get("nonce")).is_empty() {
            return Err(redirectable(&q, codes::STS_OAUTH_0562, "invalid_request", format!(
                "This request has no nonce, and response_type \"{}\" returns an ID Token from the authorization endpoint, for which OIDC Core makes nonce REQUIRED (section {}): it is what the client checks the ID Token against to detect a replay.",
                raw_type,
                if implicit { "3.2.2.1, the implicit flow" } else { "3.3.2.1, the hybrid flow" })));
        }
        if implicit {
            if let Ok(u) = url::Url::parse(&redirect_uri) {
                if u.scheme() == "http"
                    && !["localhost", "127.0.0.1", "[::1]"]
                        .contains(&u.host_str().unwrap_or(""))
                {
                    return Err(refuse(codes::STS_OAUTH_0563, "invalid_request", format!(
                        "OIDC Core section 3.2.2.1: the implicit flow MUST NOT use an http redirect_uri unless the client is a native application redirecting to localhost, 127.0.0.1 or [::1]. \"{}\" is neither, and the tokens would cross the network in clear.",
                        redirect_uri)));
                }
            }
        }
        let flows = self.clients.declared_flows_of(&client_id);
        let asked_type = sorted.join(" ");
        if let Some(declared) = flows
            .as_ref()
            .and_then(|f| f.get("response_types"))
            .and_then(Json::as_array)
        {
            let list: Vec<String> =
                declared.iter().map(|v| s(Some(v))).collect();
            if !list.contains(&asked_type) {
                return Err(redirectable(&q, codes::STS_OAUTH_0597, "unauthorized_client", format!(
                    "Client \"{}\" declares response_types {}, and this request asks for \"{}\" (RFC 7591 section 2).",
                    client_id, json!(list), raw_type)));
            }
        }
        let declares_implicit = flows
            .as_ref()
            .and_then(|f| f.get("grant_types"))
            .and_then(Json::as_array)
            .is_some_and(|g| g.iter().any(|v| v == "implicit"));
        let declares_types = flows
            .as_ref()
            .and_then(|f| f.get("response_types"))
            .is_some_and(|v| !v.is_null());
        if !asked_type.is_empty()
            && asked_type != "code"
            && self.mode.narrows_undeclared_grants()
            && !declares_types
            && !declares_implicit
        {
            return Err(redirectable(&q, codes::STS_OAUTH_0597, "unauthorized_client", format!(
                "Client \"{}\" declares no response_types, so it may use response_type=code alone (RFC 7591 section 2).",
                client_id)));
        }
        if let Some((code, error, description)) =
            self.check_authorization_request(&q, &types, &client)
        {
            return Err(redirectable(&q, code, error, description));
        }
        // RFC 8707's registered targets.
        let resources = values(q.get("resource"));
        if let Ok(asked) = parse_resource_indicators(&resources) {
            let targets = RegisteredTargets {
                clients: self.clients.as_ref(),
                settings: &self.settings,
            };
            let strangers =
                targets.unregistered(&asked, std::slice::from_ref(&ask.base));
            if !strangers.is_empty() {
                return Err(redirectable(
                    &q,
                    codes::STS_OAUTH_0950,
                    "invalid_target",
                    format!(
                        "RFC 8707 section 2: the resource {}",
                        describe_unregistered(&strangers)
                    ),
                ));
            }
        }
        Ok((q, types, client))
    }

    /// `bcp.checkAuthorizationRequest()`.
    fn check_authorization_request(
        &self,
        q: &Map<String, Json>,
        types: &[String],
        client: &Json,
    ) -> Option<(ErrorCode, &'static str, String)> {
        if !self.bcp_enabled() {
            return None;
        }
        let waived = self
            .settings
            .value_of("oauth2.allowImplicitTokenResponses")
            .as_bool()
            && !self.settings.value_of("oauth2.oauth21").as_bool();
        if types.iter().any(|t| t == "token") && !waived {
            return Some((codes::STS_OAUTH_0126, "unsupported_response_type", format!(
                "RFC 9700 section 2.1.2: clients should not use the implicit grant or any other response type that issues an access token from the authorization endpoint. Use response_type=code{}.",
                if types.iter().any(|t| t == "id_token") { " or code id_token" } else { "" })));
        }
        let confidential = crate::bcp::is_confidential(client);
        let challenge = s(q.get("code_challenge"));
        let oauth21 = self.settings.value_of("oauth2.oauth21").as_bool();
        // OAUTH 2.1 — PKCE FOR CONFIDENTIAL CLIENTS TOO, and the method
        // REQUIRED (`oauth21.pkceDecision()`): asked first and only in that
        // mode; "confidential" is a credential this service can check.
        if oauth21 && types.iter().any(|t| t == "code") {
            if !challenge.is_empty() {
                if s(q.get("code_challenge_method")).is_empty() {
                    return Some((codes::STS_OAUTH_0276, "invalid_request", format!(
                        "OAuth 2.1 ({}) section 4.1.1: code_challenge_method is REQUIRED — send code_challenge_method=S256. RFC 7636 read an absent method as plain; OAuth 2.1 removed that default and forbids plain (section 7.5.2).",
                        OAUTH21_DRAFT)));
                }
            } else {
                let checked = confidential
                    && crate::bcp::credential_on_file(client, None);
                let openid =
                    words(&s(q.get("scope"))).iter().any(|w| w == "openid");
                let nonce = !s(q.get("nonce")).is_empty();
                if !(checked && openid && nonce) {
                    let mut missing: Vec<&str> = Vec::new();
                    if !checked {
                        missing.push("the client is not confidential with a credential on file");
                    }
                    if !openid {
                        missing.push("the request is not OpenID Connect (no openid scope)");
                    }
                    if !nonce {
                        missing.push("the request carries no nonce");
                    }
                    return Some((codes::STS_OAUTH_0275, "invalid_request", format!(
                        "OAuth 2.1 ({}) section 7.5.1.1: code_challenge and code_verifier are REQUIRED for every client, confidential ones included, unless a confidential client is relying on the OpenID Connect nonce instead — and here {}. Send code_challenge with code_challenge_method=S256.",
                        OAUTH21_DRAFT, missing.join(", and "))));
                }
            }
        }
        if types.iter().any(|t| t == "code") && challenge.is_empty() && !oauth21
        {
            if !confidential {
                return Some((codes::STS_OAUTH_0127, "invalid_request", "RFC 9700 section 2.1.1: public clients must use PKCE (RFC 7636). Send code_challenge and code_challenge_method=S256. A client registered here with a token_endpoint_auth_method other than \"none\" is treated as confidential, for which PKCE is RECOMMENDED rather than required.".into()));
            }
            if self.mode.requires_pkce_of_every_client() {
                return Some((codes::STS_OAUTH_1002, "invalid_request", "This server requires PKCE (RFC 7636) of every client. Send code_challenge and code_challenge_method=S256.".into()));
            }
            tracing::warn!(
                "RFC 9700 section 2.1.1: confidential client \"{}\" sent no code_challenge. PKCE is RECOMMENDED for confidential clients; the request is answered, and this is the SHOULD it did not follow.",
                s(q.get("client_id")));
        }
        if !challenge.is_empty() {
            let method = match s(q.get("code_challenge_method")) {
                m if m.is_empty() => "plain".to_string(),
                m => m,
            };
            if method != "S256" {
                return Some((codes::STS_OAUTH_0128, "invalid_request", format!(
                    "RFC 9700 section 2.1.1: use a code challenge method that does not expose the verifier. S256 is currently the only one, and it is the only value code_challenge_methods_supported advertises in this mode. \"{}\" is refused.",
                    method)));
            }
            let well_formed = challenge.len() == 43
                && challenge.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
                });
            if !well_formed {
                return Some((codes::STS_OAUTH_0129, "invalid_request", format!(
                    "RFC 7636 section 4.2: an S256 code_challenge is the base64url encoding, without padding, of the SHA-256 of the code_verifier — 43 characters. This one is {}.",
                    challenge.encode_utf16().count())));
            }
        }
        if types.iter().any(|t| t == "id_token") && s(q.get("nonce")).is_empty()
        {
            return Some((codes::STS_OAUTH_0130, "invalid_request", "RFC 9700 section 2.1.1: the OpenID Connect nonce must be transaction-specific and bound to the user-agent transaction, and a response_type naming id_token must carry one — it is what a client validates the id_token against to detect an injected code.".into()));
        }
        None
    }

    /// The endpoint.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn answer(&self, ask: &AuthorizeAsk) -> Answer {
        let input = if ask.method.eq_ignore_ascii_case("POST") {
            let kind = ask
                .content_type
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if kind != "application/x-www-form-urlencoded" {
                return self.refuse(codes::STS_OAUTH_0564, 400, "invalid_request", &format!(
                    "An authorization request sent with POST is form-serialized — Content-Type application/x-www-form-urlencoded (OIDC Core section 3.1.2.1, section 13.2). This one is \"{}\".",
                    if kind.is_empty() { "(none)" } else { &kind }));
            }
            crate::js::fold(&crate::js::form_decode(&ask.body))
        } else {
            query_of(&ask.query)
        };
        let client_id = s(input.get("client_id"));
        let client = self.clients.client_config_of(&client_id);
        let jar = !s(input.get("request")).is_empty()
            || !s(input.get("request_uri")).is_empty();
        let signed_required = client.get("require_signed_request_object")
            == Some(&Json::Bool(true))
            || self
                .settings
                .value_of("oauth2.requireSignedRequestObject")
                .as_bool();
        if jar || signed_required {
            let mut a = self.refuse_on(ask, &input, codes::STS_OAUTH_0340, 400, "request_not_supported",
                "This authorization server does not yet read a request object (RFC 9101) or a pushed request_uri (RFC 9126): send the parameters on the request itself.", None);
            a.set("Cache-Control", "no-store");
            return a;
        }
        if !s(input.get("id_token_hint")).is_empty() {
            return self.refuse_on(ask, &input, codes::STS_OAUTH_0566, 400, "invalid_request",
                "id_token_hint: this authorization server does not yet verify an id_token_hint; send login_hint instead.", None);
        }
        // pushedRequestPolicyRefusal(): nothing is pushed here.
        let mut required_by: Vec<String> = Vec::new();
        if self
            .settings
            .value_of("oauth2.requirePushedAuthorizationRequests")
            .as_bool()
        {
            required_by
                .push("oauth2.requirePushedAuthorizationRequests".into());
        }
        if client.get("require_pushed_authorization_requests")
            == Some(&Json::Bool(true))
        {
            required_by.push(format!(
                "client \"{}\"'s require_pushed_authorization_requests",
                client_id
            ));
        }
        if !required_by.is_empty() {
            return self.refuse_on(ask, &input, codes::STS_OAUTH_0419, 400, "invalid_request", &format!(
                "this authorization request was not pushed, and {} says pushed authorization requests are the only means of sending one here (RFC 9126 section 4). POST the parameters to {}/oauth2/par first and send the request_uri it answers with.",
                required_by.join(" and "), ask.base), None);
        }
        let (q, types, client) = match self.vet(ask, &input) {
            Ok(v) => v,
            Err(e) if e.0.is_none() || !e.1.redirect => {
                let v = e.1;
                return self.refuse_on(
                    ask,
                    &input,
                    v.code,
                    v.status,
                    v.error,
                    &v.description,
                    v.page_key.as_deref(),
                );
            }
            Err(e) => {
                let (q, v) = *e;
                let q = q.unwrap_or_default();
                let session = self.sign_on.session_of(&ask.request);
                return self.fail_keyed(
                    ask,
                    &q,
                    session.is_some(),
                    v.code,
                    v.error,
                    &v.description,
                    v.page_key.as_deref(),
                );
            }
        };
        self.authorize(ask, q, types, client)
    }

    /// `fail(error, description)`: redirected to the client, or — in RFC
    /// 9700 mode, with nobody signed in and no `prompt=none` — answered
    /// here (section 4.11.2).
    fn fail(
        &self,
        ask: &AuthorizeAsk,
        q: &Map<String, Json>,
        has_session: bool,
        code: ErrorCode,
        error: &str,
        description: &str,
    ) -> Answer {
        self.fail_keyed(ask, q, has_session, code, error, description, None)
    }

    /// `fail(error, description, pageText)`.
    #[allow(clippy::too_many_arguments)]
    fn fail_keyed(
        &self,
        ask: &AuthorizeAsk,
        q: &Map<String, Json>,
        has_session: bool,
        code: ErrorCode,
        error: &str,
        description: &str,
        page_key: Option<&str>,
    ) -> Answer {
        let prompt_none =
            words(&s(q.get("prompt"))).iter().any(|p| p == "none");
        let from_sign_in = !s(q.get("authn_error")).is_empty();
        let redirect =
            !self.bcp_enabled() || has_session || prompt_none || from_sign_in;
        let types = words(&s(q.get("response_type")));
        let mode = s(q.get("response_mode"));
        let state = q.get("state").map(|v| s(Some(v)));
        let redirect_uri = s(q.get("redirect_uri"));
        if !redirect {
            return self
                .interstitial(
                    ask,
                    q,
                    code,
                    error,
                    description,
                    page_key,
                    &types,
                    &mode,
                )
                .marked(code);
        }
        self.redirect_back(
            ask,
            &redirect_uri,
            state.as_deref(),
            vec![
                ("error".into(), error.to_string()),
                ("error_description".into(), description.to_string()),
            ],
            Self::uses_fragment(&types, &mode),
            &mode,
            &s(q.get("client_id")),
            &s(q.get("ui_locales")),
        )
        .marked(code)
    }

    /// `isBrowserRequest(req)`: a GET whose `Accept` names `text/html`.
    fn is_browser(ask: &AuthorizeAsk) -> bool {
        ask.method.eq_ignore_ascii_case("GET")
            && ask.accept.to_ascii_lowercase().contains("text/html")
    }

    /// `refuseAuthorization()` and `sendRefusalPage()`: a refusal that is
    /// never redirected — the shared error page for a browser (#1326), the
    /// JSON a client library gets otherwise, with the same status, error
    /// and description.
    #[allow(clippy::too_many_arguments)]
    fn refuse_on(
        &self,
        ask: &AuthorizeAsk,
        q: &Map<String, Json>,
        code: ErrorCode,
        status: u16,
        error: &str,
        description: &str,
        page_key: Option<&str>,
    ) -> Answer {
        if !Self::is_browser(ask) {
            return self.refuse(code, status, error, description);
        }
        let ui = s(q.get("ui_locales"));
        let html = self.pages.error_page(ask, &ui, &|t, catalogs| {
            let tx = |key: &str| sts_http::error_page::text(t, key, &[]);
            let hx = |key: &str| sts_http::error_page::html(t, key, &[]);
            ErrorPageSpec {
                chooser: self.chooser_of(ask, t, catalogs),
                status,
                title: tx("oauthPages.authorizeError.title"),
                error: error.to_string(),
                message: Self::refusal_message(t, code, error, q, page_key),
                background: hx("oauthPages.authorizeError.notSent"),
                diagnostics: self.diagnostics(ask, t, q, error, description),
                ..ErrorPageSpec::default()
            }
        });
        Self::page_answer(status, html).marked(code)
    }

    fn page_answer(status: u16, html: String) -> Answer {
        let mut a = Answer::new(status, Body::Html(html));
        a.set("Content-Type", "text/html; charset=utf-8");
        a.set("Cache-Control", "no-store");
        a
    }

    /// `ErrorPage.chooser(t, req)`.
    fn chooser_of(
        &self,
        ask: &AuthorizeAsk,
        t: &sts_http::i18n::Translator<'_>,
        catalogs: &sts_http::i18n::Catalogs,
    ) -> String {
        let url = format!("{}{}", ask.prefix, ask.request.url);
        sts_http::error_page::chooser(
            t,
            catalogs,
            &sts_http::error_page::return_path(&ask.method, &url, &ask.prefix),
        )
    }

    /// `refusalMessage(t, code, error, q, pageText)`: the refusal's own
    /// sentence where `oauthPages` has one — by the key it named, then by
    /// its code — and otherwise the protocol error's general sentence.
    fn refusal_message(
        t: &sts_http::i18n::Translator<'_>,
        code: ErrorCode,
        error: &str,
        q: &Map<String, Json>,
        page_key: Option<&str>,
    ) -> String {
        let values: Vec<(&str, String)> = vec![
            ("uri", s(q.get("redirect_uri"))),
            ("type", s(q.get("response_type"))),
            ("mode", s(q.get("response_mode"))),
            ("method", s(q.get("code_challenge_method"))),
            ("client", s(q.get("client_id"))),
            ("requestUri", s(q.get("request_uri"))),
            ("prompt", s(q.get("prompt"))),
            ("tenant", s(q.get("tenant"))),
        ];
        let params: Vec<(&str, &str)> =
            values.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let candidates = vec![
            page_key
                .map(|k| format!("oauthPages.refusal.{}", k))
                .unwrap_or_default(),
            format!("oauthPages.refusal.{}", code.as_str()),
            format!("oauthPages.oauthError.{}", error),
            "oauthPages.oauthError.other".to_string(),
        ];
        sts_http::error_page::sentence(t, &candidates, &params)
    }

    /// `authorizationDiagnostics(req, t, q, error, description)`.
    fn diagnostics(
        &self,
        ask: &AuthorizeAsk,
        t: &sts_http::i18n::Translator<'_>,
        q: &Map<String, Json>,
        error: &str,
        description: &str,
    ) -> Vec<DiagnosticRow> {
        let client_id = s(q.get("client_id"));
        let name = if client_id.is_empty() {
            String::new()
        } else {
            let client = self.clients.client_config_of(&client_id);
            s(client.get("declared").and_then(|d| d.get("client_name")))
        };
        let username = self
            .sign_on
            .session_of(&ask.request)
            .map(|v| s(v.get("user").and_then(|u| u.get("username"))))
            .unwrap_or_default();
        let row = |key: &str, value: String| DiagnosticRow {
            label: sts_http::error_page::text(t, key, &[]),
            value,
        };
        vec![
            row("errorPages.application", client_id.clone()),
            row("errorPages.applicationName", name),
            row("errorPages.redirectUri", s(q.get("redirect_uri"))),
            row("errorPages.responseType", s(q.get("response_type"))),
            row("errorPages.responseMode", s(q.get("response_mode"))),
            row("errorPages.state", s(q.get("state"))),
            row("errorPages.nonce", s(q.get("nonce"))),
            row("errorPages.signedInAs", username),
            row("errorPages.error", error.to_string()),
            row(
                "errorPages.errorDescription",
                sanitize_description(description),
            ),
        ]
    }

    /// `redirectTarget(base, redirectUri, state, params, fragment)`.
    fn redirect_target(
        base: &str,
        redirect_uri: &str,
        state: Option<&str>,
        params: &[(String, String)],
        fragment: bool,
    ) -> String {
        let mut pairs: Vec<(String, String)> = params
            .iter()
            .map(|(k, v)| {
                if k == "error_description" {
                    (k.clone(), sanitize_description(v))
                } else {
                    (k.clone(), v.clone())
                }
            })
            .collect();
        if let Some(st) = state {
            pairs.push(("state".into(), st.to_string()));
        }
        pairs.push(("iss".into(), base.to_string()));
        let sep = if fragment {
            "#"
        } else if redirect_uri.contains('?') {
            "&"
        } else {
            "?"
        };
        format!("{}{}{}", redirect_uri, sep, crate::js::form_encode(&pairs))
    }

    /// `jarmUrl(res, issuer, redirectUri, fields, mode)`: the JWT, and the
    /// URL carrying it (a form_post.jwt response has one too, in the query,
    /// for the interstitial's link).
    fn jarm_target(
        &self,
        ask: &AuthorizeAsk,
        client_id: &str,
        redirect_uri: &str,
        fields: &[(String, String)],
        mode: &str,
        types: &[String],
    ) -> Result<(bool, String, String), crate::jarm::Refusal> {
        let Some(signer) = self.signer.as_ref() else {
            return Err((
                codes::STS_OAUTH_0588,
                "This client's JWT-secured authorization response cannot be                  made: no key is held to sign it."
                    .into(),
            ));
        };
        let registered = self.clients.client_config_of(client_id);
        let jwt = crate::jarm::respond(
            signer.as_ref(),
            fields,
            &registered,
            &ask.base,
            client_id,
            ((self.now_ms)() / 1000.0).floor() as i64,
            self.settings
                .value_of("oauth2.jarmResponseLifetimeS")
                .as_int(),
        )?;
        let transport = crate::jarm::transport_of(mode, types);
        let sep = if transport == "fragment" {
            "#"
        } else if redirect_uri.contains('?') {
            "&"
        } else {
            "?"
        };
        let url = format!(
            "{}{}response={}",
            redirect_uri,
            sep,
            crate::js::encode_uri_component(&jwt)
        );
        Ok((transport == "form_post", jwt, url))
    }

    /// `sendRedirectInterstitial(req, res, info)`: the page shown instead
    /// of a redirect a person must decide on (RFC 9700 section 4.11.2) —
    /// the error, and a plain link (or, for form_post, a button POSTing the
    /// same fields, #126) to the client. No script: the page is a decision.
    #[allow(clippy::too_many_arguments)]
    fn interstitial(
        &self,
        ask: &AuthorizeAsk,
        q: &Map<String, Json>,
        code: ErrorCode,
        error: &str,
        description: &str,
        page_key: Option<&str>,
        types: &[String],
        mode: &str,
    ) -> Answer {
        let redirect_uri = s(q.get("redirect_uri"));
        let client_id = s(q.get("client_id"));
        let state = q.get("state").map(|v| s(Some(v)));
        let fields = vec![
            ("error".to_string(), error.to_string()),
            ("error_description".to_string(), description.to_string()),
        ];
        let mut target = Self::redirect_target(
            &ask.base,
            &redirect_uri,
            state.as_deref(),
            &fields,
            Self::uses_fragment(types, mode),
        );
        let mut form: Option<Vec<(String, String)>> = None;
        if mode == "form_post" {
            let mut posted = vec![
                ("error".to_string(), error.to_string()),
                (
                    "error_description".to_string(),
                    sanitize_description(description),
                ),
            ];
            if let Some(st) = state.as_ref() {
                posted.push(("state".into(), st.clone()));
            }
            posted.push(("iss".into(), ask.base.clone()));
            form = Some(posted);
        }
        if crate::jarm::is_jarm(mode) {
            let mut jf = vec![
                ("error".to_string(), error.to_string()),
                ("error_description".to_string(), description.to_string()),
                ("iss".to_string(), ask.base.clone()),
            ];
            if let Some(st) = state.as_ref() {
                jf.push(("state".into(), st.clone()));
            }
            match self.jarm_target(
                ask,
                &client_id,
                &redirect_uri,
                &jf,
                mode,
                types,
            ) {
                Ok((form_post, jwt, url)) => {
                    target = url;
                    if form_post {
                        form = Some(vec![("response".into(), jwt)]);
                    }
                }
                Err((c, why)) => {
                    return Answer::refusal(c, 400, "invalid_request", &why);
                }
            }
        }
        let after_s = self
            .settings
            .value_of("oauth2.errorPageAutoRedirectS")
            .as_int()
            .max(0);
        let after_s = if form.is_some() { 0 } else { after_s };
        let ui = s(q.get("ui_locales"));
        let html = self.pages.error_page(ask, &ui, &|t, catalogs| {
            let h = |key: &str, p: &[(&str, &str)]| {
                sts_http::error_page::html(t, key, p)
            };
            let label = h(
                "oauthPages.authorizeError.continue",
                &[("uri", &redirect_uri)],
            );
            let action = match form.as_ref() {
                Some(fields) => format!(
                    "<form method=\"post\" action=\"{}\">{}<p><button \
                     type=\"submit\" class=\"as-link\">{}</button></p></form>",
                    esc(&redirect_uri),
                    fields
                        .iter()
                        .map(|(n, v)| format!(
                            "<input type=\"hidden\" name=\"{}\" \
                             value=\"{}\">",
                            esc(n),
                            esc(v)
                        ))
                        .collect::<String>(),
                    label
                ),
                None => {
                    format!("<p><a href=\"{}\">{}</a></p>", esc(&target), label)
                }
            };
            let auto = if after_s > 0 {
                format!("<p class=\"sub\">{}</p>", auto_sentence(t, after_s))
            } else {
                String::new()
            };
            ErrorPageSpec {
                chooser: self.chooser_of(ask, t, catalogs),
                status: 400,
                title: sts_http::error_page::text(
                    t,
                    "oauthPages.authorizeError.title",
                    &[],
                ),
                error: error.to_string(),
                message: Self::refusal_message(t, code, error, q, page_key),
                after: format!(
                    "{}{}<p class=\"sub\">{}</p>",
                    action,
                    auto,
                    h("oauthPages.authorizeError.continueNote", &[])
                ),
                background: h(
                    "oauthPages.authorizeError.authenticateFirst",
                    &[],
                ),
                diagnostics: self.diagnostics(ask, t, q, error, description),
                extra_head: if after_s > 0 {
                    format!(
                        "<meta http-equiv=\"refresh\" content=\"{};url={}\">",
                        after_s,
                        esc(&target)
                    )
                } else {
                    String::new()
                },
            }
        });
        Self::page_answer(400, html)
    }

    /// `authorizeRequest()` after the vetting.
    fn authorize(
        &self,
        ask: &AuthorizeAsk,
        q: Map<String, Json>,
        types: Vec<String>,
        client: Json,
    ) -> Answer {
        let client_id = s(q.get("client_id"));
        let authn_error = s(q.get("authn_error"));
        if !authn_error.is_empty() {
            let session = self.sign_on.session_of(&ask.request);
            let d = s(q.get("authn_error_description"));
            return self.fail(
                ask,
                &q,
                session.is_some(),
                codes::STS_OAUTH_0166,
                &authn_error,
                if d.is_empty() {
                    "Authentication did not complete."
                } else {
                    &d
                },
            );
        }
        let consent_error = s(q.get("consent_error"));
        if !consent_error.is_empty() {
            let session = self.sign_on.session_of(&ask.request);
            let d = s(q.get("consent_error_description"));
            return self.fail(
                ask,
                &q,
                session.is_some(),
                codes::STS_OAUTH_0167,
                &consent_error,
                if d.is_empty() {
                    "Consent was not given."
                } else {
                    &d
                },
            );
        }
        let login_hint = s(q.get("login_hint"));
        if !login_hint.is_empty() {
            self.sign_on.hint_account(&ask.request, &login_hint);
        }
        let session = self.sign_on.session_of(&ask.request);
        let starts = self
            .clients
            .setting_for(&client_id, "oauth2.spInitiatedSso")
            .map(|v| v != Json::Bool(false))
            .unwrap_or_else(|| {
                !matches!(
                    self.settings.value_of("oauth2.spInitiatedSso"),
                    sts_core::settings::SettingValue::Bool(false)
                )
            });
        if !starts {
            return self.fail(ask, &q, session.is_some(), codes::STS_OAUTH_0959, "unauthorized_client", &format!(
                "Client \"{}\" is signed in to only from this identity provider (OpenID Connect Core section 4), and this request did not follow a launch of it.",
                client_id));
        }
        let prompt = words(&s(q.get("prompt")));
        let force =
            prompt.iter().any(|p| p == "login" || p == "select_account");
        let prompt_none = prompt.iter().any(|p| p == "none");
        if let (Some(session), false) = (&session, force) {
            let sid = s(session.get("id"));
            self.sign_on.note_presented(&sid, &ask.request, &client_id);
            return self.with_consent(ask, &q, &types, &client, session);
        }
        if prompt_none {
            if let Some(need) = self.sign_on.account_choice_needed(&ask.request)
            {
                if s(need.get("reason")) == "ambiguous" {
                    self.sign_on.note_account_ambiguous(
                        &ask.request,
                        "account_selection_required was answered",
                    );
                    return self.fail(ask, &q, session.is_some(), codes::STS_OAUTH_0960, "account_selection_required",
                        "The request names none of the accounts signed in here, and prompt=none forbids showing the account picker (OIDC Core section 3.1.2.6). Send login_hint or id_token_hint, or retry without prompt=none.");
                }
            }
            return self.fail(
                ask,
                &q,
                session.is_some(),
                codes::STS_OAUTH_0170,
                "login_required",
                "No session, and prompt=none forbids showing the login screen.",
            );
        }
        let return_to =
            format!("/oauth2/authorize?{}", query_string(&q, &["prompt"]));
        let shown_scope = match s(q.get("scope")) {
            sc if sc.is_empty() => "(none requested)".to_string(),
            sc => sc,
        };
        let details = json!([
            { "label": "client_id", "value": client_id },
            { "label": "scope", "value": shown_scope },
            { "label": "redirect_uri", "value": s(q.get("redirect_uri")) },
        ]);
        let begin = Begin {
            return_to,
            details,
            hint: login_hint,
            account_choice: if prompt.iter().any(|p| p == "login") {
                "never".into()
            } else if prompt.iter().any(|p| p == "select_account") {
                "always".into()
            } else {
                String::new()
            },
            reauthentication: if session.is_some()
                && prompt.iter().any(|p| p == "login")
            {
                "prompt_login".into()
            } else {
                String::new()
            },
            protocol: "OAuth 2.0 / OIDC".into(),
            application: client_id.clone(),
            ui_locales: s(q.get("ui_locales")),
            domain_hint: s(q.get("domain_hint")),
            ..Begin::default()
        };
        match self.hand_off.begin_authentication(&begin, &ask.request) {
            Ok(location) => Answer::redirect(&if self.mode.hides_step_ids() {
                hide_step(&location, &client_id)
            } else {
                location
            }),
            Err(e) => {
                tracing::error!(
                    "{}the authorization response could not be issued: {}",
                    sts_core::log::tag(codes::STS_OAUTH_0169),
                    e
                );
                self.fail(
                    ask,
                    &q,
                    session.is_some(),
                    codes::STS_OAUTH_0169,
                    "server_error",
                    &e,
                )
            }
        }
    }

    /// The consent decision for a signed-in person, then the response
    /// (`authorizeRequest()`'s consent block): what `consent.outstanding()`
    /// says needs an answer is asked on the screen, a public client's
    /// one-time Allow spent on the pass after it, and the scopes a global
    /// consent answered noted on the person's entry (#537).
    fn with_consent(
        &self,
        ask: &AuthorizeAsk,
        q: &Map<String, Json>,
        types: &[String],
        client: &Json,
        session: &Json,
    ) -> Answer {
        let _ = client;
        let client_id = s(q.get("client_id"));
        let user = session.get("user").cloned().unwrap_or(Json::Null);
        let username = s(user.get("username"));
        let wants_consent =
            words(&s(q.get("prompt"))).iter().any(|p| p == "consent");
        let Some(screen) = self.consent.as_ref() else {
            return self.issue(ask, q, types, session);
        };
        let register = &screen.register;
        let required = register.required();
        let digest = if required && register.always_asks(client_id.trim()) {
            crate::consent::ConsentRegister::scope_answer_digest_of(&s(
                q.get("scope")
            ))
        } else {
            String::new()
        };
        let answered = !digest.is_empty()
            && !wants_consent
            && register.consume_consented(&username, &client_id, &digest);
        let decision = if required {
            register.outstanding(
                &username,
                &client_id,
                &s(q.get("scope")),
                wants_consent,
                answered,
            )
        } else {
            crate::consent::Outstanding::default()
        };
        if !decision.outstanding.is_empty() {
            if words(&s(q.get("prompt"))).iter().any(|p| p == "none") {
                return self.fail(ask, q, true, codes::STS_OAUTH_0168, "consent_required", &format!(
                    "\"{}\" has not consented {} for the client \"{}\", and prompt=none forbids showing the consent screen. Retry without prompt=none, or consent the scope for every user of this application at /admin/consent — which is what an application that must never interrupt anybody is configured with. oauth2.consentRequired turns the screen off entirely.",
                    username,
                    decision.names().iter().map(|o| format!("\"{}\"", o)).collect::<Vec<_>>().join(", "),
                    client_id));
            }
            // THE SAME `returnTo` THE SIGN-IN HOP USES, `prompt` dropped.
            let return_to = format!(
                "{}/oauth2/authorize?{}",
                crate::authorization_servers::path_of(
                    &crate::authorization_servers::current()
                ),
                self.return_query(q)
            );
            self.sign_on.hold_presentation(&s(session.get("id")));
            let already: Vec<Json> = decision
                .rows
                .iter()
                .filter(|r| !decision.outstanding.contains(r))
                .cloned()
                .collect();
            let shown_scope = match s(q.get("scope")) {
                sc if sc.is_empty() => "(none requested)".to_string(),
                sc => sc,
            };
            let info = json!({
                "returnTo": return_to,
                "username": username,
                "clientId": client_id,
                "clientName": self.clients.name_of(&client_id),
                "scopes": decision.outstanding,
                "resources": values(q.get("resource")),
                "authorizationDetails": [],
                "detailsDigest": "",
                "scopeAnswerDigest": digest,
                "rawAuthorizationDetails": [],
                "already": already,
                "protocol": "OAuth 2.0 / OIDC",
                "uiLocales": s(q.get("ui_locales")),
                "details": [
                    { "label": "client_id", "value": client_id },
                    { "label": "scope", "value": shown_scope },
                    { "label": "redirect_uri",
                      "value": s(q.get("redirect_uri")) },
                ],
            });
            return match screen.begin(&info) {
                Ok(location) => {
                    Answer::redirect(&if self.mode.hides_step_ids() {
                        hide_step(&location, &client_id)
                    } else {
                        location
                    })
                }
                Err(e) => {
                    tracing::error!(
                        "{}the authorization response could not be issued: {}",
                        sts_core::log::tag(codes::STS_OAUTH_0169),
                        e
                    );
                    self.fail(
                        ask,
                        q,
                        true,
                        codes::STS_OAUTH_0169,
                        "server_error",
                        &e,
                    )
                }
            };
        }
        let applied: Vec<String> = decision
            .rows
            .iter()
            .filter(|r| {
                r["global"] == json!(true) && r["consented"] != json!(true)
            })
            .map(|r| s(r.get("scope")))
            .collect();
        register.note_applied(&username, &client_id, &applied);
        self.issue(ask, q, types, session)
    }

    /// `authorizationReturnQuery(req, q)`: the request with `prompt`
    /// dropped, for the sign-in and consent hops to return to.
    fn return_query(&self, q: &Map<String, Json>) -> String {
        query_string(q, &["prompt"])
    }

    /// `consent.globalConsentsOf(clientId)`: `oauthGlobalConsent` on the
    /// application's entry.
    fn global_consents_of(&self, client_id: &str) -> Vec<String> {
        self.clients.global_consents_of(client_id)
    }

    /// `issueAuthorizationResponse()` for a signed-in person.
    fn issue(
        &self,
        ask: &AuthorizeAsk,
        q: &Map<String, Json>,
        types: &[String],
        session: &Json,
    ) -> Answer {
        let client_id = s(q.get("client_id"));
        let redirect_uri = s(q.get("redirect_uri"));
        let mode = s(q.get("response_mode"));
        let state = q.get("state").map(|v| s(Some(v)));
        let fragment = Self::uses_fragment(types, &mode);
        let back = |code: ErrorCode, error: &str, description: &str| {
            self.redirect_back(
                ask,
                &redirect_uri,
                state.as_deref(),
                vec![
                    ("error".into(), error.to_string()),
                    ("error_description".into(), description.to_string()),
                ],
                fragment,
                &mode,
                &client_id,
                &s(q.get("ui_locales")),
            )
            .marked(code)
        };
        if types.iter().any(|t| t == "token" || t == "id_token") {
            return back(
                codes::STS_OAUTH_0162,
                "unsupported_response_type",
                &format!(
                    "response_type \"{}\" is not supported.",
                    s(q.get("response_type"))
                ),
            );
        }
        let user = session.get("user").cloned().unwrap_or(Json::Null);
        let username = s(user.get("username"));
        let signed_in =
            session.get("authenticated") != Some(&Json::Bool(false));
        let view = sts_authn::record::view(session.as_object());
        let session_id = view.id.clone();
        let mut scope = s(q.get("scope"));
        // offlineAccessScope(): kept only with a code and consent to it.
        if words(&scope).iter().any(|w| w == "offline_access") {
            let without = words(&scope)
                .into_iter()
                .filter(|w| w != "offline_access")
                .collect::<Vec<_>>()
                .join(" ");
            let prompted =
                words(&s(q.get("prompt"))).iter().any(|p| p == "consent");
            let consented = !prompted
                && (self
                    .global_consents_of(&client_id)
                    .iter()
                    .any(|g| g == "offline_access")
                    || self.consent.as_ref().is_some_and(|c| {
                        c.register.consents_of(&username).iter().any(|g| {
                            g.client == client_id && g.scope == "offline_access"
                        })
                    }));
            if !types.iter().any(|t| t == "code") || (!prompted && !consented) {
                tracing::info!(
                    "oauth2: offline_access was asked for by \"{}\" without prompt=consent and without a recorded consent to it, and is ignored (OIDC Core section 11); the refresh token issued is an online one.",
                    client_id);
                scope = without;
            }
        }
        let resources =
            match parse_resource_indicators(&values(q.get("resource"))) {
                Ok(r) => r,
                Err(e) => {
                    return back(codes::STS_OAUTH_0154, "invalid_target", &e)
                }
            };
        let reserved =
            protocol_scopes(&self.settings, &self.scopes.credential_scopes);
        let found = audience_scopes(
            self.clients.as_ref(),
            &reserved,
            &scope,
            &client_id,
        );
        let refused = permission_refusal(
            &found,
            &self.settings,
            &self.mode,
            &client_id,
            "",
        );
        if !refused.is_empty() {
            return back(codes::STS_OAUTH_0155, "invalid_scope", &refused);
        }
        if let Some(r) = self.scopes.refusal(&scope, &client_id) {
            return back(r.code, "invalid_scope", &r.description);
        }
        if self.gated.asks_for_gated(&scope) {
            let narrowed = self.gated.narrow(
                &scope,
                &username,
                signed_in,
                &client_id,
                "authorization_code",
            );
            if narrowed.get("emptied") == Some(&Json::Bool(true)) {
                return back(
                    codes::STS_ADMIN_0822,
                    "invalid_scope",
                    &s(narrowed.get("why")),
                );
            }
            scope = s(narrowed.get("scope"));
        }
        let plan = crate::token_endpoint::plan_for(
            self.clients.as_ref(),
            &self.settings,
            &self.scopes,
            &ask.base,
            &scope,
            &client_id,
            &resources,
        );
        let plan = if plan.refusal.is_some() && resources.len() > 1 {
            resources
                .iter()
                .map(|one| {
                    crate::token_endpoint::plan_for(
                        self.clients.as_ref(),
                        &self.settings,
                        &self.scopes,
                        &ask.base,
                        &scope,
                        &client_id,
                        std::slice::from_ref(one),
                    )
                })
                .find(|p| p.refusal.is_none())
                .unwrap_or(plan)
        } else {
            plan
        };
        if let Some(r) = plan.refusal {
            return back(r.code, r.error, &r.description);
        }
        let now = (self.now_ms)();
        if let Some((code, description)) = self.grants.check_transaction_values(
            self.bcp_enabled(),
            &Json::Object(q.clone()),
            &client_id,
            now,
        ) {
            return back(code, "invalid_request", &description);
        }
        let sub = s(user.get("sub"));
        self.sign_on.note_client(
            &session_id,
            &client_id,
            &crate::jwt_access_token::JwtAccessTokens::new(
                self.settings.clone(),
            )
            .issuer_for(&ask.base),
            &sub,
        );
        let mut out: Vec<(String, String)> = Vec::new();
        let mut completed = true;
        if types.iter().any(|t| t == "code") {
            let code = (self.random_id)(24);
            let key = sts_crypto::secrets::credential_digest(&code)
                .unwrap_or_default();
            let ttl = self.grants.code_ttl_ms();
            let method = s(q.get("code_challenge_method"));
            let record = json!({
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": scope,
                "grant_management": null,
                "nonce": q.get("nonce").cloned().unwrap_or(Json::Null),
                "user": user,
                "auth_time": view.auth_time,
                "amr": view.methods,
                "acr": view.assurance_level,
                "session_id": session_id,
                "session_authenticated": signed_in,
                "authorization_server": crate::authorization_servers::current(),
                "resources": resources,
                "code_challenge": q.get("code_challenge").cloned().unwrap_or(Json::Null),
                "code_challenge_method": if method.is_empty() { "plain".to_string() } else { method },
                "dpop_jkt": s(q.get("dpop_jkt")),
                "attested_jkt": "",
                "authorization_details": null,
                "claims": null,
                // `oauth21.codeRecordFields()`: a code with no challenge
                // got past `pkceDecision()` only by the nonce exemption.
                "pkce_exempt": if self.settings.value_of("oauth2.oauth21").as_bool()
                    && s(q.get("code_challenge")).is_empty()
                {
                    "oidc-nonce"
                } else {
                    ""
                },
                "granted_at": now as i64,
                "ttlMs": ttl as i64,
                "expires": (now + ttl) as i64,
            });
            self.grants.codes.set(&key, strip_undefined(record));
            out.push(("code".into(), code));
            completed = false;
        }
        self.grants.remember_transaction_values(
            self.bcp_enabled(),
            &Json::Object(q.clone()),
            &client_id,
            completed,
            now,
        );
        self.redirect_back(
            ask,
            &redirect_uri,
            state.as_deref(),
            out,
            fragment,
            &mode,
            &client_id,
            &s(q.get("ui_locales")),
        )
    }
}

/// `JSON.stringify` drops an `undefined` member: a code record's absent
/// `nonce` and `code_challenge` are left out, as Node's are (`amr` and
/// `acr` are `null` there, and kept).
fn strip_undefined(mut record: Json) -> Json {
    if let Some(o) = record.as_object_mut() {
        for k in ["nonce", "code_challenge"] {
            if o.get(k).is_some_and(Json::is_null) {
                o.remove(k);
            }
        }
    }
    record
}

/// `StepAddress.hide(location, authn.stepApplication)` (#1454): in
/// product a sign-in step's id leaves the address for its fragment, the
/// application it is for named in `app`. Node does it to every redirect
/// in `app.js`; here to the hand-off's, the one redirect of this endpoint
/// that names a step (the realm's prefix is put on by the HTTP layer
/// after).
#[tracing::instrument(level = "debug")]
pub fn hide_step(location: &str, application: &str) -> String {
    let (path, query) = match location.split_once('?') {
        Some(pq) => pq,
        None => return location.to_string(),
    };
    let is_step = (path.starts_with("/authn/")
        && !path.starts_with("/authn/spnego")
        && path.len() > "/authn/".len()
        && path["/authn/".len()..].bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || b == b'/'
                || b == b'-'
        }))
        || path == "/oauth2/consent";
    let (name, rest) = query.split_once('=').unwrap_or(("", ""));
    let id = rest.split(['&', '#']).next().unwrap_or("");
    if !is_step
        || !["authn", "mfa", "change", "consent"].contains(&name)
        || id.is_empty()
        || query.contains('#')
    {
        return location.to_string();
    }
    format!(
        "{}{}#{}",
        path,
        if application.is_empty() {
            String::new()
        } else {
            format!(
                "?app={}",
                sts_authn::account_sets::encode_uri_component(application)
            )
        },
        query
    )
}

fn is_loopback(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    h == "127.0.0.1" || h == "::1" || h == "[::1]" || h == "localhost"
}
