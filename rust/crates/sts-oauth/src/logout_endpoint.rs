// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! OPENID CONNECT RP-INITIATED LOGOUT 1.0 (#444, phase 5, the `oauth6`
//! slice): `oauth2.ts`'s `end_session_endpoint`, `GET` and `POST
//! /oauth2/logout` (and under a named authorization server) —
//! `logoutEndpoint()`, `logoutRequest()`, `logoutRefusal()`,
//! `logoutConfirmPage()`, `logoutAskReason()`, `logoutFinish()`,
//! `logoutPage()`, `logoutAnswer()`, `logoutConfirmFor()`,
//! `logoutHintMatches()`, `hintClientOf()`, `withLogoutState()`,
//! `logoutTargetConsidered()`, and `oauth2_bcp.js`'s
//! `checkPostLogoutRedirectUri()`.
//!
//! THE ORDER IS NODE'S, and it is the fix (#124):
//!
//! 1. the request is read — a form POST's body or the query — and a
//!    malformed one is a PAGE (400, `STS-OAUTH-0171`) with the session
//!    untouched;
//! 2. an `id_token_hint` is VERIFIED: this realm's issuer, a signature it
//!    made (an expired one is still a hint), issued to the client
//!    (`STS-OAUTH-0602`, in every mode);
//! 3. `post_logout_redirect_uri` is decided, in every mode: the client's own
//!    list exactly; development still follows one no client registered,
//!    product and OAuth 2.1 mode do not; a request naming no client is
//!    never returned anywhere (#187). A refused one is not followed and the
//!    page says so in the amber box (#1302);
//! 4. the person CONFIRMS unless the request carries a verified hint for
//!    THIS session and any `logout_hint` names them, and a GET that is not
//!    a top-level navigation is asked too (#1443);
//! 5. only then THE ONE SESSION ENDS — `sts-authn`'s `end_session_for()`,
//!    the browser's own sign-out, which is `authn.endSession()`: the
//!    session is dropped (and with it, in product, its access tokens,
//!    #1449), its cookie cleared, and an online refresh token granted
//!    under it dies with it — and the return carries `state`.
//!
//! WHAT IS NOT IN THIS RUNTIME YET, through [`LogoutChannels`]: Front-
//! and Back-Channel Logout's fan-out (`frontchannel.js`,
//! `backchannel_logout.ts`), answered as Node answers a realm whose clients
//! registered no logout URI — no notification, no delivery row. The
//! page's language is negotiated from `ui_locales`, the chooser's cookie
//! and `Accept-Language`; the person's own preference and the client's
//! locale policy (`PageLocale.translatorFor()`'s other two inputs) are the
//! locale slice's, as on every other Rust page.

use std::sync::Arc;

use serde_json::{json, Map, Value as Json};
use sts_authn::ports::{Request, Response};
use sts_core::errors::{codes, ErrorCode};
use sts_core::mode::Mode;
use sts_core::settings::Settings;
use sts_http::error_page::{DiagnosticRow, ErrorPageSpec};
use sts_http::i18n::{Catalogs, Translator};

use crate::answer::{Answer, Body};
use crate::authorize::AuthorizationEndpoint;
use crate::clients::Clients;

fn s(v: Option<&Json>) -> String {
    crate::js::string_of(v)
}

/// `xmlEscape()`.
fn esc(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// What a sign-out request is.
#[derive(Debug, Clone, Default)]
pub struct LogoutAsk {
    /// `GET` or `POST`.
    pub method: String,
    pub content_type: String,
    /// The query string, without its `?`.
    pub query: String,
    /// The body of a POST.
    pub body: String,
    pub accept_language: String,
    /// `Sec-Fetch-Dest` and `Sec-Fetch-Mode` (#1443).
    pub fetch_dest: String,
    pub fetch_mode: String,
    /// `asBaseOf(req)`: the authorization server's base URL.
    pub base: String,
    /// `realms.currentPrefix()`.
    pub prefix: String,
    /// `asPathOf(req)`: `/<name>` under a named authorization server.
    pub as_path: String,
    /// The session core's view of the request.
    pub request: Request,
}

/// What the endpoint answers: the page or the redirect, the cookies the
/// session core wrote (the cleared `sts_session`, an account set's), and
/// whether the answer carries `Clear-Site-Data: "storage"` (#1440).
#[derive(Debug, Clone)]
pub struct LogoutAnswer {
    pub answer: Answer,
    pub response: Response,
}

/// Front- and Back-Channel Logout, as far as the sign-out page reads them
/// (`frontchannel`, `backchannel` in `oauth2.ts`'s deps).
pub trait LogoutChannels: Send + Sync {
    /// `backchannel.mark()`: where the deliveries this sign-out starts
    /// begin.
    fn mark(&self) -> Json {
        Json::Null
    }
    /// `backchannel.deliveriesFor(ids, mark)`.
    fn deliveries_for(&self, _ids: &[String], _mark: &Json) -> Vec<Json> {
        Vec::new()
    }
    /// `backchannel.render(rows)`: that module's own (English) table.
    fn render_deliveries(&self, _rows: &[Json]) -> String {
        String::new()
    }
    /// `frontchannel.enabled()`.
    fn front_enabled(&self) -> bool {
        false
    }
    /// `frontchannel.notificationsFor(session, issuer)`.
    fn notifications_for(&self, _session: &Json, _issuer: &str) -> Vec<Json> {
        Vec::new()
    }
    /// `frontchannel.render(notifications)`.
    fn render_notifications(&self, _rows: &[Json]) -> String {
        String::new()
    }
    /// `frontchannel.contentSecurityPolicyFor(notifications)`.
    fn content_security_policy_for(&self, _rows: &[Json]) -> String {
        String::new()
    }
}

/// No relying party is notified: Node's answer for clients that
/// registered no logout URI.
pub struct NoChannels;

impl LogoutChannels for NoChannels {}

/// The endpoint.
pub struct LogoutEndpoint {
    pub settings: Arc<Settings>,
    pub mode: Arc<Mode>,
    pub clients: Arc<dyn Clients>,
    pub sessions: Arc<sts_authn::Sessions>,
    /// The id_token_hint's verifier (`verifyIdTokenHint()`), shared with
    /// the authorization endpoint.
    pub hints: Arc<AuthorizationEndpoint>,
    pub catalogs: Arc<Catalogs>,
    /// The page footer's facts, for the shared error page (#1326).
    pub footer: sts_http::footer::Facts,
    /// `audit.reserveIncident(res)`.
    pub incident: Arc<dyn Fn() -> i64 + Send + Sync>,
    pub channels: Arc<dyn LogoutChannels>,
}

/// A refusal page's parts (`logoutRefusal()`'s `info`).
struct Refusal<'a> {
    status: u16,
    title: &'a str,
    message: String,
    params: Vec<(String, String)>,
    background: &'a str,
    after: &'a str,
    client_id: String,
    q: Map<String, Json>,
    detail: String,
}

/// A refused return (`unfollowed`): the address and the sentence's key.
struct Unfollowed {
    uri: String,
    key: &'static str,
}

/// What the page's ending shows where the return was refused (#1326).
struct Partly {
    client_id: String,
    uri: String,
    state: String,
    username: String,
    detail: String,
}

/// `logoutAskReason()`'s answer: the key, or `None` where the box says it.
type AskReason = Option<&'static str>;

impl LogoutEndpoint {
    /// The page's language: `ui_locales` first, then the chooser's cookie
    /// and `Accept-Language`.
    fn translator(&self, ask: &LogoutAsk, ui_locales: &str) -> Translator<'_> {
        let chooser =
            sts_authn::cookie::cookie_value(&ask.request.cookie, "sts_lang");
        let preferences =
            sts_http::i18n::preferences(&sts_http::i18n::Preferences {
                ui_locales: ui_locales.to_string(),
                own: None,
                chooser,
                accept_language: ask.accept_language.clone(),
            });
        self.catalogs.translator(&preferences, "")
    }

    fn html(t: &Translator<'_>, key: &str, params: &[(&str, &str)]) -> String {
        sts_http::error_page::html(t, key, params)
    }

    fn text(t: &Translator<'_>, key: &str) -> String {
        sts_http::error_page::text(t, key, &[])
    }

    /// `GET`/`POST /oauth2/logout`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn answer(&self, ask: &LogoutAsk) -> LogoutAnswer {
        let mut response = Response::default();
        let answer = self.endpoint(ask, &mut response);
        LogoutAnswer { answer, response }
    }

    /// `logoutEndpoint(req, res)`: the request read, a malformed one a
    /// page with the session untouched.
    fn endpoint(&self, ask: &LogoutAsk, response: &mut Response) -> Answer {
        let input = if ask.method.eq_ignore_ascii_case("POST") {
            let kind = ask
                .content_type
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if kind != "application/x-www-form-urlencoded" {
                return self
                    .refusal(
                        ask,
                        Refusal {
                            status: 400,
                            title: "unreadableTitle",
                            message: "notForm".into(),
                            params: vec![(
                                "type".into(),
                                if kind.is_empty() {
                                    "(none)".into()
                                } else {
                                    kind
                                },
                            )],
                            background: "",
                            after: "",
                            client_id: String::new(),
                            q: Map::new(),
                            detail: String::new(),
                        },
                    )
                    .marked(codes::STS_OAUTH_0604);
            }
            crate::js::fold(&crate::js::form_decode(&ask.body))
        } else {
            crate::js::fold(&crate::js::form_decode(&ask.query))
        };
        match crate::model::check("logout", &input, "query") {
            Err(r) => {
                tracing::debug!(
                    "oauth2: the logout request is malformed: {} on \"{}\".",
                    r.code,
                    r.field
                );
                self.refusal(
                    ask,
                    Refusal {
                        status: 400,
                        title: "unreadableTitle",
                        message: "malformed".into(),
                        params: Vec::new(),
                        background: "",
                        after: "",
                        client_id: String::new(),
                        q: Map::new(),
                        detail: r.detail,
                    },
                )
                .marked(codes::STS_OAUTH_0171)
            }
            Ok(q) => self.request(ask, &q, response),
        }
    }

    /// `logoutRefusal(req, res, info)`: the shared error page (#1326) —
    /// the reason in the box in the page's language, that nothing was
    /// done, the section collapsed, the way back and the diagnostics.
    fn refusal(&self, ask: &LogoutAsk, info: Refusal<'_>) -> Answer {
        let session = self.sessions.session_of(&ask.request, false);
        let username = session
            .as_ref()
            .map(|x| s(x.get("user").and_then(|u| u.get("username"))))
            .unwrap_or_default();
        let t = self.translator(ask, &s(info.q.get("ui_locales")));
        let key = |name: &str| format!("oauthPages.logoutRefused.{}", name);
        let params: Vec<(&str, &str)> = info
            .params
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let url = if ask.query.is_empty() {
            format!("{}{}/oauth2/logout", ask.prefix, ask.as_path)
        } else {
            format!("{}{}/oauth2/logout?{}", ask.prefix, ask.as_path, ask.query)
        };
        let label = |k: &str| Self::text(&t, k);
        let spec = ErrorPageSpec {
            chooser: sts_http::error_page::chooser(
                &t,
                &self.catalogs,
                &sts_http::error_page::return_path(
                    &ask.method,
                    &url,
                    &ask.prefix,
                ),
            ),
            status: info.status,
            title: Self::text(&t, &key(info.title)),
            message: Self::html(&t, &key(&info.message), &params),
            after: format!(
                "<p>{}</p>",
                Self::html(
                    &t,
                    &key(if info.after.is_empty() {
                        "nothingDone"
                    } else {
                        info.after
                    }),
                    &[]
                )
            ),
            background: if info.background.is_empty() {
                String::new()
            } else {
                Self::html(&t, &key(info.background), &[])
            },
            diagnostics: vec![
                DiagnosticRow {
                    label: label("errorPages.application"),
                    value: info.client_id.clone(),
                },
                DiagnosticRow {
                    label: label("errorPages.postLogoutRedirectUri"),
                    value: s(info.q.get("post_logout_redirect_uri")),
                },
                DiagnosticRow {
                    label: label("errorPages.state"),
                    value: s(info.q.get("state")),
                },
                DiagnosticRow {
                    label: label("errorPages.signedInAs"),
                    value: username,
                },
                DiagnosticRow {
                    label: label("errorPages.detail"),
                    value: info.detail.clone(),
                },
            ],
            ..ErrorPageSpec::default()
        };
        let html = sts_http::error_page::document(
            &t,
            &spec,
            (self.incident)(),
            &sts_http::error_page::iso_now(),
            &ask.prefix,
            &self.footer,
        );
        Self::page(info.status, html)
    }

    fn page(status: u16, html: String) -> Answer {
        let mut a = Answer::new(status, Body::Html(html));
        a.set("Content-Type", "text/html; charset=utf-8");
        a.set("Cache-Control", "no-store");
        a
    }

    /// `logoutTargetConsidered(target)`: http(s), or a native
    /// application's private-use address.
    fn considered(target: &str) -> bool {
        let lower = target.to_ascii_lowercase();
        !target.is_empty()
            && (lower.starts_with("http://")
                || lower.starts_with("https://")
                || crate::model::is_private_use_redirect(target))
    }

    /// `withLogoutState(target, state)`: section 3's `state` on the
    /// return, the request's value replacing any the address carries.
    #[tracing::instrument(level = "debug")]
    pub fn with_logout_state(target: &str, state: &str) -> String {
        if state.is_empty() {
            return target.to_string();
        }
        let (before, fragment) = match target.find('#') {
            Some(at) => (&target[..at], &target[at..]),
            None => (target, ""),
        };
        let (base, query) = match before.find('?') {
            Some(at) => (&before[..at], &before[at + 1..]),
            None => (before, ""),
        };
        let mut pairs: Vec<(String, String)> = crate::js::form_decode(query);
        // `URLSearchParams#set()`: the first one replaced in place, the
        // rest removed; appended where there was none.
        let mut seen = false;
        pairs.retain_mut(|(k, v)| {
            if k != "state" {
                return true;
            }
            if seen {
                return false;
            }
            seen = true;
            *v = state.to_string();
            true
        });
        if !seen {
            pairs.push(("state".into(), state.to_string()));
        }
        format!("{}?{}{}", base, crate::js::form_encode(&pairs), fragment)
    }

    /// `uriMatches()`: exact, or a loopback address with any port where
    /// the realm allows it (RFC 8252 section 7.3).
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
        let loopback = |h: &str| {
            h.eq_ignore_ascii_case("localhost")
                || h == "[::1]"
                || h == "::1"
                || h.starts_with("127.")
        };
        loopback(ha)
            && ha.eq_ignore_ascii_case(hb)
            && a.scheme() == b.scheme()
            && a.path() == b.path()
            && a.query() == b.query()
            && a.fragment() == b.fragment()
    }

    /// `bcp.checkPostLogoutRedirectUri({ target, client })`, in every
    /// mode: `Ok(())`, or the code and the description.
    #[tracing::instrument(level = "debug", skip(self, client))]
    pub fn check_post_logout_redirect_uri(
        &self,
        target: &str,
        client: &Json,
    ) -> Result<(), (ErrorCode, String)> {
        let declared: Vec<String> = client
            .get("post_logout_redirect_uris")
            .and_then(Json::as_array)
            .map(|l| l.iter().map(|u| s(Some(u))).collect())
            .unwrap_or_default();
        if !declared.is_empty() {
            if declared.iter().any(|u| self.uri_matches(u, target)) {
                return Ok(());
            }
            return Err((codes::STS_OAUTH_0123, format!(
                "RP-Initiated Logout 1.0 section 3: \"{}\" is not a post-logout redirect URI this client registered.",
                target)));
        }
        let known = client.get("known") == Some(&Json::Bool(true));
        if crate::model::is_private_use_redirect(target) {
            return Err((codes::STS_OAUTH_0290, format!(
                "\"{}\" is a native application's private-use address, and one is followed after a sign-out only when the client this request names registered it as a post_logout_redirect_uri. {}",
                target,
                if known { "That client has registered none." } else { "This request names no client this service holds." })));
        }
        let none = if known {
            "that client has registered none"
        } else {
            "this request names no client this service holds"
        };
        if self.settings.value_of("oauth2.oauth21").as_bool() {
            return Err((codes::STS_OAUTH_0286, format!(
                "OAuth 2.1 (draft-ietf-oauth-v2-1-16) section 2.3.1: a post_logout_redirect_uri is followed only when the client this request names registered it, and {}.",
                none)));
        }
        if !self.mode.accepts_unregistered_addresses() {
            return Err((codes::STS_OAUTH_0603, format!(
                "RP-Initiated Logout 1.0 section 3: \"{}\" is followed only when the client this request names (by id_token_hint or client_id) registered it, and {}.",
                target, none)));
        }
        Ok(())
    }

    /// `hintClientOf(hint)`: the client an id_token_hint was issued to,
    /// read UNVERIFIED and only to choose what it is verified against —
    /// `azp`, else the one audience.
    fn hint_client_of(hint: &str) -> String {
        let claims = crate::js::segment_json(hint, 1)
            .unwrap_or(Json::Object(Map::new()));
        let azp = s(claims.get("azp"));
        if !azp.is_empty() {
            return azp;
        }
        match claims.get("aud") {
            Some(Json::Array(l)) if l.len() == 1 => s(l.first()),
            Some(Json::Array(_)) | None | Some(Json::Null) => String::new(),
            Some(one) => s(Some(one)),
        }
    }

    /// `logoutConfirmFor(session)`: a digest of the session's CURRENT
    /// handle hash, which only a request carrying its cookie can have been
    /// shown.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn confirm_for(session: Option<&Json>) -> String {
        let handle =
            session.map(|x| s(x.get("handleHash"))).unwrap_or_default();
        if handle.is_empty() {
            return String::new();
        }
        let digest = sts_crypto::jws_alg::Hash::Sha256
            .digest(format!("{}:rp-initiated-logout", handle).as_bytes());
        let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
        hex[..32].to_string()
    }

    /// `logoutHintMatches(session, hint)`: the username, the entry's mail
    /// and the session's public subject, case-insensitively; no hint
    /// matches.
    fn hint_matches(session: &Json, hint: &str) -> bool {
        let asked = hint.trim().to_lowercase();
        if asked.is_empty() {
            return true;
        }
        let none = Json::Null;
        let user = session.get("user").unwrap_or(&none);
        let names = [
            user.get("username"),
            user.get("email"),
            user.get("mail"),
            user.get("sub"),
            session.get("subject"),
        ];
        let found = names
            .into_iter()
            .filter(|v| crate::js::truthy(*v))
            .any(|v| s(v).to_lowercase() == asked);
        found
    }

    /// `logoutRequest(req, res, q)`.
    fn request(
        &self,
        ask: &LogoutAsk,
        q: &Map<String, Json>,
        response: &mut Response,
    ) -> Answer {
        let mut mark: Option<ErrorCode> = None;
        // --- 2. the id_token_hint ---------------------------------------
        let mut client_id = s(q.get("client_id"));
        let hint = s(q.get("id_token_hint"));
        let mut hinted: Option<Json> = None;
        if !hint.is_empty() {
            let hint_client = if client_id.is_empty() {
                Self::hint_client_of(&hint)
            } else {
                client_id.clone()
            };
            let verdict =
                self.hints.verify_hint(&ask.base, &hint, &hint_client);
            if verdict.get("ok") != Some(&Json::Bool(true)) {
                let params: Vec<(String, String)> = verdict
                    .get("params")
                    .and_then(Json::as_object)
                    .map(|o| {
                        o.iter().map(|(k, v)| (k.clone(), s(Some(v)))).collect()
                    })
                    .unwrap_or_default();
                return self
                    .refusal(
                        ask,
                        Refusal {
                            status: 400,
                            title: "refusedTitle",
                            message: format!(
                                "hint.{}",
                                s(verdict.get("reason"))
                            ),
                            params,
                            background: "hintBackground",
                            after: "",
                            client_id: hint_client,
                            q: q.clone(),
                            detail: s(verdict.get("why")),
                        },
                    )
                    .marked(codes::STS_OAUTH_0602);
            }
            hinted = verdict.get("claims").cloned();
            client_id = hint_client;
        }
        let client = self.clients.client_config_of(&client_id);
        // --- 3. the return ------------------------------------------------
        let mut return_to = String::new();
        let mut unfollowed: Option<Unfollowed> = None;
        let mut refused_detail = String::new();
        let target = s(q.get("post_logout_redirect_uri"));
        let names_no_client =
            hint.is_empty() && s(q.get("client_id")).is_empty();
        if !target.is_empty() && names_no_client && Self::considered(&target) {
            mark = Some(codes::STS_OAUTH_0785);
            tracing::info!(
                "{}oauth2: a post_logout_redirect_uri was not followed: the \
                 request named no client.",
                sts_core::log::tag(codes::STS_OAUTH_0785)
            );
            unfollowed = Some(Unfollowed {
                uri: target.clone(),
                key: "noClient",
            });
            refused_detail = "RP-Initiated Logout 1.0 section 2: a sign-out \
                that carries neither an id_token_hint nor a client_id is not \
                redirected."
                .into();
        } else if !target.is_empty() && Self::considered(&target) {
            match self.check_post_logout_redirect_uri(&target, &client) {
                Ok(()) => {
                    return_to =
                        Self::with_logout_state(&target, &s(q.get("state")));
                }
                Err((code, description)) => {
                    mark = Some(code);
                    tracing::info!(
                        "oauth2: a post_logout_redirect_uri was not followed \
                         ({}): {}",
                        code.as_str(),
                        description
                    );
                    let key = if code == codes::STS_OAUTH_0123 {
                        "notRegistered"
                    } else if code == codes::STS_OAUTH_0290 {
                        "privateUse"
                    } else if code == codes::STS_OAUTH_0286
                        || code == codes::STS_OAUTH_0603
                    {
                        "clientRegisteredNone"
                    } else {
                        "notFollowed"
                    };
                    unfollowed = Some(Unfollowed {
                        uri: target.clone(),
                        key,
                    });
                    refused_detail = description;
                }
            }
        }
        // --- 4. confirmation ----------------------------------------------
        let several = self.sessions.multiple_accounts();
        let hinted_sid =
            hinted.as_ref().map(|h| s(h.get("sid"))).unwrap_or_default();
        if several && !hinted_sid.is_empty() {
            self.sessions.hint_account(
                &ask.request,
                &json!({ "sid": hinted_sid, "soft": true }),
            );
        }
        let account_key = s(q.get("sts_signout_account"));
        if several && !account_key.is_empty() {
            self.sessions.hint_account_key(&ask.request, &account_key);
        }
        let session = self.sessions.session_of(&ask.request, false);
        let choices = if several && session.is_none() {
            self.sessions.signed_in_accounts(&ask.request)
        } else {
            Vec::new()
        };
        let cookie_presented = ask
            .request
            .cookie
            .split(';')
            .any(|part| part.trim_start().starts_with("sts_session="));
        let post = ask.method.eq_ignore_ascii_case("POST");
        let confirmed = post
            && s(q.get("confirm")) == "yes"
            && s(q.get("confirm_for")) == Self::confirm_for(session.as_ref());
        let t = self.translator(ask, &s(q.get("ui_locales")));
        let refused_note = match &unfollowed {
            Some(u) => format!(
                "<div class=\"warn\" role=\"alert\" \
                 id=\"logout-return-refused\">{}</div>",
                Self::html(
                    &t,
                    &format!("oauthPages.signedOut.{}", u.key),
                    &[("uri", &u.uri)]
                )
            ),
            None => String::new(),
        };
        let front_door = sts_http::error_page::chooser(
            &t,
            &self.catalogs,
            &format!("{}/", ask.prefix),
        );
        let marked = |a: Answer| match mark {
            Some(c) => a.marked(c),
            None => a,
        };
        if post && s(q.get("confirm")) == "no" {
            let back = if return_to.is_empty() {
                String::new()
            } else {
                format!(
                    "<p><a href=\"{}\">{}</a></p>",
                    esc(&return_to),
                    Self::html(&t, "oauthPages.logout.returnToApp", &[])
                )
            };
            return marked(self.page_answer(
                200,
                &Self::text(&t, "oauthPages.logout.stillTitle"),
                &format!(
                    "{}<p>{}</p>{}",
                    refused_note,
                    Self::html(&t, "oauthPages.logout.nothingEnded", &[]),
                    back
                ),
                Some(&t),
                &front_door,
            ));
        }
        let hint_is_this_session = match (&session, hinted_sid.is_empty()) {
            (Some(held), false) => s(held.get("id")) == hinted_sid,
            _ => false,
        };
        // A GET THAT IS NOT A TOP-LEVEL NAVIGATION ENDS NOTHING (#1443).
        let not_navigating = ask.method.eq_ignore_ascii_case("GET")
            && ((!ask.fetch_dest.is_empty() && ask.fetch_dest != "document")
                || (!ask.fetch_mode.is_empty()
                    && ask.fetch_mode != "navigate"));
        let must_ask = !confirmed
            && match &session {
                Some(held) => {
                    not_navigating
                        || !(hint_is_this_session
                            && Self::hint_matches(
                                held,
                                &s(q.get("logout_hint")),
                            ))
                }
                None => post && !cookie_presented,
            };
        if choices.len() > 1 {
            return marked(self.confirm_page(
                ask,
                q,
                None,
                &client,
                &t,
                Some(&choices),
                Some("oauthPages.logout.whyNoHint"),
                &refused_note,
            ));
        }
        if must_ask {
            let reason = Self::ask_reason(
                q,
                session.as_ref(),
                hinted.as_ref(),
                &return_to,
                unfollowed.is_some(),
            );
            return marked(self.confirm_page(
                ask,
                q,
                session.as_ref(),
                &client,
                &t,
                None,
                reason,
                &refused_note,
            ));
        }
        // --- 5. the sign-out ------------------------------------------------
        let backchannel_mark = self.channels.mark();
        let sid = match (&session, several) {
            (Some(held), true) => s(held.get("id")),
            _ => String::new(),
        };
        let ended = self.sessions.end_session_for(&ask.request, response, &sid);
        let clear_site_data = session.is_some()
            && self.sessions.clear_site_data_after_sign_out(&ask.request);
        let partly = unfollowed.as_ref().map(|u| Partly {
            client_id: client_id.clone(),
            uri: u.uri.clone(),
            state: s(q.get("state")),
            username: session
                .as_ref()
                .map(|x| s(x.get("user").and_then(|u| u.get("username"))))
                .unwrap_or_default(),
            detail: refused_detail.clone(),
        });
        let mut a = self.finish(
            ask,
            ended.as_ref(),
            &backchannel_mark,
            &return_to,
            &refused_note,
            &t,
            &front_door,
            partly.as_ref(),
        );
        if clear_site_data {
            a.set("Clear-Site-Data", "\"storage\"");
        }
        marked(a)
    }

    /// `logoutAskReason(q, session, hinted, returnTo, boxed)`: why the page
    /// asks, named for the case at hand (#1301); `None` where the box above
    /// already says there was no hint.
    fn ask_reason(
        q: &Map<String, Json>,
        session: Option<&Json>,
        hinted: Option<&Json>,
        return_to: &str,
        boxed: bool,
    ) -> AskReason {
        let target = s(q.get("post_logout_redirect_uri"));
        let Some(held) = session else {
            return Some("oauthPages.logout.whyNoCookie");
        };
        let Some(hint) = hinted else {
            if !target.is_empty() && return_to.is_empty() && boxed {
                return None;
            }
            return Some("oauthPages.logout.whyNoHint");
        };
        let sid = s(hint.get("sid"));
        if sid.is_empty() {
            return Some("oauthPages.logout.whyHintNoSid");
        }
        if sid != s(held.get("id")) {
            return Some("oauthPages.logout.whyHintOtherSession");
        }
        Some("oauthPages.logout.whyLogoutHint")
    }

    /// `logoutConfirmPage(...)`: a real form that POSTs back with the
    /// request's own parameters and the value only this session's page
    /// can carry; no script. With several accounts and nothing that chose
    /// one, a form per account (#561).
    #[allow(clippy::too_many_arguments)]
    fn confirm_page(
        &self,
        ask: &LogoutAsk,
        q: &Map<String, Json>,
        session: Option<&Json>,
        client: &Json,
        t: &Translator<'_>,
        accounts: Option<&[Json]>,
        reason: AskReason,
        refused: &str,
    ) -> Answer {
        let names: Vec<&str> = [
            "post_logout_redirect_uri",
            "client_id",
            "id_token_hint",
            "state",
            "logout_hint",
            "ui_locales",
        ]
        .into_iter()
        .filter(|n| q.get(*n).is_some_and(|v| !v.is_null() && s(Some(v)) != ""))
        .collect();
        let carried: String = names
            .iter()
            .map(|n| {
                format!(
                    "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
                    n,
                    esc(&s(q.get(*n)))
                )
            })
            .collect();
        let who = session
            .map(|x| s(x.get("user").and_then(|u| u.get("username"))))
            .unwrap_or_default();
        let app = if client.get("known") == Some(&Json::Bool(true)) {
            let name = s(client.get("client_name"));
            if name.is_empty() {
                s(client.get("client_id"))
            } else {
                name
            }
        } else {
            s(q.get("client_id"))
        };
        let pairs: Vec<(String, String)> = names
            .iter()
            .map(|n| (n.to_string(), s(q.get(*n))))
            .collect();
        let here = format!(
            "{}{}/oauth2/logout{}",
            ask.prefix,
            ask.as_path,
            if pairs.is_empty() {
                String::new()
            } else {
                format!("?{}", crate::js::form_encode(&pairs))
            }
        );
        let chooser = sts_http::error_page::chooser(t, &self.catalogs, &here);
        let title = Self::text(t, "oauthPages.logout.confirmTitle");
        if let Some(list) = accounts.filter(|l| l.len() > 1) {
            let forms: String = list
                .iter()
                .map(|one| {
                    let held = self.sessions.session_by_id(&s(one.get("sid")));
                    format!(
                        "<form method=\"post\" action=\"logout\">{}<input \
                         type=\"hidden\" name=\"sts_signout_account\" \
                         value=\"{}\"><input type=\"hidden\" \
                         name=\"confirm_for\" value=\"{}\"><button \
                         type=\"submit\" name=\"confirm\" value=\"yes\">{}\
                         </button></form>",
                        carried,
                        esc(&s(one.get("key"))),
                        esc(&Self::confirm_for(held.as_ref())),
                        Self::html(
                            t,
                            "oauthPages.logout.signOutAccount",
                            &[("who", &s(one.get("username")))]
                        )
                    )
                })
                .collect();
            let count = list.len().to_string();
            let ask_text = if app.is_empty() {
                Self::html(
                    t,
                    "oauthPages.logout.askWhich",
                    &[("count", &count)],
                )
            } else {
                Self::html(
                    t,
                    "oauthPages.logout.askWhichApp",
                    &[("app", &app), ("count", &count)],
                )
            };
            return self.page_answer(
                200,
                &title,
                &format!(
                    "{}<p>{}</p>{}<form method=\"post\" action=\"logout\">{}\
                     <button type=\"submit\" name=\"confirm\" value=\"no\">{}\
                     </button></form><p class=\"sub\">{}</p>",
                    refused,
                    ask_text,
                    forms,
                    carried,
                    Self::html(t, "oauthPages.logout.stay", &[]),
                    Self::html(t, "oauthPages.logout.whyWhich", &[])
                ),
                Some(t),
                &chooser,
            );
        }
        let params = [("app", app.as_str()), ("who", who.as_str())];
        let ask_text = match (app.is_empty(), who.is_empty()) {
            (false, false) => {
                Self::html(t, "oauthPages.logout.askAppWho", &params)
            }
            (false, true) => Self::html(t, "oauthPages.logout.askApp", &params),
            (true, false) => Self::html(t, "oauthPages.logout.askWho", &params),
            (true, true) => Self::html(t, "oauthPages.logout.ask", &[]),
        };
        let why = match reason {
            None => String::new(),
            Some(key) => {
                format!("<p class=\"sub\">{}</p>", Self::html(t, key, &[]))
            }
        };
        self.page_answer(
            200,
            &title,
            &format!(
                "{}<p>{}</p><form method=\"post\" action=\"logout\">{}<input \
                 type=\"hidden\" name=\"confirm_for\" value=\"{}\"><button \
                 type=\"submit\" name=\"confirm\" value=\"yes\">{}</button> \
                 <button type=\"submit\" name=\"confirm\" value=\"no\">{}\
                 </button></form>{}",
                refused,
                ask_text,
                carried,
                esc(&Self::confirm_for(session)),
                Self::html(t, "oauthPages.logout.signOut", &[]),
                Self::html(t, "oauthPages.logout.stay", &[]),
                why
            ),
            Some(t),
            &chooser,
        )
    }

    /// `logoutPage(inner, head, t, title)`: the sign-out page's own small
    /// shell.
    fn shell(
        inner: &str,
        head: &str,
        t: Option<&Translator<'_>>,
        title: &str,
    ) -> String {
        let attributes = match t {
            Some(t) => sts_http::error_page::html_attributes(t),
            None => " lang=\"en\"".to_string(),
        };
        let title = if !title.is_empty() {
            title.to_string()
        } else {
            match t {
                Some(t) => Self::text(t, "oauthPages.signedOut.title"),
                None => "Signed out".to_string(),
            }
        };
        format!(
            "<!doctype html><html{}><head><meta charset=\"utf-8\"><meta \
             name=\"viewport\" content=\"width=device-width, \
             initial-scale=1\"><title>{}</title>{}<style>body{{font-family:\
             system-ui,-apple-system,\"Segoe UI\",Roboto,sans-serif;margin:\
             2rem auto;max-width:52rem;padding:0 1rem;line-height:1.5;color:\
             #111}}h1{{font-size:1.4rem}}h2{{font-size:1.1rem;margin-top:\
             1.6rem}}.sub{{color:#555;font-size:.9rem}}.ok{{background:\
             #e8f5e9;border-left:4px solid #2e7d32;padding:.6rem .8rem;\
             margin:1rem 0}}.warn{{background:#fff8e1;border-left:4px solid \
             #b26a00;padding:.6rem .8rem;margin:1rem 0}}table{{border-\
             collapse:collapse;width:100%;margin:.6rem 0}}th,td{{text-align:\
             left;padding:.4rem .6rem;border-bottom:1px solid #ddd;vertical-\
             align:top}}code{{background:#f4f4f4;padding:.05rem .25rem;\
             border-radius:3px;word-break:break-all}}details.language-row{{\
             float:right;margin:0 0 .5rem 1rem}}{}{}</style></head><body>{}\
             </body></html>",
            attributes,
            esc(&title),
            head,
            sts_http::error_page::FOOTER_CSS,
            sts_http::error_page::ROW_CSS,
            inner
        )
    }

    /// `logoutAnswer(res, status, title, body, t, chooser)`.
    fn page_answer(
        &self,
        status: u16,
        title: &str,
        body: &str,
        t: Option<&Translator<'_>>,
        chooser: &str,
    ) -> Answer {
        Self::page(
            status,
            Self::shell(
                &format!("{}<h1>{}</h1>{}", chooser, esc(title), body),
                "",
                t,
                title,
            ),
        )
    }

    /// `oauthPages.signedOut.returnAuto`'s one plural (`{seconds, plural,
    /// one {# second} other {# seconds}}`), English's cardinal rule.
    fn seconds_sentence(t: &Translator<'_>, n: i64) -> String {
        let raw = Self::html(t, "oauthPages.signedOut.returnAuto", &[]);
        let Some(open) = raw.find("{seconds, plural,") else {
            return raw.replace("{seconds}", &n.to_string());
        };
        let mut depth = 0;
        let mut close = raw.len();
        for (i, c) in raw[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = open + i;
                        break;
                    }
                }
                _ => {}
            }
        }
        let body = &raw[open + "{seconds, plural,".len()..close];
        let pick = |name: &str| -> Option<String> {
            let at = body.find(&format!("{} {{", name))?;
            let rest = &body[at + name.len() + 2..];
            let end = rest.find('}')?;
            Some(rest[..end].replace('#', &n.to_string()))
        };
        let chosen = if n == 1 { pick("one") } else { None }
            .or_else(|| pick("other"))
            .unwrap_or_else(|| n.to_string());
        format!("{}{}{}", &raw[..open], chosen, &raw[close + 1..])
    }

    /// `logoutFinish(...)`: the front-channel page, the return, or a page
    /// saying it is done.
    #[allow(clippy::too_many_arguments)]
    fn finish(
        &self,
        ask: &LogoutAsk,
        session: Option<&Json>,
        backchannel_mark: &Json,
        return_to: &str,
        refused_note: &str,
        t: &Translator<'_>,
        chooser: &str,
        partly: Option<&Partly>,
    ) -> Answer {
        let title_key = if partly.is_some() {
            "oauthPages.signedOut.partlyRefused"
        } else {
            "oauthPages.signedOut.title"
        };
        let ending = match partly {
            Some(p) => {
                let label = |k: &str| Self::text(t, k);
                sts_http::error_page::footer(
                    t,
                    &[
                        DiagnosticRow {
                            label: label("errorPages.application"),
                            value: p.client_id.clone(),
                        },
                        DiagnosticRow {
                            label: label("errorPages.postLogoutRedirectUri"),
                            value: p.uri.clone(),
                        },
                        DiagnosticRow {
                            label: label("errorPages.state"),
                            value: p.state.clone(),
                        },
                        DiagnosticRow {
                            label: label("errorPages.signedInAs"),
                            value: p.username.clone(),
                        },
                        DiagnosticRow {
                            label: label("errorPages.detail"),
                            value: p.detail.clone(),
                        },
                    ],
                    (self.incident)(),
                    &sts_http::error_page::iso_now(),
                    &ask.prefix,
                )
            }
            None => String::new(),
        };
        let ids: Vec<String> =
            session.map(|x| vec![s(x.get("id"))]).unwrap_or_default();
        let rows = if session.is_some() {
            self.channels.deliveries_for(&ids, backchannel_mark)
        } else {
            Vec::new()
        };
        let issuer = crate::jwt_access_token::JwtAccessTokens::new(
            self.settings.clone(),
        )
        .issuer_for(&ask.base);
        let notifications = match (self.channels.front_enabled(), session) {
            (true, Some(held)) => {
                self.channels.notifications_for(held, &issuer)
            }
            _ => Vec::new(),
        };
        let username = session
            .map(|x| s(x.get("user").and_then(|u| u.get("username"))))
            .unwrap_or_default();
        if notifications
            .iter()
            .any(|n| crate::js::truthy(n.get("url")))
        {
            let wait = self
                .settings
                .value_of("oauth2.frontchannelLogoutWaitS")
                .as_int();
            let ended = if session.is_some() {
                Self::html(
                    t,
                    "oauthPages.signedOut.frontEnded",
                    &[("username", &username)],
                )
            } else {
                Self::html(t, "oauthPages.signedOut.frontNone", &[])
            };
            let back = if return_to.is_empty() {
                String::new()
            } else {
                format!(
                    "<h2>{}</h2><p><a href=\"{}\">{}</a></p><p \
                     class=\"sub\">{}</p>",
                    Self::html(t, "oauthPages.signedOut.returnHeading", &[]),
                    esc(return_to),
                    esc(return_to),
                    if wait > 0 {
                        Self::seconds_sentence(t, wait)
                    } else {
                        Self::html(t, "oauthPages.signedOut.returnLink", &[])
                    }
                )
            };
            let inner = format!(
                "{}<h1>{}</h1><p class=\"sub\">{}</p>{}<div \
                 class=\"ok\">{}</div>{}{}{}{}",
                chooser,
                Self::html(
                    t,
                    if partly.is_some() {
                        title_key
                    } else {
                        "oauthPages.signedOut.heading"
                    },
                    &[]
                ),
                Self::html(t, "oauthPages.signedOut.frontSub", &[]),
                refused_note,
                ended,
                self.channels.render_notifications(&notifications),
                self.channels.render_deliveries(&rows),
                ending,
                back
            );
            let refresh = if !return_to.is_empty() && wait > 0 {
                format!(
                    "<meta http-equiv=\"refresh\" content=\"{};url={}\">",
                    wait,
                    esc(return_to)
                )
            } else {
                String::new()
            };
            let mut a = Self::page(
                200,
                Self::shell(
                    &inner,
                    &refresh,
                    Some(t),
                    &Self::text(t, title_key),
                ),
            );
            a.set(
                "Content-Security-Policy",
                &self.channels.content_security_policy_for(&notifications),
            );
            return a;
        }
        if !return_to.is_empty() {
            return Answer::redirect(return_to);
        }
        let ended = if session.is_some() {
            Self::html(
                t,
                "oauthPages.signedOut.ended",
                &[("username", &username)],
            )
        } else {
            Self::html(t, "oauthPages.signedOut.none", &[])
        };
        self.page_answer(
            200,
            &Self::text(t, title_key),
            &format!(
                "{}<div class=\"ok\">{}</div>{}{}",
                refused_note,
                ended,
                self.channels.render_deliveries(&rows),
                ending
            ),
            Some(t),
            chooser,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_state_replaces_the_registered_one() {
        assert_eq!(
            LogoutEndpoint::with_logout_state(
                "https://rp.example/out?state=old&x=1#f",
                "new value"
            ),
            "https://rp.example/out?state=new+value&x=1#f"
        );
        assert_eq!(
            LogoutEndpoint::with_logout_state("https://rp.example/out", ""),
            "https://rp.example/out"
        );
        assert_eq!(
            LogoutEndpoint::with_logout_state("https://rp.example/out", "s"),
            "https://rp.example/out?state=s"
        );
    }

    #[test]
    fn the_confirmation_value_is_the_handle_hash_digest() {
        let session = json!({ "handleHash": "abc" });
        let v = LogoutEndpoint::confirm_for(Some(&session));
        assert_eq!(v.len(), 32);
        assert_eq!(LogoutEndpoint::confirm_for(None), "");
    }

    #[test]
    fn a_hint_names_the_client_by_azp_or_its_one_audience() {
        let b = |v: &Json| sts_crypto::b64::encode(v.to_string().as_bytes());
        let jwt =
            |c: Json| format!("{}.{}.x", b(&json!({"alg":"RS256"})), b(&c));
        assert_eq!(
            LogoutEndpoint::hint_client_of(&jwt(json!({"aud":["a"]}))),
            "a"
        );
        assert_eq!(
            LogoutEndpoint::hint_client_of(&jwt(json!({"aud":["a","b"]}))),
            ""
        );
        assert_eq!(
            LogoutEndpoint::hint_client_of(&jwt(
                json!({"aud":["a","b"],"azp":"b"})
            )),
            "b"
        );
    }
}
