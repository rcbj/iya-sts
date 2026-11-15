// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE PAGE'S API AND THE ACT (#577): who a request is about
//! (`subjectOf()`), the one act both doors perform (`endFor()`), the
//! account step (#561), the page's view and act at `GET` and `POST
//! /authn-api/logout` (`signOutView()`, `signOutAct()`), the fan-out a
//! result leaves the browser (`fanOutOf()`), and the result sealed to
//! travel with the browser (`sealResult()`, `openResult()`).
//!
//! **THE RESULT TRAVELS WITH THE BROWSER, MACed, and nothing here stores
//! it** (rule 3m). Raw DEFLATE, base64url, then an HMAC-SHA256 under the
//! `logout-result` cluster secret over `sts-logout-result-v1.<packed>`:
//! Node's format, so a result one runtime sealed is opened by the other.

use std::io::{Read, Write};

use serde_json::{json, Map, Value};
use sts_core::errors::codes;

use crate::js::{self, or_empty, string_of, truthy, Object};
use crate::logout::{Logout, TerminateOptions};
use crate::ports::{Asked, Reply};

/// The sign-out's path.
pub const LOGOUT_PATH: &str = "/logout";
/// The signed-out document's.
pub const SIGNED_OUT_PATH: &str = "/logout/signed-out";
const RESULT_LABEL: &str = "sts-logout-result-v1";
const RESULT_TTL_MS: f64 = 5.0 * 60.0 * 1000.0;

/// What a page operation answers: `{ status, code, json }`, which the
/// `/authn-api` door sends.
#[derive(Debug, Clone, PartialEq)]
pub struct Answered {
    pub status: u16,
    pub code: Option<&'static str>,
    pub json: Value,
}

fn answered(status: u16, json: Value) -> Answered {
    Answered {
        status,
        code: None,
        json,
    }
}

/// `subjectOf()`'s answer.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Subject {
    pub username: String,
    pub key: String,
    pub session: Option<Value>,
    pub named: bool,
    pub refused: bool,
    pub asked: String,
}

/// `fanOutOf()`'s answer: the markup and the policy's overrides.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FanOut {
    pub html: String,
    pub policy: Vec<(String, String)>,
}

/// `helpers.xmlEscape()`: `&`, `<`, `>`, `"` and `'` (as `&apos;`).
// A hot path: every value drawn; no span.
pub fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

impl Logout {
    /// `subjectOf(req, body)`: a named username where naming somebody
    /// else is open (or it is the caller's own), else the session, else
    /// nobody.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn subject_of(&self, asked: &Asked, body: Option<&Object>) -> Subject {
        let authn = &self.deps.authn;
        let stats = &self.deps.stats;
        let from_body = body.map(|b| or_empty(b.get("username")));
        let named_text = match from_body.filter(|t| !t.is_empty()) {
            Some(t) => t,
            None => asked.query_text("username"),
        };
        let wanted = named_text.trim().to_string();
        if authn.multiple_accounts() {
            let account = match body.map(|b| or_empty(b.get("account"))) {
                Some(a) if !a.is_empty() => a,
                _ => asked.query_text("account"),
            };
            if !account.is_empty() {
                authn.hint_account_key(asked, &account);
            } else if !wanted.is_empty() {
                authn.hint_account(
                    asked,
                    &json!({ "loginHint": wanted, "soft": true }),
                );
            }
        }
        if !wanted.is_empty() {
            if !self.any_user_allowed() {
                let own = authn.session_of(asked);
                let own_name = own
                    .as_ref()
                    .map(|o| o.get("user"))
                    .filter(|u| truthy(*u))
                    .map(|u| string_of(u.and_then(|u| u.get("username"))))
                    .unwrap_or_default();
                if !own_name.is_empty()
                    && stats.identity_key_of(&own_name)
                        == stats.identity_key_of(&wanted)
                {
                    return Subject {
                        key: stats.identity_key_of(&own_name),
                        username: own_name,
                        session: own,
                        ..Subject::default()
                    };
                }
                return Subject {
                    refused: true,
                    asked: wanted,
                    ..Subject::default()
                };
            }
            return Subject {
                key: stats.identity_key_of(&wanted),
                username: wanted,
                named: true,
                ..Subject::default()
            };
        }
        if let Some(session) = authn.session_of(asked) {
            let username =
                or_empty(session.get("user").and_then(|u| u.get("username")));
            return Subject {
                key: stats.identity_key_of(&username),
                username,
                session: Some(session),
                ..Subject::default()
            };
        }
        Subject::default()
    }

    /// `wantsJson(req)`: `?format=json`, a JSON body, or an `Accept` naming
    /// JSON and not HTML.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn wants_json(asked: &Asked) -> bool {
        if asked.query.get("format").map(js::text).as_deref() == Some("json") {
            return true;
        }
        let low = |t: String| t.to_ascii_lowercase();
        if low(asked.header("content-type")).contains("json") {
            return true;
        }
        let accept = low(asked.header("accept"));
        accept.contains("json") && !accept.contains("text/html")
    }

    /// `refusedNameMessage(asked)`, in English.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn refused_name_message(&self, wanted: &str) -> String {
        format!(
            "{}, so /logout acts only on the session you are holding. It \
             was asked about \"{}\". To sign another person out, use \
             /admin/logout (the console's Admin Write role) or POST \
             /admin-api/logout (an access token carrying admin:write).",
            if self.deps.host.opens_test_controls() {
                "logout.anyUser is off on this instance"
            } else {
                "This service is in product mode, where a sign-out cannot \
                 name somebody else whatever logout.anyUser says"
            },
            wanted
        )
    }

    /// `nobodyMessage(act)`, in English.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn nobody_message(&self, act: bool) -> String {
        let closed = if self.deps.host.opens_test_controls() {
            "logout.anyUser is off"
        } else {
            "product mode"
        };
        let open = self.any_user_allowed();
        match (act, open) {
            (true, true) => "There is nobody to sign out: this request \
                             carries no session cookie and named no \
                             username. A POST is never redirected to the \
                             sign-in screen — a 303 would make it a GET and \
                             the fields would be gone."
                .into(),
            (true, false) => format!(
                "There is nobody to sign out: this request carries no \
                 session cookie, and naming somebody is closed ({}).",
                closed
            ),
            (false, true) => "There is no session cookie on this request. \
                              Name somebody with ?username=, or sign in at \
                              /authn/login first."
                .into(),
            (false, false) => format!(
                "There is no session cookie on this request, and naming \
                 somebody is closed ({}), so there is nobody for this \
                 endpoint to act on. Sign in at /authn/login first.",
                closed
            ),
        }
    }

    /// `issuerFor(req)`: the default authorization server's issuer.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn issuer_for(&self, asked: &Asked) -> String {
        self.deps.oauth2.issuer_of(&asked.base)
    }

    /// `reauthenticationOwed(subject, body)` (#1521, ASVS 5.0.0 7.5.2):
    /// ending somebody's OTHER sessions needs a recent sign-in; leaving
    /// never does.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn reauthentication_owed(
        &self,
        subject: &Subject,
        body: &Object,
    ) -> bool {
        let limit = js::number(Some(
            &self.deps.host.setting("account.recentAuthMinutes"),
        )) * 60.0;
        let own = subject
            .session
            .as_ref()
            .map(|s| string_of(s.get("id")))
            .unwrap_or_default();
        let others: Vec<String> = js::listed(body.get("select"))
            .iter()
            .map(js::text)
            .filter(|one| *one != own && *one != format!("session:{}", own))
            .collect();
        if limit == 0.0
            || or_empty(body.get("scope")) == "global"
            || others.is_empty()
        {
            return false;
        }
        let at = self.deps.authn.last_authenticated_at(
            subject.session.as_ref().unwrap_or(&Value::Null),
        );
        let now = self.deps.host.now_ms() / 1000.0;
        !(at > 0.0 && now - at <= limit)
    }

    /// `endFor(req, res, subject, body)`: THE ACT, once, for both doors.
    /// The cookie is cleared only where the CALLER'S OWN session was among
    /// the things ended (or, with several accounts, where the browser's
    /// default ended).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn end_for(
        &self,
        asked: &Asked,
        reply: &mut Reply,
        subject: &Subject,
        body: &Object,
    ) -> Result<(Value, bool), String> {
        let explicit_global = or_empty(body.get("scope")) == "global";
        let selection: Vec<String> = if explicit_global {
            Vec::new()
        } else {
            js::listed(body.get("select"))
                .iter()
                .map(js::text)
                .collect()
        };
        let own = subject
            .session
            .as_ref()
            .map(|s| string_of(s.get("id")))
            .unwrap_or_default();
        let issuer = self.issuer_for(asked);
        let result = self.terminate(
            &subject.key,
            &selection,
            &TerminateOptions {
                issuer,
                base: asked.base.clone(),
                browser: true,
                actor: subject.username.clone(),
                initiating_entity: if subject.named { "admin" } else { "user" }
                    .into(),
                by: if subject.named {
                    format!("a /logout request naming {}", subject.username)
                } else {
                    "the person's own sign-out at /logout".into()
                },
                spare_credentials: selection.is_empty(),
                ..TerminateOptions::default()
            },
        )?;
        let terminated = result
            .get("terminated")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let ended_own = !own.is_empty()
            && terminated.iter().any(|one| {
                string_of(one.get("id")) == format!("session:{}", own)
            });
        let authn = &self.deps.authn;
        if authn.multiple_accounts() {
            authn.after_account_sign_out(asked, reply);
        } else if ended_own {
            authn.clear_session_cookie(reply);
        }
        if ended_own || !terminated.is_empty() {
            authn.clear_site_data_after_sign_out(asked, reply);
        }
        Ok((result, ended_own))
    }

    /// `namingOf()`: who may be named here.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn naming_of(&self) -> &'static str {
        if self.any_user_allowed() {
            "open"
        } else if self.deps.host.opens_test_controls() {
            "off"
        } else {
            "product"
        }
    }

    /// `accountStep(req, always)` (#561): the browser's signed-in accounts
    /// by KEY, never a sid; `None` with the setting off or one account.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn account_step(&self, asked: &Asked, always: bool) -> Option<Value> {
        let authn = &self.deps.authn;
        if !authn.multiple_accounts() {
            return None;
        }
        let accounts = authn.signed_in_accounts(asked);
        if accounts.len() < 2 && !always {
            return None;
        }
        let hint = asked.query_text("login_hint").trim().to_lowercase();
        let named = if hint.is_empty() {
            None
        } else {
            accounts.iter().find(|one| {
                ["username", "sub", "key"]
                    .iter()
                    .any(|k| or_empty(one.get(*k)).to_lowercase() == hint)
            })
        };
        let listed: Vec<Value> = accounts
            .iter()
            .map(|one| {
                json!({ "key": one.get("key"), "username": one.get("username"),
                        "displayName": one.get("displayName"),
                        "current": one.get("current") })
            })
            .collect();
        Some(json!({ "state": "accounts", "accounts": listed,
            "preselected": named.map_or(json!(""), |n| n["key"].clone()),
            "naming": self.naming_of() }))
    }

    fn account_key_of(&self, asked: &Asked, subject: &Subject) -> String {
        let sid = subject
            .session
            .as_ref()
            .map(|s| string_of(s.get("id")))
            .unwrap_or_default();
        if sid.is_empty() || !self.deps.authn.multiple_accounts() {
            return String::new();
        }
        self.deps
            .authn
            .signed_in_accounts(asked)
            .iter()
            .find(|one| string_of(one.get("sid")) == sid)
            .map(|one| string_of(one.get("key")))
            .unwrap_or_default()
    }

    fn accounts_off() -> Answered {
        Answered {
            status: 400,
            code: Some(codes::STS_LOGOUT_0013.as_str()),
            json: json!({ "ok": false, "errors": [
                "This trust realm does not keep several signed-in accounts \
                 per browser (authn.multipleAccounts is off), so there is no \
                 account to choose."] }),
        }
    }

    /// `signOutAccountsView(req)`: `GET /authn-api/logout/accounts`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn sign_out_accounts_view(&self, asked: &Asked) -> Answered {
        if !self.deps.authn.multiple_accounts() {
            return Logout::accounts_off();
        }
        answered(
            200,
            json!({ "ok": true, "view": self.account_step(asked, true) }),
        )
    }

    /// `signOutAccountsAct(req, res, body)`: one account's inventory, or
    /// every account in this browser, each that person's own global
    /// sign-out.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn sign_out_accounts_act(
        &self,
        asked: &Asked,
        reply: &mut Reply,
        body: &Object,
    ) -> Result<Answered, String> {
        let authn = &self.deps.authn;
        if !authn.multiple_accounts() {
            return Ok(Logout::accounts_off());
        }
        let wanted = or_empty(body.get("account"));
        let accounts = authn.signed_in_accounts(asked);
        if wanted != "all" {
            let Some(one) =
                accounts.iter().find(|a| string_of(a.get("key")) == wanted)
            else {
                return Ok(Answered {
                    status: 409,
                    code: Some(codes::STS_LOGOUT_0012.as_str()),
                    json: json!({ "ok": false, "next": "refused",
                        "errors": ["That account is not signed in in this \
                                    browser any more. Choose again."],
                        "view": self.account_step(asked, true) }),
                });
            };
            let key = string_of(one.get("key"));
            return Ok(answered(
                200,
                json!({ "ok": true, "next": "inventory", "account": key,
                    "location": format!("{}?account={}", LOGOUT_PATH,
                        js::encode_uri_component(&key)) }),
            ));
        }
        let mut results = Vec::new();
        for one in &accounts {
            let username = string_of(one.get("username"));
            let key = self.deps.stats.identity_key_of(&username);
            let issuer = self.issuer_for(asked);
            results.push(
                self.terminate(
                    &key,
                    &[],
                    &TerminateOptions {
                        issuer,
                        base: asked.base.clone(),
                        browser: true,
                        actor: username,
                        initiating_entity: "user".into(),
                        by: "the person's own sign-out at /logout, of every \
                         account in the browser"
                            .into(),
                        spare_credentials: true,
                        ..TerminateOptions::default()
                    },
                )?,
            );
        }
        authn.after_account_sign_out(asked, reply);
        authn.clear_site_data_after_sign_out(asked, reply);
        let result = Logout::merged_result(&results);
        let names: Vec<String> = accounts
            .iter()
            .map(|a| string_of(a.get("username")))
            .collect();
        let mut answer = json!({ "ok": true, "next": "signed-out",
            "username": names.join(", "), "ownSessionEnded": true,
            "scope": "global" });
        if self.fans_out(&result) {
            answer["form"] = self.form_of(&result);
            return Ok(answered(200, answer));
        }
        let key = string_of(result.get("key"));
        let issuer = self.issuer_for(asked);
        let remaining = self.inventory_for(&key, &issuer)?;
        answer["view"] = Logout::result_view(&result, &remaining);
        Ok(answered(200, answer))
    }

    /// `mergedResult(results)`: several people's results as one.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn merged_result(results: &[Value]) -> Value {
        let join = |name: &str| -> Value {
            Value::Array(
                results
                    .iter()
                    .flat_map(|r| {
                        r.get(name)
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_default()
                    })
                    .collect(),
            )
        };
        let messages: Vec<String> = results
            .iter()
            .map(|r| string_of(r.get("message")))
            .collect();
        json!({ "ok": true,
            "key": results.first().map_or(json!(""), |r| r["key"].clone()),
            "scope": "global", "terminated": join("terminated"),
            "skipped": join("skipped"), "unknown": join("unknown"),
            "notifications": join("notifications"),
            "cleanups": join("cleanups"),
            "logoutRequests": join("logoutRequests"),
            "partnerLogouts": join("partnerLogouts"),
            "backchannel": join("backchannel"),
            "message": messages.join(" ") })
    }

    fn subject_refusal(&self, subject: &Subject, act: bool) -> Answered {
        if subject.refused {
            return Answered {
                status: 403,
                code: Some(codes::STS_LOGOUT_0001.as_str()),
                json: json!({ "ok": false,
                    "errors": [self.refused_name_message(&subject.asked)],
                    "view": { "state": "refused",
                        "verifiesCredentials":
                            self.deps.host.verifies_credentials() } }),
            };
        }
        Answered {
            status: 401,
            code: Some(codes::STS_LOGOUT_0002.as_str()),
            json: json!({ "ok": false, "errors": [self.nobody_message(act)],
                          "view": { "state": "nobody" } }),
        }
    }

    /// `signOutView(req)`: `GET /authn-api/logout`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn sign_out_view(&self, asked: &Asked) -> Result<Answered, String> {
        let names_whom = truthy(asked.query.get("account"))
            || truthy(asked.query.get("username"));
        if !names_whom {
            if let Some(step) = self.account_step(asked, false) {
                return Ok(answered(200, json!({ "ok": true, "view": step })));
            }
        }
        let subject = self.subject_of(asked, None);
        if subject.refused || subject.key.is_empty() {
            return Ok(self.subject_refusal(&subject, false));
        }
        let issuer = self.issuer_for(asked);
        let inventory = self.inventory_for(&subject.key, &issuer)?;
        let account = self.account_key_of(asked, &subject);
        let mut view = Map::new();
        view.insert("state".into(), json!("inventory"));
        view.insert("username".into(), json!(subject.username));
        view.insert("named".into(), json!(subject.named));
        view.insert("naming".into(), json!(self.naming_of()));
        if !account.is_empty() {
            view.insert("account".into(), json!(account));
        }
        if let Value::Object(inv) = inventory {
            for (k, v) in inv {
                view.insert(k, v);
            }
        }
        Ok(answered(200, json!({ "ok": true, "view": view })))
    }

    /// `signOutAct(req, res, body)`: `POST /authn-api/logout`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn sign_out_act(
        &self,
        asked: &Asked,
        reply: &mut Reply,
        body: &Object,
    ) -> Result<Answered, String> {
        let subject = self.subject_of(asked, Some(body));
        if subject.refused || subject.key.is_empty() {
            return Ok(self.subject_refusal(&subject, true));
        }
        if self.reauthentication_owed(&subject, body) {
            return Ok(self.reauthentication_refusal(asked, &subject, body));
        }
        let (result, ended_own) = self.end_for(asked, reply, &subject, body)?;
        let mut answer = json!({ "ok": true, "next": "signed-out",
            "username": subject.username, "ownSessionEnded": ended_own,
            "scope": result["scope"] });
        if self.fans_out(&result) {
            answer["form"] = self.form_of(&result);
            return Ok(answered(200, answer));
        }
        let issuer = self.issuer_for(asked);
        let remaining = self.inventory_for(&subject.key, &issuer)?;
        answer["view"] = Logout::result_view(&result, &remaining);
        Ok(answered(200, answer))
    }

    fn form_of(&self, result: &Value) -> Value {
        json!({ "method": "POST",
            "action": format!("{}{}", self.deps.host.realm_prefix(),
                              SIGNED_OUT_PATH),
            "fields": { "result": self.seal_result(result) } })
    }

    /// `reauthenticationRefusal(req, subject, body)`: 403, the sign-in to
    /// come back from.
    fn reauthentication_refusal(
        &self,
        asked: &Asked,
        subject: &Subject,
        body: &Object,
    ) -> Answered {
        let account = or_empty(body.get("account"));
        let return_to = if account.is_empty() {
            LOGOUT_PATH.to_string()
        } else {
            format!(
                "{}?account={}",
                LOGOUT_PATH,
                js::encode_uri_component(&account)
            )
        };
        let sign_in = self.deps.authn.begin_authentication(
            &json!({ "returnTo": return_to, "protocol": "Logout",
                "accountChoice": "never", "hint": subject.username,
                "details": [{ "label": "what happens next",
                    "value": "you will be returned to the sign-out page",
                    "note": "ending your other sessions needs a recent \
                             sign-in (account.recentAuthMinutes)" }] }),
            Some(asked),
        );
        Answered {
            status: 403,
            code: Some(codes::STS_LOGOUT_0015.as_str()),
            json: json!({ "ok": false,
                "errors": ["Sign in again, then come back to end your other \
                            sessions."],
                "view": { "state": "reauthenticate", "signIn": sign_in } }),
        }
    }

    /// `fanOutOf(results)`: what a browser still has to do — the
    /// front-channel iframes, the back-channel table, the WS-Federation
    /// cleanup images and the SAML LogoutRequest links — and the two
    /// relaxations of the page's policy that make them load.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn fan_out_of(&self, results: &[&Value]) -> FanOut {
        let gather = |name: &str| -> Vec<Value> {
            results
                .iter()
                .flat_map(|r| {
                    r.get(name)
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default()
                })
                .collect()
        };
        let notifications = gather("notifications");
        let cleanups = gather("cleanups");
        let requests = gather("logoutRequests");
        let deliveries = gather("backchannel");
        let cleanup_rows: String = cleanups
            .iter()
            .map(|t| {
                format!(
                    "<tr><td><code>{}</code></td><td>{}</td></tr>",
                    esc(&js::concat(t.get("realm"))),
                    if truthy(t.get("url")) {
                        let u = esc(&js::text(&t["url"]));
                        format!(
                            "<a href=\"{}\" target=\"_blank\" \
                             rel=\"noopener noreferrer\">{}</a>",
                            u, u
                        )
                    } else {
                        "<span class=\"cannot\">no wreply was supplied, so \
                         there is nowhere to send one</span>"
                            .into()
                    }
                )
            })
            .collect();
        let request_rows: String = requests
            .iter()
            .map(|t| {
                format!(
                    "<tr><td><code>{}</code></td><td>{}</td></tr>",
                    esc(&js::concat(t.get("entityId"))),
                    if truthy(t.get("url")) {
                        format!(
                            "<a href=\"{}\">send the LogoutRequest</a><br>\
                             <span class=\"sub\">{}</span>",
                            esc(&js::text(&t["url"])),
                            esc(&js::concat(t.get("from")))
                        )
                    } else {
                        "<span class=\"cannot\">no SingleLogoutService is \
                         known for it</span>"
                            .into()
                    }
                )
            })
            .collect();
        let images: String = cleanups
            .iter()
            .filter(|t| truthy(t.get("url")))
            .map(|t| {
                format!(
                    "<img src=\"{}\" alt=\"\" width=\"1\" height=\"1\">",
                    esc(&js::text(&t["url"]))
                )
            })
            .collect();
        let mut html = String::new();
        if !notifications.is_empty() {
            html.push_str(&self.deps.frontchannel.render(&notifications));
        }
        html.push_str(&self.deps.backchannel.render(&deliveries));
        if !cleanups.is_empty() {
            html.push_str(&format!(
                "<h2>WS-Federation cleanup requests</h2><table><thead><tr>\
                 <th>Realm</th><th>Cleanup URL</th></tr></thead><tbody>{}\
                 </tbody></table>{}{}",
                cleanup_rows,
                crate::document::note(
                    "Each was fetched as a one-pixel image as this page \
                     loaded — front-channel logout — and the links are the \
                     same URLs so a failed ping can be seen rather than \
                     guessed at."
                ),
                images
            ));
        }
        if !requests.is_empty() {
            html.push_str(&format!(
                "<h2>SAML 2.0 LogoutRequests</h2><table><thead><tr><th>\
                 Service provider</th><th>LogoutRequest</th></tr></thead>\
                 <tbody>{}</tbody></table>{}",
                request_rows,
                crate::document::note(
                    "Links rather than an automatic fan-out, which is \
                     /saml2/slo's own decision reused: a LogoutRequest is a \
                     signed message a service provider ANSWERS, and firing \
                     those into hidden frames would claim a federation-wide \
                     logout this service cannot observe."
                )
            ));
        }
        let origins = self.deps.frontchannel.frame_origins_of(&notifications);
        let mut policy = Vec::new();
        if !origins.is_empty() {
            policy.push(("frame-src".to_string(), origins.join(" ")));
        }
        if !images.is_empty() {
            policy.push(("img-src".to_string(), "'self' data: *".to_string()));
        }
        FanOut { html, policy }
    }

    /// `fansOut(result)`: whether the browser has something to do.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn fans_out(&self, result: &Value) -> bool {
        !self.fan_out_of(&[result]).html.is_empty()
            || result
                .get("partnerLogouts")
                .and_then(Value::as_array)
                .is_some_and(|l| !l.is_empty())
    }

    /// `resultView(result, remaining)`: the result as the page draws it.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn result_view(result: &Value, remaining: &Value) -> Value {
        let rows = |name: &str| -> Value {
            Value::Array(
                result
                    .get(name)
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default()
                    .iter()
                    .map(|one| {
                        json!({ "id": one.get("id"),
                                "label": if truthy(one.get("label")) {
                                    one["label"].clone()
                                } else {
                                    json!("")
                                },
                                "message": one.get("message") })
                    })
                    .collect(),
            )
        };
        json!({ "state": "result", "scope": result.get("scope"),
            "key": result.get("key"), "message": result.get("message"),
            "terminated": rows("terminated"), "skipped": rows("skipped"),
            "remaining": remaining.get("total") })
    }

    /// `sealResult(result)`: deflated, base64url, MACed with the realm
    /// and a five-minute expiry.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn seal_result(&self, result: &Value) -> String {
        let pick = |k: &str| result.get(k).cloned().unwrap_or(Value::Null);
        let mut inner = Map::new();
        for k in [
            "key",
            "scope",
            "message",
            "terminated",
            "skipped",
            "unknown",
            "notifications",
            "cleanups",
            "logoutRequests",
            "partnerLogouts",
            "backchannel",
        ] {
            inner.insert(k.into(), pick(k));
        }
        let payload = json!({ "realm": self.deps.host.realm_id(),
            "exp": js::num(self.deps.host.now_ms() + RESULT_TTL_MS),
            "result": inner });
        let text = serde_json::to_string(&payload).unwrap_or_default();
        let mut enc = flate2::write::DeflateEncoder::new(
            Vec::new(),
            flate2::Compression::new(6),
        );
        let packed =
            match enc.write_all(text.as_bytes()).and_then(|_| enc.finish()) {
                Ok(bytes) => sts_crypto::b64::encode(&bytes),
                Err(e) => {
                    tracing::error!(
                        "logout: a result could not be deflated: {}",
                        e
                    );
                    String::new()
                }
            };
        format!("{}.{}", packed, self.mac_of(&packed))
    }

    fn mac_of(&self, packed: &str) -> String {
        let data = format!("{}.{}", RESULT_LABEL, packed);
        match sts_crypto::raw_sig::hmac_sha256(
            &self.deps.host.result_secret(),
            data.as_bytes(),
        ) {
            Ok(mac) => sts_crypto::b64::encode(&mac),
            Err(e) => {
                tracing::error!("logout: a result could not be MACed: {}", e);
                String::new()
            }
        }
    }

    /// `openResult(sealed)`: the result, or why not.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn open_result(&self, sealed: &str) -> Result<Value, String> {
        let Some(dot) = sealed.rfind('.').filter(|d| *d > 0) else {
            return Err("That is not a sign-out result.".into());
        };
        let packed = &sealed[..dot];
        let expected = self.mac_of(packed);
        if expected.is_empty()
            || !sts_crypto::secrets::constant_time_equals(
                &sealed.as_bytes()[dot + 1..],
                expected.as_bytes(),
            )
        {
            return Err(
                "That sign-out result was not made by this service.".into()
            );
        }
        let payload = sts_crypto::b64::decode_loose(packed)
            .ok()
            .and_then(|bytes| {
                let mut out = Vec::new();
                let mut dec = flate2::read::DeflateDecoder::new(&bytes[..])
                    .take(16 * 1024 * 1024 + 1);
                dec.read_to_end(&mut out).ok()?;
                if out.len() > 16 * 1024 * 1024 {
                    return None;
                }
                serde_json::from_slice::<Value>(&out).ok()
            })
            .filter(|p| truthy(p.get("result")));
        let Some(payload) = payload else {
            return Err("That sign-out result could not be read.".into());
        };
        if js::text(payload.get("realm").unwrap_or(&json!("undefined")))
            != self.deps.host.realm_id()
        {
            return Err(
                "That sign-out result was made in another trust realm.".into(),
            );
        }
        // `!(exp > now)`: an exp that is not a number never is later.
        let later = js::number(payload.get("exp"))
            .partial_cmp(&self.deps.host.now_ms())
            == Some(std::cmp::Ordering::Greater);
        if !later {
            return Err(
                "That sign-out result has expired. What is still live \
                        is at /logout."
                    .into(),
            );
        }
        Ok(payload["result"].clone())
    }
}
