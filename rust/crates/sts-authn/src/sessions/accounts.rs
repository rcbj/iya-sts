// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! SEVERAL SIGNED-IN ACCOUNTS IN ONE BROWSER (#561): what the session core
//! does with a browser's account set — `authn/authn.ts`'s account half,
//! door by door, over [`crate::account_sets::AccountSets`].
//!
//! * which session a request acts as ([`Sessions::session_of`] reads
//!   `resolveAccount()`: a ticket spent on the request, a protocol's hint,
//!   the only live session, or nobody), the hint itself
//!   ([`Sessions::hint_account`]) and why nobody was answered
//!   ([`Sessions::account_choice_needed`]);
//! * the tickets a flow resumes on ([`Sessions::spend_account_ticket`],
//!   [`Sessions::ticketed_return`], [`Sessions::account_ticket_for`]);
//! * a sign-in joining the set instead of replacing the browser's session
//!   (`enrolInAccountSet()`, called by [`Sessions::start_session`]), and a
//!   session that ends moving to the set's remembered accounts;
//! * signing one account out rather than all
//!   ([`Sessions::end_session_for`], [`Sessions::after_account_sign_out`]);
//! * the picker's data and acts ([`Sessions::accounts_view`],
//!   [`Sessions::accounts_act`], [`Sessions::browser_accounts`]) — its
//!   screen and its pending record are `/authn-api`'s and the sign-in's,
//!   so an act answers what to do with the record rather than doing it;
//! * the clean-up job's body ([`Sessions::sweep_account_sets_budgeted`]).
//!
//! WHAT REPLACED WHAT. Node writes `req.stsAccount*` on the one request
//! object every later door of the request reads; here they are
//! [`crate::ports::AccountMarks`], shared by the request's clones. Node's
//! D12 writes the new set's cookie on `req.res`; a door handed no response
//! queues it on the marks (`appended`), and one handed a response appends
//! it there at the moment Node does. Every door is a no-op, or Node's old
//! behaviour, with `authn.multipleAccounts` off.

use serde_json::{json, Value};
use sts_core::errors::codes;
use sts_core::log::tag;

use super::{obj, Sessions};
use crate::account_sets::{encode_uri_component, AccountSets};
use crate::cookie;
use crate::js::{self, Object};
use crate::ports::{AccountHint, EndedSelection, Request, Response};
use crate::record::{self, SESSION_COOKIE};

/// `/authn/accounts`, the picker.
pub const ACCOUNTS_PATH: &str = "/authn/accounts";
/// `/authn/login`, the sign-in screen.
pub const LOGIN_PATH: &str = "/authn/login";
/// The scheduler job (`ACCOUNT_SET_EXPIRY_JOB`).
pub const ACCOUNT_SET_EXPIRY_JOB: &str = "authn.account-set-expiry";

/// `resolveAccount()`'s answer.
#[derive(Debug, Clone, Default)]
pub struct Resolved {
    /// `{ fallback: true }`: no set, or no live session in it; the caller
    /// reads the cookie as with the setting off.
    pub fallback: bool,
    pub sid: String,
    /// `ticket`, `hint` or `only`.
    pub how: String,
    /// `ambiguous`, `hint-unmatched` or `unread`.
    pub reason: String,
    pub row: Option<Object>,
    pub live: usize,
    pub hint: String,
}

/// An answer of the picker's API: the status, the code it is recorded
/// under (never sent), and the JSON body `answerJson()` sends with
/// `Cache-Control: no-store`; `retry_after` adds `Retry-After: 5`.
#[derive(Debug, Clone, PartialEq)]
pub struct PickerAnswer {
    pub status: u16,
    pub code: Option<&'static str>,
    pub body: Value,
    pub retry_after: bool,
}

/// What an act did to its pending sign-in, for the store that holds it
/// (`pending.delete()` / `pending.set()` in Node).
#[derive(Debug, Clone, PartialEq)]
pub enum RecordChange {
    Keep,
    Delete(String),
    Set(Object),
}

/// One act at the picker: the answer, and the pending record's change.
#[derive(Debug, Clone, PartialEq)]
pub struct ActOutcome {
    pub answer: PickerAnswer,
    pub record: RecordChange,
}

/// `beginAuthentication()`'s account half: `pick` is why the picker comes
/// first ('' for no picker), `hint` the name filled in where it changes.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BeginChoice {
    pub pick: String,
    pub hint: Option<String>,
}

/// `'…' + x` for a member that may be undefined.
fn cat(v: Option<&Value>) -> String {
    match v {
        None => "undefined".to_string(),
        Some(v) => js::text(v),
    }
}

/// `String(s).slice(0, n)`, by characters.
fn slice(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn refused(status: u16, code: &'static str, why: String) -> PickerAnswer {
    PickerAnswer {
        status,
        code: Some(code),
        body: json!({"ok": false, "next": "refused", "errors": [why]}),
        retry_after: false,
    }
}

fn ok(body: Value) -> PickerAnswer {
    PickerAnswer {
        status: 200,
        code: None,
        body,
        retry_after: false,
    }
}

/// `/[?&]authn=([^&]+)/` of a target, decoded: the pending sign-in a
/// sign-in address names, for [`Sessions::route_to_accounts`].
#[tracing::instrument(level = "debug")]
pub fn pending_id_in(target: &str) -> Option<String> {
    let at = target
        .match_indices("authn=")
        .find(|(i, _)| {
            *i > 0 && matches!(target.as_bytes()[i - 1], b'?' | b'&')
        })?
        .0;
    let raw: String =
        target[at + 6..].chars().take_while(|c| *c != '&').collect();
    if raw.is_empty() {
        return None;
    }
    crate::account_sets::decode_uri_component(&raw)
}

/// `pendingForAccounts(id)`'s test of the record: waiting on an account
/// choice, picker-only ones included, and not expired.
#[tracing::instrument(level = "debug", skip(record))]
pub fn awaits_account_choice(record: Option<&Value>, now_ms: f64) -> bool {
    let Some(r) = record.filter(|r| js::truthy(Some(r))) else {
        return false;
    };
    // `record.expires < Date.now()` is false for a NaN expiry.
    js::number(r.get("expires")).partial_cmp(&now_ms)
        != Some(std::cmp::Ordering::Less)
        && !js::truthy(r.get("restartOnly"))
        && js::truthy(r.get("accountChoice"))
}

impl Sessions {
    /// `multipleAccounts()`: `authn.multipleAccounts` in the ambient realm.
    // A hot path: every session read; no span.
    pub fn multiple_accounts(&self) -> bool {
        self.accounts.enabled()
    }

    /// The account sets' library and stores.
    // A hot path: a borrow; no span.
    pub fn account_sets(&self) -> &AccountSets {
        &self.accounts
    }

    /// `accountSetCookieName()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn account_set_cookie_name(&self) -> String {
        self.accounts.cookie_name()
    }

    // -------------------------------------------------------------------
    // The set, and what it lists.
    // -------------------------------------------------------------------

    /// `accountSetOf(req)`: the set this request created or rotated, or
    /// the one its cookie names; `None` with the request marked unread
    /// where reading it failed (a Cookie header that does not parse is
    /// one, as in Node: `cookiesOf()` throws inside the read).
    // A hot path: asked on every session read or sign-in; the door's
    // span covers it, no span of its own.
    pub(super) fn account_set_of(
        &self,
        request: Option<&Request>,
    ) -> Option<Object> {
        let r = request?;
        let set_id = r.accounts.lock().set_id.clone();
        if !set_id.is_empty() {
            return self.accounts.by_id(&set_id);
        }
        // A cookie that does not decode is skipped by cookies_of() (Node's
        // fix of 2026-11-14), so the header itself never makes the set
        // unreadable; a store that fails still does, in set_of().
        self.accounts.set_of(&cookie::cookies_of(&r.cookie))
    }

    /// `accountEligible(session)`: a browser's own authenticated sign-in.
    // A hot path: asked on every session read or sign-in; the door's
    // span covers it, no span of its own.
    pub(super) fn account_eligible(session: &Value) -> bool {
        js::truthy(session.get("user"))
            && session.get("chosen") != Some(&Value::Bool(false))
            && session.get("authenticated") != Some(&Value::Bool(false))
            && !js::truthy(session.get("rpSurface"))
            && !js::truthy(session.get("credentialKey"))
    }

    /// `accountSessionRead(sid).session`: the full map is the store here
    /// (no session window), so a read never fails.
    // A hot path: asked on every session read or sign-in; the door's
    // span covers it, no span of its own.
    pub(super) fn account_session_read(&self, sid: &str) -> Option<Value> {
        if sid.is_empty() {
            None
        } else {
            self.here().get(sid)
        }
    }

    /// `accountSessionLive(sid)`: held, eligible, neither clock run out.
    // A hot path: asked on every session read or sign-in; the door's
    // span covers it, no span of its own.
    pub(super) fn account_session_live(&self, sid: &str) -> bool {
        self.account_session_read(sid).is_some_and(|s| {
            Self::account_eligible(&s)
                && self.session_ended(Some(&s), 0.0).is_empty()
        })
    }

    /// `accountSessionKept(sid)`: live, or unread (never, here).
    fn account_session_kept(&self, sid: &str) -> bool {
        self.account_session_live(sid)
    }

    /// `accountOf(session)`: what a set remembers of a session's account.
    fn account_of(session: &Value) -> Value {
        let user = js::object_of(session.get("user"));
        let name = match js::or_empty(user.get("name")) {
            n if n.is_empty() => js::or_empty(user.get("username")),
            n => n,
        };
        json!({"sub": js::or_empty(user.get("sub")),
               "username": js::or_empty(user.get("username")),
               "displayName": name})
    }

    /// `stampAccountSet(sid, session, setId)`: the set on the row, so its
    /// end finds the set by key. Node writes the object it holds; the row
    /// as stored now is that object here, and the held copy where it has
    /// gone (Node's `sessions.set()` writes it back either way).
    fn stamp_account_set(&self, sid: &str, held: &Value, set_id: &str) {
        // IT NEVER BRINGS A SESSION BACK (Node's fix of 2026-11-14, #444
        // D12). The stamp wrote the held copy back with a plain set(), so
        // a session another request or node ended between the caller's
        // read and this write came back to life. It goes through
        // noteSessionChanged(), which writes only a row the store still
        // holds (merged with a newer copy) and nothing for one that is gone.
        if held.is_null() || held.get("accountSetId") == Some(&json!(set_id)) {
            return;
        }
        if js::or_empty(held.get("id")) != sid {
            return;
        }
        let mut session = held.clone();
        if let Some(o) = session.as_object_mut() {
            o.insert("accountSetId".into(), json!(set_id));
        }
        if !self.note_session_copy_changed(&session) {
            tracing::debug!(
                "authn: session {} is gone; its set stamp not written",
                sid
            );
        }
    }

    /// `ensureAccountSet(req, create)` (D12): the browser's set, made
    /// around its live session where it has none and `create` asks.
    fn ensure_account_set(
        &self,
        request: Option<&Request>,
        create: bool,
    ) -> Option<Object> {
        let have = self.account_set_of(request);
        let Some(r) = request else {
            return have;
        };
        if have.is_some() || !create || r.accounts.lock().set_unread {
            return have;
        }
        let (id, session) = self.cookie_session(Some(r), SESSION_COOKIE)?;
        if !Self::account_eligible(&session)
            || !self.account_session_live(&id)
            || !r.accounts.lock().response_open
        {
            return None;
        }
        let mut row = self.accounts.fresh();
        self.accounts
            .add_session(&mut row, &id, &Self::account_of(&session));
        let value = self.accounts.rotate(&mut row);
        self.accounts.save(&mut row);
        let set_id = js::string_of(row.get("id"));
        {
            let mut marks = r.accounts.lock();
            marks.appended.push(self.accounts.cookie_line(&value));
            marks.set_id = set_id.clone();
        }
        self.stamp_account_set(&id, &session, &set_id);
        self.deps.records.record_account_choice("added", None);
        let user = &session["user"];
        self.deps.audit.audit(&json!({
            "action": "account.add",
            "actor": js::or_empty(user.get("username")),
            "protocol": "Authentication", "channel": "http", "target": id,
            "summary": format!("the browser's session for {} became the \
                first account of a new account set {}",
                cat(user.get("username")), set_id),
            "detail": {"accountSet": set_id, "sessionId": id,
                       "sub": js::or_empty(user.get("sub")),
                       "adopted": true},
        }));
        Some(row)
    }

    /// The cookies a door handed no response queued for the request's
    /// own, appended here where the door was handed it.
    fn drain_appended(request: &Request, response: &mut Response) {
        for line in request.accounts.take_appended() {
            response.append_cookie(line);
        }
    }

    /// `resolveAccount(req, create)`: which session a request acts as, in
    /// the plan's order — a ticket, a hint, the only live session, nobody.
    // A hot path: asked on every session read or sign-in; the door's
    // span covers it, no span of its own.
    pub(super) fn resolve_account(
        &self,
        request: Option<&Request>,
        create: bool,
    ) -> Resolved {
        let row = self.ensure_account_set(request, create);
        let (unread, ended, selected, hint) = match request {
            Some(r) => {
                let m = r.accounts.lock();
                (
                    m.set_unread,
                    m.selection_ended.clone(),
                    m.selection.clone(),
                    m.hint.clone(),
                )
            }
            None => (false, None, String::new(), None),
        };
        if row.is_none() && unread {
            return Resolved {
                reason: "unread".into(),
                ..Resolved::default()
            };
        }
        if row.is_none() {
            if let Some(e) = &ended {
                return Resolved {
                    reason: "hint-unmatched".into(),
                    hint: e.username.clone(),
                    ..Resolved::default()
                };
            }
            return Resolved {
                fallback: true,
                ..Resolved::default()
            };
        }
        let row_o = row.clone().unwrap_or_default();
        let live: Vec<String> = js::object_of(row_o.get("sessions"))
            .keys()
            .filter(|sid| self.account_session_live(sid))
            .cloned()
            .collect();
        if live.is_empty() {
            if let Some(e) = &ended {
                return Resolved {
                    reason: "hint-unmatched".into(),
                    row,
                    hint: e.username.clone(),
                    ..Resolved::default()
                };
            }
            return Resolved {
                fallback: true,
                row,
                ..Resolved::default()
            };
        }
        let n = live.len();
        if !selected.is_empty() && live.contains(&selected) {
            return Resolved {
                sid: selected,
                how: "ticket".into(),
                row,
                live: n,
                ..Resolved::default()
            };
        }
        if let Some(e) = &ended {
            let again = if e.username.is_empty() {
                String::new()
            } else {
                self.match_account_hint(
                    &live,
                    &AccountHint {
                        login_hint: e.username.clone(),
                        ..AccountHint::default()
                    },
                )
            };
            if !again.is_empty() {
                return Resolved {
                    sid: again,
                    how: "ticket".into(),
                    row,
                    live: n,
                    ..Resolved::default()
                };
            }
            return Resolved {
                reason: "hint-unmatched".into(),
                row,
                live: n,
                hint: e.username.clone(),
                ..Resolved::default()
            };
        }
        if let Some(h) = &hint {
            let found = self.match_account_hint(&live, h);
            if !found.is_empty() {
                return Resolved {
                    sid: found,
                    how: "hint".into(),
                    row,
                    live: n,
                    ..Resolved::default()
                };
            }
            if !h.soft {
                return Resolved {
                    reason: "hint-unmatched".into(),
                    row,
                    live: n,
                    hint: h.login_hint.clone(),
                    ..Resolved::default()
                };
            }
        }
        if n == 1 {
            return Resolved {
                sid: live[0].clone(),
                how: "only".into(),
                row,
                live: 1,
                ..Resolved::default()
            };
        }
        Resolved {
            reason: "ambiguous".into(),
            row,
            live: n,
            ..Resolved::default()
        }
    }

    /// `matchAccountHint(live, hint)`: by sid, then subject, then login
    /// name or e-mail (or the subject that name resolves to).
    fn match_account_hint(
        &self,
        live: &[String],
        hint: &AccountHint,
    ) -> String {
        if !hint.sid.is_empty() && live.contains(&hint.sid) {
            return hint.sid.clone();
        }
        let users: Vec<(String, Object)> = live
            .iter()
            .map(|sid| {
                let user = self
                    .account_session_read(sid)
                    .map(|s| js::object_of(s.get("user")))
                    .unwrap_or_default();
                (sid.clone(), user)
            })
            .collect();
        if !hint.sub.is_empty() {
            if let Some((sid, _)) = users
                .iter()
                .find(|(_, u)| js::or_empty(u.get("sub")) == hint.sub)
            {
                return sid.clone();
            }
        }
        let name = hint.login_hint.trim().to_lowercase();
        if !name.is_empty() {
            let subject = self.deps.people.subject_for_name(&hint.login_hint);
            if let Some((sid, _)) = users.iter().find(|(_, u)| {
                js::or_empty(u.get("username")).to_lowercase() == name
                    || js::or_empty(u.get("email")).to_lowercase() == name
                    || (!subject.is_empty()
                        && js::or_empty(u.get("sub")) == subject)
            }) {
                return sid.clone();
            }
        }
        String::new()
    }

    /// `accountChoiceNeeded(req)`: `{ reason, accounts, hint }` where
    /// `sessionOf()` answered nobody for a browser holding several
    /// accounts; `None` otherwise, and with the setting off.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn account_choice_needed(&self, request: &Request) -> Option<Value> {
        if !self.accounts.enabled() {
            return None;
        }
        let r = self.resolve_account(Some(request), true);
        if r.fallback || !r.sid.is_empty() {
            return None;
        }
        Some(json!({"reason": r.reason, "accounts": r.live, "hint": r.hint}))
    }

    /// `hintAccount(req, { loginHint, sub, sid, soft })`: before
    /// `sessionOf()`; `username` is read as `loginHint`, empty members
    /// ignored, a hint with none no hint.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn hint_account(&self, request: &Request, hint: &Value) {
        let mut login = js::or_empty(hint.get("loginHint"));
        if login.is_empty() {
            login = js::or_empty(hint.get("username"));
        }
        let h = AccountHint {
            login_hint: slice(&login, 512),
            sub: slice(&js::or_empty(hint.get("sub")), 512),
            sid: slice(&js::or_empty(hint.get("sid")), 128),
            soft: js::truthy(hint.get("soft")),
        };
        if !h.login_hint.is_empty() || !h.sub.is_empty() || !h.sid.is_empty() {
            request.accounts.lock().hint = Some(h);
        }
    }

    /// `hintAccountKey(req, key)`: an account KEY as the hint.
    #[tracing::instrument(level = "debug", skip(self, request))]
    pub fn hint_account_key(&self, request: &Request, key: &str) {
        if key.is_empty() {
            return;
        }
        match key.strip_prefix("name:") {
            Some(name) => {
                self.hint_account(request, &json!({"loginHint": name}))
            }
            None => self.hint_account(request, &json!({"sub": key})),
        }
    }

    // -------------------------------------------------------------------
    // The tickets.
    // -------------------------------------------------------------------

    /// `spendAccountTicket(req)`: the middleware every request passes. The
    /// ticket comes off `request.url` (the HTTP layer takes it off its own
    /// parsed query too) and is spent; it counts only for THIS browser's
    /// set, THIS path and a session still live there, or for the very
    /// session the request presents with no set; a ticket whose session
    /// ended in flight, or for this path from a set the request does not
    /// carry, chooses NOBODY (#731, batch 10); anything else is ignored
    /// (`STS-AUTHN-0346`).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn spend_account_ticket(&self, request: &mut Request) {
        if !self.accounts.enabled() {
            return;
        }
        let (url, ticket) = AccountSets::strip_ticket(&request.url);
        if ticket.is_empty() {
            return;
        }
        request.url = url;
        let row = self.accounts.spend_ticket(&ticket);
        let set = self.account_set_of(Some(request));
        let path = request.url.split('?').next().unwrap_or("").to_string();
        let unread = request.accounts.lock().set_unread;
        let field = |k: &str| {
            row.as_ref()
                .map(|r| js::string_of(r.get(k)))
                .unwrap_or_default()
        };
        if row.is_some() && set.is_none() && !unread && field("path") == path {
            if let Some((id, _)) =
                self.cookie_session(Some(request), SESSION_COOKIE)
            {
                if id == field("sid") && self.account_session_live(&id) {
                    request.accounts.lock().selection = id;
                    return;
                }
            }
        }
        let set_id = set
            .as_ref()
            .map(|s| js::string_of(s.get("id")))
            .unwrap_or_default();
        let why = if row.is_none() {
            "it is unknown, spent or expired"
        } else if set.is_none() || set_id != field("setId") {
            "it was issued to another browser"
        } else if field("path") != path {
            "it was issued for another address"
        } else if !set.as_ref().is_some_and(|s| {
            js::truthy(s.get("sessions").and_then(|x| x.get(field("sid"))))
        }) || !self.account_session_live(&field("sid"))
        {
            "the session it names is no longer live in this browser"
        } else {
            ""
        };
        if why.is_empty() {
            request.accounts.lock().selection = field("sid");
            return;
        }
        let ended = row.is_some()
            && set.is_some()
            && set_id == field("setId")
            && field("path") == path;
        {
            let mut marks = request.accounts.lock();
            if ended {
                marks.selection_ended = Some(EndedSelection {
                    username: row
                        .as_ref()
                        .map(|r| js::or_empty(r.get("username")))
                        .unwrap_or_default(),
                    sid: field("sid"),
                });
            }
            if !ended && row.is_some() && field("path") == path {
                marks.selection_ended = Some(EndedSelection::default());
            }
        }
        tracing::info!(
            "{}authn: an account selection ticket on {} was ignored: {}{}.",
            tag(codes::STS_AUTHN_0346.as_str()),
            path,
            why,
            if ended {
                "; the request acts as nobody, and the flow signs in again \
                 as that account"
            } else {
                ""
            }
        );
    }

    /// `ticketedReturn(res, record, target)`: the address a finished
    /// sign-in returns to, with a ticket for the session it put in a set
    /// (`res.locals`, from the enrolment). `returnToCaller()` asks it.
    #[tracing::instrument(level = "debug", skip(self, response))]
    pub fn ticketed_return(
        &self,
        response: &Response,
        record_id: &str,
        target: &str,
    ) -> String {
        let session = js::or_empty(response.locals.get("stsAccountSession"));
        let set = js::or_empty(response.locals.get("stsAccountSet"));
        if !self.accounts.enabled() || session.is_empty() || set.is_empty() {
            return target.to_string();
        }
        let path = target.split('?').next().unwrap_or("");
        let ticket = self.accounts.mint_ticket(&set, &session, path, record_id);
        AccountSets::with_ticket(target, &ticket)
    }

    /// `accountTicketFor(req, target, hint)`: `target` with a ticket for
    /// the live account `hint` names in this browser's set; unchanged
    /// otherwise. The consent screen and federation's ACS call it.
    #[tracing::instrument(level = "debug", skip(self, request, hint))]
    pub fn account_ticket_for(
        &self,
        request: &Request,
        target: &str,
        hint: &Value,
    ) -> String {
        if !self.accounts.enabled() {
            return target.to_string();
        }
        let prior = request.accounts.lock().hint.clone();
        self.hint_account(request, hint);
        let resolved = self.resolve_account(Some(request), false);
        request.accounts.lock().hint = prior;
        let Some(row) = resolved.row.filter(|_| !resolved.fallback) else {
            return target.to_string();
        };
        if resolved.sid.is_empty() {
            return target.to_string();
        }
        let path = target.split('?').next().unwrap_or("");
        let ticket = self.accounts.mint_ticket(
            &js::string_of(row.get("id")),
            &resolved.sid,
            path,
            "",
        );
        AccountSets::with_ticket(target, &ticket)
    }

    // -------------------------------------------------------------------
    // A sign-in, and a session's end.
    // -------------------------------------------------------------------

    /// `liveAccountCount(row, defaultFound)`: the set's live sessions, and
    /// the default cookie's where it is live and not in the set yet.
    // A hot path: asked on every session read or sign-in; the door's
    // span covers it, no span of its own.
    pub(super) fn live_account_count(
        &self,
        row: Option<&Object>,
        default_found: Option<&(String, Value)>,
    ) -> usize {
        let mut n = row
            .map(|r| {
                js::object_of(r.get("sessions"))
                    .keys()
                    .filter(|sid| self.account_session_kept(sid))
                    .count()
            })
            .unwrap_or(0);
        if let Some((id, session)) = default_found {
            let listed = row.is_some_and(|r| {
                js::truthy(r.get("sessions").and_then(|s| s.get(id)))
            });
            if Self::account_eligible(session)
                && self.account_session_live(id)
                && !listed
            {
                n += 1;
            }
        }
        n
    }

    /// `accountSessionFor(row, username)`: the live session of this
    /// person in the browser's set, which a second sign-in as them
    /// re-authenticates.
    // A hot path: asked on every session read or sign-in; the door's
    // span covers it, no span of its own.
    pub(super) fn account_session_for(
        &self,
        row: Option<&Object>,
        username: &str,
    ) -> Option<(String, Value)> {
        let row = row?;
        let sid = js::object_of(row.get("sessions"))
            .keys()
            .find(|sid| {
                self.account_session_live(sid)
                    && self.account_session_read(sid).is_some_and(|s| {
                        self.same_identity(&s["user"], username)
                    })
            })
            .cloned()?;
        let session = self.account_session_read(&sid)?;
        Some((sid, session))
    }

    /// `enrolInAccountSet(req, res, session, defaultFound)`: after the
    /// session cookie (written by replacing), the session joins the set —
    /// the previous default first where it is live and not there (D12),
    /// ended members moved to remembered, the handle rotated and the set's
    /// cookie APPENDED; `res.locals` then names the session and the set.
    /// `session` is the row in hand, stamped here.
    // A hot path: asked on every session read or sign-in; the door's
    // span covers it, no span of its own.
    pub(super) fn enrol_in_account_set(
        &self,
        request: Option<&Request>,
        response: &mut Response,
        session: &mut Object,
        default_found: Option<&(String, Value)>,
    ) {
        let sid = js::string_of(session.get("id"));
        let mut row = self
            .account_set_of(request)
            .unwrap_or_else(|| self.accounts.fresh());
        let set_id = js::string_of(row.get("id"));
        if let Some((did, dsession)) = default_found {
            let listed =
                js::truthy(row.get("sessions").and_then(|s| s.get(did)));
            if *did != sid
                && Self::account_eligible(dsession)
                && self.account_session_live(did)
                && !listed
            {
                self.accounts.add_session(
                    &mut row,
                    did,
                    &Self::account_of(dsession),
                );
                self.stamp_account_set(did, dsession, &set_id);
            }
        }
        self.accounts.prune(
            &mut row,
            &mut |one| one == sid || self.account_session_kept(one),
            None,
        );
        let added = !js::truthy(row.get("sessions").and_then(|s| s.get(&sid)));
        let held = Value::Object(session.clone());
        let (done, dropped) =
            self.accounts
                .add_session(&mut row, &sid, &Self::account_of(&held));
        if !done {
            tracing::warn!(
                "{}authn: session {} could not join its browser's account \
                 set, which is full; it is the browser's session alone.",
                tag(codes::STS_AUTHN_0340.as_str()),
                sid
            );
            return;
        }
        let value = self.accounts.rotate(&mut row);
        self.accounts.save(&mut row);
        self.accounts.write_cookie(response, &value);
        if let Some(r) = request {
            r.accounts.lock().set_id = set_id.clone();
        }
        if session.get("accountSetId") != Some(&json!(set_id)) {
            session.insert("accountSetId".into(), json!(set_id));
            self.here().set(&sid, Value::Object(session.clone()));
        }
        response
            .locals
            .insert("stsAccountSession".into(), json!(sid));
        response
            .locals
            .insert("stsAccountSet".into(), json!(set_id));
        if added {
            self.deps.records.record_account_choice("added", None);
            let user = js::object_of(session.get("user"));
            let n = js::object_of(row.get("sessions")).len();
            let via = match js::or_empty(session.get("via")) {
                v if v.is_empty() => "Authentication".to_string(),
                v => v,
            };
            self.deps.audit.audit(&json!({
                "action": "account.add",
                "actor": js::or_empty(user.get("username")),
                "protocol": via, "channel": "http", "target": sid,
                "summary": format!("{} was added to account set {} ({} \
                    signed in)", cat(user.get("username")), set_id, n),
                "detail": {"accountSet": set_id, "sessionId": sid,
                           "sub": js::or_empty(user.get("sub")),
                           "signedIn": n, "droppedRemembered": dropped},
            }));
        }
    }

    /// `accountSessionEnded(session)`: a session that ended, however,
    /// moves to its set's remembered accounts, found by the stamped id.
    // A hot path: asked on every session read or sign-in; the door's
    // span covers it, no span of its own.
    pub(super) fn account_session_ended(&self, session: Option<&Value>) {
        let Some(s) = session else {
            return;
        };
        let set_id = js::or_empty(s.get("accountSetId"));
        if set_id.is_empty() {
            return;
        }
        if let Some(mut row) = self.accounts.by_id(&set_id) {
            let sid = js::string_of(s.get("id"));
            if self
                .accounts
                .end_session(&mut row, &sid, f64::NAN)
                .is_some()
            {
                self.accounts.save(&mut row);
            }
        }
    }

    /// `makeDefaultSession(res, session)` / `appendDefaultSession()`: a
    /// fresh handle, the OP browser state KEPT (#121: becoming the default
    /// is not a sign-in), the cookie written by replacing or appended.
    fn make_default_session(
        &self,
        response: &mut Response,
        session: &Value,
        append: bool,
    ) -> Value {
        let mut s = obj(session);
        let state = s.get("browserState").cloned();
        let value = self.mint(&mut s);
        if let Some(state) = state.filter(|v| js::truthy(Some(v))) {
            s.insert("browserState".into(), state);
        }
        let id = js::string_of(s.get("id"));
        self.here().set(&id, Value::Object(s.clone()));
        let line = self.cookie_line(SESSION_COOKIE, &value);
        if append {
            response.append_cookie(line);
        } else {
            response.set_cookie(line);
        }
        Value::Object(s)
    }

    // -------------------------------------------------------------------
    // What a browser holds.
    // -------------------------------------------------------------------

    fn live_in_order(&self, row: &Object) -> Vec<String> {
        let sessions = js::object_of(row.get("sessions"));
        let mut live: Vec<String> = sessions
            .keys()
            .filter(|sid| self.account_session_live(sid))
            .cloned()
            .collect();
        live.sort_by(|a, b| {
            let x = js::number_or_zero(sessions[a].get("addedAt"));
            let y = js::number_or_zero(sessions[b].get("addedAt"));
            x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal)
        });
        live
    }

    /// `accountRows(row, req)`: live accounts first, in the order they
    /// signed in; then the signed-out ones, the latest first. Never a sid.
    fn account_rows(
        &self,
        row: Option<&Object>,
        request: &Request,
    ) -> Vec<Value> {
        let Some(row) = row else {
            return Vec::new();
        };
        let own = self.cookie_session(Some(request), SESSION_COOKIE);
        let sessions = js::object_of(row.get("sessions"));
        let mut out: Vec<Value> = Vec::new();
        for sid in self.live_in_order(row) {
            let session = self.account_session_read(&sid).unwrap_or_default();
            let account = Self::account_of(&session);
            let mut display = account["displayName"].clone();
            if !js::truthy(Some(&display)) {
                display = sessions[&sid]
                    .get("displayName")
                    .cloned()
                    .unwrap_or(Value::Null);
            }
            let mut one = Object::new();
            one.insert("key".into(), json!(AccountSets::key_of(&account)));
            one.insert("sub".into(), account["sub"].clone());
            one.insert("username".into(), account["username"].clone());
            if !display.is_null() {
                one.insert("displayName".into(), display);
            }
            one.insert("state".into(), json!("signed-in"));
            one.insert(
                "signedInAt".into(),
                json!(self.session_started_at(&session)),
            );
            one.insert(
                "authTime".into(),
                json!(record::view(session.as_object()).auth_time),
            );
            one.insert(
                "current".into(),
                json!(own.as_ref().is_some_and(|o| o.0 == sid)),
            );
            out.push(Value::Object(one));
        }
        let mut remembered: Vec<Value> = js::object_of(row.get("remembered"))
            .iter()
            .map(|(key, e)| {
                let display = match js::or_empty(e.get("displayName")) {
                    d if d.is_empty() => js::or_empty(e.get("username")),
                    d => d,
                };
                json!({"key": key, "sub": js::or_empty(e.get("sub")),
                       "username": js::or_empty(e.get("username")),
                       "displayName": display, "state": "signed-out",
                       "signedOutAt": js::num(js::number_or_zero(
                           e.get("signedOutAt"))),
                       "current": false})
            })
            .collect();
        remembered.sort_by(|a, b| {
            let x = js::number_or_zero(a.get("signedOutAt"));
            let y = js::number_or_zero(b.get("signedOutAt"));
            y.partial_cmp(&x).unwrap_or(std::cmp::Ordering::Equal)
        });
        out.extend(remembered);
        out
    }

    /// `freshAccountSet(req)`: the set brought up to date for a page.
    fn fresh_account_set(&self, request: &Request) -> Option<Object> {
        let mut row = self.ensure_account_set(Some(request), true)?;
        let (ended, expired) = self.accounts.prune(
            &mut row,
            &mut |sid| self.account_session_kept(sid),
            None,
        );
        if ended > 0 || expired > 0 {
            self.accounts.save(&mut row);
        }
        Some(row)
    }

    /// `browserAccounts(req)`, for `GET /authn-api/accounts`: `{ enabled,
    /// accounts, max }`, each account `{ key, sub, username, displayName,
    /// state, signedInAt, authTime, signedOutAt, current }` — never a sid.
    /// A set D12 makes is queued on the request (`appended`).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn browser_accounts(&self, request: &Request) -> Value {
        if !self.accounts.enabled() {
            return json!({"enabled": false, "accounts": [], "max": 0});
        }
        let row = self.fresh_account_set(request);
        json!({"enabled": true,
               "accounts": self.account_rows(row.as_ref(), request),
               "max": js::num(self.accounts.max_accounts())})
    }

    /// `accountSessionsOf(req)`: the live session rows of the browser's
    /// set, in the order they joined it; [] off.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn account_sessions_of(&self, request: &Request) -> Vec<Value> {
        if !self.accounts.enabled() {
            return Vec::new();
        }
        let Some(row) = self.account_set_of(Some(request)) else {
            return Vec::new();
        };
        self.live_in_order(&row)
            .iter()
            .filter_map(|sid| self.account_session_read(sid))
            .collect()
    }

    /// `signedInAccounts(req)`: `{ key, sub, username, displayName,
    /// current, sid }` — `sid` for the server's own use, never drawn.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn signed_in_accounts(&self, request: &Request) -> Vec<Value> {
        let found = self.cookie_session(Some(request), SESSION_COOKIE);
        self.account_sessions_of(request)
            .iter()
            .map(|session| {
                let a = Self::account_of(session);
                let id = js::string_of(session.get("id"));
                let display = match js::or_empty(a.get("displayName")) {
                    d if d.is_empty() => js::or_empty(a.get("username")),
                    d => d,
                };
                json!({"key": AccountSets::key_of(&a), "sub": a["sub"],
                       "username": a["username"], "displayName": display,
                       "current": found.as_ref().is_some_and(|f| f.0 == id),
                       "sid": id})
            })
            .collect()
    }

    /// `bindingSessionOf(req, pick)` (#725 with #561): the live session a
    /// device-binding request's own proof names, held to
    /// `honouredSession()` but the binding gate; `{ session, others }`, or
    /// `None` off or with no set.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn binding_session_of(
        &self,
        request: &Request,
        pick: &dyn Fn(&Value) -> bool,
    ) -> Option<Value> {
        if !self.accounts.enabled() {
            return None;
        }
        let row = self.account_set_of(Some(request))?;
        let mut sids: Vec<String> =
            js::object_of(row.get("sessions")).keys().cloned().collect();
        if let Some((own, _)) =
            self.cookie_session(Some(request), SESSION_COOKIE)
        {
            if !sids.contains(&own) {
                sids.push(own);
            }
        }
        let live: Vec<String> = sids
            .into_iter()
            .filter(|sid| self.account_session_live(sid))
            .collect();
        let sid = live.iter().find(|one| {
            self.account_session_read(one).is_some_and(|s| pick(&s))
        });
        let session = sid.and_then(|sid| {
            let held = self.account_session_read(sid)?;
            self.honoured_session(request, sid, held, true)
        });
        let others = session.is_none() && !live.is_empty();
        Some(json!({"session": session, "others": others}))
    }

    /// `sessionCookieNames(req, sid)`: whether `sts_session` names it.
    #[tracing::instrument(level = "debug", skip(self, request))]
    pub fn session_cookie_names(&self, request: &Request, sid: &str) -> bool {
        self.cookie_session(Some(request), SESSION_COOKIE)
            .is_some_and(|f| f.0 == sid)
    }

    /// `auditActorSessionOf(req)`: the sid the request acted as, resolved
    /// with nothing made; '' with the setting off.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn audit_actor_session_of(&self, request: &Request) -> String {
        if !self.accounts.enabled() {
            return String::new();
        }
        let r = self.resolve_account(Some(request), false);
        if !r.fallback {
            return r.sid;
        }
        self.cookie_session(Some(request), SESSION_COOKIE)
            .map(|f| f.0)
            .unwrap_or_default()
    }

    /// `auditActorOf(req)`: the person a request's cookie belongs to, for
    /// the audit log, even where the session expired; with several
    /// accounts, the one the request acted as, '' where it could not tell.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn audit_actor_of(&self, request: &Request) -> String {
        if self.accounts.enabled() {
            let r = self.resolve_account(Some(request), false);
            if !r.fallback {
                return self
                    .account_session_read(&r.sid)
                    .map(|s| js::or_empty(s["user"].get("username")))
                    .unwrap_or_default();
            }
        }
        self.cookie_session(Some(request), SESSION_COOKIE)
            .map(|f| js::string_of(f.1["user"].get("username")))
            .unwrap_or_default()
    }

    /// `noteAccountAmbiguous(req, via, answer)`: the `account.ambiguous`
    /// row and counter, for a protocol that refuses rather than showing
    /// the picker (`account_selection_required`, `NoPassive`).
    #[tracing::instrument(level = "debug", skip(self, request))]
    pub fn note_account_ambiguous(
        &self,
        request: &Request,
        via: &str,
        answer: &str,
    ) {
        let row = self.account_set_of(Some(request));
        self.deps.records.record_account_choice("ambiguous", None);
        let id = row
            .as_ref()
            .map(|r| js::string_of(r.get("id")))
            .unwrap_or_default();
        let n = row
            .as_ref()
            .map(|r| js::object_of(r.get("sessions")).len())
            .unwrap_or(0);
        self.deps.audit.audit(&json!({
            "action": "account.ambiguous", "actor": "", "protocol": via,
            "channel": "http", "target": id,
            "summary": format!("a request from a browser with several \
                signed-in accounts named none of them; {}",
                if answer.is_empty() { "the account picker was shown" }
                else { answer }),
            "detail": {"accountSet": id, "signedIn": n},
        }));
    }

    // -------------------------------------------------------------------
    // The clean-up job.
    // -------------------------------------------------------------------

    /// `sweepAccountSets()`: every set of the ambient realm pruned, an
    /// empty one deleted; `{ sets, ended, expired, deleted }`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn sweep_account_sets(&self) -> Value {
        let done = self
            .accounts
            .sweep(&mut |sid| self.account_session_kept(sid));
        if done.expired > 0 {
            self.deps
                .records
                .record_account_choice("expired", Some(done.expired));
        }
        done.plain()
    }

    /// `sweepAccountSetsBudgeted()` (#784): one run of
    /// `authn.account-set-expiry`, about a second's work from where the
    /// last run stopped.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn sweep_account_sets_budgeted(&self) -> Value {
        let done = self
            .accounts
            .sweep_budgeted(&mut |sid| self.account_session_kept(sid), None)
            .await;
        if done.expired > 0 {
            self.deps
                .records
                .record_account_choice("expired", Some(done.expired));
        }
        done.budgeted()
    }

    // -------------------------------------------------------------------
    // Signing one out, or all.
    // -------------------------------------------------------------------

    /// `endSession(req, res, sid)`: with the setting on, `sid` may name a
    /// session of THIS browser's set (the set's cookie proves the browser
    /// holds it; a bare sid never does) to end instead of the cookie's;
    /// then [`Sessions::after_account_sign_out`]. Off, `sid` is ignored.
    #[tracing::instrument(level = "debug", skip(self, request, response))]
    pub fn end_session_for(
        &self,
        request: &Request,
        response: &mut Response,
        sid: &str,
    ) -> Option<Value> {
        if !self.accounts.enabled() {
            return self.end_session_alone(request, response);
        }
        let row = if sid.is_empty() {
            None
        } else {
            self.account_set_of(Some(request))
        };
        let in_set = row.as_ref().is_some_and(|r| {
            js::truthy(r.get("sessions").and_then(|s| s.get(sid)))
        }) && self.account_session_live(sid);
        let id = if in_set {
            sid.to_string()
        } else {
            self.cookie_session(Some(request), SESSION_COOKIE)
                .map(|f| f.0)
                .unwrap_or_default()
        };
        let presented = in_set
            || !cookie::cookie_value(&request.cookie, SESSION_COOKIE)
                .is_empty();
        let session = self.drop_session(
            &id,
            "the sign-out endpoint for this browser",
            presented,
            Some(request),
            "user",
        );
        self.after_account_sign_out(request, response);
        session
    }

    /// `afterAccountSignOut(req, res)`: with the browser's default session
    /// ended, its cookie cleared and the most recently added live account
    /// made the default (APPENDED after the clear); Session Management's
    /// state list written again. `{ defaultEnded, defaultNow }`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn after_account_sign_out(
        &self,
        request: &Request,
        response: &mut Response,
    ) -> Value {
        if !self.accounts.enabled() {
            return json!({"defaultEnded": false, "defaultNow": ""});
        }
        let found = self.cookie_session(Some(request), SESSION_COOKIE);
        let default_live = found
            .as_ref()
            .is_some_and(|f| self.account_session_live(&f.0));
        let live = self.account_sessions_of(request);
        let mut now = if default_live {
            found.map(|f| f.0).unwrap_or_default()
        } else {
            String::new()
        };
        if !default_live {
            self.clear_session_cookie(response, "");
            if let Some(next) = live.last() {
                self.make_default_session(response, next, true);
                now = js::string_of(next.get("id"));
            }
        }
        if let Some(sm) = &self.deps.session_management {
            if sm.enabled() {
                let value = sm.browser_states_value(&live);
                sm.write_cookie(response, &value);
            }
        }
        json!({"defaultEnded": !default_live, "defaultNow": now})
    }

    /// `clearSiteDataAfterSignOut(req, res)` (#1440): whether the answer
    /// carries `Clear-Site-Data: "storage"` — only where no account is
    /// signed in here and the browser holds no other realm's set.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn clear_site_data_after_sign_out(&self, request: &Request) -> bool {
        let own = self.accounts.cookie_name();
        let elsewhere = request.cookie.split(';').any(|part| {
            let name = part.trim().split('=').next().unwrap_or("");
            let theirs =
                name == "sts_accounts" || name.starts_with("sts_accounts_");
            theirs && name != own
        });
        !elsewhere && self.signed_in_accounts(request).is_empty()
    }

    // -------------------------------------------------------------------
    // The account picker (FR-3, FR-4): its data and acts.
    // -------------------------------------------------------------------

    /// `refuseAccountsUnread(req, res)`: a set that could not be read is a
    /// 503 with `Retry-After: 5` at the picker, never a picker drawn from
    /// what could be read. `None` where it is readable.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn refuse_accounts_unread(
        &self,
        request: &Request,
    ) -> Option<PickerAnswer> {
        if !self.accounts.enabled() {
            return None;
        }
        let row = self.account_set_of(Some(request));
        if row.is_some() || !request.accounts.lock().set_unread {
            return None;
        }
        let code = codes::STS_AUTHN_0344.as_str();
        tracing::debug!(
            "{}authn: the account picker answered 503: this browser's \
             account set could not be read.",
            tag(code)
        );
        Some(PickerAnswer {
            status: 503,
            code: Some(code),
            body: json!({
                "ok": false, "error": "unavailable",
                "error_description": "This browser's accounts could not be \
                    read. Try again.",
                "errors": ["This browser's accounts could not be read just \
                    now. Try again in a moment."],
            }),
            retry_after: true,
        })
    }

    /// `accountsView(req, record)`: the picker's view for a pending
    /// sign-in — the accounts, whether Use another account is open, the
    /// protocol's rows. `base` is `baseUrlOf(req)`, the caller's.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn accounts_view(
        &self,
        request: &Request,
        record: &Value,
        base: &str,
    ) -> Value {
        let row = self.fresh_account_set(request);
        let accounts = self.account_rows(row.as_ref(), request);
        let live = accounts
            .iter()
            .filter(|a| a["state"] == json!("signed-in"))
            .count();
        let max = self.accounts.max_accounts();
        let details: Vec<Value> = match record.get("details") {
            Some(Value::Array(d)) => d
                .iter()
                .map(|d| {
                    let value = match d.get("value") {
                        None | Some(Value::Null) => String::new(),
                        Some(v) => js::text(v),
                    };
                    json!({"label": js::or_empty(d.get("label")),
                           "value": value,
                           "note": js::or_empty(d.get("note"))})
                })
                .collect(),
            _ => Vec::new(),
        };
        json!({
            "id": js::string_of(record.get("id")),
            "base": base,
            "protocol": js::or_empty(record.get("protocol")),
            "application": js::or_empty(record.get("application")),
            "reason": js::or_empty(record.get("accountChoiceReason")),
            "accounts": accounts,
            "another": {"open": (live as f64) < max},
            "max": js::num(max),
            "details": details,
        })
    }

    /// `onToSignIn(res, record, hint)`: on to the sign-in the picker stood
    /// in front of, the hint filled in (or cleared); a picker-only record
    /// is spent.
    fn on_to_sign_in(
        record: &Value,
        hint: &str,
        location_of: &dyn Fn(&str) -> String,
    ) -> ActOutcome {
        let after = match js::or_empty(record.get("afterAccounts")) {
            a if a.is_empty() => format!(
                "{}?authn={}",
                LOGIN_PATH,
                encode_uri_component(&js::string_of(record.get("id")))
            ),
            a => a,
        };
        let change = if js::truthy(record.get("accountsOnly")) {
            RecordChange::Delete(js::string_of(record.get("id")))
        } else {
            let mut r = obj(record);
            r.insert("accountChoice".into(), json!(false));
            r.insert("hint".into(), json!(hint));
            RecordChange::Set(r)
        };
        ActOutcome {
            answer: ok(json!({"ok": true, "next": "redirect",
                              "location": location_of(&after)})),
            record: change,
        }
    }

    /// `accountsAct(req, res, record, { action, account })`: `select`
    /// continues the flow as a signed-in account (or signs a signed-out
    /// one in again), `another` goes on to the sign-in for a new account,
    /// `forget` forgets a signed-out account. The cookies go on
    /// `response`; the answer and the pending record's change are for
    /// `/authn-api` to send and store. `location_of` is `locationOf()`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn accounts_act(
        &self,
        request: &Request,
        response: &mut Response,
        record: &Value,
        body: &Value,
        location_of: &dyn Fn(&str) -> String,
    ) -> ActOutcome {
        let keep = |answer| ActOutcome {
            answer,
            record: RecordChange::Keep,
        };
        if let Some(a) = self.refuse_accounts_unread(request) {
            return keep(a);
        }
        let name = self.accounts.cookie_name();
        if !cookie::cookie_value(&request.cookie, &name).is_empty()
            && self.account_set_of(Some(request)).is_none()
        {
            self.deps
                .records
                .record_account_choice("selectFailed", None);
            tracing::info!(
                "{}authn: an act at the account picker carried an account \
                 set cookie that opens no set — another selection rotated \
                 it — and was refused.",
                tag(codes::STS_AUTHN_0348.as_str())
            );
            return keep(refused(
                409,
                codes::STS_AUTHN_0348.as_str(),
                "The accounts in this browser changed in another tab. \
                 Choose again."
                    .into(),
            ));
        }
        let row = self.fresh_account_set(request);
        Self::drain_appended(request, response);
        let key = js::or_empty(body.get("account"));
        let action = js::string_of(body.get("action"));
        let live_sid = row
            .as_ref()
            .and_then(|r| {
                js::object_of(r.get("sessions"))
                    .iter()
                    .find(|(sid, e)| {
                        AccountSets::key_of(e) == key
                            && self.account_session_live(sid)
                    })
                    .map(|(sid, _)| sid.clone())
            })
            .unwrap_or_default();
        let max = self.accounts.max_accounts();
        if action == "another" {
            let live = self.live_account_count(row.as_ref(), None);
            if live as f64 >= max {
                return keep(refused(
                    409,
                    codes::STS_AUTHN_0340.as_str(),
                    format!(
                        "This browser is already signed in to {} accounts, \
                         the most it may hold. Sign out of one of them first.",
                        live
                    ),
                ));
            }
            return Self::on_to_sign_in(record, "", location_of);
        }
        if action == "forget" {
            if !live_sid.is_empty() {
                return keep(refused(
                    409,
                    codes::STS_AUTHN_0347.as_str(),
                    "That account is still signed in. Sign it out first; \
                     only a signed-out account can be forgotten."
                        .into(),
                ));
            }
            let entry = row
                .as_ref()
                .and_then(|r| r.get("remembered").and_then(|m| m.get(&key)))
                .filter(|e| js::truthy(Some(e)))
                .cloned();
            let Some(mut row) = row else {
                return keep(Self::not_remembered());
            };
            if !self.accounts.forget(&mut row, &key) {
                return keep(Self::not_remembered());
            }
            self.accounts.save(&mut row);
            self.deps.records.record_account_choice("forgotten", None);
            let username = entry
                .as_ref()
                .map(|e| js::or_empty(e.get("username")))
                .unwrap_or_default();
            let id = js::string_of(row.get("id"));
            self.deps.audit.audit(&json!({
                "action": "account.forget", "actor": username,
                "protocol": "Authentication", "channel": "http",
                "target": id,
                "summary": format!("{} was forgotten by account set {}",
                    if username.is_empty() { "an account" }
                    else { &username }, id),
                "detail": {"accountSet": id,
                           "sub": entry.as_ref()
                               .map(|e| js::or_empty(e.get("sub")))
                               .unwrap_or_default(),
                           "sessionId": ""},
            }));
            return keep(ok(json!({"ok": true, "next": "stay"})));
        }
        if live_sid.is_empty() {
            let remembered = row
                .as_ref()
                .and_then(|r| r.get("remembered").and_then(|m| m.get(&key)))
                .filter(|e| js::truthy(Some(e)))
                .cloned();
            if let Some(e) = remembered {
                return Self::on_to_sign_in(
                    record,
                    &js::or_empty(e.get("username")),
                    location_of,
                );
            }
            self.deps
                .records
                .record_account_choice("selectFailed", None);
            return keep(refused(
                409,
                codes::STS_AUTHN_0345.as_str(),
                "That account is no longer signed in here. Choose it again \
                 to sign in, or choose another."
                    .into(),
            ));
        }
        let held = self.account_session_read(&live_sid);
        let session = held
            .and_then(|h| self.honoured_session(request, &live_sid, h, false));
        let Some(session) = session else {
            self.deps
                .records
                .record_account_choice("selectFailed", None);
            return keep(refused(
                409,
                codes::STS_AUTHN_0345.as_str(),
                "That account's session has just ended. Choose it again to \
                 sign in, or choose another."
                    .into(),
            ));
        };
        let user = js::object_of(session.get("user"));
        if js::truthy(record.get("forceMfa"))
            && js::or_empty(session.get("acr")) != "mfa"
        {
            return Self::on_to_sign_in(
                record,
                &js::or_empty(user.get("username")),
                location_of,
            );
        }
        let before = self.cookie_session(Some(request), SESSION_COOKIE);
        let switched = before.as_ref().is_none_or(|b| b.0 != live_sid);
        if switched {
            self.make_default_session(response, &session, false);
        }
        let mut row = row.unwrap_or_default();
        row.insert("lastActiveSid".into(), json!(live_sid));
        let rotated = self.accounts.rotate(&mut row);
        self.accounts.save(&mut row);
        self.accounts.write_cookie(response, &rotated);
        let set_id = js::string_of(row.get("id"));
        request.accounts.lock().set_id = set_id.clone();
        self.deps.records.record_account_choice("selected", None);
        let protocol = js::or_empty(record.get("protocol"));
        let detail = json!({"accountSet": set_id, "sessionId": live_sid,
            "sub": js::or_empty(user.get("sub")), "protocol": protocol,
            "application": js::or_empty(record.get("application"))});
        let username = js::or_empty(user.get("username"));
        self.deps.audit.audit(&json!({
            "action": "account.select", "actor": username,
            "protocol": protocol, "channel": "http", "target": live_sid,
            "summary": format!("{} was chosen at the account picker of \
                account set {}", cat(user.get("username")), set_id),
            "detail": detail,
        }));
        if switched {
            self.deps.records.record_account_choice("switched", None);
            let mut more = obj(&detail);
            more.insert(
                "previousSessionId".into(),
                json!(before.map(|b| b.0).unwrap_or_default()),
            );
            self.deps.audit.audit(&json!({
                "action": "account.switch", "actor": username,
                "protocol": protocol, "channel": "http", "target": live_sid,
                "summary": format!("the browser's default account became {}",
                    cat(user.get("username"))),
                "detail": more,
            }));
        }
        // resumeAs(): the record spent, a ticket for this session.
        let return_to = js::string_of(record.get("returnTo"));
        let path = return_to.split('?').next().unwrap_or("");
        let record_id = js::string_of(record.get("id"));
        let ticket = self
            .accounts
            .mint_ticket(&set_id, &live_sid, path, &record_id);
        let target = AccountSets::with_ticket(&return_to, &ticket);
        ActOutcome {
            answer: ok(json!({"ok": true, "next": "redirect",
                              "location": location_of(&target)})),
            record: RecordChange::Delete(record_id),
        }
    }

    fn not_remembered() -> PickerAnswer {
        refused(
            409,
            codes::STS_AUTHN_0345.as_str(),
            "That account is not one this browser remembers.".into(),
        )
    }

    // -------------------------------------------------------------------
    // beginAuthentication()'s account half.
    // -------------------------------------------------------------------

    /// The decision `beginAuthentication()` makes before its old body
    /// (`beginAuthenticationHere()`, the sign-in's): `account_choice` is
    /// `always` (select_account), `never` (a fresh sign-in) or ''; `hinted`
    /// is whether `opts.hint` or `opts.lockedUsername` is set. `None` with
    /// the setting off, when the old body is the whole of it.
    #[tracing::instrument(level = "debug", skip(self, request))]
    pub fn begin_account_choice(
        &self,
        request: Option<&Request>,
        account_choice: &str,
        hinted: bool,
    ) -> Option<BeginChoice> {
        if !self.accounts.enabled() {
            return None;
        }
        let mut pick = String::new();
        let mut unmatched = String::new();
        if let Some(r) = request.filter(|_| account_choice != "never") {
            if account_choice == "always" {
                let row = self.fresh_account_set(r);
                pick = if row.as_ref().is_some_and(|x| AccountSets::size(x) > 0)
                {
                    "select_account".into()
                } else if r.accounts.lock().set_unread {
                    "unread".into()
                } else {
                    String::new()
                };
            } else if let Some(need) = self.account_choice_needed(r) {
                match need["reason"].as_str().unwrap_or("") {
                    "ambiguous" => pick = "ambiguous".into(),
                    "unread" => pick = "unread".into(),
                    "hint-unmatched" => {
                        unmatched = js::or_empty(need.get("hint"));
                        tracing::info!(
                            "{}authn: a hint named an account with no live \
                             session in this browser; the person is sent \
                             to sign in rather than given another account.",
                            tag(codes::STS_AUTHN_0341.as_str())
                        );
                    }
                    _ => {}
                }
            }
        }
        let mut hint = None;
        if let Some(r) = request.filter(|_| account_choice != "never") {
            if !hinted {
                let resolved = self.resolve_account(Some(r), false);
                let chosen = self
                    .account_session_read(&resolved.sid)
                    .map(|s| js::or_empty(s["user"].get("username")))
                    .unwrap_or_default();
                if !chosen.is_empty() {
                    hint = Some(chosen);
                } else if !unmatched.is_empty() {
                    hint = Some(unmatched);
                }
            }
        }
        Some(BeginChoice { pick, hint })
    }

    /// `routeToAccounts(opts, target, why, req)`: the picker's record —
    /// the sign-in's own (`existing`, the record `target`'s `authn=` names,
    /// [`pending_id_in`]) marked `accountChoice` and given
    /// `afterAccounts`, or one of its own, `accountsOnly`. Answers the
    /// record for the pending store to set, and the picker's address.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn route_to_accounts(
        &self,
        existing: Option<Object>,
        opts: &Value,
        target: &str,
        why: &str,
        request: Option<&Request>,
    ) -> (Object, String) {
        let mut record = match existing {
            Some(r) => r,
            None => {
                let protocol = match js::or_empty(opts.get("protocol")) {
                    p if p.is_empty() => "OAuth 2.0 / OIDC".to_string(),
                    p => p,
                };
                let details = match opts.get("details") {
                    Some(Value::Array(d)) => Value::Array(d.clone()),
                    _ => json!([]),
                };
                obj(&json!({
                    "id": self.deps.clock.random_id(18),
                    "accountsOnly": true,
                    "returnTo": js::or_empty(opts.get("returnTo")),
                    "details": details, "hint": "", "protocol": protocol,
                    "application": js::or_empty(opts.get("application")),
                    "uiLocales": slice(&js::or_empty(opts.get("uiLocales")),
                                       256),
                    "expires": js::num(self.now() + self.pending_ttl_ms()),
                }))
            }
        };
        record.insert("accountChoice".into(), json!(true));
        record.insert("accountChoiceReason".into(), json!(why));
        record.insert("afterAccounts".into(), json!(target));
        let location = format!(
            "{}?authn={}",
            ACCOUNTS_PATH,
            encode_uri_component(&js::string_of(record.get("id")))
        );
        if why == "unread" {
            return (record, location);
        }
        let row = self.account_set_of(request);
        self.deps.records.record_account_choice("ambiguous", None);
        let id = row
            .as_ref()
            .map(|r| js::string_of(r.get("id")))
            .unwrap_or_default();
        self.deps.audit.audit(&json!({
            "action": "account.ambiguous", "actor": "",
            "protocol": js::or_empty(record.get("protocol")),
            "channel": "http", "target": id,
            "summary": if why == "select_account" {
                "the relying party asked for the account picker \
                 (prompt=select_account)"
            } else {
                "a request from a browser with several signed-in accounts \
                 named none of them; the account picker was shown"
            },
            "detail": {"accountSet": id, "reason": why,
                       "application": js::or_empty(record.get("application")),
                       "signedIn": row.as_ref().map(|r| js::object_of(
                           r.get("sessions")).len()).unwrap_or(0)},
        }));
        (record, location)
    }
}
