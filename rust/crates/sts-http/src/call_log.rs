// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE CALL LOG (`common/app.js`'s `recordTheCall()` and
//! `common/audit.js`'s `recordHttp()`): one audit row per answered request,
//! carrying the code the handler marked (`errorCodes.mark(res, …)`) or the
//! generic code of a failed status, written in the REQUEST'S realm.
//!
//! What replaced what (rust/DESIGN.md section 4):
//!
//! * `res[INCIDENT]` (the number `audit.reserveIncident(res)` put on the
//!   response) → a per-request [`CallState`] held in a task-local for the
//!   request and everything it awaits; [`reserve_incident`] asks the ring
//!   for the number once and hands back the same one after, and the row is
//!   written with it.
//! * `res.locals.apiCaller` → [`set_api_caller`], called by the management
//!   API's gate once it verified the token.
//! * `req.rawBody` for the one field read out of an admin body (`action`)
//!   → the parsed body's text, kept on the state by the body step.
//! * the actor resolver slot (`setActorResolver()`, filled by `authn.js`)
//!   → [`ActorResolver`] on the layer; with none, a row has no actor, which
//!   is Node's behaviour in a process that never loaded `authn.js`.
//! * `withSource({ req })` → the handler runs inside
//!   `AuditLog::scope_source(address)`, so every row a handler writes
//!   carries the client's address.
//!
//! `req.route.path` (the Express pattern) has no counterpart: `route` is
//! `''` on every row, and `matched` is whether the request reached a route
//! rather than the unrouted 404 ([`Unrouted`]).

use std::sync::{Arc, Mutex, PoisonError};

use axum::http::HeaderMap;
use sts_audit::log::{ApiCaller, AuditLog};

/// Marks the unrouted 404 (`not_found()`): `matched` is false on its row.
#[derive(Clone, Copy, Debug)]
pub struct Unrouted;

/// `setActorResolver()` and `setActorSessionResolver()`: the signed-in
/// user a request carries, and the session, or `''`. Must not fail and
/// must have no side effect.
pub trait ActorResolver: Send + Sync {
    fn actor_of(&self, headers: &HeaderMap) -> (String, String);
}

/// What one request's row is built from, beside the response.
pub struct CallState {
    pub(crate) log: Option<Arc<AuditLog>>,
    pub(crate) incident: Mutex<i64>,
    pub(crate) body: Mutex<Option<(String, String)>>,
    pub(crate) caller: Mutex<Option<ApiCaller>>,
}

impl CallState {
    pub(crate) fn new(log: Option<Arc<AuditLog>>) -> Arc<CallState> {
        Arc::new(CallState {
            log,
            incident: Mutex::new(0),
            body: Mutex::new(None),
            caller: Mutex::new(None),
        })
    }

    /// The reserved number, taken so it is used once (`takeIncident()`).
    pub(crate) fn take_incident(&self) -> i64 {
        let mut n =
            self.incident.lock().unwrap_or_else(PoisonError::into_inner);
        std::mem::take(&mut *n)
    }
}

tokio::task_local! {
    pub(crate) static CALL: Arc<CallState>;
}

/// `audit.reserveIncident(res)`: the `seq` this request's row will carry,
/// the incident ID an error page prints (#1326); the same number when
/// asked again; 0 outside a request or with no audit log.
///
/// THE RESERVATION AND THE ROW ARE ONE RUN in Node, because the export's
/// cursor relies on `seq` rising within a process. Here the row is written
/// at the flush of the same request, so a page that reserves and then
/// sends keeps that order as long as it awaits nothing slow in between.
#[tracing::instrument(level = "debug")]
pub fn reserve_incident() -> i64 {
    CALL.try_with(|state| {
        let Some(log) = &state.log else {
            return 0;
        };
        let mut n = state
            .incident
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if *n == 0 {
            *n = log.reserve_incident();
        }
        *n
    })
    .unwrap_or(0)
}

/// `res.locals.apiCaller = { name, owner }`: who the management API's
/// gate verified; the row names them rather than the cookie's user.
#[tracing::instrument(level = "debug")]
pub fn set_api_caller(name: &str, owner: bool) {
    let _ = CALL.try_with(|state| {
        *state.caller.lock().unwrap_or_else(PoisonError::into_inner) =
            Some(ApiCaller {
                name: name.to_string(),
                owner,
            });
    });
}

/// Keeps the body's text and type for the row's posted `action`.
// A hot path: every request with a body; no span.
pub(crate) fn keep_body(content_type: &str, text: &str) {
    let _ = CALL.try_with(|state| {
        *state.body.lock().unwrap_or_else(PoisonError::into_inner) =
            Some((content_type.to_string(), text.to_string()));
    });
}

/// `req.query` as Express's parser gives it for a flat query: each name
/// once, a repeated name an array of its values, in first-seen order.
// A hot path: every request; no span.
pub(crate) fn query_map(
    query: &str,
) -> serde_json::Map<String, serde_json::Value> {
    use serde_json::Value as Json;
    let mut out = serde_json::Map::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let name = crate::cors::form_decode(name);
        let value = Json::from(crate::cors::form_decode(value));
        match out.get_mut(&name) {
            Some(Json::Array(list)) => list.push(value),
            Some(first) => {
                let was = first.take();
                *first = Json::Array(vec![was, value]);
            }
            None => {
                out.insert(name, value);
            }
        }
    }
    out
}

/// `audit.record(event)` from inside a request: the row goes into the
/// ring the request's call log writes to, in the ambient realm. `false`
/// where there is none (outside a request, or no audit log), so a caller
/// can fall back to its log line.
#[tracing::instrument(level = "debug", skip_all)]
pub fn audit(event: &serde_json::Value) -> bool {
    CALL.try_with(|state| match &state.log {
        Some(log) => {
            log.audit(event);
            true
        }
        None => false,
    })
    .unwrap_or(false)
}
