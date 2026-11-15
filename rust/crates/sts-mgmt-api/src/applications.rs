// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The `/admin-api/applications` operations (`mgmt-api/admin_api.ts`'s
//! rows for the application registry) over `sts-registers`' application
//! register:
//!
//! * `GET /admin-api/applications` — `getApplications`, the list
//!   (`adminViews.applicationsJson(req)` without `?application=`), and the
//!   drill-down (`?application=`) IN PART: the entry, masked, and its two
//!   paged lists. The sections that read a dozen other registers — the
//!   roles, the claims preview, the delegated permissions, the signals, the
//!   enrolment, the audit log's attempts — are absent rather than empty
//!   (`ApplicationRegistry::application_detail_json()`).
//! * `POST /admin-api/applications/{action}` — the register's own acts
//!   (`adminActions.applicationsAction()`): `create`, `set`, `add`,
//!   `remove`, `update-fields`, `confirm-address`, `discard-address`,
//!   `add-owner`, `remove-owner`, the four secret acts and `forget`. An
//!   unknown action is refused in the register's words (STS-ADMIN-0500); an
//!   act of another family is not routed here.
//!
//! The answer is 200 for `ok`, 400 otherwise, marked with the register's
//! code or STS-API-0050, as the route's handler marks it.

use serde_json::{Map, Value as Json};
use sts_core::errors::codes;

use crate::gate::Caller;
use crate::request::Query;
use crate::setup::{Answered, Setup};

/// `listField(req, body, name)` for a JSON body: an array as strings, one
/// value as one, nothing for null or ''.
fn list_field(body: &Json, name: &str) -> Vec<String> {
    match body.get(name) {
        None | Some(Json::Null) => Vec::new(),
        Some(Json::String(s)) if s.is_empty() => Vec::new(),
        Some(Json::Array(l)) => l.iter().map(js_string).collect(),
        Some(v) => vec![js_string(v)],
    }
}

fn js_string(v: &Json) -> String {
    match v {
        Json::String(s) => s.clone(),
        Json::Null => "null".into(),
        other => other.to_string(),
    }
}

/// `familiesOfChoices(values)`: a combined choice (`vc`) stands for the
/// families it names.
fn families_of_choices(values: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for value in values {
        let id = value.trim().to_lowercase();
        let ids: Vec<String> = if id == "vc" {
            vec!["oid4vci".into(), "oid4vp".into()]
        } else {
            vec![id]
        };
        for one in ids {
            if !one.is_empty() && !out.contains(&one) {
                out.push(one);
            }
        }
    }
    out
}

/// `GET /admin-api/applications`: the list, or one application's
/// drill-down with `?application=` (`applicationsJson(req)`), in part.
#[tracing::instrument(level = "debug", skip(setup, query))]
pub fn list(setup: &Setup<'_>, query: &Query) -> Option<Answered> {
    let registry = setup.ports.applications()?;
    let one = query.get("application").map(js_string).unwrap_or_default();
    let q: Map<String, Json> =
        query.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let body = if one.trim().is_empty() {
        registry.applications_list_json(
            &q,
            setup.page_settings("/admin/applications"),
        )
    } else {
        // `String(req.query.application || '').trim()`.
        registry.application_detail_json(&q, one.trim())
    };
    Some(Answered {
        status: 200,
        body,
        code: None,
    })
}

/// `POST /admin-api/applications/{action}`: None when there is no register.
#[tracing::instrument(level = "debug", skip(setup, body, caller))]
pub fn action(
    setup: &Setup<'_>,
    action: &str,
    body: &Json,
    caller: Option<&Caller>,
) -> Option<Answered> {
    let registry = setup.ports.applications()?;
    let mut asked = body.as_object().cloned().unwrap_or_default();
    asked.insert("action".into(), Json::from(action));
    let asked = Json::Object(asked);
    let mut names = list_field(&asked, "protocol");
    names.extend(list_field(&asked, "protocols"));
    let protocols = families_of_choices(&names);
    let actor = caller.map(|c| c.name.clone()).unwrap_or_default();
    let ports = setup.ports.application_ports();
    let result = registry.applications_action(
        &asked,
        Some(protocols),
        &actor,
        ports.as_ref(),
    );
    registry.flush_credential_writes();
    let ok = result.is_ok();
    Some(Answered {
        status: if ok { 200 } else { 400 },
        code: if ok {
            None
        } else {
            Some(result.code.unwrap_or(codes::STS_API_0050))
        },
        body: result.answer,
    })
}
