// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! TWO COPIES OF ONE SESSION, MERGED (`mergeSessionRows()`, #46 section 3;
//! develop's 65a591462 for the client's `iss` and `sub`).
//!
//! `mine` is this process's copy, `theirs` the stored one another node
//! wrote. Each rule is chosen so that merging the answer with either side
//! again gives the answer, so two nodes merging in either order converge:
//!
//! * **The copy further along is the base**: an arrival (`chosen: false`)
//!   is behind a chosen session; then a later `authTime`, a later handle
//!   rotation, a later hosted-surface renewal.
//! * **The clocks take the latest**: `lastSeenAt` always; `expires` only
//!   when both copies are the same sign-in.
//! * **The lists are unions**: the relying parties each protocol records for
//!   its sign-out, and `relyingParties` and `events`. An OIDC client both
//!   copies hold keeps the later answer's `iss` and `sub`, and an empty one
//!   never wipes a recorded one (run 27, 2026-11-14).
//!
//! It is the `merge_row` of the session store's declaration ([`spec`]), the
//! rule `persistence_minted.js` applies under the row's lock.

use std::collections::HashSet;
use std::sync::Arc;

use serde_json::{json, Value};
use sts_core::realm_store::StoreSpec;
use sts_store::side::SESSIONS_HANDLE;

use crate::js::{self, Object};

fn rank(s: &Object) -> [f64; 4] {
    [
        if s.get("chosen") == Some(&Value::Bool(false)) {
            0.0
        } else {
            1.0
        },
        js::number_or_zero(s.get("authTime")),
        js::number_or_zero(s.get("handleIssuedAt")),
        js::number_or_zero(s.get("rpRenewedAt")),
    ]
}

/// `Math.max(Number(a) || 0, Number(b) || 0) || fallback`.
fn latest(
    a: Option<&Value>,
    b: Option<&Value>,
    fallback: Option<&Value>,
) -> Value {
    let m = js::number_or_zero(a).max(js::number_or_zero(b));
    if m != 0.0 {
        js::num(m)
    } else {
        fallback.cloned().unwrap_or(Value::Null)
    }
}

fn merge_client(here: &Object, there: &Object, now_ms: f64) -> Value {
    let later_is_there = js::number_or_zero(there.get("last"))
        > js::number_or_zero(here.get("last"));
    let (later, earlier) = if later_is_there {
        (there, here)
    } else {
        (here, there)
    };
    let mut out = js::assign(earlier, later);
    let firsts: Vec<f64> = [
        js::number_or_zero(here.get("first")),
        js::number_or_zero(there.get("first")),
    ]
    .into_iter()
    .filter(|n| *n != 0.0)
    .chain(std::iter::once(now_ms))
    .collect();
    let first = firsts.iter().copied().fold(f64::INFINITY, f64::min);
    out.insert("first".into(), js::num(first));
    out.insert(
        "last".into(),
        js::num(
            js::number_or_zero(here.get("last"))
                .max(js::number_or_zero(there.get("last"))),
        ),
    );
    out.insert(
        "count".into(),
        js::num(
            js::number_or_zero(here.get("count"))
                .max(js::number_or_zero(there.get("count"))),
        ),
    );
    let pick = |k: &str| {
        let l = js::or_empty(later.get(k));
        if l.is_empty() {
            js::or_empty(earlier.get(k))
        } else {
            l
        }
    };
    out.insert("iss".into(), json!(pick("iss")));
    out.insert("sub".into(), json!(pick("sub")));
    Value::Object(out)
}

fn merge_binding(base: &Object, other: &Object) -> Option<Value> {
    let jkt = |o: &Object| {
        o.get("dbsc")
            .and_then(|d| d.get("jkt"))
            .is_some_and(|j| js::truthy(Some(j)))
    };
    let base_bound = jkt(base);
    if jkt(other) {
        let theirs = other.get("dbsc").cloned().unwrap_or(Value::Null);
        if !base_bound {
            return Some(theirs);
        }
        let mine = base.get("dbsc").cloned().unwrap_or(Value::Null);
        if mine.get("id") != theirs.get("id") {
            return Some(mine);
        }
        let more = js::number_or_zero(theirs.get("refreshes"))
            > js::number_or_zero(mine.get("refreshes"));
        return Some(if more { theirs } else { mine });
    }
    let has = |o: &Object| js::truthy(o.get("dbsc"));
    if (has(base) || has(other)) && !base_bound {
        let left = js::object_of(base.get("dbsc"));
        let right = js::object_of(other.get("dbsc"));
        let offered: Vec<f64> = [
            js::number_or_zero(left.get("offeredAt")),
            js::number_or_zero(right.get("offeredAt")),
        ]
        .into_iter()
        .filter(|n| *n > 0.0)
        .collect();
        let skipped = |o: &Object| {
            o.get("skippedReasons")
                .and_then(Value::as_array)
                .is_some_and(|a| !a.is_empty())
        };
        let skip = if skipped(&left) {
            Some(&left)
        } else if skipped(&right) {
            Some(&right)
        } else {
            None
        };
        let mut out = js::assign(&left, &right);
        if !offered.is_empty() {
            let min = offered.iter().copied().fold(f64::INFINITY, f64::min);
            out.insert("offeredAt".into(), js::num(min));
        }
        if let Some(s) = skip {
            out.insert(
                "skippedReasons".into(),
                s.get("skippedReasons").cloned().unwrap_or(json!([])),
            );
            out.insert(
                "skippedIds".into(),
                match s.get("skippedIds") {
                    Some(a @ Value::Array(_)) => a.clone(),
                    _ => json!([]),
                },
            );
        }
        return Some(Value::Object(out));
    }
    None
}

/// `mergeSessionRows(mine, theirs)`. `now_ms` is `Date.now()`, which an OIDC
/// client neither copy saw first is stamped with.
#[tracing::instrument(level = "debug", skip_all)]
pub fn merge_session_rows(mine: &Value, theirs: &Value, now_ms: f64) -> Value {
    let Some(m) = mine.as_object() else {
        return theirs.clone();
    };
    let Some(t) = theirs.as_object() else {
        return mine.clone();
    };
    let a = rank(m);
    let b = rank(t);
    let mut mine_ahead = true;
    for i in 0..4 {
        if a[i] != b[i] {
            mine_ahead = a[i] > b[i];
            break;
        }
    }
    let (base, other) = if mine_ahead { (m, t) } else { (t, m) };
    let mut out = base.clone();
    out.insert(
        "lastSeenAt".into(),
        latest(
            m.get("lastSeenAt"),
            t.get("lastSeenAt"),
            base.get("lastSeenAt"),
        ),
    );
    if a[0] == b[0] && a[1] == b[1] {
        out.insert(
            "expires".into(),
            latest(m.get("expires"), t.get("expires"), base.get("expires")),
        );
    }
    for field in [
        "wsfedRealms",
        "saml2ServiceProviders",
        "saml11RelyingParties",
    ] {
        if let Some(Value::Object(theirs)) = other.get(field) {
            let mine = js::object_of(base.get(field));
            out.insert(field.into(), Value::Object(js::assign(theirs, &mine)));
        }
    }
    if let Some(Value::Object(clients)) = other.get("oidcClients") {
        let mut merged = js::object_of(base.get("oidcClients"));
        for (id, there) in clients {
            let there_o = js::object_of(Some(there));
            let here = merged.get(id).cloned();
            match here.filter(|h| js::truthy(Some(h))) {
                None => {
                    let there = if js::truthy(Some(there)) {
                        there.clone()
                    } else {
                        Value::Object(Object::new())
                    };
                    merged.insert(id.clone(), there);
                }
                Some(here) => {
                    let here_o = js::object_of(Some(&here));
                    merged.insert(
                        id.clone(),
                        merge_client(&here_o, &there_o, now_ms),
                    );
                }
            }
        }
        out.insert("oidcClients".into(), Value::Object(merged));
    }
    if let Some(binding) = merge_binding(base, other) {
        out.insert("dbsc".into(), binding);
    }
    for field in ["relyingParties", "events"] {
        let (Some(Value::Array(theirs)), Some(Value::Array(ours))) =
            (other.get(field), base.get(field))
        else {
            continue;
        };
        let mut seen: HashSet<String> =
            ours.iter().map(js::stringify).collect();
        let mut union = ours.clone();
        for one in theirs {
            if seen.insert(js::stringify(one)) {
                union.push(one.clone());
            }
        }
        out.insert(field.into(), Value::Array(union));
    }
    let backs =
        js::truthy(m.get("backsConsole")) || js::truthy(t.get("backsConsole"));
    out.insert("backsConsole".into(), Value::Bool(backs));
    let sub = |o: &Object| js::or_empty(o.get("subjectId"));
    let (bs, os) = (sub(base), sub(other));
    let subject = if !bs.is_empty() { bs } else { os };
    out.insert("subjectId".into(), json!(subject));
    if !js::truthy(out.get("accountSetId"))
        && js::truthy(other.get("accountSetId"))
    {
        out.insert(
            "accountSetId".into(),
            other.get("accountSetId").cloned().unwrap_or(Value::Null),
        );
    }
    Value::Object(out)
}

/// The session store's declaration (`realms.map({ persist: 'authn.sessions',
/// tombstone: true, mergeRow })`): tombstoned, so a sign-out holds against
/// a node with an older copy; merged with [`merge_session_rows`]; and no
/// `expiresAt`, so `sts_minted.expires_at` stays NULL and the generic
/// purge cannot end a session (#350). The `sts_sessions` index is filed by
/// `sts-store`'s minted flush for this handle whoever declares it.
#[tracing::instrument(level = "debug", skip(now_ms))]
pub fn spec(now_ms: Arc<dyn Fn() -> f64 + Send + Sync>) -> StoreSpec {
    let mut spec = StoreSpec::persisted(SESSIONS_HANDLE);
    spec.tombstone = true;
    spec.merge_row = Some(Arc::new(move |mine: &Value, theirs: &Value| {
        merge_session_rows(mine, theirs, now_ms())
    }));
    spec
}
