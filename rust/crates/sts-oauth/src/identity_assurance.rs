// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! OPENID CONNECT FOR IDENTITY ASSURANCE 1.0 — `verified_claims`
//! (`common/identity_assurance.ts`, #127, rule 3ay), as the authorization
//! server answers it: the request checked where the claims request is
//! parsed ([`parse_request`], section 6), and answered at the ID Token and
//! UserInfo ([`respond`]) from the verifications recorded on the person's
//! entry (`stsIdaVerification`, [`list`]).
//!
//! THE ANSWER. Per requested element, the NEWEST record whose
//! verification satisfies it — `value` / `values` on any member, `max_age`
//! on a date-time, every requested `evidence` element matched by one of
//! the record's ([`matches`]) — answering ONLY the members asked for
//! ([`project`]), with the claims both requested and verified. A claim the
//! entry no longer holds as verified is left out; a claim whose data does
//! not fulfil the request's `value`, `values` or `max_age` is left out
//! (section 5.7.4, #187); an element no record satisfies is OMITTED, never
//! answered with a weaker one. `trust_framework` is in every answer.
//!
//! DEVELOPMENT INVENTS ONE (`mode.inventsClaimValues()`), under
//! `urn:sts:demo`, for a person with no record ([`demo_record`]), covering
//! the verifiable claims asked for.
//!
//! What is not here: RECORDING a verification (`/admin-api`'s
//! `users/record-verification`, and the two automatic kinds) and the
//! Shared Signals a change sends — `/admin-api` is Node's in this runtime;
//! and, of the claims a demo verification covers, the values Node invents
//! where the entry holds none (the persona's): Rust covers what the entry
//! holds.

use serde_json::{json, Map, Value as Json};

/// `DEMO_FRAMEWORK`.
pub const DEMO_FRAMEWORK: &str = "urn:sts:demo";

/// `VERIFIABLE_CLAIMS`.
pub const VERIFIABLE_CLAIMS: [&str; 18] = [
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "birthdate",
    "gender",
    "address",
    "email",
    "phone_number",
    "place_of_birth",
    "nationalities",
    "birth_family_name",
    "birth_given_name",
    "birth_middle_name",
    "salutation",
    "title",
    "msisdn",
    "also_known_as",
];

/// The attribute the verifications are recorded in.
pub const ATTRIBUTE: &str = "stsIdaVerification";

const LEAF_KEYS: [&str; 5] =
    ["essential", "purpose", "value", "values", "max_age"];
const MAX_REQUEST_DEPTH: usize = 8;
const MAX_REQUEST_NODES: usize = 256;
const PURPOSE_MIN: usize = 3;
const PURPOSE_MAX: usize = 300;

fn is_object(v: &Json) -> bool {
    v.is_object()
}

/// `isLeafSpec(node)`: null, or an object of only the leaf keys.
fn is_leaf_spec(node: Option<&Json>) -> bool {
    match node {
        None | Some(Json::Null) => true,
        Some(Json::Object(m)) => {
            m.keys().all(|k| LEAF_KEYS.contains(&k.as_str()))
        }
        Some(_) => false,
    }
}

/// `memberKeys(node)`.
fn member_keys(node: &Json) -> Vec<String> {
    match node {
        Json::Object(m) => m
            .keys()
            .filter(|k| !LEAF_KEYS.contains(&k.as_str()))
            .cloned()
            .collect(),
        _ => Vec::new(),
    }
}

/// `canonical(value)`: JSON with its object keys sorted.
#[tracing::instrument(level = "trace", skip_all)]
pub fn canonical(value: Option<&Json>) -> String {
    fn sort(v: &Json) -> Json {
        match v {
            Json::Array(a) => Json::Array(a.iter().map(sort).collect()),
            Json::Object(m) => {
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort();
                let mut out = Map::new();
                for k in keys {
                    out.insert(k.clone(), sort(&m[k]));
                }
                Json::Object(out)
            }
            other => other.clone(),
        }
    }
    match value {
        // `JSON.stringify(undefined)` is undefined, which compares equal
        // only to another undefined.
        None => "\u{0}undefined".to_string(),
        Some(v) => sort(v).to_string(),
    }
}

/// `Date.parse()` of an ISO 8601 instant, in milliseconds.
fn parse_ms(text: &str) -> Option<i64> {
    if let Ok(t) = chrono::DateTime::parse_from_rfc3339(text) {
        return Some(t.timestamp_millis());
    }
    if let Ok(d) = chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d") {
        return d
            .and_hms_opt(0, 0, 0)
            .map(|t| t.and_utc().timestamp_millis());
    }
    None
}

/// `parseRequest(raw, where)`: the elements, and how many nodes they hold;
/// or the sentence refusing them.
#[tracing::instrument(level = "debug", skip(raw))]
pub fn parse_request(
    raw: &Json,
    member: &str,
) -> Result<(Vec<Json>, usize), String> {
    let at = format!("claims.{}.verified_claims", member);
    let is_array = raw.is_array();
    let list: Vec<Json> = match raw {
        Json::Array(a) => a.clone(),
        other => vec![other.clone()],
    };
    if list.is_empty() {
        return Err(format!(
            "{} is an empty array (Identity Assurance section 6).",
            at
        ));
    }
    struct Walk {
        at: String,
        count: usize,
        problem: Option<String>,
    }
    fn walk(w: &mut Walk, node: &Json, path: &str, depth: usize) {
        if w.problem.is_some() {
            return;
        }
        if !node.is_object() && !node.is_array() {
            return;
        }
        w.count += 1;
        if depth > MAX_REQUEST_DEPTH || w.count > MAX_REQUEST_NODES {
            w.problem = Some(format!(
                "{} is nested deeper than {} or has more than {} members.",
                w.at, MAX_REQUEST_DEPTH, MAX_REQUEST_NODES
            ));
            return;
        }
        if let Json::Array(a) = node {
            for (i, one) in a.iter().enumerate() {
                walk(w, one, &format!("{}[{}]", path, i), depth + 1);
            }
            return;
        }
        if let Some(p) = node.get("purpose") {
            let ok = p.as_str().is_some_and(|t| {
                let n = t.encode_utf16().count();
                (PURPOSE_MIN..=PURPOSE_MAX).contains(&n)
            });
            if !ok {
                w.problem = Some(format!(
                    "{}.purpose must be a string of {} to {} characters \
                     (Identity Assurance section 6).",
                    path, PURPOSE_MIN, PURPOSE_MAX
                ));
                return;
            }
        }
        if let Some(m) = node.get("max_age") {
            let ok = m
                .as_f64()
                .is_some_and(|n| n.is_finite() && n >= 0.0 && n.floor() == n);
            if !ok {
                w.problem = Some(format!(
                    "{}.max_age must be a non-negative integer number of \
                     seconds.",
                    path
                ));
                return;
            }
        }
        if let Some(v) = node.get("values") {
            if !v.as_array().is_some_and(|a| !a.is_empty()) {
                w.problem =
                    Some(format!("{}.values must be a non-empty array.", path));
                return;
            }
        }
        if let Some(e) = node.get("essential") {
            if !e.is_boolean() {
                w.problem =
                    Some(format!("{}.essential must be a boolean.", path));
                return;
            }
        }
        for key in member_keys(node) {
            walk(w, &node[&key], &format!("{}.{}", path, key), depth + 1);
        }
    }
    let mut w = Walk {
        at: at.clone(),
        count: 0,
        problem: None,
    };
    let mut elements = Vec::new();
    for (i, one) in list.iter().enumerate() {
        let path = if is_array {
            format!("{}[{}]", at, i)
        } else {
            at.clone()
        };
        if !is_object(one) {
            return Err(format!("{} must be a JSON object.", path));
        }
        let verification = one.get("verification");
        if !verification.is_some_and(is_object) {
            return Err(format!(
                "{}.verification is required, as a JSON object (Identity \
                 Assurance section 6).",
                path
            ));
        }
        if verification
            .and_then(|v| v.get("trust_framework"))
            .is_none()
        {
            return Err(format!(
                "{}.verification.trust_framework is required (Identity \
                 Assurance section 6); null asks for any.",
                path
            ));
        }
        let claims = one.get("claims");
        if !claims
            .and_then(Json::as_object)
            .is_some_and(|m| !m.is_empty())
        {
            return Err(format!(
                "{}.claims is required and may not be empty (Identity \
                 Assurance section 6).",
                path
            ));
        }
        walk(
            &mut w,
            verification.unwrap_or(&Json::Null),
            &format!("{}.verification", path),
            1,
        );
        walk(
            &mut w,
            claims.unwrap_or(&Json::Null),
            &format!("{}.claims", path),
            1,
        );
        if let Some(p) = w.problem.take() {
            return Err(p);
        }
        elements.push(json!({
            "verification": verification.cloned().unwrap_or(Json::Null),
            "claims": claims.cloned().unwrap_or(Json::Null),
        }));
    }
    Ok((elements, w.count))
}

/// `matches(request, actual)`: `now_ms` for `max_age`.
#[tracing::instrument(level = "trace", skip_all)]
pub fn matches(
    request: Option<&Json>,
    actual: Option<&Json>,
    now_ms: i64,
) -> bool {
    let request = match request {
        None | Some(Json::Null) => return true,
        Some(r) => r,
    };
    if let Json::Array(wants) = request {
        return match actual {
            Some(Json::Array(have)) => wants.iter().all(|want| {
                have.iter().any(|h| matches(Some(want), Some(h), now_ms))
            }),
            _ => false,
        };
    }
    if !request.is_object() {
        return true;
    }
    if let Some(v) = request.get("value") {
        if canonical(Some(v)) != canonical(actual) {
            return false;
        }
    }
    if let Some(Json::Array(vs)) = request.get("values") {
        if !vs.iter().any(|v| canonical(Some(v)) == canonical(actual)) {
            return false;
        }
    }
    if let Some(age) = request.get("max_age") {
        let text = match actual {
            Some(Json::String(s)) => s.clone(),
            _ => String::new(),
        };
        let max = age.as_f64().unwrap_or(f64::NAN);
        match parse_ms(&text) {
            Some(at) if (now_ms - at) as f64 <= max * 1000.0 => {}
            _ => return false,
        }
    }
    for key in member_keys(request) {
        let sub = match actual {
            Some(a) if a.is_object() || a.is_array() => a.get(&key),
            _ => None,
        };
        if !matches(request.get(&key), sub, now_ms) {
            return false;
        }
    }
    true
}

/// `project(request, actual)`: only what the request named; `None` where
/// nothing remains.
#[tracing::instrument(level = "trace", skip_all)]
pub fn project(
    request: Option<&Json>,
    actual: Option<&Json>,
    now_ms: i64,
) -> Option<Json> {
    let actual = actual?;
    if is_leaf_spec(request) {
        return Some(actual.clone());
    }
    let request = request?;
    if let Json::Array(wants) = request {
        let Json::Array(have) = actual else {
            return None;
        };
        let out: Vec<Json> = have
            .iter()
            .filter_map(|h| {
                wants
                    .iter()
                    .find(|w| matches(Some(w), Some(h), now_ms))
                    .and_then(|w| project(Some(w), Some(h), now_ms))
            })
            .collect();
        return if out.is_empty() {
            None
        } else {
            Some(Json::Array(out))
        };
    }
    if !actual.is_object() {
        return None;
    }
    let mut out = Map::new();
    for key in member_keys(request) {
        if let Some(v) = project(request.get(&key), actual.get(&key), now_ms) {
            out.insert(key, v);
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(Json::Object(out))
    }
}

/// `list(username)` over the attribute's first value: the records, newest
/// first, each with `verification` and `claims` objects and the text
/// members kept; a value that is not a JSON list reads as none.
#[tracing::instrument(level = "debug", skip_all)]
pub fn list(raw: Option<&str>, username: &str) -> Vec<Json> {
    let Some(raw) = raw.filter(|r| !r.is_empty()) else {
        return Vec::new();
    };
    let parsed: Json = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                "{}identity-assurance: the verifications recorded for {} \
                 are not JSON ({}); read as none.",
                sts_core::log::tag(sts_core::errors::codes::STS_OAUTH_0623),
                username,
                e
            );
            return Vec::new();
        }
    };
    let Json::Array(items) = parsed else {
        tracing::error!(
            "{}identity-assurance: the verifications recorded for {} are \
             not a list; read as none.",
            sts_core::log::tag(sts_core::errors::codes::STS_OAUTH_0623),
            username
        );
        return Vec::new();
    };
    items
        .into_iter()
        .filter(|one| {
            one.is_object()
                && one.get("verification").is_some_and(is_object)
                && one.get("claims").is_some_and(is_object)
        })
        .map(|one| {
            let mut kept = Map::new();
            kept.insert("verification".into(), one["verification"].clone());
            kept.insert("claims".into(), one["claims"].clone());
            for name in ["id", "recorded", "source", "by"] {
                if let Some(Json::String(t)) = one.get(name) {
                    kept.insert(name.into(), json!(t));
                }
            }
            Json::Object(kept)
        })
        .collect()
}

/// `demoRecord(username, names)`: `now_ms`, and `current` the values the
/// entry holds for the verifiable claims asked for.
#[tracing::instrument(level = "debug", skip_all)]
pub fn demo_record(now_ms: i64, current: Map<String, Json>) -> Json {
    let now = chrono::DateTime::from_timestamp_millis(now_ms)
        .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default();
    json!({ "id": "demo", "source": "demo", "recorded": now,
      "verification": { "trust_framework": DEMO_FRAMEWORK, "time": now,
        "evidence": [{ "type": "electronic_record",
          "check_details": [{ "check_method": "data" }], "time": now,
          "record": { "type": DEMO_FRAMEWORK,
                      "source": { "name": "invented by a development-mode \
service; nothing was checked" } } }] },
      "claims": current })
}

/// What [`respond`] reads: the person's records, and the values their
/// entry holds now for the claims named.
pub trait Verifications {
    /// `list(username)`.
    fn records(&self, username: &str) -> Vec<Json>;
    /// `currentValues(username, names, invented)`'s `values`.
    fn current(&self, username: &str, names: &[String]) -> Map<String, Json>;
}

/// `respond(username, elements, asArray)`: the `verified_claims` to
/// release (`None` for none) and the report, a line per element.
#[tracing::instrument(level = "debug", skip(source, elements))]
pub fn respond(
    source: &dyn Verifications,
    username: &str,
    elements: &[Json],
    as_array: bool,
    invents: bool,
    now_ms: i64,
) -> (Option<Json>, Vec<String>) {
    let mut report: Vec<String> = Vec::new();
    let mut records = source.records(username);
    let mut all: Vec<String> = Vec::new();
    for element in elements {
        if let Some(Json::Object(c)) = element.get("claims") {
            for k in c.keys() {
                if !all.contains(k) {
                    all.push(k.clone());
                }
            }
        }
    }
    if records.is_empty() && invents {
        let verifiable: Vec<String> = all
            .iter()
            .filter(|n| VERIFIABLE_CLAIMS.contains(&n.as_str()))
            .cloned()
            .collect();
        records =
            vec![demo_record(now_ms, source.current(username, &verifiable))];
        report.push(format!(
            "no verification is recorded; answered with an invented one \
             under {} (development mode)",
            DEMO_FRAMEWORK
        ));
    }
    let current = if records.is_empty() {
        Map::new()
    } else {
        source.current(username, &all)
    };
    let mut answers: Vec<Json> = Vec::new();
    for (index, element) in elements.iter().enumerate() {
        let asked: Vec<String> = element
            .get("claims")
            .and_then(Json::as_object)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        let mut chosen: Option<&Json> = None;
        let mut released = Map::new();
        for record in &records {
            if chosen.is_some() {
                break;
            }
            if !matches(
                element.get("verification"),
                record.get("verification"),
                now_ms,
            ) {
                continue;
            }
            let id = crate::js::string_of(record.get("id"));
            let mut claims = Map::new();
            let mut stale: Vec<String> = Vec::new();
            let mut unmet: Vec<String> = Vec::new();
            for one in &asked {
                let Some(have) = record["claims"].get(one) else {
                    continue;
                };
                if canonical(Some(have)) != canonical(current.get(one)) {
                    stale.push(one.clone());
                    continue;
                }
                let want = element["claims"].get(one);
                if !matches(want, Some(have), now_ms) {
                    unmet.push(one.clone());
                    continue;
                }
                if let Some(v) = project(want, Some(have), now_ms) {
                    claims.insert(one.clone(), v);
                }
            }
            if !stale.is_empty() {
                report.push(format!(
                    "element {}: {} changed on the entry since verification \
                     {} and {} not released as verified",
                    index,
                    stale.join(", "),
                    id,
                    if stale.len() > 1 { "are" } else { "is" }
                ));
            }
            if !unmet.is_empty() {
                report.push(format!(
                    "element {}: {} in verification {} {} not fulfil the \
                     value, values or max_age asked for; omitted (Identity \
                     Assurance section 5.7.4)",
                    index,
                    unmet.join(", "),
                    id,
                    if unmet.len() > 1 { "do" } else { "does" }
                ));
            }
            if !claims.is_empty() {
                chosen = Some(record);
                released = claims;
            }
        }
        let Some(chosen) = chosen else {
            report.push(format!(
                "element {}: no recorded verification satisfies it; omitted \
                 (Identity Assurance section 6)",
                index
            ));
            continue;
        };
        let mut verification = match project(
            element.get("verification"),
            chosen.get("verification"),
            now_ms,
        ) {
            Some(Json::Object(m)) => m,
            _ => Map::new(),
        };
        let framework = chosen["verification"]
            .get("trust_framework")
            .cloned()
            .unwrap_or(Json::Null);
        verification.insert("trust_framework".into(), framework.clone());
        report.push(format!(
            "element {}: verification {} under {}, {}",
            index,
            crate::js::string_of(chosen.get("id")),
            crate::js::string_of(Some(&framework)),
            released.keys().cloned().collect::<Vec<_>>().join(", ")
        ));
        answers.push(json!({ "verification": verification,
                             "claims": released }));
    }
    if !report.is_empty() {
        tracing::info!(
            "identity-assurance: verified_claims for {} — {}.",
            username,
            report.join("; ")
        );
    }
    if answers.is_empty() {
        return (None, report);
    }
    let value = if as_array || answers.len() > 1 {
        Json::Array(answers)
    } else {
        answers.remove(0)
    };
    (Some(value), report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_six_refuses_an_element_with_no_verification() {
        let e = parse_request(
            &json!({ "claims": { "given_name": null } }),
            "userinfo",
        )
        .unwrap_err();
        assert_eq!(
            e,
            "claims.userinfo.verified_claims.verification is required, as a \
             JSON object (Identity Assurance section 6)."
        );
    }

    #[test]
    fn an_evidence_request_is_matched_element_by_element() {
        let want = json!({ "trust_framework": { "value": "eidas" },
            "evidence": [{ "type": { "value": "document" },
                           "document_details": { "type": null } }] });
        let have = json!({ "trust_framework": "eidas",
            "assurance_level": "high",
            "evidence": [{ "type": "document",
                "check_details": [{ "check_method": "vpip" }],
                "document_details": { "type": "passport",
                                      "document_number": "P1" } }] });
        assert!(matches(Some(&want), Some(&have), 0));
        let p = project(Some(&want), Some(&have), 0).unwrap();
        assert_eq!(
            p,
            json!({ "trust_framework": "eidas",
                    "evidence": [{ "type": "document",
                        "document_details": { "type": "passport" } }] })
        );
    }
}
