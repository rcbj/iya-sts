// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! RFC 9470 STEP-UP AT THE AUTHORIZATION ENDPOINT (#444, phase 5, the
//! `oauth6` slice): `oauth-oidc/step_up.ts`'s half the authorization
//! endpoint asks — `parseAcrValues()`, `parseMaxAge()`, `requirementOf()`
//! (with the client's `default_acr_values` and `default_max_age`),
//! `essentialAcrValuesOf()` (an essential `acr` claims request is a
//! REQUIREMENT, OIDC Core section 5.5.1.1, not a hint), `meets()`,
//! `satisfiedAcr()`, `assessSession()`, `unmetRefusal()` and the sign-in
//! screen's demand (`screenDemandFor()`, `phishingClassFor()`).
//!
//! The levels are Node's, ordered weakest first (`0`, `1`, `mfa`), so a
//! stronger one meets a weaker request; `phr`/`phrh` are OpenID Connect EAP
//! ACR Values 1.0's classes, earned by the session's latest event
//! (`PhishingResistance`, sts-credentials); `hwk` is met by two factors
//! including a security key; any other value only by a sign-in reporting
//! exactly that acr.
//!
//! NOT HERE YET: the resource server's half (`ownResourceRequirement()`,
//! `tokenRefusal()`, `challengeHeader()`), the authorization-detail types'
//! required levels (#432 phase 6, `detailAcrsOf()` — no Rust door issues
//! RFC 9396 details yet), the compliant-device class (the device register
//! is not in this runtime: `urn:sts:acr:compliant-device` is never met),
//! and the monitor's counters (`record()`).

use serde_json::{Map, Value as Json};
use sts_core::errors::{codes, ErrorCode};
use sts_credentials::phishing::{PhishingResistance, PHR, PHRH};

/// `LEVELS`, weakest first.
pub const LEVELS: [&str; 3] = ["0", "1", "mfa"];
/// `COMPLIANT_DEVICE`.
pub const COMPLIANT_DEVICE: &str = "urn:sts:acr:compliant-device";
/// `KEY_ALIASES`.
pub const KEY_ALIASES: [&str; 1] = ["hwk"];
/// `HONOURED`: the round-trip marker on a return from a step-up sign-in.
pub const HONOURED: &str = "step_up_honoured";
/// `MAX_AGE_LIMIT`: ten years in seconds.
pub const MAX_AGE_LIMIT: i64 = 315_360_000;

/// What a request requires (`Requirement`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Requirement {
    pub acr_values: Vec<String>,
    pub max_age: Option<i64>,
    pub present: bool,
}

/// What a session was found to be (`assessSession()`'s answer).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Assessed {
    pub met: bool,
    /// `acr` or `max_age` where unmet.
    pub reason: String,
    pub retry: bool,
    pub acr: Option<String>,
    pub elapsed: f64,
    pub earned: String,
    pub hardware_shortfall: String,
}

fn s(v: Option<&Json>) -> String {
    crate::js::string_of(v)
}

/// `ACR_VALUE`: `%x21 / %x23-5B / %x5D-7E`, 1 to 256 of them.
fn acr_value_ok(one: &str) -> bool {
    let n = one.chars().count();
    (1..=256).contains(&n)
        && one.chars().all(|c| {
            let u = c as u32;
            u == 0x21
                || (0x23..=0x5B).contains(&u)
                || (0x5D..=0x7E).contains(&u)
        })
}

/// `parseAcrValues(text)`: the values in order, each once.
#[tracing::instrument(level = "debug")]
pub fn parse_acr_values(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for one in text.split_whitespace() {
        if acr_value_ok(one) && !out.iter().any(|o| o == one) {
            out.push(one.to_string());
        }
    }
    out
}

/// `parseMaxAge(value)`: whole seconds, at most ten years, or `None`.
#[tracing::instrument(level = "debug")]
pub fn parse_max_age(value: &str) -> Option<i64> {
    let text = value.trim();
    if text.is_empty()
        || text.len() > 9
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    text.parse::<i64>().ok().filter(|n| *n <= MAX_AGE_LIMIT)
}

/// `essentialAcrValuesOf(claims)`: the acr values a claims request marks
/// essential, from its `id_token` and `userinfo` members.
#[tracing::instrument(level = "debug", skip_all)]
pub fn essential_acr_values_of(claims: Option<&Json>) -> Vec<String> {
    let parsed: Json = match claims {
        Some(Json::String(t)) => serde_json::from_str(t).unwrap_or(Json::Null),
        Some(other) => other.clone(),
        None => Json::Null,
    };
    let mut out: Vec<String> = Vec::new();
    for member in ["id_token", "userinfo"] {
        let Some(request) = parsed.get(member).and_then(|m| m.get("acr"))
        else {
            continue;
        };
        if !request.is_object()
            || request.get("essential") != Some(&Json::Bool(true))
        {
            continue;
        }
        let asked: Vec<String> = match request.get("values") {
            Some(Json::Array(l)) => l.iter().map(|v| s(Some(v))).collect(),
            Some(one) => vec![s(Some(one))],
            None => match request.get("value") {
                Some(v) => vec![s(Some(v))],
                None => Vec::new(),
            },
        };
        for one in parse_acr_values(&asked.join(" ")) {
            if !out.contains(&one) {
                out.push(one);
            }
        }
    }
    out
}

/// `requirementOf(query, registered)`: the request's `acr_values` and
/// `max_age` (with its essential acr claims), the client's registered
/// defaults where the request names neither.
#[tracing::instrument(level = "debug", skip_all)]
pub fn requirement_of(q: &Map<String, Json>, registered: &Json) -> Requirement {
    let essential = essential_acr_values_of(q.get("claims"));
    let asked_acr = !s(q.get("acr_values")).is_empty() || !essential.is_empty();
    let acr_text = match registered.get("default_acr_values") {
        Some(Json::Array(list)) if !asked_acr => list
            .iter()
            .map(|v| s(Some(v)))
            .collect::<Vec<_>>()
            .join(" "),
        _ => s(q.get("acr_values")),
    };
    let max_age = match q.get("max_age") {
        Some(v) if !s(Some(v)).is_empty() => parse_max_age(&s(Some(v))),
        _ => match registered.get("default_max_age") {
            Some(v) if !v.is_null() => parse_max_age(&s(Some(v))),
            _ => None,
        },
    };
    let mut values = parse_acr_values(&acr_text);
    for one in essential {
        if !values.contains(&one) {
            values.push(one);
        }
    }
    Requirement {
        present: !values.is_empty() || max_age.is_some(),
        acr_values: values,
        max_age,
    }
}

fn level_of(acr: &str) -> i64 {
    LEVELS
        .iter()
        .position(|l| *l == acr)
        .map(|i| i as i64)
        .unwrap_or(-1)
}

fn had_level_of(acr: &str) -> i64 {
    if PhishingResistance::is_class(acr) {
        level_of("1")
    } else {
        level_of(acr)
    }
}

fn amr_of(facts: &Json) -> Vec<String> {
    match facts.get("amr") {
        Some(Json::Array(l)) => l.iter().map(|v| s(Some(v))).collect(),
        Some(Json::Null) | None => Vec::new(),
        Some(one) => vec![s(Some(one))],
    }
}

/// `meets(requested, facts)`: whether one requested value is met by an
/// authentication (`acr`, `amr`, a session's `events`).
#[tracing::instrument(level = "debug", skip(facts))]
pub fn meets(requested: &str, facts: &Json) -> bool {
    let had = s(facts.get("acr"));
    let has_events = facts.get("events").is_some_and(Json::is_array);
    if !had.is_empty()
        && had == requested
        && !(PhishingResistance::is_class(requested) && has_events)
    {
        return true;
    }
    let had_level = had_level_of(&had);
    if PhishingResistance::is_class(requested) {
        let earned = if has_events {
            PhishingResistance::of_session(facts)
        } else {
            PhishingResistance::of_acr(facts.get("acr"))
        };
        return earned.iter().any(|e| e == requested);
    }
    if requested == COMPLIANT_DEVICE {
        // The device register is not in this runtime: never met.
        return false;
    }
    if KEY_ALIASES.contains(&requested) {
        return had_level >= level_of("mfa")
            && amr_of(facts).iter().any(|a| a == "hwk");
    }
    let wanted = level_of(requested);
    wanted >= 0 && had_level >= wanted
}

/// `satisfiedAcr(acrValues, facts)`: the most preferred requested value
/// met, or the authentication's own with nothing requested.
#[tracing::instrument(level = "debug", skip(facts))]
pub fn satisfied_acr(acr_values: &[String], facts: &Json) -> Option<String> {
    if acr_values.is_empty() {
        let own = s(facts.get("acr"));
        return (!own.is_empty()).then_some(own);
    }
    acr_values.iter().find(|v| meets(v, facts)).cloned()
}

/// `assessSession(requirement, session, { honoured, windowS, now })`.
#[tracing::instrument(level = "debug", skip(session))]
pub fn assess_session(
    need: &Requirement,
    session: &Json,
    honoured: bool,
    window_s: i64,
    now_s: f64,
) -> Assessed {
    let auth_time = {
        let a = crate::js::to_number(
            session.get("authTime").unwrap_or(&Json::Null),
        );
        if a.is_finite() && a != 0.0 {
            a
        } else {
            crate::js::to_number(
                session.get("auth_time").unwrap_or(&Json::Null),
            )
        }
    };
    let auth_time = if auth_time.is_finite() {
        auth_time
    } else {
        0.0
    };
    // Seconds, as the session's events record them.
    let elapsed = if auth_time != 0.0 {
        now_s - auth_time
    } else {
        f64::INFINITY
    };
    let mut allowed = need.max_age.map(|m| m as f64);
    if let (Some(a), true) = (allowed, honoured) {
        allowed = Some(a.max(window_s as f64));
    }
    let age_met = match allowed {
        None => true,
        Some(a) => elapsed <= a,
    };
    let acr = satisfied_acr(&need.acr_values, session);
    let acr_met = need.acr_values.is_empty() || acr.is_some();
    if age_met && acr_met {
        return Assessed {
            met: true,
            acr,
            elapsed,
            ..Assessed::default()
        };
    }
    let earned = PhishingResistance::of_session(session);
    Assessed {
        met: false,
        reason: if age_met { "acr" } else { "max_age" }.into(),
        retry: !honoured,
        acr,
        elapsed,
        earned: earned.last().cloned().unwrap_or_default(),
        hardware_shortfall: if earned.is_empty() {
            String::new()
        } else {
            PhishingResistance::hardware_shortfall_of(session)
        },
    }
}

/// A number as JavaScript writes it.
fn js_number(n: f64) -> String {
    if n.is_infinite() {
        return if n > 0.0 { "Infinity" } else { "-Infinity" }.into();
    }
    if n.fract() == 0.0 && n.abs() < 1e21 {
        format!("{}", n as i64)
    } else {
        format!("{}", n)
    }
}

/// `unmetRefusal(requirement, assessed, promptNone)`: `(code, error,
/// description)`.
#[tracing::instrument(level = "debug")]
pub fn unmet_refusal(
    need: &Requirement,
    said: &Assessed,
    prompt_none: bool,
) -> (ErrorCode, &'static str, String) {
    let max_age = need
        .max_age
        .map(|m| m.to_string())
        .unwrap_or_else(|| "null".into());
    let joined = need.acr_values.join(" ");
    if prompt_none {
        return (
            codes::STS_OAUTH_0502,
            "login_required",
            format!(
                "{}, so the person must sign in again, and prompt=none \
                 forbids showing the sign-in screen.",
                if said.reason == "max_age" {
                    format!(
                        "The session authenticated {} seconds ago and max_age \
                         is {}",
                        js_number(said.elapsed),
                        max_age
                    )
                } else {
                    format!(
                        "The session's authentication does not meet \
                         acr_values \"{}\"",
                        joined
                    )
                }
            ),
        );
    }
    if said.reason == "max_age" {
        return (codes::STS_OAUTH_0501, "unmet_authentication_requirements", format!(
            "The person was asked to sign in again because max_age is {}, and the session that came back authenticated {} seconds ago — a sign-in that did not start a new authentication.",
            max_age, js_number(said.elapsed)));
    }
    let only_eap = |v: &String| v == PHRH || v == PHR;
    if need.acr_values.iter().any(|v| v == PHRH)
        && need.acr_values.iter().all(only_eap)
        && said.earned == PHR
    {
        return (codes::STS_OAUTH_0971, "unmet_authentication_requirements", format!(
            "OpenID Connect EAP ACR Values 1.0: phrh was requested, and the authentication was phishing-resistant (phr) without evidence that its key is hardware-protected: {}. phrh is met by a passkey whose attestation this realm trusts and whose backup-eligible flag is clear.",
            if said.hardware_shortfall.is_empty() { "no trusted attestation" } else { &said.hardware_shortfall }));
    }
    if !need.acr_values.is_empty()
        && need
            .acr_values
            .iter()
            .all(|v| PhishingResistance::is_class(v))
    {
        return (codes::STS_OAUTH_0970, "unmet_authentication_requirements", format!(
            "OpenID Connect EAP ACR Values 1.0: {} was requested, and the authentication performed was not phishing-resistant. phr is met by signing in with a passkey or security key already registered (alone or after a password) or with a TLS client certificate — not by a password, a one-time code, an emailed code or link, or a recovery code, nor by a key enrolled in the same sign-in on the strength of a password; phrh by such a passkey whose attestation this realm trusts and whose backup-eligible flag is clear.",
            joined));
    }
    (codes::STS_OAUTH_0500, "unmet_authentication_requirements", format!(
        "RFC 9470 section 5: acr_values \"{}\" were requested and the authentication performed does not meet any of them. This service produces {} (ordered, so a stronger one meets a weaker request); {} is met by a sign-in from the person's own compliant registered device; phr by a passkey, a security key or a TLS client certificate, and phrh by a passkey with a trusted attestation that is not backup-eligible (OpenID Connect EAP ACR Values 1.0); hwk by a password with a security key; any other value only by a sign-in that reports exactly that acr.",
        joined, LEVELS.join(", "), COMPLIANT_DEVICE))
}

fn producible(value: &str) -> bool {
    level_of(value) >= 0
        || KEY_ALIASES.contains(&value)
        || PhishingResistance::is_class(value)
}

/// `screenDemandFor(acrValues)`: `(force_mfa, force_key)` for the
/// sign-in screen.
#[tracing::instrument(level = "debug")]
pub fn screen_demand_for(acr_values: &[String]) -> (bool, bool) {
    let made: Vec<&String> =
        acr_values.iter().filter(|v| producible(v)).collect();
    if !made.is_empty() && made.iter().all(|v| PhishingResistance::is_class(v))
    {
        return (false, true);
    }
    let demands = !made.is_empty()
        && made.iter().all(|v| {
            KEY_ALIASES.contains(&v.as_str()) || level_of(v) >= level_of("mfa")
        });
    if !demands {
        return (false, false);
    }
    let keys_only = made.iter().all(|v| KEY_ALIASES.contains(&v.as_str()));
    (true, keys_only)
}

/// `phishingClassFor(acrValues, [])`: `phrh` only when nothing else would
/// answer.
#[tracing::instrument(level = "debug")]
pub fn phishing_class_for(acr_values: &[String]) -> String {
    let made: Vec<&String> =
        acr_values.iter().filter(|v| producible(v)).collect();
    if !made.is_empty() && made.iter().all(|v| *v == PHRH) {
        PHRH.to_string()
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_essential_acr_claim_is_a_requirement() {
        let mut q = Map::new();
        q.insert(
            "claims".into(),
            json!(
                r#"{"id_token":{"acr":{"essential":true,"values":["x:y"]}}}"#
            ),
        );
        let need = requirement_of(&q, &json!({}));
        assert_eq!(need.acr_values, vec!["x:y".to_string()]);
        assert!(need.present);
        let assessed =
            assess_session(&need, &json!({ "acr": "1" }), false, 600, 10.0);
        assert!(!assessed.met);
        assert_eq!(unmet_refusal(&need, &assessed, true).1, "login_required");
    }

    #[test]
    fn a_stronger_level_meets_a_weaker_request() {
        assert!(meets("1", &json!({ "acr": "mfa" })));
        assert!(!meets("mfa", &json!({ "acr": "1" })));
        assert!(meets(
            "hwk",
            &json!({ "acr": "mfa", "amr": ["pwd", "hwk"] })
        ));
        assert_eq!(parse_max_age("0"), Some(0));
        assert_eq!(parse_max_age("1e3"), None);
    }
}
