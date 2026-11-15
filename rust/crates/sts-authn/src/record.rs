// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE SESSION RECORD AND ITS EVENTS (`authn/CLAUDE.md`, *What an
//! authenticated identity is here*): a SUBJECT (`urn:uuid:<entryUUID>`), a
//! list of AUTHENTICATION EVENTS, and a SESSION with a stable `sid` and a
//! rotating cookie handle. Every artifact this service issues is a
//! projection of it; every credential it accepts is evidence on an event.
//!
//! The row is held as Node's JSON object, member for member and in Node's
//! order, because a 1.x install's sessions are live in this runtime and
//! Node reads this runtime's (D11): ten modules write members onto a
//! session (`oidcClients`, `saml2ServiceProviders`, `dbsc`, …) and a typed
//! struct would drop what it did not name. What a reader asks of a session
//! — the D15 shape — is [`view`], `sts_model`'s `Session` concept, read
//! from the row the way `DomainClasses.Session.fromRecord()` reads it.

use serde_json::{json, Value};
use sts_model::domain::{AuthenticationEvent, Session};

use crate::js::{self, Object};

/// The sign-on cookie (`SESSION_COOKIE`), `<sid>.<handle>` on the wire.
pub const SESSION_COOKIE: &str = "sts_session";

/// The one name every unauthenticated session carries
/// (`ANONYMOUS_USERNAME`).
pub const ANONYMOUS_USERNAME: &str = "anonymous";

/// How many events a session keeps: the first, and the most recent after it
/// (`MAX_SESSION_EVENTS`); `eventsDropped` counts the rest.
pub const MAX_SESSION_EVENTS: usize = 20;

/// The protocol a sign-in names when its door names none.
pub const DEFAULT_VIA: &str = "OAuth 2.0 / OIDC";

/// `methodPhraseFor(amr)`: how the identity register and the audit log say
/// what an authentication was.
#[tracing::instrument(level = "debug")]
pub fn method_phrase_for(amr: &[String]) -> String {
    let has = |f: &str| amr.iter().any(|a| a == f);
    let key = has("hwk");
    let password = has("pwd");
    let code = has("otp");
    let phrase = if has("pop") {
        "a wallet (a verifiable presentation, proof of possession of the \
         holder key)"
    } else if key && password {
        "sign-in screen (password and a security key)"
    } else if key {
        "sign-in screen (a security key alone, passwordless)"
    } else if code && password {
        "sign-in screen (password and a one-time code)"
    } else if code {
        "sign-in screen (a one-time code alone \u{2014} an emailed code or link)"
    } else {
        "sign-in screen (password)"
    };
    phrase.to_string()
}

/// `subjectIdOf(user)`: the subject a session is filed under and capped by,
/// frozen at creation — the `urn:uuid` sub, otherwise the username.
#[tracing::instrument(level = "debug", skip(user))]
pub fn subject_id_of(user: Option<&Value>) -> String {
    let user = user.and_then(Value::as_object);
    let sub = user.map(|u| js::or_empty(u.get("sub"))).unwrap_or_default();
    if sub
        .get(..9)
        .is_some_and(|p| p.eq_ignore_ascii_case("urn:uuid:"))
    {
        return sub;
    }
    user.map(|u| js::or_empty(u.get("username")))
        .unwrap_or_default()
}

/// `authorityOf(detail)`: who vouched for an authentication — this service,
/// a federation partner, or a Kerberos ticket.
#[tracing::instrument(level = "debug", skip(detail))]
pub fn authority_of(detail: &Object) -> Value {
    let federation = js::object_of(detail.get("federation"));
    if js::truthy(federation.get("id")) {
        let category = match js::or_empty(federation.get("category")) {
            c if c.is_empty() => "enterprise".to_string(),
            c => c,
        };
        let verified = if federation.get("mailVerified") == Some(&json!(false))
        {
            "false"
        } else {
            "true"
        };
        return json!({
            "kind": "federation",
            "id": js::string_of(federation.get("id")),
            "peer": js::or_empty(federation.get("peer")),
            "subject": js::or_empty(federation.get("subject")),
            "category": category,
            "provider": js::or_empty(federation.get("provider")),
            "emailVerified": verified,
        });
    }
    if detail.get("protocol") == Some(&json!("Kerberos v5"))
        && js::truthy(detail.get("presented"))
    {
        return json!({
            "kind": "kerberos",
            "principal": js::string_of(detail.get("presented")),
        });
    }
    json!({"kind": "local"})
}

/// `phishingEvidenceOf(given)`: the credential facts OpenID Connect EAP's
/// `phr` and `phrh` are read from (#723), as the issuance policy is asked
/// them before the event exists.
#[tracing::instrument(level = "debug", skip(given))]
pub fn phishing_evidence_of(given: Option<&Value>) -> Object {
    let g = js::object_of(given);
    let mut out = Object::new();
    if let Some(c @ Value::String(s)) = g.get("ceremony") {
        if s == "assertion" || s == "registration" {
            out.insert("ceremony".into(), c.clone());
        }
    }
    for k in ["attestationTrusted", "backupEligible"] {
        if let Some(b @ Value::Bool(_)) = g.get(k) {
            out.insert(k.into(), b.clone());
        }
    }
    out
}

/// The facts of a request an event records (`eventContext()`), computed
/// by the service and handed here: the digests are `sts_crypto`'s.
#[derive(Debug, Clone, Default)]
pub struct Context {
    pub address: String,
    pub ua_fingerprint: String,
    pub ja4: String,
    pub tls_stack: String,
    pub device: String,
}

/// `eventContext(detail)`'s `credential`: which credential answered, as a
/// fingerprint and the facts its door read.
#[tracing::instrument(level = "debug", skip(given, fingerprint))]
pub fn credential_context(
    given: Option<&Value>,
    fingerprint: impl Fn(&str) -> String,
) -> Object {
    let g = js::object_of(given);
    let mut c = Object::new();
    if js::truthy(g.get("kind")) {
        c.insert("kind".into(), json!(js::string_of(g.get("kind"))));
    }
    if js::truthy(g.get("id")) {
        c.insert(
            "fingerprint".into(),
            json!(fingerprint(&js::string_of(g.get("id")))),
        );
    }
    for k in ["relationship", "aaguid"] {
        if js::truthy(g.get(k)) {
            c.insert(k.into(), json!(js::string_of(g.get(k))));
        }
    }
    for k in ["backupEligible", "backupState"] {
        if let Some(b @ Value::Bool(_)) = g.get(k) {
            c.insert(k.into(), b.clone());
        }
    }
    if js::truthy(g.get("algorithm")) {
        c.insert("algorithm".into(), json!(js::string_of(g.get("algorithm"))));
    }
    if let Some(n @ Value::Number(_)) = g.get("coseAlg") {
        c.insert("coseAlg".into(), n.clone());
    }
    if let Some(Value::String(lane)) = g.get("lane") {
        if lane == "classical" || lane == "pqc" {
            c.insert("lane".into(), json!(lane));
        }
    }
    if let Some(Value::String(s)) = g.get("ceremony") {
        if s == "assertion" || s == "registration" {
            c.insert("ceremony".into(), json!(s));
        }
    }
    if let Some(b @ Value::Bool(_)) = g.get("attestationTrusted") {
        c.insert("attestationTrusted".into(), b.clone());
    }
    c
}

impl Context {
    /// The event's `context` member.
    pub fn json(&self, credential: Object) -> Value {
        json!({
            "address": self.address,
            "uaFingerprint": self.ua_fingerprint,
            "ja4": self.ja4,
            "tlsStack": self.tls_stack,
            "device": self.device,
            "credential": credential,
        })
    }
}

/// The event Node invents for a session written before events existed,
/// so that a re-authentication of it has a first event to keep.
#[tracing::instrument(level = "debug", skip(session))]
pub fn unrecorded_event(session: &Object) -> Value {
    json!({
        "at": js::num(js::number_or_zero(session.get("authTime"))),
        "amr": session.get("amr").cloned().unwrap_or(json!([])),
        "acr": js::or_empty(session.get("acr")),
        "via": js::or_empty(session.get("via")),
        "authenticated": true,
        "authority": {"kind": "unrecorded"},
        "evidence": "",
        "context": {
            "address": "", "uaFingerprint": "", "ja4": "",
            "credential": {},
        },
    })
}

/// `Authn.sessionView(session)`: the `Session` concept, read from the row.
/// A member the model names and the row lacks reads as its empty value.
#[tracing::instrument(level = "debug", skip(session))]
pub fn view(session: Option<&Object>) -> Session {
    let empty = Object::new();
    let s = session.unwrap_or(&empty);
    let int = |k: &str| {
        let n = js::number(s.get(k));
        if n.is_finite() {
            n as i64
        } else {
            0
        }
    };
    let text = |k: &str| match s.get(k) {
        Some(Value::String(t)) => t.clone(),
        Some(Value::Null) | None => String::new(),
        Some(v) => js::text(v),
    };
    let opt_text = |v: Option<&Value>| match v {
        Some(Value::String(t)) => Some(t.clone()),
        _ => None,
    };
    let user = js::object_of(s.get("user"));
    let events = match s.get("events") {
        Some(Value::Array(list)) => list
            .iter()
            .map(|e| {
                let e = js::object_of(Some(e));
                AuthenticationEvent {
                    at: js::number_or_zero(e.get("at")) as i64,
                    methods: e.get("amr").and_then(|a| {
                        a.as_array().map(|_| js::strings(Some(a)))
                    }),
                    assurance_level: opt_text(e.get("acr")),
                    protocol: js::or_empty(e.get("via")),
                    authenticated: e.get("authenticated")
                        == Some(&Value::Bool(true)),
                    authority_kind: opt_text(
                        e.get("authority").and_then(|a| a.get("kind")),
                    ),
                }
            })
            .collect(),
        _ => Vec::new(),
    };
    Session {
        id: text("id"),
        username: js::or_empty(user.get("username")),
        subject_id: text("subjectId"),
        authenticated: s.get("authenticated") == Some(&Value::Bool(true)),
        auth_time: int("authTime"),
        methods: s
            .get("amr")
            .and_then(|a| a.as_array().map(|_| js::strings(Some(a)))),
        assurance_level: opt_text(s.get("acr")),
        started_through: text("via"),
        started_at: int("startedAt"),
        expires: int("expires"),
        last_seen_at: int("lastSeenAt"),
        events,
        events_dropped: s.get("eventsDropped").map(|_| int("eventsDropped")),
        sub: opt_text(user.get("sub")),
        derived_from: opt_text(s.get("derivedFrom")),
        relying_party_surface: opt_text(s.get("rpSurface")),
        relying_party_label: opt_text(s.get("rpLabel")),
        relying_party_client_id: opt_text(s.get("rpClientId")),
        relying_party_renewals: s.get("rpRenewals").map(|_| int("rpRenewals")),
        relying_party_renewed_at: s
            .get("rpRenewedAt")
            .map(|_| int("rpRenewedAt")),
        api_calls: s.get("calls").map(|_| int("calls")),
        account_set_id: opt_text(s.get("accountSetId")),
    }
}

/// `sessionStartedAt(session)`: when a session BEGAN, in milliseconds — its
/// first event, else its `authTime` (which is its LATEST authentication
/// since 2026-09-14).
#[tracing::instrument(level = "debug", skip(session))]
pub fn started_at(session: Option<&Object>) -> i64 {
    let v = view(session);
    let first = v.events.first().map(|e| e.at).filter(|at| *at != 0);
    first.unwrap_or(v.auth_time) * 1000
}

/// `Authn.lastAuthenticatedAt(session)`: its latest event, else its
/// `authTime`, in seconds.
#[tracing::instrument(level = "debug", skip(session))]
pub fn last_authenticated_at(session: Option<&Object>) -> i64 {
    let v = view(session);
    v.events
        .last()
        .map(|e| e.at)
        .filter(|at| *at != 0)
        .unwrap_or(v.auth_time)
}

/// `attemptFacts(application, method)`: the two members every
/// authentication attempt's audit row starts its detail with.
#[tracing::instrument(level = "debug")]
pub fn attempt_facts(application: &str, method: &str) -> Object {
    let mut o = Object::new();
    o.insert("application".into(), json!(application));
    o.insert("method".into(), json!(method));
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(list: &[&str]) -> Vec<String> {
        list.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn the_method_phrases() {
        assert_eq!(
            method_phrase_for(&s(&["pwd"])),
            "sign-in screen (password)"
        );
        assert!(method_phrase_for(&s(&["pop", "pwd"])).starts_with("a wallet"));
        assert_eq!(
            method_phrase_for(&s(&["hwk", "pwd"])),
            "sign-in screen (password and a security key)"
        );
    }

    #[test]
    fn a_subject_is_the_uuid_or_the_name() {
        assert_eq!(
            subject_id_of(Some(&json!({"sub": "URN:UUID:x", "username": "a"}))),
            "URN:UUID:x"
        );
        assert_eq!(
            subject_id_of(Some(&json!({"sub": "x", "username": "a"}))),
            "a"
        );
        assert_eq!(subject_id_of(None), "");
    }
}
