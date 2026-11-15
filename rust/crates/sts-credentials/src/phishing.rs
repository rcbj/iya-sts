// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What EARNS OpenID Connect EAP's `phr` and `phrh`: a port of
//! `common/phishing_resistance.ts` (`common/CLAUDE.md` 3cp).
//!
//! `phr` is earned by an origin-bound ceremony — a WebAuthn ASSERTION (a
//! key enrolled in the same act proves nothing yet) or a client
//! certificate; `phrh` only by an assertion from a key whose attestation
//! chained to an anchor this realm holds AND that is not backup-eligible,
//! because a synced passkey is copied by its provider. A federated sign-in
//! carries the partner's own `acr`, and nothing else. Every function reads
//! an authentication event (or a session's latest) as the session record
//! holds it, so these are the same answers on every node.

use serde_json::Value as Json;

use crate::js;

/// The two classes.
pub const PHR: &str = "phr";
pub const PHRH: &str = "phrh";
/// The fact a sign-in that earned neither records.
pub const NONE: &str = "none";
/// The same classes as a SAML AuthnContextClassRef or WS-Federation `wauth`.
pub const URI_PHR: &str =
    "http://schemas.openid.net/pape/policies/2007/06/phishing-resistant";
pub const URI_PHRH: &str =
    "http://schemas.openid.net/acr/2016/07/phishing-resistant-hardware";

fn text_of(v: Option<&Json>) -> String {
    js::string_or(v, "")
}

fn classes(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_string()).collect()
}

/// `PhishingResistance`, as a namespace.
pub struct PhishingResistance;

impl PhishingResistance {
    /// `isClass(value)`.
    #[tracing::instrument(level = "debug")]
    pub fn is_class(value: &str) -> bool {
        value == PHR || value == PHRH
    }

    /// `ofEvent(event)`: the classes one authentication event earned.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn of_event(event: &Json) -> Vec<String> {
        if event.get("authenticated") == Some(&Json::Bool(false)) {
            return Vec::new();
        }
        let authority =
            text_of(event.get("authority").and_then(|a| a.get("kind")));
        if authority == "federation" {
            return PhishingResistance::of_acr(event.get("acr"));
        }
        if authority != "local" {
            return Vec::new();
        }
        let empty = Json::Null;
        let credential = event
            .get("context")
            .and_then(|c| c.get("credential"))
            .filter(|c| js::truthy(c))
            .unwrap_or(&empty);
        let kind = text_of(credential.get("kind"));
        if kind == "certificate" {
            return classes(&[PHR]);
        }
        if kind != "webauthn"
            || credential.get("ceremony").and_then(Json::as_str)
                == Some("registration")
        {
            return Vec::new();
        }
        let hardware = credential.get("attestationTrusted")
            == Some(&Json::Bool(true))
            && credential.get("backupEligible") == Some(&Json::Bool(false));
        if hardware {
            classes(&[PHR, PHRH])
        } else {
            classes(&[PHR])
        }
    }

    /// `latestEventOf(session)`: the last event that authenticated.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn latest_event_of(session: &Json) -> Option<&Json> {
        let events = session.get("events").and_then(Json::as_array)?;
        events.iter().rev().find(|e| {
            js::truthy(e) && e.get("authenticated") != Some(&Json::Bool(false))
        })
    }

    /// `ofSession(session)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn of_session(session: &Json) -> Vec<String> {
        PhishingResistance::latest_event_of(session)
            .map(PhishingResistance::of_event)
            .unwrap_or_default()
    }

    /// `ofAcr(acr)`: a partner's own `acr`, read as these classes.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn of_acr(acr: Option<&Json>) -> Vec<String> {
        let said = match acr {
            None | Some(Json::Null) => String::new(),
            Some(v) => js::string(v),
        };
        if said == PHRH {
            classes(&[PHR, PHRH])
        } else if said == PHR {
            classes(&[PHR])
        } else {
            Vec::new()
        }
    }

    /// `hardwareShortfallOf(session)`: why the latest sign-in did not earn
    /// `phrh`, in a sentence; empty when it did.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn hardware_shortfall_of(session: &Json) -> String {
        let event = PhishingResistance::latest_event_of(session);
        let empty = Json::Null;
        let credential = event
            .and_then(|e| e.get("context"))
            .and_then(|c| c.get("credential"))
            .filter(|c| js::truthy(c))
            .unwrap_or(&empty);
        let earned = event
            .map(PhishingResistance::of_event)
            .unwrap_or_else(|| PhishingResistance::of_event(&Json::Null));
        let kind = text_of(credential.get("kind"));
        if earned.iter().any(|c| c == PHRH) {
            String::new()
        } else if kind == "certificate" {
            "the sign-in was a client certificate, and nothing this service \
             holds says its private key is in hardware"
                .to_string()
        } else if kind != "webauthn" {
            "the sign-in was not a phishing-resistant ceremony".to_string()
        } else if credential.get("backupEligible") != Some(&Json::Bool(false)) {
            if credential.get("backupEligible") == Some(&Json::Bool(true)) {
                "the passkey is backup-eligible (BE set): a synced passkey is \
                 copied by its provider, not held in one hardware component"
                    .to_string()
            } else {
                "the passkey did not report its backup eligibility".to_string()
            }
        } else {
            "the passkey's attestation is not trusted (none, self, or a chain \
             to no anchor this realm holds), so its hardware is the \
             authenticator's say-so"
                .to_string()
        }
    }

    /// `factOf(classes)`: the classes, or `none`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn fact_of(list: &[String]) -> Vec<String> {
        let out: Vec<String> = list
            .iter()
            .filter(|c| PhishingResistance::is_class(c))
            .cloned()
            .collect();
        if out.is_empty() {
            vec![NONE.to_string()]
        } else {
            out
        }
    }

    /// `storedKeyEarnsHardware(key)`: whether an assertion by this stored
    /// key would earn `phrh` (what `phrh` narrows `allowCredentials` to).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn stored_key_earns_hardware(key: &Json) -> bool {
        key.get("attestation").and_then(|a| a.get("trusted"))
            == Some(&Json::Bool(true))
            && key.get("backupEligible") == Some(&Json::Bool(false))
    }

    /// `classOfUri(uri)`.
    #[tracing::instrument(level = "debug")]
    pub fn class_of_uri(uri: &str) -> String {
        let text = js::trim(uri);
        if text == URI_PHR {
            PHR.to_string()
        } else if text == URI_PHRH {
            PHRH.to_string()
        } else {
            String::new()
        }
    }

    /// `uriOfClass(cls)`.
    #[tracing::instrument(level = "debug")]
    pub fn uri_of_class(cls: &str) -> String {
        if cls == PHRH {
            URI_PHRH.to_string()
        } else if cls == PHR {
            URI_PHR.to_string()
        } else {
            String::new()
        }
    }

    /// `uriList(value)`: a list or a string, split on spaces and commas.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn uri_list(value: &Json) -> Vec<String> {
        let raw: Vec<Json> = match value {
            Json::Array(items) => items.clone(),
            Json::Null => Vec::new(),
            Json::String(s) if s.is_empty() => Vec::new(),
            other => vec![other.clone()],
        };
        let mut out = Vec::new();
        for one in &raw {
            let text = match one {
                Json::Null => String::new(),
                v => js::string(v),
            };
            for part in text.split(|c: char| js::is_space(c) || c == ',') {
                let t = js::trim(part);
                if !t.is_empty() {
                    out.push(t.to_string());
                }
            }
        }
        out
    }

    /// `signInFor(uris)`: what a request naming only EAP classes demands
    /// of the sign-in — a key, and for `phrh` alone a hardware one.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn sign_in_for(uris: &Json) -> (bool, String, bool) {
        let list = PhishingResistance::uri_list(uris);
        let classes: Vec<String> = list
            .iter()
            .map(|u| PhishingResistance::class_of_uri(u))
            .collect();
        let eap_only =
            !list.is_empty() && classes.iter().all(|c| c == PHR || c == PHRH);
        let only_hardware = eap_only && classes.iter().all(|c| c == PHRH);
        (
            eap_only,
            if only_hardware {
                PHRH.to_string()
            } else {
                String::new()
            },
            eap_only,
        )
    }

    /// `eapDemandMet(session, uris)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn eap_demand_met(session: &Json, uris: &Json) -> bool {
        let (_, class, eap_only) = PhishingResistance::sign_in_for(uris);
        if !eap_only {
            return true;
        }
        let earned = PhishingResistance::of_session(session);
        if class == PHRH {
            earned.iter().any(|c| c == PHRH)
        } else {
            earned.iter().any(|c| c == PHR)
        }
    }

    /// `assertionUri(session, uris)`: the class URI an assertion names,
    /// where one was asked and earned.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn assertion_uri(session: &Json, uris: &Json) -> String {
        let asked: Vec<String> = PhishingResistance::uri_list(uris)
            .iter()
            .map(|u| PhishingResistance::class_of_uri(u))
            .collect();
        let earned = PhishingResistance::of_session(session);
        let has = |l: &[String], c: &str| l.iter().any(|x| x == c);
        if has(&asked, PHRH) && has(&earned, PHRH) {
            URI_PHRH.to_string()
        } else if has(&asked, PHR) && has(&earned, PHR) {
            URI_PHR.to_string()
        } else {
            String::new()
        }
    }
}
