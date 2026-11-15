// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! WHAT EACH CREDENTIAL EARNS: the `amr` (RFC 8176), the `acr`, and the
//! credential context an authentication event carries — what `authn.ts`
//! hands `startSession()` at each door once a credential checked here has
//! verified, and what [`crate::phishing`] reads for EAP's `phr` and `phrh`.
//!
//! THE PORT BETWEEN THIS SLICE AND THE SESSION'S. `authn/`'s session is THE
//! identity and a credential is EVIDENCE on one of its events
//! (`authn/CLAUDE.md`). The session record is the session slice's
//! (`sts-authn`, still being written); this module is the narrowest thing
//! it needs from here: [`Evidence`] is exactly the three arguments a door
//! passes `startSession()` about the credential — `amr`, `acr` and
//! `said.credential` — and nothing about the session.
//!
//! The rules, each where `authn.ts` writes it inline:
//!
//! | Door | `amr` | `acr` |
//! |---|---|---|
//! | the password (`finishLogin`) | `pwd` | `1` |
//! | a passkey alone (`finishWebauthn`, passwordless) | `hwk` | `1` |
//! | a discoverable passkey (`finishDiscoverable`) | `hwk user` | `mfa` |
//! | a key after a first factor | first, `hwk` once | `mfa` |
//! | an authenticator app (`/authn/totp`) | first + `otp` | `mfa` |
//! | a recovery code (`/authn/backup-code`) | first + `otp` | `mfa` |
//! | an emailed code or link, second | first + `otp` once | `mfa` |
//! | an emailed code or link, first | `otp` | `1` |
//! | a client certificate, first | `swk` | `1` |
//!
//! `acr "1"` for a passkey alone is deliberate: the ceremony asks user
//! verification `preferred`, so the key proves possession and nothing about
//! the person holding it. An authenticator app or a recovery code is never a
//! first factor, so the first factor's `amr` is always there (`pwd` unless
//! the step says otherwise, `firstAmrOf()`).

use serde_json::{json, Map, Value as Json};

use crate::js;

/// What a verified credential puts on its authentication event.
#[derive(Debug, Clone, PartialEq)]
pub struct Evidence {
    pub amr: Vec<String>,
    pub acr: String,
    /// `said.credential`: `{ kind, … }`.
    pub credential: Json,
}

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_string()).collect()
}

/// `firstAmrOf(step)`: the step's own first-factor `amr`, else `pwd`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn first_amr_of(step: &Json) -> Vec<String> {
    match step.get("firstAmr").and_then(Json::as_array) {
        Some(list) if !list.is_empty() => list.iter().map(js::string).collect(),
        _ => strings(&["pwd"]),
    }
}

/// `methodPhraseFor(amr)`: the sign-in method in words, for the audit row
/// and the session pages.
#[tracing::instrument(level = "debug", skip_all)]
pub fn method_phrase_for(amr: &[String]) -> String {
    let has = |v: &str| amr.iter().any(|a| a == v);
    let (key, password, code) = (has("hwk"), has("pwd"), has("otp"));
    if has("pop") {
        "a wallet (a verifiable presentation, proof of possession of the \
         holder key)"
    } else if key && password {
        "sign-in screen (password and a security key)"
    } else if key {
        "sign-in screen (a security key alone, passwordless)"
    } else if code && password {
        "sign-in screen (password and a one-time code)"
    } else if code {
        "sign-in screen (a one-time code alone — an emailed code or link)"
    } else {
        "sign-in screen (password)"
    }
    .to_string()
}

/// `Credentials.aaguidString(value)`: a UUID, or empty for none or the
/// all-zero AAGUID.
#[tracing::instrument(level = "debug", skip_all)]
pub fn aaguid_string(value: &str) -> String {
    let hex: String = value.to_lowercase().replace('-', "");
    if hex.len() != 32
        || !hex.chars().all(|c| c.is_ascii_hexdigit())
        || hex.chars().all(|c| c == '0')
    {
        return String::new();
    }
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// `Credentials.keyLane(key)`: `pqc` or `classical`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn key_lane(key: &Json) -> String {
    if key.get("lane").and_then(Json::as_str) == Some("pqc") {
        "pqc".to_string()
    } else {
        "classical".to_string()
    }
}

/// The WebAuthn credential context of an event (`finishWebauthn()`,
/// `finishDiscoverable()`): the stored key, the ceremony's verdict flags and
/// algorithm, and whether this was a REGISTRATION (which earns no `phr`).
#[tracing::instrument(level = "debug", skip_all)]
pub fn webauthn_credential(key: &Json, verdict: &Json, ceremony: &str) -> Json {
    let flags = verdict.get("flags").cloned().unwrap_or(json!({}));
    let mut out = Map::new();
    out.insert("kind".into(), json!("webauthn"));
    out.insert(
        "id".into(),
        json!(js::string_or(key.get("credentialId"), "")),
    );
    out.insert(
        "aaguid".into(),
        json!(match key.get("aaguid").filter(|v| js::truthy(v)) {
            Some(a) => aaguid_string(&js::string(a)),
            None => String::new(),
        }),
    );
    if let Some(Json::Bool(be)) = flags.get("be") {
        out.insert("backupEligible".into(), json!(be));
    }
    if let Some(Json::Bool(bs)) = flags.get("bs") {
        out.insert("backupState".into(), json!(bs));
    }
    out.insert(
        "algorithm".into(),
        json!(js::string_or(verdict.get("algorithm"), "")),
    );
    let cose = js::number_opt(verdict.get("coseAlg"));
    if cose != 0.0 && !cose.is_nan() {
        out.insert("coseAlg".into(), js::num(cose));
    }
    out.insert("lane".into(), json!(key_lane(key)));
    out.insert("ceremony".into(), json!(ceremony));
    out.insert(
        "attestationTrusted".into(),
        json!(
            key.get("attestation").and_then(|a| a.get("trusted"))
                == Some(&Json::Bool(true))
        ),
    );
    Json::Object(out)
}

impl Evidence {
    /// The password, at the sign-in screen.
    #[tracing::instrument(level = "debug")]
    pub fn password() -> Evidence {
        Evidence {
            amr: strings(&["pwd"]),
            acr: "1".to_string(),
            credential: json!({ "kind": "password" }),
        }
    }

    /// A passkey as the only factor: `hwk`, acr `1`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn passkey_alone(credential: Json) -> Evidence {
        Evidence {
            amr: strings(&["hwk"]),
            acr: "1".to_string(),
            credential,
        }
    }

    /// A discoverable passkey, the authenticator having verified the
    /// person: `hwk` and `user`, acr `mfa`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn discoverable_passkey(credential: Json) -> Evidence {
        Evidence {
            amr: strings(&["hwk", "user"]),
            acr: "mfa".to_string(),
            credential,
        }
    }

    /// A key after a first factor: the first's `amr`, `hwk` once.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn key_after(step: &Json, credential: Json) -> Evidence {
        let mut amr: Vec<String> = first_amr_of(step)
            .into_iter()
            .filter(|a| a != "hwk")
            .collect();
        amr.push("hwk".to_string());
        Evidence {
            amr,
            acr: "mfa".to_string(),
            credential,
        }
    }

    /// An authenticator app's code after the first factor.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn totp_after(step: &Json) -> Evidence {
        let mut amr = first_amr_of(step);
        amr.push("otp".to_string());
        Evidence {
            amr,
            acr: "mfa".to_string(),
            credential: json!({ "kind": "totp" }),
        }
    }

    /// A recovery code after the first factor (`otp` is RFC 8176's nearest
    /// value, and the audit row says which mechanism it was).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn recovery_code_after(step: &Json) -> Evidence {
        let mut amr = first_amr_of(step);
        amr.push("otp".to_string());
        Evidence {
            amr,
            acr: "mfa".to_string(),
            credential: json!({ "kind": "backup-code" }),
        }
    }

    /// An emailed code or link (`kind` `code` or `link`) after the first
    /// factor: `otp` once.
    #[tracing::instrument(level = "debug", skip(step))]
    pub fn email_after(step: &Json, kind: &str) -> Evidence {
        let mut amr = first_amr_of(step);
        if !amr.iter().any(|a| a == "otp") {
            amr.push("otp".to_string());
        }
        Evidence {
            amr,
            acr: "mfa".to_string(),
            credential: json!({ "kind": format!("email-{kind}") }),
        }
    }

    /// An emailed code or link as the first factor.
    #[tracing::instrument(level = "debug")]
    pub fn email_first(kind: &str) -> Evidence {
        Evidence {
            amr: strings(&["otp"]),
            acr: "1".to_string(),
            credential: json!({ "kind": format!("email-{kind}") }),
        }
    }

    /// A client certificate as the first factor (`swk`).
    #[tracing::instrument(level = "debug")]
    pub fn certificate_first(credential_id: &str) -> Evidence {
        Evidence {
            amr: strings(&["swk"]),
            acr: "1".to_string(),
            credential: json!({ "kind": "certificate", "id": credential_id }),
        }
    }

    /// `startSession(res, username, amr, acr, via, detail, req)` with this
    /// evidence: the door's own `detail` members kept, `credential` set to
    /// what verified. `None` is a refused session; the refusal's members
    /// (`refusedWith`, `refusedWhy`, `recoveryLimited`, `postLogin`,
    /// `riskStepUp`) are then on `detail`, as Node leaves them.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn start_session(
        &self,
        sessions: &sts_authn::Sessions,
        response: &mut sts_authn::ports::Response,
        username: &str,
        via: &str,
        detail: &mut sts_authn::js::Object,
        request: Option<&sts_authn::ports::Request>,
    ) -> Option<Json> {
        detail.insert("credential".to_string(), self.credential.clone());
        sessions.start_session(
            response, username, &self.amr, &self.acr, via, detail, request,
        )
    }

    /// The event as `phishing_resistance.ts` reads it, for this crate's own
    /// question of what the evidence earns.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn phishing_classes(&self) -> Vec<String> {
        crate::phishing::PhishingResistance::of_event(&json!({
            "authority": { "kind": "local" },
            "context": { "credential": self.credential },
            "amr": self.amr, "acr": self.acr }))
    }
}
