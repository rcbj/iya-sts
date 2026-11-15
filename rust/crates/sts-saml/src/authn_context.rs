// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! HOW A SESSION AUTHENTICATED, IN BOTH SAML VOCABULARIES
//! (`saml/authn_context.ts`): one reading of the session's `amr`, `acr` and
//! door, answered once for SAML 2.0, SAML 1.1 and WS-Federation. The order
//! of the tests is Node's rule — two factors, Kerberos, a key alone, a TLS
//! certificate, a password, nothing — and a federated session carries what
//! its partner said, translated where the two vocabularies mean the same.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use crate::model;

/// SAML 2.0's unspecified class.
pub const AC_UNSPECIFIED: &str =
    "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";

/// The class URIs, from the model.
pub mod uri {
    use crate::model::term;

    #[tracing::instrument(level = "debug")]
    pub fn password_protected() -> &'static str {
        term("saml2.authnContext", "passwordProtectedTransport")
    }
    #[tracing::instrument(level = "debug")]
    pub fn kerberos() -> &'static str {
        term("saml2.authnContext", "kerberos")
    }
    #[tracing::instrument(level = "debug")]
    pub fn tls_client() -> &'static str {
        term("saml2.authnContext", "tlsClient")
    }
    #[tracing::instrument(level = "debug")]
    pub fn multifactor() -> &'static str {
        term("saml2.authnContext", "multipleAuthn")
    }
    #[tracing::instrument(level = "debug")]
    pub fn am(name: &str) -> &'static str {
        term("saml11.authnMethod", name)
    }
}

/// `{ kind, saml2, saml11, multiFactor, hardwareKey }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthnReading {
    pub kind: &'static str,
    pub saml2: String,
    pub saml11: String,
    pub multi_factor: bool,
    pub hardware_key: bool,
}

fn result(
    kind: &'static str,
    saml2: &str,
    saml11: &str,
    multi_factor: bool,
    hardware_key: bool,
) -> AuthnReading {
    AuthnReading {
        kind,
        saml2: saml2.to_string(),
        saml11: saml11.to_string(),
        multi_factor,
        hardware_key,
    }
}

/// What a session says about itself, as `forSession()` reads it.
#[derive(Clone, Debug, Default)]
pub struct SessionFacts {
    pub authenticated: bool,
    pub amr: Vec<String>,
    pub acr: String,
    pub via: String,
}

fn equivalents(from: &str, to: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Some(terms) =
        model::model()["vocabularies"][from]["terms"].as_array()
    {
        for t in terms {
            if let (Some(v), Some(eq)) =
                (t["value"].as_str(), t["equivalent"].as_str())
            {
                out.insert(v.to_string(), model::term(to, eq).to_string());
            }
        }
    }
    out
}

static SAML2_TO_SAML11: LazyLock<BTreeMap<String, String>> =
    LazyLock::new(|| equivalents("saml2.authnContext", "saml11.authnMethod"));
static SAML11_TO_SAML2: LazyLock<BTreeMap<String, String>> =
    LazyLock::new(|| equivalents("saml11.authnMethod", "saml2.authnContext"));

fn prefix(id: &str) -> String {
    model::model()["vocabularies"][id]["prefix"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

fn own_sign_in(amr: &[String], acr: &str, via: &str) -> AuthnReading {
    let has = |v: &str| amr.iter().any(|a| a == v);
    let hardware_key = has("hwk");
    let password = has("pwd");
    let code = has("otp");
    let kerberos = via.to_lowercase().contains("kerberos");
    if (hardware_key && password)
        || (code && password)
        || acr.to_lowercase() == "mfa"
    {
        return result(
            "multi-factor",
            uri::multifactor(),
            uri::multifactor(),
            true,
            hardware_key,
        );
    }
    if kerberos {
        return result(
            "kerberos",
            uri::kerberos(),
            uri::am("kerberos"),
            false,
            hardware_key,
        );
    }
    if hardware_key {
        return result(
            "hardware-key",
            AC_UNSPECIFIED,
            uri::am("hardwareToken"),
            false,
            true,
        );
    }
    if has("swk") {
        return result(
            "certificate",
            uri::tls_client(),
            uri::am("tlsClient"),
            false,
            false,
        );
    }
    if password {
        return result(
            "password",
            uri::password_protected(),
            uri::am("password"),
            false,
            false,
        );
    }
    result("none", AC_UNSPECIFIED, uri::am("unspecified"), false, false)
}

fn federated_sign_in(amr: &[String], acr: &str) -> AuthnReading {
    let partner: Vec<String> =
        amr.iter().filter(|a| *a != "federated").cloned().collect();
    let said = acr.trim();
    let hwk = partner.iter().any(|a| a == "hwk");
    let unspecified11 = uri::am("unspecified");
    if said == uri::multifactor() {
        return result("federated", said, said, true, hwk);
    }
    if !prefix("saml2.authnContext").is_empty()
        && said.starts_with(&prefix("saml2.authnContext"))
    {
        let m = SAML2_TO_SAML11
            .get(said)
            .map(String::as_str)
            .unwrap_or(unspecified11);
        return result("federated", said, m, false, hwk);
    }
    if (!prefix("saml11.authnMethod").is_empty()
        && said.starts_with(&prefix("saml11.authnMethod")))
        || SAML11_TO_SAML2.contains_key(said)
    {
        let c = SAML11_TO_SAML2
            .get(said)
            .map(String::as_str)
            .unwrap_or(AC_UNSPECIFIED);
        return result("federated", c, said, false, hwk);
    }
    if !partner.is_empty() || said.to_lowercase() == "mfa" {
        let read = own_sign_in(&partner, said, "");
        return AuthnReading {
            kind: "federated",
            ..read
        };
    }
    result("federated", AC_UNSPECIFIED, unspecified11, false, false)
}

/// `authnContext.forSession(session)`; `None` is no session.
#[tracing::instrument(level = "debug", skip_all)]
pub fn for_session(session: Option<&SessionFacts>) -> AuthnReading {
    let Some(s) = session.filter(|s| s.authenticated) else {
        return result(
            "none",
            AC_UNSPECIFIED,
            uri::am("unspecified"),
            false,
            false,
        );
    };
    if s.amr.iter().any(|a| a == "federated") {
        return federated_sign_in(&s.amr, &s.acr);
    }
    own_sign_in(&s.amr, &s.acr, &s.via)
}
