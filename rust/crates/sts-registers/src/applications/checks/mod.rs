// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE VALUE CHECKS: `normaliseFields()`, the walk a create's attributes
//! take, and every per-attribute check it and `updateApplication()` call,
//! each answering Node's sentence word for word and the code Node marks.
//!
//! | Module | What it ports |
//! |---|---|
//! | [`oauth`] | the OAuth and OpenID metadata checks: introspection, request objects, response and request defaults, subject types, PAR, mutual TLS, GNAP's trust, step-up, AuthZEN, RFC 9396 types, FGA coverage |
//! | [`uris`] | the URI and name checks: permissions and their base, the resource metadata, the home page, `initiate_login_uri`, the client display URIs, return addresses, logout URIs, CORS origins, scope tokens, SSF events, delegation, Kerberos trust, self references |
//! | [`validation`] | `common/validation.js`'s `redirectUriProblem()`, `frontchannelUriProblem()`, `backchannelUriProblem()`, `normaliseOrigin()` |
//! | [`values`] | DIDs, claim rows and selections, permission claims, the closed choices, response and token response types, authentication methods, `oauthConfidential`, the setting overrides, SAML certificates, the hosted surfaces' session bounds |

pub mod oauth;
pub mod uris;
pub mod validation;
pub mod values;

use serde_json::Value;
use sts_core::errors::{codes, ErrorCode};

use super::record::{values_of, Fields};
use super::tables::Tables;
use super::ApplicationRegistry;

/// A refusal with the code its check decided.
#[derive(Debug, Clone, PartialEq)]
pub struct Coded {
    pub message: String,
    pub code: ErrorCode,
}

impl Coded {
    /// A sentence and its code.
    #[tracing::instrument(level = "debug", skip(message))]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Coded {
        Coded {
            message: message.into(),
            code,
        }
    }
}

/// What `normaliseFields()` answers: `{ok, fields, errors}`, marked with
/// the code of the FIRST refusal.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Normalised {
    pub fields: Fields,
    pub errors: Vec<String>,
    pub code: Option<ErrorCode>,
}

impl Normalised {
    /// `ok: !errors.length`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }
}

// A HOT PATH: every check's answer passes through it, so no span.
/// Node's '' for "no problem" as an `Option`.
pub fn nz(text: String) -> Option<String> {
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// The attributes a seal applies to (`SEALED_FIELDS`).
pub const SEALED_FIELDS: &[&str] = &[
    "oauthAssertionPrivateKey",
    "oauthSamlAssertionPrivateKey",
    "gnapSymmetricKey",
    "gnapMacaroonKey",
    "didPrivateKeys",
    "secretDestCredential",
    "scimClientPassword",
    "scimClientOAuthClientSecret",
    "scimClientTlsPrivateKey",
];

/// The client display members (`CLIENT_DISPLAY_ATTRIBUTES`).
pub const CLIENT_DISPLAY_ATTRIBUTES: &[&str] =
    &["oauthLogoUri", "oauthPolicyUri", "oauthTosUri"];

/// The return and logout addresses checked as URIs (`ADDRESS_ATTRIBUTES`)
/// and how each is checked.
pub const ADDRESS_ATTRIBUTES: &[(&str, &str)] = &[
    ("samlAssertionConsumerService", "saml"),
    ("oauthRedirectUri", "redirect"),
    ("oauthPostLogoutRedirectUri", "redirect"),
    ("oauthFrontchannelLogoutUri", "frontchannel"),
    ("oauthBackchannelLogoutUri", "backchannel"),
    ("oauthCommandEndpoint", "command"),
];

// A HOT PATH: every value of every write asks it, so no span.
/// `ADDRESS_ATTRIBUTES[name]`.
pub fn address_kind(name: &str) -> Option<&'static str> {
    ADDRESS_ATTRIBUTES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, k)| *k)
}

impl ApplicationRegistry {
    /// `sealFieldValue(name, value)`: a private key sealed under the
    /// key-encryption key where keys persist; `None` when it could not be.
    #[tracing::instrument(level = "debug", skip(self, value))]
    pub fn seal_field_value(&self, name: &str, value: &str) -> Option<String> {
        if !SEALED_FIELDS.contains(&name) || value.is_empty() {
            return Some(value.to_string());
        }
        if self.env.is_sealed(value) || !self.env.keystore_persists() {
            return Some(value.to_string());
        }
        self.env.seal(value, seal_label_of(name))
    }

    /// `normaliseFields(value)`: every non-empty attribute of a create
    /// checked, in the order given; the first refusal's code marks the
    /// answer.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn normalise_fields(&self, asked: &Fields) -> Normalised {
        let t = Tables::get();
        let mut out = Normalised::default();
        let mut code: Option<ErrorCode> = None;
        let note = |c: ErrorCode, code: &mut Option<ErrorCode>| {
            if code.is_none() {
                *code = Some(c);
            }
        };
        for (name, raw) in asked {
            let values = values_of(Some(raw));
            if values.is_empty() {
                continue;
            }
            let Some(row) = t.attribute(name) else {
                out.errors.push(format!(
                    "\"{}\" is not in the published schema. GET \
                     /admin/ldap/applications lists every attribute an \
                     entry may carry; adding one that is not there means \
                     adding a row to models/directory/application.tsp, not \
                     writing it through this.",
                    name
                ));
                note(codes::STS_REG_0006, &mut code);
                continue;
            };
            if row.editable.is_empty() && name != "oauthConfidential" {
                out.errors.push(format!(
                    "\"{}\" cannot be given here. It is DERIVED — what has \
                     happened to this application rather than what it may \
                     do — and an entry created with one would be asserting a \
                     past it does not have. It is accumulated by the \
                     protocol endpoints as they accept this identifier.",
                    name
                ));
                note(codes::STS_REG_0007, &mut code);
                continue;
            }
            if row.kind != "multi" && values.len() > 1 {
                out.errors.push(format!(
                    "\"{}\" holds ONE value and {} were given. It is \
                     single-valued in the published schema, so the \
                     alternative to refusing this is keeping one of them \
                     and discarding the rest silently.",
                    name,
                    values.len()
                ));
                note(codes::STS_REG_0008, &mut code);
                continue;
            }
            let first = values[0].clone();
            if name == "oauthConfidential" {
                let stated = values::stated_confidential(&first);
                if stated.is_empty() {
                    out.errors
                        .push(values::confidential_disagreement(&first, "FALSE"));
                    note(codes::STS_REG_0363, &mut code);
                    continue;
                }
                out.fields.insert(name.clone(), Value::String(stated));
                continue;
            }
            if name == "oauthPermissionBaseUri" {
                if let Some(problem) = uris::permission_base_problem(&first) {
                    out.errors.push(problem);
                    note(codes::STS_REG_0012, &mut code);
                    continue;
                }
            }
            if name == "oauthPermission" {
                let mut seen: Vec<String> = Vec::new();
                let mut problems: Vec<String> = Vec::new();
                for one in &values {
                    let parsed = uris::parse_permission_value(one);
                    if let Some(coded) = uris::permission_operator_code_problem(
                        &parsed.name,
                        &parsed.description,
                    ) {
                        problems.push(coded);
                        note(codes::STS_REG_0367, &mut code);
                        continue;
                    }
                    if let Some(problem) =
                        uris::permission_name_problem(&parsed.name)
                    {
                        problems.push(problem);
                        note(codes::STS_REG_0013, &mut code);
                    } else if seen.contains(&parsed.name) {
                        problems.push(format!(
                            "The permission \"{}\" is given twice. A \
                             permission has one description, so give it \
                             once.",
                            parsed.name
                        ));
                        note(codes::STS_REG_0014, &mut code);
                    }
                    seen.push(parsed.name.clone());
                }
                if problems.is_empty()
                    && crate::app_permissions::permission_base_of(
                        values_of(asked.get("oauthPermissionBaseUri"))
                            .first()
                            .map(|s| Value::String(s.clone()))
                            .as_ref(),
                    )
                    .is_empty()
                {
                    problems.push(
                        "A permission is named by the base URI followed by \
                         its name, and this create carries no \
                         `oauthPermissionBaseUri` — give one with the \
                         permissions."
                            .to_string(),
                    );
                    note(codes::STS_REG_0015, &mut code);
                }
                if !problems.is_empty() {
                    out.errors.extend(problems);
                    continue;
                }
            }
            if name == "oauthRoleGatedPermission" {
                let defined: Vec<String> =
                    values_of(asked.get("oauthPermission"))
                        .iter()
                        .map(|one| uris::parse_permission_value(one).name)
                        .collect();
                if let Some(missing) =
                    values.iter().find(|one| !defined.contains(one))
                {
                    out.errors.push(uris::role_gated_problem(missing));
                    note(codes::STS_REG_0090, &mut code);
                    continue;
                }
            }
            if name == "oauthResourceMetadata"
                || name == "oauthResourceMetadataUrl"
            {
                let problem = if name == "oauthResourceMetadata" {
                    uris::resource_metadata_problem(&first)
                } else {
                    uris::resource_metadata_url_problem(&first)
                };
                if let Some(problem) = problem {
                    out.errors.push(problem);
                    note(codes::STS_REG_0089, &mut code);
                    continue;
                }
            }
            if name == "appHomePageUrl" {
                if let Some(problem) = uris::home_page_problem(&first) {
                    out.errors.push(problem);
                    note(codes::STS_REG_0011, &mut code);
                    continue;
                }
            }
            if name == "oauthInitiateLoginUri" {
                if let Some(problem) = uris::initiate_login_uri_problem(&first)
                {
                    out.errors.push(problem);
                    note(codes::STS_REG_0188, &mut code);
                    continue;
                }
            }
            if CLIENT_DISPLAY_ATTRIBUTES.contains(&name.as_str()) {
                if let Some(problem) =
                    uris::client_display_uri_problem(name, &first)
                {
                    out.errors.push(problem);
                    note(codes::STS_REG_0365, &mut code);
                    continue;
                }
            }
            if name == "gnapOwnerLookupUri" {
                if let Some(problem) = uris::owner_lookup_uri_problem(&first) {
                    out.errors.push(problem);
                    note(codes::STS_REG_0334, &mut code);
                    continue;
                }
            }
            if address_kind(name).is_some() {
                let problems: Vec<String> = values
                    .iter()
                    .filter_map(|one| uris::address_problem(name, one))
                    .collect();
                if !problems.is_empty() {
                    out.errors.extend(problems);
                    note(codes::STS_REG_0071, &mut code);
                    continue;
                }
                if name == "oauthBackchannelLogoutUri" {
                    let method = values_of(
                        asked.get("oauthTokenEndpointAuthMethod"),
                    )
                    .into_iter()
                    .next()
                    .unwrap_or_default();
                    let truthy =
                        |k: &str| asked.get(k).is_some_and(crate::js::truthy);
                    let public = method == "none"
                        || (method.is_empty()
                            && !truthy("oauthClientSecret")
                            && !truthy("oauthJwks")
                            && !truthy("oauthJwksUri"));
                    if let Some(problem) =
                        uris::backchannel_scheme_problem(&first, public, &|u| {
                            self.effects.dial_problem(u)
                        })
                    {
                        out.errors.push(problem.message);
                        note(problem.code, &mut code);
                        continue;
                    }
                }
                if name == "oauthFrontchannelLogoutUri" {
                    if let Some(problem) = uris::frontchannel_origin_problem(
                        &first,
                        asked.get("oauthRedirectUri"),
                    ) {
                        out.errors.push(problem);
                        note(codes::STS_REG_0171, &mut code);
                        continue;
                    }
                }
            }
            if name == "appCorsOrigin" {
                let problems: Vec<String> = values
                    .iter()
                    .filter_map(|one| uris::cors_origin_write_problem(one))
                    .collect();
                if !problems.is_empty() {
                    out.errors.extend(problems);
                    note(codes::STS_REG_0150, &mut code);
                    continue;
                }
                let mut origins: Vec<Value> = Vec::new();
                for one in &values {
                    let o = Value::String(validation::normalise_origin(one));
                    if !origins.contains(&o) {
                        origins.push(o);
                    }
                }
                out.fields.insert(name.clone(), Value::Array(origins));
                continue;
            }
            if name == "oauthResponseType"
                || name == "oauthAllowedTokenResponseTypes"
            {
                let mut kept: Vec<Value> = Vec::new();
                for one in &values {
                    let c = values::canonical_response_type(one);
                    let v = Value::String(c.clone());
                    if !c.is_empty() && !kept.contains(&v) {
                        kept.push(v);
                    }
                }
                out.fields.insert(name.clone(), Value::Array(kept));
                continue;
            }
            if name == "oauthAllowedScope" {
                let problems: Vec<String> = values
                    .iter()
                    .filter_map(|one| uris::scope_token_problem(one))
                    .collect();
                if !problems.is_empty() {
                    out.errors.extend(problems);
                    note(codes::STS_REG_0172, &mut code);
                    continue;
                }
            }
            if name == "ssfAllowedEvents" {
                let problems: Vec<String> = values
                    .iter()
                    .filter_map(|one| {
                        uris::ssf_allowed_event_problem(one, &|u| {
                            self.effects.ssf_event_known(u)
                        })
                    })
                    .collect();
                if !problems.is_empty() {
                    out.errors.extend(problems);
                    note(codes::STS_REG_0053, &mut code);
                    continue;
                }
            }
            if let Some(problem) =
                oauth::introspection_attribute_problem(self, name, &first, asked)
            {
                out.errors.push(problem);
                note(codes::STS_REG_0073, &mut code);
                continue;
            }
            let problems: Vec<String> = values
                .iter()
                .filter_map(|one| {
                    oauth::request_object_attribute_problem(
                        self, name, one, asked,
                    )
                })
                .collect();
            if !problems.is_empty() {
                out.errors.extend(problems);
                note(codes::STS_REG_0101, &mut code);
                continue;
            }
            let problems: Vec<String> = values
                .iter()
                .filter_map(|one| {
                    uris::delegation_attribute_problem(self, name, one)
                })
                .collect();
            if !problems.is_empty() {
                out.errors.extend(problems);
                note(codes::STS_REG_0194, &mut code);
                continue;
            }
            let problems: Vec<String> = values
                .iter()
                .filter_map(|one| {
                    uris::kerberos_trust_attribute_problem(self, name, one, &|r| {
                        self.effects.kerberos_accepts_realm(r)
                    })
                })
                .collect();
            if !problems.is_empty() {
                out.errors.extend(problems);
                note(codes::STS_REG_0362, &mut code);
                continue;
            }
            if let Some(problem) =
                oauth::pushed_authorization_attribute_problem(self, name, &first)
            {
                out.errors.push(problem);
                note(codes::STS_REG_0121, &mut code);
                continue;
            }
            if let Some(problem) =
                oauth::oidc_subject_attribute_problem(self, name, &first, asked)
            {
                out.errors.push(problem);
                note(codes::STS_REG_0168, &mut code);
                continue;
            }
            if let Some(problem) =
                oauth::gnap_mtls_trust_problem(self, name, &first)
            {
                out.errors.push(problem.message);
                note(problem.code, &mut code);
                continue;
            }
            if let Some(problem) =
                oauth::mtls_attribute_problem(self, name, &first, asked)
            {
                out.errors.push(problem.message);
                note(problem.code, &mut code);
                continue;
            }
            if let Some(problem) = oauth::client_response_attribute_problem(
                self, name, &first, asked,
            ) {
                out.errors.push(problem);
                note(codes::STS_REG_0340, &mut code);
                continue;
            }
            if let Some(problem) =
                oauth::step_up_attribute_problem(self, name, &first)
            {
                out.errors.push(problem.message);
                note(problem.code, &mut code);
                continue;
            }
            let problems: Vec<Coded> = values
                .iter()
                .filter_map(|one| oauth::authzen_attribute_problem(self, name, one))
                .collect();
            if let Some(first_problem) = problems.first() {
                note(first_problem.code, &mut code);
                out.errors.extend(problems.into_iter().map(|p| p.message));
                continue;
            }
            let problems: Vec<Coded> = values
                .iter()
                .filter_map(|one| {
                    oauth::authorization_details_attribute_problem(
                        self, name, one,
                    )
                })
                .collect();
            if let Some(first_problem) = problems.first() {
                note(first_problem.code, &mut code);
                out.errors.extend(problems.into_iter().map(|p| p.message));
                continue;
            }
            if row.kind != "multi" && SEALED_FIELDS.contains(&name.as_str()) {
                match self.seal_field_value(name, &first) {
                    Some(sealed) => {
                        out.fields.insert(name.clone(), Value::String(sealed));
                    }
                    None => {
                        out.errors.push(format!(
                            "\"{}\" is private key material and this service \
                             could not encrypt it, so it was not stored. \
                             Storing a signing key in the clear in product \
                             mode would put a working credential in every \
                             directory dump. The key-encryption key is the \
                             one /admin/persistence reports on.",
                            name
                        ));
                        note(codes::STS_REG_0019, &mut code);
                    }
                }
                continue;
            }
            let value = if row.kind == "multi" {
                Value::Array(values.into_iter().map(Value::String).collect())
            } else {
                Value::String(first)
            };
            out.fields.insert(name.clone(), value);
        }
        out.code = code;
        out
    }
}

/// `sealLabelOf(name)`: the label a sealed attribute's value is bound to.
#[tracing::instrument(level = "debug")]
pub fn seal_label_of(name: &str) -> &'static str {
    match name {
        "gnapSymmetricKey" => "gnap-shared-key",
        "gnapMacaroonKey" => "gnap-macaroon-key",
        "secretDestCredential" => "secret-destination-credential",
        "scimClientPassword"
        | "scimClientOAuthClientSecret"
        | "scimClientTlsPrivateKey" => "scim-client-credential",
        "oauthClientSecret" => "client-secret",
        "appRegistrationAccessToken" => "registration-access-token",
        _ => "application-private-key",
    }
}
