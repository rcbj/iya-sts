// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A client as the authorization server reads it: `applications.js`'s
//! `clientConfigOf()` and `declaredFlowsOf()`, over the application
//! register (`sts_registers::applications`).
//!
//! [`Clients`] is the narrow view the endpoints ask; [`RegisterClients`]
//! answers it from the register's `load()` and its client-secret records.
//! The members are `clientConfigOf()`'s, in its order, for every member the
//! endpoints of the core read; the RFC 7591 response members
//! (`clientResponseMembersOf()`) are a later slice's (registration).
//!
//! **THE REDIRECT URIs GO THROUGH `returnAddressesOf()`**, as Node's do: in
//! development every value of `oauthRedirectUri` counts; in product a value
//! still marked observed (`appReturnAddressObserved: oauthRedirectUri
//! <uri>`) is withheld into `unconfirmed_redirect_uris` until an
//! administrator confirms it, so that an address development LEARNT is not
//! a registered one in product.
//!
//! Beside the client's configuration the endpoints ask the register a few
//! questions of its own (the scope policy's declarations and delegated
//! permission grants, RFC 8707's registered targets, an application's
//! setting override); each is a method of [`Clients`] with a default that
//! answers "nothing registered", so a table in a test need answer only
//! what it records.

use std::sync::Arc;

use serde_json::{json, Map, Value as Json};
use sts_registers::applications::ApplicationRegistry;

/// The client lookups the endpoints make.
pub trait Clients: Send + Sync {
    /// `clientConfigOf(clientId)`.
    fn client_config_of(&self, client_id: &str) -> Json;
    /// `declaredFlowsOf(clientId)`: `{ grant_types, response_types }`, each
    /// a list or null, or `None` where neither is declared.
    fn declared_flows_of(&self, client_id: &str) -> Option<Json>;
    /// `allowedScopesOf(clientId)`: `oauthAllowedScope`, or `None` where
    /// the client declares none.
    fn allowed_scopes_of(&self, _client_id: &str) -> Option<Vec<String>> {
        None
    }
    /// `holdsPermission(clientId, id)`: `oauthDelegatedPermission` on the
    /// client's entry names the permission's whole identifier.
    fn holds_permission(&self, _client_id: &str, _id: &str) -> bool {
        false
    }
    /// `forPermission(id)`: the identifier of the application defining a
    /// permission, by its whole identifier.
    fn permission_defined_by(&self, _id: &str) -> Option<String> {
        None
    }
    /// `forPermission(id)` in full: `(identifier, name, baseUri)` of the
    /// permission a whole identifier names.
    fn permission_of(&self, _id: &str) -> Option<(String, String, String)> {
        None
    }
    /// `forClientId(name)` found an application.
    fn is_client_id(&self, _name: &str) -> bool {
        false
    }
    /// `RegisteredTargets.application(target)`: an application found by
    /// its `oauthAudience`, client_id, identifier or permission base URI,
    /// and registered (`registeredBy` set).
    fn registered_target(&self, _target: &str) -> bool {
        false
    }
    /// `applications.get(identifier)` found an entry (the seeded objects
    /// of this service's own APIs).
    fn seeded(&self, _identifier: &str) -> bool {
        false
    }
    /// `applications.settingFor(clientId, key, config)`: the client's own
    /// override of a setting, in force; `None` for the setting's value.
    fn setting_for(&self, _client_id: &str, _key: &str) -> Option<Json> {
        None
    }
    /// `clientAudienceNames(clientId).all`: the declared `oauthAudience`
    /// values, the client_id and the registry identifier.
    fn client_audience_names(&self, client_id: &str) -> Vec<String> {
        if client_id.trim().is_empty() {
            Vec::new()
        } else {
            vec![client_id.trim().to_string()]
        }
    }
    /// `IssuerNames.registeredApplication()`: the `registeredBy` of the
    /// application a client_id names (by `forClientId()`, else as an
    /// identifier), '' for one that was only seen.
    fn registered_by(&self, _client_id: &str) -> String {
        String::new()
    }
    /// `consent.globalConsentsOf(clientId)`: the scopes the application
    /// holds global consent to (`oauthGlobalConsent`), without repeats.
    fn global_consents_of(&self, _client_id: &str) -> Vec<String> {
        Vec::new()
    }
    /// The entry's display name (`entry.name`), or the client_id.
    fn name_of(&self, client_id: &str) -> String {
        client_id.to_string()
    }
}

/// The attribute the provenance of a return address is kept in.
pub const OBSERVED_ADDRESS_ATTRIBUTE: &str = "appReturnAddressObserved";

/// `returnAddressesOf(fields, attribute)`: `(registered, unconfirmed)`. In
/// development every address counts and none is unconfirmed; in product an
/// address a sighting marked observed is withheld.
#[tracing::instrument(level = "debug", skip(fields))]
pub fn return_addresses_of(
    fields: &Map<String, Json>,
    attribute: &str,
    accepts_unregistered: bool,
) -> (Vec<String>, Vec<String>) {
    let values = values_of(fields.get(attribute));
    if accepts_unregistered {
        return (values, Vec::new());
    }
    let marked: Vec<String> = values_of(fields.get(OBSERVED_ADDRESS_ATTRIBUTE))
        .into_iter()
        .filter_map(|mark| {
            let at = mark.find(' ')?;
            if at == 0 {
                return None;
            }
            let (named, rest) = (&mark[..at], mark[at + 1..].trim());
            (named == attribute && !rest.is_empty()).then(|| rest.to_string())
        })
        .collect();
    let (registered, unconfirmed): (Vec<String>, Vec<String>) =
        values.into_iter().partition(|one| !marked.contains(one));
    (registered, unconfirmed)
}

/// `declaredClient(record, fields, redirectCount)`: whether anything on
/// the entry was DECLARED rather than sighted.
fn declared_client(
    registered: bool,
    fields: &Map<String, Json>,
    redirects: usize,
) -> bool {
    const DECLARING: [&str; 18] = [
        "oauthTokenEndpointAuthMethod",
        "oauthClientSecret",
        "oauthJwks",
        "oauthJwksUri",
        "oauthAssertionJwks",
        "oauthAssertionIssuer",
        "oauthSamlAssertionIssuer",
        "oauthSamlAssertionSigningCertificate",
        "oauthSamlAssertionCertificate",
        "oauthTlsClientCertificateThumbprint",
        "oauthTlsClientCertificateBoundAccessTokens",
        "oauthGrantType",
        "oauthResponseType",
        "oauthTlsClientAuthSubjectDn",
        "oauthTlsClientAuthSanDns",
        "oauthTlsClientAuthSanUri",
        "oauthTlsClientAuthSanIp",
        "oauthTlsClientAuthSanEmail",
    ];
    let has = |name: &str| {
        values_of(fields.get(name))
            .iter()
            .any(|one| !one.trim().is_empty())
    };
    let allowed = values_of(fields.get("appAllowedProtocol"));
    registered
        || redirects > 0
        || DECLARING.iter().any(|name| has(name))
        || ["oauth2", "oidc", "oid4vci"]
            .iter()
            .any(|p| allowed.iter().any(|a| a == p))
}

/// The answer for a client nobody registered.
#[tracing::instrument(level = "debug", skip_all)]
pub fn unknown_client() -> Json {
    json!({ "known": false, "registered": false, "declared": false,
            "redirect_uris": [], "post_logout_redirect_uris": [],
            "token_endpoint_auth_method": "",
            "token_endpoint_auth_methods": [],
            "frontchannel_logout_uri": "",
            "frontchannel_logout_session_required": false,
            "backchannel_logout_uri": "",
            "backchannel_logout_session_required": false,
            "subject_type": "public", "sector_identifier_uri": "",
            "token_endpoint_auth_signing_alg": "", "client_secret": "" })
}

fn values_of(v: Option<&Json>) -> Vec<String> {
    match v {
        None | Some(Json::Null) => Vec::new(),
        Some(Json::Array(list)) => list
            .iter()
            .map(|one| crate::js::string_of(Some(one)))
            .collect(),
        Some(one) => vec![crate::js::string_of(Some(one))],
    }
}

fn text(fields: &Map<String, Json>, name: &str) -> Json {
    Json::from(match fields.get(name) {
        None => String::new(),
        v => crate::js::string_of(v),
    })
}

fn flag(fields: &Map<String, Json>, name: &str) -> Json {
    Json::Bool(
        crate::js::string_of(fields.get(name)).eq_ignore_ascii_case("TRUE"),
    )
}

/// `CLIENT_RESPONSE_ATTRIBUTES` (#290): a registration member and the
/// attribute that holds it.
const CLIENT_RESPONSE_ATTRIBUTES: &[(&str, &str)] = &[
    (
        "id_token_signed_response_alg",
        "oauthIdTokenSignedResponseAlg",
    ),
    (
        "id_token_encrypted_response_alg",
        "oauthIdTokenEncryptedResponseAlg",
    ),
    (
        "id_token_encrypted_response_enc",
        "oauthIdTokenEncryptedResponseEnc",
    ),
    (
        "userinfo_signed_response_alg",
        "oauthUserinfoSignedResponseAlg",
    ),
    (
        "userinfo_encrypted_response_alg",
        "oauthUserinfoEncryptedResponseAlg",
    ),
    (
        "userinfo_encrypted_response_enc",
        "oauthUserinfoEncryptedResponseEnc",
    ),
    (
        "authorization_signed_response_alg",
        "oauthAuthorizationSignedResponseAlg",
    ),
    (
        "authorization_encrypted_response_alg",
        "oauthAuthorizationEncryptedResponseAlg",
    ),
    (
        "authorization_encrypted_response_enc",
        "oauthAuthorizationEncryptedResponseEnc",
    ),
    ("default_acr_values", "oauthDefaultAcrValues"),
    ("default_max_age", "oauthDefaultMaxAge"),
];

/// The register's answers.
pub struct RegisterClients {
    pub registry: Arc<ApplicationRegistry>,
    /// Seconds, for a federation registration's expiry.
    pub now_s: Arc<dyn Fn() -> i64 + Send + Sync>,
    /// `mode.acceptsUnregisteredAddresses()`, asked per call.
    pub accepts_unregistered: Arc<dyn Fn() -> bool + Send + Sync>,
}

impl Clients for RegisterClients {
    #[tracing::instrument(level = "debug", skip(self))]
    fn client_config_of(&self, client_id: &str) -> Json {
        let loaded = self.registry.load(client_id);
        let fields = &loaded.record.fields;
        let federation_at = crate::js::to_number(
            fields.get("appFederationExpiresAt").unwrap_or(&Json::Null),
        );
        let federation_ended = fields.contains_key("appFederationRegistration")
            && !crate::js::string_of(fields.get("appFederationRegistration"))
                .is_empty()
            && (federation_at.is_nan()
                || federation_at <= (self.now_s)() as f64);
        if !loaded.known || federation_ended {
            return unknown_client();
        }
        let declared: Vec<String> =
            values_of(fields.get("oauthTokenEndpointAuthMethod"))
                .into_iter()
                .map(|one| one.trim().to_string())
                .filter(|one| !one.is_empty())
                .collect();
        let methods = if declared.is_empty() && loaded.record.registered {
            vec!["client_secret_basic".to_string()]
        } else {
            declared
        };
        let records = self.registry.client_secret_records_of(fields);
        let primary = self.registry.primary_client_secret_of(fields, None);
        let (redirects, unconfirmed) = return_addresses_of(
            fields,
            "oauthRedirectUri",
            (self.accepts_unregistered)(),
        );
        let subject_type = {
            let t = crate::js::string_of(fields.get("oauthSubjectType"));
            if t.trim().is_empty() {
                "public".to_string()
            } else {
                t.trim().to_string()
            }
        };
        let declared = declared_client(
            loaded.record.registered,
            fields,
            redirects.len() + unconfirmed.len(),
        );
        let mut config = json!({
            "known": true,
            "registered": loaded.record.registered,
            "declared": declared,
            "redirect_uris": redirects,
            "unconfirmed_redirect_uris": unconfirmed,
            "post_logout_redirect_uris":
                values_of(fields.get("oauthPostLogoutRedirectUri")),
            "token_endpoint_auth_method":
                methods.first().cloned().unwrap_or_default(),
            "token_endpoint_auth_methods": methods,
            "client_secret": primary.as_ref()
                .map(|p| p.secret.clone()).unwrap_or_default(),
            "client_secret_expires_at": primary.as_ref()
                .map_or(0, |p| p.expires_at),
            "client_secrets": records.iter().map(|one| json!({
                "id": one.id, "secret": one.secret,
                "expiresAt": one.expires_at })).collect::<Vec<_>>(),
            "jwks": text(fields, "oauthJwks"),
            "jwks_uri": text(fields, "oauthJwksUri"),
            "assertion_jwks": text(fields, "oauthAssertionJwks"),
            "tls_client_auth_subject_dn":
                text(fields, "oauthTlsClientAuthSubjectDn"),
            "tls_client_auth_san_dns": text(fields, "oauthTlsClientAuthSanDns"),
            "tls_client_auth_san_uri": text(fields, "oauthTlsClientAuthSanUri"),
            "tls_client_auth_san_ip": text(fields, "oauthTlsClientAuthSanIp"),
            "tls_client_auth_san_email":
                text(fields, "oauthTlsClientAuthSanEmail"),
            "tls_client_certificate_bound_access_tokens":
                flag(fields, "oauthTlsClientCertificateBoundAccessTokens"),
            "identifier": loaded.record.identifier,
            "subject_type": subject_type,
            "sector_identifier_uri": text(fields, "oauthSectorIdentifierUri"),
            "require_pushed_authorization_requests":
                flag(fields, "oauthRequirePushedAuthorizationRequests"),
            "token_endpoint_auth_signing_alg":
                text(fields, "oauthTokenEndpointAuthSigningAlg"),
            "certificate_thumbprint":
                text(fields, "oauthTlsClientCertificateThumbprint"),
            "introspection_signed_response_alg":
                text(fields, "oauthIntrospectionSignedResponseAlg"),
            "introspection_encrypted_response_alg":
                text(fields, "oauthIntrospectionEncryptedResponseAlg"),
            "introspection_encrypted_response_enc":
                text(fields, "oauthIntrospectionEncryptedResponseEnc"),
            "request_uris": values_of(fields.get("oauthRequestUri")),
            "request_object_signing_alg":
                text(fields, "oauthRequestObjectSigningAlg"),
            "request_object_encryption_alg":
                text(fields, "oauthRequestObjectEncryptionAlg"),
            "request_object_encryption_enc":
                text(fields, "oauthRequestObjectEncryptionEnc"),
            "require_signed_request_object":
                flag(fields, "oauthRequireSignedRequestObject"),
            "authorization_details_types":
                values_of(fields.get("oauthAuthorizationDetailsTypes")),
        });
        // #290's eleven (`clientResponseMembersOf()`): a member that is not
        // set is ABSENT, which each reader takes as "not registered".
        if let Some(out) = config.as_object_mut() {
            for (member, attribute) in CLIENT_RESPONSE_ATTRIBUTES {
                let first = values_of(fields.get(*attribute))
                    .into_iter()
                    .next()
                    .unwrap_or_default();
                let text = first.trim();
                if text.is_empty() {
                    continue;
                }
                let value = match *member {
                    "default_acr_values" => {
                        json!(text.split_whitespace().collect::<Vec<_>>())
                    }
                    "default_max_age"
                        if text.len() <= 15
                            && text.bytes().all(|b| b.is_ascii_digit()) =>
                    {
                        json!(text.parse::<i64>().unwrap_or(0))
                    }
                    _ => json!(text),
                };
                out.insert(member.to_string(), value);
            }
        }
        config
    }

    #[tracing::instrument(level = "debug", skip(self))]
    fn declared_flows_of(&self, client_id: &str) -> Option<Json> {
        let loaded = self.registry.load(client_id);
        if !loaded.known {
            return None;
        }
        let list_of = |name: &str| -> Json {
            let values: Vec<String> = values_of(loaded.record.fields.get(name))
                .into_iter()
                .map(|one| {
                    let mut parts: Vec<&str> = one.split_whitespace().collect();
                    parts.sort_unstable();
                    parts.join(" ")
                })
                .filter(|one| !one.is_empty())
                .collect();
            if values.is_empty() {
                Json::Null
            } else {
                json!(values)
            }
        };
        let grants = list_of("oauthGrantType");
        let responses = list_of("oauthResponseType");
        if grants.is_null() && responses.is_null() {
            return None;
        }
        Some(json!({ "grant_types": grants, "response_types": responses }))
    }

    #[tracing::instrument(level = "debug", skip(self))]
    fn allowed_scopes_of(&self, client_id: &str) -> Option<Vec<String>> {
        self.registry.allowed_scopes_of(client_id)
    }

    #[tracing::instrument(level = "debug", skip(self))]
    fn holds_permission(&self, client_id: &str, id: &str) -> bool {
        self.registry.holds_permission(client_id, id)
    }

    #[tracing::instrument(level = "debug", skip(self))]
    fn permission_defined_by(&self, id: &str) -> Option<String> {
        self.registry
            .for_permission(id)
            .map(|f| crate::js::string_of(f.get("identifier")))
    }

    #[tracing::instrument(level = "debug", skip(self))]
    fn permission_of(&self, id: &str) -> Option<(String, String, String)> {
        self.registry.for_permission(id).map(|f| {
            (
                crate::js::string_of(f.get("identifier")),
                crate::js::string_of(f.get("name")),
                crate::js::string_of(f.get("baseUri")),
            )
        })
    }

    #[tracing::instrument(level = "debug", skip(self))]
    fn is_client_id(&self, name: &str) -> bool {
        self.registry.for_client_id(name).is_some()
    }

    #[tracing::instrument(level = "debug", skip(self))]
    fn registered_target(&self, target: &str) -> bool {
        let wanted = target.trim();
        if wanted.is_empty() {
            return false;
        }
        let found = self
            .registry
            .for_audience(wanted)
            .or_else(|| self.registry.for_client_id(wanted))
            .or_else(|| self.registry.get(wanted))
            .or_else(|| self.registry.for_permission_base(wanted));
        found.is_some_and(|f| {
            !crate::js::string_of(f.get("registeredBy")).is_empty()
        })
    }

    #[tracing::instrument(level = "debug", skip(self))]
    fn seeded(&self, identifier: &str) -> bool {
        self.registry.get(identifier).is_some()
    }

    #[tracing::instrument(level = "debug", skip(self))]
    fn setting_for(&self, client_id: &str, key: &str) -> Option<Json> {
        Some(self.registry.setting_for(client_id, key))
    }

    #[tracing::instrument(level = "debug", skip(self))]
    fn client_audience_names(&self, client_id: &str) -> Vec<String> {
        let id = client_id.trim();
        let mut all: Vec<String> = Vec::new();
        let mut add = |one: String| {
            let t = one.trim().to_string();
            if !t.is_empty() && !all.contains(&t) {
                all.push(t);
            }
        };
        let entry = if id.is_empty() {
            None
        } else {
            self.registry
                .for_client_id(id)
                .or_else(|| self.registry.get(id))
        };
        if let Some(e) = &entry {
            for one in values_of(e["fields"].get("oauthAudience")) {
                add(one);
            }
        }
        add(id.to_string());
        if let Some(e) = &entry {
            add(crate::js::string_of(e.get("identifier")));
        }
        all
    }

    #[tracing::instrument(level = "debug", skip(self))]
    fn registered_by(&self, client_id: &str) -> String {
        let id = client_id.trim();
        let identifier = self
            .registry
            .for_client_id(id)
            .map(|e| crate::js::string_of(e.get("identifier")))
            .filter(|i| !i.is_empty())
            .unwrap_or_else(|| id.to_string());
        self.registry
            .get(&identifier)
            .map(|e| crate::js::string_of(e.get("registeredBy")))
            .unwrap_or_default()
    }

    #[tracing::instrument(level = "debug", skip(self))]
    fn global_consents_of(&self, client_id: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        if let Some(entry) = self.registry.get(client_id.trim()) {
            for one in values_of(entry["fields"].get("oauthGlobalConsent")) {
                let t = one.trim().to_string();
                if !t.is_empty() && !out.contains(&t) {
                    out.push(t);
                }
            }
        }
        out
    }

    #[tracing::instrument(level = "debug", skip(self))]
    fn name_of(&self, client_id: &str) -> String {
        self.registry
            .get(client_id)
            .map(|e| crate::js::string_of(e.get("name")))
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| client_id.to_string())
    }
}
