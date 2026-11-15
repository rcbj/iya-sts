// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A client as the authorization server reads it: `applications.js`'s
//! `clientConfigOf()` and `declaredFlowsOf()`, over the application
//! register (`sts_registers::applications`).
//!
//! [`Clients`] is the narrow view the endpoints ask; [`RegisterClients`]
//! answers it from the register's `load()` and its client-secret records.
//! The members are `clientConfigOf()`'s, in its order, for every member the
//! endpoints of this slice read; the RFC 7591 response members
//! (`clientResponseMembersOf()`) are a later slice's (registration), and
//! `redirect_uris` here are every registered value — the split of a value
//! still marked "observed" into `unconfirmed_redirect_uris`, which product
//! mode makes, is not read yet (`returnAddressesOf()`), so this runtime
//! answers as development mode does.

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
}

/// The answer for a client nobody registered.
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
        Some(Json::Array(list)) => {
            list.iter().map(|one| crate::js::string_of(Some(one))).collect()
        }
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
        crate::js::string_of(fields.get(name)).to_ascii_uppercase() == "TRUE",
    )
}

/// The register's answers.
pub struct RegisterClients {
    pub registry: Arc<ApplicationRegistry>,
    /// Seconds, for a federation registration's expiry.
    pub now_s: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl Clients for RegisterClients {
    #[tracing::instrument(level = "debug", skip(self))]
    fn client_config_of(&self, client_id: &str) -> Json {
        let loaded = self.registry.load(client_id);
        let fields = &loaded.record.fields;
        let federation_at =
            crate::js::to_number(fields.get("appFederationExpiresAt")
                .unwrap_or(&Json::Null));
        let federation_ended = fields.contains_key("appFederationRegistration")
            && crate::js::string_of(fields.get("appFederationRegistration"))
                != ""
            && !(federation_at > (self.now_s)() as f64);
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
        let redirects = values_of(fields.get("oauthRedirectUri"));
        json!({
            "known": true,
            "registered": loaded.record.registered,
            "declared": loaded.record.registered || !redirects.is_empty(),
            "redirect_uris": redirects,
            "unconfirmed_redirect_uris": [],
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
            "token_endpoint_auth_signing_alg":
                text(fields, "oauthTokenEndpointAuthSigningAlg"),
            "certificate_thumbprint":
                text(fields, "oauthTlsClientCertificateThumbprint"),
        })
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
                    let mut parts: Vec<&str> =
                        one.split_whitespace().collect();
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
}
