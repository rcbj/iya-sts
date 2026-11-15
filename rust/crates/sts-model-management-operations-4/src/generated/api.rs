// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// GENERATED from models/api/ (#1390, #444) by models/lib/rust_lib.mjs.
// Do not edit: change the model and run
// tests/tools/regenerate-model-docs.sh. tests/model_domain.js fails when
// this differs.

/// Every certificate this trust realm holds, or one of them with every X.509
/// field and its trust chain
pub mod get_certificates {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/certificates";
    pub const OPERATION_ID: &str = "getCertificates";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificate: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CertificatesItemAppearancesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
        pub where_: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200CertificatesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fingerprint: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<String>,
        #[serde(rename = "selfIssued", default, skip_serializing_if = "Option::is_none")]
        pub self_issued: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub appearances: Option<Vec<Answer200CertificatesItemAppearancesItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AppearancesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
        pub where_: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Pqc {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub family: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub standard: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ChainItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub position: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fingerprint: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub role: Option<String>,
        #[serde(rename = "signatureValid", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub signature_valid: Option<Option<bool>>,
        #[serde(rename = "signedBy", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub signed_by: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expired: Option<bool>,
        #[serde(rename = "notYetValid", default, skip_serializing_if = "Option::is_none")]
        pub not_yet_valid: Option<bool>,
        #[serde(rename = "issuerMayCertify", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub issuer_may_certify: Option<Option<bool>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub anchor: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificate: Option<sts_model_management_components_4::WithFingerprintPemSummary>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub matched: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<i64>,
        #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
        pub per_page: Option<i64>,
        #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
        pub first_row: Option<i64>,
        #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
        pub last_row: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificates: Option<Vec<Answer200CertificatesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ok: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub appearances: Option<Vec<Answer200AppearancesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pqc: Option<Answer200Pqc>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fingerprint: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificate: Option<sts_model_management_components_4::WithFingerprintPemSummary>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub chain: Option<Vec<Answer200ChainItem>>,
        #[serde(rename = "chainStatus", default, skip_serializing_if = "Option::is_none")]
        pub chain_status: Option<String>,
        #[serde(rename = "chainReason", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub chain_reason: Option<Option<String>>,
        #[serde(rename = "chainTrusted", default, skip_serializing_if = "Option::is_none")]
        pub chain_trusted: Option<bool>,
    }
}

/// The Claims Providers this realm aggregates claims from, and every person's
/// link (OIDC Core 5.6.2)
pub mod get_claim_providers {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/claim-providers";
    pub const OPERATION_ID: &str = "getClaimProviders";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(rename = "providersPage", default, skip_serializing_if = "Option::is_none")]
        pub providers_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub linkq: Option<String>,
        #[serde(rename = "linksPage", default, skip_serializing_if = "Option::is_none")]
        pub links_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ProvidersItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
        #[serde(rename = "authorizationEndpoint", default, skip_serializing_if = "Option::is_none")]
        pub authorization_endpoint: Option<String>,
        #[serde(rename = "tokenEndpoint", default, skip_serializing_if = "Option::is_none")]
        pub token_endpoint: Option<String>,
        #[serde(rename = "claimsEndpoint", default, skip_serializing_if = "Option::is_none")]
        pub claims_endpoint: Option<String>,
        #[serde(rename = "jwksUri", default, skip_serializing_if = "Option::is_none")]
        pub jwks_uri: Option<String>,
        #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
        pub client_id: Option<String>,
        #[serde(rename = "authMethod", default, skip_serializing_if = "Option::is_none")]
        pub auth_method: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub claims: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub delivery: Option<String>,
        #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
        pub created_at: Option<f64>,
        #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none")]
        pub updated_at: Option<f64>,
        #[serde(rename = "hasSecret", default, skip_serializing_if = "Option::is_none")]
        pub has_secret: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200LinksItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub provider: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sub: Option<String>,
        #[serde(rename = "linkedAt", default, skip_serializing_if = "Option::is_none")]
        pub linked_at: Option<f64>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refreshable: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub stale: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Counts {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub providers: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub links: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Matched {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub links: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Filter {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub links: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Paging {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub providers: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub links: Option<sts_model_management_components_4::WithPagePagesPerPage>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
        #[serde(rename = "redirectUri", default, skip_serializing_if = "Option::is_none")]
        pub redirect_uri: Option<String>,
        #[serde(rename = "callbackPath", default, skip_serializing_if = "Option::is_none")]
        pub callback_path: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub providers: Option<Vec<Answer200ProvidersItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub links: Option<Vec<Answer200LinksItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<Answer200Counts>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub matched: Option<Answer200Matched>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub filter: Option<Answer200Filter>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<Answer200Paging>,
    }
}

/// Register a Claims Provider
pub mod add_claim_provider {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/claim-providers/add-provider";
    pub const OPERATION_ID: &str = "addClaimProvider";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyAuthMethod {
        #[serde(rename = "client_secret_basic")]
        ClientSecretBasic,
        #[serde(rename = "client_secret_post")]
        ClientSecretPost,
        #[serde(rename = "none")]
        None,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyDelivery {
        #[serde(rename = "aggregated")]
        Aggregated,
        #[serde(rename = "distributed")]
        Distributed,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The provider's id in this realm, its `_claim_sources` key.
        pub id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// Its OpenID Provider issuer.
        pub issuer: String,
        /// Fill the endpoints left empty from the issuer's discovery document.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub discover: Option<bool>,
        #[serde(rename = "authorizationEndpoint", default, skip_serializing_if = "Option::is_none")]
        pub authorization_endpoint: Option<String>,
        #[serde(rename = "tokenEndpoint", default, skip_serializing_if = "Option::is_none")]
        pub token_endpoint: Option<String>,
        /// Its UserInfo endpoint.
        #[serde(rename = "claimsEndpoint", default, skip_serializing_if = "Option::is_none")]
        pub claims_endpoint: Option<String>,
        #[serde(rename = "jwksUri", default, skip_serializing_if = "Option::is_none")]
        pub jwks_uri: Option<String>,
        /// This realm's client_id at the provider.
        #[serde(rename = "clientId")]
        pub client_id: String,
        /// Sealed where keys persist; never returned.
        #[serde(rename = "clientSecret", default, skip_serializing_if = "Option::is_none")]
        pub client_secret: Option<String>,
        #[serde(rename = "authMethod", default, skip_serializing_if = "Option::is_none")]
        pub auth_method: Option<BodyAuthMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        /// The claim names it supplies.
        pub claims: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub delivery: Option<BodyDelivery>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
    }
}

/// Remove a Claims Provider
pub mod remove_claim_provider {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/claim-providers/remove-provider";
    pub const OPERATION_ID: &str = "removeClaimProvider";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The provider's id in this realm, its `_claim_sources` key.
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
    }
}

/// Revoke a person's link to a Claims Provider
pub mod revoke_claim_source_link {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/claim-providers/revoke-link";
    pub const OPERATION_ID: &str = "revokeClaimSourceLink";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub username: String,
        /// The provider's id in this realm, its `_claim_sources` key.
        pub provider: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
    }
}

/// Change a Claims Provider
pub mod update_claim_provider {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/claim-providers/update-provider";
    pub const OPERATION_ID: &str = "updateClaimProvider";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyAuthMethod {
        #[serde(rename = "client_secret_basic")]
        ClientSecretBasic,
        #[serde(rename = "client_secret_post")]
        ClientSecretPost,
        #[serde(rename = "none")]
        None,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyDelivery {
        #[serde(rename = "aggregated")]
        Aggregated,
        #[serde(rename = "distributed")]
        Distributed,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The provider's id in this realm, its `_claim_sources` key.
        pub id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// Its OpenID Provider issuer.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
        /// Fill the endpoints left empty from the issuer's discovery document.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub discover: Option<bool>,
        #[serde(rename = "authorizationEndpoint", default, skip_serializing_if = "Option::is_none")]
        pub authorization_endpoint: Option<String>,
        #[serde(rename = "tokenEndpoint", default, skip_serializing_if = "Option::is_none")]
        pub token_endpoint: Option<String>,
        /// Its UserInfo endpoint.
        #[serde(rename = "claimsEndpoint", default, skip_serializing_if = "Option::is_none")]
        pub claims_endpoint: Option<String>,
        #[serde(rename = "jwksUri", default, skip_serializing_if = "Option::is_none")]
        pub jwks_uri: Option<String>,
        /// This realm's client_id at the provider.
        #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
        pub client_id: Option<String>,
        /// Sealed where keys persist; never returned.
        #[serde(rename = "clientSecret", default, skip_serializing_if = "Option::is_none")]
        pub client_secret: Option<String>,
        #[serde(rename = "authMethod", default, skip_serializing_if = "Option::is_none")]
        pub auth_method: Option<BodyAuthMethod>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        /// The claim names it supplies.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub claims: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub delivery: Option<BodyDelivery>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
    }
}

/// OpenID Provider Commands: the clients, the account register, the tenant runs
/// and the deliveries
pub mod get_provider_commands {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/commands";
    pub const OPERATION_ID: &str = "getProviderCommands";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(rename = "clientsPage", default, skip_serializing_if = "Option::is_none")]
        pub clients_page: Option<i64>,
        #[serde(rename = "accountsPage", default, skip_serializing_if = "Option::is_none")]
        pub accounts_page: Option<i64>,
        #[serde(rename = "runsPage", default, skip_serializing_if = "Option::is_none")]
        pub runs_page: Option<i64>,
        #[serde(rename = "deliveriesPage", default, skip_serializing_if = "Option::is_none")]
        pub deliveries_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ClientsItemLearnedRolesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub display: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ClientsItemLearned {
        #[serde(rename = "commandsSupported", default, skip_serializing_if = "Option::is_none")]
        pub commands_supported: Option<Vec<String>>,
        #[serde(rename = "audSubRequired", default, skip_serializing_if = "Option::is_none")]
        pub aud_sub_required: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub roles: Option<Vec<Answer200ClientsItemLearnedRolesItem>>,
        #[serde(rename = "learnedAt", default, skip_serializing_if = "Option::is_none")]
        pub learned_at: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ClientsItem {
        #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
        pub client_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub endpoint: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub learned: Option<Answer200ClientsItemLearned>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200AccountsItem {
        #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
        pub client_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sub: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(rename = "lastCommand", default, skip_serializing_if = "Option::is_none")]
        pub last_command: Option<String>,
        #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none")]
        pub updated_at: Option<String>,
        #[serde(rename = "audSub", default, skip_serializing_if = "Option::is_none")]
        pub aud_sub: Option<String>,
        #[serde(rename = "lastAccess", default, skip_serializing_if = "Option::is_none")]
        pub last_access: Option<sts_model_base::unions::NumberOrString>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200DeliveriesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
        pub client_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub uri: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub generation: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attempts: Option<f64>,
        #[serde(rename = "inFlight", default, skip_serializing_if = "Option::is_none")]
        pub in_flight: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub holder: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<sts_model_base::unions::NumberOrString>,
        #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none")]
        pub error_code: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub why: Option<String>,
        #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none")]
        pub queued_at: Option<String>,
        #[serde(rename = "nextAttemptAt", default, skip_serializing_if = "Option::is_none")]
        pub next_attempt_at: Option<String>,
        #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none")]
        pub last_attempt_at: Option<String>,
        #[serde(rename = "finishedAt", default, skip_serializing_if = "Option::is_none")]
        pub finished_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub command: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sub: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub trigger: Option<String>,
        #[serde(rename = "accountState", default, skip_serializing_if = "Option::is_none")]
        pub account_state: Option<String>,
        #[serde(rename = "awaitingCallback", default, skip_serializing_if = "Option::is_none")]
        pub awaiting_callback: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Counts {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pending: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sent: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dead: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ListCounts {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub clients: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub accounts: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub runs: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub deliveries: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Paging {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub clients: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub accounts: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub runs: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub deliveries: Option<sts_model_management_components_4::WithPagePagesPerPage>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub automatic: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub clients: Option<Vec<Answer200ClientsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub accounts: Option<Vec<Answer200AccountsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub deliveries: Option<Vec<Answer200DeliveriesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<Answer200Counts>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub runs: Option<Vec<sts_model_management_components_4::WithIdClientIdCommand>>,
        #[serde(rename = "accountCommands", default, skip_serializing_if = "Option::is_none")]
        pub account_commands: Option<Vec<String>>,
        #[serde(rename = "tenantCommands", default, skip_serializing_if = "Option::is_none")]
        pub tenant_commands: Option<Vec<String>>,
        #[serde(rename = "clientIds", default, skip_serializing_if = "Option::is_none")]
        pub client_ids: Option<Vec<String>>,
        #[serde(rename = "listCounts", default, skip_serializing_if = "Option::is_none")]
        pub list_counts: Option<Answer200ListCounts>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<Answer200Paging>,
    }
}

/// Retry a dead command delivery
pub mod retry_command_delivery {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/commands/retry-delivery";
    pub const OPERATION_ID: &str = "retryCommandDelivery";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub delivery: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors192;
}

/// Send an account command about one person
pub mod send_account_command {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/commands/send-account";
    pub const OPERATION_ID: &str = "sendAccountCommand";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyCommand {
        #[serde(rename = "activate")]
        Activate,
        #[serde(rename = "maintain")]
        Maintain,
        #[serde(rename = "suspend")]
        Suspend,
        #[serde(rename = "reactivate")]
        Reactivate,
        #[serde(rename = "archive")]
        Archive,
        #[serde(rename = "restore")]
        Restore,
        #[serde(rename = "delete")]
        Delete,
        #[serde(rename = "audit")]
        Audit,
        #[serde(rename = "invalidate")]
        Invalidate,
        #[serde(rename = "migrate")]
        Migrate,
        #[serde(rename = "activate_async")]
        ActivateAsync,
        #[serde(rename = "maintain_async")]
        MaintainAsync,
        #[serde(rename = "suspend_async")]
        SuspendAsync,
        #[serde(rename = "reactivate_async")]
        ReactivateAsync,
        #[serde(rename = "archive_async")]
        ArchiveAsync,
        #[serde(rename = "restore_async")]
        RestoreAsync,
        #[serde(rename = "delete_async")]
        DeleteAsync,
        #[serde(rename = "audit_async")]
        AuditAsync,
        #[serde(rename = "invalidate_async")]
        InvalidateAsync,
        #[serde(rename = "migrate_async")]
        MigrateAsync,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(rename = "clientId")]
        pub client_id: String,
        pub username: String,
        pub command: BodyCommand,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors192;
}

/// Send a tenant command
pub mod send_tenant_command {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/commands/send-tenant";
    pub const OPERATION_ID: &str = "sendTenantCommand";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyCommand {
        #[serde(rename = "metadata")]
        Metadata,
        #[serde(rename = "audit_tenant")]
        AuditTenant,
        #[serde(rename = "suspend_tenant")]
        SuspendTenant,
        #[serde(rename = "archive_tenant")]
        ArchiveTenant,
        #[serde(rename = "delete_tenant")]
        DeleteTenant,
        #[serde(rename = "invalidate_tenant")]
        InvalidateTenant,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(rename = "clientId")]
        pub client_id: String,
        pub command: BodyCommand,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors192;
}

/// The OAuth grants this realm holds (Grant Management for OAuth 2.0)
pub mod get_grants {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/grants";
    pub const OPERATION_ID: &str = "getGrants";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub grantq: Option<String>,
        #[serde(rename = "grantsPage", default, skip_serializing_if = "Option::is_none")]
        pub grants_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200GrantsItemClientId {
        V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
        Bool(bool),
        Number(f64),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200GrantsItemSubject {
        V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
        Bool(bool),
        Number(f64),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200GrantsItemScopesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resource: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200GrantsItemUpdatedBy {
        V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
        Bool(bool),
        Number(f64),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200GrantsItem {
        #[serde(rename = "grantId", default, skip_serializing_if = "Option::is_none")]
        pub grant_id: Option<String>,
        #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub client_id: Option<Option<Answer200GrantsItemClientId>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub subject: Option<Option<Answer200GrantsItemSubject>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub generation: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tokens: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scopes: Option<Vec<Answer200GrantsItemScopesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub claims: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authorization_details: Option<Vec<serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub created_at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub last_updated: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub updated_by: Option<Option<Answer200GrantsItemUpdatedBy>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Filter {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub q: Option<Option<String>>,
        #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub client_id: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Paging {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub grants: Option<sts_model_management_components_4::WithPagePagesPerPage>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub grants: Option<Vec<Answer200GrantsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub matched: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub filter: Option<Answer200Filter>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<Answer200Paging>,
    }
}

/// Revoke a grant
pub mod revoke_grant {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/grants/revoke-grant";
    pub const OPERATION_ID: &str = "revokeGrant";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The grant_id, as GET /admin-api/grants lists it.
        #[serde(rename = "grantId")]
        pub grant_id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub revoked: Option<i64>,
    }
}

/// The authorization server's own settings
pub mod get_oauth2_settings {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/oauth2";
    pub const OPERATION_ID: &str = "getOauth2Settings";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithPageTitleWhat;
}

/// What the authorization server has done in this realm, by mechanism, with the
/// pushed authorization requests still held
pub mod get_oauth2_monitor {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/oauth2/monitor";
    pub const OPERATION_ID: &str = "getOauth2Monitor";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryState {
        #[serde(rename = "live")]
        Live,
        #[serde(rename = "spent")]
        Spent,
        #[serde(rename = "all")]
        All,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub offset: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub limit: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<QueryState>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(rename = "clientsPage", default, skip_serializing_if = "Option::is_none")]
        pub clients_page: Option<i64>,
        #[serde(rename = "stepUpClientsPage", default, skip_serializing_if = "Option::is_none")]
        pub step_up_clients_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SectionsItemEventsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub event: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counter: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub count: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SectionsItemErrorsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub count: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SectionsItemClientsItemErrorsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub count: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SectionsItemClientsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client_id: Option<String>,
        /// Each counter, for this client.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counters: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<Answer200SectionsItemClientsItemErrorsItem>>,
        #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_at: Option<Option<String>>,
        #[serde(rename = "lastEvent", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_event: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SectionsItemPushedRequestsFilter {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client_id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SectionsItemPushedRequestsPaging {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pages: Option<i64>,
        #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
        pub per_page: Option<i64>,
        #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
        pub first_row: Option<i64>,
        #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
        pub last_row: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200SectionsItemPushedRequestsItemsItemClientId {
        V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
        Bool(bool),
        Number(f64),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200SectionsItemPushedRequestsItemsItemAuthorizationServer {
        V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
        Bool(bool),
        Number(f64),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200SectionsItemPushedRequestsItemsItemSource {
        V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
        Bool(bool),
        Number(f64),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200SectionsItemPushedRequestsItemsItemRequestObjectAlg {
        V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
        Bool(bool),
        Number(f64),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200SectionsItemPushedRequestsItemsItemRequestObjectEncrypted {
        V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
        Bool(bool),
        Number(f64),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SectionsItemPushedRequestsItemsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub request_uri_digest: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub request_uri_shown: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub client_id: Option<Option<Answer200SectionsItemPushedRequestsItemsItemClientId>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub authorization_server: Option<Option<Answer200SectionsItemPushedRequestsItemsItemAuthorizationServer>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub created_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expires_in: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub spent_at: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reads: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub client_authenticated: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authentication_method: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub source: Option<Option<Answer200SectionsItemPushedRequestsItemsItemSource>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub request_object_alg: Option<Option<Answer200SectionsItemPushedRequestsItemsItemRequestObjectAlg>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub request_object_encrypted: Option<Option<Answer200SectionsItemPushedRequestsItemsItemRequestObjectEncrypted>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dpop_jkt: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attested_jkt: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub redirect_uri: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub redirect_uri_unregistered: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub response_type: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        /// The authorization request a client pushed (RFC 9126), which may carry
        /// any parameter and a request object's claims of any JSON type.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub parameters: Option<serde_json::Value>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SectionsItemPushedRequests {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub filter: Option<Answer200SectionsItemPushedRequestsFilter>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub total: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub offset: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub limit: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub capacity: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub lifetime_s: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<Answer200SectionsItemPushedRequestsPaging>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub items: Option<Vec<Answer200SectionsItemPushedRequestsItemsItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SectionsItemOwnResourceRequirement {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub acr_values: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub max_age: Option<Option<f64>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SectionsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub events: Option<Vec<Answer200SectionsItemEventsItem>>,
        /// Each counter this section shows.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub totals: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_at: Option<Option<String>>,
        #[serde(rename = "lastEvent", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub last_event: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<Answer200SectionsItemErrorsItem>>,
        #[serde(rename = "clientsPaging", default, skip_serializing_if = "Option::is_none")]
        pub clients_paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(rename = "clientsParam", default, skip_serializing_if = "Option::is_none")]
        pub clients_param: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub clients: Option<Vec<Answer200SectionsItemClientsItem>>,
        #[serde(rename = "pushedRequests", default, skip_serializing_if = "Option::is_none")]
        pub pushed_requests: Option<Answer200SectionsItemPushedRequests>,
        #[serde(rename = "ownResourceRequirement", default, skip_serializing_if = "Option::is_none")]
        pub own_resource_requirement: Option<Answer200SectionsItemOwnResourceRequirement>,
        #[serde(rename = "acrValuesSupported", default, skip_serializing_if = "Option::is_none")]
        pub acr_values_supported: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub page: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub since: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sections: Option<Vec<Answer200SectionsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actions: Option<Vec<String>>,
    }
}

/// Withdraw a pushed authorization request (RFC 9126)
pub mod delete_pushed_request {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/oauth2/monitor/delete-pushed-request";
    pub const OPERATION_ID: &str = "deletePushedRequest";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The request's handle: the base64url SHA-256 of its whole request_uri, as
        /// listed by GET /admin-api/oauth2/monitor.
        pub request_uri_digest: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors175;
}

/// The credential issuer's own settings
pub mod get_oid4vci_settings {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/oid4vci-settings";
    pub const OPERATION_ID: &str = "getOid4vciSettings";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithPageTitleWhat;
}

/// How the OpenID4VCI issuer's last Credential Request arrived
pub mod get_last_credential_request {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/oid4vci/last-request";
    pub const OPERATION_ID: &str = "getLastCredentialRequest";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub seen: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub encrypted: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub path: Option<String>,
        #[serde(rename = "contentType", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub content_type: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub kid: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub alg: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub enc: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub at: Option<String>,
    }
}

/// What a wallet told the OpenID4VCI issuer about one credential
pub mod get_credential_notification {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/oid4vci/notifications";
    pub const OPERATION_ID: &str = "getCredentialNotification";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        pub id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Answer200EventDescription {
        V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
        Bool(bool),
        Number(f64),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notification_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub event: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub event_description: Option<Option<Answer200EventDescription>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub notified_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    }
}

/// The Verifier's own settings
pub mod get_oid4vp_settings {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/oid4vp-settings";
    pub const OPERATION_ID: &str = "getOid4vpSettings";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithPageTitleWhat;
}

/// This realm as an OpenID Federation entity: its role, Entity Configuration,
/// keys, subordinates, Trust Anchors and Trust Marks
pub mod get_oidfed {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/oidfed";
    pub const OPERATION_ID: &str = "getOidfed";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(rename = "keysPage", default, skip_serializing_if = "Option::is_none")]
        pub keys_page: Option<i64>,
        #[serde(rename = "subordinatesPage", default, skip_serializing_if = "Option::is_none")]
        pub subordinates_page: Option<i64>,
        #[serde(rename = "formerPage", default, skip_serializing_if = "Option::is_none")]
        pub former_page: Option<i64>,
        #[serde(rename = "anchorsPage", default, skip_serializing_if = "Option::is_none")]
        pub anchors_page: Option<i64>,
        #[serde(rename = "issuedPage", default, skip_serializing_if = "Option::is_none")]
        pub issued_page: Option<i64>,
        #[serde(rename = "heldPage", default, skip_serializing_if = "Option::is_none")]
        pub held_page: Option<i64>,
        #[serde(rename = "policiesPage", default, skip_serializing_if = "Option::is_none")]
        pub policies_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Endpoints {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub configuration: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fetch: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub list: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resolve: Option<String>,
        #[serde(rename = "trustMark", default, skip_serializing_if = "Option::is_none")]
        pub trust_mark: Option<String>,
        #[serde(rename = "trustMarkStatus", default, skip_serializing_if = "Option::is_none")]
        pub trust_mark_status: Option<String>,
        #[serde(rename = "trustMarkList", default, skip_serializing_if = "Option::is_none")]
        pub trust_mark_list: Option<String>,
        #[serde(rename = "historicalKeys", default, skip_serializing_if = "Option::is_none")]
        pub historical_keys: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub register: Option<String>,
        #[serde(rename = "extendedList", default, skip_serializing_if = "Option::is_none")]
        pub extended_list: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub collection: Option<String>,
        #[serde(rename = "subordinateEvents", default, skip_serializing_if = "Option::is_none")]
        pub subordinate_events: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200KeysItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kid: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alg: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sealed: Option<bool>,
        #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub created_at: Option<Option<String>>,
        #[serde(rename = "activatedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub activated_at: Option<Option<String>>,
        #[serde(rename = "retiredAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub retired_at: Option<Option<String>>,
        #[serde(rename = "publishedUntil", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub published_until: Option<Option<String>>,
        #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub revoked_at: Option<Option<String>>,
        #[serde(rename = "revokedReason", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub revoked_reason: Option<Option<String>>,
        #[serde(rename = "publicJwk", default, skip_serializing_if = "Option::is_none")]
        pub public_jwk: Option<sts_model_management_components_2::WithKtyUseAlg>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SubordinatesItemSuspended {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub at: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub reason: Option<Option<String>>,
        #[serde(rename = "informationUri", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub information_uri: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SubordinatesItemEventsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub iat: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub event: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub event_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub information_uri: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SubordinatesItem {
        #[serde(rename = "entityId", default, skip_serializing_if = "Option::is_none")]
        pub entity_id: Option<String>,
        #[serde(rename = "localRealm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub local_realm: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub implicit: Option<bool>,
        #[serde(rename = "entityTypes", default, skip_serializing_if = "Option::is_none")]
        pub entity_types: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub intermediate: Option<bool>,
        #[serde(rename = "metadataPolicy", default, skip_serializing_if = "Option::is_none")]
        pub metadata_policy: Option<sts_model_management_components_2::JwkSetMetadataDocumentMetadata>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub constraints: Option<sts_model_management_components_2::JwkSetMetadataDocumentMetadata>,
        #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub created_at: Option<Option<String>>,
        #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub updated_at: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kids: Option<Vec<Option<String>>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub suspended: Option<Answer200SubordinatesItemSuspended>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub events: Option<Vec<Answer200SubordinatesItemEventsItem>>,
        #[serde(rename = "eventsTotal", default, skip_serializing_if = "Option::is_none")]
        pub events_total: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200FormerSubordinatesItemEventsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub iat: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub event: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub event_description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub information_uri: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200FormerSubordinatesItem {
        #[serde(rename = "entityId", default, skip_serializing_if = "Option::is_none")]
        pub entity_id: Option<String>,
        #[serde(rename = "localRealm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub local_realm: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub events: Option<Vec<Answer200FormerSubordinatesItemEventsItem>>,
        #[serde(rename = "eventsTotal", default, skip_serializing_if = "Option::is_none")]
        pub events_total: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TrustAnchorsItem {
        #[serde(rename = "entityId", default, skip_serializing_if = "Option::is_none")]
        pub entity_id: Option<String>,
        #[serde(rename = "localRealm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub local_realm: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kids: Option<Vec<Option<String>>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200MarkTypesItem {
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<String>,
        #[serde(rename = "lifetimeS", default, skip_serializing_if = "Option::is_none")]
        pub lifetime_s: Option<f64>,
        #[serde(rename = "logoUri", default, skip_serializing_if = "Option::is_none")]
        pub logo_uri: Option<String>,
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        pub ref_: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub delegation: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200MarkPoliciesItem {
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuers: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub owner: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200IssuedMarksItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sub: Option<String>,
        #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub issued_at: Option<Option<String>>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub expires_at: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(rename = "revokedReason", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub revoked_reason: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200HeldMarksItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
        pub type_: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub iss: Option<String>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub expires_at: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Counts {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub keys: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subordinates: Option<i64>,
        #[serde(rename = "formerSubordinates", default, skip_serializing_if = "Option::is_none")]
        pub former_subordinates: Option<i64>,
        #[serde(rename = "trustAnchors", default, skip_serializing_if = "Option::is_none")]
        pub trust_anchors: Option<i64>,
        #[serde(rename = "issuedMarks", default, skip_serializing_if = "Option::is_none")]
        pub issued_marks: Option<i64>,
        #[serde(rename = "heldMarks", default, skip_serializing_if = "Option::is_none")]
        pub held_marks: Option<i64>,
        #[serde(rename = "markPolicies", default, skip_serializing_if = "Option::is_none")]
        pub mark_policies: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Paging {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub keys: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subordinates: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(rename = "formerSubordinates", default, skip_serializing_if = "Option::is_none")]
        pub former_subordinates: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(rename = "trustAnchors", default, skip_serializing_if = "Option::is_none")]
        pub trust_anchors: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(rename = "issuedMarks", default, skip_serializing_if = "Option::is_none")]
        pub issued_marks: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(rename = "heldMarks", default, skip_serializing_if = "Option::is_none")]
        pub held_marks: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(rename = "markPolicies", default, skip_serializing_if = "Option::is_none")]
        pub mark_policies: Option<sts_model_management_components_4::WithPagePagesPerPage>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(rename = "entityId", default, skip_serializing_if = "Option::is_none")]
        pub entity_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub role: Option<String>,
        #[serde(rename = "configurationUrl", default, skip_serializing_if = "Option::is_none")]
        pub configuration_url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub endpoints: Option<Answer200Endpoints>,
        #[serde(rename = "authorityHints", default, skip_serializing_if = "Option::is_none")]
        pub authority_hints: Option<Vec<String>>,
        #[serde(rename = "realmsAreSubordinates", default, skip_serializing_if = "Option::is_none")]
        pub realms_are_subordinates: Option<bool>,
        #[serde(rename = "signingAlg", default, skip_serializing_if = "Option::is_none")]
        pub signing_alg: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub keys: Option<Vec<Answer200KeysItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subordinates: Option<Vec<Answer200SubordinatesItem>>,
        #[serde(rename = "formerSubordinates", default, skip_serializing_if = "Option::is_none")]
        pub former_subordinates: Option<Vec<Answer200FormerSubordinatesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub collection: Option<sts_model_management_components_4::WithCrawlCrawlEverySJobOff>,
        #[serde(rename = "trustAnchors", default, skip_serializing_if = "Option::is_none")]
        pub trust_anchors: Option<Vec<Answer200TrustAnchorsItem>>,
        #[serde(rename = "markTypes", default, skip_serializing_if = "Option::is_none")]
        pub mark_types: Option<Vec<Answer200MarkTypesItem>>,
        #[serde(rename = "markPolicies", default, skip_serializing_if = "Option::is_none")]
        pub mark_policies: Option<Vec<Answer200MarkPoliciesItem>>,
        #[serde(rename = "issuedMarks", default, skip_serializing_if = "Option::is_none")]
        pub issued_marks: Option<Vec<Answer200IssuedMarksItem>>,
        #[serde(rename = "heldMarks", default, skip_serializing_if = "Option::is_none")]
        pub held_marks: Option<Vec<Answer200HeldMarksItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resolutions: Option<Vec<sts_model_management_components_4::WithSubjectAnchorExpiresAt>>,
        /// This realm's Entity Configuration, the claims of a signed statement
        /// (OpenID Federation 1.1 section 3.1): its `metadata` is one document per
        /// entity type, and each is the document that protocol publishes.
        #[serde(rename = "entityConfiguration", default, skip_serializing_if = "Option::is_none")]
        pub entity_configuration: Option<serde_json::Value>,
        #[serde(rename = "entityConfigurationProblem", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub entity_configuration_problem: Option<Option<String>>,
        #[serde(rename = "statementLifetimeS", default, skip_serializing_if = "Option::is_none")]
        pub statement_lifetime_s: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_3::SettingsValue2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counts: Option<Answer200Counts>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paging: Option<Answer200Paging>,
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
    }
}

/// Carry a Trust Mark issued to this realm
pub mod add_oidfed_held_mark {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/oidfed/add-held-mark";
    pub const OPERATION_ID: &str = "addOidfedHeldMark";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// A trust-mark+jwt whose sub is this realm.
        #[serde(rename = "trustMark")]
        pub trust_mark: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
    }
}

/// Issue Trust Marks of a type
pub mod add_oidfed_mark_type {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/oidfed/add-mark-type";
    pub const OPERATION_ID: &str = "addOidfedMarkType";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The Trust Mark type identifier, a URL.
        #[serde(rename = "type")]
        pub type_: String,
        /// Seconds each mark lives; oidfed.trustMarkLifetimeS when absent.
        #[serde(rename = "lifetimeS", default, skip_serializing_if = "Option::is_none")]
        pub lifetime_s: Option<i64>,
        #[serde(rename = "logoUri", default, skip_serializing_if = "Option::is_none")]
        pub logo_uri: Option<String>,
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        pub ref_: Option<String>,
        /// A trust-mark-delegation+jwt.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub delegation: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors172;
}

/// Register an entity this realm vouches for
pub mod add_oidfed_subordinate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/oidfed/add-subordinate";
    pub const OPERATION_ID: &str = "addOidfedSubordinate";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// An Entity Identifier: an https URL with no query or fragment.
        #[serde(rename = "entityId")]
        pub entity_id: String,
        /// Its JWK Set, as a JSON object or its text.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub jwks: Option<serde_json::Value>,
        /// Read its keys from its Entity Configuration.
        #[serde(rename = "fetchJwks", default, skip_serializing_if = "Option::is_none")]
        pub fetch_jwks: Option<bool>,
        /// Metadata overriding its own (3.1.1), as a JSON object or its text.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub metadata: Option<serde_json::Value>,
        /// A metadata_policy (6.1), as a JSON object or its text.
        #[serde(rename = "metadataPolicy", default, skip_serializing_if = "Option::is_none")]
        pub metadata_policy: Option<serde_json::Value>,
        /// Critical additional operators, comma-separated.
        #[serde(rename = "metadataPolicyCrit", default, skip_serializing_if = "Option::is_none")]
        pub metadata_policy_crit: Option<String>,
        /// constraints (6.2), as a JSON object or its text.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub constraints: Option<serde_json::Value>,
        /// Its entity types, comma-separated, for the listing filter; read from its
        /// configuration when fetched.
        #[serde(rename = "entityTypes", default, skip_serializing_if = "Option::is_none")]
        pub entity_types: Option<String>,
        /// Whether it is an Intermediate.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub intermediate: Option<bool>,
        /// Recorded as the event_description of the event this act adds to the
        /// subordinate's history.
        #[serde(rename = "eventDescription", default, skip_serializing_if = "Option::is_none")]
        pub event_description: Option<String>,
        /// An http or https URL of a page about the event, recorded as its
        /// information_uri.
        #[serde(rename = "informationUri", default, skip_serializing_if = "Option::is_none")]
        pub information_uri: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors169;
}

/// Trust a Trust Anchor
pub mod add_oidfed_trust_anchor {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/oidfed/add-trust-anchor";
    pub const OPERATION_ID: &str = "addOidfedTrustAnchor";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// An Entity Identifier: an https URL with no query or fragment.
        #[serde(rename = "entityId")]
        pub entity_id: String,
        /// Its JWK Set, as a JSON object or its text.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub jwks: Option<serde_json::Value>,
        /// Read its keys from its Entity Configuration.
        #[serde(rename = "fetchJwks", default, skip_serializing_if = "Option::is_none")]
        pub fetch_jwks: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors171;
}

/// Crawl the Entity Collection now
pub mod crawl_oidfed_collection {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/oidfed/crawl-collection";
    pub const OPERATION_ID: &str = "crawlOidfedCollection";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors170;
}

/// Issue a Trust Mark to an entity
pub mod issue_oidfed_trust_mark {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/oidfed/issue-trust-mark";
    pub const OPERATION_ID: &str = "issueOidfedTrustMark";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(rename = "type")]
        pub type_: String,
        /// An Entity Identifier: an https URL with no query or fragment.
        pub sub: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(rename = "trustMark", default, skip_serializing_if = "Option::is_none")]
        pub trust_mark: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
    }
}

/// Reinstate a suspended subordinate
pub mod reinstate_oidfed_subordinate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/oidfed/reinstate-subordinate";
    pub const OPERATION_ID: &str = "reinstateOidfedSubordinate";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// An Entity Identifier: an https URL with no query or fragment.
        #[serde(rename = "entityId")]
        pub entity_id: String,
        /// Recorded as the event_description of the event this act adds to the
        /// subordinate's history.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        /// An http or https URL of a page about the event, recorded as its
        /// information_uri.
        #[serde(rename = "informationUri", default, skip_serializing_if = "Option::is_none")]
        pub information_uri: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
    }
}

/// Stop carrying a Trust Mark
pub mod remove_oidfed_held_mark {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/oidfed/remove-held-mark";
    pub const OPERATION_ID: &str = "removeOidfedHeldMark";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
    }
}

/// Remove a Trust Anchor's policy for a type
pub mod remove_oidfed_mark_policy {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/oidfed/remove-mark-policy";
    pub const OPERATION_ID: &str = "removeOidfedMarkPolicy";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(rename = "type")]
        pub type_: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
    }
}

/// Stop issuing a Trust Mark type
pub mod remove_oidfed_mark_type {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/oidfed/remove-mark-type";
    pub const OPERATION_ID: &str = "removeOidfedMarkType";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(rename = "type")]
        pub type_: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
    }
}

/// Revoke a subordinate
pub mod remove_oidfed_subordinate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/oidfed/remove-subordinate";
    pub const OPERATION_ID: &str = "removeOidfedSubordinate";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// An Entity Identifier: an https URL with no query or fragment.
        #[serde(rename = "entityId")]
        pub entity_id: String,
        /// Recorded as the event_description of the event this act adds to the
        /// subordinate's history.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        /// An http or https URL of a page about the event, recorded as its
        /// information_uri.
        #[serde(rename = "informationUri", default, skip_serializing_if = "Option::is_none")]
        pub information_uri: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
    }
}

/// Stop trusting a Trust Anchor
pub mod remove_oidfed_trust_anchor {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/oidfed/remove-trust-anchor";
    pub const OPERATION_ID: &str = "removeOidfedTrustAnchor";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// An Entity Identifier: an https URL with no query or fragment.
        #[serde(rename = "entityId")]
        pub entity_id: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
    }
}

/// Resolve an entity's Trust Chain to one of this realm's Trust Anchors
pub mod resolve_oidfed_entity {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/oidfed/resolve";
    pub const OPERATION_ID: &str = "resolveOidfedEntity";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// An Entity Identifier: an https URL with no query or fragment.
        pub sub: String,
        /// The anchor to resolve to; any of the realm's when absent.
        #[serde(rename = "trustAnchor", default, skip_serializing_if = "Option::is_none")]
        pub trust_anchor: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors174;
}

/// Revoke a retired Federation Entity Key
pub mod revoke_oidfed_key {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/oidfed/revoke-key";
    pub const OPERATION_ID: &str = "revokeOidfedKey";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyReason {
        #[serde(rename = "unspecified")]
        Unspecified,
        #[serde(rename = "compromised")]
        Compromised,
        #[serde(rename = "superseded")]
        Superseded,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub kid: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<BodyReason>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
    }
}

/// Revoke a Trust Mark this realm issued
pub mod revoke_oidfed_trust_mark {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/oidfed/revoke-trust-mark";
    pub const OPERATION_ID: &str = "revokeOidfedTrustMark";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The mark's id, from GET /admin-api/oidfed.
        pub id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
    }
}

/// Rotate the realm's Federation Entity Key
pub mod rotate_oidfed_key {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/oidfed/rotate-key";
    pub const OPERATION_ID: &str = "rotateOidfedKey";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub emergency: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub confirm: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(rename = "runId", default, skip_serializing_if = "Option::is_none")]
        pub run_id: Option<sts_model_base::unions::NumberOrString>,
    }
}

/// As a Trust Anchor: who may issue a type, and who owns it
pub mod set_oidfed_mark_policy {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/oidfed/set-mark-policy";
    pub const OPERATION_ID: &str = "setOidfedMarkPolicy";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        #[serde(rename = "type")]
        pub type_: String,
        /// Entity Identifiers, comma-separated; none means anybody.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuers: Option<String>,
        /// An Entity Identifier: an https URL with no query or fragment.
        #[serde(rename = "ownerSub", default, skip_serializing_if = "Option::is_none")]
        pub owner_sub: Option<String>,
        /// The owner's JWK Set, as a JSON object or its text.
        #[serde(rename = "ownerJwks", default, skip_serializing_if = "Option::is_none")]
        pub owner_jwks: Option<serde_json::Value>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors173;
}

/// Suspend a subordinate
pub mod suspend_oidfed_subordinate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/oidfed/suspend-subordinate";
    pub const OPERATION_ID: &str = "suspendOidfedSubordinate";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// An Entity Identifier: an https URL with no query or fragment.
        #[serde(rename = "entityId")]
        pub entity_id: String,
        /// Recorded as the event_description of the event this act adds to the
        /// subordinate's history.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        /// An http or https URL of a page about the event, recorded as its
        /// information_uri.
        #[serde(rename = "informationUri", default, skip_serializing_if = "Option::is_none")]
        pub information_uri: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
    }
}

/// Who owns an object, and whether its owners may administer it
pub mod get_ownership {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/ownership";
    pub const OPERATION_ID: &str = "getOwnership";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryKind {
        #[serde(rename = "role")]
        Role,
        #[serde(rename = "group")]
        Group,
        #[serde(rename = "service-account")]
        ServiceAccount,
        #[serde(rename = "application")]
        Application,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        pub kind: QueryKind,
        pub name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub found: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub owners: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protected: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reasons: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub marked: Option<bool>,
    }
}

/// Close an object to its owners, or open it again
pub mod set_owner_protected {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/ownership/set-protected";
    pub const OPERATION_ID: &str = "setOwnerProtected";

    /// Which kind of object.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKind {
        #[serde(rename = "role")]
        Role,
        #[serde(rename = "group")]
        Group,
        #[serde(rename = "service-account")]
        ServiceAccount,
        #[serde(rename = "application")]
        Application,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Which kind of object.
        pub kind: BodyKind,
        /// The object, as GET /admin-api/ownership names it.
        pub name: String,
        /// true closes it to its owners; false opens it again.
        pub protected: sts_model_base::unions::BoolOrString,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors141;
}

/// What survives a restart, where it is written, and whether that is working
pub mod get_persistence_settings {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/persistence";
    pub const OPERATION_ID: &str = "getPersistenceSettings";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_2::PageSettings;
}

/// The certificate authority this trust realm holds, and what has been issued
/// from it
pub mod get_pki {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/pki";
    pub const OPERATION_ID: &str = "getPki";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum QueryRows {
        #[serde(rename = "all")]
        All,
        #[serde(rename = "shown")]
        Shown,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(rename = "issuedPage", default, skip_serializing_if = "Option::is_none")]
        pub issued_page: Option<i64>,
        #[serde(rename = "personsPage", default, skip_serializing_if = "Option::is_none")]
        pub persons_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuedq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<QueryRows>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub personsq: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SignatureAlgorithmsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub weak: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub kind: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TiersItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(rename = "pathLen", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub path_len: Option<Option<i64>>,
        #[serde(rename = "keyUsage", default, skip_serializing_if = "Option::is_none")]
        pub key_usage: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub years: Option<f64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RevocationReasonsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RevocationAuthoritiesItemIssuedItem {
        #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
        pub serial_hex: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expired: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub revoked: Option<bool>,
        #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub revoked_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(rename = "revokedReason", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub revoked_reason: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub held: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RevocationAuthoritiesItemCrl {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub http: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub ldap: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RevocationAuthoritiesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(rename = "scopeSegment", default, skip_serializing_if = "Option::is_none")]
        pub scope_segment: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ca: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<String>,
        #[serde(rename = "listName", default, skip_serializing_if = "Option::is_none")]
        pub list_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issued: Option<Vec<Answer200RevocationAuthoritiesItemIssuedItem>>,
        #[serde(rename = "issuedTotal", default, skip_serializing_if = "Option::is_none")]
        pub issued_total: Option<i64>,
        #[serde(rename = "issuedPaging", default, skip_serializing_if = "Option::is_none")]
        pub issued_paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(rename = "issuedSearch", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub issued_search: Option<Option<String>>,
        #[serde(rename = "orphansSearch", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub orphans_search: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub revoked: Option<sts_model_management_components_4::WithIdLabelKid>,
        #[serde(rename = "revokedTotal", default, skip_serializing_if = "Option::is_none")]
        pub revoked_total: Option<i64>,
        #[serde(rename = "revokedNotIssued", default, skip_serializing_if = "Option::is_none")]
        pub revoked_not_issued: Option<sts_model_management_components_4::WithIdLabelKid>,
        #[serde(rename = "revokedNotIssuedTotal", default, skip_serializing_if = "Option::is_none")]
        pub revoked_not_issued_total: Option<i64>,
        #[serde(rename = "orphansPaging", default, skip_serializing_if = "Option::is_none")]
        pub orphans_paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub crl: Option<Answer200RevocationAuthoritiesItemCrl>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub ocsp: Option<Option<String>>,
        #[serde(rename = "caIssuers", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub ca_issuers: Option<Option<String>>,
        #[serde(rename = "directoryDn", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub directory_dn: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Revocation {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reasons: Option<Vec<Answer200RevocationReasonsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub authorities: Option<Vec<Answer200RevocationAuthoritiesItem>>,
        #[serde(rename = "totalRevoked", default, skip_serializing_if = "Option::is_none")]
        pub total_revoked: Option<i64>,
        #[serde(rename = "crlLifetimeMinutes", default, skip_serializing_if = "Option::is_none")]
        pub crl_lifetime_minutes: Option<f64>,
        #[serde(rename = "publishedToDirectory", default, skip_serializing_if = "Option::is_none")]
        pub published_to_directory: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PinnedSignersKeysItem {
        #[serde(rename = "useCase", default, skip_serializing_if = "Option::is_none")]
        pub use_case: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub slot: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub unit: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kid: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alg: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub crv: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub role: Option<String>,
        #[serde(rename = "pinnedAt", default, skip_serializing_if = "Option::is_none")]
        pub pinned_at: Option<String>,
        #[serde(rename = "activatesAt", default, skip_serializing_if = "Option::is_none")]
        pub activates_at: Option<String>,
        #[serde(rename = "retiredAt", default, skip_serializing_if = "Option::is_none")]
        pub retired_at: Option<String>,
        #[serde(rename = "retiredUntil", default, skip_serializing_if = "Option::is_none")]
        pub retired_until: Option<String>,
        #[serde(rename = "operatorCertificate", default, skip_serializing_if = "Option::is_none")]
        pub operator_certificate: Option<bool>,
        #[serde(rename = "supersedesUntil", default, skip_serializing_if = "Option::is_none")]
        pub supersedes_until: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
        pub serial_hex: Option<String>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expired: Option<bool>,
        #[serde(rename = "daysLeft", default, skip_serializing_if = "Option::is_none")]
        pub days_left: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub thumbprint: Option<String>,
        #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
        pub certificate_pem: Option<String>,
        #[serde(rename = "chainPem", default, skip_serializing_if = "Option::is_none")]
        pub chain_pem: Option<Vec<String>>,
        #[serde(rename = "publicKeyPem", default, skip_serializing_if = "Option::is_none")]
        pub public_key_pem: Option<String>,
        #[serde(rename = "publicJwk", default, skip_serializing_if = "Option::is_none")]
        pub public_jwk: Option<sts_model_management_components_2::JwkValue>,
        #[serde(rename = "expiringSoon", default, skip_serializing_if = "Option::is_none")]
        pub expiring_soon: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PinnedSigners {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub on: Option<bool>,
        #[serde(rename = "leadMinutes", default, skip_serializing_if = "Option::is_none")]
        pub lead_minutes: Option<f64>,
        #[serde(rename = "warningDays", default, skip_serializing_if = "Option::is_none")]
        pub warning_days: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub keys: Option<Vec<Answer200PinnedSignersKeysItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200IssuedItemPqc {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub family: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub standard: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200IssuedItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub identifier: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub name: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub purpose: Option<String>,
        #[serde(rename = "purposeLabel", default, skip_serializing_if = "Option::is_none")]
        pub purpose_label: Option<String>,
        #[serde(rename = "handleLabel", default, skip_serializing_if = "Option::is_none")]
        pub handle_label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub handle: Option<String>,
        #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<String>,
        #[serde(rename = "hasKeyPair", default, skip_serializing_if = "Option::is_none")]
        pub has_key_pair: Option<bool>,
        #[serde(rename = "privateKeyHeld", default, skip_serializing_if = "Option::is_none")]
        pub private_key_held: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
        #[serde(rename = "assertionIssuers", default, skip_serializing_if = "Option::is_none")]
        pub assertion_issuers: Option<Vec<String>>,
        #[serde(rename = "registeredOwnKeys", default, skip_serializing_if = "Option::is_none")]
        pub registered_own_keys: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pqc: Option<Answer200IssuedItemPqc>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PersonsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub jwt: Option<sts_model_management_components_4::WithHasKeyPairKeysDeclaredIssuers2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub saml: Option<sts_model_management_components_4::WithHasKeyPairKeysDeclaredIssuers2>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200SubjectKindsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PurposesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub attributes: Option<Vec<String>>,
        #[serde(rename = "issuerAttribute", default, skip_serializing_if = "Option::is_none")]
        pub issuer_attribute: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TreeUseCasesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TreeScopesItemIssuingItemCertifiedItemPqc {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub family: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub standard: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TreeScopesItemIssuingItemCertifiedItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub slot: Option<String>,
        #[serde(rename = "useCase", default, skip_serializing_if = "Option::is_none")]
        pub use_case: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub label: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub alg: Option<String>,
        #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
        pub key_alg: Option<String>,
        #[serde(rename = "signatureAlg", default, skip_serializing_if = "Option::is_none")]
        pub signature_alg: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
        pub serial_hex: Option<String>,
        #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
        pub not_before: Option<String>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expired: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub thumbprint: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pinned: Option<bool>,
        #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
        pub certificate_pem: Option<String>,
        #[serde(rename = "chainPem", default, skip_serializing_if = "Option::is_none")]
        pub chain_pem: Option<Vec<String>>,
        #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pqc: Option<Answer200TreeScopesItemIssuingItemCertifiedItemPqc>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TreeScopesItemIssuingItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub what: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub built: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ca: Option<sts_model_management_components_3::RootValue>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certified: Option<Vec<Answer200TreeScopesItemIssuingItemCertifiedItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TreeScopesItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub built: Option<bool>,
        #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
        pub key_alg: Option<String>,
        #[serde(rename = "signatureAlg", default, skip_serializing_if = "Option::is_none")]
        pub signature_alg: Option<String>,
        #[serde(rename = "altKeyAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub alt_key_alg: Option<Option<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub organisation: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub country: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub intermediate: Option<sts_model_management_components_3::RootValue>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuing: Option<Vec<Answer200TreeScopesItemIssuingItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Tree {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub root: Option<sts_model_management_components_3::RootValue>,
        #[serde(rename = "rootBuilt", default, skip_serializing_if = "Option::is_none")]
        pub root_built: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub persisted: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub organisation: Option<String>,
        #[serde(rename = "useCases", default, skip_serializing_if = "Option::is_none")]
        pub use_cases: Option<Vec<Answer200TreeUseCasesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scopes: Option<Vec<Answer200TreeScopesItem>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PageDefaults {
        #[serde(rename = "keyAlgorithm", default, skip_serializing_if = "Option::is_none")]
        pub key_algorithm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub organisation: Option<String>,
        #[serde(rename = "leafLifetimeDays", default, skip_serializing_if = "Option::is_none")]
        pub leaf_lifetime_days: Option<f64>,
        #[serde(rename = "alternativeKeyAlgorithm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub alternative_key_algorithm: Option<Option<String>>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200TierLabelsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub chain: Option<sts_model_management_components_1::ChainValue>,
        #[serde(rename = "keyAlgorithms", default, skip_serializing_if = "Option::is_none")]
        pub key_algorithms: Option<sts_model_management_components_4::WithIdLabelKind2>,
        #[serde(rename = "signatureAlgorithms", default, skip_serializing_if = "Option::is_none")]
        pub signature_algorithms: Option<Vec<Answer200SignatureAlgorithmsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tiers: Option<Vec<Answer200TiersItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub revocation: Option<Answer200Revocation>,
        #[serde(rename = "revocationNote", default, skip_serializing_if = "Option::is_none")]
        pub revocation_note: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub residency: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub encoder: Option<String>,
        #[serde(rename = "pinnedSigners", default, skip_serializing_if = "Option::is_none")]
        pub pinned_signers: Option<Answer200PinnedSigners>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actions: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issued: Option<Vec<Answer200IssuedItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub persons: Option<Vec<Answer200PersonsItem>>,
        #[serde(rename = "personSigningKeyMax", default, skip_serializing_if = "Option::is_none")]
        pub person_signing_key_max: Option<f64>,
        #[serde(rename = "personRevocationReasons", default, skip_serializing_if = "Option::is_none")]
        pub person_revocation_reasons: Option<Vec<String>>,
        #[serde(rename = "personsStorable", default, skip_serializing_if = "Option::is_none")]
        pub persons_storable: Option<bool>,
        #[serde(rename = "personAttributes", default, skip_serializing_if = "Option::is_none")]
        pub person_attributes: Option<Vec<String>>,
        #[serde(rename = "personIssuerAttribute", default, skip_serializing_if = "Option::is_none")]
        pub person_issuer_attribute: Option<String>,
        #[serde(rename = "subjectKinds", default, skip_serializing_if = "Option::is_none")]
        pub subject_kinds: Option<Vec<Answer200SubjectKindsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub purposes: Option<Vec<Answer200PurposesItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tree: Option<Answer200Tree>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub workbench: Option<sts_model_management_components_4::WithFieldsProfilesPqModes2>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub settings: Option<sts_model_management_components_3::SettingsValue2>,
        #[serde(rename = "issuedPaging", default, skip_serializing_if = "Option::is_none")]
        pub issued_paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(rename = "personsPaging", default, skip_serializing_if = "Option::is_none")]
        pub persons_paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(rename = "issuedSearch", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub issued_search: Option<Option<String>>,
        #[serde(rename = "personsSearch", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
        pub persons_search: Option<Option<String>>,
        #[serde(rename = "issuedShown", default, skip_serializing_if = "Option::is_none")]
        pub issued_shown: Option<Vec<i64>>,
        #[serde(rename = "personsShown", default, skip_serializing_if = "Option::is_none")]
        pub persons_shown: Option<Vec<i64>>,
        #[serde(rename = "pageDefaults", default, skip_serializing_if = "Option::is_none")]
        pub page_defaults: Option<Answer200PageDefaults>,
        #[serde(rename = "tierLabels", default, skip_serializing_if = "Option::is_none")]
        pub tier_labels: Option<Vec<Answer200TierLabelsItem>>,
        #[serde(rename = "serviceScope", default, skip_serializing_if = "Option::is_none")]
        pub service_scope: Option<String>,
        #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
        pub protocol_endpoints: Option<sts_model_management_components_4::WithParamsDescriptionParams>,
    }
}

/// Build this realm's certificate authority — all three tiers
pub mod build_pki_chain {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/pki/build";
    pub const OPERATION_ID: &str = "buildPkiChain";

    /// One of the ids in `keyAlgorithms` on GET /admin-api/pki: rsa-2048, rsa-3072,
    /// rsa-4096, ec-p256, ec-p384, ec-p521 or ed25519. One algorithm for all three
    /// tiers — the LEAF's signature algorithm is decided by the Issuing CA's key,
    /// and that is what a client library has to be able to verify. Defaults to
    /// `pki.keyAlgorithm`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKeyAlg {
        #[serde(rename = "rsa-2048")]
        Rsa2048,
        #[serde(rename = "rsa-3072")]
        Rsa3072,
        #[serde(rename = "rsa-4096")]
        Rsa4096,
        #[serde(rename = "ec-p256")]
        EcP256,
        #[serde(rename = "ec-p384")]
        EcP384,
        #[serde(rename = "ec-p521")]
        EcP521,
        #[serde(rename = "ed25519")]
        Ed25519,
        #[serde(rename = "ml-dsa-44")]
        MlDsa44,
        #[serde(rename = "ml-dsa-65")]
        MlDsa65,
        #[serde(rename = "ml-dsa-87")]
        MlDsa87,
        #[serde(rename = "slh-dsa-sha2-128s")]
        SlhDsaSha2128s,
        #[serde(rename = "slh-dsa-sha2-128f")]
        SlhDsaSha2128f,
        #[serde(rename = "slh-dsa-sha2-192s")]
        SlhDsaSha2192s,
        #[serde(rename = "slh-dsa-sha2-192f")]
        SlhDsaSha2192f,
        #[serde(rename = "slh-dsa-sha2-256s")]
        SlhDsaSha2256s,
        #[serde(rename = "slh-dsa-sha2-256f")]
        SlhDsaSha2256f,
        #[serde(rename = "slh-dsa-shake-128s")]
        SlhDsaShake128s,
        #[serde(rename = "slh-dsa-shake-128f")]
        SlhDsaShake128f,
        #[serde(rename = "slh-dsa-shake-192s")]
        SlhDsaShake192s,
        #[serde(rename = "slh-dsa-shake-192f")]
        SlhDsaShake192f,
        #[serde(rename = "slh-dsa-shake-256s")]
        SlhDsaShake256s,
        #[serde(rename = "slh-dsa-shake-256f")]
        SlhDsaShake256f,
        #[serde(rename = "mldsa44-rsa2048-pss-sha256")]
        Mldsa44Rsa2048PssSha256,
        #[serde(rename = "mldsa44-rsa2048-pkcs15-sha256")]
        Mldsa44Rsa2048Pkcs15Sha256,
        #[serde(rename = "mldsa44-ed25519-sha512")]
        Mldsa44Ed25519Sha512,
        #[serde(rename = "mldsa44-ecdsa-p256-sha256")]
        Mldsa44EcdsaP256Sha256,
        #[serde(rename = "mldsa65-rsa3072-pss-sha512")]
        Mldsa65Rsa3072PssSha512,
        #[serde(rename = "mldsa65-rsa3072-pkcs15-sha512")]
        Mldsa65Rsa3072Pkcs15Sha512,
        #[serde(rename = "mldsa65-rsa4096-pss-sha512")]
        Mldsa65Rsa4096PssSha512,
        #[serde(rename = "mldsa65-rsa4096-pkcs15-sha512")]
        Mldsa65Rsa4096Pkcs15Sha512,
        #[serde(rename = "mldsa65-ecdsa-p256-sha512")]
        Mldsa65EcdsaP256Sha512,
        #[serde(rename = "mldsa65-ecdsa-p384-sha512")]
        Mldsa65EcdsaP384Sha512,
        #[serde(rename = "mldsa65-ed25519-sha512")]
        Mldsa65Ed25519Sha512,
        #[serde(rename = "mldsa87-ecdsa-p384-sha512")]
        Mldsa87EcdsaP384Sha512,
        #[serde(rename = "mldsa87-ed448-shake256")]
        Mldsa87Ed448Shake256,
        #[serde(rename = "mldsa87-rsa3072-pss-sha512")]
        Mldsa87Rsa3072PssSha512,
        #[serde(rename = "mldsa87-rsa4096-pss-sha512")]
        Mldsa87Rsa4096PssSha512,
        #[serde(rename = "mldsa87-ecdsa-p521-sha512")]
        Mldsa87EcdsaP521Sha512,
        #[serde(rename = "ml-kem-512")]
        MlKem512,
        #[serde(rename = "ml-kem-768")]
        MlKem768,
        #[serde(rename = "ml-kem-1024")]
        MlKem1024,
    }

    /// The post-quantum key every authority built here holds beside its classical
    /// one (ITU-T X.509 clause 9.8, #68): one of `alternativeKeyAlgorithms` on GET
    /// /admin-api/pki, or `none` for a classical-only authority. Defaults to
    /// `pki.alternativeKeyAlgorithm`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyAltKeyAlg {
        #[serde(rename = "ml-dsa-44")]
        MlDsa44,
        #[serde(rename = "ml-dsa-65")]
        MlDsa65,
        #[serde(rename = "ml-dsa-87")]
        MlDsa87,
        #[serde(rename = "slh-dsa-sha2-128s")]
        SlhDsaSha2128s,
        #[serde(rename = "slh-dsa-sha2-128f")]
        SlhDsaSha2128f,
        #[serde(rename = "slh-dsa-sha2-192s")]
        SlhDsaSha2192s,
        #[serde(rename = "slh-dsa-sha2-192f")]
        SlhDsaSha2192f,
        #[serde(rename = "slh-dsa-sha2-256s")]
        SlhDsaSha2256s,
        #[serde(rename = "slh-dsa-sha2-256f")]
        SlhDsaSha2256f,
        #[serde(rename = "slh-dsa-shake-128s")]
        SlhDsaShake128s,
        #[serde(rename = "slh-dsa-shake-128f")]
        SlhDsaShake128f,
        #[serde(rename = "slh-dsa-shake-192s")]
        SlhDsaShake192s,
        #[serde(rename = "slh-dsa-shake-192f")]
        SlhDsaShake192f,
        #[serde(rename = "slh-dsa-shake-256s")]
        SlhDsaShake256s,
        #[serde(rename = "slh-dsa-shake-256f")]
        SlhDsaShake256f,
        #[serde(rename = "none")]
        None,
    }

    /// One of the ids in `signatureAlgorithms`. OMIT IT for "the right one for the
    /// key algorithm", which is almost always what is wanted: an EC key's digest is
    /// decided by its CURVE, so naming one here can hand a P-521 key SHA-256 —
    /// legal, verifying, and nobody's intention. A pair whose families disagree is
    /// refused with the list beside it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodySignatureAlg {
        #[serde(rename = "sha256-rsa")]
        Sha256Rsa,
        #[serde(rename = "sha384-rsa")]
        Sha384Rsa,
        #[serde(rename = "sha512-rsa")]
        Sha512Rsa,
        #[serde(rename = "sha256-rsapss")]
        Sha256Rsapss,
        #[serde(rename = "sha384-rsapss")]
        Sha384Rsapss,
        #[serde(rename = "sha512-rsapss")]
        Sha512Rsapss,
        #[serde(rename = "sha1-rsa")]
        Sha1Rsa,
        #[serde(rename = "sha256-ecdsa")]
        Sha256Ecdsa,
        #[serde(rename = "sha384-ecdsa")]
        Sha384Ecdsa,
        #[serde(rename = "sha512-ecdsa")]
        Sha512Ecdsa,
        #[serde(rename = "sha1-ecdsa")]
        Sha1Ecdsa,
        #[serde(rename = "ed25519")]
        Ed25519,
        #[serde(rename = "ml-dsa-44")]
        MlDsa44,
        #[serde(rename = "ml-dsa-65")]
        MlDsa65,
        #[serde(rename = "ml-dsa-87")]
        MlDsa87,
        #[serde(rename = "slh-dsa-sha2-128s")]
        SlhDsaSha2128s,
        #[serde(rename = "slh-dsa-sha2-128f")]
        SlhDsaSha2128f,
        #[serde(rename = "slh-dsa-sha2-192s")]
        SlhDsaSha2192s,
        #[serde(rename = "slh-dsa-sha2-192f")]
        SlhDsaSha2192f,
        #[serde(rename = "slh-dsa-sha2-256s")]
        SlhDsaSha2256s,
        #[serde(rename = "slh-dsa-sha2-256f")]
        SlhDsaSha2256f,
        #[serde(rename = "slh-dsa-shake-128s")]
        SlhDsaShake128s,
        #[serde(rename = "slh-dsa-shake-128f")]
        SlhDsaShake128f,
        #[serde(rename = "slh-dsa-shake-192s")]
        SlhDsaShake192s,
        #[serde(rename = "slh-dsa-shake-192f")]
        SlhDsaShake192f,
        #[serde(rename = "slh-dsa-shake-256s")]
        SlhDsaShake256s,
        #[serde(rename = "slh-dsa-shake-256f")]
        SlhDsaShake256f,
        #[serde(rename = "mldsa44-rsa2048-pss-sha256")]
        Mldsa44Rsa2048PssSha256,
        #[serde(rename = "mldsa44-rsa2048-pkcs15-sha256")]
        Mldsa44Rsa2048Pkcs15Sha256,
        #[serde(rename = "mldsa44-ed25519-sha512")]
        Mldsa44Ed25519Sha512,
        #[serde(rename = "mldsa44-ecdsa-p256-sha256")]
        Mldsa44EcdsaP256Sha256,
        #[serde(rename = "mldsa65-rsa3072-pss-sha512")]
        Mldsa65Rsa3072PssSha512,
        #[serde(rename = "mldsa65-rsa3072-pkcs15-sha512")]
        Mldsa65Rsa3072Pkcs15Sha512,
        #[serde(rename = "mldsa65-rsa4096-pss-sha512")]
        Mldsa65Rsa4096PssSha512,
        #[serde(rename = "mldsa65-rsa4096-pkcs15-sha512")]
        Mldsa65Rsa4096Pkcs15Sha512,
        #[serde(rename = "mldsa65-ecdsa-p256-sha512")]
        Mldsa65EcdsaP256Sha512,
        #[serde(rename = "mldsa65-ecdsa-p384-sha512")]
        Mldsa65EcdsaP384Sha512,
        #[serde(rename = "mldsa65-ed25519-sha512")]
        Mldsa65Ed25519Sha512,
        #[serde(rename = "mldsa87-ecdsa-p384-sha512")]
        Mldsa87EcdsaP384Sha512,
        #[serde(rename = "mldsa87-ed448-shake256")]
        Mldsa87Ed448Shake256,
        #[serde(rename = "mldsa87-rsa3072-pss-sha512")]
        Mldsa87Rsa3072PssSha512,
        #[serde(rename = "mldsa87-rsa4096-pss-sha512")]
        Mldsa87Rsa4096PssSha512,
        #[serde(rename = "mldsa87-ecdsa-p521-sha512")]
        Mldsa87EcdsaP521Sha512,
    }

    /// The C=, two letters, optional. It is encoded as a PrintableString, which is
    /// interoperability rather than taste — several validators refuse a UTF8String
    /// country and report it as a signature problem.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyCountry {
        #[serde(rename = "AD")]
        Ad,
        #[serde(rename = "AE")]
        Ae,
        #[serde(rename = "AF")]
        Af,
        #[serde(rename = "AG")]
        Ag,
        #[serde(rename = "AI")]
        Ai,
        #[serde(rename = "AL")]
        Al,
        #[serde(rename = "AM")]
        Am,
        #[serde(rename = "AO")]
        Ao,
        #[serde(rename = "AQ")]
        Aq,
        #[serde(rename = "AR")]
        Ar,
        #[serde(rename = "AS")]
        As,
        #[serde(rename = "AT")]
        At,
        #[serde(rename = "AU")]
        Au,
        #[serde(rename = "AW")]
        Aw,
        #[serde(rename = "AX")]
        Ax,
        #[serde(rename = "AZ")]
        Az,
        #[serde(rename = "BA")]
        Ba,
        #[serde(rename = "BB")]
        Bb,
        #[serde(rename = "BD")]
        Bd,
        #[serde(rename = "BE")]
        Be,
        #[serde(rename = "BF")]
        Bf,
        #[serde(rename = "BG")]
        Bg,
        #[serde(rename = "BH")]
        Bh,
        #[serde(rename = "BI")]
        Bi,
        #[serde(rename = "BJ")]
        Bj,
        #[serde(rename = "BL")]
        Bl,
        #[serde(rename = "BM")]
        Bm,
        #[serde(rename = "BN")]
        Bn,
        #[serde(rename = "BO")]
        Bo,
        #[serde(rename = "BQ")]
        Bq,
        #[serde(rename = "BR")]
        Br,
        #[serde(rename = "BS")]
        Bs,
        #[serde(rename = "BT")]
        Bt,
        #[serde(rename = "BV")]
        Bv,
        #[serde(rename = "BW")]
        Bw,
        #[serde(rename = "BY")]
        By,
        #[serde(rename = "BZ")]
        Bz,
        #[serde(rename = "CA")]
        Ca,
        #[serde(rename = "CC")]
        Cc,
        #[serde(rename = "CD")]
        Cd,
        #[serde(rename = "CF")]
        Cf,
        #[serde(rename = "CG")]
        Cg,
        #[serde(rename = "CH")]
        Ch,
        #[serde(rename = "CI")]
        Ci,
        #[serde(rename = "CK")]
        Ck,
        #[serde(rename = "CL")]
        Cl,
        #[serde(rename = "CM")]
        Cm,
        #[serde(rename = "CN")]
        Cn,
        #[serde(rename = "CO")]
        Co,
        #[serde(rename = "CR")]
        Cr,
        #[serde(rename = "CU")]
        Cu,
        #[serde(rename = "CV")]
        Cv,
        #[serde(rename = "CW")]
        Cw,
        #[serde(rename = "CX")]
        Cx,
        #[serde(rename = "CY")]
        Cy,
        #[serde(rename = "CZ")]
        Cz,
        #[serde(rename = "DE")]
        De,
        #[serde(rename = "DJ")]
        Dj,
        #[serde(rename = "DK")]
        Dk,
        #[serde(rename = "DM")]
        Dm,
        #[serde(rename = "DO")]
        Do,
        #[serde(rename = "DZ")]
        Dz,
        #[serde(rename = "EC")]
        Ec,
        #[serde(rename = "EE")]
        Ee,
        #[serde(rename = "EG")]
        Eg,
        #[serde(rename = "EH")]
        Eh,
        #[serde(rename = "ER")]
        Er,
        #[serde(rename = "ES")]
        Es,
        #[serde(rename = "ET")]
        Et,
        #[serde(rename = "FI")]
        Fi,
        #[serde(rename = "FJ")]
        Fj,
        #[serde(rename = "FK")]
        Fk,
        #[serde(rename = "FM")]
        Fm,
        #[serde(rename = "FO")]
        Fo,
        #[serde(rename = "FR")]
        Fr,
        #[serde(rename = "GA")]
        Ga,
        #[serde(rename = "GB")]
        Gb,
        #[serde(rename = "GD")]
        Gd,
        #[serde(rename = "GE")]
        Ge,
        #[serde(rename = "GF")]
        Gf,
        #[serde(rename = "GG")]
        Gg,
        #[serde(rename = "GH")]
        Gh,
        #[serde(rename = "GI")]
        Gi,
        #[serde(rename = "GL")]
        Gl,
        #[serde(rename = "GM")]
        Gm,
        #[serde(rename = "GN")]
        Gn,
        #[serde(rename = "GP")]
        Gp,
        #[serde(rename = "GQ")]
        Gq,
        #[serde(rename = "GR")]
        Gr,
        #[serde(rename = "GS")]
        Gs,
        #[serde(rename = "GT")]
        Gt,
        #[serde(rename = "GU")]
        Gu,
        #[serde(rename = "GW")]
        Gw,
        #[serde(rename = "GY")]
        Gy,
        #[serde(rename = "HK")]
        Hk,
        #[serde(rename = "HM")]
        Hm,
        #[serde(rename = "HN")]
        Hn,
        #[serde(rename = "HR")]
        Hr,
        #[serde(rename = "HT")]
        Ht,
        #[serde(rename = "HU")]
        Hu,
        #[serde(rename = "ID")]
        Id,
        #[serde(rename = "IE")]
        Ie,
        #[serde(rename = "IL")]
        Il,
        #[serde(rename = "IM")]
        Im,
        #[serde(rename = "IN")]
        In,
        #[serde(rename = "IO")]
        Io,
        #[serde(rename = "IQ")]
        Iq,
        #[serde(rename = "IR")]
        Ir,
        #[serde(rename = "IS")]
        Is,
        #[serde(rename = "IT")]
        It,
        #[serde(rename = "JE")]
        Je,
        #[serde(rename = "JM")]
        Jm,
        #[serde(rename = "JO")]
        Jo,
        #[serde(rename = "JP")]
        Jp,
        #[serde(rename = "KE")]
        Ke,
        #[serde(rename = "KG")]
        Kg,
        #[serde(rename = "KH")]
        Kh,
        #[serde(rename = "KI")]
        Ki,
        #[serde(rename = "KM")]
        Km,
        #[serde(rename = "KN")]
        Kn,
        #[serde(rename = "KP")]
        Kp,
        #[serde(rename = "KR")]
        Kr,
        #[serde(rename = "KW")]
        Kw,
        #[serde(rename = "KY")]
        Ky,
        #[serde(rename = "KZ")]
        Kz,
        #[serde(rename = "LA")]
        La,
        #[serde(rename = "LB")]
        Lb,
        #[serde(rename = "LC")]
        Lc,
        #[serde(rename = "LI")]
        Li,
        #[serde(rename = "LK")]
        Lk,
        #[serde(rename = "LR")]
        Lr,
        #[serde(rename = "LS")]
        Ls,
        #[serde(rename = "LT")]
        Lt,
        #[serde(rename = "LU")]
        Lu,
        #[serde(rename = "LV")]
        Lv,
        #[serde(rename = "LY")]
        Ly,
        #[serde(rename = "MA")]
        Ma,
        #[serde(rename = "MC")]
        Mc,
        #[serde(rename = "MD")]
        Md,
        #[serde(rename = "ME")]
        Me,
        #[serde(rename = "MF")]
        Mf,
        #[serde(rename = "MG")]
        Mg,
        #[serde(rename = "MH")]
        Mh,
        #[serde(rename = "MK")]
        Mk,
        #[serde(rename = "ML")]
        Ml,
        #[serde(rename = "MM")]
        Mm,
        #[serde(rename = "MN")]
        Mn,
        #[serde(rename = "MO")]
        Mo,
        #[serde(rename = "MP")]
        Mp,
        #[serde(rename = "MQ")]
        Mq,
        #[serde(rename = "MR")]
        Mr,
        #[serde(rename = "MS")]
        Ms,
        #[serde(rename = "MT")]
        Mt,
        #[serde(rename = "MU")]
        Mu,
        #[serde(rename = "MV")]
        Mv,
        #[serde(rename = "MW")]
        Mw,
        #[serde(rename = "MX")]
        Mx,
        #[serde(rename = "MY")]
        My,
        #[serde(rename = "MZ")]
        Mz,
        #[serde(rename = "NA")]
        Na,
        #[serde(rename = "NC")]
        Nc,
        #[serde(rename = "NE")]
        Ne,
        #[serde(rename = "NF")]
        Nf,
        #[serde(rename = "NG")]
        Ng,
        #[serde(rename = "NI")]
        Ni,
        #[serde(rename = "NL")]
        Nl,
        #[serde(rename = "NO")]
        No,
        #[serde(rename = "NP")]
        Np,
        #[serde(rename = "NR")]
        Nr,
        #[serde(rename = "NU")]
        Nu,
        #[serde(rename = "NZ")]
        Nz,
        #[serde(rename = "OM")]
        Om,
        #[serde(rename = "PA")]
        Pa,
        #[serde(rename = "PE")]
        Pe,
        #[serde(rename = "PF")]
        Pf,
        #[serde(rename = "PG")]
        Pg,
        #[serde(rename = "PH")]
        Ph,
        #[serde(rename = "PK")]
        Pk,
        #[serde(rename = "PL")]
        Pl,
        #[serde(rename = "PM")]
        Pm,
        #[serde(rename = "PN")]
        Pn,
        #[serde(rename = "PR")]
        Pr,
        #[serde(rename = "PS")]
        Ps,
        #[serde(rename = "PT")]
        Pt,
        #[serde(rename = "PW")]
        Pw,
        #[serde(rename = "PY")]
        Py,
        #[serde(rename = "QA")]
        Qa,
        #[serde(rename = "RE")]
        Re,
        #[serde(rename = "RO")]
        Ro,
        #[serde(rename = "RS")]
        Rs,
        #[serde(rename = "RU")]
        Ru,
        #[serde(rename = "RW")]
        Rw,
        #[serde(rename = "SA")]
        Sa,
        #[serde(rename = "SB")]
        Sb,
        #[serde(rename = "SC")]
        Sc,
        #[serde(rename = "SD")]
        Sd,
        #[serde(rename = "SE")]
        Se,
        #[serde(rename = "SG")]
        Sg,
        #[serde(rename = "SH")]
        Sh,
        #[serde(rename = "SI")]
        Si,
        #[serde(rename = "SJ")]
        Sj,
        #[serde(rename = "SK")]
        Sk,
        #[serde(rename = "SL")]
        Sl,
        #[serde(rename = "SM")]
        Sm,
        #[serde(rename = "SN")]
        Sn,
        #[serde(rename = "SO")]
        So,
        #[serde(rename = "SR")]
        Sr,
        #[serde(rename = "SS")]
        Ss,
        #[serde(rename = "ST")]
        St,
        #[serde(rename = "SV")]
        Sv,
        #[serde(rename = "SX")]
        Sx,
        #[serde(rename = "SY")]
        Sy,
        #[serde(rename = "SZ")]
        Sz,
        #[serde(rename = "TC")]
        Tc,
        #[serde(rename = "TD")]
        Td,
        #[serde(rename = "TF")]
        Tf,
        #[serde(rename = "TG")]
        Tg,
        #[serde(rename = "TH")]
        Th,
        #[serde(rename = "TJ")]
        Tj,
        #[serde(rename = "TK")]
        Tk,
        #[serde(rename = "TL")]
        Tl,
        #[serde(rename = "TM")]
        Tm,
        #[serde(rename = "TN")]
        Tn,
        #[serde(rename = "TO")]
        To,
        #[serde(rename = "TR")]
        Tr,
        #[serde(rename = "TT")]
        Tt,
        #[serde(rename = "TV")]
        Tv,
        #[serde(rename = "TW")]
        Tw,
        #[serde(rename = "TZ")]
        Tz,
        #[serde(rename = "UA")]
        Ua,
        #[serde(rename = "UG")]
        Ug,
        #[serde(rename = "UM")]
        Um,
        #[serde(rename = "US")]
        Us,
        #[serde(rename = "UY")]
        Uy,
        #[serde(rename = "UZ")]
        Uz,
        #[serde(rename = "VA")]
        Va,
        #[serde(rename = "VC")]
        Vc,
        #[serde(rename = "VE")]
        Ve,
        #[serde(rename = "VG")]
        Vg,
        #[serde(rename = "VI")]
        Vi,
        #[serde(rename = "VN")]
        Vn,
        #[serde(rename = "VU")]
        Vu,
        #[serde(rename = "WF")]
        Wf,
        #[serde(rename = "WS")]
        Ws,
        #[serde(rename = "YE")]
        Ye,
        #[serde(rename = "YT")]
        Yt,
        #[serde(rename = "ZA")]
        Za,
        #[serde(rename = "ZM")]
        Zm,
        #[serde(rename = "ZW")]
        Zw,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// One of the ids in `keyAlgorithms` on GET /admin-api/pki: rsa-2048,
        /// rsa-3072, rsa-4096, ec-p256, ec-p384, ec-p521 or ed25519. One algorithm
        /// for all three tiers — the LEAF's signature algorithm is decided by the
        /// Issuing CA's key, and that is what a client library has to be able to
        /// verify. Defaults to `pki.keyAlgorithm`.
        #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
        pub key_alg: Option<BodyKeyAlg>,
        /// The post-quantum key every authority built here holds beside its
        /// classical one (ITU-T X.509 clause 9.8, #68): one of
        /// `alternativeKeyAlgorithms` on GET /admin-api/pki, or `none` for a
        /// classical-only authority. Defaults to `pki.alternativeKeyAlgorithm`.
        #[serde(rename = "altKeyAlg", default, skip_serializing_if = "Option::is_none")]
        pub alt_key_alg: Option<BodyAltKeyAlg>,
        /// One of the ids in `signatureAlgorithms`. OMIT IT for "the right one for
        /// the key algorithm", which is almost always what is wanted: an EC key's
        /// digest is decided by its CURVE, so naming one here can hand a P-521 key
        /// SHA-256 — legal, verifying, and nobody's intention. A pair whose
        /// families disagree is refused with the list beside it.
        #[serde(rename = "signatureAlg", default, skip_serializing_if = "Option::is_none")]
        pub signature_alg: Option<BodySignatureAlg>,
        /// The O= every tier carries, and what the tiers are named after when no
        /// common name is given. Defaults to `pki.organisation`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub organisation: Option<String>,
        /// The C=, two letters, optional. It is encoded as a PrintableString, which
        /// is interoperability rather than taste — several validators refuse a
        /// UTF8String country and report it as a signature problem.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub country: Option<BodyCountry>,
        /// The Root CA's common name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cn_root: Option<String>,
        /// The Intermediate CA's common name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cn_intermediate: Option<String>,
        /// The Issuing CA's common name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cn_issuing: Option<String>,
        /// How long the Root is valid. Defaults to the certificate profile's own
        /// twenty years.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub years_root: Option<i64>,
        /// Ten by default.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub years_intermediate: Option<i64>,
        /// Five by default.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub years_issuing: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors115;
}

/// Build or replace the Root CA for the whole service
pub mod build_pki_root {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/pki/build-root";
    pub const OPERATION_ID: &str = "buildPkiRoot";

    /// One of the ids in `keyAlgorithms`. Defaults to `pki.keyAlgorithm`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKeyAlg {
        #[serde(rename = "rsa-2048")]
        Rsa2048,
        #[serde(rename = "rsa-3072")]
        Rsa3072,
        #[serde(rename = "rsa-4096")]
        Rsa4096,
        #[serde(rename = "ec-p256")]
        EcP256,
        #[serde(rename = "ec-p384")]
        EcP384,
        #[serde(rename = "ec-p521")]
        EcP521,
        #[serde(rename = "ed25519")]
        Ed25519,
        #[serde(rename = "ml-dsa-44")]
        MlDsa44,
        #[serde(rename = "ml-dsa-65")]
        MlDsa65,
        #[serde(rename = "ml-dsa-87")]
        MlDsa87,
        #[serde(rename = "slh-dsa-sha2-128s")]
        SlhDsaSha2128s,
        #[serde(rename = "slh-dsa-sha2-128f")]
        SlhDsaSha2128f,
        #[serde(rename = "slh-dsa-sha2-192s")]
        SlhDsaSha2192s,
        #[serde(rename = "slh-dsa-sha2-192f")]
        SlhDsaSha2192f,
        #[serde(rename = "slh-dsa-sha2-256s")]
        SlhDsaSha2256s,
        #[serde(rename = "slh-dsa-sha2-256f")]
        SlhDsaSha2256f,
        #[serde(rename = "slh-dsa-shake-128s")]
        SlhDsaShake128s,
        #[serde(rename = "slh-dsa-shake-128f")]
        SlhDsaShake128f,
        #[serde(rename = "slh-dsa-shake-192s")]
        SlhDsaShake192s,
        #[serde(rename = "slh-dsa-shake-192f")]
        SlhDsaShake192f,
        #[serde(rename = "slh-dsa-shake-256s")]
        SlhDsaShake256s,
        #[serde(rename = "slh-dsa-shake-256f")]
        SlhDsaShake256f,
        #[serde(rename = "mldsa44-rsa2048-pss-sha256")]
        Mldsa44Rsa2048PssSha256,
        #[serde(rename = "mldsa44-rsa2048-pkcs15-sha256")]
        Mldsa44Rsa2048Pkcs15Sha256,
        #[serde(rename = "mldsa44-ed25519-sha512")]
        Mldsa44Ed25519Sha512,
        #[serde(rename = "mldsa44-ecdsa-p256-sha256")]
        Mldsa44EcdsaP256Sha256,
        #[serde(rename = "mldsa65-rsa3072-pss-sha512")]
        Mldsa65Rsa3072PssSha512,
        #[serde(rename = "mldsa65-rsa3072-pkcs15-sha512")]
        Mldsa65Rsa3072Pkcs15Sha512,
        #[serde(rename = "mldsa65-rsa4096-pss-sha512")]
        Mldsa65Rsa4096PssSha512,
        #[serde(rename = "mldsa65-rsa4096-pkcs15-sha512")]
        Mldsa65Rsa4096Pkcs15Sha512,
        #[serde(rename = "mldsa65-ecdsa-p256-sha512")]
        Mldsa65EcdsaP256Sha512,
        #[serde(rename = "mldsa65-ecdsa-p384-sha512")]
        Mldsa65EcdsaP384Sha512,
        #[serde(rename = "mldsa65-ed25519-sha512")]
        Mldsa65Ed25519Sha512,
        #[serde(rename = "mldsa87-ecdsa-p384-sha512")]
        Mldsa87EcdsaP384Sha512,
        #[serde(rename = "mldsa87-ed448-shake256")]
        Mldsa87Ed448Shake256,
        #[serde(rename = "mldsa87-rsa3072-pss-sha512")]
        Mldsa87Rsa3072PssSha512,
        #[serde(rename = "mldsa87-rsa4096-pss-sha512")]
        Mldsa87Rsa4096PssSha512,
        #[serde(rename = "mldsa87-ecdsa-p521-sha512")]
        Mldsa87EcdsaP521Sha512,
        #[serde(rename = "ml-kem-512")]
        MlKem512,
        #[serde(rename = "ml-kem-768")]
        MlKem768,
        #[serde(rename = "ml-kem-1024")]
        MlKem1024,
    }

    /// The post-quantum key every authority built here holds beside its classical
    /// one (ITU-T X.509 clause 9.8, #68): one of `alternativeKeyAlgorithms` on GET
    /// /admin-api/pki, or `none` for a classical-only authority. Defaults to
    /// `pki.alternativeKeyAlgorithm`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyAltKeyAlg {
        #[serde(rename = "ml-dsa-44")]
        MlDsa44,
        #[serde(rename = "ml-dsa-65")]
        MlDsa65,
        #[serde(rename = "ml-dsa-87")]
        MlDsa87,
        #[serde(rename = "slh-dsa-sha2-128s")]
        SlhDsaSha2128s,
        #[serde(rename = "slh-dsa-sha2-128f")]
        SlhDsaSha2128f,
        #[serde(rename = "slh-dsa-sha2-192s")]
        SlhDsaSha2192s,
        #[serde(rename = "slh-dsa-sha2-192f")]
        SlhDsaSha2192f,
        #[serde(rename = "slh-dsa-sha2-256s")]
        SlhDsaSha2256s,
        #[serde(rename = "slh-dsa-sha2-256f")]
        SlhDsaSha2256f,
        #[serde(rename = "slh-dsa-shake-128s")]
        SlhDsaShake128s,
        #[serde(rename = "slh-dsa-shake-128f")]
        SlhDsaShake128f,
        #[serde(rename = "slh-dsa-shake-192s")]
        SlhDsaShake192s,
        #[serde(rename = "slh-dsa-shake-192f")]
        SlhDsaShake192f,
        #[serde(rename = "slh-dsa-shake-256s")]
        SlhDsaShake256s,
        #[serde(rename = "slh-dsa-shake-256f")]
        SlhDsaShake256f,
        #[serde(rename = "none")]
        None,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// One of the ids in `keyAlgorithms`. Defaults to `pki.keyAlgorithm`.
        #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
        pub key_alg: Option<BodyKeyAlg>,
        /// The post-quantum key every authority built here holds beside its
        /// classical one (ITU-T X.509 clause 9.8, #68): one of
        /// `alternativeKeyAlgorithms` on GET /admin-api/pki, or `none` for a
        /// classical-only authority. Defaults to `pki.alternativeKeyAlgorithm`.
        #[serde(rename = "altKeyAlg", default, skip_serializing_if = "Option::is_none")]
        pub alt_key_alg: Option<BodyAltKeyAlg>,
        /// The Root’s CN. Defaults to the organisation followed by "Root CA".
        #[serde(rename = "commonName", default, skip_serializing_if = "Option::is_none")]
        pub common_name: Option<String>,
        /// How long it is valid for. Defaults to the root-ca profile’s own twenty
        /// years.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub years: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors122;
}

/// Build or rebuild one scope’s branch — its Intermediate and every Issuing CA
/// under it
pub mod build_pki_scope {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/pki/build-scope";
    pub const OPERATION_ID: &str = "buildPkiScope";

    /// The key algorithm every CA in this branch is generated with.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKeyAlg {
        #[serde(rename = "rsa-2048")]
        Rsa2048,
        #[serde(rename = "rsa-3072")]
        Rsa3072,
        #[serde(rename = "rsa-4096")]
        Rsa4096,
        #[serde(rename = "ec-p256")]
        EcP256,
        #[serde(rename = "ec-p384")]
        EcP384,
        #[serde(rename = "ec-p521")]
        EcP521,
        #[serde(rename = "ed25519")]
        Ed25519,
        #[serde(rename = "ml-dsa-44")]
        MlDsa44,
        #[serde(rename = "ml-dsa-65")]
        MlDsa65,
        #[serde(rename = "ml-dsa-87")]
        MlDsa87,
        #[serde(rename = "slh-dsa-sha2-128s")]
        SlhDsaSha2128s,
        #[serde(rename = "slh-dsa-sha2-128f")]
        SlhDsaSha2128f,
        #[serde(rename = "slh-dsa-sha2-192s")]
        SlhDsaSha2192s,
        #[serde(rename = "slh-dsa-sha2-192f")]
        SlhDsaSha2192f,
        #[serde(rename = "slh-dsa-sha2-256s")]
        SlhDsaSha2256s,
        #[serde(rename = "slh-dsa-sha2-256f")]
        SlhDsaSha2256f,
        #[serde(rename = "slh-dsa-shake-128s")]
        SlhDsaShake128s,
        #[serde(rename = "slh-dsa-shake-128f")]
        SlhDsaShake128f,
        #[serde(rename = "slh-dsa-shake-192s")]
        SlhDsaShake192s,
        #[serde(rename = "slh-dsa-shake-192f")]
        SlhDsaShake192f,
        #[serde(rename = "slh-dsa-shake-256s")]
        SlhDsaShake256s,
        #[serde(rename = "slh-dsa-shake-256f")]
        SlhDsaShake256f,
        #[serde(rename = "mldsa44-rsa2048-pss-sha256")]
        Mldsa44Rsa2048PssSha256,
        #[serde(rename = "mldsa44-rsa2048-pkcs15-sha256")]
        Mldsa44Rsa2048Pkcs15Sha256,
        #[serde(rename = "mldsa44-ed25519-sha512")]
        Mldsa44Ed25519Sha512,
        #[serde(rename = "mldsa44-ecdsa-p256-sha256")]
        Mldsa44EcdsaP256Sha256,
        #[serde(rename = "mldsa65-rsa3072-pss-sha512")]
        Mldsa65Rsa3072PssSha512,
        #[serde(rename = "mldsa65-rsa3072-pkcs15-sha512")]
        Mldsa65Rsa3072Pkcs15Sha512,
        #[serde(rename = "mldsa65-rsa4096-pss-sha512")]
        Mldsa65Rsa4096PssSha512,
        #[serde(rename = "mldsa65-rsa4096-pkcs15-sha512")]
        Mldsa65Rsa4096Pkcs15Sha512,
        #[serde(rename = "mldsa65-ecdsa-p256-sha512")]
        Mldsa65EcdsaP256Sha512,
        #[serde(rename = "mldsa65-ecdsa-p384-sha512")]
        Mldsa65EcdsaP384Sha512,
        #[serde(rename = "mldsa65-ed25519-sha512")]
        Mldsa65Ed25519Sha512,
        #[serde(rename = "mldsa87-ecdsa-p384-sha512")]
        Mldsa87EcdsaP384Sha512,
        #[serde(rename = "mldsa87-ed448-shake256")]
        Mldsa87Ed448Shake256,
        #[serde(rename = "mldsa87-rsa3072-pss-sha512")]
        Mldsa87Rsa3072PssSha512,
        #[serde(rename = "mldsa87-rsa4096-pss-sha512")]
        Mldsa87Rsa4096PssSha512,
        #[serde(rename = "mldsa87-ecdsa-p521-sha512")]
        Mldsa87EcdsaP521Sha512,
        #[serde(rename = "ml-kem-512")]
        MlKem512,
        #[serde(rename = "ml-kem-768")]
        MlKem768,
        #[serde(rename = "ml-kem-1024")]
        MlKem1024,
    }

    /// The post-quantum key every authority built here holds beside its classical
    /// one (ITU-T X.509 clause 9.8, #68): one of `alternativeKeyAlgorithms` on GET
    /// /admin-api/pki, or `none` for a classical-only authority. Defaults to
    /// `pki.alternativeKeyAlgorithm`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyAltKeyAlg {
        #[serde(rename = "ml-dsa-44")]
        MlDsa44,
        #[serde(rename = "ml-dsa-65")]
        MlDsa65,
        #[serde(rename = "ml-dsa-87")]
        MlDsa87,
        #[serde(rename = "slh-dsa-sha2-128s")]
        SlhDsaSha2128s,
        #[serde(rename = "slh-dsa-sha2-128f")]
        SlhDsaSha2128f,
        #[serde(rename = "slh-dsa-sha2-192s")]
        SlhDsaSha2192s,
        #[serde(rename = "slh-dsa-sha2-192f")]
        SlhDsaSha2192f,
        #[serde(rename = "slh-dsa-sha2-256s")]
        SlhDsaSha2256s,
        #[serde(rename = "slh-dsa-sha2-256f")]
        SlhDsaSha2256f,
        #[serde(rename = "slh-dsa-shake-128s")]
        SlhDsaShake128s,
        #[serde(rename = "slh-dsa-shake-128f")]
        SlhDsaShake128f,
        #[serde(rename = "slh-dsa-shake-192s")]
        SlhDsaShake192s,
        #[serde(rename = "slh-dsa-shake-192f")]
        SlhDsaShake192f,
        #[serde(rename = "slh-dsa-shake-256s")]
        SlhDsaShake256s,
        #[serde(rename = "slh-dsa-shake-256f")]
        SlhDsaShake256f,
        #[serde(rename = "none")]
        None,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// A realm id, `*process`, or omitted for the realm this request arrived
        /// in.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        /// The key algorithm every CA in this branch is generated with.
        #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
        pub key_alg: Option<BodyKeyAlg>,
        /// The post-quantum key every authority built here holds beside its
        /// classical one (ITU-T X.509 clause 9.8, #68): one of
        /// `alternativeKeyAlgorithms` on GET /admin-api/pki, or `none` for a
        /// classical-only authority. Defaults to `pki.alternativeKeyAlgorithm`.
        #[serde(rename = "altKeyAlg", default, skip_serializing_if = "Option::is_none")]
        pub alt_key_alg: Option<BodyAltKeyAlg>,
        /// Replace an imported authority too. Default false.
        #[serde(rename = "replaceImported", default, skip_serializing_if = "Option::is_none")]
        pub replace_imported: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors119;
}

/// Remove this realm's certificate authority entirely
pub mod clear_pki_chain {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/pki/clear";
    pub const OPERATION_ID: &str = "clearPkiChain";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors119;
}

/// Empty this realm’s object store
pub mod clear_pki_objects {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/pki/clear-store";
    pub const OPERATION_ID: &str = "clearPkiObjects";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct Body {
        /// The members the schema does not name, which it allows.
        #[serde(flatten)]
        pub extra: serde_json::Map<String, serde_json::Value>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors119;
}

/// Write a key pair out as PEM, DER, a JWK set or a PKCS#12
pub mod export_pki_key_pair {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/pki/export";
    pub const OPERATION_ID: &str = "exportPkiKeyPair";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct Body {
        /// The object to write out. Omitted, the key pair in `pki_private_key` and
        /// `pki_public_key` is used.
        #[serde(rename = "objectId", default, skip_serializing_if = "Option::is_none")]
        pub object_id: Option<String>,
        /// The members the schema does not name, which it allows.
        #[serde(flatten)]
        pub extra: serde_json::Map<String, serde_json::Value>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors121;
}

/// Use a certificate authority this service did not generate
pub mod import_pki_ca {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/pki/import-ca";
    pub const OPERATION_ID: &str = "importPkiCa";

    /// `root`, or one of the use cases.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyUseCase {
        #[serde(rename = "root")]
        Root,
        #[serde(rename = "jose")]
        Jose,
        #[serde(rename = "xml")]
        Xml,
        #[serde(rename = "assertions")]
        Assertions,
        #[serde(rename = "tls")]
        Tls,
        #[serde(rename = "cell")]
        Cell,
        #[serde(rename = "spiffe")]
        Spiffe,
        #[serde(rename = "pep-tls")]
        PepTls,
        #[serde(rename = "realm-tls")]
        RealmTls,
        #[serde(rename = "kdc")]
        Kdc,
        #[serde(rename = "acme")]
        Acme,
        #[serde(rename = "est")]
        Est,
        #[serde(rename = "scep")]
        Scep,
        #[serde(rename = "tls-client")]
        TlsClient,
        #[serde(rename = "message-signing")]
        MessageSigning,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// `*service` for the Root, otherwise a realm id or `*process`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        /// `root`, or one of the use cases.
        #[serde(rename = "useCase")]
        pub use_case: BodyUseCase,
        /// The CA certificate.
        #[serde(rename = "certificatePem")]
        pub certificate_pem: String,
        /// Its private key.
        #[serde(rename = "privateKeyPem")]
        pub private_key_pem: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors119;
}

/// Issue a signing key pair to an application — or, with target=person, to
/// somebody in ou=users — from the Issuing CA
pub mod issue_pki_key_pair {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/pki/issue";
    pub const OPERATION_ID: &str = "issuePkiKeyPair";

    /// WHO the key pair is for. Defaults to `application`, which is what every
    /// caller written before this field existed sends. `person` adds a key pair to
    /// `stsAssertion*` (or `stsSamlAssertion*` for `purpose=saml`) on a `ou=users`
    /// entry instead and returns the private key once.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyTarget {
        #[serde(rename = "application")]
        Application,
        #[serde(rename = "person")]
        Person,
    }

    /// Which assertion profile the key pair is for: `jwt` for RFC 7523 and `saml`
    /// for RFC 7522. Defaults to `jwt`, which is what every caller written before
    /// this field existed sends and is why it is the default rather than a required
    /// field. A value this service does not know is REFUSED rather than defaulted —
    /// a caller that asked for a profile wants a certificate for something, and
    /// quietly handing back the other one would put a key pair on the wrong
    /// attribute set with nothing saying so.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyPurpose {
        #[serde(rename = "jwt")]
        Jwt,
        #[serde(rename = "saml")]
        Saml,
    }

    /// The LEAF's key algorithm. Defaults to the Issuing CA's, which is the chain a
    /// client library is least likely to be surprised by.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKeyAlg {
        #[serde(rename = "rsa-2048")]
        Rsa2048,
        #[serde(rename = "rsa-3072")]
        Rsa3072,
        #[serde(rename = "rsa-4096")]
        Rsa4096,
        #[serde(rename = "ec-p256")]
        EcP256,
        #[serde(rename = "ec-p384")]
        EcP384,
        #[serde(rename = "ec-p521")]
        EcP521,
        #[serde(rename = "ed25519")]
        Ed25519,
        #[serde(rename = "ml-dsa-44")]
        MlDsa44,
        #[serde(rename = "ml-dsa-65")]
        MlDsa65,
        #[serde(rename = "ml-dsa-87")]
        MlDsa87,
        #[serde(rename = "slh-dsa-sha2-128s")]
        SlhDsaSha2128s,
        #[serde(rename = "slh-dsa-sha2-128f")]
        SlhDsaSha2128f,
        #[serde(rename = "slh-dsa-sha2-192s")]
        SlhDsaSha2192s,
        #[serde(rename = "slh-dsa-sha2-192f")]
        SlhDsaSha2192f,
        #[serde(rename = "slh-dsa-sha2-256s")]
        SlhDsaSha2256s,
        #[serde(rename = "slh-dsa-sha2-256f")]
        SlhDsaSha2256f,
        #[serde(rename = "slh-dsa-shake-128s")]
        SlhDsaShake128s,
        #[serde(rename = "slh-dsa-shake-128f")]
        SlhDsaShake128f,
        #[serde(rename = "slh-dsa-shake-192s")]
        SlhDsaShake192s,
        #[serde(rename = "slh-dsa-shake-192f")]
        SlhDsaShake192f,
        #[serde(rename = "slh-dsa-shake-256s")]
        SlhDsaShake256s,
        #[serde(rename = "slh-dsa-shake-256f")]
        SlhDsaShake256f,
        #[serde(rename = "mldsa44-rsa2048-pss-sha256")]
        Mldsa44Rsa2048PssSha256,
        #[serde(rename = "mldsa44-rsa2048-pkcs15-sha256")]
        Mldsa44Rsa2048Pkcs15Sha256,
        #[serde(rename = "mldsa44-ed25519-sha512")]
        Mldsa44Ed25519Sha512,
        #[serde(rename = "mldsa44-ecdsa-p256-sha256")]
        Mldsa44EcdsaP256Sha256,
        #[serde(rename = "mldsa65-rsa3072-pss-sha512")]
        Mldsa65Rsa3072PssSha512,
        #[serde(rename = "mldsa65-rsa3072-pkcs15-sha512")]
        Mldsa65Rsa3072Pkcs15Sha512,
        #[serde(rename = "mldsa65-rsa4096-pss-sha512")]
        Mldsa65Rsa4096PssSha512,
        #[serde(rename = "mldsa65-rsa4096-pkcs15-sha512")]
        Mldsa65Rsa4096Pkcs15Sha512,
        #[serde(rename = "mldsa65-ecdsa-p256-sha512")]
        Mldsa65EcdsaP256Sha512,
        #[serde(rename = "mldsa65-ecdsa-p384-sha512")]
        Mldsa65EcdsaP384Sha512,
        #[serde(rename = "mldsa65-ed25519-sha512")]
        Mldsa65Ed25519Sha512,
        #[serde(rename = "mldsa87-ecdsa-p384-sha512")]
        Mldsa87EcdsaP384Sha512,
        #[serde(rename = "mldsa87-ed448-shake256")]
        Mldsa87Ed448Shake256,
        #[serde(rename = "mldsa87-rsa3072-pss-sha512")]
        Mldsa87Rsa3072PssSha512,
        #[serde(rename = "mldsa87-rsa4096-pss-sha512")]
        Mldsa87Rsa4096PssSha512,
        #[serde(rename = "mldsa87-ecdsa-p521-sha512")]
        Mldsa87EcdsaP521Sha512,
        #[serde(rename = "ml-kem-512")]
        MlKem512,
        #[serde(rename = "ml-kem-768")]
        MlKem768,
        #[serde(rename = "ml-kem-1024")]
        MlKem1024,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The application to issue to — or the USERNAME, with `target=person`. It
        /// must ALREADY EXIST in this realm — creating one here would be this
        /// endpoint inventing an application, or a person, in order to give it a
        /// credential.
        pub identifier: String,
        /// WHO the key pair is for. Defaults to `application`, which is what every
        /// caller written before this field existed sends. `person` adds a key pair
        /// to `stsAssertion*` (or `stsSamlAssertion*` for `purpose=saml`) on a
        /// `ou=users` entry instead and returns the private key once.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub target: Option<BodyTarget>,
        /// `target=person` only: what the person calls this key pair — at most 40
        /// letters, digits, spaces, dots, dashes, underscores and brackets (#1290).
        /// Optional.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        /// `target=person` only: the `iss` (or SAML `<Issuer>`) their assertions
        /// will carry, written as `stsAssertionIssuer` or `stsSamlAssertionIssuer`.
        /// Defaults to their username, which the grant accepts without anything
        /// being declared — asking an operator to write a name down twice is a
        /// configuration step with no decision in it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub issuer: Option<String>,
        /// Which assertion profile the key pair is for: `jwt` for RFC 7523 and
        /// `saml` for RFC 7522. Defaults to `jwt`, which is what every caller
        /// written before this field existed sends and is why it is the default
        /// rather than a required field. A value this service does not know is
        /// REFUSED rather than defaulted — a caller that asked for a profile wants
        /// a certificate for something, and quietly handing back the other one
        /// would put a key pair on the wrong attribute set with nothing saying so.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub purpose: Option<BodyPurpose>,
        /// The leaf's CN. Defaults to the identifier. The identifier also goes into
        /// a URI subjectAltName either way, because a CN is a display name and a
        /// SAN is the machine-readable one.
        #[serde(rename = "commonName", default, skip_serializing_if = "Option::is_none")]
        pub common_name: Option<String>,
        /// The LEAF's key algorithm. Defaults to the Issuing CA's, which is the
        /// chain a client library is least likely to be surprised by.
        #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
        pub key_alg: Option<BodyKeyAlg>,
        /// How long the certificate is valid. Defaults to `pki.leafLifetimeDays`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub days: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors116;
}

/// Issue a certificate from the form — any profile, any issuer, every extension
pub mod issue_pki_certificate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/pki/issue-certificate";
    pub const OPERATION_ID: &str = "issuePkiCertificate";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct Body {
        /// The members the schema does not name, which it allows.
        #[serde(flatten)]
        pub extra: serde_json::Map<String, serde_json::Value>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors120;
}

/// Use a key pair of your own for one slot
pub mod pin_pki_key_pair {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/pki/pin-key";
    pub const OPERATION_ID: &str = "pinPkiKeyPair";

    /// The use case.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyUseCase {
        #[serde(rename = "jose")]
        Jose,
        #[serde(rename = "xml")]
        Xml,
        #[serde(rename = "assertions")]
        Assertions,
        #[serde(rename = "tls")]
        Tls,
        #[serde(rename = "cell")]
        Cell,
        #[serde(rename = "spiffe")]
        Spiffe,
        #[serde(rename = "pep-tls")]
        PepTls,
        #[serde(rename = "realm-tls")]
        RealmTls,
        #[serde(rename = "kdc")]
        Kdc,
        #[serde(rename = "acme")]
        Acme,
        #[serde(rename = "est")]
        Est,
        #[serde(rename = "scep")]
        Scep,
        #[serde(rename = "tls-client")]
        TlsClient,
        #[serde(rename = "message-signing")]
        MessageSigning,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// A realm id or `*process`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        /// The use case.
        #[serde(rename = "useCase")]
        pub use_case: BodyUseCase,
        /// The algorithm, as it appears in that use case’s certified list —
        /// `RS256`, `ES256:P-256`, `EdDSA:Ed25519`.
        pub slot: String,
        /// Your private key.
        #[serde(rename = "privateKeyPem")]
        pub private_key_pem: String,
        /// Optional. Omit it and this service issues one from its own authority.
        #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
        pub certificate_pem: Option<String>,
        /// Optional, with `certificatePem`: the certificates above it, the one that
        /// issued it first. A pinned signing key publishes them as its `x5c`; each
        /// must have issued the one before (STS-PKI-0209).
        #[serde(rename = "chainPem", default, skip_serializing_if = "Option::is_none")]
        pub chain_pem: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors123;
}

/// Renew the certificates under one Issuing CA, keeping the keys
pub mod recertify_pki_use_case {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/pki/recertify";
    pub const OPERATION_ID: &str = "recertifyPkiUseCase";

    /// The use case to renew.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyUseCase {
        #[serde(rename = "jose")]
        Jose,
        #[serde(rename = "xml")]
        Xml,
        #[serde(rename = "assertions")]
        Assertions,
        #[serde(rename = "tls")]
        Tls,
        #[serde(rename = "cell")]
        Cell,
        #[serde(rename = "spiffe")]
        Spiffe,
        #[serde(rename = "pep-tls")]
        PepTls,
        #[serde(rename = "realm-tls")]
        RealmTls,
        #[serde(rename = "kdc")]
        Kdc,
        #[serde(rename = "acme")]
        Acme,
        #[serde(rename = "est")]
        Est,
        #[serde(rename = "scep")]
        Scep,
        #[serde(rename = "tls-client")]
        TlsClient,
        #[serde(rename = "message-signing")]
        MessageSigning,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// A realm id or `*process`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        /// The use case to renew.
        #[serde(rename = "useCase")]
        pub use_case: BodyUseCase,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors119;
}

/// Give one use case’s Issuing CA a new key pair
pub mod reissue_pki_use_case {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/pki/reissue-use-case";
    pub const OPERATION_ID: &str = "reissuePkiUseCase";

    /// One of `jose`, `xml`, `assertions`, `spiffe`, `pep-tls` (a realm) or `tls`
    /// (the process). Asking for one in the wrong scope is refused and the refusal
    /// says which scope it belongs to.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyUseCase {
        #[serde(rename = "jose")]
        Jose,
        #[serde(rename = "xml")]
        Xml,
        #[serde(rename = "assertions")]
        Assertions,
        #[serde(rename = "tls")]
        Tls,
        #[serde(rename = "cell")]
        Cell,
        #[serde(rename = "spiffe")]
        Spiffe,
        #[serde(rename = "pep-tls")]
        PepTls,
        #[serde(rename = "realm-tls")]
        RealmTls,
        #[serde(rename = "kdc")]
        Kdc,
        #[serde(rename = "acme")]
        Acme,
        #[serde(rename = "est")]
        Est,
        #[serde(rename = "scep")]
        Scep,
        #[serde(rename = "tls-client")]
        TlsClient,
        #[serde(rename = "message-signing")]
        MessageSigning,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// A realm id or `*process`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        /// One of `jose`, `xml`, `assertions`, `spiffe`, `pep-tls` (a realm) or
        /// `tls` (the process). Asking for one in the wrong scope is refused and
        /// the refusal says which scope it belongs to.
        #[serde(rename = "useCase")]
        pub use_case: BodyUseCase,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors119;
}

/// Lift a `certificateHold` — the one revocation RFC 5280 lets you undo
pub mod release_pki_certificate_hold {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/pki/release-hold";
    pub const OPERATION_ID: &str = "releasePkiCertificateHold";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// As on `revoke-certificate`: a realm id, `*service`, `*process`, or
        /// omitted for the realm this request arrived in.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        /// The issuing authority the hold is on. It has to be the same one that
        /// took it — a serial is only unique within an issuer.
        pub ca: String,
        /// The held certificate's serial, spelt however you like.
        #[serde(rename = "serialHex")]
        pub serial_hex: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors119;
}

/// Remove one object from this realm’s store
pub mod remove_pki_object {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/pki/remove-object";
    pub const OPERATION_ID: &str = "removePkiObject";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct Body {
        /// The `id` of a row in `workbench.objects`.
        #[serde(rename = "objectId")]
        pub object_id: String,
        /// The members the schema does not name, which it allows.
        #[serde(flatten)]
        pub extra: serde_json::Map<String, serde_json::Value>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors119;
}

/// Take an issued key pair off an application — which is NOT revocation — or
/// revoke one of a person's
pub mod revoke_pki_key_pair {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/pki/revoke";
    pub const OPERATION_ID: &str = "revokePkiKeyPair";

    /// WHOSE key pair. Defaults to `application`, which is what every caller
    /// written before this field existed sends. `person` revokes one of a
    /// `ou=users` entry's key pairs, named by `handle`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyTarget {
        #[serde(rename = "application")]
        Application,
        #[serde(rename = "person")]
        Person,
    }

    /// Which profile's key pair. Defaults to `jwt`. The other profile is untouched
    /// either way.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyPurpose {
        #[serde(rename = "jwt")]
        Jwt,
        #[serde(rename = "saml")]
        Saml,
    }

    /// `target=person` only: why. Defaults to `cessationOfOperation`;
    /// `keyCompromise` also raises a RISC credential-compromise event.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyReason {
        #[serde(rename = "cessationOfOperation")]
        CessationOfOperation,
        #[serde(rename = "keyCompromise")]
        KeyCompromise,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The application to take the key pair off — or the USERNAME, with
        /// `target=person`.
        pub identifier: String,
        /// WHOSE key pair. Defaults to `application`, which is what every caller
        /// written before this field existed sends. `person` revokes one of a
        /// `ou=users` entry's key pairs, named by `handle`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub target: Option<BodyTarget>,
        /// Which profile's key pair. Defaults to `jwt`. The other profile is
        /// untouched either way.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub purpose: Option<BodyPurpose>,
        /// `target=person` only: the key pair to revoke — its `kid` (`jwt`) or
        /// certificate thumbprint (`saml`), as GET /admin-api/users?user= lists it,
        /// or its certificate's serial in hex. Only that person's key pairs are
        /// searched.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub handle: Option<String>,
        /// `target=person` only: why. Defaults to `cessationOfOperation`;
        /// `keyCompromise` also raises a RISC credential-compromise event.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<BodyReason>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors117;
}

/// Put a serial on one certificate authority's revocation list — which is NOT
/// `revoke`
pub mod revoke_pki_certificate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/pki/revoke-certificate";
    pub const OPERATION_ID: &str = "revokePkiCertificate";

    /// RFC 5280 section 5.3.1. Defaults to `superseded`, which is what this service
    /// uses when it rotates or reissues something itself. `certificateHold` is the
    /// only one `release-hold` can undo; `unspecified` writes no reason code at
    /// all, which is what that value means on the wire.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyReason {
        #[serde(rename = "unspecified")]
        Unspecified,
        #[serde(rename = "keyCompromise")]
        KeyCompromise,
        #[serde(rename = "cACompromise")]
        CACompromise,
        #[serde(rename = "affiliationChanged")]
        AffiliationChanged,
        #[serde(rename = "superseded")]
        Superseded,
        #[serde(rename = "cessationOfOperation")]
        CessationOfOperation,
        #[serde(rename = "certificateHold")]
        CertificateHold,
        #[serde(rename = "privilegeWithdrawn")]
        PrivilegeWithdrawn,
        #[serde(rename = "aACompromise")]
        AACompromise,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// Which branch the issuer is in: a realm id, `*service` for the one Root,
        /// `*process` for the process branch, or omitted for the realm this request
        /// arrived in.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        /// The issuing authority, as `GET /admin-api/pki` names it in `revocation`:
        /// `root`, `intermediate`, or a use case id for an Issuing CA. **A
        /// revocation is made BY AN ISSUER** — a serial is only unique within one,
        /// which is why there is a list per CA and not one per realm.
        pub ca: String,
        /// The certificate's serial number in hex. Case, leading zeros and
        /// separators are all ignored: a CRL carries a DER integer and an OCSP
        /// request carries a string somebody typed, and two spellings of one serial
        /// is a certificate that is revoked and reports as good.
        #[serde(rename = "serialHex")]
        pub serial_hex: String,
        /// RFC 5280 section 5.3.1. Defaults to `superseded`, which is what this
        /// service uses when it rotates or reissues something itself.
        /// `certificateHold` is the only one `release-hold` can undo; `unspecified`
        /// writes no reason code at all, which is what that value means on the
        /// wire.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<BodyReason>,
        /// Optional. The subject DN, kept for the operator reading the list — it is
        /// not on the CRL, which carries serials.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        /// Optional. Why, in your own words, for the same reader.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors125;
}

/// Paranoid PKI mode, the signer truststore and what is pinned
pub mod get_pki_trust {
    pub const METHOD: &str = "GET";
    pub const PATH: &str = "/admin-api/pki/trust";
    pub const OPERATION_ID: &str = "getPkiTrust";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(rename = "pinsPage", default, skip_serializing_if = "Option::is_none")]
        pub pins_page: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub per: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200MasterValue {
        #[serde(rename = "auto")]
        Auto,
        #[serde(rename = "on")]
        On,
        #[serde(rename = "off")]
        Off,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Master {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub value: Option<Answer200MasterValue>,
        #[serde(rename = "inForce", default, skip_serializing_if = "Option::is_none")]
        pub in_force: Option<bool>,
        #[serde(rename = "decidedBy", default, skip_serializing_if = "Option::is_none")]
        pub decided_by: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub product: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItemExemptionsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub check: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub spec: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200RowsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub purpose: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub setting: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub covers: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub adds: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub anchors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub exemptions: Option<Vec<Answer200RowsItemExemptionsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub phase: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub on: Option<bool>,
        #[serde(rename = "inForce", default, skip_serializing_if = "Option::is_none")]
        pub in_force: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub assessed: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub refused: Option<i64>,
        #[serde(rename = "lastRefusal", default, skip_serializing_if = "Option::is_none")]
        pub last_refusal: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200Truststore {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub installed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub file: Option<String>,
        #[serde(rename = "loadedFromFile", default, skip_serializing_if = "Option::is_none")]
        pub loaded_from_file: Option<i64>,
        #[serde(rename = "maxAnchors", default, skip_serializing_if = "Option::is_none")]
        pub max_anchors: Option<i64>,
        #[serde(rename = "maxIntermediates", default, skip_serializing_if = "Option::is_none")]
        pub max_intermediates: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub anchors: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub intermediates: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub entries: Option<sts_model_management_components_4::WithOkMessageErrors112>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Answer200PinsItemStatus {
        #[serde(rename = "valid")]
        Valid,
        #[serde(rename = "expiring")]
        Expiring,
        #[serde(rename = "expired")]
        Expired,
        #[serde(rename = "not-yet-valid")]
        NotYetValid,
        #[serde(rename = "revoked")]
        Revoked,
        #[serde(rename = "chain-missing")]
        ChainMissing,
        #[serde(rename = "self-signed")]
        SelfSigned,
        #[serde(rename = "thumbprint-only")]
        ThumbprintOnly,
        #[serde(rename = "unreadable")]
        Unreadable,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200PinsItem {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
        #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
        pub where_: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub purpose: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub href: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub thumbprint: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub subject: Option<String>,
        #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
        pub not_before: Option<f64>,
        #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
        pub not_after: Option<f64>,
        #[serde(rename = "selfSigned", default, skip_serializing_if = "Option::is_none")]
        pub self_signed: Option<bool>,
        #[serde(rename = "chainedTo", default, skip_serializing_if = "Option::is_none")]
        pub chained_to: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub revocation: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<Answer200PinsItemStatus>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fingerprint256: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200ClientTruststore {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub href: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub count: Option<i64>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub realm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub master: Option<Answer200Master>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rows: Option<Vec<Answer200RowsItem>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub truststore: Option<Answer200Truststore>,
        #[serde(rename = "assessedAt", default, skip_serializing_if = "Option::is_none")]
        pub assessed_at: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pins: Option<Vec<Answer200PinsItem>>,
        #[serde(rename = "pinsTotal", default, skip_serializing_if = "Option::is_none")]
        pub pins_total: Option<i64>,
        #[serde(rename = "pinsPaging", default, skip_serializing_if = "Option::is_none")]
        pub pins_paging: Option<sts_model_management_components_4::WithPagePagesPerPage>,
        #[serde(rename = "clientTruststore", default, skip_serializing_if = "Option::is_none")]
        pub client_truststore: Option<Answer200ClientTruststore>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub actions: Option<Vec<String>>,
    }
}

/// Trust a third party's certificate authorities in this realm
pub mod add_signer_trust_anchors {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/pki/trust/add";
    pub const OPERATION_ID: &str = "addSignerTrustAnchors";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyCertificates {
        V1(Vec<String>),
        String(String),
    }

    /// Omitted: a self-issued certificate is an anchor, any other an intermediate.
    /// `accepted`: one leaf a server presents, trusted as itself for outbound TLS
    /// and for nothing else.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyKind {
        #[serde(rename = "anchor")]
        Anchor,
        #[serde(rename = "intermediate")]
        Intermediate,
        #[serde(rename = "accepted")]
        Accepted,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum BodyPurposes {
        V1(Vec<String>),
        String(String),
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// One or more PEM blocks, as one string or a list.
        pub certificates: BodyCertificates,
        /// Omitted: a self-issued certificate is an anchor, any other an
        /// intermediate. `accepted`: one leaf a server presents, trusted as itself
        /// for outbound TLS and for nothing else.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<BodyKind>,
        /// Use cases to restrict them to; none means every use case.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub purposes: Option<BodyPurposes>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors113;
}

/// Audit what this realm pins, now
pub mod recheck_pinned_certificates {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/pki/trust/recheck";
    pub const OPERATION_ID: &str = "recheckPinnedCertificates";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors114;
}

/// Stop trusting a certificate in this realm's signer truststore
pub mod remove_signer_trust_anchor {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/pki/trust/remove";
    pub const OPERATION_ID: &str = "removeSignerTrustAnchor";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub fingerprint: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
    }
}

/// Set paranoid PKI mode, or one use case's row
pub mod set_paranoid_pki_row {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/pki/trust/set-row";
    pub const OPERATION_ID: &str = "setParanoidPkiRow";

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        pub setting: String,
        pub value: sts_model_base::unions::BoolOrString,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Answer200 {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub errors: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub setting: Option<String>,
    }
}

/// Stop using a pinned key pair for one slot
pub mod unpin_pki_key_pair {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/pki/unpin-key";
    pub const OPERATION_ID: &str = "unpinPkiKeyPair";

    /// The use case.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyUseCase {
        #[serde(rename = "jose")]
        Jose,
        #[serde(rename = "xml")]
        Xml,
        #[serde(rename = "assertions")]
        Assertions,
        #[serde(rename = "tls")]
        Tls,
        #[serde(rename = "cell")]
        Cell,
        #[serde(rename = "spiffe")]
        Spiffe,
        #[serde(rename = "pep-tls")]
        PepTls,
        #[serde(rename = "realm-tls")]
        RealmTls,
        #[serde(rename = "kdc")]
        Kdc,
        #[serde(rename = "acme")]
        Acme,
        #[serde(rename = "est")]
        Est,
        #[serde(rename = "scep")]
        Scep,
        #[serde(rename = "tls-client")]
        TlsClient,
        #[serde(rename = "message-signing")]
        MessageSigning,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// A realm id; empty for this realm.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        /// The use case.
        #[serde(rename = "useCase")]
        pub use_case: BodyUseCase,
        /// The slot the key was pinned in.
        pub slot: String,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors124;
}

/// Replace an application's or a person's key pair with a certificate it
/// already holds — issued by this realm's CA, or by another with its full chain
pub mod upload_pki_certificate {
    pub const METHOD: &str = "POST";
    pub const PATH: &str = "/admin-api/pki/upload-certificate";
    pub const OPERATION_ID: &str = "uploadPkiCertificate";

    /// Which profile's key pair to replace. Defaults to `jwt`; the other is
    /// untouched.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyPurpose {
        #[serde(rename = "jwt")]
        Jwt,
        #[serde(rename = "saml")]
        Saml,
    }

    /// WHOSE key pair. Defaults to `application`; `person` ADDS a key pair to a
    /// `ou=users` entry, which must already exist (#1290).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum BodyTarget {
        #[serde(rename = "application")]
        Application,
        #[serde(rename = "person")]
        Person,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Body {
        /// The application, exactly as the registry holds it — or the USERNAME,
        /// with `target=person`.
        pub identifier: String,
        /// Which profile's key pair to replace. Defaults to `jwt`; the other is
        /// untouched.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub purpose: Option<BodyPurpose>,
        /// The leaf certificate, PEM. It may be followed by its chain in the same
        /// value.
        pub certificate: String,
        /// The certificates above it, PEM, in any order: every intermediate and the
        /// self-signed root for an external authority, nothing for this realm's
        /// own.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub chain: Option<String>,
        /// Console only: the page to return to. Ignored by this API.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub from: Option<String>,
        /// WHOSE key pair. Defaults to `application`; `person` ADDS a key pair to a
        /// `ou=users` entry, which must already exist (#1290).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub target: Option<BodyTarget>,
        /// `target=person` only: what the person calls this key pair, at most 40
        /// characters. Optional.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Query {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub cell: Option<String>,
    }

    pub type Answer200 = sts_model_management_components_4::WithOkMessageErrors118;
}

/// Reads `value` as the JSON body of `operation_id`; `None` when the
/// operation takes no JSON body.
pub fn read_body(operation_id: &str, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match operation_id {
        "addClaimProvider" => Some(serde_json::from_value::<add_claim_provider::Body>(value.clone()).map(|_| ())),
        "removeClaimProvider" => Some(serde_json::from_value::<remove_claim_provider::Body>(value.clone()).map(|_| ())),
        "revokeClaimSourceLink" => Some(serde_json::from_value::<revoke_claim_source_link::Body>(value.clone()).map(|_| ())),
        "updateClaimProvider" => Some(serde_json::from_value::<update_claim_provider::Body>(value.clone()).map(|_| ())),
        "retryCommandDelivery" => Some(serde_json::from_value::<retry_command_delivery::Body>(value.clone()).map(|_| ())),
        "sendAccountCommand" => Some(serde_json::from_value::<send_account_command::Body>(value.clone()).map(|_| ())),
        "sendTenantCommand" => Some(serde_json::from_value::<send_tenant_command::Body>(value.clone()).map(|_| ())),
        "revokeGrant" => Some(serde_json::from_value::<revoke_grant::Body>(value.clone()).map(|_| ())),
        "deletePushedRequest" => Some(serde_json::from_value::<delete_pushed_request::Body>(value.clone()).map(|_| ())),
        "addOidfedHeldMark" => Some(serde_json::from_value::<add_oidfed_held_mark::Body>(value.clone()).map(|_| ())),
        "addOidfedMarkType" => Some(serde_json::from_value::<add_oidfed_mark_type::Body>(value.clone()).map(|_| ())),
        "addOidfedSubordinate" => Some(serde_json::from_value::<add_oidfed_subordinate::Body>(value.clone()).map(|_| ())),
        "addOidfedTrustAnchor" => Some(serde_json::from_value::<add_oidfed_trust_anchor::Body>(value.clone()).map(|_| ())),
        "crawlOidfedCollection" => Some(serde_json::from_value::<crawl_oidfed_collection::Body>(value.clone()).map(|_| ())),
        "issueOidfedTrustMark" => Some(serde_json::from_value::<issue_oidfed_trust_mark::Body>(value.clone()).map(|_| ())),
        "reinstateOidfedSubordinate" => Some(serde_json::from_value::<reinstate_oidfed_subordinate::Body>(value.clone()).map(|_| ())),
        "removeOidfedHeldMark" => Some(serde_json::from_value::<remove_oidfed_held_mark::Body>(value.clone()).map(|_| ())),
        "removeOidfedMarkPolicy" => Some(serde_json::from_value::<remove_oidfed_mark_policy::Body>(value.clone()).map(|_| ())),
        "removeOidfedMarkType" => Some(serde_json::from_value::<remove_oidfed_mark_type::Body>(value.clone()).map(|_| ())),
        "removeOidfedSubordinate" => Some(serde_json::from_value::<remove_oidfed_subordinate::Body>(value.clone()).map(|_| ())),
        "removeOidfedTrustAnchor" => Some(serde_json::from_value::<remove_oidfed_trust_anchor::Body>(value.clone()).map(|_| ())),
        "resolveOidfedEntity" => Some(serde_json::from_value::<resolve_oidfed_entity::Body>(value.clone()).map(|_| ())),
        "revokeOidfedKey" => Some(serde_json::from_value::<revoke_oidfed_key::Body>(value.clone()).map(|_| ())),
        "revokeOidfedTrustMark" => Some(serde_json::from_value::<revoke_oidfed_trust_mark::Body>(value.clone()).map(|_| ())),
        "rotateOidfedKey" => Some(serde_json::from_value::<rotate_oidfed_key::Body>(value.clone()).map(|_| ())),
        "setOidfedMarkPolicy" => Some(serde_json::from_value::<set_oidfed_mark_policy::Body>(value.clone()).map(|_| ())),
        "suspendOidfedSubordinate" => Some(serde_json::from_value::<suspend_oidfed_subordinate::Body>(value.clone()).map(|_| ())),
        "setOwnerProtected" => Some(serde_json::from_value::<set_owner_protected::Body>(value.clone()).map(|_| ())),
        "buildPkiChain" => Some(serde_json::from_value::<build_pki_chain::Body>(value.clone()).map(|_| ())),
        "buildPkiRoot" => Some(serde_json::from_value::<build_pki_root::Body>(value.clone()).map(|_| ())),
        "buildPkiScope" => Some(serde_json::from_value::<build_pki_scope::Body>(value.clone()).map(|_| ())),
        "clearPkiChain" => Some(serde_json::from_value::<clear_pki_chain::Body>(value.clone()).map(|_| ())),
        "clearPkiObjects" => Some(serde_json::from_value::<clear_pki_objects::Body>(value.clone()).map(|_| ())),
        "exportPkiKeyPair" => Some(serde_json::from_value::<export_pki_key_pair::Body>(value.clone()).map(|_| ())),
        "importPkiCa" => Some(serde_json::from_value::<import_pki_ca::Body>(value.clone()).map(|_| ())),
        "issuePkiKeyPair" => Some(serde_json::from_value::<issue_pki_key_pair::Body>(value.clone()).map(|_| ())),
        "issuePkiCertificate" => Some(serde_json::from_value::<issue_pki_certificate::Body>(value.clone()).map(|_| ())),
        "pinPkiKeyPair" => Some(serde_json::from_value::<pin_pki_key_pair::Body>(value.clone()).map(|_| ())),
        "recertifyPkiUseCase" => Some(serde_json::from_value::<recertify_pki_use_case::Body>(value.clone()).map(|_| ())),
        "reissuePkiUseCase" => Some(serde_json::from_value::<reissue_pki_use_case::Body>(value.clone()).map(|_| ())),
        "releasePkiCertificateHold" => Some(serde_json::from_value::<release_pki_certificate_hold::Body>(value.clone()).map(|_| ())),
        "removePkiObject" => Some(serde_json::from_value::<remove_pki_object::Body>(value.clone()).map(|_| ())),
        "revokePkiKeyPair" => Some(serde_json::from_value::<revoke_pki_key_pair::Body>(value.clone()).map(|_| ())),
        "revokePkiCertificate" => Some(serde_json::from_value::<revoke_pki_certificate::Body>(value.clone()).map(|_| ())),
        "addSignerTrustAnchors" => Some(serde_json::from_value::<add_signer_trust_anchors::Body>(value.clone()).map(|_| ())),
        "recheckPinnedCertificates" => Some(serde_json::from_value::<recheck_pinned_certificates::Body>(value.clone()).map(|_| ())),
        "removeSignerTrustAnchor" => Some(serde_json::from_value::<remove_signer_trust_anchor::Body>(value.clone()).map(|_| ())),
        "setParanoidPkiRow" => Some(serde_json::from_value::<set_paranoid_pki_row::Body>(value.clone()).map(|_| ())),
        "unpinPkiKeyPair" => Some(serde_json::from_value::<unpin_pki_key_pair::Body>(value.clone()).map(|_| ())),
        "uploadPkiCertificate" => Some(serde_json::from_value::<upload_pki_certificate::Body>(value.clone()).map(|_| ())),
        _ => None,
    }
}

/// Reads `value` as the JSON answer of `operation_id` for `status`;
/// `None` when the model gives that status no JSON answer.
pub fn read_answer(operation_id: &str, status: u16, value: &serde_json::Value)
    -> Option<Result<(), serde_json::Error>> {
    match (operation_id, status) {
        ("getCertificates", 200) => Some(serde_json::from_value::<get_certificates::Answer200>(value.clone()).map(|_| ())),
        ("getClaimProviders", 200) => Some(serde_json::from_value::<get_claim_providers::Answer200>(value.clone()).map(|_| ())),
        ("addClaimProvider", 200) => Some(serde_json::from_value::<add_claim_provider::Answer200>(value.clone()).map(|_| ())),
        ("removeClaimProvider", 200) => Some(serde_json::from_value::<remove_claim_provider::Answer200>(value.clone()).map(|_| ())),
        ("revokeClaimSourceLink", 200) => Some(serde_json::from_value::<revoke_claim_source_link::Answer200>(value.clone()).map(|_| ())),
        ("updateClaimProvider", 200) => Some(serde_json::from_value::<update_claim_provider::Answer200>(value.clone()).map(|_| ())),
        ("getProviderCommands", 200) => Some(serde_json::from_value::<get_provider_commands::Answer200>(value.clone()).map(|_| ())),
        ("retryCommandDelivery", 200) => Some(serde_json::from_value::<retry_command_delivery::Answer200>(value.clone()).map(|_| ())),
        ("sendAccountCommand", 200) => Some(serde_json::from_value::<send_account_command::Answer200>(value.clone()).map(|_| ())),
        ("sendTenantCommand", 200) => Some(serde_json::from_value::<send_tenant_command::Answer200>(value.clone()).map(|_| ())),
        ("getGrants", 200) => Some(serde_json::from_value::<get_grants::Answer200>(value.clone()).map(|_| ())),
        ("revokeGrant", 200) => Some(serde_json::from_value::<revoke_grant::Answer200>(value.clone()).map(|_| ())),
        ("getOauth2Settings", 200) => Some(serde_json::from_value::<get_oauth2_settings::Answer200>(value.clone()).map(|_| ())),
        ("getOauth2Monitor", 200) => Some(serde_json::from_value::<get_oauth2_monitor::Answer200>(value.clone()).map(|_| ())),
        ("deletePushedRequest", 200) => Some(serde_json::from_value::<delete_pushed_request::Answer200>(value.clone()).map(|_| ())),
        ("getOid4vciSettings", 200) => Some(serde_json::from_value::<get_oid4vci_settings::Answer200>(value.clone()).map(|_| ())),
        ("getLastCredentialRequest", 200) => Some(serde_json::from_value::<get_last_credential_request::Answer200>(value.clone()).map(|_| ())),
        ("getCredentialNotification", 200) => Some(serde_json::from_value::<get_credential_notification::Answer200>(value.clone()).map(|_| ())),
        ("getOid4vpSettings", 200) => Some(serde_json::from_value::<get_oid4vp_settings::Answer200>(value.clone()).map(|_| ())),
        ("getOidfed", 200) => Some(serde_json::from_value::<get_oidfed::Answer200>(value.clone()).map(|_| ())),
        ("addOidfedHeldMark", 200) => Some(serde_json::from_value::<add_oidfed_held_mark::Answer200>(value.clone()).map(|_| ())),
        ("addOidfedMarkType", 200) => Some(serde_json::from_value::<add_oidfed_mark_type::Answer200>(value.clone()).map(|_| ())),
        ("addOidfedSubordinate", 200) => Some(serde_json::from_value::<add_oidfed_subordinate::Answer200>(value.clone()).map(|_| ())),
        ("addOidfedTrustAnchor", 200) => Some(serde_json::from_value::<add_oidfed_trust_anchor::Answer200>(value.clone()).map(|_| ())),
        ("crawlOidfedCollection", 200) => Some(serde_json::from_value::<crawl_oidfed_collection::Answer200>(value.clone()).map(|_| ())),
        ("issueOidfedTrustMark", 200) => Some(serde_json::from_value::<issue_oidfed_trust_mark::Answer200>(value.clone()).map(|_| ())),
        ("reinstateOidfedSubordinate", 200) => Some(serde_json::from_value::<reinstate_oidfed_subordinate::Answer200>(value.clone()).map(|_| ())),
        ("removeOidfedHeldMark", 200) => Some(serde_json::from_value::<remove_oidfed_held_mark::Answer200>(value.clone()).map(|_| ())),
        ("removeOidfedMarkPolicy", 200) => Some(serde_json::from_value::<remove_oidfed_mark_policy::Answer200>(value.clone()).map(|_| ())),
        ("removeOidfedMarkType", 200) => Some(serde_json::from_value::<remove_oidfed_mark_type::Answer200>(value.clone()).map(|_| ())),
        ("removeOidfedSubordinate", 200) => Some(serde_json::from_value::<remove_oidfed_subordinate::Answer200>(value.clone()).map(|_| ())),
        ("removeOidfedTrustAnchor", 200) => Some(serde_json::from_value::<remove_oidfed_trust_anchor::Answer200>(value.clone()).map(|_| ())),
        ("resolveOidfedEntity", 200) => Some(serde_json::from_value::<resolve_oidfed_entity::Answer200>(value.clone()).map(|_| ())),
        ("revokeOidfedKey", 200) => Some(serde_json::from_value::<revoke_oidfed_key::Answer200>(value.clone()).map(|_| ())),
        ("revokeOidfedTrustMark", 200) => Some(serde_json::from_value::<revoke_oidfed_trust_mark::Answer200>(value.clone()).map(|_| ())),
        ("rotateOidfedKey", 200) => Some(serde_json::from_value::<rotate_oidfed_key::Answer200>(value.clone()).map(|_| ())),
        ("setOidfedMarkPolicy", 200) => Some(serde_json::from_value::<set_oidfed_mark_policy::Answer200>(value.clone()).map(|_| ())),
        ("suspendOidfedSubordinate", 200) => Some(serde_json::from_value::<suspend_oidfed_subordinate::Answer200>(value.clone()).map(|_| ())),
        ("getOwnership", 200) => Some(serde_json::from_value::<get_ownership::Answer200>(value.clone()).map(|_| ())),
        ("setOwnerProtected", 200) => Some(serde_json::from_value::<set_owner_protected::Answer200>(value.clone()).map(|_| ())),
        ("getPersistenceSettings", 200) => Some(serde_json::from_value::<get_persistence_settings::Answer200>(value.clone()).map(|_| ())),
        ("getPki", 200) => Some(serde_json::from_value::<get_pki::Answer200>(value.clone()).map(|_| ())),
        ("buildPkiChain", 200) => Some(serde_json::from_value::<build_pki_chain::Answer200>(value.clone()).map(|_| ())),
        ("buildPkiRoot", 200) => Some(serde_json::from_value::<build_pki_root::Answer200>(value.clone()).map(|_| ())),
        ("buildPkiScope", 200) => Some(serde_json::from_value::<build_pki_scope::Answer200>(value.clone()).map(|_| ())),
        ("clearPkiChain", 200) => Some(serde_json::from_value::<clear_pki_chain::Answer200>(value.clone()).map(|_| ())),
        ("clearPkiObjects", 200) => Some(serde_json::from_value::<clear_pki_objects::Answer200>(value.clone()).map(|_| ())),
        ("exportPkiKeyPair", 200) => Some(serde_json::from_value::<export_pki_key_pair::Answer200>(value.clone()).map(|_| ())),
        ("importPkiCa", 200) => Some(serde_json::from_value::<import_pki_ca::Answer200>(value.clone()).map(|_| ())),
        ("issuePkiKeyPair", 200) => Some(serde_json::from_value::<issue_pki_key_pair::Answer200>(value.clone()).map(|_| ())),
        ("issuePkiCertificate", 200) => Some(serde_json::from_value::<issue_pki_certificate::Answer200>(value.clone()).map(|_| ())),
        ("pinPkiKeyPair", 200) => Some(serde_json::from_value::<pin_pki_key_pair::Answer200>(value.clone()).map(|_| ())),
        ("recertifyPkiUseCase", 200) => Some(serde_json::from_value::<recertify_pki_use_case::Answer200>(value.clone()).map(|_| ())),
        ("reissuePkiUseCase", 200) => Some(serde_json::from_value::<reissue_pki_use_case::Answer200>(value.clone()).map(|_| ())),
        ("releasePkiCertificateHold", 200) => Some(serde_json::from_value::<release_pki_certificate_hold::Answer200>(value.clone()).map(|_| ())),
        ("removePkiObject", 200) => Some(serde_json::from_value::<remove_pki_object::Answer200>(value.clone()).map(|_| ())),
        ("revokePkiKeyPair", 200) => Some(serde_json::from_value::<revoke_pki_key_pair::Answer200>(value.clone()).map(|_| ())),
        ("revokePkiCertificate", 200) => Some(serde_json::from_value::<revoke_pki_certificate::Answer200>(value.clone()).map(|_| ())),
        ("getPkiTrust", 200) => Some(serde_json::from_value::<get_pki_trust::Answer200>(value.clone()).map(|_| ())),
        ("addSignerTrustAnchors", 200) => Some(serde_json::from_value::<add_signer_trust_anchors::Answer200>(value.clone()).map(|_| ())),
        ("recheckPinnedCertificates", 200) => Some(serde_json::from_value::<recheck_pinned_certificates::Answer200>(value.clone()).map(|_| ())),
        ("removeSignerTrustAnchor", 200) => Some(serde_json::from_value::<remove_signer_trust_anchor::Answer200>(value.clone()).map(|_| ())),
        ("setParanoidPkiRow", 200) => Some(serde_json::from_value::<set_paranoid_pki_row::Answer200>(value.clone()).map(|_| ())),
        ("unpinPkiKeyPair", 200) => Some(serde_json::from_value::<unpin_pki_key_pair::Answer200>(value.clone()).map(|_| ())),
        ("uploadPkiCertificate", 200) => Some(serde_json::from_value::<upload_pki_certificate::Answer200>(value.clone()).map(|_| ())),
        _ => None,
    }
}
