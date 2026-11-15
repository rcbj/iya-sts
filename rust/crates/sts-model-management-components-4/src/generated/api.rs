// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// GENERATED from models/api/ (#1390, #444) by models/lib/rust_lib.mjs.
// Do not edit: change the model and run
// tests/tools/regenerate-model-docs.sh. tests/model_domain.js fails when
// this differs.

pub type VerifiedClaimsValuesOpenIdConnect = serde_json::Value;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum VerifierRequestProtocolEndpointsItemMethods {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierRequestProtocolEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<VerifierRequestProtocolEndpointsItemMethods>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum VerifierRequestFormatsItemIdentifier {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierRequestFormatsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(rename = "identifiedBy", default, skip_serializing_if = "Option::is_none")]
    pub identified_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<VerifierRequestFormatsItemIdentifier>,
    #[serde(rename = "selectiveDisclosure", default, skip_serializing_if = "Option::is_none")]
    pub selective_disclosure: Option<String>,
    #[serde(rename = "holderBinding", default, skip_serializing_if = "Option::is_none")]
    pub holder_binding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configurations: Option<Vec<String>>,
    #[serde(rename = "identifierText", default, skip_serializing_if = "Option::is_none")]
    pub identifier_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierRequestCatalogueItemAttributesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldap: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierRequestCatalogueItemIssued {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carried: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierRequestCatalogueItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nested: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<VerifierRequestCatalogueItemAttributesItem>>,
    #[serde(rename = "ldpTerms", default, skip_serializing_if = "Option::is_none")]
    pub ldp_terms: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<Vec<String>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued: Option<VerifierRequestCatalogueItemIssued>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum VerifierRequestDcqlQueryCredentialsItemMetaTypeValuesItem {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierRequestDcqlQueryCredentialsItemMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vct_values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doctype_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_values: Option<Vec<VerifierRequestDcqlQueryCredentialsItemMetaTypeValuesItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierRequestDcqlQueryCredentialsItemClaimsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierRequestDcqlQueryCredentialsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<VerifierRequestDcqlQueryCredentialsItemMeta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_cryptographic_holder_binding: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<VerifierRequestDcqlQueryCredentialsItemClaimsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierRequestDcqlQueryCredentialSetsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<Vec<String>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierRequestDcqlQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Vec<VerifierRequestDcqlQueryCredentialsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_sets: Option<Vec<VerifierRequestDcqlQueryCredentialSetsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierRequestExtrasItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<Vec<String>>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierRequestRecentVerificationsVerificationsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(rename = "responseType", default, skip_serializing_if = "Option::is_none")]
    pub response_type: Option<String>,
    #[serde(rename = "responseMode", default, skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<String>,
    #[serde(rename = "byReference", default, skip_serializing_if = "Option::is_none")]
    pub by_reference: Option<bool>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested: Option<Vec<String>>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ok: Option<Option<bool>>,
    #[serde(rename = "decidedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub decided_at: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<String>>,
    #[serde(rename = "failedChecks", default, skip_serializing_if = "Option::is_none")]
    pub failed_checks: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierRequestRecentVerifications {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifications: Option<Vec<VerifierRequestRecentVerificationsVerificationsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierRequestStartChoices {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_type: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id_prefix: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierRequest {
    #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
    pub protocol_endpoints: Option<Vec<VerifierRequestProtocolEndpointsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub defaults: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub formats: Option<Vec<VerifierRequestFormatsItem>>,
    #[serde(rename = "ldpOmitted", default, skip_serializing_if = "Option::is_none")]
    pub ldp_omitted: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalogue: Option<Vec<VerifierRequestCatalogueItem>>,
    #[serde(rename = "dcqlQuery", default, skip_serializing_if = "Option::is_none")]
    pub dcql_query: Option<VerifierRequestDcqlQuery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extras: Option<Vec<VerifierRequestExtrasItem>>,
    #[serde(rename = "recentVerifications", default, skip_serializing_if = "Option::is_none")]
    pub recent_verifications: Option<VerifierRequestRecentVerifications>,
    #[serde(rename = "startChoices", default, skip_serializing_if = "Option::is_none")]
    pub start_choices: Option<VerifierRequestStartChoices>,
}

pub type WithAdditionalPropertiesPropertiesDataset = Vec<crate::WithProviderTextUrl>;

pub type WithAdditionalPropertiesPropertiesKty = Vec<crate::WithRelationshipJtiVia2>;

pub type WithAdditionalPropertiesPropertiesPage = Vec<crate::WithIdWhatOk>;

pub type WithAdditionalPropertiesPropertiesPage3 = Vec<crate::WithScimLdapKind>;

pub type WithAdditionalPropertiesPropertiesRunId = Vec<crate::WithRunIdJobIdRealm>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithAddressListeningError {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listening: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attested: Option<bool>,
    #[serde(rename = "peerCredentials", default, skip_serializing_if = "Option::is_none")]
    pub peer_credentials: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restricted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithAlgorithmCoseAlgPostQuantum {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(rename = "coseAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cose_alg: Option<Option<i64>>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lane: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub aaguid: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub model: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithAlgorithmDescriptionKeyAlgorithm {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub parameters: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithAlgorithmDescriptionKeyKey {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(rename = "modulusBits", default, skip_serializing_if = "Option::is_none")]
    pub modulus_bits: Option<i64>,
    #[serde(rename = "publicExponent", default, skip_serializing_if = "Option::is_none")]
    pub public_exponent: Option<String>,
    #[serde(rename = "namedCurve", default, skip_serializing_if = "Option::is_none")]
    pub named_curve: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithAlgorithmDescriptionKey {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<WithAlgorithmDescriptionKeyAlgorithm>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<WithAlgorithmDescriptionKeyKey>,
    #[serde(rename = "publicKeyOctets", default, skip_serializing_if = "Option::is_none")]
    pub public_key_octets: Option<i64>,
    #[serde(rename = "publicKeyHex", default, skip_serializing_if = "Option::is_none")]
    pub public_key_hex: Option<String>,
    #[serde(rename = "spkiSha256", default, skip_serializing_if = "Option::is_none")]
    pub spki_sha256: Option<String>,
}

pub type WithApplicationsGrantsLines = Vec<crate::WithClientClientNamePermissionId2>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithApplicationsGrantsLines2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applications: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lines: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dangling: Option<i64>,
    #[serde(rename = "selfGrants", default, skip_serializing_if = "Option::is_none")]
    pub self_grants: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unused: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithApplicationsGroupsPeople {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applications: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub people: Option<Vec<String>>,
    #[serde(rename = "peopleComplete", default, skip_serializing_if = "Option::is_none")]
    pub people_complete: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithAtFamilyKind {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub at: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    #[serde(rename = "flowLabel", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub flow_label: Option<Option<String>>,
    #[serde(rename = "flowProtocol", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub flow_protocol: Option<Option<String>>,
    #[serde(rename = "flowSpec", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub flow_spec: Option<Option<String>>,
    #[serde(rename = "flowOidc", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub flow_oidc: Option<Option<String>>,
    #[serde(rename = "flowStated", default, skip_serializing_if = "Option::is_none")]
    pub flow_stated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub state: Option<Option<String>>,
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(rename = "expiresAtMs", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub expires_at_ms: Option<Option<f64>>,
}

pub type WithAtOperationOutcome = Vec<crate::WithEntryEntryUriHostNames>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithAtOperationOutcome2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub outcome: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub profile: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub principal: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub target: Option<Option<String>>,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error_code: Option<Option<String>>,
    #[serde(rename = "failInfo", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub fail_info: Option<Option<String>>,
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub serial_hex: Option<Option<String>>,
}

pub type WithAuthMethodsOauthClientAuthTlsSources = Vec<crate::WithIdIdentifierDn>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithAuthMethodsOauthClientAuthTlsSources2 {
    #[serde(rename = "authMethods", default, skip_serializing_if = "Option::is_none")]
    pub auth_methods: Option<Vec<String>>,
    #[serde(rename = "oauthClientAuth", default, skip_serializing_if = "Option::is_none")]
    pub oauth_client_auth: Option<Vec<String>>,
    #[serde(rename = "tlsSources", default, skip_serializing_if = "Option::is_none")]
    pub tls_sources: Option<Vec<String>>,
    #[serde(rename = "scopeModes", default, skip_serializing_if = "Option::is_none")]
    pub scope_modes: Option<Vec<String>>,
    #[serde(rename = "groupModes", default, skip_serializing_if = "Option::is_none")]
    pub group_modes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprovision: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithAvailableEndpointDockerId {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub available: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(rename = "dockerId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub docker_id: Option<Option<String>>,
    /// ECS's `Limits`, as it said them.
    #[serde(rename = "containerLimits", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub container_limits: Option<Option<serde_json::Map<String, serde_json::Value>>>,
    #[serde(rename = "taskLimits", default, skip_serializing_if = "Option::is_none")]
    pub task_limits: Option<sts_model_management_components_3::TaskLimitsValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<sts_model_management_components_3::StatsValue>,
    #[serde(rename = "unavailableText", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub unavailable_text: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithAvailableFromEcsCgroupVersion {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub available: Option<bool>,
    #[serde(rename = "fromEcs", default, skip_serializing_if = "Option::is_none")]
    pub from_ecs: Option<bool>,
    #[serde(rename = "cgroupVersion", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cgroup_version: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub source: Option<Option<String>>,
    #[serde(rename = "unavailableText", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub unavailable_text: Option<Option<String>>,
    #[serde(rename = "cgroupUnavailableText", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cgroup_unavailable_text: Option<Option<String>>,
    #[serde(rename = "limitVcpus", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub limit_vcpus: Option<Option<f64>>,
    #[serde(rename = "limitSource", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub limit_source: Option<Option<String>>,
    #[serde(rename = "percentOfVcpus", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub percent_of_vcpus: Option<Option<f64>>,
    #[serde(rename = "limitText", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub limit_text: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub sampled: Option<Option<String>>,
    #[serde(rename = "windowSeconds", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub window_seconds: Option<Option<f64>>,
    #[serde(rename = "coresUsed", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cores_used: Option<Option<f64>>,
    #[serde(rename = "utilisationPercent", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub utilisation_percent: Option<Option<f64>>,
    #[serde(rename = "usageSeconds", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub usage_seconds: Option<Option<f64>>,
    #[serde(rename = "userSeconds", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub user_seconds: Option<Option<f64>>,
    #[serde(rename = "systemSeconds", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub system_seconds: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub throttling: Option<sts_model_management_components_3::ThrottlingValue>,
    #[serde(rename = "throttlingText", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub throttling_text: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithAvailableFromEcsCgroupVersion2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub available: Option<bool>,
    #[serde(rename = "fromEcs", default, skip_serializing_if = "Option::is_none")]
    pub from_ecs: Option<bool>,
    #[serde(rename = "cgroupVersion", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cgroup_version: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub source: Option<Option<String>>,
    #[serde(rename = "unavailableText", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub unavailable_text: Option<Option<String>>,
    #[serde(rename = "cgroupUnavailableText", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cgroup_unavailable_text: Option<Option<String>>,
    #[serde(rename = "currentBytes", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub current_bytes: Option<Option<f64>>,
    #[serde(rename = "limitBytes", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub limit_bytes: Option<Option<f64>>,
    #[serde(rename = "limitSource", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub limit_source: Option<Option<String>>,
    #[serde(rename = "limitText", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub limit_text: Option<Option<String>>,
    #[serde(rename = "utilisationPercent", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub utilisation_percent: Option<Option<f64>>,
    #[serde(rename = "peakBytes", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub peak_bytes: Option<Option<f64>>,
    #[serde(rename = "anonBytes", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub anon_bytes: Option<Option<f64>>,
    #[serde(rename = "fileBytes", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub file_bytes: Option<Option<f64>>,
    #[serde(rename = "kernelBytes", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub kernel_bytes: Option<Option<f64>>,
    #[serde(rename = "statText", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub stat_text: Option<Option<String>>,
    #[serde(rename = "oomKills", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub oom_kills: Option<Option<f64>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithCellDescriptionRefusedPeopleItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithCellDescriptionRefused {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell: Option<String>,
    /// Why the other cell did not list them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub people: Option<Vec<WithCellDescriptionRefusedPeopleItem>>,
    /// The `after` of the next page, empty on the last.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithChallengeRpIdAllowOptions {
    #[serde(rename = "userVerification", default, skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithChallengeRpIdAllow {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(rename = "rpId", default, skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<WithChallengeRpIdAllowOptions>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithChallengeRpIdUserUser {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithChallengeRpIdUser {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(rename = "rpId", default, skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<WithChallengeRpIdUserUser>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<crate::WithRpAlgorithmsAttestation>,
}

pub type WithCheckedMatchesExpected = Vec<crate::WithMemberValueKnown>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithCheckedMatchesExpected2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub matches: Option<Option<bool>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<Vec<String>>,
    #[serde(rename = "wellKnownUrl", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub well_known_url: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

pub type WithClientClientNamePermissionId = Vec<crate::WithResourceResourceNameBaseUri>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithClientClientNamePermissionId2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(rename = "clientName", default, skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(rename = "permissionId", default, skip_serializing_if = "Option::is_none")]
    pub permission_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(rename = "resourceName", default, skip_serializing_if = "Option::is_none")]
    pub resource_name: Option<String>,
    #[serde(rename = "baseUri", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub base_uri: Option<Option<String>>,
    #[serde(rename = "permissionName", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub permission_name: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub description: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dangling: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<bool>,
}

pub type WithClusteredTextIntervalSeconds = Vec<crate::WithIdTitleModule2>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithClusteredTextIntervalSeconds2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clustered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(rename = "intervalSeconds", default, skip_serializing_if = "Option::is_none")]
    pub interval_seconds: Option<f64>,
    #[serde(rename = "staleAfterSeconds", default, skip_serializing_if = "Option::is_none")]
    pub stale_after_seconds: Option<f64>,
    #[serde(rename = "goneRemovedAfterHours", default, skip_serializing_if = "Option::is_none")]
    pub gone_removed_after_hours: Option<f64>,
    #[serde(rename = "readError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub read_error: Option<Option<String>>,
}

pub type WithContainerDefinitionContainerObjectClasses = Vec<crate::WithKeyAttributeLabel>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithContainerDefinitionContainerObjectClasses2ObjectClassesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum WithContainerDefinitionContainerObjectClasses2AttributesItemKind {
    #[serde(rename = "single")]
    Single,
    #[serde(rename = "multi")]
    Multi,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithContainerDefinitionContainerObjectClasses2AttributesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<WithContainerDefinitionContainerObjectClasses2AttributesItemKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum WithContainerDefinitionContainerObjectClasses2PersonAttributesItemKind {
    #[serde(rename = "single")]
    Single,
    #[serde(rename = "multi")]
    Multi,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithContainerDefinitionContainerObjectClasses2PersonAttributesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<WithContainerDefinitionContainerObjectClasses2PersonAttributesItemKind>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithContainerDefinitionContainerObjectClasses2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    #[serde(rename = "definitionContainer", default, skip_serializing_if = "Option::is_none")]
    pub definition_container: Option<String>,
    #[serde(rename = "objectClasses", default, skip_serializing_if = "Option::is_none")]
    pub object_classes: Option<Vec<WithContainerDefinitionContainerObjectClasses2ObjectClassesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<WithContainerDefinitionContainerObjectClasses2AttributesItem>>,
    #[serde(rename = "personAttributes", default, skip_serializing_if = "Option::is_none")]
    pub person_attributes: Option<Vec<WithContainerDefinitionContainerObjectClasses2PersonAttributesItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithCrawlCrawlEverySJobOff {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crawl: Option<sts_model_management_components_1::CrawlValue>,
    #[serde(rename = "crawlEveryS", default, skip_serializing_if = "Option::is_none")]
    pub crawl_every_s: Option<f64>,
    #[serde(rename = "jobOff", default, skip_serializing_if = "Option::is_none")]
    pub job_off: Option<String>,
}

pub type WithCredentialsCredentialsetsState = Vec<crate::WithIdFormatMeta>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithCredentialsCredentialsetsState2CredentialSetsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<Vec<String>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithCredentialsCredentialsetsState2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<crate::WithCredentialsCredentialsetsState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_sets: Option<Vec<WithCredentialsCredentialsetsState2CredentialSetsItem>>,
}

pub type WithDescriptionAdditionalPropertiesProperties = Vec<crate::WithNameKindRole>;

pub type WithDescriptionLdapClaim = Vec<crate::WithLdapClaimLabel2>;

pub type WithDescriptionOkMessage = Vec<crate::WithOwnersNameLocalName>;

pub type WithDescriptionPathLabel = Vec<crate::WithGroupSettingsDescription2>;

pub type WithDetailsTypeLinesNameIdentifier = Vec<sts_model_management_components_3::RfcDocumentResourcePublishedMay>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithDetailsTypeLinesNameIdentifier2 {
    #[serde(rename = "detailsTypeLines", default, skip_serializing_if = "Option::is_none")]
    pub details_type_lines: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(rename = "baseUri", default, skip_serializing_if = "Option::is_none")]
    pub base_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<crate::WithDetailsTypeLinesNameIdentifier>,
    #[serde(rename = "permissionLines", default, skip_serializing_if = "Option::is_none")]
    pub permission_lines: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithDnNameKind {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applications: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callbacks: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member: Option<bool>,
}

pub type WithDnOriginCreatedAt = Vec<crate::WithValueAttributeHolds>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithDnOriginCreatedAt2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "modifiedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub modified_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operational: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<crate::WithDnOriginCreatedAt>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithEntityIdJwksMetadata {
    #[serde(rename = "entityId", default, skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<sts_model_management_components_2::JwkSetMetadataDocumentMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<sts_model_management_components_2::JwkSetMetadataDocumentMetadata>,
    #[serde(rename = "metadataPolicy", default, skip_serializing_if = "Option::is_none")]
    pub metadata_policy: Option<sts_model_management_components_2::JwkSetMetadataDocumentMetadata>,
    #[serde(rename = "metadataPolicyCrit", default, skip_serializing_if = "Option::is_none")]
    pub metadata_policy_crit: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints: Option<sts_model_management_components_2::JwkSetMetadataDocumentMetadata>,
    #[serde(rename = "entityTypes", default, skip_serializing_if = "Option::is_none")]
    pub entity_types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediate: Option<bool>,
    #[serde(rename = "localRealm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub local_realm: Option<Option<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub updated_at: Option<Option<sts_model_base::unions::NumberOrString>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithEntryEntryUriHostNamesEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithEntryEntryUriHostNames {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<WithEntryEntryUriHostNamesEntry>,
    #[serde(rename = "entryUri", default, skip_serializing_if = "Option::is_none")]
    pub entry_uri: Option<String>,
    #[serde(rename = "hostNames", default, skip_serializing_if = "Option::is_none")]
    pub host_names: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithEventReactionDone {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reaction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub done: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<i64>,
    #[serde(rename = "gnapGrants", default, skip_serializing_if = "Option::is_none")]
    pub gnap_grants: Option<i64>,
    #[serde(rename = "oauthGrants", default, skip_serializing_if = "Option::is_none")]
    pub oauth_grants: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codes: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

pub type WithFieldsProfilesPqModes = Vec<crate::WithIdCaProfile>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithFieldsProfilesPqModes2SignatureAlgorithmsItem {
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
pub struct WithFieldsProfilesPqModes2KeyUsageBitsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithFieldsProfilesPqModes2ExtendedKeyUsagesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithFieldsProfilesPqModes2NetscapeTypesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithFieldsProfilesPqModes2DnFieldsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithFieldsProfilesPqModes2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profiles: Option<crate::WithIdLabelClassical>,
    #[serde(rename = "pqModes", default, skip_serializing_if = "Option::is_none")]
    pub pq_modes: Option<crate::WithIdLabelClassical2>,
    #[serde(rename = "pqMode", default, skip_serializing_if = "Option::is_none")]
    pub pq_mode: Option<String>,
    #[serde(rename = "keyAlgorithms", default, skip_serializing_if = "Option::is_none")]
    pub key_algorithms: Option<crate::WithIdLabelKind2>,
    #[serde(rename = "alternativeKeyAlgorithms", default, skip_serializing_if = "Option::is_none")]
    pub alternative_key_algorithms: Option<crate::WithIdLabelKind2>,
    #[serde(rename = "signatureAlgorithms", default, skip_serializing_if = "Option::is_none")]
    pub signature_algorithms: Option<Vec<WithFieldsProfilesPqModes2SignatureAlgorithmsItem>>,
    #[serde(rename = "signerLabel", default, skip_serializing_if = "Option::is_none")]
    pub signer_label: Option<String>,
    #[serde(rename = "keystoreFormats", default, skip_serializing_if = "Option::is_none")]
    pub keystore_formats: Option<Vec<String>>,
    #[serde(rename = "keyUsageBits", default, skip_serializing_if = "Option::is_none")]
    pub key_usage_bits: Option<Vec<WithFieldsProfilesPqModes2KeyUsageBitsItem>>,
    #[serde(rename = "extendedKeyUsages", default, skip_serializing_if = "Option::is_none")]
    pub extended_key_usages: Option<Vec<WithFieldsProfilesPqModes2ExtendedKeyUsagesItem>>,
    #[serde(rename = "netscapeTypes", default, skip_serializing_if = "Option::is_none")]
    pub netscape_types: Option<Vec<WithFieldsProfilesPqModes2NetscapeTypesItem>>,
    #[serde(rename = "accessMethods", default, skip_serializing_if = "Option::is_none")]
    pub access_methods: Option<Vec<String>>,
    #[serde(rename = "dnFields", default, skip_serializing_if = "Option::is_none")]
    pub dn_fields: Option<Vec<WithFieldsProfilesPqModes2DnFieldsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuers: Option<crate::WithIdLabelSubject>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objects: Option<crate::WithFieldsProfilesPqModes>,
    #[serde(rename = "maxObjects", default, skip_serializing_if = "Option::is_none")]
    pub max_objects: Option<i64>,
    #[serde(rename = "slowFamilies", default, skip_serializing_if = "Option::is_none")]
    pub slow_families: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithFingerprint256PemKind {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purposes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "addedBy", default, skip_serializing_if = "Option::is_none")]
    pub added_by: Option<String>,
    #[serde(rename = "addedAt", default, skip_serializing_if = "Option::is_none")]
    pub added_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<f64>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unadmittable: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithFingerprintPemSummaryFingerprints {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithFingerprintPemSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<crate::WithSubjectIssuerSerialHex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprints: Option<WithFingerprintPemSummaryFingerprints>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<crate::WithTbsCertificateSignatureAlgorithmSignatureAlgorithmsAgree>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithFromSharedRegion {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticates: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wraps: Option<String>,
}

pub type WithGroupAuthzenGroupTotal = Vec<crate::WithNameKindDn>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithGroupAuthzenGroupTotal2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(rename = "authzenGroup", default, skip_serializing_if = "Option::is_none")]
    pub authzen_group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unlocated: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holders: Option<crate::WithGroupAuthzenGroupTotal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted: Option<crate::WithGroupAuthzenGroupTotal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<crate::WithGroupAuthzenGroupTotal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<crate::WithGroupAuthzenGroupTotal>,
}

pub type WithGroupSettingsDescription = Vec<crate::WithKeyGroupLabel2>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithGroupSettingsDescription2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<crate::WithGroupSettingsDescription>,
}

pub type WithHasKeyPairKeysDeclaredIssuers = Vec<crate::WithIdLabelKid2>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithHasKeyPairKeysDeclaredIssuers2 {
    #[serde(rename = "hasKeyPair", default, skip_serializing_if = "Option::is_none")]
    pub has_key_pair: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<crate::WithHasKeyPairKeysDeclaredIssuers>,
    #[serde(rename = "declaredIssuers", default, skip_serializing_if = "Option::is_none")]
    pub declared_issuers: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuers: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdActivityGroups {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
    #[serde(rename = "intervalDays", default, skip_serializing_if = "Option::is_none")]
    pub interval_days: Option<f64>,
    #[serde(rename = "maxMails", default, skip_serializing_if = "Option::is_none")]
    pub max_mails: Option<f64>,
    #[serde(rename = "perRun", default, skip_serializing_if = "Option::is_none")]
    pub per_run: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(rename = "startedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub started_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "startedBy", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub started_by: Option<Option<String>>,
    #[serde(rename = "changedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub changed_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "changedBy", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub changed_by: Option<Option<String>>,
    #[serde(rename = "endedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ended_at: Option<Option<sts_model_base::unions::NumberOrString>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdCaProfilePqc {
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
pub struct WithIdCaProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(rename = "profileLabel", default, skip_serializing_if = "Option::is_none")]
    pub profile_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(rename = "issuerSubject", default, skip_serializing_if = "Option::is_none")]
    pub issuer_subject: Option<String>,
    #[serde(rename = "issuerId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub issuer_id: Option<Option<String>>,
    #[serde(rename = "selfSigned", default, skip_serializing_if = "Option::is_none")]
    pub self_signed: Option<bool>,
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
    pub key_alg: Option<String>,
    #[serde(rename = "keyAlgLabel", default, skip_serializing_if = "Option::is_none")]
    pub key_alg_label: Option<String>,
    #[serde(rename = "signatureAlg", default, skip_serializing_if = "Option::is_none")]
    pub signature_alg: Option<String>,
    #[serde(rename = "signatureAlgLabel", default, skip_serializing_if = "Option::is_none")]
    pub signature_alg_label: Option<String>,
    #[serde(rename = "pqMode", default, skip_serializing_if = "Option::is_none")]
    pub pq_mode: Option<String>,
    #[serde(rename = "altKeyAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub alt_key_alg: Option<Option<String>>,
    #[serde(rename = "altSigned", default, skip_serializing_if = "Option::is_none")]
    pub alt_signed: Option<bool>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "hasPrivateKey", default, skip_serializing_if = "Option::is_none")]
    pub has_private_key: Option<bool>,
    #[serde(rename = "hasCsr", default, skip_serializing_if = "Option::is_none")]
    pub has_csr: Option<bool>,
    #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
    pub certificate_pem: Option<String>,
    #[serde(rename = "csrPem", default, skip_serializing_if = "Option::is_none")]
    pub csr_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc: Option<WithIdCaProfilePqc>,
    #[serde(rename = "publicKeyPem", default, skip_serializing_if = "Option::is_none")]
    pub public_key_pem: Option<String>,
    #[serde(rename = "altPublicKeyPem", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub alt_public_key_pem: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdClientIdCommand {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accounts: Option<f64>,
    #[serde(rename = "totalAccounts", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub total_accounts: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resumes: Option<f64>,
    #[serde(rename = "lastEventId", default, skip_serializing_if = "Option::is_none")]
    pub last_event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(rename = "startedAt", default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(rename = "finishedAt", default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdDialectHost {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dialect: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(rename = "passwordProvider", default, skip_serializing_if = "Option::is_none")]
    pub password_provider: Option<String>,
    #[serde(rename = "passwordRef", default, skip_serializing_if = "Option::is_none")]
    pub password_ref: Option<String>,
    #[serde(rename = "passwordField", default, skip_serializing_if = "Option::is_none")]
    pub password_field: Option<String>,
    #[serde(rename = "caFile", default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<String>,
    #[serde(rename = "caCertificates", default, skip_serializing_if = "Option::is_none")]
    pub ca_certificates: Option<String>,
    #[serde(rename = "trustPublicRoots", default, skip_serializing_if = "Option::is_none")]
    pub trust_public_roots: Option<bool>,
    #[serde(rename = "serverName", default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    #[serde(rename = "keyColumn", default, skip_serializing_if = "Option::is_none")]
    pub key_column: Option<String>,
    #[serde(rename = "keyAttribute", default, skip_serializing_if = "Option::is_none")]
    pub key_attribute: Option<String>,
    /// The attribute each column of the operator's table is written onto.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub columns: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh: Option<Vec<String>>,
    #[serde(rename = "scheduleS", default, skip_serializing_if = "Option::is_none")]
    pub schedule_s: Option<f64>,
    #[serde(rename = "timeoutMs", default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<f64>,
    #[serde(rename = "onFailure", default, skip_serializing_if = "Option::is_none")]
    pub on_failure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdDnAttestationTypeSelectorsItem {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdDnAttestationType {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(rename = "attestationType", default, skip_serializing_if = "Option::is_none")]
    pub attestation_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selectors: Option<Vec<WithIdDnAttestationTypeSelectorsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub banned: Option<bool>,
    #[serde(rename = "canReattest", default, skip_serializing_if = "Option::is_none")]
    pub can_reattest: Option<bool>,
    #[serde(rename = "svidHash", default, skip_serializing_if = "Option::is_none")]
    pub svid_hash: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
    #[serde(rename = "firstSeen", default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
    #[serde(rename = "lastSeen", default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestations: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "selectorTexts", default, skip_serializing_if = "Option::is_none")]
    pub selector_texts: Option<Vec<String>>,
}

pub type WithIdDnSpiffeId = Vec<crate::WithTrustDomainTrustDomainIdX509Keys2>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdFamilyKindItemItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<bool>,
}

pub type WithIdFamilyKind = Vec<WithIdFamilyKindItemItem>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdFormatMetaClaimsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdFormatMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<crate::WithVctvaluesDoctypevalueTypevalues>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_cryptographic_holder_binding: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<WithIdFormatMetaClaimsItem>>,
}

pub type WithIdFromTo = Vec<crate::WithIdKindKey2>;

pub type WithIdFromTo2 = serde_json::Map<String, serde_json::Value>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdFromTo3AuthenticationsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub at: Option<Option<f64>>,
    #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_at: Option<Option<f64>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdFromTo3 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(rename = "fromRole", default, skip_serializing_if = "Option::is_none")]
    pub from_role: Option<String>,
    #[serde(rename = "toRole", default, skip_serializing_if = "Option::is_none")]
    pub to_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<Vec<String>>,
    #[serde(rename = "chainKey", default, skip_serializing_if = "Option::is_none")]
    pub chain_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub protocol: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<String>>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub type_: Option<Option<String>>,
    #[serde(rename = "typeLabel", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub type_label: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub spec: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub subject: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub actor: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acts: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<i64>,
    #[serde(rename = "firstAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub first_at: Option<Option<f64>>,
    #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_at: Option<Option<f64>>,
    #[serde(rename = "authorizedBy", default, skip_serializing_if = "Option::is_none")]
    pub authorized_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumed: Option<crate::WithOkMessageErrors63>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub produced: Option<crate::WithOkMessageErrors63>,
    #[serde(rename = "consumedFold", default, skip_serializing_if = "Option::is_none")]
    pub consumed_fold: Option<crate::WithIdFromTo2>,
    #[serde(rename = "producedFold", default, skip_serializing_if = "Option::is_none")]
    pub produced_fold: Option<crate::WithIdFromTo2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mechanism: Option<String>,
    #[serde(rename = "setOn", default, skip_serializing_if = "Option::is_none")]
    pub set_on: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentications: Option<Vec<WithIdFromTo3AuthenticationsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(rename = "audienceRegistered", default, skip_serializing_if = "Option::is_none")]
    pub audience_registered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(rename = "permissionId", default, skip_serializing_if = "Option::is_none")]
    pub permission_id: Option<String>,
    #[serde(rename = "permissionName", default, skip_serializing_if = "Option::is_none")]
    pub permission_name: Option<String>,
    #[serde(rename = "baseUri", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub base_uri: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub description: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdIdentifierDnCertificate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub not_after: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub serial: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdIdentifierDnCounts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrying: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdIdentifierDn {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "baseUrl", default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(rename = "authMethod", default, skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(rename = "tokenEndpoint", default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    #[serde(rename = "oauthClientId", default, skip_serializing_if = "Option::is_none")]
    pub oauth_client_id: Option<String>,
    #[serde(rename = "oauthClientAuth", default, skip_serializing_if = "Option::is_none")]
    pub oauth_client_auth: Option<String>,
    #[serde(rename = "oauthScope", default, skip_serializing_if = "Option::is_none")]
    pub oauth_scope: Option<String>,
    #[serde(rename = "oauthResource", default, skip_serializing_if = "Option::is_none")]
    pub oauth_resource: Option<String>,
    #[serde(rename = "tlsSource", default, skip_serializing_if = "Option::is_none")]
    pub tls_source: Option<String>,
    #[serde(rename = "tlsCertificate", default, skip_serializing_if = "Option::is_none")]
    pub tls_certificate: Option<String>,
    #[serde(rename = "caCertificates", default, skip_serializing_if = "Option::is_none")]
    pub ca_certificates: Option<String>,
    #[serde(rename = "scopeMode", default, skip_serializing_if = "Option::is_none")]
    pub scope_mode: Option<String>,
    #[serde(rename = "scopeFilter", default, skip_serializing_if = "Option::is_none")]
    pub scope_filter: Option<String>,
    #[serde(rename = "groupMode", default, skip_serializing_if = "Option::is_none")]
    pub group_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprovision: Option<String>,
    #[serde(rename = "reconcileMinutes", default, skip_serializing_if = "Option::is_none")]
    pub reconcile_minutes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    #[serde(rename = "maxRequestsPerSecond", default, skip_serializing_if = "Option::is_none")]
    pub max_requests_per_second: Option<String>,
    #[serde(rename = "scopeGroups", default, skip_serializing_if = "Option::is_none")]
    pub scope_groups: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cells: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "passwordSet", default, skip_serializing_if = "Option::is_none")]
    pub password_set: Option<bool>,
    #[serde(rename = "oauthClientSecretSet", default, skip_serializing_if = "Option::is_none")]
    pub oauth_client_secret_set: Option<bool>,
    #[serde(rename = "tlsPrivateKeySet", default, skip_serializing_if = "Option::is_none")]
    pub tls_private_key_set: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<WithIdIdentifierDnCertificate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<WithIdIdentifierDnCounts>,
    #[serde(rename = "pausedUntil", default, skip_serializing_if = "Option::is_none")]
    pub paused_until: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<f64>,
    #[serde(rename = "lastReconcileAt", default, skip_serializing_if = "Option::is_none")]
    pub last_reconcile_at: Option<String>,
    #[serde(rename = "lastReconcile", default, skip_serializing_if = "Option::is_none")]
    pub last_reconcile: Option<sts_model_management_components_1::LastReconcileValue>,
    #[serde(rename = "byCell", default, skip_serializing_if = "Option::is_none")]
    pub by_cell: Option<sts_model_management_components_1::WithAdditionalPropertiesPropertiesSubject>,
}

pub type WithIdKindKey = Vec<crate::WithSeqOriginAt3>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdKindKey2Roles {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediary: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdKindKey2Realm {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
    #[serde(rename = "isDefault", default, skip_serializing_if = "Option::is_none")]
    pub is_default: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdKindKey2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presented: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aliases: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<WithIdKindKey2Roles>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acts: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<i64>,
    #[serde(rename = "firstAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub first_at: Option<Option<f64>>,
    #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_at: Option<Option<f64>>,
    #[serde(rename = "selfTarget", default, skip_serializing_if = "Option::is_none")]
    pub self_target: Option<bool>,
    #[serde(rename = "chiefRole", default, skip_serializing_if = "Option::is_none")]
    pub chief_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<WithIdKindKey2Realm>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flows: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentications: Option<i64>,
    #[serde(rename = "isSubject", default, skip_serializing_if = "Option::is_none")]
    pub is_subject: Option<bool>,
    #[serde(rename = "isClient", default, skip_serializing_if = "Option::is_none")]
    pub is_client: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposes: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dangling: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdLabelCa {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<bool>,
    #[serde(rename = "selfSigned", default, skip_serializing_if = "Option::is_none")]
    pub self_signed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub years: Option<f64>,
    #[serde(rename = "keyUsage", default, skip_serializing_if = "Option::is_none")]
    pub key_usage: Option<Vec<String>>,
    #[serde(rename = "extKeyUsage", default, skip_serializing_if = "Option::is_none")]
    pub ext_key_usage: Option<Vec<String>>,
    #[serde(rename = "pathLen", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub path_len: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub type WithIdLabelClassical = Vec<crate::WithIdLabelCa>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdLabelClassical2ItemItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classical: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub families: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub type WithIdLabelClassical2 = Vec<WithIdLabelClassical2ItemItem>;

pub type WithIdLabelKid = Vec<crate::WithSerialHexRevokedAtReason2>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdLabelKid2Pqc {
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
pub struct WithIdLabelKid2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(rename = "caId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ca_id: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
    pub key_alg: Option<String>,
    #[serde(rename = "jwsAlg", default, skip_serializing_if = "Option::is_none")]
    pub jws_alg: Option<String>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
    pub certificate_pem: Option<String>,
    #[serde(rename = "chainPem", default, skip_serializing_if = "Option::is_none")]
    pub chain_pem: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwk: Option<sts_model_management_components_2::JwkValue>,
    #[serde(rename = "withdrawnAt", default, skip_serializing_if = "Option::is_none")]
    pub withdrawn_at: Option<String>,
    #[serde(rename = "withdrawnReason", default, skip_serializing_if = "Option::is_none")]
    pub withdrawn_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub revoked_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub reason: Option<Option<String>>,
    #[serde(rename = "privateKeyHeld", default, skip_serializing_if = "Option::is_none")]
    pub private_key_held: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc: Option<WithIdLabelKid2Pqc>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdLabelKind2ItemItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signs: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slow: Option<bool>,
    #[serde(rename = "tlsUsable", default, skip_serializing_if = "Option::is_none")]
    pub tls_usable: Option<bool>,
}

pub type WithIdLabelKind2 = Vec<WithIdLabelKind2ItemItem>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdLabelSubjectItemItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
    pub key_alg: Option<String>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(rename = "hasAlternativeKey", default, skip_serializing_if = "Option::is_none")]
    pub has_alternative_key: Option<bool>,
}

pub type WithIdLabelSubject = Vec<WithIdLabelSubjectItemItem>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdNameDoors {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doors: Option<Vec<String>>,
    #[serde(rename = "doorLabels", default, skip_serializing_if = "Option::is_none")]
    pub door_labels: Option<Vec<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<f64>,
    #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    #[serde(rename = "lastUsedAt", default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<f64>,
    #[serde(rename = "lastUsedDoor", default, skip_serializing_if = "Option::is_none")]
    pub last_used_door: Option<String>,
}

pub type WithIdNameType = Vec<crate::WithIdentifierNameOwnsResources>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdNameType2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(rename = "resourceServer", default, skip_serializing_if = "Option::is_none")]
    pub resource_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(rename = "ownerKind", default, skip_serializing_if = "Option::is_none")]
    pub owner_kind: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdNameType3 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "excludeAttributes", default, skip_serializing_if = "Option::is_none")]
    pub exclude_attributes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<sts_model_base::unions::NumberOrString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facility: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "appName", default, skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "rotateBytes", default, skip_serializing_if = "Option::is_none")]
    pub rotate_bytes: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    #[serde(rename = "contentType", default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sourcetype: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ack: Option<Option<sts_model_base::unions::BoolOrNumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<sts_model_base::unions::StringOrObject>,
    #[serde(rename = "headerText", default, skip_serializing_if = "Option::is_none")]
    pub header_text: Option<String>,
    #[serde(rename = "tokenSet", default, skip_serializing_if = "Option::is_none")]
    pub token_set: Option<bool>,
    #[serde(rename = "secretHeaderSet", default, skip_serializing_if = "Option::is_none")]
    pub secret_header_set: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(rename = "queueDepth", default, skip_serializing_if = "Option::is_none")]
    pub queue_depth: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered: Option<f64>,
    #[serde(rename = "failedPermanent", default, skip_serializing_if = "Option::is_none")]
    pub failed_permanent: Option<f64>,
    #[serde(rename = "droppedGap", default, skip_serializing_if = "Option::is_none")]
    pub dropped_gap: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retries: Option<f64>,
    #[serde(rename = "lastSuccessAt", default, skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<f64>,
    #[serde(rename = "lastFailureAt", default, skip_serializing_if = "Option::is_none")]
    pub last_failure_at: Option<f64>,
    #[serde(rename = "lastFailure", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_failure: Option<Option<String>>,
    #[serde(rename = "lastDisposition", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_disposition: Option<Option<String>>,
    #[serde(rename = "pausedUntil", default, skip_serializing_if = "Option::is_none")]
    pub paused_until: Option<f64>,
    #[serde(rename = "failingSince", default, skip_serializing_if = "Option::is_none")]
    pub failing_since: Option<f64>,
    #[serde(rename = "latencyMs", default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    #[serde(rename = "cursorSeq", default, skip_serializing_if = "Option::is_none")]
    pub cursor_seq: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdOwnerOwnerKindPermissionsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_scopes: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdOwnerOwnerKind {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(rename = "ownerKind", default, skip_serializing_if = "Option::is_none")]
    pub owner_kind: Option<String>,
    #[serde(rename = "requestingParty", default, skip_serializing_if = "Option::is_none")]
    pub requesting_party: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub requester: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(rename = "resourceServer", default, skip_serializing_if = "Option::is_none")]
    pub resource_server: Option<String>,
    #[serde(rename = "ticketKey", default, skip_serializing_if = "Option::is_none")]
    pub ticket_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<WithIdOwnerOwnerKindPermissionsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<f64>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<f64>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdProviderTermsDigest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<sts_model_base::unions::NumberOrString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(rename = "termsDigest", default, skip_serializing_if = "Option::is_none")]
    pub terms_digest: Option<String>,
    #[serde(rename = "termsText", default, skip_serializing_if = "Option::is_none")]
    pub terms_text: Option<String>,
    #[serde(rename = "acceptedBy", default, skip_serializing_if = "Option::is_none")]
    pub accepted_by: Option<String>,
    #[serde(rename = "acceptedVia", default, skip_serializing_if = "Option::is_none")]
    pub accepted_via: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment: Option<String>,
    #[serde(rename = "pageDigest", default, skip_serializing_if = "Option::is_none")]
    pub page_digest: Option<String>,
    #[serde(rename = "acceptedAt", default, skip_serializing_if = "Option::is_none")]
    pub accepted_at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdRealmClientId4 {
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
pub struct WithIdRealmClientId5 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub client_id: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub uri: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempts: Option<f64>,
    #[serde(rename = "inFlight", default, skip_serializing_if = "Option::is_none")]
    pub in_flight: Option<sts_model_base::unions::BoolOrNumber>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status: Option<Option<sts_model_base::unions::BoolOrNumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub why: Option<Option<String>>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none")]
    pub queued_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "nextAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "finishedAt", default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "authReqId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub auth_req_id: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub mode: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub username: Option<Option<String>>,
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub session_id: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub iss: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub sub: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub sid: Option<Option<String>>,
    #[serde(rename = "sessionRequired", default, skip_serializing_if = "Option::is_none")]
    pub session_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub via: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub trigger: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub encrypted: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub command: Option<Option<String>>,
    #[serde(rename = "accountState", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub account_state: Option<Option<String>>,
    #[serde(rename = "awaitingCallback", default, skip_serializing_if = "Option::is_none")]
    pub awaiting_callback: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cell: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub op: Option<Option<String>>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<f64>,
    #[serde(rename = "fenceAt", default, skip_serializing_if = "Option::is_none")]
    pub fence_at: Option<f64>,
    #[serde(rename = "tokenDigest", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub token_digest: Option<Option<String>>,
    #[serde(rename = "bodyDigest", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub body_digest: Option<Option<String>>,
    /// What an inter-cell operation carries, which is that operation's own
    /// request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdRealmUsername {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub username: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub to: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub category: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub template: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub lang: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub subject: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub from: Option<Option<String>>,
    #[serde(rename = "messageId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub message_id: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub via: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub actor: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub transport: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempts: Option<f64>,
    #[serde(rename = "inFlight", default, skip_serializing_if = "Option::is_none")]
    pub in_flight: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub why: Option<Option<String>>,
    #[serde(rename = "providerId", default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(rename = "bodyKept", default, skip_serializing_if = "Option::is_none")]
    pub body_kept: Option<bool>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none")]
    pub queued_at: Option<String>,
    #[serde(rename = "nextAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<String>,
    #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    #[serde(rename = "finishedAt", default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub text: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub html: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdRecordedSource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub recorded: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<sts_model_management_components_2::OpenIdConnectIdentityAssuranceVerification>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<crate::VerifiedClaimsValuesOpenIdConnect>,
}

pub type WithIdResourceIdScopes = Vec<crate::WithIdStateOwner2>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdResourceIdScopes2Recipient {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdResourceIdScopes2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "resourceId", default, skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<WithIdResourceIdScopes2Recipient>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(rename = "askMe", default, skip_serializing_if = "Option::is_none")]
    pub ask_me: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdStateAuthorizationServerFinalization {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub note: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdStateAuthorizationServerHistoryItem {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub note: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdStateAuthorizationServer {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(rename = "authorizationServer", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub authorization_server: Option<Option<String>>,
    #[serde(rename = "grantEndpoint", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub grant_endpoint: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub client: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub proof: Option<Option<String>>,
    #[serde(rename = "resourceOwner", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub resource_owner: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub decision: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interaction: Option<sts_model_management_components_2::InteractionValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<i64>,
    #[serde(rename = "derivedFrom", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub derived_from: Option<Option<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub updated_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finalization: Option<WithIdStateAuthorizationServerFinalization>,
    #[serde(rename = "grantExpiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub grant_expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<Vec<WithIdStateAuthorizationServerHistoryItem>>,
}

pub type WithIdStateOwner = Vec<crate::WithIdNameType2>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdStateOwner2PermissionsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdStateOwner2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(rename = "ownerKind", default, skip_serializing_if = "Option::is_none")]
    pub owner_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub requester: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(rename = "resourceServer", default, skip_serializing_if = "Option::is_none")]
    pub resource_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<WithIdStateOwner2PermissionsItem>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<f64>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdStatusEntryEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdStatusEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<WithIdStatusEntryEntry>,
    #[serde(rename = "entryUri", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub entry_uri: Option<Option<String>>,
    #[serde(rename = "eabKid", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub eab_kid: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orders: Option<i64>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "deactivatedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub deactivated_at: Option<Option<sts_model_base::unions::NumberOrString>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdStatusRequesterClient {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdStatusRequesterApproval {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "approvedAt", default, skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<f64>,
    #[serde(rename = "approvedUntil", default, skip_serializing_if = "Option::is_none")]
    pub approved_until: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdStatusRequesterApprovers {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owners: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdStatusRequester {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<WithIdStatusRequesterClient>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub application: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<sts_model_management_components_1::AuthZenCallerSentDenialBound>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<sts_model_management_components_1::AuthZenCallerSentDenialBound>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<sts_model_management_components_1::AuthZenCallerSentDenialBound>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<sts_model_management_components_2::MembersCallerSAuthZenContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emergency: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<f64>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
    #[serde(rename = "finishedAt", default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<f64>,
    #[serde(rename = "decidedBy", default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<WithIdStatusRequesterApproval>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approvers: Option<WithIdStatusRequesterApprovers>,
}

pub type WithIdTitleModule = Vec<crate::WithThreadIdSlotReady>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdTitleModule2Restarts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forked: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaced: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crashed: Option<f64>,
    #[serde(rename = "failedStarts", default, skip_serializing_if = "Option::is_none")]
    pub failed_starts: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stopped: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdTitleModule2ResponseTime {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answered: Option<f64>,
    #[serde(rename = "averageMs", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub average_ms: Option<Option<f64>>,
    #[serde(rename = "recentAverageMs", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub recent_average_ms: Option<Option<f64>>,
    #[serde(rename = "maxMs", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub max_ms: Option<Option<f64>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdTitleModule2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(rename = "stateText", default, skip_serializing_if = "Option::is_none")]
    pub state_text: Option<String>,
    #[serde(rename = "maxWorkers", default, skip_serializing_if = "Option::is_none")]
    pub max_workers: Option<f64>,
    #[serde(rename = "initialWorkers", default, skip_serializing_if = "Option::is_none")]
    pub initial_workers: Option<f64>,
    #[serde(rename = "currentWorkers", default, skip_serializing_if = "Option::is_none")]
    pub current_workers: Option<f64>,
    #[serde(rename = "readyWorkers", default, skip_serializing_if = "Option::is_none")]
    pub ready_workers: Option<f64>,
    #[serde(rename = "startingWorkers", default, skip_serializing_if = "Option::is_none")]
    pub starting_workers: Option<f64>,
    #[serde(rename = "busyWorkers", default, skip_serializing_if = "Option::is_none")]
    pub busy_workers: Option<f64>,
    #[serde(rename = "freeWorkers", default, skip_serializing_if = "Option::is_none")]
    pub free_workers: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restarts: Option<WithIdTitleModule2Restarts>,
    #[serde(rename = "responseTime", default, skip_serializing_if = "Option::is_none")]
    pub response_time: Option<WithIdTitleModule2ResponseTime>,
    #[serde(rename = "startedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub started_at: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefixes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workers: Option<crate::WithIdTitleModule>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdWhatOk {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(rename = "tookMs", default, skip_serializing_if = "Option::is_none")]
    pub took_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<sts_model_management_components_3::SecretStoreSOwnApi>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdentifierNameOwnsResources {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "ownsResources", default, skip_serializing_if = "Option::is_none")]
    pub owns_resources: Option<bool>,
    #[serde(rename = "protectionGranted", default, skip_serializing_if = "Option::is_none")]
    pub protection_granted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpts: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tickets: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIndexIdOk {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signalled: Option<bool>,
}

pub type WithIsolatesCollectedFailed = Vec<crate::WithKindPidThreadId>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIsolatesCollectedFailed2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isolates: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collected: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unanswered: Option<i64>,
    #[serde(rename = "freedBytes", default, skip_serializing_if = "Option::is_none")]
    pub freed_bytes: Option<f64>,
    #[serde(rename = "longestPauseMs", default, skip_serializing_if = "Option::is_none")]
    pub longest_pause_ms: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithIssuerMatchedAuthorizationServerIssuer {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIssuerMatchedAuthorizationServer {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub issuer: Option<Option<WithIssuerMatchedAuthorizationServerIssuer>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<bool>,
    #[serde(rename = "authorizationServer", default, skip_serializing_if = "Option::is_none")]
    pub authorization_server: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithKeyAttributeLabelDefault {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithKeyAttributeLabelValue {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithKeyAttributeLabel {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub empty: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default: Option<Option<WithKeyAttributeLabelDefault>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<WithKeyAttributeLabelValue>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub source: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mechanism: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
    #[serde(rename = "disabledWhy", default, skip_serializing_if = "Option::is_none")]
    pub disabled_why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithKeyGroupLabel2Value {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithKeyGroupLabel2Default {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithKeyGroupLabel2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(rename = "enumValues", default, skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
    #[serde(rename = "csvValues", default, skip_serializing_if = "Option::is_none")]
    pub csv_values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordered: Option<bool>,
    /// The sentence beside each of a list's values.
    #[serde(rename = "csvValueNotes", default, skip_serializing_if = "Option::is_none")]
    pub csv_value_notes: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "selectAll", default, skip_serializing_if = "Option::is_none")]
    pub select_all: Option<sts_model_management_components_3::WithOnlyWhileOnAloneWhileOnKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<WithKeyGroupLabel2Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<bool>,
    #[serde(rename = "restartReason", default, skip_serializing_if = "Option::is_none")]
    pub restart_reason: Option<String>,
    #[serde(rename = "editRefusal", default, skip_serializing_if = "Option::is_none")]
    pub edit_refusal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub env: Option<Option<String>>,
    #[serde(rename = "legacyEnv", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub legacy_env: Option<Option<String>>,
    #[serde(rename = "appconfigPath", default, skip_serializing_if = "Option::is_none")]
    pub appconfig_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default: Option<Option<WithKeyGroupLabel2Default>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithKeyLabelDecides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decides: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(rename = "builtIn", default, skip_serializing_if = "Option::is_none")]
    pub built_in: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub enabled: Option<Option<bool>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<String>,
    #[serde(rename = "readsRisk", default, skip_serializing_if = "Option::is_none")]
    pub reads_risk: Option<bool>,
}

pub type WithKeyNamesLabel = serde_json::Map<String, serde_json::Value>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithKeyNamesLabel2ItemItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<Option<String>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
}

pub type WithKeyNamesLabel2 = Vec<WithKeyNamesLabel2ItemItem>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithKeyObjectProperty {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub property: Option<String>,
    #[serde(rename = "attributeId", default, skip_serializing_if = "Option::is_none")]
    pub attribute_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(rename = "dataType", default, skip_serializing_if = "Option::is_none")]
    pub data_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multiplicity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithKindCountIdentifiers {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifiers: Option<Vec<String>>,
    #[serde(rename = "moreIdentifiers", default, skip_serializing_if = "Option::is_none")]
    pub more_identifiers: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithKindPidThreadId {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<i64>,
    #[serde(rename = "threadId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub thread_id: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(rename = "heapUsedBeforeBytes", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub heap_used_before_bytes: Option<Option<f64>>,
    #[serde(rename = "heapTotalBeforeBytes", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub heap_total_before_bytes: Option<Option<f64>>,
    #[serde(rename = "heapUsedAfterBytes", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub heap_used_after_bytes: Option<Option<f64>>,
    #[serde(rename = "heapTotalAfterBytes", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub heap_total_after_bytes: Option<Option<f64>>,
    #[serde(rename = "freedBytes", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub freed_bytes: Option<Option<f64>>,
    #[serde(rename = "durationMs", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub duration_ms: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error: Option<Option<String>>,
}

pub type WithKindTypeLexical = Vec<crate::WithKeyLabelDecides>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithKindTypeLexical2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lexical: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespaces: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "xpathCategory", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub xpath_category: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub category: Option<Option<String>>,
    #[serde(rename = "attributeId", default, skip_serializing_if = "Option::is_none")]
    pub attribute_id: Option<String>,
    #[serde(rename = "dataType", default, skip_serializing_if = "Option::is_none")]
    pub data_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub issuer: Option<Option<String>>,
    #[serde(rename = "mustBePresent", default, skip_serializing_if = "Option::is_none")]
    pub must_be_present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(rename = "contextSelectorId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub context_selector_id: Option<Option<String>>,
    #[serde(rename = "functionId", default, skip_serializing_if = "Option::is_none")]
    pub function_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub description: Option<Option<String>>,
    #[serde(rename = "variableId", default, skip_serializing_if = "Option::is_none")]
    pub variable_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithLabelEncryptionsDecryptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryptions: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decryptions: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<i64>,
    #[serde(rename = "plaintextBytes", default, skip_serializing_if = "Option::is_none")]
    pub plaintext_bytes: Option<f64>,
    #[serde(rename = "ciphertextBytes", default, skip_serializing_if = "Option::is_none")]
    pub ciphertext_bytes: Option<f64>,
    /// Milliseconds, 0 when never.
    #[serde(rename = "firstAt", default, skip_serializing_if = "Option::is_none")]
    pub first_at: Option<f64>,
    /// Milliseconds, 0 when never.
    #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none")]
    pub last_at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithLateFailedUndeliveredUndeliveredItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithLateFailedUndelivered {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub late: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undelivered: Option<Vec<WithLateFailedUndeliveredUndeliveredItem>>,
    #[serde(rename = "boundSeconds", default, skip_serializing_if = "Option::is_none")]
    pub bound_seconds: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithLdapClaimLabel2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldap: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub label: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub schema: Option<Option<String>>,
    /// Whether it is ticked, by claim set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sets: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub syntax: Option<Option<String>>,
    #[serde(rename = "pacClaimId", default, skip_serializing_if = "Option::is_none")]
    pub pac_claim_id: Option<String>,
}

pub type WithLdapClaimValue = Vec<sts_model_management_components_1::ClaimValueWouldIssued>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithLdapClaimValue2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldap: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<sts_model_management_components_1::ClaimValueWouldIssued>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "ldpTerm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ldp_term: Option<Option<String>>,
    #[serde(rename = "claimId", default, skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<crate::WithLdapClaimValue>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithLinkeddidsOkMessageContext {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithLinkeddidsOkMessage {
    #[serde(rename = "@context", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub context: Option<Option<WithLinkeddidsOkMessageContext>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_dids: Option<Vec<String>>,
}

pub type WithListedMatchedAllMatched = Vec<crate::WithIssuerMatchedAuthorizationServer>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithListedMatchedAllMatched2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listed: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<i64>,
    #[serde(rename = "allMatched", default, skip_serializing_if = "Option::is_none")]
    pub all_matched: Option<bool>,
    #[serde(rename = "anyUnmatched", default, skip_serializing_if = "Option::is_none")]
    pub any_unmatched: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<crate::WithListedMatchedAllMatched>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<sts_model_management_components_3::RfcDocumentResourcePublishedMay>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithMemberValueKnown {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<sts_model_management_components_3::RfcDocumentResourcePublishedMay>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known: Option<bool>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maps: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub problem: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithMinVersionTls12Tls13SuitesTls13SuitesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithMinVersionTls12Tls13Suites {
    #[serde(rename = "minVersion", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub min_version: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls12: Option<bool>,
    #[serde(rename = "tls13Suites", default, skip_serializing_if = "Option::is_none")]
    pub tls13_suites: Option<Vec<WithMinVersionTls12Tls13SuitesTls13SuitesItem>>,
    #[serde(rename = "tls12Ciphers", default, skip_serializing_if = "Option::is_none")]
    pub tls12_ciphers: Option<Vec<String>>,
    #[serde(rename = "pqcOnly", default, skip_serializing_if = "Option::is_none")]
    pub pqc_only: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<String>,
    #[serde(rename = "signatureAlgorithms", default, skip_serializing_if = "Option::is_none")]
    pub signature_algorithms: Option<String>,
    #[serde(rename = "sessionTimeoutS", default, skip_serializing_if = "Option::is_none")]
    pub session_timeout_s: Option<f64>,
    #[serde(rename = "sessionCacheSize", default, skip_serializing_if = "Option::is_none")]
    pub session_cache_size: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truststore: Option<String>,
    #[serde(rename = "clientAuth", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub client_auth: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithNameCoseAlgOffered {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "coseAlg", default, skip_serializing_if = "Option::is_none")]
    pub cose_alg: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offered: Option<bool>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insecure: Option<bool>,
    #[serde(rename = "notOfferedBecause", default, skip_serializing_if = "Option::is_none")]
    pub not_offered_because: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithNameDnDescription {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedence: Option<i64>,
    #[serde(rename = "selectApplications", default, skip_serializing_if = "Option::is_none")]
    pub select_applications: Option<Vec<String>>,
    #[serde(rename = "selectGroups", default, skip_serializing_if = "Option::is_none")]
    pub select_groups: Option<Vec<String>>,
    #[serde(rename = "namedBy", default, skip_serializing_if = "Option::is_none")]
    pub named_by: Option<crate::WithApplicationsGroupsPeople>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<crate::WithContainerDefinitionContainerObjectClasses>,
    #[serde(rename = "registrationAlgorithms", default, skip_serializing_if = "Option::is_none")]
    pub registration_algorithms: Option<Vec<String>>,
    #[serde(rename = "registrationMode", default, skip_serializing_if = "Option::is_none")]
    pub registration_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mechanisms: Option<Vec<String>>,
    #[serde(rename = "secondFactors", default, skip_serializing_if = "Option::is_none")]
    pub second_factors: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithNameKindDn {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scoped: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithNameKindRole {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standard: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitive: Option<bool>,
    #[serde(rename = "enum", default, skip_serializing_if = "Option::is_none")]
    pub enum_: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<sts_model_base::unions::BoolOrString>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithNameMethodsUrlMethods {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithNameMethodsUrl {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<WithNameMethodsUrlMethods>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listening: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithNamePostQuantumRequiredPrecedence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "postQuantumRequired", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum_required: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedence: Option<f64>,
    #[serde(rename = "selectGroups", default, skip_serializing_if = "Option::is_none")]
    pub select_groups: Option<Vec<String>>,
    #[serde(rename = "namedByApplications", default, skip_serializing_if = "Option::is_none")]
    pub named_by_applications: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithNamePrecedenceStoredMinLength {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithNamePrecedenceStoredHistory {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithNamePrecedenceStoredMinSymbols {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithNamePrecedenceStoredRequireUppercase {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithNamePrecedenceStoredRequireDigit {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithNamePrecedenceStoredGeneratedLength {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithNamePrecedenceStoredHashAlgorithm {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithNamePrecedenceStoredArgon2Memory {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithNamePrecedenceStoredArgon2Iterations {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithNamePrecedenceStoredArgon2Parallelism {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithNamePrecedenceStoredScryptLogN {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithNamePrecedenceStoredScryptBlockSize {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithNamePrecedenceStoredScryptParallelism {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithNamePrecedenceStored {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedence: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherited: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sources: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforced: Option<bool>,
    #[serde(rename = "minLength", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub min_length: Option<Option<WithNamePrecedenceStoredMinLength>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub history: Option<Option<WithNamePrecedenceStoredHistory>>,
    #[serde(rename = "minSymbols", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub min_symbols: Option<Option<WithNamePrecedenceStoredMinSymbols>>,
    #[serde(rename = "requireUppercase", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub require_uppercase: Option<Option<WithNamePrecedenceStoredRequireUppercase>>,
    #[serde(rename = "requireDigit", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub require_digit: Option<Option<WithNamePrecedenceStoredRequireDigit>>,
    #[serde(rename = "generatedLength", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub generated_length: Option<Option<WithNamePrecedenceStoredGeneratedLength>>,
    #[serde(rename = "hashAlgorithm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub hash_algorithm: Option<Option<WithNamePrecedenceStoredHashAlgorithm>>,
    #[serde(rename = "argon2Memory", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub argon2_memory: Option<Option<WithNamePrecedenceStoredArgon2Memory>>,
    #[serde(rename = "argon2Iterations", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub argon2_iterations: Option<Option<WithNamePrecedenceStoredArgon2Iterations>>,
    #[serde(rename = "argon2Parallelism", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub argon2_parallelism: Option<Option<WithNamePrecedenceStoredArgon2Parallelism>>,
    #[serde(rename = "scryptLogN", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub scrypt_log_n: Option<Option<WithNamePrecedenceStoredScryptLogN>>,
    #[serde(rename = "scryptBlockSize", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub scrypt_block_size: Option<Option<WithNamePrecedenceStoredScryptBlockSize>>,
    #[serde(rename = "scryptParallelism", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub scrypt_parallelism: Option<Option<WithNamePrecedenceStoredScryptParallelism>>,
}

pub type WithNamePrecedenceStored2 = Vec<crate::WithNameDnDescription>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithNamePrecedenceStored6DefaultLocale {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithNamePrecedenceStored6PopulatePreferredLanguage {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithNamePrecedenceStored6 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedence: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherited: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sources: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforced: Option<bool>,
    #[serde(rename = "defaultLocale", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default_locale: Option<Option<WithNamePrecedenceStored6DefaultLocale>>,
    #[serde(rename = "populatePreferredLanguage", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub populate_preferred_language: Option<Option<WithNamePrecedenceStored6PopulatePreferredLanguage>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithNamePrecedenceStored7RequiredAttributes {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithNamePrecedenceStored7 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedence: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherited: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sources: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforced: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,
    #[serde(rename = "requiredAttributes", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub required_attributes: Option<Option<WithNamePrecedenceStored7RequiredAttributes>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithNameTitleDescription {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persisted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,
    #[serde(rename = "largestRealm", default, skip_serializing_if = "Option::is_none")]
    pub largest_realm: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<i64>,
    #[serde(rename = "maxEntries", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub max_entries: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound: Option<String>,
    #[serde(rename = "atBound", default, skip_serializing_if = "Option::is_none")]
    pub at_bound: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifetime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counted: Option<bool>,
    #[serde(rename = "notCountedWhy", default, skip_serializing_if = "Option::is_none")]
    pub not_counted_why: Option<String>,
    #[serde(rename = "hitMeaning", default, skip_serializing_if = "Option::is_none")]
    pub hit_meaning: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub hits: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub misses: Option<Option<i64>>,
    #[serde(rename = "hitRatio", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub hit_ratio: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evictions: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusals: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub problem: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithNameValueAttribute {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multi: Option<bool>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(rename = "nameFormat", default, skip_serializing_if = "Option::is_none")]
    pub name_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(rename = "claimId", default, skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithNameValueNameFormatValue {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithNameValueNameFormat {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<WithNameValueNameFormatValue>>,
    #[serde(rename = "nameFormat", default, skip_serializing_if = "Option::is_none")]
    pub name_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multi: Option<bool>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithNotBeforeNotAfterAdditionalPropertiesNotBefore {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iso: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithNotBeforeNotAfterAdditionalPropertiesNotAfter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iso: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithNotBeforeNotAfterAdditionalProperties {
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<WithNotBeforeNotAfterAdditionalPropertiesNotBefore>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<WithNotBeforeNotAfterAdditionalPropertiesNotAfter>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOfferedDigitsSecretBitsAlgorithmsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "inUse", default, skip_serializing_if = "Option::is_none")]
    pub in_use: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOfferedDigitsSecretBits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digits: Option<f64>,
    #[serde(rename = "secretBits", default, skip_serializing_if = "Option::is_none")]
    pub secret_bits: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithms: Option<Vec<WithOfferedDigitsSecretBitsAlgorithmsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOfferedRpNameRpIdLanesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lane: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithms: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOfferedRpNameRpIdCurvesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "coseCurve", default, skip_serializing_if = "Option::is_none")]
    pub cose_curve: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOfferedRpNameRpId {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offered: Option<bool>,
    #[serde(rename = "rpName", default, skip_serializing_if = "Option::is_none")]
    pub rp_name: Option<String>,
    #[serde(rename = "rpId", default, skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(rename = "rpIdSource", default, skip_serializing_if = "Option::is_none")]
    pub rp_id_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithms: Option<crate::WithUrlRowsSerial>,
    #[serde(rename = "algorithmsSource", default, skip_serializing_if = "Option::is_none")]
    pub algorithms_source: Option<String>,
    #[serde(rename = "registrationMode", default, skip_serializing_if = "Option::is_none")]
    pub registration_mode: Option<String>,
    #[serde(rename = "insecureAlgorithms", default, skip_serializing_if = "Option::is_none")]
    pub insecure_algorithms: Option<bool>,
    #[serde(rename = "pqcOnly", default, skip_serializing_if = "Option::is_none")]
    pub pqc_only: Option<bool>,
    #[serde(rename = "pqcAlongsideClassical", default, skip_serializing_if = "Option::is_none")]
    pub pqc_alongside_classical: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lanes: Option<Vec<WithOfferedRpNameRpIdLanesItem>>,
    #[serde(rename = "upgradeMode", default, skip_serializing_if = "Option::is_none")]
    pub upgrade_mode: Option<String>,
    #[serde(rename = "upgradeAlgorithms", default, skip_serializing_if = "Option::is_none")]
    pub upgrade_algorithms: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub curves: Option<Vec<WithOfferedRpNameRpIdCurvesItem>>,
    #[serde(rename = "userVerification", default, skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,
    #[serde(rename = "userVerificationEnforced", default, skip_serializing_if = "Option::is_none")]
    pub user_verification_enforced: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
    #[serde(rename = "attestationPolicy", default, skip_serializing_if = "Option::is_none")]
    pub attestation_policy: Option<String>,
    #[serde(rename = "attestationPolicyConfigured", default, skip_serializing_if = "Option::is_none")]
    pub attestation_policy_configured: Option<String>,
    #[serde(rename = "attestationVerified", default, skip_serializing_if = "Option::is_none")]
    pub attestation_verified: Option<bool>,
    #[serde(rename = "attestationDemandsTrust", default, skip_serializing_if = "Option::is_none")]
    pub attestation_demands_trust: Option<bool>,
    #[serde(rename = "attestationFormats", default, skip_serializing_if = "Option::is_none")]
    pub attestation_formats: Option<Vec<String>>,
    #[serde(rename = "attestationAllowedAaguids", default, skip_serializing_if = "Option::is_none")]
    pub attestation_allowed_aaguids: Option<Vec<String>>,
    #[serde(rename = "attestationMinCertificationLevel", default, skip_serializing_if = "Option::is_none")]
    pub attestation_min_certification_level: Option<String>,
    #[serde(rename = "attestationRequireFips", default, skip_serializing_if = "Option::is_none")]
    pub attestation_require_fips: Option<bool>,
    #[serde(rename = "attestationAllowSafetynet", default, skip_serializing_if = "Option::is_none")]
    pub attestation_allow_safetynet: Option<bool>,
    #[serde(rename = "attestationAndroidSoftwareKeys", default, skip_serializing_if = "Option::is_none")]
    pub attestation_android_software_keys: Option<bool>,
    #[serde(rename = "attestationTrustAnchors", default, skip_serializing_if = "Option::is_none")]
    pub attestation_trust_anchors: Option<f64>,
    #[serde(rename = "timeoutMs", default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<f64>,
    #[serde(rename = "authenticatorAttachment", default, skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<String>,
    #[serde(rename = "residentKey", default, skip_serializing_if = "Option::is_none")]
    pub resident_key: Option<String>,
    #[serde(rename = "credProps", default, skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<bool>,
    #[serde(rename = "primaryAllowed", default, skip_serializing_if = "Option::is_none")]
    pub primary_allowed: Option<bool>,
    #[serde(rename = "mfaAllowed", default, skip_serializing_if = "Option::is_none")]
    pub mfa_allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usernameless: Option<bool>,
    #[serde(rename = "maxKeysPerPerson", default, skip_serializing_if = "Option::is_none")]
    pub max_keys_per_person: Option<f64>,
    #[serde(rename = "signatureCounter", default, skip_serializing_if = "Option::is_none")]
    pub signature_counter: Option<String>,
    #[serde(rename = "clientDataHash", default, skip_serializing_if = "Option::is_none")]
    pub client_data_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mds: Option<crate::WithUrlRowsSerial2>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOidNameLabel {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub critical: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<crate::X>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub text: Option<Option<String>>,
    #[serde(rename = "parseError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub parse_error: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkDeliveredHeld {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<bool>,
    #[serde(rename = "deadLettered", default, skip_serializing_if = "Option::is_none")]
    pub dead_lettered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<sts_model_management_components_3::SecurityEventTokenSClaims>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub err: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub why: Option<Option<String>>,
}

pub type WithOkKeyScope = Vec<crate::WithRelationshipLabelProtocol>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkKeyScope2NotificationsItem {
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(rename = "sessionRequired", default, skip_serializing_if = "Option::is_none")]
    pub session_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkKeyScope2CleanupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wreply: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkKeyScope2LogoutRequestsItem {
    #[serde(rename = "entityId", default, skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkKeyScope2AcrossClusterItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkKeyScope2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminated: Option<crate::WithIdFamilyKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<crate::WithIdFamilyKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unknown: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notifications: Option<Vec<WithOkKeyScope2NotificationsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanups: Option<Vec<WithOkKeyScope2CleanupsItem>>,
    #[serde(rename = "logoutRequests", default, skip_serializing_if = "Option::is_none")]
    pub logout_requests: Option<Vec<WithOkKeyScope2LogoutRequestsItem>>,
    #[serde(rename = "partnerLogouts", default, skip_serializing_if = "Option::is_none")]
    pub partner_logouts: Option<crate::WithOkKeyScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backchannel: Option<sts_model_management_components_2::WithAdditionalPropertiesPropertiesEnded>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(rename = "acrossCluster", default, skip_serializing_if = "Option::is_none")]
    pub across_cluster: Option<Vec<WithOkKeyScope2AcrossClusterItem>>,
}

pub type WithOkKindHolder = Vec<crate::WithSerialHexLabelSubject>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkKindHolder2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(rename = "implicitName", default, skip_serializing_if = "Option::is_none")]
    pub implicit_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<crate::WithOkKindHolder>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(rename = "keyAlgorithms", default, skip_serializing_if = "Option::is_none")]
    pub key_algorithms: Option<Vec<String>>,
    #[serde(rename = "defaultKeyAlg", default, skip_serializing_if = "Option::is_none")]
    pub default_key_alg: Option<String>,
    #[serde(rename = "revocationReasons", default, skip_serializing_if = "Option::is_none")]
    pub revocation_reasons: Option<Vec<String>>,
    #[serde(rename = "passwordMin", default, skip_serializing_if = "Option::is_none")]
    pub password_min: Option<f64>,
    #[serde(rename = "caAvailable", default, skip_serializing_if = "Option::is_none")]
    pub ca_available: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkLoadedExamined {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loaded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub examined: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<sts_model_base::unions::BoolOrString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors10 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<sts_model_management_components_2::DeviceView>,
    /// The key's id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(rename = "sessionsEnded", default, skip_serializing_if = "Option::is_none")]
    pub sessions_ended: Option<f64>,
    #[serde(rename = "certificatesRevoked", default, skip_serializing_if = "Option::is_none")]
    pub certificates_revoked: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithOkMessageErrors100Changed {
    V1(Vec<String>),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors100 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<sts_model_management_components_1::ApplicationValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<WithOkMessageErrors100Changed>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<crate::WithSerialHexLabelSubject2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<sts_model_management_components_2::EntryValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    /// True when the certificate was already revoked. The earlier entry is kept
    /// and its date does not move.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub already: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithOkMessageErrors101Changed {
    V1(Vec<String>),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors101 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<sts_model_management_components_1::ApplicationValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<WithOkMessageErrors101Changed>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub dn: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<crate::WithSubjectLabelEnrolledAt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithOkMessageErrors102Changed {
    V1(Vec<String>),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors102 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<sts_model_management_components_1::ApplicationValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<WithOkMessageErrors102Changed>,
    #[serde(rename = "softwareStatement", default, skip_serializing_if = "Option::is_none")]
    pub software_statement: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<sts_model_management_components_3::SoftwareStatementSClaimsRfc>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithOkMessageErrors103Changed {
    V1(Vec<String>),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithOkMessageErrors103AssertionConsumerServicesItem {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithOkMessageErrors103SingleLogoutServicesItem {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors103 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<sts_model_management_components_1::ApplicationValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<WithOkMessageErrors103Changed>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub how: Option<String>,
    #[serde(rename = "entityId", default, skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(rename = "certificateUse", default, skip_serializing_if = "Option::is_none")]
    pub certificate_use: Option<String>,
    #[serde(rename = "signingCertificates", default, skip_serializing_if = "Option::is_none")]
    pub signing_certificates: Option<i64>,
    #[serde(rename = "assertionConsumerServices", default, skip_serializing_if = "Option::is_none")]
    pub assertion_consumer_services: Option<Vec<Option<WithOkMessageErrors103AssertionConsumerServicesItem>>>,
    #[serde(rename = "singleLogoutServices", default, skip_serializing_if = "Option::is_none")]
    pub single_logout_services: Option<Vec<Option<WithOkMessageErrors103SingleLogoutServicesItem>>>,
    #[serde(rename = "nameIdFormats", default, skip_serializing_if = "Option::is_none")]
    pub name_id_formats: Option<Vec<String>>,
    #[serde(rename = "authnRequestsSigned", default, skip_serializing_if = "Option::is_none")]
    pub authn_requests_signed: Option<bool>,
    #[serde(rename = "wantAssertionsSigned", default, skip_serializing_if = "Option::is_none")]
    pub want_assertions_signed: Option<bool>,
    #[serde(rename = "validUntil", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub valid_until: Option<Option<String>>,
    #[serde(rename = "cacheDuration", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cache_duration: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithOkMessageErrors104Changed {
    V1(Vec<String>),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors104 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<sts_model_management_components_1::ApplicationValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<WithOkMessageErrors104Changed>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(rename = "contentType", default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document: Option<sts_model_management_components_3::RfcDocumentResourcePublishedMay>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pretty: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<crate::WithCheckedMatchesExpected>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<String>>,
    #[serde(rename = "signedMetadata", default, skip_serializing_if = "Option::is_none")]
    pub signed_metadata: Option<sts_model_management_components_3::RfcDocumentResourcePublishedMay>,
    #[serde(rename = "resourceCheck", default, skip_serializing_if = "Option::is_none")]
    pub resource_check: Option<crate::WithCheckedMatchesExpected2>,
    #[serde(rename = "authorizationServers", default, skip_serializing_if = "Option::is_none")]
    pub authorization_servers: Option<crate::WithListedMatchedAllMatched2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<crate::WithDetailsTypeLinesNameIdentifier2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithOkMessageErrors105Changed {
    V1(Vec<String>),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors105FilesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base64: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors105 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<sts_model_management_components_1::ApplicationValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<WithOkMessageErrors105Changed>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<String>>,
    #[serde(rename = "leftOut", default, skip_serializing_if = "Option::is_none")]
    pub left_out: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldif: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<Vec<WithOkMessageErrors105FilesItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors106 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<crate::WithIdStateAuthorizationServer>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors107 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub problems: Option<Option<Vec<serde_json::Value>>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors108 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub problems: Option<Option<Vec<serde_json::Value>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pep: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(rename = "dnsNames", default, skip_serializing_if = "Option::is_none")]
    pub dns_names: Option<Vec<String>>,
    #[serde(rename = "ipAddresses", default, skip_serializing_if = "Option::is_none")]
    pub ip_addresses: Option<Vec<String>>,
    #[serde(rename = "replacedSerialHex", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub replaced_serial_hex: Option<Option<String>>,
    #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
    pub certificate_pem: Option<String>,
    #[serde(rename = "chainPem", default, skip_serializing_if = "Option::is_none")]
    pub chain_pem: Option<Vec<String>>,
    #[serde(rename = "fullChainPem", default, skip_serializing_if = "Option::is_none")]
    pub full_chain_pem: Option<String>,
    #[serde(rename = "anchorPem", default, skip_serializing_if = "Option::is_none")]
    pub anchor_pem: Option<String>,
    #[serde(rename = "privateKeyPem", default, skip_serializing_if = "Option::is_none")]
    pub private_key_pem: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors109 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<sts_model_management_components_3::ReportValue>,
}

pub type WithOkMessageErrors11 = Vec<crate::WithIndexIdOk>;

pub type WithOkMessageErrors110 = Vec<crate::WithOkDeliveredHeld>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors111 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reports: Option<crate::WithOkMessageErrors110>,
}

pub type WithOkMessageErrors112 = Vec<crate::WithFingerprint256PemKind>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors113RefusedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors113 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added: Option<crate::WithOkMessageErrors112>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duplicates: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<Vec<WithOkMessageErrors113RefusedItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors114 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pins: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truststore: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changes: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors115 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<sts_model_management_components_1::ChainValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workbench: Option<crate::WithFieldsProfilesPqModes2>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors116 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared: Option<bool>,
    #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
    pub certificate_pem: Option<String>,
    #[serde(rename = "chainPem", default, skip_serializing_if = "Option::is_none")]
    pub chain_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<sts_model_management_components_2::JwksValue>,
    #[serde(rename = "privateKeyPem", default, skip_serializing_if = "Option::is_none")]
    pub private_key_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(rename = "jwsAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub jws_alg: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workbench: Option<crate::WithFieldsProfilesPqModes2>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors117 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub reason: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub already: Option<bool>,
    #[serde(rename = "onList", default, skip_serializing_if = "Option::is_none")]
    pub on_list: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undeclared: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workbench: Option<crate::WithFieldsProfilesPqModes2>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors118Revocation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors118 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation: Option<WithOkMessageErrors118Revocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(rename = "jwsAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub jws_alg: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workbench: Option<crate::WithFieldsProfilesPqModes2>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors119 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workbench: Option<crate::WithFieldsProfilesPqModes2>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors12 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub results: Option<crate::WithOkMessageErrors11>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors120 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<crate::WithIdCaProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dropped: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workbench: Option<crate::WithFieldsProfilesPqModes2>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors121FilesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base64: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors121 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<Vec<WithOkMessageErrors121FilesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workbench: Option<crate::WithFieldsProfilesPqModes2>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors122 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<sts_model_management_components_3::RootValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workbench: Option<crate::WithFieldsProfilesPqModes2>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors123 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(rename = "activatesAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub activates_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workbench: Option<crate::WithFieldsProfilesPqModes2>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors124 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unpinned: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workbench: Option<crate::WithFieldsProfilesPqModes2>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors125 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<sts_model_management_components_2::EntryValue2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub already: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workbench: Option<crate::WithFieldsProfilesPqModes2>,
}

pub type WithOkMessageErrors126 = Vec<crate::WithSubjectIssuerSerial>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors127AddedAnchorsItem {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub subject: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub fingerprint256: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub source: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors127 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duplicates: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchors: Option<f64>,
    #[serde(rename = "addedAnchors", default, skip_serializing_if = "Option::is_none")]
    pub added_anchors: Option<Vec<WithOkMessageErrors127AddedAnchorsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persisted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors128RemovedAnchor {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub subject: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub fingerprint256: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub source: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors128 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchors: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persisted: Option<bool>,
    #[serde(rename = "removedAnchor", default, skip_serializing_if = "Option::is_none")]
    pub removed_anchor: Option<WithOkMessageErrors128RemovedAnchor>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors129 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kvno: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etypes: Option<Vec<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retained: Option<sts_model_management_components_2::WithAdditionalPropertiesPropertiesPrincipal>,
    #[serde(rename = "keytabKvnos", default, skip_serializing_if = "Option::is_none")]
    pub keytab_kvnos: Option<Vec<i64>>,
    #[serde(rename = "keytabFilename", default, skip_serializing_if = "Option::is_none")]
    pub keytab_filename: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keytab: Option<String>,
    #[serde(rename = "trustRealm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub trust_realm: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors13 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors130 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    #[serde(rename = "trustRealm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub trust_realm: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors131 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleared: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(rename = "trustRealm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub trust_realm: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors132 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dropped: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kvnos: Option<Vec<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    #[serde(rename = "currentKvno", default, skip_serializing_if = "Option::is_none")]
    pub current_kvno: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spn: Option<String>,
    #[serde(rename = "trustRealm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub trust_realm: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors133SignedOut {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminated: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub message: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors133 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
    #[serde(rename = "trustRealm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub trust_realm: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kvno: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etypes: Option<Vec<i64>>,
    #[serde(rename = "keytabKvnos", default, skip_serializing_if = "Option::is_none")]
    pub keytab_kvnos: Option<Vec<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "keytabFilename", default, skip_serializing_if = "Option::is_none")]
    pub keytab_filename: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keytab: Option<String>,
    #[serde(rename = "passwordSet", default, skip_serializing_if = "Option::is_none")]
    pub password_set: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated: Option<bool>,
    #[serde(rename = "signedOut", default, skip_serializing_if = "Option::is_none")]
    pub signed_out: Option<WithOkMessageErrors133SignedOut>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors134 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued: Option<bool>,
    #[serde(rename = "runId", default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "alreadyQueued", default, skip_serializing_if = "Option::is_none")]
    pub already_queued: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invalidate: Option<bool>,
    #[serde(rename = "trustRealm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub trust_realm: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors135 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(rename = "trustRealm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub trust_realm: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<sts_model_management_components_3::TrustValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<sts_model_management_components_3::ShownValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub here: Option<sts_model_management_components_3::TrustValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub there: Option<sts_model_management_components_3::TrustValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<bool>,
    #[serde(rename = "otherRealm", default, skip_serializing_if = "Option::is_none")]
    pub other_realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors136 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<sts_model_management_components_1::ApplicationSummaryWithSeen>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors137 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "stillRequired", default, skip_serializing_if = "Option::is_none")]
    pub still_required: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors138 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors139 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gated: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors14LeaderAtRequest {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub node: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub pid: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub token: Option<Option<f64>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors14 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted: Option<bool>,
    #[serde(rename = "runId", default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(rename = "alreadyQueued", default, skip_serializing_if = "Option::is_none")]
    pub already_queued: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<crate::WithRunIdJobIdRealm2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(rename = "leaderAtRequest", default, skip_serializing_if = "Option::is_none")]
    pub leader_at_request: Option<WithOkMessageErrors14LeaderAtRequest>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors140OwnersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors140 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owners: Option<Vec<WithOkMessageErrors140OwnersItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors141 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "ownerProtected", default, skip_serializing_if = "Option::is_none")]
    pub owner_protected: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<sts_model_management_components_3::ServiceAccountView>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors142 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<crate::WithNamePrecedenceStored>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforced: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors143 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<sts_model_management_components_1::AuthenticationPolicyRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforced: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors144 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<sts_model_management_components_3::PolicyValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors145 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<sts_model_management_components_3::ServiceAccountPolicyRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforced: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors146 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<sts_model_management_components_2::PasskeyPolicyRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforced: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors147 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors148 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<crate::WithNamePrecedenceStored6>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforced: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors149 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<crate::WithNamePrecedenceStored7>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforced: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors15UnansweredItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<i64>,
    #[serde(rename = "threadId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub thread_id: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors15 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(rename = "generatedAt", default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub node: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<crate::WithIsolatesCollectedFailed>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unanswered: Option<Vec<WithOkMessageErrors15UnansweredItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totals: Option<crate::WithIsolatesCollectedFailed2>,
    #[serde(rename = "threadIds", default, skip_serializing_if = "Option::is_none")]
    pub thread_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors150 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definition: Option<sts_model_management_components_1::CustomAttributeDefinition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holders: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors151 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<sts_model_management_components_3::PostLoginPolicyRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforced: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors152 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<sts_model_management_components_1::ApplicationSummaryWithSeen>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<i64>,
    #[serde(rename = "withdrawnAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub withdrawn_at: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub dn: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors153 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<sts_model_management_components_3::SpiffeRegistrationView>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors154 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "referenceTypes", default, skip_serializing_if = "Option::is_none")]
    pub reference_types: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors155 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<crate::WithIdDnAttestationType>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors156 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "agentSpiffeId", default, skip_serializing_if = "Option::is_none")]
    pub agent_spiffe_id: Option<String>,
}

pub type WithOkMessageErrors157 = Vec<crate::WithAtOperationOutcome2>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors158Target {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors158 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(rename = "hmacKey", default, skip_serializing_if = "Option::is_none")]
    pub hmac_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<WithOkMessageErrors158Target>,
    #[serde(rename = "targetUri", default, skip_serializing_if = "Option::is_none")]
    pub target_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certbot: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors159 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<crate::WithIdStatusEntry>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors16 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted: Option<bool>,
    #[serde(rename = "runId", default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emergency: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub units: Option<Vec<String>>,
    /// The address to follow the run at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors160 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors161 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(rename = "hostNames", default, skip_serializing_if = "Option::is_none")]
    pub host_names: Option<Vec<String>>,
    #[serde(rename = "entryUri", default, skip_serializing_if = "Option::is_none")]
    pub entry_uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors162Target {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors162 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<WithOkMessageErrors162Target>,
    #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
    pub key_alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<crate::WithSerialHexEntryEntryUri>,
    #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
    pub certificate_pem: Option<String>,
    #[serde(rename = "chainPem", default, skip_serializing_if = "Option::is_none")]
    pub chain_pem: Option<Vec<String>>,
    #[serde(rename = "privateKeyPem", default, skip_serializing_if = "Option::is_none")]
    pub private_key_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors163Entry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors163 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<WithOkMessageErrors163Entry>,
    #[serde(rename = "entryUri", default, skip_serializing_if = "Option::is_none")]
    pub entry_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors164Entry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors164 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(rename = "hostNames", default, skip_serializing_if = "Option::is_none")]
    pub host_names: Option<Vec<String>>,
    #[serde(rename = "entryUri", default, skip_serializing_if = "Option::is_none")]
    pub entry_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<WithOkMessageErrors164Entry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unchanged: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors165Target {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors165 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<WithOkMessageErrors165Target>,
    #[serde(rename = "entryUri", default, skip_serializing_if = "Option::is_none")]
    pub entry_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(rename = "plainUrl", default, skip_serializing_if = "Option::is_none")]
    pub plain_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors166 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ra: Option<crate::WithPresentStatusSubject>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors167 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(rename = "entryUri", default, skip_serializing_if = "Option::is_none")]
    pub entry_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors168 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(rename = "entryUri", default, skip_serializing_if = "Option::is_none")]
    pub entry_uri: Option<String>,
    #[serde(rename = "hostNames", default, skip_serializing_if = "Option::is_none")]
    pub host_names: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors169 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subordinate: Option<crate::WithEntityIdJwksMetadata>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors17 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(rename = "activationUrl", default, skip_serializing_if = "Option::is_none")]
    pub activation_url: Option<String>,
    #[serde(rename = "activationLink", default, skip_serializing_if = "Option::is_none")]
    pub activation_link: Option<String>,
    #[serde(rename = "mailedTo", default, skip_serializing_if = "Option::is_none")]
    pub mailed_to: Option<String>,
    #[serde(rename = "mailError", default, skip_serializing_if = "Option::is_none")]
    pub mail_error: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors170 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collection: Option<crate::WithCrawlCrawlEverySJobOff>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors171 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<sts_model_management_components_2::JwkSetMetadataDocumentMetadata>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors172MarkType {
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
pub struct WithOkMessageErrors172 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(rename = "markType", default, skip_serializing_if = "Option::is_none")]
    pub mark_type: Option<WithOkMessageErrors172MarkType>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors173 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(rename = "markPolicy", default, skip_serializing_if = "Option::is_none")]
    pub mark_policy: Option<crate::WithTypeIssuersOwner>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors174 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<crate::WithSubjectAnchorExpiresAt>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithOkMessageErrors175ClientId {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors175 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_uri_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub client_id: Option<Option<WithOkMessageErrors175ClientId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors176FailuresItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors176 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<crate::WithIdDialectHost>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub found: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row: Option<sts_model_management_components_3::RowValue>,
    #[serde(rename = "runId", default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<sts_model_base::unions::NumberOrString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<Vec<WithOkMessageErrors176FailuresItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors177 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<sts_model_management_components_2::DestinationValue>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub version: Option<Option<sts_model_base::unions::NumberOrString>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors178 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaced: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row: Option<crate::WithKeyObjectProperty>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors179 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller: Option<crate::WithDnNameKind>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors18Existing {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors18 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<crate::WithDnOriginCreatedAt2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typed: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invented: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    #[serde(rename = "serviceAccount", default, skip_serializing_if = "Option::is_none")]
    pub service_account: Option<bool>,
    #[serde(rename = "serviceAccountError", default, skip_serializing_if = "Option::is_none")]
    pub service_account_error: Option<String>,
    #[serde(rename = "credentialError", default, skip_serializing_if = "Option::is_none")]
    pub credential_error: Option<String>,
    #[serde(rename = "passwordSet", default, skip_serializing_if = "Option::is_none")]
    pub password_set: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(rename = "activationUrl", default, skip_serializing_if = "Option::is_none")]
    pub activation_url: Option<String>,
    #[serde(rename = "activationLink", default, skip_serializing_if = "Option::is_none")]
    pub activation_link: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub existing: Option<WithOkMessageErrors18Existing>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unknown: Option<Vec<String>>,
    #[serde(rename = "mailedTo", default, skip_serializing_if = "Option::is_none")]
    pub mailed_to: Option<String>,
    #[serde(rename = "mailError", default, skip_serializing_if = "Option::is_none")]
    pub mail_error: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors180 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<crate::WithIdStatusRequester>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors181 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<i64>,
    #[serde(rename = "ownsResources", default, skip_serializing_if = "Option::is_none")]
    pub owns_resources: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors182 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors183 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share: Option<crate::WithIdResourceIdScopes2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors184 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<crate::WithIdOwnerOwnerKind>,
}

pub type WithOkMessageErrors185 = Vec<crate::WithUsernameDnKind2>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors186 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(rename = "runId", default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(rename = "alreadyQueued", default, skip_serializing_if = "Option::is_none")]
    pub already_queued: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors187 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started: Option<crate::WithIdActivityGroups>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors188Diagnostic {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub disposition: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors188 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<crate::WithIdNameType3>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<WithOkMessageErrors188Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors189 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo: Option<crate::WithTypeWidthHeight>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors19 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors190 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors191Certificate {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub subject: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub serial: Option<Option<String>>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub not_after: Option<Option<String>>,
    #[serde(rename = "rootPem", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub root_pem: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors191CellsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reachable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors191 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<sts_model_management_components_1::ClientValue2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<WithOkMessageErrors191Certificate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery: Option<crate::WithOkPatchFilter>,
    #[serde(rename = "totalResults", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub total_results: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cells: Option<Vec<WithOkMessageErrors191CellsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reachable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprovisioned: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(rename = "notPushedHere", default, skip_serializing_if = "Option::is_none")]
    pub not_pushed_here: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors192 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row: Option<crate::WithIdRealmClientId4>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<crate::WithIdClientIdCommand>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors193 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row: Option<crate::WithIdRealmClientId5>,
}

pub type WithOkMessageErrors2 = Vec<crate::WithLabelEncryptionsDecryptions>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors20 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(rename = "sessionsEnded", default, skip_serializing_if = "Option::is_none")]
    pub sessions_ended: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors21 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<bool>,
    #[serde(rename = "sessionsEnded", default, skip_serializing_if = "Option::is_none")]
    pub sessions_ended: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors22 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pseudonyms: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub pending: Option<Option<sts_model_base::unions::BoolOrStringOrObject>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors23 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors24 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors25SignedOut {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminated: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors25 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(rename = "forcedChange", default, skip_serializing_if = "Option::is_none")]
    pub forced_change: Option<bool>,
    #[serde(rename = "signedOut", default, skip_serializing_if = "Option::is_none")]
    pub signed_out: Option<WithOkMessageErrors25SignedOut>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors26SignedOut {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminated: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors26 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(rename = "resetUrl", default, skip_serializing_if = "Option::is_none")]
    pub reset_url: Option<String>,
    #[serde(rename = "passwordRevoked", default, skip_serializing_if = "Option::is_none")]
    pub password_revoked: Option<bool>,
    #[serde(rename = "signedOut", default, skip_serializing_if = "Option::is_none")]
    pub signed_out: Option<WithOkMessageErrors26SignedOut>,
    #[serde(rename = "mailedTo", default, skip_serializing_if = "Option::is_none")]
    pub mailed_to: Option<String>,
    #[serde(rename = "mailError", default, skip_serializing_if = "Option::is_none")]
    pub mail_error: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors27RemovedItem {
    #[serde(rename = "credentialId", default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(rename = "enrolledAt", default, skip_serializing_if = "Option::is_none")]
    pub enrolled_at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors27 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<Vec<WithOkMessageErrors27RemovedItem>>,
    #[serde(rename = "sessionsEnded", default, skip_serializing_if = "Option::is_none")]
    pub sessions_ended: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors28 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<crate::WithTotpKeysBackupCodes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requirement: Option<crate::WithRequiredByUserByRealm>,
    #[serde(rename = "sessionsEnded", default, skip_serializing_if = "Option::is_none")]
    pub sessions_ended: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors29 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requirement: Option<crate::WithRequiredByUserByRealm>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors3 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted: Option<bool>,
    #[serde(rename = "runId", default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// The address to follow the run at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors30SignedOut {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminated: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors30 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(rename = "serviceAccount", default, skip_serializing_if = "Option::is_none")]
    pub service_account: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<sts_model_management_components_3::ServiceAccountView>,
    #[serde(rename = "signedOut", default, skip_serializing_if = "Option::is_none")]
    pub signed_out: Option<WithOkMessageErrors30SignedOut>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors31 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<sts_model_management_components_3::ServiceAccountView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors32 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(rename = "runId", default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "alreadyQueued", default, skip_serializing_if = "Option::is_none")]
    pub already_queued: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors33 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(rename = "notDelegated", default, skip_serializing_if = "Option::is_none")]
    pub not_delegated: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors34 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(rename = "mayAct", default, skip_serializing_if = "Option::is_none")]
    pub may_act: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors35 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantics: Option<Vec<String>>,
    #[serde(rename = "defaultSemantics", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default_semantics: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors36 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors37 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors38 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<crate::WithSubjectLabelEnrolledAt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors39 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<crate::WithSerialHexSubjectKeyAlg>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<crate::WithPkcs12KeyChain>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing: Option<crate::WithOkKindHolder2>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors4 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors40 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<crate::WithSlotLabelSerialHex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub already: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<crate::WithSerialHexRevokedAtReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing: Option<crate::WithOkKindHolder2>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors41 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrolled: Option<crate::WithSubjectLabelEnrolledAt2>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors42 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub preferred: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors43 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors44 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<crate::WithIdRecordedSource>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors45 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended: Option<sts_model_management_components_2::EndedValue>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors46 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors47 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(rename = "appPassword", default, skip_serializing_if = "Option::is_none")]
    pub app_password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doors: Option<Vec<String>>,
    #[serde(rename = "doorLabels", default, skip_serializing_if = "Option::is_none")]
    pub door_labels: Option<Vec<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<f64>,
    #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    #[serde(rename = "lastUsedAt", default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<f64>,
    #[serde(rename = "lastUsedDoor", default, skip_serializing_if = "Option::is_none")]
    pub last_used_door: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors48 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<crate::WithIdNameDoors>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors49 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "upgradeId", default, skip_serializing_if = "Option::is_none")]
    pub upgrade_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ceremony: Option<crate::WithChallengeRpIdAllow>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors5RealmsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors5 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realms: Option<Vec<WithOkMessageErrors5RealmsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors50 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ceremony: Option<crate::WithChallengeRpIdUser>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors51 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "credentialId", default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(rename = "previousAlgorithm", default, skip_serializing_if = "Option::is_none")]
    pub previous_algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lane: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors52 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(rename = "enrolmentId", default, skip_serializing_if = "Option::is_none")]
    pub enrolment_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lane: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ceremony: Option<crate::WithChallengeRpIdUser>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors53EnrolledBy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors53 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lane: Option<String>,
    #[serde(rename = "credentialId", default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<f64>,
    #[serde(rename = "enrolledBy", default, skip_serializing_if = "Option::is_none")]
    pub enrolled_by: Option<WithOkMessageErrors53EnrolledBy>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors54 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<crate::WithOkKeyScope2>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors55 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<sts_model_management_components_2::WithIdRealmClientId>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors56Existing {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors56 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dangling: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<crate::WithDnOriginCreatedAt2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub existing: Option<WithOkMessageErrors56Existing>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors57 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(rename = "memberCount", default, skip_serializing_if = "Option::is_none")]
    pub member_count: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<crate::WithDnOriginCreatedAt2>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors58 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<crate::WithDnOriginCreatedAt2>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors59 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors6 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors60OwnersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors60 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owners: Option<Vec<WithOkMessageErrors60OwnersItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors61 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolves: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<crate::WithDnOriginCreatedAt2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors62 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<sts_model_base::unions::StringOrObject>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<f64>,
}

pub type WithOkMessageErrors63 = Vec<crate::WithKindCountIdentifiers>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors64 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(rename = "revocationReach", default, skip_serializing_if = "Option::is_none")]
    pub revocation_reach: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors65 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(rename = "setKey", default, skip_serializing_if = "Option::is_none")]
    pub set_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocable: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restored: Option<i64>,
    #[serde(rename = "reachedProtocol", default, skip_serializing_if = "Option::is_none")]
    pub reached_protocol: Option<i64>,
    #[serde(rename = "recordOnly", default, skip_serializing_if = "Option::is_none")]
    pub record_only: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors66Bootstrap {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<bool>,
    #[serde(rename = "passwordResetRequired", default, skip_serializing_if = "Option::is_none")]
    pub password_reset_required: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors66 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap: Option<WithOkMessageErrors66Bootstrap>,
    /// The bootstrap administrator's generated password, in product mode, once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retiring: Option<crate::WithSinceSinceIsoInProgress>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retirement: Option<crate::WithLateFailedUndelivered>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors67 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<sts_model_management_components_2::SettingSetWhereCame>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors68 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<sts_model_management_components_2::WithDescriptionGroupSettings>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors69 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleared: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors7 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors70 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<crate::WithGroupSettingsDescription>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors71 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleared: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<crate::WithGroupSettingsDescription>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors72 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleared: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<sts_model_management_components_3::WithGroupSettingsConfigFile3>,
}

pub type WithOkMessageErrors73 = Vec<crate::WithNameValueAttribute>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors74 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<crate::WithOkMessageErrors73>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors75 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sweep: Option<crate::WithOkLoadedExamined>,
}

pub type WithOkMessageErrors76 = Vec<crate::WithStateFormatResponseType>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors77 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors78 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(rename = "responseType", default, skip_serializing_if = "Option::is_none")]
    pub response_type: Option<String>,
    #[serde(rename = "responseMode", default, skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<String>,
    #[serde(rename = "byReference", default, skip_serializing_if = "Option::is_none")]
    pub by_reference: Option<bool>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dcql_query: Option<crate::WithCredentialsCredentialsetsState2>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet: Option<String>,
    #[serde(rename = "walletUrl", default, skip_serializing_if = "Option::is_none")]
    pub wallet_url: Option<String>,
    #[serde(rename = "requestUri", default, skip_serializing_if = "Option::is_none")]
    pub request_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(rename = "redirectUri", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub redirect_uri: Option<Option<String>>,
    #[serde(rename = "request_uri", default, skip_serializing_if = "Option::is_none")]
    pub request_uri_2: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors79Readiness {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors79 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship: Option<sts_model_management_components_3::RelationshipValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness: Option<WithOkMessageErrors79Readiness>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors8 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub dataset: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub version: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duplicate: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unloaded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acceptance: Option<crate::WithIdProviderTermsDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors80Endpoints {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors80 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<WithOkMessageErrors80Endpoints>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readable: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors81Polled {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acted: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rounds: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors81 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signals: Option<crate::WithRelationshipNameKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer: Option<sts_model_management_components_2::PartnerSOwnAnswerSsf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub polled: Option<WithOkMessageErrors81Polled>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors82 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<sts_model_management_components_1::ApplicationRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors83 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub how: Option<String>,
    #[serde(rename = "entityId", default, skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(rename = "certificateUse", default, skip_serializing_if = "Option::is_none")]
    pub certificate_use: Option<String>,
    #[serde(rename = "signingCertificates", default, skip_serializing_if = "Option::is_none")]
    pub signing_certificates: Option<f64>,
    #[serde(rename = "assertionConsumerServices", default, skip_serializing_if = "Option::is_none")]
    pub assertion_consumer_services: Option<Vec<String>>,
    #[serde(rename = "singleLogoutServices", default, skip_serializing_if = "Option::is_none")]
    pub single_logout_services: Option<Vec<String>>,
    #[serde(rename = "nameIdFormats", default, skip_serializing_if = "Option::is_none")]
    pub name_id_formats: Option<Vec<String>>,
    #[serde(rename = "authnRequestsSigned", default, skip_serializing_if = "Option::is_none")]
    pub authn_requests_signed: Option<bool>,
    #[serde(rename = "wantAssertionsSigned", default, skip_serializing_if = "Option::is_none")]
    pub want_assertions_signed: Option<bool>,
    #[serde(rename = "validUntil", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub valid_until: Option<Option<String>>,
    #[serde(rename = "cacheDuration", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cache_duration: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors84 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<sts_model_management_components_3::ProfileValue>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithOkMessageErrors85Changed {
    V1(Vec<String>),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors85 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<sts_model_management_components_1::ApplicationValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<WithOkMessageErrors85Changed>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithOkMessageErrors86Changed {
    V1(Vec<String>),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors86WarningsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dropped: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors86 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<sts_model_management_components_1::ApplicationValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<WithOkMessageErrors86Changed>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<WithOkMessageErrors86WarningsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithOkMessageErrors87Changed {
    V1(Vec<String>),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors87OwnersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors87 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<sts_model_management_components_1::ApplicationValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<WithOkMessageErrors87Changed>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owners: Option<Vec<WithOkMessageErrors87OwnersItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithOkMessageErrors88Changed {
    V1(Vec<String>),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors88 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<sts_model_management_components_1::ApplicationValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<WithOkMessageErrors88Changed>,
    #[serde(rename = "clientSecret", default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(rename = "secretId", default, skip_serializing_if = "Option::is_none")]
    pub secret_id: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaced: Option<bool>,
    #[serde(rename = "overlapUntil", default, skip_serializing_if = "Option::is_none")]
    pub overlap_until: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithOkMessageErrors89Changed {
    V1(Vec<String>),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors89 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<sts_model_management_components_1::ApplicationValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<WithOkMessageErrors89Changed>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors9 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row: Option<crate::WithIdRealmUsername>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithOkMessageErrors90Changed {
    V1(Vec<String>),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors90 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<sts_model_management_components_1::ApplicationValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<WithOkMessageErrors90Changed>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub did: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(rename = "verificationMethod", default, skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<String>,
    #[serde(rename = "documentUrl", default, skip_serializing_if = "Option::is_none")]
    pub document_url: Option<String>,
    /// A JWK's members, which its algorithm decides.
    #[serde(rename = "publicJwk", default, skip_serializing_if = "Option::is_none")]
    pub public_jwk: Option<serde_json::Map<String, serde_json::Value>>,
    /// A JWK's members, which its algorithm decides.
    #[serde(rename = "privateJwk", default, skip_serializing_if = "Option::is_none")]
    pub private_jwk: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "privateKeyPem", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub private_key_pem: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaced: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithOkMessageErrors91Changed {
    V1(Vec<String>),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors91 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<sts_model_management_components_1::ApplicationValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<WithOkMessageErrors91Changed>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub did: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(rename = "didConfiguration", default, skip_serializing_if = "Option::is_none")]
    pub did_configuration: Option<crate::WithLinkeddidsOkMessage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(rename = "hostAt", default, skip_serializing_if = "Option::is_none")]
    pub host_at: Option<String>,
}

pub type WithOkMessageErrors92 = Vec<crate::WithNameValueNameFormat>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithOkMessageErrors93Changed {
    V1(Vec<String>),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors93 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<sts_model_management_components_1::ApplicationValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<WithOkMessageErrors93Changed>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<crate::WithOkMessageErrors92>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithOkMessageErrors94Changed {
    V1(Vec<String>),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors94 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<sts_model_management_components_1::ApplicationValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<WithOkMessageErrors94Changed>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherited: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attributes: Option<Option<Vec<serde_json::Value>>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithOkMessageErrors95Changed {
    V1(Vec<String>),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors95SetsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherited: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors95 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<sts_model_management_components_1::ApplicationValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<WithOkMessageErrors95Changed>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sets: Option<Vec<WithOkMessageErrors95SetsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithOkMessageErrors96Changed {
    V1(Vec<String>),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors96 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<sts_model_management_components_1::ApplicationValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<WithOkMessageErrors96Changed>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attributes: Option<Option<Vec<serde_json::Value>>>,
    /// Each permission's claims.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mappings: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithOkMessageErrors97Changed {
    V1(Vec<String>),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors97 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<sts_model_management_components_1::ApplicationValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<WithOkMessageErrors97Changed>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definition: Option<sts_model_management_components_2::JsonOperatorWroteIntoAccess>,
    /// On a refusal of an access type's XACML mapping (`STS-FGA-0023`,
    /// `STS-FGA-0019`): the member of the request that was wrong — `path`,
    /// `attributeId`, `category`, `dataType`, `multiplicity` or `notForPolicy`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithOkMessageErrors98Changed {
    V1(Vec<String>),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors98 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<sts_model_management_components_1::ApplicationValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<WithOkMessageErrors98Changed>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforced: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peps: Option<crate::WithGroupAuthzenGroupTotal2>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithOkMessageErrors99Changed {
    V1(Vec<String>),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkMessageErrors99 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<sts_model_management_components_1::ApplicationValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<WithOkMessageErrors99Changed>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<crate::WithSerialHexSubjectKeyAlg2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<crate::WithPkcs12KeyChain>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkPatchFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<bool>,
    /// The path of each resource type, by its name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOwnersNameLocalName {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owners: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "localName", default, skip_serializing_if = "Option::is_none")]
    pub local_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub console: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native: Option<bool>,
    #[serde(rename = "builtIn", default, skip_serializing_if = "Option::is_none")]
    pub built_in: Option<bool>,
    #[serde(rename = "memberTypes", default, skip_serializing_if = "Option::is_none")]
    pub member_types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applications: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<String>>,
    #[serde(rename = "conferredBy", default, skip_serializing_if = "Option::is_none")]
    pub conferred_by: Option<Vec<String>>,
    #[serde(rename = "ownerProtected", default, skip_serializing_if = "Option::is_none")]
    pub owner_protected: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithPageGroupsSettingCount {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<crate::WithDescriptionPathLabel>,
    #[serde(rename = "settingCount", default, skip_serializing_if = "Option::is_none")]
    pub setting_count: Option<i64>,
    #[serde(rename = "editableCount", default, skip_serializing_if = "Option::is_none")]
    pub editable_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<Vec<String>>,
    #[serde(rename = "setWith", default, skip_serializing_if = "Option::is_none")]
    pub set_with: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<sts_model_management_components_3::WithConfigFileDefaultsFilePersistsAppconfig3>,
    #[serde(rename = "sharedWith", default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<sts_model_management_components_2::OtherPagesSettingsGroupDrawn>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithPageGroupsSettingCount2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<sts_model_management_components_3::WithConfigFileDefaultsFilePersistsAppconfig4>,
    #[serde(rename = "settingCount", default, skip_serializing_if = "Option::is_none")]
    pub setting_count: Option<i64>,
    #[serde(rename = "editableCount", default, skip_serializing_if = "Option::is_none")]
    pub editable_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<Vec<String>>,
    #[serde(rename = "setWith", default, skip_serializing_if = "Option::is_none")]
    pub set_with: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<sts_model_management_components_3::WithConfigFileDefaultsFilePersistsAppconfig5>,
    /// The other pages, by settings group.
    #[serde(rename = "sharedWith", default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithPagePagesPerPage {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noun: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithPagePagesPerPage2 {
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
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub param: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub noun: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithPagePagesPerPage3 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub param: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub noun: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithPageTitleWhatLinksItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithPageTitleWhat {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<WithPageTitleWhatLinksItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<crate::WithPageGroupsSettingCount>,
    #[serde(rename = "leadHtml", default, skip_serializing_if = "Option::is_none")]
    pub lead_html: Option<String>,
    #[serde(rename = "alsoHtml", default, skip_serializing_if = "Option::is_none")]
    pub also_html: Option<Vec<String>>,
    #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
    pub protocol_endpoints: Option<crate::WithParamsDescriptionParams>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithPageTitleWhat2LinksItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithPageTitleWhat2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<WithPageTitleWhat2LinksItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<crate::WithPageGroupsSettingCount2>,
    #[serde(rename = "leadHtml", default, skip_serializing_if = "Option::is_none")]
    pub lead_html: Option<String>,
    #[serde(rename = "alsoHtml", default, skip_serializing_if = "Option::is_none")]
    pub also_html: Option<Vec<String>>,
    #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
    pub protocol_endpoints: Option<crate::WithParamsDescriptionParams>,
}

pub type WithPagingRowsEntry = Vec<crate::WithSerialHexEntryEntryUri>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithPagingRowsEntry2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<crate::WithPagePagesPerPage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<crate::WithPagingRowsEntry>,
}

pub type WithParamsDescriptionParams = Vec<crate::WithNameMethodsUrl>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithPidThreadIdKind {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub pid: Option<Option<sts_model_base::unions::IntegerOrString>>,
    #[serde(rename = "threadId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub thread_id: Option<Option<sts_model_base::unions::IntegerOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "rssBytes", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub rss_bytes: Option<Option<f64>>,
    #[serde(rename = "heapUsedBytes", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub heap_used_bytes: Option<Option<f64>>,
    #[serde(rename = "heapTotalBytes", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub heap_total_bytes: Option<Option<f64>>,
    #[serde(rename = "externalBytes", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub external_bytes: Option<Option<f64>>,
    #[serde(rename = "arrayBuffersBytes", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub array_buffers_bytes: Option<Option<f64>>,
    #[serde(rename = "peakRssBytes", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub peak_rss_bytes: Option<Option<f64>>,
    #[serde(rename = "cpuUserSeconds", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cpu_user_seconds: Option<Option<f64>>,
    #[serde(rename = "cpuSystemSeconds", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cpu_system_seconds: Option<Option<f64>>,
    #[serde(rename = "uptimeSeconds", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub uptime_seconds: Option<Option<f64>>,
    #[serde(rename = "processWide", default, skip_serializing_if = "Option::is_none")]
    pub process_wide: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub unreadable: Option<Option<String>>,
    #[serde(rename = "notReported", default, skip_serializing_if = "Option::is_none")]
    pub not_reported: Option<String>,
}

pub type WithPidThreadIdRole = Vec<crate::WithPidThreadIdKind>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithPidThreadIdRole2 {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub pid: Option<Option<sts_model_base::unions::IntegerOrString>>,
    #[serde(rename = "threadId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub thread_id: Option<Option<sts_model_base::unions::IntegerOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithPkcs12KeyChainPkcs12 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base64: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithPkcs12KeyChainKey {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base64: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithPkcs12KeyChainChain {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base64: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithPkcs12KeyChain {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pkcs12: Option<WithPkcs12KeyChainPkcs12>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<WithPkcs12KeyChainKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<WithPkcs12KeyChainChain>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithPresentStatusSubject {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(rename = "keyAlgorithm", default, skip_serializing_if = "Option::is_none")]
    pub key_algorithm: Option<String>,
    #[serde(rename = "wantedKeyAlgorithm", default, skip_serializing_if = "Option::is_none")]
    pub wanted_key_algorithm: Option<String>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
    pub certificate_pem: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithProviderTextUrl {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub url: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub licence: Option<Option<String>>,
    #[serde(rename = "licenceUrl", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub licence_url: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
}

pub type WithRealmIssuerNodes = Vec<crate::WithSeqAtKind2>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithRealmIssuerNodes2Realm {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
    #[serde(rename = "isDefault", default, skip_serializing_if = "Option::is_none")]
    pub is_default: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithRealmIssuerNodes2Counts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodes: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edges: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithRealmIssuerNodes2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<WithRealmIssuerNodes2Realm>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodes: Option<crate::WithIdFromTo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edges: Option<crate::WithSeqAtKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<crate::WithRealmIssuerNodes>,
    #[serde(rename = "tokensLeftOff", default, skip_serializing_if = "Option::is_none")]
    pub tokens_left_off: Option<i64>,
    #[serde(rename = "maxTokenRows", default, skip_serializing_if = "Option::is_none")]
    pub max_token_rows: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acts: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chains: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<crate::WithSeqOriginAt2>,
    #[serde(rename = "credentialsOnDelegationLines", default, skip_serializing_if = "Option::is_none")]
    pub credentials_on_delegation_lines: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<WithRealmIssuerNodes2Counts>,
}

pub type WithRelationshipJtiVia = Vec<crate::WithEventReactionDone>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithRelationshipJtiVia2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    #[serde(rename = "receivedAt", default, skip_serializing_if = "Option::is_none")]
    pub received_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<String>>,
    /// An RFC 9493 subject identifier as a partner's SET carried it, in
    /// whatever format that partner chose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapping: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reactions: Option<crate::WithRelationshipJtiVia>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithRelationshipLabelProtocol {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithRelationshipNameKindCredential {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(rename = "tokenEndpoint", default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(rename = "secretHeld", default, skip_serializing_if = "Option::is_none")]
    pub secret_held: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithRelationshipNameKindCounts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acted: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithRelationshipNameKind {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "signalsEnabled", default, skip_serializing_if = "Option::is_none")]
    pub signals_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiving: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<String>,
    #[serde(rename = "eventsRequested", default, skip_serializing_if = "Option::is_none")]
    pub events_requested: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<WithRelationshipNameKindCredential>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<sts_model_management_components_1::ConfigValue>,
    #[serde(rename = "discoveryUrl", default, skip_serializing_if = "Option::is_none")]
    pub discovery_url: Option<String>,
    #[serde(rename = "discoveredAt", default, skip_serializing_if = "Option::is_none")]
    pub discovered_at: Option<String>,
    #[serde(rename = "streamId", default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<sts_model_management_components_3::StreamValue>,
    #[serde(rename = "streamDelivery", default, skip_serializing_if = "Option::is_none")]
    pub stream_delivery: Option<String>,
    #[serde(rename = "streamAud", default, skip_serializing_if = "Option::is_none")]
    pub stream_aud: Option<Vec<String>>,
    #[serde(rename = "pollEndpoint", default, skip_serializing_if = "Option::is_none")]
    pub poll_endpoint: Option<String>,
    #[serde(rename = "pushEndpoint", default, skip_serializing_if = "Option::is_none")]
    pub push_endpoint: Option<String>,
    #[serde(rename = "pushEndpointSet", default, skip_serializing_if = "Option::is_none")]
    pub push_endpoint_set: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(rename = "streamStatus", default, skip_serializing_if = "Option::is_none")]
    pub stream_status: Option<String>,
    #[serde(rename = "verifiedAt", default, skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<String>,
    #[serde(rename = "lastPollAt", default, skip_serializing_if = "Option::is_none")]
    pub last_poll_at: Option<String>,
    #[serde(rename = "lastPollResult", default, skip_serializing_if = "Option::is_none")]
    pub last_poll_result: Option<String>,
    #[serde(rename = "lastError", default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<WithRelationshipNameKindCounts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocks: Option<crate::WithRelationshipUsernameAt>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithRelationshipUsernameAtItemItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
}

pub type WithRelationshipUsernameAt = Vec<WithRelationshipUsernameAtItemItem>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithRequiredByUserByRealm {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(rename = "byUser", default, skip_serializing_if = "Option::is_none")]
    pub by_user: Option<bool>,
    #[serde(rename = "byRealm", default, skip_serializing_if = "Option::is_none")]
    pub by_realm: Option<bool>,
    #[serde(rename = "byAdministrator", default, skip_serializing_if = "Option::is_none")]
    pub by_administrator: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offered: Option<bool>,
    #[serde(rename = "exemptServiceAccount", default, skip_serializing_if = "Option::is_none")]
    pub exempt_service_account: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithResourceResourceNameBaseUriGrantedToItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithResourceResourceNameBaseUri {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(rename = "resourceName", default, skip_serializing_if = "Option::is_none")]
    pub resource_name: Option<String>,
    #[serde(rename = "baseUri", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub base_uri: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub description: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub id: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub raw: Option<Option<String>>,
    #[serde(rename = "grantedTo", default, skip_serializing_if = "Option::is_none")]
    pub granted_to: Option<Vec<WithResourceResourceNameBaseUriGrantedToItem>>,
}

pub type WithRowsProcessesWorkerThreads = Vec<crate::WithPidThreadIdRole2>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithRowsProcessesWorkerThreads2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processes: Option<i64>,
    #[serde(rename = "workerThreads", default, skip_serializing_if = "Option::is_none")]
    pub worker_threads: Option<i64>,
    #[serde(rename = "rssBytes", default, skip_serializing_if = "Option::is_none")]
    pub rss_bytes: Option<f64>,
    #[serde(rename = "processesWithRss", default, skip_serializing_if = "Option::is_none")]
    pub processes_with_rss: Option<i64>,
    #[serde(rename = "heapUsedBytes", default, skip_serializing_if = "Option::is_none")]
    pub heap_used_bytes: Option<f64>,
    #[serde(rename = "heapTotalBytes", default, skip_serializing_if = "Option::is_none")]
    pub heap_total_bytes: Option<f64>,
    #[serde(rename = "externalBytes", default, skip_serializing_if = "Option::is_none")]
    pub external_bytes: Option<f64>,
    #[serde(rename = "isolatesWithHeap", default, skip_serializing_if = "Option::is_none")]
    pub isolates_with_heap: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithRowsUnansweredDebuggerNote {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<crate::WithPidThreadIdRole>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unanswered: Option<crate::WithRowsProcessesWorkerThreads>,
    #[serde(rename = "debuggerNote", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub debugger_note: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totals: Option<crate::WithRowsProcessesWorkerThreads2>,
    #[serde(rename = "totalsText", default, skip_serializing_if = "Option::is_none")]
    pub totals_text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithRpAlgorithmsAttestationRp {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithRpAlgorithmsAttestationAuthenticatorSelection {
    #[serde(rename = "userVerification", default, skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,
    #[serde(rename = "residentKey", default, skip_serializing_if = "Option::is_none")]
    pub resident_key: Option<String>,
    #[serde(rename = "requireResidentKey", default, skip_serializing_if = "Option::is_none")]
    pub require_resident_key: Option<bool>,
    #[serde(rename = "authenticatorAttachment", default, skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithRpAlgorithmsAttestation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rp: Option<WithRpAlgorithmsAttestationRp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithms: Option<Vec<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<f64>,
    #[serde(rename = "authenticatorSelection", default, skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<WithRpAlgorithmsAttestationAuthenticatorSelection>,
    #[serde(rename = "credProps", default, skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<bool>,
    #[serde(rename = "minPinLength", default, skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hints: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithRunIdJobIdRealm {
    #[serde(rename = "runId", default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(rename = "jobId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub job_id: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<i64>,
    #[serde(rename = "fenceAt", default, skip_serializing_if = "Option::is_none")]
    pub fence_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    #[serde(rename = "nodeName", default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub pid: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker: Option<bool>,
    #[serde(rename = "dueAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub due_at: Option<Option<String>>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub queued_at: Option<Option<String>>,
    #[serde(rename = "queuedAtMs", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub queued_at_ms: Option<Option<f64>>,
    #[serde(rename = "startedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub started_at: Option<Option<String>>,
    #[serde(rename = "endedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ended_at: Option<Option<String>>,
    #[serde(rename = "durationMs", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub duration_ms: Option<Option<f64>>,
    #[serde(rename = "requestedBy", default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<String>,
    #[serde(rename = "requestedVia", default, skip_serializing_if = "Option::is_none")]
    pub requested_via: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<sts_model_management_components_2::ManualRunSParamsJson>,
    #[serde(rename = "takenOver", default, skip_serializing_if = "Option::is_none")]
    pub taken_over: Option<bool>,
    #[serde(rename = "abandonedOf", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub abandoned_of: Option<Option<String>>,
    #[serde(rename = "ranIn", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ran_in: Option<Option<String>>,
    #[serde(rename = "deferredMs", default, skip_serializing_if = "Option::is_none")]
    pub deferred_ms: Option<f64>,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    /// `summaryOf()`: the job's answer as text, 500 characters at most.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub result: Option<Option<String>>,
    #[serde(rename = "nextRunAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub next_run_at: Option<Option<String>>,
    #[serde(rename = "nextRunInMs", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub next_run_in_ms: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithRunIdJobIdRealm2 {
    #[serde(rename = "runId", default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(rename = "jobId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub job_id: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<i64>,
    #[serde(rename = "fenceAt", default, skip_serializing_if = "Option::is_none")]
    pub fence_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    #[serde(rename = "nodeName", default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub pid: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker: Option<bool>,
    #[serde(rename = "dueAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub due_at: Option<Option<String>>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub queued_at: Option<Option<String>>,
    #[serde(rename = "queuedAtMs", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub queued_at_ms: Option<Option<f64>>,
    #[serde(rename = "startedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub started_at: Option<Option<String>>,
    #[serde(rename = "endedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ended_at: Option<Option<String>>,
    #[serde(rename = "durationMs", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub duration_ms: Option<Option<f64>>,
    #[serde(rename = "requestedBy", default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<String>,
    #[serde(rename = "requestedVia", default, skip_serializing_if = "Option::is_none")]
    pub requested_via: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<sts_model_management_components_2::ManualRunSParamsJson>,
    #[serde(rename = "takenOver", default, skip_serializing_if = "Option::is_none")]
    pub taken_over: Option<bool>,
    #[serde(rename = "abandonedOf", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub abandoned_of: Option<Option<String>>,
    #[serde(rename = "ranIn", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ran_in: Option<Option<String>>,
    #[serde(rename = "deferredMs", default, skip_serializing_if = "Option::is_none")]
    pub deferred_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    /// `summaryOf()`: the job's answer as text, 500 characters at most.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub result: Option<Option<String>>,
    #[serde(rename = "nextRunAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub next_run_at: Option<Option<String>>,
    #[serde(rename = "nextRunInMs", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub next_run_in_ms: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithScimLdapKind {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ldap: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub kind: Option<Option<String>>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub type_: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub parent: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension: Option<bool>,
    #[serde(rename = "readOnly", default, skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub type WithSeqAtKind = Vec<crate::WithIdFromTo3>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSeqAtKind2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub at: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(rename = "typeLabel", default, skip_serializing_if = "Option::is_none")]
    pub type_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(rename = "chainKey", default, skip_serializing_if = "Option::is_none")]
    pub chain_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub subject: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub actor: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub target: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSeqOriginAtInitial {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presented: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSeqOriginAtIntermediary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presented: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSeqOriginAtTarget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presented: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSeqOriginAtConsumedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSeqOriginAtProducedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSeqOriginAt {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub origin: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(rename = "typeLabel", default, skip_serializing_if = "Option::is_none")]
    pub type_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial: Option<WithSeqOriginAtInitial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediary: Option<WithSeqOriginAtIntermediary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<WithSeqOriginAtTarget>,
    #[serde(rename = "authorizedBy", default, skip_serializing_if = "Option::is_none")]
    pub authorized_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumed: Option<Vec<WithSeqOriginAtConsumedItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub produced: Option<Vec<WithSeqOriginAtProducedItem>>,
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(rename = "chainKey", default, skip_serializing_if = "Option::is_none")]
    pub chain_key: Option<String>,
}

pub type WithSeqOriginAt2 = Vec<crate::WithAtFamilyKind>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSeqOriginAt3Initial {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presented: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSeqOriginAt3Intermediary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presented: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSeqOriginAt3Target {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presented: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSeqOriginAt3ConsumedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSeqOriginAt3ProducedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSeqOriginAt3 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub at: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(rename = "typeLabel", default, skip_serializing_if = "Option::is_none")]
    pub type_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial: Option<WithSeqOriginAt3Initial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediary: Option<WithSeqOriginAt3Intermediary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<WithSeqOriginAt3Target>,
    #[serde(rename = "authorizedBy", default, skip_serializing_if = "Option::is_none")]
    pub authorized_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumed: Option<Vec<WithSeqOriginAt3ConsumedItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub produced: Option<Vec<WithSeqOriginAt3ProducedItem>>,
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(rename = "chainKey", default, skip_serializing_if = "Option::is_none")]
    pub chain_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSerialHexEntryEntryUriEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSerialHexEntryEntryUriRequestedBy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSerialHexEntryEntryUriRevoked {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSerialHexEntryEntryUri {
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<WithSerialHexEntryEntryUriEntry>,
    #[serde(rename = "entryUri", default, skip_serializing_if = "Option::is_none")]
    pub entry_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub profile: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub subject: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
    #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
    pub key_alg: Option<String>,
    #[serde(rename = "keySource", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub key_source: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub via: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub issued_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "requestedBy", default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<WithSerialHexEntryEntryUriRequestedBy>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub replaces: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<WithSerialHexEntryEntryUriRevoked>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub thumbprint: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub account: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSerialHexLabelSubject {
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
    pub key_alg: Option<String>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub not_before: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub not_after: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub reason: Option<Option<String>>,
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub revoked_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
    pub certificate_pem: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSerialHexLabelSubject2 {
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub label: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub subject: Option<Option<String>>,
    #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub key_alg: Option<Option<String>>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub not_before: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub not_after: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub thumbprint: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub reason: Option<Option<String>>,
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub revoked_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub certificate_pem: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub slot: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSerialHexRevokedAtReason {
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub revoked_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "reasonCode", default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<f64>,
    #[serde(rename = "reasonWhat", default, skip_serializing_if = "Option::is_none")]
    pub reason_what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSerialHexRevokedAtReason2 {
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub revoked_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "reasonCode", default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<i64>,
    #[serde(rename = "reasonWhat", default, skip_serializing_if = "Option::is_none")]
    pub reason_what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSerialHexSubjectKeyAlg {
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
    pub key_alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub not_before: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub not_after: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
    pub certificate_pem: Option<String>,
    #[serde(rename = "chainPem", default, skip_serializing_if = "Option::is_none")]
    pub chain_pem: Option<Vec<String>>,
    #[serde(rename = "implicitName", default, skip_serializing_if = "Option::is_none")]
    pub implicit_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithSerialHexSubjectKeyAlg2ChainPem {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSerialHexSubjectKeyAlg2 {
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
    pub key_alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub label: Option<Option<String>>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
    pub certificate_pem: Option<String>,
    #[serde(rename = "chainPem", default, skip_serializing_if = "Option::is_none")]
    pub chain_pem: Option<WithSerialHexSubjectKeyAlg2ChainPem>,
    #[serde(rename = "implicitName", default, skip_serializing_if = "Option::is_none")]
    pub implicit_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSha256SubjectIssuer {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(rename = "serialNumber", default, skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readable: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithShapeLabelSublabel {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shape: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sublabel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub identifier: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dashed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSinceSinceIsoInProgress {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<f64>,
    #[serde(rename = "sinceIso", default, skip_serializing_if = "Option::is_none")]
    pub since_iso: Option<String>,
    #[serde(rename = "inProgress", default, skip_serializing_if = "Option::is_none")]
    pub in_progress: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interrupted: Option<bool>,
    #[serde(rename = "finishesBy", default, skip_serializing_if = "Option::is_none")]
    pub finishes_by: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusing: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finish: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSlotLabelSerialHex {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
    pub key_alg: Option<String>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub not_before: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub not_after: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub revoked_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub reason: Option<Option<String>>,
    #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
    pub certificate_pem: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithStateFormatResponseType {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(rename = "responseType", default, skip_serializing_if = "Option::is_none")]
    pub response_type: Option<String>,
    #[serde(rename = "responseMode", default, skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<String>,
    #[serde(rename = "byReference", default, skip_serializing_if = "Option::is_none")]
    pub by_reference: Option<bool>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested: Option<Vec<String>>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ok: Option<Option<bool>>,
    #[serde(rename = "decidedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub decided_at: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<String>>,
    #[serde(rename = "failedChecks", default, skip_serializing_if = "Option::is_none")]
    pub failed_checks: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSubJwksType {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<sts_model_management_components_2::JwkSetMetadataDocumentMetadata>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSubjectAnchorExpiresAtChainItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSubjectAnchorExpiresAt {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<Vec<WithSubjectAnchorExpiresAtChainItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<sts_model_management_components_2::JwkSetMetadataDocumentMetadata>,
    #[serde(rename = "trustMarks", default, skip_serializing_if = "Option::is_none")]
    pub trust_marks: Option<Vec<Option<String>>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSubjectIssuerSerial {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub subject: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub issuer: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub serial: Option<Option<String>>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub not_before: Option<Option<String>>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub not_after: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persisted: Option<bool>,
    #[serde(rename = "addedAt", default, skip_serializing_if = "Option::is_none")]
    pub added_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unadmittable: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSubjectIssuerSerialHex {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    #[serde(rename = "notYetValid", default, skip_serializing_if = "Option::is_none")]
    pub not_yet_valid: Option<bool>,
    #[serde(rename = "daysRemaining", default, skip_serializing_if = "Option::is_none")]
    pub days_remaining: Option<i64>,
    #[serde(rename = "publicKey", default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(rename = "signatureAlgorithm", default, skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<String>,
    #[serde(rename = "selfIssued", default, skip_serializing_if = "Option::is_none")]
    pub self_issued: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<bool>,
    #[serde(rename = "extensionCount", default, skip_serializing_if = "Option::is_none")]
    pub extension_count: Option<i64>,
}

pub type WithSubjectLabelEnrolledAt = Vec<crate::WithSha256SubjectIssuer>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSubjectLabelEnrolledAt2Location {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSubjectLabelEnrolledAt2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(rename = "enrolledAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub enrolled_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    #[serde(rename = "provedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub proved_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
    pub key_alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<WithSubjectLabelEnrolledAt2Location>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred: Option<bool>,
    #[serde(rename = "pinnedKeys", default, skip_serializing_if = "Option::is_none")]
    pub pinned_keys: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithTbsCertificateSignatureAlgorithmSignatureAlgorithmsAgreeSignatureAlgorithm {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub parameters: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithTbsCertificateSignatureAlgorithmSignatureAlgorithmsAgreeSignatureValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub octets: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hex: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithTbsCertificateSignatureAlgorithmSignatureAlgorithmsAgree {
    #[serde(rename = "tbsCertificate", default, skip_serializing_if = "Option::is_none")]
    pub tbs_certificate: Option<crate::WithVersionValueEncoded2>,
    #[serde(rename = "signatureAlgorithm", default, skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<WithTbsCertificateSignatureAlgorithmSignatureAlgorithmsAgreeSignatureAlgorithm>,
    #[serde(rename = "signatureAlgorithmsAgree", default, skip_serializing_if = "Option::is_none")]
    pub signature_algorithms_agree: Option<bool>,
    #[serde(rename = "signatureValue", default, skip_serializing_if = "Option::is_none")]
    pub signature_value: Option<WithTbsCertificateSignatureAlgorithmSignatureAlgorithmsAgreeSignatureValue>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithTextAttributesOidAttributesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithTextAttributesOid {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<WithTextAttributesOidAttributesItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithThreadIdSlotReady {
    #[serde(rename = "threadId", default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<sts_model_base::unions::IntegerOrString>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub slot: Option<Option<sts_model_base::unions::IntegerOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub busy: Option<bool>,
    #[serde(rename = "inFlight", default, skip_serializing_if = "Option::is_none")]
    pub in_flight: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub served: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retiring: Option<bool>,
    #[serde(rename = "upSeconds", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub up_seconds: Option<Option<f64>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithTotalEntriesSliceSlice {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithTotalEntriesSlice {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entries: Option<crate::WithKeyNamesLabel2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slice: Option<WithTotalEntriesSliceSlice>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub complete: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithTotpKeysBackupCodesKeysItem {
    #[serde(rename = "credentialId", default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(rename = "enrolledAt", default, skip_serializing_if = "Option::is_none")]
    pub enrolled_at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithTotpKeysBackupCodes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<WithTotpKeysBackupCodesKeysItem>>,
    #[serde(rename = "backupCodes", default, skip_serializing_if = "Option::is_none")]
    pub backup_codes: Option<bool>,
}

pub type WithTrustDomainTrustDomainIdX509Keys = Vec<crate::WithAddressListeningError>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithTrustDomainTrustDomainIdX509Keys2 {
    #[serde(rename = "trustDomain", default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<String>,
    #[serde(rename = "trustDomainId", default, skip_serializing_if = "Option::is_none")]
    pub trust_domain_id: Option<String>,
    #[serde(rename = "x509Keys", default, skip_serializing_if = "Option::is_none")]
    pub x509_keys: Option<i64>,
    #[serde(rename = "jwtKeys", default, skip_serializing_if = "Option::is_none")]
    pub jwt_keys: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<f64>,
    #[serde(rename = "refreshHint", default, skip_serializing_if = "Option::is_none")]
    pub refresh_hint: Option<f64>,
    #[serde(rename = "bundleEndpointUrl", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub bundle_endpoint_url: Option<Option<String>>,
    #[serde(rename = "bundleEndpointProfile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub bundle_endpoint_profile: Option<Option<String>>,
    #[serde(rename = "endpointSpiffeId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub endpoint_spiffe_id: Option<Option<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub updated_at: Option<Option<sts_model_base::unions::NumberOrString>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithTrustRealmKerberosRealmEnabled {
    #[serde(rename = "trustRealm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub trust_realm: Option<Option<String>>,
    #[serde(rename = "kerberosRealm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub kerberos_realm: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub reason: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub served: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithTypeIssuersOwner {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuers: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<crate::WithSubJwksType>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithTypeWidthHeight {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(rename = "updatedBy", default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src: Option<String>,
}

pub type WithUrlRowsSerial = Vec<crate::WithNameCoseAlgOffered>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithUrlRowsSerial2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(rename = "loadedAt", default, skip_serializing_if = "Option::is_none")]
    pub loaded_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known: Option<bool>,
    #[serde(rename = "nextUpdateAt", default, skip_serializing_if = "Option::is_none")]
    pub next_update_at: Option<f64>,
}

pub type WithUsernameDnKind = Vec<crate::WithAlgorithmCoseAlgPostQuantum>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithUsernameDnKind2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passkeys: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<crate::WithUsernameDnKind>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithUsersAppsName {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apps: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithValueAttributeHolds {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holds: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(rename = "userKey", default, skip_serializing_if = "Option::is_none")]
    pub user_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail: Option<String>,
    #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithVctvaluesDoctypevalueTypevaluesTypeValuesItem {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithVctvaluesDoctypevalueTypevalues {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vct_values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doctype_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_values: Option<Vec<WithVctvaluesDoctypevalueTypevaluesTypeValuesItem>>,
}

pub type WithVersionValueEncoded = Vec<crate::WithOidNameLabel>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithVersionValueEncoded2Version {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoded: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithVersionValueEncoded2SerialNumber {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decimal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub octets: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithVersionValueEncoded2Signature {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub parameters: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithVersionValueEncoded2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<WithVersionValueEncoded2Version>,
    #[serde(rename = "serialNumber", default, skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<WithVersionValueEncoded2SerialNumber>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<WithVersionValueEncoded2Signature>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<crate::WithTextAttributesOid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validity: Option<crate::WithNotBeforeNotAfterAdditionalProperties>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<crate::WithTextAttributesOid>,
    #[serde(rename = "subjectPublicKeyInfo", default, skip_serializing_if = "Option::is_none")]
    pub subject_public_key_info: Option<crate::WithAlgorithmDescriptionKey>,
    #[serde(rename = "issuerUniqueID", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub issuer_unique_id: Option<Option<String>>,
    #[serde(rename = "subjectUniqueID", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub subject_unique_id: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<crate::WithVersionValueEncoded>,
}

pub type X = serde_json::Value;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlSettingsGroupsItemSettingsItemSelectAllOnlyWhileOnItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(rename = "canBeOn", default, skip_serializing_if = "Option::is_none")]
    pub can_be_on: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlSettingsGroupsItemSettingsItemSelectAllAloneWhileOnItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(rename = "canBeOn", default, skip_serializing_if = "Option::is_none")]
    pub can_be_on: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlSettingsGroupsItemSettingsItemSelectAll {
    #[serde(rename = "onlyWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub only_while_on: Option<Vec<XacmlSettingsGroupsItemSettingsItemSelectAllOnlyWhileOnItem>>,
    #[serde(rename = "aloneWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub alone_while_on: Option<Vec<XacmlSettingsGroupsItemSettingsItemSelectAllAloneWhileOnItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum XacmlSettingsGroupsItemSettingsItemValue {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum XacmlSettingsGroupsItemSettingsItemEnv {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum XacmlSettingsGroupsItemSettingsItemLegacyEnv {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum XacmlSettingsGroupsItemSettingsItemDefault {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlSettingsGroupsItemSettingsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(rename = "enumValues", default, skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
    #[serde(rename = "csvValues", default, skip_serializing_if = "Option::is_none")]
    pub csv_values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordered: Option<bool>,
    #[serde(rename = "csvValueNotes", default, skip_serializing_if = "Option::is_none")]
    pub csv_value_notes: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "selectAll", default, skip_serializing_if = "Option::is_none")]
    pub select_all: Option<XacmlSettingsGroupsItemSettingsItemSelectAll>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<XacmlSettingsGroupsItemSettingsItemValue>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub text: Option<Option<sts_model_base::unions::BoolOrNumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<bool>,
    #[serde(rename = "restartReason", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub restart_reason: Option<Option<String>>,
    #[serde(rename = "editRefusal", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub edit_refusal: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub env: Option<Option<XacmlSettingsGroupsItemSettingsItemEnv>>,
    #[serde(rename = "legacyEnv", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub legacy_env: Option<Option<XacmlSettingsGroupsItemSettingsItemLegacyEnv>>,
    #[serde(rename = "appconfigPath", default, skip_serializing_if = "Option::is_none")]
    pub appconfig_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default: Option<Option<XacmlSettingsGroupsItemSettingsItemDefault>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlSettingsGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<XacmlSettingsGroupsItemSettingsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlSettingsContext {
    #[serde(rename = "configFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub config_file: Option<Option<String>>,
    #[serde(rename = "defaultsFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub defaults_file: Option<Option<String>>,
    #[serde(rename = "persistsAppconfig", default, skip_serializing_if = "Option::is_none")]
    pub persists_appconfig: Option<bool>,
    #[serde(rename = "persistsRealms", default, skip_serializing_if = "Option::is_none")]
    pub persists_realms: Option<bool>,
    #[serde(rename = "persistenceMode", default, skip_serializing_if = "Option::is_none")]
    pub persistence_mode: Option<String>,
    #[serde(rename = "inRealm", default, skip_serializing_if = "Option::is_none")]
    pub in_realm: Option<bool>,
    #[serde(rename = "realmId", default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<XacmlSettingsGroupsItem>>,
    #[serde(rename = "settingCount", default, skip_serializing_if = "Option::is_none")]
    pub setting_count: Option<i64>,
    #[serde(rename = "editableCount", default, skip_serializing_if = "Option::is_none")]
    pub editable_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<Vec<String>>,
    #[serde(rename = "setWith", default, skip_serializing_if = "Option::is_none")]
    pub set_with: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<XacmlSettingsContext>,
    #[serde(rename = "sharedWith", default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlProtocolEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listening: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Xacml {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xacml: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policies: Option<i64>,
    #[serde(rename = "enabledPolicies", default, skip_serializing_if = "Option::is_none")]
    pub enabled_policies: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub root: Option<Option<String>>,
    #[serde(rename = "pipAvailable", default, skip_serializing_if = "Option::is_none")]
    pub pip_available: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<XacmlSettings>,
    #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
    pub protocol_endpoints: Option<Vec<XacmlProtocolEndpointsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlDecisionStatusDetail {
    #[serde(rename = "attributeId", default, skip_serializing_if = "Option::is_none")]
    pub attribute_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(rename = "dataType", default, skip_serializing_if = "Option::is_none")]
    pub data_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lexical: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlDecisionStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub message: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<XacmlDecisionStatusDetail>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlDecisionApplicablePoliciesItemV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum XacmlDecisionApplicablePoliciesItem {
    V1(XacmlDecisionApplicablePoliciesItemV1),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlDecisionEnforcement {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bias: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub why: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlDecisionEnforcementsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bias: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub why: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlDecisionProtocolEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listening: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlDecision {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xacml: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub resource: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<XacmlDecisionStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obligations: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advice: Option<Vec<String>>,
    #[serde(rename = "applicablePolicies", default, skip_serializing_if = "Option::is_none")]
    pub applicable_policies: Option<Vec<XacmlDecisionApplicablePoliciesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforcement: Option<XacmlDecisionEnforcement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforcements: Option<Vec<XacmlDecisionEnforcementsItem>>,
    #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
    pub protocol_endpoints: Option<Vec<XacmlDecisionProtocolEndpointsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlEditorServiceOwnItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decides: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(rename = "builtIn", default, skip_serializing_if = "Option::is_none")]
    pub built_in: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub enabled: Option<Option<bool>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<String>,
    #[serde(rename = "readsRisk", default, skip_serializing_if = "Option::is_none")]
    pub reads_risk: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlEditorPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "isRoot", default, skip_serializing_if = "Option::is_none")]
    pub is_root: Option<bool>,
    #[serde(rename = "policyId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub policy_id: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub kind: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub version: Option<Option<String>>,
    #[serde(rename = "combiningAlgId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub combining_alg_id: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub description: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlEditorTreeItemOptionsAdditionsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlEditorTreeItemOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additions: Option<Vec<XacmlEditorTreeItemOptionsAdditionsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlEditorTreeItemEditNodeValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lexical: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespaces: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "xpathCategory", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub xpath_category: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub category: Option<Option<String>>,
    #[serde(rename = "attributeId", default, skip_serializing_if = "Option::is_none")]
    pub attribute_id: Option<String>,
    #[serde(rename = "dataType", default, skip_serializing_if = "Option::is_none")]
    pub data_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub issuer: Option<Option<String>>,
    #[serde(rename = "mustBePresent", default, skip_serializing_if = "Option::is_none")]
    pub must_be_present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(rename = "contextSelectorId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub context_selector_id: Option<Option<String>>,
    #[serde(rename = "functionId", default, skip_serializing_if = "Option::is_none")]
    pub function_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub description: Option<Option<String>>,
    #[serde(rename = "variableId", default, skip_serializing_if = "Option::is_none")]
    pub variable_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlEditorTreeItemEditNodeReference {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lexical: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespaces: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "xpathCategory", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub xpath_category: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub category: Option<Option<String>>,
    #[serde(rename = "attributeId", default, skip_serializing_if = "Option::is_none")]
    pub attribute_id: Option<String>,
    #[serde(rename = "dataType", default, skip_serializing_if = "Option::is_none")]
    pub data_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub issuer: Option<Option<String>>,
    #[serde(rename = "mustBePresent", default, skip_serializing_if = "Option::is_none")]
    pub must_be_present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(rename = "contextSelectorId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub context_selector_id: Option<Option<String>>,
    #[serde(rename = "functionId", default, skip_serializing_if = "Option::is_none")]
    pub function_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub description: Option<Option<String>>,
    #[serde(rename = "variableId", default, skip_serializing_if = "Option::is_none")]
    pub variable_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlEditorTreeItemEditNode {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub description: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub version: Option<Option<String>>,
    #[serde(rename = "combiningAlgId", default, skip_serializing_if = "Option::is_none")]
    pub combining_alg_id: Option<String>,
    #[serde(rename = "xpathVersion", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub xpath_version: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<()>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<()>,
    #[serde(rename = "maxDelegationDepth", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub max_delegation_depth: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<String>,
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    pub ref_: Option<String>,
    #[serde(rename = "matchId", default, skip_serializing_if = "Option::is_none")]
    pub match_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<XacmlEditorTreeItemEditNodeValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<XacmlEditorTreeItemEditNodeReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespaces: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lexical: Option<String>,
    #[serde(rename = "xpathCategory", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub xpath_category: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub category: Option<Option<String>>,
    #[serde(rename = "attributeId", default, skip_serializing_if = "Option::is_none")]
    pub attribute_id: Option<String>,
    #[serde(rename = "dataType", default, skip_serializing_if = "Option::is_none")]
    pub data_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub issuer: Option<Option<String>>,
    #[serde(rename = "mustBePresent", default, skip_serializing_if = "Option::is_none")]
    pub must_be_present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(rename = "contextSelectorId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub context_selector_id: Option<Option<String>>,
    #[serde(rename = "functionId", default, skip_serializing_if = "Option::is_none")]
    pub function_id: Option<String>,
    #[serde(rename = "variableId", default, skip_serializing_if = "Option::is_none")]
    pub variable_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlEditorTreeItemEditAlgorithmsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlEditorTreeItemEditScopeItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlEditorTreeItemEdit {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<XacmlEditorTreeItemEditNode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithms: Option<Vec<XacmlEditorTreeItemEditAlgorithmsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Vec<XacmlEditorTreeItemEditScopeItem>>,
    #[serde(rename = "valueShortType", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value_short_type: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlEditorTreeItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<XacmlEditorTreeItemOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edit: Option<XacmlEditorTreeItemEdit>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlEditorMenusTypesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlEditorMenusCategoriesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlEditorMenusFunctionsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlEditorMenusMatchFunctionsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlEditorMenus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub types: Option<Vec<XacmlEditorMenusTypesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub categories: Option<Vec<XacmlEditorMenusCategoriesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub functions: Option<Vec<XacmlEditorMenusFunctionsItem>>,
    #[serde(rename = "matchFunctions", default, skip_serializing_if = "Option::is_none")]
    pub match_functions: Option<Vec<XacmlEditorMenusMatchFunctionsItem>>,
    #[serde(rename = "xpathType", default, skip_serializing_if = "Option::is_none")]
    pub xpath_type: Option<String>,
    #[serde(rename = "resourceCategory", default, skip_serializing_if = "Option::is_none")]
    pub resource_category: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlEditorProtocolEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listening: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlEditor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xacml: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policies: Option<Vec<String>>,
    #[serde(rename = "serviceOwn", default, skip_serializing_if = "Option::is_none")]
    pub service_own: Option<Vec<XacmlEditorServiceOwnItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<XacmlEditorPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub problem: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree: Option<Vec<XacmlEditorTreeItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub menus: Option<XacmlEditorMenus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<Option<String>>>,
    #[serde(rename = "xpathVersionGaps", default, skip_serializing_if = "Option::is_none")]
    pub xpath_version_gaps: Option<Vec<Option<String>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub alfa: Option<Option<String>>,
    #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
    pub protocol_endpoints: Option<Vec<XacmlEditorProtocolEndpointsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlMonitorPolicies {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub root: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlMonitorPeps {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedded: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlMonitorDecisionsHere {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decisions: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unenforced: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undischargeable: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlMonitorDecisionsRemote {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decisions: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unenforced: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undischargeable: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlMonitorDecisionsCombined {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decisions: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unenforced: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undischargeable: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlMonitorDecisions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub here: Option<XacmlMonitorDecisionsHere>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<XacmlMonitorDecisionsRemote>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub combined: Option<XacmlMonitorDecisionsCombined>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlMonitorRealm {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlMonitorRowsItemRemote {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated: Option<bool>,
    #[serde(rename = "certificateSubject", default, skip_serializing_if = "Option::is_none")]
    pub certificate_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "registeredAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub registered_at: Option<Option<String>>,
    #[serde(rename = "lastSeen", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_seen: Option<Option<String>>,
    #[serde(rename = "syncToken", default, skip_serializing_if = "Option::is_none")]
    pub sync_token: Option<String>,
    #[serde(rename = "policyCount", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub policy_count: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(rename = "lastNotify", default, skip_serializing_if = "Option::is_none")]
    pub last_notify: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlMonitorRowsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
    pub where_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guards: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforces: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub bias: Option<Option<String>>,
    #[serde(rename = "dischargesObligations", default, skip_serializing_if = "Option::is_none")]
    pub discharges_obligations: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decisions: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub allowed: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub refused: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub permit: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub deny: Option<Option<i64>>,
    #[serde(rename = "notApplicable", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub not_applicable: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub indeterminate: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub other: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undischargeable: Option<i64>,
    #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "lastDecision", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_decision: Option<Option<String>>,
    #[serde(rename = "lastAllowed", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_allowed: Option<Option<bool>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<XacmlMonitorRowsItemRemote>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlMonitorRemoteRowsItemRemote {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated: Option<bool>,
    #[serde(rename = "certificateSubject", default, skip_serializing_if = "Option::is_none")]
    pub certificate_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "registeredAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub registered_at: Option<Option<String>>,
    #[serde(rename = "lastSeen", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_seen: Option<Option<String>>,
    #[serde(rename = "syncToken", default, skip_serializing_if = "Option::is_none")]
    pub sync_token: Option<String>,
    #[serde(rename = "policyCount", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub policy_count: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(rename = "lastNotify", default, skip_serializing_if = "Option::is_none")]
    pub last_notify: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlMonitorRemoteRowsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
    pub where_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guards: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforces: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub bias: Option<Option<String>>,
    #[serde(rename = "dischargesObligations", default, skip_serializing_if = "Option::is_none")]
    pub discharges_obligations: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decisions: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub allowed: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub refused: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub permit: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub deny: Option<Option<i64>>,
    #[serde(rename = "notApplicable", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub not_applicable: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub indeterminate: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub other: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undischargeable: Option<i64>,
    #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "lastDecision", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_decision: Option<Option<String>>,
    #[serde(rename = "lastAllowed", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_allowed: Option<Option<bool>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<XacmlMonitorRemoteRowsItemRemote>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlMonitorElsewhereItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlMonitorProtocolEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listening: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlMonitor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xacml: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policies: Option<XacmlMonitorPolicies>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peps: Option<XacmlMonitorPeps>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decisions: Option<XacmlMonitorDecisions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "remotePepsEnabled", default, skip_serializing_if = "Option::is_none")]
    pub remote_peps_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<XacmlMonitorRealm>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<XacmlMonitorRowsItem>>,
    #[serde(rename = "remoteRows", default, skip_serializing_if = "Option::is_none")]
    pub remote_rows: Option<Vec<XacmlMonitorRemoteRowsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elsewhere: Option<Vec<XacmlMonitorElsewhereItem>>,
    #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
    pub protocol_endpoints: Option<Vec<XacmlMonitorProtocolEndpointsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlPepsNotifyTransport {
    #[serde(rename = "allowHttp", default, skip_serializing_if = "Option::is_none")]
    pub allow_http: Option<bool>,
    #[serde(rename = "skipTlsVerificationSet", default, skip_serializing_if = "Option::is_none")]
    pub skip_tls_verification_set: Option<bool>,
    #[serde(rename = "skipTlsVerification", default, skip_serializing_if = "Option::is_none")]
    pub skip_tls_verification: Option<bool>,
    #[serde(rename = "caFile", default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlPepsNotify {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(rename = "allowedHosts", default, skip_serializing_if = "Option::is_none")]
    pub allowed_hosts: Option<Vec<String>>,
    #[serde(rename = "timeoutMs", default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<XacmlPepsNotifyTransport>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlPepsPepsItemListenerCertificate {
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
    #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
    pub key_alg: Option<String>,
    #[serde(rename = "signatureAlg", default, skip_serializing_if = "Option::is_none")]
    pub signature_alg: Option<String>,
    #[serde(rename = "dnsNames", default, skip_serializing_if = "Option::is_none")]
    pub dns_names: Option<Vec<String>>,
    #[serde(rename = "ipAddresses", default, skip_serializing_if = "Option::is_none")]
    pub ip_addresses: Option<Vec<String>>,
    #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<String>,
    #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
    pub certificate_pem: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlPepsPepsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    #[serde(rename = "certificateSubject", default, skip_serializing_if = "Option::is_none")]
    pub certificate_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated: Option<bool>,
    #[serde(rename = "notifyUrl", default, skip_serializing_if = "Option::is_none")]
    pub notify_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bias: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "registeredAt", default, skip_serializing_if = "Option::is_none")]
    pub registered_at: Option<String>,
    #[serde(rename = "lastSeen", default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    #[serde(rename = "syncToken", default, skip_serializing_if = "Option::is_none")]
    pub sync_token: Option<String>,
    #[serde(rename = "policyCount", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub policy_count: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub decisions: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub allowed: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub refused: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub undischargeable: Option<Option<f64>>,
    #[serde(rename = "lastNotify", default, skip_serializing_if = "Option::is_none")]
    pub last_notify: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
    #[serde(rename = "notifyProblem", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub notify_problem: Option<Option<String>>,
    #[serde(rename = "listenerCertificate", default, skip_serializing_if = "Option::is_none")]
    pub listener_certificate: Option<XacmlPepsPepsItemListenerCertificate>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlPepsElsewhereItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlPepsListenerCertificates {
    #[serde(rename = "useCase", default, skip_serializing_if = "Option::is_none")]
    pub use_case: Option<String>,
    #[serde(rename = "keyAlgorithms", default, skip_serializing_if = "Option::is_none")]
    pub key_algorithms: Option<Vec<String>>,
    #[serde(rename = "defaultKeyAlg", default, skip_serializing_if = "Option::is_none")]
    pub default_key_alg: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlPepsProtocolEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listening: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlPeps {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xacml: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "syncToken", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub sync_token: Option<Option<String>>,
    #[serde(rename = "staleAfterS", default, skip_serializing_if = "Option::is_none")]
    pub stale_after_s: Option<f64>,
    #[serde(rename = "requiresCertificate", default, skip_serializing_if = "Option::is_none")]
    pub requires_certificate: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify: Option<XacmlPepsNotify>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peps: Option<Vec<XacmlPepsPepsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elsewhere: Option<Vec<XacmlPepsElsewhereItem>>,
    #[serde(rename = "listenerCertificates", default, skip_serializing_if = "Option::is_none")]
    pub listener_certificates: Option<XacmlPepsListenerCertificates>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale: Option<i64>,
    #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
    pub protocol_endpoints: Option<Vec<XacmlPepsProtocolEndpointsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlPoliciesPoliciesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "policyId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub policy_id: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "isRoot", default, skip_serializing_if = "Option::is_none")]
    pub is_root: Option<bool>,
    #[serde(rename = "combiningAlgId", default, skip_serializing_if = "Option::is_none")]
    pub combining_alg_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub application: Option<Option<String>>,
    #[serde(rename = "orphanedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub orphaned_at: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlPoliciesApplicationPoliciesItemPoliciesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "policyId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub policy_id: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "orphanedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub orphaned_at: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referenced: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlPoliciesApplicationPoliciesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforced: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policies: Option<Vec<XacmlPoliciesApplicationPoliciesItemPoliciesItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlPoliciesTemplatesItemParametersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub help: Option<Option<String>>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub dflt: Option<Option<sts_model_base::unions::BoolOrNumberOrString>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlPoliciesTemplatesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blurb: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Vec<XacmlPoliciesTemplatesItemParametersItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlPoliciesServiceOwnItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decides: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(rename = "builtIn", default, skip_serializing_if = "Option::is_none")]
    pub built_in: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub enabled: Option<Option<bool>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<String>,
    #[serde(rename = "readsRisk", default, skip_serializing_if = "Option::is_none")]
    pub reads_risk: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlPoliciesProtocolEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listening: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlPolicies {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xacml: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub root: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policies: Option<Vec<XacmlPoliciesPoliciesItem>>,
    #[serde(rename = "applicationPolicies", default, skip_serializing_if = "Option::is_none")]
    pub application_policies: Option<Vec<XacmlPoliciesApplicationPoliciesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub templates: Option<Vec<XacmlPoliciesTemplatesItem>>,
    #[serde(rename = "serviceOwn", default, skip_serializing_if = "Option::is_none")]
    pub service_own: Option<Vec<XacmlPoliciesServiceOwnItem>>,
    #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
    pub protocol_endpoints: Option<Vec<XacmlPoliciesProtocolEndpointsItem>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum XacmlServiceOwnPolicyKey {
    #[serde(rename = "issuance")]
    Issuance,
    #[serde(rename = "access")]
    Access,
}

/// One policy this service decides its OWN boundaries with. Built in and called
/// at decision time rather than stored, so it is not in the repository — a
/// repository entry of the same name overrides it.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct XacmlServiceOwnPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<XacmlServiceOwnPolicyKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The entry name an override must be given for the PEP to pick it up. It
    /// is what `setting` says, NOT the template id — those are the same word
    /// today and need not be.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The config.js key that names it: `xacml.issuancePolicy` or
    /// `xacml.accessPolicy`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    /// The template the built-in document is built from, and the one an
    /// override should be created from so that the two start identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decides: Option<String>,
    /// Which gate asks it, and from how many sites.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<String>,
    /// Whether a repository entry of that name EXISTS. A separate fact from
    /// `builtIn`: "nobody wrote an override" and "somebody wrote one and
    /// disabled it" are opposite situations that `builtIn` alone cannot tell
    /// apart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<bool>,
    /// The entry's flag, or null when there is no entry.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub enabled: Option<Option<bool>>,
    /// Whether the BUILT-IN document is what is deciding. A fact about the
    /// decision, where `entry` is a fact about the directory.
    #[serde(rename = "builtIn", default, skip_serializing_if = "Option::is_none")]
    pub built_in: Option<bool>,
    /// Whether anything is being evaluated at all. False when an override
    /// exists and is disabled or will not load — neither policy falls back to
    /// the built-in one in that case, because a Disable button that quietly
    /// evaluated something else would be a lie.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    /// Why not, when `ok` is false. Empty otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    /// One sentence naming what is deciding right now, which is what the
    /// console prints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<String>,
    /// The members the schema does not name, which it allows.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}
