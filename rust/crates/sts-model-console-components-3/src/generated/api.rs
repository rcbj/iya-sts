// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// GENERATED from models/api/ (#1390, #444) by models/lib/rust_lib.mjs.
// Do not edit: change the model and run
// tests/tools/regenerate-model-docs.sh. tests/model_domain.js fails when
// this differs.

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum Saml2ServiceProviderListProtocolEndpointsItemMethods {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListProtocolEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Saml2ServiceProviderListProtocolEndpointsItemMethods>,
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
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListServiceProvidersItem {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentications: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<f64>,
    #[serde(rename = "firstSeen", default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
    #[serde(rename = "lastSeen", default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    #[serde(rename = "assertionConsumerServices", default, skip_serializing_if = "Option::is_none")]
    pub assertion_consumer_services: Option<Vec<String>>,
    #[serde(rename = "singleLogoutServices", default, skip_serializing_if = "Option::is_none")]
    pub single_logout_services: Option<Vec<String>>,
    #[serde(rename = "nameIdFormats", default, skip_serializing_if = "Option::is_none")]
    pub name_id_formats: Option<Vec<String>>,
    #[serde(rename = "responseBindings", default, skip_serializing_if = "Option::is_none")]
    pub response_bindings: Option<Vec<String>>,
    #[serde(rename = "lastRequestSigned", default, skip_serializing_if = "Option::is_none")]
    pub last_request_signed: Option<bool>,
    #[serde(rename = "lastRequestVerification", default, skip_serializing_if = "Option::is_none")]
    pub last_request_verification: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub slug: Option<Option<String>>,
    #[serde(rename = "idpEntityId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub idp_entity_id: Option<Option<String>>,
    #[serde(rename = "metadataUrl", default, skip_serializing_if = "Option::is_none")]
    pub metadata_url: Option<String>,
    #[serde(rename = "ssoUrl", default, skip_serializing_if = "Option::is_none")]
    pub sso_url: Option<String>,
    #[serde(rename = "sloUrl", default, skip_serializing_if = "Option::is_none")]
    pub slo_url: Option<String>,
    #[serde(rename = "arsUrl", default, skip_serializing_if = "Option::is_none")]
    pub ars_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListPaging {
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
#[serde(untagged)]
pub enum Saml2ServiceProviderListSettingsGroupsItemSettingsItemValue {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum Saml2ServiceProviderListSettingsGroupsItemSettingsItemDefault {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListSettingsGroupsItemSettingsItem {
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
    /// The sentence beside each value.
    #[serde(rename = "csvValueNotes", default, skip_serializing_if = "Option::is_none")]
    pub csv_value_notes: Option<serde_json::Map<String, serde_json::Value>>,
    /// The rules by kind: onlyWhileOn and aloneWhileOn.
    #[serde(rename = "selectAll", default, skip_serializing_if = "Option::is_none")]
    pub select_all: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<Saml2ServiceProviderListSettingsGroupsItemSettingsItemValue>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub text: Option<Option<String>>,
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
    pub default: Option<Option<Saml2ServiceProviderListSettingsGroupsItemSettingsItemDefault>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListSettingsGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<Saml2ServiceProviderListSettingsGroupsItemSettingsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListSettingsContext {
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
    #[serde(rename = "realmId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm_id: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<Saml2ServiceProviderListSettingsGroupsItem>>,
    #[serde(rename = "settingCount", default, skip_serializing_if = "Option::is_none")]
    pub setting_count: Option<i64>,
    #[serde(rename = "editableCount", default, skip_serializing_if = "Option::is_none")]
    pub editable_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<Vec<String>>,
    #[serde(rename = "setWith", default, skip_serializing_if = "Option::is_none")]
    pub set_with: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Saml2ServiceProviderListSettingsContext>,
    /// The other pages, by settings group.
    #[serde(rename = "sharedWith", default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListMdqRefusedItem {
    #[serde(rename = "entityId", default, skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(rename = "firstAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub first_at: Option<Option<String>>,
    #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_at: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListMdqRefusedPaging {
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
pub struct Saml2ServiceProviderListLastRequestVerification {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<String>,
    #[serde(rename = "signatureMethod", default, skip_serializing_if = "Option::is_none")]
    pub signature_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weak: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListSignedRequestsRequired {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListMetadataRefresh {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    #[serde(rename = "lastSuccessAt", default, skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<String>,
    #[serde(rename = "failingSince", default, skip_serializing_if = "Option::is_none")]
    pub failing_since: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListMetadataAssertionConsumerServicesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<String>,
    #[serde(rename = "isDefault", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub is_default: Option<Option<bool>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListMetadataSingleLogoutServicesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(rename = "responseLocation", default, skip_serializing_if = "Option::is_none")]
    pub response_location: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderListMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(rename = "stateWhy", default, skip_serializing_if = "Option::is_none")]
    pub state_why: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(rename = "staleAt", default, skip_serializing_if = "Option::is_none")]
    pub stale_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refreshable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh: Option<Saml2ServiceProviderListMetadataRefresh>,
    #[serde(rename = "refresherEnabled", default, skip_serializing_if = "Option::is_none")]
    pub refresher_enabled: Option<bool>,
    #[serde(rename = "refresherRunning", default, skip_serializing_if = "Option::is_none")]
    pub refresher_running: Option<bool>,
    #[serde(rename = "trustAnchors", default, skip_serializing_if = "Option::is_none")]
    pub trust_anchors: Option<f64>,
    #[serde(rename = "trustAnchorProblems", default, skip_serializing_if = "Option::is_none")]
    pub trust_anchor_problems: Option<Vec<String>>,
    #[serde(rename = "mdqUrl", default, skip_serializing_if = "Option::is_none")]
    pub mdq_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumed: Option<bool>,
    #[serde(rename = "consumedAt", default, skip_serializing_if = "Option::is_none")]
    pub consumed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub how: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(rename = "signingCertificateConfigured", default, skip_serializing_if = "Option::is_none")]
    pub signing_certificate_configured: Option<bool>,
    #[serde(rename = "validUntil", default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    #[serde(rename = "cacheDuration", default, skip_serializing_if = "Option::is_none")]
    pub cache_duration: Option<String>,
    #[serde(rename = "authnRequestsSigned", default, skip_serializing_if = "Option::is_none")]
    pub authn_requests_signed: Option<bool>,
    #[serde(rename = "wantAssertionsSigned", default, skip_serializing_if = "Option::is_none")]
    pub want_assertions_signed: Option<bool>,
    #[serde(rename = "wantAssertionsEncrypted", default, skip_serializing_if = "Option::is_none")]
    pub want_assertions_encrypted: Option<bool>,
    #[serde(rename = "nameIdFormats", default, skip_serializing_if = "Option::is_none")]
    pub name_id_formats: Option<Vec<String>>,
    #[serde(rename = "assertionConsumerServices", default, skip_serializing_if = "Option::is_none")]
    pub assertion_consumer_services: Option<Vec<Saml2ServiceProviderListMetadataAssertionConsumerServicesItem>>,
    #[serde(rename = "singleLogoutServices", default, skip_serializing_if = "Option::is_none")]
    pub single_logout_services: Option<Vec<Saml2ServiceProviderListMetadataSingleLogoutServicesItem>>,
    #[serde(rename = "encryptionCertificate", default, skip_serializing_if = "Option::is_none")]
    pub encryption_certificate: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saml2ServiceProviderList {
    #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
    pub protocol_endpoints: Option<Vec<Saml2ServiceProviderListProtocolEndpointsItem>>,
    #[serde(rename = "serviceProviders", default, skip_serializing_if = "Option::is_none")]
    pub service_providers: Option<Vec<Saml2ServiceProviderListServiceProvidersItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<Saml2ServiceProviderListPaging>,
    #[serde(rename = "unscopedMetadata", default, skip_serializing_if = "Option::is_none")]
    pub unscoped_metadata: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Saml2ServiceProviderListSettings>,
    #[serde(rename = "artifactsAwaitingResolution", default, skip_serializing_if = "Option::is_none")]
    pub artifacts_awaiting_resolution: Option<f64>,
    #[serde(rename = "requestsHeldForSignIn", default, skip_serializing_if = "Option::is_none")]
    pub requests_held_for_sign_in: Option<f64>,
    #[serde(rename = "mdqRefused", default, skip_serializing_if = "Option::is_none")]
    pub mdq_refused: Option<Vec<Saml2ServiceProviderListMdqRefusedItem>>,
    #[serde(rename = "mdqRefusedPaging", default, skip_serializing_if = "Option::is_none")]
    pub mdq_refused_paging: Option<Saml2ServiceProviderListMdqRefusedPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub found: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentications: Option<f64>,
    #[serde(rename = "assertionConsumerServices", default, skip_serializing_if = "Option::is_none")]
    pub assertion_consumer_services: Option<Vec<String>>,
    #[serde(rename = "singleLogoutServices", default, skip_serializing_if = "Option::is_none")]
    pub single_logout_services: Option<Vec<String>>,
    #[serde(rename = "nameIdFormats", default, skip_serializing_if = "Option::is_none")]
    pub name_id_formats: Option<Vec<String>>,
    #[serde(rename = "responseBindings", default, skip_serializing_if = "Option::is_none")]
    pub response_bindings: Option<Vec<String>>,
    #[serde(rename = "lastRequestSigned", default, skip_serializing_if = "Option::is_none")]
    pub last_request_signed: Option<bool>,
    #[serde(rename = "lastRequestVerification", default, skip_serializing_if = "Option::is_none")]
    pub last_request_verification: Option<Saml2ServiceProviderListLastRequestVerification>,
    #[serde(rename = "signingCertificate", default, skip_serializing_if = "Option::is_none")]
    pub signing_certificate: Option<String>,
    #[serde(rename = "signingCertificates", default, skip_serializing_if = "Option::is_none")]
    pub signing_certificates: Option<Vec<String>>,
    #[serde(rename = "observedSigningCertificate", default, skip_serializing_if = "Option::is_none")]
    pub observed_signing_certificate: Option<String>,
    #[serde(rename = "signedRequestsRequired", default, skip_serializing_if = "Option::is_none")]
    pub signed_requests_required: Option<Saml2ServiceProviderListSignedRequestsRequired>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Saml2ServiceProviderListMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub slug: Option<Option<String>>,
    #[serde(rename = "idpEntityId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub idp_entity_id: Option<Option<String>>,
    #[serde(rename = "metadataUrl", default, skip_serializing_if = "Option::is_none")]
    pub metadata_url: Option<String>,
    #[serde(rename = "ssoUrl", default, skip_serializing_if = "Option::is_none")]
    pub sso_url: Option<String>,
    #[serde(rename = "sloUrl", default, skip_serializing_if = "Option::is_none")]
    pub slo_url: Option<String>,
    #[serde(rename = "arsUrl", default, skip_serializing_if = "Option::is_none")]
    pub ars_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SamlAssertionsProtocolEndpointsItemMethods {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAssertionsProtocolEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<SamlAssertionsProtocolEndpointsItemMethods>,
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
#[serde(deny_unknown_fields)]
pub struct SamlAssertionsAssertions {
    #[serde(rename = "saml2LifetimeMin", default, skip_serializing_if = "Option::is_none")]
    pub saml2_lifetime_min: Option<f64>,
    #[serde(rename = "saml11LifetimeMin", default, skip_serializing_if = "Option::is_none")]
    pub saml11_lifetime_min: Option<f64>,
    #[serde(rename = "clockSkewS", default, skip_serializing_if = "Option::is_none")]
    pub clock_skew_s: Option<f64>,
    #[serde(rename = "saml2WindowS", default, skip_serializing_if = "Option::is_none")]
    pub saml2_window_s: Option<f64>,
    #[serde(rename = "saml11WindowS", default, skip_serializing_if = "Option::is_none")]
    pub saml11_window_s: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAssertionsPerApplicationItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SamlAssertionsSettingsItemValue {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SamlAssertionsSettingsItemDefault {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAssertionsSettingsItem {
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
    /// The sentence beside each value.
    #[serde(rename = "csvValueNotes", default, skip_serializing_if = "Option::is_none")]
    pub csv_value_notes: Option<serde_json::Map<String, serde_json::Value>>,
    /// The rules by kind: onlyWhileOn and aloneWhileOn.
    #[serde(rename = "selectAll", default, skip_serializing_if = "Option::is_none")]
    pub select_all: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<SamlAssertionsSettingsItemValue>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub text: Option<Option<String>>,
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
    pub default: Option<Option<SamlAssertionsSettingsItemDefault>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAssertionsAssertionsIssuedByKindItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<f64>,
    #[serde(rename = "noExpiry", default, skip_serializing_if = "Option::is_none")]
    pub no_expiry: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAssertionsAssertionsIssued {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forgotten: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<f64>,
    #[serde(rename = "byKind", default, skip_serializing_if = "Option::is_none")]
    pub by_kind: Option<Vec<SamlAssertionsAssertionsIssuedByKindItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAssertionsContext {
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
    #[serde(rename = "realmId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm_id: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAssertionsRowsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub kind: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAssertions {
    #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
    pub protocol_endpoints: Option<Vec<SamlAssertionsProtocolEndpointsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertions: Option<SamlAssertionsAssertions>,
    #[serde(rename = "perApplication", default, skip_serializing_if = "Option::is_none")]
    pub per_application: Option<Vec<SamlAssertionsPerApplicationItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<SamlAssertionsSettingsItem>>,
    #[serde(rename = "assertionsIssued", default, skip_serializing_if = "Option::is_none")]
    pub assertions_issued: Option<SamlAssertionsAssertionsIssued>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub now: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<SamlAssertionsContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<SamlAssertionsRowsItem>>,
    /// Each setting in seconds, by key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seconds: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SamlAttributeSetsProtocolEndpointsItemMethods {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAttributeSetsProtocolEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<SamlAttributeSetsProtocolEndpointsItemMethods>,
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
#[serde(deny_unknown_fields)]
pub struct SamlAttributeSetsAttributeCatalogueItem {
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

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAttributeSetsSetsItemClaimsItem {
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
#[serde(deny_unknown_fields)]
pub struct SamlAttributeSetsSetsItemAttributeReportItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldap: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    /// A claim value as it would be issued. Its JSON type is the catalogue
    /// row's and the person's own data, and a row may nest under a dotted path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "ldpTerm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ldp_term: Option<Option<String>>,
    #[serde(rename = "claimId", default, skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAttributeSetsSetsItemAttributeClaimPreviewItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carried: Option<bool>,
    /// A claim value as it would be issued. Its JSON type is the catalogue
    /// row's and the person's own data, and a row may nest under a dotted path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAttributeSetsSetsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<SamlAttributeSetsSetsItemClaimsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<String>>,
    /// The claims one person would be issued, keyed and nested by the claim
    /// names the catalogue and an administrator chose.
    #[serde(rename = "attributeClaims", default, skip_serializing_if = "Option::is_none")]
    pub attribute_claims: Option<serde_json::Value>,
    #[serde(rename = "attributeReport", default, skip_serializing_if = "Option::is_none")]
    pub attribute_report: Option<Vec<SamlAttributeSetsSetsItemAttributeReportItem>>,
    #[serde(rename = "attributeClaimPreview", default, skip_serializing_if = "Option::is_none")]
    pub attribute_claim_preview: Option<Vec<SamlAttributeSetsSetsItemAttributeClaimPreviewItem>>,
    /// Partners withholding it, by claim.
    #[serde(rename = "withheldFrom", default, skip_serializing_if = "Option::is_none")]
    pub withheld_from: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAttributeSetsAttributeChoicesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAttributeSetsPreview {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// By directory attribute.
    #[serde(rename = "byLdap", default, skip_serializing_if = "Option::is_none")]
    pub by_ldap: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "entryFound", default, skip_serializing_if = "Option::is_none")]
    pub entry_found: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAttributeSetsGroupsPreviewGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cn: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub rule: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<Vec<String>>,
    #[serde(rename = "viaMemberOf", default, skip_serializing_if = "Option::is_none")]
    pub via_member_of: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAttributeSetsGroupsPreview {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub key: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loaded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub claim: Option<Option<String>>,
    #[serde(rename = "valueForm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value_form: Option<Option<String>>,
    #[serde(rename = "memberOfCounts", default, skip_serializing_if = "Option::is_none")]
    pub member_of_counts: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub dn: Option<Option<String>>,
    #[serde(rename = "entryFound", default, skip_serializing_if = "Option::is_none")]
    pub entry_found: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<SamlAttributeSetsGroupsPreviewGroupsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAttributeSetsGroups {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loaded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub claim: Option<Option<String>>,
    #[serde(rename = "valueForm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value_form: Option<Option<String>>,
    #[serde(rename = "memberOfCounts", default, skip_serializing_if = "Option::is_none")]
    pub member_of_counts: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sets: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<SamlAttributeSetsGroupsPreview>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAttributeSetsWithholdingItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAttributeSets {
    #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
    pub protocol_endpoints: Option<Vec<SamlAttributeSetsProtocolEndpointsItem>>,
    #[serde(rename = "defaultSaml11Namespace", default, skip_serializing_if = "Option::is_none")]
    pub default_saml11_namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholders: Option<Vec<String>>,
    #[serde(rename = "attributeCatalogue", default, skip_serializing_if = "Option::is_none")]
    pub attribute_catalogue: Option<Vec<SamlAttributeSetsAttributeCatalogueItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sets: Option<Vec<SamlAttributeSetsSetsItem>>,
    #[serde(rename = "attributeChoices", default, skip_serializing_if = "Option::is_none")]
    pub attribute_choices: Option<Vec<SamlAttributeSetsAttributeChoicesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<SamlAttributeSetsPreview>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<SamlAttributeSetsGroups>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withholding: Option<Vec<SamlAttributeSetsWithholdingItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SamlIdpInitiatedListProtocolEndpointsItemMethods {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlIdpInitiatedListProtocolEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<SamlIdpInitiatedListProtocolEndpointsItemMethods>,
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
#[serde(deny_unknown_fields)]
pub struct SamlIdpInitiatedListIdpInitiatedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "entityId", default, skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(rename = "launchUrl", default, skip_serializing_if = "Option::is_none")]
    pub launch_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub endpoint: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlIdpInitiatedListIdpInitiatedPaging {
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
pub struct SamlIdpInitiatedListRealmSwitchesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlIdpInitiatedList {
    #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
    pub protocol_endpoints: Option<Vec<SamlIdpInitiatedListProtocolEndpointsItem>>,
    #[serde(rename = "idpInitiated", default, skip_serializing_if = "Option::is_none")]
    pub idp_initiated: Option<Vec<SamlIdpInitiatedListIdpInitiatedItem>>,
    #[serde(rename = "idpInitiatedPaging", default, skip_serializing_if = "Option::is_none")]
    pub idp_initiated_paging: Option<SamlIdpInitiatedListIdpInitiatedPaging>,
    #[serde(rename = "realmSwitches", default, skip_serializing_if = "Option::is_none")]
    pub realm_switches: Option<Vec<SamlIdpInitiatedListRealmSwitchesItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ScimProtocolEndpointsItemMethods {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimProtocolEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<ScimProtocolEndpointsItemMethods>,
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
#[serde(deny_unknown_fields)]
pub struct ScimStore {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<String>,
    #[serde(rename = "baseDn", default, skip_serializing_if = "Option::is_none")]
    pub base_dn: Option<String>,
    #[serde(rename = "userCount", default, skip_serializing_if = "Option::is_none")]
    pub user_count: Option<f64>,
    #[serde(rename = "groupCount", default, skip_serializing_if = "Option::is_none")]
    pub group_count: Option<f64>,
    #[serde(rename = "entryCount", default, skip_serializing_if = "Option::is_none")]
    pub entry_count: Option<f64>,
    #[serde(rename = "maxEntries", default, skip_serializing_if = "Option::is_none")]
    pub max_entries: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimIdentifiers {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimAuthenticationScopes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimAuthenticationSchemesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "refusedByMode", default, skip_serializing_if = "Option::is_none")]
    pub refused_by_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scoped: Option<bool>,
    #[serde(rename = "applicationScoped", default, skip_serializing_if = "Option::is_none")]
    pub application_scoped: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenged: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<String>,
    #[serde(rename = "specUri", default, skip_serializing_if = "Option::is_none")]
    pub spec_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimAuthentication {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(rename = "discoveryOpen", default, skip_serializing_if = "Option::is_none")]
    pub discovery_open: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<ScimAuthenticationScopes>,
    #[serde(rename = "hobaRegistration", default, skip_serializing_if = "Option::is_none")]
    pub hoba_registration: Option<String>,
    #[serde(rename = "digestAlgorithms", default, skip_serializing_if = "Option::is_none")]
    pub digest_algorithms: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schemes: Option<Vec<ScimAuthenticationSchemesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimReachableNegativesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimMappingUserItem {
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

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimMappingGroupItem {
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

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimMapping {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<Vec<ScimMappingUserItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<Vec<ScimMappingGroupItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimCountersOperationsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimCountersResourceTypesItem {
    #[serde(rename = "resourceType", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub resource_type: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimCounters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<f64>,
    #[serde(rename = "firstAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub first_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operations: Option<Vec<ScimCountersOperationsItem>>,
    #[serde(rename = "resourceTypes", default, skip_serializing_if = "Option::is_none")]
    pub resource_types: Option<Vec<ScimCountersResourceTypesItem>>,
    /// A count per name.
    #[serde(rename = "byStatus", default, skip_serializing_if = "Option::is_none")]
    pub by_status: Option<serde_json::Map<String, serde_json::Value>>,
    /// A count per name.
    #[serde(rename = "byScimType", default, skip_serializing_if = "Option::is_none")]
    pub by_scim_type: Option<serde_json::Map<String, serde_json::Value>>,
    /// A count per name.
    #[serde(rename = "byAuthScheme", default, skip_serializing_if = "Option::is_none")]
    pub by_auth_scheme: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ScimSettingsGroupsItemSettingsItemValue {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ScimSettingsGroupsItemSettingsItemDefault {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimSettingsGroupsItemSettingsItem {
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
    /// The sentence beside each value.
    #[serde(rename = "csvValueNotes", default, skip_serializing_if = "Option::is_none")]
    pub csv_value_notes: Option<serde_json::Map<String, serde_json::Value>>,
    /// The rules by kind: onlyWhileOn and aloneWhileOn.
    #[serde(rename = "selectAll", default, skip_serializing_if = "Option::is_none")]
    pub select_all: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<ScimSettingsGroupsItemSettingsItemValue>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub text: Option<Option<String>>,
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
    pub default: Option<Option<ScimSettingsGroupsItemSettingsItemDefault>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimSettingsGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<ScimSettingsGroupsItemSettingsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimSettingsContext {
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
    #[serde(rename = "realmId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm_id: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<ScimSettingsGroupsItem>>,
    #[serde(rename = "settingCount", default, skip_serializing_if = "Option::is_none")]
    pub setting_count: Option<i64>,
    #[serde(rename = "editableCount", default, skip_serializing_if = "Option::is_none")]
    pub editable_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<Vec<String>>,
    #[serde(rename = "setWith", default, skip_serializing_if = "Option::is_none")]
    pub set_with: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<ScimSettingsContext>,
    /// The other pages, by settings group.
    #[serde(rename = "sharedWith", default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientsItemCertificate {
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
pub struct ScimScimClientsClientsItemCounts {
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
pub struct ScimScimClientsClientsItemLastReconcile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
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
pub struct ScimScimClientsClientsItemByCellItemCounts {
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
pub struct ScimScimClientsClientsItemByCellItemQueuedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub uri: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub generation: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attempts: Option<Option<f64>>,
    #[serde(rename = "inFlight", default, skip_serializing_if = "Option::is_none")]
    pub in_flight: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error_code: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub why: Option<Option<String>>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none")]
    pub queued_at: Option<String>,
    #[serde(rename = "nextAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<String>,
    #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    #[serde(rename = "finishedAt", default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "pendingChange", default, skip_serializing_if = "Option::is_none")]
    pub pending_change: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientsItemByCellItemRetryingItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub uri: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub generation: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attempts: Option<Option<f64>>,
    #[serde(rename = "inFlight", default, skip_serializing_if = "Option::is_none")]
    pub in_flight: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error_code: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub why: Option<Option<String>>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none")]
    pub queued_at: Option<String>,
    #[serde(rename = "nextAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<String>,
    #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    #[serde(rename = "finishedAt", default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "pendingChange", default, skip_serializing_if = "Option::is_none")]
    pub pending_change: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientsItemByCellItemDeadItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub uri: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub generation: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attempts: Option<Option<f64>>,
    #[serde(rename = "inFlight", default, skip_serializing_if = "Option::is_none")]
    pub in_flight: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error_code: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub why: Option<Option<String>>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none")]
    pub queued_at: Option<String>,
    #[serde(rename = "nextAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<String>,
    #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    #[serde(rename = "finishedAt", default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "pendingChange", default, skip_serializing_if = "Option::is_none")]
    pub pending_change: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientsItemByCellItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub here: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reachable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withheld: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pushes: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<ScimScimClientsClientsItemByCellItemCounts>,
    #[serde(rename = "pausedUntil", default, skip_serializing_if = "Option::is_none")]
    pub paused_until: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<f64>,
    #[serde(rename = "lastReconcileAt", default, skip_serializing_if = "Option::is_none")]
    pub last_reconcile_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued: Option<Vec<ScimScimClientsClientsItemByCellItemQueuedItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrying: Option<Vec<ScimScimClientsClientsItemByCellItemRetryingItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead: Option<Vec<ScimScimClientsClientsItemByCellItemDeadItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientsItem {
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
    pub certificate: Option<ScimScimClientsClientsItemCertificate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<ScimScimClientsClientsItemCounts>,
    #[serde(rename = "pausedUntil", default, skip_serializing_if = "Option::is_none")]
    pub paused_until: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<f64>,
    #[serde(rename = "lastReconcileAt", default, skip_serializing_if = "Option::is_none")]
    pub last_reconcile_at: Option<String>,
    #[serde(rename = "lastReconcile", default, skip_serializing_if = "Option::is_none")]
    pub last_reconcile: Option<ScimScimClientsClientsItemLastReconcile>,
    #[serde(rename = "byCell", default, skip_serializing_if = "Option::is_none")]
    pub by_cell: Option<Vec<ScimScimClientsClientsItemByCellItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsChoices {
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
pub struct ScimScimClientsClientCertificate {
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
pub struct ScimScimClientsClientCounts {
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
pub struct ScimScimClientsClientLastReconcile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
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
pub struct ScimScimClientsClientByCellItemCounts {
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
pub struct ScimScimClientsClientByCellItemQueuedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub uri: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub generation: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attempts: Option<Option<f64>>,
    #[serde(rename = "inFlight", default, skip_serializing_if = "Option::is_none")]
    pub in_flight: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error_code: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub why: Option<Option<String>>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none")]
    pub queued_at: Option<String>,
    #[serde(rename = "nextAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<String>,
    #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    #[serde(rename = "finishedAt", default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "pendingChange", default, skip_serializing_if = "Option::is_none")]
    pub pending_change: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientByCellItemRetryingItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub uri: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub generation: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attempts: Option<Option<f64>>,
    #[serde(rename = "inFlight", default, skip_serializing_if = "Option::is_none")]
    pub in_flight: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error_code: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub why: Option<Option<String>>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none")]
    pub queued_at: Option<String>,
    #[serde(rename = "nextAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<String>,
    #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    #[serde(rename = "finishedAt", default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "pendingChange", default, skip_serializing_if = "Option::is_none")]
    pub pending_change: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientByCellItemDeadItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub uri: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub generation: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attempts: Option<Option<f64>>,
    #[serde(rename = "inFlight", default, skip_serializing_if = "Option::is_none")]
    pub in_flight: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error_code: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub why: Option<Option<String>>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none")]
    pub queued_at: Option<String>,
    #[serde(rename = "nextAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<String>,
    #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    #[serde(rename = "finishedAt", default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "pendingChange", default, skip_serializing_if = "Option::is_none")]
    pub pending_change: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientByCellItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub here: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reachable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withheld: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pushes: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<ScimScimClientsClientByCellItemCounts>,
    #[serde(rename = "pausedUntil", default, skip_serializing_if = "Option::is_none")]
    pub paused_until: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<f64>,
    #[serde(rename = "lastReconcileAt", default, skip_serializing_if = "Option::is_none")]
    pub last_reconcile_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued: Option<Vec<ScimScimClientsClientByCellItemQueuedItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrying: Option<Vec<ScimScimClientsClientByCellItemRetryingItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead: Option<Vec<ScimScimClientsClientByCellItemDeadItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientQueuesQueuedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub uri: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub generation: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attempts: Option<Option<f64>>,
    #[serde(rename = "inFlight", default, skip_serializing_if = "Option::is_none")]
    pub in_flight: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error_code: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub why: Option<Option<String>>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none")]
    pub queued_at: Option<String>,
    #[serde(rename = "nextAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<String>,
    #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    #[serde(rename = "finishedAt", default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "pendingChange", default, skip_serializing_if = "Option::is_none")]
    pub pending_change: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientQueuesRetryingItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub uri: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub generation: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attempts: Option<Option<f64>>,
    #[serde(rename = "inFlight", default, skip_serializing_if = "Option::is_none")]
    pub in_flight: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error_code: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub why: Option<Option<String>>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none")]
    pub queued_at: Option<String>,
    #[serde(rename = "nextAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<String>,
    #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    #[serde(rename = "finishedAt", default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "pendingChange", default, skip_serializing_if = "Option::is_none")]
    pub pending_change: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientQueuesDeadItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub realm: Option<Option<String>>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub uri: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub generation: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attempts: Option<Option<f64>>,
    #[serde(rename = "inFlight", default, skip_serializing_if = "Option::is_none")]
    pub in_flight: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error_code: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub why: Option<Option<String>>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none")]
    pub queued_at: Option<String>,
    #[serde(rename = "nextAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<String>,
    #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    #[serde(rename = "finishedAt", default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "pendingChange", default, skip_serializing_if = "Option::is_none")]
    pub pending_change: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientQueuesCounts {
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
pub struct ScimScimClientsClientQueues {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued: Option<Vec<ScimScimClientsClientQueuesQueuedItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrying: Option<Vec<ScimScimClientsClientQueuesRetryingItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead: Option<Vec<ScimScimClientsClientQueuesDeadItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<ScimScimClientsClientQueuesCounts>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClientDiscovery {
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
    #[serde(rename = "maxResults", default, skip_serializing_if = "Option::is_none")]
    pub max_results: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bulk: Option<bool>,
    #[serde(rename = "authenticationSchemes", default, skip_serializing_if = "Option::is_none")]
    pub authentication_schemes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClientsClient {
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
    pub certificate: Option<ScimScimClientsClientCertificate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<ScimScimClientsClientCounts>,
    #[serde(rename = "pausedUntil", default, skip_serializing_if = "Option::is_none")]
    pub paused_until: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<f64>,
    #[serde(rename = "lastReconcileAt", default, skip_serializing_if = "Option::is_none")]
    pub last_reconcile_at: Option<String>,
    #[serde(rename = "lastReconcile", default, skip_serializing_if = "Option::is_none")]
    pub last_reconcile: Option<ScimScimClientsClientLastReconcile>,
    #[serde(rename = "byCell", default, skip_serializing_if = "Option::is_none")]
    pub by_cell: Option<Vec<ScimScimClientsClientByCellItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queues: Option<ScimScimClientsClientQueues>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery: Option<ScimScimClientsClientDiscovery>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimScimClients {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clients: Option<Vec<ScimScimClientsClientsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub choices: Option<ScimScimClientsChoices>,
    #[serde(rename = "httpAllowed", default, skip_serializing_if = "Option::is_none")]
    pub http_allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<ScimScimClientsClient>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing: Option<String>,
    #[serde(rename = "cellId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cell_id: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scim {
    #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
    pub protocol_endpoints: Option<Vec<ScimProtocolEndpointsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "baseUrl", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub base_url: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub specifications: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<ScimStore>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifiers: Option<ScimIdentifiers>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<ScimAuthentication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Vec<ScimEndpointsItem>>,
    #[serde(rename = "doesNotDo", default, skip_serializing_if = "Option::is_none")]
    pub does_not_do: Option<Vec<String>>,
    #[serde(rename = "reachableNegatives", default, skip_serializing_if = "Option::is_none")]
    pub reachable_negatives: Option<Vec<ScimReachableNegativesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapping: Option<ScimMapping>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counters: Option<ScimCounters>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<ScimSettings>,
    #[serde(rename = "scimClients", default, skip_serializing_if = "Option::is_none")]
    pub scim_clients: Option<ScimScimClients>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimMonitorSchemesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "refusedByMode", default, skip_serializing_if = "Option::is_none")]
    pub refused_by_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scoped: Option<bool>,
    #[serde(rename = "applicationScoped", default, skip_serializing_if = "Option::is_none")]
    pub application_scoped: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenged: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<String>,
    #[serde(rename = "specUri", default, skip_serializing_if = "Option::is_none")]
    pub spec_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimMonitorStore {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<String>,
    #[serde(rename = "baseDn", default, skip_serializing_if = "Option::is_none")]
    pub base_dn: Option<String>,
    #[serde(rename = "userCount", default, skip_serializing_if = "Option::is_none")]
    pub user_count: Option<f64>,
    #[serde(rename = "groupCount", default, skip_serializing_if = "Option::is_none")]
    pub group_count: Option<f64>,
    #[serde(rename = "entryCount", default, skip_serializing_if = "Option::is_none")]
    pub entry_count: Option<f64>,
    #[serde(rename = "maxEntries", default, skip_serializing_if = "Option::is_none")]
    pub max_entries: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimMonitorCountersLatency {
    #[serde(rename = "totalMs", default, skip_serializing_if = "Option::is_none")]
    pub total_ms: Option<f64>,
    #[serde(rename = "averageMs", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub average_ms: Option<Option<f64>>,
    #[serde(rename = "maxMs", default, skip_serializing_if = "Option::is_none")]
    pub max_ms: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimMonitorCountersAuthentication {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distinct: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applications: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identities: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anonymous: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capped: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<f64>,
    /// A count per name.
    #[serde(rename = "byScheme", default, skip_serializing_if = "Option::is_none")]
    pub by_scheme: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimMonitorCountersOperationsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<f64>,
    #[serde(rename = "averageMs", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub average_ms: Option<Option<f64>>,
    #[serde(rename = "maxMs", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub max_ms: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimMonitorCountersResourceTypesItem {
    #[serde(rename = "resourceType", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub resource_type: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimMonitorCountersClientsItem {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub principal: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub kind: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calls: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schemes: Option<Vec<String>>,
    #[serde(rename = "resourceTypes", default, skip_serializing_if = "Option::is_none")]
    pub resource_types: Option<Vec<String>>,
    #[serde(rename = "firstAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub first_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "lastOperation", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_operation: Option<Option<String>>,
    #[serde(rename = "lastStatus", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_status: Option<Option<sts_model_base::unions::NumberOrString>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimMonitorCountersRecentItem {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub operation: Option<Option<String>>,
    #[serde(rename = "resourceType", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub resource_type: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(rename = "scimType", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub scim_type: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub scheme: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub principal: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ms: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub bytes: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub method: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub path: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimMonitorCountersRealm {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub id: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimMonitorCounters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calls: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<f64>,
    #[serde(rename = "successRate", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub success_rate: Option<Option<f64>>,
    #[serde(rename = "firstAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub first_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub since: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency: Option<ScimMonitorCountersLatency>,
    #[serde(rename = "bytesOut", default, skip_serializing_if = "Option::is_none")]
    pub bytes_out: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<ScimMonitorCountersAuthentication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operations: Option<Vec<ScimMonitorCountersOperationsItem>>,
    #[serde(rename = "resourceTypes", default, skip_serializing_if = "Option::is_none")]
    pub resource_types: Option<Vec<ScimMonitorCountersResourceTypesItem>>,
    /// A count per name.
    #[serde(rename = "byStatus", default, skip_serializing_if = "Option::is_none")]
    pub by_status: Option<serde_json::Map<String, serde_json::Value>>,
    /// A count per name.
    #[serde(rename = "byStatusClass", default, skip_serializing_if = "Option::is_none")]
    pub by_status_class: Option<serde_json::Map<String, serde_json::Value>>,
    /// A count per name.
    #[serde(rename = "byScimType", default, skip_serializing_if = "Option::is_none")]
    pub by_scim_type: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clients: Option<Vec<ScimMonitorCountersClientsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recent: Option<Vec<ScimMonitorCountersRecentItem>>,
    #[serde(rename = "recentCap", default, skip_serializing_if = "Option::is_none")]
    pub recent_cap: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<ScimMonitorCountersRealm>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimMonitor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "baseUrl", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub base_url: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schemes: Option<Vec<ScimMonitorSchemesItem>>,
    #[serde(rename = "authRequired", default, skip_serializing_if = "Option::is_none")]
    pub auth_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<ScimMonitorStore>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counters: Option<ScimMonitorCounters>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionListFilter {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub q: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub protocol: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionListUnauthenticatedPaging {
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
pub struct SessionListAccountChoices {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionListPaging {
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

/// Every session this service is holding right now, filtered and paged.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionList {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<f64>,
    #[serde(rename = "heldByKind", default, skip_serializing_if = "Option::is_none")]
    pub held_by_kind: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<SessionListFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<f64>,
    #[serde(rename = "expiryRules", default, skip_serializing_if = "Option::is_none")]
    pub expiry_rules: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<Vec<crate::SessionRow>>,
    #[serde(rename = "unauthenticatedHeld", default, skip_serializing_if = "Option::is_none")]
    pub unauthenticated_held: Option<f64>,
    #[serde(rename = "unauthenticatedKept", default, skip_serializing_if = "Option::is_none")]
    pub unauthenticated_kept: Option<bool>,
    #[serde(rename = "unauthenticatedSessions", default, skip_serializing_if = "Option::is_none")]
    pub unauthenticated_sessions: Option<Vec<crate::SessionRow>>,
    #[serde(rename = "unauthenticatedPaging", default, skip_serializing_if = "Option::is_none")]
    pub unauthenticated_paging: Option<SessionListUnauthenticatedPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windowed: Option<bool>,
    #[serde(rename = "accountChoices", default, skip_serializing_if = "Option::is_none")]
    pub account_choices: Option<SessionListAccountChoices>,
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
    pub paging: Option<SessionListPaging>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SessionRowAmr {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRowDeviceBound {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(rename = "boundAt", default, skip_serializing_if = "Option::is_none")]
    pub bound_at: Option<f64>,
    #[serde(rename = "refreshedAt", default, skip_serializing_if = "Option::is_none")]
    pub refreshed_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refreshes: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasons: Option<Vec<String>>,
}

/// One live session of any kind.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRow {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(rename = "derivedFrom", default, skip_serializing_if = "Option::is_none")]
    pub derived_from: Option<String>,
    #[serde(rename = "rpClientId", default, skip_serializing_if = "Option::is_none")]
    pub rp_client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(rename = "startedAt", default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<f64>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
    #[serde(rename = "expiryRule", default, skip_serializing_if = "Option::is_none")]
    pub expiry_rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amr: Option<SessionRowAmr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(rename = "deviceBound", default, skip_serializing_if = "Option::is_none")]
    pub device_bound: Option<SessionRowDeviceBound>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carries: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated: Option<bool>,
    #[serde(rename = "accountSet", default, skip_serializing_if = "Option::is_none")]
    pub account_set: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SignalsStatusStreamAud {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalsStatusStream {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub iss: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub aud: Option<Option<SignalsStatusStreamAud>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(rename = "statusReason", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status_reason: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_url: Option<String>,
    #[serde(rename = "pollEveryMs", default, skip_serializing_if = "Option::is_none")]
    pub poll_every_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivers: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested: Option<i64>,
    #[serde(rename = "caepDelivered", default, skip_serializing_if = "Option::is_none")]
    pub caep_delivered: Option<i64>,
    #[serde(rename = "riscDelivered", default, skip_serializing_if = "Option::is_none")]
    pub risc_delivered: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counters: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "lastPushAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_push_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "lastPushError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_push_error: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalsStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(rename = "receivePath", default, skip_serializing_if = "Option::is_none")]
    pub receive_path: Option<String>,
    #[serde(rename = "inboxPath", default, skip_serializing_if = "Option::is_none")]
    pub inbox_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sees: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "ssfEnabled", default, skip_serializing_if = "Option::is_none")]
    pub ssf_enabled: Option<bool>,
    #[serde(rename = "internalReceivers", default, skip_serializing_if = "Option::is_none")]
    pub internal_receivers: Option<bool>,
    #[serde(rename = "pushDelivery", default, skip_serializing_if = "Option::is_none")]
    pub push_delivery: Option<bool>,
    #[serde(rename = "caepEnabled", default, skip_serializing_if = "Option::is_none")]
    pub caep_enabled: Option<bool>,
    #[serde(rename = "riscEnabled", default, skip_serializing_if = "Option::is_none")]
    pub risc_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<SignalsStatusStream>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalsReceivedItemReactionsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reaction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalsReceivedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "tokenDigest", default, skip_serializing_if = "Option::is_none")]
    pub token_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub surface: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub stream: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vocabulary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(rename = "audienceOk", default, skip_serializing_if = "Option::is_none")]
    pub audience_ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// An event's body as this receiver took it in: each event type has its own
    /// members, and a refused delivery is held here too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    #[serde(rename = "verificationNote", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub verification_note: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reactions: Option<Vec<SignalsReceivedItemReactionsItem>>,
    #[serde(rename = "contentType", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub content_type: Option<Option<String>>,
    #[serde(rename = "correctMediaType", default, skip_serializing_if = "Option::is_none")]
    pub correct_media_type: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalsFilter {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub received: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalsPagingReceived {
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
pub struct SignalsPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received: Option<SignalsPagingReceived>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signals {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<SignalsStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received: Option<Vec<SignalsReceivedItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<SignalsFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<SignalsPaging>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfMetadataAuthorizationSchemesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_urn: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_methods_supported: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub add_subject_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remove_subject_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_subjects: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_schemes: Option<Vec<SsfMetadataAuthorizationSchemesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub critical_subject_members: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeliveryItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offered: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfPushTransport {
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
pub struct SsfPush {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<SsfPushTransport>,
    #[serde(rename = "allowedHosts", default, skip_serializing_if = "Option::is_none")]
    pub allowed_hosts: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retries: Option<f64>,
    #[serde(rename = "maxResponseBytes", default, skip_serializing_if = "Option::is_none")]
    pub max_response_bytes: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfEventTypesItemMembersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub required: Option<Option<sts_model_base::unions::BoolOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub type_: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfEventTypesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub subject: Option<Option<sts_model_base::unions::BoolOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<SsfEventTypesItemMembersItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,
    #[serde(rename = "subjectFormats", default, skip_serializing_if = "Option::is_none")]
    pub subject_formats: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprecated: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfSubjectFormatsItemExampleIdentifiersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfSubjectFormatsItemExample {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertion_id: Option<String>,
    #[serde(rename = "ip-addresses", default, skip_serializing_if = "Option::is_none")]
    pub ip_addresses: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifiers: Option<Vec<SsfSubjectFormatsItemExampleIdentifiersItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfSubjectFormatsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example: Option<SsfSubjectFormatsItemExample>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfComplexSubjectMembersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfAuthenticationScopes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write: Option<String>,
    #[serde(rename = "readAlso", default, skip_serializing_if = "Option::is_none")]
    pub read_also: Option<Vec<String>>,
    #[serde(rename = "writeAlso", default, skip_serializing_if = "Option::is_none")]
    pub write_also: Option<Vec<String>>,
    #[serde(rename = "writeIncludesRead", default, skip_serializing_if = "Option::is_none")]
    pub write_includes_read: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfAuthenticationSchemesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_urn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offered: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfAuthentication {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<SsfAuthenticationScopes>,
    #[serde(rename = "refusedPassword", default, skip_serializing_if = "Option::is_none")]
    pub refused_password: Option<String>,
    #[serde(rename = "metadataIsOpen", default, skip_serializing_if = "Option::is_none")]
    pub metadata_is_open: Option<bool>,
    #[serde(rename = "passwordVerified", default, skip_serializing_if = "Option::is_none")]
    pub password_verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schemes: Option<Vec<SsfAuthenticationSchemesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfStreamsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_delivered: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subjects: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counters: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "lastPushError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_push_error: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfReachableNegativesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SsfStreamDetailItemAud {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfStreamDetailItemDelivery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub endpoint_url: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfStreamDetailItemSubjectsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub verified: Option<Option<bool>>,
    #[serde(rename = "addedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub added_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    /// An RFC 9493 subject identifier, as a stream was given it or a person
    /// named it: the format decides the members, an `aliases` nests, and SSF
    /// 1.0 section 3.3 lets a receiver add its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SsfStreamDetailItemQueueItemSummaryAudience {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfStreamDetailItemQueueItemSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<SsfStreamDetailItemQueueItemSummaryAudience>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfStreamDetailItemQueueItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub queued_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "deliveredAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub delivered_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<SsfStreamDetailItemQueueItemSummary>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SsfStreamDetailItemDeadLettersItemSummaryAudience {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfStreamDetailItemDeadLettersItemSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<SsfStreamDetailItemDeadLettersItemSummaryAudience>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfStreamDetailItemDeadLettersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub queued_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "deadAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub dead_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub reason: Option<Option<String>>,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error_code: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<SsfStreamDetailItemDeadLettersItemSummary>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfStreamDetailItemLogItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfStreamDetailItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub iss: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub aud: Option<Option<SsfStreamDetailItemAud>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(rename = "statusReason", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status_reason: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<SsfStreamDetailItemDelivery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_delivered: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_requested: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub format: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub description: Option<Option<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub updated_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_by: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub internal: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counters: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "lastPushError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_push_error: Option<Option<String>>,
    #[serde(rename = "lastPushAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_push_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subjects: Option<Vec<SsfStreamDetailItemSubjectsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue: Option<Vec<SsfStreamDetailItemQueueItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead: Option<bool>,
    #[serde(rename = "deadSince", default, skip_serializing_if = "Option::is_none")]
    pub dead_since: Option<String>,
    #[serde(rename = "deadReason", default, skip_serializing_if = "Option::is_none")]
    pub dead_reason: Option<String>,
    #[serde(rename = "failingSince", default, skip_serializing_if = "Option::is_none")]
    pub failing_since: Option<String>,
    #[serde(rename = "nextProbeAt", default, skip_serializing_if = "Option::is_none")]
    pub next_probe_at: Option<String>,
    #[serde(rename = "deadLetters", default, skip_serializing_if = "Option::is_none")]
    pub dead_letters: Option<Vec<SsfStreamDetailItemDeadLettersItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<Vec<SsfStreamDetailItemLogItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLetters_2Pushes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiting: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backlog: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLetters_2 {
    #[serde(rename = "retentionS", default, skip_serializing_if = "Option::is_none")]
    pub retention_s: Option<f64>,
    #[serde(rename = "maxPerStream", default, skip_serializing_if = "Option::is_none")]
    pub max_per_stream: Option<f64>,
    #[serde(rename = "deadStreamTimeoutS", default, skip_serializing_if = "Option::is_none")]
    pub dead_stream_timeout_s: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pushes: Option<SsfDeadLetters_2Pushes>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfSettingsGroupsItemSettingsItemSelectAllOnlyWhileOnItem {
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
pub struct SsfSettingsGroupsItemSettingsItemSelectAllAloneWhileOnItem {
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
pub struct SsfSettingsGroupsItemSettingsItemSelectAll {
    #[serde(rename = "onlyWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub only_while_on: Option<Vec<SsfSettingsGroupsItemSettingsItemSelectAllOnlyWhileOnItem>>,
    #[serde(rename = "aloneWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub alone_while_on: Option<Vec<SsfSettingsGroupsItemSettingsItemSelectAllAloneWhileOnItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SsfSettingsGroupsItemSettingsItemValue {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SsfSettingsGroupsItemSettingsItemEnv {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SsfSettingsGroupsItemSettingsItemLegacyEnv {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SsfSettingsGroupsItemSettingsItemDefault {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfSettingsGroupsItemSettingsItem {
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
    pub enum_values: Option<Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>>,
    #[serde(rename = "csvValues", default, skip_serializing_if = "Option::is_none")]
    pub csv_values: Option<Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordered: Option<bool>,
    #[serde(rename = "csvValueNotes", default, skip_serializing_if = "Option::is_none")]
    pub csv_value_notes: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "selectAll", default, skip_serializing_if = "Option::is_none")]
    pub select_all: Option<SsfSettingsGroupsItemSettingsItemSelectAll>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<SsfSettingsGroupsItemSettingsItemValue>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub text: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<bool>,
    #[serde(rename = "restartReason", default, skip_serializing_if = "Option::is_none")]
    pub restart_reason: Option<String>,
    #[serde(rename = "editRefusal", default, skip_serializing_if = "Option::is_none")]
    pub edit_refusal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<SsfSettingsGroupsItemSettingsItemEnv>,
    #[serde(rename = "legacyEnv", default, skip_serializing_if = "Option::is_none")]
    pub legacy_env: Option<SsfSettingsGroupsItemSettingsItemLegacyEnv>,
    #[serde(rename = "appconfigPath", default, skip_serializing_if = "Option::is_none")]
    pub appconfig_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default: Option<Option<SsfSettingsGroupsItemSettingsItemDefault>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfSettingsGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<SsfSettingsGroupsItemSettingsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfSettingsContext {
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
pub struct SsfSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<SsfSettingsGroupsItem>>,
    #[serde(rename = "settingCount", default, skip_serializing_if = "Option::is_none")]
    pub setting_count: Option<i64>,
    #[serde(rename = "editableCount", default, skip_serializing_if = "Option::is_none")]
    pub editable_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<Vec<String>>,
    #[serde(rename = "setWith", default, skip_serializing_if = "Option::is_none")]
    pub set_with: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<SsfSettingsContext>,
    #[serde(rename = "sharedWith", default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfStreamTotals {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiting: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead: Option<i64>,
    #[serde(rename = "deadLetters", default, skip_serializing_if = "Option::is_none")]
    pub dead_letters: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfPagingStreams {
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
pub struct SsfPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<SsfPagingStreams>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SsfProtocolEndpointsItemMethods {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfProtocolEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<SsfProtocolEndpointsItemMethods>,
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
pub struct Ssf {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(rename = "metadataUrl", default, skip_serializing_if = "Option::is_none")]
    pub metadata_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<SsfMetadata>,
    #[serde(rename = "signingAlgorithm", default, skip_serializing_if = "Option::is_none")]
    pub signing_algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<Vec<SsfDeliveryItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push: Option<SsfPush>,
    #[serde(rename = "eventTypes", default, skip_serializing_if = "Option::is_none")]
    pub event_types: Option<Vec<SsfEventTypesItem>>,
    #[serde(rename = "subjectFormats", default, skip_serializing_if = "Option::is_none")]
    pub subject_formats: Option<Vec<SsfSubjectFormatsItem>>,
    #[serde(rename = "complexSubjectMembers", default, skip_serializing_if = "Option::is_none")]
    pub complex_subject_members: Option<Vec<SsfComplexSubjectMembersItem>>,
    #[serde(rename = "criticalSubjectMembers", default, skip_serializing_if = "Option::is_none")]
    pub critical_subject_members: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<SsfAuthentication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<Vec<SsfStreamsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Vec<SsfEndpointsItem>>,
    #[serde(rename = "reachableNegatives", default, skip_serializing_if = "Option::is_none")]
    pub reachable_negatives: Option<Vec<SsfReachableNegativesItem>>,
    #[serde(rename = "doesNotDo", default, skip_serializing_if = "Option::is_none")]
    pub does_not_do: Option<Vec<String>>,
    #[serde(rename = "streamDetail", default, skip_serializing_if = "Option::is_none")]
    pub stream_detail: Option<Vec<SsfStreamDetailItem>>,
    #[serde(rename = "deadLetters", default, skip_serializing_if = "Option::is_none")]
    pub dead_letters: Option<SsfDeadLetters_2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<SsfSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statuses: Option<Vec<String>>,
    #[serde(rename = "streamTotals", default, skip_serializing_if = "Option::is_none")]
    pub stream_totals: Option<SsfStreamTotals>,
    #[serde(rename = "streamFilter", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub stream_filter: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<SsfPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
    pub protocol_endpoints: Option<Vec<SsfProtocolEndpointsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersCausesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersTotals {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<i64>,
    #[serde(rename = "streamsHolding", default, skip_serializing_if = "Option::is_none")]
    pub streams_holding: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unsigned: Option<i64>,
    #[serde(rename = "deadStreams", default, skip_serializing_if = "Option::is_none")]
    pub dead_streams: Option<i64>,
    #[serde(rename = "halfOpenStreams", default, skip_serializing_if = "Option::is_none")]
    pub half_open_streams: Option<i64>,
    #[serde(rename = "failingStreams", default, skip_serializing_if = "Option::is_none")]
    pub failing_streams: Option<i64>,
    #[serde(rename = "pushStreams", default, skip_serializing_if = "Option::is_none")]
    pub push_streams: Option<i64>,
    #[serde(rename = "oldestAt", default, skip_serializing_if = "Option::is_none")]
    pub oldest_at: Option<String>,
    #[serde(rename = "newestAt", default, skip_serializing_if = "Option::is_none")]
    pub newest_at: Option<String>,
    #[serde(rename = "oldestAgeS", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub oldest_age_s: Option<Option<f64>>,
    #[serde(rename = "newestAgeS", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub newest_age_s: Option<Option<f64>>,
    #[serde(rename = "deadLetteredEver", default, skip_serializing_if = "Option::is_none")]
    pub dead_lettered_ever: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersTimelineBucketsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    #[serde(rename = "startMs", default, skip_serializing_if = "Option::is_none")]
    pub start_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersTimeline {
    #[serde(rename = "bucketS", default, skip_serializing_if = "Option::is_none")]
    pub bucket_s: Option<f64>,
    #[serde(rename = "windowS", default, skip_serializing_if = "Option::is_none")]
    pub window_s: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buckets: Option<Vec<SsfDeadLettersTimelineBucketsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak: Option<i64>,
    #[serde(rename = "olderThanWindow", default, skip_serializing_if = "Option::is_none")]
    pub older_than_window: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersByCodeItem {
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersByStatusItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersByEventTypeItem {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SsfDeadLettersStreamsItemAud {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersStreamsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub aud: Option<Option<SsfDeadLettersStreamsItemAud>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causes: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "oldestAt", default, skip_serializing_if = "Option::is_none")]
    pub oldest_at: Option<String>,
    #[serde(rename = "newestAt", default, skip_serializing_if = "Option::is_none")]
    pub newest_at: Option<String>,
    #[serde(rename = "deadLetteredEver", default, skip_serializing_if = "Option::is_none")]
    pub dead_lettered_ever: Option<f64>,
    #[serde(rename = "deadSince", default, skip_serializing_if = "Option::is_none")]
    pub dead_since: Option<String>,
    #[serde(rename = "failingSince", default, skip_serializing_if = "Option::is_none")]
    pub failing_since: Option<String>,
    #[serde(rename = "nextProbeAt", default, skip_serializing_if = "Option::is_none")]
    pub next_probe_at: Option<String>,
    #[serde(rename = "deadReason", default, skip_serializing_if = "Option::is_none")]
    pub dead_reason: Option<String>,
    #[serde(rename = "lastPushError", default, skip_serializing_if = "Option::is_none")]
    pub last_push_error: Option<String>,
    #[serde(rename = "lastPushAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_push_at: Option<Option<sts_model_base::unions::NumberOrString>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersLettersItemEvent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersLettersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub queued_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "deadAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub dead_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "ageS", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub age_s: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed: Option<bool>,
    #[serde(rename = "streamKnown", default, skip_serializing_if = "Option::is_none")]
    pub stream_known: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<SsfDeadLettersLettersItemEvent>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersSettings {
    #[serde(rename = "retentionS", default, skip_serializing_if = "Option::is_none")]
    pub retention_s: Option<f64>,
    #[serde(rename = "maxPerStream", default, skip_serializing_if = "Option::is_none")]
    pub max_per_stream: Option<f64>,
    #[serde(rename = "deadStreamTimeoutS", default, skip_serializing_if = "Option::is_none")]
    pub dead_stream_timeout_s: Option<f64>,
    #[serde(rename = "sweepS", default, skip_serializing_if = "Option::is_none")]
    pub sweep_s: Option<f64>,
    #[serde(rename = "pushConcurrency", default, skip_serializing_if = "Option::is_none")]
    pub push_concurrency: Option<f64>,
    #[serde(rename = "pushBacklog", default, skip_serializing_if = "Option::is_none")]
    pub push_backlog: Option<f64>,
    #[serde(rename = "pushRetries", default, skip_serializing_if = "Option::is_none")]
    pub push_retries: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersProcessPushes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiting: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backlog: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersProcessSweepsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub letters: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orphaned: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trimmed: Option<i64>,
    #[serde(rename = "deadStreams", default, skip_serializing_if = "Option::is_none")]
    pub dead_streams: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probes: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersProcessSinceStart {
    #[serde(rename = "firstSweepAt", default, skip_serializing_if = "Option::is_none")]
    pub first_sweep_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sweeps: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub letters: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orphaned: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trimmed: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probes: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersProcess {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub thread: Option<Option<sts_model_base::unions::IntegerOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pushes: Option<SsfDeadLettersProcessPushes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sweeps: Option<Vec<SsfDeadLettersProcessSweepsItem>>,
    #[serde(rename = "sinceStart", default, skip_serializing_if = "Option::is_none")]
    pub since_start: Option<SsfDeadLettersProcessSinceStart>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersFilter {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub q: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub stream: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cause: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLettersPagingLetters {
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
pub struct SsfDeadLettersPagingStreams {
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
pub struct SsfDeadLettersPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub letters: Option<SsfDeadLettersPagingLetters>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<SsfDeadLettersPagingStreams>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsfDeadLetters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(rename = "generatedAt", default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    #[serde(rename = "pushDelivery", default, skip_serializing_if = "Option::is_none")]
    pub push_delivery: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causes: Option<Vec<SsfDeadLettersCausesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totals: Option<SsfDeadLettersTotals>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeline: Option<SsfDeadLettersTimeline>,
    #[serde(rename = "byCode", default, skip_serializing_if = "Option::is_none")]
    pub by_code: Option<Vec<SsfDeadLettersByCodeItem>>,
    #[serde(rename = "byStatus", default, skip_serializing_if = "Option::is_none")]
    pub by_status: Option<Vec<SsfDeadLettersByStatusItem>>,
    #[serde(rename = "byEventType", default, skip_serializing_if = "Option::is_none")]
    pub by_event_type: Option<Vec<SsfDeadLettersByEventTypeItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<Vec<SsfDeadLettersStreamsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub letters: Option<Vec<SsfDeadLettersLettersItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<SsfDeadLettersSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<SsfDeadLettersProcess>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<SsfDeadLettersFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<SsfDeadLettersPaging>,
}

/// What this service is and how much it has done since it started.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(rename = "startedAt", default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(rename = "uptimeMs", default, skip_serializing_if = "Option::is_none")]
    pub uptime_ms: Option<f64>,
    /// Endpoint calls served.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calls: Option<i64>,
    #[serde(rename = "tokensHeld", default, skip_serializing_if = "Option::is_none")]
    pub tokens_held: Option<i64>,
    /// True when the token register is read on demand (#820): tokensHeld counts
    /// the recent tokens this process holds, not every token issued.
    #[serde(rename = "tokensHeldOnly", default, skip_serializing_if = "Option::is_none")]
    pub tokens_held_only: Option<bool>,
    #[serde(rename = "tokensRevoked", default, skip_serializing_if = "Option::is_none")]
    pub tokens_revoked: Option<i64>,
    /// Assertions, tickets and credentials: everything that is not a JWT.
    #[serde(rename = "artifactsHeld", default, skip_serializing_if = "Option::is_none")]
    pub artifacts_held: Option<i64>,
    /// Browser sign-on sessions really held.
    #[serde(rename = "signOnSessions", default, skip_serializing_if = "Option::is_none")]
    pub sign_on_sessions: Option<i64>,
    #[serde(rename = "usersKnown", default, skip_serializing_if = "Option::is_none")]
    pub users_known: Option<i64>,
    #[serde(rename = "usersAuthenticatedHere", default, skip_serializing_if = "Option::is_none")]
    pub users_authenticated_here: Option<i64>,
    /// The console pages this API mirrors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenLifetimesLifetimes {
    #[serde(rename = "accessTokenTtlS", default, skip_serializing_if = "Option::is_none")]
    pub access_token_ttl_s: Option<f64>,
    #[serde(rename = "idTokenTtlS", default, skip_serializing_if = "Option::is_none")]
    pub id_token_ttl_s: Option<f64>,
    #[serde(rename = "refreshTokenTtlS", default, skip_serializing_if = "Option::is_none")]
    pub refresh_token_ttl_s: Option<f64>,
    #[serde(rename = "clockSkewS", default, skip_serializing_if = "Option::is_none")]
    pub clock_skew_s: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenLifetimesSettingsItemSelectAllOnlyWhileOnItem {
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
pub struct TokenLifetimesSettingsItemSelectAllAloneWhileOnItem {
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
pub struct TokenLifetimesSettingsItemSelectAll {
    #[serde(rename = "onlyWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub only_while_on: Option<Vec<TokenLifetimesSettingsItemSelectAllOnlyWhileOnItem>>,
    #[serde(rename = "aloneWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub alone_while_on: Option<Vec<TokenLifetimesSettingsItemSelectAllAloneWhileOnItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum TokenLifetimesSettingsItemValue {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum TokenLifetimesSettingsItemDefault {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenLifetimesSettingsItem {
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
    pub select_all: Option<TokenLifetimesSettingsItemSelectAll>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<TokenLifetimesSettingsItemValue>>,
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
    pub default: Option<Option<TokenLifetimesSettingsItemDefault>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenLifetimesTokensByKindItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<i64>,
    #[serde(rename = "notYetValid", default, skip_serializing_if = "Option::is_none")]
    pub not_yet_valid: Option<i64>,
    #[serde(rename = "noExpiry", default, skip_serializing_if = "Option::is_none")]
    pub no_expiry: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenLifetimesTokens {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forgotten: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<i64>,
    #[serde(rename = "byKind", default, skip_serializing_if = "Option::is_none")]
    pub by_kind: Option<Vec<TokenLifetimesTokensByKindItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenLifetimesContext {
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
pub struct TokenLifetimesOverridableItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenLifetimes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifetimes: Option<TokenLifetimesLifetimes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<TokenLifetimesSettingsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<TokenLifetimesTokens>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub now: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<TokenLifetimesContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridable: Option<Vec<TokenLifetimesOverridableItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailUserFormsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub form: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailUserRealmsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailUserProtocolsItemMethodsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailUserProtocolsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
    #[serde(rename = "firstAt", default, skip_serializing_if = "Option::is_none")]
    pub first_at: Option<f64>,
    #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none")]
    pub last_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<UserDetailUserProtocolsItemMethodsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum UserDetailUserEventsItemAmr {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailUserEventsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presented: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amr: Option<UserDetailUserEventsItemAmr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailUserTokens {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub other: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailUserArtifactKindsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailUser {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forms: Option<Vec<UserDetailUserFormsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realms: Option<Vec<UserDetailUserRealmsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<UserDetailUserProtocolsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentications: Option<f64>,
    #[serde(rename = "firstAt", default, skip_serializing_if = "Option::is_none")]
    pub first_at: Option<f64>,
    #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none")]
    pub last_at: Option<f64>,
    #[serde(rename = "isClient", default, skip_serializing_if = "Option::is_none")]
    pub is_client: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated: Option<bool>,
    #[serde(rename = "knownBy", default, skip_serializing_if = "Option::is_none")]
    pub known_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<UserDetailUserEventsItem>>,
    #[serde(rename = "eventsForgotten", default, skip_serializing_if = "Option::is_none")]
    pub events_forgotten: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<UserDetailUserTokens>,
    #[serde(rename = "artifactKinds", default, skip_serializing_if = "Option::is_none")]
    pub artifact_kinds: Option<Vec<UserDetailUserArtifactKindsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<f64>,
    #[serde(rename = "lastActivityAt", default, skip_serializing_if = "Option::is_none")]
    pub last_activity_at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailServiceAccountOwnersItem {
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
pub struct UserDetailServiceAccountOwnership {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub marked: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasons: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailServiceAccountRotation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotates: Option<bool>,
    #[serde(rename = "nextDueAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub next_due_at: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<f64>,
    #[serde(rename = "lastError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_error: Option<Option<String>>,
    #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_attempt_at: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alarm: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailServiceAccountPolicy {
    #[serde(rename = "exemptFromSecondFactor", default, skip_serializing_if = "Option::is_none")]
    pub exempt_from_second_factor: Option<bool>,
    #[serde(rename = "allowBrowserSignIn", default, skip_serializing_if = "Option::is_none")]
    pub allow_browser_sign_in: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doors: Option<Vec<String>>,
    #[serde(rename = "requiresOwner", default, skip_serializing_if = "Option::is_none")]
    pub requires_owner: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailServiceAccount {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owners: Option<Vec<UserDetailServiceAccountOwnersItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ownership: Option<UserDetailServiceAccountOwnership>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub destination: Option<Option<String>>,
    #[serde(rename = "secretName", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub secret_name: Option<Option<String>>,
    #[serde(rename = "rotatedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub rotated_at: Option<Option<String>>,
    #[serde(rename = "previousPasswordUntil", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub previous_password_until: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation: Option<UserDetailServiceAccountRotation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<UserDetailServiceAccountPolicy>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailRisk {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    #[serde(rename = "previousLevel", default, skip_serializing_if = "Option::is_none")]
    pub previous_level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "lastAssessment", default, skip_serializing_if = "Option::is_none")]
    pub last_assessment: Option<String>,
    #[serde(rename = "crossedAt", default, skip_serializing_if = "Option::is_none")]
    pub crossed_at: Option<f64>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsPasswordResetLink {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsMfaRequirement {
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
pub struct UserDetailFactorsTotpDetail {
    #[serde(rename = "enrolledAt", default, skip_serializing_if = "Option::is_none")]
    pub enrolled_at: Option<f64>,
    #[serde(rename = "lastUsedAt", default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digits: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unusable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsBackupCodes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used: Option<f64>,
    #[serde(rename = "generatedAt", default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<f64>,
    #[serde(rename = "lastUsedAt", default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hashed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItemAlgorithm {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "coseAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cose_alg: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insecure: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lane: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItemAttestationAlgorithmsCertificatesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composite: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItemAttestationAlgorithmsAnchor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composite: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItemAttestationAlgorithmsMembersItemCertificatesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composite: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItemAttestationAlgorithmsMembersItemAnchor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composite: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItemAttestationAlgorithmsMembersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    #[serde(rename = "statementCoseAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub statement_cose_alg: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<UserDetailFactorsKeysItemAttestationAlgorithmsMembersItemCertificatesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<UserDetailFactorsKeysItemAttestationAlgorithmsMembersItemAnchor>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItemAttestationAlgorithms {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    #[serde(rename = "statementCoseAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub statement_cose_alg: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<UserDetailFactorsKeysItemAttestationAlgorithmsCertificatesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<UserDetailFactorsKeysItemAttestationAlgorithmsAnchor>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<UserDetailFactorsKeysItemAttestationAlgorithmsMembersItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItemAttestationEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syntax: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    #[serde(rename = "objectDigest", default, skip_serializing_if = "Option::is_none")]
    pub object_digest: Option<String>,
    #[serde(rename = "evidenceRecord", default, skip_serializing_if = "Option::is_none")]
    pub evidence_record: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamps: Option<Vec<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "renewedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub renewed_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "renewAfter", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub renew_after: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "hashAlgorithm", default, skip_serializing_if = "Option::is_none")]
    pub hash_algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub tsa: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItemAttestationAndroidRevocation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(rename = "listVersion", default, skip_serializing_if = "Option::is_none")]
    pub list_version: Option<String>,
    #[serde(rename = "checkedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub checked_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "chainSerials", default, skip_serializing_if = "Option::is_none")]
    pub chain_serials: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItemAttestation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub aaguid: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(rename = "certificationLevel", default, skip_serializing_if = "Option::is_none")]
    pub certification_level: Option<String>,
    #[serde(rename = "mdsStatus", default, skip_serializing_if = "Option::is_none")]
    pub mds_status: Option<String>,
    #[serde(rename = "mdsVersion", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub mds_version: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "checkedAt", default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithms: Option<UserDetailFactorsKeysItemAttestationAlgorithms>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conveyance: Option<String>,
    #[serde(rename = "enterpriseDowngraded", default, skip_serializing_if = "Option::is_none")]
    pub enterprise_downgraded: Option<bool>,
    #[serde(rename = "attestationKeyId", default, skip_serializing_if = "Option::is_none")]
    pub attestation_key_id: Option<String>,
    #[serde(rename = "deviceSerial", default, skip_serializing_if = "Option::is_none")]
    pub device_serial: Option<String>,
    #[serde(rename = "deviceSerialSource", default, skip_serializing_if = "Option::is_none")]
    pub device_serial_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<UserDetailFactorsKeysItemAttestationEvidence>,
    #[serde(rename = "androidRevocation", default, skip_serializing_if = "Option::is_none")]
    pub android_revocation: Option<UserDetailFactorsKeysItemAttestationAndroidRevocation>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItemAttestationAlgorithms_2CertificatesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItemAttestationAlgorithms_2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statements: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<UserDetailFactorsKeysItemAttestationAlgorithms_2CertificatesItem>>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItemPossiblyReplaced {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItemWithoutUsername {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsKeysItem {
    #[serde(rename = "credentialId", default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub label: Option<Option<String>>,
    #[serde(rename = "signCount", default, skip_serializing_if = "Option::is_none")]
    pub sign_count: Option<f64>,
    #[serde(rename = "enrolledAt", default, skip_serializing_if = "Option::is_none")]
    pub enrolled_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub aaguid: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<UserDetailFactorsKeysItemAlgorithm>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lane: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<UserDetailFactorsKeysItemAttestation>,
    #[serde(rename = "attestationAlgorithms", default, skip_serializing_if = "Option::is_none")]
    pub attestation_algorithms: Option<UserDetailFactorsKeysItemAttestationAlgorithms_2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub provider: Option<Option<String>>,
    #[serde(rename = "lastUsedAt", default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<f64>,
    #[serde(rename = "backupEligible", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub backup_eligible: Option<Option<bool>>,
    #[serde(rename = "backupState", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub backup_state: Option<Option<bool>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub discoverable: Option<Option<bool>>,
    #[serde(rename = "deviceSerial", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub device_serial: Option<Option<String>>,
    #[serde(rename = "possiblyReplaced", default, skip_serializing_if = "Option::is_none")]
    pub possibly_replaced: Option<UserDetailFactorsKeysItemPossiblyReplaced>,
    #[serde(rename = "withoutUsername", default, skip_serializing_if = "Option::is_none")]
    pub without_username: Option<UserDetailFactorsKeysItemWithoutUsername>,
    #[serde(rename = "postQuantumRefused", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum_refused: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsAppPasswordsItem {
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
pub struct UserDetailFactorsPasswordOnlyDoors {
    #[serde(rename = "secondFactor", default, skip_serializing_if = "Option::is_none")]
    pub second_factor: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted: Option<Vec<String>>,
    #[serde(rename = "passwordAloneDoors", default, skip_serializing_if = "Option::is_none")]
    pub password_alone_doors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sentence: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactorsPolicy {
    #[serde(rename = "totpEnabled", default, skip_serializing_if = "Option::is_none")]
    pub totp_enabled: Option<bool>,
    #[serde(rename = "backupCodesEnabled", default, skip_serializing_if = "Option::is_none")]
    pub backup_codes_enabled: Option<bool>,
    #[serde(rename = "backupCodesCount", default, skip_serializing_if = "Option::is_none")]
    pub backup_codes_count: Option<f64>,
    #[serde(rename = "webauthnEnabled", default, skip_serializing_if = "Option::is_none")]
    pub webauthn_enabled: Option<bool>,
    #[serde(rename = "primaryAllowed", default, skip_serializing_if = "Option::is_none")]
    pub primary_allowed: Option<bool>,
    #[serde(rename = "mfaAllowed", default, skip_serializing_if = "Option::is_none")]
    pub mfa_allowed: Option<bool>,
    #[serde(rename = "maxKeysPerPerson", default, skip_serializing_if = "Option::is_none")]
    pub max_keys_per_person: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFactors {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<bool>,
    #[serde(rename = "passwordChangeRequired", default, skip_serializing_if = "Option::is_none")]
    pub password_change_required: Option<bool>,
    #[serde(rename = "passwordResetLink", default, skip_serializing_if = "Option::is_none")]
    pub password_reset_link: Option<UserDetailFactorsPasswordResetLink>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
    #[serde(rename = "mfaRequirement", default, skip_serializing_if = "Option::is_none")]
    pub mfa_requirement: Option<UserDetailFactorsMfaRequirement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activated: Option<bool>,
    #[serde(rename = "mfaRequired", default, skip_serializing_if = "Option::is_none")]
    pub mfa_required: Option<bool>,
    #[serde(rename = "secondFactor", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub second_factor: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<bool>,
    #[serde(rename = "totpUsable", default, skip_serializing_if = "Option::is_none")]
    pub totp_usable: Option<bool>,
    #[serde(rename = "totpDetail", default, skip_serializing_if = "Option::is_none")]
    pub totp_detail: Option<UserDetailFactorsTotpDetail>,
    #[serde(rename = "backupCodes", default, skip_serializing_if = "Option::is_none")]
    pub backup_codes: Option<UserDetailFactorsBackupCodes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<UserDetailFactorsKeysItem>>,
    #[serde(rename = "primaryKeys", default, skip_serializing_if = "Option::is_none")]
    pub primary_keys: Option<f64>,
    #[serde(rename = "mfaKeys", default, skip_serializing_if = "Option::is_none")]
    pub mfa_keys: Option<f64>,
    #[serde(rename = "appPasswords", default, skip_serializing_if = "Option::is_none")]
    pub app_passwords: Option<Vec<UserDetailFactorsAppPasswordsItem>>,
    #[serde(rename = "passwordOnlyDoors", default, skip_serializing_if = "Option::is_none")]
    pub password_only_doors: Option<UserDetailFactorsPasswordOnlyDoors>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<UserDetailFactorsPolicy>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailSessionsItemDeviceBound {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(rename = "boundAt", default, skip_serializing_if = "Option::is_none")]
    pub bound_at: Option<f64>,
    #[serde(rename = "refreshedAt", default, skip_serializing_if = "Option::is_none")]
    pub refreshed_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refreshes: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasons: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum UserDetailSessionsItemTokensItemClientId {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum UserDetailSessionsItemTokensItemScope {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailSessionsItemTokensItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<UserDetailSessionsItemTokensItemClientId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<UserDetailSessionsItemTokensItemScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jkt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
    #[serde(rename = "x5tSpki", default, skip_serializing_if = "Option::is_none")]
    pub x5t_spki: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<f64>,
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(rename = "sessionAuthenticated", default, skip_serializing_if = "Option::is_none")]
    pub session_authenticated: Option<bool>,
    #[serde(rename = "setId", default, skip_serializing_if = "Option::is_none")]
    pub set_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
    #[serde(rename = "grantId", default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    #[serde(rename = "grantRefresh", default, skip_serializing_if = "Option::is_none")]
    pub grant_refresh: Option<bool>,
    #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<bool>,
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<f64>,
    #[serde(rename = "revokedVia", default, skip_serializing_if = "Option::is_none")]
    pub revoked_via: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailSessionsItemTokensPaging {
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
pub struct UserDetailSessionsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(rename = "startedAt", default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<f64>,
    #[serde(rename = "authTime", default, skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentications: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    #[serde(rename = "wsfedRealms", default, skip_serializing_if = "Option::is_none")]
    pub wsfed_realms: Option<Vec<String>>,
    #[serde(rename = "deviceBound", default, skip_serializing_if = "Option::is_none")]
    pub device_bound: Option<UserDetailSessionsItemDeviceBound>,
    #[serde(rename = "accountSet", default, skip_serializing_if = "Option::is_none")]
    pub account_set: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<Vec<UserDetailSessionsItemTokensItem>>,
    #[serde(rename = "tokensPaging", default, skip_serializing_if = "Option::is_none")]
    pub tokens_paging: Option<UserDetailSessionsItemTokensPaging>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailSessionsPaging {
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
#[serde(untagged)]
pub enum UserDetailTokensOnEndedSessionsItemClientId {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum UserDetailTokensOnEndedSessionsItemScope {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailTokensOnEndedSessionsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<UserDetailTokensOnEndedSessionsItemClientId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<UserDetailTokensOnEndedSessionsItemScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jkt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
    #[serde(rename = "x5tSpki", default, skip_serializing_if = "Option::is_none")]
    pub x5t_spki: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<f64>,
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(rename = "sessionAuthenticated", default, skip_serializing_if = "Option::is_none")]
    pub session_authenticated: Option<bool>,
    #[serde(rename = "setId", default, skip_serializing_if = "Option::is_none")]
    pub set_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
    #[serde(rename = "grantId", default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    #[serde(rename = "grantRefresh", default, skip_serializing_if = "Option::is_none")]
    pub grant_refresh: Option<bool>,
    #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<bool>,
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<f64>,
    #[serde(rename = "revokedVia", default, skip_serializing_if = "Option::is_none")]
    pub revoked_via: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailTokensOnEndedSessionsPaging {
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
#[serde(untagged)]
pub enum UserDetailTokensWithNoSessionItemClientId {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum UserDetailTokensWithNoSessionItemScope {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailTokensWithNoSessionItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<UserDetailTokensWithNoSessionItemClientId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<UserDetailTokensWithNoSessionItemScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jkt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
    #[serde(rename = "x5tSpki", default, skip_serializing_if = "Option::is_none")]
    pub x5t_spki: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<f64>,
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(rename = "sessionAuthenticated", default, skip_serializing_if = "Option::is_none")]
    pub session_authenticated: Option<bool>,
    #[serde(rename = "setId", default, skip_serializing_if = "Option::is_none")]
    pub set_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
    #[serde(rename = "grantId", default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    #[serde(rename = "grantRefresh", default, skip_serializing_if = "Option::is_none")]
    pub grant_refresh: Option<bool>,
    #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<bool>,
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<f64>,
    #[serde(rename = "revokedVia", default, skip_serializing_if = "Option::is_none")]
    pub revoked_via: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailTokensWithNoSessionPaging {
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
pub struct UserDetailArtifactsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<f64>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<bool>,
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<f64>,
    #[serde(rename = "revokedVia", default, skip_serializing_if = "Option::is_none")]
    pub revoked_via: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etype: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "claimSet", default, skip_serializing_if = "Option::is_none")]
    pub claim_set: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(rename = "pacClaims", default, skip_serializing_if = "Option::is_none")]
    pub pac_claims: Option<f64>,
    #[serde(rename = "entryId", default, skip_serializing_if = "Option::is_none")]
    pub entry_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person: Option<String>,
    #[serde(rename = "configId", default, skip_serializing_if = "Option::is_none")]
    pub config_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailArtifactsPaging {
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
pub struct UserDetailLdapEntryMembersItem {
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
#[serde(deny_unknown_fields)]
pub struct UserDetailLdapEntry {
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
    pub members: Option<Vec<UserDetailLdapEntryMembersItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailLdap {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub found: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<UserDetailLdapEntry>,
    #[serde(rename = "alsoNamed", default, skip_serializing_if = "Option::is_none")]
    pub also_named: Option<Vec<String>>,
    #[serde(rename = "baseDn", default, skip_serializing_if = "Option::is_none")]
    pub base_dn: Option<String>,
    #[serde(rename = "usersDn", default, skip_serializing_if = "Option::is_none")]
    pub users_dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub port: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listening: Option<bool>,
    #[serde(rename = "listenError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub listen_error: Option<Option<String>>,
    #[serde(rename = "ldapsPort", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ldaps_port: Option<Option<f64>>,
    #[serde(rename = "ldapsListening", default, skip_serializing_if = "Option::is_none")]
    pub ldaps_listening: Option<bool>,
    #[serde(rename = "autoCreateUsers", default, skip_serializing_if = "Option::is_none")]
    pub auto_create_users: Option<bool>,
    #[serde(rename = "entryCount", default, skip_serializing_if = "Option::is_none")]
    pub entry_count: Option<f64>,
    #[serde(rename = "maxEntries", default, skip_serializing_if = "Option::is_none")]
    pub max_entries: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailCredentialsKeyPairsItemKeysItemCertificate {
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
    #[serde(rename = "selfSigned", default, skip_serializing_if = "Option::is_none")]
    pub self_signed: Option<bool>,
    #[serde(rename = "keyType", default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailCredentialsKeyPairsItemKeysItemChainItem {
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
    #[serde(rename = "selfSigned", default, skip_serializing_if = "Option::is_none")]
    pub self_signed: Option<bool>,
    #[serde(rename = "keyType", default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailCredentialsKeyPairsItemKeysItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(rename = "privateKeyHeld", default, skip_serializing_if = "Option::is_none")]
    pub private_key_held: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<UserDetailCredentialsKeyPairsItemKeysItemCertificate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<Vec<UserDetailCredentialsKeyPairsItemKeysItemChainItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailCredentialsKeyPairsItemAttributes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<String>,
    #[serde(rename = "privateKey", default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailCredentialsKeyPairsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<UserDetailCredentialsKeyPairsItemKeysItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid: Option<f64>,
    #[serde(rename = "atCap", default, skip_serializing_if = "Option::is_none")]
    pub at_cap: Option<bool>,
    #[serde(rename = "handleLabel", default, skip_serializing_if = "Option::is_none")]
    pub handle_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuers: Option<Vec<String>>,
    #[serde(rename = "effectiveIssuers", default, skip_serializing_if = "Option::is_none")]
    pub effective_issuers: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<UserDetailCredentialsKeyPairsItemAttributes>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailCredentials {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub found: Option<bool>,
    #[serde(rename = "keyPairs", default, skip_serializing_if = "Option::is_none")]
    pub key_pairs: Option<Vec<UserDetailCredentialsKeyPairsItem>>,
    #[serde(rename = "maxPerPerson", default, skip_serializing_if = "Option::is_none")]
    pub max_per_person: Option<f64>,
    #[serde(rename = "revocationReasons", default, skip_serializing_if = "Option::is_none")]
    pub revocation_reasons: Option<Vec<String>>,
    #[serde(rename = "caAvailable", default, skip_serializing_if = "Option::is_none")]
    pub ca_available: Option<bool>,
    #[serde(rename = "sealsAtRest", default, skip_serializing_if = "Option::is_none")]
    pub seals_at_rest: Option<bool>,
    #[serde(rename = "selfService", default, skip_serializing_if = "Option::is_none")]
    pub self_service: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sources: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFederationLinksItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(rename = "relationshipExists", default, skip_serializing_if = "Option::is_none")]
    pub relationship_exists: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailFederationLinksPaging {
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
pub struct UserDetailKerberosKeysEtypesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etype: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailKerberosKeysRetainedItemEtypesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etype: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailKerberosKeysRetainedItem {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub kvno: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etypes: Option<Vec<UserDetailKerberosKeysRetainedItemEtypesItem>>,
    #[serde(rename = "retiredAt", default, skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailKerberosKeys {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub kvno: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etypes: Option<Vec<UserDetailKerberosKeysEtypesItem>>,
    #[serde(rename = "derivedAt", default, skip_serializing_if = "Option::is_none")]
    pub derived_at: Option<String>,
    #[serde(rename = "derivedOn", default, skip_serializing_if = "Option::is_none")]
    pub derived_on: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retained: Option<Vec<UserDetailKerberosKeysRetainedItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailKerberos {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdc: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(rename = "trustRealm", default, skip_serializing_if = "Option::is_none")]
    pub trust_realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "productKdc", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub product_kdc: Option<Option<bool>>,
    #[serde(rename = "personKeys", default, skip_serializing_if = "Option::is_none")]
    pub person_keys: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    #[serde(rename = "nameUsable", default, skip_serializing_if = "Option::is_none")]
    pub name_usable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<UserDetailKerberosKeys>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailAttributeEditorAttributesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simple: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub must: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multi: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub choices: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailAttributeEditorWithheldItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailAttributeEditor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<UserDetailAttributeEditorAttributesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withheld: Option<Vec<UserDetailAttributeEditorWithheldItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pseudonyms: Option<Vec<String>>,
    #[serde(rename = "pseudonymPending", default, skip_serializing_if = "Option::is_none")]
    pub pseudonym_pending: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailGnapGrantsItemFinalization {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailGnapGrantsItemTokensItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub label: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub issued_at: Option<Option<f64>>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub expires_at: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer: Option<bool>,
    /// An RFC 9635 access right as the client asked for it: a reference string
    /// or an object in the access type the resource server defines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<serde_json::Value>,
    #[serde(rename = "revokedWhy", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub revoked_why: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailGnapGrantsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finalization: Option<UserDetailGnapGrantsItemFinalization>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub client: Option<Option<String>>,
    #[serde(rename = "clientName", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub client_name: Option<Option<String>>,
    #[serde(rename = "authorizationServer", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub authorization_server: Option<Option<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<f64>>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub updated_at: Option<Option<f64>>,
    #[serde(rename = "grantExpiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub grant_expires_at: Option<Option<f64>>,
    #[serde(rename = "approvedBy", default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    /// An RFC 9635 access right as the client asked for it: a reference string
    /// or an object in the access type the resource server defines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rights: Option<serde_json::Value>,
    #[serde(rename = "rightsAre", default, skip_serializing_if = "Option::is_none")]
    pub rights_are: Option<String>,
    #[serde(rename = "subjectReleasedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub subject_released_at: Option<Option<f64>>,
    #[serde(rename = "derivedFrom", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub derived_from: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<Vec<UserDetailGnapGrantsItemTokensItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocable: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailGnapGrantsPaging {
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
pub struct UserDetailGnapGrantsCells {
    #[serde(rename = "multiCell", default, skip_serializing_if = "Option::is_none")]
    pub multi_cell: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub complete: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailUmaResourcesItem {
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
pub struct UserDetailUmaSharesItemRecipient {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailUmaSharesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "resourceId", default, skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<UserDetailUmaSharesItemRecipient>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(rename = "askMe", default, skip_serializing_if = "Option::is_none")]
    pub ask_me: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum UserDetailUmaHeldItemPermissions {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailUmaHeldItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(rename = "requestingParty", default, skip_serializing_if = "Option::is_none")]
    pub requesting_party: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(rename = "resourceServer", default, skip_serializing_if = "Option::is_none")]
    pub resource_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<UserDetailUmaHeldItemPermissions>,
    #[serde(rename = "upgradedFrom", default, skip_serializing_if = "Option::is_none")]
    pub upgraded_from: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum UserDetailUmaPendingItemPermissions {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailUmaPendingItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(rename = "ownerKind", default, skip_serializing_if = "Option::is_none")]
    pub owner_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(rename = "resourceServer", default, skip_serializing_if = "Option::is_none")]
    pub resource_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<UserDetailUmaPendingItemPermissions>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<f64>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailUma {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<UserDetailUmaResourcesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shares: Option<Vec<UserDetailUmaSharesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<Vec<UserDetailUmaHeldItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<Vec<UserDetailUmaPendingItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailAuthenticationEventsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(rename = "actorForm", default, skip_serializing_if = "Option::is_none")]
    pub actor_form: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// What the call site that wrote the audit row chose to record, which
    /// differs at each of hundreds of them; the keys and the values are data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailAuthenticationEventsPaging {
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
pub struct UserDetailAuthenticationEventsLog {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dropped: Option<f64>,
    #[serde(rename = "maxEvents", default, skip_serializing_if = "Option::is_none")]
    pub max_events: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageCounts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessionless: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechKeysItemPublicKeyJwk {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kty: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    #[serde(rename = "pub", default, skip_serializing_if = "Option::is_none")]
    pub pub_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechKeysItemAlgorithmV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "coseAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cose_alg: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insecure: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lane: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum UserDetailPageMfaMechKeysItemAlgorithm {
    V1(UserDetailPageMfaMechKeysItemAlgorithmV1),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechKeysItemAttestationAlgorithmsCertificatesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composite: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechKeysItemAttestationAlgorithmsAnchor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composite: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechKeysItemAttestationAlgorithmsMembersItemCertificatesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composite: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechKeysItemAttestationAlgorithmsMembersItemAnchor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composite: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechKeysItemAttestationAlgorithmsMembersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    #[serde(rename = "statementCoseAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub statement_cose_alg: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<UserDetailPageMfaMechKeysItemAttestationAlgorithmsMembersItemCertificatesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<UserDetailPageMfaMechKeysItemAttestationAlgorithmsMembersItemAnchor>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechKeysItemAttestationAlgorithms {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    #[serde(rename = "statementCoseAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub statement_cose_alg: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<UserDetailPageMfaMechKeysItemAttestationAlgorithmsCertificatesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<UserDetailPageMfaMechKeysItemAttestationAlgorithmsAnchor>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<UserDetailPageMfaMechKeysItemAttestationAlgorithmsMembersItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechKeysItemAttestationEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syntax: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    #[serde(rename = "objectDigest", default, skip_serializing_if = "Option::is_none")]
    pub object_digest: Option<String>,
    #[serde(rename = "evidenceRecord", default, skip_serializing_if = "Option::is_none")]
    pub evidence_record: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamps: Option<Vec<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "renewedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub renewed_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "renewAfter", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub renew_after: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "hashAlgorithm", default, skip_serializing_if = "Option::is_none")]
    pub hash_algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub tsa: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechKeysItemAttestationAndroidRevocation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(rename = "listVersion", default, skip_serializing_if = "Option::is_none")]
    pub list_version: Option<String>,
    #[serde(rename = "checkedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub checked_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "chainSerials", default, skip_serializing_if = "Option::is_none")]
    pub chain_serials: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechKeysItemAttestation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub aaguid: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(rename = "certificationLevel", default, skip_serializing_if = "Option::is_none")]
    pub certification_level: Option<String>,
    #[serde(rename = "mdsStatus", default, skip_serializing_if = "Option::is_none")]
    pub mds_status: Option<String>,
    #[serde(rename = "mdsVersion", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub mds_version: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "checkedAt", default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithms: Option<UserDetailPageMfaMechKeysItemAttestationAlgorithms>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conveyance: Option<String>,
    #[serde(rename = "enterpriseDowngraded", default, skip_serializing_if = "Option::is_none")]
    pub enterprise_downgraded: Option<bool>,
    #[serde(rename = "attestationKeyId", default, skip_serializing_if = "Option::is_none")]
    pub attestation_key_id: Option<String>,
    #[serde(rename = "deviceSerial", default, skip_serializing_if = "Option::is_none")]
    pub device_serial: Option<String>,
    #[serde(rename = "deviceSerialSource", default, skip_serializing_if = "Option::is_none")]
    pub device_serial_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<UserDetailPageMfaMechKeysItemAttestationEvidence>,
    #[serde(rename = "androidRevocation", default, skip_serializing_if = "Option::is_none")]
    pub android_revocation: Option<UserDetailPageMfaMechKeysItemAttestationAndroidRevocation>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechKeysItemEnrolledBy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechKeysItemAttestationRefused {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechKeysItem {
    #[serde(rename = "credentialId", default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(rename = "publicKeyJwk", default, skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<UserDetailPageMfaMechKeysItemPublicKeyJwk>,
    #[serde(rename = "signCount", default, skip_serializing_if = "Option::is_none")]
    pub sign_count: Option<f64>,
    #[serde(rename = "enrolledAt", default, skip_serializing_if = "Option::is_none")]
    pub enrolled_at: Option<f64>,
    #[serde(rename = "lastUsedAt", default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attachment: Option<Option<String>>,
    #[serde(rename = "userVerified", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub user_verified: Option<Option<bool>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub aaguid: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub algorithm: Option<Option<UserDetailPageMfaMechKeysItemAlgorithm>>,
    #[serde(rename = "coseAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cose_alg: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<UserDetailPageMfaMechKeysItemAttestation>,
    #[serde(rename = "backupEligible", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub backup_eligible: Option<Option<bool>>,
    #[serde(rename = "backupState", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub backup_state: Option<Option<bool>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub discoverable: Option<Option<bool>>,
    #[serde(rename = "minPinLength", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub min_pin_length: Option<Option<f64>>,
    #[serde(rename = "userHandle", default, skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lane: Option<String>,
    #[serde(rename = "enrolledBy", default, skip_serializing_if = "Option::is_none")]
    pub enrolled_by: Option<UserDetailPageMfaMechKeysItemEnrolledBy>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub provider: Option<Option<String>>,
    #[serde(rename = "providerSource", default, skip_serializing_if = "Option::is_none")]
    pub provider_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(rename = "upgradedAt", default, skip_serializing_if = "Option::is_none")]
    pub upgraded_at: Option<f64>,
    #[serde(rename = "upgradedTo", default, skip_serializing_if = "Option::is_none")]
    pub upgraded_to: Option<String>,
    #[serde(rename = "previousAlgorithm", default, skip_serializing_if = "Option::is_none")]
    pub previous_algorithm: Option<String>,
    #[serde(rename = "previousCoseAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub previous_cose_alg: Option<Option<f64>>,
    #[serde(rename = "previousCredentialId", default, skip_serializing_if = "Option::is_none")]
    pub previous_credential_id: Option<String>,
    #[serde(rename = "upgradeMode", default, skip_serializing_if = "Option::is_none")]
    pub upgrade_mode: Option<String>,
    #[serde(rename = "possiblyReplacedBy", default, skip_serializing_if = "Option::is_none")]
    pub possibly_replaced_by: Option<String>,
    #[serde(rename = "possiblyReplacedAt", default, skip_serializing_if = "Option::is_none")]
    pub possibly_replaced_at: Option<f64>,
    #[serde(rename = "policyRefused", default, skip_serializing_if = "Option::is_none")]
    pub policy_refused: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "attestationRefused", default, skip_serializing_if = "Option::is_none")]
    pub attestation_refused: Option<UserDetailPageMfaMechKeysItemAttestationRefused>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechTotpDetail {
    #[serde(rename = "enrolledAt", default, skip_serializing_if = "Option::is_none")]
    pub enrolled_at: Option<f64>,
    #[serde(rename = "lastUsedAt", default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digits: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unusable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechBackupCodes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used: Option<f64>,
    #[serde(rename = "generatedAt", default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<f64>,
    #[serde(rename = "lastUsedAt", default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hashed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechMailFactor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<String>,
    #[serde(rename = "optedIn", default, skip_serializing_if = "Option::is_none")]
    pub opted_in: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMechMfaRequirement {
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
pub struct UserDetailPageMfaMechPasswordResetLink {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMech {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<bool>,
    #[serde(rename = "primaryKeys", default, skip_serializing_if = "Option::is_none")]
    pub primary_keys: Option<f64>,
    #[serde(rename = "mfaKeys", default, skip_serializing_if = "Option::is_none")]
    pub mfa_keys: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<UserDetailPageMfaMechKeysItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<bool>,
    #[serde(rename = "totpUsable", default, skip_serializing_if = "Option::is_none")]
    pub totp_usable: Option<bool>,
    #[serde(rename = "totpDetail", default, skip_serializing_if = "Option::is_none")]
    pub totp_detail: Option<UserDetailPageMfaMechTotpDetail>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usable: Option<bool>,
    #[serde(rename = "backupCodes", default, skip_serializing_if = "Option::is_none")]
    pub backup_codes: Option<UserDetailPageMfaMechBackupCodes>,
    #[serde(rename = "mfaRequired", default, skip_serializing_if = "Option::is_none")]
    pub mfa_required: Option<bool>,
    #[serde(rename = "mailFactor", default, skip_serializing_if = "Option::is_none")]
    pub mail_factor: Option<UserDetailPageMfaMechMailFactor>,
    #[serde(rename = "secondFactor", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub second_factor: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activated: Option<bool>,
    #[serde(rename = "recoveryAdvised", default, skip_serializing_if = "Option::is_none")]
    pub recovery_advised: Option<bool>,
    #[serde(rename = "mfaRequirement", default, skip_serializing_if = "Option::is_none")]
    pub mfa_requirement: Option<UserDetailPageMfaMechMfaRequirement>,
    #[serde(rename = "passwordResetLink", default, skip_serializing_if = "Option::is_none")]
    pub password_reset_link: Option<UserDetailPageMfaMechPasswordResetLink>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaTotp {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digits: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<f64>,
    #[serde(rename = "secretBytes", default, skip_serializing_if = "Option::is_none")]
    pub secret_bytes: Option<f64>,
    #[serde(rename = "enrolmentTtlMs", default, skip_serializing_if = "Option::is_none")]
    pub enrolment_ttl_ms: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaWebauthn {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "rpName", default, skip_serializing_if = "Option::is_none")]
    pub rp_name: Option<String>,
    #[serde(rename = "rpId", default, skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithms: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
    #[serde(rename = "userVerification", default, skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,
    #[serde(rename = "residentKey", default, skip_serializing_if = "Option::is_none")]
    pub resident_key: Option<String>,
    #[serde(rename = "authenticatorAttachment", default, skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<String>,
    #[serde(rename = "timeoutMs", default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<f64>,
    #[serde(rename = "credProps", default, skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<bool>,
    #[serde(rename = "minPinLength", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub min_pin_length: Option<Option<sts_model_base::unions::BoolOrNumber>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hints: Option<Vec<String>>,
    #[serde(rename = "maxKeysPerPerson", default, skip_serializing_if = "Option::is_none")]
    pub max_keys_per_person: Option<f64>,
    #[serde(rename = "primaryAllowed", default, skip_serializing_if = "Option::is_none")]
    pub primary_allowed: Option<bool>,
    #[serde(rename = "mfaAllowed", default, skip_serializing_if = "Option::is_none")]
    pub mfa_allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usernameless: Option<bool>,
    #[serde(rename = "insecureAlgorithms", default, skip_serializing_if = "Option::is_none")]
    pub insecure_algorithms: Option<bool>,
    #[serde(rename = "pqcOnly", default, skip_serializing_if = "Option::is_none")]
    pub pqc_only: Option<bool>,
    #[serde(rename = "pqcAlongsideClassical", default, skip_serializing_if = "Option::is_none")]
    pub pqc_alongside_classical: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaRecovery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<f64>,
    #[serde(rename = "groupSize", default, skip_serializing_if = "Option::is_none")]
    pub group_size: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaAppPasswordsPasswordsItem {
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
pub struct UserDetailPageMfaAppPasswords {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passwords: Option<Vec<UserDetailPageMfaAppPasswordsPasswordsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaDoors {
    #[serde(rename = "secondFactor", default, skip_serializing_if = "Option::is_none")]
    pub second_factor: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted: Option<Vec<String>>,
    #[serde(rename = "passwordAloneDoors", default, skip_serializing_if = "Option::is_none")]
    pub password_alone_doors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sentence: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaVerificationsVerificationsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub recorded: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    /// The OpenID Connect for Identity Assurance `verification` element: a
    /// caller may post it whole as JSON, and a wallet or a certificate may
    /// supply it, so its evidence is that specification's to shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<serde_json::Value>,
    /// The verified claims and their values, as the OpenID Connect claim each
    /// is: a string for most, an object for `address`, a list for
    /// `nationalities`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaVerificationsPaging {
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
pub struct UserDetailPageMfaVerifications {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(rename = "trustFrameworks", default, skip_serializing_if = "Option::is_none")]
    pub trust_frameworks: Option<Vec<String>>,
    #[serde(rename = "evidenceTypes", default, skip_serializing_if = "Option::is_none")]
    pub evidence_types: Option<Vec<String>>,
    #[serde(rename = "documentTypes", default, skip_serializing_if = "Option::is_none")]
    pub document_types: Option<Vec<String>>,
    #[serde(rename = "checkMethods", default, skip_serializing_if = "Option::is_none")]
    pub check_methods: Option<Vec<String>>,
    #[serde(rename = "electronicRecordTypes", default, skip_serializing_if = "Option::is_none")]
    pub electronic_record_types: Option<Vec<String>>,
    #[serde(rename = "attestationTypes", default, skip_serializing_if = "Option::is_none")]
    pub attestation_types: Option<Vec<String>>,
    #[serde(rename = "verifiableClaims", default, skip_serializing_if = "Option::is_none")]
    pub verifiable_claims: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifications: Option<Vec<UserDetailPageMfaVerificationsVerificationsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<UserDetailPageMfaVerificationsPaging>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaDevicesDevicesItemKeysItemAttestationRevocation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(rename = "listVersion", default, skip_serializing_if = "Option::is_none")]
    pub list_version: Option<String>,
    #[serde(rename = "checkedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub checked_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "chainSerials", default, skip_serializing_if = "Option::is_none")]
    pub chain_serials: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaDevicesDevicesItemKeysItemAttestationFreshness {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaDevicesDevicesItemKeysItemAttestation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(rename = "verifiedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub verified_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "chainSerials", default, skip_serializing_if = "Option::is_none")]
    pub chain_serials: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation: Option<UserDetailPageMfaDevicesDevicesItemKeysItemAttestationRevocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freshness: Option<UserDetailPageMfaDevicesDevicesItemKeysItemAttestationFreshness>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaDevicesDevicesItemKeysItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub added: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "addedBy", default, skip_serializing_if = "Option::is_none")]
    pub added_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<UserDetailPageMfaDevicesDevicesItemKeysItemAttestation>,
    /// A device key's public material as its kind carries it: a client's JWK, a
    /// certificate, or a WebAuthn credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub material: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaDevicesDevicesItemAttestation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(rename = "keyId", default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaDevicesDevicesItemComplianceChange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub previous: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaDevicesDevicesItemStatusChange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub previous: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaDevicesDevicesItemRiskChange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub previous: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaDevicesDevicesItemEnrolment {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaDevicesDevicesItemRememberedBrowser {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<f64>,
    #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser: Option<String>,
    #[serde(rename = "secondFactorAt", default, skip_serializing_if = "Option::is_none")]
    pub second_factor_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaDevicesDevicesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(rename = "ownerKind", default, skip_serializing_if = "Option::is_none")]
    pub owner_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applications: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<UserDetailPageMfaDevicesDevicesItemKeysItem>>,
    #[serde(rename = "keyKinds", default, skip_serializing_if = "Option::is_none")]
    pub key_kinds: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<UserDetailPageMfaDevicesDevicesItemAttestation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance: Option<String>,
    #[serde(rename = "complianceChange", default, skip_serializing_if = "Option::is_none")]
    pub compliance_change: Option<UserDetailPageMfaDevicesDevicesItemComplianceChange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(rename = "statusChange", default, skip_serializing_if = "Option::is_none")]
    pub status_change: Option<UserDetailPageMfaDevicesDevicesItemStatusChange>,
    #[serde(rename = "riskLevel", default, skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
    #[serde(rename = "riskChange", default, skip_serializing_if = "Option::is_none")]
    pub risk_change: Option<UserDetailPageMfaDevicesDevicesItemRiskChange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrolment: Option<UserDetailPageMfaDevicesDevicesItemEnrolment>,
    #[serde(rename = "nativeSso", default, skip_serializing_if = "Option::is_none")]
    pub native_sso: Option<bool>,
    #[serde(rename = "rememberedBrowser", default, skip_serializing_if = "Option::is_none")]
    pub remembered_browser: Option<UserDetailPageMfaDevicesDevicesItemRememberedBrowser>,
    #[serde(rename = "sessionLive", default, skip_serializing_if = "Option::is_none")]
    pub session_live: Option<bool>,
    #[serde(rename = "lastUsed", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_used: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created: Option<Option<sts_model_base::unions::NumberOrString>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaDevices {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(rename = "maxPerPerson", default, skip_serializing_if = "Option::is_none")]
    pub max_per_person: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub devices: Option<Vec<UserDetailPageMfaDevicesDevicesItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaSelfIssuedSubjectsItemLocation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaSelfIssuedSubjectsItem {
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
    pub location: Option<UserDetailPageMfaSelfIssuedSubjectsItemLocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred: Option<bool>,
    #[serde(rename = "pinnedKeys", default, skip_serializing_if = "Option::is_none")]
    pub pinned_keys: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaSelfIssued {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(rename = "entryFound", default, skip_serializing_if = "Option::is_none")]
    pub entry_found: Option<bool>,
    #[serde(rename = "signInEnabled", default, skip_serializing_if = "Option::is_none")]
    pub sign_in_enabled: Option<bool>,
    #[serde(rename = "maxPerPerson", default, skip_serializing_if = "Option::is_none")]
    pub max_per_person: Option<f64>,
    #[serde(rename = "subjectSyntaxTypes", default, skip_serializing_if = "Option::is_none")]
    pub subject_syntax_types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subjects: Option<Vec<UserDetailPageMfaSelfIssuedSubjectsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaPublishedDidsDidsItemDeactivatedV1 {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum UserDetailPageMfaPublishedDidsDidsItemDeactivated {
    V1(UserDetailPageMfaPublishedDidsDidsItemDeactivatedV1),
    Bool(bool),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaPublishedDidsDidsItemPending {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaPublishedDidsDidsItemVersionsItemKeysItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kty: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaPublishedDidsDidsItemVersionsItemAuthorizedByItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "keyThumbprint", default, skip_serializing_if = "Option::is_none")]
    pub key_thumbprint: Option<String>,
    #[serde(rename = "versionId", default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<sts_model_base::unions::NumberOrString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaPublishedDidsDidsItemVersionsItem {
    #[serde(rename = "versionId", default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<sts_model_base::unions::NumberOrString>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<UserDetailPageMfaPublishedDidsDidsItemVersionsItemKeysItem>>,
    #[serde(rename = "authorizedBy", default, skip_serializing_if = "Option::is_none")]
    pub authorized_by: Option<Vec<UserDetailPageMfaPublishedDidsDidsItemVersionsItemAuthorizedByItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaPublishedDidsDidsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody: Option<String>,
    #[serde(rename = "documentUrl", default, skip_serializing_if = "Option::is_none")]
    pub document_url: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub deactivated: Option<Option<UserDetailPageMfaPublishedDidsDidsItemDeactivated>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred: Option<bool>,
    #[serde(rename = "currentVersion", default, skip_serializing_if = "Option::is_none")]
    pub current_version: Option<sts_model_base::unions::NumberOrString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<UserDetailPageMfaPublishedDidsDidsItemPending>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub versions: Option<Vec<UserDetailPageMfaPublishedDidsDidsItemVersionsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaPublishedDids {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(rename = "entryFound", default, skip_serializing_if = "Option::is_none")]
    pub entry_found: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publishing: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody: Option<String>,
    #[serde(rename = "maxPerPerson", default, skip_serializing_if = "Option::is_none")]
    pub max_per_person: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dids: Option<Vec<UserDetailPageMfaPublishedDidsDidsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaCertificatesCertificatesItem {
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
pub struct UserDetailPageMfaCertificates {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<UserDetailPageMfaCertificatesCertificatesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaSigningCertificatesItem {
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
pub struct UserDetailPageMfaSigning {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(rename = "implicitName", default, skip_serializing_if = "Option::is_none")]
    pub implicit_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<UserDetailPageMfaSigningCertificatesItem>>,
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
pub struct UserDetailPageMfaMailStatusOffered {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMailStatus {
    #[serde(rename = "optedIn", default, skip_serializing_if = "Option::is_none")]
    pub opted_in: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offered: Option<UserDetailPageMfaMailStatusOffered>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfaMail {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<UserDetailPageMfaMailStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usable: Option<bool>,
    #[serde(rename = "audSubs", default, skip_serializing_if = "Option::is_none")]
    pub aud_subs: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageMfa {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mech: Option<UserDetailPageMfaMech>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<UserDetailPageMfaTotp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webauthn: Option<UserDetailPageMfaWebauthn>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<UserDetailPageMfaRecovery>,
    #[serde(rename = "appPasswords", default, skip_serializing_if = "Option::is_none")]
    pub app_passwords: Option<UserDetailPageMfaAppPasswords>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doors: Option<UserDetailPageMfaDoors>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifications: Option<UserDetailPageMfaVerifications>,
    #[serde(rename = "inventsClaimValues", default, skip_serializing_if = "Option::is_none")]
    pub invents_claim_values: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub devices: Option<UserDetailPageMfaDevices>,
    #[serde(rename = "selfIssued", default, skip_serializing_if = "Option::is_none")]
    pub self_issued: Option<UserDetailPageMfaSelfIssued>,
    #[serde(rename = "publishedDids", default, skip_serializing_if = "Option::is_none")]
    pub published_dids: Option<UserDetailPageMfaPublishedDids>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<UserDetailPageMfaCertificates>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing: Option<UserDetailPageMfaSigning>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail: Option<UserDetailPageMfaMail>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageFieldGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageDelegationDelegateV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum UserDetailPageDelegationDelegate {
    V1(UserDetailPageDelegationDelegateV1),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageDelegationGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cn: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageDelegation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub found: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(rename = "notDelegated", default, skip_serializing_if = "Option::is_none")]
    pub not_delegated: Option<bool>,
    #[serde(rename = "mayAct", default, skip_serializing_if = "Option::is_none")]
    pub may_act: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub delegate: Option<Option<UserDetailPageDelegationDelegate>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantics: Option<Vec<String>>,
    #[serde(rename = "defaultSemantics", default, skip_serializing_if = "Option::is_none")]
    pub default_semantics: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<UserDetailPageDelegationGroupsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageKeyPairsPurposesItemKeysItemCertificate {
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
    #[serde(rename = "selfSigned", default, skip_serializing_if = "Option::is_none")]
    pub self_signed: Option<bool>,
    #[serde(rename = "keyType", default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageKeyPairsPurposesItemKeysItemChainItem {
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
    #[serde(rename = "selfSigned", default, skip_serializing_if = "Option::is_none")]
    pub self_signed: Option<bool>,
    #[serde(rename = "keyType", default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageKeyPairsPurposesItemKeysItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(rename = "privateKeyHeld", default, skip_serializing_if = "Option::is_none")]
    pub private_key_held: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<UserDetailPageKeyPairsPurposesItemKeysItemCertificate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<Vec<UserDetailPageKeyPairsPurposesItemKeysItemChainItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageKeyPairsPurposesItemAttributes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<String>,
    #[serde(rename = "privateKey", default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageKeyPairsPurposesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<UserDetailPageKeyPairsPurposesItemKeysItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid: Option<f64>,
    #[serde(rename = "atCap", default, skip_serializing_if = "Option::is_none")]
    pub at_cap: Option<bool>,
    #[serde(rename = "handleLabel", default, skip_serializing_if = "Option::is_none")]
    pub handle_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuers: Option<Vec<String>>,
    #[serde(rename = "effectiveIssuers", default, skip_serializing_if = "Option::is_none")]
    pub effective_issuers: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<UserDetailPageKeyPairsPurposesItemAttributes>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageKeyPairsCaKeyAlgorithmsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(rename = "tlsUsable", default, skip_serializing_if = "Option::is_none")]
    pub tls_usable: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageKeyPairsCa {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub available: Option<bool>,
    #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
    pub key_alg: Option<String>,
    #[serde(rename = "leafLifetimeDays", default, skip_serializing_if = "Option::is_none")]
    pub leaf_lifetime_days: Option<f64>,
    #[serde(rename = "keyAlgorithms", default, skip_serializing_if = "Option::is_none")]
    pub key_algorithms: Option<Vec<UserDetailPageKeyPairsCaKeyAlgorithmsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageKeyPairs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub found: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purposes: Option<Vec<UserDetailPageKeyPairsPurposesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<UserDetailPageKeyPairsCa>,
    #[serde(rename = "sealsAtRest", default, skip_serializing_if = "Option::is_none")]
    pub seals_at_rest: Option<bool>,
    #[serde(rename = "selfService", default, skip_serializing_if = "Option::is_none")]
    pub self_service: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sources: Option<Vec<String>>,
    #[serde(rename = "maxPerPerson", default, skip_serializing_if = "Option::is_none")]
    pub max_per_person: Option<f64>,
    #[serde(rename = "revocationReasons", default, skip_serializing_if = "Option::is_none")]
    pub revocation_reasons: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageServiceAccountRules {
    #[serde(rename = "requiresOwner", default, skip_serializing_if = "Option::is_none")]
    pub requires_owner: Option<bool>,
    #[serde(rename = "maxOwners", default, skip_serializing_if = "Option::is_none")]
    pub max_owners: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPageServiceProvidersItem {
    #[serde(rename = "fedId", default, skip_serializing_if = "Option::is_none")]
    pub fed_id: Option<String>,
    #[serde(rename = "fedPeer", default, skip_serializing_if = "Option::is_none")]
    pub fed_peer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetailPage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(rename = "riskAsked", default, skip_serializing_if = "Option::is_none")]
    pub risk_asked: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<UserDetailPageCounts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub back: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "blocksPerPage", default, skip_serializing_if = "Option::is_none")]
    pub blocks_per_page: Option<f64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<f64>,
    #[serde(rename = "maxEventsPerUser", default, skip_serializing_if = "Option::is_none")]
    pub max_events_per_user: Option<f64>,
    #[serde(rename = "directoryLoaded", default, skip_serializing_if = "Option::is_none")]
    pub directory_loaded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mfa: Option<UserDetailPageMfa>,
    #[serde(rename = "fieldGroups", default, skip_serializing_if = "Option::is_none")]
    pub field_groups: Option<Vec<UserDetailPageFieldGroupsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<UserDetailPageDelegation>,
    #[serde(rename = "keyPairs", default, skip_serializing_if = "Option::is_none")]
    pub key_pairs: Option<UserDetailPageKeyPairs>,
    #[serde(rename = "serviceAccountRules", default, skip_serializing_if = "Option::is_none")]
    pub service_account_rules: Option<UserDetailPageServiceAccountRules>,
    #[serde(rename = "serviceProviders", default, skip_serializing_if = "Option::is_none")]
    pub service_providers: Option<Vec<UserDetailPageServiceProvidersItem>>,
}

/// One identity: the names it has been seen under, how it authenticated, every
/// sign-on session it holds with the tokens issued on each, and its directory
/// entry.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserDetail {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<UserDetailUser>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(rename = "serviceAccount", default, skip_serializing_if = "Option::is_none")]
    pub service_account: Option<UserDetailServiceAccount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<UserDetailRisk>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub factors: Option<UserDetailFactors>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<Vec<UserDetailSessionsItem>>,
    #[serde(rename = "sessionsPaging", default, skip_serializing_if = "Option::is_none")]
    pub sessions_paging: Option<UserDetailSessionsPaging>,
    #[serde(rename = "tokensOnEndedSessions", default, skip_serializing_if = "Option::is_none")]
    pub tokens_on_ended_sessions: Option<Vec<UserDetailTokensOnEndedSessionsItem>>,
    #[serde(rename = "tokensOnEndedSessionsPaging", default, skip_serializing_if = "Option::is_none")]
    pub tokens_on_ended_sessions_paging: Option<UserDetailTokensOnEndedSessionsPaging>,
    #[serde(rename = "tokensWithNoSession", default, skip_serializing_if = "Option::is_none")]
    pub tokens_with_no_session: Option<Vec<UserDetailTokensWithNoSessionItem>>,
    #[serde(rename = "tokensWithNoSessionPaging", default, skip_serializing_if = "Option::is_none")]
    pub tokens_with_no_session_paging: Option<UserDetailTokensWithNoSessionPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<Vec<UserDetailArtifactsItem>>,
    #[serde(rename = "artifactsPaging", default, skip_serializing_if = "Option::is_none")]
    pub artifacts_paging: Option<UserDetailArtifactsPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldap: Option<UserDetailLdap>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<UserDetailCredentials>,
    #[serde(rename = "federationLinks", default, skip_serializing_if = "Option::is_none")]
    pub federation_links: Option<Vec<UserDetailFederationLinksItem>>,
    #[serde(rename = "federationLinksPaging", default, skip_serializing_if = "Option::is_none")]
    pub federation_links_paging: Option<UserDetailFederationLinksPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kerberos: Option<UserDetailKerberos>,
    #[serde(rename = "attributeEditor", default, skip_serializing_if = "Option::is_none")]
    pub attribute_editor: Option<UserDetailAttributeEditor>,
    #[serde(rename = "gnapGrants", default, skip_serializing_if = "Option::is_none")]
    pub gnap_grants: Option<Vec<UserDetailGnapGrantsItem>>,
    #[serde(rename = "gnapGrantsPaging", default, skip_serializing_if = "Option::is_none")]
    pub gnap_grants_paging: Option<UserDetailGnapGrantsPaging>,
    #[serde(rename = "gnapGrantsCells", default, skip_serializing_if = "Option::is_none")]
    pub gnap_grants_cells: Option<UserDetailGnapGrantsCells>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uma: Option<UserDetailUma>,
    #[serde(rename = "authenticationEvents", default, skip_serializing_if = "Option::is_none")]
    pub authentication_events: Option<Vec<UserDetailAuthenticationEventsItem>>,
    #[serde(rename = "authenticationEventsPaging", default, skip_serializing_if = "Option::is_none")]
    pub authentication_events_paging: Option<UserDetailAuthenticationEventsPaging>,
    #[serde(rename = "authenticationEventsMatched", default, skip_serializing_if = "Option::is_none")]
    pub authentication_events_matched: Option<f64>,
    #[serde(rename = "authenticationEventsKnownActors", default, skip_serializing_if = "Option::is_none")]
    pub authentication_events_known_actors: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "authenticationEventsLog", default, skip_serializing_if = "Option::is_none")]
    pub authentication_events_log: Option<UserDetailAuthenticationEventsLog>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<UserDetailPage>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum UserInfoClaimSetsProtocolEndpointsItemMethods {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsProtocolEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<UserInfoClaimSetsProtocolEndpointsItemMethods>,
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
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsClaimsRequestRequestableItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldap: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub label: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grouped: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsClaimsRequestDirectParameter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spellings: Option<Vec<String>>,
    #[serde(rename = "malformedIsRefused", default, skip_serializing_if = "Option::is_none")]
    pub malformed_is_refused: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsClaimsRequestPreviewReportItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldap: Option<String>,
    /// A claim value as it would be issued. Its JSON type is the catalogue
    /// row's and the person's own data, and a row may nest under a dotted path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsClaimsRequestPreview {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    /// The claims request as a caller typed it, parsed: OIDC Core 5.5 keys it
    /// by the claims they ask for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parsed: Option<serde_json::Value>,
    #[serde(rename = "ignoredMembers", default, skip_serializing_if = "Option::is_none")]
    pub ignored_members: Option<Vec<String>>,
    #[serde(rename = "idTokenNames", default, skip_serializing_if = "Option::is_none")]
    pub id_token_names: Option<Vec<String>>,
    /// The claims one person would be issued for that request, keyed by the
    /// names it asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<Vec<UserInfoClaimSetsClaimsRequestPreviewReportItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unresolvable: Option<Vec<String>>,
    #[serde(rename = "essentialAndAbsent", default, skip_serializing_if = "Option::is_none")]
    pub essential_and_absent: Option<Vec<String>>,
    #[serde(rename = "valueMismatches", default, skip_serializing_if = "Option::is_none")]
    pub value_mismatches: Option<Vec<String>>,
    #[serde(rename = "entryFound", default, skip_serializing_if = "Option::is_none")]
    pub entry_found: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsClaimsRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supported: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<String>>,
    #[serde(rename = "maxClaims", default, skip_serializing_if = "Option::is_none")]
    pub max_claims: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requestable: Option<Vec<UserInfoClaimSetsClaimsRequestRequestableItem>>,
    #[serde(rename = "fromTheSignIn", default, skip_serializing_if = "Option::is_none")]
    pub from_the_sign_in: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedence: Option<Vec<String>>,
    #[serde(rename = "notEnforced", default, skip_serializing_if = "Option::is_none")]
    pub not_enforced: Option<Vec<String>>,
    #[serde(rename = "directParameter", default, skip_serializing_if = "Option::is_none")]
    pub direct_parameter: Option<UserInfoClaimSetsClaimsRequestDirectParameter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<UserInfoClaimSetsClaimsRequestPreview>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsAttributeCatalogueItem {
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

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsSetsItemClaimsItem {
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
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsSetsItemAttributeReportItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldap: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    /// A claim value as it would be issued. Its JSON type is the catalogue
    /// row's and the person's own data, and a row may nest under a dotted path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "ldpTerm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ldp_term: Option<Option<String>>,
    #[serde(rename = "claimId", default, skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsSetsItemAttributeClaimPreviewItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carried: Option<bool>,
    /// A claim value as it would be issued. Its JSON type is the catalogue
    /// row's and the person's own data, and a row may nest under a dotted path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsSetsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<UserInfoClaimSetsSetsItemClaimsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<String>>,
    /// The claims one person would be issued, keyed and nested by the claim
    /// names the catalogue and an administrator chose.
    #[serde(rename = "attributeClaims", default, skip_serializing_if = "Option::is_none")]
    pub attribute_claims: Option<serde_json::Value>,
    #[serde(rename = "attributeReport", default, skip_serializing_if = "Option::is_none")]
    pub attribute_report: Option<Vec<UserInfoClaimSetsSetsItemAttributeReportItem>>,
    #[serde(rename = "attributeClaimPreview", default, skip_serializing_if = "Option::is_none")]
    pub attribute_claim_preview: Option<Vec<UserInfoClaimSetsSetsItemAttributeClaimPreviewItem>>,
    /// Partners withholding it, by claim.
    #[serde(rename = "withheldFrom", default, skip_serializing_if = "Option::is_none")]
    pub withheld_from: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsAttributeChoicesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsPreview {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// By directory attribute.
    #[serde(rename = "byLdap", default, skip_serializing_if = "Option::is_none")]
    pub by_ldap: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "entryFound", default, skip_serializing_if = "Option::is_none")]
    pub entry_found: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsGroupsPreviewGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cn: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub rule: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<Vec<String>>,
    #[serde(rename = "viaMemberOf", default, skip_serializing_if = "Option::is_none")]
    pub via_member_of: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsGroupsPreview {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub key: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loaded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub claim: Option<Option<String>>,
    #[serde(rename = "valueForm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value_form: Option<Option<String>>,
    #[serde(rename = "memberOfCounts", default, skip_serializing_if = "Option::is_none")]
    pub member_of_counts: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub dn: Option<Option<String>>,
    #[serde(rename = "entryFound", default, skip_serializing_if = "Option::is_none")]
    pub entry_found: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<UserInfoClaimSetsGroupsPreviewGroupsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsGroups {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loaded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub claim: Option<Option<String>>,
    #[serde(rename = "valueForm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value_form: Option<Option<String>>,
    #[serde(rename = "memberOfCounts", default, skip_serializing_if = "Option::is_none")]
    pub member_of_counts: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sets: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<UserInfoClaimSetsGroupsPreview>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSetsWithholdingItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserInfoClaimSets {
    #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
    pub protocol_endpoints: Option<Vec<UserInfoClaimSetsProtocolEndpointsItem>>,
    #[serde(rename = "reservedJwtClaims", default, skip_serializing_if = "Option::is_none")]
    pub reserved_jwt_claims: Option<Vec<String>>,
    #[serde(rename = "claimsRequest", default, skip_serializing_if = "Option::is_none")]
    pub claims_request: Option<UserInfoClaimSetsClaimsRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    #[serde(rename = "inventedEmail", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub invented_email: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholders: Option<Vec<String>>,
    #[serde(rename = "attributeCatalogue", default, skip_serializing_if = "Option::is_none")]
    pub attribute_catalogue: Option<Vec<UserInfoClaimSetsAttributeCatalogueItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sets: Option<Vec<UserInfoClaimSetsSetsItem>>,
    #[serde(rename = "attributeChoices", default, skip_serializing_if = "Option::is_none")]
    pub attribute_choices: Option<Vec<UserInfoClaimSetsAttributeChoicesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<UserInfoClaimSetsPreview>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<UserInfoClaimSetsGroups>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withholding: Option<Vec<UserInfoClaimSetsWithholdingItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListFactors {
    #[serde(rename = "withSecond", default, skip_serializing_if = "Option::is_none")]
    pub with_second: Option<f64>,
    #[serde(rename = "withTotp", default, skip_serializing_if = "Option::is_none")]
    pub with_totp: Option<f64>,
    #[serde(rename = "withKeys", default, skip_serializing_if = "Option::is_none")]
    pub with_keys: Option<f64>,
    #[serde(rename = "primaryKeys", default, skip_serializing_if = "Option::is_none")]
    pub primary_keys: Option<f64>,
    #[serde(rename = "passwordOnly", default, skip_serializing_if = "Option::is_none")]
    pub password_only: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<f64>,
    #[serde(rename = "noCredential", default, skip_serializing_if = "Option::is_none")]
    pub no_credential: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListDirectoryCounts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub people: Option<f64>,
    #[serde(rename = "withSecond", default, skip_serializing_if = "Option::is_none")]
    pub with_second: Option<f64>,
    #[serde(rename = "withTotp", default, skip_serializing_if = "Option::is_none")]
    pub with_totp: Option<f64>,
    #[serde(rename = "withKeys", default, skip_serializing_if = "Option::is_none")]
    pub with_keys: Option<f64>,
    #[serde(rename = "primaryKeys", default, skip_serializing_if = "Option::is_none")]
    pub primary_keys: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<f64>,
    #[serde(rename = "withPassword", default, skip_serializing_if = "Option::is_none")]
    pub with_password: Option<f64>,
    #[serde(rename = "passwordOnly", default, skip_serializing_if = "Option::is_none")]
    pub password_only: Option<f64>,
    #[serde(rename = "noWayIn", default, skip_serializing_if = "Option::is_none")]
    pub no_way_in: Option<f64>,
    #[serde(rename = "signedInHere", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub signed_in_here: Option<Option<f64>>,
    #[serde(rename = "neverSignedInHere", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub never_signed_in_here: Option<Option<f64>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListFilter {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub q: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub protocol: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub factor: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub kind: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListPaging {
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
pub struct UserListUsersItemFormsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub form: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListUsersItemRealmsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListUsersItemProtocolsItemMethodsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListUsersItemProtocolsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
    #[serde(rename = "firstAt", default, skip_serializing_if = "Option::is_none")]
    pub first_at: Option<f64>,
    #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none")]
    pub last_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<UserListUsersItemProtocolsItemMethodsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum UserListUsersItemEventsItemAmr {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListUsersItemEventsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presented: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amr: Option<UserListUsersItemEventsItemAmr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListUsersItemTokens {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub other: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListUsersItemArtifactKindsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListUsersItemFactorsTotpDetail {
    #[serde(rename = "enrolledAt", default, skip_serializing_if = "Option::is_none")]
    pub enrolled_at: Option<f64>,
    #[serde(rename = "lastUsedAt", default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digits: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unusable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListUsersItemFactorsBackupCodes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used: Option<f64>,
    #[serde(rename = "generatedAt", default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<f64>,
    #[serde(rename = "lastUsedAt", default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hashed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListUsersItemFactors {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(rename = "inDirectory", default, skip_serializing_if = "Option::is_none")]
    pub in_directory: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<bool>,
    #[serde(rename = "primaryKeys", default, skip_serializing_if = "Option::is_none")]
    pub primary_keys: Option<f64>,
    #[serde(rename = "mfaKeys", default, skip_serializing_if = "Option::is_none")]
    pub mfa_keys: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<bool>,
    #[serde(rename = "totpUsable", default, skip_serializing_if = "Option::is_none")]
    pub totp_usable: Option<bool>,
    #[serde(rename = "totpDetail", default, skip_serializing_if = "Option::is_none")]
    pub totp_detail: Option<UserListUsersItemFactorsTotpDetail>,
    #[serde(rename = "backupCodes", default, skip_serializing_if = "Option::is_none")]
    pub backup_codes: Option<UserListUsersItemFactorsBackupCodes>,
    #[serde(rename = "recoveryAdvised", default, skip_serializing_if = "Option::is_none")]
    pub recovery_advised: Option<bool>,
    #[serde(rename = "mfaRequired", default, skip_serializing_if = "Option::is_none")]
    pub mfa_required: Option<bool>,
    #[serde(rename = "secondFactor", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub second_factor: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usable: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserListUsersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forms: Option<Vec<UserListUsersItemFormsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realms: Option<Vec<UserListUsersItemRealmsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<UserListUsersItemProtocolsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentications: Option<f64>,
    #[serde(rename = "firstAt", default, skip_serializing_if = "Option::is_none")]
    pub first_at: Option<f64>,
    #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none")]
    pub last_at: Option<f64>,
    #[serde(rename = "isClient", default, skip_serializing_if = "Option::is_none")]
    pub is_client: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated: Option<bool>,
    #[serde(rename = "knownBy", default, skip_serializing_if = "Option::is_none")]
    pub known_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<UserListUsersItemEventsItem>>,
    #[serde(rename = "eventsForgotten", default, skip_serializing_if = "Option::is_none")]
    pub events_forgotten: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<UserListUsersItemTokens>,
    #[serde(rename = "artifactKinds", default, skip_serializing_if = "Option::is_none")]
    pub artifact_kinds: Option<Vec<UserListUsersItemArtifactKindsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<f64>,
    #[serde(rename = "lastActivityAt", default, skip_serializing_if = "Option::is_none")]
    pub last_activity_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub factors: Option<UserListUsersItemFactors>,
    #[serde(rename = "inDirectory", default, skip_serializing_if = "Option::is_none")]
    pub in_directory: Option<bool>,
    #[serde(rename = "serviceAccount", default, skip_serializing_if = "Option::is_none")]
    pub service_account: Option<bool>,
    #[serde(rename = "liveSessions", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub live_sessions: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
}

/// Everyone this service has authenticated, united with at most `scanLimit` of
/// the people the directory defines.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserList {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<f64>,
    #[serde(rename = "authenticatedHere", default, skip_serializing_if = "Option::is_none")]
    pub authenticated_here: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub factors: Option<UserListFactors>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scanned: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capped: Option<bool>,
    #[serde(rename = "scanLimit", default, skip_serializing_if = "Option::is_none")]
    pub scan_limit: Option<f64>,
    #[serde(rename = "directoryPeople", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub directory_people: Option<Option<f64>>,
    #[serde(rename = "directoryCounts", default, skip_serializing_if = "Option::is_none")]
    pub directory_counts: Option<UserListDirectoryCounts>,
    #[serde(rename = "directoryCountedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub directory_counted_at: Option<Option<String>>,
    #[serde(rename = "directoryCountsKeptFor", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub directory_counts_kept_for: Option<Option<f64>>,
    #[serde(rename = "registryCap", default, skip_serializing_if = "Option::is_none")]
    pub registry_cap: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<UserListFilter>,
    #[serde(rename = "serviceAccounts", default, skip_serializing_if = "Option::is_none")]
    pub service_accounts: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<String>>,
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
    pub paging: Option<UserListPaging>,
    #[serde(rename = "withActiveSession", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub with_active_session: Option<Option<f64>>,
    #[serde(rename = "personFieldCount", default, skip_serializing_if = "Option::is_none")]
    pub person_field_count: Option<f64>,
    #[serde(rename = "newUserContainer", default, skip_serializing_if = "Option::is_none")]
    pub new_user_container: Option<String>,
    #[serde(rename = "registryKeeps", default, skip_serializing_if = "Option::is_none")]
    pub registry_keeps: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<Vec<UserListUsersItem>>,
}

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

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithApplicationsGrantsLines3 {
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

pub type WithAtFamilyKind2 = Vec<crate::WithKeyMembersCounts2>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithAtFamilyKind3 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    #[serde(rename = "flowLabel", default, skip_serializing_if = "Option::is_none")]
    pub flow_label: Option<String>,
    #[serde(rename = "flowProtocol", default, skip_serializing_if = "Option::is_none")]
    pub flow_protocol: Option<String>,
    #[serde(rename = "flowSpec", default, skip_serializing_if = "Option::is_none")]
    pub flow_spec: Option<String>,
    #[serde(rename = "flowOidc", default, skip_serializing_if = "Option::is_none")]
    pub flow_oidc: Option<String>,
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
    #[serde(rename = "expiresAtMs", default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithClientClientNamePermissionId3 {
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
    #[serde(rename = "baseUri", default, skip_serializing_if = "Option::is_none")]
    pub base_uri: Option<String>,
    #[serde(rename = "permissionName", default, skip_serializing_if = "Option::is_none")]
    pub permission_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dangling: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<bool>,
}

pub type WithClustersDescriptionMemberOf = Vec<crate::WithKeyMembersGrants>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithClustersDescriptionMemberOf2Counts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clusters: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applications: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub largest: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alone: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joined: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithClustersDescriptionMemberOf2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clusters: Option<crate::WithClustersDescriptionMemberOf>,
    /// Each application, to its group's key.
    #[serde(rename = "memberOf", default, skip_serializing_if = "Option::is_none")]
    pub member_of: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<WithClustersDescriptionMemberOf2Counts>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithDescriptionUsersDescription {
    /// Each name in the answer that is a known person.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<serde_json::Map<String, serde_json::Value>>,
    /// Each name in the answer the registry holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apps: Option<serde_json::Map<String, serde_json::Value>>,
}

pub type WithFieldsProfilesPqModes3 = Vec<crate::WithIdCaProfile2>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithFieldsProfilesPqModes4SignatureAlgorithmsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weak: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithFieldsProfilesPqModes4KeyUsageBitsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithFieldsProfilesPqModes4ExtendedKeyUsagesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithFieldsProfilesPqModes4NetscapeTypesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithFieldsProfilesPqModes4DnFieldsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithFieldsProfilesPqModes4 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profiles: Option<crate::WithIdLabelClassical3>,
    #[serde(rename = "pqModes", default, skip_serializing_if = "Option::is_none")]
    pub pq_modes: Option<crate::WithIdLabelClassical4>,
    #[serde(rename = "pqMode", default, skip_serializing_if = "Option::is_none")]
    pub pq_mode: Option<String>,
    #[serde(rename = "keyAlgorithms", default, skip_serializing_if = "Option::is_none")]
    pub key_algorithms: Option<crate::WithIdLabelFamily>,
    #[serde(rename = "alternativeKeyAlgorithms", default, skip_serializing_if = "Option::is_none")]
    pub alternative_key_algorithms: Option<crate::WithIdLabelFamily>,
    #[serde(rename = "signatureAlgorithms", default, skip_serializing_if = "Option::is_none")]
    pub signature_algorithms: Option<Vec<WithFieldsProfilesPqModes4SignatureAlgorithmsItem>>,
    #[serde(rename = "signerLabel", default, skip_serializing_if = "Option::is_none")]
    pub signer_label: Option<String>,
    #[serde(rename = "keystoreFormats", default, skip_serializing_if = "Option::is_none")]
    pub keystore_formats: Option<Vec<String>>,
    #[serde(rename = "keyUsageBits", default, skip_serializing_if = "Option::is_none")]
    pub key_usage_bits: Option<Vec<WithFieldsProfilesPqModes4KeyUsageBitsItem>>,
    #[serde(rename = "extendedKeyUsages", default, skip_serializing_if = "Option::is_none")]
    pub extended_key_usages: Option<Vec<WithFieldsProfilesPqModes4ExtendedKeyUsagesItem>>,
    #[serde(rename = "netscapeTypes", default, skip_serializing_if = "Option::is_none")]
    pub netscape_types: Option<Vec<WithFieldsProfilesPqModes4NetscapeTypesItem>>,
    #[serde(rename = "accessMethods", default, skip_serializing_if = "Option::is_none")]
    pub access_methods: Option<Vec<String>>,
    #[serde(rename = "dnFields", default, skip_serializing_if = "Option::is_none")]
    pub dn_fields: Option<Vec<WithFieldsProfilesPqModes4DnFieldsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuers: Option<crate::WithIdLabelSubject2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objects: Option<crate::WithFieldsProfilesPqModes3>,
    #[serde(rename = "maxObjects", default, skip_serializing_if = "Option::is_none")]
    pub max_objects: Option<i64>,
    #[serde(rename = "slowFamilies", default, skip_serializing_if = "Option::is_none")]
    pub slow_families: Option<Vec<String>>,
    /// The certificate form, by field name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdCaProfile2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub profile: Option<Option<String>>,
    #[serde(rename = "profileLabel", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub profile_label: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(rename = "issuerSubject", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub issuer_subject: Option<Option<String>>,
    #[serde(rename = "issuerId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub issuer_id: Option<Option<String>>,
    #[serde(rename = "selfSigned", default, skip_serializing_if = "Option::is_none")]
    pub self_signed: Option<bool>,
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub serial_hex: Option<Option<String>>,
    #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
    pub key_alg: Option<String>,
    #[serde(rename = "keyAlgLabel", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub key_alg_label: Option<Option<String>>,
    #[serde(rename = "signatureAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub signature_alg: Option<Option<String>>,
    #[serde(rename = "signatureAlgLabel", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub signature_alg_label: Option<Option<String>>,
    #[serde(rename = "pqMode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub pq_mode: Option<Option<String>>,
    #[serde(rename = "altKeyAlg", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub alt_key_alg: Option<Option<String>>,
    #[serde(rename = "altSigned", default, skip_serializing_if = "Option::is_none")]
    pub alt_signed: Option<bool>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub not_before: Option<Option<String>>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub not_after: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub thumbprint: Option<Option<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "hasPrivateKey", default, skip_serializing_if = "Option::is_none")]
    pub has_private_key: Option<bool>,
    #[serde(rename = "hasCsr", default, skip_serializing_if = "Option::is_none")]
    pub has_csr: Option<bool>,
    #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub certificate_pem: Option<Option<String>>,
    #[serde(rename = "csrPem", default, skip_serializing_if = "Option::is_none")]
    pub csr_pem: Option<String>,
}

pub type WithIdFromTo4 = Vec<crate::WithKindCountIdentifiers3>;

pub type WithIdFromTo5 = serde_json::Map<String, serde_json::Value>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdFromTo6AuthenticationsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<f64>,
    #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none")]
    pub last_at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdFromTo6 {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<String>>,
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
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acts: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<i64>,
    #[serde(rename = "firstAt", default, skip_serializing_if = "Option::is_none")]
    pub first_at: Option<f64>,
    #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none")]
    pub last_at: Option<f64>,
    #[serde(rename = "authorizedBy", default, skip_serializing_if = "Option::is_none")]
    pub authorized_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumed: Option<crate::WithIdFromTo4>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub produced: Option<crate::WithIdFromTo4>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mechanism: Option<String>,
    #[serde(rename = "setOn", default, skip_serializing_if = "Option::is_none")]
    pub set_on: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used: Option<bool>,
    #[serde(rename = "consumedFold", default, skip_serializing_if = "Option::is_none")]
    pub consumed_fold: Option<crate::WithIdFromTo5>,
    #[serde(rename = "producedFold", default, skip_serializing_if = "Option::is_none")]
    pub produced_fold: Option<crate::WithIdFromTo5>,
    #[serde(rename = "permissionId", default, skip_serializing_if = "Option::is_none")]
    pub permission_id: Option<String>,
    #[serde(rename = "permissionName", default, skip_serializing_if = "Option::is_none")]
    pub permission_name: Option<String>,
    #[serde(rename = "baseUri", default, skip_serializing_if = "Option::is_none")]
    pub base_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentications: Option<Vec<WithIdFromTo6AuthenticationsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(rename = "audienceRegistered", default, skip_serializing_if = "Option::is_none")]
    pub audience_registered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdKindRealmRealm {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "isDefault", default, skip_serializing_if = "Option::is_none")]
    pub is_default: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdKindRealmRoles {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediary: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdKindRealm {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<WithIdKindRealmRealm>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<WithIdKindRealmRoles>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acts: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<i64>,
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
    pub protocols: Option<Vec<String>>,
    #[serde(rename = "firstAt", default, skip_serializing_if = "Option::is_none")]
    pub first_at: Option<f64>,
    #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none")]
    pub last_at: Option<f64>,
    #[serde(rename = "selfTarget", default, skip_serializing_if = "Option::is_none")]
    pub self_target: Option<bool>,
    #[serde(rename = "chiefRole", default, skip_serializing_if = "Option::is_none")]
    pub chief_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposes: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dangling: Option<i64>,
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
}

pub type WithIdLabelCa2 = Vec<crate::WithSeqOriginAt4>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdLabelCa3 {
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
    pub path_len: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub type WithIdLabelClassical3 = Vec<crate::WithIdLabelCa3>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdLabelClassical4ItemItem {
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

pub type WithIdLabelClassical4 = Vec<WithIdLabelClassical4ItemItem>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdLabelFamilyItemItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signs: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slow: Option<bool>,
    #[serde(rename = "tlsUsable", default, skip_serializing_if = "Option::is_none")]
    pub tls_usable: Option<bool>,
}

pub type WithIdLabelFamily = Vec<WithIdLabelFamilyItemItem>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdLabelSubject2ItemItem {
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

pub type WithIdLabelSubject2 = Vec<WithIdLabelSubject2ItemItem>;

pub type WithIdentifierNameBaseUri = Vec<crate::WithNameDescriptionId>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdentifierNameBaseUri2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "baseUri", default, skip_serializing_if = "Option::is_none")]
    pub base_uri: Option<String>,
    #[serde(rename = "rawBaseUri", default, skip_serializing_if = "Option::is_none")]
    pub raw_base_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<crate::WithIdentifierNameBaseUri>,
    #[serde(rename = "grantsHeld", default, skip_serializing_if = "Option::is_none")]
    pub grants_held: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum WithKeyGroupLabel5LegacyEnv {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithKeyGroupLabel5 {
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
    /// A sentence per value of the row.
    #[serde(rename = "csvValueNotes", default, skip_serializing_if = "Option::is_none")]
    pub csv_value_notes: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "selectAll", default, skip_serializing_if = "Option::is_none")]
    pub select_all: Option<crate::WithOnlyWhileOnAloneWhileOnKey2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<sts_model_base::unions::BoolOrNumberOrStringOrList>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub text: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<bool>,
    #[serde(rename = "restartReason", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub restart_reason: Option<Option<String>>,
    #[serde(rename = "editRefusal", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub edit_refusal: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub env: Option<Option<String>>,
    #[serde(rename = "legacyEnv", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub legacy_env: Option<Option<WithKeyGroupLabel5LegacyEnv>>,
    #[serde(rename = "appconfigPath", default, skip_serializing_if = "Option::is_none")]
    pub appconfig_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default: Option<Option<sts_model_base::unions::BoolOrNumberOrStringOrList>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

pub type WithKeyMembersCounts = Vec<crate::WithResourceResourceNameBaseUri2>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithKeyMembersCounts2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<crate::WithApplicationsGrantsLines3>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithKeyMembersGrants {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<crate::WithPagePagesPerPage4>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<crate::WithKeyMembersCounts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<crate::WithApplicationsGrantsLines3>,
}

pub type WithKindCountIdentifiers2 = Vec<crate::WithIdKindRealm>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithKindCountIdentifiers3 {
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

pub type WithLocaleChainCatalog = Vec<crate::WithTitleWhatItems2>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum WithLocaleChainCatalog2Direction {
    #[serde(rename = "ltr")]
    Ltr,
    #[serde(rename = "rtl")]
    Rtl,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithLocaleChainCatalog2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<WithLocaleChainCatalog2Direction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithNameDescriptionIdGrantedToItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithNameDescriptionId {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub id: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    #[serde(rename = "grantedTo", default, skip_serializing_if = "Option::is_none")]
    pub granted_to: Option<Vec<WithNameDescriptionIdGrantedToItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithNegotiatedOfferedDescriptionOfferedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithNegotiatedOfferedDescription {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub negotiated: Option<crate::WithLocaleChainCatalog2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offered: Option<Vec<WithNegotiatedOfferedDescriptionOfferedItem>>,
    /// Each catalog along the chain, by language tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalogs: Option<serde_json::Map<String, serde_json::Value>>,
    /// Each static catalog, by language tag.
    #[serde(rename = "catalogFiles", default, skip_serializing_if = "Option::is_none")]
    pub catalog_files: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkChangedClientSecret {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<bool>,
    #[serde(rename = "clientSecret", default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkErrorsLocale {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<crate::WithNegotiatedOfferedDescription>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOkErrorsWhy {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    /// The certificate form, by field name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workbench: Option<crate::WithFieldsProfilesPqModes4>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithOnlyWhileOnAloneWhileOnKey2OnlyWhileOnItem {
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
pub struct WithOnlyWhileOnAloneWhileOnKey2AloneWhileOnItem {
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
pub struct WithOnlyWhileOnAloneWhileOnKey2 {
    #[serde(rename = "onlyWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub only_while_on: Option<Vec<WithOnlyWhileOnAloneWhileOnKey2OnlyWhileOnItem>>,
    #[serde(rename = "aloneWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub alone_while_on: Option<Vec<WithOnlyWhileOnAloneWhileOnKey2AloneWhileOnItem>>,
}

pub type WithPagePagesPerPage4 = Vec<crate::WithClientClientNamePermissionId3>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithPagePagesPerPage5 {
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
pub struct WithPathLabelBlurbItemItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blurb: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidden: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

pub type WithPathLabelBlurb = Vec<WithPathLabelBlurbItemItem>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithPathLabelBlurb2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blurb: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidden: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<crate::WithPathLabelBlurb>,
}

pub type WithPathLabelBlurb3 = Vec<crate::WithPathLabelBlurb2>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithPathLabelBlurb4 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blurb: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidden: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<crate::WithPathLabelBlurb3>,
}

pub type WithRealmIssuerNodes3 = Vec<crate::WithAtFamilyKind3>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithRealmIssuerNodes4Realm {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "isDefault", default, skip_serializing_if = "Option::is_none")]
    pub is_default: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithRealmIssuerNodes4Counts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodes: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edges: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithRealmIssuerNodes4 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<WithRealmIssuerNodes4Realm>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodes: Option<crate::WithKindCountIdentifiers2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edges: Option<crate::WithSeqAtKind3>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<crate::WithTotalEntriesKey>,
    #[serde(rename = "tokensLeftOff", default, skip_serializing_if = "Option::is_none")]
    pub tokens_left_off: Option<i64>,
    #[serde(rename = "maxTokenRows", default, skip_serializing_if = "Option::is_none")]
    pub max_token_rows: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acts: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chains: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<WithRealmIssuerNodes4Counts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<crate::WithRealmIssuerNodes3>,
    #[serde(rename = "credentialsOnDelegationLines", default, skip_serializing_if = "Option::is_none")]
    pub credentials_on_delegation_lines: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithResourceResourceNameBaseUri2GrantedToItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithResourceResourceNameBaseUri2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(rename = "resourceName", default, skip_serializing_if = "Option::is_none")]
    pub resource_name: Option<String>,
    #[serde(rename = "baseUri", default, skip_serializing_if = "Option::is_none")]
    pub base_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub id: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    #[serde(rename = "grantedTo", default, skip_serializing_if = "Option::is_none")]
    pub granted_to: Option<Vec<WithResourceResourceNameBaseUri2GrantedToItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithResourcesPermissionsGrants {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<crate::WithResourcesPermissionsUnidentified>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<crate::WithKeyMembersCounts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<crate::WithPagePagesPerPage4>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<crate::WithResourcesPermissionsUnidentified2>,
}

pub type WithResourcesPermissionsUnidentified = Vec<crate::WithIdentifierNameBaseUri2>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithResourcesPermissionsUnidentified2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unidentified: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dangling: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unused: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ungranted: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clients: Option<i64>,
}

pub type WithSeqAtKind3 = Vec<crate::WithIdFromTo6>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSeqAtKind4 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<f64>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSeqOriginAt4Initial {
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
pub struct WithSeqOriginAt4Intermediary {
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
pub struct WithSeqOriginAt4Target {
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
pub struct WithSeqOriginAt4ConsumedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSeqOriginAt4ProducedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithSeqOriginAt4 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub origin: Option<Option<String>>,
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
    pub initial: Option<WithSeqOriginAt4Initial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediary: Option<WithSeqOriginAt4Intermediary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<WithSeqOriginAt4Target>,
    #[serde(rename = "authorizedBy", default, skip_serializing_if = "Option::is_none")]
    pub authorized_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumed: Option<Vec<WithSeqOriginAt4ConsumedItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub produced: Option<Vec<WithSeqOriginAt4ProducedItem>>,
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(rename = "chainKey", default, skip_serializing_if = "Option::is_none")]
    pub chain_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithShapeLabelSublabel2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shape: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub sublabel: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub identifier: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub href: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dashed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithShownPagingOnlyWhileOn {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<crate::WithKeyMembersCounts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<crate::WithPagePagesPerPage5>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithShownPagingShown {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<crate::WithPagePagesPerPage4>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<crate::WithPagePagesPerPage5>,
}

pub type WithTitleWhatItems = Vec<crate::WithPathLabelBlurb4>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithTitleWhatItems2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<crate::WithTitleWhatItems>,
}

pub type WithTotalEntriesKey = Vec<crate::WithSeqAtKind4>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithTotalEntriesKey2EntriesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithTotalEntriesKey2Slice {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum WithTotalEntriesKey2Search {
    #[serde(rename = "contains")]
    Contains,
    #[serde(rename = "exact")]
    Exact,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithTotalEntriesKey2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<WithTotalEntriesKey2EntriesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slice: Option<WithTotalEntriesKey2Slice>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search: Option<WithTotalEntriesKey2Search>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub complete: Option<bool>,
}

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
