// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// GENERATED from models/api/ (#1390, #444) by models/lib/rust_lib.mjs.
// Do not edit: change the model and run
// tests/tools/regenerate-model-docs.sh. tests/model_domain.js fails when
// this differs.

/// What the console's own action functions return, unchanged. `ok` is true when
/// the operation was applied and false when it was refused; a refusal carries
/// `errors` and is answered with HTTP 400. Successful replies carry `message` —
/// the sentence the console would have shown — plus whatever the action
/// produced: `claims` for a claim set, `selected` for the credential claim set,
/// `requested` for the verifier request, `revoked` for a count.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ActionResult {
    /// Whether the operation was applied.
    pub ok: bool,
    /// What happened, in the words the console would have used. Present on
    /// success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Why it was refused. Present when `ok` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    /// The members the schema does not name, which it allows.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Which of the two kinds the operation is (#454).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ApiIndexOperationsItemKind {
    #[serde(rename = "management")]
    Management,
    #[serde(rename = "console")]
    Console,
}

/// One operation.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiIndexOperationsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(rename = "operationId", default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// The /admin control this operation is the API form of.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mirrors: Option<String>,
    /// Which of the two kinds the operation is (#454).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<ApiIndexOperationsItemKind>,
    /// The console pages drawn from this operation's data by one of the
    /// console's own operations (#454); present only where there are any.
    #[serde(rename = "drawnOn", default, skip_serializing_if = "Option::is_none")]
    pub drawn_on: Option<Vec<String>>,
}

/// What this API is, where its document is, and every operation it offers.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiIndex {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// M.N.O.<build>: the release the repo-root VERSION file declares, followed
    /// by the build number. A stamp written before build numbers returned
    /// (#1317) reports the bare M.N.O.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The build number on its own: the UTC build instant as YYYYMMDDHHMMSS, or
    /// the BUILD_NUMBER a release build named. Absent on a stamp that carries
    /// none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<String>,
    /// True when this build was flagged as a release (STS_RELEASE=true) and
    /// named its build number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<bool>,
    /// The first twelve characters of the commit this was built from. Absent
    /// when the build could not know it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// When this build was made. Read it with `stamped`.
    #[serde(rename = "builtAt", default, skip_serializing_if = "Option::is_none")]
    pub built_at: Option<String>,
    /// True when this version came off a record written at image build time.
    /// False means the process computed its own record at startup, so `builtAt`
    /// and the build number are the moment it started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stamped: Option<bool>,
    /// Where the document is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openapi: Option<String>,
    /// Where the explorer is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docs: Option<String>,
    /// Where the console every operation mirrors is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub console: Option<String>,
    /// Whether this API requires an access token (`adminApi.authRequired`, on
    /// by default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected: Option<bool>,
    /// Every management operation, with the console page it mirrors. The
    /// console's own operations are listed by GET /admin-api/console/operations
    /// (#454).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operations: Option<Vec<ApiIndexOperationsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListFilter {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub q: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub kind: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub exclude: Option<Option<Vec<serde_json::Value>>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListKindsItemV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ApplicationListKindsItem {
    V1(ApplicationListKindsItemV1),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListSettingsGroupsItemSettingsItemSelectAllOnlyWhileOnItem {
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
pub struct ApplicationListSettingsGroupsItemSettingsItemSelectAllAloneWhileOnItem {
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
pub struct ApplicationListSettingsGroupsItemSettingsItemSelectAll {
    #[serde(rename = "onlyWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub only_while_on: Option<Vec<ApplicationListSettingsGroupsItemSettingsItemSelectAllOnlyWhileOnItem>>,
    #[serde(rename = "aloneWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub alone_while_on: Option<Vec<ApplicationListSettingsGroupsItemSettingsItemSelectAllAloneWhileOnItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ApplicationListSettingsGroupsItemSettingsItemValue {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ApplicationListSettingsGroupsItemSettingsItemDefault {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListSettingsGroupsItemSettingsItem {
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
    pub select_all: Option<ApplicationListSettingsGroupsItemSettingsItemSelectAll>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<ApplicationListSettingsGroupsItemSettingsItemValue>>,
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
    pub default: Option<Option<ApplicationListSettingsGroupsItemSettingsItemDefault>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListSettingsGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<ApplicationListSettingsGroupsItemSettingsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListSettingsContext {
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
pub struct ApplicationListSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<ApplicationListSettingsGroupsItem>>,
    #[serde(rename = "settingCount", default, skip_serializing_if = "Option::is_none")]
    pub setting_count: Option<i64>,
    #[serde(rename = "editableCount", default, skip_serializing_if = "Option::is_none")]
    pub editable_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<Vec<String>>,
    #[serde(rename = "setWith", default, skip_serializing_if = "Option::is_none")]
    pub set_with: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<ApplicationListSettingsContext>,
    /// The other pages each settings group is drawn on.
    #[serde(rename = "sharedWith", default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPaging {
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
pub struct ApplicationListProtocolsItemV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<String>>,
    #[serde(rename = "identifierAttribute", default, skip_serializing_if = "Option::is_none")]
    pub identifier_attribute: Option<String>,
    #[serde(rename = "redirectAttribute", default, skip_serializing_if = "Option::is_none")]
    pub redirect_attribute: Option<String>,
    #[serde(rename = "logoutAttribute", default, skip_serializing_if = "Option::is_none")]
    pub logout_attribute: Option<String>,
    #[serde(rename = "deliveryAttribute", default, skip_serializing_if = "Option::is_none")]
    pub delivery_attribute: Option<String>,
    #[serde(rename = "eventsAttribute", default, skip_serializing_if = "Option::is_none")]
    pub events_attribute: Option<String>,
    #[serde(rename = "secretAttribute", default, skip_serializing_if = "Option::is_none")]
    pub secret_attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ApplicationListProtocolsItem {
    V1(ApplicationListProtocolsItemV1),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListApplicationsItemReturnAddressesObservedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListApplicationsItemSecretExpiry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListApplicationsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(rename = "dnLabel", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub dn_label: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub dn: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<String>>,
    #[serde(rename = "allowedProtocols", default, skip_serializing_if = "Option::is_none")]
    pub allowed_protocols: Option<Vec<String>>,
    #[serde(rename = "recordedProtocols", default, skip_serializing_if = "Option::is_none")]
    pub recorded_protocols: Option<Vec<String>>,
    #[serde(rename = "declaredKinds", default, skip_serializing_if = "Option::is_none")]
    pub declared_kinds: Option<Vec<String>>,
    #[serde(rename = "registeredBy", default, skip_serializing_if = "Option::is_none")]
    pub registered_by: Option<String>,
    #[serde(rename = "returnAddressesObserved", default, skip_serializing_if = "Option::is_none")]
    pub return_addresses_observed: Option<Vec<ApplicationListApplicationsItemReturnAddressesObservedItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
    #[serde(rename = "firstSeen", default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
    #[serde(rename = "lastSeen", default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentications: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub description: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub origin: Option<Option<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<String>>,
    #[serde(rename = "modifiedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub modified_at: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operational: Option<Vec<String>>,
    /// By attribute name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Map<String, serde_json::Value>>,
    /// By attribute name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "secretExpiry", default, skip_serializing_if = "Option::is_none")]
    pub secret_expiry: Option<ApplicationListApplicationsItemSecretExpiry>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ConfigFieldsItemDescribedSelectAllOnlyWhileOnItem {
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
pub struct ApplicationListPageV1ConfigFieldsItemDescribedSelectAllAloneWhileOnItem {
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
pub struct ApplicationListPageV1ConfigFieldsItemDescribedSelectAll {
    #[serde(rename = "onlyWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub only_while_on: Option<Vec<ApplicationListPageV1ConfigFieldsItemDescribedSelectAllOnlyWhileOnItem>>,
    #[serde(rename = "aloneWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub alone_while_on: Option<Vec<ApplicationListPageV1ConfigFieldsItemDescribedSelectAllAloneWhileOnItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ApplicationListPageV1ConfigFieldsItemDescribedValue {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ApplicationListPageV1ConfigFieldsItemDescribedDefault {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ConfigFieldsItemDescribed {
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
    pub select_all: Option<ApplicationListPageV1ConfigFieldsItemDescribedSelectAll>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<ApplicationListPageV1ConfigFieldsItemDescribedValue>>,
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
    pub default: Option<Option<ApplicationListPageV1ConfigFieldsItemDescribedDefault>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ConfigFieldsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub long: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<sts_model_base::unions::BoolOrString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitive: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overrides: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub choices: Option<Option<Vec<serde_json::Value>>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub example: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub families: Option<Vec<String>>,
    #[serde(rename = "everyFamily", default, skip_serializing_if = "Option::is_none")]
    pub every_family: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declaration: Option<bool>,
    #[serde(rename = "primaryName", default, skip_serializing_if = "Option::is_none")]
    pub primary_name: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simple: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    #[serde(rename = "sectionLabel", default, skip_serializing_if = "Option::is_none")]
    pub section_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub described: Option<ApplicationListPageV1ConfigFieldsItemDescribed>,
    #[serde(rename = "inSimple", default, skip_serializing_if = "Option::is_none")]
    pub in_simple: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ConfigGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub families: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ConfigFamilyChoicesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub families: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ConfigProtocolsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<String>>,
    #[serde(rename = "identifierAttribute", default, skip_serializing_if = "Option::is_none")]
    pub identifier_attribute: Option<String>,
    #[serde(rename = "redirectAttribute", default, skip_serializing_if = "Option::is_none")]
    pub redirect_attribute: Option<String>,
    #[serde(rename = "logoutAttribute", default, skip_serializing_if = "Option::is_none")]
    pub logout_attribute: Option<String>,
    #[serde(rename = "deliveryAttribute", default, skip_serializing_if = "Option::is_none")]
    pub delivery_attribute: Option<String>,
    #[serde(rename = "eventsAttribute", default, skip_serializing_if = "Option::is_none")]
    pub events_attribute: Option<String>,
    #[serde(rename = "secretAttribute", default, skip_serializing_if = "Option::is_none")]
    pub secret_attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ConfigObservedOauthGrantTypeObservedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ConfigObservedOauthResponseTypeObservedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ConfigObservedAppRedirectUriObservedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ConfigObservedOauthScopeItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ConfigObservedAppAuthorizationServerItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ConfigObservedSamlNameIdFormatItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ConfigObservedSamlResponseBindingItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ConfigObservedSamlLastRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed: Option<bool>,
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
pub struct ApplicationListPageV1ConfigObservedSamlObservedSigningCertificate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ConfigObservedOauthAllowedTokenResponseTypes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforced: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waived: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ConfigObserved {
    #[serde(rename = "oauthGrantTypeObserved", default, skip_serializing_if = "Option::is_none")]
    pub oauth_grant_type_observed: Option<Vec<ApplicationListPageV1ConfigObservedOauthGrantTypeObservedItem>>,
    #[serde(rename = "oauthResponseTypeObserved", default, skip_serializing_if = "Option::is_none")]
    pub oauth_response_type_observed: Option<Vec<ApplicationListPageV1ConfigObservedOauthResponseTypeObservedItem>>,
    #[serde(rename = "appRedirectUriObserved", default, skip_serializing_if = "Option::is_none")]
    pub app_redirect_uri_observed: Option<Vec<ApplicationListPageV1ConfigObservedAppRedirectUriObservedItem>>,
    #[serde(rename = "oauthScope", default, skip_serializing_if = "Option::is_none")]
    pub oauth_scope: Option<Vec<ApplicationListPageV1ConfigObservedOauthScopeItem>>,
    #[serde(rename = "appAuthorizationServer", default, skip_serializing_if = "Option::is_none")]
    pub app_authorization_server: Option<Vec<ApplicationListPageV1ConfigObservedAppAuthorizationServerItem>>,
    #[serde(rename = "samlNameIdFormat", default, skip_serializing_if = "Option::is_none")]
    pub saml_name_id_format: Option<Vec<ApplicationListPageV1ConfigObservedSamlNameIdFormatItem>>,
    #[serde(rename = "samlResponseBinding", default, skip_serializing_if = "Option::is_none")]
    pub saml_response_binding: Option<Vec<ApplicationListPageV1ConfigObservedSamlResponseBindingItem>>,
    #[serde(rename = "samlLastRequest", default, skip_serializing_if = "Option::is_none")]
    pub saml_last_request: Option<ApplicationListPageV1ConfigObservedSamlLastRequest>,
    #[serde(rename = "samlObservedSigningCertificate", default, skip_serializing_if = "Option::is_none")]
    pub saml_observed_signing_certificate: Option<ApplicationListPageV1ConfigObservedSamlObservedSigningCertificate>,
    #[serde(rename = "oauthAllowedTokenResponseTypes", default, skip_serializing_if = "Option::is_none")]
    pub oauth_allowed_token_response_types: Option<ApplicationListPageV1ConfigObservedOauthAllowedTokenResponseTypes>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ConfigDerivedOauthAllowedScopeItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api: Option<String>,
    #[serde(rename = "apiName", default, skip_serializing_if = "Option::is_none")]
    pub api_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ConfigDerived {
    #[serde(rename = "oauthAllowedScope", default, skip_serializing_if = "Option::is_none")]
    pub oauth_allowed_scope: Option<Vec<ApplicationListPageV1ConfigDerivedOauthAllowedScopeItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<ApplicationListPageV1ConfigFieldsItem>>,
    /// Each field's values, by attribute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<ApplicationListPageV1ConfigGroupsItem>>,
    #[serde(rename = "familyChoices", default, skip_serializing_if = "Option::is_none")]
    pub family_choices: Option<Vec<ApplicationListPageV1ConfigFamilyChoicesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<ApplicationListPageV1ConfigProtocolsItem>>,
    #[serde(rename = "longTextAttributes", default, skip_serializing_if = "Option::is_none")]
    pub long_text_attributes: Option<Vec<String>>,
    /// What each attribute's search looks through.
    #[serde(rename = "fieldSearches", default, skip_serializing_if = "Option::is_none")]
    pub field_searches: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed: Option<ApplicationListPageV1ConfigObserved>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derived: Option<ApplicationListPageV1ConfigDerived>,
    /// By attribute.
    #[serde(rename = "fieldWarnings", default, skip_serializing_if = "Option::is_none")]
    pub field_warnings: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1PasskeyPolicies {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub named: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applies: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedence: Option<f64>,
    #[serde(rename = "groupPolicies", default, skip_serializing_if = "Option::is_none")]
    pub group_policies: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1CorsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ApplicationListPageV1AccessTypesItemBearer {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1AccessTypesItemXacmlItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
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
pub struct ApplicationListPageV1AccessTypesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locations: Option<Vec<String>>,
    /// The JSON an operator wrote into an access type's definition: a JSON
    /// Schema (RFC 9396 leaves a type's fields to its definition), or the
    /// definition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validate: Option<()>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub actions: Option<Option<Vec<serde_json::Value>>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub datatypes: Option<Option<Vec<serde_json::Value>>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub privileges: Option<Option<Vec<serde_json::Value>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interaction: Option<String>,
    #[serde(rename = "consentActions", default, skip_serializing_if = "Option::is_none")]
    pub consent_actions: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub bearer: Option<Option<ApplicationListPageV1AccessTypesItemBearer>>,
    #[serde(rename = "maxLifetimeS", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub max_lifetime_s: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(rename = "derivableFrom", default, skip_serializing_if = "Option::is_none")]
    pub derivable_from: Option<Vec<String>>,
    #[serde(rename = "introspectionClaims", default, skip_serializing_if = "Option::is_none")]
    pub introspection_claims: Option<Vec<String>>,
    /// The JSON an operator wrote into an access type's definition: a JSON
    /// Schema (RFC 9396 leaves a type's fields to its definition), or the
    /// definition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<serde_json::Value>,
    #[serde(rename = "validateLimits", default, skip_serializing_if = "Option::is_none")]
    pub validate_limits: Option<()>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xacml: Option<Vec<ApplicationListPageV1AccessTypesItemXacmlItem>>,
    #[serde(rename = "notForPolicy", default, skip_serializing_if = "Option::is_none")]
    pub not_for_policy: Option<Vec<String>>,
    /// The JSON an operator wrote into an access type's definition: a JSON
    /// Schema (RFC 9396 leaves a type's fields to its definition), or the
    /// definition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1FgaPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "policyId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub policy_id: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub version: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub application: Option<Option<String>>,
    #[serde(rename = "orphanedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub orphaned_at: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub own: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1FgaTypesItem {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uncovered: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<i64>,
    #[serde(rename = "notForPolicy", default, skip_serializing_if = "Option::is_none")]
    pub not_for_policy: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1FgaUnreadableItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1FgaPepsHoldersItem {
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
pub struct ApplicationListPageV1FgaPeps {
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
    pub holders: Option<Vec<ApplicationListPageV1FgaPepsHoldersItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1FgaApplicationPolicies {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1FgaChoices {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub categories: Option<Vec<String>>,
    #[serde(rename = "dataTypes", default, skip_serializing_if = "Option::is_none")]
    pub data_types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multiplicities: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1Fga {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforced: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub reference: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<ApplicationListPageV1FgaPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub types: Option<Vec<ApplicationListPageV1FgaTypesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<Vec<ApplicationListPageV1FgaUnreadableItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peps: Option<ApplicationListPageV1FgaPeps>,
    #[serde(rename = "applicationPolicies", default, skip_serializing_if = "Option::is_none")]
    pub application_policies: Option<ApplicationListPageV1FgaApplicationPolicies>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub choices: Option<ApplicationListPageV1FgaChoices>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1PermissionClaimsPermissionsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub description: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub id: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1PermissionClaimsCatalogueItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldap: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1PermissionClaims {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<ApplicationListPageV1PermissionClaimsPermissionsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalogue: Option<Vec<ApplicationListPageV1PermissionClaimsCatalogueItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ProtocolRowsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EditableSetItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitive: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EditableMultiItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitive: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EditableMultiAllItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitive: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1Editable {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set: Option<Vec<ApplicationListPageV1EditableSetItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multi: Option<Vec<ApplicationListPageV1EditableMultiItem>>,
    #[serde(rename = "multiAll", default, skip_serializing_if = "Option::is_none")]
    pub multi_all: Option<Vec<ApplicationListPageV1EditableMultiAllItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1DidMethodsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kty: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kept: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1Did {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub did: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<ApplicationListPageV1DidMethodsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origins: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1CredentialsClientSecretSecretsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<f64>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub description: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1CredentialsClientSecret {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<bool>,
    #[serde(rename = "authMethod", default, skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
    #[serde(rename = "registrationAccessTokenHeld", default, skip_serializing_if = "Option::is_none")]
    pub registration_access_token_held: Option<bool>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<ApplicationListPageV1CredentialsClientSecretSecretsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(rename = "defaultLifetimeDays", default, skip_serializing_if = "Option::is_none")]
    pub default_lifetime_days: Option<f64>,
    #[serde(rename = "overlapS", default, skip_serializing_if = "Option::is_none")]
    pub overlap_s: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1CredentialsPurposesItemCertificate {
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
    #[serde(rename = "keyType", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub key_type: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1CredentialsPurposesItemChainItem {
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
    #[serde(rename = "keyType", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub key_type: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1CredentialsPurposesItemAttributes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<String>,
    #[serde(rename = "privateKey", default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(rename = "handleLabel", default, skip_serializing_if = "Option::is_none")]
    pub handle_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1CredentialsPurposesItemRegisteredKeysItemCertificate {
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
    #[serde(rename = "keyType", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub key_type: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1CredentialsPurposesItemRegisteredKeysItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kty: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<ApplicationListPageV1CredentialsPurposesItemRegisteredKeysItemCertificate>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1CredentialsPurposesItemRegisteredCertificatesItem {
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
    #[serde(rename = "keyType", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub key_type: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1CredentialsPurposesItemRegistered {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<ApplicationListPageV1CredentialsPurposesItemRegisteredKeysItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<ApplicationListPageV1CredentialsPurposesItemRegisteredCertificatesItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1CredentialsPurposesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "privateKeyHeld", default, skip_serializing_if = "Option::is_none")]
    pub private_key_held: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<ApplicationListPageV1CredentialsPurposesItemCertificate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<Vec<ApplicationListPageV1CredentialsPurposesItemChainItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(rename = "handleLabel", default, skip_serializing_if = "Option::is_none")]
    pub handle_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuers: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<ApplicationListPageV1CredentialsPurposesItemAttributes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<ApplicationListPageV1CredentialsPurposesItemRegistered>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "sealedAtRest", default, skip_serializing_if = "Option::is_none")]
    pub sealed_at_rest: Option<bool>,
    #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
    pub certificate_pem: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1CredentialsCaKeyAlgorithmsItem {
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
pub struct ApplicationListPageV1CredentialsCa {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub available: Option<bool>,
    #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
    pub key_alg: Option<String>,
    #[serde(rename = "keyAlgorithms", default, skip_serializing_if = "Option::is_none")]
    pub key_algorithms: Option<Vec<ApplicationListPageV1CredentialsCaKeyAlgorithmsItem>>,
    #[serde(rename = "leafLifetimeDays", default, skip_serializing_if = "Option::is_none")]
    pub leaf_lifetime_days: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1CredentialsMtlsCertificatesItem {
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
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1CredentialsMtlsSubjectsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1CredentialsMtls {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<ApplicationListPageV1CredentialsMtlsCertificatesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<i64>,
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
    #[serde(rename = "implicitName", default, skip_serializing_if = "Option::is_none")]
    pub implicit_name: Option<String>,
    #[serde(rename = "caAvailable", default, skip_serializing_if = "Option::is_none")]
    pub ca_available: Option<bool>,
    #[serde(rename = "authMethod", default, skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<String>,
    #[serde(rename = "certificateMethod", default, skip_serializing_if = "Option::is_none")]
    pub certificate_method: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subjects: Option<Vec<ApplicationListPageV1CredentialsMtlsSubjectsItem>>,
    #[serde(rename = "registeredSubject", default, skip_serializing_if = "Option::is_none")]
    pub registered_subject: Option<Vec<String>>,
    #[serde(rename = "boundTokensAttribute", default, skip_serializing_if = "Option::is_none")]
    pub bound_tokens_attribute: Option<String>,
    #[serde(rename = "boundTokens", default, skip_serializing_if = "Option::is_none")]
    pub bound_tokens: Option<bool>,
    #[serde(rename = "adminApiBound", default, skip_serializing_if = "Option::is_none")]
    pub admin_api_bound: Option<bool>,
    #[serde(rename = "selfSignedThumbprint", default, skip_serializing_if = "Option::is_none")]
    pub self_signed_thumbprint: Option<String>,
    #[serde(rename = "bindingAvailable", default, skip_serializing_if = "Option::is_none")]
    pub binding_available: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1CredentialsSigningCertificatesItem {
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
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1CredentialsSigning {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<ApplicationListPageV1CredentialsSigningCertificatesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<i64>,
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
    #[serde(rename = "implicitName", default, skip_serializing_if = "Option::is_none")]
    pub implicit_name: Option<String>,
    #[serde(rename = "caAvailable", default, skip_serializing_if = "Option::is_none")]
    pub ca_available: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(rename = "wstrustDeclared", default, skip_serializing_if = "Option::is_none")]
    pub wstrust_declared: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1CredentialsStoredCertificatesItem {
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
pub struct ApplicationListPageV1CredentialsStored {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub dn: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<ApplicationListPageV1CredentialsStoredCertificatesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1Credentials {
    #[serde(rename = "oauthDeclared", default, skip_serializing_if = "Option::is_none")]
    pub oauth_declared: Option<bool>,
    #[serde(rename = "clientSecret", default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<ApplicationListPageV1CredentialsClientSecret>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purposes: Option<Vec<ApplicationListPageV1CredentialsPurposesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<ApplicationListPageV1CredentialsCa>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sources: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtls: Option<ApplicationListPageV1CredentialsMtls>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing: Option<ApplicationListPageV1CredentialsSigning>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored: Option<ApplicationListPageV1CredentialsStored>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ApplicationListPageV1SignalsStreamsItemAud {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1SignalsStreamsItemDelivery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub endpoint_url: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1SignalsStreamsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(rename = "statusReason", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status_reason: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub aud: Option<Option<ApplicationListPageV1SignalsStreamsItemAud>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<ApplicationListPageV1SignalsStreamsItemDelivery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_requested: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_delivered: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "lastPushAt", default, skip_serializing_if = "Option::is_none")]
    pub last_push_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "lastPushError", default, skip_serializing_if = "Option::is_none")]
    pub last_push_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ApplicationListPageV1SignalsSettingsItemValue {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1SignalsSettingsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<ApplicationListPageV1SignalsSettingsItemValue>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ApplicationListPageV1SignalsJsonStreamsItemAud {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1SignalsJsonStreamsItemDelivery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub endpoint_url: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1SignalsJsonStreamsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(rename = "statusReason", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status_reason: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub aud: Option<Option<ApplicationListPageV1SignalsJsonStreamsItemAud>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<ApplicationListPageV1SignalsJsonStreamsItemDelivery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_requested: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_delivered: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "lastPushAt", default, skip_serializing_if = "Option::is_none")]
    pub last_push_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "lastPushError", default, skip_serializing_if = "Option::is_none")]
    pub last_push_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ApplicationListPageV1SignalsJsonSettingsItemValue {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1SignalsJsonSettingsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<ApplicationListPageV1SignalsJsonSettingsItemValue>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1SignalsJson {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<Vec<ApplicationListPageV1SignalsJsonStreamsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<ApplicationListPageV1SignalsJsonSettingsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1Signals {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<Vec<ApplicationListPageV1SignalsStreamsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<ApplicationListPageV1SignalsSettingsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json: Option<ApplicationListPageV1SignalsJson>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ApplicationListPageV1SoftwareStatementKeyProblemsItem {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1SoftwareStatementIssued {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifies: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<f64>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
    /// RFC 7591 client metadata fixed by a software statement: any member a
    /// publisher chose, including extensions no specification defines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1SoftwareStatementRegisteredWith {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1SoftwareStatementSettings {
    #[serde(rename = "requireTrustedIssuer", default, skip_serializing_if = "Option::is_none")]
    pub require_trusted_issuer: Option<bool>,
    #[serde(rename = "opensRegistration", default, skip_serializing_if = "Option::is_none")]
    pub opens_registration: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(rename = "lifetimeSeconds", default, skip_serializing_if = "Option::is_none")]
    pub lifetime_seconds: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1SoftwareStatementJsonIssued {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifies: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<f64>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
    /// RFC 7591 client metadata fixed by a software statement: any member a
    /// publisher chose, including extensions no specification defines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1SoftwareStatementJsonRegisteredWith {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1SoftwareStatementJsonSettings {
    #[serde(rename = "requireTrustedIssuer", default, skip_serializing_if = "Option::is_none")]
    pub require_trusted_issuer: Option<bool>,
    #[serde(rename = "opensRegistration", default, skip_serializing_if = "Option::is_none")]
    pub opens_registration: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(rename = "lifetimeSeconds", default, skip_serializing_if = "Option::is_none")]
    pub lifetime_seconds: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1SoftwareStatementJson {
    #[serde(rename = "declaredIssuers", default, skip_serializing_if = "Option::is_none")]
    pub declared_issuers: Option<Vec<String>>,
    #[serde(rename = "usableKeys", default, skip_serializing_if = "Option::is_none")]
    pub usable_keys: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued: Option<ApplicationListPageV1SoftwareStatementJsonIssued>,
    #[serde(rename = "registeredWith", default, skip_serializing_if = "Option::is_none")]
    pub registered_with: Option<ApplicationListPageV1SoftwareStatementJsonRegisteredWith>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<ApplicationListPageV1SoftwareStatementJsonSettings>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1SoftwareStatement {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuers: Option<Vec<String>>,
    #[serde(rename = "usableKeys", default, skip_serializing_if = "Option::is_none")]
    pub usable_keys: Option<i64>,
    #[serde(rename = "keyProblems", default, skip_serializing_if = "Option::is_none")]
    pub key_problems: Option<Vec<Option<ApplicationListPageV1SoftwareStatementKeyProblemsItem>>>,
    #[serde(rename = "issuedToken", default, skip_serializing_if = "Option::is_none")]
    pub issued_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued: Option<ApplicationListPageV1SoftwareStatementIssued>,
    #[serde(rename = "registeredWith", default, skip_serializing_if = "Option::is_none")]
    pub registered_with: Option<ApplicationListPageV1SoftwareStatementRegisteredWith>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<ApplicationListPageV1SoftwareStatementSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json: Option<ApplicationListPageV1SoftwareStatementJson>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1RolesHeldItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(rename = "carriedAs", default, skip_serializing_if = "Option::is_none")]
    pub carried_as: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1RolesRequiredItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolves: Option<String>,
    #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1Roles {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<Vec<ApplicationListPageV1RolesHeldItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offerable: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<ApplicationListPageV1RolesRequiredItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requirable: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1PermissionsHeldItem {
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
    #[serde(rename = "permissionName", default, skip_serializing_if = "Option::is_none")]
    pub permission_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub description: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dangling: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1PermissionsExposesItemGrantedToItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1PermissionsExposesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(rename = "resourceName", default, skip_serializing_if = "Option::is_none")]
    pub resource_name: Option<String>,
    #[serde(rename = "baseUri", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub base_uri: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub description: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub id: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub raw: Option<Option<String>>,
    #[serde(rename = "grantedTo", default, skip_serializing_if = "Option::is_none")]
    pub granted_to: Option<Vec<ApplicationListPageV1PermissionsExposesItemGrantedToItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1PermissionsOfferableItemGrantedToItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1PermissionsOfferableItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(rename = "resourceName", default, skip_serializing_if = "Option::is_none")]
    pub resource_name: Option<String>,
    #[serde(rename = "baseUri", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub base_uri: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub description: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub id: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub raw: Option<Option<String>>,
    #[serde(rename = "grantedTo", default, skip_serializing_if = "Option::is_none")]
    pub granted_to: Option<Vec<ApplicationListPageV1PermissionsOfferableItemGrantedToItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1PermissionsClientsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1PermissionsHeldPagePaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noun: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1PermissionsHeldPageShownItem {
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
    #[serde(rename = "permissionName", default, skip_serializing_if = "Option::is_none")]
    pub permission_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub description: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dangling: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1PermissionsHeldPage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<ApplicationListPageV1PermissionsHeldPagePaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<Vec<ApplicationListPageV1PermissionsHeldPageShownItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1PermissionsExposedPagePaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noun: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1PermissionsExposedPageShownItemGrantedToItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1PermissionsExposedPageShownItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(rename = "resourceName", default, skip_serializing_if = "Option::is_none")]
    pub resource_name: Option<String>,
    #[serde(rename = "baseUri", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub base_uri: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub description: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub id: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub raw: Option<Option<String>>,
    #[serde(rename = "grantedTo", default, skip_serializing_if = "Option::is_none")]
    pub granted_to: Option<Vec<ApplicationListPageV1PermissionsExposedPageShownItemGrantedToItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1PermissionsExposedPage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<ApplicationListPageV1PermissionsExposedPagePaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<Vec<ApplicationListPageV1PermissionsExposedPageShownItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1PermissionsGrantedOutPagePaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noun: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1PermissionsGrantedOutPageShownItem {
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
    #[serde(rename = "permissionName", default, skip_serializing_if = "Option::is_none")]
    pub permission_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub description: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dangling: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1PermissionsGrantedOutPage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<ApplicationListPageV1PermissionsGrantedOutPagePaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<Vec<ApplicationListPageV1PermissionsGrantedOutPageShownItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1Permissions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<Vec<ApplicationListPageV1PermissionsHeldItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposes: Option<Vec<ApplicationListPageV1PermissionsExposesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offerable: Option<Vec<ApplicationListPageV1PermissionsOfferableItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clients: Option<Vec<ApplicationListPageV1PermissionsClientsItem>>,
    #[serde(rename = "heldPage", default, skip_serializing_if = "Option::is_none")]
    pub held_page: Option<ApplicationListPageV1PermissionsHeldPage>,
    #[serde(rename = "exposedPage", default, skip_serializing_if = "Option::is_none")]
    pub exposed_page: Option<ApplicationListPageV1PermissionsExposedPage>,
    #[serde(rename = "grantedOutPage", default, skip_serializing_if = "Option::is_none")]
    pub granted_out_page: Option<ApplicationListPageV1PermissionsGrantedOutPage>,
    #[serde(rename = "registerPermissions", default, skip_serializing_if = "Option::is_none")]
    pub register_permissions: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1LifetimesRowsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
    #[serde(rename = "realmValue", default, skip_serializing_if = "Option::is_none")]
    pub realm_value: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1Lifetimes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<ApplicationListPageV1LifetimesRowsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skew: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ApplicationListPageV1ClaimsItemRealmItemValue {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ClaimsItemRealmItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<ApplicationListPageV1ClaimsItemRealmItemValue>>,
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
#[serde(untagged)]
pub enum ApplicationListPageV1ClaimsItemOwnItemValue {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ClaimsItemOwnItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<ApplicationListPageV1ClaimsItemOwnItemValue>>,
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
#[serde(untagged)]
pub enum ApplicationListPageV1ClaimsItemEffectiveItemValue {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ClaimsItemEffectiveItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<ApplicationListPageV1ClaimsItemEffectiveItemValue>>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "replacesRealm", default, skip_serializing_if = "Option::is_none")]
    pub replaces_realm: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ClaimsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<Vec<ApplicationListPageV1ClaimsItemRealmItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub own: Option<Vec<ApplicationListPageV1ClaimsItemOwnItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective: Option<Vec<ApplicationListPageV1ClaimsItemEffectiveItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ClaimSelectionsCatalogueItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldap: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(rename = "ldpTerm", default, skip_serializing_if = "Option::is_none")]
    pub ldp_term: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ClaimSelectionsPreview {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// By lower-cased attribute name.
    #[serde(rename = "byLdap", default, skip_serializing_if = "Option::is_none")]
    pub by_ldap: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "entryFound", default, skip_serializing_if = "Option::is_none")]
    pub entry_found: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ApplicationListPageV1ClaimSelectionsSetsItemReportItemValue {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ClaimSelectionsSetsItemReportItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldap: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<ApplicationListPageV1ClaimSelectionsSetsItemReportItemValue>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "ldpTerm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ldp_term: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ClaimSelectionsSetsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub own: Option<Option<Vec<serde_json::Value>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherited: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective: Option<Vec<String>>,
    /// The claims, by name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<Vec<ApplicationListPageV1ClaimSelectionsSetsItemReportItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ApplicationListPageV1ClaimSelectionsCredentialReportItemValue {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ClaimSelectionsCredentialReportItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldap: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<ApplicationListPageV1ClaimSelectionsCredentialReportItemValue>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "ldpTerm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ldp_term: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ClaimSelectionsCredential {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub own: Option<Option<Vec<serde_json::Value>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherited: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective: Option<Vec<String>>,
    /// The claims, by name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<Vec<ApplicationListPageV1ClaimSelectionsCredentialReportItem>>,
    #[serde(rename = "ldpOmitted", default, skip_serializing_if = "Option::is_none")]
    pub ldp_omitted: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ClaimSelections {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalogue: Option<Vec<ApplicationListPageV1ClaimSelectionsCatalogueItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<ApplicationListPageV1ClaimSelectionsPreview>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sets: Option<Vec<ApplicationListPageV1ClaimSelectionsSetsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<ApplicationListPageV1ClaimSelectionsCredential>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentialsRulesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(rename = "allowedProfiles", default, skip_serializing_if = "Option::is_none")]
    pub allowed_profiles: Option<Vec<String>>,
    #[serde(rename = "allowedProfilesSource", default, skip_serializing_if = "Option::is_none")]
    pub allowed_profiles_source: Option<String>,
    #[serde(rename = "defaultProfile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default_profile: Option<Option<String>>,
    #[serde(rename = "defaultProfileSource", default, skip_serializing_if = "Option::is_none")]
    pub default_profile_source: Option<String>,
    #[serde(rename = "certificateLifetimeDays", default, skip_serializing_if = "Option::is_none")]
    pub certificate_lifetime_days: Option<f64>,
    #[serde(rename = "certificateLifetimeSource", default, skip_serializing_if = "Option::is_none")]
    pub certificate_lifetime_source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentialsCap {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentialsEstBasicAuthentication {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentialsEstCertificateAuthentication {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentialsEstServerKeyGeneration {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentialsEst {
    #[serde(rename = "basicAuthentication", default, skip_serializing_if = "Option::is_none")]
    pub basic_authentication: Option<ApplicationListPageV1EnrollmentCredentialsEstBasicAuthentication>,
    #[serde(rename = "certificateAuthentication", default, skip_serializing_if = "Option::is_none")]
    pub certificate_authentication: Option<ApplicationListPageV1EnrollmentCredentialsEstCertificateAuthentication>,
    #[serde(rename = "serverKeyGeneration", default, skip_serializing_if = "Option::is_none")]
    pub server_key_generation: Option<ApplicationListPageV1EnrollmentCredentialsEstServerKeyGeneration>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentialsCertificatesItemRequestedBy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ApplicationListPageV1EnrollmentCredentialsCertificatesItemAttestation {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentialsCertificatesItemRevoked {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentialsCertificatesItem {
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
    pub key_alg: Option<String>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<String>,
    #[serde(rename = "requestedBy", default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<ApplicationListPageV1EnrollmentCredentialsCertificatesItemRequestedBy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    #[serde(rename = "keySource", default, skip_serializing_if = "Option::is_none")]
    pub key_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub replaces: Option<Option<String>>,
    #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
    pub certificate_pem: Option<String>,
    #[serde(rename = "chainPem", default, skip_serializing_if = "Option::is_none")]
    pub chain_pem: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attestation: Option<Option<ApplicationListPageV1EnrollmentCredentialsCertificatesItemAttestation>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<ApplicationListPageV1EnrollmentCredentialsCertificatesItemRevoked>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentialsPagedPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noun: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentialsPagedShownItemRequestedBy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ApplicationListPageV1EnrollmentCredentialsPagedShownItemAttestation {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentialsPagedShownItemRevoked {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentialsPagedShownItem {
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
    pub key_alg: Option<String>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<String>,
    #[serde(rename = "requestedBy", default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<ApplicationListPageV1EnrollmentCredentialsPagedShownItemRequestedBy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    #[serde(rename = "keySource", default, skip_serializing_if = "Option::is_none")]
    pub key_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub replaces: Option<Option<String>>,
    #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
    pub certificate_pem: Option<String>,
    #[serde(rename = "chainPem", default, skip_serializing_if = "Option::is_none")]
    pub chain_pem: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attestation: Option<Option<ApplicationListPageV1EnrollmentCredentialsPagedShownItemAttestation>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<ApplicationListPageV1EnrollmentCredentialsPagedShownItemRevoked>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentialsPaged {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<ApplicationListPageV1EnrollmentCredentialsPagedPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<Vec<ApplicationListPageV1EnrollmentCredentialsPagedShownItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentialsEabKeysItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_by: Option<Option<String>>,
    #[serde(rename = "boundAccount", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub bound_account: Option<Option<String>>,
    #[serde(rename = "boundAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub bound_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentialsChallengesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub profile: Option<Option<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_by: Option<Option<String>>,
    #[serde(rename = "usedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub used_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentialsJsonRulesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(rename = "allowedProfiles", default, skip_serializing_if = "Option::is_none")]
    pub allowed_profiles: Option<Vec<String>>,
    #[serde(rename = "allowedProfilesSource", default, skip_serializing_if = "Option::is_none")]
    pub allowed_profiles_source: Option<String>,
    #[serde(rename = "defaultProfile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default_profile: Option<Option<String>>,
    #[serde(rename = "defaultProfileSource", default, skip_serializing_if = "Option::is_none")]
    pub default_profile_source: Option<String>,
    #[serde(rename = "certificateLifetimeDays", default, skip_serializing_if = "Option::is_none")]
    pub certificate_lifetime_days: Option<f64>,
    #[serde(rename = "certificateLifetimeSource", default, skip_serializing_if = "Option::is_none")]
    pub certificate_lifetime_source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentialsJsonCertificateCap {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentialsJsonEstBasicAuthentication {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentialsJsonEstCertificateAuthentication {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentialsJsonEstServerKeyGeneration {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentialsJsonEst {
    #[serde(rename = "basicAuthentication", default, skip_serializing_if = "Option::is_none")]
    pub basic_authentication: Option<ApplicationListPageV1EnrollmentCredentialsJsonEstBasicAuthentication>,
    #[serde(rename = "certificateAuthentication", default, skip_serializing_if = "Option::is_none")]
    pub certificate_authentication: Option<ApplicationListPageV1EnrollmentCredentialsJsonEstCertificateAuthentication>,
    #[serde(rename = "serverKeyGeneration", default, skip_serializing_if = "Option::is_none")]
    pub server_key_generation: Option<ApplicationListPageV1EnrollmentCredentialsJsonEstServerKeyGeneration>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentialsJsonCertificatesItemRequestedBy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ApplicationListPageV1EnrollmentCredentialsJsonCertificatesItemAttestation {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentialsJsonCertificatesItemRevoked {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentialsJsonCertificatesItem {
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
    pub key_alg: Option<String>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<String>,
    #[serde(rename = "requestedBy", default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<ApplicationListPageV1EnrollmentCredentialsJsonCertificatesItemRequestedBy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    #[serde(rename = "keySource", default, skip_serializing_if = "Option::is_none")]
    pub key_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub replaces: Option<Option<String>>,
    #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
    pub certificate_pem: Option<String>,
    #[serde(rename = "chainPem", default, skip_serializing_if = "Option::is_none")]
    pub chain_pem: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attestation: Option<Option<ApplicationListPageV1EnrollmentCredentialsJsonCertificatesItemAttestation>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<ApplicationListPageV1EnrollmentCredentialsJsonCertificatesItemRevoked>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentialsJsonCertificatesPaging {
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
pub struct ApplicationListPageV1EnrollmentCredentialsJsonEabKeysItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_by: Option<Option<String>>,
    #[serde(rename = "boundAccount", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub bound_account: Option<Option<String>>,
    #[serde(rename = "boundAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub bound_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentialsJsonScepChallengesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub profile: Option<Option<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_by: Option<Option<String>>,
    #[serde(rename = "usedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub used_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentialsJson {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub families: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<ApplicationListPageV1EnrollmentCredentialsJsonRulesItem>>,
    #[serde(rename = "certificateCap", default, skip_serializing_if = "Option::is_none")]
    pub certificate_cap: Option<ApplicationListPageV1EnrollmentCredentialsJsonCertificateCap>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub est: Option<ApplicationListPageV1EnrollmentCredentialsJsonEst>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<ApplicationListPageV1EnrollmentCredentialsJsonCertificatesItem>>,
    #[serde(rename = "certificatesPaging", default, skip_serializing_if = "Option::is_none")]
    pub certificates_paging: Option<ApplicationListPageV1EnrollmentCredentialsJsonCertificatesPaging>,
    #[serde(rename = "certificatesTotal", default, skip_serializing_if = "Option::is_none")]
    pub certificates_total: Option<i64>,
    #[serde(rename = "eabKeys", default, skip_serializing_if = "Option::is_none")]
    pub eab_keys: Option<Vec<ApplicationListPageV1EnrollmentCredentialsJsonEabKeysItem>>,
    #[serde(rename = "scepChallenges", default, skip_serializing_if = "Option::is_none")]
    pub scep_challenges: Option<Vec<ApplicationListPageV1EnrollmentCredentialsJsonScepChallengesItem>>,
    #[serde(rename = "hostNames", default, skip_serializing_if = "Option::is_none")]
    pub host_names: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentCredentials {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub families: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<ApplicationListPageV1EnrollmentCredentialsRulesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<ApplicationListPageV1EnrollmentCredentialsCap>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub est: Option<ApplicationListPageV1EnrollmentCredentialsEst>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<ApplicationListPageV1EnrollmentCredentialsCertificatesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paged: Option<ApplicationListPageV1EnrollmentCredentialsPaged>,
    #[serde(rename = "eabKeys", default, skip_serializing_if = "Option::is_none")]
    pub eab_keys: Option<Vec<ApplicationListPageV1EnrollmentCredentialsEabKeysItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenges: Option<Vec<ApplicationListPageV1EnrollmentCredentialsChallengesItem>>,
    #[serde(rename = "hostNames", default, skip_serializing_if = "Option::is_none")]
    pub host_names: Option<Vec<String>>,
    #[serde(rename = "keyAlgorithms", default, skip_serializing_if = "Option::is_none")]
    pub key_algorithms: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json: Option<ApplicationListPageV1EnrollmentCredentialsJson>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfigRulesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(rename = "allowedProfiles", default, skip_serializing_if = "Option::is_none")]
    pub allowed_profiles: Option<Vec<String>>,
    #[serde(rename = "allowedProfilesSource", default, skip_serializing_if = "Option::is_none")]
    pub allowed_profiles_source: Option<String>,
    #[serde(rename = "defaultProfile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default_profile: Option<Option<String>>,
    #[serde(rename = "defaultProfileSource", default, skip_serializing_if = "Option::is_none")]
    pub default_profile_source: Option<String>,
    #[serde(rename = "certificateLifetimeDays", default, skip_serializing_if = "Option::is_none")]
    pub certificate_lifetime_days: Option<f64>,
    #[serde(rename = "certificateLifetimeSource", default, skip_serializing_if = "Option::is_none")]
    pub certificate_lifetime_source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfigCap {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfigEstBasicAuthentication {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfigEstCertificateAuthentication {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfigEstServerKeyGeneration {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfigEst {
    #[serde(rename = "basicAuthentication", default, skip_serializing_if = "Option::is_none")]
    pub basic_authentication: Option<ApplicationListPageV1EnrollmentConfigEstBasicAuthentication>,
    #[serde(rename = "certificateAuthentication", default, skip_serializing_if = "Option::is_none")]
    pub certificate_authentication: Option<ApplicationListPageV1EnrollmentConfigEstCertificateAuthentication>,
    #[serde(rename = "serverKeyGeneration", default, skip_serializing_if = "Option::is_none")]
    pub server_key_generation: Option<ApplicationListPageV1EnrollmentConfigEstServerKeyGeneration>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfigCertificatesItemRequestedBy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ApplicationListPageV1EnrollmentConfigCertificatesItemAttestation {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfigCertificatesItemRevoked {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfigCertificatesItem {
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
    pub key_alg: Option<String>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<String>,
    #[serde(rename = "requestedBy", default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<ApplicationListPageV1EnrollmentConfigCertificatesItemRequestedBy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    #[serde(rename = "keySource", default, skip_serializing_if = "Option::is_none")]
    pub key_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub replaces: Option<Option<String>>,
    #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
    pub certificate_pem: Option<String>,
    #[serde(rename = "chainPem", default, skip_serializing_if = "Option::is_none")]
    pub chain_pem: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attestation: Option<Option<ApplicationListPageV1EnrollmentConfigCertificatesItemAttestation>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<ApplicationListPageV1EnrollmentConfigCertificatesItemRevoked>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfigPagedPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noun: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfigPagedShownItemRequestedBy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ApplicationListPageV1EnrollmentConfigPagedShownItemAttestation {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfigPagedShownItemRevoked {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfigPagedShownItem {
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
    pub key_alg: Option<String>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<String>,
    #[serde(rename = "requestedBy", default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<ApplicationListPageV1EnrollmentConfigPagedShownItemRequestedBy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    #[serde(rename = "keySource", default, skip_serializing_if = "Option::is_none")]
    pub key_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub replaces: Option<Option<String>>,
    #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
    pub certificate_pem: Option<String>,
    #[serde(rename = "chainPem", default, skip_serializing_if = "Option::is_none")]
    pub chain_pem: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attestation: Option<Option<ApplicationListPageV1EnrollmentConfigPagedShownItemAttestation>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<ApplicationListPageV1EnrollmentConfigPagedShownItemRevoked>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfigPaged {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<ApplicationListPageV1EnrollmentConfigPagedPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<Vec<ApplicationListPageV1EnrollmentConfigPagedShownItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfigEabKeysItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_by: Option<Option<String>>,
    #[serde(rename = "boundAccount", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub bound_account: Option<Option<String>>,
    #[serde(rename = "boundAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub bound_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfigChallengesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub profile: Option<Option<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_by: Option<Option<String>>,
    #[serde(rename = "usedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub used_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfigJsonRulesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(rename = "allowedProfiles", default, skip_serializing_if = "Option::is_none")]
    pub allowed_profiles: Option<Vec<String>>,
    #[serde(rename = "allowedProfilesSource", default, skip_serializing_if = "Option::is_none")]
    pub allowed_profiles_source: Option<String>,
    #[serde(rename = "defaultProfile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default_profile: Option<Option<String>>,
    #[serde(rename = "defaultProfileSource", default, skip_serializing_if = "Option::is_none")]
    pub default_profile_source: Option<String>,
    #[serde(rename = "certificateLifetimeDays", default, skip_serializing_if = "Option::is_none")]
    pub certificate_lifetime_days: Option<f64>,
    #[serde(rename = "certificateLifetimeSource", default, skip_serializing_if = "Option::is_none")]
    pub certificate_lifetime_source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfigJsonCertificateCap {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfigJsonEstBasicAuthentication {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfigJsonEstCertificateAuthentication {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfigJsonEstServerKeyGeneration {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfigJsonEst {
    #[serde(rename = "basicAuthentication", default, skip_serializing_if = "Option::is_none")]
    pub basic_authentication: Option<ApplicationListPageV1EnrollmentConfigJsonEstBasicAuthentication>,
    #[serde(rename = "certificateAuthentication", default, skip_serializing_if = "Option::is_none")]
    pub certificate_authentication: Option<ApplicationListPageV1EnrollmentConfigJsonEstCertificateAuthentication>,
    #[serde(rename = "serverKeyGeneration", default, skip_serializing_if = "Option::is_none")]
    pub server_key_generation: Option<ApplicationListPageV1EnrollmentConfigJsonEstServerKeyGeneration>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfigJsonCertificatesItemRequestedBy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ApplicationListPageV1EnrollmentConfigJsonCertificatesItemAttestation {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfigJsonCertificatesItemRevoked {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfigJsonCertificatesItem {
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
    pub key_alg: Option<String>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<String>,
    #[serde(rename = "requestedBy", default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<ApplicationListPageV1EnrollmentConfigJsonCertificatesItemRequestedBy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    #[serde(rename = "keySource", default, skip_serializing_if = "Option::is_none")]
    pub key_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub replaces: Option<Option<String>>,
    #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
    pub certificate_pem: Option<String>,
    #[serde(rename = "chainPem", default, skip_serializing_if = "Option::is_none")]
    pub chain_pem: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attestation: Option<Option<ApplicationListPageV1EnrollmentConfigJsonCertificatesItemAttestation>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<ApplicationListPageV1EnrollmentConfigJsonCertificatesItemRevoked>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfigJsonCertificatesPaging {
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
pub struct ApplicationListPageV1EnrollmentConfigJsonEabKeysItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_by: Option<Option<String>>,
    #[serde(rename = "boundAccount", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub bound_account: Option<Option<String>>,
    #[serde(rename = "boundAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub bound_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfigJsonScepChallengesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub profile: Option<Option<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_by: Option<Option<String>>,
    #[serde(rename = "usedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub used_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfigJson {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub families: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<ApplicationListPageV1EnrollmentConfigJsonRulesItem>>,
    #[serde(rename = "certificateCap", default, skip_serializing_if = "Option::is_none")]
    pub certificate_cap: Option<ApplicationListPageV1EnrollmentConfigJsonCertificateCap>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub est: Option<ApplicationListPageV1EnrollmentConfigJsonEst>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<ApplicationListPageV1EnrollmentConfigJsonCertificatesItem>>,
    #[serde(rename = "certificatesPaging", default, skip_serializing_if = "Option::is_none")]
    pub certificates_paging: Option<ApplicationListPageV1EnrollmentConfigJsonCertificatesPaging>,
    #[serde(rename = "certificatesTotal", default, skip_serializing_if = "Option::is_none")]
    pub certificates_total: Option<i64>,
    #[serde(rename = "eabKeys", default, skip_serializing_if = "Option::is_none")]
    pub eab_keys: Option<Vec<ApplicationListPageV1EnrollmentConfigJsonEabKeysItem>>,
    #[serde(rename = "scepChallenges", default, skip_serializing_if = "Option::is_none")]
    pub scep_challenges: Option<Vec<ApplicationListPageV1EnrollmentConfigJsonScepChallengesItem>>,
    #[serde(rename = "hostNames", default, skip_serializing_if = "Option::is_none")]
    pub host_names: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1EnrollmentConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub families: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<ApplicationListPageV1EnrollmentConfigRulesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<ApplicationListPageV1EnrollmentConfigCap>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub est: Option<ApplicationListPageV1EnrollmentConfigEst>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<ApplicationListPageV1EnrollmentConfigCertificatesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paged: Option<ApplicationListPageV1EnrollmentConfigPaged>,
    #[serde(rename = "eabKeys", default, skip_serializing_if = "Option::is_none")]
    pub eab_keys: Option<Vec<ApplicationListPageV1EnrollmentConfigEabKeysItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenges: Option<Vec<ApplicationListPageV1EnrollmentConfigChallengesItem>>,
    #[serde(rename = "hostNames", default, skip_serializing_if = "Option::is_none")]
    pub host_names: Option<Vec<String>>,
    #[serde(rename = "keyAlgorithms", default, skip_serializing_if = "Option::is_none")]
    pub key_algorithms: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json: Option<ApplicationListPageV1EnrollmentConfigJson>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1Enrollment {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<ApplicationListPageV1EnrollmentCredentials>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<ApplicationListPageV1EnrollmentConfig>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ObservedPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noun: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1ObservedShownItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1Observed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<ApplicationListPageV1ObservedPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<Vec<ApplicationListPageV1ObservedShownItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1WarningsItem {
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
pub struct ApplicationListPageV1OwnersItem {
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
pub struct ApplicationListPageV1Ownership {
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
pub struct ApplicationListPageV1Krb5AcrossFrontEndsItemProblemsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// What the sentence names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1Krb5AcrossFrontEndsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<ApplicationListPageV1Krb5AcrossFrontEndsItemProblemsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1Krb5AcrossTargetsItemProblemsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// What the sentence names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1Krb5AcrossTargetsItemClassicProblemsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// What the sentence names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1Krb5AcrossTargetsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<ApplicationListPageV1Krb5AcrossTargetsItemProblemsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(rename = "classicRefused", default, skip_serializing_if = "Option::is_none")]
    pub classic_refused: Option<bool>,
    #[serde(rename = "classicProblems", default, skip_serializing_if = "Option::is_none")]
    pub classic_problems: Option<Vec<ApplicationListPageV1Krb5AcrossTargetsItemClassicProblemsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1Krb5AcrossSelfRealmsItemProblemsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// What the sentence names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1Krb5AcrossSelfRealmsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<ApplicationListPageV1Krb5AcrossSelfRealmsItemProblemsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1Krb5AcrossTgtDelegationTrustsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1Krb5AcrossTgtDelegation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unconstrained: Option<bool>,
    #[serde(rename = "foreignTgtDelegation", default, skip_serializing_if = "Option::is_none")]
    pub foreign_tgt_delegation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusts: Option<Vec<ApplicationListPageV1Krb5AcrossTgtDelegationTrustsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1Krb5AcrossChoices {
    #[serde(rename = "krb5S4uSelfRealm", default, skip_serializing_if = "Option::is_none")]
    pub krb5_s4u_self_realm: Option<Vec<String>>,
    #[serde(rename = "krb5ForeignTgtDelegation", default, skip_serializing_if = "Option::is_none")]
    pub krb5_foreign_tgt_delegation: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1Krb5Across {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(rename = "frontEnds", default, skip_serializing_if = "Option::is_none")]
    pub front_ends: Option<Vec<ApplicationListPageV1Krb5AcrossFrontEndsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub targets: Option<Vec<ApplicationListPageV1Krb5AcrossTargetsItem>>,
    #[serde(rename = "selfRealms", default, skip_serializing_if = "Option::is_none")]
    pub self_realms: Option<Vec<ApplicationListPageV1Krb5AcrossSelfRealmsItem>>,
    #[serde(rename = "tgtDelegation", default, skip_serializing_if = "Option::is_none")]
    pub tgt_delegation: Option<ApplicationListPageV1Krb5AcrossTgtDelegation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub choices: Option<ApplicationListPageV1Krb5AcrossChoices>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListPageV1 {
    /// What each attribute of the entry is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<ApplicationListPageV1Config>,
    #[serde(rename = "passkeyPolicies", default, skip_serializing_if = "Option::is_none")]
    pub passkey_policies: Option<ApplicationListPageV1PasskeyPolicies>,
    /// By protocol.
    #[serde(rename = "launchUrls", default, skip_serializing_if = "Option::is_none")]
    pub launch_urls: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cors: Option<Vec<ApplicationListPageV1CorsItem>>,
    #[serde(rename = "accessTypes", default, skip_serializing_if = "Option::is_none")]
    pub access_types: Option<Vec<ApplicationListPageV1AccessTypesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fga: Option<ApplicationListPageV1Fga>,
    #[serde(rename = "permissionClaims", default, skip_serializing_if = "Option::is_none")]
    pub permission_claims: Option<ApplicationListPageV1PermissionClaims>,
    #[serde(rename = "grantsUncataloguedAccess", default, skip_serializing_if = "Option::is_none")]
    pub grants_uncatalogued_access: Option<bool>,
    #[serde(rename = "acceptsUnregisteredAddresses", default, skip_serializing_if = "Option::is_none")]
    pub accepts_unregistered_addresses: Option<bool>,
    #[serde(rename = "protocolRows", default, skip_serializing_if = "Option::is_none")]
    pub protocol_rows: Option<Vec<ApplicationListPageV1ProtocolRowsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<ApplicationListPageV1Editable>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did: Option<ApplicationListPageV1Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<ApplicationListPageV1Credentials>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signals: Option<ApplicationListPageV1Signals>,
    #[serde(rename = "softwareStatement", default, skip_serializing_if = "Option::is_none")]
    pub software_statement: Option<ApplicationListPageV1SoftwareStatement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<ApplicationListPageV1Roles>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<ApplicationListPageV1Permissions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifetimes: Option<ApplicationListPageV1Lifetimes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<ApplicationListPageV1ClaimsItem>>,
    #[serde(rename = "claimSelections", default, skip_serializing_if = "Option::is_none")]
    pub claim_selections: Option<ApplicationListPageV1ClaimSelections>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment: Option<ApplicationListPageV1Enrollment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed: Option<ApplicationListPageV1Observed>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<ApplicationListPageV1WarningsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owners: Option<Vec<ApplicationListPageV1OwnersItem>>,
    #[serde(rename = "maxOwners", default, skip_serializing_if = "Option::is_none")]
    pub max_owners: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ownership: Option<ApplicationListPageV1Ownership>,
    #[serde(rename = "krb5Across", default, skip_serializing_if = "Option::is_none")]
    pub krb5_across: Option<ApplicationListPageV1Krb5Across>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ApplicationListPage {
    V1(ApplicationListPageV1),
    Integer(i64),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListReturnAddressesObservedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListWarningsItem {
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
#[serde(untagged)]
pub enum ApplicationListAttributesShownItemValuesItem {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListAttributesShownItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<Option<ApplicationListAttributesShownItemValuesItem>>>,
    #[serde(rename = "sealedAtRest", default, skip_serializing_if = "Option::is_none")]
    pub sealed_at_rest: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operational: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListAttributesPaging {
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
pub struct ApplicationListAuthenticationEventsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub origin: Option<Option<sts_model_base::unions::NumberOrString>>,
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
    /// What the event recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListAuthenticationEventsPaging {
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
pub struct ApplicationListAuthenticationEventsLog {
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
pub struct ApplicationListReturnAddressesObservedShownItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListReturnAddressesObservedPaging {
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
pub struct ApplicationListCredentialsClientSecretSecretsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<f64>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub description: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCredentialsClientSecret {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<bool>,
    #[serde(rename = "authMethod", default, skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
    #[serde(rename = "registrationAccessTokenHeld", default, skip_serializing_if = "Option::is_none")]
    pub registration_access_token_held: Option<bool>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<ApplicationListCredentialsClientSecretSecretsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCredentialsKeyPairsItemCertificate {
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
    #[serde(rename = "keyType", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub key_type: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCredentialsKeyPairsItemChainItem {
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
    #[serde(rename = "keyType", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub key_type: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCredentialsKeyPairsItemAttributes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<String>,
    #[serde(rename = "privateKey", default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(rename = "handleLabel", default, skip_serializing_if = "Option::is_none")]
    pub handle_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCredentialsKeyPairsItemRegisteredKeysItemCertificate {
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
    #[serde(rename = "keyType", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub key_type: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCredentialsKeyPairsItemRegisteredKeysItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kty: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<ApplicationListCredentialsKeyPairsItemRegisteredKeysItemCertificate>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCredentialsKeyPairsItemRegisteredCertificatesItem {
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
    #[serde(rename = "keyType", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub key_type: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCredentialsKeyPairsItemRegistered {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<ApplicationListCredentialsKeyPairsItemRegisteredKeysItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<ApplicationListCredentialsKeyPairsItemRegisteredCertificatesItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCredentialsKeyPairsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "privateKeyHeld", default, skip_serializing_if = "Option::is_none")]
    pub private_key_held: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<ApplicationListCredentialsKeyPairsItemCertificate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<Vec<ApplicationListCredentialsKeyPairsItemChainItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(rename = "handleLabel", default, skip_serializing_if = "Option::is_none")]
    pub handle_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuers: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<ApplicationListCredentialsKeyPairsItemAttributes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<ApplicationListCredentialsKeyPairsItemRegistered>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCredentialsMtlsCertificatesItem {
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
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCredentialsMtlsSubjectsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCredentialsMtls {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<ApplicationListCredentialsMtlsCertificatesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<i64>,
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
    #[serde(rename = "implicitName", default, skip_serializing_if = "Option::is_none")]
    pub implicit_name: Option<String>,
    #[serde(rename = "caAvailable", default, skip_serializing_if = "Option::is_none")]
    pub ca_available: Option<bool>,
    #[serde(rename = "authMethod", default, skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<String>,
    #[serde(rename = "certificateMethod", default, skip_serializing_if = "Option::is_none")]
    pub certificate_method: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subjects: Option<Vec<ApplicationListCredentialsMtlsSubjectsItem>>,
    #[serde(rename = "registeredSubject", default, skip_serializing_if = "Option::is_none")]
    pub registered_subject: Option<Vec<String>>,
    #[serde(rename = "boundTokensAttribute", default, skip_serializing_if = "Option::is_none")]
    pub bound_tokens_attribute: Option<String>,
    #[serde(rename = "boundTokens", default, skip_serializing_if = "Option::is_none")]
    pub bound_tokens: Option<bool>,
    #[serde(rename = "adminApiBound", default, skip_serializing_if = "Option::is_none")]
    pub admin_api_bound: Option<bool>,
    #[serde(rename = "selfSignedThumbprint", default, skip_serializing_if = "Option::is_none")]
    pub self_signed_thumbprint: Option<String>,
    #[serde(rename = "bindingAvailable", default, skip_serializing_if = "Option::is_none")]
    pub binding_available: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCredentialsSigningCertificatesItem {
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
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCredentialsSigning {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<ApplicationListCredentialsSigningCertificatesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<i64>,
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
    #[serde(rename = "implicitName", default, skip_serializing_if = "Option::is_none")]
    pub implicit_name: Option<String>,
    #[serde(rename = "caAvailable", default, skip_serializing_if = "Option::is_none")]
    pub ca_available: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(rename = "wstrustDeclared", default, skip_serializing_if = "Option::is_none")]
    pub wstrust_declared: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCredentialsStoredCertificatesItem {
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
pub struct ApplicationListCredentialsStored {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub dn: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<ApplicationListCredentialsStoredCertificatesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCredentials {
    #[serde(rename = "clientSecret", default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<ApplicationListCredentialsClientSecret>,
    #[serde(rename = "keyPairs", default, skip_serializing_if = "Option::is_none")]
    pub key_pairs: Option<Vec<ApplicationListCredentialsKeyPairsItem>>,
    #[serde(rename = "caAvailable", default, skip_serializing_if = "Option::is_none")]
    pub ca_available: Option<bool>,
    #[serde(rename = "oauthDeclared", default, skip_serializing_if = "Option::is_none")]
    pub oauth_declared: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sources: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtls: Option<ApplicationListCredentialsMtls>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing: Option<ApplicationListCredentialsSigning>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored: Option<ApplicationListCredentialsStored>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ApplicationListSharedSignalsStreamsItemAud {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListSharedSignalsStreamsItemDelivery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub endpoint_url: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListSharedSignalsStreamsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(rename = "statusReason", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status_reason: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub aud: Option<Option<ApplicationListSharedSignalsStreamsItemAud>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<ApplicationListSharedSignalsStreamsItemDelivery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_requested: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_delivered: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "lastPushAt", default, skip_serializing_if = "Option::is_none")]
    pub last_push_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "lastPushError", default, skip_serializing_if = "Option::is_none")]
    pub last_push_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ApplicationListSharedSignalsSettingsItemValue {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListSharedSignalsSettingsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<ApplicationListSharedSignalsSettingsItemValue>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListSharedSignals {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<Vec<ApplicationListSharedSignalsStreamsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<ApplicationListSharedSignalsSettingsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCertificateEnrollmentRulesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(rename = "allowedProfiles", default, skip_serializing_if = "Option::is_none")]
    pub allowed_profiles: Option<Vec<String>>,
    #[serde(rename = "allowedProfilesSource", default, skip_serializing_if = "Option::is_none")]
    pub allowed_profiles_source: Option<String>,
    #[serde(rename = "defaultProfile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default_profile: Option<Option<String>>,
    #[serde(rename = "defaultProfileSource", default, skip_serializing_if = "Option::is_none")]
    pub default_profile_source: Option<String>,
    #[serde(rename = "certificateLifetimeDays", default, skip_serializing_if = "Option::is_none")]
    pub certificate_lifetime_days: Option<f64>,
    #[serde(rename = "certificateLifetimeSource", default, skip_serializing_if = "Option::is_none")]
    pub certificate_lifetime_source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCertificateEnrollmentCertificateCap {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCertificateEnrollmentEstBasicAuthentication {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCertificateEnrollmentEstCertificateAuthentication {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCertificateEnrollmentEstServerKeyGeneration {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCertificateEnrollmentEst {
    #[serde(rename = "basicAuthentication", default, skip_serializing_if = "Option::is_none")]
    pub basic_authentication: Option<ApplicationListCertificateEnrollmentEstBasicAuthentication>,
    #[serde(rename = "certificateAuthentication", default, skip_serializing_if = "Option::is_none")]
    pub certificate_authentication: Option<ApplicationListCertificateEnrollmentEstCertificateAuthentication>,
    #[serde(rename = "serverKeyGeneration", default, skip_serializing_if = "Option::is_none")]
    pub server_key_generation: Option<ApplicationListCertificateEnrollmentEstServerKeyGeneration>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCertificateEnrollmentCertificatesItemRequestedBy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ApplicationListCertificateEnrollmentCertificatesItemAttestation {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCertificateEnrollmentCertificatesItemRevoked {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCertificateEnrollmentCertificatesItem {
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(rename = "keyAlg", default, skip_serializing_if = "Option::is_none")]
    pub key_alg: Option<String>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<String>,
    #[serde(rename = "requestedBy", default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<ApplicationListCertificateEnrollmentCertificatesItemRequestedBy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    #[serde(rename = "keySource", default, skip_serializing_if = "Option::is_none")]
    pub key_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub replaces: Option<Option<String>>,
    #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
    pub certificate_pem: Option<String>,
    #[serde(rename = "chainPem", default, skip_serializing_if = "Option::is_none")]
    pub chain_pem: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attestation: Option<Option<ApplicationListCertificateEnrollmentCertificatesItemAttestation>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<ApplicationListCertificateEnrollmentCertificatesItemRevoked>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCertificateEnrollmentCertificatesPaging {
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
pub struct ApplicationListCertificateEnrollmentEabKeysItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_by: Option<Option<String>>,
    #[serde(rename = "boundAccount", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub bound_account: Option<Option<String>>,
    #[serde(rename = "boundAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub bound_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCertificateEnrollmentScepChallengesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub profile: Option<Option<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_by: Option<Option<String>>,
    #[serde(rename = "usedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub used_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCertificateEnrollment {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub families: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<ApplicationListCertificateEnrollmentRulesItem>>,
    #[serde(rename = "certificateCap", default, skip_serializing_if = "Option::is_none")]
    pub certificate_cap: Option<ApplicationListCertificateEnrollmentCertificateCap>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub est: Option<ApplicationListCertificateEnrollmentEst>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<ApplicationListCertificateEnrollmentCertificatesItem>>,
    #[serde(rename = "certificatesPaging", default, skip_serializing_if = "Option::is_none")]
    pub certificates_paging: Option<ApplicationListCertificateEnrollmentCertificatesPaging>,
    #[serde(rename = "certificatesTotal", default, skip_serializing_if = "Option::is_none")]
    pub certificates_total: Option<i64>,
    #[serde(rename = "eabKeys", default, skip_serializing_if = "Option::is_none")]
    pub eab_keys: Option<Vec<ApplicationListCertificateEnrollmentEabKeysItem>>,
    #[serde(rename = "scepChallenges", default, skip_serializing_if = "Option::is_none")]
    pub scep_challenges: Option<Vec<ApplicationListCertificateEnrollmentScepChallengesItem>>,
    #[serde(rename = "hostNames", default, skip_serializing_if = "Option::is_none")]
    pub host_names: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ApplicationListCustomClaimsItemRealmItemValue {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCustomClaimsItemRealmItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<ApplicationListCustomClaimsItemRealmItemValue>>,
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
#[serde(untagged)]
pub enum ApplicationListCustomClaimsItemOwnItemValue {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCustomClaimsItemOwnItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<ApplicationListCustomClaimsItemOwnItemValue>>,
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
#[serde(untagged)]
pub enum ApplicationListCustomClaimsItemEffectiveItemValue {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCustomClaimsItemEffectiveItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<ApplicationListCustomClaimsItemEffectiveItemValue>>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "replacesRealm", default, skip_serializing_if = "Option::is_none")]
    pub replaces_realm: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListCustomClaimsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<Vec<ApplicationListCustomClaimsItemRealmItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub own: Option<Vec<ApplicationListCustomClaimsItemOwnItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective: Option<Vec<ApplicationListCustomClaimsItemEffectiveItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListClaimSelectionsCatalogueItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldap: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(rename = "ldpTerm", default, skip_serializing_if = "Option::is_none")]
    pub ldp_term: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListClaimSelectionsPreview {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// By lower-cased attribute name.
    #[serde(rename = "byLdap", default, skip_serializing_if = "Option::is_none")]
    pub by_ldap: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "entryFound", default, skip_serializing_if = "Option::is_none")]
    pub entry_found: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ApplicationListClaimSelectionsSetsItemReportItemValue {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListClaimSelectionsSetsItemReportItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldap: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<ApplicationListClaimSelectionsSetsItemReportItemValue>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "ldpTerm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ldp_term: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListClaimSelectionsSetsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub own: Option<Option<Vec<serde_json::Value>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherited: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective: Option<Vec<String>>,
    /// The claims, by name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<Vec<ApplicationListClaimSelectionsSetsItemReportItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ApplicationListClaimSelectionsCredentialReportItemValue {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListClaimSelectionsCredentialReportItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldap: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<ApplicationListClaimSelectionsCredentialReportItemValue>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "ldpTerm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ldp_term: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListClaimSelectionsCredential {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub own: Option<Option<Vec<serde_json::Value>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherited: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective: Option<Vec<String>>,
    /// The claims, by name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<Vec<ApplicationListClaimSelectionsCredentialReportItem>>,
    #[serde(rename = "ldpOmitted", default, skip_serializing_if = "Option::is_none")]
    pub ldp_omitted: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListClaimSelections {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalogue: Option<Vec<ApplicationListClaimSelectionsCatalogueItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<ApplicationListClaimSelectionsPreview>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sets: Option<Vec<ApplicationListClaimSelectionsSetsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<ApplicationListClaimSelectionsCredential>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListTokenLifetimesLifetimesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
    #[serde(rename = "realmValue", default, skip_serializing_if = "Option::is_none")]
    pub realm_value: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListTokenLifetimes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifetimes: Option<Vec<ApplicationListTokenLifetimesLifetimesItem>>,
    #[serde(rename = "clockSkewS", default, skip_serializing_if = "Option::is_none")]
    pub clock_skew_s: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListSoftwareStatementsIssued {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifies: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<f64>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
    /// RFC 7591 client metadata fixed by a software statement: any member a
    /// publisher chose, including extensions no specification defines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListSoftwareStatementsRegisteredWith {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListSoftwareStatementsSettings {
    #[serde(rename = "requireTrustedIssuer", default, skip_serializing_if = "Option::is_none")]
    pub require_trusted_issuer: Option<bool>,
    #[serde(rename = "opensRegistration", default, skip_serializing_if = "Option::is_none")]
    pub opens_registration: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(rename = "lifetimeSeconds", default, skip_serializing_if = "Option::is_none")]
    pub lifetime_seconds: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListSoftwareStatements {
    #[serde(rename = "declaredIssuers", default, skip_serializing_if = "Option::is_none")]
    pub declared_issuers: Option<Vec<String>>,
    #[serde(rename = "usableKeys", default, skip_serializing_if = "Option::is_none")]
    pub usable_keys: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued: Option<ApplicationListSoftwareStatementsIssued>,
    #[serde(rename = "registeredWith", default, skip_serializing_if = "Option::is_none")]
    pub registered_with: Option<ApplicationListSoftwareStatementsRegisteredWith>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<ApplicationListSoftwareStatementsSettings>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListApplicationRolesHeldItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(rename = "carriedAs", default, skip_serializing_if = "Option::is_none")]
    pub carried_as: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListApplicationRolesRequiredItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolves: Option<String>,
    #[serde(rename = "displayName", default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListApplicationRoles {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<Vec<ApplicationListApplicationRolesHeldItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offerable: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<ApplicationListApplicationRolesRequiredItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requirable: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListDelegatedPermissionsHeldItem {
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
    #[serde(rename = "permissionName", default, skip_serializing_if = "Option::is_none")]
    pub permission_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub description: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dangling: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListDelegatedPermissionsExposesItemGrantedToItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListDelegatedPermissionsExposesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(rename = "resourceName", default, skip_serializing_if = "Option::is_none")]
    pub resource_name: Option<String>,
    #[serde(rename = "baseUri", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub base_uri: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub description: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub id: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub raw: Option<Option<String>>,
    #[serde(rename = "grantedTo", default, skip_serializing_if = "Option::is_none")]
    pub granted_to: Option<Vec<ApplicationListDelegatedPermissionsExposesItemGrantedToItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListDelegatedPermissionsGrantedOutItem {
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
    #[serde(rename = "permissionName", default, skip_serializing_if = "Option::is_none")]
    pub permission_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub description: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dangling: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListDelegatedPermissionsPagingHeld {
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
pub struct ApplicationListDelegatedPermissionsPagingExposes {
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
pub struct ApplicationListDelegatedPermissionsPagingGrantedOut {
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
pub struct ApplicationListDelegatedPermissionsPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<ApplicationListDelegatedPermissionsPagingHeld>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposes: Option<ApplicationListDelegatedPermissionsPagingExposes>,
    #[serde(rename = "grantedOut", default, skip_serializing_if = "Option::is_none")]
    pub granted_out: Option<ApplicationListDelegatedPermissionsPagingGrantedOut>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListDelegatedPermissions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<Vec<ApplicationListDelegatedPermissionsHeldItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposes: Option<Vec<ApplicationListDelegatedPermissionsExposesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offerable: Option<Vec<Option<String>>>,
    #[serde(rename = "grantedOut", default, skip_serializing_if = "Option::is_none")]
    pub granted_out: Option<Vec<ApplicationListDelegatedPermissionsGrantedOutItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<ApplicationListDelegatedPermissionsPaging>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationListOwnersItem {
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
pub struct ApplicationList {
    #[serde(rename = "applicationCount", default, skip_serializing_if = "Option::is_none")]
    pub application_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<sts_model_base::unions::BoolOrNumber>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<ApplicationListFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub container: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub max: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<ApplicationListKindsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<ApplicationListSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<ApplicationListPaging>,
    /// How many applications are of each kind.
    #[serde(rename = "kindCounts", default, skip_serializing_if = "Option::is_none")]
    pub kind_counts: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentications: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<ApplicationListProtocolsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applications: Option<Vec<ApplicationListApplicationsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<ApplicationListPage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(rename = "dnLabel", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub dn_label: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub dn: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
    #[serde(rename = "allowedProtocols", default, skip_serializing_if = "Option::is_none")]
    pub allowed_protocols: Option<Vec<String>>,
    #[serde(rename = "recordedProtocols", default, skip_serializing_if = "Option::is_none")]
    pub recorded_protocols: Option<Vec<String>>,
    #[serde(rename = "declaredKinds", default, skip_serializing_if = "Option::is_none")]
    pub declared_kinds: Option<Vec<String>>,
    #[serde(rename = "registeredBy", default, skip_serializing_if = "Option::is_none")]
    pub registered_by: Option<String>,
    #[serde(rename = "returnAddressesObserved", default, skip_serializing_if = "Option::is_none")]
    pub return_addresses_observed: Option<Vec<ApplicationListReturnAddressesObservedItem>>,
    #[serde(rename = "firstSeen", default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
    #[serde(rename = "lastSeen", default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub description: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub origin: Option<Option<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<String>>,
    #[serde(rename = "modifiedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub modified_at: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operational: Option<Vec<String>>,
    /// By attribute name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Map<String, serde_json::Value>>,
    /// By attribute name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub found: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<ApplicationListWarningsItem>>,
    #[serde(rename = "attributesShown", default, skip_serializing_if = "Option::is_none")]
    pub attributes_shown: Option<Vec<ApplicationListAttributesShownItem>>,
    #[serde(rename = "attributesPaging", default, skip_serializing_if = "Option::is_none")]
    pub attributes_paging: Option<ApplicationListAttributesPaging>,
    #[serde(rename = "authenticationEvents", default, skip_serializing_if = "Option::is_none")]
    pub authentication_events: Option<Vec<ApplicationListAuthenticationEventsItem>>,
    #[serde(rename = "authenticationEventsPaging", default, skip_serializing_if = "Option::is_none")]
    pub authentication_events_paging: Option<ApplicationListAuthenticationEventsPaging>,
    #[serde(rename = "authenticationEventsMatched", default, skip_serializing_if = "Option::is_none")]
    pub authentication_events_matched: Option<i64>,
    /// Which actors have a user page.
    #[serde(rename = "authenticationEventsKnownActors", default, skip_serializing_if = "Option::is_none")]
    pub authentication_events_known_actors: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "authenticationEventsLog", default, skip_serializing_if = "Option::is_none")]
    pub authentication_events_log: Option<ApplicationListAuthenticationEventsLog>,
    #[serde(rename = "returnAddressesObservedShown", default, skip_serializing_if = "Option::is_none")]
    pub return_addresses_observed_shown: Option<Vec<ApplicationListReturnAddressesObservedShownItem>>,
    #[serde(rename = "returnAddressesObservedPaging", default, skip_serializing_if = "Option::is_none")]
    pub return_addresses_observed_paging: Option<ApplicationListReturnAddressesObservedPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<ApplicationListCredentials>,
    #[serde(rename = "sharedSignals", default, skip_serializing_if = "Option::is_none")]
    pub shared_signals: Option<ApplicationListSharedSignals>,
    #[serde(rename = "certificateEnrollment", default, skip_serializing_if = "Option::is_none")]
    pub certificate_enrollment: Option<ApplicationListCertificateEnrollment>,
    #[serde(rename = "customClaims", default, skip_serializing_if = "Option::is_none")]
    pub custom_claims: Option<Vec<ApplicationListCustomClaimsItem>>,
    #[serde(rename = "claimSelections", default, skip_serializing_if = "Option::is_none")]
    pub claim_selections: Option<ApplicationListClaimSelections>,
    #[serde(rename = "tokenLifetimes", default, skip_serializing_if = "Option::is_none")]
    pub token_lifetimes: Option<ApplicationListTokenLifetimes>,
    #[serde(rename = "softwareStatements", default, skip_serializing_if = "Option::is_none")]
    pub software_statements: Option<ApplicationListSoftwareStatements>,
    #[serde(rename = "applicationRoles", default, skip_serializing_if = "Option::is_none")]
    pub application_roles: Option<ApplicationListApplicationRoles>,
    #[serde(rename = "delegatedPermissions", default, skip_serializing_if = "Option::is_none")]
    pub delegated_permissions: Option<ApplicationListDelegatedPermissions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owners: Option<Vec<ApplicationListOwnersItem>>,
    #[serde(rename = "maxOwners", default, skip_serializing_if = "Option::is_none")]
    pub max_owners: Option<f64>,
}

/// Derived from `action` and never set independently, so the two cannot
/// disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum AuditEventCategory {
    #[serde(rename = "authentication")]
    Authentication,
    #[serde(rename = "session")]
    Session,
    #[serde(rename = "directory")]
    Directory,
    #[serde(rename = "admin")]
    Admin,
    #[serde(rename = "api")]
    Api,
    #[serde(rename = "application")]
    Application,
    #[serde(rename = "protocol")]
    Protocol,
    #[serde(rename = "spiffe")]
    Spiffe,
    #[serde(rename = "signals")]
    Signals,
    #[serde(rename = "authorization")]
    Authorization,
    #[serde(rename = "service")]
    Service,
}

/// A `refused` is this service saying no and working; an `error` is this
/// service failing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum AuditEventOutcome {
    #[serde(rename = "success")]
    Success,
    #[serde(rename = "refused")]
    Refused,
    #[serde(rename = "error")]
    Error,
}

/// How it arrived. `http` the main port; `ldap` and `ldaps` the directory's
/// sockets; `kerberos` the KDC's TCP and UDP 88; `grpc` the SPIFFE Workload API
/// and SPIRE Server API; `tls` a client certificate presented to this service;
/// `console` an act taken on the admin console or `/admin-api` and recorded as
/// that act rather than as the HTTP call. `internal` is something this service
/// did on its own — the directory entry it seeds for somebody who authenticated
/// elsewhere — `none` a session that EXPIRED, which nothing sent, and empty a
/// row whose recording site named no channel. The client's address is
/// `address`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum AuditEventChannel {
    #[serde(rename = "http")]
    Http,
    #[serde(rename = "ldap")]
    Ldap,
    #[serde(rename = "ldaps")]
    Ldaps,
    #[serde(rename = "kerberos")]
    Kerberos,
    #[serde(rename = "grpc")]
    Grpc,
    #[serde(rename = "tls")]
    Tls,
    #[serde(rename = "console")]
    Console,
    #[serde(rename = "internal")]
    Internal,
    #[serde(rename = "none")]
    None,
    #[serde(rename = "")]
    Empty,
}

/// Flat facts about this event, at most twelve keys with each value trimmed.
/// What is in it depends on the action — a modify names the ATTRIBUTES it
/// changed and never their values, a search names how many entries came back,
/// an HTTP row names the route and the elapsed time.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AuditEventDetail {
    /// The members the schema does not name, which it allows.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// One thing that happened, with the facts of it and no credential of any kind.
/// Written out rather than left open because a caller filtering or alerting on
/// this list needs a name for every field.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AuditEvent {
    /// Unique across every process of the service and NEVER REUSED, including
    /// across a drop and a restart; rising within each process, not one order
    /// across them (#465). The stable name for an event — a row number would
    /// silently mean a different event as soon as the cap discarded anything.
    /// Resume reading by `at`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<i64>,
    /// The process that recorded the event, by its stable origin in the store;
    /// empty without a shared store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// When it happened, in milliseconds since the epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<i64>,
    /// Derived from `action` and never set independently, so the two cannot
    /// disagree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<AuditEventCategory>,
    /// What happened, from a fixed vocabulary the list's `actions` member
    /// enumerates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// A `refused` is this service saying no and working; an `error` is this
    /// service failing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<AuditEventOutcome>,
    /// Which failure condition this row is about — `STS-<SUBSYSTEM>-<NNNN>`,
    /// listed in docs/error-codes.md — or empty for a row that is not a
    /// failure. Every refused or failed request carries one. It is an
    /// operator's name for the condition and is never sent to the client whose
    /// request produced it.
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// The NORMALISED local name, so a row here and a row on /admin-api/users
    /// name the same person — `alice`, her `urn:uuid:<entryUUID>` subject and
    /// `alice@EXAMPLE.COM` are one identity. Empty where nothing named an
    /// actor, which an unauthenticated protocol call and an anonymous LDAP bind
    /// both are.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// The identity exactly as it was presented, when that differs from `actor`
    /// — a bind DN, a Kerberos principal, an X.509 subject. Both are carried
    /// because the collapse from one to the other is something an auditor has
    /// to be able to see rather than infer.
    #[serde(rename = "actorForm", default, skip_serializing_if = "Option::is_none")]
    pub actor_form: Option<String>,
    /// What it was done to: a DN, a request path, a session id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// The family, where one applies. Free text: the sixteen families here
    /// spell themselves differently in the places this is read from, and an
    /// enum would be a lookup table that silently drops the seventeenth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// How it arrived. `http` the main port; `ldap` and `ldaps` the directory's
    /// sockets; `kerberos` the KDC's TCP and UDP 88; `grpc` the SPIFFE Workload
    /// API and SPIRE Server API; `tls` a client certificate presented to this
    /// service; `console` an act taken on the admin console or `/admin-api` and
    /// recorded as that act rather than as the HTTP call. `internal` is
    /// something this service did on its own — the directory entry it seeds for
    /// somebody who authenticated elsewhere — `none` a session that EXPIRED,
    /// which nothing sent, and empty a row whose recording site named no
    /// channel. The client's address is `address`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<AuditEventChannel>,
    /// The client's IP address (2026-09-18): whoever sent the HTTP request,
    /// LDAP operation, Kerberos message or SPIRE Server API call this row came
    /// out of — an authentication, a refused sign-in, a consent, a sign-out.
    /// Resolved through `global.trustProxy` and `global.trustedProxies` (the
    /// right-most `X-Forwarded-For` hop that is not a named proxy) or a PROXY
    /// protocol header; behind a proxy with neither set, it is the proxy. Empty
    /// for something this service did on its own, or that arrived over a Unix
    /// socket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// One sentence, the same one the console shows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Flat facts about this event, at most twelve keys with each value
    /// trimmed. What is in it depends on the action — a modify names the
    /// ATTRIBUTES it changed and never their values, a search names how many
    /// entries came back, an HTTP row names the route and the elapsed time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<AuditEventDetail>,
    /// The members the schema does not name, which it allows.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditListFilter {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub category: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub action: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub outcome: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub actor: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub q: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub code: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub address: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditListCategoriesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditListActionsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditListEventsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub origin: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error_code: Option<Option<String>>,
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
    /// What this one kind of event recorded about its own act: several hundred
    /// call sites each name their members, and values are trimmed by
    /// `detailOf()`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

/// Which page of how many, and the query parameter that moves it.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditListPaging {
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
pub struct AuditListSettingsGroupsItemSettingsItemSelectAllOnlyWhileOnItem {
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
pub struct AuditListSettingsGroupsItemSettingsItemSelectAllAloneWhileOnItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(rename = "canBeOn", default, skip_serializing_if = "Option::is_none")]
    pub can_be_on: Option<bool>,
}

/// Present on an `ordered` setting whose select-all is narrowed by other
/// settings. `onlyWhileOn`: the values are selected only while that setting is
/// on. `aloneWhileOn`: while that setting is on, only the values are selected.
/// `canBeOn` is false where this mode never lets that setting be on.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditListSettingsGroupsItemSettingsItemSelectAll {
    #[serde(rename = "onlyWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub only_while_on: Option<Vec<AuditListSettingsGroupsItemSettingsItemSelectAllOnlyWhileOnItem>>,
    #[serde(rename = "aloneWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub alone_while_on: Option<Vec<AuditListSettingsGroupsItemSettingsItemSelectAllAloneWhileOnItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum AuditListSettingsGroupsItemSettingsItemValue {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

/// Where the effective value came from, highest first: this trust realm's own
/// value; a runtime override set through this API or the console; the setting's
/// own environment variable; a legacy variable (no row has one since #523); the
/// appconfig file CONFIG_FILE names; `env/defaults.js`, the DEFAULT appconfig
/// file that one is unioned on top of. `default` is reachable only for the
/// DERIVED settings, whose value is a function of a neighbouring setting: for
/// every other setting, no value anywhere stops this service from STARTING.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum AuditListSettingsGroupsItemSettingsItemSource {
    #[serde(rename = "realm")]
    Realm,
    #[serde(rename = "override")]
    Override,
    #[serde(rename = "env")]
    Env,
    #[serde(rename = "env-legacy")]
    EnvLegacy,
    #[serde(rename = "appconfig")]
    Appconfig,
    #[serde(rename = "defaults")]
    Defaults,
    #[serde(rename = "default")]
    Default,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum AuditListSettingsGroupsItemSettingsItemDefault {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

/// One setting: what it is, what it is set to, and where that came from.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditListSettingsGroupsItemSettingsItem {
    /// The dot path, which is BOTH the name every operation here takes and the
    /// path in the appconfig file. `oid4vci.batchSize` is
    /// `appconfig.oid4vci.batchSize`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The protocol it belongs to, and the console's section heading.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// What it does and why the default is the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// How a value posted for it is coerced and checked: one of `config.js`'s
    /// types (string, int, port, bool, csv, enum, color).
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    /// Present on `enum` settings only.
    #[serde(rename = "enumValues", default, skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
    /// Present on a `csv` setting whose entries must each be one of these;
    /// absent on an open list.
    #[serde(rename = "csvValues", default, skip_serializing_if = "Option::is_none")]
    pub csv_values: Option<Vec<String>>,
    /// Present, true, when a sensitive value here was replaced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    /// Present, true, on a `csv` setting whose order is a preference: the first
    /// value is the most preferred.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordered: Option<bool>,
    /// Present beside `csvValues` where the setting describes each value: the
    /// value mapped to one sentence.
    #[serde(rename = "csvValueNotes", default, skip_serializing_if = "Option::is_none")]
    pub csv_value_notes: Option<serde_json::Map<String, serde_json::Value>>,
    /// Present on an `ordered` setting whose select-all is narrowed by other
    /// settings. `onlyWhileOn`: the values are selected only while that setting
    /// is on. `aloneWhileOn`: while that setting is on, only the values are
    /// selected. `canBeOn` is false where this mode never lets that setting be
    /// on.
    #[serde(rename = "selectAll", default, skip_serializing_if = "Option::is_none")]
    pub select_all: Option<AuditListSettingsGroupsItemSettingsItemSelectAll>,
    /// The lowest value POST /config/set will take, on an int setting that
    /// declares one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    /// The highest value it will take.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    /// The value must be a MULTIPLE of this, counted from `min`. The four token
    /// lifetimes use 30.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    /// The effective value, coerced to its type: a number for int/port, a
    /// boolean for bool, an array of strings for csv.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<AuditListSettingsGroupsItemSettingsItemValue>>,
    /// The same value on one line: what the console shows in its input and what
    /// the environment variable would carry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Where the effective value came from, highest first: this trust realm's
    /// own value; a runtime override set through this API or the console; the
    /// setting's own environment variable; a legacy variable (no row has one
    /// since #523); the appconfig file CONFIG_FILE names; `env/defaults.js`,
    /// the DEFAULT appconfig file that one is unioned on top of. `default` is
    /// reachable only for the DERIVED settings, whose value is a function of a
    /// neighbouring setting: for every other setting, no value anywhere stops
    /// this service from STARTING.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<AuditListSettingsGroupsItemSettingsItemSource>,
    /// Whether POST /config/set will take it from the realm this answer was
    /// read in. False means either the value was consumed at startup or
    /// `editRefusal` is set. It is refused rather than accepted, because an
    /// accepted change that does nothing reads as having worked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<bool>,
    /// Why it is not editable, when the value was consumed at startup.
    #[serde(rename = "restartReason", default, skip_serializing_if = "Option::is_none")]
    pub restart_reason: Option<String>,
    /// Why this row cannot be edited from the realm the reader is in:
    /// `realms.maxCount` while a realm other than the default is ambient.
    /// Absent on every row of the default realm's answer.
    #[serde(rename = "editRefusal", default, skip_serializing_if = "Option::is_none")]
    pub edit_refusal: Option<String>,
    /// Its environment variable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    #[serde(rename = "appconfigPath", default, skip_serializing_if = "Option::is_none")]
    pub appconfig_path: Option<String>,
    /// The built-in default: the `dflt` column of `config.js`'s table, which
    /// `env/defaults.js` is GENERATED from. It is what the value WOULD be with
    /// nothing set anywhere.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default: Option<Option<AuditListSettingsGroupsItemSettingsItemDefault>>,
    /// Whether a trust realm may hold its own value for it.
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    /// Whether a runtime override is in force. Equal to `source ===
    /// "override"`, and reported separately so a caller can filter without
    /// matching a string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

/// One group's settings.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditListSettingsGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<AuditListSettingsGroupsItemSettingsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditListSettingsContext {
    #[serde(rename = "configFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub config_file: Option<Option<String>>,
    #[serde(rename = "defaultsFile", default, skip_serializing_if = "Option::is_none")]
    pub defaults_file: Option<String>,
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

/// The settings this page draws, described: the same rows GET /config returns,
/// filtered to the ones this page owns.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditListSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    /// In the order `config.js` declares them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<AuditListSettingsGroupsItem>>,
    #[serde(rename = "settingCount", default, skip_serializing_if = "Option::is_none")]
    pub setting_count: Option<i64>,
    /// How many of them can be changed while the service runs.
    #[serde(rename = "editableCount", default, skip_serializing_if = "Option::is_none")]
    pub editable_count: Option<i64>,
    /// The keys on this page with a runtime override in force.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<Vec<String>>,
    /// The operation that writes them.
    #[serde(rename = "setWith", default, skip_serializing_if = "Option::is_none")]
    pub set_with: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<AuditListSettingsContext>,
    /// A group drawn on another page as well, and those pages.
    #[serde(rename = "sharedWith", default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<serde_json::Map<String, serde_json::Value>>,
}

/// What happened here, newest first, filtered and paged. HISTORY where the rest
/// of this API is STATE. Resume by `at`, not by `seq` or by `page` (#465).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditList {
    /// Events currently in the log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<i64>,
    /// Events recorded since this process started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded: Option<i64>,
    /// Events discarded to stay under the cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dropped: Option<i64>,
    /// The cap: `audit.maxEvents`.
    #[serde(rename = "maxEvents", default, skip_serializing_if = "Option::is_none")]
    pub max_events: Option<f64>,
    /// Whether ordinary protocol endpoint calls are being recorded.
    #[serde(rename = "protocolCalls", default, skip_serializing_if = "Option::is_none")]
    pub protocol_calls: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<i64>,
    #[serde(rename = "oldestSeq", default, skip_serializing_if = "Option::is_none")]
    pub oldest_seq: Option<f64>,
    #[serde(rename = "newestSeq", default, skip_serializing_if = "Option::is_none")]
    pub newest_seq: Option<f64>,
    #[serde(rename = "byCategory", default, skip_serializing_if = "Option::is_none")]
    pub by_category: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "byOutcome", default, skip_serializing_if = "Option::is_none")]
    pub by_outcome: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "byAction", default, skip_serializing_if = "Option::is_none")]
    pub by_action: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<AuditListFilter>,
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
    pub categories: Option<Vec<AuditListCategoriesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<AuditListActionsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcomes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<AuditListEventsItem>>,
    /// Which page of how many, and the query parameter that moves it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<AuditListPaging>,
    /// The actors on this page that are people known here.
    #[serde(rename = "knownActors", default, skip_serializing_if = "Option::is_none")]
    pub known_actors: Option<serde_json::Map<String, serde_json::Value>>,
    /// The settings this page draws, described: the same rows GET /config
    /// returns, filtered to the ones this page owns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<AuditListSettings>,
    #[serde(rename = "verifiesCredentials", default, skip_serializing_if = "Option::is_none")]
    pub verifies_credentials: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persisted: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationServerListMembersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforces: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationServerListPaging {
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
pub struct AuthorizationServerListAuthorizationServersItemUrls {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorize: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationServerListAuthorizationServersItemDriftItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member: Option<String>,
    /// An RFC 8414 metadata member's value as the operator chose to publish it:
    /// any JSON, deliberately, including what no specification defines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published: Option<serde_json::Value>,
    /// An RFC 8414 metadata member's value as the operator chose to publish it:
    /// any JSON, deliberately, including what no specification defines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationServerListAuthorizationServersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The members this server overrides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overrides: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<Vec<String>>,
    #[serde(rename = "changedAt", default, skip_serializing_if = "Option::is_none")]
    pub changed_at: Option<String>,
    #[serde(rename = "memberCount", default, skip_serializing_if = "Option::is_none")]
    pub member_count: Option<i64>,
    #[serde(rename = "autoCreated", default, skip_serializing_if = "Option::is_none")]
    pub auto_created: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen: Option<f64>,
    #[serde(rename = "seenAt", default, skip_serializing_if = "Option::is_none")]
    pub seen_at: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub urls: Option<AuthorizationServerListAuthorizationServersItemUrls>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drift: Option<Vec<AuthorizationServerListAuthorizationServersItemDriftItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationServerListUrls {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorize: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationServerListDriftItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member: Option<String>,
    /// An RFC 8414 metadata member's value as the operator chose to publish it:
    /// any JSON, deliberately, including what no specification defines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published: Option<serde_json::Value>,
    /// An RFC 8414 metadata member's value as the operator chose to publish it:
    /// any JSON, deliberately, including what no specification defines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationServerList {
    #[serde(rename = "profileCount", default, skip_serializing_if = "Option::is_none")]
    pub profile_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<AuthorizationServerListMembersItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<AuthorizationServerListPaging>,
    #[serde(rename = "overrideTotal", default, skip_serializing_if = "Option::is_none")]
    pub override_total: Option<i64>,
    #[serde(rename = "driftTotal", default, skip_serializing_if = "Option::is_none")]
    pub drift_total: Option<i64>,
    #[serde(rename = "authorizationServers", default, skip_serializing_if = "Option::is_none")]
    pub authorization_servers: Option<Vec<AuthorizationServerListAuthorizationServersItem>>,
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
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The members this server overrides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overrides: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<Vec<String>>,
    #[serde(rename = "changedAt", default, skip_serializing_if = "Option::is_none")]
    pub changed_at: Option<String>,
    #[serde(rename = "memberCount", default, skip_serializing_if = "Option::is_none")]
    pub member_count: Option<i64>,
    #[serde(rename = "autoCreated", default, skip_serializing_if = "Option::is_none")]
    pub auto_created: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen: Option<f64>,
    #[serde(rename = "seenAt", default, skip_serializing_if = "Option::is_none")]
    pub seen_at: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub urls: Option<AuthorizationServerListUrls>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub found: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drift: Option<Vec<AuthorizationServerListDriftItem>>,
    /// The RFC 8414 document this server would publish: what this service
    /// builds, with the operator's overrides, whose values are any JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<serde_json::Value>,
    #[serde(rename = "memberGroups", default, skip_serializing_if = "Option::is_none")]
    pub member_groups: Option<Vec<String>>,
}

/// `pending` until it is accepted (`sent`: 200 or 204) or finally fails —
/// refused with 400, refused by the outbound policy, or out of attempts — as a
/// DEAD LETTER (`dead`), which is sent again only by `retry-backchannel`. A
/// sign-out answers BEFORE its deliveries are made, so its own reply says
/// `pending`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum BackchannelDeliveryState {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "sent")]
    Sent,
    #[serde(rename = "dead")]
    Dead,
}

/// A sign-out (any door, an account disabled included), an expiry, or a relying
/// party forgotten on a session that stays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum BackchannelDeliveryTrigger {
    #[serde(rename = "sign-out")]
    SignOut,
    #[serde(rename = "expiry")]
    Expiry,
    #[serde(rename = "forget")]
    Forget,
}

/// One OpenID Connect Back-Channel Logout 1.0 delivery: a signed (and, where
/// the client registered it, encrypted) Logout Token this service POSTs to a
/// relying party's registered backchannel_logout_uri when a session it was
/// issued an authorization response on ends. A row of a persisted, replicated
/// store — every node lists every node's — and the token itself is never in a
/// reply.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BackchannelDelivery {
    /// Derived from the session and the client, so the same delivery planned by
    /// two processes is one row. What `retry-backchannel` names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    /// The sign-on session whose end it reports — the Logout Token's `sid`.
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// The token's `aud`.
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    /// What the client registered as backchannel_logout_session_required. `sid`
    /// is sent either way.
    #[serde(rename = "sessionRequired", default, skip_serializing_if = "Option::is_none")]
    pub session_required: Option<bool>,
    /// `pending` until it is accepted (`sent`: 200 or 204) or finally fails —
    /// refused with 400, refused by the outbound policy, or out of attempts —
    /// as a DEAD LETTER (`dead`), which is sent again only by
    /// `retry-backchannel`. A sign-out answers BEFORE its deliveries are made,
    /// so its own reply says `pending`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<BackchannelDeliveryState>,
    /// 1, and one more for each operator retry; each generation is a new Logout
    /// Token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<i64>,
    /// Attempts recorded in this generation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempts: Option<i64>,
    /// An attempt is claimed and not yet recorded — being sent now, or by a
    /// process that died, in which case another takes it over when its lease
    /// lapses.
    #[serde(rename = "inFlight", default, skip_serializing_if = "Option::is_none")]
    pub in_flight: Option<bool>,
    /// The host and process that last claimed an attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    /// The last HTTP status, or 0 where none came back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<i64>,
    /// The STS-OAUTH-05xx code of the last failure.
    #[serde(rename = "errorCode", default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    /// Which door ended the session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    /// A sign-out (any door, an account disabled included), an expiry, or a
    /// relying party forgotten on a session that stays.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger: Option<BackchannelDeliveryTrigger>,
    /// The JWE alg and enc the token was encrypted with, or empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted: Option<String>,
    #[serde(rename = "queuedAt", default, skip_serializing_if = "Option::is_none")]
    pub queued_at: Option<String>,
    /// ISO 8601 while pending, else empty.
    #[serde(rename = "nextAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<String>,
    /// ISO 8601, or empty before the first.
    #[serde(rename = "lastAttemptAt", default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    /// ISO 8601, or empty while pending.
    #[serde(rename = "finishedAt", default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    /// The members the schema does not name, which it allows.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokeredUseValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configured: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentications: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<i64>,
    #[serde(rename = "lastUser", default, skip_serializing_if = "Option::is_none")]
    pub last_user: Option<String>,
    #[serde(rename = "lastSeen", default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepEventTypesItemMembersItem {
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
pub struct CaepEventTypesItem {
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
    pub members: Option<Vec<CaepEventTypesItemMembersItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,
    #[serde(rename = "subjectFormats", default, skip_serializing_if = "Option::is_none")]
    pub subject_formats: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprecated: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepSessionsItemAssurance {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(rename = "previousLevel", default, skip_serializing_if = "Option::is_none")]
    pub previous_level: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepSessionsItemRisk {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(rename = "previousLevel", default, skip_serializing_if = "Option::is_none")]
    pub previous_level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepSessionsItemCredentialsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(rename = "credentialType", default, skip_serializing_if = "Option::is_none")]
    pub credential_type: Option<String>,
    #[serde(rename = "changeType", default, skip_serializing_if = "Option::is_none")]
    pub change_type: Option<String>,
    #[serde(rename = "friendlyName", default, skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepSessionsItemEventsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(rename = "streamId", default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepSessionsItem {
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub sub: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub username: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub iss: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub protocol: Option<Option<String>>,
    #[serde(rename = "establishedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub established_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub updated_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub state: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub acr: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assurance: Option<CaepSessionsItemAssurance>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub compliance: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<CaepSessionsItemRisk>,
    /// The claims a `token-claims-change` event said changed: whichever a
    /// person configured or an emitter named.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Vec<CaepSessionsItemCredentialsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<CaepSessionsItemEventsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepApplicationsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<Vec<String>>,
    #[serde(rename = "streamCount", default, skip_serializing_if = "Option::is_none")]
    pub stream_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deliveries: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audiences: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub takes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accounts: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledged: Option<i64>,
    #[serde(rename = "receiverErrors", default, skip_serializing_if = "Option::is_none")]
    pub receiver_errors: Option<i64>,
    #[serde(rename = "lastPushAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_push_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "lastPushError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_push_error: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum CaepStreamsItemAud {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepStreamsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub aud: Option<Option<CaepStreamsItemAud>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subjects: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub takes: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepCatalogueItemMembersItem {
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
pub struct CaepCatalogueItem {
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
    pub members: Option<Vec<CaepCatalogueItemMembersItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,
    #[serde(rename = "subjectFormats", default, skip_serializing_if = "Option::is_none")]
    pub subject_formats: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprecated: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepSettingsGroupsItemSettingsItemSelectAllOnlyWhileOnItem {
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
pub struct CaepSettingsGroupsItemSettingsItemSelectAllAloneWhileOnItem {
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
pub struct CaepSettingsGroupsItemSettingsItemSelectAll {
    #[serde(rename = "onlyWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub only_while_on: Option<Vec<CaepSettingsGroupsItemSettingsItemSelectAllOnlyWhileOnItem>>,
    #[serde(rename = "aloneWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub alone_while_on: Option<Vec<CaepSettingsGroupsItemSettingsItemSelectAllAloneWhileOnItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum CaepSettingsGroupsItemSettingsItemValue {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum CaepSettingsGroupsItemSettingsItemEnv {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum CaepSettingsGroupsItemSettingsItemLegacyEnv {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum CaepSettingsGroupsItemSettingsItemDefault {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepSettingsGroupsItemSettingsItem {
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
    pub select_all: Option<CaepSettingsGroupsItemSettingsItemSelectAll>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<CaepSettingsGroupsItemSettingsItemValue>>,
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
    pub env: Option<CaepSettingsGroupsItemSettingsItemEnv>,
    #[serde(rename = "legacyEnv", default, skip_serializing_if = "Option::is_none")]
    pub legacy_env: Option<CaepSettingsGroupsItemSettingsItemLegacyEnv>,
    #[serde(rename = "appconfigPath", default, skip_serializing_if = "Option::is_none")]
    pub appconfig_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default: Option<Option<CaepSettingsGroupsItemSettingsItemDefault>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepSettingsGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<CaepSettingsGroupsItemSettingsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepSettingsContext {
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
pub struct CaepSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<CaepSettingsGroupsItem>>,
    #[serde(rename = "settingCount", default, skip_serializing_if = "Option::is_none")]
    pub setting_count: Option<i64>,
    #[serde(rename = "editableCount", default, skip_serializing_if = "Option::is_none")]
    pub editable_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<Vec<String>>,
    #[serde(rename = "setWith", default, skip_serializing_if = "Option::is_none")]
    pub set_with: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<CaepSettingsContext>,
    #[serde(rename = "sharedWith", default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepFilter {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub sessions: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub applications: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepPagingSessions {
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
pub struct CaepPagingApplications {
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
pub struct CaepPagingStreams {
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
pub struct CaepPagingEvents {
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
pub struct CaepPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<CaepPagingSessions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applications: Option<CaepPagingApplications>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<CaepPagingStreams>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<CaepPagingEvents>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepShownSessionsItemAssurance {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(rename = "previousLevel", default, skip_serializing_if = "Option::is_none")]
    pub previous_level: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepShownSessionsItemRisk {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(rename = "previousLevel", default, skip_serializing_if = "Option::is_none")]
    pub previous_level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepShownSessionsItemCredentialsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(rename = "credentialType", default, skip_serializing_if = "Option::is_none")]
    pub credential_type: Option<String>,
    #[serde(rename = "changeType", default, skip_serializing_if = "Option::is_none")]
    pub change_type: Option<String>,
    #[serde(rename = "friendlyName", default, skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepShownSessionsItemEventsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(rename = "streamId", default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepShownSessionsItem {
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub sub: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub username: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub iss: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub protocol: Option<Option<String>>,
    #[serde(rename = "establishedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub established_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub updated_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub state: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub acr: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assurance: Option<CaepShownSessionsItemAssurance>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub compliance: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<CaepShownSessionsItemRisk>,
    /// The claims a `token-claims-change` event said changed: whichever a
    /// person configured or an emitter named.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Vec<CaepShownSessionsItemCredentialsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<CaepShownSessionsItemEventsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepShownApplicationsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<Vec<String>>,
    #[serde(rename = "streamCount", default, skip_serializing_if = "Option::is_none")]
    pub stream_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deliveries: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audiences: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub takes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accounts: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledged: Option<i64>,
    #[serde(rename = "receiverErrors", default, skip_serializing_if = "Option::is_none")]
    pub receiver_errors: Option<i64>,
    #[serde(rename = "lastPushAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_push_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "lastPushError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_push_error: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum CaepShownStreamsItemAud {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepShownStreamsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub aud: Option<Option<CaepShownStreamsItemAud>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subjects: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub takes: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepShown {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<Vec<CaepShownSessionsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applications: Option<Vec<CaepShownApplicationsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<Vec<CaepShownStreamsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepMatched {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applications: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepStreamCounts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taking: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepSessionAssurance {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(rename = "previousLevel", default, skip_serializing_if = "Option::is_none")]
    pub previous_level: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepSessionRisk {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(rename = "previousLevel", default, skip_serializing_if = "Option::is_none")]
    pub previous_level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepSessionCredentialsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(rename = "credentialType", default, skip_serializing_if = "Option::is_none")]
    pub credential_type: Option<String>,
    #[serde(rename = "changeType", default, skip_serializing_if = "Option::is_none")]
    pub change_type: Option<String>,
    #[serde(rename = "friendlyName", default, skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepSessionEventsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(rename = "streamId", default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepSession {
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub sub: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub username: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub iss: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub protocol: Option<Option<String>>,
    #[serde(rename = "establishedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub established_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub updated_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub state: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub acr: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assurance: Option<CaepSessionAssurance>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub compliance: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<CaepSessionRisk>,
    /// The claims a `token-claims-change` event said changed: whichever a
    /// person configured or an emitter named.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Vec<CaepSessionCredentialsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<CaepSessionEventsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepEventsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(rename = "streamId", default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Caep {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(rename = "autoEmit", default, skip_serializing_if = "Option::is_none")]
    pub auto_emit: Option<bool>,
    #[serde(rename = "autoEmitActs", default, skip_serializing_if = "Option::is_none")]
    pub auto_emit_acts: Option<Vec<String>>,
    #[serde(rename = "omitEventTimestamp", default, skip_serializing_if = "Option::is_none")]
    pub omit_event_timestamp: Option<bool>,
    #[serde(rename = "eventTypes", default, skip_serializing_if = "Option::is_none")]
    pub event_types: Option<Vec<CaepEventTypesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totals: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<Vec<CaepSessionsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracked: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(rename = "ssfEnabled", default, skip_serializing_if = "Option::is_none")]
    pub ssf_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applications: Option<Vec<CaepApplicationsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<Vec<CaepStreamsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalogue: Option<Vec<CaepCatalogueItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<CaepSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<CaepFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<CaepPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<CaepShown>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<CaepMatched>,
    #[serde(rename = "streamCounts", default, skip_serializing_if = "Option::is_none")]
    pub stream_counts: Option<CaepStreamCounts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<CaepSession>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<CaepEventsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaepApplication {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<Vec<String>>,
    #[serde(rename = "streamCount", default, skip_serializing_if = "Option::is_none")]
    pub stream_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deliveries: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audiences: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub takes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accounts: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledged: Option<i64>,
    #[serde(rename = "receiverErrors", default, skip_serializing_if = "Option::is_none")]
    pub receiver_errors: Option<i64>,
    #[serde(rename = "lastPushAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_push_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "lastPushError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_push_error: Option<Option<String>>,
}

/// An attribute claim in a JWT or UserInfo set: the JSON type each value
/// becomes (string, number, boolean, json). A value that is not one is left
/// out. Ignored by the SAML sets. In the Kerberos PAC set (#493) EVERY row has
/// one, of string, int64, uint64 and boolean — the PAC claim type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ClaimEntryType {
    #[serde(rename = "string")]
    String,
    #[serde(rename = "number")]
    Number,
    #[serde(rename = "boolean")]
    Boolean,
    #[serde(rename = "json")]
    Json,
    #[serde(rename = "int64")]
    Int64,
    #[serde(rename = "uint64")]
    Uint64,
}

/// One custom claim. `nameFormat` applies to the SAML 2.0 set and `namespace`
/// to the SAML 1.1 set; both are ignored by the two JWT sets.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimEntry {
    pub name: String,
    /// May carry a placeholder such as ${username}; `GET /admin-api/claims`
    /// lists the ones this service expands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(rename = "nameFormat", default, skip_serializing_if = "Option::is_none")]
    pub name_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// AN ATTRIBUTE CLAIM (#94), in place of `value`: the directory attribute
    /// of the person the artifact is about that the claim carries. Only the
    /// directory, never an invented value; absent on the entry, the claim is
    /// absent. A secret, a binary value or an attribute this service keeps
    /// (sts*, hoba*, app*, pwd*) is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    /// An attribute claim: every value (a JSON array; several AttributeValues)
    /// rather than the first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multi: Option<bool>,
    /// An attribute claim in a JWT or UserInfo set: the JSON type each value
    /// becomes (string, number, boolean, json). A value that is not one is left
    /// out. Ignored by the SAML sets. In the Kerberos PAC set (#493) EVERY row
    /// has one, of string, int64, uint64 and boolean — the PAC claim type.
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<ClaimEntryType>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimSetsAttributeCatalogueItem {
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
pub struct ClaimSetsSetsItemClaimsItem {
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
pub struct ClaimSetsSetsItemAttributeReportItem {
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
pub struct ClaimSetsSetsItemAttributeClaimPreviewItem {
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
pub struct ClaimSetsSetsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<ClaimSetsSetsItemClaimsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<String>>,
    /// The claims one person would be issued, keyed and nested by the claim
    /// names the catalogue and an administrator chose.
    #[serde(rename = "attributeClaims", default, skip_serializing_if = "Option::is_none")]
    pub attribute_claims: Option<serde_json::Value>,
    #[serde(rename = "attributeReport", default, skip_serializing_if = "Option::is_none")]
    pub attribute_report: Option<Vec<ClaimSetsSetsItemAttributeReportItem>>,
    #[serde(rename = "attributeClaimPreview", default, skip_serializing_if = "Option::is_none")]
    pub attribute_claim_preview: Option<Vec<ClaimSetsSetsItemAttributeClaimPreviewItem>>,
    /// Partners withholding it, by claim.
    #[serde(rename = "withheldFrom", default, skip_serializing_if = "Option::is_none")]
    pub withheld_from: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimSetsAttributeChoicesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimSetsPreview {
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
pub struct ClaimSetsGroupsPreviewGroupsItem {
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
pub struct ClaimSetsGroupsPreview {
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
    pub groups: Option<Vec<ClaimSetsGroupsPreviewGroupsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimSetsGroups {
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
    pub preview: Option<ClaimSetsGroupsPreview>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimSetsWithholdingItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimSets {
    #[serde(rename = "reservedJwtClaims", default, skip_serializing_if = "Option::is_none")]
    pub reserved_jwt_claims: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholders: Option<Vec<String>>,
    #[serde(rename = "attributeCatalogue", default, skip_serializing_if = "Option::is_none")]
    pub attribute_catalogue: Option<Vec<ClaimSetsAttributeCatalogueItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sets: Option<Vec<ClaimSetsSetsItem>>,
    #[serde(rename = "attributeChoices", default, skip_serializing_if = "Option::is_none")]
    pub attribute_choices: Option<Vec<ClaimSetsAttributeChoicesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<ClaimSetsPreview>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<ClaimSetsGroups>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withholding: Option<Vec<ClaimSetsWithholdingItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigGroupsItemSettingsItemSelectAllOnlyWhileOnItem {
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
pub struct ConfigGroupsItemSettingsItemSelectAllAloneWhileOnItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(rename = "canBeOn", default, skip_serializing_if = "Option::is_none")]
    pub can_be_on: Option<bool>,
}

/// Present on an `ordered` setting whose select-all is narrowed by other
/// settings. `onlyWhileOn`: the values are selected only while that setting is
/// on. `aloneWhileOn`: while that setting is on, only the values are selected.
/// `canBeOn` is false where this mode never lets that setting be on.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigGroupsItemSettingsItemSelectAll {
    #[serde(rename = "onlyWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub only_while_on: Option<Vec<ConfigGroupsItemSettingsItemSelectAllOnlyWhileOnItem>>,
    #[serde(rename = "aloneWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub alone_while_on: Option<Vec<ConfigGroupsItemSettingsItemSelectAllAloneWhileOnItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ConfigGroupsItemSettingsItemValue {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

/// Where the effective value came from, highest first: this trust realm's own
/// value; a runtime override set through this API or the console; the setting's
/// own environment variable; a legacy variable (no row has one since #523); the
/// appconfig file CONFIG_FILE names; `env/defaults.js`, the DEFAULT appconfig
/// file that one is unioned on top of. `default` is reachable only for the
/// DERIVED settings, whose value is a function of a neighbouring setting: for
/// every other setting, no value anywhere stops this service from STARTING.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ConfigGroupsItemSettingsItemSource {
    #[serde(rename = "realm")]
    Realm,
    #[serde(rename = "override")]
    Override,
    #[serde(rename = "env")]
    Env,
    #[serde(rename = "env-legacy")]
    EnvLegacy,
    #[serde(rename = "appconfig")]
    Appconfig,
    #[serde(rename = "defaults")]
    Defaults,
    #[serde(rename = "default")]
    Default,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ConfigGroupsItemSettingsItemDefault {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

/// One setting: what it is, what it is set to, and where that came from.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigGroupsItemSettingsItem {
    /// The dot path, which is BOTH the name every operation here takes and the
    /// path in the appconfig file. `oid4vci.batchSize` is
    /// `appconfig.oid4vci.batchSize`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The protocol it belongs to, and the console's section heading.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// What it does and why the default is the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// How a value posted for it is coerced and checked: one of `config.js`'s
    /// types (string, int, port, bool, csv, enum, color).
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    /// Present on `enum` settings only.
    #[serde(rename = "enumValues", default, skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
    /// Present on a `csv` setting whose entries must each be one of these;
    /// absent on an open list.
    #[serde(rename = "csvValues", default, skip_serializing_if = "Option::is_none")]
    pub csv_values: Option<Vec<String>>,
    /// Present, true, when a sensitive value here was replaced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    /// Present, true, on a `csv` setting whose order is a preference: the first
    /// value is the most preferred.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordered: Option<bool>,
    /// Present beside `csvValues` where the setting describes each value: the
    /// value mapped to one sentence.
    #[serde(rename = "csvValueNotes", default, skip_serializing_if = "Option::is_none")]
    pub csv_value_notes: Option<serde_json::Map<String, serde_json::Value>>,
    /// Present on an `ordered` setting whose select-all is narrowed by other
    /// settings. `onlyWhileOn`: the values are selected only while that setting
    /// is on. `aloneWhileOn`: while that setting is on, only the values are
    /// selected. `canBeOn` is false where this mode never lets that setting be
    /// on.
    #[serde(rename = "selectAll", default, skip_serializing_if = "Option::is_none")]
    pub select_all: Option<ConfigGroupsItemSettingsItemSelectAll>,
    /// The lowest value POST /config/set will take, on an int setting that
    /// declares one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    /// The highest value it will take.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    /// The value must be a MULTIPLE of this, counted from `min`. The four token
    /// lifetimes use 30.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    /// The effective value, coerced to its type: a number for int/port, a
    /// boolean for bool, an array of strings for csv.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<ConfigGroupsItemSettingsItemValue>>,
    /// The same value on one line: what the console shows in its input and what
    /// the environment variable would carry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Where the effective value came from, highest first: this trust realm's
    /// own value; a runtime override set through this API or the console; the
    /// setting's own environment variable; a legacy variable (no row has one
    /// since #523); the appconfig file CONFIG_FILE names; `env/defaults.js`,
    /// the DEFAULT appconfig file that one is unioned on top of. `default` is
    /// reachable only for the DERIVED settings, whose value is a function of a
    /// neighbouring setting: for every other setting, no value anywhere stops
    /// this service from STARTING.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<ConfigGroupsItemSettingsItemSource>,
    /// Whether POST /config/set will take it from the realm this answer was
    /// read in. False means either the value was consumed at startup or
    /// `editRefusal` is set. It is refused rather than accepted, because an
    /// accepted change that does nothing reads as having worked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<bool>,
    /// Why it is not editable, when the value was consumed at startup.
    #[serde(rename = "restartReason", default, skip_serializing_if = "Option::is_none")]
    pub restart_reason: Option<String>,
    /// Why this row cannot be edited from the realm the reader is in:
    /// `realms.maxCount` while a realm other than the default is ambient.
    /// Absent on every row of the default realm's answer.
    #[serde(rename = "editRefusal", default, skip_serializing_if = "Option::is_none")]
    pub edit_refusal: Option<String>,
    /// Its environment variable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    #[serde(rename = "appconfigPath", default, skip_serializing_if = "Option::is_none")]
    pub appconfig_path: Option<String>,
    /// The built-in default: the `dflt` column of `config.js`'s table, which
    /// `env/defaults.js` is GENERATED from. It is what the value WOULD be with
    /// nothing set anywhere.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default: Option<Option<ConfigGroupsItemSettingsItemDefault>>,
    /// Whether a trust realm may hold its own value for it.
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    /// Whether a runtime override is in force. Equal to `source ===
    /// "override"`, and reported separately so a caller can filter without
    /// matching a string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

/// One group's settings.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<ConfigGroupsItemSettingsItem>>,
}

/// One group, and the page or pages that draw it.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigHomesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<Vec<String>>,
    /// The pages' console labels, in the same order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigSettingsGroupsItemSettingsItemSelectAllOnlyWhileOnItem {
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
pub struct ConfigSettingsGroupsItemSettingsItemSelectAllAloneWhileOnItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(rename = "canBeOn", default, skip_serializing_if = "Option::is_none")]
    pub can_be_on: Option<bool>,
}

/// Present on an `ordered` setting whose select-all is narrowed by other
/// settings. `onlyWhileOn`: the values are selected only while that setting is
/// on. `aloneWhileOn`: while that setting is on, only the values are selected.
/// `canBeOn` is false where this mode never lets that setting be on.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigSettingsGroupsItemSettingsItemSelectAll {
    #[serde(rename = "onlyWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub only_while_on: Option<Vec<ConfigSettingsGroupsItemSettingsItemSelectAllOnlyWhileOnItem>>,
    #[serde(rename = "aloneWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub alone_while_on: Option<Vec<ConfigSettingsGroupsItemSettingsItemSelectAllAloneWhileOnItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ConfigSettingsGroupsItemSettingsItemValue {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

/// Where the effective value came from, highest first: this trust realm's own
/// value; a runtime override set through this API or the console; the setting's
/// own environment variable; a legacy variable (no row has one since #523); the
/// appconfig file CONFIG_FILE names; `env/defaults.js`, the DEFAULT appconfig
/// file that one is unioned on top of. `default` is reachable only for the
/// DERIVED settings, whose value is a function of a neighbouring setting: for
/// every other setting, no value anywhere stops this service from STARTING.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ConfigSettingsGroupsItemSettingsItemSource {
    #[serde(rename = "realm")]
    Realm,
    #[serde(rename = "override")]
    Override,
    #[serde(rename = "env")]
    Env,
    #[serde(rename = "env-legacy")]
    EnvLegacy,
    #[serde(rename = "appconfig")]
    Appconfig,
    #[serde(rename = "defaults")]
    Defaults,
    #[serde(rename = "default")]
    Default,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ConfigSettingsGroupsItemSettingsItemDefault {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

/// One setting: what it is, what it is set to, and where that came from.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigSettingsGroupsItemSettingsItem {
    /// The dot path, which is BOTH the name every operation here takes and the
    /// path in the appconfig file. `oid4vci.batchSize` is
    /// `appconfig.oid4vci.batchSize`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The protocol it belongs to, and the console's section heading.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// What it does and why the default is the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// How a value posted for it is coerced and checked: one of `config.js`'s
    /// types (string, int, port, bool, csv, enum, color).
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    /// Present on `enum` settings only.
    #[serde(rename = "enumValues", default, skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
    /// Present on a `csv` setting whose entries must each be one of these;
    /// absent on an open list.
    #[serde(rename = "csvValues", default, skip_serializing_if = "Option::is_none")]
    pub csv_values: Option<Vec<String>>,
    /// Present, true, when a sensitive value here was replaced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    /// Present, true, on a `csv` setting whose order is a preference: the first
    /// value is the most preferred.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordered: Option<bool>,
    /// Present beside `csvValues` where the setting describes each value: the
    /// value mapped to one sentence.
    #[serde(rename = "csvValueNotes", default, skip_serializing_if = "Option::is_none")]
    pub csv_value_notes: Option<serde_json::Map<String, serde_json::Value>>,
    /// Present on an `ordered` setting whose select-all is narrowed by other
    /// settings. `onlyWhileOn`: the values are selected only while that setting
    /// is on. `aloneWhileOn`: while that setting is on, only the values are
    /// selected. `canBeOn` is false where this mode never lets that setting be
    /// on.
    #[serde(rename = "selectAll", default, skip_serializing_if = "Option::is_none")]
    pub select_all: Option<ConfigSettingsGroupsItemSettingsItemSelectAll>,
    /// The lowest value POST /config/set will take, on an int setting that
    /// declares one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    /// The highest value it will take.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    /// The value must be a MULTIPLE of this, counted from `min`. The four token
    /// lifetimes use 30.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    /// The effective value, coerced to its type: a number for int/port, a
    /// boolean for bool, an array of strings for csv.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<ConfigSettingsGroupsItemSettingsItemValue>>,
    /// The same value on one line: what the console shows in its input and what
    /// the environment variable would carry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Where the effective value came from, highest first: this trust realm's
    /// own value; a runtime override set through this API or the console; the
    /// setting's own environment variable; a legacy variable (no row has one
    /// since #523); the appconfig file CONFIG_FILE names; `env/defaults.js`,
    /// the DEFAULT appconfig file that one is unioned on top of. `default` is
    /// reachable only for the DERIVED settings, whose value is a function of a
    /// neighbouring setting: for every other setting, no value anywhere stops
    /// this service from STARTING.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<ConfigSettingsGroupsItemSettingsItemSource>,
    /// Whether POST /config/set will take it from the realm this answer was
    /// read in. False means either the value was consumed at startup or
    /// `editRefusal` is set. It is refused rather than accepted, because an
    /// accepted change that does nothing reads as having worked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<bool>,
    /// Why it is not editable, when the value was consumed at startup.
    #[serde(rename = "restartReason", default, skip_serializing_if = "Option::is_none")]
    pub restart_reason: Option<String>,
    /// Why this row cannot be edited from the realm the reader is in:
    /// `realms.maxCount` while a realm other than the default is ambient.
    /// Absent on every row of the default realm's answer.
    #[serde(rename = "editRefusal", default, skip_serializing_if = "Option::is_none")]
    pub edit_refusal: Option<String>,
    /// Its environment variable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    #[serde(rename = "appconfigPath", default, skip_serializing_if = "Option::is_none")]
    pub appconfig_path: Option<String>,
    /// The built-in default: the `dflt` column of `config.js`'s table, which
    /// `env/defaults.js` is GENERATED from. It is what the value WOULD be with
    /// nothing set anywhere.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default: Option<Option<ConfigSettingsGroupsItemSettingsItemDefault>>,
    /// Whether a trust realm may hold its own value for it.
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    /// Whether a runtime override is in force. Equal to `source ===
    /// "override"`, and reported separately so a caller can filter without
    /// matching a string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

/// One group's settings.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigSettingsGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<ConfigSettingsGroupsItemSettingsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigSettingsContext {
    #[serde(rename = "configFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub config_file: Option<Option<String>>,
    #[serde(rename = "defaultsFile", default, skip_serializing_if = "Option::is_none")]
    pub defaults_file: Option<String>,
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

/// The settings this page draws, described: the same rows GET /config returns,
/// filtered to the ones this page owns.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    /// In the order `config.js` declares them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<ConfigSettingsGroupsItem>>,
    #[serde(rename = "settingCount", default, skip_serializing_if = "Option::is_none")]
    pub setting_count: Option<i64>,
    /// How many of them can be changed while the service runs.
    #[serde(rename = "editableCount", default, skip_serializing_if = "Option::is_none")]
    pub editable_count: Option<i64>,
    /// The keys on this page with a runtime override in force.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<Vec<String>>,
    /// The operation that writes them.
    #[serde(rename = "setWith", default, skip_serializing_if = "Option::is_none")]
    pub set_with: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<ConfigSettingsContext>,
    /// A group drawn on another page as well, and those pages.
    #[serde(rename = "sharedWith", default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<serde_json::Map<String, serde_json::Value>>,
}

/// Every setting this service has, grouped by the protocol it belongs to. The
/// same table the /admin/config page renders and the same call it makes, so the
/// console and this API cannot come to describe different sets of settings.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The realm this was read in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    /// The keys that realm holds a value of its own for.
    #[serde(rename = "realmSettings", default, skip_serializing_if = "Option::is_none")]
    pub realm_settings: Option<Vec<String>>,
    /// The CONFIG_FILE this process was started with, which is the file to edit
    /// to make a change survive a restart. Nothing here ever writes to it.
    #[serde(rename = "configFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub config_file: Option<Option<String>>,
    /// The DEFAULT appconfig file, which `configFile` is unioned on top of key
    /// by key with the operator's value winning. A setting whose `source` is
    /// `defaults` came from here.
    #[serde(rename = "defaultsFile", default, skip_serializing_if = "Option::is_none")]
    pub defaults_file: Option<String>,
    #[serde(rename = "settingCount", default, skip_serializing_if = "Option::is_none")]
    pub setting_count: Option<i64>,
    /// How many of them POST /config/set will take. The rest are restart-only
    /// and say why in `restartReason`.
    #[serde(rename = "editableCount", default, skip_serializing_if = "Option::is_none")]
    pub editable_count: Option<i64>,
    /// The keys with a runtime override in force. Empty on a freshly started
    /// service, and emptied again by POST /config/reset-all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<Vec<String>>,
    /// In the order `config.js` declares them, which is the order the console
    /// renders its sections.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<ConfigGroupsItem>>,
    /// WHERE EACH GROUP IS EDITED: every group is drawn on the console page for
    /// the protocol it configures, so a caller can send a person to the right
    /// page. Every one of those forms posts to the same four actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homes: Option<Vec<ConfigHomesItem>>,
    /// Empty, and reported rather than left implicit. A sentence here means a
    /// setting group exists that no console page draws.
    #[serde(rename = "homeProblems", default, skip_serializing_if = "Option::is_none")]
    pub home_problems: Option<Vec<String>>,
    /// The settings this page draws, described: the same rows GET /config
    /// returns, filtered to the ones this page owns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<ConfigSettings>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum CredentialClaimsAttributesItemExampleValue {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialClaimsAttributesItemExample {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<CredentialClaimsAttributesItemExampleValue>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialClaimsAttributesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldap: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(rename = "ldpTerm", default, skip_serializing_if = "Option::is_none")]
    pub ldp_term: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example: Option<CredentialClaimsAttributesItemExample>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum CredentialClaimsProtocolEndpointsItemMethods {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialClaimsProtocolEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<CredentialClaimsProtocolEndpointsItemMethods>,
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
pub enum CredentialClaimsPreviewClaimsReportItemValue {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialClaimsPreviewClaimsReportItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldap: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<CredentialClaimsPreviewClaimsReportItemValue>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "ldpTerm", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ldp_term: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialClaimsPreviewClaims {
    /// The credential subject's claims.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<Vec<CredentialClaimsPreviewClaimsReportItem>>,
    #[serde(rename = "entryFound", default, skip_serializing_if = "Option::is_none")]
    pub entry_found: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialClaimsPreview {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<CredentialClaimsPreviewClaims>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialClaims {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub defaults: Option<Vec<String>>,
    #[serde(rename = "ldpOmitted", default, skip_serializing_if = "Option::is_none")]
    pub ldp_omitted: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<CredentialClaimsAttributesItem>>,
    #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
    pub protocol_endpoints: Option<Vec<CredentialClaimsProtocolEndpointsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<CredentialClaimsPreview>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataSignaturePolicySurfacesJoseRowsItem {
    /// The algorithm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Its name on this surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spelling: Option<String>,
    /// pq or composite, or empty for a classical algorithm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weak: Option<bool>,
    /// Whether this realm signs with it now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signs: Option<bool>,
    /// Why not, or empty.
    #[serde(rename = "signRefusal", default, skip_serializing_if = "Option::is_none")]
    pub sign_refusal: Option<String>,
    /// Whether this realm accepts it now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepts: Option<bool>,
    /// Why not, or empty.
    #[serde(rename = "acceptRefusal", default, skip_serializing_if = "Option::is_none")]
    pub accept_refusal: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataSignaturePolicySurfacesJose {
    /// The setting holding what this surface signs with.
    #[serde(rename = "signSetting", default, skip_serializing_if = "Option::is_none")]
    pub sign_setting: Option<String>,
    /// The setting holding what this surface accepts.
    #[serde(rename = "acceptSetting", default, skip_serializing_if = "Option::is_none")]
    pub accept_setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<CryptoMetadataSignaturePolicySurfacesJoseRowsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataSignaturePolicySurfacesHttpsigRowsItem {
    /// The algorithm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Its name on this surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spelling: Option<String>,
    /// pq or composite, or empty for a classical algorithm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weak: Option<bool>,
    /// Whether this realm signs with it now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signs: Option<bool>,
    /// Why not, or empty.
    #[serde(rename = "signRefusal", default, skip_serializing_if = "Option::is_none")]
    pub sign_refusal: Option<String>,
    /// Whether this realm accepts it now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepts: Option<bool>,
    /// Why not, or empty.
    #[serde(rename = "acceptRefusal", default, skip_serializing_if = "Option::is_none")]
    pub accept_refusal: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataSignaturePolicySurfacesHttpsig {
    /// The setting holding what this surface signs with.
    #[serde(rename = "signSetting", default, skip_serializing_if = "Option::is_none")]
    pub sign_setting: Option<String>,
    /// The setting holding what this surface accepts.
    #[serde(rename = "acceptSetting", default, skip_serializing_if = "Option::is_none")]
    pub accept_setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<CryptoMetadataSignaturePolicySurfacesHttpsigRowsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataSignaturePolicySurfacesCoseRowsItem {
    /// The algorithm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Its name on this surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spelling: Option<String>,
    /// pq or composite, or empty for a classical algorithm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weak: Option<bool>,
    /// Whether this realm signs with it now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signs: Option<bool>,
    /// Why not, or empty.
    #[serde(rename = "signRefusal", default, skip_serializing_if = "Option::is_none")]
    pub sign_refusal: Option<String>,
    /// Whether this realm accepts it now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepts: Option<bool>,
    /// Why not, or empty.
    #[serde(rename = "acceptRefusal", default, skip_serializing_if = "Option::is_none")]
    pub accept_refusal: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataSignaturePolicySurfacesCose {
    /// The setting holding what this surface signs with.
    #[serde(rename = "signSetting", default, skip_serializing_if = "Option::is_none")]
    pub sign_setting: Option<String>,
    /// The setting holding what this surface accepts.
    #[serde(rename = "acceptSetting", default, skip_serializing_if = "Option::is_none")]
    pub accept_setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<CryptoMetadataSignaturePolicySurfacesCoseRowsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataSignaturePolicySurfacesXmlRowsItem {
    /// The algorithm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Its name on this surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spelling: Option<String>,
    /// pq or composite, or empty for a classical algorithm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weak: Option<bool>,
    /// Whether this realm signs with it now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signs: Option<bool>,
    /// Why not, or empty.
    #[serde(rename = "signRefusal", default, skip_serializing_if = "Option::is_none")]
    pub sign_refusal: Option<String>,
    /// Whether this realm accepts it now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepts: Option<bool>,
    /// Why not, or empty.
    #[serde(rename = "acceptRefusal", default, skip_serializing_if = "Option::is_none")]
    pub accept_refusal: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataSignaturePolicySurfacesXml {
    /// The setting holding what this surface signs with.
    #[serde(rename = "signSetting", default, skip_serializing_if = "Option::is_none")]
    pub sign_setting: Option<String>,
    /// The setting holding what this surface accepts.
    #[serde(rename = "acceptSetting", default, skip_serializing_if = "Option::is_none")]
    pub accept_setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<CryptoMetadataSignaturePolicySurfacesXmlRowsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataSignaturePolicySurfacesDiRowsItem {
    /// The algorithm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Its name on this surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spelling: Option<String>,
    /// pq or composite, or empty for a classical algorithm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weak: Option<bool>,
    /// Whether this realm signs with it now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signs: Option<bool>,
    /// Why not, or empty.
    #[serde(rename = "signRefusal", default, skip_serializing_if = "Option::is_none")]
    pub sign_refusal: Option<String>,
    /// Whether this realm accepts it now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepts: Option<bool>,
    /// Why not, or empty.
    #[serde(rename = "acceptRefusal", default, skip_serializing_if = "Option::is_none")]
    pub accept_refusal: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataSignaturePolicySurfacesDi {
    /// The setting holding what this surface signs with.
    #[serde(rename = "signSetting", default, skip_serializing_if = "Option::is_none")]
    pub sign_setting: Option<String>,
    /// The setting holding what this surface accepts.
    #[serde(rename = "acceptSetting", default, skip_serializing_if = "Option::is_none")]
    pub accept_setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<CryptoMetadataSignaturePolicySurfacesDiRowsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataSignaturePolicySurfacesX509RowsItem {
    /// The algorithm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Its name on this surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spelling: Option<String>,
    /// pq or composite, or empty for a classical algorithm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weak: Option<bool>,
    /// Whether this realm signs with it now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signs: Option<bool>,
    /// Why not, or empty.
    #[serde(rename = "signRefusal", default, skip_serializing_if = "Option::is_none")]
    pub sign_refusal: Option<String>,
    /// Whether this realm accepts it now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepts: Option<bool>,
    /// Why not, or empty.
    #[serde(rename = "acceptRefusal", default, skip_serializing_if = "Option::is_none")]
    pub accept_refusal: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataSignaturePolicySurfacesX509 {
    /// The setting holding what this surface signs with.
    #[serde(rename = "signSetting", default, skip_serializing_if = "Option::is_none")]
    pub sign_setting: Option<String>,
    /// The setting holding what this surface accepts.
    #[serde(rename = "acceptSetting", default, skip_serializing_if = "Option::is_none")]
    pub accept_setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<CryptoMetadataSignaturePolicySurfacesX509RowsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataSignaturePolicySurfaces {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jose: Option<CryptoMetadataSignaturePolicySurfacesJose>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub httpsig: Option<CryptoMetadataSignaturePolicySurfacesHttpsig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cose: Option<CryptoMetadataSignaturePolicySurfacesCose>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xml: Option<CryptoMetadataSignaturePolicySurfacesXml>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub di: Option<CryptoMetadataSignaturePolicySurfacesDi>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x509: Option<CryptoMetadataSignaturePolicySurfacesX509>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataSignaturePolicy {
    #[serde(rename = "pqcOnly", default, skip_serializing_if = "Option::is_none")]
    pub pqc_only: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surfaces: Option<CryptoMetadataSignaturePolicySurfaces>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataDrift {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undescribed: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelopes: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataKeysSigning {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kty: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bits: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    #[serde(rename = "certificateFingerprint", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub certificate_fingerprint: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataKeysCurveKeysItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kty: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub kid: Option<Option<String>>,
    #[serde(rename = "certificateFingerprint", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub certificate_fingerprint: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataKeysPostQuantumKeysItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kty: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub kid: Option<Option<String>>,
    #[serde(rename = "certificateFingerprint", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub certificate_fingerprint: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataKeysPostQuantum {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithms: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<CryptoMetadataKeysPostQuantumKeysItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataKeysSignerGroupsKeysItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub kind: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub kid: Option<Option<String>>,
    #[serde(rename = "pairedSlot", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub paired_slot: Option<Option<String>>,
    #[serde(rename = "certificateFingerprint", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub certificate_fingerprint: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataKeysSignerGroups {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<CryptoMetadataKeysSignerGroupsKeysItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataKeysBbs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cryptosuite: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub curve: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataKeysTlsCertificatesItem {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub algorithm: Option<Option<String>>,
    #[serde(rename = "certificateFingerprint", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub certificate_fingerprint: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataKeysTls {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub subject: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub fingerprint256: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<CryptoMetadataKeysTlsCertificatesItem>>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub not_after: Option<Option<String>>,
    #[serde(rename = "perRealm", default, skip_serializing_if = "Option::is_none")]
    pub per_realm: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataKeysSpiffe {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready: Option<bool>,
    #[serde(rename = "perRealm", default, skip_serializing_if = "Option::is_none")]
    pub per_realm: Option<bool>,
    #[serde(rename = "trustDomain", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub trust_domain: Option<Option<String>>,
    #[serde(rename = "authoritySource", default, skip_serializing_if = "Option::is_none")]
    pub authority_source: Option<String>,
    #[serde(rename = "svidKeyType", default, skip_serializing_if = "Option::is_none")]
    pub svid_key_type: Option<String>,
    #[serde(rename = "authorityKeyType", default, skip_serializing_if = "Option::is_none")]
    pub authority_key_type: Option<String>,
    #[serde(rename = "x509KeyType", default, skip_serializing_if = "Option::is_none")]
    pub x509_key_type: Option<String>,
    #[serde(rename = "jwtKeyType", default, skip_serializing_if = "Option::is_none")]
    pub jwt_key_type: Option<String>,
    #[serde(rename = "x509Authorities", default, skip_serializing_if = "Option::is_none")]
    pub x509_authorities: Option<i64>,
    #[serde(rename = "authorityFingerprint", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub authority_fingerprint: Option<Option<String>>,
    #[serde(rename = "trustAnchors", default, skip_serializing_if = "Option::is_none")]
    pub trust_anchors: Option<i64>,
    #[serde(rename = "jwtAuthorities", default, skip_serializing_if = "Option::is_none")]
    pub jwt_authorities: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataKeys {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(rename = "regeneratedEveryStart", default, skip_serializing_if = "Option::is_none")]
    pub regenerated_every_start: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing: Option<CryptoMetadataKeysSigning>,
    #[serde(rename = "curveKeys", default, skip_serializing_if = "Option::is_none")]
    pub curve_keys: Option<Vec<CryptoMetadataKeysCurveKeysItem>>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<CryptoMetadataKeysPostQuantum>,
    #[serde(rename = "signerGroups", default, skip_serializing_if = "Option::is_none")]
    pub signer_groups: Option<CryptoMetadataKeysSignerGroups>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bbs: Option<CryptoMetadataKeysBbs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<CryptoMetadataKeysTls>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spiffe: Option<CryptoMetadataKeysSpiffe>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataFamiliesItemAlgorithmsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub how: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataFamiliesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifies: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypts: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decrypts: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hashes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<String>,
    #[serde(rename = "whatItDoesNot", default, skip_serializing_if = "Option::is_none")]
    pub what_it_does_not: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelopes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithms: Option<Vec<CryptoMetadataFamiliesItemAlgorithmsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataHashingXmlDigestMethodsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataHashingScimDigestItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataHashingFixedItem {
    #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
    pub where_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataHashingWeakItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
    pub where_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataHashing {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jws: Option<Vec<String>>,
    #[serde(rename = "xmlDigestMethods", default, skip_serializing_if = "Option::is_none")]
    pub xml_digest_methods: Option<Vec<CryptoMetadataHashingXmlDigestMethodsItem>>,
    #[serde(rename = "scimDigest", default, skip_serializing_if = "Option::is_none")]
    pub scim_digest: Option<Vec<CryptoMetadataHashingScimDigestItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed: Option<Vec<CryptoMetadataHashingFixedItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weak: Option<Vec<CryptoMetadataHashingWeakItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataSignaturesJwsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub family: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kty: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asymmetric: Option<bool>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composite: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpop: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataSignaturesXmlItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub family: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub hash: Option<Option<String>>,
    #[serde(rename = "keyKind", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub key_kind: Option<Option<String>>,
    #[serde(rename = "verifiedHere", default, skip_serializing_if = "Option::is_none")]
    pub verified_here: Option<bool>,
    #[serde(rename = "signsWith", default, skip_serializing_if = "Option::is_none")]
    pub signs_with: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataSignaturesCanonicalizationItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub exclusive: Option<Option<bool>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub comments: Option<Option<bool>>,
    #[serde(rename = "usedHere", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub used_here: Option<Option<bool>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataSignaturesCoseItem {
    #[serde(rename = "coseAlg", default, skip_serializing_if = "Option::is_none")]
    pub cose_alg: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jose: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataSignaturesOtherItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataSignatures {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jws: Option<Vec<CryptoMetadataSignaturesJwsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xml: Option<Vec<CryptoMetadataSignaturesXmlItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonicalization: Option<Vec<CryptoMetadataSignaturesCanonicalizationItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cose: Option<Vec<CryptoMetadataSignaturesCoseItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub other: Option<Vec<CryptoMetadataSignaturesOtherItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataEncryptionJweContentEncryptionItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bits: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(rename = "cekBytes", default, skip_serializing_if = "Option::is_none")]
    pub cek_bytes: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub note: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataEncryptionJwe {
    #[serde(rename = "keyManagementOut", default, skip_serializing_if = "Option::is_none")]
    pub key_management_out: Option<Vec<String>>,
    #[serde(rename = "keyManagementIn", default, skip_serializing_if = "Option::is_none")]
    pub key_management_in: Option<Vec<String>>,
    #[serde(rename = "contentEncryption", default, skip_serializing_if = "Option::is_none")]
    pub content_encryption: Option<Vec<CryptoMetadataEncryptionJweContentEncryptionItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataEncryptionXmlBlockCiphersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(rename = "keyBits", default, skip_serializing_if = "Option::is_none")]
    pub key_bits: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(rename = "ivBytes", default, skip_serializing_if = "Option::is_none")]
    pub iv_bytes: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataEncryptionXmlKeyTransportsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safe: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataEncryptionXmlConfigured {
    #[serde(rename = "blockCipher", default, skip_serializing_if = "Option::is_none")]
    pub block_cipher: Option<String>,
    #[serde(rename = "keyTransport", default, skip_serializing_if = "Option::is_none")]
    pub key_transport: Option<String>,
    #[serde(rename = "encryptAssertion", default, skip_serializing_if = "Option::is_none")]
    pub encrypt_assertion: Option<bool>,
    #[serde(rename = "encryptLogoutNameId", default, skip_serializing_if = "Option::is_none")]
    pub encrypt_logout_name_id: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataEncryptionXml {
    #[serde(rename = "blockCiphers", default, skip_serializing_if = "Option::is_none")]
    pub block_ciphers: Option<Vec<CryptoMetadataEncryptionXmlBlockCiphersItem>>,
    #[serde(rename = "keyTransports", default, skip_serializing_if = "Option::is_none")]
    pub key_transports: Option<Vec<CryptoMetadataEncryptionXmlKeyTransportsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configured: Option<CryptoMetadataEncryptionXmlConfigured>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataEncryptionKerberosPerformedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataEncryptionKerberosDecodeOnlyItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataEncryptionKerberos {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub performed: Option<Vec<CryptoMetadataEncryptionKerberosPerformedItem>>,
    #[serde(rename = "decodeOnly", default, skip_serializing_if = "Option::is_none")]
    pub decode_only: Option<Vec<CryptoMetadataEncryptionKerberosDecodeOnlyItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preference: Option<Vec<i64>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataEncryptionTls {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sockets: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataEncryption {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwe: Option<CryptoMetadataEncryptionJwe>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xml: Option<CryptoMetadataEncryptionXml>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kerberos: Option<CryptoMetadataEncryptionKerberos>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<CryptoMetadataEncryptionTls>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataPostQuantumAlgorithmsCompositeItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(rename = "mlDsa", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ml_dsa: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub traditional: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub prehash: Option<Option<String>>,
    #[serde(rename = "domainSeparator", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub domain_separator: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataPostQuantumAlgorithms {
    #[serde(rename = "mlDsa", default, skip_serializing_if = "Option::is_none")]
    pub ml_dsa: Option<Vec<String>>,
    #[serde(rename = "slhDsa", default, skip_serializing_if = "Option::is_none")]
    pub slh_dsa: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composite: Option<Vec<CryptoMetadataPostQuantumAlgorithmsCompositeItem>>,
    #[serde(rename = "keyType", default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub independence: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataPostQuantumSignaturesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub how: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataPostQuantumKeyEstablishmentSurfacesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub how: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataPostQuantumKeyEstablishmentDrafts {
    #[serde(rename = "mlKem", default, skip_serializing_if = "Option::is_none")]
    pub ml_kem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hpke: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hybrid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataPostQuantumKeyEstablishment {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surfaces: Option<Vec<CryptoMetadataPostQuantumKeyEstablishmentSurfacesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mechanisms: Option<Vec<String>>,
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hybrid: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drafts: Option<CryptoMetadataPostQuantumKeyEstablishmentDrafts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(rename = "whatWouldClose", default, skip_serializing_if = "Option::is_none")]
    pub what_would_close: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataPostQuantumSymmetric {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strongest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

/// The one to read before quoting this reply: signatures and key establishment
/// are reported separately, because a signature is checked when it is presented
/// while captured ciphertext can be kept and opened later.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataPostQuantum {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithms: Option<CryptoMetadataPostQuantumAlgorithms>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signatures: Option<Vec<CryptoMetadataPostQuantumSignaturesItem>>,
    #[serde(rename = "keyEstablishment", default, skip_serializing_if = "Option::is_none")]
    pub key_establishment: Option<CryptoMetadataPostQuantumKeyEstablishment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symmetric: Option<CryptoMetadataPostQuantumSymmetric>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadataStandardsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub specs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

/// What this service does when it signs, verifies, encrypts or decrypts, for
/// every identity service it advertises. Every algorithm list is READ FROM THE
/// MODULE THAT PERFORMS THE ALGORITHM, so it cannot claim something this
/// service does not do.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoMetadata {
    #[serde(rename = "signaturePolicy", default, skip_serializing_if = "Option::is_none")]
    pub signature_policy: Option<CryptoMetadataSignaturePolicy>,
    /// This service as the request reached it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// The trust realm the key material below belongs to. The ALGORITHM tables
    /// are process-wide; the SIGNING KEYS are per realm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(rename = "generatedAt", default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    /// Where all of this happens.
    #[serde(rename = "oneModule", default, skip_serializing_if = "Option::is_none")]
    pub one_module: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drift: Option<CryptoMetadataDrift>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<CryptoMetadataKeys>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub families: Option<Vec<CryptoMetadataFamiliesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hashing: Option<CryptoMetadataHashing>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signatures: Option<CryptoMetadataSignatures>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<CryptoMetadataEncryption>,
    /// The one to read before quoting this reply: signatures and key
    /// establishment are reported separately, because a signature is checked
    /// when it is presented while captured ciphertext can be kept and opened
    /// later.
    #[serde(rename = "postQuantum", default, skip_serializing_if = "Option::is_none")]
    pub post_quantum: Option<CryptoMetadataPostQuantum>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standards: Option<Vec<CryptoMetadataStandardsItem>>,
}

/// THE AXIS WORTH READING FIRST. `delegation` means the credential carries the
/// chain and the far end can see who is really asking. `impersonation` means
/// nothing does — so this record is the only place the fact will ever exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum DelegationActMode {
    #[serde(rename = "impersonation")]
    Impersonation,
    #[serde(rename = "delegation")]
    Delegation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum DelegationActOutcome {
    #[serde(rename = "issued")]
    Issued,
    #[serde(rename = "refused")]
    Refused,
}

/// ONE ACT: a single exchange at a single moment in which somebody acted on
/// somebody else's behalf. Not a relationship — the same three parties
/// appearing eleven times is eleven acts, and `chainKey` is what collapses
/// them.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DelegationAct {
    /// Unique across every process of the service and NEVER REUSED, including
    /// across a drop and a restart; rising within each process, not one order
    /// across them (#465). The stable name for an act; resume reading by `at`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<i64>,
    /// The process that recorded the act, by its stable origin in the store;
    /// empty without a shared store. The tie-break, with `seq`, for two acts in
    /// one millisecond.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// Milliseconds since the epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<i64>,
    /// The family, spelled as /admin-api/users spells it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// The mechanism, as its specification names it. The list's `types` member
    /// describes each one.
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    /// That mechanism in words.
    #[serde(rename = "typeLabel", default, skip_serializing_if = "Option::is_none")]
    pub type_label: Option<String>,
    /// THE AXIS WORTH READING FIRST. `delegation` means the credential carries
    /// the chain and the far end can see who is really asking. `impersonation`
    /// means nothing does — so this record is the only place the fact will ever
    /// exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<DelegationActMode>,
    /// Where the mechanism is defined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<String>,
    /// Whether THIS SERVICE decided who may perform the act. True for the three
    /// Kerberos S4U mechanisms and false for everything else, which is a real
    /// asymmetry rather than an omission — see `authorizedBy`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<DelegationActOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial: Option<crate::DelegationParty>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediary: Option<crate::DelegationParty>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<crate::DelegationParty>,
    /// The identity of the CHAIN rather than of the act: the mechanism and the
    /// three parties, with the time, the credentials and the OUTCOME left out.
    /// Acts sharing one are one edge of the picture — and the outcome is out of
    /// it deliberately, so a chain refused nine times and then fixed is one
    /// edge that changes rather than two that never meet.
    #[serde(rename = "chainKey", default, skip_serializing_if = "Option::is_none")]
    pub chain_key: Option<String>,
    /// What PERMITTED it: the attribute AND the account it is on, in the KDC's
    /// own words — or, for WS-Trust and token exchange (#108), in the
    /// delegation policy's; in development, what WOULD have refused it.
    #[serde(rename = "authorizedBy", default, skip_serializing_if = "Option::is_none")]
    pub authorized_by: Option<String>,
    /// Why it was REFUSED — the `e-text` of the error the client was sent, not
    /// a second wording that could come to disagree with it. Empty on an issued
    /// act.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumed: Option<Vec<crate::DelegationCredential>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub produced: Option<Vec<crate::DelegationCredential>>,
    /// The browser sign-on session, where there was one. USUALLY EMPTY, and
    /// that is a fact about delegation rather than a gap in the recording: a
    /// service asking on somebody's behalf has no browser anywhere in it.
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// One sentence of context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// The members the schema does not name, which it allows.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum DelegationChainMode {
    #[serde(rename = "impersonation")]
    Impersonation,
    #[serde(rename = "delegation")]
    Delegation,
}

/// One DISTINCT chain among the acts that matched — one edge of the picture.
/// This is the more useful answer to "what talks to what".
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DelegationChain {
    #[serde(rename = "chainKey", default, skip_serializing_if = "Option::is_none")]
    pub chain_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(rename = "typeLabel", default, skip_serializing_if = "Option::is_none")]
    pub type_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<DelegationChainMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial: Option<crate::DelegationParty>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediary: Option<crate::DelegationParty>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<crate::DelegationParty>,
    /// How many acts are on this edge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acts: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<i64>,
    #[serde(rename = "firstAt", default, skip_serializing_if = "Option::is_none")]
    pub first_at: Option<i64>,
    #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none")]
    pub last_at: Option<i64>,
    /// From the MOST RECENT act on the chain, so an edge that was fixed says
    /// how it works now rather than why it used to fail.
    #[serde(rename = "authorizedBy", default, skip_serializing_if = "Option::is_none")]
    pub authorized_by: Option<String>,
    /// Likewise, for a refusal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The members the schema does not name, which it allows.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// One credential presented or produced. NO CREDENTIAL IS EVER CARRIED — only
/// what kind it was and its identifier, which is the rule the audit log follows
/// and applies here twice over: a delegation is precisely the request that
/// carries two credentials at once.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DelegationCredential {
    /// `subject_token`, `actor_token`, `access_token`, `Kerberos evidence
    /// ticket`, `SAML 2.0 assertion`, `PA-FOR-USER`, and so on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// A `jti` or an AssertionID. EMPTY for a Kerberos ticket, which genuinely
    /// has none in the protocol, and for the WS-Trust JWT, which is signed
    /// directly rather than through this service's JWT funnel and so carries no
    /// `jti` and is in no register. `note` says which.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    /// What is worth knowing about this credential — whether it verified,
    /// whether it was forwardable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// The members the schema does not name, which it allows.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// One layer of the architecture. Each of the three roles uses this shape and
/// each can be an identity, an application, or BOTH — which is the fact that
/// makes the model protocol-independent rather than a Kerberos model the other
/// two are squeezed into.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DelegationParty {
    /// The NORMALISED local name, so a party here and a row on /admin-api/users
    /// name the same person — `alice`, her `urn:uuid:<entryUUID>` subject and
    /// `alice@EXAMPLE.COM` are one identity. Empty where this layer is an
    /// application rather than a person, or where nothing named it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The identity exactly as it arrived, when that differs from `key` — a
    /// Kerberos principal, a NameID, a `sub`. Both are carried because the
    /// collapse from one to the other is something a reader has to be able to
    /// see.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presented: Option<String>,
    /// The application this layer IS — a client_id, an AppliesTo, an SPN, an
    /// audience. NOT a promise that an entry exists under ou=applications: that
    /// registry holds what this service has been ASKED ABOUT, and a delegation
    /// naming something nobody has otherwise mentioned is an ordinary and
    /// interesting outcome. Look it up on /admin-api/applications to find out
    /// which.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    /// What this party is in THIS act, in the protocol's own words.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    /// The members the schema does not name, which it allows.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}
