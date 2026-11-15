// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// GENERATED from models/api/ (#1390, #444) by models/lib/rust_lib.mjs.
// Do not edit: change the model and run
// tests/tools/regenerate-model-docs.sh. tests/model_domain.js fails when
// this differs.

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListFilter {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub type_: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub mode: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub outcome: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub protocol: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub q: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListTypesItem {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListModesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListRolesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListActsItemInitial {
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
pub struct DelegationListActsItemIntermediary {
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
pub struct DelegationListActsItemTarget {
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
pub struct DelegationListActsItemConsumedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListActsItemProducedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListActsItem {
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
    pub initial: Option<DelegationListActsItemInitial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediary: Option<DelegationListActsItemIntermediary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<DelegationListActsItemTarget>,
    #[serde(rename = "authorizedBy", default, skip_serializing_if = "Option::is_none")]
    pub authorized_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumed: Option<Vec<DelegationListActsItemConsumedItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub produced: Option<Vec<DelegationListActsItemProducedItem>>,
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(rename = "chainKey", default, skip_serializing_if = "Option::is_none")]
    pub chain_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListChainsItemInitial {
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
pub struct DelegationListChainsItemIntermediary {
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
pub struct DelegationListChainsItemTarget {
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
pub struct DelegationListChainsItem {
    #[serde(rename = "chainKey", default, skip_serializing_if = "Option::is_none")]
    pub chain_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(rename = "typeLabel", default, skip_serializing_if = "Option::is_none")]
    pub type_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial: Option<DelegationListChainsItemInitial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediary: Option<DelegationListChainsItemIntermediary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<DelegationListChainsItemTarget>,
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
    #[serde(rename = "authorizedBy", default, skip_serializing_if = "Option::is_none")]
    pub authorized_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListApplicationsItemRoles {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediary: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListApplicationsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spellings: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<DelegationListApplicationsItemRoles>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<String>>,
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
    #[serde(rename = "identityKey", default, skip_serializing_if = "Option::is_none")]
    pub identity_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chains: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListGraphRealm {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
    #[serde(rename = "isDefault", default, skip_serializing_if = "Option::is_none")]
    pub is_default: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListGraphNodesItemRoles {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediary: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListGraphNodesItemRealm {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
    #[serde(rename = "isDefault", default, skip_serializing_if = "Option::is_none")]
    pub is_default: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListGraphNodesItem {
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
    pub roles: Option<DelegationListGraphNodesItemRoles>,
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
    pub realm: Option<DelegationListGraphNodesItemRealm>,
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
pub struct DelegationListGraphEdgesItemConsumedItem {
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
pub struct DelegationListGraphEdgesItemProducedItem {
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
pub struct DelegationListGraphEdgesItemAuthenticationsItem {
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
pub struct DelegationListGraphEdgesItem {
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
    pub consumed: Option<Vec<DelegationListGraphEdgesItemConsumedItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub produced: Option<Vec<DelegationListGraphEdgesItemProducedItem>>,
    #[serde(rename = "consumedFold", default, skip_serializing_if = "Option::is_none")]
    pub consumed_fold: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "producedFold", default, skip_serializing_if = "Option::is_none")]
    pub produced_fold: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mechanism: Option<String>,
    #[serde(rename = "setOn", default, skip_serializing_if = "Option::is_none")]
    pub set_on: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentications: Option<Vec<DelegationListGraphEdgesItemAuthenticationsItem>>,
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
pub struct DelegationListGraphTokensItem {
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
pub struct DelegationListGraphCredentialsItem {
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

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListGraphCounts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodes: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edges: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListGraph {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<DelegationListGraphRealm>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodes: Option<Vec<DelegationListGraphNodesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edges: Option<Vec<DelegationListGraphEdgesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<Vec<DelegationListGraphTokensItem>>,
    #[serde(rename = "tokensLeftOff", default, skip_serializing_if = "Option::is_none")]
    pub tokens_left_off: Option<i64>,
    #[serde(rename = "maxTokenRows", default, skip_serializing_if = "Option::is_none")]
    pub max_token_rows: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acts: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chains: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Vec<DelegationListGraphCredentialsItem>>,
    #[serde(rename = "credentialsOnDelegationLines", default, skip_serializing_if = "Option::is_none")]
    pub credentials_on_delegation_lines: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<DelegationListGraphCounts>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListPolicyPairsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mechanism: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(rename = "frontEnd", default, skip_serializing_if = "Option::is_none")]
    pub front_end: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(rename = "setOn", default, skip_serializing_if = "Option::is_none")]
    pub set_on: Option<String>,
    #[serde(rename = "setOnRole", default, skip_serializing_if = "Option::is_none")]
    pub set_on_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires: Option<String>,
    #[serde(rename = "targetKnown", default, skip_serializing_if = "Option::is_none")]
    pub target_known: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListPolicyAccountsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(rename = "notDelegated", default, skip_serializing_if = "Option::is_none")]
    pub not_delegated: Option<bool>,
    #[serde(rename = "trustedToAuthenticateForDelegation", default, skip_serializing_if = "Option::is_none")]
    pub trusted_to_authenticate_for_delegation: Option<bool>,
    #[serde(rename = "okAsDelegate", default, skip_serializing_if = "Option::is_none")]
    pub ok_as_delegate: Option<bool>,
    #[serde(rename = "autoCreated", default, skip_serializing_if = "Option::is_none")]
    pub auto_created: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effects: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairs: Option<Vec<DelegationListPolicyPairsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accounts: Option<Vec<DelegationListPolicyAccountsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListAllowedResourcesItemPermissionsItemGrantedToItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListAllowedResourcesItemPermissionsItem {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub description: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub id: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub raw: Option<Option<String>>,
    #[serde(rename = "grantedTo", default, skip_serializing_if = "Option::is_none")]
    pub granted_to: Option<Vec<DelegationListAllowedResourcesItemPermissionsItemGrantedToItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListAllowedResourcesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "baseUri", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub base_uri: Option<Option<String>>,
    #[serde(rename = "rawBaseUri", default, skip_serializing_if = "Option::is_none")]
    pub raw_base_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<DelegationListAllowedResourcesItemPermissionsItem>>,
    #[serde(rename = "grantsHeld", default, skip_serializing_if = "Option::is_none")]
    pub grants_held: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListAllowedPermissionsItemGrantedToItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListAllowedPermissionsItem {
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
    pub granted_to: Option<Vec<DelegationListAllowedPermissionsItemGrantedToItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListAllowedGrantsItem {
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

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListAllowedCounts {
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

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListAllowedGraphRealm {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
    #[serde(rename = "isDefault", default, skip_serializing_if = "Option::is_none")]
    pub is_default: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListAllowedGraphNodesItemRoles {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediary: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListAllowedGraphNodesItemRealm {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
    #[serde(rename = "isDefault", default, skip_serializing_if = "Option::is_none")]
    pub is_default: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListAllowedGraphNodesItem {
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
    pub roles: Option<DelegationListAllowedGraphNodesItemRoles>,
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
    pub realm: Option<DelegationListAllowedGraphNodesItemRealm>,
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
pub struct DelegationListAllowedGraphEdgesItemConsumedItem {
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
pub struct DelegationListAllowedGraphEdgesItemProducedItem {
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
pub struct DelegationListAllowedGraphEdgesItemAuthenticationsItem {
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
pub struct DelegationListAllowedGraphEdgesItem {
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
    pub consumed: Option<Vec<DelegationListAllowedGraphEdgesItemConsumedItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub produced: Option<Vec<DelegationListAllowedGraphEdgesItemProducedItem>>,
    #[serde(rename = "consumedFold", default, skip_serializing_if = "Option::is_none")]
    pub consumed_fold: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "producedFold", default, skip_serializing_if = "Option::is_none")]
    pub produced_fold: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mechanism: Option<String>,
    #[serde(rename = "setOn", default, skip_serializing_if = "Option::is_none")]
    pub set_on: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentications: Option<Vec<DelegationListAllowedGraphEdgesItemAuthenticationsItem>>,
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
pub struct DelegationListAllowedGraphTokensItem {
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
pub struct DelegationListAllowedGraphCredentialsItem {
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

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListAllowedGraphCounts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodes: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edges: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListAllowedGraph {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<DelegationListAllowedGraphRealm>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodes: Option<Vec<DelegationListAllowedGraphNodesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edges: Option<Vec<DelegationListAllowedGraphEdgesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<Vec<DelegationListAllowedGraphTokensItem>>,
    #[serde(rename = "tokensLeftOff", default, skip_serializing_if = "Option::is_none")]
    pub tokens_left_off: Option<i64>,
    #[serde(rename = "maxTokenRows", default, skip_serializing_if = "Option::is_none")]
    pub max_token_rows: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acts: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chains: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Vec<DelegationListAllowedGraphCredentialsItem>>,
    #[serde(rename = "credentialsOnDelegationLines", default, skip_serializing_if = "Option::is_none")]
    pub credentials_on_delegation_lines: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<DelegationListAllowedGraphCounts>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListAllowedFilter {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub permissions: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub grants: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListAllowedPagingPermissions {
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
pub struct DelegationListAllowedPagingGrants {
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
pub struct DelegationListAllowedPaging {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<DelegationListAllowedPagingPermissions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<DelegationListAllowedPagingGrants>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListAllowed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<DelegationListAllowedResourcesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<DelegationListAllowedPermissionsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<Vec<DelegationListAllowedGrantsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<DelegationListAllowedCounts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph: Option<DelegationListAllowedGraph>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<DelegationListAllowedFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<DelegationListAllowedPaging>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListDelegationPolicyPairsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mechanism: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(rename = "targetApplication", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub target_application: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(rename = "setOn", default, skip_serializing_if = "Option::is_none")]
    pub set_on: Option<String>,
    #[serde(rename = "setOnRole", default, skip_serializing_if = "Option::is_none")]
    pub set_on_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonates: Option<bool>,
    #[serde(rename = "subjectGroups", default, skip_serializing_if = "Option::is_none")]
    pub subject_groups: Option<Vec<String>>,
    #[serde(rename = "targetKnown", default, skip_serializing_if = "Option::is_none")]
    pub target_known: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListDelegationPolicyPairsPaging {
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
pub struct DelegationListDelegationPolicyIntermediariesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonates: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantics: Option<Vec<String>>,
    #[serde(rename = "defaultSemantics", default, skip_serializing_if = "Option::is_none")]
    pub default_semantics: Option<String>,
    #[serde(rename = "notDelegated", default, skip_serializing_if = "Option::is_none")]
    pub not_delegated: Option<bool>,
    #[serde(rename = "subjectGroups", default, skip_serializing_if = "Option::is_none")]
    pub subject_groups: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListDelegationPolicyIntermediariesPaging {
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
pub struct DelegationListDelegationPolicyPeopleItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(rename = "notDelegated", default, skip_serializing_if = "Option::is_none")]
    pub not_delegated: Option<bool>,
    #[serde(rename = "mayAct", default, skip_serializing_if = "Option::is_none")]
    pub may_act: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantics: Option<Vec<String>>,
    #[serde(rename = "defaultSemantics", default, skip_serializing_if = "Option::is_none")]
    pub default_semantics: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListDelegationPolicyPeoplePaging {
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
pub struct DelegationListDelegationPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforced: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "protectedGroups", default, skip_serializing_if = "Option::is_none")]
    pub protected_groups: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairs: Option<Vec<DelegationListDelegationPolicyPairsItem>>,
    #[serde(rename = "pairsPaging", default, skip_serializing_if = "Option::is_none")]
    pub pairs_paging: Option<DelegationListDelegationPolicyPairsPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediaries: Option<Vec<DelegationListDelegationPolicyIntermediariesItem>>,
    #[serde(rename = "intermediariesPaging", default, skip_serializing_if = "Option::is_none")]
    pub intermediaries_paging: Option<DelegationListDelegationPolicyIntermediariesPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub people: Option<Vec<DelegationListDelegationPolicyPeopleItem>>,
    #[serde(rename = "peoplePaging", default, skip_serializing_if = "Option::is_none")]
    pub people_paging: Option<DelegationListDelegationPolicyPeoplePaging>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListPaging {
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
pub struct DelegationListChainPageShownItemInitial {
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
pub struct DelegationListChainPageShownItemIntermediary {
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
pub struct DelegationListChainPageShownItemTarget {
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
pub struct DelegationListChainPageShownItem {
    #[serde(rename = "chainKey", default, skip_serializing_if = "Option::is_none")]
    pub chain_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(rename = "typeLabel", default, skip_serializing_if = "Option::is_none")]
    pub type_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial: Option<DelegationListChainPageShownItemInitial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediary: Option<DelegationListChainPageShownItemIntermediary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<DelegationListChainPageShownItemTarget>,
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
    #[serde(rename = "authorizedBy", default, skip_serializing_if = "Option::is_none")]
    pub authorized_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListChainPagePaging {
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
pub struct DelegationListChainPage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<Vec<DelegationListChainPageShownItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<DelegationListChainPagePaging>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListPairPageShownItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mechanism: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(rename = "frontEnd", default, skip_serializing_if = "Option::is_none")]
    pub front_end: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(rename = "setOn", default, skip_serializing_if = "Option::is_none")]
    pub set_on: Option<String>,
    #[serde(rename = "setOnRole", default, skip_serializing_if = "Option::is_none")]
    pub set_on_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires: Option<String>,
    #[serde(rename = "targetKnown", default, skip_serializing_if = "Option::is_none")]
    pub target_known: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListPairPagePaging {
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
pub struct DelegationListPairPage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<Vec<DelegationListPairPageShownItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<DelegationListPairPagePaging>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListFlagPageShownItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(rename = "notDelegated", default, skip_serializing_if = "Option::is_none")]
    pub not_delegated: Option<bool>,
    #[serde(rename = "trustedToAuthenticateForDelegation", default, skip_serializing_if = "Option::is_none")]
    pub trusted_to_authenticate_for_delegation: Option<bool>,
    #[serde(rename = "okAsDelegate", default, skip_serializing_if = "Option::is_none")]
    pub ok_as_delegate: Option<bool>,
    #[serde(rename = "autoCreated", default, skip_serializing_if = "Option::is_none")]
    pub auto_created: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effects: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListFlagPagePaging {
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
pub struct DelegationListFlagPage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<Vec<DelegationListFlagPageShownItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<DelegationListFlagPagePaging>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListMechanismPageShownItem {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListMechanismPagePaging {
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
pub struct DelegationListMechanismPage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<Vec<DelegationListMechanismPageShownItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<DelegationListMechanismPagePaging>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListApplicationChooserEntriesItem {
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

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListApplicationChooserSlice {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListApplicationChooser {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<DelegationListApplicationChooserEntriesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slice: Option<DelegationListApplicationChooserSlice>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub complete: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListUserChooserEntriesItem {
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

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListUserChooserSlice {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListUserChooser {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<DelegationListUserChooserEntriesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slice: Option<DelegationListUserChooserSlice>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub complete: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListPermissionsViewRegisterResourcesItemPermissionsItemGrantedToItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListPermissionsViewRegisterResourcesItemPermissionsItem {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub description: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub id: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub raw: Option<Option<String>>,
    #[serde(rename = "grantedTo", default, skip_serializing_if = "Option::is_none")]
    pub granted_to: Option<Vec<DelegationListPermissionsViewRegisterResourcesItemPermissionsItemGrantedToItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListPermissionsViewRegisterResourcesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "baseUri", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub base_uri: Option<Option<String>>,
    #[serde(rename = "rawBaseUri", default, skip_serializing_if = "Option::is_none")]
    pub raw_base_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<DelegationListPermissionsViewRegisterResourcesItemPermissionsItem>>,
    #[serde(rename = "grantsHeld", default, skip_serializing_if = "Option::is_none")]
    pub grants_held: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListPermissionsViewRegisterPermissionsItemGrantedToItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListPermissionsViewRegisterPermissionsItem {
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
    pub granted_to: Option<Vec<DelegationListPermissionsViewRegisterPermissionsItemGrantedToItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListPermissionsViewRegisterGrantsItem {
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

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListPermissionsViewRegisterCounts {
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

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListPermissionsViewRegister {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<DelegationListPermissionsViewRegisterResourcesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<DelegationListPermissionsViewRegisterPermissionsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<Vec<DelegationListPermissionsViewRegisterGrantsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<DelegationListPermissionsViewRegisterCounts>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListPermissionsViewListStatePermPageShownItemGrantedToItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListPermissionsViewListStatePermPageShownItem {
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
    pub granted_to: Option<Vec<DelegationListPermissionsViewListStatePermPageShownItemGrantedToItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListPermissionsViewListStatePermPagePaging {
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
pub struct DelegationListPermissionsViewListStatePermPage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<Vec<DelegationListPermissionsViewListStatePermPageShownItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<DelegationListPermissionsViewListStatePermPagePaging>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListPermissionsViewListStateGrantPageShownItem {
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

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListPermissionsViewListStateGrantPagePaging {
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
pub struct DelegationListPermissionsViewListStateGrantPage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<Vec<DelegationListPermissionsViewListStateGrantPageShownItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<DelegationListPermissionsViewListStateGrantPagePaging>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListPermissionsViewListState {
    #[serde(rename = "permWanted", default, skip_serializing_if = "Option::is_none")]
    pub perm_wanted: Option<String>,
    #[serde(rename = "grantWanted", default, skip_serializing_if = "Option::is_none")]
    pub grant_wanted: Option<String>,
    #[serde(rename = "permPage", default, skip_serializing_if = "Option::is_none")]
    pub perm_page: Option<DelegationListPermissionsViewListStatePermPage>,
    #[serde(rename = "grantPage", default, skip_serializing_if = "Option::is_none")]
    pub grant_page: Option<DelegationListPermissionsViewListStateGrantPage>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListPermissionsViewAllApplicationsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListPermissionsView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub register: Option<DelegationListPermissionsViewRegister>,
    #[serde(rename = "listState", default, skip_serializing_if = "Option::is_none")]
    pub list_state: Option<DelegationListPermissionsViewListState>,
    #[serde(rename = "allApplications", default, skip_serializing_if = "Option::is_none")]
    pub all_applications: Option<Vec<DelegationListPermissionsViewAllApplicationsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListExchangePolicyViewRegisterPairsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mechanism: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(rename = "targetApplication", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub target_application: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(rename = "setOn", default, skip_serializing_if = "Option::is_none")]
    pub set_on: Option<String>,
    #[serde(rename = "setOnRole", default, skip_serializing_if = "Option::is_none")]
    pub set_on_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonates: Option<bool>,
    #[serde(rename = "subjectGroups", default, skip_serializing_if = "Option::is_none")]
    pub subject_groups: Option<Vec<String>>,
    #[serde(rename = "targetKnown", default, skip_serializing_if = "Option::is_none")]
    pub target_known: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListExchangePolicyViewRegisterIntermediariesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonates: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantics: Option<Vec<String>>,
    #[serde(rename = "defaultSemantics", default, skip_serializing_if = "Option::is_none")]
    pub default_semantics: Option<String>,
    #[serde(rename = "notDelegated", default, skip_serializing_if = "Option::is_none")]
    pub not_delegated: Option<bool>,
    #[serde(rename = "subjectGroups", default, skip_serializing_if = "Option::is_none")]
    pub subject_groups: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListExchangePolicyViewRegisterPeopleItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(rename = "notDelegated", default, skip_serializing_if = "Option::is_none")]
    pub not_delegated: Option<bool>,
    #[serde(rename = "mayAct", default, skip_serializing_if = "Option::is_none")]
    pub may_act: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantics: Option<Vec<String>>,
    #[serde(rename = "defaultSemantics", default, skip_serializing_if = "Option::is_none")]
    pub default_semantics: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListExchangePolicyViewRegister {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairs: Option<Vec<DelegationListExchangePolicyViewRegisterPairsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediaries: Option<Vec<DelegationListExchangePolicyViewRegisterIntermediariesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub people: Option<Vec<DelegationListExchangePolicyViewRegisterPeopleItem>>,
    #[serde(rename = "protectedGroups", default, skip_serializing_if = "Option::is_none")]
    pub protected_groups: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforced: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListExchangePolicyViewPairsShownItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mechanism: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(rename = "targetApplication", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub target_application: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(rename = "setOn", default, skip_serializing_if = "Option::is_none")]
    pub set_on: Option<String>,
    #[serde(rename = "setOnRole", default, skip_serializing_if = "Option::is_none")]
    pub set_on_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonates: Option<bool>,
    #[serde(rename = "subjectGroups", default, skip_serializing_if = "Option::is_none")]
    pub subject_groups: Option<Vec<String>>,
    #[serde(rename = "targetKnown", default, skip_serializing_if = "Option::is_none")]
    pub target_known: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListExchangePolicyViewPairsPaging {
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
pub struct DelegationListExchangePolicyViewPairs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<Vec<DelegationListExchangePolicyViewPairsShownItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<DelegationListExchangePolicyViewPairsPaging>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListExchangePolicyViewIntermediariesShownItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonates: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantics: Option<Vec<String>>,
    #[serde(rename = "defaultSemantics", default, skip_serializing_if = "Option::is_none")]
    pub default_semantics: Option<String>,
    #[serde(rename = "notDelegated", default, skip_serializing_if = "Option::is_none")]
    pub not_delegated: Option<bool>,
    #[serde(rename = "subjectGroups", default, skip_serializing_if = "Option::is_none")]
    pub subject_groups: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListExchangePolicyViewIntermediariesPaging {
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
pub struct DelegationListExchangePolicyViewIntermediaries {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<Vec<DelegationListExchangePolicyViewIntermediariesShownItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<DelegationListExchangePolicyViewIntermediariesPaging>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListExchangePolicyViewPeopleShownItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(rename = "notDelegated", default, skip_serializing_if = "Option::is_none")]
    pub not_delegated: Option<bool>,
    #[serde(rename = "mayAct", default, skip_serializing_if = "Option::is_none")]
    pub may_act: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantics: Option<Vec<String>>,
    #[serde(rename = "defaultSemantics", default, skip_serializing_if = "Option::is_none")]
    pub default_semantics: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListExchangePolicyViewPeoplePaging {
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
pub struct DelegationListExchangePolicyViewPeople {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<Vec<DelegationListExchangePolicyViewPeopleShownItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<DelegationListExchangePolicyViewPeoplePaging>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListExchangePolicyView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub register: Option<DelegationListExchangePolicyViewRegister>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairs: Option<DelegationListExchangePolicyViewPairs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediaries: Option<DelegationListExchangePolicyViewIntermediaries>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub people: Option<DelegationListExchangePolicyViewPeople>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationListFacts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apps: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationList {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<i64>,
    #[serde(rename = "heldHere", default, skip_serializing_if = "Option::is_none")]
    pub held_here: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processes: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dropped: Option<i64>,
    #[serde(rename = "maxRecords", default, skip_serializing_if = "Option::is_none")]
    pub max_records: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<i64>,
    #[serde(rename = "oldestSeq", default, skip_serializing_if = "Option::is_none")]
    pub oldest_seq: Option<f64>,
    #[serde(rename = "newestSeq", default, skip_serializing_if = "Option::is_none")]
    pub newest_seq: Option<f64>,
    #[serde(rename = "byType", default, skip_serializing_if = "Option::is_none")]
    pub by_type: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "byMode", default, skip_serializing_if = "Option::is_none")]
    pub by_mode: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "byOutcome", default, skip_serializing_if = "Option::is_none")]
    pub by_outcome: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "byProtocol", default, skip_serializing_if = "Option::is_none")]
    pub by_protocol: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<DelegationListFilter>,
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
    pub types: Option<Vec<DelegationListTypesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modes: Option<Vec<DelegationListModesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcomes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<DelegationListRolesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acts: Option<Vec<DelegationListActsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chains: Option<Vec<DelegationListChainsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applications: Option<Vec<DelegationListApplicationsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph: Option<DelegationListGraph>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<DelegationListPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed: Option<DelegationListAllowed>,
    #[serde(rename = "delegationPolicy", default, skip_serializing_if = "Option::is_none")]
    pub delegation_policy: Option<DelegationListDelegationPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub all: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<DelegationListPaging>,
    #[serde(rename = "delegationPerPage", default, skip_serializing_if = "Option::is_none")]
    pub delegation_per_page: Option<i64>,
    #[serde(rename = "chainPage", default, skip_serializing_if = "Option::is_none")]
    pub chain_page: Option<DelegationListChainPage>,
    #[serde(rename = "pairPage", default, skip_serializing_if = "Option::is_none")]
    pub pair_page: Option<DelegationListPairPage>,
    #[serde(rename = "flagPage", default, skip_serializing_if = "Option::is_none")]
    pub flag_page: Option<DelegationListFlagPage>,
    #[serde(rename = "mechanismPage", default, skip_serializing_if = "Option::is_none")]
    pub mechanism_page: Option<DelegationListMechanismPage>,
    #[serde(rename = "applicationChooser", default, skip_serializing_if = "Option::is_none")]
    pub application_chooser: Option<DelegationListApplicationChooser>,
    #[serde(rename = "userChooser", default, skip_serializing_if = "Option::is_none")]
    pub user_chooser: Option<DelegationListUserChooser>,
    #[serde(rename = "permissionsView", default, skip_serializing_if = "Option::is_none")]
    pub permissions_view: Option<DelegationListPermissionsView>,
    #[serde(rename = "exchangePolicyView", default, skip_serializing_if = "Option::is_none")]
    pub exchange_policy_view: Option<DelegationListExchangePolicyView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facts: Option<DelegationListFacts>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum DelegationPolicyPairsItemMechanism {
    #[serde(rename = "classic")]
    Classic,
    #[serde(rename = "rbcd")]
    Rbcd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum DelegationPolicyPairsItemSetOnRole {
    #[serde(rename = "front end")]
    FrontEnd,
    #[serde(rename = "back end")]
    BackEnd,
}

/// One configured pair.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DelegationPolicyPairsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mechanism: Option<DelegationPolicyPairsItemMechanism>,
    /// The same mechanism id an ACT carries, so the two halves of this resource
    /// can be read against each other without a second lookup table.
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    /// Who may act.
    #[serde(rename = "frontEnd", default, skip_serializing_if = "Option::is_none")]
    pub front_end: Option<String>,
    /// What may be reached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    /// `msDS-AllowedToDelegateTo` or
    /// `msDS-AllowedToActOnBehalfOfOtherIdentity`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    /// THE ACCOUNT THE PERMISSION LIVES ON, and the field to read first.
    /// Classic puts it on the front end, where only a domain admin can set it;
    /// resource-based puts it on the back end, where whoever controls that
    /// object can set it themselves. That is the entire security story of RBCD.
    #[serde(rename = "setOn", default, skip_serializing_if = "Option::is_none")]
    pub set_on: Option<String>,
    #[serde(rename = "setOnRole", default, skip_serializing_if = "Option::is_none")]
    pub set_on_role: Option<DelegationPolicyPairsItemSetOnRole>,
    /// What ELSE the mechanism needs beyond the attribute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires: Option<String>,
    /// Whether this KDC has a principal by that name. A misspelt SPN fails at
    /// TGS time with an error about authorization rather than spelling.
    #[serde(rename = "targetKnown", default, skip_serializing_if = "Option::is_none")]
    pub target_known: Option<bool>,
    /// Why this pair may still fail although the attribute names it. The
    /// expensive one: a front end with no
    /// TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION gets a non-forwardable ticket out
    /// of S4U2Self, so classic S4U2Proxy then fails complaining about the
    /// evidence — two steps from the attribute that caused it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// The members the schema does not name, which it allows.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// One account.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DelegationPolicyAccountsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(rename = "notDelegated", default, skip_serializing_if = "Option::is_none")]
    pub not_delegated: Option<bool>,
    #[serde(rename = "trustedToAuthenticateForDelegation", default, skip_serializing_if = "Option::is_none")]
    pub trusted_to_authenticate_for_delegation: Option<bool>,
    /// ADVICE TO THE CLIENT and not a control: it tells a client this service
    /// may be trusted with forwarded credentials, a client is free to ignore
    /// it, and this KDC enforces nothing by it.
    #[serde(rename = "okAsDelegate", default, skip_serializing_if = "Option::is_none")]
    pub ok_as_delegate: Option<bool>,
    #[serde(rename = "autoCreated", default, skip_serializing_if = "Option::is_none")]
    pub auto_created: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// What each flag actually does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effects: Option<Vec<String>>,
    /// The members the schema does not name, which it allows.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// WHO MAY DELEGATE TO WHOM, before anybody has tried. KERBEROS ONLY, and that
/// is not an omission: Kerberos is the only family here that polices delegation
/// at all. WS-Trust puts no authorization on OnBehalfOf or ActAs, and RFC 8693
/// leaves the policy to the authorization server, which this one does not have.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DelegationPolicy {
    /// One per (front end, target, mechanism). The two mechanisms are in ONE
    /// list because the messages and the KDC options are identical and the
    /// whole difference is which of the two accounts carries the permission —
    /// which is `setOn`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairs: Option<Vec<DelegationPolicyPairsItem>>,
    /// Principals carrying a flag that changes what delegation can do to them
    /// or with them. Two of the three STOP delegation rather than permit it,
    /// and one is not a control at all. Listed whether or not a pair names
    /// them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accounts: Option<Vec<DelegationPolicyAccountsItem>>,
    /// The members the schema does not name, which it allows.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<crate::WithProviderPayloadRegion>,
    #[serde(rename = "credentialSet", default, skip_serializing_if = "Option::is_none")]
    pub credential_set: Option<bool>,
    #[serde(rename = "credentialShape", default, skip_serializing_if = "Option::is_none")]
    pub credential_shape: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceViewAttestation {
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
pub struct DeviceViewComplianceChange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub previous: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceViewStatusChange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub previous: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceViewEnrolment {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceViewRememberedBrowser {
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
pub struct DeviceView {
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
    pub keys: Option<crate::WithAdditionalPropertiesPropertiesLevel>,
    #[serde(rename = "keyKinds", default, skip_serializing_if = "Option::is_none")]
    pub key_kinds: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<DeviceViewAttestation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance: Option<String>,
    #[serde(rename = "complianceChange", default, skip_serializing_if = "Option::is_none")]
    pub compliance_change: Option<DeviceViewComplianceChange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(rename = "statusChange", default, skip_serializing_if = "Option::is_none")]
    pub status_change: Option<DeviceViewStatusChange>,
    #[serde(rename = "riskLevel", default, skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
    #[serde(rename = "riskChange", default, skip_serializing_if = "Option::is_none")]
    pub risk_change: Option<crate::RiskChangeValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrolment: Option<DeviceViewEnrolment>,
    #[serde(rename = "nativeSso", default, skip_serializing_if = "Option::is_none")]
    pub native_sso: Option<bool>,
    #[serde(rename = "rememberedBrowser", default, skip_serializing_if = "Option::is_none")]
    pub remembered_browser: Option<DeviceViewRememberedBrowser>,
    #[serde(rename = "sessionLive", default, skip_serializing_if = "Option::is_none")]
    pub session_live: Option<bool>,
    #[serde(rename = "lastUsed", default, skip_serializing_if = "Option::is_none")]
    pub last_used: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(rename = "ownerName", default, skip_serializing_if = "Option::is_none")]
    pub owner_name: Option<String>,
    #[serde(rename = "ownerFound", default, skip_serializing_if = "Option::is_none")]
    pub owner_found: Option<bool>,
    #[serde(rename = "applicationNames", default, skip_serializing_if = "Option::is_none")]
    pub application_names: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryApplicationListFilter {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub q: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryApplicationListKindsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryApplicationListSchemaObjectClassesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
    pub where_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standard: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryApplicationListSchemaAttributesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standard: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitive: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<bool>,
    #[serde(rename = "identifierName", default, skip_serializing_if = "Option::is_none")]
    pub identifier_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<sts_model_base::unions::BoolOrString>,
    #[serde(rename = "enum", default, skip_serializing_if = "Option::is_none")]
    pub enum_: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub families: Option<Vec<String>>,
    #[serde(rename = "familyWhy", default, skip_serializing_if = "Option::is_none")]
    pub family_why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overrides: Option<String>,
    #[serde(rename = "strictOverride", default, skip_serializing_if = "Option::is_none")]
    pub strict_override: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryApplicationListSchema {
    #[serde(rename = "objectClasses", default, skip_serializing_if = "Option::is_none")]
    pub object_classes: Option<Vec<DirectoryApplicationListSchemaObjectClassesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<DirectoryApplicationListSchemaAttributesItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryApplicationListApplicationsItemReturnAddressesObservedItem {
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
pub struct DirectoryApplicationListApplicationsItem {
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
    pub return_addresses_observed: Option<Vec<DirectoryApplicationListApplicationsItemReturnAddressesObservedItem>>,
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
    /// Attribute names, which are data in a schemaless directory, and values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Map<String, serde_json::Value>>,
    /// Attribute names, which are data in a schemaless directory, and values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryApplicationListPaging {
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
pub struct DirectoryApplicationList {
    #[serde(rename = "baseDn", default, skip_serializing_if = "Option::is_none")]
    pub base_dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<DirectoryApplicationListFilter>,
    #[serde(rename = "sourceOfTruth", default, skip_serializing_if = "Option::is_none")]
    pub source_of_truth: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<DirectoryApplicationListKindsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<DirectoryApplicationListSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applications: Option<Vec<DirectoryApplicationListApplicationsItem>>,
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
    pub paging: Option<DirectoryApplicationListPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

pub type DirectoryAttribute = serde_json::Map<String, serde_json::Value>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryEntryListFilter {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub q: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub origin: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryEntryListSearch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub complete: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scanned: Option<i64>,
    #[serde(rename = "scanLimit", default, skip_serializing_if = "Option::is_none")]
    pub scan_limit: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryEntryListEntriesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// Attribute names, which are data in a schemaless directory, and values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryEntryListPaging {
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
pub struct DirectoryEntryList {
    #[serde(rename = "baseDn", default, skip_serializing_if = "Option::is_none")]
    pub base_dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<DirectoryEntryListFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origins: Option<Vec<String>>,
    /// A count per name.
    #[serde(rename = "originCounts", default, skip_serializing_if = "Option::is_none")]
    pub origin_counts: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search: Option<DirectoryEntryListSearch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<DirectoryEntryListEntriesItem>>,
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
    pub paging: Option<DirectoryEntryListPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryFederationListFilter {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub q: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryFederationListRolesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryFederationListProtocolsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub needs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<String>,
    #[serde(rename = "signalsOnly", default, skip_serializing_if = "Option::is_none")]
    pub signals_only: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryFederationListSchemaObjectClassesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
    pub where_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standard: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryFederationListSchemaAttributesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standard: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitive: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<bool>,
    #[serde(rename = "identifierName", default, skip_serializing_if = "Option::is_none")]
    pub identifier_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<sts_model_base::unions::BoolOrString>,
    #[serde(rename = "enum", default, skip_serializing_if = "Option::is_none")]
    pub enum_: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub families: Option<Vec<String>>,
    #[serde(rename = "familyWhy", default, skip_serializing_if = "Option::is_none")]
    pub family_why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overrides: Option<String>,
    #[serde(rename = "strictOverride", default, skip_serializing_if = "Option::is_none")]
    pub strict_override: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryFederationListSchema {
    #[serde(rename = "objectClasses", default, skip_serializing_if = "Option::is_none")]
    pub object_classes: Option<Vec<DirectoryFederationListSchemaObjectClassesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<DirectoryFederationListSchemaAttributesItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryFederationListRelationshipsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(rename = "modifiedAt", default, skip_serializing_if = "Option::is_none")]
    pub modified_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing: Option<Vec<String>>,
    /// Attribute names, which are data in a schemaless directory, and values.
    #[serde(rename = "entryAttributes", default, skip_serializing_if = "Option::is_none")]
    pub entry_attributes: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "roleShort", default, skip_serializing_if = "Option::is_none")]
    pub role_short: Option<String>,
    #[serde(rename = "protocolLabel", default, skip_serializing_if = "Option::is_none")]
    pub protocol_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "fedId", default, skip_serializing_if = "Option::is_none")]
    pub fed_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cn: Option<String>,
    #[serde(rename = "fedName", default, skip_serializing_if = "Option::is_none")]
    pub fed_name: Option<String>,
    #[serde(rename = "fedRole", default, skip_serializing_if = "Option::is_none")]
    pub fed_role: Option<String>,
    #[serde(rename = "fedProtocol", default, skip_serializing_if = "Option::is_none")]
    pub fed_protocol: Option<String>,
    #[serde(rename = "fedProvider", default, skip_serializing_if = "Option::is_none")]
    pub fed_provider: Option<String>,
    #[serde(rename = "fedPeer", default, skip_serializing_if = "Option::is_none")]
    pub fed_peer: Option<String>,
    #[serde(rename = "fedLocalEntityId", default, skip_serializing_if = "Option::is_none")]
    pub fed_local_entity_id: Option<String>,
    #[serde(rename = "fedEnabled", default, skip_serializing_if = "Option::is_none")]
    pub fed_enabled: Option<String>,
    #[serde(rename = "fedSsoUrl", default, skip_serializing_if = "Option::is_none")]
    pub fed_sso_url: Option<String>,
    #[serde(rename = "fedTokenUrl", default, skip_serializing_if = "Option::is_none")]
    pub fed_token_url: Option<String>,
    #[serde(rename = "fedUserinfoUrl", default, skip_serializing_if = "Option::is_none")]
    pub fed_userinfo_url: Option<String>,
    #[serde(rename = "fedJwksUri", default, skip_serializing_if = "Option::is_none")]
    pub fed_jwks_uri: Option<String>,
    #[serde(rename = "fedEmailsUrl", default, skip_serializing_if = "Option::is_none")]
    pub fed_emails_url: Option<String>,
    #[serde(rename = "fedJwks", default, skip_serializing_if = "Option::is_none")]
    pub fed_jwks: Option<String>,
    #[serde(rename = "fedTrustAnchor", default, skip_serializing_if = "Option::is_none")]
    pub fed_trust_anchor: Option<String>,
    #[serde(rename = "fedSigningCertificate", default, skip_serializing_if = "Option::is_none")]
    pub fed_signing_certificate: Option<String>,
    #[serde(rename = "fedClientId", default, skip_serializing_if = "Option::is_none")]
    pub fed_client_id: Option<String>,
    #[serde(rename = "fedClientSecret", default, skip_serializing_if = "Option::is_none")]
    pub fed_client_secret: Option<String>,
    #[serde(rename = "fedResponseMode", default, skip_serializing_if = "Option::is_none")]
    pub fed_response_mode: Option<String>,
    #[serde(rename = "fedTeamId", default, skip_serializing_if = "Option::is_none")]
    pub fed_team_id: Option<String>,
    #[serde(rename = "fedKeyId", default, skip_serializing_if = "Option::is_none")]
    pub fed_key_id: Option<String>,
    #[serde(rename = "fedClientSigningKey", default, skip_serializing_if = "Option::is_none")]
    pub fed_client_signing_key: Option<String>,
    #[serde(rename = "fedTokenAuth", default, skip_serializing_if = "Option::is_none")]
    pub fed_token_auth: Option<String>,
    #[serde(rename = "fedScope", default, skip_serializing_if = "Option::is_none")]
    pub fed_scope: Option<String>,
    #[serde(rename = "fedResponseType", default, skip_serializing_if = "Option::is_none")]
    pub fed_response_type: Option<String>,
    #[serde(rename = "fedIdTokenSignedResponseAlg", default, skip_serializing_if = "Option::is_none")]
    pub fed_id_token_signed_response_alg: Option<String>,
    #[serde(rename = "fedUserinfoSignedResponseAlg", default, skip_serializing_if = "Option::is_none")]
    pub fed_userinfo_signed_response_alg: Option<String>,
    #[serde(rename = "fedUserinfo", default, skip_serializing_if = "Option::is_none")]
    pub fed_userinfo: Option<String>,
    #[serde(rename = "fedRefreshTokens", default, skip_serializing_if = "Option::is_none")]
    pub fed_refresh_tokens: Option<String>,
    #[serde(rename = "fedRefreshEverySeconds", default, skip_serializing_if = "Option::is_none")]
    pub fed_refresh_every_seconds: Option<String>,
    #[serde(rename = "fedRegister", default, skip_serializing_if = "Option::is_none")]
    pub fed_register: Option<String>,
    #[serde(rename = "fedRegisteredIssuer", default, skip_serializing_if = "Option::is_none")]
    pub fed_registered_issuer: Option<String>,
    #[serde(rename = "fedRequestObject", default, skip_serializing_if = "Option::is_none")]
    pub fed_request_object: Option<String>,
    #[serde(rename = "fedRequestObjectSigningAlg", default, skip_serializing_if = "Option::is_none")]
    pub fed_request_object_signing_alg: Option<String>,
    #[serde(rename = "fedWebFinger", default, skip_serializing_if = "Option::is_none")]
    pub fed_web_finger: Option<String>,
    #[serde(rename = "fedDiscovery", default, skip_serializing_if = "Option::is_none")]
    pub fed_discovery: Option<String>,
    #[serde(rename = "fedFapi", default, skip_serializing_if = "Option::is_none")]
    pub fed_fapi: Option<String>,
    #[serde(rename = "fedInitiateLogin", default, skip_serializing_if = "Option::is_none")]
    pub fed_initiate_login: Option<String>,
    #[serde(rename = "fedBinding", default, skip_serializing_if = "Option::is_none")]
    pub fed_binding: Option<String>,
    #[serde(rename = "fedSignRequest", default, skip_serializing_if = "Option::is_none")]
    pub fed_sign_request: Option<String>,
    #[serde(rename = "fedUsernameSource", default, skip_serializing_if = "Option::is_none")]
    pub fed_username_source: Option<String>,
    #[serde(rename = "fedSubjectClaim", default, skip_serializing_if = "Option::is_none")]
    pub fed_subject_claim: Option<String>,
    #[serde(rename = "fedAutocreateUsers", default, skip_serializing_if = "Option::is_none")]
    pub fed_autocreate_users: Option<String>,
    #[serde(rename = "fedUpdateUserAttributes", default, skip_serializing_if = "Option::is_none")]
    pub fed_update_user_attributes: Option<String>,
    #[serde(rename = "fedProvisionGroups", default, skip_serializing_if = "Option::is_none")]
    pub fed_provision_groups: Option<String>,
    #[serde(rename = "fedProvisionCap", default, skip_serializing_if = "Option::is_none")]
    pub fed_provision_cap: Option<String>,
    #[serde(rename = "fedProvisionIdleMinutes", default, skip_serializing_if = "Option::is_none")]
    pub fed_provision_idle_minutes: Option<String>,
    #[serde(rename = "fedSubjectPolicy", default, skip_serializing_if = "Option::is_none")]
    pub fed_subject_policy: Option<String>,
    #[serde(rename = "fedSubjectPattern", default, skip_serializing_if = "Option::is_none")]
    pub fed_subject_pattern: Option<String>,
    #[serde(rename = "fedMayAssertAdministrators", default, skip_serializing_if = "Option::is_none")]
    pub fed_may_assert_administrators: Option<String>,
    #[serde(rename = "fedSignalEmailMatch", default, skip_serializing_if = "Option::is_none")]
    pub fed_signal_email_match: Option<String>,
    #[serde(rename = "fedSignalsEnabled", default, skip_serializing_if = "Option::is_none")]
    pub fed_signals_enabled: Option<String>,
    #[serde(rename = "fedSignalsIssuer", default, skip_serializing_if = "Option::is_none")]
    pub fed_signals_issuer: Option<String>,
    #[serde(rename = "fedSignalsDelivery", default, skip_serializing_if = "Option::is_none")]
    pub fed_signals_delivery: Option<String>,
    #[serde(rename = "fedSignalsTokenUrl", default, skip_serializing_if = "Option::is_none")]
    pub fed_signals_token_url: Option<String>,
    #[serde(rename = "fedSignalsClientId", default, skip_serializing_if = "Option::is_none")]
    pub fed_signals_client_id: Option<String>,
    #[serde(rename = "fedSignalsClientSecret", default, skip_serializing_if = "Option::is_none")]
    pub fed_signals_client_secret: Option<String>,
    #[serde(rename = "fedSignalsScope", default, skip_serializing_if = "Option::is_none")]
    pub fed_signals_scope: Option<String>,
    #[serde(rename = "fedSignalsBearer", default, skip_serializing_if = "Option::is_none")]
    pub fed_signals_bearer: Option<String>,
    #[serde(rename = "fedSloUrl", default, skip_serializing_if = "Option::is_none")]
    pub fed_slo_url: Option<String>,
    #[serde(rename = "fedSloBinding", default, skip_serializing_if = "Option::is_none")]
    pub fed_slo_binding: Option<String>,
    #[serde(rename = "fedEndSessionUrl", default, skip_serializing_if = "Option::is_none")]
    pub fed_end_session_url: Option<String>,
    #[serde(rename = "fedAcceptSignout", default, skip_serializing_if = "Option::is_none")]
    pub fed_accept_signout: Option<String>,
    #[serde(rename = "fedRequireSignedLogout", default, skip_serializing_if = "Option::is_none")]
    pub fed_require_signed_logout: Option<String>,
    #[serde(rename = "fedEncryptionKeyType", default, skip_serializing_if = "Option::is_none")]
    pub fed_encryption_key_type: Option<String>,
    #[serde(rename = "fedKeyManagementAlgorithm", default, skip_serializing_if = "Option::is_none")]
    pub fed_key_management_algorithm: Option<String>,
    #[serde(rename = "fedContentEncryptionAlgorithm", default, skip_serializing_if = "Option::is_none")]
    pub fed_content_encryption_algorithm: Option<String>,
    #[serde(rename = "fedAllowUnencrypted", default, skip_serializing_if = "Option::is_none")]
    pub fed_allow_unencrypted: Option<String>,
    #[serde(rename = "fedClientCertificate", default, skip_serializing_if = "Option::is_none")]
    pub fed_client_certificate: Option<String>,
    #[serde(rename = "fedAllowUnsolicited", default, skip_serializing_if = "Option::is_none")]
    pub fed_allow_unsolicited: Option<String>,
    #[serde(rename = "fedApplication", default, skip_serializing_if = "Option::is_none")]
    pub fed_application: Option<String>,
    #[serde(rename = "fedAuthnMechanism", default, skip_serializing_if = "Option::is_none")]
    pub fed_authn_mechanism: Option<String>,
    #[serde(rename = "fedAuthnRelationship", default, skip_serializing_if = "Option::is_none")]
    pub fed_authn_relationship: Option<String>,
    #[serde(rename = "fedFirstSeen", default, skip_serializing_if = "Option::is_none")]
    pub fed_first_seen: Option<String>,
    #[serde(rename = "fedLastSeen", default, skip_serializing_if = "Option::is_none")]
    pub fed_last_seen: Option<String>,
    #[serde(rename = "fedAuthentications", default, skip_serializing_if = "Option::is_none")]
    pub fed_authentications: Option<String>,
    #[serde(rename = "fedUsers", default, skip_serializing_if = "Option::is_none")]
    pub fed_users: Option<String>,
    #[serde(rename = "fedLastUser", default, skip_serializing_if = "Option::is_none")]
    pub fed_last_user: Option<String>,
    #[serde(rename = "fedLastError", default, skip_serializing_if = "Option::is_none")]
    pub fed_last_error: Option<String>,
    #[serde(rename = "fedLastErrorAt", default, skip_serializing_if = "Option::is_none")]
    pub fed_last_error_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Vec<String>>,
    #[serde(rename = "fedAllowedTenants", default, skip_serializing_if = "Option::is_none")]
    pub fed_allowed_tenants: Option<Vec<String>>,
    #[serde(rename = "fedAuthorizeParams", default, skip_serializing_if = "Option::is_none")]
    pub fed_authorize_params: Option<Vec<String>>,
    #[serde(rename = "fedAttributeMap", default, skip_serializing_if = "Option::is_none")]
    pub fed_attribute_map: Option<Vec<String>>,
    #[serde(rename = "fedSubjectGroup", default, skip_serializing_if = "Option::is_none")]
    pub fed_subject_group: Option<Vec<String>>,
    #[serde(rename = "fedSubjectDomain", default, skip_serializing_if = "Option::is_none")]
    pub fed_subject_domain: Option<Vec<String>>,
    #[serde(rename = "fedHomeRealmDomain", default, skip_serializing_if = "Option::is_none")]
    pub fed_home_realm_domain: Option<Vec<String>>,
    #[serde(rename = "fedSignalsEvents", default, skip_serializing_if = "Option::is_none")]
    pub fed_signals_events: Option<Vec<String>>,
    #[serde(rename = "fedEncryptionKey", default, skip_serializing_if = "Option::is_none")]
    pub fed_encryption_key: Option<Vec<String>>,
    #[serde(rename = "fedRelease", default, skip_serializing_if = "Option::is_none")]
    pub fed_release: Option<Vec<String>>,
    #[serde(rename = "fedApplicationUse", default, skip_serializing_if = "Option::is_none")]
    pub fed_application_use: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryFederationListPaging {
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
pub struct DirectoryFederationList {
    #[serde(rename = "baseDn", default, skip_serializing_if = "Option::is_none")]
    pub base_dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<DirectoryFederationListFilter>,
    #[serde(rename = "sourceOfTruth", default, skip_serializing_if = "Option::is_none")]
    pub source_of_truth: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<DirectoryFederationListRolesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<DirectoryFederationListProtocolsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<DirectoryFederationListSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationships: Option<Vec<DirectoryFederationListRelationshipsItem>>,
    #[serde(rename = "enabledCount", default, skip_serializing_if = "Option::is_none")]
    pub enabled_count: Option<i64>,
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
    pub paging: Option<DirectoryFederationListPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryPepListFilter {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub q: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryPepListSchemaObjectClassesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
    pub where_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standard: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryPepListSchemaAttributesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standard: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitive: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<bool>,
    #[serde(rename = "identifierName", default, skip_serializing_if = "Option::is_none")]
    pub identifier_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<sts_model_base::unions::BoolOrString>,
    #[serde(rename = "enum", default, skip_serializing_if = "Option::is_none")]
    pub enum_: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub families: Option<Vec<String>>,
    #[serde(rename = "familyWhy", default, skip_serializing_if = "Option::is_none")]
    pub family_why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overrides: Option<String>,
    #[serde(rename = "strictOverride", default, skip_serializing_if = "Option::is_none")]
    pub strict_override: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryPepListSchema {
    #[serde(rename = "objectClasses", default, skip_serializing_if = "Option::is_none")]
    pub object_classes: Option<Vec<DirectoryPepListSchemaObjectClassesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<DirectoryPepListSchemaAttributesItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryPepListPepsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub origin: Option<Option<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<String>>,
    #[serde(rename = "modifiedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub modified_at: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operational: Option<Vec<String>>,
    /// Attribute names, which are data in a schemaless directory, and values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryPepListPaging {
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
pub struct DirectoryPepList {
    #[serde(rename = "baseDn", default, skip_serializing_if = "Option::is_none")]
    pub base_dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<DirectoryPepListFilter>,
    #[serde(rename = "sourceOfTruth", default, skip_serializing_if = "Option::is_none")]
    pub source_of_truth: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<DirectoryPepListSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peps: Option<Vec<DirectoryPepListPepsItem>>,
    #[serde(rename = "enabledCount", default, skip_serializing_if = "Option::is_none")]
    pub enabled_count: Option<i64>,
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
    pub paging: Option<DirectoryPepListPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryPolicyListFilter {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub q: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryPolicyListSchemaObjectClassesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
    pub where_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standard: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryPolicyListSchemaAttributesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standard: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitive: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<bool>,
    #[serde(rename = "identifierName", default, skip_serializing_if = "Option::is_none")]
    pub identifier_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<sts_model_base::unions::BoolOrString>,
    #[serde(rename = "enum", default, skip_serializing_if = "Option::is_none")]
    pub enum_: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub families: Option<Vec<String>>,
    #[serde(rename = "familyWhy", default, skip_serializing_if = "Option::is_none")]
    pub family_why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overrides: Option<String>,
    #[serde(rename = "strictOverride", default, skip_serializing_if = "Option::is_none")]
    pub strict_override: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryPolicyListSchema {
    #[serde(rename = "objectClasses", default, skip_serializing_if = "Option::is_none")]
    pub object_classes: Option<Vec<DirectoryPolicyListSchemaObjectClassesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<DirectoryPolicyListSchemaAttributesItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryPolicyListPoliciesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub origin: Option<Option<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<String>>,
    #[serde(rename = "modifiedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub modified_at: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operational: Option<Vec<String>>,
    /// Attribute names, which are data in a schemaless directory, and values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryPolicyListPaging {
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
pub struct DirectoryPolicyList {
    #[serde(rename = "baseDn", default, skip_serializing_if = "Option::is_none")]
    pub base_dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<i64>,
    #[serde(rename = "ownCount", default, skip_serializing_if = "Option::is_none")]
    pub own_count: Option<i64>,
    #[serde(rename = "applicationCount", default, skip_serializing_if = "Option::is_none")]
    pub application_count: Option<i64>,
    #[serde(rename = "applicationMax", default, skip_serializing_if = "Option::is_none")]
    pub application_max: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<DirectoryPolicyListFilter>,
    #[serde(rename = "sourceOfTruth", default, skip_serializing_if = "Option::is_none")]
    pub source_of_truth: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<DirectoryPolicyListSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policies: Option<Vec<DirectoryPolicyListPoliciesItem>>,
    #[serde(rename = "enabledCount", default, skip_serializing_if = "Option::is_none")]
    pub enabled_count: Option<i64>,
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
    pub paging: Option<DirectoryPolicyListPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryRoleListFilter {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub q: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryRoleListSchemaObjectClassesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
    pub where_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standard: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryRoleListSchemaAttributesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standard: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitive: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<bool>,
    #[serde(rename = "identifierName", default, skip_serializing_if = "Option::is_none")]
    pub identifier_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<sts_model_base::unions::BoolOrString>,
    #[serde(rename = "enum", default, skip_serializing_if = "Option::is_none")]
    pub enum_: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub families: Option<Vec<String>>,
    #[serde(rename = "familyWhy", default, skip_serializing_if = "Option::is_none")]
    pub family_why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overrides: Option<String>,
    #[serde(rename = "strictOverride", default, skip_serializing_if = "Option::is_none")]
    pub strict_override: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryRoleListSchema {
    #[serde(rename = "objectClasses", default, skip_serializing_if = "Option::is_none")]
    pub object_classes: Option<Vec<DirectoryRoleListSchemaObjectClassesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<DirectoryRoleListSchemaAttributesItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryRoleListRolesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub origin: Option<Option<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<String>>,
    #[serde(rename = "modifiedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub modified_at: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operational: Option<Vec<String>>,
    /// Attribute names, which are data in a schemaless directory, and values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryRoleListBuiltInCatalogueItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryRoleListPaging {
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
pub struct DirectoryRoleList {
    #[serde(rename = "baseDn", default, skip_serializing_if = "Option::is_none")]
    pub base_dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<DirectoryRoleListFilter>,
    #[serde(rename = "sourceOfTruth", default, skip_serializing_if = "Option::is_none")]
    pub source_of_truth: Option<String>,
    #[serde(rename = "builtIn", default, skip_serializing_if = "Option::is_none")]
    pub built_in: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<DirectoryRoleListSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<DirectoryRoleListRolesItem>>,
    #[serde(rename = "builtInCatalogue", default, skip_serializing_if = "Option::is_none")]
    pub built_in_catalogue: Option<Vec<DirectoryRoleListBuiltInCatalogueItem>>,
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
    pub paging: Option<DirectoryRoleListPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServicePersistenceDatabasePasswordSecretWhere {
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
    pub wraps: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticates: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServicePersistenceDatabasePasswordSecretProvidersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServicePersistenceDatabasePasswordSecret {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configured: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known: Option<bool>,
    #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
    pub where_: Option<DirectoryServicePersistenceDatabasePasswordSecretWhere>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub providers: Option<Vec<DirectoryServicePersistenceDatabasePasswordSecretProvidersItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServicePersistenceDatabase {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub host: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub port: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub database: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub user: Option<Option<String>>,
    #[serde(rename = "passwordFrom", default, skip_serializing_if = "Option::is_none")]
    pub password_from: Option<String>,
    #[serde(rename = "passwordProvider", default, skip_serializing_if = "Option::is_none")]
    pub password_provider: Option<String>,
    #[serde(rename = "passwordSecret", default, skip_serializing_if = "Option::is_none")]
    pub password_secret: Option<DirectoryServicePersistenceDatabasePasswordSecret>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sslmode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted: Option<bool>,
    #[serde(rename = "verifyCertificate", default, skip_serializing_if = "Option::is_none")]
    pub verify_certificate: Option<bool>,
    #[serde(rename = "caFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ca_file: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServicePersistenceRestored {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entries: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overrides: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServicePersistenceMintedHandlesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shape: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServicePersistenceMintedPoisonDropsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handles: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realms: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServicePersistenceMinted {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persisting: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supported: Option<bool>,
    #[serde(rename = "unsupportedReason", default, skip_serializing_if = "Option::is_none")]
    pub unsupported_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<bool>,
    #[serde(rename = "retentionMs", default, skip_serializing_if = "Option::is_none")]
    pub retention_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stores: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handles: Option<Vec<DirectoryServicePersistenceMintedHandlesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writes: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<f64>,
    #[serde(rename = "rowsWritten", default, skip_serializing_if = "Option::is_none")]
    pub rows_written: Option<f64>,
    #[serde(rename = "rowsDeleted", default, skip_serializing_if = "Option::is_none")]
    pub rows_deleted: Option<f64>,
    #[serde(rename = "lastWriteAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_write_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "lastError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_error: Option<Option<String>>,
    #[serde(rename = "restoredAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub restored_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restored: Option<f64>,
    #[serde(rename = "droppedUnreadable", default, skip_serializing_if = "Option::is_none")]
    pub dropped_unreadable: Option<f64>,
    #[serde(rename = "droppedUnknown", default, skip_serializing_if = "Option::is_none")]
    pub dropped_unknown: Option<f64>,
    #[serde(rename = "droppedPoison", default, skip_serializing_if = "Option::is_none")]
    pub dropped_poison: Option<f64>,
    #[serde(rename = "poisonDrops", default, skip_serializing_if = "Option::is_none")]
    pub poison_drops: Option<Vec<DirectoryServicePersistenceMintedPoisonDropsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServicePersistenceUsedAssertions {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub store: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub kind: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistent: Option<bool>,
    #[serde(rename = "atomicAcrossProcesses", default, skip_serializing_if = "Option::is_none")]
    pub atomic_across_processes: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub why: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub live: Option<Option<f64>>,
    #[serde(rename = "liveIsCurrent", default, skip_serializing_if = "Option::is_none")]
    pub live_is_current: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServicePersistenceReplicationRetentionLastTrim {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trimmed: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub bound: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readers: Option<f64>,
    #[serde(rename = "readersGone", default, skip_serializing_if = "Option::is_none")]
    pub readers_gone: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServicePersistenceReplicationRetention {
    #[serde(rename = "retentionS", default, skip_serializing_if = "Option::is_none")]
    pub retention_s: Option<f64>,
    #[serde(rename = "readerTtlS", default, skip_serializing_if = "Option::is_none")]
    pub reader_ttl_s: Option<f64>,
    #[serde(rename = "reportedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub reported_at: Option<Option<String>>,
    #[serde(rename = "reportError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub report_error: Option<Option<String>>,
    #[serde(rename = "declaredGoneAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub declared_gone_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "fanInGraceS", default, skip_serializing_if = "Option::is_none")]
    pub fan_in_grace_s: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trimming: Option<bool>,
    #[serde(rename = "lastTrim", default, skip_serializing_if = "Option::is_none")]
    pub last_trim: Option<DirectoryServicePersistenceReplicationRetentionLastTrim>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServicePersistenceReplication {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinating: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supported: Option<bool>,
    #[serde(rename = "startedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub started_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "appliedSeq", default, skip_serializing_if = "Option::is_none")]
    pub applied_seq: Option<f64>,
    #[serde(rename = "highestSeq", default, skip_serializing_if = "Option::is_none")]
    pub highest_seq: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holes: Option<f64>,
    #[serde(rename = "holeRanges", default, skip_serializing_if = "Option::is_none")]
    pub hole_ranges: Option<f64>,
    #[serde(rename = "holesAbandoned", default, skip_serializing_if = "Option::is_none")]
    pub holes_abandoned: Option<f64>,
    #[serde(rename = "pollIntervalMs", default, skip_serializing_if = "Option::is_none")]
    pub poll_interval_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pulls: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nudges: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<f64>,
    #[serde(rename = "rowsApplied", default, skip_serializing_if = "Option::is_none")]
    pub rows_applied: Option<f64>,
    /// A count per name.
    #[serde(rename = "byKind", default, skip_serializing_if = "Option::is_none")]
    pub by_kind: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "lastPullAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_pull_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "lastError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_error: Option<Option<String>>,
    #[serde(rename = "otherProcesses", default, skip_serializing_if = "Option::is_none")]
    pub other_processes: Option<f64>,
    #[serde(rename = "originsDropped", default, skip_serializing_if = "Option::is_none")]
    pub origins_dropped: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<DirectoryServicePersistenceReplicationRetention>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServicePersistenceCellsGlobalReplicationRetentionLastTrim {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trimmed: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub bound: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readers: Option<f64>,
    #[serde(rename = "readersGone", default, skip_serializing_if = "Option::is_none")]
    pub readers_gone: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServicePersistenceCellsGlobalReplicationRetention {
    #[serde(rename = "retentionS", default, skip_serializing_if = "Option::is_none")]
    pub retention_s: Option<f64>,
    #[serde(rename = "readerTtlS", default, skip_serializing_if = "Option::is_none")]
    pub reader_ttl_s: Option<f64>,
    #[serde(rename = "reportedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub reported_at: Option<Option<String>>,
    #[serde(rename = "reportError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub report_error: Option<Option<String>>,
    #[serde(rename = "declaredGoneAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub declared_gone_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "fanInGraceS", default, skip_serializing_if = "Option::is_none")]
    pub fan_in_grace_s: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trimming: Option<bool>,
    #[serde(rename = "lastTrim", default, skip_serializing_if = "Option::is_none")]
    pub last_trim: Option<DirectoryServicePersistenceCellsGlobalReplicationRetentionLastTrim>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServicePersistenceCellsGlobalReplication {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinating: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supported: Option<bool>,
    #[serde(rename = "startedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub started_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "appliedSeq", default, skip_serializing_if = "Option::is_none")]
    pub applied_seq: Option<f64>,
    #[serde(rename = "highestSeq", default, skip_serializing_if = "Option::is_none")]
    pub highest_seq: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holes: Option<f64>,
    #[serde(rename = "holeRanges", default, skip_serializing_if = "Option::is_none")]
    pub hole_ranges: Option<f64>,
    #[serde(rename = "holesAbandoned", default, skip_serializing_if = "Option::is_none")]
    pub holes_abandoned: Option<f64>,
    #[serde(rename = "pollIntervalMs", default, skip_serializing_if = "Option::is_none")]
    pub poll_interval_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pulls: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nudges: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<f64>,
    #[serde(rename = "rowsApplied", default, skip_serializing_if = "Option::is_none")]
    pub rows_applied: Option<f64>,
    /// A count per name.
    #[serde(rename = "byKind", default, skip_serializing_if = "Option::is_none")]
    pub by_kind: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "lastPullAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_pull_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "lastError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_error: Option<Option<String>>,
    #[serde(rename = "otherProcesses", default, skip_serializing_if = "Option::is_none")]
    pub other_processes: Option<f64>,
    #[serde(rename = "originsDropped", default, skip_serializing_if = "Option::is_none")]
    pub origins_dropped: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<DirectoryServicePersistenceCellsGlobalReplicationRetention>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServicePersistenceCellsRouting {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub indexed: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conflicts: Option<f64>,
    #[serde(rename = "lastConflict", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_conflict: Option<Option<String>>,
    #[serde(rename = "projectionWrites", default, skip_serializing_if = "Option::is_none")]
    pub projection_writes: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServicePersistenceCells {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub cell: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub jurisdiction: Option<Option<String>>,
    #[serde(rename = "globalReplication", default, skip_serializing_if = "Option::is_none")]
    pub global_replication: Option<DirectoryServicePersistenceCellsGlobalReplication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing: Option<DirectoryServicePersistenceCellsRouting>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServicePersistenceOrigin {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub origin: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adopted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServicePersistenceLiveness {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queries: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connects: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drops: Option<f64>,
    #[serde(rename = "viaPool", default, skip_serializing_if = "Option::is_none")]
    pub via_pool: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServicePersistenceEventLoopLastReport {
    #[serde(rename = "maxMs", default, skip_serializing_if = "Option::is_none")]
    pub max_ms: Option<f64>,
    #[serde(rename = "p99Ms", default, skip_serializing_if = "Option::is_none")]
    pub p99_ms: Option<f64>,
    #[serde(rename = "meanMs", default, skip_serializing_if = "Option::is_none")]
    pub mean_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServicePersistenceEventLoopSinceReport {
    #[serde(rename = "maxMs", default, skip_serializing_if = "Option::is_none")]
    pub max_ms: Option<f64>,
    #[serde(rename = "p99Ms", default, skip_serializing_if = "Option::is_none")]
    pub p99_ms: Option<f64>,
    #[serde(rename = "meanMs", default, skip_serializing_if = "Option::is_none")]
    pub mean_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServicePersistenceEventLoop {
    #[serde(rename = "lastReport", default, skip_serializing_if = "Option::is_none")]
    pub last_report: Option<DirectoryServicePersistenceEventLoopLastReport>,
    #[serde(rename = "sinceReport", default, skip_serializing_if = "Option::is_none")]
    pub since_report: Option<DirectoryServicePersistenceEventLoopSinceReport>,
    #[serde(rename = "warnAboveMs", default, skip_serializing_if = "Option::is_none")]
    pub warn_above_ms: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServicePersistence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(rename = "configuredMode", default, skip_serializing_if = "Option::is_none")]
    pub configured_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub healthy: Option<Option<bool>>,
    #[serde(rename = "dataDir", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub data_dir: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<DirectoryServicePersistenceDatabase>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub engine: Option<Option<String>>,
    #[serde(rename = "writeDelayMs", default, skip_serializing_if = "Option::is_none")]
    pub write_delay_ms: Option<f64>,
    #[serde(rename = "persistsDirectory", default, skip_serializing_if = "Option::is_none")]
    pub persists_directory: Option<bool>,
    #[serde(rename = "persistsRealms", default, skip_serializing_if = "Option::is_none")]
    pub persists_realms: Option<bool>,
    #[serde(rename = "persistsAppconfig", default, skip_serializing_if = "Option::is_none")]
    pub persists_appconfig: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writes: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<f64>,
    #[serde(rename = "lastWriteAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_write_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "lastError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_error: Option<Option<String>>,
    #[serde(rename = "restoredAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub restored_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restored: Option<DirectoryServicePersistenceRestored>,
    #[serde(rename = "entriesTracked", default, skip_serializing_if = "Option::is_none")]
    pub entries_tracked: Option<f64>,
    #[serde(rename = "realmsTracked", default, skip_serializing_if = "Option::is_none")]
    pub realms_tracked: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinates: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minted: Option<DirectoryServicePersistenceMinted>,
    #[serde(rename = "usedAssertions", default, skip_serializing_if = "Option::is_none")]
    pub used_assertions: Option<DirectoryServicePersistenceUsedAssertions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replication: Option<DirectoryServicePersistenceReplication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cells: Option<DirectoryServicePersistenceCells>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<DirectoryServicePersistenceOrigin>,
    #[serde(rename = "answersAfterCommit", default, skip_serializing_if = "Option::is_none")]
    pub answers_after_commit: Option<bool>,
    #[serde(rename = "commitBacklog", default, skip_serializing_if = "Option::is_none")]
    pub commit_backlog: Option<bool>,
    #[serde(rename = "retryArmed", default, skip_serializing_if = "Option::is_none")]
    pub retry_armed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liveness: Option<DirectoryServicePersistenceLiveness>,
    #[serde(rename = "eventLoop", default, skip_serializing_if = "Option::is_none")]
    pub event_loop: Option<DirectoryServicePersistenceEventLoop>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServiceTlsSaslExternal {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub available: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mechanisms: Option<Vec<String>>,
    #[serde(rename = "outsideCertificateAuthorities", default, skip_serializing_if = "Option::is_none")]
    pub outside_certificate_authorities: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServiceTlsCertificate {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub subject: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub names: Option<Option<Vec<serde_json::Value>>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub fingerprint256: Option<Option<String>>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub not_after: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServiceTls {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldaps: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub port: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listening: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error: Option<Option<String>>,
    #[serde(rename = "startTls", default, skip_serializing_if = "Option::is_none")]
    pub start_tls: Option<bool>,
    #[serde(rename = "clientCertificateMode", default, skip_serializing_if = "Option::is_none")]
    pub client_certificate_mode: Option<String>,
    #[serde(rename = "saslExternal", default, skip_serializing_if = "Option::is_none")]
    pub sasl_external: Option<DirectoryServiceTlsSaslExternal>,
    #[serde(rename = "clientCertificates", default, skip_serializing_if = "Option::is_none")]
    pub client_certificates: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<DirectoryServiceTlsCertificate>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServiceLimits {
    #[serde(rename = "maxEntries", default, skip_serializing_if = "Option::is_none")]
    pub max_entries: Option<f64>,
    #[serde(rename = "maxSearchResults", default, skip_serializing_if = "Option::is_none")]
    pub max_search_results: Option<f64>,
    #[serde(rename = "currentEntries", default, skip_serializing_if = "Option::is_none")]
    pub current_entries: Option<f64>,
    #[serde(rename = "currentEntriesEverywhere", default, skip_serializing_if = "Option::is_none")]
    pub current_entries_everywhere: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryService {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub port: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listening: Option<bool>,
    #[serde(rename = "listenError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub listen_error: Option<Option<String>>,
    #[serde(rename = "baseDn", default, skip_serializing_if = "Option::is_none")]
    pub base_dn: Option<String>,
    #[serde(rename = "usersDn", default, skip_serializing_if = "Option::is_none")]
    pub users_dn: Option<String>,
    #[serde(rename = "groupsDn", default, skip_serializing_if = "Option::is_none")]
    pub groups_dn: Option<String>,
    #[serde(rename = "namingContexts", default, skip_serializing_if = "Option::is_none")]
    pub naming_contexts: Option<Vec<String>>,
    #[serde(rename = "searchScope", default, skip_serializing_if = "Option::is_none")]
    pub search_scope: Option<String>,
    #[serde(rename = "ldapVersion", default, skip_serializing_if = "Option::is_none")]
    pub ldap_version: Option<i64>,
    #[serde(rename = "bindPolicy", default, skip_serializing_if = "Option::is_none")]
    pub bind_policy: Option<String>,
    #[serde(rename = "refusedPassword", default, skip_serializing_if = "Option::is_none")]
    pub refused_password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(rename = "referentialIntegrity", default, skip_serializing_if = "Option::is_none")]
    pub referential_integrity: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistence: Option<DirectoryServicePersistence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<DirectoryServiceTls>,
    #[serde(rename = "autoCreateUsers", default, skip_serializing_if = "Option::is_none")]
    pub auto_create_users: Option<bool>,
    #[serde(rename = "autoCreateRule", default, skip_serializing_if = "Option::is_none")]
    pub auto_create_rule: Option<String>,
    #[serde(rename = "authenticationFacts", default, skip_serializing_if = "Option::is_none")]
    pub authentication_facts: Option<String>,
    #[serde(rename = "enforcedRules", default, skip_serializing_if = "Option::is_none")]
    pub enforced_rules: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<DirectoryServiceLimits>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operations: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub specifications: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implementation: Option<String>,
    #[serde(rename = "ldapPort", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ldap_port: Option<Option<i64>>,
    #[serde(rename = "ldapsPort", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ldaps_port: Option<Option<i64>>,
    #[serde(rename = "certificateProvenance", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub certificate_provenance: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectorySpiffeSchemaObjectClassesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
    pub where_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standard: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectorySpiffeSchemaAttributesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standard: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitive: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<bool>,
    #[serde(rename = "identifierName", default, skip_serializing_if = "Option::is_none")]
    pub identifier_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<sts_model_base::unions::BoolOrString>,
    #[serde(rename = "enum", default, skip_serializing_if = "Option::is_none")]
    pub enum_: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub families: Option<Vec<String>>,
    #[serde(rename = "familyWhy", default, skip_serializing_if = "Option::is_none")]
    pub family_why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overrides: Option<String>,
    #[serde(rename = "strictOverride", default, skip_serializing_if = "Option::is_none")]
    pub strict_override: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectorySpiffeSchema {
    #[serde(rename = "objectClasses", default, skip_serializing_if = "Option::is_none")]
    pub object_classes: Option<Vec<DirectorySpiffeSchemaObjectClassesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<DirectorySpiffeSchemaAttributesItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectorySpiffeFilter {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub entryq: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub agentq: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectorySpiffeEntriesPaging {
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
pub struct DirectorySpiffeAgentsPaging {
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
pub struct DirectorySpiffeRegistrationEntriesItemSelectorsItem {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectorySpiffeRegistrationEntriesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(rename = "spiffeId", default, skip_serializing_if = "Option::is_none")]
    pub spiffe_id: Option<String>,
    #[serde(rename = "parentId", default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selectors: Option<Vec<DirectorySpiffeRegistrationEntriesItemSelectorsItem>>,
    #[serde(rename = "selectorTexts", default, skip_serializing_if = "Option::is_none")]
    pub selector_texts: Option<Vec<String>>,
    #[serde(rename = "x509SvidTtl", default, skip_serializing_if = "Option::is_none")]
    pub x509_svid_ttl: Option<f64>,
    #[serde(rename = "jwtSvidTtl", default, skip_serializing_if = "Option::is_none")]
    pub jwt_svid_ttl: Option<f64>,
    #[serde(rename = "dnsNames", default, skip_serializing_if = "Option::is_none")]
    pub dns_names: Option<Vec<String>>,
    #[serde(rename = "federatesWith", default, skip_serializing_if = "Option::is_none")]
    pub federates_with: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub downstream: Option<bool>,
    #[serde(rename = "storeSvid", default, skip_serializing_if = "Option::is_none")]
    pub store_svid: Option<bool>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    #[serde(rename = "revisionNumber", default, skip_serializing_if = "Option::is_none")]
    pub revision_number: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(rename = "svidsIssued", default, skip_serializing_if = "Option::is_none")]
    pub svids_issued: Option<f64>,
    #[serde(rename = "lastSvidAt", default, skip_serializing_if = "Option::is_none")]
    pub last_svid_at: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(rename = "modifiedAt", default, skip_serializing_if = "Option::is_none")]
    pub modified_at: Option<String>,
    /// Attribute names, which are data in a schemaless directory, and values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectorySpiffeAttestedAgentsItemSelectorsItem {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectorySpiffeAttestedAgentsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(rename = "attestationType", default, skip_serializing_if = "Option::is_none")]
    pub attestation_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selectors: Option<Vec<DirectorySpiffeAttestedAgentsItemSelectorsItem>>,
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
    /// Attribute names, which are data in a schemaless directory, and values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectorySpiffe {
    #[serde(rename = "baseDn", default, skip_serializing_if = "Option::is_none")]
    pub base_dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    #[serde(rename = "entriesContainer", default, skip_serializing_if = "Option::is_none")]
    pub entries_container: Option<String>,
    #[serde(rename = "agentsContainer", default, skip_serializing_if = "Option::is_none")]
    pub agents_container: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entries: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agents: Option<i64>,
    #[serde(rename = "maxEntries", default, skip_serializing_if = "Option::is_none")]
    pub max_entries: Option<i64>,
    #[serde(rename = "maxAgents", default, skip_serializing_if = "Option::is_none")]
    pub max_agents: Option<i64>,
    #[serde(rename = "sourceOfTruth", default, skip_serializing_if = "Option::is_none")]
    pub source_of_truth: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<DirectorySpiffeSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<DirectorySpiffeFilter>,
    #[serde(rename = "entriesPaging", default, skip_serializing_if = "Option::is_none")]
    pub entries_paging: Option<DirectorySpiffeEntriesPaging>,
    #[serde(rename = "agentsPaging", default, skip_serializing_if = "Option::is_none")]
    pub agents_paging: Option<DirectorySpiffeAgentsPaging>,
    #[serde(rename = "registrationEntries", default, skip_serializing_if = "Option::is_none")]
    pub registration_entries: Option<Vec<DirectorySpiffeRegistrationEntriesItem>>,
    #[serde(rename = "attestedAgents", default, skip_serializing_if = "Option::is_none")]
    pub attested_agents: Option<Vec<DirectorySpiffeAttestedAgentsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

pub type EditableValue = bool;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndedValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminated: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notifications: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backchannel: Option<crate::WithAdditionalPropertiesPropertiesEnded>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryValue {
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<sts_model_base::unions::NumberOrString>,
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
pub struct EntryValue2 {
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

pub type ExchangePerRightVerdictRole = serde_json::Value;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListFilter {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub q: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub role: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub category: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListSettingsGroupsItemSettingsItemSelectAllOnlyWhileOnItem {
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
pub struct FederationRelationshipListSettingsGroupsItemSettingsItemSelectAllAloneWhileOnItem {
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
pub struct FederationRelationshipListSettingsGroupsItemSettingsItemSelectAll {
    #[serde(rename = "onlyWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub only_while_on: Option<Vec<FederationRelationshipListSettingsGroupsItemSettingsItemSelectAllOnlyWhileOnItem>>,
    #[serde(rename = "aloneWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub alone_while_on: Option<Vec<FederationRelationshipListSettingsGroupsItemSettingsItemSelectAllAloneWhileOnItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum FederationRelationshipListSettingsGroupsItemSettingsItemValue {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum FederationRelationshipListSettingsGroupsItemSettingsItemEnv {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum FederationRelationshipListSettingsGroupsItemSettingsItemLegacyEnv {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum FederationRelationshipListSettingsGroupsItemSettingsItemDefault {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListSettingsGroupsItemSettingsItem {
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
    pub select_all: Option<FederationRelationshipListSettingsGroupsItemSettingsItemSelectAll>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<FederationRelationshipListSettingsGroupsItemSettingsItemValue>>,
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
    pub env: Option<FederationRelationshipListSettingsGroupsItemSettingsItemEnv>,
    #[serde(rename = "legacyEnv", default, skip_serializing_if = "Option::is_none")]
    pub legacy_env: Option<FederationRelationshipListSettingsGroupsItemSettingsItemLegacyEnv>,
    #[serde(rename = "appconfigPath", default, skip_serializing_if = "Option::is_none")]
    pub appconfig_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default: Option<Option<FederationRelationshipListSettingsGroupsItemSettingsItemDefault>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListSettingsGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<FederationRelationshipListSettingsGroupsItemSettingsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListSettingsContext {
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
pub struct FederationRelationshipListSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<FederationRelationshipListSettingsGroupsItem>>,
    #[serde(rename = "settingCount", default, skip_serializing_if = "Option::is_none")]
    pub setting_count: Option<i64>,
    #[serde(rename = "editableCount", default, skip_serializing_if = "Option::is_none")]
    pub editable_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<Vec<String>>,
    #[serde(rename = "setWith", default, skip_serializing_if = "Option::is_none")]
    pub set_with: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<FederationRelationshipListSettingsContext>,
    #[serde(rename = "sharedWith", default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListRolesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListProtocolsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub needs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<String>,
    #[serde(rename = "signalsOnly", default, skip_serializing_if = "Option::is_none")]
    pub signals_only: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListPaths {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notifications: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stepup: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slo: Option<String>,
    #[serde(rename = "backchannelLogout", default, skip_serializing_if = "Option::is_none")]
    pub backchannel_logout: Option<String>,
    #[serde(rename = "frontchannelLogout", default, skip_serializing_if = "Option::is_none")]
    pub frontchannel_logout: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<String>,
    #[serde(rename = "atprotoClient", default, skip_serializing_if = "Option::is_none")]
    pub atproto_client: Option<String>,
    #[serde(rename = "initiateLogin", default, skip_serializing_if = "Option::is_none")]
    pub initiate_login: Option<String>,
    #[serde(rename = "fragmentScript", default, skip_serializing_if = "Option::is_none")]
    pub fragment_script: Option<String>,
    #[serde(rename = "requestObject", default, skip_serializing_if = "Option::is_none")]
    pub request_object: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webfinger: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signals: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListPaging {
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
pub struct FederationRelationshipListConsumerProvidersCatalogueItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generic: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub defaults: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub needs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapters: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(rename = "emailVerified", default, skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListConsumerProviders {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalogue: Option<Vec<FederationRelationshipListConsumerProvidersCatalogueItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListRelationshipsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(rename = "roleLabel", default, skip_serializing_if = "Option::is_none")]
    pub role_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(rename = "protocolLabel", default, skip_serializing_if = "Option::is_none")]
    pub protocol_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(rename = "providerLabel", default, skip_serializing_if = "Option::is_none")]
    pub provider_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usable: Option<bool>,
    #[serde(rename = "signsIn", default, skip_serializing_if = "Option::is_none")]
    pub signs_in: Option<bool>,
    #[serde(rename = "signalsEnabled", default, skip_serializing_if = "Option::is_none")]
    pub signals_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub releases: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mappings: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentications: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<i64>,
    #[serde(rename = "lastUser", default, skip_serializing_if = "Option::is_none")]
    pub last_user: Option<String>,
    #[serde(rename = "lastSeen", default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    #[serde(rename = "lastError", default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(rename = "lastErrorAt", default, skip_serializing_if = "Option::is_none")]
    pub last_error_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListProviderV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docs: Option<String>,
    #[serde(rename = "realmOn", default, skip_serializing_if = "Option::is_none")]
    pub realm_on: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum FederationRelationshipListProvider {
    V1(FederationRelationshipListProviderV1),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListEndpoints {
    #[serde(rename = "assertionConsumerService", default, skip_serializing_if = "Option::is_none")]
    pub assertion_consumer_service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub metadata: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub jwks: Option<Option<String>>,
    #[serde(rename = "initiateLogin", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub initiate_login: Option<Option<String>>,
    #[serde(rename = "singleLogout", default, skip_serializing_if = "Option::is_none")]
    pub single_logout: Option<String>,
    #[serde(rename = "signOutCleanup", default, skip_serializing_if = "Option::is_none")]
    pub sign_out_cleanup: Option<String>,
    #[serde(rename = "backchannelLogout", default, skip_serializing_if = "Option::is_none")]
    pub backchannel_logout: Option<String>,
    #[serde(rename = "frontchannelLogout", default, skip_serializing_if = "Option::is_none")]
    pub frontchannel_logout: Option<String>,
    #[serde(rename = "postLogoutRedirect", default, skip_serializing_if = "Option::is_none")]
    pub post_logout_redirect: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListFields {
    #[serde(rename = "fedId", default, skip_serializing_if = "Option::is_none")]
    pub fed_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cn: Option<String>,
    #[serde(rename = "fedName", default, skip_serializing_if = "Option::is_none")]
    pub fed_name: Option<String>,
    #[serde(rename = "fedRole", default, skip_serializing_if = "Option::is_none")]
    pub fed_role: Option<String>,
    #[serde(rename = "fedProtocol", default, skip_serializing_if = "Option::is_none")]
    pub fed_protocol: Option<String>,
    #[serde(rename = "fedProvider", default, skip_serializing_if = "Option::is_none")]
    pub fed_provider: Option<String>,
    #[serde(rename = "fedPeer", default, skip_serializing_if = "Option::is_none")]
    pub fed_peer: Option<String>,
    #[serde(rename = "fedLocalEntityId", default, skip_serializing_if = "Option::is_none")]
    pub fed_local_entity_id: Option<String>,
    #[serde(rename = "fedEnabled", default, skip_serializing_if = "Option::is_none")]
    pub fed_enabled: Option<String>,
    #[serde(rename = "fedSsoUrl", default, skip_serializing_if = "Option::is_none")]
    pub fed_sso_url: Option<String>,
    #[serde(rename = "fedTokenUrl", default, skip_serializing_if = "Option::is_none")]
    pub fed_token_url: Option<String>,
    #[serde(rename = "fedUserinfoUrl", default, skip_serializing_if = "Option::is_none")]
    pub fed_userinfo_url: Option<String>,
    #[serde(rename = "fedJwksUri", default, skip_serializing_if = "Option::is_none")]
    pub fed_jwks_uri: Option<String>,
    #[serde(rename = "fedEmailsUrl", default, skip_serializing_if = "Option::is_none")]
    pub fed_emails_url: Option<String>,
    #[serde(rename = "fedJwks", default, skip_serializing_if = "Option::is_none")]
    pub fed_jwks: Option<String>,
    #[serde(rename = "fedTrustAnchor", default, skip_serializing_if = "Option::is_none")]
    pub fed_trust_anchor: Option<String>,
    #[serde(rename = "fedSigningCertificate", default, skip_serializing_if = "Option::is_none")]
    pub fed_signing_certificate: Option<String>,
    #[serde(rename = "fedClientId", default, skip_serializing_if = "Option::is_none")]
    pub fed_client_id: Option<String>,
    #[serde(rename = "fedClientSecret", default, skip_serializing_if = "Option::is_none")]
    pub fed_client_secret: Option<String>,
    #[serde(rename = "fedResponseMode", default, skip_serializing_if = "Option::is_none")]
    pub fed_response_mode: Option<String>,
    #[serde(rename = "fedTeamId", default, skip_serializing_if = "Option::is_none")]
    pub fed_team_id: Option<String>,
    #[serde(rename = "fedKeyId", default, skip_serializing_if = "Option::is_none")]
    pub fed_key_id: Option<String>,
    #[serde(rename = "fedClientSigningKey", default, skip_serializing_if = "Option::is_none")]
    pub fed_client_signing_key: Option<String>,
    #[serde(rename = "fedTokenAuth", default, skip_serializing_if = "Option::is_none")]
    pub fed_token_auth: Option<String>,
    #[serde(rename = "fedScope", default, skip_serializing_if = "Option::is_none")]
    pub fed_scope: Option<String>,
    #[serde(rename = "fedResponseType", default, skip_serializing_if = "Option::is_none")]
    pub fed_response_type: Option<String>,
    #[serde(rename = "fedIdTokenSignedResponseAlg", default, skip_serializing_if = "Option::is_none")]
    pub fed_id_token_signed_response_alg: Option<String>,
    #[serde(rename = "fedUserinfoSignedResponseAlg", default, skip_serializing_if = "Option::is_none")]
    pub fed_userinfo_signed_response_alg: Option<String>,
    #[serde(rename = "fedUserinfo", default, skip_serializing_if = "Option::is_none")]
    pub fed_userinfo: Option<String>,
    #[serde(rename = "fedRefreshTokens", default, skip_serializing_if = "Option::is_none")]
    pub fed_refresh_tokens: Option<String>,
    #[serde(rename = "fedRefreshEverySeconds", default, skip_serializing_if = "Option::is_none")]
    pub fed_refresh_every_seconds: Option<String>,
    #[serde(rename = "fedRegister", default, skip_serializing_if = "Option::is_none")]
    pub fed_register: Option<String>,
    #[serde(rename = "fedRegisteredIssuer", default, skip_serializing_if = "Option::is_none")]
    pub fed_registered_issuer: Option<String>,
    #[serde(rename = "fedRequestObject", default, skip_serializing_if = "Option::is_none")]
    pub fed_request_object: Option<String>,
    #[serde(rename = "fedRequestObjectSigningAlg", default, skip_serializing_if = "Option::is_none")]
    pub fed_request_object_signing_alg: Option<String>,
    #[serde(rename = "fedWebFinger", default, skip_serializing_if = "Option::is_none")]
    pub fed_web_finger: Option<String>,
    #[serde(rename = "fedDiscovery", default, skip_serializing_if = "Option::is_none")]
    pub fed_discovery: Option<String>,
    #[serde(rename = "fedFapi", default, skip_serializing_if = "Option::is_none")]
    pub fed_fapi: Option<String>,
    #[serde(rename = "fedInitiateLogin", default, skip_serializing_if = "Option::is_none")]
    pub fed_initiate_login: Option<String>,
    #[serde(rename = "fedBinding", default, skip_serializing_if = "Option::is_none")]
    pub fed_binding: Option<String>,
    #[serde(rename = "fedSignRequest", default, skip_serializing_if = "Option::is_none")]
    pub fed_sign_request: Option<String>,
    #[serde(rename = "fedUsernameSource", default, skip_serializing_if = "Option::is_none")]
    pub fed_username_source: Option<String>,
    #[serde(rename = "fedSubjectClaim", default, skip_serializing_if = "Option::is_none")]
    pub fed_subject_claim: Option<String>,
    #[serde(rename = "fedAutocreateUsers", default, skip_serializing_if = "Option::is_none")]
    pub fed_autocreate_users: Option<String>,
    #[serde(rename = "fedUpdateUserAttributes", default, skip_serializing_if = "Option::is_none")]
    pub fed_update_user_attributes: Option<String>,
    #[serde(rename = "fedProvisionGroups", default, skip_serializing_if = "Option::is_none")]
    pub fed_provision_groups: Option<String>,
    #[serde(rename = "fedProvisionCap", default, skip_serializing_if = "Option::is_none")]
    pub fed_provision_cap: Option<String>,
    #[serde(rename = "fedProvisionIdleMinutes", default, skip_serializing_if = "Option::is_none")]
    pub fed_provision_idle_minutes: Option<String>,
    #[serde(rename = "fedSubjectPolicy", default, skip_serializing_if = "Option::is_none")]
    pub fed_subject_policy: Option<String>,
    #[serde(rename = "fedSubjectPattern", default, skip_serializing_if = "Option::is_none")]
    pub fed_subject_pattern: Option<String>,
    #[serde(rename = "fedMayAssertAdministrators", default, skip_serializing_if = "Option::is_none")]
    pub fed_may_assert_administrators: Option<String>,
    #[serde(rename = "fedSignalEmailMatch", default, skip_serializing_if = "Option::is_none")]
    pub fed_signal_email_match: Option<String>,
    #[serde(rename = "fedSignalsEnabled", default, skip_serializing_if = "Option::is_none")]
    pub fed_signals_enabled: Option<String>,
    #[serde(rename = "fedSignalsIssuer", default, skip_serializing_if = "Option::is_none")]
    pub fed_signals_issuer: Option<String>,
    #[serde(rename = "fedSignalsDelivery", default, skip_serializing_if = "Option::is_none")]
    pub fed_signals_delivery: Option<String>,
    #[serde(rename = "fedSignalsTokenUrl", default, skip_serializing_if = "Option::is_none")]
    pub fed_signals_token_url: Option<String>,
    #[serde(rename = "fedSignalsClientId", default, skip_serializing_if = "Option::is_none")]
    pub fed_signals_client_id: Option<String>,
    #[serde(rename = "fedSignalsClientSecret", default, skip_serializing_if = "Option::is_none")]
    pub fed_signals_client_secret: Option<String>,
    #[serde(rename = "fedSignalsScope", default, skip_serializing_if = "Option::is_none")]
    pub fed_signals_scope: Option<String>,
    #[serde(rename = "fedSignalsBearer", default, skip_serializing_if = "Option::is_none")]
    pub fed_signals_bearer: Option<String>,
    #[serde(rename = "fedSloUrl", default, skip_serializing_if = "Option::is_none")]
    pub fed_slo_url: Option<String>,
    #[serde(rename = "fedSloBinding", default, skip_serializing_if = "Option::is_none")]
    pub fed_slo_binding: Option<String>,
    #[serde(rename = "fedEndSessionUrl", default, skip_serializing_if = "Option::is_none")]
    pub fed_end_session_url: Option<String>,
    #[serde(rename = "fedAcceptSignout", default, skip_serializing_if = "Option::is_none")]
    pub fed_accept_signout: Option<String>,
    #[serde(rename = "fedRequireSignedLogout", default, skip_serializing_if = "Option::is_none")]
    pub fed_require_signed_logout: Option<String>,
    #[serde(rename = "fedEncryptionKeyType", default, skip_serializing_if = "Option::is_none")]
    pub fed_encryption_key_type: Option<String>,
    #[serde(rename = "fedKeyManagementAlgorithm", default, skip_serializing_if = "Option::is_none")]
    pub fed_key_management_algorithm: Option<String>,
    #[serde(rename = "fedContentEncryptionAlgorithm", default, skip_serializing_if = "Option::is_none")]
    pub fed_content_encryption_algorithm: Option<String>,
    #[serde(rename = "fedAllowUnencrypted", default, skip_serializing_if = "Option::is_none")]
    pub fed_allow_unencrypted: Option<String>,
    #[serde(rename = "fedClientCertificate", default, skip_serializing_if = "Option::is_none")]
    pub fed_client_certificate: Option<String>,
    #[serde(rename = "fedAllowUnsolicited", default, skip_serializing_if = "Option::is_none")]
    pub fed_allow_unsolicited: Option<String>,
    #[serde(rename = "fedApplication", default, skip_serializing_if = "Option::is_none")]
    pub fed_application: Option<String>,
    #[serde(rename = "fedAuthnMechanism", default, skip_serializing_if = "Option::is_none")]
    pub fed_authn_mechanism: Option<String>,
    #[serde(rename = "fedAuthnRelationship", default, skip_serializing_if = "Option::is_none")]
    pub fed_authn_relationship: Option<String>,
    #[serde(rename = "fedFirstSeen", default, skip_serializing_if = "Option::is_none")]
    pub fed_first_seen: Option<String>,
    #[serde(rename = "fedLastSeen", default, skip_serializing_if = "Option::is_none")]
    pub fed_last_seen: Option<String>,
    #[serde(rename = "fedAuthentications", default, skip_serializing_if = "Option::is_none")]
    pub fed_authentications: Option<String>,
    #[serde(rename = "fedUsers", default, skip_serializing_if = "Option::is_none")]
    pub fed_users: Option<String>,
    #[serde(rename = "fedLastUser", default, skip_serializing_if = "Option::is_none")]
    pub fed_last_user: Option<String>,
    #[serde(rename = "fedLastError", default, skip_serializing_if = "Option::is_none")]
    pub fed_last_error: Option<String>,
    #[serde(rename = "fedLastErrorAt", default, skip_serializing_if = "Option::is_none")]
    pub fed_last_error_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Vec<String>>,
    #[serde(rename = "fedAllowedTenants", default, skip_serializing_if = "Option::is_none")]
    pub fed_allowed_tenants: Option<Vec<String>>,
    #[serde(rename = "fedAuthorizeParams", default, skip_serializing_if = "Option::is_none")]
    pub fed_authorize_params: Option<Vec<String>>,
    #[serde(rename = "fedAttributeMap", default, skip_serializing_if = "Option::is_none")]
    pub fed_attribute_map: Option<Vec<String>>,
    #[serde(rename = "fedSubjectGroup", default, skip_serializing_if = "Option::is_none")]
    pub fed_subject_group: Option<Vec<String>>,
    #[serde(rename = "fedSubjectDomain", default, skip_serializing_if = "Option::is_none")]
    pub fed_subject_domain: Option<Vec<String>>,
    #[serde(rename = "fedHomeRealmDomain", default, skip_serializing_if = "Option::is_none")]
    pub fed_home_realm_domain: Option<Vec<String>>,
    #[serde(rename = "fedSignalsEvents", default, skip_serializing_if = "Option::is_none")]
    pub fed_signals_events: Option<Vec<String>>,
    #[serde(rename = "fedEncryptionKey", default, skip_serializing_if = "Option::is_none")]
    pub fed_encryption_key: Option<String>,
    #[serde(rename = "fedRelease", default, skip_serializing_if = "Option::is_none")]
    pub fed_release: Option<Vec<String>>,
    #[serde(rename = "fedApplicationUse", default, skip_serializing_if = "Option::is_none")]
    pub fed_application_use: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListEditableItem {
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
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListUnmappedAttributesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListSignalsCredential {
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
pub struct FederationRelationshipListSignalsConfig {
    /// A value of a document a partner published or answered, kept and relayed
    /// as it arrived: nothing here narrows it, and a partner's odd value must
    /// not turn an operator's own page into a failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<serde_json::Value>,
    /// A value of a document a partner published or answered, kept and relayed
    /// as it arrived: nothing here narrows it, and a partner's odd value must
    /// not turn an operator's own page into a failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<serde_json::Value>,
    /// A value of a document a partner published or answered, kept and relayed
    /// as it arrived: nothing here narrows it, and a partner's odd value must
    /// not turn an operator's own page into a failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration_endpoint: Option<serde_json::Value>,
    /// A value of a document a partner published or answered, kept and relayed
    /// as it arrived: nothing here narrows it, and a partner's odd value must
    /// not turn an operator's own page into a failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_endpoint: Option<serde_json::Value>,
    /// A value of a document a partner published or answered, kept and relayed
    /// as it arrived: nothing here narrows it, and a partner's odd value must
    /// not turn an operator's own page into a failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub add_subject_endpoint: Option<serde_json::Value>,
    /// A value of a document a partner published or answered, kept and relayed
    /// as it arrived: nothing here narrows it, and a partner's odd value must
    /// not turn an operator's own page into a failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remove_subject_endpoint: Option<serde_json::Value>,
    /// A value of a document a partner published or answered, kept and relayed
    /// as it arrived: nothing here narrows it, and a partner's odd value must
    /// not turn an operator's own page into a failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_endpoint: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_methods_supported: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListSignalsStreamDelivery {
    /// A value of a document a partner published or answered, kept and relayed
    /// as it arrived: nothing here narrows it, and a partner's odd value must
    /// not turn an operator's own page into a failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<serde_json::Value>,
    /// A value of a document a partner published or answered, kept and relayed
    /// as it arrived: nothing here narrows it, and a partner's odd value must
    /// not turn an operator's own page into a failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_url: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListSignalsStream {
    /// A value of a document a partner published or answered, kept and relayed
    /// as it arrived: nothing here narrows it, and a partner's odd value must
    /// not turn an operator's own page into a failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<serde_json::Value>,
    /// A value of a document a partner published or answered, kept and relayed
    /// as it arrived: nothing here narrows it, and a partner's odd value must
    /// not turn an operator's own page into a failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<serde_json::Value>,
    /// A value of a document a partner published or answered, kept and relayed
    /// as it arrived: nothing here narrows it, and a partner's odd value must
    /// not turn an operator's own page into a failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_supported: Option<serde_json::Value>,
    /// A value of a document a partner published or answered, kept and relayed
    /// as it arrived: nothing here narrows it, and a partner's odd value must
    /// not turn an operator's own page into a failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_requested: Option<serde_json::Value>,
    /// A value of a document a partner published or answered, kept and relayed
    /// as it arrived: nothing here narrows it, and a partner's odd value must
    /// not turn an operator's own page into a failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_delivered: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<FederationRelationshipListSignalsStreamDelivery>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListSignalsCounts {
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
pub struct FederationRelationshipListSignalsBlocksItem {
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

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListSignals {
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
    pub credential: Option<FederationRelationshipListSignalsCredential>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<FederationRelationshipListSignalsConfig>,
    #[serde(rename = "discoveryUrl", default, skip_serializing_if = "Option::is_none")]
    pub discovery_url: Option<String>,
    #[serde(rename = "discoveredAt", default, skip_serializing_if = "Option::is_none")]
    pub discovered_at: Option<String>,
    #[serde(rename = "streamId", default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<FederationRelationshipListSignalsStream>,
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
    pub counts: Option<FederationRelationshipListSignalsCounts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocks: Option<Vec<FederationRelationshipListSignalsBlocksItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListSignalArrivalsItemReactionsItem {
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

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListSignalArrivalsItem {
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
    pub reactions: Option<Vec<FederationRelationshipListSignalArrivalsItemReactionsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListOutboundSignalsStreamsItem {
    #[serde(rename = "streamId", default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(rename = "eventsDelivered", default, skip_serializing_if = "Option::is_none")]
    pub events_delivered: Option<Vec<String>>,
    #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    #[serde(rename = "lastActivityAt", default, skip_serializing_if = "Option::is_none")]
    pub last_activity_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead: Option<bool>,
    #[serde(rename = "deadLetters", default, skip_serializing_if = "Option::is_none")]
    pub dead_letters: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListOutboundSignals {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<Vec<FederationRelationshipListOutboundSignalsStreamsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListEncryptionPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(rename = "keyType", default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListEncryptionJwk {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kty: Option<String>,
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
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
    pub ek: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
    #[serde(rename = "x5t#S256", default, skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListEncryptionKeysItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(rename = "keyType", default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub not_after: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "retiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub retires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decrypts: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListEncryption {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<FederationRelationshipListEncryptionPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(rename = "allowUnencrypted", default, skip_serializing_if = "Option::is_none")]
    pub allow_unencrypted: Option<bool>,
    #[serde(rename = "graceS", default, skip_serializing_if = "Option::is_none")]
    pub grace_s: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<String>,
    #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
    pub certificate_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwk: Option<FederationRelationshipListEncryptionJwk>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<FederationRelationshipListEncryptionKeysItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListClientCertificate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<bool>,
    #[serde(rename = "tokenAuth", default, skip_serializing_if = "Option::is_none")]
    pub token_auth: Option<String>,
    #[serde(rename = "renewDays", default, skip_serializing_if = "Option::is_none")]
    pub renew_days: Option<f64>,
    #[serde(rename = "certificatePem", default, skip_serializing_if = "Option::is_none")]
    pub certificate_pem: Option<String>,
    #[serde(rename = "chainPem", default, skip_serializing_if = "Option::is_none")]
    pub chain_pem: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(rename = "x5tS256", default, skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,
    #[serde(rename = "serialHex", default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(rename = "renewsAt", default, skip_serializing_if = "Option::is_none")]
    pub renews_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListLinksItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListLinksPaging {
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
pub struct FederationRelationshipListSetFieldsItem {
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
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListMultiFieldsItem {
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
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListSignalSetFieldsItem {
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
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListSchemaItem {
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
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListSignOut {
    #[serde(rename = "singleLogout", default, skip_serializing_if = "Option::is_none")]
    pub single_logout: Option<String>,
    #[serde(rename = "signOutCleanup", default, skip_serializing_if = "Option::is_none")]
    pub sign_out_cleanup: Option<String>,
    #[serde(rename = "backchannelLogout", default, skip_serializing_if = "Option::is_none")]
    pub backchannel_logout: Option<String>,
    #[serde(rename = "frontchannelLogout", default, skip_serializing_if = "Option::is_none")]
    pub frontchannel_logout: Option<String>,
    #[serde(rename = "postLogoutRedirect", default, skip_serializing_if = "Option::is_none")]
    pub post_logout_redirect: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum FederationRelationshipListProtocolEndpointsItemMethods {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationRelationshipListProtocolEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<FederationRelationshipListProtocolEndpointsItemMethods>,
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
pub struct FederationRelationshipList {
    #[serde(rename = "relationshipCount", default, skip_serializing_if = "Option::is_none")]
    pub relationship_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready: Option<sts_model_base::unions::BoolOrInteger>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<FederationRelationshipListFilter>,
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
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub container: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<FederationRelationshipListSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<FederationRelationshipListRolesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<FederationRelationshipListProtocolsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<FederationRelationshipListPaths>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<FederationRelationshipListPaging>,
    #[serde(rename = "roleCounts", default, skip_serializing_if = "Option::is_none")]
    pub role_counts: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "categoryCounts", default, skip_serializing_if = "Option::is_none")]
    pub category_counts: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "consumerProviders", default, skip_serializing_if = "Option::is_none")]
    pub consumer_providers: Option<FederationRelationshipListConsumerProviders>,
    #[serde(rename = "enabledNotConfigured", default, skip_serializing_if = "Option::is_none")]
    pub enabled_not_configured: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentications: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationships: Option<Vec<FederationRelationshipListRelationshipsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub found: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(rename = "roleLabel", default, skip_serializing_if = "Option::is_none")]
    pub role_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(rename = "protocolLabel", default, skip_serializing_if = "Option::is_none")]
    pub protocol_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub provider: Option<Option<FederationRelationshipListProvider>>,
    #[serde(rename = "providerLabel", default, skip_serializing_if = "Option::is_none")]
    pub provider_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usable: Option<bool>,
    #[serde(rename = "signsIn", default, skip_serializing_if = "Option::is_none")]
    pub signs_in: Option<bool>,
    #[serde(rename = "signalsEnabled", default, skip_serializing_if = "Option::is_none")]
    pub signals_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub releases: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mappings: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<i64>,
    #[serde(rename = "lastUser", default, skip_serializing_if = "Option::is_none")]
    pub last_user: Option<String>,
    #[serde(rename = "lastSeen", default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    #[serde(rename = "lastError", default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(rename = "lastErrorAt", default, skip_serializing_if = "Option::is_none")]
    pub last_error_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<FederationRelationshipListEndpoints>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<FederationRelationshipListFields>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<Vec<FederationRelationshipListEditableItem>>,
    #[serde(rename = "unmappedAttributes", default, skip_serializing_if = "Option::is_none")]
    pub unmapped_attributes: Option<Vec<FederationRelationshipListUnmappedAttributesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signals: Option<FederationRelationshipListSignals>,
    #[serde(rename = "signalArrivals", default, skip_serializing_if = "Option::is_none")]
    pub signal_arrivals: Option<Vec<FederationRelationshipListSignalArrivalsItem>>,
    #[serde(rename = "outboundSignals", default, skip_serializing_if = "Option::is_none")]
    pub outbound_signals: Option<FederationRelationshipListOutboundSignals>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<FederationRelationshipListEncryption>,
    #[serde(rename = "clientCertificate", default, skip_serializing_if = "Option::is_none")]
    pub client_certificate: Option<FederationRelationshipListClientCertificate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<FederationRelationshipListLinksItem>>,
    #[serde(rename = "linksPaging", default, skip_serializing_if = "Option::is_none")]
    pub links_paging: Option<FederationRelationshipListLinksPaging>,
    #[serde(rename = "setFields", default, skip_serializing_if = "Option::is_none")]
    pub set_fields: Option<Vec<FederationRelationshipListSetFieldsItem>>,
    #[serde(rename = "multiFields", default, skip_serializing_if = "Option::is_none")]
    pub multi_fields: Option<Vec<FederationRelationshipListMultiFieldsItem>>,
    #[serde(rename = "signalSetFields", default, skip_serializing_if = "Option::is_none")]
    pub signal_set_fields: Option<Vec<FederationRelationshipListSignalSetFieldsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<Vec<FederationRelationshipListSchemaItem>>,
    #[serde(rename = "enumLabels", default, skip_serializing_if = "Option::is_none")]
    pub enum_labels: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "defaultSubjectPolicy", default, skip_serializing_if = "Option::is_none")]
    pub default_subject_policy: Option<String>,
    #[serde(rename = "autocreateDefault", default, skip_serializing_if = "Option::is_none")]
    pub autocreate_default: Option<bool>,
    #[serde(rename = "subjectPolicy", default, skip_serializing_if = "Option::is_none")]
    pub subject_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypts: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    #[serde(rename = "loginHref", default, skip_serializing_if = "Option::is_none")]
    pub login_href: Option<String>,
    #[serde(rename = "metadataUrl", default, skip_serializing_if = "Option::is_none")]
    pub metadata_url: Option<String>,
    #[serde(rename = "signOut", default, skip_serializing_if = "Option::is_none")]
    pub sign_out: Option<FederationRelationshipListSignOut>,
    #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
    pub protocol_endpoints: Option<Vec<FederationRelationshipListProtocolEndpointsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForestTrustInfoValueDomainsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(rename = "dnsName", default, skip_serializing_if = "Option::is_none")]
    pub dns_name: Option<String>,
    #[serde(rename = "netbiosName", default, skip_serializing_if = "Option::is_none")]
    pub netbios_name: Option<String>,
    #[serde(rename = "sidEnabled", default, skip_serializing_if = "Option::is_none")]
    pub sid_enabled: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForestTrustInfoValueTopLevelNamesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForestTrustInfoValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domains: Option<Vec<ForestTrustInfoValueDomainsItem>>,
    #[serde(rename = "topLevelNames", default, skip_serializing_if = "Option::is_none")]
    pub top_level_names: Option<Vec<ForestTrustInfoValueTopLevelNamesItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnapMonitorEventsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnapMonitorPaging {
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
pub struct GnapMonitorRowsItemGrantsHeld {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finalized: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnapMonitorRowsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
    #[serde(rename = "finishUris", default, skip_serializing_if = "Option::is_none")]
    pub finish_uris: Option<Vec<String>>,
    #[serde(rename = "webApplication", default, skip_serializing_if = "Option::is_none")]
    pub web_application: Option<bool>,
    #[serde(rename = "grantsHeld", default, skip_serializing_if = "Option::is_none")]
    pub grants_held: Option<GnapMonitorRowsItemGrantsHeld>,
    #[serde(rename = "activeTokens", default, skip_serializing_if = "Option::is_none")]
    pub active_tokens: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counters: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "lastEvent", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_event: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnapMonitor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub since: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<GnapMonitorEventsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totals: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "tokensByFormat", default, skip_serializing_if = "Option::is_none")]
    pub tokens_by_format: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applications: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<GnapMonitorPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<GnapMonitorRowsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnapServerEndpoints {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery: Option<String>,
    #[serde(rename = "rsDiscovery", default, skip_serializing_if = "Option::is_none")]
    pub rs_discovery: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation: Option<String>,
    #[serde(rename = "tokenManagement", default, skip_serializing_if = "Option::is_none")]
    pub token_management: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introspection: Option<String>,
    #[serde(rename = "resourceRegistration", default, skip_serializing_if = "Option::is_none")]
    pub resource_registration: Option<String>,
    #[serde(rename = "userCode", default, skip_serializing_if = "Option::is_none")]
    pub user_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<String>,
    #[serde(rename = "zcapController", default, skip_serializing_if = "Option::is_none")]
    pub zcap_controller: Option<String>,
    #[serde(rename = "accessTokenStatusList", default, skip_serializing_if = "Option::is_none")]
    pub access_token_status_list: Option<String>,
    #[serde(rename = "biscuitRevocations", default, skip_serializing_if = "Option::is_none")]
    pub biscuit_revocations: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum GnapServerCapabilitiesInteractionStartModesSupported {
    V1(Vec<String>),
    Bool(bool),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum GnapServerCapabilitiesInteractionFinishMethodsSupported {
    V1(Vec<String>),
    Bool(bool),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum GnapServerCapabilitiesKeyProofsSupported {
    V1(Vec<String>),
    Bool(bool),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum GnapServerCapabilitiesSubIdFormatsSupported {
    V1(Vec<String>),
    Bool(bool),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum GnapServerCapabilitiesAssertionFormatsSupported {
    V1(Vec<String>),
    Bool(bool),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum GnapServerCapabilitiesKeyRotationSupported {
    V1(Vec<String>),
    Bool(bool),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum GnapServerCapabilitiesTokenFormatsSupported {
    V1(Vec<String>),
    Bool(bool),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnapServerCapabilities {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_request_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub interaction_start_modes_supported: Option<Option<GnapServerCapabilitiesInteractionStartModesSupported>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub interaction_finish_methods_supported: Option<Option<GnapServerCapabilitiesInteractionFinishMethodsSupported>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub key_proofs_supported: Option<Option<GnapServerCapabilitiesKeyProofsSupported>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub sub_id_formats_supported: Option<Option<GnapServerCapabilitiesSubIdFormatsSupported>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub assertion_formats_supported: Option<Option<GnapServerCapabilitiesAssertionFormatsSupported>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub key_rotation_supported: Option<Option<GnapServerCapabilitiesKeyRotationSupported>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub token_formats_supported: Option<Option<GnapServerCapabilitiesTokenFormatsSupported>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum GnapServerAuthorizationServersItemCapabilitiesInteractionStartModesSupported {
    V1(Vec<String>),
    Bool(bool),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum GnapServerAuthorizationServersItemCapabilitiesInteractionFinishMethodsSupported {
    V1(Vec<String>),
    Bool(bool),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum GnapServerAuthorizationServersItemCapabilitiesKeyProofsSupported {
    V1(Vec<String>),
    Bool(bool),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum GnapServerAuthorizationServersItemCapabilitiesSubIdFormatsSupported {
    V1(Vec<String>),
    Bool(bool),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum GnapServerAuthorizationServersItemCapabilitiesAssertionFormatsSupported {
    V1(Vec<String>),
    Bool(bool),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum GnapServerAuthorizationServersItemCapabilitiesKeyRotationSupported {
    V1(Vec<String>),
    Bool(bool),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum GnapServerAuthorizationServersItemCapabilitiesTokenFormatsSupported {
    V1(Vec<String>),
    Bool(bool),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnapServerAuthorizationServersItemCapabilities {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_request_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub interaction_start_modes_supported: Option<Option<GnapServerAuthorizationServersItemCapabilitiesInteractionStartModesSupported>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub interaction_finish_methods_supported: Option<Option<GnapServerAuthorizationServersItemCapabilitiesInteractionFinishMethodsSupported>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub key_proofs_supported: Option<Option<GnapServerAuthorizationServersItemCapabilitiesKeyProofsSupported>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub sub_id_formats_supported: Option<Option<GnapServerAuthorizationServersItemCapabilitiesSubIdFormatsSupported>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub assertion_formats_supported: Option<Option<GnapServerAuthorizationServersItemCapabilitiesAssertionFormatsSupported>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub key_rotation_supported: Option<Option<GnapServerAuthorizationServersItemCapabilitiesKeyRotationSupported>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub token_formats_supported: Option<Option<GnapServerAuthorizationServersItemCapabilitiesTokenFormatsSupported>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnapServerAuthorizationServersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<GnapServerAuthorizationServersItemCapabilities>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnapServerAuthorizationServersPaging {
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
pub struct GnapServerVerificationMaterialJwt {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_list_aggregation_endpoint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnapServerVerificationMaterialBiscuitJwk {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kty: Option<String>,
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
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
    pub ek: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
    #[serde(rename = "x5t#S256", default, skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnapServerVerificationMaterialBiscuit {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwk: Option<GnapServerVerificationMaterialBiscuitJwk>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_public_keys: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnapServerVerificationMaterialZcap {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cryptosuite: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnapServerVerificationMaterialMacaroon {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnapServerVerificationMaterialJwtEncrypted {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_server: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnapServerVerificationMaterial {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt: Option<GnapServerVerificationMaterialJwt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub biscuit: Option<GnapServerVerificationMaterialBiscuit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zcap: Option<GnapServerVerificationMaterialZcap>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macaroon: Option<GnapServerVerificationMaterialMacaroon>,
    #[serde(rename = "jwt-encrypted", default, skip_serializing_if = "Option::is_none")]
    pub jwt_encrypted: Option<GnapServerVerificationMaterialJwtEncrypted>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnapServerGrantsPaging {
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
pub struct GnapServerGrantsRowsItemInteraction {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub finish: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub started: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnapServerGrantsRowsItemFinalization {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub note: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnapServerGrantsRowsItemHistoryItem {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub note: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnapServerGrantsRowsItem {
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
    pub interaction: Option<GnapServerGrantsRowsItemInteraction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<i64>,
    #[serde(rename = "derivedFrom", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub derived_from: Option<Option<String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub updated_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finalization: Option<GnapServerGrantsRowsItemFinalization>,
    #[serde(rename = "grantExpiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub grant_expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<Vec<GnapServerGrantsRowsItemHistoryItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnapServerGrants {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub state: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub states: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<GnapServerGrantsPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<GnapServerGrantsRowsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnapServerResourceSetsPaging {
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
pub struct GnapServerResourceSetsRowsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(rename = "resourceServer", default, skip_serializing_if = "Option::is_none")]
    pub resource_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<Vec<serde_json::Value>>,
    #[serde(rename = "tokenFormats", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub token_formats: Option<Option<Vec<serde_json::Value>>>,
    #[serde(rename = "introspectionRequired", default, skip_serializing_if = "Option::is_none")]
    pub introspection_required: Option<bool>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnapServerResourceSets {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<GnapServerResourceSetsPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<GnapServerResourceSetsRowsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnapServerSettingsGroupsItemSettingsItemSelectAllOnlyWhileOnItem {
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
pub struct GnapServerSettingsGroupsItemSettingsItemSelectAllAloneWhileOnItem {
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
pub struct GnapServerSettingsGroupsItemSettingsItemSelectAll {
    #[serde(rename = "onlyWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub only_while_on: Option<Vec<GnapServerSettingsGroupsItemSettingsItemSelectAllOnlyWhileOnItem>>,
    #[serde(rename = "aloneWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub alone_while_on: Option<Vec<GnapServerSettingsGroupsItemSettingsItemSelectAllAloneWhileOnItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum GnapServerSettingsGroupsItemSettingsItemValue {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum GnapServerSettingsGroupsItemSettingsItemEnv {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum GnapServerSettingsGroupsItemSettingsItemLegacyEnv {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum GnapServerSettingsGroupsItemSettingsItemDefault {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnapServerSettingsGroupsItemSettingsItem {
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
    pub select_all: Option<GnapServerSettingsGroupsItemSettingsItemSelectAll>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<GnapServerSettingsGroupsItemSettingsItemValue>>,
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
    pub env: Option<GnapServerSettingsGroupsItemSettingsItemEnv>,
    #[serde(rename = "legacyEnv", default, skip_serializing_if = "Option::is_none")]
    pub legacy_env: Option<GnapServerSettingsGroupsItemSettingsItemLegacyEnv>,
    #[serde(rename = "appconfigPath", default, skip_serializing_if = "Option::is_none")]
    pub appconfig_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default: Option<Option<GnapServerSettingsGroupsItemSettingsItemDefault>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnapServerSettingsGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<GnapServerSettingsGroupsItemSettingsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnapServerSettingsContext {
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
pub struct GnapServerSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<GnapServerSettingsGroupsItem>>,
    #[serde(rename = "settingCount", default, skip_serializing_if = "Option::is_none")]
    pub setting_count: Option<i64>,
    #[serde(rename = "editableCount", default, skip_serializing_if = "Option::is_none")]
    pub editable_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<Vec<String>>,
    #[serde(rename = "setWith", default, skip_serializing_if = "Option::is_none")]
    pub set_with: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<GnapServerSettingsContext>,
    #[serde(rename = "sharedWith", default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnapServer {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub specifications: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<GnapServerEndpoints>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<GnapServerCapabilities>,
    #[serde(rename = "authorizationServers", default, skip_serializing_if = "Option::is_none")]
    pub authorization_servers: Option<Vec<GnapServerAuthorizationServersItem>>,
    #[serde(rename = "authorizationServersPaging", default, skip_serializing_if = "Option::is_none")]
    pub authorization_servers_paging: Option<GnapServerAuthorizationServersPaging>,
    #[serde(rename = "tokenFormats", default, skip_serializing_if = "Option::is_none")]
    pub token_formats: Option<Vec<String>>,
    #[serde(rename = "verificationMaterial", default, skip_serializing_if = "Option::is_none")]
    pub verification_material: Option<GnapServerVerificationMaterial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<GnapServerGrants>,
    #[serde(rename = "resourceSets", default, skip_serializing_if = "Option::is_none")]
    pub resource_sets: Option<GnapServerResourceSets>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<GnapServerSettings>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupDetailGroupMembersItem {
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
pub struct GroupDetailGroupClaimedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holds: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupDetailGroupOwnersItem {
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
pub struct GroupDetailGroup {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "modifiedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub modified_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operational: Option<Vec<String>>,
    #[serde(rename = "memberAttributes", default, skip_serializing_if = "Option::is_none")]
    pub member_attributes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<GroupDetailGroupMembersItem>>,
    #[serde(rename = "memberCount", default, skip_serializing_if = "Option::is_none")]
    pub member_count: Option<f64>,
    #[serde(rename = "presentCount", default, skip_serializing_if = "Option::is_none")]
    pub present_count: Option<f64>,
    #[serde(rename = "danglingCount", default, skip_serializing_if = "Option::is_none")]
    pub dangling_count: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed: Option<Vec<GroupDetailGroupClaimedItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owners: Option<Vec<GroupDetailGroupOwnersItem>>,
    #[serde(rename = "maxOwners", default, skip_serializing_if = "Option::is_none")]
    pub max_owners: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupDetailGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "objectClass", default, skip_serializing_if = "Option::is_none")]
    pub object_class: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "modifiedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub modified_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "memberCount", default, skip_serializing_if = "Option::is_none")]
    pub member_count: Option<f64>,
    #[serde(rename = "presentCount", default, skip_serializing_if = "Option::is_none")]
    pub present_count: Option<f64>,
    #[serde(rename = "danglingCount", default, skip_serializing_if = "Option::is_none")]
    pub dangling_count: Option<f64>,
    #[serde(rename = "claimedCount", default, skip_serializing_if = "Option::is_none")]
    pub claimed_count: Option<f64>,
    #[serde(rename = "ownerCount", default, skip_serializing_if = "Option::is_none")]
    pub owner_count: Option<f64>,
    #[serde(rename = "attributeCount", default, skip_serializing_if = "Option::is_none")]
    pub attribute_count: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupDetailPolicyReferencesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noun: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub choices: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupDetailOwnership {
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
pub struct GroupDetailMembersPaging {
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
pub struct GroupDetailClaimedPaging {
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
pub struct GroupDetailAdminGroups {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub read: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub write: Option<Option<String>>,
}

/// One group, with the same directory facts the list carries around it.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupDetail {
    #[serde(rename = "baseDn", default, skip_serializing_if = "Option::is_none")]
    pub base_dn: Option<String>,
    #[serde(rename = "usersDn", default, skip_serializing_if = "Option::is_none")]
    pub users_dn: Option<String>,
    #[serde(rename = "groupsDn", default, skip_serializing_if = "Option::is_none")]
    pub groups_dn: Option<String>,
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
    #[serde(rename = "entryCount", default, skip_serializing_if = "Option::is_none")]
    pub entry_count: Option<f64>,
    #[serde(rename = "maxEntries", default, skip_serializing_if = "Option::is_none")]
    pub max_entries: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub found: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested: Option<String>,
    #[serde(rename = "notAGroup", default, skip_serializing_if = "Option::is_none")]
    pub not_a_group: Option<bool>,
    #[serde(rename = "canWrite", default, skip_serializing_if = "Option::is_none")]
    pub can_write: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<GroupDetailGroup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<GroupDetailGroupsItem>>,
    #[serde(rename = "groupCount", default, skip_serializing_if = "Option::is_none")]
    pub group_count: Option<f64>,
    #[serde(rename = "policyReferences", default, skip_serializing_if = "Option::is_none")]
    pub policy_references: Option<Vec<GroupDetailPolicyReferencesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ownership: Option<GroupDetailOwnership>,
    #[serde(rename = "membersPaging", default, skip_serializing_if = "Option::is_none")]
    pub members_paging: Option<GroupDetailMembersPaging>,
    #[serde(rename = "claimedPaging", default, skip_serializing_if = "Option::is_none")]
    pub claimed_paging: Option<GroupDetailClaimedPaging>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "adminGroups", default, skip_serializing_if = "Option::is_none")]
    pub admin_groups: Option<GroupDetailAdminGroups>,
}

pub type GroupDrawnAnotherPageWell = serde_json::Map<String, serde_json::Value>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupListSettingsGroupsItemSettingsItemSelectAllOnlyWhileOnItem {
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
pub struct GroupListSettingsGroupsItemSettingsItemSelectAllAloneWhileOnItem {
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
pub struct GroupListSettingsGroupsItemSettingsItemSelectAll {
    #[serde(rename = "onlyWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub only_while_on: Option<Vec<GroupListSettingsGroupsItemSettingsItemSelectAllOnlyWhileOnItem>>,
    #[serde(rename = "aloneWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub alone_while_on: Option<Vec<GroupListSettingsGroupsItemSettingsItemSelectAllAloneWhileOnItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum GroupListSettingsGroupsItemSettingsItemValue {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum GroupListSettingsGroupsItemSettingsItemEnv {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum GroupListSettingsGroupsItemSettingsItemLegacyEnv {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum GroupListSettingsGroupsItemSettingsItemDefault {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupListSettingsGroupsItemSettingsItem {
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
    pub select_all: Option<GroupListSettingsGroupsItemSettingsItemSelectAll>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<GroupListSettingsGroupsItemSettingsItemValue>>,
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
    pub env: Option<GroupListSettingsGroupsItemSettingsItemEnv>,
    #[serde(rename = "legacyEnv", default, skip_serializing_if = "Option::is_none")]
    pub legacy_env: Option<GroupListSettingsGroupsItemSettingsItemLegacyEnv>,
    #[serde(rename = "appconfigPath", default, skip_serializing_if = "Option::is_none")]
    pub appconfig_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default: Option<Option<GroupListSettingsGroupsItemSettingsItemDefault>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupListSettingsGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<GroupListSettingsGroupsItemSettingsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupListSettingsContext {
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
pub struct GroupListSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<GroupListSettingsGroupsItem>>,
    #[serde(rename = "settingCount", default, skip_serializing_if = "Option::is_none")]
    pub setting_count: Option<i64>,
    #[serde(rename = "editableCount", default, skip_serializing_if = "Option::is_none")]
    pub editable_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<Vec<String>>,
    #[serde(rename = "setWith", default, skip_serializing_if = "Option::is_none")]
    pub set_with: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<GroupListSettingsContext>,
    #[serde(rename = "sharedWith", default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupListFilter {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub q: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub exclude: Option<Option<Vec<serde_json::Value>>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupListPaging {
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
pub struct GroupListAdminGroups {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub read: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub write: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupListGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "objectClass", default, skip_serializing_if = "Option::is_none")]
    pub object_class: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub created_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "modifiedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub modified_at: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "memberCount", default, skip_serializing_if = "Option::is_none")]
    pub member_count: Option<f64>,
    #[serde(rename = "presentCount", default, skip_serializing_if = "Option::is_none")]
    pub present_count: Option<f64>,
    #[serde(rename = "danglingCount", default, skip_serializing_if = "Option::is_none")]
    pub dangling_count: Option<f64>,
    #[serde(rename = "claimedCount", default, skip_serializing_if = "Option::is_none")]
    pub claimed_count: Option<f64>,
    #[serde(rename = "ownerCount", default, skip_serializing_if = "Option::is_none")]
    pub owner_count: Option<f64>,
    #[serde(rename = "attributeCount", default, skip_serializing_if = "Option::is_none")]
    pub attribute_count: Option<f64>,
}

/// Every group the embedded directory holds.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupList {
    #[serde(rename = "baseDn", default, skip_serializing_if = "Option::is_none")]
    pub base_dn: Option<String>,
    #[serde(rename = "usersDn", default, skip_serializing_if = "Option::is_none")]
    pub users_dn: Option<String>,
    #[serde(rename = "groupsDn", default, skip_serializing_if = "Option::is_none")]
    pub groups_dn: Option<String>,
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
    #[serde(rename = "entryCount", default, skip_serializing_if = "Option::is_none")]
    pub entry_count: Option<f64>,
    #[serde(rename = "groupCount", default, skip_serializing_if = "Option::is_none")]
    pub group_count: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<f64>,
    #[serde(rename = "canWrite", default, skip_serializing_if = "Option::is_none")]
    pub can_write: Option<bool>,
    #[serde(rename = "membershipValues", default, skip_serializing_if = "Option::is_none")]
    pub membership_values: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dangling: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<GroupListSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<GroupListFilter>,
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
    pub paging: Option<GroupListPaging>,
    #[serde(rename = "adminGroups", default, skip_serializing_if = "Option::is_none")]
    pub admin_groups: Option<GroupListAdminGroups>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<GroupListGroupsItem>>,
}

/// One group's settings.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupSSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<crate::WithDescriptionGroupSettings>,
}

pub type HolderSWalletDisclosedCredential = serde_json::Value;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InteractionValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub finish: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub started: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub expires_at: Option<Option<sts_model_base::unions::NumberOrString>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedListCoverage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub complete: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub newest: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub session: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unread: Option<bool>,
    #[serde(rename = "countEstimated", default, skip_serializing_if = "Option::is_none")]
    pub count_estimated: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedListFilter {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub family: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub kind: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub state: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub session: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedListFamiliesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedListPaging {
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
pub struct IssuedList {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<i64>,
    #[serde(rename = "heldSets", default, skip_serializing_if = "Option::is_none")]
    pub held_sets: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage: Option<IssuedListCoverage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<i64>,
    #[serde(rename = "matchedCredentials", default, skip_serializing_if = "Option::is_none")]
    pub matched_credentials: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<i64>,
    #[serde(rename = "shownCredentials", default, skip_serializing_if = "Option::is_none")]
    pub shown_credentials: Option<i64>,
    /// Credentials held in each family.
    #[serde(rename = "heldByFamily", default, skip_serializing_if = "Option::is_none")]
    pub held_by_family: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<IssuedListFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub families: Option<Vec<IssuedListFamiliesItem>>,
    #[serde(rename = "revocableKinds", default, skip_serializing_if = "Option::is_none")]
    pub revocable_kinds: Option<Vec<String>>,
    #[serde(rename = "revokedCount", default, skip_serializing_if = "Option::is_none")]
    pub revoked_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sets: Option<Vec<crate::IssuedSet>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued: Option<Vec<crate::IssuedRecord>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging: Option<IssuedListPaging>,
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
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum IssuedRecordJti {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum IssuedRecordSub {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum IssuedRecordUsername {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum IssuedRecordTyp {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum IssuedRecordClientId {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum IssuedRecordScope {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum IssuedRecordIdentifier {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

/// One thing this service issued and still remembers. Claims and facts only:
/// the signed token, the assertion XML and the ticket are deliberately not
/// kept.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedRecord {
    /// token, assertion, ticket or svid: what the `family` filter takes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// access_token, id_token, refresh_token, a SAML assertion version, a
    /// Kerberos ticket type or an SVID type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// valid, expired, revoked, "not yet valid" or "no expiry stated".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub jti: Option<Option<IssuedRecordJti>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub sub: Option<Option<IssuedRecordSub>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub username: Option<Option<IssuedRecordUsername>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub typ: Option<Option<IssuedRecordTyp>>,
    #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<f64>,
    #[serde(rename = "expiresAtMs", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub expires_at_ms: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<bool>,
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub revoked_at: Option<Option<f64>>,
    #[serde(rename = "revokedVia", default, skip_serializing_if = "Option::is_none")]
    pub revoked_via: Option<String>,
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(rename = "setId", default, skip_serializing_if = "Option::is_none")]
    pub set_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jkt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub client_id: Option<Option<IssuedRecordClientId>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub scope: Option<Option<IssuedRecordScope>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub identifier: Option<Option<IssuedRecordIdentifier>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum IssuedSetUsername {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum IssuedSetSub {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum IssuedSetClientId {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum IssuedSetScope {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

/// One issuance: everything that came back in a single reply.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedSet {
    #[serde(rename = "setKey", default, skip_serializing_if = "Option::is_none")]
    pub set_key: Option<String>,
    #[serde(rename = "setId", default, skip_serializing_if = "Option::is_none")]
    pub set_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grouped: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub families: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// How many members are in each state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub states: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<f64>,
    #[serde(rename = "expiresAtMs", default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<f64>,
    #[serde(rename = "lastExpiresAtMs", default, skip_serializing_if = "Option::is_none")]
    pub last_expires_at_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub username: Option<Option<IssuedSetUsername>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub sub: Option<Option<IssuedSetSub>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub client_id: Option<Option<IssuedSetClientId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub scope: Option<Option<IssuedSetScope>>,
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(rename = "sessionAuthenticated", default, skip_serializing_if = "Option::is_none")]
    pub session_authenticated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
    #[serde(rename = "revocableCount", default, skip_serializing_if = "Option::is_none")]
    pub revocable_count: Option<i64>,
    #[serde(rename = "revokedCount", default, skip_serializing_if = "Option::is_none")]
    pub revoked_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<crate::IssuedRecord>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedSetDetail {
    #[serde(rename = "setKey", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub set_key: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub set: Option<Option<crate::IssuedSet>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub found: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub why: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum IssuedTokenViewAudience {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedTokenView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<IssuedTokenViewAudience>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

pub type JsonOperatorWroteIntoAccess = serde_json::Value;

pub type JwkSetMetadataDocumentMetadata = serde_json::Value;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwkValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kty: Option<String>,
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
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
    pub ek: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
    #[serde(rename = "x5t#S256", default, skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwksValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<crate::WithAdditionalPropertiesPropertiesKeys>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum KerberosPacClaimsProtocolEndpointsItemMethods {
    V1(Vec<String>),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KerberosPacClaimsProtocolEndpointsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<KerberosPacClaimsProtocolEndpointsItemMethods>,
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
pub struct KerberosPacClaimsSetsItemClaimsItem {
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
pub struct KerberosPacClaimsSetsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<KerberosPacClaimsSetsItemClaimsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KerberosPacClaimsAttributeCatalogueItem {
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
pub struct KerberosPacClaimsAttributeChoicesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KerberosPacClaimsPreviewClaimsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dropped: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KerberosPacClaimsPreview {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(rename = "entryFound", default, skip_serializing_if = "Option::is_none")]
    pub entry_found: Option<bool>,
    /// By directory attribute.
    #[serde(rename = "byLdap", default, skip_serializing_if = "Option::is_none")]
    pub by_ldap: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<KerberosPacClaimsPreviewClaimsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KerberosPacClaims {
    #[serde(rename = "protocolEndpoints", default, skip_serializing_if = "Option::is_none")]
    pub protocol_endpoints: Option<Vec<KerberosPacClaimsProtocolEndpointsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholders: Option<Vec<String>>,
    #[serde(rename = "idFormat", default, skip_serializing_if = "Option::is_none")]
    pub id_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sets: Option<Vec<KerberosPacClaimsSetsItem>>,
    #[serde(rename = "attributeCatalogue", default, skip_serializing_if = "Option::is_none")]
    pub attribute_catalogue: Option<Vec<KerberosPacClaimsAttributeCatalogueItem>>,
    #[serde(rename = "attributeChoices", default, skip_serializing_if = "Option::is_none")]
    pub attribute_choices: Option<Vec<KerberosPacClaimsAttributeChoicesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<KerberosPacClaimsPreview>,
}

/// One file.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyExportFilesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base64: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyExport {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    /// One line about what came out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// True for a post-quantum key, which comes out as its public half.
    #[serde(rename = "publicOnly", default, skip_serializing_if = "Option::is_none")]
    pub public_only: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<Vec<KeyExportFilesItem>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum KeyExportRequestFormat {
    #[serde(rename = "pem")]
    Pem,
    #[serde(rename = "der")]
    Der,
    #[serde(rename = "jwk")]
    Jwk,
    #[serde(rename = "pkcs12")]
    Pkcs12,
}

/// Which key, in which format, under which password.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct KeyExportRequest {
    /// The `id` from GET /admin-api/keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<KeyExportRequestFormat>,
    /// REQUIRED for `pkcs12`. Optional for the other three, where it encrypts
    /// the private half — PKCS#8 for PEM and DER, PBES2 as a .jwe for JWK.
    /// Empty means the private key comes out in the clear, which is usually
    /// what is wanted in development and never anywhere else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// The members the schema does not name, which it allows.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyListSettingsGroupsItemSettingsItemSelectAllOnlyWhileOnItem {
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
pub struct KeyListSettingsGroupsItemSettingsItemSelectAllAloneWhileOnItem {
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
pub struct KeyListSettingsGroupsItemSettingsItemSelectAll {
    #[serde(rename = "onlyWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub only_while_on: Option<Vec<KeyListSettingsGroupsItemSettingsItemSelectAllOnlyWhileOnItem>>,
    #[serde(rename = "aloneWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub alone_while_on: Option<Vec<KeyListSettingsGroupsItemSettingsItemSelectAllAloneWhileOnItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum KeyListSettingsGroupsItemSettingsItemValue {
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
pub enum KeyListSettingsGroupsItemSettingsItemSource {
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
pub enum KeyListSettingsGroupsItemSettingsItemDefault {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

/// One setting: what it is, what it is set to, and where that came from.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyListSettingsGroupsItemSettingsItem {
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
    pub select_all: Option<KeyListSettingsGroupsItemSettingsItemSelectAll>,
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
    pub value: Option<Option<KeyListSettingsGroupsItemSettingsItemValue>>,
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
    pub source: Option<KeyListSettingsGroupsItemSettingsItemSource>,
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
    pub default: Option<Option<KeyListSettingsGroupsItemSettingsItemDefault>>,
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
pub struct KeyListSettingsGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<KeyListSettingsGroupsItemSettingsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyListSettingsContext {
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
pub struct KeyListSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    /// In the order `config.js` declares them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<KeyListSettingsGroupsItem>>,
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
    pub context: Option<KeyListSettingsContext>,
    /// A group drawn on another page as well, and those pages.
    #[serde(rename = "sharedWith", default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyListResidency {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persisting: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<String>,
    #[serde(rename = "plaintextTtlS", default, skip_serializing_if = "Option::is_none")]
    pub plaintext_ttl_s: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(rename = "realmsHeld", default, skip_serializing_if = "Option::is_none")]
    pub realms_held: Option<Vec<String>>,
    #[serde(rename = "plaintextHeld", default, skip_serializing_if = "Option::is_none")]
    pub plaintext_held: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyListKeysItemCertifiedBy {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub subject: Option<Option<String>>,
    #[serde(rename = "issuedBy", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub issued_by: Option<Option<String>>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub not_after: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyListKeysItemPqc {
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

/// One key pair.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyListKeysItem {
    /// What POST /admin-api/keys/export takes as `key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub kty: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bits: Option<f64>,
    /// Empty for the TLS key, which has a fingerprint instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// `realm` or `process`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    /// Whether a PKCS#12 is possible.
    #[serde(rename = "hasCertificate", default, skip_serializing_if = "Option::is_none")]
    pub has_certificate: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated: Option<bool>,
    #[serde(rename = "certifiedBy", default, skip_serializing_if = "Option::is_none")]
    pub certified_by: Option<KeyListKeysItemCertifiedBy>,
    /// Empty means not exportable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub formats: Option<Vec<String>>,
    #[serde(rename = "usedFor", default, skip_serializing_if = "Option::is_none")]
    pub used_for: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub fingerprint: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub subject: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub not_after: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc: Option<KeyListKeysItemPqc>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyListRotationUnitsItemNext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub since: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyListRotationUnitsItemRetiredItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(rename = "retiredAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub retired_at: Option<Option<String>>,
    #[serde(rename = "verifiesUntil", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub verifies_until: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyListRotationUnitsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub current: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<KeyListRotationUnitsItemNext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired: Option<Vec<KeyListRotationUnitsItemRetiredItem>>,
    #[serde(rename = "lastRotated", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_rotated: Option<Option<String>>,
    #[serde(rename = "intervalDays", default, skip_serializing_if = "Option::is_none")]
    pub interval_days: Option<f64>,
    #[serde(rename = "graceDays", default, skip_serializing_if = "Option::is_none")]
    pub grace_days: Option<f64>,
    #[serde(rename = "credentialSigner", default, skip_serializing_if = "Option::is_none")]
    pub credential_signer: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyListRotationRefresh {
    #[serde(rename = "lastRotated", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_rotated: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired: Option<i64>,
    #[serde(rename = "graceDays", default, skip_serializing_if = "Option::is_none")]
    pub grace_days: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyListRotation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduled: Option<bool>,
    #[serde(rename = "offReason", default, skip_serializing_if = "Option::is_none")]
    pub off_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub units: Option<Vec<KeyListRotationUnitsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh: Option<KeyListRotationRefresh>,
}

/// Every key pair this realm holds, what each is used for, and which can be
/// exported.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyList {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// The signing keys belong to this realm; the TLS key to the process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    /// The settings this page draws, described: the same rows GET /config
    /// returns, filtered to the ones this page owns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<KeyListSettings>,
    #[serde(rename = "regeneratedEveryStart", default, skip_serializing_if = "Option::is_none")]
    pub regenerated_every_start: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub residency: Option<KeyListResidency>,
    /// Every format the exporter knows. What a PARTICULAR key offers is its own
    /// `formats`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub formats: Option<Vec<String>>,
    #[serde(rename = "verifiesCredentials", default, skip_serializing_if = "Option::is_none")]
    pub verifies_credentials: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<KeyListKeysItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation: Option<KeyListRotation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KrbtgtValueEtypesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etype: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KrbtgtValueJobs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduled: Option<String>,
    #[serde(rename = "byHand", default, skip_serializing_if = "Option::is_none")]
    pub by_hand: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KrbtgtValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub kvno: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etypes: Option<Vec<KrbtgtValueEtypesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<bool>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(rename = "keyCreatedAt", default, skip_serializing_if = "Option::is_none")]
    pub key_created_at: Option<String>,
    #[serde(rename = "rotatedAt", default, skip_serializing_if = "Option::is_none")]
    pub rotated_at: Option<String>,
    #[serde(rename = "invalidatedAt", default, skip_serializing_if = "Option::is_none")]
    pub invalidated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retained: Option<crate::WithAdditionalPropertiesPropertiesPrincipal>,
    #[serde(rename = "windowOpenUntil", default, skip_serializing_if = "Option::is_none")]
    pub window_open_until: Option<String>,
    #[serde(rename = "retainedTtlSeconds", default, skip_serializing_if = "Option::is_none")]
    pub retained_ttl_seconds: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(rename = "trustRealm", default, skip_serializing_if = "Option::is_none")]
    pub trust_realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduled: Option<bool>,
    #[serde(rename = "offReason", default, skip_serializing_if = "Option::is_none")]
    pub off_reason: Option<String>,
    #[serde(rename = "intervalDays", default, skip_serializing_if = "Option::is_none")]
    pub interval_days: Option<f64>,
    #[serde(rename = "lastRotatedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_rotated_at: Option<Option<String>>,
    #[serde(rename = "nextDueAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub next_due_at: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jobs: Option<KrbtgtValueJobs>,
    #[serde(rename = "confirmWord", default, skip_serializing_if = "Option::is_none")]
    pub confirm_word: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LastRunValue {
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
    pub params: Option<crate::ManualRunSParamsJson>,
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

/// One family of live things, and the prose saying what a logout does and does
/// not reach in it.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LogoutFamily {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// The document this family's behaviour comes from, or a sentence saying
    /// there is none to cite — which is the answer for everything that cannot
    /// be recalled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminable: Option<bool>,
    /// How many are live.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<i64>,
    /// How many were held back by `logout.maxRows`. The cap is on what is
    /// LISTED and never on what a termination reaches: a global logout still
    /// ends every one of them.
    #[serde(rename = "notListed", default, skip_serializing_if = "Option::is_none")]
    pub not_listed: Option<i64>,
    /// Set when this family could not be read. The rest of the reply is
    /// unaffected — a family that cannot answer is reported rather than taking
    /// the whole inventory down.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<crate::LogoutRow>>,
    /// The members the schema does not name, which it allows.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Where `backchannelDeliveries` came from in the whole list: the page, how
/// many there are, and the 1-based row numbers this page covers. Same member
/// names the flat lists carry at the top level, one level down.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogoutInventoryBackchannelDeliveriesPaging {
    /// How many there are in all, which is what to page through rather than the
    /// length of this array.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    /// The page these rows are from, CLAMPED — `?page=999` on a two-page list
    /// reports 2, which is the page in the reply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    /// How many pages the match has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    /// Rows per page, clamped to the cap.
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    /// 1-based and inclusive; 0 when nothing matched.
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    /// 1-based and inclusive.
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
}

/// How many deliveries this realm holds in each state.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LogoutInventoryBackchannelCounts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent: Option<i64>,
    /// The dead letters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead: Option<i64>,
    /// The members the schema does not name, which it allows.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// What this service is still holding for one identity, across every protocol
/// family — or, with no `user`, the list of families a logout reaches.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LogoutInventory {
    /// The name that was asked about.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// FALSE with no `user` means this is the family list rather than an
    /// identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known: Option<bool>,
    /// The normalised identity key everything is filed under — what folds
    /// `alice`, `alice@REALM` and a `urn:` subject into one answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Browser sign-on sessions held.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<i64>,
    /// Live items in every family.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listed: Option<i64>,
    #[serde(rename = "notListed", default, skip_serializing_if = "Option::is_none")]
    pub not_listed: Option<i64>,
    /// The `logout.maxRows` cap.
    #[serde(rename = "maxRows", default, skip_serializing_if = "Option::is_none")]
    pub max_rows: Option<i64>,
    /// Whether the CONSOLE session on the request holds Admin Write. A call
    /// carrying only this API's access token has no console session, so this
    /// reads false there; what that token may do is decided by its scope at
    /// this API's gate.
    #[serde(rename = "canWrite", default, skip_serializing_if = "Option::is_none")]
    pub can_write: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub families: Option<Vec<crate::LogoutFamily>>,
    /// The same rows flattened, filtered and paged — which is what the console
    /// table shows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<crate::LogoutRow>>,
    /// The back-channel Logout Token deliveries in this realm, from EVERY node,
    /// newest first, with or without `user`, narrowed by `deliveryState` and
    /// `deliveryq` and paged by `backchannelDeliveriesPage` — where a delivery
    /// a sign-out reported as `pending` is seen to have arrived, and where the
    /// dead letters are. Every final outcome is also a `logout.backchannel`
    /// audit row.
    #[serde(rename = "backchannelDeliveries", default, skip_serializing_if = "Option::is_none")]
    pub backchannel_deliveries: Option<Vec<sts_model_management_components_1::BackchannelDelivery>>,
    /// Where `backchannelDeliveries` came from in the whole list: the page, how
    /// many there are, and the 1-based row numbers this page covers. Same
    /// member names the flat lists carry at the top level, one level down.
    #[serde(rename = "backchannelDeliveriesPaging", default, skip_serializing_if = "Option::is_none")]
    pub backchannel_deliveries_paging: Option<LogoutInventoryBackchannelDeliveriesPaging>,
    /// How many deliveries this realm holds in each state.
    #[serde(rename = "backchannelCounts", default, skip_serializing_if = "Option::is_none")]
    pub backchannel_counts: Option<LogoutInventoryBackchannelCounts>,
    /// The state asked for, or empty.
    #[serde(rename = "deliveryState", default, skip_serializing_if = "Option::is_none")]
    pub delivery_state: Option<String>,
    /// The search asked for, or empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deliveryq: Option<String>,
    /// The page these rows are from, CLAMPED — `?page=999` on a two-page list
    /// reports 2, which is the page in the reply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<i64>,
    /// How many pages the match has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<i64>,
    /// Rows per page, clamped to the cap.
    #[serde(rename = "perPage", default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<i64>,
    /// 1-based and inclusive; 0 when nothing matched.
    #[serde(rename = "firstRow", default, skip_serializing_if = "Option::is_none")]
    pub first_row: Option<i64>,
    /// 1-based and inclusive.
    #[serde(rename = "lastRow", default, skip_serializing_if = "Option::is_none")]
    pub last_row: Option<i64>,
    /// The members the schema does not name, which it allows.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// One live thing: a session, a credential, a relying party, a directory
/// connection, or an artifact that cannot be ended at all.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LogoutRow {
    /// What `POST /admin-api/logout/end` takes in `select`. It is
    /// `<family>:<handle>`, and for a row whose natural key is a CREDENTIAL —
    /// an authorization code, a pre-authorized code — the handle is a hash of
    /// it and never the value: a code in a reply is a code in a log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Which family it belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// What it is, in that family's own vocabulary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// The thing itself, for a person.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Who issued it, to whom, and what rides on it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Epoch ms, or 0 where the family cannot say.
    #[serde(rename = "startedAt", default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<i64>,
    /// Epoch ms, or 0 for "no expiry was stated" — which is the honest answer
    /// for several of these rather than an expiry of now.
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// FALSE means nothing can end it — not this service and not a real one.
    /// Nothing consults the issuer when a SAML assertion, a Kerberos service
    /// ticket or an X509-SVID is presented, so there is no revocation to
    /// perform. `why` says so in a sentence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminable: Option<bool>,
    /// When `terminable` is false, the reason. Empty otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    /// The browser sign-on session it hangs off, where there is one. Empty is a
    /// fact about the row — the direct grants have no session — rather than a
    /// gap.
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// The members the schema does not name, which it allows.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

pub type ManualRunSParamsJson = serde_json::Value;

pub type MembersCallerSAuthZenContext = serde_json::Value;

pub type MembersServerOverrides = serde_json::Map<String, serde_json::Value>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum MetricsClaimsItemClaimsItemValue {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsClaimsItemClaimsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<MetricsClaimsItemClaimsItemValue>>,
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
pub struct MetricsClaimsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<MetricsClaimsItemClaimsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsCallsRowsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<f64>,
    #[serde(rename = "totalMs", default, skip_serializing_if = "Option::is_none")]
    pub total_ms: Option<f64>,
    #[serde(rename = "maxMs", default, skip_serializing_if = "Option::is_none")]
    pub max_ms: Option<f64>,
    #[serde(rename = "lastAt", default, skip_serializing_if = "Option::is_none")]
    pub last_at: Option<f64>,
    #[serde(rename = "lastStatus", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_status: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statuses: Option<serde_json::Map<String, serde_json::Value>>,
}

/// Endpoint calls, in total and per matched route.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsCalls {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<i64>,
    #[serde(rename = "pathsHere", default, skip_serializing_if = "Option::is_none")]
    pub paths_here: Option<i64>,
    #[serde(rename = "pathsElsewhere", default, skip_serializing_if = "Option::is_none")]
    pub paths_elsewhere: Option<i64>,
    #[serde(rename = "byStatusClass", default, skip_serializing_if = "Option::is_none")]
    pub by_status_class: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "pathsCollapsed", default, skip_serializing_if = "Option::is_none")]
    pub paths_collapsed: Option<i64>,
    #[serde(rename = "healthProbes", default, skip_serializing_if = "Option::is_none")]
    pub health_probes: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<MetricsCallsRowsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsTokensByKindItem {
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

/// JWTs by kind, with the state of each.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsTokens {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<i64>,
    #[serde(rename = "heldOnly", default, skip_serializing_if = "Option::is_none")]
    pub held_only: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forgotten: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<i64>,
    #[serde(rename = "byKind", default, skip_serializing_if = "Option::is_none")]
    pub by_kind: Option<Vec<MetricsTokensByKindItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsArtifactsByKindItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<i64>,
    #[serde(rename = "noExpiry", default, skip_serializing_if = "Option::is_none")]
    pub no_expiry: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsArtifacts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<i64>,
    #[serde(rename = "heldHere", default, skip_serializing_if = "Option::is_none")]
    pub held_here: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forgotten: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<i64>,
    #[serde(rename = "byKind", default, skip_serializing_if = "Option::is_none")]
    pub by_kind: Option<Vec<MetricsArtifactsByKindItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsUsers {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<i64>,
    #[serde(rename = "heldOnly", default, skip_serializing_if = "Option::is_none")]
    pub held_only: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forgotten: Option<i64>,
    #[serde(rename = "authenticatedHere", default, skip_serializing_if = "Option::is_none")]
    pub authenticated_here: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clients: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentications: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsSessionsFamiliesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subjects: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub who: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsSessions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub families: Option<Vec<MetricsSessionsFamiliesItem>>,
    #[serde(rename = "distinctSubjects", default, skip_serializing_if = "Option::is_none")]
    pub distinct_subjects: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsSignOnSessionsRowsItemDeviceBound {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(rename = "boundAt", default, skip_serializing_if = "Option::is_none")]
    pub bound_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refreshes: Option<f64>,
    #[serde(rename = "refreshedAt", default, skip_serializing_if = "Option::is_none")]
    pub refreshed_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasons: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsSignOnSessionsRowsItem {
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
    pub authentications: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    #[serde(rename = "wsfedRealms", default, skip_serializing_if = "Option::is_none")]
    pub wsfed_realms: Option<Vec<String>>,
    #[serde(rename = "deviceBound", default, skip_serializing_if = "Option::is_none")]
    pub device_bound: Option<MetricsSignOnSessionsRowsItemDeviceBound>,
    #[serde(rename = "accountSet", default, skip_serializing_if = "Option::is_none")]
    pub account_set: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsSignOnSessions {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub held: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub active: Option<Option<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unread: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<MetricsSignOnSessionsRowsItem>>,
}

/// Everything counted: endpoint calls by matched route and status class, tokens
/// and artifacts by kind, and sessions counted BOTH ways.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metrics {
    /// Milliseconds since the epoch.
    #[serde(rename = "startedAt", default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<f64>,
    #[serde(rename = "startedAtIso", default, skip_serializing_if = "Option::is_none")]
    pub started_at_iso: Option<String>,
    /// When this snapshot was taken, in milliseconds, so that every age in it
    /// can be worked out without trusting the caller's clock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub now: Option<f64>,
    #[serde(rename = "uptimeMs", default, skip_serializing_if = "Option::is_none")]
    pub uptime_ms: Option<f64>,
    /// The custom claim sets and how many claims each holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<MetricsClaimsItem>>,
    /// Endpoint calls, in total and per matched route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calls: Option<MetricsCalls>,
    /// JWTs by kind, with the state of each.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<MetricsTokens>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<MetricsArtifacts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<MetricsUsers>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<MetricsSessions>,
    #[serde(rename = "signOnSessions", default, skip_serializing_if = "Option::is_none")]
    pub sign_on_sessions: Option<MetricsSignOnSessions>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MonitorValue {
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
    pub remote: Option<crate::XacmlPepView>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewApplicationFormRealm {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewApplicationFormKindsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewApplicationFormProtocolsItem {
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
pub struct NewApplicationFormDeclarationsItemFamiliesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewApplicationFormDeclarationsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<sts_model_base::unions::BoolOrString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitive: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub families: Option<Vec<NewApplicationFormDeclarationsItemFamiliesItem>>,
    #[serde(rename = "everyFamily", default, skip_serializing_if = "Option::is_none")]
    pub every_family: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewApplicationFormFieldsItemDescribedSelectAllOnlyWhileOnItem {
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
pub struct NewApplicationFormFieldsItemDescribedSelectAllAloneWhileOnItem {
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
pub struct NewApplicationFormFieldsItemDescribedSelectAll {
    #[serde(rename = "onlyWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub only_while_on: Option<Vec<NewApplicationFormFieldsItemDescribedSelectAllOnlyWhileOnItem>>,
    #[serde(rename = "aloneWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub alone_while_on: Option<Vec<NewApplicationFormFieldsItemDescribedSelectAllAloneWhileOnItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum NewApplicationFormFieldsItemDescribedValue {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum NewApplicationFormFieldsItemDescribedDefault {
    V1(Vec<String>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewApplicationFormFieldsItemDescribed {
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
    pub select_all: Option<NewApplicationFormFieldsItemDescribedSelectAll>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<NewApplicationFormFieldsItemDescribedValue>>,
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
    pub default: Option<Option<NewApplicationFormFieldsItemDescribedDefault>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewApplicationFormFieldsItem {
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
    pub described: Option<NewApplicationFormFieldsItemDescribed>,
    #[serde(rename = "inSimple", default, skip_serializing_if = "Option::is_none")]
    pub in_simple: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewApplicationFormFieldGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub families: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewApplicationFormFamilyChoicesItem {
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
pub struct NewApplicationFormPersistence {
    #[serde(rename = "persistsDirectory", default, skip_serializing_if = "Option::is_none")]
    pub persists_directory: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewApplicationFormResourceMetadataImport {
    #[serde(rename = "wellKnown", default, skip_serializing_if = "Option::is_none")]
    pub well_known: Option<String>,
    #[serde(rename = "acceptsNonconforming", default, skip_serializing_if = "Option::is_none")]
    pub accepts_nonconforming: Option<bool>,
    #[serde(rename = "dialsInternalAddresses", default, skip_serializing_if = "Option::is_none")]
    pub dials_internal_addresses: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewApplicationFormEditableItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<sts_model_base::unions::BoolOrString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitive: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub families: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewApplicationForm {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub container: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub max: Option<Option<f64>>,
    #[serde(rename = "applicationCount", default, skip_serializing_if = "Option::is_none")]
    pub application_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<NewApplicationFormRealm>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<NewApplicationFormKindsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<NewApplicationFormProtocolsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declarations: Option<Vec<NewApplicationFormDeclarationsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<NewApplicationFormFieldsItem>>,
    #[serde(rename = "fieldGroups", default, skip_serializing_if = "Option::is_none")]
    pub field_groups: Option<Vec<NewApplicationFormFieldGroupsItem>>,
    #[serde(rename = "familyChoices", default, skip_serializing_if = "Option::is_none")]
    pub family_choices: Option<Vec<NewApplicationFormFamilyChoicesItem>>,
    #[serde(rename = "longTextAttributes", default, skip_serializing_if = "Option::is_none")]
    pub long_text_attributes: Option<Vec<String>>,
    #[serde(rename = "defaultSecretLifetimeDays", default, skip_serializing_if = "Option::is_none")]
    pub default_secret_lifetime_days: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistence: Option<NewApplicationFormPersistence>,
    #[serde(rename = "resourceMetadataImport", default, skip_serializing_if = "Option::is_none")]
    pub resource_metadata_import: Option<NewApplicationFormResourceMetadataImport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<Vec<NewApplicationFormEditableItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewUserFormRealm {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewUserFormFieldsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invented: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewUserFormFieldGroupsItem {
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
pub struct NewUserFormGridFieldsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multi: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simple: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub takes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewUserFormCredentialsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewUserFormFieldRowsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example: Option<String>,
    #[serde(rename = "forText", default, skip_serializing_if = "Option::is_none")]
    pub for_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub families: Option<Vec<String>>,
    #[serde(rename = "everyFamily", default, skip_serializing_if = "Option::is_none")]
    pub every_family: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simple: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multi: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub takes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewUserFormPersistence {
    #[serde(rename = "persistsDirectory", default, skip_serializing_if = "Option::is_none")]
    pub persists_directory: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewUserFormPasswordPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforced: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<String>>,
}

/// Every attribute a person may be created with, and the four ways they can be
/// given a way in.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewUserForm {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub container: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<NewUserFormRealm>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(rename = "offersExampleData", default, skip_serializing_if = "Option::is_none")]
    pub offers_example_data: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<NewUserFormFieldsItem>>,
    #[serde(rename = "fieldGroups", default, skip_serializing_if = "Option::is_none")]
    pub field_groups: Option<Vec<NewUserFormFieldGroupsItem>>,
    #[serde(rename = "gridFields", default, skip_serializing_if = "Option::is_none")]
    pub grid_fields: Option<Vec<NewUserFormGridFieldsItem>>,
    #[serde(rename = "requiredAttributes", default, skip_serializing_if = "Option::is_none")]
    pub required_attributes: Option<Vec<String>>,
    #[serde(rename = "requiredEnforced", default, skip_serializing_if = "Option::is_none")]
    pub required_enforced: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Vec<NewUserFormCredentialsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(rename = "fieldRows", default, skip_serializing_if = "Option::is_none")]
    pub field_rows: Option<Vec<NewUserFormFieldRowsItem>>,
    #[serde(rename = "longTextAttributes", default, skip_serializing_if = "Option::is_none")]
    pub long_text_attributes: Option<Vec<String>>,
    #[serde(rename = "mailAvailable", default, skip_serializing_if = "Option::is_none")]
    pub mail_available: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistence: Option<NewUserFormPersistence>,
    #[serde(rename = "defaultCredential", default, skip_serializing_if = "Option::is_none")]
    pub default_credential: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    #[serde(rename = "passwordPolicy", default, skip_serializing_if = "Option::is_none")]
    pub password_policy: Option<NewUserFormPasswordPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub invented: Option<Option<serde_json::Map<String, serde_json::Value>>>,
    #[serde(rename = "inventRefused", default, skip_serializing_if = "Option::is_none")]
    pub invent_refused: Option<String>,
}

pub type OpenApi = serde_json::Value;

/// An OpenAPI 3.1.0 document.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenApi2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openapi: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub info: Option<crate::OpenApi>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servers: Option<crate::OpenApi>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<crate::OpenApi>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<crate::OpenApi>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<crate::OpenApi>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub components: Option<crate::OpenApi>,
}

pub type OpenIdConnectIdentityAssuranceVerification = serde_json::Value;

pub type OrderConfig = Vec<crate::GroupSSettings>;

pub type OtherPagesSettingsGroupDrawn = serde_json::Map<String, serde_json::Value>;

/// Which page of how many, and the query parameter that moves it.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageHowManyQueryParameter {
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

/// One link the page offers.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsLinksItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsSettingsGroupsItemSettingsItemSelectAllOnlyWhileOnItem {
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
pub struct PageSettingsSettingsGroupsItemSettingsItemSelectAllAloneWhileOnItem {
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
pub struct PageSettingsSettingsGroupsItemSettingsItemSelectAll {
    #[serde(rename = "onlyWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub only_while_on: Option<Vec<PageSettingsSettingsGroupsItemSettingsItemSelectAllOnlyWhileOnItem>>,
    #[serde(rename = "aloneWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub alone_while_on: Option<Vec<PageSettingsSettingsGroupsItemSettingsItemSelectAllAloneWhileOnItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PageSettingsSettingsGroupsItemSettingsItemValue {
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
pub enum PageSettingsSettingsGroupsItemSettingsItemSource {
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
pub enum PageSettingsSettingsGroupsItemSettingsItemDefault {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

/// One setting: what it is, what it is set to, and where that came from.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsSettingsGroupsItemSettingsItem {
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
    pub select_all: Option<PageSettingsSettingsGroupsItemSettingsItemSelectAll>,
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
    pub value: Option<Option<PageSettingsSettingsGroupsItemSettingsItemValue>>,
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
    pub source: Option<PageSettingsSettingsGroupsItemSettingsItemSource>,
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
    pub default: Option<Option<PageSettingsSettingsGroupsItemSettingsItemDefault>>,
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
pub struct PageSettingsSettingsGroupsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Vec<PageSettingsSettingsGroupsItemSettingsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsSettingsContext {
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
pub struct PageSettingsSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    /// In the order `config.js` declares them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<PageSettingsSettingsGroupsItem>>,
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
    pub context: Option<PageSettingsSettingsContext>,
    /// A group drawn on another page as well, and those pages.
    #[serde(rename = "sharedWith", default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV1DatabasePasswordSecretWhere {
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

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV1DatabasePasswordSecretProvidersItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV1DatabasePasswordSecret {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configured: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known: Option<bool>,
    #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
    pub where_: Option<PageSettingsStatusV1DatabasePasswordSecretWhere>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub providers: Option<Vec<PageSettingsStatusV1DatabasePasswordSecretProvidersItem>>,
}

/// Parsed out of the connection string, which is never returned.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV1Database {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub host: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub port: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub database: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub user: Option<Option<String>>,
    #[serde(rename = "passwordFrom", default, skip_serializing_if = "Option::is_none")]
    pub password_from: Option<String>,
    #[serde(rename = "passwordProvider", default, skip_serializing_if = "Option::is_none")]
    pub password_provider: Option<String>,
    #[serde(rename = "passwordSecret", default, skip_serializing_if = "Option::is_none")]
    pub password_secret: Option<PageSettingsStatusV1DatabasePasswordSecret>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sslmode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted: Option<bool>,
    #[serde(rename = "verifyCertificate", default, skip_serializing_if = "Option::is_none")]
    pub verify_certificate: Option<bool>,
    #[serde(rename = "caFile", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ca_file: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV1Restored {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entries: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overrides: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV1MintedHandlesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shape: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV1MintedPoisonDropsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handles: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realms: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV1Minted {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persisting: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supported: Option<bool>,
    #[serde(rename = "unsupportedReason", default, skip_serializing_if = "Option::is_none")]
    pub unsupported_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting: Option<bool>,
    #[serde(rename = "retentionMs", default, skip_serializing_if = "Option::is_none")]
    pub retention_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stores: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handles: Option<Vec<PageSettingsStatusV1MintedHandlesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writes: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<i64>,
    #[serde(rename = "rowsWritten", default, skip_serializing_if = "Option::is_none")]
    pub rows_written: Option<i64>,
    #[serde(rename = "rowsDeleted", default, skip_serializing_if = "Option::is_none")]
    pub rows_deleted: Option<i64>,
    #[serde(rename = "lastWriteAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_write_at: Option<Option<String>>,
    #[serde(rename = "lastError", default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(rename = "restoredAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub restored_at: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restored: Option<i64>,
    #[serde(rename = "droppedUnreadable", default, skip_serializing_if = "Option::is_none")]
    pub dropped_unreadable: Option<i64>,
    #[serde(rename = "droppedUnknown", default, skip_serializing_if = "Option::is_none")]
    pub dropped_unknown: Option<i64>,
    #[serde(rename = "droppedPoison", default, skip_serializing_if = "Option::is_none")]
    pub dropped_poison: Option<i64>,
    #[serde(rename = "poisonDrops", default, skip_serializing_if = "Option::is_none")]
    pub poison_drops: Option<Vec<PageSettingsStatusV1MintedPoisonDropsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV1UsedAssertions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistent: Option<bool>,
    #[serde(rename = "atomicAcrossProcesses", default, skip_serializing_if = "Option::is_none")]
    pub atomic_across_processes: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub live: Option<Option<i64>>,
    #[serde(rename = "liveIsCurrent", default, skip_serializing_if = "Option::is_none")]
    pub live_is_current: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV1ReplicationRetentionLastTrim {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error: Option<Option<String>>,
    #[serde(rename = "readersGone", default, skip_serializing_if = "Option::is_none")]
    pub readers_gone: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readers: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub bound: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trimmed: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV1ReplicationRetention {
    #[serde(rename = "retentionS", default, skip_serializing_if = "Option::is_none")]
    pub retention_s: Option<i64>,
    #[serde(rename = "readerTtlS", default, skip_serializing_if = "Option::is_none")]
    pub reader_ttl_s: Option<i64>,
    #[serde(rename = "reportedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub reported_at: Option<Option<String>>,
    #[serde(rename = "reportError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub report_error: Option<Option<String>>,
    #[serde(rename = "declaredGoneAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub declared_gone_at: Option<Option<String>>,
    #[serde(rename = "fanInGraceS", default, skip_serializing_if = "Option::is_none")]
    pub fan_in_grace_s: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trimming: Option<bool>,
    #[serde(rename = "lastTrim", default, skip_serializing_if = "Option::is_none")]
    pub last_trim: Option<PageSettingsStatusV1ReplicationRetentionLastTrim>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV1Replication {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinating: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supported: Option<bool>,
    #[serde(rename = "startedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub started_at: Option<Option<String>>,
    #[serde(rename = "appliedSeq", default, skip_serializing_if = "Option::is_none")]
    pub applied_seq: Option<f64>,
    #[serde(rename = "highestSeq", default, skip_serializing_if = "Option::is_none")]
    pub highest_seq: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holes: Option<i64>,
    #[serde(rename = "holeRanges", default, skip_serializing_if = "Option::is_none")]
    pub hole_ranges: Option<i64>,
    #[serde(rename = "holesAbandoned", default, skip_serializing_if = "Option::is_none")]
    pub holes_abandoned: Option<i64>,
    #[serde(rename = "pollIntervalMs", default, skip_serializing_if = "Option::is_none")]
    pub poll_interval_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pulls: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nudges: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<i64>,
    #[serde(rename = "rowsApplied", default, skip_serializing_if = "Option::is_none")]
    pub rows_applied: Option<i64>,
    /// Rows applied, per kind of change.
    #[serde(rename = "byKind", default, skip_serializing_if = "Option::is_none")]
    pub by_kind: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "lastPullAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_pull_at: Option<Option<String>>,
    #[serde(rename = "lastError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_error: Option<Option<String>>,
    #[serde(rename = "otherProcesses", default, skip_serializing_if = "Option::is_none")]
    pub other_processes: Option<i64>,
    #[serde(rename = "originsDropped", default, skip_serializing_if = "Option::is_none")]
    pub origins_dropped: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<PageSettingsStatusV1ReplicationRetention>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV1CellsGlobalReplicationRetentionLastTrim {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error: Option<Option<String>>,
    #[serde(rename = "readersGone", default, skip_serializing_if = "Option::is_none")]
    pub readers_gone: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readers: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub bound: Option<Option<sts_model_base::unions::NumberOrString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trimmed: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV1CellsGlobalReplicationRetention {
    #[serde(rename = "retentionS", default, skip_serializing_if = "Option::is_none")]
    pub retention_s: Option<i64>,
    #[serde(rename = "readerTtlS", default, skip_serializing_if = "Option::is_none")]
    pub reader_ttl_s: Option<i64>,
    #[serde(rename = "reportedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub reported_at: Option<Option<String>>,
    #[serde(rename = "reportError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub report_error: Option<Option<String>>,
    #[serde(rename = "declaredGoneAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub declared_gone_at: Option<Option<String>>,
    #[serde(rename = "fanInGraceS", default, skip_serializing_if = "Option::is_none")]
    pub fan_in_grace_s: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trimming: Option<bool>,
    #[serde(rename = "lastTrim", default, skip_serializing_if = "Option::is_none")]
    pub last_trim: Option<PageSettingsStatusV1CellsGlobalReplicationRetentionLastTrim>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV1CellsGlobalReplication {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinating: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supported: Option<bool>,
    #[serde(rename = "startedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub started_at: Option<Option<String>>,
    #[serde(rename = "appliedSeq", default, skip_serializing_if = "Option::is_none")]
    pub applied_seq: Option<f64>,
    #[serde(rename = "highestSeq", default, skip_serializing_if = "Option::is_none")]
    pub highest_seq: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holes: Option<i64>,
    #[serde(rename = "holeRanges", default, skip_serializing_if = "Option::is_none")]
    pub hole_ranges: Option<i64>,
    #[serde(rename = "holesAbandoned", default, skip_serializing_if = "Option::is_none")]
    pub holes_abandoned: Option<i64>,
    #[serde(rename = "pollIntervalMs", default, skip_serializing_if = "Option::is_none")]
    pub poll_interval_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pulls: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nudges: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<i64>,
    #[serde(rename = "rowsApplied", default, skip_serializing_if = "Option::is_none")]
    pub rows_applied: Option<i64>,
    /// Rows applied, per kind of change.
    #[serde(rename = "byKind", default, skip_serializing_if = "Option::is_none")]
    pub by_kind: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "lastPullAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_pull_at: Option<Option<String>>,
    #[serde(rename = "lastError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_error: Option<Option<String>>,
    #[serde(rename = "otherProcesses", default, skip_serializing_if = "Option::is_none")]
    pub other_processes: Option<i64>,
    #[serde(rename = "originsDropped", default, skip_serializing_if = "Option::is_none")]
    pub origins_dropped: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<PageSettingsStatusV1CellsGlobalReplicationRetention>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV1CellsRouting {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub indexed: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conflicts: Option<i64>,
    #[serde(rename = "lastConflict", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_conflict: Option<Option<String>>,
    #[serde(rename = "projectionWrites", default, skip_serializing_if = "Option::is_none")]
    pub projection_writes: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV1Cells {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub jurisdiction: Option<Option<String>>,
    #[serde(rename = "globalReplication", default, skip_serializing_if = "Option::is_none")]
    pub global_replication: Option<PageSettingsStatusV1CellsGlobalReplication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing: Option<PageSettingsStatusV1CellsRouting>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV1Origin {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adopted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV1Liveness {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queries: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connects: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drops: Option<i64>,
    #[serde(rename = "viaPool", default, skip_serializing_if = "Option::is_none")]
    pub via_pool: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV1EventLoopLastReport {
    #[serde(rename = "maxMs", default, skip_serializing_if = "Option::is_none")]
    pub max_ms: Option<f64>,
    #[serde(rename = "p99Ms", default, skip_serializing_if = "Option::is_none")]
    pub p99_ms: Option<f64>,
    #[serde(rename = "meanMs", default, skip_serializing_if = "Option::is_none")]
    pub mean_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV1EventLoopSinceReport {
    #[serde(rename = "maxMs", default, skip_serializing_if = "Option::is_none")]
    pub max_ms: Option<f64>,
    #[serde(rename = "p99Ms", default, skip_serializing_if = "Option::is_none")]
    pub p99_ms: Option<f64>,
    #[serde(rename = "meanMs", default, skip_serializing_if = "Option::is_none")]
    pub mean_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV1EventLoop {
    #[serde(rename = "lastReport", default, skip_serializing_if = "Option::is_none")]
    pub last_report: Option<PageSettingsStatusV1EventLoopLastReport>,
    #[serde(rename = "sinceReport", default, skip_serializing_if = "Option::is_none")]
    pub since_report: Option<PageSettingsStatusV1EventLoopSinceReport>,
    #[serde(rename = "warnAboveMs", default, skip_serializing_if = "Option::is_none")]
    pub warn_above_ms: Option<f64>,
}

/// What the store is actually doing, which is a different fact from what
/// `persistence.*` says it should.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(rename = "configuredMode", default, skip_serializing_if = "Option::is_none")]
    pub configured_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub healthy: Option<Option<bool>>,
    #[serde(rename = "dataDir", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub data_dir: Option<Option<String>>,
    /// Parsed out of the connection string, which is never returned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<PageSettingsStatusV1Database>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub engine: Option<Option<String>>,
    #[serde(rename = "writeDelayMs", default, skip_serializing_if = "Option::is_none")]
    pub write_delay_ms: Option<i64>,
    #[serde(rename = "persistsDirectory", default, skip_serializing_if = "Option::is_none")]
    pub persists_directory: Option<bool>,
    #[serde(rename = "persistsRealms", default, skip_serializing_if = "Option::is_none")]
    pub persists_realms: Option<bool>,
    #[serde(rename = "persistsAppconfig", default, skip_serializing_if = "Option::is_none")]
    pub persists_appconfig: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writes: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<i64>,
    #[serde(rename = "lastWriteAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_write_at: Option<Option<String>>,
    #[serde(rename = "lastError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_error: Option<Option<String>>,
    #[serde(rename = "restoredAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub restored_at: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restored: Option<PageSettingsStatusV1Restored>,
    #[serde(rename = "entriesTracked", default, skip_serializing_if = "Option::is_none")]
    pub entries_tracked: Option<i64>,
    #[serde(rename = "realmsTracked", default, skip_serializing_if = "Option::is_none")]
    pub realms_tracked: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinates: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minted: Option<PageSettingsStatusV1Minted>,
    #[serde(rename = "usedAssertions", default, skip_serializing_if = "Option::is_none")]
    pub used_assertions: Option<PageSettingsStatusV1UsedAssertions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replication: Option<PageSettingsStatusV1Replication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cells: Option<PageSettingsStatusV1Cells>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<PageSettingsStatusV1Origin>,
    #[serde(rename = "answersAfterCommit", default, skip_serializing_if = "Option::is_none")]
    pub answers_after_commit: Option<bool>,
    #[serde(rename = "commitBacklog", default, skip_serializing_if = "Option::is_none")]
    pub commit_backlog: Option<bool>,
    #[serde(rename = "retryArmed", default, skip_serializing_if = "Option::is_none")]
    pub retry_armed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liveness: Option<PageSettingsStatusV1Liveness>,
    #[serde(rename = "eventLoop", default, skip_serializing_if = "Option::is_none")]
    pub event_loop: Option<PageSettingsStatusV1EventLoop>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV2SelfLeasesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<sts_model_base::unions::NumberOrString>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV2SelfCapabilitiesRowsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provided: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV2SelfCapabilities {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<PageSettingsStatusV2SelfCapabilitiesRowsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing: Option<Vec<String>>,
    #[serde(rename = "acceptedMissing", default, skip_serializing_if = "Option::is_none")]
    pub accepted_missing: Option<Vec<String>>,
    #[serde(rename = "unknownAccepted", default, skip_serializing_if = "Option::is_none")]
    pub unknown_accepted: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV2Self {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub refused: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configured: Option<String>,
    #[serde(rename = "nodeId", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub node_id: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub role: Option<Option<String>>,
    #[serde(rename = "joinedAt", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub joined_at: Option<Option<String>>,
    #[serde(rename = "heartbeatMs", default, skip_serializing_if = "Option::is_none")]
    pub heartbeat_ms: Option<f64>,
    #[serde(rename = "ttlMs", default, skip_serializing_if = "Option::is_none")]
    pub ttl_ms: Option<f64>,
    #[serde(rename = "lastStallMs", default, skip_serializing_if = "Option::is_none")]
    pub last_stall_ms: Option<f64>,
    #[serde(rename = "msSinceRenewal", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub ms_since_renewal: Option<Option<f64>>,
    #[serde(rename = "heartbeatFailures", default, skip_serializing_if = "Option::is_none")]
    pub heartbeat_failures: Option<i64>,
    #[serde(rename = "lastHeartbeatError", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub last_heartbeat_error: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leases: Option<Vec<PageSettingsStatusV2SelfLeasesItem>>,
    #[serde(rename = "fingerprintSet", default, skip_serializing_if = "Option::is_none")]
    pub fingerprint_set: Option<bool>,
    #[serde(rename = "agreementSettings", default, skip_serializing_if = "Option::is_none")]
    pub agreement_settings: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<PageSettingsStatusV2SelfCapabilities>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV2NodesItemInfoCaches {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<String>,
    /// name, size, largest realm, valid, bound, hits, misses, evictions,
    /// refusals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caches: Option<Vec<Vec<Option<sts_model_base::unions::NumberOrString>>>>,
}

/// What only that node can say about itself.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV2NodesItemInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub port: Option<Option<sts_model_base::unions::BoolOrNumberOrString>>,
    #[serde(rename = "uptimeMs", default, skip_serializing_if = "Option::is_none")]
    pub uptime_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workers: Option<i64>,
    #[serde(rename = "lastStallMs", default, skip_serializing_if = "Option::is_none")]
    pub last_stall_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caches: Option<PageSettingsStatusV2NodesItemInfoCaches>,
    /// Base64, the PEM's body.
    #[serde(rename = "listenerCertificates", default, skip_serializing_if = "Option::is_none")]
    pub listener_certificates: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV2NodesItem {
    #[serde(rename = "nodeId", default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub mode: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub version: Option<Option<String>>,
    #[serde(rename = "startedAt", default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<f64>,
    #[serde(rename = "heartbeatAt", default, skip_serializing_if = "Option::is_none")]
    pub heartbeat_at: Option<f64>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
    #[serde(rename = "leftAt", default, skip_serializing_if = "Option::is_none")]
    pub left_at: Option<f64>,
    /// What only that node can say about itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub info: Option<PageSettingsStatusV2NodesItemInfo>,
    /// Whether its settings fingerprint agrees with the node answering; the
    /// fingerprint is never returned.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub agrees: Option<Option<bool>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV2MembersLeftOrExpiredItem {
    #[serde(rename = "nodeId", default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
    #[serde(rename = "earlierLives", default, skip_serializing_if = "Option::is_none")]
    pub earlier_lives: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV2Members {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub running: Option<Vec<String>>,
    /// Per running name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restarts: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "leftOrExpired", default, skip_serializing_if = "Option::is_none")]
    pub left_or_expired: Option<Vec<PageSettingsStatusV2MembersLeftOrExpiredItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV2LeasesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<f64>,
    #[serde(rename = "acquiredAt", default, skip_serializing_if = "Option::is_none")]
    pub acquired_at: Option<f64>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV2OtherCellsCellsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub jurisdiction: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reachable: Option<bool>,
    #[serde(rename = "answeredMs", default, skip_serializing_if = "Option::is_none")]
    pub answered_ms: Option<f64>,
    /// Another cell's own cluster summary, relayed: that cell may run another
    /// build, so this one does not narrow it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV2OtherCells {
    #[serde(rename = "askedAt", default, skip_serializing_if = "Option::is_none")]
    pub asked_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cells: Option<Vec<PageSettingsStatusV2OtherCellsCellsItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub error: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV2SecretsSecretsItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// Where each shared secret's value came from, never the value.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV2Secrets {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<PageSettingsStatusV2SecretsSecretsItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV2Barrier {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holds: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests: Option<i64>,
    #[serde(rename = "caughtUp", default, skip_serializing_if = "Option::is_none")]
    pub caught_up: Option<i64>,
    #[serde(rename = "gaveUp", default, skip_serializing_if = "Option::is_none")]
    pub gave_up: Option<i64>,
    #[serde(rename = "heldForCommit", default, skip_serializing_if = "Option::is_none")]
    pub held_for_commit: Option<i64>,
    #[serde(rename = "answeredUnheld", default, skip_serializing_if = "Option::is_none")]
    pub answered_unheld: Option<i64>,
    #[serde(rename = "commitFailures", default, skip_serializing_if = "Option::is_none")]
    pub commit_failures: Option<i64>,
    #[serde(rename = "totalWaitMs", default, skip_serializing_if = "Option::is_none")]
    pub total_wait_ms: Option<f64>,
    #[serde(rename = "totalHoldMs", default, skip_serializing_if = "Option::is_none")]
    pub total_hold_ms: Option<f64>,
    #[serde(rename = "refusedForCommit", default, skip_serializing_if = "Option::is_none")]
    pub refused_for_commit: Option<i64>,
    #[serde(rename = "heldForBacklog", default, skip_serializing_if = "Option::is_none")]
    pub held_for_backlog: Option<i64>,
    #[serde(rename = "ldapHeldForCommit", default, skip_serializing_if = "Option::is_none")]
    pub ldap_held_for_commit: Option<i64>,
    #[serde(rename = "ldapRefusedForCommit", default, skip_serializing_if = "Option::is_none")]
    pub ldap_refused_for_commit: Option<i64>,
    /// Responses whose commit succeeded and whose deferred check (an access
    /// token's status index, #884) then refused them; each answered 503.
    #[serde(rename = "checkRefusals", default, skip_serializing_if = "Option::is_none")]
    pub check_refusals: Option<i64>,
    #[serde(rename = "meanWaitMs", default, skip_serializing_if = "Option::is_none")]
    pub mean_wait_ms: Option<f64>,
    #[serde(rename = "meanHoldMs", default, skip_serializing_if = "Option::is_none")]
    pub mean_hold_ms: Option<f64>,
}

/// Whether a cluster is WORKING, which `cluster.mode` being set does not say.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettingsStatusV2 {
    #[serde(rename = "self", default, skip_serializing_if = "Option::is_none")]
    pub self_: Option<PageSettingsStatusV2Self>,
    #[serde(rename = "snapshotAgeMs", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub snapshot_age_ms: Option<Option<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodes: Option<Vec<PageSettingsStatusV2NodesItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<PageSettingsStatusV2Members>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leases: Option<Vec<PageSettingsStatusV2LeasesItem>>,
    #[serde(rename = "databaseNow", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub database_now: Option<Option<f64>>,
    #[serde(rename = "otherCells", default, skip_serializing_if = "Option::is_none")]
    pub other_cells: Option<PageSettingsStatusV2OtherCells>,
    /// Where each shared secret's value came from, never the value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<PageSettingsStatusV2Secrets>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub barrier: Option<PageSettingsStatusV2Barrier>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PageSettingsStatus {
    V1(PageSettingsStatusV1),
    V2(PageSettingsStatusV2),
}

/// One console page, and the settings it draws: the same described rows GET
/// /config returns, filtered to the ones that page owns.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSettings {
    /// The console path this mirrors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// What the page says the family is, as plain text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    /// The caveats the page carries, in order. On these pages the caveats are
    /// most of the content: what a family does NOT check is the half a client
    /// author cannot read off a protocol trace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<PageSettingsLinksItem>>,
    /// The settings this page draws, described: the same rows GET /config
    /// returns, filtered to the ones this page owns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<PageSettingsSettings>,
    /// The page's first paragraph, as the console draws it.
    #[serde(rename = "leadHtml", default, skip_serializing_if = "Option::is_none")]
    pub lead_html: Option<String>,
    /// The caveats, as the console draws them.
    #[serde(rename = "alsoHtml", default, skip_serializing_if = "Option::is_none")]
    pub also_html: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<PageSettingsStatus>,
}

/// Which page of how many, and the query parameter that moves it.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PagingValue {
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
pub enum ParameterSensitiveValuesMaskedValue {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ParameterSensitiveValuesMaskedDefault {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

/// One parameter, its sensitive values masked.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParameterSensitiveValuesMasked {
    /// The parameter's dot path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub value: Option<Option<ParameterSensitiveValuesMaskedValue>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub default: Option<Option<ParameterSensitiveValuesMaskedDefault>>,
    /// Where the effective value came from, as `GET /config` says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// The environment variable that sets it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<bool>,
    /// Present, true, when a sensitive value was replaced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
}

pub type PartnerSOwnAnswerSsf = serde_json::Value;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PasskeyPolicyRowAllowUsernameless {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PasskeyPolicyRowRequireUsernameless {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PasskeyPolicyRowSecurityKeyResidentKey {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PasskeyPolicyRowBackupEligibility {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PasskeyPolicyRowEnforcePinLength {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PasskeyPolicyRowMinPinLength {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PasskeyPolicyRowPinLengthOnlyIfSupported {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PasskeyPolicyRowEnforceAttestationAtSignIn {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PasskeyPolicyRowPostQuantumRequired {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PasskeyPolicyRowPostQuantumAllowCredentials {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PasskeyPolicyRowRegistrationAlgorithms {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PasskeyPolicyRowRegistrationMode {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PasskeyPolicyRowLanes {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PasskeyPolicyRowClientRules {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PasskeyPolicyRowPasskeyHints {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PasskeyPolicyRowSecurityKeyHints {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PasskeyPolicyRowSignInHints {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PasskeyPolicyRowEnterpriseSerialAttribute {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PasskeyPolicyRowUserDisplayName {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PasskeyPolicyRowRpNameExtras {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PasskeyPolicyRowCredentialLabel {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PasskeyPolicyRowAggregateDevices {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PasskeyPolicyRowRecoveryAssurance {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PasskeyPolicyRowAttestationAlgorithms {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PasskeyPolicyRowAdminEnrolment {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum PasskeyPolicyRowDeviceBoundRequired {
    V1(Vec<Option<sts_model_base::unions::BoolOrNumberOrString>>),
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyPolicyRow {
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
    #[serde(rename = "allowUsernameless", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub allow_usernameless: Option<Option<PasskeyPolicyRowAllowUsernameless>>,
    #[serde(rename = "requireUsernameless", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub require_usernameless: Option<Option<PasskeyPolicyRowRequireUsernameless>>,
    #[serde(rename = "securityKeyResidentKey", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub security_key_resident_key: Option<Option<PasskeyPolicyRowSecurityKeyResidentKey>>,
    #[serde(rename = "backupEligibility", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub backup_eligibility: Option<Option<PasskeyPolicyRowBackupEligibility>>,
    #[serde(rename = "enforcePinLength", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub enforce_pin_length: Option<Option<PasskeyPolicyRowEnforcePinLength>>,
    #[serde(rename = "minPinLength", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub min_pin_length: Option<Option<PasskeyPolicyRowMinPinLength>>,
    #[serde(rename = "pinLengthOnlyIfSupported", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub pin_length_only_if_supported: Option<Option<PasskeyPolicyRowPinLengthOnlyIfSupported>>,
    #[serde(rename = "enforceAttestationAtSignIn", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub enforce_attestation_at_sign_in: Option<Option<PasskeyPolicyRowEnforceAttestationAtSignIn>>,
    #[serde(rename = "postQuantumRequired", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub post_quantum_required: Option<Option<PasskeyPolicyRowPostQuantumRequired>>,
    #[serde(rename = "postQuantumAllowCredentials", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub post_quantum_allow_credentials: Option<Option<PasskeyPolicyRowPostQuantumAllowCredentials>>,
    #[serde(rename = "registrationAlgorithms", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub registration_algorithms: Option<Option<PasskeyPolicyRowRegistrationAlgorithms>>,
    #[serde(rename = "registrationMode", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub registration_mode: Option<Option<PasskeyPolicyRowRegistrationMode>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub lanes: Option<Option<PasskeyPolicyRowLanes>>,
    #[serde(rename = "clientRules", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub client_rules: Option<Option<PasskeyPolicyRowClientRules>>,
    #[serde(rename = "passkeyHints", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub passkey_hints: Option<Option<PasskeyPolicyRowPasskeyHints>>,
    #[serde(rename = "securityKeyHints", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub security_key_hints: Option<Option<PasskeyPolicyRowSecurityKeyHints>>,
    #[serde(rename = "signInHints", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub sign_in_hints: Option<Option<PasskeyPolicyRowSignInHints>>,
    #[serde(rename = "enterpriseSerialAttribute", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub enterprise_serial_attribute: Option<Option<PasskeyPolicyRowEnterpriseSerialAttribute>>,
    #[serde(rename = "userDisplayName", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub user_display_name: Option<Option<PasskeyPolicyRowUserDisplayName>>,
    #[serde(rename = "rpNameExtras", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub rp_name_extras: Option<Option<PasskeyPolicyRowRpNameExtras>>,
    #[serde(rename = "credentialLabel", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub credential_label: Option<Option<PasskeyPolicyRowCredentialLabel>>,
    #[serde(rename = "aggregateDevices", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub aggregate_devices: Option<Option<PasskeyPolicyRowAggregateDevices>>,
    #[serde(rename = "recoveryAssurance", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub recovery_assurance: Option<Option<PasskeyPolicyRowRecoveryAssurance>>,
    #[serde(rename = "attestationAlgorithms", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub attestation_algorithms: Option<Option<PasskeyPolicyRowAttestationAlgorithms>>,
    #[serde(rename = "adminEnrolment", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub admin_enrolment: Option<Option<PasskeyPolicyRowAdminEnrolment>>,
    #[serde(rename = "deviceBoundRequired", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub device_bound_required: Option<Option<PasskeyPolicyRowDeviceBoundRequired>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentOrderedSettingWhoseSelectOnlyWhileOnItem {
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
pub struct PresentOrderedSettingWhoseSelectAloneWhileOnItem {
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
pub struct PresentOrderedSettingWhoseSelect {
    #[serde(rename = "onlyWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub only_while_on: Option<Vec<PresentOrderedSettingWhoseSelectOnlyWhileOnItem>>,
    #[serde(rename = "aloneWhileOn", default, skip_serializing_if = "Option::is_none")]
    pub alone_while_on: Option<Vec<PresentOrderedSettingWhoseSelectAloneWhileOnItem>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskChangeValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub previous: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "beforeCompromise", default, skip_serializing_if = "Option::is_none")]
    pub before_compromise: Option<String>,
}

/// One setting: what it is, what it is set to, and where that came from.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingSetWhereCame {
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
    #[serde(rename = "selectAll", default, skip_serializing_if = "Option::is_none")]
    pub select_all: Option<crate::PresentOrderedSettingWhoseSelect>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<crate::ValueValue>,
    /// The same value on one line: what the console shows in its input and what
    /// the environment variable would carry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<crate::SourceValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editable: Option<crate::EditableValue>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<sts_model_management_components_1::DefaultValue>,
    /// Whether a trust realm may hold its own value for it.
    #[serde(rename = "realmSettable", default, skip_serializing_if = "Option::is_none")]
    pub realm_settable: Option<bool>,
    /// Whether a runtime override is in force. Equal to `source ===
    /// "override"`, and reported separately so a caller can filter without
    /// matching a string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden: Option<bool>,
}

/// Where the effective value came from, highest first: this trust realm's own
/// value; a runtime override set through this API or the console; the setting's
/// own environment variable; a legacy variable (no row has one since #523); the
/// appconfig file CONFIG_FILE names; `env/defaults.js`, the DEFAULT appconfig
/// file that one is unioned on top of. `default` is reachable only for the
/// DERIVED settings, whose value is a function of a neighbouring setting: for
/// every other setting, no value anywhere stops this service from STARTING.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SourceValue {
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

/// The model allows `null` here too: a handler answers it as `None`
/// of an `Option` of this type.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ValueValue {
    V1(Vec<sts_model_base::unions::BoolOrNumberOrString>),
    Bool(bool),
    Number(f64),
    String(String),
}

pub type WithAdditionalPropertiesPropertiesEnded = Vec<crate::WithIdRealmClientId>;

pub type WithAdditionalPropertiesPropertiesKeys = Vec<crate::WithKtyUseAlg>;

pub type WithAdditionalPropertiesPropertiesLevel = Vec<crate::WithIdKindThumbprint>;

pub type WithAdditionalPropertiesPropertiesPrincipal = Vec<crate::WithKvnoEtypesEtype>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithCertificateSubjectIssuer {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub subject: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub issuer: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub serial: Option<Option<String>>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub not_after: Option<Option<sts_model_base::unions::NumberOrString>>,
    /// A public JWK's members.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwk: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "credentialId", default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aaguid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment: Option<String>,
}

pub type WithDescriptionGroupSettings = Vec<crate::SettingSetWhereCame>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdKindThumbprint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added: Option<String>,
    #[serde(rename = "addedBy", default, skip_serializing_if = "Option::is_none")]
    pub added_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<crate::WithLevelFormatSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub material: Option<crate::WithCertificateSubjectIssuer>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithIdRealmClientId {
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
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub status: Option<Option<f64>>,
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
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(rename = "sessionRequired", default, skip_serializing_if = "Option::is_none")]
    pub session_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithKtyUseAlg {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kty: Option<String>,
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
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
    pub ek: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
    #[serde(rename = "x5t#S256", default, skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithKvnoEtypesEtypeEtypesItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etype: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "sts_model_base::double_option")]
    pub name: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithKvnoEtypesEtype {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kvno: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etypes: Option<Vec<WithKvnoEtypesEtypeEtypesItem>>,
    #[serde(rename = "retiredAt", default, skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithLevelFormatSummaryFreshness {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithLevelFormatSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(rename = "verifiedAt", default, skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<String>,
    #[serde(rename = "chainSerials", default, skip_serializing_if = "Option::is_none")]
    pub chain_serials: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation: Option<crate::WithStatusReasonSerial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freshness: Option<WithLevelFormatSummaryFreshness>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithProviderPayloadRegion {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<String>,
    #[serde(rename = "caCertificates", default, skip_serializing_if = "Option::is_none")]
    pub ca_certificates: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithStatusReasonSerial {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(rename = "listVersion", default, skip_serializing_if = "Option::is_none")]
    pub list_version: Option<String>,
    #[serde(rename = "checkedAt", default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<sts_model_base::unions::NumberOrString>,
    #[serde(rename = "chainSerials", default, skip_serializing_if = "Option::is_none")]
    pub chain_serials: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XacmlPepView {
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
